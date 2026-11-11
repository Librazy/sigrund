/* Resident G-01 acquisition worker. No workload execution code. */
#define _GNU_SOURCE
#include <sys/ptrace.h>
#include <linux/ptrace.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/sched.h>
#include <linux/seccomp.h>
#include <linux/nsfs.h>
#include <linux/kcmp.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <sys/xattr.h>
#include <errno.h>
#include <dirent.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <grp.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef SO_PEERPIDFD
#define SO_PEERPIDFD 77
#endif
#define COUNT(a) (sizeof(a) / sizeof((a)[0]))
static const char *names[] = {"cgroup", "ipc", "mnt", "net", "pid", "time", "user", "uts"};

static void fail(const char *expr, int line) {
    dprintf(2, "target capture:%d: %s: %s\n", line, expr, strerror(errno));
    _exit(77);
}
#define MUST(x) do { if (!(x)) fail(#x, __LINE__); } while (0)
static int same(int a, int b) {
    struct stat x, y;
    return fstat(a, &x) == 0 && fstat(b, &y) == 0 && x.st_dev == y.st_dev && x.st_ino == y.st_ino;
}
static int same_fs(int a, int b) {
    struct statx x, y;
    return same(a, b) && statx(a, "", AT_EMPTY_PATH, STATX_MNT_ID, &x) == 0
        && statx(b, "", AT_EMPTY_PATH, STATX_MNT_ID, &y) == 0
        && (x.stx_mask & STATX_MNT_ID) && (y.stx_mask & STATX_MNT_ID)
        && x.stx_mnt_id == y.stx_mnt_id;
}
static int open_proc(pid_t pid, const char *name, int flags) {
    char path[128];
    MUST(snprintf(path, sizeof(path), "/proc/%d/%s", pid, name) < (int)sizeof(path));
    return open(path, flags | O_CLOEXEC);
}
static void read_text(int fd, char *buffer, size_t capacity) {
    ssize_t size = pread(fd, buffer, capacity - 1, 0);
    MUST(size > 0 && (size_t)size < capacity - 1);
    buffer[size] = 0;
}
/* Only complete procfs keys may supply security decisions. */
static char *status_value(char *buffer, const char *name) {
    size_t length = strlen(name);
    for (char *line = buffer; line && *line;) {
        char *next = strchr(line, '\n');
        if (!strncmp(line, name, length)) {
            if (next) *next = 0;
            return line + length;
        }
        line = next ? next + 1 : NULL;
    }
    return NULL;
}
static unsigned long status_number(char **cursor) {
    char *p = *cursor;
    while (*p == ' ' || *p == '\t') p++;
    MUST(*p >= '0' && *p <= '9');
    errno = 0;
    char *end;
    unsigned long value = strtoul(p, &end, 10);
    MUST(errno == 0 && (*end == 0 || *end == ' ' || *end == '\t'));
    *cursor = end;
    return value;
}
static void status_end(char *p) {
    while (*p == ' ' || *p == '\t') p++;
    MUST(*p == 0);
}
static long field(pid_t pid, const char *name) {
    int fd = open_proc(pid, "status", O_RDONLY);
    char buffer[16384]; MUST(fd >= 0); read_text(fd, buffer, sizeof(buffer)); close(fd);
    char *position = status_value(buffer, name); MUST(position != NULL);
    unsigned long value = status_number(&position); status_end(position);
    MUST(value <= 2147483647UL); return (long)value;
}
static int ids_match(pid_t pid, const char *name, unsigned expected) {
    int fd = open_proc(pid, "status", O_RDONLY); char buffer[16384];
    MUST(fd >= 0); read_text(fd, buffer, sizeof(buffer)); close(fd);
    char *position = status_value(buffer, name); MUST(position != NULL);
    int matches = 1;
    for (unsigned i = 0; i < 4; i++) if (status_number(&position) != expected) matches = 0;
    status_end(position); return matches;
}
static int groups_match(pid_t pid, int socket) {
    unsigned groups[256]; socklen_t size = sizeof(groups);
    if (getsockopt(socket, SOL_SOCKET, SO_PEERGROUPS, groups, &size) != 0 || size % sizeof(unsigned)) return 0;
    int fd = open_proc(pid, "status", O_RDONLY); char buffer[16384];
    MUST(fd >= 0); read_text(fd, buffer, sizeof(buffer)); close(fd);
    char *position = status_value(buffer, "Groups:"); MUST(position != NULL);
    unsigned count = 0;
    while (*position && *position != '\n') {
        if (*position == ' ' || *position == '\t') { position++; continue; }
        unsigned long group = status_number(&position);
        if (count >= size / sizeof(unsigned) || group != groups[count++]) return 0;
    }
    return count == size / sizeof(unsigned);
}
static struct ucred credentials(int socket, int *pidfd) {
    struct ucred peer; socklen_t size = sizeof(peer);
    MUST(getsockopt(socket, SOL_SOCKET, SO_PEERCRED, &peer, &size) == 0 && size == sizeof(peer) && peer.pid > 0);
    size = sizeof(*pidfd);
    MUST(getsockopt(socket, SOL_SOCKET, SO_PEERPIDFD, pidfd, &size) == 0 && size == sizeof(*pidfd) && *pidfd >= 0);
    MUST(fcntl(*pidfd, F_SETFD, FD_CLOEXEC) == 0);
    MUST(syscall(SYS_pidfd_send_signal, *pidfd, 0, NULL, 0) == 0);
    return peer;
}
struct target {
    pid_t pid, wrapper;
    int pidfd, procfd, root, cwd, ns[8], owner[8];
    struct ucred peer;
    char uid_map[4096], gid_map[4096], setgroups[32];
    int mutator;
    char connector_label[4096];
    unsigned groups[256]; socklen_t groups_size;
};

static void stopped(pid_t pid) {
    int status;
    MUST(waitpid(pid, &status, __WALL) == pid && WIFSTOPPED(status));
}
static int live(int pidfd) {
    struct pollfd descriptor = {.fd = pidfd, .events = POLLIN};
    return poll(&descriptor, 1, 0) == 0
        && syscall(SYS_pidfd_send_signal, pidfd, 0, NULL, 0) == 0;
}
static int capture_private_fs(struct target *target, int socket) {
    unsigned long options = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC
        | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK;
    MUST(ptrace(PTRACE_SEIZE, target->pid, 0, options) == 0);
    MUST(ptrace(PTRACE_INTERRUPT, target->pid, 0, 0) == 0);
    stopped(target->pid);
    if (!live(target->pidfd)) {
        MUST(ptrace(PTRACE_DETACH, target->pid, 0, 0) == 0);
        return 0;
    }
    MUST(ptrace(PTRACE_SETOPTIONS, target->pid, 0, options | PTRACE_O_EXITKILL) == 0);
    if (!live(target->pidfd)) return 0;
    if (field(target->pid, "Threads:") != 1 || field(target->pid, "Seccomp:") != 0) return 0;
    if (!ids_match(target->pid, "Uid:", target->peer.uid) || !ids_match(target->pid, "Gid:", target->peer.gid)
        || !groups_match(target->pid, socket)) return 0;
    MUST(write(socket, "G", 1) == 1);
    int entered = 0;
    for (int step = 0; step < 8; step++) {
        MUST(ptrace(PTRACE_SYSCALL, target->pid, 0, 0) == 0);
        int status; MUST(waitpid(target->pid, &status, __WALL) == target->pid);
        if (!live(target->pidfd)) return 0;
        if (!WIFSTOPPED(status) || WSTOPSIG(status) != (SIGTRAP | 0x80) || (status >> 16) != 0) return 0;
        struct ptrace_syscall_info info = {0};
        MUST(ptrace(PTRACE_GET_SYSCALL_INFO, target->pid, sizeof(info), &info) > 0);
        if (info.op == PTRACE_SYSCALL_INFO_ENTRY) {
            if (info.entry.nr == SYS_read && !entered) continue;
            if (info.entry.nr != SYS_unshare || entered || info.arch != AUDIT_ARCH_X86_64) return 0;
#if defined(__x86_64__)
            struct user_regs_struct registers;
            MUST(ptrace(PTRACE_GETREGS, target->pid, 0, &registers) == 0);
            registers.rdi = CLONE_FS | CLONE_FILES;
            MUST(ptrace(PTRACE_SETREGS, target->pid, 0, &registers) == 0);
#else
            return 0;
#endif
            entered = 1;
        } else if (info.op == PTRACE_SYSCALL_INFO_EXIT && entered) {
            if (info.exit.is_error || info.exit.rval != 0) return 0;
            return 1; /* Leave the task stopped at this exact syscall exit. */
        }
    }
    return 0;
}

static void pin(struct target *target) {
    target->procfd = open_proc(target->pid, "", O_PATH | O_DIRECTORY); MUST(target->procfd >= 0);
    target->root = openat(target->procfd, "root", O_PATH | O_DIRECTORY | O_CLOEXEC);
    target->cwd = openat(target->procfd, "cwd", O_PATH | O_DIRECTORY | O_CLOEXEC);
    /* CLONE_FS was detached at the captured syscall exit. Root and cwd are
     * coherent retained observations and may name different directories. Job
     * cwd is independently resolved beneath the pinned root during preparation. */
    MUST(target->root >= 0 && target->cwd >= 0);
    for (size_t i = 0; i < COUNT(names); i++) {
        char name[64]; snprintf(name, sizeof(name), "ns/%s", names[i]);
        target->ns[i] = openat(target->procfd, name, O_RDONLY | O_CLOEXEC); MUST(target->ns[i] >= 0);
        target->owner[i] = ioctl(target->ns[i], NS_GET_USERNS);
        if (target->owner[i] < 0 && i == 6) target->owner[i] = dup(target->ns[i]);
        MUST(target->owner[i] >= 0);
    }
    int initial = open("/proc/self/ns/user", O_RDONLY | O_CLOEXEC); MUST(initial >= 0);
    if (!same(initial, target->ns[6])) {
        int parent = ioctl(target->ns[6], NS_GET_PARENT); MUST(parent >= 0 && same(parent, initial)); close(parent);
    }
    close(initial);
    for (size_t i = 0; i < COUNT(names); i++) if (i != 6) MUST(same(target->owner[i], target->ns[6]));
    MUST(live(target->pidfd));
    MUST(field(target->pid, "Threads:") == 1 && field(target->pid, "Seccomp:") == 0);
    const char *files[] = {"uid_map", "gid_map", "setgroups"};
    char *buffers[] = {target->uid_map, target->gid_map, target->setgroups};
    size_t sizes[] = {sizeof(target->uid_map), sizeof(target->gid_map), sizeof(target->setgroups)};
    for (size_t i = 0; i < COUNT(files); i++) {
        int fd = openat(target->procfd, files[i], O_RDONLY | O_CLOEXEC); MUST(fd >= 0);
        read_text(fd, buffers[i], sizes[i]); close(fd);
    }
}
static void revalidate(struct target *target) {
    MUST(live(target->pidfd));
    MUST(field(target->pid, "TracerPid:") == getpid() && field(target->pid, "Threads:") == 1 && field(target->pid, "Seccomp:") == 0);
    MUST(ids_match(target->pid, "Uid:", target->peer.uid) && ids_match(target->pid, "Gid:", target->peer.gid));
    for (size_t i = 0; i < COUNT(names); i++) {
        char path[64]; snprintf(path, sizeof(path), "ns/%s", names[i]);
        int fd = openat(target->procfd, path, O_RDONLY | O_CLOEXEC); MUST(fd >= 0 && same(fd, target->ns[i])); close(fd);
    }
    const char *files[] = {"uid_map", "gid_map", "setgroups"};
    char *expected[] = {target->uid_map, target->gid_map, target->setgroups};
    for (size_t i = 0; i < COUNT(files); i++) {
        char buffer[4096]; int fd = openat(target->procfd, files[i], O_RDONLY | O_CLOEXEC); MUST(fd >= 0);
        read_text(fd, buffer, sizeof(buffer)); close(fd); MUST(!strcmp(buffer, expected[i]));
    }
    int fd = openat(target->procfd, "root", O_PATH | O_CLOEXEC); MUST(fd >= 0 && same_fs(fd, target->root)); close(fd);
}
static void json_string(const char *value) {
    putchar('"');
    for (const unsigned char *p = (const unsigned char *)value; *p; p++) {
        if (*p == '"' || *p == '\\') printf("\\%c", *p);
        else if (*p < 32) printf("\\u%04x", *p);
        else putchar(*p);
    }
    putchar('"');
}
static void print_fs(int fd) {
    struct stat st; struct statx sx;
    MUST(fstat(fd, &st) == 0 && statx(fd, "", AT_EMPTY_PATH, STATX_INO | STATX_MNT_ID, &sx) == 0 && (sx.stx_mask & STATX_MNT_ID));
    printf("{\"device\":\"%llu\",\"inode\":\"%llu\",\"mount_id\":\"%llu\"}",
        (unsigned long long)st.st_dev, (unsigned long long)st.st_ino, (unsigned long long)sx.stx_mnt_id);
}
static void print_map(const char *text) {
    putchar('['); int comma = 0;
    for (const char *p = text; *p;) {
        unsigned inside, outside, count; int used;
        MUST(sscanf(p, "%u %u %u%n", &inside, &outside, &count, &used) == 3);
        if (comma++) putchar(',');
        printf("{\"inside\":%u,\"outside\":%u,\"count\":%u}", inside, outside, count);
        p += used; while (*p == '\n' || *p == ' ' || *p == '\t') p++;
    }
    putchar(']');
}
static void print_acquisition(struct target *target) {
    revalidate(target);
    const char *epoch = getenv("SIGRUND_DAEMON_EPOCH"), *instance = getenv("SIGRUND_TARGET_INSTANCE"); MUST(epoch && instance);
    int fd = open_proc(target->pid, "stat", O_RDONLY); char stattext[4096]; MUST(fd >= 0); read_text(fd, stattext, sizeof(stattext)); close(fd);
    char *ticks = strrchr(stattext, ')'); MUST(ticks != NULL); ticks += 2;
    for (int field = 3; field < 22; field++) { ticks = strchr(ticks, ' '); MUST(ticks != NULL); ticks++; }
    unsigned long long start = strtoull(ticks, NULL, 10);
    fd = open("/proc/sys/kernel/random/boot_id", O_RDONLY | O_CLOEXEC); char boot[64]; MUST(fd >= 0); read_text(fd, boot, sizeof(boot)); close(fd); boot[strcspn(boot, "\n")] = 0;
    printf("{\"schema\":\"sigrund.acquisition.phase0.v1\",\"daemon_epoch\":"); json_string(epoch);
    printf(",\"instance_id\":"); json_string(instance);
    printf(",\"pid\":%d,\"start_ticks\":\"%llu\",\"boot_id\":", target->pid, start); json_string(boot);
    int attr = openat(target->procfd, "attr/current", O_RDONLY | O_CLOEXEC); char label[4096];
    MUST(attr >= 0); read_text(attr, label, sizeof(label)); close(attr); label[strcspn(label, "\n")] = 0;
    printf(",\"capture\":\"traced_private_fs_v1\",\"anchor\":{\"host_uid\":%u,\"host_gid\":%u,\"host_groups\":[", target->peer.uid, target->peer.gid);
    for (unsigned i = 0; i < target->groups_size / sizeof(unsigned); i++) printf("%s%u", i ? "," : "", target->groups[i]);
    printf("],\"connector_label\":");
    if (target->connector_label[0]) json_string(target->connector_label); else printf("null");
    printf(",\"process_label\":"); json_string(label);
    printf(",\"no_new_privs\":%s,\"seccomp\":0},\"namespaces\":{", field(target->pid, "NoNewPrivs:") ? "true" : "false");
    for (size_t i = 0; i < COUNT(names); i++) {
        struct stat ns, owner; MUST(fstat(target->ns[i], &ns) == 0 && fstat(target->owner[i], &owner) == 0);
        if (i) putchar(',');
        json_string(names[i]);
        printf(":{\"device\":\"%llu\",\"inode\":\"%llu\",\"owner_userns_device\":\"%llu\",\"owner_userns_inode\":\"%llu\"}",
            (unsigned long long)ns.st_dev, (unsigned long long)ns.st_ino, (unsigned long long)owner.st_dev, (unsigned long long)owner.st_ino);
    }
    printf("},\"root\":"); print_fs(target->root); printf(",\"cwd\":"); print_fs(target->cwd);
    struct stat user; MUST(fstat(target->ns[6], &user) == 0);
    printf(",\"mappings\":[{\"userns_inode\":\"%llu\",\"uid\":", (unsigned long long)user.st_ino); print_map(target->uid_map);
    printf(",\"gid\":"); print_map(target->gid_map);
    target->setgroups[strcspn(target->setgroups, "\n")] = 0;
    printf(",\"setgroups\":"); json_string(target->setgroups);
    printf("}],\"lifecycle\":{\"anchor_required\":true,\"registration_id\":null,\"registration_revision\":null,\"resolver\":null}}");
}

void *sigrund_capture_begin(int socket, int expected_pid, unsigned expected_uid) {
    struct target *target = calloc(1, sizeof(*target)); MUST(target);
    target->peer = credentials(socket, &target->pidfd);
    target->pid = target->peer.pid;
    MUST(target->pid == expected_pid && target->peer.uid == expected_uid);
    target->groups_size = sizeof(target->groups);
    MUST(getsockopt(socket, SOL_SOCKET, SO_PEERGROUPS, target->groups, &target->groups_size) == 0
        && target->groups_size % sizeof(unsigned) == 0);
    socklen_t label_size = sizeof(target->connector_label) - 1;
    int result = getsockopt(socket, SOL_SOCKET, SO_PEERSEC, target->connector_label, &label_size);
    MUST(result == 0 || errno == ENOPROTOOPT);
    if (result == 0) target->connector_label[label_size] = 0;
    char byte;
    for (;;) {
        ssize_t count = read(socket, &byte, 1);
        if (count == 1) { MUST(byte == 'H'); break; }
        if (count < 0 && errno == EINTR) continue;
        MUST(count < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
        struct pollfd pending = {.fd = socket, .events = POLLIN};
        int ready = poll(&pending, 1, 100);
        MUST(ready >= 0 || errno == EINTR);
    }
    MUST(capture_private_fs(target, socket));
    pin(target);
    return target;
}
void sigrund_capture_print(void *pointer) {
    struct target *target = pointer;
    char setgroups[sizeof(target->setgroups)];
    memcpy(setgroups, target->setgroups, sizeof(setgroups));
    print_acquisition(target); putchar('\n'); fflush(stdout);
    memcpy(target->setgroups, setgroups, sizeof(setgroups));
}
void sigrund_capture_check(void *pointer) { revalidate(pointer); }
int sigrund_capture_root(void *pointer) { return ((struct target *)pointer)->root; }
int sigrund_capture_namespace(void *pointer, unsigned index) {
    MUST(index < COUNT(names));
    return ((struct target *)pointer)->ns[index];
}

void sigrund_capture_dispose(void *pointer) {
    struct target *target = pointer;
    if (live(target->pidfd)) {
        MUST(syscall(SYS_pidfd_send_signal, target->pidfd, SIGKILL, NULL, 0) == 0);
    }
    int status;
    while (waitpid(target->pid, &status, __WALL) < 0) MUST(errno == EINTR);
    close(target->pidfd); close(target->procfd); close(target->root); close(target->cwd);
    for (size_t i = 0; i < COUNT(names); i++) {
        close(target->ns[i]); close(target->owner[i]);
    }
    free(target);
}
