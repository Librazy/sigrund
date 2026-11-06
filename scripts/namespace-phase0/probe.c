/* Phase 0 experiment only. Never linked into sigrund. Run on a disposable host.
 * Namespace transitions below use pre-opened FDs and resident trusted code.
 * The host supervisor never calls setns/unshare/chroot.
 */
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
static int error_fd = -1, setup_stage, fault_stage;
static unsigned last_cap;
static const char *execution_context;
static int namespace_memfd;
static pid_t observed_child;
enum { POLICY_NORMAL, POLICY_RELOAD, POLICY_DOMAIN_PERMISSIVE, POLICY_GLOBAL_PERMISSIVE };
static int policy_mode, policy_rejected;
struct selinux_page { uint32_t version, sequence, enforcing, policyload, deny_unknown; };
static struct selinux_page status_page(void);
static int domain_enforcing(const char *context);
static int policy_matches(struct selinux_page before, const char *context, struct selinux_page *after);
static int memfd_copy(const char *path);
static void fail(const char *expr, int line) {
    if (error_fd >= 0) {
        const struct { uint32_t stage; int32_t error; } frame = {setup_stage, errno > 0 ? errno : EIO};
        dprintf(2, "probe:%d: setup stage %u: %s: %s\n", line, frame.stage, expr, strerror(frame.error));
        syscall(SYS_write, error_fd, &frame, sizeof(frame));
        syscall(SYS_exit_group, 127); __builtin_unreachable();
    }
    fprintf(stderr, "probe:%d: %s: %s\n", line, expr, strerror(errno));
    exit(1);
}
#define MUST(x) do { if (!(x)) fail(#x, __LINE__); } while (0)
static void stage(int step) { setup_stage = step; if (fault_stage == step) { errno = EIO; fail("injected setup fault", 0); } }
static int same(int a, int b) {
    struct stat x, y;
    return fstat(a, &x) == 0 && fstat(b, &y) == 0 && x.st_dev == y.st_dev && x.st_ino == y.st_ino;
}
static int open_proc(pid_t pid, const char *name, int flags) {
    char path[128];
    MUST(snprintf(path, sizeof(path), "/proc/%d/%s", pid, name) < (int)sizeof(path));
    return open(path, flags | O_CLOEXEC);
}
static int write_path(const char *path, const char *value) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    size_t size = strlen(value);
    int result = write(fd, value, size) == (ssize_t)size ? 0 : -1;
    int error = errno;
    close(fd); errno = error; return result;
}
static void write_proc(pid_t pid, const char *name, const char *value) {
    char path[128];
    snprintf(path, sizeof(path), "/proc/%d/%s", pid, name);
    MUST(write_path(path, value) == 0);
}
static void read_text(int fd, char *buffer, size_t capacity) {
    ssize_t size = pread(fd, buffer, capacity - 1, 0);
    MUST(size > 0 && (size_t)size < capacity - 1);
    buffer[size] = 0;
}
static long field(pid_t pid, const char *name) {
    int fd = open_proc(pid, "status", O_RDONLY);
    char buffer[16384]; MUST(fd >= 0); read_text(fd, buffer, sizeof(buffer)); close(fd);
    char *position = strstr(buffer, name); MUST(position != NULL);
    return strtol(position + strlen(name), NULL, 10);
}
static int ids_match(pid_t pid, const char *name, unsigned expected) {
    int fd = open_proc(pid, "status", O_RDONLY); char buffer[16384];
    MUST(fd >= 0); read_text(fd, buffer, sizeof(buffer)); close(fd);
    char *position = strstr(buffer, name); MUST(position != NULL);
    unsigned a, b, c, d;
    return sscanf(position + strlen(name), "%u %u %u %u", &a, &b, &c, &d) == 4
        && a == expected && b == expected && c == expected && d == expected;
}
static int groups_match(pid_t pid, int socket) {
    unsigned groups[256]; socklen_t size = sizeof(groups);
    if (getsockopt(socket, SOL_SOCKET, SO_PEERGROUPS, groups, &size) != 0 || size % sizeof(unsigned)) return 0;
    int fd = open_proc(pid, "status", O_RDONLY); char buffer[16384];
    MUST(fd >= 0); read_text(fd, buffer, sizeof(buffer)); close(fd);
    char *position = strstr(buffer, "Groups:"); MUST(position != NULL); position += 7;
    unsigned count = 0;
    while (*position && *position != '\n') {
        if (*position == ' ' || *position == '\t') { position++; continue; }
        char *end; unsigned long group = strtoul(position, &end, 10);
        if (end == position || count >= size / sizeof(unsigned) || group != groups[count++]) return 0;
        position = end;
    }
    return count == size / sizeof(unsigned);
}
static int socket_listener(const char *path) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    MUST(strlen(path) < sizeof(address.sun_path)); strcpy(address.sun_path, path);
    MUST(fd >= 0 && bind(fd, (void *)&address, sizeof(address)) == 0 && listen(fd, 8) == 0);
    MUST(chmod(path, 0777) == 0);
    return fd;
}
static int connect_to(const char *path) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    MUST(strlen(path) < sizeof(address.sun_path)); strcpy(address.sun_path, path);
    MUST(fd >= 0 && connect(fd, (void *)&address, sizeof(address)) == 0);
    return fd;
}
static void send_fd(int socket, int fd, pid_t pid) {
    char control[CMSG_SPACE(sizeof(int))] = {0};
    struct iovec io = {.iov_base = &pid, .iov_len = sizeof(pid)};
    struct msghdr message = {.msg_iov = &io, .msg_iovlen = 1, .msg_control = control, .msg_controllen = sizeof(control)};
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level = SOL_SOCKET; header->cmsg_type = SCM_RIGHTS; header->cmsg_len = CMSG_LEN(sizeof(int));
    memcpy(CMSG_DATA(header), &fd, sizeof(fd));
    MUST(sendmsg(socket, &message, MSG_NOSIGNAL) == sizeof(pid));
}
static int recv_fd(int socket, pid_t *pid) {
    char control[CMSG_SPACE(sizeof(int))] = {0};
    struct iovec io = {.iov_base = pid, .iov_len = sizeof(*pid)};
    struct msghdr message = {.msg_iov = &io, .msg_iovlen = 1, .msg_control = control, .msg_controllen = sizeof(control)};
    MUST(recvmsg(socket, &message, MSG_CMSG_CLOEXEC | MSG_WAITALL) == sizeof(*pid));
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    MUST(!(message.msg_flags & (MSG_CTRUNC | MSG_TRUNC)) && header != NULL
        && header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_RIGHTS
        && header->cmsg_len == CMSG_LEN(sizeof(int)) && CMSG_NXTHDR(&message, header) == NULL);
    int fd; memcpy(&fd, CMSG_DATA(header), sizeof(fd)); MUST(fd >= 0); return fd;
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
static void peer_case(const char *path) {
    int listener = socket_listener(path), pass[2], proceed[2];
    MUST(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pass) == 0 && pipe2(proceed, O_CLOEXEC) == 0);
    pid_t child = fork(); MUST(child >= 0);
    if (child == 0) {
        close(pass[0]); close(proceed[1]);
        int fd = connect_to(path); send_fd(pass[1], fd, getpid()); close(fd);
        char byte; MUST(read(proceed[0], &byte, 1) == 1); _exit(0);
    }
    close(pass[1]); close(proceed[0]);
    int connected = accept4(listener, NULL, NULL, SOCK_CLOEXEC), pidfd;
    struct ucred peer = credentials(connected, &pidfd); MUST(peer.pid == child);
    pid_t claimed; int passed = recv_fd(pass[0], &claimed); MUST(claimed == child);
    MUST(write(passed, "P", 1) == 1); char byte; MUST(read(connected, &byte, 1) == 1 && byte == 'P');
    int duplicate_pidfd;
    struct ucred after = credentials(connected, &duplicate_pidfd); close(duplicate_pidfd);
    MUST(after.pid == child && after.pid != getpid());
    MUST(write(proceed[1], "x", 1) == 1); int status; MUST(waitpid(child, &status, 0) == child && status == 0);
    struct pollfd poller = {.fd = pidfd, .events = POLLIN}; MUST(poll(&poller, 1, 1000) == 1);
    MUST(write(passed, "E", 1) == 1 && read(connected, &byte, 1) == 1 && byte == 'E');
    errno = 0; MUST(syscall(SYS_pidfd_send_signal, pidfd, 0, NULL, 0) == -1 && errno == ESRCH);
    puts("{\"case\":\"peer\",\"result\":\"passed\",\"passed_socket_keeps_connector\":true,\"connector_exit_detected\":true,\"peerpidfd\":true}");
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
static int fd_count(void) {
    DIR *directory = opendir("/proc/self/fd"); MUST(directory != NULL);
    int count = 0; struct dirent *entry;
    while ((entry = readdir(directory))) if (entry->d_name[0] != '.') count++;
    closedir(directory); return count;
}
static void stopped(pid_t pid) {
    int status; MUST(waitpid(pid, &status, __WALL) == pid && WIFSTOPPED(status));
}
static void attach(pid_t pid) {
    MUST(ptrace(PTRACE_SEIZE, pid, 0, PTRACE_O_TRACESYSGOOD | PTRACE_O_EXITKILL | PTRACE_O_TRACEEXEC | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK) == 0);
    MUST(ptrace(PTRACE_INTERRUPT, pid, 0, 0) == 0); stopped(pid);
}
static int live(int pidfd) {
    struct pollfd descriptor = {.fd = pidfd, .events = POLLIN};
    int result = poll(&descriptor, 1, 0);
    return result == 0 && syscall(SYS_pidfd_send_signal, pidfd, 0, NULL, 0) == 0;
}
/* The anchor cannot execute another syscall once its private fs snapshot exists.
 * Reject seccomp: a USER_NOTIF/TRACE filter could forge unshare's success.
 * Force/check the actual syscall at the kernel entry stop, not a client claim.
 */
static int freeze_private_fs(struct target *target, int socket) {
    attach(target->pid);
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
            struct user_regs_struct registers;
            MUST(ptrace(PTRACE_GETREGS, target->pid, 0, &registers) == 0);
            registers.rdi = CLONE_FS | CLONE_FILES;
            MUST(ptrace(PTRACE_SETREGS, target->pid, 0, &registers) == 0);
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
    MUST(target->root >= 0 && target->cwd >= 0 && same(target->root, target->cwd));
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
    int fd = openat(target->procfd, "root", O_PATH | O_CLOEXEC); MUST(fd >= 0 && same(fd, target->root)); close(fd);
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
    const char *epoch = getenv("PHASE0_DAEMON_EPOCH"), *instance = getenv("PHASE0_TARGET_INSTANCE"); MUST(epoch && instance);
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
static void deny_getppid(void) {
    struct sock_filter code[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JGE | BPF_K, 0x40000000, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_getppid, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | EACCES),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {.len = COUNT(code), .filter = code};
    MUST(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
    MUST(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1);
    MUST(syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program) == 0);
}
static void *idle_thread(void *unused) { (void)unused; for (;;) pause(); return NULL; }
static int shared_fs_mutator(void *argument) {
    int socket = *(int *)argument;
    int old_root = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC); MUST(old_root >= 0);
    char command; MUST(read(socket, &command, 1) == 1 && command == 'M');
    MUST(chdir("/alternate") == 0 && chroot(".") == 0 && chdir("/") == 0);
    MUST(write(socket, "R", 1) == 1);
    MUST(read(socket, &command, 1) == 1 && command == 'M');
    MUST(fchdir(old_root) == 0 && chroot(".") == 0 && chdir("/") == 0);
    MUST(write(socket, "R", 1) == 1);
    for (;;) pause();
    return 0;
}
static void anchor(const char *socket_path, int filtered) {
    if (filtered == 1) deny_getppid();
    if (filtered == 2) { pthread_t thread; MUST(pthread_create(&thread, NULL, idle_thread, NULL) == 0); }
    int socket = connect_to(socket_path);
    int mutator[2] = {-1, -1}; pid_t sibling = 0;
    if (filtered == 5) {
        MUST(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, mutator) == 0);
        void *stack = malloc(65536); MUST(stack != NULL);
        sibling = clone(shared_fs_mutator, (char *)stack + 65536, CLONE_FS | SIGCHLD, &mutator[1]); MUST(sibling > 0);
    }
    if (filtered == 3) MUST(setresgid(1001, 1001, 1001) == 0 && setresuid(1001, 1001, 1001) == 0);
    MUST(write(socket, "H", 1) == 1); char byte;
    if (filtered == 5) { send_fd(socket, mutator[0], sibling); close(mutator[0]); close(mutator[1]); MUST(write(socket, "Q", 1) == 1); }
    MUST(read(socket, &byte, 1) == 1);
    if (filtered == 4) syscall(SYS_execve, "/does-not-exist", NULL, NULL);
    syscall(SYS_unshare, CLONE_FS | CLONE_FILES);
    _exit(90); /* The supervisor must never release this syscall exit. */
}
static void container(const char *root, int ready, int go, int rootless, int filtered) {
    MUST(setgroups(0, NULL) == 0);
    if (rootless < 0) {
        char path[108]; MUST(snprintf(path, sizeof(path), "%s/run/client.sock", root) < (int)sizeof(path));
        MUST(chdir("/") == 0 && setresgid(1000, 1000, 1000) == 0 && setresuid(1000, 1000, 1000) == 0);
        anchor(path, filtered); _exit(1);
    }
    if (rootless > 0) {
        MUST(setresgid(1000, 1000, 1000) == 0 && setresuid(1000, 1000, 1000) == 0);
        MUST(unshare(CLONE_NEWUSER) == 0);
        MUST(write(ready, "M", 1) == 1); char byte; MUST(read(go, &byte, 1) == 1);
    }
    MUST(unshare(CLONE_NEWNS | CLONE_NEWCGROUP | CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWUTS) == 0);
    MUST(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == 0);
    MUST(mount(root, root, NULL, MS_BIND, NULL) == 0);
    MUST(unshare(CLONE_NEWPID | CLONE_NEWTIME) == 0);
    pid_t child = fork(); MUST(child >= 0);
    if (child != 0) { int status; MUST(waitpid(child, &status, 0) == child); _exit(0); }
    MUST(chdir(root) == 0 && chroot(".") == 0 && chdir("/") == 0);
    MUST(mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) == 0);
    if (rootless == 0 && filtered != 3 && filtered != 5) MUST(setresgid(1000, 1000, 1000) == 0 && setresuid(1000, 1000, 1000) == 0);
    anchor("/run/client.sock", filtered);
}
static struct target acquire(const char *root, const char *socket_path, int rootless, int filtered, int *accepted) {
    int listener = socket_listener(socket_path), ready[2], go[2];
    MUST(pipe2(ready, O_CLOEXEC) == 0 && pipe2(go, O_CLOEXEC) == 0);
    pid_t child = fork(); MUST(child >= 0);
    if (child == 0) { close(ready[0]); close(go[1]); container(root, ready[1], go[0], rootless, filtered); _exit(1); }
    close(ready[1]); close(go[0]);
    if (rootless > 0) {
        char byte; MUST(read(ready[0], &byte, 1) == 1 && byte == 'M');
        write_proc(child, "setgroups", "deny");
        write_proc(child, "uid_map", "0 1000 1\n1 100000 65535\n");
        write_proc(child, "gid_map", "0 1000 1\n1 100000 65535\n");
        MUST(write(go[1], "G", 1) == 1);
    }
    close(ready[0]); close(go[1]);
    int socket = accept4(listener, NULL, NULL, SOCK_CLOEXEC); MUST(socket >= 0);
    struct target target = {.wrapper = child, .mutator = -1}; target.peer = credentials(socket, &target.pidfd); target.pid = target.peer.pid;
    target.groups_size = sizeof(target.groups);
    MUST(getsockopt(socket, SOL_SOCKET, SO_PEERGROUPS, target.groups, &target.groups_size) == 0 && target.groups_size % sizeof(unsigned) == 0);
    socklen_t label_size = sizeof(target.connector_label) - 1;
    int label_result = getsockopt(socket, SOL_SOCKET, SO_PEERSEC, target.connector_label, &label_size);
    MUST(label_result == 0 || errno == ENOPROTOOPT);
    if (label_result == 0) target.connector_label[label_size] = 0;
    char byte; MUST(read(socket, &byte, 1) == 1 && byte == 'H');
    pid_t sibling = 0;
    if (filtered == 5) {
        pid_t ignored; target.mutator = recv_fd(socket, &ignored);
        MUST(read(socket, &byte, 1) == 1 && byte == 'Q');
        char path[128]; snprintf(path, sizeof(path), "task/%d/children", target.pid);
        int fd = open_proc(target.pid, path, O_RDONLY); char children[256]; MUST(fd >= 0); read_text(fd, children, sizeof(children)); close(fd);
        sibling = strtol(children, NULL, 10); MUST(sibling > 0);
        MUST(syscall(SYS_kcmp, target.pid, sibling, KCMP_FS, 0, 0) == 0);
    }
    MUST(target.peer.uid == (unsigned)(rootless == 0 && (filtered == 3 || filtered == 5) ? 0 : 1000));
    *accepted = freeze_private_fs(&target, socket);
    if (*accepted) pin(&target);
    if (filtered == 5) {
        MUST(*accepted && syscall(SYS_kcmp, target.pid, sibling, KCMP_FS, 0, 0) > 0);
        for (int round = 0; round < 2; round++) {
            MUST(write(target.mutator, "M", 1) == 1 && read(target.mutator, &byte, 1) == 1 && byte == 'R');
            int fd = open_proc(sibling, "root", O_PATH | O_DIRECTORY); MUST(fd >= 0);
            MUST(same(fd, target.root) == (round == 1)); close(fd);
            revalidate(&target);
        }
    }
    close(socket); close(listener); unlink(socket_path); return target;
}
static void destroy_target(struct target *target, int pinned) {
    int killed = syscall(SYS_pidfd_send_signal, target->pidfd, SIGKILL, NULL, 0);
    MUST(killed == 0 || (killed == -1 && errno == ESRCH));
    int status;
    do { MUST(waitpid(target->pid, &status, __WALL) == target->pid); if (WIFSTOPPED(status)) ptrace(PTRACE_CONT, target->pid, 0, SIGKILL); } while (WIFSTOPPED(status));
    if (target->wrapper != target->pid) MUST(waitpid(target->wrapper, &status, 0) == target->wrapper);
    struct pollfd poller = {.fd = target->pidfd, .events = POLLIN}; MUST(poll(&poller, 1, 1000) == 1);
    if (pinned) {
        /* Retained namespace/root FDs still work, but cannot establish liveness. */
        struct stat st; MUST(fstat(target->root, &st) == 0);
        for (size_t i = 0; i < COUNT(names); i++) { close(target->ns[i]); close(target->owner[i]); }
        close(target->root); close(target->cwd); close(target->procfd);
    }
    close(target->pidfd);
    if (target->mutator >= 0) close(target->mutator);
}
static void drop_identity(void) {
    stage(6);
    MUST(prctl(PR_SET_SECUREBITS, 15, 0, 0, 0) == 0);
    for (unsigned cap = 0; cap <= last_cap; cap++) MUST(prctl(PR_CAPBSET_DROP, cap, 0, 0, 0) == 0);
    MUST(setresgid(1001, 1001, 1001) == 0 && setresuid(1001, 1001, 1001) == 0);
    struct __user_cap_header_struct header = {.version = _LINUX_CAPABILITY_VERSION_3};
    struct __user_cap_data_struct data[2] = {{0}, {0}};
    MUST(syscall(SYS_capset, &header, data) == 0);
    MUST(prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0) == 0);
    MUST(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
    MUST(prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) == 1 && prctl(PR_GET_SECUREBITS, 0, 0, 0, 0) == 15);
}
static void join_target(const struct target *target) {
    stage(2);
    MUST(unshare(CLONE_FS | CLONE_FILES) == 0 && setgroups(0, NULL) == 0);
    /* user first, then resources owned by that userns. Never ignore setns errors. */
    const unsigned order[] = {6, 0, 1, 2, 3, 7, 5, 4};
    for (size_t n = 0; n < COUNT(order); n++) {
        if (n == 1) stage(3);
        unsigned i = order[n];
        char path[64]; snprintf(path, sizeof(path), "/proc/self/ns/%s", names[i]);
        int current = open(path, O_RDONLY | O_CLOEXEC); MUST(current >= 0);
        int shared = same(current, target->ns[i]); close(current);
        if (!shared) MUST(setns(target->ns[i], 0) == 0);
    }
    stage(4);
    /* setns(user) grants capabilities but preserves the old kernel IDs. Host
     * root is unmapped in the rootless profile: select that userns's mapped
     * root IDs before creating files (otherwise inode creation is EOVERFLOW).
     * These are trusted launcher credentials; the final child drops to 1001. */
    MUST(setresgid(0, 0, 0) == 0 && setresuid(0, 0, 0) == 0);
    /* This FD belongs to the target's original mount tree. Establish root
     * first, so unshare remaps root/cwd into the cloned tree. Reusing the old
     * FD after unshare would escape that private tree. */
    MUST(fchdir(target->root) == 0 && chroot(".") == 0 && chdir("/") == 0);
    MUST(unshare(CLONE_NEWNS | CLONE_NEWCGROUP) == 0);
    MUST(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == 0);
    /* A real private mount must survive final-child creation and exec, while
     * remaining absent from the pinned anchor's filesystem view. */
    MUST(mount("phase0-private", "/run", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=65536,mode=0755") == 0);
    int marker = open("/run/sigrund-phase0-private-mount", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0644);
    MUST(marker >= 0 && write(marker, "private-mount-tree\n", 19) == 19); close(marker);
}
static void verify_private_mount(int child_root, int anchor_root) {
    int marker = openat(child_root, "run/sigrund-phase0-private-mount", O_RDONLY | O_CLOEXEC);
    char contents[32]; MUST(marker >= 0 && read(marker, contents, sizeof(contents)) == 19 && !memcmp(contents, "private-mount-tree\n", 19)); close(marker);
    int private_run = openat(child_root, "run", O_PATH | O_DIRECTORY | O_CLOEXEC);
    int anchor_run = openat(anchor_root, "run", O_PATH | O_DIRECTORY | O_CLOEXEC);
    MUST(private_run >= 0 && anchor_run >= 0 && !same(private_run, anchor_run));
    close(private_run); close(anchor_run);
}
static void verify_child(pid_t pid, const struct target *target, int rootless) {
    MUST(ids_match(pid, "Uid:", rootless ? 101000 : 1001));
    MUST(ids_match(pid, "Gid:", rootless ? 101000 : 1001));
    MUST(field(pid, "NoNewPrivs:") == 1 && field(pid, "Threads:") == 1);
    int fd = open_proc(pid, "root", O_PATH | O_DIRECTORY); MUST(fd >= 0 && same(fd, target->root));
    verify_private_mount(fd, target->root); close(fd);
    for (size_t i = 0; i < COUNT(names); i++) {
        char name[64]; snprintf(name, sizeof(name), "ns/%s", names[i]);
        fd = open_proc(pid, name, O_RDONLY); MUST(fd >= 0);
        MUST(same(fd, target->ns[i]) == (i != 0 && i != 2)); close(fd);
    }
    fd = open_proc(pid, "status", O_RDONLY); char text[16384]; MUST(fd >= 0); read_text(fd, text, sizeof(text)); close(fd);
    MUST(strstr(text, "CapEff:\t0000000000000000") && strstr(text, "CapPrm:\t0000000000000000")
        && strstr(text, "CapBnd:\t0000000000000000") && strstr(text, "CapAmb:\t0000000000000000") && strstr(text, "CapInh:\t0000000000000000"));
    char *groups = strstr(text, "Groups:"); MUST(groups != NULL);
    groups += strlen("Groups:"); while (*groups == '\t' || *groups == ' ') groups++;
    MUST(*groups == '\n');
}
static void execution_case(struct target *target, const char *cgroup, const char *executable, int rootless, int inject) {
    struct selinux_page policy_before = {0}, policy_after = {0};
    if (execution_context) {
        policy_before = status_page();
        if (policy_mode == POLICY_GLOBAL_PERMISSIVE) {
            MUST(policy_before.enforcing == 0); policy_rejected = 1; return;
        }
        if (policy_mode == POLICY_DOMAIN_PERMISSIVE) {
            MUST(policy_before.enforcing == 1 && !domain_enforcing(execution_context)); policy_rejected = 1; return;
        }
        MUST(policy_matches(policy_before, execution_context, &policy_after));
    }
    revalidate(target);
    int cg = open(cgroup, O_RDONLY | O_DIRECTORY | O_CLOEXEC); MUST(cg >= 0);
    int ipc[2], gate[2], output[2], errors[2];
    MUST(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, ipc) == 0
        && pipe2(gate, O_CLOEXEC) == 0 && pipe2(output, O_CLOEXEC) == 0 && pipe2(errors, O_CLOEXEC) == 0);
    int exe = namespace_memfd ? memfd_copy(executable) : open(executable, O_RDONLY | O_CLOEXEC); MUST(exe >= 0);
    if (namespace_memfd) {
        const char label[] = "system_u:object_r:sigrund_phase0_exec_t:s0";
        MUST(fsetxattr(exe, "security.selinux", label, sizeof(label), 0) == 0);
    }
    int launcher_pidfd;
    struct clone_args args = {.flags = CLONE_PIDFD | CLONE_INTO_CGROUP, .pidfd = (uintptr_t)&launcher_pidfd, .cgroup = cg, .exit_signal = SIGCHLD};
    pid_t launcher = syscall(SYS_clone3, &args, sizeof(args)); MUST(launcher >= 0);
    if (launcher == 0) {
        error_fd = errors[1]; fault_stage = inject; close(errors[0]); stage(1);
        close(ipc[0]); close(gate[1]); close(output[0]);
        join_target(target);
        int child_pidfd;
        struct clone_args final = {.flags = CLONE_PIDFD, .pidfd = (uintptr_t)&child_pidfd, .exit_signal = SIGCHLD};
        pid_t child = syscall(SYS_clone3, &final, sizeof(final)); MUST(child >= 0);
        if (child == 0) {
            char byte; MUST(read(gate[0], &byte, 1) == 1 && byte == 'X');
            stage(5);
            MUST(dup2(output[1], 1) == 1);
            int kept = fcntl(exe, F_DUPFD_CLOEXEC, 5); MUST(kept >= 0);
            MUST(dup3(kept, 3, O_CLOEXEC) == 3);
            MUST(dup3(error_fd, 4, O_CLOEXEC) == 4 || (error_fd == 4 && errno == EINVAL)); error_fd = 4;
            MUST(syscall(SYS_close_range, 5U, ~0U, 0U) == 0);
            if (execution_context) MUST(write_path("/proc/self/attr/exec", execution_context) == 0);
            drop_identity(); stage(7);
            if (execution_context) deny_getppid();
            char *argv[] = {"namespace-probe", execution_context ? "/secret" : NULL, NULL}, *env[] = {NULL};
            syscall(SYS_execveat, 3, "", argv, env, AT_EMPTY_PATH); fail("execveat", 0);
        }
        send_fd(ipc[1], child_pidfd, child); close(child_pidfd); close(output[1]); close(gate[0]); close(errors[1]);
        int status; MUST(waitpid(child, &status, 0) == child);
        _exit(WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status));
    }
    close(errors[1]); close(ipc[1]); close(gate[0]); close(output[1]); close(exe); close(cg);
    pid_t child = 0; int child_pidfd = -1;
    if (inject == 0 || inject >= 5) {
        child_pidfd = recv_fd(ipc[0], &child);
        observed_child = child;
        MUST(child > 0 && syscall(SYS_pidfd_send_signal, child_pidfd, 0, NULL, 0) == 0);
    }
    if (inject >= 1 && inject <= 7) {
        if (inject >= 5) MUST(write(gate[1], "X", 1) == 1);
        close(gate[1]);
        int status; MUST(waitpid(launcher, &status, 0) == launcher && WIFEXITED(status) && WEXITSTATUS(status) == 127);
        struct { uint32_t stage; int32_t error; } frame;
        MUST(read(errors[0], &frame, sizeof(frame)) == sizeof(frame) && frame.stage == (unsigned)inject && frame.error == EIO);
        char byte; MUST(read(output[0], &byte, 1) == 0);
        close(errors[0]); close(output[0]); close(ipc[0]); close(launcher_pidfd); if (child_pidfd >= 0) close(child_pidfd); return;
    }
    attach(child); MUST(write(gate[1], "X", 1) == 1); close(gate[1]);
    MUST(ptrace(PTRACE_CONT, child, 0, 0) == 0);
    int status; MUST(waitpid(child, &status, __WALL) == child && WIFSTOPPED(status) && (status >> 16) == PTRACE_EVENT_EXEC);
    verify_child(child, target, rootless);
    if (execution_context) {
        int attr = open_proc(child, "attr/current", O_RDONLY); char actual[4096]; MUST(attr >= 0); read_text(attr, actual, sizeof(actual)); close(attr);
        actual[strcspn(actual, "\n")] = 0; MUST(!strcmp(actual, execution_context) && field(child, "Seccomp:") == 2);
    }
    revalidate(target);
    int fd = open_proc(child, "cgroup", O_RDONLY); char text[4096]; MUST(fd >= 0); read_text(fd, text, sizeof(text)); close(fd);
    const char *suffix = strstr(cgroup, "/sys/fs/cgroup"); MUST(suffix != NULL);
    MUST(strstr(text, suffix + strlen("/sys/fs/cgroup")) != NULL);
    if (execution_context) {
        if (policy_mode == POLICY_RELOAD) {
            puts("{\"ready\":\"policy-reload-at-exec-stop\"}"); fflush(stdout);
            char command; MUST(read(0, &command, 1) == 1 && command == 'R');
            revalidate(target);
        }
        /* Last check before release, in the host supervisor. Neither a
         * completed reload nor a permissive domain may release instructions. */
        if (!policy_matches(policy_before, execution_context, &policy_after)) policy_rejected = 2;
    }
    if (inject == 8 || inject == 9 || policy_rejected) {
        if (inject == 9) MUST(syscall(SYS_pidfd_send_signal, target->pidfd, SIGKILL, NULL, 0) == 0);
        int killed = syscall(SYS_pidfd_send_signal, child_pidfd, SIGKILL, NULL, 0);
        MUST(killed == 0 || (killed == -1 && errno == ESRCH));
        MUST(waitpid(child, &status, __WALL) == child && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    } else MUST(ptrace(PTRACE_DETACH, child, 0, 0) == 0);
    MUST(waitpid(launcher, &status, 0) == launcher && WIFEXITED(status)
        && WEXITSTATUS(status) == (inject >= 8 || policy_rejected ? 128 + SIGKILL : 0));
    struct pollfd poller = {.fd = child_pidfd, .events = POLLIN}; MUST(poll(&poller, 1, 1000) == 1);
    char result[128] = {0}; ssize_t size = read(output[0], result, sizeof(result));
    MUST(inject >= 8 || policy_rejected ? size == 0 : (execution_context ? (size == 27 && !memcmp(result, "selinux-and-seccomp-denied\n", 27))
        : (size == 23 && !memcmp(result, "namespace-workload-ran\n", 23))));
    close(errors[0]); close(output[0]); close(ipc[0]); close(child_pidfd); close(launcher_pidfd);
    if (policy_mode == POLICY_RELOAD) MUST(policy_rejected == 2 && policy_before.policyload != policy_after.policyload && policy_before.sequence != policy_after.sequence);
    else MUST(!policy_rejected);
}
static void namespace_case(const char *root, const char *socket, const char *cgroup, const char *exe, int rootless, int filtered, int inject) {
    int before_fds = fd_count();
    struct stat before[8];
    for (size_t i = 0; i < COUNT(names); i++) { char path[64]; snprintf(path, sizeof(path), "/proc/self/ns/%s", names[i]); MUST(stat(path, &before[i]) == 0); }
    int accepted;
    struct target target = acquire(root, socket, rootless, filtered, &accepted);
    if (filtered >= 1 && filtered <= 4) { MUST(!accepted); destroy_target(&target, 0); MUST(fd_count() == before_fds); printf("{\"case\":\"rejected-anchor-%d\",\"result\":\"passed\",\"rejected\":true,\"fd_leases_released\":true}\n", filtered); return; }
    MUST(accepted);
    execution_case(&target, cgroup, exe, rootless, inject);
    if (inject == 9) {
        struct pollfd poller = {.fd = target.pidfd, .events = POLLIN}; MUST(poll(&poller, 1, 1000) == 1);
        destroy_target(&target, 1); MUST(fd_count() == before_fds);
        puts("{\"case\":\"anchor-death-at-exec-stop\",\"result\":\"passed\",\"no_target_instructions\":true,\"no_retarget\":true,\"cleanup_complete\":true}"); return;
    }
    printf("{\"case\":\"%s%s\",\"result\":\"passed\",\"observed_target\":", rootless ? "rootless" : "rootful", inject ? "-setup-fault" : "");
    print_acquisition(&target);
    destroy_target(&target, 1);
    MUST(fd_count() == before_fds);
    for (size_t i = 0; i < COUNT(names); i++) { char path[64]; struct stat after; snprintf(path, sizeof(path), "/proc/self/ns/%s", names[i]); MUST(stat(path, &after) == 0 && before[i].st_ino == after.st_ino && before[i].st_dev == after.st_dev); }
    printf(",\"private_fs_capture\":true,\"held_at_syscall_exit\":true,\"host_pidfd\":true,\"coordinator_unchanged\":true,\"anchor_death_invalidates\":true,\"fd_leases_released\":true,\"fault_stage\":%d,\"workload_pid\":%d,\"private_mount_verified\":%s,\"policy_rejected_before_spawn\":%s,\"policy_rejected_at_exec_stop\":%s,\"no_workload_output\":%s}\n", inject, observed_child, observed_child && !inject ? "true" : "false", policy_rejected == 1 ? "true" : "false", policy_rejected == 2 ? "true" : "false", policy_rejected ? "true" : "false");
}
static void route_case(const char *root_a, const char *root_b, const char *cgroup, const char *exe, int rootless, int route) {
    int before_fds = fd_count();
    MUST(route >= 0 && route <= 3);
    char socket_a[108], socket_b[108];
    MUST(snprintf(socket_a, sizeof(socket_a), "%s/run/client.sock", root_a) < (int)sizeof(socket_a));
    MUST(snprintf(socket_b, sizeof(socket_b), "%s/run/client.sock", root_b) < (int)sizeof(socket_b));
    int accepted;
    struct target source = acquire(root_a, socket_a, route == 0 ? -1 : rootless, 0, &accepted); MUST(accepted);
    struct target destination;
    struct target *target;
    if (route == 2) target = &source;
    else {
        destination = acquire(root_b, socket_b, route == 1 ? -1 : rootless, 0, &accepted); MUST(accepted);
        target = &destination;
        MUST(!same(source.ns[2], target->ns[2]));
    }
    struct stat expected_root, actual_root;
    MUST(stat(route == 1 ? "/" : (route == 2 ? root_a : root_b), &expected_root) == 0);
    MUST(fstat(target->root, &actual_root) == 0 && expected_root.st_dev == actual_root.st_dev && expected_root.st_ino == actual_root.st_ino);
    execution_case(target, cgroup, exe, route == 1 ? 0 : rootless, 0);
    printf("{\"case\":\"route-%d-%s\",\"result\":\"passed\",\"observed_target\":", route, rootless ? "rootless" : "rootful");
    print_acquisition(target);
    if (target != &source) destroy_target(target, 1);
    destroy_target(&source, 1);
    MUST(fd_count() == before_fds);
    printf(",\"source_connector_captured\":true,\"destination_root_verified\":true,\"self_reuses_source_owner\":%s,\"fd_leases_released\":true}\n", route == 2 ? "true" : "false");
}
static void lifecycle_case(const char *cgroup, int exhaust) {
    int before_fds = fd_count();
    int cg = open(cgroup, O_RDONLY | O_DIRECTORY | O_CLOEXEC), ready[2];
    MUST(cg >= 0 && pipe2(ready, O_CLOEXEC) == 0);
    int launcher_pidfd;
    struct clone_args args = {.flags = CLONE_PIDFD | CLONE_INTO_CGROUP, .pidfd = (uintptr_t)&launcher_pidfd, .cgroup = cg, .exit_signal = SIGCHLD};
    pid_t launcher = syscall(SYS_clone3, &args, sizeof(args)); MUST(launcher >= 0);
    struct report { unsigned count; int exhausted; pid_t descendants[64]; } report = {0};
    if (launcher == 0) {
        close(ready[0]);
        for (unsigned i = 0; i < (exhaust ? 64U : 3U); i++) {
            pid_t child = fork();
            if (child == 0) { for (;;) pause(); }
            if (child < 0) { MUST(exhaust && errno == EAGAIN); report.exhausted = 1; break; }
            report.descendants[report.count++] = child;
        }
        MUST(write(ready[1], &report, sizeof(report)) == sizeof(report));
        for (;;) pause();
    }
    close(ready[1]); MUST(read(ready[0], &report, sizeof(report)) == sizeof(report)); close(ready[0]); close(cg);
    MUST(report.count > 0 && report.count <= 64 && report.exhausted == exhaust);
    int pidfds[64];
    for (unsigned i = 0; i < report.count; i++) { pidfds[i] = syscall(SYS_pidfd_open, report.descendants[i], 0); MUST(pidfds[i] >= 0); }
    MUST(syscall(SYS_pidfd_send_signal, launcher_pidfd, SIGKILL, NULL, 0) == 0);
    int status; MUST(waitpid(launcher, &status, 0) == launcher && WIFSIGNALED(status));
    for (unsigned i = 0; i < report.count; i++) {
        struct pollfd poller = {.fd = pidfds[i], .events = POLLIN}; MUST(poll(&poller, 1, 0) == 0);
    }
    char path[4096]; MUST(snprintf(path, sizeof(path), "%s/cgroup.kill", cgroup) < (int)sizeof(path));
    MUST(write_path(path, "1") == 0);
    for (unsigned i = 0; i < report.count; i++) {
        MUST(waitpid(-1, &status, 0) > 0 && WIFSIGNALED(status));
        struct pollfd poller = {.fd = pidfds[i], .events = POLLIN}; MUST(poll(&poller, 1, 1000) == 1); close(pidfds[i]);
    }
    errno = 0; MUST(waitpid(-1, &status, WNOHANG) == -1 && errno == ECHILD);
    close(launcher_pidfd); MUST(fd_count() == before_fds);
    printf("{\"case\":\"%s\",\"result\":\"passed\",\"descendants\":%u,\"launcher_death_does_not_finish_cleanup\":true,\"all_descendants_reaped\":true,\"fd_leases_released_after_reap\":true,\"pids_exhaustion_enforced\":%s}\n",
        exhaust ? "pids-exhaustion" : "launcher-death", report.count, exhaust ? "true" : "false");
}
static void tracer_death_case(const char *cgroup) {
    int before = fd_count(), ipc[2], gate[2];
    MUST(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, ipc) == 0 && pipe2(gate, O_CLOEXEC) == 0);
    int cg = open(cgroup, O_RDONLY | O_DIRECTORY | O_CLOEXEC); MUST(cg >= 0);
    int tracer_pidfd;
    struct clone_args args = {.flags = CLONE_PIDFD | CLONE_INTO_CGROUP, .pidfd = (uintptr_t)&tracer_pidfd, .cgroup = cg, .exit_signal = SIGCHLD};
    pid_t tracer = syscall(SYS_clone3, &args, sizeof(args)); MUST(tracer >= 0);
    if (tracer == 0) {
        close(ipc[0]); close(gate[1]);
        pid_t child = fork(); MUST(child >= 0);
        if (child == 0) { char byte; MUST(read(gate[0], &byte, 1) == 1); _exit(90); }
        attach(child);
        int child_pidfd = syscall(SYS_pidfd_open, child, 0); MUST(child_pidfd >= 0);
        send_fd(ipc[1], child_pidfd, child);
        for (;;) pause();
    }
    close(ipc[1]); close(gate[0]); close(cg);
    pid_t child; int child_pidfd = recv_fd(ipc[0], &child);
    struct pollfd poller = {.fd = child_pidfd, .events = POLLIN}; MUST(poll(&poller, 1, 0) == 0);
    MUST(syscall(SYS_pidfd_send_signal, tracer_pidfd, SIGKILL, NULL, 0) == 0);
    int status; MUST(waitpid(tracer, &status, 0) == tracer && WIFSIGNALED(status));
    MUST(waitpid(child, &status, 0) == child && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
    MUST(poll(&poller, 1, 1000) == 1);
    close(ipc[0]); close(gate[1]); close(child_pidfd); close(tracer_pidfd); MUST(fd_count() == before);
    puts("{\"case\":\"tracer-death\",\"result\":\"passed\",\"exitkill\":true,\"adopted_child_reaped\":true}");
}
/* SELinux status is a seqlock-protected kernel page, not policyvers (ABI version). */
static struct selinux_page status_page(void) {
    int fd = open("/sys/fs/selinux/status", O_RDONLY | O_CLOEXEC); MUST(fd >= 0);
    volatile struct selinux_page *page = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0); MUST(page != MAP_FAILED);
    struct selinux_page value;
    for (unsigned tries = 0;; tries++) {
        MUST(tries < 10000);
        uint32_t begin = __atomic_load_n(&page->sequence, __ATOMIC_ACQUIRE);
        if (begin & 1) continue;
        value.version = page->version; value.enforcing = page->enforcing; value.policyload = page->policyload; value.deny_unknown = page->deny_unknown;
        uint32_t end = __atomic_load_n(&page->sequence, __ATOMIC_ACQUIRE);
        if (begin == end) { value.sequence = end; break; }
    }
    munmap((void *)page, 4096); close(fd); MUST(value.version == 1); return value;
}
static int memfd_copy(const char *path) {
    int source = open(path, O_RDONLY | O_CLOEXEC); MUST(source >= 0);
    int fd = syscall(SYS_memfd_create, "phase0-workload", MFD_CLOEXEC | MFD_ALLOW_SEALING); MUST(fd >= 0);
    char bytes[16384]; ssize_t count;
    while ((count = read(source, bytes, sizeof(bytes))) > 0) MUST(write(fd, bytes, count) == count);
    MUST(count == 0); close(source);
    MUST(fcntl(fd, F_ADD_SEALS, F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) == 0);
    return fd;
}
static int domain_enforcing(const char *context) {
    /* Query the kernel decision flags, including per-domain permissive state.
     * Only the host supervisor loads libselinux, before creating any child. */
    struct decision { uint32_t allowed, decided, auditallow, auditdeny, seqno, flags; } result;
    void *library = dlopen("libselinux.so.1", RTLD_NOW | RTLD_LOCAL); MUST(library != NULL);
    unsigned short (*class_number)(const char *) = dlsym(library, "string_to_security_class");
    int (*compute)(const char *, const char *, unsigned short, unsigned, struct decision *) = dlsym(library, "security_compute_av_flags_raw");
    MUST(class_number != NULL && compute != NULL);
    unsigned short process = class_number("process"); MUST(process != 0);
    MUST(compute(context, context, process, 0, &result) == 0);
    dlclose(library); return !(result.flags & 1);
}
static int policy_matches(struct selinux_page before, const char *context, struct selinux_page *after) {
    struct selinux_page start = status_page();
    int enforcing_domain = domain_enforcing(context);
    *after = status_page();
    return before.enforcing == 1 && start.enforcing == 1 && after->enforcing == 1 && enforcing_domain
        && before.sequence == start.sequence && start.sequence == after->sequence
        && before.policyload == start.policyload && start.policyload == after->policyload;
}
static void lsm_case(const char *executable, const char *secret, const char *context, int mode) {
    MUST(mode >= 0 && mode <= 5);
    struct selinux_page before = status_page();
    if (mode == 5) {
        MUST(before.enforcing == 0);
        puts("{\"case\":\"global-permissive\",\"result\":\"passed\",\"rejected_before_spawn\":true}"); return;
    }
    MUST(before.enforcing == 1);
    if (mode == 4) {
        MUST(!domain_enforcing(context));
        puts("{\"case\":\"domain-permissive\",\"result\":\"passed\",\"rejected_before_spawn\":true}"); return;
    }
    MUST(domain_enforcing(context));
    int memfd = mode == 1;
    int exe = memfd ? memfd_copy(executable) : open(executable, O_RDONLY | O_CLOEXEC); MUST(exe >= 0);
    if (memfd) {
        const char label[] = "system_u:object_r:sigrund_phase0_exec_t:s0";
        MUST(fsetxattr(exe, "security.selinux", label, sizeof(label), 0) == 0);
    }
    int gate[2], output[2]; MUST(pipe2(gate, O_CLOEXEC) == 0 && pipe2(output, O_CLOEXEC) == 0);
    pid_t child = fork(); MUST(child >= 0);
    if (child == 0) {
        close(gate[1]); close(output[0]);
        char byte; MUST(read(gate[0], &byte, 1) == 1);
        MUST(dup2(output[1], 1) == 1);
        MUST(write_path("/proc/self/attr/exec", context) == 0);
        deny_getppid();
        MUST(dup3(exe, 3, O_CLOEXEC) == 3 || (exe == 3 && errno == EINVAL));
        MUST(syscall(SYS_close_range, 4U, ~0U, 0U) == 0);
        char *argv[] = {"phase0-lsm-workload", (char *)secret, NULL}, *env[] = {NULL};
        syscall(SYS_execveat, 3, "", argv, env, AT_EMPTY_PATH); _exit(73);
    }
    close(gate[0]); close(output[1]); attach(child);
    MUST(write(gate[1], "X", 1) == 1); close(gate[1]); MUST(ptrace(PTRACE_CONT, child, 0, 0) == 0);
    int status; MUST(waitpid(child, &status, __WALL) == child && WIFSTOPPED(status) && (status >> 16) == PTRACE_EVENT_EXEC);
    int fd = open_proc(child, "attr/current", O_RDONLY); char actual[4096]; MUST(fd >= 0); read_text(fd, actual, sizeof(actual)); close(fd);
    actual[strcspn(actual, "\n")] = 0;
    MUST(!strcmp(context, actual) && field(child, "NoNewPrivs:") == 1 && field(child, "Seccomp:") == 2);
    if (mode == 3) {
        puts("{\"ready\":\"policy-reload-at-exec-stop\"}"); fflush(stdout);
        char command; MUST(read(0, &command, 1) == 1 && command == 'R');
    }
    struct selinux_page after;
    int policy_ok = policy_matches(before, context, &after);
    if (mode == 3) MUST(!policy_ok && after.enforcing == 1 && before.policyload != after.policyload && before.sequence != after.sequence);
    else MUST(policy_ok);
    if (mode == 2 || mode == 3) {
        /* A mismatch/reload is terminal, with no target instructions released. */
        if (mode == 2) {
            char expected[4096]; MUST(strlen(context) + 4 < sizeof(expected));
            strcpy(expected, context); strcat(expected, ",c3"); MUST(strcmp(expected, actual));
        }
        MUST(kill(child, SIGKILL) == 0 && waitpid(child, &status, __WALL) == child && WIFSIGNALED(status));
        char byte; MUST(read(output[0], &byte, 1) == 0); close(output[0]); close(exe);
        printf("{\"case\":\"selinux-%s\",\"result\":\"passed\",\"rejected_at_exec_stop\":true,\"no_workload_output\":true,\"before_policyload\":%u,\"after_policyload\":%u}\n", mode == 2 ? "context-mismatch" : "policy-reload", before.policyload, after.policyload); return;
    }
    MUST(ptrace(PTRACE_DETACH, child, 0, 0) == 0);
    MUST(waitpid(child, &status, 0) == child && status == 0);
    char result[128] = {0}; MUST(read(output[0], result, sizeof(result)) == 27 && !memcmp(result, "selinux-and-seccomp-denied\n", 27));
    close(output[0]); close(exe);
    int attr = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC); char own_label[4096]; MUST(attr >= 0); read_text(attr, own_label, sizeof(own_label)); close(attr);
    own_label[strcspn(own_label, "\n")] = 0;
    printf("{\"case\":\"selinux-%s\",\"result\":\"passed\",\"nnp\":true,\"ptrace_exec_stop\":true,\"actual_context_verified\":true,\"selinux_denial\":true,\"seccomp_denial\":true,\"policyload\":%u,\"workload_pid\":%d,\"supervisor_label\":", memfd ? "memfd" : "direct", before.policyload, child);
    json_string(own_label); puts("}");
}
int main(int argc, char **argv) {
    alarm(30); MUST(prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0) == 0);
    int capfd = open("/proc/sys/kernel/cap_last_cap", O_RDONLY | O_CLOEXEC); char captext[32];
    MUST(capfd >= 0); read_text(capfd, captext, sizeof(captext)); close(capfd);
    last_cap = strtoul(captext, NULL, 10); MUST(last_cap < 64);
    execution_context = getenv("PHASE0_EXEC_CONTEXT");
    namespace_memfd = getenv("PHASE0_MEMFD") && !strcmp(getenv("PHASE0_MEMFD"), "1");
    const char *policy_case = getenv("PHASE0_POLICY_CASE");
    if (policy_case) {
        if (!strcmp(policy_case, "reload")) policy_mode = POLICY_RELOAD;
        else if (!strcmp(policy_case, "domain-permissive")) policy_mode = POLICY_DOMAIN_PERMISSIVE;
        else if (!strcmp(policy_case, "global-permissive")) policy_mode = POLICY_GLOBAL_PERMISSIVE;
        else MUST(0);
        MUST(execution_context != NULL);
    }
    if (argc == 3 && !strcmp(argv[1], "peer")) { peer_case(argv[2]); return 0; }
    if (argc == 4 && !strcmp(argv[1], "lifecycle")) { lifecycle_case(argv[2], atoi(argv[3])); return 0; }
    if (argc == 3 && !strcmp(argv[1], "tracer-death")) { tracer_death_case(argv[2]); return 0; }
    if (argc == 2 && !strcmp(argv[1], "selinux-status")) {
        struct selinux_page page = status_page();
        printf("{\"sequence\":%u,\"policyload\":%u,\"enforcing\":%u}\n", page.sequence, page.policyload, page.enforcing); return 0;
    }
    if (argc == 6 && !strcmp(argv[1], "selinux")) { lsm_case(argv[2], argv[3], argv[4], atoi(argv[5])); return 0; }
    if (argc == 9 && !strcmp(argv[1], "namespace")) { namespace_case(argv[2], argv[3], argv[4], argv[5], atoi(argv[6]), atoi(argv[7]), atoi(argv[8])); return 0; }
    if (argc == 8 && !strcmp(argv[1], "route")) { route_case(argv[2], argv[3], argv[4], argv[5], atoi(argv[6]), atoi(argv[7])); return 0; }
    fprintf(stderr, "usage: probe peer SOCKET | namespace ROOT SOCKET CGROUP EXE ROOTLESS FILTERED FAULT | selinux EXE SECRET CONTEXT MEMFD | selinux-status\n");
    return 64;
}
