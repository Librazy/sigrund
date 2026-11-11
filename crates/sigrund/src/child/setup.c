#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <linux/mount.h>
#include <linux/openat2.h>
#include <linux/sched.h>
#include <signal.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/mount.h>
#include <sys/statvfs.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

/* All storage, including mountinfo/group read-back buffers, is allocated by
 * the parent. No allocator, parser library, stdio, Rust, or destructor runs
 * between the child return of clone3 and execveat/_exit. */
#include "launcher_abi.h"
#include "namespace_filter.h"
struct setup_frame { uint32_t step; int32_t error; };
_Static_assert(sizeof(struct setup_frame) == SG_EVENT_BYTES, "sync ABI");

static void die(int sync, unsigned step, int error) {
    const struct setup_frame frame = { step, error > 0 ? error : EIO };
    /* One frame-sized write; partial or failed evidence must never exec. */
    (void)syscall(SYS_write, sync, &frame, sizeof(frame));
    syscall(SYS_exit_group, 127);
    __builtin_unreachable();
}
#define CHECK(step, expr) do { if ((expr) < 0) die(sync, step, errno); } while (0)
#define ASSERT(step, expr) do { if (!(expr)) die(sync, step, EPERM); } while (0)

static const char host_workload_context[] = "system_u:system_r:sigrund_host_workload_t:s0";
static void set_exec_context(const char *context, size_t length, int sync) {
    int attr = syscall(SYS_openat, AT_FDCWD, "/proc/self/attr/exec", O_WRONLY | O_CLOEXEC | O_NOFOLLOW, 0);
    CHECK(22, attr);
    ASSERT(22, syscall(SYS_write, attr, context, length) == (ssize_t)length);
    CHECK(22, syscall(SYS_close, attr));
}

/* Allocation-free mountinfo parser. A line is split into at most 128 fields;
 * reject truncation, escaped/bad mount names, unexpected tags and overflow.
 * Mount options and superblock options are distinct: the former must carry
 * ro,nosuid,nodev,noexec, including on every mount below the cgroup mount. */
static int eq(const char *s, size_t n, const char *expected) {
    size_t i = 0;
    for (; i < n && expected[i]; ++i) if (s[i] != expected[i]) return 0;
    return i == n && expected[i] == 0;
}
static int prefix(const char *s, size_t n, const char *p) {
    size_t i = 0;
    while (p[i]) { if (i == n || s[i] != p[i]) return 0; ++i; }
    return 1;
}
static int option(const char *s, size_t n, const char *wanted) {
    for (size_t start = 0, end; start < n; start = end + 1) {
        for (end = start; end < n && s[end] != ','; ++end) {}
        if (eq(s + start, end - start, wanted)) return 1;
    }
    return 0;
}
static int check_mountinfo(const char *buf, size_t length) {
    int found = 0;
    for (size_t begin = 0, end; begin < length; begin = end + 1) {
        for (end = begin; end < length && buf[end] != '\n'; ++end) {}
        if (end == length) return 0;
        const char *field[128]; size_t len[128]; size_t count = 0;
        for (size_t start = begin, next; start < end; start = next + 1) {
            if (count == 128) return 0;
            for (next = start; next < end && buf[next] != ' '; ++next) {}
            if (next == start) return 0;
            field[count] = buf + start; len[count++] = next - start;
        }
        if (count < 10) return 0;
        size_t sep = 6;
        while (sep < count && !eq(field[sep], len[sep], "-")) ++sep;
        if (sep + 3 >= count) return 0;
        int exact = eq(field[4], len[4], "/sys/fs/cgroup");
        int below = prefix(field[4], len[4], "/sys/fs/cgroup/");
        if (!exact && !below) continue;
        if (exact) {
            if (!eq(field[sep+1], len[sep+1], "cgroup2")) return 0;
            found = 1;
        }
        for (size_t k = 6; k < sep; ++k)
            if (prefix(field[k], len[k], "shared:") ||
                prefix(field[k], len[k], "master:") ||
                prefix(field[k], len[k], "propagate_from:")) return 0;
        if (!option(field[5], len[5], "ro") ||
            !option(field[5], len[5], "nosuid") ||
            !option(field[5], len[5], "nodev") ||
            !option(field[5], len[5], "noexec")) return 0;
    }
    return found;
}

static void lock_mounts(const struct child_spec *spec, int sync) {
    CHECK(1, syscall(SYS_mount, NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL));
    struct mount_attr attr = {
        .attr_set = MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID |
                    MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC,
    };
    CHECK(1, syscall(SYS_mount_setattr, AT_FDCWD, "/sys/fs/cgroup",
                     AT_RECURSIVE, &attr, sizeof(attr)));
    struct statvfs st;
    CHECK(1, statvfs("/sys/fs/cgroup", &st));
    unsigned long flags = ST_RDONLY | ST_NOSUID | ST_NODEV | ST_NOEXEC;
    ASSERT(1, (st.f_flag & flags) == flags);
    int fd = syscall(SYS_openat, AT_FDCWD, "/proc/self/mountinfo", O_RDONLY | O_CLOEXEC, 0);
    CHECK(1, fd);
    size_t used = 0;
    for (;;) {
        ASSERT(1, used < spec->mountinfo_capacity);
        long n = syscall(SYS_read, fd, spec->mountinfo + used, spec->mountinfo_capacity - used);
        if (n < 0 && errno == EINTR) continue;
        CHECK(1, n);
        if (!n) break;
        used += n;
    }
    CHECK(1, syscall(SYS_close, fd));
    ASSERT(1, check_mountinfo(spec->mountinfo, used));
    /* Verify the mount really rejects writes before dropping mount authority. */
    int write_fd = syscall(SYS_openat, AT_FDCWD, "/sys/fs/cgroup/cgroup.procs", O_WRONLY | O_CLOEXEC, 0);
    if (write_fd >= 0) { syscall(SYS_close, write_fd); die(sync, 1, EPERM); }
    ASSERT(1, errno == EROFS);
}

static void run_child(const struct child_spec *s) {
    int sync = s->sync;
    /* A nonroot host command must not inherit the reserved socket producer's
     * authority. Set exec_sid before any private mounts or credential changes.
     * Namespace launchers establish it before entering the destination. */
    if (s->producer_guard && !s->namespace_mode)
        set_exec_context(host_workload_context, sizeof(host_workload_context)-1, sync);
    if (s->checkpoint) {
        syscall(SYS_close, s->gate_write);
        char byte;
        long count;
        do { count = syscall(SYS_read, s->gate_read, &byte, 1); } while (count < 0 && errno == EINTR);
        if (count != 1 || byte != 'x') die(sync, 1, ECANCELED);
        syscall(SYS_close, s->gate_read);
    }
    CHECK(1, syscall(SYS_unshare, CLONE_FILES));
    int tmp_sync = syscall(SYS_fcntl, sync, F_DUPFD_CLOEXEC, 5);
    CHECK(1, tmp_sync);
    sync = tmp_sync;
    int in = syscall(SYS_fcntl, s->input, F_DUPFD_CLOEXEC, 5); CHECK(1, in);
    int out = syscall(SYS_fcntl, s->output, F_DUPFD_CLOEXEC, 5); CHECK(1, out);
    int err = syscall(SYS_fcntl, s->error, F_DUPFD_CLOEXEC, 5); CHECK(1, err);
    int exec = syscall(SYS_fcntl, s->executable, F_DUPFD_CLOEXEC, 5); CHECK(1, exec);
    CHECK(1, syscall(SYS_dup3, in, 0, 0));
    CHECK(1, syscall(SYS_dup3, out, 1, 0));
    CHECK(1, syscall(SYS_dup3, err, 2, 0));
    CHECK(1, syscall(SYS_dup3, exec, 3, O_CLOEXEC)); /* MVP is ELF only */
    CHECK(1, syscall(SYS_dup3, sync, 4, O_CLOEXEC));
    sync = 4;
    CHECK(1, syscall(SYS_close_range, 5U, ~0U, 0U));
    if (s->isolated && !s->namespace_mode) lock_mounts(s, sync);
    if (s->direct_path && s->isolated) {
        /* mnt_may_suid() suppresses file capabilities for an FD whose mount
         * belongs to the parent's namespace. Open an alias in this namespace,
         * accepting only the exact inode still pinned by FD 3 and the parent.
         * Path replacement/symlinks cannot select different executable bytes. */
        struct open_how how = {
            .flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW,
            .resolve = RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS,
        };
        int alias = syscall(SYS_openat2, AT_FDCWD, s->direct_path, &how, sizeof(how));
        CHECK(1, alias);
        struct stat pinned, candidate;
        CHECK(1, syscall(SYS_fstat, 3, &pinned));
        CHECK(1, syscall(SYS_fstat, alias, &candidate));
        ASSERT(1, S_ISREG(candidate.st_mode) && pinned.st_dev == candidate.st_dev &&
                  pinned.st_ino == candidate.st_ino);
        CHECK(1, syscall(SYS_dup3, alias, 3, O_CLOEXEC));
        CHECK(1, syscall(SYS_close, alias));
    }
    struct sigaction action = { .sa_handler = SIG_DFL };
    sigemptyset(&action.sa_mask);
    for (int sig = 1; sig < NSIG; ++sig) {
        if (sig == SIGKILL || sig == SIGSTOP || sig == 32 || sig == 33) continue;
        CHECK(1, sigaction(sig, &action, NULL));
    }
    sigset_t empty;
    sigemptyset(&empty);
    CHECK(1, sigprocmask(SIG_SETMASK, &empty, NULL));
    CHECK(1, syscall(SYS_setsid));
    if (!s->namespace_mode) CHECK(2, syscall(SYS_chdir, s->cwd));
    syscall(SYS_umask, s->mask);
    for (unsigned cap = 0; cap <= s->last_cap; ++cap)
        if (!(s->capabilities & (1ULL << cap)))
            CHECK(3, syscall(SYS_prctl, PR_CAPBSET_DROP, cap, 0, 0, 0));
    unsigned securebits = s->namespace_mode ? 15 : 0x2f;
    CHECK(4, syscall(SYS_prctl, PR_SET_SECUREBITS, securebits, 0, 0, 0));
    if (!s->namespace_mode) CHECK(5, syscall(SYS_setgroups, s->groups_len, s->groups));
    CHECK(5, syscall(SYS_setresgid, s->gid, s->gid, s->gid));
    CHECK(6, syscall(SYS_setresuid, s->uid, s->uid, s->uid));
    if (s->namespace_mode) CHECK(6, syscall(SYS_prctl, PR_SET_DUMPABLE, 0, 0, 0, 0));
    struct __user_cap_header_struct header = { _LINUX_CAPABILITY_VERSION_3, 0 };
    struct __user_cap_data_struct data[2] = {0};
    for (unsigned i = 0; i < 2; ++i)
        data[i].effective = data[i].permitted = data[i].inheritable = (uint32_t)(s->capabilities >> (32*i));
    CHECK(7, syscall(SYS_capset, &header, data));
    CHECK(8, syscall(SYS_prctl, PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0));
    for (unsigned cap = 0; cap <= s->last_cap; ++cap)
        if (s->capabilities & (1ULL << cap))
            CHECK(8, syscall(SYS_prctl, PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0));
    CHECK(9, syscall(SYS_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0));
    uint32_t a, b, c;
    CHECK(10, syscall(SYS_getresuid, &a, &b, &c));
    ASSERT(10, a == s->uid && b == a && c == a);
    CHECK(10, syscall(SYS_getresgid, &a, &b, &c));
    ASSERT(10, a == s->gid && b == a && c == a);
    long groups = syscall(SYS_getgroups, s->groups_len, s->group_check);
    CHECK(10, groups);
    ASSERT(10, (size_t)groups == s->groups_len);
    for (size_t i = 0; i < s->groups_len; ++i) ASSERT(10, s->group_check[i] == s->groups[i]);
    long observed = syscall(SYS_prctl, PR_GET_SECUREBITS, 0, 0, 0, 0);
    CHECK(10, observed); ASSERT(10, observed == securebits);
    observed = syscall(SYS_prctl, PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
    CHECK(10, observed); ASSERT(10, observed == 1);
    CHECK(10, syscall(SYS_capget, &header, data));
    for (unsigned i = 0; i < 2; ++i) {
        uint32_t expected = (uint32_t)(s->capabilities >> (32*i));
        ASSERT(10, data[i].effective == expected && data[i].permitted == expected && data[i].inheritable == expected);
    }
    for (unsigned cap = 0; cap <= s->last_cap; ++cap) {
        int wanted = !!(s->capabilities & (1ULL << cap));
        observed = syscall(SYS_prctl, PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, cap, 0, 0);
        CHECK(10, observed); ASSERT(10, observed == wanted);
        observed = syscall(SYS_prctl, PR_CAPBSET_READ, cap, 0, 0, 0);
        CHECK(10, observed); ASSERT(10, observed == wanted);
    }
    if (s->production) {
        struct sock_fprog program = {.len = sizeof(sigrund_namespace_filter) / sizeof(struct sock_filter),
                                    .filter = (struct sock_filter *)sigrund_namespace_filter};
        CHECK(22, syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program));
    }
    struct setup_frame ready = {0,0};
    if (syscall(SYS_write, sync, &ready, sizeof(ready)) != sizeof(ready)) {
        syscall(SYS_exit_group, 127);
        __builtin_unreachable();
    }
    syscall(SYS_execveat, 3, "", s->argv, s->envp, AT_EMPTY_PATH);
    die(sync, 11, errno);
}

int sigrund_spawn(const struct child_spec *spec, int cgroup_fd, int *pidfd) {
    struct clone_args args = {
        .flags = CLONE_INTO_CGROUP | CLONE_PIDFD |
                 (spec->isolated ? CLONE_NEWNS | CLONE_NEWCGROUP : 0),
        .exit_signal = SIGCHLD,
        .cgroup = cgroup_fd,
        .pidfd = (uintptr_t)pidfd,
    };
    long pid = syscall(SYS_clone3, &args, sizeof(args));
    if (pid == 0) run_child(spec);
    return pid;
}

/* Every message is exactly two native u32 values. Only the final-child message
 * carries a single kernel-created pidfd. The coordinator grants the clone only
 * after setup has finished and its short reaper barrier has been reserved. */
static void namespace_message(int control, uint32_t kind, uint32_t value, int fd, int sync) {
    uint32_t words[2] = {kind, value};
    struct iovec iov = {.iov_base = words, .iov_len = sizeof(words)};
    char ancillary[CMSG_SPACE(sizeof(int))] = {0};
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1};
    if (fd >= 0) {
        message.msg_control = ancillary; message.msg_controllen = sizeof(ancillary);
        struct cmsghdr *header = CMSG_FIRSTHDR(&message);
        header->cmsg_level = SOL_SOCKET; header->cmsg_type = SCM_RIGHTS;
        header->cmsg_len = CMSG_LEN(sizeof(int));
        memcpy(CMSG_DATA(header), &fd, sizeof(fd));
    }
    long count;
    do { count = syscall(SYS_sendmsg, control, &message, MSG_NOSIGNAL); } while (count < 0 && errno == EINTR);
    if (count != sizeof(words)) die(sync, 12, count < 0 ? errno : EIO);
}
/* Before entering another authority, replace the daemon address space. The
 * only inherited data are a sealed per-job configuration and this FD allowlist.
 * No namespace or credential change occurs on the daemon's copied memory. */
static void exec_namespace_launcher(const struct child_spec *s, const struct namespace_spec *n, int payload) {
    int sync = s->sync;
    CHECK(12, syscall(SYS_prctl, PR_SET_DUMPABLE, 0, 0, 0, 0));
    CHECK(12, syscall(SYS_unshare, CLONE_FS | CLONE_FILES));
    int wanted[18] = {s->input,s->output,s->error,s->executable,s->sync,s->gate_read,
        n->namespaces[0],n->namespaces[1],n->namespaces[2],n->namespaces[3],
        n->namespaces[4],n->namespaces[5],n->namespaces[6],n->namespaces[7],n->root,n->cwd,n->control,payload};
    int copies[18];
    for (unsigned i = 0; i < 18; ++i) { copies[i] = syscall(SYS_fcntl, wanted[i], F_DUPFD_CLOEXEC, 64); CHECK(12, copies[i]); }
    sync = copies[4];
    unsigned start = 0;
    for (unsigned i = 0; i < 18; ++i) {
        if (start < (unsigned)copies[i]) CHECK(12, syscall(SYS_close_range, start, (unsigned)copies[i]-1, 0U));
        start = (unsigned)copies[i]+1;
    }
    CHECK(12, syscall(SYS_close_range, start, ~0U, 0U));
    for (unsigned i = 0; i < 18; ++i) {
        CHECK(12, syscall(SYS_dup3, copies[i], 10+i, 0));
        if (i == 4) sync = 14;
        CHECK(12, syscall(SYS_close, copies[i]));
    }
    const char *argv[] = {"sigrund", "--internal-namespace-launcher", NULL};
    const char *envp[] = {NULL};
    /* The kernel retains the running image behind this initial-domain procfs
     * link, including across atomic package replacement. No extra image FD. */
    syscall(SYS_execve, "/proc/self/exe", argv, envp);
    die(sync, 12, errno);
}

/* This entry is called only in a fresh process, before config/secrets/listeners.
 * Storage and pointer tables contain this job alone and remain live until exit. */
void sigrund_run_namespace_launcher(const struct child_spec *original, const struct namespace_spec *source) {
    struct child_spec s = *original;
    struct namespace_spec n = *source;
    int sync = s.sync;
    CHECK(12, syscall(SYS_prctl, PR_SET_DUMPABLE, 0, 0, 0, 0));
    namespace_message(n.control, SG_EVENT_BOOTSTRAP, 0, -1, sync);
    char bootstrap; long received;
    do { received = syscall(SYS_read, n.control, &bootstrap, 1); } while (received < 0 && errno == EINTR);
    ASSERT(12, received == 1 && bootstrap == 'B');
    if (s.production) {
        /* Set the exec transition while procfs is still the trusted host tree.
         * fork preserves exec_sid; the launcher itself never execs again. */
        static const char context[] = "system_u:system_r:sigrund_workload_t:s0:c1,c2";
        set_exec_context(context, sizeof(context)-1, sync);
    } else if (s.producer_guard) {
        set_exec_context(host_workload_context, sizeof(host_workload_context)-1, sync);
    }
    CHECK(13, syscall(SYS_setgroups, 0, NULL));
    static const unsigned order[8] = {6,0,1,2,3,7,5,4};
    for (unsigned i=0;i<8;++i) {
        unsigned index = order[i];
        if (n.enter_mask & (1U << index)) CHECK(13, syscall(SYS_setns, n.namespaces[index], 0));
    }
    CHECK(13, syscall(SYS_setresgid, 0,0,0));
    CHECK(13, syscall(SYS_setresuid, 0,0,0));
    CHECK(13, syscall(SYS_prctl, PR_SET_DUMPABLE, 0, 0, 0, 0));
    CHECK(14, syscall(SYS_fchdir, n.root));
    CHECK(16, syscall(SYS_chroot, "."));
    CHECK(17, syscall(SYS_fchdir, n.cwd));
    /* Root/cwd must refer to the cloned tree, established before unshare. */
    CHECK(18, syscall(SYS_unshare, CLONE_NEWNS | CLONE_NEWCGROUP));
    CHECK(19, syscall(SYS_mount, NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL));
    CHECK(20, syscall(SYS_mount, "sigrund-private", "/run", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=65536,mode=0755"));
    struct mount_attr attr = {.attr_set=MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC};
    if (syscall(SYS_mount_setattr, AT_FDCWD, "/sys/fs/cgroup", AT_RECURSIVE, &attr, sizeof(attr)) < 0)
        ASSERT(14, errno == ENOENT);
    /* A cwd established before a covering mount can retain access beneath it.
     * Resolve in the completed private tree and require the same visible object
     * and mount as the inherited cwd, including for descendants and aliases. */
    struct open_how cwd_how = {.flags=O_PATH | O_DIRECTORY | O_CLOEXEC,
                              .resolve=RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS};
    int visible = syscall(SYS_openat2, AT_FDCWD, s.cwd, &cwd_how, sizeof(cwd_how));
    CHECK(21, visible);
    struct statx before, after;
    unsigned mask = STATX_INO | STATX_MNT_ID;
    CHECK(21, syscall(SYS_statx, AT_FDCWD, ".", 0, mask, &before));
    CHECK(21, syscall(SYS_statx, visible, "", AT_EMPTY_PATH, mask, &after));
    ASSERT(21, (before.stx_mask & mask) == mask && (after.stx_mask & mask) == mask &&
               before.stx_dev_major == after.stx_dev_major && before.stx_dev_minor == after.stx_dev_minor &&
               before.stx_ino == after.stx_ino && before.stx_mnt_id == after.stx_mnt_id);
    CHECK(21, syscall(SYS_fchdir, visible));
    CHECK(21, syscall(SYS_close, visible));
    /* Close all retained source roots/namespaces before creating the workload. */
    CHECK(14, syscall(SYS_close_range, 16U, 25U, 0U));
    namespace_message(n.control, SG_EVENT_READY, 0, -1, sync);
    char byte; long count;
    do { count=syscall(SYS_read,n.control,&byte,1); } while (count<0 && errno==EINTR);
    ASSERT(15, count==1 && byte=='C');
    int child_pidfd=-1;
    struct clone_args child = {.flags=CLONE_PIDFD, .exit_signal=SIGCHLD, .pidfd=(uintptr_t)&child_pidfd};
    long pid=syscall(SYS_clone3,&child,sizeof(child)); CHECK(15,pid);
    if (pid==0) {
        syscall(SYS_close,n.control);
        run_child(&s);
    }
    namespace_message(n.control,SG_EVENT_CHILD,(uint32_t)pid,child_pidfd,sync);
    syscall(SYS_close,child_pidfd);
    syscall(SYS_exit_group,0);
    __builtin_unreachable();
}
int sigrund_spawn_namespace_launcher(const struct child_spec *spec, const struct namespace_spec *namespace,
                                     int payload, int cgroup_fd, int *pidfd) {
    struct clone_args args = {.flags=CLONE_INTO_CGROUP | CLONE_PIDFD, .exit_signal=SIGCHLD,
                             .cgroup=cgroup_fd, .pidfd=(uintptr_t)pidfd};
    long pid=syscall(SYS_clone3,&args,sizeof(args));
    if (pid==0) exec_namespace_launcher(spec,namespace,payload);
    return pid;
}
