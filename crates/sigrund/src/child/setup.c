#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <linux/mount.h>
#include <linux/sched.h>
#include <signal.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/mount.h>
#include <sys/statvfs.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

/* All storage, including mountinfo/group read-back buffers, is allocated by
 * the parent. No allocator, parser library, stdio, Rust, or destructor runs
 * between the child return of clone3 and execveat/_exit. */
struct child_spec {
    int input, output, error, executable, sync;
    uint32_t uid, gid, mask, last_cap;
    uint64_t capabilities;
    const uint32_t *groups;
    size_t groups_len;
    const char *cwd;
    const char *const *argv;
    const char *const *envp;
    char *mountinfo;
    size_t mountinfo_capacity;
    uint32_t *group_check;
    int isolated;
};
struct setup_frame { uint32_t step; int32_t error; };
_Static_assert(sizeof(struct setup_frame) == 8, "sync ABI");

static void die(int sync, unsigned step, int error) {
    const struct setup_frame frame = { step, error > 0 ? error : EIO };
    /* One frame-sized write; partial or failed evidence must never exec. */
    (void)syscall(SYS_write, sync, &frame, sizeof(frame));
    syscall(SYS_exit_group, 127);
    __builtin_unreachable();
}
#define CHECK(step, expr) do { if ((expr) < 0) die(sync, step, errno); } while (0)
#define ASSERT(step, expr) do { if (!(expr)) die(sync, step, EPERM); } while (0)

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
    if (s->isolated) lock_mounts(s, sync);
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
    CHECK(2, syscall(SYS_chdir, s->cwd));
    syscall(SYS_umask, s->mask);
    for (unsigned cap = 0; cap <= s->last_cap; ++cap)
        if (!(s->capabilities & (1ULL << cap)))
            CHECK(3, syscall(SYS_prctl, PR_CAPBSET_DROP, cap, 0, 0, 0));
    CHECK(4, syscall(SYS_prctl, PR_SET_SECUREBITS, 0x2f, 0, 0, 0));
    CHECK(5, syscall(SYS_setgroups, s->groups_len, s->groups));
    CHECK(5, syscall(SYS_setresgid, s->gid, s->gid, s->gid));
    CHECK(6, syscall(SYS_setresuid, s->uid, s->uid, s->uid));
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
    CHECK(10, observed); ASSERT(10, observed == 0x2f);
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
