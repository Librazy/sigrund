#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <signal.h>
#include <linux/sched.h>
#include <sys/ptrace.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <unistd.h>
#include "namespace_filter.h"
#ifndef PTRACE_SECCOMP_GET_FILTER
#define PTRACE_SECCOMP_GET_FILTER 0x420c
#endif
int sigrund_verify_namespace_filter(int pid) {
    /* GET_FILTER does not take a destination capacity. Query length first,
     * and retain the kernel's full classic-BPF bound even though callers own
     * a stopped, single-threaded tracee and require exactly this program. */
    struct sock_filter actual[BPF_MAXINSNS];
    long count = ptrace(PTRACE_SECCOMP_GET_FILTER, pid, 0, NULL);
    if (count < 0) return -1;
    if (count != sizeof(sigrund_namespace_filter) / sizeof(actual[0])) { errno = EPERM; return -1; }
    count = ptrace(PTRACE_SECCOMP_GET_FILTER, pid, 0, actual);
    if (count < 0) return -1;
    if (count != sizeof(sigrund_namespace_filter) / sizeof(actual[0]) ||
        memcmp(actual, sigrund_namespace_filter, sizeof(sigrund_namespace_filter)) != 0) {
        errno = EPERM; return -1;
    }
    return 0;
}
int sigrund_probe_namespace_filter(void) {
#if !defined(__x86_64__)
    errno = ENOTSUP; return -1;
#else
    int pidfd = -1;
    struct clone_args args = {.flags = CLONE_PIDFD, .pidfd = (uintptr_t)&pidfd, .exit_signal = SIGCHLD};
    long pid = syscall(SYS_clone3, &args, sizeof(args));
    if (pid < 0) return -1;
    if (!pid) {
        struct sock_fprog program = {.len = sizeof(sigrund_namespace_filter) / sizeof(struct sock_filter),
                                    .filter = (struct sock_filter *)sigrund_namespace_filter};
        if (syscall(SYS_prctl, PR_SET_DUMPABLE, 0, 0, 0, 0) < 0 ||
            syscall(SYS_ptrace, PTRACE_TRACEME, 0, 0, 0) < 0 ||
            syscall(SYS_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) < 0 ||
            syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, 0, &program) < 0)
            syscall(SYS_exit_group, 127);
        syscall(SYS_kill, syscall(SYS_getpid), SIGSTOP);
        syscall(SYS_exit_group, 127);
    }
    int status; long found;
    do { found = waitpid(pid, &status, __WALL); } while (found < 0 && errno == EINTR);
    int result = -1;
    if (found == pid && WIFSTOPPED(status)) result = sigrund_verify_namespace_filter(pid);
    int saved = errno;
    syscall(SYS_pidfd_send_signal, pidfd, SIGKILL, NULL, 0);
    if (found == pid && !WIFEXITED(status) && !WIFSIGNALED(status))
        do { found = waitpid(pid, &status, __WALL); } while (found < 0 && errno == EINTR);
    close(pidfd);
    errno = saved;
    return result;
#endif
}
