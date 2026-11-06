/* Static, syscall-only executable: no destination loader or libc dependency. */
#include <asm/unistd.h>

static long call3(long n, long a, long b, long c) {
    long result;
    __asm__ volatile ("syscall" : "=a"(result) : "a"(n), "D"(a), "S"(b), "d"(c) : "rcx", "r11", "memory");
    return result;
}
static void output(const char *s, long size) { call3(__NR_write, 1, (long)s, size); }
__attribute__((used, noreturn)) void entry(long argc, char **argv) {
    int failed = 0;
    for (long fd = 3; fd < 64; fd++) {
        if (call3(__NR_fcntl, fd, 1 /* F_GETFD */, 0) != -9 /* EBADF */) failed = 1;
    }
    if (argc == 2) {
        long fd = call3(__NR_open, (long)argv[1], 0, 0);
        if (fd != -13) failed = 1;
        if (fd >= 0) call3(__NR_close, fd, 0, 0);
        if (call3(__NR_getppid, 0, 0, 0) != -13) failed = 1;
        if (!failed) output("selinux-and-seccomp-denied\n", sizeof("selinux-and-seccomp-denied\n") - 1);
    } else if (!failed) {
        output("namespace-workload-ran\n", 23);
    }
    call3(__NR_exit_group, failed, 0, 0);
    __builtin_unreachable();
}
__asm__(".global _start\n_start:\n mov (%rsp),%rdi\n lea 8(%rsp),%rsi\n and $-16,%rsp\n call entry\n");
