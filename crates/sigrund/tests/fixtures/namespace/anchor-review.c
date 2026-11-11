/* Review fixture with deliberate handshake delay and seccomp forgery. */
#include "anchor.h"
ssize_t write(int fd, const void *data, size_t count) {
    if (count == 1 && *(const char *)data == 'H') {
        const char *mode = getenv("SIGRUND_TEST_ANCHOR");
        if (mode && !strcmp(mode, "delay")) {
            MUST(prctl(PR_SET_NAME, "ns-review-delay", 0, 0, 0) == 0);
            sleep(2);
        }
        if (mode && !strcmp(mode, "spoof")) {
            MUST(prctl(PR_SET_NAME, "Seccomp:0", 0, 0, 0) == 0);
            struct sock_filter filter[] = {
                BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
                BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_unshare, 0, 1),
                BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO),
                BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
            };
            struct sock_fprog program = {.len = COUNT(filter), .filter = filter};
            MUST(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
            MUST(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) == 0);
        }
    }
    return syscall(SYS_write, fd, data, count);
}

int main(int argc, char **argv) {
    MUST(argc == 3 && !strcmp(argv[1], "init") && getpid() == 1);
    MUST(chdir("/") == 0);
    pid_t child = fork(); MUST(child >= 0);
    if (child == 0) anchor(argv[2]);
    int status; MUST(waitpid(child, &status, 0) == child);
    return WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL ? 0 : 1;
}
