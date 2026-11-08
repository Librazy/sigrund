/* Run the production predicates against real procfs with misleading comm. */
#include "../../../src/child/target_capture.c"
int main(void) {
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
    MUST(syscall(SYS_unshare, CLONE_FS | CLONE_FILES) == 0);
    MUST(field(getpid(), "Seccomp:") == 2);
    MUST(prctl(PR_SET_NAME, "Uid:0 0 0 0", 0, 0, 0) == 0);
    MUST(ids_match(getpid(), "Uid:", getuid()));
    MUST(prctl(PR_SET_NAME, "Groups:0", 0, 0, 0) == 0);
    unsigned groups[256]; int n = getgroups(256, groups); MUST(n >= 0);
    int pair[2]; MUST(socketpair(AF_UNIX, SOCK_STREAM, 0, pair) == 0);
    MUST(groups_match(getpid(), pair[0]));
    close(pair[0]); close(pair[1]);
    return 0;
}
