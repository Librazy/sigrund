/* Execution fixture with a bind-mounted root in util-linux unshare's already
 * private mount tree. Historical Phase 0 and Phase 1.5 producers stay unchanged. */
#define main phase0_probe_main
#include "../../../../../scripts/namespace-phase0/probe.c"
#undef main
int main(int argc, char **argv) {
    MUST(argc >= 4 && getpid() == 1);
    MUST(mount(argv[2], argv[2], NULL, MS_BIND | MS_REC, NULL) == 0);
    int source = !strcmp(argv[1], "source");
    if (source) {
        MUST(argc >= 5);
        char target[4096];
        MUST(snprintf(target, sizeof(target), "%s%s", argv[2], argv[3]) < (int)sizeof(target));
        MUST(mount(argv[3], target, NULL, MS_BIND, NULL) == 0);
    } else MUST(argc == 4 && !strcmp(argv[1], "init"));
    MUST(chdir(argv[2]) == 0 && chroot(".") == 0 && chdir("/") == 0);
    MUST(mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) == 0);
    pid_t child = fork(); MUST(child >= 0);
    if (child == 0) {
        if (source) {
            MUST(setgroups(0, NULL) == 0 && setgid(65534) == 0 && setuid(65534) == 0);
            execv(argv[4], &argv[4]); perror("source fixture exec"); _exit(126);
        }
        anchor(argv[3], 0); _exit(1);
    }
    int status; MUST(waitpid(child, &status, 0) == child);
    if (source) return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
    return WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL ? 0 : 1;
}
