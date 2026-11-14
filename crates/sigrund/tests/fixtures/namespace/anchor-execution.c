/* Bind-mounted root in the private mount tree created by unshare. */
#include "anchor.h"
int main(int argc, char **argv) {
    if (argc == 3 && !strcmp(argv[1], "anchor")) { anchor(argv[2]); return 1; }
    MUST(argc >= 4 && getpid() == 1);
    /* A runtime's / is already a mount-point root. Recursively binding it over
     * itself would leave duplicate covered cgroup mounts in mountinfo. */
    if (strcmp(argv[2], "/")) MUST(mount(argv[2], argv[2], NULL, MS_BIND | MS_REC, NULL) == 0);
    int source = !strcmp(argv[1], "source");
    if (source) {
        MUST(argc >= 5);
        char target[4096];
        MUST(snprintf(target, sizeof(target), "%s%s", argv[2], argv[3]) < (int)sizeof(target));
        MUST(mount(argv[3], target, NULL, MS_BIND, NULL) == 0);
    } else MUST(argc == 4 && (!strcmp(argv[1], "init") || !strcmp(argv[1], "idle")));
    MUST(chdir(argv[2]) == 0 && chroot(".") == 0 && chdir("/") == 0);
    MUST(mount("proc", "/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL) == 0);
    if (!strcmp(argv[1], "idle")) for (;;) pause();
    pid_t child = fork(); MUST(child >= 0);
    if (child == 0) {
        if (source) {
            MUST(setgroups(0, NULL) == 0 && setgid(65534) == 0 && setuid(65534) == 0);
            execv(argv[4], &argv[4]); perror("source fixture exec"); _exit(126);
        }
        anchor(argv[3]); _exit(1);
    }
    int status; MUST(waitpid(child, &status, 0) == child);
    if (source) return WIFEXITED(status) ? WEXITSTATUS(status) : 128 + WTERMSIG(status);
    return WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL ? 0 : 1;
}
