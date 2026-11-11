/* Qualification workload. Build a separate image for host, A and B. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>
#ifndef DESTINATION
#error DESTINATION required
#endif
int main(int argc, char **argv) {
    char context[256] = {0}, cwd[4096] = {0};
    int fd = open("/proc/self/attr/current", O_RDONLY);
    if (fd >= 0) { ssize_t n = read(fd, context, sizeof(context) - 1); if (n < 0) return 2; close(fd); }
    context[strcspn(context, "\n")] = 0;
    if (!getcwd(cwd, sizeof(cwd))) return 2;
    errno = 0;
    long parent = syscall(SYS_getppid);
    int parent_errno = errno;
    errno = 0;
    int secret = open("/srv/secret", O_RDONLY);
    int secret_errno = errno;
    if (secret >= 0) close(secret);
    printf("destination=%s uid=%u gid=%u groups=%d cwd=%s nnp=%d seccomp=%d context=%s getppid=%ld errno=%d secret=%d secret_errno=%d\n",
           DESTINATION, (unsigned)getuid(), (unsigned)getgid(), getgroups(0, NULL), cwd,
           prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0), prctl(PR_GET_SECCOMP, 0, 0, 0, 0),
           context, parent, parent_errno, secret, secret_errno);
    fflush(stdout);
    if (argc == 2 && !strcmp(argv[1], "wait")) {
        pid_t child = fork();
        if (child < 0) return 2;
        for (;;) pause();
    }
    return 0;
}
