#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ptrace.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

static int context(const char *attribute, const char *value) {
    int fd = open(attribute, O_WRONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    int result = write(fd, value, strlen(value));
    int saved = errno;
    close(fd);
    errno = saved;
    return result;
}
int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "forgery")) {
        const char *roles[] = {
            "system_u:object_r:sigrund_execution_socket_t:s0",
            "system_u:object_r:sigrund_context_socket_t:s0",
            "system_u:object_r:sigrund_anchor_socket_t:s0"
        };
        for (unsigned i = 0; i < 3; ++i) {
            int set = context("/proc/self/attr/sockcreate", roles[i]);
            int created = -1;
            if (set >= 0) created = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
            printf("role=%u set=%d created=%d errno=%d\n", i, set, created, errno);
            if (created >= 0) { close(created); return 1; }
            if (set >= 0 && context("/proc/self/attr/sockcreate", "") < 0) return 2;
        }
        if (context("/proc/self/attr/exec", "system_u:system_r:init_t:s0") >= 0) return 1;
        if (context("/proc/self/attr/current", "system_u:system_r:init_t:s0") >= 0) return 1;
        puts("producer-entry=denied");
        return 0;
    }
    if (argc == 3 && !strcmp(argv[1], "trace")) {
        char *end; long value = strtol(argv[2], &end, 10);
        if (*end || value <= 1 || value > 2147483647) return 2;
        pid_t pid = value;
        int result = ptrace(PTRACE_ATTACH, pid, 0, 0);
        printf("attach=%d errno=%d\n", result, errno);
        if (result < 0) return 1;
        int status;
        if (waitpid(pid, &status, __WALL) != pid || !WIFSTOPPED(status)) return 2;
        return ptrace(PTRACE_DETACH, pid, 0, 0) == 0 ? 0 : 2;
    }
    return 2;
}
