/* Exercise production connection waits without requiring namespace privilege. */
#include "../../../src/child/peer_auth.c"
#include "../../../src/child/client_anchor.c"
#include <stdio.h>
#include <string.h>
#include <sys/wait.h>
int main(int argc, char **argv) {
    if (argc != 3 || strlen(argv[2]) >= sizeof(((struct sockaddr_un *)0)->sun_path)) return 2;
    struct sockaddr_un address = {.sun_family=AF_UNIX};
    strcpy(address.sun_path, argv[2]);
    if (!strcmp(argv[1], "deadline")) {
        connect_stream(&address, now_ns() + 300000000);
        return 3;
    }
    if (strcmp(argv[1], "parent-death")) return 2;
    int parent = getpid();
    pid_t pid = fork();
    if (pid < 0) return 4;
    if (!pid) connector(-1, &address, &address, parent);
    printf("%d\n", pid);
    fflush(stdout);
    return waitpid(pid, NULL, 0) == pid ? 0 : 5;
}
