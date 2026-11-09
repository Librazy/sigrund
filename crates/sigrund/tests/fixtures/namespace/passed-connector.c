/* Root-owned test driver invokes the actual syscall-only connector and writes
 * its passed public stream under different credentials. */
#include <stdlib.h>
#include <string.h>
#include "../../../src/child/client_anchor.c"
int main(int argc, char **argv) {
    if (argc != 3 || strlen(argv[1]) + 7 >= sizeof(((struct sockaddr_un *)0)->sun_path)) return 2;
    struct sockaddr_un public = {.sun_family=AF_UNIX}, anchor = {.sun_family=AF_UNIX};
    strcpy(public.sun_path, argv[1]);
    strcpy(anchor.sun_path, argv[1]);
    strcat(anchor.sun_path, ".anchor");
    connector(atoi(argv[2]), &public, &anchor, getppid());
}
