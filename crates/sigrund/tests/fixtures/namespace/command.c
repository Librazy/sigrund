/* The same absolute pathname has different, runnable bytes on host and in B. */
#include <stdio.h>
#include <unistd.h>
#ifndef DESTINATION
#error DESTINATION is required
#endif
int main(void) {
    char cwd[4096];
    if (getcwd(cwd, sizeof(cwd)) == NULL) return 1;
    printf("destination=%s uid=%u gid=%u cwd=%s\n", DESTINATION,
           (unsigned)getuid(), (unsigned)getgid(), cwd);
    return 0;
}
