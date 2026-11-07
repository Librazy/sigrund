#define _GNU_SOURCE
#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
int main(void) {
    uid_t r,e,s; gid_t gr,ge,gs,groups[64];
    int n=getgroups(64,groups);
    if (getresuid(&r,&e,&s) || getresgid(&gr,&ge,&gs) || n<0) return 70;
    printf("{\"uid\":[%u,%u,%u],\"gid\":[%u,%u,%u],\"groups\":[",r,e,s,gr,ge,gs);
    for (int i=0;i<n;i++) printf("%s%u",i?",":"",groups[i]);
    puts("]}"); fflush(stdout);
    usleep(500000); /* Keep the real job's limits observable to the harness. */
    return 0;
}
