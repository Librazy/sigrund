#define _GNU_SOURCE
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <unistd.h>

/* Native workloads for actual job-limit and bounded-output acceptance. */
int main(int argc, char **argv) {
    if (argc != 2) return 64;
    if (!strcmp(argv[1], "output")) {
        unsigned char block[4096];
        for (size_t i=0;i<sizeof(block);i++) block[i]=(unsigned char)i;
        for (int i=0;i<512;i++) {
            if (fwrite(block,1,sizeof(block),stdout)!=sizeof(block)) return 70;
            if (fwrite(block,1,sizeof(block),stderr)!=sizeof(block)) return 71;
        }
        return 23;
    }
    if (!strcmp(argv[1], "memory")) {
        /* Touch well beyond the job bound, without using the host's overcommit
         * heuristics as evidence. The containing cgroup must kill this job. */
        for (int i=0;i<512;i++) {
            volatile unsigned char *p=mmap(NULL,1024*1024,PROT_READ|PROT_WRITE,MAP_PRIVATE|MAP_ANONYMOUS,-1,0);
            if (p==MAP_FAILED) return 72;
            for (int j=0;j<1024*1024;j+=4096) p[j]=1;
        }
        return 73;
    }
    if (!strcmp(argv[1], "pids")) {
        unsigned children=0;
        for (;children<256;children++) {
            pid_t child=fork();
            if (child<0) {
                if (errno!=EAGAIN) return 74;
                printf("pids-denied:%u\n",children);
                fflush(stdout);
                /* Leave descendants alive; whole-job cleanup must reap/kill
                 * them even after this primary returns successfully. */
                return children>0 && children<128 ? 0 : 75;
            }
            if (!child) { for (;;) pause(); }
        }
        return 76;
    }
    return 64;
}
