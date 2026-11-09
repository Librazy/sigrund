#define _GNU_SOURCE
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "stdin")) {
        char bytes[64];
        ssize_t count = read(0, bytes, sizeof(bytes));
        if (count < 0) { perror("stdin"); return 6; }
        printf("stdin-bytes=%zd\n", count);
        if (count && fwrite(bytes, 1, count, stdout) != (size_t)count) return 7;
        return 0;
    }
    if (argc != 2 || strcmp(argv[1], "fork")) return 2;
    int gate[2];
    if (pipe(gate) != 0) return 3;
    pid_t child = fork();
    if (child < 0) return 3;
    if (child == 0) {
        close(gate[0]);
        if (setsid() < 0 || write(gate[1], "x", 1) != 1) _exit(4);
        close(gate[1]);
        for (;;) pause();
    }
    close(gate[1]);
    char byte;
    if (read(gate[0], &byte, 1) != 1 || byte != 'x') return 5;
    close(gate[0]);
    puts("workload-ready");
    fflush(stdout);
    for (;;) pause();
}
