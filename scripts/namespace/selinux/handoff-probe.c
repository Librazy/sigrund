/* Host-root fixture for the installed fresh-exec producer, never an operator
 * entry point. The shared header supplies all event/version constants. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>
#include <sys/mman.h>
#include "launcher_abi.h"

int main(int argc, char **argv) {
    if (geteuid() != 0 || argc != 3) return 2;
    int source = open(argv[1], O_RDONLY | O_CLOEXEC);
    int payload = memfd_create("handoff-negative", MFD_ALLOW_SEALING);
    if (source < 0 || payload < 0) return 2;
    char buffer[4096]; ssize_t count;
    while ((count = read(source, buffer, sizeof(buffer))) > 0)
        if (write(payload, buffer, count) != count) return 2;
    close(source);
    if (count < 0 || lseek(payload, 0, SEEK_SET) != 0) return 2;
    if (strcmp(argv[2], "unsealed") && fcntl(payload, F_ADD_SEALS,
        F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL) < 0) return 2;
    int pair[2];
    if (socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair)) return 2;
    /* Duplicate above the ABI allowlist before remapping to avoid collisions. */
    int input = fcntl(payload, F_DUPFD_CLOEXEC, 64);
    int control = fcntl(pair[1], F_DUPFD_CLOEXEC, 64);
    int child = fork();
    if (child < 0) return 2;
    if (!child) {
        close(pair[0]);
        if (strcmp(argv[2], "missing-fds")) {
            int null = open("/dev/null", O_RDWR | O_CLOEXEC);
            for (int fd = 10; fd < 26; ++fd) if (dup2(null, fd) < 0) _exit(2);
            if (dup2(control, 26) < 0) _exit(2);
        }
        if (dup2(input, 27) < 0) _exit(2);
        close(input); close(control); close(payload); close(pair[1]);
        execl("/usr/libexec/sigrund/sigrund", "sigrund", "--internal-namespace-launcher", NULL);
        _exit(2);
    }
    close(pair[1]); close(control); close(input); close(payload);
    uint32_t event[2];
    ssize_t bytes = recv(pair[0], event, sizeof(event), 0);
    if (!strcmp(argv[2], "bad-bootstrap") || !strcmp(argv[2], "bad-namespace")) {
        if (bytes != SG_EVENT_BYTES || event[0] != SG_EVENT_BOOTSTRAP || event[1]) return 2;
        char byte = !strcmp(argv[2], "bad-bootstrap") ? 'X' : 'B';
        if (write(pair[0], &byte, 1) != 1) return 2;
    } else if (bytes != 0) return 2;
    close(pair[0]);
    int status;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status)) return 2;
    int expected = (!strcmp(argv[2], "bad-bootstrap") || !strcmp(argv[2], "bad-namespace")) ? 127 : 77;
    printf("case=%s exit=%d version=%u\n", argv[2], WEXITSTATUS(status), SG_PAYLOAD_VERSION);
    return WEXITSTATUS(status) == expected ? 0 : 1;
}
