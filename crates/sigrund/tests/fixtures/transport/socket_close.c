/* Test-only final Unix-socket close gate, including sockets never recvmsg'd. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

int close(int fd) {
    struct ucred peer;
    socklen_t length = sizeof(peer);
    unsigned char marker;
    const char *pid = getenv("SIGRUND_SOCKET_GATE_PEER_PID");
    if (pid && getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &peer, &length) == 0
        && peer.pid == atoi(pid)
        && syscall(SYS_recvfrom, fd, &marker, 1, MSG_PEEK | MSG_DONTWAIT, 0, 0) == 1
        && marker == 0xfe) {
        uint64_t tid = syscall(SYS_gettid);
        int entered = atoi(getenv("SIGRUND_GATE_ENTERED_FD"));
        int release = atoi(getenv("SIGRUND_GATE_RELEASE_FD"));
        ssize_t count;
        do { count = syscall(SYS_write, entered, &tid, sizeof(tid)); }
        while (count < 0 && errno == EINTR);
        char byte;
        do { count = syscall(SYS_read, release, &byte, 1); }
        while (count < 0 && errno == EINTR);
    }
    return syscall(SYS_close, fd);
}
