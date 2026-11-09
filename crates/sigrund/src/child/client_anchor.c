#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/sched.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

/* The CLI forks before starting relay threads. Only resident syscall code runs
 * in its dedicated connector; all caller descriptors close before capture. */
static void anchor_exit(void) {
    syscall(SYS_exit_group, 127);
    __builtin_unreachable();
}
static int64_t now_ns(void) {
    struct timespec now;
    if (syscall(SYS_clock_gettime, CLOCK_MONOTONIC, &now) < 0) anchor_exit();
    return (int64_t)now.tv_sec * 1000000000 + now.tv_nsec;
}
static int wait_until(int fd, short events, int64_t deadline) {
    int64_t remaining = deadline - now_ns();
    if (remaining <= 0) anchor_exit();
    if (remaining > 100000000) remaining = 100000000;
    struct timespec timeout = {.tv_sec=0, .tv_nsec=remaining};
    struct pollfd descriptor = {.fd=fd, .events=events};
    /* ppoll is present on both x86-64 and aarch64. A backlog retry deliberately
     * has no FD: an unconnected Unix socket is immediately writable/hung up. */
    int result = syscall(SYS_ppoll, &descriptor, fd < 0 ? 0 : 1, &timeout, NULL, 0);
    if (result < 0 && errno != EINTR) anchor_exit();
    return result > 0 ? descriptor.revents : 0;
}
static int connect_stream(const struct sockaddr_un *address, int64_t deadline) {
    int fd = syscall(SYS_socket, AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC | SOCK_NONBLOCK, 0);
    if (fd < 0) anchor_exit();
    for (;;) {
        if (now_ns() >= deadline) anchor_exit();
        if (syscall(SYS_connect, fd, address, sizeof(*address)) == 0 || errno == EISCONN) return fd;
        if (errno == EAGAIN) { wait_until(-1, 0, deadline); continue; }
        if (errno == EINTR) continue;
        if (errno != EINPROGRESS && errno != EALREADY) anchor_exit();
        int events = wait_until(fd, POLLOUT, deadline);
        if (events & (POLLERR | POLLHUP | POLLNVAL)) anchor_exit();
        if (events & POLLOUT) {
            int error = 0; socklen_t length = sizeof(error);
            if (syscall(SYS_getsockopt, fd, SOL_SOCKET, SO_ERROR, &error, &length) < 0 ||
                length != sizeof(error) || error) anchor_exit();
            return fd;
        }
    }
}
static void connector(int control, const struct sockaddr_un *public, const struct sockaddr_un *anchor, int parent) {
    if (syscall(SYS_prctl, PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) < 0 ||
        syscall(SYS_getppid) != parent) anchor_exit();
    int64_t deadline = now_ns() + 10000000000LL;
    int stream = connect_stream(public, deadline);
    int peer = connect_stream(anchor, deadline);
    char byte = 'S';
    struct iovec iov = {.iov_base=&byte, .iov_len=1};
    union { struct cmsghdr alignment; char bytes[CMSG_SPACE(sizeof(int))]; } ancillary = {0};
    struct msghdr message = {.msg_iov=&iov, .msg_iovlen=1, .msg_control=ancillary.bytes, .msg_controllen=sizeof(ancillary.bytes)};
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    header->cmsg_level=SOL_SOCKET; header->cmsg_type=SCM_RIGHTS; header->cmsg_len=CMSG_LEN(sizeof(int));
    *(int *)CMSG_DATA(header)=stream;
    if (syscall(SYS_sendmsg, control, &message, MSG_NOSIGNAL | MSG_DONTWAIT) != 1) anchor_exit();
    int retained = syscall(SYS_fcntl, peer, F_DUPFD_CLOEXEC, 10);
    if (retained < 0 || syscall(SYS_dup3, retained, 3, O_CLOEXEC) < 0) anchor_exit();
    if (syscall(SYS_close_range, 0U, 2U, 0U) < 0 || syscall(SYS_close_range, 4U, ~0U, 0U) < 0) anchor_exit();
    if (syscall(SYS_fcntl, 3, F_SETFL, 0) < 0) anchor_exit();
    byte='H';
    if (syscall(SYS_write, 3, &byte, 1) != 1) anchor_exit();
    long count;
    /* The capture contract permits only read -> unshare after H. Connection
     * retries above have their own deadline; this handshake remains covered by
     * the CLI's admission timeout and the non-maskable parent-death signal. */
    do { count=syscall(SYS_read, 3, &byte, 1); } while (count<0 && errno==EINTR);
    if (count != 1 || byte != 'G') anchor_exit();
    /* The daemon holds this thread at the successful syscall exit. */
    syscall(SYS_unshare, CLONE_FS | CLONE_FILES);
    anchor_exit();
}
int sigrun_spawn_self_connector(const struct sockaddr_un *public, const struct sockaddr_un *anchor, int *pidfd, int *control) {
    int pair[2];
    if (syscall(SYS_socketpair, AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, pair) < 0) return -1;
    struct clone_args args = {.flags=CLONE_PIDFD, .exit_signal=SIGCHLD, .pidfd=(uintptr_t)pidfd};
    int parent = syscall(SYS_getpid);
    long pid = syscall(SYS_clone3, &args, sizeof(args));
    if (pid==0) {
        syscall(SYS_close,pair[0]);
        connector(pair[1],public,anchor,parent);
    }
    int saved=errno;
    syscall(SYS_close,pair[1]);
    if (pid<0) syscall(SYS_close,pair[0]);
    else *control=pair[0];
    errno=saved;
    return pid;
}
