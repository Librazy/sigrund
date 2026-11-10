/* Exercise the production proof with real nsfs FDs and old-kernel behavior. */
#define _GNU_SOURCE
#include "../../../src/child/peer_auth.c"
#include <assert.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <grp.h>

static void older_pidfd(int error) {
    struct sock_filter filters[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, SYS_ioctl, 0, 3),
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, args[1])),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, PIDFD_GET_USER_NAMESPACE, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | error),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog program = {.len = sizeof(filters) / sizeof(filters[0]), .filter = filters};
    assert(prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
    assert(prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program) == 0);
}
static void mapping(const char *path, const char *value) {
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    assert(fd >= 0);
    assert(write(fd, value, strlen(value)) == (ssize_t)strlen(value));
    assert(close(fd) == 0);
}
static void child_namespace(void) {
    char uid[64], gid[64];
    snprintf(uid, sizeof(uid), "0 %u 1\n", (unsigned)getuid());
    snprintf(gid, sizeof(gid), "0 %u 1\n", (unsigned)getgid());
    assert(unshare(CLONE_NEWUSER) == 0);
    mapping("/proc/self/setgroups", "deny");
    mapping("/proc/self/uid_map", uid);
    mapping("/proc/self/gid_map", gid);
    assert(getuid() == 0);
}
static void rejected_root_peer(void) {
    int pair[2];
    assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0);
    struct ucred peer;
    socklen_t size = sizeof(peer);
    assert(getsockopt(pair[0], SOL_SOCKET, SO_PEERCRED, &peer, &size) == 0 && peer.uid == 0);
    for (unsigned role = 0; role < 4; ++role)
        assert(sigrun_authenticate_host_peer(pair[0], role) == -1);
    close(pair[0]); close(pair[1]);
}
int main(int argc, char **argv) {
    assert(argc >= 2);
    if (!strcmp(argv[1], "exec")) {
        assert(argc >= 3);
        older_pidfd(ENOTTY);
        execvp(argv[2], argv + 2);
        return 2;
    }
    if (!strcmp(argv[1], "host-user") || !strcmp(argv[1], "host-root") || !strcmp(argv[1], "denied")) {
        assert(getuid() == 0);
        int pair[2];
        assert(socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, pair) == 0);
        if (!strcmp(argv[1], "host-user")) {
            assert(setgroups(0, NULL) == 0 && setgid(65534) == 0 && setuid(65534) == 0);
        }
        int denied = !strcmp(argv[1], "denied");
        older_pidfd(denied ? EPERM : ENOTTY);
        for (unsigned role = 0; role < 4; ++role) {
            int result = sigrun_authenticate_host_peer(pair[0], role);
            assert(denied ? result == -1 : result == 0);
        }
        close(pair[0]); close(pair[1]);
        puts("host peer roles passed");
        return 0;
    }
    int deep = !strcmp(argv[1], "deep-proof");
    assert(deep || !strcmp(argv[1], "proof"));
    int net = open("/proc/thread-self/ns/net", O_RDONLY | O_CLOEXEC);
    int user = open("/proc/thread-self/ns/user", O_RDONLY | O_CLOEXEC);
    int ordinary = memfd_create("not-nsfs", MFD_CLOEXEC);
    assert(net >= 0 && user >= 0 && ordinary >= 0);
    assert(initial_userns_from_hint(net) == 1);
    assert(initial_userns_from_hint(user) == 0); /* Wrong namespace kind. */
    assert(initial_userns_from_hint(ordinary) == 0); /* Untrusted filesystem. */
    assert(initial_userns_from_hint(-1) == 0);
    int transfer[2];
    assert(socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, transfer) == 0);
    pid_t child = fork();
    assert(child >= 0);
    if (!child) {
        close(transfer[0]);
        child_namespace();
        if (deep) {
            for (unsigned level = 1; level < 33; ++level) child_namespace();
        }
        /* This genuine initial netns is inherited, exactly like a substituted
         * procfs namespace file. Its kernel ioctl must not prove host scope. */
        assert(initial_userns_from_hint(net) == 0);
        older_pidfd(ENOTTY);
        rejected_root_peer();
        assert(unshare(CLONE_NEWNET) == 0);
        int own = open("/proc/thread-self/ns/net", O_RDONLY | O_CLOEXEC);
        assert(own >= 0 && initial_userns_from_hint(own) == 0);
        rejected_root_peer();
        char byte = 'N';
        struct iovec iov = {.iov_base = &byte, .iov_len = 1};
        union { struct cmsghdr alignment; char bytes[CMSG_SPACE(sizeof(int))]; } ancillary = {0};
        struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
                                .msg_control = ancillary.bytes, .msg_controllen = sizeof(ancillary.bytes)};
        struct cmsghdr *header = CMSG_FIRSTHDR(&message);
        header->cmsg_level = SOL_SOCKET; header->cmsg_type = SCM_RIGHTS; header->cmsg_len = CMSG_LEN(sizeof(int));
        *(int *)CMSG_DATA(header) = own;
        assert(sendmsg(transfer[1], &message, 0) == 1);
        close(own);
        _exit(0);
    }
    close(transfer[1]);
    char byte;
    struct iovec iov = {.iov_base = &byte, .iov_len = 1};
    union { struct cmsghdr alignment; char bytes[CMSG_SPACE(sizeof(int))]; } ancillary = {0};
    struct msghdr message = {.msg_iov = &iov, .msg_iovlen = 1,
                            .msg_control = ancillary.bytes, .msg_controllen = sizeof(ancillary.bytes)};
    assert(recvmsg(transfer[0], &message, 0) == 1 && byte == 'N' && !message.msg_flags);
    struct cmsghdr *header = CMSG_FIRSTHDR(&message);
    assert(header && header->cmsg_level == SOL_SOCKET && header->cmsg_type == SCM_RIGHTS &&
           header->cmsg_len == CMSG_LEN(sizeof(int)) && !CMSG_NXTHDR(&message, header));
    int descendant = *(int *)CMSG_DATA(header);
    assert(initial_userns_from_hint(descendant) == 1); /* Host task, child-owned netns. */
    close(descendant); close(transfer[0]);
    int status;
    assert(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    close(net); close(user); close(ordinary);
    puts("initial, inherited ancestor, child-owned and invalid hints passed");
    return 0;
}
