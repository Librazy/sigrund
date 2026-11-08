/* Root-only qualification interposition. Never linked into production, and
 * fresh-exec capture/preparation helpers intentionally clear LD_PRELOAD. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <sys/prctl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static char arm[4096];
static int entered = -1, release_fd = -1;
__attribute__((constructor)) static void initialize(void) {
    const char *value = getenv("SIGRUND_NAMESPACE_NO_PTRACE");
    if (value && !strcmp(value, "1")) {
        struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
        struct __user_cap_data_struct data[2] = {{0}};
        if (syscall(SYS_capget, &header, data) ||
            prctl(PR_CAPBSET_DROP, CAP_SYS_PTRACE, 0, 0, 0)) _exit(99);
        const unsigned index = CAP_SYS_PTRACE / 32, bit = CAP_SYS_PTRACE % 32;
        data[index].effective &= ~(1u << bit);
        data[index].permitted &= ~(1u << bit);
        data[index].inheritable &= ~(1u << bit);
        if (syscall(SYS_capset, &header, data)) _exit(99);
    }
    value = getenv("SIGRUND_NAMESPACE_ARM");
    if (value) snprintf(arm, sizeof(arm), "%s", value);
    value = getenv("SIGRUND_NAMESPACE_ENTERED");
    if (value) entered = atoi(value);
    value = getenv("SIGRUND_NAMESPACE_RELEASE");
    if (value) release_fd = atoi(value);
}

/* The arm file is operator-controlled and replaced between cases. Reading it
 * does not enter any target pathname or execute code supplied by a requester. */
static int setting(char *value, size_t capacity) {
    int fd = syscall(SYS_openat, AT_FDCWD, arm, O_RDONLY | O_CLOEXEC, 0);
    if (fd < 0) return 0;
    ssize_t length = syscall(SYS_read, fd, value, capacity - 1);
    syscall(SYS_close, fd);
    if (length <= 0) return 0;
    value[length] = 0;
    return 1;
}
static int take(void) {
    return syscall(SYS_unlinkat, AT_FDCWD, arm, 0) == 0;
}

ssize_t recvmsg(int fd, struct msghdr *message, int flags) {
    ssize_t result = syscall(SYS_recvmsg, fd, message, flags);
    int saved = errno;
    char value[128];
    if (result > 0 && setting(value, sizeof(value)) && !strcmp(value, "truncate")) {
        for (struct cmsghdr *item = CMSG_FIRSTHDR(message); item;
             item = CMSG_NXTHDR(message, item)) {
            if (item->cmsg_level != SOL_SOCKET || item->cmsg_type != SCM_RIGHTS ||
                item->cmsg_len != CMSG_LEN(2 * sizeof(int))) continue;
            int rights[2];
            memcpy(rights, CMSG_DATA(item), sizeof(rights));
            struct stat source, cwd;
            if (!fstat(rights[0], &source) && S_ISREG(source.st_mode) &&
                !fstat(rights[1], &cwd) && S_ISDIR(cwd.st_mode) && take()) {
                message->msg_flags |= MSG_CTRUNC;
                char byte = 't';
                syscall(SYS_write, entered, &byte, 1);
            }
        }
    }
    errno = saved;
    return result;
}

int close(int fd) {
    int saved = errno;
    char value[128];
    unsigned long long device, inode;
    struct stat status;
    if (setting(value, sizeof(value)) &&
        sscanf(value, "close %llu %llu", &device, &inode) == 2 &&
        !fstat(fd, &status) && (unsigned long long)status.st_dev == device &&
        (unsigned long long)status.st_ino == inode && take()) {
        char byte = 'c';
        syscall(SYS_write, entered, &byte, 1);
        ssize_t count;
        do { count = syscall(SYS_read, release_fd, &byte, 1); }
        while (count < 0 && errno == EINTR);
    }
    errno = saved;
    return syscall(SYS_close, fd);
}

/* Block an actual destination observation, leaving other workers/sequencer free. */
int fstat(int fd, struct stat *status) {
    int result = syscall(SYS_fstat, fd, status);
    int saved = errno;
    char value[128]; unsigned long long device, inode;
    if (!result && setting(value, sizeof(value)) &&
        sscanf(value, "stat %llu %llu", &device, &inode) == 2 &&
        (unsigned long long)status->st_dev == device &&
        (unsigned long long)status->st_ino == inode && take()) {
        char byte = 's'; ssize_t count;
        syscall(SYS_write, entered, &byte, 1);
        do { count = syscall(SYS_read, release_fd, &byte, 1); }
        while (count < 0 && errno == EINTR);
    }
    errno = saved;
    return result;
}
int statx(int dirfd, const char *path, int flags, unsigned mask, struct statx *status) {
    int result = syscall(SYS_statx, dirfd, path, flags, mask, status);
    int saved = errno;
    if (!result && (flags & AT_EMPTY_PATH) && path && !*path) {
        struct stat observed;
        (void)fstat(dirfd, &observed);
    }
    errno = saved;
    return result;
}
