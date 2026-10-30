/* Test-only fstat interposer: block metadata for one explicitly selected inode
 * until the parent releases it. No production daemon test hooks are needed. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static void gate(uint64_t inode, uint64_t device) {
    const char *match_inode = getenv("SIGRUND_GATE_INODE");
    const char *match_device = getenv("SIGRUND_GATE_DEVICE");
    if (!match_inode || !match_device || inode != strtoull(match_inode, 0, 10)
        || device != strtoull(match_device, 0, 10)) return;
    int entered = atoi(getenv("SIGRUND_GATE_ENTERED_FD"));
    int release = atoi(getenv("SIGRUND_GATE_RELEASE_FD"));
    uint64_t tid = syscall(SYS_gettid);
    ssize_t count;
    do { count = syscall(SYS_write, entered, &tid, sizeof(tid)); }
    while (count < 0 && errno == EINTR);
    char byte;
    do { count = syscall(SYS_read, release, &byte, 1); }
    while (count < 0 && errno == EINTR);
}

int fstat(int fd, struct stat *metadata) {
    int result = syscall(SYS_fstat, fd, metadata);
    if (result == 0 && !getenv("SIGRUND_GATE_CLOSE")) gate(metadata->st_ino, metadata->st_dev);
    return result;
}

int fstat64(int fd, struct stat64 *metadata) {
    int result = syscall(SYS_fstat, fd, metadata);
    if (result == 0 && !getenv("SIGRUND_GATE_CLOSE")) gate(metadata->st_ino, metadata->st_dev);
    return result;
}

int close(int fd) {
    struct stat metadata;
    if (getenv("SIGRUND_GATE_CLOSE") && syscall(SYS_fstat, fd, &metadata) == 0)
        gate(metadata.st_ino, metadata.st_dev);
    return syscall(SYS_close, fd);
}
