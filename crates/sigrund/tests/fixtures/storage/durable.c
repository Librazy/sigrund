/* Test-only gates around real syscalls. No production environment switches. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

static int selected(const char *point) {
    const char *mode = getenv("SIGRUND_DURABLE_POINT");
    const char *arm = getenv("SIGRUND_DURABLE_ARM");
    if (!mode || !arm || strcmp(point, mode)) return 0;
    /* Only the first matching operation after explicit parent arming gates. */
    return syscall(SYS_unlink, arm) == 0;
}
static void gate(void) {
    uint64_t tid = syscall(SYS_gettid);
    int entered = atoi(getenv("SIGRUND_DURABLE_ENTERED"));
    int release = atoi(getenv("SIGRUND_DURABLE_RELEASE"));
    ssize_t n;
    do { n = syscall(SYS_write, entered, &tid, sizeof(tid)); } while (n < 0 && errno == EINTR);
    char byte;
    do { n = syscall(SYS_read, release, &byte, 1); } while (n < 0 && errno == EINTR);
}
static int suffix(int fd, const char *ending) {
    char link[64], target[4096];
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t n = syscall(SYS_readlink, link, target, sizeof(target));
    size_t length = strlen(ending);
    return n >= (ssize_t)length && !memcmp(target + n - length, ending, length);
}
static void predicate_gate(int fd) {
    char name[16] = {0}, link[64], target[4096];
    syscall(SYS_prctl, PR_GET_NAME, name, 0, 0, 0);
    if (strncmp(name, "authorization-a", 15)) return;
    snprintf(link, sizeof(link), "/proc/self/fd/%d", fd);
    ssize_t n = syscall(SYS_readlink, link, target, sizeof(target)-1);
    if (n < 0) return;
    target[n] = 0;
    if (strstr(target,"memfd:sigrun-executable") && selected("predicate-before")) gate();
}
ssize_t pread(int fd, void *buffer, size_t length, off_t offset) {
    predicate_gate(fd);
    return syscall(SYS_pread64,fd,buffer,length,offset);
}
ssize_t pread64(int fd, void *buffer, size_t length, off64_t offset) {
    predicate_gate(fd);
    return syscall(SYS_pread64,fd,buffer,length,offset);
}
ssize_t recv(int fd, void *buffer, size_t length, int flags) {
    char name[16] = {0};
    syscall(SYS_prctl, PR_GET_NAME, name, 0, 0, 0);
    int executor = !strncmp(name, "authorization-a", 15) && (flags & MSG_PEEK);
    if (executor && selected("peek-before")) gate();
    ssize_t n = syscall(SYS_recvfrom, fd, buffer, length, flags, 0, 0);
    int error = errno;
    if (executor && selected("peek-after")) gate();
    errno = error;
    return n;
}
static int synchronize(int fd, int data) {
    int wal = suffix(fd, "/state.sqlite-wal");
    int log = suffix(fd, "/audit.jsonl");
    if (wal && selected("wal-before")) gate();
    if (log && selected("audit-before")) gate();
    if (wal && selected("wal-fail")) {
        gate();
        errno = EIO;
        return -1;
    }
    int result = syscall(data ? SYS_fdatasync : SYS_fsync, fd);
    int error = errno;
    if (wal && selected("wal-after")) gate();
    errno = error;
    return result;
}
int fsync(int fd) { return synchronize(fd, 0); }
int fdatasync(int fd) { return synchronize(fd, 1); }
int renameat(int olddir, const char *oldname, int newdir, const char *newname) {
    if (!strcmp(oldname, "audit_ratchet.state.tmp") && selected("state-fail")) {
        gate();
        errno = EIO;
        return -1;
    }
    return syscall(SYS_renameat, olddir, oldname, newdir, newname);
}
