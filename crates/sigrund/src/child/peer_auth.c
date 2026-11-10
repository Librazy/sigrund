/* Authentication shared by the Rust client and its syscall-only connector.
 * No pathname is evidence of the caller's current user namespace. */
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <fcntl.h>
#include <linux/magic.h>
#include <linux/nsfs.h>
#include <linux/sched.h>
#include <sys/mman.h>
#include <sys/vfs.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#ifndef PIDFD_GET_USER_NAMESPACE
#define PIDFD_GET_USER_NAMESPACE _IO(0xff, 9)
#endif
static const char requester_context[] = "system_u:system_r:sigrund_requester_t:s0";
static const char producer_context[] = "system_u:system_r:sigrund_daemon_t:s0";
static const char host_context[] = "system_u:system_r:sigrund_host_workload_t:s0";
static const char workload_context[] = "system_u:system_r:sigrund_workload_t:s0:c1,c2";
#define INITIAL_USERNS_INO 0xeffffffdULL

/* Older pidfds cannot return a namespace FD. Treat procfs as an untrusted hint:
 * only nsfs may implement these ioctls (a FUSE ioctl can return an arbitrary FD
 * number). NS_GET_USERNS and NS_GET_PARENT enforce current_user_ns() ancestry
 * in ns_get_owner(). Obtaining init_user_ns through them
 * therefore proves the caller is initial-userns, even with substituted genuine
 * namespace files. A child retaining an initial netns FD gets EPERM.
 * See Linux kernel/user_namespace.c and fs/nsfs.c, present in Linux 6.8.
 */
static int initial_userns_from_hint(int hint) {
    struct statfs fs;
    int valid = syscall(SYS_fstatfs, hint, &fs) == 0 && fs.f_type == NSFS_MAGIC &&
                syscall(SYS_ioctl, hint, NS_GET_NSTYPE, 0) == CLONE_NEWNET;
    int userns = valid ? syscall(SYS_ioctl, hint, NS_GET_USERNS, 0) : -1;
    if (userns < 0) return 0;
    /* A host task may have joined a descendant-owned netns. Linux permits a
     * child of a level-32 parent: include level 33 and the initial namespace. */
    for (unsigned level = 0; level <= 33; ++level) {
        struct stat identity;
        if (syscall(SYS_fstatfs, userns, &fs) < 0 || fs.f_type != NSFS_MAGIC ||
            syscall(SYS_ioctl, userns, NS_GET_NSTYPE, 0) != CLONE_NEWUSER ||
            syscall(SYS_fstat, userns, &identity) < 0) break;
        if ((uint64_t)identity.st_ino == INITIAL_USERNS_INO) {
            syscall(SYS_close, userns);
            return 1;
        }
        int parent = syscall(SYS_ioctl, userns, NS_GET_PARENT, 0);
        syscall(SYS_close, userns);
        userns = parent;
        if (userns < 0) return 0;
    }
    syscall(SYS_close, userns);
    return 0;
}
static int initial_userns_compat(void) {
    int hint = syscall(SYS_openat, AT_FDCWD, "/proc/thread-self/ns/net",
                       O_RDONLY | O_CLOEXEC | O_NONBLOCK | O_NOCTTY, 0);
    if (hint < 0) return 0;
    int initial = initial_userns_from_hint(hint);
    syscall(SYS_close, hint);
    return initial;
}
static int kernel_file(const char *path, int flags) {
    int fd = syscall(SYS_openat, AT_FDCWD, path, flags | O_CLOEXEC | O_NOFOLLOW, 0);
    if (fd < 0) return -1;
    struct statfs fs;
    if (syscall(SYS_fstatfs, fd, &fs) < 0 || fs.f_type != 0xf97cff8c) {
        syscall(SYS_close, fd); errno = EPERM; return -1;
    }
    return fd;
}
static int label_is(int socket, const char *expected) {
    char actual[256] = {0}; socklen_t length = sizeof(actual);
    if (syscall(SYS_getsockopt, socket, SOL_SOCKET, SO_PEERSEC, actual, &length) < 0) return 0;
    size_t size = 0;
    while (expected[size]) ++size;
    if (size >= sizeof(actual) || (length != size && (length != size + 1 || actual[size]))) return 0;
    for (size_t i = 0; i < size; ++i) if (actual[i] != expected[i]) return 0;
    return 1;
}
/* Read the kernel's AV-decision flags. Global enforcement alone also permits
 * per-domain permissive mode; a permissive requester could forge socket SIDs.
 * All files are checked as selinuxfs, independently of the source root tree.
 * Keep this syscall-only: the disposable connector calls it after fork. */
static int domain_enforcing(const char *context) {
    int fd = kernel_file("/sys/fs/selinux/class/process/index", O_RDONLY);
    if (fd < 0) return 0;
    char number[32] = {0};
    ssize_t size = syscall(SYS_read, fd, number, sizeof(number));
    syscall(SYS_close, fd);
    if (size <= 0 || size >= (ssize_t)sizeof(number)) return 0;
    size_t digits = 0; unsigned cls = 0;
    while (digits < (size_t)size && number[digits] >= '0' && number[digits] <= '9') {
        cls = cls * 10 + (unsigned)(number[digits++] - '0');
        if (cls > 65535) return 0;
    }
    if (!cls || !digits || (digits != (size_t)size && !(digits + 1 == (size_t)size && number[digits] == '\n'))) return 0;
    char query[256]; size_t used = 0;
    for (unsigned copy = 0; copy < 2; ++copy) {
        for (size_t i = 0; context[i]; ++i) {
            if (used >= sizeof(query) - 1) return 0;
            query[used++] = context[i];
        }
        query[used++] = ' ';
    }
    for (size_t i = 0; i < digits; ++i) query[used++] = number[i];
    query[used++] = ' '; query[used++] = '0';
    fd = kernel_file("/sys/fs/selinux/access", O_RDWR);
    if (fd < 0) return 0;
    if (syscall(SYS_write, fd, query, used) != (ssize_t)used) { syscall(SYS_close, fd); return 0; }
    char reply[256];
    size = syscall(SYS_read, fd, reply, sizeof(reply));
    syscall(SYS_close, fd);
    if (size <= 0 || size >= (ssize_t)sizeof(reply)) return 0;
    size_t cursor = 0;
    for (unsigned field = 0; field < 6; ++field) {
        while (cursor < (size_t)size && (reply[cursor] == ' ' || reply[cursor] == '\n')) ++cursor;
        size_t start = cursor;
        while (cursor < (size_t)size && reply[cursor] != ' ' && reply[cursor] != '\n') {
            char c = reply[cursor++];
            if (!((c >= '0' && c <= '9') || (field != 4 && c >= 'a' && c <= 'f'))) return 0;
            if (field == 5 && c != '0') return 0;
        }
        if (cursor == start) return 0;
    }
    while (cursor < (size_t)size && (reply[cursor] == ' ' || reply[cursor] == '\n')) ++cursor;
    return cursor == (size_t)size;
}
/* Values are kernel-reported socket object labels, never pathname labels.
 * The trusted host policy must reserve these types without broad socket/domain
 * attributes or untrusted create/relabel permission. Profile names alone do
 * not establish that deployment invariant. */
static int labeled_peer(int socket, unsigned role) {
    static const char *labels[] = {
        "system_u:object_r:sigrund_execution_socket_t:s0",
        "system_u:object_r:sigrund_context_socket_t:s0",
        "system_u:object_r:sigrund_anchor_socket_t:s0"
    };
    if (role >= 3) { errno = EINVAL; return -1; }
    int self[2];
    if (syscall(SYS_socketpair, AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, self) < 0) return -1;
    int source = label_is(self[0], requester_context);
    syscall(SYS_close, self[0]); syscall(SYS_close, self[1]);
    if (!source) { errno = EPERM; return -1; }
    int status = kernel_file("/sys/fs/selinux/status", O_RDONLY);
    if (status < 0) return -1;
    volatile uint32_t *page = (volatile uint32_t *)syscall(SYS_mmap, NULL, 4096, PROT_READ, MAP_SHARED, status, 0);
    syscall(SYS_close, status);
    if (page == MAP_FAILED) return -1;
    int valid = 0;
    for (unsigned tries = 0; tries < 10000; ++tries) {
        uint32_t before = __atomic_load_n(&page[1], __ATOMIC_ACQUIRE);
        if (before & 1) continue;
        uint32_t version = page[0], enforcing = page[2], policyload = page[3];
        int authenticated = domain_enforcing(requester_context) && domain_enforcing(producer_context) && domain_enforcing(host_context) && domain_enforcing(workload_context) && label_is(socket, labels[role]);
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
        uint32_t after = __atomic_load_n(&page[1], __ATOMIC_ACQUIRE);
        if (before != after || policyload != page[3]) continue;
        valid = version == 1 && enforcing == 1 && authenticated;
        break;
    }
    syscall(SYS_munmap, (void *)page, 4096);
    if (!valid) { errno = EPERM; return -1; }
    return 0;
}
int sigrun_authenticate_host_peer(int socket, unsigned role) {
    int pidfd = syscall(SYS_pidfd_open, syscall(SYS_getpid), 0);
    if (pidfd < 0) return -1;
    int userns = syscall(SYS_ioctl, pidfd, PIDFD_GET_USER_NAMESPACE, 0);
    int saved = errno;
    syscall(SYS_close, pidfd);
    int initial;
    if (userns < 0) {
        if (saved != ENOTTY) { errno = saved; return -1; }
        initial = initial_userns_compat();
    } else {
        struct stat identity;
        int result = syscall(SYS_fstat, userns, &identity);
        saved = errno;
        syscall(SYS_close, userns);
        if (result < 0) { errno = saved; return -1; }
        initial = (uint64_t)identity.st_ino == INITIAL_USERNS_INO;
    }
    if (!initial) return labeled_peer(socket, role);
    struct ucred peer;
    socklen_t length = sizeof(peer);
    if (syscall(SYS_getsockopt, socket, SOL_SOCKET, SO_PEERCRED, &peer, &length) < 0) return -1;
    if (length != sizeof(peer) || peer.pid < 0 || peer.uid != 0) { errno = EPERM; return -1; }
    return 0;
}
