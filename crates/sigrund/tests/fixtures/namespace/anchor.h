/* Test anchor handshake shared by review and execution fixtures. */
#ifndef SIGRUND_TEST_ANCHOR_H
#define SIGRUND_TEST_ANCHOR_H
#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <sched.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>
#define COUNT(a) (sizeof(a) / sizeof((a)[0]))
#define MUST(x) do { if (!(x)) { perror(#x); exit(1); } } while (0)

static void anchor(const char *path) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    struct sockaddr_un address = {.sun_family = AF_UNIX};
    MUST(strlen(path) < sizeof(address.sun_path));
    strcpy(address.sun_path, path);
    MUST(fd >= 0 && connect(fd, (void *)&address, sizeof(address)) == 0);
    MUST(write(fd, "H", 1) == 1);
    char byte;
    MUST(read(fd, &byte, 1) == 1);
    syscall(SYS_unshare, CLONE_FS | CLONE_FILES);
    _exit(90); /* Capture must retain the task at the unshare syscall exit. */
}
#endif
