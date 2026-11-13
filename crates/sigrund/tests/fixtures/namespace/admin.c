#define _GNU_SOURCE
#include <fcntl.h>
#include <grp.h>
#include <linux/capability.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc == 3 && !strcmp(argv[1], "write")) {
        int fd = open(argv[2], O_WRONLY | O_TRUNC | O_CLOEXEC);
        if (fd < 0 || write(fd, "approved\n", 9) != 9 || close(fd)) return 2;
        return 0;
    }
    if (argc == 2 && !strcmp(argv[1], "hold")) {
        if (fork() < 0) return 2;
        for (;;) pause();
    }
    struct __user_cap_header_struct header = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct data[2] = {{0}};
    gid_t groups[256];
    int count = getgroups(256, groups);
    if (count < 0 || syscall(SYS_capget, &header, data)) return 2;
    printf("uid=%u gid=%u securebits=%d nnp=%d caps=%08x%08x groups=", getuid(), getgid(),
           prctl(PR_GET_SECUREBITS, 0, 0, 0, 0), prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0),
           data[1].effective, data[0].effective);
    for (int i = 0; i < count; i++) printf("%s%u", i ? "," : "", groups[i]);
    puts("");
    return 0;
}
