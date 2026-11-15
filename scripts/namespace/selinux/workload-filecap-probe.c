#define _GNU_SOURCE
#include <fcntl.h>
#include <linux/capability.h>
#include <stdio.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

int main(void) {
    char context[256] = {0};
    int fd = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
    if (fd < 0 || read(fd, context, sizeof(context) - 1) <= 0) return 1;
    close(fd);
    context[strcspn(context, "\n")] = 0;
    struct stat self;
    if (stat("/proc/self/exe", &self)) return 2;
    struct __user_cap_header_struct header = {.version = _LINUX_CAPABILITY_VERSION_3};
    struct __user_cap_data_struct caps[2] = {{0}};
    if (syscall(SYS_capget, &header, caps)) return 3;
    unsigned long long ambient = 0, bounding = 0;
    for (unsigned cap = 0; cap <= CAP_CHECKPOINT_RESTORE; ++cap) {
        int a = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, cap, 0, 0);
        int b = prctl(PR_CAPBSET_READ, cap, 0, 0, 0);
        if (a < 0 || b < 0) return 4;
        ambient |= (unsigned long long)a << cap;
        bounding |= (unsigned long long)b << cap;
    }
    printf("{\"context\":\"%s\",\"uid\":%u,\"inode\":%llu,\"ambient\":%llu,\"bounding\":%llu,"
           "\"effective\":%llu,\"permitted\":%llu,\"inheritable\":%llu}\n",
           context, getuid(), (unsigned long long)self.st_ino, ambient, bounding,
           caps[0].effective | ((unsigned long long)caps[1].effective << 32),
           caps[0].permitted | ((unsigned long long)caps[1].permitted << 32),
           caps[0].inheritable | ((unsigned long long)caps[1].inheritable << 32));
    return 0;
}
