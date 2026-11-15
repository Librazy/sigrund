#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <netinet/in.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

static int create_file(const char *path) {
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) return 0;
    int ok = write(fd, "approved workload\n", 18) == 18;
    close(fd);
    unlink(path);
    return ok;
}
static int tcp(void) {
    int listener = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (listener < 0) return 0;
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t size = sizeof(address);
    int ok = !bind(listener, (void *)&address, size) && !listen(listener, 1)
        && !getsockname(listener, (void *)&address, &size);
    int client = socket(AF_INET, SOCK_STREAM | SOCK_CLOEXEC, 0);
    ok = ok && client >= 0 && !connect(client, (void *)&address, size);
    int peer = ok ? accept4(listener, NULL, NULL, SOCK_CLOEXEC) : -1;
    ok = ok && peer >= 0 && write(client, "x", 1) == 1;
    char byte = 0;
    ok = ok && read(peer, &byte, 1) == 1 && byte == 'x';
    if (peer >= 0) close(peer);
    if (client >= 0) close(client);
    close(listener);
    return ok;
}
static int udp(void) {
    int server = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    if (server < 0) return 0;
    struct sockaddr_in address = {.sin_family = AF_INET, .sin_addr.s_addr = htonl(INADDR_LOOPBACK)};
    socklen_t size = sizeof(address);
    int ok = !bind(server, (void *)&address, size) && !getsockname(server, (void *)&address, &size);
    int client = socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
    ok = ok && client >= 0 && sendto(client, "x", 1, 0, (void *)&address, size) == 1;
    char byte = 0;
    ok = ok && recv(server, &byte, 1, MSG_DONTWAIT) == 1 && byte == 'x';
    if (client >= 0) close(client);
    close(server);
    return ok;
}
int main(int argc, char **argv) {
    if (argc != 3) return 64;
    char context[256] = {0};
    int fd = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC);
    if (fd < 0 || read(fd, context, sizeof(context) - 1) <= 0) return 65;
    close(fd);
    context[strcspn(context, "\n")] = 0;
    struct __user_cap_header_struct header = { .version = _LINUX_CAPABILITY_VERSION_3 };
    struct __user_cap_data_struct caps[2] = {{0}};
    if (syscall(SYS_capget, &header, caps)) return 66;
    char data[256], system[256];
    if (snprintf(data, sizeof(data), "/srv/sigrund-workloads/data/%s", argv[2]) >= (int)sizeof(data)
        || snprintf(system, sizeof(system), "/etc/sigrund-workload-%s", argv[2]) >= (int)sizeof(system)) return 67;
    int data_write = create_file(data), system_write = create_file(system), network = tcp(), datagram = udp();
    int sys_admin = !!(caps[0].effective & (1U << CAP_SYS_ADMIN));
    int mounted = 0;
    if (sys_admin && !unshare(CLONE_NEWNS)) {
        if (!mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)) {
            mkdir("/srv/sigrund-workloads/mount", 0700);
            mounted = !mount("tmpfs", "/srv/sigrund-workloads/mount", "tmpfs", MS_NOSUID | MS_NODEV, "size=4096");
            if (mounted) umount("/srv/sigrund-workloads/mount");
        }
    }
    printf("{\"context\":\"%s\",\"uid\":%u,\"data_write\":%s,\"system_write\":%s,\"tcp\":%s,\"udp\":%s,\"sys_admin\":%s,\"mount\":%s}\n",
        context, getuid(), data_write ? "true" : "false", system_write ? "true" : "false",
        network ? "true" : "false", datagram ? "true" : "false", sys_admin ? "true" : "false", mounted ? "true" : "false");
    int root = !strcmp(argv[1], "root"), maintenance = !strcmp(argv[1], "maintenance");
    char expected[256];
    snprintf(expected, sizeof(expected), "system_u:system_r:sigrund_%s_workload_t:s0", argv[1]);
    return !(data_write && system_write == (root || maintenance) && network == (strcmp(argv[1], "data") != 0)
        && datagram == (strcmp(argv[1], "data") != 0) && sys_admin == root && mounted == root && !strcmp(context, expected));
}
