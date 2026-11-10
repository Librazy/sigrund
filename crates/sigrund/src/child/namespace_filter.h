#ifndef SIGRUND_NAMESPACE_FILTER_H
#define SIGRUND_NAMESPACE_FILTER_H
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
/* namespace-selinux.v1 binds this complete native-ABI program. No inferred or
 * copied target filter. x32 and every other audit architecture terminate. */
static const struct sock_filter sigrund_namespace_filter[] = {
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, arch)),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, AUDIT_ARCH_X86_64, 1, 0),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
    BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, 0x40000000, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS),
    BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 110, 0, 1),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 13),
    BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
};
#endif
