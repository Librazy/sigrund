#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/vfs.h>
#include <unistd.h>

/* Parent-side only. Never call libselinux in the post-clone child. */
int sigrund_domain_enforcing(const char *context) {
    struct decision { uint32_t allowed, decided, auditallow, auditdeny, seqno, flags; } decision;
    void *library = dlopen("libselinux.so.1", RTLD_NOW | RTLD_LOCAL);
    if (!library) { errno = ENOTSUP; return -1; }
    unsigned short (*class_number)(const char *) = dlsym(library, "string_to_security_class");
    int (*compute)(const char *, const char *, unsigned short, unsigned, struct decision *) =
        dlsym(library, "security_compute_av_flags_raw");
    int result = -1;
    if (class_number && compute) {
        unsigned short process = class_number("process");
        if (process && compute(context, context, process, 0, &decision) == 0)
            result = !(decision.flags & 1);
    }
    dlclose(library);
    if (result < 0) errno = ENOTSUP;
    return result;
}

/* A retained kernel status mapping has no destination filesystem dependency.
 * Its immutable baseline is checked with bounded seqlock retries on hot paths. */
int sigrund_policy_token(const uint32_t *page, uint64_t *token) {
    for (unsigned tries = 0; tries < 10000; ++tries) {
        uint32_t sequence = __atomic_load_n(page + 1, __ATOMIC_ACQUIRE);
        if (sequence & 1) continue;
        uint32_t version = __atomic_load_n(page, __ATOMIC_RELAXED);
        uint32_t enforcing = __atomic_load_n(page + 2, __ATOMIC_RELAXED);
        uint32_t policyload = __atomic_load_n(page + 3, __ATOMIC_RELAXED);
        __atomic_thread_fence(__ATOMIC_SEQ_CST);
        if (sequence != __atomic_load_n(page + 1, __ATOMIC_ACQUIRE)) continue;
        if (version != 1 || enforcing != 1) { errno = EPERM; return -1; }
        *token = ((uint64_t)sequence << 32) | policyload;
        return 0;
    }
    errno = EAGAIN; return -1;
}
void *sigrund_policy_map(void) {
    int fd = open("/sys/fs/selinux/status", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return MAP_FAILED;
    struct statfs fs;
    if (fstatfs(fd, &fs) < 0 || fs.f_type != 0xf97cff8c) {
        close(fd); errno = EPERM; return MAP_FAILED;
    }
    void *page = mmap(NULL, 4096, PROT_READ, MAP_SHARED, fd, 0);
    int saved = errno; close(fd); errno = saved;
    return page;
}

#include <string.h>
int sigrund_socket_label(const char *context) {
    int fd = open("/proc/thread-self/attr/sockcreate", O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    size_t length = context ? strlen(context) : 0;
    ssize_t written = write(fd, context, length);
    int saved = errno;
    close(fd);
    if (written != (ssize_t)length) { errno = written < 0 ? saved : EIO; return -1; }
    return 0;
}

/* Check required transition permissions before accepting a production profile.
 * A valid, enforcing target context alone does not prove NNP/ptrace entry. */
int sigrund_lsm_allowed(const char *source, const char *target, const char *class_name, const char *permissions) {
    struct decision { uint32_t allowed, decided, auditallow, auditdeny, seqno, flags; } decision;
    void *library = dlopen("libselinux.so.1", RTLD_NOW | RTLD_LOCAL);
    if (!library) { errno = ENOTSUP; return -1; }
    unsigned short (*class_number)(const char *) = dlsym(library, "string_to_security_class");
    uint32_t (*permission_number)(unsigned short, const char *) = dlsym(library, "string_to_av_perm");
    int (*compute)(const char *, const char *, unsigned short, unsigned, struct decision *) =
        dlsym(library, "security_compute_av_flags_raw");
    int result = -1;
    if (class_number && permission_number && compute && strlen(permissions) < 256) {
        unsigned short cls = class_number(class_name);
        uint32_t requested = 0;
        char names[256]; strcpy(names, permissions);
        char *cursor = NULL;
        int valid = cls != 0;
        for (char *name = strtok_r(names, ",", &cursor); name; name = strtok_r(NULL, ",", &cursor)) {
            uint32_t bit = permission_number(cls, name);
            if (!bit) valid = 0;
            requested |= bit;
        }
        if (valid && requested && compute(source, target, cls, requested, &decision) == 0 &&
            !(decision.flags & 1) && (decision.allowed & requested) == requested) result = 0;
    }
    dlclose(library);
    if (result < 0) errno = EPERM;
    return result;
}
