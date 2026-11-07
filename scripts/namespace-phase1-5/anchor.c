/* Fixture-only G-01 capture, with pidfd verification before EXITKILL. */
#define main phase0_probe_main
#include "../namespace-phase0/probe.c"
#undef main

static int capture_private_fs(struct target *target, int socket) {
    unsigned long options = PTRACE_O_TRACESYSGOOD | PTRACE_O_TRACEEXEC
        | PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK;
    MUST(ptrace(PTRACE_SEIZE, target->pid, 0, options) == 0);
    MUST(ptrace(PTRACE_INTERRUPT, target->pid, 0, 0) == 0);
    stopped(target->pid);
    if (!live(target->pidfd)) {
        MUST(ptrace(PTRACE_DETACH, target->pid, 0, 0) == 0);
        return 0;
    }
    MUST(ptrace(PTRACE_SETOPTIONS, target->pid, 0, options | PTRACE_O_EXITKILL) == 0);
    if (!live(target->pidfd)) return 0;
    if (field(target->pid, "Threads:") != 1 || field(target->pid, "Seccomp:") != 0) return 0;
    if (!ids_match(target->pid, "Uid:", target->peer.uid) || !ids_match(target->pid, "Gid:", target->peer.gid)
        || !groups_match(target->pid, socket)) return 0;
    MUST(write(socket, "G", 1) == 1);
    int entered = 0;
    for (int step = 0; step < 8; step++) {
        MUST(ptrace(PTRACE_SYSCALL, target->pid, 0, 0) == 0);
        int status; MUST(waitpid(target->pid, &status, __WALL) == target->pid);
        if (!live(target->pidfd)) return 0;
        if (!WIFSTOPPED(status) || WSTOPSIG(status) != (SIGTRAP | 0x80) || (status >> 16) != 0) return 0;
        struct ptrace_syscall_info info = {0};
        MUST(ptrace(PTRACE_GET_SYSCALL_INFO, target->pid, sizeof(info), &info) > 0);
        if (info.op == PTRACE_SYSCALL_INFO_ENTRY) {
            if (info.entry.nr == SYS_read && !entered) continue;
            if (info.entry.nr != SYS_unshare || entered || info.arch != AUDIT_ARCH_X86_64) return 0;
            struct user_regs_struct registers;
            MUST(ptrace(PTRACE_GETREGS, target->pid, 0, &registers) == 0);
            registers.rdi = CLONE_FS | CLONE_FILES;
            MUST(ptrace(PTRACE_SETREGS, target->pid, 0, &registers) == 0);
            entered = 1;
        } else if (info.op == PTRACE_SYSCALL_INFO_EXIT && entered) {
            if (info.exit.is_error || info.exit.rval != 0) return 0;
            return 1; /* Leave the task stopped at this exact syscall exit. */
        }
    }
    return 0;
}

static void serve_existing(const char *path) {
    int before = fd_count();
    int listener = socket_listener(path);
    /* Only the deliberately selected owner can reach the rendezvous. */
    const char *owner = getenv("PHASE15_OWNER_UID");
    MUST(owner != NULL);
    MUST(chown(path, (uid_t)strtoul(owner, NULL, 10), (gid_t)-1) == 0);
    MUST(chmod(path, 0600) == 0);
    puts("{\"event\":\"listening\"}");
    int socket = accept4(listener, NULL, NULL, SOCK_CLOEXEC); MUST(socket >= 0);
    struct target target = {.mutator = -1};
    target.peer = credentials(socket, &target.pidfd);
    target.pid = target.peer.pid;
    target.wrapper = target.pid; /* The tracer reaps its own tracee. */
    MUST(target.peer.uid == (uid_t)strtoul(owner, NULL, 10));
    target.groups_size = sizeof(target.groups);
    MUST(getsockopt(socket, SOL_SOCKET, SO_PEERGROUPS, target.groups, &target.groups_size) == 0
         && target.groups_size % sizeof(unsigned) == 0);
    socklen_t label_size = sizeof(target.connector_label) - 1;
    int result = getsockopt(socket, SOL_SOCKET, SO_PEERSEC, target.connector_label, &label_size);
    MUST(result == 0 || errno == ENOPROTOOPT);
    if (result == 0) target.connector_label[label_size] = 0;
    char byte; MUST(read(socket, &byte, 1) == 1 && byte == 'H');
    MUST(capture_private_fs(&target, socket));
    pin(&target);
    close(socket); close(listener); MUST(unlink(path) == 0);
    char setgroups[sizeof(target.setgroups)];
    memcpy(setgroups, target.setgroups, sizeof(setgroups));
    print_acquisition(&target); putchar('\n');
    /* The historical printer trims its display copy in place. */
    memcpy(target.setgroups, setgroups, sizeof(setgroups));
    while (read(STDIN_FILENO, &byte, 1) == 1) {
        if (byte == 'L') {
            int alive = live(target.pidfd);
            if (alive) revalidate(&target);
            printf("{\"live\":%s}\n", alive ? "true" : "false");
        } else if (byte == 'K') {
            MUST(syscall(SYS_pidfd_send_signal, target.pidfd, SIGKILL, NULL, 0) == 0);
            siginfo_t information = {0};
            MUST(waitid(P_PID, (id_t)target.pid, &information, WEXITED | WNOWAIT | __WALL) == 0);
            MUST(!live(target.pidfd));
            puts("{\"anchor_exited\":true}");
        } else if (byte == 'D') {
            destroy_target(&target, 1);
            MUST(fd_count() == before);
            puts("{\"cleanup_complete\":true,\"fd_count_restored\":true}");
            return;
        } else MUST(0);
    }
    destroy_target(&target, 1);
    MUST(fd_count() == before);
}
int main(int argc, char **argv) {
    MUST(setvbuf(stdout, NULL, _IONBF, 0) == 0);
    if (argc == 2 && !strcmp(argv[1], "stale-peer")) {
        MUST(getuid() == 0);
        pid_t original = fork(); MUST(original >= 0);
        if (!original) { for (;;) pause(); }
        int original_fd = syscall(SYS_pidfd_open, original, 0); MUST(original_fd >= 0);
        MUST(kill(original, SIGKILL) == 0);
        int status; MUST(waitpid(original, &status, 0) == original);
        pid_t victim = fork(); MUST(victim >= 0);
        if (!victim) { for (;;) pause(); }
        pid_t tracer = fork(); MUST(tracer >= 0);
        if (!tracer) {
            struct target target = {.pid = victim, .pidfd = original_fd};
            MUST(!capture_private_fs(&target, -1));
            _exit(0);
        }
        MUST(waitpid(tracer, &status, 0) == tracer && status == 0);
        MUST(waitpid(victim, &status, WNOHANG) == 0 && kill(victim, 0) == 0);
        MUST(kill(victim, SIGKILL) == 0 && waitpid(victim, &status, 0) == victim);
        close(original_fd);
        puts("{\"stale_peer_rejected\":true,\"unrelated_process_survived\":true}");
        return 0;
    }
    if (argc == 3 && !strcmp(argv[1], "capture")) {
        MUST(getuid() == 0);
        alarm(90);
        serve_existing(argv[2]);
        return 0;
    }
    if (argc == 3 && !strcmp(argv[1], "init")) {
        MUST(getpid() == 1 && chdir("/") == 0);
        pid_t child = fork(); MUST(child >= 0);
        if (child == 0) { anchor(argv[2], 0); _exit(1); }
        int status; MUST(waitpid(child, &status, 0) == child);
        return WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL ? 0 : 1;
    }
    fprintf(stderr, "usage: anchor capture HOST_SOCKET | init CONTAINER_SOCKET\n");
    return 2;
}
