/* Exercise the actual entry helper inside an unprivileged disposable userns. */
#define main phase0_probe_main
#ifndef PHASE0_PROBE_SOURCE
#define PHASE0_PROBE_SOURCE "../../../../scripts/namespace-phase0/probe.c"
#endif
#include PHASE0_PROBE_SOURCE
#undef main

int main(int argc, char **argv) {
    MUST(argc == 2);
    alarm(10);
    MUST(unshare(CLONE_NEWNS) == 0);
    MUST(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == 0);
    MUST(mount(argv[1], argv[1], NULL, MS_BIND, NULL) == 0);
    struct target target = {0};
    target.root = open(argv[1], O_PATH | O_DIRECTORY | O_CLOEXEC); MUST(target.root >= 0);
    for (size_t i = 0; i < COUNT(names); i++) {
        char path[64]; snprintf(path, sizeof(path), "/proc/self/ns/%s", names[i]);
        target.ns[i] = open(path, O_RDONLY | O_CLOEXEC); MUST(target.ns[i] >= 0);
    }
    join_target(&target);
    int current_root = open("/", O_PATH | O_DIRECTORY | O_CLOEXEC); MUST(current_root >= 0);
    verify_private_mount(current_root, target.root);
    puts("{\"private_mount_visible\":true,\"anchor_mount_unchanged\":true}");
    return 0;
}
