# Phase 5B: child transition and readiness evidence

The clone/exec boundary lives in `src/child/setup.c`, compiled by `build.rs`.
Rust prepares argv/envp, groups, cwd and bounded mountinfo/read-back buffers.
After `clone3` returns in the child, C runs the transition and exits or execs
without returning to Rust, allocating, logging, locking or unwinding.

The clone uses `CLONE_INTO_CGROUP | CLONE_PIDFD`, the separate `SIGCHLD`
exit-signal field, and `CLONE_NEWNS | CLONE_NEWCGROUP` for the MVP profile.
The full ten-step path installs descriptors 0–4, closes 5+, locks the private
cgroup mount, resets signals, creates a session, installs cwd/umask, reduces
bounding capabilities, sets securebits/groups/IDs and P/E/I/ambient sets,
locks no_new_privs, and verifies the result before issuing the readiness token.
The sync writer is tracked from its actual inherited descriptor through each
duplication, including failures before FD 4 exists. Syscall failures retain
errno; read-back mismatches report EPERM. Failed or short readiness writes
exit without executing.

The parent accumulator is nonblocking, bounded to 16 bytes, and uses the
original two-second deadline. Only a complete readiness frame followed by EOF
means `READY_TO_EXEC`, whose exec outcome remains unknown. Missing, partial,
excess, malformed or late evidence fails closed; an additional step-11 frame
identifies an exec error. The runtime readiness/audit/reaping integration is
Phase 5C, and the daemon does not launch requester commands yet.

Unprivileged verification (included in `cargo test --workspace --locked`):

```sh
cargo test -p sigrund --test phase5_child --locked -- --nocapture
cargo test -p sigrund --lib execution::tests --locked
```

The separate C test translation unit uses the production source and injects
faults at syscall boundaries; these switches are absent from the library.
It checks all 12 early unshare/duplication/remap/close points against all 32
closed-FD masks, real EMFILE with every mask, and an inherited FD-4 sentinel.
It executes sealed ELF probes as UID 0 and service UID 33 with both empty and
nonempty capability sets; verifies post-exec IDs/groups, capabilities,
securebits, no_new_privs, signal state, session, umask, cwd and descriptors;
and covers failures across all credential steps, mount operations, failed
readiness writes, kills before readiness and after the token, and exec errors.
The ordinary fixture uses an unprivileged user namespace and fork to exercise
the child transition. It does not claim privileged clone3/mount acceptance.

The ignored `phase5_platform` fixture exercises actual clone3 placement,
mandatory limits, pidfds, private read-only cgroup mounts and post-exec
credentials on a delegated root test host. It also reaps a fast-exiting child
before classifying its buffered handshake and checks that parent mount flags,
mountinfo and cgroup write access remain unchanged. See
[MVP_PHASE5A.md](MVP_PHASE5A.md) for the build/run recipe. The operator will run
this privileged gate after landing; no successful privileged result is claimed.
