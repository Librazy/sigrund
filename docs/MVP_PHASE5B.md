# Phase 5B: child setup and sync-pipe foundations

The child setup boundary is implemented as a standalone syscall-oriented
module. It is intentionally usable by both job and hook launchers and does
not depend on request parsing or audit state.

Implemented:

- `clone3` argument construction uses `CLONE_INTO_CGROUP`, `CLONE_PIDFD`, and
  a separate `SIGCHLD` exit signal; the isolated variant adds
  `CLONE_NEWNS | CLONE_NEWCGROUP` explicitly;
- the sync descriptor is duplicated first, retained as the error writer until
  FD 4 is installed, and all other sources are duplicated at descriptors 5+
  before remapping 0–4;
- setup failures emit one native-endian `{u32 step, i32 errno}` frame and the
  parent classifier accepts readiness only for exactly eight bytes followed by
  EOF;
- partial, excess, malformed, missing, and late sync evidence classify as
  `SPAWN_FAILED`;
- the syscall-only post-install path covers session, cwd, umask, groups,
  credentials, `no_new_privs`, readiness, and `execveat(AT_EMPTY_PATH)`;
- focused unit tests cover descriptor placement, frame encoding and all
  readiness/error framing boundaries.

The coordinator has not yet connected these primitives to the committed-job
completion queue or central reaper. Until that wiring is added, the existing
daemon cannot report readiness or execute a child.

Verification:

```sh
cargo test -p sigrund --lib --locked
cargo clippy -p sigrund --all-targets --locked -- -D warnings
cargo fmt --all -- --check
```
