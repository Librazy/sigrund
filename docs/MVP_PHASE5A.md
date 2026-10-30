# Phase 5A: startup and committed-job ownership foundations

This phase adds the execution startup boundary without weakening the local
authorization profile when a host has no writable delegated cgroup hierarchy.

Implemented:

- cgroup v2 discovery follows `/proc/self/cgroup` and the mounted hierarchy,
  rather than assuming a systemd unit path;
- startup can create and verify `supervisor`, `jobs`, and `hooks` leaves,
  including mandatory `memory.swap.max`, `memory.oom.group`, and `pids.max`
  controls;
- stale job and hook leaves are killed and removed only after `populated 0`;
- per-job cgroups write and read back all four root-controlled limits and keep
  an owning descriptor until cleanup;
- execution startup failures are retained as an explicit fail-closed reason;
  authorization and audit remain available for rejection and recovery tests.

The coordinator now transfers a successful durable authorization as one typed
committed-job object when the delegated hierarchy is available. The object
retains the request lease, selected signer, exact authorization material and
audit lease; a missing hierarchy remains an audited fail-closed
`SPAWN_FAILED`. Child launch and central reaping are Phase 5B/5C work.

Verification:

```sh
cargo test -p sigrund --lib --locked
cargo clippy -p sigrund --all-targets --locked -- -D warnings
cargo fmt --all -- --check
```
