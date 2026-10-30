# Phase 5A: execution startup and committed-job ownership

Normal `sigrund --foreground` now requires the execution platform gate before
either listener appears. It discovers its actual cgroup v2 membership, pins
that root and its jobs/hooks directories, migrates to the supervisor leaf,
enables and verifies memory/pids controllers, checks mandatory swap/OOM/kill
controls, reconciles stale invocation cgroups, and probes real clone3,
namespace/mount isolation, credential setup, sealed memfd exec and pidfd wait.
Any unsupported interface or failed read-back aborts startup. There is no
silent fallback to an authorization-only daemon.

`--authorization-only` explicitly selects the non-executing diagnostic profile.
Existing transport/approval/authorization fixtures use this option; it avoids
mutating cgroups and preserves their original security and deadline checks.
`--check-cgroup PATH` remains a diagnostic, not execution admission evidence.

A durable authorization carries one owned `CommittedJob`: the unchanged
request and snapshot lease, captured policy, selected unrevoked signer,
canonical warrant, deterministic environment, peer identity, control socket,
lifecycle and audit lease. Its bounded single worker creates and reads back
per-job memory, swap, group-OOM and PID limits, then performs explicit cleanup.
Cgroup operations never run on the event loop. A failed setup returns its
partial owner; failed cleanup retains cgroup/request/quota ownership and
publishes a fatal error, without replacement workers or silent disposal.
Abort auditing uses the request's captured record limit.

The coordinator blocks SIGCHLD and retains its default disposition before
starting threads, and registers the subreaper before any probe clone. The
`Reaper` primitive reserves at most one unpublished clone result, services
known pidfds during that reservation, registers a returned primary before
clearing it, and requires a deferred P_ALL sweep before admitting another
clone. Sweeps are bounded to 256 orphan statuses per dispatch and retain
already-observed statuses even on a later error.

Phase 5C still must connect this reaper and registration barrier to live
requests and implement active-job shutdown. Until then the job preparation
worker never calls clone3: after disposing its empty cgroup it explicitly
aborts the committed grant with `SPAWN_FAILED` and
`AUTH_ABORTED_POST_COMMIT`. Consumption is preserved. Phase 5A/5B therefore
provide startup, ownership and child-transition foundations, not a working
end-to-end command execution service.

Verification already run without host-root privilege:

```sh
cargo test --workspace --locked -- --test-threads=1
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all -- --check
```

`phase5_reaper` uses real child/pidfd statuses: an unpublished child exits
while a registered primary exits concurrently. Known status remains
serviceable, the pending status stays waitable until registration, each exact
status is returned once, and another reservation is blocked until the deferred
sweep. The worker handoff test gates off-loop preparation, checks the unchanged
warrant/signer/environment/policy and pinned snapshot quota, cancels, then
verifies release only after returned-owner disposal. See
[MVP_PHASE5B.md](MVP_PHASE5B.md) for the syscall/credential fault matrix.

The privileged acceptance result is explicitly deferred to the operator after
landing, as requested. Build the fixture as the workspace user:

```sh
cargo test -p sigrund --test phase5_platform --locked --no-run
```

Use the absolute `phase5_platform-...` executable path printed by Cargo. In a
root test service on a disposable Linux host, run:

```sh
python3 /absolute/repository/scripts/verify-phase5.py \
  /absolute/phase5_platform-test-executable \
  --cgroup-parent /absolute/prepared/delegated/parent
```

The supplied parent must already have `memory pids` enabled in
`cgroup.subtree_control`; it must reside inside that dedicated supervising
service. The runner creates a fresh child G, moves only the test process into
it through a retained descriptor, creates private mount/cgroup namespaces,
and mounts cgroup2 with G as the visible root. Its 60-second deadline includes
namespace setup. The runner kills/removes only its fresh subtree, waits for
emptiness, and reaps the fixture. It fails early if the delegated interfaces
are missing. It never enables controllers on an arbitrary existing parent.

Configure the enclosing service with `Delegate=yes`,
`KillMode=control-group`, `SendSIGKILL=yes`, `RuntimeMaxSec=75s`, and
`TimeoutStopSec=10s` (or stricter external supervision). Keep the runner itself
in a separate supervisor leaf inside that service so enabling controllers
obeys the no-internal-process rule. This final service limit covers a blocked
cleanup syscall or abrupt runner death. Do not run this in an ordinary root
shell or move an existing interactive shell into the test hierarchy. No
successful privileged result or full V-01–V-19 conformance is claimed here.
