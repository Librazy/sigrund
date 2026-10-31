# Phase 5C: execution ownership, reaping and shutdown

The runtime and verification fixtures are committed in `3d16f0c`, with
documentation in `147c730` and the authorization-only diagnostic correction in
`7f476ba`. The workspace suite, Clippy, formatting and the existing child/reaper
tests pass. The prepared real execution/service fixtures have not yet run;
Phase 5C acceptance remains pending that evidence.

## Runtime ownership

The coordinator retains an execution context independently of its connection.
A bounded cgroup executor prepares job limits and returns the owner before
clone admission. The coordinator reserves the lifecycle and Central Reaper
barrier before dispatching one clone. Every returned PID/pidfd is registered
before releasing that barrier, including after disconnect or shutdown. Known
primaries remain reapable by pidfd while another result is unpublished. A
bounded deferred orphan sweep precedes the next clone.

The original request lease holds sealed snapshots, caller descriptors, captured
policy, signer and quota through execution. Cgroup setup/kill/removal and
potentially blocking closes stay off the event loop. Cleanup uses inotify and
reads back `populated 0`; failed cleanup retains its owner and causes fatal
shutdown. A blocked owner never authorizes replacement capacity.

Sync-pipe classification retains the original two-second deadline and preserves
early terminal status. Readiness is audited before its decision is sent;
`exec_outcome` remains `unknown`. After a normal primary exit, cleanup and the
central orphan sweep precede final auditing and `SERVER_CHILD_EXIT`. Failures
send only a failure decision. All post-commit failures preserve consumption.

After the complete readiness decision is written, control parsing runs on the
request's existing reserved I/O worker. It accepts only bounded, strictly
validated signal frames and forwards permitted signals only while the primary
remains registered. Partial-frame deadlines remain visible to the coordinator,
including when malformed ancillary-rights disposal blocks. Idle jobs do not
start a frame timer. Cancellation closes the control connection and initiates
cleanup independently of worker completion.

## Shutdown and supervision

SIGINT/SIGTERM and fatal runtime/durable errors stop admission and new commit
or spawn reservations, close controls and cancel all contexts. Already reserved
operations reconcile their actual results. The event loop and reaper continue
servicing returned children and cleanup completions. Healthy audit records
outcomes; a poisoned writer receives no new appends. Its resource owner retains
the instance lock through coordinator cleanup, including after its worker has
reported failure.

Shutdown succeeds only when execution contexts, request-worker reservations and
audit ownership have drained. `shutdown_grace_ms` emits one bounded diagnostic
on expiry; it does not release stalled owners or report successful cleanup.
Systemd `READY=1`, `WATCHDOG=1` and `STOPPING=1` notifications are supported when
configured. Watchdog heartbeats stop during shutdown. Execution must run under
a dedicated supervising service with delegation and whole-service cleanup,
including an escalation path for internally initiated fatal shutdown.

A production service should use `Type=notify`, `NotifyAccess=main`,
`Delegate=yes`, `KillMode=control-group`, `SendSIGKILL=yes`, a finite
`WatchdogSec`, and `TimeoutStopSec` greater than `shutdown_grace_ms`. A finite
runtime limit additionally bounds disposable test services. Prior-instance
children are never assigned invented wait statuses; startup reconciles their
cgroups before publishing listeners. Root/out-of-profile containment retains
the specification's qualified best-effort guarantee.

## Verification and reproduction

Run as the workspace user:

```sh
cargo build --workspace --locked
cargo test --workspace --locked -- --test-threads=1
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all -- --check
git diff --check
```

The namespace regression gates now test immediate control closure while
blocked metadata/FD/durable owners retain quotas and the instance lock. They
release those gates and verify cooperative completion rather than requiring
the process to discard outstanding ownership at SIGTERM.

In a disposable delegated root service with a final deadline and whole-service
cleanup, run:

```sh
python3 /absolute/repository/scripts/verify-phase5-runtime.py \
  --cgroup-parent /absolute/prepared/delegated/service \
  --binaries /absolute/repository/target/debug
```

The parent must already enable `memory pids`, and its runner must occupy a
separate leaf. The script creates and removes only its fresh subgroups. Its
fixtures use real binaries and SSH signatures, an unprivileged UID 65534
requester, target UID/GID 33, native copies of `id`/`true`/`false`/`sleep`, and
production clone/exec. Private native copies accommodate distributions whose
`/usr/bin/id` is a symlink, which the executable-resolution contract rejects.
The client is copied to a traversable fixture directory so a private developer
home does not invalidate the unprivileged probe.

The runtime fixtures cover exact return status and FD disposal, signal delivery,
disconnect, foreground interruption/restart, unpublished and registered early
exits, shutdown around durable commit and clone reservations, blocked cleanup,
audit poisoning with a running job, and prior-instance orphan recovery.
Interposition is confined to a separately built test library; production has
no environment-driven fault switches.

Add `--systemd` only on a prepared test host with the system bus and Python Gio
bindings. It creates uniquely named additional transient services with
20-second runtime limits, two-second watchdogs, three-second stop timeouts,
private container mount-view entry and whole-service cleanup. These test real
service stop/restart, SIGKILL cleanup and automatic escalation after a fatal
cleanup error parks its owner. Each service is stopped/reset by the runner;
its own runtime limit also covers abrupt runner death.

The delegated hierarchy must expose a coherent cgroup2 mount view. The
Distrobox launcher prepares that view only in a private mount namespace; no
host-wide mount changes or mutation of unrelated cgroups are permitted.
These runtime/service gates remain pending operator-approved execution.
