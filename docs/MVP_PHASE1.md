# Phase 1: foreground startup and local sockets

Phase 1 implements the daemon/socket exit gate in
[MVP_ROADMAP.md](../MVP_ROADMAP.md). It accepts real local connections and
validates their framing, JSON, peer credentials, and stdio descriptors. A
valid hello receives one `SERVER_AUTH_DECISION` with `status: "REJECTED"` and
a message explaining that snapshots and authorization are not implemented.
No command is executed, and no grant is consumed. The root TTY approver and
client command transport remain the work of Phases 2–3.

## Running the service

Use Rust 1.89 or newer and a Linux kernel supporting `openat2`, `accept4`,
`epoll`, `signalfd`, and atomic close-on-exec rights reception. The foreground
daemon requires effective UID and GID 0. Configure `[mvp]` as described in
[MVP_PHASE0.md](MVP_PHASE0.md), with a valid SSH signer policy and collector
configuration. Collector files must exist as regular root-owned files even
though this profile performs no network I/O.

Provision once with `sigrundctl init-host`, retaining its output securely.
Start with the default paths:

```sh
sigrund --foreground --config /etc/sigrund/config.toml \
  --signers /etc/sigrund/signers.toml
```

For an isolated provisioned installation, both provisioning and the daemon
accept matching state/log overrides. For example, after the operator creates
the root-owned directories and configuration:

```sh
sigrundctl init-host --state-dir /var/lib/sigrund-lab \
  --log-path /var/log/sigrund-lab/audit.jsonl
sigrund --foreground --config /etc/sigrund-lab/config.toml \
  --signers /etc/sigrund-lab/signers.toml \
  --state-dir /var/lib/sigrund-lab \
  --log-path /var/log/sigrund-lab/audit.jsonl \
  --socket /run/sigrund-lab/client.sock \
  --approval-socket /run/sigrund-lab/approve.sock
```

All override paths use canonical absolute spelling, without symlinks, empty,
`.` or `..` components. Configuration and signer files, state/log directories,
executable roots, collector files, and socket parent directories must have
root:root ownership and no group/other write permission. Host identity is a
64-byte secret/public Ed25519 keypair with mode `0400`; audit state and log
have mode `0600`. Configuration and signer inputs have a 1 MiB startup read
limit each. Diagnostics such as `--check-config` remain usable without root
and perform their existing configuration-only checks.

## Startup and ownership

Startup derives `host_id` from the provisioned identity, validates the public
half against the secret, holds an exclusive nonblocking `daemon.lock` in the
state directory, and pins configured executable roots and collector files.
Audit recovery verifies every bounded record and its HMAC/hash chain and
requires its host to match the provisioned identity before recovery writes.
A synchronized partial tail is truncated and recorded; a complete single
record ahead of state is ratcheted forward and recorded. Other corrupt states
fail closed. A safe stale ratchet temporary file is removed before recovery.
No listener is created until these gates pass.

The client socket defaults to `/run/sigrund.sock` (`root:root 0666`), and the
broker to `/run/sigrund-approve.sock` (`root:root 0600`). Socket creation uses a
pinned parent directory and restrictive initial permissions. Startup refuses
every pre-existing socket path, including stale sockets, symlinks, and regular
files; it never unlinks another instance's endpoint. An operator must remove a
stale endpoint after confirming that its previous daemon has stopped. SIGINT
and SIGTERM stop the loop, close connections, and remove only the socket
inodes created by this instance. SIGHUP emits a diagnostic; reload is excluded
from the thin MVP.

The event loop records kernel `SO_PEERCRED` UID/GID/PID, enforces captured
global/per-UID client socket limits during acceptance, and permits one root
broker connection. Excess connections close immediately. Broker UID
authentication occurs before any receive or parser allocation, even if a
misconfigured filesystem mode permits a non-root connection.
Invalid peer credentials, including an unmappable PID reported as zero for
an ancestor PID-namespace peer, close only that connection. Both listeners
continue serving valid peers.

## Framing and resource bounds

Every receive uses `recvmsg(MSG_CMSG_CLOEXEC | MSG_DONTWAIT)`. The first client
type byte is received separately and is the only eligible location for rights.
Remaining reads stop at the current header or payload boundary and feed the
existing `FrameAssembler`. Unexpected ancillary data, control truncation,
extra rights in alignment padding, wrong FD counts/types/access, invalid
JSON, unexpected frame types, EOF, and timeout all release owned descriptors.
No caller-passed FD is read on the event loop. Socket and received FDs are
close-on-exec, and accepted sockets are nonblocking.

Descriptor metadata checks also run off-loop: `fstat()` can block on a FUSE
or network filesystem. A fixed worker pool uses the captured
`max_io_workers_global` and `max_io_workers_per_uid` limits; exhausted capacity
returns `RESOURCE_EXHAUSTED`. Each task owns its received FDs and checks
cancellation and the original request deadline before and after metadata work.
Timeout, protocol failure, and disconnect cancel the task without reclaiming
its worker quota or FDs. Those remain pinned until the syscall returns and the
worker finishes closing its descriptors. An eventfd delivers completions to
the coordinator, which ignores stale results. Shutdown does not join blocked
workers or create replacements.

The initial request deadline starts at acceptance and is never extended by
trickling bytes. Each frame also has an immutable five-second cumulative
assembly deadline from its first successful receive, and every prepared
outgoing frame has a five-second cumulative nonblocking send deadline. Idle
broker connections have no partial-frame timer. Broker framing is the Phase 0
four-byte length plus bounded JCS document, with no descriptors. Phase 1 closes
any unsolicited root response; approval dispatch/binding belongs to Phase 3.

Diagnostic JSON lines include `DAEMON_READY`, `SOCKET_ADMITTED`,
`CLIENT_HELLO_VALIDATED`, and `FD_VALIDATION_COMPLETE`. They contain kernel
identity, execution IDs, and internal worker-task IDs, not
caller-controlled display fields or secrets. A bounded queue moves writes to
a separate diagnostic thread; overload may drop diagnostic lines. These are
not authorization audit records. Authorization sequencing, worker snapshots,
cgroup startup/runtime integration, hooks, collector RPCs, child setup, and
reaping remain later-phase requirements; the existing `--check-cgroup`
probe remains available. This service does not claim full-spec conformance.

## Implement–verify–fix gate

```sh
cargo test -p sigrund --test phase1_transport --locked
cargo test -p sigrund --test phase1_daemon --locked -- --nocapture
cargo test --workspace --locked
cargo +1.89.0 test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all -- --check
git diff --check
```

The daemon gate requires util-linux `unshare`, subordinate UID/GID ranges for
the invoking user, working `newuidmap`/`newgidmap`, and a C compiler (`cc`) for
a test-only Linux `fstat` interposer. It creates a private
user namespace with mapped UID 0 and non-root UIDs 65533/65534, then provisions
temporary state and runs the shipped daemon. It does not elevate to host
root, touch production paths, or change host cgroups. Missing prerequisites
fail the gate explicitly. Three ignored test entry points are subprocess helpers
invoked by the ordinary gate; they are executed by that gate, not waived tests.

| Phase 1 requirement | Verification evidence |
| --- | --- |
| Normal foreground daemon and path overrides | The gate launches the shipped binary with temporary configuration, identity/state/log, and socket paths, and observes `DAEMON_READY`. |
| Recovery before client readiness | Provisioned identity, partial-tail and forward recovery, mismatched host, corrupt/missing log, invalid key permissions, and missing collector file are exercised through startup. Failed gates leave no client endpoint. |
| Socket ownership, peer credentials, and quotas | Actual socket stat checks, a non-root hello with recorded UID/GID, per-UID saturation, cross-UID global saturation, released capacity, and duplicate daemon lock refusal. |
| Unmappable peer credentials | A daemon in a child PID namespace rejects repeated ancestor-namespace connections on both listeners, then successfully handles an in-namespace client and broker. |
| Root-only broker | Non-root connection denied by mode, then non-root signed reply refused by credentials after deliberately loosening the mode. A root broker response is rejected as unsolicited. |
| Bounded transport and FD cleanup | Socketpair fragmentation/coalescing, oversized headers, late/truncated/extra rights, CLOEXEC, FD type checks, synthetic send backpressure/expiry, and real-daemon FD counts after hostile traffic. |
| Cumulative deadlines and shutdown | Synthetic immutable frame/send deadlines, real initial idle/trickle request timeout, SIGTERM exit success, and removal of owned endpoints. |
| Blocking FD metadata | A test-only interposer stalls selected `fstat()` calls in the shipped daemon. Tests verify a worker TID, other-UID service, global/per-UID worker caps, timeout/disconnect quota pinning, FD cleanup after release, unchanged thread count, rejection of late results, and SIGTERM while a syscall remains blocked. |

The loop first implements a requirement, probes it through transport or the
real daemon, fixes failures, and reruns the focused gate before the workspace
gates. The fixture deliberately uses temporary executable roots and TLS files
because it exercises local startup/transport without executing commands or
making collector requests. The M-01–M-10 and V-01–V-19 execution matrices are
still subsequent-phase gates.
