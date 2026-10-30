# sigrun/sigrund implementation notes

These notes record the implementation boundary for the current `feat/mvp`
branch. The security specification remains the normative contract. A helper is
described as implemented only when its behavior is covered by a focused test;
the helper alone does not establish the end-to-end daemon guarantee.

The executable delivery plan is in [MVP_ROADMAP.md](MVP_ROADMAP.md). It
defines the thin `stdio` approval/signing workflow and the gates required
before expanding to the full v1.0 surface.

The midpoint roadmap revision adds explicit client defaults, terminal output
relaying, signer/key selection, bounded root approval, off-loop cleanup and
post-clone safety gates. Specification Section 6.3 now defines the target
local-approval profile, including a required execution-time
`mvp.approval_signer_id`. Phase 1.5 implements received-FD cleanup, retained
request/snapshot ownership, root pinning, streaming snapshot builders and
request-profile restrictions. Phases 2–3 add client options and relays, common
snapshots, explicit signer/key selection, and foreground root approval. Phase 4
adds local authorization, SQLite consumption and serialized durable audit.
Phases 5A/5B add startup, ownership and child-transition foundations; live
request execution and shutdown remain Phase 5C.
M-01–M-15 and applicable V subcases gate the revised MVP. The Phase 0/1 evidence
documents remain records of what was actually implemented and tested.

## Current implementation

The repository currently contains tested building blocks for:

- strict JSON preflight and schema validation, including duplicate-key,
  nesting, string, array, frame, DSSE, child-exit, and audit-record limits;
- canonical UUIDv7, Base64, digest, and DSSE/PAE helpers;
- policy TOML parsing, signer/root consistency checks, immutable protocol
  ceilings, collector key validation, and policy-generation snapshots;
- anchored path-prefix selection, bounded executable/stdin copying, digest
  calculation, cancellation checks, memfd sealing, and the Linux cgroup
  startup probe;
- lifecycle CAS transitions, readiness publication, reservation cancellation,
  durable one-time-grant consumption, digest revocation normalization, and
  hash-chained audit append/recovery primitives; and
- bounded frame encoding/decoding and the exact `CLIENT_HELLO`, decision,
  child-exit, and remote-batch shape validators.

The workspace suite includes the primitives above and a Phase 1 real-daemon
fixture with namespace-root and non-root peers. These tests are not substitutes
for the complete verification matrix in Section 8 of the specification.

The minimum supported Rust version is 1.89, matching the active Linux locked
dependencies (including `uuid` 1.29). The complete workspace test suite is
verified with Rust 1.89 and the lockfile, as well as the development toolchain.

The SSHSIG verifier now parses raw `SSHSIG` envelopes for `ssh-ed25519` and
`sk-ssh-ed25519`, checks the warrant namespace and SHA-512 envelope, matches
the configured public-key algorithm, and enforces the configured FIDO user
presence and verification flags. OpenPGP and Sigstore adapters remain future
integration work.

## Completed roadmap Phase 0

The thin-MVP boundary is implemented and documented in
[docs/MVP_PHASE0.md](docs/MVP_PHASE0.md). `warrant` supplies typed command,
execution-context, policy, warrant, immutable canonical-warrant, and completed
CSR contracts. Canonical JSON sorts object keys recursively by UTF-16 code
units and checks exact input/output bytes. `approval` defines bounded broker
requests and approved/rejected responses, with execution-ID, selected-signer,
and complete CSR binding. These operations validate syntax and binding; the
runtime still must verify signatures and all authorization predicates.

An opt-in `[mvp]` daemon configuration table fixes `stdio`, disables hooks and
PTY, requires local audit without remote ACK, and sets the active approval
capacity to one. The profile is retained in captured policy generations. Only
SSH Ed25519 signer adapters are accepted under that profile. The shared CLI
parser defines daemon/client/approver commands and separate socket overrides;
all three commands expose `--help`. The `sigrun` runtime now implements the
Phase 2 requester path; `sigrund-approve` implements the Phase 3 root-TTY
approval and SSH signing path described below.

The implement/verify/fix loop exercised golden canonical bytes, UTF-16 key
ordering, maximum-size round trips, invalid schema and encoding cases,
every CSR field's binding, checked TTL arithmetic, profile rejection, and real
binary diagnostics. Verification exposed a Clippy style error, which was
fixed. Contract inspection also removed a hardcoded default TTL from request
shape validation: the CSR builder now enforces the captured configuration
limit and checked timestamp arithmetic. Signed hellos reject unsigned-only
fields, and supplementary GIDs reject the Linux overflow sentinel.
Final inspection found that serializing absent hello fields as null could
reject a valid request at the byte ceiling. Optional fields now remain absent
on output, and the raw hello parser checks original wire lengths before
deserialization and the unsigned limit after mode selection. Exact-ceiling
tests cover both request modes and the unsigned serialized body.

## Phase 1: foreground startup and sockets

The normal daemon path now runs a nonblocking epoll loop under the opt-in MVP
profile. It verifies root ownership and permissions, pins executable roots and
collector files, derives and checks the provisioned host identity, locks the
state directory, removes a safe stale ratchet temporary file, and completes
host-bound audit recovery before binding the sockets. The client endpoint is
`root:root 0666`; the separate approval broker is `root:root 0600` and checks
`SO_PEERCRED.uid == 0` before allocating a broker parser or receiving bytes.

Admission enforces configured global/per-UID socket limits at `accept4()`.
Every control receive uses `recvmsg(MSG_CMSG_CLOEXEC | MSG_DONTWAIT)` with
bounded ancillary storage. Framing retains cumulative receive/send deadlines,
checks the exact stdio FD matrix, and closes all pending/delivered rights on
failure. A valid hello produces a `CLIENT_HELLO_VALIDATED` diagnostic with the
kernel peer identity and one explicit `REJECTED` decision. Unsolicited broker
responses never authorize a request. Diagnostics use a bounded off-loop queue;
they are separate from the Phase 4 authorization audit records.

Descriptor metadata validation runs on fixed off-loop workers, since even
`fstat()` can block on FUSE or remote filesystems. Global/per-UID worker quotas
and received FDs remain owned by a task after timeout/disconnect until actual
cleanup; cancellation checks surround the metadata calls. Completion arrives
through eventfd, and late results cannot change a terminal decision. Shutdown
never joins a stalled worker. Invalid `SO_PEERCRED` results, including PID zero
from an ancestor PID namespace, reject only the individual connection.

The implement/verify/fix loop added socketpair probes and a real-daemon fixture
inside an unprivileged user namespace, with mapped UID 0, 65533, and 65534.
Verification caught an inaccessible test executable for non-root peers and
missing context on audit startup errors; both were corrected. Final inspection
also added raw path-component validation before `Path` can normalize spelling
and replaced timing guesses in admission tests with observed admission events.
The fixture checks both audit recovery cases, host binding, startup refusal,
actual quotas/deadlines, shutdown cleanup, and unchanged daemon FD counts after
hostile requests. See [docs/MVP_PHASE1.md](docs/MVP_PHASE1.md) for the gate and
its prerequisites.
Review regressions additionally gate `fstat()` in the real daemon to verify
worker isolation, quota pinning, late-result suppression, and responsive
shutdown. A child PID-namespace fixture verifies that unmappable peers cannot
stop either listener and that valid peers still work afterward.

## Phase 1.5: ownership and snapshot foundations

[docs/MVP_PHASE1_5.md](docs/MVP_PHASE1_5.md) tracks the five midpoint findings
and their Implement–Verify–Fix evidence. The shared I/O pool now reserves
global/per-UID capacity before receiving a frame and receives/parses/validates
and disposes of caller rights on that worker. Quota refusal closes the local
socket without receiving its queued rights. Partial-frame timeout, malformed
ancillary data, JSON/profile failure, disconnect and stale results cannot
close caller FDs on the control loop. Root broker receives use the same budget;
idle broker connections consume no slot.

Successful validation returns a lease retaining the hello, descriptors,
captured policy, requester UID, deadline and cancellation flag. It may carry
sealed executable/stdin snapshots and continue on the same reserved worker.
Dropping the lease schedules disposal there; only cleanup completion releases
the worker slot. Socket readiness is disabled while the worker receives, with
disconnect/error events and coordinator deadlines still active.
Every connection retirement explicitly removes its epoll registration before
closing the coordinator's socket. A worker's duplicate socket may outlive it
during blocked disposal; leaving the registration active would repeatedly
deliver hangups for a removed token. The real-daemon fixture verifies removal
while cleanup remains blocked.

Executable roots now use separate `O_PATH | O_DIRECTORY` pinning, while
readable-file and executable-relative opens retain their appropriate flags.
Worker-only snapshot builders stream/hash with fixed 64-KiB scratch storage,
reserve aggregate RAM before memfd allocation, retain quotas through source
close and ownership transfer, seal the destination, rewind it, and trim hashed
stdin to actual length. Empty stdin is valid. The common snapshot coordinator
and source-selection/signature gate are integrated in Phase 2 on the retained
worker lease.

The MVP request gate enforces one-time/stdio/null-or-hashed-stdin, no scripts,
no forwarded caller environment and no same-UID execution using kernel peer
UID. These restrictions apply before metadata for signed and unsigned requests;
they do not replace signature verification or the full authorization predicate.

## Phase 2: client transport and common snapshots

The Phase 2 client captures and validates requester options before connecting,
constructs the exact canonical hello with documented defaults, duplicates
caller descriptors before allocating internal FDs, and sends stdout/stderr
(plus hashed stdin when selected) with the first hello byte using bounded
nonblocking `SCM_RIGHTS`. Separate relay threads keep control and cancellation
responsive while local sinks block; status output remains newline-delimited and
separate from child output. Malformed, wrong-state, fragmented, disconnected,
and deadline-expired server responses are handled with the specified status
codes, and output is drained through EOF after child exit.

The daemon continues each validated request on its existing reserved worker.
Preparation selects a pinned root, opens the executable beneath it with
`openat2()`, snapshots and hashes sealed executable/stdin memfds, retains
source/root identities and captured policy, and builds a canonical CSR from
kernel peer credentials and the provisioned host identity. Signed DSSE
requests verify an SSHSIG candidate and static policy before source opening,
then compare signed executable/stdin digests against the sealed results.
Snapshot memory and descriptor ownership remain charged until worker cleanup.
No approval, durable authorization, or child spawn is attempted in this phase:
unsigned requests receive `TIMEOUT_CSR`, and signed requests receive a bounded
rejection after preparation.

Focused implementation–verification–fix evidence is recorded in
[docs/MVP_PHASE2.md](docs/MVP_PHASE2.md).

## Completed roadmap Phase 3

[docs/MVP_PHASE3.md](docs/MVP_PHASE3.md) maps each deliverable to its
verification evidence. The daemon reserves one unsigned approval slot after
static policy checks and before snapshots. It uses the same reserved worker,
sealed executable/stdin, captured policy and exact CSR for broker exchange and
SSH verification. No approver, refusal, busy admission, expiry and disconnect
have bounded outcomes; cancellation invalidates the prompt and retains worker,
FD and RAM reservations through cleanup.

`sigrund-approve` validates UID 0, its foreground controlling TTY, the trusted
broker and root-controlled policy/identity. It displays every CSR field with
escaped indexed arguments and signs only explicit `y`/`yes`. OpenSSH receives
fixed arguments and DSSE PAE on stdin; the helper is bounded, killed and reaped
on abort, and its signature is verified locally before delivery. Actual PTY
fixtures cover software keys, encrypted private-key passphrase entry and
public keys backed by an SSH agent. Physical FIDO signing remains unverified;
existing simulated SK verification does not establish hardware operation.

The Phase 3 boundary now hands a successfully verified approval to the Phase 4
authorization executor. The executor revalidates retained snapshots, signer,
peer, environment, validity, and policy, consumes one-time grants in SQLite,
and appends authenticated `AUTH_COMMIT`/`AUTH_ABORTED_POST_COMMIT` records.
The local profile then returns `SPAWN_FAILED` with an explicit Phase 5 handoff;
no elevated child or readiness frame is created.

Phase 4's completed checklist and verification evidence are in
[docs/MVP_PHASE4.md](docs/MVP_PHASE4.md). Runtime tests cover concurrent
matching-peer redemption, all three revocation selectors, signed null/hashed
stdin, cancellation around commit, blocked WAL/audit sync, fatal persistence
errors and startup recovery. Final authorization rehashes retained sealed
bytes and checks root identity, mode/ownership/seals and ELF. SQLite database
and sidecars stay under a verified directory FD; metadata verification closes
its separate database FD before SQLite locks it so it cannot release SQLite's
process-wide POSIX locks and hide later administrative revocations.

## Completed roadmap Phase 4.5

Phase 4.5 closes the pre-execution response deadline gap. Each admitted
request reserves one bounded audit lease at accept time, separately from its
socket, worker and snapshot ownership. Timeout, refusal, policy and resource
denials enqueue their record without waiting for SQLite or fsync, then publish
one decision through the control socket. Closing the socket cannot discard the
lease; the durable executor owns it until append completion or fail-closed
shutdown. Admission counters use fixed monotonic windows with bounded UID
state, and refused attempts are coalesced into one diagnostic slot.

`StoragePressure` checks the pinned audit/state filesystems with checked
`fstatvfs` arithmetic and enforces the configured log high-water and free-space
floors. Capacity checks run in the durable executor and startup; pressure is
sticky until verified restart. ENOSPC/EIO and failed capacity queries stop the
service without retrying uncertain authorization. The Phase 4 namespace gate
reads `REQUEST_TIMEOUT` and `RESOURCE_EXHAUSTED` while a WAL/audit sync remains
blocked, then verifies replay and shutdown behavior after releasing the gate.
The pre-FD-4 child setup, pending-spawn reaper barrier and active-job shutdown
contracts are frozen in the specification. Phase 5B implements the tracked
child error descriptor; the tested registration-barrier primitive is ready for
Phase 5C's runtime integration. Active-job shutdown remains Phase 5C work.

The durable sequencer also refreshes the pressure gate after every successful
append. The owned record that reaches the high-water mark persists, while new
requests are refused without waiting for a later durable operation. The
`storage_pressure::exit_gate` namespace fixture starts with a verified log one
byte below the threshold, crosses it with a real rejection, checks that the
next connection is refused before admission, and reopens the resulting audit
history. Removing the post-append check makes this regression test fail.

## Landed Phase 5A/5B foundations

Normal foreground startup now performs pinned cgroup initialization and an
isolated kernel/credential/exec probe before publishing listeners. The explicit
`--authorization-only` profile keeps non-executing diagnostics available.
A committed job retains its original request, snapshots, selected signer,
canonical warrant, environment, policy and audit owners through bounded
off-loop cgroup preparation/cleanup. Failed partial setup retains a cleanup
owner. A cancellation test holds this handoff blocked and checks that quotas
remain pinned until actual owner disposal.

The standalone reaper reserves one unpublished clone, keeps registered pidfds
serviceable, registers returned children before clearing the barrier, and
requires a bounded deferred sweep before another reservation. A real-child
fixture verifies concurrent early exits without status theft. The C child
path covers the full descriptor/mount/credential transition with parent-owned
buffers and syscall-only error/exec handling. Its fault matrix and sealed-ELF
post-exec probes run unprivileged in a user namespace.

See [MVP_PHASE5A.md](docs/MVP_PHASE5A.md) and
[MVP_PHASE5B.md](docs/MVP_PHASE5B.md) for exact evidence and commands. The
operator explicitly deferred privileged testing until after landing. The
ignored `phase5_platform` fixture and bounded supervisor runner are supplied;
no successful local privileged acceptance result is claimed. Requester clone
dispatch, readiness/audit publication, active-job reaping and shutdown remain
Phase 5C. The current job worker prepares/disposes an empty cgroup and records
a post-commit abort instead of launching a command without those protections.

## Deliberately incomplete runtime

The following specification surfaces are still stubs and must not be treated
as production functionality:

| Surface | Current behavior | Required integration |
| --- | --- | --- |
| `sigrund` | Runs under `[mvp]` after the execution startup gate, or with explicit `--authorization-only`; signed/unsigned requests share retained snapshots, SQLite consumption and authenticated local audit. Successful authorization still returns `SPAWN_FAILED` while preserving consumption. | Live clone/reaper/readiness/shutdown integration, hooks, audit replication, PTY and reload. |
| `sigrun` | Normal command supports unsigned construction or `--warrant PATH`, hello/descriptor transport, stdio relay, separate status reporting and signal/deadline handling. Signed input forbids field overrides and preserves canonical payload bytes. | PTY/window transport and validation against actual child execution. |
| `sigrund-approve` | Root peer/TTY verification, bounded broker transport, complete escaped prompting, OpenSSH key/agent signing and cancellation are implemented. | Physical FIDO signing evidence; native agent adapter is optional follow-on work. |
| `sigrund-collector` | `--validate-batch` is available; the normal command exits with status 78. | TLS server, exact HTTP/DSSE framing, host authentication, batch verification, deduplication, cursor durability, and denial/receipt responses. |
| `sigrundctl` | UUID validation/generation and root-only `init-host` provisioning with ownership/permission checks and durable state publication are available. | Sealing/template commands, revocation administration, anchor-file output, and complete operator workflows. |
| Verification matrix | No V-01 through V-19 end-to-end harness exists. | Linux integration fixtures and deterministic race gates required by every row of Section 8. |

Diagnostic options such as `--check-config`, `--check-cgroup`,
`--validate-hello`, and `--validate-batch` validate inputs or a local probe;
they do not open the production socket, authorize a request, spawn a child, or
provide any runtime security guarantee.

## Implementation order

Follow [MVP_ROADMAP.md](MVP_ROADMAP.md) as the delivery order: preserve the
completed transport, snapshot and root-approval gates (Phases 0–3), then add
the completed authorization/commit/local-audit gates (Phases 4–4.5), followed by
cgroup startup/child setup/reaping (Phase 5) and execution fixtures (Phase 6).
Implement the applicable security subcases alongside each phase. PTY, hooks,
remote replication, reload and additional signature adapters follow the thin
workflow in separate milestones. Full v1.0 conformance still requires all
V-01 through V-19, not just the MVP gates or unit tests and Clippy.

## Contract clarifications made during implementation

The implementation uses the following crash-recovery and durability rules:

1. `audit_ratchet.state` retains `initial_key_hex` so startup can verify the
   genesis record and replay HMACs across the complete log. It is protected by
   the same `0600` state-file permissions and is never exposed in normal
   request processing. Retaining this seed means the format is not
   forward-secure after host/state compromise; the full limit and external
   checkpoint boundary are explicit in specification Section 7.2.
2. Once an audit record has been fsynced, any failure publishing the successor
   state poisons that writer. It may not append another record with the old
   sequence/key; restart or an equivalent verified reconciliation must recover
   the durable log/state pair first.
3. Partial-tail recovery requires a synchronized log/state checkpoint. A log
   one complete record ahead of state plus any partial tail is corruption;
   recovery leaves both files unchanged. Startup verifies one bounded record
   at a time and retains only the current key, hashes, host, sequence, and byte
   offset, so memory use does not grow with log history.
4. Provisioning fsyncs the genesis log's parent directory before publishing
   ratchet state. New directory hierarchies are synced through their ancestors
   before use, and the state directory is synced after atomic state rename.
   Any failed directory barrier prevents successful provisioning.
