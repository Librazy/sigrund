# sigrun/sigrund implementation notes

These notes record the implementation boundary for the current `feat/mvp`
branch. The security specification remains the normative contract. A helper is
described as implemented only when its behavior is covered by a focused test;
the helper alone does not establish the end-to-end daemon guarantee.

The executable delivery plan is in [MVP_ROADMAP.md](MVP_ROADMAP.md). It
defines the thin `stdio` approval/signing workflow and the gates required
before expanding to the full v1.0 surface.

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

The current workspace suite has 67 tests and Clippy is clean. These tests exercise
the primitives above; they are not substitutes for the verification matrix in
Section 8 of the specification.

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
all three commands expose `--help`. The new `sigrund-approve` entry point
reports its unavailable runtime with status 78 until Phase 3 is implemented.

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

## Deliberately incomplete runtime

The following specification surfaces are still stubs and must not be treated
as production functionality:

| Surface | Current behavior | Required integration |
| --- | --- | --- |
| `sigrund` | Reads and validates configuration and signer policy, optionally runs the cgroup check, then exits with status 78. | Startup recovery, root pinning, socket creation, epoll ownership, admission quotas, authorization, hooks, audit replication, `clone3`, child reaping, and reload handling. |
| `sigrun` | `--validate-hello` and `--encode-signal` are available; the normal command exits with status 78. | SCM_RIGHTS/PTY transport, hello construction, snapshots, status-fd output, signal/window relaying, deadline handling, and terminal cleanup. |
| `sigrund-approve` | Parses the frozen command form and provides `--help`; normal invocation exits with status 78. | Root peer/TTY verification, broker transport, sanitized prompting, SSH-agent/key signing, and bounded approval delivery. |
| `sigrund-collector` | `--validate-batch` is available; the normal command exits with status 78. | TLS server, exact HTTP/DSSE framing, host authentication, batch verification, deduplication, cursor durability, and denial/receipt responses. |
| `sigrundctl` | UUID validation/generation and `init-host` provisioning are available. | Sealing/template commands, revocation administration, anchor-file output, safe ownership checks, and complete operator error handling. |
| Verification matrix | No V-01 through V-19 end-to-end harness exists. | Linux integration fixtures and deterministic race gates required by every row of Section 8. |

Diagnostic options such as `--check-config`, `--check-cgroup`,
`--validate-hello`, and `--validate-batch` validate inputs or a local probe;
they do not open the production socket, authorize a request, spawn a child, or
provide any runtime security guarantee.

## Implementation order

1. Build the daemon startup path: provisioned identity/audit recovery,
   cgroup hierarchy and pinned roots, canonical configuration generations, and
   fail-closed socket readiness.
2. Build bounded control transport and descriptor ownership, then implement
   the common executable/stdin snapshot phase and per-request quota ownership.
3. Add signed and unsigned authorization, SQLite consumption, lifecycle
   reservation reconciliation, and local audit sequencing.
4. Add hook sandboxing and nonblocking hook I/O, then collector TLS/DSSE
   replication and startup checkpoint reconciliation.
5. Add child credential/mount setup, PTY transfer, central reaping, reload,
   and disconnect teardown.
6. Implement V-01 through V-19 in isolated Linux fixtures. A release is not
   conformant until these cases pass in addition to unit tests and Clippy.

## Contract clarifications made during implementation

The implementation uses the following crash-recovery and durability rules:

1. `audit_ratchet.state` retains `initial_key_hex` so startup can verify the
   genesis record and replay HMACs across the complete log. It is protected by
   the same `0600` state-file permissions and is never exposed in normal
   request processing.
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
