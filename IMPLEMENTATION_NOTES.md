# sigrun/sigrund implementation notes

These notes record the implementation boundary for the current `feat/mvp`
branch. The security specification remains the normative contract. A helper is
described as implemented only when its behavior is covered by a focused test;
the helper alone does not establish the end-to-end daemon guarantee.

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

The current unit suite has 36 tests and Clippy is clean. These tests exercise
the primitives above; they are not substitutes for the verification matrix in
Section 8 of the specification.

The SSHSIG verifier now parses raw `SSHSIG` envelopes for `ssh-ed25519` and
`sk-ssh-ed25519`, checks the warrant namespace and SHA-512 envelope, matches
the configured public-key algorithm, and enforces the configured FIDO user
presence and verification flags. OpenPGP and Sigstore adapters remain future
integration work.

## Deliberately incomplete runtime

The following specification surfaces are still stubs and must not be treated
as production functionality:

| Surface | Current behavior | Required integration |
| --- | --- | --- |
| `sigrund` | Reads and validates configuration and signer policy, optionally runs the cgroup check, then exits with status 78. | Startup recovery, root pinning, socket creation, epoll ownership, admission quotas, authorization, hooks, audit replication, `clone3`, child reaping, and reload handling. |
| `sigrun` | `--validate-hello` and `--encode-signal` are available; the normal command exits with status 78. | SCM_RIGHTS/PTY transport, hello construction, snapshots, status-fd output, signal/window relaying, deadline handling, and terminal cleanup. |
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

The specification now makes two crash-recovery details explicit:

1. `audit_ratchet.state` retains `initial_key_hex` so startup can verify the
   genesis record and replay HMACs across the complete log. It is protected by
   the same `0600` state-file permissions and is never exposed in normal
   request processing.
2. Once an audit record has been fsynced, any failure publishing the successor
   state poisons that writer. It may not append another record with the old
   sequence/key; restart or an equivalent verified reconciliation must recover
   the durable log/state pair first.
