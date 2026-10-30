# Phase 0: frozen thin-MVP contracts

Phase 0 implements the types, validators, configuration boundary, and command
forms needed by the later runtime phases in [MVP_ROADMAP.md](../MVP_ROADMAP.md).
The security specification remains authoritative for the warrant and client
protocol. The approval broker and `[mvp]` table are implementation contracts
for the restricted first workflow.

This document records the completed Phase 0 contract. The midpoint revision
of [the roadmap](../MVP_ROADMAP.md) and specification Section 6.3 require
additional profile restrictions, signer configuration and CLI options before
execution is enabled. Phase 1.5 implements the request restrictions; signer
configuration and CLI extensions belong to Phases 2–4 and are not accepted
by the current parser.

## Configuration profile

Add this table at the end of the normal daemon configuration:

```toml
[mvp]
tty_mode = "stdio"
hooks_enabled = false
pty_enabled = false
max_active_approval_requests = 1
```

The table's presence selects the MVP profile; its fields have the defaults
shown, so `[mvp]` alone also selects it. Omitting the table retains the full
specification's configuration validation. Every other value for these fields,
an unknown field, or top-level `require_remote_audit_ack = true` fails
configuration validation. Collector configuration remains mandatory and
validated even though network use is disabled. Existing positive hook quotas
remain valid configuration but cannot enable hooks under this profile.

The profile allows only `ssh-ed25519` and `sk-ssh-ed25519` signer entries.
Existing signer ceilings and exact root-list equality still apply. The
profile's request gate validates the full hello and rejects any PTY request.
It is retained with a request's captured policy generation. Phase 1 limits
broker connections; Phase 3 must enforce one active approval request before
snapshotting/dispatch. Phase 0 establishes the capacity contract without
creating a request registry.

## Command forms

```sh
sigrund --foreground --socket /run/sigrund.sock \
  --approval-socket /run/sigrund-approve.sock \
  --config /etc/sigrund/config.toml --signers /etc/sigrund/signers.toml
sigrund-approve --socket /run/sigrund-approve.sock --tty /dev/tty
sigrun --socket /run/sigrund.sock -- /usr/bin/id -u
```

The default sockets are `/run/sigrund.sock` and `/run/sigrund-approve.sock`;
the default approval TTY is `/dev/tty`. Socket/TTY/config overrides use
absolute paths. The two daemon socket paths must differ. `--config` and
`--signers` take precedence over `SIGRUND_CONFIG`/`SIGRUND_SIGNERS`, which
take precedence over the defaults above. All three binaries support `--help`.
Unknown, duplicate, missing-value, and conflicting options return status 64.
The client's `--` terminates option parsing; subsequent arguments retain
their exact values, including empty strings and strings beginning with `--`.
The command executable must use an absolute path and argv has at most 256
entries. The foreground daemon mode is also the default daemon invocation.

Diagnostics remain runnable now:

```sh
sigrund --check-config --config /absolute/config.toml --signers /absolute/signers.toml
sigrund --check-cgroup /absolute/delegated/cgroup --config /absolute/config.toml
sigrun --validate-hello hello.json
sigrun --encode-signal 15
```

`--validate-hello` now validates a signed envelope's decoded canonical warrant,
TTY equality, and caller environment as well as its outer shape. It does not
verify signatures or grant authorization. The signal diagnostic accepts only
the specification's five forwarding signals: 1, 2, 10, 12, and 15.
Normal client/approver commands currently return status 78. The daemon now
provides the Phase 1 socket service described in [MVP_PHASE1.md](MVP_PHASE1.md);
prompting and execution still belong to subsequent phases.

## Canonical warrant and CSR

`sigrund_core::warrant` provides `Command`, `ExecutionContext`, `GrantPolicy`,
`Warrant`, `CanonicalWarrant`, and `Csr`. The completed CSR has exactly the
specification's warrant schema, including host/peer identity, grant, policy,
and measured executable/stdin digests. It is the unsigned document that will
become the DSSE payload.

`CanonicalWarrant::parse` and `Csr::parse` accept at most 65,536 bytes and
require exact JCS bytes. They reject unknown or duplicate fields, invalid
UTF-8, fractional/exponent numbers, excessive nesting/arrays, overlong
strings/maps, forbidden control/BiDi characters, and invalid field bounds.
Nullable `stdin_sha256` and `not_after` keys are required even when null.
TTY/stdin compatibility, digest nullability, lowercase digests, UUIDv7,
UID/GID, policy validity, environment names, and sorted lists are checked.

The integer-only JCS serializer sorts keys recursively using UTF-16 code-unit
order and emits compact JSON. Schema numeric values fit the exact JCS integer
range. Canonical wrappers retain both the parsed document and its bytes with
immutable access. Reformatting, alternative escapes, trailing whitespace,
different key order, and `-0` therefore fail the byte comparison.

`Csr::from_unsigned` validates the hello and fills it using daemon-supplied
host identity, kernel peer credentials, grant ID, time, and sealed-snapshot
digests. The caller must obtain those inputs from trusted sources. The builder
checks the captured maximum TTL and timestamp addition. It creates no
snapshots and grants no authorization.

`ClientHello::parse_request` is the raw-input entry point for later transports:
it checks the original frame-body byte length before parsing, then applies
the unsigned-request limit after selecting the mode and validates all fields.
Absent mode-specific fields remain absent on serialization. Whitespace and
alternative escapes count toward the wire limit even though they do not
appear in a compact reserialization.

`DsseEnvelope::from_warrant`, `to_jcs`, `parse_jcs`, and `warrant` apply strict
Base64 and outer field bounds and validate the decoded canonical warrant.
The outer client hello itself may use ordinary JSON whitespace as allowed by
the specification. `Csr::bind_envelope` compares every canonical payload byte;
it rejects changes to command, context, identity, policy, grant, or digests.
Cryptographic verification and retained-FD policy checks remain mandatory in
the Phase 4 coordinator.

## Root approval broker

The Phase 1 transport must authenticate UID 0 before parsing these documents.
Its framing contract is a four-byte big-endian unsigned body length followed
by one JCS JSON document, with a body limit of 524,288 bytes. Empty bodies are
invalid. The broker carries no ancillary descriptors. These are separate
broker frames; the specification's existing client control frame types and
limits are unchanged. Phase 1 implements bounded reads/writes and deadlines.

An `ApprovalRequest` contains exactly:

| Field | Contract |
| --- | --- |
| `exec_id` | Canonical lowercase UUIDv7 for this execution. |
| `signer_id` | Selected configured signer ID, 1–128 ASCII bytes. |
| `csr_payload` | Exact canonical CSR JSON as a string, at most 65,536 decoded UTF-8 bytes. |

An `ApprovalResponse` has one of two exact field sets:

| `status` | Required fields |
| --- | --- |
| `approved` | `status`, `exec_id`, `dsse_envelope`. |
| `rejected` | `status`, `exec_id`, `reason` (1–1024 UTF-8 bytes). |

Request and response `parse_jcs`/`to_jcs` methods enforce their field schemas,
structural/string limits, and exact canonical encoding. Unknown statuses and
fields, omitted fields, duplicates, and invalid embedded documents fail.
Display sanitization remains required when Phase 3 interpolates these values.

`ApprovalRequest::bind_response` validates both documents and requires the
same execution ID. An approved response must have exactly one signature from
the selected `signer_id` and a warrant matching the retained CSR byte-for-byte.
A matching rejection returns no warrant. This operation establishes binding;
it does not authenticate the peer, verify the signature, consume a grant, or
allow a spawn. The coordinator must perform those later checks explicitly.

## Verification and completion evidence

The workspace requires Rust 1.89 or newer. The declared minimum matches the
locked Linux dependencies and is checked with the full workspace tests:

```sh
cargo +1.89.0 test --workspace --locked
```

Run the focused tests while implementing, fix failures, then run the phase
gates:

```sh
cargo test -p sigrund-core --test phase0_contracts
cargo test -p sigrund --test phase0_cli
cargo test --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
git diff --check
```

The contract suite includes a fixed canonical byte vector, UTF-16 key-order
checks, successful warrant/CSR/envelope/approval round trips, a maximum-size
65,536-byte warrant, schema/encoding rejection cases, mutation of every
warrant field, captured TTL/overflow checks, execution/signer binding, and
profile rejection. The CLI suite invokes the shipped binaries for help,
explicit config paths, invalid profiles, and signed-hello validation, and
tests exact argv/socket parsing. The SSH unit tests also verify successful
software and simulated security-key SSHSIG signatures with UP/UV enforcement.

Passing these gates completes Phase 0. Phase 1 adds working sockets; a root
TTY prompt, two-UID execution, and the revised M-01–M-15 runtime matrix remain gates
of the subsequent roadmap phases.
