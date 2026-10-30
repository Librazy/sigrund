# Phase 4: authorization, commit, and local audit

Implement–Verify–Fix checklist (complete for the local thin profile):

| Item | Contract | Verification evidence |
| --- | --- | --- |
| P4-01 | Complete thin-profile Section 4.2 predicate against retained sealed snapshots, selected signer, peer and policy generation. | `phase4::exit_gate` rejects wrong host/UID/GID/signature, capability/group ceilings, same UID, executable digest and validity. `final_authorization_rechecks_retained_policy_and_identity` checks the final root path/device/inode, signer, caller environment, stdin and exact sorted envp. `final_snapshot_gate` checks actual digests, mode/ownership, seals, ELF, size and cancellation. Existing Phase 0/2 profile/shape tests cover unsupported modes, scripts, environment inheritance and TTY combinations. Phase 3 replaces the source after sealing and still authorizes the reviewed snapshot. |
| P4-02 | Serialized SQLite authorization with realtime sampled after BEGIN; coordinator commit reservation and final executor cancellation check. | `phase4::exit_gate` concurrently redeems identical signed bytes from matching peers: one commit, one replay denial. It revokes by grant, payload and signer. Phase 3 revokes while approval is pending. State tests verify lock-ordered realtime and rollback guards; deterministic runtime gates cover cancellation before reservation, before the final check, and after the check/durable COMMIT. |
| P4-03 | One bounded off-loop authorization/audit executor, with owned request/FD/RAM reservations retained through disposal. | The runtime gate blocks real WAL and audit syncs, checks executor TID differs from coordinator PID, exhausts both workers without adding threads, and verifies a partial-frame deadline still cleans up. A sealed executable remains open after requester disconnect until durable reconciliation. Signalfd shutdown remains responsive, and restart observes consumption. Existing disposal tests retain worker/FD/RAM ownership through blocking closes. |
| P4-04 | Authenticated serialized AUTH_COMMIT, post-commit abort, rejection and diagnostic records; poison on durable-write uncertainty. | The runtime gate reopens authenticated history after authorization and denial, repairs a synchronized partial tail, and recovers one record forward after injected state-rename failure. SQLite fsync failure exits 78 without a decision, readiness, or automatic retry. Core audit tests verify HMACs, host/sequence/link binding, bounded recovery and writer poisoning. SIGHUP produces a durable `RELOAD_UNAVAILABLE` diagnostic. |
| P4-05 | Signed-warrant CLI input with exact immutable payload and explicit option compatibility. | Real non-root `sigrun --warrant PATH` redeems null and hashed stdin, reports `SPAWN_FAILED` then replay on a separate status FD, and preserves consumption across restart. `phase4_options` rejects signed-field overrides and malformed files before connecting. Client signed-input tests check unchanged payload bytes and derived stdin; profile gates forbid inherited caller environment. |
| P4-06 | Coordinator decisions and Phase 5 handoff boundary. | Runtime assertions reject readiness and execution audit events. Local acceptance appends `AUTH_COMMIT` then matching `AUTH_ABORTED_POST_COMMIT` before `SPAWN_FAILED`, with an explicit message that the one-time grant remains consumed. Expiry/revocation/replay and policy/snapshot denials return their specified statuses. Reserved cancellation never replies before its result and audit are reconciled. |

The exit gate invokes production binaries in a Linux user namespace with root
and mapped non-root requester credentials. The Phase 3 gate additionally uses
a real controlling PTY and OpenSSH helper for interactive approval. The Phase 4
gate uses independent SSHSIG construction for direct signed redemption. Its
executable is an ELF-shaped snapshot fixture; no elevated command runs yet.

The deterministic test shim in `tests/fixtures/durable_gate.c` interposes real
reads, socket peeks, WAL/audit synchronization and state rename. A parent must
explicitly arm each gate, receive the executor's TID and release it. These are
test-process environment settings under `LD_PRELOAD`, with no production test
switches. A close after the final COMMIT check may still consume the grant;
the fixture expects reconciliation, not an impossible check/syscall guarantee.

Phase 4.5 corrective gate evidence:

- `phase4::blocked_io_remains_bounded_and_responsive` reads `REQUEST_TIMEOUT`
  and `RESOURCE_EXHAUSTED` frames before releasing a blocked WAL/audit sync.
  The denial path publishes through the control socket immediately while its
  reserved audit lease remains queued and bounded; a later audit completion
  cannot publish a second decision.
- `admission` tests exercise fixed per-UID/global windows, bounded UID state,
  reload debt, diagnostic coalescing and ownership release after delayed
  persistence. `storage` tests exercise checked `fstatvfs` arithmetic, log
  high-water and free-space floors, all pinned filesystems, and sticky
  fail-closed pressure.
- The sequencer performs capacity checks off the event loop before every
  append. Startup validates the same thresholds before listeners are exposed.
  Phase 5 remains responsible for the pre-FD-4 setup implementation, the
  pending-spawn/reaper barrier, and shutdown reconciliation; those contracts
  are frozen in the specification and roadmap but are not claimed as runtime
  features here.

The implement/verify/fix loop also corrected these issues:

- Final authorization now rehashes the actual sealed bytes, checks retained
  root identity, root ownership/modes/seals and ELF, and builds sorted envp
  from signed values. Cached digests alone cannot authorize changed bytes.
- SQLite metadata verification closes its independently opened database FD
  before SQLite takes POSIX locks. Closing it later can release process-wide
  locks and hide external revocations. Pinned-directory and administrative
  revocation regressions also exercise the custom VFS and WAL/SHM paths.
- The sequencer reports panics as fatal durable-state failures and finishes
  pending lifecycle cancellation after a reserved operation's result is known.
- The concurrent state test opens both connections before its barrier and
  bounds result waits, so a setup failure cannot hang the test indefinitely.

Multi-signature review follow-up: preparation retains every independently
verified, policy-compliant signer. Final authorization rechecks each candidate's
complete ceilings and pinned root; the SQLite transaction then selects an
unrevoked candidate before consumption. Grant/payload revocations still deny
the entire warrant. Consumption and commit/abort audit records name the selected
signer. `multisignature_revocation` in the Phase 4 namespace gate uses two distinct
keys and revokes the first after snapshot preparation. It checks fallback in
both signature orders, replay, exact consumption/audit identity, invalid or
policy-ineligible fallback signatures, all-signers-revoked denial, whole-warrant
revocation, and rejection when only combined permissions could satisfy policy.

Reproducible checks (all pass):

```sh
cargo +1.89.0 test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all -- --check
git diff --check
```

Verified on Linux `7.2.11-300.fc45.x86_64`, x86_64, with Rust 1.89.0 and
development Rust `1.101.0-nightly (92ffebece 2026-10-28)`. The fixture requires
Linux user namespaces with subordinate UID/GID mappings, `unshare`, `/proc`,
PTYs, OpenSSH tools and a C compiler (`cc`); missing prerequisites fail the
gate. Ignored inner namespace tests are invoked by the outer gates. This
document and the checked-in fixtures are the verification artifacts.

M-06 is covered for local one-time consumption. M-07 covers approval and
commit cancellation; spawning remains Phase 5. M-10 covers local partial and
forward recovery. M-14 covers filesystem and durable-state stalls; job
cleanup remains Phase 5. Applicable V-01–V-05, V-09, V-13–V-15, V-18 and
V-19 subcases have focused evidence across these phases. Remote, reusable-mode,
hook, PTY and child-execution subcases remain unverified; no complete V row or
full v1.0 conformance is claimed.

Local audit retains `initial_key_hex` for history verification. It detects
corruption under protected-state assumptions, but cannot provide forward
secrecy after root compromise or detect whole-state rollback. `DAEMON_READY`
explicitly reports `local_audit_forward_secure: false`; external checkpoints
and remote ACK remain separate post-MVP work. A durable-store error stops the
daemon without retrying; restart reconciles surviving state before listening.

All Phase 0–3 gates remain passing. The MVP remains local
audit only, with hooks, PTY, reload and remote ACK disabled. Phase 5 is required
for actual command execution; passing authorization does not establish a
successful child setup or permit an early readiness response.
