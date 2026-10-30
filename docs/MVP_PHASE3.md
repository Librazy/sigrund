# Phase 3: root approval and SSH signing

Implement–Verify–Fix checklist (complete for the Phase 3 approval slice):

| Item | Contract | Verification evidence |
| --- | --- | --- |
| P3-01 | Explicit configured SSH signer and root-controlled policy/key selection. | `approval_signer_selection_is_explicit_bounded_and_unambiguous` validates selection, absence, duplicates and bounds; `approver_requires_operator_controlled_identity_and_policy_options` checks CLI paths/duplicates. The PTY fixture rejects an explicitly selected wrong identity. Core configuration/crypto tests reject wrong algorithms and enforce SK UP/UV flags. |
| P3-02 | Root-only broker with one unsigned approval slot reserved after static policy checks and before snapshots. | `phase3::exit_gate` drives the real daemon through no-approver, busy, static-policy denial, disconnect, stale execution/signer, malformed/duplicate replies and reconnect. Its busy request names a nonexistent executable to prove it is denied before source opening. Existing Phase 1 namespace gates verify peer authentication and root-only broker admission. |
| P3-03 | Foreground controlling-TTY confirmation with every field escaped and displayed. | The real PTY fixture covers `yes`, blank, `no`, terminal EOF, TTY loss and non-TTY invocation. It checks all CSR fields, indexed empty/quoted/Unicode arguments, nonempty groups/capabilities and actual executable/stdin digests. `display_escaping_preserves_boundaries_without_terminal_controls` probes control/BiDi escaping. |
| P3-04 | OpenSSH signs DSSE PAE over exact CSR bytes with fixed arguments; return raw binary SSHSIG. | `openssh_signs_exact_dsse_pae_and_rejects_other_keys_namespaces_and_payloads` interoperates with the installed `ssh-keygen` and rejects wrong key, namespace and bare-CSR signing. The PTY gate signs with an unencrypted private key, a public key loaded into a real `ssh-agent`, and an encrypted private key with passphrase input on the root TTY. |
| P3-05 | Immutable cumulative approval and independent frame deadlines; cancellation terminates/reaps the helper. | `approval_deadline_rejects_late_completion_even_before_timer_dispatch` exercises both timer-first and completion-first ordering after the immutable 120-second deadline and forbids a second decision. Transport gates verify bounded frame/send deadlines. `helper_abort_kills_and_reaps_child_and_bounds_input_output` tests slow input, cancellation/timeout/broker-loss callbacks, reaping and excessive output. The real PTY fixture cancels an OpenSSH child blocked on an agent query and verifies its process disappears before the approver exits. |
| P3-06 | Verify returned envelope against the retained CSR, captured policy and sealed snapshots. | The real daemon rejects changed argv, executable digest, target UID and grant ID even with valid signatures; also rejects wrong execution/signer/signature and expired warrants. The successful path uses hashed binary stdin and replaces the source file after displaying the original digest. Core contract tests bind every CSR field and reject noncanonical encodings. Preparation/worker gates retain sealed snapshots, identity, captured policy, and worker/FD/RAM reservations through cleanup. |

The namespace gate invokes the production `sigrun`, `sigrund` and
`sigrund-approve` binaries with namespace-root and a mapped non-root requester.
It provisions temporary host state, generates disposable software SSH keys,
creates a controlling foreground PTY and uses real OpenSSH helpers. Its
snapshot fixture is deliberately an ELF-shaped file: no elevated command is
executed during this phase. The original Phase 3 gate required no durable
authorization. Phase 4 has extended this same fixture to assert authenticated
commit/post-commit abort and one-time consumption after successful approval,
and rejection records for refusal, expiry and invalid responses. See
[MVP_PHASE4.md](MVP_PHASE4.md) for that completed integration boundary.

Approval is not durable execution authorization. At the original Phase 3
boundary a verified response produced `REJECTED`; the Phase 4 executor now
performs local durable authorization and returns `SPAWN_FAILED` with an
explicit Phase 5 handoff. No approver produces `TIMEOUT_CSR`, busy
admission produces `RESOURCE_EXHAUSTED`, explicit refusal produces `REJECTED`,
and broker loss/malformed transport produces `TIMEOUT_CSR`. The returned CSR
keeps its original grant and validity; waiting never renews it. Validated
refusal reasons are escaped before delivery. Cancellation or a faulty broker
retires that connection; reconnect can service only a fresh request.

The implement/verify/fix loop corrected the default `/dev/tty` identity check:
its inode device number identifies the device alias, so both descriptors are
compared using `TIOCGDEV` and checked against the foreground process group.
It also moved static unsigned signer policy checks onto the reserved worker
before slot reservation, bounded helper I/O and checked cleanup under agent
backpressure. A test-fixture FD leak discovered during TTY-loss testing was
fixed by applying close-on-exec to both PTY ends.

Encrypted-key review probes additionally verified that cancelling a passphrase
read used to leave terminal echo disabled. The helper now captures terminal
attributes before spawning and restores them only after reaping, on both
success and failure. The real PTY gate checks full attribute restoration after
broker cancellation and local termination; the bounded-helper gate also covers
timeout and I/O-error cleanup with echo disabled.

The signing helper also overrides inherited `SSH_ASKPASS_REQUIRE` with `never`
and removes `SSH_ASKPASS`. The encrypted-key PTY test launches the approver
with forced askpass and an executable that can supply the correct fixture
passphrase; it requires terminal entry and verifies that executable is never
invoked.

Reproducible checks:

```sh
cargo +1.89.0 test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all -- --check
git diff --check
```

All four checks pass for this implementation. The workspace suite runs on
Rust 1.89 with the locked dependencies; Clippy runs with warnings denied on
the development toolchain.

The workspace command includes `phase3::exit_gate`; its ignored inner
namespace fixture is invoked by that gate. The integration prerequisites are
Linux user namespaces with subordinate UID/GID mappings, `unshare`, PTYs,
`/proc`, `/usr/bin/ssh-keygen`, `/usr/bin/ssh-agent` and `/usr/bin/ssh-add`.
Missing prerequisites fail the gate rather than skip it. The cumulative
120-second deadline race is exercised with injected event/completion times;
it is not a claim that a physical 120-second human wait was tested.

For a provisioned foreground daemon with `[mvp]`, set
`approval_signer_id = "<configured SSH signer ID>"` and run the root watcher:

```sh
sigrund-approve --socket "$TEST_APPROVAL_SOCKET" --tty /dev/tty \
  --signers "$TEST_SIGNERS" --identity "$TEST_SSH_IDENTITY"
```

The identity is selected by the operator and must match that signer. Use a
private OpenSSH key file, or the corresponding public key file with the key
loaded into root's explicitly selected SSH agent. There is no arbitrary
agent-key fallback. An empty daemon signer setting preserves CSR-only
behavior; it cannot enable execution. The operator sees every field before
`Approve and sign? [y/N]`; only `y` or `yes` signs.

Physical FIDO signing still requires separate hardware evidence. Existing
simulated SK verification does not establish device presence/verification or
hardware signing. Durable authorization, SQLite consumption and audit commit
remain Phase 4; cgroup/credential setup, `clone3`, readiness and child exit
remain Phase 5. These gates cover the approval portions of M-12/M-13 and do
not establish complete MVP execution or v1.0 conformance.
