# Namespace-aware execution: phased v3 roadmap

Updated 2026-11-07. This is the delivery roadmap for the
[draft normative v3 security specification](<../sigrun sigrund Security Architecture and Implementation Specification.md>).
The specification owns the contract; this document owns implementation order,
feasibility decisions, acceptance evidence and deferred scope. NS-01–NS-16 refer
to its stable namespace requirements; G-01–G-05 refer to its release-blocking
design gates. Supported host CLI options are documented in the
[Phase 1 record](NAMESPACE_PHASE1.md); later-phase selectors remain planned.

## Current state and intended outcome

The current runtime implements the local **v3 host** one-time SSH/stdio profile,
with explicit host/account/profile selection and a retained epoch-bound owner.
It runs jobs in the daemon's configured domain, creates private namespaces for isolation,
and uses a requester-access helper limited to the daemon filesystem domain and
initial userns mappings. Direct-execution checkpoints verify executable evidence
and credentials; they are not general namespace/LSM verifiers. See
[implementation notes](../IMPLEMENTATION_NOTES.md#deferred-namespace-aware-executable-evidence)
for the ComposeFS limitation and current coverage. Namespace-root fixtures do
not establish container-routing support.

The v3 outcome is one host authority executing in explicitly selected local
existing environments:

| Route | Source → destination | Destination identity |
| --- | --- | --- |
| 0 | Host → container B | B's account and numeric credentials |
| 1 | Container A → host | Host account and numeric credentials |
| 2 | Container A → its supported authenticated environment | That environment's account and credentials |
| 3 | Container A → container B | B's account and numeric credentials |

All routes need policy and signer approval, including cross-owner execution.
Rootful container root, mapped rootless root and host root remain distinct.
Mapping a source container account into a host account is a separate deferred
selection mode. Remote hosts, proxy authentication, container creation and socket
injection are out of scope. Operators expose both client endpoints; the approval
socket and state remain host-controlled.

V3 replaces v2 contracts without compatibility requirements. Wire formats,
configuration, CLI, signing domains, storage and collector contracts can change
together. Use explicit fresh provisioning, with no automatic migration or deletion
of old state. Runnable documentation now describes the v3 cutover; historical
Phase 0 experiment records remain independent.

## Architecture and implementation boundaries

```mermaid
flowchart LR
    C[Client intent or full request] --> H[Host authentication and admission]
    H --> T[Validated pinned target]
    T --> P[Destination preparation helper]
    P --> A[Approval and durable authorization]
    A --> E[Namespace executor]
    E --> S[Host supervision and cleanup]
```

Use the native Linux executor as the common backend. Carry target resources and
leases through preparation, approval, authorization and job cleanup; preserve the
coordinator's namespaces. Separate selector input, retained execution resources,
signed bindings and optional manager identity. The first implementation slice
uses only the host target; later slices add administrator-validated explicit
targets. Self requires its own source-attribution gate.

| Integration | Useful role | Boundary |
| --- | --- | --- |
| Docker/Podman/containerd or other manager APIs | Optional names, scoped identity, ownership/configuration metadata and lifecycle evidence | Same target acquisition and host authorization; an exec API may not expose retained-FD execution, placement or checkpoints |
| runc/crun | Potential specific, explicitly integrated runtime adapter | No universal control plane; bypassing a manager can violate bookkeeping and cleanup |
| Native Linux helpers | Destination preparation, namespace entry, retained evidence, child setup and supervision | Must demonstrate supported mappings, ordering, placement and confinement |

OCI provides configuration vocabulary, not unique container identity or a
universal discovery interface. No integration may claim manager-exec equivalence
from namespace membership alone.

The principal implementation seams are core schemas/crypto/policy; daemon
transport/admission and request leases; preparation/access/evidence;
authorization/approval; execution/cgroups/reaper/runtime; and storage/audit.
Introduce a target resource owner instead of passing bare PIDs or pathname-only
roots through those boundaries. Existing host child setup is a baseline profile,
not a ready-made rootless executor.

## Delivery phases

Each phase is a reviewable milestone, not a calendar estimate. Its completion
record must identify changes, applicable requirements, commands/fixtures, observed
results, supported combinations and remaining blockers. Failed or partial gates
remain visible; they cannot be converted into support claims by documentation.

### Phase 0 — Contract and feasibility

**Dependencies:** None. **Subsystems:** source transport, target acquisition,
Linux helpers, cgroups/reaping, LSM verification, core policy/schema design.

The [Phase 0 contracts and experiment record](NAMESPACE_PHASE0.md) defines the
constrained-anchor prototype, bounded schemas, commands and qualification limits.
Its isolated experiments do not enable production namespace execution. In
particular, strict safety under concurrent SELinux policy replacement remains a
blocked deployment combination.

**Deliverables:**

- Resolve G-01: define connector versus message-sender attribution for self;
  specify socket inheritance/passing, connector exit, credential/exec races,
  context changes and an acquisition mechanism resistant to PID reuse and mixed
  observations. Repeated procfs reads alone are not a proof of atomic capture.
- Resolve G-02/G-03: prototype supported userns entry, composed mappings,
  `setgroups=deny`, root/cwd handling, PID/time child creation, launcher placement,
  host-visible pidfds, tracing and reaping. Test the candidate launcher-in-job-
  cgroup approach before prescribing it as the production sequence.
- Resolve G-04: prototype required LSM transitions and actual-state verification
  under NNP/ptrace, direct/memfd models and enforcing policies. Define policy
  reload/version detection and explicit seccomp installation requirements.
- Resolve G-05: freeze canonical acquisition/constraint records, scoped target
  and signer policy, registration/revocation interfaces, CLI selection grammar,
  target FD/helper quotas and supported full-access binding distribution.
- Update the draft specification with decisions and a supported/rejected matrix.
  Identify kernel/architecture, namespace ownership, delegation and enforcement
  prerequisites. Keep unresolved combinations blocked.

**Exit gate:** Every prerequisite for the first supported profile has a concrete
contract and prototype evidence. Other combinations are explicitly unsupported
or blocked. Self cannot enable without G-01; confinement claims cannot enable
without G-04. Prototype success is not an integrated-runtime release gate.

### Phase 1 — V3 foundation and host target

**Status:** Complete for the qualified v3 host profile (2026-11-07); see the
[implementation and evidence record](NAMESPACE_PHASE1.md). The local one-time
stdio workflow passed the integrated host qualification below. Container
execution remains disabled.

**Dependencies:** Phase 0's applicable contract/schema decisions.
**Subsystems:** core protocol/crypto/configuration, CLI/approver, target ownership,
storage/audit and collector schemas.

**Deliverables:**

- Implement strict v3 intent, resolved numeric credentials, target instance and
  immutable profile bindings. Carry a host-target resource owner through the
  existing pipeline before introducing container entry.
- Replace wire/signature/configuration/state contracts coherently; add explicit
  fresh-state provisioning and incompatible-state rejection. Collector contracts
  bind the same execution digest even while collector runtime remains deferred.
- Update approval rendering to show authority, epoch/instance, verified target
  description, mapping context, numeric identity and complete constraints.
- Implement bounded target/helper ownership and private diagnostics. Preserve
  fixed-deadline outcomes, complete approval delivery before workload spawn,
  replay/revocation, durable consumption and independent cleanup accounting.

**Exit gate:** Independent canonicalization/intent/PAE/SSHSIG fixtures, strict
cross-version rejection, approval-display checks, fresh-state recovery and all
applicable local V-01–V-20 security cases pass under v3. No namespace capability
is advertised at this milestone.

#### Phase 1 host qualification: V-01–V-20

Qualified 2026-11-07 on Fedora 44 x86_64, kernel
`6.19.10-300.fc44.x86_64`, glibc 2.43, enforcing SELinux with an explicitly
administrative unconfined supervisor, initial identity maps and delegated
cgroup v2 memory/pids. Fs-verity used ext4 with 4-KiB blocks. This is a host-only
qualification; it makes no container-entry or target LSM-confinement claim.

Commands and hashes are recorded in the
[implementation record](NAMESPACE_PHASE1.md#completed-qualification) and
[sanitized evidence](evidence/namespace-phase1-host-20261107.json). The final
`scripts/check.py` run passed all ten checks. The full
`scripts/verify-acceptance.py` entry point passed platform, runtime, v3 privacy,
all seven trust gates, 26 execution gates and integrated host scenarios;
`scripts/verify-phase1-rust.py` passed all nine selected privileged gates.
Two additional privileged ComposeFS store/metacopy tests also passed. Each
privileged supervisor finished successfully and removed its cgroup. These
results use matching binaries from the recorded source snapshot. Ignored Cargo
labels for privileged/child-only fixtures do not serve as passing evidence.

The ordinary command ran as the unprivileged workspace user; the privileged
commands ran from `/home/lab/sigrund-phase1` inside independently bounded
systemd supervisors, with the recorded administrative SELinux context:

```sh
python3 scripts/check.py --artifacts /tmp/sigrund-phase1-checks-candidate9-20261107
python3 scripts/verify-acceptance.py \
  --binaries /home/lab/sigrund-phase1/target/debug \
  --checks /home/lab/sigrund-phase1/checks-candidate9.json \
  --artifacts /home/lab/sigrund-phase1/acceptance-final11-artifacts --requester lab
python3 scripts/verify-phase1-rust.py \
  --daemon-tests /home/lab/sigrund-phase1/target/debug/deps/daemon-d3a936486236a676 \
  --library-tests /home/lab/sigrund-phase1/target/debug/deps/sigrund-51ba23e59c78f6b4 \
  --artifacts /home/lab/sigrund-phase1/rust-final10-artifacts
```

The final checked source SHA-256 is
`84bdd0dffddbd8cde12dbffe8414b41efc45c2444677ca9745dc0f91aa9271ed`.
The evidence record defines its path/content algorithm, identifies matching
production and test binaries, and records the script-only rollback-fixture
correction after the Rust run. The disposable qualification VM was removed
after private artifact preservation.

| Case | Phase 1 applicability and observed result |
| --- | --- |
| V-01 | **Passed, host scope.** Strict wire/context/CSR/signature/config/state/ratchet/audit/collector version tests; real root fresh provisioning, prior/partial sets and sidecars, missing/v2/future/mixed startup rejection before listeners, with existing bytes preserved. |
| V-02 | **Passed.** Strict target-independent context, malformed/rights rejection, bounded pools, generation checks. Integrated occupation of 2 per-UID/8 global context slots still permits a real signed job with execution admission allowance 1. |
| V-03 | **Passed.** Native v3 local preparation, accessible/missing/unreadable sources and ancestors, unchanged thin fallback, local full-only/export refusal, finite stdin captured once. |
| V-04 | **Passed, host identity domain.** DAC/ACL/supplementary-group/ancestor checks, forged evidence rejection, retained-source/path replacement. Unavailable or mismatched preparation domains fail locally or fall back unchanged; destination namespace-domain support is deferred. |
| V-05 | **Passed.** Raw sockets compare generic scheduled TIMEOUT for silent denials; root broker tests cover refusal, absent/disconnected broker, malformed/expired approval. The account-existence test consumes the same 13,824 stdin bytes, produces no workload output and reaches the same 2.5-second deadline. |
| V-06 | **Passed.** Canonical original-intent and signed field substitutions; live epoch/instance/acquisition/profile/authority/credential/origin/model substitutions all return scheduled TIMEOUT. Restart invalidates old warrants/bundles; stale offline bytes are preserved then denied. Account/profile changes after preparation preserve the approved resolved credentials/profile. Thin standalone/reconnect redemption is rejected. |
| V-07 | **Passed on the recorded filesystems.** All four models, fs-verity SHA-256/SHA-512, direct streaming/bounds, memfd seals, ctime lease, mutation, noexec, metadata/file capabilities, tracer death. Additional root store-protection and real overlay-metacopy rehash tests pass. Arbitrary filesystems or mutable administrator stores are not qualified. |
| V-08 | **Passed.** Actual root/service credentials and exact groups, five capability sets, securebits 47, NNP, cwd/umask and cgroup mount flags; direct checkpoints enforce before target instructions. Memfd reports unknown exact exec outcome. Unavailable checkpoint/kernel capabilities and unsupported isolation requirements are rejected. |
| V-09 | **Passed.** Production preparation/review/commit boundaries, late/duplicate approvals and fsync/commit races under deterministic deadlines. One public winner, no deadline extension or spawn after timeout; late committed consumption survives. |
| V-10 | **Passed.** Partial/blocked APPROVED delivery and disconnect, syscall/setup/clone/exec failures, pre-spawn cancellation, release/reaper races and fast exits. Complete delivery precedes workload spawn/output; later failures retain consumption and one terminal outcome. Remote collector authorization is deferred. |
| V-11 | **Passed for software-key host workflow.** Independent JCS/intent/DSSE-PAE/OpenSSH/two-digest vectors and real unprivileged export/offline sign/package/redeem preserve canonical bytes and environment. Wrong key/domain/payload and authenticated SK UP/UV flag failures are tested. Physical FIDO device interaction remains unqualified and is not claimed by this milestone. |
| V-12 | **Passed.** Ordinary transport tests plus production privileged raw-socket framing, fragmentation, deadlines, rights, bounds, blocked read/close, output backpressure and actual descriptor cleanup. |
| V-13 | **Passed for fixed configuration.** Existing rates/sockets/workers/RAM/audit/review limits compose with host ceilings. Integrated target/review/FD/helper exhaustion keeps ownership through timeout and blocked cleanup, then allows reacquisition only after disposal. Context pool is independent. Reload remains deferred. |
| V-14 | **Passed.** Concurrent redemption yields one commit; replay after restart, revocation and expiration, locked/failed durable work and late commits retain uniqueness/consumption and private reconciliation. |
| V-15 | **Passed, schema/validator milestone only.** Actual consumption stores 32 raw binding bytes equal to AUTH_COMMIT and collector target_auth lowercase hex. Mismatched/uppercase digests and old/future record schemas are rejected. Remote mTLS, ACK, receipts and retry runtime are deferred and disabled. |
| V-16 | **Passed for root TTY.** Exact live private review/CSR records are verified before complete escaped evidence display. Refusal, EOF, wrong key, slow/encrypted signing, cancellation, reconnect and revocation pass. Private records require the reserved root principal. Hook execution remains deferred. |
| V-17 | **Passed for stdio.** Independent 2-MiB stdout/stderr, blocked-output cancellation, retained endpoints and cleanup. PTY rights/resize/terminal workflow remains deferred and rejected. |
| V-18 | **Passed.** Real platform and child/reaper fault gates: cgroup mount flags/propagation, credential and FD remap failures, sync-FD sentinel, unpublished clone results and concurrent exits. Parent mount state and cleanup ownership are preserved. |
| V-19 | **Passed within the stated local-audit boundary.** Independent v3 HMAC/ratchet recomputation; corrupted/partial/forward recovery, storage poison/threshold and startup cases; consumption survives recovery. A deliberate complete authentic rollback demonstrates the need for an external checkpoint, while the fresh epoch rejects the old warrant. External rollback protection is deferred. |
| V-20 | **Passed.** Real systemd shutdown/crash/restart with silent requests, commits/clones and blocked cleanup; escalation and supervisor cgroup removal. CPU, disk, admission and other shared-resource effects remain outside the protocol-only confidentiality guarantee. |

There are no skipped privileged cases within the qualified Phase 1 host scope.
Physical FIDO interaction, additional deployment platforms and later-phase
features above remain explicitly unqualified; Phase 0 prototypes do not close
their gates.


### Phase 1.5 — Operator workflow for an existing rootless container

**Status:** Planned for a separate implementation PR. Phase 1 supplies the v3
host workflow. The [Phase 0 record](NAMESPACE_PHASE0.md#g-05-bounded-records-and-administration)
supplies the registration grammar and evidence contracts.

**User story:** A host operator wants a one-time command to run as a service
account inside an already-running rootless container B. The operator must be
able to establish which environment will receive the command and withdraw that
authority while a request is pending.

1. **Make B available.** Write and exercise an operator recipe on a real
   rootless deployment. Identify who may start the dedicated single-threaded
   anchor inside B, how root authenticates and captures it using G-01, which
   socket and ptrace permissions are required, and who owns cleanup. Use the
   G-05 registration ID/revision, declared host owner UID and profile digest.
   Record prerequisites and observed failures, including denied attachment.
2. **Explain the target at review time.** Produce a private sample review from
   the captured records. Distinguish the operator's label and declared owner
   from the observed epoch, instance, root, namespaces and mappings. An operator
   should be able to explain what the label refers to and which facts justify
   that claim. Exercise the existing host workflow alongside it: follow a thin
   request's public TIMEOUT to the private diagnosis by execution ID, and show
   the immediate REJECTED outcome for explicit refusal of a validated full CSR.
3. **Exercise replacement and revocation.** Pause a fixture review, replace B
   under the same name, and record two outcomes. If the anchor dies, its instance
   becomes invalid. If the old anchor survives, its binding still identifies the
   old process environment. Revoke the old revision, register the replacement
   with a fresh instance, and verify that the pending review cannot authorize
   the replacement. Record what the administrator must do when no manager
   lifecycle signal is available.
4. **Simplify the host code before adding selectors.** Give each public v3 wire
   document one authoritative serialized type and validator shared by client
   and daemon. Keep private preparation inputs such as ComposeFS enrollment in
   the trusted binding. Exercise the real parse/serialize paths against existing
   canonical vectors, unknown-key rejection and target-independent context tests.

**Exit gate:** Deliver the reproducible recipe, private review example and a
reusable fixture with an account present only in B, distinct executable bytes
at the same absolute path on host and in B, and a distinguishable destination
cwd. Record acquisition, revision replacement, revocation and actual cleanup
on the stated topology. Run Phase 1 host regressions after the wire-type
consolidation. This milestone exercises registration and review semantics in
the fixture. Production registry integration and destination preparation belong
to Phase 2, workload spawn to Phase 3. Record any unsupported anchor topology
and keep its dependent route gated.

### Phase 2 — Pinned targets and destination preparation

**Dependencies:** Phase 1.5's demonstrated anchor workflow, G-01 acquisition and G-05 management contracts.
**Subsystems:** target registry, workers/helpers, account/path/evidence preparation,
source access, authorization and cancellation.

**Deliverables:**

- Integrate registered B first. Reuse the Phase 1.5 fixture through the production
  registry and preparation workers. At the pending-review boundary, revoke or
  replace the registration and verify that authorization fails for the old
  revision. Check the destination-only account, executable bytes and cwd.
- Extend the same ownership path to validated daemon-PID-scope process targets.
  Retain pidfd/proc/namespace/root resources, mappings and lifecycle state; scope
  instances to the daemon epoch and invalidate rather than re-resolve.
- Revalidate before review/final authorization and retain the same owner for later
  spawn checks. Add anchor monitoring and resource-exhaustion behavior.
- Prepare accounts, executable, cwd and environment in bounded destination
  helpers. Start with numeric credentials or bounded account-file parsing;
  never execute arbitrary target NSS modules with host privilege.
- Provide explicit cross-domain thin intent. Keep unsupported full/full-only/
  export access domains closed; do not turn them into privileged expansion.
  Select unsigned executable evidence in the destination and preserve signed
  bytes/model/target exactly.

**Exit gate:** Tests prove stale bindings cannot retarget; private preparation
cannot disclose target existence/accounts; account/mapping edits do not redirect
approval; identical paths with different bytes/cwd use the intended destination.
Target/helper leases remain charged through real cleanup. No container workload
execution is advertised yet.

### Phase 3 — Native execution and supervision

**Dependencies:** Phase 2 and validated G-02/G-03 plans; G-01 for self.
**Subsystems:** launcher/executor, syscall-only child setup, cgroups, reaper,
checkpoints and runtime lifecycle.

**Deliverables:**

- Implement validated namespace/root entry with declared private isolation and
  explicit final-child creation after PID/time namespace entry.
- Preserve retained executable/stdio inputs, exact destination credentials,
  capabilities, securebits and NNP; verify the actual final context.
- Enforce host-controlled job placement/limits, launcher/final-child ownership,
  cancellation, anchor-death teardown, deadlines and descendant cleanup.
- Run the Phase 2 host → B request end to end first. Observe the actual child's
  account, executable output and cwd, then cancel a job and verify descendant
  cleanup. Repeat the pending-review replacement case and check for zero spawn.
- Next exercise A → host with both public endpoints exposed. Add A → self with
  the connector handshake and inherited/passed-socket cases, then A → B with
  independent source and destination lifetimes. Cover supported rootful/rootless targets and
  same-owner/cross-owner policy. Enable self only when its acquisition and
  transport semantics are integrated and verified.

**Exit gate:** Integrated route, namespace, mapping, placement, setup-fault,
registration-race and cleanup scenarios pass for declared profiles. Any blocked
route remains explicitly incomplete; passing explicit targets does not complete
self. Work at this stage remains experimental until applicable Phase 4 gates pass.

### Phase 4 — Confinement, full evidence and packaging

**Dependencies:** Phase 3; G-04 and the applicable full-access G-05 contract.
**Subsystems:** security profiles, exec verifier, source access, evidence negotiation,
approval, daemon packaging and privileged acceptance.

**Deliverables:**

- Qualify one explicit host → B deployment first using the same fixture,
  operator recipe and actual child observations. Publish the supported topology,
  evidence model and enforcement prerequisites for each additional route.
  Keep G-04's strict concurrent-policy-replacement case open until verified.
- Implement supported composable SELinux/AppArmor transitions and actual-state
  verification, policy-change handling and declared seccomp restrictions.
  Include memfd checkpoints wherever the approved profile requires them.
- Validate profiles on genuinely enforcing systems. Disabled, unreadable,
  unconfined and permissive/complain states cannot satisfy required enforcement;
  never remove NNP/tracing or switch signed executable models to pass a test.
- Add supported destination full-CSR/export access and binding paths. Reconcile
  unsigned evidence eligibility across cloned ComposeFS/PrivateMounts while
  preserving provenance, exact intent and signed-mismatch rejection.
- Supply daemon LSM packaging policy separately from target confinement policy.
  Document socket exposure, delegation, explicit fresh provisioning and profile
  limitations for administrators.

**Exit gate:** Each candidate production profile passes real enforcing-platform,
full/thin/export/evidence, public/private-outcome, durable-consumption and lifecycle
cases. Any unsupported full-access or confinement combination remains rejected
and listed. No claim of arbitrary requester confinement or manager-exec equivalence.

### Phase 5 — Optional resolvers and release qualification

**Dependencies:** Validated executor/authorization contracts from Phases 1–4.
**Subsystems:** manager adapters, lifecycle evidence, deployment documentation and
acceptance/release reporting.

**Deliverables:**

- Replay the Phase 1.5 same-name replacement with the old anchor still alive.
  For a manager-backed target, demonstrate which authenticated manager event or
  generation check invalidates the old binding and how resolver loss is handled.
- Add optional manager resolvers scoped by endpoint, owner/tenant and manager
  namespace. Validate their resources through the existing acquisition path;
  names and user-owned metadata confer no independent authority.
- Bind required lifecycle/configuration evidence and handle stop/delete,
  replacement, name reuse and resolver loss without redirecting a job.
- Complete the platform/profile matrix and publish reproducible evidence for all
  advertised routes. Mark unsupported cases, experimental features and optional
  adapters explicitly. A validated manager-free release does not wait for adapters.

**Exit gate:** Manager integration passes scoped-name, dishonest/stale metadata,
replacement and teardown cases without changing host authorization ownership.
Every shipped profile passes all applicable V/NS requirements; no helper-only
fixture substitutes for end-to-end evidence.

## Requirement and acceptance traceability

The main specification defines required results. This table assigns delivery and
verification ownership, preserving the original proposal's acceptance coverage.

| Requirement | Contract location in main spec | Phases | Required evidence |
| --- | --- | --- | --- |
| NS-01 — Routes/deployment | §1.5 | 0, 1.5, 3–5 | Existing rootless B operator recipe; four routes; rootful/rootless; correct destination account; both client endpoints |
| NS-02 — Source attribution | §1.5 | 0, 2–3 | Shared/unshared namespaces, inherited/passed sockets, connector exit, exec/credential races |
| NS-03 — Selector/identity separation | §1.5 | 0–2 | Names/PIDs/inodes/cgroups/images cannot independently authorize or identify a generation |
| NS-04 — Instance lifetime | §1.5, §4.2 | 0, 1.5, 2–3 | Same-name replacement with a surviving anchor; PID reuse, context/change-and-restore races, anchor death, restart/replacement and daemon restart |
| NS-05 — Mapped authority/injection | §1.1, §4.2 | 0, 2–4 | Nested/unmapped credentials, groups/setgroups, rootless UID 0, injection authority and mapping composition |
| NS-06 — Scoped/cross-owner policy | §1.5–1.6, §4.1–4.2 | 0–3 | Requester/signer ceilings, cross-owner approval, equal integers in different domains |
| NS-07 — Destination/access | §2.2.1 | 1.5 (fixture), 2, 4 | Different bytes/cwd at same paths, account changes, mutable roots, bounded lookup and requester-access denial |
| NS-08 — Evidence/provenance | §2.2.1–2.2.2 | 2, 4 | ComposeFS/PrivateMounts, default/full-only/export/thin, unsigned negotiation and signed substitution rejection |
| NS-09 — Placement | §5.4 | 0, 3–4 | Userns/delegation, cgroup view versus membership, limits, escape boundary and manager teardown |
| NS-10 — Executor | §5.4 | 0, 3–4 | Root/cwd, namespace ordering, PID/time children, idmapped mounts, final context and syscall-only setup |
| NS-11 — Confinement | §5.5 | 0, 4 | Enforcing SELinux/AppArmor, full ranges/stacks, policy reload/reuse, seccomp and NNP/ptrace/direct/memfd |
| NS-12 — Ownership/privacy | §5.4 | 1–5 | Cancellation/disconnect, target/helper/tracer death, exhaustion, blocked cleanup, TIMEOUT timing and irreversible consumption |
| NS-13 — Resolvers | §1.5 | 5 | Scoped identity, metadata trust, loss/restart, no direct-runtime bypass of manager assumptions |
| NS-14 — Approval binding | §3.2–3.2.1, §6.3 | 0–4 | Independent schema/crypto fixtures, identity/profile substitution, complete approval display |
| NS-15 — Audit/versioning | §7 | 1–5 | Private source/approved/observed distinction, execution digest equality, fresh state and collector binding |
| NS-16 — Release evidence | §8.3–8.4 | All | Reproducible integrated matrix; truthful current/target/deferred status |

Record exact kernel/architecture, namespace/mapping topology, cgroup delegation,
LSM enforcement/policy versions and executable model with privileged results.
Use deterministic clocks for disclosure scheduling and bounded sockets for
actual delivery. Run raw-socket cases as well as CLI cases; namespace-root and
ordinary delegated-platform tests supplement rather than replace real-host gates.

## Scope, decisions and documentation completion

The former proposal is incorporated as follows: goals/deployment and identity
move to §1.5; destination preparation to §2.2; signed semantics to §3.2 and §4;
execution/lifecycle to §5.4; confinement to §5.5; acceptance to §8. The native
backend rationale remains here. The Phase 0 record distinguishes the draft registration grammar from the
installed host CLI; friendly manager names require Phase 5 integration.

Keep these independent features deferred unless explicitly selected for a
separate milestone: PTY, hook runtime, remote collector/ACK runtime, reload,
reusable grants, direct scripts and additional signing adapters. Preserve their
target contracts in the main spec. Physical FIDO claims need hardware evidence.
No namespace phase claims interpreter dependency integrity, arbitrary existing
seccomp extraction, remote execution or automatic account translation to the host.

For this documentation update, validate relative links/anchors, section references,
application versus Linux ABI versions, JSON/TOML/SQL examples where concrete,
PAE lengths/hex and intent hashes. Review wire, approval, policy, consumption,
audit and collector bindings together. All draft schemas need independent
fixtures before their runtime release. README and implementation notes must
describe the shipped v3 host behavior; changing this roadmap does not close a
runtime gate or enable any CLI option.
