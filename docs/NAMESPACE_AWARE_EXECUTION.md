# Namespace-aware execution: phased v3 roadmap

Updated 2026-11-10. This is the delivery roadmap for the
[draft normative v3 security specification](<../sigrun sigrund Security Architecture and Implementation Specification.md>).
The specification owns the contract; this document owns implementation order,
feasibility decisions, acceptance evidence and deferred scope. NS-01–NS-16 refer
to its stable namespace requirements; G-01–G-05 refer to its release-blocking
design gates. Supported host CLI options are documented in the
[Phase 1 record](NAMESPACE_PHASE1.md). Registered/process private review is
documented in the [Phase 2 guide](NAMESPACE_PHASE2.md). Opt-in experimental
namespace execution and self capture are documented in the
[Phase 3 guide](NAMESPACE_PHASE3.md).

## Current state and intended outcome

The current runtime implements the local **v3 host** one-time SSH/stdio profile,
with explicit host/account/profile selection and a retained epoch-bound owner.
It runs jobs in the daemon's configured domain, creates private namespaces for isolation,
and uses a requester-access helper limited to the daemon filesystem domain and
initial userns mappings. Direct-execution checkpoints verify executable evidence
and credentials; they are not general namespace/LSM verifiers. See
[implementation notes](../IMPLEMENTATION_NOTES.md#executable-trust-selection)
for the ComposeFS limitation and current coverage. Namespace-root fixtures do
not establish container-routing support.

Phase 2 adds production root-controlled registration of a constrained dedicated
anchor, cached destination roots and bounded account/path preparation. Explicit
registered/process thin requests reach verified private root-TTY review and final
signature checks, then stop before consumption, public APPROVED and workload
spawn. All public namespace outcomes under those profiles retain the
admission-based TIMEOUT.

Phase 3 adds a distinct experimental constraint contract. Registered/process and
self thin requests under that profile can consume, receive APPROVED and run
through a verified final-child exec stop. Four routes, initial/one-child-userns
targets and namespace ownership/failure cases have integrated production-code
qualification, with complete host regression passing. Historical Phase 0/2
profiles retain their private no-execution boundary. This is experimental
execution without a production LSM/seccomp confinement claim.

Phase 4 qualifies the explicit `namespace-selinux-v1` thin one-time SSH/stdio
profile on Fedora 44 x86-64 across all four routes, including real rootless sources.
Its [record](NAMESPACE_PHASE4.md) separates the installed qualification snapshot
from subsequent producer-guard and older-kernel authentication fixes. Phase 5
consolidates final-candidate release evidence for this manager-free scope;
optional manager integration follows as a separate milestone. Neither milestone
automatically enables the independent later Phase 4 gates.

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
injection are out of scope. Unsigned requesters need the execution socket and
`.context`; a self requester also needs `.anchor`. For host → registered B,
only B's dedicated anchor needs the rendezvous endpoint inside B. Management,
approval and state stay on the host. See the [endpoint table](NAMESPACE_PHASE3.md#operator-workflow).

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

**Status:** Complete for the recorded native rootless fixture and production
host schema consolidation (2026-11-07). The [operator recipe and implementation
record](NAMESPACE_PHASE15.md) and [sanitized qualification evidence](evidence/namespace-phase15-20261107.json)
record eight fixture gates, all 11 ordinary checks and all 23 Phase 1 host
acceptance gates. The [Phase 0 record](NAMESPACE_PHASE0.md#g-05-bounded-records-and-administration)
supplies the frozen registration grammar and evidence contracts. Production
registry integration, destination preparation and workload spawn retain their
Phase 2 and Phase 3 ownership.

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

The qualified fixture uses Fedora 44 x86_64, kernel
`6.19.10-300.fc44.x86_64`, enforcing SELinux with an administrative unconfined
supervisor, and one child user namespace whose parent is the initial namespace.
All selected non-user namespaces belong to that child. Automatic subordinate
mappings have observed `setgroups=allow` and empty inherited supplementary
groups. Missing host ptrace permission and mixed namespace ownership were
rejected. The original and replacement anchors were killed and reaped, retained
FD counts returned to baseline, fixture paths were removed, and both external
supervisors finished with empty or removed cgroups. Nested and manager-created
topologies require their own qualification. G-04's later confinement gates remain
open for their declared combinations.

### Phase 2 — Pinned targets and destination preparation

**Status:** Complete for the qualified private-review boundary (2026-11-08).
Production registration, destination preparation, root-TTY review and final
signature checks pass 21 namespace gates, all 11 ordinary checks and the full
23-gate host acceptance suite. The disposable guest was removed after preserving
evidence and verifying cleanup. See the [operator guide](NAMESPACE_PHASE2.md)
and [sanitized qualification record](evidence/namespace-phase2-20261108.json).
Namespace workload execution remains disabled.
The [review follow-up](NAMESPACE_PHASE2_REVIEW.md) supersedes the initial source
snapshot: all 13 review findings are addressed, with 25 production namespace
gates and the complete host acceptance suite passing on the corrected build.

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

The production process-context digest uses versioned
`sigrund.process-context.v1`: the frozen acquisition record plus the cached
executable-root identity map. This pins roots for the entire generation and
preserves the historical Phase 0 bytes. The independent execution-binding digest
still covers exactly canonical `{target_binding, security_constraints}`.
Registration uses the live host daemon epoch; restart requires fresh capture.
Namespace profiles are prospective review obligations in this phase. Workload
confinement has no execution claim until the Phase 3/4 gates pass.

#### Phase 2 acceptance applicability

The [Phase 2 guide](NAMESPACE_PHASE2.md) records commands, topology and evidence.
This table adds namespace preparation/review dispositions to the host V-01–V-20
record above. A private approval never closes a namespace workload gate.

| Gate | Phase 2 disposition |
| --- | --- |
| V-01 | Strict namespace record/context/review schemas and frozen vectors pass; existing v3 provisioning/version rejection remains a host regression gate. No new durable namespace schema is introduced. |
| V-02 | Public context remains target-independent. Management/anchor records travel on separate bounded endpoints; profile and target absence receive no public evidence. |
| V-03 | Real registered and daemon-PID process thin selection, named/numeric accounts and finite input pass. Namespace full-only/export/bundle options fail locally. |
| V-04 | Different bytes/cwd at the same path use the retained destination. Cached root pathname replacement cannot redirect preparation. Namespace full-access proof and cloned mount domains remain Phase 4. |
| V-05 | Raw unknown target/account/profile, refusal, absent/partial/disconnected/late approval and malformed helper IPC preserve scheduled TIMEOUT and zero workload output. Finite stdin is drained before private lookup. |
| V-06 | Exact CSR/context/constraint/selector checks pass. Replacement changes revision, instance and profile; pending old review fails. Account edits preserve signed credentials; restart discards registrations and rejects stale full/signed input without fallback. |
| V-07 | Real destination digest-memfd and digest-direct evidence passes; direct access checks use composed host credentials. Namespace ctime/fs-verity, ComposeFS and workload checkpoints remain later qualifications. |
| V-08 | Numeric and named destination IDs/groups are signed and mapped independently; equal local integers and equal mapped host UIDs are distinguished. Actual namespace child credentials/capabilities remain Phase 3. |
| V-09 | The final signature/policy/evidence predicate is exercised before a hard private no-consumption gate. Late replies cannot grant. Namespace durable commit is deliberately unavailable. |
| V-10 | No namespace APPROVED or spawn exists, including after a valid signature, partial reply or disconnect. Host delivery-before-spawn and later-failure consumption remain regression gates. |
| V-11 | Independent frozen JCS/digest and existing production signing vectors pass; real root TTY uses the normal SSH signature path. Namespace offline export/redemption is closed. Physical FIDO remains unqualified. |
| V-12 | Production management and helper framing is bounded. A corrupted real FD transfer closes received rights and permits a healthy retry. Existing raw transport/blocked-I/O host checks remain required. |
| V-13 | Ordinary tests cover global/per-UID target/review limits and retired registrations. Privileged blocked actual root close retains helper quota, rejects excess acquisition, and allows reacquisition only after disposal. One-review broker limit remains. |
| V-14 | Revocation, replacement and anchor death cancel pending approval while the old owner remains retained. Process selectors cannot reacquire arbitrary PIDs. Namespace grants cannot be consumed or replayed. |
| V-15 | Private audit separates authenticated source, approved mapped destination and null observed execution; its binding digest matches independent CSR hashing. Namespace DB/collector consumption is absent. Host three-way digest equality remains the collector milestone. |
| V-16 | The shipped root TTY verifies root epoch records and displays complete escaped acquisition, registration, mappings, credentials, provenance, pinned roots and prospective constraints before signing. Mismatch tests prevent rendering. Hooks remain deferred. |
| V-17 | Actual requester CLI receives TIMEOUT, no stdout and no early output EOF. Namespace stdio relay/PTY execution is deferred; host stdio/cancellation checks remain required. |
| V-18 | Fresh-exec production capture/preparation passes on the stated rootless topology; mixed ownership, missing roots and denied ptrace fail closed. Namespace entry, placement and final-child faults remain Phase 3. |
| V-19 | Namespace registrations are ephemeral and never reconstructed from durable IDs. Host audit/recovery and consumption regressions remain required; external rollback protection is still deferred. |
| V-20 | Production shutdown reaps a live capture/anchor and removes management/anchor listeners; restart creates a fresh epoch. Whole-service cleanup is independently verified. Namespace workload teardown remains Phase 3. |

### Phase 3 — Native execution and supervision

**Status:** Complete for the declared experimental profile/topology. The 39-case
namespace matrix, 25-case Phase 2 regression, eleven ordinary checks and complete
23-gate host acceptance pass with matching source and binaries. See the
[implementation and qualification guide](NAMESPACE_PHASE3.md).

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

#### Phase 3 acceptance applicability

The 39-case production runner qualifies the experimental profile on Fedora 44
x86-64, enforcing ambient SELinux with an unconfined administrative service,
cgroup v2 delegation, initial userns self targets and one-child-userns B targets.
Its four actual CLI routes use different destination executable bytes. The A
source uses the initial user namespace even when its root and other namespaces
are private. Authenticating the daemon from a rootless source, nested/mixed
namespace ownership and idmapped mounts remain unqualified.
The Phase 3 guide describes these boundaries and exact reproduction commands.

| Gate | Phase 3 experimental disposition |
| --- | --- |
| V-01 | Strict versioned experimental constraints/self-context/review contracts and unchanged historical vectors pass. The full host run requalifies v3 provisioning and startup rejection. |
| V-02 | Context remains target-independent; self uses a separate bounded anchor rendezvous and private epoch evidence. |
| V-03 | Real CLI host→B, A→host, A→self and A→B, process selection, named/numeric destination accounts and connector relay pass. |
| V-04 | Actual different destination bytes, retained roots/cwd and mapped accounts pass. Namespace full-access proof remains Phase 4. |
| V-05 | Experimental root/groups denial, partial/disconnected/late broker approval and target invalidation retain scheduled TIMEOUT with no workload output. |
| V-06 | Source substitutions are rejected; account edits preserve approved numeric IDs; pending same-name replacement keeps the old anchor and prevents old consumption/spawn. |
| V-07 | Digest-memfd execution is sealed and independently verified at exec stop. Other namespace executable models are not enabled by this profile. |
| V-08 | Actual mapped nonroot UID/GID, empty groups/five capability sets, securebits 15, NNP, root/cwd and private namespaces are checked before target instructions. |
| V-09 | Final worker proof binds the exact warrant and live lease. A gated late durable commit retains consumption without spawning after public TIMEOUT. |
| V-10 | Partial APPROVED delivery, setns/root/private-mount/final-clone errors, short handoffs, setup deadline and final credential/NNP/exec failures produce zero workload output and retain consumption. |
| V-11 | Existing independent signing/digest vectors pass; actual root-TTY SSH signing enables self execution. Namespace full/export/offline remains closed; physical FIDO remains unqualified. |
| V-12 | Native launch handoff checks strict ordering, sizes, ancillary rights and kernel pidfd identity; malformed real transfers clean up without losing consumption. |
| V-13 | Blocked namespace cleanup retains the sole per-UID helper through another request's TIMEOUT, permits another UID's host execution, then admits a healthy retry after actual cleanup. Capture reservations are staged before acquisition. |
| V-14 | Revocation/disconnect and self connector death kill primary and session-detached descendants. Retained generations never follow a replacement. Namespace standalone signed redemption remains rejected. |
| V-15 | Namespace consumption stores the same 32 raw digest bytes as private AUTH_COMMIT and collector target_auth; deliberate collector mismatch is rejected. Observed execution is separate from approved target/source facts. |
| V-16 | The real root TTY verifies and displays authenticated connector evidence, live acquisition/mappings, resolved accounts, provenance and complete experimental constraints before signing. |
| V-17 | Actual CLI/stdio relay, output in the selected destination and descendant cleanup pass. PTY remains deferred. |
| V-18 | Native host-cgroup launcher, PID/time final child, subreaper adoption, exec checkpoint, private run/cgroup mounts, setup-FD closure and thirteen real setup/handoff fault cases pass. Fresh-exec memory isolation, dumpability admission, null-input binding and covered-cwd rejection also pass. |
| V-19 | Namespace durable consumption and digest equality pass, with full host provisioning/audit recovery regression. External rollback protection remains deferred. |
| V-20 | Namespace revocation, connector/peer death, blocked cleanup and whole-service supervisor cleanup pass. Phase 2 requalifies capture shutdown/restart; full host crash/shutdown and operator-service regression pass. |

NS-01/02 are exercised by the four routes, original-connector socket passing and
self connector death. NS-03/04/06 use retained generations, independent scoped
rules and replacement/revocation checks. NS-05/07/08 are limited to the declared
mapping topologies, thin destination preparation and sealed-byte profile.
NS-09/10 verify actual placement/context and native fault cleanup. NS-12/14/15
cover retained ownership, disclosure scheduling, exact approval and three-way
digest equality. NS-16 has the matching complete regression record in the
[sanitized evidence](evidence/namespace-phase3-fedora44-20261109.json), with private
raw artifacts preserved and the disposable VM removed. NS-11 production confinement stays in Phase 4 and NS-13
manager resolvers in Phase 5.

### Phase 4 — First production namespace profile

**Status: the first thin-only production gate is qualified on Fedora 44 x86-64.**
The [Phase 4 record](NAMESPACE_PHASE4.md) and
[sanitized evidence](evidence/namespace-phase4-fedora44-20261110.json) cover the
installed host → registered rootless B route and real rootless A → B, A → host
and A → self. The explicit `namespace-selinux-v1` profile requires enforcing
requester/producer/workload domains, locked untrusted accounts and trusted
unconfined host administrators. Follow the
[installed operator recipe](NAMESPACE_PHASE4_OPERATOR.md). Qualification applies
to this named deployment and thin one-time SSH/stdio scope. The independent later
gates below remain closed until separately qualified.

**Carry forward two Phase 3 security checks:**

- **Client authentication (NS-01).** The Phase 3 client could send intent and
  finite stdin to a substitute socket whose unprivileged host owner appears
  as UID 0 to a rootless requester. Reject an unprovable peer before sending
  a query, request or rights. Test counterfeit context and execution listeners
  independently, and retain a genuine host-peer positive control. This is a
  client disclosure, not evidence of host authorization bypass. Supporting a
  rootless requester is a separate gate from running *into* rootless B.
  The installed qualification passes genuine rootless endpoints on all four
  routes and rejects counterfeit context, execution and anchor listeners before
  data or rights. The exact requester-domain prerequisite is part of that scope.
- **Requester injection (NS-05).** Exercise a requester with a different mapped
  UID from the workload but ownership of, or tracing authority over, B's user
  namespace. Attempt attachment after exec-stop release; include a control that
  demonstrates the attempted trace can succeed without the claimed guard. This
  is qualified for the enforcing production profile: the different-UID owner
  control attaches successfully, while attachment to the released self workload
  is denied. The experimental profile rejects known nonroot namespace-owner
  authority before destination preparation/review, including self.

**First production gate (NS-16), passed for the deployment above.** The
qualification records all of the following from installed packages:

1. **Bring B online.** Document the exact OS, kernel, namespace ownership and
   mappings, delegation, socket exposure and LSM prerequisites. Provision fresh
   v3 state, configure independent daemon and signer rules, and start the
   service. Use a supported tool or reproducible installation recipe to start
   the dedicated disposable anchor in the running B. Register it from the host.
   The operator must be able to do this without running the test harness.
2. **Enforce one immutable profile (G-04).** Specify the executable model,
   effective LSM requirements, explicit seccomp policy and policy-change
   guarantee. Package daemon policy separately from workload policy. Verify
   actual confinement at exec stop on an enforcing system, then exercise a
   workload operation denied by that policy. Reject disabled, unreadable, permissive,
   complain, unconfined or mismatched states when enforcement is required.
   Preserve NNP, tracing and the signed executable model. When adding this
   transition, give the Rust and C launcher one authoritative descriptor and
   event layout and test malformed handoffs and cleanup. A sealed image does
   not bind libraries or scripts subsequently loaded from B.
3. **Run and withdraw the command.** Follow the operator guide: approve the
   destination-only account, credentials, executable and cwd; distinguish
   APPROVED from readiness; check actual child identity, output and exit status.
   Correlate a public TIMEOUT with its private diagnosis by execution ID. Revoke
   during review (no consumption or spawn) and during execution (whole-job
   teardown). Restart the daemon, verify the old binding is unusable, and
   register a fresh anchor for a successful retry.
4. **Publish release evidence.** Record package versions/digests, commands,
   platform, observed enforcement, public/private outcomes, durable consumption
   and actual descendant cleanup. Re-run host acceptance and applicable V/NS
   cases against the candidate. Verify that namespace full-only/export fails
   locally without submission or an exported CSR. Raw full/signed namespace
   submissions that reach authorization must retain the scheduled TIMEOUT
   without fallback, consumption or spawn. These negative results qualify the
   exclusions; an untested applicable confinement or lifecycle guarantee blocks
   release.

**Later Phase 4 gates, independent of the thin-only release:**

| Capability | Evidence required before enabling it |
| --- | --- |
| Namespace client-full, export and offline redemption (G-05) | Trusted epoch binding distribution, requester-limited destination access, cloned ComposeFS/PrivateMounts evidence where applicable, preserved provenance, signed mismatch and replay rejection. |
| Other source topologies and routes | Establish host authority in each source user namespace; test real and substitute endpoints, original-connector attribution and applicable self/anchor lifetimes. Never accept overflow or mapped UID zero alone as host-root proof. |
| Other LSM stacks, executable models or policy-change guarantees (G-04) | Qualify each combination on its enforcing system with NNP and tracing intact. For a claim that no instruction runs under concurrently replaced policy, demonstrate serialization for the complete job lifetime; final token sampling is insufficient. Keep the strict combination blocked otherwise. |

Manager-backed identity and teardown remain Phase 5. A manager-free profile
identifies the registered process environment and carries no manager-exec claim.

### Phase 5 — Optional resolvers and release qualification

**Dependencies:** Validated executor/authorization contracts from Phases 1–4.
**Subsystems:** manager adapters, lifecycle evidence, deployment documentation and
acceptance/release reporting.

**Status: Phase 5A and the selected Phase 5B Podman deployment are qualified.** The
[Phase 5A completion record](NAMESPACE_PHASE5A.md) and
[candidate evidence](evidence/namespace-phase5a-20261110.json) cover clean candidate
`77ed109`, fresh installed RPM qualification and matching complete host acceptance.
The [Phase 5 delivery plan](NAMESPACE_PHASE5.md) defines reproduction obligations,
adapter design decisions and acceptance cases. Historical Phase 4 evidence remains
a separate snapshot. Publishing or merging the release is a separate action.

The [Phase 5B record](NAMESPACE_PHASE5B.md) and
[adapter evidence](evidence/namespace-phase5b-20261111.json) qualify Podman 5.8.1
on the named Fedora deployment for host and real rootless A sources to a rootful
Podman B. Runtime `164db5f` and verification snapshot `6b5fe87` have identical
runtime artifacts; the latter fixes only host trust-harness broker handoff.
Equal-name engine scope, generation/configuration loss, pending/running teardown,
ownership/quotas and matching host/manager-free regressions pass. Other manager
versions/deployments remain unqualified, with no manager exec-policy equivalence.

#### Phase 5A — Manager-free release qualification

- Freeze the candidate commit, build inputs, package/binary/policy hashes and
  advertised platform/profile/route matrix. Keep historical evidence immutable
  and identify which results cover the candidate, including the review fixes.
- Run ordinary release checks, complete host acceptance and the installed
  namespace matrix on matching candidate artifacts. Include host-only producer
  separation, older-kernel client/approver compatibility, source attribution,
  confinement, lifecycle, consumption/audit binding and exclusion regressions.
- Publish a reproducible, sanitized evidence bundle and reconcile the README,
  implementation notes, operator recipe and specification status. Record all
  applicable V/NS dispositions, failures and unsupported combinations explicitly.

**Exit gate:** Every advertised combination passes its applicable integrated
cases against the identified candidate. Fedora 44 x86-64 production namespace
evidence, Ubuntu 24.04 kernel 6.8 host compatibility and ARM64 cross-build results
remain distinct claims. No helper-only fixture substitutes for installed
end-to-end evidence. This manager-free release does not wait for adapters and
claims a retained process environment, not a manager execution generation.

#### Phase 5B — Optional manager integration

- The selected [Podman integration](NAMESPACE_PHASE5B.md) uses a local root-owned
  API, the default Libpod namespace, systemd cgroup v2 and a private PID-1 init.
  Its [operator recipe](NAMESPACE_PHASE5B_OPERATOR.md) defines trusted administrator
  access and the enforcing deployment. Other adapters/scopes remain unqualified.
  Endpoint/owner/namespace, generation/configuration evidence, observation bounds
  and permanent invalidation are explicit parts of the binding.
- Version the bounded selector/acquisition schemas and independent binding
  fixtures before exposure. Validate resolver results through the existing
  acquisition, private review and host authorization path. Names and user-owned
  metadata confer no independent authority; manager exec APIs are not a shortcut.
- Replay Phase 1.5 same-name replacement with the old anchor still alive. Prove
  which authenticated generation check or event invalidates the binding. Cover
  stop/delete, name reuse, stale/dishonest metadata, event gaps and resolver loss
  during review and execution, without reacquiring or redirecting an approved job.

**Exit gate:** The selected adapter passes scoped-name, generation, configuration,
loss/restart and whole-job teardown cases on its installed deployment while
preserving host policy, confidentiality and durable consumption. Publish its
matrix/evidence separately; adapters without passing evidence remain disabled.
Exact manager-exec equivalence requires its own demonstrated configuration and
lifecycle contract and is never inferred from namespace membership.

## Requirement and acceptance traceability

The main specification defines required results. This table assigns delivery and
verification ownership, preserving the original proposal's acceptance coverage.

| Requirement | Contract location in main spec | Phases | Required evidence |
| --- | --- | --- | --- |
| NS-01 — Routes/deployment | §1.5 | 0, 1.5, 3–5 | Existing rootless B operator recipe; four routes; rootful/rootless; correct destination account; route-specific endpoints and authenticated daemon |
| NS-02 — Source attribution | §1.5 | 0, 2–3 | Shared/unshared namespaces, inherited/passed sockets, connector exit, exec/credential races |
| NS-03 — Selector/identity separation | §1.5 | 0–2 | Names/PIDs/inodes/cgroups/images cannot independently authorize or identify a generation |
| NS-04 — Instance lifetime | §1.5, §4.2 | 0, 1.5, 2–3 | Same-name replacement with a surviving anchor; PID reuse, context/change-and-restore races, anchor death, restart/replacement and daemon restart |
| NS-05 — Mapped authority/injection | §1.1, §4.2 | 0, 2–4 | Nested/unmapped credentials, groups/setgroups, rootless UID 0, post-release requester tracing authority and mapping composition |
| NS-06 — Scoped/cross-owner policy | §1.5–1.6, §4.1–4.2 | 0–3 | Requester/signer ceilings, cross-owner approval, equal integers in different domains |
| NS-07 — Destination/access | §2.2.1 | 1.5 (fixture), 2, 4 | Different bytes/cwd at same paths, account changes, mutable roots, bounded lookup and requester-access denial |
| NS-08 — Evidence/provenance | §2.2.1–2.2.2 | 2, 4 | ComposeFS/PrivateMounts, default/full-only/export/thin, unsigned negotiation and signed substitution rejection |
| NS-09 — Placement | §5.4 | 0, 3–4 | Userns/delegation, cgroup view versus membership, limits, escape boundary and manager teardown |
| NS-10 — Executor | §5.4 | 0, 3–4 | Root/cwd, namespace ordering, PID/time children, idmapped mounts, final context and syscall-only setup |
| NS-11 — Confinement | §5.5 | 0, 4 | Enforcing SELinux/AppArmor, full ranges/stacks, policy reload/reuse, seccomp and NNP/ptrace/direct/memfd |
| NS-12 — Ownership/privacy | §5.4 | 1–5 | Cancellation/disconnect, target/helper/tracer death, exhaustion, blocked cleanup, TIMEOUT timing and irreversible consumption |
| NS-13 — Resolvers | §1.5 | 5B (optional) | Scoped identity, authenticated generation/configuration evidence, same-name replacement with a surviving anchor, loss/restart/event gaps and teardown; no direct-runtime bypass of manager assumptions |
| NS-14 — Approval binding | §3.2–3.2.1, §6.3 | 0–4 | Independent schema/crypto fixtures, identity/profile substitution, complete approval display |
| NS-15 — Audit/versioning | §7 | 1–5 | Private source/approved/observed distinction, execution digest equality, fresh state and collector binding |
| NS-16 — Release evidence | §8.3–8.4 | All; final candidate in 5A, adapters in 5B | Matching candidate/package/policy artifacts and reproducible integrated matrix; truthful current/target/deferred status |

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
