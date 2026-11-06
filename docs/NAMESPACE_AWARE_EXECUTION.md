# Namespace-aware execution: phased v3 roadmap

Updated 2026-11-05. This is the delivery roadmap for the
[draft normative v3 security specification](<../sigrun sigrund Security Architecture and Implementation Specification.md>).
The specification owns the contract; this document owns implementation order,
feasibility decisions, acceptance evidence and deferred scope. NS-01–NS-16 refer
to its stable namespace requirements; G-01–G-05 refer to its release-blocking
design gates. This roadmap does not introduce usable CLI options.

## Current state and intended outcome

The current runtime implements a local **v2** one-time SSH/stdio profile. It runs
jobs in the daemon's configured domain, creates private namespaces for isolation,
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
of old state. Keep runnable v2 documentation accurate until implementation changes.

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
uses host and administrator-validated explicit targets. Self requires its own
source-attribution gate.

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

### Phase 2 — Pinned targets and destination preparation

**Dependencies:** Phase 1; G-01 acquisition and G-05 management contracts.
**Subsystems:** target registry, workers/helpers, account/path/evidence preparation,
source access, authorization and cancellation.

**Deliverables:**

- Add administrator-registered and validated daemon-PID-scope process targets.
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
- Exercise all four routes using supported rootful/rootless targets and
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
| NS-01 — Routes/deployment | §1.5 | 0, 3–5 | Four routes; rootful/rootless; correct destination account; both client endpoints |
| NS-02 — Source attribution | §1.5 | 0, 2–3 | Shared/unshared namespaces, inherited/passed sockets, connector exit, exec/credential races |
| NS-03 — Selector/identity separation | §1.5 | 0–2 | Names/PIDs/inodes/cgroups/images cannot independently authorize or identify a generation |
| NS-04 — Instance lifetime | §1.5, §4.2 | 0, 2–3 | PID reuse, context/change-and-restore races, anchor death, restart/replacement and daemon restart |
| NS-05 — Mapped authority/injection | §1.1, §4.2 | 0, 2–4 | Nested/unmapped credentials, groups/setgroups, rootless UID 0, injection authority and mapping composition |
| NS-06 — Scoped/cross-owner policy | §1.5–1.6, §4.1–4.2 | 0–3 | Requester/signer ceilings, cross-owner approval, equal integers in different domains |
| NS-07 — Destination/access | §2.2.1 | 2, 4 | Different bytes/cwd at same paths, account changes, mutable roots, bounded lookup and requester-access denial |
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
backend rationale remains here. CLI examples are deliberately omitted until
G-05 fixes the grammar; friendly manager names require Phase 5 integration.

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
continue to describe actual v2 behavior; changing this roadmap does not close a
runtime gate or enable any CLI option.
