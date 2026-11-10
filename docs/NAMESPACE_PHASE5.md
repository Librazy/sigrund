# Namespace-aware execution Phase 5 delivery plan

Status: Phase 5A qualified, Phase 5B implementation and qualification in progress,
2026-11-10. This document refines the
[roadmap](NAMESPACE_AWARE_EXECUTION.md#phase-5--optional-resolvers-and-release-qualification)
and describes separate runtime qualification gates. The
[specification](<../sigrun sigrund Security Architecture and Implementation Specification.md>)
owns NS-13 resolver semantics and NS-16 release obligations. Phase 5A closes the
manager-free release evidence; Phase 5B is an optional, separately qualified
manager adapter. Phase 5A may ship while Phase 5B remains deferred.

The [Phase 5A completion record](NAMESPACE_PHASE5A.md) and
[candidate evidence](evidence/namespace-phase5a-20261110.json) qualify candidate
`77ed109` for the declared manager-free release scope. The requirements below
remain the reproduction and requalification checklist for future candidates.

## Phase 5A: identify and qualify the release candidate

The [Phase 4 record](NAMESPACE_PHASE4.md) contains an installed-package snapshot
and a separate review follow-up. Those results are inputs to final qualification,
not a single complete acceptance run against the final candidate. Preserve the
historical evidence JSON and publish a new candidate record.

The candidate matrix is deliberately limited:

| Combination | Existing evidence | Phase 5A obligation |
| --- | --- | --- |
| Fedora 44 x86-64, enforcing SELinux, `namespace-selinux-v1`, thin one-time SSH/stdio | Installed host → registered rootless B, real rootless A → B, A → host and A → self; follow-up route checks | Repeat complete installed namespace and host acceptance on matching final packages, including confinement, source attribution, lifecycle and exclusions |
| Packaged SELinux daemon with no namespace profiles | Follow-up approved UID 0/65534 commands leave the producer domain and cannot create reserved socket labels | Include the host-only producer regression in the candidate evidence |
| Ubuntu 24.04 x86-64, kernel `6.8.0-142-generic`, host authentication | Actual client and approver acceptance plus nsfs ancestry compatibility regressions | Repeat the compatibility cases on the older kernel; this row does not qualify production namespace execution or a full Ubuntu deployment |
| ARM64 host binaries | Cross-build only | Record candidate build evidence without an ARM64 runtime or production namespace claim |
| Other LSMs, executable models, namespace topologies or manager adapters | Not qualified by these results | Mark deferred/unsupported for this release; add a separate integrated gate before advertising support |

Freeze the exact candidate revision and clean-tree status before building.
Record toolchain/build inputs, source digest coverage, package versions and
digests, runtime and privileged-test binary hashes, installed policy hashes,
kernel/architecture, actual UID/GID maps, delegation, source domains and workload
constraints. Package stripping must be accounted for when matching tested and
installed binaries. A source digest that excludes documentation is not a complete
repository identity; retain the commit and evidence-document identity too.

Use the existing entry points, with the prerequisites and privilege boundaries in
their guides:

1. Run [ordinary release checks](../scripts/check.py) as the workspace user and
   retain the manifest and matching built/staged artifacts.
2. Build/install candidate packages in a disposable enforcing deployment and
   follow the [operator recipe](NAMESPACE_PHASE4_OPERATOR.md) from fresh explicit
   provisioning. Run [complete host acceptance](../scripts/verify-acceptance.py)
   against the matching artifacts.
3. Run the installed `verify-installed.py` matrix with lifecycle, security and
   exclusions enabled, `verify-source.py`, and `verify-bindings.py`. After
   draining/stopping the daemon, run `verify-host-only.py` as documented. Confirm
   restored enforcing policy, configuration and actual job cleanup.
4. Run the privileged client compatibility and actual approver gates through
   [the Rust gate runner](../scripts/verify-phase1-rust.py) on the older kernel.
   Retain genuine-peer positives and rejection of substituted ancestors, wrong
   namespace types, non-nsfs hints and non-ENOTTY failures. Keep the maximum-depth
   ancestry case and confined rootless compatibility controls on Fedora.
5. Reconcile all V-01–V-20 and NS-01–NS-16 dispositions for each advertised
   combination. A failed applicable case blocks that combination; an exclusion
   needs an explicit boundary and, where reachable, a rejection test. NS-13 is
   deferred because no manager adapter is enabled, not recorded as a test pass.

The new evidence bundle must associate each case with its command, environment,
candidate artifacts, expected/observed result and raw-log location. Include
public/private outcome correlation, consumption counts, observed descendant
cleanup, and canonical consumption/audit/collector binding equality where
applicable. Publish sanitized evidence only: omit keys, provisioning secrets,
ratchet state and private authorization payloads. Describe recovery and retained
state without publishing those contents.

If candidate code, policy or packaging changes, identify and rerun affected gates
and re-establish artifact matching before declaring release readiness. A
documentation-only change may reference unchanged checked artifacts with its
exact revision/delta recorded; it must not imply another runtime test run.

**Phase 5A completion:** publish the candidate matrix and evidence, align the
README/specification/implementation notes/operator guide, and record any blocked
combinations. This qualifies the declared release scope, not all v3 target
features. Publishing or merging the release remains a separate action.

## Phase 5B: select and qualify one optional adapter

Podman is selected as the first adapter. The [integration contract](NAMESPACE_PHASE5B.md)
and [operator recipe](NAMESPACE_PHASE5B_OPERATOR.md) define a local root-owned
Podman 5.8.1 service in the default Libpod namespace, systemd cgroup v2 and a
single private PID namespace on enforcing Fedora 44 x86-64. Rootless APIs,
other manager namespaces and Docker/containerd remain outside this gate.
Installed acceptance must pass before the selected combination is qualified.
The contract records:

- The authenticated manager endpoint, owner/tenant and manager namespace, who
  controls their metadata, and the host administrator's independent policy.
- How manager object identity and execution generation map to an acquired,
  retained process environment. A name, runtime ID or live old anchor alone is
  insufficient to establish a current manager generation.
- Required configuration/lifecycle evidence and its authenticated observation
  mechanism. Specify revalidation points, event ordering/gap handling,
  cancellation bounds, and behavior on resolver/manager restart or loss.
- Bounded/versioned selector and acquisition records, immutable evidence
  digests, exact private approval display, audit fields and independent schema/
  signature fixtures. Do not invent manager selector aliases in the existing CLI.
- Quotas and deadlines for resolver calls, retained resources and cleanup;
  unsupported configurations and any explicitly claimed manager-exec semantics.

All resolved resources pass through the existing acquisition, destination
preparation, daemon/signer policy, approval, consumption and supervision path.
Resolver access grants no host authority and adds no public existence oracle.
Changing required generation/configuration evidence invalidates the binding;
never refresh it in place to a replacement. Loss of required evidence invalidates
pending authorization and cancels active jobs. Recovery requires fresh
acquisition and approval, with no refund of durable consumption.

| Acceptance case | Required observation |
| --- | --- |
| Equal names across endpoints, tenants/owners or manager namespaces | Exact configured scope is enforced; no cross-scope resolution or authority |
| Dishonest/stale metadata, reused runtime ID, PID reuse or mismatched resources | Acquisition rejects the mismatch before authorization; names/metadata cannot redirect lookup |
| Same-name replacement with the original anchor still alive | Authenticated generation/lifecycle evidence invalidates the old manager binding even though its process resources remain live |
| Stop/delete, replacement or required configuration change during review | Pending binding invalidates; no consumption/spawn; admitted thin request retains scheduled TIMEOUT |
| The same events after durable consumption or during execution | No redirect/refund; no unreleased workload starts, or the running job and supervised descendants terminate within the declared containment boundary |
| Resolver disconnect/restart, lost events or uncertain generation | Required evidence is treated as lost; stale grants cannot resume after reconnection |
| Repeated failures, cancellation and exhausted resolver quotas | Bounded ownership/deadlines and actual cleanup; no silent admission or privacy bypass |
| Genuine scoped target and fresh acquisition after recovery | Real CLI/private approval/execution succeed, with correct credentials, confinement, consumption/audit binding and teardown |

Run these against the installed manager and candidate daemon, including real
replacement/teardown and independently observed descendants. Helper-only mocks
can support development but cannot close the adapter release gate. Do not bypass
manager lifecycle assumptions through direct runtime execution. Namespace entry
alone establishes no manager-exec equivalence.

**Phase 5B completion:** publish a separate adapter matrix, operator recipe and
reproducible evidence with all applicable V/NS dispositions. Unsupported managers
and combinations remain disabled; Phase 5A's manager-free claim stays distinct.

## Independent gates remain closed

Neither milestone enables namespace client-full/export/offline redemption,
process-PID production targets, other LSM stacks or policy-change guarantees,
other executable models, broader namespace topologies, or ARM64 production
execution. Each needs its own existing Phase 4 gate and integrated evidence.
PTY, hooks, remote collector/ACK, reload, reusable grants, direct scripts and
additional signing adapters remain separate milestones. No claim is added for
atomic policy replacement, interpreter dependency integrity or physical FIDO.
