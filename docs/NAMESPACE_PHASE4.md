# Namespace-aware execution Phase 4

## Qualified scope

The first thin-only production profile passed installed-package qualification on
2026-11-10: Fedora 44 x86-64, kernel `6.19.10-300.fc44.x86_64`, enforcing SELinux,
unified cgroup v2 and systemd delegation. It supports one-time SSH approval and
stdio for host → registered rootless B, real rootless A → B, A → host and A → self.
This qualifies the named deployment and immutable `namespace-selinux-v1` profile;
it is not a claim of complete namespace-specification conformance.

Follow the [installed operator recipe](NAMESPACE_PHASE4_OPERATOR.md). The
[sanitized evidence](evidence/namespace-phase4-fedora44-20261110.json) records
commands, source/package/binary/policy hashes, actual observations, outcomes and
cleanup. The recipe starts B independently, then enters B to start the disposable
installed `sigrund-anchor`; registration does not create the destination. Fresh
configuration, state and logs are provisioned explicitly. Installation starts
neither the daemon nor provisioning.

Untrusted source and destination-owner accounts are locked, have nologin shells,
no sudo and no alternate execution path. Their code runs in the enforcing
`sigrund_requester_t` domain through root-owned systemd units. All unconfined host
accounts are trusted administrators. Exposing sockets to an arbitrary unconfined
rootless container does not meet this deployment's prerequisites: Fedora permits
unconfined subjects to enter `init_t`, which can enter the reserved producer.
Neither subordinate UID ownership nor a profile name establishes these invariants.

A and B use different owners (host UIDs 1200 and 1300) and separate subordinate
ranges. Both have a single child user namespace owning all eight selected
namespaces; the approved nonroot service UID/GID is 12001 with empty groups.
The evidence records actual maps and mapped host credentials. Different owners
also keep the retained B acquisition and concurrent self acquisition/preparation
within the existing per-UID helper ceiling. Nested/mixed ownership, arbitrary
namespace sharing and idmapped-mount topologies are not qualified here.

## Enforced contract and host authentication

`sigrund.constraints.namespace-selinux.v1` binds digest-memfd execution, exact
workload context `system_u:system_r:sigrund_workload_t:s0:c1,c2`, sealed-image
context `system_u:object_r:sigrund_workload_exec_t:s0`, NNP, securebits 15,
empty capability sets, private mount/cgroup isolation and exec-stop verification.
The native x86-64 seccomp program denies `getppid` with EACCES and rejects foreign
architectures and x32 entry. Numeric root and nonempty supplementary groups are
excluded. Independent canonical constraint and execution-binding fixtures leave
historical Phase 0 fixtures unchanged.

The fresh-exec launcher sets its exec context while it still has trusted host
procfs, before entering the destination. The coordinator verifies the complete
installed BPF program at exec stop; the worker checks actual context/range,
enforcement, credentials, capabilities, namespaces, root/cwd, placement and setup
FD closure before release. Each positive namespace route performed the denied
syscall and attempted to read an independently labeled denial sentinel. Sealing
the ELF does not bind libraries or scripts subsequently loaded from B.

The client obtains its own user namespace using a kernel-created self pidfd and
`PIDFD_GET_USER_NAMESPACE`, independently of container-controlled procfs. Initial
user-namespace peers require host UID 0. Rootless clients require their exact
requester label, global and per-domain enforcement, genuine selinuxfs status/AV
queries and an endpoint-specific kernel socket label. Execution, context and
anchor roles have separate reserved types. Checks precede queries, intent,
signed submissions, finite stdin, rights and connector handshakes; authentication
failure never falls back to thin mode. Counterfeit listeners in the qualified
source domain received neither bytes nor ancillary rights.

The daemon, workload and requester SELinux modules are packaged separately.
Producer and untrusted types omit Fedora's generic `domain` and unconfined
attributes. Policy assertions prohibit untrusted process transitions, workload
injection and reserved socket SID creation/relabeling. Approved host commands
also leave the producer domain for `sigrund_host_workload_t`, including under a
host-only daemon configuration. The obligation travels through the sealed
launcher payload. A regression probe first reproduced reserved-label creation
by a nonroot host command in the producer domain, then verified denial after
this fix. The existing host contract retains its ambient-LSM semantics.

Startup rejects an unconfined/mismatched daemon, global or relevant per-domain
permissive mode, unreadable enforcement state and unavailable transition/filter
verification before publishing listeners. Kernel policy-generation dependencies
remain attached to target leases and running jobs. Policy change invalidates
bindings and terminates jobs; operators must drain jobs before policy replacement,
restart and register fresh anchors. Detection and termination do not serialize
policy replacement with every workload instruction.

`launcher_abi.h` supplies Rust and C descriptor/event layouts and payload version
3. Build-generated declarations and a native probe compare every field's offset,
size and alignment. Installed malformed handoffs cover unsealed/truncated input,
wrong version, missing producer guard or descriptors, bad bootstrap and bad
namespace FDs; no workload runs.

Experimental execution remains separate. It rejects nonroot namespace-owner
requesters, including self, before destination account/path reads when the
production injection guard is unavailable. Unknown ownership also rejects.
Historical Phase 3 evidence does not qualify a broader experimental combination.

## Verification and release dispositions

The checked release snapshot passed all eleven ordinary checks. The installed
RPM runtime binaries match that check manifest byte for byte. The installed
33-case four-route, lifecycle, confinement, malformed-handoff and exclusion matrix
passed, together with two additional installed source-attribution/lifecycle cases;
its case list and matching private/public outcomes are in the evidence record.
The complete host acceptance entry point also passed against the matching staged
RPM binaries, including privileged Rust, platform, runtime, trust, execution,
operator, recovery and shutdown gates. Its 23 host gates include ten privileged
Rust gates, seven trust cases and 26 execution cases. The final qualifier-only
updates have identical runtime and privileged test binary hashes; the evidence
records both checked snapshots and their three-file source delta. Compiled Rust
fixtures use the same build's recorded unstripped executables. The collector
validator independently
accepted matching canonical binding digests from consumption/audit and rejected
altered digests. ARM64 host binaries cross-built successfully; no ARM64 execution
or production namespace profile is claimed.

Complete APPROVED delivery precedes launch. A passed rootless stream remains
attributed to its original connector even when
a host-root process writes the request. Killing only a captured self connector,
with its relay alive, terminates the primary and a kernel-identified forked child.
Review revocation consumes nothing; running revocation kills the primary and forked descendant and retains durable
consumption. Restart retires the old registration; fresh registration succeeds.
A namespace owner could attach to a different-UID unguarded control, but attachment
to the released self workload was denied. Policy reload terminated that live job.
A real post-approval namespace-entry failure retained consumption, emitted no
workload bytes and never reached readiness. Final restoration returned all
required domains and global SELinux to enforcing mode.

| Cases | Applicable disposition for this profile |
| --- | --- |
| V-01, V-06, V-11 | Strict schemas, independent vectors, unchanged v3 provisioning, epoch/binding/signature checks and real root-TTY SSH approval pass. Namespace full/offline and hardware FIDO are excluded. |
| V-02, V-05, V-12, V-13 | Existing target-independent context, framing/deadline/resource ownership and host confidentiality regressions pass. Installed raw full/signed submissions retain scheduled generic TIMEOUT with no consumption/output; counterfeit source listeners receive no data or rights. |
| V-03, V-04, V-07 | The four installed routes use the selected destination's distinct bytes, retained root/cwd, named account and digest-memfd model. Namespace full-only/export fails locally without submission/export. Other executable models remain excluded. |
| V-08, V-18 | Actual mapped credentials, empty groups/capabilities, NNP, context/range, exact seccomp, private isolation, placement and FD closure pass; native ABI and installed handoff/setup failures pass with cleanup. |
| V-09, V-10, V-14 | Existing hard deadline/delivery/replay regressions pass. Installed review/running revocation, restart and post-approval failure preserve the required consumption and cleanup behavior. |
| V-15, V-19 | Consumption stores the same 32 raw binding bytes as independently hashed canonical constraints/binding, private AUTH_COMMIT and validated collector target_auth. Host audit/recovery regressions pass; remote ACK and external rollback protection remain deferred. |
| V-16, V-17, V-20 | Actual controlling-TTY review displays executable destination constraints before signing; stdio output/exit, descendant teardown, restart/retry and complete host operator/shutdown regressions pass. PTY and hooks remain deferred. |
| NS-01, NS-02 | Genuine rootless sources and all four routes pass with endpoint authentication and connection-time connector attribution. Passed-stream attribution and captured self-connector death pass under the installed production profile; no per-message sender authentication is claimed. |
| NS-03, NS-04, NS-06, NS-07 | Retained acquisitions and independent scoped daemon/signer rules bind destination identity, credentials and bytes. Review/running revocation, anchor disposal and restart cannot retarget the old binding. Broader manager generation claims are excluded. |
| NS-05, NS-11 | Different-UID owner trace control succeeds; released workload injection is denied. Actual confinement, native filter, denial operations, disabled/permissive/unreadable/mismatched state, policy reload and host producer separation pass on the named SELinux deployment. |
| NS-08 | Thin namespace execution passes; local full/export and raw full/signed exclusions pass. ComposeFS/cloned full-preparation and namespace offline redemption remain closed. |
| NS-09, NS-10, NS-12 | Actual placement/isolation, production entry failure, malformed handoffs, whole-job revocation and matching host resource/shutdown regressions pass. Only the recorded single-child-userns topology is qualified. |
| NS-13 | Manager resolvers are not enabled and remain Phase 5. |
| NS-14, NS-15, NS-16 | Frozen vectors, exact private review, canonical consumption/audit/collector equality, fresh installed provisioning, reproducible operator steps and matching release/host artifacts pass within this scope. |

## Independent later gates

Namespace client-full/export/offline redemption, process-PID production targets,
other LSM stacks/ranges, other executable models and additional topologies need
their own integrated qualification. The x86-64 production contract is not an
ARM64 contract. Physical FIDO, PTY, hooks, remote collector/ACK, reusable grants,
reload and manager-backed identity/lifecycle remain separately deferred. No
claim of atomic policy replacement or dependency integrity is made.
