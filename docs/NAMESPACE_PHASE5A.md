# Namespace-aware execution Phase 5A qualification

Phase 5A passed for candidate
`77ed1094eb5f3b5167bd6dcb589c16a968164df5` on 2026-11-10. This record implements
the [Phase 5A plan](NAMESPACE_PHASE5.md#phase-5a-identify-and-qualify-the-release-candidate).
The historical [Phase 4 evidence](evidence/namespace-phase4-fedora44-20261110.json)
remains unchanged. The new [sanitized candidate evidence](evidence/namespace-phase5a-20261110.json)
records complete host acceptance, installed qualification, artifact identities,
commands, raw-log locations/hashes and all 36 V/NS requirement dispositions.

## Candidate and artifact identity

The candidate was clean before building. Ordinary release checks cover runtime,
test, configuration, script and packaging inputs with source digest
`22ea3432c7a8744420fe496094aabe75d941e02ebdc29a2c6f93b536f4ae1096`.
The commit/tree identity additionally binds documentation. RPMs have version
`0.1.0-0.20261110.phase5a.git77ed109.fc44`; all five installed runtime binaries
match the ordinary-check manifest after the recorded strip transformations.
`rpm -V sigrun sigrund` passed. The collector is the separately checked build's
validation binary and is not claimed as a remote collector service.

Follow the [installed operator recipe](NAMESPACE_PHASE4_OPERATOR.md) to reproduce
fresh provisioning, independent B startup, registration and real TTY review.
The qualification preserved the previous lab's configuration/state/logs in a
root-only backup before creating a new explicit provisioning set. It did not
migrate or reuse the old epoch or grants.

## Support matrix

| Combination | Result and scope |
| --- | --- |
| Fedora 44 x86-64, kernel `6.19.10-300.fc44.x86_64`, enforcing SELinux, cgroup v2/systemd delegation | Installed `namespace-selinux-v1` thin one-time SSH/stdio: host → registered rootless B, real rootless A → B, A → host and A → self pass |
| Same Fedora deployment, host-only configuration | Approved UID 0 and UID 65534 commands transition to `sigrund_host_workload_t`; reserved-label forgery and producer entry are denied |
| Ubuntu 24.04 x86-64, kernel `6.8.0-142-generic` | Actual client and controlling-TTY approver compatibility pass; production namespace execution is unqualified |
| ARM64 host binaries | Candidate cross-build passes with the recorded Zig compiler wrapper; no ARM64 execution qualification |
| Other LSMs, executable models, source/namespace topologies, process-PID production targets and manager adapters | Remain unqualified/disabled for the production profile |

The Fedora profile retains its locked untrusted accounts, enforcing requester
domain, trusted unconfined administrators, separate A/B owners and single-child
user-namespace topology. Source and destination identities, UID/GID maps,
policy hashes and actual final-child observations belong to the evidence;
subordinate range allocation alone does not establish confinement.

## Verification and requirement dispositions

The ordinary release suite passes all eleven checks. The fresh installed matrix
passes all 33 route, lifecycle, confinement, malformed-handoff and exclusion cases.
The separate source-attribution runner passes two cases; the confined rootless
compatibility control passes host and registered-B execution with the newer
pidfd ioctl disabled. Binding validation passes for 13 executions, including
independent collector mismatch rejection. The host-only producer runner passes
four cases. Ubuntu's actual approver and privileged client compatibility gates
pass, including maximum-depth namespace ancestry and fatal-error rejection.

Complete host acceptance passes all 23 top-level gates, including eleven
privileged Rust gates, seven trust cases and 26 execution cases. The same
ordinary-check manifest and matching binary/test hashes are used throughout.
Its delegated supervisor cgroup is removed; final inspection finds no job
cgroups, clean RPM verification, a stopped daemon and enforcing global/relevant
SELinux domains. The previous provisioning remains preserved separately.

The evidence maps every V/NS requirement to the declared profile's applicable
cases and exclusions. NS-13 is deferred because no adapter is enabled. The
matrix below summarizes that applicability; it does not qualify the excluded
features in the full target specification.

| Requirements | Candidate evidence and limits |
| --- | --- |
| V-01, V-06, V-11; NS-14 | Independent schema/crypto vectors, exact private review and actual SSH approval; namespace full/offline and physical FIDO excluded |
| V-02, V-05, V-12, V-13; NS-01, NS-02 | Host confidentiality/resource regressions, four installed routes, genuine/counterfeit endpoints, passed-stream attribution and captured-connector death |
| V-03, V-04, V-07; NS-03, NS-04, NS-06, NS-07, NS-08 | Retained destination bytes/root/cwd/accounts, scoped independent policy, epoch/revocation/restart; tested local full/export and raw full/signed exclusions |
| V-08, V-18; NS-05, NS-09, NS-10, NS-11 | Actual mapped credentials, final-child placement/isolation/confinement, exact seccomp, owner-injection control/denial and setup failures; named SELinux topology only |
| V-09, V-10, V-14; NS-12 | Review/running revocation, connector/descendant death, failure after consumption, replay/deadline and whole-job cleanup; no grant refunds |
| V-15, V-19; NS-15 | Canonical consumption/audit/collector equality, collector mismatch rejection and host recovery; no remote ACK or external rollback protection |
| V-16, V-17, V-20; NS-16 | Real TTY display, stdio/exit, operator/recovery/shutdown and reproducible matching candidate artifacts; PTY/hooks excluded |
| NS-13 | Optional manager resolvers remain deferred; no adapter is enabled |

The evidence includes the exact supplemental confined-rootless compatibility
driver source and hash so it can be reproduced alongside the committed native
fixture. It publishes selected synthetic outcomes and final-child observations,
not signing keys, state databases, ratchet state or private authorization
payloads. Raw logs remain in the private locations named by the record.

This completion update changes documentation/evidence only relative to the
frozen candidate. Runtime, tests, scripts, configuration and packaging inputs
remain identical. The evidence binds the candidate commit/tree and tracked-file
hashes, and separately hashes the final status documents; these document changes
do not represent another runtime test run. Phase 5B remains deferred.

## Exclusions and operating limits

Namespace client-full/export/offline execution remains closed. Local full-only
and export reject without privileged preparation; raw full/signed submissions
retain scheduled TIMEOUT without consumption or spawn. Manager resolvers (NS-13)
remain deferred, with no manager-generation or manager-exec claim. Each target
is a retained process environment within the daemon epoch.

Policy replacement uses detection and termination: drain before replacement,
restart and register fresh anchors. It is not serialized with every workload
instruction. The sealed ELF does not bind dependencies subsequently loaded from
the destination. PTY, hooks, reload, reusable grants, direct scripts, remote
collector/ACK, additional signing adapters and physical FIDO remain independent
gates. Publishing or merging a release is separate from this qualification.
