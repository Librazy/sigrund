# Namespace-aware execution Phase 5B: Podman adapter

Status: qualified for the declared Podman deployment, 2026-11-11. Runtime
candidate `164db5f` and verification snapshot `6b5fe87` have identical runtime,
privileged-test, namespace-helper, policy and packaging inputs. The latter fixes
only approval-broker handoff in the host trust harness and adds its regressions.
Phase 5A's manager-free qualification remains a separate candidate record.

## Integration contract

The first adapter uses a host-root-controlled local Podman Unix API service,
with host UID/GID 0 and the default Libpod manager namespace. Endpoint, owner
and manager namespace form the explicit resolver scope. Remote/TCP endpoints,
rootless services and other manager namespaces require separate qualification.
Podman 5.8.1 itself reports nondefault Libpod namespaces as unimplemented;
the adapter rejects those selectors explicitly.
The daemon authenticates the kernel socket peer and root-controlled endpoint
path; container-owned labels and names confer no host authority.

The initial deployment uses Podman 5.8.1, cgroup v2 with the systemd manager,
and a single private PID namespace. Kernel observations must place the manager
init at PID 1 in `/machine.slice/libpod-FULL_ID.scope/container`; an unrelated
or stale manager-returned PID cannot establish that association. The endpoint
directory is pinned without symlinks, the socket is root:root with no access
for other users, and each connection authenticates host UID/GID 0. The root
group and accounts able to use the API are trusted host administrators.

A host administrator registers a scoped Podman container name together with a
fresh dedicated anchor. Requesters continue selecting the resulting root-owned
`registered:ID`; no manager discovery endpoint or guessed CLI alias is added.
The versioned management request carries the manager selector. Required evidence
identifies the exact container ID, running init PID/start identity, start time,
configuration digest and authenticated API endpoint. All selected environment
resources still pass through G-01 capture and existing policy/approval/execution.
The dedicated anchor must match the manager init's namespaces and root; an
arbitrary PID returned by metadata cannot bypass acquisition or authorize entry.

Manager evidence must be included in a new versioned process context/review,
its canonical digest and private display. Historical manager-free schema bytes
remain unchanged. Independent vectors must cover the new binding before it is
exposed. Daemon and signer rules continue independently authorizing registration
scope, credentials and constraints; resolver access supplies no extra authority.

Use a provisional name lookup only as a full-ID filter hint, then acknowledge
an object-ID-scoped lifecycle stream before acquiring the authoritative manager
snapshot and process pins. Require the fresh lookup to agree with that ID. Equal
names in another engine/namespace are not lifecycle authority. Verify again
before publishing, and retain the stream and init pidfd for the binding lifetime.
Monitor exact-name generation, required configuration and running state with
bounded authenticated checks. A relevant event, stream failure, malformed or
excessive response, failed revalidation, endpoint replacement or uncertain
manager generation permanently invalidates the lease. Never reconnect a retained
binding or refresh it in place. Recovery requires new registration/acquisition
and approval, with no refund of durable consumption.

Observation/cancellation bounds and API resource limits must be fixed before
qualification. They describe detection and termination, not atomic serialization
of manager operations with workload instructions. Stop/delete, same-name
replacement with the old anchor alive, config changes and resolver restart/loss
must invalidate pending authorization and cancel running supervised descendants.
The adapter uses native retained-resource execution; it makes no claim of exact
Podman exec-policy equivalence. The operator must explicitly configure the
qualified executable/confinement model and manager teardown prerequisites.

The implementation uses a 200 ms refresh interval, a two-second total query
deadline and a three-second maximum evidence age. Idle stream reads yield every
100 ms. Finite request/header/body I/O retries idle intervals only within the
total query deadline, preserving partial framing without extending that deadline.
The ten-second management acquisition deadline is checked again after resolver
revalidation and before publication; expiry or shutdown cannot publish a target.
Loss is permanent for that retained owner, including after name restoration
or service recovery. The ordinary job supervisor observes the invalidated owner
and performs cleanup; integrated tests must measure the complete teardown bound.
HTTP headers are limited to 16 KiB, a finite inspect response or chunk to 1 MiB,
an event line to 64 KiB and the stream to 256 events per second. Malformed,
duplicate or ambiguous framing fails closed. A manager dependency reserves
twenty target-FD slots and one helper slot before opening resources, in addition
to the normal capture charge; cleanup joins the monitor and closes resources
before refunding quotas. Existing hard/per-UID helper ceilings remain effective.

The native `register-podman` operation takes all of `--podman-endpoint`,
`--podman-owner-uid 0`, `--podman-namespace default` and `--podman-container`,
alongside the existing registration ID, anchor PID/owner UID and security profile.
Its root-only wire operation is `register_podman_v1`, containing the strict
`sigrund.podman-selector.v1` record. Runtime observations use
`sigrund.podman-evidence.v1`; `sigrund.podman-context.v1` and
`sigrund.podman-review.v1` bind/display that evidence and retain the ordinary
acquisition record unchanged. The manager configuration digest covers Config,
HostConfig, Mounts, ProcessLabel, MountLabel, AppArmorProfile, Namespace, Image,
Rootfs and Dependencies using the exact-integer canonical JSON contract. An
unrepresentable or unavailable required record rejects acquisition.

Load the separate `sigrund_podman` SELinux module explicitly for this integration.
It permits only the producer to connect to the local manager API; it grants no
requester/workload API access. Manager-free provisioning does not load it.

## Installed candidate qualification

The [sanitized evidence](evidence/namespace-phase5b-20261111.json) closes the
[Phase 5B acceptance matrix](NAMESPACE_PHASE5.md#phase-5b-select-and-qualify-one-optional-adapter)
for Fedora 44 x86-64, kernel `6.19.10-300.fc44.x86_64`, enforcing SELinux,
Podman 5.8.1 and the explicit [operator deployment](NAMESPACE_PHASE5B_OPERATOR.md).
The destination uses the initial user namespace, a private PID namespace,
systemd cgroup v2 and a read-only administrator-owned rootfs with a trusted init.
Host and real rootless A sources execute as destination UID/GID 12001 with empty
groups, NNP, the exact seccomp program and the displayed workload context.

RPMs `0.1.0-0.20261111.phase5b3.git164db5f.fc44` contain the frozen runtime.
All five installed binaries match the checked, RPM-transformed binaries;
`rpm -V sigrun sigrund` passes. Both checked snapshots pass all eleven ordinary
checks. The verification snapshot changes only `scripts/verify-trust.py` and
its Python tests; the evidence records the exact delta and unchanged binary
hashes. Installed namespace acceptance uses the frozen packaged helpers.

| Installed gate | Result |
| --- | --- |
| Real routes and lifecycle | 26 cases pass: host/A → Podman B, replacement, stop/delete, configuration, pause and API loss during review/running execution, stale rejection and fresh recovery |
| Resolver evidence | 37 cases pass: mismatched PID/ID/name/namespace, dishonest owner labels, malformed/missing/duplicate records, event loss, stalls and version changes |
| Ownership and quotas | Nine cases pass: cancellation, retained-registration survival, repeated quota rejection and release after actual disposal |
| Scope | Six cases pass: equal names in two real engines, wrong-anchor rejection, correct alternate-endpoint execution, native namespace exclusion and explicit namespace/owner selector rejection |
| Native dependency | Generation loss with a live old init, no revival, fresh acquisition, cancellation/cleanup accounting and endpoint-directory replacement pass |
| Binding equality | 67 managed, manager-free and host-only executions pass canonical consumption/audit/collector equality and altered-binding rejection |

Fourteen running lifecycle/fault/cancellation cases independently observe at
least two supervised descendants each and verify their exit and job removal.
The largest measured teardown is 2.68 seconds, below the six-second gate.
Pending-review cases attempt the old approval and retain scheduled TIMEOUT with
zero consumption and no readiness/spawn. Restoring state never revives their
registrations. These measurements describe this deployment's detection and
termination behavior; they do not serialize manager operations with execution.

The live source sample authenticates the original connector and observes UID
mapping `0 → 1200` and `1..65535 → 589824..655358`; B has the initial identity
map. The matching manager-free regression passes all 33 cases and all four routes,
two source-attribution cases, two confined rootless compatibility controls and
four host-only producer cases. Complete host acceptance passes 23 gates,
including eleven privileged Rust gates, seven trust cases and 26 execution cases.

The initial host acceptance attempt timed out waiting for broker admission.
Inspection identified an unsynchronized trust-harness broker handoff. The bounded
pre-request EOF retry and deterministic real-socket tests fix the harness; the
complete suite passes with unchanged runtime artifacts. An initial
Ubuntu TTY test returned TIMEOUT instead of its expected dry-run result; the same
candidate passed the separate isolated client/approver rerun. Both attempts are
retained. Ubuntu 6.8 results concern host authentication only. ARM64 is cross-build
evidence only. Neither qualifies production namespace execution on that platform.

The evidence records all 36 V/NS dispositions, exact commands, helper sources,
package/policy/binary hashes, actual mappings, raw-log locations/hashes and final
restoration. Historical Phase 4/5A evidence remains unchanged. Final inspection
finds no jobs or disposable services/containers, unmounted fixture binds, restored
configuration, enforcing relevant domains and clean RPM verification. Prior
provisioning sets remain in separate private backups.

## Operating limits

The default per-UID helper ceiling is two. A managed capture consumes both slots
for its owner, permitting one concurrent root-owned managed registration in this
recipe. Quotas remain charged until the actual monitor/descriptors/helper are
disposed; a revoke acknowledgment alone does not establish available capacity.

Rootless APIs/nonroot owners and nondefault manager namespaces reject explicitly.
Other Podman versions, remote APIs, other managers, LSMs, executable models and
namespace topologies require their own qualification. Untrusted rootful
container-root sources and unrestricted administrative Podman exec are outside
this deployment. Native entry supplies no manager exec-policy equivalence.
Namespace full/export/offline, process-PID production targets, PTY, hooks, remote
ACK, reload, reusable grants, scripts and physical FIDO retain independent gates.

The final qualification commit updates documentation/evidence relative to the
verified harness snapshot. It does not change runtime artifacts or imply another
runtime run. Packaged operator text belongs to the frozen revision; the final
source guide updates qualification status and operating limits.
