# Namespace-aware execution Phase 5B: Podman adapter

Status: implementation in progress. Podman is the selected first manager.
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

## Qualification still required

The [Phase 5B acceptance matrix](NAMESPACE_PHASE5.md#phase-5b-select-and-qualify-one-optional-adapter)
remains open until installed Podman and candidate daemon runs demonstrate every
applicable case, including real replacement and whole-job teardown. Unit/API
fixtures alone do not enable this adapter for production. Publish exact versions,
platform/profile, commands, artifacts, V/NS dispositions and an operator recipe
when those gates pass.
