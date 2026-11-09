# Namespace-aware execution Phase 3

## Implementation status

Phase 3 is complete for the declared experimental profile and topology. The
constraint contract, exact-warrant
verification record, acquisition-time namespace FD handoff, staged native
launcher and final-child exec checkpoint are integrated. Explicit registered,
process and authenticated self thin requests can execute under the opt-in
experimental profile. All four routes pass integrated qualification using the
actual CLI: host to B, A to host, A to self and A to B.

The 39-case integrated namespace qualification and 25-case Phase 2 regression
pass on enforcing Fedora 44 x86-64, kernel 6.19.10-300.fc44.x86_64. All eleven
ordinary checks pass against the same source and binaries. The
[sanitized qualification record](evidence/namespace-phase3-fedora44-20261109.json)
records exact hashes, commands, platform and individual results. Complete host
acceptance passes all 23 gates, including nine privileged Rust gates, seven
trust cases and 26 execution-failure cases. The clean full run includes the
operator workflow; its PTY confirmation harness now observes the input-flush
notification before answering. Private raw evidence is retained under
the private artifact collection recorded in the qualification JSON.

The experimental profile uses schema
`sigrund.constraints.namespace-experimental.v1` and profile ID
`namespace-experimental-v1`. Its canonical fixture is in
`crates/sigrund-core/tests/fixtures/v3-namespace/experimental-constraints.json`.
The contract requires digest-memfd, an exec checkpoint, private mount/cgroup
isolation, securebits 15, NNP, finite resource limits and empty capabilities.
Process review and daemon policy require a nonzero destination UID and empty
groups. SELinux fields explicitly declare no requested transition, with empty
context, enforcing false and policy-change handling unmanaged. Ambient kernel
LSM policy still applies. Seccomp is explicitly none. These declarations bind
the experimental executor's obligations. Production confinement qualification
belongs to Phase 4.

The existing phase0 constraint schema continues to require its complete
enforcing SELinux context and reject-on-policy-change behavior. Its frozen
vectors remain independently tested.

Final worker verification now produces a private record bound to the exact
canonical warrant hash, instance and registration revision. Authorization checks
that record against the retained owner and current document, with destination
filesystem checks remaining on the request worker.

## Execution and ownership

Capture transfers all eight namespace FDs before publishing READY. The daemon
checks identity and namespace type and reserves capacity before acquisition.
The verified execution plan retains the owner's charged namespace FDs and the original
owner through authorization and cleanup. Destination I/O stays on bounded workers.
Fresh-exec capture waits for an explicit acquisition grant: spawn duplicates
close before target-pin acquisition starts. Each stage reserves before acquiring
its descriptors. Queued transfers, daemon-owned descriptors, helper-only pins
and inherited fork copies remain charged for their actual ownership intervals.

The launcher is created directly in the host job cgroup and fresh-execs the
running daemon image before entering any destination authority. Only the
fixed descriptor allowlist and a bounded sealed per-job configuration cross
exec; daemon keys, other requests and the daemon environment do not. The
coordinator attaches an EXITKILL tracer before granting the namespace transition.
Credential transitions require initial host UID/GID maps and
`fs.suid_dumpable` set to 0 or 2; value 1 is rejected before private approval.
The launcher disables dumping before entry and after its credential changes.
It clears groups,
enters the approved namespaces, establishes the pinned root/cwd, and then creates
private mount/cgroup views. The experimental topology requires the captured root
to be a mount point. A plain chroot directory is rejected before consumption.
The fixture binds its root before chroot, following the validated Phase 0 recipe.

Null stdin uses a retained, verified host `/dev/null` descriptor, including for
namespace jobs. Output descriptors cannot supply input. Experimental profiles
must fit all daemon job ceilings at configuration load. A requested cwd at or
below `/run` is rejected before review; after private mounts, the launcher also
resolves the approved cwd and compares its inode and mount identity with the
inherited cwd before final-child creation. This prevents a covered cwd from
retaining access beneath the private runtime mount.

Anchor/helper pidfds remain independently pollable during capture IPC. No
blocked directory exchange suppresses death detection. Destination preparation
charges its eleven-descriptor parent spawn peak; launcher reservations cover
eight parent descriptors and eighteen bootstrap duplicates without raising the
frozen ceilings. Connector backlog retries use portable `ppoll`, a monotonic
connection deadline and a real backoff; parent death kills the connector even
before the public stream is transferred. Its capture handshake preserves the
required `read` then `unshare` sequence.

The initial launcher registration barrier ends before destination setup. Only
after READY does the coordinator reserve a second short barrier and permit final
child creation. The launcher transfers a kernel-created pidfd and exits. The
host subreaper observes that exit and adopts the gated child before installing
its tracer and releasing setup. The tested kernel rejects CLONE_PARENT for this
PID/time entry sequence, so explicit adoption establishes the final parentage.

At exec stop, a bounded worker verifies the sealed image, host-mapped credentials,
capabilities and NNP, joined/private namespaces, root/cwd in the private tree,
private run mount, restrictive cgroup mounts, actual host job placement, absence
of setup descriptors and the declared seccomp state. Ambient LSM observations
are recorded separately. Release rechecks liveness, cancellation and deadlines.
Every post-commit failure retains consumption. Complete APPROVED delivery
precedes the launcher. Revocation and disconnect tear down the whole job cgroup.

## Operator workflow

Start with fresh v3 provisioning and the qualified dedicated-anchor deployment
in the [Phase 2 guide](NAMESPACE_PHASE2.md). Deliberately append
[`namespace-experimental-profiles.toml.example`](../config/namespace-experimental-profiles.toml.example)
to daemon policy and the matching
[`namespace-experimental-signers.toml.example`](../config/namespace-experimental-signers.toml.example)
rules to the selected signer. Adjust requester IDs and scopes before starting
the daemon. The historical `selinux-minimal` example retains private review only.

The selected root must be a mount point, with `/run` available for a private
tmpfs and every configured executable root present. The execution fixture
demonstrates binding the root before chroot. An ordinary chroot directory or
mixed namespace ownership is rejected. This phase does not modify an existing
container to satisfy these requirements.

Select an execution cwd outside `/run` and its descendants. Keep
`fs.suid_dumpable` at 0 or 2 throughout namespace preparation and execution;
concurrent host security-policy replacement remains outside this fixed-policy
qualification.

Register the already-connected dedicated anchor as host root:

```sh
sigrundctl target register container-b --socket /run/sigrund.sock \
  --pid 12345 --owner-uid 1000 --security-profile namespace-experimental-v1
```

An ordinary requester selects the destination explicitly:

```sh
sigrun --socket /run/sigrund.sock --target registered:container-b \
  --account phase2_service --security-profile namespace-experimental-v1 \
  --cwd /srv/service -- /usr/bin/tool
sigrun --socket /run/sigrund.sock --target self \
  --target-uid 12001 --target-gid 12001 \
  --security-profile namespace-experimental-v1 --cwd / -- /usr/bin/tool
```

For self, expose the public socket, `.context` and `.anchor` paths together.
The CLI creates a dedicated single-threaded connector before starting relays,
passes its public stream to the parent and keeps the original connector pidfd.
The daemon matches the public connector to the anchor rendezvous and holds it
at the successful private-filesystem syscall exit. Passing or inheriting that
stream preserves its connector's identity, even if a different UID writes it.
The approval display includes those authenticated socket observations separately
from acquired live process attributes, target mappings and resolved credentials.
Connector death invalidates the self owner and tears down its whole job.

Run the root-TTY approver as documented in Phase 2. It displays the complete
experimental constraints and explicitly states that no LSM transition is
requested. The workload starts only after complete public APPROVED delivery and
the final-child exec checkpoint. Named-account edits after preparation cannot
redirect approved numeric credentials. Replacement/revocation invalidates a
pending old review; a label never follows its replacement automatically.

Namespace requests are thin-only. Full-only, namespace CSR export and signed
namespace redemption remain unavailable. Host full/offline workflows continue
to use their host profile and explicit trusted binding bundle.

## Platform scope and qualification

The exercised execution platform is Fedora 44 x86-64, kernel
6.19.10-300.fc44.x86_64, enforcing SELinux with an unconfined administrative
service and cgroup v2 memory/pids delegation. Declared target topologies are the
initial user namespace and one child user namespace, with every joined non-user
namespace owned by the selected user namespace. Rootless B maps service
UID/GID 12001 to host 536288. The tested A source uses the initial user namespace
and private namespaces/root. Cross-owner B and same-owner self rules are distinct.

A client may authenticate a host daemon outside its PID namespace (kernel peer
PID zero), while server admission still requires a positive original connector
PID. The client continues requiring peer UID zero in its own user namespace.
Consequently a source user namespace in which host root is unmapped cannot use
the CLI; overflow UID is never accepted as root authentication. Such source
topologies, nested/mixed ownership, idmapped mounts, other architectures and
manager-specific deployments have no qualification claim here. Ambient LSM
policy may also deny a declared operation. Phase 4 must resolve deployment
authority and confinement for any broader support claim.

The whole workspace also passes an ARM64 compile check, including the connector's
portable wait syscall. Namespace runtime qualification remains limited to the
x86-64 platform above.

Reproduce ordinary checks as the workspace user, then run qualification as root
on a disposable native systemd host with GCC/static glibc, util-linux, subordinate
IDs for the owner, OpenSSH tools, strace, ACL/libcap utilities, fsverity-utils,
e2fsprogs and Python GObject.

When transferring prebuilt Rust test executables, preserve their embedded
`CARGO_BIN_EXE` paths on the guest as well as the binary paths in `checks.json`.
Changing the manifest alone does not rewrite those build-time paths.

```sh
python3 scripts/check.py --artifacts /var/tmp/sigrund-phase3-checks
# Matching source, production binaries and test executables on the guest:
python3 scripts/verify-namespace-phase3.py --owner lab \
  --binaries /absolute/sigrund/target/debug --artifacts /var/lib/sigrund-phase3-new
python3 scripts/verify-namespace-phase2.py --owner lab \
  --binaries /absolute/sigrund/target/debug --artifacts /var/lib/sigrund-phase2-new
python3 scripts/verify-acceptance.py --requester lab \
  --binaries /absolute/sigrund/target/debug \
  --checks /var/tmp/sigrund-phase3-checks/checks.json \
  --artifacts /var/lib/sigrund-phase3-host-new
```

The namespace runner uses a bounded delegated service and root-private evidence.
It checks actual CLI routes and TTY signing, passed sockets, connector death,
null/finite stdin with readable output rights, covered cwd and unsafe dumpability
denial, fresh-exec memory isolation,
replacement/account races, private deadlines, setup/handoff failures, incomplete
APPROVED delivery, late durable consumption and blocked cleanup. It verifies
database/audit/collector binding equality for successful and post-commit-failed
jobs. Cleanup failure makes qualification fail. The separate Phase 2 and host
suites retain their independent applicability; historical prototype evidence
does not substitute for these production runs.

## Completed qualification

The checked source SHA-256 is
`626f08c10d2cf3bf1e566b895c94a34d71e37334c3e121776533cc3a5f412fbf`.
All three privileged suites and the eleven ordinary checks use its matching
production binaries. The host supervisor verified cgroup removal; the namespace
supervisors independently verified whole-service cleanup. The disposable VM was
removed after private artifact preservation.

The [roadmap](NAMESPACE_AWARE_EXECUTION.md#phase-3-acceptance-applicability)
records NS-01–NS-16 and V-01–V-20 applicability. No privileged case was skipped
within this declared scope. The unsupported deployments and Phase 4/5 features
above retain their separate qualification gates.
