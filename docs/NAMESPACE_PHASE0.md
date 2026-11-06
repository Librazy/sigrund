# Namespace-aware execution Phase 0

Phase 0 supplies executable experiments and bounded draft contracts for G-01–G-05.
It does not enable namespace execution in the production v2 binaries. The
[roadmap](NAMESPACE_AWARE_EXECUTION.md) continues to own delivery order and the
[security specification](<../sigrun sigrund Security Architecture and Implementation Specification.md>)
owns the v3 requirements. Application versions, private record versions and Linux
ABIs are separate.

The [historical Fedora 44 run](evidence/namespace-phase0-fedora44-x86_64.json)
recorded 54 passing experiments, but review found that it did not prove private
mount-tree use, namespaced SELinux policy guarding or interrupted domain-permissive
cleanup. It is superseded as evidence for those guarantees. Its original hashes
and results remain available; the current checker rejects that snapshot against
the changed sources and expanded 62-case inventory. The complete historical
artifacts are in `target/namespace-phase0-evidence/`.

The [review-fix validation record](evidence/namespace-phase0-review-fixes.json)
records all 62 native cases passing on enforcing Fedora 44, independent validation
of all 40 acquisition records, and successful recovery after killing a live
domain-permissive service with SIGKILL. The native run also exposed and verified
the mapped-launcher-ID correction described below. Those generated artifacts
are in `target/namespace-phase0-review-evidence/`.

The [stop-timeout recovery validation](evidence/namespace-phase0-stop-timeout.json)
records a subsequent correction to both outer cleanup paths. A real stop-client
timeout and direct SIGKILL both recover global/domain enforcement, remove the
test module and ownership markers, and permit repeated cleanup. All 62 native
cases and 40 acquisition records were rerun and independently checked against
the updated runner. Those artifacts are in
`target/namespace-phase0-stop-timeout-evidence/`.

The [PR review validation](evidence/namespace-phase0-pr14-review.json) records
explicit opt-in native Rust tests, a real SELinux context mismatch rejected by
the shared exec checkpoint, and a guard-bypass mutation detected by that negative
case. All 62 native cases and 40 acquisition records were rerun against these
sources. The shared-FS mutator cleanup was also checked against the original
helper in both rootful and rootless modes; namespace-init teardown already reaps
it, and each probe now checks for leftover children before exiting. Current
generated evidence is in `target/namespace-phase0-pr14-evidence/`.
The full Phase 0 exit gate
remains blocked on the strict concurrent-policy-
replacement requirement described under G-04 below.

## Artifacts and reproduction

`crates/sigrund-phase0` is a non-publishable workspace member. Production crates
do not depend on it. It contains strict record validators, selection/management
grammar fixtures, mapped-ID composition, scoped policy examples, complete approval
rendering and independent signing vectors. Its offline checker neither issues
bindings nor establishes live authority. Linux experiments are in
`scripts/namespace-phase0`; they are never linked into the daemon.

Run the ordinary checks as the workspace user:

```sh
cargo test -p sigrund-phase0 --locked
python3 scripts/namespace-phase0/verify-vectors.py
python3 -m unittest discover -s scripts/tests -p test_namespace_phase0.py -v
```

The two environment-dependent tests in `tests/probe.rs` are explicitly ignored
by ordinary workspace tests. On x86-64 Linux, run them separately with:

```sh
cargo test -p sigrund-phase0 --test probe --locked -- --ignored
```

They require `cc`, coreutils `timeout` and the relevant kernel interfaces
(including `SO_PEERPIDFD`). The mount test additionally needs util-linux
`unshare --map-auto --map-root-user`, configured subordinate UID/GID maps and
permission to create user/mount namespaces. An explicitly requested native test
fails if these prerequisites are unavailable; ordinary tests report it ignored.

The privileged runner needs a **disposable x86-64 systemd host with enforcing
SELinux**, a C compiler, Python, libselinux, the SELinux development Makefile,
`semodule`, `semanage`, `chcon`, `restorecon`, `setenforce` and journald audit
records. On Fedora these come from gcc, make, policycoreutils-devel,
policycoreutils-python-utils, libselinux and selinux-policy-devel. Run:

```sh
python3 scripts/verify-namespace-phase0.py \
  --disposable-host --artifacts /var/tmp/sigrund-phase0-evidence

# After the main runner has finished, exercise sudden service termination:
python3 scripts/verify-namespace-phase0-recovery.py \
  --disposable-host --artifacts /var/tmp/sigrund-phase0-recovery

# Exercise a real systemctl stop timeout and forced service cleanup:
python3 scripts/verify-namespace-phase0-recovery.py \
  --disposable-host --stop-timeout-regression \
  --artifacts /var/tmp/sigrund-phase0-stop-timeout
```

Run this command as root in the guest. The artifact directory must be new and
short enough for Unix socket paths (108 bytes including the terminator). The
runner uses a dedicated delegated service, finite memory/PID/swap ceilings,
per-case kill/cleanup and a whole-service deadline. A host lock prevents
overlapping policy experiments. It refuses to replace an existing test module.
It briefly tests global and domain permissive states as **negative cases**, then
restores enforcing mode and removes its module. A recovery intent marker precedes
the domain-permissive transaction. Both ordinary and outer timeout cleanup remove
that setting before unloading the test module, retain markers if cleanup fails,
and allow repeated cleanup after an interrupted transaction. Both outer cleanup
paths share service shutdown: a failed or timed-out stop triggers SIGKILL for all
service processes. Cleanup waits for an inactive/failed service and an empty or
removed cgroup before restoring policy, so surviving policy transactions cannot
race restoration. If termination cannot be confirmed, it reports failure and
retains the ownership markers for retry. Positive workload cases require
enforcement, NNP, tracing and actual denied operations.

The separate recovery regression installs the test policy, waits for a dedicated
service to commit the domain-permissive transaction and disable global enforcement,
then kills all processes in that service with SIGKILL. With
`--stop-timeout-regression`, a slow `ExecStop` forces the stop client to time out;
the shared cleanup must then kill the service and recover policy. Both modes
invoke the same host-side recovery as the main runner,
checks global enforcement, absence of the permissive setting and test module,
removal of ownership markers, and successful repeated cleanup. Its bounded service
and host lock keep it separate from the main experiment run; `recovery.json`
records its source hashes and observed results.

Copy the artifacts to the workspace and independently validate them:

```sh
cargo run -p sigrund-phase0 --bin sigrund-phase0-contract --locked -- \
  evidence /absolute/path/to/sigrund-phase0-evidence
```

The manifest records the kernel, architecture, OS, compiler, binary/source hashes,
LSM stack, supervisor/workload contexts, delegation, commands, per-case outcomes,
raw outputs and canonical acquisition digests. The checker requires the complete
62-case inventory, the complete source-hash inventory, matching executable and
current-source hashes, and all 40 required canonical acquisition records in the
same daemon epoch. Omitting an acquisition digest cannot skip validation.
Missing, duplicate, changed-source and failed cases cannot become a passing run.
`passed` qualifies these experiments only.

## G-01: connector capture and private filesystem state

The initial self contract is **connector attribution at an explicit capture
handshake**, not writer attribution or the connector's earlier connection-time
namespace snapshot. An inherited/passed stream retains its connector identity.
The client keeps a dedicated single-threaded anchor alive and uses another
process for request/stdio relaying. Operators must permit the host tracer to
attach. Arbitrary container init processes are not accepted as anchors.

1. Obtain `SO_PEERCRED`, bounded `SO_PEERGROUPS`, optional `SO_PEERSEC` and
   `SO_PEERPIDFD` from the accepted stream. Do not replace the authenticated pidfd
   with `pidfd_open()` on a later caller-supplied PID. A pidfd is checked for
   liveness around PID-based ptrace/proc lookup; no binding is released on failure.
2. After the setup-complete handshake, seize/interrupt the connector with
   `PTRACE_O_EXITKILL`, syscall stops and exec/clone/fork event tracing. Require one
   thread and no installed seccomp filter. All four live UID/GID values and live
   supplementary groups must match the connection credential snapshot. Observe
   socket and process security labels separately.
3. Permit only completion of the handshake read, then intercept an `unshare`
   entry. Check the x86-64 syscall ABI and force its arguments to
   `CLONE_FS | CLONE_FILES`. Require the actual kernel syscall exit to succeed.
   Any unexpected syscall/event or failure rejects the acquisition. Seccomp is
   rejected because TRACE/USER_NOTIF could otherwise fabricate a successful exit.
4. Hold the anchor at that syscall-exit stop for the entire instance lifetime.
   Pin proc, root, cwd, namespace and owning-userns FDs; capture initialized maps
   and setgroups state. Check liveness and captured observations again before
   spawn and at the final-child checkpoint. Never resume the anchor into user
   instructions; disposal kills and reaps it.

The capture point is the successful kernel filesystem/FD-table unshare. The
kernel copies root/cwd under its filesystem-state lock. Source namespace
membership and credentials cannot change while this single thread stays at the
controlled stops. After unshare, external `CLONE_FS` peers cannot alter its private
root/cwd, and `CLONE_FILES` peers cannot replace its descriptors. This argument
does not rely on cooperative client instructions or repeated procfs sampling.
The adversarial fixture proves the old FS state was shared with `kcmp`, then
changes and restores that sibling's root while the captured root remains fixed.
Shared memory does not grant another task a syscall on the stopped anchor's
behalf. Host administrators/kernel compromise remain outside the threat model.

Maps must already be initialized. UID/GID maps cannot be rewritten; a later
setgroups allow-to-deny change is irreversible and invalidates the observation.
These references freeze identity, not filesystem contents, mount topology,
libraries, LSM policy or manager configuration. Manager-free bindings identify
this retained process environment, not a container generation.

Registrations and explicit daemon-PID selectors initially require the same
dedicated-anchor acquisition. A registration name or an administrator-provided
PID alone cannot bypass it. Anchor exit, tracer loss, changed observations,
revocation or daemon restart invalidate the instance. Retained FDs are not proof
of liveness, and names/PIDs are never reacquired to repair an instance.

## G-02/G-03: entry and ownership

The tested namespace topology is either the initial userns or one child userns
whose parent is the initial userns. Every joined non-user namespace must be owned
by the selected userns. Acquisition validates those relationships using nsfs
ioctls. Nested, mixed-owner, ancestor-entry and unknown/idmapped mount combinations
are rejected/unqualified; the fixture constructs its own ordinary bind roots.
Pure contract tests additionally compose nested maps and reject holes/overflow.

The experiment uses resident trusted C helpers and static syscall-only workloads.
Production adoption must port the transitions into the existing preallocated,
syscall-only child path; prototype libc wrappers are not a production child ABI.

The entry recipe is:

1. The host supervisor creates a trusted launcher with
   `CLONE_PIDFD | CLONE_INTO_CGROUP` in an already limited job cgroup. Launcher and
   final child both count toward its PID ceiling.
2. Detach launcher FS/FD state and clear supplementary groups while still in the
   initial userns. Enter user, cgroup, IPC, mount, network, UTS, time and PID
   namespaces in that order, skipping only verified already-shared identities.
   Preserve the host coordinator's namespace set.
3. Select mapped UID/GID 0 for the trusted launcher before filesystem setup.
   Entering a userns preserves the old kernel IDs; host root is unmapped in the
   rootless profile and cannot create the private marker (`EOVERFLOW`). These
   temporary launcher IDs do not change the final child's approved identity.
   Establish the pinned root and cwd **before** cloning the private mount/cgroup
   namespaces, then make propagation recursively private. The pinned root FD
   belongs to the original mount tree; using it for chroot after cloning would
   bypass the private copy. Mount a private tmpfs on `/run`, then create the final
   child. PID/time entry applies to this new child, not to the launcher itself.
4. Return the final host-visible PID and a kernel-created pidfd over bounded
   private IPC. Hold the final child at a gate until its host tracer is installed.
   Close unrelated FDs; keep executable FD 3 and the close-on-exec error pipe at
   FD 4. Establish securebits 15, empty capability sets/bounding set, exact numeric
   IDs, empty groups and NNP. Under `setgroups=deny`, groups were cleared before
   entry; no failed group operation is ignored.
5. At the exec stop, verify the **final** child's root, namespace membership,
   host-mapped UID/GID values, groups, capabilities, NNP and actual cgroup
   membership before releasing instructions. Require different private
   mount/cgroup namespace identities, verify the private `/run` mount's marker
   and confirm that the anchor still sees its original `/run` directory.

The candidate rootless map is `0 -> 1000` and `1..65535 -> 100000..165534` for both
UIDs and GIDs, with setgroups denied. Destination UID/GID 1001 therefore become
host 101000. Rootful/host destination 1001 remains host 1001. Normal rootful and
host source anchors use host UID/GID 1000; separate rootful privileged fixtures
exercise credential mutation and shared-FS attacks. Rootless UID 0 never means
host root. Execution of destination root or nonempty capability/group profiles
needs separate qualification.

Setup errors have one native 8-byte `{u32 stage, i32 errno}` frame over private
IPC; EOF/truncation is not success. Stages 1–7 cover placement, user entry,
remaining namespaces, root, final-child gate, credentials and exec. Stage 8 tests
exec-stop rejection, and stage 9 tests anchor loss before release. Fault cases
must produce no workload output. Host pidfds, parentage, ptrace waits and a
subreaper cover final-child ownership. Separate tests kill the tracer/launcher,
exhaust the PID limit, adopt/reap descendants and retain ownership until cleanup.
The service cgroup provides an independent ceiling if the harness dies.
Each probe also requires `waitpid(-1, __WALL | WNOHANG)` to report `ECHILD`
before returning, while the outer service is still alive. In the shared-FS
fixture, the anchor is PID 1 of its new PID namespace; killing it makes the
kernel kill and reap the mutator before the wrapper finishes waiting.

The test filesystem exposes only fixture endpoints and no management sockets or
delegated cgroup controls. Production containment still needs the host-service
access exclusions in §1.1; namespace membership alone does not establish them.

## G-04: SELinux and seccomp

The experiment supplies a separate test supervisor/workload policy. It allows the
explicit transition to `sigrund_phase0_t`, including `process2:nnp_transition`
and tracing, while denying reads of `sigrund_phase0_secret_t`. The SELinux probes
run their host supervisor in the separately declared
`sigrund_phase0_supervisor_t` administrative domain and verify that actual label.
The experiment grants that domain broad administrative access; this is not
production daemon packaging policy. The workload domain is enforcing.

Both retained-file and sealed-memfd models preserve NNP and ptrace and verify the
complete actual context, including `s0:c1,c2`, at the exec stop. Memfd support here
uses an explicitly assigned executable label on the sealed copy. It does **not**
reproduce original path/source-file label semantics. Profiles requiring those
semantics cannot substitute this model. Each model also runs through the rootful
and rootless namespace launcher. Workload read denials must have matching
enforcing AVCs for every workload PID; an `EACCES` alone is insufficient.

Read the SELinux status page with its seqlock. The relevant token is enforcement,
sequence and **policyload**, not `/sys/fs/selinux/policyvers` (the policy ABI).
Query kernel access-decision flags to reject per-domain permissive mode as well
as global permissive mode. Missing/unreadable status, context mismatch or token
change rejects the profile. Host and namespaced execution use the same guard:
sample before preparation, check enforcement and the domain decision under a
stable token, then recheck immediately before releasing the exec stop. The reload
tests change policy while the workload is held at exec stop and require rejection
without target instructions. Namespaced tests cover rootful/rootless entry with
both direct and memfd executables; separate namespaced negative cases reject
global/domain permissiveness before launcher creation. The context-mismatch
fixture sets the child's actual exec label to a different category set while
preserving the authorized context. The same checkpoint used for ordinary host
and namespaced execution must return `context_mismatch`; the observation records
both contexts, SIGKILL/reaping and no workload output. Test mode does not select
the rejection branch. The current validation
record includes passing native results for all these cases; the original 54-case
record remains historical.

Production must retain this policy dependency from preparation through cleanup,
revalidate immediately before release and invalidate/cancel on a detected change.
The status page is not a policy lock and there is no claimed atomic
policy-load/ptrace-detach transaction. Deployments requiring absolutely no
instruction under a concurrently replaced policy need administrator-controlled
policy serialization for the complete job lifetime; that deployment mechanism is
blocked until implemented and tested. The passing experiment establishes
transition, observation and rejection feasibility, not arbitrary concurrent
reload safety.

Seccomp is explicit configuration: x86-64 native ABI, deny selected syscall
numbers with a fixed errno, allow other native syscalls, and kill other ABIs/x32.
The fixture denies `getppid` with EACCES and exercises the actual syscall. It does
not extract another task's filters or claim manager-policy equivalence. Existing
source filters, arbitrary BPF, AppArmor/LSM stacking and unreadable enforcement
remain blocked for the initial profile.

## G-05: bounded records and administration

`contracts.rs` and its independent ASCII/JCS fixtures freeze these private record
shapes. A change requires a record-version/vector update before runtime adoption:

| Record | Bound meaning |
| --- | --- |
| Acquisition | Epoch/instance, boot/PID/start identity, capture mechanism, connection/current process observations, eight namespace identities/owners, pinned root/cwd, mapping ancestry and lifecycle dependencies |
| Constraints | Profile ID, entered/private namespaces, capabilities/securebits/NNP, cgroup ceilings, complete SELinux requirement, explicit seccomp, executable model and exec-stop obligations |
| Registration | Administrator ID/revision, daemon-scope anchor PID, administrator-declared host owner UID and immutable profile digest |
| Scoped rule | Host requester UID ceiling, one host/self/registered scope, destination-relative UID/GID/groups, exact profile digest and explicit cross-owner permission |
| Binding bundle | Host authority, exact signed target-binding shape, complete immutable constraints and verified profile digest |

Records are at most 64 KiB, depth 16; mapping ancestry is at most eight layers
with 64 extents per UID/GID map. Kernel u64 identities use canonical decimal
strings, avoiding JCS's exact-integer limit. Maps are sorted, nonoverlapping and
exclude unmapped/overflow IDs. Namespace identities include device and inode;
they do not independently authorize anything. Identifiers use ASCII letters,
digits, `_`, `-`, `.` and are 1–128 bytes. Display descriptions are sanitized
UTF-8 up to 1024 bytes. Complete SELinux contexts have a 4096-byte bound. Unknown
fields, duplicate keys, mixed selector/account forms and unsupported tags fail.

The current selection grammar is a **draft parser fixture**, not installed CLI
functionality:

```text
--target host|self|registered:ID|process:DAEMON_PID
--account NAME
  OR --target-uid UID --target-gid GID [--supplementary-gids GID,GID,...]
--security-profile ID

sigrundctl target register ID --pid DAEMON_PID --owner-uid HOST_UID --security-profile ID
sigrundctl target revoke ID
sigrundctl target export-binding ID --output /ABSOLUTE/NEW_FILE
```

No selector/profile/account default is implicit. Groups are sorted and duplicates
rejected. Registration ownership is an administrator assertion, not inferred
container identity. A raw process selector must match an administrator-allowed
scope and the same retained instance; no global numeric UID ceiling authorizes
arbitrary processes. Host policy and one signer rule must each independently
authorize the resolved destination scope/credentials/profile and cross-owner use.
Resolved host kernel identities drive injection checks; equal namespace-local
integers do not imply equal authority, and different integers can map to one UID.

Management operations remain host-root only. The future root-controlled registry
provides register, revoke and export-binding operations with strict bounded
records; these operations do not belong on either client endpoint or `.context`.
Registration validates/acquires before returning an epoch-bound instance.
Revocation invalidates all dependent pending bindings and cancels dependent jobs;
replacement allocates a fresh revision/instance, never retargets existing grants.
The revision is a fresh administrator/daemon-generated 256-bit token, not a
self-referential content hash. Profiles are addressed by canonical content hash.
Generation replacement is atomic; captured ceilings cannot bypass revocation.
Reload as a general feature remains deferred.

Export is a new mode-0600 file created by the root CLI, followed by deliberate
administrator distribution to an authorized user over an authenticated path.
The receiver must already trust that path and the host authority. The bundle
reveals no new public discovery API. Its IDs/hash do not replace a live registry
entry. Full/offline preparation still requires requester access to destination
files; an unavailable access domain fails without privileged expansion. Initial
cross-domain routes use thin preparation; cross-domain full/export remains gated
for Phase 4. The signed v3 fixture binds the original intent, target epoch/instance
and constraint digest under the v3 DSSE/SSHSIG domains; production v2 rejects it.
`execution-binding.json` independently fixes SHA-256 over canonical
`{target_binding, security_constraints}`: local consumption stores the same 32
bytes whose lowercase hex appears in AUTH_COMMIT and collector `target_auth`.
The full payload hash separately binds numeric credentials and command intent.

Default hard ceilings are 64 registrations, 64 target leases globally/4 per host
requester UID, 2048 retained target FDs globally/128 per UID, 16 helpers globally/2
per UID, 16 reviews globally/2 per UID and one launcher per job. They compose with
existing socket/worker/admission limits, never replace them. Reserve actual FDs
before acquisition (the base resource bundle uses 20), charge transient duplicates,
helpers and launchers separately, and retain charges during cancellation or
blocked cleanup. Stage-specific C tests prove FD return only after process/target
cleanup; aggregate runtime admission/exhaustion is a Phase 1 integration gate.

## Qualification boundary

The first evidence platform is Fedora 44 x86-64, kernel
`6.19.10-300.fc44.x86_64`, cgroup v2 with memory/PID/swap controls and enforcing
SELinux. Exact versions and hashes belong in each evidence manifest; this is not
a minimum-kernel claim. Required syscalls/nsfs/ptrace/LSM operations are probed
directly and unavailable operations fail closed.

| Combination | Phase 0 status |
| --- | --- |
| Four routes, host and explicit constrained rootful/rootless anchors | Native prototype evidence required by the 62-case runner |
| Single child userns, initialized ordinary maps, exact numeric non-root account, empty groups/capabilities | Candidate entry profile |
| Enforcing SELinux, NNP + ptrace, direct and explicitly labeled sealed memfd, explicit syscall deny list | Candidate confinement profile; concurrent policy replacement limitation above remains blocked |
| Multithreaded/seccomp-filtered/credential-changing/unexpected-exec anchors | Rejection evidence |
| Socket passing, connector exit, old shared-FS mutation/restoration, setup faults, anchor/tracer/launcher loss and PID pressure | Required adversarial evidence |
| Nested/mixed-owner namespaces, arbitrary process capture, idmapped mounts, namespaced file capabilities, target root/capability grants, arbitrary existing seccomp, AppArmor/stacking and ARM64 | Unsupported or unqualified; separate evidence required |
| Manager identities/teardown, ComposeFS eligibility, cross-domain full access, integrated privacy/consumption and production daemon LSM packaging | Later delivery gates |

The Phase 0 record must preserve these limitations. In particular, the concurrent
policy-replacement prerequisite means the full requested milestone cannot be
declared unconditionally complete. Phase 1 can use the frozen contract fixtures;
features depending on an unresolved combination remain disabled. No experiment
replaces integrated V-01–V-20/NS acceptance in Phases 1–5.
