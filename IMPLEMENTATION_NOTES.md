# sigrun/sigrund implementation notes

This document describes the local v3 SSH/stdio workflow, namespace execution,
operator setup and test layout. The
[security specification](<sigrun sigrund Security Architecture and Implementation Specification.md>)
defines the broader protocol and security requirements.
For installation and the five host/container routes, use the [Quick Start](QUICK_START.md).

## V3 implementation and validation

Clients prepare canonical full CSRs from bounded public context or submit unchanged
thin intent. Full-only/export never request privileged expansion. Finite stdin is
spooled once locally and sealed again by the daemon before target inspection.
The separate context listener is the execution socket pathname plus `.context`;
it has independent rate/active limits and a fixed worker pool for reads and
ancillary descriptor cleanup, and publishes no target-specific data.

Full requests require an isolated fresh-exec access helper with kernel-authenticated
UID/GID/supplementary groups, cleared capabilities and `no_new_privs`. It traverses
from `/` without privileged directory handles, validates the pinned root identity,
and returns a retained readable FD through private IPC. It stays non-dumpable
through the credential transition and file access. The supported access domain
requires initial user-namespace mappings and protected `fs.suid_dumpable` (0 or 2).
Unsupported domains fail closed; namespace fixtures cannot establish this boundary.
Read permission is sufficient; requester execute permission is not required.

Thin expansion uses pinned roots privately. Canonical intent, signed origin and
active execution ID bind the complete evidence and exact capability profile.
Thin approvals cannot be exported or redeemed through the signed endpoint.
The daemon retains observable endpoints and thin review capacity until the public
outcome, hiding preparation failures and thin mandator refusal behind the configurable
admission-based deadline. Full and signed failures also time out, except that explicit mandator refusal
of a validated full CSR returns immediate `REJECTED`. Decisions contain only
`exec_id` and `status`.

Durable authorization precedes `APPROVED`; complete delivery precedes spawn.
Readiness and results are separate frames. Late durable commits remain consumed
and are reconciled/audited without execution. Private outcome audit distinguishes
scheduled outcomes from completed frame writes and undelivered responses.

Wire/warrant version 3.0, v3 signature/ratchet domains, and versioned database,
audit and ratchet state reject legacy formats. Explicitly provision a fresh,
coherent state set; startup never migrates or deletes old records.

## Supported workflow and limits

The `[mvp]` local profile requires an explicit `approval_signer_id` naming one SSH
signer. It supports `ssh-ed25519`/`sk-ssh-ed25519`, one-time grants, stdio, and
null or hashed finite stdin. It excludes direct scripts, caller environment
forwarding, same-UID execution, PTY, hooks and remote audit ACK. Collector config
remains mandatory even when remote acknowledgements are disabled.

Clients select an explicit target/profile and either `--account NAME` or numeric
UID/GID with exact supplementary groups. Defaults are no capabilities, captured
absolute cwd, `LANG=C.UTF-8`, `PATH=/usr/sbin:/usr/bin`, umask `077`, null stdin
and a 900-second TTL within daemon/signer ceilings. Executables use canonical
absolute paths under configured roots; arguments have no shell/PATH evaluation.
`--stdin sha256` snapshots finite file/pipe input; TTY stdin is rejected.
`--status-fd` must not alias command output. Denial exits 255, protocol/disconnect
failure 254, usage error 64; execution returns the child's status.

The single-slot broker displays the complete CSR, escaped/indexed arguments and
key fingerprint on root's controlling TTY. Enter `y`/`yes` to approve or `n`/`no`
to refuse; invalid input reprompts within the original admission deadline.
Pending input is discarded between prompts. Timeout/disconnect aborts the exchange
and reconnects the watcher. Signals, TTY loss or trust failures stop it. OpenSSH
signs DSSE PAE with namespace `sigrun.warrant.v3` and SHA-512 using a root-owned
identity or root's agent; askpass is disabled and terminal state is restored.
Software/encrypted/agent fixtures do not establish physical FIDO support.

Busy, absent-approver and failed thin requests retain the generic admission-based
TIMEOUT (default 120 seconds, configurable 1–300 seconds). Validated full refusal
returns immediate REJECTED with its reason private. Pre-commit failures consume
nothing; post-commit failures retain consumption. Complete APPROVED delivery
precedes spawn; readiness and final results follow separately.

Interpreter approval grants programmable authority within the selected credentials.
A digest binds the executable, without binding later script, import or library
reads. See [interpreter guidance](docs/PRIVILEGED_INTERPRETERS.md).

## Host bindings and provisioning

Full preparation/export requires an administrator-distributed binding bundle;
`.context` contains no target records. Each immutable profile fixes one executable
model. Insufficient local evidence preserves the same thin intent for ordinary
submission; full-only/export fails locally. Signed mismatches never fall back.

Provision a new, coherent v3 state/log set using `sigrundctl init-host --state-dir
/var/lib/sigrund --log-path /var/log/sigrund/audit.jsonl`. Preserve the printed
audit anchor privately and retain older state separately. Root exports a live host
binding into a new mode-0600 file:

```sh
sigrundctl target export-binding host --security-profile host-baseline \
  --epoch-file /var/lib/sigrund/host-epoch.json \
  --output /root/host-baseline-binding.json
```

Distribute that private target evidence deliberately to the intended requester,
who selects it with `--binding-bundle PATH`. The client checks its host authority,
acquisition/profile digests and local root/namespace/mapping evidence. Public
context cannot refresh a stale epoch; redemption rejects it. Restart invalidates
all bindings and warrants, even unused/unexpired ones. Export a fresh bundle after
restart or profile changes. See [package setup](packaging/README.md#configure-the-daemon)
and [offline signing](#operator-lab).

## Namespace execution

The host daemon authenticates the original connector through kernel credentials,
groups, pidfd and applicable security label. Passing a stream does not change
attribution to its later writer. Host clients have a kernel-authenticated
compatibility path when `PIDFD_GET_USER_NAMESPACE` is unavailable; namespace
capture still requires its supported kernel operations.

| Target/profile | Supported behavior |
| --- | --- |
| `host` / configured host profile | Thin, full and offline one-time SSH/stdio; daemon's retained execution environment. The packaged producer transitions commands to `sigrund_host_workload_t`, including host-only configurations. |
| `registered:ID`, `self` / `namespace-selinux-v1` | Thin online approval, sealed executable/input, exact SELinux workload transition, explicit seccomp and final-child exec verification. |
| `registered:ID`, `process:DAEMON_PID`, `self` / `namespace-experimental-v1` | Opt-in native execution without a requested LSM transition or seccomp filter. Known nonroot namespace-owner injection authority rejects before review, including experimental self. |
| Preview constraint schema | Private review only; generic TIMEOUT without consumption or execution. |

The enforcing deployment is Fedora 44 x86-64 with cgroup v2/systemd and SELinux.
Manager-free routes are host → registered rootless B and real rootless A → B,
A → host and A → self. A rootless environment has one child user namespace owning
all eight selected namespaces, coherent UID/GID maps and a mount-point root.
Untrusted requester/owner accounts must have locked passwords, nologin shells,
no sudo or alternate execution path, and remain in enforcing
`system_u:system_r:sigrund_requester_t:s0`. All unconfined host accounts are trusted
administrators. Exposing sockets to an arbitrary unconfined container is insufficient.

Production namespace full/export/offline redemption and process-PID targets are
excluded. Other namespace topologies, idmapped mounts, target root/capability
grants, AppArmor/stacked LSMs, executable models and platforms require separate
integration coverage. Ubuntu kernel 6.8 host authentication and ARM64 builds do
not establish namespace runtime support on those platforms.

### Acquisition, approval and execution

Root registers a disposable, single-threaded, unfiltered anchor inside an already
running environment. Capture authenticates its rendezvous, verifies the original
pidfd before enabling EXITKILL, forces successful `unshare(CLONE_FS | CLONE_FILES)`
and retains it at syscall exit. It pins root/cwd, all eight namespace handles,
namespace ownership, mapping/setgroups evidence and configured executable roots.
`self` captures its original public connector through the `.anchor` rendezvous;
the syscall-only connector and parent relay retain connection-time attribution.

Strict bounded records bind the daemon epoch, instance, registration revision,
acquisition and executable-root identities. Self additionally binds authenticated
source observations. Existing `*.phase0.v1` schema identifiers remain stable wire
identifiers; they do not require the retired development crate. Records are at
most 64 KiB, depth 16, with at most eight mapping layers and 64 extents per map;
kernel u64 identities use canonical decimal strings. Namespace, manager and host
vectors live under `crates/sigrund-core/tests/fixtures/`.

Fresh-exec destination workers resolve bounded account files, executable and cwd
beneath pinned roots, without host NSS fallback. Numeric accounts retain exact
requested groups; named accounts resolve destination primary/supplementary groups.
Daemon and signer independently authorize scope, cross-owner access, mapped
credentials and the exact constraint digest. Root's private TTY review binds the
complete intent, resolved evidence and CSR. Public failures retain the original
admission-based TIMEOUT and disclose no target-existence information.

One retained owner lease survives review, durable consumption, complete APPROVED
delivery, fresh-exec launcher handoff and cleanup. Only explicit FDs and a sealed
bounded configuration cross launcher exec; daemon memory, keys and environment
never enter the destination. The host tracer gates namespace entry, adopts the
final child through pidfd handoff, and verifies its exec stop before release:
credentials/groups, capabilities, NNP, namespaces/root/cwd, private mounts,
actual job cgroup, FD table, executable and declared LSM/seccomp state.

Production constraints require a labeled sealed ELF, the exact enforcing workload
SID, empty capabilities/groups, nonzero destination UID, securebits 15, NNP and
an explicit native-ABI seccomp deny list. Startup rejects unavailable enforcement,
permissive domains or incompatible profiles before serving. Policy-generation
changes invalidate owners and terminate jobs. Drain jobs before replacing policy;
this detection/termination contract provides no atomic policy-replacement interlock.

Anchor/helper death, revocation, cancellation and lost required evidence invalidate
the retained owner. Names or matching inodes never reacquire authority. Pending
failure consumes nothing; every post-commit failure retains consumption and tears
down the whole job, including descendants. Recovery needs a fresh anchor and approval.
Hard ceilings are 64 registrations, and global/per-UID limits of 64/4 leases,
2048/128 target FDs, 16/2 helpers and 16/2 reviews, plus one launcher per job.
Reserve before acquisition, charge transient duplicates, and refund only after
actual close/reap. Blocked cleanup remains charged; the local broker allows one review.

### Installed SELinux setup

The [Quick Start](QUICK_START.md#3-prepare-the-container-demo) contains the complete
fresh-host provisioning and five-route walkthrough. It uses the installed helpers
under `/usr/share/doc/sigrund/namespace/selinux/`, locked source/destination owners,
a root-only software signing key and independently scoped daemon/signer rules.
The recipe is disposable; generated state/configuration must not replace an
existing deployment. Its transient services have a ten-minute lifetime.

B's init starts independently before its disposable anchor is registered. The
source helper enters its actual rootless environment and runs the installed client
under the enforcing requester domain. Requests use exact destination account,
root/cwd, executable and profile evidence. Root reviews the complete private
record; APPROVED confirms consumption, followed by readiness and exit separately.

Revocation invalidates review and kills supervised jobs while retaining any
consumption. Start a fresh anchor before retrying. After daemon restart, refresh
the environment's bind of the recreated socket directory before reacquisition.
Stop transient services and unmount runtime/selinuxfs/device binds before removing
roots; preserve configuration, keys, state and audit together.

### Optional Podman lifecycle binding

The adapter supports local rootful Podman 5.8.1, a root-owned Unix API in the
default Libpod namespace, systemd cgroup v2, an initial-user-namespace destination
and a single private PID namespace whose init is PID 1. Its read-only rootfs and
init are administrator controlled. API/Podman-exec access and the socket's root
group are trusted host authority. Rootless/nonroot services, remote APIs,
nondefault manager namespaces and untrusted rootful container-root sources are excluded.
Host and real rootless A can request B as nonroot UID/GID 12001 with empty groups.

For this deployment, install Podman and container-selinux, then provision a fresh
host with `python3 "$NS_DOCS/podman/prepare-installed.py" --requester nsrequester`.
It loads the optional `sigrund_podman` module for producer API access only. Build
the host/A/B workloads and create source A using the
[Quick Start](QUICK_START.md#3-prepare-the-container-demo). Start `sigrund.service` and
`podman.socket`, run `restorecon -RF /run/podman`, and require a root:root socket
with mode 0660 or stricter and `container_var_run_t`. Start B independently:

```sh
python3 "$NS_DOCS/podman/prepare-rootfs.py" --workload /var/tmp/tool-b
podman run --detach --name sigrund-podman-b --rootfs --read-only --network none \
  --security-opt label=level:s0 --volume /run/sigrund:/run/sigrund \
  /var/lib/sigrund-podman-rootfs /usr/bin/sleep infinity
python3 "$NS_DOCS/podman/register-podman.py"
```

The registration helper pins namespace/root handles before starting a dedicated
anchor. The daemon independently matches those resources to the API init's exact
`/machine.slice/libpod-FULL_ID.scope/container` cgroup and PID-1 identity. The
underlying root-only operation is:

```sh
sigrundctl target register-podman container-b --pid DAEMON_ANCHOR_PID --owner-uid 0 \
  --security-profile namespace-selinux-v1 --socket /run/sigrund/client.sock \
  --podman-endpoint /run/podman/podman.sock --podman-owner-uid 0 \
  --podman-namespace default --podman-container sigrund-podman-b
```

Requesters still select `registered:container-b`; there is no public manager-name
lookup. Versioned manager context/review binds endpoint identity, owner/namespace,
full container ID, init/start identity, configuration digest and authenticated
peer. The required configuration covers Config, HostConfig, Mounts, ProcessLabel,
MountLabel, AppArmorProfile, Namespace, Image, Rootfs and Dependencies. Manager
metadata never expands daemon/signer authority or supplies Podman exec-policy equivalence.

A provisional lookup supplies a full-ID filter hint; acknowledge the filtered
chunked event stream before authoritative inspect and process capture. The fresh
snapshot must agree. Retain init/peer pidfds, endpoint directory and stream for
the binding lifetime. Relevant events, generation/configuration changes, malformed
or excessive replies, EOF/event gaps, endpoint replacement and failed revalidation
permanently invalidate it. Equal names in another engine confer no authority.
Never reconnect or revive an old binding; recovery requires fresh acquisition/approval.

Refresh every 200 ms with a two-second total query deadline, 100 ms idle I/O
quanta and three-second maximum evidence age. Management acquisition is bounded
to ten seconds and rechecks expiry/shutdown before publication. Headers are at
most 16 KiB; finite bodies/chunks 1 MiB; event lines 64 KiB and 256 events/second.
Manager acquisition reserves 20 FD slots and one helper before opening resources,
in addition to normal capture. The two-helper per-UID ceiling permits one managed
registration for owner UID 0 in this recipe. Loss cancels supervised descendants
without refunding consumption; observation is bounded detection, not atomic
serialization of manager operations with workload instructions.

## Code ownership and security boundaries

| Area | Responsibility |
| --- | --- |
| `sigrund-core` | Strict bounded JSON, canonical warrant/CSR and broker schemas, policy validation, crypto, framing, lifecycle CAS, SQLite consumption and authenticated audit recovery. |
| `cli`, `client`, `approver`, `warrant_tools` | Options, requester output/status and signal handling, root-TTY signing, and byte-preserving offline packaging. |
| `daemon`, `transport`, `admission`, `workers`, `socket_disposal` | Coordinator transitions, credential checks, bounded socket/worker ownership, deadlines, framing and off-loop disposal. |
| `linux`, `memfd`, `snapshot`, `preparation`, `authorization` | Pinned executable-root resolution, sealed snapshots, digest/signature binding and final authorization predicates. |
| `podman`, `podman::api` | Authenticated scoped manager evidence, bounded HTTP/event I/O and sticky lifecycle invalidation around normal capture. |
| `target_registry`, `target_capture`, `target_management`, `destination`, `destination_helper`, `process_request` | Epoch-local registered/self owners, root management, fresh-exec acquisition/preparation, mapped policy, private review and actual namespace-context verification. |
| `sequencer`, `storage` | Serialized durable consumption/audit, retained denial-audit leases, poison handling and sticky storage-pressure admission gates. |
| `startup`, `cgroup`, `jobs`, `execution`, `reaper`, `runtime`, `service` | Verified provisioning/startup, cgroup limits, syscall-only child transition, readiness, reaping, shutdown and service-manager supervision. |

The coordinator owns transitions and the single authorization decision. Workers
return owned results; FDs, snapshots, captured policy and quota charges move
together. Caller-controlled I/O, persistence and final closes run off-loop.
Cancellation never refunds resources before actual cleanup. Sockets retire from
epoll before disposal, including when workers retain duplicates.

Signed/unsigned preparation shares bounded workers. Final authorization rechecks
retained root identity, executable/input evidence, policy, validity and revocation.
One-time consumption records the raw payload digest. Commit/spawn reservations
reconcile irreversible outcomes before cancellation completes; unpublished-child
barriers keep reaping correct. Pre-commit denial delivery is independent of durable
audit I/O; its audit lease remains retained. Storage pressure latches admission.

Startup verifies root-owned inputs, locks state, recovers audit and probes kernel/
credential operations before listeners. Job cgroups enforce memory, swap and PID
limits. Shutdown stops admission, reconciles work, kills/reaps jobs and retains
cleanup ownership. Systemd supplies watchdog and whole-service cleanup.
`--authorization-only` is an explicit non-executing diagnostic mode.

Provisioning uses private trusted paths, atomic publication and fsync barriers.
Recovery verifies bounded HMAC/sequence/host/hash-linked audit records against
ratchet state. Failed publication poisons the writer until recovery. Retained
`initial_key_hex` enables history verification but provides no forward secrecy
after state compromise or whole-state rollback protection without external checkpoints.

## Executable trust selection

`executable_trust_models` defaults to `["fs_verity", "ctime", "digest_direct",
"digest_memfd"]`. Selection precedes approval; a signed warrant never switches
models. Each host profile selects exactly one enabled model. Use the shipped
`host-baseline` sealed-memfd profile for snapshot-only requests.

Ctime is online-only. Unprivileged clients submit a tentative version fingerprint;
matching their earlier byte observation is best effort. Before requesting the
mandator's signature, the daemon acquires `F_SETLEASE(F_RDLCK)` on the retained
source and establishes a protected baseline. Existing writable FDs and surviving
shared writable mappings prevent acquisition. Contention is retried every 10 ms
for at most 250 ms, within the request deadline. Unsupported leasing or exhausted
contention rejects that fixed ctime profile; a completed full
CSR naming ctime is rejected if that model cannot be established.

Under the lease, two `statx(AT_EMPTY_PATH | AT_STATX_FORCE_SYNC)` observations
bracket `fsync`; device, inode, size and ctime must agree, and eligibility is
rechecked. Synchronization runs on a reserved worker and does not promise an
interruptible syscall. Late completion is rejected under the existing deadline.
The uninterrupted lease, rather than timestamp changes during synchronization,
protects content from signing through execution.

The daemon consumes SIGIO through signalfd; `F_GETLEASE` is authoritative even
when signals coalesce or arrive late. A pending break, forced revocation or failed
lease query invalidates the attempt without reacquisition or refund after durable
consumption. The lease remains held through approval, authorization and launch.
After inode, evidence, metadata and credential verification at the exec stop, the
worker releases it: kernel executable write exclusion already protects the loaded
inode before target entry. Rejection, cancellation, timeout and shutdown release
leases through worker-owned cleanup. Administrative writers can delay acquisition
or interrupt approval even without modifying bytes.

Offline export skips ctime and chooses the first remaining eligible configured
model; a ctime-only policy cannot export a CSR. Pre-signed ctime warrants,
including warrants from older builds or resubmitted online approvals, are rejected
because redemption cannot establish protection back to their signing time.

`[digest_direct].allow_admin_trusted_composefs` defaults to `true`; set it to
`false` to exclude ComposeFS from direct execution. Existing executable-root
allowlists still apply. At startup the daemon recognizes only the host's booted,
read-only OSTree ComposeFS root, with one metadata lower and one data-only
`/sysroot/ostree/repo/objects` layer, no upper/workdir/userxattr, and known mount
options. Legacy `lowerdir=metadata::data` and newer `lowerdir+=...,datadir+=...`
representations are supported. Discovery requires the initial UID mapping and
PID 1's user/mount namespaces. The metadata lower mount is detached by OSTree;
its displayed path cannot be reopened. This model trusts the administrator's
boot-created metadata, rather than claiming to measure or authenticate it.

Before enrollment, the daemon checks every data-store ancestor and scans the
store without following symlinks or crossing mounts. Directories and regular
objects must be root-owned, without group/other write permissions or extended
access/default ACLs, on supported local storage. Symlink objects are not data
sources: OverlayFS data-only lookup rejects symlinks. Inspection is bounded to
250,000 entries, eight levels, ten seconds and a 4 MiB mount table. Unsupported,
inaccessible, unprotected or over-budget arrangements remain ineligible; the
daemon can still serve snapshot requests. The enrolled root and data-store FDs
remain pinned for the daemon's lifetime. Restart to reevaluate a changed layout.

Clients learn the qualified mount ID through public context; the daemon derives
its own enrollment and independently checks each retained executable. Mount IDs
are matched to descriptors, not path prefixes or client assertions. ComposeFS
executables must remain read-only and root-owned with ordinary metadata and no
file capabilities. Each request records `admin_trusted_composefs` in the audit;
online approvals display the administrator-maintenance assumption. The signed
model remains `digest_direct` with a full-file SHA-256. Preparation,
pre-consumption and exec-stop checks always hash the entire file; overlay ctime
never authorizes a cached hash. Existing inode, access and credential checks
remain in force.

Administrators must preserve backing-object protection and never modify active
objects in place, including through another writable mount or a privileged job.
The startup scan does not continuously police administrators or their updates.
This extension supplies no kernel write exclusion and no protection against a
privileged writer changing executable pages after the final hash. A read-only
view alone is insufficient. `ctime` and `fs_verity` eligibility are unchanged.

Verity binds a kernel-measured descriptor digest. Ctime binds the version of an
eligible root-managed local ELF under a continuous online-approval read lease.
Digest_direct signs a full-file SHA-256 and
executes the retained source, then hashes again at `PTRACE_EVENT_EXEC` before any
loader/target instruction. All direct models revalidate execution metadata and
exact credentials at authorization and at the exec stop. Supported direct files
preserve `/proc/self/exe` identity and ordinary host file-capability semantics
within the requested authority ceiling. File-capability transitions use an
inode-checked alias in the child's private mount namespace; an unavailable or
replaced path fails closed while the original FD stays pinned. Set-ID files, extended ACLs and noexec
mounts require fallback; unknown/namespaced/idmapped file capabilities do too.

All v3 warrants sign origin, canonical intent hash and all five expected post-exec
capability sets for every trust model, in addition to the requested authority
ceiling. Legacy warrant versions and signature domains fail closed. See normative
Section 2.2.2 for the evidence and credential table.

Direct execution uses no executable snapshot RAM. Verity/ctime may exceed both
size limits. Digest_direct uses a fixed 64 KiB buffer and its own
`max_direct_digest_bytes` (256 MiB default, 1 GiB ceiling) and
`direct_digest_timeout_ms` (5000 default, 30000 ceiling). Original request/setup
deadlines remain enforced; the coordinator owns the subsequent hashing and
post-exec verification deadlines. Cancellation is checked between chunks, while
reservations remain held until actual worker completion. Memfd and hashed stdin
retain their existing size/RAM limits. Memfd strips file capabilities and exposes
an execute-only anonymous `/proc/self/exe`; programs relying on reading their
original executable may require an eligible direct model.

Ctime trusts root maintenance/timestamps; digest_direct uses either a supported
local filesystem's executable write exclusion or the explicitly documented
administrator-maintained ComposeFS contract above. None authenticate the dynamic
loader, libraries, configuration or an LSM transition. Post-commit verification
failure consumes a one-time warrant without refund. Tracer death before release
kills the tracee. Successful detach clears tracing state for later SIGSTOP.

The privileged `scripts/verify-trust.py` gates cover ext4 verity (SHA-256/512),
large direct ELFs, digest mutation, file-capability profiles, `/proc/self/exe`,
metadata changes during online approval, noexec fallback and tracer death.
ComposeFS also has two ignored privileged Rust fixtures: run
`composefs::tests::privileged_store_protection_and_bounds` and
`executable::tests::composefs_rehash_detects_data_changes_hidden_by_metacopy`
from the library test binary as root under
`unshare --mount --propagation private`, with `--ignored --exact`.
The latter changes backing bytes while retaining identical metacopy timestamps
and verifies that pre-consumption hashing detects the change. A native OSTree
ComposeFS guest additionally exercises real enrollment, client-full and online
approval, opt-out, backing-store rejection and no downgrade after signing.


## Operator lab

Use a disposable native systemd host meeting startup's kernel/cgroup requirements.
Build as an ordinary user; prepare as root with an existing requester distinct
from UID 0, 33 and 65534. The lab directory must be new under a trusted parent:

```sh
export TEST_REPO=/absolute/sigrund
python3 "$TEST_REPO/scripts/operator-lab.py" prepare \
  --directory /var/lib/sigrund-demo --binaries "$TEST_REPO/target/debug" \
  --requester requester
source /var/lib/sigrund-demo/environment.sh
python3 "$TEST_REPO/scripts/operator-lab.py" start --directory "$TEST_BASE"
python3 "$TEST_REPO/scripts/operator-lab.py" status --directory "$TEST_BASE"
```

The helper generates disposable software keys, isolated state/policy and inactive
collector placeholders. It installs a unique temporary service under `/run/systemd/system`.
After stopping it, `foreground --directory "$TEST_BASE"` provides an alternative
systemd-run recipe with the same supervision. Use one recipe at a time.

In root's separate TTY, source `environment.sh` and run:

```sh
"$TEST_BIN/sigrund-approve" --socket "$TEST_APPROVAL_SOCKET" --tty /dev/tty \
  --signers "$TEST_SIGNERS" --identity "$TEST_SSH_IDENTITY" --epoch-file "$TEST_EPOCH"
```

In the requester login, source the same environment and run:

```sh
"$TEST_BIN/sigrun" --socket "$TEST_SOCKET" --target host --security-profile host-baseline \
  --target-uid 0 --target-gid 0 --cwd / --status-fd 3 \
  -- "$TEST_COMMANDS/id" -u 3>request.status.jsonl
```

Select numeric UID/GID 33 for the service-user example. The lab exports its own
sockets; the binaries and packages default to `/run/sigrund/{client,approve}.sock`,
with state under `/var/lib/sigrund` and audit logs under `/var/log/sigrund`.

For offline signing, root first exports a live binding and deliberately distributes
it to the requester as described in [host bindings and provisioning](#host-bindings-and-provisioning).
Set `TRUSTED_BINDING` to that distributed file. Run full export as the **requester**
into a new file in a writable directory:

```sh
"$TEST_BIN/sigrun" --socket "$TEST_SOCKET" --target host --security-profile host-baseline \
  --target-uid 0 --target-gid 0 --cwd / \
  --binding-bundle "$TRUSTED_BINDING" --export-csr request.csr -- "$TEST_COMMANDS/id" -u
```

Export uses the supplied binding and target-independent public context. A
profile requiring online-only ctime cannot be exported;
unreadable, incomplete or unavailable offline evidence fails locally.
Have root obtain the exact file, review every field, then sign and package it.
Choose new output paths; the helpers refuse overwrites. The example below assumes
root has copied that requester file to `$TEST_BASE/request.csr`:

```sh
"$TEST_BIN/sigrundctl" csr-pae --csr "$TEST_BASE/request.csr" \
  --pae "$TEST_BASE/request.pae"
python3 -m json.tool "$TEST_BASE/request.csr"
# Review every field before signing.
ssh-keygen -Y sign -n sigrun.warrant.v3 -O hashalg=sha512 \
  -f "$TEST_SSH_IDENTITY" "$TEST_BASE/request.pae"
"$TEST_BIN/sigrundctl" pack-warrant --csr "$TEST_BASE/request.csr" \
  --signature "$TEST_BASE/request.pae.sig" --signer-id "$TEST_SIGNER_ID" \
  --output "$TEST_BASE/request.warrant.json"
chmod 0644 "$TEST_BASE/request.warrant.json"
```

The original requester redeems before expiry with
`"$TEST_BIN/sigrun" --socket "$TEST_SOCKET" --warrant "$TEST_BASE/request.warrant.json"`.
A second redemption is replay-denied. Packaging preserves signed bytes and
refuses output overwrite; it does not grant authorization or refresh validity.

Stop either lab recipe as root with
`python3 "$TEST_REPO/scripts/operator-lab.py" stop --directory "$TEST_BASE"`.
Verify the unit, sockets and cgroup are gone. State and keys remain private.
After uncertain commit/spawn outcomes, inspect status, audit and consumption
state before obtaining fresh approval. Do not retry automatically or delete
consumption records. For storage pressure, stop, restore capacity without
truncating history, and restart to revalidate. Keep host identity, full audit
history, ratchet state, SQLite database and sidecars together.

## Tests and reproduction

Rust integration suites and native fixtures are organized by their owning
module. Tests inside source modules remain beside the implementation.

| Suite | Main coverage |
| --- | --- |
| `sigrund-core/tests/contracts/{warrant,approval,config,json,protocol}.rs` | Canonical bytes, bounds, every signed CSR field, exact broker schemas, profile/signer restrictions and wire ceilings. |
| `sigrund/tests/{cli,client,transport}.rs` | CLI/defaults, malformed frames and rights, deadlines, status isolation, TTY/file/pipe relays, blocked/broken output and cancellation. |
| `sigrund/tests/{linux,snapshot}.rs` | Root pinning, safe resolution, bounded sealed copying, mutation/EOF handling and retained RAM ownership. |
| `sigrund/tests/daemon.rs` and `daemon/` | Real namespace-root daemon, non-root peers, startup/provisioning, approval/refusal/signing/reconnect, replay/revocation, blocked I/O/disposal, durable denials and storage pressure. |
| `sigrund/tests/{cgroup,execution,reaper}.rs` | Delegated platform operations, child setup failures and FD sentinels, early exits and reaper registration barrier. |
| `sigrund/tests/warrant_tools.rs` | Offline CSR/PAE/SSHSIG byte preservation and malformed/ambiguous input. |
| `sigrund/tests/fixtures/{execution,storage,transport}/` | Native probes and fault interposers; fault switches never enter production builds. |
| `scripts/tests/` | Acceptance cancellation observation order and operator-service lifetime guards. |

The MSRV is Rust 1.89, declared in the workspace's `Cargo.toml` and inherited
by both crates. `rust-toolchain.toml` pins an exact Rust release for development,
including Clippy, rustfmt and rust-analyzer. Rust sources are opt-in. Cargo resolver 3
prefers dependencies compatible with the declared MSRV when updating the
lockfile; CI verifies compatibility with the actual minimum compiler.
See [maintenance](MAINTENANCE.md) for the toolchain update procedure.
A C compiler, Python 3, OpenSSH and uidmap utilities are required.
Namespace fixtures need subordinate UID/GID mappings and permitted user
namespaces. Run ordinary checks as an unprivileged user:

```sh
python3 scripts/check.py --artifacts /tmp/sigrund-checks
```

This runs the locked workspace build/tests, Clippy, formatting, diff and Python
checks and discovers the delegated platform test executable through Cargo JSON.
It binds source and binary digests to the temporary check manifest. Use fresh
artifact directories after source changes; keep run output outside the checkout.

Privileged acceptance additionally needs systemd, actual delegated `memory`
and `pids` controllers with swap controls, the required Linux namespace/mount
and clone operations, strace and Python PyGObject. As root on a disposable test
host, run:

```sh
python3 /absolute/sigrund/scripts/verify-acceptance.py \
  --checks /tmp/sigrund-checks/checks.json --binaries /absolute/sigrund/target/debug \
  --requester requester --artifacts /tmp/sigrund-acceptance
```

The entry point runs `verify-privileged-rust.py` against the recorded test binaries,
then supervises platform, runtime, trust, execution and v3 protocol gates. It covers
actual approval/offline signing, replay/revocation, privacy, resource ownership,
post-commit failure, recovery and service shutdown. Require success and supervisor
cgroup removal; namespace-root fixtures alone cannot establish those boundaries.

For a targeted initial-userns retry, obtain test executables from Cargo JSON and
pass `--daemon-tests`, `--library-tests`, optional `--client-tests`, and a new
`--artifacts` directory to `verify-privileged-rust.py`. Run inside a dedicated
systemd service with `Delegate=yes`, `KillMode=control-group` and
`RuntimeMaxSec=900s`. Each gate has a 300-second limit. Enforcing SELinux needs
the deployment's administrative supervisor context. Keep generated output outside
the checkout.

Namespace checks are grouped under `scripts/namespace/`: `verify-review.py`
exercises capture/private preview, and `verify-execution.py` exercises the native
experimental executor. Both require `--binaries DIR --owner USER --artifacts NEW_DIR`
and supervise their own disposable systemd service. Native fixtures belong to
`sigrund/tests/fixtures/namespace/`; canonical records/signatures belong to
`sigrund-core/tests/fixtures/{v3-host,namespace,manager}/`.

Installed SELinux tests use `namespace/selinux/verify-installed.py --artifacts
NEW_DIR --lifecycle --security --exclusions`, plus `verify-source.py`,
`verify-host-only.py` and `verify-bindings.py` for attribution, host producer
transitions and audit/collector digest equality. The host-only runner requires
`--owner TRUSTED_ADMIN` and temporarily changes config; the binding runner needs
`--collector MATCHING_BINARY`. Podman tests use `namespace/podman/verify-installed.py`,
`verify-resolver.py`, `verify-scopes.py` and `verify-ownership.py`, each with a new
`--artifacts` directory. Run installed suites sequentially on the disposable
setup above; they deliberately modify policy, containers and API services, and
require their own unused private working directories. Check cleanup as well as
case outcomes. Run manifests, traces and private reviews stay outside the repository.

## Continuous integration

CI uses disposable Ubuntu 24.04 x86-64 and ARM64 VMs for the pinned development
toolchain's format, Clippy, workspace tests and privileged host acceptance.
An independent x86-64 job builds/tests all targets at the manifest's MSRV with
the lockfile. Clippy respects that MSRV. Caches bind architecture/toolchain;
unsupported kernel features, failed gates and surviving supervisor cgroups fail CI.

CI and Packages share `should-run.yml`: pushes with an open same-repository PR
skip duplicate checks; PR, manual and tag runs proceed. Each workflow cancels
older runs in separate branch/PR concurrency groups. Acceptance repeats ordinary
checks before root integration against the recorded source/build. Logs, manifests
and traces are seven-day Actions artifacts; keys, ratchet state, anchors and
databases are excluded. Software-key fixtures make no physical FIDO claim.

## Remaining specification scope

Distribution packaging is described in the [package guide](packaging/README.md).
The separate Packages workflow builds Fedora 44/45 RPMs and Ubuntu 24.04/26.04
DEBs on x86-64, with independent client and daemon packages. Fresh-container
installation/upgrade/removal tests validate packaging; they do not replace the
native privileged execution gates. Packages never provision or automatically
start the daemon, and preserve operator state on removal.

Beyond the implemented workflow, independent deferred features include:

- PTY transfer, window relaying, terminal cleanup and unrestricted input.
- Trusted hook execution and strict deadline/output/confidentiality integration.
- Remote TLS collector service, replication/ACK, receipts, durable cursors,
  provisioning anchors and external rollback/checkpoint protection. The
  collector binary currently supplies validation diagnostics only.
- Policy reload with aggregate generation quotas, scripts/reusable grants,
  OpenPGP/Sigstore adapters and safe administrative revocation tooling.
- Real hardware signing acceptance before claiming physical security-key
  interaction, plus qualification of additional deployment platforms.

Broader namespace deployment claims require separate integration coverage.
No v2 compatibility layer or automatic state migration is planned. Interpreter
artifact binding remains separate deferred work.

## Proposed setup experience

This is a design direction; the commands below are **not implemented**. The
[Quick Start](QUICK_START.md) documents today's supported commands. The next
usability improvement should remove repeated manual configuration without
expanding target authority or supported deployment scope.

A proposed host workflow is:

```text
sigrundctl doctor
sigrundctl setup host --requester USER --identity /root/.ssh/KEY \
  --target-account root --executable /usr/bin/id --plan /root/sigrund-setup.json
sigrundctl setup apply --plan /root/sigrund-setup.json
```

`doctor` should report host prerequisites, current installation/state and exact
profile availability without changing persistent state. Planning should resolve
explicit identities, render complete daemon/signer configuration and show file,
service and credential effects. Applying should revalidate those inputs, refuse
unrelated existing/partial state, publish root-owned files atomically and provision
once. Service startup should be a distinct explicit option. Retrying must report
verified completed steps; interruption needs an inspected recovery path that never
replaces identities or resets consumption. Existing deployments require a separate
inspected update operation.

The initial preset should select local audit, one-time SSH/stdio, sealed finite
input and digest-memfd with explicit requester, destination and executable scope.
Unused remote-collector settings/files should become unnecessary through an
explicit configuration-validation change; fake TLS credentials must not become
an ordinary setup requirement. Existing state/audit guarantees remain unchanged.
Use an existing SSH identity by default; generating a disposable software key
should require an explicit demo choice. Configure an approver launch command
without transferring signing authority to the daemon.

Namespace setup should be a separate explicit operation that checks the enforcing
requester/workload policy, mappings, mounts and endpoint access before producing
a plan. A later target setup wrapper can coordinate dedicated anchors and the
existing administrator registration operations, including the qualified scoped
Podman adapter. Keep public `registered:ID`/`self` semantics and the exact private
review. Never infer host privilege from manager access, weaken enforcement,
automatically enable an experimental profile, or revive stale registrations.
Root-controlled client presets may fill repetitive options only if the complete
requested/resolved fields remain visible and signed.

Before implementation, settle the plan's versioned format, stale-plan detection,
secret handling, partial-apply recovery and host-only defaults. Deliver a native
host setup/diagnosis path first, then enforcing namespace/manager setup with its
own integration coverage. None of this requires a development-phase CLI or new
public target-discovery service.
