# sigrun/sigrund implementation notes

The [security specification](<sigrun sigrund Security Architecture and Implementation Specification.md>)
now defines the **draft v3 target**, including namespace-aware execution. These
notes describe the implemented **v2 local one-time SSH/stdio profile**; the
specification rewrite does not change runtime contracts or establish v3 support.
The [phased roadmap](docs/NAMESPACE_AWARE_EXECUTION.md) tracks v3 delivery and
release gates. Deferred features and acceptance limits below remain part of the
current implementation assessment.

## V2 implementation and validation

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
outcome, hiding preparation failures and mandator refusal behind the configurable
admission-based deadline. Validated full requests may receive explicit refusal;
signed failures time out. Decisions contain only `exec_id` and `status`.

Durable authorization precedes `APPROVED`; complete delivery precedes spawn.
Readiness and results are separate frames. Late durable commits remain consumed
and are reconciled/audited without execution. Private outcome audit distinguishes
scheduled outcomes from completed frame writes and undelivered responses.

Wire/warrant version 2.0, v2 signature/ratchet domains, and versioned database,
audit and ratchet state reject legacy formats. Explicitly provision a fresh,
coherent state set; startup never migrates or deletes old records.

The regression suites cover v2 schemas, local preparation, deadlines, provenance,
state rejection and the existing execution profile. `scripts/verify-v2.py` adds
native raw-socket DAC/ACL/ancestor/supplementary-group checks and compares hidden
thin failures, output endpoint behavior, exact outcomes and private audit.
The complete applicable V-01–V-20 acceptance matrix remains the release gate;
passing a subset does not establish full v2 conformance.

## Supported workflow and limits

An unprivileged requester runs `sigrun`; a foreground root approver reviews the
complete request on its own controlling TTY and signs with an explicitly chosen
SSH key. The daemon verifies the signature and policy, consumes the one-time
grant, persists local audit, executes the retained executable and sealed finite stdin, and returns
separate stdout/stderr and the primary child's exit status. Pre-signed warrants
use the same authorization and execution gates without an online approver.

Execution requires the `[mvp]` daemon profile and a configured
`approval_signer_id` naming exactly one SSH signer. This profile supports
`ssh-ed25519` and `sk-ssh-ed25519`, one-time grants, `stdio`, and null or hashed
finite stdin. It rejects direct scripts, caller environment forwarding,
same-UID execution, PTY, hooks and remote audit acknowledgements. Collector
configuration is still mandatory and validated. The approval capacity is one;
busy requests silently time out. Absent approvers, invalid requests, broker
loss and thin refusal remain silent until `authorization_timeout_ms` from
admission (120 seconds by default; configurable from 1 to 300 seconds).
An explicit mandator refusal of a validated full CSR returns `REJECTED`.
No unsuccessful pre-commit outcome consumes a grant.

The client defaults to UID/GID `0:0`, no supplementary groups or capabilities,
its captured absolute cwd, exact environment `LANG=C.UTF-8` and
`PATH=/usr/sbin:/usr/bin`, umask `077`, null stdin and a 900-second TTL subject
to daemon/signer bounds. Executables require absolute canonical paths beneath
configured roots. Arguments are exact values without shell evaluation or PATH
search. `--stdin sha256` snapshots finite file/pipe input; TTY stdin is rejected.
`--status-fd` must be separate from command output, including descriptor aliases.
Authorization denial defaults to exit 255, protocol/disconnect failure to 254,
and usage errors to 64; successful execution returns the child's status.

Root approves only with `y` or `yes` after every CSR field and the selected key
fingerprint are displayed with escaped arguments. Confirmation requires Enter;
`n` or `no` rejects. Pending TTY input is discarded after each prompt. Blank,
invalid and overlong answers reprompt within the admission-based authorization deadline.
Timeout or broker disconnect aborts that exchange and reconnects the watcher
for future requests, discarding unfinished confirmation. Local signals, TTY
loss and trust/protocol failures still stop it. The root-owned identity may
be a private key or a public key backed by root's SSH agent. Signing uses
OpenSSH SSHSIG over DSSE PAE, with namespace `sigrun.warrant.v2` and SHA-512.
Passphrases stay on the verified TTY; askpass is disabled, and terminal settings
are restored after helper cancellation. Software, encrypted-key and agent paths
have fixtures; simulated security-key signatures do not prove physical FIDO
operation.

Interpreter approval grants programmable authority within the selected
credentials. An executable digest does not bind mutable script files, libraries
or imports. Jobs execute in the daemon's configured domain; requester namespaces
are not followed automatically. Cross-container/host routing is unimplemented.
See [privileged interpreter guidance](docs/PRIVILEGED_INTERPRETERS.md) and the
[namespace-aware execution roadmap](docs/NAMESPACE_AWARE_EXECUTION.md).

### Deferred namespace-aware executable evidence

Namespace-aware workflows are not implemented. Their target requirements are now
in the draft v3 specification, with implementation phases and acceptance ownership
in the [roadmap](docs/NAMESPACE_AWARE_EXECUTION.md). The requester-access helper
resolves paths in the daemon's mount namespace using authenticated requester
credentials; jobs execute in that daemon's domain. Neither follows the
requester's namespace set. The private mount namespace used for child isolation
and namespace-root test fixtures do not establish container routing or
cross-namespace workflow support.

A known ComposeFS limitation occurs when a client sees a cloned mount tree,
such as `systemd` `PrivateMounts=` or a container exposing the host socket.
Public context advertises the daemon-enrolled mount ID. A different mount ID
on the client's executable cannot qualify against that enrollment, so local
evidence selection can choose `digest_memfd` while daemon-local selection chooses
`digest_direct`. Unsigned `full_csr` preparation independently chooses the
daemon's preferred eligible model and rejects evidence that differs from the
client's CSR before approval. Local full-CSR preparation can succeed in this
case, so the client's fallback on local preparation errors does not trigger a
thin request. Cross-namespace snapshot fallback is therefore not guaranteed.

Run the requester in the daemon's execution domain (for example, use host
execution for a host daemon). For a recognized ComposeFS root, setting
`[digest_direct].allow_admin_trusted_composefs = false` removes this ComposeFS
selection difference; `executable_trust_models = ["digest_memfd"]` explicitly
selects snapshots on both sides. These settings do not implement namespace
routing or reconcile different executable bytes, credentials or cwd paths.

The namespace-aware implementation must resolve this limitation as part of its
destination contract. It must bind executable and cwd resolution, requester
identity and evidence to the verified destination, then reconcile unsigned
full-CSR model selection there. Any deliberate thin fallback must preserve
intent and approval provenance; `--full-only` and CSR export must never silently
request privileged expansion. Already signed warrants must retain their signed
model and bytes, with no downgrade on a mismatch. Acceptance must cover cloned
ComposeFS mount trees, `PrivateMounts=`, supported container routes, identical
paths with different destination bytes, default/full-only/export/thin requests,
and signed-request rejection without consumption or model switching. This work
is deferred to namespace-aware workflows; the current evidence checks continue
to fail closed.

## Code ownership and security boundaries

| Area | Responsibility |
| --- | --- |
| `sigrund-core` | Strict bounded JSON, canonical warrant/CSR and broker schemas, policy validation, crypto, framing, lifecycle CAS, SQLite consumption and authenticated audit recovery. |
| `cli`, `client`, `approver`, `warrant_tools` | Options, requester output/status and signal handling, root-TTY signing, and byte-preserving offline packaging. |
| `daemon`, `transport`, `admission`, `workers`, `socket_disposal` | Coordinator transitions, credential checks, bounded socket/worker ownership, deadlines, framing and off-loop disposal. |
| `linux`, `memfd`, `snapshot`, `preparation`, `authorization` | Pinned executable-root resolution, sealed snapshots, digest/signature binding and final authorization predicates. |
| `sequencer`, `storage` | Serialized durable consumption/audit, retained denial-audit leases, poison handling and sticky storage-pressure admission gates. |
| `startup`, `cgroup`, `jobs`, `execution`, `reaper`, `runtime`, `service` | Verified provisioning/startup, cgroup limits, syscall-only child transition, readiness, reaping, shutdown and service-manager supervision. |

The coordinator owns request transitions and the single authorization decision.
Workers return owned results; FDs, snapshots, captured policy and quota charges
move together. Caller-controlled metadata, reads, final descriptor/socket closes
and filesystem persistence run off-loop. Timeout or disconnect cannot release a
worker/RAM/audit reservation until its owner actually finishes cleanup. Sockets
are unregistered from epoll before retirement, including when a worker retains
a duplicate. Unmappable peer credentials reject only that connection.

Executable preparation and stdin snapshots share the same bounded worker path for
signed and unsigned requests. Root pinning permits mount crossings; executable
resolution beneath a pinned root uses stricter `openat2` restrictions. Final
authorization rechecks retained root identity, sealed bytes, policy, validity and
revocation. Multi-signature envelopes select an eligible unrevoked signer under
the serialized revocation gate. One-time consumption stores the raw SHA-256
payload digest; database failures are distinguished from replay conflicts.

Pre-commit denials have bounded delivery independent of durable audit I/O;
a separate bounded audit lease remains owned until persistence or fatal shutdown.
Storage pressure latches after an append crosses the threshold. Commit/spawn
reservations defer cancellation results until the operation is reconciled.
Returned children are registered before the reaper's unpublished-spawn barrier
opens; known children remain serviceable. The child tracks its actual error-pipe
FD through remapping rather than assuming inherited FD 4 is safe. Readiness
confirms setup, with exec outcome still unknown.

Startup pins and verifies trusted root-owned files/directories, locks state,
recovers audit through verified descriptors, and probes required kernel and
credential operations before exposing listeners. Each job enforces memory,
swap and PID limits. Shutdown stops admission, reconciles reserved work, kills
and reaps jobs, and retains cleanup ownership. Systemd supplies the final
whole-service kill boundary for stalled cleanup; watchdog deadlines bound idle
polling. `--authorization-only` is an explicit non-executing diagnostic mode.

Provisioning uses private files, trusted directories, atomic ratchet-state
publication and file/parent-directory fsync barriers. Audit recovery streams
bounded records and verifies HMACs, sequence, host and hash links. It permits a
partial tail only at a synchronized checkpoint, or one complete record ahead
of state with no partial tail. Failed state publication poisons the writer until
verified recovery. Retaining `initial_key_hex` enables history verification but
provides neither forward secrecy after root/state compromise nor protection
against whole-state rollback without an external checkpoint.

## Executable trust selection

`executable_trust_models` defaults to `["fs_verity", "ctime", "digest_direct",
"digest_memfd"]`. Selection precedes approval; a signed warrant never switches
models. Set `["digest_memfd"]` for snapshot-only operation.

Ctime is online-only. Unprivileged clients submit a tentative version fingerprint;
matching their earlier byte observation is best effort. Before requesting the
mandator's signature, the daemon acquires `F_SETLEASE(F_RDLCK)` on the retained
source and establishes a protected baseline. Existing writable FDs and surviving
shared writable mappings prevent acquisition. Contention is retried every 10 ms
for at most 250 ms, within the request deadline. Unsupported leasing or exhausted
contention permits selection of another model before approval; a completed full
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
preserve `/proc/self/exe` identity and ordinary host v2 file-capability semantics
within the requested authority ceiling. File-capability transitions use an
inode-checked alias in the child's private mount namespace; an unavailable or
replaced path fails closed while the original FD stays pinned. Set-ID files, extended ACLs and noexec
mounts require fallback; unknown/namespaced/idmapped file capabilities do too.

All v2 warrants sign origin, canonical intent hash and all five expected post-exec
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

Use a disposable native Linux systemd host with unified cgroup v2 and the
required kernel operations. Root in a container alone does not establish
working delegation, mount visibility or service-manager transport. The startup
probe is authoritative; the lab does not implement namespace routing.

Build as the workspace user. As root, prepare a fresh directory directly under
a trusted root-owned parent, using an existing ordinary requester login distinct
from UID 0, 33 and 65534:

```sh
export TEST_REPO=/absolute/sigrund
python3 "$TEST_REPO/scripts/operator-lab.py" prepare \
  --directory /var/lib/sigrund-demo --binaries "$TEST_REPO/target/debug" \
  --requester requester
source /var/lib/sigrund-demo/environment.sh
python3 "$TEST_REPO/scripts/operator-lab.py" start --directory "$TEST_BASE"
python3 "$TEST_REPO/scripts/operator-lab.py" status --directory "$TEST_BASE"
```

The helper copies binaries/native test commands and generates a disposable
root-owned software signing key, signer policy and isolated state. Collector
files are inactive placeholders for this local-only profile. It installs only
a uniquely named temporary unit under `/run/systemd/system`. After stopping the
service recipe, `foreground --directory "$TEST_BASE"` uses `systemd-run` with
the same delegation, readiness, watchdog and whole-service cleanup. Use one
recipe at a time. Packaged sockets are `/run/sigrund/client.sock` and
`/run/sigrund/approve.sock`; bare binary defaults are `/run/sigrund.sock` and
`/run/sigrund-approve.sock`. The lab exports its own socket paths.

In root's separate controlling terminal:

```sh
source /var/lib/sigrund-demo/environment.sh
"$TEST_BIN/sigrund-approve" --socket "$TEST_APPROVAL_SOCKET" --tty /dev/tty \
  --signers "$TEST_SIGNERS" --identity "$TEST_SSH_IDENTITY"
```

In the requester login:

```sh
source /var/lib/sigrund-demo/environment.sh
"$TEST_BIN/sigrun" --socket "$TEST_SOCKET" --cwd / --status-fd 3 \
  -- "$TEST_COMMANDS/id" -u 3>request.status.jsonl
```

Approval prints the target UID and returns the child's status. A service-user
request can add `--target-uid 33 --target-gid 33`; `--stdin sha256` binds piped
or redirected input. Keep status in its own file and inspect it separately.

For offline signing, run full export as the **requester** into a new file in a
writable directory:

```sh
"$TEST_BIN/sigrun" --socket "$TEST_SOCKET" --cwd / \
  --export-csr request.csr -- "$TEST_COMMANDS/id" -u
```

Export queries only public context and skips the online-only ctime model;
unreadable, incomplete or unavailable offline evidence fails locally.
Have root obtain the exact file, review every field, then sign and package it.
Choose new output paths; the helpers refuse overwrites. The example below assumes
root has copied that requester file to `$TEST_BASE/request.csr`:

```sh
"$TEST_BIN/sigrundctl" csr-pae --csr "$TEST_BASE/request.csr" \
  --pae "$TEST_BASE/request.pae"
python3 -m json.tool "$TEST_BASE/request.csr"
# Review every field before signing.
ssh-keygen -Y sign -n sigrun.warrant.v2 -O hashalg=sha512 \
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

The entry point supervises `verify-platform.py`, `verify-runtime.py` and
`verify-execution.py`, plus the native `verify-v2.py` gate, then exercises offline signing, binding/concurrent replay,
output/limits, post-commit failure, local recovery and both operator recipes.
Checks include real root/service credentials, setup and registration races,
shutdown/restart/escalation, and cancellation while output stays blocked.
Operator units bind their lifetime to the acceptance service; deadlines and
whole-service cleanup apply even if Python is killed. Require both suite
success and supervisor cgroup removal. Namespace fixtures alone do not establish
privileged runtime behavior. Generated manifests, logs and traces are disposable
run output; historical results are available through Git history.

## Continuous integration

GitHub Actions runs on pushes, pull requests and manual dispatch using disposable
native Ubuntu 24.04 VMs: `ubuntu-24.04` for x86-64 and `ubuntu-24.04-arm` for
ARM64. Formatting, builds, Clippy, workspace tests and full privileged acceptance
run on both architectures using the exact toolchain pinned in
`rust-toolchain.toml`. CI installs the active toolchain from that file, so
updating the pin updates these jobs and package
builds together. Formatting and Clippy run only on the development toolchain;
Clippy reads the MSRV from the crate manifests and treats warnings as errors.
A separate x86-64 MSRV job reads `workspace.package.rust-version` from
`Cargo.toml`, installs the first release of that Rust minor version, builds every workspace
target and runs workspace tests. All builds and tests use the lockfile, so newer
APIs, syntax or incompatible locked dependencies fail the MSRV job. Development
build caches include the architecture and resolved compiler version. Acceptance
artifacts include the architecture so parallel jobs cannot overwrite each other.

Both CI and Packages use the shared `should-run.yml` workflow to skip push checks
when the branch already heads an open PR within this repository. Pull requests,
manual runs and tag pushes still run. Each workflow cancels older runs for the
same branch ref or PR number. Branch and PR groups are separate so a skipped push
cannot cancel PR checks; CI and Packages also have separate groups.

Full privileged acceptance follows successful formatting, development checks and
MSRV tests. It repeats `scripts/check.py` as the unprivileged runner before
running the root acceptance harness against that exact source/build. Check manifests bind
the toolchain file and record compiler/Cargo versions. Runner preparation
installs Linux test tools, configures subordinate IDs and permits the namespace
fixtures. These changes apply only to disposable hosted VMs. Unsupported kernel
features, failed acceptance gates and retained supervisor cgroups fail CI.

The acceptance job summary lists gate outcomes and cgroup cleanup. Non-secret
logs, manifests and syscall traces are uploaded on success or failure as
seven-day Actions artifacts; signing keys, ratchet state, anchors and databases
are excluded. Results stay outside the checkout. Automated TTY/SSHSIG tests
exercise software keys, not physical FIDO interaction.

## Remaining specification scope

Distribution packaging is described in the [package guide](packaging/README.md).
The separate Packages workflow builds Fedora 44/45 RPMs and Ubuntu 24.04/26.04
DEBs on x86-64, with independent client and daemon packages. Fresh-container
installation/upgrade/removal tests validate packaging; they do not replace the
native privileged execution gates. Packages never provision or automatically
start the daemon, and preserve operator state on removal.

The existing local profile still needs integrated acceptance evidence; the
replacement v3 specification retains the V-01–V-20 obligations and adds NS-01–NS-16.
Those v3 gates are future requirements, not claims about current v2 test results.
Beyond the implemented workflow, independent deferred features include:

- PTY transfer, window relaying, terminal cleanup and unrestricted input.
- Trusted hook execution and strict deadline/output/confidentiality integration.
- Remote TLS collector service, replication/ACK, receipts, durable cursors,
  provisioning anchors and external rollback/checkpoint protection. The
  collector binary currently supplies validation diagnostics only.
- Policy reload with aggregate generation quotas, scripts/reusable grants,
  OpenPGP/Sigstore adapters and safe administrative revocation tooling.
- Complete applicable v2 V-01–V-20 end-to-end cases and real hardware
  signing acceptance before claiming physical security-key support.

Selectable host/container execution domains now have a draft v3 contract and
[gated roadmap](docs/NAMESPACE_AWARE_EXECUTION.md). Source capture, namespace entry,
cgroup placement and enforceable confinement remain release-blocking design gates.
No v2 compatibility layer or automatic state migration is planned; explicit fresh
v3 provisioning must preserve existing state. Interpreter artifact binding remains
separate deferred work.
