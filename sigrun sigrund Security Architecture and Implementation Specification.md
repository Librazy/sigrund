# `sigrun` & `sigrund` Security Architecture and Implementation Specification (v3.0)

This is the **draft normative v3 target contract**, not a description of the
current runtime. One host authority authenticates, prepares, approves and
supervises execution in explicitly selected local environments. Full/thin
provenance, confidential outcomes, executable evidence, durable authorization,
hooks and audit replication remain part of this contract.

The implemented local one-time SSH/stdio runtime is **v2**; see
[implementation notes](IMPLEMENTATION_NOTES.md). This rewrite does not enable
v3 or establish conformance. The [phased roadmap](docs/NAMESPACE_AWARE_EXECUTION.md)
tracks requirements, feasibility gates and release evidence. Requirements marked
NS-01–NS-16 are normative obligations; unresolved mechanisms in Section 8.4 are
release blockers, not permission to weaken those obligations. Schema examples
are draft v3 contracts and must gain independent fixtures before runtime release.

V3 is a clean break. Wire formats, configuration, CLI, signatures, database,
audit/ratchet state and collector contracts may change together. Reject v2 and
other unsupported contracts; provide no compatibility negotiation or automatic
migration. Fresh provisioning requires explicitly selected empty state/log
locations. Never delete or reinterpret existing state. DSSE still uses its
standard v1 PAE encoding; Linux cgroup v2 and Linux file-capability ABI versions
are independent of the application version.

Internal failure names such as `POLICY_VIOLATION`, `REPLAY_DETECTED` and
`SPAWN_FAILED` identify private diagnostics, not authorization statuses on the
requester socket. Section 2.1 is the exhaustive public outcome contract.

---

## 1. Trust Boundaries, Cgroup Initialization, and Admission Control

### 1.1 Explicit Architectural Guarantee Boundaries

`sigrun` and `sigrund` replace PAM and Polkit with a capability-scoped execution architecture over a Unix domain socket (`/run/sigrund.sock`, `0666`, `SOCK_STREAM`). To ensure security claims match what the Linux kernel and external infrastructure can strictly enforce, v3 establishes the following explicit boundaries:

1. **Non-Root vs. Host-Root Cgroup Containment Boundary:**
* **Guaranteed Containment (Explicit Safe Capability Profile):** This guarantee applies only when `target_uid != 0` and the granted capability set is a subset of the enumerated safe profile `{ CAP_NET_BIND_SERVICE }` (including the empty set). Every other capability, including capabilities added by future kernels, is outside this profile. The target UID, primary GID, and supplementary GIDs must confer no authority to migrate processes through host services: the workload must have no usable access to host management sockets, APIs, credentials, or delegated cgroup controls, including systemd, D-Bus policy methods that move PIDs, Docker/containerd/CRI, and equivalent privileged helpers. This excludes access conveyed by filesystem ownership, ACLs, group membership, service authorization policy, passed FDs, or inherited credentials. Deployment policy must establish these access restrictions; a read-only cgroup mount alone does not establish them. Under these conditions, the child runs in a new cgroup namespace (`CLONE_NEWCGROUP`) and mount namespace (`CLONE_NEWNS`) where `/sys/fs/cgroup` is recursively read-only, cannot migrate processes out of `job-<exec_id>` directly or through a host control plane, and all descendants remaining there are torn down via `cgroup.kill`.
* **Best-Effort Containment (Any Execution Outside the Safe Profile or Access Restrictions):** A process running as host UID `0` (even with reduced capabilities and a read-only `/sys/fs/cgroup` mount) retains UID `0` ownership authority over the host filesystem and host IPC sockets (such as `/run/systemd/private` and `/run/dbus/system_bus_socket`). Such a process can request the host `systemd` manager to allocate a transient scope and migrate PIDs out of `job-<exec_id>`. Therefore, for `target_uid == 0`, any capability outside the safe profile, or any usable host control-plane access, initial cgroup placement (`CLONE_INTO_CGROUP`) is enforced, but post-spawn containment and descendant cleanup are **best-effort operational lifecycle management**, not a sandbox against a malicious root process.


2. **Mapped Identity & Process Injection Boundary (NS-05):**
* Requester IDs are host-observed kernel credentials. Target IDs are interpreted
  in the selected user namespace. Equal integers in different user namespaces
  neither prove nor disprove a shared kernel identity or tracing authority.
* Rootless UID 0 is not host root. Evaluate composed UID/GID mappings, userns
  ownership, capabilities, dumpability, ancestry and applicable LSM/Yama rules.
  Reject unmapped/overflow credentials and unsupported nesting; never substitute
  an overflow value or a host account with the same name.
* `allow_same_uid_elevation = false` rejects execution sharing the requester's
  kernel UID. An opt-in requires a verified post-exec process-injection guard
  for the actual destination and executable model. Section 4.2 describes the
  restricted host case; it is not a general rootless recipe. Other namespace
  ownership or capability paths that permit requester injection must also be
  excluded. Unknown injection authority fails closed.

3. **Storage Rollback vs. Live-Memory VM Snapshot Boundary:**
* Local SQLite commits (`PRAGMA synchronous = FULL`) prevent replay of `one_time` grants on an intact local filesystem.
* When `require_remote_audit_ack = true` is enabled, the remote collector's startup checkpoint reconciliation (`AUDIT_REMOTE_CHECKPOINT_MISMATCH`) detects whole-disk rollback on daemon startup, and its durable `(host_id, grant_id)` and `(host_id, payload_sha256)` deduplication prevents **fresh redemption of a `one_time` warrant after a local SQLite database rollback**.
* **Live-memory VM snapshot restoration**—where a hypervisor captures live guest RAM and CPU registers *after* `sigrund` verifies the remote collector's receipt and *before* `clone3()` completes, and later resumes that running state—cannot be detected inside the guest OS. Protecting external targets against duplicate effects from restored live VM memory requires idempotency or fencing tokens at the target service.


4. **Host Clone Detection Boundary:**
* Comparing `/etc/machine-id` and `/sys/class/dmi/id/product_uuid` at startup is a **heuristic safeguard** against accidental unsealed VM templates where the hypervisor assigns a new SMBIOS UUID. It cannot detect a byte-for-byte clone that preserves both SMBIOS UUID and disk state. Provisioning pipelines must seal templates with `sigrundctl seal-template` and initialize unique host keys on first boot with `sigrundctl init-host`.


5. **Script & Dynamic Dependency Boundary:**
* Executable evidence binds only the chosen model's content or version identity;
  ctime is not a content hash. Sealed hashed stdin binds its exact byte stream.
  None of these models authenticate dynamically linked libraries resolved from
  mutable paths, configuration files read after startup, or files sourced by an
  interpreter.

Approval delegates the effects of the complete command, including argv,
environment, input and working directory. A signed shell/interpreter or a
privileged tool accepting caller-selected paths can confer broad authority
despite an authentic executable digest. The cwd is a signed path, not a sealed
directory tree. Operators must review those effects; host UID 0 with an empty
capability set still has ownership-based authority, but does not have every
Linux capability (Section 5.3). Local audit protection has the protected-state
and key-compromise limits in Section 7.2.


The containment classification above is the host baseline. For a namespace target,
classify effective host authority through the verified mapping and access
context, not `target_uid == 0` alone. Rootful container root and mapped rootless
root must be displayed separately from host root. Namespace membership does not
prove inability to escape job placement; the declared profile must establish
that guarantee or explicitly retain best-effort cleanup. A privileged container
already controlling the host, daemon state or management interfaces is outside
the isolation guarantee (NS-01, NS-05, NS-09).

### 1.1.1 Pre-Authorization File Confidentiality

The daemon is not a public privileged stat, hash, or CSR service. The confidentiality
contract applies to raw socket callers as well as the supplied CLI. A full CSR is
prepared under requester privileges and checked through requester-limited
filesystem access before mandator review. A thin CSR is only execution intent;
its privileged expansion and resulting evidence are private to trusted approval
components. Both forms bind exactly the requested intent. A client-provided
label, hash, inode number, or claimed UID is never proof of access.

For an admitted thin request, all unsuccessful authorization paths produce the
same `TIMEOUT` payload at its fixed admission-based deadline, including explicit
mandator refusal. No CSR, evidence, preparation status, reason, early output EOF,
or early release of approval capacity distinguishes those paths. `APPROVED` is
the deliberate disclosure boundary. It permits later execution results/output;
it does not attest that a child has started or will start.

This is a protocol-level confidentiality guarantee, not complete timing or
shared-resource noninterference. CPU load, filesystem/cache behavior, blocked
workers, storage pressure, other host activity, daemon failure and supervisor
shutdown may be observable. Rate/resource controls bound these effects without
claiming to eliminate them. Admission/transport defenses that run before target
inspection may close a connection immediately. Detailed private audit is not
exposed through a requester diagnostics endpoint.

Requester-limited access must be established in the selected destination under
the supported source-access contract (NS-07). UID/GID impersonation alone does
not reproduce requester LSM or Landlock restrictions. A privileged destination
root FD is not proof of requester traversal permission. Unsupported access
domains fail closed for full requests. Readability and required directory search
permission establish file eligibility; requester execute permission is not
required for elevation. Thin expansion is a separate private path, not an access
proof or a fallback that full-only/export may invoke.


### 1.2 Startup Cgroup v2 Initialization & Supervisor Leaf

`sigrund.service` runs under systemd with `Delegate=yes` on a unified cgroup v2 hierarchy (`/sys/fs/cgroup`). Under Linux cgroup v2's no-internal-processes rule, domain controllers (`memory`, `pids`) cannot be enabled in `cgroup.subtree_control` while a process resides directly in that cgroup.

Before opening `/run/sigrund.sock`, `sigrund` executes the following mandatory startup sequence and fails closed (exiting with a fatal error) if any step fails:

1. **Subreaper Registration:** Calls `prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)` so orphaned descendants of this daemon are reparented to it while it remains alive. This does not adopt processes already reparented to PID 1 or another subreaper after an earlier daemon instance died.
2. **Directory Creation:** Resolves and pins its own delegated service cgroup path $G$ before migration (e.g., `/sys/fs/cgroup/system.slice/sigrund.service`), using its cgroup membership and the verified cgroup v2 mount rather than a hardcoded unit name, and creates three subdirectories (`0755 root:root`): $G\text{/supervisor}$, $G\text{/jobs}$, and $G\text{/hooks}$.
   On restart with a retained hierarchy whose domain controllers remain enabled,
   the external supervisor may start the daemon directly in `G/supervisor`.
   Only that exact leaf name permits selecting its immediate parent as `G`:
   startup pins and verifies root-owned, non-writable, no-symlink `G`,
   `supervisor`, `jobs` and `hooks`, requires `G/cgroup.procs` empty,
   the supervisor leaf's `cgroup.subtree_control` empty, and no other process
   in the supervisor leaf. Normal initialization and orphan reconciliation
   still run before listeners. Do not disable controllers to enter `G`, infer
   arbitrary ancestors, or use requester-supplied cgroup/namespace identities.
3. **Daemon Migration to Supervisor Leaf:** Writes its own PID (`getpid()`) to $G\text{/supervisor/cgroup.procs}$, vacating the root of $G$.
4. **Controller Enablement:** Reads $G\text{/cgroup.controllers}$, verifies both `memory` and `pids` are present, and writes `"+memory +pids\n"` sequentially to $G\text{/cgroup.subtree\_control}$, $G\text{/jobs/cgroup.subtree\_control}$, and $G\text{/hooks/cgroup.subtree\_control}$.
5. **Orphan Cleanup from Prior Crashes:** Iterates over any existing `job-*` directories under $G\text{/jobs}$ and `hook-*` directories under $G\text{/hooks}$, writes `"1\n"` to each `cgroup.kill`, waits for `populated 0` in `cgroup.events`, drains only processes that are actually children of the current daemon via the Central Reaper (`waitid(P_ALL, 0, ..., WEXITED | WNOHANG)`), logs an `ORPHAN_CLEANUP` audit entry, and removes the directories via `rmdir()`. Prior-instance processes may already belong to PID 1 or another subreaper; the new daemon can kill their cgroups but cannot generally reap them or recover their exit status. Their current parent is responsible for reaping; cleanup completion requires `populated 0`, not successful `waitid()` for those non-children.
6. **Startup Limit Verification Gate:** Creates $G\text{/hooks/startup-probe}$, writes `"67108864\n"` to `memory.max`, `"0\n"` to `memory.swap.max`, `"1\n"` to `memory.oom.group`, and `"32\n"` to `pids.max`, fails closed if `memory.swap.max` is absent or any write/read-back differs, and reads back each file to confirm the kernel accepted the exact limits, verifies `cgroup.kill` is writable, and removes $G\text{/hooks/startup-probe}$ with `rmdir()`.

### 1.3 Admission Control & Pinned Worker Quotas for Blocking I/O

The coordinator handles bounded nonblocking socket I/O, timers, signals and
owned-result handoffs. All potentially blocking filesystem operations (including
metadata, credential-helper work, reads, closes, cgroup work, SQLite and fsync)
run off-loop. `O_NONBLOCK` does not make regular-file I/O nonblocking, and a
caller can change the flags of a shared open file description. Cancellation
cannot reclaim ownership from an uninterruptible syscall.

Execution admission at `accept4()` captures policy, `t0 = CLOCK_MONOTONIC`, and
`D = t0 + authorization_timeout_ms` with checked arithmetic. Reserve a control
socket, response storage, endpoint-retention capacity and bounded audit slot
before accepting rights. Admission failures close immediately without target
inspection or a per-attempt audit flood. Context-query connections use a separate public listener and
fixed limits (Section 2.1.2), no rights, no target work and no execution deadline.

| Resource | Default / immutable ceiling | Ownership rule |
| --- | --- | --- |
| Execution control sockets, global/per UID | 64/4 | Retain through public outcome or disconnect; no unbounded waiting queue |
| All owned Unix sockets / final-close workers | 128 / 2 | Includes listeners, context, broker, rejected and worker-retained sockets; reserve before accept, release only after actual final close |
| I/O tasks including credential helpers, global/per UID | 16/2 | Metadata, hash, copy and cleanup share the budget; no replacement capacity for blocked tasks |
| Snapshot RAM, global/per UID | 512 MiB/128 MiB | Reserve before allocation; retain until actual descriptor cleanup |
| Memfd executable bytes | 64 MiB | Positive regular source, bounded copying and mutation checks |
| Direct digest bytes | 256 MiB / 1 GiB | Fixed buffer at most 64 KiB; no executable snapshot allocation |
| Hashed stdin bytes | 16 MiB | Reserve maximum before collection, trim to measured size at EOF |
| Initial assembly/preparation deadline | 5000 ms / 5000 ms | `t0 + request_deadline_ms`; an internal stage failure does not advance public timeout |
| Authorization deadline | 120000 ms / 300000 ms | Configurable 1000..300000; absolute `D`, never restarted |
| Direct hashing deadline | 5000 ms / 30000 ms | Assigned once per hash phase, capped by `D` before approval |
| Control-frame assembly/send deadline | 5000 ms | Cumulative per frame; progress never resets it |

Reserve the applicable approval-capacity slot before any target-dependent work
for an unsigned request. A thin request retains that slot until its public
outcome at `D`, successful approval delivery, or requester disconnect, even if
preparation or a mandator already failed. An admitted request unable to reserve
capacity takes the silent-timeout path without target inspection. A full CSR
may release its slot on an explicit visible rejection. Actual resource owners
can outlive the logical reservation after cancellation; their charges are not
refunded until cleanup completes. A separate bounded response owner retains
client-visible endpoints, not a fake free worker or prematurely freed snapshot.

Retain stdout/stderr endpoints without writes, truncation or early EOF before
authorization. Collect finite stdin before private target inspection, then keep
the client's original endpoints alive until the public outcome. Private cleanup
must not close the last observable endpoint early. At `D`, begin the fixed
`TIMEOUT` frame and only then retire endpoints through bounded off-loop cleanup.
Endpoint close is scheduled only after the timeout frame is sent or its fixed send
deadline expires. No syscall scheduling or client backpressure guarantee of exact arrival time is
claimed; deterministic timers must schedule identical failure paths at `D`.

Before/after every at-most-65536-byte read, workers check cancellation and their
captured phase deadline. Stage expiry cancels work and schedules silence until
`D`; it never sends a filesystem-dependent early error. At `D`, the coordinator
can deliver timeout even while a task or commit is blocked. That task retains
all FD, worker, memory and audit ownership and cannot later authorize execution.
Remove sockets from epoll before retirement. Final socket close, including
unread queued rights and listener backlog, uses the reserved disposal workers.
Pause listeners when disposal capacity is exhausted; do not spin or add workers.

### 1.3.1 Request Ownership, Cancellation, and Irreversible Operations

Use an atomic lifecycle/decision state with acquire/release CAS. The coordinator
alone advances requests; workers return owned results and never independently
approve, consume, or spawn. Each completion carries request, policy and phase
identity. Define these states and permitted forward transitions:

```text
ADMITTED -> PREPARING -> [HASHING] -> REVIEWING -> AUTHORIZING
          signed requests skip REVIEWING after signature/static checks
AUTHORIZING -> COMMITTING -> COMMITTED -> APPROVAL_DELIVERY
APPROVAL_DELIVERY -> APPROVED -> SPAWNING -> RUNNING -> FINISHED
any pre-approval failure -> SILENT_TIMEOUT -> TIMED_OUT
validated full-CSR mandator refusal -> REJECTED
requester disconnect -> CANCELLED (with retained operation reconciliation)
```

`SILENT_TIMEOUT` is terminal for authorization: it has no transition back to work,
review, commit or spawn. `REJECTED`, `TIMED_OUT` and `CANCELLED` also cannot revive.
Store a single public decision initially `UNDECIDED`; only a matching CAS may
claim `APPROVED`, `REJECTED`, `TIMEOUT` or non-wire `NO_REPLY`. Rejection of a thin
request atomically enters `SILENT_TIMEOUT`, invalidates its prompt and stops all
remaining mandators. No later signature can override it.

* **Deadline races:** Every pre-approval transition checks `now < D` even if its
  timer has not fired. Initial collection, hashing, hook, broker and collector
  sub-deadlines are capped by `D`. Stale stage callbacks cannot cancel a newer
  phase; the overall deadline remains active until approval delivery starts.
* **Commit reservation:** Recheck policy, expiry, cancellation and deadline before
  reserving `AUTHORIZING -> COMMITTING`, and again before issuing `COMMIT`.
  A prior terminal winner rolls back. A timeout during in-flight persistence may
  claim the public timeout and prohibit spawn without pretending to cancel or
  roll back the syscall. Maintain a separate owned reconciliation record for
  the pending transaction. A late successful commit stays consumed and records
  `AUTH_COMMIT` followed by `AUTH_ABORTED_POST_COMMIT` with no execution. An
  uncertain commit is never retried or refunded automatically.
* **Approval delivery:** Only completed database consumption (when applicable),
  durable local audit and required verified collector ALLOW can enter
  `APPROVAL_DELIVERY`. Check `now < D`, connection and warrant expiry and claim
  `APPROVED` atomically before emitting any decision bytes. This wins against
  timeout. The complete frame must be sent within the independent five-second
  send deadline; partial send or disconnect cancels with no spawn and no second
  decision. Successful delivery transitions to `APPROVED`. Remote receipt or
  audit completion alone never resurrects a timed-out request.
* **Spawn reservation:** Only after complete approval delivery may the coordinator
  recheck expiry/liveness and reserve `APPROVED -> SPAWNING`. Recheck cancellation
  before `clone3()`. If cancellation races an in-flight clone, retain the pending
  context, register the returned PID/pidfd, kill/reap and reconcile. There is no
  authorization timeout after approval; subsequent failures are execution results.
* **Execution and cleanup:** Preserve the Central Reaper registration barrier,
  direct-model exec verification/release reservation and cgroup cleanup. User
  cancellation after approval closes the connection until execution readiness;
  afterward signals follow Section 2.4. Ownership outlives disconnect/shutdown
  until reconciliation and actual cleanup finish.

A `TIMEOUT` means no authorization was delivered and this request will not
execute. It does not prove its one-time grant was never consumed. A transport
failure during approval delivery is an uncertain client observation; never
retry automatically or claim that execution/consumption was impossible.

### 1.3.2 Independent Outcome Delivery and Audit Ownership

Before execution admission reserve one audit slot per request against UID/global
limits, plus bounded response and endpoint-retention storage. Each slot stores
at most one `audit_record_max_bytes` record and fixed metadata. Transfer ownership
exactly once and reuse capacity sequentially; no unbounded event queue is allowed.
A separate diagnostic slot supports aggregated admission-refusal counts.

Private failure processing can occur immediately, but public delivery obeys
Sections 1.3.1 and 2.1. Timeout delivery never waits for SQLite, audit fsync or
blocked cleanup. A late audit result cannot send another decision. A crash can
lose a queued denial record; successful authorization still requires durable
`AUTH_COMMIT` and any configured remote ACK before `APPROVED`.

Retain unresolved commit and outcome owners independently of the socket. Record
internal reason, request origin, intent digest, intended public outcome and
actual delivery status privately. Do not claim a frame was received merely
because a socket write succeeded. No requester endpoint exposes these records.

Exhaustion before admission closes without parsing or target lookup; admitted
resource failures enter `SILENT_TIMEOUT`. Saturating aggregate counters, bounded
UID/window tables and retained leases span policy generations. Fatal persistence
failure stops admission and invokes supervised shutdown; it never permits
execution without durable authorization. The confidentiality guarantee excludes
daemon/supervisor failure and does not require hiding service-wide death.

### 1.4 Normative Daemon Configuration and Policy Generations

`sigrund` reads one canonical TOML configuration at `/etc/sigrund/config.toml` before startup and fails closed on a missing file, unknown key, duplicate key, invalid type, non-canonical path/list, or failed validation. The following schema and defaults are normative; omitted optional keys take the shown default:

```toml
# Identity and authorization
allow_same_uid_elevation = false       # bool
require_remote_audit_ack = false       # bool
csr_allowed_executable_dirs = ["/usr/bin", "/usr/sbin"] # sorted absolute paths
executable_trust_models = ["fs_verity", "ctime", "digest_direct", "digest_memfd"] # ordered, unique, nonempty

# Hook identity and quotas
sigrun_hook_uid = 987                   # example only: dedicated reserved approval UID
sigrun_hook_gid = 987                   # example only: dedicated reserved approval GID
max_active_hooks_per_uid = 1            # positive uint32
max_active_hooks_global = 8             # positive uint32
hook_invocations_per_uid = 5            # positive uint32 per hook_window_secs
hook_window_secs = 60                   # positive uint32
hook_timeout_ms = 25000                 # positive uint32

# Admission and snapshot limits
max_active_sockets_global = 64          # positive uint32
max_active_sockets_per_uid = 4          # positive uint32
max_io_workers_global = 16              # positive uint32
max_io_workers_per_uid = 2              # positive uint32
snapshot_ram_global_bytes = 536870912   # positive uint64
snapshot_ram_per_uid_bytes = 134217728  # positive uint64
max_executable_bytes = 67108864         # positive uint64
max_direct_digest_bytes = 268435456     # positive uint64, <= 1073741824
direct_digest_timeout_ms = 5000        # positive uint32, <= 30000
max_stdin_bytes = 16777216              # positive uint64
request_deadline_ms = 5000              # initial assembly/preparation stage; <= 5000
authorization_timeout_ms = 120000       # uint32, 1000..300000; fixed from admission
request_admissions_global = 256        # uint32, 1..=4096 per admission_window_secs
request_admissions_per_uid = 16        # uint32, 1..=request_admissions_global
admission_window_secs = 60             # uint32, 1..=3600; restart-only
max_pending_audits_global = 128        # uint32, 2..=128, includes one diagnostic slot
max_pending_audits_per_uid = 8          # uint32, 1..=8 and < global limit

# Job cgroups
job_memory_max_bytes = 268435456        # positive finite uint64
job_memory_swap_max_bytes = 0           # finite uint64
job_pids_max = 128                      # positive uint64
shutdown_grace_ms = 10000              # uint32, 1..=60000; restart-only

# Collector (always required and validated; network use requires require_remote_audit_ack=true)
collector_base_url = "https://collector.example.invalid" # absolute https URL, no fragment/userinfo
collector_server_name = "collector.example.invalid"      # ASCII DNS name, <=255 bytes
collector_ca_file = "/etc/sigrund/collector-ca.pem"     # absolute regular root-owned path
collector_client_cert_file = "/etc/sigrund/collector-client.crt"
collector_client_key_file = "/etc/sigrund/collector-client.key"
collector_key_id = "collector-v1"                        # ASCII 1..=128 bytes
collector_public_key = "<strict-padded-base64-32-byte-ed25519-key>"
collector_rpc_timeout_ms = 3000                           # positive uint32

# Audit and path policy
audit_record_max_bytes = 65536          # fixed; may not be increased
audit_log_high_water_bytes = 1073741824 # positive uint64; >= audit_record_max_bytes
audit_min_free_bytes = 67108864         # positive uint64; >= audit_record_max_bytes
max_onetime_window_secs = 3600          # positive uint64
max_ttl_secs = 31536000                  # positive uint64, checked timestamp arithmetic ceiling

```

`csr_allowed_executable_dirs` is a sorted, duplicate-free list of absolute directory paths that are neither `/` nor descendants with `.`/`..`/empty components. Every `[[signers]]` entry must contain an exactly equal canonical list in `allowed_executable_dirs`; a signer list that differs, is broader, or is absent rejects the complete configuration. For the host target, the daemon pins these roots per policy generation; for other targets, it pins the same destination-relative policy roots during private preparation against the retained instance. Root FDs are scoped to both target and policy generation, never reused by pathname across destinations. `collector_base_url`, TLS files, key ID, and public key are required and validated for every configuration generation, even when remote ACK is disabled; network use is disabled in that mode. Hook UID/GID, all quotas, and job limits are root-controlled configuration and cannot be raised by warrants. The host must expose a writable `memory.swap.max` file in the delegated hierarchy; `job_memory_swap_max_bytes` may be zero or a finite nonnegative value and is written/read back on every startup probe and job cgroup. Missing swap control is a startup failure. `max`/unlimited values are rejected.

The following are immutable protocol/security ceilings, not freely adjustable limits: frame payload maxima and JSON structural limits in Section 2.1.1; `max_active_sockets_global/per_uid <= 64/4`; `max_io_workers_global/per_uid <= 16/2`; total owned Unix sockets `<= 128` with exactly `2` fixed final-close workers; `request_deadline_ms <= 5000`; `authorization_timeout_ms` in `1000..300000`; `snapshot_ram_global_bytes <= 536870912` and `snapshot_ram_per_uid_bytes <= 134217728`; `max_executable_bytes <= 67108864`; `max_stdin_bytes <= 16777216`; `hook_timeout_ms <= 25000`; `collector_rpc_timeout_ms <= 3000`; control-frame assembly/send deadlines remain the immutable `5000 ms` protocol deadline; `audit_record_max_bytes == 65536`; and finite numeric/identifier bounds in Section 3.5. Admission counters, audit reservations and storage/shutdown controls follow the process-wide rules below; their stated maxima are immutable. All other listed numeric values are captured from the policy generation at request admission and used consistently for that request, hook pipeline, RPC, snapshots, and job cgroup. A lower value may reduce availability or resource consumption; no reload or warrant may exceed a ceiling.

A successful `SIGHUP` parses and validates a complete replacement, checks all signer/root relationships and filesystem identities, then atomically installs it with a new monotonically increasing `policy_generation`. Existing requests retain the generation, signer ceilings, root FDs, hook identity, quotas, collector settings, and job limits captured at admission; a reload never mutates an active job or hook. New requests use only the new generation. Failed reloads leave the prior generation active and emit an audit diagnostic without changing authorization policy. A restart repeats full validation before opening the socket. Security-sensitive keys cannot be changed by partial file edits or per-request fields.

Resource accounting spans all live policy generations. Admission checks the
aggregate global/per-UID sockets, workers and snapshot bytes against the new
request's captured limits and the immutable ceilings. Lowering a limit does
not evict existing owners, but blocks new reservations until aggregate usage
permits them. Reload cannot create replacement capacity for pinned old workers.
Admission rates use fixed windows of `admission_window_secs` measured with
`CLOCK_MONOTONIC` from daemon startup, shared by every requester UID and policy
generation. Before parsing or receiving rights, atomically check the active
socket limits, global/per-UID window counts and audit reservation capacity.
Only a successful admission increments both counters; charges are not refunded
on disconnect or early rejection. Excess connections close immediately and
never reach snapshots or signature verification. Window boundaries can admit
a burst on each side; concurrency and retained-ownership limits still apply.
Keep at most 4096 per-UID counter entries (the immutable global window ceiling);
refuse a new UID if no entry is available. Clear expired window counters;
resource leases live separately and are never cleared by a window rollover.
Context-query counters use the separate immutable limits in Section 2.1.2 and
share only bounded socket/disposal ownership. The root-only broker retains its
separate connection/pipeline limits and
cannot create unbounded diagnostics through repeated reconnects.

Reload preserves the current window's counts and all pending-audit charges.
New admission uses the new limits against aggregate usage; lowering them
blocks new owners without evicting existing ones. `admission_window_secs` and
`shutdown_grace_ms` changes require restart and reject an attempted reload.
The latest validated storage thresholds govern new authorization admission
process-wide; they do not rewrite an active job's limits. All counters, byte
reservations and deadline arithmetic are checked for overflow and fail closed.
These rate controls bound work per window, not cumulative disk usage or
fairness against an attacker exhausting the global window. Section 7.2.1
provides the independent disk-pressure gate.

The optional restricted local approval profile is defined in Section 6.3;
it disables reload and does not relax the startup, descriptor or execution gates.

### 1.5 Execution Environments, Source Identity, and Target Acquisition

**NS-01 — Local authority and deployment.** All routes use one host daemon for
policy, root-TTY approval, durable authorization and supervision:

| Route | Source | Destination | Account interpretation |
| --- | --- | --- | --- |
| 0 | Host | Existing container B | In B |
| 1 | Container A | Host | Host account |
| 2 | Container A | Its own supported environment | In that environment |
| 3 | Container A | Existing container B | In B |

Execution is local; no remote-host or delegated proxy authentication is implied.
Operators expose the client socket and its `.context` companion with their path
relationship intact. No socket injection, container modification or container
creation is performed. Approval sockets, state and management credentials stay
host-controlled. DAC and SELinux/AppArmor must permit connection; reachability
only permits submission. Mapping a source container account into a host account
is a separate deferred selection mode.

**NS-02 — Authenticated source contract.** The baseline attributes requests to
kernel-authenticated connection credentials (`SO_PEERCRED`, `SO_PEERGROUPS`) as
observed by the host daemon. Credentials are captured at connection time; an
inherited or passed socket does not establish the identity of its later writer.
This baseline is explicit connector attribution, not per-message authentication.
Caller usernames, namespace IDs and runtime labels are untrusted claims.

Capture applicable `SO_PEERSEC` and process attributes with their observation
source/time in private audit; socket security attributes are not complete live
process confinement. Validate UID/GID mappings and overflow/unmapped results.
`self` requires a stronger, race-checked acquisition contract tying the selected
environment to the authenticated source. Before enabling it, Phase 0 must choose
and specify connector capture or authenticated message-sender attribution,
including inherited/passed sockets, connector exit, exec, credential and
namespace changes. Reading procfs for a connection-time PID later is insufficient.
No undocumented per-message authentication is inferred from the existing stream.

**NS-03 — Selection is not authority.** Distinguish:

| Object | Meaning |
| --- | --- |
| Selector | Host, self, administrator registration, or explicitly scoped process reference; optional resolvers supply manager names |
| Pinned target | Daemon-owned process reference, namespace FDs, root FD, verified mapping/context observations and lifecycle lease |
| Signed target binding | Daemon epoch and instance ID bound to the retained context and verified display description |
| Manager identity | Optional additional scoped evidence, never a replacement for resource validation |

Host means the daemon's configured execution environment. Self means the
supported authenticated caller environment, including allowed unshares; it need
not be the manager's original container. Explicit process PIDs are interpreted
in the daemon's PID namespace, never guessed from caller-visible numbers.
A process reference authorizes nothing. Names, PIDs, namespace inodes, cgroup
paths, image digests and runtime IDs are each insufficient instance identities.
Shared namespaces do not identify a unique container.

**NS-04 — Acquisition, revalidation and invalidation.** Resolve and pin before
review; revalidate before final authorization, before spawn, and before releasing
execution. Acquire a retained process reference (pidfd where supported), pinned
proc reference, namespace/root FDs, ownership relationships and mapping evidence
under one documented race-resistant acquisition contract. Protect lookup against
PID reuse and mixed observations. Repeated procfs reads alone do not prove an
atomic capture or detect change-and-restore races. Unsupported acquisitions fail
closed; the Phase 0 gate must prove the supported mechanism.

Keep a private bounded instance registry scoped to a fresh daemon epoch. IDs
without retained resources provide no authority. Reject on anchor exit,
inconsistent or changed relevant context, or lost required lifecycle evidence.
Never reacquire a matching name/PID to replace an approved target. Namespace FDs
can outlive an instance and are not liveness proof. Daemon restart invalidates
all ephemeral bindings, including otherwise unexpired warrants. The host target
also receives an epoch-scoped binding. Manager-free bindings identify a validated
process environment, not a universal container generation.

**NS-06 — Destination ownership and policy.** Host policy must authorize the
requester, target registration/scope, target credentials, security constraints and
signer independently of container ownership. Cross-owner execution is neither
implicitly allowed nor categorically forbidden. Signer keys and runtime socket
access cannot override daemon policy. User-owned manager metadata cannot grant
host privileges or arbitrary namespace entry. Registration, revocation and
profile management use host-administrator interfaces; no requester-facing
existence/lookup service may bypass thin-request confidentiality.

**NS-13 — Optional manager resolvers.** Scope manager identities by endpoint,
owner/tenant and manager namespace. Validate returned process resources with the
same acquisition and policy gates as explicit targets. Manager metadata supplies
additional identity/configuration/lifecycle evidence; it cannot independently
authorize host privilege. Bind required resolver evidence and define loss/restart
behavior. Native runtime IDs may outlive execution generations. Exact manager
exec semantics require separately validated configuration integration; neither
OCI state nor direct runc/crun invocation supplies that equivalence automatically.

### 1.6 Target and Security Policy Configuration

Target registrations and named security profiles are root-controlled policy,
validated as a complete generation. Unknown targets/profiles are denied privately.
Numeric target UID/GID/group ceilings apply within explicitly allowed target
scopes; never treat a flat numeric allowlist as permission for every namespace.
Approved constraints are immutable bytes or content-addressed versions, not a
mutable profile name. Removal/revocation invalidates pending authorization;
changed policy cannot silently expand an existing grant. Captured generations
retain resource limits, but do not bypass mandatory revocation or LSM-policy
revalidation.

The base configuration in Section 1.4 remains applicable. Phase 0 must specify
bounded registration/profile schemas, management CLI, revocation and dependency
metadata before those interfaces ship. The syntax is not inferred from the
conceptual examples in the roadmap. Aggregate quotas must include pinned target
FDs, registrations, helpers, launcher processes, pending review and cleanup;
Phase 1 must supply concrete limits and exhaustion tests within the existing
admission ceilings. Cancellation releases a reservation only after actual cleanup.

The backend is a native Linux namespace executor. Manager APIs are optional
resolvers, not universal execution backends. Direct runc/crun access underneath
a manager is not supported as a generic control plane. OCI supplies useful
configuration vocabulary, not globally unique identity or automatic inheritance
of manager execution policy (NS-13).

## 2. Wire Protocol, Request Shapes, and Job Lifecycle

The [Phase 0 contract supplement](docs/NAMESPACE_PHASE0.md) fixes the initial
constrained-anchor source-attribution mechanism, bounded private acquisition and
constraint records, target-scoped policy/management grammar, binding distribution
and quota defaults. Its experimental validators and fixtures are the concrete
draft schema reference for the initial profile. These are not production v2
interfaces. Unsupported combinations and the concurrent-SELinux-policy-replacement
limitation remain blocked; later runtime gates must implement and validate the
same contracts before issuing bindings or making support claims.

### 2.1 Binary Framing & Public Outcome Contract

Use the existing five-byte framing: one type byte, then a four-byte unsigned
big-endian payload length, then exactly that many UTF-8 JSON bytes. V3 request
objects explicitly contain `version: "3.0"`; legacy shapes are not negotiated.
Unknown fields, duplicates and extra frames are rejected. Application signing
and state versions are independently enforced.

| Type | Direction / legal state | Maximum payload | Rights |
| --- | --- | --- | --- |
| `0x01 CLIENT_HELLO` | Client, first execution frame | 524288 | Exactly the Section 2.3 set |
| `0x02 SERVER_AUTH_DECISION` | Server, once before execution | 1024 | None |
| `0x03 CLIENT_SIGNAL` | Client, after execution readiness | 64 | None |
| `0x04 CLIENT_WINSIZE` | Client, after PTY readiness | 128 | None |
| `0x05 SERVER_EXEC_RESULT` | Server, once after APPROVED | 1024 | None |
| `0x06 CLIENT_CONTEXT_QUERY` | Client, first frame on separate connection | 64 | None |
| `0x07 SERVER_CONTEXT` | Server, only response to context query | 16384 | None |
| `0x08 SERVER_EXEC_READY` | Server, at most once after APPROVED | 1024 | One PTY master only for PTY |

A decision has exactly `exec_id` (daemon-generated UUIDv7 at admission) and
`status`, with no free-form message, reason, signature, CSR or evidence:

```json
{"exec_id":"0192d8f4-9a00-7000-8000-112233445566","status":"APPROVED"}
```

| Submission | APPROVED | REJECTED | TIMEOUT |
| --- | --- | --- | --- |
| `full_csr` | Verified, durably authorized | Only explicit refusal by a mandator after successful full validation | All other pre-approval failures/no outcome |
| `thin_csr` | Verified, durably authorized after private expansion | Never | Every unsuccessful pre-approval path, including explicit refusal |
| `signed` | Verified v3 client-full warrant, durably authorized | Never (no mandator consulted) | Invalid/expired/revoked/replayed warrant or any other pre-approval failure |

`TIMEOUT` is scheduled at the fixed admission-based deadline; no intermediate
status is sent. A syntactically plausible full CSR does not earn a rejection
channel: requester-access validation and exact evidence verification must pass
before it reaches a mandator. Semantic/schema errors in a complete bounded
execution frame also take the silent timeout path. Before target inspection,
transport faults (bad type/length, incomplete frame, invalid ancillary layout,
unsupported wire version) may close immediately with no auth decision. Service
shutdown/crash and requester disconnect are transport events, not hidden rejection
statuses. Never return internal errors as alternative authorization statuses.

`APPROVED` acknowledges completed authorization and consumption when applicable,
not setup or exec success. Send it completely before spawning or target output.
`SERVER_EXEC_READY` has exactly `exec_id` and `exec_outcome`, either `unknown`
(setup handshake without a required checkpoint) or `exec_event_observed`
(verified and released exec stop, including memfd when required by its profile).
It does not repeat authorization. Failure before readiness still produces an
execution result after the original approval.

`SERVER_EXEC_RESULT` has exactly `exec_id`, `status`, `exit_code`, and `signal`.
For `status: "EXITED"`, exactly one of `exit_code` (0..255) and `signal` (1..64)
is non-null. For `SETUP_FAILED`, `EXEC_FAILED` or `CANCELLED`, both are null;
private audit retains errno and details. Emit once after owned-job cleanup,
including when no child was created. Stop/continue notifications are not results.
Checkpoint failures for any model are `EXEC_FAILED`; unchecked memfd's unknown-exec distinction
is retained (Section 2.4).

`sigrun --status-fd` writes each decision/readiness/result payload as JSONL,
separate from command output and descriptor aliases. It exits 255 (or configured
`--auth-fail-exit-code`) for rejection/timeout, child status or `128 + signal`
for EXITED, 254 for non-EXITED execution failure or transport failure, and 64 for
local usage errors. Relay output after APPROVED, even before readiness, but send
signals/resize only after readiness. Drain output through EOF after a result.
On disconnect restore the terminal and report a local transport error; never
invent a remote timeout or retry automatically. No v3 decision contains a CSR.

### 2.1.1 Bounds, Frame Deadlines, and Transport Failure

Validate type/direction/state before length, and length before allocation or
payload reads. Reject zero/oversized lengths without draining or resynchronizing.
Bound storage to one frame plus its header. Initial assembly and every later
partial frame have a cumulative five-second deadline from the first byte;
initial assembly is additionally bounded by `t0 + request_deadline_ms` and `D`.
Send deadlines are likewise five seconds; short reads/writes never reset them.
Idle waiting for authorization or child exit does not start a partial-frame timer.

Decode strict JSON with maximum depth 8, arrays 256, maps/environment 128, and
ordinary strings 4096 UTF-8 bytes. Canonical CSR/warrant bytes are at most 65536;
`csr_payload` allows 65536 decoded bytes, DSSE `payload` 87384 Base64 characters,
each signature 32768 Base64 characters and key ID 128 ASCII characters. Wire
payload bounds include escaping/envelopes; satisfying an inner limit alone is
insufficient. All integer/Unicode checks in Sections 3.3–3.5 apply.

Transport faults close all actually received rights via off-loop owners; no
resynchronization or target lookup follows. A well-framed but invalid request
retains response endpoints for silent timeout. A post-approval protocol failure
starts job teardown and sends no second auth decision. Cancellation of blocked
work retains all quotas. A sender unable to serialize a bounded response closes
rather than emitting a partial alternative outcome.

### 2.1.2 Target-Independent Public Context

Use a separate root-owned 0666 context socket whose pathname is the execution
socket pathname plus `.context` (for example `/run/sigrund.sock.context`). Both
client and daemon derive it from their configured execution socket path; startup
checks the resulting Unix-socket path bound and trusted parent. Publish it only
after the same startup/recovery gates as the execution listener. On this socket
send exactly `{"version":"3.0"}` as `CLIENT_CONTEXT_QUERY`. The daemon accepts no path, intent or rights and performs
no request-dependent filesystem inspection. Authenticate the daemon through its
trusted socket location and root peer credentials. Context queries do not consume
approval slots or execution-request rate counters. Limit them to 8 active global,
2 per UID, and 64 global/8 per UID per existing admission window; these fixed
ceilings share the total Unix-socket disposal budget. Assemble/send within five
seconds, then close; no second query/submission is allowed on that connection. The context listener
rejects execution frames; the execution listener rejects context frames before
any target work. The separate listener makes admission accounting unambiguous.

`SERVER_CONTEXT` has exactly `version`, `host_id`, `policy_generation`,
`executable_trust_models`, `limits`, and `features`. `limits` has exactly
`max_executable_bytes`, `max_direct_digest_bytes`, `direct_digest_timeout_ms`,
`max_stdin_bytes`, `max_ttl_secs`, `max_onetime_window_secs`, and
`authorization_timeout_ms`, with captured configuration values. `features` has
exactly `direct_exec_checkpoint`, `host_file_capabilities` (booleans), and
`tty_modes`, `stdin_policies`, `grant_modes` (bounded arrays of supported enum
strings). Publish only startup-probed/configured support, never target-specific
eligibility, signer lists, secrets or private paths. Model order is authoritative
for unsigned selection; actual policy and limits are captured afresh at submission.

Context is advisory preparation input, not authorization or a policy lease.
A stale context can cause timeout; it must not cause the daemon to rewrite a CSR
or silently select another model. A client may retain context for offline full
CSR preparation, but submission always revalidates against current captured policy.

### 2.2 Full CSR, Thin CSR, and Signed Submissions

A complete canonical **intent** has exactly `command`, `execution_context`,
`policy`, `caller_env`, `target`, `account`, and `security_profile`. Its command has `allow_interpreted_script`, `argv`,
`cwd`, `executable_path`, `stdin_policy`, and `tty_mode`. Its execution context
has `capabilities`, `env_exact`, `caller_env_allowlist`, and `umask`.
`account` selects either destination numeric UID/GID/supplementary groups or a
destination account name; the resolved credentials belong to the warrant
execution context. Section 3.2.1 defines these additional selection fields.
Its policy has `mode` and `ttl_secs`.
These fields retain Sections 2.3 and 4.2 bounds; requested capabilities are an
authority ceiling, not a claim about the final kernel sets.

All hello objects have exactly the common keys `version`, `mode`, `tty_mode`,
`caller_env` plus the single mode-specific key below; no mixed forms are accepted:

| `mode` | Additional key | Content |
| --- | --- | --- |
| `full_csr` | `csr_payload` | Canonical full v3 CSR as a UTF-8 JSON string |
| `thin_csr` | `intent` | The complete intent object; no fabricated executable evidence |
| `signed` | `dsse_envelope` | V3 envelope with a client-full warrant; no unsigned overrides |

Hello `tty_mode` and `caller_env` must exactly equal the corresponding intent or
warrant values. Thin requests have no complete CSR at submission; full CSRs use
the complete v3 warrant schema (Section 3.2) without signatures. Full CSR and
signed modes require `request_origin: "client_full"` and `approval_exec_id: null`.
A standalone signed `daemon_expanded_thin` warrant is always refused without
lookup; it is valid only as the broker/hook response for its active thin request.

`sigrun` obtains target-independent public context and preserves exact intent
and finite stdin. In a supported full-access domain it attempts unprivileged
destination preparation. Cross-domain workflows provide an explicit thin-intent
path; a client must not hash its local same-named executable as destination evidence. It generates a CSPRNG UUIDv7 grant ID,
uses local realtime for validity, and binds host identity and its own UID/GID;
the daemon checks these against authenticated identity and time/policy. Walk the
enabled trust models in order. Conclusively ineligible models permit the next;
an inaccessible observation or inability to construct complete evidence/profile
triggers automatic thin fallback, not invented evidence or guessed eligibility.
Requester execute permission is not required. Local diagnostics identify fallback
without reporting any daemon-derived information. `--full-only` forbids fallback.

V3 `sigrun --export-csr PATH -- ...` prepares and exports a full canonical CSR
without execution submission (and implies full-only). It may query public context;
it never requests privileged expansion. Offline `sigrundctl csr-pae --csr PATH`
and `pack-warrant` consume those bytes, sign/package without rewriting fields,
and refuse overwrites. Thin requests have no export/redemption path. These are
v3 target semantics; runnable v2 commands remain documented in implementation
notes. Full preparation/export requires an already trustworthy destination
binding obtainable without privileged public target discovery (NS-07).

### 2.2.1 Preparation, Access Validation, and Exact Binding

1. **Admission and static checks:** Capture policy/identity and identify the
   bounded submission mode. Reserve review capacity for unsigned requests before
   semantic/static policy checks; an identified thin request retains that
   reservation even if those checks fail. Enforce bounded syntax,
   host/requester/target/grant compatibility and lexical executable-root
   eligibility before target access. Check that at least one candidate signer
   independently satisfies static ceilings (the configured signer for local
   approval); no configured signer means no target work. Signed submissions first
   verify signatures, origin,
   host, peer, validity and static signer policy before privileged preparation.
2. **Finite stdin first:** `sigrun` captures finite input once into a bounded
   immutable local spool before computing a full CSR or falling back. Pass that
   same spool for either mode. Raw clients may pass the Section 2.3 finite source;
   the daemon validates, copies, hashes and seals it before any private executable
   inspection, retaining the original observable endpoints until outcome. Full
   and signed requests must match their claimed stdin hash; thin expansion adds
   the measured hash. Null input uses verified `/dev/null`; future unrestricted
   input remains explicitly unbound. No failure retries or rereads a pipe.
3. **Full-CSR access helper:** Capture kernel-authenticated UID/GID and supplementary
   groups from `SO_PEERCRED`/`SO_PEERGROUPS`; client JSON and account-database group
   reconstruction are not evidence. If unavailable or unmappable, fail closed.
   Use a dedicated isolated process with those credentials, cleared capabilities
   and `no_new_privs`, never process-wide credential changes in daemon threads.
   Make the helper non-dumpable after dropping credentials, keep it protected from
   same-UID tracing/injection through completion, and do not exec again in a way
   that resets that protection. Give it only the starting root, private result
   channel and required request data; never inherited secrets or privileged
   directory handles beneath `/`. Bind returned FDs/results to its reserved task.
   A caller running as the helper UID must not be able to fabricate its result.
   Do not replace the requester's authenticated groups with the requested target
   groups, and do not grant the helper authority from the requested capability set.
   Resolve from the validated destination `/` under the supported requester
   access contract (NS-07), with no symlinks
   or magic links, including every ancestor of the selected root. Check that the
   requester-opened root matches the target/generation's pinned device/inode, then apply
   the relative no-cross-mount resolution in Section 4.2. A privileged root FD
   alone cannot establish traversal permission. Require a readable regular source
   and retain its opened FD. Do not use an `access()`-then-privileged-reopen pattern.
4. **Full verification:** Through that retained source independently verify the
   exact proposed model, evidence, stdin commitment, intent hash and expected
   capability sets, within bounded worker/deadline rules. Kernel support and
   trust-model eligibility must hold in the destination; daemon startup context
   alone cannot establish either destination compatibility or requester access. Check ordering/eligibility under captured policy. An invalid full CSR
   silently times out without mandator delivery or automatic expansion. The
   mandator receives the exact client CSR bytes only after all checks succeed.
   An unsigned full CSR may select a different eligible model from the daemon
   default if that exact model and evidence validate under destination policy;
   preference order alone is not grounds to rewrite the CSR. A change requiring
   new bytes requires a new request, never silent privileged expansion.
5. **Thin expansion:** With root authority resolve only beneath the selected
   pinned root using Section 4.2. Choose the first eligible enabled model and
   retain its snapshot/source. Derive the exact post-exec profile. Generate grant
   ID, authenticated host/peer identity and bounded validity; add measured input
   and executable evidence. Set `request_origin: "daemon_expanded_thin"`, the
   canonical intent hash and the active `approval_exec_id`. Preserve every intent
   field, including argv, cwd, environment, target authority and requested TTL.
   Any error enters silent timeout without mandator delivery. Neither partial nor
   completed CSR is ever returned to the requester.
6. **Evidence ownership:** Memfd sources must be regular, positive and within
   bounds; reserve RAM, copy in chunks at most 65536, require EOF at the original
   size and unchanged final size, hash the copied bytes and require ELF magic
   when scripts are disabled. Apply root ownership and mode 0111 (0555 only for
   explicitly permitted scripts); install/read back all five seals. Direct
   sources follow Section 2.2.2. No source path is reopened to repair changed
   evidence after review; a permitted child capability alias must identify the
   same retained inode. Finite stdin has mode 0400 and the same seals.
7. **Review and authorization:** Only a successfully completed/verified CSR
   reaches trusted approval components. Returned signatures must bind every
   canonical byte, including provenance and active-request binding. Thin grants
   are one-time and online-only even when reusable full grants are enabled.
   Apply all final signature, policy, evidence, revocation and expiry gates to
   retained objects before consumption. No approval refreshes validity or permits
   model substitution. Direct evidence is rechecked at the existing exec stop.

**NS-07 — Destination preparation and access domains.** Preparation runs in a
dedicated bounded helper against the pinned target. Resolve executable roots,
accounts, cwd and execution inputs there; do not inherit a container cwd for a
host request or copy caller files implicitly. Numeric identities must map in
the validated destination. Account lookup is bounded and cannot invoke arbitrary
destination NSS code with host privilege. Initial support uses explicit numeric
credentials or bounded destination account-file parsing; other backends require
a separate validated helper profile. Bind both original account selection and
resolved numeric credentials/mapping context; later account changes cannot
redirect an approval.

The destination helper receives only required resources and bounded IPC, never
daemon secrets, management sockets or unrelated directory handles. Retain the
executable and immutable stdin before review. Sign cwd as a destination path;
a retained cwd FD/final-context check must prevent accidental use of a different
execution domain, without claiming an immutable directory tree. Full access must
account for applicable source confinement and mappings. If that cannot be proven,
reject full/full-only/export; privileged thin expansion is not requester evidence.
The public context endpoint stays target-independent and returns no instance,
account or private profile inventory.

**NS-08 — Evidence negotiation.** Eligibility and unsigned-model reconciliation
are destination-local, including cloned ComposeFS mounts and `PrivateMounts=`.
An enrolled host mount ID or matching pathname does not identify destination
bytes. Bind retained evidence, exact model, source-access result and resolved
credentials together. Preserve submitted intent and full/thin provenance.
Already signed bytes, model, target and constraints cannot switch or downgrade
on mismatch. Mutable scripts, loaders, libraries and configuration remain outside
executable evidence; see [interpreter guidance](docs/PRIVILEGED_INTERPRETERS.md).


### 2.2.2 Configurable Executable Trust Models (v3)

All four models use the v3 tagged `command.executable_trust` representation.
Only `digest_memfd` copies executable bytes into a sealed memfd. Hashed stdin
retains its separate sealing contract. Legacy warrant formats are rejected.

**Selection.** `executable_trust_models` is an ordered, nonempty, unique list,
defaulting to `["fs_verity", "ctime", "digest_direct", "digest_memfd"]`. Capture
this policy with each admitted request. Full-CSR preparation and thin expansion select the first
eligible enabled model before approval under Section 2.2.1. Missing kernel support, unsupported
filesystems/metadata and candidate size limits allow selection of the next
model. I/O errors and changed observations reject. Completed full CSRs and signed warrants require their
specific model to remain enabled and eligible; never downgrade, rewrite or resnapshot.

**Common direct eligibility.** Resolve a positive-size regular ELF through the
pinned-root `openat2` algorithm and retain that source FD through cleanup.
Require ordinary target UID/GID/supplementary-group execute permission, including
UID 0 under `SECBIT_NOROOT`, no setuid/setgid bits or extended access ACL, and an
executable source mount (`!ST_NOEXEC`). All direct models require the probed
ptrace checkpoint and the daemon's effective `CAP_SYS_PTRACE` for inspection
after child credential changes. Unsupported sources can use enabled memfd fallback before
approval. Source inspection, fixed-buffer hashing, verity ioctls and descriptor
cleanup run on reserved workers. Direct execution preserves the source inode
and normal `/proc/self/exe` behavior; this does not promise an unchanged pathname
after rename/unlink or integrity of the loader, shared libraries or other inputs.

| Model | Signed executable evidence | Before durable consumption | At exec stop |
| --- | --- | --- | --- |
| `fs_verity` | Kernel verity algorithm and descriptor measurement | Remeasure and recheck eligibility/expected credentials | Same inode, verity measurement, eligibility and exact credentials |
| `ctime` | Device, inode, size, ctime seconds and nanoseconds; online approval only | Same version, root-managed eligibility and uninterrupted read lease from before approval | Same version, inode, eligibility and exact credentials; hand off intact lease to kernel executable write exclusion |
| `digest_direct` | Full-file SHA-256 | Recheck eligibility; rehash if the internal version fingerprint changed | Same inode, mandatory full-file hash, eligibility and exact credentials |
| `digest_memfd` | Typed full-file `sha256` | Verify sealed snapshot and existing bounds | Existing untraced exec path |

Ownership, mode, raw capability xattrs, ACLs and mount attributes are not separate
signed fields. They are re-read when determining eligibility and the resulting
credential profile. Ctime's signed version implicitly rejects changes to those
inode attributes. Every direct model repeats eligibility before consumption and
at the checkpoint, because fs-verity alone does not protect execution metadata.

**fs-verity.** Admit ext-family, F2FS and Btrfs with successful
`FS_IOC_MEASURE_VERITY`. `ENODATA`, `ENOTTY`, `EOPNOTSUPP` mean unavailable.
Support SHA-256/32-byte and SHA-512/64-byte measurements. Sign the kernel's verity
descriptor digest, not a hash of the file byte stream. Never enable verity on
behalf of a requester. Kernel verified paging supplies immutable content;
the checkpoint still checks mutable metadata and the credential transition.

**ctime.** Trust root maintenance and local timestamp semantics. Require root
ownership, no group/other write permissions and the common execution-metadata
checks. Admit only ext-family, F2FS, Btrfs, XFS and tmpfs. Sign device, inode and
size as canonical unsigned decimal strings (inode/size positive, size at most
`i64::MAX`), and ctime as nonnegative bounded seconds plus nanoseconds below one
billion. Updates require fresh approval. This is a version check, not a content
signature or protection against malicious privileged timestamp manipulation.

Ctime is available only for online approval. Client evidence is tentative;
equality with the client's earlier byte observation is best effort. The required
content-integrity interval begins before the mandator signs and ends at the
verified exec checkpoint. Before requesting approval, the daemon acquires
`F_SETLEASE(F_RDLCK)` on the retained source. Retry contention every 10 ms for at
most 250 ms, checking cancellation and the request deadline. Unsupported leasing
or exhausted contention makes this candidate unavailable before approval;
completed full CSRs cannot change their selected model.

Under the lease, bracket `fsync` with `statx(AT_EMPTY_PATH | AT_STATX_FORCE_SYNC)`
and require identical device/inode/size/ctime, rechecked eligibility and an intact
read lease. I/O failures, inconsistent observations and late results reject.
These operations run on the reserved worker; the deadline cannot forcibly
interrupt a blocked filesystem syscall. Fsync does not reconstruct historical
mapped writes and is not the source of the integrity guarantee.

Keep the same lease through approval, authorization and launch. Consume SIGIO as
a wakeup through the daemon's signalfd, and use `F_GETLEASE` to detect pending
breaks and forced revocation independently of notification delivery. Any break,
loss or query failure irreversibly invalidates the attempt, even without changed
bytes; never reacquire a lease for that approval. After all exec-stop inode,
evidence, eligibility and credential checks succeed, release the lease on the
worker and hand protection to the loaded inode's kernel executable write
exclusion before allowing target instructions. Existing cleanup and durable
consumption rules apply. Administrative writers may interrupt approval.

Offline CSR export skips ctime while preserving the remaining configured model
order. Reject ctime warrants on the pre-signed redemption endpoint, including
older warrants and separately resubmitted online approvals. No protected offline
signing session is provided.

**digest_direct.** Admit only ext-family, F2FS, Btrfs, XFS and tmpfs, whose Linux
executable write exclusion makes a full hash at the exec stop authoritative.
Remote, FUSE, generic overlay and unknown filesystems are ineligible. The
administrator-maintained OSTree ComposeFS exception below is enabled by default. Hash the retained
source with a buffer of at most 64 KiB; never allocate an executable snapshot.
Sign the full-file SHA-256. An internal dev/inode/size/ctime fingerprint permits
skipping unchanged pre-consumption rehashes; it is not signed and never replaces
the mandatory post-exec hash. Reject mutation during hashing. Kernel exec fails
with an outstanding writer; the stopped loaded inode cannot be ordinarily
modified before release. Privileged kernel/filesystem bypass is out of scope.

**Administrator-maintained ComposeFS exception.**
`[digest_direct].allow_admin_trusted_composefs` defaults to true. False disables
this exception. Scope remains limited by the executable directory allowlists.
Qualify only the host's booted read-only OSTree ComposeFS root, with the expected
single metadata lower/data-only object-store arrangement and no writable upper,
workdir, userxattr or unknown mount options. Require initial user identity
mapping and the host PID 1 user/mount namespaces during daemon discovery.
Identify the root using its descriptor's mount ID; preserve that root and the
backing-store descriptor for the lifetime of enrollment. Require root ownership,
no group/other writes or extended access/default ACLs on all backing-store
ancestors, directories and regular objects; reject nested mounts and unsupported
storage. Scan without following symlinks and bound startup work. OSTree symlink
objects cannot serve as data-only sources. The detached metadata layer is trusted
as administrator-created boot state, not measured as fs-verity evidence.

The administrator must maintain those protections and must not modify active
backing objects in place. This is an additional trust assumption, not Linux
executable write exclusion. It includes administrator actions through privileged
jobs and writable aliases. Discovery failure leaves this exception unavailable.
Public context advertises only the host daemon-qualified mount ID; the daemon
never accepts client enrollment claims. This enrollment is a host-only baseline,
not qualification of a cloned destination mount. Destination support requires
private validation of its exact backing/mount assumptions; otherwise the exception
is ineligible there. Never expose target mount inventory through public context. Revalidate the source mount identity,
read-only status, root ownership and ordinary execution metadata at selection,
authorization and the exec checkpoint. Initially exclude file capabilities.
Always hash at preparation, before consumption and at the exec checkpoint;
never use overlay ctime to skip a hash. Preserve existing inode and credential
checks. Record the ComposeFS basis in audit and online approval display. Keep
the signed evidence as `digest_direct` plus SHA-256; never change models after
approval. The administrator-maintenance assumption is what prevents changes
after the last hash; no protection against violating that assumption is claimed.


`max_direct_digest_bytes` defaults to 256 MiB, maximum 1 GiB;
`direct_digest_timeout_ms` defaults to 5000, maximum 30000. These bounds are
independent of memfd's `max_executable_bytes` (maximum 64 MiB). Verity and ctime
have neither hashing limit nor executable snapshot RAM charge. Stdin retains its
existing size/RAM limits. Initial source eligibility and stdin preparation use
the original request deadline. The coordinator then CAS-transitions
`PREPARING -> HASHING`, assigns a once-only hash deadline, and resumes the
same reserved worker. Completion transitions to `REVIEWING` for unsigned requests
or `AUTHORIZING` for signed requests; stale phase timeouts cannot cancel a later phase. Conditional final-authorization rehashing
also has a fixed hashing deadline. Before approval every such deadline is capped
by the admission-based `D`; expiration takes the silent-timeout path. The
two-second spawn/setup deadline is never
extended while waiting for exec. A timely digest_direct exec event starts a
separate fixed verification deadline; other models retain the spawn deadline.
Check cancellation/deadlines between chunks and after the final chunk. Individual
kernel I/O calls are not preemptible; admission, worker, descriptor and job
reservations remain owned until actual completion/cleanup, even after timeout.

**Capability authority and signed execution profiles.** Intent supplies
only authority ceiling `capabilities = C`. Full-CSR clients derive, and the daemon independently verifies,
`execution_context.post_exec_capabilities`; for thin requests the daemon derives
these sets before the mandator signs. The field is required for every v3 model, containing sorted unique named
`permitted`, `effective`, `inheritable`, `ambient`, and `bounding` sets. The
ordinary ELF profile has all five sets equal to C. Each set is sorted/unique,
contains only supported capabilities within C, I and B equal C, E is a subset
of P, and A is a subset of P intersect I. Reject violations before review. Keep pre-exec sets equal to C,
`no_new_privs` and locked securebits. Never repair credentials after exec.

Initially support only exact Linux v2 host-user-namespace file-capability xattrs
on positively identified non-idmapped, non-nosuid mounts. Unsupported revisions,
namespaces, unknown mount metadata and malformed xattrs are ineligible. Both
file permitted and inheritable masks must be subsets of explicit C and the
signer's ceiling. Linux suppresses file capabilities when the execution FD's
mount belongs to the parent's namespace. For a capability-bearing transition,
the syscall-only child setup opens a symlink-free alias of the approved absolute
path in its private mount namespace, compares its device/inode against the
retained source FD, and executes only that identical inode. The original FD
stays pinned by the parent. Replacement or an unavailable alias fails closed;
there is no approval for alternate bytes or fallback. At exec the loaded inode
and exact resulting sets must still match. For such files derive `I = B = C`, `A = empty`,
`P = (fP & C) | (fI & C)`, and `E = P` when the file effective flag is set,
otherwise `E = empty`. Unsupported file-capability semantics can use memfd,
which intentionally strips those attributes. For memfd all five expected sets equal C.
There are no implicit legacy capability profiles in v3.

**Evidence encoding.** `command.executable_trust` is required and contains exactly
one of these tagged objects (measurements below are illustrative):

```json
{"model":"fs_verity","algorithm":"sha256","digest":"<64 lowercase hex digits>"}
{"model":"ctime","device":"2049","inode":"12345","size":"67108865","ctime_sec":1800000000,"ctime_nsec":123456789}
{"model":"digest_direct","sha256":"<64 lowercase hex digits>"}
{"model":"digest_memfd","sha256":"<64 lowercase hex digits>"}
```

Reject mixed representations, unknown fields, invalid measurements, a separate
`executable_sha256` field, profiles exceeding C, or any legacy version. Full
CSRs include claimed exact profiles; thin intents cannot contain derived profiles.
No full-CSR claim is accepted without independent validation. Approval and private
audit bind evidence, authority, profile and provenance. Checkpoint audit includes
the profile observed by exact comparison. No such evidence appears in a requester
pre-authorization response.

**Checkpoint and cancellation.** For direct models and any profile requiring
post-exec verification, before child exec the coordinator attaches
using `PTRACE_SEIZE` and `PTRACE_O_TRACEEXEC | PTRACE_O_EXITKILL`, registers the
PID/pidfd and releases a private startup pipe. This works when another thread
clones the child. The Central Reaper reports exec stops separately from exits;
sync-pipe EOF alone cannot release a direct child. At `PTRACE_EVENT_EXEC`, no
loader/target user instruction has run. A bounded worker verifies the loaded
`/proc/<pid>/exe` identity, model evidence, eligibility, all four UID and GID
values, supplementary groups, all five capability sets and `NoNewPrivs = 1`.

Before detach the coordinator checks cancellation, connection, warrant expiry
and the applicable post-approval verification deadline, reserves `RUNNING -> RELEASING`, then
detaches and reconciles `RELEASING -> RUNNING`. Clear the reaper's tracing
registration after successful detach so ordinary later suspension still works.
Cancellation during release is pending until detach's result is known. Any
failure, unexpected stop, timeout or disconnect kills/cleans up without release;
tracer death before detach kills the child. Readiness is audited only after
verification and release as `exec_event_observed`. Memfd may retain `unknown`
only when its declared security profile requires no exec checkpoint; NS-11
requires verified release for every model with post-exec confinement constraints.
Consumption precedes clone: post-commit failures consume a one-time warrant,
with no refund, fallback or retry. Namespace and LSM verification are additional
NS-10/NS-11 obligations; dependency integrity remains outside executable evidence.

### 2.3 `tty_mode` and `stdin_policy` Compatibility Matrix

Hello `tty_mode` must equal the intent/warrant command's mode before preparation.
Every mismatch or unsupported combination is a private validation failure and
silently times out; an invalid ancillary layout is a transport error before
any target inspection. The future PTY/unrestricted profile remains deferred
in the local implementation profile, not implicitly enabled by this rewrite.

| `tty_mode` | `stdin_policy` | Required descriptors | Validation and binding |
| --- | --- | --- | --- |
| `stdio` | `null` | stdout, stderr | Output: FIFO, regular file or verified `/dev/null`; daemon supplies verified null stdin; `stdin_sha256` null |
| `stdio` | `sha256` | stdin, stdout, stderr | Input: FIFO or regular file; collect before executable inspection into sealed memfd and bind 64-digit SHA-256; output types as above |
| `stdio` | `unrestricted_interactive` | stdin, stdout, stderr | FIFO, regular file or character device; explicit signer permission; no stdin digest |
| `pty` | `unrestricted_interactive` | None | Allocate PTY after APPROVED; transfer master on SERVER_EXEC_READY only; no stdin digest |
| `pty` | `null` or `sha256` | Forbidden | Never convert to unrestricted input |

Reject sockets, directories and O_PATH descriptors in every row. Reject caller
TTYs in null/hashed stdio. `sigrun` uses pipe write ends and bounded separate
stdout/stderr relays for a terminal invocation. Retain their last write ends
until the public decision; do not expose early EOF or write diagnostics to them.
A raw client may supply regular output files; do not modify them before approval.

Hash-input collection uses the retained immutable spool when supplied by sigrun;
raw finite sources are also bounded and sealed. Keep their original endpoints
until outcome even after collection, so executable-dependent cleanup cannot be
observed through pipe lifetime. Never silently change the input policy.

After APPROVED, service output concurrently with setup/results and cancellation
under sink backpressure. After a terminal execution result, drain pending output
through EOF. Broken sinks abort the connection. Before execution readiness,
cancellation closes the control socket; afterward only the specified signals
are forwarded. Child output remains untrusted and never feeds approval prompts.

### 2.3.1 Normative `recvmsg()` and Descriptor Ownership Rules

The following rules govern connector-attributed client-to-daemon reads on the
`SOCK_STREAM` control socket; the FD matrix alone is insufficient. A G-01 decision
to authenticate message senders must revise this ancillary/framing contract and
its bounds explicitly before self can use that mode; it cannot be added behind
these rules or inferred from socket visibility.

1. **Receive Every Byte with Ancillary Inspection:** Use `recvmsg(..., MSG_CMSG_CLOEXEC | MSG_DONTWAIT)` for every receive, including after `CLIENT_HELLO`; do not use `read()`, `recv()`, or `MSG_PEEK` paths that discard or duplicate ancillary delivery. Supply a bounded control buffer of `CMSG_SPACE(3 * sizeof(int))` on every call, reset `msg_controllen` before each call, and inspect returned `msg_flags` and every returned `cmsghdr` before accepting payload bytes. Received descriptors acquire `FD_CLOEXEC` atomically via `MSG_CMSG_CLOEXEC`; setting it afterward with `fcntl()` is insufficient.
2. **Unambiguous Frame Association:** For `stdio`, the client uses one `sendmsg()` to send exactly the first byte (`0x01 CLIENT_HELLO`) with its complete descriptor set in one `SOL_SOCKET`/`SCM_RIGHTS` message; for `pty`, it sends that byte with no ancillary data. It then sends the four-byte length and JSON payload without ancillary data. The daemon uses a one-byte iovec until its first successful data-bearing `recvmsg()` returns that type byte (retrying `EINTR` and waiting for readiness on `EAGAIN`); this is the only receive eligible to accept descriptors. Subsequent reads are bounded to the remaining header or payload of the current frame, never spanning frame boundaries. Stream fragmentation does not relax the rule: descriptors attached to the length, payload, a later frame, or any later receive are rejected. A second `CLIENT_HELLO` is a protocol error.
3. **Strict Control Validation:** Reject `MSG_CTRUNC` unconditionally, even if the visible descriptors appear to satisfy the matrix. Reject malformed control lengths (including an `SCM_RIGHTS` payload that is empty or not an integral number of `int` FDs), more than one returned ancillary message, and any message other than `SOL_SOCKET`/`SCM_RIGHTS`. `SO_PASSCRED` and, where supported, `SO_PASSPIDFD` are disabled; caller UID/GID comes from `SO_PEERCRED` and full-access supplementary groups from `SO_PEERGROUPS`, not ancillary credentials. Ancillary messages on any receive after the initial type byte are forbidden. Linux may coalesce sender-side rights messages; validate the messages actually returned by `recvmsg()` and their aggregate descriptor count, without claiming to recover sender-side control-message boundaries.
4. **Exact Descriptor Count and Deferred Use:** Collect all descriptors returned on the eligible receive into request-owned storage, but do not use them until the complete bounded `CLIENT_HELLO` parses and the count, order, and types match Section 2.3. Reject extra descriptors immediately (including any that fit in control-buffer alignment padding); never discard extras and accept a prefix. Reject missing descriptors once the frame is complete. For `pty`, any received descriptor is invalid. For `stdio`, the sole ancillary message must supply exactly the matrix's two or three FDs in the specified order. Check types with `fstat()` and reject `O_PATH` using `fcntl(F_GETFL)` before use.
5. **Close on Every Failure; Never Resynchronize:** On truncation, unexpected/multiple messages, extra FDs, invalid transport framing, EOF before frame completion, or transport timeout, close **every FD delivered by that receive**, including those in other returned `SCM_RIGHTS` messages, plus every FD already held by the rejected request. Inspect all safely traversable returned control messages and collect their FDs before taking a rejection branch; an error in one message must not leak FDs from another. The kernel closes rights omitted by control truncation; the daemon closes all rights actually delivered. Transfer FD ownership exactly once only after validation. A framing or ancillary error is terminal for the connection: discard buffered input, close the socket (which releases queued, undelivered rights), and never parse a later frame or associate later descriptors with another request. Do not send a detailed authorization error. Complete bounded requests with invalid JSON/schema or later validation failures retain observable endpoints until Section 2.1 timeout; transport faults close immediately without target inspection. After APPROVED follow Section 2.4 disconnect teardown. Normal completion and disconnect also close all request-owned FDs. Cleanup of FDs already transferred to an I/O worker follows Section 1.3: cancel that task, retain its quota accounting until its owner actually closes the FDs, and never double-close a transferred descriptor.

### 2.3.2 Server-to-Client PTY Transfer and Ownership

1. **Eligible frame:** Exactly one PTY master is sent only on `0x08 SERVER_EXEC_READY`
   for a PTY request after a complete `APPROVED`. Authorization decisions and
   execution results never carry rights. Allocate the PTY only after approval.
2. **Send layout:** Prepare the complete bounded readiness payload first. Send
   exactly its type byte in a one-byte `sendmsg` with one `SOL_SOCKET/SCM_RIGHTS`
   containing one FD; then send length/body without rights. Use `MSG_NOSIGNAL |
   MSG_DONTWAIT`, one cumulative five-second send deadline and bounded retries
   for EINTR/EAGAIN. After the type byte succeeds never resend its rights. A
   partial-frame failure closes the connection and tears down the approved job.
3. **Receive validation:** Use `recvmsg(MSG_CMSG_CLOEXEC | MSG_DONTWAIT)` for every
   server read, a reset `CMSG_SPACE(sizeof(int))` buffer, and a one-byte read for
   each type byte. Bound later reads to that frame. Reject truncation, malformed
   control lengths, wrong level/type, extra FDs (including alignment padding),
   rights on any other frame or later receive, and duplicate readiness. Keep the
   FD pending until the complete payload validates; no terminal operation occurs
   on an unvalidated FD. Disable automatic ancillary credentials/pidfds.
4. **FD validation:** Require a character device, O_RDWR, no O_PATH and successful
   `TIOCGPTN` proving a PTY master; require CLOEXEC at receipt. Only then promote
   it and set O_NONBLOCK for relaying. On failure close all received/pending FDs,
   restore the terminal, cancel the connection and report local protocol failure.
5. **Ownership:** SCM_RIGHTS duplicates ownership, not transfer-by-close. The
   daemon retains a master for validated resize ioctls, never competing for data
   reads, and closes parent slave references after clone. Client and daemon close
   their owned references on failure, result completion or disconnect; queued
   undelivered rights are separately disposed with the socket. A partial readiness
   frame cannot become another outcome. A result cannot interleave with a partial
   readiness frame. On daemon disconnect the client restores its terminal without
   waiting for PTY EOF, even if another process retains a slave.

### 2.4 Two-Frame `sync_pipe` Exec Handshake & Centralized Reaper (Resolving Findings 3 & 4)

The concrete step numbers, direct-child wait calls and process-group signal
recipe below describe the host baseline. Namespace launchers must preserve the
same classification, registration and cleanup guarantees through the G-03
parentage/reaper plan. Do not assume a launcher-created final child is directly
waitable by the daemon, or that its host-visible PID is its process-group ID.
G-02/G-03 must define bounded namespace setup error frames and signal routing
before implementation; silent reuse of host step meanings is not permitted.

1. **Two-Frame Pre-Exec Handshake on `sync_pipe` (Setup Readiness and Reported Failures):**
* A child killed before writing the readiness frame produces `0` bytes followed by `EOF`. A child killed after writing the frame but before entering `execveat()` produces the same 8-byte frame followed by `EOF` as a successful exec, including a fast `/bin/true` exit. Death after an exec error but before writing its error frame is also indistinguishable. `EOF` means the write end closed; `FD_CLOEXEC` cannot establish why it closed. Direct execution of an arbitrary target cannot provide an exact parent-side exec-success notification in this race window. A stronger contract would require a trusted post-exec trampoline reporting after its own exec transition; a memfd profile without a checkpoint does not claim target exec success. Direct models and memfd profiles requiring post-exec verification instead use the verified ptrace exec checkpoint in Section 2.2.2.
* Accordingly, `sigrund` uses an explicit two-frame protocol over `FD 4` (`sync_pipe[1]`, `O_CLOEXEC`), where each frame is an 8-byte struct `{ u32 step, i32 errno }` in native endianness:
* If any child setup step `1..=10` fails prior to `execveat()`, the child writes `{ step: 1..10, errno: >0 }` (8 bytes) and calls `_exit(127)`.
* In Step 10, immediately after the Read-Back Verification Gate passes and immediately before calling `syscall(SYS_execveat, ...)`, the child writes the 8-byte **`READY_TO_EXEC`** frame `{ step: 0, errno: 0 }`.
* The readiness write must return exactly `8`; otherwise the child calls `_exit(127)` without exec. Immediately after `write(4, &READY_TO_EXEC, 8)` returns `8`, the child invokes `syscall(SYS_execveat, 3, "", argv_ptrs, envp_ptrs, AT_EMPTY_PATH)`.
* If `execveat()` fails and returns `-1`, the child writes a second 8-byte **`EXECVEAT_ERR`** frame `{ step: 11, errno: errno }` (making 16 bytes total in the pipe buffer) and calls `_exit(127)`.
* On a successful exec transition, the kernel closes `FD 4` (`O_CLOEXEC`) without writing a second frame. Process death, including a fatal failure during exec, also closes it; closure is not an exec-success acknowledgement.


* **Parent (`sigrund`) Classification Rules (monitored via `epoll` with a `2000 ms` timeout until `sync_pipe[0]` reaches `EOF`):**
* **`0` bytes read before `EOF`:** No setup-readiness evidence -> classified as `SPAWN_FAILED`. A `2000 ms` timeout before `EOF`, even after a readiness frame, is also `SPAWN_FAILED`.
* **Exactly `8` bytes read followed by `EOF`, with `step` in `1..=10` and `errno > 0`:** Reported setup failure -> classified as `SPAWN_FAILED`.
* **Exactly `16` bytes read followed by `EOF` (`{ step: 0, errno: 0 }` then `{ step: 11, errno: >0 }`):** Reported `execveat()` error -> classified as `SPAWN_FAILED`.
* **Exactly `8` bytes read equal to `{ step: 0, errno: 0 }` followed by `EOF`:** All 10 setup steps passed; exec outcome is unknown -> classified as `READY_TO_EXEC`. `sigrund` appends `EXEC_READY_TO_EXEC` (`child_pid`, `exec_outcome: "unknown"`) to the audit log and sends `0x08 SERVER_EXEC_READY` (`exec_outcome: "unknown"`), after the prior APPROVED. All models requiring a checkpoint withhold readiness until it verifies and releases the child. This classification also applies to a child killed in the post-token/pre-syscall window. The Central Reaper preserves any already-observed terminal status and sends it afterward in `0x05 SERVER_EXEC_RESULT`; a signal termination or exit code alone does not establish whether exec occurred.
* **Any other byte sequence, partial frame, or excess bytes:** Protocol fault -> classified as `SPAWN_FAILED`. Reads may split or combine frames; the parent accumulates bytes through `EOF`, with a maximum of 16 bytes, before classifying.
* On any `SPAWN_FAILED` outcome, `sigrund` tears down `job-<exec_id>` via `cgroup.kill`, appends `EXEC_SPAWN_FAILED` to the audit log, and sends `SERVER_EXEC_RESULT` with `SETUP_FAILED` (setup/clone/handshake failure) or `EXEC_FAILED` (reported exec or checkpoint failure); it never sends a second auth decision.


2. **Centralized Child & Subreaper Dispatcher (Preventing Cross-Job Exit-Status Theft):**
* Calling `waitid(P_ALL, 0, ...)` inside an individual job's cleanup handler is **forbidden**, because `P_ALL` can reap another concurrent job's primary child and cause that second job's `waitid(P_PIDFD, ...)` call to fail with `ECHILD`.
* All job and hook `clone3()` calls set the separate `args.exit_signal = SIGCHLD` field (Sections 5.1 and 6.1); it is not part of `args.flags`. The daemon blocks `SIGCHLD` in all threads for `signalfd` delivery, retains its default disposition, and must not set `SIG_IGN` or `SA_NOCLDWAIT`, so direct children remain waitable with ordinary `WEXITED | WNOHANG` (no `__WCLONE`/`__WALL` needed for these children).
* Instead, `sigrund` maintains a single-threaded **Central Reaper** on the main `epoll` loop backed by a registry `active_primary_pids: HashMap<pid_t, ContextId>` (containing the `child_pid` of every active job and `hook_pid` of every active hook):
* Whenever a tracked `child_pidfd` signals `EPOLLIN`, the Central Reaper calls `waitid(P_PIDFD, child_pidfd, &siginfo, WEXITED | WNOHANG)` to harvest that specific process's `(si_code, si_status)`, removes `child_pid` from `active_primary_pids`, and records the terminal status on the owning job/hook context.
* **Pending-spawn registration barrier:** Before dispatching any off-loop job or hook clone, the coordinator registers a bounded pending-spawn context retaining its lifecycle reservation, inputs and cgroup cleanup owner. While any clone result is unpublished, the Central Reaper must not issue `waitid(P_ALL, ...)`: an unregistered primary may already have exited. It continues servicing registered primaries with `waitid(P_PIDFD, ...)`. The spawn completion transfers PID/pidfd into `active_primary_pids` before releasing its pending context, including after cancellation or shutdown; a failed clone releases the barrier only after confirming no child exists. On clearing the last barrier, immediately sweep for waitable children even if the original SIGCHLD notification was already consumed. Serialize clone dispatch: at most one unpublished clone result may exist, and perform the deferred sweep before dispatching the next clone. This prevents a stream of new clones from indefinitely extending the barrier. No PID status is discarded or guessed during the barrier. This bounded ownership may delay orphan reaping while a clone is blocked; it does not authorize replacement workers or unbounded new spawns.
* Whenever the daemon's `signalfd(SIGCHLD)` fires or a cgroup's `cgroup.events` reaches `populated 0`, and no pending-spawn barrier exists, the Central Reaper loops on `waitid(P_ALL, 0, &siginfo, WEXITED | WNOHANG)`:
* If `siginfo.si_pid` is present in `active_primary_pids`, the Central Reaper removes it from `active_primary_pids` and delivers `(si_code, si_status)` directly to that owning job/hook context (so its exit status is never lost even if `waitid(P_ALL, ...)` reaped it before its `pidfd` event was processed).
* If `siginfo.si_pid` is **not** in `active_primary_pids`, with no pending-spawn barrier it is an unregistered descendant (`PR_SET_CHILD_SUBREAPER`) and its status can be discarded. Every direct job/hook child must use the registration contract above.


3. **Signal Forwarding, Normal Exit, and Disconnect Teardown:**
* **Signal Forwarding (`0x03 CLIENT_SIGNAL`):** While the job's primary child remains in `active_primary_pids` (`child_pidfd` open and unreaped), `sigrund` validates `signal` $\in \{\text{SIGINT}, \text{SIGTERM}, \text{SIGHUP}, \text{SIGUSR1}, \text{SIGUSR2}\}$ and calls `kill(-child_pid, signal)`.
* **Normal Primary-Child Exit:** Once the Central Reaper records the primary child's `(si_code, si_status)` for `job-<exec_id>`:
1. `sigrund` writes `"1\n"` to `job-<exec_id>/cgroup.kill` to kill any lingering background processes in that cgroup.
2. Preserve the primary status and finish sync/checkpoint classification before
   releasing descriptors needed to verify it. Observe `populated 0` through
   `inotify`, drain reparented children through the Central Reaper, and release
   owned child/executable/stdin descriptors and cgroup resources off-loop.
3. APPROVED was already delivered before clone. Send SERVER_EXEC_READY at most
   once if classification permits it (it may already have been sent while the
   child was running), append EXEC_EXIT, then send SERVER_EXEC_RESULT with EXITED
   and the preserved primary status. Setup/exec failure follows the failure-result
   path instead. Send exactly one result after cleanup and close the connection;
   neither path repeats authorization.


* **Client Disconnect (`EPOLLHUP` / `EPOLLERR`):** If the client socket closes while the job is active, `sigrund` writes `"1\n"` to `job-<exec_id>/cgroup.kill`, waits for `populated 0`, collects the primary child's termination status via the Central Reaper, releases quotas, removes `job-<exec_id>` via `rmdir()`, and appends `EXEC_EXIT` (`exit_code`, `signal`, `disconnected: true`).


### 2.4.1 Daemon Shutdown and External Cleanup

Block SIGINT/SIGTERM/SIGCHLD before creating threads and receive them through
signalfd. SIGINT/SIGTERM or a fatal durable-store error enters one irreversible
shutdown state: stop all listeners and new commit/spawn reservations, close
control connections, and cancel every request. No new approval or readiness is published
after this transition. Already-reserved operations must reconcile their actual
results under Section 1.3.1; every returned child is registered and scheduled
for cgroup teardown even if its client has gone. A consumed grant is never
rolled back to make a shutdown look retryable.

Keep the event loop, pending-spawn registry and Central Reaper alive while
bounded off-loop owners kill cgroups, observe `populated 0`, dispose of FDs and
persist outcomes when the audit writer is healthy. Never append through a
poisoned writer or wait synchronously for a blocked worker. Retain the daemon
instance lock and all outstanding ownership until cleanup completes or the
external supervisor terminates the process. `shutdown_grace_ms` is the deadline
for cooperative cleanup, not proof that uninterruptible kernel work stopped.
On expiry, emit a bounded best-effort diagnostic and remain quiescent with
cleanup ownership intact pending completion or supervisor escalation; do not
resume admission, drop live jobs or falsely report successful cleanup.

Execution deployments, including foreground tests, require a dedicated
supervising service with cgroup delegation and whole-service cleanup on daemon
death. For systemd, use `Delegate=yes`, `KillMode=control-group`,
`SendSIGKILL=yes`, and `TimeoutStopSec` greater than `shutdown_grace_ms`.
The supervisor must also detect internally initiated shutdown or a stalled
daemon (for example through a service watchdog) and initiate bounded stop/kill
escalation; a stop timeout alone does not run merely because the daemon entered
its own fatal state. The integration recipe must configure and test that path.
The foreground recipe must run inside such a service, not an ordinary root
shell or a scope whose cleanup depends on that shell exiting. SIGKILL or host
failure cannot run daemon cleanup; the supervisor kills remaining service
processes, and restart performs Section 1.2 orphan cleanup before listening.
Tasks stuck in uninterruptible kernel waits may delay even external cleanup;
never reopen admission over surviving unverified jobs. Escaped root or
out-of-profile workloads retain Section 1.1's best-effort limitation. Prior
instance children are not assumed to be waitable by the new daemon.

---

## 3. Canonical Signed-Byte Protocol & Signature Verification

### 3.1 DSSE v1.0 Pre-Authentication Encoding (PAE)

Warrants use **DSSE v1.0** wrapping an **RFC 8785 (JCS)** canonical JSON payload.

* **Payload Type (`payloadType`):** `"application/vnd.sigrun.warrant.v3+json"` (exact length: **38** ASCII bytes).
* **PAE Formula:**
```text
PAE(payloadType, payload) =
    "DSSEv1 "
    || ASCII_DEC(BYTE_LEN(payloadType)) || " " || payloadType || " "
    || ASCII_DEC(BYTE_LEN(payload))     || " " || payload

```


* **Interoperability Test Vector:**
* `payloadType` (38 bytes): `application/vnd.sigrun.warrant.v3+json`
* Sample JCS `payload` (67 bytes):
```json
{"grant_id":"0192d8f4-7c1b-7000-8a01-9f8b3c4d5e6f","version":"3.0"}

```


* Exact 119-byte PAE string:
```text
DSSEv1 38 application/vnd.sigrun.warrant.v3+json 67 {"grant_id":"0192d8f4-7c1b-7000-8a01-9f8b3c4d5e6f","version":"3.0"}

```


* Exact PAE Hex Prefix (first 52 bytes):
`445353457631203338206170706c69636174696f6e2f766e642e73696772756e2e77617272616e742e76332b6a736f6e20363720`

The minimal payload above is a PAE interoperability vector, not a valid warrant.

### 3.2 Canonical Warrant and CSR Schema (`3.0`)

A full CSR and a signed warrant payload use the same exact schema. All fields
are mandatory; nullable fields must be present. A CSR has no signatures. An
approved envelope must retain the exact CSR bytes. The pretty-printed example
below illustrates shape; transport/signing uses canonical JCS, not indentation.
Its executable digest is illustrative, not authorization for an installed tool.

Warrant top-level keys are exactly `version`, `request_origin`, `intent_sha256`,
`approval_exec_id`, `caller_env`, `command`, `execution_context`, `grant_id`,
`host_id`, `policy`, `requester_uid`, `requester_gid`, `intent`, `target_binding`,
and `security_constraints`. Command adds exactly
`executable_trust` and `stdin_sha256` to the intent command. Execution context
adds `target_uid`, `target_gid`, `supplementary_gids`, and
`post_exec_capabilities` to the intent context. Policy has exactly
`mode`, `not_before`, `not_after`. Every model requires all five explicit
post-exec capability sets, validated by Section 2.2.2.

`request_origin` is either `client_full` with null `approval_exec_id`, or
`daemon_expanded_thin` with the active daemon-generated execution UUID. The
latter requires `one_time`, the matching live thin request and its exact retained
CSR; it cannot enter through the signed-redemption endpoint, reconnect or restart.
The client cannot select an origin to bypass access validation. The mandator
signs provenance with the rest of the warrant.

Compute `intent_sha256 = hex(SHA256(JCS(intent)))` over the embedded, complete
original intent. Require byte-equivalent canonical intent to the submitted thin
intent or full CSR intent before review and at final authorization. Warrant
command equals intent command plus measured evidence. Execution context equals
intent context plus resolved numeric credentials and expected capability sets;
these must satisfy the account selector, mapping and authority checks. Policy
TTL equals `not_after - not_before`, or zero for permanent grants. Caller
environment must equal the intent's values. Target binding must resolve the
submitted selector and constraints must satisfy the requested profile under
captured policy. Retain the original intent, not only its digest. No field in
resolved data may override command, environment or requested authority.

```json
{
  "approval_exec_id": null,
  "caller_env": {},
  "command": {
    "allow_interpreted_script": false,
    "argv": [
      "/usr/bin/id",
      "-u"
    ],
    "cwd": "/",
    "executable_path": "/usr/bin/id",
    "executable_trust": {
      "model": "digest_memfd",
      "sha256": "79290b29fb6884d6b7954521b5d9f603f4799ca574faa276619161283115f0a6"
    },
    "stdin_policy": "null",
    "stdin_sha256": null,
    "tty_mode": "stdio"
  },
  "execution_context": {
    "caller_env_allowlist": [],
    "capabilities": [],
    "env_exact": {
      "LANG": "C.UTF-8",
      "PATH": "/usr/sbin:/usr/bin"
    },
    "post_exec_capabilities": {
      "ambient": [],
      "bounding": [],
      "effective": [],
      "inheritable": [],
      "permitted": []
    },
    "supplementary_gids": [],
    "target_gid": 0,
    "target_uid": 0,
    "umask": 63
  },
  "grant_id": "0192d8f4-7c1b-7000-8a01-9f8b3c4d5e6f",
  "host_id": "sigrun-host:sha256:8f1f0466fc41bb150b4a15c1bc827805b86d72882bf2a2aaea2698dae6018027",
  "intent": {
    "account": {
      "gid": 0,
      "kind": "numeric",
      "supplementary_gids": [],
      "uid": 0
    },
    "caller_env": {},
    "command": {
      "allow_interpreted_script": false,
      "argv": [
        "/usr/bin/id",
        "-u"
      ],
      "cwd": "/",
      "executable_path": "/usr/bin/id",
      "stdin_policy": "null",
      "tty_mode": "stdio"
    },
    "execution_context": {
      "caller_env_allowlist": [],
      "capabilities": [],
      "env_exact": {
        "LANG": "C.UTF-8",
        "PATH": "/usr/sbin:/usr/bin"
      },
      "umask": 63
    },
    "policy": {
      "mode": "one_time",
      "ttl_secs": 900
    },
    "security_profile": "host-baseline",
    "target": {
      "kind": "host"
    }
  },
  "intent_sha256": "17819df45609ee1455c8e2a14799c0f92f15523c44da52cc77463c250ccf1cb2",
  "policy": {
    "mode": "one_time",
    "not_after": 1793372100,
    "not_before": 1793371200
  },
  "request_origin": "client_full",
  "requester_gid": 1001,
  "requester_uid": 1001,
  "security_constraints": {
    "profile_id": "host-baseline",
    "profile_sha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  },
  "target_binding": {
    "context_sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "daemon_epoch": "0192d8f4-0000-7000-8000-000000000001",
    "description": "Host execution environment",
    "instance_id": "0192d8f4-0000-7000-8000-000000000002",
    "kind": "host"
  },
  "version": "3.0"
}
```

Unknown/missing fields, legacy versions, invalid origin/exec bindings, malformed
hashes, mixed evidence, wrong stdin nullability, excess capability profiles and
changed intent fail closed. Full CSR identity is checked against kernel peer
credentials and local host identity without rewriting client bytes. Thin identity
and grant fields are assigned by the daemon. No public outcome includes this
payload, including on timeout or approval.

### 3.2.1 Selection and Signed Execution Bindings (NS-14)

The complete original intent is signed alongside resolved execution fields:

| Intent field | Exact draft shape and interpretation |
| --- | --- |
| `target` | `{kind: "host"}` or `{kind: "self"}`; `{kind: "registered", id: string}`; `{kind: "process", pid: positive integer, pid_scope: "daemon"}` |
| `account` | `{kind: "numeric", uid: u32, gid: u32, supplementary_gids: [u32]}` or `{kind: "name", name: string}` |
| `security_profile` | Nonempty root-configured profile identifier |

For named accounts, use the captured destination account's primary and
supplementary groups, then sign the exact sorted numeric result. No host NSS
fallback. Explicit numeric selection uses exactly its requested groups.
IDs/groups retain existing numeric bounds; account/profile/registration strings
are sanitized UTF-8, 1..128 bytes. Reject unknown tags, mixed forms and extra
fields. Process PID is in `1..=2147483647`; it is never used as a substitute for
the instance binding on redemption. Manager-name selector syntax is deferred to
Phase 5 and requires a schema revision before exposure; examples are not aliases
that an implementation may guess.

`target_binding` has exactly `kind` (`host` or `process_environment`),
`daemon_epoch` and `instance_id` (UUIDv7), `description` (sanitized UTF-8,
1..1024 bytes), and `context_sha256` (64 lowercase hex digits). The digest binds
the canonical private acquisition record: pinned process identity, namespace
identities/ownership, root identity, composed UID/GID mappings and setgroups
state, and required lifecycle/resolver scope. Phase 0 must finalize that bounded
record schema and coherent acquisition procedure before any binding is issued.
The digest/IDs are not authority without a matching live retained target.

`security_constraints` has exactly `profile_id` (same identifier as the intent)
and `profile_sha256` (64 lowercase hex digits). The digest is SHA-256 of the
canonical resolved constraint object, including namespace/isolation rules,
capability/securebits/NNP rules, cgroup ceilings, LSM requirements, seccomp and
verification obligations. This immutable object must be available to the daemon
and trusted approver; missing versions fail closed, never resolve to a current
same-named profile. Phase 0 must freeze its bounded schema. Display its complete
meaning before signing; a digest alone is not an adequate approval UI.

All targets, including host, are epoch-bound. Full/offline preparation needs a
trustworthy existing binding and immutable constraint object through an
administrator-approved access path; no new public target discovery endpoint is
implied. If unavailable, full-only/export fails locally or through the defined
private failure path. Redemption after restart requires fresh preparation and
approval. Reusable grants, when separately implemented, remain limited to the
same live instance and epoch; they never follow a registration to its replacement.
The sample context/profile digests are illustrative, not usable registrations.

#### Phase 3 experimental namespace contract

The opt-in `sigrund.constraints.namespace-experimental.v1` record is distinct
from the frozen Phase 0 constraints. Its canonical record is
[`experimental-constraints.json`](crates/sigrund-core/tests/fixtures/v3-namespace/experimental-constraints.json).
It requires all eight declared namespace inputs, private mount/cgroup views,
digest-memfd, a final-child exec stop, securebits 15, NNP, finite memory/pids
limits and empty capability sets. Destination UID must be nonzero and requested
supplementary groups empty. SELinux fields declare no requested transition
(`context=""`, `enforcing=false`, `policy_change="unmanaged"`); AppArmor is
unsupported and seccomp is explicitly none. Ambient kernel LSM policy still
applies. This experimental profile does not qualify production confinement or
relax any historical profile. Phase 4 owns those additional obligations.

Registered/process bindings retain `sigrund.process-context.v1`: exactly the
acquisition and pinned executable-root map. Self uses
`sigrund.self-context.v1`, adding `authenticated_source` with the original
public connector's positive host PID, UID, GID, sorted supplementary GIDs and
required nullable `security_label`. These are the host daemon's kernel socket
observations, distinct from live acquisition process attributes. Self acquisition
must match that connector via its original peer pidfd and the dedicated `.anchor`
rendezvous. The single thread is traced through successful `unshare(CLONE_FS |
CLONE_FILES)` and held at syscall exit; namespace/root/mapping observations are
then pinned. Connector death, exec, credential or namespace changes invalidate
capture. Relaying an inherited/passed public stream never changes attribution.
The CLI uses a dedicated syscall-only connector and keeps its pidfd through
completion; the parent relays the stream. Exposing self requires the `.anchor`
endpoint alongside the public socket and target-independent `.context` endpoint.

Root-controlled review records are `sigrund.process-review.v1` for registrations
and `sigrund.self-review.v1` for self. The `registration` key is mandatory;
self requires null, an authenticated source, and null registration lifecycle
fields. A registered review requires its exact registration/revision and no
self source. Both must verify the exact CSR, resolved credentials, complete
constraints, executable/cwd identities and context digest before rendering or
signing. Namespace requests remain thin-only in this phase; full/signed namespace
input is rejected without fallback.

The actual execution lease survives authorization, complete APPROVED delivery,
launcher/final-child handoff, exec-stop verification and cleanup. Destination
I/O and capture exchanges stay off the durable sequencer. Capture helpers wait
for an explicit acquisition grant after fresh exec, so inherited-descriptor
copies close before target-pin reservations begin; each stage reserves before
its own acquisition. No timeout or cancellation refunds live resources. Durable
consumption survives all post-commit failures, including incomplete APPROVED
delivery and a commit whose completion is observed after the request deadline.

The namespace launcher MUST fresh-exec before entering destination authority,
carrying only a bounded sealed per-job configuration and the explicit descriptor
allowlist. It MUST NOT carry the live daemon's address space, environment, keys
or unrelated requests into a target user namespace. The host coordinator attaches
its EXITKILL tracer before granting namespace entry. Initial host mappings and
`fs.suid_dumpable` 0 or 2 are required for credential transitions; value 1 is
rejected before review and checked again before execution. Dumpability is
disabled before namespace entry and after credential changes. Concurrent host
security-policy replacement is not qualified by this experimental profile.

Null stdin MUST use a verified retained host null-device descriptor; output
rights are never an input fallback. Configured experimental limits MUST fit the
daemon's job ceilings before admission. Requested cwd beneath the covered `/run`
tree is rejected before approval, and the completed private tree MUST resolve
the approved cwd to the same inode and mount as the actual inherited cwd before
final-child creation. Anchor and helper death MUST remain observable without
acquiring the capture IPC mutex. Transient spawn descriptors and inherited
duplicates remain charged through actual close or reap. Self connection retries
have an independent deadline, bounded backoff and parent-death protection;
their capture handshake retains the constrained read-to-unshare sequence.


### 3.3 Strict JCS Round-Trip & String Sanitization Rules

1. `sigrund` Base64-decodes `dsse_envelope.payload` (strict RFC 4648 standard alphabet, no whitespace) and rejects payloads over `65536` bytes.
2. `sigrund` parses the JSON into `Warrant`, rejecting duplicate keys at any depth, unknown fields, non-integer numbers, strings exceeding `4096` UTF-8 bytes, and any string containing C0 controls (`U+0000`..`U+001F`), DEL/C1 controls (`U+007F`..`U+009F`), or Unicode BiDi control characters (`U+061C`, `U+200E`, `U+200F`, `U+202A`..`U+202E`, `U+2066`..`U+2069`).
3. `sigrund` re-serializes `Warrant` using RFC 8785 (JCS) and asserts **byte-for-byte equality** with the raw decoded `payload` bytes. Exact-name `caller_env_allowlist` is the only caller-environment forwarding field; obsolete `env_wildcard_allowlist` is rejected, never interpreted as a regex policy.
4. Exported client-full CSR bytes remain canonical JCS (an export file may have
   one trailing newline that tooling strips before canonical verification).
   Thin-derived bytes never reach a requester status/output channel. When
   individual fields are interpolated into trusted displays or private logs,
   escape bytes outside printable ASCII and backslash/quote as `\xXX` or
   `\u{XXXX}`. Do not send expanded evidence through untrusted logs or webhooks.


### 3.4 Signature Verification Adapters & Single-Signer Rule

1. **`raw-ed25519`:** 64-byte Ed25519 signature ($R \parallel S$) verified directly over `PAE` via strict non-malleable verification (`verify_strict`, rejecting small-order points and non-canonical scalars $S \ge L$).
2. **`ssh-ed25519` and `sk-ssh-ed25519` (`PROTOCOL.sshsig`):**
* Base64-decoded `sig` is the raw binary `SSHSIG` blob: 6-byte magic `"SSHSIG"`, `uint32(1)` version, `string(publickey)` matching `signers.toml`, `string(namespace)` equal to `"sigrun.warrant.v3"` (17 bytes), empty `string(reserved)`, and `string(hash_algorithm)` equal to `"sha512"`.
* Recomputes `signed_data`:
```text
signed_data =
    "SSHSIG"                          // 6 raw bytes: 0x535348534947
    || uint32_be(17) || "sigrun.warrant.v3"
    || uint32_be(0)  || ""
    || uint32_be(6)  || "sha512"
    || uint32_be(64) || SHA512(PAE)

```


* For `ssh-ed25519`, verifies the 64-byte signature over `signed_data`.
* For `sk-ssh-ed25519@openssh.com`, verifies the 64-byte signature over:
```text
sk_message =
    SHA256(application_string)        // 32 bytes (e.g. SHA256("ssh:"))
    || uint8(flags)                   // 1 byte
    || uint32_be(counter)             // 4 bytes
    || SHA256(signed_data)            // 32 bytes

```


and enforces hardware flags:
* If `signer.require_user_presence == true`, requires `(flags & 0x01) == 0x01` (FIDO `UP` bit); otherwise rejects.
* If `signer.require_user_verification == true`, requires `(flags & 0x04) == 0x04` (FIDO `UV` bit); otherwise rejects.


3. **`openpgp-v4-ed25519`:** Binary OpenPGP detached signature packet (tag `2`, v4 or v6, signature type `0x00`) verified against the pinned fingerprint in `signers.toml`, requiring a hashed Issuer Fingerprint subpacket, valid Ed25519 signature over `PAE`, and hashed Signature Creation Time (`sig_time`) satisfying:
* For `"one_time"` and `"time_range"` grants: $\text{not\_before} - 300 \le \text{sig\_time} \le \text{not\_after}$.
* For `"permanent"` grants (where `not_after` is `null`): $\text{not\_before} - 300 \le \text{sig\_time} \le \text{now} + 300$.


4. **`sigstore-bundle-v0.3`:** UTF-8 JSON Sigstore Bundle verified offline against `/etc/sigrund/trusted_root.json` (Fulcio leaf chain, OIDC Issuer `1.3.6.1.4.1.57264.1.8`, SAN identity, Rekor inclusion proof and SET within leaf validity, and signature over `PAE`).
5. **Single-Signer Authorization Rule:** Permissions across multiple signatures are never combined. At least **one single signature entry** in `dsse_envelope.signatures` (`1..=4`) must reference an unrevoked `signer_id`, pass cryptographic verification under Section 3.4, and satisfy the complete Section 4.2 ceiling policy for that `signer_id`.

---

### 3.5 Canonical Numeric and Identifier Bounds

All numeric JSON values are decimal integers, never floating-point or exponent forms. `grant_id` and `exec_id` are canonical lowercase UUIDv7 strings: exactly 36 ASCII characters in `8-4-4-4-12` form, hexadecimal digits lowercase, version nibble `7`, and RFC 4122 variant nibble `8`, `9`, `a`, or `b`; no braces or URN prefix is accepted. Client-full grant IDs and daemon-generated thin grant/execution IDs use CSPRNG-backed UUIDv7 generators. The daemon rejects active/state collisions and enforces replay protection independently of the claimed generator.

UID and GID fields are integers in `0..=4294967294` (`UINT32_MAX` is the Linux overflow sentinel and is rejected), with `uid_t`/`gid_t` conversion checked before every syscall. Timestamps are signed 64-bit Unix seconds in `0..=253402300799` (9999-12-31T23:59:59Z); `CLOCK_REALTIME` conversion and comparisons use checked `time_t`/`int64` operations. `ttl_secs` is an integer in `0..=daemon.max_ttl_secs`, and `not_after = not_before + ttl_secs` uses checked unsigned/signed conversion; overflow, negative results, or a result outside the timestamp range rejects the request. `max_ttl_secs`, policy windows, sizes, quotas, and cgroup limits use checked `uint64` arithmetic and are bounded by the configuration schema. Array lengths, frame lengths, and sequence numbers are checked before casts to `size_t`, `off_t`, or syscall argument types. These bounds apply to signed warrants, unsigned CSRs, hook JSON, audit records, and collector receipts.

## 4. Complete Authorization Gate, Contiguous Audit Replication, and Durable Commit

### 4.1 Signer Ceiling Policy (`/etc/sigrund/signers.toml`)

```toml
[[signers]]
signer_id = "mandator-alice-yubikey"
type = "sk-ssh-ed25519"
public_key = "sk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29t..."
require_user_presence = true
require_user_verification = false
allowed_requester_uids = [1001, 1002]
allowed_target_uids = [0, 33]
allowed_target_gids = [0, 33]
allowed_supplementary_gids = [33, 104]
allow_same_uid_elevation = false
allowed_capabilities = ["CAP_NET_BIND_SERVICE", "CAP_NET_ADMIN", "CAP_SYS_ADMIN"]
allowed_modes = ["one_time", "time_range"]
max_ttl_secs = 3600
allow_unrestricted_stdin = false
allow_pty = false
allow_interpreted_scripts = false
allowed_executable_dirs = ["/usr/bin", "/usr/sbin"]

```

The numeric ceilings above are scoped to explicitly permitted execution targets
and immutable security profiles (Section 1.6), never global namespace-independent
UIDs. The draft entry illustrates the base fields; target-scope/profile policy
syntax is a Phase 0 schema gate. Requester IDs remain host-observed. A signature
must satisfy one complete signer policy; ownership and multiple partial signers
do not combine to authorize cross-owner execution (NS-06).

### 4.2 Unified Pre-Consumption Authorization Gate

Before opening the SQLite transaction or spawning a child, `sigrund` verifies that all 9 predicates below hold for the validated `Warrant` $W$, the kernel socket credentials `ucred` (`SO_PEERCRED`), the local `host_id`, the retained model-specific executable, optional sealed `stdin_memfd`, provenance/intent binding, and selected `signer`:

1. **Version, Provenance & Host Audience:** $W\text{.version} == \text{"3.0"}$ and $W\text{.host\_id} == \text{local\_host\_id}$. Require Section 3.2 origin, intent digest and active thin-request binding; full requests must retain successful requester-access validation, and standalone signed warrants must have client-full provenance.
2. **Kernel Peer Credentials:** $W\text{.requester\_uid} == \text{ucred.uid}$, $W\text{.requester\_gid} == \text{ucred.gid}$, and $W\text{.requester\_uid} \in \text{signer.allowed\_requester\_uids}$.
3. **Target Credentials, Supplementary GID Ceiling, & Same-UID Injection Guard:**
* $W\text{.execution\_context.target\_uid} \in \text{signer.allowed\_target\_uids}$.
* $W\text{.execution\_context.target\_gid} \in \text{signer.allowed\_target\_gids}$.
* $W\text{.execution\_context.supplementary\_gids}$ is sorted in strictly ascending order (no duplicates, max `64` entries), and every GID $g \in W\text{.execution\_context.supplementary\_gids}$ satisfies $g \in \text{signer.allowed\_supplementary\_gids}$.
* **Same-UID Injection Guard:** Resolve kernel identities through NS-05 before
  comparison. Reject shared-kernel-UID execution unless both daemon and signer
  explicitly opt in and the supported destination profile proves prevention of
  requester injection. Unknown mappings or authority fail closed. For the host
  initial-user-namespace profile only, all conditions below are required; they
  cannot authorize a rootless/nested mapping by analogy:
1. Both `/etc/sigrund/config.toml` and the signer's entry in `signers.toml` explicitly set `allow_same_uid_elevation = true`.
2. $W\text{.execution\_context.target\_uid} \ne 0$, $W\text{.command.allow\_interpreted\_script} == \text{false}$, and neither `CAP_DAC_READ_SEARCH` nor `CAP_DAC_OVERRIDE` is in $W\text{.execution\_context.capabilities}$.
3. `exec_memfd` (owned by `root:root`) has mode `0111` (`--x--x--x`, no read bits) applied via `fchmod(exec_memfd, 0111)` prior to sealing, and `/proc/sys/fs/suid_dumpable` is read and verified to equal `"0\n"`. Because `target_uid` lacks `MAY_READ` permission on the root-owned mode-`0111` `exec_memfd`, the Linux kernel's `would_dump()` sets `BINPRM_FLAGS_ENFORCE_NONDUMP` during `execveat()`, keeping `mm->dumpable = 0` (`SUID_DUMP_DISABLE`) *after* `execveat()`.
4. `/proc/sys/kernel/yama/ptrace_scope` is read and verified to be `'1'`, `'2'`, or `'3'` (ensuring the Yama LSM blocks same-UID tracing from non-ancestor processes).


* $W\text{.execution\_context.umask} \le 511$ (`0777`).


4. **Capability Ceiling and Exact Profile:** Require all five post-exec capability sets and the model-specific derivation in Section 2.2.2 to match retained evidence and remain within the explicit authority ceiling. Every capability in $W\text{.execution\_context.capabilities}$ is a valid Linux capability ($\le \text{CAP\_LAST\_CAP}$), sorted canonically without duplicates, and present in `signer.allowed_capabilities`.
5. **TTY & Standard Input Binding:**
* $W\text{.command.tty\_mode} == \text{CLIENT\_HELLO.tty\_mode}$ and $(W\text{.command.tty\_mode}, W\text{.command.stdin\_policy})$ satisfies the Section 2.3 matrix.
* If `tty_mode == "pty"`, `signer.allow_pty == true`.
* If `stdin_policy == "unrestricted_interactive"`, `signer.allow_unrestricted_stdin == true`.
* If `stdin_policy == "sha256"`, `stdin_memfd` is sealed with `F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_FUTURE_WRITE` and `hex(SHA256(stdin_memfd))` equals $W\text{.command.stdin\_sha256}$ in constant time; otherwise `stdin_sha256` is `null`.


6. **Anchored Executable Path, Snapshot Verification, & Digest Match:**
* The absolute `command.executable_path` must start with `/` and contain no trailing slash, empty component, `.` or `..` component. Configured allowed directories obey the same syntax, cannot be `/`, and have no duplicates. For the host target at startup, or within destination preparation for a selected instance, open its validated `/` and pre-open each configured root with `openat2(root_fd, root_path_without_leading_slash, ...)`, `O_PATH | O_DIRECTORY | O_CLOEXEC`, and `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`; retain its FD and `(st_dev, st_ino)`, and fail the corresponding startup/preparation if a configured root cannot be pinned. Root objects are fixed for that target and policy generation.
* **Select and strip:** Among the candidate roots for the phase (Section 2.2.1), choose the longest complete-component prefix `D` such that the path starts with `D + "/"` and has a nonempty suffix. No match is `POLICY_VIOLATION`. Strip exactly `D + "/"`; the resulting `relative_path` must be nonempty, not start with `/`, and contain no empty/`.`/`..` components. For example `/usr/bin/systemctl` under `/usr/bin` becomes `systemctl`; `/usr/bin-evil/x` does not match `/usr/bin`. Resolve only `openat2(selected_dir_fd, relative_path, &how, sizeof(how))`:
```c
struct open_how how = {
    .flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK,
    .resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV
};

```
* No absolute pathname is passed to this `RESOLVE_BENEATH` call, and no fallback to a broader root is permitted after failure. Reject symlinks/magic links, cross-mount traversal, non-regular sources, and snapshot errors under Section 2.2.1. An executable that equals a root directory is not eligible.
* At the final authorization gate, reapply selection under the winning signer's roots and require the selected root pathname and pinned `(st_dev, st_ino)` to equal the retained snapshot metadata; otherwise reject rather than resnapshot. Configure CSR roots to match signer roots. For full CSRs also require retained Section 2.2.1 requester traversal/read validation. For digest_memfd check all seals, root ownership, mode 0111 with ELF magic (0555 only for permitted scripts), and constant-time equality of SHA256(exec_memfd) to command.executable_trust.sha256. For direct models reverify their exact typed evidence, eligibility and expected profile on the retained source. Require the approved model still enabled; no fallback or recopy is permitted. `argv` length is 1..256.

7. **Deterministic `envp` Construction from Empty Environment:**
* `caller_env_allowlist` is an array of exact variable names, sorted lexicographically with no duplicates (maximum `128` entries); it replaces `env_wildcard_allowlist`, which is rejected as an unknown field. No regex or glob syntax is supported. Every `env_exact` key, allowlisted name, and `caller_env` key matches `^[A-Z_][A-Z0-9_]{0,127}$`; `env_exact` and the allowlist have zero overlap.
* **Normative Caller-Environment Denylist:** Reject an allowlisted literal name if it starts with any listed prefix or equals any listed exact name:
* **Prefixes:** `LD_`, `DYLD_`, `GIT_`, `BASH_FUNC_`, `GLIBC_`
* **Exact Names:** `PATH`, `IFS`, `CDPATH`, `ENV`, `BASH_ENV`, `PROMPT_COMMAND`, `SHELLOPTS`, `BASHOPTS`, `PS4`, `GLOBIGNORE`, `EXECIGNORE`, `TMPDIR`, `TMP`, `TEMP`, `TZ`, `LOCPATH`, `GCONV_PATH`, `GETCONF_DIR`, `HOSTALIASES`, `LOCALDOMAIN`, `NLSPATH`, `RES_OPTIONS`, `PYTHONPATH`, `PYTHONHOME`, `PYTHONSTARTUP`, `PYTHONINSPECT`, `PYTHONUSERBASE`, `PERLLIB`, `PERL5LIB`, `PERL5OPT`, `PERL5DB`, `RUBYLIB`, `RUBYOPT`, `DLN_LIBRARY_PATH`, `NODE_OPTIONS`, `NODE_PATH`, `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, `CLASSPATH`, `GOFLAGS`, `CGO_CFLAGS`, `CGO_LDFLAGS`, `RUSTFLAGS`, `CARGO_BUILD_RUSTC_WRAPPER`, `OPENSSL_CONF`, `OPENSSL_ENGINES`, `OPENSSL_MODULES`, `NSS_DEFAULT_DB_TYPE`, `KRB5_CONFIG`, `KRB5CCNAME`, `DBUS_SESSION_BUS_ADDRESS`, `XDG_CONFIG_DIRS`, `XDG_DATA_DIRS`, `XAUTHORITY`


* Require `CLIENT_HELLO.caller_env == W.caller_env`; every key must equal an entry in `caller_env_allowlist` byte-for-byte. Each value in `caller_env` and `env_exact` is a UTF-8 string of at most `4096` bytes and contains no control/BiDi characters under Section 3.3. Empty values are permitted; absent allowlisted names are omitted. No value pattern is evaluated.
* `sigrund` constructs `envp` starting from an **empty array `[]`**, inserts `"K=V"` from `env_exact` and validated `caller_env`, and sorts lexicographically by key. Host daemon environment variables are never inherited.


8. **Grant Mode & Validity Bounds:**
* $W\text{.policy.mode} \in \text{signer.allowed\_modes}$.
* `"one_time"`: `not_before` and `not_after` are integers with $0 \le (\text{not\_after} - \text{not\_before}) \le \min(\text{signer.max\_ttl\_secs}, \text{daemon.max\_onetime\_window\_secs})$.
* `"time_range"`: `not_before` and `not_after` are integers with $0 \le (\text{not\_after} - \text{not\_before}) \le \text{signer.max\_ttl\_secs}$.
* `"permanent"`: `not_before` is an integer and `not_after` is `null`.


9. **Target Instance, Mappings and Constraints (NS-04–NS-06, NS-14):**
Require the signed epoch/instance/context digest to match the same live retained
target; revalidate namespace/root/mapping observations and required lifecycle
evidence. Check destination-scoped requester and signer policy, registration and
profile revocation, original account selection and resolved numeric credentials.
Require the exact immutable security constraints, current required enforcement,
and a supported verification plan. No name resolution, account lookup or model
fallback may replace approved inputs. Apply the same liveness/constraint gates
before spawn and exec release; post-consumption failure does not refund a grant.

### 4.3 SQLite State Transaction (`/var/lib/sigrund/state.sqlite`)

Fresh provisioning sets `PRAGMA user_version = 3`. Startup reads and requires
that exact schema version before opening listeners; missing/older/newer versions
are fatal, never implicitly initialized or migrated. Initialize a fresh database
with `PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA busy_timeout = 5000;`.
The collector database also requires schema version 3. Preserve the existing
strict uniqueness/revocation semantics, and bind consumption to provenance:

```sql
CREATE TABLE consumed_grants (
    grant_id TEXT PRIMARY KEY,
    payload_sha256 BLOB NOT NULL UNIQUE,
    signer_id TEXT NOT NULL,
    requester_uid INTEGER NOT NULL,
    exec_id TEXT NOT NULL,
    request_origin TEXT NOT NULL CHECK (request_origin IN ('client_full', 'daemon_expanded_thin')),
    intent_sha256 BLOB NOT NULL CHECK (length(intent_sha256) = 32),
    execution_binding_sha256 BLOB NOT NULL CHECK (length(execution_binding_sha256) = 32),
    approval_exec_id TEXT,
    not_after INTEGER NOT NULL,
    consumed_at INTEGER NOT NULL
) STRICT;

CREATE TABLE revocations (
    target_type TEXT NOT NULL CHECK (target_type IN ('grant_id', 'payload_sha256', 'signer_id')),
    target_value TEXT NOT NULL,
    revoked_at INTEGER NOT NULL,
    reason TEXT NOT NULL,
    PRIMARY KEY (target_type, target_value)
) STRICT;

```

Define `execution_binding_sha256` as SHA-256 of canonical JCS
`{"target_binding": W.target_binding, "security_constraints": W.security_constraints}`.
Store 32 raw bytes locally and 64 lowercase hex digits in audit/collector data.
The canonical payload digest separately binds the complete resolved credentials,
command and intent. The execution binding is required in AUTH_COMMIT and its
collector `target_auth`, compared by strict equality and retained with consumption.
Collector receipts bind it transitively through the authenticated record hash and
payload digest; remote ALLOW never substitutes for local instance liveness.

For a consumed thin grant require `approval_exec_id == exec_id`; for client-full
require null. Store `intent_sha256` as 32 raw bytes; audit/collector use lowercase
hex. Consumption does not imply a child was spawned or an approval frame received;
protected outcome records resolve those facts. Never delete a consumed row after
failure, timeout or disconnect.

Define `payload_sha256_bytes` as the raw 32-byte digest of the canonical DSSE warrant payload, and `payload_sha256_hex` as its 64-character lowercase hexadecimal representation. Store the raw bytes in `consumed_grants.payload_sha256`; store digest revocations as lowercase hex text in `revocations.target_value`. All JSON/audit/collector hashes use lowercase hex. Administrative revocation input accepts valid hex in either case but normalizes it to lowercase before insertion/comparison; reject non-64-digit digest input. If SQL performs conversion, use `lower(hex(?))` with the raw digest BLOB bound to `?`; SQLite `hex()` alone is uppercase and must not be compared to lowercase text. Other revocation types keep their exact string semantics.

For **every** grant mode (`"one_time"`, `"time_range"`, `"permanent"`):

1. Execute `BEGIN IMMEDIATE TRANSACTION;`.
2. Query `clock_gettime(CLOCK_REALTIME, &now)`: assert $\text{now.tv\_sec} \ge W\text{.policy.not\_before}$ and (for `"one_time"` and `"time_range"`) $\text{now.tv\_sec} \le W\text{.policy.not\_after}$; otherwise `ROLLBACK;` and record private `EXPIRED_OR_NOT_YET_VALID`; public delivery follows Section 2.1.
3. Query `revocations` for matches on `grant_id`, canonical lowercase `payload_sha256_hex`, or `signer_id`. If found, `ROLLBACK;` and record private `REVOKED`; public delivery follows Section 2.1.
4. If $W\text{.policy.mode} == \text{"one\_time"}$, execute `INSERT INTO consumed_grants ...`. On `SQLITE_CONSTRAINT_PRIMARYKEY` or `SQLITE_CONSTRAINT_UNIQUE`, `ROLLBACK;` and record private `REPLAY_DETECTED`; public delivery follows Section 2.1.
5. Immediately before `COMMIT;`, apply Section 1.3.1's cancellation/deadline checks and `AUTHORIZING -> COMMITTING` reservation; cancel/rollback if it cannot be acquired. Execute `COMMIT;` off the control loop and reconcile cancellation before advancing to `COMMITTED`.

### 4.4 Contiguous Audit Batch Replication, Collector Deduplication, & Final Expiry Gate (Resolving Finding 2)

Because local audit events (`EXEC_READY_TO_EXEC`, `EXEC_SPAWN_FAILED`, `EXEC_EXIT`, `AUTH_ABORTED_POST_COMMIT`, `ORPHAN_CLEANUP`, `RATCHET_*_RECOVERY`) are appended between successive `AUTH_COMMIT` events, sending only `AUTH_COMMIT` records to the remote collector would create sequence gaps in `prev_record_sha256` and prevent the collector from verifying chain continuity.

Therefore, `sigrund` implements a **Contiguous Ordered Batch Replication and Authorization Protocol**:

1. **Serialized Local Audit Sequencer & Persistent Acknowledged Cursor (`remote_acked_seq`):**
* All local audit log writes and remote collector RPCs are serialized through a single internal **Audit & Replication Sequencer** in `sigrund`.
* `/var/lib/sigrund/audit_ratchet.state` persists `"remote_acked_seq": <int>` (the highest `seq` acknowledged by a valid signed collector receipt; initialized to `0` when Genesis record `seq = 0` is registered).


2. **Contiguous Batch Construction (`records[remote_acked_seq + 1 ..= auth_commit_seq]`):**
* Immediately after `COMMIT;` succeeds in Section 4.3, the Audit & Replication Sequencer appends and ratchets the local `AUTH_COMMIT` event at `seq = N`. Its authenticated event body contains `event_type: "AUTH_COMMIT"`, `seq`, `host_id`, `exec_id`, `grant_id`, `payload_sha256`, `signer_id`, `policy_mode`, `not_before`, `not_after`, `request_origin`, `intent_sha256`, `execution_binding_sha256`, and `approval_exec_id`, populated from the validated warrant and selected signer (with `exec_id` assigned by the daemon). These fields are covered by `entry_hmac`; `seq` identifies the record and is exposed as `auth_commit_seq` in `target_auth`.
* When `require_remote_audit_ack = true` is configured, the sequencer streams canonical JCS audit records from `/var/log/sigrund/audit.jsonl` with sequence numbers from `remote_acked_seq + 1` through `N` (inclusive, in strict ascending `seq` order, including all intervening readiness, exit, abort, and recovery records) in bounded `RemoteAuditBatchRequest` chunks over mTLS, with the exact HTTP and signature encoding in Section 4.4.1. The entire authorization replication operation shares the captured policy-generation `collector_rpc_timeout_ms` deadline (default `3000 ms`, immutable ceiling `3000 ms`) (`CLOCK_MONOTONIC`), including all chunks and retries; chunking does not reset it.
* **RPC Bounds:** Each request contains `1..=256` `records_jcs` entries, whose decoded UTF-8 byte lengths sum to at most `1048576` bytes (1 MiB). The complete serialized UTF-8 JSON RPC body, including JSON escaping and metadata, is also at most `1048576` bytes; no compression is used. Each canonical audit record is at most `65536` UTF-8 bytes. Both peers enforce the body limit before allocation and the count/decoded limits while parsing. All audit appends enforce the per-record limit before writing; oversized records fail closed without spawn rather than being truncated or skipped.
* **Exact `RemoteAuditBatchRequest` schema:** The request is one canonical JCS object with exactly these top-level keys and no others: `first_seq` (nonnegative integer), `last_seq` (nonnegative integer), `host_id` (nonempty canonical host ID string), `records_jcs` (array of canonical JCS record strings), and `target_auth` (either `null` or the exact object below). Require `first_seq <= last_seq`, `last_seq - first_seq + 1` computed with checked arithmetic, `records_jcs.length == last_seq - first_seq + 1`, and strict ascending record sequence numbers with no gaps. Each record string is a complete canonical audit record without its on-disk newline delimiter, at most `65536` UTF-8 bytes; the array count and aggregate/body limits are in the RPC bounds above. `target_auth: null` is required for ingestion-only/startup chunks and means no authorization or grant write. A non-null `target_auth` is allowed only when the chunk ends at its `auth_commit_seq` and has exactly these keys: `auth_commit_seq`, `exec_id`, `grant_id`, `host_id`, `not_after`, `not_before`, `payload_sha256`, `policy_mode`, `signer_id`, `request_origin`, `intent_sha256`, `execution_binding_sha256`, and `approval_exec_id`; `not_after` is an integer for `one_time`/`time_range` and `null` for `permanent`, while other fields have the Sections 3.2/3.5 bounds and origin-dependent approval_exec_id nullability. The final chunk for a pending execution has `auth_commit_seq == last_seq`; an intermediate chunk must have `target_auth == null`. Unknown fields, missing fields, duplicate keys, a non-null target on an intermediate chunk, or a null target on a final authorization chunk are rejected before ingestion/authorization.
* **Chunking:** Choose the largest nonempty contiguous prefix fitting all limits; never split a record. Wait for and verify its signed receipt, durably advance `remote_acked_seq`, then send the next prefix. Intermediate chunks set `target_auth: null` and only ingest audit records; they cannot authorize execution or consume grants. Only the final chunk ending at `N` includes non-null `target_auth` for the pending execution. Historical `AUTH_COMMIT` records in intermediate chunks are ingested without authorization. Retry a chunk with identical bytes and bounds after a lost receipt, within the same deadline. On failure, retain the last durably acknowledged cursor and fail the pending authorization; a partial upload never permits spawn.
* Example final authorization chunk:
```json
{
  "first_seq": 40,
  "host_id": "sigrun-host:sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "last_seq": 42,
  "records_jcs": [
    "<canonical-jcs-string-seq-40-EXEC_READY_TO_EXEC>",
    "<canonical-jcs-string-seq-41-EXEC_EXIT>",
    "<canonical-jcs-string-seq-42-AUTH_COMMIT>"
  ],
  "target_auth": {
    "auth_commit_seq": 42,
    "request_origin": "client_full",
    "intent_sha256": "<64 lowercase hex digits of canonical intent>",
    "execution_binding_sha256": "<64 lowercase hex digits of execution binding>",
    "approval_exec_id": null,
    "exec_id": "0192d8f4-9a00-7000-8000-112233445566",
    "grant_id": "0192d8f4-7c1b-7000-8a01-9f8b3c4d5e6f",
    "host_id": "sigrun-host:sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
    "not_after": 1793374800,
    "not_before": 1793371200,
    "payload_sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
    "policy_mode": "one_time",
    "signer_id": "mandator-alice-yubikey"
  }
}

```


3. **Collector Contiguous Chain Verification vs. Grant Authorization:**
* **Step C0 (Authenticated Host Binding and Request Shape):** The collector requires a valid mTLS client leaf certificate chaining to its configured client CA, with current validity, client-auth EKU, and applicable revocation checks. At provisioning, an administrator registers an explicit mapping `hex(SHA256(DER(leaf.SubjectPublicKeyInfo))) -> host_id` alongside the host's verification anchor (Section 7.1). Each registered client key maps to exactly one host; certificate/key rotation requires an administratively authorized mapping update. The host identity key and TLS key may differ; no relationship between them is inferred. The collector derives `authenticated_host_id` solely from this registry after TLS proof of key possession, never from the request's claimed `host_id`, certificate CN, or an unregistered SAN. Missing/ambiguous mappings or a request `host_id != authenticated_host_id` fail before chain ingestion. Checkpoint queries use the same binding. The daemon verifies the collector's server certificate against its configured trust root and expected server name, in addition to verifying signed receipts.
* C0 also rejects requests violating the RPC bounds, `len(records_jcs) != last_seq - first_seq + 1`, noncontiguous sequence numbers, or records whose authenticated body `host_id` differs from `authenticated_host_id`. Record parsing is strict canonical JCS with duplicate keys rejected; the collector selects all chain and deduplication state by `authenticated_host_id`.
* The collector maintains per `host_id`: `collector_next_seq`, `collector_expected_key` ($K_{\text{collector\_next\_seq}}$), `collector_last_record_sha256`, and the durable `remote_consumed_grants` table:
```sql
CREATE TABLE remote_consumed_grants (
    host_id TEXT NOT NULL,
    grant_id TEXT NOT NULL,
    payload_sha256 TEXT NOT NULL,
    first_exec_id TEXT NOT NULL,
    request_origin TEXT NOT NULL,
    intent_sha256 TEXT NOT NULL,
    execution_binding_sha256 TEXT NOT NULL,
    approval_exec_id TEXT,
    first_seq INTEGER NOT NULL,
    consumed_at INTEGER NOT NULL,
    PRIMARY KEY (host_id, grant_id),
    UNIQUE (host_id, payload_sha256)
) STRICT;

```


* **Step C1 (Contiguous Audit Chain Ingestion):** The collector iterates through `records_jcs` in ascending `seq` order (`first_seq ..= last_seq`):
* If `r.seq < collector_next_seq`: verifies `SHA256(r) == stored_record_sha256[r.seq]` (tolerating idempotent re-transmission of previously ingested records if an earlier network receipt was dropped in transit). If the bytes differ from the stored record, rejects immediately with `AUDIT_CHAIN_DIVERGENCE`.
* If `r.seq == collector_next_seq`: verifies `r.prev_record_sha256 == collector_last_record_sha256` and `r.entry_hmac == HMAC_SHA256(collector_expected_key, r_body_jcs)`, durably stores `r`, ratchets `collector_expected_key` to $K_{r.\text{seq}+1}$, sets `collector_last_record_sha256 = hex(SHA256(r))`, and increments `collector_next_seq`.
* If `r.seq > collector_next_seq`: rejects with `AUDIT_SEQUENCE_GAP`.


* **Step C2 (Target Execution Authorization & Mode-Specific Deduplication):**
After ingesting the audit chain through `last_seq` (so the host's audit chain remains contiguous even if the target execution is denied), the collector handles `target_auth` as follows:
* If `target_auth == null`, skip authorization and all grant-consumption writes, and return an ingestion-only receipt with `decision: "ACK_ONLY"`.
* Otherwise, require `target_auth.auth_commit_seq == last_seq`, load the parsed authenticated record at that sequence (including on retransmission), and require `event_type == "AUTH_COMMIT"`. Compare **every** target field by strict typed equality to that record: `exec_id`, `grant_id`, `payload_sha256`, `signer_id`, `policy_mode`, `not_before`, `not_after`, `host_id`, `request_origin`, `intent_sha256`, `execution_binding_sha256`, and `approval_exec_id`; also require `target_auth.host_id == request.host_id == authenticated_host_id`. Missing, extra, ill-typed, or unequal target fields fail with `AUTH_RECORD_MISMATCH` without any authorization or grant-consumption write. Matching the sequence alone is insufficient. Require client_full with null approval_exec_id, or daemon_expanded_thin with approval_exec_id equal to exec_id and policy_mode one_time; require 64-digit lowercase intent_sha256 and execution_binding_sha256. Collector approval cannot turn a historical thin grant into a new execution. Validity values must be integer timestamps, with a non-null `not_after >= not_before` for `one_time`/`time_range`, and `not_after: null` for `permanent`; unknown policy modes are rejected.
* After these comparisons, derive all authorization inputs, deduplication keys, and authorization receipt fields **from the authenticated record**, not from the supplied `target_auth` object:
1. Verify `not_before <= collector_now` and (if `policy_mode != "permanent"`) `collector_now <= not_after`; on failure return a signed `DENY_EXPIRED` receipt without grant consumption.
2. Verify `(host_id, grant_id)`, `(host_id, payload_sha256)`, and `signer_id` are not revoked on the collector; on failure return a signed `DENY_REVOKED` receipt without grant consumption.
3. Branch by the authenticated `policy_mode`:
* **`"one_time"`:** Attempts `INSERT INTO remote_consumed_grants (host_id, grant_id, payload_sha256, first_exec_id, request_origin, intent_sha256, execution_binding_sha256, approval_exec_id, first_seq, consumed_at) VALUES (...)`.
* If the insert succeeds: sets `decision = "ALLOW"`.
* If a uniqueness conflict occurs on `(host_id, grant_id)` or `(host_id, payload_sha256)`: if the existing row exactly matches the authenticated record's `grant_id`, `payload_sha256`, `exec_id` (`first_exec_id`), and `seq` (`first_seq`), plus the exact stored provenance/intent/binding fields (indicating an in-window retry of the same authorization), sets `decision = "ALLOW"`; otherwise (e.g., a second redemption attempt after a local SQLite database rollback) sets `decision = "DENY_REPLAY"`.


* **`"time_range"` or `"permanent"`:** Permits repeated `(host_id, grant_id)` and `(host_id, payload_sha256)` across distinct `exec_id` values and sets `decision = "ALLOW"`.


* **Step C3 (Signed Collector Receipt):**
After durably committing the ingested chain checkpoint and any grant-consumption decision, the collector returns a DSSE/JCS receipt (`payloadType: "application/vnd.sigrun.collector-receipt.v3+json"`) signed with the collector private key corresponding to the configured `collector_public_key`:
```json
{
  "acked_through_seq": 42,
  "acked_through_sha256": "<sha256-of-record-42>",
  "decision": "ALLOW",
  "exec_id": "0192d8f4-9a00-7000-8000-112233445566",
  "grant_id": "0192d8f4-7c1b-7000-8a01-9f8b3c4d5e6f",
  "host_id": "sigrun-host:sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "payload_sha256": "4b227777d4dd1fc61c6f884f48641d02b4d121d3fd328cb08b5531fcacdabf8a",
  "policy_mode": "one_time",
  "receipt_timestamp": 1793371205
}

```


* For ingestion-only chunks (`target_auth: null`), the same signed receipt schema uses `decision: "ACK_ONLY"` and `exec_id`, `grant_id`, `payload_sha256`, and `policy_mode` all `null`; `host_id` is the authenticated host and `acked_through_seq`/`acked_through_sha256` identify that chunk's last record. `ACK_ONLY` never permits spawn.

* **Daemon Receipt Handling & Cursor Advancement:**
* For each chunk ending at `M`, require the expected DSSE payload type, valid signature under the configured collector key, exact local `host_id`, `acked_through_seq == M`, and `acked_through_sha256 == hex(SHA256(record_M))`. For every ingestion-only chunk (including all startup chunks), require `ACK_ONLY` and the null authorization fields. For the final authorization chunk (`M == N`), require `exec_id`, `grant_id`, `payload_sha256`, and `policy_mode` to equal the pending authenticated `AUTH_COMMIT` record, and an authorization decision rather than `ACK_ONLY`. Only then durably update `remote_acked_seq = M` in `/var/lib/sigrund/audit_ratchet.state`, preserving the current ratchet state.
* Only a verified final `ALLOW` receipt authorizes proceeding to the final expiry/approval-delivery gate; all collector denial codes remain private and map to scheduled TIMEOUT before approval. A verified `DENY_REPLAY` maps to local `REPLAY_DETECTED`; `DENY_EXPIRED` maps to `EXPIRED_OR_NOT_YET_VALID`; and `DENY_REVOKED` maps to `REVOKED`. Each verified denial appends `AUTH_ABORTED_POST_COMMIT` and never calls `clone3()`; the denial receipt may advance the acknowledged cursor. `AUTH_RECORD_MISMATCH`, malformed/mismatched receipts, other collector errors, and cumulative RPC timeout append `AUTH_ABORTED_POST_COMMIT` when applicable and record private `REMOTE_AUDIT_FAILED` (public TIMEOUT); invalid receipts never advance the cursor. The daemon accepts only the exact decision/field combinations of Section 4.4.1.


4. **Final Authorization and Spawn Gates:** After durable local AUTH_COMMIT and
   any required verified collector ALLOW, recheck cancellation, `now < D`, all
   final authorization predicates, and realtime warrant validity. Enter approval
   delivery under Section 1.3.1. No receipt extends D. A denial/late completion
   takes scheduled TIMEOUT and records any consumed grant without execution.
   After complete APPROVED delivery, separately reserve `APPROVED -> SPAWNING`
   and recheck connection, cancellation and warrant validity immediately before
   clone. A post-approval expiry/setup failure produces an execution result, never
   a second auth decision or refund. Required AUTH_COMMIT precedes any post-commit
   abort record, including reconciliation after socket loss.

### 4.4.1 Exact Remote RPC Framing and Collector Signature Encoding

* **Transport and Message Boundaries:** Use HTTPS with TLS 1.3 and the Section 4.4 mTLS/hostname checks, HTTP/1.1 (ALPN `http/1.1`), and no upgrade, HTTP/2, pipelining, or concurrent requests on one connection. `POST /v3/audit/batch` carries the `RemoteAuditBatchRequest`. `POST /v3/audit/checkpoint` carries exactly `{ "host_id": "<local_host_id>" }`. Each request and response has exactly one `Content-Type: application/json` and one `Content-Length` (unsigned decimal body byte count, no sign or leading zero except `0`). Headers are case-insensitive, at most `8192` bytes total including the terminating CRLFCRLF. Reject duplicate length/type headers, `Transfer-Encoding`, non-identity `Content-Encoding`, interim responses, trailers, and body bytes beyond the declared length. Each body consists of exactly that many UTF-8 bytes; read no unbounded EOF-delimited body. Reused connections send the next request only after consuming the complete prior response. The batch request bound is `1048576` body bytes; checkpoint requests and error responses are at most `4096`; signed responses are at most `16384`. Check lengths before body allocation. Header parsing, TLS handshakes, sends, reads, and retries all share the operation's captured policy-generation cumulative `collector_rpc_timeout_ms` deadline; use nonblocking network I/O off or integrated with the control loop, never a blocking RPC on it.
* **JSON and HTTP Results:** Successful RPCs, including authorization denials and `ACK_ONLY`, return HTTP `200` with the DSSE envelope below. Batch/checkpoint request bodies and DSSE envelope/payload JSON are canonical JCS with no BOM, whitespace suffix, or newline; reject duplicate/unknown fields, wrong types, invalid UTF-8, or nesting beyond `8`. Checkpoint requests use the same authenticated host mapping as batches. A rejected RPC returns a final non-200 HTTP status (400 for bad input/chain mismatch, 403 for host authorization failure) and exactly `{ "error": "<code>" }` with an ASCII code of `1..=128` bytes; it never authorizes execution or advances the daemon cursor. Unrecognized status/code, malformed framing, TLS failure, and timeout fail closed. Error bodies are diagnostic, not signed receipts. If any record ingestion committed before an error, retry/checkpoint reconciliation still uses the authenticated durable chain state.
* **Pinned Receipt Key and DSSE Envelope:** Configure `collector_key_id` (nonempty ASCII, maximum `128` bytes) and `collector_public_key` as strict padded RFC 4648 standard Base64 encoding of one raw **32-byte Ed25519 public key**. For both signed response kinds, the outer object has exactly `payload`, `payloadType`, and `signatures`, with exactly one signature object containing exactly `keyid` and `sig`. `keyid` must equal the configured ID. `payload` is strict padded RFC 4648 standard Base64 of the canonical JCS payload bytes (maximum `4096` decoded bytes), with no whitespace or alternate alphabet. `sig` is the same Base64 encoding of the raw **64-byte Ed25519 signature `R || S`**, exactly `88` ASCII characters; it is not an SSH/OpenPGP packet or a signature over the outer JSON. Sign DSSE v1 PAE over the actual UTF-8 `payloadType` and decoded payload bytes, using the decimal byte lengths for that type and payload as in Section 3.1 (not the warrant's fixed type length). Verify via strict Ed25519 verification, rejecting non-canonical scalars and small-order points. For every Base64 string require `encode(decode(value)) == value` to reject non-canonical padding bits. No adapter negotiation or key selection from untrusted `keyid` is allowed.
* **Receipt Payloads:** Batch response `payloadType` is exactly `application/vnd.sigrun.collector-receipt.v3+json`; its payload has exactly the fields shown in C3. Allowed `decision` values are `ALLOW`, `DENY_REPLAY`, `DENY_EXPIRED`, `DENY_REVOKED`, and `ACK_ONLY`, with C2's mode/nullability rules. `acked_through_seq` and `receipt_timestamp` are nonnegative integers; record/payload digests are exactly 64 lowercase hex digits, and identifiers are the authenticated record values. A checkpoint uses type `application/vnd.sigrun.collector-checkpoint.v3+json` and exactly `host_id`, `collector_last_seq`, `collector_last_record_sha256`, and `receipt_timestamp`; the sequence is a nonnegative integer and digest is 64 lowercase hex digits for its durable last record. Genesis must already be registered; an unknown host has no implicit zero checkpoint. Verify the signature/type, exact local host binding, and field shapes before Section 7.3 reconciliation. Receipt timestamps are collector UTC Unix seconds; they do not replace the daemon's monotonic operation deadline or final warrant-expiry check.

---

## 5. Child Cgroup Setup, Mount Flags, Descriptor Table, and Credential Transition

The host baseline in Sections 5.1–5.3 remains one execution profile. Namespace
targets must use the validated entry/placement plan in Section 5.4 and the
verification contract in Section 5.5. Do not apply the host clone flags,
credential calls or mount recipe unchanged across user namespaces. The final
FD layout, syscall-only transition, bounded errors and ownership invariants
apply to both profiles.

### 5.1 Per-Invocation Job Cgroup & `clone3()` Flags

For each authorized execution `exec_id`, `sigrund` creates `G/jobs/job-<exec_id>` beneath the pinned delegated root from Section 1.2 and opens `cgroup_fd`. **Before `clone3()`**, write and read back all of these root-controlled limits:

| Job Cgroup File | Default Value | Daemon Configuration |
| --- | --- | --- |
| `memory.max` | `268435456` (256 MiB) | `job_memory_max_bytes`, positive finite integer |
| `memory.swap.max` | `0` | `job_memory_swap_max_bytes`, finite nonnegative integer |
| `memory.oom.group` | `1` | Required, not warrant-overridable |
| `pids.max` | `128` | `job_pids_max`, positive finite integer |

The daemon config may set other finite values; `max`/unlimited values are rejected and warrants cannot raise these limits. Missing files, failed writes, or unequal read-back fail closed as `SPAWN_FAILED` before any job child exists. The startup probe verifies these interfaces, including swap and group-OOM control, before accepting requests. `memory.max`/`pids.max` cover descendants remaining in the job cgroup; the process count includes threads. Allocation/fork failures and OOM termination are normal workload outcomes, with the primary child's actual wait status reported. These per-job limits supplement, rather than replace, snapshot RAM and active-socket quotas; they do not bound aggregate host usage below the sum of admitted jobs or resources charged elsewhere. Host-root/out-of-profile jobs may evade containment as described in Section 1.1; finite initial cgroup limits do not strengthen that guarantee.


* For the host baseline, if `CAP_SYS_ADMIN` is **not** in $W\text{.execution\_context.capabilities}$, `sigrund` calls `clone3()` with `CLONE_INTO_CGROUP | CLONE_PIDFD | CLONE_NEWNS | CLONE_NEWCGROUP`.
* For the host baseline, if `CAP_SYS_ADMIN` **is** in $W\text{.execution\_context.capabilities}$, `sigrund` calls `clone3()` with `CLONE_INTO_CGROUP | CLONE_PIDFD`.
* In both cases, initialize `struct clone_args` with `args.flags` as above, `args.exit_signal = SIGCHLD`, `args.cgroup = cgroup_fd`, and `args.pidfd` pointing to writable parent storage for the returned pidfd; all unused fields are zero. `SIGCHLD` must not be ORed into `args.flags`. This makes every primary job an ordinary waitable `SIGCHLD` child for the Central Reaper.

### 5.2 Deterministic Child Descriptor Table (`FDs 0..=4`)

| Child FD | Role | `FD_CLOEXEC` State | Behavior Across `execveat(3, "", argv, envp, AT_EMPTY_PATH)` |
| --- | --- | --- | --- |
| **`0`** | `stdin` | Cleared (`0`) | Inherited (`/dev/null`, sealed `stdin_memfd` rewound to offset `0`, client FD, or PTY slave). |
| **`1`** | `stdout` | Cleared (`0`) | Inherited by executed program. |
| **`2`** | `stderr` | Cleared (`0`) | Inherited by executed program. |
| **`3`** | Retained executable FD (memfd or direct source/verified alias) | **Set (`FD_CLOEXEC`)** when `allow_interpreted_script == false`; **Cleared (`0`)** when `true`. | Closed by kernel before ELF entry point; kept open only if `binfmt_script` rewrites `argv` to `/dev/fd/3`. |
| **`4`** | `sync_pipe_w` | **Set (`FD_CLOEXEC`)** | Used for the two-frame handshake (`READY_TO_EXEC` before `execveat()`, plus `EXECVEAT_ERR` if `execveat()` returns `-1`); closed by the kernel when `execveat()` succeeds. |
| **`5..~0U`** | Closed | Closed via `close_range(5, ~0U, 0)` | Absent in child. |

### 5.3 10-Step Child Transition Sequence

The daemon is multithreaded. Before `clone3()`, prepare immutable argv/envp
storage, descriptor actions and bounded buffers for the setup checks. From
the child return of `clone3()` until `execveat()` or `_exit()`, use only an
audited syscall-only/async-signal-safe path: no heap allocation, Rust formatting,
logging, mutexes, unwinding, general library parsers or destructor-driven exit.
Mountinfo verification uses a bounded allocation-free parser and fails closed
on overflow. Preserve syscall errno when emitting a setup-error frame.
The parent registers the returned PID/pidfd with the Central Reaper before
processing queued child-exit notifications; a fast exit must not be discarded
as an untracked orphan. These requirements also apply to hook child setup.

On any error in Steps 1–10 prior to `execveat()`, preserve errno, attempt one
8-byte `{ u32 step, i32 errno }` error frame (`step` in `1..=10`) on the tracked
sync-pipe write descriptor, then call `_exit(127)`. Initially this is the actual
inherited `sync_pipe_w`, not descriptor number 4. Duplicate that write end
first to a safe temporary descriptor and update the tracked number only after
a successful syscall. Keep it valid through every subsequent duplication and
remap; change the tracked number to 4 only after `dup3(tmp_sync, 4, O_CLOEXEC)`
succeeds. All other source descriptors are duplicated before remapping 0–4.
Thus unshare/duplication failures, EMFILE, and initially closed or unrelated
FDs 0–4 cannot cause an error write into an unrelated inherited descriptor.
If the error write fails or is short, exit without exec; the parent treats
missing/partial evidence as `SPAWN_FAILED`. Apply the same rule to hook H1,
using the actual hook sync writer until FD 3 is successfully installed.

The host-baseline setup sequence is (namespace profiles use Section 5.4):

1. **Descriptors, Recursive Read-Only Cgroup Mount, & Session:**
* Call `unshare(CLONE_FILES)`.
* Duplicate `sync_pipe_w` first, then `child_stdin`, `child_stdout`, `child_stderr`, and the retained executable FD to temporary descriptors `>= 5` via `fcntl(fd, F_DUPFD_CLOEXEC, 5)`, tracking the error writer as specified above.
* Assign `dup2(tmp_in, 0)`, `dup2(tmp_out, 1)`, `dup2(tmp_err, 2)`, `dup3(tmp_exec, 3, exec_cloexec_flag)`, `dup3(tmp_sync, 4, O_CLOEXEC)`, and call `close_range(5, ~0U, 0)`.
* If spawned without `CAP_SYS_ADMIN` (with `CLONE_NEWNS | CLONE_NEWCGROUP`), execute the following exact mount lock sequence while the setup child still has its initial mount authority. The existing cgroup v2 mount is already copied into the child's mount namespace: make propagation private, then apply `mount_setattr()` directly to that mount and its submounts. Do not bind `/sys/fs/cgroup` onto itself. Every syscall failure is a Step 1 failure; unsupported kernels fail closed rather than using a fallback mount operation. Here `fail_step1(err)` writes `{ step: 1, errno: err }` to `FD 4` and calls `_exit(127)`:
```c
if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1)
    fail_step1(errno);
struct mount_attr attr = {
    .attr_set = MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC,
};
if (syscall(SYS_mount_setattr, AT_FDCWD, "/sys/fs/cgroup",
            AT_RECURSIVE, &attr, sizeof(attr)) == -1)
    fail_step1(errno);
struct statvfs stv;
if (statvfs("/sys/fs/cgroup", &stv) == -1)
    fail_step1(errno);
unsigned long req = ST_RDONLY | ST_NOSUID | ST_NODEV | ST_NOEXEC;
if ((stv.f_flag & req) != req)
    fail_step1(EPERM);

```
* Read `/proc/self/mountinfo` to confirm the mount at `/sys/fs/cgroup` is `cgroup2` and it and every descendant mount have `ro,nosuid,nodev,noexec` and no shared/slave propagation tags. A missing cgroup v2 mount, parse failure, or flag mismatch is a Step 1 failure. The daemon's mount namespace must remain unchanged. V-18 tests this exact syscall sequence before credential drop.


* Reset daemon-modified signal dispositions (including `SIGPIPE` and `SIGCHLD`) to `SIG_DFL` and clear the signal mask with `sigprocmask(SIG_SETMASK, &empty_set, NULL)` before exec; never leak the daemon's blocked `SIGCHLD` or ignored `SIGPIPE` into the target.
* Call `setsid()`. (Do not call `setpgid()`.) If `tty_mode == "pty"`, call `ioctl(0, TIOCSCTTY, 0)`.


2. **Working Directory & Umask:** Call `chdir(W.command.cwd)` and `umask(W.execution_context.umask)`.
3. **Bounding Set Reduction:** For `cap` in `0..=CAP_LAST_CAP`, if `cap` $\notin C$, call `prctl(PR_CAPBSET_DROP, cap, 0, 0, 0)`.
4. **Lock Securebits (`0x2f`):** Call `prctl(PR_SET_SECUREBITS, SECBIT_KEEP_CAPS_LOCKED | SECBIT_NO_SETUID_FIXUP | SECBIT_NO_SETUID_FIXUP_LOCKED | SECBIT_NOROOT | SECBIT_NOROOT_LOCKED, 0, 0, 0)`.
5. **GIDs:** Call `setgroups(supplementary_gids.len(), supplementary_gids.as_ptr())` and `setresgid(target_gid, target_gid, target_gid)`.
6. **UIDs:** Call `setresuid(target_uid, target_uid, target_uid)`.
7. **Capability Sets (`P = E = I = C`):** Call `capset()` (`_LINUX_CAPABILITY_VERSION_3`) setting `permitted = C`, `effective = C`, `inheritable = C`.
8. **Ambient Capabilities (`Amb = C`):** Call `prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_CLEAR_ALL, 0, 0, 0)`, then for each `cap` $\in C$, call `prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_RAISE, cap, 0, 0)`.
9. **Lock `no_new_privs`:** Call `prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)`.
10. **Read-Back Verification Gate, `READY_TO_EXEC` Token, & `execveat()`:**
* Assert via kernel syscalls: `getresuid() == (target_uid, target_uid, target_uid)`, `getresgid() == (target_gid, target_gid, target_gid)`, `getgroups() == supplementary_gids`, `prctl(PR_GET_SECUREBITS) == 0x2f`, `prctl(PR_GET_NO_NEW_PRIVS) == 1`, `capget() == (P: C, E: C, I: C)`, and for all `0..=CAP_LAST_CAP`, `PR_CAP_AMBIENT_IS_SET` and `PR_CAPBSET_READ` equal `1` iff `cap` $\in C$.
* Write the 8-byte `READY_TO_EXEC` frame `{ step: 0, errno: 0 }` to `FD 4`; call `_exit(127)` without exec unless the write returns exactly `8`.
* Call `syscall(SYS_execveat, 3, "", argv_ptrs, envp_ptrs, AT_EMPTY_PATH)`.
* If `execveat()` returns, write the 8-byte `EXECVEAT_ERR` frame `{ step: 11, errno: errno }` to `FD 4` and call `_exit(127)`.


---

### 5.4 Namespace Entry, Placement and Lifecycle (NS-09, NS-10, NS-12)

**NS-09 — Host-supervised placement.** Cgroup namespace membership changes the
view; it does not move a process. Preserve finite memory/PID limits and lifecycle
ownership in host-controlled per-job cgroups. Do not blindly migrate into
manager-owned cgroups or assume `CLONE_INTO_CGROUP` permissions survive userns
entry. The initial candidate is a trusted launcher placed in the job cgroup
before namespace entry, with final children inheriting placement. Phase 0 must
verify this against supported userns ownership/delegation, visible cgroup roots,
manager teardown and escape paths before it becomes a supported recipe.
Account for launchers and helpers in process limits. Refuse profiles whose
required containment/placement cannot be enforced.

**NS-10 — Dedicated executor.** The host coordinator never changes its namespaces.
Use fresh, dedicated helpers with bounded IPC; prepare all storage, descriptor
actions and library-derived transition data before the critical syscall-only
child path. Helper namespace entry must not load untrusted destination libraries
or leak daemon keys, management FDs or unrelated host roots. Close acquired
namespace/root FDs before target execution after establishing the intended
context; retain independent supervising references in the host.

A supported entry plan must explicitly specify:

1. Namespace set, owning user namespaces, required capabilities and entry order;
   already-shared namespaces and unsupported ancestors/nesting are handled
   deliberately, not by ignoring `setns()` failures.
2. Pinned root establishment and declared private mount isolation, propagation,
   cwd resolution and prevention of host-root escape through inherited FDs.
3. PID/time namespace entry followed by creation of the actual workload child;
   entering a PID namespace alone does not move the calling task into it.
4. Host-visible PID/pidfd acquisition, launcher/final-child parentage, registration
   barriers, tracer ownership, reaping and launcher-death behavior.
5. Exact supplementary groups, GID/UID, securebits, capabilities, NNP and security
   transitions, with before/after readback and mapping-aware host observations.

`setgroups=deny`, nested maps, idmapped mounts and namespaced file capabilities
need separate supported cases; host root does not make them interchangeable.
Do not ignore a failed `setgroups()` or silently retain launcher groups. Initial
file-capability support remains the host ABI case in Section 2.2.2; expansion
requires its own evidence and transition tests. Setup failures cannot run loader
or target instructions. Namespace/root/credential checks must reference the
actual final child, not only the launcher.

**NS-12 — Lifecycle and disclosure.** The host daemon owns replay/consumption,
audit, output, deadlines, cancellation, reaping and cleanup. Monitor anchor death,
required resolver loss, container teardown and helper/tracer death. Invalidate
pending authorization and cancel active jobs on loss of required instance
liveness; never substitute a replacement. Kill/reap all supervised descendants
within the declared containment boundary. Retain target/helper/worker leases
until cleanup actually finishes, including blocked filesystem operations.

Keep existing public outcomes: all unsuccessful admitted thin requests receive
uniform TIMEOUT at the fixed deadline; target existence, accounts and LSM errors
stay private. APPROVED means durable authorization and complete response delivery
must precede workload spawn. Preparation helpers are not authorized workload
execution. Readiness/results remain separate. Pre-authorization failures do not
consume grants; post-consumption spawn, liveness or verification failures do not
refund them. Explicit rejection remains restricted to validated full requests.

### 5.5 Execution Security Profiles and Actual-State Verification (NS-11)

Namespace entry is not manager-exec policy reproduction. Each immutable resolved
profile declares what is entered, configured, verified, or unsupported:

| Property | Required contract |
| --- | --- |
| Namespaces/root | Pinned source context, declared child isolation, verified final membership/root |
| Credentials/capabilities | Composed mappings; exact groups/UID/GID and before/after capability sets; securebits and NNP |
| Cgroups | Host-owned limits, placement, lifecycle interaction and containment classification |
| SELinux | Complete context including MLS/MCS range; supported transition; actual enforcement and post-exec context |
| AppArmor | Policy namespace, profile/stack, mode and supported transition; actual post-exec confinement |
| Seccomp/other restrictions | Explicit supported configuration and installation/verification strategy, never inferred from another task's namespace |

Constraints compose across applicable LSMs. Disabled, unreadable, unconfined,
permissive/complain and enforcing states are distinct; none substitutes for
required enforcement. A profile name or label does not freeze policy bytes.
Define observable policy version/reload invalidation and revalidation before
release; if the required change detection cannot be guaranteed, reject that
combination. An immutable sigrund profile digest binds requested constraints,
not the kernel's mutable policy implementation.

Do not silently remove NNP or tracing to make an LSM transition work. Verify
supported combinations on actual enforcing systems. A successful transition
request does not prove the resulting confinement. Extend the exec-stop verifier
to inspect effective confinement before releasing target/loader instructions,
including memfd paths when the profile requires it. Reject combinations for
which this guarantee is unavailable. Exec-stop rejection cannot undo kernel
state changes already performed by exec, so the supported profile must also
account for those effects.

Memfd does not preserve source-file labels/path semantics. A profile requiring
those semantics must use a validated compatible executable model, with no
post-signing switch. Pinned namespaces/root/executable FDs do not freeze mutable
libraries, root filesystems or LSM policy. Existing target seccomp filters cannot
generally be extracted and copied; exact manager-policy reproduction requires
additional configuration integration. Daemon packaging needs separate LSM policy
for sockets, helpers, state, cgroups and verification; target policy is not a
substitute for daemon policy.


## 6. Hook Sandbox, `pivot_root` Sequence, and Evaluation Contract (Resolving Finding 5)

### 6.1 Hook Quotas & Complete `pivot_root` Sandbox Sequence

* **Admission Quotas:** Each request captures `max_active_hooks_per_uid`, `max_active_hooks_global`, `hook_invocations_per_uid`, and `hook_window_secs` from its policy generation (defaults `1`, `8`, `5`, and `60`). `sigrund` permits at most the captured active pipelines per UID/global and enforces the captured token bucket for unsigned invocations; admitted excess requests enter SILENT_TIMEOUT without target lookup. Thin review-capacity reservations remain held until their public outcome even after the actual hook exits; process/FD ownership lasts through real cleanup. Reloads affect only requests admitted under the new generation; active hook pipelines retain their captured quotas and window.
* **Per-Hook Cgroup & Namespace Isolation:** Each hook executable in `/etc/sigrund/hooks.d/` (regular files owned by `root:root`, mode `0755`, evaluated in lexicographical filename order) is spawned into `G/hooks/hook-<hook_exec_id>` beneath the pinned delegated root from Section 1.2 with `memory.max = 67108864` (64 MiB), `memory.swap.max = 0`, and `pids.max = 32`, via `clone3()` with `args.flags = CLONE_NEWNS | CLONE_NEWIPC | CLONE_NEWPID | CLONE_NEWCGROUP | CLONE_INTO_CGROUP | CLONE_PIDFD`, `args.exit_signal = SIGCHLD`, `args.cgroup = hook_cgroup_fd`, and `args.pidfd` pointing to writable parent storage for the returned pidfd (all unused fields zero). The separate exit signal makes hooks ordinary waitable children of the daemon in the daemon's PID namespace, including hooks that die before exec.
* The hook sync pipe uses the same 8-byte native-endian `{ u32 step, i32 errno }` frame format as Section 2.4. A setup failure reports `{ step: 1..4, errno: >0 }` (H1..H4) and exits `127`; after descriptor assignment the write end is `FD 3`.

1. **Step H1 (Contiguous `FDs 0..=3` & `close_range(4, ~0U, 0)`):**
* Call `unshare(CLONE_FILES)`.
* Duplicate `hook_sync_pipe_w` first, then `hook_stdin`, `hook_stdout`, and `hook_stderr` to temporary FDs `>= 4`, tracking the actual error writer according to Section 5.3 until FD 3 is installed.
* Assign `dup2(tmp_in, 0)`, `dup2(tmp_out, 1)`, `dup2(tmp_err, 2)`, and `dup3(tmp_sync, 3, O_CLOEXEC)`.
* Call `close_range(4, ~0U, 0)` and `setsid()`. Reset daemon-modified signal dispositions to `SIG_DFL` and clear the blocked signal mask before hook exec, as for jobs.


2. **Step H2 (Mount Isolation & Complete `pivot_root` Preparation While Privileged):**
* Call `mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)` so no mount changes propagate to the host namespace.
* Ensure `/run/sigrund/hook-stage` exists (`0755 root:root`) and mount a `16 MiB` `tmpfs` (`MS_NOSUID | MS_NODEV | MS_NOEXEC`, `"size=16m,mode=0755"`) on `/run/sigrund/hook-stage`.
* Create the staging directory tree inside `/run/sigrund/hook-stage`:
* `/run/sigrund/hook-stage/oldroot` (`0700`)
* `/run/sigrund/hook-stage/proc` (`0555`)
* `/run/sigrund/hook-stage/tmp` (`1777`)
* `/run/sigrund/hook-stage/usr`, `/run/sigrund/hook-stage/bin`, `/run/sigrund/hook-stage/lib`, `/run/sigrund/hook-stage/lib64` (if `/lib64` exists on host)
* `/run/sigrund/hook-stage/etc/resolv.conf` (empty file target for file bind mount), `/run/sigrund/hook-stage/etc/ssl`, `/run/sigrund/hook-stage/etc/ca-certificates`, `/run/sigrund/hook-stage/etc/sigrund/hooks.d`, `/run/sigrund/hook-stage/etc/sigrund/hook-secrets`


* For each read-only path (`usr`, `bin`, `lib`, `lib64`, `etc/resolv.conf`, `etc/ssl`, `etc/ca-certificates`, `etc/sigrund/hooks.d`, `etc/sigrund/hook-secrets`), call `mount(src, dst, NULL, MS_BIND | MS_REC, NULL)` followed by `syscall(SYS_mount_setattr, AT_FDCWD, dst, AT_RECURSIVE, &ro_attr, sizeof(ro_attr))` with `MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV`.
* Mount a fresh `proc` instance at `/run/sigrund/hook-stage/proc` (`mount("proc", "/run/sigrund/hook-stage/proc", "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, NULL)`).
* Mount a `16 MiB` writable `tmpfs` at `/run/sigrund/hook-stage/tmp` (`mount("tmpfs", "/run/sigrund/hook-stage/tmp", "tmpfs", MS_NOSUID | MS_NODEV | MS_NOEXEC, "size=16m,mode=1777")`).
* Change directory to the new root: `chdir("/run/sigrund/hook-stage")`.
* Execute the pivot: `syscall(SYS_pivot_root, ".", "oldroot")`.
* Change working directory to the pivoted root: `chdir("/")`.
* Detach the old root hierarchy: `umount2("/oldroot", MNT_DETACH)`.
* Remove the empty mountpoint directory: `rmdir("/oldroot")`.
* Seal the root `tmpfs` itself read-only (`syscall(SYS_mount_setattr, AT_FDCWD, "/", 0, &ro_root_attr, sizeof(ro_root_attr))` with `MOUNT_ATTR_RDONLY | MOUNT_ATTR_NOSUID | MOUNT_ATTR_NODEV | MOUNT_ATTR_NOEXEC`), leaving `/tmp` as the only writable mount in the namespace.


3. **Step H3 (Drop All Capabilities & Credentials):**
* Drop all bounding capabilities (`0..=CAP_LAST_CAP`), call `setgroups(0, NULL)`, `setresgid(sigrun_hook_gid, ...)`, `setresuid(sigrun_hook_uid, ...)`, zero `Permitted`, `Effective`, `Inheritable`, and `Ambient` capabilities, and set `PR_SET_NO_NEW_PRIVS = 1`.


4. **Step H4 (Verify & Execute):**
* Verify `uid == sigrun_hook_uid`, `gid == sigrun_hook_gid`, `CapEff == CapPrm == CapInh == 0`, and `NoNewPrivs == 1`; write the full 8-byte `READY_TO_EXEC` frame `{ step: 0, errno: 0 }` to `FD 3` and call `execve(hook_path, [hook_path], ["PATH=/usr/bin:/bin", "HOME=/tmp", "LANG=C.UTF-8"])`. A readiness-write failure exits `127` without exec. If `execve()` returns, write `{ step: 5, errno: errno }` to `FD 3` and exit `127`. The readiness frame proves setup only, with the same exec ambiguity as the job handshake.


### 6.2 Trusted Hook Input, Results, and Confidential Evaluation

Hooks are trusted approval components, not requester-controlled plugins. Every
hook executable/configuration and parent directory is root-controlled and not
requester-writable. When enabled, require a dedicated non-login UID/GID explicitly
configured as `sigrun_hook_uid/gid`; UID 65534 or another shared service identity
is forbidden. Reserve that host kernel principal from requester and mapped target
UID/GID/supplementary-group policy; compare composed kernel identities rather
than unrelated namespace-local numbers. Protect process inspection, IPC, files,
logs and inherited FDs from ordinary requesters; prevent core dumps and credential
or CSR exposure across exec. A sandbox does not itself make approval input public.
All same-principal hooks belong to the trusted computing base. Keep Section 6.1
mount, capability, resource, helper-signing and FD restrictions.

Only a fully prepared/verified CSR enters the hook chain. Bind its private
context to execution ID, origin, canonical intent hash and exact CSR bytes.
Deliver one immutable canonical buffer at most 65536 bytes to hook stdin using
a nonblocking pipe, at most 16384 bytes per dispatch, servicing stdout/stderr,
sync pipe and cancellation concurrently. On complete delivery close hook stdin;
this is a private hook endpoint, not the requester stdin endpoint. EPIPE, early
exit, incomplete delivery or setup failure is a hook fault. Never replay input
after rejection, cancellation or timeout.

All hooks share `min(D, hook_start + hook_timeout_ms)` as one cumulative deadline.
No next hook or partial progress extends it. Each hook stdout is bounded to
524288 bytes, stderr to 4096; reserve output capacity within the captured hook
quota before spawn. This accommodates a bounded DSSE envelope without the old
small-output fallback. Continue enforcing inner CSR, signature and JSON bounds.
Keep stderr private. Require complete delivery, normal exit zero and a valid
Section 6.1 sync handshake before interpreting one strict JSON result:

| Exact keys | Meaning |
| --- | --- |
| `status: "approved"`, `dsse_envelope` | Stop evaluation; verify signature, provenance, full canonical binding and final policy on retained evidence |
| `status: "rejected"`, `reason` | Stop evaluation irrevocably; reason is a private 1..1024-byte sanitized string |
| `status: "abstain"` | Continue only if the captured deadline and live request permit |

Reject duplicate/unknown keys, invalid UTF-8/types, excessive nesting, trailing
content and oversized results. A fault/abstention permits the next configured
hook only while the request is live and within budget; a rejection never does.
Malformed or invalid approval cannot be treated as approval or rewrite the CSR.
After each hook, kill/reap its remaining cgroup processes before another hook.

For full CSRs an explicit rejection produces generic REJECTED immediately;
for thin CSRs it enters SILENT_TIMEOUT and preserves the public deadline and
approval reservation. Exhaustion, abstention, invalid approval or expiry enters
SILENT_TIMEOUT for either form. Never emit a fallback CSR. A late completion or
signature cannot resume evaluation. Details remain in protected audit only.

### 6.3 Optional Local Root-TTY Approval Profile

The `[mvp]` profile replaces hook dispatch with one authenticated root approver.
It uses the same full/thin preparation, provenance, deadlines, durable gates and
public outcomes. Signed client-full warrants bypass review, not authorization.
This is the v3 target for local root-TTY approval. The existing implementation
supports a v2 local profile; this document does not claim v3 availability.

**Configuration:** Exact fields are `tty_mode = "stdio"`, `hooks_enabled = false`,
`pty_enabled = false`, `max_active_approval_requests = 1`, and a nonempty
`approval_signer_id` referencing exactly one configured SSH signer. The first
four retain their shown defaults and reject alternatives. No empty-signer CSR
export/diagnostic mode exists. Require `require_remote_audit_ack = false`; collector
configuration validation remains mandatory. SIGHUP reload remains disabled here.
Only one-time, stdio, null/hashed stdin, ELF (no direct scripts), empty caller-env
allowlist/forwarding, and distinct mapped requester/target kernel UIDs are
supported. Namespace targets additionally require all applicable NS gates. Unsupported
semantics follow the generic public timeout contract. Deferred features cannot
be enabled by a warrant or profile override.

**Broker transport:** Use the distinct root:root 0600 approval socket in a trusted
root-owned directory. Authenticate root SO_PEERCRED before parsing either side.
The approver verifies socket/parent ownership and mode. Permit one root approver
connection and one outstanding request. Frames are four-byte big-endian lengths
plus 1..524288 bytes of exact JCS, with no SCM_RIGHTS. Five-second partial-frame
assembly/send limits are capped by the remaining authorization budget.

An approval request has exactly `exec_id`, `signer_id`, `csr_payload`, and
`remaining_ms`. The first is the active UUIDv7, the second is the configured
signer, and CSR bytes are canonical and at most 65536. `remaining_ms` is an integer
1..300000 computed at dispatch; it helps local UI/helper cancellation but is not
signed authority and never replaces the daemon's absolute D. It can only shorten
the approver's local budget and cannot extend/reissue a prompt.

An approval response has exactly either `status: "approved"`, `exec_id`,
`dsse_envelope`, or `status: "rejected"`, `exec_id`, `reason`. Reason is a private
1..1024-byte sanitized string. Require strict JCS, one signature from the selected
signer, matching request/connection identity, and payload byte-for-byte equal to
the retained CSR. A root socket peer's confirmation alone is not authorization.
Sign the v3 DSSE PAE using the configured SSH adapter and namespace.

**Lifecycle:** Reserve the single approval slot before unsigned target work.
No available slot means silent timeout without target lookup; no queue is built.
A missing approver, broker disconnect, malformed response or review expiry enters
SILENT_TIMEOUT. No prompt is reissued automatically on reconnect. On thin rejection
invalidate the prompt immediately while retaining the slot until the public
outcome at D (or disconnect). No separate 120-second timer starts after preparation:
review/signing use the remainder of the admission-based authorization budget.
Disconnect or timeout cancels the helper and invalidates broker ownership; late
responses cannot approve. Worker/FD/RAM cleanup ownership remains independent.

The foreground approver reconnects after timeout or broker disconnect for
future requests; reconnecting never reissues an old prompt automatically. Shut
down the old connection, terminate/reap any signing helper and restore terminal
settings before reconnecting. Discard unfinished TTY input, retry transient
missing/refused sockets with bounded polling, and revalidate socket/parent
ownership and peer credentials on every connection. Local cancellation, TTY
loss, malformed protocol or failed trust checks stop the approver rather than
retrying those failures.

**Root interaction:** Require effective UID 0 and a verified controlling TTY.
Select identity/key/agent only through trusted operator configuration. Verify key
fingerprint, signer, algorithm, namespace and UP/UV requirements. Display the
origin prominently (`client_full` or `daemon_expanded_thin`), intent digest,
active thin binding, all command/environment/input fields, host/peer/target
identities, evidence, authority ceiling, five expected capability sets, grant and
validity. Include daemon authority, target epoch/instance, verified description,
namespace/mapping context, resolved numeric identity and complete immutable
security constraints. Explicitly distinguish host root, rootful container root
and mapped rootless root; neither a friendly name nor profile digest alone
is sufficient review information (NS-14). Render argv as indexed escaped values; no shell command is constructed.
Do not truncate fields and then permit signing. Confirm with `[y/yes/n/no]`:
only explicit `y` or `yes` followed by Enter signs; `n` or `no` followed by
Enter rejects. Flush pending terminal input immediately after displaying each
prompt so typeahead cannot confirm or reject a new request. Blank, invalid and
overlong answers reprompt without extending the admission-based authorization
deadline; bound answer storage and drain overlong lines without accepting a
valid prefix. EOF or terminal loss cannot approve. Keep passphrase/FIDO input
on that TTY, disable askpass, restore terminal state, and bound/terminate/reap
signing helpers on timeout, broker loss or cancellation. The requester sees
neither the reason nor the expanded CSR.

Verification must cover buffered Enter/affirmative input before a prompt,
repeated invalid answers, input without Enter, timeout recovery, and unfinished
confirmation from a cancelled request never carrying into the next one, in
addition to the applicable Section 8 cases.

**Offline signing:** Only client-full CSRs can be exported and signed offline
under Section 2.2. No timeout extraction command, root thin-export API, reusable
thin grant, or standalone redemption of thin-derived approval exists.

---

## 7. Hash-Chained Ratcheting Audit Log & Crash Recovery

Every audit record, ratchet-state object and verification anchor includes the
required integer `schema_version: 3`; this field is covered by canonical hashes
and HMACs. Startup and collector ingestion reject any other/missing version.
Ratchet domain separation is `sigrun-ratchet-v3`. No v1/v2 state is accepted as a v3
anchor merely because its hashes verify.

All logs, journals/diagnostic sinks, temporary CSR buffers, broker transport and
collector storage that receive private request facts must be restricted to
trusted administrators/approval principals. There is no requester audit or
preparation-status API. Requester-visible output contains only Section 2.1 data.
Bound and sanitize diagnostics; never dump secret signer/ratchet material.

AUTH_COMMIT binds request origin, intent digest, thin approval execution binding,
canonical payload and execution-binding digests, selected signer, authority and
expected profile alongside
existing host/peer/grant/policy fields. A bounded PRIVATE_OUTCOME record binds
exec_id, origin/intent when validated (null if malformed), internal failure reason,
intended public status, and delivery state (`not_started`, `sent`, `failed`, or
`no_reply`). Do not infer client receipt from `sent`. AUTH_ABORTED_POST_COMMIT
records consumption without execution, including late commits, lost approvals
and post-approval spawn failure. All new events remain part of the contiguous
replicated chain; no private rejection disappears from ordering merely because
it was hidden from the requester. Avoid embedding entire CSRs in every record;
retain digests and bounded fields within the 65536-byte ceiling.

**NS-15 — Private namespace audit and coherent versions.** Record observed
source identity/LSM attributes, approved target constraints and observed execution
results as distinct bounded data. Link target acquisition, invalidation, mapping,
profile version, placement, checkpoint and cleanup events by exec/instance IDs.
No source observation is silently relabeled as target enforcement. Preserve the
existing chain, replay and private-outcome rules. Required evidence too large to
fit must fail closed; do not truncate approval-critical fields. Instance registry
entries are ephemeral even though historical audit/consumption remains durable.
Fresh v3 deployments require matching clients, approvers and collectors where
enabled; v2 state must not be adopted merely because its hashes verify.

### 7.1 Provisioning (`sigrundctl init-host`)

1. Requires explicitly selected empty state/log locations and refuses if any prior key, database, WAL/SHM sidecar, ratchet state, temporary state or log exists. No automatic deletion, reset, adoption or migration is provided. Create schema-version-3 database, audit and ratchet objects as one protected provisioning set; incomplete provisioning fails startup and requires explicit operator remediation.
2. Creates the Section 4.3 schema-version-3 SQLite database with durable initialization, generates the Ed25519 host identity keypair in `/var/lib/sigrund/host_identity.key` (`0400 root:root`), `fsync()`s it, and computes `host_id`.
3. Generates a 256-bit initial ratchet key $K_0$ via `getrandom(..., GRND_NONBLOCK)`.
4. Creates `/var/log/sigrund/audit.jsonl` (`0600 root:root`), writes the single-line JCS Genesis Record at `seq = 0` (`schema_version: 3`, `event_type: "AUDIT_INIT"`, `host_id: <local_host_id>`, `prev_record_sha256: "0000000000000000000000000000000000000000000000000000000000000000"`, `entry_hmac = HMAC_SHA256(K_0, genesis_body_jcs)`) terminated by `\n`, and calls `fsync(log_fd)`.
5. Computes $K_1 = \text{SHA-256}(K_0 \parallel \text{"sigrun-ratchet-v3"})$, writes:
```json
{
  "schema_version": 3,
  "key_hex": "<64-char-hex-K_1>",
  "initial_key_hex": "<64-char-hex-K_0>",
  "last_record_sha256": "<64-char-hex-SHA256-of-record-0-jcs-bytes>",
  "remote_acked_seq": 0,
  "seq": 1
}

```


to `/var/lib/sigrund/audit_ratchet.state.tmp` (`0600 root:root`), calls `fsync(tmp_fd)`, closes `tmp_fd`, atomically renames `audit_ratchet.state.tmp` to `/var/lib/sigrund/audit_ratchet.state`, and calls `fsync(var_lib_dir_fd)`.
6. Outputs the verification anchor `{ "schema_version": 3, "host_id": "...", "initial_seq": 0, "anchor_key_hex": "<hex-of-K_0>", "genesis_record_sha256": "<SHA256(record_0)>" }` to `stdout` (or `--anchor-out <path>`) for registration with external verifiers/collectors together with the authorized TLS client-key-to-host mapping in Section 4.4, and **only after outputting the anchor** zeroes $K_0$ in memory via `explicit_bzero()`.

### 7.2 Per-Event Append & Atomic Ratchet Protocol

To write event `seq = i` ($i \ge 1$) using current state $S = (\text{seq} = i, K_i, \text{last\_record\_sha256}, \text{remote\_acked\_seq})$:

1. Construct the event object with `schema_version = 3`, `seq = i`, `host_id = local_host_id`, and `prev_record_sha256 = S.last_record_sha256`, compute `entry_hmac = HMAC_SHA256(K_i, event_body_jcs)`, and serialize the complete record as canonical single-line JCS JSON (`record_i_bytes`) **without a trailing newline**. `entry_hmac` is the 64-character lowercase hex encoding of the HMAC result (decode to raw bytes before constant-time verification). `event_body_jcs` is the canonical object with `entry_hmac` omitted; `record_i_bytes` includes that field. HMAC inputs, record hashes, `prev_record_sha256`, and replicated `records_jcs` exclude the on-disk line delimiter. Enforce the Section 4.4 limit of `65536` bytes for `record_i_bytes` before writing; fail closed if it is exceeded.
2. Record the current EOF byte offset `eof_before` of `/var/log/sigrund/audit.jsonl`. Write exactly `record_i_bytes || "\n"` (one newline byte, `0x0a`) to `audit.jsonl` and call `fsync(log_fd)`.
* If `write()` or `fsync(log_fd)` fails, attempt `ftruncate(log_fd, eof_before)` and then `fsync(log_fd)` as compensation. If either rollback operation fails, immediately fail closed: stop accepting requests, close the control socket, emit no further audit record, and require operator recovery after verifying the log/state pair. If both succeed, abort the operation in memory without ratcheting $K_i$; a failed write/flush never advances the ratchet.


3. Compute $K_{i+1} = \text{SHA-256}(K_i \parallel \text{"sigrun-ratchet-v3"})$ and `record_i_sha256 = hex(SHA256(record_i_bytes))`.
4. Write `{ "schema_version": 3, "key_hex": "<K_{i+1}>", "last_record_sha256": "<record_i_sha256>", "remote_acked_seq": S.remote_acked_seq, "seq": i + 1 }` to `/var/lib/sigrund/audit_ratchet.state.tmp` (`0600 root:root`), call `fsync(tmp_fd)`, close `tmp_fd`, call `rename("audit_ratchet.state.tmp", "audit_ratchet.state")`, and call `fsync(var_lib_dir_fd)`.
5. Zero $K_i$ in memory (`explicit_bzero`).

Every state replacement preserves `schema_version: 3` and also carries `initial_key_hex`, the protected 64-character
hexadecimal encoding of $K_0$, unchanged for the lifetime of the host. It is
needed to verify the genesis record and replay the ratchet during startup
recovery. It is never used as a request-time signing key and remains covered
by the state file's `0600` ownership and permission requirements.

**Security limit:** Retaining `initial_key_hex` permits derivation of every
past and future ratchet key. This format therefore provides no forward-secure
audit authenticity after compromise of the host's state or UID 0. Zeroing a
working key does not remove the retained seed. Local checks detect corruption
and inconsistent edits while the protected state remains trustworthy; an
attacker controlling both log and state can rewrite a self-consistent history
or roll both back. Collector checkpoints protect history already committed
outside the host according to Sections 1.1 and 4.4; an unreplicated suffix
has no such protection. Verification anchors contain secret HMAC material
and must be handled as secrets. A future forward-secure format would require
removing the locally recoverable seed and redesigning verification/migration;
that property must not be claimed for this format or the local-only MVP.

If the record and log `fsync()` succeed but any temporary-state creation,
state write, rename, or directory `fsync()` fails, the in-memory writer is
poisoned immediately. It must reject every later append until a startup-style
verified reconciliation has established whether the log is synchronized or
one record ahead and has published a matching state file. Reusing the old
sequence and ratchet key after a durable log write is forbidden.

### 7.2.1 Audit Storage Pressure and Authorization Admission

Before listening and before each new consumption transaction, the bounded
durable executor checks log length and free space on the pinned log and state
filesystems, including the SQLite/WAL filesystem if different. Use checked
`fstatvfs` available-byte arithmetic; failed checks stop authorization. If log
length is at or above `audit_log_high_water_bytes` or any filesystem has fewer
than `audit_min_free_bytes` available, stop requester admission and do not
begin new consumption or spawn reservations. Reconcile operations already
reserved; the ownership and cancellation rules still apply. Recheck before
spawn admission when authorization was delayed by a remote round trip.
Also refresh the pressure gate before every audit append, including rejection
and diagnostic records, so a stream of denied requests closes admission at the
threshold without waiting for a successful authorization. Threshold crossings
still allow already-owned records to be persisted as described below. A failed
capacity query is a fatal storage-health error and initiates shutdown.
Checks and filesystem operations never run on the event loop.

The high-water mark is an admission threshold, not a truncation limit or a
promise that all remaining audit writes will fit. Pending rejection records,
already-reserved commits and job outcomes may append beyond it. Do not create
one new record for every connection refused under pressure; use Section
1.3.2's bounded aggregation. Space can disappear after a successful check:
ENOSPC/EIO during a durable operation follows the existing transaction and
ratchet failure rules and triggers Section 2.4.1 shutdown. Never retry an
uncertain consumption, drop an `AUTH_COMMIT` to keep serving, truncate valid
history, reset the consumption database, or authorize without durable audit.

Resume only after operator remediation and verified startup recovery (restart
is required after this pressure gate closes). Expand storage or move the
complete protected state/log set through a controlled offline procedure;
raising the high-water threshold requires sufficient free space. This version
defines no safe history pruning/rotation protocol: replication acknowledgement
does not by itself permit deleting a log prefix. Deployment instructions must
include capacity monitoring and recovery steps preserving host identity, all
consumption state and complete authenticated history. Admission windows bound
write rate but cannot bound lifetime log/database growth.

### 7.3 Startup Crash-Recovery & Integrity Gate

On every daemon startup, before creating any public/broker listener, first require schema version 3 in the database, ratchet state and complete audit records. Never mutate a legacy/unknown state set. Only after this version gate may verified v3 recovery remove a leftover `audit_ratchet.state.tmp`. Load `/var/lib/sigrund/audit_ratchet.state` ($S$), and scan `/var/log/sigrund/audit.jsonl` from byte `0`, verifying each HMAC from the protected initial seed/domain as well as parsing every complete `\n`-terminated line and verifying that `seq` increments strictly from `0` by `1` and that every record $k > 0$ has `prev_record_sha256 == hex(SHA256(record_{k-1}_jcs_bytes))`. Let `last_seq` be the `seq` of the last complete `\n`-terminated record:

1. **Case 1 (Partial Trailing Bytes After Power Loss During Step 2 Write):**
* If `audit.jsonl` contains trailing bytes after the final `\n` that do not end in `\n` (or fail JSON parsing), `sigrund` checks whether `last_seq == S.seq - 1` **and** `hex(SHA256(record_{last_seq})) == S.last_record_sha256`.
* If both hold, `sigrund` truncates `audit.jsonl` to `valid_eof` via `ftruncate(log_fd, valid_eof)`, calls `fsync(log_fd)`, and appends `RATCHET_PARTIAL_WRITE_TRUNCATED` at `S.seq`. Otherwise, `sigrund` **fails closed** (`AUDIT_TAMPER_OR_CORRUPTION`).


2. **Case 2 (Clean Synchronized State):**
* No trailing partial bytes exist, `last_seq == S.seq - 1`, and `hex(SHA256(record_{last_seq})) == S.last_record_sha256`. Startup local check succeeds.


3. **Case 3 (Single-Record Unratcheted Crash — Crash Between Step 2 `fsync(log_fd)` and Step 4 `rename()`):**
* No trailing partial bytes exist, and `last_seq == S.seq`. `sigrund` verifies `hex(SHA256(record_{last_seq - 1})) == S.last_record_sha256` and `record_{last_seq}.entry_hmac == HMAC_SHA256(S.key_hex, record_{last_seq}_body_jcs)` in constant time, completes the ratchet transition to `seq = last_seq + 1`, zeroes $K_{\text{last\_seq}}$, and appends `RATCHET_FORWARD_RECOVERY`. If either check fails, `sigrund` **fails closed**.


4. **Case 4 (State Ahead of Log / Log Truncation):**
* If `audit.jsonl` is empty/missing or `S.seq > last_seq + 1`, `sigrund` **fails closed** (`AUDIT_TAMPER_OR_CORRUPTION`).


5. **Case 5 (Log Ahead of State or Interior Chain Mismatch):**
* If `last_seq > S.seq`, or any record has a `seq` gap or `prev_record_sha256` mismatch, `sigrund` **fails closed** (`AUDIT_TAMPER_OR_CORRUPTION`).


6. **Case 6 (Remote Collector Checkpoint Reconciliation when `require_remote_audit_ack == true`):**
* On startup, `sigrund` queries the remote collector for its latest `(collector_last_seq, collector_last_record_sha256)` for `host_id`:
* If `last_seq < collector_last_seq` (indicating whole-host or audit-log storage rollback behind the collector's committed state) or if the local record at `collector_last_seq` does not match `collector_last_record_sha256`, `sigrund` **fails closed immediately** (`AUDIT_REMOTE_CHECKPOINT_MISMATCH`) and refuses to open `/run/sigrund.sock`.
* If `last_seq >= collector_last_seq` and the local record at `collector_last_seq` matches `collector_last_record_sha256`, `sigrund` sets `S.remote_acked_seq = collector_last_seq` and replicates any unacknowledged suffix `collector_last_seq + 1 ..= last_seq` before opening `/run/sigrund.sock`, using the bounded chunking and verified per-chunk cursor advancement of Section 4.4 with `target_auth: null` on every chunk. Startup replay ingests historical authorizations without authorizing or consuming them; any chunk failure prevents startup.


---

## 8. Cumulative Verification & Security Validation Matrix (v3)

### 8.1 Isolated Test Fixtures

The rows below are normative v3 acceptance requirements, not claims about current
tests. Use disposable Linux hosts with real delegated cgroup v2, controlled
root-owned fixtures and distinct unprivileged requesters. Exercise actual sockets,
SCM_RIGHTS, credential helpers, signing, persistence and execution. Use deterministic
gates and an injectable monotonic clock to prove races; arbitrary sleeps alone
are insufficient. Namespace-only fixtures supplement, not replace, real host tests.
Never manipulate production credentials or state. Record source/build identity,
expected/public/private outcomes, resource ownership and cleanup for each run.

### 8.2 Required Verification Cases

| Case | Fixtures and actions | Required observations |
| --- | --- | --- |
| V-01: Versions and provisioning | Old/missing/future wire, CSR, signature-domain, database, ratchet, audit and collector versions; partial/existing provisioning sets | Fail closed before target work/listening as applicable; no automatic migration/deletion; only explicit fresh v3 state initializes |
| V-02: Public context | Query every supported profile; inject path/rights/unknown keys; change generation; exhaust context limits independently | Only bounded target-independent context; no filesystem probe, signer secrets, approval occupancy or execution-rate charge; stale context never rewrites CSR |
| V-03: Client preparation and fallback | Accessible/unreadable/nonexistent executables; unreadable ancestor; uncertain higher-priority eligibility; finite pipe stdin; full-only and export | Unprivileged complete CSR or locally identified unchanged thin intent; no invented evidence, silent model downgrade or second stdin read; full-only/export never expand remotely |
| V-04: Full-CSR access proof | Forge hashes/ctime/profile/provenance; DAC and ACL denials, supplementary-group access, inaccessible ancestors above pinned root, unmapped groups/domain; rename after check | Access helper uses authenticated credentials/groups and full traversal; privileged FDs cannot bypass ancestors; retained source prevents reopen races; invalid requests never reach mandators |
| V-05: Thin confidentiality | Missing file, inaccessible file/directory, non-ELF, size/hash failure, policy denial, absent broker, explicit rejection, malformed/expired approval | Identical TIMEOUT status/field shape and scheduled D (normalizing admission-generated exec_id), no CSR/reason/progress; compare raw control bytes, early EOF, regular-output changes, stdin consumption and approval-slot observations |
| V-06: Provenance and intent | Alter argv, cwd, environment, target/groups/capability ceiling, input policy, TTL, intent hash, origin or active execution ID; replay thin approval via signed endpoint/reconnect/restart | Exact canonical binding, immutable intent, prominent trusted origin display; only active one-time thin approval accepted; no standalone/exported thin redemption |
| V-07: Trust models | All four models; verity SHA-256/512; ctime version changes; direct digest limits/streaming; memfd seals; unsupported filesystem, noexec, ACL/set-ID and file-capability metadata | Correct preference order before completion; exact model fixed afterward; existing bounds/eligibility retained; no changed bytes, rehash bypass, fallback or replacement after approval |
| V-08: Credentials and exec checkpoint | Ordinary and file-capability ELFs, UID/GID/groups, five sets, NNP, alias replacement, digest mutation, tracer death and cancellation at release | Exact signed profile at authorization and exec stop; no loader/target instruction before direct verification; failure kills/reaps without repair; memfd strips file caps and keeps unknown exec outcome |
| V-09: Decision and deadline races | Gate each preparation/hash/review/commit boundary; reject then submit late/duplicate/concurrent approval; advance D while work/fsync blocked; vary timeout config | One atomic public winner; thin rejection immediately final internally; no stage extends D; no execution after timeout; late commit remains consumed and audited without execution |
| V-10: Approval then execution | Gate audit/collector success, partial approval sends, disconnect, clone/setup/exec errors, kill before/after sync token, fast exit | No clone/output before complete APPROVED delivery; optional EXEC_READY then exactly one EXEC_RESULT; no second decision/refund; memfd readiness never claims exact exec success |
| V-11: Signatures and offline workflow | Independent DSSE/JCS/SSHSIG vectors; key/namespace/UP/UV failures; offline client-full export/sign/package/redeem; different runtime env | Canonical bytes preserved; v3 domain required; one signer independently authorizes; exact environment/intent bound; no TIMEOUT payload or root thin-export API |
| V-12: Framing and descriptors | Every frame/state and size boundary; duplicate/unknown keys, excessive depth; malformed/truncated/extra/misplaced rights; fragmented traffic; blocked close/read and sink backpressure | Bounded allocation/assembly, no resynchronization; transport failures do no target work; semantic failures hold endpoints until timeout; descriptors disposed exactly once off-loop |
| V-13: Admission and accounting | Exhaust per-UID/global rates, sockets, workers/helpers, RAM, audits and review slots; reload lower limits; cross windows with retained ownership | Bounded tables/queues; no replacement worker pools or quota refund before actual cleanup; held thin slot hides early refusal; context cannot exhaust execution counters |
| V-14: Replay, revocation and durable ownership | Concurrent redemption, digest/signature revocation, expiration, locked WAL/fsync, failure around commit and audit publication | One-time uniqueness; all nonapproved submissions publicly timeout; no retry of uncertain commit; late consumed grants remain recorded; bounded private outcome reconciliation |
| V-15: Collector | mTLS host binding, contiguous chunks, exact provenance/intent/exec target equality, retry/duplicate/replay, malformed receipts, deadline and denied final chunk | Only authenticated v3 chain/ALLOW completes remote authorization; no skipped records or mismatched intent; late ALLOW cannot revive timeout; private denials do not reach requester |
| V-16: Trusted hooks and root TTY | Ordinary user/shared-UID process attempts to inspect CSR/logs/IPC; hook faults/abstention/rejection; root EOF, wrong key, slow signing, broker reconnect | Reserved approval principal; complete sanitized provenance/evidence display; rejection stops chain; thin refusal stays silent; no shared nobody account or untrusted evidence export |
| V-17: PTY and output | Future PTY profile; rights on auth/rejection/result; missing/extra master; disconnect after type byte; signals/resize before readiness; output before result | PTY transfer only on EXEC_READY after APPROVED; terminal restore/FD cleanup; bounded independent stdio streams; no premature EOF before thin outcome |
| V-18: Child setup and reaper | Cgroup mount flags/propagation, every credential/FD remap fault, writable sync-FD sentinel, unpublished clone result and concurrent exits | Parent mount state unchanged; exact setup readback; only actual sync pipe receives errors; barrier prevents exit theft; tracked cleanup and safe-profile containment claims preserved |
| V-19: Audit and recovery | Independently recompute v3 HMAC/ratchet; corrupt/truncate/rollback log/state, poison fsync/rename, high-water/free-space thresholds; restart reconciliation | Exact schema/domain/chain; bounded private records; no authorization without durable audit; fail closed on uncertain recovery, no deletion of consumption; retained-seed/rollback limits explicitly tested |
| V-20: Shutdown and resource side channels | Shutdown/crash with silent requests, in-flight commit/clone and blocked cleanup; service-manager escalation and restart | No new work after shutdown, all owners reconciled or supervised cleanup; no fictitious timeout delivery or rollback; document observed shared-resource effects outside the protocol guarantee |

### 8.2.1 Cross-Cutting Acceptance Rules

Run relevant full/thin/signed cases across all enabled trust models and supported
execution profiles. Inspect public and private outcomes separately. Use raw-socket
clients as well as sigrun so CLI behavior cannot conceal a protocol flaw. Include
UID/GID/group isolation, helper failures, access changes, policy reload and
reserved-principal exclusions. Prove deadline scheduling with deterministic clocks,
and measure actual delivery with bounded writable sockets; do not mistake ordinary
scheduler jitter for a constant-time guarantee.

No passing unit test alone establishes caller-access enforcement, confidentiality,
credential transitions, durable consumption, ptrace behavior or supervised cleanup.
All new schema examples, PAE lengths/hex, intent hashes, field counts, bounds and
state diagrams must have independently checkable fixtures before runtime release.

### 8.3 Implementation Status and Release Gate (NS-16)

The current implementation is the **v2 local one-time SSH/stdio profile**, as
recorded in [implementation notes](IMPLEMENTATION_NOTES.md). No v3 runtime or
namespace support is established by this specification update. Preserve that
status until integrated evidence demonstrates each claimed capability.

The [roadmap](docs/NAMESPACE_AWARE_EXECUTION.md) defines six dependency-ordered
phases, requirement traceability and their acceptance gates. All applicable
V-01–V-20 cases above remain required under v3; add the namespace matrix below.
Phases 2–3 can yield experimental execution, not production support. No profile
ships before its applicable confinement, packaging and lifecycle gates pass.
Manager resolvers are optional and cannot delay a validated manager-free profile.

Keep PTY, hooks, collector/remote ACK, reload, reusable grants, scripts and extra
signing adapters independently deferred until their integrated cases pass. They
remain target requirements, not mandatory scope for the namespace implementation
milestones. Hardware FIDO claims still require physical acceptance. Full v3
conformance requires all claimed target features and applicable V/NS cases;
a subset must name its supported profile and exclusions explicitly.

| Requirement | Integrated acceptance scenario and required result |
| --- | --- |
| NS-01 | All four routes, rootful/rootless, same-owner/cross-owner; destination account and explicit policy/approval are correct; both client endpoints function |
| NS-02 | Shared/unshared namespaces, inherited/passed sockets, connector exit, exec/credential/context races; adhere to declared attribution or reject |
| NS-03–NS-04 | PID reuse, anchor death, change-and-restore races, restart/replacement, daemon restart while reviewing; stale binding rejects without retargeting |
| NS-05–NS-06 | Nested/unmapped IDs, setgroups restrictions, cross-owner requests, equal numeric IDs in different namespaces and different IDs mapping to one kernel UID; no authority confusion or injection bypass |
| NS-07 | Identical paths with different destination bytes/cwd, account edits, mutable roots and inaccessible ancestors; retained destination evidence and resolved approved credentials prevail |
| NS-08 | Cloned ComposeFS mounts/PrivateMounts, default/full-only/export/explicit-thin flows, unsigned alternative-model validation and signed mismatch; no privileged full fallback or signed switching |
| NS-09–NS-10 | Userns entry, PID/time child creation, root/mount isolation, idmapped mounts, cgroup placement and delegation; actual final context and descendant supervision match profile |
| NS-11 | Real SELinux/AppArmor enforcement including stacks/ranges, disabled/permissive/complain/unreadable states, policy reload/reuse, seccomp, NNP/ptrace/direct/memfd; require declared actual constraints before release |
| NS-12 | Disconnect/cancel, target deletion, resolver/helper/tracer death, exhausted quotas and blocked cleanup; bounded ownership, correct disclosure timing and consumption |
| NS-13 | Scoped manager names/owners/endpoints, stale or dishonest metadata and lifecycle loss; validate resources under unchanged host authorization |
| NS-14–NS-15 | Independent schema/JCS/PAE/signature vectors, altered bindings/intent/profile, approval rendering, fresh-state rejection and audit/collector equality; no downgrade, hidden field or incompatible-state adoption |
| NS-16 | Reproducible integrated results for each advertised platform/profile; no helper-only or namespace-root fixture substituted for a release gate |

### 8.4 Release-Blocking Design Gates

Phase 0 must produce reviewable decisions, bounded schemas and prototype evidence
for the following before dependent runtime features are enabled:

| Gate | Required decision/evidence | Blocked capability |
| --- | --- | --- |
| G-01 | Source attribution and coherent process-context acquisition; socket passing, credential/exec races and change-and-restore handling | Self selection; any target acquisition without the corresponding proof |
| G-02 | Namespace/userns entry order, mapping composition, setgroups and root/cwd handling; supported kernel/features and explicit rejection matrix | Each affected rootful/rootless execution profile |
| G-03 | Host launcher placement, PID/time child creation, host pidfd/tracer/reaper ownership, manager teardown and escape boundaries | Supervised namespace execution |
| G-04 | Enforceable LSM transitions and policy-change detection with NNP/ptrace/executable models; explicit seccomp strategy | Every profile claiming those constraints |
| G-05 | Canonical acquisition/constraint records, target-scoped policy/registration schemas, CLI grammar, full-access binding distribution and quotas | Issuing bindings, enabling management/full/export interfaces |

A failed gate yields an explicit unsupported combination, not a fallback or an
unqualified support claim. An unresolved gate stays visibly blocked. Record kernel,
architecture, userns/delegation, LSM enforcement and exact executable profile in
evidence. Tests on disposable real hosts complement unit tests; privileged
namespace-root fixtures and delegated-platform smoke tests cannot replace them.
