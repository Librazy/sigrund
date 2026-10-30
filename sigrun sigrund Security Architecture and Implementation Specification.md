# `sigrun` & `sigrund` Security Architecture and Implementation Specification (v1.0)

This document is the complete, self-contained v1.0 specification for `sigrun` (unprivileged CLI client) and `sigrund` (root execution daemon). It defines the trust boundaries, cgroup v2 hierarchy initialization, admission and quota controls, wire protocol, cryptographic envelopes, unified authorization predicate (including same-UID injection prevention), child credential and mount transitions, hook sandboxing, contiguous audit replication and collector deduplication, audit crash-recovery state machine, and cumulative verification matrix. Section 8.3 records the current implementation boundary and release gate; a validated helper or command-line probe is not an implementation of the runtime contract by itself.

---

## 1. Trust Boundaries, Cgroup Initialization, and Admission Control

### 1.1 Explicit Architectural Guarantee Boundaries

`sigrun` and `sigrund` replace PAM and Polkit with a capability-scoped execution architecture over a Unix domain socket (`/run/sigrund.sock`, `0666`, `SOCK_STREAM`). To ensure security claims match what the Linux kernel and external infrastructure can strictly enforce, v1.0 establishes five explicit boundaries:

1. **Non-Root vs. Host-Root Cgroup Containment Boundary:**
* **Guaranteed Containment (Explicit Safe Capability Profile):** This guarantee applies only when `target_uid != 0` and the granted capability set is a subset of the enumerated safe profile `{ CAP_NET_BIND_SERVICE }` (including the empty set). Every other capability, including capabilities added by future kernels, is outside this profile. The target UID, primary GID, and supplementary GIDs must confer no authority to migrate processes through host services: the workload must have no usable access to host management sockets, APIs, credentials, or delegated cgroup controls, including systemd, D-Bus policy methods that move PIDs, Docker/containerd/CRI, and equivalent privileged helpers. This excludes access conveyed by filesystem ownership, ACLs, group membership, service authorization policy, passed FDs, or inherited credentials. Deployment policy must establish these access restrictions; a read-only cgroup mount alone does not establish them. Under these conditions, the child runs in a new cgroup namespace (`CLONE_NEWCGROUP`) and mount namespace (`CLONE_NEWNS`) where `/sys/fs/cgroup` is recursively read-only, cannot migrate processes out of `job-<exec_id>` directly or through a host control plane, and all descendants remaining there are torn down via `cgroup.kill`.
* **Best-Effort Containment (Any Execution Outside the Safe Profile or Access Restrictions):** A process running as host UID `0` (even with reduced capabilities and a read-only `/sys/fs/cgroup` mount) retains UID `0` ownership authority over the host filesystem and host IPC sockets (such as `/run/systemd/private` and `/run/dbus/system_bus_socket`). Such a process can request the host `systemd` manager to allocate a transient scope and migrate PIDs out of `job-<exec_id>`. Therefore, for `target_uid == 0`, any capability outside the safe profile, or any usable host control-plane access, initial cgroup placement (`CLONE_INTO_CGROUP`) is enforced, but post-spawn containment and descendant cleanup are **best-effort operational lifecycle management**, not a sandbox against a malicious root process.


2. **Same-UID Privilege Elevation & Process Injection Boundary (Resolving Finding 1):**
* Standard Linux `execve()` resets process dumpability to `1` (`SUID_DUMP_USER`) when the effective UID/GID before `execve()` matches the real UID/GID and the executed binary is readable (`MAY_READ`), and the kernel's `__ptrace_may_access()` check does not compare `supplementary_gids`. If a warrant granted `target_uid == requester_uid` with additional privileged `supplementary_gids` and zero capabilities on a system permitting same-UID tracing (e.g., Yama `ptrace_scope == 0`), the unprivileged requester could attach to the child via `ptrace` or `process_vm_writev` after `execveat()` and hijack those supplementary groups.
* Therefore, **by default (`allow_same_uid_elevation = false`), `sigrund` rejects all warrants where `target_uid == requester_uid`**, requiring elevated commands to transition to a dedicated target UID (`target_uid != requester_uid`). Even when `allow_same_uid_elevation = true` is explicitly configured for a deployment, `sigrund` permits `target_uid == requester_uid` **only** when kernel-enforced post-exec non-dumpability (`exec_memfd` mode `0111` + `/proc/sys/fs/suid_dumpable == 0`) and Yama ancestor-only ptrace restrictions (`/proc/sys/kernel/yama/ptrace_scope` at least `1`) are verified active prior to spawn (Section 4.2 Predicate 3).


3. **Storage Rollback vs. Live-Memory VM Snapshot Boundary:**
* Local SQLite commits (`PRAGMA synchronous = FULL`) prevent replay of `one_time` grants on an intact local filesystem.
* When `require_remote_audit_ack = true` is enabled, the remote collector's startup checkpoint reconciliation (`AUDIT_REMOTE_CHECKPOINT_MISMATCH`) detects whole-disk rollback on daemon startup, and its durable `(host_id, grant_id)` and `(host_id, payload_sha256)` deduplication prevents **fresh redemption of a `one_time` warrant after a local SQLite database rollback**.
* **Live-memory VM snapshot restoration**—where a hypervisor captures live guest RAM and CPU registers *after* `sigrund` verifies the remote collector's receipt and *before* `clone3()` completes, and later resumes that running state—cannot be detected inside the guest OS. Protecting external targets against duplicate effects from restored live VM memory requires idempotency or fencing tokens at the target service.


4. **Host Clone Detection Boundary:**
* Comparing `/etc/machine-id` and `/sys/class/dmi/id/product_uuid` at startup is a **heuristic safeguard** against accidental unsealed VM templates where the hypervisor assigns a new SMBIOS UUID. It cannot detect a byte-for-byte clone that preserves both SMBIOS UUID and disk state. Provisioning pipelines must seal templates with `sigrundctl seal-template` and initialize unique host keys on first boot with `sigrundctl init-host`.


5. **Script & Dynamic Dependency Boundary:**
* Sealing and hashing the target binary (`exec_memfd`) and standard input (`stdin_memfd`) authenticates only those exact byte streams. It does not authenticate dynamically linked libraries resolved from mutable paths, configuration files read after startup, or files sourced by an interpreter.

Approval delegates the effects of the complete command, including argv,
environment, input and working directory. A signed shell/interpreter or a
privileged tool accepting caller-selected paths can confer broad authority
despite an authentic executable digest. The cwd is a signed path, not a sealed
directory tree. Operators must review those effects; host UID 0 with an empty
capability set still has ownership-based authority, but does not have every
Linux capability (Section 5.3). Local audit protection has the protected-state
and key-compromise limits in Section 7.2.



### 1.2 Startup Cgroup v2 Initialization & Supervisor Leaf

`sigrund.service` runs under systemd with `Delegate=yes` on a unified cgroup v2 hierarchy (`/sys/fs/cgroup`). Under Linux cgroup v2's no-internal-processes rule, domain controllers (`memory`, `pids`) cannot be enabled in `cgroup.subtree_control` while a process resides directly in that cgroup.

Before opening `/run/sigrund.sock`, `sigrund` executes the following mandatory startup sequence and fails closed (exiting with a fatal error) if any step fails:

1. **Subreaper Registration:** Calls `prctl(PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)` so orphaned descendants of this daemon are reparented to it while it remains alive. This does not adopt processes already reparented to PID 1 or another subreaper after an earlier daemon instance died.
2. **Directory Creation:** Resolves and pins its own delegated service cgroup path $G$ before migration (e.g., `/sys/fs/cgroup/system.slice/sigrund.service`), using its cgroup membership and the verified cgroup v2 mount rather than a hardcoded unit name, and creates three subdirectories (`0755 root:root`): $G\text{/supervisor}$, $G\text{/jobs}$, and $G\text{/hooks}$.
3. **Daemon Migration to Supervisor Leaf:** Writes its own PID (`getpid()`) to $G\text{/supervisor/cgroup.procs}$, vacating the root of $G$.
4. **Controller Enablement:** Reads $G\text{/cgroup.controllers}$, verifies both `memory` and `pids` are present, and writes `"+memory +pids\n"` sequentially to $G\text{/cgroup.subtree\_control}$, $G\text{/jobs/cgroup.subtree\_control}$, and $G\text{/hooks/cgroup.subtree\_control}$.
5. **Orphan Cleanup from Prior Crashes:** Iterates over any existing `job-*` directories under $G\text{/jobs}$ and `hook-*` directories under $G\text{/hooks}$, writes `"1\n"` to each `cgroup.kill`, waits for `populated 0` in `cgroup.events`, drains only processes that are actually children of the current daemon via the Central Reaper (`waitid(P_ALL, 0, ..., WEXITED | WNOHANG)`), logs an `ORPHAN_CLEANUP` audit entry, and removes the directories via `rmdir()`. Prior-instance processes may already belong to PID 1 or another subreaper; the new daemon can kill their cgroups but cannot generally reap them or recover their exit status. Their current parent is responsible for reaping; cleanup completion requires `populated 0`, not successful `waitid()` for those non-children.
6. **Startup Limit Verification Gate:** Creates $G\text{/hooks/startup-probe}$, writes `"67108864\n"` to `memory.max`, `"0\n"` to `memory.swap.max`, `"1\n"` to `memory.oom.group`, and `"32\n"` to `pids.max`, fails closed if `memory.swap.max` is absent or any write/read-back differs, and reads back each file to confirm the kernel accepted the exact limits, verifies `cgroup.kill` is writable, and removes $G\text{/hooks/startup-probe}$ with `rmdir()`.

### 1.3 Admission Control & Pinned Worker Quotas for Blocking I/O

Regular files (`S_ISREG`) do not support `epoll` and ignore `O_NONBLOCK` on local disk reads. Furthermore, when a client passes a pipe (`S_ISFIFO`) over `SCM_RIGHTS` for `stdin`, the client shares the underlying kernel open file description (`struct file`) and can clear `O_NONBLOCK` via `fcntl(fd, F_SETFL, 0)` after validation. Once a worker thread enters a blocking `read()` syscall in the kernel, calling `dup2()` on that descriptor number in userspace does not replace the `struct file` already pinned by the active `read()` call, and signal delivery cannot eliminate pre-syscall race windows or interrupt uninterruptible disk waits (`TASK_UNINTERRUPTIBLE`).

Therefore, `sigrund` enforces the following **Response Deadline and Quota-Pinning Contract**:

1. **Main Control Thread Non-Blocking Invariant:** The main `epoll` event loop handles control sockets, nonblocking hook pipes, child sync pipes, `pidfd`/`signalfd(SIGCHLD)` notifications, `inotify` events, and timers. It never reads filesystem binaries or client-passed `SCM_RIGHTS` descriptors, performs blocking hook-pipe writes, or waits on SQLite/fsync/network operations. Such blocking work is dispatched off-loop; its completion is delivered back to the request coordinator.
   This includes potentially blocking `openat2`, `fstat`, `close`, and cleanup
   of caller-controlled descriptors, even on malformed-request, excess-rights,
   timeout and stale-completion paths. Metadata-only operations and RAII
   destruction are not exemptions. Before receiving rights, reserve bounded
   capacity for their eventual off-loop disposal; if unavailable, stop admission
   before receiving more rights. The owning task retains quota through actual
   cleanup. Cgroup filesystem operations and durable audit/database work also
   run off-loop with bounded queues; a blocked operation cannot stall socket
   deadlines, signal dispatch or other connections.
2. **Policy-Generation I/O Worker Pool:** Potentially blocking reads (`exec_memfd` binary copying and `stdin_memfd` input collection) are dispatched to a pool sized by the admitted request's captured `max_io_workers_global` and `max_io_workers_per_uid` values (defaults `16` and `2`). The pool is fixed for that policy generation; no replacement threads exceed the captured global value. These values may be lowered by configuration but never exceed immutable ceilings of `16` global and `2` per UID.
   Metadata, copy and descriptor-cleanup stages share this budget; separate
   stage pools cannot each claim the full allowance. Uninterruptible tasks
   may exhaust capacity and cause `RESOURCE_EXHAUSTED`; responsiveness does
   not guarantee recovery of capacity until those tasks actually finish.
3. **Response Deadline vs. Resource Reclamation:**
* Each request is assigned the captured policy-generation `request_deadline_ms` snapshot/initial-response deadline (`5000 ms` default; immutable ceiling `5000 ms`) upon `accept4()`. It covers hello assembly and common executable/stdin snapshotting through the handoff to authorization; it is disarmed when Section 1.3.1 advances to `AUTHORIZING`. Hook, remote RPC, partial-frame, and final-expiry phases use their own deadlines and do not inherit or reset this one.
* Before and after every immutable `65536`-byte read chunk, the worker checks `clock_gettime(CLOCK_MONOTONIC)` against the deadline and checks an atomic `cancelled` flag.
* If the captured request deadline expires on the main `epoll` thread while a worker thread is still running or blocked inside `read()` :
1. The main thread attempts the terminal-state compare-and-swap in Section 1.3.1. Only the winning timeout path sets `cancelled = true`, sends `0x02 SERVER_AUTH_DECISION` (`status: "REQUEST_TIMEOUT"`) once, and closes the client control socket. A late worker completion cannot revive that request.
2. **Strict Quota Pinning Until Actual Worker Exit:** The blocked worker thread, its open file descriptors, its `exec_memfd` / `stdin_memfd` buffers, its per-UID worker slot (`1` of captured `max_io_workers_per_uid`), its global worker slot (`1` of captured `max_io_workers_global`), and its reserved snapshot memory bytes (`st_size` / `max_stdin_bytes`) **remain strictly accounted for against the caller's UID and global quotas** until the underlying `read()` syscall actually returns in the kernel and the worker thread closes its descriptors and exits its task function.





| Resource / Parameter | Enforced Limit | Enforcement Stage & Failure Code |
| --- | --- | --- |
| **Global / Per-UID Active Control Sockets** | Captured `max_active_sockets_global` / `max_active_sockets_per_uid` (defaults `64` / `4`; immutable ceilings `64` / `4`) | Enforced on `accept4()`; excess connections closed immediately. |
| **Global / Per-UID Pinned I/O Workers** | Captured `max_io_workers_global` / `max_io_workers_per_uid` (defaults `16` / `2`; immutable ceilings `16` / `2`) | Accounted until worker thread completes cleanup; returns `RESOURCE_EXHAUSTED`. |
| **Requester Handshake/Snapshot Deadline** | Captured `request_deadline_ms` (default `5000 ms`; immutable ceiling `5000 ms`) | Cumulative deadline from `accept4()` through `CLIENT_HELLO`, common executable/stdin snapshotting, and coordinator handoff; returns `REQUEST_TIMEOUT` only while that phase is active. |
| **Control Frame Payload Limits (Both Directions)** | `CLIENT_HELLO`: `196608` bytes; `SERVER_AUTH_DECISION`: `524288` bytes; `CLIENT_SIGNAL`: `64` bytes; `CLIENT_WINSIZE`: `128` bytes; `SERVER_CHILD_EXIT`: `128` bytes | Section 2.1.1: reject an unknown/out-of-state type immediately; reject an oversized length before allocation or payload reads. |
| **Control Frame Assembly Deadline** | `5000 ms` per frame (`CLOCK_MONOTONIC`), including after authorization | Section 2.1.1: cumulative from its first byte through header and payload, never extended by progress; the initial hello also remains subject to the original accept-based deadline. |
| **Outer Envelope String Limits** | `dsse_envelope.payload`: max `87384` ASCII Base64 bytes (64 KiB raw); `signatures[].sig`: max `32768` Base64 bytes; `signatures[].keyid`: max `128` ASCII bytes | Checked during `CLIENT_HELLO` parsing; returns `INVALID_REQUEST`. |
| **Inner Warrant / Request JSON Limits** | Max decoded byte length `65536` (64 KiB); max nesting depth `8`; max array length `256`; max `env_exact` / `caller_env` entries `128`; **max individual string length `4096` UTF-8 bytes** | Checked during strict JSON deserialization; returns `INVALID_REQUEST`. |
| **Global / Per-UID Pinned Snapshot RAM** | Captured `snapshot_ram_global_bytes` / `snapshot_ram_per_uid_bytes` (defaults `512 MiB` / `128 MiB`; immutable ceilings equal defaults) | Reserved before `memfd_create` and held until `close(memfd)` completes; returns `RESOURCE_EXHAUSTED`. |
| **Max Executable Size** | Captured `max_executable_bytes` (default `67108864`; immutable ceiling `67108864`) | Checked via `fstat()` and after every `65536`-byte read chunk. |
| **Max Hashed `stdin` Size** | Captured `max_stdin_bytes` (default `16777216`; immutable ceiling `16777216`) | Reserved up front (the captured `max_stdin_bytes` against UID quota during read, trimmed to actual size at `EOF`) and checked on every chunk. |

---

### 1.3.1 Request Ownership, Cancellation, and Irreversible Operations

Each request has an atomic lifecycle state `SNAPSHOTTING -> AUTHORIZING -> COMMITTING -> COMMITTED -> SPAWNING -> RUNNING`, terminal states `CANCELLED` and `FAILED`, an atomic `cancelled` flag, and a single decision slot initially `UNDECIDED`. Hooks use separate hook-context state; this lifecycle describes job admission. Lifecycle state and decision slot form one atomic control word; transitions use acquire/release compare-and-swap (CAS), never an unchecked load followed by a store. Claiming a terminal outcome or readiness updates state/decision together, so a stale live-state observation cannot publish readiness after a terminal winner. Only the request coordinator advances authorization; I/O workers only produce owned sealed snapshots or errors, and **never** perform authorization, commit, audit authorization RPCs, or spawn children themselves.

* **Snapshot completion vs. timeout:** The captured request deadline covers hello reception and common snapshotting. The coordinator checks the monotonic deadline and CASes `SNAPSHOTTING -> AUTHORIZING` only after both snapshots are complete. The timer competes with CAS `SNAPSHOTTING -> CANCELLED`; only one can win. If the deadline has already passed, completion must take the cancellation path even if the timer callback has not run. Losing completions close their owned results and cannot commit or spawn. A successful transition disarms that phase's timer; stale callbacks carry a phase/generation identifier and cannot cancel a later phase. Captured `hook_timeout_ms` (default `25000 ms`, immutable ceiling `25000 ms`), captured `collector_rpc_timeout_ms` (default `3000 ms`, immutable ceiling `3000 ms`), and partial-frame deadlines remain separate; the original snapshot deadline does not forbid the documented longer hook pipeline.
* **Terminal decisions and external cancellation:** Cancellation from disconnect, malformed frames, or an active phase deadline sets `cancelled` and CASes a cancellable state (`SNAPSHOTTING`, `AUTHORIZING`, or `COMMITTED`) to `CANCELLED`; a `RUNNING` request may also be cancelled, with immediate tracked-child teardown. Rejection similarly claims `FAILED`. A response requires the matching combined-state CAS from decision `UNDECIDED` to the selected decision; only the winner may send `SERVER_AUTH_DECISION`. Disconnect may claim a non-wire `NO_REPLY` outcome instead. Neither terminal state may transition back to a live state. Once readiness has been reported, later cancellation performs job teardown without sending another auth decision. Cancellation retains all worker/FD/RAM quota accounting until actual owner cleanup, as in Section 1.3.
* **Commit reservation:** Immediately before database `COMMIT`, recheck `cancelled`, connection liveness, and the current phase deadline, then CAS `AUTHORIZING -> COMMITTING`. A cancellation that already won prevents the CAS and forces `ROLLBACK`. The commit executor checks cancellation again immediately before issuing `COMMIT`; otherwise it rolls back. `COMMITTING` reserves the operation against a competing terminal-state transition. Cancellation arriving during that reservation sets the flag and is reconciled when the operation returns: a completed commit may have consumed a one-time grant, but cancellation prevents further authorization/spawn. On success, advance to `COMMITTED`; if cancellation is pending, immediately claim `CANCELLED`, append the required local `AUTH_COMMIT` and post-commit abort, and do not spawn. This audit reconciliation is serialized by the Audit & Replication Sequencer even when the client has disconnected. Never tell a client that a timeout rolled back an already-completed commit.
* **Spawn reservation:** After audit/collector authorization, recheck cancellation, connection liveness, active phase deadlines, and warrant expiry immediately before CAS `COMMITTED -> SPAWNING`. Recheck cancellation once more immediately before `clone3()`. A prior terminal-state winner prevents spawn. If cancellation arrives after the reservation/final check, the syscall may already be in flight: do not publish a cancellation decision while claiming no child could exist. Register the returned PID/pidfd, reconcile cancellation, kill the new job cgroup and reap the child if necessary, then finish cancellation without reporting readiness. Only a non-cancelled successful clone advances to `RUNNING` and sync-handshake classification.
* **Reservation semantics:** Commit and spawn admission linearize at their CAS reservations. No terminal timeout response may race with a reserved operation and then be followed by untracked side effects. Pending cancellation during a reservation is resolved only after that operation's result is known and cleanup is arranged; an uninterruptible kernel operation can delay this response, just as it can delay resource reclamation. A check alone cannot eliminate the interval between a userspace check and a syscall. Test these races with deterministic gates, not timing assumptions.

### 1.3.2 Independent Denial Delivery and Audit Ownership

Before admitting a requester, reserve one bounded rejection-audit slot against
both UID and global limits. The reservation includes storage for at most one
`audit_record_max_bytes` record plus bounded metadata, and remains charged
through queued/in-flight persistence or fatal shutdown, independently of the
socket and I/O-worker leases. Transfer ownership exactly once. A queue entry
must never depend on a live connection object to remain owned.

A pre-commit terminal winner (timeout, refusal, policy denial, unavailable
approver or resource denial) publishes its decision immediately on the
nonblocking control path, with the existing five-second send deadline. It
queues its rejection record using that reserved capacity; it does not wait
for SQLite, audit fsync, or descriptor disposal. A late audit completion can
release ownership but cannot publish another decision or revive the request.
A denial therefore does not promise that its audit record is already durable;
a crash may lose a queued rejection. Authorization retains the durable
`AUTH_COMMIT` and optional remote-ACK requirements before spawning. Cancellation
in `COMMITTING` or `SPAWNING` still follows Section 1.3.1 reconciliation and
cannot use this rule to report an unreserved outcome.

If admission cannot reserve audit capacity, close the new connection before
receiving rights or parsing a request. Do not enqueue an individual durable
record for that refusal. Aggregate admission-refusal counts in fixed-size,
saturating counters and emit at most one coalesced diagnostic per admission
window when bounded audit capacity is available. Reserve one global diagnostic
slot within the configured global audit limit; diagnostics cannot consume
request reservations. Repeated errors must not create an unbounded side queue.
For accepted requests, transfer the reservation into the committed-job context
and retain it through the last required outcome record. Emit that context's
records sequentially, reusing its bounded capacity after each append completes;
never accumulate an unbounded per-job event list. Hook/replication diagnostics
must also obtain bounded capacity before producing records.
An admitted request that later lacks worker capacity can use its already-owned
audit reservation to report `RESOURCE_EXHAUSTED`. Fatal persistence failure
stops admission and invokes Section 2.4.1; it never permits execution merely
because a rejection was already delivered.

Successful authorization transfers an owned committed-job context to the
coordinator: exact warrant bytes, selected eligible unrevoked signer,
consumption/commit identity, sealed snapshots, validated argv/envp, captured
policy/root identities and all resource leases. The coordinator alone reserves
spawning. Neither reconnection nor a worker completion may recopy the binary,
change signed inputs, consume again or independently spawn. Pending-spawn,
live-job and cleanup ownership survive loss of the client connection.

### 1.4 Normative Daemon Configuration and Policy Generations

`sigrund` reads one canonical TOML configuration at `/etc/sigrund/config.toml` before startup and fails closed on a missing file, unknown key, duplicate key, invalid type, non-canonical path/list, or failed validation. The following schema and defaults are normative; omitted optional keys take the shown default:

```toml
# Identity and authorization
allow_same_uid_elevation = false       # bool
require_remote_audit_ack = false       # bool
csr_allowed_executable_dirs = ["/usr/bin", "/usr/sbin"] # sorted absolute paths

# Hook identity and quotas
sigrun_hook_uid = 65534                 # uint32, != UINT32_MAX
sigrun_hook_gid = 65534                 # uint32, != UINT32_MAX
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
max_stdin_bytes = 16777216              # positive uint64
request_deadline_ms = 5000              # positive uint32
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

`csr_allowed_executable_dirs` is a sorted, duplicate-free list of absolute directory paths that are neither `/` nor descendants with `.`/`..`/empty components. Every `[[signers]]` entry must contain an exactly equal canonical list in `allowed_executable_dirs`; a signer list that differs, is broader, or is absent rejects the complete configuration. The daemon pre-opens and pins these roots once per policy generation. `collector_base_url`, TLS files, key ID, and public key are required and validated for every configuration generation, even when remote ACK is disabled; network use is disabled in that mode. Hook UID/GID, all quotas, and job limits are root-controlled configuration and cannot be raised by warrants. The host must expose a writable `memory.swap.max` file in the delegated hierarchy; `job_memory_swap_max_bytes` may be zero or a finite nonnegative value and is written/read back on every startup probe and job cgroup. Missing swap control is a startup failure. `max`/unlimited values are rejected.

The following are immutable protocol/security ceilings, not freely adjustable limits: frame payload maxima and JSON structural limits in Section 2.1.1; `max_active_sockets_global/per_uid <= 64/4`; `max_io_workers_global/per_uid <= 16/2`; `request_deadline_ms <= 5000`; `snapshot_ram_global_bytes <= 536870912` and `snapshot_ram_per_uid_bytes <= 134217728`; `max_executable_bytes <= 67108864`; `max_stdin_bytes <= 16777216`; `hook_timeout_ms <= 25000`; `collector_rpc_timeout_ms <= 3000`; control-frame assembly/send deadlines remain the immutable `5000 ms` protocol deadline; `audit_record_max_bytes == 65536`; and finite numeric/identifier bounds in Section 3.5. Admission counters, audit reservations and storage/shutdown controls follow the process-wide rules below; their stated maxima are immutable. All other listed numeric values are captured from the policy generation at request admission and used consistently for that request, hook pipeline, RPC, snapshots, and job cgroup. A lower value may reduce availability or resource consumption; no reload or warrant may exceed a ceiling.

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
The root-only broker retains its separate connection/pipeline limits and
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

## 2. Wire Protocol, Request Shapes, and Job Lifecycle

### 2.1 Binary Framing & Terminal Status Contract (Resolving Finding 3)

All traffic on `/run/sigrund.sock` uses length-prefixed binary frames:

```text
+------------------+-------------------+-----------------------------------+
| Frame Type (1 B) | Payload Len (4 B) | Payload (Big-Endian Length Bytes) |
+------------------+-------------------+-----------------------------------+

```

* `0x01 CLIENT_HELLO`: Sent once by `sigrun` upon connection, accompanied by exactly one `SCM_RIGHTS` message when `tty_mode == "stdio"`, containing the descriptors required by Section 2.3; `tty_mode == "pty"` sends none. Ancillary data is attached only to the first frame-type byte, as specified below.
* `0x02 SERVER_AUTH_DECISION`: Sent once by `sigrund`:
```json
{
  "csr_payload": null,
  "exec_id": "0192d8f4-9a00-7000-8000-112233445566",
  "message": "Authorized and ready to attempt exec via mandator-alice-yubikey",
  "status": "READY_TO_EXEC"
}

```


Valid `status` values:
* **Setup Complete (`"READY_TO_EXEC"`):** Emitted **only after** `clone3()` succeeds, the child completes all 10 setup and read-back verification steps, writes the 8-byte `READY_TO_EXEC` token (`{ step: 0, errno: 0 }`) to `sync_pipe_w` at the exec call boundary, and `sync_pipe_r` reaches `EOF` without an `EXECVEAT_ERR` frame (Section 2.4). This proves setup completion only. It does **not** prove that `execveat()` was entered or succeeded: the child can be killed after writing the token and before the syscall, or before reporting a returned error. This state replaces `APPROVED` in the wire protocol; v1.0 exposes no exact exec-success status for an arbitrary directly executed target. The subsequent `0x05 SERVER_CHILD_EXIT` reports the primary child's termination, whether it died before or after exec.
* **Pre-Exec / Spawn Rejection:** `"REJECTED"`, `"TIMEOUT_CSR"`, `"INVALID_REQUEST"`, `"INVALID_TTY_STDIN_COMBINATION"`, `"POLICY_VIOLATION"`, `"EXPIRED_OR_NOT_YET_VALID"`, `"REVOKED"`, `"REPLAY_DETECTED"`, `"EXECUTABLE_MUTATED_OR_TOO_LARGE"`, `"STDIN_HASH_MISMATCH"`, `"REMOTE_AUDIT_FAILED"`, `"REQUEST_TIMEOUT"`, `"RESOURCE_EXHAUSTED"`, `"SPAWN_FAILED"`.


* `0x03 CLIENT_SIGNAL`: `{ "signal": 15 }` (`SIGINT=2`, `SIGTERM=15`, `SIGHUP=1`, `SIGUSR1=10`, `SIGUSR2=12`).
* `0x04 CLIENT_WINSIZE`: `{ "cols": 120, "rows": 40, "xpixel": 0, "ypixel": 0 }`.
* `0x05 SERVER_CHILD_EXIT`: `{ "exit_code": 0, "signal": null }` (emitted once after the primary child exits and its cgroup is torn down). The object has exactly these two required keys. For `CLD_EXITED`, `exit_code` is an integer in `0..=255` and `signal` is `null`; for `CLD_KILLED`/`CLD_DUMPED`, `exit_code` is `null` and `signal` is an integer in `1..=64`. Exactly one is non-null; both null, both non-null, missing/extra keys, and other wait-status codes are protocol errors. Stop/continue notifications never produce this frame.
* **Client Exit & Status Reporting Contract:**
* When `--status-fd N` is passed to `sigrun`, `sigrun` writes the JSON payloads of `0x02 SERVER_AUTH_DECISION` and (if `"READY_TO_EXEC"`) `0x05 SERVER_CHILD_EXIT` as newline-delimited JSON to FD `N`.
* If `status == "READY_TO_EXEC"`, `sigrun` relays terminal resize/signal events, waits for `0x05 SERVER_CHILD_EXIT`, and exits with `exit_code` (or `128 + signal`). If the daemon connection drops unexpectedly after `"READY_TO_EXEC"` without a `SERVER_CHILD_EXIT` frame, `sigrun` writes `{ "error": "DAEMON_DISCONNECTED" }` to `--status-fd` (if enabled) and exits with `254`.
* If `status != "READY_TO_EXEC"`, `sigrun` formats the sanitized `message` (and the canonical JCS JSON string `csr_payload`, without PEM armor, if `status == "TIMEOUT_CSR"`) to `stderr` and exits with `255` (configurable via `--auth-fail-exit-code`).



### 2.1.1 Per-Type Size Limits, State Validation, and Frame Deadlines

Both endpoints enforce the following maximum serialized UTF-8 JSON **payload** lengths, excluding the five-byte frame header. Senders check limits before sending; receivers check the type before reading the length and the length before allocating or reading the payload:

| Type | Direction and Allowed State | Maximum Payload Bytes |
| --- | --- | --- |
| `0x01 CLIENT_HELLO` | Client to daemon, first frame only | `196608` |
| `0x02 SERVER_AUTH_DECISION` | Daemon to client, first frame only | `524288` |
| `0x03 CLIENT_SIGNAL` | Client to daemon, only after `READY_TO_EXEC` | `64` |
| `0x04 CLIENT_WINSIZE` | Client to daemon, only after `READY_TO_EXEC` with `tty_mode == "pty"` | `128` |
| `0x05 SERVER_CHILD_EXIT` | Daemon to client, once after `READY_TO_EXEC` | `128` |

* **Reject Before Allocation:** An unknown type, wrong direction, duplicate decision/hello/exit, or type invalid for the current state is a terminal protocol error immediately upon reading the type byte; do not wait for its length or payload. For a valid type, collect only the four-byte length, interpret it as an unsigned big-endian `u32`, and reject zero or lengths above the table limit before allocating payload storage. Do not drain an oversized payload or attempt stream resynchronization. Bound userspace receive storage to one incomplete frame (five-byte header plus that type's maximum payload); never allocate from an unchecked length or queue unbounded raw input.
* **Bounded JSON:** Reject invalid UTF-8/JSON, duplicate keys, excessive nesting (maximum `8`), unexpected fields, and wrong field types. `CLIENT_SIGNAL` has exactly one integer `signal` from the Section 2.4 allowlist; `CLIENT_WINSIZE` has exactly four integers `cols`, `rows`, `xpixel`, and `ypixel`, each in `0..=65535`. A decision's `message` is at most `4096` UTF-8 bytes and non-null `csr_payload` at most `65536` UTF-8 bytes before JSON escaping; the `524288`-byte wire bound includes escaping and all other fields. `csr_payload` is non-null only for `TIMEOUT_CSR`. A sender unable to serialize a valid bounded response fails the connection rather than sending an oversized frame.
* **Cumulative Assembly Deadline in Every State:** Once the first byte of any frame is received, both endpoints start a `5000 ms` `CLOCK_MONOTONIC` deadline covering the rest of the type/header/payload assembly and validation. Partial reads, `EINTR`, `EAGAIN`, new ancillary data, or trickled bytes never reset it. For the initial `CLIENT_HELLO`, use the earlier of this deadline and the existing `accept_time + 5000 ms` deadline; executable/stdin collection still shares that accept-based deadline. After authorization, apply the same per-frame cumulative deadline to every signal/window-size frame, independent of job runtime. Idle connections with no partial frame do not start this timer; an idle control socket must not terminate a healthy long-running job. The client likewise permits the daemon's authorization/hook processing and job runtime while no server frame is in progress.
* **Error and Timeout Teardown:** A daemon receiving an oversized/invalid frame closes all delivered and retained request FDs under Section 2.3.1 and closes the connection. Before a decision, it may send one bounded `INVALID_REQUEST` (or `REQUEST_TIMEOUT` on assembly expiry) if the socket remains writable; it must not wait for the invalid payload. After `READY_TO_EXEC`, it sends no second decision and immediately starts Section 2.4 disconnect teardown, including `cgroup.kill`; frame assembly never delays primary-child exit processing, teardown, or the Central Reaper. A client detecting invalid framing, oversized data, or assembly expiry closes all received/retained PTY FDs and the control socket, restores its local terminal, writes `{ "error": "SERVER_PROTOCOL_ERROR" }` to `--status-fd` if enabled, and exits `254`. Unexpected EOF instead uses `DAEMON_DISCONNECTED` with the same cleanup and exit code. Neither endpoint processes another frame after a framing error.
* **Bounded Sending:** Each outgoing frame also has a cumulative `5000 ms` nonblocking send deadline from when that frame is ready to send, including its first byte and all short writes/retries. Failure or expiry closes the connection and follows the same ownership/disconnect cleanup. This does not impose a deadline on waiting for authorization or job completion before a server frame is ready.

### 2.2 Signed and Unsigned `CLIENT_HELLO` Schemas

* **Mode A: Signed Request (`mode == "signed"`)**
```json
{
  "caller_env": {
    "TERM": "xterm-256color"
  },
  "dsse_envelope": {
    "payload": "<base64-jcs-warrant-bytes>",
    "payloadType": "application/vnd.sigrun.warrant.v1+json",
    "signatures": [
      {
        "keyid": "mandator-alice-yubikey",
        "sig": "<base64-signature-bytes>"
      }
    ]
  },
  "mode": "signed",
  "tty_mode": "stdio"
}

```


* **Mode B: Unsigned Hook / CSR Request (`mode == "unsigned_csr_request"`)**
```json
{
  "caller_env": {},
  "mode": "unsigned_csr_request",
  "requested_command": {
    "allow_interpreted_script": false,
    "argv": [
      "/usr/bin/systemctl",
      "restart",
      "nginx.service"
    ],
    "cwd": "/var/empty",
    "executable_path": "/usr/bin/systemctl",
    "stdin_policy": "null",
    "tty_mode": "stdio"
  },
  "requested_execution_context": {
    "capabilities": [
      "CAP_SYS_ADMIN"
    ],
    "env_exact": {
      "LANG": "C.UTF-8",
      "PATH": "/usr/sbin:/usr/bin"
    },
    "caller_env_allowlist": [],
    "supplementary_gids": [],
    "target_gid": 0,
    "target_uid": 0,
    "umask": 63
  },
  "requested_policy": {
    "mode": "one_time",
    "ttl_secs": 900
  },
  "tty_mode": "stdio"
}

```


Both request modes must complete the common phase below. Unsigned requests do not have a separate snapshot implementation.

### 2.2.1 Common Executable and Standard-Input Snapshot Phase

1. **Validated Inputs and Candidate Roots:** After bounded hello/ancillary validation, extract `command` from the canonical signed warrant or `requested_command` from an unsigned request. For signed requests, first verify the DSSE signatures and select one candidate signer under Section 3.4, and check the host, peer, static policy ceilings, and path eligibility that do not depend on snapshots. Use that signer's `allowed_executable_dirs`. For unsigned requests, require the top-level `tty_mode` to equal `requested_command.tty_mode` byte-for-byte **before any snapshot or hook execution**; validate request syntax, peer identity, admission, and Section 2.3 compatibility, and use daemon `csr_allowed_executable_dirs` (default `["/usr/bin", "/usr/sbin"]`). This daemon ceiling permits snapshot preparation, not execution. The daemon configuration must satisfy the exact-root relationship in Section 1.4: every signer has the same canonical `allowed_executable_dirs` list as `csr_allowed_executable_dirs`; otherwise configuration load/startup fails closed. Thus the unsigned snapshot root metadata is already valid for every signer a hook may select. Pre-open these configured directories at startup as specified in Section 4.2 Predicate 6.
2. **Executable Copy:** On the bounded I/O worker pool, resolve the absolute executable path by the prefix-selection/stripping algorithm in Predicate 6. `fstat()` must show a regular file with a positive `st_size` no greater than the captured `max_executable_bytes` for this policy generation. Reserve that many snapshot bytes before creating `exec_memfd` with `MFD_CLOEXEC | MFD_ALLOW_SEALING | MFD_EXEC`; retain the source identity and selected root metadata. Read in chunks of at most `65536` bytes, handling short reads/writes and checking deadline/cancellation before and after each chunk. Require EOF at exactly the initial `st_size`; early EOF, extra bytes, or changed size at final `fstat()` rejects with `EXECUTABLE_MUTATED_OR_TOO_LARGE`. Hash exactly the copied memfd bytes. If scripts are disabled require ELF magic and mode `0111`; otherwise use `0555` and require signer script permission at final authorization. Before sealing, apply root ownership and that mode. Install and read back `F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_FUTURE_WRITE`; any failure aborts. Source writes during copying are not an atomic source-file snapshot, but subsequent authorization binds exactly the completed sealed bytes.
3. **Hashed Standard Input:** If `stdin_policy == "sha256"`, reserve captured `max_stdin_bytes` bytes, copy the validated client stdin FD on the same bounded pool to `stdin_memfd` (`MFD_CLOEXEC | MFD_ALLOW_SEALING`) until EOF, enforcing the captured `max_stdin_bytes` maximum and the same chunk/deadline/cancellation rules. Empty stdin is valid. Hash the exact bytes, install/read back the same seals, rewind to offset `0`, close the original client stdin FD, and trim the reservation to actual size. For `null` or `unrestricted_interactive`, create no stdin snapshot and require `stdin_sha256: null`; use Section 2.3's `/dev/null`, passed FD, or PTY behavior instead.
4. **Bind the Request to Results:** A signed request compares both applicable digests against its signed lowercase SHA-256 fields (`STDIN_HASH_MISMATCH` for stdin, `EXECUTABLE_MUTATED_OR_TOO_LARGE` for executable) and passes the retained sealed FDs to the full Section 4.2 gate. An unsigned request populates the CSR with the measured digests, actual `SO_PEERCRED` UID/GID, local `host_id`, a fresh UUIDv7 `grant_id`, and `not_before = now`, `not_after = now + ttl_secs` (or null for `permanent`), then serializes canonical JCS and invokes Section 6. The completed CSR is at most `65536` UTF-8 bytes. A returned warrant must agree with every CSR field, including command, execution context, policy, host/peer, grant, and digests; run all signature and authorization checks against the **same sealed FDs and retained root metadata**. Never reopen or recopy an executable/stdin after hook approval to make a differing warrant fit.
5. **Handoff and Cleanup:** Both modes hand completed results to the coordinator through Section 1.3.1's CAS, within the original accept-based deadline. No database consumption or job spawn is allowed before successful handoff and the full authorization gate. On cancellation/error, each owning worker closes its sources/memfds when it actually returns; snapshot quota remains pinned until then. The executable is executed only via the retained sealed `exec_memfd`, not by reopening its path.


### 2.3 `tty_mode` and `stdin_policy` Compatibility Matrix

`warrant.command.tty_mode` must equal `CLIENT_HELLO.tty_mode`; for `unsigned_csr_request`, `requested_command.tty_mode` must equal both the top-level `CLIENT_HELLO.tty_mode` and the top-level request `tty_mode` before Section 2.2.1. Any mismatch is rejected with `INVALID_TTY_STDIN_COMBINATION` before snapshotting or hooks. Any combination outside the first four rows is rejected with `INVALID_TTY_STDIN_COMBINATION`:

| `tty_mode` | `stdin_policy` | Required `SCM_RIGHTS` FDs | Permitted FD Types (`fstat`) | `stdin_sha256` Requirement |
| --- | --- | --- | --- | --- |
| **`"stdio"`** | **`"null"`** | Exactly 2 FDs (`stdout`, `stderr`); child `FD 0` is `/dev/null` | `S_ISFIFO`, `S_ISREG`, or `/dev/null` (`makedev(1,3)`). **All other `S_ISCHR` (including caller TTYs), `S_ISSOCK`, `S_ISDIR`, and `O_PATH` are rejected.** | Must be `null`. |
| **`"stdio"`** | **`"sha256"`** | Exactly 3 FDs (`stdin`, `stdout`, `stderr`) | `stdin`: `S_ISFIFO` or `S_ISREG` (copied into sealed `stdin_memfd`, then client FD closed).<br>

<br>`stdout`, `stderr`: `S_ISFIFO`, `S_ISREG`, or `/dev/null` (`S_ISCHR` TTYs rejected). | 64-char lowercase hex SHA-256 matching `SHA256(stdin_memfd)`. |
| **`"stdio"`** | **`"unrestricted_interactive"`** | Exactly 3 FDs (`stdin`, `stdout`, `stderr`) | `S_ISFIFO`, `S_ISREG`, or `S_ISCHR`. (`S_ISSOCK`, `S_ISDIR`, `O_PATH` rejected). | Must be `null`. |
| **`"pty"`** | **`"unrestricted_interactive"`** | **0 FDs** (any `SCM_RIGHTS` rejected) | `sigrund` allocates a fresh PTY pair via `posix_openpt(O_RDWR | O_NOCTTY)` and passes exactly one master PTY FD to `sigrun` on the type byte of `SERVER_AUTH_DECISION` (`"READY_TO_EXEC"`) under Section 2.3.2. | Must be `null`. |
| **`"pty"`** | **`"null"`** or **`"sha256"`** | **FORBIDDEN** | Rejected with `INVALID_TTY_STDIN_COMBINATION`. | N/A |

For a requester invoked from a terminal in `stdio/null` or `stdio/sha256`
mode, `sigrun` must provide pipe write ends for stdout/stderr and relay their
read ends to the local sinks. It must not pass TTY descriptors or silently
switch to unrestricted input to make the request succeed. Keep the two output
streams separate and queues bounded; service control frames and cancellation
under sink backpressure, including sinks whose writes may block. After receiving
the child-exit frame, drain pending output through pipe EOF before returning
the child status. Broken sinks abort the request and close its control socket.
Before readiness, user cancellation closes the socket; afterward only the
specified signals are forwarded. No PTY or raw-terminal setup is implied by
this relay. Child output remains untrusted and never feeds an approval prompt.

### 2.3.1 Normative `recvmsg()` and Descriptor Ownership Rules

The following rules govern all client-to-daemon reads on the `SOCK_STREAM` control socket; the FD matrix alone is insufficient:

1. **Receive Every Byte with Ancillary Inspection:** Use `recvmsg(..., MSG_CMSG_CLOEXEC | MSG_DONTWAIT)` for every receive, including after `CLIENT_HELLO`; do not use `read()`, `recv()`, or `MSG_PEEK` paths that discard or duplicate ancillary delivery. Supply a bounded control buffer of `CMSG_SPACE(3 * sizeof(int))` on every call, reset `msg_controllen` before each call, and inspect returned `msg_flags` and every returned `cmsghdr` before accepting payload bytes. Received descriptors acquire `FD_CLOEXEC` atomically via `MSG_CMSG_CLOEXEC`; setting it afterward with `fcntl()` is insufficient.
2. **Unambiguous Frame Association:** For `stdio`, the client uses one `sendmsg()` to send exactly the first byte (`0x01 CLIENT_HELLO`) with its complete descriptor set in one `SOL_SOCKET`/`SCM_RIGHTS` message; for `pty`, it sends that byte with no ancillary data. It then sends the four-byte length and JSON payload without ancillary data. The daemon uses a one-byte iovec until its first successful data-bearing `recvmsg()` returns that type byte (retrying `EINTR` and waiting for readiness on `EAGAIN`); this is the only receive eligible to accept descriptors. Subsequent reads are bounded to the remaining header or payload of the current frame, never spanning frame boundaries. Stream fragmentation does not relax the rule: descriptors attached to the length, payload, a later frame, or any later receive are rejected. A second `CLIENT_HELLO` is a protocol error.
3. **Strict Control Validation:** Reject `MSG_CTRUNC` unconditionally, even if the visible descriptors appear to satisfy the matrix. Reject malformed control lengths (including an `SCM_RIGHTS` payload that is empty or not an integral number of `int` FDs), more than one returned ancillary message, and any message other than `SOL_SOCKET`/`SCM_RIGHTS`. `SO_PASSCRED` and, where supported, `SO_PASSPIDFD` are disabled; caller identity comes from `SO_PEERCRED`, not ancillary credentials. Ancillary messages on any receive after the initial type byte are forbidden. Linux may coalesce sender-side rights messages; validate the messages actually returned by `recvmsg()` and their aggregate descriptor count, without claiming to recover sender-side control-message boundaries.
4. **Exact Descriptor Count and Deferred Use:** Collect all descriptors returned on the eligible receive into request-owned storage, but do not use them until the complete bounded `CLIENT_HELLO` parses and the count, order, and types match Section 2.3. Reject extra descriptors immediately (including any that fit in control-buffer alignment padding); never discard extras and accept a prefix. Reject missing descriptors once the frame is complete. For `pty`, any received descriptor is invalid. For `stdio`, the sole ancillary message must supply exactly the matrix's two or three FDs in the specified order. Check types with `fstat()` and reject `O_PATH` using `fcntl(F_GETFL)` before use.
5. **Close on Every Failure; Never Resynchronize:** On truncation, unexpected/multiple messages, extra FDs, invalid framing/JSON, EOF before frame completion, timeout, or any later validation failure, close **every FD delivered by that receive**, including those in other returned `SCM_RIGHTS` messages, plus every FD already held by the rejected request. Inspect all safely traversable returned control messages and collect their FDs before taking a rejection branch; an error in one message must not leak FDs from another. The kernel closes rights omitted by control truncation; the daemon closes all rights actually delivered. Transfer FD ownership exactly once only after validation. A framing or ancillary error is terminal for the connection: discard buffered input, close the socket (which releases queued, undelivered rights), and never parse a later frame or associate later descriptors with another request. Send `INVALID_REQUEST` if no decision has yet been sent and a response is possible; otherwise follow the active-job disconnect teardown in Section 2.4. Normal completion and disconnect also close all request-owned FDs. Cleanup of FDs already transferred to an I/O worker follows Section 1.3: cancel that task, retain its quota accounting until its owner actually closes the FDs, and never double-close a transferred descriptor.

### 2.3.2 Server-to-Client PTY Transfer and Ownership

1. **The Only Eligible Server Frame:** Exactly one PTY master FD is sent if and only if the request uses `tty_mode == "pty"` and the daemon sends `SERVER_AUTH_DECISION` with `status: "READY_TO_EXEC"`. Every rejection (including `SPAWN_FAILED`), every `stdio` decision, and every `SERVER_CHILD_EXIT` carries **zero** FDs and no ancillary messages. The daemon prepares the complete bounded decision payload before starting the transfer; it must not send a readiness byte/FD and then substitute a rejection payload.
2. **Exact `sendmsg()` Layout:** For an eligible decision, `sigrund` sends one byte `0x02` in a single one-byte iovec, with one `cmsghdr` whose `cmsg_level = SOL_SOCKET`, `cmsg_type = SCM_RIGHTS`, `cmsg_len = CMSG_LEN(sizeof(int))`, and whose data is exactly one native `int` containing the PTY master FD. The zero-initialized control buffer and `msg_controllen` have size `CMSG_SPACE(sizeof(int))`. Call `sendmsg(..., MSG_NOSIGNAL | MSG_DONTWAIT)` until it returns exactly `1`, retrying only `EINTR`/`EAGAIN` within the Section 2.1.1 send deadline. After that byte succeeds, never resend the rights: send the four-byte big-endian payload length and JSON payload, allowing short writes, with **no ancillary data**. A zero return, unrecoverable error, partial-frame failure, or expiry terminates the connection. All ineligible frames send their type byte without ancillary data. Serialize complete frames so the terminal frame cannot interleave with the decision.
3. **Client `recvmsg()` Validation:** `sigrun` uses `recvmsg(..., MSG_CMSG_CLOEXEC | MSG_DONTWAIT)` for every server receive, with a bounded `CMSG_SPACE(sizeof(int))` control buffer reset before each call; it never uses a receive path that discards ancillary data. Disable `SO_PASSCRED` and, where available, `SO_PASSPIDFD`. Read each frame-type byte with a one-byte iovec, then read only the remaining length/payload of that frame. Reject `MSG_CTRUNC`, malformed control lengths, unexpected levels/types, more than one returned ancillary message, and an aggregate count other than exactly one FD for an eligible decision (including extra FDs that fit alignment padding). No ancillary data is allowed on the length/payload or any later frame. Retain a received FD as pending, without using it, until the complete size-bounded decision JSON passes validation within its assembly deadline. As in Section 2.3.1, Linux may merge sender-side rights messages; validate returned control structures and the complete delivered FD count.
4. **Decision/FD Binding and Faults:** Only a validated `pty`/`READY_TO_EXEC` decision can promote its pending FD to the client's active PTY master. A missing FD, duplicate/extra FD, an FD received on a rejection or `stdio` decision, malformed ancillary data, or misplaced rights is a terminal server protocol error, even if the JSON itself is otherwise valid. Check `fstat()` for `S_ISCHR`, `fcntl(F_GETFL)` for `O_RDWR` and absence of `O_PATH`, and successful `ioctl(fd, TIOCGPTN, &pty_number)` to verify a PTY master before use; syscall failure or mismatch is also a protocol error. The received FD must already have `FD_CLOEXEC` from `MSG_CMSG_CLOEXEC`; after validation, set `O_NONBLOCK` for terminal relaying. Close every FD actually delivered on a failed receive/decision, not merely the first FD, and any previously pending or active PTY FD. Report `SERVER_PROTOCOL_ERROR`, restore the local terminal, close the control socket, and exit `254` as in Section 2.1.1; do not fall back to stdio or treat missing rights as a successful rejection.
5. **Ownership Across Transfer and Disconnect:** `SCM_RIGHTS` creates a client-owned descriptor referring to the same open file description; successful `sendmsg()` does not close the daemon's descriptor. The daemon owns the initial master/slave descriptors, sets them close-on-exec, and closes its slave after successful `clone3()` (the child owns its inherited slave references). It retains one master for validated `CLIENT_WINSIZE` handling via `ioctl(master_fd, TIOCSWINSZ, ...)`, without competing for PTY data reads. On rejection, spawn/send failure, normal job teardown, or client disconnect, the daemon closes its master and every remaining parent-owned slave descriptor as part of cleanup. The client owns a pending FD immediately upon receipt and the active master after validation; it closes pending/active FDs on any protocol/read/send/relay failure, normal job completion, or daemon disconnect, restores its terminal, and closes the control socket. A client exit or failure therefore triggers daemon disconnect teardown even if rights were transferred before the decision payload completed. Unexpected EOF during that transfer closes the pending FD and reports `DAEMON_DISCONNECTED`. Closing either endpoint's socket releases queued undelivered rights; neither endpoint may rely on socket closure to close FDs already delivered into userspace. The client's active master is also closed on daemon disconnect even if another process still holds the slave; it must not wait for PTY EOF before disconnect cleanup.

### 2.4 Two-Frame `sync_pipe` Exec Handshake & Centralized Reaper (Resolving Findings 3 & 4)

1. **Two-Frame Pre-Exec Handshake on `sync_pipe` (Setup Readiness and Reported Failures):**
* A child killed before writing the readiness frame produces `0` bytes followed by `EOF`. A child killed after writing the frame but before entering `execveat()` produces the same 8-byte frame followed by `EOF` as a successful exec, including a fast `/bin/true` exit. Death after an exec error but before writing its error frame is also indistinguishable. `EOF` means the write end closed; `FD_CLOEXEC` cannot establish why it closed. Direct execution of an arbitrary target cannot provide an exact parent-side exec-success notification in this race window. A stronger contract would require a trusted post-exec trampoline reporting after its own exec transition; v1.0 does not implement one or claim target exec success.
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
* **Exactly `8` bytes read equal to `{ step: 0, errno: 0 }` followed by `EOF`:** All 10 setup steps passed; exec outcome is unknown -> classified as `READY_TO_EXEC`. `sigrund` appends `EXEC_READY_TO_EXEC` (`child_pid`, `exec_outcome: "unknown"`) to the audit log and sends `0x02 SERVER_AUTH_DECISION` (`status: "READY_TO_EXEC"`). This classification also applies to a child killed in the post-token/pre-syscall window. The Central Reaper preserves any already-observed terminal status and sends it afterward in `0x05 SERVER_CHILD_EXIT`; a signal termination or exit code alone does not establish whether exec occurred.
* **Any other byte sequence, partial frame, or excess bytes:** Protocol fault -> classified as `SPAWN_FAILED`. Reads may split or combine frames; the parent accumulates bytes through `EOF`, with a maximum of 16 bytes, before classifying.
* On any `SPAWN_FAILED` outcome, `sigrund` tears down `job-<exec_id>` via `cgroup.kill`, appends `EXEC_SPAWN_FAILED` to the audit log, and sends `0x02 SERVER_AUTH_DECISION` (`status: "SPAWN_FAILED"`).




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
2. `sigrund` waits for `populated 0` on `job-<exec_id>/cgroup.events` via `inotify`, invokes the Central Reaper to drain any reparented grandchildren, closes `child_pidfd` and `exec_memfd`/`stdin_memfd` (releasing the UID's snapshot RAM quota), and removes `job-<exec_id>` with `rmdir()`.
3. The job context finishes sync-pipe classification and sends `SERVER_AUTH_DECISION` before any terminal frame. For `READY_TO_EXEC`, `sigrund` appends `EXEC_EXIT` (`exit_code`, `signal`, `disconnected: false`) to `/var/log/sigrund/audit.jsonl`, sends `0x05 SERVER_CHILD_EXIT` to `sigrun`, and closes the client socket. For `SPAWN_FAILED`, it follows the failure path above and sends no subsequent terminal frame.


* **Client Disconnect (`EPOLLHUP` / `EPOLLERR`):** If the client socket closes while the job is active, `sigrund` writes `"1\n"` to `job-<exec_id>/cgroup.kill`, waits for `populated 0`, collects the primary child's termination status via the Central Reaper, releases quotas, removes `job-<exec_id>` via `rmdir()`, and appends `EXEC_EXIT` (`exit_code`, `signal`, `disconnected: true`).



### 2.4.1 Daemon Shutdown and External Cleanup

Block SIGINT/SIGTERM/SIGCHLD before creating threads and receive them through
signalfd. SIGINT/SIGTERM or a fatal durable-store error enters one irreversible
shutdown state: stop both listeners and new commit/spawn reservations, close
control connections, and cancel every request. No new readiness is published
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

* **Payload Type (`payloadType`):** `"application/vnd.sigrun.warrant.v1+json"` (exact length: **38** ASCII bytes).
* **PAE Formula:**
```text
PAE(payloadType, payload) =
    "DSSEv1 "
    || ASCII_DEC(BYTE_LEN(payloadType)) || " " || payloadType || " "
    || ASCII_DEC(BYTE_LEN(payload))     || " " || payload

```


* **Interoperability Test Vector:**
* `payloadType` (38 bytes): `application/vnd.sigrun.warrant.v1+json`
* Sample JCS `payload` (67 bytes):
```json
{"grant_id":"0192d8f4-7c1b-7000-8a01-9f8b3c4d5e6f","version":"1.0"}

```


* Exact 119-byte PAE string:
```text
DSSEv1 38 application/vnd.sigrun.warrant.v1+json 67 {"grant_id":"0192d8f4-7c1b-7000-8a01-9f8b3c4d5e6f","version":"1.0"}

```


* Exact PAE Hex Prefix (first 52 bytes):
`445353457631203338206170706c69636174696f6e2f766e642e73696772756e2e77617272616e742e76312b6a736f6e20363720`



### 3.2 Canonical Warrant Schema (`v1.0`)

```json
{
  "command": {
    "allow_interpreted_script": false,
    "argv": [
      "/usr/bin/systemctl",
      "restart",
      "nginx.service"
    ],
    "cwd": "/var/empty",
    "executable_path": "/usr/bin/systemctl",
    "executable_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "stdin_policy": "null",
    "stdin_sha256": null,
    "tty_mode": "stdio"
  },
  "execution_context": {
    "capabilities": [
      "CAP_SYS_ADMIN"
    ],
    "env_exact": {
      "LANG": "C.UTF-8",
      "PATH": "/usr/sbin:/usr/bin",
      "SYSTEMD_LOG_LEVEL": "info"
    },
    "caller_env_allowlist": [],
    "supplementary_gids": [],
    "target_gid": 0,
    "target_uid": 0,
    "umask": 63
  },
  "grant_id": "0192d8f4-7c1b-7000-8a01-9f8b3c4d5e6f",
  "host_id": "sigrun-host:sha256:9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
  "policy": {
    "mode": "one_time",
    "not_after": 1793374800,
    "not_before": 1793371200
  },
  "requester_gid": 1001,
  "requester_uid": 1001,
  "version": "1.0"
}

```

### 3.3 Strict JCS Round-Trip & String Sanitization Rules

1. `sigrund` Base64-decodes `dsse_envelope.payload` (strict RFC 4648 standard alphabet, no whitespace) and rejects payloads over `65536` bytes.
2. `sigrund` parses the JSON into `Warrant`, rejecting duplicate keys at any depth, unknown fields, non-integer numbers, strings exceeding `4096` UTF-8 bytes, and any string containing C0 controls (`U+0000`..`U+001F`), DEL/C1 controls (`U+007F`..`U+009F`), or Unicode BiDi control characters (`U+061C`, `U+200E`, `U+200F`, `U+202A`..`U+202E`, `U+2066`..`U+2069`).
3. `sigrund` re-serializes `Warrant` using RFC 8785 (JCS) and asserts **byte-for-byte equality** with the raw decoded `payload` bytes. Exact-name `caller_env_allowlist` is the only v1.0 caller-environment forwarding field; obsolete `env_wildcard_allowlist` is rejected, never interpreted as a regex policy.
4. Canonical wire/status/CSR document outputs retain their specified JSON bytes; for `TIMEOUT_CSR`, the client prints the canonical CSR document followed by one newline, without PEM armor or escaping its structural JSON syntax. Whenever `sigrun`, `sigrund`, `sigrund-approve`, or a hook interpolates an individual warrant/CSR field into other display text, logs, or chat webhooks, all bytes outside printable ASCII (`0x20..0x7E`) as well as `\` and `"` are escaped as `\xXX` or `\u{XXXX}`.

### 3.4 Signature Verification Adapters & Single-Signer Rule

1. **`raw-ed25519`:** 64-byte Ed25519 signature ($R \parallel S$) verified directly over `PAE` via strict non-malleable verification (`verify_strict`, rejecting small-order points and non-canonical scalars $S \ge L$).
2. **`ssh-ed25519` and `sk-ssh-ed25519` (`PROTOCOL.sshsig`):**
* Base64-decoded `sig` is the raw binary `SSHSIG` blob: 6-byte magic `"SSHSIG"`, `uint32(1)` version, `string(publickey)` matching `signers.toml`, `string(namespace)` equal to `"sigrun.warrant.v1"` (17 bytes), empty `string(reserved)`, and `string(hash_algorithm)` equal to `"sha512"`.
* Recomputes `signed_data`:
```text
signed_data =
    "SSHSIG"                          // 6 raw bytes: 0x535348534947
    || uint32_be(17) || "sigrun.warrant.v1"
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

All numeric JSON values are decimal integers, never floating-point or exponent forms. `grant_id` and `exec_id` are canonical lowercase UUIDv7 strings: exactly 36 ASCII characters in `8-4-4-4-12` form, hexadecimal digits lowercase, version nibble `7`, and RFC 4122 variant nibble `8`, `9`, `a`, or `b`; no braces or URN prefix is accepted. The daemon-generated `grant_id` and `exec_id` use a CSPRNG-backed UUIDv7 generator and reject a collision in the active registry or SQLite state.

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

### 4.2 Unified 8-Part Pre-Consumption Authorization Gate (Resolving Finding 1)

Before opening the SQLite transaction or spawning a child, `sigrund` verifies that all 8 predicates below hold for the validated `Warrant` $W$, the kernel socket credentials `ucred` (`SO_PEERCRED`), the local `host_id`, the sealed `exec_memfd`, the optional sealed `stdin_memfd`, and the selected `signer`:

1. **Version & Host Audience:** $W\text{.version} == \text{"1.0"}$ and $W\text{.host\_id} == \text{local\_host\_id}$.
2. **Kernel Peer Credentials:** $W\text{.requester\_uid} == \text{ucred.uid}$, $W\text{.requester\_gid} == \text{ucred.gid}$, and $W\text{.requester\_uid} \in \text{signer.allowed\_requester\_uids}$.
3. **Target Credentials, Supplementary GID Ceiling, & Same-UID Injection Guard:**
* $W\text{.execution\_context.target\_uid} \in \text{signer.allowed\_target\_uids}$.
* $W\text{.execution\_context.target\_gid} \in \text{signer.allowed\_target\_gids}$.
* $W\text{.execution\_context.supplementary\_gids}$ is sorted in strictly ascending order (no duplicates, max `64` entries), and every GID $g \in W\text{.execution\_context.supplementary\_gids}$ satisfies $g \in \text{signer.allowed\_supplementary\_gids}$.
* **Same-UID Injection Guard:** If $W\text{.execution\_context.target\_uid} == W\text{.requester\_uid}$, the warrant is **rejected with `POLICY_VIOLATION`** unless **all** of the following hold:
1. Both `/etc/sigrund/config.toml` and the signer's entry in `signers.toml` explicitly set `allow_same_uid_elevation = true`.
2. $W\text{.execution\_context.target\_uid} \ne 0$, $W\text{.command.allow\_interpreted\_script} == \text{false}$, and neither `CAP_DAC_READ_SEARCH` nor `CAP_DAC_OVERRIDE` is in $W\text{.execution\_context.capabilities}$.
3. `exec_memfd` (owned by `root:root`) has mode `0111` (`--x--x--x`, no read bits) applied via `fchmod(exec_memfd, 0111)` prior to sealing, and `/proc/sys/fs/suid_dumpable` is read and verified to equal `"0\n"`. Because `target_uid` lacks `MAY_READ` permission on the root-owned mode-`0111` `exec_memfd`, the Linux kernel's `would_dump()` sets `BINPRM_FLAGS_ENFORCE_NONDUMP` during `execveat()`, keeping `mm->dumpable = 0` (`SUID_DUMP_DISABLE`) *after* `execveat()`.
4. `/proc/sys/kernel/yama/ptrace_scope` is read and verified to be `'1'`, `'2'`, or `'3'` (ensuring the Yama LSM blocks same-UID tracing from non-ancestor processes).


* $W\text{.execution\_context.umask} \le 511$ (`0777`).


4. **Capability Ceiling:** Every capability in $W\text{.execution\_context.capabilities}$ is a valid Linux capability ($\le \text{CAP\_LAST\_CAP}$), sorted canonically without duplicates, and present in `signer.allowed_capabilities`.
5. **TTY & Standard Input Binding:**
* $W\text{.command.tty\_mode} == \text{CLIENT\_HELLO.tty\_mode}$ and $(W\text{.command.tty\_mode}, W\text{.command.stdin\_policy})$ satisfies the Section 2.3 matrix.
* If `tty_mode == "pty"`, `signer.allow_pty == true`.
* If `stdin_policy == "unrestricted_interactive"`, `signer.allow_unrestricted_stdin == true`.
* If `stdin_policy == "sha256"`, `stdin_memfd` is sealed with `F_SEAL_SEAL | F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_WRITE | F_SEAL_FUTURE_WRITE` and `hex(SHA256(stdin_memfd))` equals $W\text{.command.stdin\_sha256}$ in constant time; otherwise `stdin_sha256` is `null`.


6. **Anchored Executable Path, Snapshot Verification, & Digest Match:**
* The absolute `command.executable_path` must start with `/` and contain no trailing slash, empty component, `.` or `..` component. Configured allowed directories obey the same syntax, cannot be `/`, and have no duplicates. At startup, open `/` once and pre-open each configured root with `openat2(root_fd, root_path_without_leading_slash, ...)`, `O_PATH | O_DIRECTORY | O_CLOEXEC`, and `RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS`; retain its FD and `(st_dev, st_ino)`, and fail startup if a configured root cannot be pinned. Root objects are fixed for that policy generation.
* **Select and strip:** Among the candidate roots for the phase (Section 2.2.1), choose the longest complete-component prefix `D` such that the path starts with `D + "/"` and has a nonempty suffix. No match is `POLICY_VIOLATION`. Strip exactly `D + "/"`; the resulting `relative_path` must be nonempty, not start with `/`, and contain no empty/`.`/`..` components. For example `/usr/bin/systemctl` under `/usr/bin` becomes `systemctl`; `/usr/bin-evil/x` does not match `/usr/bin`. Resolve only `openat2(selected_dir_fd, relative_path, &how, sizeof(how))`:
```c
struct open_how how = {
    .flags = O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK,
    .resolve = RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS | RESOLVE_NO_MAGICLINKS | RESOLVE_NO_XDEV
};

```
* No absolute pathname is passed to this `RESOLVE_BENEATH` call, and no fallback to a broader root is permitted after failure. Reject symlinks/magic links, cross-mount traversal, non-regular sources, and snapshot errors under Section 2.2.1. An executable that equals a root directory is not eligible.
* At the final authorization gate, reapply selection under the winning signer's roots and require the selected root pathname and pinned `(st_dev, st_ino)` to equal the retained snapshot metadata; otherwise reject rather than resnapshot. Configure CSR roots to match signer roots for unsigned workflows. Check that the common-phase snapshot is sealed, root-owned, has mode `0111` with ELF magic when scripts are disabled, or mode `0555` with `signer.allow_interpreted_scripts == true` when enabled. `hex(SHA256(exec_memfd))` must equal `command.executable_sha256` in constant time; `argv` length is `1..=256`. These are checks of the common-phase result, not another copy operation.

7. **Deterministic `envp` Construction from Empty Environment:**
* `caller_env_allowlist` is an array of exact variable names, sorted lexicographically with no duplicates (maximum `128` entries); it replaces `env_wildcard_allowlist`, which is rejected as an unknown field. No regex or glob syntax is supported. Every `env_exact` key, allowlisted name, and `caller_env` key matches `^[A-Z_][A-Z0-9_]{0,127}$`; `env_exact` and the allowlist have zero overlap.
* **Normative Caller-Environment Denylist:** Reject an allowlisted literal name if it starts with any listed prefix or equals any listed exact name:
* **Prefixes:** `LD_`, `DYLD_`, `GIT_`, `BASH_FUNC_`, `GLIBC_`
* **Exact Names:** `PATH`, `IFS`, `CDPATH`, `ENV`, `BASH_ENV`, `PROMPT_COMMAND`, `SHELLOPTS`, `BASHOPTS`, `PS4`, `GLOBIGNORE`, `EXECIGNORE`, `TMPDIR`, `TMP`, `TEMP`, `TZ`, `LOCPATH`, `GCONV_PATH`, `GETCONF_DIR`, `HOSTALIASES`, `LOCALDOMAIN`, `NLSPATH`, `RES_OPTIONS`, `PYTHONPATH`, `PYTHONHOME`, `PYTHONSTARTUP`, `PYTHONINSPECT`, `PYTHONUSERBASE`, `PERLLIB`, `PERL5LIB`, `PERL5OPT`, `PERL5DB`, `RUBYLIB`, `RUBYOPT`, `DLN_LIBRARY_PATH`, `NODE_OPTIONS`, `NODE_PATH`, `JAVA_TOOL_OPTIONS`, `_JAVA_OPTIONS`, `CLASSPATH`, `GOFLAGS`, `CGO_CFLAGS`, `CGO_LDFLAGS`, `RUSTFLAGS`, `CARGO_BUILD_RUSTC_WRAPPER`, `OPENSSL_CONF`, `OPENSSL_ENGINES`, `OPENSSL_MODULES`, `NSS_DEFAULT_DB_TYPE`, `KRB5_CONFIG`, `KRB5CCNAME`, `DBUS_SESSION_BUS_ADDRESS`, `XDG_CONFIG_DIRS`, `XDG_DATA_DIRS`, `XAUTHORITY`


* Every `CLIENT_HELLO.caller_env` key must equal an entry in `caller_env_allowlist` byte-for-byte. Each value in `caller_env` and `env_exact` is a UTF-8 string of at most `4096` bytes and contains no control/BiDi characters under Section 3.3. Empty values are permitted; absent allowlisted names are omitted. No value pattern is evaluated.
* `sigrund` constructs `envp` starting from an **empty array `[]`**, inserts `"K=V"` from `env_exact` and validated `caller_env`, and sorts lexicographically by key. Host daemon environment variables are never inherited.


8. **Grant Mode & Validity Bounds:**
* $W\text{.policy.mode} \in \text{signer.allowed\_modes}$.
* `"one_time"`: `not_before` and `not_after` are integers with $0 \le (\text{not\_after} - \text{not\_before}) \le \min(\text{signer.max\_ttl\_secs}, \text{daemon.max\_onetime\_window\_secs})$.
* `"time_range"`: `not_before` and `not_after` are integers with $0 \le (\text{not\_after} - \text{not\_before}) \le \text{signer.max\_ttl\_secs}$.
* `"permanent"`: `not_before` is an integer and `not_after` is `null`.



### 4.3 SQLite State Transaction (`/var/lib/sigrund/state.sqlite`)

Initialized with `PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA busy_timeout = 5000;`:

```sql
CREATE TABLE consumed_grants (
    grant_id TEXT PRIMARY KEY,
    payload_sha256 BLOB NOT NULL UNIQUE,
    signer_id TEXT NOT NULL,
    requester_uid INTEGER NOT NULL,
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

Define `payload_sha256_bytes` as the raw 32-byte digest of the canonical DSSE warrant payload, and `payload_sha256_hex` as its 64-character lowercase hexadecimal representation. Store the raw bytes in `consumed_grants.payload_sha256`; store digest revocations as lowercase hex text in `revocations.target_value`. All JSON/audit/collector hashes use lowercase hex. Administrative revocation input accepts valid hex in either case but normalizes it to lowercase before insertion/comparison; reject non-64-digit digest input. If SQL performs conversion, use `lower(hex(?))` with the raw digest BLOB bound to `?`; SQLite `hex()` alone is uppercase and must not be compared to lowercase text. Other revocation types keep their exact string semantics.

For **every** grant mode (`"one_time"`, `"time_range"`, `"permanent"`):

1. Execute `BEGIN IMMEDIATE TRANSACTION;`.
2. Query `clock_gettime(CLOCK_REALTIME, &now)`: assert $\text{now.tv\_sec} \ge W\text{.policy.not\_before}$ and (for `"one_time"` and `"time_range"`) $\text{now.tv\_sec} \le W\text{.policy.not\_after}$; otherwise `ROLLBACK;` and return `EXPIRED_OR_NOT_YET_VALID`.
3. Query `revocations` for matches on `grant_id`, canonical lowercase `payload_sha256_hex`, or `signer_id`. If found, `ROLLBACK;` and return `REVOKED`.
4. If $W\text{.policy.mode} == \text{"one\_time"}$, execute `INSERT INTO consumed_grants ...`. On `SQLITE_CONSTRAINT_PRIMARYKEY` or `SQLITE_CONSTRAINT_UNIQUE`, `ROLLBACK;` and return `REPLAY_DETECTED`.
5. Immediately before `COMMIT;`, apply Section 1.3.1's cancellation/deadline checks and `AUTHORIZING -> COMMITTING` reservation; cancel/rollback if it cannot be acquired. Execute `COMMIT;` off the control loop and reconcile cancellation before advancing to `COMMITTED`.

### 4.4 Contiguous Audit Batch Replication, Collector Deduplication, & Final Expiry Gate (Resolving Finding 2)

Because local audit events (`EXEC_READY_TO_EXEC`, `EXEC_SPAWN_FAILED`, `EXEC_EXIT`, `AUTH_ABORTED_POST_COMMIT`, `ORPHAN_CLEANUP`, `RATCHET_*_RECOVERY`) are appended between successive `AUTH_COMMIT` events, sending only `AUTH_COMMIT` records to the remote collector would create sequence gaps in `prev_record_sha256` and prevent the collector from verifying chain continuity.

Therefore, `sigrund` implements a **Contiguous Ordered Batch Replication and Authorization Protocol**:

1. **Serialized Local Audit Sequencer & Persistent Acknowledged Cursor (`remote_acked_seq`):**
* All local audit log writes and remote collector RPCs are serialized through a single internal **Audit & Replication Sequencer** in `sigrund`.
* `/var/lib/sigrund/audit_ratchet.state` persists `"remote_acked_seq": <int>` (the highest `seq` acknowledged by a valid signed collector receipt; initialized to `0` when Genesis record `seq = 0` is registered).


2. **Contiguous Batch Construction (`records[remote_acked_seq + 1 ..= auth_commit_seq]`):**
* Immediately after `COMMIT;` succeeds in Section 4.3, the Audit & Replication Sequencer appends and ratchets the local `AUTH_COMMIT` event at `seq = N`. Its authenticated event body contains `event_type: "AUTH_COMMIT"`, `seq`, `host_id`, `exec_id`, `grant_id`, `payload_sha256`, `signer_id`, `policy_mode`, `not_before`, and `not_after`, populated from the validated warrant and selected signer (with `exec_id` assigned by the daemon). These fields are covered by `entry_hmac`; `seq` identifies the record and is exposed as `auth_commit_seq` in `target_auth`.
* When `require_remote_audit_ack = true` is configured, the sequencer streams canonical JCS audit records from `/var/log/sigrund/audit.jsonl` with sequence numbers from `remote_acked_seq + 1` through `N` (inclusive, in strict ascending `seq` order, including all intervening readiness, exit, abort, and recovery records) in bounded `RemoteAuditBatchRequest` chunks over mTLS, with the exact HTTP and signature encoding in Section 4.4.1. The entire authorization replication operation shares the captured policy-generation `collector_rpc_timeout_ms` deadline (default `3000 ms`, immutable ceiling `3000 ms`) (`CLOCK_MONOTONIC`), including all chunks and retries; chunking does not reset it.
* **RPC Bounds:** Each request contains `1..=256` `records_jcs` entries, whose decoded UTF-8 byte lengths sum to at most `1048576` bytes (1 MiB). The complete serialized UTF-8 JSON RPC body, including JSON escaping and metadata, is also at most `1048576` bytes; no compression is used. Each canonical audit record is at most `65536` UTF-8 bytes. Both peers enforce the body limit before allocation and the count/decoded limits while parsing. All audit appends enforce the per-record limit before writing; oversized records fail closed without spawn rather than being truncated or skipped.
* **Exact `RemoteAuditBatchRequest` schema:** The request is one canonical JCS object with exactly these top-level keys and no others: `first_seq` (nonnegative integer), `last_seq` (nonnegative integer), `host_id` (nonempty canonical host ID string), `records_jcs` (array of canonical JCS record strings), and `target_auth` (either `null` or the exact object below). Require `first_seq <= last_seq`, `last_seq - first_seq + 1` computed with checked arithmetic, `records_jcs.length == last_seq - first_seq + 1`, and strict ascending record sequence numbers with no gaps. Each record string is a complete canonical audit record without its on-disk newline delimiter, at most `65536` UTF-8 bytes; the array count and aggregate/body limits are in the RPC bounds above. `target_auth: null` is required for ingestion-only/startup chunks and means no authorization or grant write. A non-null `target_auth` is allowed only when the chunk ends at its `auth_commit_seq` and has exactly these keys: `auth_commit_seq`, `exec_id`, `grant_id`, `host_id`, `not_after`, `not_before`, `payload_sha256`, `policy_mode`, and `signer_id`; `not_after` is an integer for `one_time`/`time_range` and `null` for `permanent`, while all other fields have the Section 3.5 bounds. The final chunk for a pending execution has `auth_commit_seq == last_seq`; an intermediate chunk must have `target_auth == null`. Unknown fields, missing fields, duplicate keys, a non-null target on an intermediate chunk, or a null target on a final authorization chunk are rejected before ingestion/authorization.
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
* Otherwise, require `target_auth.auth_commit_seq == last_seq`, load the parsed authenticated record at that sequence (including on retransmission), and require `event_type == "AUTH_COMMIT"`. Compare **every** target field by strict typed equality to that record: `exec_id`, `grant_id`, `payload_sha256`, `signer_id`, `policy_mode`, `not_before`, `not_after`, and `host_id`; also require `target_auth.host_id == request.host_id == authenticated_host_id`. Missing, extra, ill-typed, or unequal target fields fail with `AUTH_RECORD_MISMATCH` without any authorization or grant-consumption write. Matching the sequence alone is insufficient. Validity values must be integer timestamps, with a non-null `not_after >= not_before` for `one_time`/`time_range`, and `not_after: null` for `permanent`; unknown policy modes are rejected.
* After these comparisons, derive all authorization inputs, deduplication keys, and authorization receipt fields **from the authenticated record**, not from the supplied `target_auth` object:
1. Verify `not_before <= collector_now` and (if `policy_mode != "permanent"`) `collector_now <= not_after`; on failure return a signed `DENY_EXPIRED` receipt without grant consumption.
2. Verify `(host_id, grant_id)`, `(host_id, payload_sha256)`, and `signer_id` are not revoked on the collector; on failure return a signed `DENY_REVOKED` receipt without grant consumption.
3. Branch by the authenticated `policy_mode`:
* **`"one_time"`:** Attempts `INSERT INTO remote_consumed_grants (host_id, grant_id, payload_sha256, first_exec_id, first_seq, consumed_at) VALUES (...)`.
* If the insert succeeds: sets `decision = "ALLOW"`.
* If a uniqueness conflict occurs on `(host_id, grant_id)` or `(host_id, payload_sha256)`: if the existing row exactly matches the authenticated record's `grant_id`, `payload_sha256`, `exec_id` (`first_exec_id`), and `seq` (`first_seq`) (indicating an in-window retry of the same authorization), sets `decision = "ALLOW"`; otherwise (e.g., a second redemption attempt after a local SQLite database rollback) sets `decision = "DENY_REPLAY"`.


* **`"time_range"` or `"permanent"`:** Permits repeated `(host_id, grant_id)` and `(host_id, payload_sha256)` across distinct `exec_id` values and sets `decision = "ALLOW"`.




* **Step C3 (Signed Collector Receipt):**
After durably committing the ingested chain checkpoint and any grant-consumption decision, the collector returns a DSSE/JCS receipt (`payloadType: "application/vnd.sigrun.collector-receipt.v1+json"`) signed with the collector private key corresponding to the configured `collector_public_key`:
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
* Only a verified final `ALLOW` receipt authorizes proceeding to the final expiry gate. A verified `DENY_REPLAY` maps to local `REPLAY_DETECTED`; `DENY_EXPIRED` maps to `EXPIRED_OR_NOT_YET_VALID`; and `DENY_REVOKED` maps to `REVOKED`. Each verified denial appends `AUTH_ABORTED_POST_COMMIT` and never calls `clone3()`; the denial receipt may advance the acknowledged cursor. `AUTH_RECORD_MISMATCH`, malformed/mismatched receipts, other collector errors, and cumulative RPC timeout append `AUTH_ABORTED_POST_COMMIT` when applicable and return `REMOTE_AUDIT_FAILED`; invalid receipts never advance the cursor. The daemon accepts only the exact decision/field combinations of Section 4.4.1.




4. **Final Cancellation and Pre-Spawn Expiry Revalidation:** After the required receipt (or durable local audit authorization when remote ACK is disabled), apply Section 1.3.1's cancellation/deadline checks and `COMMITTED -> SPAWNING` reservation. Immediately prior to `clone3()`, `sigrund` checks `clock_gettime(CLOCK_REALTIME, &now_final)` and asserts $\text{now\_final.tv\_sec} \ge W\text{.policy.not\_before}$ and (for `"one_time"` and `"time_range"`) $\text{now\_final.tv\_sec} \le W\text{.policy.not\_after}$. If expired, release the reservation without calling `clone3()`, log `AUTH_ABORTED_POST_COMMIT`, and return `EXPIRED_OR_NOT_YET_VALID`. Cancellation is reconciled under Section 1.3.1; a cancelled post-commit grant remains consumed and logs `AUTH_ABORTED_POST_COMMIT` (appending the required `AUTH_COMMIT` first if the cancellation arrived immediately after database commit).

### 4.4.1 Exact Remote RPC Framing and Collector Signature Encoding

* **Transport and Message Boundaries:** Use HTTPS with TLS 1.3 and the Section 4.4 mTLS/hostname checks, HTTP/1.1 (ALPN `http/1.1`), and no upgrade, HTTP/2, pipelining, or concurrent requests on one connection. `POST /v1/audit/batch` carries the `RemoteAuditBatchRequest`. `POST /v1/audit/checkpoint` carries exactly `{ "host_id": "<local_host_id>" }`. Each request and response has exactly one `Content-Type: application/json` and one `Content-Length` (unsigned decimal body byte count, no sign or leading zero except `0`). Headers are case-insensitive, at most `8192` bytes total including the terminating CRLFCRLF. Reject duplicate length/type headers, `Transfer-Encoding`, non-identity `Content-Encoding`, interim responses, trailers, and body bytes beyond the declared length. Each body consists of exactly that many UTF-8 bytes; read no unbounded EOF-delimited body. Reused connections send the next request only after consuming the complete prior response. The batch request bound is `1048576` body bytes; checkpoint requests and error responses are at most `4096`; signed responses are at most `16384`. Check lengths before body allocation. Header parsing, TLS handshakes, sends, reads, and retries all share the operation's captured policy-generation cumulative `collector_rpc_timeout_ms` deadline; use nonblocking network I/O off or integrated with the control loop, never a blocking RPC on it.
* **JSON and HTTP Results:** Successful RPCs, including authorization denials and `ACK_ONLY`, return HTTP `200` with the DSSE envelope below. Batch/checkpoint request bodies and DSSE envelope/payload JSON are canonical JCS with no BOM, whitespace suffix, or newline; reject duplicate/unknown fields, wrong types, invalid UTF-8, or nesting beyond `8`. Checkpoint requests use the same authenticated host mapping as batches. A rejected RPC returns a final non-200 HTTP status (400 for bad input/chain mismatch, 403 for host authorization failure) and exactly `{ "error": "<code>" }` with an ASCII code of `1..=128` bytes; it never authorizes execution or advances the daemon cursor. Unrecognized status/code, malformed framing, TLS failure, and timeout fail closed. Error bodies are diagnostic, not signed receipts. If any record ingestion committed before an error, retry/checkpoint reconciliation still uses the authenticated durable chain state.
* **Pinned Receipt Key and DSSE Envelope:** Configure `collector_key_id` (nonempty ASCII, maximum `128` bytes) and `collector_public_key` as strict padded RFC 4648 standard Base64 encoding of one raw **32-byte Ed25519 public key**. For both signed response kinds, the outer object has exactly `payload`, `payloadType`, and `signatures`, with exactly one signature object containing exactly `keyid` and `sig`. `keyid` must equal the configured ID. `payload` is strict padded RFC 4648 standard Base64 of the canonical JCS payload bytes (maximum `4096` decoded bytes), with no whitespace or alternate alphabet. `sig` is the same Base64 encoding of the raw **64-byte Ed25519 signature `R || S`**, exactly `88` ASCII characters; it is not an SSH/OpenPGP packet or a signature over the outer JSON. Sign DSSE v1 PAE over the actual UTF-8 `payloadType` and decoded payload bytes, using the decimal byte lengths for that type and payload as in Section 3.1 (not the warrant's fixed type length). Verify via strict Ed25519 verification, rejecting non-canonical scalars and small-order points. For every Base64 string require `encode(decode(value)) == value` to reject non-canonical padding bits. No adapter negotiation or key selection from untrusted `keyid` is allowed.
* **Receipt Payloads:** Batch response `payloadType` is exactly `application/vnd.sigrun.collector-receipt.v1+json`; its payload has exactly the fields shown in C3. Allowed `decision` values are `ALLOW`, `DENY_REPLAY`, `DENY_EXPIRED`, `DENY_REVOKED`, and `ACK_ONLY`, with C2's mode/nullability rules. `acked_through_seq` and `receipt_timestamp` are nonnegative integers; record/payload digests are exactly 64 lowercase hex digits, and identifiers are the authenticated record values. A checkpoint uses type `application/vnd.sigrun.collector-checkpoint.v1+json` and exactly `host_id`, `collector_last_seq`, `collector_last_record_sha256`, and `receipt_timestamp`; the sequence is a nonnegative integer and digest is 64 lowercase hex digits for its durable last record. Genesis must already be registered; an unknown host has no implicit zero checkpoint. Verify the signature/type, exact local host binding, and field shapes before Section 7.3 reconciliation. Receipt timestamps are collector UTC Unix seconds; they do not replace the daemon's monotonic operation deadline or final warrant-expiry check.

---

## 5. Child Cgroup Setup, Mount Flags, Descriptor Table, and Credential Transition

### 5.1 Per-Invocation Job Cgroup & `clone3()` Flags

For each authorized execution `exec_id`, `sigrund` creates `G/jobs/job-<exec_id>` beneath the pinned delegated root from Section 1.2 and opens `cgroup_fd`. **Before `clone3()`**, write and read back all of these root-controlled limits:

| Job Cgroup File | Default Value | Daemon Configuration |
| --- | --- | --- |
| `memory.max` | `268435456` (256 MiB) | `job_memory_max_bytes`, positive finite integer |
| `memory.swap.max` | `0` | `job_memory_swap_max_bytes`, finite nonnegative integer |
| `memory.oom.group` | `1` | Required, not warrant-overridable |
| `pids.max` | `128` | `job_pids_max`, positive finite integer |

The daemon config may set other finite values; `max`/unlimited values are rejected and warrants cannot raise these limits. Missing files, failed writes, or unequal read-back fail closed as `SPAWN_FAILED` before any job child exists. The startup probe verifies these interfaces, including swap and group-OOM control, before accepting requests. `memory.max`/`pids.max` cover descendants remaining in the job cgroup; the process count includes threads. Allocation/fork failures and OOM termination are normal workload outcomes, with the primary child's actual wait status reported. These per-job limits supplement, rather than replace, snapshot RAM and active-socket quotas; they do not bound aggregate host usage below the sum of admitted jobs or resources charged elsewhere. Host-root/out-of-profile jobs may evade containment as described in Section 1.1; finite initial cgroup limits do not strengthen that guarantee.


* If `CAP_SYS_ADMIN` is **not** in $W\text{.execution\_context.capabilities}$, `sigrund` calls `clone3()` with `CLONE_INTO_CGROUP | CLONE_PIDFD | CLONE_NEWNS | CLONE_NEWCGROUP`.
* If `CAP_SYS_ADMIN` **is** in $W\text{.execution\_context.capabilities}$, `sigrund` calls `clone3()` with `CLONE_INTO_CGROUP | CLONE_PIDFD`.
* In both cases, initialize `struct clone_args` with `args.flags` as above, `args.exit_signal = SIGCHLD`, `args.cgroup = cgroup_fd`, and `args.pidfd` pointing to writable parent storage for the returned pidfd; all unused fields are zero. `SIGCHLD` must not be ORed into `args.flags`. This makes every primary job an ordinary waitable `SIGCHLD` child for the Central Reaper.

### 5.2 Deterministic Child Descriptor Table (`FDs 0..=4`)

| Child FD | Role | `FD_CLOEXEC` State | Behavior Across `execveat(3, "", argv, envp, AT_EMPTY_PATH)` |
| --- | --- | --- | --- |
| **`0`** | `stdin` | Cleared (`0`) | Inherited (`/dev/null`, sealed `stdin_memfd` rewound to offset `0`, client FD, or PTY slave). |
| **`1`** | `stdout` | Cleared (`0`) | Inherited by executed program. |
| **`2`** | `stderr` | Cleared (`0`) | Inherited by executed program. |
| **`3`** | `exec_memfd` | **Set (`FD_CLOEXEC`)** when `allow_interpreted_script == false`; **Cleared (`0`)** when `true`. | Closed by kernel before ELF entry point; kept open only if `binfmt_script` rewrites `argv` to `/dev/fd/3`. |
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

The setup sequence is:

1. **Descriptors, Recursive Read-Only Cgroup Mount, & Session:**
* Call `unshare(CLONE_FILES)`.
* Duplicate `sync_pipe_w` first, then `child_stdin`, `child_stdout`, `child_stderr`, and `exec_memfd` to temporary descriptors `>= 5` via `fcntl(fd, F_DUPFD_CLOEXEC, 5)`, tracking the error writer as specified above.
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
* Read `/proc/self/mountinfo` to confirm the mount at `/sys/fs/cgroup` is `cgroup2` and it and every descendant mount have `ro,nosuid,nodev,noexec` and no shared/slave propagation tags. A missing cgroup v2 mount, parse failure, or flag mismatch is a Step 1 failure. The daemon's mount namespace must remain unchanged. V-11 tests this exact syscall sequence before credential drop.


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

## 6. Hook Sandbox, `pivot_root` Sequence, and Evaluation Contract (Resolving Finding 5)

### 6.1 Hook Quotas & Complete `pivot_root` Sandbox Sequence

* **Admission Quotas:** Each request captures `max_active_hooks_per_uid`, `max_active_hooks_global`, `hook_invocations_per_uid`, and `hook_window_secs` from its policy generation (defaults `1`, `8`, `5`, and `60`). `sigrund` permits at most the captured active pipelines per UID/global and enforces the captured token bucket for unsigned invocations; excess requests return `RESOURCE_EXHAUSTED`. Reloads affect only requests admitted under the new generation; active hook pipelines retain their captured quotas and window.
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





### 6.2 Hook Input, Output Schema, Timeouts, and Evaluation Order

1. **Nonblocking Input Delivery:** Create `hook_stdin` with `pipe2(O_CLOEXEC)` and set `O_NONBLOCK` on the parent write end before registering it with `epoll` for `EPOLLOUT` (the child read end may remain blocking). Retain one immutable canonical JCS CSR buffer of at most `65536` bytes and a byte offset. On writable events, write at most `16384` bytes per dispatch, advance by the actual short-write count, retry `EINTR` within that dispatch budget, and return to the event loop on `EAGAIN`. Concurrently drain stdout/stderr/sync pipes; never wait for input completion before servicing output. On full delivery, unregister/close the parent input FD to signal EOF. Ignore `SIGPIPE` in the daemon and treat `EPIPE`, other write errors, early hook exit before complete delivery, or deadline expiry as a hook fault; close input and tear down the hook cgroup before any next hook. Never duplicate/deliver the remaining input after cancellation.
2. **Timeouts & Output Bounds:** All hooks in `/etc/sigrund/hooks.d/` share the captured policy-generation `hook_timeout_ms` budget (default `25000 ms`, immutable ceiling `25000 ms`) (`CLOCK_MONOTONIC`) per request, starting before the first hook is spawned and covering setup, **all stdin delivery**, output, sync EOF, and hook exit. Hook-to-hook transitions and partial writes do not reset it. At expiry, stop all I/O, close the parent pipes, kill the active hook cgroup, and use the fallback outcome after arranging cleanup. For each hook, `sigrund` reads at most `32768` bytes from `hook_stdout` and `4096` bytes from `hook_stderr` via `epoll`.
3. **Hook Sync Validation:** The parent drains `hook_sync_pipe_r` via `epoll` alongside stdout/stderr, accumulating at most 16 bytes until `EOF` within the cumulative hook deadline. A valid readiness result is exactly one `{ step: 0, errno: 0 }` frame followed by `EOF`. A setup error frame, readiness plus exec-error frame (`step: 5, errno > 0`), missing/partial/malformed/excess data, or missing `EOF` at the deadline makes the hook a fault. Readiness is necessary for considering hook JSON but is not an exec-success acknowledgement.
4. **Hook Result Evaluation:** When a hook exits, `sigrund` kills any remaining processes in `hook-<hook_exec_id>` via `cgroup.kill`, reaps them via the Central Reaper, removes the cgroup directory, and inspects the validated sync result, `exit_code`, and bounded `hook_stdout`. Only complete stdin delivery, a valid readiness result, normal `exit_code == 0`, and valid output JSON can produce explicit approval or rejection:
* **Strict Output Schema:** After bounded collection through EOF, parse exactly one UTF-8 JSON object (optional surrounding JSON whitespace only), maximum nesting depth `8`; reject duplicate keys at every depth, unknown fields, non-integer numbers, invalid UTF-8, trailing JSON/garbage, and schema/type errors. Required/exact top-level key sets are `{"status", "dsse_envelope"}` for `approved`, `{"status", "reason"}` for `rejected`, and `{"status"}` for `abstain`; all other status values fault. `reason` is a string of `1..=1024` UTF-8 bytes with no Section 3.3 control/BiDi characters. Its sanitized decision-message representation must also fit `4096` bytes; otherwise fault. The approved envelope has exactly `payload`, `payloadType`, and `signatures`; signature objects have exactly `keyid` and `sig`, with the Section 2/3 Base64/string bounds. The total hook stdout bound `32768` still applies, so a larger otherwise-valid warrant cannot travel through a hook and falls back to CSR. Unknown/duplicate keys in decoded warrant payloads are rejected by the normal authorization parser.
* **Explicit Approval (`exit_code == 0`):** Hook outputs `{ "status": "approved", "dsse_envelope": { ... } }`. Evaluation stops immediately; `sigrund` verifies `dsse_envelope` through Sections 3 and 4 against the already-sealed `exec_memfd` and `stdin_memfd`.
* **Explicit Rejection (`exit_code == 0`):** Hook outputs `{ "status": "rejected", "reason": "..." }`. Evaluation stops immediately; `sigrund` returns `0x02 SERVER_AUTH_DECISION` (`status: "REJECTED"`, `message: <sanitized-reason>`).
* **Abstention or Fault:** If the hook outputs `{ "status": "abstain" }`, fails sync validation, terminates by signal, exits non-zero, exceeds output limits, outputs invalid JSON, or times out, `sigrund` advances to the next hook if time remains in the captured `hook_timeout_ms` budget.
* **Fallback CSR Emission:** If all hooks abstain or the captured `hook_timeout_ms` cumulative budget expires without `"approved"` or `"rejected"`, `sigrund` returns `0x02 SERVER_AUTH_DECISION` (`status: "TIMEOUT_CSR"`, `csr_payload: <canonical-jcs-csr-string>`).



---

### 6.3 Optional Local Root-TTY Approval Profile

This optional profile implements the first local human-approval workflow.
It replaces Section 6.2 hook dispatch for unsigned requests with a separate
root foreground approver. It never bypasses the common snapshot phase,
Sections 3–4 authorization, audit durability, or Section 5 child setup.
Signed requests use the same gates without consulting the broker.

**Profile configuration and scope:** A `[mvp]` table selects this profile.
Its exact fields are `tty_mode = "stdio"`, `hooks_enabled = false`,
`pty_enabled = false`, `max_active_approval_requests = 1`, and
`approval_signer_id = "<configured SSH signer ID>"`. The first four fields
default to the shown values and reject alternatives; the signer ID is required
before enabling execution, references exactly one signer and uses Section 3.5
bounds. Only `ssh-ed25519` and `sk-ssh-ed25519` policy entries are supported.
Require `require_remote_audit_ack = false` and retain mandatory collector
configuration validation. SIGHUP does not reload this profile.

Both signed and unsigned requests must use `one_time`, `stdio`, `null` or
`sha256` stdin, `allow_interpreted_script = false`, an empty
`caller_env_allowlist` and empty `caller_env`. Same-UID execution is rejected
even if the general configuration opts into it. Other unsupported profile
values fail with `POLICY_VIOLATION`; malformed shapes retain their existing
protocol errors. No setting or signed warrant can enable a deferred feature.
The Phase 0/1 transport-only implementation lacks the new signer setting;
it must continue rejecting execution until these additions are implemented.

**Broker trust and bytes:** Use a distinct root:root `0600` `SOCK_STREAM`
socket in a trusted root-owned directory. Authenticate `SO_PEERCRED.uid == 0`
before parsing either peer's messages; invalid credentials close only that
connection. The approver also verifies the socket and parent ownership/modes.
Only one root approver connection and one outstanding approval are permitted.
Each broker frame is a four-byte big-endian length followed by one exact JCS
document of `1..=524288` bytes, with no ancillary descriptors. Enforce the
five-second cumulative frame/send deadlines independently of human waiting.

An approval request has exactly `exec_id` (UUIDv7), `signer_id` (configured ID),
and `csr_payload` (the complete canonical CSR string, at most 65536 decoded
UTF-8 bytes). A response has exactly either `status: "approved"`, `exec_id`,
`dsse_envelope`, or `status: "rejected"`, `exec_id`, `reason` (1–1024 UTF-8
bytes obeying Section 3.3). Apply strict duplicate/unknown-field, depth, schema
and canonical-encoding checks. An approved response contains exactly one
signature from the selected signer and a payload byte-for-byte equal to the
retained CSR. Derive DSSE PAE from those payload bytes, then sign PAE using
Section 3.4 SSHSIG; neither signing bare JSON nor signing a displayed digest
is equivalent. A root peer's confirmation is not itself authorization.

**Admission and deadlines:** After static profile/policy checks, reserve the
single approval slot before starting unsigned snapshots. Busy requests receive
`RESOURCE_EXHAUSTED`, without an unbounded waiting queue. Snapshot completion
still competes with the accept-based deadline under Section 1.3.1. At successful
handoff to `AUTHORIZING`, start a separate immutable `120000 ms` monotonic
deadline covering broker delivery, human confirmation and signing. This is
not the hook timeout and progress never resets it. Verify that deadline when
accepting the response, even if its timer callback has not run. A verified
response handed to local authorization disarms it; final warrant expiry and
cancellation checks remain mandatory. Approval never refreshes the grant's
signed validity window.

If no authenticated approver is connected at handoff, send `TIMEOUT_CSR`
immediately with the completed canonical CSR. Explicit refusal sends
`REJECTED`; broker disconnect, malformed response or approval timeout sends
`TIMEOUT_CSR`. Signature/policy failures use the normal authorization denial.
These pre-commit outcomes cannot consume a grant or spawn. A requester
disconnect cancels without a wire reply. On cancellation, timeout or broker
protocol fault, close the broker connection to invalidate the outstanding
prompt; do not reuse it for another request. Ignore late completions and bind
all results to execution ID, connection identity and captured policy. Release
the approval slot on resolution/cancellation, but retain worker, FD and RAM
reservations until actual cleanup. An idle approver may reconnect for future
requests; reconnecting never reissues an old prompt automatically.

**Root interaction:** The approver requires effective UID 0 and a verified
controlling TTY, with prompts and key passphrase/FIDO interactions on that
TTY rather than broker stdin. Its root-controlled signer configuration and
explicit key/agent selection must match the requested signer ID, public key,
algorithm, namespace and UP/UV policy. Never choose an arbitrary agent key
or take an identity-file path from the request. Display every CSR field,
execution ID and selected key fingerprint before confirmation; render argv
as indexed escaped strings, environment as individual exact key/value pairs,
and include groups, capabilities, umask, script permission, host/requester/
target identities, input/executable digests, mode, grant and validity. Do not
truncate away fields and then permit approval. Confirm with `[y/N]`: only
explicit `y` or `yes` signs; blank input, EOF or TTY loss denies. No shell
command is assembled from request data. Any signing helper has bounded output
and is terminated/reaped on broker loss, timeout or local cancellation.

Verification must cover real terminal output through the Section 2.3 relay,
OpenSSH signing interoperability, complete sanitized display, no approver,
busy admission, wrong key/PAE/namespace, refusal/EOF, slow signing, expired
warrants, stale/duplicate replies, reconnect and disconnect at every boundary.
M-01–M-15 in the MVP roadmap are the profile's release gates; they supplement
the applicable Section 8 cases and do not establish full v1.0 conformance.

---

## 7. Hash-Chained Ratcheting Audit Log & Crash Recovery

### 7.1 Provisioning (`sigrundctl init-host`)

1. Refuses to run if `/var/lib/sigrund/host_identity.key`, `/var/lib/sigrund/audit_ratchet.state`, or `/var/log/sigrund/audit.jsonl` exists.
2. Generates the Ed25519 host identity keypair in `/var/lib/sigrund/host_identity.key` (`0400 root:root`), `fsync()`s it, and computes `host_id`.
3. Generates a 256-bit initial ratchet key $K_0$ via `getrandom(..., GRND_NONBLOCK)`.
4. Creates `/var/log/sigrund/audit.jsonl` (`0600 root:root`), writes the single-line JCS Genesis Record at `seq = 0` (`event_type: "AUDIT_INIT"`, `host_id: <local_host_id>`, `prev_record_sha256: "0000000000000000000000000000000000000000000000000000000000000000"`, `entry_hmac = HMAC_SHA256(K_0, genesis_body_jcs)`) terminated by `\n`, and calls `fsync(log_fd)`.
5. Computes $K_1 = \text{SHA-256}(K_0 \parallel \text{"sigrun-ratchet-v1"})$, writes:
```json
{
  "key_hex": "<64-char-hex-K_1>",
  "initial_key_hex": "<64-char-hex-K_0>",
  "last_record_sha256": "<64-char-hex-SHA256-of-record-0-jcs-bytes>",
  "remote_acked_seq": 0,
  "seq": 1
}

```


to `/var/lib/sigrund/audit_ratchet.state.tmp` (`0600 root:root`), calls `fsync(tmp_fd)`, closes `tmp_fd`, atomically renames `audit_ratchet.state.tmp` to `/var/lib/sigrund/audit_ratchet.state`, and calls `fsync(var_lib_dir_fd)`.
6. Outputs the verification anchor `{ "host_id": "...", "initial_seq": 0, "anchor_key_hex": "<hex-of-K_0>", "genesis_record_sha256": "<SHA256(record_0)>" }` to `stdout` (or `--anchor-out <path>`) for registration with external verifiers/collectors together with the authorized TLS client-key-to-host mapping in Section 4.4, and **only after outputting the anchor** zeroes $K_0$ in memory via `explicit_bzero()`.

### 7.2 Per-Event Append & Atomic Ratchet Protocol

To write event `seq = i` ($i \ge 1$) using current state $S = (\text{seq} = i, K_i, \text{last\_record\_sha256}, \text{remote\_acked\_seq})$:

1. Construct the event object with `seq = i`, `host_id = local_host_id`, and `prev_record_sha256 = S.last_record_sha256`, compute `entry_hmac = HMAC_SHA256(K_i, event_body_jcs)`, and serialize the complete record as canonical single-line JCS JSON (`record_i_bytes`) **without a trailing newline**. `entry_hmac` is the 64-character lowercase hex encoding of the HMAC result (decode to raw bytes before constant-time verification). `event_body_jcs` is the canonical object with `entry_hmac` omitted; `record_i_bytes` includes that field. HMAC inputs, record hashes, `prev_record_sha256`, and replicated `records_jcs` exclude the on-disk line delimiter. Enforce the Section 4.4 limit of `65536` bytes for `record_i_bytes` before writing; fail closed if it is exceeded.
2. Record the current EOF byte offset `eof_before` of `/var/log/sigrund/audit.jsonl`. Write exactly `record_i_bytes || "\n"` (one newline byte, `0x0a`) to `audit.jsonl` and call `fsync(log_fd)`.
* If `write()` or `fsync(log_fd)` fails, attempt `ftruncate(log_fd, eof_before)` and then `fsync(log_fd)` as compensation. If either rollback operation fails, immediately fail closed: stop accepting requests, close the control socket, emit no further audit record, and require operator recovery after verifying the log/state pair. If both succeed, abort the operation in memory without ratcheting $K_i$; a failed write/flush never advances the ratchet.


3. Compute $K_{i+1} = \text{SHA-256}(K_i \parallel \text{"sigrun-ratchet-v1"})$ and `record_i_sha256 = hex(SHA256(record_i_bytes))`.
4. Write `{ "key_hex": "<K_{i+1}>", "last_record_sha256": "<record_i_sha256>", "remote_acked_seq": S.remote_acked_seq, "seq": i + 1 }` to `/var/lib/sigrund/audit_ratchet.state.tmp` (`0600 root:root`), call `fsync(tmp_fd)`, close `tmp_fd`, call `rename("audit_ratchet.state.tmp", "audit_ratchet.state")`, and call `fsync(var_lib_dir_fd)`.
5. Zero $K_i$ in memory (`explicit_bzero`).

The state file also carries `initial_key_hex`, the protected 64-character
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

On every daemon startup (before creating `/run/sigrund.sock`), `sigrund` removes any leftover `audit_ratchet.state.tmp`, loads `/var/lib/sigrund/audit_ratchet.state` ($S$), and scans `/var/log/sigrund/audit.jsonl` from byte `0`, parsing every complete `\n`-terminated line and verifying that `seq` increments strictly from `0` by `1` and that every record $k > 0$ has `prev_record_sha256 == hex(SHA256(record_{k-1}_jcs_bytes))`. Let `last_seq` be the `seq` of the last complete `\n`-terminated record:

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

## 8. Cumulative Verification & Security Validation Matrix (`v1.0`)

### 8.1 Isolated Test Fixtures

Each case runs in a fresh isolated daemon state with test signing keys and actual test accounts, never by weakening a production policy. The baseline test signer copies the ceilings in Section 4.1 but substitutes a valid test public key; each warrant is signed with the matching private key and binds the connecting account's actual UID/GID and the test host. Unless a case deliberately violates a predicate, executable/stdin digests, target UID/GID and supplementary groups, environment, mode, validity window, and quotas all satisfy the authorization gate. Use distinct fresh grants between cases and subcases, except where replay of the same grant is the test. Additional fixture policies are explicit:

* **V-01 concurrency fixture:** After checking default admission limits in subcase 1, use the default immutable socket/worker ceilings (`64` global / `4` per UID sockets and `16` global / `2` per UID workers) with a bounded client pool of four open sockets. Submit the exact same signed `one_time` warrant from 32 queued callers, all UID `1001` with the same actual requester GID. Use a small executable so snapshots fit the default per-UID/global RAM quotas. All target fields remain within the baseline signer ceilings. its warrant uses `stdin_policy: "null"`.
* **V-02 same-UID fixture (subcase 2 only):** Add `1001` to `allowed_target_uids` of a dedicated test signer; use `target_gid: 33`, `supplementary_gids: [33]`, and `capabilities: []`. Run the default-denial subcase with both daemon and signer `allow_same_uid_elevation = false`, then the opt-in subcases with both set to `true`. All target ceilings pass before the same-UID guard is evaluated. Subcase 1 uses the baseline signer's actual `allowed_supplementary_gids = [33, 104]`.
* **V-06 credential fixture:** A dedicated test signer has `allowed_requester_uids = [1001]`, `allowed_target_uids = [0, 1005]`, `allowed_target_gids = [0, 33]`, `allowed_supplementary_gids = [33]`, and `allowed_capabilities = ["CAP_NET_ADMIN", "CAP_NET_BIND_SERVICE"]`; all other ceilings follow the baseline. Sign separate warrants for (a) UID/GID `0:0`, no supplementary groups, `CAP_NET_ADMIN`, and (b) UID/GID `1005:33`, supplementary group `33`, `CAP_NET_BIND_SERVICE`, both requested by UID `1001`.

* **Other policy-dependent cases:** V-02 subcase 3 uses Signer A with `CAP_SYS_ADMIN` excluded and Signer B with it allowed, keeping all unrelated ceilings valid. V-03 uses trust entries matching each signature format; its OpenPGP fixture explicitly allows `permanent` as well as `one_time`. V-07 and V-12 use a fixture allowing PTY and unrestricted stdin so the FD/TTY checks and PTY transfer are exercised independently of signer policy. V-13 uses otherwise-valid `stdio` and `pty` requests under the corresponding fixtures and fresh long-running jobs for post-authorization violations. V-10 uses UID/GID `33:33` for safe-profile probes and extends the test capability ceiling only for its explicitly out-of-profile classification cases.

### 8.2 Verification Cases

| Test ID | Invariant / Vulnerability Tested | Test Procedure | Expected Outcome |
| --- | --- | --- | --- |
| **V-01** | Per-UID admission limits, same-UID concurrent `one_time` redemption, & expiry | 1. Open 5 concurrent sockets from UID 1001 (`limit = 4`).<br>

<br>2. Using the V-01 concurrency fixture in Section 8.1, have 32 queued callers running as UID `1001` submit the exact same valid `one_time` warrant through the bounded four-socket client pool with matching requester UID/GID.<br>

<br>3. Submit `one_time` warrants with `now` before `not_before`, `now` after `not_after`, and a request delayed `2.5s` by a hook/RPC so `not_after` passes before `clone3()`. | 1. 5th socket closed immediately on `accept4()`.<br>

<br>2. Exactly **1** request returns `"READY_TO_EXEC"` and spawns; the other **31** return `"REPLAY_DETECTED"`.<br>

<br>3. All three time-window cases return `"EXPIRED_OR_NOT_YET_VALID"` without spawning; the delayed `one_time` grant remains consumed in SQLite. |
| **V-02** | Authorization gate, same-UID ptrace/injection guard, & multi-sig isolation | 1. Submit warrants with mismatched `SO_PEERCRED`, mismatched `host_id`, or `supplementary_gids: [6]` exceeding the baseline `allowed_supplementary_gids = [33, 104]`.<br>

<br>2. Using the V-02 same-UID fixture in Section 8.1 (which allows target UID `1001`), submit a warrant with `target_uid == requester_uid` (`1001`), `supplementary_gids: [33]`, and `capabilities: []` under default config, and under `allow_same_uid_elevation = true` with Yama `ptrace_scope = 0` vs `ptrace_scope = 1` + `suid_dumpable = 0`. Execute a small post-exec probe (e.g., `cred-probe`) that calls `prctl(PR_GET_DUMPABLE, 0, 0, 0, 0)` before changing dumpability and includes its integer return value as `dumpable` in its stdout JSON; a syscall error fails the probe. Keep it alive while a separate same-UID process attempts `PTRACE_ATTACH`.<br>

<br>3. Submit DSSE envelope with Signer A (valid sig, lacks `CAP_SYS_ADMIN`) + Signer B (invalid sig, allows `CAP_SYS_ADMIN`). | 1. Rejected with `POLICY_VIOLATION`.<br>

<br>2. Rejected under default config and when `ptrace_scope == 0`; when permitted (`ptrace_scope >= 1`, `suid_dumpable == 0`, `exec_memfd` mode `0111`), the probe reports `"dumpable": 0` in its post-exec JSON and same-UID `PTRACE_ATTACH` fails with `EPERM`. `/proc/<pid>/status` is supplementary evidence only: absence of `Dumpable` is permitted, and `CoreDumping` is not a substitute for `PR_GET_DUMPABLE`.<br>

<br>3. Rejected; permissions across signers are never unioned. |
| **V-03** | DSSE PAE interop, JCS parser differentials, FIDO2 `UP` bit, & OpenPGP `permanent` time check | 1. Verify the Section 3.1 119-byte `v1` PAE test vector.<br>

<br>2. Submit JSON with duplicate keys, non-JCS key order, ESC (`\x1b`), and BiDi (`U+202E`).<br>

<br>3. Submit `sk-ssh-ed25519@openssh.com` with `flags = 0x00` when `require_user_presence = true`.<br>

<br>4. Verify `openpgp-v4-ed25519` signature on both a `one_time` grant and a `permanent` grant (`not_after: null`). | 1 & 4. Verify cleanly.<br>

<br>2 & 3. Rejected with `INVALID_REQUEST`. |
| **V-04** | Anchored path resolution, FIFO open, binary mutation, & concurrent growth | 1. Submit `executable_path: "/usr/bin/../../tmp/evil"` and a symlink inside `/usr/bin`.<br>

<br>2. Point `executable_path` at a named FIFO.<br>

<br>3. Modify binary between CSR and execution, or concurrently append/write via an open writable FD during `exec_memfd` copy. | 1. Rejected by `openat2(RESOLVE_BENEATH | RESOLVE_NO_SYMLINKS)`.<br>

<br>2. `O_NONBLOCK` + `fstat` rejects FIFO without blocking.<br>

<br>3. Mutation rejected by SHA-256 or `total_copied != st_size`, or child executes sealed `exec_memfd` unaffected by later writes. |
| **V-05** | Clean-room `envp` construction & sealed `stdin_memfd` binding | 1. Caller sets `PATH=/tmp` and `LD_PRELOAD=/tmp/evil.so` before invoking `sigrun` on a warrant with `env_exact: {"PATH": "/usr/bin"}`.<br>

<br>2. Attempt caller exact-name allowlist for `LD_PRELOAD` or `PYTHONPATH`.<br>

<br>3. Submit `stdin_policy: "sha256"` with mismatched `stdin` bytes.<br>

<br>4. With `caller_env_allowlist: ["TERM"]`, forward a safe `TERM` value, omit `TERM`, try unlisted `LANG`, use `LC_*`/regex syntax, and submit the obsolete `env_wildcard_allowlist` field.<br> | 1. Child runs with only `PATH=/usr/bin`; `LD_PRELOAD` is absent.<br>

<br>2. Rejected by caller-environment denylist.<br>

<br>3. Rejected with `STDIN_HASH_MISMATCH`.<br>

<br>4. Exact `TERM` forwarding and omission succeed; unlisted names, pattern syntax, and the obsolete field are rejected. Values use only the documented string rules, with no hidden regex matching. |
| **V-06** | Post-exec credential, capability, securebits, & FD table probe (`cred-probe`) | Using the V-06 credential fixture and warrants in Section 8.1, execute `/usr/libexec/sigrun/cred-probe` under: (a) `target_uid: 0`, `capabilities: ["CAP_NET_ADMIN"]`, and (b) `target_uid: 1005`, `supplementary_gids: [33]`, `capabilities: ["CAP_NET_BIND_SERVICE"]`. | Output JSON confirms exact `resuid`, `resgid`, `supplementary_gids`, `securebits_hex: "0x2f"`, `no_new_privs: 1`, exact capability sets (`P=E=I=Amb=Bnd`), `dumpable` from `prctl(PR_GET_DUMPABLE)`, and `open_fds: [0, 1, 2]`. |
| **V-07** | Malformed `SCM_RIGHTS`, TTY/stdin matrix, & stalled pipe quota pinning | 1. Send `CLIENT_HELLO` with `S_ISSOCK`, `S_ISDIR`, `O_PATH`, or wrong FD count.<br>

<br>2. Request `"pty"` with `"null"`/`"sha256"`, or pass a caller TTY as `stdout` under `"null"`.<br>

<br>3. Pass 2 stalled pipes (clearing `O_NONBLOCK` from caller) from UID 1001 while UID 1002 runs normal requests.<br>

<br>4. Exercise Section 2.3.1 with truncated ancillary data (`MSG_CTRUNC`), multiple returned control messages, unexpected ancillary types, and four or more FDs (including an extra FD fitting alignment padding). Attach rights to the hello length/payload, a second hello, signal/resize frames, and bytes following a framing error. Test fragmented valid hellos and inspect received `FD_CLOEXEC` before any subsequent `fcntl()`. Use real socketpairs for descriptor delivery, truncation, and stream association; additionally exercise decoder error branches with a test harness for malformed or unexpected control structures that Linux filters or normalizes before delivery.<br> | 1 & 2. Rejected immediately.<br>

<br>3. UID 1001 receives `REQUEST_TIMEOUT` at `5000 ms` while its 2 stalled workers remain pinned against UID 1001's quota (blocking a 3rd request from UID 1001 with `RESOURCE_EXHAUSTED`) until the pipes close; UID 1002 requests complete in under `50 ms`.<br>

<br>4. Only the initial hello type-byte receive may accept exactly one rights message with the matrix's exact FD count. All other ancillary cases terminate the connection without spawn (or tear down an already-active job). All received and retained request FDs close on every rejection; repeated attacks leave the daemon's FD count unchanged. Valid fragmentation preserves FD association, all received FDs already have `FD_CLOEXEC`, and no post-error frame is processed. For sender-side rights messages merged by Linux, enforce the returned-message and aggregate-count rules rather than assuming original message boundaries remain observable. |
| **V-08** | Two-frame `sync_pipe` handshake, Central Reaper concurrency, & hook `pivot_root` | 1. Inject child `SIGKILL` (a) before writing readiness and (b) after the full readiness write but before the exec syscall, using a deterministic test gate at that boundary. Also test `execveat()` `ENOEXEC`, fast `/bin/true` exit, malformed/partial sync frames, and timeout.<br>

<br>2. Run 16 concurrent jobs that spawn orphaned grandchildren and exit simultaneously with distinct exit codes `1..=16`; include hooks that exit before exec. Inspect job and hook `clone_args.exit_signal` and exercise both pidfd and `SIGCHLD`/`P_ALL` reaper paths.<br>

<br>3. Verify hook `pivot_root` mounts (`/` and `/usr` read-only, `/oldroot` detached, only `/tmp` writable, `FDs [0,1,2]`). Inject missing, malformed, and exec-error hook sync frames even with exit `0` and approval JSON.<br> | 1. Kill before readiness (`0` bytes), reported `ENOEXEC` (`16` bytes), malformed/partial frames, and timeout return `SPAWN_FAILED`. Kill after readiness and before exec (`8` bytes + `EOF`) returns `READY_TO_EXEC` then `SERVER_CHILD_EXIT` (`signal: 9`); `/bin/true` returns `READY_TO_EXEC` then exit `0`. Neither readiness outcome claims exec success.<br>

<br>2. Every job receives its exact distinct exit code `1..=16` with zero `ECHILD` races. All direct job/hook children use `exit_signal == SIGCHLD` and are reaped without clone-child wait options, including pre-exec deaths.<br>

<br>3. Hook sandbox verified; sync faults prevent either approval or rejection JSON from being accepted. |
| **V-09** | Contiguous batch replication, DB-only vs. whole-disk rollback, & audit crash recovery | 1. Execute Job 1 (`seq 1..3`) and submit Job 2 (`seq 4`); verify collector receives records `1, 2, 3, 4` in one contiguous batch.<br>

<br>2. Roll back **only** `state.sqlite` and re-submit `one_time` vs `time_range` warrant.<br>

<br>3. Roll back **entire disk** (`audit.jsonl` + `state.sqlite`) behind `collector_last_seq` and start `sigrund`.<br>

<br>4. Test local startup recovery for partial trailing line, unratcheted single record (`last_seq == S.seq`), and truncated log (`S.seq > last_seq + 1`).<br>

<br>5. Independently alter each `target_auth` field (`auth_commit_seq`, `exec_id`, `grant_id`, `payload_sha256`, `signer_id`, `policy_mode`, both validity bounds, `host_id`) while leaving authenticated record bytes unchanged; test missing/extra/ill-typed fields and a non-`AUTH_COMMIT` target record. Use an unregistered TLS key, then a key registered to host A with a request claiming host B.<br>

<br>6. Accumulate a suffix exceeding 256 records and 1 MiB. Test limits at and above each bound, a lost intermediate receipt, lost final `ALLOW` receipt, cumulative timeout, and startup suffix replication.<br> | 1. Collector verifies unbroken hash/ratchet chain across `1..4`.<br>

<br>2. Collector ingests audit batch, rejects `one_time` with `DENY_REPLAY` (`REPLAY_DETECTED`), and allows `time_range`.<br>

<br>3. `sigrund` fails closed at startup with `AUDIT_REMOTE_CHECKPOINT_MISMATCH`.<br>

<br>4. Partial line and unratcheted record recover cleanly; truncated log fails closed with `AUDIT_TAMPER_OR_CORRUPTION`.<br>

<br>5. Altered authorization metadata is rejected with `AUTH_RECORD_MISMATCH`, without deduplication writes or spawn; C0 rejects unauthenticated host claims before ingestion. Authorization decisions use only authenticated record values.<br>

<br>6. Chunks obey count, decoded-byte, and serialized-body limits with no gaps or split records. Intermediate receipts are `ACK_ONLY` and cannot authorize or consume grants; only final authenticated `ALLOW` permits proceeding. Identical retries are idempotent, cursor advancement is durable per chunk, exceeding limits fails before excessive allocation, and timeout prevents spawn. Startup chunks all use null targets and never authorize historical jobs. |
| **V-10** | Startup orphan ownership and safe-profile containment boundary | 1. Crash the daemon while jobs/hooks survive in their cgroups; restart after those processes have been reparented to PID 1 or another subreaper.<br>

<br>2. Under nonzero UID with `C = {}` and `C = { CAP_NET_BIND_SERVICE }`, establish the Section 1.1 host-access restrictions, attempt direct cgroup migration and host control-plane migration, and spawn background descendants. Separately classify nonzero-UID grants with `CAP_NET_ADMIN`, `CAP_SETUID`, or host management socket access.<br> | 1. Restart kills old cgroups, observes `populated 0`, logs cleanup, and removes directories without expecting `waitid()` ownership or old exit statuses; existing parents reap those processes.<br>

<br>2. Safe-profile migration attempts fail and descendants are killed with their job cgroup. All examples outside the enumerated capability/access conditions carry only best-effort containment claims, even if their particular migration attempts fail. |
| **V-11** | Exact cgroup mount syscall sequence and namespace isolation | In a disposable cgroup v2 test host with a writable parent cgroup mount, open a fresh job cgroup and call `clone3()` with `CLONE_INTO_CGROUP | CLONE_PIDFD | CLONE_NEWNS | CLONE_NEWCGROUP` and `exit_signal = SIGCHLD`. While the setup child still has mount authority, run the Section 5.3 Step 1 code verbatim: `mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL)`, then `syscall(SYS_mount_setattr, AT_FDCWD, "/sys/fs/cgroup", AT_RECURSIVE, &attr, sizeof(attr))`, then `statvfs()` and the mountinfo checks. Capture syscall return values and errors. Attempt `open("/sys/fs/cgroup/cgroup.procs", O_WRONLY | O_CLOEXEC)` inside the child before dropping credentials. Compare parent mount flags and write access before/after; then complete the credential transition and exec probe. Repeat with injected `mount()`/`mount_setattr()` failure.<br> | Both mount operations return `0`; no same-source bind is issued and no `EINVAL`/`EBUSY` workaround is needed. Child mount and submount flags are `ro,nosuid,nodev,noexec`, propagation is private, and the pre-drop write-open fails with `EROFS`. Parent flags and write access are unchanged. Normal setup reaches `READY_TO_EXEC` and the post-exec probe confirms the flags. Injected syscall failures report `{ step: 1, errno: <injected> }`, return `SPAWN_FAILED`, and never exec. |
| **V-12** | Server PTY ancillary layout, client validation, and FD ownership | 1. Use the PTY fixture to execute a probe. Capture the server's one-byte `sendmsg()` carrying `0x02` and one master FD, then fragmented length/payload writes. Receive with one-byte type reads and `MSG_CMSG_CLOEXEC`; verify `TIOCGPTN`, access mode, terminal relaying, and resize handling.<br>

<br>2. Test missing, duplicate/extra, truncated, malformed, and unexpected ancillary data; attach rights to length/payload, a rejection decision, a `stdio` decision, and `SERVER_CHILD_EXIT`. Include an extra FD fitting alignment padding. Use a receive-decoder harness for kernel-filtered/normalized structures.<br>

<br>3. Disconnect either endpoint after the rights byte but before the decision payload completes, fail the client's relay, and test normal completion and daemon disconnect while another process holds the slave.<br> | 1. Exactly one master is accepted only with the complete `pty`/`READY_TO_EXEC` decision; it is close-on-exec at receipt and unused while pending. Fragmentation does not resend or misassociate rights.<br>

<br>2. All invalid transfers close every delivered FD and the control socket, restore the client terminal, report `SERVER_PROTOCOL_ERROR`, and exit `254`; no fallback or successful rejection hides the error. Repeated cases do not increase either endpoint's FD count.<br>

<br>3. Pending/active master and parent-owned slave references close on their specified cleanup paths; unexpected EOF reports `DAEMON_DISCONNECTED`. Client failure triggers cgroup teardown, daemon failure releases the client master without waiting for PTY EOF, and normal completion leaves no retained PTY FDs. |
| **V-13** | Per-type frame limits and cumulative assembly deadlines before and after authorization | For every type in Section 2.1.1, test a valid payload at its maximum length (using permitted JSON whitespace padding), then length `0`, maximum plus one, and `0xffffffff`, sending only the type/length for oversized cases. Test unknown types, wrong direction, and duplicate/out-of-state frames. After `READY_TO_EXEC`, send partial signal/resize headers or bodies and trickle bytes across `5000 ms`; repeat against the client with a partial server decision/exit, including a pending PTY FD. Also leave a healthy job's control socket idle for longer than `5000 ms` with no partial frame. Monitor receiver allocations, FD counts, cgroup teardown, and other concurrent jobs.<br> | Valid bounded frames parse; unknown/out-of-state types fail upon their type byte, and zero/oversized lengths fail immediately after the length without payload allocation or draining. User-space storage remains bounded by one validated frame limit. Assembly expiry occurs by the original first-byte deadline despite trickling; the initial hello also respects the accept-based deadline. After authorization, invalid/expired client frames cause immediate disconnect teardown with no second auth decision, and malformed server frames cause client FD cleanup, terminal restoration, `SERVER_PROTOCOL_ERROR`, and exit `254`. Job exit and other jobs remain responsive during partial reads. Idle sockets with no pending frame do not time out healthy jobs. |
| **V-14** | Common snapshots in both modes and anchored relative path resolution | Run the same executable/hashed-stdin request through signed and unsigned workflows. Inspect retained memfd bytes, modes, seals, source FD closure, digest binding, and cancellation handoff. Mutate executable/stdin after copying and alter a hook-returned command/context/grant/digest. Submit unsigned requests with mismatched top-level/requested-command `tty_mode`. Configure overlapping allowed roots, then test `/usr/bin/probe`, `/usr/bin-evil/probe`, paths equal to a root, symlinks, cross-mount traversal, and traversal components. Capture `openat2()` arguments.<br> | Both modes produce the same immutable snapshots before consumption/spawn; later source changes cannot alter execution. The hook cannot substitute any CSR field or cause recopy. Longest component-prefix selection passes only the stripped relative suffix to the pinned root FD, never an absolute path with `RESOLVE_BENEATH`; invalid prefixes/traversals and final signer/root metadata mismatch reject. All failure paths retain quotas until actual FD owner cleanup. |
| **V-15** | Cancellation linearization and terminal response ownership | Use deterministic gates after the worker's last cancellation check, before snapshot-result handoff, immediately before/after commit reservation, before `COMMIT`, and before/after spawn reservation/final syscall check. At each gate fire the matching timeout or disconnect, then release work. Exercise a commit that completes while cancellation is pending and a clone that returns a child after its reservation. Record lifecycle/decision CAS winners, database state, audit records, and all returned PIDs/pidfds.<br> | A snapshot timeout winner cannot be revived by late results; workers never authorize/spawn. A cancellation winner before a reservation causes rollback/no clone. Reserved operations reconcile pending cancellation after known results: consumed grants remain consumed, `AUTH_COMMIT` precedes `AUTH_ABORTED_POST_COMMIT`, and any returned child is registered and torn down without readiness. Exactly one decision is published (or no reply on disconnect); no timeout response is followed by an untracked commit/spawn. Phase-stale timers have no effect. |
| **V-16** | Nonblocking hook stdin, shared deadline, and strict hook JSON | Send a near-64-KiB CSR to a hook that never reads stdin; also test slow reads, short writes, output-before-input, `EPIPE`, early exit, and cancellation. Run other clients concurrently. Test duplicate/unknown keys, nested duplicates, multiple JSON objects, unknown statuses, missing fields, invalid UTF-8, fractional numbers, and rejection reasons of 1024 vs. 1025 UTF-8 bytes.<br> | The main loop never blocks on pipe writes, drains output concurrently, delivers each input byte once, and closes stdin at completion. All hook phases share the original 25-second budget; stalled delivery cannot extend it or delay unrelated jobs. Failed/incomplete input prevents hook JSON acceptance. Only exact bounded schemas can approve/reject; all other outputs fault and follow the remaining-budget/fallback rules. |
| **V-17** | Enforced job memory/process limits | Under safe-profile UID/GID `33:33`, read job cgroup controls before clone; use one probe allocating memory beyond the configured bound and another creating processes/threads until denied. Inject a cgroup-limit write/read-back failure and test invalid unlimited config. Keep all snapshot/admission limits satisfied.<br> | Defaults are `memory.max = 268435456`, `memory.swap.max = 0`, `memory.oom.group = 1`, and `pids.max = 128` before the child exists. Excess allocations trigger bounded allocation failure/OOM; process/thread creation fails at the cgroup limit. Primary wait status and teardown remain correct. Missing/failed controls prevent spawn; unlimited config is rejected. Host-root/out-of-profile guarantees remain qualified. |
| **V-18** | Audit delimiter/hash normalization and complete wire encodings | Append two audit records, inspect exact log bytes, and independently recompute hashes/HMACs without newline delimiters. Insert a digest revocation using uppercase admin input and redeem the matching lowercase warrant digest. Validate normal vs. signal child-exit objects, both-null/both-non-null variants, and CSR status output. Exchange batch/checkpoint RPCs with known raw Ed25519 keys; verify PAE/signatures independently. Test duplicate/missing lengths, chunked/EOF framing, oversized bodies/headers, trailing bytes, wrong DSSE type/key ID, SSH-wrapped signatures, non-canonical Base64, and untrusted checkpoint host IDs.<br> | Exactly one `0x0a` separates records and all verification inputs exclude it. Digest revocation matches after lowercase normalization. Only the specified mutually exclusive exit fields pass; CSR bytes are canonical JSON without PEM armor. Only exact bounded HTTP/1.1 messages and raw-Ed25519 DSSE envelopes verify; malformed RPCs never advance the daemon cursor or permit spawn. Signed host-bound checkpoints reconcile only after full verification. |
| **V-19** | Unsigned field binding, root-policy generation, numeric bounds, remote denial mapping, and rollback fail-closed behavior | 1. Configure two signer entries with unequal executable-root lists, attempt startup and reload, then correct them and perform a `SIGHUP` while active requests use the old generation. Change hook quotas and the request deadline between generations, and keep an active hook pipeline running during the reload. Submit unsigned requests with matching and mismatched duplicate `tty_mode` fields.<br>

<br>2. Submit UUIDs with uppercase/incorrect version or variant, UID/GID `UINT32_MAX`, timestamps outside `0..=253402300799`, negative/exponent/fractional `ttl_secs`, and values that overflow `not_before + ttl_secs`.<br>

<br>3. Return verified collector `DENY_EXPIRED`, `DENY_REVOKED`, and `DENY_REPLAY`; separately corrupt a receipt. Inject `ftruncate()` and compensating `fsync()` failures after an audit write error.<br> | 1. Unequal signer/CSR roots fail configuration atomically; corrected reload creates a new generation while active requests retain old roots/limits, including hook quotas and deadlines; only newly admitted requests use changed hook quotas. Unsigned tty mismatch is rejected before snapshotting or hooks.<br>

<br>2. Only canonical lowercase UUIDv7 and bounded UID/GID/timestamp/integer values pass; overflow is rejected without allocation, commit, or spawn.<br>

<br>3. Verified denials map to `EXPIRED_OR_NOT_YET_VALID`, `REVOKED`, and `REPLAY_DETECTED` respectively, append the post-commit abort, and never spawn. Corrupt receipts fail as `REMOTE_AUDIT_FAILED` without cursor advancement. Rollback failure stops accepting requests and fails closed without ratcheting. |

### 8.2.1 Required Pre-Execution Regression Subcases

These extend the existing V rows; they are not optional roadmap-only tests.
The local MVP runs the job/local-audit portions before claiming completion;
hook, reload and remote subcases remain requirements for their owning features.

| Existing cases | Additional deterministic fixture | Required observation |
| --- | --- | --- |
| V-07, V-13, V-19 | Gate WAL/audit fsync while unrelated requests expire, are refused, have no approver or exhaust workers. Keep sockets writable and receive decisions before releasing the gate. Repeat disconnects across admission windows. | Pre-commit replies obey their phase/send deadlines; no second decision on audit completion; retained audit/worker/FD/RAM charges stay bounded and release exactly once. Reservation outcomes remain reconciled. |
| V-19 | Exhaust per-UID and global admission windows with many UIDs; cross a window boundary with pinned audits, lower quotas on reload, attempt restart-only changes and invalid/overflowing limits. | Exact configured counts, bounded UID table, preserved reload debt and retained ownership; excess admission closes before parsing or receiving rights; no per-attempt durable rejection flood. |
| V-09, V-18, V-19 | Cross log high water and each distinct filesystem's free-space floor; inject failed capacity checks, ENOSPC and EIO before/after commit. | Admission stops, uncertain transactions are not retried, committed records are not skipped, poison rules and shutdown apply. Verified restart after remediation preserves host identity, history and consumption. |
| V-06, V-08, V-11 | Inject unshare and every initial FD duplication/remap failure, including EMFILE and closed descriptors 0–4; place a writable sentinel at inherited FD 4 (FD 3 for hooks). | Only the actual sync pipe receives error bytes; unrelated sentinel contents remain unchanged; missing/partial evidence never yields readiness or exec. |
| V-08, V-10 | Gate publication after clone returns, let that child and a registered primary exit concurrently, then cancel or start shutdown before releasing the gate. | The registration barrier prevents untracked-primary status theft; registered primaries remain serviceable; both exact statuses are delivered once and cancelled children are torn down without readiness. |
| V-08, V-10, V-17 | SIGINT/SIGTERM and fatal-storage shutdown before/after commit and clone reservations, during running work and blocked cleanup; force daemon death and exercise supervisor escalation/restart in a real delegated service. | No new reservations/readiness after shutdown; ownership and instance lock persist through reconciliation; whole-service cleanup and orphan recovery precede restart admission, with no invented prior-instance exit status or containment claim. |

### 8.3 Implementation Status and Release Gate

This specification is the target runtime contract. The current repository
contains tested protocol, policy, snapshot, lifecycle, state, audit, framing,
path, memfd, and cgroup helper primitives. Phases 0–3 provide typed request and
broker contracts, bounded foreground transport, retained sealed snapshots,
root-TTY approval, and SSH signing. Phase 4 now integrates the local thin
profile authorization predicate, one bounded off-loop SQLite/audit sequencer,
one-time consumption, authenticated `AUTH_COMMIT`/rejection records, and
post-commit abort reconciliation. Phase 4.5 adds independent pre-commit denial
responses, retained bounded audit ownership, admission windows and sticky
storage-pressure gates, including post-append refresh.

Phases 5A/5B add descriptor-pinned cgroup startup, bounded committed-job
preparation/cleanup, the standalone pending-spawn registration barrier and
syscall-only clone/descriptor/mount/credential/exec transition. Normal foreground
startup requires its isolated platform probe; `--authorization-only` explicitly
selects the non-executing diagnostic profile. Startup probes create trusted test
children, but requester commands still stop at an audited post-commit abort:
`SPAWN_FAILED`, with consumption preserved. Live requester clone dispatch,
readiness publication, central reaper integration and active-job shutdown remain
Phase 5C requirements. The collector, hooks, reload, remote ACK and PTY also
remain pending.

Unprivileged ownership, real-child registration-barrier and syscall-fault tests
are implemented. The operator explicitly defers privileged delegated-host
acceptance until after Phase 5A/5B land. Its ignored fixture and runner are
provided in the phase evidence documents; the ordinary workspace suite does
not prove those privileged gates. Sections 2.4–5.3 retain their full runtime
requirements, including shutdown and actual post-exec observations.

The following integrations are required before claiming v1.0 conformance:

1. `sigrund` still must complete policy reload, hooks, collector replication,
   live child dispatch/readiness, PTY transfer, central reaping, active-job
   shutdown and disconnect teardown. Privileged cgroup/child acceptance remains
   pending. Startup recovery, root pinning, common snapshots,
   bounded transport, and local authorization/SQLite commit are integrated.
2. `sigrun` must complete server PTY transfer, window relaying, PTY terminal
   cleanup and validation against actual child execution. The stdio
   `CLIENT_HELLO` descriptor contract, signed/unsigned request construction,
   status-fd reporting, frame deadlines and signal handling are integrated.
3. `sigrund-collector` must implement authenticated TLS transport, exact
   HTTP/DSSE framing, contiguous batch verification, host binding,
   deduplication, durable cursor advancement, and the denial mappings in
   Section 4.4.
4. `sigrundctl` must complete provisioning and operator workflows, including
   the anchor-output contract and safe administrative revocation operations.
5. V-01 through V-19 must run in isolated Linux fixtures with deterministic
   gates for cancellation, commit/spawn reservations, crash recovery, and
   descriptor transfer. Unit tests, `cargo test`, and Clippy alone do not
   satisfy this matrix.

An implementation may claim a row of the matrix only when the end-to-end
observable behavior in that row passes. A helper unit test may support a row,
but cannot waive a missing daemon, client, collector, or operator integration.
