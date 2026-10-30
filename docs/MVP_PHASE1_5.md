# Phase 1.5: resource ownership and snapshot preparation

Phase 1.5 closes the midpoint code-review findings before the Phase 2 client
and common-snapshot runtime. The daemon continues to reject execution. This
phase implements reusable foundations; it does not claim a working approval
or execution path.

## Implement–Verify–Fix loop

For each row, implement its contract, run the focused probe, fix every failure,
then run the existing Phase 0/1 regressions. Record the observed results below.
Do not advance to Phase 2 with a failing row.

| Item | Implementation contract | Required verification |
| --- | --- | --- |
| P15-01 | Reserve a shared global/per-UID worker before any receive that can deliver caller rights. Receive, reject and close those rights off-loop, including malformed frames, timeout, disconnect, quota refusal and stale completions. Keep quotas through actual disposal. | Real-daemon blocked-close interposer; other-UID traffic and shutdown remain responsive, no replacement workers, no premature quota release, and cleanup restores FD counts. |
| P15-02 | Separate `O_PATH` directory/root pinning from readable-file opens. Pin roots with `O_DIRECTORY`, permit mount crossing during root pinning, and restrict executable-relative opens with `NO_XDEV`. | Assert descriptor flags, reject non-directory roots, and exercise mount-crossing vs. relative symlink/mount rejection in isolated Linux fixtures. |
| P15-03 | Return an owned validated request that retains the hello, descriptors, captured policy, cancellation and shared worker reservation. Continuation and cleanup use the same reserved worker. | Successful validation preserves FD identity; continuation runs off-loop without acquiring a second quota slot; cancellation/stale results release only after disposal. |
| P15-04 | Stream and hash into memfds with bounded chunk storage, interrupted-I/O handling, cancellation/deadline checks, finite snapshot reservations, seals and rewound stdin. Permit empty hashed stdin; executable size remains positive and exact. | Empty/short/interrupted/growing inputs, cancellation, bounds/quota rejection, seal/write rejection, offset and digest checks; reservations survive ownership transfer and release on cleanup. |
| P15-05 | Apply the updated thin-profile restrictions to both signed and unsigned hellos before descriptor metadata/snapshot work. Use kernel requester UID for the same-UID guard. | Accept null/hashed stdin and reject reusable modes, scripts, unrestricted input, caller environment and same-UID requests; real-daemon denials occur before blocked metadata. |

The signing identity configuration and approval runtime remain Phase 3 work.
The full client/relay/snapshot coordinator remains Phase 2 work. The profile
continues to reject execution throughout this phase.

## Gates

```sh
cargo test -p sigrund --lib --test phase15_foundations --locked
cargo test -p sigrund-core --test phase0_contracts --locked
cargo test -p sigrund --test phase1_transport --locked
cargo test -p sigrund --test phase1_daemon --locked -- --nocapture
cargo test --workspace --locked
cargo +1.89.0 test --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all -- --check
git diff --check
```

The Phase 1 namespace fixture prerequisites still apply. Tests must not weaken
production policy or require host-root changes. A missing prerequisite fails
the gate with an actionable diagnostic.

## Evidence

All five rows and the workspace gates pass on Linux
`7.2.11-300.fc45.x86_64`, with Rust `1.101.0-nightly` and the declared minimum
Rust `1.89.0`. The workspace run includes 76 passing top-level tests. Four
ignored entry points are fixture subprocess helpers invoked by their ordinary
gates, not waived tests. Clippy with warnings denied, formatting and diff checks
pass. The minimum-toolchain run repeats the complete workspace, including the
namespace-root/non-root daemon and blocked-close snapshot fixtures.

Final verification used `--offline` against the cached registry/index.
`Cargo.lock` and dependency versions are unchanged.

| Item | Implemented evidence |
| --- | --- |
| P15-01 | `IoWorkers` reserves capacity before duplicating/receiving a control socket. All caller-rights reception and disposal happens on its fixed worker. `verify_blocked_cleanup` in the real-daemon gate stalls `close()` for valid, malformed-JSON/type/ancillary, late-rights, timeout, disconnect, profile-denial and broker requests. It observes worker TIDs, unchanged thread count, pinned UID quota, other-UID service, exact completion events, FD recovery and responsive SIGTERM. It also inspects the live epoll registrations to require removal of each retired connection before blocked disposal completes. Existing blocked-`fstat` and PID-namespace regressions still run. |
| P15-02 | `phase15_foundations` checks `O_PATH`, `O_DIRECTORY` and CLOEXEC, rejects regular-file roots and symlinks, pins `/proc` across a real mount boundary, then requires `EXDEV` for executable-relative traversal into that mount. Startup uses this directory helper for configured executable roots. |
| P15-03 | The worker continuation test retains the exact descriptor numbers, hello, captured policy, UID and deadline across two continuations on the same worker. It builds a real sealed snapshot in that lease, proves no second slot is admitted, cancels a later continuation, and verifies disposal releases both RAM and the worker reservation. Stale results in the real-daemon timeout/disconnect regressions cannot revive a request. |
| P15-04 | `phase15_foundations` verifies streaming digest/size/offset/seals, short reads/writes and EINTR, early EOF/excess data, empty hashed stdin, executable ELF/size bounds, cancellation, global/per-UID RAM limits, ownership transfer and cleanup. A subprocess stalls the actual snapshot source close and proves RAM stays charged before and after transfer into the sealed result. |
| P15-05 | `phase15_profile_restrictions_apply_to_signed_and_unsigned_requests` accepts both supported stdin policies and rejects scripts, unrestricted input, forwarded environment, reusable modes and same-UID requests (including a signed requester-UID lie). The blocked-metadata daemon fixture verifies profile denials before the selected `fstat` can run. |

The loop caught and fixed a completion-order race: failed validation originally
published its error before a separate quota-release message. Error completion
now releases the already-cleaned reservation in the same coordinator drain.
Cleanup probes also wait for the request's exact completion event instead of
assuming that an FD-count change proves the reservation was released. Clippy's
large-enum finding was fixed by boxing retained request state, and the shutdown
probe was corrected to consume an already-published rejection before checking EOF.
Final workspace verification also exposed a race in the serial malformed-frame
probes: the next request could arrive before the previous request's disposal
reservation was released. These probes now wait for that request's exact
cleanup event before sending the next input; the separate saturation probes
continue to require quota denials while disposal is blocked.
Ordinary hello probes now send the complete frame in one `sendmsg` call,
avoiding a second write racing an expected early quota denial. Separate
fragmentation probes retain their early-rejection checks.

Review exposed a socket-ownership issue: a worker's duplicate control socket
kept a retired connection registered in epoll while partial-frame rights were
blocked in disposal. Level-triggered hangup events could then spin the
coordinator on the removed token. All connection retirement paths now issue
`EPOLL_CTL_DEL` before dropping the coordinator's socket. The registration
regression failed against the previous implementation and passed with the fix;
it checks `/proc/<pid>/fdinfo` while disposal is blocked instead of relying on
CPU timing.

The normal client, approval prompt, common snapshot coordinator and execution
remain later-phase work. The transport parser itself can still be used
synchronously by unprivileged diagnostics/tests; the daemon invokes its receive
and destructor paths only on reserved workers. A quota-refused connection is
closed without receiving its queued rights. Idle sockets reserve no worker;
once frame reception begins, partial input consumes a slot through timeout and
actual disposal. This stricter admission behavior prevents cleanup capacity from
being multiplied independently of metadata and snapshot workers.

## Post-1.5 fixups

Audit recovery now consumes the exact verified state/log descriptors and retains
the verified state-directory descriptor. Identity/state/log opens, stale temporary
cleanup, temporary state creation, atomic rename and directory fsync use those
directory identities. Renaming an attacker-writable ancestor cannot redirect
recovery or later state publication to replacement paths. The real-daemon
namespace gate pauses after verification, replaces both directory paths, and
requires partial-tail and forward recovery to modify only the verified files.
A core audit test also replaces the directory after opening the writer and
verifies a subsequent append and state publication remain on the original files.
