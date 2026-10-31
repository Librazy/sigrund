# Phase 6 MVP coverage map

This map is updated by the Phase 6 acceptance run. `implemented` means the
code and a focused test exist. `verified` requires the real two-UID delegated
fixture. `deferred` is outside the thin MVP and must not be presented as
supported.

| Milestone | Coverage | Evidence source | Status |
| --- | --- | --- | --- |
| M-01 | Root approval, SSH signature, child result | `operator-workflow`, Phase 6 manifest | verified |
| M-02 | Refusal, blank confirmation, timeout | Phase 3 deterministic deadline fixtures; Phase 6 operator blank-refusal gate | verified refusal; deadline/cancellation regressions passed in ordinary checks |
| M-03 | Non-root broker rejection | Phase 1/3 fixtures | implemented |
| M-04 | Signed CSR mutation binding | `binding-and-concurrent-replay` | verified |
| M-05 | Snapshot mutation/size | Phase 1.5 and Phase 5D fixtures | implemented |
| M-06 | Concurrent one-time replay | `binding-and-concurrent-replay` | verified |
| M-07 | Disconnect/shutdown reservation reconciliation | Phase 5C/5D service artifacts | verified in repeated Phase 5 runtime/failure gates |
| M-08 | Exit, signal, pre-ready and registration race | Phase 5C/5D runtime/failure artifacts | verified in repeated Phase 5 runtime/failure gates |
| M-09 | Descriptor/frame bounds | Phase 1/2 transport fixtures | implemented |
| M-10 | Partial/forward audit recovery | `synchronized-partial-tail-recovery`, Phase 5C poison gate | verified |
| M-11 | TTY, separate output/status, large output, hashed stdin | `operator-workflow`, `output-and-enforced-limits` | verified |
| M-12 | Complete display and real OpenSSH signing | Phase 3 and Phase 5D | verified in repeated Phase 5 runtime/failure gates |
| M-13 | Broker loss, slow signing, reconnect | Phase 3 fixtures | implemented |
| M-14 | Blocked I/O, audit, pressure, cleanup | Phase 4.5/5C, storage fixture and Phase 6 acceptance | implemented; applicable delegated gates verified |
| M-15 | Root/service identities, cgroup controls, setup errors | Phase 5D + VM platform gate | verified in repeated Phase 5 runtime/failure gates |
| V-01..V-06, V-08, V-10..V-11, V-14..V-15, V-17..V-19 | Applicable local/MVP subcases | Phase 0–5 tests and Phase 6 manifest | applicable portions; full rows pending |
| V-07, V-13 | Ancillary layout, stdio matrix, frame bounds/deadlines and worker ownership | Phase 1/2/5 fixtures | applicable local subcases implemented; PTY/resize subcases deferred |
| V-12, V-16 | PTY transport and hooks | specification and focused parser tests | deferred |
| V-09 | Local recovery; remote replication, checkpoint and rollback | Phase 4/5C/6 local recovery fixtures; collector shape validator | local recovery verified; remote runtime and rollback protection deferred |

The final Phase 6 manifest and ordinary-check evidence are retained in
[`docs/evidence/phase6-2026-10-31`](evidence/phase6-2026-10-31/README.md).
The final ordinary check set repeats the referenced focused fixtures in the
VM as an unprivileged build user; the privileged wrapper repeats the Phase 5
platform/runtime/failure gates against those binaries. The map does not claim
full V-01–V-19 conformance. PTY, hooks, remote audit
ACK, reload, reusable grants and additional signature adapters remain later
milestones. The Phase 6 manifest records the exact subcases that passed.
