# Phase 4: authorization, commit, and local audit

Implement–Verify–Fix checklist (implemented for the local-audit boundary):

| Item | Contract | Required evidence |
| --- | --- | --- |
| P4-01 | Complete thin-profile Section 4.2 predicate against retained sealed snapshots, selected signer, peer and policy generation. | Host/peer/signer, root identity, mode/seals/ELF, constant-time digests, environment, capability/group, stdin/TTY, validity and same-UID probes; source replacement must keep the original snapshot. |
| P4-02 | Serialized SQLite authorization with realtime sampled after BEGIN; coordinator commit reservation and final executor cancellation check. | Exactly-once/concurrent redemption, revocation and expiry; deterministic cancellation before reservation, before COMMIT, and after durable COMMIT. |
| P4-03 | One bounded off-loop authorization/audit executor, with owned request/FD/RAM reservations retained through disposal. | Blocked durable I/O leaves sockets, deadlines and shutdown responsive; admission is bounded, disconnect cannot lose reconciliation, and no snapshot worker commits. |
| P4-04 | Authenticated serialized AUTH_COMMIT, post-commit abort, rejection and diagnostic records; poison on durable-write uncertainty. | Reopen/crash recovery after real acceptance and denial; injected persistence failure never retries or produces readiness. |
| P4-05 | Signed-warrant CLI input with exact immutable payload and explicit option compatibility. | Real binary signed redemption and replay; malformed/unsupported input rejected before connecting, no signed-field overrides or inherited environment. |
| P4-06 | Coordinator decisions and Phase 5 handoff boundary. | Required denial statuses/messages; no child before the later execution phase, no READY_TO_EXEC without child setup, and consumed grants never described as rolled back. |

Verification evidence:

- The Phase 3 namespace fixture drives approved requests through retained
  snapshot authorization and verifies `AUTH_COMMIT` followed by
  `AUTH_ABORTED_POST_COMMIT`, one-time SQLite consumption, and the explicit
  Phase 5 handoff status. Refusal, timeout, broker loss, and malformed
  approval paths append authenticated rejection records.
- SQLite tests cover lock-ordered realtime sampling, revocation, expiry,
  replay, rollback before commit, and cancellation after the commit
  reservation. Audit tests cover HMAC, sequence/host binding, recovery,
  poison-on-persistence-failure, bounded records, and atomic state publication.
- `sigrun --warrant PATH` validates and transmits the exact canonical signed
  payload; incompatible command-building options fail before connecting.
  Authorization runs on one bounded executor and retains worker leases and
  sealed snapshots until disposal.

The implementation must preserve all Phase 0–3 gates. The MVP remains local
audit only, with hooks, PTY, reload and remote ACK disabled. Phase 5 is required
for actual command execution; passing authorization does not establish a
successful child setup or permit an early readiness response.
