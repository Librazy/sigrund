# Phase 2: client transport and common snapshots

Implement–Verify–Fix checklist (complete for the Phase 2 slice):

| Item | Contract | Evidence required |
| --- | --- | --- |
| P2-01 | ✅ Explicit requester options/defaults; exact argv, environment, cwd and canonical arrays; unsupported input rejected before connecting. | `phase2_options` covers defaults, overrides, duplicate/overflow/non-UTF-8 values and verifies the real binary exits before connecting. |
| P2-02 | ✅ Bounded nonblocking hello with rights on its first byte; strict server framing, status FD, exit and signal handling. | `phase2_client` covers fragmentation, backpressure, ancillary placement, malformed/state-invalid replies, denial, child exit, disconnect, signals and cumulative deadlines; `phase2_transport` verifies one-shot rights delivery under a full send buffer. |
| P2-03 | ✅ Separate pipe output relays with bounded buffering; sinks may block without blocking control or cancellation; drain through EOF after exit. | The namespace client fixture covers terminal and redirected output, large writes, a blocked sink, broken sink, readiness cancellation and EOF draining. |
| P2-04 | ✅ Same reserved worker and captured policy across descriptor validation, anchored source open, sealed executable/stdin snapshots and CSR construction. | The daemon fixture produces canonical CSRs for null, empty and binary stdin; preparation unit gates verify source/root identities, seals, offsets, digest bindings, source replacement isolation and quota release. |
| P2-05 | ✅ Signed requests verify a candidate signature and static ceilings before snapshots, then compare signed digests; no authorization or spawn. | Preparation unit gates build and verify an SSHSIG request, cover wrong namespace/key and host/peer/policy/root fields, and distinguish executable and stdin digest denials. |
| P2-06 | ✅ Coordinator CAS handoff within original deadline; stale completion cannot revive a cancelled request; retain quotas until actual off-loop disposal. | Existing Phase 1.5 worker/lifecycle gates plus daemon snapshot continuations cover deadline/cancellation and retained ownership; source operations run only on the reserved worker and all cleanup/quota probes pass. |

Focused gates were run after implementation and fixes. The workspace suite, the
user-namespace client and daemon gates, Clippy with warnings denied, formatting,
and whitespace checks pass on Rust 1.89. Phase 2 deliberately stops after CSR
and snapshot handoff: root prompting/signing, durable authorization, cgroup
execution and child reaping remain Phases 3–5. The client fake-server tests
prove framing and relay behavior, while the daemon fixture separately proves
the real snapshot/CSR path; neither claims authorization or child execution.
