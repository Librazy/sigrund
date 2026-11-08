# Phase 2 review resolutions

All 13 supplied findings were valid. The fixes preserve the private no-spawn,
no-consumption boundary and the public admission-based TIMEOUT. Changes are
organized around capture validation, preflight authority, bounded ownership and
qualification reporting.

| Finding | Resolution |
| --- | --- |
| Spoofed proc status fields | All three parsers match complete line prefixes and consume validated numeric fields. A native production-parser fixture installs a filter that falsely succeeds at unshare, sets misleading task names, and verifies the real proc values. Production capture rejects the filtered spoofed anchor. |
| Authority after destination access | Static daemon/signer scopes and common ceilings run before helper work. Numeric selection is checked immediately; named resolution uses a two-stage private exchange whose policy acknowledgement precedes executable/cwd access. |
| Device open side effects | Account and executable sources are pinned with O_PATH and checked as regular before readable reopening through the retained procfd. Symlink and executable mount-crossing restrictions remain. FIFO and device controls are rejected. |
| Long global reaper barrier | Destination helper pidfds are acquired under the short spawn barrier. Subsequent signaling, waiting and actual exit observation use pidfds, including coordinator-reaped children. |
| Filesystem operations on sequencer | The approval worker performs final namespace evidence checks. A privileged interposer pauses actual destination statx after approval while a separate signed host job still commits and exits. The sequencer accepts only its private verification marker and performs lifecycle checks before the unconditional Phase 2 denial; it never performs destination stat/hash/capture IPC. |
| Blocking management disposal | A bounded disposal queue retains retired generations and charges. Acquisition and failed-acquisition disposal run on a persistent bounded worker, preserving PDEATHSIG lifetime. Pending/listener anchor sockets use bounded off-loop disposal with charges held through actual close. These workers exist only when namespace profiles are enabled. Management continues revocation and lifecycle monitoring. A blocked-close regression revokes a second target before releasing the first. |
| Interrupted capture exchange | Every command retires the stream until its complete validated response is consumed. Timeout/cancellation/error leaves it permanently invalid; later requests cannot consume old acknowledgements or rights. |
| Root mount identity omitted | Transferred roots are checked against complete device/inode/mount ID. C root/cwd equality and root revalidation also include mount IDs. |
| Cwd slash rejected | Slash duplicates the pinned root directly; tests cover slash, nested cwd and traversal rejection. |
| Pending rendezvous monopolization | Pending sockets are limited to four per authenticated UID, below the global sixteen, and disconnected peers are removed. A sixteen-connector flood from one UID leaves another owner able to register. |
| Root ordering mismatch | Returned roots are compared by exact count and membership, preserving configured PathBuf order for indexed FD retrieval. |
| Delayed H handshake | Nonblocking handshake reads retry EINTR/EAGAIN under the existing acquisition deadline. A producer wrapper delays H after connection; registration still succeeds. |
| Cleanup failure exits zero | Final evidence is saved before failed qualification raises. Ordinary harness tests cover both cleanup failure and successful private evidence publication. |

Historical Phase 0 and Phase 1.5 sources and fixture bytes remain unchanged.
Production regressions are exercised on a disposable Fedora guest; ordinary
checks include workspace tests, Clippy, formatting, Python harness tests and
independent host/namespace vectors. The original qualification record remains
historical evidence for its named source digest.

The follow-up validation uses the complete checked source snapshot and matching
production/test binaries. Native capture checks run on Fedora 44 x86-64 in a
disposable systemd guest, with enforcing SELinux and delegated cgroup v2.
The test harness adds real filtered-name spoofing and delayed-handshake cases,
a per-UID rendezvous flood, and blocked destination-stat and anchor-close cases.
The Phase 2 no-execution boundary remains explicit in all cases.

## Verified results

The [sanitized follow-up evidence](evidence/namespace-phase2-reviewed-20261108.json)
records the exact source/build, commands and results. All 11 ordinary checks pass
with 195 Rust passes and 32 Python harness tests. All 25 production namespace
gates and all 23 host acceptance gates pass, including nine privileged Rust,
seven trust and 26 execution gates. Device rejection and its regular-file control
also pass under actual syscall tracing. Namespace approvals still consume no
grant and spawn no workload.

Final source SHA-256: `3307b800f578b1ad562e128dba650581f32397126726cda5f6e25548972429e8`.
The namespace, host and ordinary manifests match this source and the exact same
production and privileged-test binary hashes. Raw private artifacts are retained
under `/var/tmp/sigrund-phase2-review-evidence`. Both supervisors verified cleanup,
and the disposable qualification guest was destroyed. The initial Phase 2
qualification remains a historical snapshot and is superseded by this record.

Commands:

```sh
python3 scripts/check.py --artifacts /var/tmp/sigrund-phase2-review-complete-checks
# On the disposable Fedora guest, as root:
python3 scripts/verify-namespace-phase2.py --owner lab \
  --binaries /home/lab/sigrund-phase2-review/bin \
  --artifacts /var/lib/sigrund-phase2-review-complete
python3 scripts/verify-acceptance.py --requester lab \
  --binaries /home/lab/sigrund-phase2-review/bin \
  --checks /home/lab/sigrund-phase2-review/checks.json \
  --artifacts /var/lib/sigrund-phase2-host-complete
```
