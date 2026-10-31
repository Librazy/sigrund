# Phase 6 acceptance evidence

The Phase 6 MVP gate passed on 2026-10-31 in the disposable pvem guest
`sigrund-phase6` (VM 9012), Ubuntu 26.04, kernel
`7.0.0-34-generic`, x86-64. The final run used a distinct unprivileged
workspace user, requester UID 1002, root UID 0, and target service UID 33.

The final repeat includes commit `f1a0530` (watchdog-aware epoll deadlines)
and the fixture correction that restores collector placeholder permissions
after testing a missing file, independently of the guest caller's umask `0002`.

The ordinary gate was run as the unprivileged workspace user and passed build,
workspace tests, Clippy with warnings denied, formatting, diff, Python syntax,
and the platform-test build. The root acceptance command was:

```sh
sudo -n python3 scripts/verify-mvp.py \
  --checks /tmp/phase6-checks-k785z7ah/fixed/checks.json \
  --binaries /home/lab/sigrund-phase6-current/target/debug \
  --requester mvp-requester \
  --artifacts /var/tmp/sigrund-phase6-current-acceptance
```

The manifest records `result: passed`, all nine gates passed, and the
supervising systemd cgroup reported `cgroup_removed: true`:

- real delegated Phase 5 platform and runtime gates;
- setup-failure, race, syscall-trace and root-TTY failure gates;
- offline CSR/PAE/SSHSIG packaging and one-time replay;
- signed-field mutation, concurrent replay, UID and stdin binding;
- separate stdout/stderr/status, large output, OOM and pids limits;
- post-commit job-limit failure and replay consumption;
- synchronized partial-tail audit recovery; and
- packaged service plus foreground recipe with root approval, refusal,
  service-UID execution, hashed stdin, restart and cleanup.

The guest required `kernel.apparmor_restrict_unprivileged_userns=0` for the
unprivileged namespace credential fixture; this change was confined to the
disposable VM. No private key, ratchet state, provisioning anchor or SQLite
consumption database is included here. `run/manifest.json` and
`run/supervisor.json` are the authoritative result files; the copied
`run/ordinary-checks.json` binds the acceptance to the ordinary check set.

The ordinary source digest is
`5073e21a9a77033f1281baf9a442f3f46ac688f67796471a7384f1cf0d0a49c0`.
A separate ordinary check set on the development workstation passed against
the same digest. The VM gate finished successfully in 37.603 seconds; its
service and cgroup were absent after cleanup. Documentation and evidence-only
edits after acceptance do not change the checked runtime/build-input digest.

Terminal prompt transcripts are rendered as LF-delimited review text with
trailing prompt spaces removed. Audit JSONL, signed CSR/PAE/SSHSIG artifacts,
status records and manifests retain their original bytes.

The tagged disposable guest `sigrund-phase6` (VM 9012) was destroyed with
`pvem destroy sigrund-phase6 --yes` after evidence collection and successful
service/cgroup cleanup. No local privileged test was run.

Phase 6 deliverable audit:

| Requirement | Current evidence |
| --- | --- |
| Isolated root approver and separate requester, exact command/status | `operator-workflow` prompt, terminal and status artifacts; requester 1002, root 0, service UID 33 |
| Valid provisioning/configuration, executable roots and inactive collector settings | `scripts/mvp-lab.py prepare`; `operator-workflow` service and successful startup |
| Packaged/foreground delegation, watchdog and cleanup | `operator-workflow` with both recipes; repeated `runtime` gate; `supervisor.json` |
| Exact offline CSR, DSSE PAE and SSHSIG packaging, redemption/replay | `offline-workflow` signed artifacts and audit; ordinary `phase6_tools` tests |
| Binding, binary stdin, separate output, signal/exit, limits and races | `binding-and-concurrent-replay`, `output-and-enforced-limits`, repeated platform/runtime and all 26 failure gates |
| Recovery, retained consumption, pressure and interruption | `synchronized-partial-tail-recovery`, `failed-job-limit`, repeated runtime poison/restart tests and ordinary Phase 4/storage-pressure tests |
| Copyable operator walkthrough and safe cleanup/recovery instructions | `docs/MVP_PHASE6.md`; tested `mvp-lab.py` service/foreground recipes |
| Scope and traceability | `docs/MVP_COVERAGE.md`; full v1.0 features remain explicitly deferred |
