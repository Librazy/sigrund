# Phase 5C/5D acceptance evidence — 2026-10-31

Real Linux execution was tested in temporary delegated systemd services on
kernel `7.2.11-300.fc45.x86_64`, inside the development container's private
mount view. Both approved launchers reported service success/status 0 and
final service cgroup removal. The ordinary workspace suite, Clippy, formatting
and diff checks also passed. Phase 6 packaging and full-spec conformance are
separate milestones.

- [Phase 5C results](phase5c-result.json): all 13 gate/point results from the
  expanded runtime/service launch. This is a transcription of captured tool
  output, with provenance identifying the raw root-owned launcher log. It is
  not presented as a daemon-generated manifest.
- [Phase 5D manifest](phase5d-manifest.json): original machine-written command,
  kernel, binary digests, 26 passed gates and observations. The same launch
  repeated the Phase 5A/5B platform fixture: 1 passed, 0 failed.
- [Post-exec observations](post-exec-observed.json): original kernel-read IDs,
  groups, capability sets, securebits, no_new_privs, umask, cwd, session,
  mount flags and FD/signal checks for all four UID/capability combinations.
- [Syscall excerpt](syscalls-excerpt.log): selected actual clone3, execveat,
  waitid, mount and credential calls, prefixed with their original trace names.
- [Complete Phase 5D artifact archive](phase5d-artifacts.tar.gz): 129 original
  files, including all 43 syscall traces, per-fixture audit/diagnostic output,
  prompts, separate status records and process/cgroup observations. Its SHA-256
  is `3f39c34cd2712b9c9df87b868a6dcbda7f2ed2e0ddb7bdfde4e603cab6da7210`.

The archive contains fixture outputs only: no private signing keys, ratchet
keys, databases, or host identity/state files. List it with
`tar -tzf phase5d-artifacts.tar.gz` and extract into a fresh directory when
reviewing the full traces. Temporary paths, PIDs, timestamps and host IDs
identify that run and are not stable values for subsequent executions.

The original Phase 5D artifact directory was
`/tmp/sigrund-phase5-failures/sigrund-phase5-failures-5f2969a847384549ac44b2293391c7bf.service-artifacts`.
The test command, fixture setup, scope and limitations are documented in
[Phase 5C](../../MVP_PHASE5C.md) and [Phase 5D](../../MVP_PHASE5D.md).

The privileged workflow used the explicitly approved
[distrobox-pkexec skill](/var/home/librazy/.agents/skills/distrobox-pkexec/SKILL.md).
Its authentication prompt ran in the operator's TTY waiter. These results
do not grant permission for another elevation.
