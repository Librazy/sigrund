# Phase 6 local Distrobox acceptance: partial, not passing

Tested implementation commit: `1f66ebd` (`fix(daemon): dispose control sockets
off the coordinator`). Kernel: `7.2.11-300.fc45.x86_64`. Environment: rootful
Podman `development` Distrobox, workspace requester UID/GID 1000, root approver
UID 0, and target service UID/GID 33. The container's systemd client is 259;
the host systemd manager is 262. This record supplements the earlier native VM
evidence; it does not replace that evidence or declare the current full gate
passing.

## Results

The fresh ordinary gate passed all eight checks in `scripts/check-mvp.py`:
build, workspace tests, Clippy, formatting, whitespace, Python compilation,
harness regressions and platform-fixture build. `checks.json` binds source
and binary digests to this run.

The last full local attempt is retained in `run/manifest.json`. Its overall
result is **failed**, with eight passing top-level gates:

| Gate | Result |
| --- | --- |
| Real platform / clone3 / cgroup / mount / credential operations | Passed |
| Runtime, reaping, shutdown, restart and service escalation | Passed |
| Failure/race suite, root-TTY approval, post-exec observations and tracing | Passed |
| Offline warrant workflow | Passed |
| Authorization binding and concurrent replay | Passed |
| Output, blocked-sink cancellation, memory and process limits | Passed |
| Failed job-limit setup / consumed grant / replay rejection | Passed |
| Synchronized partial-tail audit recovery | Passed |
| Complete packaged and foreground operator workflow | Failed at foreground service startup |

The retained Phase 5D manifest reports all 26 subgates passed. The operator
workflow also completed its packaged-service portion, including real root-TTY
approval/refusal, SSH signatures, an unprivileged requester, target UID 0 and
33, sealed executable replacement resistance, and hashed stdin. It did not
complete the foreground recipe, so it is not counted as a passing gate.

Blocked-output cancellation specifically returned exit 130 for SIGINT and
confirmed cleanup before draining output. This reruns the strengthened
cancellation assertion added after the earlier native VM evidence.

## Local execution adapter and failure isolation

The exact elevated command was:

```sh
~/.local/bin/pkexec-run -- /usr/bin/python3 /tmp/sigrund-phase6-local-1f66ebd/run.py
```

Each elevation received explicit operator approval under the
`distrobox-pkexec` skill. The root launcher uses the host system bus to create
a unique delegated systemd service with a ten-minute runtime ceiling,
15-second stop ceiling and whole-service cleanup. It enters the Distrobox
filesystem, creates a private mount namespace, retains a coherent host
cgroup2 view, and privately exposes host runtime-directory/notify endpoints.
The adapter enters that prepared view for host-managed daemon services and
maps only the uniquely named acceptance units' executable/condition paths.
It does not change host-wide mount propagation or production daemon state.

The repository's real `verify-mvp.py --inside` entry point runs the gates.
No acceptance assertions were replaced. The local wrappers are environment
adaptations, so this is not an unmodified native-host service-recipe result.
`local-adapter/` records the final launcher and wrapper for inspection; they
are machine-specific evidence, not a portable installer.

Initial adapter attempts corrected a missing recursive host-view bind and
systemctl's container/chroot handling. Those failures preceded successful
platform/runtime and packaged-service execution. The remaining foreground
failure occurs in `systemd-run`, before the daemon starts. Switching from the
container client to the host-native client did not resolve it.

A final bounded preflight reproduced the failure with `/usr/bin/true`, using
two fresh temporary services with ten-second limits and acceptance-supervisor
dependencies. Pipe-backed standard streams returned:

```text
Failed to start transient service unit: Connection reset by peer
```

File-backed standard streams returned:

```text
Failed to start transient service unit: Failed to set unit properties: Bad message
```

Both failures occur without invoking `sigrund`. `transport-preflight.json`
retains these observations. The launcher therefore stopped without another
acceptance repeat. The underlying systemd/D-Bus/descriptor transport cause
remains unresolved; a systemd version mismatch alone is not an established
explanation. The latest preflight's supervisor is recorded separately from
the last full acceptance attempt.

## Cleanup and evidence boundary

Every temporary supervising cgroup was removed. A final read-only systemd
query found no live acceptance/operator/Phase 5 service units; runtime socket
directories and container operator-lab directories were also absent. See
`cleanup.json`, `run/supervisor.json` and `transport-supervisor.json`.

Only check manifests, non-secret gate logs, the failure manifest, cleanup
observations and adapter source are copied here. The platform log omits its
terminal empty line for repository whitespace checks. Disposable SSH keys,
provisioning anchors, ratchet state and consumption databases are excluded.

## Dogfooding implications

The current daemon executes in its configured deployment context and can work
in this prepared rootful Distrobox arrangement. It does not discover or route
to a host/container destination, map arbitrary requester namespaces, or grant
host-root authority merely because a container requester is UID 0. The test
uses explicit host-systemd delegation and namespace entry outside the daemon.

Replacing routine pkexec requests is feasible after provisioning a separate
broker, root-owned policy/state, a root-TTY approver and signing identity, and
an explicitly authorized launcher. Keep that broker and the external systemd
cleanup/recovery path independent of test daemons that acceptance deliberately
kills. UID 0 does not restore capabilities that a warrant omitted. A signature
over a Python executable and script pathname also does not authenticate the
script bytes; a repeatable privileged launcher needs protected inputs or an
explicit content-binding contract.

No persistent dogfooding broker was installed by this test run. The unresolved
foreground systemd transport must be addressed before claiming a complete
local operator recipe. Cross-domain routing remains separate design work; see
[the execution-domain notes](../../INTERPRETERS_AND_EXECUTION_DOMAINS.md).
