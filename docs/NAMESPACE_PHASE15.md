# Namespace-aware execution Phase 1.5

This milestone supplies an exercised operator workflow, a reusable native
rootless-container fixture and shared production v3 wire contracts. The
registration and destination review run in an isolated fixture using the frozen
G-01/G-05 records. The installed clients expose the Phase 1 host workflow.
Production registration and destination preparation are Phase 2 deliverables,
and container workload execution follows in Phase 3.

## Operator recipe

Use a disposable x86-64 Linux host with systemd, a unified cgroup v2 hierarchy,
working memory/pids delegation and permitted unprivileged user namespaces.
Install a C compiler, static glibc, Python 3, util-linux, shadow's `newuidmap` and
`newgidmap`, OpenSSH tools and the usual host acceptance dependencies. Select a
real unprivileged owner with subordinate UID and GID ranges containing at least
65535 IDs. The exercised Fedora owner is `lab`, host UID/GID 1000, with
`lab:524288:65536` in both `/etc/subuid` and `/etc/subgid`.

Build and check the repository as the workspace user. Run the fixture as host
root from that checked tree on the disposable host. Choose a new artifact path
for each run. Its existing parent and every ancestor must be root-owned,
non-symlink directories without group or other write permission. The runner
checks that requirement before creating artifacts and again inside the supervisor.

```sh
python3 scripts/check.py --artifacts /tmp/sigrund-phase15-checks
# On the disposable host, as root, with the matching built binaries available
python3 scripts/verify-namespace-phase15.py \
  --artifacts /var/lib/sigrund-phase15-evidence \
  --binaries /absolute/path/to/target/debug --owner lab
```

The runner creates one independently bounded systemd service, with memory and
process ceilings, a 180-second runtime limit and whole-service shutdown. It
creates a private artifact directory and a unique `/run/sigrund-p15-*` fixture.
Host root owns each minimal root and its populated directories. The selected
owner launches a native rootless
container using the following command shape, with supplementary host groups
cleared before entry.

```sh
setpriv --reuid=1000 --regid=1000 --clear-groups \
  unshare --map-auto --map-root-user --mount --cgroup --ipc --net --uts \
  --time --pid --fork --kill-child --mount-proc --root /run/THIS-RUN/B1 \
  /anchor init /run/capture.sock
```

These paths and IDs are supplied by the runner. Its static PID-1 fixture forks a
dedicated single-threaded anchor inside B. The root capture process creates the
rendezvous socket before that launch. The socket has mode 0600 and the selected
host owner UID, with traversable fixture ancestors. B is running before the
administrator assigns its registration label and revision.

The host capture process authenticates the connector with `SO_PEERCRED`,
`SO_PEERPIDFD`, `SO_PEERGROUPS` and available peer LSM information. It applies the
frozen G-01 syscall-entry/exit capture from the Phase 0 probe, checks initialized
mapping ancestry and namespace ownership, and retains proc, root, cwd, namespace,
owning-userns and pidfd references. It holds the anchor at the successful
`unshare(CLONE_FS | CLONE_FILES)` syscall exit until disposal. The capture seizes without `EXITKILL`, stops the process, and verifies the
original connector pidfd before enabling `EXITKILL`. Host root needs
permitted ptrace and procfs access in the initial user namespace, including
applicable LSM and Yama permission. The fixture exercises attachment with
`CAP_SYS_PTRACE` removed and records the resulting `EPERM`.

The tested map is destination `0 -> host 1000`, then destination `1..65535 ->
host 524288..589822`, for both UIDs and GIDs. Destination service UID/GID 12001
therefore maps to host 536288. The observed `setgroups` state is `allow`, with
empty inherited supplementary groups. On util-linux 2.41.3, adding explicit
`--setgroups=deny` to this automatic subordinate-mapping command failed with
`Operation not permitted`. The recorded recipe uses its observed mapping state.

The rootless topology has one child user namespace whose parent is the initial
user namespace. Every selected non-user namespace belongs to that child.
A negative case shares the host time namespace, and acquisition rejects its
mismatched owning user namespace. Nested and other mixed-ownership deployments
retain the Phase 0 qualification restrictions. Manager-created environments
require their own acquisition qualification.

## Registration, private review and lifecycle

The root runner's `FixtureRegistry` exercises the G-05 register/revoke contract.
It allocates a random 256-bit revision, binds a live owner to the fixture epoch
and UUIDv7 instance, and records an administrator-declared owner and immutable
profile digest. A pending review retains that generation's acquisition and
registration hashes. The fixture supplies these artifacts with mode 0600.

| Artifact | Meaning |
| --- | --- |
| `registration.json` | Operator label, fresh revision, daemon-scope anchor PID, declared host owner and requested profile hash |
| `acquisition.json` | Observed epoch/instance, boot/PID/start identity, held capture, root/cwd, namespaces, mapping ancestry and lifecycle dependency |
| `constraints.json` | Complete requested frozen constraints, including LSM, seccomp, executable model and checkpoint obligations |
| `review.private.json` | Validated private review with declared label/owner, complete observed records, resolved fixture credentials and measured file evidence |
| `replacement-*.json` | Fresh generation while the original anchor survives |
| `after-death-*.json` | Fresh generation after the preceding anchor exits |
| `host-outcomes.private.json` | Real host public decisions and private audit records joined by execution ID |
| `*.stderr`, `supervisor.private.log` | Capture, container and supervisor diagnostics |
| `evidence.json` | Platform, commands, source/binary hashes, case results and cleanup observations |

The fixture's `sigrund-phase15-review` renderer validates the exact acquisition,
registration and constraints records before producing output. Wrong PID,
revision or profile inputs produce no review. The display identifies the
operator label and administrator-declared owner separately from the observed
process environment. Complete namespace identities, mappings and constraints
remain visible. Requested confinement describes the prospective executor's
obligations. The fixture qualifies acquisition and review behavior.

B has `phase15_service` in its bounded account files at destination UID/GID
12001 with empty groups. That account is absent from the host. The fixture
builds distinct runnable static ELF files at the same absolute pathname on host
and in B, and creates different cwd markers at the same destination path. It
reads B's files through the retained anchor root and records both executable
hashes and the destination cwd marker. These assets establish the expected
account/path/cwd observations for the Phase 2 and Phase 3 tests.

Replacement exercises both lifecycle outcomes. A surviving old anchor keeps its
binding to the old environment until the administrator revokes its revision.
The administrator then registers B's replacement with a fresh instance and
revision. The earlier pending review fails authorization. When an anchor dies,
its pending review becomes invalid even while retained FDs still exist, and a
new same-name registration cannot revive it. Unit regressions additionally bind
profile and declared-owner changes to the pending review.

Without a manager lifecycle signal, operators must revoke the old registration
when retiring or replacing its environment. A label conveys the administrator's
selection. Captured kernel evidence identifies the retained process environment.
The root capture owner kills and reaps the dedicated anchor, then closes every
retained FD. B's PID 1 reaps its anchor and exits, and `unshare --kill-child`
provides a further lifetime boundary. The runner verifies restored FD counts,
container exit and removal of its fixture paths. The external supervisor verifies
that its service is stopped and its cgroup is empty before reporting success.

For the host workflow, the runner explicitly refuses a thin request, observes
its scheduled generic `TIMEOUT`, and locates the private outcome by the returned
execution ID. A separate validated full CSR receives immediate `REJECTED` on
explicit refusal. Neither case commits authorization or produces workload
output. Root operators can use the same execution-ID correlation with the
existing private audit/diagnostic paths.

## Production schema consolidation

`v3::Hello` owns the public hello serialization and validation used by both the
client and daemon. `protocol::ClientHello` adapts it into internal preparation
fields. `ResolvedIntent` represents that internal numeric view, and `v3::Intent`
retains the complete original selection used for signed hashes and private
provenance. Canonical warrant parsing and DSSE parsing use the production
validators across both entry points.

`v3::PublicContext`, `ContextFeatures` and `ContextQuery` are shared through
protocol re-exports. The client validates public preparation limits and features
with the same contract validator. Enabled model policy and checkpoint probe
availability remain separate inputs so an unavailable local preparation path
can reach the existing thin fallback. ComposeFS enrollment travels from the trusted
host binding as an explicit private evidence-preparation input.

Regression tests round-trip production thin, full and signed paths against the
existing canonical data and compare original intent hashes. They reject version,
TTY and caller-environment substitutions, duplicate/unknown keys and private
preparation data in public context. Historical Phase 0 vectors retain their
original bytes.

## Validation record

Completed on 2026-11-07 for the recorded native rootless topology. The
[sanitized evidence](evidence/namespace-phase15-20261107.json) records the exact
commands, source and binary hashes, individual gates and cleanup results.
Raw manifests, the complete private review and execution-ID diagnosis examples
are retained in `/var/tmp/sigrund-phase15-reviewed-evidence` on the development host.

All 11 ordinary checks passed with 177 ordinary Rust test passes and 30 Python
harness tests. The eight rootless fixture gates passed, including attachment
permission denial, mixed namespace ownership rejection, both replacement
lifecycles and actual cleanup. The complete Phase 1 acceptance entry point passed
all 23 gates, including nine privileged Rust gates, seven trust gates, 26
execution gates, real root approval, offline signing/redemption, digest equality,
recovery and shutdown. The final source SHA-256 is
`dfa25007511de666ada998d75a369e60fc8a5483ff72d7e6108ff5303ffb2542`.

Ordinary checks ran as the workspace user with Rust/Cargo 1.99.1. Qualification
ran on Fedora 44 x86_64 with kernel `6.19.10-300.fc44.x86_64`, enforcing SELinux
and an administrative unconfined supervisor. Matching production and test
binaries were copied from the ordinary build, with their embedded build paths
mapped to the guest checkout. Source and binary digests match the checked tree.
The host acceptance supervisor removed its cgroup, and the rootless fixture
supervisor was stopped and empty after disposing its anchors and files. The
disposable qualification guest was removed after preserving the private artifacts.

The executed commands were

```sh
python3 scripts/check.py --artifacts /var/tmp/sigrund-phase15-review-checks
# On the disposable Fedora guest, as host root
python3 scripts/verify-namespace-phase15.py \
  --artifacts /var/lib/sigrund-phase15-reviewed \
  --binaries /home/lab/sigrund-phase15/bin --owner lab
python3 scripts/verify-acceptance.py \
  --binaries /home/lab/sigrund-phase15/bin \
  --checks /home/lab/sigrund-phase15/checks.json \
  --artifacts /var/lib/sigrund-phase15-host-reviewed --requester lab
```

The schema consolidation initially exposed the shared validator's rejection of
configured direct models when their checkpoint probe was unavailable. The
regression test now preserves separate model eligibility and probe availability,
and the real privileged approver gate passes. Historical Phase 0 records and
vectors retain their original contents.

Production registry and destination preparation remain assigned to Phase 2.
Phase 3 owns workload execution in B, and Phase 4 owns each deployment's enforcing
confinement qualification. The acquisition fixture does not qualify those gates.


## Review corrections

Host root retains ownership of the fixture filesystem throughout acquisition and
review, protecting its account files, executable and cwd from owner-controlled
path replacement during privileged writes. Artifact directories require a
root-controlled parent and ancestry, checked before creation and inside the
supervisor. The runner reuses the operator lab's existing directory validator.

The G-01 capture verifies the original connector pidfd after seizing and stopping
the candidate, then enables `EXITKILL`. A deterministic stale-peer gate supplies
a dead original pidfd with an unrelated live PID and verifies that the unrelated
process survives tracer exit. Frozen Phase 0 probe contents retain their original
bytes.

Public context accepts independently configured positive TTL and one-time-window
ceilings, with a regression for a 600-second TTL and 3600-second window.
Destination executable evidence uses one captured-root byte observation for its
comparison and digest. Thin timeout measurements start at submission, while the
full-CSR refusal measurement starts at refusal.
