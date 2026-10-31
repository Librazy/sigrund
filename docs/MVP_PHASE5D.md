# Phase 5D: real execution failure and race verification

The executable gate is prepared in `scripts/verify-phase5-failures.py`.
It has not yet run on the delegated host. Phase 5D remains incomplete until
that gate and the Phase 5A–5C gates pass together. Syntax/compilation checks
and the unprivileged child/reaper tests do not establish privileged acceptance.

The harness uses production daemon/client/approver binaries, disposable software
SSH keys, root-owned temporary configuration/state and isolated job cgroups.
Faults live only in a separately compiled `execution_gate.c` interposer; the
production daemon has no environment-controlled test switches. The C setup
fixture also exposes a post-exec observation mode, preserving its existing
assertions and reporting actual kernel-read credential, capability, namespace
mount, session, FD and signal observations as JSON.

## Reproduction

Build and run the ordinary regression gates as the workspace user:

```sh
cargo build --workspace --locked
cargo test --workspace --locked -- --test-threads=1
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo fmt --all -- --check
git diff --check
```

Run the Phase 5A/5B fixture using the recipe in [MVP_PHASE5A.md](MVP_PHASE5A.md),
then the Phase 5C runtime and `--systemd` service gates in
[MVP_PHASE5C.md](MVP_PHASE5C.md). In the same prepared, coherent cgroup v2
environment, under a separate dedicated delegated root service with a final
180-second deadline and whole-service cleanup, run:

```sh
python3 /absolute/repository/scripts/verify-phase5-failures.py \
  --cgroup-parent /absolute/prepared/delegated/service \
  --binaries /absolute/repository/target/debug \
  --strace /absolute/path/to/strace \
  --artifacts /absolute/fresh/artifact-directory
```

The parent must already enable `memory pids`; the supervisor occupies a separate
leaf. The gate creates and removes only fresh fixture subgroups. It requires
`cc`, OpenSSH, Python, a runnable `strace`, and permission to trace its own root
daemon. A missing prerequisite fails the gate. It does not skip tracing or
replace the real cgroup/credential execution path with namespace-only tests.
Use a fresh artifact directory for each attempt, including failed attempts.

The controlled root TTY is a new foreground PTY owned by the fixture's root
approver, never an operator's existing terminal. The harness submits `no` and
`yes` only to prompts for its own disposable requests and key. It executes a
private native copy of `id`, since distributions can make `/usr/bin/id` a
symlink rejected by executable resolution. The root approval test runs the
unsigned client as UID 65534 and verifies that approved `id -u` runs as UID 0,
prints `0`, and returns status zero. This supplies execution evidence for the
user story; Phase 6 still owns the packaged operator walkthrough, full fixture
interface and additional user-story cases. No physical FIDO evidence is claimed.

## Required observations

Every row below is prepared and pending delegated-host verification.

| Gate | Required evidence |
| --- | --- |
| Missing startup support | Missing swap control, unavailable clone3 and unavailable mount_setattr reject startup with status 78 before either listener is published. |
| Setup steps 1–10 | A real clone enters the production child transition; a selected syscall fails with EIO, only SPAWN_FAILED is sent, and EXEC_SPAWN_FAILED identifies the step. |
| Descriptor exhaustion | A real cloned child exhausts its own descriptor limit before FD installation and reports step 1/EMFILE through its valid sync writer. The existing 32-mask/sentinel matrix additionally checks inherited FD 4 safety. |
| Exec error | Both injected execveat failure and a real kernel ENOEXEC after ELF snapshot acceptance produce SPAWN_FAILED and no child-exit frame. |
| Readiness framing/deadline | Pre-token kill, partial/excess evidence, and stopped children before/after the token fail closed. Both stopped cases retain the original two-second readiness deadline. |
| Post-token/pre-exec kill | Complete token plus EOF gives READY_TO_EXEC with exec_outcome unknown, followed once by signal 9. No success-of-exec claim is made. |
| Consumption after failure | Reusing the exact envelope after every post-commit failure yields REPLAY_DETECTED. |
| Root-TTY workflow | Real unsigned unprivileged client, root refusal/confirmation, OpenSSH signature, UID 0 execution, separate status records and exact exit status. Refusal consumes no grant. |
| Control and exit races | Concurrent true/false children preserve independent statuses; every allowed signal reaches a running job; forbidden signal, wrong frame type, ancillary rights and partial-frame timeout close controls and kill/reap jobs. An idle control socket survives five seconds without starting a frame deadline. |
| Actual execution state | UID 0/33 with empty/nonempty capabilities report saved/real/effective IDs, groups, P/E/I/bounding/ambient sets, securebits, no_new_privs, umask, cwd, session and mount flags. FD and signal assertions run inside the executed program. |
| Client I/O and disposal | Exact binary hashed stdin reaches cat; id/true/false return exact statuses through the real client; status JSON stays separate from output; all job cgroups and request/pidfd descriptors return to baseline. |
| Syscall trace | A real strace attachment records clone3 placement, namespace/mount operations, credential setup, execveat and pidfd-based central reaping. |

`manifest.json` records the command, platform/kernel, binary SHA-256 digests,
each completed gate and final status. Each fixture preserves its audit and
diagnostics plus cgroup/process observations before cleanup. The root-TTY case
preserves prompts and separate status records; the post-exec case preserves
kernel observations and per-thread/process syscall traces. An incomplete or
failed manifest is not acceptance evidence. Disposable private SSH keys and
ratchet keys are never copied into the artifacts.

## Traceability and remaining scope

M-08 combines these failures, exact exits and post-token death with Phase 5C's
real unpublished-child registration barrier. M-14 combines Phase 5C's blocked
cleanup/durable-failure shutdown with the ordinary metadata, FD, snapshot,
rejection-audit and storage-pressure gates from Phases 1.5/4/4.5. M-15 combines
the real startup failures and post-exec state observations with Phase 5B's
syscall/FD fault matrix and the delegated Phase 5A/5B platform fixture.

This remains thin-MVP coverage of the corresponding V-06/V-08/V-10/V-11/V-15/
V-17 subcases. PTY, hooks, reusable grants, remote collector ACKs, reload and
the complete V-01–V-19 stress matrix remain later work. All acceptance statuses
stay pending until the recorded real gates prove the requirements above.
