# Phase 6: reproducible MVP acceptance and operator lab

Phase 6 packages and accepts the local `stdio` workflow. The requester and
approver use separate terminals and identities. Root confirms the complete
request and signs with a root-owned SSH key; the daemon executes the retained
snapshot and returns output and the primary child's status.

The executable verification entry points are `scripts/check-mvp.py` and
`scripts/verify-mvp.py`. The latter runs on a disposable systemd Linux host,
with a real unified cgroup v2 hierarchy and the required kernel operations.
It does not substitute a user namespace for the privileged execution gate.
Local privileged testing is deferred; acceptance runs in a disposable pvem
guest. The final result and non-secret artifacts are retained in
[`docs/evidence/phase6-2026-10-31`](evidence/phase6-2026-10-31/README.md), and
coverage is tracked in the [MVP coverage map](MVP_COVERAGE.md).

## Prerequisites and verification loop

Use a disposable native x86-64 Linux guest with a recent kernel, systemd,
cgroup v2 `memory` and `pids`, swap controls, `clone3`, `openat2`, executable
sealable memfds, `mount_setattr`, and the needed root capabilities. The daemon's
startup probe is the authoritative execution feature gate; missing features
fail the run. Install Rust >= 1.89 with Cargo/Clippy/rustfmt, a C compiler,
Python 3 with PyGObject (`python3-gi`), OpenSSH, strace, git, and uidmap tools.
The ordinary tests need subordinate UID/GID mappings for the build user and
permitted user-namespace creation. Keep the test guest's package trust and
mirror configuration; no package installation on the PVE host is needed.

For example, launch an existing Ubuntu 26.04 template with pvem, using one
work label for the run (consult the pvem skill for current limits):

```sh
pvem new sigrund-phase6 --distro ubuntu2604 --memory 4096 --cores 4 \
  --session sigrund-mvp-phase6 --purpose 'Verify sigrund Phase 6 MVP' --start
pvem ssh sigrund-phase6
```

Transfer a clean source checkout to the guest without `target`, secret files,
or local compiler settings. Build and check as its unprivileged workspace
user, then run the acceptance entry point as guest root. Create the requester
login once as root, or pass an existing ordinary login such as the pvem `lab`
account. Root, requester and target service UID 33 must be distinct.

```sh
# Unprivileged guest workspace user; all artifact paths must be fresh.
cd /absolute/sigrund
python3 scripts/check-mvp.py --artifacts /home/lab/phase6-checks-1

# Guest root only. sudo here is inside the disposable VM.
sudo -n /usr/bin/python3 /absolute/sigrund/scripts/verify-mvp.py \
  --checks /home/lab/phase6-checks-1/checks.json \
  --binaries /absolute/sigrund/target/debug \
  --requester lab --artifacts /home/lab/phase6-acceptance-1
```

`check-mvp.py` records build, full workspace tests, Clippy, formatting, diff
and Python syntax checks. It obtains the platform fixture's executable from
Cargo's JSON artifact output rather than guessing a filename. Source and
binary digests bind that evidence to acceptance; source or binary changes
require a new ordinary check directory.

`verify-mvp.py` checks prerequisites and creates one uniquely named delegated
supervising service with a ten-minute runtime ceiling, a 15-second stop
ceiling, and whole-service SIGKILL cleanup. Its runner moves into a leaf before
enabling `memory pids` in the newly delegated root. The existing Phase 5
runtime tests additionally create their own bounded transient services.
Only fresh fixture cgroups, units, processes and directories are changed.

The loop is implement, run ordinary checks, run VM acceptance, inspect the
first failed gate and retained logs, fix its cause, and repeat against a new
source snapshot and artifact directory. A failed or incomplete manifest is
never passing evidence. Inspect both `manifest.json` and `supervisor.json`:
the suite must pass and the supervising cgroup must be removed. The inherited
Phase 5D manifest, syscall traces, prompt/status files and per-fixture audit
logs remain available under the acceptance directory. Private SSH keys,
ratchet state, provisioning anchors and consumption databases are not exported.

## Manual setup

Run the manual lab in the disposable VM. The setup helper is not an installer:
it creates an isolated configuration and copies binaries without replacing
production paths. Choose a new path directly under a trusted root-owned
parent, for example `/var/lib`; symlink or writable ancestors are rejected.
Keep the lab path free of spaces and systemd specifier characters.

```sh
# Root, once, if a dedicated requester account is wanted.
useradd --create-home --shell /bin/bash mvp-requester

# Root; first build the binaries as the workspace user.
export TEST_REPO=/absolute/sigrund
python3 "$TEST_REPO/scripts/mvp-lab.py" prepare \
  --directory /var/lib/sigrund-mvp-demo \
  --binaries "$TEST_REPO/target/debug" --requester mvp-requester
source /var/lib/sigrund-mvp-demo/environment.sh
```

`environment.sh` defines every `TEST_*` path: base, daemon configuration,
signer policy, state, audit log, both sockets, private SSH identity, signer ID,
unit, runtime directory, copied binaries, native commands and requester login.
It is public and contains no key material. The setup pins one canonical
executable root containing native, memfd-compatible copies of `id`, `cat`,
`true`, `false` and `sleep`; it does not depend on distribution symlink aliases
or multicall executable naming. The exact executable content remains subject
to signing and snapshot checks.

A disposable root-owned software Ed25519 key is generated with no passphrase
for the lab. This supplies OpenSSH signing evidence, not physical FIDO
presence/verification evidence. An operational deployment should use its own
protected key/agent and reviewed signer policy.

The profile explicitly disables remote audit acknowledgements. Its required
collector URL, server name, public key and root-private file paths are present
and validated. The three collector files are clearly labelled inactive local
fixture placeholders, not usable TLS credentials. Before enabling remote
audit in a future implementation, replace them with actual provisioned and
registered collector credentials and complete that feature's acceptance gate.

## Start the packaged service or foreground recipe

For the service recipe, as root:

```sh
python3 "$TEST_REPO/scripts/mvp-lab.py" start --directory "$TEST_BASE"
python3 "$TEST_REPO/scripts/mvp-lab.py" status --directory "$TEST_BASE"
journalctl --follow --unit "$TEST_UNIT" --output=cat
```

The helper generates a uniquely named unit from `packaging/sigrund.service`,
substitutes the lab's paths, installs it only in `/run/systemd/system`, and
starts it. The packaged unit uses notification readiness, delegation,
`KillMode=control-group`, SIGKILL escalation, watchdogs and a stop timeout
longer than the default `shutdown_grace_ms`. Its sockets live in the managed
runtime directory, which is removed after forced death before service restart.
Production packaged sockets are `/run/sigrund/client.sock` and
`/run/sigrund/approve.sock`; use explicit socket options. Bare binary defaults
remain `/run/sigrund.sock` and `/run/sigrund-approve.sock`.

Alternatively, run this in **root terminal 1**, after stopping the service
recipe. `foreground` executes the exact `systemd-run --pipe --wait` command
with the same delegation, readiness, watchdog and cleanup properties. The
service manager owns the daemon and jobs even if the terminal disappears.

```sh
python3 "$TEST_REPO/scripts/mvp-lab.py" foreground --directory "$TEST_BASE"
```

In another root terminal, `mvp-lab.py status` prints and verifies `G`, the
service's actual delegated path discovered through systemd. It verifies the
`memory pids` subtree controllers and `supervisor`, `jobs` and `hooks` leaves.
Do not infer delegation from having a root shell, manually relocate an
existing service, or run both recipes at once.

## Root approval and requester invocation

In **root terminal 2**:

```sh
source /var/lib/sigrund-mvp-demo/environment.sh
"$TEST_BIN/sigrund-approve" --socket "$TEST_APPROVAL_SOCKET" --tty /dev/tty \
  --signers "$TEST_SIGNERS" --identity "$TEST_SSH_IDENTITY"
```

In a **separate requester login**, attached to a terminal:

```sh
source /var/lib/sigrund-mvp-demo/environment.sh
"$TEST_BIN/sigrun" --socket "$TEST_SOCKET" --cwd / \
  --status-fd 3 -- "$TEST_COMMANDS/id" -u 3>request.status.jsonl
printf 'client exit: %s\n' "$?"
```

Root sees indexed arguments and all signed fields, including requester/target
identities, exact environment, stdin binding, executable digest, validity,
host/grant/execution identities and signer fingerprint. Blank or `no` refuses;
only `y`/`yes` signs. Approval prints `0` on the requester terminal and returns
zero. Status JSON goes to the separate file, never the command's stdout.
The requester sees a waiting diagnostic on stderr before authorization.

A service-UID request and exact binary stdin can be demonstrated with:

```sh
python3 -c 'import sys; sys.stdout.buffer.write(b"\x00reviewed\xff\n")' > input.bin
"$TEST_BIN/sigrun" --socket "$TEST_SOCKET" --cwd / \
  --target-uid 33 --target-gid 33 --stdin sha256 --status-fd 3 \
  -- "$TEST_COMMANDS/cat" <input.bin >output.bin 3>input.status.jsonl
cmp input.bin output.bin
```

Root reviews the stdin digest before approving. Default stdin is `null`;
`sha256` reads bounded finite input through EOF. This profile has no unrestricted
input or remote child PTY. The local requester terminal works through pipe
relays. Interpreter approval still delegates programmable authority; a digest
alone does not authenticate mutable script paths or dependencies. Execution
uses the daemon's configured domain; see
[the interpreter/domain notes](INTERPRETERS_AND_EXECUTION_DOMAINS.md).

## Export, sign and redeem a pre-signed warrant

Stop only the approver with Ctrl-C. A new requester invocation now returns
`TIMEOUT_CSR` immediately with a canonical CSR in its separate status file;
no grant is consumed and no child runs. Capture a fresh request with sufficient
TTL, using the same requester login that will redeem it:

```sh
"$TEST_BIN/sigrun" --socket "$TEST_SOCKET" --cwd / --status-fd 3 \
  -- "$TEST_COMMANDS/id" -u 3>request.status.jsonl
# Expected authorization-denial exit 255.
```

Root then extracts the exact CSR and PAE, reviews every field, and signs:

```sh
"$TEST_BIN/sigrundctl" csr-pae --status /home/mvp-requester/request.status.jsonl \
  --csr "$TEST_BASE/request.csr" --pae "$TEST_BASE/request.pae"
python3 -m json.tool "$TEST_BASE/request.csr"
# Inspect all fields above before signing; no automatic approval is implied.
ssh-keygen -Y sign -n sigrun.warrant.v1 -O hashalg=sha512 \
  -f "$TEST_SSH_IDENTITY" "$TEST_BASE/request.pae"
"$TEST_BIN/sigrundctl" pack-warrant --csr "$TEST_BASE/request.csr" \
  --signature "$TEST_BASE/request.pae.sig" --signer-id "$TEST_SIGNER_ID" \
  --output "$TEST_BASE/request.warrant.json"
chmod 0644 "$TEST_BASE/request.warrant.json"
```

These tools never reconstruct signed fields. `csr-pae` accepts exactly one
`TIMEOUT_CSR` status record and validates its canonical CSR. `pack-warrant`
decodes armored SSHSIG into binary signature bytes, verifies the exact
payload, namespace and hash algorithm, and creates the DSSE envelope. The
daemon independently verifies configured signer trust, policy, requester,
expiry, executable/stdin bindings and replay state. Outputs use new private
files and refuse overwrite. Packaging is not authorization.

Back in the original requester login:

```sh
"$TEST_BIN/sigrun" --socket "$TEST_SOCKET" --status-fd 3 \
  --warrant "$TEST_BASE/request.warrant.json" 3>redeem.status.jsonl
# Repeat the identical invocation: REPLAY_DETECTED, exit 255, no second child.
```

Redeem before the original validity expires. Approval/export waiting does not
refresh the expiry. A new request needs new output filenames and fresh
approval; never edit the CSR to make an old signature fit.

## Recovery and cleanup

`READY_TO_EXEC` confirms completed setup, with exec outcome unknown. A later
exec/setup failure can consume a one-time grant permanently. After a lost
connection or shutdown during commit/spawn, the command outcome can be
uncertain. Inspect the separate status records, audit entries by execution and
grant ID, and the retained consumption database before obtaining fresh approval.
Do not automatically replay a command, delete consumption records, re-provision
host state, or promise exactly-once external effects after VM restoration.

Storage pressure closes admission. Stop the service, inspect diagnostics and
the log/state filesystems, free unrelated disk space or expand storage, and
increase the root-reviewed audit high-water bound if the intact log has reached
it. Restart to revalidate capacity and recover the authenticated log/state pair.
Keep host identity, the full audit history, ratchet state, `state.sqlite` and
its SQLite sidecars together. No log truncation/rotation or state rollback is
an approved remediation. Local audit retains the initial ratchet key and does
not provide forward secrecy after root compromise or whole-state rollback
protection; external collector/checkpoint work remains deferred.

```sh
# Root; works for either recipe. State and signing material are preserved.
python3 "$TEST_REPO/scripts/mvp-lab.py" stop --directory "$TEST_BASE"
```

Verify the unit, runtime sockets and service cgroup are gone. The helper removes
only its uniquely named temporary unit. Preserve the lab directory for review;
its key/state/anchor are private and must not enter shared artifacts. The
acceptance harness automatically deletes its own disposable secrets after
retaining non-secret evidence. After collecting VM evidence, destroy only the
pvem-tagged guest created for this work, using `pvem destroy <name> --yes`.

## Recorded acceptance

The final acceptance repeat, including the watchdog deadline correction and
umask-independent collector fixture repair, passed on 2026-10-31 in pvem guest `sigrund-phase6`
(VM 9012), Ubuntu 26.04 with kernel `7.0.0-34-generic` on x86-64. The
ordinary unprivileged checks and the root delegated acceptance service both
passed. The manifest records platform, runtime, failure/race, offline warrant,
binding/replay, output/limits, post-commit failure, audit recovery, and
operator-workflow gates as `passed`; the supervisor reports
`cgroup_removed: true`.

The operator gate used requester UID 1002, root UID 0, and target service UID
33. It exercised root-TTY approval and refusal, real OpenSSH signing, separate
terminal output and status, hashed stdin, packaged and foreground service
recipes, restart, and cleanup. The guest needed
`kernel.apparmor_restrict_unprivileged_userns=0` for its unprivileged namespace
credential fixture; that setting was confined to the disposable guest. See
[`docs/evidence/phase6-2026-10-31/README.md`](evidence/phase6-2026-10-31/README.md)
for the command, manifest and artifact boundary.
