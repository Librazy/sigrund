# sigrun / sigrund

[MIT licensed](LICENSE).

Signed command elevation for Linux. An unprivileged user requests a command;
a root operator reviews it on their own terminal and signs it with an SSH key.
The daemon verifies the signature and policy, records the authorization,
executes the command, and returns its output and exit status to the requester.

The local **v3 host** profile supports private thin intent and client-generated
full CSRs, bound to a live daemon epoch, exact numeric credentials and an
immutable security profile. Phase 2 adds registered process environments and
private destination preparation/review. Phase 3 adds opt-in experimental native
execution for registered/process and authenticated self targets, with an actual
final-child exec checkpoint. Historical namespace preview profiles retain their
scheduled TIMEOUT without consumption or execution. Phase 4 adds an explicitly
selected, enforcing SELinux namespace profile for thin one-time approval on the
[qualified Fedora deployment](docs/NAMESPACE_PHASE4.md). See the
[Phase 5 release and optional-adapter plan](docs/NAMESPACE_PHASE5.md),
[Phase 3 workflow and platform scope](docs/NAMESPACE_PHASE3.md),
[Phase 2 operator and qualification guide](docs/NAMESPACE_PHASE2.md), the
[Phase 1 implementation and qualification record](docs/NAMESPACE_PHASE1.md),
[implementation notes](IMPLEMENTATION_NOTES.md) and
[security specification](<sigrun sigrund Security Architecture and Implementation Specification.md>).
Thin refusal and authorization failures produce an admission-based TIMEOUT.
Explicit refusal of a validated full CSR produces immediate REJECTED. Expanded
evidence and refusal reasons stay private.

V3 breaks v2 wire, warrant, signature, configuration and durable-state formats.
Provision an explicitly selected fresh state/log set with matching components;
there is no automatic migration or deletion.

## How the current implementation works

1. Host execution requires `--target host`, an explicit account or numeric credentials,
   and `--security-profile ID`. With an administrator-distributed live binding
   bundle it queries target-independent context and prepares a full CSR using
   its own file access. Otherwise it submits the unchanged thin intent.
   `--full-only` forbids fallback; `--export-csr PATH` exports locally without
   requesting execution. Finite stdin is captured once.
2. `sigrund` checks the same live target owner, immutable profile and independent
   daemon/signer rules. It verifies full-request access with authenticated
   requester credentials, or privately expands thin intent. It retains exact
   executable evidence and immutable input before review.
3. Root's `sigrund-approve` verifies private epoch acquisition/constraint records,
   displays the complete original intent and resolved execution evidence, then
   signs after confirmation on its own controlling TTY.
4. The daemon revalidates the retained owner and policy, consumes the one-time
   grant and persists audit. Complete APPROVED delivery precedes workload spawn.
   Explicit full-CSR refusal returns REJECTED. Other authorization failures
   wait for the admission-based TIMEOUT.
5. Separate readiness/results accompany stdout/stderr. `sigrun` returns the
   primary child's status and drains remaining output. Restart invalidates old
   warrants and binding bundles, including unexpired, unused grants.

`sigrundctl` provisions host state and packages offline warrants. The
`sigrund-collector` binary currently provides validation diagnostics only.

## Packages

The [Packages workflow](https://github.com/Librazy/sigrund/actions/workflows/packages.yml)
builds RPMs for Fedora 44/45 and DEBs for Ubuntu 24.04/26.04 on x86-64.
Install `sigrun` alone for the client; `sigrund` contains the daemon, SSH approver,
administration tool and systemd unit. Packages require explicit configuration
and provisioning before starting the daemon. See the
[package guide](packaging/README.md) for artifacts, installation and upgrades.

## Build

Use Linux with Rust installed through rustup, a C compiler and standard build
tools. The minimum supported Rust version (MSRV) is **1.89**, declared in the
workspace's `Cargo.toml`. Development uses the exact Rust release pinned in
`rust-toolchain.toml`, including rustfmt, Clippy and rust-analyzer. Rust sources
are opt-in; see [maintenance](MAINTENANCE.md) for setup and toolchain updates.

```sh
git clone https://github.com/Librazy/sigrund.git
cd sigrund
cargo build --workspace --locked
```

Binaries are written to `target/debug/`. Execution additionally requires unified
cgroup v2 with delegated memory and PID controllers, swap controls, and the
kernel namespace, mount, `openat2`, sealed-memfd and `clone3` operations checked
at startup. The supported operator recipe uses systemd for delegation,
watchdog supervision and whole-service cleanup. OpenSSH and Python 3 are needed
for the demo below.

## Try local approval

Use a disposable native Linux systemd host and an existing unprivileged login
named `requester` (substitute your own login). The lab helper creates isolated
configuration, state, test commands and a disposable root-owned SSH signing key.
It installs a uniquely named temporary service under `/run/systemd/system`.

After building as your ordinary user, run these commands in a **root shell**.
Replace `/absolute/sigrund` with the checkout path; the lab directory must be new
and beneath a trusted root-owned parent.

```sh
export TEST_REPO=/absolute/sigrund
python3 "$TEST_REPO/scripts/operator-lab.py" prepare \
  --directory /var/lib/sigrund-demo --binaries "$TEST_REPO/target/debug" \
  --requester requester
source /var/lib/sigrund-demo/environment.sh
python3 "$TEST_REPO/scripts/operator-lab.py" start --directory "$TEST_BASE"
python3 "$TEST_REPO/scripts/operator-lab.py" status --directory "$TEST_BASE"
```

In a **root terminal**, start the foreground approver:

```sh
source /var/lib/sigrund-demo/environment.sh
"$TEST_BIN/sigrund-approve" --socket "$TEST_APPROVAL_SOCKET" --tty /dev/tty \
  --signers "$TEST_SIGNERS" --identity "$TEST_SSH_IDENTITY" --epoch-file "$TEST_EPOCH"
```

In the **requester's terminal**, from a writable directory:

```sh
source /var/lib/sigrund-demo/environment.sh
"$TEST_BIN/sigrun" --socket "$TEST_SOCKET" --target host --security-profile host-baseline \
  --target-uid 0 --target-gid 0 --cwd / --status-fd 3 \
  -- "$TEST_COMMANDS/id" -u 3>request.status.jsonl
echo "$?"
```

Review the displayed request on root's terminal and enter `yes`. The requester
receives `0` from `id -u` and exit status `0`. Status JSON goes to its own file.
Confirmation requires Enter: `y`/`yes` approves and `n`/`no` rejects. Empty or
invalid answers reprompt until the original approval deadline. After timeout
or connection loss, the approver reconnects to watch for future requests.
Commands use absolute executable paths and exact arguments, without shell
evaluation or PATH lookup. Stdin defaults to null; `--stdin sha256` binds finite
piped or redirected input.

Stop the approver with Ctrl-C. In a root shell, stop the lab service:

```sh
python3 "$TEST_REPO/scripts/operator-lab.py" stop --directory /var/lib/sigrund-demo
```

Stopping preserves signing keys, host identity, audit and consumed grants.
The [operator notes](IMPLEMENTATION_NOTES.md#operator-lab) cover offline signing,
service-user targets, foreground daemon operation and recovery. The
[daemon configuration](config/sigrund.toml.example),
[signer policy](config/signers.toml.example) and
[systemd unit](packaging/sigrund.service) are templates; configure real identities
and policy before using them outside the disposable lab.

## Current scope

The runtime executes host jobs. The explicit `namespace-experimental-v1` profile
enables thin requests for `registered:ID`, `process:DAEMON_PID` and `self`.
Root registers/revokes dedicated anchors; self captures its authenticated
connector through the `.anchor` endpoint. The qualified experimental topology
and constraints are in the [Phase 3 guide](docs/NAMESPACE_PHASE3.md). The explicit `namespace-selinux-v1` production profile is qualified on Fedora 44
x86-64 for installed thin one-time SSH/stdio: host → registered rootless B,
real rootless A → B, A → host and A → self. Follow the
[installed operator recipe](docs/NAMESPACE_PHASE4_OPERATOR.md) and
[scope/evidence record](docs/NAMESPACE_PHASE4.md). Untrusted accounts must remain
in the enforcing requester domain; all unconfined host accounts are trusted
administrators. Arbitrary unconfined containers and other platforms/topologies
are not qualified. The client authenticates each host endpoint before disclosure.
Experimental execution excludes known namespace-owner injection authority;
nonroot experimental self rejects before review.
The [fresh provisioning and binding export procedure](docs/NAMESPACE_PHASE1.md#explicit-v3-provisioning-and-binding-export)
explains the cutover, private bundle distribution and offline signing.

The local execution profile supports SSH Ed25519 signatures, one-time grants,
separate stdout/stderr, finite sealed stdin, cancellation, replay prevention,
authenticated local audit/recovery and bounded job supervision. Security-key
signature verification is implemented; physical FIDO interaction still needs
hardware acceptance testing.

PTY sessions, hook execution, remote collector/ACK integration, policy reload,
reusable grants and remote-host routing remain outside this profile.
Collector configuration is required even when remote audit is disabled. See
[implementation notes](IMPLEMENTATION_NOTES.md#remaining-specification-scope)
for the full remaining specification scope.

Approving a privileged interpreter such as Bash, Python or Node grants its
programmable authority under the selected credentials. Executable snapshots do
not bind mutable script files, imports or libraries. Host execution uses the
daemon's configured domain; namespace execution requires explicit selection,
a live captured owner and scoped approval. Experimental execution does not
provide production LSM/seccomp confinement. Root inside a container alone does not supply the
required delegation and kernel access. These boundaries are discussed in
[privileged interpreter guidance](docs/PRIVILEGED_INTERPRETERS.md) and the
[namespace-aware execution roadmap](docs/NAMESPACE_AWARE_EXECUTION.md).

## Development and verification

Run ordinary checks as an unprivileged user:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked -- --test-threads=1
```

Production host integration gates run separately as initial-userns root on a
disposable supervised host. The [Phase 1.5 operator fixture](docs/NAMESPACE_PHASE15.md)
exercises rootless anchor acquisition, private review and registration lifecycle.
Phase 0 namespace experiments additionally need
`uidmap`, subordinate mappings and permitted user namespaces. For the complete check harness and real privileged acceptance,
including dependencies and cleanup requirements, see
[tests and reproduction](IMPLEMENTATION_NOTES.md#tests-and-reproduction).

[GitHub Actions](https://github.com/Librazy/sigrund/actions/workflows/ci.yml)
runs formatting, Clippy, workspace tests and privileged acceptance on disposable
Ubuntu VMs on x86-64 and ARM64 using the pinned development toolchain. A separate
x86-64 job reads the MSRV from `Cargo.toml`, builds every target and runs
workspace tests using the committed lockfile. Clippy uses the manifest's MSRV
when suggesting APIs; Cargo's resolver prefers MSRV-compatible dependencies
when updating the lockfile.
Acceptance exercises actual approval/execution, replay denial,
cancellation, recovery and service shutdown; ordinary unit tests alone do not
validate those kernel and service-manager boundaries.

Executable models are enabled with `executable_trust_models`; each immutable
host profile fixes one exact model and its checkpoint obligations. The example
`host-baseline` profile uses `digest_memfd`. Configure a distinct, digest-bound
profile and scoped rules for each additional permitted model. Signed inputs
never switch models. Direct models execute retained source FDs and verify evidence
and credentials at an exec stop, preserving eligible host file capabilities.
Memfd snapshots strip file capabilities and report unknown exact exec outcome.

Ctime requires online approval with an uninterrupted read lease through the
exec stop; export and pre-signed ctime redemption are rejected. Recognized
administrator-maintained ComposeFS roots can qualify for direct digest after
startup enrollment. This assumes administrators preserve active backing objects.
The exception can be disabled with `[digest_direct] allow_admin_trusted_composefs = false`.
Neither a cloned mount ID nor a matching pathname supplies target authority.
See [executable trust details](IMPLEMENTATION_NOTES.md#executable-trust-selection).
