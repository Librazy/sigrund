# sigrun / sigrund

[MIT licensed](LICENSE).

Signed command elevation for Linux. An unprivileged user requests a command;
a root operator reviews it on their own terminal and signs it with an SSH key.
The daemon verifies the signature and policy, records the authorization,
executes the command, and returns its output and exit status to the requester.

The local **v2** profile supports client-generated full CSRs and private daemon
expansion of thin CSRs. The [security specification](<sigrun sigrund Security Architecture and Implementation Specification.md>)
defines the protocol and broader target. Thin requests receive only approval or
an admission-based timeout; expanded evidence and refusal reasons stay private.
Full requests additionally permit explicit rejection after requester-access and
evidence validation. No authorization response contains a CSR or diagnostic.

V2 retains all four executable trust models and separates durable authorization
from execution readiness/results. It breaks old protocol, warrant, signature and
state formats. Provision fresh state and use matching components; there is no
migration or automatic deletion. See [implementation status](IMPLEMENTATION_NOTES.md#v2-implementation-and-validation).

## How the current implementation works

1. `sigrun` queries public preparation context on a separate socket, captures finite
   stdin once, and tries to prepare a full CSR with its own file access. If it
   cannot, it submits the same intent as a thin CSR. `--full-only` forbids fallback;
   `--export-csr PATH` exports a full CSR without requesting execution.
2. `sigrund` independently verifies full requests through a process using the
   requester's authenticated UID/GID/groups, or privately expands thin requests.
   It retains exact executable evidence and immutable input before review.
3. `sigrund-approve`, running as root on a controlling TTY, displays the complete
   request, including origin and intent hash, and signs after confirmation.
4. The daemon verifies policy/signature, consumes the one-time grant and persists
   audit, then completely sends `APPROVED` before spawning. Unsuccessful requests
   receive `TIMEOUT` at the fixed deadline; only validated full requests may
   receive an explicit mandator `REJECTED`.
5. Separate readiness and execution-result frames accompany stdout/stderr.
   `sigrun` returns the primary child's exit status and drains remaining output.

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
  --signers "$TEST_SIGNERS" --identity "$TEST_SSH_IDENTITY"
```

In the **requester's terminal**, from a writable directory:

```sh
source /var/lib/sigrund-demo/environment.sh
"$TEST_BIN/sigrun" --socket "$TEST_SOCKET" --cwd / --status-fd 3 \
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

The local execution profile supports SSH Ed25519 signatures, one-time grants,
separate stdout/stderr, finite sealed stdin, cancellation, replay prevention,
authenticated local audit/recovery and bounded job supervision. Security-key
signature verification is implemented; physical FIDO interaction still needs
hardware acceptance testing.

PTY sessions, hook execution, remote collector/ACK integration, policy reload,
reusable grants and cross-host/container routing remain outside this profile.
Collector configuration is required even when remote audit is disabled. See
[implementation notes](IMPLEMENTATION_NOTES.md#remaining-specification-scope)
for the full remaining specification scope.

Approving a privileged interpreter such as Bash, Python or Node grants its
programmable authority under the selected credentials. Executable snapshots do
not bind mutable script files, imports or libraries. Execution uses the daemon's
configured domain; it does not follow requester namespaces or automatically
cross container boundaries. Root inside a container alone does not supply the
required delegation and kernel access. These boundaries are discussed in
[interpreter and execution-domain design notes](docs/INTERPRETERS_AND_EXECUTION_DOMAINS.md).

## Development and verification

Run ordinary checks as an unprivileged user:

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked -- --test-threads=1
```

Namespace tests need `uidmap`, subordinate UID/GID mappings and permitted user
namespaces. For the complete check harness and real privileged acceptance,
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

Executable trust models are configurable with `executable_trust_models`, defaulting
to `["fs_verity", "ctime", "digest_direct", "digest_memfd"]`. Direct models
execute retained source FDs and verify evidence and credentials at an exec stop,
preserving `/proc/self/exe` and eligible file capabilities. Digest_direct uses
bounded streaming SHA-256 with independent size/time limits; verity and ctime
avoid executable hashing. Other files use digest+sealed memfd. Set
`["digest_memfd"]` for snapshot-only operation; see the executable trust section
in [implementation notes](IMPLEMENTATION_NOTES.md) for guarantees and compatibility.

Recognized OSTree ComposeFS roots use `digest_direct` by default after daemon
startup checks the administrator-protected backing object store. This trusts
administrators to preserve object protection and never modify active objects in
place; it does not provide fs-verity or executable write exclusion. Writable
`usroverlay`, unrecognized overlays and failed eligibility checks retain snapshot
fallback. To opt out:

```toml
[digest_direct]
allow_admin_trusted_composefs = false
```

The initial adapter supports the booted OSTree ComposeFS root in the host mount
namespace with its data-only store at `/sysroot/ostree/repo/objects`. It does not
assume every read-only overlay is ComposeFS. Client, daemon and approver versions
must match for the new public-context and approval fields.
