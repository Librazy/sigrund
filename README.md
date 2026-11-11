# sigrun / sigrund

Signed command elevation for Linux. An unprivileged user requests a command;
a root operator reviews the resolved command, credentials and execution environment
on their own terminal and signs with an SSH key. The daemon verifies independent
daemon and signer policy, records the one-time authorization, and returns the
command's output and exit status to the requester. [MIT licensed](LICENSE).

Execution can target the host, an administrator-registered process environment,
or the authenticated caller's environment. Namespace execution uses retained
process and namespace handles, destination account/path resolution, explicit
security profiles and supervised job cgroups. An optional local Podman adapter
binds a registration to a container's configuration and lifecycle.

Start with the [Quick Start](QUICK_START.md) for installation, configuration and
host-only, host-to-container, inside-container, container-to-host and
container-to-container examples.

## Components

| Component | Purpose |
| --- | --- |
| `sigrun` | Request commands and relay stdin, stdout, stderr, status and cancellation. |
| `sigrund` | Authenticate peers, prepare requests, enforce policy, persist authorization and supervise execution. |
| `sigrund-approve` | Review and sign requests on root's controlling terminal using OpenSSH. |
| `sigrundctl` | Provision state, manage registrations, export host bindings and package offline warrants. |
| `sigrund-anchor` | Supply a disposable capture anchor inside an existing environment. |
| `sigrund-collector` | Validate audit/binding records diagnostically. |

## Build and install

Build on Linux with rustup, a C compiler and standard build tools:

```sh
cargo build --workspace --locked
```

Binaries are in `target/debug/`. The MSRV is Rust **1.89**;
`rust-toolchain.toml` pins the development compiler and tools. See
[maintenance](MAINTENANCE.md) for toolchain setup.

The [Packages workflow](https://github.com/Librazy/sigrund/actions/workflows/packages.yml)
builds separate client and daemon RPMs for Fedora 44/45 and DEBs for Ubuntu
24.04/26.04 on x86-64. Packages require explicit configuration and provisioning;
installation does not start the daemon. Follow the [package guide](packaging/README.md).

Execution requires unified cgroup v2 with delegated memory/PID and swap controls,
and the kernel namespace, mount, pidfd, `openat2`, sealed-memfd and `clone3`
operations checked at startup. Use a native systemd host for delegation,
watchdog supervision and whole-service cleanup.

## Request and approve

Configure identities, independent daemon/signer policy and a fresh state/log set
using the [Quick Start](QUICK_START.md). For a disposable
demonstration with generated software signing keys, use the
[operator lab](IMPLEMENTATION_NOTES.md#operator-lab).

On a configured host, run the approver in a **root terminal**:

```sh
sigrund-approve --socket /run/sigrund/approve.sock --tty /dev/tty \
  --identity /root/.ssh/id_ed25519 --epoch-file /var/lib/sigrund-v3/host-epoch.json
```

In the **requester's terminal**, request a command allowed by policy:

```sh
sigrun --socket /run/sigrund/client.sock --target host \
  --security-profile host-baseline --target-uid 0 --target-gid 0 --cwd / \
  --status-fd 3 -- /usr/bin/id -u 3>request.status.jsonl
```

Review every displayed field and enter `yes` on root's terminal. Arguments are
exact values without shell evaluation or PATH lookup. Stdin defaults to null;
`--stdin sha256` binds finite redirected or piped input. `APPROVED` means durable
authorization; readiness and exit status follow separately. Namespace requests
use `--target registered:ID` or `--target self` with an explicitly configured
profile and destination credentials. See [namespace execution](IMPLEMENTATION_NOTES.md#namespace-execution)
for setup and deployment limits.

## Security and scope

The local v3 workflow supports SSH Ed25519 signatures, one-time grants, sealed
finite stdin, separate output streams, cancellation, replay prevention and
authenticated local audit/recovery. Host requests support thin intent, full CSRs
and offline signing. Namespace execution supports thin online approval with
`digest_memfd`; its enforcing SELinux deployment is scoped to Fedora 44 x86-64.
The Podman integration supports a local root-owned Podman 5.8.1 API in the default
Libpod namespace. [Implementation notes](IMPLEMENTATION_NOTES.md) describe the
supported topology, confinement prerequisites and experimental profile.

Approving an interpreter delegates its programmable authority under the selected
credentials. Executable snapshots do not bind later script, import or library
reads; see [interpreter guidance](docs/PRIVILEGED_INTERPRETERS.md). Untrusted
namespace owners must remain in the enforcing requester domain. Unconfined host
accounts and Podman API administrators are trusted. Policy-change handling
detects changes and terminates work; it does not serialize every instruction
with policy replacement.

PTY, hooks, remote collector/ACK integration, policy reload, reusable grants and
remote-host routing remain outside the local profile. Physical FIDO interaction
requires hardware acceptance. Matching v3 components and a fresh coherent state
set are required; startup rejects incompatible state without migration or deletion.
The [security specification](<sigrun sigrund Security Architecture and Implementation Specification.md>)
records the broader protocol and security requirements.

## Development

Run ordinary checks as an unprivileged user, with output outside the checkout:

```sh
python3 scripts/check.py --artifacts /tmp/sigrund-checks
```

This runs the locked workspace build/tests, formatting, Clippy, Python harness
tests and independent contract vectors. [CI](https://github.com/Librazy/sigrund/actions/workflows/ci.yml)
also runs MSRV checks and privileged host acceptance on disposable x86-64 and
ARM64 Ubuntu VMs. Namespace/SELinux/Podman integration requires the dedicated
native deployment described in [tests and reproduction](IMPLEMENTATION_NOTES.md#tests-and-reproduction).
