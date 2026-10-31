# Distribution packages

The project and both packages are MIT licensed. Each DEB ships the license in
`/usr/share/doc/<package>/copyright`; each RPM declares `License: MIT` and ships
it in `/usr/share/licenses/<package>/LICENSE`.

GitHub Actions builds native **x86-64** packages in Fedora 44/45 and Ubuntu
24.04/26.04 containers, using the repository's pinned Rust toolchain and locked
dependencies. Download the `packages-<distribution>-x86_64` artifact from a
successful **Packages** workflow run. Each archive contains two packages,
`SHA256SUMS`, and source/toolchain/image information in `build-info.txt`.

| Package | Installed components | Runtime dependencies |
| --- | --- | --- |
| `sigrun` | `/usr/bin/sigrun`, documentation and license | Native shared libraries; no daemon, systemd or SSH dependency |
| `sigrund` | `/usr/libexec/sigrund/sigrund`, `/usr/bin/sigrund-approve`, `/usr/bin/sigrundctl`, systemd unit and configuration examples | Native shared libraries, systemd and OpenSSH client |

Neither package depends on the other. Install both on a machine that will host
the daemon and run requests locally. The diagnostic-only collector binary is
not packaged as a working collector service.

## Install

Select the artifact matching the target distribution, then verify its checksum:

```sh
sha256sum --check SHA256SUMS
```

As root, install only the client, or both packages:

```sh
# Fedora: client only
dnf install ./sigrun-*.rpm
# Fedora: add the daemon and operator tools
dnf install ./sigrund-*.rpm

# Ubuntu: client only
apt install ./sigrun_*.deb
# Ubuntu: add the daemon and operator tools
apt install ./sigrund_*.deb
```

These are unsigned CI snapshot artifacts, not a signed RPM/APT repository or
GitHub Release. Checksums detect corruption; they do not independently establish
authenticity. The upstream Cargo version is combined with a timestamp, commit,
distribution and build revision so snapshots can be upgraded normally. Only
install artifacts from a source revision and workflow run you trust.

## Configure the daemon

Installation does **not** generate signing keys, provision state, enable or start
the service. Examples are installed under `/usr/share/doc/sigrund/examples/`;
they contain placeholders and are not usable policy as shipped.

As root, copy them into place on a fresh deployment:

```sh
install -m 0600 /usr/share/doc/sigrund/examples/sigrund.toml.example /etc/sigrund/config.toml
install -m 0600 /usr/share/doc/sigrund/examples/signers.toml.example /etc/sigrund/signers.toml
```

Edit both files before proceeding. Set real SSH signer keys, allowed requester
and target IDs, matching executable roots, and the `[mvp]` profile with its
`approval_signer_id`. Collector configuration and referenced credential files
remain required even with remote acknowledgements disabled; the supplied
placeholders must be replaced. For a disposable local-only demonstration, use
the repository's operator lab helper, which prepares the inactive collector
fixtures explicitly. See the
[operator notes](https://github.com/Librazy/sigrund/blob/main/IMPLEMENTATION_NOTES.md#operator-lab)
for the supported profile and full setup workflow.

Validate configuration, then provision a **new** host exactly once. Retain the
provisioning output privately; it includes audit anchor material.

```sh
/usr/libexec/sigrund/sigrund --check-config
(umask 077; set -C; sigrundctl init-host > /root/sigrund-initial-anchor.json)
systemctl enable --now sigrund.service
```

Use the packaged service socket paths explicitly; the bare binaries retain
their original default paths:

```sh
# Root's controlling terminal; choose your actual SSH identity.
sigrund-approve --socket /run/sigrund/approve.sock --tty /dev/tty \
  --identity /root/.ssh/id_ed25519

# Ordinary requester's terminal; command must be allowed by configured policy.
sigrun --socket /run/sigrund/client.sock --cwd / -- /usr/bin/id -u
```

Execution needs a compatible kernel, delegated cgroup v2 memory/PID controls
including swap limits, and the required namespace/mount operations. The daemon
probes these before serving requests. Installing in a container does not create
delegation, a systemd manager or host/container routing.

## Upgrade and removal

Upgrades replace executables and reload systemd's unit definitions. They do not
restart the daemon automatically: finish active work, stop any old approver, and
explicitly restart the service and approver to use the new binaries.

Removal stops and disables the service when a systemd manager is running.
Configuration, signing material, identity, audit history and consumed grants are
preserved, including after Debian purge. Removing a package must not reset
one-time consumption or audit continuity. Manage those records separately as a
coherent persistent dataset.

## Build and validation

`build-container.sh` installs target-distribution build dependencies and builds
release binaries. `build.py` stages separate payloads, obtains Debian shared
library dependencies with `dpkg-shlibdeps`, and uses RPM's automatic dependency
generator. No setuid executables or file capabilities are installed.

Each job resolves its distribution tag once and uses that immutable repository
digest for both the build and smoke containers. Artifacts record the original
tag, resolved digest and image ID. Distribution tags can change between runs;
distribution package repositories and the rustup installer remain live inputs.
This metadata supplies image provenance, not a bit-for-bit reproducibility
guarantee.

The workflow starts separate **fresh** target containers for daemon-only and
combined scenarios. It checks dependency metadata in both directions and
asserts that daemon-only installation and upgrade leave the client absent.
The combined scenario begins with client-only installation, checks that the
daemon is absent, then installs both packages and verifies the client survives
daemon removal. Both scenarios check checksums, real version upgrades, binary
entry points, service unit syntax, root ownership/modes and preservation of
operator data through upgrade/removal. The service stays disabled throughout.
These are packaging smoke tests, not execution acceptance: the existing CI
workflow separately tests actual kernel execution and service supervision on a
native privileged VM. Per-distribution privileged execution certification and
ARM64 builds are not included yet.

For a local build after `cargo build --release --locked -p sigrund --bins`, use
the matching distro's packaging tools and a fresh output directory:

```sh
python3 packaging/build.py --format deb --release 0.20261031.local.1 --output /tmp/sigrund-debs
# On Fedora, use --format rpm and an empty output directory instead.
```

The container build/smoke scripts install and remove system packages; run them
only inside disposable CI containers. They are not host setup scripts.
