# Quick Start

Run a command with approval from a root operator. One `sigrund` daemon runs on
the host; the operator reviews and signs requests in a separate host terminal.
The requester receives stdout, stderr and the command's exit status.

| Scenario | Client location | `--target` | `--security-profile` |
| --- | --- | --- | --- |
| Host-only | Host | `host` | `host-baseline` |
| Host → container B | Host | `registered:container-b` | `namespace-selinux-v1` |
| Inside container A → A | A | `self` | `namespace-selinux-v1` |
| Container A → host | A | `host` | `host-baseline` |
| Container A → container B | A | `registered:container-b` | `namespace-selinux-v1` |

“Inside container” means using the host daemon to execute in the authenticated
caller's environment. This guide does not run a daemon inside a container.

Choose **host-only setup** for a host installation, or the **container demo**
for the four namespace routes. These are alternative fresh setups: the demo
provisioner refuses an existing host-only configuration or state set.

## 1. Install

Use a native Linux host with systemd and delegated cgroup v2 memory/PID and swap
controls. Startup checks the required kernel operations. Container routes in this
guide require **Fedora 44 x86-64 with enforcing SELinux** and the supplied
restricted requester setup. Package availability on other distributions does
not establish namespace execution support there.

Download `packages-<distribution>-x86_64` from a successful
[Packages workflow](https://github.com/Librazy/sigrund/actions/workflows/packages.yml)
run and extract it. In that directory, run as **host root**:

```sh
sha256sum --check SHA256SUMS
# Fedora:
dnf install ./sigrun-*.rpm ./sigrund-*.rpm
# Ubuntu, instead:
apt install ./sigrun_*.deb ./sigrund_*.deb
```

The client package is `sigrun`. The daemon package includes `sigrund`,
`sigrund-approve`, `sigrundctl` and `sigrund-anchor`. Installation does not
provision state or start the service. Use matching versions throughout.
See the [package guide](packaging/README.md) for upgrades and removal.

## 2. Host-only setup

Use an existing unprivileged login, called `requester` below. Run administrative
commands in a **host-root shell**. Start with unused configuration/state paths;
retain an existing deployment as a complete separate set.

```sh
id -u requester
install -m 0600 /usr/share/doc/sigrund/examples/sigrund.toml.example /etc/sigrund/config.toml
install -m 0600 /usr/share/doc/sigrund/examples/signers.toml.example /etc/sigrund/signers.toml
ssh-keygen -t ed25519 -f /etc/sigrund/approver
cat /etc/sigrund/approver.pub
```

Choose a passphrase when prompted. Edit the two TOML files before continuing:

| File | Settings for this example |
| --- | --- |
| `config.toml` | Enable the existing commented `[mvp]` table and set `approval_signer_id = "quickstart-root"`. Set `executable_trust_models = ["digest_memfd"]` and `csr_allowed_executable_dirs = ["/usr/bin"]`. Keep the supplied `host-baseline` profile unchanged. |
| `config.toml`, `[[host_rules]]` | Set `requester_uids` to the numeric UID printed above, `target_uids = [0]`, `target_gids = [0]`, `supplementary_gids = []`, and `cross_owner = true`. Keep the supplied profile digest. |
| `signers.toml`, `[[signers]]` | Set `signer_id = "quickstart-root"`, `type = "ssh-ed25519"`, and `public_key` to the complete public-key line printed above. Set both `require_user_presence` and `require_user_verification` to `false` for this software key. |
| `signers.toml`, `[[signers]]` | Set `allowed_requester_uids` to the requester's numeric UID, `allowed_target_uids = [0]`, `allowed_target_gids = [0]`, `allowed_supplementary_gids = []`, `allowed_capabilities = []`, `allowed_modes = ["one_time"]`, and `allowed_executable_dirs = ["/usr/bin"]`. |
| `signers.toml`, `[[signers.host_rules]]` | Match the daemon's host rule, including requester UID, target IDs, empty groups, profile digest and `cross_owner = true`. |

Both policies must permit the request. Here the operator is authorizing host
root execution of commands under `/usr/bin`; narrow the executable roots and
credentials for a real deployment. Do not change profile fields without updating
its canonical digest and both policies.

The current local-only profile still requires collector configuration and three
root-owned files. Keep `require_remote_audit_ack = false`. Replace the
`collector_public_key` placeholder with `"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="`
and create the inactive local-only files:

```sh
(umask 077; set -C
 for name in collector-ca.pem collector-client.crt collector-client.key; do
   printf 'INACTIVE local-audit only; not TLS credentials\n' > "/etc/sigrund/$name" || exit
 done)
```

These are inactive placeholders, not collector credentials. No remote collector
is used by this workflow. Validate, then provision once:

```sh
/usr/libexec/sigrund/sigrund --check-config
(umask 077; set -C; sigrundctl init-host \
  --state-dir /var/lib/sigrund-v3 --log-path /var/log/sigrund-v3/audit.jsonl \
  > /root/sigrund-initial-anchor.json)
systemctl enable --now sigrund.service
```

Keep the initial anchor private. Never delete state to reset a failed request.

In a separate **host-root terminal**, start the approver:

```sh
sigrund-approve --socket /run/sigrund/approve.sock --tty /dev/tty \
  --identity /etc/sigrund/approver --epoch-file /var/lib/sigrund-v3/host-epoch.json
```

In the **requester's terminal**, run:

```sh
sigrun --socket /run/sigrund/client.sock --target host \
  --security-profile host-baseline --target-uid 0 --target-gid 0 --cwd / \
  -- /usr/bin/id -u
```

Review every displayed field in the root terminal and enter `yes`. Expect output
`0` and exit status `0`. Stdin defaults to null; `--stdin sha256` binds finite
redirected or piped input. Commands and arguments are exact, without shell
expansion or PATH lookup. Approving an interpreter delegates its programmable
authority; see [interpreter guidance](docs/PRIVILEGED_INTERPRETERS.md).

## 3. Prepare the container demo

Use a **fresh disposable Fedora 44 host** after installing both packages. All
commands in this section run as **host root**. Untrusted code must remain in the
enforcing `sigrund_requester_t` domain; unconfined host accounts are trusted
administrators. An ordinary container with the socket mounted is insufficient.

```sh
dnf install python3 gcc glibc-static make selinux-policy-devel \
  policycoreutils-python-utils setools-console shadow-utils util-linux
getenforce
export NS_DOCS=/usr/share/doc/sigrund/namespace
useradd --uid 1200 --create-home --shell /usr/sbin/nologin nsrequester
useradd --uid 1300 --create-home --shell /usr/sbin/nologin nsowner
```

`getenforce` must print `Enforcing`. Choose unused host IDs. Check `/etc/subuid`
and `/etc/subgid`: each account needs at least 65536 subordinate IDs, with
nonoverlapping ranges. Keep these accounts locked, without login, sudo or an
alternate execution path.

Provision the demo, allow two minutes for interactive approval, and validate:

```sh
python3 "$NS_DOCS/selinux/prepare-installed.py" --requester nsrequester \
  --state-dir /var/lib/sigrund-v3 --log-path /var/log/sigrund-v3/audit.jsonl
sed -i 's/^authorization_timeout_ms = 5000$/authorization_timeout_ms = 120000/' /etc/sigrund/config.toml
/usr/libexec/sigrund/sigrund --check-config
```

The helper creates scoped daemon/signer policy, a disposable unencrypted SSH key,
local-only collector placeholders, fresh state and the SELinux modules. It starts
no service. Use these generated credentials only for this disposable demo.

Build the same command path with distinct host/A/B output, then create the two
environments and register B:

```sh
cc -static -O2 -DDESTINATION='"host"' "$NS_DOCS/selinux/workload.c" \
  -o /usr/local/libexec/sigrund-namespace/tool
cc -static -O2 -DDESTINATION='"A"' "$NS_DOCS/selinux/workload.c" -o /var/tmp/tool-a
cc -static -O2 -DDESTINATION='"B"' "$NS_DOCS/selinux/workload.c" -o /var/tmp/tool-b
restorecon -RF /usr/local/libexec/sigrund-namespace
systemctl start sigrund.service
python3 "$NS_DOCS/selinux/environment.py" create a --owner nsrequester --workload /var/tmp/tool-a
python3 "$NS_DOCS/selinux/environment.py" create b --owner nsowner --workload /var/tmp/tool-b
python3 "$NS_DOCS/selinux/environment.py" init b
python3 "$NS_DOCS/selinux/environment.py" anchor b --registration container-b
```

B has an independent init and a disposable capture anchor. The helpers copy the
matching client/anchor and libraries into the demo roots and expose the required
endpoints. Their transient services have a ten-minute limit; complete the examples
within it. These are controlled demo environments, not arbitrary Docker containers.

In a separate **host-root terminal**, start the approver and leave it running:

```sh
sigrund-approve --socket /run/sigrund/approve.sock --tty /dev/tty \
  --identity /var/lib/sigrund-namespace-lab/approver \
  --epoch-file /var/lib/sigrund-v3/host-epoch.json
```

## 4. Try the four container routes

Run the following commands from the **administrative host-root shell** used for
setup, with `NS_DOCS` still set. The wrappers launch the actual requester under
the restricted account/domain, either on the host or inside rootless A. Confirm
each request in the separate approver terminal.

### Host → container B

```sh
systemd-run --wait --pipe --collect --uid=nsrequester \
  --property=SELinuxContext=system_u:system_r:sigrund_requester_t:s0 \
  /usr/bin/sigrun --socket /run/sigrund/client.sock --target registered:container-b \
  --security-profile namespace-selinux-v1 --account ns_service --cwd /srv/service \
  -- /usr/local/libexec/sigrund-namespace/tool
```

Expect `destination=B`, UID/GID `12001`, empty groups, NNP and the workload
context. The example also reports denials for its configured syscall and secret read.

### Inside container A → A

```sh
python3 "$NS_DOCS/selinux/environment.py" client a -- \
  --target self --security-profile namespace-selinux-v1 \
  --account ns_service --cwd /srv/service -- /usr/local/libexec/sigrund-namespace/tool
```

Expect `destination=A` with the same namespace workload constraints. `self`
selects the authenticated caller's environment; it needs no B registration.

### Container A → host

```sh
python3 "$NS_DOCS/selinux/environment.py" client a -- \
  --target host --security-profile host-baseline \
  --target-uid 65534 --target-gid 65534 --cwd / -- /usr/local/libexec/sigrund-namespace/tool
```

Expect `destination=host`, UID/GID `65534`, and the host workload context. This
uses the host profile's constraints rather than the namespace profile's seccomp rules.

### Container A → container B

```sh
python3 "$NS_DOCS/selinux/environment.py" client a -- \
  --target registered:container-b --security-profile namespace-selinux-v1 \
  --account ns_service --cwd /srv/service -- /usr/local/libexec/sigrund-namespace/tool
```

Expect `destination=B`, with B's account and executable bytes despite the client
running in A. Namespace execution supports thin online approval; namespace
full/export/offline redemption is excluded. Do not use the experimental profile
to bypass the enforcing deployment's prerequisites.

For an administrator-controlled Podman B, use the separate
[Podman setup](IMPLEMENTATION_NOTES.md#optional-podman-lifecycle-binding). Its
supported API is local, root-owned Podman 5.8.1 in the default Libpod namespace.
The requester still uses `registered:container-b`.

## 5. Stop, recover and diagnose

`APPROVED` records durable authorization; readiness and exit follow separately.
Authorization failures normally disclose only `TIMEOUT`. An explicit refusal of
a validated full host CSR returns `REJECTED`. Check private daemon logs as root:

```sh
systemctl status sigrund.service
journalctl -u sigrund.service --no-pager -n 100
```

For the container demo, withdraw B (disposing its anchor), then stop B's init
and the daemon:

```sh
sigrundctl target revoke container-b --socket /run/sigrund/client.sock
systemctl stop sigrund-namespace-b-init.service
systemctl stop sigrund.service
```

Stop any still-running A/host client units too. Before deleting demo roots under
`/var/lib/sigrund-namespace-environments/`, unmount each root's `run/sigrund`,
`sys/fs/selinux` and `dev/null` binds. Preserve keys, configuration, audit and state
together; stopping does not erase them.

Restart invalidates old bindings. For this demo, restart B's init to refresh its
socket-directory mount, then register a fresh anchor and obtain fresh approval.
Drain jobs before changing SELinux policy. See
[namespace contracts and operating limits](IMPLEMENTATION_NOTES.md#namespace-execution)
for the complete support boundary, and the
[isolated source-build lab](IMPLEMENTATION_NOTES.md#operator-lab) for a host-only
trial that leaves packaged configuration untouched.
