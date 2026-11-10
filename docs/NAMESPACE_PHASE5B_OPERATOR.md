# Installed Podman adapter operator recipe

The Phase 5B record (`docs/NAMESPACE_PHASE5B.md` in the source repository)
qualifies this deployment. Use a disposable Fedora 44 x86-64 host with
Podman 5.8.1, enforcing SELinux, cgroup v2 and systemd delegation. This recipe
uses the default rootful Libpod namespace and a read-only root-owned rootfs;
the container init is PID 1 in a private PID namespace. Only trusted host
administrators may access the Podman API or use Podman exec. Untrusted users
have locked accounts and run in the enforcing requester domain. Approved
workloads use the nonroot destination service account. This recipe makes no
claim for untrusted rootful container-root sources or Podman exec equivalence.

## Fresh provisioning and independent destination startup

Install matching candidate `sigrun`/`sigrund` RPMs and the dependencies from the
[Phase 4 operator recipe](NAMESPACE_PHASE4_OPERATOR.md), plus Podman and
container-selinux. Use an unused host UID and subordinate ranges for the locked
requester account; the commands below use UID 1200. Preserve any existing
configuration/state/logs separately before selecting a new empty provisioning
set. The provisioning tool refuses existing or partial sets.

As the trusted host-root administrator:

```sh
useradd --uid 1200 --create-home --shell /usr/sbin/nologin phase4req
python3 /usr/share/doc/sigrund/namespace-phase5/prepare-installed.py \
  --requester phase4req
systemctl start podman.socket
restorecon -RF /run/podman
```

The qualification provisioning uses a fixed five-second disclosure deadline and
preserves the ordinary admission/context/resource ceilings. The batch runner
paces client invocations to respect the separate eight-context-queries/minute
ceiling. Default rate enforcement is also tested by complete host acceptance.
The optional module supplies the daemon API permission and the `/run/podman`
file-context rule. Confirm root:root ownership, mode 0660 or stricter, and
`container_var_run_t` labeling on the socket. The root group is trusted. No
requester/workload receives manager API access. Review independently generated
daemon and signer rules; `registered:container-b` requires explicit cross-owner
permission and UID/GID 12001 with empty groups in this deployment.

Build distinct static example workloads from the installed source:

```sh
cc -static -O2 -DDESTINATION='"host"' \
  /usr/share/doc/sigrund/namespace-phase4/workload.c \
  -o /usr/local/libexec/sigrund-phase4/tool
cc -static -O2 -DDESTINATION='"A"' \
  /usr/share/doc/sigrund/namespace-phase4/workload.c -o /var/tmp/phase5b-tool-a
cc -static -O2 -DDESTINATION='"Podman-B"' \
  /usr/share/doc/sigrund/namespace-phase4/workload.c -o /var/tmp/phase5b-tool-b
restorecon -RF /usr/local/libexec/sigrund-phase4
python3 /usr/share/doc/sigrund/namespace-phase5/prepare-rootfs.py \
  --workload /var/tmp/phase5b-tool-b
systemctl start sigrund.service
python3 /usr/share/doc/sigrund/namespace-phase4/environment.py create a \
  --owner phase4req --workload /var/tmp/phase5b-tool-a
podman run --detach --name sigrund-phase5b-b --rootfs --read-only \
  --network none --security-opt label=level:s0 \
  --volume /run/sigrund:/run/sigrund /var/lib/sigrund-phase5b-rootfs \
  /usr/bin/sleep infinity
```

The rootfs helper creates account files, installed binaries and their libraries,
a service directory and an independently labeled denial sentinel. It refuses an
existing root. It starts no service/container and registers no target. The Podman
command independently starts B. Keep the rootfs host-owned and inaccessible to
untrusted writes. Sealing the approved ELF does not bind its later dependencies.

## Register, review and execute

Start the disposable anchor and register it from the host:

```sh
python3 /usr/share/doc/sigrund/namespace-phase5/register-podman.py
```

The helper authenticates the root API, checks the prepared rootfs, and pins
namespace/root handles before asking systemd to launch the installed anchor.
The service enters those pinned handles; it does not execute based on a later
lookup of a reusable PID. The daemon independently performs the constrained G-01
capture, verifies the init's cgroup/private-PID identity and matches the anchor's
root/namespaces. It binds manager identity/configuration and monitors lifecycle.
The helper's JSON output records the actual init/anchor PIDs, container ID and
unit. These values select observations; they authorize no request by themselves.

The underlying root-only operation is:

```sh
sigrundctl target register-podman container-b --pid DAEMON_ANCHOR_PID \
  --owner-uid 0 --security-profile namespace-selinux-v1 \
  --socket /run/sigrund/client.sock --podman-endpoint /run/podman/podman.sock \
  --podman-owner-uid 0 --podman-namespace default --podman-container sigrund-phase5b-b
```

The default per-UID helper ceiling is two; this managed capture uses both slots
for owner UID 0, permitting one concurrent managed registration in this recipe.
If registration reports resource exhaustion after revocation, wait for actual
job/helper disposal and start a fresh anchor before retrying.

The daemon's existing management socket authenticates the administrator. The
requester continues using `registered:container-b`. In a separate root TTY,
start the approver exactly as in the Phase 4 recipe. Review the manager endpoint,
owner/namespace, container ID, init/start identity, configuration digest and
loss/execution contracts, together with the complete destination constraints.
Manager metadata never expands daemon/signer policy.

Submit the host request in the restricted source domain:

```sh
systemd-run --wait --pipe --collect --uid=phase4req \
  --property=SELinuxContext=system_u:system_r:sigrund_requester_t:s0 \
  /usr/bin/sigrun --socket /run/sigrund/client.sock \
  --target registered:container-b --security-profile namespace-selinux-v1 \
  --account phase4_service --cwd /srv/service \
  -- /usr/local/libexec/sigrund-phase4/tool
```

For the real rootless A source, use the Phase 4 `environment.py client a` command
with the same target/profile/account/command. Expect destination `Podman-B`, UID
and GID 12001, empty groups, NNP, the exact workload context, and EACCES from the
configured denied syscall and secret read. APPROVED records durable authorization;
readiness and final output/exit remain separate.

## Lifecycle, evidence and cleanup

Changing the required manager generation/configuration, stopping/deleting B or
losing required resolver evidence invalidates review and cancels supervised
jobs. Restoring a name or reconnecting the API never revives that binding.
Acquire a fresh anchor/registration and obtain fresh approval after recovery.
Post-consumption failures retain consumption. Withdraw explicitly with:

```sh
sigrundctl target revoke container-b --socket /run/sigrund/client.sock
systemctl stop sigrund-phase5b-b-anchor.service
```

Drain jobs before policy replacement. After daemon restart, restart/recreate B
so its `/run/sigrund` bind exposes the new runtime directory, then register a
fresh anchor. Restart invalidates the old epoch even if the container survives.
Policy-change handling detects and terminates; it does not serialize every
workload instruction with replacement.

The installed acceptance runner uses this same client, real private TTY approver
and actual manager. It deliberately changes/removes/restarts the disposable B and
Podman API, and briefly stops/continues only the daemon controller to demonstrate
same-name replacement while the original anchor remains alive. It leaves the
watchdog and enforcement enabled. Use a new private artifact directory:

```sh
python3 /usr/share/doc/sigrund/namespace-phase5/verify-installed.py \
  --artifacts /var/tmp/NEW-phase5b-evidence
python3 /usr/share/doc/sigrund/namespace-phase5/verify-resolver.py \
  --artifacts /var/tmp/NEW-phase5b-resolver-evidence
python3 /usr/share/doc/sigrund/namespace-phase5/verify-scopes.py \
  --artifacts /var/tmp/NEW-phase5b-scopes-evidence
python3 /usr/share/doc/sigrund/namespace-phase5/verify-ownership.py \
  --artifacts /var/tmp/NEW-phase5b-ownership-evidence
```

Run these sequentially; they share a registration, approver and fixed resource
ceilings. The resolver runner creates a root-only forwarding fault injector,
then exercises native registration and actual approval/execution through it.
The scope runner creates a second real rootful engine with separate storage
and a socket-activated API. Its service
uses the ordinary container runtime domain and labels the alternate store
`container_var_lib_t` before startup. Podman 5.8.1 rejects nondefault Libpod
namespaces as unimplemented; the runner records that native exclusion and
verifies explicit rejection of nondefault namespaces and nonroot API owners.
The ownership runner tests client disconnect and retained helper quotas without
replacing a still-valid registration. Each runner records private reviews and
public outcomes in its new root-only artifact directory. The scope runner's
storage/runtime directories and the resolver runner's private directory must
also be unused; preserve previous runs before repeating. No fault injector or
alternate engine forms part of the production service.

Stop the anchor and daemon and remove the disposable container before unmounting
A's runtime/selinuxfs/dev binds or deleting the prepared trees. Preserve
configuration, state, logs and private evidence together when retaining the lab.
Do not publish keys, ratchet state, databases or private authorization payloads.
