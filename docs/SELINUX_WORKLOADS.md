# Administrator-selected SELinux workloads

The optional policy RPM defines multiple workload domains. An administrator
selects profiles in `config.toml`, authorizes their exact SHA-256 digests in
scoped daemon rules, and independently authorizes those digests and capabilities
in signer rules. The user selects `--security-profile`; the mandator reviews the
resolved constraints, context, authority and capability set before signing.
Installing the RPM alone does not authorize any new profile.

| Tier | Intended use | Writable files | Network | Linux authority in shipped examples |
| --- | --- | --- | --- | --- |
| Existing host baseline | Existing native commands | Existing ordinary files, without general file creation | None | None |
| Existing production namespace | Restricted service and negative-policy checks | Explicit service data | None | None; fixed nonroot contract and seccomp |
| `data` | Local jobs, generators, batch processing | `sigrund_workload_data_t` files/directories, including creation | None | None |
| `network` | TCP/UDP services, API clients | Same service data | TCP/UDP clients and servers, DNS, all ports | `CAP_NET_BIND_SERVICE` |
| `maintenance` | Package installation and system file maintenance | Broad ordinary filesystem management and relabeling | Same as network | Explicit file ownership/DAC, identity, chroot and resource capabilities |
| `root` | Administrator-approved unrestricted recovery | Fedora unconfined filesystem authority | Fedora unconfined network authority | All 41 capabilities through `CAP_CHECKPOINT_RESTORE`, including `CAP_SYS_ADMIN` |

Every new tier has host and namespace examples, named `host-TIER-v1` and
`namespace-TIER-v1`. The SELinux contexts are
`system_u:system_r:sigrund_TIER_workload_t:s0`. Namespaces remain a separate
selection: a network profile does not change which network namespace is joined.
Data and network profiles can read ordinary files that DAC permits; they are
write boundaries, not secret-read isolation. Their examples use UID 0 for easy
comparison; administrators can authorize a nonroot service UID instead.

Maintenance is trusted system administration. Its broad filesystem rights can
change system configuration and install privileged startup code; it is not a
sandbox for an untrusted package or script. Raw sockets, mount management and
SELinux policy management are outside its direct permission set. Package script
requirements vary; use a deliberately approved root profile for operations that
need additional authority.

Root is **full host root authority**, including SELinux policy loading and
enforcement control through Fedora's unconfined interfaces. A root job may
replace the daemon, create host services, move tasks out of its cgroup, or escape
container containment. Its cgroup limits and disconnect cancellation supervise
cooperating jobs; they do not constrain a hostile root administrator. Namespace
root requires the host's initial user namespace and must be approved as host
root, even though execution begins in the selected container. The launcher
still starts with a private mount/cgroup view, explicit capabilities, locked
securebits and `no_new_privs`; these do not revoke the granted root authority.
The approval UI prints `FULL HOST ROOT AUTHORITY` for this tier.

The policy does not mark a domain permissive or disable SELinux. Workloads start
in their own SID, and the reserved daemon SID and authentication socket types
are not granted directly to them. Root can deliberately replace policy, so those
assertions protect normal entry paths rather than the system from its root
administrator. Narrower profiles retain their existing policy boundaries.

## Enable selected profiles

Use the matching daemon/client and policy RPMs. Drain jobs and stop the daemon
before policy installation or replacement. Append only the needed profiles and
scopes from `config/workload-profiles.toml.example`; copy the corresponding
rules from `config/workload-signers.toml.example` into the selected signer.
Installed examples live in `/usr/share/doc/sigrund/examples/`.

The examples give maintenance and root 1 GiB of memory. Raise the daemon's
`job_memory_max_bytes` ceiling to at least `1073741824` before enabling them.
Each job uses its signed profile's memory, swap and PID limits. Global settings
are ceilings, not implicit authority to raise the signed limits. Changing a
profile's resources, capabilities or context changes its digest: recompute and
replace both daemon and signer rule digests.

Extend the selected signer's `allowed_capabilities` to include the capabilities
of every enabled tier. Keep these names sorted and unique. Capabilities remain
explicit in the request and must exactly match the selected profile; profile
selection does not silently add capabilities. A new enforcing profile refuses
startup without genuine enforcing SELinux and the packaged producer domain.
Root additionally requires UID 0 and the complete explicit capability set.
Other tiers cannot request `CAP_SYS_ADMIN`.

For service data, create a durable file-context mapping and restore the labels:

```sh
semanage fcontext -a -t sigrund_workload_data_t '/srv/my-service(/.*)?'
restorecon -RF /srv/my-service
```

Set DAC ownership for the selected account. Preserve those labels on bind mounts;
container-wide `:z`/`:Z` relabeling replaces them with container labels and loses
the service-data authorization.

For example, request a networking job with:

```sh
sigrun --target host --security-profile host-network-v1 \
  --target-uid 0 --target-gid 0 --capability CAP_NET_BIND_SERVICE \
  --cwd / -- /usr/bin/my-native-program
```

For a profile with many capabilities, a local trusted copy of the shipped
examples can construct the exact CLI arguments:

```python
import subprocess, tomllib
from pathlib import Path
profiles = tomllib.loads(Path('/usr/share/doc/sigrund/examples/workload-profiles.toml.example').read_text())
profile = next(p for p in profiles['host_profiles'] if p['profile_id'] == 'host-root-v1')
argv = ['sigrun', '--target', 'host', '--security-profile', profile['profile_id'],
        '--target-uid', '0', '--target-gid', '0', '--cwd', '/']
for capability in profile['capabilities']:
    argv += ['--capability', capability]
subprocess.run([*argv, '--', '/usr/bin/id'], check=True)
```

Use `--target self --security-profile namespace-TIER-v1` for a rootful container.
The requester must be unfiltered and single-threaded during namespace capture;
Podman's default seccomp filter is not supported for that acquisition path.
Registered targets require a fresh registration bound to the selected profile
digest. Arbitrary process targets cannot use administrative namespace profiles.

The new namespaces use the existing administrator execution schema with an
explicit, allowlisted enforcing context. Production namespace seccomp and
executable labeling contracts remain separate. Policy-generation changes
invalidate pending work and terminate supervised jobs; drain/restart the daemon
and acquire fresh registrations after replacement.

## Disposable qualification

Compile `scripts/namespace/selinux/workload-profile-probe.c` as a native program,
install it at `/usr/bin/sigrund-workload-probe`, prepare
`/srv/sigrund-workloads/data` with `sigrund_workload_data_t`, and provision the
examples for the disposable requester and its test-only TTY signer. Then run as
trusted host root:

```sh
python3 scripts/namespace/selinux/verify-workloads.py \
  --identity /root/test-approver --artifacts /root/workload-results \
  --podman-image localhost/sigrund-workloads:test
```

The optional local image must contain the matching client, probe and libraries,
requester credentials and standard mount points. The harness never pulls an
image or loads policy. It verifies actual SIDs, file creation allowed/denied,
TCP allowed/denied, effective `CAP_SYS_ADMIN`, an isolated tmpfs mount for root,
real TTY approvals, single grant consumption and whole-job cgroup cleanup.
Expected denied operations appear in its private kernel audit log. Host and
namespace root approval text must contain the full-authority notice.

`--package-rpm` additionally verifies package installation and removal for
maintenance and root. Build the data-only `workload-fixture.spec` with
`rpmbuild -bb`, stage its RPM at `/srv/sigrund-workloads/fixture.rpm`, and provide
native `/usr/bin/dnf5` on the host and native `/usr/bin/rpm`, its libraries and
RPM configuration in the local image. Host cases use DNF with repositories
disabled; namespace cases install and remove with RPM inside one disposable
container. No package scripts or dependencies are used by this fixture.

On 2026-11-14, all 14 cases passed on a disposable Fedora 44 x86_64 VM,
kernel `6.19.10-300.fc44.x86_64`, with SELinux enforcing. The four host and
four rootful Podman self profiles produced their exact workload SIDs and the
expected file, TCP/UDP and mount results. Maintenance and root completed local
DNF installation/removal on the host and RPM installation/removal in the
container. Every request completed real TTY approval, consumed one grant and
removed its job cgroup. The fixture does not qualify arbitrary package scripts,
external network access, registered targets or rootless containers.

The default Rust suite passed 228 tests on that VM (34 privileged tests remained
ignored). All three workload authorization contract tests also passed, including
the later-added check that a lower-tier rule cannot authorize root or changed
constraints. All 37 Python harness tests, Clippy with warnings denied, formatting
and independent host/namespace protocol vectors passed.

To verify that already-running host jobs retain their policy dependency, drain
and stop the disposable daemon, then run:

```sh
python3 scripts/namespace/selinux/verify-workload-supervision.py \
  --identity /root/test-approver --artifacts /root/supervision-results
```

This test reloads the installed SELinux policy and temporarily disables global
enforcement in separate cases. Each case starts and approves a long-running
host data job, changes policy only after its execution-ready audit record, and
requires SIGKILL, single grant consumption and cgroup removal while the daemon
remains running. It restores enforcement and leaves the daemon stopped. Both
cases reproduced surviving jobs before the supervision fix and passed afterward
on the Fedora 44 kernel above.

The direct root/file-capability regression uses the same drained, stopped
disposable host and a single test signer authorized for the root tier:

```sh
python3 scripts/namespace/selinux/verify-workload-filecaps.py \
  --identity /root/test-approver --artifacts /root/filecap-results
```

It temporarily adds a direct root profile and matching daemon/signer rules,
compiles a native probe, and checks execution without file capabilities and with
`CAP_NET_BIND_SERVICE` in `p`, `ep` and `eip` modes. It verifies the actual inode,
root SID and all five capability sets, as well as the exec checkpoint, single
grant consumption and cgroup removal. Configuration is restored, the probe is
removed and the daemon is left stopped. On the Fedora 44 kernel above, all three
file-capability cases reproduced checkpoint rejection before the alias-reopening
fix; all four cases passed afterward.
