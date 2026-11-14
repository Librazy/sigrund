# SELinux policy

Fedora release artifacts include optional `sigrund-selinux` and
`sigrund-selinux-podman` RPMs. CI builds these noarch modules separately against
the Fedora 44 and 45 policy interfaces. Use packages from the same distribution
and release as the daemon; the target does not need `make`, `selinux-policy-devel`
or a policy compiler.

For the base daemon, workload and restricted requester policy, finish active jobs,
stop the daemon and install the policy package explicitly:

```sh
systemctl stop sigrund.service
dnf install ./sigrund-selinux-[0-9]*.noarch.rpm
```

The package uses Fedora's SELinux RPM macros to install the three modules in one
transaction and relabel affected paths. It depends on the matching daemon,
targeted base policy and policy management tools. Installing only `sigrund` does
not pull in this package: `Suggests` keeps policy activation explicit. Loading it
also transitions approved **host** commands to `sigrund_host_workload_t`, with
that domain's SELinux permissions. It does not enable namespace rules, create
accounts or keys, initialize state, or start/restart a service. Configure the
desired profiles and independent signer rules before starting the daemon.

Drain and stop the daemon before policy upgrades or removal, and upgrade the
daemon and its installed policy packages together. Policy replacement invalidates
live owners/jobs; acquire fresh registrations after restarting. Removal unregisters
the packaged modules and restores affected path contexts, while retaining daemon
configuration, identity, state and audit history.

On Silverblue, layer the desired RPMs with `rpm-ostree install` and boot the
resulting deployment. The policy belongs to the deployment; do not copy the daemon
to another path to work around the read-only `/usr`. The container package tests
exercise the policy store, not Silverblue deployment or enforcing kernel execution.

For source development only, install the matching distribution's
`selinux-policy-devel`, `make` and policy build tools, build with `make`, and load
the modules in one transaction on a disposable host:

```sh
semodule -i sigrund_daemon.pp sigrund_workload.pp sigrund_requester.pp
restorecon -RF /etc/sigrund /usr/libexec/sigrund/sigrund
```

Untrusted code, including namespace owners and mapping helpers, must stay in
enforcing `system_u:system_r:sigrund_requester_t:s0`. The root-owned systemd
recipe supplies entry; requester accounts require locked passwords, nologin shells
and no sudo or alternate execution path. Unconfined host accounts are trusted
administrators. These modules do not constrain an unconfined host account.

Clients authenticate reserved socket labels and check producer/requester/workload
enforcement through genuine selinuxfs. Its `/access` query needs a write/read
transaction; `compute_av` supplies no policy-loading permission. Policy assertions
prohibit requester domain transitions, workload ptrace and reserved-label creation.
Administrative approval additionally requires initial-user-namespace host root.

Approved host commands transition to `sigrund_host_workload_t`, including host-only
configurations. Production namespace jobs enter their exact workload SID. Neither
workload may create reserved socket labels or transition into the producer domain.
Policy-generation changes invalidate owners and terminate jobs. Drain jobs before
replacement and acquire fresh registrations afterward; this provides detection
and termination without an atomic replacement interlock.

For the optional local rootful Podman adapter, explicitly install the matching
`sigrund-selinux-podman` RPM (source developers can build `make podman`). It depends
on the base policy package and `container-selinux`, and loads `sigrund_podman.pp`.
The Podman engine and API service remain separately managed: start the root-owned
API socket and run `restorecon -RF /run/podman`. The module labels the path `container_var_run_t` and permits only
the producer to connect to runtime/systemd listeners. Requesters and workloads
receive no manager API access.

See the [implementation notes](../../IMPLEMENTATION_NOTES.md#namespace-execution)
for scope and setup. Packages install those notes at
`/usr/share/doc/sigrund/IMPLEMENTATION_NOTES.md`, with disposable recipes under
`/usr/share/doc/sigrund/namespace/{selinux,podman}/`.
