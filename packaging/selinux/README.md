# SELinux policy

Build the daemon, workload and requester modules with `make`, then load them
in one transaction:

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

For the optional local rootful Podman adapter, build `make podman`, load
`sigrund_podman.pp`, start the root-owned API socket and run `restorecon -RF
/run/podman`. The module labels the path `container_var_run_t` and permits only
the producer to connect to runtime/systemd listeners. Requesters and workloads
receive no manager API access.

See the [implementation notes](../../IMPLEMENTATION_NOTES.md#namespace-execution)
for scope and setup. Packages install those notes at
`/usr/share/doc/sigrund/IMPLEMENTATION_NOTES.md`, with disposable recipes under
`/usr/share/doc/sigrund/namespace/{selinux,podman}/`.
