# Phase 4 Fedora SELinux candidate

Build all three modules with `make`, then load them in one transaction:

```sh
semodule -i sigrund_daemon.pp sigrund_workload.pp sigrund_requester.pp
restorecon -RF /etc/sigrund /usr/libexec/sigrund/sigrund
```

The daemon and workload policies remain separate. The requester policy defines
the untrusted actor in the qualified deployment. It deliberately has neither the
generic `domain` attribute nor any process transition permission. All untrusted
code, including namespace owners and mapping helpers, must stay in
`system_u:system_r:sigrund_requester_t:s0`, with that domain enforcing. The
root-owned systemd recipe provides its entry. Requester accounts are locked,
have a nologin shell, have no sudo access and have no alternate execution path.
Unconfined host accounts must be trusted administrators. The modules do not make
an unconfined, non-administrative host account safe: Fedora permits unconfined
subjects to enter `init_t`, which can enter the daemon producer domain.

The client checks its source label through a kernel socket pair, checks the
requester, producer and both workload domain enforcement flags through the kernel AV API, and
checks the endpoint's reserved socket label. Each SELinux file must belong to
selinuxfs. The `/access` query uses a write/read transaction, so the source's
selinuxfs view must permit that operation. `compute_av` grants no policy-loading
or enforcement-changing authority. The policy assertions separately prohibit
requester entry into another domain, workload ptrace, and reserved socket SID
creation/relabeling. Administrative approval uses initial-user-namespace host
root authentication.

Approved host commands also leave the producer domain. The executor arms the
`sigrund_host_workload_t` transition while the host procfs view is trusted, before
credentials or mounts change. This applies whenever the daemon runs in its
reserved producer context, including host-only configurations. Namespace
launchers carry this obligation through their sealed, versioned payload; the
production namespace profile still enters its own exact workload context.
Host constraints retain their existing ambient-LSM contract. Neither workload
type can create reserved socket labels or transition into a producer. An
unconfined host command must never inherit the producer's reserved-label powers.

Drain jobs before replacing policy. The daemon pins a policy-generation token;
observed changes invalidate targets and terminate jobs. This is detection and
termination, without an atomic interlock against concurrent policy replacement.
Restart the daemon and register a fresh anchor after any policy change.

The installed operator guide is `../NAMESPACE_PHASE4_OPERATOR.md`. Qualification
status and platform limits are recorded in `docs/NAMESPACE_PHASE4.md` in the
source repository; installing these sources does not itself qualify a deployment.

## Optional Podman resolver policy

The default build installs no manager API permission. For the separately
qualified local rootful Podman deployment, build `make podman`, load
`sigrund_podman.pp`, and run `restorecon -RF /run/podman` after starting the
standard root-owned socket. The optional file-context rule labels that directory
and socket `container_var_run_t`; the module permits only the producer to connect
to the container runtime or systemd-activated listener. Requester and workload
domains receive no manager API access. Follow
[the Podman operator recipe](../NAMESPACE_PHASE5B_OPERATOR.md) for scope,
administrator trust, lifecycle and confinement prerequisites. When reading this
file in the source tree, use [the source recipe](../../docs/NAMESPACE_PHASE5B_OPERATOR.md).
