# Administrator-registered SELinux domains

Host administrators can register an existing enforcing domain for approved host
or rootful namespace jobs. A domain need not be created for sigrund. Suitable
jobs include database backups, application deployment and log archival.
Registration is not authorization: scoped daemon rules and independent signer
rules must authorize the resolved profile digest and explicit capabilities.

The registry is `/etc/sigrund/selinux-domains.d/<id>.toml`. It and its parents
must be root-owned, without symlinks or group/other write permissions. Registry
mutations require UID 0 in the initial user namespace. The daemon validates
referenced registrations at startup and retains its policy generation guard.
Updates require draining jobs, stopping the daemon, changing configuration, and
restarting. Removing a registration does not terminate already running jobs.

## Prepare an existing domain

The domain must accept the daemon's traced `no_new_privs` transition, permit
execution of the selected image label, and permit FD transfer and daemon
supervision. The policy RPM installs `sigrund_custom.if`; call
`sigrund_custom_domain(existing_type)` in an administrator-maintained adaptation
module if those permissions are missing. This interface grants execution
plumbing, not business data or network permissions. Review its rules before
applying it to a shared service domain. `acme_backup.te` in the packaged
namespace/selinux examples illustrates a separate business domain and labeled
source/archive data. Its optional container rules permit reading and executing
ordinary image content labeled `container_file_t` or `container_ro_file_t`; bind-mounted secrets must
retain distinct labels.

The registration check verifies essential entry/FD permissions and rejects
requester injection, producer-domain entry and reserved authentication socket
creation/relabeling. It cannot certify that arbitrary policy implements the
administrator's description or prove least privilege. Real execution tests are
required, including dynamic libraries, direct image labels, stdin/stdout and
cancellation. Existing domains with incompatible requester/producer permissions
must use a compatible adaptation or a dedicated domain.

A domain can also be entered through other system-service entrypoints. sigrund
approval governs only sigrund-launched jobs. Shared-domain policy changes affect
all processes using that domain. Enforcing alone does not mean sandboxed.

## Register and authorize

After installing all policy modules and preparing business file labels and DAC:

```sh
sigrundctl selinux-domain fingerprint system_u:system_r:acme_backup_job_t:s0
```

Copy `selinux-domain.toml.example`, replace its fingerprint, and run:

```sh
sigrundctl selinux-domain check /root/acme-backup.toml
sigrundctl selinux-domain register /root/acme-backup.toml
sigrundctl selinux-domain list
```

Use `register --replace` for an intentional replacement. The check and register
commands never install policy or alter signer permissions.

Create a host profile using this shape (choose your own limits and ID):

```toml
[[host_profiles]]
profile_id = "host-acme-backup-v1"
schema = "sigrund.host-custom-domain.v1"
capabilities = []
executable_model = "digest_memfd"
join_namespaces = []
lsm = "selinux_workload_required"
memory_max = 268435456
memory_swap_max = 0
pids_max = 128
private_mount = true
private_cgroup = true
no_new_privs = true
securebits = 47
seccomp = "no_filter_required"
verify_exec_stop = true

[host_profiles.custom_domain]
# Copy the complete validated registration descriptor here.
# This is signed profile content, not a path or an unsigned lookup.
```

Custom host profiles always require an exec checkpoint, including memfd jobs.
For namespace jobs copy the namespace-data example, replace its schema with
`sigrund.constraints.namespace-custom-domain.v1`, set `selinux.context` to the
registered context, and embed the descriptor in `[namespace_profiles.custom_domain]`.
Keep `enforcing = true`, `policy_change = "detect_and_terminate"`, and no
`executable_context`. The direct variant uses schema
`sigrund.constraints.namespace-custom-domain-direct.v1` and `digest_direct`;
all existing direct-storage qualification requirements still apply.

Do not set the built-in `workload` field for a custom host profile. Built-in and
custom selections are mutually exclusive. `CAP_SYS_ADMIN` remains exclusive to
the built-in root tier. Namespace custom jobs require the host's initial user
namespace and existing supported self/registered-target acquisition paths.

Export the candidate configuration to compute its canonical profile digest
before adding scoped daemon and independent signer rules. Export uses the same
canonical JSON and SHA-256 contract as other profiles and does not require rules
to authorize the candidate already:

```sh
sigrundctl profile export host-acme-backup-v1 --config /etc/sigrund/config.toml
```

The export contains the full profile, its digest, the registration descriptor
and digest, policy fingerprint and matching daemon rules. The signer must
independently authorize that exact profile digest, identities, scopes and
capabilities. Capabilities remain explicit request fields; selection does not
silently add them. Existing profile digests and wire representations are
unchanged. Older binaries reject custom schemas.

After restarting the daemon, request the job normally:

```sh
sigrun --target host --security-profile host-acme-backup-v1 \
  --target-uid 12001 --target-gid 12001 \
  -- /usr/bin/acme-backup
```

The approval displays the context, enforcing requirement, registration digest,
policy fingerprint and administrator declaration, alongside command and identity
constraints. Execution verifies the exact context before release and records it
with the registration and policy fingerprints. Failures never fall back to an
ambient or built-in domain.

## Policy updates and revocation

The fingerprint algorithm `sigrund.loaded-policy-snapshot.v1` hashes the domain
separator, kernel-exported binary policy, a separator, and canonical JSON of the
sorted active boolean map. Reads must complete within one stable kernel status
generation. A module file hash alone cannot represent all effective rules.

Any policy reload, committed boolean change or enforcement change invalidates
the existing guard, including changes unrelated to the domain. Pending work is
invalidated and dependent supervised jobs are terminated. Returning settings to
their earlier values does not reactivate old work. Restart requires a matching
policy fingerprint. Re-register after policy changes, regenerate profile
summaries/digests, update both authorizers, restart, and refresh namespace target
registrations bound to changed digests.

File labels, DAC and network configuration remain administrator-maintained
runtime prerequisites. The fingerprint does not freeze them. Trusted host root
can replace policy and daemon binaries; this feature does not defend against a
host administrator.

To revoke, drain or terminate affected jobs, stop the daemon, remove referencing
profiles/rules, run `sigrundctl selinux-domain remove <id>`, remove signer
authorizations, and restart. V1 has no runtime permissive switching, automatic
business-policy generation or live registry reload.

## Qualification

Run the packaged `verify-custom-domains.py` on a disposable enforcing host with
matching profiles/signers and the labeled example data. It exercises host and
namespace source reads, secret denials, and byte-exact finite stdin. Supply
`--podman-image` to use an actual rootful container instead of the host self
namespace acquisition path. The local image needs sigrun, cat, tee, sleep and
their dynamic dependencies, plus the requester account.

`--registration-checks` tests startup rejection of missing, writable and changed
registrations. `--policy-changes` reloads policy, toggles a boolean and disables
global enforcement temporarily, checks supervised-job termination and stale
fingerprint rejection after restart, then restores settings. These options
intentionally stop/restart the daemon; never use them on a production host.

The initial qualification used Fedora 44, kernel
`6.19.10-300.fc44.x86_64`, enforcing SELinux and a local rootful Podman image.
All 13 runner scenarios passed: host/container source reads, secret denials,
byte-exact finite stdin, missing/writable/changed registration rejection,
boolean-change cancellation, stale-policy restart rejection, policy-reload
cancellation and enforcement-loss cancellation. The host self-namespace path
also passed its six execution and three policy-supervision scenarios. The
read-only stdin descriptor regression is covered by the snapshot tests.
