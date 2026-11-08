# Namespace-aware execution Phase 2

Phase 2 implements production registration, retained target ownership,
destination preparation and private signed review for an explicit process
environment. It stops before durable authorization: even an approved namespace
request receives its original scheduled generic `TIMEOUT`. There is no namespace
`AUTH_COMMIT`, public `APPROVED` or workload spawn. Host execution remains enabled.
Namespace execution, placement and confinement are Phase 3/4 deliverables.

## Configure and register

Start with the [fresh v3 host provisioning procedure](NAMESPACE_PHASE1.md#explicit-v3-provisioning-and-binding-export).
Existing v3 host state remains usable; registrations are deliberately ephemeral.
Configure host profiles/rules independently. Append the
[namespace profile/rule example](../config/namespace-profiles.toml.example) to
the daemon configuration and configure matching `signers.namespace_rules`.
The [namespace-only signer example](../config/namespace-signers.toml.example)
grants no host authority. Select that signer in `[mvp].approval_signer_id` for
private namespace review, and configure real keys, requester IDs and roots.

Both daemon and selected signer must independently permit the whole request in
one scoped rule: registration, requester, destination UID/GID/groups, exact profile
hash and cross-owner permission. Common signer requester, executable-root,
capability, mode and TTL ceilings also apply. Numeric credentials are relative
to the destination. Named accounts are resolved once from bounded destination
`etc/passwd` and `etc/group` files, without loading target NSS modules. Resolved
numeric credentials are signed and never looked up again at authorization.
Mapped requester/target host UID equality remains forbidden.

For a client socket `/run/sigrund.sock`, enabling namespace profiles also creates
`/run/sigrund.sock.management` (root-only, mode 0600) and
`/run/sigrund.sock.anchor` (mode 0666, authenticated dedicated-anchor rendezvous).
Expose the anchor endpoint deliberately to the selected environment; exposing
it does not grant registration authority. Management never injects a socket into
the target. Keep the approval socket and epoch file root-controlled.

The environment must supply a dedicated, single-threaded anchor with no seccomp
filter. The [native fixture anchor](../scripts/namespace-phase1-5/anchor.c)
demonstrates the G-01 handshake. The anchor connects, accepts the capture
handshake and performs the traced `unshare(CLONE_FS | CLONE_FILES)`. The daemon
holds it at the successful syscall exit for the registration's lifetime. Select
its PID as seen by the daemon, not a container-local PID or the workload PID.
The anchor is killed on disposal, so it must be disposable.

As host root, after the dedicated anchor connects:

```sh
sigrundctl target register container-b --pid 12345 --owner-uid 1000 \
  --security-profile selinux-minimal --socket /run/sigrund.sock
```

Registration binds a fresh revision, UUIDv7 instance and daemon epoch to that
live owner, pinned root, namespace and mapping evidence, every configured
executable root, and immutable profile. All configured executable roots must be
present as canonical directories without symlinks in the target. Missing roots
or unsupported capture topology prevent publication. Replacement requires a
fresh dedicated anchor; one anchor cannot be recaptured under another label.

The exercised topology is Fedora 44 x86-64, with one child user namespace of the
initial user namespace and all eight selected namespaces owned by that child.
The fixture requires root ptrace/proc access, including `CAP_SYS_PTRACE` and LSM
permission. It checks automatic subordinate mappings with destination 0 mapped
to host 1000 and destination 1..65535 mapped to host 524288..589822. Destination
service UID/GID 12001 maps to host 536288. Mixed namespace ownership, nested
user namespaces and other architectures are outside this qualification.

## Request and review

An ordinary requester can submit explicitly selected thin intent:

```sh
sigrun --socket /run/sigrund.sock --target registered:container-b \
  --account phase2_service --security-profile selinux-minimal \
  --cwd /srv/service --ttl-secs 120 -- /usr/bin/tool
# Numeric alternative preserves exactly these groups (none when omitted):
sigrun --socket /run/sigrund.sock --target process:12345 \
  --target-uid 12001 --target-gid 12001 \
  --security-profile selinux-minimal --cwd /srv/service --ttl-secs 120 -- /usr/bin/tool
```

`process:PID` selects the same existing permitted registration. It never
captures an arbitrary PID or reconstructs an instance. `self` remains rejected.
Cross-domain `--full-only`, `--export-csr` and `--binding-bundle` fail locally.
Raw full and signed namespace submissions are rejected without fallback.
`.context` remains target-independent. Host full/offline workflows are unchanged.

The root approver uses the existing command and controlling terminal:

```sh
sigrund-approve --socket /run/sigrund-approve.sock --tty /dev/tty \
  --signers /etc/sigrund/signers.toml --identity /root/reviewer-key \
  --epoch-file /var/lib/sigrund/host-epoch.json
```

Before prompting it verifies the exact CSR against root-controlled acquisition,
registration, executable-root and constraint records in the locked epoch file.
The display includes authority, epoch/instance, declared owner and registration,
observed namespace/mapping identities, original intent, requested account,
resolved destination and composed host credentials, executable/cwd evidence,
provenance and complete prospective constraints. Missing or mismatched evidence
prevents signing. The display explicitly identifies the Phase 2 private boundary.
The frozen broker request wire shape is unchanged.

The daemon revalidates the original retained owner, policy, executable, cwd,
stdin and signature before returning private `PHASE2_EXECUTION_DISABLED`.
Refusal, missing target/account/profile, invalidation and successful private
approval all retain the admission-based public `TIMEOUT`. Private audit keeps
authenticated source, approved target and absent observed execution distinct.
No namespace grant is consumed, including after a valid signature.

## Lifetime and bounds

Revoke before retiring or replacing an environment:

```sh
sigrundctl target revoke container-b --socket /run/sigrund.sock
```

Revocation, replacement and anchor/helper death invalidate pending review and
cancel its broker exchange. Leases continue to own the original resources until
actual close/reap. Restart discards registrations and invalidates prior evidence;
register a new dedicated anchor in the new epoch. No registration is recovered
from a signed identifier, PID, pathname or durable database row.

Executable roots are cached FDs, not paths reopened during preparation.
`sigrund.process-context.v1` hashes exactly the frozen acquisition record plus
the map of executable-root identities. Pathname replacement cannot redirect a
generation. The separate execution-binding digest still covers exactly canonical
`{target_binding, security_constraints}`. Destination preparation uses fresh-exec
bounded helpers and composes captured mappings independently in daemon and
approver. Digest-memfd and digest-direct preparation retain the selected model.

Limits compose with existing admission, worker, socket and RAM limits: 64 live
or cleaning registrations, 64/4 target leases, 2048/128 retained target FDs,
16/2 helpers and 16/2 reviews globally/per UID. The local broker admits one
outstanding review. Reserve before acquisition, count transient descriptor
duplicates, and refund only after actual close/reap. A private deadline or
disconnect does not refund a blocked cleanup. Helpers clear inherited environment,
close unrelated descriptors and cannot suppress the daemon's orphan reaper.

## Reproduce qualification

Use a disposable native systemd host with the prerequisites in the
[Phase 1.5 recipe](NAMESPACE_PHASE15.md#operator-recipe), including a real
unprivileged owner with subordinate IDs. Ordinary checks run as the workspace
user; privileged scripts run as host root. Use a new artifact directory under a
trusted root-owned parent for each run.

```sh
python3 scripts/check.py --artifacts /var/tmp/sigrund-phase2-checks
# On the disposable guest with the matching source and binaries:
python3 scripts/verify-namespace-phase2.py --owner lab \
  --binaries /absolute/sigrund/target/debug \
  --artifacts /var/lib/sigrund-phase2-evidence
python3 scripts/verify-acceptance.py --requester lab \
  --binaries /absolute/sigrund/target/debug \
  --checks /absolute/phase2-checks/checks.json \
  --artifacts /var/lib/sigrund-phase2-host-evidence
```

The namespace runner has an independent 180-second systemd limit and whole-service
cleanup. Its root-only fault library affects only the daemon; fresh-exec helpers
clear the library environment. It exercises actual descriptor-transfer corruption
and blocks a real retained-root close, rather than adding production test hooks.
Private artifacts include complete evidence/display/audit and must stay private.
The full host entry point also runs privileged Rust, platform, runtime, v3,
trust, execution, recovery and operator acceptance gates. No prototype result
substitutes for these production checks.

## Qualification record

Completed 2026-11-08 for the stated native rootless topology. The
[sanitized evidence](evidence/namespace-phase2-20261108.json) records commands,
source/build digests, individual gates and cleanup. All 11 ordinary checks pass,
with 193 ordinary Rust test passes and 30 Python harness tests. All 21 production
namespace gates pass. The full host acceptance entry point passes all 23 gates,
including nine privileged Rust, seven trust and 26 execution gates, real host
approval, offline redemption, digest equality, recovery and shutdown.

The initial qualification source SHA-256 is
`0f10bfd7684250608e7aab86ab978c22d4567aae99d1a379b1c9da2fd0bc0e91`.
The namespace run matches that snapshot. Host acceptance started before the last
namespace harness refinements; every production and privileged-test binary digest
matches the final checked build. Sources, matching test binaries and their
embedded build paths were mapped into the disposable guest. Raw private artifacts
are retained beneath `/var/tmp/sigrund-phase2-reviewed-evidence` on the development
host. The namespace supervisor verified stopped/empty state; host acceptance
verified supervisor cgroup removal. The qualification guest was destroyed.

This closes the preparation/private-review milestone. Namespace workload
execution, enforcing child confinement, self acquisition, nested/mixed topologies,
manager adapters and namespace full/export/offline access remain deferred, as
listed in the roadmap's V-01–V-20 dispositions. Historical Phase 0/1.5 evidence
and fixture bytes remain unchanged.

## Review corrections

The review follow-up hardens the acquisition and worker boundaries. The
[review resolution record](NAMESPACE_PHASE2_REVIEW.md) maps every finding to its
fix and validation. The initial evidence above describes the original snapshot;
the follow-up record identifies the corrected build separately.
