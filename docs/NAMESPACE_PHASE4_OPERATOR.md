# Installed Phase 4 operator recipe

This recipe targets a disposable Fedora 44 x86-64 machine with enforcing SELinux,
systemd delegation and the required pidfd namespace operations. It uses the
installed RPMs, one-time thin intent, SSH signing and stdio. Namespace full,
export, offline redemption, process-PID targets and other LSM stacks are excluded.
The example workload is static; sealing its ELF does not bind other libraries or
scripts a different workload might subsequently load from its destination.

All unconfined host accounts are trusted administrators. Untrusted requester and
destination-owner accounts have locked passwords, nologin shells and no sudo or
alternate execution path. Start their code through the provided systemd recipe,
in the enforcing `sigrund_requester_t` domain. Exposing sockets to an unconfined
rootless container does not satisfy these prerequisites. The operator owns
the installed recipe and provisioning files; the namespace owners cannot edit
host mount points or the root-owned manifests.

## Provision and bring B online

Install the candidate `sigrun` and `sigrund` RPMs and Fedora's `gcc`,
`glibc-static`, `make`, `selinux-policy-devel`, `policycoreutils-python-utils`,
`setools-console`, `shadow-utils` and `util-linux` packages. Installation does
not start or initialize the service. Choose unused host IDs and non-overlapping
subordinate ID ranges. On a fresh Fedora host, ordinary `useradd` allocates
subordinate ranges; verify `/etc/subuid` and `/etc/subgid` before proceeding.
The source and B owners are different accounts: one retained B capture and a
concurrent self capture/preparation would otherwise exceed the two-helper
per-UID ceiling.

As host root:

```sh
useradd --uid 1200 --create-home --shell /usr/sbin/nologin phase4req
useradd --uid 1300 --create-home --shell /usr/sbin/nologin phase4dst
python3 /usr/share/doc/sigrund/namespace-phase4/prepare-installed.py \
  --requester phase4req --state-dir /var/lib/sigrund-v3 \
  --log-path /var/log/sigrund-v3/audit.jsonl
systemctl start sigrund.service
```

The provisioning script refuses existing or partial config/state/log sets,
loads the three packaged policy modules, writes independently scoped daemon and
signer rules and creates a root-only SSH signing key. These software-key settings
are for the disposable qualification deployment. Review the generated config and
signer rules before starting. The daemon requires its exact producer context and
enforcing requester/workload contexts before publishing listeners.

Build distinct example bytes at the same command path, then create the source
and destination trees. These commands use the shipped recipe, without starting
the verification runner:

```sh
mkdir -p /usr/local/libexec/sigrund-phase4
cc -static -O2 -DDESTINATION='"host"' \
  /usr/share/doc/sigrund/namespace-phase4/workload.c \
  -o /usr/local/libexec/sigrund-phase4/tool
cc -static -O2 -DDESTINATION='"A"' \
  /usr/share/doc/sigrund/namespace-phase4/workload.c -o /var/tmp/tool-a
cc -static -O2 -DDESTINATION='"B"' \
  /usr/share/doc/sigrund/namespace-phase4/workload.c -o /var/tmp/tool-b
restorecon -RF /usr/local/libexec/sigrund-phase4
python3 /usr/share/doc/sigrund/namespace-phase4/environment.py create a \
  --owner phase4req --workload /var/tmp/tool-a
python3 /usr/share/doc/sigrund/namespace-phase4/environment.py create b \
  --owner phase4dst --workload /var/tmp/tool-b
python3 /usr/share/doc/sigrund/namespace-phase4/environment.py init b
python3 /usr/share/doc/sigrund/namespace-phase4/environment.py anchor b \
  --registration container-b
```

B's init runs independently before its disposable anchor is started with
`nsenter`. The host registers the anchor's host-visible PID within its bounded
rendezvous window. Revoking the anchor leaves B's init running. Each helper
service has a ten-minute ceiling for this disposable recipe. Record the actual
UID/GID maps from the retained acquisition; subordinate-ID allocation is host
specific. `/run/sigrund` and genuine selinuxfs are exposed by bind mounts. The
source can query the kernel AV API, without authority to load or weaken policy.

## Review and execute

In a separate host-root controlling terminal:

```sh
sigrund-approve --socket /run/sigrund/approve.sock \
  --epoch-file /var/lib/sigrund-v3/host-epoch.json \
  --identity /var/lib/sigrund-phase4-qualification/approver
```

Submit host → B from the host namespace in the restricted requester domain:

```sh
systemd-run --wait --pipe --collect --uid=phase4req \
  --property=SELinuxContext=system_u:system_r:sigrund_requester_t:s0 \
  /usr/bin/sigrun --socket /run/sigrund/client.sock \
  --target registered:container-b --security-profile namespace-selinux-v1 \
  --account phase4_service --cwd /srv/service \
  -- /usr/local/libexec/sigrund-phase4/tool
```

Submit real rootless A → B using the installed source client:

```sh
python3 /usr/share/doc/sigrund/namespace-phase4/environment.py client a -- \
  --target registered:container-b --security-profile namespace-selinux-v1 \
  --account phase4_service --cwd /srv/service \
  -- /usr/local/libexec/sigrund-phase4/tool
```

For A → self, replace `registered:container-b` with `self`. For A → host, use
`--target host --security-profile host-baseline --target-uid 65534
--target-gid 65534 --cwd /` in place of the namespace target/profile/account/cwd.
The host route uses its separately scoped host contract.
The installed producer policy moves host commands into `sigrund_host_workload_t`
before their first instruction; host commands do not inherit the daemon's socket
label authority. The existing host contract's ambient LSM policy still applies.

At the prompt, inspect the destination account, mapped credentials, retained
root/cwd, executable digest, security constraints and execution binding before
typing `yes`. `APPROVED` confirms durable consumption. Readiness and the exit
result follow separately. The namespace example prints destination A or B,
UID/GID 12001, empty groups, NNP=1, seccomp=2, the exact workload context and
EACCES for both `getppid` and the labeled denial sentinel. Its exit code is zero.
Private `EXEC_READY_TO_EXEC` records contain the actual exec-stop facts.

For public/private timeout correlation, pass `--status-fd 3` to a client invoked
from a shell with `3>status.jsonl`; use its execution ID to select
`PRIVATE_OUTCOME` records in `/var/log/sigrund-v3/audit.jsonl`. FD 3 must be distinct
from stdout/stderr. Denials retain the scheduled generic public `TIMEOUT`; the
private record gives its diagnosis. The installed verification runner records
the review ID and matching public/private audit outcomes automatically.

## Withdraw, restart and retry

Append `wait` after the example command to create a running workload and its
forked descendant. Revoke during review or while it runs:

```sh
sigrundctl target revoke container-b --socket /run/sigrund/client.sock
```

Review revocation creates no consumption or child. Running revocation kills the
whole job and retains consumption. The disposable anchor exits while B's init
continues. Start a fresh anchor with the earlier `anchor b --registration` command
to register the retained environment again.

After a daemon restart or policy replacement, the old binding is unusable.
Systemd recreates the socket directory; the old B mount still references its
retired inode. For this recipe, stop the anchor/init units, start B's init again
and register a fresh anchor. Existing running jobs must be drained before policy
replacement. Policy-change detection and termination do not serialize policy
replacement with every workload instruction.

Optional automated evidence uses the same installed tools and actual TTY
approver. It changes enforcement settings temporarily on this disposable host
and restores them in cleanup:

```sh
python3 /usr/share/doc/sigrund/namespace-phase4/verify-installed.py \
  --artifacts /var/tmp/NEW-phase4-evidence --lifecycle --security
  # Add --exclusions to include raw full/signed and counterfeit-peer cases.
python3 /usr/share/doc/sigrund/namespace-phase4/verify-source.py \
  --artifacts /var/tmp/NEW-phase4-source-evidence
```

The source runner verifies connection-time attribution after a rootless source
passes its stream to a host-root writer, then kills only a captured self
connector while its relay remains alive. Actual forked descendants are identified
with kernel pidfd information and their exit is observed through retained pidfds.

For consumption/audit/collector digest equality, run the shipped
`verify-bindings.py` with `--collector` pointing at the collector binary from the
same checked source/build and a new `--artifacts` directory. This validates the
collector's binding schema; the local-approval profile does not claim a remote
collector acknowledgment or forward-secure local audit.

Stop the `sigrund-phase4-*-client`, `*-anchor` and `*-init` units before removing
the trees. Unmount each tree's `run/sigrund`, `sys/fs/selinux` and `dev/null` bind
mounts first. Keep config/state/logs together if preserving this provisioning set.
