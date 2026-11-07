# Namespace-aware execution Phase 1 implementation record

Updated 2026-11-07. **Phase 1 is complete for the qualified v3 host profile.** The production daemon, client,
approver, configuration and durable state now use v3. Only the host target is
implemented. Container, process, registered and `self` targets are rejected.
The final ordinary, privileged and integrated acceptance gates passed; the
completion audit and V-01–V-20 dispositions are recorded below.

## Implemented host path

The canonical warrant preserves the complete original intent alongside resolved
numeric credentials, executable evidence and one immutable security profile.
The warrant digest covers all of those fields. A separate execution-binding
digest covers exactly canonical `{target_binding, security_constraints}`.
Consumption stores that digest as 32 raw bytes; AUTH_COMMIT and collector
`target_auth` use lowercase hex. Both daemon policy and one signer's scoped rule
must independently authorize the target credentials and profile.

After recovery and startup probes, the daemon allocates a fresh UUIDv7 epoch and
host instance, retaining the host root, executable roots, namespaces and initial
identity mappings. Preparation, review, authorization and job cleanup retain the
same owner; authorization and spawn revalidate it. Restart invalidates prior
bindings even when their grant has not expired. Account names resolve once from
bounded, trusted host passwd/group data. Numeric selection preserves the exact
requested sorted supplementary groups.

The explicitly versioned host acquisition and constraint records describe the
current native executor: private mount/cgroup isolation, exact credentials and
capabilities, securebits `0x2f`, NNP, finite cgroup limits and the selected
executable model's actual checkpoint obligations. Profiles requiring namespace
joins, an LSM transition or a seccomp filter are rejected. `CAP_SYS_ADMIN` is
unsupported by this host constraint version because the existing executor's
administrative-capability path does not provide the declared private isolation.
Startup rejects a profile if its required checkpoint or kernel capabilities
are unavailable, before publishing the epoch or listeners. The shipped baseline
uses `digest_memfd`, without claiming an exec stop. Direct models require the
startup-qualified exec checkpoint. Host target leases/FDs/helpers/reviews compose
with existing admission, worker, RAM and audit limits and remain owned through
close/reap. Their hard global/per-UID ceilings are respectively `64/4`,
`2048/128`, `16/2` and `16/2`. Startup pins and transient inherited FD copies
are charged before acquisition/fork. Accounting can conservatively exhaust a
ceiling before every nominal target slot is occupied. The local broker retains
its single outstanding review limit.

The client requires `--target host`, an account selection and a security profile.
A deliberate administrator-distributed binding bundle enables local full
preparation/export. Without usable local evidence, ordinary unsigned submission
falls back to the unchanged thin intent; full-only/export fail locally. Signed
input never falls back. The root approver verifies acquisition/profile records
from the locked root-controlled live epoch before rendering the complete intent,
resolved fields and host evidence with escaped strings and indexed arguments.

Thin refusal and authorization failures retain the admission-based deadline and
generic TIMEOUT response. Explicit mandator refusal of a validated full CSR
returns immediate REJECTED, with its reason kept private. Committed grants remain consumed after every later failure;
spawn requires complete APPROVED delivery. Authenticated requester facts,
approved target facts and observed execution facts remain separate in private
audit records.

## Explicit v3 provisioning and binding export

Preserve previous state and logs as a separate set. There is no automatic
migration, adoption, deletion or package-time initialization. Select new absolute
state and log locations, both empty, including SQLite and ratchet sidecars:

```sh
sigrundctl init-host --state-dir /var/lib/sigrund-v3 \
  --log-path /var/log/sigrund-v3/audit.jsonl
```

Retain the printed audit anchor privately. Install root-controlled v3 config and
signer policy, enable the local `[mvp]` profile with an explicit signer, and pass
these state/log paths to the delegated systemd service. Startup rejects missing,
old, future and mixed state before listeners appear. The daemon writes its
root-only live epoch file into the selected state directory.

For local full/export workflows, root creates a new mode-0600 bundle file from
the live daemon. Distribution to the intended requester is a separate deliberate
administrator action; bundle contents are private target evidence:

```sh
sigrundctl target export-binding host --security-profile host-baseline \
  --epoch-file /var/lib/sigrund-v3/host-epoch.json \
  --output /root/host-baseline-binding.json
```

After distribution, the requester can explicitly use the trusted bundle:

```sh
sigrun --target host --security-profile host-baseline \
  --target-uid 33 --target-gid 33 --supplementary-gid 33 \
  --binding-bundle /path/to/distributed-binding.json -- /usr/bin/id
```

Use `--account NAME` instead of numeric credential options for named selection.
The root watcher must use the same state set, for example
`--epoch-file /var/lib/sigrund-v3/host-epoch.json`. Export again after restart or
profile changes. `.context` remains target-independent and is not a binding
bundle distribution endpoint.

The bundle is explicitly trusted administrator input. The client checks its
authority against public host context, its acquisition/profile digests and the
local root, namespace and mapping evidence. Public context deliberately contains
no epoch or target-discovery information: local offline export can therefore
preserve a stale bundle's epoch. Redemption still rejects it; the client never
silently refreshes signed bytes or changes the executable model.

Offline signing preserves the exported CSR bytes:

```sh
sigrun --target host --security-profile host-baseline \
  --target-uid 33 --target-gid 33 --binding-bundle /path/to/distributed-binding.json \
  --export-csr request.csr -- /usr/bin/id
sigrundctl csr-pae --csr request.csr --pae request.pae
ssh-keygen -Y sign -n sigrun.warrant.v3 -O hashalg=sha512 -f /path/to/identity request.pae
sigrundctl pack-warrant --csr request.csr --signature request.pae.sig \
  --signer-id mandator-alice-yubikey --output request.warrant
sigrun --warrant request.warrant
```

## Completed qualification

The checked-in [sanitized evidence record](evidence/namespace-phase1-host-20261107.json)
records commands, source/binary/test hashes, individual gate results and the
supervisor cleanup result. Raw logs, manifests and traces are retained privately
under `/tmp/sigrund-phase1-evidence`; keys, anchors, databases and raw private
approval evidence are not checked in.

The final source snapshot is
`84bdd0dffddbd8cde12dbffe8414b41efc45c2444677ca9745dc0f91aa9271ed`, using
the path/NUL/content/NUL algorithm in `scripts/check.py`. This covers Cargo
inputs, crates, scripts, config and packaging; documentation is outside that
digest. Ordinary verification used Rust/Cargo 1.99.1 on Fedora x86_64,
kernel `7.2.15-300.fc45.x86_64`:

```sh
python3 scripts/check.py --artifacts /tmp/sigrund-phase1-checks-candidate9-20261107
```

All ten checks passed: locked build/workspace tests, Clippy with warnings denied,
formatting, diff whitespace, Python compilation, 25 harness tests, independent
host vectors, frozen Phase 0 vectors and platform-test build. There were 171
ordinary Rust test passes. Privileged tests and child-only fixtures are listed
as ignored in the ordinary run; the production host gates were then explicitly
executed below. Historical Phase 0 vectors remain unchanged.

Privileged qualification used a disposable Fedora 44 x86_64 VM, kernel
`6.19.10-300.fc44.x86_64`, glibc 2.43, initial identity UID/GID maps, unified
cgroup v2 with delegated memory/pids, and enforcing SELinux. Supervisors used
`unconfined_u:unconfined_r:unconfined_t:s0-s0:c0.c1023`. This qualifies native
host execution on an enforcing system; target LSM confinement is not part of
this profile. Fs-verity used ext4 with 4-KiB blocks and verity enabled, with both
SHA-256 and SHA-512. Other architectures/filesystems are not certified by this run.

From `/home/lab/sigrund-phase1`, the acceptance command was:

```sh
python3 scripts/verify-acceptance.py \
  --binaries /home/lab/sigrund-phase1/target/debug \
  --checks /home/lab/sigrund-phase1/checks-candidate9.json \
  --artifacts /home/lab/sigrund-phase1/acceptance-final11-artifacts --requester lab
```

It passed the platform gate, 13 runtime lifecycle/systemd cases, native v3
confidentiality/access cases, all seven executable-trust gates, 26 execution
cases with 47 strace files, and the integrated binding/offline/replay/quota/
context/input/account/profile/output/recovery/operator scenarios. The complete
entry point returned success and its delegated supervisor cgroup was removed.

The separate privileged Rust command was:

```sh
python3 scripts/verify-phase1-rust.py \
  --daemon-tests /home/lab/sigrund-phase1/target/debug/deps/daemon-d3a936486236a676 \
  --library-tests /home/lab/sigrund-phase1/target/debug/deps/sigrund-51ba23e59c78f6b4 \
  --artifacts /home/lab/sigrund-phase1/rust-final10-artifacts
```

All nine gates passed, including production raw sockets, deadline/late-commit
races, partial approval delivery, revocation, root TTY display/signing,
provisioning/version rejection, storage/recovery and live private review
records. Each selected test had to report one actual pass. The final script-only
SQLite fixture correction changed no Rust inputs or compiled test/production
binaries; their hashes match the final ordinary and acceptance manifests.

Two additional existing privileged ComposeFS tests passed on that same library
binary. Each ran as root under `unshare --mount --propagation private`, with
`--exact NAME --ignored --nocapture --test-threads=1`:

- `composefs::tests::privileged_store_protection_and_bounds`
- `executable::tests::composefs_rehash_detects_data_changes_hidden_by_metacopy`

These verify store protections and metacopy rehashing on the real overlay
filesystem. They do not qualify arbitrary administrator-maintained stores.
All privileged runs used independently bounded systemd services with whole
cgroup cleanup. No skipped production host case or prototype substitutes for
the evidence above.

## Completion audit against the approved plan

| Deliverable | Implementation and observed result |
| --- | --- |
| Strict host contract | Production core v3 schemas, canonical signed bytes and host-specific versioned records; independent JCS/intent/PAE/OpenSSH/two-digest fixtures pass. Old/missing/future versions and unsupported enforcement fail closed. Phase 0 records remain independent. |
| One live owner | Post-probe epoch and instance retain pinned root/namespace/mapping evidence through preparation, review, authorization, spawn and cleanup. Restart/substitution tests deny stale bindings; final identity/policy rechecks and actual blocked-cleanup quota ownership pass. |
| Same client/approver binding | Explicit host/account/profile CLI, root-only new 0600 bundle export, bounded named resolution, exact numeric selection, unchanged thin fallback and local full-only/export refusal pass. Root TTY evidence verification/rendering, client-full and offline export/sign/redeem pass. Account/profile edits after preparation preserve the approved resolved values. |
| Coherent v3 durable cutover | Fresh explicit provisioning and missing/v2/future/mixed/partial startup tests pass before listeners. Consumption contains 32 raw digest bytes; AUTH_COMMIT and collector target_auth contain the identical lowercase hex. Independent audit/ratchet recomputation, partial-tail/crash recovery, replay/revocation and failure-after-commit tests pass. |
| Integrated evidence and docs | Final ordinary suite, privileged Rust gates and complete platform/runtime/v3/trust/execution/acceptance entry point pass on matching binaries. The roadmap contains the full V-01–V-20 disposition. Runnable docs describe fresh provisioning, live bundle distribution and offline signing. |

The [roadmap qualification matrix](NAMESPACE_AWARE_EXECUTION.md#phase-1-host-qualification-v-01v-20)
contains the disposition for every V case. Collector schema/validator coverage,
root TTY and independent stdio are the applicable portions of V-15/V-16/V-17;
remote ACK, hooks, PTY, reload, reusable grants and container execution remain
deferred and disabled. Authenticated security-key UP/UV flag verification is
tested with signed fixtures; physical FIDO device interaction is not qualified.

The rollback experiment restores a complete authentic old disposable dataset.
As documented, a local retained seed cannot detect coordinated rollback of all
state/log/ratchet files without an external checkpoint. The test demonstrates
that limit explicitly and verifies that the new epoch still rejects the old
warrant. It does not claim external rollback protection.

## Review corrections

The review follow-up verifies full-CSR named accounts against bounded host
account data before review, moves host checkpoint verification to workers,
excludes sibling-only FD copies from fork accounting, carries ComposeFS
enrollment in private bundles, rejects numeric groups with named accounts and
runs privileged Rust gates through the normal acceptance entry point. The
qualification above records the original source snapshot. Follow-up regression
results are recorded separately and do not replace that snapshot's hashes.
