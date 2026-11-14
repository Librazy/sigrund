# Administrator-maintained OverlayFS qualification

The `namespace-admin-direct-v1` profile permits `digest_direct` for qualified
rootful containers sharing the host's initial user namespace. It extends the
administrator-maintained backing-store assumption previously used for host
ComposeFS. It does not extend `ctime` eligibility or claim kernel protection
against backing-file writes.

Enable it using the shipped
[`namespace-admin-direct-v1` profile](../config/namespace-admin-direct-profiles.toml.example)
and matching [signer rules](../config/namespace-admin-direct-signers.toml.example).
Daemon and signer independently authorize the profile digest. Storage evidence
is private to the captured request and approval; no backing paths are published
through public context. See [deployment instructions](../IMPLEMENTATION_NOTES.md#rootful-overlayfs-direct-execution).

## Required contract

Trusted administrators must preserve layer identities and their mounted
relationships, keep relevant backing paths root-managed, prevent untrusted
writable aliases and retained writable handles/mappings, and avoid modifying
active backing objects in place. This includes administrator actions through
approved privileged jobs. The administrators must be trusted for the actual
authority of those jobs.

Ownership, mode, ACL, filesystem, mount and object checks establish observable
conditions. They cannot establish historical handle absence or enforce future
administrator behavior. Mountinfo layer paths are discovery hints under this
contract. An apparently read-only merged view is insufficient.

## Reproduce

Run the ordinary checks as the workspace owner:

```sh
python3 scripts/check.py --artifacts /tmp/sigrund-overlay-checks
```

On a disposable systemd host, stage those binaries and the matching source tree.
Run the ignored kernel tests as initial-userns root in a private mount namespace:

```sh
unshare -m --propagation private /path/to/library-tests \
  overlay::tests::rootful_overlay --ignored --test-threads=1
python3 scripts/namespace/verify-overlay.py \
  --binaries /path/to/binaries --artifacts /root/overlay-results \
  --runtime podman --runtime docker
```

The runtime harness builds a local scratch image and uses privileged, unfiltered
fixture anchors. This qualifies the execution and storage path; it does not
claim equivalence to runtime-managed exec policy. Each artifact directory must
be new. `result.json` records the kernel, source digest, binary hashes, engine
versions, storage configuration and completed cases. Mount tables and private
audit/diagnostic logs accompany the result.

`--distrobox NAME` additionally tests an already initialized disposable rootful
Podman Distrobox. The harness copies three commands into its root and removes
them on completion. `--producer` uses the installed SELinux daemon producer and
checks the existing host workload domain without modifying policy or relabeling
container executables. For the native filesystem path, use
`scripts/namespace/verify-admin.py --direct`, optionally with `--producer`.

## Verification record

Local verification on 2026-11-13 passed all workspace checks, including 225 Rust
tests, 34 Python harness tests, Clippy with warnings denied, formatting and host
and namespace protocol vectors. Privileged tests are separately qualified below.

The disposable Fedora 44 x86_64 host ran kernel
`6.19.10-300.fc44.x86_64` with Btrfs backing storage. All five kernel OverlayFS
tests passed. They cover lower/upper/metacopy/data-only resolution, management
links, redirects, whiteouts, opacity, copy-up and replacement, unsafe modes and
ACLs, nested mounts, cancellation, digest changes despite stable merged
metadata, and loaded ELF-byte mismatch rejection.

The source digest reported by `scripts/check.py` and the final runtime
fixtures was `b2c26ef133436a41ec9a099f36cd2e8ce497668c9a09dc581fac9315c2376e40`.
The staged daemon SHA-256 was
`716d7e26dff7a0c1e173c562fdfb1957228d556128564a353716ca32a0c72a38`.
After adding the configuration examples and this record to package staging,
the complete local checks passed again with source digest
`ebf41d0ddac5172d1dffc3cf8ce59346731915e72a8602a7a0505b7cc034478a`.
The executable sources and runtime test harness were unchanged by that
packaging adjustment.

Rootful Distrobox 1.8.2.5 on Podman 5.8.1 passed all four cases: self execution,
registered execution as UID 0 and UID 33 with supplementary group 104, and
disconnect cancellation. This used an actual Fedora 44 Distrobox with an upper
executable. Hidden cgroup aliases beneath the launcher's private `/run` and a
covered `/sys/fs/cgroup` mount are distinguished from the child's visible mount;
visible cgroups retain the restriction checks.

With the installed SELinux producer, Podman 5.8.1 (crun 1.27) and Docker 29.9.3
(containerd OverlayFS snapshotter) passed all 34 runtime cases. Each engine
passed 17 cases: four self executions, eight registered executions across root
and nonroot credentials, three approval-time copy-up/replacement rejections,
disconnect cancellation and rejection of a visible writable cgroup alias.
All 26 successful executions entered
`system_u:system_r:sigrund_host_workload_t:s0`. No SELinux policy or container
executable labels were changed to obtain these results.

Podman exercised an actual metacopy object with `metacopy=on`. Docker's default
snapshotter had no metacopy option, so its chmod case exercised full copy-up;
that run does not qualify Docker metacopy. The tests used local scratch images
and verified both storage evidence in private review and matching AUTH_COMMIT
audit evidence.

The native-filesystem direct profile passed all 13 admin-producer cases,
including credential/group/capability parity, owner/group writes, self execution,
reserved producer/socket protections, cancellation, consumed-approval replay,
registration revocation and remapped-user-namespace rejection. That run preceded
the final cgroup-shadow verification adjustment.

The write-exclusion fixture observed:

| Retained writer or alias | Exec result |
| --- | --- |
| Writable FD opened through the merged path | `ETXTBSY` |
| Shared writable mapping through the merged path, after closing that FD | Allowed |
| Writable FD opened directly on backing | Allowed |
| Shared writable backing mapping after closing its FD | Allowed |
| Writable FD opened through a bind alias of backing | Allowed |

Opening a merged-path writer while the command is stopped at the exec event also
returned `ETXTBSY`; opening its real lower backing for write succeeded. These are
observations for this kernel, not a write-exclusion guarantee for OverlayFS.

## Boundaries

Only the separate, explicitly authorized direct admin schema enables this
exception. Existing memfd, rootless/remapped and other namespace profiles retain
their contracts. Namespace full CSR, offline/export requests, file capabilities,
set-ID files, userxattr, idmapped or nested backing mounts, inaccessible layer
paths and unknown mount options are unsupported. ELF load verification currently
requires little-endian ELF64. Kernel support for statx/statmount and the target
mount namespace ID query is required; unavailable evidence rejects the request.

Discovery has fixed size and traversal limits and uses existing request quotas,
deadlines and cancellation ownership. A layout within the 128-layer parser bound
can still exceed the FD budget, especially with concurrent requests or retained
targets; capacity rejection does not enable a different trust model. Native
filesystem execution continues using the ordinary direct-executable contract.

Additional kernels, architectures, backing filesystems and production image
layouts require their own runtime qualification. SELinux can reject original
container labels; the storage exception does not override that decision.
