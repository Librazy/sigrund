# Privileged interpreters and namespace-aware execution

Design discussion recorded on 2026-10-31. These notes capture the intended
separation of authorization, execution and destination routing. They propose
follow-on work; they do not add protocol fields, CLI options or implementation
claims to the current specification or MVP roadmap.

The motivating use case is replacing a fragile personal pkexec workflow with
one request, a root-TTY confirmation and SSH signature, execution, and a returned
exit status. Supporting programmable commands and containers should preserve
that clear approval boundary.

## Privileged interpreters

The elevation mechanism should execute the approved request and enforce its
credentials and lifecycle. Deciding whether to grant an interpreter broad
authority belongs to signer/deployment policy and informed approval. The
mechanism cannot generally determine whether arbitrary Bash, Python, Node or
native code is safe.

Approving an interpreter delegates programmable authority within the granted
credentials and execution environment. Host UID 0 with reduced capabilities
still has substantial ownership-based authority, although it does not thereby
regain every Linux capability. The existing specification's Section 1.1
qualifies containment and describes the script/dynamic-dependency boundary.

### What the signature authenticates

| Request form | Authenticated inputs and remaining boundary |
| --- | --- |
| `python -c '…'` or `bash -c '…'` | Signed argv binds the inline code. Imported modules, sourced files, subprocesses and other dependencies can remain mutable. |
| `python script.py` | The interpreter snapshot and signed script pathname are bound. The script's contents are not authenticated by the interpreter digest. |
| Interpreter reading sealed stdin | The signed stdin digest binds those input bytes. Additional files and dependencies remain outside that snapshot. |
| Interpreter reading live stdin | Approval delegates execution of future caller-supplied input; it does not approve a fixed program body. |
| Direct shebang script | A future script execution contract must define which script/interpreter bytes and dependencies it authenticates. The MVP currently rejects direct scripts. |

`allow_interpreted_script = false` is not an interpreter prohibition. Bash,
Python and Node are themselves ELF executables and may receive code through
arguments, files or stdin. Native programs can expose equivalent command
execution or privileged file-write behavior, so an interpreter blacklist
cannot establish narrow authority.

For personal interactive elevation, explicitly approving broad programmable
authority is a reasonable use case. For narrowly delegated automation,
prefer a trusted task-specific helper with a constrained interface. If fixed
script artifacts are needed later, define their snapshots, signed digests
and delivery to the interpreter explicitly. Authenticating a script does not
automatically authenticate its modules, packages, libraries or configuration.

Approval presentation should make fixed versus future caller-controlled inputs
clear, along with target credentials, stdin policy, cwd and environment. An
executable digest proves byte identity; it does not prove limited effects.
Interpreter heuristics may help presentation but must not become a security
claim or a substitute for reviewing the complete request.

## Execution destinations and namespaces

Root is relative to a user namespace. Paths, process visibility, networking,
capabilities and UID/GID mappings also depend on execution context. A target
UID alone cannot identify where an approved command will run.

The proposed first extension is one independently identified daemon execution
domain per host or container, with routing to the destination daemon. A domain
is a configured authority and execution context, not a caller-supplied label
or a single namespace inode.

| Request origin and destination | Authority that validates and executes |
| --- | --- |
| Host to host | Host daemon |
| Host to container A | Container A's daemon |
| Container A to itself | Container A's daemon |
| Container A to host | Host daemon through an explicitly exposed route |
| Container A to container B | Container B's daemon through an explicitly authorized route |

These are proposed deployment arrangements, not currently implemented routing
modes. A privileged container can also request another destination, but its
privilege is not an automatic grant from that destination's policy. Equally,
a host daemon cannot claim isolation from a privileged container that already
has effective control over the host, daemon state or management interfaces.

### Required destination contracts

1. **Signed destination identity.** Every domain needs unique provisioned
   identity and state. The existing `host_id` can bind a destination daemon
   when identities are unique, but it does not describe a namespace set or
   authenticate container origin. Containers must not share provisioned host
   identity/state as a shortcut. A future schema must explicitly bind any
   selectable execution context that one daemon can serve.
2. **Requester identity in the destination's terms.** Container UID 0 is not
   automatically host root. `SO_PEERCRED` provides kernel credentials as seen
   by the receiver; it does not establish a trustworthy container name or a
   complete source-domain identity. UID mappings, unmapped credentials and
   any proxy's authentication/delegation rules need explicit contracts.
3. **Destination-local preparation.** Resolve executable roots, seal inputs,
   interpret cwd, construct environment and apply target identities in the
   destination context. Never approve a host snapshot and silently execute a
   different container file with the same pathname. Policy must also define
   whose filesystem supplies any script or file inputs.
4. **Visible approval and authoritative policy.** Display the verified
   destination before signing, distinguishing host root from container root.
   Endpoint reachability and possession of a signing key do not override the
   destination's signer/requester policy. A destination label is presentation,
   not proof of identity.
5. **Bounded routing and lifecycle.** Define which daemon owns admission,
   one-time consumption, audit, cancellation and cleanup across a route.
   Existing local socket/SCM_RIGHTS semantics cannot simply be assumed for a
   proxy or remote transport. Cross-host descriptor transfer is not available
   through Unix ancillary messages.

For a daemon inside a container, UID 0 on its approval socket is authority in
that deployment's namespace context. It must not be presented as proof of
host-root approval. Cross-domain approval requires a separately defined trust
relationship; forwarding claimed UIDs is insufficient.

### Containers without an internal daemon

A later host-managed executor could use a trusted runtime adapter to execute
inside registered containers. This is a separate namespace-transition design,
not permission to accept an arbitrary PID and call `setns()`.

That design needs trusted container registration, pinned namespace and root
descriptors, container instance/generation binding, UID/GID mappings, namespace
entry ordering, destination cgroup ownership, process reaping and teardown.
Replacement or restart between approval and spawn must not redirect the grant
to another container. PID reuse must not redirect namespace selection.
Mutable root filesystems and runtime-management sockets remain trust boundaries
even after namespace descriptors are pinned.

Namespace entry must occur in a dedicated execution path, preserving the
coordinator's nonblocking and namespace invariants. User/PID namespace rules,
runtime security policy and the required child-creation sequence need their
own design and tests before such an adapter can be enabled.

## MVP boundary and follow-on gates

Complete Phase 5C/5D and the two-UID end-to-end fixture using execution in the
daemon's configured domain, with the existing documented child-isolation
changes. This boundary does not automatically follow the requester's
namespaces or add cross-domain routing. Phase 5C now wires live requester execution, with real runtime/service
acceptance still pending; these notes do not establish that acceptance.

Before extending that boundary, decide whether independently deployed daemons
or a host runtime adapter serve each supported destination, and version any
needed signed identity/context fields. Useful follow-on verification includes:

- Inline code versus mutable script paths and sealed versus live stdin;
  direct-script rejection must not be mistaken for interpreter blocking.
- Host/container destination substitution and cross-domain warrant replay.
- Mapped and unmapped requester credentials, including container UID 0.
- Container restart, replacement and PID reuse between approval and spawn.
- Executable/cwd resolution in the destination and misleading display labels.
- Route loss, cancellation, replay consumption, audit and cleanup ownership.

These gates require additional design and implementation after the current
MVP; they are not satisfied by the existing namespace-root or Phase 5A/5B
platform tests.
