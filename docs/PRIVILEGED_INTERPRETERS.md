# Privileged interpreters

Design discussion recorded on 2026-10-31. This document explains interpreter
authorization and executable-evidence boundaries. Proposed artifact binding
and live-input behavior are follow-on design, not additions to the implemented
protocol or the [security specification](<../sigrun sigrund Security Architecture and Implementation Specification.md>).

The motivating use case is replacing a fragile personal pkexec workflow with
one request, a root-TTY confirmation and SSH signature, execution, and a returned
exit status. Approving programmable commands should preserve that clear
approval boundary.

## Authority and authenticated inputs

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

## Execution environment

The current local profile executes in the daemon's configured domain; it does
not automatically follow requester namespaces or cross container boundaries.
The proposed [namespace-aware execution design](NAMESPACE_AWARE_EXECUTION.md)
uses one host daemon to authorize execution in explicitly selected environments.
The destination and security constraints determine the authority delegated to
an interpreter. Container root and host root must be distinguished at approval.

## Follow-on verification

Future interpreter and input extensions need acceptance scenarios covering:

- Signed inline code versus mutable script pathnames, imports and libraries.
- Sealed stdin versus future caller-controlled live input. The current local
  profile supports finite sealed input, not live interactive sessions.
- Direct-script rejection without misrepresenting it as interpreter blocking.
- Any future script snapshot/delivery mechanism and its remaining dependency
  boundary.
- Approval presentation of target credentials, execution environment and
  fixed versus future caller-controlled inputs.

These scenarios do not establish namespace-aware execution support. Current
implementation scope and test entry points are described in the
[implementation notes](../IMPLEMENTATION_NOTES.md).
