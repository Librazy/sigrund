# User-Friendly Approval Process

Status: milestone 1 implemented. Recorded on 2026-11-18. The basic
`sigrund-approve-tui` and text approver share a client session for one live
request. See the [quick start](../QUICK_START.md#2-host-only-setup) for operator
instructions. Subsequent milestones below describe planned behavior.

## Goal

Make command approval easy to inspect and act on from a terminal, and explore
approval from a normal desktop session. A request should belong to the daemon
throughout its approval lifetime, so opening, closing or replacing an approver
does not lose an otherwise valid request. Multiple authorized approvers should
be able to view active requests and approve or reject them.

Administrator policy, requester intent and signer authority remain distinct.
Every accepted approval must bind the exact reviewed request and pass the
daemon's independent policy and signature checks before authorization.

## Baseline when the epic was recorded

- `sigrund-approve` combines socket handling, review-evidence validation, text
  rendering, terminal input and OpenSSH signing in
  [approver.rs](../crates/sigrund/src/approver.rs).
- The daemon admits one root approval connection and reserves one global
  approval slot. Other requests reaching an occupied slot fail internally;
  they are not queued, even if their clients remain connected until `TIMEOUT`.
- The [approval protocol](../crates/sigrund-core/src/approval.rs) pushes one
  `ApprovalRequest` and accepts an approved or rejected response. It has no
  enumeration, lookup, subscription, resume or decision-acknowledgement operation.
- An interrupted approval exchange fails the request. Reconnection waits for
  a fresh request rather than recovering the interrupted one.
- The [host epoch registry](../crates/sigrund/src/host_registry.rs) publishes
  one current host or process review record. Supporting concurrent requests
  also requires replacing this single-request evidence publication model.

## Scope and workstreams

### 0. Shared approval client layer and standalone TUI

Refactor `sigrund-approve` into reusable protocol/session handling and separate
presentation layers. Keep the existing text client and introduce a standalone
TUI binary; the proposed name is `sigrund-approve-tui`.

The shared layer should own transport authentication, framing, request and
evidence validation, deadlines, session synchronization, decision submission and
acknowledgements. Keep signing behind a reusable interface so presentation code
does not construct signed payloads or duplicate cryptographic checks. Document
the interface and wire contract sufficiently for third-party approval clients.

The TUI should provide an active-request list, a scrollable request detail view,
explicit approve/reject actions, remaining approval time and connection state.
Show requester identity, target environment, resolved command and argument
boundaries, target credentials, capabilities, security profile, stdin policy,
signer identity and verified evidence. Make complete request details accessible
and prominently identify broad authority such as full host root access.

The standalone TUI opens with a compact human review, with separate Arguments,
Environment, Access and Evidence pages selected by `1`–`5`. Machine verification
records remain in Evidence; the default page shows a bounded argument preview
with an explicit notice when arguments are omitted. Arguments retains every
indexed value. Colors and text markers describe verified scope and authority,
without implying that an executable or command has safe behavior. Confirmation
returns to the review page and requires a fresh explicit decision.

Acceptance criteria:

- Text and TUI clients use the same validation and submission logic.
- Request text cannot inject terminal controls or disguise argument boundaries;
  long values remain inspectable without silent truncation.
- Selection changes, refreshes and buffered input cannot approve a different
  request from the one explicitly confirmed.
- The signing view prints the full executable and signer to the primary terminal
  buffer before OpenSSH takes input. Status messages, PIN prompts and failure
  diagnostics share the same terminal, in order. Normal exit, errors and
  cancellation restore the terminal state.
- The UI distinguishes a local signing action, a submitted decision, daemon
  authorization and execution status. It claims only states confirmed by the
  relevant interface.

### 1. Multiple concurrent approval requests

Replace the single approval slot with a bounded set of daemon-owned requests.
Multiple requests must remain independently reviewable and actionable, including
when no approver is connected. Admission and retained-resource limits must cover
both global usage and per-requester usage, with documented overload behavior.

Each entry must retain its immutable CSR, exact review evidence, original
deadline and execution resources. Review evidence must be indexed and validated
per request, including daemon epoch and CSR binding, so concurrent publication
cannot overwrite another request's evidence. Account for retained executable
and stdin descriptors, namespace handles, stopped targets, leases, memory,
workers and cleanup capacity rather than counting only queue entries.

Acceptance criteria:

- At least two independent requests can remain pending and be decided in either
  order without mixing commands, signatures, evidence or execution resources.
- A request admitted without a connected approver is visible when an authorized
  approver connects before its deadline.
- Expiring, cancelling or rejecting one request does not end unrelated requests.
- Capacity exhaustion has bounded resource use and documented requester-visible
  behavior; a slow approver cannot block admission or cleanup for all requests.
- Cleanup remains accounted for until resources are actually released.

### 2. Discoverable requests and recoverable approval sessions

Extend `approve.sock` so a newly connected client can list active requests,
retrieve a specific request and its evidence, observe changes and submit an
approval or rejection for an existing, non-expired request. Specify protocol
versioning, message bounds, error responses and compatibility with the existing
text client before rollout. Exact operation names and message schemas remain
design work.

Separate the lifetime of an approval-client connection from the lifetime of the
request. Closing a UI, losing its socket, abandoning a prompt or failing a local
signing attempt must not automatically fail an otherwise valid pending request.
An incomplete or malformed client exchange must not consume that request's
approval opportunity. A subsequent authorized client can retrieve and act on it
within the original deadline.

Expiry, explicit rejection, requester cancellation/disconnection and invalidated
execution prerequisites still terminate pending work under the applicable
lifecycle rules. Reconnection never extends deadlines or revives terminal
requests. This epic requires recovery across approval-client connections;
recovery across daemon restart is a separate design decision because execution
resources and evidence are bound to a live daemon epoch.

Acceptance criteria:

- Disconnect before submitting a complete valid decision, reconnect with a new
  client and decide the same still-valid request successfully.
- After a lost decision acknowledgement, a client can determine the authoritative
  outcome. Retrying cannot create a second authorization or execution.
- Initial enumeration plus change observation has defined synchronization and
  resynchronization semantics, so clients do not silently miss intervening events.
- Expired or invalidated requests cannot be approved from a stale detail view.
- Define bounded retention of decision results for reconciliation; request
  lookup does not imply an unlimited historical audit API.

### 3. Multiple simultaneous approver clients

Allow multiple authenticated approver clients to connect concurrently. Any
client authorized for a request can view it and submit an approval or rejection.
Viewing a request does not exclusively claim it, and one client's disconnect
does not withdraw the request from other clients.

Decision handling must serialize competing actions against authoritative daemon
state. The proposed rule is that the first valid decision atomically accepted
by the daemon wins. Validate the client's authority, request binding, deadline
and, for approval, signature before accepting a decision; receiving an invalid
submission must not reserve or resolve the request. Specify how this acceptance
interacts with the existing durable authorization commit and failure handling.

Acceptance criteria:

- Two clients can inspect the same pending request; either can decide it.
- Approve/approve and approve/reject races yield one accepted decision. Other
  clients receive the current outcome and cannot overwrite it.
- Duplicate submissions, late signatures and retries after lost responses never
  cause duplicate consumption or execution.
- All observing clients learn when a request is decided, expired, cancelled or
  invalidated; slow consumers have bounded buffers and a resynchronization path.
- Authorization and audit records distinguish the authenticated submitting client
  from the cryptographic signer where those identities differ.

Multiple clients do not imply multi-signature quorum approval or permission to
use arbitrary signer identities. Existing signer policy still governs which
signatures can authorize a request.

### 4. System D-Bus and a user-session GUI

Explore a system D-Bus interface and a graphical approval client running as a
normal desktop user. Produce a design and feasibility prototype that reuses the
same daemon-owned requests and decision semantics as terminal clients.

The exploration must address:

- Whether the daemon exposes D-Bus directly or a privileged adapter bridges to
  the approval service, and how service activation and lifecycle are managed.
- Authentication of callers and administrator-configured permissions to discover,
  read and decide requests. A desktop login alone must not grant approval power
  or access to every request's private command and environment data.
- How a user-session client obtains signing authority and interacts with keys,
  agents and hardware authenticators while preserving configured signer checks.
- Trust in the user-session UI, including requester and approver sharing a UID,
  session compromise, locked/inactive sessions and multiple logged-in users.
- SELinux policy, packaging, notifications and interoperability with simultaneous
  text and TUI clients.

Acceptance for this workstream is a documented architecture, trust model,
prototype findings and a decision on production GUI scope. The prototype should
demonstrate authorized request discovery and an approval/rejection round trip,
and test denial of unauthorized reads and decisions. If the proposed trust
boundary cannot be established, record that limitation and the required changes.
No GUI toolkit or D-Bus authorization mechanism is selected by this epic.

## Delivery sequence

1. **Implemented:** Extract the common client layer and build the standalone TUI against the
   existing single-request workflow. Establish presentation and terminal tests.
2. Design and implement the request registry, per-request evidence, lifecycle and
   versioned discovery/decision protocol together. Update both first-party
   clients to support concurrent requests and reconnection.
3. Enable concurrent approver clients with atomic decision arbitration,
   acknowledgements, synchronization and bounded result retention.
4. Complete D-Bus/GUI exploration using the established session semantics. Record
   the authorization design before enabling standard-user access.

Each milestone should update protocol documentation, deployment/upgrade guidance
and relevant acceptance tests. Existing clients must either remain compatible
through a documented path or fail clearly; never silently reinterpret messages.

## Cross-cutting validation and open decisions

Acceptance coverage must include host and namespace requests, concurrent evidence
publication, disconnects at each decision/commit boundary, cancellation during
signing, expiry races, stale daemon epochs, resource exhaustion and slow clients.
Retain signature validation, independent daemon/signer policy, one-time grant
consumption, audit and execution checks throughout the refactor.

Resolve these details in implementation proposals:

- Protocol version negotiation or endpoint migration, operation schemas and
  third-party client API packaging/versioning.
- Global/per-requester limits, fair admission, event backpressure and result
  retention durations.
- The exact decision linearization point, retry identity and outcome model around
  durable authorization and execution failure.
- How per-request review evidence is delivered and how legacy epoch readers are
  migrated.
- Whether daemon-restart recovery is feasible for any request class; it is not
  required for approval-client reconnection.
- User-session visibility, decision authority and signing-key custody for the
  D-Bus/GUI path.
