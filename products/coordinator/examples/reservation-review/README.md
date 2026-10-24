# Reservation review and agreement

This maintained composition keeps the reservation source authoritative for the
request, review, agreement and final reservation outcome. Scheduling remains
the only capacity authority. The BReg package stores those as separate facts,
and the Coordinator workflow records product results back into that source.

`request-only/` submits review, records approval or rejection, completes a
deterministic agreement fixture when required, then attempts direct Scheduling
admission. Review and agreement do not reserve capacity. The Coordinator
scenario proves the successful native operation composition; it does not
simulate a commit-time Scheduling refusal.

A hold-based variant, which creates an ordinary Scheduling hold during review,
is a deployment choice and is not shipped here. It would record the hold's
`expiresAt` as the source-owned `decisionDeadline`, confirm the exact hold on
approval plus completed agreement, release it on rejection, withdrawal or
cancellation, and record `hold-expired` without confirming at or after the
deadline. The source registry models both capacity policies, and the
`scheduling_adapter` tests cover the Coordinator hold operations.

The agreement wait is a deterministic scenario boundary. It models only a
completed or failed external agreement result. It is not an agreement service, signature provider, legal determination or
authority grant.
Likewise, a source record or reviewer decision grants no Scheduling access.
Each Scheduling mutation uses Coordinator task authority to obtain a current,
action-bounded credential, and Scheduling decides each call under its own
policy.

The compiled service journey keeps administrative review and capacity
authority separate. Deciding the reservation review invalidates grants owned
by that review task. A distinct, current capacity-authorization task therefore
supplies the Scheduling grant for the exact reservation, location and allowed
actions. Its grant is neither created nor extended by the review decision.
Changing a source fact does not itself revoke a separate active Casework task
or grant. Deployments must close or revoke that
authority through Casework when its operational purpose ends.

## Recovery

Coordinator persists exact operation inputs before dispatch. Appointment
creation keeps its original idempotency key and recovers through the original
read-only receipt. A restart, duplicate callback or lost acknowledgment must
resume that command. It must not create another key or another appointment.
If an original receipt is unavailable, operators leave the source operation
unresolved and investigate. They do not infer absence from a missing receipt.
Scheduling receipt retention must cover the longest expected review period.

## Files and checks

`source-registry/registry.yaml` owns the source state machine. The generated
contracts inside each Coordinator project are derived from that package and
let `coordinatorctl` validate the BReg action calls without a live BReg server.
The Scheduling project and records the native proof uses are in `scheduling/`.
`runtime.yaml` shows separate least-privilege source, review, Scheduling and
Messaging connections with placeholder public deployment URLs.

From the repository root, check the source package and the project with the
maintained CLIs:

```sh
bregctl check products/coordinator/examples/reservation-review/source-registry
coordinatorctl check --project products/coordinator/examples/reservation-review/request-only
coordinatorctl test --project products/coordinator/examples/reservation-review/request-only
```

The scenarios are deterministic composition checks. They establish routing,
source action inputs and the approval and rejection branches.
They do not establish runtime authorization, PostgreSQL lock behavior or
product HTTP interoperability.

`test-native-services.py` is the separate compiled-service proof. It drives
BReg source actions, Casework review and capacity tasks, Coordinator execution,
Scheduling capacity and authorized Messaging through their public APIs. It
restarts Coordinator while reviews are pending, confirms one reservation,
records one rejection, reconciles a lost Scheduling response through the
original receipt, and retries a lost BReg response as the exact same command.
The agreement outcome remains a deterministic fixture. This journey proves
product interoperability; the focused PostgreSQL tests remain the proof for
lock ordering, hold expiry, owner retention and receipt retention.
