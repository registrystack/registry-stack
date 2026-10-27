# Earlier appointment alert project

This project composes an earlier-appointment alert from a source subscription,
Scheduling availability and Messaging. One run evaluates one source-owned
condition. A small source-side scheduler may start at most three runs at
prevalidated instants, at least five minutes apart and within one day. Each planned start leaves the workflow's full ten-minute
deadline before the exact source expiry. The workflow contains no cycle or
native Scheduling completion wait.

The adjacent BReg project owns the subscription and its durable state machine:

```text
active -> claimed -> dispatching -> notified
   |          |             |
   +----------+-------------+-> withdrawn
```

`conditionId` identifies one subscription revision. A new preference or new
consent creates a new condition; an old condition is never reset. `claim-alert`
atomically admits one run, and `authorize-alert-dispatch` rechecks consent and
calendar-date expiry before the external effect. A different run that sees
`dispatching` finishes with `existing-run-owns-dispatch`. If Messaging's answer
is lost, only the original Coordinator run may `retry-same` or reconcile its
saved command.

The workflow reads the appointment through the `appointment-detail`
connection, which must exchange a current grant containing `appointment.read`
for the appointment's retained service and location. For the source-managed
appointment used here, the grant also carries a signed `schedulingManager`
that Scheduling binds to the stored manager. The workflow selects one
appointment ID from the source subscription; the grant itself is not bound to
an appointment ID. The separate `catalogue` connection has public read scope
and calls `scheduling.preview-availability/v1` without a grant. No operational
profile is configured or reused. The preview contains the full duration, party
counts, primary allocation and required additional allocation.

The source and appointment are reread after the initial claim. Capacity is
previewed again, then BReg atomically authorizes dispatch. The source and
appointment are read once more immediately before Messaging submission.
Cancellation, rescheduling, withdrawal, expiry, or full-bundle loss suppresses
the alert when observed before that point. A change after the last read can
race with dispatch because these products do not share a transaction.

From the repository root, run:

```sh
bregctl check \
  products/coordinator/examples/earlier-appointment-alerts/source-registry
bregctl generate actions \
  products/coordinator/examples/earlier-appointment-alerts/source-registry \
  --output /new/scratch/path
bregctl generate schemas \
  products/coordinator/examples/earlier-appointment-alerts/source-registry \
  --output /new/record-contracts
messagingctl generate templates \
  --project products/coordinator/examples/earlier-appointment-alerts/notices \
  --output /new/notices.contract.json
coordinatorctl check \
  --project products/coordinator/examples/earlier-appointment-alerts --explain
coordinatorctl test \
  --project products/coordinator/examples/earlier-appointment-alerts
```

The committed `generated/alerts.contract.json` and `generated/alert-subscription.schema.json`
come from the adjacent source project. The record import checks the fake replies' API field
names while allowing fields hidden by access policy. `generated/notices.contract.json` comes
from the adjacent `notices` Messaging project and checks the notice's computed template data
and locale. Copy regenerated contracts into those paths when you change either owning project.
Messaging's own access profile still authorizes the live call.

The deterministic scenarios cover an accepted complete-bundle alert,
withdrawal after claim, a rescheduled appointment, cross-run dispatch
suppression, and an uncertain Messaging answer recovered with `retry-same`.
They do not prove live PostgreSQL guards, real signed grant status, Scheduling
capacity reads, or provider dispatch; no native-service proof covers this
example.
