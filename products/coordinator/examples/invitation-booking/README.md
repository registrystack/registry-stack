# Invitation to book reference

This backend reference keeps the invitation in an authoritative Base Registry
Engine project, sends the invitation through Registry Messaging, and books only
after a current source claim and a separately authorized Registry Scheduling
capacity decision. It contains no guest claim route or user interface.

The reference has two Coordinator projects because issuance and acceptance are
different powers:

- `issue-invitation` is admitted only for an institutional issuer. It invokes
  the source-owned `issue-invitation` Action, rereads the created record, then
  submits one governed message. The message URL contains only the opaque BReg
  invitation record identifier. It carries no name, contact detail, beneficiary
  reference, task grant, access token or invitation capability.
- `accept-invitation` is admitted only for an institutional or source
  application that has already authenticated the person or representative and
  authorized this acceptance. The URL does not authenticate its visitor. This
  project deliberately does not accept a caller-supplied actor or beneficiary
  identifier as proof of a relationship.

The BReg project under `source-registry/` is reference configuration. An
institution may use an equivalent authoritative application, but it must retain
the same boundaries: current acceptance authorization and relationship facts
belong to the source, and Scheduling owns every capacity decision.

## Current decision and source claim

The source record contains one stable `acceptanceId`, unique within its issuer,
the bounded offering, location context, optional exact resource constraint,
source-owned beneficiary reference, current `acceptanceAuthorized` decision, relationship end date,
inclusive UTC `expiresOn` date, and state. The Action `claim-invitation`
atomically changes `issued` to `accepting` only while:

- state is still `issued`;
- the source's current acceptance decision is true;
- the current UTC date is on or before both `relationshipValidThrough` and
  `expiresOn`.

These are BReg server-date commit guards, not times supplied by the acceptance
request. `expiresOn` is date-granular and inclusive through that UTC calendar
date. This example makes no exact-instant expiry claim. An expiry worker may
invoke `expire-invitation` on the first later UTC date so ordinary reads return
the explicit `expired` state; the claim guard remains the authoritative refusal
if that maintenance is late.

Revocation and claim race on the same BReg row. `revoke-invitation` can change
only `issued` to `revoked`; `claim-invitation` can change only `issued` to
`accepting`. Exactly one transaction wins. Once state is `accepting`, a new
revocation cannot silently race a booking that may already have been sent.
Withdrawal then requires resolving the original Scheduling command and, when an
appointment exists, using the separately authorized Scheduling cancellation
lifecycle before recording a corresponding source transition. This bounded
reference does not pretend cancellation happened by rewriting the invitation.

BReg action handlers cannot inspect a stored row or the clock to construct a
precise declared-refusal reason. A state observed as `expired`, `revoked` or
ineligible has a named workflow outcome. If one of those facts changes between
the read and atomic claim, the guarded Action returns a generic source
precondition refusal and commits nothing. The producer rereads the source rather
than interpreting that refusal as a capacity result.

## Booking authority and allocation

After the claim, the workflow rereads the authoritative record. Search bounds,
service, party reference and optional exact resource come from that record,
not from the invitation URL or acceptance input. The source's `location` is
invitation context only. Scheduling resolves the operational location from its
current offering, and the Casework grant must authorize that exact location.
For an assigned resource, the source's current relationship decision is one
claim guard. The source-owned selected duration and opaque resource identifier
are hard Scheduling availability and admission constraints. Scheduling still
checks that the offering permits those selections, the resource is in the pool,
currently available and capable, and capacity remains at commit.

The booking request uses `manager: schedulingManager` and the source-owned
beneficiary reference. Those values grant nothing by themselves. The supplied
task-grant reference must resolve at the configured authority to a current grant
for the exact Scheduling issuer, subject, client, service, location and create
action, including the signed source-manager subject. A current grant and
Scheduling policy decide the booking; the invitation reserves no slot and
creates no hold.

If the constrained availability read returns no slot, the workflow invokes
`record-no-capacity` before finishing. That Action atomically changes the claimed
record to the durable `no-capacity` outcome, so it is not left `accepting` and no
capacity claim exists. A later attempt requires a deliberate new invitation or
source transition with a new acceptance procedure.

## Duplicate delivery, response loss and restart

The source application starts `accept-invitation` with the source-owned
`acceptanceId` as the Coordinator start idempotency key. Every retry, including
one made after a timeout or by a restarted producer, must use the same
Coordinator start idempotency key, the same verified producer identity, expected
workflow revision and exact input bytes. That recovers the original run and its
prepared product commands. A different owner cannot observe or reuse the
receipt, and a changed request conflicts.

This is essential because the Scheduling `duplicateKey` is only an additional
active-claim constraint. It does not replace durable exact-key recovery. The
original Coordinator run retains the Scheduling operation key, request bytes and
owner. If the booking response is lost, `reconcile` uses Scheduling's original
request, key and observation identity to retrieve the authoritative receipt. A
missing or expired receipt remains unresolved and must never be treated as proof
that no appointment exists.

After a confirmed receipt, `record-booking-result` records the exact
`acceptanceId` and appointment identifier while the source state is still
`accepting`. If that BReg response is lost, `retry-same` resends the saved
prepared command with its original BReg key. The transition, record revision,
history, audit entry and receipt committed together, so a replay cannot create a
second result. Coordinator restart preserves the same workflow snapshot and
commands before either recovery.

Source state is enough for another authorized producer to decide what to
recover without manufacturing a new effect:

- `issued` means no acceptance claim committed;
- `accepting` means recover the existing Coordinator run using the same start
  key and owner, then reconcile its Scheduling step if uncertain;
- `booked` carries the durable appointment result;
- `no-capacity`, `expired` and `revoked` are terminal outcomes in this
  reference.

Starting a second run under a different idempotency key does not recover the
first operation key. Its source claim is refused once the original claim has
committed. Operators inspect and recover the first run; they do not issue a
fresh booking command.

## Data boundary

The booking URL and Scheduling external references contain opaque record
identifiers only. Contact data stays in the restricted BReg record and the
private Messaging request. The workflows define no outbound hook carrying
invitation state. Routine examples, URLs and expected diagnostics contain only
synthetic values. Operated deployments must keep Coordinator state encryption,
audit redaction and product retention configured because issuer input and the
source read do contain restricted data.

## Authoring checks

From the repository root, check the source project and both workflows:

```sh
bregctl check products/coordinator/examples/invitation-booking/source-registry
bregctl generate actions \
  products/coordinator/examples/invitation-booking/source-registry \
  --output /new/scratch/path
coordinatorctl check \
  --project products/coordinator/examples/invitation-booking/issue-invitation \
  --explain
coordinatorctl test \
  --project products/coordinator/examples/invitation-booking/issue-invitation
coordinatorctl check \
  --project products/coordinator/examples/invitation-booking/accept-invitation \
  --explain
coordinatorctl test \
  --project products/coordinator/examples/invitation-booking/accept-invitation
```

Copy the generated `action-contracts.json` to each project's
`generated/invitations.contract.json`, then review the changed revisions before
packaging. The committed files were produced from the adjacent source project.

The deterministic scenarios prove authored routing and recovery choices against
synthetic product replies. They do not prove BReg PostgreSQL guards, live task
grant status, Scheduling capacity transactions, Messaging acceptance, or
cross-service restart. The reservation-review example's `test-native-services.py`
is the compiled-service proof for the same product boundaries (a real Casework
grant carrying a signed `schedulingManager`, a lost Scheduling response
reconciled through the original receipt, and a Coordinator restart); no native
journey covers this example.
