# Registry Scheduling changelog

## Unreleased

- Publish the scheduling MVP: published openings, exact-time offerings over
  interchangeable resource pools, published arrival windows with channel
  subquotas, holds, and accountable appointments, over PostgreSQL. The
  contract is unreleased and carries no frozen compatibility promise.
- Keep the capacity ledger inside the runtime's own transaction. A hold or
  appointment is created, moved, or released only inside that transaction, and
  no other product may write the ledger; eligibility stays with the source
  system.
- Authorize every commitment with a task grant whose scheduling bounds name
  the offering's service, its location, and the action, bounded to 64
  permissions of 32 actions with no wildcard. Only the grant's expiry is
  re-checked inside the capacity transaction.
- Document the maintained Casework approval and stock ThunderID exchange path,
  and feed its exact exchanged bearer through Scheduling's real authenticator
  before the adopter uses it for an appointment.
- Emit each committed scheduling change as a CloudEvents 1.0 event through the
  outbox to a configured reminder destination, and keep intents readable in
  place when no destination is configured.
- Retain idempotency attempt receipts for the configured period and forget
  listing cursors after fifteen minutes. Appointment, history, outbox, and
  audit retention are deferred.
- Provide `schedulingctl init`, `check`, `test`, `explain`, and `package`, and
  write complete `runtime.example.yaml` and `records.yaml` documents beside
  every initialized project.
- Carry the product's own contract checks, security-invariant matrix, and
  offline authoring journey under this folder.
- Deliver declared `after` URL observers for confirmed, rescheduled, and
  cancelled appointments from a transactionally captured, bounded projection;
  refuse conditions, principals, local handlers, and observer proposals.
- Re-check hold expiry after locking its supply during confirmation, so a
  delayed confirmation cannot claim capacity that became bookable and was
  committed elsewhere after the hold expired.
- Close the beta review races and contract gaps: include exact-time buffers in
  locked snapshots, scope duplicate keys to their offering, enforce requested
  capabilities, reject cross-offering reschedules, keep cancellations
  available during rolling policy changes, prevent occupied resources moving
  between pools, replay the winning idempotency receipt, and refuse policy
  publications that strand standing window commitments.
