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
- Emit each committed scheduling change as a CloudEvents 1.0 event through the
  outbox to a configured reminder destination, and keep intents readable in
  place when no destination is configured.
- Retain idempotency attempt receipts for the configured period and forget
  listing cursors after fifteen minutes. Appointment, history, outbox, and
  audit retention are deferred.
- Provide `schedulingctl init`, `check`, `test`, `explain`, and `package`, and
  write a complete `runtime.example.yaml` beside every initialized project.
- Carry the product's own contract checks, security-invariant matrix, and
  offline authoring journey under this folder.
- Validate authored hooks with the shared Registry Stack declaration shape and
  handler ABI while continuing to refuse every non-empty hook list until
  Scheduling defines product-owned trigger, projection, and execution contracts.
