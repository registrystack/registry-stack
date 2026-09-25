# Registry Scheduling changelog

## Unreleased

- BREAKING: write audit through the shared platform audit writer instead of
  a hash-chained journal published from a PostgreSQL outbox.
  - The `audit` block takes `hashKeyRef`, `destination` (`file`, the
    default, or `stdout`), and, for `file` only, the absolute `path`,
    `rotateBytes` (default 104857600, at least 1048576), and `retainDays`
    (default 90, at most 36500). An existing `{path, hashKeyRef}` block keeps
    working as a `file` destination.
  - Every entry carries the schema `registry-scheduling-audit/v1`, a
    `request` or `response` phase, and a correlation shared by a decision's
    request and response entries; a response names that correlation as its
    `eventId`. The runtime writes a commitment's request entry before it
    opens the capacity transaction and its response entry after that
    transaction commits or rolls back. A refused request entry opens no
    transaction and answers `service.unavailable`; a refused response entry
    for a committed commitment answers `service.unavailable` with the
    commitment in place. A permission refused before the transaction is one
    response entry.
  - Hook delivery writes an attempt's request entry before egress and its
    terminal response entry with the same correlation; a refused entry leaves
    the delivery pending and sends nothing.
  - Entries are no longer hash-chained, and the runtime keeps no audit state
    in PostgreSQL. Schema version 8 drops `scheduling_audit_outbox`;
    `migrate` refuses while the outbox still holds unpublished records, so
    run the previous release until its publisher has drained the outbox,
    then migrate.
  - `/readyz` reports ready only while the audit writer is ready.
  - `schedulingctl records apply` writes its request entry before it
    replaces the records and its response entry after, to a sibling file
    named for its role beside `audit.path` (`audit.schedulingctl.ndjson`
    beside `audit.ndjson`), and refuses to replace anything when that file
    cannot be opened.

## v0.34.0 - 2026-09-25

- Registry Scheduling has no user-visible changes in this release.

## v0.33.0 - 2026-09-22

- Publish the scheduling MVP: published openings, exact-time offerings over
  interchangeable resource pools, published arrival windows with channel
  subquotas, holds, and accountable appointments, over PostgreSQL. The
  contract is pre-1.0 and may change in a later minor release.
- Keep the capacity ledger inside the runtime's own transaction. A hold or
  appointment is created, moved, or released only inside that transaction, and
  no other product may write the ledger; eligibility stays with the source
  system.
- Validate a policy against the published window records it governs, which
  refuses a window whose staffing pool also backs an exact-time offering.
  The authoring tooling reports it against the files on disk, and policy
  publication and records replacement re-run the same check at the database
  under the locks they already hold, so a deployment that bypasses the
  authoring tooling cannot publish the combination it refuses.
- Keep one supply identifier to one kind of supply. A resource pool and a
  published window anchor their capacity transactions on the same row keyed by
  that identifier, so authoring refuses the collision from either side and both
  anchor writes name the standing supply rather than aborting one publish path
  and silently skipping the anchor on the other.
- Authorize every commitment with a task grant whose scheduling bounds name
  the offering's service, its location, and the action, bounded to 64
  permissions of 32 actions with no wildcard. Only the grant's expiry is
  re-checked inside the capacity transaction.
- Write one pseudonymized authorization audit record for every commitment
  decision: the allowed case, the permission mismatches refused before the
  capacity transaction opens, and the commitments that transaction refuses,
  including an admission refusal, the hold ceiling, a lapsed grant, a stale
  observed revision, and a cancellation past its cutoff. A failed transaction
  and a replaced environment decided nothing and are not audited; an
  idempotency key refusal is carried by the attempt receipt instead.
- Document the maintained Casework approval and stock ThunderID exchange path,
  and feed its exact exchanged bearer through Scheduling's real authenticator
  before the adopter uses it for an appointment.
- Emit each committed scheduling change as a CloudEvents 1.0 event through the
  outbox to a configured reminder destination, and keep intents readable in
  place when no destination is configured.
- Retain idempotency attempt receipts for the configured period and forget
  listing cursors after fifteen minutes. Appointment, history, outbox, and
  audit retention are deferred.
- Answer a release or cancellation retry from the policy revision that
  governed the claim. Publication may retire an offering, or keep its
  identifier and sell it under a different service or location, once no claim
  on it is live, and the retry each receipt exists to serve is still
  authorized against the offering as it stood when the claim was committed.
- Bound the offering-wide duplicate guard to the bookings it decides on. The
  ledger closes no booking when its time passes, so the active claims carrying
  one party's key accumulate for the life of the deployment; the guard now
  reads an index over the key, the offering, and the booking's end rather than
  over the key alone.
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
- Keep arrival offerings as policy references while operators publish their
  concrete window capacity through atomic runtime records. Apply location
  openings and closures to live window availability and admission, and refuse
  a request whose start differs from the selected window.
- Close the beta review races and contract gaps: include exact-time buffers in
  locked snapshots, scope duplicate keys to their offering, enforce requested
  capabilities, reject cross-offering reschedules, keep cancellations
  available during rolling policy changes, prevent occupied resources moving
  between pools, replay the winning idempotency receipt, and refuse policy
  publications that strand standing commitments. Keep explanation probes,
  multi-pattern reopenings, long-range availability, deployment-bound records
  updates, ownership checks, and replayed response fields aligned with those
  same runtime contracts.
