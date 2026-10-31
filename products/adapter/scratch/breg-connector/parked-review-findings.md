# Parked connector: review findings to carry into the delivery design

Recorded 2026-10-31 from the independent codex review over the branch
(`products/adapter/scratch/codex-review-1.log`). The connector is parked
behind its off-by-default feature and linked by nothing; these findings
travel with it into whatever delivery design the revised brief settles
on. None is fixed in the parked code.

- [P1] Bind persisted attempts to their original destination
  (`src/breg/batch.rs:294`). After a restart with a changed origin,
  record type, or access profile, a restored batch is rebuilt against
  the current connector binding without detecting the change, so a
  create batch can execute at a different destination where the original
  idempotency key gives no protection. Persist and verify the
  destination and metadata-binding identity before sending; the
  connector-owned patch, tombstone, and ingestion envelopes need the
  same protection.
- [P2] Persist guarded action conditions before the first send
  (`src/breg/action.rs:245`). A guarded action that updates its own
  target changes the conditions a later preflight returns; a lost
  response then recovers with different request bytes under the original
  key and produces `idempotency.key-reused` instead of replaying the
  committed receipt. Persist the original conditions and native prepared
  evidence before the mutation and reuse them during recovery.
- [P2] Recheck import authority when sending restored attempts
  (`src/breg/ingestion.rs:355`). The import-authority check runs only at
  preparation; a restored attempt still creates runs or submits chunks
  after a restart that disabled the authority. Check the current
  authority in the execution paths of both ingestion operations.
- [P2] Match the complete announcement before adopting a run
  (`src/breg/ingestion.rs:377`). When multiple open runs share an input
  digest, recovery adopts the first without comparing package revision,
  schema fingerprint, operation, lengths, or counts against the prepared
  announcement. Compare all announcement fields and keep the outcome
  uncertain when the matching run is not unique.
