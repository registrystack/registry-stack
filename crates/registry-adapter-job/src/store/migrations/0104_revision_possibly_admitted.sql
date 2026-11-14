-- A revised event of the item's current sequence may have been admitted:
-- its answer was lost and a later answer for the same event was a refusal.
-- The refusal does not answer the lost attempt, so the sequence's frozen
-- receiver and body identities stay frozen across the refusal and any
-- rescan, and a retry is sent only to the same receiver with the same body.
-- A changed digest starts a new sequence and clears the state.

ALTER TABLE adapter_job_items
    ADD COLUMN revision_possibly_admitted boolean NOT NULL DEFAULT false;

-- A refused row written before this column existed cannot say whether its
-- refusal answered the retry of a lost revised event, so a refused revision
-- that froze a receiver keeps it frozen.
UPDATE adapter_job_items
SET revision_possibly_admitted = true
WHERE status = 'refused'
  AND admitted_before
  AND receiver_identity IS NOT NULL;
