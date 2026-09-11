-- Global workers order by lease first; source reconciliation constrains the
-- source and generation before applying the same lease ordering.
CREATE INDEX IF NOT EXISTS casework_subjects_sync_claim_idx
    ON casework_subjects(sync_lease_until, source_id, subject_kind, subject_id)
    WHERE erased_at IS NULL AND sync_pending;

CREATE INDEX IF NOT EXISTS casework_subjects_source_sync_claim_idx
    ON casework_subjects(source_id, binding_generation, sync_lease_until, subject_kind, subject_id)
    WHERE erased_at IS NULL AND sync_pending;
