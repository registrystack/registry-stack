ALTER TABLE casework_subjects
    ADD COLUMN IF NOT EXISTS erased_at timestamptz;
ALTER TABLE casework_items
    ADD COLUMN IF NOT EXISTS erased_at timestamptz;

ALTER TABLE casework_attempts
    ALTER COLUMN displayed_binding DROP NOT NULL;
ALTER TABLE casework_attempts
    ALTER COLUMN recovery_evidence DROP NOT NULL;
ALTER TABLE casework_attempts
    DROP CONSTRAINT IF EXISTS casework_attempts_recovery_evidence_check;
ALTER TABLE casework_attempts
    ADD CONSTRAINT casework_attempts_recovery_evidence_check
    CHECK (
        recovery_evidence IS NULL
        OR octet_length(recovery_evidence) BETWEEN 1 AND 65536
    );

CREATE INDEX IF NOT EXISTS casework_subjects_not_erased_sync_idx
    ON casework_subjects(sync_pending, source_id, subject_kind, subject_id)
    WHERE erased_at IS NULL;

CREATE INDEX IF NOT EXISTS casework_events_item_idx
    ON casework_events(item_id);
CREATE INDEX IF NOT EXISTS casework_idempotency_live_response_resource_idx
    ON casework_idempotency(resource)
    WHERE response IS NOT NULL;
CREATE INDEX IF NOT EXISTS casework_cursors_last_item_idx
    ON casework_cursors(last_item_id)
    WHERE last_item_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS casework_assignment_cursors_last_item_idx
    ON casework_assignment_cursors(last_item_id)
    WHERE last_item_id IS NOT NULL;
