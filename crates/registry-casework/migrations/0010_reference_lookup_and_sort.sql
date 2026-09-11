ALTER TABLE casework_items
    ADD COLUMN IF NOT EXISTS display_reference text
    CHECK (
        display_reference IS NULL
        OR char_length(display_reference) BETWEEN 1 AND 512
    );

ALTER TABLE casework_cursors
    ADD COLUMN IF NOT EXISTS last_first_observed_at timestamptz;
ALTER TABLE casework_cursors
    ADD COLUMN IF NOT EXISTS last_subject_kind text;

CREATE INDEX IF NOT EXISTS casework_items_reference_lookup_idx
    ON casework_items((display_reference COLLATE "C"), item_id)
    WHERE erased_at IS NULL AND display_reference IS NOT NULL;
CREATE INDEX IF NOT EXISTS casework_items_active_age_idx
    ON casework_items(queue_id, first_observed_at, item_id)
    WHERE erased_at IS NULL
      AND state NOT IN ('completed','superseded','cancelled');
CREATE INDEX IF NOT EXISTS casework_items_active_type_idx
    ON casework_items(queue_id, subject_kind, first_observed_at, item_id)
    WHERE erased_at IS NULL
      AND state NOT IN ('completed','superseded','cancelled');
