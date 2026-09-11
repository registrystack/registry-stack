-- The occurrence identity index is rebuilt here rather than in the base file so
-- that a repeated migrate never drops a live uniqueness constraint. The drop and
-- the create share one transaction, so the constraint is never observably absent.
DROP INDEX IF EXISTS casework_items_occurrence_idx;
CREATE UNIQUE INDEX IF NOT EXISTS casework_items_occurrence_idx
    ON casework_items(source_id, subject_kind, subject_id, occurrence_key);

CREATE INDEX IF NOT EXISTS casework_cursors_retention_idx
    ON casework_cursors(expires_at, cursor_id);

CREATE INDEX IF NOT EXISTS casework_clock_occurrences_item_idx
    ON casework_clock_occurrences(item_id)
    WHERE item_id IS NOT NULL;
