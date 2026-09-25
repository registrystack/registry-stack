-- The outbox keeps every published record, so the backlog the publisher reads
-- and the metrics listener counts is a shrinking share of a growing table.
-- This partial index holds only the unpublished rows, in the publisher's read
-- order, so neither reading scans the published history.
CREATE INDEX IF NOT EXISTS casework_audit_outbox_pending_idx
    ON casework_audit_outbox(event_id)
    WHERE published_at IS NULL;
