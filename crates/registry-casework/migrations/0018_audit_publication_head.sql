-- The keyed hash of the last audit record the publisher appended to the audit
-- journal and confirmed here. The publication mark and this head change in one
-- statement, so a runtime that takes the audit publication lease can compare
-- the head with the journal and refuse to publish when a restore has left the
-- database and the journal at different points.
CREATE TABLE IF NOT EXISTS casework_audit_publication_head (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    record_hash text NOT NULL CHECK (record_hash ~ '^[0-9a-f]{64}$'),
    recorded_at timestamptz NOT NULL
);
