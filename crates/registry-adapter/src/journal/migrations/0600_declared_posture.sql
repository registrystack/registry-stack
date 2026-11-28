-- Require a known posture on every insert. Existing rows may hold NULL.
ALTER TABLE adapter_journal_events
    ADD COLUMN posture text,
    ADD CONSTRAINT adapter_journal_events_posture_check
        CHECK (posture IS NOT NULL AND posture IN ('production', 'development')) NOT VALID;
