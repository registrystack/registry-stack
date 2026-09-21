-- Durable scheduling state for unified review activity clocks. The pinned
-- holiday document and evaluated effects prevent a later holiday publication
-- from silently rewriting an already-running occurrence.
ALTER TABLE casework_review_clock_occurrences
    ADD COLUMN holiday_document jsonb,
    ADD COLUMN reminders jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN steps jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN next_action_at timestamptz;

CREATE INDEX casework_review_clock_due_idx
    ON casework_review_clock_occurrences(next_action_at,clock_occurrence_id)
    WHERE scope='activity' AND state='running' AND next_action_at IS NOT NULL;

CREATE INDEX casework_review_clock_missing_facts_idx
    ON casework_review_clock_occurrences(updated_at,clock_occurrence_id)
    WHERE scope='activity' AND state='source_facts_missing';

CREATE TABLE casework_review_clock_effects (
    clock_occurrence_id uuid NOT NULL
        REFERENCES casework_review_clock_occurrences(clock_occurrence_id) ON DELETE CASCADE,
    effect_kind text NOT NULL CHECK (effect_kind IN ('reminder','step')),
    effect_id text NOT NULL CHECK (octet_length(effect_id) BETWEEN 1 AND 128),
    event_id uuid NOT NULL UNIQUE,
    applied_at timestamptz NOT NULL,
    PRIMARY KEY (clock_occurrence_id,effect_kind,effect_id)
);
