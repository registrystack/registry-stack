-- Exact-digest replay must return the bounded result of the original mutation.
-- Existing heads remain nullable because earlier schemas did not retain it;
-- the runtime refuses an outcome-unknown replay instead of fabricating one.
ALTER TABLE scheduling_busy_source_heads
    ADD COLUMN last_outcome jsonb;

ALTER TABLE scheduling_busy_source_heads
    ADD CONSTRAINT scheduling_busy_source_heads_outcome_check CHECK (
        last_outcome IS NULL OR jsonb_typeof(last_outcome) = 'object'
    );
