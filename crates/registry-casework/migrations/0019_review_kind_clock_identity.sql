-- Subject clocks continue across versions of one review kind, but concurrent
-- review kinds for the same subject must keep independent time budgets. Refuse
-- pre-existing unified-review clocks whose legacy identity cannot be inferred
-- safely rather than silently sharing their budget across review kinds.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1
          FROM casework_review_clock_occurrences
         WHERE scope='subject'
           AND (
               correlation_key NOT LIKE 'review-kind:%'
               OR octet_length(correlation_key)<=octet_length('review-kind:')
           )
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = '55000',
            MESSAGE = 'legacy unified-review subject clocks cannot be migrated safely',
            HINT = 'finish or remove only confirmed disposable in-flight reviews before retrying';
    END IF;
END
$$;

ALTER TABLE casework_review_clock_occurrences
    ADD CONSTRAINT casework_review_clock_subject_kind_check
    CHECK (scope<>'subject' OR (
        correlation_key LIKE 'review-kind:%'
        AND octet_length(correlation_key)>octet_length('review-kind:')
    ));
