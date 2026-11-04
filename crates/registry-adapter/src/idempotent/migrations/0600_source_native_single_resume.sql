-- Admit the explicit source-native one-effect replay form without changing
-- historical v0500 bytes or rewriting existing two-or-more-step rows.
DO $$
DECLARE
    old_constraint name;
BEGIN
    SELECT constraint_name
      INTO old_constraint
      FROM information_schema.check_constraints
     WHERE constraint_schema = current_schema()
       AND constraint_name IN (
           SELECT conname
             FROM pg_constraint
            WHERE conrelid = 'adapter_idempotency_resumes'::regclass
              AND contype = 'c'
              AND pg_get_constraintdef(oid) LIKE '%step_count >= 2%'
              AND pg_get_constraintdef(oid) LIKE '%next_step < step_count%'
       );

    IF old_constraint IS NULL THEN
        RAISE EXCEPTION
            'adapter.idempotency-resume-step-constraint: v0500 step constraint not found';
    END IF;

    EXECUTE format(
        'ALTER TABLE adapter_idempotency_resumes DROP CONSTRAINT %I',
        old_constraint
    );
END
$$;

ALTER TABLE adapter_idempotency_resumes
    ADD CONSTRAINT adapter_idempotency_resumes_step_range_check
    CHECK (step_count >= 1 AND next_step < step_count);
