-- Structured decision results for hosted items (option H2).
--
-- A kind may declare a result schema in configuration; a Requester may narrow
-- it per item at create time; a deciding person submits the structured result
-- with the outcome. The result is Casework's own decision data, like the
-- reason: it is erased on the same terminal clock as the display payload, and
-- the accountability record keeps only a digest until its own clock expires.

ALTER TABLE casework_hosted_items ADD COLUMN result_constraints jsonb;

-- The 0002 nullability CHECK was auto-named by PostgreSQL, so locate it by
-- definition and replace it with one that also erases result_constraints with
-- the requester payload. Constraints are optional at creation, so they may be
-- NULL while the payload is live, but never present once it is erased.
DO $$
DECLARE
    erased_payload_check text;
BEGIN
    SELECT conname INTO erased_payload_check
    FROM pg_constraint
    WHERE conrelid = 'casework_hosted_items'::regclass
      AND contype = 'c'
      AND pg_get_constraintdef(oid) ~ '\(requester_issuer IS NULL\) = \(display IS NULL\)';
    IF erased_payload_check IS NOT NULL THEN
        EXECUTE format(
            'ALTER TABLE casework_hosted_items DROP CONSTRAINT %I',
            erased_payload_check
        );
    END IF;
END
$$;

ALTER TABLE casework_hosted_items
    ADD CONSTRAINT casework_hosted_items_payload_erasure_check
    CHECK (
        (requester_issuer IS NULL) = (display IS NULL)
        AND (result_constraints IS NULL OR requester_issuer IS NOT NULL)
    );

ALTER TABLE casework_hosted_terminal_events ADD COLUMN result jsonb;

ALTER TABLE casework_hosted_terminal_events
    ADD CONSTRAINT casework_hosted_terminal_events_result_state_check
    CHECK (state = 'completed' OR result IS NULL);

ALTER TABLE casework_hosted_accountability ADD COLUMN result_digest text;

ALTER TABLE casework_hosted_accountability
    ADD CONSTRAINT casework_hosted_accountability_result_digest_check
    CHECK (result_digest IS NULL OR result_digest ~ '^sha256:[0-9a-f]{64}$');
