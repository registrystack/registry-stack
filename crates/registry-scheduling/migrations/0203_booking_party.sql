ALTER TABLE scheduling_claims
    ADD COLUMN recipient_count integer,
    ADD COLUMN attendee_count integer,
    ADD COLUMN party_references jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD CONSTRAINT scheduling_claims_party_counts_check CHECK (
        (recipient_count IS NULL AND attendee_count IS NULL)
        OR (recipient_count IS NOT NULL AND recipient_count >= 0
            AND attendee_count IS NOT NULL AND attendee_count > 0
            AND attendee_count >= recipient_count)
    ),
    ADD CONSTRAINT scheduling_claims_party_references_check CHECK (
        jsonb_typeof(party_references) = 'array'
        AND jsonb_array_length(party_references) <= 16
    );
