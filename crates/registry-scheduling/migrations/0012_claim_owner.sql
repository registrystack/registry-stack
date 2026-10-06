-- A hold or an appointment is owned by the verified token issuer and subject
-- that booked it, stored beside the pseudonym history and audit carry, so
-- rotating the audit hash key leaves every claim with its owner. A claim
-- written before this migration recorded only the pseudonym, from which the
-- owner cannot be recovered: it keeps its capacity, its history, and its
-- pseudonym, and no caller owns it.
ALTER TABLE scheduling_claims
    ADD COLUMN owner_issuer text,
    ADD COLUMN owner_subject text,
    ADD CONSTRAINT scheduling_claims_owner_check CHECK (
        (owner_issuer IS NULL AND owner_subject IS NULL)
        OR (owner_issuer IS NOT NULL AND owner_issuer <> ''
            AND owner_subject IS NOT NULL AND owner_subject <> '')
    );
