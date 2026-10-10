-- The verified token issuer and subject own the claim; history and audit
-- retain its pseudonym. A claim with no owner belongs to no caller.
ALTER TABLE scheduling_claims
    ADD COLUMN owner_issuer text,
    ADD COLUMN owner_subject text,
    ADD CONSTRAINT scheduling_claims_owner_check CHECK (
        (owner_issuer IS NULL AND owner_subject IS NULL)
        OR (owner_issuer IS NOT NULL AND owner_issuer <> ''
            AND owner_subject IS NOT NULL AND owner_subject <> '')
    );
