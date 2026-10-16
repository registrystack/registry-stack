-- Claim and history rows remain. Only expired ownership is tombstoned.
-- The digest is an inert reference, never authority to read or act.
ALTER TABLE scheduling_claims
    ADD COLUMN owner_reference text,
    ADD COLUMN owner_erased_at timestamptz,
    ADD CONSTRAINT scheduling_claims_owner_reference_check CHECK (
        owner_reference IS NULL OR owner_reference ~ '^sha256:[0-9a-f]{64}$'
    ),
    ADD CONSTRAINT scheduling_claims_owner_erasure_check CHECK (
        (owner_erased_at IS NULL AND owner_reference IS NULL)
        OR (owner_erased_at IS NOT NULL AND owner_reference IS NOT NULL
            AND owner_issuer IS NULL AND owner_subject IS NULL)
    );
