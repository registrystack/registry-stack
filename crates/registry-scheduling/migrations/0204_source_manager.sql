ALTER TABLE scheduling_claims
    ADD COLUMN manager_source_issuer text,
    ADD COLUMN manager_subject text,
    ADD CONSTRAINT scheduling_claims_source_manager_check CHECK (
        (manager_source_issuer IS NULL AND manager_subject IS NULL)
        OR (manager_source_issuer IS NOT NULL
            AND manager_source_issuer <> ''
            AND octet_length(manager_source_issuer) <= 512
            AND manager_subject IS NOT NULL
            AND manager_subject <> ''
            AND octet_length(manager_subject) <= 512)
    );
