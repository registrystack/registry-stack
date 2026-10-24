ALTER TABLE scheduling_claims
    ADD COLUMN operational_scope_version smallint NOT NULL DEFAULT 0,
    ADD COLUMN operational_service text,
    ADD COLUMN operational_location text,
    ADD COLUMN operational_mode text,
    ADD CONSTRAINT scheduling_claims_operational_scope_check CHECK (
        (operational_scope_version = 0
            AND operational_service IS NULL
            AND operational_location IS NULL
            AND operational_mode IS NULL)
        OR
        (operational_scope_version = 1
            AND operational_service IS NOT NULL AND operational_service <> ''
            AND operational_location IS NOT NULL AND operational_location <> ''
            AND operational_mode IN ('exact-time', 'arrival-window'))
    );

-- An older runtime that survives an operator's activation cannot create an
-- unlabeled claim: omitting the new columns now chooses version 1, whose check
-- requires every immutable security label.
ALTER TABLE scheduling_claims
    ALTER COLUMN operational_scope_version SET DEFAULT 1;

CREATE INDEX scheduling_claims_operational_displayed_idx
    ON scheduling_claims(
        operational_service,
        operational_location,
        displayed_start,
        claim_id
    )
    WHERE kind = 'booking' AND operational_scope_version = 1;

CREATE INDEX scheduling_claims_operational_occupied_idx
    ON scheduling_claims(
        operational_service,
        operational_location,
        occupied_start,
        claim_id
    )
    WHERE kind = 'booking' AND operational_scope_version = 1;
