-- Published windows reserve physical resources once through the same
-- claim-allocation ledger as every exact reservation. Window booking claims
-- point to the window but carry only units; they never duplicate its room,
-- facilitator, or equipment allocations.
ALTER TABLE scheduling_claims
    DROP CONSTRAINT scheduling_claims_kind_check,
    ADD CONSTRAINT scheduling_claims_kind_check
        CHECK (kind IN ('booking', 'hold', 'window'));

-- A window parent is the window's own reservation of the resources its record
-- declares, written with the records and named by the window it serves. One
-- window has at most one, so its allocations are never counted twice.
CREATE UNIQUE INDEX scheduling_window_parent_claim_idx
    ON scheduling_claims(supply_id)
    WHERE kind = 'window';
