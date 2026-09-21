-- The offering-wide duplicate guard filters on three columns: the key the
-- caller sent, the offering the claim was made under, and whether the booking
-- it names is still ahead. Schema version 1 indexed the key alone, leaving the
-- other two to a recheck over every active claim carrying that key. A booking
-- stays 'active' once its time has passed, because the ledger publishes no
-- completion transition and nothing sweeps elapsed bookings closed, so the
-- rechecked set grows for the life of the deployment rather than with the
-- bookings a party currently holds. Index the whole predicate instead.
CREATE INDEX IF NOT EXISTS scheduling_claims_duplicate_lookup_idx
    ON scheduling_claims(duplicate_key, offering, occupied_end)
    WHERE state = 'active' AND duplicate_key IS NOT NULL;

DROP INDEX IF EXISTS scheduling_claims_duplicate_idx;
