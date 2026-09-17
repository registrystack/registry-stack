-- The records revision. Every wholesale records replacement increments it,
-- and a capacity transaction reads it under the supply anchor it holds: a
-- commitment whose facts were resolved before a replacement is refused
-- rather than allowed to name a resource the deployment no longer carries.
ALTER TABLE scheduling_meta
    ADD COLUMN facts_revision bigint NOT NULL DEFAULT 0;

-- A suppressed reminder is retained rather than deleted. The row keeps
-- accounting for an intent whose appointment moved on, whether or not a
-- dispatch already in flight reached its destination.
ALTER TABLE scheduling_outbox DROP CONSTRAINT scheduling_outbox_delivery_state_check;
ALTER TABLE scheduling_outbox
    ADD CONSTRAINT scheduling_outbox_delivery_state_check
    CHECK (delivery_state IN ('pending','delivered','failed','local','suppressed'));
