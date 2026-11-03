-- A signed Coordinator event freezes its body metadata and selected public
-- receiver identity per item sequence. These columns remain progress metadata,
-- never an event payload or a destination record correlation.

ALTER TABLE adapter_job_items
    ADD COLUMN event_time timestamptz,
    ADD COLUMN delivery_attempt bigint,
    ADD COLUMN receiver_identity bytea,
    ADD COLUMN receiver_identity_known boolean NOT NULL DEFAULT false,
    ADD COLUMN canonical_body_identity bytea,
    ADD COLUMN canonical_body_identity_known boolean NOT NULL DEFAULT false;

UPDATE adapter_job_items
SET event_time = first_seen,
    delivery_attempt = 1;

ALTER TABLE adapter_job_items
    ALTER COLUMN event_time SET NOT NULL,
    ALTER COLUMN delivery_attempt SET NOT NULL,
    ADD CONSTRAINT adapter_job_items_delivery_attempt_check
        CHECK (delivery_attempt >= 1),
    ADD CONSTRAINT adapter_job_items_receiver_identity_check
        CHECK (receiver_identity IS NULL OR octet_length(receiver_identity) = 32),
    ADD CONSTRAINT adapter_job_items_receiver_identity_state_check
        CHECK (receiver_identity_known OR receiver_identity IS NULL),
    ADD CONSTRAINT adapter_job_items_canonical_body_identity_check
        CHECK (canonical_body_identity IS NULL OR octet_length(canonical_body_identity) = 32),
    ADD CONSTRAINT adapter_job_items_canonical_body_identity_state_check
        CHECK (canonical_body_identity_known OR canonical_body_identity IS NULL);

-- File and SFTP item identity is governed by the source route, decoder,
-- selector, endpoint and namespace. The host binds their public digest before
-- reading so an identity change cannot silently stage different registrations.
ALTER TABLE adapter_job_state
    ADD COLUMN item_identity_digest bytea,
    ADD CONSTRAINT adapter_job_state_item_identity_digest_check
        CHECK (item_identity_digest IS NULL OR octet_length(item_identity_digest) = 32);
