-- Host-owned asynchronous write recovery extends the existing idempotency
-- row. Fixed-size digests bind the live status handle to its verified caller,
-- logical deployment, request and artifact. The bounded text identifiers are
-- reviewed artifact identifiers needed to recover the original authority and
-- route without guessing. No raw caller identity, request payload, source
-- response, URL or credential is retained.
ALTER TABLE adapter_idempotency_entries
    ADD COLUMN artifact_digest bytea
        CHECK (octet_length(artifact_digest) = 32),
    ADD COLUMN async_deployment_digest bytea
        CHECK (octet_length(async_deployment_digest) = 32),
    ADD COLUMN async_binding_digest bytea
        CHECK (octet_length(async_binding_digest) = 32),
    ADD COLUMN async_binding_id varchar(256),
    ADD COLUMN async_profile_operation varchar(256),
    ADD COLUMN async_concrete_operation varchar(256),
    ADD COLUMN async_record_type varchar(256),
    ADD COLUMN async_source_id varchar(256),
    ADD COLUMN async_recovery_id char(64)
        CHECK (async_recovery_id ~ '^[0-9a-f]{64}$'),
    ADD COLUMN async_accepted_at timestamptz,
    ADD COLUMN async_expires_at timestamptz,
    ADD COLUMN async_poll_lease_id bytea
        CHECK (octet_length(async_poll_lease_id) = 16),
    ADD COLUMN async_poll_lease_until timestamptz;

ALTER TABLE adapter_idempotency_entries
    DROP CONSTRAINT adapter_idempotency_entries_state_check,
    ADD CONSTRAINT adapter_idempotency_entries_state_check CHECK (state IN (
        'claimed',
        'effect_started',
        'accepted',
        'accepted_expired',
        'completed',
        'failed',
        'completed_expired',
        'failed_expired')),
    DROP CONSTRAINT adapter_idempotency_state_shape;

ALTER TABLE adapter_idempotency_entries
    ADD CONSTRAINT adapter_idempotency_state_shape CHECK (
        -- An ordinary synchronous row has no asynchronous authority.
        (state = 'claimed'
            AND effect_started_at IS NULL
            AND terminal_at IS NULL
            AND expires_at IS NULL
            AND response_status IS NULL
            AND response_content_type IS NULL
            AND response_body IS NULL
            AND response_request_id IS NULL
            AND artifact_digest IS NULL
            AND async_deployment_digest IS NULL
            AND async_binding_digest IS NULL
            AND async_binding_id IS NULL
            AND async_profile_operation IS NULL
            AND async_concrete_operation IS NULL
            AND async_record_type IS NULL
            AND async_source_id IS NULL
            AND async_recovery_id IS NULL
            AND async_accepted_at IS NULL
            AND async_expires_at IS NULL
            AND async_poll_lease_id IS NULL
            AND async_poll_lease_until IS NULL)
        OR
        -- A spent effect is either the historical/ordinary unknown shape, or
        -- carries bounded live recovery metadata precommitted before the send.
        (state = 'effect_started'
            AND effect_started_at IS NOT NULL
            AND terminal_at IS NULL
            AND expires_at IS NULL
            AND response_status IS NULL
            AND response_content_type IS NULL
            AND response_body IS NULL
            AND async_accepted_at IS NULL
            AND async_source_id IS NULL
            AND (
                (response_request_id IS NULL
                    AND artifact_digest IS NULL
                    AND async_deployment_digest IS NULL
                    AND async_binding_digest IS NULL
                    AND async_binding_id IS NULL
                    AND async_profile_operation IS NULL
                    AND async_concrete_operation IS NULL
                    AND async_record_type IS NULL
                    AND async_recovery_id IS NULL
                    AND async_expires_at IS NULL
                    AND async_poll_lease_id IS NULL
                    AND async_poll_lease_until IS NULL)
                OR
                (response_request_id IS NOT NULL
                    AND artifact_digest IS NOT NULL
                    AND async_deployment_digest IS NOT NULL
                    AND async_binding_digest IS NOT NULL
                    AND async_binding_id IS NOT NULL
                    AND async_profile_operation IS NOT NULL
                    AND async_concrete_operation IS NOT NULL
                    AND async_record_type IS NOT NULL
                    AND async_expires_at IS NOT NULL
                    AND ((async_poll_lease_id IS NULL AND async_poll_lease_until IS NULL)
                        OR (async_poll_lease_id IS NOT NULL
                            AND async_poll_lease_until IS NOT NULL)))))
        OR
        -- Accepted custody always has exact 202 bytes and one source-native id.
        (state = 'accepted'
            AND effect_started_at IS NOT NULL
            AND terminal_at IS NULL
            AND expires_at IS NOT NULL
            AND response_status = 202
            AND response_content_type IS NOT NULL
            AND response_body IS NOT NULL
            AND response_request_id IS NOT NULL
            AND artifact_digest IS NOT NULL
            AND async_deployment_digest IS NOT NULL
            AND async_binding_digest IS NOT NULL
            AND async_binding_id IS NOT NULL
            AND async_profile_operation IS NOT NULL
            AND async_concrete_operation IS NOT NULL
            AND async_record_type IS NOT NULL
            AND async_source_id IS NOT NULL
            AND async_accepted_at IS NOT NULL
            AND async_expires_at IS NOT NULL
            AND ((async_poll_lease_id IS NULL AND async_poll_lease_until IS NULL)
                OR (async_poll_lease_id IS NOT NULL
                    AND async_poll_lease_until IS NOT NULL)))
        OR
        -- An expired acceptance is a spent key with all disclosure custody gone.
        (state = 'accepted_expired'
            AND effect_started_at IS NOT NULL
            AND terminal_at IS NULL
            AND expires_at IS NOT NULL
            AND response_status IS NULL
            AND response_content_type IS NULL
            AND response_body IS NULL
            AND response_request_id IS NULL
            AND artifact_digest IS NULL
            AND async_deployment_digest IS NULL
            AND async_binding_digest IS NULL
            AND async_binding_id IS NULL
            AND async_profile_operation IS NULL
            AND async_concrete_operation IS NULL
            AND async_record_type IS NULL
            AND async_source_id IS NULL
            AND async_recovery_id IS NULL
            AND async_accepted_at IS NULL
            AND async_expires_at IS NULL
            AND async_poll_lease_id IS NULL
            AND async_poll_lease_until IS NULL)
        OR
        -- Terminal custody may retain the caller-bound status link until its
        -- original accepted expiry. Source identifiers are cleared at once.
        (state IN ('completed', 'failed')
            AND terminal_at IS NOT NULL
            AND expires_at IS NOT NULL
            AND response_status IS NOT NULL
            AND response_content_type IS NOT NULL
            AND response_body IS NOT NULL
            AND response_request_id IS NOT NULL
            AND async_source_id IS NULL
            AND async_recovery_id IS NULL
            AND async_poll_lease_id IS NULL
            AND async_poll_lease_until IS NULL
            AND (
                (artifact_digest IS NULL
                    AND async_deployment_digest IS NULL
                    AND async_binding_digest IS NULL
                    AND async_binding_id IS NULL
                    AND async_profile_operation IS NULL
                    AND async_concrete_operation IS NULL
                    AND async_record_type IS NULL
                    AND async_accepted_at IS NULL
                    AND async_expires_at IS NULL)
                OR
                (artifact_digest IS NOT NULL
                    AND async_deployment_digest IS NOT NULL
                    AND async_binding_digest IS NOT NULL
                    AND async_binding_id IS NOT NULL
                    AND async_profile_operation IS NOT NULL
                    AND async_concrete_operation IS NOT NULL
                    AND async_record_type IS NOT NULL
                    AND async_expires_at IS NOT NULL)))
        OR
        (state IN ('completed_expired', 'failed_expired')
            AND terminal_at IS NOT NULL
            AND expires_at IS NOT NULL
            AND response_status IS NULL
            AND response_content_type IS NULL
            AND response_body IS NULL
            AND response_request_id IS NULL
            AND artifact_digest IS NULL
            AND async_deployment_digest IS NULL
            AND async_binding_digest IS NULL
            AND async_binding_id IS NULL
            AND async_profile_operation IS NULL
            AND async_concrete_operation IS NULL
            AND async_record_type IS NULL
            AND async_source_id IS NULL
            AND async_recovery_id IS NULL
            AND async_accepted_at IS NULL
            AND async_expires_at IS NULL
            AND async_poll_lease_id IS NULL
            AND async_poll_lease_until IS NULL)
    );

-- The response request id is the sole opaque status handle. It is unique only
-- while a live asynchronous binding can resolve it; ordinary exact-response
-- custody retains the same field independently after the link expires.
CREATE UNIQUE INDEX adapter_idempotency_async_status_id_idx
    ON adapter_idempotency_entries (response_request_id)
    WHERE async_binding_digest IS NOT NULL;

CREATE INDEX adapter_idempotency_async_expiry_idx
    ON adapter_idempotency_entries (async_expires_at, scope_digest)
    WHERE async_binding_digest IS NOT NULL;

CREATE INDEX adapter_idempotency_async_artifact_idx
    ON adapter_idempotency_entries (
        async_deployment_digest, artifact_digest, async_expires_at)
    WHERE async_binding_digest IS NOT NULL;

-- One digest-only row serializes artifact activation with pre-effect custody
-- admission for a logical deployment. Readers and recovery never advance it.
CREATE TABLE adapter_idempotency_async_artifacts (
    deployment_digest bytea PRIMARY KEY
        CHECK (octet_length(deployment_digest) = 32),
    artifact_digest bytea NOT NULL
        CHECK (octet_length(artifact_digest) = 32)
);
