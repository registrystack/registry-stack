-- Retain only the closed semantic response headers required to replay native
-- write results. Nullable columns add no value to existing rows and do not
-- rewrite v0600 response custody.
ALTER TABLE adapter_idempotency_entries
    ADD COLUMN response_location bytea CHECK (
        octet_length(response_location) BETWEEN 1 AND 2048),
    ADD COLUMN response_etag bytea CHECK (
        octet_length(response_etag) BETWEEN 1 AND 258),
    DROP CONSTRAINT adapter_idempotency_state_shape;

ALTER TABLE adapter_idempotency_entries
    ADD CONSTRAINT adapter_idempotency_state_shape CHECK (
        (state = 'claimed'
            AND effect_started_at IS NULL
            AND terminal_at IS NULL
            AND expires_at IS NULL
            AND response_status IS NULL
            AND response_content_type IS NULL
            AND response_location IS NULL
            AND response_etag IS NULL
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
        (state = 'effect_started'
            AND effect_started_at IS NOT NULL
            AND terminal_at IS NULL
            AND expires_at IS NULL
            AND response_status IS NULL
            AND response_content_type IS NULL
            AND response_location IS NULL
            AND response_etag IS NULL
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
        (state = 'accepted'
            AND effect_started_at IS NOT NULL
            AND terminal_at IS NULL
            AND expires_at IS NOT NULL
            AND response_status = 202
            AND response_body IS NOT NULL
            AND (response_content_type IS NOT NULL
                OR octet_length(response_body) = 0)
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
        (state = 'accepted_expired'
            AND effect_started_at IS NOT NULL
            AND terminal_at IS NULL
            AND expires_at IS NOT NULL
            AND response_status IS NULL
            AND response_content_type IS NULL
            AND response_location IS NULL
            AND response_etag IS NULL
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
        (state IN ('completed', 'failed')
            AND terminal_at IS NOT NULL
            AND expires_at IS NOT NULL
            AND response_status IS NOT NULL
            AND response_body IS NOT NULL
            AND (response_content_type IS NOT NULL
                OR octet_length(response_body) = 0)
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
            AND response_location IS NULL
            AND response_etag IS NULL
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
