-- Exact replay includes the Adapter-generated response request id. A v0200
-- completed or failed row has response bytes but not the id that accompanied
-- them, so it cannot be repaired or safely replayed. Preserve those rows and
-- refuse the migration until an operator reconciles them. Nonterminal rows
-- can acquire an id when they finish; expired tombstones have no response to
-- replay and remain spent without one.
DO $response_request_id$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM adapter_idempotency_entries
        WHERE state IN ('completed', 'failed')
        LIMIT 1
    ) THEN
        RAISE EXCEPTION USING
            ERRCODE = 'P0001',
            MESSAGE = 'adapter.idempotency-legacy-response-id';
    END IF;
END
$response_request_id$;

ALTER TABLE adapter_idempotency_entries
    ADD COLUMN response_request_id text
    CONSTRAINT adapter_idempotency_response_request_id_format
        CHECK (response_request_id ~ '^[0-9a-f]{32}$');

ALTER TABLE adapter_idempotency_entries
    DROP CONSTRAINT adapter_idempotency_state_shape;

ALTER TABLE adapter_idempotency_entries
    ADD CONSTRAINT adapter_idempotency_state_shape CHECK (
        (state = 'claimed'
            AND effect_started_at IS NULL
            AND terminal_at IS NULL
            AND expires_at IS NULL
            AND response_status IS NULL
            AND response_content_type IS NULL
            AND response_body IS NULL
            AND response_request_id IS NULL)
        OR
        (state = 'effect_started'
            AND effect_started_at IS NOT NULL
            AND terminal_at IS NULL
            AND expires_at IS NULL
            AND response_status IS NULL
            AND response_content_type IS NULL
            AND response_body IS NULL
            AND response_request_id IS NULL)
        OR
        (state IN ('completed', 'failed')
            AND terminal_at IS NOT NULL
            AND expires_at IS NOT NULL
            AND response_status IS NOT NULL
            AND response_content_type IS NOT NULL
            AND response_body IS NOT NULL
            AND response_request_id IS NOT NULL)
        OR
        (state IN ('completed_expired', 'failed_expired')
            AND terminal_at IS NOT NULL
            AND expires_at IS NOT NULL
            AND response_status IS NULL
            AND response_content_type IS NULL
            AND response_body IS NULL
            AND response_request_id IS NULL)
    );
