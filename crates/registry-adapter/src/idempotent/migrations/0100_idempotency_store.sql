-- Adapter idempotency response custody (products/adapter/CONCEPT.md section 9,
-- D12). The namespace digest binds verified caller issuer, subject, and acting
-- client_id, the deployment identity, the concrete facade operation, and the caller's key without
-- storing any raw component. The request digest detects changed-request reuse.
-- Digests and terminal timestamps remain after response erasure solely to keep
-- the spent namespace closed; they are fixed-size metadata, never unbounded raw
-- caller values. This table is deliberately separate from the value-free audit
-- journal and has its own migration ledger.
CREATE TABLE adapter_idempotency_entries (
    scope_digest bytea PRIMARY KEY CHECK (octet_length(scope_digest) = 32),
    request_digest bytea NOT NULL CHECK (octet_length(request_digest) = 32),
    state text NOT NULL CHECK (state IN (
        'claimed',
        'effect_started',
        'completed',
        'failed',
        'completed_expired',
        'failed_expired')),
    claimed_at timestamptz NOT NULL,
    effect_started_at timestamptz,
    terminal_at timestamptz,
    expires_at timestamptz,
    response_status smallint CHECK (response_status BETWEEN 100 AND 599),
    response_content_type bytea CHECK (
        octet_length(response_content_type) BETWEEN 1 AND 256),
    response_body bytea CHECK (octet_length(response_body) <= 1048576),
    CONSTRAINT adapter_idempotency_state_shape CHECK (
        (state = 'claimed'
            AND effect_started_at IS NULL
            AND terminal_at IS NULL
            AND expires_at IS NULL
            AND response_status IS NULL
            AND response_content_type IS NULL
            AND response_body IS NULL)
        OR
        (state = 'effect_started'
            AND effect_started_at IS NOT NULL
            AND terminal_at IS NULL
            AND expires_at IS NULL
            AND response_status IS NULL
            AND response_content_type IS NULL
            AND response_body IS NULL)
        OR
        (state IN ('completed', 'failed')
            AND terminal_at IS NOT NULL
            AND expires_at IS NOT NULL
            AND response_status IS NOT NULL
            AND response_content_type IS NOT NULL
            AND response_body IS NOT NULL)
        OR
        (state IN ('completed_expired', 'failed_expired')
            AND terminal_at IS NOT NULL
            AND expires_at IS NOT NULL
            AND response_status IS NULL
            AND response_content_type IS NULL
            AND response_body IS NULL)
    )
);

-- The supervised sweep reads only terminal responses whose custody horizon
-- has passed. The scope digest makes ties stable without exposing a key.
CREATE INDEX adapter_idempotency_expiry_idx
    ON adapter_idempotency_entries (expires_at, scope_digest)
    WHERE state IN ('completed', 'failed');
