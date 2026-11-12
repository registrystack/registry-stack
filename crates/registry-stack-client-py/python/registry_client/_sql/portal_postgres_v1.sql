CREATE SCHEMA IF NOT EXISTS registry_client_portal;

CREATE TABLE IF NOT EXISTS registry_client_portal.migrations (
    version smallint PRIMARY KEY,
    checksum text NOT NULL,
    applied_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    CONSTRAINT migrations_version_positive CHECK (version > 0),
    CONSTRAINT migrations_checksum_bounded CHECK (length(checksum) = 64)
);

CREATE TABLE IF NOT EXISTS registry_client_portal.key_state (
    singleton boolean PRIMARY KEY DEFAULT true,
    active_key_id text NOT NULL,
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    CONSTRAINT key_state_singleton CHECK (singleton),
    CONSTRAINT key_state_key_id_bounded CHECK (
        length(active_key_id) BETWEEN 1 AND 128
    )
);

CREATE TABLE IF NOT EXISTS registry_client_portal.chains (
    chain_digest bytea PRIMARY KEY,
    closed boolean NOT NULL DEFAULT false,
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    CONSTRAINT chains_digest_length CHECK (octet_length(chain_digest) = 32)
);

CREATE TABLE IF NOT EXISTS registry_client_portal.pending (
    state_digest bytea PRIMARY KEY,
    chain_digest bytea NOT NULL REFERENCES registry_client_portal.chains(chain_digest)
        ON DELETE CASCADE,
    expires_at double precision NOT NULL,
    key_id text NOT NULL,
    ciphertext bytea NOT NULL,
    CONSTRAINT pending_state_digest_length CHECK (octet_length(state_digest) = 32),
    CONSTRAINT pending_chain_digest_length CHECK (octet_length(chain_digest) = 32),
    CONSTRAINT pending_expiry_finite CHECK (
        expires_at NOT IN ('Infinity'::double precision, '-Infinity'::double precision, 'NaN'::double precision)
    ),
    CONSTRAINT pending_key_id_bounded CHECK (length(key_id) BETWEEN 1 AND 128),
    CONSTRAINT pending_ciphertext_bounded CHECK (
        octet_length(ciphertext) BETWEEN 29 AND 1048604
    )
);

CREATE INDEX IF NOT EXISTS pending_chain
    ON registry_client_portal.pending(chain_digest);

CREATE TABLE IF NOT EXISTS registry_client_portal.sessions (
    session_digest bytea PRIMARY KEY,
    generation bigint NOT NULL,
    expires_at double precision NOT NULL,
    key_id text NOT NULL,
    ciphertext bytea NOT NULL,
    CONSTRAINT sessions_digest_length CHECK (octet_length(session_digest) = 32),
    CONSTRAINT sessions_generation_nonnegative CHECK (generation >= 0),
    CONSTRAINT sessions_expiry_finite CHECK (
        expires_at NOT IN ('Infinity'::double precision, '-Infinity'::double precision, 'NaN'::double precision)
    ),
    CONSTRAINT sessions_key_id_bounded CHECK (length(key_id) BETWEEN 1 AND 128),
    CONSTRAINT sessions_ciphertext_bounded CHECK (
        octet_length(ciphertext) BETWEEN 29 AND 1048604
    )
);
