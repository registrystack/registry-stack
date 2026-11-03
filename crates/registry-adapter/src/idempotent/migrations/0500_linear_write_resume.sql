-- A resumable write keeps only its current ordinal, finite lease and declared
-- source identifiers. The exact caller request is supplied again and checked
-- by the existing request digest; neither request nor source response bytes
-- are retained here.
CREATE TABLE adapter_idempotency_resumes (
    scope_digest bytea PRIMARY KEY
        REFERENCES adapter_idempotency_entries(scope_digest) ON DELETE CASCADE,
    request_digest bytea NOT NULL
        CHECK (octet_length(request_digest) = 32),
    deployment_digest bytea NOT NULL
        CHECK (octet_length(deployment_digest) = 32),
    artifact_digest bytea NOT NULL
        CHECK (octet_length(artifact_digest) = 32),
    next_step integer NOT NULL CHECK (next_step >= 0),
    step_count integer NOT NULL CHECK (step_count >= 2 AND next_step < step_count),
    expires_at timestamptz NOT NULL,
    lease_id bytea NOT NULL CHECK (octet_length(lease_id) = 16),
    lease_until timestamptz NOT NULL,
    step_started boolean NOT NULL DEFAULT false,
    CHECK (lease_until <= expires_at)
);

CREATE INDEX adapter_idempotency_resume_expiry_idx
    ON adapter_idempotency_resumes (expires_at, scope_digest);

CREATE INDEX adapter_idempotency_resume_artifact_idx
    ON adapter_idempotency_resumes (
        deployment_digest, artifact_digest, expires_at);

CREATE TABLE adapter_idempotency_resume_bindings (
    scope_digest bytea NOT NULL
        REFERENCES adapter_idempotency_resumes(scope_digest) ON DELETE CASCADE,
    step_ordinal integer NOT NULL CHECK (step_ordinal >= 0),
    name varchar(256) NOT NULL CHECK (name <> ''),
    value varchar(256) NOT NULL
        CHECK (value <> '' AND value !~ '[[:cntrl:]]'),
    PRIMARY KEY (scope_digest, name)
);
