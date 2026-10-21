-- SPDX-License-Identifier: Apache-2.0
-- Document Store schema, version 100: the 1.0 baseline.

-- The storage binding a deployment pinned at its first write. A later start
-- under another backend, bucket, or scope refuses rather than reading or
-- writing content somewhere else.
CREATE TABLE IF NOT EXISTS documents_storage_binding (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    backend text NOT NULL CHECK (backend IN ('database', 's3')),
    binding_digest text NOT NULL CHECK (binding_digest ~ '^[0-9a-f]{64}$'),
    pinned_at timestamptz NOT NULL
);

-- One document in custody, under the policy binding frozen at reservation.
CREATE TABLE IF NOT EXISTS documents_documents (
    document_id uuid PRIMARY KEY,
    policy_id text NOT NULL CHECK (policy_id <> ''),
    policy_version text NOT NULL CHECK (policy_version <> ''),
    policy_digest text NOT NULL CHECK (policy_digest ~ '^sha256:[0-9a-f]{64}$'),
    custodian_subject text NOT NULL CHECK (custodian_subject <> ''),
    created_at timestamptz NOT NULL
);

CREATE INDEX IF NOT EXISTS documents_documents_custodian_idx
    ON documents_documents (custodian_subject, policy_id);

-- One immutable document version. The upload, verification, and eligibility
-- dimensions move independently; the status a reader sees is derived from
-- them. Provenance is written once, at reservation and at finalization.
CREATE TABLE IF NOT EXISTS documents_versions (
    version_id uuid PRIMARY KEY,
    document_id uuid NOT NULL REFERENCES documents_documents (document_id),
    upload_id uuid NOT NULL UNIQUE,
    upload_state text NOT NULL
        CHECK (upload_state IN ('reserved', 'finalized', 'expired')),
    verification_state text NOT NULL
        CHECK (verification_state IN ('pending', 'approved', 'rejected')),
    eligibility text NOT NULL
        CHECK (eligibility IN ('suspended', 'releasable')),
    media_type text NOT NULL CHECK (media_type <> ''),
    expected_digest text NOT NULL CHECK (expected_digest ~ '^sha256:[0-9a-f]{64}$'),
    length bigint NOT NULL CHECK (length > 0),
    actor_issuer text NOT NULL CHECK (actor_issuer <> ''),
    actor_subject text NOT NULL CHECK (actor_subject <> ''),
    actor_kind text NOT NULL CHECK (actor_kind IN ('service', 'human')),
    client_id text NOT NULL CHECK (client_id <> ''),
    access_profile_id text NOT NULL CHECK (access_profile_id <> ''),
    issuing_institution text NOT NULL CHECK (issuing_institution <> ''),
    reserved_at timestamptz NOT NULL,
    upload_expires_at timestamptz NOT NULL CHECK (upload_expires_at > reserved_at),
    computed_digest text CHECK (computed_digest ~ '^sha256:[0-9a-f]{64}$'),
    finalized_at timestamptz,
    storage_backend text CHECK (storage_backend IN ('database', 's3')),
    object_id uuid,
    verification_binding_digest text,
    verified_binding_digest text,
    verified_digest text,
    verified_media_type text,
    verified_at timestamptz,
    CONSTRAINT documents_versions_finalized_shape CHECK (
        (upload_state = 'finalized'
            AND computed_digest = expected_digest
            AND finalized_at IS NOT NULL
            AND storage_backend IS NOT NULL
            AND verification_binding_digest IS NOT NULL
            AND (storage_backend = 'database') = (object_id IS NULL))
        OR (upload_state <> 'finalized'
            AND computed_digest IS NULL
            AND finalized_at IS NULL
            AND storage_backend IS NULL
            AND object_id IS NULL
            AND verification_state = 'pending'
            AND eligibility = 'suspended')
    ),
    CONSTRAINT documents_versions_release_shape CHECK (
        eligibility = 'suspended'
        OR (verification_state = 'approved'
            AND verified_binding_digest = verification_binding_digest
            AND verified_digest = computed_digest
            AND verified_media_type = media_type
            AND verified_at IS NOT NULL)
    ),
    CONSTRAINT documents_versions_rejection_shape CHECK (
        verification_state <> 'rejected' OR eligibility = 'suspended'
    )
);

CREATE INDEX IF NOT EXISTS documents_versions_document_idx
    ON documents_versions (document_id);

-- Content held in PostgreSQL, one row per finalized version.
CREATE TABLE IF NOT EXISTS documents_contents (
    version_id uuid PRIMARY KEY REFERENCES documents_versions (version_id),
    content bytea NOT NULL
);

-- An S3 object written for an upload attempt. The row is committed before
-- the object PUT, under a fresh object id per attempt, so an orphan left by
-- a failed attempt stays findable. `committed` turns true in the finalizing
-- transaction of the one attempt that won.
CREATE TABLE IF NOT EXISTS documents_staged_objects (
    object_id uuid PRIMARY KEY,
    version_id uuid NOT NULL REFERENCES documents_versions (version_id),
    binding_digest text NOT NULL CHECK (binding_digest ~ '^[0-9a-f]{64}$'),
    sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    length bigint NOT NULL CHECK (length > 0),
    staged_at timestamptz NOT NULL,
    committed boolean NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS documents_staged_objects_version_idx
    ON documents_staged_objects (version_id);

-- The content verification job table, exactly the shape
-- `registry-platform-dispatch` declares (`JobTable::create_statements`),
-- keyed by the version and a part derived from the verifier binding. A unit
-- test holds the two in parity.
CREATE TABLE IF NOT EXISTS documents_verification_jobs (
    version_id uuid NOT NULL,
    part text NOT NULL
        CHECK (part <> '' AND octet_length(part) <= 256),
    generation bigint NOT NULL CHECK (generation > 0),
    state text NOT NULL
        CONSTRAINT documents_verification_jobs_state_values CHECK (
            state IN ('pending', 'leased', 'delivered', 'dead-lettered',
                      'expired', 'unknown', 'cancelled')
        ),
    attempt smallint NOT NULL CHECK (attempt >= 0),
    next_attempt_at timestamptz,
    attempt_started_at timestamptz,
    lease_expires_at timestamptz,
    lease_token uuid,
    delivered_at timestamptz,
    dead_lettered_at timestamptz,
    expired_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
    PRIMARY KEY (version_id, part),
    CONSTRAINT documents_verification_jobs_shape CHECK (
        (state = 'pending'
            AND next_attempt_at IS NOT NULL
            AND attempt_started_at IS NULL
            AND lease_expires_at IS NULL
            AND lease_token IS NULL
            AND delivered_at IS NULL
            AND dead_lettered_at IS NULL
            AND expired_at IS NULL)
        OR (state = 'leased'
            AND attempt > 0
            AND next_attempt_at IS NULL
            AND attempt_started_at IS NOT NULL
            AND lease_expires_at > attempt_started_at
            AND lease_token IS NOT NULL
            AND delivered_at IS NULL
            AND dead_lettered_at IS NULL
            AND expired_at IS NULL)
        OR (state = 'delivered'
            AND attempt > 0
            AND next_attempt_at IS NULL
            AND attempt_started_at IS NULL
            AND lease_expires_at IS NULL
            AND lease_token IS NULL
            AND delivered_at IS NOT NULL
            AND dead_lettered_at IS NULL
            AND expired_at IS NULL)
        OR (state = 'dead-lettered'
            AND attempt > 0
            AND next_attempt_at IS NULL
            AND attempt_started_at IS NULL
            AND lease_expires_at IS NULL
            AND lease_token IS NULL
            AND delivered_at IS NULL
            AND dead_lettered_at IS NOT NULL)
        OR (state = 'expired'
            AND next_attempt_at IS NULL
            AND attempt_started_at IS NULL
            AND lease_expires_at IS NULL
            AND lease_token IS NULL
            AND delivered_at IS NULL
            AND dead_lettered_at IS NULL
            AND expired_at IS NOT NULL)
        OR (state = 'unknown'
            AND attempt > 0
            AND next_attempt_at IS NULL
            AND attempt_started_at IS NULL
            AND lease_expires_at IS NULL
            AND lease_token IS NULL
            AND delivered_at IS NULL
            AND dead_lettered_at IS NULL
            AND expired_at IS NULL)
        OR (state = 'cancelled'
            AND next_attempt_at IS NULL
            AND attempt_started_at IS NULL
            AND lease_expires_at IS NULL
            AND lease_token IS NULL
            AND delivered_at IS NULL
            AND dead_lettered_at IS NULL
            AND expired_at IS NULL)
    )
);
CREATE INDEX IF NOT EXISTS documents_verification_jobs_due_idx
    ON documents_verification_jobs (next_attempt_at, version_id, part)
    WHERE state = 'pending';
CREATE INDEX IF NOT EXISTS documents_verification_jobs_lease_idx
    ON documents_verification_jobs (lease_expires_at, version_id, part)
    WHERE state = 'leased';


ALTER TABLE documents_verification_jobs
    ADD CONSTRAINT documents_verification_jobs_version
        FOREIGN KEY (version_id) REFERENCES documents_versions (version_id);
