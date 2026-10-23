-- SPDX-License-Identifier: Apache-2.0
-- Document Store schema, version 100: the 1.0 baseline.
--
-- Erasure deletes bytes, never records. A document and its versions stay as
-- tombstones once their content is erased, so every foreign key below is
-- `ON DELETE RESTRICT`: no delete may cascade through a grant, a job, or a
-- version and take an audit-relevant row with it, and a delete that would
-- strand a referencing row fails instead. The rows erasure does delete
-- (`documents_contents`, `documents_staged_objects`) are referenced by
-- nothing.

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
    custodian_issuer text NOT NULL CHECK (custodian_issuer <> ''),
    custodian_subject text NOT NULL CHECK (custodian_subject <> ''),
    custodian_kind text NOT NULL CHECK (custodian_kind IN ('service', 'human')),
    -- The person on whose behalf custody is held, when the custody profile
    -- names one. Never used to decide release by itself.
    represented_principal_subject text
        CHECK (represented_principal_subject <> ''),
    -- An untrusted caller-supplied label: stored and returned, never used
    -- for authorization.
    label text CHECK (octet_length(label) BETWEEN 1 AND 256),
    created_at timestamptz NOT NULL,
    -- When the custodian asked for the document's removal. Set once, by the
    -- first request: a later request is a repeat. A rejection arms its
    -- version's erasure without setting it, so a removal after a rejection
    -- is still the first.
    removal_requested_at timestamptz CHECK (removal_requested_at >= created_at)
);

-- The custodian quota sums bytes per custodian (issuer, kind, subject) and policy.
CREATE INDEX IF NOT EXISTS documents_documents_custodian_idx
    ON documents_documents (custodian_issuer, custodian_kind, custodian_subject, policy_id);

-- The caller's documents, listed in creation order.
CREATE INDEX IF NOT EXISTS documents_documents_custodian_list_idx
    ON documents_documents (custodian_issuer, custodian_subject, created_at, document_id);

-- One immutable document version. The upload, verification, and eligibility
-- dimensions move independently; the status a reader sees is derived from
-- them. Provenance is written once, at reservation and at finalization.
CREATE TABLE IF NOT EXISTS documents_versions (
    version_id uuid PRIMARY KEY,
    -- RESTRICT: a document row is a tombstone that outlives its versions'
    -- bytes; it is never deleted while a version names it.
    document_id uuid NOT NULL
        REFERENCES documents_documents (document_id) ON DELETE RESTRICT,
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
    issuing_institution text CHECK (issuing_institution <> ''),
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
    -- The custody clock: a custodian's removal request moves a version to
    -- `pending` with the policy's cleanup grace frozen into `erasure_due_at`,
    -- and the sweep records `erased` once the bytes are gone. No grant
    -- expiry or revocation touches these columns.
    erasure_state text NOT NULL DEFAULT 'none'
        CHECK (erasure_state IN ('none', 'pending', 'erased')),
    erasure_requested_at timestamptz,
    erasure_due_at timestamptz,
    erased_at timestamptz,
    -- Advanced by every update that changes the version's state, so the
    -- revision an event reports only grows for one version.
    revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1),
    -- A CHECK passes when its expression is NULL, so every equality on a
    -- nullable column in the shape checks below carries its own IS NOT NULL.
    CONSTRAINT documents_versions_finalized_shape CHECK (
        (upload_state = 'finalized'
            AND computed_digest IS NOT NULL
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
    CONSTRAINT documents_versions_erasure_shape CHECK (
        (erasure_state = 'none'
            AND erasure_requested_at IS NULL
            AND erasure_due_at IS NULL
            AND erased_at IS NULL)
        OR (erasure_state = 'pending'
            AND erasure_requested_at IS NOT NULL
            AND erasure_due_at IS NOT NULL
            AND erasure_due_at >= erasure_requested_at
            AND erased_at IS NULL)
        OR (erasure_state = 'erased'
            AND erasure_requested_at IS NOT NULL
            AND erasure_due_at IS NOT NULL
            AND erasure_due_at >= erasure_requested_at
            AND erased_at IS NOT NULL
            AND erased_at >= erasure_requested_at)
    ),
    -- A version whose removal was requested is never releasable again.
    CONSTRAINT documents_versions_release_shape CHECK (
        eligibility = 'suspended'
        OR (erasure_state = 'none'
            AND verification_state = 'approved'
            AND verified_binding_digest IS NOT NULL
            AND verification_binding_digest IS NOT NULL
            AND verified_binding_digest = verification_binding_digest
            AND verified_digest IS NOT NULL
            AND computed_digest IS NOT NULL
            AND verified_digest = computed_digest
            AND verified_media_type IS NOT NULL
            AND verified_media_type = media_type
            AND verified_at IS NOT NULL)
    ),
    CONSTRAINT documents_versions_rejection_shape CHECK (
        verification_state <> 'rejected' OR eligibility = 'suspended'
    ),
    -- The pair a grant names, so a grant cannot name another document's
    -- version.
    CONSTRAINT documents_versions_document_version UNIQUE (document_id, version_id)
);

CREATE INDEX IF NOT EXISTS documents_versions_document_idx
    ON documents_versions (document_id);

-- The upload-expiry sweep reads only reserved versions past their deadline,
-- oldest first: a partial index on the deadline over the reserved rows lets
-- it range-scan the due prefix instead of the whole version table, and stays
-- as small as the set of uploads in flight.
CREATE INDEX IF NOT EXISTS documents_versions_upload_expiry_idx
    ON documents_versions (upload_expires_at)
    WHERE upload_state = 'reserved';

-- The erasure sweep reads only versions awaiting erasure whose grace has
-- passed: the partial index holds just the pending rows, ordered by due
-- time, so the scan stops at the first version not yet due.
CREATE INDEX IF NOT EXISTS documents_versions_erasure_due_idx
    ON documents_versions (erasure_due_at)
    WHERE erasure_state = 'pending';

-- Documents a caller reserved for another custodian, listed in creation
-- order.
CREATE INDEX IF NOT EXISTS documents_versions_actor_idx
    ON documents_versions (actor_issuer, actor_subject, reserved_at, document_id);

-- One document grant: a named recipient, one exact version, and an expiry
-- frozen at issue. A grant is never extended; revocation is final.
CREATE TABLE IF NOT EXISTS documents_grants (
    grant_id uuid PRIMARY KEY,
    -- RESTRICT on both: a grant is share history the custodian and the
    -- audit trail still name after erasure. Erasure revokes a grant and
    -- keeps its row; it never deletes one.
    document_id uuid NOT NULL
        REFERENCES documents_documents (document_id) ON DELETE RESTRICT,
    version_id uuid NOT NULL
        REFERENCES documents_versions (version_id) ON DELETE RESTRICT,
    grantee_issuer text NOT NULL CHECK (grantee_issuer <> ''),
    grantee_subject text NOT NULL CHECK (grantee_subject <> ''),
    grantee_kind text NOT NULL
        CONSTRAINT documents_grants_grantee_kind CHECK (grantee_kind IN ('service', 'human')),
    granted_by_issuer text NOT NULL CHECK (granted_by_issuer <> ''),
    granted_by_subject text NOT NULL CHECK (granted_by_subject <> ''),
    granted_by_profile text NOT NULL CHECK (granted_by_profile <> ''),
    issued_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > issued_at),
    revoked_at timestamptz CHECK (revoked_at >= issued_at),
    -- 1 at issue, advanced once by revocation, the only later change.
    revision bigint NOT NULL DEFAULT 1 CHECK (revision >= 1),
    -- RESTRICT: like the single-column keys above, the pair a grant names
    -- outlives erasure; a version is never deleted while a grant names it.
    CONSTRAINT documents_grants_document_version FOREIGN KEY (document_id, version_id)
        REFERENCES documents_versions (document_id, version_id) ON DELETE RESTRICT
);

CREATE INDEX IF NOT EXISTS documents_grants_document_idx
    ON documents_grants (document_id, issued_at, grant_id);
CREATE INDEX IF NOT EXISTS documents_grants_grantee_idx
    ON documents_grants (grantee_issuer, grantee_subject, grantee_kind, issued_at, grant_id);
CREATE INDEX IF NOT EXISTS documents_grants_version_idx
    ON documents_grants (version_id, grantee_issuer, grantee_subject, grantee_kind);

-- One idempotency key, scoped to the caller and the operation and stored
-- only as a digest. The request digest is the canonical body's; the
-- resource is the one the first request created. A key expires with the
-- receipt retention period. It carries no foreign key: a key's resource
-- may be a document or a grant, both kept as tombstones, so erasure never
-- leaves a key naming a missing row. The erasure sweep does not prune keys.
CREATE TABLE IF NOT EXISTS documents_idempotency (
    key_digest text PRIMARY KEY CHECK (key_digest ~ '^[0-9a-f]{64}$'),
    request_digest text NOT NULL CHECK (request_digest ~ '^[0-9a-f]{64}$'),
    resource_id uuid NOT NULL,
    created_at timestamptz NOT NULL,
    expires_at timestamptz NOT NULL CHECK (expires_at > created_at)
);

-- Content held in PostgreSQL, one row per finalized version.
CREATE TABLE IF NOT EXISTS documents_contents (
    -- RESTRICT: erasure deletes this row and keeps the version. A version
    -- is never deleted, so the bytes never vanish by cascade unrecorded.
    -- Deleting the row makes the bytes unservable at once; the space they
    -- held is reclaimed only when PostgreSQL vacuums the table and its
    -- TOAST relation.
    version_id uuid PRIMARY KEY
        REFERENCES documents_versions (version_id) ON DELETE RESTRICT,
    content bytea NOT NULL
);

-- An S3 object written for an upload attempt. The row is committed before
-- the object PUT, under a fresh object id per attempt, so an orphan left by
-- a failed attempt stays findable. `committed` turns true in the finalizing
-- transaction of the one attempt that won.
CREATE TABLE IF NOT EXISTS documents_staged_objects (
    object_id uuid PRIMARY KEY,
    -- RESTRICT: the row is deleted only after its object is confirmed gone,
    -- by the erasure or orphan sweep; the version stays.
    version_id uuid NOT NULL
        REFERENCES documents_versions (version_id) ON DELETE RESTRICT,
    binding_digest text NOT NULL CHECK (binding_digest ~ '^[0-9a-f]{64}$'),
    sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
    length bigint NOT NULL CHECK (length > 0),
    staged_at timestamptz NOT NULL,
    committed boolean NOT NULL DEFAULT false
);

CREATE INDEX IF NOT EXISTS documents_staged_objects_version_idx
    ON documents_staged_objects (version_id);

-- The orphan sweep reads only uncommitted rows older than its settling age:
-- the partial index holds just the uncommitted rows, which a finalized
-- upload leaves none of, ordered by staging time.
CREATE INDEX IF NOT EXISTS documents_staged_objects_orphan_idx
    ON documents_staged_objects (staged_at)
    WHERE NOT committed;

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
            AND lease_expires_at IS NOT NULL
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
    -- RESTRICT: a job is attempt history for a version that is never
    -- deleted.
    ADD CONSTRAINT documents_verification_jobs_version
        FOREIGN KEY (version_id) REFERENCES documents_versions (version_id)
        ON DELETE RESTRICT;

-- The erasure job table, exactly the shape `registry-platform-dispatch`
-- declares (`JobTable::create_statements`), keyed by the version and a
-- fixed part. One job erases one version's bytes. A unit test holds the two
-- in parity.
CREATE TABLE IF NOT EXISTS documents_erasure_jobs (
    version_id uuid NOT NULL,
    part text NOT NULL
        CHECK (part <> '' AND octet_length(part) <= 256),
    generation bigint NOT NULL CHECK (generation > 0),
    state text NOT NULL
        CONSTRAINT documents_erasure_jobs_state_values CHECK (
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
    CONSTRAINT documents_erasure_jobs_shape CHECK (
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
            AND lease_expires_at IS NOT NULL
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
CREATE INDEX IF NOT EXISTS documents_erasure_jobs_due_idx
    ON documents_erasure_jobs (next_attempt_at, version_id, part)
    WHERE state = 'pending';
CREATE INDEX IF NOT EXISTS documents_erasure_jobs_lease_idx
    ON documents_erasure_jobs (lease_expires_at, version_id, part)
    WHERE state = 'leased';


ALTER TABLE documents_erasure_jobs
    -- RESTRICT: a job is attempt history for a version that is never
    -- deleted.
    ADD CONSTRAINT documents_erasure_jobs_version
        FOREIGN KEY (version_id) REFERENCES documents_versions (version_id)
        ON DELETE RESTRICT;

-- The activation ledger: one row per package `documentsctl apply` made
-- active, oldest first. `serve` refuses a database whose newest row does
-- not name the deployed package and this deployment's database id.
CREATE TABLE IF NOT EXISTS documents_activations (
    activation_id uuid PRIMARY KEY,
    apply_order bigint NOT NULL UNIQUE CHECK (apply_order > 0),
    package_digest text NOT NULL CHECK (package_digest ~ '^sha256:[0-9a-f]{64}$'),
    predecessor_package_digest text CHECK (predecessor_package_digest ~ '^sha256:[0-9a-f]{64}$'),
    database_id text NOT NULL CHECK (length(database_id) BETWEEN 1 AND 256),
    plan_kind text NOT NULL CHECK (plan_kind IN ('initial', 'successor')),
    applied_at timestamptz NOT NULL,
    operator_reference_hash text,
    backup_references text[] NOT NULL DEFAULT '{}' CHECK (cardinality(backup_references) <= 16),
    role_mode text NOT NULL CHECK (role_mode IN ('single', 'split')),
    CHECK ((plan_kind = 'initial') = (predecessor_package_digest IS NULL))
);
