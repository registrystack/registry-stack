// SPDX-License-Identifier: Apache-2.0
//! Installation and catalog attestation for Relay's PostgreSQL state plane.

use std::fmt;

use thiserror::Error;
use tokio_postgres::{Client, GenericClient, Row, Transaction};

use super::fence::ServingFenceLockKey;

pub(crate) const DURABLE_AUDIT_CAPABILITY_V1: &str = "registry.relay.postgres-durable-audit/v1";
pub(crate) const SERVING_FENCE_CAPABILITY_V1: &str = "registry.relay.postgres-serving-fence/v1";
pub(crate) const PERSISTENT_QUOTA_CAPABILITY_V1: &str =
    "registry.relay.postgres-persistent-quota/v1";
pub(crate) const AUDIT_PSEUDONYM_KEYRING_CAPABILITY_V1: &str =
    "registry.relay.postgres-audit-pseudonym-keyring/v1";
pub(crate) const STATE_PLANE_SCHEMA_VERSION_V1: i32 = 1;
// This semantic identity deliberately changes when a capability revision or
// cross-runtime protocol invariant changes. Exact PostgreSQL structure and
// executable bodies are attested separately by the live catalog fingerprints.
#[cfg(test)]
const STATE_PLANE_SCHEMA_IDENTITY_PREIMAGE_V1: &str = concat!(
    "registry.relay.postgres-state-plane.semantic-identity.v1\0",
    "schema-version=1\0",
    "durable-audit=registry.relay.postgres-durable-audit/v1\0",
    "serving-fence=registry.relay.postgres-serving-fence/v1\0",
    "persistent-quota=registry.relay.postgres-persistent-quota/v1\0",
    "audit-pseudonym-keyring=registry.relay.postgres-audit-pseudonym-keyring/v1\0",
    "consultation-completion=atomic-intent-sealed-seed-plan-slots-selected-operations-known-unfinished-recovery-v1\0",
    "consultation-authorization=database-expiry-seed-timeout-exact-dispatch-prefix-v2\0",
    "consultation-credentials=direct-data-auth-reference-distinct-fresh-opencrvs-no-expiry-jwks-v2\0",
    "serving-fence-order=fence-row-keyring-intent-permit-audit-head-v1\0",
    "key-order=utf8-bytewise-key-order-v1\0",
);
pub(crate) const STATE_PLANE_SCHEMA_FINGERPRINT_V1: &str =
    "sha256:6602f5a07f80cb18d8b5cc78f0369d8b3bd765547f4765b39509997bbaca3090";

pub(super) const MIGRATION_ADVISORY_LOCK_KEY_V1: i64 = 7_221_091_440;
const SUPPORTED_POSTGRES_MIN_MAJOR: i32 = 16;
const SUPPORTED_POSTGRES_MAX_MAJOR: i32 = 18;

// Filled from the semantic catalog descriptor below on disposable supported
// PostgreSQL majors. Constraint rendering is explicitly versioned because
// pg_get_constraintdef is not a cross-major wire contract.
const CONSTRAINT_FINGERPRINT_PG16: &str = "4c5905e22d262645abcd05affe4da82f";
const CONSTRAINT_FINGERPRINT_PG17: &str = "4c5905e22d262645abcd05affe4da82f";
const CONSTRAINT_FINGERPRINT_PG18: &str = "6c11c5f44018f8cf06c439af932d7a15";
const COLUMN_FINGERPRINT_PG16: &str = "1098f1125fa6f613d521504e985a351a";
const COLUMN_FINGERPRINT_PG17: &str = "1098f1125fa6f613d521504e985a351a";
const COLUMN_FINGERPRINT_PG18: &str = "1098f1125fa6f613d521504e985a351a";
const FUNCTION_FINGERPRINT_PG16: &str = "ff865db8ec5369d3b87ac2498e0f7bf6";
const FUNCTION_FINGERPRINT_PG17: &str = "ff865db8ec5369d3b87ac2498e0f7bf6";
const FUNCTION_FINGERPRINT_PG18: &str = "ff865db8ec5369d3b87ac2498e0f7bf6";
const CAPABILITY_HELPER_BODY_FINGERPRINT_V1: &str = "31af68e3b2ef65fead1674a7758ac418";

/// Runtime-forceable session semantics. Server/SUSET state that the runtime
/// cannot safely repair is rejected by the attested SQL capability instead.
pub(super) const RUNTIME_SESSION_LIMITS_SQL: &str = r#"
SET statement_timeout = '5s';
SET lock_timeout = '2s';
SET idle_in_transaction_session_timeout = '5s';
SET synchronous_commit = 'on';
SET search_path = pg_catalog, relay_state_private;
SET client_encoding = 'UTF8';
SET standard_conforming_strings = 'on';
SET default_transaction_isolation = 'read committed';
"#;

const INSTALL_TRANSACTION_LIMITS_SQL: &str = r#"
SET LOCAL lock_timeout = '5s';
SET LOCAL statement_timeout = '30s';
SET LOCAL idle_in_transaction_session_timeout = '10s';
SET LOCAL synchronous_commit = 'on';
SET LOCAL search_path = pg_catalog, relay_state_private;
"#;

/// Clean-or-attested v1 DDL. Partial schemas are rejected before this runs.
pub(crate) const POSTGRES_STATE_PLANE_MIGRATION_V1: &str = r#"
CREATE SCHEMA IF NOT EXISTS relay_state_private;
CREATE SCHEMA IF NOT EXISTS relay_state_api;
ALTER SCHEMA relay_state_private OWNER TO CURRENT_USER;
ALTER SCHEMA relay_state_api OWNER TO CURRENT_USER;
REVOKE ALL ON SCHEMA relay_state_private FROM PUBLIC;
REVOKE ALL ON SCHEMA relay_state_api FROM PUBLIC;

CREATE TABLE IF NOT EXISTS relay_state_private.state_plane_metadata (
    singleton boolean NOT NULL DEFAULT true,
    schema_version integer NOT NULL,
    capability_id text NOT NULL,
    capability_fingerprint text NOT NULL,
    owner_role_oid oid NOT NULL,
    runtime_role_oid oid NOT NULL,
    audit_pseudonym_maintenance_role_oid oid NOT NULL,
    audit_pseudonym_reader_role_oid oid NOT NULL,
    chain_key_epoch_id text NOT NULL,
    serving_fence_capability_id text NOT NULL,
    serving_fence_lock_key bigint NOT NULL,
    quota_capability_id text NOT NULL,
    audit_pseudonym_keyring_capability_id text NOT NULL,
    audit_pseudonym_keyring_lock_key bigint NOT NULL,
    installed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT state_plane_metadata_pk PRIMARY KEY (singleton),
    CONSTRAINT state_plane_metadata_singleton_check CHECK (singleton),
    CONSTRAINT state_plane_metadata_schema_version_check CHECK (schema_version = 1),
    CONSTRAINT state_plane_metadata_capability_id_check CHECK (
        capability_id = 'registry.relay.postgres-durable-audit/v1'
    ),
    CONSTRAINT state_plane_metadata_fingerprint_check CHECK (
        capability_fingerprint =
        'sha256:6602f5a07f80cb18d8b5cc78f0369d8b3bd765547f4765b39509997bbaca3090'
    ),
    CONSTRAINT state_plane_metadata_roles_distinct_check CHECK (
        owner_role_oid <> runtime_role_oid
        AND owner_role_oid <> audit_pseudonym_maintenance_role_oid
        AND owner_role_oid <> audit_pseudonym_reader_role_oid
        AND runtime_role_oid <> audit_pseudonym_maintenance_role_oid
        AND runtime_role_oid <> audit_pseudonym_reader_role_oid
        AND audit_pseudonym_maintenance_role_oid <> audit_pseudonym_reader_role_oid
    ),
    CONSTRAINT state_plane_metadata_chain_epoch_check CHECK (
        octet_length(chain_key_epoch_id) BETWEEN 1 AND 64
        AND chain_key_epoch_id ~ '^[A-Za-z0-9][A-Za-z0-9._:-]*$'
    ),
    CONSTRAINT state_plane_metadata_fence_capability_check CHECK (
        serving_fence_capability_id = 'registry.relay.postgres-serving-fence/v1'
    ),
    CONSTRAINT state_plane_metadata_fence_lock_key_check CHECK (
        serving_fence_lock_key <> 0 AND serving_fence_lock_key <> 7221091440
    ),
    CONSTRAINT state_plane_metadata_quota_capability_check CHECK (
        quota_capability_id = 'registry.relay.postgres-persistent-quota/v1'
    ),
    CONSTRAINT state_plane_metadata_pseudonym_keyring_capability_check CHECK (
        audit_pseudonym_keyring_capability_id =
        'registry.relay.postgres-audit-pseudonym-keyring/v1'
    ),
    CONSTRAINT state_plane_metadata_pseudonym_keyring_lock_key_check CHECK (
        audit_pseudonym_keyring_lock_key <> 0
        AND audit_pseudonym_keyring_lock_key <> 7221091440
        AND audit_pseudonym_keyring_lock_key <> serving_fence_lock_key
    )
);

CREATE TABLE IF NOT EXISTS relay_state_private.audit_chain_head (
    singleton boolean NOT NULL DEFAULT true,
    generation bigint NOT NULL DEFAULT 0,
    record_hash bytea NULL,
    advanced_at timestamptz NULL,
    CONSTRAINT audit_chain_head_pk PRIMARY KEY (singleton),
    CONSTRAINT audit_chain_head_singleton_check CHECK (singleton),
    CONSTRAINT audit_chain_head_generation_check CHECK (generation >= 0),
    CONSTRAINT audit_chain_head_hash_check CHECK (
        record_hash IS NULL OR octet_length(record_hash) = 32
    )
);
INSERT INTO relay_state_private.audit_chain_head (singleton, generation, record_hash)
VALUES (true, 0, NULL)
ON CONFLICT (singleton) DO NOTHING;

CREATE TABLE IF NOT EXISTS relay_state_private.audit_phase (
    stream_kind text NOT NULL,
    operation_id text NOT NULL,
    phase text NOT NULL,
    payload_digest bytea NOT NULL,
    envelope_id text NOT NULL,
    timestamp_unix_ms bigint NOT NULL,
    predecessor_hash bytea NULL,
    record_json text NOT NULL,
    envelope_json text NOT NULL,
    record_hash bytea NOT NULL,
    attempt_stream_kind text NULL,
    attempt_operation_id text NULL,
    attempt_phase text NULL,
    attempt_envelope_id text NULL,
    attempt_record_hash bytea NULL,
    inserted_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT audit_phase_pk PRIMARY KEY (stream_kind, operation_id, phase),
    CONSTRAINT audit_phase_envelope_id_unique UNIQUE (envelope_id),
    CONSTRAINT audit_phase_stored_identity_unique UNIQUE (
        stream_kind, operation_id, phase, envelope_id, record_hash
    ),
    CONSTRAINT audit_phase_stream_kind_check CHECK (stream_kind IN (
        'consultation', 'materialization', 'denial',
        'startup_credential_probe', 'readiness_credential_probe'
    )),
    CONSTRAINT audit_phase_operation_id_check CHECK (
        operation_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'
    ),
    CONSTRAINT audit_phase_phase_check CHECK (
        phase IN ('attempt', 'completion', 'denial_decision')
    ),
    CONSTRAINT audit_phase_payload_digest_check CHECK (octet_length(payload_digest) = 32),
    CONSTRAINT audit_phase_envelope_id_check CHECK (
        envelope_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'
    ),
    CONSTRAINT audit_phase_predecessor_hash_check CHECK (
        predecessor_hash IS NULL OR octet_length(predecessor_hash) = 32
    ),
    CONSTRAINT audit_phase_record_json_check CHECK (
        octet_length(record_json) <= 1048576
        AND jsonb_typeof(record_json::jsonb) = 'object'
    ),
    CONSTRAINT audit_phase_envelope_json_check CHECK (
        octet_length(envelope_json) <= 1310720
        AND jsonb_typeof(envelope_json::jsonb) = 'object'
    ),
    CONSTRAINT audit_phase_record_hash_check CHECK (octet_length(record_hash) = 32),
    CONSTRAINT audit_phase_attempt_record_hash_check CHECK (
        attempt_record_hash IS NULL OR octet_length(attempt_record_hash) = 32
    ),
    CONSTRAINT audit_phase_stream_phase_check CHECK (
        (stream_kind = 'denial' AND phase = 'denial_decision')
        OR (stream_kind <> 'denial' AND phase IN ('attempt', 'completion'))
    ),
    CONSTRAINT audit_phase_completion_reference_check CHECK (
        (
            phase = 'completion'
            AND attempt_stream_kind = stream_kind
            AND attempt_operation_id = operation_id
            AND attempt_phase = 'attempt'
            AND attempt_envelope_id IS NOT NULL
            AND attempt_record_hash IS NOT NULL
        )
        OR
        (
            phase <> 'completion'
            AND attempt_stream_kind IS NULL
            AND attempt_operation_id IS NULL
            AND attempt_phase IS NULL
            AND attempt_envelope_id IS NULL
            AND attempt_record_hash IS NULL
        )
    ),
    CONSTRAINT audit_phase_attempt_fk FOREIGN KEY (
        attempt_stream_kind, attempt_operation_id, attempt_phase,
        attempt_envelope_id, attempt_record_hash
    ) REFERENCES relay_state_private.audit_phase (
        stream_kind, operation_id, phase, envelope_id, record_hash
    )
);

CREATE TABLE IF NOT EXISTS relay_state_private.serving_fence_state (
    singleton boolean NOT NULL DEFAULT true,
    generation bigint NOT NULL DEFAULT 0,
    holder_id text NULL,
    holder_backend_pid integer NULL,
    acquired_at timestamptz NULL,
    takeover_pending boolean NOT NULL DEFAULT false,
    takeover_pg_not_before timestamptz NULL,
    admission_open boolean NOT NULL DEFAULT false,
    CONSTRAINT serving_fence_state_pk PRIMARY KEY (singleton),
    CONSTRAINT serving_fence_state_singleton_check CHECK (singleton),
    CONSTRAINT serving_fence_state_generation_check CHECK (generation >= 0),
    CONSTRAINT serving_fence_state_holder_id_check CHECK (
        holder_id IS NULL OR holder_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'
    ),
    CONSTRAINT serving_fence_state_shape_check CHECK (
        (
            generation = 0
            AND holder_id IS NULL
            AND holder_backend_pid IS NULL
            AND acquired_at IS NULL
            AND NOT takeover_pending
            AND takeover_pg_not_before IS NULL
            AND NOT admission_open
        )
        OR
        (
            generation > 0
            AND holder_id IS NOT NULL
            AND holder_backend_pid IS NOT NULL
            AND holder_backend_pid > 0
            AND acquired_at IS NOT NULL
            AND (takeover_pending = (takeover_pg_not_before IS NOT NULL))
            AND NOT (takeover_pending AND admission_open)
        )
    )
);
INSERT INTO relay_state_private.serving_fence_state (
    singleton, generation, takeover_pending, admission_open
) VALUES (true, 0, false, false)
ON CONFLICT (singleton) DO NOTHING;

CREATE TABLE IF NOT EXISTS relay_state_private.consultation_completion_intent (
    operation_id text NOT NULL,
    attempt_stream_kind text NOT NULL DEFAULT 'consultation',
    attempt_phase text NOT NULL DEFAULT 'attempt',
    attempt_envelope_id text NOT NULL,
    attempt_record_hash bytea NOT NULL,
    attempt_payload_digest bytea NOT NULL,
    fence_generation bigint NOT NULL,
    holder_id text NOT NULL,
    budget_ms integer NOT NULL,
    decision_expires_at_unix_ms bigint NOT NULL,
    credential_permit_count smallint NOT NULL,
    data_permit_count smallint NOT NULL,
    created_at timestamptz NOT NULL,
    total_deadline_at timestamptz NOT NULL,
    completion_seed_schema text NOT NULL,
    completion_seed_canonical text NOT NULL,
    completion_seed_digest bytea NOT NULL,
    pseudonym_key_id text NOT NULL,
    pseudonym_bundle_canonical text NOT NULL,
    pseudonym_bundle_digest bytea NOT NULL,
    state text NOT NULL DEFAULT 'open',
    recovery_marked_at timestamptz NULL,
    completion_stream_kind text NULL,
    completion_operation_id text NULL,
    completion_phase text NULL,
    completion_envelope_id text NULL,
    completion_record_hash bytea NULL,
    completed_at timestamptz NULL,
    CONSTRAINT consultation_completion_intent_pk PRIMARY KEY (operation_id),
    CONSTRAINT consultation_completion_intent_deadline_unique UNIQUE (
        operation_id, total_deadline_at
    ),
    CONSTRAINT consultation_completion_intent_operation_id_check CHECK (
        operation_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'
    ),
    CONSTRAINT consultation_completion_intent_attempt_shape_check CHECK (
        attempt_stream_kind = 'consultation'
        AND attempt_phase = 'attempt'
        AND attempt_envelope_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'
        AND octet_length(attempt_record_hash) = 32
        AND octet_length(attempt_payload_digest) = 32
    ),
    CONSTRAINT consultation_completion_intent_fence_check CHECK (
        fence_generation > 0
        AND holder_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'
    ),
    CONSTRAINT consultation_completion_intent_deadline_check CHECK (
        budget_ms BETWEEN 1 AND 20000
        AND decision_expires_at_unix_ms BETWEEN 0 AND 9007199254740991
        AND total_deadline_at = created_at + budget_ms * interval '1 millisecond'
    ),
    CONSTRAINT consultation_completion_intent_permit_manifest_check CHECK (
        credential_permit_count BETWEEN 0 AND 1
        AND data_permit_count BETWEEN 0 AND 5
        AND credential_permit_count + data_permit_count BETWEEN 0 AND 6
    ),
    CONSTRAINT consultation_completion_intent_seed_check CHECK (
        completion_seed_schema = 'registry.relay.consultation-completion-seed/v1'
        AND octet_length(completion_seed_canonical) BETWEEN 1 AND 262144
        AND jsonb_typeof(completion_seed_canonical::jsonb) = 'object'
        AND completion_seed_canonical::jsonb ->> 'schema' = completion_seed_schema
        AND octet_length(completion_seed_digest) = 32
        AND completion_seed_digest = pg_catalog.sha256(
            pg_catalog.convert_to(completion_seed_canonical, 'UTF8')
        )
    ),
    CONSTRAINT consultation_completion_intent_pseudonym_check CHECK (
        pseudonym_key_id ~ '^[a-z0-9][a-z0-9._-]{0,63}$'
        AND octet_length(pseudonym_bundle_canonical) BETWEEN 1 AND 16384
        AND jsonb_typeof(pseudonym_bundle_canonical::jsonb) = 'object'
        AND pseudonym_bundle_canonical::jsonb ->> 'commitment_key_id' = pseudonym_key_id
        AND octet_length(pseudonym_bundle_digest) = 32
        AND pseudonym_bundle_digest = pg_catalog.sha256(
            pg_catalog.convert_to(pseudonym_bundle_canonical, 'UTF8')
        )
    ),
    CONSTRAINT consultation_completion_intent_state_check CHECK (
        state IN ('open', 'recovery_ready', 'completed')
    ),
    CONSTRAINT consultation_completion_intent_terminal_shape_check CHECK (
        (
            state = 'open'
            AND recovery_marked_at IS NULL
            AND completion_stream_kind IS NULL
            AND completion_operation_id IS NULL
            AND completion_phase IS NULL
            AND completion_envelope_id IS NULL
            AND completion_record_hash IS NULL
            AND completed_at IS NULL
        )
        OR (
            state = 'recovery_ready'
            AND recovery_marked_at IS NOT NULL
            AND recovery_marked_at >= created_at
            AND completion_stream_kind IS NULL
            AND completion_operation_id IS NULL
            AND completion_phase IS NULL
            AND completion_envelope_id IS NULL
            AND completion_record_hash IS NULL
            AND completed_at IS NULL
        )
        OR (
            state = 'completed'
            AND completion_stream_kind = 'consultation'
            AND completion_operation_id = operation_id
            AND completion_phase = 'completion'
            AND completion_envelope_id IS NOT NULL
            AND completion_record_hash IS NOT NULL
            AND octet_length(completion_record_hash) = 32
            AND completed_at IS NOT NULL
            AND completed_at >= created_at
        )
    ),
    CONSTRAINT consultation_completion_intent_attempt_fk FOREIGN KEY (
        attempt_stream_kind, operation_id, attempt_phase,
        attempt_envelope_id, attempt_record_hash
    ) REFERENCES relay_state_private.audit_phase (
        stream_kind, operation_id, phase, envelope_id, record_hash
    ),
    CONSTRAINT consultation_completion_intent_completion_fk FOREIGN KEY (
        completion_stream_kind, completion_operation_id, completion_phase,
        completion_envelope_id, completion_record_hash
    ) REFERENCES relay_state_private.audit_phase (
        stream_kind, operation_id, phase, envelope_id, record_hash
    )
);

CREATE TABLE IF NOT EXISTS relay_state_private.consultation_audit_context (
    backend_pid integer NOT NULL,
    transaction_id bigint NOT NULL,
    operation_id text NOT NULL,
    purpose text NOT NULL,
    CONSTRAINT consultation_audit_context_pk PRIMARY KEY (
        backend_pid, transaction_id, operation_id, purpose
    ),
    CONSTRAINT consultation_audit_context_shape_check CHECK (
        backend_pid > 0
        AND transaction_id > 0
        AND operation_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'
        AND purpose IN ('attempt_snapshot', 'attempt_cas')
    )
);

CREATE TABLE IF NOT EXISTS relay_state_private.dispatch_permit (
    operation_id text NOT NULL,
    kind text NOT NULL,
    ordinal smallint NOT NULL,
    fence_generation bigint NOT NULL,
    holder_id text NOT NULL,
    deadline_at timestamptz NOT NULL,
    source_operation_id text NULL,
    dispatched_at timestamptz NULL,
    abandoned_at timestamptz NULL,
    completion_stream_kind text NULL,
    completion_operation_id text NULL,
    completion_phase text NULL,
    completion_envelope_id text NULL,
    completion_record_hash bytea NULL,
    CONSTRAINT dispatch_permit_pk PRIMARY KEY (operation_id, kind, ordinal),
    CONSTRAINT dispatch_permit_kind_ordinal_check CHECK (
        (kind = 'credential' AND ordinal = 0)
        OR (kind = 'data' AND ordinal BETWEEN 0 AND 4)
    ),
    CONSTRAINT dispatch_permit_generation_check CHECK (fence_generation > 0),
    CONSTRAINT dispatch_permit_holder_id_check CHECK (
        holder_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'
    ),
    CONSTRAINT dispatch_permit_source_operation_check CHECK (
        (source_operation_id IS NULL) = (dispatched_at IS NULL)
        AND (
            source_operation_id IS NULL
            OR source_operation_id ~ '^[a-z][a-z0-9._-]{0,95}$'
        )
    ),
    CONSTRAINT dispatch_permit_terminal_shape_check CHECK (
        (dispatched_at IS NULL OR dispatched_at <= deadline_at)
        AND (abandoned_at IS NULL OR abandoned_at >= dispatched_at)
        AND (
            (
                completion_stream_kind IS NULL
                AND completion_operation_id IS NULL
                AND completion_phase IS NULL
                AND completion_envelope_id IS NULL
                AND completion_record_hash IS NULL
                AND abandoned_at IS NULL
            )
            OR (
                completion_stream_kind = 'consultation'
                AND completion_operation_id = operation_id
                AND completion_phase = 'completion'
                AND completion_envelope_id IS NOT NULL
                AND completion_record_hash IS NOT NULL
                AND octet_length(completion_record_hash) = 32
            )
        )
    ),
    CONSTRAINT dispatch_permit_intent_deadline_fk FOREIGN KEY (
        operation_id, deadline_at
    ) REFERENCES relay_state_private.consultation_completion_intent (
        operation_id, total_deadline_at
    ),
    CONSTRAINT dispatch_permit_completion_fk FOREIGN KEY (
        completion_stream_kind, completion_operation_id, completion_phase,
        completion_envelope_id, completion_record_hash
    ) REFERENCES relay_state_private.audit_phase (
        stream_kind, operation_id, phase, envelope_id, record_hash
    )
);
CREATE INDEX IF NOT EXISTS dispatch_permit_takeover_idx
ON relay_state_private.dispatch_permit (
    fence_generation, completion_envelope_id, abandoned_at, deadline_at
);
CREATE INDEX IF NOT EXISTS consultation_completion_intent_takeover_idx
ON relay_state_private.consultation_completion_intent (
    fence_generation, state, total_deadline_at, operation_id
);

CREATE TABLE IF NOT EXISTS relay_state_private.consultation_quota_bucket (
    workload_id text NOT NULL,
    profile_id text NOT NULL,
    profile_version bigint NOT NULL,
    rate_per_minute integer NOT NULL,
    burst_tokens integer NOT NULL,
    tokens_numerator bigint NOT NULL,
    last_refill_at timestamptz NOT NULL,
    CONSTRAINT consultation_quota_bucket_pk PRIMARY KEY (
        workload_id, profile_id, profile_version
    ),
    CONSTRAINT consultation_quota_bucket_workload_check CHECK (
        workload_id ~ '^[a-z][a-z0-9._-]{0,95}$'
    ),
    CONSTRAINT consultation_quota_bucket_profile_check CHECK (
        profile_id ~ '^[a-z][a-z0-9._-]{0,95}$'
    ),
    CONSTRAINT consultation_quota_bucket_version_check CHECK (
        profile_version BETWEEN 1 AND 9999999999
    ),
    CONSTRAINT consultation_quota_bucket_rate_check CHECK (
        rate_per_minute BETWEEN 1 AND 60
    ),
    CONSTRAINT consultation_quota_bucket_burst_check CHECK (
        burst_tokens BETWEEN 1 AND 10
    ),
    CONSTRAINT consultation_quota_bucket_tokens_check CHECK (
        tokens_numerator BETWEEN 0 AND burst_tokens::bigint * 60000000
    ),
    CONSTRAINT consultation_quota_bucket_time_check CHECK (
        pg_catalog.isfinite(last_refill_at)
    )
);

CREATE TABLE IF NOT EXISTS relay_state_private.audit_pseudonym_keyring (
    singleton boolean NOT NULL DEFAULT true,
    generation bigint NOT NULL,
    metadata_digest bytea NOT NULL,
    metadata_canonical text NOT NULL,
    active_key_id text NOT NULL,
    active_since_unix_ms bigint NOT NULL,
    active_write_deadline_unix_ms bigint NOT NULL,
    audit_event_retention_ms bigint NOT NULL,
    retained_key_ids text[] NOT NULL,
    retained_retired_at_unix_ms bigint[] NOT NULL,
    retained_destroy_after_unix_ms bigint[] NOT NULL,
    used_key_id_count bigint NOT NULL,
    used_key_ids_digest bytea NOT NULL,
    transitioned_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT audit_pseudonym_keyring_pk PRIMARY KEY (singleton),
    CONSTRAINT audit_pseudonym_keyring_singleton_check CHECK (singleton),
    CONSTRAINT audit_pseudonym_keyring_generation_check CHECK (
        generation BETWEEN 1 AND 9007199254740991
    ),
    CONSTRAINT audit_pseudonym_keyring_metadata_digest_check CHECK (
        octet_length(metadata_digest) = 32
    ),
    CONSTRAINT audit_pseudonym_keyring_metadata_canonical_check CHECK (
        octet_length(metadata_canonical) BETWEEN 1 AND 16384
        AND jsonb_typeof(metadata_canonical::jsonb) = 'object'
    ),
    CONSTRAINT audit_pseudonym_keyring_active_key_id_check CHECK (
        octet_length(active_key_id) BETWEEN 1 AND 64
        AND active_key_id ~ '^[a-z0-9][a-z0-9._-]{0,63}$'
    ),
    CONSTRAINT audit_pseudonym_keyring_time_check CHECK (
        active_since_unix_ms BETWEEN 0 AND 9007199254740991
        AND active_write_deadline_unix_ms > active_since_unix_ms
        AND active_write_deadline_unix_ms <= 9007199254740991
        AND audit_event_retention_ms BETWEEN 1 AND 9007199254740991
    ),
    CONSTRAINT audit_pseudonym_keyring_retained_shape_check CHECK (
        cardinality(retained_key_ids) <= 31
        AND cardinality(retained_key_ids) = cardinality(retained_retired_at_unix_ms)
        AND cardinality(retained_key_ids) = cardinality(retained_destroy_after_unix_ms)
        AND (
            cardinality(retained_key_ids) = 0
            OR (
                array_ndims(retained_key_ids) = 1
                AND array_ndims(retained_retired_at_unix_ms) = 1
                AND array_ndims(retained_destroy_after_unix_ms) = 1
                AND array_lower(retained_key_ids, 1) = 1
                AND array_lower(retained_retired_at_unix_ms, 1) = 1
                AND array_lower(retained_destroy_after_unix_ms, 1) = 1
            )
        )
    ),
    CONSTRAINT audit_pseudonym_keyring_history_commitment_check CHECK (
        used_key_id_count >= 1 AND octet_length(used_key_ids_digest) = 32
    )
);

CREATE TABLE IF NOT EXISTS relay_state_private.audit_pseudonym_used_key_id (
    key_id text NOT NULL,
    first_generation bigint NOT NULL,
    first_activated_at_unix_ms bigint NOT NULL,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT audit_pseudonym_used_key_id_pk PRIMARY KEY (key_id),
    CONSTRAINT audit_pseudonym_used_key_id_key_check CHECK (
        octet_length(key_id) BETWEEN 1 AND 64
        AND key_id ~ '^[a-z0-9][a-z0-9._-]{0,63}$'
    ),
    CONSTRAINT audit_pseudonym_used_key_id_generation_check CHECK (
        first_generation BETWEEN 1 AND 9007199254740991
    ),
    CONSTRAINT audit_pseudonym_used_key_id_time_check CHECK (
        first_activated_at_unix_ms BETWEEN 0 AND 9007199254740991
    )
);

CREATE TABLE IF NOT EXISTS relay_state_private.audit_pseudonym_transition_context (
    backend_pid integer NOT NULL,
    transaction_id bigint NOT NULL,
    transition_kind text NOT NULL,
    transition_time_unix_ms bigint NOT NULL,
    expected_generation bigint NOT NULL,
    expected_metadata_digest bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT audit_pseudonym_transition_context_pk PRIMARY KEY (
        backend_pid, transaction_id
    ),
    CONSTRAINT audit_pseudonym_transition_context_backend_check CHECK (
        backend_pid > 0
    ),
    CONSTRAINT audit_pseudonym_transition_context_transaction_check CHECK (
        transaction_id > 0
    ),
    CONSTRAINT audit_pseudonym_transition_context_kind_check CHECK (
        transition_kind IN ('rotation', 'maintenance')
    ),
    CONSTRAINT audit_pseudonym_transition_context_time_check CHECK (
        transition_time_unix_ms BETWEEN 0 AND 9007199254740991
    ),
    CONSTRAINT audit_pseudonym_transition_context_generation_check CHECK (
        expected_generation BETWEEN 1 AND 9007199254740991
    ),
    CONSTRAINT audit_pseudonym_transition_context_digest_check CHECK (
        octet_length(expected_metadata_digest) = 32
    )
);

ALTER TABLE relay_state_private.state_plane_metadata OWNER TO CURRENT_USER;
ALTER TABLE relay_state_private.audit_chain_head OWNER TO CURRENT_USER;
ALTER TABLE relay_state_private.audit_phase OWNER TO CURRENT_USER;
ALTER TABLE relay_state_private.serving_fence_state OWNER TO CURRENT_USER;
ALTER TABLE relay_state_private.consultation_completion_intent OWNER TO CURRENT_USER;
ALTER TABLE relay_state_private.consultation_audit_context OWNER TO CURRENT_USER;
ALTER TABLE relay_state_private.dispatch_permit OWNER TO CURRENT_USER;
ALTER TABLE relay_state_private.consultation_quota_bucket OWNER TO CURRENT_USER;
ALTER TABLE relay_state_private.audit_pseudonym_keyring OWNER TO CURRENT_USER;
ALTER TABLE relay_state_private.audit_pseudonym_used_key_id OWNER TO CURRENT_USER;
ALTER TABLE relay_state_private.audit_pseudonym_transition_context OWNER TO CURRENT_USER;
REVOKE ALL ON ALL TABLES IN SCHEMA relay_state_private FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA relay_state_private FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA relay_state_private REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA relay_state_private REVOKE ALL ON SEQUENCES FROM PUBLIC;

CREATE OR REPLACE FUNCTION relay_state_private.jsonb_object_key_count_v1(p_value jsonb)
RETURNS integer
LANGUAGE sql
IMMUTABLE
SET search_path = pg_catalog, relay_state_private
SET lock_timeout = '2s'
SET statement_timeout = '5s'
SET idle_in_transaction_session_timeout = '5s'
SET synchronous_commit = 'on'
AS $function$
    SELECT count(*)::integer FROM pg_catalog.jsonb_object_keys(p_value)
$function$;

CREATE OR REPLACE FUNCTION relay_state_private.consultation_recursive_schema_valid_v1(
    p_schema jsonb,
    p_depth integer
)
RETURNS bigint[]
LANGUAGE plpgsql
IMMUTABLE
SET search_path = pg_catalog, relay_state_private
SET lock_timeout = '2s'
SET statement_timeout = '5s'
SET idle_in_transaction_session_timeout = '5s'
SET synchronous_commit = 'on'
AS $function$
DECLARE
    v_type text;
    v_field record;
    v_child bigint[];
    v_nodes bigint := 1;
    v_expanded_nodes bigint := 1;
    v_field_count integer;
BEGIN
    -- The compiler numbers the first schema node as depth one. This helper is
    -- called at depth zero for each acquisition-union child independently, so
    -- the largest accepted value here is seven.
    IF p_depth NOT BETWEEN 0 AND 7
       OR jsonb_typeof(p_schema) IS DISTINCT FROM 'object'
    THEN
        RETURN ARRAY[0, 0, 0]::bigint[];
    END IF;
    v_type := p_schema ->> 'type';
    IF v_type = 'object' THEN
        v_field_count := relay_state_private.jsonb_object_key_count_v1(p_schema -> 'fields');
        IF relay_state_private.jsonb_object_key_count_v1(p_schema) <> 4
           OR p_schema - ARRAY[
               'type', 'nullable', 'reject_unknown_fields', 'fields'
           ]::text[] <> '{}'::jsonb
           OR jsonb_typeof(p_schema -> 'nullable') <> 'boolean'
           OR p_schema ->> 'reject_unknown_fields' <> 'true'
           OR jsonb_typeof(p_schema -> 'fields') <> 'object'
           OR v_field_count NOT BETWEEN 1 AND 32
        THEN
            RETURN ARRAY[0, 0, 0]::bigint[];
        END IF;
        FOR v_field IN SELECT * FROM pg_catalog.jsonb_each(p_schema -> 'fields') LOOP
            IF octet_length(v_field.key) NOT BETWEEN 1 AND 128
               OR v_field.key ~ '[[:cntrl:]]'
               OR jsonb_typeof(v_field.value) <> 'object'
               OR relay_state_private.jsonb_object_key_count_v1(v_field.value) <> 2
               OR v_field.value - ARRAY['required', 'schema']::text[] <> '{}'::jsonb
               OR jsonb_typeof(v_field.value -> 'required') <> 'boolean'
            THEN
                RETURN ARRAY[0, 0, 0]::bigint[];
            END IF;
            v_child := relay_state_private.consultation_recursive_schema_valid_v1(
                v_field.value -> 'schema', p_depth + 1
            );
            IF v_child[1] <> 1 THEN
                RETURN ARRAY[0, 0, 0]::bigint[];
            END IF;
            v_nodes := v_nodes + v_child[2];
            v_expanded_nodes := v_expanded_nodes + v_child[3];
            IF v_nodes > 256 OR v_expanded_nodes > 4096 THEN
                RETURN ARRAY[0, 0, 0]::bigint[];
            END IF;
        END LOOP;
    ELSIF v_type = 'array' THEN
        IF relay_state_private.jsonb_object_key_count_v1(p_schema) <> 4
           OR p_schema - ARRAY['type', 'nullable', 'max_items', 'items']::text[] <> '{}'::jsonb
           OR jsonb_typeof(p_schema -> 'nullable') <> 'boolean'
           OR jsonb_typeof(p_schema -> 'max_items') <> 'number'
           OR (p_schema ->> 'max_items')::numeric <>
                trunc((p_schema ->> 'max_items')::numeric)
           OR (p_schema ->> 'max_items')::integer NOT BETWEEN 1 AND 256
        THEN
            RETURN ARRAY[0, 0, 0]::bigint[];
        END IF;
        v_child := relay_state_private.consultation_recursive_schema_valid_v1(
            p_schema -> 'items', p_depth + 1
        );
        IF v_child[1] <> 1 THEN
            RETURN ARRAY[0, 0, 0]::bigint[];
        END IF;
        v_nodes := v_nodes + v_child[2];
        v_expanded_nodes := v_expanded_nodes
            + (p_schema ->> 'max_items')::integer * v_child[3];
        IF v_nodes > 256 OR v_expanded_nodes > 4096 THEN
            RETURN ARRAY[0, 0, 0]::bigint[];
        END IF;
    ELSIF v_type = 'string' THEN
        IF relay_state_private.jsonb_object_key_count_v1(p_schema) <> 3
           OR p_schema - ARRAY['type', 'nullable', 'max_bytes']::text[] <> '{}'::jsonb
           OR jsonb_typeof(p_schema -> 'nullable') <> 'boolean'
           OR jsonb_typeof(p_schema -> 'max_bytes') <> 'number'
           OR (p_schema ->> 'max_bytes')::numeric <>
                trunc((p_schema ->> 'max_bytes')::numeric)
           OR (p_schema ->> 'max_bytes')::integer NOT BETWEEN 1 AND 65536
        THEN
            RETURN ARRAY[0, 0, 0]::bigint[];
        END IF;
    ELSIF v_type = 'boolean' THEN
        IF relay_state_private.jsonb_object_key_count_v1(p_schema) <> 2
           OR p_schema - ARRAY['type', 'nullable']::text[] <> '{}'::jsonb
           OR jsonb_typeof(p_schema -> 'nullable') <> 'boolean'
        THEN
            RETURN ARRAY[0, 0, 0]::bigint[];
        END IF;
    ELSIF v_type IN ('integer', 'number') THEN
        IF relay_state_private.jsonb_object_key_count_v1(p_schema) <> 4
           OR p_schema - ARRAY[
               'type', 'nullable', 'minimum', 'maximum'
           ]::text[] <> '{}'::jsonb
           OR jsonb_typeof(p_schema -> 'nullable') <> 'boolean'
           OR jsonb_typeof(p_schema -> 'minimum') <> 'number'
           OR jsonb_typeof(p_schema -> 'maximum') <> 'number'
           OR (p_schema ->> 'minimum')::numeric <>
                trunc((p_schema ->> 'minimum')::numeric)
           OR (p_schema ->> 'maximum')::numeric <>
                trunc((p_schema ->> 'maximum')::numeric)
           OR (p_schema ->> 'minimum')::numeric
                NOT BETWEEN -9007199254740991 AND 9007199254740991
           OR (p_schema ->> 'maximum')::numeric
                NOT BETWEEN -9007199254740991 AND 9007199254740991
           OR (p_schema ->> 'minimum')::numeric > (p_schema ->> 'maximum')::numeric
        THEN
            RETURN ARRAY[0, 0, 0]::bigint[];
        END IF;
    ELSE
        RETURN ARRAY[0, 0, 0]::bigint[];
    END IF;
    RETURN ARRAY[1, v_nodes, v_expanded_nodes]::bigint[];
EXCEPTION WHEN OTHERS THEN
    RETURN ARRAY[0, 0, 0]::bigint[];
END;
$function$;

CREATE OR REPLACE FUNCTION relay_state_private.consultation_completion_seed_valid_v1(
    p_seed_canonical text
)
RETURNS boolean
LANGUAGE plpgsql
IMMUTABLE
SET search_path = pg_catalog, relay_state_private
SET lock_timeout = '2s'
SET statement_timeout = '5s'
SET idle_in_transaction_session_timeout = '5s'
SET synchronous_commit = 'on'
AS $function$
DECLARE
    v_seed jsonb;
    v_schema_measure bigint[];
    v_acquisition_field record;
    v_previous_disclosure_field text := NULL;
    v_public_outcome text;
    v_public_outcome_sort integer;
    v_previous_public_outcome_sort integer := -1;
    v_index integer;
    v_operation jsonb;
    v_operation_kind_sort integer;
    v_previous_operation_kind_sort integer := -1;
    v_previous_source_operation_id text := NULL;
    v_credential_operation_count integer := 0;
    v_data_operation_count integer := 0;
    v_binding jsonb;
    v_binding_sort integer;
    v_previous_binding_sort integer := -1;
    v_credential_binding_count integer := 0;
    v_data_binding_count integer := 0;
    v_allowed_index integer;
    v_allowed_operation_id text;
    v_previous_allowed_operation_id text;
BEGIN
    IF p_seed_canonical IS NULL
       OR octet_length(p_seed_canonical) NOT BETWEEN 1 AND 262144
    THEN
        RETURN false;
    END IF;
    v_seed := p_seed_canonical::jsonb;
    IF jsonb_typeof(v_seed #> '{acquisition,schema}') IS DISTINCT FROM 'object'
       OR relay_state_private.jsonb_object_key_count_v1(
           v_seed #> '{acquisition,schema}'
       ) <> 2
       OR (v_seed #> '{acquisition,schema}') - ARRAY['type', 'fields']::text[]
            <> '{}'::jsonb
       OR v_seed #>> '{acquisition,schema,type}' <> 'acquisition_union'
       OR jsonb_typeof(v_seed #> '{acquisition,schema,fields}') IS DISTINCT FROM 'object'
       OR relay_state_private.jsonb_object_key_count_v1(
           v_seed #> '{acquisition,schema,fields}'
       ) NOT BETWEEN 1 AND 64
    THEN
        RETURN false;
    END IF;
    FOR v_acquisition_field IN
        SELECT * FROM pg_catalog.jsonb_each(v_seed #> '{acquisition,schema,fields}')
    LOOP
        IF v_acquisition_field.key !~ '^[a-z][a-z0-9._-]{0,95}$' THEN
            RETURN false;
        END IF;
        v_schema_measure := relay_state_private.consultation_recursive_schema_valid_v1(
            v_acquisition_field.value, 0
        );
        IF v_schema_measure[1] <> 1
           OR v_schema_measure[2] NOT BETWEEN 1 AND 256
           OR v_schema_measure[3] NOT BETWEEN 1 AND 4096
        THEN
            RETURN false;
        END IF;
    END LOOP;
    IF jsonb_typeof(v_seed) IS DISTINCT FROM 'object'
       OR relay_state_private.jsonb_object_key_count_v1(v_seed) <> 17
       OR v_seed - ARRAY[
           'schema', 'correlation', 'profile', 'integration_pack',
           'private_binding_hash', 'workload', 'purpose', 'policy',
           'acquisition', 'destinations', 'credential',
           'authorized_operation_union', 'dispatch', 'bounds', 'request_digest',
           'authorization_context_digest', 'execution_plan_digest'
       ]::text[] <> '{}'::jsonb
       OR v_seed ->> 'schema'
            IS DISTINCT FROM 'registry.relay.consultation-completion-seed/v1'
       OR relay_state_private.jsonb_object_key_count_v1(v_seed -> 'correlation') <> 1
       OR (v_seed -> 'correlation') - ARRAY['notary_evaluation_id']::text[] <> '{}'::jsonb
       OR jsonb_typeof(v_seed #> '{correlation,notary_evaluation_id}')
            NOT IN ('string', 'null')
       OR (jsonb_typeof(v_seed #> '{correlation,notary_evaluation_id}') = 'string'
           AND v_seed #>> '{correlation,notary_evaluation_id}'
                !~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$')
       OR relay_state_private.jsonb_object_key_count_v1(v_seed -> 'profile') <> 3
       OR (v_seed -> 'profile') - ARRAY['id', 'version', 'contract_hash']::text[] <> '{}'::jsonb
       OR v_seed #>> '{profile,id}' !~ '^[a-z][a-z0-9._-]{0,95}$'
       OR v_seed #>> '{profile,version}' !~ '^[1-9][0-9]{0,9}$'
       OR v_seed #>> '{profile,contract_hash}' !~ '^sha256:[0-9a-f]{64}$'
       OR relay_state_private.jsonb_object_key_count_v1(v_seed -> 'integration_pack') <> 3
       OR (v_seed -> 'integration_pack') - ARRAY['id', 'version', 'hash']::text[] <> '{}'::jsonb
       OR v_seed #>> '{integration_pack,id}' !~ '^[a-z][a-z0-9._-]{0,95}$'
       OR v_seed #>> '{integration_pack,version}' !~ '^[1-9][0-9]{0,9}$'
       OR v_seed #>> '{integration_pack,hash}' !~ '^sha256:[0-9a-f]{64}$'
       OR v_seed ->> 'private_binding_hash' !~ '^sha256:[0-9a-f]{64}$'
       OR relay_state_private.jsonb_object_key_count_v1(v_seed -> 'workload') <> 3
       OR (v_seed -> 'workload') - ARRAY['id', 'tenant_id', 'registry_id']::text[] <> '{}'::jsonb
       OR v_seed #>> '{workload,id}' !~ '^[a-z][a-z0-9._-]{0,95}$'
       OR v_seed #>> '{workload,tenant_id}' !~ '^[a-z][a-z0-9._-]{0,95}$'
       OR v_seed #>> '{workload,registry_id}' !~ '^[a-z][a-z0-9._-]{0,95}$'
       OR jsonb_typeof(v_seed -> 'purpose') IS DISTINCT FROM 'string'
       OR octet_length(v_seed ->> 'purpose') NOT BETWEEN 1 AND 256
       OR v_seed ->> 'purpose' ~ '[[:space:],[:cntrl:]]'
       OR relay_state_private.jsonb_object_key_count_v1(v_seed -> 'policy') <> 5
       OR (v_seed -> 'policy') - ARRAY[
           'id', 'hash', 'legal_basis_id', 'consent',
           'obligations_digest'
       ]::text[] <> '{}'::jsonb
       OR v_seed #>> '{policy,id}' !~ '^[a-z][a-z0-9._-]{0,95}$'
       OR v_seed #>> '{policy,hash}' !~ '^sha256:[0-9a-f]{64}$'
       OR v_seed #>> '{policy,legal_basis_id}' !~ '^[a-z][a-z0-9._-]{0,95}$'
       OR relay_state_private.jsonb_object_key_count_v1(v_seed #> '{policy,consent}') <> 4
       OR (v_seed #> '{policy,consent}') - ARRAY[
           'required', 'verifier_id', 'contract_hash', 'decision'
       ]::text[] <> '{}'::jsonb
       OR jsonb_typeof(v_seed #> '{policy,consent,required}') <> 'boolean'
       OR jsonb_typeof(v_seed #> '{policy,consent,verifier_id}') NOT IN ('string', 'null')
       OR (jsonb_typeof(v_seed #> '{policy,consent,verifier_id}') = 'string'
           AND v_seed #>> '{policy,consent,verifier_id}' !~ '^[a-z][a-z0-9._-]{0,95}$')
       OR jsonb_typeof(v_seed #> '{policy,consent,contract_hash}') NOT IN ('string', 'null')
       OR (jsonb_typeof(v_seed #> '{policy,consent,contract_hash}') = 'string'
           AND v_seed #>> '{policy,consent,contract_hash}' !~ '^sha256:[0-9a-f]{64}$')
       OR v_seed #>> '{policy,consent,decision}' NOT IN ('not_required', 'verified')
       OR ((v_seed #>> '{policy,consent,required}')::boolean
           <> (v_seed #>> '{policy,consent,decision}' = 'verified'))
       OR ((v_seed #>> '{policy,consent,required}')::boolean
           <> (jsonb_typeof(v_seed #> '{policy,consent,verifier_id}') = 'string'))
       OR ((v_seed #>> '{policy,consent,required}')::boolean
           <> (jsonb_typeof(v_seed #> '{policy,consent,contract_hash}') = 'string'))
       OR v_seed #>> '{policy,obligations_digest}' !~ '^sha256:[0-9a-f]{64}$'
       OR relay_state_private.jsonb_object_key_count_v1(v_seed -> 'acquisition') <> 5
       OR (v_seed -> 'acquisition') - ARRAY[
           'class', 'schema', 'disclosure_fields', 'public_outcomes',
           'provenance_contract'
       ]::text[] <> '{}'::jsonb
       OR v_seed #>> '{acquisition,class}' NOT IN (
           'materialized_snapshot', 'source_projected_exact', 'bounded_full_record'
       )
       OR jsonb_typeof(v_seed #> '{acquisition,disclosure_fields}') IS DISTINCT FROM 'array'
       OR jsonb_array_length(v_seed #> '{acquisition,disclosure_fields}') NOT BETWEEN 0 AND 64
       OR (
           jsonb_array_length(v_seed #> '{acquisition,disclosure_fields}') = 0
           AND (
               v_seed #>> '{acquisition,class}' <> 'bounded_full_record'
               OR v_seed #>> '{dispatch,plan_kind}' <> 'bounded_http'
               OR (v_seed #>> '{bounds,data_exchanges}')::integer <> 2
               OR (v_seed #>> '{bounds,credential_exchanges}')::integer <> 1
               OR jsonb_typeof(v_seed #> '{bounds,credential_token_lifetime_ms}') <> 'null'
           )
       )
       OR jsonb_typeof(v_seed #> '{acquisition,public_outcomes}') IS DISTINCT FROM 'array'
       OR jsonb_array_length(v_seed #> '{acquisition,public_outcomes}') NOT BETWEEN 1 AND 3
       OR relay_state_private.jsonb_object_key_count_v1(
           v_seed #> '{acquisition,provenance_contract}'
       ) <> 4
       OR (v_seed #> '{acquisition,provenance_contract}') - ARRAY[
           'source_observed_at', 'source_revision',
           'snapshot_generation', 'snapshot_published_at'
       ]::text[] <> '{}'::jsonb
       OR v_seed #> '{acquisition,provenance_contract,source_observed_at}'
            IS DISTINCT FROM 'null'::jsonb
       OR v_seed #> '{acquisition,provenance_contract,source_revision}'
            IS DISTINCT FROM 'null'::jsonb
       OR v_seed #>> '{acquisition,provenance_contract,snapshot_generation}'
            NOT IN ('required', 'absent')
       OR v_seed #>> '{acquisition,provenance_contract,snapshot_published_at}'
            NOT IN ('required', 'absent')
       OR (
           (v_seed #>> '{acquisition,class}' = 'materialized_snapshot') <>
           (v_seed #>> '{acquisition,provenance_contract,snapshot_generation}' = 'required')
       )
       OR (
           (v_seed #>> '{acquisition,class}' = 'materialized_snapshot') <>
           (v_seed #>> '{acquisition,provenance_contract,snapshot_published_at}' = 'required')
       )
       OR relay_state_private.jsonb_object_key_count_v1(v_seed -> 'destinations') <> 2
       OR (v_seed -> 'destinations') - ARRAY[
           'credential_destination_id', 'data_destination_id'
       ]::text[] <> '{}'::jsonb
       OR jsonb_typeof(v_seed #> '{destinations,credential_destination_id}')
            NOT IN ('string', 'null')
       OR (jsonb_typeof(v_seed #> '{destinations,credential_destination_id}') = 'string'
           AND v_seed #>> '{destinations,credential_destination_id}'
                !~ '^[a-z][a-z0-9._-]{0,95}$')
       OR jsonb_typeof(v_seed #> '{destinations,data_destination_id}')
            NOT IN ('string', 'null')
       OR (jsonb_typeof(v_seed #> '{destinations,data_destination_id}') = 'string'
           AND v_seed #>> '{destinations,data_destination_id}'
                !~ '^[a-z][a-z0-9._-]{0,95}$')
       OR relay_state_private.jsonb_object_key_count_v1(v_seed -> 'credential') <> 2
       OR (v_seed -> 'credential') - ARRAY['reference', 'generation']::text[] <> '{}'::jsonb
       OR jsonb_typeof(v_seed #> '{credential,reference}') NOT IN ('string', 'null')
       OR (jsonb_typeof(v_seed #> '{credential,reference}') = 'string'
           AND v_seed #>> '{credential,reference}' !~ '^[a-z][a-z0-9._-]{0,95}$')
       OR jsonb_typeof(v_seed #> '{credential,generation}') NOT IN ('number', 'null')
       OR (jsonb_typeof(v_seed #> '{credential,generation}') = 'number'
           AND ((v_seed #>> '{credential,generation}')::numeric <>
                    trunc((v_seed #>> '{credential,generation}')::numeric)
                OR (v_seed #>> '{credential,generation}')::bigint
                    NOT BETWEEN 1 AND 9007199254740991))
       OR pg_catalog.num_nonnulls(
           CASE WHEN jsonb_typeof(v_seed #> '{credential,reference}') = 'null'
                THEN NULL ELSE v_seed #>> '{credential,reference}' END,
           CASE WHEN jsonb_typeof(v_seed #> '{credential,generation}') = 'null'
                THEN NULL ELSE v_seed #>> '{credential,generation}' END
       ) NOT IN (0, 2)
       OR jsonb_typeof(v_seed -> 'authorized_operation_union') IS DISTINCT FROM 'array'
       OR jsonb_array_length(v_seed -> 'authorized_operation_union') > 6
       OR relay_state_private.jsonb_object_key_count_v1(v_seed -> 'dispatch') <> 2
       OR (v_seed -> 'dispatch') - ARRAY[
           'plan_kind', 'permit_bindings'
       ]::text[] <> '{}'::jsonb
       OR v_seed #>> '{dispatch,plan_kind}' NOT IN (
           'snapshot_exact', 'bounded_http', 'sandboxed_rhai'
       )
       OR jsonb_typeof(v_seed #> '{dispatch,permit_bindings}') IS DISTINCT FROM 'array'
       OR jsonb_array_length(v_seed #> '{dispatch,permit_bindings}') > 6
       OR relay_state_private.jsonb_object_key_count_v1(v_seed -> 'bounds') <> 12
       OR (v_seed -> 'bounds') - ARRAY[
           'source_matches', 'disclosed_records', 'data_exchanges',
           'credential_exchanges', 'data_destinations', 'source_bytes',
           'timeout_ms', 'max_in_flight', 'quota_rate_per_minute',
           'quota_burst', 'public_response_bytes',
           'credential_token_lifetime_ms'
       ]::text[] <> '{}'::jsonb
       OR (v_seed #>> '{bounds,source_matches}')::integer NOT BETWEEN 1 AND 2
       OR (
           (v_seed #>> '{bounds,source_matches}')::integer = 1
           AND v_seed #> '{acquisition,public_outcomes}'
                <> '["match","no_match"]'::jsonb
       )
       OR (
           (v_seed #>> '{bounds,source_matches}')::integer = 2
           AND v_seed #> '{acquisition,public_outcomes}'
                <> '["match","no_match","ambiguous"]'::jsonb
       )
       OR (v_seed #>> '{bounds,disclosed_records}')::integer <> 1
       OR (v_seed #>> '{bounds,data_exchanges}')::integer NOT BETWEEN 0 AND 5
       OR (v_seed #>> '{bounds,credential_exchanges}')::integer NOT BETWEEN 0 AND 1
       OR (v_seed #>> '{bounds,data_destinations}')::integer NOT BETWEEN 0 AND 1
       OR (v_seed #>> '{bounds,source_bytes}')::bigint NOT BETWEEN 1 AND 1048576
       OR (v_seed #>> '{bounds,timeout_ms}')::integer NOT BETWEEN 1 AND 20000
       OR EXISTS (
           SELECT 1
           FROM pg_catalog.jsonb_each(v_seed -> 'bounds') AS bound(name, value)
           WHERE bound.name <> 'credential_token_lifetime_ms'
             AND (
                 jsonb_typeof(bound.value) <> 'number'
                 OR (bound.value #>> '{}')::numeric <> trunc((bound.value #>> '{}')::numeric)
             )
       )
       OR (v_seed #>> '{bounds,max_in_flight}')::integer NOT BETWEEN 1 AND 16
       OR (v_seed #>> '{bounds,quota_rate_per_minute}')::integer NOT BETWEEN 1 AND 60
       OR (v_seed #>> '{bounds,quota_burst}')::integer NOT BETWEEN 1 AND 10
       OR (v_seed #>> '{bounds,public_response_bytes}')::integer NOT BETWEEN 1 AND 65536
       OR jsonb_typeof(v_seed #> '{bounds,credential_token_lifetime_ms}')
            NOT IN ('number', 'null')
       OR (jsonb_typeof(v_seed #> '{bounds,credential_token_lifetime_ms}') = 'number'
           AND ((v_seed #>> '{bounds,credential_token_lifetime_ms}')::numeric <>
                    trunc((v_seed #>> '{bounds,credential_token_lifetime_ms}')::numeric)
                OR (v_seed #>> '{bounds,credential_token_lifetime_ms}')::bigint
                    NOT BETWEEN 1 AND 86400000))
       OR ((v_seed #>> '{bounds,credential_exchanges}')::integer = 1
           AND jsonb_typeof(v_seed #> '{credential,reference}') <> 'string')
       OR (jsonb_typeof(v_seed #> '{credential,reference}') = 'string'
           AND (v_seed #>> '{bounds,credential_exchanges}')::integer = 0
           AND (v_seed #>> '{bounds,data_exchanges}')::integer = 0)
       OR ((v_seed #>> '{bounds,credential_exchanges}')::integer = 1) <>
          (jsonb_typeof(v_seed #> '{destinations,credential_destination_id}') = 'string')
       OR (
           (v_seed #>> '{bounds,credential_exchanges}')::integer = 0
           AND jsonb_typeof(v_seed #> '{bounds,credential_token_lifetime_ms}') <> 'null'
       )
       OR (
           (v_seed #>> '{bounds,credential_exchanges}')::integer = 1
           AND jsonb_typeof(v_seed #> '{bounds,credential_token_lifetime_ms}') = 'null'
           AND (
               v_seed #>> '{dispatch,plan_kind}' <> 'bounded_http'
               OR v_seed #>> '{acquisition,class}' <> 'bounded_full_record'
               OR jsonb_array_length(v_seed #> '{acquisition,disclosure_fields}') <> 0
               OR (v_seed #>> '{bounds,data_exchanges}')::integer <> 2
               OR jsonb_array_length(v_seed -> 'authorized_operation_union') <> 3
               OR jsonb_array_length(v_seed #> '{dispatch,permit_bindings}') <> 3
           )
       )
       OR ((v_seed #>> '{bounds,data_exchanges}')::integer > 0) <>
          (jsonb_typeof(v_seed #> '{destinations,data_destination_id}') = 'string')
       OR v_seed ->> 'request_digest' !~ '^sha256:[0-9a-f]{64}$'
       OR v_seed ->> 'authorization_context_digest' !~ '^sha256:[0-9a-f]{64}$'
       OR v_seed ->> 'execution_plan_digest' !~ '^sha256:[0-9a-f]{64}$'
    THEN
        RETURN false;
    END IF;
    FOR v_index IN 0..jsonb_array_length(v_seed #> '{acquisition,disclosure_fields}') - 1 LOOP
        IF jsonb_typeof(v_seed #> ARRAY['acquisition', 'disclosure_fields', v_index::text]) <> 'string'
           OR v_seed #>> ARRAY['acquisition', 'disclosure_fields', v_index::text]
                !~ '^[a-z][a-z0-9._-]{0,95}$'
           OR (
               v_previous_disclosure_field IS NOT NULL
               AND pg_catalog.convert_to(
                   v_seed #>> ARRAY[
                       'acquisition', 'disclosure_fields', v_index::text
                   ],
                   'UTF8'
               ) <= pg_catalog.convert_to(v_previous_disclosure_field, 'UTF8')
           )
        THEN
            RETURN false;
        END IF;
        v_previous_disclosure_field := v_seed #>> ARRAY[
            'acquisition', 'disclosure_fields', v_index::text
        ];
    END LOOP;
    FOR v_index IN 0..jsonb_array_length(v_seed #> '{acquisition,public_outcomes}') - 1 LOOP
        IF jsonb_typeof(v_seed #> ARRAY[
               'acquisition', 'public_outcomes', v_index::text
           ]) <> 'string'
        THEN
            RETURN false;
        END IF;
        v_public_outcome := v_seed #>> ARRAY[
            'acquisition', 'public_outcomes', v_index::text
        ];
        v_public_outcome_sort := CASE v_public_outcome
            WHEN 'match' THEN 0
            WHEN 'no_match' THEN 1
            WHEN 'ambiguous' THEN 2
            ELSE -1
        END;
        IF v_public_outcome_sort <= v_previous_public_outcome_sort
           OR (
               v_public_outcome = 'ambiguous'
               AND (v_seed #>> '{bounds,source_matches}')::integer <> 2
           )
        THEN
            RETURN false;
        END IF;
        v_previous_public_outcome_sort := v_public_outcome_sort;
    END LOOP;
    FOR v_index IN 0..jsonb_array_length(v_seed -> 'authorized_operation_union') - 1 LOOP
        v_operation := v_seed #> ARRAY['authorized_operation_union', v_index::text];
        IF jsonb_typeof(v_operation) <> 'object'
           OR relay_state_private.jsonb_object_key_count_v1(v_operation) <> 2
           OR v_operation - ARRAY['kind', 'operation_id']::text[] <> '{}'::jsonb
           OR jsonb_typeof(v_operation -> 'kind') <> 'string'
           OR v_operation ->> 'kind' NOT IN ('credential', 'data')
           OR jsonb_typeof(v_operation -> 'operation_id') <> 'string'
           OR v_operation ->> 'operation_id' !~ '^[a-z][a-z0-9._-]{0,95}$'
        THEN
            RETURN false;
        END IF;
        v_operation_kind_sort := CASE v_operation ->> 'kind'
            WHEN 'credential' THEN 0
            ELSE 1
        END;
        IF v_operation_kind_sort < v_previous_operation_kind_sort
           OR (
               v_operation_kind_sort = v_previous_operation_kind_sort
               AND pg_catalog.convert_to(v_operation ->> 'operation_id', 'UTF8')
                    <= pg_catalog.convert_to(v_previous_source_operation_id, 'UTF8')
           )
        THEN
            RETURN false;
        END IF;
        IF v_operation ->> 'kind' = 'credential' THEN
            v_credential_operation_count := v_credential_operation_count + 1;
        ELSE
            v_data_operation_count := v_data_operation_count + 1;
        END IF;
        v_previous_operation_kind_sort := v_operation_kind_sort;
        v_previous_source_operation_id := v_operation ->> 'operation_id';
    END LOOP;
    IF v_credential_operation_count NOT BETWEEN 0 AND 1
       OR v_credential_operation_count <>
            (v_seed #>> '{bounds,credential_exchanges}')::integer
       OR (v_data_operation_count > 0) <>
            ((v_seed #>> '{bounds,data_exchanges}')::integer > 0)
    THEN
        RETURN false;
    END IF;
    FOR v_index IN 0..jsonb_array_length(v_seed #> '{dispatch,permit_bindings}') - 1 LOOP
        v_binding := v_seed #> ARRAY['dispatch', 'permit_bindings', v_index::text];
        IF jsonb_typeof(v_binding) <> 'object'
           OR relay_state_private.jsonb_object_key_count_v1(v_binding) <> 3
           OR v_binding - ARRAY[
               'kind', 'ordinal', 'allowed_operation_ids'
           ]::text[] <> '{}'::jsonb
           OR jsonb_typeof(v_binding -> 'kind') <> 'string'
           OR jsonb_typeof(v_binding -> 'ordinal') <> 'number'
           OR (v_binding ->> 'ordinal')::numeric <>
                trunc((v_binding ->> 'ordinal')::numeric)
           OR NOT (
               (v_binding ->> 'kind' = 'credential'
                AND (v_binding ->> 'ordinal')::integer = 0)
               OR (v_binding ->> 'kind' = 'data'
                   AND (v_binding ->> 'ordinal')::integer BETWEEN 0 AND 4)
           )
           OR jsonb_typeof(v_binding -> 'allowed_operation_ids') <> 'array'
           OR jsonb_array_length(v_binding -> 'allowed_operation_ids') NOT BETWEEN 1 AND 5
        THEN
            RETURN false;
        END IF;
        v_binding_sort := CASE v_binding ->> 'kind'
            WHEN 'credential' THEN 0
            ELSE 1 + (v_binding ->> 'ordinal')::integer
        END;
        IF v_binding_sort <= v_previous_binding_sort THEN
            RETURN false;
        END IF;
        IF v_binding ->> 'kind' = 'credential' THEN
            v_credential_binding_count := v_credential_binding_count + 1;
            IF v_credential_binding_count > 1
               OR jsonb_array_length(v_binding -> 'allowed_operation_ids') <> 1
            THEN
                RETURN false;
            END IF;
        ELSE
            IF (v_binding ->> 'ordinal')::integer <> v_data_binding_count THEN
                RETURN false;
            END IF;
            v_data_binding_count := v_data_binding_count + 1;
        END IF;
        v_previous_allowed_operation_id := NULL;
        FOR v_allowed_index IN 0..jsonb_array_length(
            v_binding -> 'allowed_operation_ids'
        ) - 1 LOOP
            IF jsonb_typeof(v_binding #> ARRAY[
                   'allowed_operation_ids', v_allowed_index::text
               ]) <> 'string'
            THEN
                RETURN false;
            END IF;
            v_allowed_operation_id := v_binding #>> ARRAY[
                'allowed_operation_ids', v_allowed_index::text
            ];
            IF v_allowed_operation_id !~ '^[a-z][a-z0-9._-]{0,95}$'
               OR (
                   v_previous_allowed_operation_id IS NOT NULL
                   AND pg_catalog.convert_to(v_allowed_operation_id, 'UTF8')
                        <= pg_catalog.convert_to(v_previous_allowed_operation_id, 'UTF8')
               )
               OR NOT EXISTS (
                   SELECT 1
                   FROM pg_catalog.jsonb_array_elements(
                       v_seed -> 'authorized_operation_union'
                   ) AS operation(value)
                   WHERE operation.value ->> 'kind' = v_binding ->> 'kind'
                     AND operation.value ->> 'operation_id' = v_allowed_operation_id
               )
            THEN
                RETURN false;
            END IF;
            v_previous_allowed_operation_id := v_allowed_operation_id;
        END LOOP;
        IF v_seed #>> '{dispatch,plan_kind}' = 'sandboxed_rhai'
           AND v_binding ->> 'kind' = 'data'
           AND v_binding -> 'allowed_operation_ids' IS DISTINCT FROM (
               SELECT COALESCE(pg_catalog.jsonb_agg(
                   operation.value -> 'operation_id' ORDER BY operation.ordinal
               ), '[]'::jsonb)
               FROM pg_catalog.jsonb_array_elements(
                   v_seed -> 'authorized_operation_union'
               ) WITH ORDINALITY AS operation(value, ordinal)
               WHERE operation.value ->> 'kind' = 'data'
           )
        THEN
            RETURN false;
        END IF;
        v_previous_binding_sort := v_binding_sort;
    END LOOP;
    IF v_credential_binding_count <> v_credential_operation_count
       OR v_credential_binding_count <>
            (v_seed #>> '{bounds,credential_exchanges}')::integer
       OR v_data_binding_count <>
            (v_seed #>> '{bounds,data_exchanges}')::integer
       OR (
           v_seed #>> '{dispatch,plan_kind}' = 'snapshot_exact'
           AND (
               v_credential_operation_count + v_data_operation_count <> 0
               OR v_credential_binding_count + v_data_binding_count <> 0
               OR v_seed #>> '{acquisition,class}' <> 'materialized_snapshot'
           )
       )
       OR (
           v_seed #>> '{dispatch,plan_kind}' <> 'snapshot_exact'
           AND (
               v_data_operation_count = 0
               OR v_data_binding_count = 0
               OR v_seed #>> '{acquisition,class}' = 'materialized_snapshot'
           )
       )
       OR (
           v_seed #>> '{dispatch,plan_kind}' = 'bounded_http'
           AND (
               v_data_binding_count <> v_data_operation_count
               OR EXISTS (
                   SELECT 1
                   FROM pg_catalog.jsonb_array_elements(
                       v_seed -> 'authorized_operation_union'
                   ) AS operation(value)
                   WHERE operation.value ->> 'kind' = 'data'
                     AND NOT EXISTS (
                         SELECT 1
                         FROM pg_catalog.jsonb_array_elements(
                             v_seed #> '{dispatch,permit_bindings}'
                         ) AS binding(value)
                         WHERE binding.value ->> 'kind' = 'data'
                           AND binding.value -> 'allowed_operation_ids'
                                ? (operation.value ->> 'operation_id')
                     )
               )
           )
       )
       OR (
           (v_seed #>> '{bounds,credential_exchanges}')::integer = 1
           AND jsonb_typeof(v_seed #> '{bounds,credential_token_lifetime_ms}') = 'null'
           AND NOT EXISTS (
               SELECT 1
               FROM pg_catalog.jsonb_array_elements(
                   v_seed -> 'authorized_operation_union'
               ) AS jwks(value)
               WHERE jwks.value ->> 'kind' = 'data'
                 AND jwks.value ->> 'operation_id' ~ '\.jwks$'
                 AND EXISTS (
                     SELECT 1
                     FROM pg_catalog.jsonb_array_elements(
                         v_seed -> 'authorized_operation_union'
                     ) AS search(value)
                     WHERE search.value ->> 'kind' = 'data'
                       AND search.value ->> 'operation_id' = pg_catalog.left(
                           jwks.value ->> 'operation_id',
                           pg_catalog.length(jwks.value ->> 'operation_id') - 5
                       )
                 )
                 AND EXISTS (
                     SELECT 1
                     FROM pg_catalog.jsonb_array_elements(
                         v_seed #> '{dispatch,permit_bindings}'
                     ) AS permit(value)
                     WHERE permit.value ->> 'kind' = 'data'
                       AND (permit.value ->> 'ordinal')::integer = 0
                       AND permit.value -> 'allowed_operation_ids'
                            = pg_catalog.jsonb_build_array(jwks.value -> 'operation_id')
                 )
                 AND EXISTS (
                     SELECT 1
                     FROM pg_catalog.jsonb_array_elements(
                         v_seed #> '{dispatch,permit_bindings}'
                     ) AS permit(value)
                     WHERE permit.value ->> 'kind' = 'data'
                       AND (permit.value ->> 'ordinal')::integer = 1
                       AND permit.value -> 'allowed_operation_ids'
                            = pg_catalog.jsonb_build_array(pg_catalog.left(
                                jwks.value ->> 'operation_id',
                                pg_catalog.length(jwks.value ->> 'operation_id') - 5
                            ))
                 )
           )
       )
    THEN
        RETURN false;
    END IF;
    RETURN true;
EXCEPTION WHEN OTHERS THEN
    RETURN false;
END;
$function$;

CREATE OR REPLACE FUNCTION relay_state_private.audit_pseudonym_metadata_canonical_v1(
    p_generation bigint,
    p_active_key_id text,
    p_active_since_unix_ms bigint,
    p_active_write_deadline_unix_ms bigint,
    p_audit_event_retention_ms bigint,
    p_retained_key_ids text[],
    p_retained_retired_at_unix_ms bigint[],
    p_retained_destroy_after_unix_ms bigint[]
)
RETURNS text
LANGUAGE plpgsql
IMMUTABLE
SET search_path = pg_catalog, relay_state_private
SET lock_timeout = '2s'
SET statement_timeout = '5s'
SET idle_in_transaction_session_timeout = '5s'
SET synchronous_commit = 'on'
AS $function$
DECLARE
    v_retained_count integer;
    v_index integer;
    v_previous_key_id text := NULL;
    v_retained_canonical text := '';
BEGIN
    IF p_generation IS NULL OR p_active_key_id IS NULL
       OR p_active_since_unix_ms IS NULL
       OR p_active_write_deadline_unix_ms IS NULL
       OR p_audit_event_retention_ms IS NULL
       OR p_retained_key_ids IS NULL
       OR p_retained_retired_at_unix_ms IS NULL
       OR p_retained_destroy_after_unix_ms IS NULL
       OR p_generation NOT BETWEEN 1 AND 9007199254740991
       OR p_active_key_id !~ '^[a-z0-9][a-z0-9._-]{0,63}$'
       OR octet_length(p_active_key_id) NOT BETWEEN 1 AND 64
       OR p_active_since_unix_ms NOT BETWEEN 0 AND 9007199254740991
       OR p_active_write_deadline_unix_ms <= p_active_since_unix_ms
       OR p_active_write_deadline_unix_ms > 9007199254740991
       OR p_audit_event_retention_ms NOT BETWEEN 1 AND 9007199254740991
       OR cardinality(p_retained_key_ids) > 31
       OR cardinality(p_retained_key_ids) <> cardinality(p_retained_retired_at_unix_ms)
       OR cardinality(p_retained_key_ids) <> cardinality(p_retained_destroy_after_unix_ms)
       OR (
           cardinality(p_retained_key_ids) > 0
           AND (
               array_ndims(p_retained_key_ids) <> 1
               OR array_ndims(p_retained_retired_at_unix_ms) <> 1
               OR array_ndims(p_retained_destroy_after_unix_ms) <> 1
               OR array_lower(p_retained_key_ids, 1) <> 1
               OR array_lower(p_retained_retired_at_unix_ms, 1) <> 1
               OR array_lower(p_retained_destroy_after_unix_ms, 1) <> 1
           )
       )
    THEN
        RETURN NULL;
    END IF;
    v_retained_count := cardinality(p_retained_key_ids);
    FOR v_index IN 1..v_retained_count LOOP
        IF p_retained_key_ids[v_index] IS NULL
           OR p_retained_retired_at_unix_ms[v_index] IS NULL
           OR p_retained_destroy_after_unix_ms[v_index] IS NULL
           OR p_retained_key_ids[v_index] !~ '^[a-z0-9][a-z0-9._-]{0,63}$'
           OR octet_length(p_retained_key_ids[v_index]) NOT BETWEEN 1 AND 64
           OR p_retained_key_ids[v_index] = p_active_key_id
           OR (v_previous_key_id IS NOT NULL
               AND pg_catalog.convert_to(p_retained_key_ids[v_index], 'UTF8')
                    <= pg_catalog.convert_to(v_previous_key_id, 'UTF8'))
           OR p_retained_retired_at_unix_ms[v_index] NOT BETWEEN 0 AND 9007199254740991
           OR p_retained_destroy_after_unix_ms[v_index]
                <= p_retained_retired_at_unix_ms[v_index]
           OR p_retained_destroy_after_unix_ms[v_index] > 9007199254740991
           OR p_retained_retired_at_unix_ms[v_index] > p_active_since_unix_ms
           OR p_retained_destroy_after_unix_ms[v_index] <= p_active_since_unix_ms
           OR p_retained_retired_at_unix_ms[v_index]
                > 9007199254740991 - p_audit_event_retention_ms
           OR p_retained_destroy_after_unix_ms[v_index]
                < p_retained_retired_at_unix_ms[v_index] + p_audit_event_retention_ms
        THEN
            RETURN NULL;
        END IF;
        IF v_index > 1 THEN
            v_retained_canonical := v_retained_canonical || ',';
        END IF;
        v_retained_canonical := v_retained_canonical || pg_catalog.format(
            '{"destroy_after_unix_ms":%s,"key_id":"%s","retired_at_unix_ms":%s}',
            p_retained_destroy_after_unix_ms[v_index],
            p_retained_key_ids[v_index],
            p_retained_retired_at_unix_ms[v_index]
        );
        v_previous_key_id := p_retained_key_ids[v_index];
    END LOOP;
    RETURN pg_catalog.format(
        '{"active_key_id":"%s","active_since_unix_ms":%s,'
        '"active_write_deadline_unix_ms":%s,"audit_event_retention_ms":%s,'
        '"generation":%s,"retained_keys":[%s],'
        '"schema":"registry.audit-pseudonym-keyring/v1"}',
        p_active_key_id, p_active_since_unix_ms,
        p_active_write_deadline_unix_ms, p_audit_event_retention_ms,
        p_generation, v_retained_canonical
    );
END;
$function$;

CREATE OR REPLACE FUNCTION relay_state_private.audit_pseudonym_history_snapshot_v1()
RETURNS TABLE (
    used_key_id_count bigint,
    used_key_ids_digest bytea,
    used_key_ids text[]
)
LANGUAGE plpgsql
STABLE
SET search_path = pg_catalog, relay_state_private
SET lock_timeout = '2s'
SET statement_timeout = '5s'
SET idle_in_transaction_session_timeout = '5s'
SET synchronous_commit = 'on'
AS $function$
DECLARE
    v_count bigint;
    v_total_id_bytes bigint;
    v_ids text[];
    v_framed_ids bytea;
BEGIN
    SELECT count(*)::bigint,
           COALESCE(sum(octet_length(row.key_id)), 0)::bigint,
           COALESCE(pg_catalog.array_agg(
               row.key_id ORDER BY pg_catalog.convert_to(row.key_id, 'UTF8')
           ), ARRAY[]::text[]),
           COALESCE(pg_catalog.string_agg(
               pg_catalog.int2send(octet_length(row.key_id)::smallint)
               || pg_catalog.convert_to(row.key_id, 'UTF8'),
               pg_catalog.decode('', 'hex')
               ORDER BY pg_catalog.convert_to(row.key_id, 'UTF8')
           ), pg_catalog.decode('', 'hex'))
    INTO v_count, v_total_id_bytes, v_ids, v_framed_ids
    FROM relay_state_private.audit_pseudonym_used_key_id AS row;
    IF v_count > 4096 OR v_total_id_bytes > 262144 THEN
        RAISE EXCEPTION 'audit pseudonym used-key-id history exceeds its protocol bound'
            USING ERRCODE = '54000';
    END IF;
    RETURN QUERY SELECT
        v_count,
        pg_catalog.sha256(
            pg_catalog.convert_to(
                'registry.audit-pseudonym-key-id-history.v1', 'UTF8'
            ) || pg_catalog.decode('00', 'hex')
              || pg_catalog.int8send(v_count)
              || v_framed_ids
        ),
        v_ids;
END;
$function$;

CREATE OR REPLACE FUNCTION relay_state_private.capability_valid_v1()
RETURNS boolean
LANGUAGE sql
STABLE
SET search_path = pg_catalog, relay_state_private
SET lock_timeout = '2s'
SET statement_timeout = '5s'
SET idle_in_transaction_session_timeout = '5s'
SET synchronous_commit = 'on'
AS $function$
WITH metadata AS (
    SELECT * FROM relay_state_private.state_plane_metadata
    WHERE singleton = true
      AND schema_version = 1
      AND capability_id = 'registry.relay.postgres-durable-audit/v1'
      AND capability_fingerprint =
        'sha256:6602f5a07f80cb18d8b5cc78f0369d8b3bd765547f4765b39509997bbaca3090'
      AND serving_fence_capability_id = 'registry.relay.postgres-serving-fence/v1'
      AND serving_fence_lock_key <> 0
      AND serving_fence_lock_key <> 7221091440
      AND quota_capability_id = 'registry.relay.postgres-persistent-quota/v1'
      AND audit_pseudonym_keyring_capability_id =
        'registry.relay.postgres-audit-pseudonym-keyring/v1'
      AND audit_pseudonym_keyring_lock_key <> 0
      AND audit_pseudonym_keyring_lock_key <> 7221091440
      AND audit_pseudonym_keyring_lock_key <> serving_fence_lock_key
),
target_schemas AS (
    SELECT namespace.oid, namespace.nspname, namespace.nspowner, namespace.nspacl
    FROM pg_catalog.pg_namespace AS namespace
    WHERE namespace.nspname IN ('relay_state_private', 'relay_state_api')
),
target_relations AS (
    SELECT namespace.nspname, relation.relname, relation.relkind,
           relation.relowner, relation.relacl, relation.relpersistence,
           relation.relrowsecurity, relation.relforcerowsecurity,
           relation.relispartition, access_method.amname
    FROM pg_catalog.pg_class AS relation
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    LEFT JOIN pg_catalog.pg_am AS access_method ON access_method.oid = relation.relam
    WHERE namespace.nspname IN ('relay_state_private', 'relay_state_api')
      AND relation.relkind IN ('r', 'p', 'v', 'm', 'S', 'f')
),
target_indexes AS (
    SELECT table_relation.relname AS table_name,
           index_relation.relname AS index_name,
           index_relation.relowner, index_relation.relpersistence,
           index_relation.reloptions, access_method.amname,
           index_row.indisunique, index_row.indisprimary,
           index_row.indisexclusion, index_row.indimmediate,
           index_row.indisclustered, index_row.indisvalid,
           index_row.indcheckxmin, index_row.indisready,
           index_row.indislive, index_row.indisreplident,
           index_row.indnullsnotdistinct,
           pg_catalog.pg_get_indexdef(index_relation.oid) AS index_definition,
           index_row.indexprs IS NULL AS expression_free,
           index_row.indpred IS NULL AS predicate_free,
           EXISTS (
               SELECT 1 FROM pg_catalog.pg_constraint AS constraint_row
               WHERE constraint_row.conindid = index_relation.oid
                 AND constraint_row.conrelid = table_relation.oid
                 AND constraint_row.contype IN ('p', 'u')
           ) AS constraint_backed
    FROM pg_catalog.pg_index AS index_row
    JOIN pg_catalog.pg_class AS index_relation
      ON index_relation.oid = index_row.indexrelid
    JOIN pg_catalog.pg_class AS table_relation
      ON table_relation.oid = index_row.indrelid
    JOIN pg_catalog.pg_namespace AS namespace
      ON namespace.oid = table_relation.relnamespace
    JOIN pg_catalog.pg_am AS access_method ON access_method.oid = index_relation.relam
    WHERE namespace.nspname = 'relay_state_private'
      AND table_relation.relname IN (
          'state_plane_metadata', 'audit_chain_head', 'audit_phase',
          'serving_fence_state', 'consultation_completion_intent',
          'consultation_audit_context', 'dispatch_permit', 'consultation_quota_bucket',
          'audit_pseudonym_keyring', 'audit_pseudonym_used_key_id',
          'audit_pseudonym_transition_context'
      )
),
target_triggers AS (
    SELECT relation.relname, trigger_row.tgisinternal, trigger_row.tgenabled,
           constraint_row.conname
    FROM pg_catalog.pg_trigger AS trigger_row
    JOIN pg_catalog.pg_class AS relation ON relation.oid = trigger_row.tgrelid
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    LEFT JOIN pg_catalog.pg_constraint AS constraint_row
      ON constraint_row.oid = trigger_row.tgconstraint
    WHERE namespace.nspname = 'relay_state_private'
      AND relation.relname IN (
          'state_plane_metadata', 'audit_chain_head', 'audit_phase',
          'serving_fence_state', 'consultation_completion_intent',
          'consultation_audit_context', 'dispatch_permit', 'consultation_quota_bucket',
          'audit_pseudonym_keyring', 'audit_pseudonym_used_key_id',
          'audit_pseudonym_transition_context'
      )
),
target_rules AS (
    SELECT relation.relname, rewrite_rule.rulename
    FROM pg_catalog.pg_rewrite AS rewrite_rule
    JOIN pg_catalog.pg_class AS relation ON relation.oid = rewrite_rule.ev_class
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'relay_state_private'
      AND relation.relname IN (
          'state_plane_metadata', 'audit_chain_head', 'audit_phase',
          'serving_fence_state', 'consultation_completion_intent',
          'consultation_audit_context', 'dispatch_permit', 'consultation_quota_bucket',
          'audit_pseudonym_keyring', 'audit_pseudonym_used_key_id',
          'audit_pseudonym_transition_context'
      )
),
target_policies AS (
    SELECT relation.relname, policy.polname
    FROM pg_catalog.pg_policy AS policy
    JOIN pg_catalog.pg_class AS relation ON relation.oid = policy.polrelid
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    WHERE namespace.nspname = 'relay_state_private'
      AND relation.relname IN (
          'state_plane_metadata', 'audit_chain_head', 'audit_phase',
          'serving_fence_state', 'consultation_completion_intent',
          'consultation_audit_context', 'dispatch_permit', 'consultation_quota_bucket',
          'audit_pseudonym_keyring', 'audit_pseudonym_used_key_id',
          'audit_pseudonym_transition_context'
      )
),
target_functions AS (
    SELECT namespace.nspname, procedure.oid, procedure.proname, procedure.proowner,
           procedure.prosecdef, procedure.proconfig, procedure.provolatile,
           procedure.proparallel, procedure.proleakproof, procedure.prokind,
           procedure.prorettype, procedure.proretset, procedure.proallargtypes,
           procedure.proargmodes, procedure.proargnames, procedure.proargtypes,
           procedure.prosrc, procedure.proacl, language.lanname
    FROM pg_catalog.pg_proc AS procedure
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
    JOIN pg_catalog.pg_language AS language ON language.oid = procedure.prolang
    WHERE namespace.nspname IN ('relay_state_private', 'relay_state_api')
),
schema_acl AS (
    SELECT schema_row.nspname, acl.*
    FROM target_schemas AS schema_row
    CROSS JOIN LATERAL pg_catalog.aclexplode(
        COALESCE(schema_row.nspacl, pg_catalog.acldefault('n', schema_row.nspowner))
    ) AS acl
),
table_acl AS (
    SELECT relation.nspname, relation.relname, acl.*
    FROM target_relations AS relation
    CROSS JOIN LATERAL pg_catalog.aclexplode(
        COALESCE(relation.relacl, pg_catalog.acldefault('r', relation.relowner))
    ) AS acl
    WHERE relation.relkind IN ('r', 'p')
),
function_acl AS (
    SELECT function_row.nspname, function_row.proname, acl.*
    FROM target_functions AS function_row
    CROSS JOIN LATERAL pg_catalog.aclexplode(
        COALESCE(function_row.proacl, pg_catalog.acldefault('f', function_row.proowner))
    ) AS acl
),
constraint_fingerprint AS (
    SELECT pg_catalog.md5(COALESCE(pg_catalog.string_agg(
        namespace.nspname || '.' || relation.relname || '.' || constraint_row.conname
        || ':' || constraint_row.contype::text
        || ':' || constraint_row.convalidated::text
        || ':' || constraint_row.condeferrable::text
        || ':' || constraint_row.condeferred::text
        || ':' || COALESCE(constraint_row.conkey::text, '')
        || ':' || COALESCE(constraint_row.confkey::text, '')
        || ':' || COALESCE(referenced.relname, '')
        || ':' || pg_catalog.pg_get_constraintdef(constraint_row.oid, true),
        E'\n' ORDER BY namespace.nspname, relation.relname, constraint_row.conname
    ), '')) AS value
    FROM pg_catalog.pg_constraint AS constraint_row
    JOIN pg_catalog.pg_class AS relation ON relation.oid = constraint_row.conrelid
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    LEFT JOIN pg_catalog.pg_class AS referenced ON referenced.oid = constraint_row.confrelid
    WHERE namespace.nspname = 'relay_state_private'
),
column_fingerprint AS (
    SELECT pg_catalog.md5(COALESCE(pg_catalog.string_agg(
        relation.relname || '.' || attribute.attnum::text || ':' || attribute.attname
        || ':' || pg_catalog.format_type(attribute.atttypid, attribute.atttypmod)
        || ':' || attribute.attnotnull::text
        || ':default_collation=' || (attribute.attcollation = type_row.typcollation)::text
        || ':identity=' || attribute.attidentity::text
        || ':generated=' || attribute.attgenerated::text
        || ':acl=' || COALESCE(attribute.attacl::text, '')
        || ':options=' || COALESCE(attribute.attoptions::text, '')
        || ':' || COALESCE(pg_catalog.pg_get_expr(default_row.adbin, default_row.adrelid), ''),
        E'\n' ORDER BY relation.relname, attribute.attnum
    ), '')) AS value
    FROM pg_catalog.pg_attribute AS attribute
    JOIN pg_catalog.pg_class AS relation ON relation.oid = attribute.attrelid
    JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = relation.relnamespace
    JOIN pg_catalog.pg_type AS type_row ON type_row.oid = attribute.atttypid
    LEFT JOIN pg_catalog.pg_attrdef AS default_row
      ON default_row.adrelid = attribute.attrelid AND default_row.adnum = attribute.attnum
    WHERE namespace.nspname = 'relay_state_private'
      AND relation.relkind IN ('r', 'p')
      AND attribute.attnum > 0 AND NOT attribute.attisdropped
),
function_fingerprint AS (
    SELECT pg_catalog.md5(COALESCE(pg_catalog.string_agg(
        function_row.nspname || '.' || function_row.proname
        || ':args=' || pg_catalog.oidvectortypes(function_row.proargtypes)
        || ':return=' || pg_catalog.format_type(function_row.prorettype, NULL)
        || ':set=' || function_row.proretset::text
        || ':alltypes=' || COALESCE((
            SELECT pg_catalog.string_agg(pg_catalog.format_type(type_oid, NULL), ',' ORDER BY ordinal)
            FROM pg_catalog.unnest(function_row.proallargtypes) WITH ORDINALITY AS all_types(type_oid, ordinal)
        ), '')
        || ':modes=' || COALESCE(function_row.proargmodes::text, '')
        || ':names=' || COALESCE(function_row.proargnames::text, '')
        || ':kind=' || function_row.prokind::text
        || ':security=' || function_row.prosecdef::text
        || ':config=' || COALESCE(function_row.proconfig::text, '')
        || ':volatile=' || function_row.provolatile::text
        || ':parallel=' || function_row.proparallel::text
        || ':leakproof=' || function_row.proleakproof::text
        || ':language=' || function_row.lanname
        || ':body=' || CASE
            WHEN function_row.nspname = 'relay_state_api'
              OR function_row.proname IN (
                  'audit_pseudonym_metadata_canonical_v1',
                  'audit_pseudonym_history_snapshot_v1',
                  'consultation_completion_seed_valid_v1',
                  'consultation_recursive_schema_valid_v1',
                  'jsonb_object_key_count_v1',
                  'consultation_completion_snapshot_internal_v1',
                  'consultation_completion_cas_internal_v1'
              )
            THEN pg_catalog.md5(function_row.prosrc) ELSE '' END,
        E'\n' ORDER BY function_row.nspname, function_row.proname,
                     pg_catalog.oidvectortypes(function_row.proargtypes)
    ), '')) AS value
    FROM target_functions AS function_row
),
server AS (
    SELECT current_setting('server_version_num')::integer / 10000 AS major
)
SELECT
    current_setting('max_prepared_transactions')::integer = 0
    AND current_setting('fsync') = 'on'
    AND current_setting('full_page_writes') = 'on'
    AND current_setting('synchronous_commit') = 'on'
    AND current_setting('client_encoding') = 'UTF8'
    AND current_setting('standard_conforming_strings') = 'on'
    AND current_setting('session_replication_role') = 'origin'
    AND current_setting('default_transaction_isolation') = 'read committed'
    AND current_setting('transaction_isolation') = 'read committed'
    AND current_setting('default_transaction_read_only') = 'off'
    AND current_setting('transaction_read_only') = 'off'
    AND NOT pg_catalog.pg_is_in_recovery()
    AND (SELECT major BETWEEN 16 AND 18 FROM server)
    AND (SELECT count(*) = 1 FROM metadata)
    AND (
        (
            NOT EXISTS (
                SELECT 1 FROM relay_state_private.audit_pseudonym_keyring
            )
            AND NOT EXISTS (
                SELECT 1 FROM relay_state_private.audit_pseudonym_used_key_id
            )
        )
        OR EXISTS (
            SELECT 1
            FROM relay_state_private.audit_pseudonym_keyring AS keyring
            CROSS JOIN LATERAL
                relay_state_private.audit_pseudonym_history_snapshot_v1() AS history
            WHERE keyring.singleton = true
              AND keyring.metadata_canonical =
                  relay_state_private.audit_pseudonym_metadata_canonical_v1(
                      keyring.generation,
                      keyring.active_key_id,
                      keyring.active_since_unix_ms,
                      keyring.active_write_deadline_unix_ms,
                      keyring.audit_event_retention_ms,
                      keyring.retained_key_ids,
                      keyring.retained_retired_at_unix_ms,
                      keyring.retained_destroy_after_unix_ms
                  )
              AND keyring.metadata_digest = pg_catalog.sha256(
                  pg_catalog.convert_to(keyring.metadata_canonical, 'UTF8')
              )
              AND keyring.used_key_id_count = history.used_key_id_count
              AND keyring.used_key_ids_digest = history.used_key_ids_digest
              AND keyring.active_key_id = ANY(history.used_key_ids)
              AND NOT EXISTS (
                  SELECT 1
                  FROM pg_catalog.unnest(keyring.retained_key_ids) AS retained(key_id)
                  WHERE retained.key_id <> ALL(history.used_key_ids)
              )
        )
    )
    AND EXISTS (
        SELECT 1 FROM metadata AS bound
        JOIN pg_catalog.pg_roles AS owner_role ON owner_role.oid = bound.owner_role_oid
        JOIN pg_catalog.pg_roles AS runtime_role ON runtime_role.oid = bound.runtime_role_oid
        JOIN pg_catalog.pg_roles AS maintenance_role
          ON maintenance_role.oid = bound.audit_pseudonym_maintenance_role_oid
        JOIN pg_catalog.pg_roles AS reader_role
          ON reader_role.oid = bound.audit_pseudonym_reader_role_oid
        WHERE bound.owner_role_oid = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user)
          AND NOT owner_role.rolcanlogin AND NOT owner_role.rolsuper
          AND NOT owner_role.rolcreaterole AND NOT owner_role.rolbypassrls
          AND NOT owner_role.rolreplication AND NOT owner_role.rolcreatedb
          AND runtime_role.rolcanlogin AND NOT runtime_role.rolsuper
          AND NOT runtime_role.rolcreaterole AND NOT runtime_role.rolbypassrls
          AND NOT runtime_role.rolreplication AND NOT runtime_role.rolcreatedb
          AND maintenance_role.rolcanlogin AND NOT maintenance_role.rolsuper
          AND NOT maintenance_role.rolcreaterole AND NOT maintenance_role.rolbypassrls
          AND NOT maintenance_role.rolreplication AND NOT maintenance_role.rolcreatedb
          AND reader_role.rolcanlogin AND NOT reader_role.rolsuper
          AND NOT reader_role.rolcreaterole AND NOT reader_role.rolbypassrls
          AND NOT reader_role.rolreplication AND NOT reader_role.rolcreatedb
          AND NOT EXISTS (
              SELECT 1 FROM pg_catalog.pg_auth_members AS membership
              WHERE membership.member IN (
                        bound.owner_role_oid, bound.runtime_role_oid,
                        bound.audit_pseudonym_maintenance_role_oid,
                        bound.audit_pseudonym_reader_role_oid
                    )
                 OR membership.roleid IN (
                        bound.owner_role_oid, bound.runtime_role_oid,
                        bound.audit_pseudonym_maintenance_role_oid,
                        bound.audit_pseudonym_reader_role_oid
                    )
          )
    )
    AND (SELECT count(*) = 2 FROM target_schemas)
    AND NOT EXISTS (
        SELECT 1 FROM target_schemas, metadata
        WHERE target_schemas.nspowner <> metadata.owner_role_oid
    )
    AND (SELECT count(*) = 11 FROM target_relations)
    AND NOT EXISTS (
        SELECT 1 FROM target_relations, metadata
        WHERE target_relations.nspname <> 'relay_state_private'
           OR target_relations.relkind <> 'r'
           OR target_relations.relowner <> metadata.owner_role_oid
           OR target_relations.relpersistence <> 'p'
           OR target_relations.relrowsecurity
           OR target_relations.relforcerowsecurity
           OR target_relations.relispartition
           OR target_relations.amname IS DISTINCT FROM 'heap'
           OR target_relations.relname NOT IN (
               'state_plane_metadata', 'audit_chain_head', 'audit_phase',
               'serving_fence_state', 'consultation_completion_intent',
               'consultation_audit_context', 'dispatch_permit', 'consultation_quota_bucket',
               'audit_pseudonym_keyring', 'audit_pseudonym_used_key_id',
               'audit_pseudonym_transition_context'
           )
    )
    AND (SELECT count(*) = 16 FROM target_indexes)
    AND NOT EXISTS (
        SELECT 1 FROM target_indexes, metadata
        WHERE target_indexes.relowner <> metadata.owner_role_oid
           OR target_indexes.relpersistence <> 'p'
           OR target_indexes.reloptions IS NOT NULL
           OR target_indexes.amname <> 'btree'
           OR target_indexes.indisexclusion
           OR NOT target_indexes.indimmediate
           OR target_indexes.indisclustered
           OR NOT target_indexes.indisvalid
           OR target_indexes.indcheckxmin
           OR NOT target_indexes.indisready
           OR NOT target_indexes.indislive
           OR target_indexes.indisreplident
           OR target_indexes.indnullsnotdistinct
           OR NOT target_indexes.expression_free
           OR NOT target_indexes.predicate_free
           OR target_indexes.index_name NOT IN (
               'state_plane_metadata_pk', 'audit_chain_head_pk', 'audit_phase_pk',
               'audit_phase_envelope_id_unique',
               'audit_phase_stored_identity_unique',
               'serving_fence_state_pk',
               'consultation_completion_intent_pk',
               'consultation_completion_intent_deadline_unique',
               'consultation_completion_intent_takeover_idx',
               'consultation_audit_context_pk', 'dispatch_permit_pk',
               'dispatch_permit_takeover_idx', 'consultation_quota_bucket_pk',
               'audit_pseudonym_keyring_pk', 'audit_pseudonym_used_key_id_pk',
               'audit_pseudonym_transition_context_pk'
           )
           OR NOT (
               (target_indexes.table_name = 'state_plane_metadata'
                AND target_indexes.index_name = 'state_plane_metadata_pk')
               OR (target_indexes.table_name = 'audit_chain_head'
                   AND target_indexes.index_name = 'audit_chain_head_pk')
               OR (target_indexes.table_name = 'audit_phase'
                   AND target_indexes.index_name IN (
                       'audit_phase_pk', 'audit_phase_envelope_id_unique',
                       'audit_phase_stored_identity_unique'
                   ))
               OR (target_indexes.table_name = 'serving_fence_state'
                   AND target_indexes.index_name = 'serving_fence_state_pk')
               OR (target_indexes.table_name = 'consultation_completion_intent'
                   AND target_indexes.index_name IN (
                       'consultation_completion_intent_pk',
                       'consultation_completion_intent_deadline_unique',
                       'consultation_completion_intent_takeover_idx'
                   ))
               OR (target_indexes.table_name = 'consultation_audit_context'
                   AND target_indexes.index_name = 'consultation_audit_context_pk')
               OR (target_indexes.table_name = 'dispatch_permit'
                   AND target_indexes.index_name IN (
                       'dispatch_permit_pk', 'dispatch_permit_takeover_idx'
                   ))
               OR (target_indexes.table_name = 'consultation_quota_bucket'
                   AND target_indexes.index_name = 'consultation_quota_bucket_pk')
               OR (target_indexes.table_name = 'audit_pseudonym_keyring'
                   AND target_indexes.index_name = 'audit_pseudonym_keyring_pk')
               OR (target_indexes.table_name = 'audit_pseudonym_used_key_id'
                   AND target_indexes.index_name = 'audit_pseudonym_used_key_id_pk')
               OR (target_indexes.table_name = 'audit_pseudonym_transition_context'
                   AND target_indexes.index_name = 'audit_pseudonym_transition_context_pk')
           )
           OR (
               target_indexes.index_name IN (
                   'state_plane_metadata_pk', 'audit_chain_head_pk', 'audit_phase_pk',
                   'serving_fence_state_pk', 'consultation_completion_intent_pk',
                   'consultation_audit_context_pk', 'dispatch_permit_pk',
                   'consultation_quota_bucket_pk', 'audit_pseudonym_keyring_pk',
                   'audit_pseudonym_used_key_id_pk',
                   'audit_pseudonym_transition_context_pk'
               ) AND NOT target_indexes.indisprimary
           )
           OR (
               target_indexes.index_name IN (
                   'audit_phase_envelope_id_unique',
                   'audit_phase_stored_identity_unique',
                   'consultation_completion_intent_deadline_unique'
               ) AND target_indexes.indisprimary
           )
           OR (
               target_indexes.index_name = 'dispatch_permit_takeover_idx'
               AND (
                   target_indexes.indisunique
                   OR target_indexes.indisprimary
                   OR target_indexes.constraint_backed
                   OR target_indexes.index_definition <>
                       'CREATE INDEX dispatch_permit_takeover_idx ON relay_state_private.dispatch_permit USING btree (fence_generation, completion_envelope_id, abandoned_at, deadline_at)'
               )
           )
           OR (
               target_indexes.index_name = 'consultation_completion_intent_takeover_idx'
               AND (
                   target_indexes.indisunique
                   OR target_indexes.indisprimary
                   OR target_indexes.constraint_backed
                   OR target_indexes.index_definition <>
                       'CREATE INDEX consultation_completion_intent_takeover_idx ON relay_state_private.consultation_completion_intent USING btree (fence_generation, state, total_deadline_at, operation_id)'
               )
           )
           OR (
               target_indexes.index_name NOT IN (
                   'dispatch_permit_takeover_idx',
                   'consultation_completion_intent_takeover_idx'
               )
               AND (NOT target_indexes.indisunique OR NOT target_indexes.constraint_backed)
           )
    )
    AND (SELECT count(*) = 20 FROM target_triggers)
    AND NOT EXISTS (
        SELECT 1 FROM target_triggers
        WHERE NOT target_triggers.tgisinternal
           OR target_triggers.tgenabled <> 'O'
           OR target_triggers.conname NOT IN (
               'audit_phase_attempt_fk',
               'consultation_completion_intent_attempt_fk',
               'consultation_completion_intent_completion_fk',
               'dispatch_permit_intent_deadline_fk',
               'dispatch_permit_completion_fk'
           )
    )
    AND NOT EXISTS (SELECT 1 FROM target_rules)
    AND NOT EXISTS (SELECT 1 FROM target_policies)
    AND (SELECT count(*) = 31 FROM target_functions)
    AND NOT EXISTS (
        SELECT 1 FROM target_functions, metadata
        WHERE target_functions.proowner <> metadata.owner_role_oid
           OR target_functions.prokind <> 'f'
           OR target_functions.proparallel <> 'u'
           OR target_functions.proleakproof
           OR target_functions.proconfig IS DISTINCT FROM ARRAY[
                'search_path=pg_catalog, relay_state_private',
                'lock_timeout=2s',
                'statement_timeout=5s',
                'idle_in_transaction_session_timeout=5s',
                'synchronous_commit=on'
              ]::text[]
           OR (target_functions.nspname = 'relay_state_private'
               AND NOT (
                   NOT target_functions.prosecdef
                   AND (
                       (target_functions.proname = 'capability_valid_v1'
                           AND target_functions.lanname = 'sql')
                       OR (target_functions.proname = 'jsonb_object_key_count_v1'
                           AND target_functions.lanname = 'sql')
                       OR (target_functions.proname IN (
                            'audit_pseudonym_metadata_canonical_v1',
                            'audit_pseudonym_history_snapshot_v1',
                            'consultation_completion_seed_valid_v1',
                            'consultation_recursive_schema_valid_v1',
                            'consultation_completion_snapshot_internal_v1',
                            'consultation_completion_cas_internal_v1'
                           ) AND target_functions.lanname = 'plpgsql')
                   )
               ))
           OR (target_functions.nspname = 'relay_state_api'
                       AND NOT (target_functions.proname IN (
                            'audit_phase_snapshot_v1', 'audit_phase_duplicate_v1',
                            'audit_phase_cas_v1', 'audit_readiness_v1',
                            'consultation_attempt_intent_snapshot_v1',
                            'consultation_attempt_intent_cas_v1',
                            'consultation_completion_snapshot_normal_v1',
                            'consultation_completion_snapshot_recovery_v1',
                            'consultation_completion_cas_normal_v1',
                            'consultation_completion_cas_unfinished_v1',
                            'consultation_completion_cas_recovery_v1',
                            'serving_fence_acquire_v1', 'serving_fence_finalize_v1',
                            'serving_fence_open_after_recovery_v1',
                            'serving_fence_status_v1',
                            'dispatch_permit_authorize_v1',
                            'serving_fence_release_v1', 'quota_reserve_v1',
                            'audit_pseudonym_keyring_snapshot_v1',
                            'audit_pseudonym_keyring_readiness_v1',
                            'audit_pseudonym_keyring_initialize_v1',
                            'audit_pseudonym_keyring_rotate_v1',
                            'audit_pseudonym_keyring_maintain_v1'
                       )
                        AND target_functions.prosecdef
                        AND target_functions.lanname = 'plpgsql'))
           OR target_functions.nspname NOT IN ('relay_state_private', 'relay_state_api')
    )
    AND (SELECT count(*) = 7 FROM schema_acl)
    AND NOT EXISTS (
        SELECT 1 FROM schema_acl, metadata
        WHERE schema_acl.grantor <> metadata.owner_role_oid
           OR schema_acl.is_grantable
           OR NOT (
               (schema_acl.nspname = 'relay_state_private'
                AND schema_acl.grantee = metadata.owner_role_oid
                AND schema_acl.privilege_type IN ('CREATE', 'USAGE'))
               OR (schema_acl.nspname = 'relay_state_api'
                   AND schema_acl.grantee = metadata.owner_role_oid
                   AND schema_acl.privilege_type IN ('CREATE', 'USAGE'))
               OR (schema_acl.nspname = 'relay_state_api'
                   AND schema_acl.grantee IN (
                       metadata.runtime_role_oid,
                       metadata.audit_pseudonym_maintenance_role_oid,
                       metadata.audit_pseudonym_reader_role_oid
                   )
                   AND schema_acl.privilege_type = 'USAGE')
           )
    )
    AND (SELECT count(*) FROM table_acl) = (
        SELECT 11 * count(*) FROM metadata
        CROSS JOIN LATERAL pg_catalog.aclexplode(
            pg_catalog.acldefault('r', metadata.owner_role_oid)
        ) AS expected_acl
    )
    AND NOT EXISTS (
        SELECT 1 FROM table_acl, metadata
        WHERE table_acl.grantor <> metadata.owner_role_oid
           OR table_acl.grantee <> metadata.owner_role_oid
           OR table_acl.is_grantable
           OR table_acl.privilege_type NOT IN (
               'SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE',
               'REFERENCES', 'TRIGGER', 'MAINTAIN'
           )
    )
    AND (SELECT count(*) = 58 FROM function_acl)
    AND NOT EXISTS (
        SELECT 1 FROM function_acl, metadata
        WHERE function_acl.grantor <> metadata.owner_role_oid
           OR function_acl.is_grantable
           OR function_acl.privilege_type <> 'EXECUTE'
           OR NOT (
               (function_acl.nspname = 'relay_state_private'
                AND function_acl.grantee = metadata.owner_role_oid)
               OR (function_acl.nspname = 'relay_state_api'
                   AND function_acl.grantee = metadata.owner_role_oid)
               OR (function_acl.nspname = 'relay_state_api'
                   AND function_acl.proname IN (
                       'audit_phase_snapshot_v1', 'audit_phase_duplicate_v1',
                       'audit_phase_cas_v1',
                       'consultation_attempt_intent_snapshot_v1',
                       'consultation_attempt_intent_cas_v1',
                       'consultation_completion_snapshot_normal_v1',
                       'consultation_completion_snapshot_recovery_v1',
                       'consultation_completion_cas_normal_v1',
                       'consultation_completion_cas_unfinished_v1',
                       'consultation_completion_cas_recovery_v1',
                       'audit_readiness_v1', 'serving_fence_acquire_v1',
                       'serving_fence_finalize_v1',
                       'serving_fence_open_after_recovery_v1',
                       'serving_fence_status_v1', 'dispatch_permit_authorize_v1',
                       'serving_fence_release_v1',
                       'quota_reserve_v1'
                   )
                   AND function_acl.grantee = metadata.runtime_role_oid)
               OR (function_acl.nspname = 'relay_state_api'
                   AND function_acl.proname IN (
                       'audit_pseudonym_keyring_snapshot_v1',
                       'audit_pseudonym_keyring_readiness_v1'
                   )
                   AND function_acl.grantee IN (
                       metadata.runtime_role_oid,
                       metadata.audit_pseudonym_maintenance_role_oid,
                       metadata.audit_pseudonym_reader_role_oid
                   ))
               OR (function_acl.nspname = 'relay_state_api'
                   AND function_acl.proname IN (
                       'audit_pseudonym_keyring_initialize_v1',
                       'audit_pseudonym_keyring_rotate_v1',
                       'audit_pseudonym_keyring_maintain_v1'
                   )
                   AND function_acl.grantee =
                       metadata.audit_pseudonym_maintenance_role_oid)
           )
    )
    AND (SELECT value = CASE server.major
            WHEN 16 THEN '4c5905e22d262645abcd05affe4da82f'
            WHEN 17 THEN '4c5905e22d262645abcd05affe4da82f'
            WHEN 18 THEN '6c11c5f44018f8cf06c439af932d7a15'
            ELSE '' END FROM constraint_fingerprint, server)
    AND (SELECT value = CASE server.major
            WHEN 16 THEN '1098f1125fa6f613d521504e985a351a'
            WHEN 17 THEN '1098f1125fa6f613d521504e985a351a'
            WHEN 18 THEN '1098f1125fa6f613d521504e985a351a'
            ELSE '' END FROM column_fingerprint, server)
    AND (SELECT value = CASE server.major
            WHEN 16 THEN 'ff865db8ec5369d3b87ac2498e0f7bf6'
            WHEN 17 THEN 'ff865db8ec5369d3b87ac2498e0f7bf6'
            WHEN 18 THEN 'ff865db8ec5369d3b87ac2498e0f7bf6'
            ELSE '' END FROM function_fingerprint, server);
$function$;

CREATE OR REPLACE FUNCTION relay_state_api.audit_phase_snapshot_v1(
    p_stream_kind text,
    p_operation_id text,
    p_phase text,
    p_payload_digest bytea,
    p_expected_chain_key_epoch_id text,
    p_pseudonym_key_id text,
    p_pseudonym_generation bigint,
    p_pseudonym_metadata_digest bytea,
    p_expected_keyring_lock_key bigint
)
RETURNS TABLE (
    outcome text,
    stored_envelope_id text,
    stored_chain_hash bytea,
    candidate_predecessor_hash bytea,
    candidate_generation bigint
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, relay_state_private
SET lock_timeout = '2s'
SET statement_timeout = '5s'
SET idle_in_transaction_session_timeout = '5s'
SET synchronous_commit = 'on'
AS $function$
DECLARE
    v_started_at timestamptz := clock_timestamp();
    v_runtime_oid oid;
    v_session_oid oid;
    v_existing relay_state_private.audit_phase%ROWTYPE;
    v_existing_record jsonb;
    v_pseudonym_fields_present integer;
    v_existing_pseudonym_payload_present boolean;
    v_keyring relay_state_private.audit_pseudonym_keyring%ROWTYPE;
    v_keyring_now_unix_us numeric;
BEGIN
    PERFORM set_config('lock_timeout', '2s', false);
    PERFORM set_config('statement_timeout', '5s', false);
    PERFORM set_config('idle_in_transaction_session_timeout', '5s', false);
    PERFORM set_config('synchronous_commit', 'on', false);
    SELECT metadata.runtime_role_oid INTO v_runtime_oid
    FROM relay_state_private.state_plane_metadata AS metadata
    WHERE metadata.singleton = true;
    SELECT oid INTO v_session_oid FROM pg_catalog.pg_roles WHERE rolname = session_user;
    IF v_session_oid IS DISTINCT FROM v_runtime_oid THEN
        RAISE EXCEPTION 'durable audit caller is not bound' USING ERRCODE = '42501';
    END IF;
    IF current_setting('search_path') <> 'pg_catalog, relay_state_private'
       OR current_setting('lock_timeout') <> '2s'
       OR current_setting('statement_timeout') <> '5s'
       OR current_setting('idle_in_transaction_session_timeout') <> '5s'
       OR current_setting('synchronous_commit') <> 'on'
       OR current_setting('client_encoding') <> 'UTF8'
       OR current_setting('standard_conforming_strings') <> 'on'
       OR current_setting('session_replication_role') <> 'origin'
       OR current_setting('default_transaction_isolation') <> 'read committed'
       OR current_setting('transaction_isolation') <> 'read committed'
       OR current_setting('default_transaction_read_only') <> 'off'
       OR current_setting('transaction_read_only') <> 'off'
       OR pg_catalog.pg_is_in_recovery()
    THEN
        RAISE EXCEPTION 'durable audit runtime session is unsafe' USING ERRCODE = '55000';
    END IF;
    IF NOT relay_state_private.capability_valid_v1() THEN
        RAISE EXCEPTION 'durable audit capability unavailable' USING ERRCODE = '55000';
    END IF;
    IF p_stream_kind IS NULL OR p_operation_id IS NULL OR p_phase IS NULL
       OR p_payload_digest IS NULL OR p_expected_chain_key_epoch_id IS NULL
       OR p_expected_keyring_lock_key IS NULL
       OR p_stream_kind NOT IN (
           'consultation', 'materialization', 'denial',
           'startup_credential_probe', 'readiness_credential_probe'
       )
       OR p_operation_id !~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'
       OR octet_length(p_payload_digest) <> 32
       OR NOT (
           (p_stream_kind = 'denial' AND p_phase = 'denial_decision')
           OR (p_stream_kind <> 'denial' AND p_phase IN ('attempt', 'completion'))
       )
    THEN
        RAISE EXCEPTION 'invalid durable audit request' USING ERRCODE = '22023';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM relay_state_private.state_plane_metadata AS metadata
        WHERE metadata.singleton = true
          AND metadata.chain_key_epoch_id = p_expected_chain_key_epoch_id
          AND metadata.audit_pseudonym_keyring_lock_key = p_expected_keyring_lock_key
    ) THEN
        RAISE EXCEPTION 'durable audit deployment authority drifted'
            USING ERRCODE = '55000';
    END IF;
    IF p_stream_kind = 'consultation' AND NOT EXISTS (
        SELECT 1
        FROM relay_state_private.consultation_audit_context AS context
        WHERE context.backend_pid = pg_catalog.pg_backend_pid()
          AND context.transaction_id = pg_catalog.txid_current()
          AND context.operation_id = p_operation_id
          AND context.purpose = 'attempt_snapshot'
          AND p_phase = 'attempt'
    ) THEN
        RAISE EXCEPTION 'consultation audit snapshot requires atomic intent context'
            USING ERRCODE = '42501';
    END IF;
    v_pseudonym_fields_present := pg_catalog.num_nonnulls(
        p_pseudonym_key_id,
        p_pseudonym_generation,
        p_pseudonym_metadata_digest
    );
    IF v_pseudonym_fields_present NOT IN (0, 3)
       OR (p_stream_kind = 'consultation' AND v_pseudonym_fields_present <> 3)
       OR (v_pseudonym_fields_present = 3
           AND p_stream_kind NOT IN ('consultation', 'denial'))
       OR (v_pseudonym_fields_present = 3
           AND (
               p_pseudonym_key_id !~ '^[a-z0-9][a-z0-9._-]{0,63}$'
               OR octet_length(p_pseudonym_key_id) NOT BETWEEN 1 AND 64
               OR p_pseudonym_generation NOT BETWEEN 1 AND 9007199254740991
               OR octet_length(p_pseudonym_metadata_digest) <> 32
           ))
    THEN
        RAISE EXCEPTION 'durable audit pseudonym authority is invalid'
            USING ERRCODE = '22023';
    END IF;
    SELECT phase_row.* INTO v_existing
    FROM relay_state_private.audit_phase AS phase_row
    WHERE phase_row.stream_kind = p_stream_kind
      AND phase_row.operation_id = p_operation_id
      AND phase_row.phase = p_phase;
    IF FOUND THEN
        IF v_existing.payload_digest IS DISTINCT FROM p_payload_digest THEN
            IF clock_timestamp() - v_started_at > interval '5 seconds' THEN
                RAISE EXCEPTION 'durable audit snapshot exceeded its deadline'
                    USING ERRCODE = '57014';
            END IF;
            RETURN QUERY SELECT
                'conflicting_duplicate'::text, v_existing.envelope_id,
                v_existing.record_hash, NULL::bytea, NULL::bigint;
            RETURN;
        END IF;
        v_existing_record := v_existing.record_json::jsonb;
        v_existing_pseudonym_payload_present :=
            v_existing_record @? '$.**.commitment_key_id'
            OR v_existing_record @? '$.**.subject_handle'
            OR v_existing_record @? '$.**.input_commitment'
            OR v_existing_record @? '$.**.predicate_commitment'
            OR v_existing_record @? '$.**.consent_evidence_commitment';
        IF (p_stream_kind = 'denial' AND v_existing_pseudonym_payload_present
            AND v_pseudonym_fields_present <> 3)
           OR (v_pseudonym_fields_present = 3
               AND v_existing_record #>> '{payload,commitment_key_id}'
                    IS DISTINCT FROM p_pseudonym_key_id)
        THEN
            RAISE EXCEPTION 'durable audit pseudonym authority is invalid'
                USING ERRCODE = '22023';
        END IF;
        IF clock_timestamp() - v_started_at > interval '5 seconds' THEN
            RAISE EXCEPTION 'durable audit snapshot exceeded its deadline'
                USING ERRCODE = '57014';
        END IF;
        RETURN QUERY SELECT
            'identical_duplicate'::text,
            v_existing.envelope_id, v_existing.record_hash,
            NULL::bytea, NULL::bigint;
        RETURN;
    END IF;
    IF v_pseudonym_fields_present = 3 THEN
        PERFORM pg_catalog.pg_advisory_xact_lock_shared(p_expected_keyring_lock_key);
        IF NOT EXISTS (
            SELECT 1
            FROM relay_state_private.state_plane_metadata AS metadata
            WHERE metadata.singleton = true
              AND metadata.chain_key_epoch_id = p_expected_chain_key_epoch_id
              AND metadata.audit_pseudonym_keyring_lock_key = p_expected_keyring_lock_key
        ) THEN
            RAISE EXCEPTION 'durable audit deployment authority drifted'
                USING ERRCODE = '55000';
        END IF;
        SELECT row.* INTO v_keyring
        FROM relay_state_private.audit_pseudonym_keyring AS row
        WHERE row.singleton = true;
        v_keyring_now_unix_us := pg_catalog.floor(
            extract(epoch FROM clock_timestamp()) * 1000000
        );
        IF NOT FOUND
           OR v_keyring.active_key_id IS DISTINCT FROM p_pseudonym_key_id
           OR v_keyring.generation IS DISTINCT FROM p_pseudonym_generation
           OR v_keyring.metadata_digest IS DISTINCT FROM p_pseudonym_metadata_digest
           OR v_keyring_now_unix_us
                < v_keyring.active_since_unix_ms::numeric * 1000
           OR v_keyring_now_unix_us
                >= v_keyring.active_write_deadline_unix_ms::numeric * 1000
           OR EXISTS (
               SELECT 1
               FROM pg_catalog.unnest(
                   v_keyring.retained_destroy_after_unix_ms
               ) AS deadline(value)
               WHERE deadline.value::numeric * 1000 <= v_keyring_now_unix_us
           )
        THEN
            RAISE EXCEPTION 'durable audit pseudonym authority is stale'
                USING ERRCODE = '55000';
        END IF;
    END IF;
    RETURN QUERY
    SELECT 'candidate'::text, NULL::text, NULL::bytea,
           head.record_hash, head.generation
    FROM relay_state_private.audit_chain_head AS head
    WHERE head.singleton = true;
    IF clock_timestamp() - v_started_at > interval '5 seconds' THEN
        RAISE EXCEPTION 'durable audit snapshot exceeded its deadline'
            USING ERRCODE = '57014';
    END IF;
END;
$function$;

CREATE OR REPLACE FUNCTION relay_state_api.audit_phase_duplicate_v1(
    p_stream_kind text,
    p_operation_id text,
    p_phase text,
    p_payload_digest bytea,
    p_expected_chain_key_epoch_id text,
    p_expected_keyring_lock_key bigint
)
RETURNS TABLE (
    outcome text,
    stored_envelope_id text,
    stored_chain_hash bytea
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, relay_state_private
SET lock_timeout = '2s'
SET statement_timeout = '5s'
SET idle_in_transaction_session_timeout = '5s'
SET synchronous_commit = 'on'
AS $function$
DECLARE
    v_started_at timestamptz := clock_timestamp();
    v_runtime_oid oid;
    v_session_oid oid;
    v_existing relay_state_private.audit_phase%ROWTYPE;
    v_existing_record jsonb;
BEGIN
    PERFORM set_config('lock_timeout', '2s', false);
    PERFORM set_config('statement_timeout', '5s', false);
    PERFORM set_config('idle_in_transaction_session_timeout', '5s', false);
    PERFORM set_config('synchronous_commit', 'on', false);
    SELECT metadata.runtime_role_oid INTO v_runtime_oid
    FROM relay_state_private.state_plane_metadata AS metadata
    WHERE metadata.singleton = true;
    SELECT oid INTO v_session_oid FROM pg_catalog.pg_roles WHERE rolname = session_user;
    IF v_session_oid IS DISTINCT FROM v_runtime_oid THEN
        RAISE EXCEPTION 'durable audit caller is not bound' USING ERRCODE = '42501';
    END IF;
    IF current_setting('search_path') <> 'pg_catalog, relay_state_private'
       OR current_setting('lock_timeout') <> '2s'
       OR current_setting('statement_timeout') <> '5s'
       OR current_setting('idle_in_transaction_session_timeout') <> '5s'
       OR current_setting('synchronous_commit') <> 'on'
       OR current_setting('client_encoding') <> 'UTF8'
       OR current_setting('standard_conforming_strings') <> 'on'
       OR current_setting('session_replication_role') <> 'origin'
       OR current_setting('default_transaction_isolation') <> 'read committed'
       OR current_setting('transaction_isolation') <> 'read committed'
       OR current_setting('default_transaction_read_only') <> 'off'
       OR current_setting('transaction_read_only') <> 'off'
       OR pg_catalog.pg_is_in_recovery()
    THEN
        RAISE EXCEPTION 'durable audit runtime session is unsafe' USING ERRCODE = '55000';
    END IF;
    IF NOT relay_state_private.capability_valid_v1() THEN
        RAISE EXCEPTION 'durable audit capability unavailable' USING ERRCODE = '55000';
    END IF;
    IF p_stream_kind IS NULL OR p_operation_id IS NULL OR p_phase IS NULL
       OR p_payload_digest IS NULL OR p_expected_chain_key_epoch_id IS NULL
       OR p_expected_keyring_lock_key IS NULL
       OR p_stream_kind NOT IN ('consultation', 'denial')
       OR p_operation_id !~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'
       OR octet_length(p_payload_digest) <> 32
       OR NOT (
           (p_stream_kind = 'denial' AND p_phase = 'denial_decision')
           OR (p_stream_kind = 'consultation' AND p_phase IN ('attempt', 'completion'))
       )
    THEN
        RAISE EXCEPTION 'invalid durable audit duplicate recovery request'
            USING ERRCODE = '22023';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM relay_state_private.state_plane_metadata AS metadata
        WHERE metadata.singleton = true
          AND metadata.chain_key_epoch_id = p_expected_chain_key_epoch_id
          AND metadata.audit_pseudonym_keyring_lock_key = p_expected_keyring_lock_key
    ) THEN
        RAISE EXCEPTION 'durable audit deployment authority drifted'
            USING ERRCODE = '55000';
    END IF;
    SELECT phase_row.* INTO v_existing
    FROM relay_state_private.audit_phase AS phase_row
    WHERE phase_row.stream_kind = p_stream_kind
      AND phase_row.operation_id = p_operation_id
      AND phase_row.phase = p_phase;
    IF NOT FOUND THEN
        outcome := 'not_found';
        RETURN NEXT;
        RETURN;
    END IF;
    v_existing_record := v_existing.record_json::jsonb;
    IF v_existing_record #>> '{payload,commitment_key_id}' IS NULL
       OR v_existing_record #>> '{payload,commitment_key_id}'
            !~ '^[a-z0-9][a-z0-9._-]{0,63}$'
       OR octet_length(v_existing_record #>> '{payload,commitment_key_id}')
            NOT BETWEEN 1 AND 64
    THEN
        RAISE EXCEPTION 'durable audit duplicate is not pseudonym-bound'
            USING ERRCODE = '22023';
    END IF;
    IF clock_timestamp() - v_started_at > interval '5 seconds' THEN
        RAISE EXCEPTION 'durable audit duplicate recovery exceeded its deadline'
            USING ERRCODE = '57014';
    END IF;
    outcome := CASE WHEN v_existing.payload_digest = p_payload_digest
        THEN 'identical_duplicate' ELSE 'conflicting_duplicate' END;
    stored_envelope_id := v_existing.envelope_id;
    stored_chain_hash := v_existing.record_hash;
    RETURN NEXT;
END;
$function$;

CREATE OR REPLACE FUNCTION relay_state_api.audit_phase_cas_v1(
    p_stream_kind text,
    p_operation_id text,
    p_phase text,
    p_payload_digest bytea,
    p_candidate_generation bigint,
    p_candidate_predecessor_hash bytea,
    p_envelope_id text,
    p_timestamp_unix_ms bigint,
    p_record_json text,
    p_envelope_json text,
    p_record_hash bytea,
    p_attempt_envelope_id text,
    p_attempt_record_hash bytea,
    p_pseudonym_key_id text,
    p_pseudonym_generation bigint,
    p_pseudonym_metadata_digest bytea,
    p_expected_chain_key_epoch_id text,
    p_expected_keyring_lock_key bigint
)
RETURNS TABLE (
    outcome text,
    stored_envelope_id text,
    stored_chain_hash bytea
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, relay_state_private
SET lock_timeout = '2s'
SET statement_timeout = '5s'
SET idle_in_transaction_session_timeout = '5s'
SET synchronous_commit = 'on'
AS $function$
DECLARE
    v_started_at timestamptz := clock_timestamp();
    v_runtime_oid oid;
    v_session_oid oid;
    v_existing relay_state_private.audit_phase%ROWTYPE;
    v_existing_record jsonb;
    v_record jsonb;
    v_envelope jsonb;
    v_expected_digest text;
    v_inserted_rows bigint;
    v_pseudonym_fields_present integer;
    v_pseudonym_payload_present boolean;
    v_existing_pseudonym_payload_present boolean;
    v_keyring relay_state_private.audit_pseudonym_keyring%ROWTYPE;
    v_keyring_now_unix_us numeric;
BEGIN
    PERFORM set_config('lock_timeout', '2s', false);
    PERFORM set_config('statement_timeout', '5s', false);
    PERFORM set_config('idle_in_transaction_session_timeout', '5s', false);
    PERFORM set_config('synchronous_commit', 'on', false);
    SELECT metadata.runtime_role_oid INTO v_runtime_oid
    FROM relay_state_private.state_plane_metadata AS metadata
    WHERE metadata.singleton = true;
    SELECT oid INTO v_session_oid FROM pg_catalog.pg_roles WHERE rolname = session_user;
    IF v_session_oid IS DISTINCT FROM v_runtime_oid THEN
        RAISE EXCEPTION 'durable audit caller is not bound' USING ERRCODE = '42501';
    END IF;
    IF current_setting('search_path') <> 'pg_catalog, relay_state_private'
       OR current_setting('lock_timeout') <> '2s'
       OR current_setting('statement_timeout') <> '5s'
       OR current_setting('idle_in_transaction_session_timeout') <> '5s'
       OR current_setting('synchronous_commit') <> 'on'
       OR current_setting('client_encoding') <> 'UTF8'
       OR current_setting('standard_conforming_strings') <> 'on'
       OR current_setting('session_replication_role') <> 'origin'
       OR current_setting('default_transaction_isolation') <> 'read committed'
       OR current_setting('transaction_isolation') <> 'read committed'
       OR current_setting('default_transaction_read_only') <> 'off'
       OR current_setting('transaction_read_only') <> 'off'
       OR pg_catalog.pg_is_in_recovery()
    THEN
        RAISE EXCEPTION 'durable audit runtime session is unsafe' USING ERRCODE = '55000';
    END IF;
    IF NOT relay_state_private.capability_valid_v1() THEN
        RAISE EXCEPTION 'durable audit capability unavailable' USING ERRCODE = '55000';
    END IF;
    IF p_stream_kind IS NULL OR p_operation_id IS NULL OR p_phase IS NULL
       OR p_payload_digest IS NULL OR p_candidate_generation IS NULL
       OR p_envelope_id IS NULL OR p_timestamp_unix_ms IS NULL
       OR p_record_json IS NULL OR p_envelope_json IS NULL OR p_record_hash IS NULL
       OR p_expected_chain_key_epoch_id IS NULL OR p_expected_keyring_lock_key IS NULL
       OR p_stream_kind NOT IN (
           'consultation', 'materialization', 'denial',
           'startup_credential_probe', 'readiness_credential_probe'
       )
       OR p_operation_id !~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'
       OR p_envelope_id !~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'
       OR octet_length(p_payload_digest) <> 32
       OR octet_length(p_record_hash) <> 32
       OR p_candidate_generation < 0
       OR (p_candidate_predecessor_hash IS NOT NULL
           AND octet_length(p_candidate_predecessor_hash) <> 32)
       OR octet_length(p_record_json) > 1048576
       OR octet_length(p_envelope_json) > 1310720
       OR NOT (
           (p_stream_kind = 'denial' AND p_phase = 'denial_decision')
           OR (p_stream_kind <> 'denial' AND p_phase IN ('attempt', 'completion'))
       )
    THEN
        RAISE EXCEPTION 'invalid durable audit request' USING ERRCODE = '22023';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM relay_state_private.state_plane_metadata AS metadata
        WHERE metadata.singleton = true
          AND metadata.chain_key_epoch_id = p_expected_chain_key_epoch_id
          AND metadata.audit_pseudonym_keyring_lock_key = p_expected_keyring_lock_key
    ) THEN
        RAISE EXCEPTION 'durable audit deployment authority drifted'
            USING ERRCODE = '55000';
    END IF;
    IF p_stream_kind = 'consultation' AND NOT EXISTS (
        SELECT 1
        FROM relay_state_private.consultation_audit_context AS context
        WHERE context.backend_pid = pg_catalog.pg_backend_pid()
          AND context.transaction_id = pg_catalog.txid_current()
          AND context.operation_id = p_operation_id
          AND context.purpose = 'attempt_cas'
          AND p_phase = 'attempt'
    ) THEN
        RAISE EXCEPTION 'consultation audit CAS requires atomic intent context'
            USING ERRCODE = '42501';
    END IF;
    v_pseudonym_fields_present := pg_catalog.num_nonnulls(
        p_pseudonym_key_id,
        p_pseudonym_generation,
        p_pseudonym_metadata_digest
    );
    IF v_pseudonym_fields_present NOT IN (0, 3)
       OR (p_stream_kind = 'consultation' AND v_pseudonym_fields_present <> 3)
       OR (v_pseudonym_fields_present = 3
           AND p_stream_kind NOT IN ('consultation', 'denial'))
       OR (v_pseudonym_fields_present = 3
           AND (
               p_pseudonym_key_id !~ '^[a-z0-9][a-z0-9._-]{0,63}$'
               OR octet_length(p_pseudonym_key_id) NOT BETWEEN 1 AND 64
               OR p_pseudonym_generation NOT BETWEEN 1 AND 9007199254740991
               OR octet_length(p_pseudonym_metadata_digest) <> 32
           ))
    THEN
        RAISE EXCEPTION 'durable audit pseudonym authority is invalid'
            USING ERRCODE = '22023';
    END IF;

    SELECT phase_row.* INTO v_existing
    FROM relay_state_private.audit_phase AS phase_row
    WHERE phase_row.stream_kind = p_stream_kind
      AND phase_row.operation_id = p_operation_id
      AND phase_row.phase = p_phase;
    IF FOUND THEN
        IF v_existing.payload_digest IS DISTINCT FROM p_payload_digest THEN
            IF clock_timestamp() - v_started_at > interval '5 seconds' THEN
                RAISE EXCEPTION 'durable audit CAS exceeded its deadline'
                    USING ERRCODE = '57014';
            END IF;
            RETURN QUERY SELECT
                'conflicting_duplicate'::text, v_existing.envelope_id,
                v_existing.record_hash;
            RETURN;
        END IF;
        v_existing_record := v_existing.record_json::jsonb;
        v_existing_pseudonym_payload_present :=
            v_existing_record @? '$.**.commitment_key_id'
            OR v_existing_record @? '$.**.subject_handle'
            OR v_existing_record @? '$.**.input_commitment'
            OR v_existing_record @? '$.**.predicate_commitment'
            OR v_existing_record @? '$.**.consent_evidence_commitment';
        IF (p_stream_kind = 'denial' AND v_existing_pseudonym_payload_present
            AND v_pseudonym_fields_present <> 3)
           OR (v_pseudonym_fields_present = 3
               AND v_existing_record #>> '{payload,commitment_key_id}'
                    IS DISTINCT FROM p_pseudonym_key_id)
        THEN
            RAISE EXCEPTION 'durable audit pseudonym authority is invalid'
                USING ERRCODE = '22023';
        END IF;
        IF clock_timestamp() - v_started_at > interval '5 seconds' THEN
            RAISE EXCEPTION 'durable audit CAS exceeded its deadline'
                USING ERRCODE = '57014';
        END IF;
        RETURN QUERY SELECT
            'identical_duplicate'::text,
            v_existing.envelope_id, v_existing.record_hash;
        RETURN;
    END IF;

    v_record := p_record_json::jsonb;
    v_envelope := p_envelope_json::jsonb;
    v_expected_digest := 'sha256:' || encode(p_payload_digest, 'hex');
    IF jsonb_typeof(v_record) IS DISTINCT FROM 'object'
       OR v_record - ARRAY[
           'schema', 'stream_kind', 'operation_id', 'phase',
           'payload_digest', 'payload'
       ]::text[] <> '{}'::jsonb
       OR v_record ->> 'schema' IS DISTINCT FROM 'registry.durable-audit/v1'
       OR v_record ->> 'stream_kind' IS DISTINCT FROM p_stream_kind
       OR v_record ->> 'operation_id' IS DISTINCT FROM p_operation_id
       OR v_record ->> 'phase' IS DISTINCT FROM p_phase
       OR v_record ->> 'payload_digest' IS DISTINCT FROM v_expected_digest
       OR jsonb_typeof(v_record -> 'payload') IS DISTINCT FROM 'object'
       OR jsonb_typeof(v_envelope) IS DISTINCT FROM 'object'
       OR v_envelope - ARRAY[
           'envelope_id', 'timestamp_unix_ms', 'prev_hash', 'record', 'record_hash'
       ]::text[] <> '{}'::jsonb
       OR v_envelope ->> 'envelope_id' IS DISTINCT FROM p_envelope_id
       OR (v_envelope ->> 'timestamp_unix_ms')::bigint IS DISTINCT FROM p_timestamp_unix_ms
       OR v_envelope -> 'record' IS DISTINCT FROM v_record
       OR v_envelope ->> 'record_hash' IS DISTINCT FROM encode(p_record_hash, 'hex')
       OR (p_candidate_predecessor_hash IS NULL
           AND v_envelope -> 'prev_hash' IS DISTINCT FROM 'null'::jsonb)
       OR (p_candidate_predecessor_hash IS NOT NULL
           AND v_envelope ->> 'prev_hash'
               IS DISTINCT FROM encode(p_candidate_predecessor_hash, 'hex'))
    THEN
        RAISE EXCEPTION 'durable audit envelope is inconsistent' USING ERRCODE = '22023';
    END IF;
    IF p_phase = 'completion' THEN
        IF p_attempt_envelope_id IS NULL OR p_attempt_record_hash IS NULL
           OR octet_length(p_attempt_record_hash) <> 32
           OR v_record #>> '{payload,attempt_event,envelope_id}'
                IS DISTINCT FROM p_attempt_envelope_id
           OR v_record #>> '{payload,attempt_event,chain_hash}'
                IS DISTINCT FROM 'registry-audit-chain-v1:'
                    || encode(p_attempt_record_hash, 'hex')
        THEN
            RAISE EXCEPTION 'durable audit completion reference invalid'
                USING ERRCODE = '22023';
        END IF;
    ELSIF p_attempt_envelope_id IS NOT NULL OR p_attempt_record_hash IS NOT NULL THEN
        RAISE EXCEPTION 'durable audit envelope is inconsistent' USING ERRCODE = '22023';
    END IF;

    v_pseudonym_payload_present :=
        v_record @? '$.**.commitment_key_id'
        OR v_record @? '$.**.subject_handle'
        OR v_record @? '$.**.input_commitment'
        OR v_record @? '$.**.predicate_commitment'
        OR v_record @? '$.**.consent_evidence_commitment';
    IF (p_stream_kind = 'denial' AND v_pseudonym_payload_present
        AND v_pseudonym_fields_present <> 3)
       OR (v_pseudonym_fields_present = 3
           AND v_record #>> '{payload,commitment_key_id}'
                IS DISTINCT FROM p_pseudonym_key_id)
    THEN
        RAISE EXCEPTION 'durable audit pseudonym authority is invalid'
            USING ERRCODE = '22023';
    END IF;
    IF v_pseudonym_fields_present = 3 THEN
        PERFORM pg_catalog.pg_advisory_xact_lock_shared(p_expected_keyring_lock_key);
        IF NOT EXISTS (
            SELECT 1
            FROM relay_state_private.state_plane_metadata AS metadata
            WHERE metadata.singleton = true
              AND metadata.chain_key_epoch_id = p_expected_chain_key_epoch_id
              AND metadata.audit_pseudonym_keyring_lock_key = p_expected_keyring_lock_key
        ) THEN
            RAISE EXCEPTION 'durable audit deployment authority drifted'
                USING ERRCODE = '55000';
        END IF;
        SELECT row.* INTO v_keyring
        FROM relay_state_private.audit_pseudonym_keyring AS row
        WHERE row.singleton = true;
        v_keyring_now_unix_us := pg_catalog.floor(
            extract(epoch FROM clock_timestamp()) * 1000000
        );
        IF NOT FOUND
           OR v_keyring.active_key_id IS DISTINCT FROM p_pseudonym_key_id
           OR v_keyring.generation IS DISTINCT FROM p_pseudonym_generation
           OR v_keyring.metadata_digest IS DISTINCT FROM p_pseudonym_metadata_digest
           OR v_keyring_now_unix_us
                < v_keyring.active_since_unix_ms::numeric * 1000
           OR v_keyring_now_unix_us
                >= v_keyring.active_write_deadline_unix_ms::numeric * 1000
           OR EXISTS (
               SELECT 1
               FROM pg_catalog.unnest(
                   v_keyring.retained_destroy_after_unix_ms
               ) AS deadline(value)
               WHERE deadline.value::numeric * 1000 <= v_keyring_now_unix_us
           )
        THEN
            RAISE EXCEPTION 'durable audit pseudonym authority is stale'
                USING ERRCODE = '55000';
        END IF;
    END IF;

    UPDATE relay_state_private.audit_chain_head AS head
    SET generation = head.generation + 1,
        record_hash = p_record_hash,
        advanced_at = clock_timestamp()
    WHERE head.singleton = true
      AND head.generation = p_candidate_generation
      AND head.record_hash IS NOT DISTINCT FROM p_candidate_predecessor_hash;
    IF NOT FOUND THEN
        SELECT phase_row.* INTO v_existing
        FROM relay_state_private.audit_phase AS phase_row
        WHERE phase_row.stream_kind = p_stream_kind
          AND phase_row.operation_id = p_operation_id
          AND phase_row.phase = p_phase;
        IF FOUND THEN
            IF clock_timestamp() - v_started_at > interval '5 seconds' THEN
                RAISE EXCEPTION 'durable audit CAS exceeded its deadline'
                    USING ERRCODE = '57014';
            END IF;
            RETURN QUERY SELECT
                CASE WHEN v_existing.payload_digest = p_payload_digest
                    THEN 'identical_duplicate'::text ELSE 'conflicting_duplicate'::text END,
                v_existing.envelope_id, v_existing.record_hash;
        ELSE
            IF clock_timestamp() - v_started_at > interval '5 seconds' THEN
                RAISE EXCEPTION 'durable audit CAS exceeded its deadline'
                    USING ERRCODE = '57014';
            END IF;
            RETURN QUERY SELECT 'head_changed'::text, NULL::text, NULL::bytea;
        END IF;
        RETURN;
    END IF;

    INSERT INTO relay_state_private.audit_phase (
        stream_kind, operation_id, phase, payload_digest, envelope_id,
        timestamp_unix_ms, predecessor_hash, record_json, envelope_json,
        record_hash, attempt_stream_kind, attempt_operation_id, attempt_phase,
        attempt_envelope_id, attempt_record_hash
    ) VALUES (
        p_stream_kind, p_operation_id, p_phase, p_payload_digest, p_envelope_id,
        p_timestamp_unix_ms, p_candidate_predecessor_hash, p_record_json,
        p_envelope_json, p_record_hash,
        CASE WHEN p_phase = 'completion' THEN p_stream_kind ELSE NULL END,
        CASE WHEN p_phase = 'completion' THEN p_operation_id ELSE NULL END,
        CASE WHEN p_phase = 'completion' THEN 'attempt' ELSE NULL END,
        p_attempt_envelope_id, p_attempt_record_hash
    );
    GET DIAGNOSTICS v_inserted_rows = ROW_COUNT;
    IF v_inserted_rows <> 1 THEN
        RAISE EXCEPTION 'durable audit insert did not store exactly one row'
            USING ERRCODE = '55000';
    END IF;
    IF clock_timestamp() - v_started_at > interval '5 seconds' THEN
        RAISE EXCEPTION 'durable audit CAS exceeded its deadline'
            USING ERRCODE = '57014';
    END IF;
    RETURN QUERY SELECT 'inserted'::text, p_envelope_id, p_record_hash;
END;
$function$;

CREATE OR REPLACE FUNCTION relay_state_api.consultation_attempt_intent_snapshot_v1(
    p_operation_id text,
    p_payload_digest bytea,
    p_completion_seed_canonical text,
    p_completion_seed_digest bytea,
    p_pseudonym_bundle_canonical text,
    p_pseudonym_bundle_digest bytea,
    p_pseudonym_key_id text,
    p_pseudonym_generation bigint,
    p_pseudonym_metadata_digest bytea,
    p_fence_lock_key bigint,
    p_holder_id text,
    p_fence_generation bigint,
    p_budget_ms integer,
    p_decision_expires_at_unix_ms bigint,
    p_permit_kinds text[],
    p_permit_ordinals smallint[],
    p_expected_chain_key_epoch_id text,
    p_expected_keyring_lock_key bigint
)
RETURNS TABLE (
    outcome text,
    stored_envelope_id text,
    stored_chain_hash bytea,
    candidate_predecessor_hash bytea,
    candidate_generation bigint,
    deadline_unix_ms bigint,
    stored_permit_kinds text[],
    stored_permit_ordinals smallint[]
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, relay_state_private
SET lock_timeout = '2s'
SET statement_timeout = '5s'
SET idle_in_transaction_session_timeout = '5s'
SET synchronous_commit = 'on'
AS $function$
DECLARE
    v_audit record;
    v_intent relay_state_private.consultation_completion_intent%ROWTYPE;
    v_existing_record jsonb;
    v_stored_kinds text[];
    v_stored_ordinals smallint[];
BEGIN
    PERFORM set_config('lock_timeout', '2s', false);
    PERFORM set_config('statement_timeout', '5s', false);
    PERFORM set_config('idle_in_transaction_session_timeout', '5s', false);
    PERFORM set_config('synchronous_commit', 'on', false);
    IF NOT relay_state_private.consultation_completion_seed_valid_v1(
           p_completion_seed_canonical
       )
       OR p_completion_seed_digest IS NULL
       OR p_completion_seed_digest IS DISTINCT FROM pg_catalog.sha256(
           pg_catalog.convert_to(p_completion_seed_canonical, 'UTF8')
       )
       OR p_pseudonym_bundle_canonical IS NULL
       OR p_pseudonym_bundle_digest IS NULL
       OR p_pseudonym_bundle_digest IS DISTINCT FROM pg_catalog.sha256(
           pg_catalog.convert_to(p_pseudonym_bundle_canonical, 'UTF8')
       )
       OR p_pseudonym_bundle_canonical::jsonb - ARRAY[
           'commitment_key_id', 'subject_handle', 'input_commitment',
           'predicate_commitment', 'consent_evidence_commitment'
       ]::text[] <> '{}'::jsonb
       OR p_pseudonym_bundle_canonical::jsonb ->> 'commitment_key_id'
            IS DISTINCT FROM p_pseudonym_key_id
       OR jsonb_typeof(p_pseudonym_bundle_canonical::jsonb -> 'subject_handle') <> 'string'
       OR jsonb_typeof(p_pseudonym_bundle_canonical::jsonb -> 'input_commitment') <> 'string'
       OR jsonb_typeof(p_pseudonym_bundle_canonical::jsonb -> 'predicate_commitment') <> 'string'
       OR jsonb_typeof(p_pseudonym_bundle_canonical::jsonb -> 'consent_evidence_commitment')
            NOT IN ('string', 'null')
       OR p_budget_ms NOT BETWEEN 1 AND 20000
       OR p_decision_expires_at_unix_ms IS NULL
       OR p_decision_expires_at_unix_ms NOT BETWEEN 0 AND 9007199254740991
       OR (p_completion_seed_canonical::jsonb #>> '{bounds,timeout_ms}')::integer
            IS DISTINCT FROM p_budget_ms
       OR p_permit_kinds IS NULL OR p_permit_ordinals IS NULL
       OR cardinality(p_permit_kinds) <> cardinality(p_permit_ordinals)
       OR cardinality(p_permit_kinds) > 6
       OR COALESCE(array_ndims(p_permit_kinds), 1) <> 1
       OR COALESCE(array_ndims(p_permit_ordinals), 1) <> 1
       OR EXISTS (
           SELECT 1
           FROM unnest(p_permit_kinds, p_permit_ordinals)
                AS permit(kind, ordinal)
           WHERE NOT (
               (permit.kind = 'credential' AND permit.ordinal = 0)
               OR (permit.kind = 'data' AND permit.ordinal BETWEEN 0 AND 4)
           )
       )
       OR (SELECT count(*) FROM unnest(p_permit_kinds, p_permit_ordinals)
               AS permit(kind, ordinal)) <>
          (SELECT count(*) FROM (
               SELECT DISTINCT permit.kind, permit.ordinal
               FROM unnest(p_permit_kinds, p_permit_ordinals)
                    AS permit(kind, ordinal)
           ) AS distinct_permit)
       OR COALESCE((
           SELECT pg_catalog.array_agg(permit.ordinal ORDER BY permit.ordinal)
           FROM unnest(p_permit_kinds, p_permit_ordinals)
                AS permit(kind, ordinal)
           WHERE permit.kind = 'data'
       ), ARRAY[]::smallint[]) IS DISTINCT FROM COALESCE((
           SELECT pg_catalog.array_agg(value::smallint ORDER BY value)
           FROM pg_catalog.generate_series(
               0,
               (SELECT count(*)::integer - 1
                FROM pg_catalog.unnest(p_permit_kinds) AS kind(value)
                WHERE kind.value = 'data')
           ) AS value
       ), ARRAY[]::smallint[])
       OR p_permit_kinds IS DISTINCT FROM COALESCE((
           SELECT pg_catalog.array_agg(
               permit.kind ORDER BY CASE permit.kind WHEN 'credential' THEN 0 ELSE 1 END,
                                    permit.ordinal
           )
           FROM unnest(p_permit_kinds, p_permit_ordinals)
                AS permit(kind, ordinal)
       ), ARRAY[]::text[])
       OR p_permit_ordinals IS DISTINCT FROM COALESCE((
           SELECT pg_catalog.array_agg(
               permit.ordinal ORDER BY CASE permit.kind WHEN 'credential' THEN 0 ELSE 1 END,
                                       permit.ordinal
           )
           FROM unnest(p_permit_kinds, p_permit_ordinals)
                AS permit(kind, ordinal)
       ), ARRAY[]::smallint[])
       OR p_permit_kinds IS DISTINCT FROM COALESCE((
           SELECT pg_catalog.array_agg(binding.value ->> 'kind' ORDER BY binding.ordinal)
           FROM pg_catalog.jsonb_array_elements(
               p_completion_seed_canonical::jsonb #> '{dispatch,permit_bindings}'
           ) WITH ORDINALITY AS binding(value, ordinal)
       ), ARRAY[]::text[])
       OR p_permit_ordinals IS DISTINCT FROM COALESCE((
           SELECT pg_catalog.array_agg(
               (binding.value ->> 'ordinal')::smallint ORDER BY binding.ordinal
           )
           FROM pg_catalog.jsonb_array_elements(
               p_completion_seed_canonical::jsonb #> '{dispatch,permit_bindings}'
           ) WITH ORDINALITY AS binding(value, ordinal)
       ), ARRAY[]::smallint[])
       OR (p_completion_seed_canonical::jsonb #>> '{bounds,credential_exchanges}')::integer
            <> (SELECT count(*) FROM pg_catalog.unnest(p_permit_kinds) AS kind(value)
                WHERE kind.value = 'credential')
       OR (p_completion_seed_canonical::jsonb #>> '{bounds,data_exchanges}')::integer
            <> (SELECT count(*) FROM pg_catalog.unnest(p_permit_kinds) AS kind(value)
                WHERE kind.value = 'data')
    THEN
        RAISE EXCEPTION 'invalid consultation completion intent request'
            USING ERRCODE = '22023';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM relay_state_private.serving_fence_state AS fence
        JOIN relay_state_private.state_plane_metadata AS metadata
          ON metadata.singleton = true
        WHERE fence.singleton = true
          AND fence.generation = p_fence_generation
          AND fence.holder_id = p_holder_id
          AND fence.admission_open AND NOT fence.takeover_pending
          AND metadata.serving_fence_lock_key = p_fence_lock_key
          AND EXISTS (
              SELECT 1 FROM pg_catalog.pg_locks AS lock_row
              WHERE lock_row.locktype = 'advisory'
                AND lock_row.pid = fence.holder_backend_pid
                AND lock_row.database = (
                    SELECT database_row.oid FROM pg_catalog.pg_database AS database_row
                    WHERE database_row.datname = current_database()
                )
                AND lock_row.classid::bigint = ((p_fence_lock_key >> 32) & 4294967295)
                AND lock_row.objid::bigint = (p_fence_lock_key & 4294967295)
                AND lock_row.objsubid = 1 AND lock_row.granted
          )
    ) THEN
        RETURN QUERY SELECT 'ownership_lost'::text, NULL::text, NULL::bytea,
            NULL::bytea, NULL::bigint, NULL::bigint, NULL::text[], NULL::smallint[];
        RETURN;
    END IF;
    IF floor(extract(epoch FROM clock_timestamp()) * 1000)::bigint
           >= p_decision_expires_at_unix_ms
       AND NOT EXISTS (
           SELECT 1
           FROM relay_state_private.consultation_completion_intent AS intent
           WHERE intent.operation_id = p_operation_id
       )
    THEN
        RETURN QUERY SELECT 'decision_expired'::text, NULL::text, NULL::bytea,
            NULL::bytea, NULL::bigint, NULL::bigint, NULL::text[], NULL::smallint[];
        RETURN;
    END IF;
    INSERT INTO relay_state_private.consultation_audit_context (
        backend_pid, transaction_id, operation_id, purpose
    ) VALUES (
        pg_catalog.pg_backend_pid(), pg_catalog.txid_current(),
        p_operation_id, 'attempt_snapshot'
    );
    SELECT * INTO STRICT v_audit
    FROM relay_state_api.audit_phase_snapshot_v1(
        'consultation', p_operation_id, 'attempt', p_payload_digest,
        p_expected_chain_key_epoch_id, p_pseudonym_key_id,
        p_pseudonym_generation, p_pseudonym_metadata_digest,
        p_expected_keyring_lock_key
    );
    DELETE FROM relay_state_private.consultation_audit_context AS context
    WHERE context.backend_pid = pg_catalog.pg_backend_pid()
      AND context.transaction_id = pg_catalog.txid_current()
      AND context.operation_id = p_operation_id
      AND context.purpose = 'attempt_snapshot';
    IF v_audit.outcome = 'candidate' THEN
        RETURN QUERY SELECT 'candidate'::text, NULL::text, NULL::bytea,
            v_audit.candidate_predecessor_hash, v_audit.candidate_generation,
            NULL::bigint, p_permit_kinds, p_permit_ordinals;
        RETURN;
    ELSIF v_audit.outcome = 'conflicting_duplicate' THEN
        RETURN QUERY SELECT 'conflicting_duplicate'::text,
            v_audit.stored_envelope_id, v_audit.stored_chain_hash,
            NULL::bytea, NULL::bigint, NULL::bigint, NULL::text[], NULL::smallint[];
        RETURN;
    ELSIF v_audit.outcome <> 'identical_duplicate' THEN
        RAISE EXCEPTION 'consultation attempt snapshot protocol drifted'
            USING ERRCODE = '55000';
    END IF;
    SELECT intent.* INTO v_intent
    FROM relay_state_private.consultation_completion_intent AS intent
    WHERE intent.operation_id = p_operation_id;
    SELECT COALESCE(pg_catalog.array_agg(
               permit.kind ORDER BY CASE permit.kind WHEN 'credential' THEN 0 ELSE 1 END,
                                    permit.ordinal
           ), ARRAY[]::text[]),
           COALESCE(pg_catalog.array_agg(
               permit.ordinal ORDER BY CASE permit.kind WHEN 'credential' THEN 0 ELSE 1 END,
                                       permit.ordinal
           ), ARRAY[]::smallint[])
    INTO v_stored_kinds, v_stored_ordinals
    FROM relay_state_private.dispatch_permit AS permit
    WHERE permit.operation_id = p_operation_id;
    SELECT phase_row.record_json::jsonb INTO v_existing_record
    FROM relay_state_private.audit_phase AS phase_row
    WHERE phase_row.stream_kind = 'consultation'
      AND phase_row.operation_id = p_operation_id
      AND phase_row.phase = 'attempt';
    IF NOT FOUND OR v_intent.operation_id IS NULL THEN
        RAISE EXCEPTION 'consultation attempt is missing its atomic intent'
            USING ERRCODE = '55000';
    END IF;
    IF v_intent.attempt_envelope_id = v_audit.stored_envelope_id
       AND v_intent.attempt_record_hash = v_audit.stored_chain_hash
       AND v_intent.attempt_payload_digest = p_payload_digest
       AND v_intent.fence_generation = p_fence_generation
       AND v_intent.holder_id = p_holder_id
       AND v_intent.budget_ms = p_budget_ms
       AND v_intent.decision_expires_at_unix_ms = p_decision_expires_at_unix_ms
       AND v_intent.credential_permit_count = (
           SELECT count(*) FROM pg_catalog.unnest(p_permit_kinds) AS kind(value)
           WHERE kind.value = 'credential'
       )
       AND v_intent.data_permit_count = (
           SELECT count(*) FROM pg_catalog.unnest(p_permit_kinds) AS kind(value)
           WHERE kind.value = 'data'
       )
       AND v_intent.completion_seed_canonical = p_completion_seed_canonical
       AND v_intent.completion_seed_digest = p_completion_seed_digest
       AND v_intent.pseudonym_key_id = p_pseudonym_key_id
       AND v_intent.pseudonym_bundle_canonical = p_pseudonym_bundle_canonical
       AND v_intent.pseudonym_bundle_digest = p_pseudonym_bundle_digest
       AND v_stored_kinds = p_permit_kinds
       AND v_stored_ordinals = p_permit_ordinals
       AND v_existing_record #> '{payload,completion_seed}'
            = p_completion_seed_canonical::jsonb
       AND v_existing_record #>> '{payload,commitment_key_id}' = p_pseudonym_key_id
    THEN
        RETURN QUERY SELECT 'identical_duplicate'::text,
            v_audit.stored_envelope_id, v_audit.stored_chain_hash,
            NULL::bytea, NULL::bigint,
            floor(extract(epoch FROM v_intent.total_deadline_at) * 1000)::bigint,
            v_stored_kinds, v_stored_ordinals;
    ELSE
        RETURN QUERY SELECT 'conflicting_duplicate'::text,
            v_audit.stored_envelope_id, v_audit.stored_chain_hash,
            NULL::bytea, NULL::bigint,
            floor(extract(epoch FROM v_intent.total_deadline_at) * 1000)::bigint,
            v_stored_kinds, v_stored_ordinals;
    END IF;
END;
$function$;

CREATE OR REPLACE FUNCTION relay_state_api.consultation_attempt_intent_cas_v1(
    p_operation_id text,
    p_payload_digest bytea,
    p_candidate_generation bigint,
    p_candidate_predecessor_hash bytea,
    p_envelope_id text,
    p_timestamp_unix_ms bigint,
    p_record_json text,
    p_envelope_json text,
    p_record_hash bytea,
    p_completion_seed_canonical text,
    p_completion_seed_digest bytea,
    p_pseudonym_bundle_canonical text,
    p_pseudonym_bundle_digest bytea,
    p_pseudonym_key_id text,
    p_pseudonym_generation bigint,
    p_pseudonym_metadata_digest bytea,
    p_fence_lock_key bigint,
    p_holder_id text,
    p_fence_generation bigint,
    p_budget_ms integer,
    p_decision_expires_at_unix_ms bigint,
    p_permit_kinds text[],
    p_permit_ordinals smallint[],
    p_expected_chain_key_epoch_id text,
    p_expected_keyring_lock_key bigint
)
RETURNS TABLE (
    outcome text,
    stored_envelope_id text,
    stored_chain_hash bytea,
    deadline_unix_ms bigint,
    stored_permit_kinds text[],
    stored_permit_ordinals smallint[]
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, relay_state_private
SET lock_timeout = '2s'
SET statement_timeout = '5s'
SET idle_in_transaction_session_timeout = '5s'
SET synchronous_commit = 'on'
AS $function$
DECLARE
    v_snapshot record;
    v_audit record;
    v_record jsonb := p_record_json::jsonb;
    v_now timestamptz := clock_timestamp();
    v_deadline timestamptz;
BEGIN
    -- The serving-fence row is the root of the consultation mutation lock
    -- order. Holding SHARE from before authority validation through commit
    -- prevents a successor generation from scanning before this intent is
    -- durable. KEY SHARE would not conflict with the fence's non-key UPDATE.
    PERFORM fence.singleton
    FROM relay_state_private.serving_fence_state AS fence
    WHERE fence.singleton = true
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'serving fence state is unavailable' USING ERRCODE = '55000';
    END IF;
    -- Reuse the exact replay, authority, fence, seed, bundle, and permit-set
    -- validation before touching the chain head.
    SELECT * INTO STRICT v_snapshot
    FROM relay_state_api.consultation_attempt_intent_snapshot_v1(
        p_operation_id, p_payload_digest,
        p_completion_seed_canonical, p_completion_seed_digest,
        p_pseudonym_bundle_canonical, p_pseudonym_bundle_digest,
        p_pseudonym_key_id, p_pseudonym_generation,
        p_pseudonym_metadata_digest, p_fence_lock_key, p_holder_id,
        p_fence_generation, p_budget_ms, p_decision_expires_at_unix_ms, p_permit_kinds,
        p_permit_ordinals, p_expected_chain_key_epoch_id,
        p_expected_keyring_lock_key
    );
    IF v_snapshot.outcome <> 'candidate' THEN
        RETURN QUERY SELECT v_snapshot.outcome, v_snapshot.stored_envelope_id,
            v_snapshot.stored_chain_hash, v_snapshot.deadline_unix_ms,
            v_snapshot.stored_permit_kinds, v_snapshot.stored_permit_ordinals;
        RETURN;
    END IF;
    IF v_snapshot.candidate_generation IS DISTINCT FROM p_candidate_generation
       OR v_snapshot.candidate_predecessor_hash
            IS DISTINCT FROM p_candidate_predecessor_hash
    THEN
        RETURN QUERY SELECT 'head_changed'::text, NULL::text, NULL::bytea,
            NULL::bigint, p_permit_kinds, p_permit_ordinals;
        RETURN;
    END IF;
    -- Serialize behind the exact audit head before the final expiry check.
    -- Otherwise a caller could pass the check and then wait on the head until
    -- after its authorization decision expired before mutating it.
    PERFORM head.singleton
    FROM relay_state_private.audit_chain_head AS head
    WHERE head.singleton = true
    FOR UPDATE;
    v_now := clock_timestamp();
    IF floor(extract(epoch FROM v_now) * 1000)::bigint
           >= p_decision_expires_at_unix_ms
    THEN
        RETURN QUERY SELECT 'decision_expired'::text, NULL::text, NULL::bytea,
            NULL::bigint, p_permit_kinds, p_permit_ordinals;
        RETURN;
    END IF;
    IF v_record #> '{payload,completion_seed}'
            IS DISTINCT FROM p_completion_seed_canonical::jsonb
       OR v_record #>> '{payload,commitment_key_id}'
            IS DISTINCT FROM p_pseudonym_key_id
       OR v_record #>> '{payload,subject_handle}'
            IS DISTINCT FROM p_pseudonym_bundle_canonical::jsonb ->> 'subject_handle'
       OR v_record #>> '{payload,input_commitment}'
            IS DISTINCT FROM p_pseudonym_bundle_canonical::jsonb ->> 'input_commitment'
       OR v_record #>> '{payload,predicate_commitment}'
            IS DISTINCT FROM p_pseudonym_bundle_canonical::jsonb ->> 'predicate_commitment'
       OR v_record #> '{payload,consent_evidence_commitment}'
            IS DISTINCT FROM p_pseudonym_bundle_canonical::jsonb
                -> 'consent_evidence_commitment'
    THEN
        RAISE EXCEPTION 'consultation attempt does not contain its sealed completion seed'
            USING ERRCODE = '22023';
    END IF;
    INSERT INTO relay_state_private.consultation_audit_context (
        backend_pid, transaction_id, operation_id, purpose
    ) VALUES (
        pg_catalog.pg_backend_pid(), pg_catalog.txid_current(),
        p_operation_id, 'attempt_cas'
    );
    SELECT * INTO STRICT v_audit
    FROM relay_state_api.audit_phase_cas_v1(
        'consultation', p_operation_id, 'attempt', p_payload_digest,
        p_candidate_generation, p_candidate_predecessor_hash, p_envelope_id,
        p_timestamp_unix_ms, p_record_json, p_envelope_json, p_record_hash,
        NULL, NULL, p_pseudonym_key_id, p_pseudonym_generation,
        p_pseudonym_metadata_digest, p_expected_chain_key_epoch_id,
        p_expected_keyring_lock_key
    );
    DELETE FROM relay_state_private.consultation_audit_context AS context
    WHERE context.backend_pid = pg_catalog.pg_backend_pid()
      AND context.transaction_id = pg_catalog.txid_current()
      AND context.operation_id = p_operation_id
      AND context.purpose = 'attempt_cas';
    IF v_audit.outcome <> 'inserted' THEN
        RETURN QUERY SELECT v_audit.outcome, v_audit.stored_envelope_id,
            v_audit.stored_chain_hash, NULL::bigint,
            p_permit_kinds, p_permit_ordinals;
        RETURN;
    END IF;
    v_deadline := v_now + p_budget_ms * interval '1 millisecond';
    INSERT INTO relay_state_private.consultation_completion_intent (
        operation_id, attempt_envelope_id, attempt_record_hash,
        attempt_payload_digest, fence_generation, holder_id, budget_ms,
        decision_expires_at_unix_ms,
        credential_permit_count, data_permit_count,
        created_at, total_deadline_at, completion_seed_schema,
        completion_seed_canonical, completion_seed_digest, pseudonym_key_id,
        pseudonym_bundle_canonical, pseudonym_bundle_digest
    ) VALUES (
        p_operation_id, p_envelope_id, p_record_hash, p_payload_digest,
        p_fence_generation, p_holder_id, p_budget_ms,
        p_decision_expires_at_unix_ms,
        (SELECT count(*) FROM pg_catalog.unnest(p_permit_kinds) AS kind(value)
         WHERE kind.value = 'credential'),
        (SELECT count(*) FROM pg_catalog.unnest(p_permit_kinds) AS kind(value)
         WHERE kind.value = 'data'),
        v_now, v_deadline,
        'registry.relay.consultation-completion-seed/v1',
        p_completion_seed_canonical, p_completion_seed_digest,
        p_pseudonym_key_id, p_pseudonym_bundle_canonical,
        p_pseudonym_bundle_digest
    );
    INSERT INTO relay_state_private.dispatch_permit (
        operation_id, kind, ordinal, fence_generation, holder_id, deadline_at
    )
    SELECT p_operation_id, permit.kind, permit.ordinal,
           p_fence_generation, p_holder_id, v_deadline
    FROM unnest(p_permit_kinds, p_permit_ordinals)
         AS permit(kind, ordinal);
    IF (SELECT count(*) FROM relay_state_private.dispatch_permit AS permit
        WHERE permit.operation_id = p_operation_id) <> cardinality(p_permit_kinds)
    THEN
        RAISE EXCEPTION 'consultation permit set was not inserted exactly'
            USING ERRCODE = '55000';
    END IF;
    RETURN QUERY SELECT 'inserted'::text, p_envelope_id, p_record_hash,
        floor(extract(epoch FROM v_deadline) * 1000)::bigint,
        p_permit_kinds, p_permit_ordinals;
END;
$function$;

CREATE OR REPLACE FUNCTION relay_state_private.consultation_completion_snapshot_internal_v1(
    p_operation_id text,
    p_required_state text,
    p_expected_deadline_unix_ms bigint,
    p_expected_permit_kinds text[],
    p_expected_permit_ordinals smallint[]
)
RETURNS TABLE (
    outcome text,
    intent_state text,
    attempt_envelope_id text,
    attempt_record_hash bytea,
    completion_seed_canonical text,
    completion_seed_digest bytea,
    pseudonym_key_id text,
    pseudonym_bundle_canonical text,
    pseudonym_bundle_digest bytea,
    deadline_unix_ms bigint,
    permit_kinds text[],
    permit_ordinals smallint[],
    permit_source_operation_ids text[],
    permit_dispatched_at_unix_us bigint[],
    dispatched_credential_count bigint,
    dispatched_data_count bigint,
    candidate_predecessor_hash bytea,
    candidate_generation bigint,
    stored_completion_envelope_id text,
    stored_completion_chain_hash bytea,
    stored_completion_payload_digest bytea
)
LANGUAGE plpgsql
SET search_path = pg_catalog, relay_state_private
SET lock_timeout = '2s'
SET statement_timeout = '5s'
SET idle_in_transaction_session_timeout = '5s'
SET synchronous_commit = 'on'
AS $function$
DECLARE
    v_intent relay_state_private.consultation_completion_intent%ROWTYPE;
    v_kinds text[];
    v_ordinals smallint[];
    v_source_operation_ids text[];
    v_dispatched_at_unix_us bigint[];
    v_credential_count bigint;
    v_data_count bigint;
    v_stored_digest bytea;
BEGIN
    SELECT intent.* INTO v_intent
    FROM relay_state_private.consultation_completion_intent AS intent
    WHERE intent.operation_id = p_operation_id;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'unknown'::text, NULL::text, NULL::text, NULL::bytea,
            NULL::text, NULL::bytea, NULL::text, NULL::text, NULL::bytea,
            NULL::bigint, NULL::text[], NULL::smallint[], NULL::text[], NULL::bigint[],
            NULL::bigint, NULL::bigint, NULL::bytea, NULL::bigint,
            NULL::text, NULL::bytea, NULL::bytea;
        RETURN;
    END IF;
    SELECT COALESCE(pg_catalog.array_agg(
               permit.kind ORDER BY CASE permit.kind WHEN 'credential' THEN 0 ELSE 1 END,
                                    permit.ordinal
           ), ARRAY[]::text[]),
           COALESCE(pg_catalog.array_agg(
               permit.ordinal ORDER BY CASE permit.kind WHEN 'credential' THEN 0 ELSE 1 END,
                                       permit.ordinal
           ), ARRAY[]::smallint[]),
           COALESCE(pg_catalog.array_agg(
               permit.source_operation_id
               ORDER BY CASE permit.kind WHEN 'credential' THEN 0 ELSE 1 END,
                        permit.ordinal
           ), ARRAY[]::text[]),
           COALESCE(pg_catalog.array_agg(
               CASE WHEN permit.dispatched_at IS NULL THEN NULL::bigint
                    ELSE floor(extract(epoch FROM permit.dispatched_at) * 1000000)::bigint
               END
               ORDER BY CASE permit.kind WHEN 'credential' THEN 0 ELSE 1 END,
                        permit.ordinal
           ), ARRAY[]::bigint[]),
           count(*) FILTER (
               WHERE permit.kind = 'credential' AND permit.dispatched_at IS NOT NULL
           ),
           count(*) FILTER (
               WHERE permit.kind = 'data' AND permit.dispatched_at IS NOT NULL
           )
    INTO v_kinds, v_ordinals, v_source_operation_ids, v_dispatched_at_unix_us,
         v_credential_count, v_data_count
    FROM relay_state_private.dispatch_permit AS permit
    WHERE permit.operation_id = p_operation_id;
    IF p_expected_deadline_unix_ms IS NOT NULL AND (
           floor(extract(epoch FROM v_intent.total_deadline_at) * 1000)::bigint
               <> p_expected_deadline_unix_ms
           OR v_kinds IS DISTINCT FROM p_expected_permit_kinds
           OR v_ordinals IS DISTINCT FROM p_expected_permit_ordinals
       )
    THEN
        outcome := 'permit_mismatch';
    ELSIF v_intent.credential_permit_count <> (
              SELECT count(*) FROM pg_catalog.unnest(v_kinds) AS kind(value)
              WHERE kind.value = 'credential'
          )
          OR v_intent.data_permit_count <> (
              SELECT count(*) FROM pg_catalog.unnest(v_kinds) AS kind(value)
              WHERE kind.value = 'data'
          )
          OR EXISTS (
              SELECT 1
              FROM relay_state_private.dispatch_permit AS dispatched
              WHERE dispatched.operation_id = p_operation_id
                AND dispatched.kind = 'data'
                AND dispatched.dispatched_at IS NOT NULL
                AND EXISTS (
                    SELECT 1
                    FROM relay_state_private.dispatch_permit AS prior
                    WHERE prior.operation_id = dispatched.operation_id
                      AND prior.kind = 'data'
                      AND prior.ordinal < dispatched.ordinal
                      AND prior.dispatched_at IS NULL
                )
          )
          OR (
              v_intent.completion_seed_canonical::jsonb #>> '{dispatch,plan_kind}'
                  = 'bounded_http'
              AND EXISTS (
                  SELECT 1
                  FROM relay_state_private.dispatch_permit AS dispatched
                  WHERE dispatched.operation_id = p_operation_id
                    AND dispatched.kind = 'data'
                    AND dispatched.dispatched_at IS NOT NULL
                  GROUP BY dispatched.source_operation_id
                  HAVING count(*) > 1
              )
          )
    THEN
        RAISE EXCEPTION 'consultation permit manifest is incomplete or out of order'
            USING ERRCODE = '55000';
    ELSIF v_intent.state = 'completed' THEN
        SELECT phase_row.payload_digest INTO v_stored_digest
        FROM relay_state_private.audit_phase AS phase_row
        WHERE phase_row.stream_kind = 'consultation'
          AND phase_row.operation_id = p_operation_id
          AND phase_row.phase = 'completion'
          AND phase_row.envelope_id = v_intent.completion_envelope_id
          AND phase_row.record_hash = v_intent.completion_record_hash;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'completed consultation intent lost its completion audit'
                USING ERRCODE = '55000';
        END IF;
        outcome := 'completed';
    ELSIF v_intent.state <> p_required_state THEN
        outcome := 'state_conflict';
    ELSE
        outcome := 'candidate';
    END IF;
    RETURN QUERY SELECT outcome, v_intent.state, v_intent.attempt_envelope_id,
        v_intent.attempt_record_hash, v_intent.completion_seed_canonical,
        v_intent.completion_seed_digest, v_intent.pseudonym_key_id,
        v_intent.pseudonym_bundle_canonical, v_intent.pseudonym_bundle_digest,
        floor(extract(epoch FROM v_intent.total_deadline_at) * 1000)::bigint,
        v_kinds, v_ordinals, v_source_operation_ids, v_dispatched_at_unix_us,
        v_credential_count, v_data_count,
        CASE WHEN outcome = 'candidate' THEN head.record_hash ELSE NULL END,
        CASE WHEN outcome = 'candidate' THEN head.generation ELSE NULL END,
        v_intent.completion_envelope_id, v_intent.completion_record_hash,
        v_stored_digest
    FROM relay_state_private.audit_chain_head AS head
    WHERE head.singleton = true;
END;
$function$;

CREATE OR REPLACE FUNCTION relay_state_api.consultation_completion_snapshot_normal_v1(
    p_operation_id text,
    p_fence_lock_key bigint,
    p_holder_id text,
    p_fence_generation bigint,
    p_expected_deadline_unix_ms bigint,
    p_expected_permit_kinds text[],
    p_expected_permit_ordinals smallint[],
    p_current_pseudonym_key_id text,
    p_current_pseudonym_generation bigint,
    p_current_pseudonym_metadata_digest bytea,
    p_expected_chain_key_epoch_id text,
    p_expected_keyring_lock_key bigint
)
RETURNS TABLE (
    outcome text, intent_state text, attempt_envelope_id text,
    attempt_record_hash bytea, completion_seed_canonical text,
    completion_seed_digest bytea, pseudonym_key_id text,
    pseudonym_bundle_canonical text, pseudonym_bundle_digest bytea,
    deadline_unix_ms bigint, permit_kinds text[], permit_ordinals smallint[],
    permit_source_operation_ids text[],
    permit_dispatched_at_unix_us bigint[],
    dispatched_credential_count bigint, dispatched_data_count bigint,
    candidate_predecessor_hash bytea, candidate_generation bigint,
    stored_completion_envelope_id text, stored_completion_chain_hash bytea,
    stored_completion_payload_digest bytea
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, relay_state_private
SET lock_timeout = '2s'
SET statement_timeout = '5s'
SET idle_in_transaction_session_timeout = '5s'
SET synchronous_commit = 'on'
AS $function$
DECLARE
    v_runtime_oid oid;
    v_session_oid oid;
    v_intent_state text;
    v_keyring relay_state_private.audit_pseudonym_keyring%ROWTYPE;
    v_now_unix_us numeric;
BEGIN
    PERFORM set_config('lock_timeout', '2s', false);
    PERFORM set_config('statement_timeout', '5s', false);
    PERFORM set_config('idle_in_transaction_session_timeout', '5s', false);
    PERFORM set_config('synchronous_commit', 'on', false);
    SELECT metadata.runtime_role_oid INTO v_runtime_oid
    FROM relay_state_private.state_plane_metadata AS metadata
    WHERE metadata.singleton = true;
    SELECT oid INTO v_session_oid FROM pg_catalog.pg_roles WHERE rolname = session_user;
    IF v_session_oid IS DISTINCT FROM v_runtime_oid
       OR NOT relay_state_private.capability_valid_v1()
       OR NOT EXISTS (
           SELECT 1 FROM relay_state_private.state_plane_metadata AS metadata
           WHERE metadata.singleton = true
             AND metadata.chain_key_epoch_id = p_expected_chain_key_epoch_id
             AND metadata.audit_pseudonym_keyring_lock_key = p_expected_keyring_lock_key
       )
    THEN
        RAISE EXCEPTION 'normal consultation completion caller is unavailable'
            USING ERRCODE = '55000';
    END IF;
    SELECT intent.state INTO v_intent_state
    FROM relay_state_private.consultation_completion_intent AS intent
    WHERE intent.operation_id = p_operation_id;
    IF v_intent_state IS DISTINCT FROM 'completed' THEN
        IF NOT EXISTS (
            SELECT 1
            FROM relay_state_private.serving_fence_state AS fence
            JOIN relay_state_private.state_plane_metadata AS metadata
              ON metadata.singleton = true
            WHERE fence.singleton = true
              AND fence.generation = p_fence_generation
              AND fence.holder_id = p_holder_id
              AND fence.admission_open AND NOT fence.takeover_pending
              AND metadata.serving_fence_lock_key = p_fence_lock_key
              AND EXISTS (
                  SELECT 1 FROM pg_catalog.pg_locks AS lock_row
                  WHERE lock_row.locktype = 'advisory'
                    AND lock_row.pid = fence.holder_backend_pid
                    AND lock_row.database = (
                        SELECT database_row.oid FROM pg_catalog.pg_database AS database_row
                        WHERE database_row.datname = current_database()
                    )
                    AND lock_row.classid::bigint = ((p_fence_lock_key >> 32) & 4294967295)
                    AND lock_row.objid::bigint = (p_fence_lock_key & 4294967295)
                    AND lock_row.objsubid = 1 AND lock_row.granted
              )
        ) THEN
            RETURN QUERY SELECT 'ownership_lost'::text, NULL::text, NULL::text,
                NULL::bytea, NULL::text, NULL::bytea, NULL::text, NULL::text,
                NULL::bytea, NULL::bigint, NULL::text[], NULL::smallint[], NULL::text[],
                NULL::bigint[], NULL::bigint, NULL::bigint, NULL::bytea, NULL::bigint,
                NULL::text, NULL::bytea, NULL::bytea;
            RETURN;
        END IF;
        PERFORM pg_catalog.pg_advisory_xact_lock_shared(p_expected_keyring_lock_key);
        SELECT keyring.* INTO v_keyring
        FROM relay_state_private.audit_pseudonym_keyring AS keyring
        WHERE keyring.singleton = true;
        v_now_unix_us := floor(extract(epoch FROM clock_timestamp()) * 1000000);
        IF NOT FOUND
           OR v_keyring.active_key_id IS DISTINCT FROM p_current_pseudonym_key_id
           OR v_keyring.generation IS DISTINCT FROM p_current_pseudonym_generation
           OR v_keyring.metadata_digest IS DISTINCT FROM p_current_pseudonym_metadata_digest
           OR v_now_unix_us < v_keyring.active_since_unix_ms::numeric * 1000
           OR v_now_unix_us >= v_keyring.active_write_deadline_unix_ms::numeric * 1000
        THEN
            RETURN QUERY SELECT 'pseudonym_authority_stale'::text,
                NULL::text, NULL::text, NULL::bytea, NULL::text, NULL::bytea,
                NULL::text, NULL::text, NULL::bytea, NULL::bigint,
                NULL::text[], NULL::smallint[], NULL::text[], NULL::bigint[],
                NULL::bigint, NULL::bigint, NULL::bytea, NULL::bigint,
                NULL::text, NULL::bytea, NULL::bytea;
            RETURN;
        END IF;
    END IF;
    RETURN QUERY SELECT *
    FROM relay_state_private.consultation_completion_snapshot_internal_v1(
        p_operation_id, 'open', p_expected_deadline_unix_ms,
        p_expected_permit_kinds, p_expected_permit_ordinals
    );
END;
$function$;

CREATE OR REPLACE FUNCTION relay_state_api.consultation_completion_snapshot_recovery_v1(
    p_operation_id text,
    p_fence_lock_key bigint,
    p_holder_id text,
    p_fence_generation bigint,
    p_expected_chain_key_epoch_id text,
    p_expected_keyring_lock_key bigint
)
RETURNS TABLE (
    outcome text, intent_state text, attempt_envelope_id text,
    attempt_record_hash bytea, completion_seed_canonical text,
    completion_seed_digest bytea, pseudonym_key_id text,
    pseudonym_bundle_canonical text, pseudonym_bundle_digest bytea,
    deadline_unix_ms bigint, permit_kinds text[], permit_ordinals smallint[],
    permit_source_operation_ids text[],
    permit_dispatched_at_unix_us bigint[],
    dispatched_credential_count bigint, dispatched_data_count bigint,
    candidate_predecessor_hash bytea, candidate_generation bigint,
    stored_completion_envelope_id text, stored_completion_chain_hash bytea,
    stored_completion_payload_digest bytea
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, relay_state_private
SET lock_timeout = '2s'
SET statement_timeout = '5s'
SET idle_in_transaction_session_timeout = '5s'
SET synchronous_commit = 'on'
AS $function$
DECLARE
    v_runtime_oid oid;
    v_session_oid oid;
BEGIN
    PERFORM set_config('lock_timeout', '2s', false);
    PERFORM set_config('statement_timeout', '5s', false);
    PERFORM set_config('idle_in_transaction_session_timeout', '5s', false);
    PERFORM set_config('synchronous_commit', 'on', false);
    SELECT metadata.runtime_role_oid INTO v_runtime_oid
    FROM relay_state_private.state_plane_metadata AS metadata
    WHERE metadata.singleton = true;
    SELECT oid INTO v_session_oid FROM pg_catalog.pg_roles WHERE rolname = session_user;
    IF v_session_oid IS DISTINCT FROM v_runtime_oid
       OR NOT relay_state_private.capability_valid_v1()
       OR NOT EXISTS (
           SELECT 1 FROM relay_state_private.state_plane_metadata AS metadata
           WHERE metadata.singleton = true
             AND metadata.chain_key_epoch_id = p_expected_chain_key_epoch_id
             AND metadata.audit_pseudonym_keyring_lock_key = p_expected_keyring_lock_key
       )
    THEN
        RAISE EXCEPTION 'consultation recovery caller is unavailable'
            USING ERRCODE = '55000';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM relay_state_private.serving_fence_state AS fence
        JOIN relay_state_private.state_plane_metadata AS metadata
          ON metadata.singleton = true
        JOIN relay_state_private.consultation_completion_intent AS intent
          ON intent.operation_id = p_operation_id
        WHERE fence.singleton = true
          AND fence.generation = p_fence_generation
          AND fence.holder_id = p_holder_id
          AND fence.takeover_pending AND NOT fence.admission_open
          AND intent.fence_generation < p_fence_generation
          AND intent.state IN ('recovery_ready', 'completed')
          AND metadata.serving_fence_lock_key = p_fence_lock_key
          AND EXISTS (
              SELECT 1 FROM pg_catalog.pg_locks AS lock_row
              WHERE lock_row.locktype = 'advisory'
                AND lock_row.pid = fence.holder_backend_pid
                AND lock_row.database = (
                    SELECT database_row.oid FROM pg_catalog.pg_database AS database_row
                    WHERE database_row.datname = current_database()
                )
                AND lock_row.classid::bigint = ((p_fence_lock_key >> 32) & 4294967295)
                AND lock_row.objid::bigint = (p_fence_lock_key & 4294967295)
                AND lock_row.objsubid = 1 AND lock_row.granted
          )
    ) THEN
        RETURN QUERY SELECT 'ownership_lost'::text, NULL::text, NULL::text,
            NULL::bytea, NULL::text, NULL::bytea, NULL::text, NULL::text,
            NULL::bytea, NULL::bigint, NULL::text[], NULL::smallint[], NULL::text[],
            NULL::bigint[], NULL::bigint, NULL::bigint, NULL::bytea, NULL::bigint,
            NULL::text, NULL::bytea, NULL::bytea;
        RETURN;
    END IF;
    RETURN QUERY SELECT *
    FROM relay_state_private.consultation_completion_snapshot_internal_v1(
        p_operation_id, 'recovery_ready', NULL, NULL, NULL
    );
END;
$function$;

CREATE OR REPLACE FUNCTION relay_state_private.consultation_completion_cas_internal_v1(
    p_operation_id text,
    p_required_state text,
    p_completion_class text,
    p_recovery_generation bigint,
    p_expected_deadline_unix_ms bigint,
    p_expected_permit_kinds text[],
    p_expected_permit_ordinals smallint[],
    p_payload_digest bytea,
    p_candidate_generation bigint,
    p_candidate_predecessor_hash bytea,
    p_envelope_id text,
    p_timestamp_unix_ms bigint,
    p_record_json text,
    p_envelope_json text,
    p_record_hash bytea,
    p_expected_chain_key_epoch_id text
)
RETURNS TABLE (
    outcome text,
    stored_envelope_id text,
    stored_chain_hash bytea,
    completion_outcome text
)
LANGUAGE plpgsql
SET search_path = pg_catalog, relay_state_private
SET lock_timeout = '2s'
SET statement_timeout = '5s'
SET idle_in_transaction_session_timeout = '5s'
SET synchronous_commit = 'on'
AS $function$
DECLARE
    v_intent relay_state_private.consultation_completion_intent%ROWTYPE;
    v_existing relay_state_private.audit_phase%ROWTYPE;
    v_record jsonb := p_record_json::jsonb;
    v_envelope jsonb := p_envelope_json::jsonb;
    v_payload jsonb;
    v_facts jsonb;
    v_execution_result jsonb;
    v_provenance jsonb;
    v_seed jsonb;
    v_bundle jsonb;
    v_kinds text[];
    v_ordinals smallint[];
    v_dispatched_credentials bigint;
    v_dispatched_data bigint;
    v_expected_permit_evidence jsonb;
    v_expected_actual_path jsonb;
    v_expected_outcome text;
    v_now timestamptz := clock_timestamp();
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM relay_state_private.state_plane_metadata AS metadata
        WHERE metadata.singleton = true
          AND metadata.chain_key_epoch_id = p_expected_chain_key_epoch_id
    ) THEN
        RAISE EXCEPTION 'consultation completion chain authority drifted'
            USING ERRCODE = '55000';
    END IF;
    SELECT intent.* INTO v_intent
    FROM relay_state_private.consultation_completion_intent AS intent
    WHERE intent.operation_id = p_operation_id
    FOR UPDATE;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'unknown'::text, NULL::text, NULL::bytea, NULL::text;
        RETURN;
    END IF;
    IF v_intent.state = 'completed' THEN
        SELECT phase_row.* INTO v_existing
        FROM relay_state_private.audit_phase AS phase_row
        WHERE phase_row.stream_kind = 'consultation'
          AND phase_row.operation_id = p_operation_id
          AND phase_row.phase = 'completion';
        IF NOT FOUND
           OR v_existing.envelope_id IS DISTINCT FROM v_intent.completion_envelope_id
           OR v_existing.record_hash IS DISTINCT FROM v_intent.completion_record_hash
        THEN
            RAISE EXCEPTION 'completed consultation intent is corrupt'
                USING ERRCODE = '55000';
        END IF;
        RETURN QUERY SELECT
            CASE WHEN v_existing.payload_digest = p_payload_digest
                 THEN 'identical_duplicate'::text
                 ELSE 'conflicting_duplicate'::text END,
            v_existing.envelope_id, v_existing.record_hash,
            v_existing.record_json::jsonb #>> '{payload,outcome}';
        RETURN;
    END IF;
    IF v_intent.state <> p_required_state THEN
        RETURN QUERY SELECT 'state_conflict'::text, NULL::text, NULL::bytea, NULL::text;
        RETURN;
    END IF;
    IF p_required_state = 'recovery_ready' THEN
        IF p_recovery_generation IS NULL
           OR p_recovery_generation <= v_intent.fence_generation
           OR p_completion_class <> 'recovery'
        THEN
            RAISE EXCEPTION 'consultation recovery generation is stale'
                USING ERRCODE = '22023';
        END IF;
    ELSIF p_required_state <> 'open'
          OR p_recovery_generation IS NOT NULL
          OR p_completion_class NOT IN ('known', 'unfinished')
    THEN
        RAISE EXCEPTION 'consultation completion mode is invalid'
            USING ERRCODE = '22023';
    END IF;
    PERFORM permit.operation_id
    FROM relay_state_private.dispatch_permit AS permit
    WHERE permit.operation_id = p_operation_id
    ORDER BY CASE permit.kind WHEN 'credential' THEN 0 ELSE 1 END,
             permit.ordinal
    FOR UPDATE;
    SELECT COALESCE(pg_catalog.array_agg(
               permit.kind ORDER BY CASE permit.kind WHEN 'credential' THEN 0 ELSE 1 END,
                                    permit.ordinal
           ), ARRAY[]::text[]),
           COALESCE(pg_catalog.array_agg(
               permit.ordinal ORDER BY CASE permit.kind WHEN 'credential' THEN 0 ELSE 1 END,
                                       permit.ordinal
           ), ARRAY[]::smallint[]),
           count(*) FILTER (
               WHERE permit.kind = 'credential' AND permit.dispatched_at IS NOT NULL
           ),
           count(*) FILTER (
               WHERE permit.kind = 'data' AND permit.dispatched_at IS NOT NULL
           ),
           COALESCE(pg_catalog.jsonb_agg(
               pg_catalog.jsonb_build_object(
                   'kind', permit.kind,
                   'ordinal', permit.ordinal,
                   'operation_id', permit.source_operation_id,
                   'dispatched_at_unix_us', CASE
                       WHEN permit.dispatched_at IS NULL THEN NULL::bigint
                       ELSE floor(extract(epoch FROM permit.dispatched_at) * 1000000)::bigint
                   END
               ) ORDER BY CASE permit.kind WHEN 'credential' THEN 0 ELSE 1 END,
                          permit.ordinal
           ), '[]'::jsonb),
           COALESCE(pg_catalog.jsonb_agg(
               pg_catalog.jsonb_build_object(
                   'kind', permit.kind, 'ordinal', permit.ordinal,
                   'operation_id', permit.source_operation_id
               ) ORDER BY CASE permit.kind WHEN 'credential' THEN 0 ELSE 1 END,
                          permit.ordinal
           ) FILTER (WHERE permit.dispatched_at IS NOT NULL), '[]'::jsonb)
    INTO v_kinds, v_ordinals, v_dispatched_credentials, v_dispatched_data,
         v_expected_permit_evidence, v_expected_actual_path
    FROM relay_state_private.dispatch_permit AS permit
    WHERE permit.operation_id = p_operation_id;
    IF v_intent.credential_permit_count <> (
           SELECT count(*) FROM pg_catalog.unnest(v_kinds) AS kind(value)
           WHERE kind.value = 'credential'
       )
       OR v_intent.data_permit_count <> (
           SELECT count(*) FROM pg_catalog.unnest(v_kinds) AS kind(value)
           WHERE kind.value = 'data'
       )
       OR (p_expected_deadline_unix_ms IS NOT NULL AND
           floor(extract(epoch FROM v_intent.total_deadline_at) * 1000)::bigint
               <> p_expected_deadline_unix_ms)
       OR (p_expected_permit_kinds IS NOT NULL
           AND v_kinds IS DISTINCT FROM p_expected_permit_kinds)
       OR (p_expected_permit_ordinals IS NOT NULL
           AND v_ordinals IS DISTINCT FROM p_expected_permit_ordinals)
       OR EXISTS (
           SELECT 1
           FROM relay_state_private.dispatch_permit AS permit
           WHERE permit.operation_id = p_operation_id
             AND permit.source_operation_id IS NOT NULL
             AND NOT EXISTS (
                 SELECT 1
                 FROM pg_catalog.jsonb_array_elements(
                     v_intent.completion_seed_canonical::jsonb
                         #> '{dispatch,permit_bindings}'
                 ) AS binding(value)
                 WHERE binding.value ->> 'kind' = permit.kind
                   AND (binding.value ->> 'ordinal')::smallint = permit.ordinal
                   AND binding.value -> 'allowed_operation_ids'
                        ? permit.source_operation_id
             )
       )
    THEN
        RETURN QUERY SELECT 'permit_mismatch'::text, NULL::text, NULL::bytea, NULL::text;
        RETURN;
    END IF;
    v_expected_outcome := CASE
        WHEN p_completion_class = 'known' THEN 'known_complete'
        WHEN v_dispatched_credentials + v_dispatched_data = 0 THEN 'not_started'
        ELSE 'outcome_unknown'
    END;
    v_payload := v_record -> 'payload';
    v_bundle := v_intent.pseudonym_bundle_canonical::jsonb;
    v_seed := v_intent.completion_seed_canonical::jsonb;
    IF jsonb_typeof(v_record) IS DISTINCT FROM 'object'
       OR v_record - ARRAY[
           'schema', 'stream_kind', 'operation_id', 'phase',
           'payload_digest', 'payload'
       ]::text[] <> '{}'::jsonb
       OR v_record ->> 'schema' IS DISTINCT FROM 'registry.durable-audit/v1'
       OR v_record ->> 'stream_kind' IS DISTINCT FROM 'consultation'
       OR v_record ->> 'operation_id' IS DISTINCT FROM p_operation_id
       OR v_record ->> 'phase' IS DISTINCT FROM 'completion'
       OR v_record ->> 'payload_digest'
            IS DISTINCT FROM 'sha256:' || encode(p_payload_digest, 'hex')
       OR jsonb_typeof(v_payload) IS DISTINCT FROM 'object'
       OR v_payload - ARRAY[
           'attempt_event', 'completion_seed', 'commitment_key_id',
           'subject_handle', 'input_commitment', 'predicate_commitment',
           'consent_evidence_commitment', 'outcome', 'permit_evidence',
           'completion_facts'
       ]::text[] <> '{}'::jsonb
       OR v_payload #>> '{attempt_event,envelope_id}'
            IS DISTINCT FROM v_intent.attempt_envelope_id
       OR v_payload #>> '{attempt_event,chain_hash}'
            IS DISTINCT FROM 'registry-audit-chain-v1:'
                || encode(v_intent.attempt_record_hash, 'hex')
       OR v_payload -> 'completion_seed'
            IS DISTINCT FROM v_intent.completion_seed_canonical::jsonb
       OR v_payload ->> 'commitment_key_id' IS DISTINCT FROM v_intent.pseudonym_key_id
       OR v_payload ->> 'subject_handle' IS DISTINCT FROM v_bundle ->> 'subject_handle'
       OR v_payload ->> 'input_commitment' IS DISTINCT FROM v_bundle ->> 'input_commitment'
       OR v_payload ->> 'predicate_commitment'
            IS DISTINCT FROM v_bundle ->> 'predicate_commitment'
       OR v_payload -> 'consent_evidence_commitment'
            IS DISTINCT FROM v_bundle -> 'consent_evidence_commitment'
       OR v_payload ->> 'outcome' IS DISTINCT FROM v_expected_outcome
       OR v_payload -> 'permit_evidence' IS DISTINCT FROM v_expected_permit_evidence
       OR jsonb_typeof(v_envelope) IS DISTINCT FROM 'object'
       OR v_envelope - ARRAY[
           'envelope_id', 'timestamp_unix_ms', 'prev_hash', 'record', 'record_hash'
       ]::text[] <> '{}'::jsonb
       OR v_envelope ->> 'envelope_id' IS DISTINCT FROM p_envelope_id
       OR (v_envelope ->> 'timestamp_unix_ms')::bigint IS DISTINCT FROM p_timestamp_unix_ms
       OR v_envelope -> 'record' IS DISTINCT FROM v_record
       OR v_envelope ->> 'record_hash' IS DISTINCT FROM encode(p_record_hash, 'hex')
       OR (p_candidate_predecessor_hash IS NULL
           AND v_envelope -> 'prev_hash' IS DISTINCT FROM 'null'::jsonb)
       OR (p_candidate_predecessor_hash IS NOT NULL
           AND v_envelope ->> 'prev_hash'
               IS DISTINCT FROM encode(p_candidate_predecessor_hash, 'hex'))
    THEN
        RAISE EXCEPTION 'consultation completion payload is inconsistent'
            USING ERRCODE = '22023';
    END IF;
    v_facts := v_payload -> 'completion_facts';
    v_execution_result := v_facts -> 'execution_result';
    v_provenance := v_facts -> 'provenance';
    IF p_completion_class = 'known' THEN
        IF jsonb_typeof(v_facts) IS DISTINCT FROM 'object'
           OR v_facts - ARRAY[
               'schema', 'execution_result', 'provenance',
               'actual_credential_exchanges', 'actual_data_exchanges', 'actual_path'
           ]::text[] <> '{}'::jsonb
           OR v_facts ->> 'schema'
                IS DISTINCT FROM 'registry.relay.consultation-completion-facts/v1'
           OR (v_facts ->> 'actual_credential_exchanges')::bigint
                IS DISTINCT FROM v_dispatched_credentials
           OR (v_facts ->> 'actual_data_exchanges')::bigint
                IS DISTINCT FROM v_dispatched_data
           OR v_facts -> 'actual_path' IS DISTINCT FROM v_expected_actual_path
           OR jsonb_typeof(v_execution_result) IS DISTINCT FROM 'object'
           OR v_execution_result ->> 'class'
                NOT IN ('public_success', 'known_failure')
        THEN
            RAISE EXCEPTION 'known consultation completion facts are inconsistent'
                USING ERRCODE = '22023';
        END IF;
        IF v_execution_result ->> 'class' = 'public_success' THEN
            IF relay_state_private.jsonb_object_key_count_v1(v_execution_result) <> 2
               OR v_execution_result - ARRAY['class', 'outcome']::text[] <> '{}'::jsonb
               OR jsonb_typeof(v_execution_result -> 'outcome') <> 'string'
               OR NOT (
                   v_seed #> '{acquisition,public_outcomes}'
                       ? (v_execution_result ->> 'outcome')
               )
               OR jsonb_typeof(v_provenance) IS DISTINCT FROM 'object'
               OR relay_state_private.jsonb_object_key_count_v1(v_provenance) <> 5
               OR v_provenance - ARRAY[
                   'relay_acquired_at_unix_ms', 'source_observed_at_unix_ms',
                   'source_revision', 'snapshot_generation',
                   'snapshot_published_at_unix_ms'
               ]::text[] <> '{}'::jsonb
               OR jsonb_typeof(v_provenance -> 'relay_acquired_at_unix_ms') <> 'number'
               OR (v_provenance ->> 'relay_acquired_at_unix_ms')::numeric <>
                    trunc((v_provenance ->> 'relay_acquired_at_unix_ms')::numeric)
               OR (v_provenance ->> 'relay_acquired_at_unix_ms')::numeric
                    NOT BETWEEN 0 AND 9007199254740991
               OR v_provenance -> 'source_observed_at_unix_ms'
                    IS DISTINCT FROM 'null'::jsonb
               OR v_provenance -> 'source_revision'
                    IS DISTINCT FROM 'null'::jsonb
               OR (
                   v_seed #>> '{acquisition,class}' = 'materialized_snapshot'
                   AND (
                       jsonb_typeof(v_provenance -> 'snapshot_generation') <> 'string'
                       OR v_provenance ->> 'snapshot_generation'
                            !~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'
                       OR jsonb_typeof(v_provenance -> 'snapshot_published_at_unix_ms')
                            <> 'number'
                       OR (v_provenance ->> 'snapshot_published_at_unix_ms')::numeric <>
                            trunc((v_provenance ->> 'snapshot_published_at_unix_ms')::numeric)
                       OR (v_provenance ->> 'snapshot_published_at_unix_ms')::numeric
                            NOT BETWEEN 0 AND 9007199254740991
                       OR (v_provenance ->> 'snapshot_published_at_unix_ms')::numeric
                            > (v_provenance ->> 'relay_acquired_at_unix_ms')::numeric
                   )
               )
               OR (
                   v_seed #>> '{acquisition,class}' <> 'materialized_snapshot'
                   AND (
                       v_provenance -> 'snapshot_generation' IS DISTINCT FROM 'null'::jsonb
                       OR v_provenance -> 'snapshot_published_at_unix_ms'
                            IS DISTINCT FROM 'null'::jsonb
                       OR v_dispatched_data = 0
                   )
               )
            THEN
                RAISE EXCEPTION 'public consultation completion facts are inconsistent'
                    USING ERRCODE = '22023';
            END IF;
        ELSE
            IF relay_state_private.jsonb_object_key_count_v1(v_execution_result) <> 2
               OR v_execution_result - ARRAY[
                   'class', 'failure_class'
               ]::text[] <> '{}'::jsonb
               OR v_execution_result ->> 'failure_class' NOT IN (
                   'credential_unavailable', 'source_unavailable',
                   'response_contract_violation', 'cardinality_violation'
               )
               OR v_provenance IS DISTINCT FROM 'null'::jsonb
               OR (
                   v_seed #>> '{acquisition,class}' <> 'materialized_snapshot'
                   AND v_dispatched_credentials + v_dispatched_data = 0
               )
            THEN
                RAISE EXCEPTION 'known consultation failure facts are inconsistent'
                    USING ERRCODE = '22023';
            END IF;
        END IF;
    ELSIF v_facts IS DISTINCT FROM 'null'::jsonb THEN
        RAISE EXCEPTION 'unfinished consultation completion cannot contain facts'
            USING ERRCODE = '22023';
    END IF;
    UPDATE relay_state_private.audit_chain_head AS head
    SET generation = head.generation + 1,
        record_hash = p_record_hash,
        advanced_at = v_now
    WHERE head.singleton = true
      AND head.generation = p_candidate_generation
      AND head.record_hash IS NOT DISTINCT FROM p_candidate_predecessor_hash;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'head_changed'::text, NULL::text, NULL::bytea,
            v_expected_outcome;
        RETURN;
    END IF;
    INSERT INTO relay_state_private.audit_phase (
        stream_kind, operation_id, phase, payload_digest, envelope_id,
        timestamp_unix_ms, predecessor_hash, record_json, envelope_json,
        record_hash, attempt_stream_kind, attempt_operation_id, attempt_phase,
        attempt_envelope_id, attempt_record_hash
    ) VALUES (
        'consultation', p_operation_id, 'completion', p_payload_digest,
        p_envelope_id, p_timestamp_unix_ms, p_candidate_predecessor_hash,
        p_record_json, p_envelope_json, p_record_hash,
        'consultation', p_operation_id, 'attempt',
        v_intent.attempt_envelope_id, v_intent.attempt_record_hash
    );
    UPDATE relay_state_private.dispatch_permit AS permit
    SET abandoned_at = CASE WHEN p_required_state = 'recovery_ready'
                            THEN v_now ELSE NULL END,
        completion_stream_kind = 'consultation',
        completion_operation_id = p_operation_id,
        completion_phase = 'completion',
        completion_envelope_id = p_envelope_id,
        completion_record_hash = p_record_hash
    WHERE permit.operation_id = p_operation_id
      AND permit.completion_envelope_id IS NULL;
    IF (SELECT count(*) FROM relay_state_private.dispatch_permit AS permit
        WHERE permit.operation_id = p_operation_id
          AND permit.completion_envelope_id = p_envelope_id
          AND permit.completion_record_hash = p_record_hash)
       <> v_intent.credential_permit_count + v_intent.data_permit_count
    THEN
        RAISE EXCEPTION 'consultation completion did not link its exact permit set'
            USING ERRCODE = '55000';
    END IF;
    UPDATE relay_state_private.consultation_completion_intent AS intent
    SET state = 'completed',
        completion_stream_kind = 'consultation',
        completion_operation_id = p_operation_id,
        completion_phase = 'completion',
        completion_envelope_id = p_envelope_id,
        completion_record_hash = p_record_hash,
        completed_at = v_now
    WHERE intent.operation_id = p_operation_id
      AND intent.state = p_required_state;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'consultation completion intent changed concurrently'
            USING ERRCODE = '55000';
    END IF;
    RETURN QUERY SELECT 'inserted'::text, p_envelope_id, p_record_hash,
        v_expected_outcome;
END;
$function$;

CREATE OR REPLACE FUNCTION relay_state_api.consultation_completion_cas_normal_v1(
    p_operation_id text,
    p_fence_lock_key bigint,
    p_holder_id text,
    p_fence_generation bigint,
    p_expected_deadline_unix_ms bigint,
    p_expected_permit_kinds text[],
    p_expected_permit_ordinals smallint[],
    p_current_pseudonym_key_id text,
    p_current_pseudonym_generation bigint,
    p_current_pseudonym_metadata_digest bytea,
    p_payload_digest bytea,
    p_candidate_generation bigint,
    p_candidate_predecessor_hash bytea,
    p_envelope_id text,
    p_timestamp_unix_ms bigint,
    p_record_json text,
    p_envelope_json text,
    p_record_hash bytea,
    p_expected_chain_key_epoch_id text,
    p_expected_keyring_lock_key bigint
)
RETURNS TABLE (
    outcome text, stored_envelope_id text,
    stored_chain_hash bytea, completion_outcome text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, relay_state_private
SET lock_timeout = '2s'
SET statement_timeout = '5s'
SET idle_in_transaction_session_timeout = '5s'
SET synchronous_commit = 'on'
AS $function$
DECLARE
    v_snapshot record;
BEGIN
    -- Lock order: fence row, keyring advisory transaction lock, intent,
    -- permits, audit head, then inserts.
    PERFORM fence.singleton
    FROM relay_state_private.serving_fence_state AS fence
    WHERE fence.singleton = true
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'serving fence state is unavailable' USING ERRCODE = '55000';
    END IF;
    SELECT * INTO STRICT v_snapshot
    FROM relay_state_api.consultation_completion_snapshot_normal_v1(
        p_operation_id, p_fence_lock_key, p_holder_id, p_fence_generation,
        p_expected_deadline_unix_ms, p_expected_permit_kinds,
        p_expected_permit_ordinals, p_current_pseudonym_key_id,
        p_current_pseudonym_generation, p_current_pseudonym_metadata_digest,
        p_expected_chain_key_epoch_id, p_expected_keyring_lock_key
    );
    IF v_snapshot.outcome NOT IN ('candidate', 'completed') THEN
        RETURN QUERY SELECT v_snapshot.outcome, NULL::text, NULL::bytea, NULL::text;
        RETURN;
    END IF;
    RETURN QUERY SELECT *
    FROM relay_state_private.consultation_completion_cas_internal_v1(
        p_operation_id, 'open', 'known', NULL, p_expected_deadline_unix_ms,
        p_expected_permit_kinds, p_expected_permit_ordinals,
        p_payload_digest, p_candidate_generation, p_candidate_predecessor_hash,
        p_envelope_id, p_timestamp_unix_ms, p_record_json, p_envelope_json,
        p_record_hash, p_expected_chain_key_epoch_id
    );
END;
$function$;

CREATE OR REPLACE FUNCTION relay_state_api.consultation_completion_cas_unfinished_v1(
    p_operation_id text,
    p_fence_lock_key bigint,
    p_holder_id text,
    p_fence_generation bigint,
    p_expected_deadline_unix_ms bigint,
    p_expected_permit_kinds text[],
    p_expected_permit_ordinals smallint[],
    p_current_pseudonym_key_id text,
    p_current_pseudonym_generation bigint,
    p_current_pseudonym_metadata_digest bytea,
    p_payload_digest bytea,
    p_candidate_generation bigint,
    p_candidate_predecessor_hash bytea,
    p_envelope_id text,
    p_timestamp_unix_ms bigint,
    p_record_json text,
    p_envelope_json text,
    p_record_hash bytea,
    p_expected_chain_key_epoch_id text,
    p_expected_keyring_lock_key bigint
)
RETURNS TABLE (
    outcome text, stored_envelope_id text,
    stored_chain_hash bytea, completion_outcome text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, relay_state_private
SET lock_timeout = '2s'
SET statement_timeout = '5s'
SET idle_in_transaction_session_timeout = '5s'
SET synchronous_commit = 'on'
AS $function$
DECLARE
    v_snapshot record;
BEGIN
    PERFORM fence.singleton
    FROM relay_state_private.serving_fence_state AS fence
    WHERE fence.singleton = true
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'serving fence state is unavailable' USING ERRCODE = '55000';
    END IF;
    SELECT * INTO STRICT v_snapshot
    FROM relay_state_api.consultation_completion_snapshot_normal_v1(
        p_operation_id, p_fence_lock_key, p_holder_id, p_fence_generation,
        p_expected_deadline_unix_ms, p_expected_permit_kinds,
        p_expected_permit_ordinals, p_current_pseudonym_key_id,
        p_current_pseudonym_generation, p_current_pseudonym_metadata_digest,
        p_expected_chain_key_epoch_id, p_expected_keyring_lock_key
    );
    IF v_snapshot.outcome NOT IN ('candidate', 'completed') THEN
        RETURN QUERY SELECT v_snapshot.outcome, NULL::text, NULL::bytea, NULL::text;
        RETURN;
    END IF;
    RETURN QUERY SELECT *
    FROM relay_state_private.consultation_completion_cas_internal_v1(
        p_operation_id, 'open', 'unfinished', NULL, p_expected_deadline_unix_ms,
        p_expected_permit_kinds, p_expected_permit_ordinals,
        p_payload_digest, p_candidate_generation, p_candidate_predecessor_hash,
        p_envelope_id, p_timestamp_unix_ms, p_record_json, p_envelope_json,
        p_record_hash, p_expected_chain_key_epoch_id
    );
END;
$function$;

CREATE OR REPLACE FUNCTION relay_state_api.consultation_completion_cas_recovery_v1(
    p_operation_id text,
    p_fence_lock_key bigint,
    p_holder_id text,
    p_fence_generation bigint,
    p_payload_digest bytea,
    p_candidate_generation bigint,
    p_candidate_predecessor_hash bytea,
    p_envelope_id text,
    p_timestamp_unix_ms bigint,
    p_record_json text,
    p_envelope_json text,
    p_record_hash bytea,
    p_expected_chain_key_epoch_id text,
    p_expected_keyring_lock_key bigint
)
RETURNS TABLE (
    outcome text, stored_envelope_id text,
    stored_chain_hash bytea, completion_outcome text
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, relay_state_private
SET lock_timeout = '2s'
SET statement_timeout = '5s'
SET idle_in_transaction_session_timeout = '5s'
SET synchronous_commit = 'on'
AS $function$
DECLARE
    v_snapshot record;
BEGIN
    PERFORM fence.singleton
    FROM relay_state_private.serving_fence_state AS fence
    WHERE fence.singleton = true
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'serving fence state is unavailable' USING ERRCODE = '55000';
    END IF;
    SELECT * INTO STRICT v_snapshot
    FROM relay_state_api.consultation_completion_snapshot_recovery_v1(
        p_operation_id, p_fence_lock_key, p_holder_id, p_fence_generation,
        p_expected_chain_key_epoch_id, p_expected_keyring_lock_key
    );
    IF v_snapshot.outcome NOT IN ('candidate', 'completed') THEN
        RETURN QUERY SELECT v_snapshot.outcome, NULL::text, NULL::bytea, NULL::text;
        RETURN;
    END IF;
    RETURN QUERY SELECT *
    FROM relay_state_private.consultation_completion_cas_internal_v1(
        p_operation_id, 'recovery_ready', 'recovery', p_fence_generation,
        NULL, NULL, NULL, p_payload_digest, p_candidate_generation,
        p_candidate_predecessor_hash, p_envelope_id, p_timestamp_unix_ms,
        p_record_json, p_envelope_json, p_record_hash,
        p_expected_chain_key_epoch_id
    );
END;
$function$;

CREATE OR REPLACE FUNCTION relay_state_api.audit_readiness_v1(
    p_expected_chain_key_epoch_id text
)
RETURNS TABLE (
    ready boolean,
    capability_id text,
    capability_fingerprint text,
    owner_role_oid bigint,
    runtime_role_oid bigint,
    audit_pseudonym_maintenance_role_oid bigint,
    audit_pseudonym_reader_role_oid bigint,
    chain_key_epoch_id text,
    quota_capability_id text,
    audit_pseudonym_keyring_capability_id text,
    audit_pseudonym_keyring_lock_key bigint
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, relay_state_private
SET lock_timeout = '2s'
SET statement_timeout = '5s'
SET idle_in_transaction_session_timeout = '5s'
SET synchronous_commit = 'on'
AS $function$
DECLARE
    v_started_at timestamptz := clock_timestamp();
    v_runtime_oid oid;
    v_session_oid oid;
BEGIN
    PERFORM set_config('lock_timeout', '2s', false);
    PERFORM set_config('statement_timeout', '5s', false);
    PERFORM set_config('idle_in_transaction_session_timeout', '5s', false);
    PERFORM set_config('synchronous_commit', 'on', false);
    SELECT metadata.runtime_role_oid INTO v_runtime_oid
    FROM relay_state_private.state_plane_metadata AS metadata
    WHERE metadata.singleton = true;
    SELECT oid INTO v_session_oid FROM pg_catalog.pg_roles WHERE rolname = session_user;
    IF v_session_oid IS DISTINCT FROM v_runtime_oid THEN
        RAISE EXCEPTION 'durable audit caller is not bound' USING ERRCODE = '42501';
    END IF;
    RETURN QUERY
    SELECT relay_state_private.capability_valid_v1()
           AND current_setting('search_path') = 'pg_catalog, relay_state_private'
           AND current_setting('lock_timeout') = '2s'
           AND current_setting('statement_timeout') = '5s'
           AND current_setting('idle_in_transaction_session_timeout') = '5s'
           AND current_setting('synchronous_commit') = 'on'
           AND current_setting('client_encoding') = 'UTF8'
           AND current_setting('standard_conforming_strings') = 'on'
           AND current_setting('session_replication_role') = 'origin'
           AND current_setting('default_transaction_isolation') = 'read committed'
           AND current_setting('transaction_isolation') = 'read committed'
           AND current_setting('default_transaction_read_only') = 'off'
           AND current_setting('transaction_read_only') = 'off'
           AND NOT pg_catalog.pg_is_in_recovery()
           AND metadata.chain_key_epoch_id = p_expected_chain_key_epoch_id
           AND EXISTS (
               SELECT 1 FROM relay_state_private.audit_chain_head AS head
               WHERE head.singleton = true AND head.generation >= 0
                 AND (head.record_hash IS NULL OR octet_length(head.record_hash) = 32)
           ),
           metadata.capability_id,
           metadata.capability_fingerprint,
           metadata.owner_role_oid::bigint,
           metadata.runtime_role_oid::bigint,
           metadata.audit_pseudonym_maintenance_role_oid::bigint,
           metadata.audit_pseudonym_reader_role_oid::bigint,
           metadata.chain_key_epoch_id,
           metadata.quota_capability_id,
           metadata.audit_pseudonym_keyring_capability_id,
           metadata.audit_pseudonym_keyring_lock_key
    FROM relay_state_private.state_plane_metadata AS metadata
    WHERE metadata.singleton = true;
    IF clock_timestamp() - v_started_at > interval '5 seconds' THEN
        RAISE EXCEPTION 'durable audit readiness exceeded its deadline'
            USING ERRCODE = '57014';
    END IF;
END;
$function$;

CREATE OR REPLACE FUNCTION relay_state_api.audit_pseudonym_keyring_readiness_v1(
    p_expected_chain_key_epoch_id text,
    p_expected_role_kind text
)
RETURNS TABLE (
    ready boolean,
    capability_id text,
    capability_fingerprint text,
    owner_role_oid bigint,
    caller_role_oid bigint,
    chain_key_epoch_id text,
    audit_pseudonym_keyring_capability_id text,
    audit_pseudonym_keyring_lock_key bigint
)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, relay_state_private
SET lock_timeout = '2s'
SET statement_timeout = '5s'
SET idle_in_transaction_session_timeout = '5s'
SET synchronous_commit = 'on'
AS $function$
DECLARE
    v_started_at timestamptz := clock_timestamp();
    v_session_oid oid;
    v_expected_oid oid;
BEGIN
    PERFORM set_config('lock_timeout', '2s', false);
    PERFORM set_config('statement_timeout', '5s', false);
    PERFORM set_config('idle_in_transaction_session_timeout', '5s', false);
    PERFORM set_config('synchronous_commit', 'on', false);
    SELECT oid INTO v_session_oid FROM pg_catalog.pg_roles WHERE rolname = session_user;
    SELECT CASE p_expected_role_kind
        WHEN 'runtime' THEN metadata.runtime_role_oid
        WHEN 'maintenance' THEN metadata.audit_pseudonym_maintenance_role_oid
        WHEN 'reader' THEN metadata.audit_pseudonym_reader_role_oid
        ELSE NULL::oid
    END INTO v_expected_oid
    FROM relay_state_private.state_plane_metadata AS metadata
    WHERE metadata.singleton = true;
    IF v_expected_oid IS NULL OR v_session_oid IS DISTINCT FROM v_expected_oid THEN
        RAISE EXCEPTION 'audit pseudonym keyring caller role is not bound'
            USING ERRCODE = '42501';
    END IF;
    RETURN QUERY
    SELECT relay_state_private.capability_valid_v1()
           AND current_setting('search_path') = 'pg_catalog, relay_state_private'
           AND current_setting('lock_timeout') = '2s'
           AND current_setting('statement_timeout') = '5s'
           AND current_setting('idle_in_transaction_session_timeout') = '5s'
           AND current_setting('synchronous_commit') = 'on'
           AND current_setting('client_encoding') = 'UTF8'
           AND current_setting('standard_conforming_strings') = 'on'
           AND current_setting('session_replication_role') = 'origin'
           AND current_setting('default_transaction_isolation') = 'read committed'
           AND current_setting('transaction_isolation') = 'read committed'
           AND current_setting('default_transaction_read_only') = 'off'
           AND current_setting('transaction_read_only') = 'off'
           AND NOT pg_catalog.pg_is_in_recovery()
           AND metadata.chain_key_epoch_id = p_expected_chain_key_epoch_id,
           metadata.capability_id,
           metadata.capability_fingerprint,
           metadata.owner_role_oid::bigint,
           v_expected_oid::bigint,
           metadata.chain_key_epoch_id,
           metadata.audit_pseudonym_keyring_capability_id,
           metadata.audit_pseudonym_keyring_lock_key
    FROM relay_state_private.state_plane_metadata AS metadata
    WHERE metadata.singleton = true;
    IF clock_timestamp() - v_started_at > interval '5 seconds' THEN
        RAISE EXCEPTION 'audit pseudonym keyring readiness exceeded its deadline'
            USING ERRCODE = '57014';
    END IF;
END;
$function$;

CREATE OR REPLACE FUNCTION relay_state_api.serving_fence_acquire_v1(
    p_lock_key bigint,
    p_holder_id text
)
RETURNS TABLE (
    outcome text,
    fence_generation bigint,
    holder_id text,
    lock_key bigint,
    takeover_required boolean,
    admission_open boolean
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, relay_state_private
SET lock_timeout = '2s'
SET statement_timeout = '5s'
SET idle_in_transaction_session_timeout = '5s'
SET synchronous_commit = 'on'
AS $function$
DECLARE
    v_runtime_oid oid;
    v_session_oid oid;
    v_lock_acquired boolean := false;
    v_prior_barrier timestamptz;
    v_takeover_required boolean;
    v_generation bigint;
    v_admission_open boolean;
BEGIN
    PERFORM set_config('lock_timeout', '2s', false);
    PERFORM set_config('statement_timeout', '5s', false);
    PERFORM set_config('idle_in_transaction_session_timeout', '5s', false);
    PERFORM set_config('synchronous_commit', 'on', false);
    SELECT metadata.runtime_role_oid INTO v_runtime_oid
    FROM relay_state_private.state_plane_metadata AS metadata
    WHERE metadata.singleton = true;
    SELECT oid INTO v_session_oid FROM pg_catalog.pg_roles WHERE rolname = session_user;
    IF v_session_oid IS DISTINCT FROM v_runtime_oid THEN
        RAISE EXCEPTION 'serving fence caller is not bound' USING ERRCODE = '42501';
    END IF;
    IF NOT relay_state_private.capability_valid_v1() THEN
        RAISE EXCEPTION 'serving fence capability unavailable' USING ERRCODE = '55000';
    END IF;
    IF p_lock_key IS NULL OR p_holder_id IS NULL
       OR p_holder_id !~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'
       OR NOT EXISTS (
           SELECT 1 FROM relay_state_private.state_plane_metadata AS metadata
           WHERE metadata.singleton = true
             AND metadata.serving_fence_capability_id =
                 'registry.relay.postgres-serving-fence/v1'
             AND metadata.serving_fence_lock_key = p_lock_key
       )
    THEN
        RAISE EXCEPTION 'invalid serving fence acquisition' USING ERRCODE = '22023';
    END IF;
    IF EXISTS (
        SELECT 1 FROM pg_catalog.pg_locks AS lock_row
        WHERE lock_row.locktype = 'advisory'
          AND lock_row.pid = pg_catalog.pg_backend_pid()
          AND lock_row.database = (
              SELECT database_row.oid FROM pg_catalog.pg_database AS database_row
              WHERE database_row.datname = current_database()
          )
          AND lock_row.classid::bigint = ((p_lock_key >> 32) & 4294967295)
          AND lock_row.objid::bigint = (p_lock_key & 4294967295)
          AND lock_row.objsubid = 1
          AND lock_row.granted
    ) THEN
        RAISE EXCEPTION 'serving fence session already owns the lock'
            USING ERRCODE = '55000';
    END IF;

    SELECT pg_catalog.pg_try_advisory_lock(p_lock_key) INTO v_lock_acquired;
    IF NOT v_lock_acquired THEN
        RETURN QUERY SELECT 'contended'::text, NULL::bigint, NULL::text,
            p_lock_key, NULL::boolean, false;
        RETURN;
    END IF;

    BEGIN
        -- The successor owns the session advisory lock before it joins the
        -- row-level protocol. Lock the singleton before the intent scan so a
        -- generation-dependent writer that already holds SHARE must commit or
        -- abort first. The following READ COMMITTED statement then sees that
        -- writer's durable intent.
        PERFORM fence.singleton
        FROM relay_state_private.serving_fence_state AS fence
        WHERE fence.singleton = true
        FOR UPDATE;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'serving fence state is unavailable' USING ERRCODE = '55000';
        END IF;
        SELECT max(intent.total_deadline_at + interval '1 second')
        INTO v_prior_barrier
        FROM relay_state_private.consultation_completion_intent AS intent
        WHERE intent.state <> 'completed';
        v_takeover_required := v_prior_barrier IS NOT NULL;
        v_admission_open := NOT v_takeover_required;
        UPDATE relay_state_private.serving_fence_state AS fence
        SET generation = fence.generation + 1,
            holder_id = p_holder_id,
            holder_backend_pid = pg_catalog.pg_backend_pid(),
            acquired_at = clock_timestamp(),
            takeover_pending = v_takeover_required,
            takeover_pg_not_before = v_prior_barrier,
            admission_open = v_admission_open
        WHERE fence.singleton = true
        RETURNING fence.generation INTO v_generation;
        IF NOT FOUND OR v_generation <= 0 THEN
            RAISE EXCEPTION 'serving fence state is unavailable' USING ERRCODE = '55000';
        END IF;
        RETURN QUERY SELECT 'acquired'::text, v_generation, p_holder_id,
            p_lock_key, v_takeover_required, v_admission_open;
    EXCEPTION WHEN OTHERS THEN
        PERFORM pg_catalog.pg_advisory_unlock(p_lock_key);
        RAISE;
    END;
END;
$function$;

CREATE OR REPLACE FUNCTION relay_state_api.serving_fence_finalize_v1(
    p_lock_key bigint,
    p_holder_id text,
    p_fence_generation bigint
)
RETURNS TABLE (
    outcome text,
    remaining_ms bigint,
    recovery_operation_ids text[]
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, relay_state_private
SET lock_timeout = '2s'
SET statement_timeout = '5s'
SET idle_in_transaction_session_timeout = '5s'
SET synchronous_commit = 'on'
AS $function$
DECLARE
    v_runtime_oid oid;
    v_session_oid oid;
    v_now timestamptz := clock_timestamp();
    v_pending boolean;
    v_barrier timestamptz;
    v_open boolean;
    v_recovery_operation_ids text[] := ARRAY[]::text[];
BEGIN
    PERFORM set_config('lock_timeout', '2s', false);
    PERFORM set_config('statement_timeout', '5s', false);
    PERFORM set_config('idle_in_transaction_session_timeout', '5s', false);
    PERFORM set_config('synchronous_commit', 'on', false);
    SELECT metadata.runtime_role_oid INTO v_runtime_oid
    FROM relay_state_private.state_plane_metadata AS metadata
    WHERE metadata.singleton = true;
    SELECT oid INTO v_session_oid FROM pg_catalog.pg_roles WHERE rolname = session_user;
    IF v_session_oid IS DISTINCT FROM v_runtime_oid THEN
        RAISE EXCEPTION 'serving fence caller is not bound' USING ERRCODE = '42501';
    END IF;
    IF NOT relay_state_private.capability_valid_v1() THEN
        RAISE EXCEPTION 'serving fence capability unavailable' USING ERRCODE = '55000';
    END IF;
    PERFORM fence.singleton
    FROM relay_state_private.serving_fence_state AS fence
    WHERE fence.singleton = true
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'serving fence state is unavailable' USING ERRCODE = '55000';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_locks AS lock_row
        WHERE lock_row.locktype = 'advisory'
          AND lock_row.pid = pg_catalog.pg_backend_pid()
          AND lock_row.database = (
              SELECT database_row.oid FROM pg_catalog.pg_database AS database_row
              WHERE database_row.datname = current_database()
          )
          AND lock_row.classid::bigint = ((p_lock_key >> 32) & 4294967295)
          AND lock_row.objid::bigint = (p_lock_key & 4294967295)
          AND lock_row.objsubid = 1
          AND lock_row.granted
    ) OR NOT EXISTS (
        SELECT 1 FROM relay_state_private.serving_fence_state AS fence
        JOIN relay_state_private.state_plane_metadata AS metadata
          ON metadata.singleton = true
        WHERE fence.singleton = true
          AND fence.generation = p_fence_generation
          AND fence.holder_id = p_holder_id
          AND fence.holder_backend_pid = pg_catalog.pg_backend_pid()
          AND metadata.serving_fence_lock_key = p_lock_key
    ) THEN
        RETURN QUERY SELECT 'ownership_lost'::text, NULL::bigint, NULL::text[];
        RETURN;
    END IF;
    SELECT fence.takeover_pending, fence.takeover_pg_not_before, fence.admission_open
    INTO v_pending, v_barrier, v_open
    FROM relay_state_private.serving_fence_state AS fence
    WHERE fence.singleton = true;
    IF v_open AND NOT v_pending THEN
        RETURN QUERY SELECT 'recovery_ready'::text, 0::bigint, ARRAY[]::text[];
        RETURN;
    END IF;
    IF NOT v_pending OR v_barrier IS NULL THEN
        RETURN QUERY SELECT 'ownership_lost'::text, NULL::bigint, NULL::text[];
        RETURN;
    END IF;
    IF v_now < v_barrier THEN
        RETURN QUERY SELECT 'barrier_pending'::text,
            greatest(1::bigint, ceil(extract(epoch FROM (v_barrier - v_now)) * 1000)::bigint),
            ARRAY[]::text[];
        RETURN;
    END IF;
    -- The bytewise order is part of the deadlock and deterministic recovery
    -- protocol. Lock every prior incomplete intent before normal finalizers can
    -- decide whether they still own the open state.
    PERFORM intent.operation_id
    FROM relay_state_private.consultation_completion_intent AS intent
    WHERE intent.fence_generation < p_fence_generation
      AND intent.state <> 'completed'
    ORDER BY pg_catalog.convert_to(intent.operation_id, 'UTF8')
    FOR UPDATE;
    UPDATE relay_state_private.consultation_completion_intent AS intent
    SET state = 'recovery_ready', recovery_marked_at = v_now
    WHERE intent.fence_generation < p_fence_generation
      AND intent.state = 'open';
    SELECT COALESCE(
        pg_catalog.array_agg(
            intent.operation_id
            ORDER BY pg_catalog.convert_to(intent.operation_id, 'UTF8')
        ),
        ARRAY[]::text[]
    ) INTO v_recovery_operation_ids
    FROM relay_state_private.consultation_completion_intent AS intent
    WHERE intent.fence_generation < p_fence_generation
      AND intent.state = 'recovery_ready';
    -- Admission intentionally remains closed. Only the separate recovery-open
    -- function may clear the takeover barrier after every intent is completed.
    RETURN QUERY SELECT 'recovery_ready'::text, 0::bigint,
        v_recovery_operation_ids;
END;
$function$;

CREATE OR REPLACE FUNCTION relay_state_api.serving_fence_open_after_recovery_v1(
    p_lock_key bigint,
    p_holder_id text,
    p_fence_generation bigint
)
RETURNS TABLE (outcome text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, relay_state_private
SET lock_timeout = '2s'
SET statement_timeout = '5s'
SET idle_in_transaction_session_timeout = '5s'
SET synchronous_commit = 'on'
AS $function$
DECLARE
    v_runtime_oid oid;
    v_session_oid oid;
BEGIN
    PERFORM set_config('lock_timeout', '2s', false);
    PERFORM set_config('statement_timeout', '5s', false);
    PERFORM set_config('idle_in_transaction_session_timeout', '5s', false);
    PERFORM set_config('synchronous_commit', 'on', false);
    SELECT metadata.runtime_role_oid INTO v_runtime_oid
    FROM relay_state_private.state_plane_metadata AS metadata
    WHERE metadata.singleton = true;
    SELECT oid INTO v_session_oid FROM pg_catalog.pg_roles WHERE rolname = session_user;
    IF v_session_oid IS DISTINCT FROM v_runtime_oid THEN
        RAISE EXCEPTION 'serving fence caller is not bound' USING ERRCODE = '42501';
    END IF;
    IF NOT relay_state_private.capability_valid_v1() THEN
        RAISE EXCEPTION 'serving fence capability unavailable' USING ERRCODE = '55000';
    END IF;
    -- Opening admission is a fence-state transition. Serialize it with every
    -- recovery completion before checking that no incomplete intent remains.
    PERFORM fence.singleton
    FROM relay_state_private.serving_fence_state AS fence
    WHERE fence.singleton = true
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'serving fence state is unavailable' USING ERRCODE = '55000';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM relay_state_private.serving_fence_state AS fence
        JOIN relay_state_private.state_plane_metadata AS metadata
          ON metadata.singleton = true
        WHERE fence.singleton = true
          AND fence.generation = p_fence_generation
          AND fence.holder_id = p_holder_id
          AND fence.holder_backend_pid = pg_catalog.pg_backend_pid()
          AND fence.takeover_pending AND NOT fence.admission_open
          AND metadata.serving_fence_lock_key = p_lock_key
    ) OR NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_locks AS lock_row
        WHERE lock_row.locktype = 'advisory'
          AND lock_row.pid = pg_catalog.pg_backend_pid()
          AND lock_row.database = (
              SELECT database_row.oid FROM pg_catalog.pg_database AS database_row
              WHERE database_row.datname = current_database()
          )
          AND lock_row.classid::bigint = ((p_lock_key >> 32) & 4294967295)
          AND lock_row.objid::bigint = (p_lock_key & 4294967295)
          AND lock_row.objsubid = 1
          AND lock_row.granted
    ) THEN
        RETURN QUERY SELECT 'ownership_lost'::text;
        RETURN;
    END IF;
    IF EXISTS (
        SELECT 1
        FROM relay_state_private.consultation_completion_intent AS intent
        WHERE intent.fence_generation < p_fence_generation
          AND intent.state <> 'completed'
    ) THEN
        RETURN QUERY SELECT 'recovery_incomplete'::text;
        RETURN;
    END IF;
    UPDATE relay_state_private.serving_fence_state AS fence
    SET takeover_pending = false,
        takeover_pg_not_before = NULL,
        admission_open = true
    WHERE fence.singleton = true
      AND fence.generation = p_fence_generation
      AND fence.holder_id = p_holder_id
      AND fence.holder_backend_pid = pg_catalog.pg_backend_pid()
      AND fence.takeover_pending AND NOT fence.admission_open;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'serving fence recovery opening changed concurrently'
            USING ERRCODE = '55000';
    END IF;
    RETURN QUERY SELECT 'opened'::text;
END;
$function$;

CREATE OR REPLACE FUNCTION relay_state_api.serving_fence_status_v1(
    p_lock_key bigint,
    p_holder_id text,
    p_fence_generation bigint
)
RETURNS TABLE (outcome text)
LANGUAGE plpgsql
STABLE
SECURITY DEFINER
SET search_path = pg_catalog, relay_state_private
SET lock_timeout = '2s'
SET statement_timeout = '5s'
SET idle_in_transaction_session_timeout = '5s'
SET synchronous_commit = 'on'
AS $function$
DECLARE
    v_runtime_oid oid;
    v_session_oid oid;
BEGIN
    PERFORM set_config('lock_timeout', '2s', false);
    PERFORM set_config('statement_timeout', '5s', false);
    PERFORM set_config('idle_in_transaction_session_timeout', '5s', false);
    PERFORM set_config('synchronous_commit', 'on', false);
    SELECT metadata.runtime_role_oid INTO v_runtime_oid
    FROM relay_state_private.state_plane_metadata AS metadata
    WHERE metadata.singleton = true;
    SELECT oid INTO v_session_oid FROM pg_catalog.pg_roles WHERE rolname = session_user;
    IF v_session_oid IS DISTINCT FROM v_runtime_oid THEN
        RAISE EXCEPTION 'serving fence caller is not bound' USING ERRCODE = '42501';
    END IF;
    IF NOT relay_state_private.capability_valid_v1() THEN
        RETURN QUERY SELECT 'ownership_lost'::text;
        RETURN;
    END IF;
    IF EXISTS (
        SELECT 1 FROM relay_state_private.serving_fence_state AS fence
        JOIN relay_state_private.state_plane_metadata AS metadata
          ON metadata.singleton = true
        WHERE fence.singleton = true
          AND fence.generation = p_fence_generation
          AND fence.holder_id = p_holder_id
          AND fence.holder_backend_pid = pg_catalog.pg_backend_pid()
          AND fence.admission_open AND NOT fence.takeover_pending
          AND metadata.serving_fence_lock_key = p_lock_key
    ) AND EXISTS (
        SELECT 1 FROM pg_catalog.pg_locks AS lock_row
        WHERE lock_row.locktype = 'advisory'
          AND lock_row.pid = pg_catalog.pg_backend_pid()
          AND lock_row.database = (
              SELECT database_row.oid FROM pg_catalog.pg_database AS database_row
              WHERE database_row.datname = current_database()
          )
          AND lock_row.classid::bigint = ((p_lock_key >> 32) & 4294967295)
          AND lock_row.objid::bigint = (p_lock_key & 4294967295)
          AND lock_row.objsubid = 1
          AND lock_row.granted
    ) THEN
        RETURN QUERY SELECT 'ready'::text;
    ELSE
        RETURN QUERY SELECT 'ownership_lost'::text;
    END IF;
END;
$function$;

CREATE OR REPLACE FUNCTION relay_state_api.dispatch_permit_authorize_v1(
    p_lock_key bigint,
    p_holder_id text,
    p_fence_generation bigint,
    p_operation_id text,
    p_kind text,
    p_ordinal smallint,
    p_source_operation_id text,
    p_expected_deadline_unix_ms bigint
)
RETURNS TABLE (outcome text, deadline_unix_ms bigint)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, relay_state_private
SET lock_timeout = '2s'
SET statement_timeout = '5s'
SET idle_in_transaction_session_timeout = '5s'
SET synchronous_commit = 'on'
AS $function$
DECLARE
    v_runtime_oid oid;
    v_session_oid oid;
    v_intent relay_state_private.consultation_completion_intent%ROWTYPE;
    v_permit relay_state_private.dispatch_permit%ROWTYPE;
    v_dispatched_at timestamptz;
BEGIN
    PERFORM set_config('lock_timeout', '2s', false);
    PERFORM set_config('statement_timeout', '5s', false);
    PERFORM set_config('idle_in_transaction_session_timeout', '5s', false);
    PERFORM set_config('synchronous_commit', 'on', false);
    SELECT metadata.runtime_role_oid INTO v_runtime_oid
    FROM relay_state_private.state_plane_metadata AS metadata
    WHERE metadata.singleton = true;
    SELECT oid INTO v_session_oid FROM pg_catalog.pg_roles WHERE rolname = session_user;
    IF v_session_oid IS DISTINCT FROM v_runtime_oid THEN
        RAISE EXCEPTION 'dispatch permit caller is not bound' USING ERRCODE = '42501';
    END IF;
    IF NOT relay_state_private.capability_valid_v1() THEN
        RAISE EXCEPTION 'dispatch permit capability unavailable' USING ERRCODE = '55000';
    END IF;
    PERFORM fence.singleton
    FROM relay_state_private.serving_fence_state AS fence
    WHERE fence.singleton = true
    FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'serving fence state is unavailable' USING ERRCODE = '55000';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM relay_state_private.serving_fence_state AS fence
        JOIN relay_state_private.state_plane_metadata AS metadata
          ON metadata.singleton = true
        WHERE fence.singleton = true
          AND fence.generation = p_fence_generation
          AND fence.holder_id = p_holder_id
          AND fence.holder_backend_pid = pg_catalog.pg_backend_pid()
          AND fence.admission_open AND NOT fence.takeover_pending
          AND metadata.serving_fence_lock_key = p_lock_key
    ) OR NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_locks AS lock_row
        WHERE lock_row.locktype = 'advisory'
          AND lock_row.pid = pg_catalog.pg_backend_pid()
          AND lock_row.database = (
              SELECT database_row.oid FROM pg_catalog.pg_database AS database_row
              WHERE database_row.datname = current_database()
          )
          AND lock_row.classid::bigint = ((p_lock_key >> 32) & 4294967295)
          AND lock_row.objid::bigint = (p_lock_key & 4294967295)
          AND lock_row.objsubid = 1
          AND lock_row.granted
    ) THEN
        RETURN QUERY SELECT 'ownership_lost'::text, NULL::bigint;
        RETURN;
    END IF;
    IF p_operation_id IS NULL
       OR p_operation_id !~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'
       OR NOT (
           (p_kind = 'credential' AND p_ordinal = 0)
           OR (p_kind = 'data' AND p_ordinal BETWEEN 0 AND 4)
       )
       OR p_source_operation_id IS NULL
       OR p_source_operation_id !~ '^[a-z][a-z0-9._-]{0,95}$'
       OR p_expected_deadline_unix_ms IS NULL
    THEN
        RAISE EXCEPTION 'invalid dispatch permit authorization'
            USING ERRCODE = '22023';
    END IF;
    SELECT intent.* INTO v_intent
    FROM relay_state_private.consultation_completion_intent AS intent
    WHERE intent.operation_id = p_operation_id
    FOR SHARE;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'unknown'::text, NULL::bigint;
        RETURN;
    ELSIF v_intent.fence_generation <> p_fence_generation
          OR v_intent.holder_id <> p_holder_id THEN
        RETURN QUERY SELECT 'stale_generation'::text,
            floor(extract(epoch FROM v_intent.total_deadline_at) * 1000)::bigint;
        RETURN;
    ELSIF NOT EXISTS (
        SELECT 1
        FROM pg_catalog.jsonb_array_elements(
            v_intent.completion_seed_canonical::jsonb #> '{dispatch,permit_bindings}'
        ) AS binding(value)
        WHERE binding.value ->> 'kind' = p_kind
          AND (binding.value ->> 'ordinal')::smallint = p_ordinal
          AND binding.value -> 'allowed_operation_ids' ? p_source_operation_id
    ) THEN
        RETURN QUERY SELECT 'source_operation_rejected'::text,
            floor(extract(epoch FROM v_intent.total_deadline_at) * 1000)::bigint;
        RETURN;
    END IF;
    PERFORM permit.operation_id
    FROM relay_state_private.dispatch_permit AS permit
    WHERE permit.operation_id = p_operation_id
    ORDER BY CASE permit.kind WHEN 'credential' THEN 0 ELSE 1 END,
             permit.ordinal
    FOR UPDATE;
    SELECT permit.* INTO v_permit
    FROM relay_state_private.dispatch_permit AS permit
    WHERE permit.operation_id = p_operation_id
      AND permit.kind = p_kind
      AND permit.ordinal = p_ordinal
    FOR UPDATE;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'unknown'::text, NULL::bigint;
    ELSIF v_permit.fence_generation <> p_fence_generation
          OR v_permit.holder_id <> p_holder_id THEN
        RETURN QUERY SELECT 'stale_generation'::text,
            floor(extract(epoch FROM v_permit.deadline_at) * 1000)::bigint;
    ELSIF floor(extract(epoch FROM v_permit.deadline_at) * 1000)::bigint
              <> p_expected_deadline_unix_ms THEN
        RETURN QUERY SELECT 'permit_mismatch'::text,
            floor(extract(epoch FROM v_permit.deadline_at) * 1000)::bigint;
    ELSIF v_permit.abandoned_at IS NOT NULL THEN
        RETURN QUERY SELECT 'abandoned'::text,
            floor(extract(epoch FROM v_permit.deadline_at) * 1000)::bigint;
    ELSIF v_permit.completion_envelope_id IS NOT NULL THEN
        RETURN QUERY SELECT 'completed'::text,
            floor(extract(epoch FROM v_permit.deadline_at) * 1000)::bigint;
    ELSIF v_permit.dispatched_at IS NOT NULL
          AND v_permit.source_operation_id IS DISTINCT FROM p_source_operation_id THEN
        RETURN QUERY SELECT 'operation_conflict'::text,
            floor(extract(epoch FROM v_permit.deadline_at) * 1000)::bigint;
    ELSIF v_permit.dispatched_at IS NOT NULL THEN
        RETURN QUERY SELECT 'already_dispatched'::text,
            floor(extract(epoch FROM v_permit.deadline_at) * 1000)::bigint;
    ELSIF p_kind = 'credential' AND EXISTS (
        SELECT 1
        FROM relay_state_private.dispatch_permit AS permit
        WHERE permit.operation_id = p_operation_id
          AND permit.kind = 'data'
          AND permit.dispatched_at IS NOT NULL
    ) THEN
        RETURN QUERY SELECT 'permit_order_violation'::text,
            floor(extract(epoch FROM v_permit.deadline_at) * 1000)::bigint;
    ELSIF p_kind = 'data' AND (
        EXISTS (
            SELECT 1
            FROM relay_state_private.dispatch_permit AS permit
            WHERE permit.operation_id = p_operation_id
              AND permit.kind = 'data'
              AND permit.ordinal < p_ordinal
              AND permit.dispatched_at IS NULL
        )
        OR EXISTS (
            SELECT 1
            FROM relay_state_private.dispatch_permit AS permit
            WHERE permit.operation_id = p_operation_id
              AND permit.kind = 'data'
              AND permit.ordinal > p_ordinal
              AND permit.dispatched_at IS NOT NULL
        )
    ) THEN
        RETURN QUERY SELECT 'permit_order_violation'::text,
            floor(extract(epoch FROM v_permit.deadline_at) * 1000)::bigint;
    ELSIF p_kind = 'data'
          AND v_intent.completion_seed_canonical::jsonb #>> '{dispatch,plan_kind}'
              = 'bounded_http'
          AND EXISTS (
              SELECT 1
              FROM relay_state_private.dispatch_permit AS permit
              WHERE permit.operation_id = p_operation_id
                AND permit.kind = 'data'
                AND permit.ordinal <> p_ordinal
                AND permit.source_operation_id = p_source_operation_id
                AND permit.dispatched_at IS NOT NULL
          ) THEN
        RETURN QUERY SELECT 'operation_reuse_rejected'::text,
            floor(extract(epoch FROM v_permit.deadline_at) * 1000)::bigint;
    ELSIF clock_timestamp() >= v_permit.deadline_at THEN
        RETURN QUERY SELECT 'expired'::text,
            floor(extract(epoch FROM v_permit.deadline_at) * 1000)::bigint;
    ELSE
        v_dispatched_at := clock_timestamp();
        UPDATE relay_state_private.dispatch_permit AS permit
        SET source_operation_id = p_source_operation_id,
            dispatched_at = v_dispatched_at
        WHERE permit.operation_id = p_operation_id
          AND permit.kind = p_kind
          AND permit.ordinal = p_ordinal
          AND permit.source_operation_id IS NULL
          AND permit.dispatched_at IS NULL
          AND permit.abandoned_at IS NULL
          AND permit.completion_envelope_id IS NULL;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'dispatch permit authorization changed concurrently'
                USING ERRCODE = '55000';
        END IF;
        RETURN QUERY SELECT 'authorized'::text,
            floor(extract(epoch FROM v_permit.deadline_at) * 1000)::bigint;
    END IF;
END;
$function$;

CREATE OR REPLACE FUNCTION relay_state_api.serving_fence_release_v1(
    p_lock_key bigint,
    p_holder_id text,
    p_fence_generation bigint
)
RETURNS TABLE (outcome text)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, relay_state_private
SET lock_timeout = '2s'
SET statement_timeout = '5s'
SET idle_in_transaction_session_timeout = '5s'
SET synchronous_commit = 'on'
AS $function$
DECLARE
    v_runtime_oid oid;
    v_session_oid oid;
BEGIN
    PERFORM set_config('lock_timeout', '2s', false);
    PERFORM set_config('statement_timeout', '5s', false);
    PERFORM set_config('idle_in_transaction_session_timeout', '5s', false);
    PERFORM set_config('synchronous_commit', 'on', false);
    SELECT metadata.runtime_role_oid INTO v_runtime_oid
    FROM relay_state_private.state_plane_metadata AS metadata
    WHERE metadata.singleton = true;
    SELECT oid INTO v_session_oid FROM pg_catalog.pg_roles WHERE rolname = session_user;
    IF v_session_oid IS DISTINCT FROM v_runtime_oid THEN
        RAISE EXCEPTION 'serving fence caller is not bound' USING ERRCODE = '42501';
    END IF;
    -- Wait for every generation-dependent writer before closing admission and
    -- releasing the session advisory lock. A successor that obtains the
    -- advisory lock before this transaction commits will wait on this row.
    PERFORM fence.singleton
    FROM relay_state_private.serving_fence_state AS fence
    WHERE fence.singleton = true
    FOR UPDATE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'serving fence state is unavailable' USING ERRCODE = '55000';
    END IF;
    IF NOT EXISTS (
        SELECT 1 FROM relay_state_private.serving_fence_state AS fence
        JOIN relay_state_private.state_plane_metadata AS metadata
          ON metadata.singleton = true
        WHERE fence.singleton = true
          AND fence.generation = p_fence_generation
          AND fence.holder_id = p_holder_id
          AND fence.holder_backend_pid = pg_catalog.pg_backend_pid()
          AND metadata.serving_fence_lock_key = p_lock_key
    ) OR NOT EXISTS (
        SELECT 1 FROM pg_catalog.pg_locks AS lock_row
        WHERE lock_row.locktype = 'advisory'
          AND lock_row.pid = pg_catalog.pg_backend_pid()
          AND lock_row.database = (
              SELECT database_row.oid FROM pg_catalog.pg_database AS database_row
              WHERE database_row.datname = current_database()
          )
          AND lock_row.classid::bigint = ((p_lock_key >> 32) & 4294967295)
          AND lock_row.objid::bigint = (p_lock_key & 4294967295)
          AND lock_row.objsubid = 1
          AND lock_row.granted
    ) THEN
        RETURN QUERY SELECT 'ownership_lost'::text;
        RETURN;
    END IF;
    UPDATE relay_state_private.serving_fence_state AS fence
    SET admission_open = false,
        takeover_pending = false,
        takeover_pg_not_before = NULL
    WHERE fence.singleton = true
      AND fence.generation = p_fence_generation
      AND fence.holder_id = p_holder_id;
    IF NOT FOUND OR NOT pg_catalog.pg_advisory_unlock(p_lock_key) THEN
        RAISE EXCEPTION 'serving fence release failed' USING ERRCODE = '55000';
    END IF;
    RETURN QUERY SELECT 'released'::text;
END;
$function$;

CREATE OR REPLACE FUNCTION relay_state_api.quota_reserve_v1(
    p_workload_id text,
    p_profile_id text,
    p_profile_version bigint,
    p_rate_per_minute integer,
    p_burst_tokens integer
)
RETURNS TABLE (
    outcome text,
    retry_after_ms bigint,
    rate_per_minute integer,
    burst_tokens integer
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, relay_state_private
SET lock_timeout = '2s'
SET statement_timeout = '5s'
SET idle_in_transaction_session_timeout = '5s'
SET synchronous_commit = 'on'
AS $function$
DECLARE
    v_started_at timestamptz := clock_timestamp();
    v_now timestamptz;
    v_runtime_oid oid;
    v_session_oid oid;
    v_bucket relay_state_private.consultation_quota_bucket%ROWTYPE;
    v_capacity bigint;
    v_elapsed_us numeric := 0;
    v_max_elapsed_us numeric := 0;
    v_refill_numerator bigint := 0;
    v_tokens bigint;
    v_last_refill_at timestamptz;
    v_missing_numerator bigint;
    v_rollback_gap_us numeric := 0;
    v_token_wait_us numeric;
    v_total_wait_us numeric;
    v_retry_after_ms bigint;
    v_changed_rows bigint;
BEGIN
    PERFORM set_config('lock_timeout', '2s', false);
    PERFORM set_config('statement_timeout', '5s', false);
    PERFORM set_config('idle_in_transaction_session_timeout', '5s', false);
    PERFORM set_config('synchronous_commit', 'on', false);
    SELECT metadata.runtime_role_oid INTO v_runtime_oid
    FROM relay_state_private.state_plane_metadata AS metadata
    WHERE metadata.singleton = true;
    SELECT oid INTO v_session_oid FROM pg_catalog.pg_roles WHERE rolname = session_user;
    IF v_session_oid IS DISTINCT FROM v_runtime_oid THEN
        RAISE EXCEPTION 'consultation quota caller is not bound' USING ERRCODE = '42501';
    END IF;
    IF current_setting('search_path') <> 'pg_catalog, relay_state_private'
       OR current_setting('lock_timeout') <> '2s'
       OR current_setting('statement_timeout') <> '5s'
       OR current_setting('idle_in_transaction_session_timeout') <> '5s'
       OR current_setting('synchronous_commit') <> 'on'
       OR current_setting('client_encoding') <> 'UTF8'
       OR current_setting('standard_conforming_strings') <> 'on'
       OR current_setting('session_replication_role') <> 'origin'
       OR current_setting('default_transaction_isolation') <> 'read committed'
       OR current_setting('transaction_isolation') <> 'read committed'
       OR current_setting('default_transaction_read_only') <> 'off'
       OR current_setting('transaction_read_only') <> 'off'
       OR pg_catalog.pg_is_in_recovery()
    THEN
        RAISE EXCEPTION 'consultation quota runtime session is unsafe'
            USING ERRCODE = '55000';
    END IF;
    IF NOT relay_state_private.capability_valid_v1() THEN
        RAISE EXCEPTION 'consultation quota capability unavailable'
            USING ERRCODE = '55000';
    END IF;
    IF p_workload_id IS NULL OR p_profile_id IS NULL OR p_profile_version IS NULL
       OR p_rate_per_minute IS NULL OR p_burst_tokens IS NULL
       OR p_workload_id !~ '^[a-z][a-z0-9._-]{0,95}$'
       OR p_profile_id !~ '^[a-z][a-z0-9._-]{0,95}$'
       OR p_profile_version NOT BETWEEN 1 AND 9999999999
       OR p_rate_per_minute NOT BETWEEN 1 AND 60
       OR p_burst_tokens NOT BETWEEN 1 AND 10
    THEN
        RAISE EXCEPTION 'invalid consultation quota request' USING ERRCODE = '22023';
    END IF;

    v_capacity := p_burst_tokens::bigint * 60000000;
    v_now := clock_timestamp();
    INSERT INTO relay_state_private.consultation_quota_bucket AS bucket (
        workload_id, profile_id, profile_version, rate_per_minute,
        burst_tokens, tokens_numerator, last_refill_at
    ) VALUES (
        p_workload_id, p_profile_id, p_profile_version, p_rate_per_minute,
        p_burst_tokens, v_capacity, v_now
    ) ON CONFLICT (workload_id, profile_id, profile_version) DO NOTHING;

    SELECT bucket.* INTO STRICT v_bucket
    FROM relay_state_private.consultation_quota_bucket AS bucket
    WHERE bucket.workload_id = p_workload_id
      AND bucket.profile_id = p_profile_id
      AND bucket.profile_version = p_profile_version
    FOR UPDATE;
    IF v_bucket.rate_per_minute NOT BETWEEN 1 AND 60
       OR v_bucket.burst_tokens NOT BETWEEN 1 AND 10
       OR v_bucket.tokens_numerator < 0
       OR v_bucket.tokens_numerator > v_bucket.burst_tokens::bigint * 60000000
       OR NOT pg_catalog.isfinite(v_bucket.last_refill_at)
    THEN
        RAISE EXCEPTION 'consultation quota bucket is corrupt' USING ERRCODE = '55000';
    END IF;

    -- Limits are durably bound at first use. A later lowering or profile
    -- change requires a governed maintenance transition that preserves the
    -- conservative token balance. Mismatch never mutates or refills the row.
    IF v_bucket.rate_per_minute <> p_rate_per_minute
       OR v_bucket.burst_tokens <> p_burst_tokens
    THEN
        RETURN QUERY SELECT 'limit_mismatch'::text, NULL::bigint,
            v_bucket.rate_per_minute, v_bucket.burst_tokens;
        RETURN;
    END IF;

    v_tokens := v_bucket.tokens_numerator;
    v_last_refill_at := v_bucket.last_refill_at;
    IF v_now >= v_last_refill_at THEN
        -- PostgreSQL timestamps have microsecond resolution. One whole token
        -- is 60,000,000 numerator units, so each elapsed microsecond adds
        -- exactly rate_per_minute units. Cap elapsed time before multiplying.
        v_max_elapsed_us := pg_catalog.ceil(
            (v_capacity - v_tokens)::numeric / p_rate_per_minute::numeric
        );
        v_elapsed_us := LEAST(
            pg_catalog.floor(
                extract(epoch FROM (v_now - v_last_refill_at)) * 1000000
            ),
            v_max_elapsed_us
        );
        v_refill_numerator := (v_elapsed_us * p_rate_per_minute::numeric)::bigint;
        v_tokens := LEAST(v_capacity, v_tokens + v_refill_numerator);
        v_last_refill_at := v_now;
    END IF;

    IF v_tokens >= 60000000 THEN
        v_tokens := v_tokens - 60000000;
        v_retry_after_ms := 0;
        outcome := 'allowed';
    ELSE
        v_missing_numerator := 60000000 - v_tokens;
        v_token_wait_us := pg_catalog.ceil(
            v_missing_numerator::numeric / p_rate_per_minute::numeric
        );
        IF v_now < v_last_refill_at THEN
            v_rollback_gap_us := pg_catalog.floor(
                extract(epoch FROM (v_last_refill_at - v_now)) * 1000000
            );
        END IF;
        v_total_wait_us := v_rollback_gap_us + v_token_wait_us;
        IF v_total_wait_us > 60000000 THEN
            RETURN QUERY SELECT 'clock_anomaly'::text, NULL::bigint,
                p_rate_per_minute, p_burst_tokens;
            RETURN;
        END IF;
        v_retry_after_ms := pg_catalog.ceil(v_total_wait_us / 1000)::bigint;
        IF v_retry_after_ms NOT BETWEEN 1 AND 60000 THEN
            RAISE EXCEPTION 'consultation quota retry calculation is invalid'
                USING ERRCODE = '55000';
        END IF;
        outcome := 'exhausted';
    END IF;

    UPDATE relay_state_private.consultation_quota_bucket AS bucket
    SET tokens_numerator = v_tokens,
        last_refill_at = v_last_refill_at
    WHERE bucket.workload_id = p_workload_id
      AND bucket.profile_id = p_profile_id
      AND bucket.profile_version = p_profile_version
      AND bucket.rate_per_minute = p_rate_per_minute
      AND bucket.burst_tokens = p_burst_tokens;
    GET DIAGNOSTICS v_changed_rows = ROW_COUNT;
    IF v_changed_rows <> 1 THEN
        RAISE EXCEPTION 'consultation quota update did not change exactly one row'
            USING ERRCODE = '55000';
    END IF;
    IF clock_timestamp() - v_started_at > interval '5 seconds' THEN
        RAISE EXCEPTION 'consultation quota reservation exceeded its deadline'
            USING ERRCODE = '57014';
    END IF;
    retry_after_ms := v_retry_after_ms;
    rate_per_minute := p_rate_per_minute;
    burst_tokens := p_burst_tokens;
    RETURN NEXT;
END;
$function$;

CREATE OR REPLACE FUNCTION relay_state_api.audit_pseudonym_keyring_snapshot_v1(
    p_purpose text,
    p_lookup_key_ids text[],
    p_expected_chain_key_epoch_id text,
    p_expected_keyring_lock_key bigint
)
RETURNS TABLE (
    outcome text,
    authoritative_now_unix_ms bigint,
    generation bigint,
    metadata_digest bytea,
    metadata_canonical text,
    active_key_id text,
    active_since_unix_ms bigint,
    active_write_deadline_unix_ms bigint,
    audit_event_retention_ms bigint,
    retained_key_ids text[],
    retained_retired_at_unix_ms bigint[],
    retained_destroy_after_unix_ms bigint[],
    used_key_id_count bigint,
    used_key_ids_digest bytea,
    used_key_ids text[],
    active_write_remaining_ms bigint,
    lookup_key_ids text[],
    lookup_retired_at_unix_ms bigint[],
    lookup_destroy_after_unix_ms bigint[]
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, relay_state_private
SET lock_timeout = '2s'
SET statement_timeout = '5s'
SET idle_in_transaction_session_timeout = '5s'
SET synchronous_commit = 'on'
AS $function$
DECLARE
    v_started_at timestamptz := clock_timestamp();
    v_now timestamptz;
    v_now_unix_us numeric;
    v_runtime_oid oid;
    v_maintenance_oid oid;
    v_reader_oid oid;
    v_session_oid oid;
    v_current relay_state_private.audit_pseudonym_keyring%ROWTYPE;
    v_history record;
BEGIN
    PERFORM set_config('lock_timeout', '2s', false);
    PERFORM set_config('statement_timeout', '5s', false);
    PERFORM set_config('idle_in_transaction_session_timeout', '5s', false);
    PERFORM set_config('synchronous_commit', 'on', false);
    SELECT metadata.runtime_role_oid,
           metadata.audit_pseudonym_maintenance_role_oid,
           metadata.audit_pseudonym_reader_role_oid
    INTO v_runtime_oid, v_maintenance_oid, v_reader_oid
    FROM relay_state_private.state_plane_metadata AS metadata
    WHERE metadata.singleton = true;
    SELECT oid INTO v_session_oid FROM pg_catalog.pg_roles WHERE rolname = session_user;
    IF p_purpose IS NULL
       OR p_purpose NOT IN ('rotation', 'maintenance', 'write', 'lookup')
       OR p_lookup_key_ids IS NULL
       OR p_expected_chain_key_epoch_id IS NULL
       OR p_expected_keyring_lock_key IS NULL
       OR (p_purpose = 'write' AND v_session_oid IS DISTINCT FROM v_runtime_oid)
       OR (p_purpose IN ('rotation', 'maintenance')
           AND v_session_oid IS DISTINCT FROM v_maintenance_oid)
       OR (p_purpose = 'lookup' AND v_session_oid IS DISTINCT FROM v_reader_oid)
    THEN
        RAISE EXCEPTION 'audit pseudonym keyring caller is not bound'
            USING ERRCODE = '42501';
    END IF;
    IF current_setting('search_path') <> 'pg_catalog, relay_state_private'
       OR current_setting('lock_timeout') <> '2s'
       OR current_setting('statement_timeout') <> '5s'
       OR current_setting('idle_in_transaction_session_timeout') <> '5s'
       OR current_setting('synchronous_commit') <> 'on'
       OR current_setting('client_encoding') <> 'UTF8'
       OR current_setting('standard_conforming_strings') <> 'on'
       OR current_setting('session_replication_role') <> 'origin'
       OR current_setting('default_transaction_isolation') <> 'read committed'
       OR current_setting('transaction_isolation') <> 'read committed'
       OR current_setting('default_transaction_read_only') <> 'off'
       OR current_setting('transaction_read_only') <> 'off'
       OR pg_catalog.pg_is_in_recovery()
    THEN
        RAISE EXCEPTION 'audit pseudonym keyring runtime session is unsafe'
            USING ERRCODE = '55000';
    END IF;
    IF NOT relay_state_private.capability_valid_v1() THEN
        RAISE EXCEPTION 'audit pseudonym keyring capability unavailable'
            USING ERRCODE = '55000';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM relay_state_private.state_plane_metadata AS metadata
        WHERE metadata.singleton = true
          AND metadata.chain_key_epoch_id = p_expected_chain_key_epoch_id
          AND metadata.audit_pseudonym_keyring_lock_key = p_expected_keyring_lock_key
    ) THEN
        RAISE EXCEPTION 'audit pseudonym deployment authority drifted'
            USING ERRCODE = '55000';
    END IF;
    IF (p_purpose <> 'lookup' AND cardinality(p_lookup_key_ids) <> 0)
       OR (p_purpose = 'lookup' AND cardinality(p_lookup_key_ids) NOT BETWEEN 1 AND 32)
       OR (cardinality(p_lookup_key_ids) > 0 AND (
           array_ndims(p_lookup_key_ids) <> 1
           OR array_lower(p_lookup_key_ids, 1) <> 1
           OR EXISTS (
               SELECT 1
               FROM pg_catalog.unnest(p_lookup_key_ids) WITH ORDINALITY AS requested(key_id, ordinal)
               WHERE requested.key_id IS NULL
                  OR requested.key_id !~ '^[a-z0-9][a-z0-9._-]{0,63}$'
                  OR octet_length(requested.key_id) NOT BETWEEN 1 AND 64
                  OR (requested.ordinal > 1
                      AND pg_catalog.convert_to(requested.key_id, 'UTF8')
                          <= pg_catalog.convert_to(
                              p_lookup_key_ids[requested.ordinal - 1], 'UTF8'
                          ))
           )
       ))
    THEN
        RAISE EXCEPTION 'invalid audit pseudonym lookup subset'
            USING ERRCODE = '22023';
    END IF;
    IF p_purpose IN ('rotation', 'maintenance') THEN
        PERFORM pg_catalog.pg_advisory_xact_lock(p_expected_keyring_lock_key);
    ELSE
        PERFORM pg_catalog.pg_advisory_xact_lock_shared(p_expected_keyring_lock_key);
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM relay_state_private.state_plane_metadata AS metadata
        WHERE metadata.singleton = true
          AND metadata.chain_key_epoch_id = p_expected_chain_key_epoch_id
          AND metadata.audit_pseudonym_keyring_lock_key = p_expected_keyring_lock_key
    ) THEN
        RAISE EXCEPTION 'audit pseudonym deployment authority drifted'
            USING ERRCODE = '55000';
    END IF;
    IF p_purpose IN ('rotation', 'maintenance') THEN
        SELECT row.* INTO v_current
        FROM relay_state_private.audit_pseudonym_keyring AS row
        WHERE row.singleton = true
        FOR UPDATE;
    ELSE
        SELECT row.* INTO v_current
        FROM relay_state_private.audit_pseudonym_keyring AS row
        WHERE row.singleton = true;
    END IF;
    v_now := clock_timestamp();
    v_now_unix_us := pg_catalog.floor(extract(epoch FROM v_now) * 1000000);
    authoritative_now_unix_ms := pg_catalog.floor(v_now_unix_us / 1000)::bigint;
    IF NOT FOUND THEN
        outcome := 'uninitialized';
        lookup_key_ids := ARRAY[]::text[];
        lookup_retired_at_unix_ms := ARRAY[]::bigint[];
        lookup_destroy_after_unix_ms := ARRAY[]::bigint[];
        RETURN NEXT;
        RETURN;
    END IF;
    IF p_purpose IN ('rotation', 'maintenance') THEN
        DELETE FROM relay_state_private.audit_pseudonym_transition_context;
        INSERT INTO relay_state_private.audit_pseudonym_transition_context (
            backend_pid, transaction_id, transition_kind,
            transition_time_unix_ms, expected_generation,
            expected_metadata_digest
        ) VALUES (
            pg_catalog.pg_backend_pid(), pg_catalog.txid_current(), p_purpose,
            authoritative_now_unix_ms, v_current.generation,
            v_current.metadata_digest
        );
    END IF;
    SELECT * INTO STRICT v_history
    FROM relay_state_private.audit_pseudonym_history_snapshot_v1();
    IF v_current.metadata_canonical IS DISTINCT FROM
           relay_state_private.audit_pseudonym_metadata_canonical_v1(
               v_current.generation, v_current.active_key_id,
               v_current.active_since_unix_ms,
               v_current.active_write_deadline_unix_ms,
               v_current.audit_event_retention_ms,
               v_current.retained_key_ids,
               v_current.retained_retired_at_unix_ms,
               v_current.retained_destroy_after_unix_ms
           )
       OR v_current.metadata_digest IS DISTINCT FROM pg_catalog.sha256(
           pg_catalog.convert_to(v_current.metadata_canonical, 'UTF8')
       )
       OR v_current.used_key_id_count IS DISTINCT FROM v_history.used_key_id_count
       OR v_current.used_key_ids_digest IS DISTINCT FROM v_history.used_key_ids_digest
       OR v_current.active_key_id <> ALL(v_history.used_key_ids)
       OR EXISTS (
           SELECT 1 FROM pg_catalog.unnest(v_current.retained_key_ids) AS retained(key_id)
           WHERE retained.key_id <> ALL(v_history.used_key_ids)
       )
    THEN
        RAISE EXCEPTION 'audit pseudonym keyring authority is incomplete'
            USING ERRCODE = '55000';
    END IF;
    generation := v_current.generation;
    metadata_digest := v_current.metadata_digest;
    metadata_canonical := NULL;
    active_key_id := NULL;
    active_since_unix_ms := NULL;
    active_write_deadline_unix_ms := NULL;
    audit_event_retention_ms := NULL;
    retained_key_ids := ARRAY[]::text[];
    retained_retired_at_unix_ms := ARRAY[]::bigint[];
    retained_destroy_after_unix_ms := ARRAY[]::bigint[];
    used_key_id_count := NULL;
    used_key_ids_digest := NULL;
    used_key_ids := ARRAY[]::text[];
    active_write_remaining_ms := NULL;
    lookup_key_ids := ARRAY[]::text[];
    lookup_retired_at_unix_ms := ARRAY[]::bigint[];
    lookup_destroy_after_unix_ms := ARRAY[]::bigint[];
    IF p_purpose IN ('rotation', 'maintenance') THEN
        metadata_canonical := v_current.metadata_canonical;
        active_key_id := v_current.active_key_id;
        active_since_unix_ms := v_current.active_since_unix_ms;
        active_write_deadline_unix_ms := v_current.active_write_deadline_unix_ms;
        audit_event_retention_ms := v_current.audit_event_retention_ms;
        retained_key_ids := v_current.retained_key_ids;
        retained_retired_at_unix_ms := v_current.retained_retired_at_unix_ms;
        retained_destroy_after_unix_ms := v_current.retained_destroy_after_unix_ms;
        used_key_id_count := v_history.used_key_id_count;
        used_key_ids_digest := v_history.used_key_ids_digest;
        used_key_ids := v_history.used_key_ids;
    ELSIF p_purpose = 'write' THEN
        active_key_id := v_current.active_key_id;
        active_since_unix_ms := v_current.active_since_unix_ms;
        active_write_deadline_unix_ms := v_current.active_write_deadline_unix_ms;
        IF v_now_unix_us < v_current.active_since_unix_ms::numeric * 1000 THEN
            outcome := 'not_active';
            RETURN NEXT;
            RETURN;
        END IF;
        IF v_now_unix_us >= v_current.active_write_deadline_unix_ms::numeric * 1000 THEN
            outcome := 'deadline_reached';
            RETURN NEXT;
            RETURN;
        END IF;
        IF EXISTS (
            SELECT 1
            FROM pg_catalog.unnest(v_current.retained_destroy_after_unix_ms) AS deadline(value)
            WHERE deadline.value::numeric * 1000 <= v_now_unix_us
        ) THEN
            outcome := 'retained_expired';
            RETURN NEXT;
            RETURN;
        END IF;
        active_write_remaining_ms := pg_catalog.floor(
            (v_current.active_write_deadline_unix_ms::numeric * 1000 - v_now_unix_us)
            / 1000
        )::bigint;
        IF active_write_remaining_ms < 1 THEN
            outcome := 'deadline_reached';
            active_write_remaining_ms := NULL;
            RETURN NEXT;
            RETURN;
        END IF;
    ELSIF p_purpose = 'lookup' THEN
        SELECT COALESCE(pg_catalog.array_agg(requested.key_id ORDER BY requested.ordinal), ARRAY[]::text[]),
               COALESCE(pg_catalog.array_agg(
                   CASE WHEN requested.key_id = v_current.active_key_id
                       THEN NULL::bigint ELSE retained.retired_at END
                   ORDER BY requested.ordinal
               ), ARRAY[]::bigint[]),
               COALESCE(pg_catalog.array_agg(
                   CASE WHEN requested.key_id = v_current.active_key_id
                       THEN NULL::bigint ELSE retained.destroy_after END
                   ORDER BY requested.ordinal
               ), ARRAY[]::bigint[])
        INTO lookup_key_ids, lookup_retired_at_unix_ms,
             lookup_destroy_after_unix_ms
        FROM pg_catalog.unnest(p_lookup_key_ids) WITH ORDINALITY
            AS requested(key_id, ordinal)
        LEFT JOIN LATERAL (
            SELECT v_current.retained_key_ids[retained_index] AS key_id,
                   v_current.retained_retired_at_unix_ms[retained_index] AS retired_at,
                   v_current.retained_destroy_after_unix_ms[retained_index] AS destroy_after
            FROM pg_catalog.generate_subscripts(
                v_current.retained_key_ids, 1
            ) AS retained_index
        ) AS retained
          ON retained.key_id = requested.key_id
        WHERE requested.key_id = v_current.active_key_id
           OR (
               retained.key_id IS NOT NULL
               AND retained.destroy_after::numeric * 1000 > v_now_unix_us
           );
        IF cardinality(lookup_key_ids) <> cardinality(p_lookup_key_ids) THEN
            outcome := 'unauthorized_lookup';
            lookup_key_ids := ARRAY[]::text[];
            lookup_retired_at_unix_ms := ARRAY[]::bigint[];
            lookup_destroy_after_unix_ms := ARRAY[]::bigint[];
            RETURN NEXT;
            RETURN;
        END IF;
    END IF;
    outcome := 'ready';
    IF clock_timestamp() - v_started_at > interval '5 seconds' THEN
        RAISE EXCEPTION 'audit pseudonym keyring snapshot exceeded its deadline'
            USING ERRCODE = '57014';
    END IF;
    RETURN NEXT;
END;
$function$;

CREATE OR REPLACE FUNCTION relay_state_api.audit_pseudonym_keyring_initialize_v1(
    p_generation bigint,
    p_metadata_digest bytea,
    p_metadata_canonical text,
    p_active_key_id text,
    p_active_since_unix_ms bigint,
    p_active_write_deadline_unix_ms bigint,
    p_audit_event_retention_ms bigint,
    p_retained_key_ids text[],
    p_retained_retired_at_unix_ms bigint[],
    p_retained_destroy_after_unix_ms bigint[],
    p_expected_chain_key_epoch_id text,
    p_expected_keyring_lock_key bigint
)
RETURNS TABLE (
    outcome text,
    stored_generation bigint,
    stored_metadata_digest bytea
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, relay_state_private
SET lock_timeout = '2s'
SET statement_timeout = '5s'
SET idle_in_transaction_session_timeout = '5s'
SET synchronous_commit = 'on'
AS $function$
DECLARE
    v_started_at timestamptz := clock_timestamp();
    v_now_unix_us numeric;
    v_runtime_oid oid;
    v_session_oid oid;
    v_current relay_state_private.audit_pseudonym_keyring%ROWTYPE;
    v_history record;
    v_expected_canonical text;
BEGIN
    PERFORM set_config('lock_timeout', '2s', false);
    PERFORM set_config('statement_timeout', '5s', false);
    PERFORM set_config('idle_in_transaction_session_timeout', '5s', false);
    PERFORM set_config('synchronous_commit', 'on', false);
    SELECT metadata.audit_pseudonym_maintenance_role_oid INTO v_runtime_oid
    FROM relay_state_private.state_plane_metadata AS metadata
    WHERE metadata.singleton = true;
    SELECT oid INTO v_session_oid FROM pg_catalog.pg_roles WHERE rolname = session_user;
    IF v_session_oid IS DISTINCT FROM v_runtime_oid THEN
        RAISE EXCEPTION 'audit pseudonym keyring caller is not bound'
            USING ERRCODE = '42501';
    END IF;
    IF current_setting('search_path') <> 'pg_catalog, relay_state_private'
       OR current_setting('lock_timeout') <> '2s'
       OR current_setting('statement_timeout') <> '5s'
       OR current_setting('idle_in_transaction_session_timeout') <> '5s'
       OR current_setting('synchronous_commit') <> 'on'
       OR current_setting('client_encoding') <> 'UTF8'
       OR current_setting('standard_conforming_strings') <> 'on'
       OR current_setting('session_replication_role') <> 'origin'
       OR current_setting('default_transaction_isolation') <> 'read committed'
       OR current_setting('transaction_isolation') <> 'read committed'
       OR current_setting('default_transaction_read_only') <> 'off'
       OR current_setting('transaction_read_only') <> 'off'
       OR pg_catalog.pg_is_in_recovery()
    THEN
        RAISE EXCEPTION 'audit pseudonym keyring runtime session is unsafe'
            USING ERRCODE = '55000';
    END IF;
    IF NOT relay_state_private.capability_valid_v1() THEN
        RAISE EXCEPTION 'audit pseudonym keyring capability unavailable'
            USING ERRCODE = '55000';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM relay_state_private.state_plane_metadata AS metadata
        WHERE metadata.singleton = true
          AND metadata.chain_key_epoch_id = p_expected_chain_key_epoch_id
          AND metadata.audit_pseudonym_keyring_lock_key = p_expected_keyring_lock_key
    ) THEN
        RAISE EXCEPTION 'audit pseudonym deployment authority drifted'
            USING ERRCODE = '55000';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(p_expected_keyring_lock_key);
    IF NOT EXISTS (
        SELECT 1
        FROM relay_state_private.state_plane_metadata AS metadata
        WHERE metadata.singleton = true
          AND metadata.chain_key_epoch_id = p_expected_chain_key_epoch_id
          AND metadata.audit_pseudonym_keyring_lock_key = p_expected_keyring_lock_key
    ) THEN
        RAISE EXCEPTION 'audit pseudonym deployment authority drifted'
            USING ERRCODE = '55000';
    END IF;
    DELETE FROM relay_state_private.audit_pseudonym_transition_context;
    SELECT row.* INTO v_current
    FROM relay_state_private.audit_pseudonym_keyring AS row
    WHERE row.singleton = true
    FOR UPDATE;
    IF FOUND THEN
        stored_generation := v_current.generation;
        stored_metadata_digest := v_current.metadata_digest;
        outcome := CASE
            WHEN v_current.generation = p_generation
             AND v_current.metadata_digest = p_metadata_digest
             AND v_current.metadata_canonical = p_metadata_canonical
            THEN 'identical' ELSE 'already_initialized' END;
        RETURN NEXT;
        RETURN;
    END IF;
    v_expected_canonical :=
        relay_state_private.audit_pseudonym_metadata_canonical_v1(
            p_generation, p_active_key_id, p_active_since_unix_ms,
            p_active_write_deadline_unix_ms, p_audit_event_retention_ms,
            p_retained_key_ids, p_retained_retired_at_unix_ms,
            p_retained_destroy_after_unix_ms
        );
    IF v_expected_canonical IS NULL
       OR p_metadata_canonical IS DISTINCT FROM v_expected_canonical
       OR p_metadata_digest IS NULL OR octet_length(p_metadata_digest) <> 32
       OR p_metadata_digest IS DISTINCT FROM pg_catalog.sha256(
           pg_catalog.convert_to(p_metadata_canonical, 'UTF8')
       )
       OR p_generation <> 1
       OR cardinality(p_retained_key_ids) <> 0
       OR EXISTS (SELECT 1 FROM relay_state_private.audit_pseudonym_used_key_id)
    THEN
        outcome := 'invalid';
        RETURN NEXT;
        RETURN;
    END IF;
    v_now_unix_us := pg_catalog.floor(extract(epoch FROM clock_timestamp()) * 1000000);
    IF v_now_unix_us < p_active_since_unix_ms::numeric * 1000 THEN
        outcome := 'not_active';
        RETURN NEXT;
        RETURN;
    END IF;
    IF v_now_unix_us >= p_active_write_deadline_unix_ms::numeric * 1000
       OR pg_catalog.floor(
           (p_active_write_deadline_unix_ms::numeric * 1000 - v_now_unix_us) / 1000
       ) < 1
    THEN
        outcome := 'deadline_reached';
        RETURN NEXT;
        RETURN;
    END IF;
    INSERT INTO relay_state_private.audit_pseudonym_used_key_id (
        key_id, first_generation, first_activated_at_unix_ms
    ) VALUES (p_active_key_id, p_generation, p_active_since_unix_ms);
    SELECT * INTO STRICT v_history
    FROM relay_state_private.audit_pseudonym_history_snapshot_v1();
    INSERT INTO relay_state_private.audit_pseudonym_keyring (
        singleton, generation, metadata_digest, metadata_canonical,
        active_key_id, active_since_unix_ms, active_write_deadline_unix_ms,
        audit_event_retention_ms, retained_key_ids,
        retained_retired_at_unix_ms, retained_destroy_after_unix_ms,
        used_key_id_count, used_key_ids_digest
    ) VALUES (
        true, p_generation, p_metadata_digest, p_metadata_canonical,
        p_active_key_id, p_active_since_unix_ms, p_active_write_deadline_unix_ms,
        p_audit_event_retention_ms, p_retained_key_ids,
        p_retained_retired_at_unix_ms, p_retained_destroy_after_unix_ms,
        v_history.used_key_id_count, v_history.used_key_ids_digest
    );
    IF clock_timestamp() - v_started_at > interval '5 seconds' THEN
        RAISE EXCEPTION 'audit pseudonym keyring initialization exceeded its deadline'
            USING ERRCODE = '57014';
    END IF;
    outcome := 'initialized';
    stored_generation := p_generation;
    stored_metadata_digest := p_metadata_digest;
    RETURN NEXT;
END;
$function$;

CREATE OR REPLACE FUNCTION relay_state_api.audit_pseudonym_keyring_rotate_v1(
    p_expected_generation bigint,
    p_expected_metadata_digest bytea,
    p_expected_history_count bigint,
    p_expected_history_digest bytea,
    p_transition_time_unix_ms bigint,
    p_successor_generation bigint,
    p_successor_metadata_digest bytea,
    p_successor_metadata_canonical text,
    p_successor_active_key_id text,
    p_successor_active_since_unix_ms bigint,
    p_successor_active_write_deadline_unix_ms bigint,
    p_successor_audit_event_retention_ms bigint,
    p_successor_retained_key_ids text[],
    p_successor_retained_retired_at_unix_ms bigint[],
    p_successor_retained_destroy_after_unix_ms bigint[],
    p_expected_chain_key_epoch_id text,
    p_expected_keyring_lock_key bigint
)
RETURNS TABLE (
    outcome text,
    stored_generation bigint,
    stored_metadata_digest bytea
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, relay_state_private
SET lock_timeout = '2s'
SET statement_timeout = '5s'
SET idle_in_transaction_session_timeout = '5s'
SET synchronous_commit = 'on'
AS $function$
DECLARE
    v_started_at timestamptz := clock_timestamp();
    v_now_unix_us numeric;
    v_runtime_oid oid;
    v_session_oid oid;
    v_current relay_state_private.audit_pseudonym_keyring%ROWTYPE;
    v_history record;
    v_context record;
    v_expected_canonical text;
    v_index integer;
    v_successor_index integer;
BEGIN
    PERFORM set_config('lock_timeout', '2s', false);
    PERFORM set_config('statement_timeout', '5s', false);
    PERFORM set_config('idle_in_transaction_session_timeout', '5s', false);
    PERFORM set_config('synchronous_commit', 'on', false);
    SELECT metadata.audit_pseudonym_maintenance_role_oid INTO v_runtime_oid
    FROM relay_state_private.state_plane_metadata AS metadata
    WHERE metadata.singleton = true;
    SELECT oid INTO v_session_oid FROM pg_catalog.pg_roles WHERE rolname = session_user;
    IF v_session_oid IS DISTINCT FROM v_runtime_oid THEN
        RAISE EXCEPTION 'audit pseudonym keyring caller is not bound'
            USING ERRCODE = '42501';
    END IF;
    IF current_setting('search_path') <> 'pg_catalog, relay_state_private'
       OR current_setting('lock_timeout') <> '2s'
       OR current_setting('statement_timeout') <> '5s'
       OR current_setting('idle_in_transaction_session_timeout') <> '5s'
       OR current_setting('synchronous_commit') <> 'on'
       OR current_setting('client_encoding') <> 'UTF8'
       OR current_setting('standard_conforming_strings') <> 'on'
       OR current_setting('session_replication_role') <> 'origin'
       OR current_setting('default_transaction_isolation') <> 'read committed'
       OR current_setting('transaction_isolation') <> 'read committed'
       OR current_setting('default_transaction_read_only') <> 'off'
       OR current_setting('transaction_read_only') <> 'off'
       OR pg_catalog.pg_is_in_recovery()
    THEN
        RAISE EXCEPTION 'audit pseudonym keyring runtime session is unsafe'
            USING ERRCODE = '55000';
    END IF;
    IF NOT relay_state_private.capability_valid_v1() THEN
        RAISE EXCEPTION 'audit pseudonym keyring capability unavailable'
            USING ERRCODE = '55000';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM relay_state_private.state_plane_metadata AS metadata
        WHERE metadata.singleton = true
          AND metadata.chain_key_epoch_id = p_expected_chain_key_epoch_id
          AND metadata.audit_pseudonym_keyring_lock_key = p_expected_keyring_lock_key
    ) THEN
        RAISE EXCEPTION 'audit pseudonym deployment authority drifted'
            USING ERRCODE = '55000';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(p_expected_keyring_lock_key);
    IF NOT EXISTS (
        SELECT 1
        FROM relay_state_private.state_plane_metadata AS metadata
        WHERE metadata.singleton = true
          AND metadata.chain_key_epoch_id = p_expected_chain_key_epoch_id
          AND metadata.audit_pseudonym_keyring_lock_key = p_expected_keyring_lock_key
    ) THEN
        RAISE EXCEPTION 'audit pseudonym deployment authority drifted'
            USING ERRCODE = '55000';
    END IF;
    SELECT row.* INTO v_current
    FROM relay_state_private.audit_pseudonym_keyring AS row
    WHERE row.singleton = true
    FOR UPDATE;
    IF NOT FOUND THEN
        outcome := 'stale';
        RETURN NEXT;
        RETURN;
    END IF;
    SELECT * INTO STRICT v_history
    FROM relay_state_private.audit_pseudonym_history_snapshot_v1();
    IF v_current.metadata_canonical IS DISTINCT FROM
           relay_state_private.audit_pseudonym_metadata_canonical_v1(
               v_current.generation, v_current.active_key_id,
               v_current.active_since_unix_ms,
               v_current.active_write_deadline_unix_ms,
               v_current.audit_event_retention_ms,
               v_current.retained_key_ids,
               v_current.retained_retired_at_unix_ms,
               v_current.retained_destroy_after_unix_ms
           )
       OR v_current.metadata_digest IS DISTINCT FROM pg_catalog.sha256(
           pg_catalog.convert_to(v_current.metadata_canonical, 'UTF8')
       )
       OR v_current.used_key_id_count IS DISTINCT FROM v_history.used_key_id_count
       OR v_current.used_key_ids_digest IS DISTINCT FROM v_history.used_key_ids_digest
       OR v_current.active_key_id <> ALL(v_history.used_key_ids)
       OR EXISTS (
           SELECT 1 FROM pg_catalog.unnest(v_current.retained_key_ids) AS retained(key_id)
           WHERE retained.key_id <> ALL(v_history.used_key_ids)
       )
    THEN
        outcome := 'authority_incomplete';
        RETURN NEXT;
        RETURN;
    END IF;
    IF v_current.generation IS DISTINCT FROM p_expected_generation
       OR v_current.metadata_digest IS DISTINCT FROM p_expected_metadata_digest
       OR v_history.used_key_id_count IS DISTINCT FROM p_expected_history_count
       OR v_history.used_key_ids_digest IS DISTINCT FROM p_expected_history_digest
    THEN
        outcome := 'stale';
        RETURN NEXT;
        RETURN;
    END IF;
    IF v_history.used_key_id_count >= 4096
       OR (
           SELECT COALESCE(sum(octet_length(history_row.key_id)), 0)::bigint
           FROM relay_state_private.audit_pseudonym_used_key_id AS history_row
       ) + COALESCE(octet_length(p_successor_active_key_id), 0) > 262144
    THEN
        outcome := 'history_full';
        RETURN NEXT;
        RETURN;
    END IF;
    SELECT context.* INTO v_context
    FROM relay_state_private.audit_pseudonym_transition_context AS context
    WHERE context.backend_pid = pg_catalog.pg_backend_pid()
      AND context.transaction_id = pg_catalog.txid_current()
    FOR UPDATE;
    v_now_unix_us := pg_catalog.floor(extract(epoch FROM clock_timestamp()) * 1000000);
    IF NOT FOUND
       OR v_context.transition_kind IS DISTINCT FROM 'rotation'
       OR v_context.transition_time_unix_ms IS DISTINCT FROM p_transition_time_unix_ms
       OR v_context.expected_generation IS DISTINCT FROM p_expected_generation
       OR v_context.expected_metadata_digest IS DISTINCT FROM p_expected_metadata_digest
       OR p_transition_time_unix_ms IS NULL
       OR p_transition_time_unix_ms NOT BETWEEN 0 AND 9007199254740991
       OR p_transition_time_unix_ms::numeric * 1000 > v_now_unix_us
       OR v_now_unix_us - p_transition_time_unix_ms::numeric * 1000 > 5000000
    THEN
        outcome := 'invalid';
        RETURN NEXT;
        RETURN;
    END IF;
    IF v_now_unix_us > v_current.active_write_deadline_unix_ms::numeric * 1000 THEN
        outcome := 'deadline_reached';
        RETURN NEXT;
        RETURN;
    END IF;
    v_expected_canonical :=
        relay_state_private.audit_pseudonym_metadata_canonical_v1(
            p_successor_generation, p_successor_active_key_id,
            p_successor_active_since_unix_ms,
            p_successor_active_write_deadline_unix_ms,
            p_successor_audit_event_retention_ms,
            p_successor_retained_key_ids,
            p_successor_retained_retired_at_unix_ms,
            p_successor_retained_destroy_after_unix_ms
        );
    IF v_expected_canonical IS NULL
       OR p_successor_metadata_canonical IS DISTINCT FROM v_expected_canonical
       OR p_successor_metadata_digest IS NULL
       OR octet_length(p_successor_metadata_digest) <> 32
       OR p_successor_metadata_digest IS DISTINCT FROM pg_catalog.sha256(
           pg_catalog.convert_to(p_successor_metadata_canonical, 'UTF8')
       )
       OR p_successor_metadata_digest = v_current.metadata_digest
       OR p_successor_generation <= v_current.generation
       OR p_successor_active_since_unix_ms <> p_transition_time_unix_ms
       OR p_successor_active_since_unix_ms <= v_current.active_since_unix_ms
       OR p_successor_active_write_deadline_unix_ms
            <= v_current.active_write_deadline_unix_ms
       OR p_successor_active_write_deadline_unix_ms::numeric * 1000 <= v_now_unix_us
       OR p_successor_audit_event_retention_ms < v_current.audit_event_retention_ms
       OR p_successor_active_key_id = ANY(v_history.used_key_ids)
       OR EXISTS (
           SELECT 1
           FROM pg_catalog.unnest(p_successor_retained_destroy_after_unix_ms) AS deadline(value)
           WHERE deadline.value::numeric * 1000 <= v_now_unix_us
       )
    THEN
        outcome := CASE WHEN p_successor_active_key_id = ANY(v_history.used_key_ids)
            THEN 'reused' ELSE 'invalid' END;
        RETURN NEXT;
        RETURN;
    END IF;
    v_successor_index := pg_catalog.array_position(
        p_successor_retained_key_ids, v_current.active_key_id
    );
    IF v_successor_index IS NULL
       OR p_successor_retained_retired_at_unix_ms[v_successor_index]
            <> p_transition_time_unix_ms
    THEN
        outcome := 'invalid';
        RETURN NEXT;
        RETURN;
    END IF;
    FOR v_index IN 1..cardinality(v_current.retained_key_ids) LOOP
        v_successor_index := pg_catalog.array_position(
            p_successor_retained_key_ids, v_current.retained_key_ids[v_index]
        );
        IF v_current.retained_destroy_after_unix_ms[v_index] <= p_transition_time_unix_ms THEN
            IF v_successor_index IS NOT NULL THEN
                outcome := 'invalid';
                RETURN NEXT;
                RETURN;
            END IF;
        ELSIF v_successor_index IS NULL
           OR p_successor_retained_retired_at_unix_ms[v_successor_index]
                <> v_current.retained_retired_at_unix_ms[v_index]
           OR p_successor_retained_destroy_after_unix_ms[v_successor_index]
                < v_current.retained_destroy_after_unix_ms[v_index]
        THEN
            outcome := 'invalid';
            RETURN NEXT;
            RETURN;
        END IF;
    END LOOP;
    FOR v_index IN 1..cardinality(p_successor_retained_key_ids) LOOP
        IF p_successor_retained_key_ids[v_index] <> v_current.active_key_id
           AND pg_catalog.array_position(
               v_current.retained_key_ids, p_successor_retained_key_ids[v_index]
           ) IS NULL
        THEN
            outcome := 'invalid';
            RETURN NEXT;
            RETURN;
        END IF;
    END LOOP;
    INSERT INTO relay_state_private.audit_pseudonym_used_key_id (
        key_id, first_generation, first_activated_at_unix_ms
    ) VALUES (
        p_successor_active_key_id, p_successor_generation,
        p_successor_active_since_unix_ms
    ) ON CONFLICT (key_id) DO NOTHING;
    IF NOT FOUND THEN
        outcome := 'reused';
        RETURN NEXT;
        RETURN;
    END IF;
    SELECT * INTO STRICT v_history
    FROM relay_state_private.audit_pseudonym_history_snapshot_v1();
    DELETE FROM relay_state_private.audit_pseudonym_transition_context AS context
    WHERE context.backend_pid = pg_catalog.pg_backend_pid()
      AND context.transaction_id = pg_catalog.txid_current();
    IF NOT FOUND THEN
        RAISE EXCEPTION 'audit pseudonym rotation context was not consumed'
            USING ERRCODE = '55000';
    END IF;
    UPDATE relay_state_private.audit_pseudonym_keyring AS row
    SET generation = p_successor_generation,
        metadata_digest = p_successor_metadata_digest,
        metadata_canonical = p_successor_metadata_canonical,
        active_key_id = p_successor_active_key_id,
        active_since_unix_ms = p_successor_active_since_unix_ms,
        active_write_deadline_unix_ms = p_successor_active_write_deadline_unix_ms,
        audit_event_retention_ms = p_successor_audit_event_retention_ms,
        retained_key_ids = p_successor_retained_key_ids,
        retained_retired_at_unix_ms = p_successor_retained_retired_at_unix_ms,
        retained_destroy_after_unix_ms = p_successor_retained_destroy_after_unix_ms,
        used_key_id_count = v_history.used_key_id_count,
        used_key_ids_digest = v_history.used_key_ids_digest,
        transitioned_at = clock_timestamp()
    WHERE row.singleton = true
      AND row.generation = p_expected_generation
      AND row.metadata_digest = p_expected_metadata_digest;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'audit pseudonym rotation lost its locked authority'
            USING ERRCODE = '55000';
    END IF;
    IF clock_timestamp() - v_started_at > interval '5 seconds' THEN
        RAISE EXCEPTION 'audit pseudonym keyring rotation exceeded its deadline'
            USING ERRCODE = '57014';
    END IF;
    outcome := 'rotated';
    stored_generation := p_successor_generation;
    stored_metadata_digest := p_successor_metadata_digest;
    RETURN NEXT;
END;
$function$;

CREATE OR REPLACE FUNCTION relay_state_api.audit_pseudonym_keyring_maintain_v1(
    p_expected_generation bigint,
    p_expected_metadata_digest bytea,
    p_expected_history_count bigint,
    p_expected_history_digest bytea,
    p_transition_time_unix_ms bigint,
    p_successor_generation bigint,
    p_successor_metadata_digest bytea,
    p_successor_metadata_canonical text,
    p_successor_active_key_id text,
    p_successor_active_since_unix_ms bigint,
    p_successor_active_write_deadline_unix_ms bigint,
    p_successor_audit_event_retention_ms bigint,
    p_successor_retained_key_ids text[],
    p_successor_retained_retired_at_unix_ms bigint[],
    p_successor_retained_destroy_after_unix_ms bigint[],
    p_expected_chain_key_epoch_id text,
    p_expected_keyring_lock_key bigint
)
RETURNS TABLE (
    outcome text,
    stored_generation bigint,
    stored_metadata_digest bytea
)
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = pg_catalog, relay_state_private
SET lock_timeout = '2s'
SET statement_timeout = '5s'
SET idle_in_transaction_session_timeout = '5s'
SET synchronous_commit = 'on'
AS $function$
DECLARE
    v_started_at timestamptz := clock_timestamp();
    v_now_unix_us numeric;
    v_runtime_oid oid;
    v_session_oid oid;
    v_current relay_state_private.audit_pseudonym_keyring%ROWTYPE;
    v_history record;
    v_context record;
    v_expected_canonical text;
    v_index integer;
    v_successor_index integer;
BEGIN
    PERFORM set_config('lock_timeout', '2s', false);
    PERFORM set_config('statement_timeout', '5s', false);
    PERFORM set_config('idle_in_transaction_session_timeout', '5s', false);
    PERFORM set_config('synchronous_commit', 'on', false);
    SELECT metadata.audit_pseudonym_maintenance_role_oid INTO v_runtime_oid
    FROM relay_state_private.state_plane_metadata AS metadata
    WHERE metadata.singleton = true;
    SELECT oid INTO v_session_oid FROM pg_catalog.pg_roles WHERE rolname = session_user;
    IF v_session_oid IS DISTINCT FROM v_runtime_oid THEN
        RAISE EXCEPTION 'audit pseudonym keyring caller is not bound'
            USING ERRCODE = '42501';
    END IF;
    IF current_setting('search_path') <> 'pg_catalog, relay_state_private'
       OR current_setting('lock_timeout') <> '2s'
       OR current_setting('statement_timeout') <> '5s'
       OR current_setting('idle_in_transaction_session_timeout') <> '5s'
       OR current_setting('synchronous_commit') <> 'on'
       OR current_setting('client_encoding') <> 'UTF8'
       OR current_setting('standard_conforming_strings') <> 'on'
       OR current_setting('session_replication_role') <> 'origin'
       OR current_setting('default_transaction_isolation') <> 'read committed'
       OR current_setting('transaction_isolation') <> 'read committed'
       OR current_setting('default_transaction_read_only') <> 'off'
       OR current_setting('transaction_read_only') <> 'off'
       OR pg_catalog.pg_is_in_recovery()
    THEN
        RAISE EXCEPTION 'audit pseudonym keyring runtime session is unsafe'
            USING ERRCODE = '55000';
    END IF;
    IF NOT relay_state_private.capability_valid_v1() THEN
        RAISE EXCEPTION 'audit pseudonym keyring capability unavailable'
            USING ERRCODE = '55000';
    END IF;
    IF NOT EXISTS (
        SELECT 1
        FROM relay_state_private.state_plane_metadata AS metadata
        WHERE metadata.singleton = true
          AND metadata.chain_key_epoch_id = p_expected_chain_key_epoch_id
          AND metadata.audit_pseudonym_keyring_lock_key = p_expected_keyring_lock_key
    ) THEN
        RAISE EXCEPTION 'audit pseudonym deployment authority drifted'
            USING ERRCODE = '55000';
    END IF;
    PERFORM pg_catalog.pg_advisory_xact_lock(p_expected_keyring_lock_key);
    IF NOT EXISTS (
        SELECT 1
        FROM relay_state_private.state_plane_metadata AS metadata
        WHERE metadata.singleton = true
          AND metadata.chain_key_epoch_id = p_expected_chain_key_epoch_id
          AND metadata.audit_pseudonym_keyring_lock_key = p_expected_keyring_lock_key
    ) THEN
        RAISE EXCEPTION 'audit pseudonym deployment authority drifted'
            USING ERRCODE = '55000';
    END IF;
    SELECT row.* INTO v_current
    FROM relay_state_private.audit_pseudonym_keyring AS row
    WHERE row.singleton = true
    FOR UPDATE;
    IF NOT FOUND THEN
        outcome := 'stale';
        RETURN NEXT;
        RETURN;
    END IF;
    SELECT * INTO STRICT v_history
    FROM relay_state_private.audit_pseudonym_history_snapshot_v1();
    IF v_current.metadata_canonical IS DISTINCT FROM
           relay_state_private.audit_pseudonym_metadata_canonical_v1(
               v_current.generation, v_current.active_key_id,
               v_current.active_since_unix_ms,
               v_current.active_write_deadline_unix_ms,
               v_current.audit_event_retention_ms,
               v_current.retained_key_ids,
               v_current.retained_retired_at_unix_ms,
               v_current.retained_destroy_after_unix_ms
           )
       OR v_current.metadata_digest IS DISTINCT FROM pg_catalog.sha256(
           pg_catalog.convert_to(v_current.metadata_canonical, 'UTF8')
       )
       OR v_current.used_key_id_count IS DISTINCT FROM v_history.used_key_id_count
       OR v_current.used_key_ids_digest IS DISTINCT FROM v_history.used_key_ids_digest
       OR v_current.active_key_id <> ALL(v_history.used_key_ids)
       OR EXISTS (
           SELECT 1 FROM pg_catalog.unnest(v_current.retained_key_ids) AS retained(key_id)
           WHERE retained.key_id <> ALL(v_history.used_key_ids)
       )
    THEN
        outcome := 'authority_incomplete';
        RETURN NEXT;
        RETURN;
    END IF;
    IF v_current.generation IS DISTINCT FROM p_expected_generation
       OR v_current.metadata_digest IS DISTINCT FROM p_expected_metadata_digest
       OR v_history.used_key_id_count IS DISTINCT FROM p_expected_history_count
       OR v_history.used_key_ids_digest IS DISTINCT FROM p_expected_history_digest
    THEN
        outcome := 'stale';
        RETURN NEXT;
        RETURN;
    END IF;
    SELECT context.* INTO v_context
    FROM relay_state_private.audit_pseudonym_transition_context AS context
    WHERE context.backend_pid = pg_catalog.pg_backend_pid()
      AND context.transaction_id = pg_catalog.txid_current()
    FOR UPDATE;
    v_now_unix_us := pg_catalog.floor(extract(epoch FROM clock_timestamp()) * 1000000);
    IF NOT FOUND
       OR v_context.transition_kind IS DISTINCT FROM 'maintenance'
       OR v_context.transition_time_unix_ms IS DISTINCT FROM p_transition_time_unix_ms
       OR v_context.expected_generation IS DISTINCT FROM p_expected_generation
       OR v_context.expected_metadata_digest IS DISTINCT FROM p_expected_metadata_digest
       OR p_transition_time_unix_ms IS NULL
       OR p_transition_time_unix_ms NOT BETWEEN 0 AND 9007199254740991
       OR p_transition_time_unix_ms::numeric * 1000 > v_now_unix_us
       OR v_now_unix_us - p_transition_time_unix_ms::numeric * 1000 > 5000000
    THEN
        outcome := 'invalid';
        RETURN NEXT;
        RETURN;
    END IF;
    IF v_now_unix_us >= v_current.active_write_deadline_unix_ms::numeric * 1000 THEN
        outcome := 'deadline_reached';
        RETURN NEXT;
        RETURN;
    END IF;
    v_expected_canonical :=
        relay_state_private.audit_pseudonym_metadata_canonical_v1(
            p_successor_generation, p_successor_active_key_id,
            p_successor_active_since_unix_ms,
            p_successor_active_write_deadline_unix_ms,
            p_successor_audit_event_retention_ms,
            p_successor_retained_key_ids,
            p_successor_retained_retired_at_unix_ms,
            p_successor_retained_destroy_after_unix_ms
        );
    IF v_expected_canonical IS NULL
       OR p_successor_metadata_canonical IS DISTINCT FROM v_expected_canonical
       OR p_successor_metadata_digest IS NULL
       OR octet_length(p_successor_metadata_digest) <> 32
       OR p_successor_metadata_digest IS DISTINCT FROM pg_catalog.sha256(
           pg_catalog.convert_to(p_successor_metadata_canonical, 'UTF8')
       )
       OR p_successor_metadata_digest = v_current.metadata_digest
       OR p_successor_generation <= v_current.generation
       OR p_successor_active_key_id <> v_current.active_key_id
       OR p_successor_active_since_unix_ms <> v_current.active_since_unix_ms
       OR p_successor_active_write_deadline_unix_ms
            <> v_current.active_write_deadline_unix_ms
       OR p_successor_audit_event_retention_ms < v_current.audit_event_retention_ms
    THEN
        outcome := 'invalid';
        RETURN NEXT;
        RETURN;
    END IF;
    FOR v_index IN 1..cardinality(v_current.retained_key_ids) LOOP
        v_successor_index := pg_catalog.array_position(
            p_successor_retained_key_ids, v_current.retained_key_ids[v_index]
        );
        IF v_current.retained_destroy_after_unix_ms[v_index]::numeric * 1000
                <= v_now_unix_us
        THEN
            IF v_successor_index IS NOT NULL THEN
                outcome := 'invalid';
                RETURN NEXT;
                RETURN;
            END IF;
        ELSIF v_successor_index IS NULL
           OR p_successor_retained_retired_at_unix_ms[v_successor_index]
                <> v_current.retained_retired_at_unix_ms[v_index]
           OR p_successor_retained_destroy_after_unix_ms[v_successor_index]
                <> v_current.retained_destroy_after_unix_ms[v_index]
        THEN
            outcome := 'invalid';
            RETURN NEXT;
            RETURN;
        END IF;
    END LOOP;
    FOR v_index IN 1..cardinality(p_successor_retained_key_ids) LOOP
        IF pg_catalog.array_position(
            v_current.retained_key_ids, p_successor_retained_key_ids[v_index]
        ) IS NULL THEN
            outcome := 'invalid';
            RETURN NEXT;
            RETURN;
        END IF;
    END LOOP;
    DELETE FROM relay_state_private.audit_pseudonym_transition_context AS context
    WHERE context.backend_pid = pg_catalog.pg_backend_pid()
      AND context.transaction_id = pg_catalog.txid_current();
    IF NOT FOUND THEN
        RAISE EXCEPTION 'audit pseudonym maintenance context was not consumed'
            USING ERRCODE = '55000';
    END IF;
    UPDATE relay_state_private.audit_pseudonym_keyring AS row
    SET generation = p_successor_generation,
        metadata_digest = p_successor_metadata_digest,
        metadata_canonical = p_successor_metadata_canonical,
        active_key_id = p_successor_active_key_id,
        active_since_unix_ms = p_successor_active_since_unix_ms,
        active_write_deadline_unix_ms = p_successor_active_write_deadline_unix_ms,
        audit_event_retention_ms = p_successor_audit_event_retention_ms,
        retained_key_ids = p_successor_retained_key_ids,
        retained_retired_at_unix_ms = p_successor_retained_retired_at_unix_ms,
        retained_destroy_after_unix_ms = p_successor_retained_destroy_after_unix_ms,
        transitioned_at = clock_timestamp()
    WHERE row.singleton = true
      AND row.generation = p_expected_generation
      AND row.metadata_digest = p_expected_metadata_digest
      AND row.used_key_id_count = p_expected_history_count
      AND row.used_key_ids_digest = p_expected_history_digest;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'audit pseudonym maintenance lost its locked authority'
            USING ERRCODE = '55000';
    END IF;
    IF clock_timestamp() - v_started_at > interval '5 seconds' THEN
        RAISE EXCEPTION 'audit pseudonym keyring maintenance exceeded its deadline'
            USING ERRCODE = '57014';
    END IF;
    outcome := 'maintained';
    stored_generation := p_successor_generation;
    stored_metadata_digest := p_successor_metadata_digest;
    RETURN NEXT;
END;
$function$;

ALTER FUNCTION relay_state_private.audit_pseudonym_metadata_canonical_v1(
    bigint, text, bigint, bigint, bigint, text[], bigint[], bigint[]
) OWNER TO CURRENT_USER;
ALTER FUNCTION relay_state_private.audit_pseudonym_history_snapshot_v1()
    OWNER TO CURRENT_USER;
ALTER FUNCTION relay_state_private.consultation_completion_seed_valid_v1(text)
    OWNER TO CURRENT_USER;
ALTER FUNCTION relay_state_private.consultation_recursive_schema_valid_v1(jsonb, integer)
    OWNER TO CURRENT_USER;
ALTER FUNCTION relay_state_private.jsonb_object_key_count_v1(jsonb)
    OWNER TO CURRENT_USER;
ALTER FUNCTION relay_state_private.capability_valid_v1() OWNER TO CURRENT_USER;
ALTER FUNCTION relay_state_private.consultation_completion_snapshot_internal_v1(
    text, text, bigint, text[], smallint[]
) OWNER TO CURRENT_USER;
ALTER FUNCTION relay_state_private.consultation_completion_cas_internal_v1(
    text, text, text, bigint, bigint, text[], smallint[], bytea, bigint, bytea,
    text, bigint, text, text, bytea, text
) OWNER TO CURRENT_USER;
ALTER FUNCTION relay_state_api.audit_phase_snapshot_v1(
    text, text, text, bytea, text, text, bigint, bytea, bigint
)
    OWNER TO CURRENT_USER;
ALTER FUNCTION relay_state_api.audit_phase_duplicate_v1(
    text, text, text, bytea, text, bigint
)
    OWNER TO CURRENT_USER;
ALTER FUNCTION relay_state_api.audit_phase_cas_v1(
    text, text, text, bytea, bigint, bytea, text, bigint,
    text, text, bytea, text, bytea, text, bigint, bytea, text, bigint
) OWNER TO CURRENT_USER;
ALTER FUNCTION relay_state_api.consultation_attempt_intent_snapshot_v1(
    text, bytea, text, bytea, text, bytea, text, bigint, bytea, bigint,
    text, bigint, integer, bigint, text[], smallint[], text, bigint
) OWNER TO CURRENT_USER;
ALTER FUNCTION relay_state_api.consultation_attempt_intent_cas_v1(
    text, bytea, bigint, bytea, text, bigint, text, text, bytea, text,
    bytea, text, bytea, text, bigint, bytea, bigint, text, bigint, integer,
    bigint, text[], smallint[], text, bigint
) OWNER TO CURRENT_USER;
ALTER FUNCTION relay_state_api.consultation_completion_snapshot_normal_v1(
    text, bigint, text, bigint, bigint, text[], smallint[], text, bigint,
    bytea, text, bigint
) OWNER TO CURRENT_USER;
ALTER FUNCTION relay_state_api.consultation_completion_snapshot_recovery_v1(
    text, bigint, text, bigint, text, bigint
) OWNER TO CURRENT_USER;
ALTER FUNCTION relay_state_api.consultation_completion_cas_normal_v1(
    text, bigint, text, bigint, bigint, text[], smallint[], text, bigint,
    bytea, bytea, bigint, bytea, text, bigint, text, text, bytea, text, bigint
) OWNER TO CURRENT_USER;
ALTER FUNCTION relay_state_api.consultation_completion_cas_unfinished_v1(
    text, bigint, text, bigint, bigint, text[], smallint[], text, bigint,
    bytea, bytea, bigint, bytea, text, bigint, text, text, bytea, text, bigint
) OWNER TO CURRENT_USER;
ALTER FUNCTION relay_state_api.consultation_completion_cas_recovery_v1(
    text, bigint, text, bigint, bytea, bigint, bytea, text, bigint, text,
    text, bytea, text, bigint
) OWNER TO CURRENT_USER;
ALTER FUNCTION relay_state_api.audit_readiness_v1(text) OWNER TO CURRENT_USER;
ALTER FUNCTION relay_state_api.audit_pseudonym_keyring_readiness_v1(text, text)
    OWNER TO CURRENT_USER;
ALTER FUNCTION relay_state_api.serving_fence_acquire_v1(bigint, text)
    OWNER TO CURRENT_USER;
ALTER FUNCTION relay_state_api.serving_fence_finalize_v1(bigint, text, bigint)
    OWNER TO CURRENT_USER;
ALTER FUNCTION relay_state_api.serving_fence_open_after_recovery_v1(bigint, text, bigint)
    OWNER TO CURRENT_USER;
ALTER FUNCTION relay_state_api.serving_fence_status_v1(bigint, text, bigint)
    OWNER TO CURRENT_USER;
ALTER FUNCTION relay_state_api.dispatch_permit_authorize_v1(
    bigint, text, bigint, text, text, smallint, text, bigint
) OWNER TO CURRENT_USER;
ALTER FUNCTION relay_state_api.serving_fence_release_v1(bigint, text, bigint)
    OWNER TO CURRENT_USER;
ALTER FUNCTION relay_state_api.quota_reserve_v1(text, text, bigint, integer, integer)
    OWNER TO CURRENT_USER;
ALTER FUNCTION relay_state_api.audit_pseudonym_keyring_snapshot_v1(
    text, text[], text, bigint
)
    OWNER TO CURRENT_USER;
ALTER FUNCTION relay_state_api.audit_pseudonym_keyring_initialize_v1(
    bigint, bytea, text, text, bigint, bigint, bigint, text[], bigint[], bigint[],
    text, bigint
) OWNER TO CURRENT_USER;
ALTER FUNCTION relay_state_api.audit_pseudonym_keyring_rotate_v1(
    bigint, bytea, bigint, bytea, bigint, bigint, bytea, text, text,
    bigint, bigint, bigint, text[], bigint[], bigint[], text, bigint
) OWNER TO CURRENT_USER;
ALTER FUNCTION relay_state_api.audit_pseudonym_keyring_maintain_v1(
    bigint, bytea, bigint, bytea, bigint, bigint, bytea, text, text,
    bigint, bigint, bigint, text[], bigint[], bigint[], text, bigint
) OWNER TO CURRENT_USER;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA relay_state_private FROM PUBLIC;
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA relay_state_api FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA relay_state_private REVOKE ALL ON FUNCTIONS FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA relay_state_api REVOKE ALL ON FUNCTIONS FROM PUBLIC;
"#;

/// Non-secret configured audit-chain key epoch identity.
///
/// This coordinates replicas. It does not authenticate key material or prove
/// that two deployments did not reuse an identifier for different secrets.
#[derive(Clone, PartialEq, Eq)]
pub(crate) struct AuditChainKeyEpochId(String);

impl AuditChainKeyEpochId {
    pub(crate) fn parse(value: &str) -> Result<Self, StatePlaneInstallError> {
        let mut chars = value.chars();
        let Some(first) = chars.next() else {
            return Err(StatePlaneInstallError::InvalidChainKeyEpochId);
        };
        if value.len() > 64
            || !first.is_ascii_alphanumeric()
            || !chars.all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | ':' | '-')
            })
        {
            return Err(StatePlaneInstallError::InvalidChainKeyEpochId);
        }
        Ok(Self(value.to_owned()))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for AuditChainKeyEpochId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_tuple("AuditChainKeyEpochId")
            .field(&self.0)
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct RuntimeDatabaseRole(String);

impl RuntimeDatabaseRole {
    pub(crate) fn parse(value: &str) -> Result<Self, StatePlaneInstallError> {
        let mut chars = value.chars();
        let Some(first) = chars.next() else {
            return Err(StatePlaneInstallError::InvalidRuntimeRole);
        };
        if value.len() > 63
            || !(first == '_' || first.is_ascii_alphabetic())
            || !chars.all(|character| character == '_' || character.is_ascii_alphanumeric())
        {
            return Err(StatePlaneInstallError::InvalidRuntimeRole);
        }
        Ok(Self(value.to_owned()))
    }

    fn quoted(&self) -> String {
        format!("\"{}\"", self.0)
    }
}

impl fmt::Debug for RuntimeDatabaseRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RuntimeDatabaseRole(<redacted>)")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct AuditPseudonymMaintenanceDatabaseRole(String);

impl AuditPseudonymMaintenanceDatabaseRole {
    pub(crate) fn parse(value: &str) -> Result<Self, StatePlaneInstallError> {
        validate_database_role_name(value)
            .then(|| Self(value.to_owned()))
            .ok_or(StatePlaneInstallError::InvalidPseudonymMaintenanceRole)
    }

    fn quoted(&self) -> String {
        format!("\"{}\"", self.0)
    }
}

impl fmt::Debug for AuditPseudonymMaintenanceDatabaseRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuditPseudonymMaintenanceDatabaseRole(<redacted>)")
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct AuditPseudonymReaderDatabaseRole(String);

impl AuditPseudonymReaderDatabaseRole {
    pub(crate) fn parse(value: &str) -> Result<Self, StatePlaneInstallError> {
        validate_database_role_name(value)
            .then(|| Self(value.to_owned()))
            .ok_or(StatePlaneInstallError::InvalidPseudonymReaderRole)
    }

    fn quoted(&self) -> String {
        format!("\"{}\"", self.0)
    }
}

impl fmt::Debug for AuditPseudonymReaderDatabaseRole {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuditPseudonymReaderDatabaseRole(<redacted>)")
    }
}

fn validate_database_role_name(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    value.len() <= 63
        && (first == '_' || first.is_ascii_alphabetic())
        && chars.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) struct AuditPseudonymKeyringLockKey(i64);

impl AuditPseudonymKeyringLockKey {
    pub(crate) fn new(value: i64) -> Result<Self, StatePlaneInstallError> {
        if value == 0 || value == MIGRATION_ADVISORY_LOCK_KEY_V1 {
            return Err(StatePlaneInstallError::InvalidPseudonymKeyringLockKey);
        }
        Ok(Self(value))
    }

    pub(crate) const fn as_i64(self) -> i64 {
        self.0
    }
}

impl fmt::Debug for AuditPseudonymKeyringLockKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AuditPseudonymKeyringLockKey(<deployment authority>)")
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum StatePlaneInstallError {
    #[error("Relay state-plane runtime role is invalid")]
    InvalidRuntimeRole,
    #[error("Relay audit-pseudonym maintenance role is invalid")]
    InvalidPseudonymMaintenanceRole,
    #[error("Relay audit-pseudonym reader role is invalid")]
    InvalidPseudonymReaderRole,
    #[error("Relay state-plane authority roles must be distinct")]
    AuthorityRoleCollision,
    #[error("Relay audit-pseudonym keyring lock key is invalid")]
    InvalidPseudonymKeyringLockKey,
    #[error("Relay audit-pseudonym keyring lock key collides with another state-plane lock")]
    PseudonymKeyringLockKeyCollision,
    #[error("Relay state-plane chain-key epoch identifier is invalid")]
    InvalidChainKeyEpochId,
    #[error("Relay state-plane installation session is not an isolated owner migration")]
    InvalidMigrationAuthority,
    #[error("Relay state-plane owner role is not isolated")]
    OwnerRoleNotIsolated,
    #[error("Relay state-plane runtime role is not isolated")]
    RuntimeRoleNotIsolated,
    #[error("Relay audit-pseudonym maintenance role is not isolated")]
    PseudonymMaintenanceRoleNotIsolated,
    #[error("Relay audit-pseudonym reader role is not isolated")]
    PseudonymReaderRoleNotIsolated,
    #[error("Relay state-plane database configuration is unsupported")]
    UnsafeDatabaseConfiguration,
    #[error("Relay state-plane capability catalog has drifted")]
    CapabilityDrift,
    #[error("Relay state-plane installation is unavailable")]
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(super) enum RuntimeCapabilityError {
    #[error("Relay state-plane runtime identity is not bound")]
    WrongRuntimeIdentity,
    #[error("Relay state-plane capability has drifted")]
    Drift,
    #[error("Relay state-plane capability is unavailable")]
    Unavailable,
}

#[derive(Debug, Clone, Copy)]
struct BoundRoleOids {
    owner: i64,
    runtime: i64,
    maintenance: i64,
    reader: i64,
}

pub(crate) async fn install_postgres_state_plane_v1(
    client: &mut Client,
    runtime_role: &RuntimeDatabaseRole,
    chain_key_epoch_id: &AuditChainKeyEpochId,
    serving_fence_lock_key: ServingFenceLockKey,
    maintenance_role: &AuditPseudonymMaintenanceDatabaseRole,
    reader_role: &AuditPseudonymReaderDatabaseRole,
    audit_pseudonym_keyring_lock_key: AuditPseudonymKeyringLockKey,
) -> Result<(), StatePlaneInstallError> {
    if runtime_role.0 == maintenance_role.0
        || runtime_role.0 == reader_role.0
        || maintenance_role.0 == reader_role.0
    {
        return Err(StatePlaneInstallError::AuthorityRoleCollision);
    }
    if serving_fence_lock_key.as_i64() == audit_pseudonym_keyring_lock_key.as_i64() {
        return Err(StatePlaneInstallError::PseudonymKeyringLockKeyCollision);
    }
    let transaction = client
        .transaction()
        .await
        .map_err(|_| StatePlaneInstallError::Unavailable)?;
    transaction
        .batch_execute(INSTALL_TRANSACTION_LIMITS_SQL)
        .await
        .map_err(|_| StatePlaneInstallError::Unavailable)?;
    transaction
        .query_one(
            "SELECT pg_catalog.pg_advisory_xact_lock($1)",
            &[&MIGRATION_ADVISORY_LOCK_KEY_V1],
        )
        .await
        .map_err(|_| StatePlaneInstallError::Unavailable)?;

    let role_oids =
        validate_install_roles(&transaction, runtime_role, maintenance_role, reader_role).await?;
    let schema_count = try_i64(
        &transaction
            .query_one(
                "SELECT count(*) AS schema_count FROM pg_catalog.pg_namespace \
                 WHERE nspname IN ('relay_state_private', 'relay_state_api')",
                &[],
            )
            .await
            .map_err(|_| StatePlaneInstallError::Unavailable)?,
        "schema_count",
    )?;
    if schema_count != 0 && schema_count != 2 {
        return Err(StatePlaneInstallError::CapabilityDrift);
    }
    if schema_count == 2 {
        let catalog_shape = transaction
            .query_one(
                "SELECT ( \
                     SELECT count(*) = 2 \
                            AND bool_and(namespace.nspowner = $1::bigint::oid) \
                     FROM pg_catalog.pg_namespace AS namespace \
                     WHERE namespace.nspname IN ('relay_state_private', 'relay_state_api') \
                 ) AS schemas_owned, \
                 EXISTS ( \
                     SELECT 1 FROM pg_catalog.pg_class AS relation \
                     JOIN pg_catalog.pg_namespace AS namespace \
                       ON namespace.oid = relation.relnamespace \
                     WHERE namespace.nspname = 'relay_state_private' \
                       AND relation.relname = 'state_plane_metadata' \
                       AND relation.relkind IN ('r', 'p') \
                 ) AS metadata_exists, \
                 NOT EXISTS ( \
                     SELECT 1 FROM pg_catalog.pg_class AS relation \
                     JOIN pg_catalog.pg_namespace AS namespace \
                       ON namespace.oid = relation.relnamespace \
                     WHERE namespace.nspname = 'relay_state_private' \
                       AND relation.relname = 'state_plane_metadata' \
                       AND relation.relowner <> $1::bigint::oid \
                 ) AS metadata_owned",
                &[&role_oids.owner],
            )
            .await
            .map_err(|_| StatePlaneInstallError::Unavailable)?;
        if !try_bool(&catalog_shape, "schemas_owned")?
            || !try_bool(&catalog_shape, "metadata_exists")?
            || !try_bool(&catalog_shape, "metadata_owned")?
            || !owner_capability_matches(
                &transaction,
                role_oids,
                chain_key_epoch_id,
                serving_fence_lock_key,
                audit_pseudonym_keyring_lock_key,
            )
            .await?
        {
            return Err(StatePlaneInstallError::CapabilityDrift);
        }
    }

    transaction
        .batch_execute(POSTGRES_STATE_PLANE_MIGRATION_V1)
        .await
        .map_err(|_| StatePlaneInstallError::Unavailable)?;
    bind_or_validate_metadata(
        &transaction,
        role_oids,
        chain_key_epoch_id,
        serving_fence_lock_key,
        audit_pseudonym_keyring_lock_key,
    )
    .await?;
    transaction
        .batch_execute(&role_grants_sql(
            runtime_role,
            maintenance_role,
            reader_role,
        ))
        .await
        .map_err(|_| StatePlaneInstallError::Unavailable)?;
    if !owner_capability_matches(
        &transaction,
        role_oids,
        chain_key_epoch_id,
        serving_fence_lock_key,
        audit_pseudonym_keyring_lock_key,
    )
    .await?
    {
        return Err(StatePlaneInstallError::CapabilityDrift);
    }
    transaction
        .commit()
        .await
        .map_err(|_| StatePlaneInstallError::Unavailable)
}

async fn validate_install_roles(
    transaction: &Transaction<'_>,
    runtime_role: &RuntimeDatabaseRole,
    maintenance_role: &AuditPseudonymMaintenanceDatabaseRole,
    reader_role: &AuditPseudonymReaderDatabaseRole,
) -> Result<BoundRoleOids, StatePlaneInstallError> {
    let row = transaction
        .query_opt(
            r#"
SELECT owner_role.oid::bigint AS owner_oid,
       runtime_role.oid::bigint AS runtime_oid,
       maintenance_role.oid::bigint AS maintenance_oid,
       reader_role.oid::bigint AS reader_oid,
       session_role.rolsuper AS session_is_superuser,
       session_role.oid <> owner_role.oid AS session_is_distinct,
       NOT owner_role.rolcanlogin AND NOT owner_role.rolsuper
         AND NOT owner_role.rolcreaterole AND NOT owner_role.rolbypassrls
         AND NOT owner_role.rolreplication AND NOT owner_role.rolcreatedb AS owner_safe,
       runtime_role.rolcanlogin AND NOT runtime_role.rolsuper
         AND NOT runtime_role.rolcreaterole AND NOT runtime_role.rolbypassrls
         AND NOT runtime_role.rolreplication AND NOT runtime_role.rolcreatedb AS runtime_safe,
       maintenance_role.rolcanlogin AND NOT maintenance_role.rolsuper
         AND NOT maintenance_role.rolcreaterole AND NOT maintenance_role.rolbypassrls
         AND NOT maintenance_role.rolreplication AND NOT maintenance_role.rolcreatedb
         AS maintenance_safe,
       reader_role.rolcanlogin AND NOT reader_role.rolsuper
         AND NOT reader_role.rolcreaterole AND NOT reader_role.rolbypassrls
         AND NOT reader_role.rolreplication AND NOT reader_role.rolcreatedb AS reader_safe,
       NOT EXISTS (
           SELECT 1 FROM pg_catalog.pg_auth_members AS membership
           WHERE membership.member = owner_role.oid OR membership.roleid = owner_role.oid
       ) AS owner_membership_safe,
       NOT EXISTS (
           SELECT 1 FROM pg_catalog.pg_auth_members AS membership
           WHERE membership.member = runtime_role.oid OR membership.roleid = runtime_role.oid
       ) AS runtime_membership_safe,
       NOT EXISTS (
           SELECT 1 FROM pg_catalog.pg_auth_members AS membership
           WHERE membership.member = maintenance_role.oid
              OR membership.roleid = maintenance_role.oid
       ) AS maintenance_membership_safe,
       NOT EXISTS (
           SELECT 1 FROM pg_catalog.pg_auth_members AS membership
           WHERE membership.member = reader_role.oid OR membership.roleid = reader_role.oid
       ) AS reader_membership_safe,
       current_setting('max_prepared_transactions')::integer = 0 AS prepared_safe,
       current_setting('fsync') = 'on'
         AND current_setting('full_page_writes') = 'on' AS durability_safe,
       current_setting('client_encoding') = 'UTF8'
         AND current_setting('standard_conforming_strings') = 'on'
         AND current_setting('session_replication_role') = 'origin'
         AND current_setting('default_transaction_isolation') = 'read committed'
         AND current_setting('transaction_isolation') = 'read committed'
         AS session_semantics_safe,
       current_setting('default_transaction_read_only') = 'off'
         AND current_setting('transaction_read_only') = 'off'
         AND NOT pg_catalog.pg_is_in_recovery() AS primary_writable,
       current_setting('server_version_num')::integer / 10000 BETWEEN $4 AND $5
         AS version_safe
FROM pg_catalog.pg_roles AS owner_role
JOIN pg_catalog.pg_roles AS session_role ON session_role.rolname = session_user
JOIN pg_catalog.pg_roles AS runtime_role ON runtime_role.rolname = $1
JOIN pg_catalog.pg_roles AS maintenance_role ON maintenance_role.rolname = $2
JOIN pg_catalog.pg_roles AS reader_role ON reader_role.rolname = $3
WHERE owner_role.rolname = current_user
"#,
            &[
                &runtime_role.0,
                &maintenance_role.0,
                &reader_role.0,
                &SUPPORTED_POSTGRES_MIN_MAJOR,
                &SUPPORTED_POSTGRES_MAX_MAJOR,
            ],
        )
        .await
        .map_err(|_| StatePlaneInstallError::Unavailable)?
        .ok_or(StatePlaneInstallError::InvalidRuntimeRole)?;
    if !try_bool(&row, "session_is_superuser")? || !try_bool(&row, "session_is_distinct")? {
        return Err(StatePlaneInstallError::InvalidMigrationAuthority);
    }
    if !try_bool(&row, "prepared_safe")?
        || !try_bool(&row, "durability_safe")?
        || !try_bool(&row, "session_semantics_safe")?
        || !try_bool(&row, "primary_writable")?
        || !try_bool(&row, "version_safe")?
    {
        return Err(StatePlaneInstallError::UnsafeDatabaseConfiguration);
    }
    if !try_bool(&row, "owner_safe")? || !try_bool(&row, "owner_membership_safe")? {
        return Err(StatePlaneInstallError::OwnerRoleNotIsolated);
    }
    if !try_bool(&row, "runtime_safe")? || !try_bool(&row, "runtime_membership_safe")? {
        return Err(StatePlaneInstallError::RuntimeRoleNotIsolated);
    }
    if !try_bool(&row, "maintenance_safe")? || !try_bool(&row, "maintenance_membership_safe")? {
        return Err(StatePlaneInstallError::PseudonymMaintenanceRoleNotIsolated);
    }
    if !try_bool(&row, "reader_safe")? || !try_bool(&row, "reader_membership_safe")? {
        return Err(StatePlaneInstallError::PseudonymReaderRoleNotIsolated);
    }
    let role_oids = BoundRoleOids {
        owner: try_i64(&row, "owner_oid")?,
        runtime: try_i64(&row, "runtime_oid")?,
        maintenance: try_i64(&row, "maintenance_oid")?,
        reader: try_i64(&row, "reader_oid")?,
    };
    let mut distinct = std::collections::BTreeSet::new();
    distinct.extend([
        role_oids.owner,
        role_oids.runtime,
        role_oids.maintenance,
        role_oids.reader,
    ]);
    if distinct.len() != 4 {
        return Err(StatePlaneInstallError::AuthorityRoleCollision);
    }
    Ok(role_oids)
}

async fn bind_or_validate_metadata(
    transaction: &Transaction<'_>,
    role_oids: BoundRoleOids,
    chain_key_epoch_id: &AuditChainKeyEpochId,
    serving_fence_lock_key: ServingFenceLockKey,
    audit_pseudonym_keyring_lock_key: AuditPseudonymKeyringLockKey,
) -> Result<(), StatePlaneInstallError> {
    let existing = transaction
        .query_opt(
            r#"
SELECT schema_version, capability_id, capability_fingerprint,
       owner_role_oid::bigint AS owner_role_oid,
       runtime_role_oid::bigint AS runtime_role_oid,
       audit_pseudonym_maintenance_role_oid::bigint AS maintenance_role_oid,
       audit_pseudonym_reader_role_oid::bigint AS reader_role_oid,
       chain_key_epoch_id, serving_fence_capability_id, serving_fence_lock_key,
       quota_capability_id, audit_pseudonym_keyring_capability_id,
       audit_pseudonym_keyring_lock_key
FROM relay_state_private.state_plane_metadata WHERE singleton = true
"#,
            &[],
        )
        .await
        .map_err(|_| StatePlaneInstallError::Unavailable)?;
    if let Some(existing) = existing {
        let matches = try_i32(&existing, "schema_version")? == STATE_PLANE_SCHEMA_VERSION_V1
            && try_str(&existing, "capability_id")? == DURABLE_AUDIT_CAPABILITY_V1
            && try_str(&existing, "capability_fingerprint")? == STATE_PLANE_SCHEMA_FINGERPRINT_V1
            && try_i64(&existing, "owner_role_oid")? == role_oids.owner
            && try_i64(&existing, "runtime_role_oid")? == role_oids.runtime
            && try_i64(&existing, "maintenance_role_oid")? == role_oids.maintenance
            && try_i64(&existing, "reader_role_oid")? == role_oids.reader
            && try_str(&existing, "chain_key_epoch_id")? == chain_key_epoch_id.as_str()
            && try_str(&existing, "serving_fence_capability_id")? == SERVING_FENCE_CAPABILITY_V1
            && try_i64(&existing, "serving_fence_lock_key")? == serving_fence_lock_key.as_i64()
            && try_str(&existing, "quota_capability_id")? == PERSISTENT_QUOTA_CAPABILITY_V1
            && try_str(&existing, "audit_pseudonym_keyring_capability_id")?
                == AUDIT_PSEUDONYM_KEYRING_CAPABILITY_V1
            && try_i64(&existing, "audit_pseudonym_keyring_lock_key")?
                == audit_pseudonym_keyring_lock_key.as_i64();
        return if matches {
            Ok(())
        } else {
            Err(StatePlaneInstallError::CapabilityDrift)
        };
    }
    transaction
        .execute(
            r#"
INSERT INTO relay_state_private.state_plane_metadata (
    singleton, schema_version, capability_id, capability_fingerprint,
    owner_role_oid, runtime_role_oid, audit_pseudonym_maintenance_role_oid,
    audit_pseudonym_reader_role_oid, chain_key_epoch_id,
    serving_fence_capability_id, serving_fence_lock_key, quota_capability_id,
    audit_pseudonym_keyring_capability_id, audit_pseudonym_keyring_lock_key
) VALUES (
    true, $1, $2, $3, $4::bigint::oid, $5::bigint::oid, $6::bigint::oid,
    $7::bigint::oid, $8, $9, $10, $11, $12, $13
)
"#,
            &[
                &STATE_PLANE_SCHEMA_VERSION_V1,
                &DURABLE_AUDIT_CAPABILITY_V1,
                &STATE_PLANE_SCHEMA_FINGERPRINT_V1,
                &role_oids.owner,
                &role_oids.runtime,
                &role_oids.maintenance,
                &role_oids.reader,
                &chain_key_epoch_id.as_str(),
                &SERVING_FENCE_CAPABILITY_V1,
                &serving_fence_lock_key.as_i64(),
                &PERSISTENT_QUOTA_CAPABILITY_V1,
                &AUDIT_PSEUDONYM_KEYRING_CAPABILITY_V1,
                &audit_pseudonym_keyring_lock_key.as_i64(),
            ],
        )
        .await
        .map_err(|_| StatePlaneInstallError::Unavailable)?;
    Ok(())
}

fn role_grants_sql(
    runtime_role: &RuntimeDatabaseRole,
    maintenance_role: &AuditPseudonymMaintenanceDatabaseRole,
    reader_role: &AuditPseudonymReaderDatabaseRole,
) -> String {
    let runtime = runtime_role.quoted();
    let maintenance = maintenance_role.quoted();
    let reader = reader_role.quoted();
    format!(
        r#"
REVOKE ALL ON SCHEMA relay_state_private FROM {runtime}, {maintenance}, {reader};
REVOKE ALL ON ALL TABLES IN SCHEMA relay_state_private FROM {runtime}, {maintenance}, {reader};
REVOKE ALL ON ALL SEQUENCES IN SCHEMA relay_state_private FROM {runtime}, {maintenance}, {reader};
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA relay_state_private FROM {runtime}, {maintenance}, {reader};
REVOKE ALL ON SCHEMA relay_state_api FROM {runtime}, {maintenance}, {reader};
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA relay_state_api FROM {runtime}, {maintenance}, {reader};
GRANT USAGE ON SCHEMA relay_state_api TO {runtime}, {maintenance}, {reader};
GRANT EXECUTE ON FUNCTION relay_state_api.audit_phase_snapshot_v1(
    text, text, text, bytea, text, text, bigint, bytea, bigint
)
    TO {runtime};
GRANT EXECUTE ON FUNCTION relay_state_api.audit_phase_duplicate_v1(
    text, text, text, bytea, text, bigint
) TO {runtime};
GRANT EXECUTE ON FUNCTION relay_state_api.audit_phase_cas_v1(
    text, text, text, bytea, bigint, bytea, text, bigint,
    text, text, bytea, text, bytea, text, bigint, bytea, text, bigint
) TO {runtime};
GRANT EXECUTE ON FUNCTION relay_state_api.consultation_attempt_intent_snapshot_v1(
    text, bytea, text, bytea, text, bytea, text, bigint, bytea, bigint,
    text, bigint, integer, bigint, text[], smallint[], text, bigint
) TO {runtime};
GRANT EXECUTE ON FUNCTION relay_state_api.consultation_attempt_intent_cas_v1(
    text, bytea, bigint, bytea, text, bigint, text, text, bytea, text,
    bytea, text, bytea, text, bigint, bytea, bigint, text, bigint, integer,
    bigint, text[], smallint[], text, bigint
) TO {runtime};
GRANT EXECUTE ON FUNCTION relay_state_api.consultation_completion_snapshot_normal_v1(
    text, bigint, text, bigint, bigint, text[], smallint[], text, bigint,
    bytea, text, bigint
) TO {runtime};
GRANT EXECUTE ON FUNCTION relay_state_api.consultation_completion_snapshot_recovery_v1(
    text, bigint, text, bigint, text, bigint
) TO {runtime};
GRANT EXECUTE ON FUNCTION relay_state_api.consultation_completion_cas_normal_v1(
    text, bigint, text, bigint, bigint, text[], smallint[], text, bigint,
    bytea, bytea, bigint, bytea, text, bigint, text, text, bytea, text, bigint
) TO {runtime};
GRANT EXECUTE ON FUNCTION relay_state_api.consultation_completion_cas_unfinished_v1(
    text, bigint, text, bigint, bigint, text[], smallint[], text, bigint,
    bytea, bytea, bigint, bytea, text, bigint, text, text, bytea, text, bigint
) TO {runtime};
GRANT EXECUTE ON FUNCTION relay_state_api.consultation_completion_cas_recovery_v1(
    text, bigint, text, bigint, bytea, bigint, bytea, text, bigint, text,
    text, bytea, text, bigint
) TO {runtime};
GRANT EXECUTE ON FUNCTION relay_state_api.audit_readiness_v1(text) TO {runtime};
GRANT EXECUTE ON FUNCTION relay_state_api.serving_fence_acquire_v1(bigint, text)
    TO {runtime};
GRANT EXECUTE ON FUNCTION relay_state_api.serving_fence_finalize_v1(bigint, text, bigint)
    TO {runtime};
GRANT EXECUTE ON FUNCTION relay_state_api.serving_fence_open_after_recovery_v1(bigint, text, bigint)
    TO {runtime};
GRANT EXECUTE ON FUNCTION relay_state_api.serving_fence_status_v1(bigint, text, bigint)
    TO {runtime};
GRANT EXECUTE ON FUNCTION relay_state_api.dispatch_permit_authorize_v1(
    bigint, text, bigint, text, text, smallint, text, bigint
) TO {runtime};
GRANT EXECUTE ON FUNCTION relay_state_api.serving_fence_release_v1(bigint, text, bigint)
    TO {runtime};
GRANT EXECUTE ON FUNCTION relay_state_api.quota_reserve_v1(
    text, text, bigint, integer, integer
) TO {runtime};
GRANT EXECUTE ON FUNCTION relay_state_api.audit_pseudonym_keyring_snapshot_v1(
    text, text[], text, bigint
)
    TO {runtime}, {maintenance}, {reader};
GRANT EXECUTE ON FUNCTION relay_state_api.audit_pseudonym_keyring_readiness_v1(text, text)
    TO {runtime}, {maintenance}, {reader};
GRANT EXECUTE ON FUNCTION relay_state_api.audit_pseudonym_keyring_initialize_v1(
    bigint, bytea, text, text, bigint, bigint, bigint, text[], bigint[], bigint[],
    text, bigint
) TO {maintenance};
GRANT EXECUTE ON FUNCTION relay_state_api.audit_pseudonym_keyring_rotate_v1(
    bigint, bytea, bigint, bytea, bigint, bigint, bytea, text, text,
    bigint, bigint, bigint, text[], bigint[], bigint[], text, bigint
) TO {maintenance};
GRANT EXECUTE ON FUNCTION relay_state_api.audit_pseudonym_keyring_maintain_v1(
    bigint, bytea, bigint, bytea, bigint, bigint, bytea, text, text,
    bigint, bigint, bigint, text[], bigint[], bigint[], text, bigint
) TO {maintenance};
"#
    )
}

async fn owner_capability_matches(
    client: &impl GenericClient,
    role_oids: BoundRoleOids,
    chain_key_epoch_id: &AuditChainKeyEpochId,
    serving_fence_lock_key: ServingFenceLockKey,
    audit_pseudonym_keyring_lock_key: AuditPseudonymKeyringLockKey,
) -> Result<bool, StatePlaneInstallError> {
    let metadata = client
        .query_opt(
            r#"
SELECT schema_version, capability_id, capability_fingerprint,
       owner_role_oid::bigint AS owner_role_oid,
       runtime_role_oid::bigint AS runtime_role_oid,
       audit_pseudonym_maintenance_role_oid::bigint AS maintenance_role_oid,
       audit_pseudonym_reader_role_oid::bigint AS reader_role_oid,
       chain_key_epoch_id, serving_fence_capability_id, serving_fence_lock_key,
       quota_capability_id, audit_pseudonym_keyring_capability_id,
       audit_pseudonym_keyring_lock_key
FROM relay_state_private.state_plane_metadata WHERE singleton = true
"#,
            &[],
        )
        .await
        .map_err(|_| StatePlaneInstallError::Unavailable)?;
    let Some(metadata) = metadata else {
        return Ok(false);
    };
    let metadata_matches = try_i32(&metadata, "schema_version")? == STATE_PLANE_SCHEMA_VERSION_V1
        && try_str(&metadata, "capability_id")? == DURABLE_AUDIT_CAPABILITY_V1
        && try_str(&metadata, "capability_fingerprint")? == STATE_PLANE_SCHEMA_FINGERPRINT_V1
        && try_i64(&metadata, "owner_role_oid")? == role_oids.owner
        && try_i64(&metadata, "runtime_role_oid")? == role_oids.runtime
        && try_i64(&metadata, "maintenance_role_oid")? == role_oids.maintenance
        && try_i64(&metadata, "reader_role_oid")? == role_oids.reader
        && try_str(&metadata, "chain_key_epoch_id")? == chain_key_epoch_id.as_str()
        && try_str(&metadata, "serving_fence_capability_id")? == SERVING_FENCE_CAPABILITY_V1
        && try_i64(&metadata, "serving_fence_lock_key")? == serving_fence_lock_key.as_i64()
        && try_str(&metadata, "quota_capability_id")? == PERSISTENT_QUOTA_CAPABILITY_V1
        && try_str(&metadata, "audit_pseudonym_keyring_capability_id")?
            == AUDIT_PSEUDONYM_KEYRING_CAPABILITY_V1
        && try_i64(&metadata, "audit_pseudonym_keyring_lock_key")?
            == audit_pseudonym_keyring_lock_key.as_i64();
    if !metadata_matches {
        return Ok(false);
    }
    let helper_matches = helper_body_matches(client, role_oids.owner)
        .await
        .map_err(|_| StatePlaneInstallError::Unavailable)?;
    if !helper_matches {
        return Ok(false);
    }
    client
        .query_one(
            "SELECT relay_state_private.capability_valid_v1() AS valid",
            &[],
        )
        .await
        .map_err(|_| StatePlaneInstallError::Unavailable)
        .and_then(|row| try_bool(&row, "valid"))
}

pub(super) async fn validate_runtime_capability_v1(
    client: &Client,
    chain_key_epoch_id: &AuditChainKeyEpochId,
) -> Result<(), RuntimeCapabilityError> {
    validate_runtime_capability_expected_v1(client, chain_key_epoch_id, None).await
}

pub(super) async fn validate_runtime_pseudonym_capability_v1(
    client: &Client,
    chain_key_epoch_id: &AuditChainKeyEpochId,
    keyring_lock_key: AuditPseudonymKeyringLockKey,
) -> Result<(), RuntimeCapabilityError> {
    validate_runtime_capability_expected_v1(client, chain_key_epoch_id, Some(keyring_lock_key))
        .await
}

async fn validate_runtime_capability_expected_v1(
    client: &Client,
    chain_key_epoch_id: &AuditChainKeyEpochId,
    expected_keyring_lock_key: Option<AuditPseudonymKeyringLockKey>,
) -> Result<(), RuntimeCapabilityError> {
    let identity = client
        .query_one(
            r#"
SELECT session_role.oid::bigint AS session_oid,
       current_role_row.oid::bigint AS current_oid
FROM pg_catalog.pg_roles AS session_role
JOIN pg_catalog.pg_roles AS current_role_row ON current_role_row.rolname = current_user
WHERE session_role.rolname = session_user
"#,
            &[],
        )
        .await
        .map_err(|_| RuntimeCapabilityError::Unavailable)?;
    let session_oid = try_i64_runtime(&identity, "session_oid")?;
    let current_oid = try_i64_runtime(&identity, "current_oid")?;
    let readiness = client
        .query_opt(
            "SELECT * FROM relay_state_api.audit_readiness_v1($1)",
            &[&chain_key_epoch_id.as_str()],
        )
        .await
        .map_err(|error| {
            if error
                .as_db_error()
                .is_some_and(|error| error.code().code() == "42501")
            {
                RuntimeCapabilityError::WrongRuntimeIdentity
            } else {
                RuntimeCapabilityError::Unavailable
            }
        })?
        .ok_or(RuntimeCapabilityError::Drift)?;
    let runtime_oid = try_i64_runtime(&readiness, "runtime_role_oid")?;
    if session_oid != runtime_oid || current_oid != runtime_oid {
        return Err(RuntimeCapabilityError::WrongRuntimeIdentity);
    }
    let actual_keyring_lock_key = try_i64_runtime(&readiness, "audit_pseudonym_keyring_lock_key")?;
    if !try_bool_runtime(&readiness, "ready")?
        || try_str_runtime(&readiness, "capability_id")? != DURABLE_AUDIT_CAPABILITY_V1
        || try_str_runtime(&readiness, "capability_fingerprint")?
            != STATE_PLANE_SCHEMA_FINGERPRINT_V1
        || try_str_runtime(&readiness, "chain_key_epoch_id")? != chain_key_epoch_id.as_str()
        || try_str_runtime(&readiness, "quota_capability_id")? != PERSISTENT_QUOTA_CAPABILITY_V1
        || try_str_runtime(&readiness, "audit_pseudonym_keyring_capability_id")?
            != AUDIT_PSEUDONYM_KEYRING_CAPABILITY_V1
        || actual_keyring_lock_key == 0
        || expected_keyring_lock_key
            .is_some_and(|expected| actual_keyring_lock_key != expected.as_i64())
    {
        return Err(RuntimeCapabilityError::Drift);
    }
    let owner_oid = try_i64_runtime(&readiness, "owner_role_oid")?;
    if !helper_body_matches(client, owner_oid).await? {
        return Err(RuntimeCapabilityError::Drift);
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum KeyringDatabaseRoleKind {
    Runtime,
    Maintenance,
    Reader,
}

impl KeyringDatabaseRoleKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Runtime => "runtime",
            Self::Maintenance => "maintenance",
            Self::Reader => "reader",
        }
    }
}

pub(super) async fn validate_keyring_role_capability_v1(
    client: &Client,
    chain_key_epoch_id: &AuditChainKeyEpochId,
    keyring_lock_key: AuditPseudonymKeyringLockKey,
    role_kind: KeyringDatabaseRoleKind,
) -> Result<(), RuntimeCapabilityError> {
    let identity = client
        .query_one(
            r#"
SELECT session_role.oid::bigint AS session_oid,
       current_role_row.oid::bigint AS current_oid
FROM pg_catalog.pg_roles AS session_role
JOIN pg_catalog.pg_roles AS current_role_row ON current_role_row.rolname = current_user
WHERE session_role.rolname = session_user
"#,
            &[],
        )
        .await
        .map_err(|_| RuntimeCapabilityError::Unavailable)?;
    let session_oid = try_i64_runtime(&identity, "session_oid")?;
    let current_oid = try_i64_runtime(&identity, "current_oid")?;
    let readiness = client
        .query_opt(
            "SELECT * FROM relay_state_api.audit_pseudonym_keyring_readiness_v1($1, $2)",
            &[&chain_key_epoch_id.as_str(), &role_kind.as_str()],
        )
        .await
        .map_err(|error| {
            if error
                .as_db_error()
                .is_some_and(|error| error.code().code() == "42501")
            {
                RuntimeCapabilityError::WrongRuntimeIdentity
            } else {
                RuntimeCapabilityError::Unavailable
            }
        })?
        .ok_or(RuntimeCapabilityError::Drift)?;
    let caller_oid = try_i64_runtime(&readiness, "caller_role_oid")?;
    if session_oid != caller_oid || current_oid != caller_oid {
        return Err(RuntimeCapabilityError::WrongRuntimeIdentity);
    }
    if !try_bool_runtime(&readiness, "ready")?
        || try_str_runtime(&readiness, "capability_id")? != DURABLE_AUDIT_CAPABILITY_V1
        || try_str_runtime(&readiness, "capability_fingerprint")?
            != STATE_PLANE_SCHEMA_FINGERPRINT_V1
        || try_str_runtime(&readiness, "chain_key_epoch_id")? != chain_key_epoch_id.as_str()
        || try_str_runtime(&readiness, "audit_pseudonym_keyring_capability_id")?
            != AUDIT_PSEUDONYM_KEYRING_CAPABILITY_V1
        || try_i64_runtime(&readiness, "audit_pseudonym_keyring_lock_key")?
            != keyring_lock_key.as_i64()
    {
        return Err(RuntimeCapabilityError::Drift);
    }
    let owner_oid = try_i64_runtime(&readiness, "owner_role_oid")?;
    if !helper_body_matches(client, owner_oid).await? {
        return Err(RuntimeCapabilityError::Drift);
    }
    Ok(())
}

async fn helper_body_matches(
    client: &impl GenericClient,
    owner_oid: i64,
) -> Result<bool, RuntimeCapabilityError> {
    let row = client
        .query_one(
            r#"
SELECT count(*) = 1
       AND bool_and(procedure.proowner = $1::bigint::oid)
       AND bool_and(pg_catalog.md5(procedure.prosrc) = $2) AS valid
FROM pg_catalog.pg_proc AS procedure
JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = procedure.pronamespace
WHERE namespace.nspname = 'relay_state_private'
  AND procedure.proname = 'capability_valid_v1'
  AND pg_catalog.oidvectortypes(procedure.proargtypes) = ''
"#,
            &[&owner_oid, &CAPABILITY_HELPER_BODY_FINGERPRINT_V1],
        )
        .await
        .map_err(|_| RuntimeCapabilityError::Unavailable)?;
    try_bool_runtime(&row, "valid")
}

fn try_bool(row: &Row, column: &str) -> Result<bool, StatePlaneInstallError> {
    row.try_get(column)
        .map_err(|_| StatePlaneInstallError::CapabilityDrift)
}

fn try_i32(row: &Row, column: &str) -> Result<i32, StatePlaneInstallError> {
    row.try_get(column)
        .map_err(|_| StatePlaneInstallError::CapabilityDrift)
}

fn try_i64(row: &Row, column: &str) -> Result<i64, StatePlaneInstallError> {
    row.try_get(column)
        .map_err(|_| StatePlaneInstallError::CapabilityDrift)
}

fn try_str<'a>(row: &'a Row, column: &str) -> Result<&'a str, StatePlaneInstallError> {
    row.try_get(column)
        .map_err(|_| StatePlaneInstallError::CapabilityDrift)
}

fn try_bool_runtime(row: &Row, column: &str) -> Result<bool, RuntimeCapabilityError> {
    row.try_get(column)
        .map_err(|_| RuntimeCapabilityError::Drift)
}

fn try_i64_runtime(row: &Row, column: &str) -> Result<i64, RuntimeCapabilityError> {
    row.try_get(column)
        .map_err(|_| RuntimeCapabilityError::Drift)
}

fn try_str_runtime<'a>(row: &'a Row, column: &str) -> Result<&'a str, RuntimeCapabilityError> {
    row.try_get(column)
        .map_err(|_| RuntimeCapabilityError::Drift)
}

#[cfg(test)]
mod tests {
    use std::fmt::Write as _;

    use sha2::{Digest, Sha256};

    use super::*;

    #[test]
    fn migration_uses_optimistic_cas_not_cross_call_reservations() {
        assert!(POSTGRES_STATE_PLANE_MIGRATION_V1.contains("audit_phase_snapshot_v1"));
        assert!(POSTGRES_STATE_PLANE_MIGRATION_V1.contains("audit_phase_cas_v1"));
        assert!(
            POSTGRES_STATE_PLANE_MIGRATION_V1.contains("head.generation = p_candidate_generation")
        );
        assert!(!POSTGRES_STATE_PLANE_MIGRATION_V1.contains("audit_phase_preparation"));
        let audit_sql = POSTGRES_STATE_PLANE_MIGRATION_V1
            .split(
                "CREATE OR REPLACE FUNCTION \
                 relay_state_api.consultation_attempt_intent_snapshot_v1",
            )
            .next()
            .expect("generic audit migration prefix");
        assert!(!audit_sql.contains("FOR UPDATE"));
    }

    #[test]
    fn consultation_attempt_and_dispatch_authority_is_database_closed() {
        for required in [
            "decision_expires_at_unix_ms bigint NOT NULL",
            "IS DISTINCT FROM p_budget_ms",
            "'decision_expired'::text",
            "'permit_order_violation'::text",
            "'operation_reuse_rejected'::text",
            "#>> '{dispatch,plan_kind}'",
            "permit.ordinal < p_ordinal",
            "permit.ordinal > p_ordinal",
        ] {
            assert!(
                POSTGRES_STATE_PLANE_MIGRATION_V1.contains(required),
                "consultation state protocol omitted {required}"
            );
        }
    }

    #[test]
    fn completion_seed_allows_only_the_closed_fresh_open_crvs_null_lifetime_shape() {
        for required in [
            "jsonb_array_length(v_seed #> '{acquisition,disclosure_fields}') NOT BETWEEN 0 AND 64",
            "jwks.value ->> 'operation_id' ~ '\\.jwks$'",
            "jsonb_typeof(v_seed #> '{bounds,credential_token_lifetime_ms}') = 'null'",
            "(permit.value ->> 'ordinal')::integer = 0",
            "(permit.value ->> 'ordinal')::integer = 1",
        ] {
            assert!(
                POSTGRES_STATE_PLANE_MIGRATION_V1.contains(required),
                "OpenCRVS completion-seed validation omitted {required}"
            );
        }
    }

    #[test]
    fn function_attestation_covers_full_abi_and_kind() {
        for field in [
            "prorettype",
            "proretset",
            "proallargtypes",
            "proargmodes",
            "proargnames",
            "prokind",
            "proparallel",
            "proleakproof",
            "prosecdef",
            "proconfig",
        ] {
            assert!(POSTGRES_STATE_PLANE_MIGRATION_V1.contains(field));
        }
    }

    #[test]
    fn migration_closes_both_membership_directions_and_prepared_transactions() {
        assert!(POSTGRES_STATE_PLANE_MIGRATION_V1.contains("membership.member IN"));
        assert!(POSTGRES_STATE_PLANE_MIGRATION_V1.contains("membership.roleid IN"));
        assert!(POSTGRES_STATE_PLANE_MIGRATION_V1.contains("max_prepared_transactions"));
        assert!(POSTGRES_STATE_PLANE_MIGRATION_V1.contains("current_setting('fsync') = 'on'"));
        assert!(POSTGRES_STATE_PLANE_MIGRATION_V1
            .contains("current_setting('full_page_writes') = 'on'"));
        assert!(POSTGRES_STATE_PLANE_MIGRATION_V1
            .contains("current_setting('default_transaction_read_only') = 'off'"));
        assert!(POSTGRES_STATE_PLANE_MIGRATION_V1
            .contains("current_setting('transaction_read_only') = 'off'"));
        assert!(POSTGRES_STATE_PLANE_MIGRATION_V1.contains("NOT pg_catalog.pg_is_in_recovery()"));
    }

    #[test]
    fn runtime_functions_own_fixed_limits() {
        assert_eq!(
            POSTGRES_STATE_PLANE_MIGRATION_V1
                .matches("SET lock_timeout = '2s'")
                .count(),
            31
        );
        assert_eq!(
            POSTGRES_STATE_PLANE_MIGRATION_V1
                .matches("set_config('idle_in_transaction_session_timeout', '5s', false)")
                .count(),
            19
        );
        assert_eq!(
            POSTGRES_STATE_PLANE_MIGRATION_V1
                .matches("SET synchronous_commit = 'on'")
                .count(),
            31
        );
        assert_eq!(
            POSTGRES_STATE_PLANE_MIGRATION_V1
                .matches("set_config('synchronous_commit', 'on', false)")
                .count(),
            19
        );
        assert!(POSTGRES_STATE_PLANE_MIGRATION_V1.contains("exceeded its deadline"));
        for required_setting in [
            "current_setting('search_path')",
            "current_setting('client_encoding')",
            "current_setting('standard_conforming_strings')",
            "current_setting('session_replication_role')",
            "current_setting('default_transaction_isolation')",
            "current_setting('transaction_isolation')",
            "current_setting('default_transaction_read_only')",
            "current_setting('transaction_read_only')",
        ] {
            assert!(POSTGRES_STATE_PLANE_MIGRATION_V1.contains(required_setting));
        }
    }

    #[test]
    fn quota_uses_exact_postgres_time_and_atomic_row_locking() {
        for required in [
            "consultation_quota_bucket",
            "quota_reserve_v1",
            "FOR UPDATE",
            "extract(epoch FROM (v_now - v_last_refill_at)) * 1000000",
            "v_elapsed_us * p_rate_per_minute::numeric",
            "v_now >= v_last_refill_at",
            "v_rollback_gap_us + v_token_wait_us",
            "v_total_wait_us > 60000000",
            "clock_anomaly",
            "v_retry_after_ms NOT BETWEEN 1 AND 60000",
            "limit_mismatch",
            "consultation quota bucket is corrupt",
        ] {
            assert!(POSTGRES_STATE_PLANE_MIGRATION_V1.contains(required));
        }
        let quota_sql = POSTGRES_STATE_PLANE_MIGRATION_V1
            .split("CREATE OR REPLACE FUNCTION relay_state_api.quota_reserve_v1")
            .nth(1)
            .expect("quota SQL")
            .split("CREATE OR REPLACE FUNCTION relay_state_api.audit_pseudonym_keyring_snapshot_v1")
            .next()
            .expect("quota function body");
        assert!(!quota_sql.contains("pg_advisory_xact_lock(p_"));
    }

    #[test]
    fn keyring_identifier_order_is_utf8_bytewise() {
        assert_eq!(
            POSTGRES_STATE_PLANE_MIGRATION_V1
                .matches("ORDER BY pg_catalog.convert_to(row.key_id, 'UTF8')")
                .count(),
            2
        );
        for required in [
            "pg_catalog.convert_to(p_retained_key_ids[v_index], 'UTF8')",
            "pg_catalog.convert_to(v_previous_key_id, 'UTF8')",
            "pg_catalog.convert_to(requested.key_id, 'UTF8')",
            "p_lookup_key_ids[requested.ordinal - 1], 'UTF8'",
        ] {
            assert!(POSTGRES_STATE_PLANE_MIGRATION_V1.contains(required));
        }
    }

    #[test]
    fn catalog_attestation_covers_durable_executable_relation_state() {
        for field in [
            "relpersistence",
            "relrowsecurity",
            "relforcerowsecurity",
            "target_indexes",
            "target_triggers",
            "target_policies",
            "indisvalid",
            "indisready",
            "indislive",
            "attcollation",
            "attidentity",
            "attgenerated",
            "attribute.attacl",
            "holder_backend_pid IS NOT NULL",
            "GET DIAGNOSTICS v_inserted_rows = ROW_COUNT",
        ] {
            assert!(POSTGRES_STATE_PLANE_MIGRATION_V1.contains(field));
        }
    }

    #[test]
    fn bounded_identifiers_reject_ddl_input() {
        assert!(AuditChainKeyEpochId::parse("audit-chain.2026-07:primary").is_ok());
        assert!(AuditChainKeyEpochId::parse("").is_err());
        assert!(AuditChainKeyEpochId::parse("bad/value").is_err());
        assert!(RuntimeDatabaseRole::parse("registry_relay_runtime_1").is_ok());
        assert!(RuntimeDatabaseRole::parse("relay-runtime").is_err());
    }

    #[test]
    fn catalog_fingerprints_are_versioned_and_frozen() {
        for fingerprint in [
            CONSTRAINT_FINGERPRINT_PG16,
            CONSTRAINT_FINGERPRINT_PG17,
            CONSTRAINT_FINGERPRINT_PG18,
            COLUMN_FINGERPRINT_PG16,
            COLUMN_FINGERPRINT_PG17,
            COLUMN_FINGERPRINT_PG18,
            FUNCTION_FINGERPRINT_PG16,
            FUNCTION_FINGERPRINT_PG17,
            FUNCTION_FINGERPRINT_PG18,
            CAPABILITY_HELPER_BODY_FINGERPRINT_V1,
        ] {
            assert_eq!(fingerprint.len(), 32);
            assert!(fingerprint.bytes().all(|byte| byte.is_ascii_hexdigit()));
        }
        assert!(!POSTGRES_STATE_PLANE_MIGRATION_V1.contains("__"));
    }

    #[test]
    fn schema_fingerprint_is_the_framed_semantic_identity() {
        assert!(STATE_PLANE_SCHEMA_IDENTITY_PREIMAGE_V1.ends_with('\0'));
        for semantic_revision in [
            DURABLE_AUDIT_CAPABILITY_V1,
            SERVING_FENCE_CAPABILITY_V1,
            PERSISTENT_QUOTA_CAPABILITY_V1,
            AUDIT_PSEUDONYM_KEYRING_CAPABILITY_V1,
            "database-expiry-seed-timeout-exact-dispatch-prefix-v2",
            "direct-data-auth-reference-distinct-fresh-opencrvs-no-expiry-jwks-v2",
            "utf8-bytewise-key-order-v1",
        ] {
            assert!(
                STATE_PLANE_SCHEMA_IDENTITY_PREIMAGE_V1.contains(semantic_revision),
                "semantic fingerprint preimage omitted {semantic_revision}"
            );
        }
        let mut calculated = String::from("sha256:");
        for byte in Sha256::digest(STATE_PLANE_SCHEMA_IDENTITY_PREIMAGE_V1.as_bytes()) {
            write!(&mut calculated, "{byte:02x}").expect("write to String");
        }
        assert_eq!(calculated, STATE_PLANE_SCHEMA_FINGERPRINT_V1);
    }
}
