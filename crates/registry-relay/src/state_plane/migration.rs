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
    "key-order=utf8-bytewise-key-order-v1\0",
);
pub(crate) const STATE_PLANE_SCHEMA_FINGERPRINT_V1: &str =
    "sha256:c381f2fbf8b6e5afbd428a0a4f53f2ba8571913aaf0d11351d4065b376e8ceef";

pub(super) const MIGRATION_ADVISORY_LOCK_KEY_V1: i64 = 7_221_091_440;
const SUPPORTED_POSTGRES_MIN_MAJOR: i32 = 16;
const SUPPORTED_POSTGRES_MAX_MAJOR: i32 = 18;

// Filled from the semantic catalog descriptor below on disposable supported
// PostgreSQL majors. Constraint rendering is explicitly versioned because
// pg_get_constraintdef is not a cross-major wire contract.
const CONSTRAINT_FINGERPRINT_PG16: &str = "b94332ef6c5b85a716b75a08c5296450";
const CONSTRAINT_FINGERPRINT_PG17: &str = "b94332ef6c5b85a716b75a08c5296450";
const CONSTRAINT_FINGERPRINT_PG18: &str = "50514ab7d176148d8af8a6e14fdd4c00";
const COLUMN_FINGERPRINT_PG16: &str = "4983bc1f7f0b50c8f820ad8544e70d81";
const COLUMN_FINGERPRINT_PG17: &str = "4983bc1f7f0b50c8f820ad8544e70d81";
const COLUMN_FINGERPRINT_PG18: &str = "4983bc1f7f0b50c8f820ad8544e70d81";
const FUNCTION_FINGERPRINT_PG16: &str = "bdc9313a889a1d7a25a06b04cba77bad";
const FUNCTION_FINGERPRINT_PG17: &str = "bdc9313a889a1d7a25a06b04cba77bad";
const FUNCTION_FINGERPRINT_PG18: &str = "bdc9313a889a1d7a25a06b04cba77bad";
const CAPABILITY_HELPER_BODY_FINGERPRINT_V1: &str = "31554bfb3eb93b535eac932f9f2c831c";

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
        'sha256:c381f2fbf8b6e5afbd428a0a4f53f2ba8571913aaf0d11351d4065b376e8ceef'
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

CREATE TABLE IF NOT EXISTS relay_state_private.dispatch_permit (
    operation_id text NOT NULL,
    fence_generation bigint NOT NULL,
    holder_id text NOT NULL,
    budget_ms integer NOT NULL,
    created_at timestamptz NOT NULL,
    deadline_at timestamptz NOT NULL,
    completed_at timestamptz NULL,
    abandoned_at timestamptz NULL,
    CONSTRAINT dispatch_permit_pk PRIMARY KEY (operation_id),
    CONSTRAINT dispatch_permit_operation_id_check CHECK (
        operation_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'
    ),
    CONSTRAINT dispatch_permit_generation_check CHECK (fence_generation > 0),
    CONSTRAINT dispatch_permit_holder_id_check CHECK (
        holder_id ~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'
    ),
    CONSTRAINT dispatch_permit_budget_check CHECK (budget_ms BETWEEN 1 AND 10000),
    CONSTRAINT dispatch_permit_deadline_check CHECK (
        deadline_at = created_at + budget_ms * interval '1 millisecond'
    ),
    CONSTRAINT dispatch_permit_terminal_time_check CHECK (
        (completed_at IS NULL OR completed_at >= created_at)
        AND (abandoned_at IS NULL OR abandoned_at >= created_at)
        AND NOT (completed_at IS NOT NULL AND abandoned_at IS NOT NULL)
    )
);
CREATE INDEX IF NOT EXISTS dispatch_permit_takeover_idx
ON relay_state_private.dispatch_permit (
    fence_generation, completed_at, abandoned_at, deadline_at
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
ALTER TABLE relay_state_private.dispatch_permit OWNER TO CURRENT_USER;
ALTER TABLE relay_state_private.consultation_quota_bucket OWNER TO CURRENT_USER;
ALTER TABLE relay_state_private.audit_pseudonym_keyring OWNER TO CURRENT_USER;
ALTER TABLE relay_state_private.audit_pseudonym_used_key_id OWNER TO CURRENT_USER;
ALTER TABLE relay_state_private.audit_pseudonym_transition_context OWNER TO CURRENT_USER;
REVOKE ALL ON ALL TABLES IN SCHEMA relay_state_private FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA relay_state_private FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA relay_state_private REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA relay_state_private REVOKE ALL ON SEQUENCES FROM PUBLIC;

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
        'sha256:c381f2fbf8b6e5afbd428a0a4f53f2ba8571913aaf0d11351d4065b376e8ceef'
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
          'serving_fence_state', 'dispatch_permit', 'consultation_quota_bucket',
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
          'serving_fence_state', 'dispatch_permit', 'consultation_quota_bucket',
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
          'serving_fence_state', 'dispatch_permit', 'consultation_quota_bucket',
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
          'serving_fence_state', 'dispatch_permit', 'consultation_quota_bucket',
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
                  'audit_pseudonym_history_snapshot_v1'
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
    AND (SELECT count(*) = 9 FROM target_relations)
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
               'serving_fence_state', 'dispatch_permit', 'consultation_quota_bucket',
               'audit_pseudonym_keyring', 'audit_pseudonym_used_key_id',
               'audit_pseudonym_transition_context'
           )
    )
    AND (SELECT count(*) = 12 FROM target_indexes)
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
               'serving_fence_state_pk', 'dispatch_permit_pk',
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
                   'serving_fence_state_pk', 'dispatch_permit_pk',
                   'consultation_quota_bucket_pk', 'audit_pseudonym_keyring_pk',
                   'audit_pseudonym_used_key_id_pk',
                   'audit_pseudonym_transition_context_pk'
               ) AND NOT target_indexes.indisprimary
           )
           OR (
               target_indexes.index_name IN (
                   'audit_phase_envelope_id_unique',
                   'audit_phase_stored_identity_unique'
               ) AND target_indexes.indisprimary
           )
           OR (
               target_indexes.index_name = 'dispatch_permit_takeover_idx'
               AND (
                   target_indexes.indisunique
                   OR target_indexes.indisprimary
                   OR target_indexes.constraint_backed
                   OR target_indexes.index_definition <>
                       'CREATE INDEX dispatch_permit_takeover_idx ON relay_state_private.dispatch_permit USING btree (fence_generation, completed_at, abandoned_at, deadline_at)'
               )
           )
           OR (
               target_indexes.index_name <> 'dispatch_permit_takeover_idx'
               AND (NOT target_indexes.indisunique OR NOT target_indexes.constraint_backed)
           )
    )
    AND (SELECT count(*) = 4 FROM target_triggers)
    AND NOT EXISTS (
        SELECT 1 FROM target_triggers
        WHERE target_triggers.relname <> 'audit_phase'
           OR NOT target_triggers.tgisinternal
           OR target_triggers.tgenabled <> 'O'
           OR target_triggers.conname IS DISTINCT FROM 'audit_phase_attempt_fk'
    )
    AND NOT EXISTS (SELECT 1 FROM target_rules)
    AND NOT EXISTS (SELECT 1 FROM target_policies)
    AND (SELECT count(*) = 20 FROM target_functions)
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
                       OR (target_functions.proname IN (
                            'audit_pseudonym_metadata_canonical_v1',
                            'audit_pseudonym_history_snapshot_v1'
                           ) AND target_functions.lanname = 'plpgsql')
                   )
               ))
           OR (target_functions.nspname = 'relay_state_api'
                       AND NOT (target_functions.proname IN (
                            'audit_phase_snapshot_v1', 'audit_phase_duplicate_v1',
                            'audit_phase_cas_v1', 'audit_readiness_v1',
                            'serving_fence_acquire_v1', 'serving_fence_finalize_v1',
                            'serving_fence_status_v1', 'dispatch_permit_create_v1',
                            'dispatch_permit_authorize_v1', 'dispatch_permit_complete_v1',
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
        SELECT 9 * count(*) FROM metadata
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
    AND (SELECT count(*) = 41 FROM function_acl)
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
                       'audit_readiness_v1', 'serving_fence_acquire_v1',
                       'serving_fence_finalize_v1', 'serving_fence_status_v1',
                       'dispatch_permit_create_v1', 'dispatch_permit_authorize_v1',
                       'dispatch_permit_complete_v1', 'serving_fence_release_v1',
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
            WHEN 16 THEN 'b94332ef6c5b85a716b75a08c5296450'
            WHEN 17 THEN 'b94332ef6c5b85a716b75a08c5296450'
            WHEN 18 THEN '50514ab7d176148d8af8a6e14fdd4c00'
            ELSE '' END FROM constraint_fingerprint, server)
    AND (SELECT value = CASE server.major
            WHEN 16 THEN '4983bc1f7f0b50c8f820ad8544e70d81'
            WHEN 17 THEN '4983bc1f7f0b50c8f820ad8544e70d81'
            WHEN 18 THEN '4983bc1f7f0b50c8f820ad8544e70d81'
            ELSE '' END FROM column_fingerprint, server)
    AND (SELECT value = CASE server.major
            WHEN 16 THEN 'bdc9313a889a1d7a25a06b04cba77bad'
            WHEN 17 THEN 'bdc9313a889a1d7a25a06b04cba77bad'
            WHEN 18 THEN 'bdc9313a889a1d7a25a06b04cba77bad'
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
        SELECT max(permit.deadline_at + interval '1 second')
        INTO v_prior_barrier
        FROM relay_state_private.dispatch_permit AS permit
        WHERE permit.completed_at IS NULL AND permit.abandoned_at IS NULL;
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
    abandoned_count bigint
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
    v_abandoned bigint := 0;
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
        RETURN QUERY SELECT 'ownership_lost'::text, NULL::bigint, NULL::bigint;
        RETURN;
    END IF;
    SELECT fence.takeover_pending, fence.takeover_pg_not_before, fence.admission_open
    INTO v_pending, v_barrier, v_open
    FROM relay_state_private.serving_fence_state AS fence
    WHERE fence.singleton = true;
    IF v_open AND NOT v_pending THEN
        RETURN QUERY SELECT 'opened'::text, 0::bigint, 0::bigint;
        RETURN;
    END IF;
    IF NOT v_pending OR v_barrier IS NULL THEN
        RETURN QUERY SELECT 'ownership_lost'::text, NULL::bigint, NULL::bigint;
        RETURN;
    END IF;
    IF v_now < v_barrier THEN
        RETURN QUERY SELECT 'barrier_pending'::text,
            greatest(1::bigint, ceil(extract(epoch FROM (v_barrier - v_now)) * 1000)::bigint),
            0::bigint;
        RETURN;
    END IF;
    UPDATE relay_state_private.dispatch_permit AS permit
    SET abandoned_at = v_now
    WHERE permit.fence_generation < p_fence_generation
      AND permit.completed_at IS NULL AND permit.abandoned_at IS NULL;
    GET DIAGNOSTICS v_abandoned = ROW_COUNT;
    UPDATE relay_state_private.serving_fence_state AS fence
    SET takeover_pending = false,
        takeover_pg_not_before = NULL,
        admission_open = true
    WHERE fence.singleton = true
      AND fence.generation = p_fence_generation
      AND fence.holder_id = p_holder_id
      AND fence.holder_backend_pid = pg_catalog.pg_backend_pid();
    IF NOT FOUND THEN
        RAISE EXCEPTION 'serving fence ownership changed' USING ERRCODE = '55000';
    END IF;
    RETURN QUERY SELECT 'opened'::text, 0::bigint, v_abandoned;
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

CREATE OR REPLACE FUNCTION relay_state_api.dispatch_permit_create_v1(
    p_lock_key bigint,
    p_holder_id text,
    p_fence_generation bigint,
    p_operation_id text,
    p_budget_ms integer
)
RETURNS TABLE (
    outcome text,
    operation_id text,
    fence_generation bigint,
    holder_id text,
    budget_ms integer,
    deadline_unix_ms bigint
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
    v_existing relay_state_private.dispatch_permit%ROWTYPE;
    v_inserted bigint;
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
    IF p_operation_id IS NULL OR p_operation_id !~ '^[0-7][0-9A-HJKMNP-TV-Z]{25}$'
       OR p_budget_ms IS NULL OR p_budget_ms NOT BETWEEN 1 AND 10000
    THEN
        RAISE EXCEPTION 'invalid dispatch permit request' USING ERRCODE = '22023';
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
        RETURN QUERY SELECT 'ownership_lost'::text, p_operation_id,
            NULL::bigint, NULL::text, NULL::integer, NULL::bigint;
        RETURN;
    END IF;
    SELECT permit.* INTO v_existing
    FROM relay_state_private.dispatch_permit AS permit
    WHERE permit.operation_id = p_operation_id;
    IF FOUND THEN
        RETURN QUERY SELECT
            CASE WHEN v_existing.fence_generation = p_fence_generation
                       AND v_existing.holder_id = p_holder_id
                       AND v_existing.budget_ms = p_budget_ms
                THEN 'identical_replay'::text ELSE 'conflicting_replay'::text END,
            v_existing.operation_id, v_existing.fence_generation,
            v_existing.holder_id, v_existing.budget_ms,
            floor(extract(epoch FROM v_existing.deadline_at) * 1000)::bigint;
        RETURN;
    END IF;
    INSERT INTO relay_state_private.dispatch_permit (
        operation_id, fence_generation, holder_id, budget_ms,
        created_at, deadline_at
    ) VALUES (
        p_operation_id, p_fence_generation, p_holder_id, p_budget_ms,
        v_now, v_now + p_budget_ms * interval '1 millisecond'
    );
    GET DIAGNOSTICS v_inserted = ROW_COUNT;
    IF v_inserted <> 1 THEN
        RAISE EXCEPTION 'dispatch permit insert did not store exactly one row'
            USING ERRCODE = '55000';
    END IF;
    RETURN QUERY SELECT 'inserted'::text, p_operation_id,
        p_fence_generation, p_holder_id, p_budget_ms,
        floor(extract(epoch FROM (v_now + p_budget_ms * interval '1 millisecond')) * 1000)::bigint;
END;
$function$;

CREATE OR REPLACE FUNCTION relay_state_api.dispatch_permit_authorize_v1(
    p_lock_key bigint,
    p_holder_id text,
    p_fence_generation bigint,
    p_operation_id text
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
    v_permit relay_state_private.dispatch_permit%ROWTYPE;
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
    SELECT permit.* INTO v_permit
    FROM relay_state_private.dispatch_permit AS permit
    WHERE permit.operation_id = p_operation_id;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'unknown'::text, NULL::bigint;
    ELSIF v_permit.fence_generation <> p_fence_generation
          OR v_permit.holder_id <> p_holder_id THEN
        RETURN QUERY SELECT 'stale_generation'::text,
            floor(extract(epoch FROM v_permit.deadline_at) * 1000)::bigint;
    ELSIF v_permit.abandoned_at IS NOT NULL THEN
        RETURN QUERY SELECT 'abandoned'::text,
            floor(extract(epoch FROM v_permit.deadline_at) * 1000)::bigint;
    ELSIF v_permit.completed_at IS NOT NULL THEN
        RETURN QUERY SELECT 'completed'::text,
            floor(extract(epoch FROM v_permit.deadline_at) * 1000)::bigint;
    ELSIF clock_timestamp() >= v_permit.deadline_at THEN
        RETURN QUERY SELECT 'expired'::text,
            floor(extract(epoch FROM v_permit.deadline_at) * 1000)::bigint;
    ELSE
        RETURN QUERY SELECT 'authorized'::text,
            floor(extract(epoch FROM v_permit.deadline_at) * 1000)::bigint;
    END IF;
END;
$function$;

CREATE OR REPLACE FUNCTION relay_state_api.dispatch_permit_complete_v1(
    p_lock_key bigint,
    p_holder_id text,
    p_fence_generation bigint,
    p_operation_id text
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
    v_permit relay_state_private.dispatch_permit%ROWTYPE;
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
        RETURN QUERY SELECT 'ownership_lost'::text;
        RETURN;
    END IF;
    SELECT permit.* INTO v_permit
    FROM relay_state_private.dispatch_permit AS permit
    WHERE permit.operation_id = p_operation_id;
    IF NOT FOUND THEN
        RETURN QUERY SELECT 'unknown'::text;
    ELSIF v_permit.fence_generation <> p_fence_generation
          OR v_permit.holder_id <> p_holder_id THEN
        RETURN QUERY SELECT 'stale_generation'::text;
    ELSIF v_permit.abandoned_at IS NOT NULL THEN
        RETURN QUERY SELECT 'abandoned'::text;
    ELSIF v_permit.completed_at IS NOT NULL THEN
        RETURN QUERY SELECT 'already_completed'::text;
    ELSE
        UPDATE relay_state_private.dispatch_permit AS permit
        SET completed_at = clock_timestamp()
        WHERE permit.operation_id = p_operation_id
          AND permit.completed_at IS NULL AND permit.abandoned_at IS NULL;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'dispatch permit completion changed concurrently'
                USING ERRCODE = '55000';
        END IF;
        RETURN QUERY SELECT 'completed'::text;
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
ALTER FUNCTION relay_state_private.capability_valid_v1() OWNER TO CURRENT_USER;
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
ALTER FUNCTION relay_state_api.audit_readiness_v1(text) OWNER TO CURRENT_USER;
ALTER FUNCTION relay_state_api.audit_pseudonym_keyring_readiness_v1(text, text)
    OWNER TO CURRENT_USER;
ALTER FUNCTION relay_state_api.serving_fence_acquire_v1(bigint, text)
    OWNER TO CURRENT_USER;
ALTER FUNCTION relay_state_api.serving_fence_finalize_v1(bigint, text, bigint)
    OWNER TO CURRENT_USER;
ALTER FUNCTION relay_state_api.serving_fence_status_v1(bigint, text, bigint)
    OWNER TO CURRENT_USER;
ALTER FUNCTION relay_state_api.dispatch_permit_create_v1(
    bigint, text, bigint, text, integer
) OWNER TO CURRENT_USER;
ALTER FUNCTION relay_state_api.dispatch_permit_authorize_v1(
    bigint, text, bigint, text
) OWNER TO CURRENT_USER;
ALTER FUNCTION relay_state_api.dispatch_permit_complete_v1(
    bigint, text, bigint, text
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
GRANT EXECUTE ON FUNCTION relay_state_api.audit_readiness_v1(text) TO {runtime};
GRANT EXECUTE ON FUNCTION relay_state_api.serving_fence_acquire_v1(bigint, text)
    TO {runtime};
GRANT EXECUTE ON FUNCTION relay_state_api.serving_fence_finalize_v1(bigint, text, bigint)
    TO {runtime};
GRANT EXECUTE ON FUNCTION relay_state_api.serving_fence_status_v1(bigint, text, bigint)
    TO {runtime};
GRANT EXECUTE ON FUNCTION relay_state_api.dispatch_permit_create_v1(
    bigint, text, bigint, text, integer
) TO {runtime};
GRANT EXECUTE ON FUNCTION relay_state_api.dispatch_permit_authorize_v1(
    bigint, text, bigint, text
) TO {runtime};
GRANT EXECUTE ON FUNCTION relay_state_api.dispatch_permit_complete_v1(
    bigint, text, bigint, text
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
    if !helper_body_matches(client, role_oids.owner)
        .await
        .map_err(|_| StatePlaneInstallError::Unavailable)?
    {
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
            .split("CREATE OR REPLACE FUNCTION relay_state_api.quota_reserve_v1")
            .next()
            .expect("audit migration prefix");
        assert!(!audit_sql.contains("FOR UPDATE"));
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
            20
        );
        assert_eq!(
            POSTGRES_STATE_PLANE_MIGRATION_V1
                .matches("set_config('idle_in_transaction_session_timeout', '5s', false)")
                .count(),
            17
        );
        assert_eq!(
            POSTGRES_STATE_PLANE_MIGRATION_V1
                .matches("SET synchronous_commit = 'on'")
                .count(),
            20
        );
        assert_eq!(
            POSTGRES_STATE_PLANE_MIGRATION_V1
                .matches("set_config('synchronous_commit', 'on', false)")
                .count(),
            17
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
