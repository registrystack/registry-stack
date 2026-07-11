// SPDX-License-Identifier: Apache-2.0
//! Installation and catalog attestation for Relay's PostgreSQL state plane.

use std::fmt;

use thiserror::Error;
use tokio_postgres::{Client, GenericClient, Row, Transaction};

use super::fence::ServingFenceLockKey;

pub(crate) const DURABLE_AUDIT_CAPABILITY_V1: &str = "registry.relay.postgres-durable-audit/v1";
pub(crate) const SERVING_FENCE_CAPABILITY_V1: &str = "registry.relay.postgres-serving-fence/v1";
pub(crate) const STATE_PLANE_SCHEMA_VERSION_V1: i32 = 1;
pub(crate) const STATE_PLANE_SCHEMA_FINGERPRINT_V1: &str =
    "sha256:bd1058dd6010b0b2e6f27200149bbc488b54a0516178def93a04b3a380144418";

pub(super) const MIGRATION_ADVISORY_LOCK_KEY_V1: i64 = 7_221_091_440;
const SUPPORTED_POSTGRES_MIN_MAJOR: i32 = 16;
const SUPPORTED_POSTGRES_MAX_MAJOR: i32 = 18;

// Filled from the semantic catalog descriptor below on disposable supported
// PostgreSQL majors. Constraint rendering is explicitly versioned because
// pg_get_constraintdef is not a cross-major wire contract.
const CONSTRAINT_FINGERPRINT_PG16: &str = "22a9c0e13067bbc7210faff7d5ca840c";
const CONSTRAINT_FINGERPRINT_PG17: &str = "22a9c0e13067bbc7210faff7d5ca840c";
const CONSTRAINT_FINGERPRINT_PG18: &str = "a12595e348f0730b0e72d376246cc8a7";
const COLUMN_FINGERPRINT_PG16: &str = "d609ba7f07d479944391a6a2e2fbc356";
const COLUMN_FINGERPRINT_PG17: &str = "d609ba7f07d479944391a6a2e2fbc356";
const COLUMN_FINGERPRINT_PG18: &str = "d609ba7f07d479944391a6a2e2fbc356";
const FUNCTION_FINGERPRINT_PG16: &str = "bda2c51bcd31a82ad8e81cf3d0e4b346";
const FUNCTION_FINGERPRINT_PG17: &str = "bda2c51bcd31a82ad8e81cf3d0e4b346";
const FUNCTION_FINGERPRINT_PG18: &str = "bda2c51bcd31a82ad8e81cf3d0e4b346";
const CAPABILITY_HELPER_BODY_FINGERPRINT_V1: &str = "287f29327b683efbf1a8c582a35e67fe";

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
    chain_key_epoch_id text NOT NULL,
    serving_fence_capability_id text NOT NULL,
    serving_fence_lock_key bigint NOT NULL,
    installed_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    CONSTRAINT state_plane_metadata_pk PRIMARY KEY (singleton),
    CONSTRAINT state_plane_metadata_singleton_check CHECK (singleton),
    CONSTRAINT state_plane_metadata_schema_version_check CHECK (schema_version = 1),
    CONSTRAINT state_plane_metadata_capability_id_check CHECK (
        capability_id = 'registry.relay.postgres-durable-audit/v1'
    ),
    CONSTRAINT state_plane_metadata_fingerprint_check CHECK (
        capability_fingerprint =
        'sha256:bd1058dd6010b0b2e6f27200149bbc488b54a0516178def93a04b3a380144418'
    ),
    CONSTRAINT state_plane_metadata_roles_distinct_check CHECK (
        owner_role_oid <> runtime_role_oid
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

ALTER TABLE relay_state_private.state_plane_metadata OWNER TO CURRENT_USER;
ALTER TABLE relay_state_private.audit_chain_head OWNER TO CURRENT_USER;
ALTER TABLE relay_state_private.audit_phase OWNER TO CURRENT_USER;
ALTER TABLE relay_state_private.serving_fence_state OWNER TO CURRENT_USER;
ALTER TABLE relay_state_private.dispatch_permit OWNER TO CURRENT_USER;
REVOKE ALL ON ALL TABLES IN SCHEMA relay_state_private FROM PUBLIC;
REVOKE ALL ON ALL SEQUENCES IN SCHEMA relay_state_private FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA relay_state_private REVOKE ALL ON TABLES FROM PUBLIC;
ALTER DEFAULT PRIVILEGES IN SCHEMA relay_state_private REVOKE ALL ON SEQUENCES FROM PUBLIC;

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
        'sha256:bd1058dd6010b0b2e6f27200149bbc488b54a0516178def93a04b3a380144418'
      AND serving_fence_capability_id = 'registry.relay.postgres-serving-fence/v1'
      AND serving_fence_lock_key <> 0
      AND serving_fence_lock_key <> 7221091440
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
          'serving_fence_state', 'dispatch_permit'
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
          'serving_fence_state', 'dispatch_permit'
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
          'serving_fence_state', 'dispatch_permit'
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
          'serving_fence_state', 'dispatch_permit'
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
        || ':body=' || CASE WHEN function_row.nspname = 'relay_state_api'
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
    AND EXISTS (
        SELECT 1 FROM metadata AS bound
        JOIN pg_catalog.pg_roles AS owner_role ON owner_role.oid = bound.owner_role_oid
        JOIN pg_catalog.pg_roles AS runtime_role ON runtime_role.oid = bound.runtime_role_oid
        WHERE bound.owner_role_oid = (SELECT oid FROM pg_catalog.pg_roles WHERE rolname = current_user)
          AND NOT owner_role.rolcanlogin AND NOT owner_role.rolsuper
          AND NOT owner_role.rolcreaterole AND NOT owner_role.rolbypassrls
          AND NOT owner_role.rolreplication AND NOT owner_role.rolcreatedb
          AND runtime_role.rolcanlogin AND NOT runtime_role.rolsuper
          AND NOT runtime_role.rolcreaterole AND NOT runtime_role.rolbypassrls
          AND NOT runtime_role.rolreplication AND NOT runtime_role.rolcreatedb
          AND NOT EXISTS (
              SELECT 1 FROM pg_catalog.pg_auth_members AS membership
              WHERE membership.member IN (bound.owner_role_oid, bound.runtime_role_oid)
                 OR membership.roleid IN (bound.owner_role_oid, bound.runtime_role_oid)
          )
    )
    AND (SELECT count(*) = 2 FROM target_schemas)
    AND NOT EXISTS (
        SELECT 1 FROM target_schemas, metadata
        WHERE target_schemas.nspowner <> metadata.owner_role_oid
    )
    AND (SELECT count(*) = 5 FROM target_relations)
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
               'serving_fence_state', 'dispatch_permit'
           )
    )
    AND (SELECT count(*) = 8 FROM target_indexes)
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
               'dispatch_permit_takeover_idx'
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
           )
           OR (
               target_indexes.index_name IN (
                   'state_plane_metadata_pk', 'audit_chain_head_pk', 'audit_phase_pk',
                   'serving_fence_state_pk', 'dispatch_permit_pk'
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
    AND (SELECT count(*) = 11 FROM target_functions)
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
               AND NOT (target_functions.proname = 'capability_valid_v1'
                        AND NOT target_functions.prosecdef
                        AND target_functions.lanname = 'sql'))
           OR (target_functions.nspname = 'relay_state_api'
                       AND NOT (target_functions.proname IN (
                            'audit_phase_snapshot_v1', 'audit_phase_cas_v1', 'audit_readiness_v1',
                            'serving_fence_acquire_v1', 'serving_fence_finalize_v1',
                            'serving_fence_status_v1', 'dispatch_permit_create_v1',
                            'dispatch_permit_authorize_v1', 'dispatch_permit_complete_v1',
                            'serving_fence_release_v1'
                       )
                        AND target_functions.prosecdef
                        AND target_functions.lanname = 'plpgsql'))
           OR target_functions.nspname NOT IN ('relay_state_private', 'relay_state_api')
    )
    AND (SELECT count(*) = 5 FROM schema_acl)
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
                   AND schema_acl.grantee = metadata.runtime_role_oid
                   AND schema_acl.privilege_type = 'USAGE')
           )
    )
    AND (SELECT count(*) FROM table_acl) = (
        SELECT 5 * count(*) FROM metadata
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
    AND (SELECT count(*) = 21 FROM function_acl)
    AND NOT EXISTS (
        SELECT 1 FROM function_acl, metadata
        WHERE function_acl.grantor <> metadata.owner_role_oid
           OR function_acl.is_grantable
           OR function_acl.privilege_type <> 'EXECUTE'
           OR NOT (
               (function_acl.nspname = 'relay_state_private'
                AND function_acl.grantee = metadata.owner_role_oid)
               OR (function_acl.nspname = 'relay_state_api'
                   AND function_acl.grantee IN (
                       metadata.owner_role_oid, metadata.runtime_role_oid
                   ))
           )
    )
    AND (SELECT value = CASE server.major
            WHEN 16 THEN '22a9c0e13067bbc7210faff7d5ca840c'
            WHEN 17 THEN '22a9c0e13067bbc7210faff7d5ca840c'
            WHEN 18 THEN 'a12595e348f0730b0e72d376246cc8a7'
            ELSE '' END FROM constraint_fingerprint, server)
    AND (SELECT value = CASE server.major
            WHEN 16 THEN 'd609ba7f07d479944391a6a2e2fbc356'
            WHEN 17 THEN 'd609ba7f07d479944391a6a2e2fbc356'
            WHEN 18 THEN 'd609ba7f07d479944391a6a2e2fbc356'
            ELSE '' END FROM column_fingerprint, server)
    AND (SELECT value = CASE server.major
            WHEN 16 THEN 'bda2c51bcd31a82ad8e81cf3d0e4b346'
            WHEN 17 THEN 'bda2c51bcd31a82ad8e81cf3d0e4b346'
            WHEN 18 THEN 'bda2c51bcd31a82ad8e81cf3d0e4b346'
            ELSE '' END FROM function_fingerprint, server);
$function$;

CREATE OR REPLACE FUNCTION relay_state_api.audit_phase_snapshot_v1(
    p_stream_kind text,
    p_operation_id text,
    p_phase text,
    p_payload_digest bytea
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
       OR p_payload_digest IS NULL
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
    SELECT phase_row.* INTO v_existing
    FROM relay_state_private.audit_phase AS phase_row
    WHERE phase_row.stream_kind = p_stream_kind
      AND phase_row.operation_id = p_operation_id
      AND phase_row.phase = p_phase;
    IF FOUND THEN
        IF clock_timestamp() - v_started_at > interval '5 seconds' THEN
            RAISE EXCEPTION 'durable audit snapshot exceeded its deadline'
                USING ERRCODE = '57014';
        END IF;
        RETURN QUERY SELECT
            CASE WHEN v_existing.payload_digest = p_payload_digest
                THEN 'identical_duplicate'::text ELSE 'conflicting_duplicate'::text END,
            v_existing.envelope_id, v_existing.record_hash,
            NULL::bytea, NULL::bigint;
        RETURN;
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
    p_attempt_record_hash bytea
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
    v_record jsonb;
    v_envelope jsonb;
    v_expected_digest text;
    v_inserted_rows bigint;
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
    chain_key_epoch_id text
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
           metadata.chain_key_epoch_id
    FROM relay_state_private.state_plane_metadata AS metadata
    WHERE metadata.singleton = true;
    IF clock_timestamp() - v_started_at > interval '5 seconds' THEN
        RAISE EXCEPTION 'durable audit readiness exceeded its deadline'
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

ALTER FUNCTION relay_state_private.capability_valid_v1() OWNER TO CURRENT_USER;
ALTER FUNCTION relay_state_api.audit_phase_snapshot_v1(text, text, text, bytea)
    OWNER TO CURRENT_USER;
ALTER FUNCTION relay_state_api.audit_phase_cas_v1(
    text, text, text, bytea, bigint, bytea, text, bigint,
    text, text, bytea, text, bytea
) OWNER TO CURRENT_USER;
ALTER FUNCTION relay_state_api.audit_readiness_v1(text) OWNER TO CURRENT_USER;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub(crate) enum StatePlaneInstallError {
    #[error("Relay state-plane runtime role is invalid")]
    InvalidRuntimeRole,
    #[error("Relay state-plane chain-key epoch identifier is invalid")]
    InvalidChainKeyEpochId,
    #[error("Relay state-plane installation session is not an isolated owner migration")]
    InvalidMigrationAuthority,
    #[error("Relay state-plane owner role is not isolated")]
    OwnerRoleNotIsolated,
    #[error("Relay state-plane runtime role is not isolated")]
    RuntimeRoleNotIsolated,
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
}

pub(crate) async fn install_postgres_state_plane_v1(
    client: &mut Client,
    runtime_role: &RuntimeDatabaseRole,
    chain_key_epoch_id: &AuditChainKeyEpochId,
    serving_fence_lock_key: ServingFenceLockKey,
) -> Result<(), StatePlaneInstallError> {
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

    let role_oids = validate_install_roles(&transaction, runtime_role).await?;
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
    )
    .await?;
    transaction
        .batch_execute(&runtime_role_grants_sql(runtime_role))
        .await
        .map_err(|_| StatePlaneInstallError::Unavailable)?;
    if !owner_capability_matches(
        &transaction,
        role_oids,
        chain_key_epoch_id,
        serving_fence_lock_key,
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
) -> Result<BoundRoleOids, StatePlaneInstallError> {
    let row = transaction
        .query_opt(
            r#"
SELECT owner_role.oid::bigint AS owner_oid,
       runtime_role.oid::bigint AS runtime_oid,
       session_role.rolsuper AS session_is_superuser,
       session_role.oid <> owner_role.oid AS session_is_distinct,
       NOT owner_role.rolcanlogin AND NOT owner_role.rolsuper
         AND NOT owner_role.rolcreaterole AND NOT owner_role.rolbypassrls
         AND NOT owner_role.rolreplication AND NOT owner_role.rolcreatedb AS owner_safe,
       runtime_role.rolcanlogin AND NOT runtime_role.rolsuper
         AND NOT runtime_role.rolcreaterole AND NOT runtime_role.rolbypassrls
         AND NOT runtime_role.rolreplication AND NOT runtime_role.rolcreatedb AS runtime_safe,
       NOT EXISTS (
           SELECT 1 FROM pg_catalog.pg_auth_members AS membership
           WHERE membership.member = owner_role.oid OR membership.roleid = owner_role.oid
       ) AS owner_membership_safe,
       NOT EXISTS (
           SELECT 1 FROM pg_catalog.pg_auth_members AS membership
           WHERE membership.member = runtime_role.oid OR membership.roleid = runtime_role.oid
       ) AS runtime_membership_safe,
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
       current_setting('server_version_num')::integer / 10000 BETWEEN $2 AND $3
         AS version_safe
FROM pg_catalog.pg_roles AS owner_role
JOIN pg_catalog.pg_roles AS session_role ON session_role.rolname = session_user
JOIN pg_catalog.pg_roles AS runtime_role ON runtime_role.rolname = $1
WHERE owner_role.rolname = current_user
"#,
            &[
                &runtime_role.0,
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
    let role_oids = BoundRoleOids {
        owner: try_i64(&row, "owner_oid")?,
        runtime: try_i64(&row, "runtime_oid")?,
    };
    if role_oids.owner == role_oids.runtime {
        return Err(StatePlaneInstallError::RuntimeRoleNotIsolated);
    }
    Ok(role_oids)
}

async fn bind_or_validate_metadata(
    transaction: &Transaction<'_>,
    role_oids: BoundRoleOids,
    chain_key_epoch_id: &AuditChainKeyEpochId,
    serving_fence_lock_key: ServingFenceLockKey,
) -> Result<(), StatePlaneInstallError> {
    let existing = transaction
        .query_opt(
            r#"
SELECT schema_version, capability_id, capability_fingerprint,
       owner_role_oid::bigint AS owner_role_oid,
       runtime_role_oid::bigint AS runtime_role_oid, chain_key_epoch_id,
       serving_fence_capability_id, serving_fence_lock_key
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
            && try_str(&existing, "chain_key_epoch_id")? == chain_key_epoch_id.as_str()
            && try_str(&existing, "serving_fence_capability_id")? == SERVING_FENCE_CAPABILITY_V1
            && try_i64(&existing, "serving_fence_lock_key")? == serving_fence_lock_key.as_i64();
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
    owner_role_oid, runtime_role_oid, chain_key_epoch_id,
    serving_fence_capability_id, serving_fence_lock_key
) VALUES (true, $1, $2, $3, $4::bigint::oid, $5::bigint::oid, $6, $7, $8)
"#,
            &[
                &STATE_PLANE_SCHEMA_VERSION_V1,
                &DURABLE_AUDIT_CAPABILITY_V1,
                &STATE_PLANE_SCHEMA_FINGERPRINT_V1,
                &role_oids.owner,
                &role_oids.runtime,
                &chain_key_epoch_id.as_str(),
                &SERVING_FENCE_CAPABILITY_V1,
                &serving_fence_lock_key.as_i64(),
            ],
        )
        .await
        .map_err(|_| StatePlaneInstallError::Unavailable)?;
    Ok(())
}

fn runtime_role_grants_sql(runtime_role: &RuntimeDatabaseRole) -> String {
    let role = runtime_role.quoted();
    format!(
        r#"
REVOKE ALL ON SCHEMA relay_state_private FROM {role};
REVOKE ALL ON ALL TABLES IN SCHEMA relay_state_private FROM {role};
REVOKE ALL ON ALL SEQUENCES IN SCHEMA relay_state_private FROM {role};
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA relay_state_private FROM {role};
REVOKE ALL ON SCHEMA relay_state_api FROM {role};
REVOKE ALL ON ALL FUNCTIONS IN SCHEMA relay_state_api FROM {role};
GRANT USAGE ON SCHEMA relay_state_api TO {role};
GRANT EXECUTE ON FUNCTION relay_state_api.audit_phase_snapshot_v1(text, text, text, bytea)
    TO {role};
GRANT EXECUTE ON FUNCTION relay_state_api.audit_phase_cas_v1(
    text, text, text, bytea, bigint, bytea, text, bigint,
    text, text, bytea, text, bytea
) TO {role};
GRANT EXECUTE ON FUNCTION relay_state_api.audit_readiness_v1(text) TO {role};
GRANT EXECUTE ON FUNCTION relay_state_api.serving_fence_acquire_v1(bigint, text)
    TO {role};
GRANT EXECUTE ON FUNCTION relay_state_api.serving_fence_finalize_v1(bigint, text, bigint)
    TO {role};
GRANT EXECUTE ON FUNCTION relay_state_api.serving_fence_status_v1(bigint, text, bigint)
    TO {role};
GRANT EXECUTE ON FUNCTION relay_state_api.dispatch_permit_create_v1(
    bigint, text, bigint, text, integer
) TO {role};
GRANT EXECUTE ON FUNCTION relay_state_api.dispatch_permit_authorize_v1(
    bigint, text, bigint, text
) TO {role};
GRANT EXECUTE ON FUNCTION relay_state_api.dispatch_permit_complete_v1(
    bigint, text, bigint, text
) TO {role};
GRANT EXECUTE ON FUNCTION relay_state_api.serving_fence_release_v1(bigint, text, bigint)
    TO {role};
"#
    )
}

async fn owner_capability_matches(
    client: &impl GenericClient,
    role_oids: BoundRoleOids,
    chain_key_epoch_id: &AuditChainKeyEpochId,
    serving_fence_lock_key: ServingFenceLockKey,
) -> Result<bool, StatePlaneInstallError> {
    let metadata = client
        .query_opt(
            r#"
SELECT schema_version, capability_id, capability_fingerprint,
       owner_role_oid::bigint AS owner_role_oid,
       runtime_role_oid::bigint AS runtime_role_oid, chain_key_epoch_id,
       serving_fence_capability_id, serving_fence_lock_key
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
        && try_str(&metadata, "chain_key_epoch_id")? == chain_key_epoch_id.as_str()
        && try_str(&metadata, "serving_fence_capability_id")? == SERVING_FENCE_CAPABILITY_V1
        && try_i64(&metadata, "serving_fence_lock_key")? == serving_fence_lock_key.as_i64();
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
    if !try_bool_runtime(&readiness, "ready")?
        || try_str_runtime(&readiness, "capability_id")? != DURABLE_AUDIT_CAPABILITY_V1
        || try_str_runtime(&readiness, "capability_fingerprint")?
            != STATE_PLANE_SCHEMA_FINGERPRINT_V1
        || try_str_runtime(&readiness, "chain_key_epoch_id")? != chain_key_epoch_id.as_str()
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
    use super::*;

    #[test]
    fn migration_uses_optimistic_cas_not_cross_call_reservations() {
        assert!(POSTGRES_STATE_PLANE_MIGRATION_V1.contains("audit_phase_snapshot_v1"));
        assert!(POSTGRES_STATE_PLANE_MIGRATION_V1.contains("audit_phase_cas_v1"));
        assert!(
            POSTGRES_STATE_PLANE_MIGRATION_V1.contains("head.generation = p_candidate_generation")
        );
        assert!(!POSTGRES_STATE_PLANE_MIGRATION_V1.contains("audit_phase_preparation"));
        assert!(!POSTGRES_STATE_PLANE_MIGRATION_V1.contains("FOR UPDATE"));
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
            11
        );
        assert_eq!(
            POSTGRES_STATE_PLANE_MIGRATION_V1
                .matches("set_config('idle_in_transaction_session_timeout', '5s', false)")
                .count(),
            10
        );
        assert_eq!(
            POSTGRES_STATE_PLANE_MIGRATION_V1
                .matches("SET synchronous_commit = 'on'")
                .count(),
            11
        );
        assert_eq!(
            POSTGRES_STATE_PLANE_MIGRATION_V1
                .matches("set_config('synchronous_commit', 'on', false)")
                .count(),
            10
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
}
