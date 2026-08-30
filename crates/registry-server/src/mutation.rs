// SPDX-License-Identifier: Apache-2.0

//! One product-owned PostgreSQL transaction for a complete record mutation.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use deadpool_postgres::Client;
use registry_platform_audit::AuditProfile;
use registry_platform_canonical_json::canonicalize_json;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio_postgres::types::ToSql;
use tokio_postgres::{error::SqlState, GenericClient, Transaction};
use uuid::Uuid;

use crate::artifacts::event_data_schema_binding;
use crate::audit::{
    append_terminal_audit, profile_is_keyed, record_pre_io_audit, PreIoAudit, PreIoAuditKind,
    RegistryAuditError, TerminalAudit, TerminalAuditOutcome,
};
use crate::compiler::{
    WEBHOOK_ATTEMPT_TIMEOUT_MS, WEBHOOK_BACKOFF_MULTIPLIER, WEBHOOK_INITIAL_BACKOFF_MS,
    WEBHOOK_MAXIMUM_ATTEMPTS, WEBHOOK_MAXIMUM_BACKOFF_MS,
};
use crate::contract::{
    AccessProfileSource, EventTrigger, FieldTypeSource, MutationMode, Operation,
};
use crate::data::{validate_field_value, FieldValue};
use crate::event_destination::ActivatedEventDestinationRegistry;
use crate::idempotency::{
    insert_result, lock_and_load, resolve_binding, HeldResponse, IdempotencyBinding,
    IdempotencyError, PermittedResponseHeader, StoredResultMetadata,
};
use crate::model::{
    CompiledEntity, CompiledEventDelivery, CompiledRegistry, CompiledRoute,
    CompiledWebhookDeliveryMode, CompiledWebhookRetryProfile, HttpMethod,
};
use crate::outbox::{insert_configured_events, OutboxError, OutboxMutation};
use crate::postgres::{
    begin_record_transaction, ClaimContext, ExpectedRegistryIdentity, RegistryLockKey,
    SqlIdentifier,
};
use crate::revision::{canonical_snapshot, insert_revision, RevisionError, RevisionInsert};

const MAX_LOGICAL_ID_BYTES: usize = 256;
const TOMBSTONE_CURSOR: &str = "registry_tombstone_current";

/// Install the exact W3 mutation journal contract with the migration role.
///
/// The schema is intentionally product-owned here. PostgreSQL catalog closure
/// consumes these exact objects rather than independently defining them.
pub async fn install_mutation_schema(
    migration: &impl GenericClient,
    runtime_role: &SqlIdentifier,
) -> Result<(), MutationError> {
    migration
        .batch_execute(
            "CREATE TABLE IF NOT EXISTS registry_internal.registry_revisions (
                 entity_id text NOT NULL CHECK (entity_id <> ''),
                 record_id uuid NOT NULL,
                 record_reference text NOT NULL CHECK (record_reference <> ''),
                 record_revision bigint NOT NULL CHECK (record_revision > 0),
                 predecessor_revision bigint
                     CHECK (predecessor_revision IS NULL OR predecessor_revision > 0),
                 record_lifecycle text NOT NULL
                     CHECK (record_lifecycle IN ('active', 'tombstoned')),
                 package_revision text NOT NULL CHECK (package_revision <> ''),
                 operation_id text NOT NULL CHECK (operation_id <> ''),
                 mutation_kind text NOT NULL
                     CHECK (mutation_kind IN ('create', 'patch', 'tombstone')),
                 principal_reference text NOT NULL CHECK (principal_reference <> ''),
                 request_reference text NOT NULL CHECK (request_reference <> ''),
                 snapshot bytea NOT NULL
                     CHECK (octet_length(snapshot) > 0 AND octet_length(snapshot) <= 2097152),
                 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                 PRIMARY KEY (entity_id, record_id, record_revision),
                 CHECK (predecessor_revision IS NULL OR predecessor_revision < record_revision)
             );
             CREATE TABLE IF NOT EXISTS registry_internal.registry_outbox (
                 outbox_id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
                 event_id uuid NOT NULL UNIQUE,
                 event_type text NOT NULL CHECK (event_type <> ''),
                 trigger text NOT NULL CHECK (trigger IN ('created', 'patched', 'tombstoned')),
                 entity_id text NOT NULL CHECK (entity_id <> ''),
                 record_reference text NOT NULL CHECK (record_reference <> ''),
                 record_revision bigint NOT NULL CHECK (record_revision > 0),
                 package_revision text NOT NULL CHECK (package_revision <> ''),
                 schema_fingerprint text NOT NULL CHECK (schema_fingerprint <> ''),
                 payload bytea
                     CONSTRAINT registry_outbox_payload_bounds CHECK (
                         payload IS NULL OR
                         (octet_length(payload) > 0 AND octet_length(payload) <= 2097152)
                     ),
                 payload_expires_at timestamptz NOT NULL,
                 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                 UNIQUE (event_id, package_revision, schema_fingerprint)
             );
             CREATE TABLE IF NOT EXISTS registry_internal.registry_webhook_deliveries (
                 event_id uuid NOT NULL,
                 compiled_delivery_id text NOT NULL
                     CHECK (compiled_delivery_id <> '' AND octet_length(compiled_delivery_id) <= 256),
                 logical_destination_id text NOT NULL
                     CHECK (logical_destination_id ~ '^[a-z][a-z0-9_-]{0,63}$'),
                 destination_binding_digest text NOT NULL
                     CHECK (destination_binding_digest ~ '^sha256:[0-9a-f]{64}$'),
                 package_revision text NOT NULL
                     CHECK (package_revision <> '' AND octet_length(package_revision) <= 256),
                 schema_fingerprint text NOT NULL
                     CHECK (schema_fingerprint <> '' AND octet_length(schema_fingerprint) <= 256),
                 data_schema text NOT NULL
                     CONSTRAINT registry_webhook_delivery_data_schema_bounds CHECK (
                         data_schema <> '' AND octet_length(data_schema) <= 2048
                     ),
                 classification_ceiling text NOT NULL
                     CHECK (classification_ceiling IN ('public', 'internal', 'restricted')),
                 authentication_profile text NOT NULL
                     CHECK (authentication_profile = 'hmac_sha256_v1'),
                 delivery_mode text NOT NULL CHECK (delivery_mode = 'after_commit'),
                 attempt_timeout_ms bigint NOT NULL
                     CHECK (attempt_timeout_ms BETWEEN 100 AND 10000),
                 initial_backoff_ms bigint NOT NULL
                     CHECK (initial_backoff_ms BETWEEN 100 AND 3600000),
                 maximum_backoff_ms bigint NOT NULL
                     CHECK (maximum_backoff_ms BETWEEN initial_backoff_ms AND 3600000),
                 exponential_backoff_multiplier smallint NOT NULL
                     CHECK (exponential_backoff_multiplier = 2),
                 maximum_attempts smallint NOT NULL
                     CHECK (maximum_attempts BETWEEN 1 AND 20),
                 retry_delays_ms bigint[] NOT NULL
                     CHECK (
                         cardinality(retry_delays_ms) = maximum_attempts - 1
                         AND array_position(retry_delays_ms, NULL) IS NULL
                         AND initial_backoff_ms <= ALL(retry_delays_ms)
                         AND maximum_backoff_ms >= ALL(retry_delays_ms)
                     ),
                 maximum_payload_bytes bigint NOT NULL
                     CHECK (maximum_payload_bytes BETWEEN 1 AND 1048576),
                 payload_digest bytea NOT NULL CHECK (octet_length(payload_digest) = 32),
                 deployed_attempt_timeout_ms bigint NOT NULL
                     CHECK (deployed_attempt_timeout_ms BETWEEN 100 AND attempt_timeout_ms),
                 deployed_maximum_attempts smallint NOT NULL
                     CHECK (deployed_maximum_attempts BETWEEN 1 AND maximum_attempts),
                 dead_letter text NOT NULL CHECK (dead_letter = 'required'),
                 operator_replay boolean NOT NULL,
                 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                 PRIMARY KEY (event_id, compiled_delivery_id),
                 FOREIGN KEY (event_id, package_revision, schema_fingerprint)
                     REFERENCES registry_internal.registry_outbox
                         (event_id, package_revision, schema_fingerprint)
                     ON DELETE RESTRICT
             );
             CREATE TABLE IF NOT EXISTS registry_internal.registry_webhook_delivery_state (
                 event_id uuid NOT NULL,
                 compiled_delivery_id text NOT NULL
                     CHECK (compiled_delivery_id <> '' AND octet_length(compiled_delivery_id) <= 256),
                 generation bigint NOT NULL CHECK (generation > 0),
                 state text NOT NULL
                     CONSTRAINT registry_webhook_delivery_state_values CHECK (
                         state IN ('pending', 'leased', 'delivered', 'dead_lettered', 'expired')
                     ),
                 attempt smallint NOT NULL CHECK (attempt BETWEEN 0 AND 20),
                 next_attempt_at timestamptz,
                 attempt_started_at timestamptz,
                 lease_expires_at timestamptz,
                 lease_token uuid,
                 delivered_at timestamptz,
                 dead_lettered_at timestamptz,
                 expired_at timestamptz,
                 updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                 PRIMARY KEY (event_id, compiled_delivery_id),
                 FOREIGN KEY (event_id, compiled_delivery_id)
                     REFERENCES registry_internal.registry_webhook_deliveries
                         (event_id, compiled_delivery_id)
                     ON DELETE RESTRICT,
                 CONSTRAINT registry_webhook_delivery_state_shape CHECK (
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
                     OR (state = 'dead_lettered'
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
                 )
             );
             CREATE INDEX IF NOT EXISTS registry_webhook_delivery_state_due_idx
                 ON registry_internal.registry_webhook_delivery_state
                     (next_attempt_at, event_id, compiled_delivery_id)
                 WHERE state = 'pending';
             CREATE INDEX IF NOT EXISTS registry_webhook_delivery_state_expired_idx
                 ON registry_internal.registry_webhook_delivery_state
                     (lease_expires_at, event_id, compiled_delivery_id)
                 WHERE state = 'leased';
             CREATE TABLE IF NOT EXISTS registry_internal.registry_audit (
                 envelope_id text PRIMARY KEY CHECK (envelope_id <> ''),
                 record_hash bytea NOT NULL UNIQUE CHECK (octet_length(record_hash) = 32),
                 envelope bytea NOT NULL
                     CHECK (octet_length(envelope) > 0 AND octet_length(envelope) <= 65536),
                 created_at timestamptz NOT NULL DEFAULT transaction_timestamp()
             );
             CREATE TABLE IF NOT EXISTS registry_internal.registry_audit_head (
                 singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
                 last_hash bytea CHECK (last_hash IS NULL OR octet_length(last_hash) = 32)
             );
             CREATE TABLE IF NOT EXISTS registry_internal.registry_idempotency (
                 key_reference text PRIMARY KEY CHECK (key_reference <> ''),
                 binding_reference text NOT NULL CHECK (binding_reference <> ''),
                 result_kind text NOT NULL CHECK (result_kind IN ('record', 'batch')),
                 record_reference text CHECK (record_reference <> ''),
                 record_revision bigint CHECK (record_revision > 0),
                 result_count smallint CHECK (result_count > 0 AND result_count <= 100),
                 response_status smallint NOT NULL CHECK (response_status BETWEEN 200 AND 299),
                 response_body bytea NOT NULL
                     CHECK (octet_length(response_body) > 0 AND octet_length(response_body) <= 2097152),
                 response_headers bytea NOT NULL CHECK (octet_length(response_headers) <= 65536),
                 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                 CHECK (
                     (result_kind = 'record' AND record_reference IS NOT NULL
                         AND record_revision IS NOT NULL AND result_count IS NULL)
                     OR
                     (result_kind = 'batch' AND record_reference IS NULL
                         AND record_revision IS NULL AND result_count IS NOT NULL)
                 )
             );
             REVOKE ALL ON registry_internal.registry_revisions,
                 registry_internal.registry_outbox,
                 registry_internal.registry_webhook_deliveries,
                 registry_internal.registry_webhook_delivery_state,
                 registry_internal.registry_audit,
                 registry_internal.registry_audit_head,
                 registry_internal.registry_idempotency FROM PUBLIC;",
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
    // `CREATE TABLE IF NOT EXISTS` does not evolve databases activated by an
    // earlier Registry Server build. Legacy outbox rows receive the
    // conservative seven-day default from their original capture time. A
    // legacy webhook row has no V1 data-schema binding, so it cannot safely be
    // reinterpreted as a V1 delivery and requires explicit operator migration.
    // Keep this upgrade idempotent so package activation cannot leave the
    // runtime expecting a column or nullability contract the durable outbox
    // does not have.
    migration
        .batch_execute(
            "ALTER TABLE registry_internal.registry_outbox
                 ADD COLUMN IF NOT EXISTS payload_expires_at timestamptz;
             UPDATE registry_internal.registry_outbox
                SET payload_expires_at = created_at + interval '7 days'
              WHERE payload_expires_at IS NULL;
             DO $registry_outbox_upgrade$
             BEGIN
                 IF EXISTS (
                     SELECT 1 FROM pg_catalog.pg_attribute
                      WHERE attrelid = 'registry_internal.registry_outbox'::regclass
                        AND attname = 'payload' AND attnotnull
                 ) THEN
                     ALTER TABLE registry_internal.registry_outbox
                         ALTER COLUMN payload DROP NOT NULL;
                 END IF;
                 IF EXISTS (
                     SELECT 1 FROM pg_catalog.pg_constraint
                      WHERE conrelid = 'registry_internal.registry_outbox'::regclass
                        AND conname = 'registry_outbox_payload_check'
                 ) THEN
                     ALTER TABLE registry_internal.registry_outbox
                         DROP CONSTRAINT registry_outbox_payload_check;
                 END IF;
                 IF NOT EXISTS (
                     SELECT 1 FROM pg_catalog.pg_constraint
                      WHERE conrelid = 'registry_internal.registry_outbox'::regclass
                        AND conname = 'registry_outbox_payload_bounds'
                 ) THEN
                     ALTER TABLE registry_internal.registry_outbox
                         ADD CONSTRAINT registry_outbox_payload_bounds CHECK (
                             payload IS NULL OR
                             (octet_length(payload) > 0 AND octet_length(payload) <= 2097152)
                         );
                 END IF;
                 IF EXISTS (
                     SELECT 1 FROM pg_catalog.pg_attribute
                      WHERE attrelid = 'registry_internal.registry_outbox'::regclass
                        AND attname = 'payload_expires_at' AND NOT attnotnull
                 ) THEN
                     ALTER TABLE registry_internal.registry_outbox
                         ALTER COLUMN payload_expires_at SET NOT NULL;
                 END IF;
             END
             $registry_outbox_upgrade$;
             ALTER TABLE registry_internal.registry_webhook_deliveries
                 ADD COLUMN IF NOT EXISTS data_schema text;
             DO $registry_webhook_delivery_upgrade$
             BEGIN
                 IF EXISTS (
                     SELECT 1
                       FROM registry_internal.registry_webhook_deliveries
                      WHERE data_schema IS NULL
                 ) THEN
                     RAISE EXCEPTION USING
                         MESSAGE = 'pre-V1 webhook history requires explicit operator migration';
                 END IF;
                 IF EXISTS (
                     SELECT 1 FROM pg_catalog.pg_attribute
                      WHERE attrelid =
                            'registry_internal.registry_webhook_deliveries'::regclass
                        AND attname = 'data_schema' AND NOT attnotnull
                 ) THEN
                     ALTER TABLE registry_internal.registry_webhook_deliveries
                         ALTER COLUMN data_schema SET NOT NULL;
                 END IF;
                 IF NOT EXISTS (
                     SELECT 1 FROM pg_catalog.pg_constraint
                      WHERE conrelid =
                            'registry_internal.registry_webhook_deliveries'::regclass
                        AND conname = 'registry_webhook_delivery_data_schema_bounds'
                 ) THEN
                     ALTER TABLE registry_internal.registry_webhook_deliveries
                         ADD CONSTRAINT registry_webhook_delivery_data_schema_bounds CHECK (
                             data_schema <> '' AND octet_length(data_schema) <= 2048
                         );
                 END IF;
             END
             $registry_webhook_delivery_upgrade$;
             ALTER TABLE registry_internal.registry_webhook_delivery_state
                 ADD COLUMN IF NOT EXISTS expired_at timestamptz;
             DO $registry_webhook_state_upgrade$
             BEGIN
                 IF EXISTS (
                     SELECT 1 FROM pg_catalog.pg_constraint
                      WHERE conrelid =
                            'registry_internal.registry_webhook_delivery_state'::regclass
                        AND conname = 'registry_webhook_delivery_state_state_check'
                 ) THEN
                     ALTER TABLE registry_internal.registry_webhook_delivery_state
                         DROP CONSTRAINT registry_webhook_delivery_state_state_check;
                 END IF;
                 IF EXISTS (
                     SELECT 1 FROM pg_catalog.pg_constraint
                      WHERE conrelid =
                            'registry_internal.registry_webhook_delivery_state'::regclass
                        AND conname = 'registry_webhook_delivery_state_check'
                 ) THEN
                     ALTER TABLE registry_internal.registry_webhook_delivery_state
                         DROP CONSTRAINT registry_webhook_delivery_state_check;
                 END IF;
                 IF NOT EXISTS (
                     SELECT 1 FROM pg_catalog.pg_constraint
                      WHERE conrelid =
                            'registry_internal.registry_webhook_delivery_state'::regclass
                        AND conname = 'registry_webhook_delivery_state_values'
                 ) THEN
                     ALTER TABLE registry_internal.registry_webhook_delivery_state
                         ADD CONSTRAINT registry_webhook_delivery_state_values CHECK (
                             state IN (
                                 'pending', 'leased', 'delivered', 'dead_lettered', 'expired'
                             )
                         );
                 END IF;
                 IF NOT EXISTS (
                     SELECT 1 FROM pg_catalog.pg_constraint
                      WHERE conrelid =
                            'registry_internal.registry_webhook_delivery_state'::regclass
                        AND conname = 'registry_webhook_delivery_state_shape'
                 ) THEN
                     ALTER TABLE registry_internal.registry_webhook_delivery_state
                         ADD CONSTRAINT registry_webhook_delivery_state_shape CHECK (
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
                             OR (state = 'dead_lettered'
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
                         );
                 END IF;
             END
             $registry_webhook_state_upgrade$;",
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
    let role = runtime_role.as_str();
    migration
        .batch_execute(&format!(
            "REVOKE ALL ON registry_internal.registry_revisions,
                 registry_internal.registry_outbox,
                 registry_internal.registry_webhook_deliveries,
                 registry_internal.registry_webhook_delivery_state,
                 registry_internal.registry_audit,
                 registry_internal.registry_audit_head,
                 registry_internal.registry_idempotency FROM \"{role}\";
             GRANT SELECT, INSERT ON registry_internal.registry_revisions,
                 registry_internal.registry_outbox,
                 registry_internal.registry_webhook_deliveries,
                 registry_internal.registry_audit,
                 registry_internal.registry_idempotency TO \"{role}\";
             GRANT UPDATE (payload) ON registry_internal.registry_outbox TO \"{role}\";
             GRANT SELECT, INSERT, UPDATE
                 ON registry_internal.registry_webhook_delivery_state TO \"{role}\";
             GRANT SELECT, INSERT, UPDATE ON registry_internal.registry_audit_head TO \"{role}\";
             GRANT USAGE, SELECT ON SEQUENCE registry_internal.registry_outbox_outbox_id_seq
                 TO \"{role}\";"
        ))
        .await
        .map_err(|_| MutationError::Unavailable)?;
    Ok(())
}

#[derive(Clone)]
pub struct MutationPlan {
    route: CompiledRoute,
    entity: CompiledEntity,
    event_deliveries: Vec<CompiledEventDelivery>,
}

impl MutationPlan {
    pub fn from_compiled(
        registry: &CompiledRegistry,
        route_id: &str,
    ) -> Result<Self, MutationError> {
        let route = registry
            .routes()
            .routes
            .iter()
            .find(|route| route.id == route_id)
            .ok_or(MutationError::InvalidRequest)?;
        let entity = registry
            .entities()
            .get(&route.entity_id)
            .ok_or(MutationError::InvalidRequest)?;
        match (route.operation, route.method) {
            (Operation::Create, HttpMethod::Post)
            | (Operation::Patch, HttpMethod::Patch)
            | (Operation::Tombstone, HttpMethod::Delete)
            | (Operation::Batch, HttpMethod::Post) => {}
            _ => return Err(MutationError::InvalidRequest),
        }
        if matches!(route.operation, Operation::Patch | Operation::Tombstone)
            && entity.mutation_mode != MutationMode::Mutable
        {
            return Err(MutationError::InvalidRequest);
        }
        if route.operation == Operation::Tombstone && !entity.tombstone {
            return Err(MutationError::InvalidRequest);
        }
        if route.operation == Operation::Batch && entity.batch.is_none() {
            return Err(MutationError::InvalidRequest);
        }
        let inventory = registry
            .physical_names()
            .entities
            .get(&entity.id)
            .ok_or(MutationError::InvalidRequest)?;
        if inventory.table != entity.physical_table
            || entity.fields.iter().any(|(id, field)| {
                inventory.fields.get(id) != Some(&field.physical_name)
                    || !valid_physical_identifier(&field.physical_name)
            })
            || !valid_physical_identifier(&entity.physical_table)
        {
            return Err(MutationError::InvalidRequest);
        }
        let event_deliveries = exact_entity_event_deliveries(registry, entity)?;
        Ok(Self {
            route: route.clone(),
            entity: entity.clone(),
            event_deliveries,
        })
    }

    #[must_use]
    pub fn operation_id(&self) -> &str {
        &self.route.id
    }

    #[must_use]
    pub fn route(&self) -> &str {
        &self.route.path
    }

    fn batch_item(&self, operation: Operation, profile_id: &str) -> Result<Self, MutationError> {
        if self.route.operation != Operation::Batch
            || !matches!(operation, Operation::Create | Operation::Patch)
        {
            return Err(MutationError::InvalidRequest);
        }
        let (method, path) = match operation {
            Operation::Create => (
                HttpMethod::Post,
                format!("/v1/records/{}", self.entity.route),
            ),
            Operation::Patch => (
                HttpMethod::Patch,
                format!("/v1/records/{}/{{record_id}}", self.entity.route),
            ),
            _ => return Err(MutationError::InvalidRequest),
        };
        Ok(Self {
            route: CompiledRoute {
                id: format!(
                    "records.{}.{}",
                    self.entity.id,
                    match operation {
                        Operation::Create => "create",
                        Operation::Patch => "patch",
                        _ => unreachable!(),
                    }
                ),
                entity_id: self.entity.id.clone(),
                method,
                path,
                operation,
                query_kind: None,
                revision_kind: None,
                maximum_records: None,
                access_profiles: vec![profile_id.to_owned()],
                default_access_profile: profile_id.to_owned(),
            },
            entity: self.entity.clone(),
            event_deliveries: self.event_deliveries.clone(),
        })
    }
}

fn exact_entity_event_deliveries(
    registry: &CompiledRegistry,
    entity: &CompiledEntity,
) -> Result<Vec<CompiledEventDelivery>, MutationError> {
    // A widened or substituted serialized inventory would become outbound
    // authority. Re-derive every source-bound member before retaining it.
    let deliveries = registry
        .event_deliveries()
        .deliveries
        .iter()
        .filter(|delivery| delivery.entity_id == entity.id)
        .cloned()
        .collect::<Vec<_>>();
    let mut delivery_ids = BTreeSet::new();
    let mut delivered_events = BTreeSet::new();
    for delivery in &deliveries {
        let event = entity
            .events
            .get(&delivery.event_id)
            .ok_or(MutationError::InvalidRequest)?;
        let webhook = event
            .webhook
            .as_ref()
            .ok_or(MutationError::InvalidRequest)?;
        let expected_projection = event.projection.iter().cloned().collect::<Vec<_>>();
        let classification_ceiling = event
            .projection
            .iter()
            .chain(event_condition_fields(event))
            .filter_map(|field| entity.fields.get(field))
            .map(|field| field.classification)
            .max()
            .ok_or(MutationError::InvalidRequest)?;
        let data_schema = event_data_schema_binding(registry.registry_id(), entity, event)
            .map_err(|_| MutationError::InvalidRequest)?;
        if !delivery_ids.insert(delivery.id.as_str())
            || !delivered_events.insert(delivery.event_id.as_str())
            || delivery.id != format!("events.{}.{}.webhook", entity.id, event.id)
            || delivery.trigger != event.trigger
            || delivery.destination_id != webhook.destination_id
            || delivery.projection_fields != expected_projection
            || delivery.when != event.when
            || delivery.classification_ceiling != classification_ceiling
            || delivery.data_schema != data_schema.data_schema
            || delivery.data_schema_fingerprint != data_schema.fingerprint
            || delivery.data_schema_artifact_path != data_schema.artifact_path
            || delivery.authentication_profile
                != crate::contract::WebhookAuthenticationProfile::HmacSha256V1
            || delivery.delivery_mode != CompiledWebhookDeliveryMode::AfterCommit
            || delivery.retry_profile != CompiledWebhookRetryProfile::RegistryV1
            || delivery.attempt_timeout_ms != WEBHOOK_ATTEMPT_TIMEOUT_MS
            || delivery.initial_backoff_ms != WEBHOOK_INITIAL_BACKOFF_MS
            || delivery.maximum_backoff_ms != WEBHOOK_MAXIMUM_BACKOFF_MS
            || delivery.exponential_backoff_multiplier != WEBHOOK_BACKOFF_MULTIPLIER
            || delivery.maximum_attempts != WEBHOOK_MAXIMUM_ATTEMPTS
            || delivery.retry_delays_ms
                != expected_retry_delays(
                    WEBHOOK_INITIAL_BACKOFF_MS,
                    WEBHOOK_MAXIMUM_BACKOFF_MS,
                    WEBHOOK_MAXIMUM_ATTEMPTS,
                )
            || delivery.dead_letter != crate::contract::WebhookDeadLetterMode::Required
            || !delivery.operator_replay
            || Some(delivery.maximum_payload_bytes)
                != expected_maximum_event_payload_bytes(entity, event)
        {
            return Err(MutationError::InvalidRequest);
        }
    }
    if entity
        .events
        .values()
        .any(|event| event.webhook.is_some() && !delivered_events.contains(event.id.as_str()))
    {
        return Err(MutationError::InvalidRequest);
    }
    Ok(deliveries)
}

fn event_condition_fields(event: &crate::contract::EventSource) -> impl Iterator<Item = &String> {
    let mut fields = BTreeSet::new();
    if let Some(crate::contract::EventConditionSource::Fields {
        changed,
        before_equals,
        after_equals,
    }) = &event.when
    {
        fields.extend(changed.iter());
        fields.extend(before_equals.keys());
        fields.extend(after_equals.keys());
    }
    fields.into_iter()
}

fn expected_maximum_event_payload_bytes(
    entity: &CompiledEntity,
    event: &crate::contract::EventSource,
) -> Option<u32> {
    crate::compiler::maximum_compiled_event_payload_bytes(entity, event)
}

fn expected_retry_delays(initial_ms: u32, maximum_ms: u32, maximum_attempts: u8) -> Vec<u32> {
    let mut delay = initial_ms;
    (1..maximum_attempts)
        .map(|_| {
            let current = delay;
            delay = delay.saturating_mul(2).min(maximum_ms);
            current
        })
        .collect()
}

pub struct MutationRequest<'a> {
    pub plan: &'a MutationPlan,
    pub idempotency_key: &'a str,
    pub claims: &'a ClaimContext,
    pub record_id: Option<&'a str>,
    pub expected_etag: Option<&'a str>,
    pub body: MutationBody,
    pub response_fields: BTreeSet<String>,
}

pub struct BatchMutationRequest<'a> {
    pub plan: &'a MutationPlan,
    pub idempotency_key: &'a str,
    pub claims: &'a ClaimContext,
    pub items: Vec<BatchMutationItem>,
    pub response_fields: BTreeSet<String>,
    pub body_bytes: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BatchMutationItem {
    Create(Map<String, Value>),
    Patch {
        record_id: String,
        expected_etag: String,
        patch: Vec<PatchOperation>,
    },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum MutationBody {
    Create(Map<String, Value>),
    Patch(Vec<PatchOperation>),
    Tombstone,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum PatchOperation {
    Add { path: String, value: Value },
    Replace { path: String, value: Value },
    Remove { path: String },
    Test { path: String, value: Value },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MutationOutcome {
    response: HeldResponse,
    replayed: bool,
}

impl MutationOutcome {
    #[must_use]
    pub fn response(&self) -> &HeldResponse {
        &self.response
    }

    #[must_use]
    pub fn replayed(&self) -> bool {
        self.replayed
    }
}

#[derive(Clone)]
pub struct MutationCoordinator {
    lock_key: RegistryLockKey,
    lock_timeout: Duration,
    expected: ExpectedRegistryIdentity,
    audit_profile: AuditProfile,
    event_destinations: Option<Arc<ActivatedEventDestinationRegistry>>,
}

impl MutationCoordinator {
    #[must_use]
    pub fn new(
        lock_key: RegistryLockKey,
        lock_timeout: Duration,
        expected: ExpectedRegistryIdentity,
        audit_profile: AuditProfile,
    ) -> Self {
        Self::new_with_event_destinations(lock_key, lock_timeout, expected, audit_profile, None)
    }

    #[must_use]
    pub fn new_with_event_destinations(
        lock_key: RegistryLockKey,
        lock_timeout: Duration,
        expected: ExpectedRegistryIdentity,
        audit_profile: AuditProfile,
        event_destinations: Option<Arc<ActivatedEventDestinationRegistry>>,
    ) -> Self {
        Self {
            lock_key,
            lock_timeout,
            expected,
            audit_profile,
            event_destinations,
        }
    }

    /// Execute a mutation only through durable attempt/refusal and terminal
    /// audit gates. No public mutation entry point bypasses this ordering.
    pub async fn execute(
        &self,
        client: &mut Client,
        request: MutationRequest<'_>,
    ) -> Result<MutationOutcome, MutationError> {
        self.execute_guarded(client, &request, FaultControl::Disabled)
            .await
    }

    pub async fn execute_batch(
        &self,
        client: &mut Client,
        request: BatchMutationRequest<'_>,
    ) -> Result<MutationOutcome, MutationError> {
        self.execute_batch_guarded(client, &request, FaultControl::Disabled)
            .await
    }

    #[cfg(feature = "postgres-test")]
    #[doc(hidden)]
    pub async fn execute_batch_with_fault(
        &self,
        client: &mut Client,
        request: BatchMutationRequest<'_>,
        fault: MutationFaultPoint,
    ) -> Result<MutationOutcome, MutationError> {
        self.execute_batch_guarded(client, &request, FaultControl::At(fault))
            .await
    }

    #[cfg(feature = "postgres-test")]
    #[doc(hidden)]
    pub async fn execute_with_fault(
        &self,
        client: &mut Client,
        request: MutationRequest<'_>,
        fault: MutationFaultPoint,
    ) -> Result<MutationOutcome, MutationError> {
        self.execute_guarded(client, &request, FaultControl::At(fault))
            .await
    }

    async fn execute_guarded(
        &self,
        client: &mut Client,
        request: &MutationRequest<'_>,
        fault: FaultControl,
    ) -> Result<MutationOutcome, MutationError> {
        if !profile_is_keyed(&self.audit_profile) {
            return Err(MutationError::Unavailable);
        }
        if let Err(error) = validate_request(request, &self.expected) {
            self.record_boundary_audit(client, request, PreIoAuditKind::Refusal)
                .await?;
            return Err(error);
        }
        self.record_boundary_audit(client, request, PreIoAuditKind::Attempt)
            .await?;
        let result = self.execute_after_attempt(client, request, fault).await;
        if result.is_err() && !fault.is_enabled() {
            self.record_boundary_audit(client, request, PreIoAuditKind::Refusal)
                .await?;
        }
        result
    }

    async fn execute_batch_guarded(
        &self,
        client: &mut Client,
        request: &BatchMutationRequest<'_>,
        fault: FaultControl,
    ) -> Result<MutationOutcome, MutationError> {
        if !profile_is_keyed(&self.audit_profile) {
            return Err(MutationError::Unavailable);
        }
        if let Err(error) = validate_batch_request(request, &self.expected) {
            self.record_batch_boundary_audit(client, request, PreIoAuditKind::Refusal)
                .await?;
            return Err(error);
        }
        self.record_batch_boundary_audit(client, request, PreIoAuditKind::Attempt)
            .await?;
        let result = self
            .execute_batch_after_attempt(client, request, fault)
            .await;
        if result.is_err() && !fault.is_enabled() {
            self.record_batch_boundary_audit(client, request, PreIoAuditKind::Refusal)
                .await?;
        }
        result
    }

    async fn record_batch_boundary_audit(
        &self,
        client: &mut Client,
        request: &BatchMutationRequest<'_>,
        kind: PreIoAuditKind,
    ) -> Result<(), MutationError> {
        record_pre_io_audit(
            client,
            self.lock_key,
            self.lock_timeout,
            &self.expected,
            request.claims,
            &self.audit_profile,
            PreIoAudit {
                kind,
                method: request.plan.route.method,
                operation_id: &request.plan.route.id,
                target_record: None,
            },
        )
        .await?;
        Ok(())
    }

    async fn record_boundary_audit(
        &self,
        client: &mut Client,
        request: &MutationRequest<'_>,
        kind: PreIoAuditKind,
    ) -> Result<(), MutationError> {
        record_pre_io_audit(
            client,
            self.lock_key,
            self.lock_timeout,
            &self.expected,
            request.claims,
            &self.audit_profile,
            PreIoAudit {
                kind,
                method: request.plan.route.method,
                operation_id: &request.plan.route.id,
                target_record: request.record_id,
            },
        )
        .await?;
        Ok(())
    }

    async fn execute_after_attempt(
        &self,
        client: &mut Client,
        request: &MutationRequest<'_>,
        fault: FaultControl,
    ) -> Result<MutationOutcome, MutationError> {
        let canonical_request_digest = canonical_request_digest(request)?;
        let binding = resolve_binding(
            &self.audit_profile,
            &IdempotencyBinding {
                key: request.idempotency_key,
                context: request.claims,
                method: request.plan.route.method,
                route: &request.plan.route.path,
                target_record: request.record_id,
                package_revision: &self.expected.package_revision,
                response_fields: &request.response_fields,
                canonical_request_digest,
            },
        )?;
        let transaction = begin_record_transaction(
            client,
            self.lock_key,
            self.lock_timeout,
            &self.expected,
            request.claims,
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;

        if let Some(stored) = lock_and_load(transaction.transaction(), &binding).await? {
            if !matches!(&stored.metadata, StoredResultMetadata::Record { .. }) {
                return Err(MutationError::Unavailable);
            }
            append_terminal_audit(
                transaction.transaction(),
                &self.audit_profile,
                TerminalAudit {
                    outcome: TerminalAuditOutcome::Replayed,
                    method: request.plan.route.method,
                    operation_id: request.plan.route.id.clone(),
                    entity_id: request.plan.entity.id.clone(),
                    package_revision: self.expected.package_revision.clone(),
                    selected_access_profile: request.claims.access_profile().to_owned(),
                    purpose_present: request.claims.purpose().is_some(),
                    principal_reference: Some(binding.principal_reference.clone()),
                    record_reference: match &stored.metadata {
                        StoredResultMetadata::Record {
                            record_reference, ..
                        } => Some(record_reference.clone()),
                        StoredResultMetadata::Batch { .. } => None,
                    },
                    record_revision: match &stored.metadata {
                        StoredResultMetadata::Record {
                            record_revision, ..
                        } => Some(*record_revision),
                        StoredResultMetadata::Batch { .. } => None,
                    },
                    result_count: None,
                    field_set_reference: None,
                },
            )
            .await?;
            transaction
                .commit()
                .await
                .map_err(|_| MutationError::Unavailable)?;
            return Ok(MutationOutcome {
                response: stored.response,
                replayed: true,
            });
        }

        fault.fail_at(MutationFaultPoint::BeforeCurrentRow)?;
        let current = apply_current_row(
            transaction.transaction(),
            request,
            &self.audit_profile,
            &self.expected.package_revision,
        )
        .await?;
        let record_reference = match request.record_id {
            Some(_) => binding.record_reference.clone(),
            None => record_reference(
                &self.audit_profile,
                &self.expected.package_revision,
                &current.record_id,
            )?,
        };
        let held = self.held_response(request, &current)?;
        let snapshot = canonical_snapshot(&current.data)?;
        fault.fail_at(MutationFaultPoint::BeforeRevision)?;
        insert_revision(
            transaction.transaction(),
            RevisionInsert {
                entity_id: &request.plan.entity.id,
                record_id: current.record_uuid,
                record_reference: &record_reference,
                record_revision: current.record_revision,
                predecessor_revision: current.predecessor_revision,
                lifecycle: &current.record_lifecycle,
                package_revision: &self.expected.package_revision,
                operation_id: &request.plan.route.id,
                mutation_kind: mutation_kind(request.plan.route.operation),
                principal_reference: &binding.principal_reference,
                request_reference: &binding.binding_reference,
                snapshot: &snapshot,
            },
        )
        .await?;
        fault.fail_at(MutationFaultPoint::BeforeOutbox)?;
        insert_configured_events(
            transaction.transaction(),
            &request.plan.entity.events,
            &request.plan.event_deliveries,
            self.event_destinations.as_deref(),
            OutboxMutation {
                trigger: mutation_trigger(request.plan.route.operation),
                entity_id: &request.plan.entity.id,
                record_id: &current.record_id,
                record_reference: &record_reference,
                record_revision: current.record_revision,
                package_revision: &self.expected.package_revision,
                schema_fingerprint: &self.expected.schema_fingerprint,
                before: current.before_data.as_ref(),
                after: (request.plan.route.operation != Operation::Tombstone)
                    .then_some(&current.data),
                payload_retention: self
                    .event_destinations
                    .as_deref()
                    .map_or(Duration::from_secs(7 * 24 * 60 * 60), |destinations| {
                        destinations.payload_retention()
                    }),
            },
        )
        .await?;
        fault.fail_at(MutationFaultPoint::BeforeTerminalAudit)?;
        append_terminal_audit(
            transaction.transaction(),
            &self.audit_profile,
            TerminalAudit {
                outcome: TerminalAuditOutcome::Committed,
                method: request.plan.route.method,
                operation_id: request.plan.route.id.clone(),
                entity_id: request.plan.entity.id.clone(),
                package_revision: self.expected.package_revision.clone(),
                selected_access_profile: request.claims.access_profile().to_owned(),
                purpose_present: request.claims.purpose().is_some(),
                principal_reference: Some(binding.principal_reference.clone()),
                record_reference: Some(record_reference.clone()),
                record_revision: Some(current.record_revision),
                result_count: None,
                field_set_reference: None,
            },
        )
        .await?;
        fault.fail_at(MutationFaultPoint::BeforeIdempotency)?;
        insert_result(
            transaction.transaction(),
            &binding,
            &StoredResultMetadata::Record {
                record_revision: current.record_revision,
                record_reference: record_reference.clone(),
            },
            &held,
        )
        .await?;
        fault.fail_at(MutationFaultPoint::BeforeCommit)?;
        transaction
            .commit()
            .await
            .map_err(|_| MutationError::Unavailable)?;
        fault.fail_at(MutationFaultPoint::AfterCommitBeforeResponseRelease)?;
        Ok(MutationOutcome {
            response: held,
            replayed: false,
        })
    }

    async fn execute_batch_after_attempt(
        &self,
        client: &mut Client,
        request: &BatchMutationRequest<'_>,
        fault: FaultControl,
    ) -> Result<MutationOutcome, MutationError> {
        let canonical_request_digest = canonical_batch_request_digest(request)?;
        let binding = resolve_binding(
            &self.audit_profile,
            &IdempotencyBinding {
                key: request.idempotency_key,
                context: request.claims,
                method: request.plan.route.method,
                route: &request.plan.route.path,
                target_record: None,
                package_revision: &self.expected.package_revision,
                response_fields: &request.response_fields,
                canonical_request_digest,
            },
        )?;
        let transaction = begin_record_transaction(
            client,
            self.lock_key,
            self.lock_timeout,
            &self.expected,
            request.claims,
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;

        if let Some(stored) = lock_and_load(transaction.transaction(), &binding).await? {
            let StoredResultMetadata::Batch { result_count } = stored.metadata else {
                return Err(MutationError::Unavailable);
            };
            append_terminal_audit(
                transaction.transaction(),
                &self.audit_profile,
                TerminalAudit {
                    outcome: TerminalAuditOutcome::Replayed,
                    method: request.plan.route.method,
                    operation_id: request.plan.route.id.clone(),
                    entity_id: request.plan.entity.id.clone(),
                    package_revision: self.expected.package_revision.clone(),
                    selected_access_profile: request.claims.access_profile().to_owned(),
                    purpose_present: request.claims.purpose().is_some(),
                    principal_reference: Some(binding.principal_reference.clone()),
                    record_reference: None,
                    record_revision: None,
                    result_count: Some(usize::from(result_count)),
                    field_set_reference: None,
                },
            )
            .await?;
            transaction
                .commit()
                .await
                .map_err(|_| MutationError::Unavailable)?;
            return Ok(MutationOutcome {
                response: stored.response,
                replayed: true,
            });
        }

        let mut held_items = Vec::with_capacity(request.items.len());
        for (item_index, item) in request.items.iter().enumerate() {
            let item_plan = request
                .plan
                .batch_item(item.operation(), request.claims.access_profile())?;
            let (record_id, expected_etag, body) = item.request_parts();
            let item_request = MutationRequest {
                plan: &item_plan,
                idempotency_key: request.idempotency_key,
                claims: request.claims,
                record_id,
                expected_etag,
                body,
                response_fields: request.response_fields.clone(),
            };
            fault.fail_at(MutationFaultPoint::BeforeCurrentRow)?;
            let current = apply_current_row(
                transaction.transaction(),
                &item_request,
                &self.audit_profile,
                &self.expected.package_revision,
            )
            .await?;
            let record_reference = record_reference(
                &self.audit_profile,
                &self.expected.package_revision,
                &current.record_id,
            )?;
            let snapshot = canonical_snapshot(&current.data)?;
            fault.fail_at(MutationFaultPoint::BeforeRevision)?;
            insert_revision(
                transaction.transaction(),
                RevisionInsert {
                    entity_id: &item_plan.entity.id,
                    record_id: current.record_uuid,
                    record_reference: &record_reference,
                    record_revision: current.record_revision,
                    predecessor_revision: current.predecessor_revision,
                    lifecycle: &current.record_lifecycle,
                    package_revision: &self.expected.package_revision,
                    operation_id: &item_plan.route.id,
                    mutation_kind: mutation_kind(item_plan.route.operation),
                    principal_reference: &binding.principal_reference,
                    request_reference: &binding.binding_reference,
                    snapshot: &snapshot,
                },
            )
            .await?;
            fault.fail_at(MutationFaultPoint::BeforeOutbox)?;
            insert_configured_events(
                transaction.transaction(),
                &item_plan.entity.events,
                &item_plan.event_deliveries,
                self.event_destinations.as_deref(),
                OutboxMutation {
                    trigger: mutation_trigger(item_plan.route.operation),
                    entity_id: &item_plan.entity.id,
                    record_id: &current.record_id,
                    record_reference: &record_reference,
                    record_revision: current.record_revision,
                    package_revision: &self.expected.package_revision,
                    schema_fingerprint: &self.expected.schema_fingerprint,
                    before: current.before_data.as_ref(),
                    after: Some(&current.data),
                    payload_retention: self
                        .event_destinations
                        .as_deref()
                        .map_or(Duration::from_secs(7 * 24 * 60 * 60), |destinations| {
                            destinations.payload_retention()
                        }),
                },
            )
            .await?;
            held_items.push(self.batch_item_response(request, item, &current)?);
            #[cfg(feature = "postgres-test")]
            if item_index == 0 {
                fault.fail_at(MutationFaultPoint::AfterFirstBatchItem)?;
            }
            #[cfg(not(feature = "postgres-test"))]
            let _ = item_index;
        }

        let result_count =
            u16::try_from(held_items.len()).map_err(|_| MutationError::Unavailable)?;
        let held = HeldResponse::from_json(
            200,
            &json!({"results": held_items}),
            BTreeMap::from([(
                PermittedResponseHeader::ContentType,
                b"application/json".to_vec(),
            )]),
        )?;
        fault.fail_at(MutationFaultPoint::BeforeTerminalAudit)?;
        append_terminal_audit(
            transaction.transaction(),
            &self.audit_profile,
            TerminalAudit {
                outcome: TerminalAuditOutcome::Committed,
                method: request.plan.route.method,
                operation_id: request.plan.route.id.clone(),
                entity_id: request.plan.entity.id.clone(),
                package_revision: self.expected.package_revision.clone(),
                selected_access_profile: request.claims.access_profile().to_owned(),
                purpose_present: request.claims.purpose().is_some(),
                principal_reference: Some(binding.principal_reference.clone()),
                record_reference: None,
                record_revision: None,
                result_count: Some(usize::from(result_count)),
                field_set_reference: None,
            },
        )
        .await?;
        fault.fail_at(MutationFaultPoint::BeforeIdempotency)?;
        insert_result(
            transaction.transaction(),
            &binding,
            &StoredResultMetadata::Batch { result_count },
            &held,
        )
        .await?;
        fault.fail_at(MutationFaultPoint::BeforeCommit)?;
        transaction
            .commit()
            .await
            .map_err(|_| MutationError::Unavailable)?;
        fault.fail_at(MutationFaultPoint::AfterCommitBeforeResponseRelease)?;
        Ok(MutationOutcome {
            response: held,
            replayed: false,
        })
    }

    fn batch_item_response(
        &self,
        request: &BatchMutationRequest<'_>,
        item: &BatchMutationItem,
        current: &CurrentRow,
    ) -> Result<Value, MutationError> {
        let data = current
            .data
            .iter()
            .filter(|(field, _)| request.response_fields.contains(*field))
            .map(|(field, value)| (field.clone(), value.clone()))
            .collect::<Map<_, _>>();
        let etag = strong_record_etag(
            &self.audit_profile,
            request.claims,
            &self.expected.package_revision,
            &current.record_id,
            current.record_revision,
            &request.response_fields,
        )?;
        Ok(json!({
            "operation": match item {
                BatchMutationItem::Create(_) => "create",
                BatchMutationItem::Patch { .. } => "patch",
            },
            "id": current.record_id,
            "revision": current.record_revision,
            "etag": etag,
            "data": data,
        }))
    }

    fn held_response(
        &self,
        request: &MutationRequest<'_>,
        current: &CurrentRow,
    ) -> Result<HeldResponse, MutationError> {
        let data = current
            .data
            .iter()
            .filter(|(field, _)| request.response_fields.contains(*field))
            .map(|(field, value)| (field.clone(), value.clone()))
            .collect::<Map<_, _>>();
        let body = json!({
            "id": current.record_id,
            "revision": current.record_revision,
            "data": data,
        });
        let etag = strong_record_etag(
            &self.audit_profile,
            request.claims,
            &self.expected.package_revision,
            &current.record_id,
            current.record_revision,
            &request.response_fields,
        )?;
        let mut headers = BTreeMap::from([
            (
                PermittedResponseHeader::ContentType,
                b"application/json".to_vec(),
            ),
            (PermittedResponseHeader::Etag, etag.into_bytes()),
        ]);
        let status = match request.plan.route.operation {
            Operation::Create => {
                headers.insert(
                    PermittedResponseHeader::Location,
                    format!(
                        "{}/{}",
                        request.plan.route.path.trim_end_matches('/'),
                        current.record_id
                    )
                    .into_bytes(),
                );
                201
            }
            Operation::Patch => 200,
            Operation::Tombstone => 200,
            _ => return Err(MutationError::InvalidRequest),
        };
        HeldResponse::from_json(status, &body, headers).map_err(MutationError::from)
    }
}

pub(crate) fn strong_record_etag(
    profile: &AuditProfile,
    claims: &ClaimContext,
    package_revision: &str,
    record_id: &str,
    record_revision: i64,
    response_fields: &BTreeSet<String>,
) -> Result<String, MutationError> {
    let key_hasher = profile.key_hasher();
    let principal_reference = claims
        .principal()
        .map(|principal| {
            key_hasher.audit_reference_hash(
                "registry-server-principal-v1",
                package_revision,
                principal,
            )
        })
        .transpose()
        .map_err(|_| MutationError::Unavailable)?;
    let row_boundaries = claims
        .row_boundaries()
        .iter()
        .map(|boundary| {
            let reference_context = format!(
                "{package_revision}:{}:{}",
                boundary.field(),
                boundary.operator().as_str()
            );
            let value_references = boundary
                .values()
                .into_iter()
                .map(|value| {
                    key_hasher.audit_reference_hash(
                        "registry-server-row-boundary-value-v1",
                        &reference_context,
                        value,
                    )
                })
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| MutationError::Unavailable)?;
            Ok(json!({
                "field": boundary.field(),
                "operator": boundary.operator().as_str(),
                "valueReferences": value_references,
            }))
        })
        .collect::<Result<Vec<_>, MutationError>>()?;
    let authorization_context = json!({
        "entityId": claims.entity_id(),
        "principalReference": principal_reference,
        "selectedAccessProfile": claims.access_profile(),
        "verifiedPurpose": claims.purpose(),
        "rowBoundaries": row_boundaries,
    });
    let etag_input = canonicalize_json(&json!({
        "authorizationContext": authorization_context,
        "packageRevision": package_revision,
        "recordId": record_id,
        "recordRevision": record_revision,
        "responseFields": response_fields,
    }))
    .map_err(|_| MutationError::InvalidRequest)?;
    let etag_input = std::str::from_utf8(&etag_input).map_err(|_| MutationError::InvalidRequest)?;
    let digest = profile
        .key_hasher()
        .audit_reference_hash(
            "registry-server-response-etag-v1",
            package_revision,
            etag_input,
        )
        .map_err(|_| MutationError::Unavailable)?;
    Ok(format!("\"rs-{digest}\""))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum MutationError {
    #[error("mutation request is invalid")]
    InvalidRequest,
    #[error("mutation precondition failed")]
    PreconditionFailed,
    #[error("mutation conflicts with current state")]
    Conflict,
    #[error("idempotency key is already bound to another request")]
    IdempotencyConflict,
    #[error("mutation service is unavailable")]
    Unavailable,
}

#[cfg(feature = "postgres-test")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MutationFaultPoint {
    BeforeCurrentRow,
    BeforeRevision,
    BeforeOutbox,
    AfterFirstBatchItem,
    BeforeTerminalAudit,
    BeforeIdempotency,
    BeforeCommit,
    AfterCommitBeforeResponseRelease,
}

#[cfg(not(feature = "postgres-test"))]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum MutationFaultPoint {
    BeforeCurrentRow,
    BeforeRevision,
    BeforeOutbox,
    BeforeTerminalAudit,
    BeforeIdempotency,
    BeforeCommit,
    AfterCommitBeforeResponseRelease,
}

#[derive(Clone, Copy)]
enum FaultControl {
    Disabled,
    #[cfg(feature = "postgres-test")]
    At(MutationFaultPoint),
}

impl FaultControl {
    fn fail_at(self, point: MutationFaultPoint) -> Result<(), MutationError> {
        #[cfg(feature = "postgres-test")]
        if matches!(self, Self::At(configured) if configured == point) {
            return Err(MutationError::Unavailable);
        }
        let _ = (self, point);
        Ok(())
    }

    fn is_enabled(self) -> bool {
        #[cfg(feature = "postgres-test")]
        if matches!(self, Self::At(_)) {
            return true;
        }
        false
    }
}

struct CurrentRow {
    record_uuid: Uuid,
    record_id: String,
    record_revision: i64,
    predecessor_revision: Option<i64>,
    record_lifecycle: String,
    before_data: Option<Map<String, Value>>,
    data: Map<String, Value>,
}

async fn apply_current_row(
    transaction: &Transaction<'_>,
    request: &MutationRequest<'_>,
    audit_profile: &AuditProfile,
    package_revision: &str,
) -> Result<CurrentRow, MutationError> {
    match request.plan.route.operation {
        Operation::Create => {
            let record_id = Uuid::new_v4().to_string();
            apply_create_row(transaction, request, &record_id).await
        }
        Operation::Patch => {
            let current = load_current_row_for_update(transaction, request).await?;
            let expected = request
                .expected_etag
                .ok_or(MutationError::InvalidRequest)?
                .as_bytes();
            let current_etag = strong_record_etag(
                audit_profile,
                request.claims,
                package_revision,
                &current.record_id,
                current.record_revision,
                &request.response_fields,
            )?;
            if expected.ct_eq(current_etag.as_bytes()).unwrap_u8() != 1 {
                return Err(MutationError::PreconditionFailed);
            }
            let before_data = current.data.clone();
            let data = apply_patch_document(request, &current.data)?;
            let mut row =
                apply_patch_row(transaction, request, current.record_revision, data).await?;
            row.predecessor_revision = Some(current.record_revision);
            row.before_data = Some(before_data);
            Ok(row)
        }
        Operation::Tombstone => {
            let current = load_tombstone_row_for_update(transaction, request).await?;
            let expected = request
                .expected_etag
                .ok_or(MutationError::InvalidRequest)?
                .as_bytes();
            let current_etag = strong_record_etag(
                audit_profile,
                request.claims,
                package_revision,
                &current.record_id,
                current.record_revision,
                &request.response_fields,
            )?;
            if expected.ct_eq(current_etag.as_bytes()).unwrap_u8() != 1 {
                return Err(MutationError::PreconditionFailed);
            }
            apply_tombstone_row(transaction, request, current).await
        }
        _ => Err(MutationError::InvalidRequest),
    }
}

async fn apply_create_row(
    transaction: &Transaction<'_>,
    request: &MutationRequest<'_>,
    record_id: &str,
) -> Result<CurrentRow, MutationError> {
    let MutationBody::Create(data) = &request.body else {
        return Err(MutationError::InvalidRequest);
    };
    let submitted_fields = request
        .plan
        .entity
        .fields
        .values()
        .filter(|field| data.contains_key(&field.id))
        .collect::<Vec<_>>();
    let mut values = Vec::<Option<String>>::with_capacity(submitted_fields.len() + 2);
    values.push(Some(record_id.to_owned()));
    for field in &submitted_fields {
        values.push(sql_value(&data[&field.id], &field.field_type)?);
    }
    let parameters = values
        .iter()
        .map(|value| value as &(dyn ToSql + Sync))
        .collect::<Vec<_>>();
    let table = quote_identifier(&request.plan.entity.physical_table);
    let field_columns = submitted_fields
        .iter()
        .map(|field| quote_identifier(&field.physical_name))
        .collect::<Vec<_>>();
    let field_parameters = submitted_fields
        .iter()
        .enumerate()
        .map(|(index, field)| typed_parameter(index + 2, &field.field_type))
        .collect::<Vec<_>>();
    let returning = returning_projection(&request.plan.entity);

    let mut columns = vec![
        "record_id".to_owned(),
        "record_revision".to_owned(),
        "record_lifecycle".to_owned(),
    ];
    columns.extend(field_columns);
    let mut placeholders = vec![
        "$1::text::uuid".to_owned(),
        "1".to_owned(),
        "'active'".to_owned(),
    ];
    placeholders.extend(field_parameters);
    let sql = format!(
        "INSERT INTO registry_data.{table} ({}) VALUES ({}) RETURNING {returning}",
        columns.join(", "),
        placeholders.join(", ")
    );
    let row = transaction
        .query_one(&sql, &parameters)
        .await
        .map_err(map_database_error)?;
    row_to_current(&request.plan.entity, &row)
}

async fn apply_patch_row(
    transaction: &Transaction<'_>,
    request: &MutationRequest<'_>,
    expected_revision: i64,
    data: Map<String, Value>,
) -> Result<CurrentRow, MutationError> {
    let record_id = request.record_id.ok_or(MutationError::InvalidRequest)?;
    let submitted_fields = request
        .plan
        .entity
        .fields
        .values()
        .filter(|field| data.contains_key(&field.id))
        .collect::<Vec<_>>();
    if submitted_fields.is_empty() {
        return Err(MutationError::InvalidRequest);
    }
    let mut values = Vec::<Option<String>>::with_capacity(submitted_fields.len() + 2);
    values.push(Some(record_id.to_owned()));
    for field in &submitted_fields {
        values.push(sql_value(&data[&field.id], &field.field_type)?);
    }
    values.push(Some(expected_revision.to_string()));
    let parameters = values
        .iter()
        .map(|value| value as &(dyn ToSql + Sync))
        .collect::<Vec<_>>();
    let table = quote_identifier(&request.plan.entity.physical_table);
    let assignments = submitted_fields
        .iter()
        .enumerate()
        .map(|(index, field)| {
            format!(
                "{} = {}",
                quote_identifier(&field.physical_name),
                typed_parameter(index + 2, &field.field_type)
            )
        })
        .collect::<Vec<_>>();
    let expected_parameter = values.len();
    let returning = returning_projection(&request.plan.entity);
    let sql = format!(
        "UPDATE registry_data.{table}
         SET record_revision = record_revision + 1,
             active_package_revision = DEFAULT,
             updated_at = transaction_timestamp(),
             {}
         WHERE record_id = $1::text::uuid
           AND record_revision = ${expected_parameter}::text::bigint
           AND record_lifecycle = 'active'
         RETURNING {returning}",
        assignments.join(", ")
    );
    let row = transaction
        .query_opt(&sql, &parameters)
        .await
        .map_err(map_database_error)?
        .ok_or(MutationError::PreconditionFailed)?;
    row_to_current(&request.plan.entity, &row)
}

async fn apply_tombstone_row(
    transaction: &Transaction<'_>,
    request: &MutationRequest<'_>,
    current: CurrentRow,
) -> Result<CurrentRow, MutationError> {
    let _ = request.record_id.ok_or(MutationError::InvalidRequest)?;
    let table = quote_identifier(&request.plan.entity.physical_table);
    let next_revision = current
        .record_revision
        .checked_add(1)
        .ok_or(MutationError::Unavailable)?;
    let changed = transaction
        .execute(
            &format!(
                "UPDATE registry_data.{table}
                 SET record_revision = $1::bigint,
                     record_lifecycle = 'tombstoned',
                     active_package_revision = DEFAULT,
                     updated_at = transaction_timestamp()
                 WHERE CURRENT OF {TOMBSTONE_CURSOR}"
            ),
            &[&next_revision],
        )
        .await
        .map_err(map_database_error)?;
    if changed != 1 {
        return Err(MutationError::PreconditionFailed);
    }
    Ok(CurrentRow {
        record_uuid: current.record_uuid,
        record_id: current.record_id,
        record_revision: next_revision,
        predecessor_revision: Some(current.record_revision),
        record_lifecycle: "tombstoned".to_owned(),
        before_data: Some(current.data.clone()),
        data: current.data,
    })
}

async fn load_current_row_for_update(
    transaction: &Transaction<'_>,
    request: &MutationRequest<'_>,
) -> Result<CurrentRow, MutationError> {
    let record_id = request.record_id.ok_or(MutationError::InvalidRequest)?;
    if !valid_uuid(record_id) {
        return Err(MutationError::InvalidRequest);
    }
    let table = quote_identifier(&request.plan.entity.physical_table);
    let returning = returning_projection(&request.plan.entity);
    let sql = format!(
        "SELECT {returning}
         FROM registry_data.{table}
         WHERE record_id = $1::text::uuid
           AND record_lifecycle = 'active'
         FOR UPDATE"
    );
    let row = transaction
        .query_opt(&sql, &[&record_id])
        .await
        .map_err(map_database_error)?
        .ok_or(MutationError::PreconditionFailed)?;
    row_to_current(&request.plan.entity, &row)
}

async fn load_tombstone_row_for_update(
    transaction: &Transaction<'_>,
    request: &MutationRequest<'_>,
) -> Result<CurrentRow, MutationError> {
    let record_id = request.record_id.ok_or(MutationError::InvalidRequest)?;
    if !valid_uuid(record_id) {
        return Err(MutationError::InvalidRequest);
    }
    let table = quote_identifier(&request.plan.entity.physical_table);
    let returning = returning_projection(&request.plan.entity);
    let declare = format!(
        "DECLARE {TOMBSTONE_CURSOR} NO SCROLL CURSOR FOR
         SELECT {returning}
         FROM registry_data.{table}
         WHERE record_id = $1::text::uuid
           AND record_lifecycle = 'active'
         FOR UPDATE"
    );
    transaction
        .execute(&declare, &[&record_id])
        .await
        .map_err(map_database_error)?;
    let fetch = format!("FETCH FORWARD 1 FROM {TOMBSTONE_CURSOR}");
    let row = transaction
        .query_opt(&fetch, &[])
        .await
        .map_err(map_database_error)?
        .ok_or(MutationError::PreconditionFailed)?;
    row_to_current(&request.plan.entity, &row)
}

fn apply_patch_document(
    request: &MutationRequest<'_>,
    current: &Map<String, Value>,
) -> Result<Map<String, Value>, MutationError> {
    let MutationBody::Patch(operations) = &request.body else {
        return Err(MutationError::InvalidRequest);
    };
    if operations.is_empty() {
        return Err(MutationError::InvalidRequest);
    }
    let profile = selected_profile(request)?;
    let mut materialized = current.clone();
    let mut changed = Map::new();
    let mut mutated = false;
    for operation in operations {
        match operation {
            PatchOperation::Add { path, value } | PatchOperation::Replace { path, value } => {
                let field_id = patch_field(path)?;
                let field = request
                    .plan
                    .entity
                    .fields
                    .get(&field_id)
                    .ok_or(MutationError::InvalidRequest)?;
                if !profile.writable_fields.contains(&field_id) || value.is_null() && field.required
                {
                    return Err(MutationError::InvalidRequest);
                }
                sql_value(value, &field.field_type)?;
                materialized.insert(field_id.clone(), value.clone());
                changed.insert(field_id, value.clone());
                mutated = true;
            }
            PatchOperation::Remove { path } => {
                let field_id = patch_field(path)?;
                let field = request
                    .plan
                    .entity
                    .fields
                    .get(&field_id)
                    .ok_or(MutationError::InvalidRequest)?;
                if field.required || !profile.writable_fields.contains(&field_id) {
                    return Err(MutationError::InvalidRequest);
                }
                materialized.insert(field_id.clone(), Value::Null);
                changed.insert(field_id, Value::Null);
                mutated = true;
            }
            PatchOperation::Test { path, value } => {
                let field_id = patch_field(path)?;
                if !profile.readable_fields.contains(&field_id)
                    || !request.plan.entity.fields.contains_key(&field_id)
                {
                    return Err(MutationError::InvalidRequest);
                }
                if materialized.get(&field_id) != Some(value) {
                    return Err(MutationError::Conflict);
                }
            }
        }
    }
    if !mutated {
        return Err(MutationError::InvalidRequest);
    }
    Ok(changed)
}

pub fn parse_json_patch_document(value: Value) -> Result<Vec<PatchOperation>, MutationError> {
    let operations = value.as_array().ok_or(MutationError::InvalidRequest)?;
    if operations.is_empty() || operations.len() > 128 {
        return Err(MutationError::InvalidRequest);
    }
    operations
        .iter()
        .map(|operation| {
            let object = operation.as_object().ok_or(MutationError::InvalidRequest)?;
            let op = object
                .get("op")
                .and_then(Value::as_str)
                .ok_or(MutationError::InvalidRequest)?;
            let path = object
                .get("path")
                .and_then(Value::as_str)
                .ok_or(MutationError::InvalidRequest)?;
            match op {
                "add" | "replace" | "test" if object.len() == 3 && object.contains_key("value") => {
                    let value = object["value"].clone();
                    match op {
                        "add" => Ok(PatchOperation::Add {
                            path: path.to_owned(),
                            value,
                        }),
                        "replace" => Ok(PatchOperation::Replace {
                            path: path.to_owned(),
                            value,
                        }),
                        "test" => Ok(PatchOperation::Test {
                            path: path.to_owned(),
                            value,
                        }),
                        _ => unreachable!(),
                    }
                }
                "remove" if object.len() == 2 => Ok(PatchOperation::Remove {
                    path: path.to_owned(),
                }),
                _ => Err(MutationError::InvalidRequest),
            }
        })
        .collect()
}

fn patch_field(path: &str) -> Result<String, MutationError> {
    let suffix = path
        .strip_prefix("/data/")
        .ok_or(MutationError::InvalidRequest)?;
    if suffix.is_empty() || suffix.contains('/') {
        return Err(MutationError::InvalidRequest);
    }
    decode_pointer_segment(suffix)
}

fn decode_pointer_segment(value: &str) -> Result<String, MutationError> {
    let mut decoded = String::with_capacity(value.len());
    let mut chars = value.chars();
    while let Some(character) = chars.next() {
        if character != '~' {
            decoded.push(character);
            continue;
        }
        match chars.next() {
            Some('0') => decoded.push('~'),
            Some('1') => decoded.push('/'),
            _ => return Err(MutationError::InvalidRequest),
        }
    }
    Ok(decoded)
}

fn returning_projection(entity: &CompiledEntity) -> String {
    let mut expressions = vec![
        "record_id::text".to_owned(),
        "record_revision".to_owned(),
        "record_lifecycle".to_owned(),
    ];
    expressions.extend(entity.fields.values().map(field_json_projection));
    expressions.join(", ")
}

fn field_json_projection(field: &crate::model::CompiledField) -> String {
    let column = quote_identifier(&field.physical_name);
    match field.field_type {
        FieldTypeSource::Decimal { .. } => format!("to_jsonb({column}::text)"),
        _ => format!("to_jsonb({column})"),
    }
}

fn row_to_current(
    entity: &CompiledEntity,
    row: &tokio_postgres::Row,
) -> Result<CurrentRow, MutationError> {
    let record_id = row
        .try_get::<_, String>(0)
        .map_err(|_| MutationError::Unavailable)?;
    let record_revision = row
        .try_get::<_, i64>(1)
        .map_err(|_| MutationError::Unavailable)?;
    let record_lifecycle = row
        .try_get::<_, String>(2)
        .map_err(|_| MutationError::Unavailable)?;
    let record_uuid = Uuid::parse_str(&record_id).map_err(|_| MutationError::Unavailable)?;
    if record_uuid.to_string() != record_id
        || record_revision <= 0
        || !matches!(record_lifecycle.as_str(), "active" | "tombstoned")
        || row.len() != entity.fields.len() + 3
    {
        return Err(MutationError::Unavailable);
    }
    let mut data = Map::new();
    for (index, field) in entity.fields.values().enumerate() {
        let value = row
            .try_get::<_, Option<Value>>(index + 3)
            .map_err(|_| MutationError::Unavailable)?
            .unwrap_or(Value::Null);
        data.insert(field.id.clone(), value);
    }
    Ok(CurrentRow {
        record_uuid,
        record_id,
        record_revision,
        predecessor_revision: None,
        record_lifecycle,
        before_data: None,
        data,
    })
}

fn validate_request(
    request: &MutationRequest<'_>,
    expected: &ExpectedRegistryIdentity,
) -> Result<(), MutationError> {
    expected
        .validate()
        .map_err(|_| MutationError::InvalidRequest)?;
    request
        .claims
        .validate()
        .map_err(|_| MutationError::InvalidRequest)?;
    let profile = selected_profile(request)?;
    let submitted_fields = request.body.submitted_fields()?;
    if request.claims.entity_id() != request.plan.entity.id
        || request.claims.principal().is_none()
        || profile.anonymous
        || request.plan.route.id.is_empty()
        || request.plan.route.id.len() > MAX_LOGICAL_ID_BYTES
        || request.plan.entity.id.is_empty()
        || request.plan.entity.id.len() > MAX_LOGICAL_ID_BYTES
        || submitted_fields
            .iter()
            .any(|field| !request.plan.entity.fields.contains_key(field))
        || submitted_fields
            .iter()
            .any(|field| !profile.writable_fields.contains(field))
        || request.response_fields.is_empty()
        || !request.response_fields.is_subset(&profile.readable_fields)
    {
        return Err(MutationError::InvalidRequest);
    }
    match request.plan.route.operation {
        Operation::Create
            if request.record_id.is_none()
                && request.expected_etag.is_none()
                && matches!(request.body, MutationBody::Create(_)) =>
        {
            let MutationBody::Create(data) = &request.body else {
                unreachable!("create request body matched above")
            };
            if request
                .plan
                .entity
                .fields
                .values()
                .any(|field| field.required && !data.contains_key(&field.id))
            {
                return Err(MutationError::InvalidRequest);
            }
        }
        Operation::Patch
            if request.record_id.is_some_and(valid_uuid)
                && request.expected_etag.is_some_and(valid_strong_etag)
                && matches!(&request.body, MutationBody::Patch(operations) if !operations.is_empty()) =>
            {}
        Operation::Tombstone
            if request.record_id.is_some_and(valid_uuid)
                && request.expected_etag.is_some_and(valid_strong_etag)
                && matches!(request.body, MutationBody::Tombstone) => {}
        _ => return Err(MutationError::InvalidRequest),
    }
    if let MutationBody::Create(data) = &request.body {
        for (field_id, value) in data {
            let field = &request.plan.entity.fields[field_id];
            if value.is_null() && field.required {
                return Err(MutationError::InvalidRequest);
            }
            sql_value(value, &field.field_type)?;
        }
    }
    Ok(())
}

impl BatchMutationItem {
    fn operation(&self) -> Operation {
        match self {
            Self::Create(_) => Operation::Create,
            Self::Patch { .. } => Operation::Patch,
        }
    }

    fn request_parts(&self) -> (Option<&str>, Option<&str>, MutationBody) {
        match self {
            Self::Create(data) => (None, None, MutationBody::Create(data.clone())),
            Self::Patch {
                record_id,
                expected_etag,
                patch,
            } => (
                Some(record_id),
                Some(expected_etag),
                MutationBody::Patch(patch.clone()),
            ),
        }
    }

    fn canonical_json(&self) -> Value {
        match self {
            Self::Create(data) => json!({"operation": "create", "data": data}),
            Self::Patch {
                record_id,
                expected_etag,
                patch,
            } => json!({
                "operation": "patch",
                "recordId": record_id,
                "ifMatch": expected_etag,
                "patch": mutation_body_json(&MutationBody::Patch(patch.clone())),
            }),
        }
    }
}

fn validate_batch_request(
    request: &BatchMutationRequest<'_>,
    expected: &ExpectedRegistryIdentity,
) -> Result<(), MutationError> {
    expected
        .validate()
        .map_err(|_| MutationError::InvalidRequest)?;
    request
        .claims
        .validate()
        .map_err(|_| MutationError::InvalidRequest)?;
    let batch = request
        .plan
        .entity
        .batch
        .as_ref()
        .ok_or(MutationError::InvalidRequest)?;
    let profile = request
        .plan
        .entity
        .access_profiles
        .get(request.claims.access_profile())
        .ok_or(MutationError::InvalidRequest)?;
    if request.plan.route.operation != Operation::Batch
        || request.plan.route.method != HttpMethod::Post
        || request.claims.entity_id() != request.plan.entity.id
        || request.claims.principal().is_none()
        || profile.anonymous
        || !profile.operations.contains(&Operation::Batch)
        || !request
            .plan
            .route
            .access_profiles
            .iter()
            .any(|candidate| candidate == request.claims.access_profile())
        || request.items.is_empty()
        || request.items.len() > usize::from(batch.maximum_items)
        || request.body_bytes == 0
        || request.body_bytes > batch.maximum_bytes as usize
        || request.response_fields.is_empty()
        || !request.response_fields.is_subset(&profile.readable_fields)
    {
        return Err(MutationError::InvalidRequest);
    }

    for item in &request.items {
        if !profile.operations.contains(&item.operation())
            || item.operation() == Operation::Patch
                && request.plan.entity.mutation_mode != MutationMode::Mutable
        {
            return Err(MutationError::InvalidRequest);
        }
        let item_plan = request
            .plan
            .batch_item(item.operation(), request.claims.access_profile())?;
        let (record_id, expected_etag, body) = item.request_parts();
        let item_request = MutationRequest {
            plan: &item_plan,
            idempotency_key: request.idempotency_key,
            claims: request.claims,
            record_id,
            expected_etag,
            body,
            response_fields: request.response_fields.clone(),
        };
        validate_request(&item_request, expected)?;
        if let MutationBody::Patch(operations) = &item_request.body {
            validate_patch_static(&item_request, operations)?;
        }
    }
    Ok(())
}

fn validate_patch_static(
    request: &MutationRequest<'_>,
    operations: &[PatchOperation],
) -> Result<(), MutationError> {
    let profile = selected_profile(request)?;
    let mut mutated = false;
    for operation in operations {
        let path = match operation {
            PatchOperation::Add { path, .. }
            | PatchOperation::Replace { path, .. }
            | PatchOperation::Remove { path }
            | PatchOperation::Test { path, .. } => path,
        };
        let field_id = patch_field(path)?;
        let field = request
            .plan
            .entity
            .fields
            .get(&field_id)
            .ok_or(MutationError::InvalidRequest)?;
        match operation {
            PatchOperation::Add { value, .. } | PatchOperation::Replace { value, .. } => {
                if !profile.writable_fields.contains(&field_id) || value.is_null() && field.required
                {
                    return Err(MutationError::InvalidRequest);
                }
                sql_value(value, &field.field_type)?;
                mutated = true;
            }
            PatchOperation::Remove { .. } => {
                if field.required || !profile.writable_fields.contains(&field_id) {
                    return Err(MutationError::InvalidRequest);
                }
                mutated = true;
            }
            PatchOperation::Test { value, .. } => {
                if !profile.readable_fields.contains(&field_id) {
                    return Err(MutationError::InvalidRequest);
                }
                if !value.is_null() {
                    sql_value(value, &field.field_type)?;
                }
            }
        }
    }
    if !mutated {
        return Err(MutationError::InvalidRequest);
    }
    Ok(())
}

fn selected_profile<'a>(
    request: &'a MutationRequest<'a>,
) -> Result<&'a AccessProfileSource, MutationError> {
    let profile = request
        .plan
        .entity
        .access_profiles
        .get(request.claims.access_profile())
        .ok_or(MutationError::InvalidRequest)?;
    if !request
        .plan
        .route
        .access_profiles
        .iter()
        .any(|candidate| candidate == request.claims.access_profile())
    {
        return Err(MutationError::InvalidRequest);
    }
    Ok(profile)
}

fn canonical_request_digest(request: &MutationRequest<'_>) -> Result<[u8; 32], MutationError> {
    let canonical = canonicalize_json(&json!({
        "method": method_name(request.plan.route.method),
        "route": request.plan.route.path,
        "targetRecord": request.record_id,
        "expectedEtag": request.expected_etag,
        "mutationBody": mutation_body_json(&request.body),
    }))
    .map_err(|_| MutationError::InvalidRequest)?;
    Ok(Sha256::digest(canonical).into())
}

fn canonical_batch_request_digest(
    request: &BatchMutationRequest<'_>,
) -> Result<[u8; 32], MutationError> {
    let canonical = canonicalize_json(&json!({
        "method": method_name(request.plan.route.method),
        "route": request.plan.route.path,
        "items": request.items.iter().map(BatchMutationItem::canonical_json).collect::<Vec<_>>(),
    }))
    .map_err(|_| MutationError::InvalidRequest)?;
    Ok(Sha256::digest(canonical).into())
}

impl MutationBody {
    fn submitted_fields(&self) -> Result<Vec<String>, MutationError> {
        match self {
            Self::Create(data) => Ok(data.keys().cloned().collect()),
            Self::Patch(operations) => operations
                .iter()
                .filter_map(|operation| match operation {
                    PatchOperation::Add { path, .. }
                    | PatchOperation::Replace { path, .. }
                    | PatchOperation::Remove { path } => Some(patch_field(path)),
                    PatchOperation::Test { .. } => None,
                })
                .collect(),
            Self::Tombstone => Ok(Vec::new()),
        }
    }
}

fn mutation_body_json(body: &MutationBody) -> Value {
    match body {
        MutationBody::Create(data) => json!({"create": data}),
        MutationBody::Patch(operations) => Value::Array(
            operations
                .iter()
                .map(|operation| match operation {
                    PatchOperation::Add { path, value } => {
                        json!({"op": "add", "path": path, "value": value})
                    }
                    PatchOperation::Replace { path, value } => {
                        json!({"op": "replace", "path": path, "value": value})
                    }
                    PatchOperation::Remove { path } => json!({"op": "remove", "path": path}),
                    PatchOperation::Test { path, value } => {
                        json!({"op": "test", "path": path, "value": value})
                    }
                })
                .collect(),
        ),
        MutationBody::Tombstone => json!({"tombstone": true}),
    }
}

fn valid_strong_etag(value: &str) -> bool {
    value.len() > 5
        && value.len() <= 256
        && value.starts_with("\"rs-")
        && value.ends_with('"')
        && value.as_bytes()[1..value.len() - 1]
            .iter()
            .all(|byte| matches!(byte, 0x21 | 0x23..=0x7e))
}

fn record_reference(
    profile: &AuditProfile,
    package_revision: &str,
    record_id: &str,
) -> Result<String, MutationError> {
    profile
        .key_hasher()
        .audit_reference_hash("registry-server-record-v1", package_revision, record_id)
        .map_err(|_| MutationError::Unavailable)
}

fn sql_value(value: &Value, field_type: &FieldTypeSource) -> Result<Option<String>, MutationError> {
    if value.is_null() {
        return Ok(None);
    }
    if !validate_field_value(FieldValue::Json(value), field_type) {
        return Err(MutationError::InvalidRequest);
    }
    let value = match field_type {
        FieldTypeSource::Boolean => value.as_bool().map(|value| value.to_string()),
        FieldTypeSource::Int64 => value.as_i64().map(|value| value.to_string()),
        FieldTypeSource::Decimal { .. } => value.as_str().map(str::to_owned),
        FieldTypeSource::String { .. }
        | FieldTypeSource::Text { .. }
        | FieldTypeSource::VocabularyCode { .. }
        | FieldTypeSource::Date
        | FieldTypeSource::Timestamp
        | FieldTypeSource::Uuid
        | FieldTypeSource::Reference { .. } => value.as_str().map(str::to_owned),
        FieldTypeSource::Crs84Point { .. } | FieldTypeSource::Structured { .. } => {
            canonicalize_json(value)
                .ok()
                .and_then(|bytes| String::from_utf8(bytes).ok().filter(|_| !value.is_null()))
        }
    }
    .ok_or(MutationError::InvalidRequest)?;
    Ok(Some(value))
}

fn typed_parameter(index: usize, field_type: &FieldTypeSource) -> String {
    let cast = match field_type {
        FieldTypeSource::Boolean => "boolean",
        FieldTypeSource::String { .. }
        | FieldTypeSource::Text { .. }
        | FieldTypeSource::VocabularyCode { .. } => "text",
        FieldTypeSource::Int64 => "bigint",
        FieldTypeSource::Decimal {
            precision, scale, ..
        } => {
            return format!("${index}::text::numeric({precision},{scale})");
        }
        FieldTypeSource::Date => "date",
        FieldTypeSource::Timestamp => "timestamptz",
        FieldTypeSource::Uuid | FieldTypeSource::Reference { .. } => "uuid",
        FieldTypeSource::Crs84Point { .. } | FieldTypeSource::Structured { .. } => "jsonb",
    };
    format!("${index}::text::{cast}")
}

fn mutation_trigger(operation: Operation) -> EventTrigger {
    match operation {
        Operation::Create => EventTrigger::Created,
        Operation::Patch => EventTrigger::Patched,
        Operation::Tombstone => EventTrigger::Tombstoned,
        _ => unreachable!("mutation plans admit only create, patch, and tombstone"),
    }
}

fn mutation_kind(operation: Operation) -> &'static str {
    match operation {
        Operation::Create => "create",
        Operation::Patch => "patch",
        Operation::Tombstone => "tombstone",
        _ => unreachable!("mutation plans admit only create, patch, and tombstone"),
    }
}

fn method_name(method: HttpMethod) -> &'static str {
    match method {
        HttpMethod::Delete => "DELETE",
        HttpMethod::Get => "GET",
        HttpMethod::Patch => "PATCH",
        HttpMethod::Post => "POST",
    }
}

fn map_database_error(error: tokio_postgres::Error) -> MutationError {
    match error.code() {
        Some(code)
            if code == &SqlState::UNIQUE_VIOLATION
                || code == &SqlState::FOREIGN_KEY_VIOLATION
                || code == &SqlState::CHECK_VIOLATION
                || code == &SqlState::NOT_NULL_VIOLATION
                || code == &SqlState::EXCLUSION_VIOLATION =>
        {
            MutationError::Conflict
        }
        _ => MutationError::Unavailable,
    }
}

fn valid_physical_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte == b'_' || byte.is_ascii_lowercase())
        && bytes.all(|byte| byte == b'_' || byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value.len() <= 63
}

fn quote_identifier(value: &str) -> String {
    debug_assert!(valid_physical_identifier(value));
    format!("\"{value}\"")
}

fn valid_uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, byte)| match index {
            8 | 13 | 18 | 23 => byte == b'-',
            _ => byte.is_ascii_hexdigit(),
        })
        && Uuid::parse_str(value).is_ok_and(|identifier| identifier.to_string() == value)
}

impl From<IdempotencyError> for MutationError {
    fn from(error: IdempotencyError) -> Self {
        match error {
            IdempotencyError::InvalidInput => Self::InvalidRequest,
            IdempotencyError::Conflict => Self::IdempotencyConflict,
            IdempotencyError::Unavailable => Self::Unavailable,
        }
    }
}

impl From<RevisionError> for MutationError {
    fn from(error: RevisionError) -> Self {
        match error {
            RevisionError::InvalidSnapshot => Self::InvalidRequest,
            RevisionError::Unavailable => Self::Unavailable,
        }
    }
}

impl From<OutboxError> for MutationError {
    fn from(error: OutboxError) -> Self {
        match error {
            OutboxError::InvalidProjection => Self::InvalidRequest,
            OutboxError::Unavailable => Self::Unavailable,
        }
    }
}

impl From<RegistryAuditError> for MutationError {
    fn from(error: RegistryAuditError) -> Self {
        match error {
            RegistryAuditError::InvalidContext => Self::InvalidRequest,
            RegistryAuditError::Unavailable => Self::Unavailable,
        }
    }
}

#[cfg(all(test, feature = "postgres-test"))]
mod tests {
    use super::*;

    #[test]
    fn response_etag_binds_package_authority_boundary_and_projection() {
        let profile = AuditProfile::production_from_secret_bytes(vec![0x4d; 32].into())
            .expect("test profile is strongly keyed");
        let baseline = ClaimContext::kernel_for_test(
            "principal".to_owned(),
            "operator".to_owned(),
            Some("purpose-a".to_owned()),
            "zone-a".to_owned(),
        )
        .expect("baseline context is valid");
        let changed_purpose = ClaimContext::kernel_for_test(
            "principal".to_owned(),
            "operator".to_owned(),
            Some("purpose-b".to_owned()),
            "zone-a".to_owned(),
        )
        .expect("changed-purpose context is valid");
        let changed_boundary = ClaimContext::kernel_for_test(
            "principal".to_owned(),
            "operator".to_owned(),
            Some("purpose-a".to_owned()),
            "zone-b".to_owned(),
        )
        .expect("changed-boundary context is valid");
        let changed_profile = ClaimContext::kernel_for_test(
            "principal".to_owned(),
            "review-operator".to_owned(),
            Some("purpose-a".to_owned()),
            "zone-a".to_owned(),
        )
        .expect("changed-profile context is valid");
        let baseline_fields = BTreeSet::from(["label".to_owned()]);
        let changed_fields = BTreeSet::from(["label".to_owned(), "quantity".to_owned()]);
        let etag = |claims, package_revision, response_fields| {
            strong_record_etag(
                &profile,
                claims,
                package_revision,
                "00000000-0000-0000-0000-000000000001",
                1,
                response_fields,
            )
            .expect("ETag context is canonical")
        };

        let baseline_etag = etag(&baseline, "package-1", &baseline_fields);
        assert_ne!(
            baseline_etag,
            etag(&baseline, "package-2", &baseline_fields)
        );
        assert_ne!(
            baseline_etag,
            etag(&changed_profile, "package-1", &baseline_fields)
        );
        assert_ne!(
            baseline_etag,
            etag(&changed_purpose, "package-1", &baseline_fields)
        );
        assert_ne!(
            baseline_etag,
            etag(&changed_boundary, "package-1", &baseline_fields)
        );
        assert_ne!(baseline_etag, etag(&baseline, "package-1", &changed_fields));
    }

    #[test]
    fn mutation_scalar_validation_refuses_invalid_lexical_values_before_sql() {
        for (field_type, value) in [
            (FieldTypeSource::Uuid, "not-a-uuid"),
            (
                FieldTypeSource::Reference {
                    target: "entry".to_owned(),
                    on_delete: Default::default(),
                },
                "still-not-a-uuid",
            ),
            (FieldTypeSource::Date, "2026-02-30"),
            (FieldTypeSource::Timestamp, "2026-08-29 12:00:00"),
        ] {
            assert_eq!(
                sql_value(&Value::String(value.to_owned()), &field_type),
                Err(MutationError::InvalidRequest)
            );
        }
        assert_eq!(
            sql_value(
                &Value::String("too-long".to_owned()),
                &FieldTypeSource::String {
                    min_length: 1,
                    max_length: 3,
                },
            ),
            Err(MutationError::InvalidRequest)
        );
        assert_eq!(
            sql_value(
                &Value::String("01.20".to_owned()),
                &FieldTypeSource::Decimal {
                    precision: 4,
                    scale: 2,
                    minimum: Some("0.00".to_owned()),
                    maximum: Some("9.99".to_owned()),
                },
            ),
            Err(MutationError::InvalidRequest)
        );
        assert_eq!(
            sql_value(
                &Value::String("10.00".to_owned()),
                &FieldTypeSource::Decimal {
                    precision: 4,
                    scale: 2,
                    minimum: Some("0.00".to_owned()),
                    maximum: Some("9.99".to_owned()),
                },
            ),
            Err(MutationError::InvalidRequest)
        );
        assert_eq!(
            sql_value(
                &json!({"type":"Point","coordinates":[100.123,10.12345]}),
                &FieldTypeSource::Crs84Point {
                    precision: 4,
                    bbox: None,
                },
            ),
            Err(MutationError::InvalidRequest)
        );
        assert_eq!(
            sql_value(
                &json!({"code":"ok","extra":"refused"}),
                &FieldTypeSource::Structured {
                    max_bytes: 128,
                    schema: json!({
                        "type": "object",
                        "additionalProperties": false,
                        "properties": {"code": {"type": "string"}},
                        "required": ["code"]
                    }),
                },
            ),
            Err(MutationError::InvalidRequest)
        );
        assert_eq!(
            sql_value(
                &json!({"code":"ok"}),
                &FieldTypeSource::Structured {
                    max_bytes: 8,
                    schema: json!({
                        "type": "object",
                        "additionalProperties": false,
                        "properties": {"code": {"type": "string"}},
                        "required": ["code"]
                    }),
                },
            ),
            Err(MutationError::InvalidRequest)
        );
        assert!(sql_value(
            &json!({"type":"Point","coordinates":[100.1234,10.1234]}),
            &FieldTypeSource::Crs84Point {
                precision: 4,
                bbox: None,
            },
        )
        .is_ok());
    }
}
