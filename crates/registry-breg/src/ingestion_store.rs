// SPDX-License-Identifier: Apache-2.0

//! Product-owned ingestion-run bookkeeping.
//!
//! One ingestion run is the durable, caller-driven account of a bulk import:
//! the binding it was created under, the committed chunk prefix, and the
//! receipt of every committed chunk. The source rows themselves never reach
//! these tables. A chunk receipt holds exactly what the ordinary batch route
//! answers the same authorized caller with, and it is erased with the record
//! history it describes.

use std::fmt;

use registry_platform_audit::AuditProfile;
use registry_platform_canonical_json::parse_json_strict;
use serde_json::{json, Value};
use tokio_postgres::GenericClient;
use uuid::Uuid;

use crate::postgres::SqlIdentifier;

/// The product-owned ingestion tables and the privileges the runtime role
/// holds on them. Catalog closure consumes this exact list.
pub(crate) const INGESTION_TABLES: &[(&str, &[&str])] = &[
    ("registry_ingestion_runs", &["INSERT", "SELECT", "UPDATE"]),
    (
        "registry_ingestion_run_chunks",
        &["INSERT", "SELECT", "UPDATE"],
    ),
    (
        "registry_ingestion_run_chunk_records",
        &["INSERT", "SELECT"],
    ),
];

/// One chunk receipt is the batch answer for one bounded chunk, so it holds
/// no more than the idempotency cache it accompanies.
const MAX_RECEIPT_BYTES: usize = crate::idempotency::MAX_HELD_BODY_BYTES;
/// The member-to-field-identity map stored beside a receipt: one short
/// identifier pair per committed answer member, negligible beside the
/// receipt ceiling it is bounded under.
pub(crate) const MAX_FIELD_BINDINGS_BYTES: usize = 16 * 1024;
/// Runs are operator-driven and few; one page stays explicitly bounded.
pub(crate) const MAX_RUN_PAGE_SIZE: i64 = 100;
pub(crate) const DEFAULT_RUN_PAGE_SIZE: i64 = 25;

const RUN_DIGEST_PATTERN: &str = "^[0-9a-f]{64}$";

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum IngestionRunStatus {
    Open,
    Complete,
    Cancelled,
    Blocked,
}

impl IngestionRunStatus {
    fn as_str(self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Complete => "complete",
            Self::Cancelled => "cancelled",
            Self::Blocked => "blocked",
        }
    }

    pub(crate) fn parse(value: &str) -> Option<Self> {
        match value {
            "open" => Some(Self::Open),
            "complete" => Some(Self::Complete),
            "cancelled" => Some(Self::Cancelled),
            "blocked" => Some(Self::Blocked),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum IngestionBlockedReason {
    ActivePackageChanged,
}

impl IngestionBlockedReason {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::ActivePackageChanged => "active_package_changed",
        }
    }

    /// The wire form the run document answers with; storage stays snake_case.
    pub(crate) fn wire_str(self) -> &'static str {
        match self {
            Self::ActivePackageChanged => "activePackageChanged",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "active_package_changed" => Some(Self::ActivePackageChanged),
            _ => None,
        }
    }
}

/// The bounded, value-free classification of the last chunk attempt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub(crate) enum IngestionAttemptOutcome {
    Committed,
    Replayed,
    InvalidItem,
    Refused,
    BindingChanged,
    ChunkMismatch,
    RunNotOpen,
    Unavailable,
}

impl IngestionAttemptOutcome {
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Replayed => "replayed",
            Self::InvalidItem => "invalid_item",
            Self::Refused => "refused",
            Self::BindingChanged => "binding_changed",
            Self::ChunkMismatch => "chunk_mismatch",
            Self::RunNotOpen => "run_not_open",
            Self::Unavailable => "unavailable",
        }
    }

    /// The wire form the run document answers with; storage stays snake_case.
    pub(crate) fn wire_str(self) -> &'static str {
        match self {
            Self::Committed => "committed",
            Self::Replayed => "replayed",
            Self::InvalidItem => "invalidItem",
            Self::Refused => "refused",
            Self::BindingChanged => "bindingChanged",
            Self::ChunkMismatch => "chunkMismatch",
            Self::RunNotOpen => "runNotOpen",
            Self::Unavailable => "unavailable",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "committed" => Some(Self::Committed),
            "replayed" => Some(Self::Replayed),
            "invalid_item" => Some(Self::InvalidItem),
            "refused" => Some(Self::Refused),
            "binding_changed" => Some(Self::BindingChanged),
            "chunk_mismatch" => Some(Self::ChunkMismatch),
            "run_not_open" => Some(Self::RunNotOpen),
            "unavailable" => Some(Self::Unavailable),
            _ => None,
        }
    }
}

/// One durable run row.
#[derive(Clone, Eq, PartialEq)]
pub(crate) struct IngestionRunRecord {
    pub(crate) run_id: Uuid,
    pub(crate) created_principal_reference: String,
    pub(crate) package_revision: String,
    pub(crate) schema_fingerprint: String,
    pub(crate) entity_id: String,
    pub(crate) operation: String,
    pub(crate) profile_id: String,
    /// The keyed reference of the claim context the run was created under.
    /// Chunk submissions and receipt reads must resolve the same reference,
    /// so a drifted context cannot replay or continue another context's run.
    pub(crate) bound_context_reference: String,
    pub(crate) input_digest: String,
    pub(crate) input_length: i64,
    pub(crate) item_count: i64,
    pub(crate) chunk_count: i64,
    pub(crate) chunk_algorithm_version: String,
    pub(crate) maximum_items: i64,
    pub(crate) maximum_bytes: i64,
    pub(crate) status: IngestionRunStatus,
    pub(crate) blocked_reason: Option<IngestionBlockedReason>,
    pub(crate) next_chunk_index: i64,
    pub(crate) committed_items: i64,
    pub(crate) committed_prefix_digest: String,
    pub(crate) last_attempt_outcome: Option<IngestionAttemptOutcome>,
    pub(crate) last_attempt_chunk_index: Option<i64>,
    pub(crate) created_at: chrono::DateTime<chrono::Utc>,
    pub(crate) updated_at: chrono::DateTime<chrono::Utc>,
}

impl fmt::Debug for IngestionRunRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IngestionRunRecord")
            .field("run_id", &self.run_id)
            .field("status", &self.status)
            .field("entity_id", &self.entity_id)
            .field("operation", &self.operation)
            .field("next_chunk_index", &self.next_chunk_index)
            .field("committed_items", &self.committed_items)
            .finish_non_exhaustive()
    }
}

impl IngestionRunRecord {
    /// The run is not writable when the active package or schema fingerprint
    /// no longer matches the binding it was created under.
    pub(crate) fn active_binding_matches(
        &self,
        package_revision: &str,
        schema_fingerprint: &str,
    ) -> bool {
        self.package_revision == package_revision && self.schema_fingerprint == schema_fingerprint
    }

    /// The status a caller is told about, without persisting a transition:
    /// an open run whose binding no longer matches the active package is
    /// already blocked for writes.
    pub(crate) fn reported_status(
        &self,
        package_revision: &str,
        schema_fingerprint: &str,
    ) -> IngestionRunStatus {
        if self.status == IngestionRunStatus::Open
            && !self.active_binding_matches(package_revision, schema_fingerprint)
        {
            IngestionRunStatus::Blocked
        } else {
            self.status
        }
    }

    /// Render the operational, value-free view of one run.
    pub(crate) fn response_json(
        &self,
        active_package_revision: &str,
        active_schema_fingerprint: &str,
    ) -> Value {
        let mut run = json!({
            "runId": self.run_id.to_string(),
            "status": self.reported_status(active_package_revision, active_schema_fingerprint)
                .as_str(),
            "blockedReason": match (
                self.reported_status(active_package_revision, active_schema_fingerprint),
                self.blocked_reason,
            ) {
                (IngestionRunStatus::Blocked, reason) => Value::String(
                    reason
                        .unwrap_or(IngestionBlockedReason::ActivePackageChanged)
                        .wire_str()
                        .to_owned(),
                ),
                _ => Value::Null,
            },
            "entityId": self.entity_id,
            "operation": self.operation,
            "profileId": self.profile_id,
            "packageRevision": self.package_revision,
            "schemaFingerprint": self.schema_fingerprint,
            "inputDigest": self.input_digest,
            "inputLength": self.input_length,
            "itemCount": self.item_count,
            "chunkCount": self.chunk_count,
            "chunkAlgorithmVersion": self.chunk_algorithm_version,
            "maximumItems": self.maximum_items,
            "maximumBytes": self.maximum_bytes,
            "nextChunkIndex": self.next_chunk_index,
            "committedItems": self.committed_items,
            "committedPrefixDigest": self.committed_prefix_digest,
            "lastAttempt": match self.last_attempt_outcome {
                Some(outcome) => json!({
                    "outcome": outcome.wire_str(),
                    "chunkIndex": self.last_attempt_chunk_index,
                }),
                None => Value::Null,
            },
            "createdAt": self.created_at.to_rfc3339(),
            "updatedAt": self.updated_at.to_rfc3339(),
        });
        if let Some(object) = run.as_object_mut() {
            object.insert(
                "complete".to_owned(),
                json!(
                    self.reported_status(active_package_revision, active_schema_fingerprint)
                        == IngestionRunStatus::Complete
                ),
            );
        }
        run
    }
}

/// The binding a new run is created under.
pub(crate) struct NewIngestionRun {
    pub(crate) created_principal_reference: String,
    pub(crate) package_revision: String,
    pub(crate) schema_fingerprint: String,
    pub(crate) entity_id: String,
    pub(crate) operation: String,
    pub(crate) profile_id: String,
    pub(crate) bound_context_reference: String,
    pub(crate) input_digest: String,
    pub(crate) input_length: i64,
    pub(crate) item_count: i64,
    pub(crate) chunk_count: i64,
    pub(crate) chunk_algorithm_version: String,
    pub(crate) maximum_items: i64,
    pub(crate) maximum_bytes: i64,
}

/// One committed chunk and the receipt that proves it.
pub(crate) struct IngestionChunkCommit {
    pub(crate) run_id: Uuid,
    pub(crate) chunk_index: i64,
    pub(crate) chunk_digest: String,
    pub(crate) prefix_digest: String,
    pub(crate) item_count: i64,
    pub(crate) end_item: i64,
    /// The exact canonical batch answer for this chunk. It carries what the
    /// ordinary batch route answers the same authorized caller with and is
    /// erased with the record history it describes.
    pub(crate) receipt: Vec<u8>,
    /// The canonical JSON map binding each receipt data member to the logical
    /// field id that produced it, derived from the same answer the receipt
    /// stores. Every later release of the stored answer re-checks each member
    /// against the field identity it was committed under.
    pub(crate) receipt_field_bindings: String,
}

/// One stored chunk receipt, either live or erased.
pub(crate) struct StoredChunkReceipt {
    pub(crate) chunk_index: i64,
    pub(crate) chunk_digest: String,
    pub(crate) prefix_digest: String,
    pub(crate) item_count: i64,
    pub(crate) end_item: i64,
    pub(crate) receipt: Option<Vec<u8>>,
    /// The stored member-to-field-identity map of the committed answer.
    /// Value-free metadata: it survives receipt erasure, and a live receipt
    /// without it is stored corruption.
    pub(crate) field_bindings: Option<std::collections::BTreeMap<String, String>>,
    pub(crate) erased: bool,
}

impl StoredChunkReceipt {
    /// The committed-window shape a recovered receipt must still carry. A row
    /// that fails this is stored corruption, answered as an outage rather
    /// than replayed to the caller.
    pub(crate) fn committed_shape_is_valid(&self) -> bool {
        self.item_count > 0
            && self.end_item >= self.item_count
            && self.prefix_digest.len() == 64
            && self
                .prefix_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub(crate) enum IngestionStoreError {
    #[error("ingestion run input is invalid")]
    InvalidInput,
    #[error("ingestion run state is unavailable")]
    Unavailable,
}

/// The run-bound context one ingestion-driven batch execution carries into
/// the mutation transaction. The transaction holds it while the run row lock
/// is held, so the checkpoint and the mutation cannot diverge. The committed
/// window end is derived from the locked run row rather than announced, so a
/// stale announcement can never move it.
pub struct IngestionChunkBinding {
    pub(crate) run_id: Uuid,
    pub(crate) chunk_index: i64,
    pub(crate) chunk_digest: String,
    pub(crate) prefix_digest: String,
    pub(crate) item_count: i64,
    /// The run creator principal reference, so transaction-appended run audit
    /// records stay attributable without the caller claims at hand.
    pub(crate) created_principal_reference: String,
}

impl IngestionChunkBinding {
    /// The announced chunk shape the submission path admits before any lock.
    pub(crate) fn shape_is_valid(&self) -> bool {
        self.chunk_index >= 0
            && self.item_count > 0
            && self.chunk_digest.len() == 64
            && self
                .chunk_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            && self.prefix_digest.len() == 64
            && self
                .prefix_digest
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            && !self.created_principal_reference.is_empty()
    }
}

/// The closed refusal vocabulary the chunk submission path answers with. It
/// is bounded and value-free: no chunk bytes, row values, or bearer material
/// travel with it.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum IngestionRefusal {
    #[error("ingestion run is not open for the requested transition")]
    RunNotOpen,
    #[error("ingestion chunk does not match the expected next chunk")]
    ChunkMismatch,
    #[error("active package no longer matches the run binding")]
    BindingChanged,
    #[error("the stored receipt of the committed chunk was erased")]
    ReceiptErased,
}

pub(crate) async fn install(
    migration: &impl GenericClient,
    runtime_role: &SqlIdentifier,
) -> Result<(), IngestionStoreError> {
    migration
        .batch_execute(&format!(
            "CREATE TABLE IF NOT EXISTS registry_internal.registry_ingestion_runs (
                 run_id uuid PRIMARY KEY,
                 created_principal_reference text NOT NULL
                     CHECK (created_principal_reference <> ''),
                 package_revision text NOT NULL CHECK (package_revision <> ''),
                 schema_fingerprint text NOT NULL CHECK (schema_fingerprint <> ''),
                 entity_id text NOT NULL CHECK (entity_id <> ''),
                 operation text NOT NULL CHECK (operation IN ('create', 'patch')),
                 profile_id text NOT NULL CHECK (profile_id <> ''),
                 bound_context_reference text NOT NULL
                     CHECK (bound_context_reference <> ''),
                 input_digest text NOT NULL CHECK (input_digest ~ '{RUN_DIGEST_PATTERN}'),
                 input_length bigint NOT NULL CHECK (input_length > 0),
                 item_count bigint NOT NULL CHECK (item_count > 0),
                 chunk_count bigint NOT NULL CHECK (chunk_count > 0),
                 chunk_algorithm_version text NOT NULL CHECK (chunk_algorithm_version <> ''),
                 maximum_items int NOT NULL CHECK (maximum_items > 0),
                 maximum_bytes bigint NOT NULL CHECK (maximum_bytes > 0),
                 status text NOT NULL
                     CONSTRAINT registry_ingestion_runs_status_values
                     CHECK (status IN ('open', 'complete', 'cancelled', 'blocked')),
                 blocked_reason text
                     CONSTRAINT registry_ingestion_runs_blocked_reason_values
                     CHECK (blocked_reason IS NULL OR
                         blocked_reason IN ('active_package_changed')),
                 next_chunk_index bigint NOT NULL CHECK (next_chunk_index >= 0),
                 committed_items bigint NOT NULL CHECK (committed_items >= 0),
                 committed_prefix_digest text NOT NULL
                     CHECK (committed_prefix_digest ~ '{RUN_DIGEST_PATTERN}'),
                 last_attempt_outcome text
                     CONSTRAINT registry_ingestion_runs_attempt_values
                     CHECK (last_attempt_outcome IS NULL OR last_attempt_outcome IN
                         ('committed', 'replayed', 'invalid_item', 'refused',
                          'binding_changed', 'chunk_mismatch', 'run_not_open', 'unavailable')),
                 last_attempt_chunk_index bigint
                     CHECK (last_attempt_chunk_index IS NULL OR last_attempt_chunk_index >= 0),
                 created_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                 updated_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                 CONSTRAINT registry_ingestion_runs_blocked_shape CHECK (
                     (status = 'blocked') = (blocked_reason IS NOT NULL)
                 ),
                 CONSTRAINT registry_ingestion_runs_prefix_shape CHECK (
                     (next_chunk_index = 0 AND committed_items = 0) OR next_chunk_index > 0
                 )
             );
             CREATE TABLE IF NOT EXISTS registry_internal.registry_ingestion_run_chunks (
                 run_id uuid NOT NULL
                     REFERENCES registry_internal.registry_ingestion_runs(run_id)
                     ON DELETE CASCADE,
                 chunk_index bigint NOT NULL CHECK (chunk_index >= 0),
                 chunk_digest text NOT NULL CHECK (chunk_digest ~ '{RUN_DIGEST_PATTERN}'),
                 prefix_digest text NOT NULL CHECK (prefix_digest ~ '{RUN_DIGEST_PATTERN}'),
                 item_count bigint NOT NULL CHECK (item_count > 0),
                 end_item bigint NOT NULL CHECK (end_item > 0),
                 receipt bytea,
                 receipt_field_bindings text
                     CONSTRAINT registry_ingestion_run_chunks_field_bindings_shape CHECK (
                         receipt IS NULL OR (
                             receipt_field_bindings IS NOT NULL
                             AND octet_length(receipt_field_bindings) > 0
                             AND octet_length(receipt_field_bindings)
                                 <= {MAX_FIELD_BINDINGS_BYTES})
                     ),
                 erased_at timestamptz,
                 committed_at timestamptz NOT NULL DEFAULT transaction_timestamp(),
                 PRIMARY KEY (run_id, chunk_index),
                 CONSTRAINT registry_ingestion_run_chunks_erasure_shape CHECK (
                     (receipt IS NULL AND erased_at IS NOT NULL)
                     OR (receipt IS NOT NULL AND erased_at IS NULL
                         AND octet_length(receipt) > 0
                         AND octet_length(receipt) <= {MAX_RECEIPT_BYTES})
                 )
             );
             CREATE TABLE IF NOT EXISTS registry_internal.registry_ingestion_run_chunk_records (
                 run_id uuid NOT NULL
                     REFERENCES registry_internal.registry_ingestion_runs(run_id)
                     ON DELETE CASCADE,
                 chunk_index bigint NOT NULL CHECK (chunk_index >= 0),
                 record_id uuid NOT NULL,
                 record_revision bigint NOT NULL CHECK (record_revision > 0),
                 PRIMARY KEY (run_id, chunk_index, record_id)
             );
             REVOKE ALL ON registry_internal.registry_ingestion_runs,
                 registry_internal.registry_ingestion_run_chunks,
                 registry_internal.registry_ingestion_run_chunk_records FROM PUBLIC;
             GRANT INSERT, SELECT, UPDATE ON registry_internal.registry_ingestion_runs
                 TO \"{role}\";
             GRANT INSERT, SELECT, UPDATE ON registry_internal.registry_ingestion_run_chunks
                 TO \"{role}\";
             GRANT INSERT, SELECT
                 ON registry_internal.registry_ingestion_run_chunk_records TO \"{role}\";",
            role = runtime_role.as_str(),
        ))
        .await
        .map_err(|_| IngestionStoreError::Unavailable)?;
    Ok(())
}

fn parse_run_row(row: &tokio_postgres::Row) -> Option<IngestionRunRecord> {
    let status: String = row.get("status");
    Some(IngestionRunRecord {
        run_id: row.get("run_id"),
        created_principal_reference: row.get("created_principal_reference"),
        package_revision: row.get("package_revision"),
        schema_fingerprint: row.get("schema_fingerprint"),
        entity_id: row.get("entity_id"),
        operation: row.get("operation"),
        profile_id: row.get("profile_id"),
        bound_context_reference: row.get("bound_context_reference"),
        input_digest: row.get("input_digest"),
        input_length: row.get("input_length"),
        item_count: row.get("item_count"),
        chunk_count: row.get("chunk_count"),
        chunk_algorithm_version: row.get("chunk_algorithm_version"),
        maximum_items: i64::from(row.get::<_, i32>("maximum_items")),
        maximum_bytes: row.get("maximum_bytes"),
        status: IngestionRunStatus::parse(&status)?,
        blocked_reason: row
            .try_get::<_, Option<String>>("blocked_reason")
            .ok()
            .flatten()
            .as_deref()
            .and_then(IngestionBlockedReason::parse),
        next_chunk_index: row.get("next_chunk_index"),
        committed_items: row.get("committed_items"),
        committed_prefix_digest: row.get("committed_prefix_digest"),
        last_attempt_outcome: row
            .try_get::<_, Option<String>>("last_attempt_outcome")
            .ok()
            .flatten()
            .as_deref()
            .and_then(IngestionAttemptOutcome::parse),
        last_attempt_chunk_index: row
            .try_get::<_, Option<i64>>("last_attempt_chunk_index")
            .ok()
            .flatten(),
        created_at: row.get("created_at"),
        updated_at: row.get("updated_at"),
    })
}

const RUN_COLUMNS: &str =
    "run_id, created_principal_reference, package_revision, schema_fingerprint,
    entity_id, operation, profile_id, bound_context_reference, input_digest, input_length,
    item_count, chunk_count, chunk_algorithm_version, maximum_items, maximum_bytes, status,
    blocked_reason, next_chunk_index, committed_items, committed_prefix_digest,
    last_attempt_outcome, last_attempt_chunk_index, created_at, updated_at";

pub(crate) fn validate_new_run(run: &NewIngestionRun) -> Result<(), IngestionStoreError> {
    let digest = |value: &str| {
        value.len() == 64
            && value
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    };
    if run.created_principal_reference.is_empty()
        || run.package_revision.is_empty()
        || run.schema_fingerprint.is_empty()
        || run.entity_id.is_empty()
        || run.profile_id.is_empty()
        || run.bound_context_reference.is_empty()
        || !matches!(run.operation.as_str(), "create" | "patch")
        || !digest(&run.input_digest)
        || run.input_length <= 0
        || run.item_count <= 0
        || run.chunk_count <= 0
        || run.chunk_algorithm_version.is_empty()
        || run.maximum_items <= 0
        || run.maximum_bytes <= 0
        || run.maximum_items > i64::from(u16::MAX)
        // The greedy chunker emits at least one item per chunk and at most
        // maximum_items, so the announced counts must respect both bounds.
        // The minimum count is the ceiling of item_count over
        // maximum_items; `1 + (item_count - 1) / maximum_items` computes it
        // without overflow, where `item_count + maximum_items - 1` wraps
        // near i64::MAX, and both operands are positive because the clause
        // above has already refused non-positive values.
        || run.chunk_count > run.item_count
        || run.chunk_count < 1 + (run.item_count - 1) / run.maximum_items
    {
        return Err(IngestionStoreError::InvalidInput);
    }
    Ok(())
}

pub(crate) async fn insert_run(
    client: &impl GenericClient,
    run: &NewIngestionRun,
) -> Result<IngestionRunRecord, IngestionStoreError> {
    let run_id = Uuid::new_v4();
    // The column is int4, so the parameter must bind as i32; validation has
    // already capped the value far below the i32 range.
    let maximum_items =
        i32::try_from(run.maximum_items).map_err(|_| IngestionStoreError::InvalidInput)?;
    let row = client
        .query_one(
            &format!(
                "INSERT INTO registry_internal.registry_ingestion_runs
                     (run_id, created_principal_reference, package_revision, schema_fingerprint,
                      entity_id, operation, profile_id, bound_context_reference, input_digest,
                      input_length, item_count, chunk_count, chunk_algorithm_version,
                      maximum_items, maximum_bytes, status, blocked_reason, next_chunk_index,
                      committed_items, committed_prefix_digest, last_attempt_outcome,
                      last_attempt_chunk_index)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
                         'open', NULL, 0, 0, $16, NULL, NULL)
                 RETURNING {RUN_COLUMNS}",
            ),
            &[
                &run_id,
                &run.created_principal_reference,
                &run.package_revision,
                &run.schema_fingerprint,
                &run.entity_id,
                &run.operation,
                &run.profile_id,
                &run.bound_context_reference,
                &run.input_digest,
                &run.input_length,
                &run.item_count,
                &run.chunk_count,
                &run.chunk_algorithm_version,
                &maximum_items,
                &run.maximum_bytes,
                &empty_digest_hex(),
            ],
        )
        .await
        .map_err(|_| IngestionStoreError::Unavailable)?;
    parse_run_row(&row).ok_or(IngestionStoreError::Unavailable)
}

/// The sha256 of the empty input, the committed prefix digest of a run that
/// has committed no chunk.
fn empty_digest_hex() -> String {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest([]);
    let mut encoded = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

/// The package identity the database holds active right now, so every
/// instance, including one a successor activation has left stale, reads and
/// gates runs against the durable binding rather than its own.
pub(crate) async fn active_binding(
    client: &impl GenericClient,
) -> Result<(String, String), IngestionStoreError> {
    let row = client
        .query_opt(
            "SELECT active_package_revision, schema_fingerprint
               FROM registry_internal.registry_state
              WHERE singleton",
            &[],
        )
        .await
        .map_err(|_| IngestionStoreError::Unavailable)?
        .ok_or(IngestionStoreError::Unavailable)?;
    Ok((row.get(0), row.get(1)))
}

pub(crate) async fn load_run(
    client: &impl GenericClient,
    run_id: Uuid,
) -> Result<Option<IngestionRunRecord>, IngestionStoreError> {
    let row = client
        .query_opt(
            &format!(
                "SELECT {RUN_COLUMNS}
                   FROM registry_internal.registry_ingestion_runs
                  WHERE run_id = $1",
            ),
            &[&run_id],
        )
        .await
        .map_err(|_| IngestionStoreError::Unavailable)?;
    row.as_ref().and_then(parse_run_row).pipe_some()
}

trait PipeSome<T> {
    fn pipe_some(self) -> Result<Option<T>, IngestionStoreError>;
}

impl<T> PipeSome<T> for Option<T> {
    fn pipe_some(self) -> Result<Option<T>, IngestionStoreError> {
        Ok(self)
    }
}

/// Load one run for the chunk submission path, holding the row lock that
/// serializes every concurrent submission against the same run. The lock is
/// taken inside the caller's record transaction, so it is released with it.
pub(crate) async fn lock_run(
    transaction: &tokio_postgres::Transaction<'_>,
    run_id: Uuid,
) -> Result<Option<IngestionRunRecord>, IngestionStoreError> {
    let row = transaction
        .query_opt(
            &format!(
                "SELECT {RUN_COLUMNS}
                   FROM registry_internal.registry_ingestion_runs
                  WHERE run_id = $1
                  FOR UPDATE",
            ),
            &[&run_id],
        )
        .await
        .map_err(|_| IngestionStoreError::Unavailable)?;
    row.as_ref().and_then(parse_run_row).pipe_some()
}

/// The filters one bounded, principal-scoped run listing accepts.
pub(crate) struct IngestionRunListFilter<'a> {
    pub(crate) principal_reference: &'a str,
    /// The keyed reference of the access context the listing caller presents.
    /// A run appears only to the context that created it, so the listing
    /// exposes no more than the per-run surfaces already answer that same
    /// context with.
    pub(crate) bound_context_reference: &'a str,
    pub(crate) entity_id: Option<&'a str>,
    pub(crate) profile_id: Option<&'a str>,
    pub(crate) status: Option<IngestionRunStatus>,
    pub(crate) input_digest: Option<&'a str>,
    /// Keyset paging: return only runs ordered before this run id. The
    /// caller resolves the id to its sort key first, so an unknown cursor is
    /// refused as input rather than silently matching nothing.
    pub(crate) after: Option<(chrono::DateTime<chrono::Utc>, Uuid)>,
    pub(crate) limit: i64,
}

pub(crate) async fn list_runs(
    client: &impl GenericClient,
    filter: &IngestionRunListFilter<'_>,
) -> Result<(Vec<IngestionRunRecord>, bool), IngestionStoreError> {
    if filter.principal_reference.is_empty()
        || filter.bound_context_reference.is_empty()
        || filter.limit <= 0
        || filter.limit > MAX_RUN_PAGE_SIZE
        || filter.input_digest.is_some_and(|digest| {
            digest.len() != 64
                || !digest
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
    {
        return Err(IngestionStoreError::InvalidInput);
    }
    let status = filter.status.map(|status| status.as_str().to_owned());
    let after_created_at = filter.after.map(|(created_at, _)| created_at);
    let after_run_id = filter.after.map(|(_, run_id)| run_id);
    // The status filter runs on the status a run document renders, so an
    // open run whose binding a successor package retired answers as blocked
    // here exactly as it does everywhere else. The durable binding, not the
    // process's own, decides it, and the filter applies before the page cut.
    let rows = client
        .query(
            &format!(
                "SELECT {RUN_COLUMNS}
                   FROM registry_internal.registry_ingestion_runs
                  CROSS JOIN (
                       SELECT active_package_revision AS state_package_revision,
                              schema_fingerprint AS state_schema_fingerprint
                         FROM registry_internal.registry_state
                        WHERE singleton
                   ) AS active
                  WHERE created_principal_reference = $1
                    AND bound_context_reference = $9
                    AND ($2::text IS NULL OR entity_id = $2)
                    AND ($3::text IS NULL OR profile_id = $3)
                    AND ($4::text IS NULL OR $4 = CASE
                            WHEN status <> 'open' THEN status
                            WHEN package_revision = active.state_package_revision
                                 AND schema_fingerprint = active.state_schema_fingerprint
                                THEN 'open'
                            ELSE 'blocked'
                        END)
                    AND ($5::text IS NULL OR input_digest = $5)
                    AND ($7::timestamptz IS NULL OR (created_at, run_id) < ($7, $8))
                  ORDER BY created_at DESC, run_id DESC
                  LIMIT $6",
            ),
            &[
                &filter.principal_reference,
                &filter.entity_id,
                &filter.profile_id,
                &status,
                &filter.input_digest,
                &(filter.limit + 1),
                &after_created_at,
                &after_run_id,
                &filter.bound_context_reference,
            ],
        )
        .await
        .map_err(|_| IngestionStoreError::Unavailable)?;
    let has_more = rows.len() > filter.limit as usize;
    let runs = rows
        .into_iter()
        .take(filter.limit as usize)
        .filter_map(|row| parse_run_row(&row))
        .collect::<Vec<_>>();
    if runs.len() != filter.limit as usize && has_more {
        return Err(IngestionStoreError::Unavailable);
    }
    Ok((runs, has_more))
}

/// Record the bounded outcome of one refused chunk attempt. The refusal
/// itself is already audited by the ordinary batch boundary audit, so this
/// writes operational metadata only.
pub(crate) async fn record_attempt(
    client: &impl GenericClient,
    run_id: Uuid,
    outcome: IngestionAttemptOutcome,
    chunk_index: i64,
) -> Result<(), IngestionStoreError> {
    if chunk_index < 0 {
        return Err(IngestionStoreError::InvalidInput);
    }
    client
        .execute(
            "UPDATE registry_internal.registry_ingestion_runs
                SET last_attempt_outcome = $2,
                    last_attempt_chunk_index = $3,
                    updated_at = transaction_timestamp()
              WHERE run_id = $1",
            &[&run_id, &outcome.as_str(), &chunk_index],
        )
        .await
        .map_err(|_| IngestionStoreError::Unavailable)?;
    Ok(())
}

/// Mark a run blocked for writes because its binding no longer matches the
/// active package. The run remains inspectable under its retention policy.
pub(crate) async fn mark_blocked(
    client: &impl GenericClient,
    run_id: Uuid,
    reason: IngestionBlockedReason,
) -> Result<(), IngestionStoreError> {
    client
        .execute(
            "UPDATE registry_internal.registry_ingestion_runs
                SET status = 'blocked',
                    blocked_reason = $2,
                    updated_at = transaction_timestamp()
              WHERE run_id = $1
                AND status = 'open'",
            &[&run_id, &reason.as_str()],
        )
        .await
        .map_err(|_| IngestionStoreError::Unavailable)?;
    Ok(())
}

/// Cancel an open or blocked run, preserving the committed chunk prefix.
pub(crate) async fn cancel_run(
    client: &impl GenericClient,
    run_id: Uuid,
    outcome: IngestionAttemptOutcome,
) -> Result<Option<IngestionRunRecord>, IngestionStoreError> {
    let row = client
        .query_opt(
            &format!(
                "UPDATE registry_internal.registry_ingestion_runs
                    SET status = 'cancelled',
                        blocked_reason = NULL,
                        last_attempt_outcome = $2,
                        last_attempt_chunk_index = NULL,
                        updated_at = transaction_timestamp()
                  WHERE run_id = $1
                    AND status IN ('open', 'blocked')
                  RETURNING {RUN_COLUMNS}",
            ),
            &[&run_id, &outcome.as_str()],
        )
        .await
        .map_err(|_| IngestionStoreError::Unavailable)?;
    row.as_ref().and_then(parse_run_row).pipe_some()
}

/// Load the stored receipt of one committed chunk.
pub(crate) async fn load_chunk(
    client: &impl GenericClient,
    run_id: Uuid,
    chunk_index: i64,
) -> Result<Option<StoredChunkReceipt>, IngestionStoreError> {
    let row = client
        .query_opt(
            "SELECT chunk_index, chunk_digest, prefix_digest, item_count, end_item, receipt,
                    receipt_field_bindings, erased_at
               FROM registry_internal.registry_ingestion_run_chunks
              WHERE run_id = $1
                AND chunk_index = $2",
            &[&run_id, &chunk_index],
        )
        .await
        .map_err(|_| IngestionStoreError::Unavailable)?;
    let Some(row) = row else {
        return Ok(None);
    };
    let erased_at: Option<chrono::DateTime<chrono::Utc>> = row.get("erased_at");
    Ok(Some(StoredChunkReceipt {
        chunk_index: row.get("chunk_index"),
        chunk_digest: row.get("chunk_digest"),
        prefix_digest: row.get("prefix_digest"),
        item_count: row.get("item_count"),
        end_item: row.get("end_item"),
        receipt: row.try_get("receipt").ok(),
        // A malformed stored map reads as absent, so the release refuses the
        // receipt as stored corruption instead of trusting a partial map.
        field_bindings: row
            .try_get::<_, Option<String>>("receipt_field_bindings")
            .ok()
            .flatten()
            .as_deref()
            .and_then(parse_field_bindings),
        erased: erased_at.is_some(),
    }))
}

/// Commit one chunk receipt and advance the run checkpoint. The caller holds
/// the run row lock inside the same transaction, so the guarded update must
/// advance exactly one row.
pub(crate) async fn commit_chunk(
    transaction: &tokio_postgres::Transaction<'_>,
    commit: &IngestionChunkCommit,
    outcome: IngestionAttemptOutcome,
) -> Result<(), IngestionStoreError> {
    if commit.chunk_index < 0
        || commit.item_count <= 0
        || commit.end_item < commit.item_count
        || commit.receipt.is_empty()
        || commit.receipt.len() > MAX_RECEIPT_BYTES
        || !valid_receipt(&commit.receipt)
        || commit.receipt_field_bindings.is_empty()
        || commit.receipt_field_bindings.len() > MAX_FIELD_BINDINGS_BYTES
        || parse_field_bindings(&commit.receipt_field_bindings).is_none()
    {
        return Err(IngestionStoreError::InvalidInput);
    }
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_ingestion_run_chunks
                 (run_id, chunk_index, chunk_digest, prefix_digest, item_count, end_item,
                  receipt, receipt_field_bindings, erased_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NULL)",
            &[
                &commit.run_id,
                &commit.chunk_index,
                &commit.chunk_digest,
                &commit.prefix_digest,
                &commit.item_count,
                &commit.end_item,
                &commit.receipt,
                &commit.receipt_field_bindings,
            ],
        )
        .await
        .map_err(|_| IngestionStoreError::Unavailable)?;
    let records = receipt_records(&commit.receipt).ok_or(IngestionStoreError::InvalidInput)?;
    for (record_id, record_revision) in records {
        transaction
            .execute(
                "INSERT INTO registry_internal.registry_ingestion_run_chunk_records
                     (run_id, chunk_index, record_id, record_revision)
                 VALUES ($1, $2, $3, $4)",
                &[
                    &commit.run_id,
                    &commit.chunk_index,
                    &record_id,
                    &record_revision,
                ],
            )
            .await
            .map_err(|_| IngestionStoreError::Unavailable)?;
    }
    let next_index = commit.chunk_index + 1;
    let changed = transaction
        .execute(
            "UPDATE registry_internal.registry_ingestion_runs
                SET next_chunk_index = $2,
                    committed_items = committed_items + $3,
                    committed_prefix_digest = $4,
                    status = CASE WHEN $2 = chunk_count THEN 'complete' ELSE 'open' END,
                    last_attempt_outcome = $5,
                    last_attempt_chunk_index = $6,
                    updated_at = transaction_timestamp()
              WHERE run_id = $1
                AND next_chunk_index = $6
                AND status = 'open'",
            &[
                &commit.run_id,
                &next_index,
                &commit.item_count,
                &commit.prefix_digest,
                &outcome.as_str(),
                &commit.chunk_index,
            ],
        )
        .await
        .map_err(|_| IngestionStoreError::Unavailable)?;
    if changed != 1 {
        return Err(IngestionStoreError::Unavailable);
    }
    Ok(())
}

/// The record links one receipt describes, parsed from its own bounded shape.
/// Every result row of a batch answer carries the record id and revision.
fn receipt_records(receipt: &[u8]) -> Option<Vec<(Uuid, i64)>> {
    let value = parse_json_strict(receipt).ok()?;
    let results = value.get("results")?.as_array()?;
    let mut records = Vec::with_capacity(results.len());
    for result in results {
        let id = result.get("id")?.as_str()?;
        let revision = result.get("revision")?.as_i64()?;
        records.push((Uuid::parse_str(id).ok()?, revision));
    }
    Some(records)
}

fn valid_receipt(receipt: &[u8]) -> bool {
    parse_json_strict(receipt)
        .is_ok_and(|value| value.get("snapshot").is_some_and(Value::is_string))
}

/// The canonical member-to-field-identity map one batch answer was produced
/// under: every data member is keyed by a stored field's api name, so the
/// map binds each member to the logical field id that produced it. A member
/// the active entity does not store refuses the derivation, because a
/// receipt the runtime built never carries one.
pub(crate) fn receipt_field_bindings(
    entity: &crate::model::CompiledEntity,
    receipt: &[u8],
) -> Option<String> {
    let value = parse_json_strict(receipt).ok()?;
    let results = value.get("results")?.as_array()?;
    let mut bindings = serde_json::Map::new();
    for result in results {
        let data = result.get("data")?.as_object()?;
        for member in data.keys() {
            let field = entity
                .stored_fields
                .iter()
                .find(|field| field.logical.api_name == *member)
                .map(|field| field.logical.id.clone())?;
            bindings.insert(member.clone(), Value::String(field));
        }
    }
    let canonical =
        registry_platform_canonical_json::canonicalize_json(&Value::Object(bindings)).ok()?;
    String::from_utf8(canonical).ok()
}

/// The stored member-to-field-identity map of one committed answer, parsed
/// strictly: a non-empty object of non-empty string field ids, nothing else.
pub(crate) fn parse_field_bindings(
    raw: &str,
) -> Option<std::collections::BTreeMap<String, String>> {
    let value = parse_json_strict(raw.as_bytes()).ok()?;
    let object = value.as_object()?;
    let mut bindings = std::collections::BTreeMap::new();
    for (member, field) in object {
        let field = field.as_str()?;
        if member.is_empty() || field.is_empty() {
            return None;
        }
        bindings.insert(member.clone(), field.to_owned());
    }
    Some(bindings)
}

/// Tombstone every chunk receipt that describes one erased revision of the
/// record. Called inside the record-history erasure transaction, so a receipt
/// never outlives the history it describes, while a receipt describing only
/// later revisions of the same record survives.
pub(crate) async fn scrub_receipts_for_records(
    transaction: &tokio_postgres::Transaction<'_>,
    entity_id: &str,
    record_id: Uuid,
    erase_through_revision: i64,
) -> Result<u64, IngestionStoreError> {
    if entity_id.is_empty() || erase_through_revision <= 0 {
        return Err(IngestionStoreError::InvalidInput);
    }
    let changed = transaction
        .execute(
            "UPDATE registry_internal.registry_ingestion_run_chunks AS chunk
                SET receipt = NULL,
                    erased_at = transaction_timestamp()
              WHERE chunk.erased_at IS NULL
                AND EXISTS (
                    SELECT 1
                      FROM registry_internal.registry_ingestion_run_chunk_records AS link
                      JOIN registry_internal.registry_ingestion_runs AS run
                        ON run.run_id = link.run_id
                     WHERE link.run_id = chunk.run_id
                       AND link.chunk_index = chunk.chunk_index
                       AND link.record_id = $2
                       AND link.record_revision <= $3
                       AND run.entity_id = $1
                )",
            &[&entity_id, &record_id, &erase_through_revision],
        )
        .await
        .map_err(|_| IngestionStoreError::Unavailable)?;
    Ok(changed)
}

/// Append one value-free ingestion-run lifecycle record to the chained audit
/// journal. Digests and counts are hashes and integers; no source row, chunk
/// body, or bearer material ever appears.
pub(crate) async fn append_run_audit(
    transaction: &tokio_postgres::Transaction<'_>,
    profile: &AuditProfile,
    record: Value,
) -> Result<(), IngestionStoreError> {
    crate::audit::append_envelope(transaction, profile, record)
        .await
        .map_err(|_| IngestionStoreError::Unavailable)
}

/// The canonical lifecycle record for one run transition.
pub(crate) fn run_audit_record(
    outcome: &str,
    run: &IngestionRunRecord,
    package_revision: &str,
    principal_reference: &str,
    correlation: Option<&str>,
) -> Value {
    let mut record = json!({
        "kind": "ingestionRun",
        "phase": "terminal",
        "outcome": outcome,
        "runId": run.run_id.to_string(),
        "packageRevision": package_revision,
        "entityId": run.entity_id,
        "operation": run.operation,
        "selectedAccessProfile": run.profile_id,
        "principalReference": principal_reference,
        "committedItems": run.committed_items,
        "nextChunkIndex": run.next_chunk_index,
        "status": run.status.as_str(),
    });
    if let Some(correlation) = correlation {
        record["correlation"] = json!(correlation);
    }
    record
}

/// The value-free disclosure record for one retained receipt release: a
/// replay and a recovery both release the stored batch answer a second
/// time, so both owe the journal a record of that disclosure, never the
/// answer itself.
pub(crate) fn receipt_disclosure_record(
    run: &IngestionRunRecord,
    chunk_index: i64,
    principal_reference: &str,
    correlation: Option<&str>,
) -> Value {
    let mut record = json!({
        "kind": "ingestionReceipt",
        "phase": "disclosure",
        "runId": run.run_id.to_string(),
        "chunkIndex": chunk_index,
        "packageRevision": run.package_revision,
        "entityId": run.entity_id,
        "operation": run.operation,
        "selectedAccessProfile": run.profile_id,
        "principalReference": principal_reference,
        "status": run.status.as_str(),
    });
    if let Some(correlation) = correlation {
        record["correlation"] = json!(correlation);
    }
    record
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_receipt_ceiling_is_the_idempotency_response_ceiling() {
        // A batch answer the coordinator accepts into the idempotency cache
        // must also persist as its chunk receipt; a smaller receipt ceiling
        // would roll a valid chunk back after commit-time acceptance.
        assert_eq!(MAX_RECEIPT_BYTES, crate::idempotency::MAX_HELD_BODY_BYTES);
    }

    fn run() -> NewIngestionRun {
        NewIngestionRun {
            created_principal_reference: "principal-reference".to_owned(),
            package_revision: "revision-1".to_owned(),
            schema_fingerprint: "fingerprint-1".to_owned(),
            entity_id: "installation".to_owned(),
            operation: "create".to_owned(),
            profile_id: "facility-operator".to_owned(),
            bound_context_reference: "context-reference".to_owned(),
            input_digest: "a".repeat(64),
            input_length: 640,
            item_count: 5,
            chunk_count: 2,
            chunk_algorithm_version: "greedy-canonical-http-batch-v1".to_owned(),
            maximum_items: 4,
            maximum_bytes: 262_144,
        }
    }

    #[test]
    fn a_consistent_run_binding_is_accepted() {
        assert_eq!(validate_new_run(&run()), Ok(()));
    }

    #[test]
    fn an_inconsistent_chunk_count_is_refused() {
        // Five items with four per chunk need two chunks; one is refused.
        let mut binding = run();
        binding.chunk_count = 1;
        assert_eq!(
            validate_new_run(&binding),
            Err(IngestionStoreError::InvalidInput)
        );
        // More chunks than items is refused the other way.
        let mut binding = run();
        binding.chunk_count = 6;
        assert_eq!(
            validate_new_run(&binding),
            Err(IngestionStoreError::InvalidInput)
        );
    }

    #[test]
    fn an_item_count_near_the_maximum_still_requires_its_minimum_chunk_count() {
        // The minimum chunk count must stay checkable when the announced
        // item count approaches i64::MAX; the ceiling arithmetic must not
        // overflow while refusing one chunk for the whole input.
        let mut binding = run();
        binding.item_count = i64::MAX;
        binding.input_length = i64::MAX;
        binding.chunk_count = 1;
        assert_eq!(
            validate_new_run(&binding),
            Err(IngestionStoreError::InvalidInput)
        );
    }

    #[test]
    fn the_exact_minimum_chunk_count_boundary_is_accepted() {
        // Two hundred items with one hundred per chunk need exactly two
        // chunks; the boundary count is accepted and one below is refused.
        let mut binding = run();
        binding.item_count = 200;
        binding.maximum_items = 100;
        binding.chunk_count = 2;
        assert_eq!(validate_new_run(&binding), Ok(()));
        binding.chunk_count = 1;
        assert_eq!(
            validate_new_run(&binding),
            Err(IngestionStoreError::InvalidInput)
        );
    }

    #[test]
    fn a_malformed_input_digest_is_refused() {
        let mut binding = run();
        binding.input_digest = "A".repeat(64);
        assert_eq!(
            validate_new_run(&binding),
            Err(IngestionStoreError::InvalidInput)
        );
        let mut binding = run();
        binding.input_digest = "a".repeat(63);
        assert_eq!(
            validate_new_run(&binding),
            Err(IngestionStoreError::InvalidInput)
        );
    }

    #[test]
    fn an_open_run_reports_blocked_once_the_active_package_changed() {
        let record = IngestionRunRecord {
            run_id: Uuid::new_v4(),
            created_principal_reference: "principal-reference".to_owned(),
            package_revision: "revision-1".to_owned(),
            schema_fingerprint: "fingerprint-1".to_owned(),
            entity_id: "installation".to_owned(),
            operation: "create".to_owned(),
            profile_id: "facility-operator".to_owned(),
            bound_context_reference: "context-reference".to_owned(),
            input_digest: "a".repeat(64),
            input_length: 640,
            item_count: 5,
            chunk_count: 2,
            chunk_algorithm_version: "greedy-canonical-http-batch-v1".to_owned(),
            maximum_items: 4,
            maximum_bytes: 262_144,
            status: IngestionRunStatus::Open,
            blocked_reason: None,
            next_chunk_index: 1,
            committed_items: 4,
            committed_prefix_digest: "b".repeat(64),
            last_attempt_outcome: Some(IngestionAttemptOutcome::Committed),
            last_attempt_chunk_index: Some(0),
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        assert_eq!(
            record.reported_status("revision-1", "fingerprint-1"),
            IngestionRunStatus::Open
        );
        assert_eq!(
            record.reported_status("revision-2", "fingerprint-1"),
            IngestionRunStatus::Blocked
        );
        let rendered = record.response_json("revision-2", "fingerprint-1");
        assert_eq!(rendered["status"], "blocked");
        assert_eq!(rendered["blockedReason"], "activePackageChanged");
        assert_eq!(rendered["nextChunkIndex"], 1);
    }

    #[test]
    fn a_receipt_without_record_links_is_refused() {
        let commit = IngestionChunkCommit {
            run_id: Uuid::new_v4(),
            chunk_index: 0,
            chunk_digest: "a".repeat(64),
            prefix_digest: "b".repeat(64),
            item_count: 1,
            end_item: 1,
            receipt: br#"{"snapshot":"ref"}"#.to_vec(),
            receipt_field_bindings: "{}".to_owned(),
        };
        assert_eq!(
            receipt_records(&commit.receipt),
            None,
            "a receipt without results carries no record links and is refused"
        );
    }

    fn bindings_registry() -> crate::model::CompiledRegistry {
        let fixture = r#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"bindings-test","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "entities":[{
            "id":"entry","primaryDataset":"test-dataset","route":"entries","mutationMode":"mutable","classification":"internal",
            "fields":[
              {"id":"tenant","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"},
              {"id":"serial-code","apiName":"serialNumber","type":"string","maxLength":64,"classification":"internal"}
            ]
          }],
          "accessProfiles":[{
            "id":"operator","default":true,"principalClaim":"registry_principal",
            "requiredPurposes":["review"],
            "permissions":[{
              "entity":"entry","operations":["create"],
              "readableFields":["tenant","serial-code"],
              "writableFields":["tenant","serial-code"],
              "rowBoundaries":[]
            }]
          }]
        }"#;
        let project =
            crate::contract::parse_project_json(fixture.as_bytes()).expect("the fixture parses");
        crate::compiler::compile_project(&project, &[], crate::compiler::CompileProfile::Authoring)
            .expect("the fixture compiles")
    }

    #[test]
    fn a_receipt_derives_the_field_identities_its_members_were_committed_under() {
        let registry = bindings_registry();
        let entity = registry.entities().get("entry").expect("fixture entity");
        let receipt = br#"{"results":[
            {"id":"11111111-1111-4111-8111-111111111111","revision":1,
             "data":{"serialNumber":"SN-1","tenant":"a"}}]}"#;
        let bindings = receipt_field_bindings(entity, receipt).expect("the map derives");
        assert_eq!(
            bindings, r#"{"serialNumber":"serial-code","tenant":"tenant"}"#,
            "each member binds to the logical field id that produced it"
        );
        assert_eq!(
            parse_field_bindings(&bindings).expect("the derived map parses"),
            std::collections::BTreeMap::from([
                ("serialNumber".to_owned(), "serial-code".to_owned()),
                ("tenant".to_owned(), "tenant".to_owned()),
            ])
        );
    }

    #[test]
    fn a_member_the_entity_does_not_store_refuses_the_derivation() {
        let registry = bindings_registry();
        let entity = registry.entities().get("entry").expect("fixture entity");
        assert_eq!(
            receipt_field_bindings(
                entity,
                br#"{"results":[{"id":"11111111-1111-4111-8111-111111111111",
                     "revision":1,"data":{"ghost":"x"}}]}"#,
            ),
            None,
            "a member no stored field produces cannot be bound"
        );
        assert_eq!(
            receipt_field_bindings(entity, br#"{"snapshot":"ref"}"#),
            None,
            "an answer without results carries no members to bind"
        );
    }

    #[test]
    fn a_field_bindings_map_parses_strictly() {
        assert_eq!(
            parse_field_bindings(r#"{"serialNumber":"serial-code"}"#),
            Some(std::collections::BTreeMap::from([(
                "serialNumber".to_owned(),
                "serial-code".to_owned()
            )]))
        );
        assert_eq!(parse_field_bindings("{"), None, "malformed JSON refuses");
        assert_eq!(
            parse_field_bindings(r#"["serialNumber"]"#),
            None,
            "a non-object refuses"
        );
        assert_eq!(
            parse_field_bindings(r#"{"serialNumber":7}"#),
            None,
            "a non-string field id refuses"
        );
        assert_eq!(
            parse_field_bindings(r#"{"":"serial-code"}"#),
            None,
            "an empty member name refuses"
        );
        assert_eq!(
            parse_field_bindings(r#"{"serialNumber":""}"#),
            None,
            "an empty field id refuses"
        );
    }

    #[test]
    fn an_empty_prefix_digest_matches_the_sha256_of_nothing() {
        assert_eq!(
            empty_digest_hex(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }
}
