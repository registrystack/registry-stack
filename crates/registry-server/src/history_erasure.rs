// SPDX-License-Identifier: Apache-2.0

//! Server-owned historical erasure maintenance for retained record history.
//!
//! This is intentionally one bounded maintenance path, not a retention-policy
//! framework. It erases retained journal bytes for one record through a caller
//! supplied revision, scrubs shared correction context for every affected
//! commit, preserves minimal commit stubs, and shrinks global history coverage
//! so old snapshot bookmarks cannot reconstruct erased bytes.
//!
//! Operators remain responsible for saved exports, downstream consumers that
//! already received event payloads, and database backup lifecycle. This path
//! records that responsibility in the maintenance audit record; it does not
//! claim automatic deletion outside this database.

use std::{fmt, time::Duration};

use registry_platform_audit::{AuditChainHasher, AuditEnvelope, AuditKeyHasher, AuditProfile};
use registry_platform_canonical_json::canonicalize_json;
use serde_json::{json, Value};
use tokio_postgres::Client;
use uuid::Uuid;

use crate::history_commit::{lock_history_head, HistoryCommitError};
use crate::idempotency::{tombstone_erased_cached_responses, IdempotencyError};
use crate::postgres::{
    verify_migration_role, ConnectionConfig, ExpectedRegistryIdentity, PostgresKernelError,
    RegistryLockKey, SqlIdentifier,
};

const MAX_ENTITY_ID_BYTES: usize = 256;
const MAX_OPERATOR_REFERENCE_BYTES: usize = 512;
const MAX_REASON_BYTES: usize = 1024;
const MAX_ERASURE_REVISIONS: i64 = 10_000;
const MAX_LOCK_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_STATEMENT_TIMEOUT: Duration = Duration::from_secs(60 * 60);
const AUDIT_OPERATION_ID: &str = "history-erasure-maintenance";

#[derive(Clone, Eq, PartialEq)]
pub struct RecordHistoryErasureTarget<'a> {
    entity_id: &'a str,
    record_id: Uuid,
    erase_through_revision: i64,
}

impl fmt::Debug for RecordHistoryErasureTarget<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RecordHistoryErasureTarget")
            .field("entity_id", &self.entity_id)
            .field("record_id", &"<redacted>")
            .field("erase_through_revision", &self.erase_through_revision)
            .finish()
    }
}

impl<'a> RecordHistoryErasureTarget<'a> {
    #[must_use]
    pub fn new(entity_id: &'a str, record_id: Uuid, erase_through_revision: i64) -> Self {
        Self {
            entity_id,
            record_id,
            erase_through_revision,
        }
    }
}

#[derive(Clone, Copy)]
pub struct HistoryErasureTimeouts {
    lock: Duration,
    statement: Duration,
}

impl HistoryErasureTimeouts {
    pub fn new(lock: Duration, statement: Duration) -> Result<Self, HistoryErasureError> {
        if lock.is_zero()
            || lock > MAX_LOCK_TIMEOUT
            || statement.is_zero()
            || statement > MAX_STATEMENT_TIMEOUT
        {
            return Err(HistoryErasureError::InvalidInput);
        }
        Ok(Self { lock, statement })
    }
}

pub struct HistoryErasureRequest<'a> {
    pub expected: &'a ExpectedRegistryIdentity,
    pub migration_role: &'a SqlIdentifier,
    pub lock_key: RegistryLockKey,
    pub timeouts: HistoryErasureTimeouts,
    pub audit_profile: &'a AuditProfile,
    pub operator_reference: &'a str,
    pub reason: &'a str,
    pub target: RecordHistoryErasureTarget<'a>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryErasureOutcome {
    pub coverage_ready: bool,
    pub unavailable_after_position: Option<i64>,
    pub affected_commit_count: u64,
    pub erased_revision_count: u64,
    pub erased_commit_member_count: u64,
    pub scrubbed_change_context_count: u64,
    pub scrubbed_outbox_payload_count: u64,
    pub scrubbed_cached_response_count: u64,
    pub removed_descriptor_count: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HistoryErasureError {
    #[error("history erasure input is invalid")]
    InvalidInput,
    #[error("history erasure requires the configured migration authority")]
    MigrationAuthority,
    #[error("history erasure found no retained target history")]
    TargetUnavailable,
    #[error("history erasure cannot run while history coverage is not ready")]
    HistoryNotReady,
    #[error("history erasure storage is unavailable")]
    Unavailable,
}

impl From<HistoryCommitError> for HistoryErasureError {
    fn from(error: HistoryCommitError) -> Self {
        match error {
            HistoryCommitError::InvalidInput => Self::InvalidInput,
            HistoryCommitError::NotReady => Self::HistoryNotReady,
            HistoryCommitError::UnknownReference
            | HistoryCommitError::WrongLineage
            | HistoryCommitError::FutureReference
            | HistoryCommitError::Unavailable => Self::Unavailable,
        }
    }
}

impl From<PostgresKernelError> for HistoryErasureError {
    fn from(error: PostgresKernelError) -> Self {
        match error {
            PostgresKernelError::RoleInvariant(_) => Self::MigrationAuthority,
            PostgresKernelError::Configuration(_) => Self::InvalidInput,
            PostgresKernelError::Connection
            | PostgresKernelError::Pool
            | PostgresKernelError::PoolBuild
            | PostgresKernelError::CatalogInvariant(_)
            | PostgresKernelError::RegistryUnavailable => Self::Unavailable,
        }
    }
}

impl From<IdempotencyError> for HistoryErasureError {
    fn from(error: IdempotencyError) -> Self {
        match error {
            IdempotencyError::InvalidInput => Self::InvalidInput,
            IdempotencyError::Conflict | IdempotencyError::Unavailable => Self::Unavailable,
        }
    }
}

/// Open the configured migration connection, verify the configured role, and
/// run the bounded erasure transaction under the Registry maintenance lock.
pub async fn erase_record_history_with_connection(
    connection: &ConnectionConfig,
    request: HistoryErasureRequest<'_>,
) -> Result<HistoryErasureOutcome, HistoryErasureError> {
    let pool = connection.build_pool()?;
    let mut client = pool
        .get()
        .await
        .map_err(|_| HistoryErasureError::Unavailable)?;
    erase_record_history(&mut client, request).await
}

/// Run one targeted historical erasure through an already opened migration
/// connection. The transaction uses the exclusive Registry advisory lock, then
/// the commit-head row, then the audit head, preserving the runtime lock order.
pub async fn erase_record_history(
    client: &mut Client,
    request: HistoryErasureRequest<'_>,
) -> Result<HistoryErasureOutcome, HistoryErasureError> {
    validate_request(&request)?;
    verify_migration_role(client, request.migration_role).await?;

    let transaction = client
        .transaction()
        .await
        .map_err(|_| HistoryErasureError::Unavailable)?;
    set_local_timeouts(&transaction, request.timeouts).await?;
    transaction
        .execute(
            "SELECT pg_catalog.pg_advisory_xact_lock($1)",
            &[&request.lock_key.get()],
        )
        .await
        .map_err(|_| HistoryErasureError::Unavailable)?;
    verify_ready_identity(&transaction, request.expected).await?;

    let head = lock_history_head(&transaction).await?;
    let summary = target_revision_summary(&transaction, &request.target).await?;
    let affected_positions = affected_commit_positions(&transaction, &request.target).await?;
    let coverage_update = coverage_update_for_erasure(
        head.coverage_ready,
        head.coverage_baseline_position,
        head.unavailable_after_position,
        summary.has_unindexed_revisions,
        affected_positions.first().copied(),
    )?;

    let scrubbed_cached_response_count = tombstone_erased_cached_responses(
        &transaction,
        request.target.entity_id,
        request.target.record_id,
        request.target.erase_through_revision,
        &affected_positions,
    )
    .await?;
    let scrubbed_outbox_payload_count =
        scrub_outbox_payloads(&transaction, &request.target).await?;
    let scrubbed_change_context_count =
        scrub_change_contexts(&transaction, &affected_positions).await?;
    let erased_commit_member_count = delete_commit_members(&transaction, &request.target).await?;
    let erased_revision_count = delete_revisions(&transaction, &request.target).await?;
    let removed_descriptor_count =
        delete_unreferenced_history_descriptors(&transaction, request.expected).await?;
    update_coverage(&transaction, coverage_update).await?;

    let outcome = HistoryErasureOutcome {
        coverage_ready: coverage_update.coverage_ready,
        unavailable_after_position: coverage_update.unavailable_after_position,
        affected_commit_count: u64::try_from(affected_positions.len())
            .map_err(|_| HistoryErasureError::Unavailable)?,
        erased_revision_count,
        erased_commit_member_count,
        scrubbed_change_context_count,
        scrubbed_outbox_payload_count,
        scrubbed_cached_response_count,
        removed_descriptor_count,
    };
    append_history_erasure_audit(&transaction, &request, &outcome).await?;
    transaction
        .commit()
        .await
        .map_err(|_| HistoryErasureError::Unavailable)?;
    Ok(outcome)
}

async fn affected_commit_positions(
    transaction: &tokio_postgres::Transaction<'_>,
    target: &RecordHistoryErasureTarget<'_>,
) -> Result<Vec<i64>, HistoryErasureError> {
    let rows = transaction
        .query(
            "SELECT DISTINCT commit_position
               FROM registry_internal.registry_revision_commit_members
              WHERE entity_id = $1
                AND record_id = $2
                AND record_revision <= $3
              ORDER BY commit_position",
            &[
                &target.entity_id,
                &target.record_id,
                &target.erase_through_revision,
            ],
        )
        .await
        .map_err(|_| HistoryErasureError::Unavailable)?;
    Ok(rows.into_iter().map(|row| row.get(0)).collect())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct TargetRevisionSummary {
    revision_count: i64,
    has_unindexed_revisions: bool,
}

async fn target_revision_summary(
    transaction: &tokio_postgres::Transaction<'_>,
    target: &RecordHistoryErasureTarget<'_>,
) -> Result<TargetRevisionSummary, HistoryErasureError> {
    let row = transaction
        .query_one(
            "SELECT count(*)::bigint,
                    COALESCE(bool_or(member.commit_position IS NULL), false)
               FROM registry_internal.registry_revisions AS revision
               LEFT JOIN registry_internal.registry_revision_commit_members AS member
                 ON member.entity_id = revision.entity_id
                AND member.record_id = revision.record_id
                AND member.record_revision = revision.record_revision
              WHERE revision.entity_id = $1
                AND revision.record_id = $2
                AND revision.record_revision <= $3",
            &[
                &target.entity_id,
                &target.record_id,
                &target.erase_through_revision,
            ],
        )
        .await
        .map_err(|_| HistoryErasureError::Unavailable)?;
    let summary = TargetRevisionSummary {
        revision_count: row.get(0),
        has_unindexed_revisions: row.get(1),
    };
    if summary.revision_count == 0 {
        return Err(HistoryErasureError::TargetUnavailable);
    }
    if summary.revision_count > MAX_ERASURE_REVISIONS {
        return Err(HistoryErasureError::InvalidInput);
    }
    Ok(summary)
}

async fn scrub_outbox_payloads(
    transaction: &tokio_postgres::Transaction<'_>,
    target: &RecordHistoryErasureTarget<'_>,
) -> Result<u64, HistoryErasureError> {
    transaction
        .execute(
            "UPDATE registry_internal.registry_outbox AS outbox
                SET payload = NULL
              WHERE outbox.payload IS NOT NULL
                AND EXISTS (
                    SELECT 1
                      FROM registry_internal.registry_revisions AS revision
                     WHERE revision.entity_id = $1
                       AND revision.record_id = $2
                       AND revision.record_revision <= $3
                       AND outbox.entity_id = revision.entity_id
                       AND outbox.record_reference = revision.record_reference
                       AND outbox.record_revision = revision.record_revision
                )",
            &[
                &target.entity_id,
                &target.record_id,
                &target.erase_through_revision,
            ],
        )
        .await
        .map_err(|_| HistoryErasureError::Unavailable)
}

async fn scrub_change_contexts(
    transaction: &tokio_postgres::Transaction<'_>,
    affected_positions: &[i64],
) -> Result<u64, HistoryErasureError> {
    transaction
        .execute(
            "UPDATE registry_internal.registry_revision_commits
                SET change_context = NULL, change_context_digest = NULL
              WHERE commit_position = ANY($1::bigint[])
                AND change_context IS NOT NULL",
            &[&affected_positions],
        )
        .await
        .map_err(|_| HistoryErasureError::Unavailable)
}

async fn delete_commit_members(
    transaction: &tokio_postgres::Transaction<'_>,
    target: &RecordHistoryErasureTarget<'_>,
) -> Result<u64, HistoryErasureError> {
    transaction
        .execute(
            "DELETE FROM registry_internal.registry_revision_commit_members
              WHERE entity_id = $1
                AND record_id = $2
                AND record_revision <= $3",
            &[
                &target.entity_id,
                &target.record_id,
                &target.erase_through_revision,
            ],
        )
        .await
        .map_err(|_| HistoryErasureError::Unavailable)
}

async fn delete_revisions(
    transaction: &tokio_postgres::Transaction<'_>,
    target: &RecordHistoryErasureTarget<'_>,
) -> Result<u64, HistoryErasureError> {
    transaction
        .execute(
            "DELETE FROM registry_internal.registry_revisions
              WHERE entity_id = $1
                AND record_id = $2
                AND record_revision <= $3",
            &[
                &target.entity_id,
                &target.record_id,
                &target.erase_through_revision,
            ],
        )
        .await
        .map_err(|_| HistoryErasureError::Unavailable)
}

async fn delete_unreferenced_history_descriptors(
    transaction: &tokio_postgres::Transaction<'_>,
    expected: &ExpectedRegistryIdentity,
) -> Result<u64, HistoryErasureError> {
    transaction
        .execute(
            "DELETE FROM registry_internal.registry_history_schemas AS descriptor
              WHERE descriptor.package_revision <> $1
                AND NOT EXISTS (
                    SELECT 1
                      FROM registry_internal.registry_revisions AS revision
                     WHERE revision.package_revision = descriptor.package_revision
                )",
            &[&expected.package_revision],
        )
        .await
        .map_err(|_| HistoryErasureError::Unavailable)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct CoverageUpdate {
    coverage_ready: bool,
    unavailable_after_position: Option<i64>,
}

fn coverage_update_for_erasure(
    current_ready: bool,
    coverage_baseline_position: i64,
    current_unavailable_after_position: Option<i64>,
    has_unindexed_revisions: bool,
    earliest_affected_position: Option<i64>,
) -> Result<CoverageUpdate, HistoryErasureError> {
    if !current_ready || has_unindexed_revisions {
        return Ok(CoverageUpdate {
            coverage_ready: false,
            unavailable_after_position: current_unavailable_after_position,
        });
    }
    let earliest = earliest_affected_position.ok_or(HistoryErasureError::TargetUnavailable)?;
    if earliest <= coverage_baseline_position {
        return Ok(CoverageUpdate {
            coverage_ready: false,
            unavailable_after_position: current_unavailable_after_position,
        });
    }
    let requested = earliest
        .checked_sub(1)
        .ok_or(HistoryErasureError::InvalidInput)?;
    Ok(CoverageUpdate {
        coverage_ready: true,
        unavailable_after_position: Some(
            current_unavailable_after_position.map_or(requested, |current| current.min(requested)),
        ),
    })
}

async fn update_coverage(
    transaction: &tokio_postgres::Transaction<'_>,
    update: CoverageUpdate,
) -> Result<(), HistoryErasureError> {
    let changed = transaction
        .execute(
            "UPDATE registry_internal.registry_commit_head
                SET coverage_ready = $1,
                    unavailable_after_position = $2,
                    updated_at = transaction_timestamp()
              WHERE singleton
                AND (
                    unavailable_after_position IS NULL
                    OR $2::bigint IS NULL
                    OR unavailable_after_position >= $2
                )",
            &[&update.coverage_ready, &update.unavailable_after_position],
        )
        .await
        .map_err(|_| HistoryErasureError::Unavailable)?;
    if changed != 1 {
        return Err(HistoryErasureError::Unavailable);
    }
    Ok(())
}

async fn verify_ready_identity(
    transaction: &tokio_postgres::Transaction<'_>,
    expected: &ExpectedRegistryIdentity,
) -> Result<(), HistoryErasureError> {
    expected.validate()?;
    let row = transaction
        .query_opt(
            "SELECT package_id, environment, instance_id, database_id,
                    active_package_revision, schema_fingerprint, package_sequence,
                    maintenance_status
               FROM registry_internal.registry_state
              WHERE singleton
              FOR UPDATE",
            &[],
        )
        .await
        .map_err(|_| HistoryErasureError::Unavailable)?
        .ok_or(HistoryErasureError::Unavailable)?;
    let ready = row.get::<_, String>(7) == "ready"
        && row.get::<_, String>(0) == expected.package_id
        && row.get::<_, String>(1) == expected.environment
        && row.get::<_, String>(2) == expected.instance_id
        && row.get::<_, String>(3) == expected.database_id
        && row.get::<_, String>(4) == expected.package_revision
        && row.get::<_, String>(5) == expected.schema_fingerprint
        && row.get::<_, i64>(6) == expected.package_sequence;
    if !ready {
        return Err(HistoryErasureError::Unavailable);
    }
    Ok(())
}

async fn append_history_erasure_audit(
    transaction: &tokio_postgres::Transaction<'_>,
    request: &HistoryErasureRequest<'_>,
    outcome: &HistoryErasureOutcome,
) -> Result<(), HistoryErasureError> {
    if !profile_is_keyed(request.audit_profile) {
        return Err(HistoryErasureError::InvalidInput);
    }
    let key_hasher = request.audit_profile.key_hasher();
    let operator_reference = key_hasher
        .audit_reference_hash(
            "registry-server-history-erasure-operator-v1",
            &request.expected.package_revision,
            request.operator_reference,
        )
        .map_err(|_| HistoryErasureError::InvalidInput)?;
    let target_reference = key_hasher
        .audit_reference_hash(
            "registry-server-history-erasure-target-v1",
            &request.expected.package_revision,
            &format!(
                "{}:{}:{}",
                request.target.entity_id,
                request.target.record_id,
                request.target.erase_through_revision
            ),
        )
        .map_err(|_| HistoryErasureError::InvalidInput)?;
    let reason_reference = key_hasher
        .audit_reference_hash(
            "registry-server-history-erasure-reason-v1",
            &request.expected.package_revision,
            request.reason,
        )
        .map_err(|_| HistoryErasureError::InvalidInput)?;
    append_audit_envelope(
        transaction,
        request.audit_profile,
        json!({
            "schema": "registry-server-history-erasure-audit/v1",
            "phase": "terminal",
            "outcome": "committed",
            "operationId": AUDIT_OPERATION_ID,
            "packageRevision": request.expected.package_revision,
            "operatorReference": operator_reference,
            "targetReference": target_reference,
            "reasonReference": reason_reference,
            "coverageReady": outcome.coverage_ready,
            "unavailableAfterPosition": outcome.unavailable_after_position,
            "affectedCommitCount": outcome.affected_commit_count,
            "erasedRevisionCount": outcome.erased_revision_count,
            "erasedCommitMemberCount": outcome.erased_commit_member_count,
            "scrubbedChangeContextCount": outcome.scrubbed_change_context_count,
            "scrubbedOutboxPayloadCount": outcome.scrubbed_outbox_payload_count,
            "scrubbedCachedResponseCount": outcome.scrubbed_cached_response_count,
            "removedDescriptorCount": outcome.removed_descriptor_count,
            "operatorResponsibility": "saved_exports_event_consumers_and_backups",
            "stubPolicy": "commit_position_and_minimized_origin_retained_context_removed",
        }),
    )
    .await
}

async fn append_audit_envelope(
    transaction: &tokio_postgres::Transaction<'_>,
    profile: &AuditProfile,
    record: Value,
) -> Result<(), HistoryErasureError> {
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_audit_head (singleton, last_hash)
             VALUES (true, NULL)
             ON CONFLICT (singleton) DO NOTHING",
            &[],
        )
        .await
        .map_err(|_| HistoryErasureError::Unavailable)?;
    let row = transaction
        .query_one(
            "SELECT last_hash
               FROM registry_internal.registry_audit_head
              WHERE singleton
              FOR UPDATE",
            &[],
        )
        .await
        .map_err(|_| HistoryErasureError::Unavailable)?;
    let previous = row
        .get::<_, Option<Vec<u8>>>(0)
        .map(|bytes| <[u8; 32]>::try_from(bytes).map_err(|_| HistoryErasureError::Unavailable))
        .transpose()?;
    let envelope = AuditEnvelope::new_with_hasher(record, previous, &profile.chain_hasher())
        .map_err(|_| HistoryErasureError::Unavailable)?;
    let envelope_value =
        serde_json::to_value(&envelope).map_err(|_| HistoryErasureError::Unavailable)?;
    let envelope_bytes =
        canonicalize_json(&envelope_value).map_err(|_| HistoryErasureError::Unavailable)?;
    let changed = transaction
        .execute(
            "INSERT INTO registry_internal.registry_audit
                 (envelope_id, record_hash, envelope)
             VALUES ($1, $2, $3)",
            &[
                &envelope.envelope_id,
                &envelope.record_hash.as_slice(),
                &envelope_bytes,
            ],
        )
        .await
        .map_err(|_| HistoryErasureError::Unavailable)?;
    if changed != 1 {
        return Err(HistoryErasureError::Unavailable);
    }
    let changed = transaction
        .execute(
            "UPDATE registry_internal.registry_audit_head
                SET last_hash = $1
              WHERE singleton",
            &[&envelope.record_hash.as_slice()],
        )
        .await
        .map_err(|_| HistoryErasureError::Unavailable)?;
    if changed != 1 {
        return Err(HistoryErasureError::Unavailable);
    }
    Ok(())
}

async fn set_local_timeouts(
    transaction: &tokio_postgres::Transaction<'_>,
    timeouts: HistoryErasureTimeouts,
) -> Result<(), HistoryErasureError> {
    let lock_millis =
        u64::try_from(timeouts.lock.as_millis()).map_err(|_| HistoryErasureError::InvalidInput)?;
    let statement_millis = u64::try_from(timeouts.statement.as_millis())
        .map_err(|_| HistoryErasureError::InvalidInput)?;
    transaction
        .execute(
            "SELECT set_config('lock_timeout', $1::text, true),
                    set_config('statement_timeout', $2::text, true)",
            &[
                &format!("{lock_millis}ms"),
                &format!("{statement_millis}ms"),
            ],
        )
        .await
        .map_err(|_| HistoryErasureError::Unavailable)?;
    Ok(())
}

fn validate_request(request: &HistoryErasureRequest<'_>) -> Result<(), HistoryErasureError> {
    request.expected.validate()?;
    if request.target.entity_id.is_empty()
        || request.target.entity_id.len() > MAX_ENTITY_ID_BYTES
        || request.target.entity_id.chars().any(char::is_control)
        || request.target.erase_through_revision <= 0
        || request.operator_reference.is_empty()
        || request.operator_reference.len() > MAX_OPERATOR_REFERENCE_BYTES
        || request.operator_reference.chars().any(char::is_control)
        || request.reason.is_empty()
        || request.reason.len() > MAX_REASON_BYTES
        || request.reason.chars().any(char::is_control)
        || !profile_is_keyed(request.audit_profile)
    {
        return Err(HistoryErasureError::InvalidInput);
    }
    Ok(())
}

fn profile_is_keyed(profile: &AuditProfile) -> bool {
    matches!(profile.chain_hasher(), AuditChainHasher::Keyed(_))
        && matches!(profile.key_hasher(), AuditKeyHasher::Keyed(_))
}
