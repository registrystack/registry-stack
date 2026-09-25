// SPDX-License-Identifier: Apache-2.0

//! BReg-owned historical erasure maintenance for retained record history.
//!
//! This is intentionally one bounded maintenance path, not a retention-policy
//! framework. It erases retained journal bytes for one record through a caller
//! supplied revision, scrubs shared correction context for every affected
//! commit, preserves minimal commit stubs, and shrinks global history coverage
//! so old snapshot bookmarks cannot reconstruct erased bytes.
//!
//! Operators remain responsible for saved exports, downstream consumers that
//! already received event payloads, and database backup lifecycle. This path
//! records that responsibility in the maintenance audit entry; it does not
//! claim automatic deletion outside this database.

use std::fmt;

use registry_platform_audit::AuditEntry;
use serde_json::{json, Value};
use tokio_postgres::Client;
use uuid::Uuid;

use crate::audit::RegistryAudit;
use crate::history_commit::{lock_history_head, HistoryCommitError};
use crate::history_maintenance::{
    append_maintenance_entries, profile_is_keyed, set_local_timeouts, verify_ready_identity,
    HistoryMaintenanceError,
};
use crate::idempotency::{tombstone_erased_cached_responses, IdempotencyError};
use crate::postgres::{
    verify_migration_role, ConnectionConfig, ExpectedRegistryIdentity, PostgresKernelError,
    RegistryLockKey, SqlIdentifier,
};

pub use crate::history_maintenance::HistoryMaintenanceTimeouts as HistoryErasureTimeouts;

const MAX_ENTITY_ID_BYTES: usize = 256;
const MAX_OPERATOR_REFERENCE_BYTES: usize = 512;
const MAX_REASON_BYTES: usize = 1024;
pub(crate) const MAX_ERASURE_REVISIONS: i64 = 10_000;
const AUDIT_OPERATION_ID: &str = "history-erasure-maintenance";
/// The audit schema of the per-record history erasure entry.
pub const HISTORY_ERASURE_AUDIT_SCHEMA: &str = "breg-history-erasure-audit/v2";

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

pub struct HistoryErasureRequest<'a> {
    pub expected: &'a ExpectedRegistryIdentity,
    pub migration_role: &'a SqlIdentifier,
    pub lock_key: RegistryLockKey,
    pub timeouts: HistoryErasureTimeouts,
    pub audit: &'a RegistryAudit,
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
    pub scrubbed_ingestion_receipt_count: u64,
    pub scrubbed_request_target_count: u64,
    pub scrubbed_request_proposal_count: u64,
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
    #[error("history erasure found a cached response no JSON reader accepts")]
    CachedResponseUnreadable,
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
        Self::from(HistoryMaintenanceError::from(error))
    }
}

impl From<HistoryMaintenanceError> for HistoryErasureError {
    fn from(error: HistoryMaintenanceError) -> Self {
        match error {
            HistoryMaintenanceError::InvalidInput => Self::InvalidInput,
            HistoryMaintenanceError::MigrationAuthority => Self::MigrationAuthority,
            HistoryMaintenanceError::Unavailable => Self::Unavailable,
        }
    }
}

impl From<IdempotencyError> for HistoryErasureError {
    fn from(error: IdempotencyError) -> Self {
        match error {
            IdempotencyError::InvalidInput => Self::InvalidInput,
            IdempotencyError::CachedResponseUnreadable => Self::CachedResponseUnreadable,
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
/// the commit-head row, preserving the runtime lock order. The erasure's
/// `request` entry is accepted before the transaction opens, and its
/// `response` entry is appended after the transaction commits.
pub async fn erase_record_history(
    client: &mut Client,
    request: HistoryErasureRequest<'_>,
) -> Result<HistoryErasureOutcome, HistoryErasureError> {
    erase_record_history_scoped(client, request, None).await
}

/// Run the ordinary bounded erasure while correlating its audit entry and its
/// durable lifecycle progress to a parent maintenance lifecycle. The public generic erasure API remains
/// unscoped; only product-owned compound maintenance uses this marker.
pub(crate) async fn erase_record_history_for_lifecycle(
    client: &mut Client,
    request: HistoryErasureRequest<'_>,
    lifecycle_reference: &str,
) -> Result<HistoryErasureOutcome, HistoryErasureError> {
    if lifecycle_reference.is_empty() {
        return Err(HistoryErasureError::InvalidInput);
    }
    erase_record_history_scoped(client, request, Some(lifecycle_reference)).await
}

async fn erase_record_history_scoped(
    client: &mut Client,
    request: HistoryErasureRequest<'_>,
    lifecycle_reference: Option<&str>,
) -> Result<HistoryErasureOutcome, HistoryErasureError> {
    validate_request(&request)?;
    verify_migration_role(client, request.migration_role).await?;
    // A standalone erasure's request entry is accepted before its
    // transaction opens, so an audit outage erases nothing. A lifecycle
    // erasure runs under the request entry its parent lifecycle appended.
    if lifecycle_reference.is_none() {
        append_maintenance_entries(
            request.audit,
            vec![history_erasure_request_entry(&request)?],
        )
        .await?;
    }

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
        lifecycle_reference.is_some(),
    )?;

    let scrubbed_cached_response_count = tombstone_erased_cached_responses(
        &transaction,
        request.target.entity_id,
        request.target.record_id,
        request.target.erase_through_revision,
        &affected_positions,
    )
    .await?;
    let scrubbed_ingestion_receipt_count = crate::ingestion_store::scrub_receipts_for_records(
        &transaction,
        request.target.entity_id,
        request.target.record_id,
        request.target.erase_through_revision,
    )
    .await
    .map_err(|_| HistoryErasureError::Unavailable)?;
    let scrubbed_outbox_payload_count =
        scrub_outbox_payloads(&transaction, &request.target).await?;
    // Change-request proposals and target snapshots are workflow records, not
    // retained record history. Generic record-history erasure deliberately
    // preserves them; field-encryption erase-and-rebaseline has its own
    // narrowly scoped scrub for plaintext copies created before the flip.
    let scrubbed_request_target_count = 0;
    let scrubbed_request_proposal_count = 0;
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
        scrubbed_ingestion_receipt_count,
        scrubbed_request_target_count,
        scrubbed_request_proposal_count,
        removed_descriptor_count,
    };
    let entry = history_erasure_entry(&request, &outcome, lifecycle_reference)?;
    match lifecycle_reference {
        Some(lifecycle_reference) => {
            record_lifecycle_erasure_progress(
                &transaction,
                &request,
                lifecycle_reference,
                &outcome,
            )
            .await?;
        }
        None => record_standalone_erasure_coverage(&transaction, &outcome).await?,
    }
    transaction
        .commit()
        .await
        .map_err(|_| HistoryErasureError::Unavailable)?;
    append_maintenance_entries(request.audit, vec![entry]).await?;
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
    lifecycle_scoped: bool,
) -> Result<CoverageUpdate, HistoryErasureError> {
    // A lifecycle erasure is never a recorded standalone erasure, so it must
    // not leave coverage ready for the successor interlock to admit.
    if !current_ready || has_unindexed_revisions || lifecycle_scoped {
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

/// Record the coverage a standalone erasure left ready, in the same commit as
/// the erasure. A successor apply admits a ready head with an unavailable
/// position only when this row names that position; a lifecycle erasure
/// records no row, so it still freezes successors until a rebaseline.
async fn record_standalone_erasure_coverage(
    transaction: &tokio_postgres::Transaction<'_>,
    outcome: &HistoryErasureOutcome,
) -> Result<(), HistoryErasureError> {
    let (true, Some(unavailable_after_position)) =
        (outcome.coverage_ready, outcome.unavailable_after_position)
    else {
        return Ok(());
    };
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_history_erasure_coverage
                    (unavailable_after_position)
             VALUES ($1)
             ON CONFLICT (unavailable_after_position) DO NOTHING",
            &[&unavailable_after_position],
        )
        .await
        .map_err(|_| HistoryErasureError::Unavailable)?;
    Ok(())
}

/// Record one lifecycle-correlated erasure's counts, in the same commit as the
/// erasure, so the closing lifecycle step aggregates durable state rather
/// than audit output.
async fn record_lifecycle_erasure_progress(
    transaction: &tokio_postgres::Transaction<'_>,
    request: &HistoryErasureRequest<'_>,
    lifecycle_reference: &str,
    outcome: &HistoryErasureOutcome,
) -> Result<(), HistoryErasureError> {
    let target_record_reference = lifecycle_target_record_reference(request)?;
    let count = |value: u64| i64::try_from(value).map_err(|_| HistoryErasureError::Unavailable);
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_field_encryption_lifecycle_progress
                    (lifecycle_reference, progress_kind, target_record_reference,
                     erased_revision_count, erased_commit_member_count,
                     scrubbed_change_context_count, scrubbed_outbox_payload_count,
                     scrubbed_cached_response_count, removed_descriptor_count)
             VALUES ($1, 'record-erasure', $2, $3, $4, $5, $6, $7, $8)",
            &[
                &lifecycle_reference,
                &target_record_reference,
                &count(outcome.erased_revision_count)?,
                &count(outcome.erased_commit_member_count)?,
                &count(outcome.scrubbed_change_context_count)?,
                &count(outcome.scrubbed_outbox_payload_count)?,
                &count(outcome.scrubbed_cached_response_count)?,
                &count(outcome.removed_descriptor_count)?,
            ],
        )
        .await
        .map_err(|_| HistoryErasureError::Unavailable)?;
    Ok(())
}

fn lifecycle_target_record_reference(
    request: &HistoryErasureRequest<'_>,
) -> Result<String, HistoryErasureError> {
    request
        .audit
        .profile()
        .key_hasher()
        .audit_reference_hash(
            "breg-history-erasure-target-record-v1",
            &request.expected.package_revision,
            &format!("{}:{}", request.target.entity_id, request.target.record_id),
        )
        .map_err(|_| HistoryErasureError::InvalidInput)
}

/// The keyed operator, target, and reason references one erasure's entries
/// carry instead of the values they name.
struct ErasureReferences {
    operator: String,
    target: String,
    reason: String,
}

fn erasure_references(
    request: &HistoryErasureRequest<'_>,
) -> Result<ErasureReferences, HistoryErasureError> {
    if !profile_is_keyed(request.audit.profile()) {
        return Err(HistoryErasureError::InvalidInput);
    }
    let key_hasher = request.audit.profile().key_hasher();
    let operator = key_hasher
        .audit_reference_hash(
            "breg-history-erasure-operator-v1",
            &request.expected.package_revision,
            request.operator_reference,
        )
        .map_err(|_| HistoryErasureError::InvalidInput)?;
    let target = key_hasher
        .audit_reference_hash(
            "breg-history-erasure-target-v1",
            &request.expected.package_revision,
            &format!(
                "{}:{}:{}",
                request.target.entity_id,
                request.target.record_id,
                request.target.erase_through_revision
            ),
        )
        .map_err(|_| HistoryErasureError::InvalidInput)?;
    let reason = key_hasher
        .audit_reference_hash(
            "breg-history-erasure-reason-v1",
            &request.expected.package_revision,
            request.reason,
        )
        .map_err(|_| HistoryErasureError::InvalidInput)?;
    Ok(ErasureReferences {
        operator,
        target,
        reason,
    })
}

/// Build a standalone erasure's `request` entry, correlated by its keyed
/// target reference as its `response` entry is. It names only the references
/// that response entry already records.
fn history_erasure_request_entry(
    request: &HistoryErasureRequest<'_>,
) -> Result<AuditEntry, HistoryErasureError> {
    let references = erasure_references(request)?;
    Ok(AuditEntry::request(
        HISTORY_ERASURE_AUDIT_SCHEMA,
        references.target.clone(),
        json!({
            "phase": "attempt",
            "outcome": "started",
            "operationId": AUDIT_OPERATION_ID,
            "packageRevision": request.expected.package_revision,
            "operatorReference": references.operator,
            "targetReference": references.target,
            "reasonReference": references.reason,
        }),
    ))
}

/// Build the erasure's `response` entry, correlated by the parent lifecycle
/// reference or, for a standalone erasure, by its keyed target reference.
fn history_erasure_entry(
    request: &HistoryErasureRequest<'_>,
    outcome: &HistoryErasureOutcome,
    lifecycle_reference: Option<&str>,
) -> Result<AuditEntry, HistoryErasureError> {
    let ErasureReferences {
        operator: operator_reference,
        target: target_reference,
        reason: reason_reference,
    } = erasure_references(request)?;
    let mut record = json!({
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
        "scrubbedIngestionReceiptCount": outcome.scrubbed_ingestion_receipt_count,
        "scrubbedRequestTargetCount": outcome.scrubbed_request_target_count,
        "scrubbedRequestProposalCount": outcome.scrubbed_request_proposal_count,
        "removedDescriptorCount": outcome.removed_descriptor_count,
        "operatorResponsibility": "saved_exports_event_consumers_and_backups",
        "stubPolicy": "commit_position_and_minimized_origin_retained_context_removed",
    });
    let correlation = lifecycle_reference
        .map_or_else(|| target_reference.clone(), std::borrow::ToOwned::to_owned);
    if let Some(lifecycle_reference) = lifecycle_reference {
        let object = record
            .as_object_mut()
            .ok_or(HistoryErasureError::Unavailable)?;
        let target_record_reference = lifecycle_target_record_reference(request)?;
        object.insert(
            "lifecycleReference".to_owned(),
            Value::String(lifecycle_reference.to_owned()),
        );
        object.insert(
            "targetRecordReference".to_owned(),
            Value::String(target_record_reference),
        );
    }
    Ok(AuditEntry::response(
        HISTORY_ERASURE_AUDIT_SCHEMA,
        correlation,
        record,
    ))
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
        || !profile_is_keyed(request.audit.profile())
    {
        return Err(HistoryErasureError::InvalidInput);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const STANDALONE: bool = false;
    const LIFECYCLE: bool = true;

    #[test]
    fn standalone_erasure_after_the_baseline_narrows_ready_coverage() {
        assert_eq!(
            coverage_update_for_erasure(true, 0, None, false, Some(2), STANDALONE)
                .expect("coverage update"),
            CoverageUpdate {
                coverage_ready: true,
                unavailable_after_position: Some(1),
            }
        );
        assert_eq!(
            coverage_update_for_erasure(true, 0, Some(1), false, Some(5), STANDALONE)
                .expect("coverage update"),
            CoverageUpdate {
                coverage_ready: true,
                unavailable_after_position: Some(1),
            },
            "an earlier boundary is never widened"
        );
    }

    #[test]
    fn erasure_at_or_before_the_baseline_leaves_coverage_not_ready() {
        assert_eq!(
            coverage_update_for_erasure(true, 3, None, false, Some(3), STANDALONE)
                .expect("coverage update"),
            CoverageUpdate {
                coverage_ready: false,
                unavailable_after_position: None,
            }
        );
    }

    #[test]
    fn not_ready_coverage_or_unindexed_revisions_stay_not_ready() {
        for (ready, unindexed) in [(false, false), (true, true)] {
            assert_eq!(
                coverage_update_for_erasure(ready, 0, Some(4), unindexed, Some(6), STANDALONE)
                    .expect("coverage update"),
                CoverageUpdate {
                    coverage_ready: false,
                    unavailable_after_position: Some(4),
                }
            );
        }
    }

    #[test]
    fn lifecycle_erasure_never_leaves_coverage_ready() {
        assert_eq!(
            coverage_update_for_erasure(true, 0, Some(4), false, Some(2), LIFECYCLE)
                .expect("coverage update"),
            CoverageUpdate {
                coverage_ready: false,
                unavailable_after_position: Some(4),
            }
        );
    }
}
