// SPDX-License-Identifier: Apache-2.0

//! Server-owned coverage rebaseline for retained record history.
//!
//! A historical erasure shrinks global snapshot coverage: it marks every
//! position at or after the earliest erased commit unavailable, or clears
//! coverage entirely when it reached the baseline. Nothing in the write path
//! widens coverage again, so `:snapshot` reads of current state stay refused
//! until an operator re-establishes a covered starting position.
//!
//! This is that bounded maintenance path. It resurrects nothing: it proves the
//! retained journal head of every live row still reproduces that row, then
//! installs one baseline commit at the head and moves the coverage baseline to
//! it. References before the new baseline stay refused, because the bytes they
//! named are gone.

use registry_platform_audit::AuditProfile;
use serde_json::json;
use tokio_postgres::Client;

use crate::history_commit::{
    allocate_coverage_baseline_commit, lock_history_head, HistoryCommitError,
};
use crate::history_maintenance::{
    append_audit_envelope, profile_is_keyed, set_local_timeouts, verify_ready_identity,
    HistoryMaintenanceError,
};
use crate::history_migration::{verify_live_rows_match_journal_heads, HistoryMigrationError};
use crate::model::CompiledRegistry;
use crate::postgres::{
    set_force_row_security, verify_migration_role, ConnectionConfig, ExpectedRegistryIdentity,
    PostgresKernelError, RegistryLockKey, SqlIdentifier,
};

pub use crate::history_maintenance::HistoryMaintenanceTimeouts as HistoryRebaselineTimeouts;

const MAX_OPERATOR_REFERENCE_BYTES: usize = 512;
const AUDIT_OPERATION_ID: &str = "history-rebaseline-maintenance";
const BASELINE_SYSTEM_ORIGIN: &str = "registry-server-coverage-rebaseline-v1";

pub struct HistoryRebaselineRequest<'a> {
    pub expected: &'a ExpectedRegistryIdentity,
    pub migration_role: &'a SqlIdentifier,
    pub lock_key: RegistryLockKey,
    pub timeouts: HistoryRebaselineTimeouts,
    pub audit_profile: &'a AuditProfile,
    pub operator_reference: &'a str,
    pub registry: &'a CompiledRegistry,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HistoryRebaselineOutcome {
    pub baseline_position: i64,
    pub verified_entity_count: u64,
    pub verified_record_count: u64,
    pub previous_coverage_baseline_position: i64,
    pub previous_unavailable_after_position: Option<i64>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HistoryRebaselineError {
    #[error("history rebaseline input is invalid")]
    InvalidInput,
    #[error("history rebaseline requires the configured migration authority")]
    MigrationAuthority,
    #[error("history coverage is already complete")]
    CoverageComplete,
    #[error("history rebaseline cannot run before a history baseline exists")]
    HistoryNotReady,
    #[error("history rebaseline requires every retained journal head to be indexed by a commit")]
    UnindexedRevisions,
    #[error("history rebaseline requires the retained journal head to reproduce every live row")]
    LiveHistoryMismatch,
    #[error("history rebaseline exceeds the supported live-row budget")]
    LiveRowBudgetExceeded,
    #[error("history rebaseline storage is unavailable")]
    Unavailable,
}

impl From<HistoryCommitError> for HistoryRebaselineError {
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

impl From<PostgresKernelError> for HistoryRebaselineError {
    fn from(error: PostgresKernelError) -> Self {
        Self::from(HistoryMaintenanceError::from(error))
    }
}

impl From<HistoryMaintenanceError> for HistoryRebaselineError {
    fn from(error: HistoryMaintenanceError) -> Self {
        match error {
            HistoryMaintenanceError::InvalidInput => Self::InvalidInput,
            HistoryMaintenanceError::MigrationAuthority => Self::MigrationAuthority,
            HistoryMaintenanceError::Unavailable => Self::Unavailable,
        }
    }
}

impl From<HistoryMigrationError> for HistoryRebaselineError {
    fn from(error: HistoryMigrationError) -> Self {
        match error {
            HistoryMigrationError::UnexpectedRowShape => Self::LiveHistoryMismatch,
            HistoryMigrationError::BaselineBudgetExceeded => Self::LiveRowBudgetExceeded,
            HistoryMigrationError::UnsupportedObject => Self::InvalidInput,
            _ => Self::Unavailable,
        }
    }
}

/// Open the configured migration connection, verify the configured role, and
/// run the bounded rebaseline transaction under the Registry maintenance lock.
pub async fn rebaseline_history_coverage_with_connection(
    connection: &ConnectionConfig,
    request: HistoryRebaselineRequest<'_>,
) -> Result<HistoryRebaselineOutcome, HistoryRebaselineError> {
    let pool = connection.build_pool()?;
    let mut client = pool
        .get()
        .await
        .map_err(|_| HistoryRebaselineError::Unavailable)?;
    rebaseline_history_coverage(&mut client, request).await
}

/// Re-establish snapshot coverage from the current state through an already
/// opened migration connection. The transaction takes the exclusive Registry
/// advisory lock, then the commit-head row, then the audit head, preserving the
/// runtime lock order the erasure path uses.
pub async fn rebaseline_history_coverage(
    client: &mut Client,
    request: HistoryRebaselineRequest<'_>,
) -> Result<HistoryRebaselineOutcome, HistoryRebaselineError> {
    validate_request(&request)?;
    verify_migration_role(client, request.migration_role).await?;

    let transaction = client
        .transaction()
        .await
        .map_err(|_| HistoryRebaselineError::Unavailable)?;
    set_local_timeouts(&transaction, request.timeouts).await?;
    transaction
        .execute(
            "SELECT pg_catalog.pg_advisory_xact_lock($1)",
            &[&request.lock_key.get()],
        )
        .await
        .map_err(|_| HistoryRebaselineError::Unavailable)?;
    verify_ready_identity(&transaction, request.expected).await?;

    let head = lock_history_head(&transaction).await?;
    if head.coverage_ready && head.unavailable_after_position.is_none() {
        return Err(HistoryRebaselineError::CoverageComplete);
    }
    if has_unindexed_journal_heads(&transaction).await? {
        return Err(HistoryRebaselineError::UnindexedRevisions);
    }

    // Reuse the migration baseline check: it proves the retained journal head
    // of every live row still reproduces that row, so the new baseline vouches
    // only for state the journal already holds. A live registry's journal
    // legitimately spans several package revisions, so no single revision is
    // required of the heads.
    //
    // Entity tables force row-level security on their owner, so the check reads
    // nothing until the migration authority lifts that force for this
    // transaction, exactly as an existing-data migration baseline does. Every
    // other role keeps its policies, and the force is restored before the
    // transaction commits.
    let tables = entity_tables(request.registry);
    set_force_row_security(&transaction, &tables, false).await?;
    let verified =
        verify_live_rows_match_journal_heads(&transaction, request.registry.entities(), None).await;
    set_force_row_security(&transaction, &tables, true).await?;
    let members = verified?;

    // Every retained journal head is already indexed, which the refusal above
    // proved, so the baseline commit carries no member of its own. It is the
    // covered position reconstruction starts from; the members earlier commits
    // hold reproduce the live rows verified here.
    let committed = allocate_coverage_baseline_commit(
        &transaction,
        &head,
        &request.expected.package_revision,
        BASELINE_SYSTEM_ORIGIN,
    )
    .await?;
    let changed = transaction
        .execute(
            "UPDATE registry_internal.registry_commit_head
                SET coverage_baseline_position = $1,
                    coverage_ready = true,
                    unavailable_after_position = NULL,
                    updated_at = transaction_timestamp()
              WHERE singleton",
            &[&committed.position],
        )
        .await
        .map_err(|_| HistoryRebaselineError::Unavailable)?;
    if changed != 1 {
        return Err(HistoryRebaselineError::Unavailable);
    }

    let outcome = HistoryRebaselineOutcome {
        baseline_position: committed.position,
        verified_entity_count: u64::try_from(request.registry.entities().len())
            .map_err(|_| HistoryRebaselineError::Unavailable)?,
        verified_record_count: u64::try_from(members.len())
            .map_err(|_| HistoryRebaselineError::Unavailable)?,
        previous_coverage_baseline_position: head.coverage_baseline_position,
        previous_unavailable_after_position: head.unavailable_after_position,
    };
    append_history_rebaseline_audit(&transaction, &request, &outcome).await?;
    transaction
        .commit()
        .await
        .map_err(|_| HistoryRebaselineError::Unavailable)?;
    Ok(outcome)
}

fn entity_tables(registry: &CompiledRegistry) -> Vec<String> {
    registry
        .entities()
        .values()
        .map(|entity| entity.physical_table.clone())
        .collect()
}

/// Report whether any retained journal head carries no commit member.
///
/// Reconstruction from the new baseline reads the newest member at or before
/// the position it starts from, so it reaches a record only through the commit
/// that indexes that record's journal head. Earlier revisions an existing-data
/// migration left outside the commit index are unreachable from every covered
/// position and cannot make the new baseline vouch for anything.
async fn has_unindexed_journal_heads(
    transaction: &tokio_postgres::Transaction<'_>,
) -> Result<bool, HistoryRebaselineError> {
    let row = transaction
        .query_one(
            "SELECT EXISTS (
                 SELECT 1
                   FROM (
                       SELECT DISTINCT ON (entity_id, record_id)
                              entity_id, record_id, record_revision
                         FROM registry_internal.registry_revisions
                        ORDER BY entity_id, record_id, record_revision DESC
                   ) AS head
                   LEFT JOIN registry_internal.registry_revision_commit_members AS member
                     ON member.entity_id = head.entity_id
                    AND member.record_id = head.record_id
                    AND member.record_revision = head.record_revision
                  WHERE member.commit_position IS NULL
             )",
            &[],
        )
        .await
        .map_err(|_| HistoryRebaselineError::Unavailable)?;
    Ok(row.get::<_, bool>(0))
}

async fn append_history_rebaseline_audit(
    transaction: &tokio_postgres::Transaction<'_>,
    request: &HistoryRebaselineRequest<'_>,
    outcome: &HistoryRebaselineOutcome,
) -> Result<(), HistoryRebaselineError> {
    if !profile_is_keyed(request.audit_profile) {
        return Err(HistoryRebaselineError::InvalidInput);
    }
    let operator_reference = request
        .audit_profile
        .key_hasher()
        .audit_reference_hash(
            "registry-server-history-rebaseline-operator-v1",
            &request.expected.package_revision,
            request.operator_reference,
        )
        .map_err(|_| HistoryRebaselineError::InvalidInput)?;
    append_audit_envelope(
        transaction,
        request.audit_profile,
        json!({
            "schema": "registry-server-history-rebaseline-audit/v1",
            "phase": "terminal",
            "outcome": "committed",
            "operationId": AUDIT_OPERATION_ID,
            "packageRevision": request.expected.package_revision,
            "operatorReference": operator_reference,
            "baselinePosition": outcome.baseline_position,
            "verifiedEntityCount": outcome.verified_entity_count,
            "verifiedRecordCount": outcome.verified_record_count,
            "previousCoverageBaselinePosition": outcome.previous_coverage_baseline_position,
            "previousUnavailableAfterPosition": outcome.previous_unavailable_after_position,
            "coveragePolicy": "references_before_the_new_baseline_remain_unavailable",
            "sourcePolicy": "live_rows_verified_against_retained_journal_heads",
        }),
    )
    .await?;
    Ok(())
}

fn validate_request(request: &HistoryRebaselineRequest<'_>) -> Result<(), HistoryRebaselineError> {
    request.expected.validate()?;
    if request.operator_reference.is_empty()
        || request.operator_reference.len() > MAX_OPERATOR_REFERENCE_BYTES
        || request.registry.entities().is_empty()
    {
        return Err(HistoryRebaselineError::InvalidInput);
    }
    if !profile_is_keyed(request.audit_profile) {
        return Err(HistoryRebaselineError::InvalidInput);
    }
    Ok(())
}
