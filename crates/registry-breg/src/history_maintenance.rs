// SPDX-License-Identifier: Apache-2.0

//! Shared plumbing for the bounded, audited history maintenance paths.
//!
//! Every maintenance path runs under the same interlock: the configured
//! migration authority, bounded lock and statement timeouts, the exclusive
//! Registry advisory lock, a ready registry identity, and a correlated pair
//! of audit entries whose records carry references and counts instead of
//! values: a `request` entry accepted before the transaction opens, and a
//! `response` entry appended after it commits. A path run inside a parent
//! maintenance lifecycle runs under that lifecycle's request entry. The
//! erasure and rebaseline paths differ only
//! in what they change inside that transaction, so the interlock lives here
//! once.

use std::time::Duration;

use registry_platform_audit::{AuditEntry, AuditKeyHasher, AuditProfile, AuditRequest};

use crate::audit::RegistryAudit;
use crate::postgres::{
    lock_wait_ended, ExpectedRegistryIdentity, PostgresKernelError, RegistryLockKey,
};

const MAX_LOCK_TIMEOUT: Duration = Duration::from_secs(300);
const MAX_STATEMENT_TIMEOUT: Duration = Duration::from_secs(60 * 60);

/// Bounded lock and statement timeouts for one maintenance transaction.
#[derive(Clone, Copy)]
pub struct HistoryMaintenanceTimeouts {
    lock: Duration,
    statement: Duration,
}

impl HistoryMaintenanceTimeouts {
    pub fn new(lock: Duration, statement: Duration) -> Result<Self, HistoryMaintenanceError> {
        if lock.is_zero()
            || lock > MAX_LOCK_TIMEOUT
            || statement.is_zero()
            || statement > MAX_STATEMENT_TIMEOUT
        {
            return Err(HistoryMaintenanceError::InvalidInput);
        }
        Ok(Self { lock, statement })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum HistoryMaintenanceError {
    #[error("history maintenance input is invalid")]
    InvalidInput,
    #[error("history maintenance requires the configured migration authority")]
    MigrationAuthority,
    #[error("another session held the exclusive migration lock past the lock timeout")]
    MigrationLockHeld,
    #[error("history maintenance storage is unavailable")]
    Unavailable,
}

impl From<PostgresKernelError> for HistoryMaintenanceError {
    fn from(error: PostgresKernelError) -> Self {
        match error {
            PostgresKernelError::RoleInvariant(_) => Self::MigrationAuthority,
            PostgresKernelError::Configuration(_)
            | PostgresKernelError::FieldPatternSyntax { .. }
            | PostgresKernelError::FieldPatternExistingRows { .. }
            | PostgresKernelError::FieldEncryptionBlindCollision { .. }
            | PostgresKernelError::FieldEncryptionRetainedRequestSnapshots { .. } => {
                Self::InvalidInput
            }
            PostgresKernelError::Connection
            | PostgresKernelError::Statement(_)
            | PostgresKernelError::Pool
            | PostgresKernelError::PoolBuild
            | PostgresKernelError::CatalogInvariant(_)
            | PostgresKernelError::RegistryUnavailable
            | PostgresKernelError::HistoryCoverageIncomplete
            | PostgresKernelError::RetiredAuditRowsPresent => Self::Unavailable,
            PostgresKernelError::MigrationLockHeld => Self::MigrationLockHeld,
        }
    }
}

pub(crate) async fn set_local_timeouts(
    transaction: &tokio_postgres::Transaction<'_>,
    timeouts: HistoryMaintenanceTimeouts,
) -> Result<(), HistoryMaintenanceError> {
    let lock_millis = u64::try_from(timeouts.lock.as_millis())
        .map_err(|_| HistoryMaintenanceError::InvalidInput)?;
    let statement_millis = u64::try_from(timeouts.statement.as_millis())
        .map_err(|_| HistoryMaintenanceError::InvalidInput)?;
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
        .map_err(|_| HistoryMaintenanceError::Unavailable)?;
    Ok(())
}

/// Take the exclusive Registry advisory lock for the rest of the
/// transaction. A wait the lock timeout ends means another session holds the
/// lock; every other failure is an outage.
pub(crate) async fn lock_registry(
    transaction: &tokio_postgres::Transaction<'_>,
    lock_key: RegistryLockKey,
) -> Result<(), HistoryMaintenanceError> {
    transaction
        .execute(
            "SELECT pg_catalog.pg_advisory_xact_lock($1)",
            &[&lock_key.get()],
        )
        .await
        .map_err(|error| {
            if lock_wait_ended(&error) {
                HistoryMaintenanceError::MigrationLockHeld
            } else {
                HistoryMaintenanceError::Unavailable
            }
        })?;
    Ok(())
}

/// Lock the registry state row and require it to be ready for the expected
/// package binding. A mismatch and a non-ready state answer alike, so the
/// refusal never discloses which invariant failed.
pub(crate) async fn verify_ready_identity(
    transaction: &tokio_postgres::Transaction<'_>,
    expected: &ExpectedRegistryIdentity,
) -> Result<(), HistoryMaintenanceError> {
    expected.validate()?;
    let row = transaction
        .query_opt(
            "SELECT package_id, database_id, active_package_digest,
                    active_activation_id::text, schema_fingerprint, maintenance_status
               FROM registry_internal.registry_state
              WHERE singleton
              FOR UPDATE",
            &[],
        )
        .await
        .map_err(|_| HistoryMaintenanceError::Unavailable)?
        .ok_or(HistoryMaintenanceError::Unavailable)?;
    let ready = row.get::<_, String>(5) == "ready"
        && row.get::<_, String>(0) == expected.package_id
        && row.get::<_, String>(1) == expected.database_id
        && row.get::<_, String>(2) == expected.package_digest
        && row.get::<_, String>(3) == expected.activation_id
        && row.get::<_, String>(4) == expected.schema_fingerprint;
    if !ready {
        return Err(HistoryMaintenanceError::Unavailable);
    }
    Ok(())
}

pub(crate) fn profile_is_keyed(profile: &AuditProfile) -> bool {
    matches!(profile.key_hasher(), AuditKeyHasher::Keyed(_))
}

/// Append a maintenance `request` entry before its transaction opens and
/// return the handle that owes its response. The terminal entry appended
/// after commit, under the same schema and correlation, answers it; a
/// maintenance run that returns first writes the request's fields with the
/// `unfinished` outcome when the handle is dropped.
pub(crate) async fn begin_maintenance_request(
    audit: &RegistryAudit,
    entry: AuditEntry,
) -> Result<AuditRequest, HistoryMaintenanceError> {
    let mut unfinished = entry.record().clone();
    if let Some(fields) = unfinished.as_object_mut() {
        fields.insert("phase".to_owned(), "terminal".into());
        fields.insert("outcome".to_owned(), "unfinished".into());
    }
    audit
        .begin(entry, unfinished)
        .await
        .map_err(|_| HistoryMaintenanceError::Unavailable)
}

/// Append maintenance entries after the transaction that made their change
/// durable has committed. A refused entry reports the maintenance path
/// unavailable even though its change already committed: the operator sees
/// the failure and the audit carries no entry for that change.
pub(crate) async fn append_maintenance_entries(
    audit: &RegistryAudit,
    entries: Vec<AuditEntry>,
) -> Result<(), HistoryMaintenanceError> {
    for entry in entries {
        audit
            .append(entry)
            .await
            .map_err(|_| HistoryMaintenanceError::Unavailable)?;
    }
    Ok(())
}
