// SPDX-License-Identifier: Apache-2.0
//! Operator-only removal of held idempotency responses past their receipt
//! horizon.
//!
//! The runtime already refuses an exact retry past the horizon when it reads
//! the spent key, whether or not this sweep has run. The sweep only removes
//! the held bytes; every spent row keeps its caller, key, binding, and times,
//! so the key stays spent and the retry is still refused rather than
//! executed.

use std::{path::Path, time::Duration};

use registry_platform_audit::AuditEntry;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::audit::RegistryAudit;
use crate::history_maintenance::{lock_registry, HistoryMaintenanceError};
use crate::idempotency::{drop_expired_receipts, expired_receipts_remain};
use crate::mutation::MutationError;
use crate::package::PackageError;
use crate::postgres::{
    verify_catalog_identity_for_catalog, verify_migration_role, ConnectionConfig,
    ExpectedManagedCatalog, ExpectedRegistryIdentity, RegistryLockKey, SqlIdentifier,
};
use crate::runtime_config::load_runtime_config;

/// Schema of the request and response entries of one idempotency receipt
/// sweep.
pub const IDEMPOTENCY_RETENTION_AUDIT_SCHEMA: &str = "breg-idempotency-retention-audit/v1";

/// Package-bound authority for dropping held idempotency responses past their
/// receipt horizon. The migration identity, actual target catalog and registry
/// interlock are checked again in the same transaction that drops them.
pub struct IdempotencyRetentionOperatorService {
    expected: ExpectedRegistryIdentity,
    expected_catalog: ExpectedManagedCatalog,
    lock_key: RegistryLockKey,
    migration_connection: ConnectionConfig,
    migration_role: SqlIdentifier,
    runtime_role: SqlIdentifier,
    lock_timeout: Duration,
    statement_timeout: Duration,
    audit: RegistryAudit,
}

impl IdempotencyRetentionOperatorService {
    pub async fn from_runtime_config(path: &Path) -> Result<Self, MutationError> {
        if !path.is_absolute() {
            return Err(MutationError::InvalidRequest);
        }
        let config = load_runtime_config(path).map_err(|_| MutationError::Unavailable)?;
        let package = config.load_active_package().map_err(|error| match error {
            PackageError::ExpectedDigestMismatch(mismatch) => {
                MutationError::PackagePinMismatch(mismatch)
            }
            _ => MutationError::Unavailable,
        })?;
        let pool = config
            .runtime_database_connection_config()
            .map_err(|_| MutationError::Unavailable)?
            .build_pool()
            .map_err(|_| MutationError::Unavailable)?;
        let mut client = pool.get().await.map_err(|_| MutationError::Unavailable)?;
        let startup = crate::startup::prepare_loaded_startup(
            package,
            config.identity().database_id(),
            &mut client,
            config.database().roles().migration(),
            config.database().roles().runtime(),
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
        Ok(Self {
            expected: startup.expected_identity().clone(),
            expected_catalog: startup.expected_catalog().clone(),
            lock_key: startup.lock_key(),
            migration_connection: config
                .migration_database_connection_config()
                .map_err(|_| MutationError::Unavailable)?,
            migration_role: config.database().roles().migration().clone(),
            runtime_role: config.database().roles().runtime().clone(),
            lock_timeout: config.operational_timeouts().migration_lock,
            statement_timeout: config.operational_timeouts().migration_statement,
            audit: RegistryAudit::open_companion(&config)
                .await
                .map_err(|_| MutationError::Unavailable)?,
        })
    }

    #[cfg(feature = "postgres-test")]
    #[doc(hidden)]
    pub fn new_for_test(
        expected: ExpectedRegistryIdentity,
        expected_catalog: ExpectedManagedCatalog,
        lock_key: RegistryLockKey,
        migration_connection: ConnectionConfig,
        migration_role: SqlIdentifier,
        runtime_role: SqlIdentifier,
        audit: RegistryAudit,
    ) -> Self {
        Self {
            expected,
            expected_catalog,
            lock_key,
            migration_connection,
            migration_role,
            runtime_role,
            lock_timeout: Duration::from_secs(5),
            statement_timeout: Duration::from_secs(10),
            audit,
        }
    }

    /// Drop the held responses whose receipt horizon passed before `before`.
    ///
    /// The request entry, naming the threshold, is accepted before the
    /// transaction opens, so an audit outage drops nothing. Its response
    /// records the dropped count once the transaction commits, or the failure
    /// when it does not.
    pub async fn erase_expired(
        &self,
        before: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, MutationError> {
        if before > chrono::Utc::now() {
            return Err(MutationError::InvalidRequest);
        }
        let correlation = Uuid::new_v4().to_string();
        let record = |phase: &str, outcome: &str| -> Value {
            json!({
                "kind": "idempotencyRetention",
                "phase": phase,
                "outcome": outcome,
                "packageRevision": self.expected.activation_id,
                "actor": "breg:idempotency-retention-operator",
                "before": before.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                "correlation": correlation,
            })
        };
        let mut attempt = self
            .audit
            .begin(
                AuditEntry::request(
                    IDEMPOTENCY_RETENTION_AUDIT_SCHEMA,
                    correlation.clone(),
                    record("attempt", "started"),
                ),
                record("terminal", "unfinished"),
            )
            .await
            .map_err(|_| MutationError::Unavailable)?;
        let erased = match self.erase_in_transaction(before).await {
            Ok(Erasure::Committed(erased)) => Ok(erased),
            // A commit that returned an error may still have committed, so
            // the outcome recorded for this destructive operation is the one
            // the database holds, read on a fresh connection.
            Ok(Erasure::Unacknowledged { erased, cutoff }) => {
                match self.expired_receipts_remain(cutoff).await {
                    Some(false) => Ok(erased),
                    resolved => {
                        let outcome = if resolved == Some(true) {
                            "failed"
                        } else {
                            "unfinished"
                        };
                        if attempt.respond(record("terminal", outcome)).await.is_err() {
                            tracing::error!(
                                "the unacknowledged idempotency retention's response audit entry was not recorded"
                            );
                        }
                        return Err(MutationError::Unavailable);
                    }
                }
            }
            Err(error) => Err(error),
        };
        match erased {
            Ok(erased) => {
                let mut response = record("terminal", "erased");
                response["erased"] = json!(erased);
                // The sweep committed; a refused entry reports the command
                // unavailable, and the writer then refuses every later entry.
                attempt
                    .respond(response)
                    .await
                    .map_err(|_| MutationError::Unavailable)?;
                Ok(erased)
            }
            Err(error) => {
                if attempt.respond(record("terminal", "failed")).await.is_err() {
                    tracing::error!(
                        "the failed idempotency retention's response audit entry was not recorded"
                    );
                }
                Err(error)
            }
        }
    }

    /// Whether a held response past its horizon at `cutoff` remains, read on
    /// a fresh connection after a sweep commit returned an error. `None` when
    /// it cannot be read.
    async fn expired_receipts_remain(&self, cutoff: chrono::DateTime<chrono::Utc>) -> Option<bool> {
        let pool = self.migration_connection.build_pool().ok()?;
        let client = pool.get().await.ok()?;
        expired_receipts_remain(&client, cutoff).await.ok()
    }

    /// Drop the expired held responses in one transaction. A commit that
    /// returned an error, which does not prove the transaction rolled back, is
    /// reported with the count it would have dropped and the cutoff it
    /// dropped through; every earlier error is returned as one.
    async fn erase_in_transaction(
        &self,
        before: chrono::DateTime<chrono::Utc>,
    ) -> Result<Erasure, MutationError> {
        let pool = self
            .migration_connection
            .build_pool()
            .map_err(|_| MutationError::Unavailable)?;
        let mut client = pool.get().await.map_err(|_| MutationError::Unavailable)?;
        let client: &mut tokio_postgres::Client = &mut client;
        verify_migration_role(client, &self.migration_role)
            .await
            .map_err(|_| MutationError::Unavailable)?;
        let transaction = client
            .transaction()
            .await
            .map_err(|_| MutationError::Unavailable)?;
        transaction
            .query_one(
                "SELECT set_config('lock_timeout', $1, true), set_config('statement_timeout', $2, true)",
                &[
                    &format!("{}ms", self.lock_timeout.as_millis()),
                    &format!("{}ms", self.statement_timeout.as_millis()),
                ],
            )
            .await
            .map_err(|_| MutationError::Unavailable)?;
        lock_registry(&transaction, self.lock_key)
            .await
            .map_err(|error| match error {
                HistoryMaintenanceError::MigrationLockHeld => MutationError::MigrationLockHeld,
                _ => MutationError::Unavailable,
            })?;
        verify_catalog_identity_for_catalog(
            &transaction,
            &self.expected,
            &self.expected_catalog,
            &self.migration_role,
            &self.runtime_role,
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
        let ready: bool = transaction
            .query_one(
                "SELECT maintenance_status = 'ready' FROM registry_internal.registry_state WHERE singleton",
                &[],
            )
            .await
            .map_err(|_| MutationError::Unavailable)?
            .get(0);
        if !ready {
            return Err(MutationError::Unavailable);
        }
        // The cutoff the sweep applies, fixed by the transaction's start.
        let cutoff: chrono::DateTime<chrono::Utc> = transaction
            .query_one("SELECT LEAST($1, CURRENT_TIMESTAMP)", &[&before])
            .await
            .map_err(|_| MutationError::Unavailable)?
            .get(0);
        let erased = drop_expired_receipts(&transaction, before).await?;
        if transaction.commit().await.is_err() {
            return Ok(Erasure::Unacknowledged { erased, cutoff });
        }
        Ok(Erasure::Committed(erased))
    }
}

/// How a sweep transaction ended once every statement in it succeeded.
enum Erasure {
    Committed(u64),
    Unacknowledged {
        erased: u64,
        cutoff: chrono::DateTime<chrono::Utc>,
    },
}

/// Drop only held responses whose receipt horizon has passed. Diagnostics
/// contain no connection, caller, key, or response values.
pub async fn erase_expired(path: &Path, before: &str) -> Result<u64, MutationError> {
    if !path.is_absolute() {
        return Err(MutationError::InvalidRequest);
    }
    let before = chrono::DateTime::parse_from_rfc3339(before)
        .map_err(|_| MutationError::InvalidRequest)?
        .with_timezone(&chrono::Utc);
    if before > chrono::Utc::now() {
        return Err(MutationError::InvalidRequest);
    }
    IdempotencyRetentionOperatorService::from_runtime_config(path)
        .await?
        .erase_expired(before)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn malformed_or_future_boundaries_fail_before_configuration_io() {
        for (path, boundary) in [
            ("relative.yaml", "2020-01-01T00:00:00Z"),
            ("/nonexistent/config.yaml", "private-invalid-boundary"),
            ("/nonexistent/config.yaml", "9999-01-01T00:00:00Z"),
        ] {
            assert!(matches!(
                erase_expired(Path::new(path), boundary).await,
                Err(MutationError::InvalidRequest)
            ));
        }
    }
}
