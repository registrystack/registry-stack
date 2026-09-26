// SPDX-License-Identifier: Apache-2.0
//! Operator-only erasure of expired protected action and request Evidence material.

use std::{path::Path, time::Duration};

use registry_platform_audit::AuditEntry;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::audit::RegistryAudit;
use crate::mutation::{erase_expired_action_evidence, MutationError};
use crate::postgres::{
    verify_catalog_identity_for_catalog, verify_migration_role, ConnectionConfig,
    ExpectedManagedCatalog, ExpectedRegistryIdentity, RegistryLockKey, SqlIdentifier,
};
use crate::runtime_config::load_runtime_config;

/// Schema of the request and response entries of one expired-Evidence
/// erasure.
pub const EVIDENCE_RETENTION_AUDIT_SCHEMA: &str = "breg-evidence-retention-audit/v1";

/// Package-bound authority for erasing expired protected Evidence material.
/// The migration identity, actual target catalog and registry interlock are
/// checked again in the same transaction that deletes the retained material.
pub struct ActionEvidenceRetentionOperatorService {
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

impl ActionEvidenceRetentionOperatorService {
    pub async fn from_runtime_config(path: &Path) -> Result<Self, MutationError> {
        if !path.is_absolute() {
            return Err(MutationError::InvalidRequest);
        }
        let config = load_runtime_config(path).map_err(|_| MutationError::Unavailable)?;
        let pool = config
            .runtime_database_connection_config()
            .map_err(|_| MutationError::Unavailable)?
            .build_pool()
            .map_err(|_| MutationError::Unavailable)?;
        let mut client = pool.get().await.map_err(|_| MutationError::Unavailable)?;
        let startup = crate::startup::prepare_startup(
            config.package().root(),
            &config.package_load_context(),
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

    /// Erase the retained Evidence material whose expiry is before `before`.
    ///
    /// The request entry, naming the threshold, is accepted before the
    /// erasure transaction opens, so an audit outage erases nothing. Its
    /// response records the erased count once the transaction commits, or
    /// the failure when it does not.
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
                "kind": "evidenceRetention",
                "phase": phase,
                "outcome": outcome,
                "packageRevision": self.expected.package_revision,
                "actor": "breg:evidence-retention-operator",
                "before": before.to_rfc3339_opts(chrono::SecondsFormat::Secs, true),
                "correlation": correlation,
            })
        };
        let mut attempt = self
            .audit
            .begin(
                AuditEntry::request(
                    EVIDENCE_RETENTION_AUDIT_SCHEMA,
                    correlation.clone(),
                    record("attempt", "started"),
                ),
                record("terminal", "unfinished"),
            )
            .await
            .map_err(|_| MutationError::Unavailable)?;
        match self.erase_in_transaction(before).await {
            Ok(erased) => {
                let mut response = record("terminal", "erased");
                response["erased"] = json!(erased);
                // The erasure committed; a refused entry reports the command
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
                        "the failed Evidence retention's response audit entry was not recorded"
                    );
                }
                Err(error)
            }
        }
    }

    async fn erase_in_transaction(
        &self,
        before: chrono::DateTime<chrono::Utc>,
    ) -> Result<u64, MutationError> {
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
        transaction.query_one(
            "SELECT set_config('lock_timeout', $1, true), set_config('statement_timeout', $2, true)",
            &[&format!("{}ms", self.lock_timeout.as_millis()), &format!("{}ms", self.statement_timeout.as_millis())],
        ).await.map_err(|_| MutationError::Unavailable)?;
        transaction
            .execute(
                "SELECT pg_catalog.pg_advisory_xact_lock($1)",
                &[&self.lock_key.get()],
            )
            .await
            .map_err(|_| MutationError::Unavailable)?;
        verify_catalog_identity_for_catalog(
            &transaction,
            &self.expected,
            &self.expected_catalog,
            &self.migration_role,
            &self.runtime_role,
        )
        .await
        .map_err(|_| MutationError::Unavailable)?;
        let ready: bool = transaction.query_one(
            "SELECT maintenance_status = 'ready' FROM registry_internal.registry_state WHERE singleton", &[])
            .await.map_err(|_| MutationError::Unavailable)?.get(0);
        if !ready {
            return Err(MutationError::Unavailable);
        }
        let erased = erase_expired_action_evidence(&transaction, before).await?;
        transaction
            .commit()
            .await
            .map_err(|_| MutationError::Unavailable)?;
        Ok(erased)
    }
}

/// Erase only material whose declared expiry has passed. Diagnostics contain
/// no connection, selector, assertion or provider values.
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
    ActionEvidenceRetentionOperatorService::from_runtime_config(path)
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
