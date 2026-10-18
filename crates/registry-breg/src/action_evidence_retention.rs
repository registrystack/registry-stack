// SPDX-License-Identifier: Apache-2.0

//! Bounded expiry of accepted Evidence material under the runtime role.

use std::time::Duration;

use registry_platform_audit::AuditEntry;
use serde_json::json;
use tokio::sync::watch;
use tokio_postgres::GenericClient;

use crate::audit::RegistryAudit;
use crate::postgres::{
    begin_registry_transaction, cancellation::QueryCancellationGuard, ExpectedRegistryIdentity,
    RegistryLockKey, RuntimePool, RuntimeRevoke, SqlIdentifier,
};

pub(crate) const EXPIRY_FUNCTION: &str = "registry_internal.expire_action_evidence_uses()";
/// Schema shared by manual and runtime Evidence erasure.
pub const EVIDENCE_RETENTION_AUDIT_SCHEMA: &str = "breg-evidence-retention-audit/v2";

pub(crate) async fn install(
    migration: &impl GenericClient,
    runtime_role: &SqlIdentifier,
) -> Result<(), tokio_postgres::Error> {
    let revoke = RuntimeRevoke::detect(migration, runtime_role)
        .await?
        .with_public();
    migration.batch_execute(&format!(
        "CREATE INDEX IF NOT EXISTS registry_action_evidence_uses_expiry
             ON registry_internal.registry_action_evidence_uses (expires_at);
         CREATE INDEX IF NOT EXISTS registry_proposal_evidence_uses_expiry
             ON registry_internal.registry_proposal_evidence_uses (expires_at);
         CREATE OR REPLACE FUNCTION {EXPIRY_FUNCTION}
             RETURNS bigint LANGUAGE sql SECURITY DEFINER
             SET search_path = pg_catalog, registry_internal AS $body$
             WITH action_due AS (
                 SELECT application_id, ordinal FROM registry_internal.registry_action_evidence_uses
                 WHERE expires_at <= transaction_timestamp()
                 ORDER BY expires_at LIMIT 1000 FOR UPDATE SKIP LOCKED
             ), action_removed AS (
                 DELETE FROM registry_internal.registry_action_evidence_uses AS entry USING action_due
                 WHERE entry.application_id=action_due.application_id AND entry.ordinal=action_due.ordinal
                 RETURNING 1
             ), proposal_due AS (
                 SELECT application_id, ordinal FROM registry_internal.registry_proposal_evidence_uses
                 WHERE expires_at <= transaction_timestamp()
                 ORDER BY expires_at LIMIT 1000 FOR UPDATE SKIP LOCKED
             ), proposal_removed AS (
                 DELETE FROM registry_internal.registry_proposal_evidence_uses AS entry USING proposal_due
                 WHERE entry.application_id=proposal_due.application_id AND entry.ordinal=proposal_due.ordinal
                 RETURNING 1
             ) SELECT (SELECT count(*) FROM action_removed) + (SELECT count(*) FROM proposal_removed);
             $body$;
         REVOKE ALL ON FUNCTION {EXPIRY_FUNCTION} FROM {revoke};
         GRANT EXECUTE ON FUNCTION {EXPIRY_FUNCTION} TO {role};",
        role=runtime_role.quoted(),
    )).await
}

/// Runtime-only authority: no migration credential or access to retained assertions.
#[derive(Clone)]
pub struct EvidenceRetentionWorker {
    pool: RuntimePool,
    expected: ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    audit: RegistryAudit,
}

impl EvidenceRetentionWorker {
    pub(crate) fn new(
        pool: RuntimePool,
        expected: ExpectedRegistryIdentity,
        lock_key: RegistryLockKey,
        audit: RegistryAudit,
    ) -> Self {
        Self {
            pool,
            expected,
            lock_key,
            audit,
        }
    }

    #[cfg(feature = "postgres-test")]
    #[doc(hidden)]
    pub fn new_for_test(
        pool: RuntimePool,
        expected: ExpectedRegistryIdentity,
        lock_key: RegistryLockKey,
        audit: RegistryAudit,
    ) -> Self {
        Self::new(pool, expected, lock_key, audit)
    }

    /// Sweep immediately, then once a minute. Shutdown cancels in-flight SQL and
    /// leaves an unfinished audit answer through the audit attempt guard.
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        let mut interval = tokio::time::interval(Duration::from_secs(60));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            if *shutdown.borrow() {
                return;
            }
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() { return; }
                }
                _ = async {
                    interval.tick().await;
                    if self.tick().await.is_err() {
                        tracing::error!("Evidence retention sweep failed");
                    }
                } => {}
            }
        }
    }

    async fn tick(&self) -> Result<(), ()> {
        let correlation = uuid::Uuid::new_v4().to_string();
        let record = |phase: &str, outcome: &str| {
            json!({
                "kind":"evidenceRetention", "phase":phase, "outcome":outcome,
                "activationId":self.expected.activation_id,
                "actor":"breg:evidence-retention-worker", "correlation":correlation,
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
            .map_err(|_| ())?;
        let result = self.erase_batch().await;
        let mut response = record(
            "terminal",
            match result {
                Ok(_) => "erased",
                Err(ExpiryError::Failed) => "failed",
                Err(ExpiryError::Unfinished) => "unfinished",
            },
        );
        if let Ok(erased) = result {
            response["erased"] = json!(erased);
        }
        attempt.respond(response).await.map_err(|_| ())?;
        result.map(|_| ()).map_err(|_| ())
    }

    async fn erase_batch(&self) -> Result<i64, ExpiryError> {
        let client = self.pool.get().await.map_err(|_| ExpiryError::Failed)?;
        let mut guard = QueryCancellationGuard::new(self.pool.clone(), client);
        let transaction = begin_registry_transaction(
            guard.client(),
            self.lock_key,
            Duration::from_secs(5),
            &self.expected,
        )
        .await
        .map_err(|_| ExpiryError::Failed)?;
        transaction
            .set_statement_budget(Duration::from_secs(10))
            .await
            .map_err(|_| ExpiryError::Failed)?;
        let erased = transaction
            .transaction()
            .query_one(
                "SELECT registry_internal.expire_action_evidence_uses()",
                &[],
            )
            .await
            .map_err(|_| ExpiryError::Failed)?
            .get(0);
        transaction
            .commit()
            .await
            .map_err(|_| ExpiryError::Unfinished)?;
        guard.disarm();
        Ok(erased)
    }
}

#[derive(Clone, Copy)]
enum ExpiryError {
    Failed,
    Unfinished,
}
