// SPDX-License-Identifier: Apache-2.0

//! Bounded, durable verification work. Uploads never wait for this worker.

use std::time::Duration;

use registry_platform_audit::AuditProfile;
use serde_json::json;
use tokio::sync::watch;
use tokio_postgres::{Client, Transaction};

use crate::attachment_storage::AttachmentStorage;
use crate::attachment_store::{self, VerificationJob};
use crate::attachment_verification::{AttachmentVerification, AttachmentVerificationVerdict};
use crate::postgres::{ExpectedRegistryIdentity, RegistryLockKey, RuntimePool};

#[derive(Clone)]
pub struct AttachmentVerificationWorker {
    pool: RuntimePool,
    expected: ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    lock_timeout: Duration,
    audit: AuditProfile,
    storage: AttachmentStorage,
    verification: AttachmentVerification,
}

#[derive(Debug, thiserror::Error)]
#[error("attachment verification work is unavailable")]
pub struct VerificationWorkerError;

type Result<T> = std::result::Result<T, VerificationWorkerError>;

impl AttachmentVerificationWorker {
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool: RuntimePool,
        expected: ExpectedRegistryIdentity,
        lock_key: RegistryLockKey,
        lock_timeout: Duration,
        audit: AuditProfile,
        storage: AttachmentStorage,
        verification: AttachmentVerification,
    ) -> Self {
        Self {
            pool,
            expected,
            lock_key,
            lock_timeout,
            audit,
            storage,
            verification,
        }
    }

    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        loop {
            if *shutdown.borrow() {
                return;
            }
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() { return; }
                }
                result = self.run_once() => {
                    if result.is_err() {
                        crate::startup::OperationalEvent::AttachmentVerificationIterationFailed.emit();
                    }
                }
            }
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() { return; }
                }
                () = tokio::time::sleep(Duration::from_secs(1)) => {}
            }
        }
    }

    /// Claim and process at most one job. The attempt commits before any
    /// content read or verifier request; verdict and terminal audit commit
    /// together. Cancellation leaves a lease which another worker can retry.
    pub async fn run_once(&self) -> Result<bool> {
        // The durable lease is four minutes. A whole iteration, including
        // database waits and both external services, gets at most three, so a
        // timed-out worker cannot commit an approval after its lease expires.
        tokio::time::timeout(Duration::from_secs(180), self.run_once_inner())
            .await
            .map_err(unavailable)?
    }

    async fn run_once_inner(&self) -> Result<bool> {
        let AttachmentVerification::Http(verifier) = &self.verification else {
            return Ok(false);
        };
        let mut client = self.pool.get().await.map_err(unavailable)?;
        let transaction = self.admitted(&mut client).await?;
        let Some(job) =
            attachment_store::claim_verification(&transaction, &self.verification.binding_digest())
                .await
                .map_err(unavailable)?
        else {
            transaction.commit().await.map_err(unavailable)?;
            return Ok(false);
        };
        self.audit_job(&transaction, &job, "attempt", "started")
            .await?;
        transaction.commit().await.map_err(unavailable)?;
        drop(client);

        let verdict = match self.content(&job).await {
            Ok(bytes) => verifier
                .verify(&job.sha256, &job.content_type, bytes)
                .await
                .ok(),
            Err(_) => None,
        };
        let mut client = self.pool.get().await.map_err(unavailable)?;
        let transaction = self.admitted(&mut client).await?;
        let (updated, outcome) = match verdict {
            Some(verdict) => {
                let approved = verdict == AttachmentVerificationVerdict::Approved;
                (
                    attachment_store::finish_verification(&transaction, &job, approved)
                        .await
                        .map_err(unavailable)?,
                    if approved { "approved" } else { "rejected" },
                )
            }
            None => (
                attachment_store::retry_verification(&transaction, &job)
                    .await
                    .map_err(unavailable)?,
                "retry_pending",
            ),
        };
        // Erasure or lease expiry can win while the external verifier runs.
        // A stale verdict never creates replacement work or references.
        self.audit_job(
            &transaction,
            &job,
            "terminal",
            if updated { outcome } else { "discarded" },
        )
        .await?;
        transaction.commit().await.map_err(unavailable)?;
        if updated && verdict.is_none() {
            crate::startup::OperationalEvent::AttachmentVerificationRetryPending.emit();
        }
        Ok(true)
    }

    async fn content(&self, job: &VerificationJob) -> Result<Vec<u8>> {
        let mut client = self.pool.get().await.map_err(unavailable)?;
        let transaction = self.admitted(&mut client).await?;
        let stored = attachment_store::load_verification_content(&transaction, job)
            .await
            .map_err(unavailable)?;
        let bytes = match (&self.storage, stored) {
            (AttachmentStorage::Database, Some(bytes)) if job.backend_id == "database" => bytes,
            (AttachmentStorage::S3(storage), None)
                if job.backend_id == self.storage.binding_digest() =>
            {
                storage
                    .get(&job.sha256, job.byte_size)
                    .await
                    .map_err(unavailable)?
            }
            _ => return Err(VerificationWorkerError),
        };
        if bytes.len() as u64 != job.byte_size
            || attachment_store::content_hash(&bytes) != job.sha256
        {
            return Err(VerificationWorkerError);
        }
        transaction.commit().await.map_err(unavailable)?;
        Ok(bytes)
    }

    async fn admitted<'a>(&self, client: &'a mut Client) -> Result<Transaction<'a>> {
        let transaction = client.transaction().await.map_err(unavailable)?;
        transaction.execute(
            "SELECT set_config('lock_timeout', $1, true), set_config('statement_timeout', '30s', true)",
            &[&format!("{}ms", self.lock_timeout.as_millis())],
        ).await.map_err(unavailable)?;
        transaction
            .execute(
                "SELECT pg_advisory_xact_lock_shared($1)",
                &[&self.lock_key.get()],
            )
            .await
            .map_err(unavailable)?;
        let expected = &self.expected;
        let ready: bool = transaction
            .query_one(
                "SELECT EXISTS (SELECT 1 FROM registry_internal.registry_state WHERE singleton
             AND package_id=$1 AND environment=$2 AND instance_id=$3 AND database_id=$4
             AND active_package_revision=$5 AND schema_fingerprint=$6 AND package_sequence=$7
             AND maintenance_status='ready')",
                &[
                    &expected.package_id,
                    &expected.environment,
                    &expected.instance_id,
                    &expected.database_id,
                    &expected.package_revision,
                    &expected.schema_fingerprint,
                    &expected.package_sequence,
                ],
            )
            .await
            .map_err(unavailable)?
            .get(0);
        if !ready {
            return Err(VerificationWorkerError);
        }
        transaction
            .execute(
                "SELECT set_config('registry.active_package_revision', $1, true),
                    set_config('registry.principal', 'breg:attachment-verifier', true)",
                &[&expected.package_revision],
            )
            .await
            .map_err(unavailable)?;
        attachment_store::verify_backend_binding(
            &transaction,
            &self.storage.binding_digest(),
            &self.verification.binding_digest(),
        )
        .await
        .map_err(unavailable)?;
        Ok(transaction)
    }

    async fn audit_job(
        &self,
        transaction: &Transaction<'_>,
        job: &VerificationJob,
        phase: &str,
        outcome: &str,
    ) -> Result<()> {
        let hasher = self.audit.key_hasher();
        let reference = hasher
            .audit_reference_hash(
                "breg-attachment-verification-v1",
                &self.expected.package_revision,
                &format!("{}:{}:{}", job.sha256, job.content_type, job.lease_id),
            )
            .map_err(unavailable)?;
        crate::audit::append_envelope(
            transaction,
            &self.audit,
            json!({
                "kind": "attachmentVerification", "phase": phase, "outcome": outcome,
                "packageRevision": self.expected.package_revision,
                "actor": "breg:attachment-verifier", "verificationReference": reference,
            }),
        )
        .await
        .map_err(unavailable)
    }
}

fn unavailable<T>(_: T) -> VerificationWorkerError {
    VerificationWorkerError
}
