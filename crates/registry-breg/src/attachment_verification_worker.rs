// SPDX-License-Identifier: Apache-2.0

//! Bounded, durable verification work. Uploads never wait for this worker.

use std::sync::Arc;
use std::time::Duration;

use registry_platform_audit::AuditEntry;
use serde_json::json;
use tokio::sync::watch;
use tokio_postgres::{Client, Transaction};

use crate::attachment_storage::AttachmentStorage;
use crate::attachment_store::{self, VerificationJob};
use crate::attachment_verification::{AttachmentVerification, AttachmentVerificationVerdict};
use crate::audit::RegistryAudit;
use crate::metrics::LastSuccess;
use crate::postgres::{ExpectedRegistryIdentity, RegistryLockKey, RuntimePool};

#[derive(Clone)]
pub struct AttachmentVerificationWorker {
    pool: RuntimePool,
    expected: ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    lock_timeout: Duration,
    audit: RegistryAudit,
    storage: AttachmentStorage,
    verification: AttachmentVerification,
    last_success: Arc<LastSuccess>,
}

/// The audit schema of the attachment-verification attempt and outcome
/// entries.
pub const ATTACHMENT_VERIFICATION_AUDIT_SCHEMA: &str = "breg-attachment-verification-audit/v1";

#[derive(Debug, thiserror::Error)]
#[error("attachment verification work is unavailable")]
pub struct VerificationWorkerError;

type Result<T> = std::result::Result<T, VerificationWorkerError>;

/// What one pass did with the work it found.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Iteration {
    /// No job was due, and no job an earlier attempt failed waits for its
    /// retry.
    Idle,
    /// No job was due, but a job an earlier attempt failed waits for its
    /// retry.
    RetryWaiting,
    /// The verifier answered, and its verdict committed or was discarded as
    /// stale.
    Verdict,
    /// The content or the verifier failed, and the job waits for a retry.
    RetryPending,
}

impl AttachmentVerificationWorker {
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool: RuntimePool,
        expected: ExpectedRegistryIdentity,
        lock_key: RegistryLockKey,
        lock_timeout: Duration,
        audit: RegistryAudit,
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
            last_success: Arc::default(),
        }
    }

    /// The handle this worker notes each iteration that reached a verdict, or
    /// found no due job while no failed job waits for its retry.
    #[must_use]
    pub fn last_success(&self) -> Arc<LastSuccess> {
        Arc::clone(&self.last_success)
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
                    let worked = match result {
                        Ok(worked) => worked,
                        Err(_) => {
                            crate::startup::OperationalEvent::AttachmentVerificationIterationFailed.emit();
                            false
                        }
                    };
                    // A job just finished, so another may be due: claim it
                    // without waiting. Only an idle or failed pass waits.
                    if worked {
                        continue;
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

    /// Claim and process at most one job. The lease commits and the attempt's
    /// `request` entry is accepted before any content read or verifier
    /// request; the verdict commits before its `response` entry is appended.
    /// A refused attempt entry, a failed verdict commit, or a cancellation
    /// before that commit leaves a lease which another worker can retry.
    /// Returns whether a job was claimed, and notes a success only for a pass
    /// that reached a verdict, or that found no due job while no failed job
    /// waits for its retry. A pass that left its job pending for a retry, or
    /// found nothing due while a failed job waits, is never a success.
    pub async fn run_once(&self) -> Result<bool> {
        // The durable lease is four minutes. A whole iteration, including
        // database waits and both external services, gets at most three, so a
        // timed-out worker cannot commit an approval after its lease expires.
        let iteration = tokio::time::timeout(Duration::from_secs(180), self.run_once_inner())
            .await
            .map_err(unavailable)??;
        if matches!(iteration, Iteration::Idle | Iteration::Verdict) {
            self.last_success.record();
        }
        Ok(matches!(
            iteration,
            Iteration::Verdict | Iteration::RetryPending
        ))
    }

    async fn run_once_inner(&self) -> Result<Iteration> {
        let AttachmentVerification::Http(verifier) = &self.verification else {
            return Ok(Iteration::Idle);
        };
        let mut client = self.pool.get().await.map_err(unavailable)?;
        let transaction = self.admitted(&mut client).await?;
        let Some(job) =
            attachment_store::claim_verification(&transaction, &self.verification.binding_digest())
                .await
                .map_err(unavailable)?
        else {
            let waiting = attachment_store::verification_retry_waiting(
                &transaction,
                &self.verification.binding_digest(),
            )
            .await
            .map_err(unavailable)?;
            transaction.commit().await.map_err(unavailable)?;
            return Ok(if waiting {
                Iteration::RetryWaiting
            } else {
                Iteration::Idle
            });
        };
        transaction.commit().await.map_err(unavailable)?;
        drop(client);
        // Held until the terminal entry answers it; a run that ends first,
        // including one its time budget cancels, answers it as unfinished.
        let _attempt = self.begin_job(&job).await?;

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
                "retry-pending",
            ),
        };
        // Erasure or lease expiry can win while the external verifier runs.
        // A stale verdict never creates replacement work or references.
        // The terminal entry is appended only after the verdict commits, so
        // it never records a verdict that rolled back. A commit error does not
        // prove either outcome: the attempt is then answered as unfinished
        // when its handle drops, and a rolled-back job is retried after its
        // lease expires.
        transaction.commit().await.map_err(unavailable)?;
        self.audit_job(
            &job,
            "terminal",
            if updated { outcome } else { "discarded" },
        )
        .await?;
        if updated && verdict.is_none() {
            crate::startup::OperationalEvent::AttachmentVerificationRetryPending.emit();
        }
        Ok(if verdict.is_some() {
            Iteration::Verdict
        } else {
            Iteration::RetryPending
        })
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
             AND package_id=$1 AND database_id=$2 AND active_package_digest=$3
             AND active_activation_id::text=$4 AND schema_fingerprint=$5
             AND maintenance_status='ready')",
                &[
                    &expected.package_id,
                    &expected.database_id,
                    &expected.package_digest,
                    &expected.activation_id,
                    &expected.schema_fingerprint,
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
                &[&expected.activation_id],
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

    /// Append the attempt `request` entry of one leased job and return the
    /// handle that owes its terminal `response`.
    async fn begin_job(
        &self,
        job: &VerificationJob,
    ) -> Result<registry_platform_audit::AuditRequest> {
        let (reference, record) = self.job_record(job, "attempt", "started")?;
        let (_, unfinished) = self.job_record(job, "terminal", "unfinished")?;
        self.audit
            .begin(
                AuditEntry::request(ATTACHMENT_VERIFICATION_AUDIT_SCHEMA, reference, record),
                unfinished,
            )
            .await
            .map_err(unavailable)
    }

    /// Append one verification entry. The attempt is the `request` entry and
    /// the terminal outcome is the `response` entry; both are correlated by
    /// the keyed verification reference of the leased job.
    async fn audit_job(&self, job: &VerificationJob, phase: &str, outcome: &str) -> Result<()> {
        let (reference, record) = self.job_record(job, phase, outcome)?;
        let entry = if phase == "attempt" {
            AuditEntry::request(ATTACHMENT_VERIFICATION_AUDIT_SCHEMA, reference, record)
        } else {
            AuditEntry::response(ATTACHMENT_VERIFICATION_AUDIT_SCHEMA, reference, record)
        };
        self.audit.append(entry).await.map_err(unavailable)
    }

    fn job_record(
        &self,
        job: &VerificationJob,
        phase: &str,
        outcome: &str,
    ) -> Result<(String, serde_json::Value)> {
        let hasher = self.audit.profile().key_hasher();
        let reference = hasher
            .audit_reference_hash(
                "breg-attachment-verification-v1",
                &self.expected.activation_id,
                &format!("{}:{}:{}", job.sha256, job.content_type, job.lease_id),
            )
            .map_err(unavailable)?;
        let record = json!({
            "kind": "attachmentVerification", "phase": phase, "outcome": outcome,
            "packageRevision": self.expected.activation_id,
            "actor": "breg:attachment-verifier", "verificationReference": reference,
        });
        Ok((reference, record))
    }
}

fn unavailable<T>(_: T) -> VerificationWorkerError {
    VerificationWorkerError
}
