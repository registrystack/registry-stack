// SPDX-License-Identifier: Apache-2.0

//! Bounded, durable verification work. Uploads never wait for this worker.
//!
//! Every pending verdict row has one job in the
//! `registry_attachment_verification_jobs` table, enqueued in the upload
//! transaction that created the row, and the shared
//! `registry-platform-dispatch` core runs it: one worker at a time holds a
//! job under a fenced lease, the attempt is audited before any byte is read
//! or sent, a lease that lapses is recovered to a backed-off retry, and a
//! verifier that cannot answer is retried with backoff and never given up
//! on. Only a verdict the configured verifier returned for the exact bytes,
//! media type, and verifier binding of the row approves or rejects it.

use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use registry_platform_audit::AuditEntry;
use registry_platform_dispatch::postgres::{
    AttemptAudit, ClaimRefusal, Decoded, DispatchConfig, DispatchConnection, DispatchEvent,
    DispatchOutcome, DispatchSql, DispatchStore, DispatchTransport, Dispatcher, JobKey, JobTable,
    LeasedJob, PooledClient, ReplayAudit, SelectSql, TargetAction, Transition, TransitionAudit,
    TransitionOutcome, LEASE_FINALIZATION_ALLOWANCE,
};
use registry_platform_dispatch::{
    AttemptTimeoutBound, Backoff, ConfigError, DispatchError, Jitter, JobPolicy, RetrySchedule,
    SendOutcome, Sent, UncertainOutcome, MAX_ATTEMPT_TIMEOUT,
};
use serde_json::json;
use tokio::sync::watch;
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;

use crate::attachment_storage::AttachmentStorage;
use crate::attachment_store::{self, VerificationContent, VerificationTarget};
use crate::attachment_verification::{
    AttachmentVerification, AttachmentVerificationVerdict, HttpAttachmentVerifier,
};
use crate::audit::RegistryAudit;
use crate::metrics::LastSuccess;
use crate::postgres::{ExpectedRegistryIdentity, RegistryLockKey, RuntimePool};

/// The audit schema of the attachment-verification attempt and outcome
/// entries.
pub const ATTACHMENT_VERIFICATION_AUDIT_SCHEMA: &str = "breg-attachment-verification-audit/v3";

/// The verification job table, in the shape `registry-platform-dispatch`
/// declares.
const JOB_TABLE: &str = "registry_attachment_verification_jobs";
/// The one part every verification job uses: a verdict row has one job.
const JOB_PART: &str = "verification";

/// The attempts one verification job may use. With a 30 second initial
/// delay doubling to a one hour maximum, this is years of retries: a
/// quarantined attachment waits for a verdict rather than for an operator,
/// and BReg offers no replay of a given-up job.
const MAXIMUM_ATTEMPTS: i16 = i16::MAX;

/// The time one verification attempt may spend on its storage read and its
/// verifier call together: the attempt timeout less the allowance the lease
/// keeps for recording the outcome. Configuration load refuses a storage and
/// verifier timeout pair that adds up to more.
pub(crate) const ATTEMPT_BUDGET: Duration =
    MAX_ATTEMPT_TIMEOUT.saturating_sub(LEASE_FINALIZATION_ALLOWANCE);

/// The dispatch policy every verification job runs under.
fn verification_policy() -> JobPolicy {
    JobPolicy {
        attempt_timeout: MAX_ATTEMPT_TIMEOUT,
        maximum_attempts: MAXIMUM_ATTEMPTS,
        retry: RetrySchedule::Backoff(Backoff {
            initial: Duration::from_secs(30),
            maximum: Duration::from_secs(60 * 60),
            multiplier: 2,
            jitter: Jitter::Equal,
        }),
        on_uncertain: UncertainOutcome::Retry,
        expires_at: None,
    }
}

/// The verification job table under `registry_internal`.
pub(crate) fn job_table() -> JobTable {
    JobTable::new("registry_internal", JOB_TABLE, "verification_id", JOB_PART)
        .expect("the verification job table names are plain identifiers")
}

fn job_key(verification_id: Uuid) -> std::result::Result<JobKey, ConfigError> {
    JobKey::new(verification_id, JOB_PART)
}

/// Enqueue the verification job of a verdict row the caller's transaction
/// just created.
pub(crate) async fn enqueue(
    transaction: &Transaction<'_>,
    verification_id: Uuid,
) -> std::result::Result<(), DispatchError> {
    let key = job_key(verification_id).map_err(|_| DispatchError::Unavailable)?;
    registry_platform_dispatch::postgres::enqueue(transaction, &job_table(), &key, None).await
}

const CLAIM_COLUMNS: &str = "verdict.verification_id, verdict.sha256, verdict.content_type, \
     verdict.verdict, blob.byte_size, blob.backend_id";
const CLAIM_JOINS: &str = "LEFT JOIN {schema}.registry_attachment_verification AS verdict \
       ON verdict.verification_id = state.verification_id \
     LEFT JOIN {schema}.registry_attachment_blobs AS blob ON blob.sha256 = verdict.sha256";
/// A verdict row waits for a verifier when it was written under the pinned
/// verifier binding for bytes a live reference still holds.
macro_rules! verifiable {
    () => {
        "(verdict.policy_digest = (SELECT verification_policy \
             FROM {schema}.registry_attachment_storage_binding WHERE singleton) \
         AND blob.state = 'live' \
         AND EXISTS (SELECT 1 FROM {schema}.registry_proposal_attachments AS reference \
             WHERE reference.sha256 = verdict.sha256 \
               AND reference.content_type = verdict.content_type \
               AND reference.erased_at IS NULL))"
    };
}
/// A job is claimable when its verdict row is gone or decided, so it can
/// end, or when the pending row is verifiable. Any other pending row waits
/// unclaimed.
const CLAIM_PREDICATE: &str = concat!(
    "verdict.verification_id IS NULL OR verdict.verdict <> 'pending' OR ",
    verifiable!()
);
/// A pending verdict row is stranded when it is verifiable but has no job
/// that can still run: its job is missing, or it stopped without a verdict.
const STRANDED_VERDICT: &str = concat!(
    "SELECT 1 FROM {schema}.registry_attachment_verification AS verdict \
       LEFT JOIN {schema}.registry_attachment_blobs AS blob ON blob.sha256 = verdict.sha256 \
     WHERE verdict.verdict = 'pending' AND ",
    verifiable!(),
    " AND NOT EXISTS (SELECT 1 FROM {schema}.{table} AS state \
         WHERE state.verification_id = verdict.verification_id \
           AND state.state IN ('pending', 'leased'))"
);

fn claim_select() -> SelectSql {
    SelectSql {
        columns: CLAIM_COLUMNS,
        joins: CLAIM_JOINS,
        predicate: CLAIM_PREDICATE,
    }
}

fn plain_select() -> SelectSql {
    SelectSql {
        columns: "",
        joins: "",
        predicate: "TRUE",
    }
}

#[derive(Clone)]
pub struct AttachmentVerificationWorker {
    admission: Arc<Admission>,
    engine: Option<Engine>,
    last_success: Arc<LastSuccess>,
}

/// The dispatcher and transport of a configured verifier.
#[derive(Clone)]
struct Engine {
    dispatcher: Dispatcher<VerificationStore>,
    transport: Arc<VerificationTransport>,
    /// The store's discarded leases, emptied after every pass.
    discarded: Arc<Mutex<HashSet<Uuid>>>,
    /// Serialises passes, so emptying the discarded leases after one pass
    /// never drops a mark another pass has yet to audit.
    pass: Arc<tokio::sync::Mutex<()>>,
}

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
    /// retry, or a pending verdict is stranded without a job that can run.
    RetryWaiting,
    /// The verifier answered, and its verdict committed or was discarded as
    /// stale, or the job's verdict row was already gone.
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
        let admission = Arc::new(Admission {
            pool,
            expected,
            lock_key,
            lock_timeout,
            storage_binding: storage.binding_digest(),
            verification_binding: verification.binding_digest(),
        });
        let engine = match &verification {
            AttachmentVerification::Disabled => None,
            AttachmentVerification::Http(verifier) => {
                let discarded = Arc::<Mutex<HashSet<Uuid>>>::default();
                let store = VerificationStore {
                    admission: Arc::clone(&admission),
                    audit,
                    discarded: Arc::clone(&discarded),
                };
                let dispatcher = Dispatcher::new(
                    store,
                    DispatchConfig {
                        table: job_table(),
                        sql: DispatchSql {
                            claim: claim_select(),
                            lapsed: plain_select(),
                            expiry: None,
                            target: plain_select(),
                        },
                        attempt_timeout: AttemptTimeoutBound::new(
                            Duration::from_secs(1),
                            MAX_ATTEMPT_TIMEOUT,
                        )
                        .expect("the verification attempt-timeout bound is ordered"),
                        replayable: &[],
                    },
                )
                .expect("the verification dispatch configuration is valid");
                Some(Engine {
                    dispatcher,
                    transport: Arc::new(VerificationTransport {
                        admission: Arc::clone(&admission),
                        storage,
                        verifier: Arc::clone(verifier),
                    }),
                    discarded,
                    pass: Arc::default(),
                })
            }
        };
        Self {
            admission,
            engine,
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

    /// Claim and process at most one job through the shared dispatch core.
    /// The lease commits and the attempt's `request` entry is accepted before
    /// any content read or verifier request; the verdict commits before its
    /// `response` entry is appended. A refused attempt entry, a failed verdict
    /// commit, or a stop before that commit leaves a lease that lapses, and
    /// the worker that recovers it answers the attempt as unfinished and
    /// schedules its retry.
    /// Returns whether a job was claimed, and notes a success only for a pass
    /// that reached a verdict, or that found no due job while no failed job
    /// waits for its retry. A pass that left its job pending for a retry, or
    /// found nothing due while a failed job waits, is never a success.
    pub async fn run_once(&self) -> Result<bool> {
        let iteration = self.run_once_inner().await?;
        if matches!(iteration, Iteration::Idle | Iteration::Verdict) {
            self.last_success.record();
        }
        Ok(matches!(
            iteration,
            Iteration::Verdict | Iteration::RetryPending
        ))
    }

    async fn run_once_inner(&self) -> Result<Iteration> {
        let Some(engine) = &self.engine else {
            return Ok(Iteration::Idle);
        };
        let outcome = {
            let _pass = engine.pass.lock().await;
            let outcome = engine
                .dispatcher
                .dispatch_once(engine.transport.as_ref())
                .await;
            // A finish that failed after its verdict write was refused never
            // reaches its terminal entry, so its discard mark goes here,
            // whatever the outcome.
            engine
                .discarded
                .lock()
                .map_err(|_| VerificationWorkerError)?
                .clear();
            outcome.map_err(unavailable)?
        };
        match outcome {
            DispatchOutcome::Idle => Ok(if self.retry_waiting().await? {
                Iteration::RetryWaiting
            } else {
                Iteration::Idle
            }),
            DispatchOutcome::Delivered => Ok(Iteration::Verdict),
            DispatchOutcome::RetryScheduled => {
                crate::startup::OperationalEvent::AttachmentVerificationRetryPending.emit();
                Ok(Iteration::RetryPending)
            }
            // The policy neither expires nor holds a job, and its attempts
            // outlast any deployment, so a job that stopped is a failure an
            // operator must see.
            DispatchOutcome::DeadLettered | DispatchOutcome::Unknown | DispatchOutcome::Expired => {
                Err(VerificationWorkerError)
            }
        }
    }

    /// Whether a claimable job an earlier attempt failed waits for its
    /// retry, or holds a lapsed lease the next claim recovers, or a
    /// verifiable pending verdict is stranded with no job that can still
    /// run. A job another worker holds a live lease on is not waiting.
    async fn retry_waiting(&self) -> Result<bool> {
        let mut client = self.admission.pool.get().await.map_err(unavailable)?;
        let transaction = client.transaction().await.map_err(unavailable)?;
        self.admission.admit(&transaction).await?;
        let schema = job_table().schema().to_owned();
        let statement = format!(
            "SELECT EXISTS (SELECT 1 FROM {schema}.{JOB_TABLE} AS state {}
              WHERE ((state.state = 'pending' AND state.attempt > 0)
                  OR (state.state = 'leased' AND state.lease_expires_at <= transaction_timestamp()))
                AND ({}))
              OR EXISTS ({})",
            CLAIM_JOINS.replace("{schema}", &schema),
            CLAIM_PREDICATE.replace("{schema}", &schema),
            STRANDED_VERDICT
                .replace("{schema}", &schema)
                .replace("{table}", JOB_TABLE),
        );
        let waiting: bool = transaction
            .query_one(&statement, &[])
            .await
            .map_err(unavailable)?
            .get(0);
        transaction.commit().await.map_err(unavailable)?;
        Ok(waiting)
    }
}

/// The registry identity and bindings every verification transaction is
/// admitted under.
struct Admission {
    pool: RuntimePool,
    expected: ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    lock_timeout: Duration,
    storage_binding: String,
    verification_binding: String,
}

impl Admission {
    /// Bound the transaction's waits, share the registry lock, check the
    /// active registry identity, enter the attachment row-level security
    /// scope, and check the pinned storage and verifier bindings.
    async fn admit(&self, transaction: &Transaction<'_>) -> Result<()> {
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
            transaction,
            &self.storage_binding,
            &self.verification_binding,
        )
        .await
        .map_err(unavailable)?;
        Ok(())
    }
}

/// What one verification attempt found.
#[derive(Clone, Debug, Eq, PartialEq)]
enum VerificationDetail {
    /// The verifier answered with this verdict.
    Verdict(AttachmentVerificationVerdict),
    /// The verdict row is gone or already decided, so no verifier request
    /// was made.
    Settled,
    /// No verdict: the content could not be read or checked, or the
    /// verifier did not answer.
    Failed,
}

fn failed() -> Sent<VerificationDetail> {
    Sent {
        outcome: SendOutcome::Transient { retry_after: None },
        detail: VerificationDetail::Failed,
    }
}

fn ended(detail: VerificationDetail) -> Sent<VerificationDetail> {
    Sent {
        outcome: SendOutcome::Accepted {
            receiver_reference: None,
        },
        detail,
    }
}

/// The audit identity of a job outside its own attempt: its verdict row and,
/// for a lapsed lease, the lease that attempt held.
#[derive(Clone, Debug, Eq, PartialEq)]
struct VerificationRecord {
    verification_id: Uuid,
    lease_token: Option<Uuid>,
}

/// The BReg consumer of the platform dispatch core.
struct VerificationStore {
    admission: Arc<Admission>,
    audit: RegistryAudit,
    /// Leases whose verdict arrived after its row was retired, so their
    /// terminal entry records a discard rather than the verdict.
    discarded: Arc<Mutex<HashSet<Uuid>>>,
}

impl VerificationStore {
    fn reference(&self, correlation: &str) -> std::result::Result<String, DispatchError> {
        self.audit
            .profile()
            .key_hasher()
            .audit_reference_hash(
                "breg-attachment-verification-v2",
                &self.admission.expected.activation_id,
                correlation,
            )
            .map_err(|_| DispatchError::Unavailable)
    }

    /// Append one verification entry. The attempt is the `request` entry and
    /// the terminal outcome is the `response` entry; both are correlated by
    /// the keyed verification reference of the lease.
    async fn append(
        &self,
        correlation: &str,
        phase: &str,
        outcome: &str,
    ) -> std::result::Result<(), DispatchError> {
        let reference = self.reference(correlation)?;
        let record = json!({
            "kind": "attachmentVerification", "phase": phase, "outcome": outcome,
            "activationId": self.admission.expected.activation_id,
            "actor": "breg:attachment-verifier", "verificationReference": reference,
        });
        let entry = if phase == "attempt" {
            AuditEntry::request(ATTACHMENT_VERIFICATION_AUDIT_SCHEMA, reference, record)
        } else {
            AuditEntry::response(ATTACHMENT_VERIFICATION_AUDIT_SCHEMA, reference, record)
        };
        self.audit
            .append(entry)
            .await
            .map_err(|_| DispatchError::Unavailable)
    }

    fn take_discarded(&self, lease_token: Uuid) -> bool {
        self.discarded
            .lock()
            .is_ok_and(|mut discarded| discarded.remove(&lease_token))
    }
}

fn lease_correlation(verification_id: Uuid, lease_token: Uuid) -> String {
    format!("{verification_id}:{lease_token}")
}

/// One claimed verification job: its verdict row's identifier and, while
/// that row still waits for a verdict, what the attempt must verify.
#[derive(Clone, Debug)]
struct VerificationJob {
    verification_id: Uuid,
    /// `None` when the verdict row is gone or already decided.
    target: Option<VerificationTarget>,
}

fn decode_job(
    row: &Row,
    first: usize,
) -> std::result::Result<VerificationJob, tokio_postgres::Error> {
    Ok(VerificationJob {
        verification_id: row.try_get(0)?,
        target: decode_target(row, first)?,
    })
}

fn decode_target(
    row: &Row,
    first: usize,
) -> std::result::Result<Option<VerificationTarget>, tokio_postgres::Error> {
    let verification_id: Option<Uuid> = row.try_get(first)?;
    let verdict: Option<String> = row.try_get(first + 3)?;
    let (Some(verification_id), Some("pending")) = (verification_id, verdict.as_deref()) else {
        return Ok(None);
    };
    let byte_size: i64 = row.try_get(first + 4)?;
    Ok(Some(VerificationTarget {
        verification_id,
        sha256: row.try_get(first + 1)?,
        content_type: row.try_get(first + 2)?,
        byte_size: u64::try_from(byte_size).unwrap_or(u64::MAX),
        backend_id: row.try_get(first + 5)?,
    }))
}

#[async_trait]
impl DispatchStore for VerificationStore {
    type Job = VerificationJob;
    type Record = VerificationRecord;
    type Detail = VerificationDetail;
    type Context = ();

    fn capture_context(&self) {}

    async fn connection(&self) -> std::result::Result<DispatchConnection, DispatchError> {
        let client = self
            .admission
            .pool
            .get()
            .await
            .map_err(|_| DispatchError::Unavailable)?;
        Ok(PooledClient::boxed(client))
    }

    async fn verify_transaction(
        &self,
        transaction: &Transaction<'_>,
    ) -> std::result::Result<(), DispatchError> {
        self.admission
            .admit(transaction)
            .await
            .map_err(|_| DispatchError::Unavailable)
    }

    fn decode_claim(
        &self,
        row: &Row,
        first: usize,
    ) -> std::result::Result<Decoded<Self::Job>, ClaimRefusal> {
        decode_job(row, first)
            .map(|job| Decoded {
                policy: verification_policy(),
                job,
            })
            .map_err(|_| ClaimRefusal::Unavailable)
    }

    fn claim_record(&self, job: &Self::Job) -> VerificationRecord {
        VerificationRecord {
            verification_id: job.verification_id,
            lease_token: None,
        }
    }

    fn decode_lapsed(
        &self,
        row: &Row,
        _first: usize,
    ) -> std::result::Result<Decoded<VerificationRecord>, DispatchError> {
        Ok(Decoded {
            policy: verification_policy(),
            job: VerificationRecord {
                verification_id: row.try_get(0)?,
                lease_token: Some(row.try_get(4)?),
            },
        })
    }

    fn decode_expired(
        &self,
        row: &Row,
        _first: usize,
    ) -> std::result::Result<VerificationRecord, DispatchError> {
        Ok(VerificationRecord {
            verification_id: row.try_get(0)?,
            lease_token: None,
        })
    }

    /// BReg offers no operator replay or cancellation of a verification job.
    fn decode_target(
        &self,
        _row: &Row,
        _first: usize,
        _key: &JobKey,
        _action: TargetAction,
    ) -> std::result::Result<Option<VerificationRecord>, DispatchError> {
        Ok(None)
    }

    async fn write_attempt(
        &self,
        transaction: &Transaction<'_>,
        job: &LeasedJob<Self::Job>,
        audit: AttemptAudit<'_, VerificationDetail>,
    ) -> std::result::Result<(), DispatchError> {
        let AttemptAudit::Finished { sent, .. } = audit else {
            return Ok(());
        };
        let VerificationDetail::Verdict(verdict) = &sent.detail else {
            return Ok(());
        };
        let approved = *verdict == AttachmentVerificationVerdict::Approved;
        let recorded = attachment_store::record_verification_verdict(
            transaction,
            job.key.id(),
            job.lease_token,
            approved,
        )
        .await
        .map_err(|_| DispatchError::Unavailable)?;
        if !recorded {
            self.discarded
                .lock()
                .map_err(|_| DispatchError::Unavailable)?
                .insert(job.lease_token);
        }
        Ok(())
    }

    async fn after_finished(
        &self,
        transaction: &Transaction<'_>,
        job: &LeasedJob<Self::Job>,
        _disposition: registry_platform_dispatch::postgres::Disposition,
    ) -> std::result::Result<(), DispatchError> {
        attachment_store::forget_retired_verification(transaction, job.key.id())
            .await
            .map_err(|_| DispatchError::Unavailable)
    }

    async fn record_attempt_audit(
        &self,
        job: &LeasedJob<Self::Job>,
        audit: AttemptAudit<'_, VerificationDetail>,
        _context: &(),
    ) -> std::result::Result<(), DispatchError> {
        let correlation = lease_correlation(job.key.id(), job.lease_token);
        match audit {
            AttemptAudit::Started => self.append(&correlation, "attempt", "started").await,
            AttemptAudit::Finished { sent, disposition } => {
                let discarded = self.take_discarded(job.lease_token);
                let outcome = match &sent.detail {
                    _ if discarded => "discarded",
                    VerificationDetail::Settled => "discarded",
                    VerificationDetail::Verdict(AttachmentVerificationVerdict::Approved) => {
                        "approved"
                    }
                    VerificationDetail::Verdict(AttachmentVerificationVerdict::Rejected) => {
                        "rejected"
                    }
                    VerificationDetail::Failed => disposition.as_str(),
                };
                self.append(&correlation, "terminal", outcome).await
            }
            AttemptAudit::Interrupted { .. } => {
                self.take_discarded(job.lease_token);
                self.append(&correlation, "terminal", "unfinished").await
            }
        }
    }

    async fn record_transition_audit(
        &self,
        audit: &TransitionAudit<VerificationRecord>,
        outcome: TransitionOutcome,
        _context: &(),
    ) -> std::result::Result<(), DispatchError> {
        if outcome != TransitionOutcome::Committed {
            return Ok(());
        }
        match (audit.transition, audit.record.lease_token) {
            // The worker that held the lapsed lease never answered its
            // attempt; the recovering worker answers it as unfinished.
            (Transition::LeaseLapsed(_), Some(lease_token)) => {
                let correlation = lease_correlation(audit.record.verification_id, lease_token);
                self.append(&correlation, "terminal", "unfinished").await
            }
            // Unreachable: the dispatcher this worker configures has no
            // expiry statement and no replayable or cancellable action, and
            // every lapsed record carries its lease token. A transition that
            // arrives anyway has no attempt to correlate with, so it fails
            // visibly rather than write an entry no attempt answers to.
            (Transition::LeaseLapsed(_), None)
            | (Transition::Expired { .. } | Transition::Cancelled, _) => {
                Err(DispatchError::Unavailable)
            }
        }
    }

    /// BReg offers no operator replay of a verification job, and the
    /// dispatcher it configures accepts none.
    async fn record_replay_audit(
        &self,
        _audit: &ReplayAudit<VerificationRecord>,
        _context: &(),
    ) -> std::result::Result<(), DispatchError> {
        Err(DispatchError::Unavailable)
    }

    fn operational_event(&self, event: DispatchEvent) {
        // A refused claim step also fails the iteration, which the worker
        // reports once. The policy neither expires nor quarantines a job, so
        // either event means an operator must look.
        match event {
            DispatchEvent::IterationFailed | DispatchEvent::TransitionFailed(_) => {}
            DispatchEvent::JobExpired | DispatchEvent::JobQuarantined(_) => {
                crate::startup::OperationalEvent::AttachmentVerificationIterationFailed.emit();
            }
        }
    }
}

/// Reads a leased job's bytes and asks the verifier.
struct VerificationTransport {
    admission: Arc<Admission>,
    storage: AttachmentStorage,
    verifier: Arc<HttpAttachmentVerifier>,
}

impl VerificationTransport {
    async fn attempt(&self, job: &LeasedJob<VerificationJob>) -> Sent<VerificationDetail> {
        let Some(target) = &job.job.target else {
            return ended(VerificationDetail::Settled);
        };
        let bytes = match self.content(target, job.lease_token).await {
            Ok(Some(bytes)) => bytes,
            Ok(None) => return ended(VerificationDetail::Settled),
            Err(_) => return failed(),
        };
        match self
            .verifier
            .verify(&target.sha256, &target.content_type, bytes)
            .await
        {
            Ok(verdict) => ended(VerificationDetail::Verdict(verdict)),
            Err(_) => failed(),
        }
    }

    /// The exact bytes of a still-pending verdict row, or `None` when the
    /// row is gone or already decided. The registry lock and the hash lock
    /// are held until the bytes are read and checked, so physical deletion
    /// cannot race the read.
    async fn content(
        &self,
        target: &VerificationTarget,
        lease_token: Uuid,
    ) -> Result<Option<Vec<u8>>> {
        let mut client = self.admission.pool.get().await.map_err(unavailable)?;
        let transaction = client.transaction().await.map_err(unavailable)?;
        self.admission.admit(&transaction).await?;
        let stored =
            match attachment_store::load_verification_content(&transaction, target, lease_token)
                .await
                .map_err(unavailable)?
            {
                VerificationContent::Settled => return Ok(None),
                VerificationContent::Pending(stored) => stored,
            };
        let bytes = match (&self.storage, stored) {
            (AttachmentStorage::Database, Some(bytes)) if target.backend_id == "database" => bytes,
            (AttachmentStorage::S3(storage), None)
                if target.backend_id == self.admission.storage_binding =>
            {
                storage
                    .get(&target.sha256, target.byte_size)
                    .await
                    .map_err(unavailable)?
            }
            _ => return Err(VerificationWorkerError),
        };
        if bytes.len() as u64 != target.byte_size
            || attachment_store::content_hash(&bytes) != target.sha256
        {
            return Err(VerificationWorkerError);
        }
        transaction.commit().await.map_err(unavailable)?;
        Ok(Some(bytes))
    }
}

#[async_trait]
impl DispatchTransport for VerificationTransport {
    type Job = VerificationJob;
    type Detail = VerificationDetail;

    async fn send(
        &self,
        job: &LeasedJob<VerificationJob>,
    ) -> std::result::Result<Sent<VerificationDetail>, DispatchError> {
        let Some(budget) = job.remaining_budget(SystemTime::now()) else {
            return Ok(failed());
        };
        Ok(tokio::time::timeout(budget, self.attempt(job))
            .await
            .unwrap_or_else(|_| failed()))
    }
}

fn unavailable<T>(_: T) -> VerificationWorkerError {
    VerificationWorkerError
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_policy_is_valid_never_expires_and_retries_on_backoff() {
        let policy = verification_policy();
        assert!(policy.is_valid(
            &AttemptTimeoutBound::new(Duration::from_secs(1), MAX_ATTEMPT_TIMEOUT).unwrap()
        ));
        assert_eq!(policy.expires_at, None);
        assert_eq!(policy.on_uncertain, UncertainOutcome::Retry);
        assert_eq!(policy.maximum_attempts, i16::MAX);
    }

    #[test]
    fn the_job_table_fits_the_dispatch_bounds() {
        let table = job_table();
        assert_eq!(table.table(), JOB_TABLE);
        assert!(job_key(Uuid::new_v4()).is_ok());
    }

    #[test]
    fn only_a_verifier_answer_ends_a_job_with_a_verdict() {
        for verdict in [
            AttachmentVerificationVerdict::Approved,
            AttachmentVerificationVerdict::Rejected,
        ] {
            let sent = ended(VerificationDetail::Verdict(verdict));
            assert!(matches!(sent.outcome, SendOutcome::Accepted { .. }));
        }
        assert!(matches!(
            failed().outcome,
            SendOutcome::Transient { retry_after: None }
        ));
        assert_eq!(failed().detail, VerificationDetail::Failed);
    }
}
