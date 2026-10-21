// SPDX-License-Identifier: Apache-2.0

//! Content verification: one dispatch job per finalized version and
//! verifier binding.
//!
//! The finalizing transaction enqueues the job under the key
//! `idempotency_key(domain, [versionId, verifierBinding])`. The worker reads
//! the stored content, checks it against the version's digest and length,
//! and asks the verifier. Only an `approved` verdict bound to the version's
//! digest, media type, and the current verifier binding makes it
//! releasable. A verifier that cannot answer is retried with backoff for
//! about seven days and then dead-lettered; a dead-letter leaves the
//! version pending and suspended, never approved and never rejected.
//!
//! At startup, every version recorded under another verifier binding is
//! suspended and given a job under the current one, and its pending job
//! under the old binding is cancelled. A worker that claims a job recorded
//! under a binding other than its own retries it rather than ending it, so
//! a worker under the version's own binding can still verify it.

use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use registry_platform_config::SecretResolver;
use registry_platform_dispatch::postgres::{
    AttemptAudit, ClaimRefusal, Decoded, DispatchConfig, DispatchConnection, DispatchEvent,
    DispatchSql, DispatchStore, DispatchTransport, Dispatcher, JobKey, JobState, JobTable,
    LeasedJob, ReplayAudit, SelectSql, TargetAction, TransitionAudit, TransitionOutcome,
};
use registry_platform_dispatch::{
    idempotency_key, AttemptTimeoutBound, Backoff, ConfigError, DispatchError, FailureCode, Jitter,
    JobPolicy, RetrySchedule, SendOutcome, Sent, UncertainOutcome, MAX_ATTEMPT_TIMEOUT,
};
use registry_platform_objectstore::{
    HttpVerifier, HttpVerifierSettings, Verdict, VerifierError, VerifierNamespace,
};
use serde_json::json;
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;

use crate::audit::{DocumentsAudit, CONTENT_VERIFICATION_EVENT};
use crate::config::ContentVerificationConfig;
use crate::content::{digest_hex, ContentStorage};
use crate::store::{PostgresStore, StoreError};
use crate::transfer::TransferBudget;

/// The verification job table, in the shape `registry-platform-dispatch`
/// declares.
pub const JOB_TABLE: &str = "documents_verification_jobs";

/// The binding recorded when no verifier is configured.
pub const DISABLED_BINDING: &str = "disabled";

/// The domain the job part is derived under.
const JOB_DOMAIN: &[u8] = b"documents-content-verification-v1";
/// The binding domain of the HTTP verifier.
const HTTP_BINDING_DOMAIN: &str = "documents-content-verification-http-v1";

/// The attempts one verification job may use. With a 30 second initial
/// delay doubling to a one hour maximum and equal jitter, the expected span
/// of every retry is about seven days.
pub const MAXIMUM_ATTEMPTS: i16 = 231;

/// The failure code of a job whose verifier binding is no longer current.
const SUPERSEDED: &str = "binding-superseded";

/// The part of a version's job under one verifier binding.
#[must_use]
pub fn job_part(version_id: Uuid, binding: &str) -> String {
    idempotency_key(JOB_DOMAIN, &[version_id.as_bytes(), binding.as_bytes()])
}

/// The dispatch policy every verification job runs under.
#[must_use]
pub fn verification_policy() -> JobPolicy {
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

/// The job table the verification jobs live in, under `schema`.
pub fn job_table(schema: &str) -> Result<JobTable, ConfigError> {
    JobTable::new(schema, JOB_TABLE, "version_id", "part")
}

/// The most dead letters one operator listing returns.
pub const MAXIMUM_DEAD_LETTER_LISTING: u16 = 500;

/// A dead-lettered content verification job, as an operator lists it.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeadLetter {
    pub version_id: Uuid,
    /// The generation a replay names as `--expected-generation`.
    pub generation: i64,
    pub attempt: i16,
    /// When the job was dead-lettered, in UTC, RFC 3339 to the second.
    pub dead_lettered_at: String,
}

/// A replayed job: pending again, at attempt zero, under a new generation.
#[derive(Clone, Debug, Eq, PartialEq, serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Replayed {
    pub version_id: Uuid,
    pub generation: i64,
}

/// Why an operator replay was refused. A refused replay changes nothing.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ReplayRefusal {
    #[error("the version has no content verification job under its verifier binding")]
    NotFound,
    #[error("the content verification job is {state}; only a dead-lettered job is replayed")]
    NotDeadLettered { state: String },
    #[error("the content verification job is at generation {current}; name it with --expected-generation {current}")]
    StaleGeneration { current: i64 },
    #[error("the content verification job changed while it was replayed; list the dead letters and try again")]
    Changed,
}

/// A replay that was refused, or that could not reach the database.
#[derive(Debug, thiserror::Error)]
pub enum ReplayError {
    #[error(transparent)]
    Refused(#[from] ReplayRefusal),
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl From<tokio_postgres::Error> for ReplayError {
    fn from(error: tokio_postgres::Error) -> Self {
        Self::Store(StoreError::Query(error))
    }
}

/// The oldest `limit` dead-lettered jobs under each version's current
/// verifier binding. It reads and changes nothing else.
pub async fn dead_letters(
    store: &PostgresStore,
    limit: u16,
) -> Result<Vec<DeadLetter>, StoreError> {
    let limit = i64::from(limit.min(MAXIMUM_DEAD_LETTER_LISTING));
    let client = store.client().await?;
    let rows = client
        .query(
            "SELECT j.version_id, j.part, j.generation, j.attempt,
                    to_char(j.dead_lettered_at AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"'),
                    v.verification_binding_digest
               FROM documents_verification_jobs j
               JOIN documents_versions v ON v.version_id = j.version_id
              WHERE j.state = 'dead-lettered'
              ORDER BY j.dead_lettered_at, j.version_id
              LIMIT $1",
            &[&limit],
        )
        .await?;
    let mut letters = Vec::with_capacity(rows.len());
    for row in rows {
        let version_id: Uuid = row.try_get(0)?;
        let part: String = row.try_get(1)?;
        let binding: Option<String> = row.try_get(5)?;
        // A job under a binding the version no longer carries is not the
        // one a replay reaches; the startup sweep gave the version another.
        if binding.is_some_and(|binding| job_part(version_id, &binding) == part) {
            letters.push(DeadLetter {
                version_id,
                generation: row.try_get(2)?,
                attempt: row.try_get(3)?,
                dead_lettered_at: row.try_get(4)?,
            });
        }
    }
    Ok(letters)
}

/// Return the dead-lettered job of `version_id` under its current verifier
/// binding to pending, at attempt zero under the next generation, through
/// the dispatcher's generation-checked replay. The version stays pending
/// and suspended until the job's verdict. Every other job is refused.
pub async fn replay(
    store: &PostgresStore,
    dispatcher: &Dispatcher<VerificationStore>,
    version_id: Uuid,
    expected_generation: i64,
) -> Result<Replayed, ReplayError> {
    let client = store.client().await?;
    let binding: Option<String> = client
        .query_opt(
            "SELECT verification_binding_digest FROM documents_versions WHERE version_id = $1",
            &[&version_id],
        )
        .await?
        .map(|row| row.try_get(0))
        .transpose()?
        .flatten();
    let binding = binding.ok_or(ReplayRefusal::NotFound)?;
    let part = job_part(version_id, &binding);
    let row = client
        .query_opt(
            "SELECT state, generation FROM documents_verification_jobs
              WHERE version_id = $1 AND part = $2",
            &[&version_id, &part],
        )
        .await?
        .ok_or(ReplayRefusal::NotFound)?;
    drop(client);
    let state: String = row.try_get(0)?;
    let current: i64 = row.try_get(1)?;
    if state != JobState::DeadLettered.as_str() {
        return Err(ReplayRefusal::NotDeadLettered { state }.into());
    }
    if current != expected_generation {
        return Err(ReplayRefusal::StaleGeneration { current }.into());
    }
    let key = JobKey::new(version_id, part).map_err(|_| ReplayRefusal::NotFound)?;
    let generation = dispatcher
        .replay(&key, expected_generation)
        .await
        .map_err(|_| ReplayRefusal::Changed)?;
    Ok(Replayed {
        version_id,
        generation,
    })
}

/// Where a verdict comes from: the configured HTTP verifier, or no
/// verifier at all.
#[async_trait]
pub trait VerdictSource: Send + Sync {
    /// The binding a verdict is recorded under.
    fn binding_digest(&self) -> &str;

    /// The verdict on `bytes`, whose lowercase hex SHA-256 is `sha256`.
    async fn verdict(
        &self,
        sha256: &str,
        media_type: &str,
        bytes: Vec<u8>,
    ) -> Result<Verdict, VerifierError>;
}

/// No verifier: every version is approved under the `disabled` binding.
/// Accepted only beside a development loopback listener.
#[derive(Debug)]
pub struct DisabledVerifier;

#[async_trait]
impl VerdictSource for DisabledVerifier {
    fn binding_digest(&self) -> &str {
        DISABLED_BINDING
    }

    async fn verdict(&self, _: &str, _: &str, _: Vec<u8>) -> Result<Verdict, VerifierError> {
        Ok(Verdict::Approved)
    }
}

#[async_trait]
impl VerdictSource for HttpVerifier {
    fn binding_digest(&self) -> &str {
        HttpVerifier::binding_digest(self)
    }

    async fn verdict(
        &self,
        sha256: &str,
        media_type: &str,
        bytes: Vec<u8>,
    ) -> Result<Verdict, VerifierError> {
        self.verify(sha256, media_type, bytes).await
    }
}

/// Activate the verifier `config` names. Nothing is sent.
pub fn activate_verifier(
    config: &ContentVerificationConfig,
    max_content_bytes: u64,
    resolver: &SecretResolver,
) -> Result<Arc<dyn VerdictSource>, VerifierError> {
    match config {
        ContentVerificationConfig::Disabled {} => Ok(Arc::new(DisabledVerifier)),
        ContentVerificationConfig::Http { settings } => {
            let verifier = HttpVerifierSettings::from_config(settings)?.activate(
                VerifierNamespace {
                    binding_domain: HTTP_BINDING_DOMAIN,
                    max_content_bytes,
                },
                resolver,
            )?;
            Ok(Arc::new(verifier))
        }
    }
}

/// What one verification attempt found.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum VerificationDetail {
    /// The verifier approved the content under `binding`.
    Approved { binding: String },
    /// The verifier rejected the content under `binding`.
    Rejected { binding: String },
    /// The job's binding is no longer the current one.
    Superseded,
    /// No verdict: the content could not be read or checked, or the
    /// verifier did not answer.
    Failed,
}

/// The attempt outcome a verifier answer leads to. A verdict, either way,
/// delivers the job; anything else is retried and can never approve or
/// reject.
#[must_use]
pub fn outcome_for(
    result: Result<Verdict, VerifierError>,
    binding: &str,
) -> Sent<VerificationDetail> {
    match result {
        Ok(verdict) => Sent {
            outcome: SendOutcome::Accepted {
                receiver_reference: None,
            },
            detail: match verdict {
                Verdict::Approved => VerificationDetail::Approved {
                    binding: binding.to_owned(),
                },
                Verdict::Rejected => VerificationDetail::Rejected {
                    binding: binding.to_owned(),
                },
            },
        },
        Err(error) => {
            tracing::warn!(error = %error, "content verification did not answer; the version stays pending");
            failed()
        }
    }
}

fn failed() -> Sent<VerificationDetail> {
    Sent {
        outcome: SendOutcome::Transient { retry_after: None },
        detail: VerificationDetail::Failed,
    }
}

/// One claimed verification job: the version's recorded content and the
/// binding it was finalized or re-armed under.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerificationJob {
    pub version_id: Uuid,
    pub media_type: String,
    pub computed_digest: String,
    pub length: u64,
    pub object_id: Option<Uuid>,
    /// The verifier binding the version is currently recorded under.
    pub binding: String,
}

const JOB_COLUMNS: &str = "version.media_type, version.computed_digest, version.length, \
     version.object_id, version.verification_binding_digest";
const JOB_JOINS: &str =
    "JOIN {schema}.documents_versions AS version ON version.version_id = state.version_id";

fn select() -> SelectSql {
    SelectSql {
        columns: JOB_COLUMNS,
        joins: JOB_JOINS,
        predicate: "TRUE",
    }
}

fn decode_job(row: &Row, first: usize) -> Result<VerificationJob, DispatchError> {
    let media_type: String = row.try_get(first)?;
    let computed_digest: Option<String> = row.try_get(first + 1)?;
    let length: i64 = row.try_get(first + 2)?;
    let object_id: Option<Uuid> = row.try_get(first + 3)?;
    let binding: String = row.try_get(first + 4)?;
    Ok(VerificationJob {
        version_id: row.try_get(0)?,
        media_type,
        computed_digest: computed_digest.ok_or(DispatchError::Unavailable)?,
        length: u64::try_from(length).map_err(|_| DispatchError::Unavailable)?,
        object_id,
        binding,
    })
}

struct PooledClient(deadpool_postgres::Client);

impl Deref for PooledClient {
    type Target = tokio_postgres::Client;

    fn deref(&self) -> &tokio_postgres::Client {
        &self.0
    }
}

impl DerefMut for PooledClient {
    fn deref_mut(&mut self) -> &mut tokio_postgres::Client {
        &mut self.0
    }
}

/// The Document Store consumer of the platform dispatch core.
pub struct VerificationStore {
    store: PostgresStore,
    schema: String,
    audit: DocumentsAudit,
}

impl VerificationStore {
    #[must_use]
    pub fn new(store: PostgresStore, schema: String, audit: DocumentsAudit) -> Self {
        Self {
            store,
            schema,
            audit,
        }
    }

    async fn append(
        &self,
        request: bool,
        correlation: String,
        record: serde_json::Value,
    ) -> Result<(), DispatchError> {
        let written = if request {
            self.audit.request(&correlation, record).await
        } else {
            self.audit.response(&correlation, record).await
        };
        written.map_err(|error| {
            tracing::error!(error = %error, "the content verification audit entry could not be written");
            DispatchError::Unavailable
        })
    }
}

/// The dispatcher over the verification jobs in `schema`.
pub fn dispatcher(store: VerificationStore) -> Result<Dispatcher<VerificationStore>, ConfigError> {
    let table = job_table(&store.schema)?;
    Dispatcher::new(
        store,
        DispatchConfig {
            table,
            sql: DispatchSql {
                claim: select(),
                lapsed: select(),
                expiry: None,
                target: select(),
            },
            attempt_timeout: AttemptTimeoutBound::new(Duration::from_secs(1), MAX_ATTEMPT_TIMEOUT)?,
            replayable: &[JobState::DeadLettered],
        },
    )
}

#[async_trait]
impl DispatchStore for VerificationStore {
    type Job = VerificationJob;
    type Record = Uuid;
    type Detail = VerificationDetail;
    type Context = ();

    fn capture_context(&self) {}

    async fn connection(&self) -> Result<DispatchConnection, DispatchError> {
        let client = self.store.client().await.map_err(|error| {
            tracing::error!(error = %error, "the content verification worker could not reach the database");
            DispatchError::Unavailable
        })?;
        Ok(Box::new(PooledClient(client)))
    }

    async fn verify_transaction(&self, transaction: &Transaction<'_>) -> Result<(), DispatchError> {
        let schema: Option<String> = transaction
            .query_one("SELECT current_schema()", &[])
            .await?
            .try_get(0)?;
        if schema.as_deref() == Some(self.schema.as_str()) {
            Ok(())
        } else {
            Err(DispatchError::Unavailable)
        }
    }

    fn decode_claim(
        &self,
        row: &Row,
        first: usize,
    ) -> Result<Decoded<VerificationJob>, ClaimRefusal> {
        decode_job(row, first)
            .map(|job| Decoded {
                policy: verification_policy(),
                job,
            })
            .map_err(|_| ClaimRefusal::Unavailable)
    }

    fn claim_record(&self, job: &VerificationJob) -> Uuid {
        job.version_id
    }

    fn decode_lapsed(&self, row: &Row, _first: usize) -> Result<Decoded<Uuid>, DispatchError> {
        Ok(Decoded {
            policy: verification_policy(),
            job: row.try_get(0)?,
        })
    }

    fn decode_expired(&self, row: &Row, _first: usize) -> Result<Uuid, DispatchError> {
        Ok(row.try_get(0)?)
    }

    /// The record of a targeted job is its version. The target row leads
    /// with the dispatch columns, so the version is read from the key.
    fn decode_target(
        &self,
        _row: &Row,
        _first: usize,
        key: &JobKey,
        _action: TargetAction,
    ) -> Result<Option<Uuid>, DispatchError> {
        Ok(Some(key.id()))
    }

    async fn write_attempt(
        &self,
        transaction: &Transaction<'_>,
        job: &LeasedJob<VerificationJob>,
        audit: AttemptAudit<'_, VerificationDetail>,
    ) -> Result<(), DispatchError> {
        let AttemptAudit::Finished { sent, .. } = audit else {
            return Ok(());
        };
        let version_id = job.key.id();
        let digest = &job.job.computed_digest;
        let statement = match &sent.detail {
            VerificationDetail::Approved { binding } => Some((
                "UPDATE documents_versions
                    SET verification_state = 'approved', eligibility = 'releasable',
                        verified_binding_digest = $2, verified_digest = $3,
                        verified_media_type = media_type, verified_at = transaction_timestamp()
                  WHERE version_id = $1 AND upload_state = 'finalized'
                    AND verification_state <> 'rejected' AND erasure_state = 'none'
                    AND verification_binding_digest = $2 AND computed_digest = $3
                    AND media_type = $4",
                binding,
            )),
            VerificationDetail::Rejected { binding } => Some((
                "UPDATE documents_versions
                    SET verification_state = 'rejected', eligibility = 'suspended',
                        verified_binding_digest = $2, verified_digest = $3,
                        verified_media_type = media_type, verified_at = transaction_timestamp()
                  WHERE version_id = $1 AND upload_state = 'finalized'
                    AND erasure_state = 'none'
                    AND verification_binding_digest = $2 AND computed_digest = $3
                    AND media_type = $4",
                binding,
            )),
            VerificationDetail::Superseded | VerificationDetail::Failed => None,
        };
        if let Some((sql, binding)) = statement {
            let changed = transaction
                .execute(sql, &[&version_id, binding, digest, &job.job.media_type])
                .await?;
            if changed == 0 {
                return unrecorded_verdict(transaction, version_id, binding).await;
            }
        }
        Ok(())
    }

    async fn record_attempt_audit(
        &self,
        job: &LeasedJob<VerificationJob>,
        audit: AttemptAudit<'_, VerificationDetail>,
        _context: &(),
    ) -> Result<(), DispatchError> {
        let correlation = format!("{}:{}:{}", job.key.id(), job.generation, job.attempt);
        let base = |outcome: &str, disposition: &str, verdict: Option<&str>| {
            json!({
                "event": CONTENT_VERIFICATION_EVENT,
                "versionId": job.key.id().to_string(),
                "generation": job.generation,
                "attempt": job.attempt,
                "outcome": outcome,
                "disposition": disposition,
                "verdict": verdict,
            })
        };
        match audit {
            AttemptAudit::Started => {
                self.append(true, correlation, base("requested", "leased", None))
                    .await
            }
            AttemptAudit::Finished { sent, disposition } => {
                let verdict = match &sent.detail {
                    VerificationDetail::Approved { .. } => "approved",
                    VerificationDetail::Rejected { .. } => "rejected",
                    VerificationDetail::Superseded => "superseded",
                    VerificationDetail::Failed => "none",
                };
                self.append(
                    false,
                    correlation,
                    base("committed", disposition.as_str(), Some(verdict)),
                )
                .await
            }
            AttemptAudit::Interrupted { disposition } => {
                self.append(
                    false,
                    correlation,
                    base("interrupted", disposition.as_str(), None),
                )
                .await
            }
        }
    }

    async fn record_transition_audit(
        &self,
        audit: &TransitionAudit<Uuid>,
        outcome: TransitionOutcome,
        _context: &(),
    ) -> Result<(), DispatchError> {
        let outcome = match outcome {
            TransitionOutcome::Committed => "committed",
            TransitionOutcome::Refused => "refused",
            TransitionOutcome::Unfinished => "unfinished",
        };
        let correlation = format!(
            "{}:{}:{}:{}",
            audit.key.id(),
            audit.generation,
            audit.attempt,
            audit.transition.as_str()
        );
        let record = json!({
            "event": CONTENT_VERIFICATION_EVENT,
            "versionId": audit.key.id().to_string(),
            "generation": audit.generation,
            "attempt": audit.attempt,
            "transition": audit.transition.as_str(),
            "outcome": outcome,
            "disposition": audit.transition.disposition().as_str(),
        });
        self.append(true, correlation.clone(), record.clone())
            .await?;
        self.append(false, correlation, record).await
    }

    async fn record_replay_audit(
        &self,
        audit: &ReplayAudit<Uuid>,
        _context: &(),
    ) -> Result<(), DispatchError> {
        let correlation = format!("{}:{}:replay", audit.key.id(), audit.generation);
        let record = json!({
            "event": CONTENT_VERIFICATION_EVENT,
            "versionId": audit.key.id().to_string(),
            "generation": audit.generation,
            "transition": "replayed",
            "from": audit.from.as_str(),
            "outcome": format!("{:?}", audit.outcome).to_lowercase(),
        });
        let request =
            audit.outcome == registry_platform_dispatch::postgres::ReplayOutcome::Requested;
        self.append(request, correlation, record).await
    }

    fn operational_event(&self, event: DispatchEvent) {
        match event {
            DispatchEvent::IterationFailed | DispatchEvent::TransitionFailed(_) => {
                tracing::error!(event = ?event, "a content verification dispatch step failed");
            }
            DispatchEvent::JobExpired | DispatchEvent::JobQuarantined(_) => {
                tracing::warn!(event = ?event, "a content verification job left the claim set");
            }
        }
    }
}

/// Decide what a verdict that changed no version row means. A version that
/// has since moved to another verifier binding, was already rejected, or
/// whose removal its custodian requested needs no verdict from this job,
/// which is delivered without one. Anything else means the version no
/// longer matches what the job read, so the attempt is refused and the job
/// is retried after its lease lapses rather than delivered with nothing
/// recorded.
async fn unrecorded_verdict(
    transaction: &Transaction<'_>,
    version_id: Uuid,
    binding: &str,
) -> Result<(), DispatchError> {
    let current = transaction
        .query_opt(
            "SELECT verification_binding_digest, verification_state, erasure_state <> 'none'
               FROM documents_versions WHERE version_id = $1",
            &[&version_id],
        )
        .await?;
    let (current_binding, state, erasing) = match &current {
        Some(row) => (
            row.try_get::<_, Option<String>>(0)?,
            row.try_get::<_, String>(1)?,
            row.try_get::<_, bool>(2)?,
        ),
        None => (None, String::new(), false),
    };
    if erasing {
        tracing::info!(
            version = %version_id,
            "a verdict arrived for a version whose erasure was requested; it was not recorded"
        );
        Ok(())
    } else if current.is_some() && current_binding.as_deref() != Some(binding) {
        tracing::info!(
            version = %version_id,
            "a verdict arrived for a version whose verifier binding has since changed; it was not recorded"
        );
        Ok(())
    } else if state == "rejected" {
        tracing::warn!(
            version = %version_id,
            "a verdict arrived for a version that is already rejected; it was not recorded"
        );
        Ok(())
    } else {
        tracing::error!(
            version = %version_id,
            "a verdict matched no version under the current verifier binding; it was not recorded and verification will retry"
        );
        Err(DispatchError::Unavailable)
    }
}

/// Reads a claimed version's content and asks the verifier. The bytes an
/// attempt holds are counted against the transfer budget uploads and
/// downloads share; an attempt waits for room rather than adding to it,
/// and waits only within its attempt timeout: `send` bounds the whole
/// attempt, the wait included, by the attempt budget left, and an attempt
/// that runs out of it ends as a transient failure, so a job never holds
/// its lease past the attempt deadline.
pub struct VerificationTransport {
    store: PostgresStore,
    storage: Arc<ContentStorage>,
    verifier: Arc<dyn VerdictSource>,
    budget: TransferBudget,
}

impl VerificationTransport {
    #[must_use]
    pub fn new(
        store: PostgresStore,
        storage: Arc<ContentStorage>,
        verifier: Arc<dyn VerdictSource>,
        budget: TransferBudget,
    ) -> Self {
        Self {
            store,
            storage,
            verifier,
            budget,
        }
    }

    async fn attempt(&self, job: &LeasedJob<VerificationJob>) -> Sent<VerificationDetail> {
        let version_id = job.key.id();
        let binding = self.verifier.binding_digest();
        // A job under a binding the version is no longer recorded under can
        // never record a verdict, whichever worker holds it.
        if job.key.part() != job_part(version_id, &job.job.binding) {
            return match FailureCode::new(SUPERSEDED) {
                Ok(code) => Sent {
                    outcome: SendOutcome::Permanent { code },
                    detail: VerificationDetail::Superseded,
                },
                Err(_) => failed(),
            };
        }
        // A current job claimed by a worker under another binding, as while
        // two instances with different verifiers run side by side, is left
        // for a worker under the version's own binding.
        if job.job.binding != binding {
            tracing::warn!(
                version = %version_id,
                "a content verification job is recorded under another verifier binding; it is left for a worker under that binding"
            );
            return failed();
        }
        // Bounded by the attempt timeout `send` applies to this whole call.
        let Some(_permit) = self.budget.reserve(job.job.length).await else {
            tracing::error!("the transfer budget is closed; verification will retry");
            return failed();
        };
        let content = self
            .storage
            .read(
                &self.store,
                version_id,
                job.job.object_id,
                &job.job.computed_digest,
                job.job.length,
            )
            .await;
        let bytes = match content {
            Ok(bytes) => bytes,
            Err(error) => {
                tracing::error!(
                    version = %version_id,
                    error = %error,
                    "stored content could not be read or failed its integrity check; verification will retry"
                );
                return failed();
            }
        };
        let Some(sha256) = digest_hex(&job.job.computed_digest) else {
            return failed();
        };
        let result = self
            .verifier
            .verdict(sha256, &job.job.media_type, bytes)
            .await;
        outcome_for(result, binding)
    }
}

#[async_trait]
impl DispatchTransport for VerificationTransport {
    type Job = VerificationJob;
    type Detail = VerificationDetail;

    async fn send(
        &self,
        job: &LeasedJob<VerificationJob>,
    ) -> Result<Sent<VerificationDetail>, DispatchError> {
        let Some(budget) = job.remaining_budget(SystemTime::now()) else {
            return Ok(failed());
        };
        match tokio::time::timeout(budget, self.attempt(job)).await {
            Ok(sent) => Ok(sent),
            Err(_) => {
                tracing::warn!(version = %job.key.id(), "a content verification attempt ran out of time");
                Ok(failed())
            }
        }
    }
}

/// Suspend every finalized, unrejected version recorded under a verifier
/// binding other than `binding`, record it under `binding`, and give it a
/// pending job under that binding. A job that already finished under the
/// same binding is re-armed as a new generation, and a pending job under any
/// other binding is cancelled, so no worker spends an attempt on a binding
/// that can no longer record a verdict. Returns how many versions were
/// suspended.
pub async fn sweep_bindings(store: &PostgresStore, binding: &str) -> Result<u64, StoreError> {
    let mut client = store.client().await?;
    let transaction = client.transaction().await?;
    let rows = transaction
        .query(
            "UPDATE documents_versions
                SET eligibility = 'suspended', verification_binding_digest = $1
              WHERE upload_state = 'finalized' AND verification_state <> 'rejected'
                AND erasure_state = 'none' AND verification_binding_digest <> $1
              RETURNING version_id",
            &[&binding],
        )
        .await?;
    for row in &rows {
        let version_id: Uuid = row.try_get(0)?;
        let part = job_part(version_id, binding);
        arm_job(&transaction, version_id, &part).await?;
        transaction
            .execute(
                "UPDATE documents_verification_jobs
                    SET state = 'cancelled', next_attempt_at = NULL,
                        updated_at = transaction_timestamp()
                  WHERE version_id = $1 AND part <> $2 AND state = 'pending'",
                &[&version_id, &part],
            )
            .await?;
    }
    transaction.commit().await?;
    Ok(rows.len() as u64)
}

/// Make the job of `version_id` under `part` pending now: insert it, or
/// re-arm it as a new generation when it already finished.
pub(crate) async fn arm_job(
    transaction: &Transaction<'_>,
    version_id: Uuid,
    part: &str,
) -> Result<(), tokio_postgres::Error> {
    transaction
        .execute(
            "INSERT INTO documents_verification_jobs
                 (version_id, part, generation, state, attempt, next_attempt_at)
             VALUES ($1, $2, 1, 'pending', 0, transaction_timestamp())
             ON CONFLICT (version_id, part) DO UPDATE
                SET generation = documents_verification_jobs.generation + 1,
                    state = 'pending', attempt = 0,
                    next_attempt_at = transaction_timestamp(),
                    attempt_started_at = NULL, lease_expires_at = NULL, lease_token = NULL,
                    delivered_at = NULL, dead_lettered_at = NULL, expired_at = NULL,
                    updated_at = transaction_timestamp()
              WHERE documents_verification_jobs.state NOT IN ('pending', 'leased')",
            &[&version_id, &part],
        )
        .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DAY_MS: i64 = 24 * 60 * 60 * 1000;

    fn span(policy: &JobPolicy, sample: impl Fn(i64) -> u64) -> i64 {
        let RetrySchedule::Backoff(backoff) = &policy.retry else {
            panic!("verification retries on backoff");
        };
        (1..policy.maximum_attempts)
            .map(|attempt| {
                let base = (30_000_i64 << (attempt - 1).min(20)).min(3_600_000);
                RetrySchedule::Backoff(*backoff)
                    .delay_after(attempt, None, sample(base))
                    .unwrap()
            })
            .sum()
    }

    #[test]
    fn retries_span_about_seven_days_and_never_expire() {
        let policy = verification_policy();
        assert!(policy.is_valid(
            &AttemptTimeoutBound::new(Duration::from_secs(1), MAX_ATTEMPT_TIMEOUT).unwrap()
        ));
        assert_eq!(policy.expires_at, None);
        let shortest = span(&policy, |_| 0);
        let longest = span(&policy, |base| u64::try_from(base / 2).unwrap());
        let expected = (shortest + longest) / 2;
        assert!(
            (6 * DAY_MS..=8 * DAY_MS).contains(&expected),
            "expected span {expected} ms"
        );
        assert!(shortest >= 4 * DAY_MS, "shortest span {shortest} ms");
    }

    #[test]
    fn the_job_part_binds_the_version_and_the_verifier() {
        let version = Uuid::new_v4();
        let part = job_part(version, "binding-a");
        assert_eq!(part, job_part(version, "binding-a"));
        assert_ne!(part, job_part(version, "binding-b"));
        assert_ne!(part, job_part(Uuid::new_v4(), "binding-a"));
        assert!(JobKey::new(version, part).is_ok());
    }

    /// SEC-17: only a verdict approves or rejects; an unavailable verifier,
    /// an integrity refusal, or a secret failure leaves the job to retry
    /// with no verdict recorded.
    #[test]
    fn only_a_verdict_approves_or_rejects() {
        let approved = outcome_for(Ok(Verdict::Approved), "b");
        assert!(matches!(approved.outcome, SendOutcome::Accepted { .. }));
        assert_eq!(
            approved.detail,
            VerificationDetail::Approved {
                binding: "b".to_owned()
            }
        );
        let rejected = outcome_for(Ok(Verdict::Rejected), "b");
        assert!(matches!(rejected.outcome, SendOutcome::Accepted { .. }));
        assert_eq!(
            rejected.detail,
            VerificationDetail::Rejected {
                binding: "b".to_owned()
            }
        );
        for error in [
            VerifierError::Unavailable,
            VerifierError::Integrity,
            VerifierError::Secret,
            VerifierError::InvalidConfiguration,
        ] {
            let sent = outcome_for(Err(error), "b");
            assert!(matches!(sent.outcome, SendOutcome::Transient { .. }));
            assert_eq!(sent.detail, VerificationDetail::Failed);
        }
    }

    #[tokio::test]
    async fn the_disabled_verifier_approves_under_its_own_binding() {
        let verifier = DisabledVerifier;
        assert_eq!(VerdictSource::binding_digest(&verifier), DISABLED_BINDING);
        assert_eq!(
            verifier.verdict("00", "application/pdf", Vec::new()).await,
            Ok(Verdict::Approved)
        );
    }
}
