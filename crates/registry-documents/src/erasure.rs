// SPDX-License-Identifier: Apache-2.0

//! Cleanup: erasure of the bytes a custodian asked to remove, expiry of
//! uploads that missed their deadline, and the sweep of orphaned objects.
//!
//! Eligibility is a query over version state, never a long-lived job per
//! object. Each cleanup pass expires every reserved upload past its
//! deadline, gives every version whose erasure is due one dispatch job, and
//! erases objects an unfinished upload left behind. The erasure job is
//! delivered only once the version's servable bytes are gone: for content
//! held in PostgreSQL, its content row is deleted; for content held in S3,
//! the object is deleted and a read of it must answer 404. The transaction
//! that records the attempt deletes what was confirmed and records the
//! version `erased`, so an attempt interrupted at any point is resumed by
//! the next one without a second erasure being recorded.
//!
//! "Erased" means this Store can no longer serve the bytes. PostgreSQL
//! returns the space of a deleted content row only after vacuum, and an
//! S3 provider's own replication or backups are outside what the Store
//! controls.
//!
//! With `cleanup.erasure: paused`, no erasure job is armed or attempted and
//! no orphaned object is erased. A removal request still stops release at
//! once, and a lapsed upload is still expired, since neither erases bytes.

use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use registry_platform_dispatch::postgres::{
    AttemptAudit, ClaimRefusal, Decoded, DispatchConfig, DispatchConnection, DispatchEvent,
    DispatchSql, DispatchStore, DispatchTransport, Dispatcher, JobKey, JobState, JobTable,
    LeasedJob, ReplayAudit, ReplayOutcome, SelectSql, TargetAction, TransitionAudit,
    TransitionOutcome,
};
use registry_platform_dispatch::{
    AttemptTimeoutBound, Backoff, ConfigError, DispatchError, Jitter, JobPolicy, RetrySchedule,
    SendOutcome, Sent, UncertainOutcome, MAX_ATTEMPT_TIMEOUT,
};
use serde_json::json;
use thiserror::Error;
use tokio_postgres::{Row, Transaction};
use uuid::Uuid;

use crate::audit::{DocumentsAudit, ERASURE_EVENT, ORPHAN_ERASURE_EVENT, UPLOAD_EXPIRY_EVENT};
use crate::config::Erasure;
use crate::content::ContentStorage;
use crate::store::{PostgresStore, StoreError};

/// The erasure job table, in the shape `registry-platform-dispatch`
/// declares.
pub const JOB_TABLE: &str = "documents_erasure_jobs";

/// The one part of a version's erasure job: a version is erased once.
pub const JOB_PART: &str = "content";

/// The attempts one erasure job may use, spread over about seven days as
/// a verification job's are. A dead-lettered erasure leaves the version
/// pending and unservable until an operator replays it.
pub const MAXIMUM_ATTEMPTS: i16 = 231;

/// The most rows one cleanup step reads or changes at once.
const BATCH: i64 = 100;

/// The most orphaned objects one cleanup pass erases.
const ORPHAN_BATCH: i64 = 32;

/// How long an unfinished upload's object is left alone beyond the longest
/// transfer deadline, so a write still in flight is never swept.
pub const ORPHAN_MARGIN: Duration = Duration::from_secs(10 * 60);

/// The dispatch policy every erasure job runs under.
#[must_use]
pub fn erasure_policy() -> JobPolicy {
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

/// The job table the erasure jobs live in, under `schema`.
pub fn job_table(schema: &str) -> Result<JobTable, ConfigError> {
    JobTable::new(schema, JOB_TABLE, "version_id", "part")
}

/// What one erasure attempt confirmed.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ErasureDetail {
    /// Committed objects whose deletion was confirmed by a 404 read.
    pub confirmed: Vec<Uuid>,
    /// Every servable copy of the version's bytes is confirmed gone, so the
    /// recording transaction may record the version erased.
    pub complete: bool,
}

/// One claimed erasure job.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureJob {
    pub version_id: Uuid,
}

fn select() -> SelectSql {
    SelectSql {
        columns: "version.erasure_state",
        joins:
            "JOIN {schema}.documents_versions AS version ON version.version_id = state.version_id",
        predicate: "TRUE",
    }
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

/// The Document Store erasure consumer of the platform dispatch core.
pub struct ErasureStore {
    store: PostgresStore,
    schema: String,
    audit: DocumentsAudit,
}

impl ErasureStore {
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
            tracing::error!(error = %error, "the erasure audit entry could not be written");
            DispatchError::Unavailable
        })
    }
}

/// The dispatcher over the erasure jobs in `schema`.
pub fn dispatcher(store: ErasureStore) -> Result<Dispatcher<ErasureStore>, ConfigError> {
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
impl DispatchStore for ErasureStore {
    type Job = ErasureJob;
    type Record = Uuid;
    type Detail = ErasureDetail;
    type Context = ();

    fn capture_context(&self) {}

    async fn connection(&self) -> Result<DispatchConnection, DispatchError> {
        let client = self.store.client().await.map_err(|error| {
            tracing::error!(error = %error, "the erasure worker could not reach the database");
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

    fn decode_claim(&self, row: &Row, _first: usize) -> Result<Decoded<ErasureJob>, ClaimRefusal> {
        row.try_get(0)
            .map(|version_id| Decoded {
                policy: erasure_policy(),
                job: ErasureJob { version_id },
            })
            .map_err(|_| ClaimRefusal::Unavailable)
    }

    fn claim_record(&self, job: &ErasureJob) -> Uuid {
        job.version_id
    }

    fn decode_lapsed(&self, row: &Row, _first: usize) -> Result<Decoded<Uuid>, DispatchError> {
        Ok(Decoded {
            policy: erasure_policy(),
            job: row.try_get(0)?,
        })
    }

    fn decode_expired(&self, row: &Row, _first: usize) -> Result<Uuid, DispatchError> {
        Ok(row.try_get(0)?)
    }

    fn decode_target(
        &self,
        row: &Row,
        _first: usize,
        _key: &JobKey,
        _action: TargetAction,
    ) -> Result<Option<Uuid>, DispatchError> {
        Ok(Some(row.try_get(0)?))
    }

    /// Delete the rows of every object the attempt confirmed gone and, once
    /// nothing servable is left, the content row, and record the version
    /// erased. The version moves only from `pending`, so an attempt that
    /// repeats a recorded erasure changes nothing.
    async fn write_attempt(
        &self,
        transaction: &Transaction<'_>,
        job: &LeasedJob<ErasureJob>,
        audit: AttemptAudit<'_, ErasureDetail>,
    ) -> Result<(), DispatchError> {
        let AttemptAudit::Finished { sent, .. } = audit else {
            return Ok(());
        };
        let version_id = job.key.id();
        if !sent.detail.confirmed.is_empty() {
            transaction
                .execute(
                    "DELETE FROM documents_staged_objects
                      WHERE version_id = $1 AND committed AND object_id = ANY($2)",
                    &[&version_id, &sent.detail.confirmed],
                )
                .await?;
        }
        if sent.detail.complete {
            transaction
                .execute(
                    "DELETE FROM documents_contents WHERE version_id = $1",
                    &[&version_id],
                )
                .await?;
            transaction
                .execute(
                    "UPDATE documents_versions
                        SET erasure_state = 'erased', erased_at = transaction_timestamp()
                      WHERE version_id = $1 AND erasure_state = 'pending'",
                    &[&version_id],
                )
                .await?;
        }
        Ok(())
    }

    async fn record_attempt_audit(
        &self,
        job: &LeasedJob<ErasureJob>,
        audit: AttemptAudit<'_, ErasureDetail>,
        _context: &(),
    ) -> Result<(), DispatchError> {
        let correlation = format!("{}:{}:{}", job.key.id(), job.generation, job.attempt);
        let base = |outcome: &str, disposition: &str| {
            json!({
                "event": ERASURE_EVENT,
                "versionId": job.key.id().to_string(),
                "generation": job.generation,
                "attempt": job.attempt,
                "outcome": outcome,
                "disposition": disposition,
            })
        };
        match audit {
            AttemptAudit::Started => {
                self.append(true, correlation, base("requested", "leased"))
                    .await
            }
            AttemptAudit::Finished { sent, disposition } => {
                let mut record = base(
                    if sent.detail.complete {
                        "erased"
                    } else {
                        "incomplete"
                    },
                    disposition.as_str(),
                );
                record["confirmedObjects"] = json!(sent.detail.confirmed.len());
                self.append(false, correlation, record).await
            }
            AttemptAudit::Interrupted { disposition } => {
                self.append(
                    false,
                    correlation,
                    base("interrupted", disposition.as_str()),
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
            "event": ERASURE_EVENT,
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
            "event": ERASURE_EVENT,
            "versionId": audit.key.id().to_string(),
            "generation": audit.generation,
            "transition": "replayed",
            "from": audit.from.as_str(),
            "outcome": format!("{:?}", audit.outcome).to_lowercase(),
        });
        let request = audit.outcome == ReplayOutcome::Requested;
        self.append(request, correlation, record).await
    }

    fn operational_event(&self, event: DispatchEvent) {
        match event {
            DispatchEvent::IterationFailed | DispatchEvent::TransitionFailed(_) => {
                tracing::error!(event = ?event, "an erasure dispatch step failed");
            }
            DispatchEvent::JobExpired | DispatchEvent::JobQuarantined(_) => {
                tracing::warn!(event = ?event, "an erasure job left the claim set");
            }
        }
    }
}

/// Erases a claimed version's servable bytes. Content held in PostgreSQL
/// is erased by the recording transaction itself; an object in S3 is
/// deleted here and confirmed gone by a read that answers 404.
pub struct ErasureTransport {
    store: PostgresStore,
    storage: Arc<ContentStorage>,
}

impl ErasureTransport {
    #[must_use]
    pub fn new(store: PostgresStore, storage: Arc<ContentStorage>) -> Self {
        Self { store, storage }
    }

    async fn attempt(&self, version_id: Uuid) -> Sent<ErasureDetail> {
        if matches!(self.storage.as_ref(), ContentStorage::Database { .. }) {
            return delivered(Vec::new());
        }
        // Only a committed object can be served. An object an unfinished
        // upload left uncommitted is the orphan sweep's.
        let rows = match self.committed_objects(version_id).await {
            Ok(rows) => rows,
            Err(error) => {
                tracing::error!(version = %version_id, error = %error, "the objects to erase could not be read; erasure will retry");
                return incomplete(Vec::new());
            }
        };
        let mut confirmed = Vec::with_capacity(rows.len());
        for (object_id, binding, sha256) in rows {
            match self.delete(object_id, &binding, &sha256).await {
                Ok(()) => confirmed.push(object_id),
                Err(error) => {
                    tracing::warn!(version = %version_id, error = %error, "an object was not confirmed erased; erasure will retry");
                    return incomplete(confirmed);
                }
            }
        }
        delivered(confirmed)
    }

    async fn committed_objects(
        &self,
        version_id: Uuid,
    ) -> Result<Vec<(Uuid, String, String)>, CleanupError> {
        let client = self.store.client().await?;
        let rows = client
            .query(
                "SELECT object_id, binding_digest, sha256 FROM documents_staged_objects
                  WHERE version_id = $1 AND committed",
                &[&version_id],
            )
            .await?;
        rows.iter()
            .map(|row| Ok((row.try_get(0)?, row.try_get(1)?, row.try_get(2)?)))
            .collect()
    }

    async fn delete(
        &self,
        object_id: Uuid,
        binding: &str,
        sha256: &str,
    ) -> Result<(), CleanupError> {
        delete_object(&self.storage, object_id, binding, sha256).await
    }
}

fn delivered(confirmed: Vec<Uuid>) -> Sent<ErasureDetail> {
    Sent {
        outcome: SendOutcome::Accepted {
            receiver_reference: None,
        },
        detail: ErasureDetail {
            confirmed,
            complete: true,
        },
    }
}

fn incomplete(confirmed: Vec<Uuid>) -> Sent<ErasureDetail> {
    Sent {
        outcome: SendOutcome::Transient { retry_after: None },
        detail: ErasureDetail {
            confirmed,
            complete: false,
        },
    }
}

/// Delete one object under the scope it was staged in and confirm it gone.
/// An object whose recorded binding is not this deployment's is never
/// touched.
async fn delete_object(
    storage: &ContentStorage,
    object_id: Uuid,
    binding: &str,
    sha256: &str,
) -> Result<(), CleanupError> {
    let object = storage.object(object_id).await?;
    if object.binding_digest() != binding {
        return Err(CleanupError::BindingMismatch);
    }
    object.delete(sha256).await?;
    Ok(())
}

#[async_trait]
impl DispatchTransport for ErasureTransport {
    type Job = ErasureJob;
    type Detail = ErasureDetail;

    async fn send(
        &self,
        job: &LeasedJob<ErasureJob>,
    ) -> Result<Sent<ErasureDetail>, DispatchError> {
        let Some(budget) = job.remaining_budget(SystemTime::now()) else {
            return Ok(incomplete(Vec::new()));
        };
        match tokio::time::timeout(budget, self.attempt(job.key.id())).await {
            Ok(sent) => Ok(sent),
            Err(_) => {
                tracing::warn!(version = %job.key.id(), "an erasure attempt ran out of time");
                Ok(incomplete(Vec::new()))
            }
        }
    }
}

/// A cleanup step failed. No variant carries a URL, an object key, a
/// credential, or a backend response.
#[derive(Debug, Error)]
pub enum CleanupError {
    #[error("the cleanup query failed: {0}")]
    Query(#[from] tokio_postgres::Error),
    #[error("the cleanup connection failed: {0}")]
    Store(#[from] StoreError),
    #[error("the cleanup storage step failed: {0}")]
    Storage(#[from] crate::content::StorageError),
    #[error("object storage refused: {0}")]
    Object(#[from] registry_platform_objectstore::ObjectStoreError),
    #[error("an object's recorded binding is not this deployment's")]
    BindingMismatch,
    #[error("the cleanup audit entry could not be written")]
    Audit,
}

/// What one cleanup pass changed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct CleanupPass {
    /// Reserved uploads past their deadline, now expired.
    pub expired_uploads: u64,
    /// Versions due for erasure that were given their erasure job.
    pub armed_erasures: u64,
    /// Orphaned objects erased.
    pub erased_orphans: u64,
}

/// One cleanup pass. Uploads past their deadline are expired whatever the
/// erasure setting; erasure jobs are armed and orphaned objects older than
/// `orphan_age` erased only while erasure is active.
pub async fn cleanup_once(
    store: &PostgresStore,
    storage: &ContentStorage,
    audit: &DocumentsAudit,
    erasure: Erasure,
    orphan_age: Duration,
) -> Result<CleanupPass, CleanupError> {
    let mut pass = CleanupPass {
        expired_uploads: expire_uploads(store, audit).await?,
        ..CleanupPass::default()
    };
    if erasure == Erasure::Active {
        pass.armed_erasures = arm_due_erasures(store).await?;
        pass.erased_orphans = erase_orphans(store, storage, audit, orphan_age).await?;
    }
    Ok(pass)
}

/// Expire every reserved upload past its deadline, a batch per
/// transaction. Each batch's request entry is written before it commits.
async fn expire_uploads(
    store: &PostgresStore,
    audit: &DocumentsAudit,
) -> Result<u64, CleanupError> {
    let mut expired = 0;
    loop {
        let mut client = store.client().await?;
        let transaction = client.transaction().await?;
        // Served by documents_versions_upload_expiry_idx.
        let rows = transaction
            .query(
                "SELECT version_id FROM documents_versions
                  WHERE upload_state = 'reserved' AND upload_expires_at <= transaction_timestamp()
                  ORDER BY upload_expires_at
                  LIMIT $1 FOR UPDATE SKIP LOCKED",
                &[&BATCH],
            )
            .await?;
        let ids = rows
            .iter()
            .map(|row| row.try_get(0))
            .collect::<Result<Vec<Uuid>, _>>()?;
        if ids.is_empty() {
            return Ok(expired);
        }
        let names = json!(ids.iter().map(Uuid::to_string).collect::<Vec<_>>());
        let request = audit
            .begin(
                UPLOAD_EXPIRY_EVENT,
                json!({"event": UPLOAD_EXPIRY_EVENT, "versionIds": names}),
            )
            .await
            .map_err(|_| CleanupError::Audit)?;
        transaction
            .execute(
                "UPDATE documents_versions SET upload_state = 'expired'
                  WHERE version_id = ANY($1) AND upload_state = 'reserved'",
                &[&ids],
            )
            .await?;
        transaction.commit().await?;
        request
            .finish(
                json!({"event": UPLOAD_EXPIRY_EVENT, "outcome": "expired", "versionIds": names}),
            )
            .await
            .map_err(|_| CleanupError::Audit)?;
        expired += ids.len() as u64;
        if (ids.len() as i64) < BATCH {
            return Ok(expired);
        }
    }
}

/// Give every version whose erasure is due its one erasure job. A version
/// that already has one, in whatever state, keeps it: a dead-lettered
/// erasure waits for an operator's replay rather than being re-armed.
async fn arm_due_erasures(store: &PostgresStore) -> Result<u64, CleanupError> {
    let client = store.client().await?;
    // The candidates are read through documents_versions_erasure_due_idx,
    // and the existing job through the job table's primary key.
    let armed = client
        .execute(
            "INSERT INTO documents_erasure_jobs
                 (version_id, part, generation, state, attempt, next_attempt_at)
             SELECT version.version_id, $1, 1, 'pending', 0, transaction_timestamp()
               FROM documents_versions AS version
              WHERE version.erasure_state = 'pending'
                AND version.erasure_due_at <= transaction_timestamp()
                AND NOT EXISTS (SELECT 1 FROM documents_erasure_jobs AS job
                                 WHERE job.version_id = version.version_id AND job.part = $1)
             ON CONFLICT (version_id, part) DO NOTHING",
            &[&JOB_PART],
        )
        .await?;
    Ok(armed)
}

/// Erase objects an unfinished upload left uncommitted once they are older
/// than `orphan_age`. Each object's row is locked for the length of its
/// erasure, so a late commit of the same object waits and then finds no
/// row, and the row is deleted only once the object is confirmed gone.
async fn erase_orphans(
    store: &PostgresStore,
    storage: &ContentStorage,
    audit: &DocumentsAudit,
    orphan_age: Duration,
) -> Result<u64, CleanupError> {
    if matches!(storage, ContentStorage::Database { .. }) {
        return Ok(0);
    }
    let age = i64::try_from(orphan_age.as_secs()).unwrap_or(i64::MAX);
    let mut erased = 0;
    for _ in 0..ORPHAN_BATCH {
        let mut client = store.client().await?;
        let transaction = client.transaction().await?;
        // Served by documents_staged_objects_orphan_idx.
        let Some(row) = transaction
            .query_opt(
                "SELECT object_id, version_id, binding_digest, sha256
                   FROM documents_staged_objects
                  WHERE NOT committed
                    AND staged_at <= transaction_timestamp() - make_interval(secs => $1::bigint)
                  ORDER BY staged_at
                  LIMIT 1 FOR UPDATE SKIP LOCKED",
                &[&age],
            )
            .await?
        else {
            break;
        };
        let object_id: Uuid = row.try_get(0)?;
        let version_id: Uuid = row.try_get(1)?;
        let binding: String = row.try_get(2)?;
        let sha256: String = row.try_get(3)?;
        let record = json!({
            "event": ORPHAN_ERASURE_EVENT,
            "objectId": object_id.to_string(),
            "versionId": version_id.to_string(),
        });
        let request = audit
            .begin(ORPHAN_ERASURE_EVENT, record.clone())
            .await
            .map_err(|_| CleanupError::Audit)?;
        if let Err(error) = delete_object(storage, object_id, &binding, &sha256).await {
            tracing::warn!(object = %object_id, error = %error, "an orphaned object was not confirmed erased; the next pass retries it");
            let mut refused = record;
            refused["outcome"] = json!("refused");
            request
                .finish(refused)
                .await
                .map_err(|_| CleanupError::Audit)?;
            return Err(error);
        }
        transaction
            .execute(
                "DELETE FROM documents_staged_objects WHERE object_id = $1 AND NOT committed",
                &[&object_id],
            )
            .await?;
        transaction.commit().await?;
        let mut done = record;
        done["outcome"] = json!("erased");
        request
            .finish(done)
            .await
            .map_err(|_| CleanupError::Audit)?;
        erased += 1;
    }
    Ok(erased)
}

/// What an operator sees of erasure: the setting, and how many versions
/// wait for it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ErasureStatus {
    pub erasure: Erasure,
    /// Versions whose erasure was requested and whose grace has not ended.
    pub awaiting_grace: i64,
    /// Versions whose grace has ended and whose bytes are not yet erased.
    pub due: i64,
    /// Erasure jobs that used every attempt and wait for a replay.
    pub dead_lettered: i64,
}

/// The erasure status of the deployment behind `store`, under the setting
/// its runtime document names.
pub async fn erasure_status(
    store: &PostgresStore,
    erasure: Erasure,
) -> Result<ErasureStatus, StoreError> {
    let client = store.client().await?;
    let row = client
        .query_one(
            "SELECT
                 (SELECT count(*) FROM documents_versions
                   WHERE erasure_state = 'pending' AND erasure_due_at > now()),
                 (SELECT count(*) FROM documents_versions
                   WHERE erasure_state = 'pending' AND erasure_due_at <= now()),
                 (SELECT count(*) FROM documents_erasure_jobs WHERE state = 'dead-lettered')",
            &[],
        )
        .await?;
    Ok(ErasureStatus {
        erasure,
        awaiting_grace: row.try_get(0)?,
        due: row.try_get(1)?,
        dead_lettered: row.try_get(2)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_erasure_is_delivered_only_when_complete() {
        let done = delivered(vec![Uuid::nil()]);
        assert!(done.detail.complete);
        assert!(matches!(done.outcome, SendOutcome::Accepted { .. }));
        let partial = incomplete(vec![Uuid::nil()]);
        assert!(!partial.detail.complete);
        assert_eq!(partial.detail.confirmed, vec![Uuid::nil()]);
        assert!(matches!(partial.outcome, SendOutcome::Transient { .. }));
    }

    #[test]
    fn an_erasure_job_retries_for_days_before_it_dead_letters() {
        let policy = erasure_policy();
        assert_eq!(policy.maximum_attempts, MAXIMUM_ATTEMPTS);
        assert_eq!(policy.on_uncertain, UncertainOutcome::Retry);
        assert!(policy.expires_at.is_none());
    }
}
