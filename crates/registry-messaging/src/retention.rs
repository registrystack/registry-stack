// SPDX-License-Identifier: Apache-2.0

//! Retention: what the deployment's `retention` periods erase, and when.
//!
//! Every period counts from a fixed instant the store already holds:
//!
//! - a message's payload, its recipient contact and rendered parts, is
//!   erased `payloadDays` after its dispatch job reached a terminal state
//!   (`delivered`, `dead_lettered`, `expired`, or `cancelled`), and the
//!   content-free message record stays;
//! - the message record is deleted `recordDays` after that terminal state,
//!   and its payload, job, attempts, delivery receipts, and idempotency
//!   record go with it;
//! - a submission receipt, the stored answer an idempotent replay returns,
//!   is erased when its `submissionReceiptDays` end, and its key stays
//!   spent until the record goes.
//!
//! A message still pending, leased, or in an unknown outcome is never
//! erased, whatever its age: its payload may yet be sent, requeued, or
//! settled. A terminal job is locked while its payload is erased, so an
//! operator requeue either happens first, and the message is skipped, or
//! after, and the requeued message fails as `payload-erased` without a send.
//!
//! One run is one transaction under one advisory lock, so two runs never
//! interleave, and it writes its audit record into the outbox in that
//! transaction. The runtime runs it on an interval with its own credential;
//! `messagingctl retention erase-expired` runs it with the migration
//! credential, as a preview unless applied. A cutoff later than the
//! database's clock is refused: retention erases what has expired, never
//! what will.

use std::time::{Duration, SystemTime};

use serde::Serialize;
use serde_json::{json, Value};
use thiserror::Error;
use tokio::sync::watch;
use tokio_postgres::Transaction;

use crate::config::RetentionConfig;
use crate::dispatch::Actor;
use crate::messages::format_instant;
use crate::outbox;
use crate::store::{PostgresStore, StoreError};

/// The event a retention run journals.
pub const RETENTION_ERASED_EVENT: &str = "messaging.retention.erased";

/// How often the runtime's sweep runs.
pub const SWEEP_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// Serializes retention runs on one transaction lock. The key spells the
/// ASCII bytes of "msgretnt".
const RETENTION_LOCK_KEY: i64 = 0x6d73_6772_6574_6e74;

/// How long a run waits for a row another transaction holds.
const LOCK_TIMEOUT: &str = "5s";

/// How long any one statement of a run may take. A run that takes longer
/// is rolled back whole and erases nothing.
const STATEMENT_TIMEOUT: &str = "60s";

/// The job states a message ends in. Only these are ever erased.
const TERMINAL: &str = "('delivered', 'dead_lettered', 'expired', 'cancelled')";

/// Who ran a retention pass.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetentionActor {
    /// The runtime's own periodic sweep.
    Runtime,
    /// An operator through `messagingctl retention erase-expired`.
    OperatorTool,
}

impl RetentionActor {
    fn to_json(self) -> Value {
        match self {
            Self::Runtime => json!({"kind": "runtime"}),
            Self::OperatorTool => Actor::OperatorTool.to_json(),
        }
    }
}

/// What one run found expired, and whether it erased it.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct RetentionReport {
    /// The cutoff every period was counted back from.
    pub before: String,
    /// Whether this run erased what it counted.
    pub applied: bool,
    /// Payloads past their period.
    pub payloads: u64,
    /// Message records past their period.
    pub records: u64,
    /// Submission receipts past their period.
    pub submission_receipts: u64,
}

impl RetentionReport {
    fn erased_anything(&self) -> bool {
        self.payloads > 0 || self.records > 0 || self.submission_receipts > 0
    }
}

#[derive(Debug, Error)]
pub enum RetentionError {
    #[error("the retention cutoff is later than the database clock; retention erases only what has already expired")]
    FutureCutoff,
    #[error("the Messaging retention run failed: {0}")]
    Store(#[from] StoreError),
    #[error("the Messaging retention run could not write its audit record")]
    Audit,
}

impl From<tokio_postgres::Error> for RetentionError {
    fn from(error: tokio_postgres::Error) -> Self {
        Self::Store(StoreError::Query(error))
    }
}

/// Count what expired by `before` under `retention`, and with `apply` erase
/// it, in one transaction under the retention lock. With no `before`, the
/// cutoff is the database's clock at the start of the run, so a runtime
/// whose clock runs ahead of the database's never has its sweep refused.
///
/// An applied run by the operator tool is always journaled; one by the
/// runtime only when it erased something, so the hourly sweep does not
/// grow the journal with empty passes. A preview writes nothing.
///
/// # Errors
///
/// [`RetentionError::FutureCutoff`] when `before` is later than the
/// database clock, and the store's error when a statement fails, in which
/// case nothing was erased.
pub async fn erase_expired(
    store: &PostgresStore,
    retention: RetentionConfig,
    before: Option<SystemTime>,
    apply: bool,
    actor: RetentionActor,
) -> Result<RetentionReport, RetentionError> {
    let mut client = store.client().await?;
    let transaction = client.transaction().await?;
    transaction
        .query_one(
            "SELECT set_config('lock_timeout', $1, true), \
                    set_config('statement_timeout', $2, true)",
            &[&LOCK_TIMEOUT, &STATEMENT_TIMEOUT],
        )
        .await?;
    transaction
        .execute("SELECT pg_advisory_xact_lock($1)", &[&RETENTION_LOCK_KEY])
        .await?;
    let row = transaction
        .query_one(
            "SELECT coalesce($1::timestamptz, transaction_timestamp()), \
                    coalesce($1::timestamptz > transaction_timestamp(), false)",
            &[&before],
        )
        .await?;
    if row.get::<_, bool>(1) {
        return Err(RetentionError::FutureCutoff);
    }
    let before: SystemTime = row.get(0);
    let payload_days = i32::from(retention.payload_days);
    let record_days = i32::from(retention.record_days);
    let (payloads, submission_receipts, records) = if apply {
        (
            erase_payloads(&transaction, before, payload_days).await?,
            expire_submission_receipts(&transaction, before).await?,
            delete_records(&transaction, before, record_days).await?,
        )
    } else {
        (
            count(&transaction, &payloads_due(""), before, Some(payload_days)).await?,
            count(&transaction, SUBMISSION_RECEIPTS_DUE, before, None).await?,
            count(&transaction, &records_due(""), before, Some(record_days)).await?,
        )
    };
    let report = RetentionReport {
        before: format_instant(before),
        applied: apply,
        payloads,
        records,
        submission_receipts,
    };
    let journaled = match actor {
        RetentionActor::OperatorTool => apply,
        RetentionActor::Runtime => apply && report.erased_anything(),
    };
    if journaled {
        outbox::write(
            &transaction,
            json!({
                "event": RETENTION_ERASED_EVENT,
                "before": report.before,
                "payloads": report.payloads,
                "records": report.records,
                "submissionReceipts": report.submission_receipts,
                "retention": retention,
                "actor": actor.to_json(),
            }),
        )
        .await
        .map_err(|_| RetentionError::Audit)?;
    }
    transaction.commit().await?;
    Ok(report)
}

/// The terminal jobs whose payload is past its period and not yet erased,
/// with `lock` appended to the query.
fn payloads_due(lock: &str) -> String {
    format!(
        "SELECT job.message_id \
           FROM messaging_dispatch_jobs AS job \
           JOIN messaging_message_payloads AS payload USING (message_id) \
          WHERE job.state IN {TERMINAL} \
            AND job.updated_at <= $1::timestamptz - make_interval(days => $2) \
            AND payload.erased_at IS NULL{lock}"
    )
}

/// The terminal jobs whose record is past its period, with `lock` appended.
fn records_due(lock: &str) -> String {
    format!(
        "SELECT job.message_id \
           FROM messaging_dispatch_jobs AS job \
          WHERE job.state IN {TERMINAL} \
            AND job.updated_at <= $1::timestamptz - make_interval(days => $2){lock}"
    )
}

const SUBMISSION_RECEIPTS_DUE: &str = "SELECT 1 FROM messaging_idempotency \
      WHERE erased_at IS NULL AND expires_at <= $1::timestamptz";

async fn count(
    transaction: &Transaction<'_>,
    due: &str,
    before: SystemTime,
    days: Option<i32>,
) -> Result<u64, RetentionError> {
    let query = format!("SELECT count(*) FROM ({due}) AS due");
    let row = match days {
        Some(days) => transaction.query_one(&query, &[&before, &days]).await?,
        None => transaction.query_one(&query, &[&before]).await?,
    };
    Ok(u64::try_from(row.get::<_, i64>(0)).unwrap_or(0))
}

/// Null the recipient and the parts of every payload past its period. The
/// jobs are locked first: a job an operator requeued since the read no
/// longer matches and is skipped.
async fn erase_payloads(
    transaction: &Transaction<'_>,
    before: SystemTime,
    days: i32,
) -> Result<u64, RetentionError> {
    let due = payloads_due(" FOR UPDATE OF job");
    Ok(transaction
        .execute(
            &format!(
                "WITH due AS ({due}) \
                 UPDATE messaging_message_payloads AS payload \
                    SET recipient = NULL, subject = NULL, text_body = NULL, html_body = NULL, \
                        erased_at = transaction_timestamp() \
                   FROM due \
                  WHERE payload.message_id = due.message_id"
            ),
            &[&before, &days],
        )
        .await?)
}

/// Erase every submission receipt past its period. The row stays, so its
/// key stays spent and a replay answers `idempotency.expired`.
async fn expire_submission_receipts(
    transaction: &Transaction<'_>,
    before: SystemTime,
) -> Result<u64, RetentionError> {
    Ok(transaction
        .execute(
            "UPDATE messaging_idempotency \
                SET status_code = NULL, receipt = NULL, erased_at = transaction_timestamp() \
              WHERE erased_at IS NULL AND expires_at <= $1::timestamptz",
            &[&before],
        )
        .await?)
}

/// Delete every message record past its period. The payload, the job, the
/// attempts, and the receipts cascade; the idempotency record has no
/// foreign key and is deleted by the message it names.
async fn delete_records(
    transaction: &Transaction<'_>,
    before: SystemTime,
    days: i32,
) -> Result<u64, RetentionError> {
    let due = records_due(" FOR UPDATE OF job");
    Ok(transaction
        .execute(
            &format!(
                "WITH due AS ({due}), \
                      keys AS (DELETE FROM messaging_idempotency AS key \
                                USING due WHERE key.message_id = due.message_id) \
                 DELETE FROM messaging_messages AS message \
                  USING due \
                  WHERE message.message_id = due.message_id"
            ),
            &[&before, &days],
        )
        .await?)
}

/// The runtime's retention sweep: one applied run at the database's
/// current time on every interval, the first at startup.
pub struct RetentionSweep {
    store: PostgresStore,
    retention: RetentionConfig,
}

impl std::fmt::Debug for RetentionSweep {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RetentionSweep")
            .field("retention", &self.retention)
            .finish_non_exhaustive()
    }
}

impl RetentionSweep {
    #[must_use]
    pub fn new(store: PostgresStore, retention: RetentionConfig) -> Self {
        Self { store, retention }
    }

    /// One applied run at the database's current time.
    ///
    /// # Errors
    ///
    /// As [`erase_expired`].
    pub async fn pass(&self) -> Result<RetentionReport, RetentionError> {
        erase_expired(
            &self.store,
            self.retention,
            None,
            true,
            RetentionActor::Runtime,
        )
        .await
    }

    /// Run a pass every `interval` until `shutdown` turns true. A failed
    /// pass is logged once until a pass succeeds again, and the next
    /// interval retries it; nothing it would have erased is lost.
    pub async fn run(self, interval: Duration, mut shutdown: watch::Receiver<bool>) {
        let mut failing = false;
        loop {
            match self.pass().await {
                Ok(report) => {
                    if std::mem::take(&mut failing) {
                        tracing::info!("Messaging retention recovered");
                    }
                    if report.erased_anything() {
                        tracing::info!(
                            payloads = report.payloads,
                            records = report.records,
                            submission_receipts = report.submission_receipts,
                            "Messaging retention erased expired data"
                        );
                    }
                }
                Err(error) => {
                    if !failing {
                        tracing::warn!(error = %error, "Messaging retention pass did not complete");
                        failing = true;
                    }
                }
            }
            if *shutdown.borrow() {
                return;
            }
            tokio::select! {
                () = tokio::time::sleep(interval) => {}
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return;
                    }
                }
            }
        }
    }
}
