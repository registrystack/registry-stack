// SPDX-License-Identifier: Apache-2.0

//! Delivery-intent dispatch over the platform dispatch core.
//!
//! Scheduling keeps the outbox table, the columns that say what to deliver,
//! the rendering of each intent as a shared hook envelope, and the send. The
//! core owns the claim, the fenced lease, retry scheduling, and the terminal
//! states.
//!
//! Every intent runs under one fixed policy: a five-second attempt timeout,
//! eight attempts, a frozen retry schedule doubling from thirty seconds, no
//! expiry, and a retry when an attempt's outcome is unknown, because every
//! event carries the intent's identifier as its `id` and the destination
//! deduplicates on it. A reminder no attempt has started on is cancelled by
//! the cancellation or reschedule that supersedes it, in that transaction. A
//! claimed reminder whose appointment was cancelled or moved to a newer
//! revision is set aside without a send, by a liveness read under its lease
//! at the moment it would be sent; a lease that lapsed starts no send. A row
//! the claim cannot take is set aside without a send so it never stalls the
//! rows behind it.

use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use registry_platform_dispatch::postgres::{
    AttemptAudit, ClaimRefusal, Columns, Decoded, DispatchConfig, DispatchConnection,
    DispatchEvent, DispatchSql, DispatchStore, DispatchTransport, Dispatcher, Disposition, JobKey,
    JobState, JobTable, LapsedJob, LeasedJob, Quarantine, QuarantineDisposition, QuarantineReason,
    ReplayAudit, SelectSql, TargetAction, TransitionAudit, TransitionOutcome,
};
use registry_platform_dispatch::{
    AttemptTimeoutBound, DispatchError, FailureCode, JobPolicy, RetrySchedule, SendOutcome, Sent,
    UncertainOutcome,
};
use registry_platform_httputil::destination::{
    DestinationAuthorizationValue, DestinationRequestError,
};
use tokio_postgres::{Row, Transaction};

use super::{delivery_of, reminder_event, Delivery, ReminderTransport};
use crate::store::{OutboxRow, PostgresStore, StoreError};

/// The delivery-intent outbox table.
pub(crate) const OUTBOX_TABLE: &str = "scheduling_outbox";

/// How long one send may take.
pub(crate) const INTENT_ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);

/// The attempts an intent may consume before it is held for an operator.
const INTENT_MAXIMUM_ATTEMPTS: i16 = 8;

/// The wait after each failed attempt, in milliseconds: thirty seconds,
/// doubling. The eighth attempt is the last, so seven delays cover it.
const INTENT_RETRY_DELAYS_MS: [i64; 7] = [
    30_000, 60_000, 120_000, 240_000, 480_000, 960_000, 1_920_000,
];

/// The failure class of an attempt that was not acknowledged, including one
/// whose lease lapsed before its outcome was recorded.
pub(crate) const DELIVERY_FAILED: &str = "delivery_failed";

/// The failure class of an intent the destination refused outright: an
/// answer outside the success and retry classes.
pub(crate) const DESTINATION_REFUSED: &str = "destination_refused";

/// The failure class of an intent held because the deployment declares no
/// reminders destination. An operator reads it as `local`.
pub(crate) const DESTINATION_UNCONFIGURED: &str = "destination_unconfigured";

/// The failure class of an intent whose payload cannot become an event.
pub(crate) const EVENT_UNRENDERABLE: &str = "event_unrenderable";

/// The failure class of a reminder whose appointment was cancelled or moved
/// to a newer revision before it was sent. Nobody is meant to deliver it, so
/// an operator does not see it as undelivered work.
pub(crate) const SUPERSEDED: &str = "superseded";

/// The failure class of a row the claim could not read as an intent.
const DELIVERY_UNREADABLE: &str = "delivery_unreadable";

/// The failure class of a row whose attempts already reach the ceiling.
const ATTEMPTS_EXHAUSTED: &str = "attempts_exhausted";

/// The failure class of a row whose policy the core refused.
const POLICY_REFUSED: &str = "policy_refused";

/// The failure class of a row whose lapsed lease could not be recovered.
const RECOVERY_FAILED: &str = "recovery_failed";

/// The failure class of a row that could not be expired.
const EXPIRY_FAILED: &str = "expiry_failed";

/// The dispatcher over the delivery-intent outbox.
pub(crate) type IntentDispatcher = Dispatcher<IntentStore>;

/// The one policy every delivery intent runs under.
pub(crate) fn intent_policy() -> JobPolicy {
    JobPolicy {
        attempt_timeout: INTENT_ATTEMPT_TIMEOUT,
        maximum_attempts: INTENT_MAXIMUM_ATTEMPTS,
        retry: RetrySchedule::Frozen {
            delays_ms: INTENT_RETRY_DELAYS_MS.to_vec(),
        },
        on_uncertain: UncertainOutcome::Retry,
        expires_at: None,
    }
}

/// The attempt timeouts the dispatcher accepts: exactly the fixed one.
fn attempt_bound() -> Result<AttemptTimeoutBound, StoreError> {
    AttemptTimeoutBound::new(INTENT_ATTEMPT_TIMEOUT, INTENT_ATTEMPT_TIMEOUT)
        .map_err(|_| StoreError::Configuration)
}

/// The failure class a row set aside for `reason`, after `attempt`
/// attempts, records.
fn quarantine_class(reason: QuarantineReason, attempt: i16) -> &'static str {
    match reason {
        QuarantineReason::ClaimUnreadable if attempt >= INTENT_MAXIMUM_ATTEMPTS => {
            ATTEMPTS_EXHAUSTED
        }
        QuarantineReason::ClaimUnreadable => DELIVERY_UNREADABLE,
        QuarantineReason::PolicyRefused => POLICY_REFUSED,
        QuarantineReason::RecoveryFailed => RECOVERY_FAILED,
        QuarantineReason::ExpiryFailed | QuarantineReason::ClaimExpiryFailed => EXPIRY_FAILED,
    }
}

/// The failure class a finished attempt records: none for a delivery, the
/// transport's own code for a refusal, and a failed delivery otherwise.
fn finished_class(outcome: &SendOutcome) -> Option<String> {
    match outcome {
        SendOutcome::Accepted { .. } => None,
        SendOutcome::Permanent { code } => Some(code.as_str().to_owned()),
        SendOutcome::Transient { .. } | SendOutcome::MaybeSent => Some(DELIVERY_FAILED.to_owned()),
    }
}

fn dispatch_sql() -> DispatchSql {
    DispatchSql {
        claim: SelectSql {
            columns: "state.claim_id, state.appointment_revision, state.due_at, state.payload",
            joins: "",
            predicate: "TRUE",
        },
        lapsed: SelectSql {
            columns: "",
            joins: "",
            predicate: "TRUE",
        },
        // No intent expires: an undelivered one stays for an operator.
        expiry: None,
        // Scheduling offers no operator replay or cancellation of an intent.
        target: SelectSql {
            columns: "",
            joins: "",
            predicate: "FALSE",
        },
    }
}

/// One pooled runtime client framed for the dispatch core's connection
/// seam. The pool receives the client back when this wrapper is dropped.
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

/// The Scheduling consumer of the platform dispatch core.
pub(crate) struct IntentStore {
    store: PostgresStore,
    schema: String,
}

/// The dispatcher over `store`'s delivery-intent outbox, in the schema its
/// sessions resolve names in.
pub(crate) async fn intent_dispatcher(
    store: PostgresStore,
) -> Result<IntentDispatcher, StoreError> {
    let schema = store.schema_name().await?;
    let table = JobTable::new(&schema, OUTBOX_TABLE, "outbox_id", "purpose")
        .map_err(|_| StoreError::Configuration)?;
    Dispatcher::new(
        IntentStore { store, schema },
        DispatchConfig {
            table,
            sql: dispatch_sql(),
            attempt_timeout: attempt_bound()?,
            replayable: &[],
        },
    )
    .map_err(|_| StoreError::Configuration)
}

#[async_trait]
impl DispatchStore for IntentStore {
    type Job = OutboxRow;
    type Record = ();
    type Detail = ();
    type Context = ();

    fn capture_context(&self) {}

    async fn connection(&self) -> Result<DispatchConnection, DispatchError> {
        let client = self
            .store
            .intent_dispatch_client()
            .await
            .map_err(|_| DispatchError::Unavailable)?;
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

    fn decode_claim(&self, row: &Row, first: usize) -> Result<Decoded<OutboxRow>, ClaimRefusal> {
        let read = || -> Result<OutboxRow, tokio_postgres::Error> {
            Ok(OutboxRow {
                outbox_id: row.try_get(0)?,
                purpose: row.try_get(1)?,
                claim_id: row.try_get(first)?,
                appointment_revision: row.try_get(first + 1)?,
                due_at: row.try_get::<_, DateTime<Utc>>(first + 2)?,
                payload: row.try_get(first + 3)?,
            })
        };
        let job = read().map_err(|_| ClaimRefusal::Unavailable)?;
        Ok(Decoded {
            policy: intent_policy(),
            job,
        })
    }

    fn claim_record(&self, _job: &OutboxRow) {}

    fn decode_lapsed(&self, _row: &Row, _first: usize) -> Result<Decoded<()>, DispatchError> {
        Ok(Decoded {
            policy: intent_policy(),
            job: (),
        })
    }

    fn decode_expired(&self, _row: &Row, _first: usize) -> Result<(), DispatchError> {
        // The core sweeps no expiry: no intent policy carries one.
        Err(DispatchError::Unavailable)
    }

    fn decode_target(
        &self,
        _row: &Row,
        _first: usize,
        _key: &JobKey,
        _action: TargetAction,
    ) -> Result<Option<()>, DispatchError> {
        Ok(None)
    }

    // A delivery intent has no audit lifecycle of its own: the capacity
    // decision that minted it is the audited fact, and the outbox row
    // records where its delivery stands.
    async fn record_attempt_audit(
        &self,
        _job: &LeasedJob<OutboxRow>,
        _audit: AttemptAudit<'_, ()>,
        _context: &(),
    ) -> Result<(), DispatchError> {
        Ok(())
    }

    async fn record_transition_audit(
        &self,
        _audit: &TransitionAudit<()>,
        _outcome: TransitionOutcome,
        _context: &(),
    ) -> Result<(), DispatchError> {
        Ok(())
    }

    async fn record_replay_audit(
        &self,
        _audit: &ReplayAudit<()>,
        _context: &(),
    ) -> Result<(), DispatchError> {
        Err(DispatchError::Unavailable)
    }

    fn operational_event(&self, event: DispatchEvent) {
        match event {
            DispatchEvent::JobExpired => {
                tracing::info!("a Scheduling delivery intent was expired undelivered");
            }
            DispatchEvent::JobQuarantined(reason) => {
                tracing::info!(
                    reason = ?reason,
                    "a Scheduling delivery intent was set aside without a send"
                );
            }
            DispatchEvent::TransitionFailed(code) => {
                tracing::warn!(
                    code = ?code,
                    "a Scheduling delivery intent claim did not complete"
                );
            }
            DispatchEvent::IterationFailed => {
                tracing::warn!("a Scheduling delivery intent pass did not complete");
            }
        }
    }

    async fn lapsed_columns(
        &self,
        _transaction: &Transaction<'_>,
        _lapsed: &LapsedJob<()>,
        _disposition: Disposition,
    ) -> Result<Columns, DispatchError> {
        Ok(Columns::new().set("last_failure_class", DELIVERY_FAILED))
    }

    fn finished_columns(
        &self,
        _job: &LeasedJob<OutboxRow>,
        sent: &Sent<()>,
        _disposition: Disposition,
    ) -> Result<Columns, DispatchError> {
        Ok(Columns::new().set("last_failure_class", finished_class(&sent.outcome)))
    }

    async fn may_have_reached_receiver(
        &self,
        _transaction: &Transaction<'_>,
        _key: &JobKey,
        _generation: i64,
        _attempt: i16,
    ) -> Result<bool, DispatchError> {
        // The destination deduplicates on the intent's identifier, so an
        // intent that may have arrived is retried or set aside like one
        // that did not.
        Ok(false)
    }

    fn quarantines(&self) -> bool {
        true
    }

    async fn quarantine(
        &self,
        transaction: &Transaction<'_>,
        quarantine: Quarantine<'_>,
    ) -> Result<QuarantineDisposition, DispatchError> {
        // A row with an attempt behind it is dead-lettered like one whose
        // attempts ran out; one never attempted expires, so the shape check
        // and the claim both leave it alone for good.
        let (state, stamp) = if quarantine.attempt > 0 {
            (
                JobState::DeadLettered,
                "dead_lettered_at = transaction_timestamp(), ",
            )
        } else {
            (JobState::Expired, "expired_at = transaction_timestamp(), ")
        };
        let class = quarantine_class(quarantine.reason, quarantine.attempt);
        let changed = transaction
            .execute(
                &format!(
                    "UPDATE {OUTBOX_TABLE} \
                        SET state = $4, next_attempt_at = NULL, attempt_started_at = NULL, \
                            lease_expires_at = NULL, lease_token = NULL, \
                            last_failure_class = $5, \
                            {stamp}updated_at = transaction_timestamp() \
                      WHERE outbox_id = $1 AND purpose = $2 AND generation = $3"
                ),
                &[
                    &quarantine.key.id(),
                    &quarantine.key.part(),
                    &quarantine.generation,
                    &state.as_str(),
                    &class,
                ],
            )
            .await?;
        if changed != 1 {
            return Err(DispatchError::Unavailable);
        }
        // The core reports a committed quarantine without its row, so the
        // row is named here, before the claim transaction commits.
        tracing::warn!(
            outbox_id = %quarantine.key.id(),
            purpose = quarantine.key.part(),
            attempt = quarantine.attempt,
            reason = ?quarantine.reason,
            failure_class = class,
            state = state.as_str(),
            "setting a Scheduling delivery intent aside without a send"
        );
        Ok(QuarantineDisposition::Quarantined(state))
    }
}

/// Whether a leased intent still describes a decision the caller stands by.
/// A confirmation, change or cancellation always does. A reminder does only
/// while its appointment is active at the revision the reminder was minted
/// for: a cancellation or reschedule that committed after the claim
/// supersedes it (INT-02).
const LIVENESS_SELECT: SelectSql = SelectSql {
    columns: "(state.purpose <> 'reminder' \
              OR (claim.state = 'active' AND claim.revision = state.appointment_revision))",
    joins: "JOIN {schema}.scheduling_claims AS claim ON claim.claim_id = state.claim_id",
    predicate: "TRUE",
};

fn decode_liveness(row: &Row, first: usize) -> Result<bool, tokio_postgres::Error> {
    row.try_get(first)
}

/// The send half: one intent to the configured reminders destination, or a
/// local hold when the deployment declares none.
pub(crate) struct IntentTransport {
    dispatcher: IntentDispatcher,
    scheduling_id: String,
    destination: Option<Arc<ReminderTransport>>,
}

impl IntentTransport {
    pub(crate) fn new(
        dispatcher: IntentDispatcher,
        scheduling_id: String,
        destination: Option<Arc<ReminderTransport>>,
    ) -> Self {
        Self {
            dispatcher,
            scheduling_id,
            destination,
        }
    }
}

fn refusal(class: &str) -> Result<Sent<()>, DispatchError> {
    Ok(Sent {
        outcome: SendOutcome::Permanent {
            code: FailureCode::new(class).map_err(|_| DispatchError::Unavailable)?,
        },
        detail: (),
    })
}

fn sent(outcome: SendOutcome) -> Result<Sent<()>, DispatchError> {
    Ok(Sent {
        outcome,
        detail: (),
    })
}

#[async_trait]
impl DispatchTransport for IntentTransport {
    type Job = OutboxRow;
    type Detail = ();

    async fn send(&self, job: &LeasedJob<OutboxRow>) -> Result<Sent<()>, DispatchError> {
        let row = &job.job;
        // The intent's own liveness, read under its lease immediately before
        // the send: a reminder whose appointment was cancelled or moved to a
        // newer revision is not sent. A lease that lapsed or was taken over,
        // or an unreadable answer, sends nothing and leaves the lease to
        // lapse into a retry.
        let current = self
            .dispatcher
            .read_leased(job.fence(), &LIVENESS_SELECT, decode_liveness)
            .await
            .map_err(|_| DispatchError::Unavailable)?;
        if !current {
            tracing::info!(
                outbox_id = %row.outbox_id,
                "a claimed reminder was superseded before its dispatch"
            );
            return refusal(SUPERSEDED);
        }
        let Some(destination) = &self.destination else {
            // Nothing is sent: no destination exists. The intent stays
            // recorded instead of pretending a delivery happened.
            return refusal(DESTINATION_UNCONFIGURED);
        };
        let body = match reminder_event(&self.scheduling_id, row) {
            Ok(body) => body,
            Err(error) => {
                tracing::error!(
                    error = %error,
                    outbox_id = %row.outbox_id,
                    "a due delivery intent could not be rendered"
                );
                // No amount of retrying fixes a payload that cannot become
                // an event.
                return refusal(EVENT_UNRENDERABLE);
            }
        };
        let authorization = destination
            .bearer
            .as_ref()
            .map(|secret| DestinationAuthorizationValue::bearer(secret.expose_secret().to_vec()))
            .transpose();
        let request = match authorization {
            Ok(authorization) => destination
                .template
                .render(&[], &[], authorization, Some(body)),
            Err(_) => Err(DestinationRequestError::InvalidAuthorization),
        };
        let request = match request {
            Ok(request) => request,
            Err(error) => {
                tracing::error!(
                    error = %error,
                    outbox_id = %row.outbox_id,
                    "a delivery intent request could not be rendered"
                );
                return sent(SendOutcome::Transient { retry_after: None });
            }
        };
        match destination
            .policy
            .send(request, job.policy.attempt_timeout)
            .await
        {
            Ok(response) => match delivery_of(response.status().as_u16()) {
                Delivery::Delivered => sent(SendOutcome::Accepted {
                    receiver_reference: None,
                }),
                Delivery::Transient => sent(SendOutcome::Transient { retry_after: None }),
                Delivery::Refused => {
                    tracing::warn!(
                        outbox_id = %row.outbox_id,
                        status = response.status().as_u16(),
                        "a reminders destination refused a delivery intent outright"
                    );
                    refusal(DESTINATION_REFUSED)
                }
            },
            Err(error) => {
                tracing::warn!(
                    error = %error,
                    outbox_id = %row.outbox_id,
                    "a delivery intent attempt did not reach a verdict"
                );
                sent(SendOutcome::Transient { retry_after: None })
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn normalized(sql: &str) -> String {
        sql.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    #[test]
    fn the_outbox_migration_is_exactly_the_dispatch_core_shape() {
        let migration = include_str!("../../migrations/0100_scheduling.sql");
        let table = JobTable::new("public", OUTBOX_TABLE, "outbox_id", "purpose")
            .expect("the outbox table names");
        let declared = normalized(&table.create_statements().join("\n").replace("public.", ""));
        let start = migration
            .find("CREATE TABLE IF NOT EXISTS scheduling_outbox")
            .expect("the outbox table");
        let end = migration
            .find("ALTER TABLE scheduling_outbox")
            .expect("the outbox table's own columns");
        assert_eq!(normalized(&migration[start..end]), declared);
    }

    #[test]
    fn the_intent_policy_is_the_loops_written_contract() {
        let policy = intent_policy();
        assert!(policy.is_valid(&attempt_bound().expect("the attempt bound")));
        assert_eq!(policy.attempt_timeout, Duration::from_secs(5));
        assert_eq!(policy.maximum_attempts, 8);
        assert_eq!(policy.on_uncertain, UncertainOutcome::Retry);
        assert_eq!(policy.expires_at, None);
        // Thirty seconds after the first failure, doubling, and never past
        // the hour: the seventh and last wait is thirty-two minutes.
        let waits: Vec<i64> = (1..8)
            .map(|attempt| {
                policy
                    .retry
                    .delay_after(attempt, None, 0)
                    .expect("a wait after this attempt")
                    / 1000
            })
            .collect();
        assert_eq!(waits, vec![30, 60, 120, 240, 480, 960, 1920]);
        assert!(waits.iter().all(|wait| *wait <= 3600));
        // The eighth attempt is the last: no wait follows it.
        assert!(policy.retry.delay_after(8, None, 0).is_err());
    }

    #[test]
    fn a_frozen_schedule_ignores_a_receivers_pause_hint() {
        let retry = intent_policy().retry;
        assert_eq!(
            retry
                .delay_after(1, Some(Duration::from_secs(600)), 0)
                .expect("a wait after the first attempt"),
            30_000
        );
    }

    #[test]
    fn a_finished_attempt_records_the_class_of_its_outcome() {
        assert_eq!(
            finished_class(&SendOutcome::Accepted {
                receiver_reference: None
            }),
            None
        );
        for class in [
            DESTINATION_REFUSED,
            DESTINATION_UNCONFIGURED,
            EVENT_UNRENDERABLE,
            SUPERSEDED,
        ] {
            assert_eq!(
                finished_class(&SendOutcome::Permanent {
                    code: FailureCode::new(class).expect("a failure code"),
                }),
                Some(class.to_owned())
            );
        }
        assert_eq!(
            finished_class(&SendOutcome::Transient { retry_after: None }),
            Some(DELIVERY_FAILED.to_owned())
        );
        assert_eq!(
            finished_class(&SendOutcome::MaybeSent),
            Some(DELIVERY_FAILED.to_owned())
        );
    }

    #[test]
    fn a_set_aside_intent_records_the_class_of_its_reason() {
        for (reason, attempt, class) in [
            (QuarantineReason::ClaimUnreadable, 8, ATTEMPTS_EXHAUSTED),
            (QuarantineReason::ClaimUnreadable, 2, DELIVERY_UNREADABLE),
            (QuarantineReason::PolicyRefused, 0, POLICY_REFUSED),
            (QuarantineReason::RecoveryFailed, 1, RECOVERY_FAILED),
            (QuarantineReason::ExpiryFailed, 0, EXPIRY_FAILED),
            (QuarantineReason::ClaimExpiryFailed, 0, EXPIRY_FAILED),
        ] {
            assert_eq!(
                quarantine_class(reason, attempt),
                class,
                "{reason:?} after {attempt} attempts"
            );
        }
    }
}
