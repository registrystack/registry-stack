//! Review completion delivery over the platform dispatch core.
//!
//! Casework keeps the completion outbox table, the columns that say what to
//! deliver and for how long it may be delivered, and the send itself. The
//! core owns the claim, the fenced lease, retry scheduling, and the terminal
//! states.
//!
//! The delivery policy is read from the runtime's configured destination at
//! every claim and lease recovery, not frozen when the review completed: the
//! attempt timeout, the attempt count, and one constant retry delay, with
//! the row's `retained_until` as its expiry. A lapsed lease and a failed
//! attempt are retried alike, because every wake-up carries the terminal
//! event's id as its idempotency key and holds no review content. A row the
//! claim cannot take, such as one whose destination this runtime no longer
//! configures, is set aside without a send so it never stalls the rows
//! behind it.

use std::collections::BTreeMap;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use async_trait::async_trait;
use registry_platform_dispatch::postgres::{
    AttemptAudit, ClaimRefusal, Decoded, DispatchConfig, DispatchConnection, DispatchEvent,
    DispatchSql, DispatchStore, DispatchTransport, Dispatcher, Disposition, JobKey, JobState,
    JobTable, LapsedJob, LeasedJob, Quarantine, QuarantineDisposition, ReplayAudit, SelectSql,
    TargetAction, TransitionAudit, TransitionOutcome,
};
use registry_platform_dispatch::{
    AttemptTimeoutBound, DispatchError, FailureCode, JobPolicy, RetrySchedule, SendOutcome, Sent,
    UncertainOutcome,
};
use tokio_postgres::{Row, Transaction};

use super::{deliver_review_completion, ReviewCompletionTarget};
use crate::config::{
    MAXIMUM_REVIEW_COMPLETION_TIMEOUT_MILLISECONDS, MINIMUM_REVIEW_COMPLETION_TIMEOUT_MILLISECONDS,
};
use crate::{LeasedReviewCompletion, PostgresStore, StoreError};

/// The completion outbox table.
pub(super) const COMPLETION_TABLE: &str = "casework_review_completion_outbox";

/// The failure class of an attempt that was not acknowledged, including one
/// whose lease lapsed before its outcome was recorded.
const DELIVERY_FAILED: &str = "delivery_failed";

/// The failure class of a row whose destination this runtime does not
/// configure.
const DESTINATION_UNCONFIGURED: &str = "destination_unconfigured";

/// The failure class of a row the claim could not read as a delivery.
const DELIVERY_UNREADABLE: &str = "delivery_unreadable";

/// The configured completion destinations, by destination id.
pub(super) type CompletionTargets = Arc<BTreeMap<String, Arc<ReviewCompletionTarget>>>;

/// The dispatcher over the completion outbox.
pub(super) type CompletionDispatcher = Dispatcher<CompletionStore>;

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

/// The Casework consumer of the platform dispatch core.
pub(super) struct CompletionStore {
    store: PostgresStore,
    schema: String,
    targets: CompletionTargets,
}

impl CompletionStore {
    /// The policy a delivery to `destination_id` runs under, or `None` when
    /// this runtime does not configure the destination or its configuration
    /// does not fit a dispatch policy.
    fn policy(&self, destination_id: &str, retained_until: SystemTime) -> Option<JobPolicy> {
        let target = self.targets.get(destination_id)?;
        completion_policy(target, retained_until)
    }

    fn decode_policy(
        &self,
        row: &Row,
        destination: usize,
        retained_until: usize,
    ) -> Result<Option<JobPolicy>, tokio_postgres::Error> {
        let destination_id: String = row.try_get(destination)?;
        let retained_until: SystemTime = row.try_get(retained_until)?;
        Ok(self.policy(&destination_id, retained_until))
    }
}

fn completion_policy(
    target: &ReviewCompletionTarget,
    retained_until: SystemTime,
) -> Option<JobPolicy> {
    let maximum_attempts = i16::try_from(target.maximum_attempts).ok()?;
    let retry_delays = usize::try_from(maximum_attempts.checked_sub(1)?).ok()?;
    let delay_ms = i64::try_from(target.retry.as_millis()).ok()?;
    Some(JobPolicy {
        attempt_timeout: target.timeout,
        maximum_attempts,
        retry: RetrySchedule::Frozen {
            delays_ms: vec![delay_ms; retry_delays],
        },
        on_uncertain: UncertainOutcome::Retry,
        expires_at: Some(retained_until),
    })
}

/// The attempt timeouts the runtime configuration accepts.
fn attempt_bound() -> Result<AttemptTimeoutBound, StoreError> {
    AttemptTimeoutBound::new(
        Duration::from_millis(MINIMUM_REVIEW_COMPLETION_TIMEOUT_MILLISECONDS),
        Duration::from_millis(MAXIMUM_REVIEW_COMPLETION_TIMEOUT_MILLISECONDS),
    )
    .map_err(|_| StoreError::Configuration)
}

fn dispatch_sql() -> DispatchSql {
    DispatchSql {
        claim: SelectSql {
            columns: "state.destination_id, state.recipient_binding, state.retained_until, \
                      terminal.request_id, terminal.result_id, terminal.completed_at",
            joins: "JOIN {schema}.casework_review_terminal_events AS terminal \
                    ON terminal.event_id = state.event_id",
            predicate: "TRUE",
        },
        lapsed: SelectSql {
            columns: "state.destination_id, state.retained_until",
            joins: "",
            predicate: "TRUE",
        },
        expiry: None,
        // Casework offers no operator replay or cancellation of a delivery.
        target: SelectSql {
            columns: "",
            joins: "",
            predicate: "FALSE",
        },
    }
}

/// The dispatcher over `store`'s completion outbox, in the schema its
/// sessions resolve names in, delivering to `targets`.
pub(super) async fn completion_dispatcher(
    store: PostgresStore,
    targets: CompletionTargets,
) -> Result<CompletionDispatcher, StoreError> {
    let schema: Option<String> = store
        .client()
        .await?
        .query_one("SELECT current_schema()", &[])
        .await?
        .try_get(0)?;
    let schema = schema.ok_or(StoreError::Configuration)?;
    let table = JobTable::new(&schema, COMPLETION_TABLE, "event_id", "destination_id")
        .map_err(|_| StoreError::Configuration)?;
    Dispatcher::new(
        CompletionStore {
            store,
            schema,
            targets,
        },
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
impl DispatchStore for CompletionStore {
    type Job = LeasedReviewCompletion;
    type Record = ();
    type Detail = ();
    type Context = ();

    fn capture_context(&self) {}

    async fn connection(&self) -> Result<DispatchConnection, DispatchError> {
        let client = self
            .store
            .client()
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

    fn decode_claim(
        &self,
        row: &Row,
        first: usize,
    ) -> Result<Decoded<LeasedReviewCompletion>, ClaimRefusal> {
        let policy = self
            .decode_policy(row, first, first + 2)
            .map_err(|_| ClaimRefusal::Unavailable)?
            .ok_or(ClaimRefusal::PolicyRefused)?;
        let read = || -> Result<LeasedReviewCompletion, tokio_postgres::Error> {
            Ok(LeasedReviewCompletion {
                event: registry_casework_core::ReviewCompletion {
                    event_type: registry_casework_core::ReviewCompletionType::ReviewCompleted,
                    event_id: row.try_get(0)?,
                    request_id: row.try_get(first + 3)?,
                    result_id: row.try_get(first + 4)?,
                    completed_at: row.try_get(first + 5)?,
                },
                destination_id: row.try_get(first)?,
                recipient_binding: row.try_get(first + 1)?,
            })
        };
        let job = read().map_err(|_| ClaimRefusal::Unavailable)?;
        Ok(Decoded { policy, job })
    }

    fn claim_record(&self, _job: &LeasedReviewCompletion) {}

    fn decode_lapsed(&self, row: &Row, first: usize) -> Result<Decoded<()>, DispatchError> {
        let policy = self
            .decode_policy(row, first, first + 1)?
            .ok_or(DispatchError::Unavailable)?;
        Ok(Decoded { policy, job: () })
    }

    fn decode_expired(&self, _row: &Row, _first: usize) -> Result<(), DispatchError> {
        // The core sweeps no expiry: a row past its retention is expired when
        // it is next claimed, and erased by review retention.
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

    // Completion wake-ups carry no review content and have no audit
    // lifecycle of their own: the review's terminal event is the audited
    // fact, and the outbox row records where its delivery stands.
    async fn record_attempt_audit(
        &self,
        _job: &LeasedJob<LeasedReviewCompletion>,
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
                tracing::info!(
                    "a Casework review completion delivery reached the end of its retention undelivered"
                );
            }
            DispatchEvent::JobQuarantined(reason) => {
                tracing::warn!(
                    reason = ?reason,
                    "a Casework review completion delivery was set aside without a send"
                );
            }
            DispatchEvent::TransitionFailed(code) => {
                tracing::warn!(
                    code = ?code,
                    "a Casework review completion claim did not complete"
                );
            }
            DispatchEvent::IterationFailed => {
                tracing::warn!("a Casework review completion delivery pass did not complete");
            }
        }
    }

    async fn lapsed_columns(
        &self,
        _transaction: &Transaction<'_>,
        _lapsed: &LapsedJob<()>,
        _disposition: Disposition,
    ) -> Result<registry_platform_dispatch::postgres::Columns, DispatchError> {
        Ok(registry_platform_dispatch::postgres::Columns::new()
            .set("last_failure_class", DELIVERY_FAILED))
    }

    fn finished_columns(
        &self,
        _job: &LeasedJob<LeasedReviewCompletion>,
        sent: &Sent<()>,
        _disposition: Disposition,
    ) -> Result<registry_platform_dispatch::postgres::Columns, DispatchError> {
        let class = match &sent.outcome {
            SendOutcome::Accepted { .. } => None,
            SendOutcome::Permanent { .. } => Some(DESTINATION_UNCONFIGURED),
            SendOutcome::Transient { .. } | SendOutcome::MaybeSent => Some(DELIVERY_FAILED),
        };
        Ok(registry_platform_dispatch::postgres::Columns::new().set("last_failure_class", class))
    }

    async fn may_have_reached_receiver(
        &self,
        _transaction: &Transaction<'_>,
        _key: &JobKey,
        _generation: i64,
        _attempt: i16,
    ) -> Result<bool, DispatchError> {
        // Every receiver deduplicates on the event id, so a delivery that
        // may have arrived is retried or set aside like one that did not.
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
        let class = if self.targets.contains_key(quarantine.key.part()) {
            DELIVERY_UNREADABLE
        } else {
            DESTINATION_UNCONFIGURED
        };
        let changed = transaction
            .execute(
                &format!(
                    "UPDATE {COMPLETION_TABLE} \
                        SET state = $4, next_attempt_at = NULL, attempt_started_at = NULL, \
                            lease_expires_at = NULL, lease_token = NULL, \
                            last_failure_class = $5, \
                            {stamp}updated_at = transaction_timestamp() \
                      WHERE event_id = $1 AND destination_id = $2 AND generation = $3"
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
        Ok(QuarantineDisposition::Quarantined(state))
    }
}

/// The send half: one wake-up to one configured destination.
pub(super) struct CompletionTransport {
    client: reqwest::Client,
    targets: CompletionTargets,
}

impl CompletionTransport {
    pub(super) fn new(client: reqwest::Client, targets: CompletionTargets) -> Self {
        Self { client, targets }
    }
}

#[async_trait]
impl DispatchTransport for CompletionTransport {
    type Job = LeasedReviewCompletion;
    type Detail = ();

    async fn send(
        &self,
        job: &LeasedJob<LeasedReviewCompletion>,
    ) -> Result<Sent<()>, DispatchError> {
        let Some(target) = self.targets.get(&job.job.destination_id) else {
            return Ok(Sent {
                outcome: SendOutcome::Permanent {
                    code: FailureCode::new(DESTINATION_UNCONFIGURED)
                        .map_err(|_| DispatchError::Unavailable)?,
                },
                detail: (),
            });
        };
        let outcome = if deliver_review_completion(&self.client, target, &job.job).await {
            SendOutcome::Accepted {
                receiver_reference: None,
            }
        } else {
            SendOutcome::Transient { retry_after: None }
        };
        Ok(Sent {
            outcome,
            detail: (),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn normalized(sql: &str) -> String {
        sql.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    #[test]
    fn the_completion_outbox_migration_is_exactly_the_dispatch_core_shape() {
        let migration = include_str!("../../migrations/0100_reviews.sql");
        let table = JobTable::new("public", COMPLETION_TABLE, "event_id", "destination_id")
            .expect("the completion outbox table names");
        let declared = normalized(&table.create_statements().join("\n").replace("public.", ""));
        let start = migration
            .find("CREATE TABLE IF NOT EXISTS casework_review_completion_outbox")
            .expect("the completion outbox table");
        let end = migration
            .find("ALTER TABLE casework_review_completion_outbox")
            .expect("the completion outbox table's own columns");
        assert_eq!(normalized(&migration[start..end]), declared);
    }

    fn target(maximum_attempts: u32, retry: Duration) -> ReviewCompletionTarget {
        ReviewCompletionTarget {
            url: "http://127.0.0.1/completion".to_owned(),
            credential: super::super::ReviewCompletionCredential::Bearer(
                registry_platform_httputil::BearerToken::new("completion-secret".to_owned())
                    .expect("test bearer token"),
            ),
            timeout: Duration::from_secs(30),
            maximum_attempts,
            retry,
        }
    }

    #[test]
    fn every_configured_destination_maps_to_a_valid_frozen_policy() {
        let bound = attempt_bound().expect("the configured attempt timeout bound");
        let retained_until = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000_000);
        for (attempts, retry) in [
            (1, Duration::from_secs(1)),
            (3, Duration::from_secs(30)),
            (100, Duration::from_secs(86_400)),
        ] {
            let policy = completion_policy(&target(attempts, retry), retained_until)
                .expect("a configured destination policy");
            assert!(policy.is_valid(&bound), "{attempts} attempts");
            assert_eq!(i64::from(policy.maximum_attempts), i64::from(attempts));
            assert_eq!(policy.on_uncertain, UncertainOutcome::Retry);
            assert_eq!(policy.expires_at, Some(retained_until));
            let RetrySchedule::Frozen { delays_ms } = policy.retry else {
                panic!("a frozen retry schedule");
            };
            assert_eq!(
                delays_ms.len(),
                usize::try_from(attempts - 1).expect("delays")
            );
            assert!(delays_ms
                .iter()
                .all(|delay| *delay == i64::try_from(retry.as_millis()).expect("delay")));
        }
    }

    #[test]
    fn a_destination_outside_the_dispatch_bounds_has_no_policy() {
        let retained_until = SystemTime::UNIX_EPOCH;
        assert!(completion_policy(&target(0, Duration::from_secs(1)), retained_until).is_none());
        assert!(completion_policy(
            &target(u32::from(u16::MAX), Duration::from_secs(1)),
            retained_until
        )
        .is_none());
    }
}
