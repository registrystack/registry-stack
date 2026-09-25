// SPDX-License-Identifier: Apache-2.0

//! The hook delivery tables over the generic dispatch core.
//!
//! `registry_webhook_delivery_state` is the job table, keyed by `event_id`
//! and `compiled_delivery_id`. The captured policy and payload live in the
//! delivery and outbox rows the statements below join; every lease, fence,
//! reap, retry, dead letter, expiry, and replay transition runs in
//! [`registry_platform_dispatch::postgres::Dispatcher`], and this store
//! supplies only what is hook-owned: the frozen policy decoding, the audit
//! mapping, the proposal and answer bookkeeping columns, and the retained
//! payload erasure.

use std::time::Duration;

use async_trait::async_trait;
use registry_platform_dispatch::postgres::{
    AttemptAudit, ClaimRefusal, Columns, Decoded, DispatchConnection, DispatchEvent, DispatchSql,
    DispatchStore, Disposition, ExpirySql, JobKey, JobState, LapsedJob, LeasedJob, SelectSql,
    TargetAction, Transition, TransitionAudit, TransitionCode,
};
use registry_platform_dispatch::{
    AttemptTimeoutBound, DispatchError, JobPolicy, RetrySchedule, Sent, UncertainOutcome,
};
use tokio_postgres::{Row, Transaction};

use super::seams::{
    DeliveryAuditDisposition, DeliveryAuditOutcome, DeliveryAuditPhase, DeliveryAuditRecord,
    DeliveryError, DeliveryOperationalEvent, DeliverySeams, DeliveryTransitionCode,
    HookDestination, HookHandler, HookHandlerBinding, ProposalReceiptRecovery,
};
use super::service::{
    bounded_text, proposal_columns, validate_captured_policy, AttemptResult, ProposalColumns,
};
use crate::{delivery_schema, HookHandlerKind};

pub(super) const STATE_TABLE: &str = "registry_webhook_delivery_state";
pub(super) const ID_COLUMN: &str = "event_id";
pub(super) const PART_COLUMN: &str = "compiled_delivery_id";

/// The operator may replay only a dead-lettered delivery.
pub(super) const REPLAYABLE: &[JobState] = &[JobState::DeadLettered];

/// The captured attempt timeouts a hook delivery may carry.
pub(super) fn attempt_timeout_bound() -> AttemptTimeoutBound {
    AttemptTimeoutBound::new(Duration::from_millis(100), Duration::from_secs(10))
        .expect("the hook attempt-timeout bound is well formed")
}

/// The hook-owned halves of the core's statements.
pub(super) const DISPATCH_SQL: DispatchSql = DispatchSql {
    claim: SelectSql {
        columns: "delivery.deployed_attempt_timeout_ms,
                  delivery.deployed_maximum_attempts,
                  delivery.retry_delays_ms,
                  delivery.package_revision,
                  delivery.handler_kind",
        joins: "JOIN {schema}.registry_webhook_deliveries AS delivery
                  ON delivery.event_id = state.event_id
                 AND delivery.compiled_delivery_id = state.compiled_delivery_id
                JOIN {schema}.registry_outbox AS outbox
                  ON outbox.event_id = delivery.event_id",
        predicate: "state.attempt < delivery.deployed_maximum_attempts
                    AND outbox.payload IS NOT NULL
                    AND outbox.payload_expires_at > transaction_timestamp()",
    },
    lapsed: SelectSql {
        columns: "delivery.deployed_attempt_timeout_ms,
                  delivery.deployed_maximum_attempts,
                  delivery.retry_delays_ms,
                  delivery.package_revision",
        joins: "JOIN {schema}.registry_webhook_deliveries AS delivery
                  ON delivery.event_id = state.event_id
                 AND delivery.compiled_delivery_id = state.compiled_delivery_id",
        predicate: "TRUE",
    },
    expiry: Some(ExpirySql {
        states: &[JobState::Pending, JobState::DeadLettered],
        select: SelectSql {
            columns: "delivery.package_revision",
            joins: "JOIN {schema}.registry_webhook_deliveries AS delivery
                      ON delivery.event_id = state.event_id
                     AND delivery.compiled_delivery_id = state.compiled_delivery_id
                    JOIN {schema}.registry_outbox AS outbox
                      ON outbox.event_id = delivery.event_id",
            predicate: "outbox.payload IS NOT NULL
                        AND outbox.payload_expires_at <= transaction_timestamp()",
        },
        order_by: "outbox.payload_expires_at",
        lock_of: "state, outbox",
    }),
    target: SelectSql {
        columns: "delivery.operator_replay,
                  delivery.package_revision,
                  delivery.logical_destination_id,
                  delivery.destination_binding_digest,
                  delivery.handler_kind",
        joins: "JOIN {schema}.registry_webhook_deliveries AS delivery
                  ON delivery.event_id = state.event_id
                 AND delivery.compiled_delivery_id = state.compiled_delivery_id
                JOIN {schema}.registry_outbox AS outbox
                  ON outbox.event_id = delivery.event_id",
        predicate: "outbox.payload IS NOT NULL
                    AND outbox.payload_expires_at > transaction_timestamp()",
    },
};

impl From<DispatchError> for DeliveryError {
    fn from(_error: DispatchError) -> Self {
        Self::Unavailable
    }
}

impl From<DeliveryError> for DispatchError {
    fn from(_error: DeliveryError) -> Self {
        Self::Unavailable
    }
}

/// What a claim decodes for the send: the revision the row was captured
/// under and the handler kind it binds.
pub(super) struct HookJob {
    pub(super) package_revision: String,
    pub(super) handler_kind: HookHandlerKind,
}

/// What a recovery, expiry, or replay row decodes for its audit.
pub(super) struct HookRecord {
    package_revision: String,
}

/// The dispatch store over one product's delivery seams.
pub(super) struct HookStore<S: DeliverySeams> {
    pub(super) seams: S,
    pub(super) schema: String,
}

impl<S: DeliverySeams> HookStore<S> {
    fn sql(&self, template: &str) -> String {
        delivery_schema::render(&self.schema, template)
    }
}

/// Whether the binding a retained row was written against is still the
/// active one: for the `url` kind that is the activated destination, and for
/// a local kind it is the reviewed program the deployed package holds under
/// the same digest.
pub(super) fn binding_is_activated<S: DeliverySeams>(
    seams: &S,
    handler_kind: Option<HookHandlerKind>,
    logical_destination_id: Option<&str>,
    compiled_delivery_id: &str,
    package_revision: &str,
    destination_binding_digest: &str,
) -> bool {
    match handler_kind {
        Some(HookHandlerKind::Url) => logical_destination_id
            .and_then(|id| seams.destination(id))
            .is_some_and(|destination| destination.binding_digest() == destination_binding_digest),
        Some(kind @ (HookHandlerKind::Rhai | HookHandlerKind::Wasm)) => {
            logical_destination_id.is_none()
                && seams
                    .handler(HookHandlerBinding {
                        kind,
                        compiled_delivery_id,
                        package_revision,
                        handler_digest: destination_binding_digest,
                    })
                    .is_some_and(|handler| handler.handler_digest() == destination_binding_digest)
        }
        None => false,
    }
}

/// The captured frozen profile as the core's policy. Hook delivery retries
/// every failure, including a lapsed lease, and never expires a retry early:
/// payload expiry is its own transition.
fn captured_policy(
    deployed_attempt_timeout_ms: i64,
    deployed_maximum_attempts: i16,
    retry_delays_ms: Vec<i64>,
) -> Result<JobPolicy, DeliveryError> {
    Ok(JobPolicy {
        attempt_timeout: Duration::from_millis(
            u64::try_from(deployed_attempt_timeout_ms).map_err(|_| DeliveryError::Unavailable)?,
        ),
        maximum_attempts: deployed_maximum_attempts,
        retry: RetrySchedule::Frozen {
            delays_ms: retry_delays_ms,
        },
        on_uncertain: UncertainOutcome::Retry,
        expires_at: None,
    })
}

/// The captured policy columns, validated exactly as the delivery tables
/// bound them.
fn decode_policy(row: &Row, first: usize) -> Result<JobPolicy, DeliveryError> {
    let deployed_attempt_timeout_ms = row.try_get::<_, i64>(first)?;
    let deployed_maximum_attempts = row.try_get::<_, i16>(first + 1)?;
    let retry_delays_ms = row.try_get::<_, Vec<i64>>(first + 2)?;
    validate_captured_policy(
        deployed_attempt_timeout_ms,
        deployed_maximum_attempts,
        &retry_delays_ms,
    )?;
    captured_policy(
        deployed_attempt_timeout_ms,
        deployed_maximum_attempts,
        retry_delays_ms,
    )
}

const fn audit_disposition(
    disposition: Disposition,
) -> Result<DeliveryAuditDisposition, DispatchError> {
    match disposition {
        Disposition::Leased => Ok(DeliveryAuditDisposition::Leased),
        Disposition::Delivered => Ok(DeliveryAuditDisposition::Delivered),
        Disposition::RetryPending => Ok(DeliveryAuditDisposition::RetryPending),
        Disposition::DeadLettered => Ok(DeliveryAuditDisposition::DeadLettered),
        Disposition::Expired => Ok(DeliveryAuditDisposition::Expired),
        Disposition::ReplayPending => Ok(DeliveryAuditDisposition::ReplayPending),
        // Hook delivery holds no attempt as unknown and cancels nothing.
        Disposition::Unknown | Disposition::Cancelled => Err(DispatchError::Unavailable),
    }
}

const fn transition_code(code: TransitionCode) -> DeliveryTransitionCode {
    match code {
        TransitionCode::ClaimIdentityRefused => DeliveryTransitionCode::ClaimIdentityRefused,
        TransitionCode::ClaimRecoveryFailed => DeliveryTransitionCode::ClaimRecoveryFailed,
        TransitionCode::ClaimSelectFailed => DeliveryTransitionCode::ClaimSelectFailed,
        TransitionCode::ClaimPolicyRefused => DeliveryTransitionCode::ClaimPolicyRefused,
        TransitionCode::ClaimUpdateFailed => DeliveryTransitionCode::ClaimUpdateFailed,
        TransitionCode::ClaimAuditFailed => DeliveryTransitionCode::ClaimAuditFailed,
        TransitionCode::ClaimCommitFailed => DeliveryTransitionCode::ClaimCommitFailed,
    }
}

/// The proposal bookkeeping columns as owned extra columns of one terminal
/// transition.
fn with_proposal_columns(columns: Columns, proposal: &ProposalColumns<'_>) -> Columns {
    columns
        .set(
            "proposal_disposition",
            proposal.disposition.map(str::to_owned),
        )
        .set("proposal_resulting_revision", proposal.resulting_revision)
        .set("proposal_code", proposal.code.map(str::to_owned))
        .set("proposal_summary", proposal.summary.map(str::to_owned))
}

#[async_trait]
impl<S: DeliverySeams> DispatchStore for HookStore<S> {
    type Job = HookJob;
    type Record = HookRecord;
    type Detail = AttemptResult;

    async fn connection(&self) -> Result<DispatchConnection, DispatchError> {
        Ok(self.seams.connection().await?)
    }

    async fn verify_transaction(&self, transaction: &Transaction<'_>) -> Result<(), DispatchError> {
        Ok(self.seams.verify_transaction(transaction).await?)
    }

    fn claim_record(&self, job: &HookJob) -> HookRecord {
        HookRecord {
            package_revision: job.package_revision.clone(),
        }
    }

    fn decode_claim(&self, row: &Row, first: usize) -> Result<Decoded<HookJob>, ClaimRefusal> {
        let deployed_attempt_timeout_ms = row
            .try_get::<_, i64>(first)
            .map_err(|_| ClaimRefusal::Unavailable)?;
        let deployed_maximum_attempts = row
            .try_get::<_, i16>(first + 1)
            .map_err(|_| ClaimRefusal::Unavailable)?;
        let retry_delays_ms = row
            .try_get::<_, Vec<i64>>(first + 2)
            .map_err(|_| ClaimRefusal::Unavailable)?;
        let package_revision =
            bounded_text(row, first + 3, 256).map_err(|_| ClaimRefusal::Unavailable)?;
        let Some(handler_kind) = bounded_text(row, first + 4, 8)
            .ok()
            .and_then(|kind| HookHandlerKind::from_spelling(&kind))
        else {
            return Err(ClaimRefusal::PolicyRefused);
        };
        validate_captured_policy(
            deployed_attempt_timeout_ms,
            deployed_maximum_attempts,
            &retry_delays_ms,
        )
        .map_err(|_| ClaimRefusal::PolicyRefused)?;
        let policy = captured_policy(
            deployed_attempt_timeout_ms,
            deployed_maximum_attempts,
            retry_delays_ms,
        )
        .map_err(|_| ClaimRefusal::PolicyRefused)?;
        Ok(Decoded {
            policy,
            job: HookJob {
                package_revision,
                handler_kind,
            },
        })
    }

    fn decode_lapsed(&self, row: &Row, first: usize) -> Result<Decoded<HookRecord>, DispatchError> {
        let policy = decode_policy(row, first)?;
        let package_revision = bounded_text(row, first + 3, 256)?;
        Ok(Decoded {
            policy,
            job: HookRecord { package_revision },
        })
    }

    fn decode_expired(&self, row: &Row, first: usize) -> Result<HookRecord, DispatchError> {
        Ok(HookRecord {
            package_revision: bounded_text(row, first, 256)?,
        })
    }

    fn decode_target(
        &self,
        row: &Row,
        first: usize,
        key: &JobKey,
        action: TargetAction,
    ) -> Result<Option<HookRecord>, DispatchError> {
        if action != TargetAction::Replay {
            return Ok(None);
        }
        let operator_replay = row.try_get::<_, bool>(first)?;
        let package_revision = bounded_text(row, first + 1, 256)?;
        let logical_destination_id = row
            .try_get::<_, Option<String>>(first + 2)?
            .filter(|id| id.len() <= 64);
        let destination_binding_digest = bounded_text(row, first + 3, 71)?;
        let handler_kind = bounded_text(row, first + 4, 8)
            .ok()
            .and_then(|kind| HookHandlerKind::from_spelling(&kind));
        // The binding a replay re-opens must still be the one the row was
        // written against.
        let binding_activated = binding_is_activated(
            &self.seams,
            handler_kind,
            logical_destination_id.as_deref(),
            key.part(),
            &package_revision,
            &destination_binding_digest,
        );
        Ok((operator_replay && binding_activated).then_some(HookRecord { package_revision }))
    }

    async fn record_attempt_audit(
        &self,
        transaction: &Transaction<'_>,
        job: &LeasedJob<HookJob>,
        audit: AttemptAudit<'_, AttemptResult>,
    ) -> Result<(), DispatchError> {
        let (phase, outcome, disposition) = match audit {
            AttemptAudit::Started => (
                DeliveryAuditPhase::Attempt,
                DeliveryAuditOutcome::AttemptStarted,
                DeliveryAuditDisposition::Leased,
            ),
            AttemptAudit::Finished { sent, disposition } => (
                DeliveryAuditPhase::Terminal,
                sent.detail.outcome,
                audit_disposition(disposition)?,
            ),
        };
        Ok(self
            .seams
            .record_audit(
                transaction,
                DeliveryAuditRecord {
                    event_id: job.key.id(),
                    compiled_delivery_id: job.key.part(),
                    package_revision: &job.job.package_revision,
                    generation: job.generation,
                    attempt: job.attempt,
                    phase,
                    outcome,
                    disposition,
                },
            )
            .await?)
    }

    async fn record_transition_audit(
        &self,
        transaction: &Transaction<'_>,
        audit: TransitionAudit<'_, HookRecord>,
    ) -> Result<(), DispatchError> {
        let (phase, outcome) = match audit.transition {
            Transition::LeaseLapsed(_) => (
                DeliveryAuditPhase::Terminal,
                DeliveryAuditOutcome::WorkerInterrupted,
            ),
            Transition::Expired { .. } => (
                DeliveryAuditPhase::Terminal,
                DeliveryAuditOutcome::PayloadExpired,
            ),
            Transition::Replayed { .. } => (
                DeliveryAuditPhase::Replay,
                DeliveryAuditOutcome::ReplayRequested,
            ),
            Transition::Cancelled => return Err(DispatchError::Unavailable),
        };
        Ok(self
            .seams
            .record_audit(
                transaction,
                DeliveryAuditRecord {
                    event_id: audit.key.id(),
                    compiled_delivery_id: audit.key.part(),
                    package_revision: &audit.record.package_revision,
                    generation: audit.generation,
                    attempt: audit.attempt,
                    phase,
                    outcome,
                    disposition: audit_disposition(audit.transition.disposition())?,
                },
            )
            .await?)
    }

    fn operational_event(&self, event: DispatchEvent) {
        self.seams.operational_event(match event {
            DispatchEvent::IterationFailed => DeliveryOperationalEvent::IterationFailed,
            DispatchEvent::TransitionFailed(code) => {
                DeliveryOperationalEvent::TransitionFailed(transition_code(code))
            }
            // The hook operational vocabulary reports failures only; an
            // expiry is recorded by its delivery audit.
            DispatchEvent::JobExpired => return,
            // The hook store never quarantines, so the core never reports
            // one: a refused hook row fails its claim instead.
            DispatchEvent::JobQuarantined(_) => return,
        });
    }

    async fn lapsed_columns(
        &self,
        transaction: &Transaction<'_>,
        lapsed: &LapsedJob<HookRecord>,
        disposition: Disposition,
    ) -> Result<Columns, DispatchError> {
        if disposition != Disposition::DeadLettered {
            return Ok(Columns::new());
        }
        // The final worker may have committed a proposal before dying or
        // losing its lease. Recover under the same delivery-scoped boundary
        // before the reaper makes that row terminal; otherwise this direct
        // dead-letter path would hide the committed application behind an
        // all-null proposal disposition.
        let proposal = self
            .seams
            .recover_proposal_receipt_in_transaction(
                transaction,
                ProposalReceiptRecovery {
                    event_id: lapsed.key.id(),
                    compiled_delivery_id: lapsed.key.part(),
                },
            )
            .await?;
        let columns = proposal_columns("dead_lettered", proposal.as_ref())?;
        Ok(with_proposal_columns(Columns::new(), &columns))
    }

    fn finished_columns(
        &self,
        _job: &LeasedJob<HookJob>,
        sent: &Sent<AttemptResult>,
        disposition: Disposition,
    ) -> Result<Columns, DispatchError> {
        // The raw answer is erased when delivery becomes terminal: the row
        // retains the digest, disposition, code, and bounded summary, never
        // the answer bytes, so nothing delivered stays readable as a payload.
        let (state, message_digest) = match disposition {
            Disposition::Delivered => (
                "delivered",
                sent.detail
                    .answer
                    .as_ref()
                    .map(|answer| answer.digest.to_vec()),
            ),
            Disposition::DeadLettered => ("dead_lettered", None),
            Disposition::RetryPending => return Ok(Columns::new()),
            _ => return Err(DispatchError::Unavailable),
        };
        let columns = proposal_columns(state, sent.detail.proposal.as_ref())?;
        Ok(with_proposal_columns(
            Columns::new()
                .set("handler_message", None::<Vec<u8>>)
                .set("handler_message_digest", message_digest),
            &columns,
        ))
    }

    async fn after_finished(
        &self,
        transaction: &Transaction<'_>,
        job: &LeasedJob<HookJob>,
        disposition: Disposition,
    ) -> Result<(), DispatchError> {
        if disposition != Disposition::Delivered {
            return Ok(());
        }
        let erased = transaction
            .execute(
                &self.sql(
                    "UPDATE {schema}.registry_outbox
                        SET payload = NULL
                      WHERE event_id = $1 AND payload IS NOT NULL",
                ),
                &[&job.key.id()],
            )
            .await?;
        if erased != 1 {
            return Err(DispatchError::Unavailable);
        }
        Ok(())
    }

    async fn after_expired(
        &self,
        transaction: &Transaction<'_>,
        key: &JobKey,
        _record: &HookRecord,
    ) -> Result<(), DispatchError> {
        let payload_changed = transaction
            .execute(
                &self.sql(
                    "UPDATE {schema}.registry_outbox
                    SET payload = NULL
                  WHERE event_id = $1
                    AND payload IS NOT NULL
                    AND payload_expires_at <= transaction_timestamp()",
                ),
                &[&key.id()],
            )
            .await?;
        if payload_changed != 1 {
            return Err(DispatchError::Unavailable);
        }
        Ok(())
    }
}
