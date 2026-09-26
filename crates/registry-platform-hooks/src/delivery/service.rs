// SPDX-License-Identifier: Apache-2.0

//! The at-least-once delivery worker: claim, send, finalize, and the
//! operator status and replay surface.
//!
//! This is the moved delivery core. Claim, lease/CAS, lease reaping, retry
//! scheduling, dead-lettering, payload expiry, attempt-budget accounting,
//! idempotency-key construction, and transport-vs-deadline classification
//! keep the behavior they had while the worker lived in the owning product's
//! runtime; every product-owned input arrives through the seams, and the
//! worker sends the captured envelope bytes unchanged, with the delivery
//! attributes the transport carries beside them.

use std::time::{Duration, SystemTime};

use registry_platform_httputil::destination::{DestinationSendError, EventDeliveryHeaders};
use sha2::{Digest, Sha256};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use tokio::sync::watch;
use tokio::time::Instant;
use tokio_postgres::Transaction;
use uuid::Uuid;

use super::seams::{
    DeliveryAuditDisposition, DeliveryAuditOutcome, DeliveryAuditPhase, DeliveryAuditRecord,
    DeliveryError, DeliveryOperationalEvent, DeliverySeams, DeliverySignatureFields,
    DeliveryTransitionCode, DestinationAnswer, HookDestination, HookHandler, HookHandlerBinding,
    ProposalApplication, ProposalOutcome, ProposalReceiptRecovery,
};
use crate::delivery_schema;
use crate::envelope::{EnvelopeLimits, HookEnvelope};
use crate::{ErrorCategory, HandlerOutputLimits, HookHandlerKind, HookMessage};

impl From<tokio_postgres::Error> for DeliveryError {
    fn from(_error: tokio_postgres::Error) -> Self {
        Self::Unavailable
    }
}

const LEASE_FINALIZATION_ALLOWANCE: Duration = Duration::from_secs(5);
const WORKER_POLL_INTERVAL: Duration = Duration::from_millis(100);
/// The waits between the read-backs of a transition whose commit returned an
/// error: one fewer than the read-backs, and short, since a caller is failing
/// while they run.
const READ_BACK_BACKOFF: [Duration; 2] = [Duration::from_millis(50), Duration::from_millis(100)];
pub const MAX_DELIVERY_STATUS_RESULTS: u16 = 100;

/// The product-supplied constants the worker cannot derive.
///
/// The adopting product passes its own values; the values it used before the
/// move keep the bytes on the wire identical.
pub struct DeliveryConfig {
    /// The product schema that holds the delivery tables. The name is
    /// interpolated into SQL, so only a plain lowercase SQL identifier is
    /// accepted.
    pub schema: String,
    /// The product's idempotency-key domain, bound into every delivery
    /// idempotency key. It must stay stable for the life of retained work,
    /// because a changed domain changes every future key.
    pub idempotency_domain: Vec<u8>,
    /// The delivery source identity sent with every delivery (`ce-source`
    /// and the signed source component): the producing product and
    /// deployment identity.
    pub delivery_source: String,
}

/// A delivery-audit event held by the worker until it is recorded, such as
/// one whose transition must commit first.
#[derive(Clone)]
struct PendingAudit {
    event_id: Uuid,
    compiled_delivery_id: String,
    package_revision: String,
    generation: i64,
    attempt: i16,
    phase: DeliveryAuditPhase,
    outcome: DeliveryAuditOutcome,
    disposition: DeliveryAuditDisposition,
}

impl PendingAudit {
    fn record(&self) -> DeliveryAuditRecord<'_> {
        DeliveryAuditRecord {
            event_id: self.event_id,
            compiled_delivery_id: &self.compiled_delivery_id,
            package_revision: &self.package_revision,
            generation: self.generation,
            attempt: self.attempt,
            phase: self.phase,
            outcome: self.outcome,
            disposition: self.disposition,
        }
    }
}

/// The delivery worker over one product's seams.
#[derive(Clone)]
pub struct DeliveryService<S: DeliverySeams> {
    seams: S,
    schema: String,
    idempotency_domain: Vec<u8>,
    delivery_source: String,
}

impl<S: DeliverySeams> DeliveryService<S> {
    /// Bind the worker to one product's seams and constants.
    ///
    /// # Panics
    ///
    /// Panics when `config.schema` is not a plain lowercase SQL identifier of
    /// at most 63 bytes, because the schema name is interpolated into SQL.
    #[must_use]
    pub fn new(seams: S, config: DeliveryConfig) -> Self {
        let schema = delivery_schema::require_plain_identifier(&config.schema).to_owned();
        Self {
            seams,
            schema,
            idempotency_domain: config.idempotency_domain,
            delivery_source: config.delivery_source,
        }
    }

    /// Claim, audit, send, settle, and finalize at most one due delivery.
    ///
    /// The pre-egress audit and lease commit before request rendering or
    /// destination policy execution. Delivery is therefore explicitly
    /// at-least-once when a process stops after network I/O and before CAS
    /// finalization. An accepted answer that is a proposal is applied
    /// through the product's apply seam between the answer and
    /// finalization; an uncertain apply leaves the lease for expiry
    /// recovery rather than recording a disposition.
    pub async fn deliver_once(&self) -> Result<DeliveryOutcome, DeliveryError> {
        let Some(claim) = self.claim().await? else {
            return Ok(DeliveryOutcome::Idle);
        };
        let attempt = self.reload_and_send(&claim).await?;
        self.finalize(&claim, attempt).await
    }

    /// Refuse startup or operator use if retained work cannot use its exact
    /// captured destination under the active deployment bindings.
    pub async fn verify_retained_bindings(&self) -> Result<(), DeliveryError> {
        let mut client = self.seams.connection().await?;
        let transaction = client.transaction().await?;
        self.seams.verify_transaction(&transaction).await?;
        let rows = transaction
            .query(
                &self.sql(
                    "SELECT DISTINCT delivery.handler_kind,
                                 delivery.logical_destination_id,
                                 delivery.compiled_delivery_id,
                                 delivery.package_revision,
                                 delivery.destination_binding_digest
                   FROM {schema}.registry_webhook_delivery_state AS state
                   JOIN {schema}.registry_webhook_deliveries AS delivery
                     ON delivery.event_id = state.event_id
                    AND delivery.compiled_delivery_id = state.compiled_delivery_id
                   JOIN {schema}.registry_outbox AS outbox
                     ON outbox.event_id = delivery.event_id
                  WHERE (
                            state.state IN ('pending', 'leased')
                            OR (
                                state.state = 'dead_lettered'
                                AND delivery.operator_replay
                            )
                        )
                    AND outbox.payload IS NOT NULL
                    AND outbox.payload_expires_at > transaction_timestamp()",
                ),
                &[],
            )
            .await?;
        for row in rows {
            let handler_kind = bounded_text(&row, 0, 8)
                .ok()
                .and_then(|kind| HookHandlerKind::from_spelling(&kind));
            let logical_destination_id = row
                .try_get::<_, Option<String>>(1)?
                .filter(|id| id.len() <= 64);
            let compiled_delivery_id = bounded_delivery_id(&row, 2)?;
            let package_revision = bounded_text(&row, 3, 256)?;
            let destination_binding_digest = bounded_text(&row, 4, 71)?;
            // The binding a retained row must still use is the one it was
            // written against: for the `url` kind that is the activated
            // destination, and for a local kind it is the reviewed program
            // the deployed package holds under the same digest.
            let binding_activated = match handler_kind {
                Some(HookHandlerKind::Url) => logical_destination_id
                    .as_deref()
                    .and_then(|id| self.seams.destination(id))
                    .is_some_and(|destination| {
                        destination.binding_digest() == destination_binding_digest
                    }),
                Some(kind @ (HookHandlerKind::Rhai | HookHandlerKind::Wasm)) => {
                    logical_destination_id.is_none()
                        && self
                            .seams
                            .handler(HookHandlerBinding {
                                kind,
                                compiled_delivery_id: &compiled_delivery_id,
                                package_revision: &package_revision,
                                handler_digest: &destination_binding_digest,
                            })
                            .is_some_and(|handler| {
                                handler.handler_digest() == destination_binding_digest
                            })
                }
                None => false,
            };
            if !binding_activated {
                return Err(DeliveryError::Unavailable);
            }
        }
        transaction.commit().await?;
        Ok(())
    }

    /// Return bounded, value-free pending and terminal operator metadata.
    pub async fn list(&self, limit: u16) -> Result<Vec<DeliveryStatus>, DeliveryError> {
        if limit == 0 || limit > MAX_DELIVERY_STATUS_RESULTS {
            return Err(DeliveryError::Unavailable);
        }
        let mut client = self.seams.connection().await?;
        let transaction = client.transaction().await?;
        self.seams.verify_transaction(&transaction).await?;
        let rows = transaction
            .query(
                &self.sql(
                    "SELECT state.event_id, state.compiled_delivery_id,
                        state.generation, state.state, state.attempt,
                        outbox.payload IS NOT NULL
                            AND outbox.payload_expires_at > transaction_timestamp(),
                        outbox.payload_expires_at
                   FROM {schema}.registry_webhook_delivery_state AS state
                   JOIN {schema}.registry_outbox AS outbox
                     ON outbox.event_id = state.event_id
                  WHERE state.state IN ('pending', 'dead_lettered', 'expired')
                  ORDER BY state.updated_at DESC, state.event_id,
                           state.compiled_delivery_id
                  LIMIT $1",
                ),
                &[&i64::from(limit)],
            )
            .await?;
        let mut statuses = Vec::with_capacity(rows.len());
        for row in rows {
            let event_id = row.try_get::<_, Uuid>(0)?;
            let compiled_delivery_id = bounded_delivery_id(&row, 1)?;
            let generation = row.try_get::<_, i64>(2)?;
            let stored_state = bounded_text(&row, 3, 32)?;
            let attempt = row.try_get::<_, i16>(4)?;
            let payload_available = row.try_get::<_, bool>(5)?;
            let payload_expires_at = row.try_get::<_, SystemTime>(6)?;
            let state = delivery_status_kind(&stored_state, payload_available)?;
            statuses.push(DeliveryStatus {
                event_id,
                compiled_delivery_id,
                generation,
                state,
                attempt,
                payload_available,
                payload_expires_at: OffsetDateTime::from(payload_expires_at)
                    .format(&Rfc3339)
                    .map_err(|_| DeliveryError::Unavailable)?,
            });
        }
        transaction.commit().await?;
        Ok(statuses)
    }

    /// Reset one terminal delivery for an explicitly permitted operator replay
    /// and return the committed replacement generation.
    ///
    /// Every absent, stale, forbidden, or nonterminal target returns the same
    /// value-free refusal.
    pub async fn replay(
        &self,
        event_id: Uuid,
        compiled_delivery_id: &str,
        expected_generation: i64,
    ) -> Result<i64, DeliveryError>
    where
        S: Clone,
    {
        // The replay runs to its response in a task of its own: once its
        // request entry is accepted, a caller that stops waiting (a timeout
        // or a disconnect) cannot leave that request unanswered.
        let service = self.clone();
        let compiled_delivery_id = compiled_delivery_id.to_owned();
        tokio::spawn(async move {
            service
                .replay_in(event_id, &compiled_delivery_id, expected_generation)
                .await
        })
        .await
        .map_err(|_| DeliveryError::Unavailable)?
    }

    async fn replay_in(
        &self,
        event_id: Uuid,
        compiled_delivery_id: &str,
        expected_generation: i64,
    ) -> Result<i64, DeliveryError> {
        if compiled_delivery_id.is_empty()
            || compiled_delivery_id.len() > 256
            || expected_generation <= 0
        {
            return Err(DeliveryError::Unavailable);
        }
        let mut client = self.seams.connection().await?;
        let transaction = client.transaction().await?;
        self.seams.verify_transaction(&transaction).await?;
        let row = transaction
            .query_opt(
                &self.sql(
                    "SELECT state.generation, state.state, delivery.operator_replay,
                        delivery.package_revision, delivery.logical_destination_id,
                        delivery.destination_binding_digest, delivery.handler_kind
                 FROM {schema}.registry_webhook_delivery_state AS state
                 JOIN {schema}.registry_webhook_deliveries AS delivery
                   ON delivery.event_id = state.event_id
                  AND delivery.compiled_delivery_id = state.compiled_delivery_id
                 JOIN {schema}.registry_outbox AS outbox
                   ON outbox.event_id = delivery.event_id
                 WHERE state.event_id = $1
                   AND state.compiled_delivery_id = $2
                   AND outbox.payload IS NOT NULL
                   AND outbox.payload_expires_at > transaction_timestamp()
                 FOR UPDATE OF state",
                ),
                &[&event_id, &compiled_delivery_id],
            )
            .await?
            .ok_or(DeliveryError::Unavailable)?;
        let generation = row.try_get::<_, i64>(0)?;
        let state = row.try_get::<_, String>(1)?;
        let operator_replay = row.try_get::<_, bool>(2)?;
        let package_revision = bounded_text(&row, 3, 256)?;
        let logical_destination_id = row
            .try_get::<_, Option<String>>(4)?
            .filter(|id| id.len() <= 64);
        let destination_binding_digest = bounded_text(&row, 5, 71)?;
        let handler_kind = bounded_text(&row, 6, 8)
            .ok()
            .and_then(|kind| HookHandlerKind::from_spelling(&kind));
        // The binding a replay re-opens must still be the one the row was
        // written against: for the `url` kind that is the activated
        // destination, and for a local kind it is the reviewed program the
        // deployed package holds under the same digest.
        let binding_activated = match handler_kind {
            Some(HookHandlerKind::Url) => logical_destination_id
                .as_deref()
                .and_then(|id| self.seams.destination(id))
                .is_some_and(|destination| {
                    destination.binding_digest() == destination_binding_digest
                }),
            Some(kind @ (HookHandlerKind::Rhai | HookHandlerKind::Wasm)) => {
                logical_destination_id.is_none()
                    && self
                        .seams
                        .handler(HookHandlerBinding {
                            kind,
                            compiled_delivery_id,
                            package_revision: &package_revision,
                            handler_digest: &destination_binding_digest,
                        })
                        .is_some_and(|handler| {
                            handler.handler_digest() == destination_binding_digest
                        })
            }
            None => false,
        };
        if generation != expected_generation
            || !operator_replay
            || state != "dead_lettered"
            || !binding_activated
        {
            return Err(DeliveryError::Unavailable);
        }
        let next_generation = generation
            .checked_add(1)
            .ok_or(DeliveryError::Unavailable)?;
        // The replay's request is on record before the reset, and its
        // response records whether the reset committed.
        let replay = PendingAudit {
            event_id,
            compiled_delivery_id: compiled_delivery_id.to_owned(),
            package_revision: package_revision.clone(),
            generation: next_generation,
            attempt: 0,
            phase: DeliveryAuditPhase::Replay,
            outcome: DeliveryAuditOutcome::ReplayRequested,
            disposition: DeliveryAuditDisposition::ReplayPending,
        };
        self.seams.record_audit(replay.record()).await?;
        let reset = match self
            .reset_for_replay(&transaction, event_id, compiled_delivery_id, generation)
            .await
        {
            // A reset that failed or changed no row did not commit.
            Err(error) => Err(error),
            Ok(()) => match transaction.commit().await {
                Ok(()) => Ok(()),
                Err(error) => {
                    // The commit's acknowledgement may be all that was lost.
                    if self
                        .transition_committed(
                            &PendingAudit {
                                outcome: DeliveryAuditOutcome::ReplayCommitted,
                                ..replay.clone()
                            },
                            None,
                        )
                        .await
                        == Some(true)
                    {
                        Ok(())
                    } else {
                        Err(error.into())
                    }
                }
            },
        };
        let (outcome, disposition) = if reset.is_ok() {
            (
                DeliveryAuditOutcome::ReplayCommitted,
                DeliveryAuditDisposition::ReplayPending,
            )
        } else {
            (
                DeliveryAuditOutcome::ReplayRefused,
                DeliveryAuditDisposition::DeadLettered,
            )
        };
        let recorded = self
            .seams
            .record_audit(
                PendingAudit {
                    outcome,
                    disposition,
                    ..replay
                }
                .record(),
            )
            .await;
        reset?;
        recorded?;
        Ok(next_generation)
    }

    /// Reset one dead-lettered delivery to pending under its next generation,
    /// leaving the commit to the caller.
    async fn reset_for_replay(
        &self,
        transaction: &Transaction<'_>,
        event_id: Uuid,
        compiled_delivery_id: &str,
        generation: i64,
    ) -> Result<(), DeliveryError> {
        let next_generation = generation
            .checked_add(1)
            .ok_or(DeliveryError::Unavailable)?;
        let changed = transaction
            .execute(
                &self.sql(
                    "UPDATE {schema}.registry_webhook_delivery_state
                 SET generation = $4,
                     state = 'pending',
                     attempt = 0,
                     next_attempt_at = transaction_timestamp(),
                     attempt_started_at = NULL,
                     lease_expires_at = NULL,
                     lease_token = NULL,
                     delivered_at = NULL,
                     dead_lettered_at = NULL,
                     expired_at = NULL,
                     updated_at = transaction_timestamp()
                 WHERE event_id = $1
                   AND compiled_delivery_id = $2
                   AND generation = $3
                   AND state = 'dead_lettered'",
                ),
                &[
                    &event_id,
                    &compiled_delivery_id,
                    &generation,
                    &next_generation,
                ],
            )
            .await?;
        if changed != 1 {
            return Err(DeliveryError::Unavailable);
        }
        Ok(())
    }

    async fn claim(&self) -> Result<Option<DeliveryClaim>, DeliveryError> {
        let mut client = self.seams.connection().await?;
        let transaction = client.transaction().await?;
        if self.seams.verify_transaction(&transaction).await.is_err() {
            self.refused(DeliveryTransitionCode::ClaimIdentityRefused);
            return Err(DeliveryError::Unavailable);
        }
        // Recovered and expired deliveries are recorded once this
        // transaction commits.
        let mut committed = Vec::new();
        if self
            .reap_expired_leases(&transaction, &mut committed)
            .await
            .is_err()
        {
            self.refused(DeliveryTransitionCode::ClaimRecoveryFailed);
            return Err(DeliveryError::Unavailable);
        }
        self.expire_retained_payload(&transaction, &mut committed)
            .await?;
        let row = transaction
            .query_opt(
                &self.sql(
                    "SELECT state.event_id, state.compiled_delivery_id,
                        state.generation, state.attempt,
                        delivery.deployed_attempt_timeout_ms,
                        delivery.deployed_maximum_attempts,
                        delivery.retry_delays_ms,
                        delivery.package_revision,
                        delivery.handler_kind
                 FROM {schema}.registry_webhook_delivery_state AS state
                 JOIN {schema}.registry_webhook_deliveries AS delivery
                   ON delivery.event_id = state.event_id
                  AND delivery.compiled_delivery_id = state.compiled_delivery_id
                 JOIN {schema}.registry_outbox AS outbox
                   ON outbox.event_id = delivery.event_id
                 WHERE state.state = 'pending'
                   AND state.next_attempt_at <= transaction_timestamp()
                   AND state.attempt < delivery.deployed_maximum_attempts
                   AND outbox.payload IS NOT NULL
                   AND outbox.payload_expires_at > transaction_timestamp()
                 ORDER BY state.next_attempt_at, state.event_id, state.compiled_delivery_id
                 FOR UPDATE OF state SKIP LOCKED
                 LIMIT 1",
                ),
                &[],
            )
            .await
            .map_err(|_| {
                self.refused(DeliveryTransitionCode::ClaimSelectFailed);
                DeliveryError::Unavailable
            })?;
        let Some(row) = row else {
            if let Err(error) = transaction.commit().await {
                self.record_resolved(committed).await;
                return Err(error.into());
            }
            self.record_committed(committed).await?;
            return Ok(None);
        };
        let event_id = row.try_get::<_, Uuid>(0)?;
        let compiled_delivery_id = bounded_delivery_id(&row, 1)?;
        let generation = row.try_get::<_, i64>(2)?;
        let prior_attempt = row.try_get::<_, i16>(3)?;
        let deployed_attempt_timeout_ms = row.try_get::<_, i64>(4)?;
        let deployed_maximum_attempts = row.try_get::<_, i16>(5)?;
        let retry_delays_ms = row.try_get::<_, Vec<i64>>(6)?;
        let package_revision =
            bounded_text(&row, 7, 256).map_err(|_| DeliveryError::Unavailable)?;
        let Some(handler_kind) = bounded_text(&row, 8, 8)
            .ok()
            .and_then(|kind| HookHandlerKind::from_spelling(&kind))
        else {
            self.refused(DeliveryTransitionCode::ClaimPolicyRefused);
            return Err(DeliveryError::Unavailable);
        };
        let attempt = prior_attempt
            .checked_add(1)
            .filter(|attempt| *attempt <= deployed_maximum_attempts)
            .ok_or(DeliveryError::Unavailable)?;
        if validate_captured_policy(
            deployed_attempt_timeout_ms,
            deployed_maximum_attempts,
            &retry_delays_ms,
        )
        .is_err()
        {
            self.refused(DeliveryTransitionCode::ClaimPolicyRefused);
            return Err(DeliveryError::Unavailable);
        }
        let lease_token = Uuid::new_v4();
        let allowance_ms = i64::try_from(LEASE_FINALIZATION_ALLOWANCE.as_millis())
            .map_err(|_| DeliveryError::Unavailable)?;
        let changed = transaction
            .execute(
                &self.sql(
                    "UPDATE {schema}.registry_webhook_delivery_state
                 SET state = 'leased',
                     attempt = $5,
                     next_attempt_at = NULL,
                     attempt_started_at = transaction_timestamp(),
                     lease_expires_at = transaction_timestamp()
                         + ($6::bigint + $7::bigint) * interval '1 millisecond',
                     lease_token = $8,
                     updated_at = transaction_timestamp()
                 WHERE event_id = $1
                   AND compiled_delivery_id = $2
                   AND generation = $3
                   AND state = 'pending'
                   AND attempt = $4",
                ),
                &[
                    &event_id,
                    &compiled_delivery_id,
                    &generation,
                    &prior_attempt,
                    &attempt,
                    &deployed_attempt_timeout_ms,
                    &allowance_ms,
                    &lease_token,
                ],
            )
            .await
            .map_err(|_| {
                self.refused(DeliveryTransitionCode::ClaimUpdateFailed);
                DeliveryError::Unavailable
            })?;
        if changed != 1 {
            return Err(DeliveryError::Unavailable);
        }
        let attempt_started_at = transaction
            .query_one("SELECT transaction_timestamp()", &[])
            .await?
            .try_get::<_, SystemTime>(0)?;
        let started = PendingAudit {
            event_id,
            compiled_delivery_id: compiled_delivery_id.clone(),
            package_revision: package_revision.clone(),
            generation,
            attempt,
            phase: DeliveryAuditPhase::Attempt,
            outcome: DeliveryAuditOutcome::AttemptStarted,
            disposition: DeliveryAuditDisposition::Leased,
        };
        if self.seams.record_audit(started.record()).await.is_err() {
            self.refused(DeliveryTransitionCode::ClaimAuditFailed);
            return Err(DeliveryError::Unavailable);
        }
        if transaction.commit().await.is_err() {
            self.refused(DeliveryTransitionCode::ClaimCommitFailed);
            // A failed commit acknowledgement does not prove a rollback, so
            // read what the database holds. Each recovered or expired
            // delivery is recorded if it reads back as durable, whatever the
            // lease's own fate. A lease that did commit sends nothing from
            // here and is answered when it expires; one that rolled back, or
            // one whose fate cannot be read, is answered now, since a second
            // interrupted answer is harmless and none is not.
            let lease_committed = self.transition_committed(&started, Some(lease_token)).await;
            self.record_resolved(committed).await;
            if lease_committed != Some(true) {
                let interrupted = PendingAudit {
                    phase: DeliveryAuditPhase::Terminal,
                    outcome: DeliveryAuditOutcome::WorkerInterrupted,
                    disposition: DeliveryAuditDisposition::RetryPending,
                    ..started
                };
                // A refused entry has already stopped the product's writer,
                // which reports it; the claim fails either way.
                let _ = self.seams.record_audit(interrupted.record()).await;
            }
            return Err(DeliveryError::Unavailable);
        }
        self.record_committed(committed).await?;
        Ok(Some(DeliveryClaim {
            event_id,
            compiled_delivery_id,
            generation,
            attempt,
            attempt_started_at,
            lease_token,
            deployed_maximum_attempts,
            retry_delays_ms,
            package_revision,
            handler_kind,
        }))
    }

    async fn reap_expired_leases(
        &self,
        transaction: &Transaction<'_>,
        committed: &mut Vec<PendingAudit>,
    ) -> Result<(), DeliveryError> {
        let row = transaction
            .query_opt(
                &self.sql(
                    "SELECT state.event_id, state.compiled_delivery_id,
                        state.generation, state.attempt, state.lease_token,
                        delivery.deployed_attempt_timeout_ms,
                        delivery.deployed_maximum_attempts,
                        delivery.retry_delays_ms,
                        delivery.package_revision
                 FROM {schema}.registry_webhook_delivery_state AS state
                 JOIN {schema}.registry_webhook_deliveries AS delivery
                   ON delivery.event_id = state.event_id
                  AND delivery.compiled_delivery_id = state.compiled_delivery_id
                 WHERE state.state = 'leased'
                   AND state.lease_expires_at <= transaction_timestamp()
                 ORDER BY state.lease_expires_at, state.event_id, state.compiled_delivery_id
                 FOR UPDATE OF state SKIP LOCKED
                 LIMIT 1",
                ),
                &[],
            )
            .await?;
        let Some(row) = row else {
            return Ok(());
        };
        let event_id = row.try_get::<_, Uuid>(0)?;
        let compiled_delivery_id = bounded_delivery_id(&row, 1)?;
        let generation = row.try_get::<_, i64>(2)?;
        let attempt = row.try_get::<_, i16>(3)?;
        let lease_token = row.try_get::<_, Uuid>(4)?;
        let deployed_attempt_timeout_ms = row.try_get::<_, i64>(5)?;
        let deployed_maximum_attempts = row.try_get::<_, i16>(6)?;
        let retry_delays_ms = row.try_get::<_, Vec<i64>>(7)?;
        let package_revision = bounded_text(&row, 8, 256)?;
        validate_captured_policy(
            deployed_attempt_timeout_ms,
            deployed_maximum_attempts,
            &retry_delays_ms,
        )?;
        let dead_lettered = attempt >= deployed_maximum_attempts;
        // The final worker may have committed a proposal before dying or
        // losing its lease. Recover under the same delivery-scoped boundary
        // before the reaper makes that row terminal; otherwise this direct
        // dead-letter path would hide the committed application behind an
        // all-null proposal disposition.
        let proposal = if dead_lettered {
            self.seams
                .recover_proposal_receipt_in_transaction(
                    transaction,
                    ProposalReceiptRecovery {
                        event_id,
                        compiled_delivery_id: &compiled_delivery_id,
                    },
                )
                .await?
        } else {
            None
        };
        let changed = if dead_lettered {
            let columns = proposal_columns("dead_lettered", proposal.as_ref())?;
            transaction
                .execute(
                    &self.sql(
                        "UPDATE {schema}.registry_webhook_delivery_state
                     SET state = 'dead_lettered',
                         next_attempt_at = NULL,
                         attempt_started_at = NULL,
                         lease_expires_at = NULL,
                         lease_token = NULL,
                         proposal_disposition = $6,
                         proposal_resulting_revision = $7,
                         proposal_code = $8,
                         proposal_summary = $9,
                         dead_lettered_at = transaction_timestamp(),
                         updated_at = transaction_timestamp()
                     WHERE event_id = $1
                       AND compiled_delivery_id = $2
                       AND generation = $3
                       AND attempt = $4
                       AND lease_token = $5
                       AND state = 'leased'
                       AND lease_expires_at <= transaction_timestamp()",
                    ),
                    &[
                        &event_id,
                        &compiled_delivery_id,
                        &generation,
                        &attempt,
                        &lease_token,
                        &columns.disposition,
                        &columns.resulting_revision,
                        &columns.code,
                        &columns.summary,
                    ],
                )
                .await
        } else {
            let delay_ms = scheduled_retry_delay(&retry_delays_ms, attempt)?;
            transaction
                .execute(
                    &self.sql(
                        "UPDATE {schema}.registry_webhook_delivery_state
                     SET state = 'pending',
                         next_attempt_at = transaction_timestamp()
                             + $6::bigint * interval '1 millisecond',
                         attempt_started_at = NULL,
                         lease_expires_at = NULL,
                         lease_token = NULL,
                         updated_at = transaction_timestamp()
                     WHERE event_id = $1
                       AND compiled_delivery_id = $2
                       AND generation = $3
                       AND attempt = $4
                       AND lease_token = $5
                       AND state = 'leased'
                       AND lease_expires_at <= transaction_timestamp()",
                    ),
                    &[
                        &event_id,
                        &compiled_delivery_id,
                        &generation,
                        &attempt,
                        &lease_token,
                        &delay_ms,
                    ],
                )
                .await
        }?;
        if changed != 1 {
            return Err(DeliveryError::Unavailable);
        }
        committed.push(PendingAudit {
            event_id,
            compiled_delivery_id,
            package_revision,
            generation,
            attempt,
            phase: DeliveryAuditPhase::Terminal,
            outcome: DeliveryAuditOutcome::WorkerInterrupted,
            disposition: if dead_lettered {
                DeliveryAuditDisposition::DeadLettered
            } else {
                DeliveryAuditDisposition::RetryPending
            },
        });
        Ok(())
    }

    async fn expire_retained_payload(
        &self,
        transaction: &Transaction<'_>,
        committed: &mut Vec<PendingAudit>,
    ) -> Result<(), DeliveryError> {
        let row = transaction
            .query_opt(
                &self.sql(
                    "SELECT state.event_id, state.compiled_delivery_id,
                        state.generation, state.attempt, delivery.package_revision
                   FROM {schema}.registry_webhook_delivery_state AS state
                   JOIN {schema}.registry_webhook_deliveries AS delivery
                     ON delivery.event_id = state.event_id
                    AND delivery.compiled_delivery_id = state.compiled_delivery_id
                   JOIN {schema}.registry_outbox AS outbox
                     ON outbox.event_id = delivery.event_id
                  WHERE state.state IN ('pending', 'dead_lettered')
                    AND outbox.payload IS NOT NULL
                    AND outbox.payload_expires_at <= transaction_timestamp()
                  ORDER BY outbox.payload_expires_at, state.event_id,
                           state.compiled_delivery_id
                  FOR UPDATE OF state, outbox SKIP LOCKED
                  LIMIT 1",
                ),
                &[],
            )
            .await?;
        let Some(row) = row else {
            return Ok(());
        };
        let event_id = row.try_get::<_, Uuid>(0)?;
        let compiled_delivery_id = bounded_delivery_id(&row, 1)?;
        let generation = row.try_get::<_, i64>(2)?;
        let attempt = row.try_get::<_, i16>(3)?;
        let package_revision = bounded_text(&row, 4, 256)?;
        let state_changed = transaction
            .execute(
                &self.sql(
                    "UPDATE {schema}.registry_webhook_delivery_state
                    SET state = CASE WHEN state = 'pending' THEN 'expired' ELSE state END,
                        next_attempt_at = NULL,
                        attempt_started_at = NULL,
                        lease_expires_at = NULL,
                        lease_token = NULL,
                        expired_at = transaction_timestamp(),
                        updated_at = transaction_timestamp()
                  WHERE event_id = $1
                    AND compiled_delivery_id = $2
                    AND generation = $3
                    AND state IN ('pending', 'dead_lettered')",
                ),
                &[&event_id, &compiled_delivery_id, &generation],
            )
            .await?;
        let payload_changed = transaction
            .execute(
                &self.sql(
                    "UPDATE {schema}.registry_outbox
                    SET payload = NULL
                  WHERE event_id = $1
                    AND payload IS NOT NULL
                    AND payload_expires_at <= transaction_timestamp()",
                ),
                &[&event_id],
            )
            .await?;
        if state_changed != 1 || payload_changed != 1 {
            return Err(DeliveryError::Unavailable);
        }
        committed.push(PendingAudit {
            event_id,
            compiled_delivery_id,
            package_revision,
            generation,
            attempt,
            phase: DeliveryAuditPhase::Terminal,
            outcome: DeliveryAuditOutcome::PayloadExpired,
            disposition: DeliveryAuditDisposition::Expired,
        });
        Ok(())
    }

    async fn reload_and_send(&self, claim: &DeliveryClaim) -> Result<AttemptResult, DeliveryError> {
        let material = match self.reload_material(claim).await {
            Ok(material) => material,
            Err(MaterialLoadError::Unavailable) => return Err(DeliveryError::Unavailable),
            Err(MaterialLoadError::PayloadRefused) => {
                return Ok(DeliveryAuditOutcome::PayloadRefused.into())
            }
            Err(MaterialLoadError::BindingRefused) => {
                return Ok(material_binding_refusal(claim.handler_kind).into())
            }
        };
        if claim.handler_kind.is_local() {
            return self.run_local_handler(claim, material).await;
        }
        let Some(destination_id) = material.logical_destination_id.as_deref() else {
            return Ok(DeliveryAuditOutcome::DestinationBindingRefused.into());
        };
        let Some(destination) = self.seams.destination(destination_id) else {
            return Ok(DeliveryAuditOutcome::DestinationBindingRefused.into());
        };
        let deployed_timeout_ms = i64::try_from(destination.attempt_timeout().as_millis())
            .map_err(|_| DeliveryError::Unavailable)?;
        if destination.binding_digest() != material.destination_binding_digest
            || deployed_timeout_ms != material.deployed_attempt_timeout_ms
            || i16::from(destination.maximum_attempts()) != material.deployed_maximum_attempts
        {
            return Ok(DeliveryAuditOutcome::DestinationBindingRefused.into());
        }
        let delivery_time = OffsetDateTime::from(claim.attempt_started_at)
            .format(&Rfc3339)
            .map_err(|_| DeliveryError::Unavailable)?;
        let event_time = OffsetDateTime::from(material.event_time)
            .format(&Rfc3339)
            .map_err(|_| DeliveryError::Unavailable)?;
        let event_id = claim.event_id.to_string();
        let source = &self.delivery_source;
        let generation = claim.generation.to_string();
        let attempt = claim.attempt.to_string();
        let idempotency_key = delivery_idempotency_key(
            &self.idempotency_domain,
            claim.event_id,
            &claim.compiled_delivery_id,
            claim.generation,
            &material.payload_digest,
            &material.destination_binding_digest,
        );
        let signature = destination.sign_delivery(DeliverySignatureFields {
            id: &event_id,
            source,
            event_type: &material.event_type,
            time: &event_time,
            data_schema: &material.data_schema,
            generation: &generation,
            attempt: &attempt,
            delivery_time: &delivery_time,
            idempotency_key: &idempotency_key,
            body: &material.body,
        });
        let Ok(signature) = signature else {
            return Ok(DeliveryAuditOutcome::DestinationPolicyRefused.into());
        };
        // The envelope bytes outlive the request: a proposal answer hands
        // them to the product's apply seam after the send returns.
        let envelope = material.body.clone();
        let request = match destination.render_delivery(
            EventDeliveryHeaders {
                id: event_id.as_bytes(),
                source: source.as_bytes(),
                event_type: material.event_type.as_bytes(),
                time: event_time.as_bytes(),
                dataschema: material.data_schema.as_bytes(),
                generation: generation.as_bytes(),
                attempt: attempt.as_bytes(),
                delivery_time: delivery_time.as_bytes(),
                idempotency_key: idempotency_key.as_bytes(),
                signature: signature.as_bytes(),
            },
            material.body,
        ) {
            Ok(request) => request,
            Err(_) => return Ok(DeliveryAuditOutcome::DestinationPolicyRefused.into()),
        };
        let attempt_timeout = Duration::from_millis(
            u64::try_from(material.deployed_attempt_timeout_ms)
                .map_err(|_| DeliveryError::Unavailable)?,
        );
        let Some(remaining) =
            remaining_attempt_budget(attempt_timeout, claim.attempt_started_at, SystemTime::now())
        else {
            return Ok(DeliveryAuditOutcome::DestinationTimeout.into());
        };
        if remaining.is_zero() {
            return Ok(DeliveryAuditOutcome::DestinationTimeout.into());
        }
        let monotonic_deadline = Instant::now() + remaining;
        match destination.send_delivery(request, remaining).await {
            // The destination answered: its bounded body is the handler
            // message, read under the same ceiling and the same canonical
            // rule a local answer is read under. A proposal in that message
            // is applied through the product's seam before finalize.
            Ok(DestinationAnswer::Delivered { body }) => {
                let result = accepted_answer_result(&body);
                self.settle_answer(claim, &envelope, result).await
            }
            Ok(DestinationAnswer::NonSuccess { .. }) => {
                Ok(DeliveryAuditOutcome::HttpNonSuccess.into())
            }
            Ok(DestinationAnswer::AnswerRefused(failure)) => {
                Ok(DeliveryAuditOutcome::handler_failure(failure.category).into())
            }
            Err(error) => Ok(classify_send_error(
                error,
                monotonic_deadline.saturating_duration_since(Instant::now())
                    <= Duration::from_millis(1),
            )
            .into()),
        }
    }

    /// Run one local-kind attempt: resolve the product's handler for the
    /// binding the row recorded, run it over the stored envelope bytes with
    /// the remaining attempt budget, and read its answer.
    ///
    /// A local row is signed by nothing and sent nowhere: the engine holds
    /// the reviewed program, so there is no destination to resolve, no
    /// signature to compute, and no request to render. The binding check is
    /// the same one the `url` path makes, against the handler the product
    /// resolved rather than the destination it activated.
    async fn run_local_handler(
        &self,
        claim: &DeliveryClaim,
        material: DeliveryMaterial,
    ) -> Result<AttemptResult, DeliveryError> {
        let Some(handler) = self.seams.handler(HookHandlerBinding {
            kind: claim.handler_kind,
            compiled_delivery_id: &claim.compiled_delivery_id,
            package_revision: &claim.package_revision,
            handler_digest: &material.destination_binding_digest,
        }) else {
            return Ok(DeliveryAuditOutcome::HandlerBindingRefused.into());
        };
        let deployed_timeout_ms = i64::try_from(handler.attempt_timeout().as_millis())
            .map_err(|_| DeliveryError::Unavailable)?;
        if handler.handler_digest() != material.destination_binding_digest
            || deployed_timeout_ms != material.deployed_attempt_timeout_ms
            || i16::from(handler.maximum_attempts()) != material.deployed_maximum_attempts
        {
            return Ok(DeliveryAuditOutcome::HandlerBindingRefused.into());
        }
        let attempt_timeout = Duration::from_millis(
            u64::try_from(material.deployed_attempt_timeout_ms)
                .map_err(|_| DeliveryError::Unavailable)?,
        );
        let Some(remaining) =
            remaining_attempt_budget(attempt_timeout, claim.attempt_started_at, SystemTime::now())
        else {
            return Ok(DeliveryAuditOutcome::handler_failure(ErrorCategory::Deadline).into());
        };
        if remaining.is_zero() {
            return Ok(DeliveryAuditOutcome::handler_failure(ErrorCategory::Deadline).into());
        }
        match handler.run(&material.body, remaining).await {
            Ok(answer) => {
                let result = accepted_answer_result(&answer);
                self.settle_answer(claim, &material.body, result).await
            }
            Err(failure) => Ok(DeliveryAuditOutcome::handler_failure(failure.category).into()),
        }
    }

    /// Hand an accepted proposal to the product's apply seam.
    ///
    /// The settle step runs after the answer is accepted and before the
    /// finalize transaction, so the disposition the row records is the one
    /// the apply produced and the two can never disagree. An answer that is
    /// not a proposal never reaches the seam. An uncertain apply (`Err`)
    /// propagates: the row keeps its lease and expiry recovery retries, and
    /// the retry relies on the seam's idempotent application identity so the
    /// same answer applies once.
    async fn settle_answer(
        &self,
        claim: &DeliveryClaim,
        envelope: &[u8],
        mut result: AttemptResult,
    ) -> Result<AttemptResult, DeliveryError> {
        let Some(answer) = result.answer.as_ref() else {
            return Ok(result);
        };
        if !matches!(answer.message, HookMessage::Proposal { .. }) {
            result.proposal = self
                .seams
                .recover_proposal_receipt(ProposalReceiptRecovery {
                    event_id: claim.event_id,
                    compiled_delivery_id: &claim.compiled_delivery_id,
                })
                .await?;
            return Ok(result);
        }
        let outcome = self
            .seams
            .apply_proposal(ProposalApplication {
                event_id: claim.event_id,
                compiled_delivery_id: &claim.compiled_delivery_id,
                generation: claim.generation,
                attempt: claim.attempt,
                lease_token: claim.lease_token,
                package_revision: &claim.package_revision,
                envelope,
                answer: &answer.bytes,
                answer_digest: &answer.digest,
            })
            .await?;
        result.proposal = Some(outcome);
        Ok(result)
    }

    async fn reload_material(
        &self,
        claim: &DeliveryClaim,
    ) -> Result<DeliveryMaterial, MaterialLoadError> {
        let mut client = self
            .seams
            .connection()
            .await
            .map_err(|_| MaterialLoadError::Unavailable)?;
        let transaction = client
            .transaction()
            .await
            .map_err(|_| MaterialLoadError::Unavailable)?;
        self.seams
            .verify_transaction(&transaction)
            .await
            .map_err(|_| MaterialLoadError::Unavailable)?;
        let row = transaction
            .query_opt(
                &self.sql(
                    "SELECT outbox.event_type, outbox.payload,
                        outbox.package_revision, outbox.schema_fingerprint,
                        delivery.destination_binding_digest,
                        delivery.logical_destination_id,
                        delivery.maximum_payload_bytes,
                        delivery.payload_digest,
                        delivery.deployed_attempt_timeout_ms,
                        delivery.deployed_maximum_attempts,
                        delivery.authentication_profile,
                        delivery.delivery_mode,
                        delivery.dead_letter,
                        delivery.data_schema,
                        outbox.created_at
                 FROM {schema}.registry_webhook_delivery_state AS state
                 JOIN {schema}.registry_webhook_deliveries AS delivery
                   ON delivery.event_id = state.event_id
                  AND delivery.compiled_delivery_id = state.compiled_delivery_id
                 JOIN {schema}.registry_outbox AS outbox
                   ON outbox.event_id = delivery.event_id
                  AND outbox.package_revision = delivery.package_revision
                  AND outbox.schema_fingerprint = delivery.schema_fingerprint
                 WHERE state.event_id = $1
                   AND state.compiled_delivery_id = $2
                   AND state.generation = $3
                   AND state.attempt = $4
                   AND state.lease_token = $5
                   AND state.state = 'leased'
                   AND state.lease_expires_at > transaction_timestamp()
                   AND outbox.payload IS NOT NULL
                   AND outbox.payload_expires_at > transaction_timestamp()
                 FOR SHARE OF state",
                ),
                &[
                    &claim.event_id,
                    &claim.compiled_delivery_id,
                    &claim.generation,
                    &claim.attempt,
                    &claim.lease_token,
                ],
            )
            .await
            .map_err(|_| MaterialLoadError::Unavailable)?
            .ok_or(MaterialLoadError::Unavailable)?;
        let event_type =
            bounded_text(&row, 0, 256).map_err(|_| MaterialLoadError::PayloadRefused)?;
        let body = row
            .try_get::<_, Option<Vec<u8>>>(1)
            .map_err(|_| MaterialLoadError::PayloadRefused)?;
        let body = body.ok_or(MaterialLoadError::PayloadRefused)?;
        let outbox_package_revision =
            bounded_text(&row, 2, 256).map_err(|_| MaterialLoadError::PayloadRefused)?;
        let outbox_schema_fingerprint =
            bounded_text(&row, 3, 256).map_err(|_| MaterialLoadError::PayloadRefused)?;
        let destination_binding_digest =
            bounded_text(&row, 4, 71).map_err(|_| MaterialLoadError::PayloadRefused)?;
        let logical_destination_id = row
            .try_get::<_, Option<String>>(5)
            .map_err(|_| MaterialLoadError::PayloadRefused)?
            .map(|id| {
                (id.len() <= 64)
                    .then_some(id)
                    .ok_or(MaterialLoadError::PayloadRefused)
            })
            .transpose()?;
        let maximum_payload_bytes = row
            .try_get::<_, i64>(6)
            .map_err(|_| MaterialLoadError::PayloadRefused)?;
        let payload_digest = row
            .try_get::<_, Vec<u8>>(7)
            .map_err(|_| MaterialLoadError::PayloadRefused)?;
        let deployed_attempt_timeout_ms = row
            .try_get::<_, i64>(8)
            .map_err(|_| MaterialLoadError::PayloadRefused)?;
        let deployed_maximum_attempts = row
            .try_get::<_, i16>(9)
            .map_err(|_| MaterialLoadError::PayloadRefused)?;
        let authentication_profile =
            bounded_text(&row, 10, 32).map_err(|_| MaterialLoadError::PayloadRefused)?;
        let delivery_mode =
            bounded_text(&row, 11, 32).map_err(|_| MaterialLoadError::PayloadRefused)?;
        let dead_letter =
            bounded_text(&row, 12, 32).map_err(|_| MaterialLoadError::PayloadRefused)?;
        let data_schema =
            bounded_text(&row, 13, 2_048).map_err(|_| MaterialLoadError::PayloadRefused)?;
        let event_time = row
            .try_get::<_, SystemTime>(14)
            .map_err(|_| MaterialLoadError::PayloadRefused)?;
        transaction
            .commit()
            .await
            .map_err(|_| MaterialLoadError::Unavailable)?;
        // A row carries a destination when, and only when, it binds the
        // `url` kind: a local kind runs the engine's own reviewed program
        // and has nowhere to send.
        if logical_destination_id.is_some() != (claim.handler_kind == HookHandlerKind::Url) {
            return Err(MaterialLoadError::BindingRefused);
        }
        if outbox_package_revision != claim.package_revision
            || outbox_schema_fingerprint.is_empty()
            || authentication_profile != "hmac_sha256_v1"
            || delivery_mode != "after_commit"
            || dead_letter != "required"
            || !(100..=10_000).contains(&deployed_attempt_timeout_ms)
            || !(1..=20).contains(&deployed_maximum_attempts)
        {
            return Err(MaterialLoadError::BindingRefused);
        }
        accept_stored_envelope(
            &body,
            &StoredEnvelope {
                event_id: claim.event_id,
                event_type: &event_type,
                source: &self.delivery_source,
                data_schema: &data_schema,
                event_time,
                maximum_payload_bytes,
                payload_digest: &payload_digest,
            },
        )?;
        Ok(DeliveryMaterial {
            event_type,
            body,
            payload_digest,
            destination_binding_digest,
            logical_destination_id,
            deployed_attempt_timeout_ms,
            deployed_maximum_attempts,
            data_schema,
            event_time,
        })
    }

    async fn finalize(
        &self,
        claim: &DeliveryClaim,
        attempt: AttemptResult,
    ) -> Result<DeliveryOutcome, DeliveryError> {
        let AttemptResult {
            outcome,
            answer,
            mut proposal,
        } = attempt;
        // A proposal may have committed before an earlier worker lost its
        // lease or failed to finalize. If every later attempt fails before
        // accepting an answer, recover that receipt before the last attempt
        // becomes an all-null dead letter. Nonterminal failures keep the
        // ordinary retry path and avoid an extra database lookup.
        if proposal.is_none()
            && answer.is_none()
            && claim.attempt >= claim.deployed_maximum_attempts
        {
            proposal = self
                .seams
                .recover_proposal_receipt(ProposalReceiptRecovery {
                    event_id: claim.event_id,
                    compiled_delivery_id: &claim.compiled_delivery_id,
                })
                .await?;
        }
        let mut client = self.seams.connection().await?;
        let transaction = client.transaction().await?;
        self.seams.verify_transaction(&transaction).await?;
        let (disposition, work_outcome) = if proposal
            .as_ref()
            .is_some_and(|proposal| matches!(proposal, ProposalOutcome::DeadLettered { .. }))
        {
            // A dead-lettered proposal is deterministic: retrying the
            // delivery cannot apply it, so the row is terminal now regardless
            // of the attempts it has left.
            (
                DeliveryAuditDisposition::DeadLettered,
                DeliveryOutcome::DeadLettered,
            )
        } else if outcome == DeliveryAuditOutcome::Delivered {
            (
                DeliveryAuditDisposition::Delivered,
                DeliveryOutcome::Delivered,
            )
        } else if claim.attempt >= claim.deployed_maximum_attempts {
            (
                DeliveryAuditDisposition::DeadLettered,
                DeliveryOutcome::DeadLettered,
            )
        } else {
            (
                DeliveryAuditDisposition::RetryPending,
                DeliveryOutcome::RetryScheduled,
            )
        };
        let changed = match work_outcome {
            DeliveryOutcome::Delivered => {
                self.update_terminal_state(
                    &transaction,
                    claim,
                    "delivered",
                    answer.as_ref(),
                    proposal.as_ref(),
                )
                .await?
            }
            DeliveryOutcome::DeadLettered => {
                self.update_terminal_state(
                    &transaction,
                    claim,
                    "dead_lettered",
                    None,
                    proposal.as_ref(),
                )
                .await?
            }
            DeliveryOutcome::RetryScheduled => {
                let delay_ms = scheduled_retry_delay(&claim.retry_delays_ms, claim.attempt)?;
                transaction
                    .execute(
                        &self.sql(
                            "UPDATE {schema}.registry_webhook_delivery_state
                         SET state = 'pending',
                             next_attempt_at = transaction_timestamp()
                                 + $6::bigint * interval '1 millisecond',
                             attempt_started_at = NULL,
                             lease_expires_at = NULL,
                             lease_token = NULL,
                             updated_at = transaction_timestamp()
                         WHERE event_id = $1
                           AND compiled_delivery_id = $2
                           AND generation = $3
                           AND attempt = $4
                           AND lease_token = $5
                           AND state = 'leased'",
                        ),
                        &[
                            &claim.event_id,
                            &claim.compiled_delivery_id,
                            &claim.generation,
                            &claim.attempt,
                            &claim.lease_token,
                            &delay_ms,
                        ],
                    )
                    .await?
            }
            DeliveryOutcome::Idle => return Err(DeliveryError::Unavailable),
        };
        if changed != 1 {
            return Err(DeliveryError::Unavailable);
        }
        if work_outcome == DeliveryOutcome::Delivered {
            let erased = transaction
                .execute(
                    &self.sql(
                        "UPDATE {schema}.registry_outbox
                        SET payload = NULL
                      WHERE event_id = $1 AND payload IS NOT NULL",
                    ),
                    &[&claim.event_id],
                )
                .await?;
            if erased != 1 {
                return Err(DeliveryError::Unavailable);
            }
        }
        let terminal = PendingAudit {
            event_id: claim.event_id,
            compiled_delivery_id: claim.compiled_delivery_id.clone(),
            package_revision: claim.package_revision.clone(),
            generation: claim.generation,
            attempt: claim.attempt,
            phase: DeliveryAuditPhase::Terminal,
            outcome,
            disposition,
        };
        if let Err(error) = transaction.commit().await {
            // A lost acknowledgement does not prove a rollback, and a
            // terminal row is never reaped, so a disposition that did commit
            // is recorded here or never. One that rolled back leaves the
            // lease for expiry recovery, which answers the attempt.
            match self.transition_committed(&terminal, None).await {
                Some(true) => {}
                Some(false) => return Err(error.into()),
                None => {
                    // The disposition's fate cannot be read, and one that
                    // did commit is never answered by expiry recovery, so the
                    // attempt is answered now as interrupted: a second
                    // interrupted answer is harmless and none is not.
                    let interrupted = PendingAudit {
                        outcome: DeliveryAuditOutcome::WorkerInterrupted,
                        disposition: DeliveryAuditDisposition::RetryPending,
                        ..terminal
                    };
                    // A refused entry has already stopped the product's
                    // writer, which reports it; finalize fails either way.
                    let _ = self.seams.record_audit(interrupted.record()).await;
                    return Err(error.into());
                }
            }
        }
        // Recorded once the disposition committed, so the journal never
        // names a disposition the database does not hold.
        self.seams.record_audit(terminal.record()).await?;
        Ok(work_outcome)
    }

    /// Record the events of a transaction whose commit returned an error,
    /// each only if the transition it names is durable.
    async fn record_resolved(&self, events: Vec<PendingAudit>) {
        for event in events {
            // A refused entry has already stopped the product's writer,
            // which reports it; the caller is failing either way.
            if self.transition_committed(&event, None).await == Some(true) {
                let _ = self.seams.record_audit(event.record()).await;
            }
        }
    }

    /// Whether the transition `event` records is durable, read on a fresh
    /// connection after its commit returned an error, since a failed commit
    /// acknowledgement does not prove the transaction rolled back. `None`
    /// when the state cannot be read. An attempt's lease is matched on the
    /// token this worker wrote.
    async fn transition_committed(
        &self,
        event: &PendingAudit,
        lease_token: Option<Uuid>,
    ) -> Option<bool> {
        for read_back in 0..=READ_BACK_BACKOFF.len() {
            if let Some(wait) = read_back
                .checked_sub(1)
                .and_then(|index| READ_BACK_BACKOFF.get(index))
            {
                tokio::time::sleep(*wait).await;
            }
            let Ok(client) = self.seams.connection().await else {
                continue;
            };
            let Ok(row) = client
                .query_opt(
                    &self.sql(
                        "SELECT state, generation, attempt, lease_token, expired_at IS NOT NULL
                           FROM {schema}.registry_webhook_delivery_state
                          WHERE event_id = $1 AND compiled_delivery_id = $2",
                    ),
                    &[&event.event_id, &event.compiled_delivery_id],
                )
                .await
            else {
                continue;
            };
            let Some(row) = row else {
                return Some(false);
            };
            let (Ok(state), Ok(generation), Ok(attempt), Ok(token), Ok(expired)) = (
                row.try_get::<_, String>(0),
                row.try_get::<_, i64>(1),
                row.try_get::<_, i16>(2),
                row.try_get::<_, Option<Uuid>>(3),
                row.try_get::<_, bool>(4),
            ) else {
                return None;
            };
            return Some(transition_holds(
                event,
                &ObservedDelivery {
                    state: &state,
                    generation,
                    attempt,
                    lease_token: token,
                    expired,
                },
                lease_token,
            ));
        }
        None
    }

    /// Record the events of a transaction that has committed.
    async fn record_committed(&self, committed: Vec<PendingAudit>) -> Result<(), DeliveryError> {
        for event in committed {
            self.seams.record_audit(event.record()).await?;
        }
        Ok(())
    }

    async fn update_terminal_state(
        &self,
        transaction: &Transaction<'_>,
        claim: &DeliveryClaim,
        state: &str,
        answer: Option<&AcceptedAnswer>,
        proposal: Option<&ProposalOutcome>,
    ) -> Result<u64, DeliveryError> {
        let timestamp_column = match state {
            "delivered" => "delivered_at",
            "dead_lettered" => "dead_lettered_at",
            _ => return Err(DeliveryError::Unavailable),
        };
        let columns = proposal_columns(state, proposal)?;
        // The raw answer is erased when delivery becomes terminal: the row
        // retains the digest, disposition, code, and bounded summary, never
        // the answer bytes, so nothing delivered stays readable as a payload.
        let message: Option<Vec<u8>> = None;
        let message_digest = answer.map(|answer| answer.digest.to_vec());
        transaction
            .execute(
                &format!(
                    "UPDATE {schema}.registry_webhook_delivery_state
                     SET state = '{state}',
                         next_attempt_at = NULL,
                         attempt_started_at = NULL,
                         lease_expires_at = NULL,
                         lease_token = NULL,
                         handler_message = $6,
                         handler_message_digest = $7,
                         proposal_disposition = $8,
                         proposal_resulting_revision = $9,
                         proposal_code = $10,
                         proposal_summary = $11,
                         {timestamp_column} = transaction_timestamp(),
                         updated_at = transaction_timestamp()
                     WHERE event_id = $1
                       AND compiled_delivery_id = $2
                       AND generation = $3
                       AND attempt = $4
                       AND lease_token = $5
                       AND state = 'leased'",
                    schema = self.schema,
                ),
                &[
                    &claim.event_id,
                    &claim.compiled_delivery_id,
                    &claim.generation,
                    &claim.attempt,
                    &claim.lease_token,
                    &message,
                    &message_digest,
                    &columns.disposition,
                    &columns.resulting_revision,
                    &columns.code,
                    &columns.summary,
                ],
            )
            .await
            .map_err(|_| DeliveryError::Unavailable)
    }

    /// Report one refused claim-path transition through the operational seam.
    fn refused(&self, code: DeliveryTransitionCode) {
        self.seams
            .operational_event(DeliveryOperationalEvent::TransitionFailed(code));
    }

    /// Render one SQL template with this deployment's schema name. The
    /// schema was validated as a plain identifier at construction, so the
    /// interpolation is safe.
    fn sql(&self, template: &str) -> String {
        delivery_schema::render(&self.schema, template)
    }
}

/// One delivery row as read back after a commit returned an error.
struct ObservedDelivery<'a> {
    state: &'a str,
    generation: i64,
    attempt: i16,
    lease_token: Option<Uuid>,
    expired: bool,
}

/// Whether `observed` shows the transition `event` records as durable. An
/// attempt's lease is matched on the token this worker wrote.
fn transition_holds(
    event: &PendingAudit,
    observed: &ObservedDelivery<'_>,
    lease_token: Option<Uuid>,
) -> bool {
    let current = observed.generation == event.generation;
    let at_attempt = current && observed.attempt == event.attempt;
    let state = observed.state;
    match (event.phase, event.disposition) {
        (DeliveryAuditPhase::Attempt, _) => {
            at_attempt
                && state == "leased"
                && observed.lease_token.is_some()
                && observed.lease_token == lease_token
        }
        // Only a replay's reset writes a generation, and generations only
        // grow, so the replacement generation or a later one proves the reset
        // committed whatever state the worker or a later replay has since
        // moved it to.
        (DeliveryAuditPhase::Replay, _) => observed.generation >= event.generation,
        (DeliveryAuditPhase::Terminal, DeliveryAuditDisposition::Expired) => {
            current && observed.expired
        }
        (DeliveryAuditPhase::Terminal, DeliveryAuditDisposition::Delivered) => {
            at_attempt && state == "delivered"
        }
        // A dead letter leaves that state only through a replay, which
        // writes a later generation.
        (DeliveryAuditPhase::Terminal, DeliveryAuditDisposition::DeadLettered) => {
            (at_attempt && state == "dead_lettered") || observed.generation > event.generation
        }
        // A scheduled retry is claimed again under a later attempt of the
        // same generation, which a rolled-back retry reaches only after its
        // lease expires and the reaper answers the attempt itself.
        (DeliveryAuditPhase::Terminal, DeliveryAuditDisposition::RetryPending) => {
            (at_attempt && state == "pending" && observed.lease_token.is_none())
                || (current && observed.attempt > event.attempt)
        }
        (
            DeliveryAuditPhase::Terminal,
            DeliveryAuditDisposition::Leased | DeliveryAuditDisposition::ReplayPending,
        ) => false,
    }
}

/// The post-commit delivery loop: claim, send, finalize, until shutdown.
pub struct DeliveryWorker<S: DeliverySeams> {
    service: DeliveryService<S>,
}

impl<S: DeliverySeams> DeliveryWorker<S> {
    #[must_use]
    pub fn new(service: DeliveryService<S>) -> Self {
        Self { service }
    }

    /// Run until the shutdown watch closes or carries `true`.
    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        let service = self.service;
        loop {
            if *shutdown.borrow() {
                return;
            }
            if service.deliver_once().await.is_err() {
                service
                    .seams
                    .operational_event(DeliveryOperationalEvent::IterationFailed);
            }
            tokio::select! {
                changed = shutdown.changed() => {
                    if changed.is_err() || *shutdown.borrow() {
                        return;
                    }
                }
                () = tokio::time::sleep(WORKER_POLL_INTERVAL) => {}
            }
        }
    }
}

/// One claimed delivery, frozen between the lease commit and finalization.
struct DeliveryClaim {
    event_id: Uuid,
    compiled_delivery_id: String,
    generation: i64,
    attempt: i16,
    attempt_started_at: SystemTime,
    lease_token: Uuid,
    deployed_maximum_attempts: i16,
    retry_delays_ms: Vec<i64>,
    package_revision: String,
    handler_kind: HookHandlerKind,
}

struct DeliveryMaterial {
    event_type: String,
    body: Vec<u8>,
    payload_digest: Vec<u8>,
    destination_binding_digest: String,
    logical_destination_id: Option<String>,
    deployed_attempt_timeout_ms: i64,
    deployed_maximum_attempts: i16,
    data_schema: String,
    event_time: SystemTime,
}

enum MaterialLoadError {
    Unavailable,
    BindingRefused,
    PayloadRefused,
}

/// What one attempt produced: its audited outcome, the accepted message to
/// record with it when the handler answered, and, when that message carried
/// a proposal, what became of it.
struct AttemptResult {
    outcome: DeliveryAuditOutcome,
    answer: Option<AcceptedAnswer>,
    /// The settled outcome of the proposal the answer carried, set once the
    /// product's apply seam has answered. Always `None` for an answer that
    /// proposed nothing.
    proposal: Option<ProposalOutcome>,
}

impl From<DeliveryAuditOutcome> for AttemptResult {
    fn from(outcome: DeliveryAuditOutcome) -> Self {
        Self {
            outcome,
            answer: None,
            proposal: None,
        }
    }
}

/// One accepted handler message and the digest of exactly the bytes
/// recorded for it.
#[derive(Debug)]
struct AcceptedAnswer {
    message: HookMessage,
    bytes: Vec<u8>,
    digest: [u8; 32],
}

/// The refusal recorded when the delivery row and its binding disagree,
/// named for the kind the row binds.
const fn material_binding_refusal(kind: HookHandlerKind) -> DeliveryAuditOutcome {
    if kind.is_local() {
        DeliveryAuditOutcome::HandlerBindingRefused
    } else {
        DeliveryAuditOutcome::DestinationBindingRefused
    }
}

/// Read one handler answer and turn it into the attempt result it implies.
///
/// An accepted answer is a delivered attempt carrying the message; a refused
/// one is the failure category the taxonomy assigns it, and nothing is
/// recorded.
fn accepted_answer_result(body: &[u8]) -> AttemptResult {
    match accept_handler_answer(body) {
        Ok(answer) => AttemptResult {
            outcome: DeliveryAuditOutcome::Delivered,
            answer: Some(answer),
            proposal: None,
        },
        Err(category) => DeliveryAuditOutcome::handler_failure(category).into(),
    }
}

/// Accept one handler answer: bound it, read it, and digest exactly the
/// bytes that will be recorded.
///
/// Both kinds answer the same way. An empty answer is the `none` answer: a
/// handler that observes and proposes nothing need not write a body, and the
/// record still carries the message it means. Anything else is read as the
/// handler message under the library ceiling, so an answer over the ceiling
/// is a resource failure and a malformed or non-canonical answer is a source
/// failure, exactly as the taxonomy states.
///
/// The recorded bytes are the message's own canonical encoding rather than
/// the bytes as they arrived, so the digest covers what the state holds and
/// the two can never disagree. Reading requires the arriving bytes to equal
/// their canonicalization, so for a non-empty answer the two are the same
/// bytes.
fn accept_handler_answer(body: &[u8]) -> Result<AcceptedAnswer, ErrorCategory> {
    let limits = HandlerOutputLimits::default();
    let message = if body.is_empty() {
        HookMessage::Nothing
    } else {
        HookMessage::from_canonical_json(body, &limits).map_err(|error| error.category())?
    };
    let bytes = message
        .to_canonical_json(&limits)
        .map_err(|error| error.category())?;
    let digest = Sha256::digest(&bytes).into();
    Ok(AcceptedAnswer {
        message,
        bytes,
        digest,
    })
}

/// The proposal bookkeeping values one terminal UPDATE writes: the
/// disposition the answer's proposal earned, the revision an applied
/// proposal produced, or the bounded reason a proposal was refused or
/// dead-lettered.
///
/// A delivered row always states one of `none`, `applied`, or `refused`. A
/// row the proposal path dead-letters states `dead_lettered` with its
/// reason. A row that dead-letters without accepting an answer keeps the
/// all-null legacy shape: it never had a proposal to settle.
fn proposal_columns<'a>(
    state: &str,
    proposal: Option<&'a ProposalOutcome>,
) -> Result<ProposalColumns<'a>, DeliveryError> {
    match (state, proposal) {
        ("delivered", None) => Ok(ProposalColumns {
            disposition: Some("none"),
            resulting_revision: None,
            code: None,
            summary: None,
        }),
        ("delivered", Some(ProposalOutcome::Applied { resulting_revision })) => {
            Ok(ProposalColumns {
                disposition: Some("applied"),
                resulting_revision: Some(*resulting_revision),
                code: None,
                summary: None,
            })
        }
        ("delivered", Some(ProposalOutcome::Refused { code, summary })) => Ok(ProposalColumns {
            disposition: Some("refused"),
            resulting_revision: None,
            code: Some(code.as_str()),
            summary: Some(summary.as_str()),
        }),
        ("dead_lettered", Some(ProposalOutcome::DeadLettered { code, summary })) => {
            Ok(ProposalColumns {
                disposition: Some("dead_lettered"),
                resulting_revision: None,
                code: Some(code.as_str()),
                summary: Some(summary.as_str()),
            })
        }
        ("dead_lettered", None) => Ok(ProposalColumns {
            disposition: None,
            resulting_revision: None,
            code: None,
            summary: None,
        }),
        // A settled outcome the finalize routing never pairs with this
        // state: an applied or refused proposal delivers, a dead-lettered
        // one never does.
        _ => Err(DeliveryError::Unavailable),
    }
}

/// The proposal columns one terminal UPDATE writes, borrowed from the
/// settled outcome they record.
struct ProposalColumns<'a> {
    disposition: Option<&'a str>,
    resulting_revision: Option<i64>,
    code: Option<&'a str>,
    summary: Option<&'a str>,
}

/// What the delivery row and the worker's own configuration say the stored
/// envelope must be.
struct StoredEnvelope<'a> {
    event_id: Uuid,
    event_type: &'a str,
    source: &'a str,
    data_schema: &'a str,
    event_time: SystemTime,
    maximum_payload_bytes: i64,
    payload_digest: &'a [u8],
}

/// Accept the stored envelope bytes the worker is about to deliver unchanged.
///
/// The stored bytes are the delivery body, so the worker re-reads them as an
/// envelope and refuses a row whose headers could disagree with the body it is
/// about to sign. The per-delivery bound measures those same bytes, so an
/// envelope over the bound is refused here rather than sent.
fn accept_stored_envelope(
    body: &[u8],
    expected: &StoredEnvelope<'_>,
) -> Result<(), MaterialLoadError> {
    let maximum = usize::try_from(expected.maximum_payload_bytes)
        .map_err(|_| MaterialLoadError::PayloadRefused)?;
    let envelope = HookEnvelope::from_canonical_bytes(body, &EnvelopeLimits::tightened_to(maximum))
        .map_err(|_| MaterialLoadError::PayloadRefused)?;
    if expected.payload_digest.len() != 32
        || expected.payload_digest != Sha256::digest(body).as_slice()
    {
        return Err(MaterialLoadError::PayloadRefused);
    }
    if envelope.id != expected.event_id.to_string()
        || envelope.event_type != expected.event_type
        || envelope.source != expected.source
        || envelope.dataschema != expected.data_schema
        || envelope.time != OffsetDateTime::from(expected.event_time)
    {
        return Err(MaterialLoadError::PayloadRefused);
    }
    Ok(())
}

/// The work result of one delivery iteration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryOutcome {
    Idle,
    Delivered,
    RetryScheduled,
    DeadLettered,
}

/// Bounded, value-free operator delivery state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryStatusKind {
    Pending,
    DeadLettered,
    Expired,
}

/// One operator status result: pending and terminal delivery metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeliveryStatus {
    pub event_id: Uuid,
    pub compiled_delivery_id: String,
    pub generation: i64,
    pub state: DeliveryStatusKind,
    pub attempt: i16,
    pub payload_available: bool,
    pub payload_expires_at: String,
}

/// The stored delivery state and payload availability, mapped onto the
/// operator's status kind. A pending row whose payload has expired reports
/// `Expired`, exactly as a stored `expired` row does.
fn delivery_status_kind(
    stored_state: &str,
    payload_available: bool,
) -> Result<DeliveryStatusKind, DeliveryError> {
    match stored_state {
        "pending" if payload_available => Ok(DeliveryStatusKind::Pending),
        "pending" | "expired" => Ok(DeliveryStatusKind::Expired),
        "dead_lettered" => Ok(DeliveryStatusKind::DeadLettered),
        _ => Err(DeliveryError::Unavailable),
    }
}

/// The retry delay owed after `attempt`, or a refusal when the captured
/// profile has no positive delay for it.
fn scheduled_retry_delay(retry_delays_ms: &[i64], attempt: i16) -> Result<i64, DeliveryError> {
    let delay_index = usize::try_from(attempt - 1).map_err(|_| DeliveryError::Unavailable)?;
    retry_delays_ms
        .get(delay_index)
        .filter(|delay| **delay > 0)
        .copied()
        .ok_or(DeliveryError::Unavailable)
}

fn classify_send_error(
    error: DestinationSendError,
    deadline_reached: bool,
) -> DeliveryAuditOutcome {
    match error {
        DestinationSendError::DeadlineExceeded => DeliveryAuditOutcome::DestinationTimeout,
        DestinationSendError::ResolutionFailed
        | DestinationSendError::TooManyResolverAnswers
        | DestinationSendError::NoResolverAnswers
        | DestinationSendError::ResolverPortMismatch
        | DestinationSendError::ResolverAddressFamilyMismatch
        | DestinationSendError::LiteralOriginMismatch
        | DestinationSendError::CloudMetadataDenied
        | DestinationSendError::AlwaysDeniedAddress
        | DestinationSendError::PrivateAddressNotAllowed
        | DestinationSendError::NonGlobalAddressDenied
        | DestinationSendError::DevelopmentAddressDenied => {
            DeliveryAuditOutcome::DestinationResolutionRefused
        }
        DestinationSendError::ResolutionCapacityUnavailable
        | DestinationSendError::TlsMaterialUnavailable
        | DestinationSendError::ClientBuildFailed
        | DestinationSendError::TooManyResponseHeaders
        | DestinationSendError::ResponseHeaderBytesExceeded => {
            DeliveryAuditOutcome::DestinationTransportUnavailable
        }
        DestinationSendError::TransportFailed if deadline_reached => {
            DeliveryAuditOutcome::DestinationTimeout
        }
        DestinationSendError::TransportFailed => {
            DeliveryAuditOutcome::DestinationTransportUnavailable
        }
        DestinationSendError::InvalidRemainingTimeout
        | DestinationSendError::InvalidFrozenPolicy
        | DestinationSendError::InvalidFrozenRequest => {
            DeliveryAuditOutcome::DestinationPolicyRefused
        }
    }
}

/// Attempt budget still available for the request, or `None` once the captured
/// attempt timeout is spent.
///
/// The claim timestamp is the database clock and `now` is this process's clock,
/// so the two disagree by whatever offset separates the two hosts. An attempt
/// that appears to start in the local future has spent none of its budget, and
/// the request that follows still gets at most the captured attempt timeout.
fn remaining_attempt_budget(
    attempt_timeout: Duration,
    attempt_started_at: SystemTime,
    now: SystemTime,
) -> Option<Duration> {
    let elapsed = now
        .duration_since(attempt_started_at)
        .unwrap_or(Duration::ZERO);
    attempt_timeout.checked_sub(elapsed)
}

fn bounded_delivery_id(row: &tokio_postgres::Row, index: usize) -> Result<String, DeliveryError> {
    bounded_text(row, index, 256)
}

fn bounded_text(
    row: &tokio_postgres::Row,
    index: usize,
    maximum: usize,
) -> Result<String, DeliveryError> {
    let value = row
        .try_get::<_, String>(index)
        .map_err(|_| DeliveryError::Unavailable)?;
    if value.is_empty() || value.len() > maximum {
        return Err(DeliveryError::Unavailable);
    }
    Ok(value)
}

fn validate_captured_policy(
    deployed_attempt_timeout_ms: i64,
    deployed_maximum_attempts: i16,
    retry_delays_ms: &[i64],
) -> Result<(), DeliveryError> {
    let expected_delays = usize::try_from(deployed_maximum_attempts.saturating_sub(1))
        .map_err(|_| DeliveryError::Unavailable)?;
    if !(100..=10_000).contains(&deployed_attempt_timeout_ms)
        || !(1..=20).contains(&deployed_maximum_attempts)
        || retry_delays_ms.len() < expected_delays
        || retry_delays_ms
            .iter()
            .any(|delay| !(100..=3_600_000).contains(delay))
    {
        return Err(DeliveryError::Unavailable);
    }
    Ok(())
}

/// The delivery idempotency key for one attempt: the product's domain, then
/// the length-prefixed attempt identity, digested. Stable across retries of
/// one attempt and changed by a new generation.
fn delivery_idempotency_key(
    idempotency_domain: &[u8],
    event_id: Uuid,
    compiled_delivery_id: &str,
    generation: i64,
    payload_digest: &[u8],
    destination_binding_digest: &str,
) -> String {
    let mut input = Vec::new();
    input.extend_from_slice(idempotency_domain);
    append_length_prefixed(&mut input, event_id.to_string().as_bytes());
    append_length_prefixed(&mut input, compiled_delivery_id.as_bytes());
    append_length_prefixed(&mut input, generation.to_string().as_bytes());
    append_length_prefixed(&mut input, payload_digest);
    append_length_prefixed(&mut input, destination_binding_digest.as_bytes());
    format!("sha256:{}", hex::encode(Sha256::digest(input)))
}

fn append_length_prefixed(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use registry_platform_httputil::destination::{
        DestinationRequestError, EventDestinationRequest,
    };

    use super::*;
    use crate::delivery::{
        insert_delivery, DeliveryCapture, DeliveryConnection, DeliverySignatureRefused,
    };

    // A destination the tests below never reach: it exists only so the seam
    // fixtures can name their associated destination type.
    #[derive(Clone, Copy, Debug)]
    struct UnusedDestination;

    #[async_trait::async_trait]
    impl HookDestination for UnusedDestination {
        fn binding_digest(&self) -> &str {
            ""
        }

        fn attempt_timeout(&self) -> Duration {
            Duration::ZERO
        }

        fn maximum_attempts(&self) -> u8 {
            1
        }

        fn sign_delivery(
            &self,
            _fields: DeliverySignatureFields<'_>,
        ) -> Result<String, DeliverySignatureRefused> {
            Err(DeliverySignatureRefused)
        }

        fn render_delivery(
            &self,
            _headers: EventDeliveryHeaders<'_>,
            _body: Vec<u8>,
        ) -> Result<EventDestinationRequest, DestinationRequestError> {
            unreachable!("no test below reaches a destination")
        }

        async fn send_delivery(
            &self,
            _request: EventDestinationRequest,
            _remaining: Duration,
        ) -> Result<DestinationAnswer, DestinationSendError> {
            unreachable!("no test below reaches a destination")
        }
    }

    /// A handler no test below resolves: the seams under test refuse every
    /// binding, so nothing ever runs.
    struct UnusedHandler;

    #[async_trait::async_trait]
    impl HookHandler for UnusedHandler {
        fn handler_digest(&self) -> &str {
            ""
        }

        fn attempt_timeout(&self) -> Duration {
            Duration::ZERO
        }

        fn maximum_attempts(&self) -> u8 {
            1
        }

        async fn run(
            &self,
            _envelope: &[u8],
            _remaining: Duration,
        ) -> Result<Vec<u8>, crate::delivery::HandlerRunFailure> {
            unreachable!("no test below reaches a handler")
        }
    }

    /// A seam set that refuses every connection and records every
    /// operational event it is given.
    struct RefusingSeams {
        events: Arc<Mutex<Vec<DeliveryOperationalEvent>>>,
    }

    #[async_trait::async_trait]
    impl DeliverySeams for RefusingSeams {
        type Destination = UnusedDestination;
        type Handler = UnusedHandler;

        async fn connection(&self) -> Result<DeliveryConnection, DeliveryError> {
            Err(DeliveryError::Unavailable)
        }

        async fn verify_transaction(
            &self,
            _transaction: &Transaction<'_>,
        ) -> Result<(), DeliveryError> {
            Err(DeliveryError::Unavailable)
        }

        fn destination(&self, _logical_destination_id: &str) -> Option<Self::Destination> {
            None
        }

        fn handler(&self, _binding: HookHandlerBinding<'_>) -> Option<Self::Handler> {
            None
        }

        async fn record_audit(
            &self,
            _record: DeliveryAuditRecord<'_>,
        ) -> Result<(), DeliveryError> {
            Err(DeliveryError::Unavailable)
        }

        fn operational_event(&self, event: DeliveryOperationalEvent) {
            self.events.lock().expect("events lock").push(event);
        }

        async fn apply_proposal(
            &self,
            _application: ProposalApplication<'_>,
        ) -> Result<ProposalOutcome, DeliveryError> {
            Err(DeliveryError::Unavailable)
        }

        async fn recover_proposal_receipt(
            &self,
            _recovery: ProposalReceiptRecovery<'_>,
        ) -> Result<Option<ProposalOutcome>, DeliveryError> {
            Err(DeliveryError::Unavailable)
        }

        async fn recover_proposal_receipt_in_transaction(
            &self,
            _transaction: &Transaction<'_>,
            _recovery: ProposalReceiptRecovery<'_>,
        ) -> Result<Option<ProposalOutcome>, DeliveryError> {
            Err(DeliveryError::Unavailable)
        }
    }

    const STORED_EVENT_ID: &str = "4e2f6d6c-6f0a-4c2f-9c1a-2d0f7a8b6c51";
    const STORED_SOURCE: &str = "urn:registrystack:test:instance:hooks-delivery";
    const STORED_DATA_SCHEMA: &str = "urn:test:event-schema:permit.granted";

    fn stored_envelope() -> HookEnvelope {
        HookEnvelope {
            id: STORED_EVENT_ID.to_owned(),
            event_type: "permit.granted".to_owned(),
            source: STORED_SOURCE.to_owned(),
            time: OffsetDateTime::from_unix_timestamp_nanos(1_767_225_600_123_000_000)
                .expect("capture instant"),
            subject: crate::EventSubject {
                record_reference:
                    "8f14e45fceea467a9cc18b2a4b9e2a1103b41d5ad4c88c8f2a0a9ac4f4c0d2b7".to_owned(),
                record_revision: 3,
            },
            dataschema: STORED_DATA_SCHEMA.to_owned(),
            data: serde_json::json!({ "values": { "status": "granted" } }),
            causation: crate::Causation::root(STORED_EVENT_ID),
        }
    }

    fn stored_binding<'a>(body: &'a [u8], digest: &'a [u8]) -> StoredEnvelope<'a> {
        StoredEnvelope {
            event_id: Uuid::parse_str(STORED_EVENT_ID).expect("event id"),
            event_type: "permit.granted",
            source: STORED_SOURCE,
            data_schema: STORED_DATA_SCHEMA,
            event_time: SystemTime::UNIX_EPOCH + Duration::from_millis(1_767_225_600_123),
            maximum_payload_bytes: i64::try_from(body.len()).expect("bound"),
            payload_digest: digest,
        }
    }

    fn replay_of(generation: i64) -> PendingAudit {
        PendingAudit {
            event_id: Uuid::nil(),
            compiled_delivery_id: "delivery".to_owned(),
            package_revision: "revision".to_owned(),
            generation,
            attempt: 0,
            phase: DeliveryAuditPhase::Replay,
            outcome: DeliveryAuditOutcome::ReplayCommitted,
            disposition: DeliveryAuditDisposition::ReplayPending,
        }
    }

    fn observed(state: &str, generation: i64, attempt: i16) -> ObservedDelivery<'_> {
        ObservedDelivery {
            state,
            generation,
            attempt,
            lease_token: None,
            expired: false,
        }
    }

    fn terminal_of(disposition: DeliveryAuditDisposition) -> PendingAudit {
        PendingAudit {
            attempt: 1,
            phase: DeliveryAuditPhase::Terminal,
            outcome: DeliveryAuditOutcome::WorkerInterrupted,
            disposition,
            ..replay_of(1)
        }
    }

    #[test]
    fn a_committed_retry_holds_after_its_next_attempt_is_claimed() {
        let retry = terminal_of(DeliveryAuditDisposition::RetryPending);
        assert!(transition_holds(&retry, &observed("pending", 1, 1), None));
        assert!(
            transition_holds(&retry, &observed("leased", 1, 2), None),
            "the next attempt proves the retry committed"
        );
        assert!(
            !transition_holds(
                &retry,
                &ObservedDelivery {
                    lease_token: Some(Uuid::nil()),
                    ..observed("leased", 1, 1)
                },
                None
            ),
            "a lease still at the attempt proves the retry rolled back"
        );
    }

    #[test]
    fn a_committed_dead_letter_holds_after_it_is_replayed() {
        let dead_letter = terminal_of(DeliveryAuditDisposition::DeadLettered);
        assert!(transition_holds(
            &dead_letter,
            &observed("dead_lettered", 1, 1),
            None
        ));
        assert!(
            transition_holds(&dead_letter, &observed("pending", 2, 0), None),
            "a replay generation proves the dead letter committed"
        );
        assert!(!transition_holds(
            &dead_letter,
            &observed("leased", 1, 1),
            None
        ));
    }

    #[test]
    fn a_replay_whose_reset_committed_holds_after_the_worker_moves_it() {
        let replay = replay_of(2);
        for state in ["pending", "leased", "delivered", "dead_lettered"] {
            assert!(
                transition_holds(&replay, &observed(state, 2, 1), None),
                "the replacement generation proves the reset in state {state}"
            );
        }
        assert!(
            transition_holds(&replay, &observed("pending", 3, 0), None),
            "a later replay's generation proves this reset committed before it"
        );
        assert!(
            !transition_holds(&replay, &observed("dead_lettered", 1, 2), None),
            "the prior generation proves the reset rolled back"
        );
    }

    #[test]
    fn the_worker_accepts_the_stored_envelope_it_will_deliver_unchanged() {
        let body = stored_envelope()
            .to_canonical_bytes(&EnvelopeLimits::default())
            .expect("envelope bytes");
        let digest = Sha256::digest(&body).to_vec();
        assert!(
            accept_stored_envelope(&body, &stored_binding(&body, &digest)).is_ok(),
            "the stored envelope matches the delivery row that governs it"
        );
    }

    #[test]
    fn the_worker_refuses_a_body_that_is_not_an_envelope() {
        let body = br#"{"entity":"permit","recordId":"8f14e45f","revision":3}"#.to_vec();
        let digest = Sha256::digest(&body).to_vec();
        assert!(
            accept_stored_envelope(&body, &stored_binding(&body, &digest)).is_err(),
            "a stored body in the pre-envelope shape is refused, never delivered"
        );
    }

    #[test]
    fn the_worker_refuses_an_envelope_that_disagrees_with_its_delivery_row() {
        let mut envelope = stored_envelope();
        envelope.source = "urn:registrystack:test:instance:other".to_owned();
        let body = envelope
            .to_canonical_bytes(&EnvelopeLimits::default())
            .expect("envelope bytes");
        let digest = Sha256::digest(&body).to_vec();
        assert!(
            accept_stored_envelope(&body, &stored_binding(&body, &digest)).is_err(),
            "an envelope whose source differs from the header the worker would sign is refused"
        );

        let mut envelope = stored_envelope();
        envelope.time += Duration::from_millis(1);
        let body = envelope
            .to_canonical_bytes(&EnvelopeLimits::default())
            .expect("envelope bytes");
        let digest = Sha256::digest(&body).to_vec();
        assert!(
            accept_stored_envelope(&body, &stored_binding(&body, &digest)).is_err(),
            "an envelope whose time differs from the stored capture instant is refused"
        );
    }

    #[test]
    fn the_per_delivery_bound_measures_the_whole_stored_envelope() {
        let body = stored_envelope()
            .to_canonical_bytes(&EnvelopeLimits::default())
            .expect("envelope bytes");
        let digest = Sha256::digest(&body).to_vec();
        let data_bytes = serde_json::to_vec(&stored_envelope().data).expect("data bytes");
        assert!(data_bytes.len() < body.len());
        let mut binding = stored_binding(&body, &digest);
        binding.maximum_payload_bytes = i64::try_from(body.len() - 1).expect("bound");
        assert!(
            accept_stored_envelope(&body, &binding).is_err(),
            "the bound refuses envelope bytes, not the product projection alone"
        );
    }

    #[test]
    fn the_worker_refuses_an_envelope_whose_captured_digest_does_not_match() {
        let body = stored_envelope()
            .to_canonical_bytes(&EnvelopeLimits::default())
            .expect("envelope bytes");
        let digest = Sha256::digest(b"other bytes").to_vec();
        assert!(
            accept_stored_envelope(&body, &stored_binding(&body, &digest)).is_err(),
            "the captured payload digest still pins the bytes the idempotency key is built from"
        );
    }

    #[test]
    fn attempt_budget_is_unspent_when_the_claim_clock_runs_ahead_of_this_process() {
        let attempt_timeout = Duration::from_millis(2_000);
        let attempt_started_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        let ahead_of_this_process = attempt_started_at - Duration::from_millis(5);
        assert_eq!(
            remaining_attempt_budget(attempt_timeout, attempt_started_at, ahead_of_this_process),
            Some(attempt_timeout),
            "a claim that appears to start in the local future has spent none of its budget"
        );
    }

    #[test]
    fn attempt_budget_is_exhausted_once_the_captured_attempt_timeout_elapses() {
        let attempt_timeout = Duration::from_millis(2_000);
        let attempt_started_at = SystemTime::UNIX_EPOCH + Duration::from_secs(1_000);
        assert_eq!(
            remaining_attempt_budget(
                attempt_timeout,
                attempt_started_at,
                attempt_started_at + Duration::from_millis(1_500)
            ),
            Some(Duration::from_millis(500))
        );
        assert_eq!(
            remaining_attempt_budget(
                attempt_timeout,
                attempt_started_at,
                attempt_started_at + Duration::from_millis(2_001)
            ),
            None,
            "an attempt that outlives its captured timeout never reaches the destination"
        );
    }

    #[test]
    fn idempotency_key_is_stable_across_retries_and_changes_on_replay_generation() {
        let domain = b"hooks-delivery-idempotency-v1";
        let event_id =
            Uuid::parse_str("00000000-0000-4000-8000-000000000001").expect("fixture UUID parses");
        let digest = Sha256::digest(br#"{"label":"value"}"#);
        let first_key = delivery_idempotency_key(
            domain,
            event_id,
            "events.case.created.webhook",
            1,
            digest.as_slice(),
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        let repeated_key = delivery_idempotency_key(
            domain,
            event_id,
            "events.case.created.webhook",
            1,
            digest.as_slice(),
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        let replay_key = delivery_idempotency_key(
            domain,
            event_id,
            "events.case.created.webhook",
            2,
            digest.as_slice(),
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        assert_eq!(first_key, repeated_key);
        assert_ne!(first_key, replay_key);
        assert!(first_key.starts_with("sha256:"));
        assert_eq!(first_key.len(), 71);
    }

    #[test]
    fn the_idempotency_key_is_bound_to_its_configured_domain() {
        let event_id =
            Uuid::parse_str("00000000-0000-4000-8000-000000000001").expect("fixture UUID parses");
        let digest = Sha256::digest(br#"{"label":"value"}"#);
        let binding = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let one = delivery_idempotency_key(
            b"hooks-delivery-idempotency-v1",
            event_id,
            "events.case.created.webhook",
            1,
            digest.as_slice(),
            binding,
        );
        let other = delivery_idempotency_key(
            b"another-product-idempotency-v1",
            event_id,
            "events.case.created.webhook",
            1,
            digest.as_slice(),
            binding,
        );
        assert_ne!(
            one, other,
            "two products never share a delivery idempotency key"
        );
    }

    #[test]
    fn transport_failure_is_separate_from_a_reached_attempt_deadline() {
        assert_eq!(
            classify_send_error(DestinationSendError::TransportFailed, false),
            DeliveryAuditOutcome::DestinationTransportUnavailable
        );
        assert_eq!(
            classify_send_error(DestinationSendError::TransportFailed, true),
            DeliveryAuditOutcome::DestinationTimeout
        );
        assert_eq!(
            classify_send_error(DestinationSendError::DeadlineExceeded, false),
            DeliveryAuditOutcome::DestinationTimeout
        );
    }

    #[test]
    fn captured_policy_bounds_are_enforced_exactly() {
        let delays = [1_000, 2_000];
        assert!(validate_captured_policy(100, 1, &[]).is_ok());
        assert!(validate_captured_policy(10_000, 3, &delays).is_ok());
        assert!(validate_captured_policy(99, 1, &[]).is_err());
        assert!(validate_captured_policy(10_001, 1, &[]).is_err());
        assert!(validate_captured_policy(100, 0, &[]).is_err());
        assert!(validate_captured_policy(100, 21, &[]).is_err());
        assert!(
            validate_captured_policy(100, 2, &[99]).is_err(),
            "a delay below the floor is refused"
        );
        assert!(
            validate_captured_policy(100, 3, &[1_000]).is_err(),
            "a shortened delay list is refused"
        );
    }

    #[test]
    fn the_scheduled_retry_delay_comes_from_the_captured_profile() {
        let delays = [500, 1_500];
        assert_eq!(scheduled_retry_delay(&delays, 1), Ok(500));
        assert_eq!(scheduled_retry_delay(&delays, 2), Ok(1_500));
        assert_eq!(
            scheduled_retry_delay(&delays, 3),
            Err(DeliveryError::Unavailable),
            "an attempt past the captured profile is refused"
        );
        assert_eq!(
            scheduled_retry_delay(&[0], 1),
            Err(DeliveryError::Unavailable),
            "a non-positive delay is refused"
        );
    }

    #[test]
    fn the_operator_status_reflects_payload_expiry_on_pending_rows() {
        assert_eq!(
            delivery_status_kind("pending", true),
            Ok(DeliveryStatusKind::Pending)
        );
        assert_eq!(
            delivery_status_kind("pending", false),
            Ok(DeliveryStatusKind::Expired)
        );
        assert_eq!(
            delivery_status_kind("expired", false),
            Ok(DeliveryStatusKind::Expired)
        );
        assert_eq!(
            delivery_status_kind("dead_lettered", false),
            Ok(DeliveryStatusKind::DeadLettered)
        );
        assert_eq!(
            delivery_status_kind("leased", true),
            Err(DeliveryError::Unavailable)
        );
    }

    #[test]
    #[should_panic(expected = "delivery schema must be a plain lowercase SQL identifier")]
    fn a_service_refuses_a_schema_that_is_not_a_plain_identifier() {
        let seams = RefusingSeams {
            events: Arc::new(Mutex::new(Vec::new())),
        };
        let _ = DeliveryService::new(
            seams,
            DeliveryConfig {
                schema: "registry; drop table users".to_owned(),
                idempotency_domain: b"hooks-delivery-refusal-test-v1".to_vec(),
                delivery_source: "urn:registrystack:test:instance:hooks-delivery".to_owned(),
            },
        );
    }

    #[tokio::test]
    async fn the_worker_loop_reports_iteration_failures_and_stops_on_shutdown() {
        let events = Arc::new(Mutex::new(Vec::new()));
        let service = DeliveryService::new(
            RefusingSeams {
                events: Arc::clone(&events),
            },
            DeliveryConfig {
                schema: "hooks_delivery_loop_test".to_owned(),
                idempotency_domain: b"hooks-delivery-loop-test-v1".to_vec(),
                delivery_source: "urn:registrystack:test:instance:hooks-delivery".to_owned(),
            },
        );
        let (shutdown_tx, shutdown_rx) = watch::channel(false);
        let handle = tokio::spawn(DeliveryWorker::new(service).run(shutdown_rx));
        tokio::time::sleep(Duration::from_millis(250)).await;
        shutdown_tx
            .send(true)
            .expect("the shutdown receiver is alive");
        handle.await.expect("the worker task joins");
        let recorded = events.lock().expect("events lock");
        assert!(
            recorded.contains(&DeliveryOperationalEvent::IterationFailed),
            "a failed iteration is reported through the operational seam"
        );
        assert!(
            recorded.iter().all(|event| *event
                != DeliveryOperationalEvent::TransitionFailed(
                    DeliveryTransitionCode::ClaimIdentityRefused
                )),
            "a failure before the claim transaction emits no transition code"
        );
    }
    #[test]
    fn an_empty_answer_body_reads_as_the_none_answer() {
        let accepted = accept_handler_answer(b"").expect("an empty body is the none answer");
        assert_eq!(
            accepted.bytes,
            br#"{"answer":"none"}"#.to_vec(),
            "an empty body is recorded as the canonical none answer"
        );
    }

    #[test]
    fn an_answer_over_the_output_ceiling_is_a_resource_failure() {
        let mut body = br#"{"answer":"proposal","document":{"padding":""#.to_vec();
        body.resize(body.len() + crate::MAX_OUTPUT_BYTES, b'x');
        body.extend_from_slice(br#""}}"#);
        assert_eq!(
            accept_handler_answer(&body).expect_err("an oversize answer is refused"),
            ErrorCategory::Resource,
            "a body over the ceiling is a resource failure"
        );
    }

    #[test]
    fn a_malformed_answer_is_a_source_failure() {
        assert_eq!(
            accept_handler_answer(b"not json").expect_err("a malformed answer is refused"),
            ErrorCategory::Source,
            "a body that is not the handler message is a source failure"
        );
        assert_eq!(
            accept_handler_answer(br#"{"answer":"maybe"}"#)
                .expect_err("an unknown answer is refused"),
            ErrorCategory::Source,
            "a body outside the closed answer vocabulary is a source failure"
        );
    }

    #[test]
    fn a_non_canonical_answer_is_a_source_failure() {
        assert_eq!(
            accept_handler_answer(br#"{"answer": "none"}"#)
                .expect_err("a non-canonical answer is refused"),
            ErrorCategory::Source,
            "a body that is not its own canonicalization is a source failure"
        );
    }

    #[test]
    fn the_recorded_answer_digest_covers_the_canonical_message_bytes() {
        let body =
            br#"{"answer":"refusal","code":"permit.expired","summary":"The permit lapsed."}"#;
        let accepted = accept_handler_answer(body).expect("a refusal answer is accepted");
        assert_eq!(
            accepted.bytes,
            body.to_vec(),
            "the recorded message is the canonical answer the handler produced"
        );
        assert_eq!(
            accepted.digest.to_vec(),
            Sha256::digest(body).to_vec(),
            "the recorded digest covers exactly the recorded message bytes"
        );
    }

    /// A seam set that records every proposal it is handed and answers with a
    /// programmed outcome. Every method the delivery path before the apply
    /// step uses still refuses, so nothing but the apply seam is reachable.
    struct ProposalSeams {
        applications: Arc<Mutex<Vec<RecordedApplication>>>,
        recoveries: Arc<Mutex<Vec<RecordedRecovery>>>,
        answer: Result<ProposalOutcome, DeliveryError>,
        recovery: Result<Option<ProposalOutcome>, DeliveryError>,
    }

    struct RecordedApplication {
        event_id: Uuid,
        compiled_delivery_id: String,
        package_revision: String,
        envelope: Vec<u8>,
        answer: Vec<u8>,
        answer_digest: [u8; 32],
    }

    struct RecordedRecovery {
        event_id: Uuid,
        compiled_delivery_id: String,
    }

    #[async_trait::async_trait]
    impl DeliverySeams for ProposalSeams {
        type Destination = UnusedDestination;
        type Handler = UnusedHandler;

        async fn connection(&self) -> Result<DeliveryConnection, DeliveryError> {
            Err(DeliveryError::Unavailable)
        }

        async fn verify_transaction(
            &self,
            _transaction: &Transaction<'_>,
        ) -> Result<(), DeliveryError> {
            Err(DeliveryError::Unavailable)
        }

        fn destination(&self, _logical_destination_id: &str) -> Option<Self::Destination> {
            None
        }

        fn handler(&self, _binding: HookHandlerBinding<'_>) -> Option<Self::Handler> {
            None
        }

        async fn record_audit(
            &self,
            _record: DeliveryAuditRecord<'_>,
        ) -> Result<(), DeliveryError> {
            Err(DeliveryError::Unavailable)
        }

        fn operational_event(&self, _event: DeliveryOperationalEvent) {}

        async fn apply_proposal(
            &self,
            application: ProposalApplication<'_>,
        ) -> Result<ProposalOutcome, DeliveryError> {
            self.applications
                .lock()
                .expect("applications lock")
                .push(RecordedApplication {
                    event_id: application.event_id,
                    compiled_delivery_id: application.compiled_delivery_id.to_owned(),
                    package_revision: application.package_revision.to_owned(),
                    envelope: application.envelope.to_vec(),
                    answer: application.answer.to_vec(),
                    answer_digest: *application.answer_digest,
                });
            self.answer.clone()
        }

        async fn recover_proposal_receipt(
            &self,
            recovery: ProposalReceiptRecovery<'_>,
        ) -> Result<Option<ProposalOutcome>, DeliveryError> {
            self.recoveries
                .lock()
                .expect("recoveries lock")
                .push(RecordedRecovery {
                    event_id: recovery.event_id,
                    compiled_delivery_id: recovery.compiled_delivery_id.to_owned(),
                });
            self.recovery.clone()
        }

        async fn recover_proposal_receipt_in_transaction(
            &self,
            _transaction: &Transaction<'_>,
            recovery: ProposalReceiptRecovery<'_>,
        ) -> Result<Option<ProposalOutcome>, DeliveryError> {
            self.recoveries
                .lock()
                .expect("recoveries lock")
                .push(RecordedRecovery {
                    event_id: recovery.event_id,
                    compiled_delivery_id: recovery.compiled_delivery_id.to_owned(),
                });
            self.recovery.clone()
        }
    }

    fn proposal_claim() -> DeliveryClaim {
        DeliveryClaim {
            event_id: Uuid::parse_str(STORED_EVENT_ID).expect("event id"),
            compiled_delivery_id: "events.permit.granted.webhook".to_owned(),
            generation: 1,
            attempt: 1,
            attempt_started_at: SystemTime::UNIX_EPOCH + Duration::from_secs(1_000),
            lease_token: Uuid::new_v4(),
            deployed_maximum_attempts: 2,
            retry_delays_ms: vec![1_000],
            package_revision:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_owned(),
            handler_kind: HookHandlerKind::Rhai,
        }
    }

    fn proposal_service(
        applications: Arc<Mutex<Vec<RecordedApplication>>>,
        recoveries: Arc<Mutex<Vec<RecordedRecovery>>>,
        answer: Result<ProposalOutcome, DeliveryError>,
        recovery: Result<Option<ProposalOutcome>, DeliveryError>,
    ) -> DeliveryService<ProposalSeams> {
        DeliveryService::new(
            ProposalSeams {
                applications,
                recoveries,
                answer,
                recovery,
            },
            DeliveryConfig {
                schema: "hooks_delivery_proposal_test".to_owned(),
                idempotency_domain: b"hooks-delivery-proposal-test-v1".to_vec(),
                delivery_source: STORED_SOURCE.to_owned(),
            },
        )
    }

    fn stored_envelope_bytes() -> Vec<u8> {
        stored_envelope()
            .to_canonical_bytes(&EnvelopeLimits::default())
            .expect("envelope bytes")
    }

    #[tokio::test]
    async fn an_accepted_proposal_is_handed_to_the_product_seam() {
        let applications = Arc::new(Mutex::new(Vec::new()));
        let recoveries = Arc::new(Mutex::new(Vec::new()));
        let service = proposal_service(
            Arc::clone(&applications),
            Arc::clone(&recoveries),
            Ok(ProposalOutcome::Applied {
                resulting_revision: 7,
            }),
            Ok(None),
        );
        let claim = proposal_claim();
        let envelope = stored_envelope_bytes();
        let answer = br#"{"answer":"proposal","document":{"kind":"action-outcome"}}"#;
        let settled = service
            .settle_answer(&claim, &envelope, accepted_answer_result(answer))
            .await
            .expect("the apply seam answers");
        assert!(matches!(
            settled.proposal,
            Some(ProposalOutcome::Applied {
                resulting_revision: 7
            })
        ));
        let recorded = applications.lock().expect("applications lock");
        assert_eq!(recorded.len(), 1, "exactly one application per proposal");
        assert_eq!(recorded[0].event_id, claim.event_id);
        assert_eq!(recorded[0].compiled_delivery_id, claim.compiled_delivery_id);
        assert_eq!(recorded[0].package_revision, claim.package_revision);
        assert_eq!(recorded[0].envelope, envelope);
        assert_eq!(recorded[0].answer, answer.to_vec());
        let expected_digest: [u8; 32] = Sha256::digest(answer).into();
        assert_eq!(
            recorded[0].answer_digest, expected_digest,
            "the application identity is the digest of exactly the recorded answer bytes"
        );
    }

    #[tokio::test]
    async fn an_uncertain_apply_fails_closed_before_any_finalization() {
        // The seam's error means the apply may have committed and the worker
        // cannot know: the attempt result must not become a delivered row, so
        // the error propagates and the lease is left for expiry recovery.
        let applications = Arc::new(Mutex::new(Vec::new()));
        let recoveries = Arc::new(Mutex::new(Vec::new()));
        let service = proposal_service(
            Arc::clone(&applications),
            Arc::clone(&recoveries),
            Err(DeliveryError::Unavailable),
            Ok(None),
        );
        let claim = proposal_claim();
        let envelope = stored_envelope_bytes();
        let answer = br#"{"answer":"proposal","document":{"kind":"action-outcome"}}"#;
        let settled = service
            .settle_answer(&claim, &envelope, accepted_answer_result(answer))
            .await;
        assert!(
            matches!(settled, Err(DeliveryError::Unavailable)),
            "an uncertain apply never reaches finalize as a settled outcome"
        );
        assert_eq!(
            applications.lock().expect("applications lock").len(),
            1,
            "the seam was asked exactly once before the uncertainty"
        );
    }

    #[tokio::test]
    async fn an_answer_that_proposes_nothing_checks_only_for_a_committed_proposal() {
        let applications = Arc::new(Mutex::new(Vec::new()));
        let recoveries = Arc::new(Mutex::new(Vec::new()));
        let service = proposal_service(
            Arc::clone(&applications),
            Arc::clone(&recoveries),
            Ok(ProposalOutcome::Applied {
                resulting_revision: 7,
            }),
            Ok(None),
        );
        let claim = proposal_claim();
        let envelope = stored_envelope_bytes();
        for body in [
            b"".as_slice(),
            br#"{"answer":"none"}"#.as_slice(),
            br#"{"answer":"refusal","code":"permit.expired","summary":"The permit lapsed."}"#
                .as_slice(),
        ] {
            let settled = service
                .settle_answer(&claim, &envelope, accepted_answer_result(body))
                .await
                .expect("an answer without a proposal checks for an earlier receipt");
            assert!(
                settled.proposal.is_none(),
                "a none or refusal answer carries no proposal to apply"
            );
        }
        assert!(
            applications.lock().expect("applications lock").is_empty(),
            "the apply seam is only asked for a proposal answer"
        );
        let recoveries = recoveries.lock().expect("recoveries lock");
        assert_eq!(recoveries.len(), 3);
        assert!(recoveries.iter().all(|recovery| {
            recovery.event_id == claim.event_id
                && recovery.compiled_delivery_id == claim.compiled_delivery_id
        }));
    }

    #[tokio::test]
    async fn a_non_proposal_answer_keeps_a_recovered_proposal_conflict() {
        let applications = Arc::new(Mutex::new(Vec::new()));
        let recoveries = Arc::new(Mutex::new(Vec::new()));
        let conflict = ProposalOutcome::DeadLettered {
            code: crate::BoundedText::try_from("hook.proposal.answer_conflict")
                .expect("within the code bound"),
            summary: crate::BoundedText::try_from(
                "This delivery already applied a different answer; the first application stands.",
            )
            .expect("within the summary bound"),
        };
        let service = proposal_service(
            Arc::clone(&applications),
            Arc::clone(&recoveries),
            Err(DeliveryError::Unavailable),
            Ok(Some(conflict.clone())),
        );
        let claim = proposal_claim();
        let settled = service
            .settle_answer(
                &claim,
                &stored_envelope_bytes(),
                accepted_answer_result(br#"{"answer":"none"}"#),
            )
            .await
            .expect("the committed proposal receipt settles the changed answer");
        assert_eq!(settled.proposal, Some(conflict));
        assert!(applications.lock().expect("applications lock").is_empty());
        assert_eq!(recoveries.lock().expect("recoveries lock").len(), 1);
    }

    #[test]
    fn the_terminal_transition_writes_the_disposition_it_earned() {
        let applied = ProposalOutcome::Applied {
            resulting_revision: 3,
        };
        let refused = ProposalOutcome::Refused {
            code: crate::BoundedText::try_from("hook.proposal.outcome_refused")
                .expect("within the code bound"),
            summary: crate::BoundedText::try_from("the proposal failed validation")
                .expect("within the summary bound"),
        };
        let dead_lettered = ProposalOutcome::DeadLettered {
            code: crate::BoundedText::try_from("hook.proposal.no_principal")
                .expect("within the code bound"),
            summary: crate::BoundedText::try_from("the hook declares no principal")
                .expect("within the summary bound"),
        };

        let none = proposal_columns("delivered", None).expect("delivered always states one");
        assert_eq!(none.disposition, Some("none"));
        assert_eq!(none.resulting_revision, None);
        assert_eq!(none.code, None);
        assert_eq!(none.summary, None);

        let applied_columns =
            proposal_columns("delivered", Some(&applied)).expect("applied is recorded");
        assert_eq!(applied_columns.disposition, Some("applied"));
        assert_eq!(applied_columns.resulting_revision, Some(3));
        assert_eq!(applied_columns.code, None);
        assert_eq!(applied_columns.summary, None);

        let refused_columns =
            proposal_columns("delivered", Some(&refused)).expect("a refusal is recorded");
        assert_eq!(refused_columns.disposition, Some("refused"));
        assert_eq!(refused_columns.resulting_revision, None);
        assert_eq!(refused_columns.code, Some("hook.proposal.outcome_refused"));
        assert_eq!(
            refused_columns.summary,
            Some("the proposal failed validation")
        );

        let dead_columns = proposal_columns("dead_lettered", Some(&dead_lettered))
            .expect("a dead-lettered proposal is recorded");
        assert_eq!(dead_columns.disposition, Some("dead_lettered"));
        assert_eq!(dead_columns.resulting_revision, None);
        assert_eq!(dead_columns.code, Some("hook.proposal.no_principal"));
        assert_eq!(dead_columns.summary, Some("the hook declares no principal"));

        // A row that dead-letters without accepting an answer keeps the
        // legacy all-null shape: it never had a proposal to settle.
        let exhausted = proposal_columns("dead_lettered", None).expect("legacy shape holds");
        assert_eq!(exhausted.disposition, None);
        assert_eq!(exhausted.resulting_revision, None);
        assert_eq!(exhausted.code, None);
        assert_eq!(exhausted.summary, None);
    }

    /// Wraps a plain connection as the `DeliveryConnection` the seam trait
    /// requires, the way a product wraps its pooled client.
    struct DirectClient(tokio_postgres::Client);

    impl std::ops::Deref for DirectClient {
        type Target = tokio_postgres::Client;

        fn deref(&self) -> &Self::Target {
            &self.0
        }
    }

    impl std::ops::DerefMut for DirectClient {
        fn deref_mut(&mut self) -> &mut Self::Target {
            &mut self.0
        }
    }

    async fn connect_test_database(url: &str) -> tokio_postgres::Client {
        let (client, connection) = tokio_postgres::connect(url, tokio_postgres::NoTls)
            .await
            .expect("connect to the local PostgreSQL test database");
        tokio::spawn(async move {
            if let Err(error) = connection.await {
                eprintln!("test database connection closed: {error}");
            }
        });
        client
    }

    type RecordedAudit = (
        DeliveryAuditPhase,
        DeliveryAuditOutcome,
        DeliveryAuditDisposition,
    );

    /// A local handler that only answers to its reviewed digest, so a replay
    /// can find the binding its row was written against.
    struct DigestHandler(String);

    #[async_trait::async_trait]
    impl HookHandler for DigestHandler {
        fn handler_digest(&self) -> &str {
            &self.0
        }

        fn attempt_timeout(&self) -> Duration {
            Duration::ZERO
        }

        fn maximum_attempts(&self) -> u8 {
            1
        }

        async fn run(
            &self,
            _envelope: &[u8],
            _remaining: Duration,
        ) -> Result<Vec<u8>, crate::delivery::HandlerRunFailure> {
            unreachable!("no real-database test runs a handler")
        }
    }

    /// A seam set that opens its own connection against a real PostgreSQL
    /// test database and records every audit record it is given, so a test can
    /// prove which transitions were written. Connections are numbered from
    /// one in the order they are opened: a test may refuse chosen ones, and
    /// may run one statement on a chosen one before the service uses it, to
    /// stand for another session acting at that moment.
    struct RealDbSeams {
        url: String,
        audit: Arc<Mutex<Vec<RecordedAudit>>>,
        connections: Mutex<u32>,
        refused_connections: Vec<u32>,
        interleave: Option<(u32, String)>,
        handler_digest: Option<String>,
    }

    impl RealDbSeams {
        fn new(url: &str, audit: &Arc<Mutex<Vec<RecordedAudit>>>) -> Self {
            Self {
                url: url.to_owned(),
                audit: Arc::clone(audit),
                connections: Mutex::new(0),
                refused_connections: Vec::new(),
                interleave: None,
                handler_digest: None,
            }
        }
    }

    #[async_trait::async_trait]
    impl DeliverySeams for RealDbSeams {
        type Destination = UnusedDestination;
        type Handler = DigestHandler;

        async fn connection(&self) -> Result<DeliveryConnection, DeliveryError> {
            let number = {
                let mut connections = self.connections.lock().expect("connections lock");
                *connections += 1;
                *connections
            };
            if self.refused_connections.contains(&number) {
                return Err(DeliveryError::Unavailable);
            }
            let client = connect_test_database(&self.url).await;
            if let Some((_, statement)) = self.interleave.as_ref().filter(|(at, _)| *at == number) {
                client
                    .batch_execute(statement)
                    .await
                    .expect("the interleaved statement runs");
            }
            Ok(Box::new(DirectClient(client)))
        }

        async fn verify_transaction(
            &self,
            _transaction: &Transaction<'_>,
        ) -> Result<(), DeliveryError> {
            Ok(())
        }

        fn destination(&self, _logical_destination_id: &str) -> Option<Self::Destination> {
            None
        }

        fn handler(&self, binding: HookHandlerBinding<'_>) -> Option<Self::Handler> {
            self.handler_digest
                .as_deref()
                .filter(|digest| *digest == binding.handler_digest)
                .map(|digest| DigestHandler(digest.to_owned()))
        }

        async fn record_audit(&self, record: DeliveryAuditRecord<'_>) -> Result<(), DeliveryError> {
            self.audit.lock().expect("audit lock").push((
                record.phase,
                record.outcome,
                record.disposition,
            ));
            Ok(())
        }

        fn operational_event(&self, _event: DeliveryOperationalEvent) {}

        async fn apply_proposal(
            &self,
            _application: ProposalApplication<'_>,
        ) -> Result<ProposalOutcome, DeliveryError> {
            Err(DeliveryError::Unavailable)
        }

        async fn recover_proposal_receipt(
            &self,
            _recovery: ProposalReceiptRecovery<'_>,
        ) -> Result<Option<ProposalOutcome>, DeliveryError> {
            Err(DeliveryError::Unavailable)
        }

        async fn recover_proposal_receipt_in_transaction(
            &self,
            _transaction: &Transaction<'_>,
            _recovery: ProposalReceiptRecovery<'_>,
        ) -> Result<Option<ProposalOutcome>, DeliveryError> {
            Err(DeliveryError::Unavailable)
        }
    }

    // Requires a real PostgreSQL connection: `Transaction<'_>` cannot be
    // faked, and the guarded update this test forces to zero rows is the
    // real lease-vs-CAS statement running against a real table. Run with
    // `--ignored` and `HOOKS_TEST_DATABASE_URL` set to a disposable database.
    #[tokio::test]
    #[ignore = "requires a local PostgreSQL test database named by HOOKS_TEST_DATABASE_URL"]
    async fn finalize_refuses_a_terminal_transition_when_the_lease_was_stolen() {
        let url = std::env::var("HOOKS_TEST_DATABASE_URL")
            .expect("HOOKS_TEST_DATABASE_URL is required for the real PostgreSQL finalize test");
        let schema = "hooks_delivery_lease_test";
        let mut client = connect_test_database(&url).await;
        client
            .batch_execute(&format!(
                "DROP SCHEMA IF EXISTS {schema} CASCADE; CREATE SCHEMA {schema};"
            ))
            .await
            .expect("reset the test schema");
        delivery_schema::install(&client, schema)
            .await
            .expect("install the delivery schema");

        let event_id = Uuid::parse_str(STORED_EVENT_ID).expect("event id");
        let compiled_delivery_id = "events.permit.granted.webhook";
        let package_revision =
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        let schema_fingerprint =
            "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";

        client
            .execute(
                &format!(
                    "INSERT INTO {schema}.registry_outbox
                     (event_id, event_type, trigger, entity_id, record_reference,
                      record_revision, package_revision, schema_fingerprint, payload_expires_at)
                     VALUES ($1, $2, 'test', 'permit', $3, 3, $4, $5,
                             transaction_timestamp() + interval '1 day')",
                ),
                &[
                    &event_id,
                    &"permit.granted",
                    &"8f14e45fceea467a9cc18b2a4b9e2a1103b41d5ad4c88c8f2a0a9ac4f4c0d2b7",
                    &package_revision,
                    &schema_fingerprint,
                ],
            )
            .await
            .expect("insert the outbox row");

        {
            let transaction = client.transaction().await.expect("insert transaction");
            insert_delivery(
                &transaction,
                schema,
                event_id,
                DeliveryCapture {
                    compiled_delivery_id,
                    handler_kind: HookHandlerKind::Rhai,
                    logical_destination_id: None,
                    destination_binding_digest:
                        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                    package_revision,
                    schema_fingerprint,
                    data_schema: STORED_DATA_SCHEMA,
                    classification_ceiling: "public",
                    authentication_profile: "hmac_sha256_v1",
                    delivery_mode: "after_commit",
                    attempt_timeout_ms: 5_000,
                    initial_backoff_ms: 1_000,
                    maximum_backoff_ms: 60_000,
                    exponential_backoff_multiplier: 2,
                    maximum_attempts: 3,
                    retry_delays_ms: &[1_000, 2_000],
                    maximum_payload_bytes: 1_024,
                    payload: b"{}",
                    deployed_attempt_timeout_ms: 5_000,
                    deployed_maximum_attempts: 3,
                    dead_letter: "required",
                    operator_replay: false,
                },
            )
            .await
            .expect("insert the delivery row");
            transaction.commit().await.expect("commit the insert");
        }

        // Simulate another worker stealing the lease: the row is `leased`
        // under a lease token that is not the one the finalizing worker
        // holds.
        let stolen_lease_token = Uuid::new_v4();
        let changed = client
            .execute(
                &format!(
                    "UPDATE {schema}.registry_webhook_delivery_state
                     SET state = 'leased',
                         attempt = 1,
                         next_attempt_at = NULL,
                         attempt_started_at = transaction_timestamp(),
                         lease_expires_at = transaction_timestamp() + interval '30 seconds',
                         lease_token = $1
                     WHERE event_id = $2 AND compiled_delivery_id = $3",
                ),
                &[&stolen_lease_token, &event_id, &compiled_delivery_id],
            )
            .await
            .expect("simulate an active lease");
        assert_eq!(changed, 1, "the inserted delivery state row exists");

        let audit = Arc::new(Mutex::new(Vec::new()));
        let service = DeliveryService::new(
            RealDbSeams::new(&url, &audit),
            DeliveryConfig {
                schema: schema.to_owned(),
                idempotency_domain: b"hooks-delivery-lease-test-v1".to_vec(),
                delivery_source: STORED_SOURCE.to_owned(),
            },
        );
        let claim = DeliveryClaim {
            event_id,
            compiled_delivery_id: compiled_delivery_id.to_owned(),
            generation: 1,
            attempt: 1,
            attempt_started_at: SystemTime::now(),
            // The finalizing worker's own lease token: fresh, so it never
            // matches the stolen token now stored on the row.
            lease_token: Uuid::new_v4(),
            deployed_maximum_attempts: 3,
            retry_delays_ms: vec![1_000, 2_000],
            package_revision: package_revision.to_owned(),
            handler_kind: HookHandlerKind::Rhai,
        };

        let result = service
            .finalize(&claim, AttemptResult::from(DeliveryAuditOutcome::Delivered))
            .await;

        assert!(
            matches!(result, Err(DeliveryError::Unavailable)),
            "a lease-guarded update that changes zero rows must fail closed"
        );
        assert_eq!(
            *audit.lock().expect("audit lock"),
            Vec::<RecordedAudit>::new(),
            "no audit entry for a transition that did not happen"
        );
    }

    const REAL_DELIVERY_ID: &str = "events.permit.granted.webhook";
    const REAL_PACKAGE_REVISION: &str =
        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const REAL_HANDLER_DIGEST: &str =
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";
    const REAL_SCHEMA_FINGERPRINT: &str =
        "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc";
    const OTHER_EVENT_ID: &str = "9b1c3a5e-2d4f-4e6a-8b0c-1d3e5f7a9b2c";

    fn real_database_url() -> String {
        std::env::var("HOOKS_TEST_DATABASE_URL")
            .expect("HOOKS_TEST_DATABASE_URL is required for the real PostgreSQL tests")
    }

    /// Install the delivery schema afresh under `schema` and return an
    /// administrative connection to the test database.
    async fn fresh_delivery_schema(url: &str, schema: &str) -> tokio_postgres::Client {
        let client = connect_test_database(url).await;
        client
            .batch_execute(&format!(
                "DROP SCHEMA IF EXISTS {schema} CASCADE; CREATE SCHEMA {schema};"
            ))
            .await
            .expect("reset the test schema");
        delivery_schema::install(&client, schema)
            .await
            .expect("install the delivery schema");
        client
    }

    /// Insert one pending local-handler delivery of `event_id` whose stored
    /// payload expires after `payload_lifetime`, a PostgreSQL interval.
    async fn insert_real_delivery(
        client: &mut tokio_postgres::Client,
        schema: &str,
        event_id: Uuid,
        payload_lifetime: &str,
        operator_replay: bool,
    ) {
        client
            .execute(
                &format!(
                    "INSERT INTO {schema}.registry_outbox
                     (event_id, event_type, trigger, entity_id, record_reference,
                      record_revision, package_revision, schema_fingerprint, payload,
                      payload_expires_at)
                     VALUES ($1, 'permit.granted', 'test', 'permit', $2, 3, $3, $4, $5,
                             transaction_timestamp() + interval '{payload_lifetime}')",
                ),
                &[
                    &event_id,
                    &"8f14e45fceea467a9cc18b2a4b9e2a1103b41d5ad4c88c8f2a0a9ac4f4c0d2b7",
                    &REAL_PACKAGE_REVISION,
                    &REAL_SCHEMA_FINGERPRINT,
                    &b"{}".as_slice(),
                ],
            )
            .await
            .expect("insert the outbox row");
        let transaction = client.transaction().await.expect("insert transaction");
        insert_delivery(
            &transaction,
            schema,
            event_id,
            DeliveryCapture {
                compiled_delivery_id: REAL_DELIVERY_ID,
                handler_kind: HookHandlerKind::Rhai,
                logical_destination_id: None,
                destination_binding_digest: REAL_HANDLER_DIGEST,
                package_revision: REAL_PACKAGE_REVISION,
                schema_fingerprint: REAL_SCHEMA_FINGERPRINT,
                data_schema: STORED_DATA_SCHEMA,
                classification_ceiling: "public",
                authentication_profile: "hmac_sha256_v1",
                delivery_mode: "after_commit",
                attempt_timeout_ms: 5_000,
                initial_backoff_ms: 1_000,
                maximum_backoff_ms: 60_000,
                exponential_backoff_multiplier: 2,
                maximum_attempts: 3,
                retry_delays_ms: &[1_000, 2_000],
                maximum_payload_bytes: 1_024,
                payload: b"{}",
                deployed_attempt_timeout_ms: 5_000,
                deployed_maximum_attempts: 3,
                dead_letter: "required",
                operator_replay,
            },
        )
        .await
        .expect("insert the delivery row");
        transaction.commit().await.expect("commit the insert");
    }

    fn real_service(seams: RealDbSeams, schema: &str) -> DeliveryService<RealDbSeams> {
        DeliveryService::new(
            seams,
            DeliveryConfig {
                schema: schema.to_owned(),
                idempotency_domain: b"hooks-delivery-real-test-v1".to_vec(),
                delivery_source: STORED_SOURCE.to_owned(),
            },
        )
    }

    /// A replay whose reset changed no row did not commit, so its response
    /// is a refusal even when the row reads back under the generation the
    /// replay would have written, here because another replay wrote it.
    #[tokio::test]
    #[ignore = "requires a local PostgreSQL test database named by HOOKS_TEST_DATABASE_URL"]
    async fn a_replay_whose_reset_changed_no_row_is_refused() {
        let url = real_database_url();
        let schema = "hooks_delivery_replay_refused_test";
        let mut client = fresh_delivery_schema(&url, schema).await;
        let event_id = Uuid::parse_str(STORED_EVENT_ID).expect("event id");
        insert_real_delivery(&mut client, schema, event_id, "1 day", true).await;
        client
            .batch_execute(&format!(
                "UPDATE {schema}.registry_webhook_delivery_state
                    SET state = 'dead_lettered', attempt = 3, next_attempt_at = NULL,
                        dead_lettered_at = transaction_timestamp();
                 CREATE FUNCTION {schema}.skip_reset() RETURNS trigger
                 LANGUAGE plpgsql AS $$
                 BEGIN
                     IF current_setting('hooks_test.allow_reset', true) = 'on' THEN
                         RETURN NEW;
                     END IF;
                     RETURN NULL;
                 END $$;
                 CREATE TRIGGER skip_reset
                     BEFORE UPDATE ON {schema}.registry_webhook_delivery_state
                     FOR EACH ROW WHEN (NEW.generation > OLD.generation)
                     EXECUTE FUNCTION {schema}.skip_reset();"
            ))
            .await
            .expect("make the reset change no row");

        let audit = Arc::new(Mutex::new(Vec::new()));
        let service = real_service(
            RealDbSeams {
                handler_digest: Some(REAL_HANDLER_DIGEST.to_owned()),
                // The first connection after the replay's own stands for a
                // concurrent replay that commits the next generation.
                interleave: Some((
                    2,
                    format!(
                        "SET hooks_test.allow_reset = 'on';
                         UPDATE {schema}.registry_webhook_delivery_state
                            SET generation = 2, state = 'pending', attempt = 0,
                                next_attempt_at = transaction_timestamp(),
                                dead_lettered_at = NULL"
                    ),
                )),
                ..RealDbSeams::new(&url, &audit)
            },
            schema,
        );

        let result = service.replay_in(event_id, REAL_DELIVERY_ID, 1).await;

        assert!(
            matches!(result, Err(DeliveryError::Unavailable)),
            "a reset that changed no row fails: {result:?}"
        );
        assert_eq!(
            *audit.lock().expect("audit lock"),
            vec![
                (
                    DeliveryAuditPhase::Replay,
                    DeliveryAuditOutcome::ReplayRequested,
                    DeliveryAuditDisposition::ReplayPending,
                ),
                (
                    DeliveryAuditPhase::Replay,
                    DeliveryAuditOutcome::ReplayRefused,
                    DeliveryAuditDisposition::DeadLettered,
                ),
            ]
        );
    }

    /// A claim whose lease commit failed still records every transition of
    /// that transaction that reads back as durable, even when the lease's
    /// own fate cannot be read.
    #[tokio::test]
    #[ignore = "requires a local PostgreSQL test database named by HOOKS_TEST_DATABASE_URL"]
    async fn a_claim_whose_lease_commit_failed_records_its_durable_transitions() {
        let url = real_database_url();
        let schema = "hooks_delivery_claim_commit_test";
        let mut client = fresh_delivery_schema(&url, schema).await;
        let expiring = Uuid::parse_str(STORED_EVENT_ID).expect("event id");
        let claimable = Uuid::parse_str(OTHER_EVENT_ID).expect("event id");
        insert_real_delivery(&mut client, schema, expiring, "-1 second", false).await;
        insert_real_delivery(&mut client, schema, claimable, "1 day", false).await;
        client
            .batch_execute(&format!(
                "CREATE FUNCTION {schema}.refuse_lease() RETURNS trigger
                 LANGUAGE plpgsql AS $$
                 BEGIN
                     RAISE EXCEPTION 'lease commit refused';
                 END $$;
                 CREATE CONSTRAINT TRIGGER refuse_lease
                     AFTER UPDATE ON {schema}.registry_webhook_delivery_state
                     DEFERRABLE INITIALLY DEFERRED
                     FOR EACH ROW WHEN (NEW.state = 'leased')
                     EXECUTE FUNCTION {schema}.refuse_lease();"
            ))
            .await
            .expect("make the lease commit fail");

        let audit = Arc::new(Mutex::new(Vec::new()));
        let service = real_service(
            RealDbSeams {
                // Every read-back of the lease fails, so its fate is unknown.
                refused_connections: vec![2, 3, 4],
                // The next connection reads back the payload expiry, which
                // this stands for having committed.
                interleave: Some((
                    5,
                    format!(
                        "UPDATE {schema}.registry_webhook_delivery_state
                            SET state = 'expired', next_attempt_at = NULL,
                                expired_at = transaction_timestamp()
                          WHERE event_id = '{expiring}';
                         UPDATE {schema}.registry_outbox SET payload = NULL
                          WHERE event_id = '{expiring}'"
                    ),
                )),
                ..RealDbSeams::new(&url, &audit)
            },
            schema,
        );

        let result = service.claim().await;

        assert!(
            matches!(result, Err(DeliveryError::Unavailable)),
            "a claim whose commit failed fails"
        );
        let recorded = audit.lock().expect("audit lock").clone();
        assert_eq!(
            recorded.first(),
            Some(&(
                DeliveryAuditPhase::Attempt,
                DeliveryAuditOutcome::AttemptStarted,
                DeliveryAuditDisposition::Leased,
            ))
        );
        assert!(
            recorded.contains(&(
                DeliveryAuditPhase::Terminal,
                DeliveryAuditOutcome::PayloadExpired,
                DeliveryAuditDisposition::Expired,
            )),
            "the durable expiry is recorded: {recorded:?}"
        );
        assert!(
            recorded.contains(&(
                DeliveryAuditPhase::Terminal,
                DeliveryAuditOutcome::WorkerInterrupted,
                DeliveryAuditDisposition::RetryPending,
            )),
            "the attempt of unknown fate is answered: {recorded:?}"
        );
        assert_eq!(recorded.len(), 3, "{recorded:?}");
    }

    /// A terminal transition whose commit failed and whose fate cannot be
    /// read back still answers the attempt, after a bounded backoff between
    /// the read-backs.
    #[tokio::test]
    #[ignore = "requires a local PostgreSQL test database named by HOOKS_TEST_DATABASE_URL"]
    async fn finalize_answers_an_attempt_whose_commit_cannot_be_read_back() {
        let url = real_database_url();
        let schema = "hooks_delivery_finalize_unknown_test";
        let mut client = fresh_delivery_schema(&url, schema).await;
        let event_id = Uuid::parse_str(STORED_EVENT_ID).expect("event id");
        insert_real_delivery(&mut client, schema, event_id, "1 day", false).await;
        let lease_token = Uuid::new_v4();
        let changed = client
            .execute(
                &format!(
                    "UPDATE {schema}.registry_webhook_delivery_state
                     SET state = 'leased',
                         attempt = 1,
                         next_attempt_at = NULL,
                         attempt_started_at = transaction_timestamp(),
                         lease_expires_at = transaction_timestamp() + interval '30 seconds',
                         lease_token = $1
                     WHERE event_id = $2",
                ),
                &[&lease_token, &event_id],
            )
            .await
            .expect("lease the delivery");
        assert_eq!(changed, 1);
        client
            .batch_execute(&format!(
                "CREATE FUNCTION {schema}.refuse_delivered() RETURNS trigger
                 LANGUAGE plpgsql AS $$
                 BEGIN
                     RAISE EXCEPTION 'terminal commit refused';
                 END $$;
                 CREATE CONSTRAINT TRIGGER refuse_delivered
                     AFTER UPDATE ON {schema}.registry_webhook_delivery_state
                     DEFERRABLE INITIALLY DEFERRED
                     FOR EACH ROW WHEN (NEW.state = 'delivered')
                     EXECUTE FUNCTION {schema}.refuse_delivered();"
            ))
            .await
            .expect("make the terminal commit fail");

        let audit = Arc::new(Mutex::new(Vec::new()));
        let service = real_service(
            RealDbSeams {
                refused_connections: vec![2, 3, 4],
                ..RealDbSeams::new(&url, &audit)
            },
            schema,
        );
        let claim = DeliveryClaim {
            event_id,
            compiled_delivery_id: REAL_DELIVERY_ID.to_owned(),
            generation: 1,
            attempt: 1,
            attempt_started_at: SystemTime::now(),
            lease_token,
            deployed_maximum_attempts: 3,
            retry_delays_ms: vec![1_000, 2_000],
            package_revision: REAL_PACKAGE_REVISION.to_owned(),
            handler_kind: HookHandlerKind::Rhai,
        };

        let started = Instant::now();
        let result = service
            .finalize(&claim, AttemptResult::from(DeliveryAuditOutcome::Delivered))
            .await;
        let elapsed = started.elapsed();

        assert!(
            matches!(result, Err(DeliveryError::Unavailable)),
            "a terminal commit that failed fails: {result:?}"
        );
        assert_eq!(
            *audit.lock().expect("audit lock"),
            vec![(
                DeliveryAuditPhase::Terminal,
                DeliveryAuditOutcome::WorkerInterrupted,
                DeliveryAuditDisposition::RetryPending,
            )]
        );
        let backoff: Duration = READ_BACK_BACKOFF.iter().sum();
        assert!(
            elapsed >= backoff,
            "the read-backs wait {backoff:?} between them, took {elapsed:?}"
        );
    }
}
