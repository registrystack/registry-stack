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

    /// Claim, audit, send, and finalize at most one due delivery.
    ///
    /// The pre-egress audit and lease commit before request rendering or
    /// destination policy execution. Delivery is therefore explicitly
    /// at-least-once when a process stops after network I/O and before CAS
    /// finalization.
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
                    "SELECT DISTINCT delivery.logical_destination_id,
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
            let logical_id = bounded_text(&row, 0, 64)?;
            let binding_digest = bounded_text(&row, 1, 71)?;
            if self
                .seams
                .destination(&logical_id)
                .is_none_or(|destination| destination.binding_digest() != binding_digest)
            {
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
        self.seams
            .record_audit(
                &transaction,
                DeliveryAuditRecord {
                    event_id,
                    compiled_delivery_id,
                    package_revision: &package_revision,
                    generation: next_generation,
                    attempt: 0,
                    phase: DeliveryAuditPhase::Replay,
                    outcome: DeliveryAuditOutcome::ReplayRequested,
                    disposition: DeliveryAuditDisposition::ReplayPending,
                },
            )
            .await?;
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
        transaction.commit().await?;
        Ok(next_generation)
    }

    async fn claim(&self) -> Result<Option<DeliveryClaim>, DeliveryError> {
        let mut client = self.seams.connection().await?;
        let transaction = client.transaction().await?;
        if self.seams.verify_transaction(&transaction).await.is_err() {
            self.refused(DeliveryTransitionCode::ClaimIdentityRefused);
            return Err(DeliveryError::Unavailable);
        }
        if self.reap_expired_leases(&transaction).await.is_err() {
            self.refused(DeliveryTransitionCode::ClaimRecoveryFailed);
            return Err(DeliveryError::Unavailable);
        }
        self.expire_retained_payload(&transaction).await?;
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
            transaction.commit().await?;
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
        if self
            .seams
            .record_audit(
                &transaction,
                DeliveryAuditRecord {
                    event_id,
                    compiled_delivery_id: &compiled_delivery_id,
                    package_revision: &package_revision,
                    generation,
                    attempt,
                    phase: DeliveryAuditPhase::Attempt,
                    outcome: DeliveryAuditOutcome::AttemptStarted,
                    disposition: DeliveryAuditDisposition::Leased,
                },
            )
            .await
            .is_err()
        {
            self.refused(DeliveryTransitionCode::ClaimAuditFailed);
            return Err(DeliveryError::Unavailable);
        }
        transaction.commit().await.map_err(|_| {
            self.refused(DeliveryTransitionCode::ClaimCommitFailed);
            DeliveryError::Unavailable
        })?;
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
        self.seams
            .record_audit(
                transaction,
                DeliveryAuditRecord {
                    event_id,
                    compiled_delivery_id: &compiled_delivery_id,
                    package_revision: &package_revision,
                    generation,
                    attempt,
                    phase: DeliveryAuditPhase::Terminal,
                    outcome: DeliveryAuditOutcome::WorkerInterrupted,
                    disposition: if dead_lettered {
                        DeliveryAuditDisposition::DeadLettered
                    } else {
                        DeliveryAuditDisposition::RetryPending
                    },
                },
            )
            .await?;
        let changed = if dead_lettered {
            transaction
                .execute(
                    &self.sql(
                        "UPDATE {schema}.registry_webhook_delivery_state
                     SET state = 'dead_lettered',
                         next_attempt_at = NULL,
                         attempt_started_at = NULL,
                         lease_expires_at = NULL,
                         lease_token = NULL,
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
        Ok(())
    }

    async fn expire_retained_payload(
        &self,
        transaction: &Transaction<'_>,
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
        self.seams
            .record_audit(
                transaction,
                DeliveryAuditRecord {
                    event_id,
                    compiled_delivery_id: &compiled_delivery_id,
                    package_revision: &package_revision,
                    generation,
                    attempt,
                    phase: DeliveryAuditPhase::Terminal,
                    outcome: DeliveryAuditOutcome::PayloadExpired,
                    disposition: DeliveryAuditDisposition::Expired,
                },
            )
            .await?;
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
            // rule a local answer is read under.
            Ok(DestinationAnswer::Delivered { body }) => Ok(accepted_answer_result(&body)),
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
            Ok(answer) => Ok(accepted_answer_result(&answer)),
            Err(failure) => Ok(DeliveryAuditOutcome::handler_failure(failure.category).into()),
        }
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
        let AttemptResult { outcome, answer } = attempt;
        let mut client = self.seams.connection().await?;
        let transaction = client.transaction().await?;
        self.seams.verify_transaction(&transaction).await?;
        let (disposition, work_outcome) = if outcome == DeliveryAuditOutcome::Delivered {
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
        self.seams
            .record_audit(
                &transaction,
                DeliveryAuditRecord {
                    event_id: claim.event_id,
                    compiled_delivery_id: &claim.compiled_delivery_id,
                    package_revision: &claim.package_revision,
                    generation: claim.generation,
                    attempt: claim.attempt,
                    phase: DeliveryAuditPhase::Terminal,
                    outcome,
                    disposition,
                },
            )
            .await?;
        let changed = match work_outcome {
            DeliveryOutcome::Delivered => {
                self.update_terminal_state(&transaction, claim, "delivered", answer.as_ref())
                    .await?
            }
            DeliveryOutcome::DeadLettered => {
                self.update_terminal_state(&transaction, claim, "dead_lettered", None)
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
        transaction.commit().await?;
        Ok(work_outcome)
    }

    async fn update_terminal_state(
        &self,
        transaction: &Transaction<'_>,
        claim: &DeliveryClaim,
        state: &str,
        answer: Option<&AcceptedAnswer>,
    ) -> Result<u64, DeliveryError> {
        let timestamp_column = match state {
            "delivered" => "delivered_at",
            "dead_lettered" => "dead_lettered_at",
            _ => return Err(DeliveryError::Unavailable),
        };
        let message = answer.map(|answer| answer.bytes.clone());
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

/// What one attempt produced: its audited outcome and, when the handler
/// answered, the accepted message to record with it.
struct AttemptResult {
    outcome: DeliveryAuditOutcome,
    answer: Option<AcceptedAnswer>,
}

impl From<DeliveryAuditOutcome> for AttemptResult {
    fn from(outcome: DeliveryAuditOutcome) -> Self {
        Self {
            outcome,
            answer: None,
        }
    }
}

/// One accepted handler message and the digest of exactly the bytes
/// recorded for it.
#[derive(Debug)]
struct AcceptedAnswer {
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
    Ok(AcceptedAnswer { bytes, digest })
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
    use crate::delivery::{DeliveryConnection, DeliverySignatureRefused};

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
            _transaction: &Transaction<'_>,
            _record: DeliveryAuditRecord<'_>,
        ) -> Result<(), DeliveryError> {
            Err(DeliveryError::Unavailable)
        }

        fn operational_event(&self, event: DeliveryOperationalEvent) {
            self.events.lock().expect("events lock").push(event);
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
}
