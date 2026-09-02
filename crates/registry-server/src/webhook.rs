// SPDX-License-Identifier: Apache-2.0

//! Package-bound, at-least-once webhook delivery state machine.

use std::path::Path;
#[cfg(feature = "postgres-test")]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hmac::{Hmac, KeyInit, Mac};
use registry_platform_audit::AuditProfile;
use registry_platform_canonical_json::{canonicalize_json, parse_json_strict};
use registry_platform_httputil::destination::{DestinationSendError, EventDeliveryHeaders};
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use tokio::sync::watch;
use tokio::time::Instant;
use tokio_postgres::Transaction;
use uuid::Uuid;

use crate::audit::{
    append_webhook_audit, WebhookAudit, WebhookAuditDisposition, WebhookAuditOutcome,
    WebhookAuditPhase,
};
use crate::event_destination::ActivatedEventDestinationRegistry;
use crate::package::load_package;
use crate::postgres::{ExpectedRegistryIdentity, RegistryLockKey, RuntimePool};
use crate::runtime_config::load_runtime_config;
use crate::startup::{OperationalEvent, WebhookStateTransitionCode};

const LEASE_FINALIZATION_ALLOWANCE: Duration = Duration::from_secs(5);
const WORKER_POLL_INTERVAL: Duration = Duration::from_millis(100);
const SIGNATURE_DOMAIN: &[u8] = b"registry-server-webhook-signature-v1";
const IDEMPOTENCY_DOMAIN: &[u8] = b"registry-server-webhook-idempotency-v1";
pub const MAX_WEBHOOK_STATUS_RESULTS: u16 = 100;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WebhookDeliveryError {
    #[error("webhook delivery is unavailable")]
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WebhookOperatorError {
    #[error("webhook operator request is unavailable")]
    Unavailable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebhookDeliveryStatusKind {
    Pending,
    DeadLettered,
    Expired,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WebhookDeliveryStatus {
    pub event_id: Uuid,
    pub compiled_delivery_id: String,
    pub generation: i64,
    pub state: WebhookDeliveryStatusKind,
    pub attempt: i16,
    pub payload_available: bool,
    pub payload_expires_at: String,
}

/// Verified, product-owned operator boundary used by `registry-serverctl`.
///
/// Construction closes package, database identity, destination, and audit
/// bindings before list or replay is available. The CLI therefore owns no SQL,
/// retry transition, or signing behavior.
pub struct WebhookOperatorService {
    delivery: WebhookDeliveryService,
}

impl WebhookOperatorService {
    pub async fn from_runtime_config(path: &Path) -> Result<Self, WebhookOperatorError> {
        let config = load_runtime_config(path).map_err(|_| WebhookOperatorError::Unavailable)?;
        let package_root = config.package().root().to_path_buf();
        {
            let context = config.package_load_context();
            load_package(&package_root, &context).map_err(|_| WebhookOperatorError::Unavailable)?;
        }
        let connection = config
            .runtime_database_connection_config()
            .map_err(|_| WebhookOperatorError::Unavailable)?;
        let pool = connection
            .build_pool()
            .map_err(|_| WebhookOperatorError::Unavailable)?;
        let mut client = pool
            .get()
            .await
            .map_err(|_| WebhookOperatorError::Unavailable)?;
        let context = config.package_load_context();
        let startup = crate::startup::prepare_startup(
            &package_root,
            &context,
            &mut client,
            config.database().roles().migration(),
            config.database().roles().runtime(),
        )
        .await
        .map_err(|_| WebhookOperatorError::Unavailable)?;
        drop(client);
        let destinations = Arc::new(
            config
                .activate_event_destinations(startup.package().registry())
                .map_err(|_| WebhookOperatorError::Unavailable)?,
        );
        let audit_profile = config
            .audit_profile()
            .map_err(|_| WebhookOperatorError::Unavailable)?;
        let delivery = WebhookDeliveryService::new(
            pool,
            destinations,
            startup.expected_identity().clone(),
            startup.lock_key(),
            config.operational_timeouts().record_lock,
            audit_profile,
        );
        delivery
            .verify_retained_bindings()
            .await
            .map_err(|_| WebhookOperatorError::Unavailable)?;
        Ok(Self { delivery })
    }

    pub async fn list(
        &self,
        limit: u16,
    ) -> Result<Vec<WebhookDeliveryStatus>, WebhookOperatorError> {
        self.delivery
            .list(limit)
            .await
            .map_err(|_| WebhookOperatorError::Unavailable)
    }

    pub async fn replay(
        &self,
        event_id: Uuid,
        compiled_delivery_id: &str,
        expected_generation: i64,
    ) -> Result<i64, WebhookOperatorError> {
        self.delivery
            .replay(event_id, compiled_delivery_id, expected_generation)
            .await
            .map_err(|_| WebhookOperatorError::Unavailable)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WebhookWorkOutcome {
    Idle,
    Delivered,
    RetryScheduled,
    DeadLettered,
}

#[derive(Clone)]
pub struct WebhookDeliveryService {
    pool: RuntimePool,
    destinations: Arc<ActivatedEventDestinationRegistry>,
    expected: ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    lock_timeout: Duration,
    audit_profile: AuditProfile,
}

impl WebhookDeliveryService {
    #[must_use]
    pub fn new(
        pool: RuntimePool,
        destinations: Arc<ActivatedEventDestinationRegistry>,
        expected: ExpectedRegistryIdentity,
        lock_key: RegistryLockKey,
        lock_timeout: Duration,
        audit_profile: AuditProfile,
    ) -> Self {
        Self {
            pool,
            destinations,
            expected,
            lock_key,
            lock_timeout,
            audit_profile,
        }
    }

    /// Claim, audit, send, and finalize at most one due delivery.
    ///
    /// The pre-egress audit and lease commit before request rendering or
    /// destination policy execution. Delivery is therefore explicitly
    /// at-least-once when a process stops after network I/O and before CAS
    /// finalization.
    pub async fn deliver_once(&self) -> Result<WebhookWorkOutcome, WebhookDeliveryError> {
        let Some(claim) = self.claim().await? else {
            return Ok(WebhookWorkOutcome::Idle);
        };
        let outcome = self.reload_and_send(&claim).await?;
        self.finalize(&claim, outcome).await
    }

    /// Refuse startup or operator use if retained work cannot use its exact
    /// captured destination under the active deployment bindings.
    pub async fn verify_retained_bindings(&self) -> Result<(), WebhookDeliveryError> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        let transaction = client
            .transaction()
            .await
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        self.verify_transaction(&transaction).await?;
        let rows = transaction
            .query(
                "SELECT DISTINCT delivery.logical_destination_id,
                                 delivery.destination_binding_digest
                   FROM registry_internal.registry_webhook_delivery_state AS state
                   JOIN registry_internal.registry_webhook_deliveries AS delivery
                     ON delivery.event_id = state.event_id
                    AND delivery.compiled_delivery_id = state.compiled_delivery_id
                   JOIN registry_internal.registry_outbox AS outbox
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
                &[],
            )
            .await
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        for row in rows {
            let logical_id = bounded_text(&row, 0, 64)?;
            let binding_digest = bounded_text(&row, 1, 71)?;
            if self
                .destinations
                .lookup(&logical_id)
                .is_none_or(|destination| destination.binding_digest() != binding_digest)
            {
                return Err(WebhookDeliveryError::Unavailable);
            }
        }
        transaction
            .commit()
            .await
            .map_err(|_| WebhookDeliveryError::Unavailable)
    }

    /// Return bounded, value-free pending and terminal operator metadata.
    pub async fn list(
        &self,
        limit: u16,
    ) -> Result<Vec<WebhookDeliveryStatus>, WebhookDeliveryError> {
        if limit == 0 || limit > MAX_WEBHOOK_STATUS_RESULTS {
            return Err(WebhookDeliveryError::Unavailable);
        }
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        let transaction = client
            .transaction()
            .await
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        self.verify_transaction(&transaction).await?;
        let rows = transaction
            .query(
                "SELECT state.event_id, state.compiled_delivery_id,
                        state.generation, state.state, state.attempt,
                        outbox.payload IS NOT NULL
                            AND outbox.payload_expires_at > transaction_timestamp(),
                        outbox.payload_expires_at
                   FROM registry_internal.registry_webhook_delivery_state AS state
                   JOIN registry_internal.registry_outbox AS outbox
                     ON outbox.event_id = state.event_id
                  WHERE state.state IN ('pending', 'dead_lettered', 'expired')
                  ORDER BY state.updated_at DESC, state.event_id,
                           state.compiled_delivery_id
                  LIMIT $1",
                &[&i64::from(limit)],
            )
            .await
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        let mut statuses = Vec::with_capacity(rows.len());
        for row in rows {
            let event_id = row
                .try_get::<_, Uuid>(0)
                .map_err(|_| WebhookDeliveryError::Unavailable)?;
            let compiled_delivery_id = bounded_delivery_id(&row, 1)?;
            let generation = row
                .try_get::<_, i64>(2)
                .map_err(|_| WebhookDeliveryError::Unavailable)?;
            let stored_state = bounded_text(&row, 3, 32)?;
            let attempt = row
                .try_get::<_, i16>(4)
                .map_err(|_| WebhookDeliveryError::Unavailable)?;
            let payload_available = row
                .try_get::<_, bool>(5)
                .map_err(|_| WebhookDeliveryError::Unavailable)?;
            let payload_expires_at = row
                .try_get::<_, SystemTime>(6)
                .map_err(|_| WebhookDeliveryError::Unavailable)?;
            let state = match stored_state.as_str() {
                "pending" if payload_available => WebhookDeliveryStatusKind::Pending,
                "pending" | "expired" => WebhookDeliveryStatusKind::Expired,
                "dead_lettered" => WebhookDeliveryStatusKind::DeadLettered,
                _ => return Err(WebhookDeliveryError::Unavailable),
            };
            statuses.push(WebhookDeliveryStatus {
                event_id,
                compiled_delivery_id,
                generation,
                state,
                attempt,
                payload_available,
                payload_expires_at: OffsetDateTime::from(payload_expires_at)
                    .format(&Rfc3339)
                    .map_err(|_| WebhookDeliveryError::Unavailable)?,
            });
        }
        transaction
            .commit()
            .await
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
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
    ) -> Result<i64, WebhookDeliveryError> {
        if compiled_delivery_id.is_empty()
            || compiled_delivery_id.len() > 256
            || expected_generation <= 0
        {
            return Err(WebhookDeliveryError::Unavailable);
        }
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        let transaction = client
            .transaction()
            .await
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        self.verify_transaction(&transaction).await?;
        let row = transaction
            .query_opt(
                "SELECT state.generation, state.state, delivery.operator_replay,
                        delivery.package_revision, delivery.logical_destination_id,
                        delivery.destination_binding_digest
                 FROM registry_internal.registry_webhook_delivery_state AS state
                 JOIN registry_internal.registry_webhook_deliveries AS delivery
                   ON delivery.event_id = state.event_id
                  AND delivery.compiled_delivery_id = state.compiled_delivery_id
                 JOIN registry_internal.registry_outbox AS outbox
                   ON outbox.event_id = delivery.event_id
                 WHERE state.event_id = $1
                   AND state.compiled_delivery_id = $2
                   AND outbox.payload IS NOT NULL
                   AND outbox.payload_expires_at > transaction_timestamp()
                 FOR UPDATE OF state",
                &[&event_id, &compiled_delivery_id],
            )
            .await
            .map_err(|_| WebhookDeliveryError::Unavailable)?
            .ok_or(WebhookDeliveryError::Unavailable)?;
        let generation = row
            .try_get::<_, i64>(0)
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        let state = row
            .try_get::<_, String>(1)
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        let operator_replay = row
            .try_get::<_, bool>(2)
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        let package_revision = bounded_text(&row, 3, 256)?;
        let logical_destination_id = bounded_text(&row, 4, 64)?;
        let destination_binding_digest = bounded_text(&row, 5, 71)?;
        if generation != expected_generation
            || !operator_replay
            || state != "dead_lettered"
            || self
                .destinations
                .lookup(&logical_destination_id)
                .is_none_or(|destination| {
                    destination.binding_digest() != destination_binding_digest
                })
        {
            return Err(WebhookDeliveryError::Unavailable);
        }
        let next_generation = generation
            .checked_add(1)
            .ok_or(WebhookDeliveryError::Unavailable)?;
        append_webhook_audit(
            &transaction,
            &self.audit_profile,
            WebhookAudit {
                event_id,
                compiled_delivery_id,
                package_revision: &package_revision,
                generation: next_generation,
                attempt: 0,
                phase: WebhookAuditPhase::Replay,
                outcome: WebhookAuditOutcome::ReplayRequested,
                disposition: WebhookAuditDisposition::ReplayPending,
            },
        )
        .await
        .map_err(|_| WebhookDeliveryError::Unavailable)?;
        let changed = transaction
            .execute(
                "UPDATE registry_internal.registry_webhook_delivery_state
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
                &[
                    &event_id,
                    &compiled_delivery_id,
                    &generation,
                    &next_generation,
                ],
            )
            .await
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        if changed != 1 {
            return Err(WebhookDeliveryError::Unavailable);
        }
        transaction
            .commit()
            .await
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        Ok(next_generation)
    }

    async fn claim(&self) -> Result<Option<DeliveryClaim>, WebhookDeliveryError> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        let transaction = client
            .transaction()
            .await
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        if self.verify_transaction(&transaction).await.is_err() {
            webhook_failure(WebhookStateTransitionCode::ClaimIdentityRefused);
            return Err(WebhookDeliveryError::Unavailable);
        }
        if self.reap_expired_leases(&transaction).await.is_err() {
            webhook_failure(WebhookStateTransitionCode::ClaimRecoveryFailed);
            return Err(WebhookDeliveryError::Unavailable);
        }
        self.expire_retained_payload(&transaction).await?;
        let row = transaction
            .query_opt(
                "SELECT state.event_id, state.compiled_delivery_id,
                        state.generation, state.attempt,
                        delivery.deployed_attempt_timeout_ms,
                        delivery.deployed_maximum_attempts,
                        delivery.retry_delays_ms,
                        delivery.package_revision
                 FROM registry_internal.registry_webhook_delivery_state AS state
                 JOIN registry_internal.registry_webhook_deliveries AS delivery
                   ON delivery.event_id = state.event_id
                  AND delivery.compiled_delivery_id = state.compiled_delivery_id
                 JOIN registry_internal.registry_outbox AS outbox
                   ON outbox.event_id = delivery.event_id
                 WHERE state.state = 'pending'
                   AND state.next_attempt_at <= transaction_timestamp()
                   AND state.attempt < delivery.deployed_maximum_attempts
                   AND outbox.payload IS NOT NULL
                   AND outbox.payload_expires_at > transaction_timestamp()
                 ORDER BY state.next_attempt_at, state.event_id, state.compiled_delivery_id
                 FOR UPDATE OF state SKIP LOCKED
                 LIMIT 1",
                &[],
            )
            .await
            .map_err(|_| {
                webhook_failure(WebhookStateTransitionCode::ClaimSelectFailed);
                WebhookDeliveryError::Unavailable
            })?;
        let Some(row) = row else {
            transaction
                .commit()
                .await
                .map_err(|_| WebhookDeliveryError::Unavailable)?;
            return Ok(None);
        };
        let event_id = row
            .try_get::<_, Uuid>(0)
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        let compiled_delivery_id = bounded_delivery_id(&row, 1)?;
        let generation = row
            .try_get::<_, i64>(2)
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        let prior_attempt = row
            .try_get::<_, i16>(3)
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        let deployed_attempt_timeout_ms = row
            .try_get::<_, i64>(4)
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        let deployed_maximum_attempts = row
            .try_get::<_, i16>(5)
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        let retry_delays_ms = row
            .try_get::<_, Vec<i64>>(6)
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        let package_revision =
            bounded_text(&row, 7, 256).map_err(|_| WebhookDeliveryError::Unavailable)?;
        let attempt = prior_attempt
            .checked_add(1)
            .filter(|attempt| *attempt <= deployed_maximum_attempts)
            .ok_or(WebhookDeliveryError::Unavailable)?;
        if validate_captured_policy(
            deployed_attempt_timeout_ms,
            deployed_maximum_attempts,
            &retry_delays_ms,
        )
        .is_err()
        {
            webhook_failure(WebhookStateTransitionCode::ClaimPolicyRefused);
            return Err(WebhookDeliveryError::Unavailable);
        }
        let lease_token = Uuid::new_v4();
        let allowance_ms = i64::try_from(LEASE_FINALIZATION_ALLOWANCE.as_millis())
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        let changed = transaction
            .execute(
                "UPDATE registry_internal.registry_webhook_delivery_state
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
                webhook_failure(WebhookStateTransitionCode::ClaimUpdateFailed);
                WebhookDeliveryError::Unavailable
            })?;
        if changed != 1 {
            return Err(WebhookDeliveryError::Unavailable);
        }
        let attempt_started_at = transaction
            .query_one("SELECT transaction_timestamp()", &[])
            .await
            .map_err(|_| WebhookDeliveryError::Unavailable)?
            .try_get::<_, SystemTime>(0)
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        if append_webhook_audit(
            &transaction,
            &self.audit_profile,
            WebhookAudit {
                event_id,
                compiled_delivery_id: &compiled_delivery_id,
                package_revision: &package_revision,
                generation,
                attempt,
                phase: WebhookAuditPhase::Attempt,
                outcome: WebhookAuditOutcome::AttemptStarted,
                disposition: WebhookAuditDisposition::Leased,
            },
        )
        .await
        .is_err()
        {
            webhook_failure(WebhookStateTransitionCode::ClaimAuditFailed);
            return Err(WebhookDeliveryError::Unavailable);
        }
        transaction.commit().await.map_err(|_| {
            webhook_failure(WebhookStateTransitionCode::ClaimCommitFailed);
            WebhookDeliveryError::Unavailable
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
        }))
    }

    async fn reap_expired_leases(
        &self,
        transaction: &Transaction<'_>,
    ) -> Result<(), WebhookDeliveryError> {
        let row = transaction
            .query_opt(
                "SELECT state.event_id, state.compiled_delivery_id,
                        state.generation, state.attempt, state.lease_token,
                        delivery.deployed_attempt_timeout_ms,
                        delivery.deployed_maximum_attempts,
                        delivery.retry_delays_ms,
                        delivery.package_revision
                 FROM registry_internal.registry_webhook_delivery_state AS state
                 JOIN registry_internal.registry_webhook_deliveries AS delivery
                   ON delivery.event_id = state.event_id
                  AND delivery.compiled_delivery_id = state.compiled_delivery_id
                 WHERE state.state = 'leased'
                   AND state.lease_expires_at <= transaction_timestamp()
                 ORDER BY state.lease_expires_at, state.event_id, state.compiled_delivery_id
                 FOR UPDATE OF state SKIP LOCKED
                 LIMIT 1",
                &[],
            )
            .await
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        let Some(row) = row else {
            return Ok(());
        };
        let event_id = row
            .try_get::<_, Uuid>(0)
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        let compiled_delivery_id = bounded_delivery_id(&row, 1)?;
        let generation = row
            .try_get::<_, i64>(2)
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        let attempt = row
            .try_get::<_, i16>(3)
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        let lease_token = row
            .try_get::<_, Uuid>(4)
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        let deployed_attempt_timeout_ms = row
            .try_get::<_, i64>(5)
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        let deployed_maximum_attempts = row
            .try_get::<_, i16>(6)
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        let retry_delays_ms = row
            .try_get::<_, Vec<i64>>(7)
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        let package_revision = bounded_text(&row, 8, 256)?;
        validate_captured_policy(
            deployed_attempt_timeout_ms,
            deployed_maximum_attempts,
            &retry_delays_ms,
        )?;
        let dead_lettered = attempt >= deployed_maximum_attempts;
        append_webhook_audit(
            transaction,
            &self.audit_profile,
            WebhookAudit {
                event_id,
                compiled_delivery_id: &compiled_delivery_id,
                package_revision: &package_revision,
                generation,
                attempt,
                phase: WebhookAuditPhase::Terminal,
                outcome: WebhookAuditOutcome::WorkerInterrupted,
                disposition: if dead_lettered {
                    WebhookAuditDisposition::DeadLettered
                } else {
                    WebhookAuditDisposition::RetryPending
                },
            },
        )
        .await
        .map_err(|_| WebhookDeliveryError::Unavailable)?;
        let changed = if dead_lettered {
            transaction
                .execute(
                    "UPDATE registry_internal.registry_webhook_delivery_state
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
            let delay_index =
                usize::try_from(attempt - 1).map_err(|_| WebhookDeliveryError::Unavailable)?;
            let delay_ms = *retry_delays_ms
                .get(delay_index)
                .filter(|delay| **delay > 0)
                .ok_or(WebhookDeliveryError::Unavailable)?;
            transaction
                .execute(
                    "UPDATE registry_internal.registry_webhook_delivery_state
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
        }
        .map_err(|_| WebhookDeliveryError::Unavailable)?;
        if changed != 1 {
            return Err(WebhookDeliveryError::Unavailable);
        }
        Ok(())
    }

    async fn expire_retained_payload(
        &self,
        transaction: &Transaction<'_>,
    ) -> Result<(), WebhookDeliveryError> {
        let row = transaction
            .query_opt(
                "SELECT state.event_id, state.compiled_delivery_id,
                        state.generation, state.attempt, delivery.package_revision
                   FROM registry_internal.registry_webhook_delivery_state AS state
                   JOIN registry_internal.registry_webhook_deliveries AS delivery
                     ON delivery.event_id = state.event_id
                    AND delivery.compiled_delivery_id = state.compiled_delivery_id
                   JOIN registry_internal.registry_outbox AS outbox
                     ON outbox.event_id = delivery.event_id
                  WHERE state.state IN ('pending', 'dead_lettered')
                    AND outbox.payload IS NOT NULL
                    AND outbox.payload_expires_at <= transaction_timestamp()
                  ORDER BY outbox.payload_expires_at, state.event_id,
                           state.compiled_delivery_id
                  FOR UPDATE OF state, outbox SKIP LOCKED
                  LIMIT 1",
                &[],
            )
            .await
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        let Some(row) = row else {
            return Ok(());
        };
        let event_id = row
            .try_get::<_, Uuid>(0)
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        let compiled_delivery_id = bounded_delivery_id(&row, 1)?;
        let generation = row
            .try_get::<_, i64>(2)
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        let attempt = row
            .try_get::<_, i16>(3)
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        let package_revision = bounded_text(&row, 4, 256)?;
        append_webhook_audit(
            transaction,
            &self.audit_profile,
            WebhookAudit {
                event_id,
                compiled_delivery_id: &compiled_delivery_id,
                package_revision: &package_revision,
                generation,
                attempt,
                phase: WebhookAuditPhase::Terminal,
                outcome: WebhookAuditOutcome::PayloadExpired,
                disposition: WebhookAuditDisposition::Expired,
            },
        )
        .await
        .map_err(|_| WebhookDeliveryError::Unavailable)?;
        let state_changed = transaction
            .execute(
                "UPDATE registry_internal.registry_webhook_delivery_state
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
                &[&event_id, &compiled_delivery_id, &generation],
            )
            .await
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        let payload_changed = transaction
            .execute(
                "UPDATE registry_internal.registry_outbox
                    SET payload = NULL
                  WHERE event_id = $1
                    AND payload IS NOT NULL
                    AND payload_expires_at <= transaction_timestamp()",
                &[&event_id],
            )
            .await
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        if state_changed != 1 || payload_changed != 1 {
            return Err(WebhookDeliveryError::Unavailable);
        }
        Ok(())
    }

    async fn reload_and_send(
        &self,
        claim: &DeliveryClaim,
    ) -> Result<WebhookAuditOutcome, WebhookDeliveryError> {
        let material = match self.reload_material(claim).await {
            Ok(material) => material,
            Err(MaterialLoadError::Unavailable) => return Err(WebhookDeliveryError::Unavailable),
            Err(MaterialLoadError::PayloadRefused) => {
                return Ok(WebhookAuditOutcome::PayloadRefused)
            }
            Err(MaterialLoadError::BindingRefused) => {
                return Ok(WebhookAuditOutcome::DestinationBindingRefused)
            }
        };
        let Some(destination) = self.destinations.lookup(&material.logical_destination_id) else {
            return Ok(WebhookAuditOutcome::DestinationBindingRefused);
        };
        let deployed_timeout_ms = i64::try_from(destination.attempt_timeout().as_millis())
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        if destination.binding_digest() != material.destination_binding_digest
            || deployed_timeout_ms != material.deployed_attempt_timeout_ms
            || i16::from(destination.maximum_attempts()) != material.deployed_maximum_attempts
        {
            return Ok(WebhookAuditOutcome::DestinationBindingRefused);
        }
        let delivery_time = OffsetDateTime::from(claim.attempt_started_at)
            .format(&Rfc3339)
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        let event_time = OffsetDateTime::from(material.event_time)
            .format(&Rfc3339)
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        let event_id = claim.event_id.to_string();
        let source = format!(
            "urn:registrystack:registry:{}:instance:{}",
            self.expected.package_id, self.expected.instance_id
        );
        let generation = claim.generation.to_string();
        let attempt = claim.attempt.to_string();
        let idempotency_key = webhook_idempotency_key(
            claim.event_id,
            &claim.compiled_delivery_id,
            claim.generation,
            &material.payload_digest,
            &material.destination_binding_digest,
        );
        let signature = destination.with_hmac_sha256_key(|key| {
            webhook_signature(
                key,
                SignatureFields {
                    id: &event_id,
                    source: &source,
                    event_type: &material.event_type,
                    time: &event_time,
                    data_schema: &material.data_schema,
                    generation: &generation,
                    attempt: &attempt,
                    delivery_time: &delivery_time,
                    method: "POST",
                    request_target: destination.request_target(),
                    content_type: "application/json",
                    idempotency_key: &idempotency_key,
                    body: &material.body,
                },
            )
        });
        let Ok(signature) = signature else {
            return Ok(WebhookAuditOutcome::DestinationPolicyRefused);
        };
        let request = match destination.request_template().render_event(
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
            Err(_) => return Ok(WebhookAuditOutcome::DestinationPolicyRefused),
        };
        let attempt_timeout = Duration::from_millis(
            u64::try_from(material.deployed_attempt_timeout_ms)
                .map_err(|_| WebhookDeliveryError::Unavailable)?,
        );
        let elapsed = SystemTime::now()
            .duration_since(claim.attempt_started_at)
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        let Some(remaining) = attempt_timeout.checked_sub(elapsed) else {
            return Ok(WebhookAuditOutcome::DestinationTimeout);
        };
        if remaining.is_zero() {
            return Ok(WebhookAuditOutcome::DestinationTimeout);
        }
        let monotonic_deadline = Instant::now() + remaining;
        match destination.policy().send(request, remaining).await {
            Ok(response) if response.status().is_success() => Ok(WebhookAuditOutcome::Delivered),
            Ok(_) => Ok(WebhookAuditOutcome::HttpNonSuccess),
            Err(error) => Ok(classify_send_error(
                error,
                monotonic_deadline.saturating_duration_since(Instant::now())
                    <= Duration::from_millis(1),
            )),
        }
    }

    async fn reload_material(
        &self,
        claim: &DeliveryClaim,
    ) -> Result<DeliveryMaterial, MaterialLoadError> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| MaterialLoadError::Unavailable)?;
        let transaction = client
            .transaction()
            .await
            .map_err(|_| MaterialLoadError::Unavailable)?;
        self.verify_transaction(&transaction)
            .await
            .map_err(|_| MaterialLoadError::Unavailable)?;
        let row = transaction
            .query_opt(
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
                 FROM registry_internal.registry_webhook_delivery_state AS state
                 JOIN registry_internal.registry_webhook_deliveries AS delivery
                   ON delivery.event_id = state.event_id
                  AND delivery.compiled_delivery_id = state.compiled_delivery_id
                 JOIN registry_internal.registry_outbox AS outbox
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
        let logical_destination_id =
            bounded_text(&row, 5, 64).map_err(|_| MaterialLoadError::PayloadRefused)?;
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
        let digest = Sha256::digest(&body);
        let parsed = parse_json_strict(&body).map_err(|_| MaterialLoadError::PayloadRefused)?;
        let canonical =
            canonicalize_json(&parsed).map_err(|_| MaterialLoadError::PayloadRefused)?;
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
        if body.is_empty()
            || i64::try_from(body.len()).ok() > Some(maximum_payload_bytes)
            || payload_digest.len() != 32
            || payload_digest.as_slice() != digest.as_slice()
            || canonical != body
            || !parsed.is_object()
        {
            return Err(MaterialLoadError::PayloadRefused);
        }
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
        outcome: WebhookAuditOutcome,
    ) -> Result<WebhookWorkOutcome, WebhookDeliveryError> {
        let mut client = self
            .pool
            .get()
            .await
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        let transaction = client
            .transaction()
            .await
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        self.verify_transaction(&transaction).await?;
        let (disposition, work_outcome) = if outcome == WebhookAuditOutcome::Delivered {
            (
                WebhookAuditDisposition::Delivered,
                WebhookWorkOutcome::Delivered,
            )
        } else if claim.attempt >= claim.deployed_maximum_attempts {
            (
                WebhookAuditDisposition::DeadLettered,
                WebhookWorkOutcome::DeadLettered,
            )
        } else {
            (
                WebhookAuditDisposition::RetryPending,
                WebhookWorkOutcome::RetryScheduled,
            )
        };
        append_webhook_audit(
            &transaction,
            &self.audit_profile,
            WebhookAudit {
                event_id: claim.event_id,
                compiled_delivery_id: &claim.compiled_delivery_id,
                package_revision: &claim.package_revision,
                generation: claim.generation,
                attempt: claim.attempt,
                phase: WebhookAuditPhase::Terminal,
                outcome,
                disposition,
            },
        )
        .await
        .map_err(|_| WebhookDeliveryError::Unavailable)?;
        let changed = match work_outcome {
            WebhookWorkOutcome::Delivered => {
                self.update_terminal_state(&transaction, claim, "delivered")
                    .await?
            }
            WebhookWorkOutcome::DeadLettered => {
                self.update_terminal_state(&transaction, claim, "dead_lettered")
                    .await?
            }
            WebhookWorkOutcome::RetryScheduled => {
                let delay_index = usize::try_from(claim.attempt - 1)
                    .map_err(|_| WebhookDeliveryError::Unavailable)?;
                let delay_ms = *claim
                    .retry_delays_ms
                    .get(delay_index)
                    .filter(|delay| **delay > 0)
                    .ok_or(WebhookDeliveryError::Unavailable)?;
                transaction
                    .execute(
                        "UPDATE registry_internal.registry_webhook_delivery_state
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
                        &[
                            &claim.event_id,
                            &claim.compiled_delivery_id,
                            &claim.generation,
                            &claim.attempt,
                            &claim.lease_token,
                            &delay_ms,
                        ],
                    )
                    .await
                    .map_err(|_| WebhookDeliveryError::Unavailable)?
            }
            WebhookWorkOutcome::Idle => return Err(WebhookDeliveryError::Unavailable),
        };
        if changed != 1 {
            return Err(WebhookDeliveryError::Unavailable);
        }
        if work_outcome == WebhookWorkOutcome::Delivered {
            let erased = transaction
                .execute(
                    "UPDATE registry_internal.registry_outbox
                        SET payload = NULL
                      WHERE event_id = $1 AND payload IS NOT NULL",
                    &[&claim.event_id],
                )
                .await
                .map_err(|_| WebhookDeliveryError::Unavailable)?;
            if erased != 1 {
                return Err(WebhookDeliveryError::Unavailable);
            }
        }
        transaction
            .commit()
            .await
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        Ok(work_outcome)
    }

    async fn update_terminal_state(
        &self,
        transaction: &Transaction<'_>,
        claim: &DeliveryClaim,
        state: &str,
    ) -> Result<u64, WebhookDeliveryError> {
        let timestamp_column = match state {
            "delivered" => "delivered_at",
            "dead_lettered" => "dead_lettered_at",
            _ => return Err(WebhookDeliveryError::Unavailable),
        };
        transaction
            .execute(
                &format!(
                    "UPDATE registry_internal.registry_webhook_delivery_state
                     SET state = '{state}',
                         next_attempt_at = NULL,
                         attempt_started_at = NULL,
                         lease_expires_at = NULL,
                         lease_token = NULL,
                         {timestamp_column} = transaction_timestamp(),
                         updated_at = transaction_timestamp()
                     WHERE event_id = $1
                       AND compiled_delivery_id = $2
                       AND generation = $3
                       AND attempt = $4
                       AND lease_token = $5
                       AND state = 'leased'"
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
            .map_err(|_| WebhookDeliveryError::Unavailable)
    }

    async fn verify_transaction(
        &self,
        transaction: &Transaction<'_>,
    ) -> Result<(), WebhookDeliveryError> {
        if self.lock_timeout.is_zero() || self.lock_timeout > Duration::from_secs(30) {
            return Err(WebhookDeliveryError::Unavailable);
        }
        let timeout_millis = i32::try_from(self.lock_timeout.as_millis())
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        transaction
            .execute(
                "SELECT set_config('lock_timeout', $1::text, true)",
                &[&format!("{timeout_millis}ms")],
            )
            .await
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        transaction
            .execute(
                "SELECT pg_advisory_xact_lock_shared($1)",
                &[&self.lock_key.get()],
            )
            .await
            .map_err(|_| WebhookDeliveryError::Unavailable)?;
        let state = transaction
            .query_opt(
                "SELECT package_id, environment, instance_id, database_id,
                        active_package_revision, schema_fingerprint, package_sequence,
                        maintenance_status
                 FROM registry_internal.registry_state
                 WHERE singleton",
                &[],
            )
            .await
            .map_err(|_| WebhookDeliveryError::Unavailable)?
            .ok_or(WebhookDeliveryError::Unavailable)?;
        let ready = state.try_get::<_, String>(7).ok().as_deref() == Some("ready")
            && state.try_get::<_, String>(0).ok().as_deref()
                == Some(self.expected.package_id.as_str())
            && state.try_get::<_, String>(1).ok().as_deref()
                == Some(self.expected.environment.as_str())
            && state.try_get::<_, String>(2).ok().as_deref()
                == Some(self.expected.instance_id.as_str())
            && state.try_get::<_, String>(3).ok().as_deref()
                == Some(self.expected.database_id.as_str())
            && state.try_get::<_, String>(4).ok().as_deref()
                == Some(self.expected.package_revision.as_str())
            && state.try_get::<_, String>(5).ok().as_deref()
                == Some(self.expected.schema_fingerprint.as_str())
            && state.try_get::<_, i64>(6).ok() == Some(self.expected.package_sequence);
        if !ready {
            return Err(WebhookDeliveryError::Unavailable);
        }
        Ok(())
    }
}

#[derive(Clone)]
pub struct WebhookWorker {
    kind: WebhookWorkerKind,
}

impl WebhookWorker {
    #[must_use]
    pub fn new(service: WebhookDeliveryService) -> Self {
        Self {
            kind: WebhookWorkerKind::Delivery(Box::new(service)),
        }
    }

    pub async fn run(self, mut shutdown: watch::Receiver<bool>) {
        #[cfg(not(feature = "postgres-test"))]
        let WebhookWorkerKind::Delivery(service) = self.kind;
        #[cfg(feature = "postgres-test")]
        let service = match self.kind {
            WebhookWorkerKind::Delivery(service) => service,
            WebhookWorkerKind::LifecycleProbe(probe) => {
                probe.run(shutdown).await;
                return;
            }
        };
        loop {
            if *shutdown.borrow() {
                return;
            }
            if service.deliver_once().await.is_err() {
                OperationalEvent::WebhookWorkerIterationFailed.emit();
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

#[derive(Clone)]
enum WebhookWorkerKind {
    Delivery(Box<WebhookDeliveryService>),
    #[cfg(feature = "postgres-test")]
    LifecycleProbe(WebhookWorkerLifecycleProbe),
}

/// Test-only observation point for proving startup task ownership.
#[cfg(feature = "postgres-test")]
#[doc(hidden)]
#[derive(Clone)]
pub struct WebhookWorkerLifecycleProbe {
    state: Arc<WebhookWorkerLifecycleState>,
    hang: bool,
}

#[cfg(feature = "postgres-test")]
struct WebhookWorkerLifecycleState {
    started: AtomicBool,
    running: AtomicBool,
    stopped: AtomicBool,
}

#[cfg(feature = "postgres-test")]
impl WebhookWorkerLifecycleProbe {
    #[must_use]
    pub fn new(hang: bool) -> Self {
        Self {
            state: Arc::new(WebhookWorkerLifecycleState {
                started: AtomicBool::new(false),
                running: AtomicBool::new(false),
                stopped: AtomicBool::new(false),
            }),
            hang,
        }
    }

    #[must_use]
    pub fn worker(&self) -> WebhookWorker {
        WebhookWorker {
            kind: WebhookWorkerKind::LifecycleProbe(self.clone()),
        }
    }

    #[must_use]
    pub fn started(&self) -> bool {
        self.state.started.load(Ordering::SeqCst)
    }

    #[must_use]
    pub fn running(&self) -> bool {
        self.state.running.load(Ordering::SeqCst)
    }

    #[must_use]
    pub fn stopped(&self) -> bool {
        self.state.stopped.load(Ordering::SeqCst)
    }

    async fn run(self, mut shutdown: watch::Receiver<bool>) {
        self.state.started.store(true, Ordering::SeqCst);
        self.state.running.store(true, Ordering::SeqCst);
        let _guard = WebhookWorkerLifecycleGuard(Arc::clone(&self.state));
        if self.hang {
            std::future::pending::<()>().await;
        }
        while !*shutdown.borrow() {
            if shutdown.changed().await.is_err() {
                return;
            }
        }
    }
}

#[cfg(feature = "postgres-test")]
struct WebhookWorkerLifecycleGuard(Arc<WebhookWorkerLifecycleState>);

#[cfg(feature = "postgres-test")]
impl Drop for WebhookWorkerLifecycleGuard {
    fn drop(&mut self) {
        self.0.running.store(false, Ordering::SeqCst);
        self.0.stopped.store(true, Ordering::SeqCst);
    }
}

fn webhook_failure(code: WebhookStateTransitionCode) {
    OperationalEvent::WebhookStateTransitionFailed(code).emit();
}

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
}

struct DeliveryMaterial {
    event_type: String,
    body: Vec<u8>,
    payload_digest: Vec<u8>,
    destination_binding_digest: String,
    logical_destination_id: String,
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

fn classify_send_error(error: DestinationSendError, deadline_reached: bool) -> WebhookAuditOutcome {
    match error {
        DestinationSendError::DeadlineExceeded => WebhookAuditOutcome::DestinationTimeout,
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
            WebhookAuditOutcome::DestinationResolutionRefused
        }
        DestinationSendError::ResolutionCapacityUnavailable
        | DestinationSendError::TlsMaterialUnavailable
        | DestinationSendError::ClientBuildFailed
        | DestinationSendError::TooManyResponseHeaders
        | DestinationSendError::ResponseHeaderBytesExceeded => {
            WebhookAuditOutcome::DestinationTransportUnavailable
        }
        DestinationSendError::TransportFailed if deadline_reached => {
            WebhookAuditOutcome::DestinationTimeout
        }
        DestinationSendError::TransportFailed => {
            WebhookAuditOutcome::DestinationTransportUnavailable
        }
        DestinationSendError::InvalidRemainingTimeout
        | DestinationSendError::InvalidFrozenPolicy
        | DestinationSendError::InvalidFrozenRequest => {
            WebhookAuditOutcome::DestinationPolicyRefused
        }
    }
}

fn bounded_delivery_id(
    row: &tokio_postgres::Row,
    index: usize,
) -> Result<String, WebhookDeliveryError> {
    bounded_text(row, index, 256)
}

fn bounded_text(
    row: &tokio_postgres::Row,
    index: usize,
    maximum: usize,
) -> Result<String, WebhookDeliveryError> {
    let value = row
        .try_get::<_, String>(index)
        .map_err(|_| WebhookDeliveryError::Unavailable)?;
    if value.is_empty() || value.len() > maximum {
        return Err(WebhookDeliveryError::Unavailable);
    }
    Ok(value)
}

fn validate_captured_policy(
    deployed_attempt_timeout_ms: i64,
    deployed_maximum_attempts: i16,
    retry_delays_ms: &[i64],
) -> Result<(), WebhookDeliveryError> {
    let expected_delays = usize::try_from(deployed_maximum_attempts.saturating_sub(1))
        .map_err(|_| WebhookDeliveryError::Unavailable)?;
    if !(100..=10_000).contains(&deployed_attempt_timeout_ms)
        || !(1..=20).contains(&deployed_maximum_attempts)
        || retry_delays_ms.len() < expected_delays
        || retry_delays_ms
            .iter()
            .any(|delay| !(100..=3_600_000).contains(delay))
    {
        return Err(WebhookDeliveryError::Unavailable);
    }
    Ok(())
}

fn webhook_idempotency_key(
    event_id: Uuid,
    compiled_delivery_id: &str,
    generation: i64,
    payload_digest: &[u8],
    destination_binding_digest: &str,
) -> String {
    let mut input = Vec::new();
    input.extend_from_slice(IDEMPOTENCY_DOMAIN);
    append_length_prefixed(&mut input, event_id.to_string().as_bytes());
    append_length_prefixed(&mut input, compiled_delivery_id.as_bytes());
    append_length_prefixed(&mut input, generation.to_string().as_bytes());
    append_length_prefixed(&mut input, payload_digest);
    append_length_prefixed(&mut input, destination_binding_digest.as_bytes());
    format!("sha256:{}", hex::encode(Sha256::digest(input)))
}

#[derive(Clone, Copy)]
struct SignatureFields<'a> {
    id: &'a str,
    source: &'a str,
    event_type: &'a str,
    time: &'a str,
    data_schema: &'a str,
    generation: &'a str,
    attempt: &'a str,
    delivery_time: &'a str,
    method: &'a str,
    request_target: &'a str,
    content_type: &'a str,
    idempotency_key: &'a str,
    body: &'a [u8],
}

fn webhook_signature(
    key: &[u8],
    fields: SignatureFields<'_>,
) -> Result<String, WebhookDeliveryError> {
    let mut input = Vec::new();
    input.extend_from_slice(SIGNATURE_DOMAIN);
    for value in [
        b"1.0".as_slice(),
        fields.id.as_bytes(),
        fields.source.as_bytes(),
        fields.event_type.as_bytes(),
        fields.time.as_bytes(),
        fields.data_schema.as_bytes(),
        fields.generation.as_bytes(),
        fields.attempt.as_bytes(),
        fields.delivery_time.as_bytes(),
        fields.method.as_bytes(),
        fields.request_target.as_bytes(),
        fields.content_type.as_bytes(),
        fields.idempotency_key.as_bytes(),
        fields.body,
    ] {
        append_length_prefixed(&mut input, value);
    }
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| WebhookDeliveryError::Unavailable)?;
    mac.update(&input);
    Ok(format!(
        "v1={}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    ))
}

fn append_length_prefixed(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_sha256_v1_binds_every_header_and_exact_canonical_body() {
        let key = [0x5a; 32];
        let fields = SignatureFields {
            id: "00000000-0000-4000-8000-000000000001",
            source: "urn:registrystack:registry:example:instance:primary",
            event_type: "case-created-v1",
            time: "2026-08-30T00:00:00Z",
            data_schema:
                "urn:registrystack:registry:example:event:case-created-v1:schema:sha256:aaa",
            generation: "1",
            attempt: "1",
            delivery_time: "2026-08-30T00:00:01Z",
            method: "POST",
            request_target: "/hooks/registry",
            content_type: "application/json",
            idempotency_key:
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            body: br#"{"entity":"case","values":{"label":"value"}}"#,
        };
        let baseline = webhook_signature(&key, fields).expect("bounded signature computes");
        macro_rules! assert_field_is_bound {
            ($member:ident, $changed:expr) => {{
                let mut changed = fields;
                changed.$member = $changed;
                assert_ne!(
                    baseline,
                    webhook_signature(&key, changed).expect("changed signature computes")
                );
            }};
        }
        assert_field_is_bound!(id, "00000000-0000-4000-8000-000000000002");
        assert_field_is_bound!(source, "urn:registrystack:registry:other:instance:primary");
        assert_field_is_bound!(event_type, "case-patched-v1");
        assert_field_is_bound!(time, "2026-08-30T00:00:02Z");
        assert_field_is_bound!(data_schema, "urn:registrystack:schema:changed");
        assert_field_is_bound!(generation, "2");
        assert_field_is_bound!(attempt, "2");
        assert_field_is_bound!(delivery_time, "2026-08-30T00:00:03Z");
        assert_field_is_bound!(method, "PUT");
        assert_field_is_bound!(request_target, "/hooks/other");
        assert_field_is_bound!(content_type, "application/cloudevents+json");
        assert_field_is_bound!(
            idempotency_key,
            "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
        );
        assert_field_is_bound!(body, br#"{"entity":"case","values":{"label":"changed"}}"#);
        assert_ne!(
            baseline,
            webhook_signature(&[0x6b; 32], fields).expect("changed key computes")
        );
        assert!(baseline.starts_with("v1="));
        assert!(!baseline[3..].contains('='));
    }

    #[test]
    fn idempotency_key_is_stable_across_retries_and_changes_on_replay_generation() {
        let event_id =
            Uuid::parse_str("00000000-0000-4000-8000-000000000001").expect("fixture UUID parses");
        let digest = Sha256::digest(br#"{"label":"value"}"#);
        let first_key = webhook_idempotency_key(
            event_id,
            "events.case.created.webhook",
            1,
            digest.as_slice(),
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        let repeated_key = webhook_idempotency_key(
            event_id,
            "events.case.created.webhook",
            1,
            digest.as_slice(),
            "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        );
        let replay_key = webhook_idempotency_key(
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
    fn transport_failure_is_separate_from_a_reached_attempt_deadline() {
        assert_eq!(
            classify_send_error(DestinationSendError::TransportFailed, false),
            WebhookAuditOutcome::DestinationTransportUnavailable
        );
        assert_eq!(
            classify_send_error(DestinationSendError::TransportFailed, true),
            WebhookAuditOutcome::DestinationTimeout
        );
        assert_eq!(
            classify_send_error(DestinationSendError::DeadlineExceeded, false),
            WebhookAuditOutcome::DestinationTimeout
        );
    }
}
