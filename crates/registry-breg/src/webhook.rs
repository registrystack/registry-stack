// SPDX-License-Identifier: Apache-2.0

//! Base Registry Engine's adoption of the platform delivery core.
//!
//! The at-least-once delivery worker lives in `registry-platform-hooks`
//! behind the delivery seams. This module supplies those seams with Base
//! Registry Engine's side: the runtime pool, the deployment-identity
//! preflight, the webhook audit journal, the operational vocabulary, and the
//! activated destinations. The worker's claim, lease, retry, dead-letter,
//! expiry, and operator behavior moved with this adoption, and the signed
//! bytes on the wire are unchanged: the same signing scheme signs the same
//! field values with the same key material, and the idempotency domain and
//! delivery source identity are passed through unchanged.
//!
//! The public surface is re-exported under the names `bregctl` and the
//! PostgreSQL integration tests already use.

use std::ops::{Deref, DerefMut};
use std::path::Path;
#[cfg(feature = "postgres-test")]
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use registry_platform_audit::AuditProfile;
use registry_platform_crypto::breg_webhook::{sign_v1, SignatureFields};
use registry_platform_hooks::delivery::{
    DeliveryAuditDisposition, DeliveryAuditOutcome, DeliveryAuditPhase, DeliveryAuditRecord,
    DeliveryConfig, DeliveryConnection, DeliveryError, DeliveryOperationalEvent, DeliverySeams,
    DeliveryService, DeliverySignatureFields, DeliverySignatureRefused, DeliveryTransitionCode,
    DeliveryWorker, DestinationAnswer, HookDestination,
};
use registry_platform_httputil::destination::{
    DestinationRequestError, DestinationSendError, EventDeliveryHeaders, EventDestinationRequest,
};
use tokio::sync::watch;
use tokio_postgres::Transaction;
use uuid::Uuid;

use crate::audit::{
    append_webhook_audit, WebhookAudit, WebhookAuditDisposition, WebhookAuditOutcome,
    WebhookAuditPhase,
};
use crate::event_destination::{ActivatedEventDestination, ActivatedEventDestinationRegistry};
use crate::package::load_package;
use crate::postgres::{ExpectedRegistryIdentity, RegistryLockKey, RuntimePool};
use crate::runtime_config::load_runtime_config;
use crate::startup::{OperationalEvent, WebhookStateTransitionCode};

pub use registry_platform_hooks::delivery::{
    DeliveryError as WebhookDeliveryError, DeliveryOutcome as WebhookWorkOutcome,
    DeliveryStatus as WebhookDeliveryStatus, DeliveryStatusKind as WebhookDeliveryStatusKind,
    MAX_DELIVERY_STATUS_RESULTS as MAX_WEBHOOK_STATUS_RESULTS,
};

const IDEMPOTENCY_DOMAIN: &[u8] = b"breg-webhook-idempotency-v1";
/// The schema Base Registry Engine installs the platform delivery tables
/// into, and the one the worker and the capture INSERT read and write.
pub(crate) const DELIVERY_SCHEMA: &str = "registry_internal";
const _: () = assert!(
    crate::compiler::MAX_WEBHOOK_PAYLOAD_BYTES as usize
        == registry_platform_crypto::breg_webhook::MAX_BODY_BYTES
);

#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum WebhookOperatorError {
    #[error("webhook operator request is unavailable")]
    Unavailable,
}

/// Verified, product-owned operator boundary used by `bregctl`.
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

/// Base Registry Engine's seams under the platform delivery worker: the
/// runtime pool, the deployment-identity preflight, the webhook audit
/// journal, the operational vocabulary, and the activated destinations.
#[derive(Clone)]
struct BregDeliverySeams {
    pool: RuntimePool,
    destinations: Arc<ActivatedEventDestinationRegistry>,
    expected: ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    lock_timeout: Duration,
    audit_profile: AuditProfile,
}

#[async_trait::async_trait]
impl DeliverySeams for BregDeliverySeams {
    type Destination = DestinationBinding;

    async fn connection(&self) -> Result<DeliveryConnection, DeliveryError> {
        let client = self
            .pool
            .get()
            .await
            .map_err(|_| DeliveryError::Unavailable)?;
        Ok(Box::new(PooledClient(client)))
    }

    async fn verify_transaction(&self, transaction: &Transaction<'_>) -> Result<(), DeliveryError> {
        if self.lock_timeout.is_zero() || self.lock_timeout > Duration::from_secs(30) {
            return Err(DeliveryError::Unavailable);
        }
        let timeout_millis =
            i32::try_from(self.lock_timeout.as_millis()).map_err(|_| DeliveryError::Unavailable)?;
        transaction
            .execute(
                "SELECT set_config('lock_timeout', $1::text, true)",
                &[&format!("{timeout_millis}ms")],
            )
            .await
            .map_err(|_| DeliveryError::Unavailable)?;
        transaction
            .execute(
                "SELECT pg_advisory_xact_lock_shared($1)",
                &[&self.lock_key.get()],
            )
            .await
            .map_err(|_| DeliveryError::Unavailable)?;
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
            .map_err(|_| DeliveryError::Unavailable)?
            .ok_or(DeliveryError::Unavailable)?;
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
            return Err(DeliveryError::Unavailable);
        }
        Ok(())
    }

    fn destination(&self, logical_destination_id: &str) -> Option<Self::Destination> {
        self.destinations
            .lookup_shared(logical_destination_id)
            .map(DestinationBinding)
    }

    async fn record_audit(
        &self,
        transaction: &Transaction<'_>,
        record: DeliveryAuditRecord<'_>,
    ) -> Result<(), DeliveryError> {
        append_webhook_audit(
            transaction,
            &self.audit_profile,
            WebhookAudit {
                event_id: record.event_id,
                compiled_delivery_id: record.compiled_delivery_id,
                package_revision: record.package_revision,
                generation: record.generation,
                attempt: record.attempt,
                phase: audit_phase(record.phase),
                outcome: audit_outcome(record.outcome),
                disposition: audit_disposition(record.disposition),
            },
        )
        .await
        .map_err(|_| DeliveryError::Unavailable)
    }

    fn operational_event(&self, event: DeliveryOperationalEvent) {
        match event {
            DeliveryOperationalEvent::IterationFailed => {
                OperationalEvent::WebhookWorkerIterationFailed.emit();
            }
            DeliveryOperationalEvent::TransitionFailed(code) => {
                OperationalEvent::WebhookStateTransitionFailed(transition_code(code)).emit();
            }
        }
    }
}

/// One pooled runtime client framed for the delivery worker's connection
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

/// One activated delivery destination, handed to the worker as the neutral
/// destination seam.
#[derive(Clone)]
struct DestinationBinding(Arc<ActivatedEventDestination>);

#[async_trait::async_trait]
impl HookDestination for DestinationBinding {
    fn binding_digest(&self) -> &str {
        self.0.binding_digest()
    }

    fn attempt_timeout(&self) -> Duration {
        self.0.attempt_timeout()
    }

    fn maximum_attempts(&self) -> u8 {
        self.0.maximum_attempts()
    }

    fn sign_delivery(
        &self,
        fields: DeliverySignatureFields<'_>,
    ) -> Result<String, DeliverySignatureRefused> {
        let DeliverySignatureFields {
            id,
            source,
            event_type,
            time,
            data_schema,
            generation,
            attempt,
            delivery_time,
            idempotency_key,
            body,
        } = fields;
        self.0
            .with_hmac_sha256_key(|key| {
                sign_v1(
                    key,
                    SignatureFields {
                        id,
                        source,
                        event_type,
                        time,
                        data_schema,
                        generation,
                        attempt,
                        delivery_time,
                        method: "POST",
                        request_target: self.0.request_target(),
                        content_type: "application/json",
                        idempotency_key,
                        body,
                    },
                )
            })
            .map_err(|_| DeliverySignatureRefused)
    }

    fn render_delivery(
        &self,
        headers: EventDeliveryHeaders<'_>,
        body: Vec<u8>,
    ) -> Result<EventDestinationRequest, DestinationRequestError> {
        self.0.request_template().render_event(headers, body)
    }

    async fn send_delivery(
        &self,
        request: EventDestinationRequest,
        remaining: Duration,
    ) -> Result<DestinationAnswer, DestinationSendError> {
        let response = self.0.policy().send(request, remaining).await?;
        if response.status().is_success() {
            Ok(DestinationAnswer::Delivered)
        } else {
            Ok(DestinationAnswer::NonSuccess)
        }
    }
}

fn audit_phase(phase: DeliveryAuditPhase) -> WebhookAuditPhase {
    match phase {
        DeliveryAuditPhase::Attempt => WebhookAuditPhase::Attempt,
        DeliveryAuditPhase::Terminal => WebhookAuditPhase::Terminal,
        DeliveryAuditPhase::Replay => WebhookAuditPhase::Replay,
    }
}

fn audit_outcome(outcome: DeliveryAuditOutcome) -> WebhookAuditOutcome {
    match outcome {
        DeliveryAuditOutcome::AttemptStarted => WebhookAuditOutcome::AttemptStarted,
        DeliveryAuditOutcome::Delivered => WebhookAuditOutcome::Delivered,
        DeliveryAuditOutcome::HttpNonSuccess => WebhookAuditOutcome::HttpNonSuccess,
        DeliveryAuditOutcome::DestinationTimeout => WebhookAuditOutcome::DestinationTimeout,
        DeliveryAuditOutcome::DestinationResolutionRefused => {
            WebhookAuditOutcome::DestinationResolutionRefused
        }
        DeliveryAuditOutcome::DestinationTransportUnavailable => {
            WebhookAuditOutcome::DestinationTransportUnavailable
        }
        DeliveryAuditOutcome::DestinationPolicyRefused => {
            WebhookAuditOutcome::DestinationPolicyRefused
        }
        DeliveryAuditOutcome::DestinationBindingRefused => {
            WebhookAuditOutcome::DestinationBindingRefused
        }
        DeliveryAuditOutcome::PayloadRefused => WebhookAuditOutcome::PayloadRefused,
        DeliveryAuditOutcome::PayloadExpired => WebhookAuditOutcome::PayloadExpired,
        DeliveryAuditOutcome::WorkerInterrupted => WebhookAuditOutcome::WorkerInterrupted,
        DeliveryAuditOutcome::ReplayRequested => WebhookAuditOutcome::ReplayRequested,
    }
}

fn audit_disposition(disposition: DeliveryAuditDisposition) -> WebhookAuditDisposition {
    match disposition {
        DeliveryAuditDisposition::Leased => WebhookAuditDisposition::Leased,
        DeliveryAuditDisposition::Delivered => WebhookAuditDisposition::Delivered,
        DeliveryAuditDisposition::RetryPending => WebhookAuditDisposition::RetryPending,
        DeliveryAuditDisposition::DeadLettered => WebhookAuditDisposition::DeadLettered,
        DeliveryAuditDisposition::Expired => WebhookAuditDisposition::Expired,
        DeliveryAuditDisposition::ReplayPending => WebhookAuditDisposition::ReplayPending,
    }
}

fn transition_code(code: DeliveryTransitionCode) -> WebhookStateTransitionCode {
    match code {
        DeliveryTransitionCode::ClaimIdentityRefused => {
            WebhookStateTransitionCode::ClaimIdentityRefused
        }
        DeliveryTransitionCode::ClaimRecoveryFailed => {
            WebhookStateTransitionCode::ClaimRecoveryFailed
        }
        DeliveryTransitionCode::ClaimSelectFailed => WebhookStateTransitionCode::ClaimSelectFailed,
        DeliveryTransitionCode::ClaimPolicyRefused => {
            WebhookStateTransitionCode::ClaimPolicyRefused
        }
        DeliveryTransitionCode::ClaimUpdateFailed => WebhookStateTransitionCode::ClaimUpdateFailed,
        DeliveryTransitionCode::ClaimAuditFailed => WebhookStateTransitionCode::ClaimAuditFailed,
        DeliveryTransitionCode::ClaimCommitFailed => WebhookStateTransitionCode::ClaimCommitFailed,
    }
}

/// Base Registry Engine's delivery service: the platform delivery worker
/// bound to Base Registry Engine's seams and constants.
#[derive(Clone)]
pub struct WebhookDeliveryService {
    delivery: DeliveryService<BregDeliverySeams>,
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
        let config = DeliveryConfig {
            schema: DELIVERY_SCHEMA.to_owned(),
            idempotency_domain: IDEMPOTENCY_DOMAIN.to_vec(),
            delivery_source: format!(
                "urn:registrystack:registry:{}:instance:{}",
                expected.package_id, expected.instance_id
            ),
        };
        let seams = BregDeliverySeams {
            pool,
            destinations,
            expected,
            lock_key,
            lock_timeout,
            audit_profile,
        };
        Self {
            delivery: DeliveryService::new(seams, config),
        }
    }

    /// Claim, audit, send, and finalize at most one due delivery.
    ///
    /// The pre-egress audit and lease commit before request rendering or
    /// destination policy execution. Delivery is therefore explicitly
    /// at-least-once when a process stops after network I/O and before CAS
    /// finalization.
    pub async fn deliver_once(&self) -> Result<WebhookWorkOutcome, WebhookDeliveryError> {
        self.delivery.deliver_once().await
    }

    /// Refuse startup or operator use if retained work cannot use its exact
    /// captured destination under the active deployment bindings.
    pub async fn verify_retained_bindings(&self) -> Result<(), WebhookDeliveryError> {
        self.delivery.verify_retained_bindings().await
    }

    /// Return bounded, value-free pending and terminal operator metadata.
    pub async fn list(
        &self,
        limit: u16,
    ) -> Result<Vec<WebhookDeliveryStatus>, WebhookDeliveryError> {
        self.delivery.list(limit).await
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
        self.delivery
            .replay(event_id, compiled_delivery_id, expected_generation)
            .await
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

    pub async fn run(self, shutdown: watch::Receiver<bool>) {
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
        DeliveryWorker::new(service.delivery).run(shutdown).await;
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
