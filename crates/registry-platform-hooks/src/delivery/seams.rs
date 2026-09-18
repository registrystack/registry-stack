// SPDX-License-Identifier: Apache-2.0

//! The product seams the delivery worker runs through: connection, identity
//! preflight, audit, operational events, and activated destinations.
//!
//! Everything product-owned enters here, and it enters through one trait so a
//! product implements its side as a unit. The worker carries no product name
//! and no product policy: the signing scheme and its key material, the
//! idempotency domain, the audit vocabulary, the operational vocabulary, and
//! the identity check all stay with the product, expressed as the neutral
//! contracts below.

use std::ops::DerefMut;
use std::time::Duration;

use async_trait::async_trait;
use registry_platform_httputil::destination::{
    DestinationRequestError, DestinationSendError, EventDeliveryHeaders, EventDestinationRequest,
};
use tokio_postgres::Transaction;
use uuid::Uuid;

/// One pooled product connection framed for the worker.
///
/// The worker opens its claim, material, and finalize transactions on
/// separate connections, exactly as the owning product's pool provided them
/// before the move.
pub type DeliveryConnection = Box<dyn DerefMut<Target = tokio_postgres::Client> + Send>;

/// Value-free refusal while doing delivery work.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DeliveryError {
    #[error("hook delivery is unavailable")]
    Unavailable,
}

/// The product-owned surface the delivery worker runs through.
///
/// One trait, not several: a product binds its pool, its identity preflight,
/// its audit journal, its operational vocabulary, and its activated
/// destinations together, and the worker never sees any of them concretely.
#[async_trait]
pub trait DeliverySeams: Send + Sync + 'static {
    /// The product's activated destination for one compiled logical id.
    type Destination: HookDestination;

    /// One pooled connection for a worker transaction.
    async fn connection(&self) -> Result<DeliveryConnection, DeliveryError>;

    /// The product's identity preflight, called inside every worker
    /// transaction at the point where the product verified its deployment
    /// identity before the move.
    async fn verify_transaction(&self, transaction: &Transaction<'_>) -> Result<(), DeliveryError>;

    /// The activated destination for a compiled logical destination id, or
    /// `None` when that id is not activated.
    fn destination(&self, logical_destination_id: &str) -> Option<Self::Destination>;

    /// Record one neutral delivery-audit event in the product's audit
    /// journal, inside the transaction the worker is about to commit. Every
    /// audited occurrence and every audited field of the moved worker arrives
    /// here.
    async fn record_audit(
        &self,
        transaction: &Transaction<'_>,
        record: DeliveryAuditRecord<'_>,
    ) -> Result<(), DeliveryError>;

    /// Report one operational event through the product's vocabulary.
    fn operational_event(&self, event: DeliveryOperationalEvent);
}

/// One activated delivery destination, resolved by the product for a
/// compiled logical destination id.
///
/// Signing and sending stay with the product: the key material never leaves
/// the destination, and the product's mapping fills the signature's method,
/// request target, and content type from the same binding the transport
/// uses, so signing and transport cannot disagree.
#[async_trait]
pub trait HookDestination: Send + Sync {
    /// Digest of the exact binding this destination was activated under.
    fn binding_digest(&self) -> &str;

    /// Deployed per-attempt timeout.
    fn attempt_timeout(&self) -> Duration;

    /// Deployed maximum attempt count.
    fn maximum_attempts(&self) -> u8;

    /// Sign one delivery with the product's scheme and key material.
    fn sign_delivery(
        &self,
        fields: DeliverySignatureFields<'_>,
    ) -> Result<String, DeliverySignatureRefused>;

    /// Render the signed request for transport.
    fn render_delivery(
        &self,
        headers: EventDeliveryHeaders<'_>,
        body: Vec<u8>,
    ) -> Result<EventDestinationRequest, DestinationRequestError>;

    /// Send the rendered request with the remaining attempt budget.
    async fn send_delivery(
        &self,
        request: EventDestinationRequest,
        remaining: Duration,
    ) -> Result<DestinationAnswer, DestinationSendError>;
}

/// The neutral signing input for one delivery attempt.
///
/// The product maps this onto its own scheme. The values are exactly the
/// ones the wire carries: changing any of them changes wire bytes.
#[derive(Clone, Copy, Debug)]
pub struct DeliverySignatureFields<'a> {
    pub id: &'a str,
    pub source: &'a str,
    pub event_type: &'a str,
    pub time: &'a str,
    pub data_schema: &'a str,
    pub generation: &'a str,
    pub attempt: &'a str,
    pub delivery_time: &'a str,
    pub idempotency_key: &'a str,
    pub body: &'a [u8],
}

/// The product's signing scheme refused the input.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DeliverySignatureRefused;

/// Whether the destination answered an attempt with a success status.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DestinationAnswer {
    /// The destination answered 2xx.
    Delivered,
    /// The destination answered, and not with 2xx.
    NonSuccess,
}

/// The closed phase of a neutral delivery-audit event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryAuditPhase {
    Attempt,
    Terminal,
    Replay,
}

/// The closed outcome of a neutral delivery-audit event: exactly the
/// outcomes the moved worker records, named for the mechanism they describe.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryAuditOutcome {
    AttemptStarted,
    Delivered,
    HttpNonSuccess,
    DestinationTimeout,
    DestinationResolutionRefused,
    DestinationTransportUnavailable,
    DestinationPolicyRefused,
    DestinationBindingRefused,
    PayloadRefused,
    PayloadExpired,
    WorkerInterrupted,
    ReplayRequested,
}

/// The closed disposition of a neutral delivery-audit event.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryAuditDisposition {
    Leased,
    Delivered,
    RetryPending,
    DeadLettered,
    Expired,
    ReplayPending,
}

/// One neutral delivery-audit event.
///
/// This is the complete audit surface of the worker: every occurrence the
/// moved worker audited arrives here once, with exactly these fields, and
/// the product maps it 1:1 onto its own audit vocabulary and journal.
#[derive(Clone, Copy, Debug)]
pub struct DeliveryAuditRecord<'a> {
    pub event_id: Uuid,
    pub compiled_delivery_id: &'a str,
    pub package_revision: &'a str,
    pub generation: i64,
    pub attempt: i16,
    pub phase: DeliveryAuditPhase,
    pub outcome: DeliveryAuditOutcome,
    pub disposition: DeliveryAuditDisposition,
}

/// The closed state-transition failure codes of the claim path. The codes
/// identify only the failed transition class and never carry destination or
/// event values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryTransitionCode {
    ClaimIdentityRefused,
    ClaimRecoveryFailed,
    ClaimSelectFailed,
    ClaimPolicyRefused,
    ClaimUpdateFailed,
    ClaimAuditFailed,
    ClaimCommitFailed,
}

/// The closed operational-event vocabulary of the worker: low-cardinality,
/// value-free process state, deliberately unrelated to audit.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryOperationalEvent {
    /// One worker poll iteration failed.
    IterationFailed,
    /// One claim-path state transition failed.
    TransitionFailed(DeliveryTransitionCode),
}
