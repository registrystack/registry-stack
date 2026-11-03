// SPDX-License-Identifier: Apache-2.0

//! The engine-facing RabbitMQ source seam.
//!
//! The listener-free engine owns only the bounded delivery shape and the
//! source-owned settlement contract. The job host owns the broker client,
//! credentials, TLS, queue topology, and connection lifecycle. A reviewed
//! decoder turns [`RabbitMqMessage::body`] into the source route's item page;
//! this seam deliberately does not assume that every queue payload is JSON.

use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;

/// AMQP 0-9-1 carries `message-id` as a short string, whose encoded byte
/// length cannot exceed 255.
pub const MAXIMUM_RABBITMQ_SOURCE_IDENTITY_BYTES: usize = 255;

/// Immutable engine state for one RabbitMQ source endpoint. Broker authority,
/// credentials, TLS, and topology remain in the host binding.
#[derive(Clone, Debug)]
pub struct RabbitMqPlan {
    /// The runtime namespace every encoded broker message identity carries.
    pub namespace: String,
}

/// One bounded broker poll. An empty poll is an ordinary `Ok(None)`, not a
/// source failure.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RabbitMqReadRequest {
    maximum_message_bytes: usize,
    deadline: Duration,
}

impl RabbitMqReadRequest {
    /// Construct a finite read request.
    ///
    /// # Errors
    ///
    /// A zero byte ceiling or zero deadline is not a bound and is refused.
    pub fn new(
        maximum_message_bytes: usize,
        deadline: Duration,
    ) -> Result<Self, RabbitMqReadFault> {
        if maximum_message_bytes == 0 || deadline.is_zero() {
            return Err(RabbitMqReadFault::InvalidBounds);
        }
        Ok(Self {
            maximum_message_bytes,
            deadline,
        })
    }

    /// The largest fully received message body this poll retains.
    ///
    /// The transport may have allocated the body before it can apply this
    /// check, so the broker must enforce the deployment's hard publish limit.
    #[must_use]
    pub const fn maximum_message_bytes(self) -> usize {
        self.maximum_message_bytes
    }

    /// The total deadline for connection, topology verification, and read.
    #[must_use]
    pub const fn deadline(self) -> Duration {
        self.deadline
    }
}

/// A RabbitMQ read failure. Every variant is value-free: it carries no
/// broker address, queue, credential, message identity, or payload.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RabbitMqReadFault {
    /// The request did not carry finite positive bounds.
    #[error("the RabbitMQ read bounds are invalid")]
    InvalidBounds,
    /// The bounded poll reached its deadline.
    #[error("the RabbitMQ read timed out")]
    Timeout,
    /// The broker connection or channel was unavailable.
    #[error("the RabbitMQ source is unavailable")]
    Unavailable,
    /// The broker refused the configured durable source and dead-letter
    /// topology: a permission failure, or declared arguments that differ from
    /// the existing queue's.
    #[error("the RabbitMQ topology was refused")]
    Topology,
    /// The configured source queue does not exist and the host was not asked
    /// to declare it.
    #[error("the RabbitMQ source queue does not exist")]
    MissingQueue,
    /// The configured dead-letter exchange does not exist and the host was not
    /// asked to declare it.
    #[error("the RabbitMQ dead-letter exchange does not exist")]
    MissingDeadLetterExchange,
    /// The broker delivery carried no nonempty stable `message-id`.
    #[error("the RabbitMQ delivery has no source identity")]
    MissingIdentity,
    /// The stable source identity exceeded the AMQP short-string bound.
    #[error("the RabbitMQ delivery source identity exceeds its bound")]
    IdentityBound,
    /// The broker yielded a fully received body larger than the configured
    /// retained-message ceiling.
    #[error("the RabbitMQ delivery exceeds its byte bound")]
    Oversized,
    /// The publisher did not mark the delivery persistent (`delivery_mode=2`).
    #[error("the RabbitMQ delivery is not persistent")]
    NonPersistent,
}

/// A broker settlement failure. `Uncertain` means the caller cannot know
/// whether the broker applied the acknowledgement or rejection; the durable
/// item outcome and stable retry identity make a redelivery safe.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum RabbitMqSettlementFault {
    /// The settlement could not reach a live channel.
    #[error("the RabbitMQ delivery could not be settled")]
    Unavailable,
    /// The channel ended or the one-shot settlement handle was already used.
    #[error("the RabbitMQ delivery settlement is uncertain")]
    Uncertain,
}

/// Source-owned settlement for one delivery.
///
/// `accept` acknowledges only after every destination outcome for the message
/// is durably accepted. `refuse` rejects with requeue disabled so configured
/// broker dead-lettering owns the refused payload. Dropping an unsettled
/// delivery must close its host channel so the broker requeues it.
pub trait RabbitMqSettlement: Send + Sync {
    /// Acknowledge a durably accepted delivery.
    fn accept(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<(), RabbitMqSettlementFault>> + Send + '_>>;

    /// Reject an item-scoped refusal without requeueing it.
    fn refuse(
        &self,
    ) -> Pin<Box<dyn Future<Output = Result<(), RabbitMqSettlementFault>> + Send + '_>>;
}

/// One broker delivery and the source-owned handle that settles it.
///
/// The body and stable source identity are intentionally private. `Debug`
/// reports only byte counts and the broker's redelivery flag.
pub struct RabbitMqMessage {
    source_identity: String,
    redelivered: bool,
    body: Vec<u8>,
    settlement: Arc<dyn RabbitMqSettlement>,
}

impl RabbitMqMessage {
    /// Construct one bounded-identity delivery from a host transport.
    ///
    /// # Errors
    ///
    /// A missing, empty, or over-bound source identity is refused before the
    /// reviewed decoder sees the body.
    pub fn new(
        source_identity: Option<&str>,
        redelivered: bool,
        body: Vec<u8>,
        settlement: Arc<dyn RabbitMqSettlement>,
    ) -> Result<Self, RabbitMqReadFault> {
        let Some(source_identity) = source_identity.filter(|identity| !identity.is_empty()) else {
            return Err(RabbitMqReadFault::MissingIdentity);
        };
        if source_identity.len() > MAXIMUM_RABBITMQ_SOURCE_IDENTITY_BYTES {
            return Err(RabbitMqReadFault::IdentityBound);
        }
        Ok(Self {
            source_identity: source_identity.to_owned(),
            redelivered,
            body,
            settlement,
        })
    }

    /// The broker publisher's stable message identity.
    #[must_use]
    pub fn source_identity(&self) -> &str {
        &self.source_identity
    }

    /// Whether RabbitMQ marked this delivery as a redelivery.
    #[must_use]
    pub const fn redelivered(&self) -> bool {
        self.redelivered
    }

    /// The private payload for the reviewed source decoder.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }

    /// A shared handle to the one-shot source settlement.
    #[must_use]
    pub fn settlement(&self) -> Arc<dyn RabbitMqSettlement> {
        Arc::clone(&self.settlement)
    }

    /// Split the delivery without copying its private body or identity.
    #[must_use]
    pub fn into_parts(self) -> (String, bool, Vec<u8>, Arc<dyn RabbitMqSettlement>) {
        (
            self.source_identity,
            self.redelivered,
            self.body,
            self.settlement,
        )
    }
}

impl fmt::Debug for RabbitMqMessage {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RabbitMqMessage")
            .field("source_identity_bytes", &self.source_identity.len())
            .field("redelivered", &self.redelivered)
            .field("body_bytes", &self.body.len())
            .finish_non_exhaustive()
    }
}

/// The host-supplied RabbitMQ source. One bounded empty poll is normal idle.
pub trait RabbitMqSource: Send + Sync {
    /// Read at most one broker message under the caller's finite bounds.
    fn read<'a>(
        &'a self,
        request: &'a RabbitMqReadRequest,
    ) -> Pin<Box<dyn Future<Output = Result<Option<RabbitMqMessage>, RabbitMqReadFault>> + Send + 'a>>;
}

/// The source-owned receipt parked beside one route run. It contains only the
/// final-page identity invariant and the settlement handle, never the payload,
/// broker address, queue, or credential.
pub struct RabbitMqPageReceipt {
    expected_key: String,
    expected_revision: String,
    redelivered: bool,
    settlement_deadline: Duration,
    settlement: Arc<dyn RabbitMqSettlement>,
}

impl RabbitMqPageReceipt {
    /// Construct the receipt a one-message decoder parks before later route
    /// steps may normalize the item value.
    #[must_use]
    pub fn new(
        expected_key: String,
        expected_revision: String,
        redelivered: bool,
        settlement_deadline: Duration,
        settlement: Arc<dyn RabbitMqSettlement>,
    ) -> Self {
        Self {
            expected_key,
            expected_revision,
            redelivered,
            settlement_deadline,
            settlement,
        }
    }

    /// The exact item key the final reviewed route must preserve.
    #[must_use]
    pub fn expected_key(&self) -> &str {
        &self.expected_key
    }

    /// The deterministic raw-message revision the final route must preserve.
    #[must_use]
    pub fn expected_revision(&self) -> &str {
        &self.expected_revision
    }

    /// Whether the broker marked this delivery as a redelivery.
    #[must_use]
    pub const fn redelivered(&self) -> bool {
        self.redelivered
    }

    /// Acknowledge this delivery after its durable item row says accepted.
    pub async fn accept(&self) -> Result<(), RabbitMqSettlementFault> {
        tokio::time::timeout(self.settlement_deadline, self.settlement.accept())
            .await
            .map_err(|_| RabbitMqSettlementFault::Uncertain)?
    }

    /// Reject this delivery without requeue after its durable item row says
    /// refused.
    pub async fn refuse(&self) -> Result<(), RabbitMqSettlementFault> {
        tokio::time::timeout(self.settlement_deadline, self.settlement.refuse())
            .await
            .map_err(|_| RabbitMqSettlementFault::Uncertain)?
    }
}

impl fmt::Debug for RabbitMqPageReceipt {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RabbitMqPageReceipt")
            .field("expected_key_bytes", &self.expected_key.len())
            .field("expected_revision_bytes", &self.expected_revision.len())
            .field("redelivered", &self.redelivered)
            .finish_non_exhaustive()
    }
}

/// Derive the collision-free item key for one fixed namespace and AMQP
/// message-id. URL-safe base64 has no `/`, so the final slash unambiguously
/// separates the operator namespace from the broker identity.
#[must_use]
pub fn rabbitmq_item_key(namespace: &str, source_identity: &str) -> String {
    format!(
        "{namespace}/{}",
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(source_identity.as_bytes())
    )
}
