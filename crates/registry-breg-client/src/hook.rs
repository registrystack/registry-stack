use std::time::{Duration, SystemTime};

use registry_platform_hooks::receiver::{
    verify_delivery, DeliveryFreshness, ReceiverError, SignedDelivery,
};

/// How the verifier bounds the signed delivery time.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum BRegHookFreshness {
    /// Refuse a delivery time further than 300 seconds from the receiver clock.
    #[default]
    DefaultWindow,
    /// Refuse a delivery time further than `skew` from the receiver clock.
    ///
    /// The Rust verifier applies `skew` as given. A zero `skew` refuses every
    /// delivery and a very large one disables the window. The Node and Python
    /// bindings accept 1 to 3600 seconds only. A receiver that wants no window
    /// of its own uses [`Self::CallerEnforced`], which says so explicitly.
    Within { skew: Duration },
    /// Check only that the delivery time is well formed. The caller enforces
    /// its own window.
    CallerEnforced,
}

/// Exact request material supplied to the BReg Version 1 hook verifier.
///
/// Header pairs retain order and duplicates; names are matched without regard
/// to ASCII case. The key and body are never rendered by this type or by its
/// refusal errors.
pub struct BRegHookDelivery<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub headers: &'a [(String, String)],
    pub body: &'a [u8],
    pub key: &'a [u8],
    pub freshness: BRegHookFreshness,
}

impl std::fmt::Debug for BRegHookDelivery<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BRegHookDelivery(<redacted>)")
    }
}

/// Authenticated BReg hook attributes and exact body.
///
/// Verification applies the delivery-time window named by
/// [`BRegHookFreshness`], 300 seconds by default. It does not apply replay or
/// deduplication policy. Receivers must deduplicate on `idempotency_key`
/// before acting on the body.
#[derive(Clone, Eq, PartialEq)]
pub struct BRegVerifiedHookDelivery {
    pub id: String,
    pub source: String,
    pub event_type: String,
    pub time: String,
    pub data_schema: String,
    pub generation: String,
    pub attempt: String,
    pub delivery_time: String,
    pub idempotency_key: String,
    pub body: Vec<u8>,
}

impl std::fmt::Debug for BRegVerifiedHookDelivery {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BRegVerifiedHookDelivery")
            .field("body_bytes", &self.body.len())
            .finish_non_exhaustive()
    }
}

/// Closed, value-free reason a BReg hook delivery was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum BRegHookVerificationError {
    #[error("a required Base Registry Engine hook header is missing")]
    MissingHeader,
    #[error("the Base Registry Engine hook delivery time is invalid; check the signed delivery time and sender clock")]
    InvalidDeliveryTime,
    #[error("the Base Registry Engine hook delivery time is outside the freshness window; check the receiver clock, or pass a wider window")]
    StaleDelivery,
    #[error("a Base Registry Engine hook header is repeated; remove duplicate signed headers")]
    DuplicateHeader,
    #[error(
        "the Base Registry Engine hook body exceeds the Version 1 limit; reduce the body size"
    )]
    BodyTooLarge,
    #[error("the Base Registry Engine hook verification key is too short; configure a key of at least 32 bytes")]
    InvalidKey,
    #[error("the Base Registry Engine hook signature is malformed")]
    MalformedSignature,
    #[error("the Base Registry Engine hook signature does not match")]
    SignatureMismatch,
    #[error("the Base Registry Engine hook signature version is unsupported")]
    UnsupportedVersion,
}

impl BRegHookVerificationError {
    /// Stable refusal code exposed by language bindings.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::MissingHeader => "missing-header",
            Self::InvalidDeliveryTime => "invalid-delivery-time",
            Self::StaleDelivery => "stale-delivery",
            Self::DuplicateHeader => "duplicate-header",
            Self::BodyTooLarge => "body-too-large",
            Self::InvalidKey => "invalid-key",
            Self::MalformedSignature => "malformed-signature",
            Self::SignatureMismatch => "signature-mismatch",
            Self::UnsupportedVersion => "unsupported-version",
        }
    }
}

/// Verify one exact BReg Version 1 hook delivery against the system clock.
///
/// This delegates header extraction, the signature input, RFC 3339
/// delivery-time validation, and constant-time HMAC comparison to the shared
/// `registry_platform_hooks::receiver::verify_delivery`. The delivery time must
/// fall inside the window `delivery.freshness` names, 300 seconds either way by
/// default. Deduplication stays with the caller.
pub fn verify_hook_delivery(
    delivery: BRegHookDelivery<'_>,
) -> Result<BRegVerifiedHookDelivery, BRegHookVerificationError> {
    verify_hook_delivery_at(delivery, SystemTime::now())
}

/// Same as [`verify_hook_delivery`], against `now`. For tests and for callers
/// with their own clock.
pub fn verify_hook_delivery_at(
    delivery: BRegHookDelivery<'_>,
    now: SystemTime,
) -> Result<BRegVerifiedHookDelivery, BRegHookVerificationError> {
    let freshness = match delivery.freshness {
        BRegHookFreshness::DefaultWindow => DeliveryFreshness::default_at(now),
        BRegHookFreshness::Within { skew } => DeliveryFreshness::Within { now, skew },
        BRegHookFreshness::CallerEnforced => DeliveryFreshness::CallerEnforced,
    };
    let verified = verify_delivery(
        SignedDelivery {
            method: delivery.method,
            request_target: delivery.path,
            headers: delivery
                .headers
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_bytes())),
            body: delivery.body,
            key: delivery.key,
        },
        freshness,
    )
    .map_err(map_receiver_error)?;

    Ok(BRegVerifiedHookDelivery {
        id: verified.id.to_owned(),
        source: verified.source.to_owned(),
        event_type: verified.event_type.to_owned(),
        time: verified.time.to_owned(),
        data_schema: verified.data_schema.to_owned(),
        generation: verified.generation.to_owned(),
        attempt: verified.attempt.to_owned(),
        delivery_time: verified.delivery_time.to_owned(),
        idempotency_key: verified.idempotency_key.to_owned(),
        body: delivery.body.to_vec(),
    })
}

fn map_receiver_error(error: ReceiverError) -> BRegHookVerificationError {
    match error {
        ReceiverError::MissingHeader => BRegHookVerificationError::MissingHeader,
        ReceiverError::InvalidDeliveryTime => BRegHookVerificationError::InvalidDeliveryTime,
        ReceiverError::Stale => BRegHookVerificationError::StaleDelivery,
        ReceiverError::DuplicateHeader => BRegHookVerificationError::DuplicateHeader,
        ReceiverError::BodyTooLarge => BRegHookVerificationError::BodyTooLarge,
        ReceiverError::InvalidKey => BRegHookVerificationError::InvalidKey,
        ReceiverError::UnsupportedVersion => BRegHookVerificationError::UnsupportedVersion,
        ReceiverError::SignatureMismatch => BRegHookVerificationError::SignatureMismatch,
        ReceiverError::MalformedHeader | ReceiverError::MalformedSignature => {
            BRegHookVerificationError::MalformedSignature
        }
        _ => BRegHookVerificationError::MalformedSignature,
    }
}
