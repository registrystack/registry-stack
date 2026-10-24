use std::collections::BTreeMap;

use registry_platform_hooks::receiver::{
    verify_delivery, DeliveryFreshness, ReceiverError, SignedDelivery,
};

/// Exact request material supplied to the BReg Version 1 hook verifier.
///
/// Header names are matched without regard to ASCII case. The key and body are
/// never rendered by this type or by its refusal errors.
pub struct BRegHookDelivery<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub headers: &'a BTreeMap<String, String>,
    pub body: &'a [u8],
    pub key: &'a [u8],
}

impl std::fmt::Debug for BRegHookDelivery<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BRegHookDelivery(<redacted>)")
    }
}

/// Authenticated BReg hook attributes and exact body.
///
/// Verification does not apply replay, delivery-time skew, or deduplication
/// policy. Receivers must apply those policies to `delivery_time` and
/// `idempotency_key` before acting on the body.
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
            Self::DuplicateHeader => "duplicate-header",
            Self::BodyTooLarge => "body-too-large",
            Self::InvalidKey => "invalid-key",
            Self::MalformedSignature => "malformed-signature",
            Self::SignatureMismatch => "signature-mismatch",
            Self::UnsupportedVersion => "unsupported-version",
        }
    }
}

/// Verify one exact BReg Version 1 hook delivery without applying receiver policy.
///
/// This delegates header extraction, the signature input, RFC 3339
/// delivery-time validation, and constant-time HMAC comparison to the shared
/// `registry_platform_hooks::receiver::verify_delivery`. Caller-enforced
/// freshness leaves the receiver's clock policy separate; the caller receives
/// the authenticated raw delivery time to enforce its own skew bound.
pub fn verify_hook_delivery(
    delivery: BRegHookDelivery<'_>,
) -> Result<BRegVerifiedHookDelivery, BRegHookVerificationError> {
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
        DeliveryFreshness::CallerEnforced,
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
        ReceiverError::InvalidDeliveryTime | ReceiverError::Stale => {
            BRegHookVerificationError::InvalidDeliveryTime
        }
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
