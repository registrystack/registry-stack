use std::time::{Duration, SystemTime};

use registry_platform_hooks::receiver::{
    verify_hook_delivery as verify_standard_delivery, DeliveryFreshness, HookDelivery,
};
use registry_platform_hooks::{DeliveryKey, DeliveryKeys};
use time::format_description::well_known::Rfc3339;

/// How the verifier bounds the signed delivery time.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum BRegHookFreshness {
    /// Refuse a delivery time further than 300 seconds from the receiver clock.
    #[default]
    DefaultWindow,
    /// Refuse a delivery time further than `skew` from the receiver clock.
    ///
    /// The Rust verifier applies `skew` as given. The Node and Python
    /// bindings accept 1 to 3600 seconds. Use [`Self::CallerEnforced`] to
    /// enforce the window in the receiver.
    Within { skew: Duration },
    /// Verify authenticity and timestamp syntax. The caller enforces the window.
    CallerEnforced,
}

/// Exact request material supplied to the BReg Standard Webhooks verifier.
///
/// Header pairs retain order and duplicates; names are matched without regard
/// to ASCII case. The key and body are never rendered by this type or by its
/// refusal errors.
pub struct BRegHookDelivery<'a> {
    pub headers: &'a [(String, String)],
    pub body: &'a [u8],
    pub key: &'a [u8],
    pub previous_key: Option<&'a [u8]>,
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
/// deduplication policy. Receivers must deduplicate on `source` and `id`
/// before acting on the body.
#[derive(Clone, Eq, PartialEq)]
pub struct BRegVerifiedHookDelivery {
    pub id: String,
    pub timestamp: u64,
    pub source: String,
    pub event_type: String,
    pub time: String,
    pub data_schema: String,
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
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum BRegHookVerificationError {
    #[error("a required hook header is missing. Check Content-Type and the three webhook headers")]
    MissingHeader,
    #[error("a required hook header is repeated. Remove duplicate headers")]
    DuplicateHeader,
    #[error("the hook content type is invalid. Set Content-Type to application/json")]
    InvalidContentType,
    #[error("the webhook id is invalid. Check the webhook-id header")]
    InvalidId,
    #[error(
        "the webhook timestamp is invalid. Use canonical Unix seconds and check the sender clock"
    )]
    InvalidTimestamp,
    #[error("the webhook timestamp is outside the freshness window. Check the clocks or configure a wider window")]
    StaleDelivery,
    #[error("the webhook signature is malformed. Check the Standard Webhooks signature encoding")]
    MalformedSignature,
    #[error("the webhook signature version is unsupported. Check that the sender signs with v1")]
    UnsupportedVersion,
    #[error("the webhook signature does not match. Check the key and exact signed bytes")]
    SignatureMismatch,
    #[error("the hook body exceeds the size limit. Reduce the body size")]
    BodyTooLarge,
    #[error("{detail}")]
    InvalidKey { detail: String },
    #[error("the hook envelope is invalid. Check the canonical JSON envelope")]
    InvalidEnvelope,
    #[error(
        "the webhook id differs from the envelope id. Check that the sender uses the envelope id"
    )]
    IdMismatch,
    #[error("the hook delivery came from a development peer")]
    DevelopmentPeer,
}

impl BRegHookVerificationError {
    /// Stable refusal code exposed by language bindings.
    #[must_use]
    pub const fn code(&self) -> &'static str {
        match self {
            Self::MissingHeader => "missing-header",
            Self::DuplicateHeader => "duplicate-header",
            Self::InvalidContentType => "invalid-content-type",
            Self::InvalidId => "invalid-id",
            Self::InvalidTimestamp => "invalid-timestamp",
            Self::StaleDelivery => "stale-delivery",
            Self::MalformedSignature => "malformed-signature",
            Self::UnsupportedVersion => "unsupported-version",
            Self::SignatureMismatch => "signature-mismatch",
            Self::BodyTooLarge => "body-too-large",
            Self::InvalidKey { .. } => "invalid-key",
            Self::InvalidEnvelope => "invalid-envelope",
            Self::IdMismatch => "id-mismatch",
            Self::DevelopmentPeer => "development-peer",
        }
    }
}

/// Verify one exact BReg Standard Webhooks delivery against the system clock.
///
/// The shared hooks verifier authenticates the exact body and checks the
/// canonical envelope and event identity. The default freshness window is
/// 300 seconds in either direction. Deduplication stays with the caller.
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
    let current = DeliveryKey::new(delivery.key)
        .map_err(|error| invalid_key("current", delivery.key, error.code()))?;
    let previous = delivery
        .previous_key
        .map(|bytes| {
            DeliveryKey::new(bytes).map_err(|error| invalid_key("previous", bytes, error.code()))
        })
        .transpose()?;
    let keys = DeliveryKeys::new(current, previous).map_err(|_| {
        BRegHookVerificationError::InvalidKey {
            detail: "The previous hook key equals the current key. Pass the key the sender used before rotation, or omit the previous key.".into(),
        }
    })?;
    let verified = verify_standard_delivery(
        HookDelivery {
            headers: delivery
                .headers
                .iter()
                .map(|(name, value)| (name.as_str(), value.as_bytes())),
            body: delivery.body,
            keys: &keys,
        },
        freshness,
    )
    .map_err(|error| {
        map_receiver_error(error.code()).unwrap_or(BRegHookVerificationError::MalformedSignature)
    })?;

    Ok(BRegVerifiedHookDelivery {
        id: verified.id.to_owned(),
        timestamp: verified.timestamp,
        source: verified.envelope.source,
        event_type: verified.envelope.event_type,
        time: verified
            .envelope
            .time
            .format(&Rfc3339)
            .map_err(|_| BRegHookVerificationError::InvalidEnvelope)?,
        data_schema: verified.envelope.dataschema,
        body: verified.body.to_vec(),
    })
}

fn invalid_key(which: &str, bytes: &[u8], code: &str) -> BRegHookVerificationError {
    let detail = match code {
        "key-is-secret-text" => format!(
            "The {which} hook key starts with whsec_ and must be supplied as exact key bytes."
        ),
        _ => {
            let length = bytes.len();
            let newline = if bytes.ends_with(b"\n") {
                " including a trailing newline"
            } else {
                ""
            };
            format!(
                "The {which} hook key is {length} bytes{newline} and must contain 32 to 64 exact bytes."
            )
        }
    };
    BRegHookVerificationError::InvalidKey { detail }
}

fn map_receiver_error(code: &str) -> Option<BRegHookVerificationError> {
    use BRegHookVerificationError::*;
    Some(match code {
        "missing-header" => MissingHeader,
        "duplicate-header" => DuplicateHeader,
        "invalid-content-type" => InvalidContentType,
        "invalid-id" => InvalidId,
        "invalid-timestamp" => InvalidTimestamp,
        "stale-delivery" => StaleDelivery,
        "malformed-signature" => MalformedSignature,
        "unsupported-version" => UnsupportedVersion,
        "signature-mismatch" => SignatureMismatch,
        "body-too-large" => BodyTooLarge,
        "invalid-envelope" => InvalidEnvelope,
        "id-mismatch" => IdMismatch,
        "development-peer" => DevelopmentPeer,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_shared_receiver_code_has_a_distinct_mapping() {
        // The receiver enum is non-exhaustive and exposes no code inventory.
        // Read both code methods so new upstream codes also enter this check.
        let sources = [
            include_str!("../../registry-platform-hooks/src/receiver.rs")
                .split_once("impl HookDeliveryError {")
                .unwrap()
                .1,
            include_str!("../../registry-platform-crypto/src/delivery_signature.rs")
                .split_once("impl DeliverySignatureError {")
                .unwrap()
                .1,
        ];
        let codes = sources.into_iter().flat_map(|source| {
            source
                .split_once("\n}\n")
                .unwrap()
                .0
                .lines()
                .filter_map(|line| {
                    let (_, value) = line.split_once("=> \"")?;
                    Some(value.split_once('"').unwrap().0)
                })
        });
        let mut count = 0;
        for code in codes {
            count += 1;
            assert_eq!(
                map_receiver_error(code).map(|error| error.code()),
                Some(code)
            );
        }
        assert!(count >= 12);
        assert_eq!(map_receiver_error("unknown-receiver-code"), None);
    }
}
