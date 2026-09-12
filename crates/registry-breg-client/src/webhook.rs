use std::{collections::BTreeMap, time::Duration};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use registry_platform_crypto::breg_webhook::{verify_v1, SignatureFields, VerificationError};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

const SIGNATURE_PREFIX: &str = "v1=";
const SIGNATURE_BYTES: usize = 32;
const SIGNATURE_TEXT_BYTES: usize = 43;
const CE_SPECVERSION: &str = "ce-specversion";
const CE_ID: &str = "ce-id";
const CE_SOURCE: &str = "ce-source";
const CE_TYPE: &str = "ce-type";
const CE_TIME: &str = "ce-time";
const CE_DATASCHEMA: &str = "ce-dataschema";
const EVENT_GENERATION: &str = "x-registry-event-generation";
const DELIVERY_ATTEMPT: &str = "x-registry-delivery-attempt";
const DELIVERY_TIME: &str = "x-registry-delivery-time";
const CONTENT_TYPE: &str = "content-type";
const IDEMPOTENCY_KEY: &str = "idempotency-key";
const SIGNATURE: &str = "x-registry-signature";

/// Exact request material supplied to the BReg Version 1 webhook verifier.
///
/// Header names are matched without regard to ASCII case. The key and body are
/// never rendered by this type or by its refusal errors.
pub struct BRegWebhookDelivery<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub headers: &'a BTreeMap<String, String>,
    pub body: &'a [u8],
    pub key: &'a [u8],
}

impl std::fmt::Debug for BRegWebhookDelivery<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("BRegWebhookDelivery(<redacted>)")
    }
}

/// Authenticated BReg webhook attributes and exact body.
///
/// Verification does not apply replay, delivery-time skew, or deduplication
/// policy. Receivers must apply those policies to `delivery_time` and
/// `idempotency_key` before acting on the body.
#[derive(Clone, Eq, PartialEq)]
pub struct BRegVerifiedWebhookDelivery {
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

impl std::fmt::Debug for BRegVerifiedWebhookDelivery {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BRegVerifiedWebhookDelivery")
            .field("body_bytes", &self.body.len())
            .finish_non_exhaustive()
    }
}

/// Closed, value-free reason a BReg webhook delivery was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum BRegWebhookVerificationError {
    #[error("a required Base Registry Engine webhook header is missing")]
    MissingHeader,
    #[error("the Base Registry Engine webhook signature is malformed")]
    MalformedSignature,
    #[error("the Base Registry Engine webhook signature does not match")]
    SignatureMismatch,
    #[error("the Base Registry Engine webhook signature version is unsupported")]
    UnsupportedVersion,
}

impl BRegWebhookVerificationError {
    /// Stable refusal code exposed by language bindings.
    #[must_use]
    pub const fn code(self) -> &'static str {
        match self {
            Self::MissingHeader => "missing_header",
            Self::MalformedSignature => "malformed_signature",
            Self::SignatureMismatch => "signature_mismatch",
            Self::UnsupportedVersion => "unsupported_version",
        }
    }
}

/// Verify one exact BReg Version 1 webhook delivery without applying receiver policy.
///
/// This delegates the signature input, canonical delivery-time validation, and
/// constant-time HMAC comparison to `registry-platform-crypto`. Passing the
/// claimed delivery instant with zero skew disables only receiver clock policy;
/// the caller receives that authenticated value to enforce its own skew bound.
pub fn verify_webhook_delivery(
    delivery: BRegWebhookDelivery<'_>,
) -> Result<BRegVerifiedWebhookDelivery, BRegWebhookVerificationError> {
    let specversion = header(delivery.headers, CE_SPECVERSION)?;
    if specversion != "1.0" {
        return Err(BRegWebhookVerificationError::UnsupportedVersion);
    }
    let id = header(delivery.headers, CE_ID)?;
    let source = header(delivery.headers, CE_SOURCE)?;
    let event_type = header(delivery.headers, CE_TYPE)?;
    let time = header(delivery.headers, CE_TIME)?;
    let data_schema = header(delivery.headers, CE_DATASCHEMA)?;
    let generation_text = header(delivery.headers, EVENT_GENERATION)?;
    let attempt_text = header(delivery.headers, DELIVERY_ATTEMPT)?;
    let delivery_time = header(delivery.headers, DELIVERY_TIME)?;
    let content_type = header(delivery.headers, CONTENT_TYPE)?;
    let idempotency_key = header(delivery.headers, IDEMPOTENCY_KEY)?;
    let signature = header(delivery.headers, SIGNATURE)?;

    validate_signature_shape(signature)?;
    positive_decimal(generation_text)?;
    positive_decimal(attempt_text)?;
    let claimed_delivery_time = OffsetDateTime::parse(delivery_time, &Rfc3339)
        .map(std::time::SystemTime::from)
        .map_err(|_| BRegWebhookVerificationError::MalformedSignature)?;

    verify_v1(
        delivery.key,
        SignatureFields {
            id,
            source,
            event_type,
            time,
            data_schema,
            generation: generation_text,
            attempt: attempt_text,
            delivery_time,
            method: delivery.method,
            request_target: delivery.path,
            content_type,
            idempotency_key,
            body: delivery.body,
        },
        signature,
        claimed_delivery_time,
        Duration::ZERO,
    )
    .map_err(map_verification_error)?;

    Ok(BRegVerifiedWebhookDelivery {
        id: id.to_owned(),
        source: source.to_owned(),
        event_type: event_type.to_owned(),
        time: time.to_owned(),
        data_schema: data_schema.to_owned(),
        generation: generation_text.to_owned(),
        attempt: attempt_text.to_owned(),
        delivery_time: delivery_time.to_owned(),
        idempotency_key: idempotency_key.to_owned(),
        body: delivery.body.to_vec(),
    })
}

fn header<'a>(
    headers: &'a BTreeMap<String, String>,
    expected: &str,
) -> Result<&'a str, BRegWebhookVerificationError> {
    let mut matches = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case(expected));
    let (_, value) = matches
        .next()
        .ok_or(BRegWebhookVerificationError::MissingHeader)?;
    if matches.next().is_some() {
        return Err(BRegWebhookVerificationError::MalformedSignature);
    }
    Ok(value)
}

fn validate_signature_shape(signature: &str) -> Result<(), BRegWebhookVerificationError> {
    let encoded = signature
        .strip_prefix(SIGNATURE_PREFIX)
        .ok_or(BRegWebhookVerificationError::UnsupportedVersion)?;
    if encoded.len() != SIGNATURE_TEXT_BYTES {
        return Err(BRegWebhookVerificationError::MalformedSignature);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| BRegWebhookVerificationError::MalformedSignature)?;
    if decoded.len() != SIGNATURE_BYTES || URL_SAFE_NO_PAD.encode(decoded) != encoded {
        return Err(BRegWebhookVerificationError::MalformedSignature);
    }
    Ok(())
}

fn positive_decimal(value: &str) -> Result<i64, BRegWebhookVerificationError> {
    let parsed = value
        .parse::<i64>()
        .ok()
        .filter(|parsed| *parsed > 0 && parsed.to_string() == value)
        .ok_or(BRegWebhookVerificationError::MalformedSignature)?;
    Ok(parsed)
}

fn map_verification_error(error: VerificationError) -> BRegWebhookVerificationError {
    match error {
        VerificationError::UnsupportedVersion => BRegWebhookVerificationError::UnsupportedVersion,
        VerificationError::InvalidSignature => BRegWebhookVerificationError::SignatureMismatch,
        VerificationError::InvalidKey
        | VerificationError::InputTooLarge
        | VerificationError::InvalidDeliveryTime
        | VerificationError::DeliveryTimeSkew => BRegWebhookVerificationError::MalformedSignature,
    }
}
