// SPDX-License-Identifier: Apache-2.0
//! Version 1 hook delivery signing and verification.
//!
//! One HMAC-SHA-256 scheme over the exact wire fields of a signed HTTP hook
//! delivery, shared by the product that sends a delivery and the receiver
//! that authenticates one. The scheme carries no product policy: the caller
//! owns the key material, the destination binding, and the freshness window
//! it passes as `allowed_skew`.
//!
//! The signing domain and the length-prefixed field order below are wire
//! bytes that deployed receivers already verify, so they keep their Version
//! 1 spelling whatever the Rust names around them are.
//!
//! Standard Webhooks symmetric signatures use the separate `sign` and
//! `verify` entry points and authenticate the ID, timestamp, and exact body.

use std::time::{Duration, SystemTime};

use base64::engine::general_purpose::STANDARD;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2::Sha256;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use zeroize::Zeroizing;

/// The Version 1 signing domain, as deployed receivers verify it.
///
/// This is the shared Version 1 domain for every product that signs or
/// verifies a hook delivery, not a Base Registry Engine domain: Scheduling and
/// Coordinator deliveries carry it too. The `breg-` prefix is kept only for
/// wire compatibility.
///
/// Wire bytes: the spelling is fixed by the receivers that already accept
/// it, not by what this module or its callers are named.
const SIGNATURE_DOMAIN: &[u8] = b"breg-webhook-signature-v1";
const SIGNING_INPUT_VERSION: &[u8] = b"1.0";
const SIGNATURE_PREFIX: &str = "v1=";
const HMAC_SHA256_BYTES: usize = 32;

/// Minimum shared-secret size accepted by the Version 1 contract.
pub const MIN_HMAC_SHA256_KEY_BYTES: usize = 32;
/// Maximum exact webhook body covered by the Version 1 contract.
pub const MAX_BODY_BYTES: usize = 1_048_576;
/// Maximum combined byte length of the signed metadata fields.
pub const MAX_METADATA_BYTES: usize = 32_768;

type HmacSha256 = Hmac<Sha256>;

/// Exact fields covered by a Version 1 hook delivery signature.
///
/// Values are signed as their wire bytes. Callers must pass the received HTTP
/// method, request target, content type, headers, and body without normalization.
#[derive(Clone, Copy, Debug)]
pub struct SignatureFields<'a> {
    pub id: &'a str,
    pub source: &'a str,
    pub event_type: &'a str,
    pub time: &'a str,
    pub data_schema: &'a str,
    pub generation: &'a str,
    pub attempt: &'a str,
    pub delivery_time: &'a str,
    pub method: &'a str,
    pub request_target: &'a str,
    pub content_type: &'a str,
    pub idempotency_key: &'a str,
    pub body: &'a [u8],
}

/// Value-free failure while constructing a Version 1 signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum SigningError {
    #[error("the webhook signing key is invalid")]
    InvalidKey,
    #[error("the webhook signing input exceeds the Version 1 bounds")]
    InputTooLarge,
}

/// Value-free failure while verifying a Version 1 signature.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum VerificationError {
    #[error("the webhook signing key is invalid")]
    InvalidKey,
    #[error("the webhook signing input exceeds the Version 1 bounds")]
    InputTooLarge,
    #[error("the webhook signature version is unsupported")]
    UnsupportedVersion,
    #[error("the webhook signature is invalid")]
    InvalidSignature,
    #[error("the webhook delivery time is invalid")]
    InvalidDeliveryTime,
    #[error("the webhook delivery time is outside the allowed skew")]
    DeliveryTimeSkew,
}

/// Sign the exact Version 1 wire fields with HMAC-SHA-256.
pub fn sign_v1(key: &[u8], fields: SignatureFields<'_>) -> Result<String, SigningError> {
    validate_key(key).map_err(|()| SigningError::InvalidKey)?;
    let input = signing_input(fields).ok_or(SigningError::InputTooLarge)?;
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| SigningError::InvalidKey)?;
    mac.update(&input);
    Ok(format!(
        "{SIGNATURE_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    ))
}

/// Verify a Version 1 signature and the receiver's delivery-time freshness policy.
///
/// The signature comparison uses the HMAC implementation's constant-time tag
/// verification. `allowed_skew` applies in both directions around `now`.
pub fn verify_v1(
    key: &[u8],
    fields: SignatureFields<'_>,
    signature: &str,
    now: SystemTime,
    allowed_skew: Duration,
) -> Result<(), VerificationError> {
    verify_signature(key, fields, signature)?;
    validate_delivery_time(fields.delivery_time, now, allowed_skew)
}

/// Authenticate exact Version 1 bytes and validate RFC 3339 time grammar.
/// The caller must enforce its own clock window before using the delivery.
pub fn verify_v1_authenticity(
    key: &[u8],
    fields: SignatureFields<'_>,
    signature: &str,
) -> Result<(), VerificationError> {
    verify_signature(key, fields, signature)?;
    OffsetDateTime::parse(fields.delivery_time, &Rfc3339)
        .map_err(|_| VerificationError::InvalidDeliveryTime)?;
    Ok(())
}

fn verify_signature(
    key: &[u8],
    fields: SignatureFields<'_>,
    signature: &str,
) -> Result<(), VerificationError> {
    validate_key(key).map_err(|()| VerificationError::InvalidKey)?;
    let input = signing_input(fields).ok_or(VerificationError::InputTooLarge)?;
    let encoded = signature
        .strip_prefix(SIGNATURE_PREFIX)
        .ok_or(VerificationError::UnsupportedVersion)?;
    if encoded.len() != 43 {
        return Err(VerificationError::InvalidSignature);
    }
    let tag = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| VerificationError::InvalidSignature)?;
    if tag.len() != HMAC_SHA256_BYTES {
        return Err(VerificationError::InvalidSignature);
    }
    let mut mac = HmacSha256::new_from_slice(key).map_err(|_| VerificationError::InvalidKey)?;
    mac.update(&input);
    mac.verify_slice(&tag)
        .map_err(|_| VerificationError::InvalidSignature)?;
    Ok(())
}

fn validate_key(key: &[u8]) -> Result<(), ()> {
    if key.len() < MIN_HMAC_SHA256_KEY_BYTES {
        Err(())
    } else {
        Ok(())
    }
}

fn signing_input(fields: SignatureFields<'_>) -> Option<Vec<u8>> {
    let metadata = [
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
    ];
    let metadata_bytes = metadata
        .iter()
        .try_fold(0_usize, |total, value| total.checked_add(value.len()))?;
    if metadata_bytes > MAX_METADATA_BYTES || fields.body.len() > MAX_BODY_BYTES {
        return None;
    }

    let capacity = SIGNATURE_DOMAIN
        .len()
        .checked_add((metadata.len() + 2).checked_mul(size_of::<u64>())?)?
        .checked_add(SIGNING_INPUT_VERSION.len())?
        .checked_add(metadata_bytes)?
        .checked_add(fields.body.len())?;
    let mut input = Vec::with_capacity(capacity);
    input.extend_from_slice(SIGNATURE_DOMAIN);
    append_length_prefixed(&mut input, SIGNING_INPUT_VERSION);
    for value in metadata {
        append_length_prefixed(&mut input, value);
    }
    append_length_prefixed(&mut input, fields.body);
    Some(input)
}

fn append_length_prefixed(output: &mut Vec<u8>, value: &[u8]) {
    output.extend_from_slice(&(value.len() as u64).to_be_bytes());
    output.extend_from_slice(value);
}

fn validate_delivery_time(
    value: &str,
    now: SystemTime,
    allowed_skew: Duration,
) -> Result<(), VerificationError> {
    let parsed = OffsetDateTime::parse(value, &Rfc3339)
        .map_err(|_| VerificationError::InvalidDeliveryTime)?;
    let delivery_nanos = parsed.unix_timestamp_nanos();
    let now_nanos = system_time_unix_nanos(now);
    if delivery_nanos.abs_diff(now_nanos) > allowed_skew.as_nanos() {
        return Err(VerificationError::DeliveryTimeSkew);
    }
    Ok(())
}

fn system_time_unix_nanos(value: SystemTime) -> i128 {
    match value.duration_since(SystemTime::UNIX_EPOCH) {
        Ok(duration) => i128::try_from(duration.as_nanos()).unwrap_or(i128::MAX),
        Err(error) => -i128::try_from(error.duration().as_nanos()).unwrap_or(i128::MAX),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: &[u8] = b"webhook-delivery-signing-key-0123456789abcdef";

    fn fields() -> SignatureFields<'static> {
        SignatureFields {
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
        }
    }

    fn delivery_time() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_788_048_001)
    }

    #[test]
    fn v1_fixed_vector_preserves_the_wire_contract() {
        assert_eq!(
            sign_v1(KEY, fields()).unwrap(),
            "v1=OzL5k0ghZJb9nPbb-JOVsroWeanipBlZXbeKDd52RcM"
        );
    }

    #[test]
    fn v1_binds_every_field_and_exact_body() {
        let baseline = sign_v1(KEY, fields()).unwrap();
        macro_rules! assert_field_is_bound {
            ($member:ident, $changed:expr) => {{
                let mut changed = fields();
                changed.$member = $changed;
                assert_ne!(baseline, sign_v1(KEY, changed).unwrap());
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
        assert_ne!(baseline, sign_v1(&[0x6b; 32], fields()).unwrap());
    }

    #[test]
    fn verify_v1_accepts_exact_signature_within_skew() {
        let signature = sign_v1(KEY, fields()).unwrap();
        verify_v1(
            KEY,
            fields(),
            &signature,
            delivery_time() + Duration::from_secs(30),
            Duration::from_secs(30),
        )
        .unwrap();
    }

    #[test]
    fn rfc3339_fraction_spellings_bind_raw_bytes_before_freshness() {
        for timestamp in [
            "2026-08-30T00:00:01Z",
            "2026-08-30T00:00:01.12Z",
            "2026-08-30T00:00:01.120Z",
            "2026-08-30T00:00:01.000Z",
        ] {
            let exact = SignatureFields {
                delivery_time: timestamp,
                ..fields()
            };
            let signature = sign_v1(KEY, exact).unwrap();
            assert_eq!(
                verify_v1(
                    KEY,
                    exact,
                    &signature,
                    delivery_time(),
                    Duration::from_secs(1)
                ),
                Ok(()),
                "{timestamp}"
            );
            let changed = SignatureFields {
                delivery_time: "invalid-canary-time",
                ..exact
            };
            assert_eq!(
                verify_v1(
                    KEY,
                    changed,
                    &signature,
                    delivery_time(),
                    Duration::from_secs(1)
                ),
                Err(VerificationError::InvalidSignature)
            );
            assert_eq!(
                verify_v1(
                    KEY,
                    changed,
                    &sign_v1(KEY, changed).unwrap(),
                    delivery_time(),
                    Duration::from_secs(1)
                ),
                Err(VerificationError::InvalidDeliveryTime)
            );
            assert_eq!(
                verify_v1(
                    KEY,
                    exact,
                    &signature,
                    delivery_time() + Duration::from_secs(31),
                    Duration::from_secs(1)
                ),
                Err(VerificationError::DeliveryTimeSkew)
            );
        }
    }

    #[test]
    fn verify_v1_refuses_wrong_version_signature_and_delivery_time() {
        let signature = sign_v1(KEY, fields()).unwrap();
        assert_eq!(
            verify_v1(
                KEY,
                fields(),
                &signature.replacen("v1=", "v2=", 1),
                delivery_time(),
                Duration::from_secs(30)
            ),
            Err(VerificationError::UnsupportedVersion)
        );
        assert_eq!(
            verify_v1(
                KEY,
                fields(),
                &signature,
                delivery_time() + Duration::from_secs(31),
                Duration::from_secs(30)
            ),
            Err(VerificationError::DeliveryTimeSkew)
        );
        assert_eq!(
            verify_v1(
                KEY,
                fields(),
                &signature,
                delivery_time() - Duration::from_secs(31),
                Duration::from_secs(30)
            ),
            Err(VerificationError::DeliveryTimeSkew)
        );
        let mut invalid = fields();
        invalid.delivery_time = "2026-08-30T00:00:61Z";
        assert_eq!(
            verify_v1(
                KEY,
                invalid,
                &sign_v1(KEY, invalid).unwrap(),
                delivery_time(),
                Duration::from_secs(30)
            ),
            Err(VerificationError::InvalidDeliveryTime)
        );
    }

    #[test]
    fn verify_v1_refuses_tampering_short_keys_and_unbounded_input() {
        let signature = sign_v1(KEY, fields()).unwrap();
        let mut tampered = fields();
        tampered.body = br#"{"tampered":true}"#;
        assert_eq!(
            verify_v1(
                KEY,
                tampered,
                &signature,
                delivery_time(),
                Duration::from_secs(30)
            ),
            Err(VerificationError::InvalidSignature)
        );
        assert_eq!(
            verify_v1(
                b"short",
                fields(),
                &signature,
                delivery_time(),
                Duration::from_secs(30)
            ),
            Err(VerificationError::InvalidKey)
        );
        let oversized_body = vec![0; MAX_BODY_BYTES + 1];
        let mut oversized = fields();
        oversized.body = &oversized_body;
        assert_eq!(sign_v1(KEY, oversized), Err(SigningError::InputTooLarge));
        let oversized_id = "x".repeat(MAX_METADATA_BYTES + 1);
        let mut oversized = fields();
        oversized.id = &oversized_id;
        assert_eq!(sign_v1(KEY, oversized), Err(SigningError::InputTooLarge));
    }
}

/// The Standard Webhooks symmetric signature version.
pub const SIGNATURE_VERSION: &str = "v1";
pub const MAX_HMAC_SHA256_KEY_BYTES: usize = 64;
pub const MAX_WEBHOOK_ID_BYTES: usize = 256;
pub const MAX_SIGNATURE_ENTRIES: usize = 4;
/// Recommended freshness window in both directions.
pub const DELIVERY_TOLERANCE: Duration = Duration::from_secs(300);

const STANDARD_WEBHOOKS_TAG_ENCODED_BYTES: usize = 44;

/// Validated exact key bytes for Standard Webhooks, zeroized on drop.
pub struct DeliveryKey(Zeroizing<Vec<u8>>);

impl DeliveryKey {
    pub fn new(bytes: &[u8]) -> Result<Self, DeliveryKeyError> {
        if bytes.starts_with(b"whsec_") {
            return Err(DeliveryKeyError::SecretText);
        }
        let length = bytes.len();
        if length < MIN_HMAC_SHA256_KEY_BYTES {
            return Err(DeliveryKeyError::TooShort { length });
        }
        if length > MAX_HMAC_SHA256_KEY_BYTES {
            return Err(DeliveryKeyError::TooLong {
                length,
                trailing_newline: bytes.ends_with(b"\n"),
            });
        }
        Ok(Self(Zeroizing::new(bytes.to_vec())))
    }
}

impl std::fmt::Debug for DeliveryKey {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("[REDACTED]")
    }
}

/// Standard Webhooks keys in signing order, with an optional rotation key.
#[derive(Debug)]
pub struct DeliveryKeys {
    current: DeliveryKey,
    previous: Option<DeliveryKey>,
}

impl DeliveryKeys {
    pub fn new(
        current: DeliveryKey,
        previous: Option<DeliveryKey>,
    ) -> Result<Self, DeliveryKeyError> {
        if previous
            .as_ref()
            .is_some_and(|key| crate::constant_time_eq(&current.0, &key.0))
        {
            return Err(DeliveryKeyError::PreviousEqualsCurrent);
        }
        Ok(Self { current, previous })
    }

    fn iter(&self) -> impl Iterator<Item = &DeliveryKey> {
        std::iter::once(&self.current).chain(self.previous.iter())
    }
}

/// A Standard Webhooks key policy refusal.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DeliveryKeyError {
    #[error("the delivery key is {length} bytes. The minimum is {MIN_HMAC_SHA256_KEY_BYTES}")]
    TooShort { length: usize },
    #[error(
        "the delivery key is {length} bytes. The maximum is {MAX_HMAC_SHA256_KEY_BYTES}{}",
        if *trailing_newline { " (the last byte is a newline)" } else { "" }
    )]
    TooLong {
        length: usize,
        trailing_newline: bool,
    },
    #[error("the delivery key starts with whsec_. Supply the exact key bytes")]
    SecretText,
    #[error("the previous delivery key equals the current delivery key")]
    PreviousEqualsCurrent,
}

impl DeliveryKeyError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::TooShort { .. } => "key-too-short",
            Self::TooLong { .. } => "key-too-long",
            Self::SecretText => "key-is-secret-text",
            Self::PreviousEqualsCurrent => "previous-key-equals-current",
        }
    }
}

/// Two configuration labels that refer to the same delivery key bytes.
#[derive(Debug, Eq, PartialEq, thiserror::Error)]
#[error("delivery keys at {first:?} and {second:?} share the same bytes")]
pub struct DuplicateDeliveryKey {
    first: String,
    second: String,
}

impl DuplicateDeliveryKey {
    pub const fn code(&self) -> &'static str {
        "key-repeated"
    }
}

/// Refuse exact key reuse among the supplied configuration labels.
pub fn distinct_delivery_keys<'a>(
    keys: impl IntoIterator<Item = (&'a str, &'a DeliveryKey)>,
) -> Result<(), DuplicateDeliveryKey> {
    let mut seen: Vec<(&str, &DeliveryKey)> = Vec::new();
    for (label, key) in keys {
        if let Some((first, _)) = seen
            .iter()
            .find(|(_, prior)| crate::constant_time_eq(&prior.0, &key.0))
        {
            return Err(DuplicateDeliveryKey {
                first: (*first).to_owned(),
                second: label.to_owned(),
            });
        }
        seen.push((label, key));
    }
    Ok(())
}

/// Value-free failure while signing or verifying Standard Webhooks content.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DeliverySignatureError {
    #[error("the webhook ID is invalid")]
    InvalidId,
    #[error("the webhook timestamp is invalid")]
    InvalidTimestamp,
    #[error("the webhook timestamp is outside the allowed delivery window")]
    StaleDelivery,
    #[error("the webhook signature header is malformed")]
    MalformedSignature,
    #[error("the webhook signature header contains no supported version")]
    UnsupportedVersion,
    #[error("the webhook signature does not match")]
    SignatureMismatch,
    #[error("the webhook body exceeds {MAX_BODY_BYTES} bytes")]
    BodyTooLarge,
}

impl DeliverySignatureError {
    pub const fn code(&self) -> &'static str {
        match self {
            Self::InvalidId => "invalid-id",
            Self::InvalidTimestamp => "invalid-timestamp",
            Self::StaleDelivery => "stale-delivery",
            Self::MalformedSignature => "malformed-signature",
            Self::UnsupportedVersion => "unsupported-version",
            Self::SignatureMismatch => "signature-mismatch",
            Self::BodyTooLarge => "body-too-large",
        }
    }
}

/// Exact values from the Standard Webhooks headers and HTTP body.
#[derive(Clone, Copy)]
pub struct SignedContent<'a> {
    pub id: &'a str,
    pub timestamp: &'a str,
    pub signature: &'a str,
    pub body: &'a [u8],
}

/// Produce a Standard Webhooks signature header with the current key first.
pub fn sign(
    keys: &DeliveryKeys,
    id: &str,
    timestamp: u64,
    body: &[u8],
) -> Result<String, DeliverySignatureError> {
    validate_standard_webhooks_input(id, body)?;
    let timestamp = timestamp.to_string();
    let mut signature = String::new();
    for key in keys.iter() {
        if !signature.is_empty() {
            signature.push(' ');
        }
        let mac = standard_webhooks_mac(&key.0, id, &timestamp, body);
        signature.push_str(SIGNATURE_VERSION);
        signature.push(',');
        STANDARD.encode_string(mac.finalize().into_bytes(), &mut signature);
    }
    Ok(signature)
}

/// Authenticate the delivery and enforce the receiver's two-sided clock window.
pub fn verify(
    keys: &DeliveryKeys,
    content: SignedContent<'_>,
    now: SystemTime,
    tolerance: Duration,
) -> Result<u64, DeliverySignatureError> {
    let timestamp = verify_authenticity(keys, content)?;
    let delivery_nanos = i128::from(timestamp) * 1_000_000_000;
    if delivery_nanos.abs_diff(system_time_unix_nanos(now)) > tolerance.as_nanos() {
        return Err(DeliverySignatureError::StaleDelivery);
    }
    Ok(timestamp)
}

/// Authenticate the exact delivery bytes and return the parsed Unix timestamp.
/// The caller must enforce freshness before using the delivery.
pub fn verify_authenticity(
    keys: &DeliveryKeys,
    content: SignedContent<'_>,
) -> Result<u64, DeliverySignatureError> {
    validate_standard_webhooks_input(content.id, content.body)?;
    let timestamp = parse_webhook_timestamp(content.timestamp)?;
    let tags = parse_standard_webhooks_header(content.signature)?;
    for key in keys.iter() {
        let mac = standard_webhooks_mac(&key.0, content.id, content.timestamp, content.body);
        if tags.iter().any(|tag| mac.clone().verify_slice(tag).is_ok()) {
            return Ok(timestamp);
        }
    }
    Err(DeliverySignatureError::SignatureMismatch)
}

fn validate_standard_webhooks_input(id: &str, body: &[u8]) -> Result<(), DeliverySignatureError> {
    if id.is_empty()
        || id.len() > MAX_WEBHOOK_ID_BYTES
        || !id
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'.')
    {
        return Err(DeliverySignatureError::InvalidId);
    }
    if body.len() > MAX_BODY_BYTES {
        return Err(DeliverySignatureError::BodyTooLarge);
    }
    Ok(())
}

fn parse_webhook_timestamp(timestamp: &str) -> Result<u64, DeliverySignatureError> {
    if timestamp.is_empty()
        || timestamp.len() > 20
        || (timestamp.len() > 1 && timestamp.starts_with('0'))
        || !timestamp.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(DeliverySignatureError::InvalidTimestamp);
    }
    timestamp
        .parse()
        .map_err(|_| DeliverySignatureError::InvalidTimestamp)
}

fn parse_standard_webhooks_header(
    header: &str,
) -> Result<Vec<[u8; HMAC_SHA256_BYTES]>, DeliverySignatureError> {
    let malformed = DeliverySignatureError::MalformedSignature;
    let mut tags = Vec::new();
    for (index, entry) in header.split(' ').enumerate() {
        if index == MAX_SIGNATURE_ENTRIES {
            return Err(malformed);
        }
        let (version, value) = entry.split_once(',').ok_or(malformed)?;
        if version.is_empty() || value.is_empty() {
            return Err(malformed);
        }
        if version != SIGNATURE_VERSION {
            continue;
        }
        if value.len() != STANDARD_WEBHOOKS_TAG_ENCODED_BYTES {
            return Err(malformed);
        }
        // STANDARD requires canonical padding and zero unused bits.
        let mut tag = [0; HMAC_SHA256_BYTES];
        if STANDARD
            .decode_slice(value, &mut tag)
            .map_err(|_| malformed)?
            != tag.len()
        {
            return Err(malformed);
        }
        tags.push(tag);
    }
    if tags.is_empty() {
        return Err(DeliverySignatureError::UnsupportedVersion);
    }
    Ok(tags)
}

fn standard_webhooks_mac(key: &[u8], id: &str, timestamp: &str, body: &[u8]) -> HmacSha256 {
    let mut mac = HmacSha256::new_from_slice(key).expect("HMAC accepts keys of any length");
    mac.update(id.as_bytes());
    mac.update(b".");
    mac.update(timestamp.as_bytes());
    mac.update(b".");
    mac.update(body);
    mac
}

#[cfg(test)]
mod standard_webhooks_tests {
    use super::*;

    #[test]
    fn sign_matches_the_published_standard_webhooks_vector() {
        let key = base64::engine::general_purpose::STANDARD
            .decode("MfKQ9r8GKYqrTwjUPD8ILPZIo2LaLaSw")
            .unwrap();
        let mac = standard_webhooks_mac(
            &key,
            "msg_p5jXN8AQM9LWM0D4loKWxJek",
            "1614265330",
            br#"{"test": 2432232314}"#,
        );
        let tag = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());
        assert_eq!(
            format!("{SIGNATURE_VERSION},{tag}"),
            "v1,g0hM9SsE+OTPJTGt/tmIKtSyZlE3uFJELVlNIOLJ1OE="
        );
    }
}
