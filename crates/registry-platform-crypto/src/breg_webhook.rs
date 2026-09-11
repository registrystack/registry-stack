// SPDX-License-Identifier: Apache-2.0
//! Base Registry Engine Version 1 webhook signing and verification.

use std::time::{Duration, SystemTime};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use hmac::{Hmac, KeyInit as _, Mac as _};
use sha2::Sha256;
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

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

/// Exact fields covered by a Base Registry Engine Version 1 webhook signature.
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
    validate_delivery_time(fields.delivery_time, now, allowed_skew)
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
    if parsed
        .format(&Rfc3339)
        .map_err(|_| VerificationError::InvalidDeliveryTime)?
        != value
    {
        return Err(VerificationError::InvalidDeliveryTime);
    }
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
    fn v1_fixed_vector_preserves_the_breg_wire_contract() {
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
        let mut noncanonical = fields();
        noncanonical.delivery_time = "2026-08-30T00:00:01+00:00";
        assert_eq!(
            verify_v1(
                KEY,
                noncanonical,
                &sign_v1(KEY, noncanonical).unwrap(),
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
