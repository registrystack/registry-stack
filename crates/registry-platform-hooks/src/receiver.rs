// SPDX-License-Identifier: Apache-2.0
//! Receiver-side verification of one signed Version 1 hook delivery.
//!
//! Every product that receives a signed hook delivery reads the same twelve
//! transport headers, rebuilds the same signed fields, and calls the same
//! `registry-platform-crypto` verifier. This module is that one reading, so a
//! receiver never re-derives the field order, the header set, or the
//! signature shape on its own.
//!
//! It verifies authenticity only. Which source a receiver trusts, which event
//! types and schemas it accepts, the content type it requires, its
//! deduplication on the idempotency key, and what the body means stay with
//! the receiving product, which checks them on the returned
//! [`VerifiedDelivery`].

use std::time::{Duration, SystemTime};

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use registry_platform_crypto::delivery_signature::{
    self, verify_v1, verify_v1_authenticity, DeliveryKeys, DeliverySignatureError, SignatureFields,
    SignedContent, VerificationError, MAX_BODY_BYTES,
};

use crate::{EnvelopeLimits, HookEnvelope};

const SIGNATURE_PREFIX: &str = "v1=";
const SIGNATURE_BYTES: usize = 32;
const SIGNATURE_TEXT_BYTES: usize = 43;

/// The transport headers a Version 1 delivery carries, in the order they are
/// checked. Names are matched without regard to ASCII case.
const HEADERS: [&str; 12] = [
    "ce-specversion",
    "ce-id",
    "ce-source",
    "ce-type",
    "ce-time",
    "ce-dataschema",
    "x-registry-event-generation",
    "x-registry-delivery-attempt",
    "x-registry-delivery-time",
    "content-type",
    "idempotency-key",
    "x-registry-signature",
];

/// How far a signed delivery time may be from the receiver clock, in either
/// direction, when the receiver names no window of its own.
pub const DEFAULT_DELIVERY_SKEW: Duration = delivery_signature::DELIVERY_TOLERANCE;

/// How the receiver bounds the signed delivery time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryFreshness {
    /// Refuse a delivery time further than `skew` from `now`, in either
    /// direction.
    Within { now: SystemTime, skew: Duration },
    /// The caller enforces its clock window on the verified timestamp
    /// before acting on the delivery.
    CallerEnforced,
}

impl DeliveryFreshness {
    /// The default window around `now`.
    #[must_use]
    pub const fn default_at(now: SystemTime) -> Self {
        Self::Within {
            now,
            skew: DEFAULT_DELIVERY_SKEW,
        }
    }
}

/// Required Standard Webhooks delivery headers, matched case-insensitively.
pub const HOOK_DELIVERY_HEADERS: [&str; 4] = [
    "content-type",
    "webhook-id",
    "webhook-timestamp",
    "webhook-signature",
];

/// Exact request material. The iterator must include every header occurrence.
pub struct HookDelivery<'a, H> {
    pub headers: H,
    pub body: &'a [u8],
    pub keys: &'a DeliveryKeys,
}

/// Authenticated and decoded Standard Webhooks delivery.
pub struct VerifiedHookDelivery<'a> {
    pub id: &'a str,
    pub timestamp: u64,
    pub envelope: HookEnvelope,
    pub body: &'a [u8],
}

impl std::fmt::Debug for VerifiedHookDelivery<'_> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("VerifiedHookDelivery([REDACTED])")
    }
}

/// Value-free reasons to refuse a Standard Webhooks delivery.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum HookDeliveryError {
    #[error("a required hook delivery header is missing")]
    MissingHeader,
    #[error("a required hook delivery header is repeated")]
    DuplicateHeader,
    #[error("the hook delivery content type must be application/json")]
    InvalidContentType,
    #[error(transparent)]
    Signature(#[from] DeliverySignatureError),
    #[error("the hook delivery body is not a canonical hook envelope")]
    InvalidEnvelope,
    #[error("webhook-id does not match the hook envelope id")]
    IdMismatch,
}

impl HookDeliveryError {
    /// Stable refusal code for the failed validation.
    pub const fn code(&self) -> &'static str {
        match self {
            Self::MissingHeader => "missing-header",
            Self::DuplicateHeader => "duplicate-header",
            Self::InvalidContentType => "invalid-content-type",
            Self::Signature(error) => error.code(),
            Self::InvalidEnvelope => "invalid-envelope",
            Self::IdMismatch => "id-mismatch",
        }
    }
}

/// Verify the exact received bytes before decoding the canonical hook envelope.
pub fn verify_hook_delivery<'a, H>(
    delivery: HookDelivery<'a, H>,
    freshness: DeliveryFreshness,
) -> Result<VerifiedHookDelivery<'a>, HookDeliveryError>
where
    H: IntoIterator<Item = (&'a str, &'a [u8])>,
{
    let mut headers = [None; HOOK_DELIVERY_HEADERS.len()];
    for (name, value) in delivery.headers {
        if let Some(index) = HOOK_DELIVERY_HEADERS
            .iter()
            .position(|header| name.eq_ignore_ascii_case(header))
        {
            if headers[index].replace(value).is_some() {
                return Err(HookDeliveryError::DuplicateHeader);
            }
        }
    }
    let [Some(content_type), Some(id), Some(timestamp), Some(signature)] = headers else {
        return Err(HookDeliveryError::MissingHeader);
    };
    if content_type != b"application/json" {
        return Err(HookDeliveryError::InvalidContentType);
    }

    let id = std::str::from_utf8(id).map_err(|_| DeliverySignatureError::InvalidId)?;
    let content = SignedContent {
        id,
        timestamp: std::str::from_utf8(timestamp)
            .map_err(|_| DeliverySignatureError::InvalidTimestamp)?,
        signature: std::str::from_utf8(signature)
            .map_err(|_| DeliverySignatureError::MalformedSignature)?,
        body: delivery.body,
    };
    let timestamp = match freshness {
        DeliveryFreshness::Within { now, skew } => {
            delivery_signature::verify(delivery.keys, content, now, skew)
        }
        DeliveryFreshness::CallerEnforced => {
            delivery_signature::verify_authenticity(delivery.keys, content)
        }
    }?;
    let envelope = HookEnvelope::from_canonical_bytes(delivery.body, &EnvelopeLimits::default())
        .map_err(|_| HookDeliveryError::InvalidEnvelope)?;
    if envelope.id != id {
        return Err(HookDeliveryError::IdMismatch);
    }
    Ok(VerifiedHookDelivery {
        id,
        timestamp,
        envelope,
        body: delivery.body,
    })
}

/// Exact request material of one received delivery.
///
/// `headers` yields every received header as its name and raw value bytes,
/// duplicates included, so an ambiguous signed header is refused rather than
/// resolved. The key and body are never rendered by this type or by its
/// refusal errors.
pub struct SignedDelivery<'a, H> {
    pub method: &'a str,
    pub request_target: &'a str,
    pub headers: H,
    pub body: &'a [u8],
    pub key: &'a [u8],
}

impl<H> std::fmt::Debug for SignedDelivery<'_, H> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("SignedDelivery(<redacted>)")
    }
}

/// Authenticated delivery attributes, borrowed from the received headers.
///
/// Every field is covered by the signature. The body is the caller's own
/// `body`, unchanged.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedDelivery<'a> {
    pub id: &'a str,
    pub source: &'a str,
    pub event_type: &'a str,
    pub time: &'a str,
    pub data_schema: &'a str,
    pub generation: &'a str,
    pub attempt: &'a str,
    pub delivery_time: &'a str,
    pub content_type: &'a str,
    pub idempotency_key: &'a str,
}

/// Closed, value-free reason a delivery was refused.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[non_exhaustive]
pub enum ReceiverError {
    #[error("a required hook delivery header is missing")]
    MissingHeader,
    #[error("a hook delivery header is repeated")]
    DuplicateHeader,
    #[error("a hook delivery header is malformed")]
    MalformedHeader,
    #[error("the hook delivery version is unsupported")]
    UnsupportedVersion,
    #[error("the hook delivery signature is malformed")]
    MalformedSignature,
    #[error("the hook delivery signature does not match")]
    SignatureMismatch,
    #[error("the hook delivery time is invalid; check the signed delivery time and sender clock")]
    InvalidDeliveryTime,
    #[error("the hook delivery time is outside the receiver's allowed skew")]
    Stale,
    #[error("the hook delivery body exceeds the {MAX_BODY_BYTES}-byte Version 1 signable bound")]
    BodyTooLarge,
    #[error("the hook delivery verification key is shorter than the Version 1 minimum")]
    InvalidKey,
}

/// Verify one signed Version 1 hook delivery.
///
/// Reads the transport headers, requires CloudEvents spec version `1.0`, a
/// `v1=` signature of the exact Version 1 shape and canonical positive decimal
/// generation and attempt counters, then delegates the signing input,
/// RFC 3339 delivery-time validation, and constant-time HMAC comparison to
/// `registry_platform_crypto::delivery_signature::verify_v1`. A body above
/// [`MAX_BODY_BYTES`] is refused before the signature is computed; a receiver
/// that buffers the body applies the same bound before reading it.
///
/// Header values must be visible ASCII, space or tab.
pub fn verify_delivery<'a, H>(
    delivery: SignedDelivery<'a, H>,
    freshness: DeliveryFreshness,
) -> Result<VerifiedDelivery<'a>, ReceiverError>
where
    H: IntoIterator<Item = (&'a str, &'a [u8])>,
{
    let mut slots: [Slot<'a>; HEADERS.len()] = [Slot::Missing; HEADERS.len()];
    for (name, value) in delivery.headers {
        if let Some(index) = HEADERS
            .iter()
            .position(|expected| name.eq_ignore_ascii_case(expected))
        {
            slots[index] = match slots[index] {
                Slot::Missing => Slot::Present(value),
                _ => Slot::Duplicate,
            };
        }
    }
    let mut values = [""; HEADERS.len()];
    for (index, slot) in slots.into_iter().enumerate() {
        values[index] = slot.value()?;
        if index == 0 && values[0] != "1.0" {
            return Err(ReceiverError::UnsupportedVersion);
        }
    }
    let [_, id, source, event_type, time, data_schema, generation, attempt, delivery_time, content_type, idempotency_key, signature] =
        values;

    validate_signature_shape(signature)?;
    positive_decimal(generation)?;
    positive_decimal(attempt)?;
    if delivery.body.len() > MAX_BODY_BYTES {
        return Err(ReceiverError::BodyTooLarge);
    }
    let fields = SignatureFields {
        id,
        source,
        event_type,
        time,
        data_schema,
        generation,
        attempt,
        delivery_time,
        method: delivery.method,
        request_target: delivery.request_target,
        content_type,
        idempotency_key,
        body: delivery.body,
    };
    match freshness {
        DeliveryFreshness::Within { now, skew } => {
            verify_v1(delivery.key, fields, signature, now, skew)
        }
        DeliveryFreshness::CallerEnforced => {
            verify_v1_authenticity(delivery.key, fields, signature)
        }
    }
    .map_err(|error| match error {
        VerificationError::InvalidKey => ReceiverError::InvalidKey,
        VerificationError::InputTooLarge => ReceiverError::MalformedHeader,
        VerificationError::UnsupportedVersion => ReceiverError::UnsupportedVersion,
        VerificationError::InvalidSignature => ReceiverError::SignatureMismatch,
        VerificationError::InvalidDeliveryTime => ReceiverError::InvalidDeliveryTime,
        VerificationError::DeliveryTimeSkew => ReceiverError::Stale,
    })?;

    Ok(VerifiedDelivery {
        id,
        source,
        event_type,
        time,
        data_schema,
        generation,
        attempt,
        delivery_time,
        content_type,
        idempotency_key,
    })
}

#[derive(Clone, Copy)]
enum Slot<'a> {
    Missing,
    Present(&'a [u8]),
    Duplicate,
}

impl<'a> Slot<'a> {
    fn value(self) -> Result<&'a str, ReceiverError> {
        match self {
            Self::Missing => Err(ReceiverError::MissingHeader),
            Self::Duplicate => Err(ReceiverError::DuplicateHeader),
            Self::Present(bytes) => {
                if !bytes
                    .iter()
                    .all(|byte| *byte == b'\t' || (0x20..0x7f).contains(byte))
                {
                    return Err(ReceiverError::MalformedHeader);
                }
                std::str::from_utf8(bytes).map_err(|_| ReceiverError::MalformedHeader)
            }
        }
    }
}

fn validate_signature_shape(signature: &str) -> Result<(), ReceiverError> {
    let encoded = signature
        .strip_prefix(SIGNATURE_PREFIX)
        .ok_or(ReceiverError::UnsupportedVersion)?;
    if encoded.len() != SIGNATURE_TEXT_BYTES {
        return Err(ReceiverError::MalformedSignature);
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| ReceiverError::MalformedSignature)?;
    if decoded.len() != SIGNATURE_BYTES || URL_SAFE_NO_PAD.encode(decoded) != encoded {
        return Err(ReceiverError::MalformedSignature);
    }
    Ok(())
}

fn positive_decimal(value: &str) -> Result<(), ReceiverError> {
    value
        .parse::<i64>()
        .ok()
        .filter(|parsed| *parsed > 0 && parsed.to_string() == value)
        .map(|_| ())
        .ok_or(ReceiverError::MalformedHeader)
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_platform_crypto::delivery_signature::sign_v1;

    const KEY: &[u8] = b"webhook-delivery-signing-key-0123456789abcdef";
    const HOOK_ID: &str = "00000000-0000-4000-8000-000000000001";
    const HOOK_BODY: &[u8] = br#"{"causation":{"hop":0,"root":"00000000-0000-4000-8000-000000000001"},"data":{},"dataschema":"urn:example:schema","id":"00000000-0000-4000-8000-000000000001","source":"urn:example:source","subject":{"recordReference":"example/case/42","recordRevision":3},"time":"2026-08-30T00:00:00Z","type":"case-created"}"#;

    fn hook_keys() -> DeliveryKeys {
        use registry_platform_crypto::delivery_signature::DeliveryKey;
        DeliveryKeys::new(DeliveryKey::new(&[42; 32]).unwrap(), None).unwrap()
    }

    fn with_hook_headers<T>(
        id: &str,
        run: impl FnOnce([(&str, &[u8]); 4], &DeliveryKeys) -> T,
    ) -> T {
        use registry_platform_crypto::delivery_signature::sign;
        let keys = hook_keys();
        let signature = sign(&keys, id, 1000, HOOK_BODY).unwrap();
        run(
            [
                ("content-type", b"application/json"),
                ("webhook-id", id.as_bytes()),
                ("webhook-timestamp", b"1000"),
                ("webhook-signature", signature.as_bytes()),
            ],
            &keys,
        )
    }

    #[test]
    fn verify_hook_delivery_accepts_a_signed_envelope() {
        with_hook_headers(HOOK_ID, |headers, keys| {
            let delivery = verify_hook_delivery(
                HookDelivery {
                    headers,
                    body: HOOK_BODY,
                    keys,
                },
                DeliveryFreshness::CallerEnforced,
            )
            .unwrap();
            assert_eq!(delivery.id, HOOK_ID);
            assert_eq!(delivery.envelope.id, HOOK_ID);
            assert_eq!(delivery.timestamp, 1000);
            assert_eq!(delivery.body, HOOK_BODY);
        });
    }

    #[test]
    fn verify_hook_delivery_refuses_missing_or_duplicate_headers() {
        with_hook_headers(HOOK_ID, |headers, keys| {
            for (index, (name, value)) in headers.iter().enumerate() {
                let mut missing = headers.to_vec();
                missing.remove(index);
                let repeated = [(name.to_ascii_uppercase(), *value)];
                for (headers, expected) in [
                    (missing, "missing-header"),
                    (
                        headers
                            .into_iter()
                            .chain([(repeated[0].0.as_str(), repeated[0].1)])
                            .collect(),
                        "duplicate-header",
                    ),
                ] {
                    let error = verify_hook_delivery(
                        HookDelivery {
                            headers,
                            body: HOOK_BODY,
                            keys,
                        },
                        DeliveryFreshness::CallerEnforced,
                    )
                    .unwrap_err();
                    assert_eq!(error.code(), expected);
                }
            }
        });
    }

    #[test]
    fn verify_hook_delivery_refuses_an_envelope_whose_id_differs() {
        with_hook_headers("other-event", |headers, keys| {
            let error = verify_hook_delivery(
                HookDelivery {
                    headers,
                    body: HOOK_BODY,
                    keys,
                },
                DeliveryFreshness::CallerEnforced,
            )
            .unwrap_err();
            assert_eq!(error.code(), "id-mismatch");
        });
    }

    #[test]
    fn verify_hook_delivery_checks_content_type_and_authenticity_before_decoding() {
        use registry_platform_crypto::delivery_signature::sign;
        with_hook_headers(HOOK_ID, |mut headers, keys| {
            headers[0].1 = b"application/json; charset=utf-8";
            let error = verify_hook_delivery(
                HookDelivery {
                    headers,
                    body: b"!",
                    keys,
                },
                DeliveryFreshness::CallerEnforced,
            )
            .unwrap_err();
            assert_eq!(error.code(), "invalid-content-type");
            headers[0].1 = b"application/json";
            let error = verify_hook_delivery(
                HookDelivery {
                    headers,
                    body: b"!",
                    keys,
                },
                DeliveryFreshness::CallerEnforced,
            )
            .unwrap_err();
            assert_eq!(error.code(), "signature-mismatch");
            let signature = sign(keys, HOOK_ID, 1000, b"!").unwrap();
            let headers = [
                headers[0],
                headers[1],
                headers[2],
                ("webhook-signature", signature.as_bytes()),
            ];
            let error = verify_hook_delivery(
                HookDelivery {
                    headers,
                    body: b"!",
                    keys,
                },
                DeliveryFreshness::CallerEnforced,
            )
            .unwrap_err();
            assert_eq!(error.code(), "invalid-envelope");
        });
    }

    #[test]
    fn verify_hook_delivery_applies_300_seconds_by_default() {
        with_hook_headers(HOOK_ID, |headers, keys| {
            for now in [700, 1300] {
                assert!(verify_hook_delivery(
                    HookDelivery {
                        headers,
                        body: HOOK_BODY,
                        keys
                    },
                    DeliveryFreshness::default_at(
                        SystemTime::UNIX_EPOCH + Duration::from_secs(now)
                    )
                )
                .is_ok());
            }
            for now in [699, 1301] {
                let error = verify_hook_delivery(
                    HookDelivery {
                        headers,
                        body: HOOK_BODY,
                        keys,
                    },
                    DeliveryFreshness::default_at(
                        SystemTime::UNIX_EPOCH + Duration::from_secs(now),
                    ),
                )
                .unwrap_err();
                assert_eq!(error.code(), "stale-delivery");
            }
        });
    }

    const BODY: &[u8] = br#"{"entity":"case","values":{"label":"value"}}"#;
    const TARGET: &str = "/hooks/registry";
    // The crypto crate's fixed Version 1 vector for these exact fields.
    const SIGNATURE: &str = "v1=OzL5k0ghZJb9nPbb-JOVsroWeanipBlZXbeKDd52RcM";

    fn headers() -> Vec<(String, String)> {
        [
            ("Ce-Specversion", "1.0"),
            ("CE-ID", "00000000-0000-4000-8000-000000000001"),
            (
                "ce-source",
                "urn:registrystack:registry:example:instance:primary",
            ),
            ("ce-type", "case-created-v1"),
            ("ce-time", "2026-08-30T00:00:00Z"),
            (
                "ce-dataschema",
                "urn:registrystack:registry:example:event:case-created-v1:schema:sha256:aaa",
            ),
            ("x-registry-event-generation", "1"),
            ("x-registry-delivery-attempt", "1"),
            ("x-registry-delivery-time", "2026-08-30T00:00:01Z"),
            (
                "idempotency-key",
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
            ("content-type", "application/json"),
            ("accept", "application/json"),
            ("x-registry-signature", SIGNATURE),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect()
    }

    fn delivery_instant() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(1_788_048_001)
    }

    fn verify<'a>(
        headers: &'a [(String, String)],
        body: &'a [u8],
        freshness: DeliveryFreshness,
    ) -> Result<VerifiedDelivery<'a>, ReceiverError> {
        verify_delivery(
            SignedDelivery {
                method: "POST",
                request_target: TARGET,
                headers: headers
                    .iter()
                    .map(|(name, value)| (name.as_str(), value.as_bytes())),
                body,
                key: KEY,
            },
            freshness,
        )
    }

    fn with(name: &str, value: &str) -> Vec<(String, String)> {
        let mut changed = headers();
        changed
            .iter_mut()
            .find(|(existing, _)| existing.eq_ignore_ascii_case(name))
            .expect("known header")
            .1 = value.to_owned();
        changed
    }

    fn without(name: &str) -> Vec<(String, String)> {
        let mut changed = headers();
        changed.retain(|(existing, _)| !existing.eq_ignore_ascii_case(name));
        changed
    }

    #[test]
    fn the_fixed_vector_verifies_and_returns_every_signed_attribute() {
        let headers = headers();
        let verified = verify(&headers, BODY, DeliveryFreshness::CallerEnforced).unwrap();
        assert_eq!(
            verified,
            VerifiedDelivery {
                id: "00000000-0000-4000-8000-000000000001",
                source: "urn:registrystack:registry:example:instance:primary",
                event_type: "case-created-v1",
                time: "2026-08-30T00:00:00Z",
                data_schema:
                    "urn:registrystack:registry:example:event:case-created-v1:schema:sha256:aaa",
                generation: "1",
                attempt: "1",
                delivery_time: "2026-08-30T00:00:01Z",
                content_type: "application/json",
                idempotency_key:
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            }
        );
    }

    #[test]
    fn the_receiver_clock_window_is_applied_only_when_asked() {
        let headers = headers();
        let fresh = DeliveryFreshness::Within {
            now: delivery_instant() + Duration::from_secs(30),
            skew: Duration::from_secs(30),
        };
        assert!(verify(&headers, BODY, fresh).is_ok());
        let stale = DeliveryFreshness::Within {
            now: delivery_instant() + Duration::from_secs(31),
            skew: Duration::from_secs(30),
        };
        assert_eq!(verify(&headers, BODY, stale), Err(ReceiverError::Stale));
        assert!(
            verify(&headers, BODY, DeliveryFreshness::CallerEnforced).is_ok(),
            "the caller owns the clock window"
        );
    }

    #[test]
    fn the_default_window_is_300_seconds_in_both_directions() {
        assert_eq!(DEFAULT_DELIVERY_SKEW, Duration::from_secs(300));
        let headers = headers();
        let at = |now: SystemTime| verify(&headers, BODY, DeliveryFreshness::default_at(now));
        let delivered = delivery_instant();
        assert!(at(delivered + Duration::from_secs(300)).is_ok());
        assert_eq!(
            at(delivered + Duration::from_secs(301)),
            Err(ReceiverError::Stale)
        );
        assert!(at(delivered - Duration::from_secs(300)).is_ok());
        assert_eq!(
            at(delivered - Duration::from_secs(301)),
            Err(ReceiverError::Stale)
        );
    }

    #[test]
    fn every_signed_header_is_required_and_bound() {
        for name in HEADERS {
            assert_eq!(
                verify(&without(name), BODY, DeliveryFreshness::CallerEnforced),
                Err(ReceiverError::MissingHeader),
                "{name}"
            );
        }
        for (name, value) in [
            ("ce-id", "00000000-0000-4000-8000-000000000002"),
            (
                "ce-source",
                "urn:registrystack:registry:other:instance:primary",
            ),
            ("ce-type", "case-patched-v1"),
            ("ce-time", "2026-08-30T00:00:02Z"),
            ("ce-dataschema", "urn:example:other"),
            ("x-registry-event-generation", "2"),
            ("x-registry-delivery-attempt", "2"),
            ("x-registry-delivery-time", "2026-08-30T00:00:02Z"),
            ("content-type", "text/plain"),
            ("idempotency-key", "sha256:other"),
        ] {
            assert_eq!(
                verify(&with(name, value), BODY, DeliveryFreshness::CallerEnforced),
                Err(ReceiverError::SignatureMismatch),
                "{name}"
            );
        }
        let headers = headers();
        assert_eq!(
            verify(&headers, b"{}", DeliveryFreshness::CallerEnforced),
            Err(ReceiverError::SignatureMismatch)
        );
        let moved = verify_delivery(
            SignedDelivery {
                method: "POST",
                request_target: "/elsewhere",
                headers: headers
                    .iter()
                    .map(|(name, value)| (name.as_str(), value.as_bytes())),
                body: BODY,
                key: KEY,
            },
            DeliveryFreshness::CallerEnforced,
        );
        assert_eq!(moved, Err(ReceiverError::SignatureMismatch));
    }

    #[test]
    fn a_repeated_signed_header_is_refused_in_any_case_spelling() {
        let mut repeated = headers();
        repeated.push(("CE-SOURCE".into(), "urn:example:other".into()));
        assert_eq!(
            verify(&repeated, BODY, DeliveryFreshness::CallerEnforced),
            Err(ReceiverError::DuplicateHeader)
        );
        let mut unrelated = headers();
        unrelated.push(("accept".into(), "text/plain".into()));
        assert!(
            verify(&unrelated, BODY, DeliveryFreshness::CallerEnforced).is_ok(),
            "an unsigned header may repeat"
        );
    }

    #[test]
    fn version_shape_and_counter_refusals_are_distinct() {
        assert_eq!(
            verify(
                &with("ce-specversion", "0.3"),
                BODY,
                DeliveryFreshness::CallerEnforced
            ),
            Err(ReceiverError::UnsupportedVersion)
        );
        assert_eq!(
            verify(
                &with("x-registry-signature", &SIGNATURE.replacen("v1=", "v2=", 1)),
                BODY,
                DeliveryFreshness::CallerEnforced
            ),
            Err(ReceiverError::UnsupportedVersion)
        );
        for malformed in [
            "v1=truncated",
            "v1=OzL5k0ghZJb9nPbb-JOVsroWeanipBlZXbeKDd52RcN",
        ] {
            assert_eq!(
                verify(
                    &with("x-registry-signature", malformed),
                    BODY,
                    DeliveryFreshness::CallerEnforced
                ),
                Err(ReceiverError::MalformedSignature),
                "{malformed}"
            );
        }
        for counter in ["0", "-1", "01", "+1", "1.0", "", "9223372036854775808"] {
            for name in ["x-registry-event-generation", "x-registry-delivery-attempt"] {
                assert_eq!(
                    verify(
                        &with(name, counter),
                        BODY,
                        DeliveryFreshness::CallerEnforced
                    ),
                    Err(ReceiverError::MalformedHeader),
                    "{name}={counter}"
                );
            }
        }
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../registry-platform-crypto/tests/fixtures/delivery-signatures.json"
        ))
        .unwrap();
        let vector = vectors
            .as_array()
            .unwrap()
            .iter()
            .find(|value| value["valid"] == false)
            .unwrap();
        let mut invalid_headers = with(
            "x-registry-delivery-time",
            vector["deliveryTime"].as_str().unwrap(),
        );
        for (name, value) in &mut invalid_headers {
            if *name == "x-registry-signature" {
                *value = vector["signature"].as_str().unwrap().to_owned();
            }
        }
        let invalid_delivery_time =
            verify(&invalid_headers, BODY, DeliveryFreshness::CallerEnforced);
        assert_eq!(
            invalid_delivery_time,
            Err(ReceiverError::InvalidDeliveryTime)
        );
        assert_eq!(
            invalid_delivery_time.unwrap_err().to_string(),
            "the hook delivery time is invalid; check the signed delivery time and sender clock"
        );
        assert_eq!(
            verify(
                &with("ce-type", "case-created-v1\u{e9}"),
                BODY,
                DeliveryFreshness::CallerEnforced
            ),
            Err(ReceiverError::MalformedHeader),
            "header values are visible ASCII"
        );
    }

    #[test]
    fn the_body_bound_is_the_signable_bound() {
        let oversized = vec![b' '; MAX_BODY_BYTES + 1];
        let mut headers = headers();
        let signable = vec![b' '; MAX_BODY_BYTES];
        let signature = sign_v1(
            KEY,
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
                request_target: TARGET,
                content_type: "application/json",
                idempotency_key:
                    "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                body: &signable,
            },
        )
        .unwrap();
        headers.retain(|(name, _)| name != "x-registry-signature");
        headers.push(("x-registry-signature".into(), signature));
        assert!(verify(&headers, &signable, DeliveryFreshness::CallerEnforced).is_ok());
        let error = verify(&headers, &oversized, DeliveryFreshness::CallerEnforced).unwrap_err();
        assert_eq!(error, ReceiverError::BodyTooLarge);
        assert!(
            error.to_string().contains("1048576-byte"),
            "the refusal names the limit: {error}"
        );
    }

    #[test]
    fn a_short_key_is_refused_without_rendering_it() {
        let headers = headers();
        let error = verify_delivery(
            SignedDelivery {
                method: "POST",
                request_target: TARGET,
                headers: headers
                    .iter()
                    .map(|(name, value)| (name.as_str(), value.as_bytes())),
                body: BODY,
                key: b"tiny-key-material",
            },
            DeliveryFreshness::CallerEnforced,
        )
        .unwrap_err();
        assert_eq!(error, ReceiverError::InvalidKey);
        assert!(!error.to_string().contains("tiny-key-material"));
    }
}
