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
    verify_v1, SignatureFields, VerificationError, MAX_BODY_BYTES,
};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};

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

/// How the receiver bounds the signed delivery time.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DeliveryFreshness {
    /// Refuse a delivery time further than `skew` from `now`, in either
    /// direction.
    Within { now: SystemTime, skew: Duration },
    /// Check only that the delivery time is a canonical RFC 3339 instant. The
    /// caller enforces its own clock window on
    /// [`VerifiedDelivery::delivery_time`] before acting on the body.
    CallerEnforced,
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
/// canonical delivery-time validation, and constant-time HMAC comparison to
/// `registry_platform_crypto::delivery_signature::verify_v1`. A body above
/// [`MAX_BODY_BYTES`] is refused before the signature is computed; a receiver
/// that buffers the body applies the same bound before reading it.
///
/// Header values must be visible ASCII, the rule HTTP header values follow.
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
    let (now, skew) = match freshness {
        DeliveryFreshness::Within { now, skew } => (now, skew),
        DeliveryFreshness::CallerEnforced => (
            OffsetDateTime::parse(delivery_time, &Rfc3339)
                .map(SystemTime::from)
                .map_err(|_| ReceiverError::MalformedHeader)?,
            Duration::ZERO,
        ),
    };
    verify_v1(
        delivery.key,
        SignatureFields {
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
        },
        signature,
        now,
        skew,
    )
    .map_err(|error| match error {
        VerificationError::InvalidKey => ReceiverError::InvalidKey,
        VerificationError::InputTooLarge => ReceiverError::MalformedHeader,
        VerificationError::UnsupportedVersion => ReceiverError::UnsupportedVersion,
        VerificationError::InvalidSignature => ReceiverError::SignatureMismatch,
        VerificationError::InvalidDeliveryTime => ReceiverError::MalformedHeader,
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
        assert_eq!(
            verify(
                &with("x-registry-delivery-time", "yesterday"),
                BODY,
                DeliveryFreshness::CallerEnforced
            ),
            Err(ReceiverError::MalformedHeader)
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
