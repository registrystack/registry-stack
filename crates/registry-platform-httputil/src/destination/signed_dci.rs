// SPDX-License-Identifier: Apache-2.0
//! Product-neutral signed DCI response verification and decoding.
//!
//! The caller supplies the reviewed DCI protocol identities, selector binding,
//! locale, pagination, and byte bounds. This boundary owns the closed compact
//! RS256 JWS, fresh same-origin JWKS key selection, signed-sibling equality,
//! envelope correlation, and record-minimization rules. Integrations cannot
//! weaken those rules through product metadata or source-version labels.

use std::fmt;
use std::marker::PhantomData;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use registry_platform_canonical_json::parse_json_strict;
use registry_platform_crypto::{verify, PublicJwk};
use serde_json::{Map, Value};
use thiserror::Error;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;
use uuid::Uuid;
use zeroize::Zeroizing;

use super::json::{ClosedJsonDecoder, ClosedJsonOutcome};
use super::sensitive_json::SensitiveJsonValue;
use super::{BoundedDestinationBody, DataDestination, DataDestinationBody};

const MAX_SIGNED_DCI_JWKS_BYTES: usize = 64 * 1_024;
const MAX_SIGNED_DCI_RESPONSE_BYTES: usize = 256 * 1_024;
const MAX_JWS_HEADER_BYTES: usize = 512;
const MAX_JWS_KID_BYTES: usize = 512;
const MAX_RSA_SIGNATURE_BYTES: usize = 1_024;
const MIN_RSA_MODULUS_BITS: usize = 2_048;
const MAX_RSA_MODULUS_BITS: usize = 8_192;
const MAX_EXPECTED_IDENTIFIER_BYTES: usize = 160;
const MAX_EXPECTED_SELECTOR_BYTES: usize = 256;
const MAX_SIGNED_DCI_EXACT_COMPONENTS: usize = 8;

/// Invalid request-bound values supplied while compiling a signed DCI decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SignedDciExpectationError {
    #[error("signed DCI response expectation is invalid")]
    InvalidExpectation,
}

/// Value-free signed DCI response failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum SignedDciDecodeError {
    #[error("signed DCI JWKS response exceeds its reviewed byte bound")]
    JwksTooLarge,
    #[error("signed DCI response exceeds its reviewed byte bound")]
    ResponseTooLarge,
    #[error("signed DCI JWKS violates the closed key-set contract")]
    InvalidJwks,
    #[error("signed DCI response does not contain the required compact JWS")]
    InvalidSignedResponse,
    #[error("signed DCI key does not satisfy the pinned trust contract")]
    SigningKeyRejected,
    #[error("signed DCI response signature verification failed")]
    SignatureVerificationFailed,
    #[error("signed DCI payload does not equal its response sibling")]
    SignedPayloadMismatch,
    #[error("signed DCI response violates the closed envelope")]
    EnvelopeContractViolation,
    #[error("signed DCI response correlation does not match its request")]
    CorrelationViolation,
    #[error("signed DCI response identity does not match its request")]
    IdentityViolation,
    #[error("signed DCI record does not match its request selector")]
    SelectorBindingViolation,
    #[error("signed DCI source returned a non-success status")]
    SourceRejected,
    #[error("signed DCI response pagination is inconsistent")]
    PaginationViolation,
    #[error("signed DCI response exceeds the exact-search cardinality bound")]
    CardinalityViolation,
    #[error("signed DCI record violates its closed acquisition schema")]
    RecordContractViolation,
}

/// Bound the next signed-DCI response body by the aggregate bytes remaining
/// after the already-read verification response. Raw response bytes remain
/// opaque to the caller.
pub fn remaining_signed_dci_body_limit(
    verification_body: &DataDestinationBody,
    aggregate_limit: u64,
    per_response_limit: u32,
) -> Result<usize, SignedDciDecodeError> {
    let verification_bytes = u64::try_from(verification_body.bytes.len())
        .map_err(|_| SignedDciDecodeError::ResponseTooLarge)?;
    let remaining = aggregate_limit
        .checked_sub(verification_bytes)
        .filter(|remaining| *remaining > 0)
        .ok_or(SignedDciDecodeError::ResponseTooLarge)?;
    usize::try_from(u64::from(per_response_limit).min(remaining))
        .map_err(|_| SignedDciDecodeError::ResponseTooLarge)
}

/// Request-bound values for one reviewed signed DCI response.
pub struct SignedDciExpectation {
    message_id: Box<str>,
    sender_id: Box<str>,
    receiver_id: Option<Box<str>>,
    selector: SignedDciSelectorExpectation,
    protocol_version: Box<str>,
    registry_type: Box<str>,
    record_type: Box<str>,
    locale: Box<str>,
    page_number: u64,
    page_size: u64,
    max_jwks_bytes: usize,
    max_response_bytes: usize,
}

enum SignedDciSelectorExpectation {
    IdtypeValue {
        identifier_type: Box<str>,
        value: Zeroizing<String>,
    },
    ExactAnd(Box<[SignedDciExpectedComponent]>),
}

struct SignedDciExpectedComponent {
    response_pointer: Box<[Box<str>]>,
    value: Zeroizing<String>,
}

/// One request-bound response location in a structured DCI exact-AND selector.
pub struct SignedDciExactComponent<'a> {
    pub response_pointer: &'a str,
    pub expected_value: &'a str,
}

impl SignedDciExpectation {
    /// Compile an idtype-value selector plus exact request correlation,
    /// protocol identities, pagination, and response byte bounds.
    #[allow(clippy::too_many_arguments)]
    pub fn new_idtype_value(
        message_id: &str,
        sender_id: &str,
        receiver_id: Option<&str>,
        expected_selector: &str,
        protocol_version: &str,
        registry_type: &str,
        record_type: &str,
        identifier_type: &str,
        locale: &str,
        page_number: u64,
        page_size: u64,
        max_jwks_bytes: usize,
        max_response_bytes: usize,
    ) -> Result<Self, SignedDciExpectationError> {
        if !valid_expected_identifier(message_id)
            || !valid_expected_identifier(sender_id)
            || receiver_id.is_some_and(|value| !valid_expected_identifier(value))
            || !valid_expected_selector(expected_selector)
            || [
                protocol_version,
                registry_type,
                record_type,
                identifier_type,
                locale,
            ]
            .iter()
            .any(|value| !valid_expected_identifier(value))
            || page_number == 0
            || !(1..=2).contains(&page_size)
            || !(1..=MAX_SIGNED_DCI_JWKS_BYTES).contains(&max_jwks_bytes)
            || !(1..=MAX_SIGNED_DCI_RESPONSE_BYTES).contains(&max_response_bytes)
        {
            return Err(SignedDciExpectationError::InvalidExpectation);
        }
        Ok(Self {
            message_id: message_id.into(),
            sender_id: sender_id.into(),
            receiver_id: receiver_id.map(Into::into),
            selector: SignedDciSelectorExpectation::IdtypeValue {
                identifier_type: identifier_type.into(),
                value: Zeroizing::new(expected_selector.to_owned()),
            },
            protocol_version: protocol_version.into(),
            registry_type: registry_type.into(),
            record_type: record_type.into(),
            locale: locale.into(),
            page_number,
            page_size,
            max_jwks_bytes,
            max_response_bytes,
        })
    }

    /// Compile an exact-AND selector plus exact request correlation, protocol
    /// identities, pagination, and response byte bounds.
    #[allow(clippy::too_many_arguments)]
    pub fn new_exact_and(
        message_id: &str,
        sender_id: &str,
        receiver_id: Option<&str>,
        components: &[SignedDciExactComponent<'_>],
        protocol_version: &str,
        registry_type: &str,
        record_type: &str,
        locale: &str,
        page_number: u64,
        page_size: u64,
        max_jwks_bytes: usize,
        max_response_bytes: usize,
    ) -> Result<Self, SignedDciExpectationError> {
        if !valid_expected_identifier(message_id)
            || !valid_expected_identifier(sender_id)
            || receiver_id.is_some_and(|value| !valid_expected_identifier(value))
            || [protocol_version, registry_type, record_type, locale]
                .iter()
                .any(|value| !valid_expected_identifier(value))
            || !(1..=MAX_SIGNED_DCI_EXACT_COMPONENTS).contains(&components.len())
            || page_number == 0
            || !(1..=2).contains(&page_size)
            || !(1..=MAX_SIGNED_DCI_JWKS_BYTES).contains(&max_jwks_bytes)
            || !(1..=MAX_SIGNED_DCI_RESPONSE_BYTES).contains(&max_response_bytes)
        {
            return Err(SignedDciExpectationError::InvalidExpectation);
        }
        let mut pointers = std::collections::BTreeSet::new();
        let components = components
            .iter()
            .map(|component| {
                let response_pointer = decode_pointer(component.response_pointer)?;
                if !pointers.insert(response_pointer.clone())
                    || !valid_expected_selector(component.expected_value)
                {
                    return Err(SignedDciExpectationError::InvalidExpectation);
                }
                Ok(SignedDciExpectedComponent {
                    response_pointer,
                    value: Zeroizing::new(component.expected_value.to_owned()),
                })
            })
            .collect::<Result<Box<[_]>, _>>()?;
        Ok(Self {
            message_id: message_id.into(),
            sender_id: sender_id.into(),
            receiver_id: receiver_id.map(Into::into),
            selector: SignedDciSelectorExpectation::ExactAnd(components),
            protocol_version: protocol_version.into(),
            registry_type: registry_type.into(),
            record_type: record_type.into(),
            locale: locale.into(),
            page_number,
            page_size,
            max_jwks_bytes,
            max_response_bytes,
        })
    }
}

impl fmt::Debug for SignedDciExpectation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedDciExpectation")
            .field("message_id", &"[REDACTED]")
            .field("sender_id", &"[REDACTED]")
            .field(
                "receiver_id",
                &self.receiver_id.as_ref().map(|_| "[REDACTED]"),
            )
            .field("selector", &"[REDACTED]")
            .field("max_jwks_bytes", &self.max_jwks_bytes)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish()
    }
}

/// Closed verifier and decoder for one reviewed signed DCI response contract.
pub struct SignedDciDecoder<'decoder> {
    expected: SignedDciExpectation,
    record_decoder: Option<&'decoder ClosedJsonDecoder>,
}

impl<'decoder> SignedDciDecoder<'decoder> {
    /// Bind a request expectation to the complete logical-record schema.
    #[must_use]
    pub const fn new(
        expected: SignedDciExpectation,
        record_decoder: &'decoder ClosedJsonDecoder,
    ) -> Self {
        Self {
            expected,
            record_decoder: Some(record_decoder),
        }
    }

    /// Bind a request expectation for a reviewed Script helper.
    ///
    /// The helper verifies and releases the bounded signed payload. Record
    /// traversal remains in the hash-covered Script and therefore has no
    /// synthesized Relay operation schema.
    #[must_use]
    pub const fn new_script(expected: SignedDciExpectation) -> Self {
        Self {
            expected,
            record_decoder: None,
        }
    }

    /// Consume fresh same-origin JWKS and DCI response bodies, verify the exact
    /// signed sibling, and release only closed cardinality/projection output.
    pub fn decode(
        &self,
        jwks_body: DataDestinationBody,
        response_body: DataDestinationBody,
    ) -> Result<ClosedJsonOutcome, SignedDciDecodeError> {
        let (mut payload, envelope, _) = self.verify_payload(jwks_body, response_body)?;
        let records = SensitiveJsonValue::new(Value::Array(take_records(payload.value_mut())?));
        let records = records
            .value()
            .as_array()
            .ok_or(SignedDciDecodeError::RecordContractViolation)?;
        let mut bytes = Zeroizing::new(Vec::new());
        bytes.push(b'[');
        for (index, record) in records.iter().enumerate() {
            if index > 0 {
                bytes.push(b',');
            }
            bytes.extend_from_slice(b"{\"record\":");
            serde_json::to_writer(&mut *bytes, record)
                .map_err(|_| SignedDciDecodeError::RecordContractViolation)?;
            bytes.push(b'}');
        }
        bytes.push(b']');
        let body = BoundedDestinationBody::<DataDestination> {
            bytes,
            slot: PhantomData,
        };
        let decoded = self
            .record_decoder
            .ok_or(SignedDciDecodeError::RecordContractViolation)?
            .decode(body)
            .map_err(|_| SignedDciDecodeError::RecordContractViolation)?;

        if envelope.pagination_total_count > 1 {
            return Ok(ClosedJsonOutcome::Ambiguous);
        }
        Ok(decoded)
    }

    /// Verify and release the complete signed DCI payload for a reviewed
    /// script protocol helper. This performs the same JWS, JWKS, correlation,
    /// identity, selector, and cardinality checks as `decode`, but deliberately
    /// leaves country record traversal and projection to the reviewed adapter.
    pub fn decode_verified_payload(
        &self,
        jwks_body: DataDestinationBody,
        response_body: DataDestinationBody,
    ) -> Result<Value, SignedDciDecodeError> {
        let (payload, envelope, _) = self.verify_payload(jwks_body, response_body)?;
        let records = records(payload.value())?;
        if envelope.pagination_total_count != records.len() as u64 {
            return Err(SignedDciDecodeError::PaginationViolation);
        }
        Ok(payload.into_value())
    }

    /// Verify and release the payload together with the exact aggregate bytes
    /// consumed from the JWKS and signed-response exchanges.
    pub fn decode_verified_payload_with_encoded_bytes(
        &self,
        jwks_body: DataDestinationBody,
        response_body: DataDestinationBody,
    ) -> Result<(Value, usize), SignedDciDecodeError> {
        let (payload, envelope, encoded_bytes) = self.verify_payload(jwks_body, response_body)?;
        let records = records(payload.value())?;
        if envelope.pagination_total_count != records.len() as u64 {
            return Err(SignedDciDecodeError::PaginationViolation);
        }
        Ok((payload.into_value(), encoded_bytes))
    }

    #[doc(hidden)]
    pub fn decode_verified_payload_offline_fixture(
        &self,
        jwks_bytes: &[u8],
        response_bytes: &[u8],
    ) -> Result<Value, SignedDciDecodeError> {
        self.decode_verified_payload(
            BoundedDestinationBody {
                bytes: Zeroizing::new(jwks_bytes.to_vec()),
                slot: PhantomData,
            },
            BoundedDestinationBody {
                bytes: Zeroizing::new(response_bytes.to_vec()),
                slot: PhantomData,
            },
        )
    }

    fn verify_payload(
        &self,
        jwks_body: DataDestinationBody,
        response_body: DataDestinationBody,
    ) -> Result<(SensitiveJsonValue, ValidatedEnvelope, usize), SignedDciDecodeError> {
        let BoundedDestinationBody {
            bytes: jwks_bytes,
            slot: _,
        } = jwks_body;
        if jwks_bytes.len() > self.expected.max_jwks_bytes {
            return Err(SignedDciDecodeError::JwksTooLarge);
        }
        let jwks_encoded_bytes = jwks_bytes.len();
        let jwks = parse_json_strict(jwks_bytes.as_slice())
            .map_err(|_| SignedDciDecodeError::InvalidJwks)?;
        drop(jwks_bytes);
        let jwks = SensitiveJsonValue::new(jwks);

        let BoundedDestinationBody {
            bytes: response_bytes,
            slot: _,
        } = response_body;
        if response_bytes.len() > self.expected.max_response_bytes {
            return Err(SignedDciDecodeError::ResponseTooLarge);
        }
        let response_encoded_bytes = response_bytes.len();
        let response = parse_json_strict(response_bytes.as_slice())
            .map_err(|_| SignedDciDecodeError::InvalidSignedResponse)?;
        drop(response_bytes);
        let mut unsigned_sibling = SensitiveJsonValue::new(response);
        let compact = take_compact_signature(unsigned_sibling.value_mut())?;
        let jws = parse_compact_jws(compact.as_bytes(), self.expected.max_response_bytes)?;
        let public_key = select_signing_key(jwks.value(), jws.kid.as_str())?;
        verify(
            jws.signing_input.as_slice(),
            jws.signature.as_slice(),
            &public_key,
        )
        .map_err(|_| SignedDciDecodeError::SignatureVerificationFailed)?;

        let payload = parse_json_strict(jws.payload.as_slice())
            .map_err(|_| SignedDciDecodeError::InvalidSignedResponse)?;
        let payload = SensitiveJsonValue::new(payload);
        if payload.value() != unsigned_sibling.value() {
            return Err(SignedDciDecodeError::SignedPayloadMismatch);
        }

        let envelope = validate_envelope(payload.value(), &self.expected)?;
        let records = records(payload.value())?;
        validate_record_selector(records, &self.expected.selector)?;
        let encoded_bytes = jwks_encoded_bytes
            .checked_add(response_encoded_bytes)
            .ok_or(SignedDciDecodeError::ResponseTooLarge)?;
        Ok((payload, envelope, encoded_bytes))
    }

    /// Verify caller-owned offline fixture bytes with the exact production
    /// JWKS, JWS, envelope, selector, and record decoder path.
    #[doc(hidden)]
    pub fn decode_offline_fixture(
        &self,
        jwks_bytes: &[u8],
        response_bytes: &[u8],
    ) -> Result<ClosedJsonOutcome, SignedDciDecodeError> {
        self.decode(
            BoundedDestinationBody {
                bytes: Zeroizing::new(jwks_bytes.to_vec()),
                slot: PhantomData,
            },
            BoundedDestinationBody {
                bytes: Zeroizing::new(response_bytes.to_vec()),
                slot: PhantomData,
            },
        )
    }
}

impl fmt::Debug for SignedDciDecoder<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SignedDciDecoder")
            .field("expected", &self.expected)
            .field("record_decoder", &self.record_decoder)
            .finish()
    }
}

struct ParsedCompactJws {
    kid: Zeroizing<String>,
    signing_input: Zeroizing<Vec<u8>>,
    payload: Zeroizing<Vec<u8>>,
    signature: Zeroizing<Vec<u8>>,
}

fn take_compact_signature(response: &mut Value) -> Result<Zeroizing<String>, SignedDciDecodeError> {
    let object = response
        .as_object_mut()
        .ok_or(SignedDciDecodeError::InvalidSignedResponse)?;
    if !object_has_exact_keys(object, &["header", "message", "signature"], &[]) {
        return Err(SignedDciDecodeError::InvalidSignedResponse);
    }
    let Value::String(signature) = object
        .remove("signature")
        .ok_or(SignedDciDecodeError::InvalidSignedResponse)?
    else {
        return Err(SignedDciDecodeError::InvalidSignedResponse);
    };
    if signature.is_empty() || !signature.is_ascii() {
        return Err(SignedDciDecodeError::InvalidSignedResponse);
    }
    Ok(Zeroizing::new(signature))
}

fn parse_compact_jws(
    compact: &[u8],
    max_payload_bytes: usize,
) -> Result<ParsedCompactJws, SignedDciDecodeError> {
    let mut segments = compact.split(|byte| *byte == b'.');
    let protected = segments
        .next()
        .filter(|value| !value.is_empty())
        .ok_or(SignedDciDecodeError::InvalidSignedResponse)?;
    let payload_segment = segments
        .next()
        .filter(|value| !value.is_empty())
        .ok_or(SignedDciDecodeError::InvalidSignedResponse)?;
    let signature_segment = segments
        .next()
        .filter(|value| !value.is_empty())
        .ok_or(SignedDciDecodeError::InvalidSignedResponse)?;
    if segments.next().is_some() {
        return Err(SignedDciDecodeError::InvalidSignedResponse);
    }

    let protected_bytes = decode_base64url(protected, MAX_JWS_HEADER_BYTES)
        .ok_or(SignedDciDecodeError::InvalidSignedResponse)?;
    let protected_value = parse_json_strict(protected_bytes.as_slice())
        .map_err(|_| SignedDciDecodeError::InvalidSignedResponse)?;
    let protected_value = SensitiveJsonValue::new(protected_value);
    let protected_object = protected_value
        .value()
        .as_object()
        .filter(|object| object_has_exact_keys(object, &["alg", "kid"], &[]))
        .ok_or(SignedDciDecodeError::InvalidSignedResponse)?;
    if required_string(protected_object, "alg")
        .map_err(|_| SignedDciDecodeError::InvalidSignedResponse)?
        != "RS256"
    {
        return Err(SignedDciDecodeError::InvalidSignedResponse);
    }
    let kid = required_string(protected_object, "kid")
        .map_err(|_| SignedDciDecodeError::InvalidSignedResponse)?;
    if !valid_jwk_kid(kid) {
        return Err(SignedDciDecodeError::InvalidSignedResponse);
    }
    let kid = Zeroizing::new(kid.to_owned());
    let payload = decode_base64url(payload_segment, max_payload_bytes)
        .ok_or(SignedDciDecodeError::InvalidSignedResponse)?;
    let signature = decode_base64url(signature_segment, MAX_RSA_SIGNATURE_BYTES)
        .ok_or(SignedDciDecodeError::InvalidSignedResponse)?;

    let second_dot = protected
        .len()
        .checked_add(1)
        .and_then(|value| value.checked_add(payload_segment.len()))
        .ok_or(SignedDciDecodeError::InvalidSignedResponse)?;
    let signing_input = compact
        .get(..second_dot)
        .ok_or(SignedDciDecodeError::InvalidSignedResponse)?
        .to_vec();
    Ok(ParsedCompactJws {
        kid,
        signing_input: Zeroizing::new(signing_input),
        payload,
        signature,
    })
}

fn decode_base64url(encoded: &[u8], max_decoded_bytes: usize) -> Option<Zeroizing<Vec<u8>>> {
    let max_encoded_bytes = max_decoded_bytes
        .checked_add(2)?
        .checked_div(3)?
        .checked_mul(4)?;
    if encoded.is_empty()
        || encoded.len() > max_encoded_bytes
        || encoded.contains(&b'=')
        || !encoded.is_ascii()
    {
        return None;
    }
    let decoded = Zeroizing::new(URL_SAFE_NO_PAD.decode(encoded).ok()?);
    let canonical = Zeroizing::new(URL_SAFE_NO_PAD.encode(decoded.as_slice()));
    if decoded.len() > max_decoded_bytes || canonical.as_bytes() != encoded {
        return None;
    }
    Some(decoded)
}

fn select_signing_key(jwks: &Value, expected_kid: &str) -> Result<PublicJwk, SignedDciDecodeError> {
    let object = jwks.as_object().ok_or(SignedDciDecodeError::InvalidJwks)?;
    let keys = object
        .get("keys")
        .and_then(Value::as_array)
        .filter(|keys| (1..=16).contains(&keys.len()))
        .ok_or(SignedDciDecodeError::InvalidJwks)?;

    let mut selected = None;
    for value in keys {
        let key = value.as_object().ok_or(SignedDciDecodeError::InvalidJwks)?;
        let kid = required_string(key, "kid").map_err(|_| SignedDciDecodeError::InvalidJwks)?;
        if !valid_jwk_kid(kid) {
            return Err(SignedDciDecodeError::InvalidJwks);
        }
        if kid != expected_kid {
            continue;
        }
        if selected.is_some() {
            return Err(SignedDciDecodeError::SigningKeyRejected);
        }
        if !object_has_exact_keys(key, &["kty", "kid", "use", "alg", "n", "e"], &[]) {
            return Err(SignedDciDecodeError::InvalidJwks);
        }
        let kty = required_string(key, "kty").map_err(|_| SignedDciDecodeError::InvalidJwks)?;
        let key_use = required_string(key, "use").map_err(|_| SignedDciDecodeError::InvalidJwks)?;
        let alg = required_string(key, "alg").map_err(|_| SignedDciDecodeError::InvalidJwks)?;
        let n = required_string(key, "n").map_err(|_| SignedDciDecodeError::InvalidJwks)?;
        let e = required_string(key, "e").map_err(|_| SignedDciDecodeError::InvalidJwks)?;
        if kty != "RSA" || key_use != "sig" || alg != "RS256" {
            return Err(SignedDciDecodeError::SigningKeyRejected);
        }
        validate_rsa_public_members(n, e)?;
        selected = Some((kid, n, e));
    }
    let (kid, n, e) = selected.ok_or(SignedDciDecodeError::SigningKeyRejected)?;
    Ok(PublicJwk {
        kty: "RSA".to_owned(),
        kid: Some(kid.to_owned()),
        alg: Some("RS256".to_owned()),
        crv: None,
        x: None,
        y: None,
        n: Some(n.to_owned()),
        e: Some(e.to_owned()),
    })
}

fn validate_rsa_public_members(n: &str, e: &str) -> Result<(), SignedDciDecodeError> {
    let modulus = decode_base64url(n.as_bytes(), MAX_RSA_MODULUS_BITS.div_ceil(8))
        .ok_or(SignedDciDecodeError::SigningKeyRejected)?;
    let first = *modulus
        .first()
        .ok_or(SignedDciDecodeError::SigningKeyRejected)?;
    if first == 0 {
        return Err(SignedDciDecodeError::SigningKeyRejected);
    }
    let modulus_bits = modulus
        .len()
        .checked_sub(1)
        .and_then(|bytes| bytes.checked_mul(8))
        .and_then(|bits| bits.checked_add((u8::BITS - first.leading_zeros()) as usize))
        .ok_or(SignedDciDecodeError::SigningKeyRejected)?;
    if !(MIN_RSA_MODULUS_BITS..=MAX_RSA_MODULUS_BITS).contains(&modulus_bits) {
        return Err(SignedDciDecodeError::SigningKeyRejected);
    }

    let exponent =
        decode_base64url(e.as_bytes(), 8).ok_or(SignedDciDecodeError::SigningKeyRejected)?;
    if exponent.first() == Some(&0) {
        return Err(SignedDciDecodeError::SigningKeyRejected);
    }
    let exponent = exponent
        .iter()
        .try_fold(0_u64, |value, byte| {
            value.checked_mul(256)?.checked_add(u64::from(*byte))
        })
        .ok_or(SignedDciDecodeError::SigningKeyRejected)?;
    if exponent < 3 || exponent.is_multiple_of(2) {
        return Err(SignedDciDecodeError::SigningKeyRejected);
    }
    Ok(())
}

struct ValidatedEnvelope {
    pagination_total_count: u64,
}

fn validate_envelope(
    response: &Value,
    expected: &SignedDciExpectation,
) -> Result<ValidatedEnvelope, SignedDciDecodeError> {
    let outer = exact_object(response, &["header", "message"], &[])?;
    let header = exact_object(
        outer
            .get("header")
            .ok_or(SignedDciDecodeError::EnvelopeContractViolation)?,
        &[
            "version",
            "message_id",
            "message_ts",
            "action",
            "status",
            "total_count",
            "sender_id",
            "is_msg_encrypted",
        ],
        &["receiver_id"],
    )?;
    if required_string(header, "version")? != expected.protocol_version.as_ref()
        || required_string(header, "action")? != "on-search"
        || required_bool(header, "is_msg_encrypted")?
        || parse_rfc3339(required_string(header, "message_ts")?).is_err()
    {
        return Err(SignedDciDecodeError::EnvelopeContractViolation);
    }
    if required_string(header, "status")? != "succ" {
        return Err(SignedDciDecodeError::SourceRejected);
    }
    if required_string(header, "message_id")? != expected.message_id.as_ref() {
        return Err(SignedDciDecodeError::CorrelationViolation);
    }
    if required_string(header, "sender_id")? != expected.sender_id.as_ref()
        || optional_string(header, "receiver_id")? != expected.receiver_id.as_deref()
    {
        return Err(SignedDciDecodeError::IdentityViolation);
    }

    let message = exact_object(
        outer
            .get("message")
            .ok_or(SignedDciDecodeError::EnvelopeContractViolation)?,
        &["transaction_id", "correlation_id", "search_response"],
        &[],
    )?;
    if required_string(message, "transaction_id")? != expected.message_id.as_ref() {
        return Err(SignedDciDecodeError::CorrelationViolation);
    }
    if !is_canonical_uuid(required_string(message, "correlation_id")?) {
        return Err(SignedDciDecodeError::CorrelationViolation);
    }
    let responses = message
        .get("search_response")
        .and_then(Value::as_array)
        .filter(|responses| responses.len() == 1)
        .ok_or(SignedDciDecodeError::CardinalityViolation)?;
    let response = exact_object(
        responses
            .first()
            .ok_or(SignedDciDecodeError::CardinalityViolation)?,
        &[
            "reference_id",
            "timestamp",
            "status",
            "data",
            "pagination",
            "locale",
        ],
        &[],
    )?;
    if required_string(response, "reference_id")? != expected.message_id.as_ref() {
        return Err(SignedDciDecodeError::CorrelationViolation);
    }
    if parse_rfc3339(required_string(response, "timestamp")?).is_err() {
        return Err(SignedDciDecodeError::EnvelopeContractViolation);
    }
    if required_string(response, "status")? != "succ" {
        return Err(SignedDciDecodeError::SourceRejected);
    }

    let data = exact_object(
        response
            .get("data")
            .ok_or(SignedDciDecodeError::EnvelopeContractViolation)?,
        &["version", "reg_type", "reg_record_type", "reg_records"],
        &[],
    )?;
    if required_string(data, "version")? != expected.protocol_version.as_ref()
        || required_string(data, "reg_type")? != expected.registry_type.as_ref()
        || required_string(data, "reg_record_type")? != expected.record_type.as_ref()
        || required_string(response, "locale")? != expected.locale.as_ref()
    {
        return Err(SignedDciDecodeError::EnvelopeContractViolation);
    }
    let records = data
        .get("reg_records")
        .and_then(Value::as_array)
        .ok_or(SignedDciDecodeError::EnvelopeContractViolation)?;
    if records.len() > expected.page_size as usize
        || records.iter().any(|record| !record.is_object())
    {
        return Err(SignedDciDecodeError::CardinalityViolation);
    }
    if required_u64(header, "total_count")? != records.len() as u64 {
        return Err(SignedDciDecodeError::CardinalityViolation);
    }

    let pagination = exact_object(
        response
            .get("pagination")
            .ok_or(SignedDciDecodeError::PaginationViolation)?,
        &["page_number", "page_size", "total_count"],
        &[],
    )
    .map_err(|_| SignedDciDecodeError::PaginationViolation)?;
    let pagination_total_count = required_u64(pagination, "total_count")
        .map_err(|_| SignedDciDecodeError::PaginationViolation)?;
    if required_u64(pagination, "page_number")
        .map_err(|_| SignedDciDecodeError::PaginationViolation)?
        != expected.page_number
        || required_u64(pagination, "page_size")
            .map_err(|_| SignedDciDecodeError::PaginationViolation)?
            != expected.page_size
        || pagination_total_count < records.len() as u64
        || (pagination_total_count == 0) != records.is_empty()
    {
        return Err(SignedDciDecodeError::PaginationViolation);
    }
    Ok(ValidatedEnvelope {
        pagination_total_count,
    })
}

fn take_records(response: &mut Value) -> Result<Vec<Value>, SignedDciDecodeError> {
    response
        .get_mut("message")
        .and_then(Value::as_object_mut)
        .and_then(|message| message.get_mut("search_response"))
        .and_then(Value::as_array_mut)
        .and_then(|responses| responses.first_mut())
        .and_then(Value::as_object_mut)
        .and_then(|response| response.get_mut("data"))
        .and_then(Value::as_object_mut)
        .and_then(|data| data.get_mut("reg_records"))
        .and_then(Value::as_array_mut)
        .map(std::mem::take)
        .ok_or(SignedDciDecodeError::EnvelopeContractViolation)
}

fn records(response: &Value) -> Result<&[Value], SignedDciDecodeError> {
    response
        .get("message")
        .and_then(Value::as_object)
        .and_then(|message| message.get("search_response"))
        .and_then(Value::as_array)
        .and_then(|responses| responses.first())
        .and_then(Value::as_object)
        .and_then(|response| response.get("data"))
        .and_then(Value::as_object)
        .and_then(|data| data.get("reg_records"))
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .ok_or(SignedDciDecodeError::EnvelopeContractViolation)
}

fn validate_record_selector(
    records: &[Value],
    expected: &SignedDciSelectorExpectation,
) -> Result<(), SignedDciDecodeError> {
    for record in records {
        match expected {
            SignedDciSelectorExpectation::IdtypeValue {
                identifier_type,
                value,
            } => {
                let first_identifier = record
                    .as_object()
                    .and_then(|record| record.get("identifier"))
                    .and_then(Value::as_array)
                    .and_then(|identifiers| identifiers.first())
                    .and_then(Value::as_object)
                    .ok_or(SignedDciDecodeError::SelectorBindingViolation)?;
                if first_identifier
                    .get("identifier_type")
                    .and_then(Value::as_str)
                    != Some(identifier_type)
                    || first_identifier
                        .get("identifier_value")
                        .and_then(Value::as_str)
                        != Some(value.as_str())
                {
                    return Err(SignedDciDecodeError::SelectorBindingViolation);
                }
            }
            SignedDciSelectorExpectation::ExactAnd(components) => {
                for component in components {
                    if resolve_pointer(record, &component.response_pointer).and_then(Value::as_str)
                        != Some(component.value.as_str())
                    {
                        return Err(SignedDciDecodeError::SelectorBindingViolation);
                    }
                }
            }
        }
    }
    Ok(())
}

fn decode_pointer(pointer: &str) -> Result<Box<[Box<str>]>, SignedDciExpectationError> {
    if !pointer.starts_with('/') || pointer.len() > 512 {
        return Err(SignedDciExpectationError::InvalidExpectation);
    }
    pointer[1..]
        .split('/')
        .map(|token| {
            let mut decoded = String::new();
            let mut chars = token.chars();
            while let Some(character) = chars.next() {
                if character == '~' {
                    decoded.push(match chars.next() {
                        Some('0') => '~',
                        Some('1') => '/',
                        _ => return Err(SignedDciExpectationError::InvalidExpectation),
                    });
                } else if character.is_control() {
                    return Err(SignedDciExpectationError::InvalidExpectation);
                } else {
                    decoded.push(character);
                }
            }
            (!decoded.is_empty())
                .then(|| decoded.into_boxed_str())
                .ok_or(SignedDciExpectationError::InvalidExpectation)
        })
        .collect()
}

fn resolve_pointer<'a>(mut value: &'a Value, tokens: &[Box<str>]) -> Option<&'a Value> {
    for token in tokens {
        value = match value {
            Value::Object(object) => object.get(token.as_ref())?,
            Value::Array(array) => {
                let index = token.parse::<usize>().ok()?;
                if token.as_ref() != index.to_string() {
                    return None;
                }
                array.get(index)?
            }
            _ => return None,
        };
    }
    Some(value)
}

fn exact_object<'a>(
    value: &'a Value,
    required: &[&str],
    optional: &[&str],
) -> Result<&'a Map<String, Value>, SignedDciDecodeError> {
    value
        .as_object()
        .filter(|object| object_has_exact_keys(object, required, optional))
        .ok_or(SignedDciDecodeError::EnvelopeContractViolation)
}

fn object_has_exact_keys(
    object: &Map<String, Value>,
    required: &[&str],
    optional: &[&str],
) -> bool {
    required.iter().all(|name| object.contains_key(*name))
        && object
            .keys()
            .all(|name| required.contains(&name.as_str()) || optional.contains(&name.as_str()))
}

fn required_string<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<&'a str, SignedDciDecodeError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or(SignedDciDecodeError::EnvelopeContractViolation)
}

fn optional_string<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<Option<&'a str>, SignedDciDecodeError> {
    match object.get(field) {
        Some(Value::String(value)) => Ok(Some(value)),
        Some(_) => Err(SignedDciDecodeError::EnvelopeContractViolation),
        None => Ok(None),
    }
}

fn required_u64(object: &Map<String, Value>, field: &str) -> Result<u64, SignedDciDecodeError> {
    object
        .get(field)
        .and_then(Value::as_u64)
        .ok_or(SignedDciDecodeError::EnvelopeContractViolation)
}

fn required_bool(object: &Map<String, Value>, field: &str) -> Result<bool, SignedDciDecodeError> {
    object
        .get(field)
        .and_then(Value::as_bool)
        .ok_or(SignedDciDecodeError::EnvelopeContractViolation)
}

fn parse_rfc3339(value: &str) -> Result<OffsetDateTime, time::error::Parse> {
    OffsetDateTime::parse(value, &Rfc3339)
}

fn is_canonical_uuid(value: &str) -> bool {
    Uuid::parse_str(value)
        .ok()
        .is_some_and(|uuid| uuid.hyphenated().to_string() == value)
}

fn valid_expected_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_EXPECTED_IDENTIFIER_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'"' && byte != b'\\')
}

fn valid_expected_selector(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_EXPECTED_SELECTOR_BYTES
        && value.chars().all(|character| !character.is_control())
}

fn valid_jwk_kid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_JWS_KID_BYTES
        && value.is_ascii()
        && !value.bytes().any(|byte| byte.is_ascii_control())
}

// Both operands must remain data-slot bodies. Credential response bytes cannot
// enter this product decoder.
const _: fn(BoundedDestinationBody<DataDestination>) = |_: DataDestinationBody| {};

#[cfg(test)]
mod tests;
