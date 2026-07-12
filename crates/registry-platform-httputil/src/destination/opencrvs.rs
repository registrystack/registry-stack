// SPDX-License-Identifier: Apache-2.0
//! OpenCRVS DCI v1.9.0-rc.1 signed response decoding.
//!
//! This is deliberately a product-and-release-specific boundary, not a generic
//! JWS or DCI extension framework. The pinned OpenCRVS adapter signs an exact
//! DCI response sibling with a compact RS256 JWS and publishes the fresh key in
//! a same-origin JWKS response. Keeping those rules closed here prevents Relay
//! integration packs from weakening key selection, envelope correlation, or
//! record minimization through configuration.

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

const OPENCRVS_DCI_VERSION: &str = "1.0.0";
const OPENCRVS_REGISTRY_TYPE: &str = "ns:org:RegistryType:Civil";
const OPENCRVS_RECORD_TYPE: &str = "spdci-extensions-dci:Person";
const OPENCRVS_LOCALE: &str = "eng";
const OPENCRVS_PAGE_NUMBER: u64 = 1;
const OPENCRVS_PAGE_SIZE: u64 = 2;
const MAX_OPENCRVS_JWKS_BYTES: usize = 64 * 1_024;
const MAX_OPENCRVS_SIGNED_RESPONSE_BYTES: usize = 256 * 1_024;
const MAX_JWS_HEADER_BYTES: usize = 512;
const MAX_JWS_KID_BYTES: usize = 512;
const MAX_RSA_SIGNATURE_BYTES: usize = 1_024;
const MIN_RSA_MODULUS_BITS: usize = 2_048;
const MAX_RSA_MODULUS_BITS: usize = 8_192;
const MAX_EXPECTED_IDENTIFIER_BYTES: usize = 160;

/// Invalid request-bound values supplied while compiling an OpenCRVS decoder.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum OpenCrvsDciV190Rc1ExpectationError {
    #[error("OpenCRVS DCI response expectation is invalid")]
    InvalidExpectation,
}

/// Value-free OpenCRVS signed-response failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum OpenCrvsDciV190Rc1DecodeError {
    #[error("OpenCRVS JWKS response exceeds its reviewed byte bound")]
    JwksTooLarge,
    #[error("OpenCRVS signed response exceeds its reviewed byte bound")]
    ResponseTooLarge,
    #[error("OpenCRVS JWKS violates the closed key-set contract")]
    InvalidJwks,
    #[error("OpenCRVS response does not contain the required compact JWS")]
    InvalidSignedResponse,
    #[error("OpenCRVS signing key does not satisfy the pinned trust contract")]
    SigningKeyRejected,
    #[error("OpenCRVS response signature verification failed")]
    SignatureVerificationFailed,
    #[error("OpenCRVS signed payload does not equal its response sibling")]
    SignedPayloadMismatch,
    #[error("OpenCRVS response violates the closed DCI envelope")]
    EnvelopeContractViolation,
    #[error("OpenCRVS response correlation does not match its request")]
    CorrelationViolation,
    #[error("OpenCRVS response identity does not match its request")]
    IdentityViolation,
    #[error("OpenCRVS returned a non-success DCI status")]
    SourceRejected,
    #[error("OpenCRVS response pagination is inconsistent")]
    PaginationViolation,
    #[error("OpenCRVS response exceeds the exact-search cardinality bound")]
    CardinalityViolation,
    #[error("OpenCRVS record violates its closed acquisition schema")]
    RecordContractViolation,
}

/// Request-bound values for one pinned OpenCRVS exact DCI response.
pub struct OpenCrvsDciV190Rc1Expectation {
    message_id: Box<str>,
    sender_id: Box<str>,
    receiver_id: Option<Box<str>>,
    max_jwks_bytes: usize,
    max_response_bytes: usize,
}

impl OpenCrvsDciV190Rc1Expectation {
    /// Compile exact request correlation, identities, and response byte bounds.
    pub fn new(
        message_id: &str,
        sender_id: &str,
        receiver_id: Option<&str>,
        max_jwks_bytes: usize,
        max_response_bytes: usize,
    ) -> Result<Self, OpenCrvsDciV190Rc1ExpectationError> {
        if !valid_expected_identifier(message_id)
            || !valid_expected_identifier(sender_id)
            || receiver_id.is_some_and(|value| !valid_expected_identifier(value))
            || !(1..=MAX_OPENCRVS_JWKS_BYTES).contains(&max_jwks_bytes)
            || !(1..=MAX_OPENCRVS_SIGNED_RESPONSE_BYTES).contains(&max_response_bytes)
        {
            return Err(OpenCrvsDciV190Rc1ExpectationError::InvalidExpectation);
        }
        Ok(Self {
            message_id: message_id.into(),
            sender_id: sender_id.into(),
            receiver_id: receiver_id.map(Into::into),
            max_jwks_bytes,
            max_response_bytes,
        })
    }
}

impl fmt::Debug for OpenCrvsDciV190Rc1Expectation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenCrvsDciV190Rc1Expectation")
            .field("message_id", &"[REDACTED]")
            .field("sender_id", &"[REDACTED]")
            .field(
                "receiver_id",
                &self.receiver_id.as_ref().map(|_| "[REDACTED]"),
            )
            .field("max_jwks_bytes", &self.max_jwks_bytes)
            .field("max_response_bytes", &self.max_response_bytes)
            .finish()
    }
}

/// Closed decoder for the pinned OpenCRVS DCI response contract.
pub struct OpenCrvsDciV190Rc1Decoder<'decoder> {
    expected: OpenCrvsDciV190Rc1Expectation,
    record_decoder: &'decoder ClosedJsonDecoder,
}

impl<'decoder> OpenCrvsDciV190Rc1Decoder<'decoder> {
    /// Bind a request expectation to the complete logical-record schema.
    #[must_use]
    pub const fn new(
        expected: OpenCrvsDciV190Rc1Expectation,
        record_decoder: &'decoder ClosedJsonDecoder,
    ) -> Self {
        Self {
            expected,
            record_decoder,
        }
    }

    /// Consume fresh same-origin JWKS and DCI response bodies, verify the exact
    /// signed sibling, and release only closed cardinality/projection output.
    pub fn decode(
        &self,
        jwks_body: DataDestinationBody,
        response_body: DataDestinationBody,
    ) -> Result<ClosedJsonOutcome, OpenCrvsDciV190Rc1DecodeError> {
        let BoundedDestinationBody {
            bytes: jwks_bytes,
            slot: _,
        } = jwks_body;
        if jwks_bytes.len() > self.expected.max_jwks_bytes {
            return Err(OpenCrvsDciV190Rc1DecodeError::JwksTooLarge);
        }
        let jwks = parse_json_strict(jwks_bytes.as_slice())
            .map_err(|_| OpenCrvsDciV190Rc1DecodeError::InvalidJwks)?;
        drop(jwks_bytes);
        let jwks = SensitiveJsonValue::new(jwks);

        let BoundedDestinationBody {
            bytes: response_bytes,
            slot: _,
        } = response_body;
        if response_bytes.len() > self.expected.max_response_bytes {
            return Err(OpenCrvsDciV190Rc1DecodeError::ResponseTooLarge);
        }
        let response = parse_json_strict(response_bytes.as_slice())
            .map_err(|_| OpenCrvsDciV190Rc1DecodeError::InvalidSignedResponse)?;
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
        .map_err(|_| OpenCrvsDciV190Rc1DecodeError::SignatureVerificationFailed)?;

        let payload = parse_json_strict(jws.payload.as_slice())
            .map_err(|_| OpenCrvsDciV190Rc1DecodeError::InvalidSignedResponse)?;
        let mut payload = SensitiveJsonValue::new(payload);
        if payload.value() != unsigned_sibling.value() {
            return Err(OpenCrvsDciV190Rc1DecodeError::SignedPayloadMismatch);
        }

        let envelope = validate_envelope(payload.value(), &self.expected)?;
        let records = take_records(payload.value_mut())?;
        let logical_records = records
            .into_iter()
            .map(|record| {
                let mut logical = Map::new();
                logical.insert("record".to_owned(), record);
                SensitiveJsonValue::new(Value::Object(logical))
            })
            .collect::<Vec<_>>();

        let mut decoded = Vec::with_capacity(logical_records.len());
        for record in &logical_records {
            let mut bytes = Zeroizing::new(Vec::new());
            serde_json::to_writer(&mut *bytes, record.value())
                .map_err(|_| OpenCrvsDciV190Rc1DecodeError::RecordContractViolation)?;
            let body = BoundedDestinationBody::<DataDestination> {
                bytes,
                slot: PhantomData,
            };
            let outcome = self
                .record_decoder
                .decode(body)
                .map_err(|_| OpenCrvsDciV190Rc1DecodeError::RecordContractViolation)?;
            if !matches!(outcome, ClosedJsonOutcome::One(_)) {
                return Err(OpenCrvsDciV190Rc1DecodeError::RecordContractViolation);
            }
            decoded.push(outcome);
        }

        if envelope.pagination_total_count > 1 || decoded.len() > 1 {
            return Ok(ClosedJsonOutcome::Ambiguous);
        }
        match decoded.pop() {
            Some(outcome) => Ok(outcome),
            None => Ok(ClosedJsonOutcome::NoMatch),
        }
    }
}

impl fmt::Debug for OpenCrvsDciV190Rc1Decoder<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OpenCrvsDciV190Rc1Decoder")
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

fn take_compact_signature(
    response: &mut Value,
) -> Result<Zeroizing<String>, OpenCrvsDciV190Rc1DecodeError> {
    let object = response
        .as_object_mut()
        .ok_or(OpenCrvsDciV190Rc1DecodeError::InvalidSignedResponse)?;
    if !object_has_exact_keys(object, &["header", "message", "signature"], &[]) {
        return Err(OpenCrvsDciV190Rc1DecodeError::InvalidSignedResponse);
    }
    let Value::String(signature) = object
        .remove("signature")
        .ok_or(OpenCrvsDciV190Rc1DecodeError::InvalidSignedResponse)?
    else {
        return Err(OpenCrvsDciV190Rc1DecodeError::InvalidSignedResponse);
    };
    if signature.is_empty() || !signature.is_ascii() {
        return Err(OpenCrvsDciV190Rc1DecodeError::InvalidSignedResponse);
    }
    Ok(Zeroizing::new(signature))
}

fn parse_compact_jws(
    compact: &[u8],
    max_payload_bytes: usize,
) -> Result<ParsedCompactJws, OpenCrvsDciV190Rc1DecodeError> {
    let mut segments = compact.split(|byte| *byte == b'.');
    let protected = segments
        .next()
        .filter(|value| !value.is_empty())
        .ok_or(OpenCrvsDciV190Rc1DecodeError::InvalidSignedResponse)?;
    let payload_segment = segments
        .next()
        .filter(|value| !value.is_empty())
        .ok_or(OpenCrvsDciV190Rc1DecodeError::InvalidSignedResponse)?;
    let signature_segment = segments
        .next()
        .filter(|value| !value.is_empty())
        .ok_or(OpenCrvsDciV190Rc1DecodeError::InvalidSignedResponse)?;
    if segments.next().is_some() {
        return Err(OpenCrvsDciV190Rc1DecodeError::InvalidSignedResponse);
    }

    let protected_bytes = decode_base64url(protected, MAX_JWS_HEADER_BYTES)
        .ok_or(OpenCrvsDciV190Rc1DecodeError::InvalidSignedResponse)?;
    let protected_value = parse_json_strict(protected_bytes.as_slice())
        .map_err(|_| OpenCrvsDciV190Rc1DecodeError::InvalidSignedResponse)?;
    let protected_value = SensitiveJsonValue::new(protected_value);
    let protected_object = protected_value
        .value()
        .as_object()
        .filter(|object| object_has_exact_keys(object, &["alg", "kid"], &[]))
        .ok_or(OpenCrvsDciV190Rc1DecodeError::InvalidSignedResponse)?;
    if required_string(protected_object, "alg")
        .map_err(|_| OpenCrvsDciV190Rc1DecodeError::InvalidSignedResponse)?
        != "RS256"
    {
        return Err(OpenCrvsDciV190Rc1DecodeError::InvalidSignedResponse);
    }
    let kid = required_string(protected_object, "kid")
        .map_err(|_| OpenCrvsDciV190Rc1DecodeError::InvalidSignedResponse)?;
    if !valid_jwk_kid(kid) {
        return Err(OpenCrvsDciV190Rc1DecodeError::InvalidSignedResponse);
    }
    let kid = Zeroizing::new(kid.to_owned());
    let payload = decode_base64url(payload_segment, max_payload_bytes)
        .ok_or(OpenCrvsDciV190Rc1DecodeError::InvalidSignedResponse)?;
    let signature = decode_base64url(signature_segment, MAX_RSA_SIGNATURE_BYTES)
        .ok_or(OpenCrvsDciV190Rc1DecodeError::InvalidSignedResponse)?;

    let second_dot = protected
        .len()
        .checked_add(1)
        .and_then(|value| value.checked_add(payload_segment.len()))
        .ok_or(OpenCrvsDciV190Rc1DecodeError::InvalidSignedResponse)?;
    let signing_input = compact
        .get(..second_dot)
        .ok_or(OpenCrvsDciV190Rc1DecodeError::InvalidSignedResponse)?
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

fn select_signing_key(
    jwks: &Value,
    expected_kid: &str,
) -> Result<PublicJwk, OpenCrvsDciV190Rc1DecodeError> {
    let object = jwks
        .as_object()
        .filter(|object| object_has_exact_keys(object, &["keys"], &[]))
        .ok_or(OpenCrvsDciV190Rc1DecodeError::InvalidJwks)?;
    let keys = object
        .get("keys")
        .and_then(Value::as_array)
        .filter(|keys| keys.len() == 2)
        .ok_or(OpenCrvsDciV190Rc1DecodeError::InvalidJwks)?;

    let mut selected = None;
    let mut signing_key_count = 0_usize;
    let mut encryption_key_count = 0_usize;
    let mut signing_kid = None;
    let mut encryption_kid = None;
    for value in keys {
        let key = value
            .as_object()
            .filter(|key| object_has_exact_keys(key, &["kty", "kid", "use", "alg", "n", "e"], &[]))
            .ok_or(OpenCrvsDciV190Rc1DecodeError::InvalidJwks)?;
        let kty =
            required_string(key, "kty").map_err(|_| OpenCrvsDciV190Rc1DecodeError::InvalidJwks)?;
        let kid =
            required_string(key, "kid").map_err(|_| OpenCrvsDciV190Rc1DecodeError::InvalidJwks)?;
        let key_use =
            required_string(key, "use").map_err(|_| OpenCrvsDciV190Rc1DecodeError::InvalidJwks)?;
        let alg =
            required_string(key, "alg").map_err(|_| OpenCrvsDciV190Rc1DecodeError::InvalidJwks)?;
        let n =
            required_string(key, "n").map_err(|_| OpenCrvsDciV190Rc1DecodeError::InvalidJwks)?;
        let e =
            required_string(key, "e").map_err(|_| OpenCrvsDciV190Rc1DecodeError::InvalidJwks)?;
        if kty != "RSA" || !valid_jwk_kid(kid) {
            return Err(OpenCrvsDciV190Rc1DecodeError::InvalidJwks);
        }
        validate_rsa_public_members(n, e)?;

        if key_use == "sig" && alg == "RS256" {
            signing_key_count = signing_key_count
                .checked_add(1)
                .ok_or(OpenCrvsDciV190Rc1DecodeError::InvalidJwks)?;
            if kid == expected_kid && selected.replace((kid, n, e)).is_some() {
                return Err(OpenCrvsDciV190Rc1DecodeError::SigningKeyRejected);
            }
            signing_kid = Some(kid);
        } else if key_use == "enc" && alg == "RSA-OAEP-256" {
            encryption_key_count = encryption_key_count
                .checked_add(1)
                .ok_or(OpenCrvsDciV190Rc1DecodeError::InvalidJwks)?;
            encryption_kid = Some(kid);
        } else {
            return Err(OpenCrvsDciV190Rc1DecodeError::InvalidJwks);
        }
    }
    if signing_key_count != 1 || encryption_key_count != 1 || signing_kid == encryption_kid {
        return Err(OpenCrvsDciV190Rc1DecodeError::InvalidJwks);
    }
    let (kid, n, e) = selected.ok_or(OpenCrvsDciV190Rc1DecodeError::SigningKeyRejected)?;
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

fn validate_rsa_public_members(n: &str, e: &str) -> Result<(), OpenCrvsDciV190Rc1DecodeError> {
    let modulus = decode_base64url(n.as_bytes(), MAX_RSA_MODULUS_BITS.div_ceil(8))
        .ok_or(OpenCrvsDciV190Rc1DecodeError::SigningKeyRejected)?;
    let first = *modulus
        .first()
        .ok_or(OpenCrvsDciV190Rc1DecodeError::SigningKeyRejected)?;
    if first == 0 {
        return Err(OpenCrvsDciV190Rc1DecodeError::SigningKeyRejected);
    }
    let modulus_bits = modulus
        .len()
        .checked_sub(1)
        .and_then(|bytes| bytes.checked_mul(8))
        .and_then(|bits| bits.checked_add((u8::BITS - first.leading_zeros()) as usize))
        .ok_or(OpenCrvsDciV190Rc1DecodeError::SigningKeyRejected)?;
    if !(MIN_RSA_MODULUS_BITS..=MAX_RSA_MODULUS_BITS).contains(&modulus_bits) {
        return Err(OpenCrvsDciV190Rc1DecodeError::SigningKeyRejected);
    }

    let exponent = decode_base64url(e.as_bytes(), 8)
        .ok_or(OpenCrvsDciV190Rc1DecodeError::SigningKeyRejected)?;
    if exponent.first() == Some(&0) {
        return Err(OpenCrvsDciV190Rc1DecodeError::SigningKeyRejected);
    }
    let exponent = exponent
        .iter()
        .try_fold(0_u64, |value, byte| {
            value.checked_mul(256)?.checked_add(u64::from(*byte))
        })
        .ok_or(OpenCrvsDciV190Rc1DecodeError::SigningKeyRejected)?;
    if exponent < 3 || exponent.is_multiple_of(2) {
        return Err(OpenCrvsDciV190Rc1DecodeError::SigningKeyRejected);
    }
    Ok(())
}

struct ValidatedEnvelope {
    pagination_total_count: u64,
}

fn validate_envelope(
    response: &Value,
    expected: &OpenCrvsDciV190Rc1Expectation,
) -> Result<ValidatedEnvelope, OpenCrvsDciV190Rc1DecodeError> {
    let outer = exact_object(response, &["header", "message"], &[])?;
    let header = exact_object(
        outer
            .get("header")
            .ok_or(OpenCrvsDciV190Rc1DecodeError::EnvelopeContractViolation)?,
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
    if required_string(header, "version")? != OPENCRVS_DCI_VERSION
        || required_string(header, "action")? != "on-search"
        || required_bool(header, "is_msg_encrypted")?
        || parse_rfc3339(required_string(header, "message_ts")?).is_err()
    {
        return Err(OpenCrvsDciV190Rc1DecodeError::EnvelopeContractViolation);
    }
    if required_string(header, "status")? != "succ" {
        return Err(OpenCrvsDciV190Rc1DecodeError::SourceRejected);
    }
    if required_string(header, "message_id")? != expected.message_id.as_ref() {
        return Err(OpenCrvsDciV190Rc1DecodeError::CorrelationViolation);
    }
    if required_string(header, "sender_id")? != expected.sender_id.as_ref()
        || optional_string(header, "receiver_id")? != expected.receiver_id.as_deref()
    {
        return Err(OpenCrvsDciV190Rc1DecodeError::IdentityViolation);
    }

    let message = exact_object(
        outer
            .get("message")
            .ok_or(OpenCrvsDciV190Rc1DecodeError::EnvelopeContractViolation)?,
        &["transaction_id", "correlation_id", "search_response"],
        &[],
    )?;
    if required_string(message, "transaction_id")? != expected.message_id.as_ref() {
        return Err(OpenCrvsDciV190Rc1DecodeError::CorrelationViolation);
    }
    if !is_canonical_uuid(required_string(message, "correlation_id")?) {
        return Err(OpenCrvsDciV190Rc1DecodeError::CorrelationViolation);
    }
    let responses = message
        .get("search_response")
        .and_then(Value::as_array)
        .filter(|responses| responses.len() == 1)
        .ok_or(OpenCrvsDciV190Rc1DecodeError::CardinalityViolation)?;
    let response = exact_object(
        responses
            .first()
            .ok_or(OpenCrvsDciV190Rc1DecodeError::CardinalityViolation)?,
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
        return Err(OpenCrvsDciV190Rc1DecodeError::CorrelationViolation);
    }
    if parse_rfc3339(required_string(response, "timestamp")?).is_err() {
        return Err(OpenCrvsDciV190Rc1DecodeError::EnvelopeContractViolation);
    }
    if required_string(response, "status")? != "succ" {
        return Err(OpenCrvsDciV190Rc1DecodeError::SourceRejected);
    }

    let data = exact_object(
        response
            .get("data")
            .ok_or(OpenCrvsDciV190Rc1DecodeError::EnvelopeContractViolation)?,
        &["version", "reg_type", "reg_record_type", "reg_records"],
        &[],
    )?;
    if required_string(data, "version")? != OPENCRVS_DCI_VERSION
        || required_string(data, "reg_type")? != OPENCRVS_REGISTRY_TYPE
        || required_string(data, "reg_record_type")? != OPENCRVS_RECORD_TYPE
        || required_string(response, "locale")? != OPENCRVS_LOCALE
    {
        return Err(OpenCrvsDciV190Rc1DecodeError::EnvelopeContractViolation);
    }
    let records = data
        .get("reg_records")
        .and_then(Value::as_array)
        .ok_or(OpenCrvsDciV190Rc1DecodeError::EnvelopeContractViolation)?;
    if records.len() > OPENCRVS_PAGE_SIZE as usize
        || records.iter().any(|record| !record.is_object())
    {
        return Err(OpenCrvsDciV190Rc1DecodeError::CardinalityViolation);
    }
    if required_u64(header, "total_count")? != records.len() as u64 {
        return Err(OpenCrvsDciV190Rc1DecodeError::CardinalityViolation);
    }

    let pagination = exact_object(
        response
            .get("pagination")
            .ok_or(OpenCrvsDciV190Rc1DecodeError::PaginationViolation)?,
        &["page_number", "page_size", "total_count"],
        &[],
    )
    .map_err(|_| OpenCrvsDciV190Rc1DecodeError::PaginationViolation)?;
    let pagination_total_count = required_u64(pagination, "total_count")
        .map_err(|_| OpenCrvsDciV190Rc1DecodeError::PaginationViolation)?;
    if required_u64(pagination, "page_number")
        .map_err(|_| OpenCrvsDciV190Rc1DecodeError::PaginationViolation)?
        != OPENCRVS_PAGE_NUMBER
        || required_u64(pagination, "page_size")
            .map_err(|_| OpenCrvsDciV190Rc1DecodeError::PaginationViolation)?
            != OPENCRVS_PAGE_SIZE
        || pagination_total_count < records.len() as u64
        || (pagination_total_count == 0) != records.is_empty()
    {
        return Err(OpenCrvsDciV190Rc1DecodeError::PaginationViolation);
    }
    Ok(ValidatedEnvelope {
        pagination_total_count,
    })
}

fn take_records(response: &mut Value) -> Result<Vec<Value>, OpenCrvsDciV190Rc1DecodeError> {
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
        .ok_or(OpenCrvsDciV190Rc1DecodeError::EnvelopeContractViolation)
}

fn exact_object<'a>(
    value: &'a Value,
    required: &[&str],
    optional: &[&str],
) -> Result<&'a Map<String, Value>, OpenCrvsDciV190Rc1DecodeError> {
    value
        .as_object()
        .filter(|object| object_has_exact_keys(object, required, optional))
        .ok_or(OpenCrvsDciV190Rc1DecodeError::EnvelopeContractViolation)
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
) -> Result<&'a str, OpenCrvsDciV190Rc1DecodeError> {
    object
        .get(field)
        .and_then(Value::as_str)
        .ok_or(OpenCrvsDciV190Rc1DecodeError::EnvelopeContractViolation)
}

fn optional_string<'a>(
    object: &'a Map<String, Value>,
    field: &str,
) -> Result<Option<&'a str>, OpenCrvsDciV190Rc1DecodeError> {
    match object.get(field) {
        Some(Value::String(value)) => Ok(Some(value)),
        Some(_) => Err(OpenCrvsDciV190Rc1DecodeError::EnvelopeContractViolation),
        None => Ok(None),
    }
}

fn required_u64(
    object: &Map<String, Value>,
    field: &str,
) -> Result<u64, OpenCrvsDciV190Rc1DecodeError> {
    object
        .get(field)
        .and_then(Value::as_u64)
        .ok_or(OpenCrvsDciV190Rc1DecodeError::EnvelopeContractViolation)
}

fn required_bool(
    object: &Map<String, Value>,
    field: &str,
) -> Result<bool, OpenCrvsDciV190Rc1DecodeError> {
    object
        .get(field)
        .and_then(Value::as_bool)
        .ok_or(OpenCrvsDciV190Rc1DecodeError::EnvelopeContractViolation)
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
