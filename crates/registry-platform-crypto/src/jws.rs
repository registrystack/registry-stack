// SPDX-License-Identifier: Apache-2.0
//! Compact JWS (RFC 7515) parsing, verification, and signing.
//!
//! Parsing bounds every segment before decoding it, reads the protected header
//! with the workspace's strict JSON parser (duplicate members refused), and
//! refuses `crit` and `b64`. Verification requires the header `alg` to equal
//! the key's own algorithm and to appear in the caller's allow-list, and
//! releases the payload only after the signature verifies. Signing takes `alg`
//! and `kid` from the [`SigningProvider`], never from the caller.
//!
//! Errors are a closed set of categories. They never contain the token, its
//! segments, or key material.

use crate::{parse_json_strict, verify, PublicJwk, SigningAlgorithm, SigningProvider};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use serde_json::{Map, Value};
use std::fmt;
use thiserror::Error;

/// Longest encoded signature accepted: 1024 bytes (RSA-8192) in base64url.
const MAX_SIGNATURE_SEGMENT_BYTES: usize = 1366;

/// Size bounds applied while parsing a compact JWS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JwsLimits {
    /// Longest accepted compact serialization, in bytes.
    pub max_compact_bytes: usize,
    /// Longest accepted decoded protected header, in bytes.
    pub max_header_bytes: usize,
    /// Longest accepted decoded payload, in bytes.
    pub max_payload_bytes: usize,
}

impl Default for JwsLimits {
    fn default() -> Self {
        Self {
            max_compact_bytes: 256 * 1024,
            max_header_bytes: 8 * 1024,
            max_payload_bytes: 128 * 1024,
        }
    }
}

/// Closed set of compact JWS failure categories.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum JwsError {
    #[error("JWS exceeds a size limit")]
    TooLarge,
    #[error("malformed compact JWS")]
    Malformed,
    #[error("JWS protected header is not a strict JSON object")]
    InvalidHeader,
    #[error("JWS protected header uses an unsupported parameter")]
    UnsupportedHeader,
    #[error("JWS algorithm is missing or unsupported")]
    UnsupportedAlgorithm,
    #[error("JWS algorithm is not allowed here")]
    AlgorithmNotAllowed,
    #[error("JWS algorithm does not match the verification key")]
    AlgorithmMismatch,
    #[error("JWS signature verification failed")]
    SignatureInvalid,
    #[error("JWS header member is set by the signer and cannot be supplied")]
    ReservedHeader,
    #[error("JWS signing failed")]
    SigningFailed,
}

/// A parsed, not yet verified, compact JWS.
///
/// Nothing in it is trustworthy until [`CompactJws::verify`] succeeds.
pub struct CompactJws<'a> {
    signing_input: &'a str,
    header: Map<String, Value>,
    payload: Vec<u8>,
    signature: Vec<u8>,
}

impl fmt::Debug for CompactJws<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompactJws").finish_non_exhaustive()
    }
}

fn encoded_bound(decoded: usize) -> usize {
    decoded.div_ceil(3) * 4
}

fn decode_segment(segment: &str) -> Result<Vec<u8>, JwsError> {
    URL_SAFE_NO_PAD
        .decode(segment)
        .map_err(|_| JwsError::Malformed)
}

/// Split and bound a compact JWS, and parse its protected header.
///
/// Refuses headers carrying `crit` or `b64`. The `alg` header is checked by
/// [`CompactJws::algorithm`] and [`CompactJws::verify`].
pub fn parse_compact_jws<'a>(
    token: &'a str,
    limits: &JwsLimits,
) -> Result<CompactJws<'a>, JwsError> {
    if token.len() > limits.max_compact_bytes {
        return Err(JwsError::TooLarge);
    }
    let mut segments = token.split('.');
    let (Some(header_b64), Some(payload_b64), Some(signature_b64), None) = (
        segments.next(),
        segments.next(),
        segments.next(),
        segments.next(),
    ) else {
        return Err(JwsError::Malformed);
    };
    if header_b64.len() > encoded_bound(limits.max_header_bytes)
        || payload_b64.len() > encoded_bound(limits.max_payload_bytes)
        || signature_b64.len() > MAX_SIGNATURE_SEGMENT_BYTES
    {
        return Err(JwsError::TooLarge);
    }
    if header_b64.is_empty() || signature_b64.is_empty() {
        return Err(JwsError::Malformed);
    }
    let header_bytes = decode_segment(header_b64)?;
    if header_bytes.len() > limits.max_header_bytes {
        return Err(JwsError::TooLarge);
    }
    let payload = decode_segment(payload_b64)?;
    if payload.len() > limits.max_payload_bytes {
        return Err(JwsError::TooLarge);
    }
    let signature = decode_segment(signature_b64)?;

    let Ok(Value::Object(header)) = parse_json_strict(&header_bytes) else {
        return Err(JwsError::InvalidHeader);
    };
    if header.contains_key("crit") || header.contains_key("b64") {
        return Err(JwsError::UnsupportedHeader);
    }
    Ok(CompactJws {
        signing_input: &token[..header_b64.len() + 1 + payload_b64.len()],
        header,
        payload,
        signature,
    })
}

impl CompactJws<'_> {
    /// The unverified protected header.
    #[must_use]
    pub fn header(&self) -> &Map<String, Value> {
        &self.header
    }

    /// The algorithm named by the header `alg`.
    ///
    /// `none`, a missing or non-string `alg`, and any algorithm outside
    /// [`SigningAlgorithm`] are refused.
    pub fn algorithm(&self) -> Result<SigningAlgorithm, JwsError> {
        let name = self
            .header
            .get("alg")
            .and_then(Value::as_str)
            .ok_or(JwsError::UnsupportedAlgorithm)?;
        [
            SigningAlgorithm::EdDsa,
            SigningAlgorithm::Es256,
            SigningAlgorithm::Es384,
            SigningAlgorithm::Rs256,
            SigningAlgorithm::Rs384,
        ]
        .into_iter()
        .find(|algorithm| algorithm.jwa_name() == name)
        .ok_or(JwsError::UnsupportedAlgorithm)
    }

    /// Verify the signature and return the payload.
    ///
    /// The header algorithm must be in `allowed` and equal the algorithm of
    /// `key`. The payload is not reachable before this succeeds.
    pub fn verify(&self, key: &PublicJwk, allowed: &[SigningAlgorithm]) -> Result<&[u8], JwsError> {
        let algorithm = self.algorithm()?;
        if !allowed.contains(&algorithm) {
            return Err(JwsError::AlgorithmNotAllowed);
        }
        if key.algorithm().ok() != Some(algorithm) {
            return Err(JwsError::AlgorithmMismatch);
        }
        verify(self.signing_input.as_bytes(), &self.signature, key)
            .map_err(|_| JwsError::SignatureInvalid)?;
        Ok(&self.payload)
    }
}

/// Sign `payload` as a compact JWS.
///
/// The protected header is `extra_header` plus `alg` and `kid` from `signer`.
/// A caller-supplied `alg` or `kid` is refused, as are `crit` and `b64`, which
/// this module does not support.
pub async fn sign_compact_jws(
    extra_header: Map<String, Value>,
    payload: &[u8],
    signer: &dyn SigningProvider,
) -> Result<String, JwsError> {
    if extra_header.contains_key("alg") || extra_header.contains_key("kid") {
        return Err(JwsError::ReservedHeader);
    }
    if extra_header.contains_key("crit") || extra_header.contains_key("b64") {
        return Err(JwsError::UnsupportedHeader);
    }
    let mut header = extra_header;
    header.insert(
        "alg".to_owned(),
        Value::String(signer.algorithm().jwa_name().to_owned()),
    );
    header.insert("kid".to_owned(), Value::String(signer.key_id().to_owned()));
    let header_bytes =
        serde_json::to_vec(&Value::Object(header)).map_err(|_| JwsError::SigningFailed)?;
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header_bytes),
        URL_SAFE_NO_PAD.encode(payload)
    );
    let signature = signer
        .sign(signing_input.as_bytes())
        .await
        .map_err(|_| JwsError::SigningFailed)?;
    Ok(format!(
        "{signing_input}.{}",
        URL_SAFE_NO_PAD.encode(signature)
    ))
}
