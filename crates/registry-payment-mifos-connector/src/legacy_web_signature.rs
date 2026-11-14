// SPDX-License-Identifier: Apache-2.0

//! Exact input construction for connector-common v1.8.1's legacy web
//! signature mechanism.
//!
//! Despite the upstream `JWS` name, this is not JOSE or an RS256 signature.
//! The released Java code hashes a colon-joined UTF-8 string with SHA3-256,
//! renders the digest as lowercase hexadecimal, then passes those ASCII bytes
//! to the JVM's default RSA cipher with a private key. Key custody and that
//! legacy raw-RSA operation remain host responsibilities.

use crate::{build_batch_request, header_text, BatchCommand, ConnectorError, SecretHeader};
use std::{future::Future, pin::Pin};
use zeroize::Zeroizing;

/// Exact released connector-common source profile implemented by this module.
pub const LEGACY_WEB_SIGNATURE_PROFILE: &str =
    "ph-ee-connector-common/v1.8.1:rsa-cipher-sha3-256/v1";

const MAX_BODY_BYTES: usize = 65_536;
const MAX_HEADER_BYTES: usize = 128;

/// Values selected by connector-common's released fixed header order.
///
/// Missing values are skipped. Present values are included in this exact
/// order: `X-BatchID`, `X-CorrelationID`, `Platform-TenantId`.
#[derive(Clone, Copy)]
pub struct LegacySignatureHeaders<'a> {
    batch_id: Option<&'a str>,
    correlation_id: Option<&'a str>,
    tenant: Option<&'a str>,
}

impl<'a> LegacySignatureHeaders<'a> {
    /// Headers emitted by Registry Stack's released raw batch request.
    #[must_use]
    pub const fn bulk_request(correlation_id: &'a str, tenant: &'a str) -> Self {
        Self {
            batch_id: None,
            correlation_id: Some(correlation_id),
            tenant: Some(tenant),
        }
    }

    /// Headers observed on one released bulk response.
    ///
    /// Callers must pass only values actually present exactly once on the
    /// bounded HTTP response. They must not derive them from a request or body.
    #[must_use]
    pub const fn response(
        batch_id: Option<&'a str>,
        correlation_id: Option<&'a str>,
        tenant: &'a str,
    ) -> Self {
        Self {
            batch_id,
            correlation_id,
            tenant: Some(tenant),
        }
    }

    /// No selected headers, for exact compatibility and negative tests.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            batch_id: None,
            correlation_id: None,
            tenant: None,
        }
    }

    fn ordered(self) -> [Option<&'a str>; 3] {
        [self.batch_id, self.correlation_id, self.tenant]
    }
}

/// The exact UTF-8 bytes connector-common hashes.
///
/// This type intentionally implements neither `Debug` nor `Clone`: it can
/// contain party identifiers and payment details and must not enter logs.
pub struct LegacySignaturePreimage(Zeroizing<Vec<u8>>);

impl LegacySignaturePreimage {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        self.0.as_slice()
    }
}

/// The lowercase 64-byte ASCII SHA3-256 digest passed to the raw-RSA provider.
///
/// This type intentionally implements neither `Debug` nor `Clone`. Although
/// it is not a key, it is a stable correlate of the signed payment request.
pub struct LegacySignatureDigest(Zeroizing<[u8; 64]>);

impl LegacySignatureDigest {
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        std::str::from_utf8(self.0.as_slice())
            .expect("legacy digest construction emits lowercase ASCII hex")
    }
}

/// Build connector-common v1.8.1's exact colon-joined UTF-8 signing input.
///
/// The Java implementation removes the final separator when the body is
/// empty. It fails when both the selected headers and body are empty; this
/// helper returns a value-free error for that malformed input.
pub fn legacy_signature_preimage(
    headers: LegacySignatureHeaders<'_>,
    body: &[u8],
) -> Result<LegacySignaturePreimage, ConnectorError> {
    if body.len() > MAX_BODY_BYTES || std::str::from_utf8(body).is_err() {
        return Err(ConnectorError::Command);
    }

    let mut output = Zeroizing::new(Vec::with_capacity(body.len() + 3 * (MAX_HEADER_BYTES + 1)));
    let mut selected = false;
    for value in headers.ordered().into_iter().flatten() {
        if !header_text(value, MAX_HEADER_BYTES) {
            return Err(ConnectorError::Command);
        }
        output.extend_from_slice(value.as_bytes());
        output.push(b':');
        selected = true;
    }

    if body.is_empty() {
        if !selected {
            return Err(ConnectorError::Command);
        }
        output.pop();
    } else {
        output.extend_from_slice(body);
    }
    Ok(LegacySignaturePreimage(output))
}

/// Hash an exact legacy preimage as lowercase SHA3-256 hexadecimal.
pub fn legacy_signature_digest(
    headers: LegacySignatureHeaders<'_>,
    body: &[u8],
) -> Result<LegacySignatureDigest, ConnectorError> {
    let preimage = legacy_signature_preimage(headers, body)?;
    let digest = registry_platform_crypto::sha3_256(preimage.as_bytes());
    let mut encoded = Zeroizing::new([0u8; 64]);
    for (index, byte) in digest.iter().copied().enumerate() {
        encoded[index * 2] = hex(byte >> 4);
        encoded[index * 2 + 1] = hex(byte & 0x0f);
    }
    Ok(LegacySignatureDigest(encoded))
}

/// Hash the exact bytes of a validated one-instruction raw batch request.
///
/// The supplied body must equal this connector's encoding of `command`. This
/// prevents a host from signing one representation and dispatching another.
pub fn legacy_batch_request_signature_digest(
    command: &BatchCommand,
    tenant: &str,
    body: &[u8],
) -> Result<LegacySignatureDigest, ConnectorError> {
    let expected = Zeroizing::new(build_batch_request(command)?);
    if expected.as_slice() != body {
        return Err(ConnectorError::Command);
    }
    legacy_signature_digest(
        LegacySignatureHeaders::bulk_request(&command.correlation_id, tenant),
        body,
    )
}

const fn hex(value: u8) -> u8 {
    match value {
        0..=9 => b'0' + value,
        10..=15 => b'a' + value - 10,
        _ => unreachable!(),
    }
}

/// Value-free refusal from a host-side legacy raw-RSA provider.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum LegacySignatureError {
    #[error("the Mifos legacy signature provider refused the operation")]
    Refused,
    #[error("the Mifos legacy signature did not verify")]
    Mismatch,
    #[error("the Mifos legacy signature provider is unavailable")]
    Unavailable,
}

/// A bounded asynchronous host-side legacy signature operation.
pub type LegacySignatureFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, LegacySignatureError>> + Send + 'a>>;

/// Secret-backed host implementation of connector-common's raw-RSA private
/// operation over the exact 64 lowercase ASCII digest bytes.
///
/// Implementations must produce standard padded Base64 for `X-SIGNATURE`.
/// A standards-based JOSE or RS256 signer is not compatible.
pub trait LegacyWebSignatureSigner: Send + Sync {
    fn sign_digest_hex<'a>(
        &'a self,
        digest: &'a LegacySignatureDigest,
    ) -> LegacySignatureFuture<'a, SecretHeader>;
}

/// Host implementation of connector-common's matching public-key recovery
/// and constant-time digest comparison.
///
/// Implementations must treat a missing, repeated, malformed, or mismatched
/// response signature as failure and must not log either input.
pub trait LegacyWebSignatureVerifier: Send + Sync {
    fn verify_digest_hex<'a>(
        &'a self,
        digest: &'a LegacySignatureDigest,
        signature: &'a [u8],
    ) -> LegacySignatureFuture<'a, ()>;
}
