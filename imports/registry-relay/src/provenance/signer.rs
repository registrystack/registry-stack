// SPDX-License-Identifier: Apache-2.0
//! Signer trait and supporting types for provenance.
//!
//! Implementations live under [`crate::provenance::signers`]. The trait
//! takes JSON-shaped header and payload and returns a compact JWS
//! string. Building the JWS by hand (rather than going through the
//! `jsonwebtoken::encode` Claims path) lets us own the VCDM 2.0
//! envelope shape end-to-end.

use thiserror::Error;

use crate::config::ProvenanceAlgorithm;
use registry_platform_crypto::KeyReadiness;

/// JWS signing algorithm. Mirrors [`ProvenanceAlgorithm`] but lives
/// inside the signer module so signer-side code does not depend on the
/// config crate's public types beyond what the trait surface allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum SigningAlgorithm {
    EdDSA,
    ES256,
}

impl From<ProvenanceAlgorithm> for SigningAlgorithm {
    fn from(value: ProvenanceAlgorithm) -> Self {
        match value {
            ProvenanceAlgorithm::EdDSA => SigningAlgorithm::EdDSA,
            ProvenanceAlgorithm::ES256 => SigningAlgorithm::ES256,
        }
    }
}

impl SigningAlgorithm {
    /// Canonical JWS `alg` header value per RFC 7518 / 8037.
    pub fn jws_alg(self) -> &'static str {
        match self {
            SigningAlgorithm::EdDSA => "EdDSA",
            SigningAlgorithm::ES256 => "ES256",
        }
    }
}

/// Errors returned by [`Signer`] implementations.
///
/// The variants intentionally do not carry private key material or env
/// var values: callers log only the stable variant identity, and the
/// underlying source error stays internal to the impl.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SignerError {
    /// The signing backend is reachable but cannot serve this request
    /// (KMS outage, key disabled). Renders 503 to the caller.
    #[error("signer unavailable")]
    Unavailable,
    /// Loading the configured key failed at startup (malformed JWK,
    /// missing env var, KMS describe failure). Surfaced at startup.
    #[error("signer key load failed: {reason}")]
    KeyLoad { reason: &'static str },
    /// Crypto primitive returned an error during signing.
    #[error("sign call failed: {reason}")]
    Sign { reason: &'static str },
    /// The configured `signing_algorithm` does not match the key
    /// (e.g. `EdDSA` configured but the JWK declares `ES256`).
    #[error("signer algorithm mismatch")]
    AlgorithmMismatch,
}

/// Trait implemented by the in-process software signer and future
/// remote signer adapters.
///
/// `sign` takes the JSON header and JSON payload, encodes both as
/// base64url, signs the `header_b64.payload_b64` byte sequence, and
/// returns the compact-serialised JWS.
pub trait Signer: Send + Sync {
    /// Algorithm the signer is bound to. Must equal the configured
    /// algorithm for the verification method.
    fn algorithm(&self) -> SigningAlgorithm;

    /// Absolute `verificationMethod` URI for the active key, used as
    /// the JWS `kid` header.
    fn verification_method_id(&self) -> &str;

    /// Sign the header / payload pair. Returns the compact JWS
    /// (`header.payload.signature`) as a UTF-8 string.
    fn sign(
        &self,
        header: serde_json::Value,
        payload: serde_json::Value,
    ) -> Result<String, SignerError>;

    /// Public JWK for the active signing key. Used by the gateway
    /// `/.well-known/did.json` builder.
    fn public_jwk(&self) -> serde_json::Value;

    /// Current health of the local signer backend.
    fn readiness(&self) -> KeyReadiness {
        KeyReadiness::Ready
    }
}
