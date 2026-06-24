// SPDX-License-Identifier: Apache-2.0
//! In-process software signer.
//!
//! Reads a private JWK from an environment variable at startup, parses
//! it with the shared Registry Platform crypto crate, and signs each
//! request by constructing the compact JWS by hand: we base64url-encode
//! the header and payload, sign the joined string, then assemble
//! `header.payload.signature`.
//!
//! Private key material lives behind [`zeroize::Zeroizing`] where the
//! crate supports it. Env var contents are wiped after parsing and are
//! never logged.

use std::env;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use registry_platform_crypto::{sign, PrivateJwk};
use serde_json::Value;
use zeroize::Zeroizing;

use crate::config::SoftwareSignerConfig;

use super::super::signer::{Signer, SignerError, SigningAlgorithm};

/// In-process signer backed by a private JWK loaded from an env var.
pub struct SoftwareSigner {
    algorithm: SigningAlgorithm,
    jwk: PrivateJwk,
    verification_method_id: String,
}

impl std::fmt::Debug for SoftwareSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SoftwareSigner")
            .field("algorithm", &self.algorithm)
            .field("verification_method_id", &self.verification_method_id)
            .finish_non_exhaustive()
    }
}

impl SoftwareSigner {
    /// Build a [`SoftwareSigner`] from configuration. The private JWK
    /// is read from the env var named by `cfg.jwk_env`.
    ///
    /// # Errors
    ///
    /// Returns [`SignerError::KeyLoad`] if the env var is unset or the
    /// JWK does not parse. Returns [`SignerError::AlgorithmMismatch`]
    /// if the JWK's `alg` (when present) does not match the configured
    /// algorithm.
    pub fn from_config(
        cfg: &SoftwareSignerConfig,
        verification_method_id: String,
    ) -> Result<Self, SignerError> {
        let raw = env::var(&cfg.jwk_env).map_err(|_| SignerError::KeyLoad {
            reason: "jwk_env unset",
        })?;
        let raw = Zeroizing::new(raw);
        Self::from_jwk_str(&raw, cfg.signing_algorithm.into(), verification_method_id)
    }

    /// Build a [`SoftwareSigner`] from an in-memory private JWK string.
    /// Secret-store adapters should use this when the key material is
    /// already available in process and should not round-trip through
    /// environment variables.
    ///
    /// # Errors
    ///
    /// Returns [`SignerError::KeyLoad`] if the JWK does not parse, or
    /// [`SignerError::AlgorithmMismatch`] if the JWK's `alg` conflicts
    /// with `algorithm`.
    pub fn from_jwk_str(
        raw: &str,
        algorithm: SigningAlgorithm,
        verification_method_id: String,
    ) -> Result<Self, SignerError> {
        let value: Value = serde_json::from_str(raw).map_err(|_| SignerError::KeyLoad {
            reason: "jwk parse failed",
        })?;
        // If the JWK explicitly declares `alg`, it must match.
        if let Some(jwk_alg) = value.get("alg").and_then(Value::as_str) {
            if jwk_alg != algorithm.jws_alg() {
                return Err(SignerError::AlgorithmMismatch);
            }
        }
        if algorithm == SigningAlgorithm::ES256 {
            return Err(SignerError::KeyLoad {
                reason: "ES256 software path not yet wired in V1; use EdDSA",
            });
        }
        let mut jwk = PrivateJwk::parse(raw).map_err(map_jwk_error)?;
        if jwk.kid.is_none() {
            jwk.kid = Some(verification_method_id.clone());
        }

        Ok(Self {
            algorithm,
            jwk,
            verification_method_id,
        })
    }
}

fn map_jwk_error(_: registry_platform_crypto::JwkError) -> SignerError {
    SignerError::KeyLoad {
        reason: "jwk validation failed",
    }
}

impl Signer for SoftwareSigner {
    fn algorithm(&self) -> SigningAlgorithm {
        self.algorithm
    }

    fn verification_method_id(&self) -> &str {
        &self.verification_method_id
    }

    fn sign(&self, header: Value, payload: Value) -> Result<String, SignerError> {
        let header_bytes = serde_json::to_vec(&header).map_err(|_| SignerError::Sign {
            reason: "header serialize",
        })?;
        let payload_bytes = serde_json::to_vec(&payload).map_err(|_| SignerError::Sign {
            reason: "payload serialize",
        })?;
        let header_b64 = URL_SAFE_NO_PAD.encode(&header_bytes);
        let payload_b64 = URL_SAFE_NO_PAD.encode(&payload_bytes);
        let signing_input = format!("{header_b64}.{payload_b64}");
        let signature =
            sign(signing_input.as_bytes(), &self.jwk).map_err(|_| SignerError::Sign {
                reason: "registry platform sign",
            })?;
        Ok(format!(
            "{}.{}",
            signing_input,
            URL_SAFE_NO_PAD.encode(signature)
        ))
    }

    fn public_jwk(&self) -> Value {
        serde_json::to_value(self.jwk.public()).unwrap_or(Value::Null)
    }
}
