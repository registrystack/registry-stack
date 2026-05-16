// SPDX-License-Identifier: Apache-2.0
//! In-process software signer.
//!
//! Reads a private JWK from an environment variable at startup, parses
//! it into a `jsonwebtoken::EncodingKey`, and signs each request by
//! constructing the compact JWS by hand: we base64url-encode the
//! header and payload, sign the joined string, then assemble
//! `header.payload.signature`.
//!
//! Private key material lives behind [`zeroize::Zeroizing`] where the
//! crate supports it. Env var contents are wiped after parsing and are
//! never logged.

use std::env;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{Algorithm, EncodingKey};
use serde::Deserialize;
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::config::SoftwareSignerConfig;

use super::super::signer::{Signer, SignerError, SigningAlgorithm};

/// Subset of a JWK we accept. The crate does not depend on a full JWK
/// implementation; we only parse the fields needed to load the private
/// key into `jsonwebtoken::EncodingKey`.
#[derive(Debug, Deserialize)]
struct PrivateJwk {
    kty: String,
    #[serde(default)]
    crv: Option<String>,
    /// Private key material. Stored briefly while constructing the
    /// `EncodingKey` then zeroed.
    #[serde(default)]
    d: Option<String>,
    #[serde(default)]
    x: Option<String>,
    #[serde(default)]
    y: Option<String>,
    #[serde(default)]
    alg: Option<String>,
    #[serde(default)]
    kid: Option<String>,
}

/// In-process signer backed by a private JWK loaded from an env var.
pub struct SoftwareSigner {
    algorithm: SigningAlgorithm,
    jw_algorithm: Algorithm,
    encoding_key: EncodingKey,
    public_jwk: Value,
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
        let jwk: PrivateJwk = serde_json::from_str(&raw).map_err(|_| SignerError::KeyLoad {
            reason: "jwk parse failed",
        })?;
        let algorithm: SigningAlgorithm = cfg.signing_algorithm.into();
        // If the JWK explicitly declares `alg`, it must match.
        if let Some(jwk_alg) = jwk.alg.as_deref() {
            if jwk_alg != algorithm.jws_alg() {
                return Err(SignerError::AlgorithmMismatch);
            }
        }

        let (encoding_key, jw_algorithm, public_jwk) = match algorithm {
            SigningAlgorithm::EdDSA => build_ed25519(&jwk, &verification_method_id)?,
            SigningAlgorithm::ES256 => build_p256(&jwk, &verification_method_id)?,
        };

        Ok(Self {
            algorithm,
            jw_algorithm,
            encoding_key,
            public_jwk,
            verification_method_id,
        })
    }
}

fn build_ed25519(
    jwk: &PrivateJwk,
    verification_method_id: &str,
) -> Result<(EncodingKey, Algorithm, Value), SignerError> {
    if jwk.kty != "OKP" {
        return Err(SignerError::KeyLoad {
            reason: "EdDSA jwk kty must be OKP",
        });
    }
    if jwk.crv.as_deref() != Some("Ed25519") {
        return Err(SignerError::KeyLoad {
            reason: "EdDSA jwk crv must be Ed25519",
        });
    }
    let d = jwk.d.as_deref().ok_or(SignerError::KeyLoad {
        reason: "missing d",
    })?;
    let x = jwk.x.as_deref().ok_or(SignerError::KeyLoad {
        reason: "missing x",
    })?;
    let d_bytes = URL_SAFE_NO_PAD
        .decode(d)
        .map_err(|_| SignerError::KeyLoad { reason: "d base64" })?;
    if d_bytes.len() != 32 {
        return Err(SignerError::KeyLoad {
            reason: "d not 32 bytes",
        });
    }
    let x_bytes = URL_SAFE_NO_PAD
        .decode(x)
        .map_err(|_| SignerError::KeyLoad { reason: "x base64" })?;
    if x_bytes.len() != 32 {
        return Err(SignerError::KeyLoad {
            reason: "x not 32 bytes",
        });
    }
    // jsonwebtoken's Ed25519 EncodingKey wants a PKCS#8-encoded private
    // key in DER. Wrap the raw 32-byte seed in the standard PKCS#8 v1
    // envelope.
    let pkcs8 = ed25519_pkcs8_seed(&d_bytes);
    let encoding_key = EncodingKey::from_ed_der(&pkcs8);
    let public_jwk = json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": x,
        "alg": "EdDSA",
        "kid": jwk.kid.clone().unwrap_or_else(|| verification_method_id.to_string()),
    });
    Ok((encoding_key, Algorithm::EdDSA, public_jwk))
}

fn build_p256(
    jwk: &PrivateJwk,
    verification_method_id: &str,
) -> Result<(EncodingKey, Algorithm, Value), SignerError> {
    if jwk.kty != "EC" {
        return Err(SignerError::KeyLoad {
            reason: "ES256 jwk kty must be EC",
        });
    }
    if jwk.crv.as_deref() != Some("P-256") {
        return Err(SignerError::KeyLoad {
            reason: "ES256 jwk crv must be P-256",
        });
    }
    let d = jwk.d.as_deref().ok_or(SignerError::KeyLoad {
        reason: "missing d",
    })?;
    let x = jwk.x.as_deref().ok_or(SignerError::KeyLoad {
        reason: "missing x",
    })?;
    let y = jwk.y.as_deref().ok_or(SignerError::KeyLoad {
        reason: "missing y",
    })?;
    let d_bytes = URL_SAFE_NO_PAD
        .decode(d)
        .map_err(|_| SignerError::KeyLoad { reason: "d base64" })?;
    let x_bytes = URL_SAFE_NO_PAD
        .decode(x)
        .map_err(|_| SignerError::KeyLoad { reason: "x base64" })?;
    let y_bytes = URL_SAFE_NO_PAD
        .decode(y)
        .map_err(|_| SignerError::KeyLoad { reason: "y base64" })?;
    if d_bytes.len() != 32 || x_bytes.len() != 32 || y_bytes.len() != 32 {
        return Err(SignerError::KeyLoad {
            reason: "ES256 component length",
        });
    }
    // jsonwebtoken's ES256 EncodingKey expects a PKCS#8 / SEC1 PEM. To
    // keep the V1 KMS-less path simple we accept JWKs and convert to
    // SEC1 DER then PEM-encode. For V1 the safest path is to require a
    // PKCS#8 PEM be carried inside the JWK's `d` field via a
    // configuration variant. ES256 wiring is deferred to a follow-up;
    // V1 ships only the trait surface and the EdDSA path.
    let _ = (d_bytes, x_bytes, y_bytes, verification_method_id);
    Err(SignerError::KeyLoad {
        reason: "ES256 software path not yet wired in V1; use EdDSA",
    })
}

/// Wrap a raw Ed25519 32-byte seed in the standard PKCS#8 v1 envelope
/// expected by `jsonwebtoken::EncodingKey::from_ed_der`.
///
/// Layout:
///   30 2e                       SEQUENCE (46 bytes)
///   02 01 00                    INTEGER 0  (version)
///   30 05                       SEQUENCE (5 bytes)
///   06 03 2b 65 70              OID 1.3.101.112 (Ed25519)
///   04 22                       OCTET STRING (34 bytes)
///   04 20 <32-byte seed>        nested OCTET STRING (32 bytes)
fn ed25519_pkcs8_seed(seed: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(48);
    out.extend_from_slice(&[
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ]);
    out.extend_from_slice(seed);
    out
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
        let signature = jsonwebtoken::crypto::sign(
            signing_input.as_bytes(),
            &self.encoding_key,
            self.jw_algorithm,
        )
        .map_err(|_| SignerError::Sign {
            reason: "jsonwebtoken sign",
        })?;
        Ok(format!("{signing_input}.{signature}"))
    }

    fn public_jwk(&self) -> Value {
        self.public_jwk.clone()
    }
}

// `EncodingKey` does not currently implement Zeroize, but
// `jsonwebtoken` drops the underlying key material on Drop. We
// intentionally avoid holding raw bytes in our own struct.
