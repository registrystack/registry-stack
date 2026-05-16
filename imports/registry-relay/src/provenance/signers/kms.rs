// SPDX-License-Identifier: Apache-2.0
//! KMS-backed signer hooks.
//!
//! V1 ships only the trait surface plus a deterministic
//! [`MockKmsSigner`] used in tests to prove the [`Signer`] contract is
//! decoupled from the in-process software path. A real AWS KMS impl
//! lands behind a future `kms-aws` cargo feature; the seam is
//! deliberately small so that addition is purely additive.
//!
//! # Why a mock
//!
//! The orchestrator and Wave 3 integration tests need to exercise the
//! `kind: kms` config branch end to end without standing up a KMS. The
//! mock loads an Ed25519 seed from an env var (same shape as the
//! software signer's `jwk_env`) and signs locally. This is *not* a
//! production code path: it is gated by `KmsProvider::Mock` in the
//! configuration enum, which itself is documented as test-only.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use jsonwebtoken::{Algorithm, EncodingKey};
use serde_json::{json, Value};
use zeroize::Zeroizing;

use crate::config::{KmsProvider, KmsSignerConfig, ProvenanceAlgorithm};

use super::super::signer::{Signer, SignerError, SigningAlgorithm};

// TODO: AwsKmsSigner behind --features kms-aws. The real backend calls
// the KMS Sign API for every request, never holds private bytes, and
// constructs the compact JWS the same way the software path does (i.e.
// base64url-encode header and payload, sign the joined bytes, attach
// the returned signature). Public-key material for `public_jwk()` comes
// from the KMS GetPublicKey response cached at startup.

/// In-process mock for the KMS backend.
///
/// Loads a raw Ed25519 32-byte seed from the env var named in
/// [`KmsSignerConfig::key_id`] (interpreted here as the env var name,
/// not the AWS key ARN). The seed is base64url-encoded; tests generate
/// one via `ed25519-dalek` and write it into the env before
/// constructing the signer.
pub struct MockKmsSigner {
    algorithm: SigningAlgorithm,
    encoding_key: EncodingKey,
    public_jwk: Value,
    verification_method_id: String,
}

impl std::fmt::Debug for MockKmsSigner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MockKmsSigner")
            .field("algorithm", &self.algorithm)
            .field("verification_method_id", &self.verification_method_id)
            .finish_non_exhaustive()
    }
}

impl MockKmsSigner {
    /// Build a [`MockKmsSigner`] from configuration. Reads the seed
    /// from the env var named in `cfg.key_id` (mock-only convention).
    ///
    /// # Errors
    ///
    /// Returns [`SignerError::KeyLoad`] if the env var is unset, fails
    /// to decode, or is not 32 bytes. Returns
    /// [`SignerError::AlgorithmMismatch`] if the config does not
    /// declare EdDSA (the only algorithm wired in the mock).
    pub fn from_config(
        cfg: &KmsSignerConfig,
        verification_method_id: String,
    ) -> Result<Self, SignerError> {
        if cfg.provider != KmsProvider::Mock {
            return Err(SignerError::KeyLoad {
                reason: "MockKmsSigner only supports KmsProvider::Mock",
            });
        }
        if cfg.signing_algorithm != ProvenanceAlgorithm::EdDSA {
            return Err(SignerError::AlgorithmMismatch);
        }

        let raw = std::env::var(&cfg.key_id).map_err(|_| SignerError::KeyLoad {
            reason: "mock kms key env unset",
        })?;
        let raw = Zeroizing::new(raw);
        let seed = URL_SAFE_NO_PAD
            .decode(raw.as_bytes())
            .map_err(|_| SignerError::KeyLoad {
                reason: "mock kms seed base64",
            })?;
        if seed.len() != 32 {
            return Err(SignerError::KeyLoad {
                reason: "mock kms seed not 32 bytes",
            });
        }
        let pkcs8 = super::software::ed25519_pkcs8_seed(&seed);
        let encoding_key = EncodingKey::from_ed_der(&pkcs8);

        // Derive the public key from the seed so the JWK carries a
        // verifiable `x`. The real KMS backend will read the public key
        // from `GetPublicKey` at startup; the mock derives it locally so
        // tests and the `/.well-known/did.json` document have a working
        // verification key.
        let seed_arr: [u8; 32] = seed
            .as_slice()
            .try_into()
            .expect("seed length checked above");
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&seed_arr);
        let public_bytes = signing_key.verifying_key().to_bytes();
        let public_x = URL_SAFE_NO_PAD.encode(public_bytes);
        let public_jwk = json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "alg": "EdDSA",
            "x": public_x,
            "kid": verification_method_id.clone(),
        });

        Ok(Self {
            algorithm: SigningAlgorithm::EdDSA,
            encoding_key,
            public_jwk,
            verification_method_id,
        })
    }
}

impl Signer for MockKmsSigner {
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
            Algorithm::EdDSA,
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
