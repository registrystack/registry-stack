// SPDX-License-Identifier: Apache-2.0
//! Trait-surface tests for [`registry_relay::provenance::Signer`].
//!
//! V1 supports local software signing only. These tests drive the
//! production [`SoftwareSigner`] through the trait and keep one tiny
//! external-adapter implementation to prove future remote signers can
//! still plug into the same boundary.

use std::env;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use registry_platform_crypto::KeyReadiness;
use registry_relay::config::{ProvenanceAlgorithm, SoftwareSignerConfig};
use registry_relay::provenance::signers::software::SoftwareSigner;
use registry_relay::provenance::{Signer, SignerError, SigningAlgorithm};
use serde_json::{json, Value};

// Each #[test] case uses its own env var name. cargo runs `#[test]`
// cases inside a single binary in parallel by default; sharing one env
// name across tests would race when each test generates and exports a
// fresh keypair.
const JWK_ENV_ALG: &str = "SIGNER_TRAIT_TEST_JWK_ALG";
const JWK_ENV_SHAPE: &str = "SIGNER_TRAIT_TEST_JWK_SHAPE";
const JWK_ENV_VERIFY: &str = "SIGNER_TRAIT_TEST_JWK_VERIFY";
const JWK_ENV_PUBLIC: &str = "SIGNER_TRAIT_TEST_JWK_PUBLIC";

fn generate_jwk_and_export(env_name: &str) -> VerifyingKey {
    let sk = SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key();
    let jwk = json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "d": URL_SAFE_NO_PAD.encode(sk.to_bytes()),
        "x": URL_SAFE_NO_PAD.encode(vk.to_bytes()),
        "alg": "EdDSA",
    });
    env::set_var(
        env_name,
        serde_json::to_string(&jwk).expect("jwk serializes"),
    );
    vk
}

fn build_software_signer(env_name: &str, vm_id: &str) -> (SoftwareSigner, VerifyingKey) {
    let vk = generate_jwk_and_export(env_name);
    let cfg = SoftwareSignerConfig {
        jwk_env: env_name.to_string(),
        signing_algorithm: ProvenanceAlgorithm::EdDSA,
    };
    let signer =
        SoftwareSigner::from_config(&cfg, vm_id.to_string()).expect("software signer builds");
    (signer, vk)
}

#[test]
fn software_signer_exposes_configured_algorithm_and_vm_id() {
    let (signer, _vk) = build_software_signer(JWK_ENV_ALG, "did:web:example#software-1");
    assert_eq!(signer.algorithm(), SigningAlgorithm::EdDSA);
    assert_eq!(
        signer.verification_method_id(),
        "did:web:example#software-1"
    );
    assert_eq!(signer.readiness(), KeyReadiness::Ready);
}

#[test]
fn software_signer_produces_three_segment_jws_with_expected_header() {
    let (signer, _vk) = build_software_signer(JWK_ENV_SHAPE, "did:web:example#software-2");
    let header = json!({
        "alg": "EdDSA",
        "typ": "vc+jwt",
        "kid": "did:web:example#software-2",
    });
    let payload = json!({
        "iss": "did:web:example",
        "sub": "did:web:example:entity:42",
        "claim": "aggregate_result",
    });
    let jws = signer.sign(header.clone(), payload.clone()).expect("sign");
    let parts: Vec<&str> = jws.split('.').collect();
    assert_eq!(parts.len(), 3, "compact JWS has three segments");

    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .expect("header is base64url");
    let header_round: Value = serde_json::from_slice(&header_bytes).expect("header is JSON");
    assert_eq!(header_round, header);

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("payload is base64url");
    let payload_round: Value = serde_json::from_slice(&payload_bytes).expect("payload is JSON");
    assert_eq!(payload_round, payload);
}

#[test]
fn software_signature_verifies_against_exported_public_key() {
    let (signer, vk) = build_software_signer(JWK_ENV_VERIFY, "did:web:example#software-3");
    let header = json!({"alg":"EdDSA","kid":"did:web:example#software-3"});
    let payload = json!({"foo":"bar"});
    let jws = signer.sign(header, payload).expect("sign");
    let parts: Vec<&str> = jws.split('.').collect();
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let signature_bytes = URL_SAFE_NO_PAD
        .decode(parts[2])
        .expect("signature base64url");
    let signature_arr: [u8; 64] = signature_bytes
        .as_slice()
        .try_into()
        .expect("Ed25519 signature is 64 bytes");
    let signature = ed25519_dalek::Signature::from_bytes(&signature_arr);
    vk.verify_strict(signing_input.as_bytes(), &signature)
        .expect("signature verifies against the exported verifying key");
}

#[test]
fn software_signer_public_jwk_carries_exported_public_key() {
    let (signer, vk) = build_software_signer(JWK_ENV_PUBLIC, "did:web:example#software-jwk");
    let jwk = signer.public_jwk();
    let expected_x = URL_SAFE_NO_PAD.encode(vk.to_bytes());
    let x_str = jwk
        .get("x")
        .and_then(|v| v.as_str())
        .expect("public_jwk carries an `x` field");
    assert_eq!(x_str, expected_x, "public_jwk `x` matches the exported key");
    assert_eq!(jwk["kid"], "did:web:example#software-jwk");
    assert!(
        jwk.get("d").is_none(),
        "public_jwk must not expose private d"
    );
}

struct ExternalTestSigner {
    verification_method_id: String,
    readiness: KeyReadiness,
}

impl Signer for ExternalTestSigner {
    fn algorithm(&self) -> SigningAlgorithm {
        SigningAlgorithm::EdDSA
    }

    fn verification_method_id(&self) -> &str {
        &self.verification_method_id
    }

    fn sign(&self, _header: Value, _payload: Value) -> Result<String, SignerError> {
        Ok("e30.e30.c2lnbmF0dXJl".to_string())
    }

    fn public_jwk(&self) -> Value {
        json!({
            "kty": "OKP",
            "crv": "Ed25519",
            "x": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "kid": self.verification_method_id,
        })
    }

    fn readiness(&self) -> KeyReadiness {
        self.readiness
    }
}

#[test]
fn signer_trait_accepts_future_external_adapters() {
    let signer: Box<dyn Signer> = Box::new(ExternalTestSigner {
        verification_method_id: "did:web:example#future-adapter".to_string(),
        readiness: KeyReadiness::Degraded,
    });
    assert_eq!(signer.algorithm(), SigningAlgorithm::EdDSA);
    assert_eq!(
        signer.verification_method_id(),
        "did:web:example#future-adapter"
    );
    assert_eq!(
        signer.sign(json!({}), json!({})).expect("external sign"),
        "e30.e30.c2lnbmF0dXJl"
    );
    assert_eq!(signer.readiness(), KeyReadiness::Degraded);
}
