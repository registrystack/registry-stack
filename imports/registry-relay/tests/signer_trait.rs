// SPDX-License-Identifier: Apache-2.0
//! Trait-surface tests for [`data_gate::provenance::Signer`].
//!
//! Drives the [`MockKmsSigner`] through the trait to confirm:
//!
//! * `algorithm()` and `verification_method_id()` reflect the
//!   configuration.
//! * `sign()` returns a 3-segment compact JWS (header.payload.sig)
//!   whose header decodes to JSON with the expected fields and whose
//!   signature verifies against the seeded key.
//! * Misconfigurations surface as `SignerError::AlgorithmMismatch` /
//!   `KeyLoad` without panicking.

use std::env;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use data_gate::config::{KmsProvider, KmsSignerConfig, ProvenanceAlgorithm};
use data_gate::provenance::signers::kms::MockKmsSigner;
use data_gate::provenance::{Signer, SignerError, SigningAlgorithm};
use ed25519_dalek::{SigningKey, VerifyingKey, SECRET_KEY_LENGTH};
use rand_core::OsRng;
use serde_json::json;

const MISMATCH_SEED_ENV: &str = "SIGNER_TRAIT_TEST_MOCK_SEED_MISMATCH";
// Each #[test] case uses its own env var name. cargo runs `#[test]`
// cases inside a single binary in parallel by default; sharing one env
// name across tests would race when each test generates and exports a
// fresh seed.
const SEED_ENV_ALG: &str = "SIGNER_TRAIT_TEST_SEED_ALG";
const SEED_ENV_SHAPE: &str = "SIGNER_TRAIT_TEST_SEED_SHAPE";
const SEED_ENV_VERIFY: &str = "SIGNER_TRAIT_TEST_SEED_VERIFY";
const SEED_ENV_JWK: &str = "SIGNER_TRAIT_TEST_SEED_JWK";

fn generate_seed_and_export(env_name: &str) -> SigningKey {
    let sk = SigningKey::generate(&mut OsRng);
    let bytes: [u8; SECRET_KEY_LENGTH] = sk.to_bytes();
    let encoded = URL_SAFE_NO_PAD.encode(bytes);
    env::set_var(env_name, encoded);
    sk
}

fn build_mock_signer(env_name: &str, vm_id: &str) -> (MockKmsSigner, VerifyingKey) {
    let sk = generate_seed_and_export(env_name);
    let vk = sk.verifying_key();
    let cfg = KmsSignerConfig {
        provider: KmsProvider::Mock,
        key_id: env_name.to_string(),
        signing_algorithm: ProvenanceAlgorithm::EdDSA,
    };
    let signer = MockKmsSigner::from_config(&cfg, vm_id.to_string()).expect("mock signer builds");
    (signer, vk)
}

#[test]
fn mock_signer_exposes_configured_algorithm_and_vm_id() {
    let (signer, _vk) = build_mock_signer(SEED_ENV_ALG, "did:web:example#mock-1");
    assert_eq!(signer.algorithm(), SigningAlgorithm::EdDSA);
    assert_eq!(signer.verification_method_id(), "did:web:example#mock-1");
}

#[test]
fn mock_signer_produces_three_segment_jws_with_expected_header() {
    let (signer, _vk) = build_mock_signer(SEED_ENV_SHAPE, "did:web:example#mock-2");
    let header = json!({
        "alg": "EdDSA",
        "typ": "vc+jwt",
        "kid": "did:web:example#mock-2",
    });
    let payload = json!({
        "iss": "did:web:example",
        "sub": "did:web:example:entity:42",
        "claim": "verify_result",
    });
    let jws = signer.sign(header.clone(), payload.clone()).expect("sign");
    let parts: Vec<&str> = jws.split('.').collect();
    assert_eq!(parts.len(), 3, "compact JWS has three segments");

    let header_bytes = URL_SAFE_NO_PAD
        .decode(parts[0])
        .expect("header is base64url");
    let header_round: serde_json::Value =
        serde_json::from_slice(&header_bytes).expect("header is JSON");
    assert_eq!(header_round, header);

    let payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("payload is base64url");
    let payload_round: serde_json::Value =
        serde_json::from_slice(&payload_bytes).expect("payload is JSON");
    assert_eq!(payload_round, payload);
}

#[test]
fn mock_signature_verifies_against_seeded_public_key() {
    let (signer, vk) = build_mock_signer(SEED_ENV_VERIFY, "did:web:example#mock-3");
    let header = json!({"alg":"EdDSA","kid":"did:web:example#mock-3"});
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
        .expect("signature verifies against the seeded verifying key");
}

#[test]
fn mock_signer_public_jwk_carries_seeded_public_key() {
    // B5: the mock kms signer must publish a real `x` so consumers of
    // `public_jwk()` can verify the signatures it produces. Previously
    // the JWK was emitted with an empty / missing `x`, which made the
    // DID-Document path unverifiable.
    let (signer, vk) = build_mock_signer(SEED_ENV_JWK, "did:web:example#mock-jwk");
    let jwk = signer.public_jwk();
    let expected_x = URL_SAFE_NO_PAD.encode(vk.to_bytes());
    let x_str = jwk
        .get("x")
        .and_then(|v| v.as_str())
        .expect("public_jwk carries an `x` field");
    assert_eq!(x_str, expected_x, "public_jwk `x` matches the seeded key");
    let x_bytes = URL_SAFE_NO_PAD
        .decode(x_str)
        .expect("public_jwk `x` decodes as base64url");
    assert_eq!(x_bytes.len(), 32, "Ed25519 public key is 32 bytes");

    // And the published `x` should round-trip to a verifying key that
    // verifies a signature produced by the same signer.
    let header = json!({"alg":"EdDSA","kid":"did:web:example#mock-jwk"});
    let payload = json!({"hello":"world"});
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
    let x_arr: [u8; 32] = x_bytes.as_slice().try_into().expect("x is 32 bytes");
    let reconstructed_vk =
        VerifyingKey::from_bytes(&x_arr).expect("public_jwk `x` is a valid Ed25519 key");
    reconstructed_vk
        .verify_strict(signing_input.as_bytes(), &signature)
        .expect("signature verifies against the public_jwk-derived key");
}

#[test]
fn mock_signer_rejects_es256_algorithm() {
    generate_seed_and_export(MISMATCH_SEED_ENV);
    let cfg = KmsSignerConfig {
        provider: KmsProvider::Mock,
        key_id: MISMATCH_SEED_ENV.to_string(),
        signing_algorithm: ProvenanceAlgorithm::ES256,
    };
    let err = MockKmsSigner::from_config(&cfg, "did:web:example#mock-4".to_string())
        .expect_err("ES256 must be rejected by the mock");
    match err {
        SignerError::AlgorithmMismatch => {}
        other => panic!("expected AlgorithmMismatch, got {other:?}"),
    }
}

#[test]
fn mock_signer_rejects_aws_provider() {
    env::set_var(
        "SIGNER_TRAIT_TEST_AWS_REJECT",
        URL_SAFE_NO_PAD.encode([0u8; 32]),
    );
    let cfg = KmsSignerConfig {
        provider: KmsProvider::AwsKms,
        key_id: "SIGNER_TRAIT_TEST_AWS_REJECT".to_string(),
        signing_algorithm: ProvenanceAlgorithm::EdDSA,
    };
    let err = MockKmsSigner::from_config(&cfg, "did:web:example#mock-5".to_string())
        .expect_err("AwsKms must be rejected by the mock");
    assert!(matches!(err, SignerError::KeyLoad { .. }));
}

#[test]
fn signer_error_does_not_carry_secret_material_in_display() {
    // Defensive: confirm the Display impl is what we expect so the
    // error never leaks a private key reason verbatim into a response
    // body. (The Display already uses the static reason strings.)
    let err = SignerError::KeyLoad {
        reason: "fake reason for display",
    };
    let msg = format!("{err}");
    assert!(msg.contains("fake reason for display"));
    assert!(!msg.contains("0x"));
}
