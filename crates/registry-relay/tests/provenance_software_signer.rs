// SPDX-License-Identifier: Apache-2.0
//! End-to-end tests for the in-process software signer.
//!
//! Generates a fresh Ed25519 keypair, writes the private JWK into an
//! env var, builds [`SoftwareSigner`], signs a sample VC-shaped payload,
//! and verifies the resulting compact JWS against the matching public
//! key. Also covers the rejection branches (`kty`/`crv` mismatch,
//! malformed `d`, ES256 deferred).

use std::env;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{SigningKey, VerifyingKey, SECRET_KEY_LENGTH};
use rand_core::OsRng;
use registry_relay::config::{ProvenanceAlgorithm, SoftwareSignerConfig};
use registry_relay::provenance::signers::software::SoftwareSigner;
use registry_relay::provenance::{Signer, SignerError, SigningAlgorithm};
use serde_json::json;

fn export_jwk(env_name: &str) -> (SigningKey, VerifyingKey) {
    let sk = SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key();
    let d_bytes: [u8; SECRET_KEY_LENGTH] = sk.to_bytes();
    let d_b64 = URL_SAFE_NO_PAD.encode(d_bytes);
    let x_b64 = URL_SAFE_NO_PAD.encode(vk.to_bytes());
    let jwk = json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "d": d_b64,
        "x": x_b64,
        "alg": "EdDSA",
        "kid": "did:web:example#sw-test",
    });
    env::set_var(
        env_name,
        serde_json::to_string(&jwk).expect("jwk to string"),
    );
    (sk, vk)
}

fn build_signer(env_name: &str, vm_id: &str) -> (SoftwareSigner, VerifyingKey) {
    let (_sk, vk) = export_jwk(env_name);
    let cfg = SoftwareSignerConfig {
        jwk_env: env_name.to_string(),
        signing_algorithm: ProvenanceAlgorithm::EdDSA,
    };
    let signer = SoftwareSigner::from_config(&cfg, vm_id.to_string()).expect("signer builds");
    (signer, vk)
}

#[test]
fn software_signer_signs_and_round_trips() {
    let (signer, vk) = build_signer("SOFTWARE_SIGNER_TEST_OK_JWK", "did:web:example#sw-ok");
    assert_eq!(signer.algorithm(), SigningAlgorithm::EdDSA);
    assert_eq!(signer.verification_method_id(), "did:web:example#sw-ok");

    let header = json!({
        "alg": "EdDSA",
        "typ": "vc+jwt",
        "kid": "did:web:example#sw-ok",
    });
    let payload = json!({
        "iss": "did:web:example",
        "sub": "did:web:example:entity:hello",
        "iat": 1_700_000_000,
        "vc_claim": {
            "kind": "aggregate_result",
            "match": true,
        },
    });
    let jws = signer.sign(header, payload).expect("sign");
    let parts: Vec<&str> = jws.split('.').collect();
    assert_eq!(parts.len(), 3);

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let signature_bytes = URL_SAFE_NO_PAD.decode(parts[2]).expect("sig base64url");
    let signature_arr: [u8; 64] = signature_bytes
        .as_slice()
        .try_into()
        .expect("Ed25519 signature is 64 bytes");
    let signature = ed25519_dalek::Signature::from_bytes(&signature_arr);
    vk.verify_strict(signing_input.as_bytes(), &signature)
        .expect("signature verifies");
}

#[test]
fn public_jwk_carries_kid_and_kty() {
    let (signer, _vk) = build_signer("SOFTWARE_SIGNER_TEST_PUB_JWK", "did:web:example#sw-pub");
    let pjwk = signer.public_jwk();
    assert_eq!(pjwk["kty"], "OKP");
    assert_eq!(pjwk["crv"], "Ed25519");
    assert_eq!(pjwk["alg"], "EdDSA");
    assert_eq!(pjwk["kid"], "did:web:example#sw-test");
    // Private d must not appear.
    assert!(pjwk.get("d").is_none(), "public_jwk leaked private d field");
}

#[test]
fn missing_env_var_returns_key_load_error() {
    let env_name = "SOFTWARE_SIGNER_TEST_UNSET_JWK";
    env::remove_var(env_name);
    let cfg = SoftwareSignerConfig {
        jwk_env: env_name.to_string(),
        signing_algorithm: ProvenanceAlgorithm::EdDSA,
    };
    let err = SoftwareSigner::from_config(&cfg, "did:web:example#sw-unset".to_string())
        .expect_err("unset env must fail");
    assert!(matches!(err, SignerError::KeyLoad { .. }));
}

#[test]
fn malformed_jwk_returns_key_load_error() {
    let env_name = "SOFTWARE_SIGNER_TEST_BAD_JWK";
    env::set_var(env_name, "{not: valid json");
    let cfg = SoftwareSignerConfig {
        jwk_env: env_name.to_string(),
        signing_algorithm: ProvenanceAlgorithm::EdDSA,
    };
    let err = SoftwareSigner::from_config(&cfg, "did:web:example#sw-bad".to_string())
        .expect_err("malformed jwk must fail");
    assert!(matches!(err, SignerError::KeyLoad { .. }));
}

#[test]
fn jwk_with_wrong_kty_is_rejected_for_eddsa() {
    let env_name = "SOFTWARE_SIGNER_TEST_WRONG_KTY";
    let jwk = json!({
        "kty": "EC",
        "crv": "Ed25519",
        "d": URL_SAFE_NO_PAD.encode([0u8; 32]),
        "x": URL_SAFE_NO_PAD.encode([0u8; 32]),
    });
    env::set_var(env_name, serde_json::to_string(&jwk).unwrap());
    let cfg = SoftwareSignerConfig {
        jwk_env: env_name.to_string(),
        signing_algorithm: ProvenanceAlgorithm::EdDSA,
    };
    let err = SoftwareSigner::from_config(&cfg, "did:web:example#sw-kty".to_string())
        .expect_err("EC kty must be rejected when EdDSA is configured");
    assert!(matches!(err, SignerError::KeyLoad { .. }));
}

#[test]
fn jwk_declared_alg_must_match_configured_algorithm() {
    let env_name = "SOFTWARE_SIGNER_TEST_ALG_MISMATCH";
    let jwk = json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "d": URL_SAFE_NO_PAD.encode([1u8; 32]),
        "x": URL_SAFE_NO_PAD.encode([2u8; 32]),
        "alg": "ES256",
    });
    env::set_var(env_name, serde_json::to_string(&jwk).unwrap());
    let cfg = SoftwareSignerConfig {
        jwk_env: env_name.to_string(),
        signing_algorithm: ProvenanceAlgorithm::EdDSA,
    };
    let err = SoftwareSigner::from_config(&cfg, "did:web:example#sw-alg".to_string())
        .expect_err("declared alg mismatch must be rejected");
    assert!(matches!(err, SignerError::AlgorithmMismatch));
}

#[test]
fn es256_software_path_is_documented_as_deferred() {
    // The V1 software path returns a KeyLoad error for ES256 with a
    // specific reason string. This test pins that behaviour so the
    // follow-up that wires ES256 must explicitly remove the
    // "deferred" guard.
    let env_name = "SOFTWARE_SIGNER_TEST_ES256_DEFERRED";
    let jwk = json!({
        "kty": "EC",
        "crv": "P-256",
        "d": URL_SAFE_NO_PAD.encode([3u8; 32]),
        "x": URL_SAFE_NO_PAD.encode([4u8; 32]),
        "y": URL_SAFE_NO_PAD.encode([5u8; 32]),
    });
    env::set_var(env_name, serde_json::to_string(&jwk).unwrap());
    let cfg = SoftwareSignerConfig {
        jwk_env: env_name.to_string(),
        signing_algorithm: ProvenanceAlgorithm::ES256,
    };
    let err = SoftwareSigner::from_config(&cfg, "did:web:example#sw-es256".to_string())
        .expect_err("ES256 software path is deferred in V1");
    match err {
        SignerError::KeyLoad { reason } => {
            assert!(
                reason.contains("ES256"),
                "reason should mention ES256, got: {reason}"
            );
        }
        other => panic!("expected KeyLoad for deferred ES256, got {other:?}"),
    }
}
