// SPDX-License-Identifier: Apache-2.0
//! End-to-end orchestrator coverage: build a [`ResolvedProvenanceConfig`]
//! by hand (with a [`SoftwareSigner`]), call
//! [`ProvenanceState::issue`] for each claim type, and verify the
//! resulting compact JWS against the matching public key.
//!
//! The unit-level shape tests in `provenance_jwt_envelope.rs` already
//! pin the VCDM 2.0 invariants; this binary covers the wiring between
//! the resolved config (URLs, claim validity windows, signer choice)
//! and the envelope encoder, plus the cross-check that
//! `exp == iat + claim_validity.<type>` per claim type.

use std::env;
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey, SECRET_KEY_LENGTH};
use rand_core::OsRng;
use registry_relay::config::{ProvenanceAlgorithm, SoftwareSignerConfig};
use registry_relay::provenance::jwt_vc::ClaimType;
use registry_relay::provenance::signers::software::SoftwareSigner;
use registry_relay::provenance::{
    IssuanceContext, IssuerMode, ProvenanceState, ResolvedClaimValidity, ResolvedProvenanceConfig,
    ResolvedUrls, Signer,
};
use serde_json::{json, Value};
use time::OffsetDateTime;

fn export_jwk(env_name: &str) -> VerifyingKey {
    let sk = SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key();
    let d_bytes: [u8; SECRET_KEY_LENGTH] = sk.to_bytes();
    let jwk = json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "d": URL_SAFE_NO_PAD.encode(d_bytes),
        "x": URL_SAFE_NO_PAD.encode(vk.to_bytes()),
        "alg": "EdDSA",
    });
    env::set_var(env_name, serde_json::to_string(&jwk).unwrap());
    vk
}

fn build_state(
    env_name: &str,
    aggregate_window: Duration,
    entity_window: Duration,
) -> (ProvenanceState, VerifyingKey) {
    let vk = export_jwk(env_name);
    let cfg = SoftwareSignerConfig {
        jwk_env: env_name.to_string(),
        signing_algorithm: ProvenanceAlgorithm::EdDSA,
    };
    let signer = SoftwareSigner::from_config(&cfg, "did:web:gw.example#orch".to_string())
        .expect("signer builds");
    let signer: Arc<dyn Signer> = Arc::new(signer);
    let resolved = ResolvedProvenanceConfig {
        enabled: true,
        mode: IssuerMode::Gateway,
        issuer_did: "did:web:gw.example".to_string(),
        verification_method_id: "did:web:gw.example#orch".to_string(),
        accepted_media_types: vec!["application/vc+jwt".to_string()],
        claim_validity: ResolvedClaimValidity {
            aggregate_result: aggregate_window,
            entity_record: entity_window,
        },
        urls: ResolvedUrls {
            provenance_context_url: "https://gw.example/contexts/provenance/v1.jsonld".to_string(),
            schema_base_url: "https://gw.example/schemas".to_string(),
        },
        signer,
        retired_keys: Vec::new(),
    };
    (ProvenanceState::new(resolved), vk)
}

fn decode_payload(jws: &str, vk: &VerifyingKey) -> Value {
    let parts: Vec<&str> = jws.split('.').collect();
    assert_eq!(parts.len(), 3, "compact JWS shape");
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).expect("sig base64url");
    let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().expect("64-byte sig");
    let signature = Signature::from_bytes(&sig_arr);
    vk.verify_strict(signing_input.as_bytes(), &signature)
        .expect("signature verifies");
    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).expect("payload base64url");
    serde_json::from_slice(&payload_bytes).expect("payload is JSON")
}

#[test]
fn orchestrator_issues_signed_vc_for_each_claim_type() {
    let aggregate_window = Duration::from_secs(3600); // 1 hour
    let entity_window = Duration::from_secs(86_400); // 24 hours
    let (state, vk) = build_state("ORCHESTRATOR_TEST_JWK", aggregate_window, entity_window);

    let issued_at = OffsetDateTime::from_unix_timestamp(1_730_000_000).unwrap();

    for (claim_type, expected_window, expected_schema, expected_tag) in [
        (
            ClaimType::AggregateResult,
            aggregate_window,
            "https://gw.example/schemas/aggregate-result/v1.json",
            "AggregateResult",
        ),
        (
            ClaimType::EntityRecord,
            entity_window,
            "https://gw.example/schemas/entity-record/v1.json",
            "EntityRecord",
        ),
    ] {
        let signed = state
            .issue(IssuanceContext {
                claim_type,
                subject_uri: "https://gw.example/sub".to_string(),
                credential_subject: json!({"id": "https://gw.example/sub"}),
                issued_at,
            })
            .expect("issue must succeed");

        // Metadata cross-checks.
        assert_eq!(signed.claim_type, claim_type);
        assert_eq!(signed.issuer_did, "did:web:gw.example");
        assert_eq!(signed.verification_method_id, "did:web:gw.example#orch");
        assert_eq!(signed.subject_uri, "https://gw.example/sub");
        assert_eq!(signed.iat, issued_at.unix_timestamp());
        assert_eq!(signed.nbf, signed.iat);
        assert_eq!(
            signed.exp,
            signed.iat + (expected_window.as_secs() as i64),
            "exp should equal iat + claim_validity for {claim_type:?}",
        );
        assert!(
            signed.jti.starts_with("urn:uuid:"),
            "jti must be urn:uuid: prefixed, got {}",
            signed.jti
        );

        // Cryptographic + structural payload verification.
        let payload = decode_payload(&signed.compact_jws, &vk);
        assert_eq!(payload["type"][1], expected_tag);
        assert_eq!(payload["credentialSchema"]["id"], expected_schema);
        assert_eq!(
            payload["@context"][1],
            "https://gw.example/contexts/provenance/v1.jsonld"
        );
        assert_eq!(payload["jti"], signed.jti);
        assert_eq!(payload["id"], signed.jti);
        assert_eq!(payload["iat"].as_i64().unwrap(), signed.iat);
        assert_eq!(payload["nbf"].as_i64().unwrap(), signed.nbf);
        assert_eq!(payload["exp"].as_i64().unwrap(), signed.exp);
    }
}

#[test]
fn each_issuance_gets_a_fresh_jti() {
    let (state, _vk) = build_state(
        "ORCHESTRATOR_TEST_FRESH_JTI_JWK",
        Duration::from_secs(60),
        Duration::from_secs(60),
    );
    let issued_at = OffsetDateTime::from_unix_timestamp(1_730_100_000).unwrap();
    let ctx = || IssuanceContext {
        claim_type: ClaimType::AggregateResult,
        subject_uri: "https://gw.example/sub".to_string(),
        credential_subject: json!({"id": "https://gw.example/sub"}),
        issued_at,
    };
    let a = state.issue(ctx()).expect("issue a");
    let b = state.issue(ctx()).expect("issue b");
    assert_ne!(a.jti, b.jti, "jti must be unique across issuances");
    assert_ne!(
        a.compact_jws, b.compact_jws,
        "compact JWS must differ because jti differs"
    );
}
