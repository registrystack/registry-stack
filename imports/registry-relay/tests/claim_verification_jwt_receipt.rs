// SPDX-License-Identifier: Apache-2.0
//! Claim-verification signed JWT receipt shape and signing tests.

use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey, SECRET_KEY_LENGTH};
use rand_core::OsRng;
use registry_relay::provenance::jwt_receipt::{
    self, ClaimVerificationReceiptInputs, CLAIM_VERIFICATION_RECEIPT_MEDIA_TYPE,
    CLAIM_VERIFICATION_RECEIPT_TYPE,
};
use registry_relay::provenance::signers::software::SoftwareSigner;
use registry_relay::provenance::{
    ClaimVerificationReceiptContext, IssuerMode, ProvenanceState, ResolvedClaimValidity,
    ResolvedProvenanceConfig, ResolvedUrls, Signer, SigningAlgorithm,
};
use serde_json::{json, Value};
use time::OffsetDateTime;

fn export_jwk() -> (String, VerifyingKey) {
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
    (serde_json::to_string(&jwk).unwrap(), vk)
}

fn build_signer(vm_id: &str) -> (SoftwareSigner, VerifyingKey) {
    let (jwk, vk) = export_jwk();
    let signer = SoftwareSigner::from_jwk_str(&jwk, SigningAlgorithm::EdDSA, vm_id.to_string())
        .expect("signer builds");
    (signer, vk)
}

fn decode_part(part: &str) -> Value {
    let bytes = URL_SAFE_NO_PAD
        .decode(part)
        .expect("compact-JWS part is base64url");
    serde_json::from_slice(&bytes).expect("compact-JWS part is JSON")
}

fn split_and_verify(compact_jws: &str, vk: &VerifyingKey) -> (Value, Value) {
    let parts: Vec<&str> = compact_jws.split('.').collect();
    assert_eq!(parts.len(), 3, "compact JWS must have three parts");

    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).expect("sig base64url");
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .expect("Ed25519 signature is 64 bytes");
    let signature = Signature::from_bytes(&sig_arr);
    vk.verify_strict(signing_input.as_bytes(), &signature)
        .expect("signature must verify against matching public key");

    (decode_part(parts[0]), decode_part(parts[1]))
}

#[test]
fn receipt_header_payload_shape_and_signature_verify() {
    let (signer, vk) = build_signer("did:web:data.example.gov#key-1");
    let issued_at = OffsetDateTime::from_unix_timestamp(1_779_013_800).unwrap();
    let valid_until = issued_at + time::Duration::seconds(300);

    let receipt = jwt_receipt::encode(
        &signer,
        ClaimVerificationReceiptInputs {
            issuer: "did:web:data.example.gov".to_string(),
            subject: "client:benefits-service".to_string(),
            audience: "client:benefits-service".to_string(),
            issued_at,
            valid_until,
            verification_id: "01J5K8M0000000000000000ABC".to_string(),
            dataset: "civil_registry".to_string(),
            entity: "birth_record".to_string(),
            decision: "match".to_string(),
            ruleset: "birth-certificate-request-v1".to_string(),
            purpose_declared: Some("benefits-eligibility".to_string()),
            checked_at: "2026-05-17T10:30:00Z".to_string(),
            claim_hash: "hmac-sha256:4a1f9c2b8d7e0f".to_string(),
            evidence_hash: Some("hmac-sha256:9f14a0d2bc331e".to_string()),
        },
    )
    .expect("receipt encodes");

    assert_eq!(
        receipt.jti,
        "urn:registry-relay:claim-verification:01J5K8M0000000000000000ABC"
    );

    let (header, payload) = split_and_verify(&receipt.compact_jws, &vk);

    assert_eq!(header["alg"], "EdDSA");
    assert_eq!(header["typ"], "claim-verification-receipt+jwt");
    assert_eq!(header["kid"], "did:web:data.example.gov#key-1");
    assert!(
        header.get("cty").is_none(),
        "claim-verification receipts must not emit VC cty"
    );

    assert_eq!(payload["iss"], "did:web:data.example.gov");
    assert_eq!(payload["sub"], "client:benefits-service");
    assert_eq!(payload["aud"], "client:benefits-service");
    assert_eq!(payload["iat"], issued_at.unix_timestamp());
    assert_eq!(payload["nbf"], issued_at.unix_timestamp() - 5);
    assert_eq!(payload["exp"], valid_until.unix_timestamp());
    assert_eq!(payload["jti"], receipt.jti);
    assert_eq!(payload["receipt_type"], CLAIM_VERIFICATION_RECEIPT_TYPE);
    assert_eq!(payload["verification_id"], "01J5K8M0000000000000000ABC");
    assert_eq!(payload["dataset"], "civil_registry");
    assert_eq!(payload["entity"], "birth_record");
    assert_eq!(payload["decision"], "match");
    assert_eq!(payload["ruleset"], "birth-certificate-request-v1");
    assert_eq!(payload["purpose_declared"], "benefits-eligibility");
    assert_eq!(payload["checked_at"], "2026-05-17T10:30:00Z");
    assert_eq!(payload["claim_hash"], "hmac-sha256:4a1f9c2b8d7e0f");
    assert_eq!(payload["evidence_hash"], "hmac-sha256:9f14a0d2bc331e");

    for forbidden in [
        "@context",
        "type",
        "credentialSubject",
        "credentialStatus",
        "validFrom",
        "validUntil",
    ] {
        assert!(
            payload.get(forbidden).is_none(),
            "receipt payload must not contain VC field {forbidden}"
        );
    }
}

#[test]
fn provenance_state_receipt_uses_verify_result_validity_window() {
    let (signer, vk) = build_signer("did:web:data.example.gov#receipt");
    let signer: Arc<dyn Signer> = Arc::new(signer);
    let state = ProvenanceState::new(ResolvedProvenanceConfig {
        enabled: true,
        mode: IssuerMode::Gateway,
        issuer_did: "did:web:data.example.gov".to_string(),
        verification_method_id: "did:web:data.example.gov#receipt".to_string(),
        accepted_media_types: vec![CLAIM_VERIFICATION_RECEIPT_MEDIA_TYPE.to_string()],
        claim_validity: ResolvedClaimValidity {
            verify_result: Duration::from_secs(300),
            aggregate_result: Duration::from_secs(86_400),
            entity_record: Duration::from_secs(86_400),
        },
        urls: ResolvedUrls {
            provenance_context_url: "https://gw.example/contexts/provenance/v1.jsonld".to_string(),
            schema_base_url: "https://gw.example/schemas".to_string(),
        },
        signer,
        retired_keys: vec![],
    });

    let issued_at = OffsetDateTime::from_unix_timestamp(1_779_013_800).unwrap();
    let receipt = state
        .issue_claim_verification_receipt(ClaimVerificationReceiptContext {
            subject: "client:benefits-service".to_string(),
            audience: "client:benefits-service".to_string(),
            verification_id: "01J5K8M0000000000000000ABD".to_string(),
            dataset: "civil_registry".to_string(),
            entity: "birth_record".to_string(),
            decision: "mismatch".to_string(),
            ruleset: "birth-certificate-request-v1".to_string(),
            purpose_declared: None,
            checked_at: "2026-05-17T10:30:00Z".to_string(),
            claim_hash: "hmac-sha256:abc".to_string(),
            evidence_hash: None,
            issued_at,
        })
        .expect("state issues receipt");

    assert_eq!(receipt.iat, issued_at.unix_timestamp());
    assert_eq!(receipt.nbf, issued_at.unix_timestamp() - 5);
    assert_eq!(receipt.exp, issued_at.unix_timestamp() + 300);

    let (header, payload) = split_and_verify(&receipt.compact_jws, &vk);
    assert_eq!(header["typ"], "claim-verification-receipt+jwt");
    assert_eq!(header["kid"], "did:web:data.example.gov#receipt");
    assert_eq!(payload["exp"], issued_at.unix_timestamp() + 300);
    assert!(payload.get("purpose_declared").is_none());
    assert!(
        payload.get("evidence_hash").is_none(),
        "evidence_hash should be omitted when no evidence was submitted"
    );
}
