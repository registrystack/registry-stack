// SPDX-License-Identifier: Apache-2.0
//! Evidence-verification signed JWT receipt shape and signing tests.

use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey, SECRET_KEY_LENGTH};
use rand_core::OsRng;
use registry_relay::provenance::jwt_receipt::{
    self, EvidenceVerificationReceiptInputs, EVIDENCE_VERIFICATION_RECEIPT_MEDIA_TYPE,
    EVIDENCE_VERIFICATION_RECEIPT_TYPE,
};
use registry_relay::provenance::signers::software::SoftwareSigner;
use registry_relay::provenance::{
    EvidenceVerificationReceiptContext, IssuerMode, ProvenanceState, ResolvedClaimValidity,
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

fn sample_cccev_evidence(decision: &str) -> Value {
    json!({
        "@type": "cccev:Evidence",
        "cccev:supportsValue": {
            "@type": "cccev:SupportedValue",
            "cccev:value": decision,
        }
    })
}

#[test]
fn receipt_header_payload_shape_and_signature_verify() {
    let (signer, vk) = build_signer("did:web:data.example.gov#key-1");
    let issued_at = OffsetDateTime::from_unix_timestamp(1_779_013_800).unwrap();
    let valid_until = issued_at + time::Duration::seconds(300);

    let receipt = jwt_receipt::encode(
        &signer,
        EvidenceVerificationReceiptInputs {
            issuer: "did:web:data.example.gov".to_string(),
            subject: "did:web:data.example.gov".to_string(),
            audience: "client:benefits-service".to_string(),
            issued_at,
            valid_until,
            verification_id: "01J5K8M0000000000000000ABC".to_string(),
            decision: "match".to_string(),
            requirement: Some("https://data.example.gov/requirements/birth-facts".to_string()),
            evidence_type: "https://data.example.gov/evidence-types/birth-record-facts".to_string(),
            evidence_offering: "https://data.example.gov/evidence-offerings/birth-record-facts"
                .to_string(),
            issuing_authority: json!({
                "id": "civil_registry_authority",
                "name": "Civil Registry Authority",
                "country": "FR"
            }),
            jurisdiction: Some(json!({ "country": "FR" })),
            level_of_assurance: Some("substantial".to_string()),
            dataset: "civil_registry".to_string(),
            entity: "birth_record".to_string(),
            purpose_declared: Some("benefits-eligibility".to_string()),
            checked_at: "2026-05-17T10:30:00Z".to_string(),
            claim_salt: "0123456789abcdef0123456789abcdef".to_string(),
            claim_hash: "hmac-sha256:4a1f9c2b8d7e0f".to_string(),
            evidence_hash: Some("hmac-sha256:9f14a0d2bc331e".to_string()),
            cccev_evidence: sample_cccev_evidence("match"),
        },
    )
    .expect("receipt encodes");

    assert_eq!(
        receipt.jti,
        "urn:registry-relay:evidence-verification:01J5K8M0000000000000000ABC"
    );

    let (header, payload) = split_and_verify(&receipt.compact_jws, &vk);

    assert_eq!(header["alg"], "EdDSA");
    assert_eq!(header["typ"], "evidence-verification-receipt+jwt");
    assert_eq!(header["kid"], "did:web:data.example.gov#key-1");
    assert!(
        header.get("cty").is_none(),
        "evidence-verification receipts must not emit VC cty"
    );

    assert_eq!(payload["iss"], "did:web:data.example.gov");
    assert_eq!(payload["sub"], "did:web:data.example.gov");
    assert_eq!(payload["aud"], "client:benefits-service");
    assert_ne!(payload["sub"], payload["aud"]);
    assert_eq!(payload["iat"], issued_at.unix_timestamp());
    assert_eq!(payload["nbf"], issued_at.unix_timestamp() - 5);
    assert_eq!(payload["exp"], valid_until.unix_timestamp());
    assert_eq!(payload["jti"], receipt.jti);
    assert_eq!(payload["receipt_type"], EVIDENCE_VERIFICATION_RECEIPT_TYPE);
    assert_eq!(payload["verification_id"], "01J5K8M0000000000000000ABC");
    assert_eq!(payload["decision"], "match");
    assert_eq!(
        payload["requirement"],
        "https://data.example.gov/requirements/birth-facts"
    );
    assert_eq!(
        payload["evidence_type"],
        "https://data.example.gov/evidence-types/birth-record-facts"
    );
    assert_eq!(
        payload["evidence_offering"],
        "https://data.example.gov/evidence-offerings/birth-record-facts"
    );
    assert_eq!(payload["issuing_authority"]["country"], "FR");
    assert_eq!(payload["jurisdiction"]["country"], "FR");
    assert_eq!(payload["level_of_assurance"], "substantial");
    assert_eq!(payload["dataset"], "civil_registry");
    assert_eq!(payload["entity"], "birth_record");
    assert_eq!(
        payload["disclaimer"],
        "This token records that a verification check was executed. It does not attest that the subject holds any status or right."
    );
    assert_eq!(payload["purpose_declared"], "benefits-eligibility");
    assert_eq!(payload["checked_at"], "2026-05-17T10:30:00Z");
    assert_eq!(payload["claim_hash"], "hmac-sha256:4a1f9c2b8d7e0f");
    assert_eq!(payload["evidence_hash"], "hmac-sha256:9f14a0d2bc331e");
    assert_eq!(payload["cccev_evidence"]["@type"], "cccev:Evidence");
    assert_eq!(
        payload["cccev_evidence"]["cccev:supportsValue"]["cccev:value"],
        "match"
    );

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
fn provenance_state_receipt_validity_is_five_minutes() {
    let (signer, vk) = build_signer("did:web:data.example.gov#receipt");
    let signer: Arc<dyn Signer> = Arc::new(signer);
    let state = ProvenanceState::new(ResolvedProvenanceConfig {
        enabled: true,
        mode: IssuerMode::Gateway,
        issuer_did: "did:web:data.example.gov".to_string(),
        verification_method_id: "did:web:data.example.gov#receipt".to_string(),
        accepted_media_types: vec![EVIDENCE_VERIFICATION_RECEIPT_MEDIA_TYPE.to_string()],
        claim_validity: ResolvedClaimValidity {
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
        .issue_evidence_verification_receipt(EvidenceVerificationReceiptContext {
            subject: "client:benefits-service".to_string(),
            audience: "client:casework-system".to_string(),
            verification_id: "01J5K8M0000000000000000ABD".to_string(),
            decision: "mismatch".to_string(),
            requirement: None,
            evidence_type: "https://data.example.gov/evidence-types/birth-record-facts".to_string(),
            evidence_offering: "https://data.example.gov/evidence-offerings/birth-record-facts"
                .to_string(),
            issuing_authority: json!({ "id": "civil_registry_authority" }),
            jurisdiction: None,
            level_of_assurance: None,
            dataset: "civil_registry".to_string(),
            entity: "birth_record".to_string(),
            purpose_declared: None,
            checked_at: "2026-05-17T10:30:00Z".to_string(),
            claim_salt: "0123456789abcdef0123456789abcdef".to_string(),
            claim_hash: "hmac-sha256:abc".to_string(),
            evidence_hash: None,
            cccev_evidence: sample_cccev_evidence("mismatch"),
            issued_at,
        })
        .expect("state issues receipt");

    assert_eq!(receipt.iat, issued_at.unix_timestamp());
    assert_eq!(receipt.nbf, issued_at.unix_timestamp() - 5);
    assert_eq!(receipt.exp, issued_at.unix_timestamp() + 300);

    let (header, payload) = split_and_verify(&receipt.compact_jws, &vk);
    assert_eq!(header["typ"], "evidence-verification-receipt+jwt");
    assert_eq!(header["kid"], "did:web:data.example.gov#receipt");
    assert_eq!(payload["exp"], issued_at.unix_timestamp() + 300);
    assert_eq!(payload["sub"], "client:benefits-service");
    assert_eq!(payload["aud"], "client:casework-system");
    assert_ne!(payload["sub"], payload["aud"]);
    assert_eq!(
        payload["cccev_evidence"]["cccev:supportsValue"]["cccev:value"],
        "mismatch"
    );
    assert!(payload.get("purpose_declared").is_none());
    assert!(
        payload.get("evidence_hash").is_none(),
        "evidence_hash should be omitted when no evidence was submitted"
    );
}

#[test]
fn provenance_state_caps_receipt_validity_at_five_minutes() {
    let (signer, _vk) = build_signer("did:web:data.example.gov#receipt");
    let signer: Arc<dyn Signer> = Arc::new(signer);
    let state = ProvenanceState::new(ResolvedProvenanceConfig {
        enabled: true,
        mode: IssuerMode::Gateway,
        issuer_did: "did:web:data.example.gov".to_string(),
        verification_method_id: "did:web:data.example.gov#receipt".to_string(),
        accepted_media_types: vec![EVIDENCE_VERIFICATION_RECEIPT_MEDIA_TYPE.to_string()],
        claim_validity: ResolvedClaimValidity {
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
        .issue_evidence_verification_receipt(EvidenceVerificationReceiptContext {
            subject: "did:web:data.example.gov".to_string(),
            audience: "client:benefits-service".to_string(),
            verification_id: "01J5K8M0000000000000000ABE".to_string(),
            decision: "match".to_string(),
            requirement: None,
            evidence_type: "https://data.example.gov/evidence-types/birth-record-facts".to_string(),
            evidence_offering: "https://data.example.gov/evidence-offerings/birth-record-facts"
                .to_string(),
            issuing_authority: json!({ "id": "civil_registry_authority" }),
            jurisdiction: None,
            level_of_assurance: None,
            dataset: "civil_registry".to_string(),
            entity: "birth_record".to_string(),
            purpose_declared: None,
            checked_at: "2026-05-17T10:30:00Z".to_string(),
            claim_salt: "0123456789abcdef0123456789abcdef".to_string(),
            claim_hash: "hmac-sha256:abc".to_string(),
            evidence_hash: None,
            cccev_evidence: sample_cccev_evidence("match"),
            issued_at,
        })
        .expect("state issues receipt");

    assert_eq!(receipt.exp, issued_at.unix_timestamp() + 300);
}
