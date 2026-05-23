// SPDX-License-Identifier: Apache-2.0
//! Cryptographic and structural correctness of the VC-JWT envelope.
//!
//! Mints an Ed25519 keypair, builds a [`SoftwareSigner`] from a private
//! JWK loaded via env var, hands the signer to [`jwt_vc::encode`], and
//! then:
//!
//! * Splits the compact JWS into header / payload / signature.
//! * Verifies the signature byte-for-byte against the matching public
//!   key.
//! * Decodes the header and payload as JSON and asserts the VCDM 2.0
//!   shape (top-level `@context`, `type`, `id`, `issuer`, `validFrom`,
//!   `validUntil`, `credentialSubject`, `credentialSchema` + JWT
//!   registered claims; **no** nested `vc` claim).
//! * Confirms `iat == nbf`, `exp == iat + window`, that `validFrom`
//!   parses to `nbf`, and that `validUntil` parses to `exp`.
//!
//! These invariants are load-bearing for cross-implementation
//! verifiers, so we pin them at the test level rather than relying on
//! the encoder's structure alone.

use std::env;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey, SECRET_KEY_LENGTH};
use rand_core::OsRng;
use registry_relay::config::{ProvenanceAlgorithm, SoftwareSignerConfig};
use registry_relay::provenance::jwt_vc::{self, ClaimType, VcEnvelopeInputs, VCDM_V2_CONTEXT};
use registry_relay::provenance::signers::software::SoftwareSigner;
use serde_json::{json, Value};
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

fn export_jwk(env_name: &str) -> VerifyingKey {
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
    });
    env::set_var(env_name, serde_json::to_string(&jwk).unwrap());
    vk
}

fn build_signer(env_name: &str, vm_id: &str) -> (SoftwareSigner, VerifyingKey) {
    let vk = export_jwk(env_name);
    let cfg = SoftwareSignerConfig {
        jwk_env: env_name.to_string(),
        signing_algorithm: ProvenanceAlgorithm::EdDSA,
    };
    let signer = SoftwareSigner::from_config(&cfg, vm_id.to_string()).expect("signer builds");
    (signer, vk)
}

fn decode_part(part: &str) -> Value {
    let bytes = URL_SAFE_NO_PAD
        .decode(part)
        .expect("compact-JWS part is base64url");
    serde_json::from_slice(&bytes).expect("compact-JWS part is JSON")
}

#[test]
fn vc_jwt_envelope_is_well_shaped_and_verifies() {
    let (signer, vk) = build_signer("VC_JWT_ENVELOPE_TEST_OK_JWK", "did:web:example.test#key-1");

    let issued_at = OffsetDateTime::from_unix_timestamp(1_726_000_000).unwrap();
    let valid_until = OffsetDateTime::from_unix_timestamp(1_726_604_800).unwrap();

    let inputs = VcEnvelopeInputs {
        claim_type: ClaimType::AggregateResult,
        issuer_did: "did:web:example.test".to_string(),
        verification_method_id: "did:web:example.test#key-1".to_string(),
        subject_uri: "https://gw.example/datasets/foo/entity/X".to_string(),
        credential_subject: json!({
            "id": "https://gw.example/datasets/foo/entity/X",
            "dataset": "foo",
            "entity": "entity",
            "subjectId": "X",
            "predicate": "is_eligible",
            "value": true,
            "asOf": "2026-05-16T12:00:00Z",
        }),
        provenance_context_url: "https://gw.example/contexts/provenance/v1.jsonld".to_string(),
        credential_schema_url: "https://gw.example/schemas/aggregate-result/v1.json".to_string(),
        issued_at,
        valid_until,
    };
    let envelope = jwt_vc::encode(&signer, inputs).expect("encode");

    // Compact JWS shape.
    let parts: Vec<&str> = envelope.compact_jws.split('.').collect();
    assert_eq!(parts.len(), 3, "compact JWS must be three parts");

    // Cryptographic verification.
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).expect("sig base64url");
    let sig_arr: [u8; 64] = sig_bytes
        .as_slice()
        .try_into()
        .expect("Ed25519 sig is 64 bytes");
    let signature = Signature::from_bytes(&sig_arr);
    vk.verify_strict(signing_input.as_bytes(), &signature)
        .expect("signature must verify against the matching public key");

    // JOSE header shape.
    let header = decode_part(parts[0]);
    assert_eq!(header["alg"], "EdDSA");
    assert_eq!(header["typ"], "vc+jwt");
    assert_eq!(header["cty"], "vc");
    assert_eq!(header["kid"], "did:web:example.test#key-1");

    // VCDM 2.0 + JWT registered claims payload.
    let payload = decode_part(parts[1]);

    // @context: VCDM v2 base + our provenance context.
    let ctx = payload["@context"].as_array().expect("@context array");
    assert_eq!(ctx[0], VCDM_V2_CONTEXT);
    assert_eq!(ctx[1], "https://gw.example/contexts/provenance/v1.jsonld");

    // type: ["VerifiableCredential", "<ClaimType tag>"].
    let types = payload["type"].as_array().expect("type array");
    assert_eq!(types[0], "VerifiableCredential");
    assert_eq!(types[1], "AggregateResult");

    // id and jti are the same urn:uuid; id is also returned in the
    // metadata struct.
    let payload_id = payload["id"].as_str().expect("id string");
    let payload_jti = payload["jti"].as_str().expect("jti string");
    assert_eq!(payload_id, payload_jti);
    assert_eq!(payload_id, envelope.jti);
    assert!(
        payload_id.starts_with("urn:uuid:"),
        "id must be a urn:uuid, got {payload_id}",
    );

    // issuer == iss; sub == subject_uri.
    assert_eq!(payload["issuer"], "did:web:example.test");
    assert_eq!(payload["iss"], "did:web:example.test");
    assert_eq!(payload["sub"], "https://gw.example/datasets/foo/entity/X");

    // credentialSubject is verbatim.
    assert_eq!(payload["credentialSubject"]["predicate"], "is_eligible");
    assert_eq!(payload["credentialSubject"]["value"], true);

    // credentialSchema embeds the resolved schema URL.
    assert_eq!(
        payload["credentialSchema"]["id"],
        "https://gw.example/schemas/aggregate-result/v1.json"
    );
    assert_eq!(payload["credentialSchema"]["type"], "JsonSchema");

    // No nested vc claim per VCDM 2.0 (legacy claim removed in JOSE/COSE
    // recommendation).
    assert!(
        payload.get("vc").is_none(),
        "VCDM 2.0 JOSE binding forbids a nested vc claim"
    );

    // Timestamp invariants.
    let iat = payload["iat"].as_i64().expect("iat int");
    let nbf = payload["nbf"].as_i64().expect("nbf int");
    let exp = payload["exp"].as_i64().expect("exp int");
    assert_eq!(iat, issued_at.unix_timestamp());
    assert_eq!(nbf, iat);
    assert_eq!(exp, valid_until.unix_timestamp());
    assert_eq!(envelope.iat, iat);
    assert_eq!(envelope.nbf, nbf);
    assert_eq!(envelope.exp, exp);

    // validFrom / validUntil are RFC 3339 strings that parse back to
    // the nbf/exp unix seconds.
    let valid_from_str = payload["validFrom"].as_str().expect("validFrom string");
    let valid_until_str = payload["validUntil"].as_str().expect("validUntil string");
    let parsed_from = OffsetDateTime::parse(valid_from_str, &Rfc3339).expect("validFrom parses");
    let parsed_until = OffsetDateTime::parse(valid_until_str, &Rfc3339).expect("validUntil parses");
    assert_eq!(parsed_from.unix_timestamp(), nbf);
    assert_eq!(parsed_until.unix_timestamp(), exp);
}

#[test]
fn aggregate_and_entity_claim_types_set_the_right_type_tag_and_schema() {
    // Single signer reused across claim types: the encoder selects the
    // tag and schema path from `ClaimType` alone.
    let (signer, _vk) = build_signer(
        "VC_JWT_ENVELOPE_TEST_MULTI_TAG_JWK",
        "did:web:example.test#key-2",
    );
    let issued_at = OffsetDateTime::from_unix_timestamp(1_726_100_000).unwrap();
    let valid_until = OffsetDateTime::from_unix_timestamp(1_726_700_000).unwrap();

    for (claim_type, type_tag, schema_url) in [
        (
            ClaimType::AggregateResult,
            "AggregateResult",
            "https://gw.example/schemas/aggregate-result/v1.json",
        ),
        (
            ClaimType::EntityRecord,
            "EntityRecord",
            "https://gw.example/schemas/entity-record/v1.json",
        ),
    ] {
        let envelope = jwt_vc::encode(
            &signer,
            VcEnvelopeInputs {
                claim_type,
                issuer_did: "did:web:example.test".to_string(),
                verification_method_id: "did:web:example.test#key-2".to_string(),
                subject_uri: "https://gw.example/sub".to_string(),
                credential_subject: json!({"id": "https://gw.example/sub"}),
                provenance_context_url: "https://gw.example/contexts/provenance/v1.jsonld"
                    .to_string(),
                credential_schema_url: schema_url.to_string(),
                issued_at,
                valid_until,
            },
        )
        .expect("encode");
        let parts: Vec<&str> = envelope.compact_jws.split('.').collect();
        let payload = decode_part(parts[1]);
        assert_eq!(payload["type"][1], type_tag);
        assert_eq!(payload["credentialSchema"]["id"], schema_url);
    }
}
