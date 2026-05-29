// SPDX-License-Identifier: Apache-2.0
//! Relay regression coverage for the shared Registry Platform SD-JWT helpers.

use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use registry_relay::provenance::sdjwt::{
    validate_holder_proof, Disclosure, HolderConfirmation, HolderProofBindings, HolderProofPolicy,
    PrivateJwk, SdJwtIssuanceInput, SdJwtIssuer,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const ISSUER_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"did:web:relay.example#issuer"}"#;
const HOLDER_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"did:key:z6Mkholder#key-1"}"#;
const NOW: i64 = 1_700_000_000;
const SERVICE_ID: &str = "registry-relay";

#[tokio::test]
async fn sdjwt_jti_matches_credential_id() {
    let signed = issue_sdjwt(Vec::new()).await;

    assert_eq!(signed.jti, signed.credential_id);
    let payload = jwt_payload(&signed.jwt);
    assert_eq!(payload["jti"], signed.credential_id);
    assert_eq!(payload["id"], signed.credential_id);
}

#[tokio::test]
async fn sd_digests_are_sorted_by_digest() {
    let signed = issue_sdjwt(vec![
        Disclosure {
            name: "third".to_string(),
            value: json!(3),
        },
        Disclosure {
            name: "first".to_string(),
            value: json!(1),
        },
        Disclosure {
            name: "second".to_string(),
            value: json!(2),
        },
    ])
    .await;
    let payload = jwt_payload(&signed.jwt);
    let sd = payload["_sd"]
        .as_array()
        .expect("_sd array")
        .iter()
        .map(|value| value.as_str().expect("digest").to_string())
        .collect::<Vec<_>>();
    let mut expected = signed
        .jwt
        .split('~')
        .skip(1)
        .filter(|disclosure| !disclosure.is_empty())
        .map(|disclosure| URL_SAFE_NO_PAD.encode(Sha256::digest(disclosure.as_bytes())))
        .collect::<Vec<_>>();
    expected.sort_unstable();

    assert_eq!(sd, expected);
}

#[test]
fn holder_proof_requires_exp_greater_than_iat() {
    let holder = holder_key();
    let mut payload = proof_payload("proof-exp-eq-iat");
    payload["exp"] = json!(NOW);
    let proof = sign_holder_proof(&holder, payload);

    validate_holder_proof(
        &proof,
        &holder.public(),
        &bindings(&claim_set()),
        &policy(),
        NOW,
    )
    .expect_err("exp must be greater than iat");
}

#[test]
fn holder_proof_lifetime_must_not_exceed_300s() {
    let holder = holder_key();
    let mut payload = proof_payload("proof-over-lifetime");
    payload["exp"] = json!(NOW + 301);
    let proof = sign_holder_proof(&holder, payload);

    validate_holder_proof(
        &proof,
        &holder.public(),
        &bindings(&claim_set()),
        &policy(),
        NOW,
    )
    .expect_err("holder proof lifetime must be <= 300 seconds");
}

#[test]
fn holder_proof_audience_must_equal_service_id() {
    let holder = holder_key();
    let mut payload = proof_payload("proof-wrong-aud");
    payload["aud"] = json!("registry-notary");
    let proof = sign_holder_proof(&holder, payload);

    validate_holder_proof(
        &proof,
        &holder.public(),
        &bindings(&claim_set()),
        &policy(),
        NOW,
    )
    .expect_err("aud must equal relay service id");
}

#[test]
fn holder_proof_enforces_full_holder_proof_bindings() {
    let holder = holder_key();
    let claim_set = claim_set();
    let baseline = sign_holder_proof(&holder, proof_payload("proof-baseline"));
    validate_holder_proof(
        &baseline,
        &holder.public(),
        &bindings(&claim_set),
        &policy(),
        NOW,
    )
    .expect("baseline validates");

    let mut wrong_sub = bindings(&claim_set);
    wrong_sub.expected_sub = "did:key:z6Mkwrong";
    validate_holder_proof(&baseline, &holder.public(), &wrong_sub, &policy(), NOW)
        .expect_err("expected_sub binding must match");

    let mut wrong_eval = bindings(&claim_set);
    wrong_eval.evaluation_id = "eval-wrong";
    validate_holder_proof(&baseline, &holder.public(), &wrong_eval, &policy(), NOW)
        .expect_err("evaluation_id binding must match");

    let mut wrong_profile = bindings(&claim_set);
    wrong_profile.credential_profile = "profile-wrong";
    validate_holder_proof(&baseline, &holder.public(), &wrong_profile, &policy(), NOW)
        .expect_err("credential_profile binding must match");

    let wrong_disclosure_hash = b"wrong-disclosure-hash".to_vec();
    let mut wrong_disclosure = bindings(&claim_set);
    wrong_disclosure.disclosure_hash = &wrong_disclosure_hash;
    validate_holder_proof(
        &baseline,
        &holder.public(),
        &wrong_disclosure,
        &policy(),
        NOW,
    )
    .expect_err("disclosure hash binding must match");

    let wrong_claim_set = vec!["benefit_status".to_string()];
    let wrong_claims = bindings(&wrong_claim_set);
    validate_holder_proof(&baseline, &holder.public(), &wrong_claims, &policy(), NOW)
        .expect_err("claim_set binding must match");
}

async fn issue_sdjwt(
    disclosures: Vec<Disclosure>,
) -> registry_relay::provenance::sdjwt::SignedSdJwt {
    let issuer = SdJwtIssuer::from_jwk(PrivateJwk::parse(ISSUER_JWK).expect("issuer jwk"))
        .expect("issuer builds");
    let holder = holder_key();
    issuer
        .issue(SdJwtIssuanceInput {
            iss: "did:web:relay.example".to_string(),
            sub_ref: "https://relay.example/datasets/social_registry/individual/ind-1".to_string(),
            iat: NOW,
            exp: NOW + 600,
            vct: "https://relay.example/credentials/entity-record/v1".to_string(),
            credential_id: None,
            status: None,
            cnf: Some(HolderConfirmation {
                jwk: holder.public(),
                kid: Some("did:key:z6Mkholder#key-1".to_string()),
            }),
            disclosures,
        })
        .await
        .expect("sd-jwt issues")
}

fn holder_key() -> PrivateJwk {
    PrivateJwk::parse(HOLDER_JWK).expect("holder jwk")
}

fn policy() -> HolderProofPolicy {
    HolderProofPolicy {
        audience: SERVICE_ID.to_string(),
        max_lifetime: Duration::from_secs(300),
    }
}

fn claim_set() -> Vec<String> {
    vec!["eligibility".to_string(), "household_size".to_string()]
}

fn bindings<'a>(claim_set: &'a [String]) -> HolderProofBindings<'a> {
    HolderProofBindings {
        expected_sub: "did:key:z6Mkholder",
        evaluation_id: "eval-123",
        credential_profile: "entity-record-v1",
        disclosure_hash: b"redacted-disclosure-hash",
        claim_set,
    }
}

fn proof_payload(jti: &str) -> Value {
    json!({
        "sub": "did:key:z6Mkholder",
        "aud": SERVICE_ID,
        "iat": NOW,
        "exp": NOW + 300,
        "jti": jti,
        "evaluation_id": "eval-123",
        "credential_profile": "entity-record-v1",
        "disclosure": URL_SAFE_NO_PAD.encode(b"redacted-disclosure-hash"),
        "claims": ["eligibility", "household_size"],
    })
}

fn sign_holder_proof(holder: &PrivateJwk, payload: Value) -> String {
    let header = json!({"alg": "EdDSA", "typ": "kb+jwt", "kid": "did:key:z6Mkholder#key-1"});
    let header_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header JSON"));
    let payload_b64 = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("payload JSON"));
    let signing_input = format!("{header_b64}.{payload_b64}");
    let signature =
        registry_platform_crypto::sign(signing_input.as_bytes(), holder).expect("proof signs");
    format!("{}.{}", signing_input, URL_SAFE_NO_PAD.encode(signature))
}

fn jwt_payload(sd_jwt: &str) -> Value {
    let compact = sd_jwt.split('~').next().expect("compact jwt");
    let payload = compact.split('.').nth(1).expect("payload segment");
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(payload).expect("payload base64url"))
        .expect("payload JSON")
}
