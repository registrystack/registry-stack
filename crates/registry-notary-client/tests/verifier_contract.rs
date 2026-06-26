// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "verifier")]

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use registry_notary_client::verifier;
use registry_notary_client::{
    HolderBindingPolicy, RegistryNotaryClient, VerificationError, VerifyOptions,
};
use registry_notary_core::SD_JWT_VC_JWT_TYP;
use registry_platform_crypto::{did_jwk_from_public_jwk, sign, PrivateJwk};
use registry_platform_sdjwt::{Disclosure, HolderConfirmation, SdJwtIssuanceInput, SdJwtIssuer};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;

const ISSUER: &str = "did:web:issuer.test";
const VCT: &str = "https://vct.example/test";
const NOW: i64 = 1_700_000_010;
const KB_AUD: &str = "https://verifier.example/callback";
const KB_NONCE: &str = "nonce-1700000010";
const ISSUER_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"did:web:issuer.test#key-1"}"#;
const ISSUER_P256_JWK: &str = r#"{"kty":"EC","crv":"P-256","d":"MInq88dvxx-e1-MEfmdes4I6Gt2QbsKoEmYyk2j0Oj4","x":"3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4","y":"GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU","alg":"ES256","kid":"did:web:issuer.test#p256-key-1"}"#;
const ROTATED_ISSUER_JWK: &str = r#"{"crv":"Ed25519","d":"f4QIxnAyRWzhuBOmNRgvBTE56mWePdsPL0mvCtl8Gys","x":"pv4e_hXHBLN27rcs6VDFV1ED0TiU8M3xy9vsuWFEsec","kty":"OKP","alg":"EdDSA","kid":"did:web:issuer.test#key-2"}"#;
const HOLDER_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"holder-key-1"}"#;

#[tokio::test]
async fn verify_sd_jwt_vc_accepts_valid_holder_bound_credential() {
    let holder = holder_did();
    let compact = issue_sd_jwt(ISSUER_JWK, ISSUER, NOW, NOW + 50, Some(&holder)).await;
    let verified = verifier::verify_sd_jwt_vc(
        &compact,
        &jwks(ISSUER_JWK),
        &options().holder_binding(HolderBindingPolicy::RequiredKid(holder.clone())),
    )
    .expect("credential verifies");

    assert_eq!(verified.issuer, ISSUER);
    assert_eq!(verified.vct, VCT);
    assert_eq!(verified.key_id, "did:web:issuer.test#key-1");
    assert_eq!(verified.algorithm, "EdDSA");
    assert_eq!(verified.disclosure_count, 1);
    assert_eq!(verified.holder_key_id.as_deref(), Some(holder.as_str()));
}

#[tokio::test]
async fn verify_sd_jwt_vc_accepts_credential_without_disclosures() {
    let compact = issue_plain_jwt_vc(ISSUER_JWK, ISSUER, NOW, NOW + 50);

    let verified = verifier::verify_sd_jwt_vc(&compact, &jwks(ISSUER_JWK), &options())
        .expect("credential without disclosures verifies");

    assert_eq!(verified.issuer, ISSUER);
    assert_eq!(verified.disclosure_count, 0);
}

#[tokio::test]
async fn verify_sd_jwt_vc_accepts_es256_credential() {
    let compact = issue_sd_jwt(ISSUER_P256_JWK, ISSUER, NOW, NOW + 50, None).await;

    let verified = verifier::verify_sd_jwt_vc(
        &compact,
        &jwks(ISSUER_P256_JWK),
        &options().accepted_algorithms(["ES256"]),
    )
    .expect("ES256 credential verifies");

    assert_eq!(verified.issuer, ISSUER);
    assert_eq!(verified.vct, VCT);
    assert_eq!(verified.key_id, "did:web:issuer.test#p256-key-1");
    assert_eq!(verified.algorithm, "ES256");
    assert_eq!(verified.disclosure_count, 1);
}

#[tokio::test]
async fn verify_sd_jwt_vc_accepts_selectively_disclosed_subset() {
    let compact = issue_sd_jwt_with_claims(
        ISSUER_JWK,
        ISSUER,
        NOW,
        NOW + 50,
        None,
        &["claim-a", "claim-b"],
    )
    .await;
    let presentation = keep_first_disclosure(&compact);

    let verified = verifier::verify_sd_jwt_vc(&presentation, &jwks(ISSUER_JWK), &options())
        .expect("selective disclosure verifies");

    assert_eq!(verified.disclosure_count, 1);
}

#[tokio::test]
async fn verify_sd_jwt_vc_rejects_duplicate_presented_disclosure() {
    let compact = issue_sd_jwt_with_claims(
        ISSUER_JWK,
        ISSUER,
        NOW,
        NOW + 50,
        None,
        &["claim-a", "claim-b"],
    )
    .await;
    let presentation = duplicate_first_disclosure(&compact);

    let error = verifier::verify_sd_jwt_vc(&presentation, &jwks(ISSUER_JWK), &options())
        .expect_err("duplicate disclosure is rejected");

    assert_code(error, "disclosure.digest_mismatch");
}

#[tokio::test]
async fn verify_sd_jwt_vc_separates_key_binding_jwt_from_disclosures() {
    let compact = issue_sd_jwt(ISSUER_JWK, ISSUER, NOW, NOW + 50, Some(&holder_did())).await;
    let presentation = format!("{compact}{}", signed_key_binding_jwt(&compact));

    let verified = verifier::verify_sd_jwt_vc(
        &presentation,
        &jwks(ISSUER_JWK),
        &options()
            .holder_binding(HolderBindingPolicy::Required)
            .key_binding_challenge(KB_AUD, KB_NONCE),
    )
    .expect("key binding jwt is not treated as a disclosure");

    assert_eq!(verified.disclosure_count, 1);
}

#[tokio::test]
async fn verify_sd_jwt_vc_rejects_key_binding_without_expected_challenge() {
    let compact = issue_sd_jwt(ISSUER_JWK, ISSUER, NOW, NOW + 50, Some(&holder_did())).await;
    let presentation = format!("{compact}{}", signed_key_binding_jwt(&compact));

    let error = verifier::verify_sd_jwt_vc(
        &presentation,
        &jwks(ISSUER_JWK),
        &options().holder_binding(HolderBindingPolicy::Required),
    )
    .expect_err("key binding challenge is required");

    assert_code(error, "holder_binding.challenge_required");
}

#[tokio::test]
async fn verify_sd_jwt_vc_rejects_missing_key_binding_for_expected_challenge() {
    let compact = issue_sd_jwt(ISSUER_JWK, ISSUER, NOW, NOW + 50, Some(&holder_did())).await;

    let error = verifier::verify_sd_jwt_vc(
        &compact,
        &jwks(ISSUER_JWK),
        &options()
            .holder_binding(HolderBindingPolicy::Required)
            .key_binding_challenge(KB_AUD, KB_NONCE),
    )
    .expect_err("missing key binding jwt is rejected for verifier challenge");

    assert_code(error, "holder_binding.challenge_required");
}

#[tokio::test]
async fn verify_sd_jwt_vc_accepts_optional_key_binding_without_challenge() {
    let compact = issue_sd_jwt(ISSUER_JWK, ISSUER, NOW, NOW + 50, Some(&holder_did())).await;
    let presentation = format!("{compact}{}", signed_key_binding_jwt(&compact));

    let verified = verifier::verify_sd_jwt_vc(&presentation, &jwks(ISSUER_JWK), &options())
        .expect("optional key binding does not require a verifier challenge");

    assert_eq!(
        verified.holder_key_id.as_deref(),
        Some(holder_did().as_str())
    );
}

#[tokio::test]
async fn verify_sd_jwt_vc_rejects_wrong_key_binding_audience() {
    let compact = issue_sd_jwt(ISSUER_JWK, ISSUER, NOW, NOW + 50, Some(&holder_did())).await;
    let presentation = format!("{compact}{}", signed_key_binding_jwt(&compact));

    let error = verifier::verify_sd_jwt_vc(
        &presentation,
        &jwks(ISSUER_JWK),
        &options()
            .holder_binding(HolderBindingPolicy::Required)
            .key_binding_challenge("https://other-verifier.example/callback", KB_NONCE),
    )
    .expect_err("key binding audience must match");

    assert_code(error, "holder_binding.proof_invalid");
}

#[tokio::test]
async fn verify_sd_jwt_vc_rejects_wrong_key_binding_nonce() {
    let compact = issue_sd_jwt(ISSUER_JWK, ISSUER, NOW, NOW + 50, Some(&holder_did())).await;
    let presentation = format!("{compact}{}", signed_key_binding_jwt(&compact));

    let error = verifier::verify_sd_jwt_vc(
        &presentation,
        &jwks(ISSUER_JWK),
        &options()
            .holder_binding(HolderBindingPolicy::Required)
            .key_binding_challenge(KB_AUD, "stale-nonce"),
    )
    .expect_err("key binding nonce must match");

    assert_code(error, "holder_binding.proof_invalid");
}

#[tokio::test]
async fn verify_sd_jwt_vc_rejects_wrong_key_binding_sd_hash() {
    let compact = issue_sd_jwt(ISSUER_JWK, ISSUER, NOW, NOW + 50, Some(&holder_did())).await;
    let presentation = format!(
        "{compact}{}",
        signed_key_binding_jwt_with_payload(json!({
            "iat": NOW,
            "exp": NOW + 30,
            "aud": KB_AUD,
            "nonce": KB_NONCE,
            "sd_hash": "wrong"
        }))
    );

    let error = verifier::verify_sd_jwt_vc(
        &presentation,
        &jwks(ISSUER_JWK),
        &options()
            .holder_binding(HolderBindingPolicy::Required)
            .key_binding_challenge(KB_AUD, KB_NONCE),
    )
    .expect_err("key binding sd_hash must match");

    assert_code(error, "holder_binding.proof_invalid");
}

#[tokio::test]
async fn verify_sd_jwt_vc_rejects_key_binding_sd_hash_without_trailing_separator() {
    let compact = issue_sd_jwt(ISSUER_JWK, ISSUER, NOW, NOW + 50, Some(&holder_did())).await;
    let presentation = format!(
        "{compact}{}",
        signed_key_binding_jwt_with_payload(json!({
            "iat": NOW,
            "exp": NOW + 30,
            "aud": KB_AUD,
            "nonce": KB_NONCE,
            "sd_hash": URL_SAFE_NO_PAD.encode(Sha256::digest(
                compact.strip_suffix('~').unwrap_or(&compact).as_bytes()
            )),
        }))
    );

    let error = verifier::verify_sd_jwt_vc(
        &presentation,
        &jwks(ISSUER_JWK),
        &options()
            .holder_binding(HolderBindingPolicy::Required)
            .key_binding_challenge(KB_AUD, KB_NONCE),
    )
    .expect_err("key binding sd_hash must cover the trailing separator");

    assert_code(error, "holder_binding.proof_invalid");
}

#[tokio::test]
async fn verify_sd_jwt_vc_rejects_expired_key_binding_jwt() {
    let compact = issue_sd_jwt(ISSUER_JWK, ISSUER, NOW, NOW + 50, Some(&holder_did())).await;
    let presentation = format!(
        "{compact}{}",
        signed_key_binding_jwt_with_payload(json!({
            "iat": NOW - 300,
            "exp": NOW - 200,
            "aud": KB_AUD,
            "nonce": KB_NONCE,
            "sd_hash": URL_SAFE_NO_PAD.encode(Sha256::digest(
                compact.as_bytes()
            )),
        }))
    );

    let error = verifier::verify_sd_jwt_vc(
        &presentation,
        &jwks(ISSUER_JWK),
        &options()
            .holder_binding(HolderBindingPolicy::Required)
            .key_binding_challenge(KB_AUD, KB_NONCE),
    )
    .expect_err("expired key binding jwt must be rejected");

    assert_code(error, "holder_binding.proof_invalid");
}

#[tokio::test]
async fn verify_sd_jwt_vc_rejects_bad_key_binding_jwt() {
    let compact = issue_sd_jwt(ISSUER_JWK, ISSUER, NOW, NOW + 50, Some(&holder_did())).await;
    let presentation = format!("{compact}{}", unsigned_compact_jws());

    let error = verifier::verify_sd_jwt_vc(
        &presentation,
        &jwks(ISSUER_JWK),
        &options()
            .holder_binding(HolderBindingPolicy::Required)
            .key_binding_challenge(KB_AUD, KB_NONCE),
    )
    .expect_err("bad key binding jwt is rejected");

    assert_code(error, "holder_binding.proof_invalid");
}

#[tokio::test]
async fn verify_sd_jwt_vc_rejects_bad_signature() {
    let compact = tamper_signature(&issue_sd_jwt(ISSUER_JWK, ISSUER, NOW, NOW + 50, None).await);
    let error = verifier::verify_sd_jwt_vc(&compact, &jwks(ISSUER_JWK), &options())
        .expect_err("bad signature is rejected");

    assert_code(error, "signature.invalid");
}

#[tokio::test]
async fn verify_sd_jwt_vc_rejects_unknown_kid() {
    let compact = rewrite_header(
        &issue_sd_jwt(ISSUER_JWK, ISSUER, NOW, NOW + 50, None).await,
        |header| header["kid"] = json!("did:web:issuer.test#missing"),
    );
    let error = verifier::verify_sd_jwt_vc(&compact, &jwks(ISSUER_JWK), &options())
        .expect_err("unknown kid is rejected");

    assert_code(error, "key.unknown");
}

#[tokio::test]
async fn verify_sd_jwt_vc_rejects_disallowed_algorithm() {
    let compact = rewrite_header(
        &issue_sd_jwt(ISSUER_JWK, ISSUER, NOW, NOW + 50, None).await,
        |header| header["alg"] = json!("RS256"),
    );
    let error = verifier::verify_sd_jwt_vc(&compact, &jwks(ISSUER_JWK), &options())
        .expect_err("disallowed alg is rejected");

    assert_code(error, "algorithm.disallowed");
}

#[tokio::test]
async fn verify_sd_jwt_vc_rejects_wrong_issuer() {
    let compact = issue_sd_jwt(ISSUER_JWK, ISSUER, NOW, NOW + 50, None).await;
    let error = verifier::verify_sd_jwt_vc(
        &compact,
        &jwks(ISSUER_JWK),
        &VerifyOptions::new("did:web:other.example").now(now()),
    )
    .expect_err("wrong issuer is rejected");

    assert_code(error, "claim.issuer_mismatch");
}

#[tokio::test]
async fn verify_sd_jwt_vc_rejects_expired_credential() {
    let compact = issue_sd_jwt(ISSUER_JWK, ISSUER, NOW - 300, NOW - 200, None).await;
    let error = verifier::verify_sd_jwt_vc(&compact, &jwks(ISSUER_JWK), &options())
        .expect_err("expired credential is rejected");

    assert_code(error, "claim.time_invalid");
}

#[tokio::test]
async fn verify_sd_jwt_vc_rejects_invalid_disclosure_digest() {
    let compact = tamper_disclosure(&issue_sd_jwt(ISSUER_JWK, ISSUER, NOW, NOW + 50, None).await);
    let error = verifier::verify_sd_jwt_vc(&compact, &jwks(ISSUER_JWK), &options())
        .expect_err("invalid disclosure digest is rejected");

    assert_code(error, "disclosure.digest_mismatch");
}

#[tokio::test]
async fn verify_sd_jwt_vc_rejects_missing_required_holder_binding() {
    let compact = issue_sd_jwt(ISSUER_JWK, ISSUER, NOW, NOW + 50, None).await;
    let error = verifier::verify_sd_jwt_vc(
        &compact,
        &jwks(ISSUER_JWK),
        &options().holder_binding(HolderBindingPolicy::Required),
    )
    .expect_err("missing holder binding is rejected");

    assert_code(error, "holder_binding.required");
}

#[tokio::test]
async fn verifier_errors_do_not_render_credential_fragments() {
    let compact = issue_sd_jwt(ISSUER_JWK, ISSUER, NOW, NOW + 50, None).await;
    let error = verifier::verify_sd_jwt_vc(
        &compact,
        &jwks(ISSUER_JWK),
        &VerifyOptions::new("did:web:other.example").now(now()),
    )
    .expect_err("wrong issuer is rejected");
    let rendered = format!("{error:?} {error}");

    assert!(rendered.contains("claim.issuer_mismatch"));
    assert!(!rendered.contains(&compact));
    for fragment in compact.split(['.', '~']) {
        if fragment.len() > 12 {
            assert!(
                !rendered.contains(fragment),
                "error rendered compact credential fragment"
            );
        }
    }
}

#[tokio::test]
async fn client_verifier_refreshes_once_on_unknown_kid() {
    let counter = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route(
            "/.well-known/evidence/jwks.json",
            get(rotating_jwks_handler),
        )
        .with_state(Arc::clone(&counter));
    let base = spawn(app).await;
    let client = RegistryNotaryClient::builder(base)
        .build()
        .expect("client builds");
    let compact = issue_sd_jwt(ROTATED_ISSUER_JWK, ISSUER, NOW, NOW + 50, None).await;

    let verified = client
        .verify_sd_jwt_vc(&compact, options())
        .await
        .expect("refresh finds rotated key");

    assert_eq!(verified.key_id, "did:web:issuer.test#key-2");
    assert_eq!(counter.load(Ordering::SeqCst), 2);
}

async fn issue_sd_jwt(
    private_jwk: &str,
    issuer_id: &str,
    iat: i64,
    exp: i64,
    holder_id: Option<&str>,
) -> String {
    issue_sd_jwt_with_claims(private_jwk, issuer_id, iat, exp, holder_id, &["claim-a"]).await
}

async fn issue_sd_jwt_with_claims(
    private_jwk: &str,
    issuer_id: &str,
    iat: i64,
    exp: i64,
    holder_id: Option<&str>,
    claim_names: &[&str],
) -> String {
    let sd_jwt_issuer =
        SdJwtIssuer::from_jwk(PrivateJwk::parse(private_jwk).expect("issuer jwk parses"))
            .expect("issuer builds");
    let holder_confirmation = holder_id.map(|kid| {
        let holder = PrivateJwk::parse(HOLDER_JWK).expect("holder jwk parses");
        HolderConfirmation {
            jwk: holder.public(),
            kid: Some(kid.to_string()),
        }
    });
    sd_jwt_issuer
        .issue(SdJwtIssuanceInput {
            iss: issuer_id.to_string(),
            sub_ref: holder_id.unwrap_or("subject-ref").to_string(),
            credential_id: Some("urn:ulid:01HG0000000000000000000000".to_string()),
            iat,
            exp,
            vct: VCT.to_string(),
            status: None,
            public_claims: BTreeMap::new(),
            cnf: holder_confirmation,
            disclosures: claim_names
                .iter()
                .map(|claim_name| Disclosure {
                    name: (*claim_name).to_string(),
                    value: json!({"satisfied": true}),
                })
                .collect(),
        })
        .await
        .expect("sd-jwt issues")
        .jwt
}

fn issue_plain_jwt_vc(private_jwk: &str, issuer_id: &str, iat: i64, exp: i64) -> String {
    let issuer = PrivateJwk::parse(private_jwk).expect("issuer jwk parses");
    let header = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "alg": "EdDSA",
            "kid": "did:web:issuer.test#key-1",
            "typ": SD_JWT_VC_JWT_TYP,
        }))
        .expect("header serializes"),
    );
    let payload = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "iss": issuer_id,
            "sub": "subject-ref",
            "jti": "urn:ulid:01HG0000000000000000000000",
            "iat": iat,
            "exp": exp,
            "vct": VCT,
        }))
        .expect("payload serializes"),
    );
    let signing_input = format!("{header}.{payload}");
    let signature = sign(signing_input.as_bytes(), &issuer).expect("issuer signs");
    format!("{}.{}", signing_input, URL_SAFE_NO_PAD.encode(signature))
}

fn options() -> VerifyOptions {
    VerifyOptions::new(ISSUER).expected_vct(VCT).now(now())
}

fn now() -> time::OffsetDateTime {
    time::OffsetDateTime::from_unix_timestamp(NOW).expect("test timestamp")
}

fn jwks(private_jwk: &str) -> Value {
    let public = PrivateJwk::parse(private_jwk).expect("jwk parses").public();
    json!({ "keys": [serde_json::to_value(public).expect("public jwk serializes")] })
}

fn holder_did() -> String {
    let holder = PrivateJwk::parse(HOLDER_JWK).expect("holder jwk parses");
    did_jwk_from_public_jwk(&holder.public()).expect("holder did encodes")
}

fn assert_code(error: VerificationError, code: &str) {
    assert_eq!(error.code(), code);
}

fn tamper_signature(compact: &str) -> String {
    let (jwt, suffix) = compact.split_once('~').expect("sd-jwt has disclosure");
    let mut parts = jwt.split('.').collect::<Vec<_>>();
    let mut signature = URL_SAFE_NO_PAD
        .decode(parts[2])
        .expect("signature base64 decodes");
    signature[0] ^= 0x01;
    let signature = URL_SAFE_NO_PAD.encode(signature);
    parts[2] = &signature;
    format!("{}~{suffix}", parts.join("."))
}

fn tamper_disclosure(compact: &str) -> String {
    let mut parts = compact.split('~').collect::<Vec<_>>();
    let mut disclosure = parts[1].to_string();
    let replacement = if disclosure.ends_with('A') { "B" } else { "A" };
    disclosure.pop();
    disclosure.push_str(replacement);
    parts[1] = &disclosure;
    parts.join("~")
}

fn keep_first_disclosure(compact: &str) -> String {
    let mut parts = compact.split('~');
    let jwt = parts.next().expect("issuer jwt");
    let first_disclosure = parts.next().expect("first disclosure");
    format!("{jwt}~{first_disclosure}~")
}

fn duplicate_first_disclosure(compact: &str) -> String {
    let mut parts = compact.split('~');
    let jwt = parts.next().expect("issuer jwt");
    let first_disclosure = parts.next().expect("first disclosure");
    format!("{jwt}~{first_disclosure}~{first_disclosure}~")
}

fn unsigned_compact_jws() -> String {
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","typ":"kb+jwt"}"#);
    let payload = URL_SAFE_NO_PAD.encode(br#"{"iat":1700000010}"#);
    format!("{header}.{payload}.signature")
}

fn signed_key_binding_jwt(sd_jwt: &str) -> String {
    signed_key_binding_jwt_with_payload(json!({
        "iat": NOW,
        "exp": NOW + 30,
        "aud": KB_AUD,
        "nonce": KB_NONCE,
        "sd_hash": URL_SAFE_NO_PAD.encode(Sha256::digest(sd_jwt.as_bytes())),
    }))
}

fn signed_key_binding_jwt_with_payload(payload: Value) -> String {
    let holder = PrivateJwk::parse(HOLDER_JWK).expect("holder jwk parses");
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"EdDSA","typ":"kb+jwt","kid":"holder-key-1"}"#);
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("payload serializes"));
    let signing_input = format!("{header}.{payload}");
    let signature = sign(signing_input.as_bytes(), &holder).expect("holder proof signs");
    format!("{}.{}", signing_input, URL_SAFE_NO_PAD.encode(signature))
}

fn rewrite_header(compact: &str, mutate: impl FnOnce(&mut Value)) -> String {
    let (jwt, suffix) = compact.split_once('~').expect("sd-jwt has disclosure");
    let mut parts = jwt.split('.').collect::<Vec<_>>();
    let mut header: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(parts[0])
            .expect("header base64 decodes"),
    )
    .expect("header json decodes");
    mutate(&mut header);
    let header_b64 =
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header serializes"));
    parts[0] = &header_b64;
    format!("{}~{suffix}", parts.join("."))
}

async fn rotating_jwks_handler(State(counter): State<Arc<AtomicUsize>>) -> Json<Value> {
    let call = counter.fetch_add(1, Ordering::SeqCst);
    if call == 0 {
        Json(jwks(ISSUER_JWK))
    } else {
        Json(jwks(ROTATED_ISSUER_JWK))
    }
}

async fn spawn(app: Router) -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind test server");
    let addr: SocketAddr = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        axum::serve(listener, app).await.expect("test server runs");
    });
    format!("http://{addr}")
}
