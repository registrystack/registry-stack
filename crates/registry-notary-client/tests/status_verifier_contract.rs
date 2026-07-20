// SPDX-License-Identifier: Apache-2.0

#![cfg(all(feature = "verifier", feature = "test-support"))]

use std::collections::BTreeMap;
use std::io::Write;
use std::sync::{Arc, Mutex};

use axum::body::Body;
use axum::extract::State;
use axum::http::{header, HeaderValue, Response, StatusCode};
use axum::routing::get;
use axum::{Json, Router};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use registry_notary_client::verifier;
use registry_notary_client::{
    RegistryNotaryClient, StatusListPolicy, VerificationError, VerifyOptions,
};
use registry_platform_crypto::PrivateJwk;
use registry_platform_sdjwt::{Disclosure, SdJwtIssuanceInput, SdJwtIssuer};
use serde_json::{json, Value};
use time::OffsetDateTime;
use tokio::net::TcpListener;

const ISSUER: &str = "did:web:issuer.test";
const VCT: &str = "https://vct.example/test";
const NOW: i64 = 1_700_000_010;
const ISSUER_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"did:web:issuer.test#key-1"}"#;

#[derive(Clone)]
struct HarnessState {
    jwks: Value,
    status: Arc<Mutex<StatusHttpResponse>>,
}

#[derive(Clone)]
struct StatusHttpResponse {
    status: StatusCode,
    content_type: Option<&'static str>,
    content_encoding: Option<&'static str>,
    location: Option<&'static str>,
    body: String,
}

impl Default for StatusHttpResponse {
    fn default() -> Self {
        Self {
            status: StatusCode::SERVICE_UNAVAILABLE,
            content_type: Some("application/statuslist+jwt"),
            content_encoding: None,
            location: None,
            body: String::new(),
        }
    }
}

struct StatusHarness {
    base_url: String,
    status_uri: String,
    state: HarnessState,
    client: RegistryNotaryClient,
}

impl StatusHarness {
    async fn start() -> Self {
        let state = HarnessState {
            jwks: jwks(),
            status: Arc::new(Mutex::new(StatusHttpResponse::default())),
        };
        let app = Router::new()
            .route("/.well-known/evidence/jwks.json", get(jwks_handler))
            .route("/status", get(status_handler))
            .with_state(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("test listener binds");
        let address = listener.local_addr().expect("test listener has address");
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("test server remains available");
        });
        let base_url = format!("http://{address}");
        let status_uri = format!("{base_url}/status");
        let client = RegistryNotaryClient::builder(&base_url)
            .build()
            .expect("test client builds");
        Self {
            base_url,
            status_uri,
            state,
            client,
        }
    }

    fn options(&self) -> VerifyOptions {
        VerifyOptions::new(ISSUER)
            .now(OffsetDateTime::from_unix_timestamp(NOW).expect("test time is valid"))
            .status_list(
                StatusListPolicy::loopback_for_testing(ISSUER, &self.base_url)
                    .expect("loopback test policy is valid"),
            )
    }

    async fn credential(&self, status_uri: &str, index: u64) -> String {
        issuer()
            .issue(SdJwtIssuanceInput {
                iss: ISSUER.to_string(),
                sub_ref: "subject-ref".to_string(),
                credential_id: Some("urn:ulid:01HG0000000000000000000000".to_string()),
                iat: NOW,
                exp: NOW + 600,
                vct: VCT.to_string(),
                status: Some(json!({
                    "status_list": {
                        "idx": index,
                        "uri": status_uri,
                    }
                })),
                public_claims: BTreeMap::new(),
                cnf: None,
                disclosures: vec![Disclosure {
                    name: "claim-a".to_string(),
                    value: json!({"satisfied": true}),
                }],
            })
            .await
            .expect("status-bearing credential issues")
            .jwt
    }

    async fn signed_status(&self, payload: Value) -> String {
        issuer()
            .sign_compact_jwt("statuslist+jwt", payload)
            .await
            .expect("status token signs")
    }

    fn valid_payload(&self, encoded_list: &str) -> Value {
        json!({
            "iss": ISSUER,
            "sub": self.status_uri,
            "aud": self.status_uri,
            "iat": NOW,
            "exp": NOW + 100,
            "ttl": 100,
            "status_list": {
                "bits": 8,
                "lst": encoded_list,
            }
        })
    }

    fn respond(&self, response: StatusHttpResponse) {
        *self.state.status.lock().expect("status response lock") = response;
    }

    async fn respond_with_token(&self, token: String) {
        self.respond(StatusHttpResponse {
            status: StatusCode::OK,
            body: token,
            ..StatusHttpResponse::default()
        });
    }
}

#[tokio::test]
async fn async_verifier_accepts_signed_valid_status() {
    let harness = StatusHarness::start().await;
    let credential = harness.credential(&harness.status_uri, 0).await;
    let token = harness
        .signed_status(harness.valid_payload("eJxjAAAAAQAB"))
        .await;
    harness.respond_with_token(token).await;

    let verified = harness
        .client
        .verify_sd_jwt_vc(&credential, harness.options())
        .await
        .expect("valid status-bearing credential verifies");

    assert_eq!(verified.issuer, ISSUER);
}

#[tokio::test]
async fn synchronous_verifier_never_skips_status() {
    let harness = StatusHarness::start().await;
    let credential = harness.credential(&harness.status_uri, 0).await;

    let missing_policy = verifier::verify_sd_jwt_vc(
        &credential,
        &jwks(),
        &VerifyOptions::new(ISSUER)
            .now(OffsetDateTime::from_unix_timestamp(NOW).expect("test time is valid")),
    )
    .expect_err("status cannot be skipped without policy");
    assert_code(missing_policy, "status.policy_required");

    let requires_fetch = verifier::verify_sd_jwt_vc(&credential, &jwks(), &harness.options())
        .expect_err("synchronous verification cannot skip the fetch");
    assert_code(requires_fetch, "status.fetch_required");
}

#[tokio::test]
async fn revoked_suspended_and_unknown_status_fail_closed() {
    for (encoded, expected_code) in [
        ("eJxjBAAAAgAC", "status.revoked"),
        ("eJxjAgAAAwAD", "status.suspended"),
        (&encoded_status_list(&[3]), "status.unknown"),
    ] {
        let harness = StatusHarness::start().await;
        let credential = harness.credential(&harness.status_uri, 0).await;
        let token = harness.signed_status(harness.valid_payload(encoded)).await;
        harness.respond_with_token(token).await;

        let error = harness
            .client
            .verify_sd_jwt_vc(&credential, harness.options())
            .await
            .expect_err("non-valid status is rejected");
        assert_code(error, expected_code);
    }
}

#[tokio::test]
async fn invalid_status_claims_signature_index_and_compression_fail_closed() {
    let harness = StatusHarness::start().await;
    let mut cases = Vec::new();

    let mut wrong_issuer = harness.valid_payload("eJxjAAAAAQAB");
    wrong_issuer["iss"] = json!("did:web:other.example");
    cases.push((wrong_issuer, 0, "status.claim.issuer_mismatch"));

    let mut wrong_uri = harness.valid_payload("eJxjAAAAAQAB");
    wrong_uri["sub"] = json!(format!("{}/other", harness.base_url));
    cases.push((wrong_uri, 0, "status.claim.uri_mismatch"));

    let mut wrong_audience = harness.valid_payload("eJxjAAAAAQAB");
    wrong_audience["aud"] = json!("https://verifier.example");
    cases.push((wrong_audience, 0, "status.claim.audience_mismatch"));

    let mut stale = harness.valid_payload("eJxjAAAAAQAB");
    stale["iat"] = json!(NOW - 400);
    stale["exp"] = json!(NOW - 300);
    cases.push((stale, 0, "status.claim.time_invalid"));

    let mut excessive_lifetime = harness.valid_payload("eJxjAAAAAQAB");
    excessive_lifetime["exp"] = json!(NOW + 301);
    excessive_lifetime["ttl"] = json!(301);
    cases.push((excessive_lifetime, 0, "status.claim.time_invalid"));

    cases.push((
        harness.valid_payload("eJxjAAAAAQAB"),
        1,
        "status.index.invalid",
    ));

    let decompression_bomb = encoded_status_list(&vec![0; 128 * 1024 + 1]);
    cases.push((
        harness.valid_payload(&decompression_bomb),
        0,
        "status.list.decompression_limit",
    ));

    for (payload, index, expected_code) in cases {
        let credential = harness.credential(&harness.status_uri, index).await;
        let token = harness.signed_status(payload).await;
        harness.respond_with_token(token).await;
        let error = harness
            .client
            .verify_sd_jwt_vc(&credential, harness.options())
            .await
            .expect_err("invalid status material is rejected");
        assert_code(error, expected_code);
    }

    let credential = harness.credential(&harness.status_uri, 0).await;
    let token = harness
        .signed_status(harness.valid_payload("eJxjAAAAAQAB"))
        .await;
    harness.respond_with_token(tamper_signature(&token)).await;
    let error = harness
        .client
        .verify_sd_jwt_vc(&credential, harness.options())
        .await
        .expect_err("invalid status signature is rejected");
    assert_code(error, "status.signature.invalid");

    let valid_token = harness
        .signed_status(harness.valid_payload("eJxjAAAAAQAB"))
        .await;
    for (token, expected_code) in [
        (
            rewrite_status_header(&valid_token, |header| {
                header["kid"] = json!("did:web:issuer.test#unknown")
            }),
            "status.key.unknown",
        ),
        (
            rewrite_status_header(&valid_token, |header| header["alg"] = json!("RS256")),
            "status.algorithm.disallowed",
        ),
        (
            rewrite_status_header(&valid_token, |header| {
                header["jku"] = json!("https://attacker.example/jwks.json")
            }),
            "status.header.untrusted_key_reference",
        ),
    ] {
        harness.respond_with_token(token).await;
        let error = harness
            .client
            .verify_sd_jwt_vc(&credential, harness.options())
            .await
            .expect_err("untrusted status signing metadata is rejected");
        assert_code(error, expected_code);
    }
}

#[tokio::test]
async fn status_transport_rejects_redirect_media_type_encoding_and_size() {
    let harness = StatusHarness::start().await;
    let credential = harness.credential(&harness.status_uri, 0).await;

    let cases = [
        (
            StatusHttpResponse {
                status: StatusCode::SERVICE_UNAVAILABLE,
                ..StatusHttpResponse::default()
            },
            "status.http_status_invalid",
        ),
        (
            StatusHttpResponse {
                status: StatusCode::FOUND,
                location: Some("https://other.example/status"),
                ..StatusHttpResponse::default()
            },
            "status.redirect_denied",
        ),
        (
            StatusHttpResponse {
                status: StatusCode::OK,
                content_type: Some("application/json"),
                body: "not-a-token".to_string(),
                ..StatusHttpResponse::default()
            },
            "status.media_type_invalid",
        ),
        (
            StatusHttpResponse {
                status: StatusCode::OK,
                content_encoding: Some("gzip"),
                body: "not-a-token".to_string(),
                ..StatusHttpResponse::default()
            },
            "status.content_encoding_denied",
        ),
        (
            StatusHttpResponse {
                status: StatusCode::OK,
                body: "not-a-compact-jwt".to_string(),
                ..StatusHttpResponse::default()
            },
            "status.token_malformed",
        ),
        (
            StatusHttpResponse {
                status: StatusCode::OK,
                body: "x".repeat(256 * 1024 + 1),
                ..StatusHttpResponse::default()
            },
            "status.response_too_large",
        ),
    ];

    for (response, expected_code) in cases {
        harness.respond(response);
        let error = harness
            .client
            .verify_sd_jwt_vc(&credential, harness.options())
            .await
            .expect_err("unsafe status response is rejected");
        assert_code(error, expected_code);
    }
}

#[tokio::test]
async fn status_origin_and_destination_must_be_explicit_and_safe() {
    let harness = StatusHarness::start().await;
    let untrusted_uri = "https://status.other.example/status";
    let credential = harness.credential(untrusted_uri, 0).await;
    let error = harness
        .client
        .verify_sd_jwt_vc(&credential, harness.options())
        .await
        .expect_err("unlisted status origin is rejected before fetch");
    assert_code(error, "status.origin_untrusted");

    let unsafe_uri = "https://127.0.0.1/status";
    let credential = harness.credential(unsafe_uri, 0).await;
    let options = VerifyOptions::new(ISSUER)
        .now(OffsetDateTime::from_unix_timestamp(NOW).expect("test time is valid"))
        .status_list(
            StatusListPolicy::new(ISSUER, "https://127.0.0.1")
                .expect("structurally valid HTTPS origin"),
        );
    let error = harness
        .client
        .verify_sd_jwt_vc(&credential, options)
        .await
        .expect_err("private destination is rejected");
    assert_code(error, "status.destination_unsafe");

    let closed_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("closed-port probe binds");
    let closed_address = closed_listener
        .local_addr()
        .expect("closed-port probe has address");
    drop(closed_listener);
    let unreachable_origin = format!("http://{closed_address}");
    let unreachable_uri = format!("{unreachable_origin}/status");
    let credential = harness.credential(&unreachable_uri, 0).await;
    let options = VerifyOptions::new(ISSUER)
        .now(OffsetDateTime::from_unix_timestamp(NOW).expect("test time is valid"))
        .status_list(
            StatusListPolicy::loopback_for_testing(ISSUER, unreachable_origin)
                .expect("loopback test policy is valid"),
        );
    let error = harness
        .client
        .verify_sd_jwt_vc(&credential, options)
        .await
        .expect_err("unreachable status endpoint is rejected");
    assert_code(error, "status.unreachable");
}

#[test]
fn status_policy_requires_exact_https_origins() {
    assert!(StatusListPolicy::new(ISSUER, "http://status.example").is_err());
    assert!(StatusListPolicy::new(ISSUER, "https://status.example/path").is_err());
    assert!(StatusListPolicy::new(ISSUER, "https://user@status.example").is_err());
    assert!(StatusListPolicy::new(ISSUER, "https://status.example")
        .expect("primary origin is accepted")
        .allow_origin("https://status-backup.example:8443")
        .is_ok());
}

fn issuer() -> SdJwtIssuer {
    SdJwtIssuer::from_jwk(PrivateJwk::parse(ISSUER_JWK).expect("issuer JWK parses"))
        .expect("issuer builds")
}

fn jwks() -> Value {
    let public = PrivateJwk::parse(ISSUER_JWK)
        .expect("issuer JWK parses")
        .public();
    json!({"keys": [serde_json::to_value(public).expect("public JWK serializes")]})
}

fn encoded_status_list(bytes: &[u8]) -> String {
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(bytes).expect("status list compresses");
    URL_SAFE_NO_PAD.encode(encoder.finish().expect("status compression finishes"))
}

fn rewrite_status_header(token: &str, mutate: impl FnOnce(&mut Value)) -> String {
    let mut parts = token.split('.');
    let encoded_header = parts.next().expect("status token has header");
    let payload = parts.next().expect("status token has payload");
    let signature = parts.next().expect("status token has signature");
    assert!(parts.next().is_none());
    let mut header: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(encoded_header)
            .expect("status header decodes"),
    )
    .expect("status header is JSON");
    mutate(&mut header);
    let header = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header serializes"));
    format!("{header}.{payload}.{signature}")
}

fn tamper_signature(token: &str) -> String {
    let mut parts = token.split('.');
    let header = parts.next().expect("status token has header");
    let payload = parts.next().expect("status token has payload");
    let encoded_signature = parts.next().expect("status token has signature");
    assert!(parts.next().is_none());
    let mut signature = URL_SAFE_NO_PAD
        .decode(encoded_signature)
        .expect("status signature decodes");
    signature[0] ^= 1;
    format!("{header}.{payload}.{}", URL_SAFE_NO_PAD.encode(signature))
}

fn assert_code(error: VerificationError, expected: &str) {
    assert_eq!(error.code(), expected, "unexpected verifier error: {error}");
}

async fn jwks_handler(State(state): State<HarnessState>) -> Json<Value> {
    Json(state.jwks)
}

async fn status_handler(State(state): State<HarnessState>) -> Response<Body> {
    let response = state.status.lock().expect("status response lock").clone();
    let mut builder = Response::builder().status(response.status);
    if let Some(content_type) = response.content_type {
        builder = builder.header(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    }
    if let Some(content_encoding) = response.content_encoding {
        builder = builder.header(
            header::CONTENT_ENCODING,
            HeaderValue::from_static(content_encoding),
        );
    }
    if let Some(location) = response.location {
        builder = builder.header(header::LOCATION, HeaderValue::from_static(location));
    }
    builder
        .body(Body::from(response.body))
        .expect("test response builds")
}
