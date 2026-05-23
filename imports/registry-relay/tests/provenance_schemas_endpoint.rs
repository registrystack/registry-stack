// SPDX-License-Identifier: Apache-2.0
//! Public `/schemas/{claim_type}/{version}` route coverage.
//!
//! Asserts that the three published schemas (verify-result,
//! aggregate-result, entity-record) return their pinned bytes verbatim,
//! that the response carries `application/schema+json` plus the long
//! cache directive `public, max-age=86400`, and that unknown
//! `(claim_type, version)` pairs surface 404 + the stable code
//! `provenance.unknown_resource`.

use std::env;
use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use axum_test::TestServer;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{SigningKey, SECRET_KEY_LENGTH};
use rand_core::OsRng;
use registry_relay::audit::{AuditSink, InMemorySink};
use registry_relay::auth::api_key::ApiKeyAuth;
use registry_relay::config::{Config, ProvenanceAlgorithm, SoftwareSignerConfig};
use registry_relay::provenance::resources;
use registry_relay::provenance::signers::software::SoftwareSigner;
use registry_relay::provenance::{
    IssuerMode, ProvenanceState, ResolvedClaimValidity, ResolvedProvenanceConfig, ResolvedUrls,
    Signer,
};
use registry_relay::server::build_app_with_provenance;
use serde_json::{json, Value};

fn load_example_config() -> Config {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config/example.yaml");
    let fingerprint = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    unsafe {
        env::set_var("STATS_OFFICE_API_KEY_HASH", fingerprint);
        env::set_var("PROGRAM_SYSTEM_API_KEY_HASH", fingerprint);
        env::set_var("VERIFICATION_SERVICE_API_KEY_HASH", fingerprint);
        env::set_var(
            "CLAIM_VERIFICATION_BINDING_KEY",
            "hex:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        );
    }
    registry_relay::config::load(&path).expect("example config loads")
}

fn export_jwk(env_name: &str) {
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
}

fn build_state() -> Arc<ProvenanceState> {
    let env_name = "SCHEMAS_ENDPOINT_TEST_JWK";
    export_jwk(env_name);
    let cfg = SoftwareSignerConfig {
        jwk_env: env_name.to_string(),
        signing_algorithm: ProvenanceAlgorithm::EdDSA,
    };
    let signer =
        SoftwareSigner::from_config(&cfg, "did:web:example#k".to_string()).expect("signer builds");
    let signer: Arc<dyn Signer> = Arc::new(signer);
    Arc::new(ProvenanceState::new(ResolvedProvenanceConfig {
        enabled: true,
        mode: IssuerMode::Gateway,
        issuer_did: "did:web:example".to_string(),
        verification_method_id: "did:web:example#k".to_string(),
        accepted_media_types: vec!["application/vc+jwt".to_string()],
        claim_validity: ResolvedClaimValidity {
            verify_result: Duration::from_secs(3600),
            aggregate_result: Duration::from_secs(3600),
            entity_record: Duration::from_secs(3600),
        },
        urls: ResolvedUrls {
            provenance_context_url: "https://gw.example/contexts/provenance/v1.jsonld".to_string(),
            schema_base_url: "https://gw.example/schemas".to_string(),
        },
        signer,
        retired_keys: Vec::new(),
    }))
}

fn build_app() -> axum::Router {
    let config = Arc::new(load_example_config());
    let auth = Arc::new(ApiKeyAuth::new(Vec::new()));
    let sink: Arc<dyn AuditSink> = Arc::new(InMemorySink::new());
    build_app_with_provenance(config, auth, sink, Some(build_state())).unwrap()
}

#[tokio::test]
async fn verify_result_schema_is_served_verbatim() {
    let server = TestServer::new(build_app());
    let resp = server.get("/schemas/verify-result/v1.json").await;
    resp.assert_status(StatusCode::OK);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/schema+json"
    );
    assert_eq!(
        resp.headers().get("cache-control").unwrap(),
        "public, max-age=86400"
    );
    assert_eq!(
        resp.headers().get("access-control-allow-origin").unwrap(),
        "*"
    );
    let body_bytes = resp.as_bytes();
    assert_eq!(body_bytes.as_ref(), resources::VERIFY_RESULT_V1);
    // Sanity: also a valid JSON document.
    let _json: Value = serde_json::from_slice(body_bytes.as_ref()).expect("valid JSON");
}

#[tokio::test]
async fn aggregate_result_schema_is_served_verbatim() {
    let server = TestServer::new(build_app());
    let resp = server.get("/schemas/aggregate-result/v1.json").await;
    resp.assert_status(StatusCode::OK);
    assert_eq!(resp.as_bytes().as_ref(), resources::AGGREGATE_RESULT_V1);
}

#[tokio::test]
async fn entity_record_schema_is_served_verbatim() {
    let server = TestServer::new(build_app());
    let resp = server.get("/schemas/entity-record/v1.json").await;
    resp.assert_status(StatusCode::OK);
    assert_eq!(resp.as_bytes().as_ref(), resources::ENTITY_RECORD_V1);
}

#[tokio::test]
async fn unknown_schema_returns_404_with_stable_code() {
    let server = TestServer::new(build_app());
    let resp = server.get("/schemas/nonexistent/v1.json").await;
    resp.assert_status(StatusCode::NOT_FOUND);
    let body: Value = resp.json();
    assert_eq!(body["code"], "provenance.unknown_resource");
}

#[tokio::test]
async fn unknown_version_for_known_type_returns_404() {
    let server = TestServer::new(build_app());
    let resp = server.get("/schemas/verify-result/v99.json").await;
    resp.assert_status(StatusCode::NOT_FOUND);
    let body: Value = resp.json();
    assert_eq!(body["code"], "provenance.unknown_resource");
}

#[tokio::test]
async fn schemas_route_is_not_mounted_without_provenance_state() {
    // Without provenance, the `/schemas/...` path is not part of the
    // public router. The data-plane catch-all (protected by the auth
    // layer) sees the request first, so the wire response is `401`
    // (no credential presented). Either 401 or 404 satisfies the
    // invariant: the unauthenticated public surface does not serve
    // this path.
    let config = Arc::new(load_example_config());
    let auth = Arc::new(ApiKeyAuth::new(Vec::new()));
    let sink: Arc<dyn AuditSink> = Arc::new(InMemorySink::new());
    let app = build_app_with_provenance(config, auth, sink, None).unwrap();
    let server = TestServer::new(app);
    let resp = server.get("/schemas/verify-result/v1.json").await;
    let status = resp.status_code();
    assert!(
        status == StatusCode::NOT_FOUND || status == StatusCode::UNAUTHORIZED,
        "without provenance state, /schemas must not be served on the public surface; got {status}"
    );
    if status == StatusCode::OK {
        panic!("/schemas must not be served when provenance state is absent");
    }
}
