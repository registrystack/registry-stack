// SPDX-License-Identifier: Apache-2.0
//! Public `/contexts/{vocab}/{version}` route coverage.
//!
//! Asserts that the in-tree JSON-LD contexts (the data_gate
//! `provenance/v1.jsonld` document and the vendored W3C VC 2.0 context
//! at `credentials/v2`) are served verbatim with `application/ld+json`
//! plus `public, max-age=86400`, and that unknown `(vocab, version)`
//! pairs return 404 with the `provenance.unknown_resource` code.

use std::env;
use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use axum_test::TestServer;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use data_gate::audit::{AuditSink, InMemorySink};
use data_gate::auth::api_key::ApiKeyAuth;
use data_gate::config::{Config, ProvenanceAlgorithm, SoftwareSignerConfig};
use data_gate::provenance::resources;
use data_gate::provenance::signers::software::SoftwareSigner;
use data_gate::provenance::{
    IssuerMode, ProvenanceState, ResolvedClaimValidity, ResolvedProvenanceConfig, ResolvedUrls,
    Signer,
};
use data_gate::server::build_app_with_provenance;
use ed25519_dalek::{SigningKey, SECRET_KEY_LENGTH};
use rand_core::OsRng;
use serde_json::{json, Value};

fn load_example_config() -> Config {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config/example.yaml");
    let phc = "$argon2id$v=19$m=19456,t=2,p=1$dGVzdHNhbHRkZ3RmaXh0dXJl$\
               EFMrkqK4dXMTH8DBlEvNN3wL/qmRvDjCwIAt7BqDpUw";
    unsafe {
        env::set_var("STATS_OFFICE_API_KEY_HASH", phc);
        env::set_var("PROGRAM_SYSTEM_API_KEY_HASH", phc);
        env::set_var("VERIFICATION_SERVICE_API_KEY_HASH", phc);
    }
    data_gate::config::load(&path).expect("example config loads")
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
    let env_name = "CONTEXTS_ENDPOINT_TEST_JWK";
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
    build_app_with_provenance(config, auth, sink, Some(build_state()))
}

#[tokio::test]
async fn provenance_v1_context_is_served_verbatim() {
    let server = TestServer::new(build_app());
    let resp = server.get("/contexts/provenance/v1.jsonld").await;
    resp.assert_status(StatusCode::OK);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/ld+json"
    );
    assert_eq!(
        resp.headers().get("cache-control").unwrap(),
        "public, max-age=86400"
    );
    assert_eq!(resp.as_bytes().as_ref(), resources::PROVENANCE_CONTEXT_V1);
    let _json: Value = serde_json::from_slice(resp.as_bytes().as_ref()).expect("valid JSON-LD");
}

#[tokio::test]
async fn vendored_vc_v2_context_is_served_verbatim() {
    let server = TestServer::new(build_app());
    let resp = server.get("/contexts/credentials/v2").await;
    resp.assert_status(StatusCode::OK);
    assert_eq!(
        resp.headers().get("content-type").unwrap(),
        "application/ld+json"
    );
    assert_eq!(resp.as_bytes().as_ref(), resources::VC_V2_CONTEXT);
}

#[tokio::test]
async fn unknown_vocab_returns_404_with_stable_code() {
    let server = TestServer::new(build_app());
    let resp = server.get("/contexts/nope/v1.jsonld").await;
    resp.assert_status(StatusCode::NOT_FOUND);
    let body: Value = resp.json();
    assert_eq!(body["code"], "provenance.unknown_resource");
}

#[tokio::test]
async fn contexts_route_is_not_mounted_without_provenance_state() {
    // Without provenance, the `/contexts/...` path is not part of the
    // public router. The data-plane catch-all (protected by the auth
    // layer) sees the request first, so the wire response is `401`
    // (no credential presented). The point of this test is that the
    // unauthenticated public branch *does not* serve the path; either
    // a 401 (auth rejected) or 404 (no route) satisfies that.
    let config = Arc::new(load_example_config());
    let auth = Arc::new(ApiKeyAuth::new(Vec::new()));
    let sink: Arc<dyn AuditSink> = Arc::new(InMemorySink::new());
    let app = build_app_with_provenance(config, auth, sink, None);
    let server = TestServer::new(app);
    let resp = server.get("/contexts/provenance/v1.jsonld").await;
    let status = resp.status_code();
    assert!(
        status == StatusCode::NOT_FOUND || status == StatusCode::UNAUTHORIZED,
        "without provenance state, /contexts must not be served on the public surface; got {status}"
    );
    if status == StatusCode::OK {
        panic!("/contexts must not be served when provenance state is absent");
    }
}
