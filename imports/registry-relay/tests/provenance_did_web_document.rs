// SPDX-License-Identifier: Apache-2.0
//! End-to-end coverage for the public `/.well-known/did.json` route.
//!
//! Gateway mode: the route returns a 200 with `application/did+json`,
//! a 24h-ish cache directive (the handler returns `max-age=300`), and
//! a DID Document whose `assertionMethod` references the active key's
//! verification-method id, and whose `verificationMethod[0]` carries
//! the active signer's public JWK without leaking the private `d`
//! component.
//!
//! Delegated mode: the same route returns 404 with the stable error
//! code `provenance.did_document_unavailable` because in delegated
//! mode the ministry hosts its own DID Document.

use std::env;
use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use axum_test::TestServer;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{SigningKey, VerifyingKey, SECRET_KEY_LENGTH};
use rand_core::OsRng;
use registry_relay::audit::{AuditSink, InMemorySink};
use registry_relay::auth::api_key::ApiKeyAuth;
use registry_relay::config::{Config, ProvenanceAlgorithm, SoftwareSignerConfig};
use registry_relay::provenance::signers::software::SoftwareSigner;
use registry_relay::provenance::{
    IssuerMode, ProvenanceState, ResolvedClaimValidity, ResolvedProvenanceConfig,
    ResolvedRetiredKey, ResolvedUrls, Signer,
};
use registry_relay::server::build_app_with_provenance;
use serde_json::{json, Value};
use time::OffsetDateTime;

const VM_ID: &str = "did:web:gw.example#key-1";
const ISSUER_DID: &str = "did:web:gw.example";

fn load_example_config() -> Config {
    let path = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("config/example.yaml");
    let fingerprint = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    unsafe {
        env::set_var("STATS_OFFICE_API_KEY_HASH", fingerprint);
        env::set_var("PROGRAM_SYSTEM_API_KEY_HASH", fingerprint);
        env::set_var("VERIFICATION_SERVICE_API_KEY_HASH", fingerprint);
    }
    registry_relay::config::load(&path).expect("example config loads")
}

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

fn build_software_signer(env_name: &str, vm_id: &str) -> (Arc<SoftwareSigner>, VerifyingKey) {
    let vk = export_jwk(env_name);
    let cfg = SoftwareSignerConfig {
        jwk_env: env_name.to_string(),
        signing_algorithm: ProvenanceAlgorithm::EdDSA,
    };
    let signer = SoftwareSigner::from_config(&cfg, vm_id.to_string()).expect("signer builds");
    (Arc::new(signer), vk)
}

fn build_state(mode: IssuerMode, signer: Arc<SoftwareSigner>) -> Arc<ProvenanceState> {
    build_state_with_retired(mode, signer, Vec::new())
}

fn build_state_with_retired(
    mode: IssuerMode,
    signer: Arc<SoftwareSigner>,
    retired_keys: Vec<ResolvedRetiredKey>,
) -> Arc<ProvenanceState> {
    build_state_with_retired_and_validity(
        mode,
        signer,
        retired_keys,
        ResolvedClaimValidity {
            verify_result: Duration::from_secs(3600),
            aggregate_result: Duration::from_secs(3600),
            entity_record: Duration::from_secs(3600),
        },
    )
}

fn build_state_with_retired_and_validity(
    mode: IssuerMode,
    signer: Arc<SoftwareSigner>,
    retired_keys: Vec<ResolvedRetiredKey>,
    claim_validity: ResolvedClaimValidity,
) -> Arc<ProvenanceState> {
    let resolved = ResolvedProvenanceConfig {
        enabled: true,
        mode,
        issuer_did: ISSUER_DID.to_string(),
        verification_method_id: VM_ID.to_string(),
        accepted_media_types: vec!["application/vc+jwt".to_string()],
        claim_validity,
        urls: ResolvedUrls {
            provenance_context_url: "https://gw.example/contexts/provenance/v1.jsonld".to_string(),
            schema_base_url: "https://gw.example/schemas".to_string(),
        },
        signer: signer as Arc<dyn Signer>,
        retired_keys,
    };
    Arc::new(ProvenanceState::new(resolved))
}

fn make_retired_key(
    env_suffix: &str,
    vm_id: &str,
    retired_after: OffsetDateTime,
) -> ResolvedRetiredKey {
    let sk = SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key();
    let public_jwk = json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "kid": vm_id,
        "x": URL_SAFE_NO_PAD.encode(vk.to_bytes()),
    });
    // Export full keypair so load_retired_keys can read the public JWK
    // from env (though these tests bypass that path and build directly).
    let _ = env_suffix; // not needed when building ResolvedRetiredKey directly
    ResolvedRetiredKey {
        verification_method_id: vm_id.to_string(),
        public_jwk,
        retired_after,
    }
}

fn build_app(state: Option<Arc<ProvenanceState>>) -> axum::Router {
    let config = Arc::new(load_example_config());
    let auth = Arc::new(ApiKeyAuth::new(Vec::new()));
    let sink: Arc<dyn AuditSink> = Arc::new(InMemorySink::new());
    build_app_with_provenance(config, auth, sink, state)
}

#[tokio::test]
async fn gateway_mode_serves_did_document() {
    let (signer, vk) = build_software_signer("DID_WEB_TEST_GATEWAY_JWK", VM_ID);
    let state = build_state(IssuerMode::Gateway, signer);
    let app = build_app(Some(state));
    let server = TestServer::new(app);

    let resp = server.get("/.well-known/did.json").await;
    resp.assert_status(StatusCode::OK);
    let content_type = resp
        .headers()
        .get("content-type")
        .expect("content-type header")
        .to_str()
        .unwrap()
        .to_string();
    assert!(
        content_type.starts_with("application/did+json"),
        "content-type was {content_type}"
    );

    let body: Value = resp.json();
    assert_eq!(body["id"], ISSUER_DID);

    // assertionMethod includes the active vm id.
    let assertion = body["assertionMethod"].as_array().expect("assertionMethod");
    assert_eq!(assertion.len(), 1);
    assert_eq!(assertion[0], VM_ID);

    // verificationMethod[0] carries the public JWK; the `d` private
    // component must not be present in any verificationMethod entry.
    let methods = body["verificationMethod"].as_array().expect("vm array");
    assert!(!methods.is_empty(), "verificationMethod must not be empty");
    let active = &methods[0];
    assert_eq!(active["id"], VM_ID);
    assert_eq!(active["controller"], ISSUER_DID);
    let pjwk = &active["publicKeyJwk"];
    assert_eq!(pjwk["kty"], "OKP");
    assert_eq!(pjwk["crv"], "Ed25519");
    let x_b64 = pjwk["x"].as_str().expect("publicKeyJwk.x");
    let x_bytes = URL_SAFE_NO_PAD.decode(x_b64).expect("x base64url");
    assert_eq!(
        x_bytes,
        vk.to_bytes(),
        "publicKeyJwk.x must match the signer's public Ed25519 bytes"
    );
    for entry in methods {
        assert!(
            entry["publicKeyJwk"].get("d").is_none(),
            "private d must never appear in a DID Document verificationMethod entry"
        );
    }
}

#[tokio::test]
async fn gateway_mode_surfaces_retired_keys_in_did_document() {
    // Regression: the DID handler must not silently drop retired keys
    // that the
    // operator declared in configuration. Until each retired key's
    // last-issued VC has expired, a consumer needs to be able to
    // resolve `did:web:<host>` and find the retired `kid` so they can
    // verify already-issued credentials.
    let (active_signer, active_vk) =
        build_software_signer("DID_WEB_TEST_GATEWAY_WITH_RETIRED_ACTIVE_JWK", VM_ID);

    // Build a retired key. Only the public JWK belongs in the DID
    // Document; `d` (private) must never leave the operator's secret
    // store.
    let retired_vm_id = "did:web:gw.example#key-0";
    let retired_sk = SigningKey::generate(&mut OsRng);
    let retired_vk = retired_sk.verifying_key();
    let retired_public_jwk = json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "alg": "EdDSA",
        "kid": retired_vm_id,
        "x": URL_SAFE_NO_PAD.encode(retired_vk.to_bytes()),
    });
    // Pin retired_after to 30 minutes ago so the key is still within
    // the 1-hour claim-validity window and must appear in the document.
    let fixed_now = time::OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("fixed now");
    let retired_after = fixed_now - time::Duration::minutes(30);
    let retired = vec![ResolvedRetiredKey {
        verification_method_id: retired_vm_id.to_string(),
        public_jwk: retired_public_jwk.clone(),
        retired_after,
    }];

    let fixed_now_fn: fn() -> OffsetDateTime =
        || time::OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("fixed now");
    let resolved = ResolvedProvenanceConfig {
        enabled: true,
        mode: IssuerMode::Gateway,
        issuer_did: ISSUER_DID.to_string(),
        verification_method_id: VM_ID.to_string(),
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
        signer: active_signer as Arc<dyn Signer>,
        retired_keys: retired,
    };
    let state = Arc::new(ProvenanceState::new_with_clock(resolved, fixed_now_fn));
    let app = build_app(Some(state));
    let server = TestServer::new(app);

    let resp = server.get("/.well-known/did.json").await;
    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();

    // assertionMethod must reference only the active key. Retired keys
    // verify old credentials but cannot sign new ones.
    let assertion = body["assertionMethod"].as_array().expect("assertionMethod");
    assert_eq!(assertion, &vec![Value::String(VM_ID.to_string())]);

    // verificationMethod[0] is active; verificationMethod[1..] are
    // retired keys in declaration order.
    let methods = body["verificationMethod"].as_array().expect("vm array");
    assert_eq!(
        methods.len(),
        2,
        "DID Document must surface the active key plus all retired keys"
    );
    assert_eq!(methods[0]["id"], VM_ID);
    let active_x = methods[0]["publicKeyJwk"]["x"].as_str().expect("active x");
    assert_eq!(
        URL_SAFE_NO_PAD.decode(active_x).unwrap(),
        active_vk.to_bytes(),
    );

    assert_eq!(methods[1]["id"], retired_vm_id);
    assert_eq!(methods[1]["controller"], ISSUER_DID);
    let retired_x = methods[1]["publicKeyJwk"]["x"].as_str().expect("retired x");
    assert_eq!(
        URL_SAFE_NO_PAD.decode(retired_x).unwrap(),
        retired_vk.to_bytes(),
    );

    // The retired key's private component must never leak.
    for entry in methods {
        assert!(
            entry["publicKeyJwk"].get("d").is_none(),
            "private d must never appear in any verificationMethod entry"
        );
    }
}

#[tokio::test]
async fn delegated_mode_returns_404_with_stable_code() {
    let (signer, _vk) = build_software_signer("DID_WEB_TEST_DELEGATED_JWK", VM_ID);
    let state = build_state(IssuerMode::Delegated, signer);
    let app = build_app(Some(state));
    let server = TestServer::new(app);

    let resp = server.get("/.well-known/did.json").await;
    resp.assert_status(StatusCode::NOT_FOUND);
    let body: Value = resp.json();
    assert_eq!(body["code"], "provenance.did_document_unavailable");
}

#[tokio::test]
async fn disabled_provenance_keeps_public_routes_invisible() {
    // B2: when `provenance.enabled` is `false`, the orchestrator state
    // exists (so internal wiring stays the same) but the public,
    // unauthenticated routes must not be mounted. A deployment that
    // loads a config with `enabled: false` should be indistinguishable
    // from one that omits the `provenance:` block entirely: the schemas,
    // contexts, and DID Document routes are
    // absent from the public surface.
    let (signer, _vk) = build_software_signer("DID_WEB_TEST_DISABLED_JWK", VM_ID);
    let resolved = ResolvedProvenanceConfig {
        enabled: false,
        mode: IssuerMode::Gateway,
        issuer_did: ISSUER_DID.to_string(),
        verification_method_id: VM_ID.to_string(),
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
        signer: signer as Arc<dyn Signer>,
        retired_keys: Vec::new(),
    };
    let state = Arc::new(ProvenanceState::new(resolved));
    let app = build_app(Some(state));
    let server = TestServer::new(app);

    for path in [
        "/.well-known/did.json",
        "/schemas/verify-result/v1.json",
        "/contexts/provenance/v1.jsonld",
    ] {
        let resp = server.get(path).await;
        let status = resp.status_code();
        assert!(
            status == StatusCode::NOT_FOUND || status == StatusCode::UNAUTHORIZED,
            "with provenance disabled, {path} must not be served on the public surface; got {status}"
        );
        assert_ne!(
            status,
            StatusCode::OK,
            "{path} must not be served while provenance.enabled = false"
        );
    }
}

#[tokio::test]
async fn route_is_not_mounted_when_no_provenance_state_configured() {
    // Without a `ProvenanceState`, the `/.well-known/did.json` route
    // is not mounted on the unauthenticated public surface. The
    // data-plane catch-all (protected by the auth layer) then sees
    // the request, so the wire response is `401`. Either 401 (auth
    // rejected the request before any handler ran) or 404 (no route)
    // satisfies the invariant: the public, unauthenticated branch
    // does not serve the DID document.
    let app = build_app(None);
    let server = TestServer::new(app);
    let resp = server.get("/.well-known/did.json").await;
    let status = resp.status_code();
    assert!(
        status == StatusCode::NOT_FOUND || status == StatusCode::UNAUTHORIZED,
        "without provenance state, /.well-known/did.json must not be served on the public surface; got {status}"
    );
    if status == StatusCode::OK {
        panic!("/.well-known/did.json must not be served when provenance state is absent");
    }
}

// Clock-injection helpers for retired-key expiry tests.
// `fixed_now` is a known epoch; all three tests are expressed relative to it.
//
// max_validity = max(24h, 24h, 24h) = 86400 s
// clock_skew_grace = 300 s
// cutoff = retired_after + 86400 + 300
// Key is present iff now <= cutoff, i.e. retired_after >= now - 86700

const FIXED_NOW_TS: i64 = 1_750_000_000;

fn fixed_now() -> OffsetDateTime {
    OffsetDateTime::from_unix_timestamp(FIXED_NOW_TS).expect("fixed now")
}

fn build_pinned_state_with_one_retired(
    signer: Arc<SoftwareSigner>,
    retired_key: ResolvedRetiredKey,
) -> Arc<ProvenanceState> {
    let resolved = ResolvedProvenanceConfig {
        enabled: true,
        mode: IssuerMode::Gateway,
        issuer_did: ISSUER_DID.to_string(),
        verification_method_id: VM_ID.to_string(),
        accepted_media_types: vec!["application/vc+jwt".to_string()],
        // max_validity = 24 h across all three fields
        claim_validity: ResolvedClaimValidity {
            verify_result: Duration::from_secs(86_400),
            aggregate_result: Duration::from_secs(86_400),
            entity_record: Duration::from_secs(86_400),
        },
        urls: ResolvedUrls {
            provenance_context_url: "https://gw.example/contexts/provenance/v1.jsonld".to_string(),
            schema_base_url: "https://gw.example/schemas".to_string(),
        },
        signer: signer as Arc<dyn Signer>,
        retired_keys: vec![retired_key],
    };
    Arc::new(ProvenanceState::new_with_clock(resolved, fixed_now))
}

#[tokio::test]
async fn retired_key_within_grace_window_appears_in_did_document() {
    // retired_after = now - 1h: well within max_validity (24h) + grace (5min).
    // The key must still appear in verificationMethod.
    let (signer, _) = build_software_signer(
        "DID_WEB_TEST_RETIRED_WITHIN_GRACE_JWK",
        "did:web:gw.example#key-retired-within",
    );
    let retired_vm_id = "did:web:gw.example#key-within";
    let retired_after = fixed_now() - time::Duration::hours(1);
    let retired_key = make_retired_key("unused", retired_vm_id, retired_after);

    let state = build_pinned_state_with_one_retired(signer, retired_key);
    let app = build_app(Some(state));
    let server = TestServer::new(app);

    let resp = server.get("/.well-known/did.json").await;
    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    let methods = body["verificationMethod"].as_array().expect("vm array");
    assert_eq!(
        methods.len(),
        2,
        "retired key within grace window must appear in verificationMethod"
    );
    let ids: Vec<&str> = methods.iter().map(|m| m["id"].as_str().unwrap()).collect();
    assert!(
        ids.contains(&retired_vm_id),
        "retired vm id must be present; got {ids:?}"
    );
}

#[tokio::test]
async fn retired_key_past_grace_window_drops_out() {
    // retired_after = now - 25h: past max_validity (24h) + grace (5min) = 24h5min.
    // The key must be absent from verificationMethod.
    let (signer, _) = build_software_signer(
        "DID_WEB_TEST_RETIRED_PAST_GRACE_JWK",
        "did:web:gw.example#key-retired-past",
    );
    let retired_vm_id = "did:web:gw.example#key-past";
    let retired_after = fixed_now() - time::Duration::hours(25);
    let retired_key = make_retired_key("unused", retired_vm_id, retired_after);

    let state = build_pinned_state_with_one_retired(signer, retired_key);
    let app = build_app(Some(state));
    let server = TestServer::new(app);

    let resp = server.get("/.well-known/did.json").await;
    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    let methods = body["verificationMethod"].as_array().expect("vm array");
    assert_eq!(
        methods.len(),
        1,
        "retired key past grace window must be dropped; verificationMethod should have only the active key"
    );
    assert_eq!(methods[0]["id"], VM_ID);
}

#[tokio::test]
async fn retired_key_at_exact_cutoff_is_present() {
    // retired_after = now - (24h + 5min) exactly.
    // cutoff = retired_after + 86400 + 300 = now exactly.
    // Condition: now <= cutoff, so now == cutoff means the key is still included.
    let (signer, _) = build_software_signer(
        "DID_WEB_TEST_RETIRED_EXACT_CUTOFF_JWK",
        "did:web:gw.example#key-retired-exact",
    );
    let retired_vm_id = "did:web:gw.example#key-exact";
    // 24h + 5min = 86400 + 300 = 86700 s
    let retired_after = fixed_now() - time::Duration::seconds(86_700);
    let retired_key = make_retired_key("unused", retired_vm_id, retired_after);

    let state = build_pinned_state_with_one_retired(signer, retired_key);
    let app = build_app(Some(state));
    let server = TestServer::new(app);

    let resp = server.get("/.well-known/did.json").await;
    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    let methods = body["verificationMethod"].as_array().expect("vm array");
    // now == cutoff => now <= cutoff is true => key is present
    assert_eq!(
        methods.len(),
        2,
        "retired key at exactly the cutoff must still appear (now <= cutoff)"
    );
    let ids: Vec<&str> = methods.iter().map(|m| m["id"].as_str().unwrap()).collect();
    assert!(
        ids.contains(&retired_vm_id),
        "retired vm id at exact cutoff must be present; got {ids:?}"
    );
}
