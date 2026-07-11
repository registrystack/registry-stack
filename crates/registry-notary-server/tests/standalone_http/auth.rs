// SPDX-License-Identifier: Apache-2.0

use super::support::*;
#[allow(unused_imports)]
use super::{
    admin::*, audit::*, credentials::*, federation::*, http_contracts::*, oid4vci::*, preauth::*,
    sources::*,
};

#[tokio::test]
pub(super) async fn oidc_mode_verifies_token_from_fixture_idp() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    config.auth.mode = EvidenceAuthMode::Oidc;
    config.auth.api_keys.clear();
    config.auth.bearer_tokens.clear();
    config.auth.oidc = Some(EvidenceOidcAuthConfig {
        issuer: idp.issuer(),
        jwks_url: idp.jwks_uri(),
        userinfo_endpoint: None,
        userinfo_issuers: Vec::new(),
        audiences: vec!["registry-notary".to_string()],
        allowed_clients: vec!["registry-client".to_string()],
        allowed_algorithms: vec!["EdDSA".to_string()],
        allowed_token_types: vec!["JWT".to_string()],
        scope_claim: "scope".to_string(),
        scope_separator: " ".to_string(),
        scope_map: BTreeMap::new(),
        principal_claim: "sub".to_string(),
        leeway: Duration::from_secs(60),
        allow_insecure_localhost: true,
    });
    let token = idp.mint_token(json!({
        "sub": "caseworker",
        "aud": "registry-notary",
        "azp": "registry-client",
        "scope": "farmer_registry:evidence_verification",
    }));

    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let denied = server.get("/v1/claims").await;
    denied.assert_status(StatusCode::UNAUTHORIZED);

    let response = server
        .get("/v1/claims")
        .add_header("authorization", format!("Bearer {token}"))
        .await;
    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["data"][0]["id"], json!("farmed-land-size"));

    let now = OffsetDateTime::now_utc().unix_timestamp();
    let id_token_typ = sign_ed25519_compact_jwt(
        fixtures::ED25519_PRIVATE_JWK,
        "id_token",
        "registry-platform-testing-ed25519-1",
        json!({
            "iss": idp.issuer(),
            "sub": "caseworker",
            "aud": "registry-notary",
            "azp": "registry-client",
            "scope": "farmer_registry:evidence_verification",
            "iat": now,
            "nbf": now,
            "exp": now + 300,
        }),
    );
    let wrong_typ = server
        .get("/v1/claims")
        .add_header("authorization", format!("Bearer {id_token_typ}"))
        .await;
    wrong_typ.assert_status(StatusCode::UNAUTHORIZED);

    let audit = std::fs::read_to_string(&audit_path).expect("audit was written");
    let envelopes = audit_envelopes(&audit_path);
    assert!(envelopes
        .iter()
        .any(|envelope| envelope.record.get("principal_id_hash").is_some()));
    assert!(envelopes
        .iter()
        .all(|envelope| envelope.record.get("principal_id").is_none()));
    let claims_audit = envelopes
        .iter()
        .map(|envelope| &envelope.record)
        .find(|record| record["path"] == json!("/v1/claims") && record["status"] == json!(200))
        .expect("claims audit record exists");
    assert_eq!(
        claims_audit["scopes_used"],
        json!(["farmer_registry:evidence_verification"])
    );
    assert!(!audit.contains(&token));

    idp.stop().await;
}

#[tokio::test]
pub(super) async fn oidc_metrics_scope_can_scrape_metrics_but_non_metrics_cannot() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    config.server.admin_listener.mode = RegistryNotaryAdminListenerMode::SharedWithPublic;
    config.auth.mode = EvidenceAuthMode::Oidc;
    config.auth.api_keys.clear();
    config.auth.bearer_tokens.clear();
    config.auth.oidc = Some(EvidenceOidcAuthConfig {
        issuer: idp.issuer(),
        jwks_url: idp.jwks_uri(),
        userinfo_endpoint: None,
        userinfo_issuers: Vec::new(),
        audiences: vec!["registry-notary".to_string()],
        allowed_clients: vec!["registry-client".to_string()],
        allowed_algorithms: vec!["EdDSA".to_string()],
        allowed_token_types: vec!["JWT".to_string()],
        scope_claim: "scope".to_string(),
        scope_separator: " ".to_string(),
        scope_map: [(
            "metrics_read".to_string(),
            vec!["registry_notary:metrics_read".to_string()],
        )]
        .into_iter()
        .collect(),
        principal_claim: "sub".to_string(),
        leeway: Duration::from_secs(60),
        allow_insecure_localhost: true,
    });
    let non_admin_token = idp.mint_token(json!({
        "sub": "caseworker",
        "aud": "registry-notary",
        "azp": "registry-client",
        "scope": "farmer_registry:evidence_verification",
    }));
    let metrics_token = idp.mint_token(json!({
        "sub": "metrics-reader",
        "aud": "registry-notary",
        "azp": "registry-client",
        "scope": "metrics_read",
    }));

    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let non_metrics = server
        .get("/metrics")
        .add_header("authorization", format!("Bearer {non_admin_token}"))
        .await;
    non_metrics.assert_status(StatusCode::FORBIDDEN);
    assert!(!non_metrics
        .text()
        .contains("registry_notary_http_requests_total"));

    let metrics = server
        .get("/metrics")
        .add_header("authorization", format!("Bearer {metrics_token}"))
        .await;
    metrics.assert_status_ok();
    assert!(metrics
        .text()
        .contains("registry_notary_http_requests_total"));

    idp.stop().await;
}

#[tokio::test]
pub(super) async fn jwks_is_public_and_contains_no_private_members() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(self_attestation_oidc_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let jwks = server.get("/.well-known/evidence/jwks.json").await;

    jwks.assert_status_ok();
    let jwks_body: Value = jwks.json();
    let keys = jwks_body["keys"].as_array().expect("JWKS keys");
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0]["kid"], json!("did:web:issuer.example#key-1"));
    assert!(keys[0].get("d").is_none());

    idp.stop().await;
}

#[tokio::test]
pub(super) async fn oidc_self_attestation_evaluates_renders_and_audits_access_mode() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let source_hits = Arc::new(AtomicUsize::new(0));
    let source_hits_for_route = Arc::clone(&source_hits);
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/people/entities/person/records",
            get(
                move |headers: HeaderMap, query: Query<BTreeMap<String, String>>| {
                    let source_hits = Arc::clone(&source_hits_for_route);
                    async move {
                        source_hits.fetch_add(1, Ordering::SeqCst);
                        self_attestation_registry_data_api(headers, query).await
                    }
                },
            ),
        ));
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(self_attestation_oidc_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let token = idp.mint_token(json!({
        "sub": "citizen-subject",
        "aud": "registry-notary-citizen",
        "azp": "citizen-portal",
        "scope": "self_attestation",
        "national_id": "person-1",
        "auth_time": now,
        "iat": now,
        "exp": now + 300,
        "nbf": now,
    }));
    let authorization = format!("Bearer {token}");

    let jwks = server.get("/.well-known/evidence/jwks.json").await;
    jwks.assert_status_ok();
    let jwks_body: Value = jwks.json();
    assert_eq!(jwks_body["keys"].as_array().expect("JWKS keys").len(), 1);
    assert_eq!(
        jwks_body["keys"][0]["kid"],
        json!("did:web:issuer.example#key-1")
    );
    assert!(jwks_body["keys"][0].get("d").is_none());

    let evaluate = server
        .post("/v1/evaluations")
        .add_header("authorization", authorization.clone())
        .add_header("x-request-id", "req-self-attest-1")
        .json(&json!({
            "claims": ["person-is-alive"],
            "disclosure": "value",
            "format": "application/vnd.registry-notary.claim-result+json"
        }))
        .await;
    evaluate.assert_status_ok();
    let evaluate_body: Value = evaluate.json();
    assert_eq!(evaluate_body["results"][0]["value"], json!(true));
    // Self-attestation flows produce results under the canonical evaluation
    // policy, so generated_by carries the policy triple.
    let generated_by = &evaluate_body["results"][0]["provenance"]["generated_by"];
    assert_eq!(generated_by["policy_id"], json!("self-attestation"));
    assert!(
        generated_by["policy_hash"]
            .as_str()
            .expect("self-attestation provenance carries policy_hash")
            .starts_with("sha256:"),
        "policy_hash must use the sha256:<hex> prefixed format"
    );
    let evaluation_id = evaluate_body["results"][0]["evaluation_id"]
        .as_str()
        .expect("evaluation id returned")
        .to_string();

    let render = server
        .post(&format!("/v1/evaluations/{evaluation_id}/render"))
        .add_header("authorization", authorization)
        .add_header("x-request-id", "req-self-attest-1")
        .json(&json!({
            "disclosure": "value",
            "format": "application/vnd.registry-notary.claim-result+json"
        }))
        .await;
    render.assert_status_ok();
    let render_body: Value = render.json();
    assert_eq!(render_body["results"][0]["value"], json!(true));

    let audit = std::fs::read_to_string(&audit_path).expect("audit was written");
    assert!(!audit.contains(&token));
    assert!(!audit.contains("person-1"));
    assert!(!audit.contains("citizen-subject"));
    assert!(!audit.contains("source-token"));
    let records = audit_envelopes(&audit_path)
        .into_iter()
        .map(|envelope| envelope.record)
        .collect::<Vec<_>>();
    let evaluate_audit = records
        .iter()
        .find(|record| {
            record["path"] == json!("/v1/evaluations")
                && record["decision"] == json!("evaluate")
                && record["status"] == json!(200)
        })
        .expect("evaluate audit record exists");
    assert_eq!(
        evaluate_audit["access_mode"],
        json!("self_attestation"),
        "{evaluate_audit}"
    );
    assert!(evaluate_audit["policy_hash"].is_string());
    assert!(evaluate_audit.get("correlation_id").is_none());
    assert!(evaluate_audit["correlation_id_hash"]
        .as_str()
        .expect("correlation id hash is string")
        .starts_with("hmac-sha256:"));
    assert!(evaluate_audit.get("principal_id").is_none());
    assert!(evaluate_audit.get("principal_id_hash").is_some());
    assert_eq!(evaluate_audit["scopes_used"], json!(["self_attestation"]));

    let render_audit = records
        .iter()
        .find(|record| {
            record["path"] == json!("/v1/evaluations/{evaluation_id}/render")
                && record["decision"] == json!("render")
                && record["status"] == json!(200)
        })
        .expect("render audit record exists");
    assert_eq!(render_audit["access_mode"], json!("self_attestation"));
    assert_eq!(render_audit["scopes_used"], json!(["self_attestation"]));
    assert_eq!(
        render_audit["purposes"],
        json!(["citizen_self_attestation"])
    );
    assert!(render_audit["policy_hash"].is_string());
    assert!(render_audit.get("correlation_id").is_none());
    assert!(render_audit["correlation_id_hash"]
        .as_str()
        .expect("correlation id hash is string")
        .starts_with("hmac-sha256:"));

    idp.stop().await;
}
