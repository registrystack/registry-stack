// SPDX-License-Identifier: Apache-2.0

use super::support::*;
#[allow(unused_imports)]
use super::{
    admin::*, audit::*, credentials::*, federation::*, http_contracts::*, oid4vci::*, preauth::*,
};

#[tokio::test]
pub(super) async fn malformed_authorization_with_valid_api_key_is_candidate_neutral() {
    assert_ambiguous_primary_headers_are_candidate_neutral(
        axum::http::HeaderValue::from_bytes(b"\xff").expect("opaque header value is valid"),
        axum::http::HeaderValue::from_static("api-token"),
    )
    .await;
}

#[tokio::test]
pub(super) async fn valid_authorization_with_non_utf8_api_key_is_candidate_neutral() {
    assert_ambiguous_primary_headers_are_candidate_neutral(
        axum::http::HeaderValue::from_static("Bearer api-token"),
        axum::http::HeaderValue::from_bytes(b"\xff").expect("opaque header value is valid"),
    )
    .await;
}

async fn assert_ambiguous_primary_headers_are_candidate_neutral(
    authorization: axum::http::HeaderValue,
    api_key: axum::http::HeaderValue,
) {
    const API_KEY_MARKER: &str = "api-token";
    const PRINCIPAL_MARKER: &str = "caseworker";
    const BEARER_PRINCIPAL_MARKER: &str = "bearer-caseworker";
    const SCOPE_MARKER: &str = "farmer_registry:evidence_verification";

    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = notary_only_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    config.auth.bearer_tokens.push(EvidenceCredentialConfig {
        id: BEARER_PRINCIPAL_MARKER.to_string(),
        fingerprint: env_fingerprint_ref("TEST_EVIDENCE_API_KEY_HASH"),
        scopes: vec![SCOPE_MARKER.to_string()],
        authorization_details: None,
    });
    let app = standalone_router(config)
        .await
        .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let response = server
        .get("/v1/claims")
        .add_header("x-api-key", api_key)
        .add_header("authorization", authorization)
        .await;

    response.assert_status(StatusCode::BAD_REQUEST);
    let problem: Value = response.json();
    assert_eq!(problem["code"], json!("auth.multiple_credentials"));
    assert_eq!(
        problem["detail"],
        json!("provide exactly one authentication credential")
    );
    assert!(problem.get("data").is_none());
    let rendered = problem.to_string();
    for marker in [
        API_KEY_MARKER,
        PRINCIPAL_MARKER,
        BEARER_PRINCIPAL_MARKER,
        SCOPE_MARKER,
    ] {
        assert!(
            !rendered.contains(marker),
            "problem body leaked marker {marker}"
        );
    }

    let audit = std::fs::read_to_string(&audit_path).expect("audit was written");
    for marker in [
        API_KEY_MARKER,
        PRINCIPAL_MARKER,
        BEARER_PRINCIPAL_MARKER,
        SCOPE_MARKER,
    ] {
        assert!(!audit.contains(marker), "audit leaked marker {marker}");
    }
    let records = audit_envelopes(&audit_path)
        .into_iter()
        .map(|envelope| envelope.record)
        .filter(|record| record["path"] == json!("/v1/claims"))
        .collect::<Vec<_>>();
    assert_eq!(records.len(), 1, "one request must emit one audit record");
    let record = &records[0];
    assert_eq!(record["status"], json!(400));
    assert_eq!(record["decision"], json!("denied"));
    assert_eq!(record["error_code"], json!("auth.multiple_credentials"));
    assert!(record.get("principal_id").is_none());
    assert!(record.get("principal_id_hash").is_none());
    assert_eq!(record["scopes_used"], json!([]));
    assert!(record.get("relay_consultation_count").is_none());
    assert!(record.get("relay_consultation_ids").is_none());
}

#[tokio::test]
pub(super) async fn additive_api_key_and_oidc_authenticate_on_the_same_router() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );

    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = notary_only_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
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

    let app = standalone_router(config)
        .await
        .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let denied = server.get("/v1/claims").await;
    denied.assert_status(StatusCode::UNAUTHORIZED);

    let response = server
        .get("/v1/claims")
        .add_header("authorization", format!("Bearer {token}"))
        .await;
    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["data"][0]["id"], json!("farmer-under-4ha"));

    let api_key_response = server
        .get("/v1/claims")
        .add_header("x-api-key", "api-token")
        .await;
    api_key_response.assert_status_ok();

    let ambiguous = server
        .get("/v1/claims")
        .add_header("x-api-key", "api-token")
        .add_header("authorization", format!("Bearer {token}"))
        .await;
    ambiguous.assert_status(StatusCode::BAD_REQUEST);

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

    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = notary_only_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    config.server.admin_listener.mode = RegistryNotaryAdminListenerMode::SharedWithPublic;
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

    let app = standalone_router(config)
        .await
        .expect("standalone router builds");
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
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(subject_access_oidc_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    ))
    .await
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
#[cfg(feature = "registry-notary-cel")]
pub(super) async fn oidc_subject_access_evaluates_renders_and_audits_access_mode() {
    set_audit_secret();
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(subject_access_oidc_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    ))
    .await
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let token = idp.mint_token(json!({
        "sub": "citizen-subject",
        "aud": "registry-notary-citizen",
        "azp": "citizen-portal",
        "scope": "subject_access",
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
    assert_eq!(generated_by["policy_id"], json!("subject-access"));
    assert!(
        generated_by["policy_hash"]
            .as_str()
            .expect("subject-access provenance carries policy_hash")
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
        json!("subject_bound"),
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
    assert_eq!(evaluate_audit["scopes_used"], json!(["subject_access"]));

    let render_audit = records
        .iter()
        .find(|record| {
            record["path"] == json!("/v1/evaluations/{evaluation_id}/render")
                && record["decision"] == json!("render")
                && record["status"] == json!(200)
        })
        .expect("render audit record exists");
    assert_eq!(render_audit["access_mode"], json!("subject_bound"));
    assert_eq!(render_audit["scopes_used"], json!(["subject_access"]));
    assert_eq!(render_audit["purposes"], json!(["citizen_subject_access"]));
    assert!(render_audit["policy_hash"].is_string());
    assert!(render_audit.get("correlation_id").is_none());
    assert!(render_audit["correlation_id_hash"]
        .as_str()
        .expect("correlation id hash is string")
        .starts_with("hmac-sha256:"));

    idp.stop().await;
}
