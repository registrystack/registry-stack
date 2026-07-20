// SPDX-License-Identifier: Apache-2.0

use super::support::*;
#[allow(unused_imports)]
use super::{admin::*, audit::*, auth::*, credentials::*, federation::*, oid4vci::*, preauth::*};

#[tokio::test]
pub(super) async fn request_body_limit_returns_413_above_threshold() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(notary_only_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    ))
    .await
    .expect("standalone router builds");
    let server = TestServer::new(app);

    let response = server
        .post("/v1/evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("content-type", "application/json")
        .add_header(header::CONTENT_LENGTH, "1048577")
        .await;

    response.assert_status(StatusCode::PAYLOAD_TOO_LARGE);
    let content_type = response
        .headers()
        .get("content-type")
        .expect("content-type header")
        .to_str()
        .expect("content-type is valid");
    assert!(content_type.starts_with("application/problem+json"));
    let body: Value = response.json();
    assert_eq!(body["status"], json!(413));
    assert_eq!(
        body["type"],
        json!("https://id.registrystack.org/problems/registry-platform/request/body-too-large")
    );
    let body_text = serde_json::to_string(&body).expect("problem body serializes");
    assert!(
        !body_text.contains("api-token"),
        "oversized-body problem response must not echo credential material"
    );
    assert!(
        !body_text.contains("1048577"),
        "oversized-body problem response must not echo the supplied content length"
    );
}

#[tokio::test]
pub(super) async fn request_uri_limit_returns_414_problem_details() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(notary_only_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    ))
    .await
    .expect("standalone router builds");
    let server = TestServer::builder().mock_transport().build(app);
    let long_path = format!("/{}", "a".repeat(8 * 1024 + 1));

    let response = server
        .get(&long_path)
        .add_header("x-api-key", "api-token")
        .await;

    response.assert_status(StatusCode::URI_TOO_LONG);
    let content_type = response
        .headers()
        .get("content-type")
        .expect("content-type header")
        .to_str()
        .expect("content-type is valid");
    assert!(content_type.starts_with("application/problem+json"));
    let body: Value = response.json();
    assert_eq!(body["status"], json!(414));
    assert_eq!(
        body["type"],
        json!("https://id.registrystack.org/problems/registry-notary/request/uri-too-long")
    );
    assert_eq!(body["code"], json!("request.uri_too_long"));
    let body_text = serde_json::to_string(&body).expect("problem body serializes");
    assert!(
        !body_text.contains(&long_path),
        "overlong-URI problem response must not echo the submitted URI"
    );
}

#[tokio::test]
pub(super) async fn error_responses_match_rfc_9457_problem_details_shape() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(notary_only_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    ))
    .await
    .expect("standalone router builds");
    let server = TestServer::builder().mock_transport().build(app);

    let response = server
        .get("/v1/claims")
        .add_header("x-request-id", "req-auth-1")
        .await;

    response.assert_status(StatusCode::UNAUTHORIZED);
    let content_type = response
        .headers()
        .get("content-type")
        .expect("content-type header")
        .to_str()
        .expect("content-type is valid");
    assert!(content_type.starts_with("application/problem+json"));
    let body: Value = response.json();
    assert_server_owned_request_id(&response, &body, "req-auth-1");
    assert_eq!(body["status"], json!(401));
    assert_eq!(body["title"], json!("Missing credential"));
    assert_eq!(body["code"], json!("auth.missing_credential"));
    assert!(body["type"].as_str().is_some_and(
        |value| value.starts_with("https://id.registrystack.org/problems/registry-notary/")
    ));
    assert!(body["detail"].as_str().is_some());
}

#[tokio::test]
pub(super) async fn evaluation_json_rejections_and_unsupported_idempotency_are_problem_details() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(notary_only_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    ))
    .await
    .expect("standalone router builds");
    let server = TestServer::builder().mock_transport().build(app);

    let old_shape = server
        .post("/v1/evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("x-request-id", "req-problem-1")
        .add_header("content-type", "application/json")
        .bytes(Bytes::from_static(
            br#"{"subject":{"id":"person-1","id_type":"national_id"},"claims":["farmed-land-size"]}"#,
        ))
        .await;
    let old_shape_body: Value = old_shape.json();
    assert_server_owned_request_id(&old_shape, &old_shape_body, "req-problem-1");
    assert_eq!(old_shape_body["code"], json!("request.invalid"));

    let old_shape = server
        .post("/v1/evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("content-type", "application/json")
        .bytes(Bytes::from_static(
            br#"{"subject":{"id":"person-1","id_type":"national_id"},"claims":["farmed-land-size"]}"#,
        ))
        .await;
    assert_request_invalid_problem(old_shape);

    let malformed_json = server
        .post("/v1/evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("content-type", "application/json")
        .text("{")
        .await;
    assert_request_invalid_problem(malformed_json);

    let wrong_content_type = server
        .post("/v1/evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("content-type", "text/plain")
        .text("{}")
        .await;
    assert_request_invalid_problem(wrong_content_type);

    for route in [
        "/v1/evaluations",
        "/v1/evaluations/eval-1/render",
        "/v1/credentials",
    ] {
        let response = server
            .post(route)
            .add_header("x-api-key", "api-token")
            .add_header("idempotency-key", "unsupported-key")
            .add_header("content-type", "application/json")
            .text("{}")
            .await;
        assert_request_invalid_problem(response);
    }
}

pub(super) fn assert_server_owned_request_id(
    response: &axum_test::TestResponse,
    body: &Value,
    inbound_request_id: &str,
) {
    let header_request_id = response
        .headers()
        .get("x-request-id")
        .and_then(|value| value.to_str().ok())
        .expect("x-request-id response header is present");
    let body_request_id = body["request_id"]
        .as_str()
        .expect("ProblemDetails request_id is present");

    assert_eq!(header_request_id, body_request_id);
    assert_ne!(body_request_id, inbound_request_id);
    Ulid::from_string(body_request_id).expect("request_id is a server-minted ULID");
}

pub(super) fn assert_request_invalid_problem(response: axum_test::TestResponse) {
    response.assert_status(StatusCode::BAD_REQUEST);
    let content_type = response
        .headers()
        .get("content-type")
        .expect("content-type header")
        .to_str()
        .expect("content-type is valid");
    assert!(content_type.starts_with("application/problem+json"));
    let body: Value = response.json();
    assert_eq!(body["status"], json!(400));
    assert_eq!(body["code"], json!("request.invalid"));
    assert!(body["type"]
        .as_str()
        .is_some_and(|value| value.ends_with("/request/invalid")));
}

#[tokio::test]
pub(super) async fn cors_csp_corp_headers_present_and_corp_conditional() {
    set_audit_secret();
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
    config.server.cors.allowed_origins = vec!["https://client.example.test".to_string()];
    let app = standalone_router(config)
        .await
        .expect("standalone router builds");
    let server = TestServer::builder().mock_transport().build(app);

    let response = server
        .get("/healthz")
        .add_header("origin", "https://client.example.test")
        .await;

    response.assert_status_ok();
    assert_eq!(
        response
            .headers()
            .get("access-control-allow-origin")
            .and_then(|value| value.to_str().ok()),
        Some("https://client.example.test")
    );
    assert_eq!(
        response
            .headers()
            .get("content-security-policy")
            .and_then(|value| value.to_str().ok()),
        Some("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; frame-ancestors 'none'")
    );
    assert_eq!(
        response
            .headers()
            .get("x-content-type-options")
            .and_then(|value| value.to_str().ok()),
        Some("nosniff")
    );
    assert_eq!(
        response
            .headers()
            .get("referrer-policy")
            .and_then(|value| value.to_str().ok()),
        Some("no-referrer")
    );
    assert_eq!(
        response
            .headers()
            .get("x-frame-options")
            .and_then(|value| value.to_str().ok()),
        Some("DENY")
    );
    assert_eq!(
        response
            .headers()
            .get("permissions-policy")
            .and_then(|value| value.to_str().ok()),
        Some("camera=(), microphone=(), geolocation=(), payment=(), usb=(), browsing-topics=()")
    );
    assert_eq!(
        response
            .headers()
            .get("cross-origin-opener-policy")
            .and_then(|value| value.to_str().ok()),
        Some("same-origin")
    );
    assert_eq!(
        response
            .headers()
            .get("cross-origin-resource-policy")
            .and_then(|value| value.to_str().ok()),
        Some("cross-origin")
    );
}

#[tokio::test]
pub(super) async fn subject_access_cors_uses_wallet_origins_on_browser_paths() {
    set_audit_secret();
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = subject_access_oid4vci_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    config.server.cors.allowed_origins = vec!["https://ops.example.test".to_string()];
    let app = standalone_router(config)
        .await
        .expect("standalone router builds");
    let server = TestServer::builder().mock_transport().build(app);

    let wallet = server
        .get("/.well-known/evidence-service")
        .add_header("origin", "https://wallet.example.gov")
        .await;
    wallet.assert_status(StatusCode::UNAUTHORIZED);
    assert_eq!(
        wallet
            .headers()
            .get("access-control-allow-origin")
            .and_then(|value| value.to_str().ok()),
        Some("https://wallet.example.gov")
    );

    let type_metadata = server
        .get("/credentials/civil-status")
        .add_header("host", "127.0.0.1:4325")
        .add_header("x-forwarded-proto", "http")
        .add_header("origin", "https://wallet.example.gov")
        .await;
    type_metadata.assert_status_ok();
    assert_eq!(
        type_metadata
            .headers()
            .get("access-control-allow-origin")
            .and_then(|value| value.to_str().ok()),
        Some("https://wallet.example.gov")
    );

    let ops = server
        .get("/.well-known/evidence-service")
        .add_header("origin", "https://ops.example.test")
        .await;
    ops.assert_status(StatusCode::UNAUTHORIZED);
    assert!(ops.headers().get("access-control-allow-origin").is_none());

    let healthz = server
        .get("/healthz")
        .add_header("origin", "https://ops.example.test")
        .await;
    healthz.assert_status_ok();
    assert_eq!(
        healthz
            .headers()
            .get("access-control-allow-origin")
            .and_then(|value| value.to_str().ok()),
        Some("https://ops.example.test")
    );
}

#[tokio::test]
pub(super) async fn subject_access_preflight_uses_wallet_origin_allow_list() {
    set_audit_secret();
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = subject_access_oid4vci_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    config.server.cors.allowed_origins = vec!["https://ops.example.test".to_string()];
    let app = standalone_router(config)
        .await
        .expect("standalone router builds");
    let server = TestServer::builder().mock_transport().build(app);

    let wallet = server
        .method(Method::OPTIONS, "/v1/evaluations")
        .add_header("origin", "https://wallet.example.gov")
        .add_header("access-control-request-method", "POST")
        .add_header(
            "access-control-request-headers",
            "authorization, content-type",
        )
        .await;
    wallet.assert_status(StatusCode::NO_CONTENT);
    assert_eq!(
        wallet
            .headers()
            .get("access-control-allow-origin")
            .and_then(|value| value.to_str().ok()),
        Some("https://wallet.example.gov")
    );
    assert_eq!(
        wallet
            .headers()
            .get("access-control-allow-headers")
            .and_then(|value| value.to_str().ok()),
        Some("authorization, content-type")
    );

    let type_metadata = server
        .method(Method::OPTIONS, "/credentials/civil-status")
        .add_header("origin", "https://wallet.example.gov")
        .add_header("access-control-request-method", "GET")
        .await;
    type_metadata.assert_status(StatusCode::NO_CONTENT);
    assert_eq!(
        type_metadata
            .headers()
            .get("access-control-allow-origin")
            .and_then(|value| value.to_str().ok()),
        Some("https://wallet.example.gov")
    );
    assert!(
        type_metadata
            .headers()
            .get("access-control-allow-methods")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|methods| methods.split(',').any(|method| method.trim() == "GET")),
        "preflight response should allow GET"
    );

    let ops = server
        .method(Method::OPTIONS, "/v1/evaluations")
        .add_header("origin", "https://ops.example.test")
        .add_header("access-control-request-method", "POST")
        .await;
    ops.assert_status(StatusCode::NO_CONTENT);
    assert!(ops.headers().get("access-control-allow-origin").is_none());
}

#[tokio::test]
pub(super) async fn standalone_router_hides_admin_and_metrics_when_admin_listener_is_not_shared() {
    for mode in [
        RegistryNotaryAdminListenerMode::Dedicated,
        RegistryNotaryAdminListenerMode::Disabled,
    ] {
        set_audit_secret();
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
        add_admin_api_key(&mut config);
        config.server.admin_listener.mode = mode;
        config.server.admin_listener.bind = "127.0.0.1:19091".parse().expect("valid admin bind");

        let app = standalone_router(config)
            .await
            .expect("standalone router builds");
        let server = TestServer::builder().mock_transport().build(app);

        server.get("/healthz").await.assert_status_ok();
        server
            .post("/admin/v1/reload")
            .add_header("x-api-key", "admin-token")
            .await
            .assert_status(StatusCode::NOT_FOUND);
        server
            .get("/metrics")
            .add_header("x-api-key", "admin-token")
            .await
            .assert_status(StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
pub(super) async fn standalone_router_default_config_hides_admin_and_metrics() {
    set_audit_secret();
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
    add_admin_api_key(&mut config);

    let app = standalone_router(config)
        .await
        .expect("standalone router builds");
    let server = TestServer::builder().mock_transport().build(app);

    server.get("/healthz").await.assert_status_ok();
    server
        .post("/admin/v1/reload")
        .add_header("x-api-key", "admin-token")
        .await
        .assert_status(StatusCode::NOT_FOUND);
    server
        .get("/metrics")
        .add_header("x-api-key", "admin-token")
        .await
        .assert_status(StatusCode::NOT_FOUND);
}

#[tokio::test]
pub(super) async fn standalone_server_can_serve_openapi_without_auth_when_configured() {
    set_audit_secret();
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
    config.server.openapi_requires_auth = false;
    let app = standalone_router(config)
        .await
        .expect("standalone router builds");
    let server = TestServer::builder().mock_transport().build(app);

    let openapi = server.get("/openapi.json").await;
    openapi.assert_status_ok();
    let openapi_body: Value = openapi.json();
    assert_eq!(openapi_body["openapi"], json!("3.1.0"));
    assert!(openapi_body["paths"]["/v1/evaluations"].is_object());
}

#[tokio::test]
pub(super) async fn openapi_json_handler_denies_without_runtime_state_by_default() {
    let server = TestServer::new(registry_notary_server::api::public_router());

    server
        .get("/openapi.json")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
pub(super) async fn public_router_exposes_no_batch_credential_or_oid4vci_route() {
    let server = TestServer::new(registry_notary_server::api::public_router());

    for route in [
        "/v1/batch-credentials",
        "/v1/credentials/batch",
        "/oid4vci/batch-credential",
        "/oid4vci/batch-credentials",
    ] {
        server
            .post(route)
            .await
            .assert_status(StatusCode::NOT_FOUND);
    }
}

#[tokio::test]
pub(super) async fn standalone_server_serves_docs_shell_without_auth() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");

    let config = notary_only_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    let app = standalone_router(config)
        .await
        .expect("standalone router builds");
    let server = TestServer::builder().mock_transport().build(app);

    let docs = server.get("/docs").await;
    docs.assert_status_ok();
    let docs_body = docs.text();
    assert!(docs_body.contains("Registry Notary API"));
    assert!(docs_body.contains("/openapi.json"));
    assert!(docs_body.contains("/docs/scalar.js"));
    assert!(docs_body.contains("X-Api-Key"));

    let bundle = server.get("/docs/scalar.js").await;
    bundle.assert_status_ok();
    let content_type = bundle
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .expect("bundle content type");
    assert!(content_type.starts_with("application/javascript"));

    let denied_openapi = server.get("/openapi.json").await;
    denied_openapi.assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
pub(super) async fn request_uri_limit_414_carries_server_owned_request_id() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(notary_only_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    ))
    .await
    .expect("standalone router builds");
    let server = TestServer::builder().mock_transport().build(app);
    let long_path = format!("/{}", "a".repeat(8 * 1024 + 1));

    let response = server
        .get(&long_path)
        .add_header("x-request-id", "client-supplied-id")
        .await;

    response.assert_status(StatusCode::URI_TOO_LONG);
    let body: Value = response.json();
    assert_server_owned_request_id(&response, &body, "client-supplied-id");
}

#[tokio::test]
pub(super) async fn request_body_limit_413_carries_server_owned_request_id() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(notary_only_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    ))
    .await
    .expect("standalone router builds");
    let server = TestServer::new(app);

    let response = server
        .post("/v1/evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("content-type", "application/json")
        .add_header(header::CONTENT_LENGTH, "1048577")
        .add_header("x-request-id", "client-supplied-id")
        .await;

    response.assert_status(StatusCode::PAYLOAD_TOO_LARGE);
    let body: Value = response.json();
    assert_server_owned_request_id(&response, &body, "client-supplied-id");
}
