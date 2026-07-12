// SPDX-License-Identifier: Apache-2.0

use super::support::*;
#[allow(unused_imports)]
use super::{
    admin::*, audit::*, auth::*, credentials::*, federation::*, http_contracts::*, preauth::*,
    sources::*,
};

#[tokio::test]
pub(super) async fn oid4vci_metadata_offer_and_nonce_are_public() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let app = standalone_router(self_attestation_oid4vci_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let metadata = server.get("/.well-known/openid-credential-issuer").await;
    metadata.assert_status_ok();
    let metadata_body: Value = metadata.json();
    assert_eq!(
        metadata_body["credential_configurations_supported"]["person_is_alive_sd_jwt"]["display"]
            [0]["name"],
        json!("Person is alive")
    );
    let metadata_text = metadata_body.to_string();
    assert!(!metadata_text.contains("source_connections"));
    assert!(!metadata_text.contains("source-token"));

    let offer = server.get("/oid4vci/credential-offer").await;
    offer.assert_status_ok();
    let offer_body: Value = offer.json();
    assert_eq!(
        offer_body["credential_configuration_ids"][0],
        json!("person_is_alive_sd_jwt")
    );
    let filtered_offer = server
        .get("/oid4vci/credential-offer?credential_configuration_id=person_is_alive_sd_jwt")
        .await;
    filtered_offer.assert_status_ok();
    let filtered_offer_body: Value = filtered_offer.json();
    assert_eq!(
        filtered_offer_body["credential_configuration_ids"],
        json!(["person_is_alive_sd_jwt"])
    );
    let unknown_offer = server
        .get("/oid4vci/credential-offer?credential_configuration_id=unknown")
        .await;
    unknown_offer.assert_status(StatusCode::BAD_REQUEST);
    let unknown_offer_body: Value = unknown_offer.json();
    assert_eq!(unknown_offer_body["error"], json!("invalid_request"));

    let nonce = server.post("/oid4vci/nonce").json(&json!({})).await;
    nonce.assert_status_ok();
    let nonce_body: Value = nonce.json();
    assert!(nonce_body["c_nonce"]
        .as_str()
        .is_some_and(|value| !value.is_empty()));
    assert_eq!(nonce_body["c_nonce_expires_in"], json!(300));

    let bad_nonce = server
        .post("/oid4vci/nonce")
        .json(&json!({"subject": "person-2"}))
        .await;
    bad_nonce.assert_status(StatusCode::BAD_REQUEST);
    let bad_nonce_body: Value = bad_nonce.json();
    assert_eq!(bad_nonce_body["error"], json!("invalid_request"));

    idp.stop().await;
}

#[tokio::test]
pub(super) async fn oid4vci_nonce_is_rate_limited_before_reservation() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oid4vci_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    config
        .self_attestation
        .rate_limits
        .invalid_token_per_client_address_per_minute = 2;
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    server
        .post("/oid4vci/nonce")
        .add_header("x-forwarded-for", "203.0.113.10")
        .json(&json!({}))
        .await
        .assert_status_ok();
    server
        .post("/oid4vci/nonce")
        .add_header("x-forwarded-for", "203.0.113.11")
        .json(&json!({}))
        .await
        .assert_status_ok();

    let limited = server
        .post("/oid4vci/nonce")
        .add_header("x-forwarded-for", "203.0.113.12")
        .json(&json!({}))
        .await;
    limited.assert_status(StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        limited.json::<Value>()["error"],
        json!("temporarily_unavailable")
    );

    idp.stop().await;
}

#[tokio::test]
pub(super) async fn oid4vci_type_metadata_is_public_and_matches_configured_vct() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oid4vci_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    // Forwarded host/proto are honored only from trusted proxies; the
    // axum-test client connects over loopback, so trust the loopback peer.
    config.server.trusted_proxy_ips = vec![
        "127.0.0.1".parse().expect("ipv4 loopback parses"),
        "::1".parse().expect("ipv6 loopback parses"),
    ];
    let app = standalone_router(config).expect("standalone router builds");
    // Serve with connect-info so the forwarded-host trust gate can see the
    // loopback peer; a plain `Router` over http_transport injects no
    // `ConnectInfo`, which would make the trust gate reject every request.
    let server = TestServer::builder()
        .http_transport()
        .build(app.into_make_service_with_connect_info::<std::net::SocketAddr>());

    let response = server
        .get("/credentials/civil-status")
        .add_header("host", "internal-notary:8080")
        .add_header("x-forwarded-host", "127.0.0.1:4325")
        .add_header("x-forwarded-proto", "http")
        .await;
    response.assert_status_ok();
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    let body: Value = response.json();
    assert_eq!(
        body["vct"],
        json!("http://127.0.0.1:4325/credentials/civil-status")
    );
    assert_eq!(body["name"], json!("Person is alive"));
    assert_eq!(body["display"][0]["locale"], json!("en-US"));
    assert_eq!(body["display"][0]["name"], json!("Person is alive"));
    assert_eq!(body["claims"][0]["path"], json!(["person-is-alive"]));
    assert_eq!(body["claims"][0]["display"][0]["locale"], json!("en-US"));
    assert_eq!(
        body["claims"][0]["display"][0]["label"],
        json!("Person is alive")
    );
    assert_eq!(body["claims"][0]["sd"], json!("always"));
    assert_eq!(body["claims"][0]["mandatory"], json!(true));

    let query_response = server
        .get("/credentials/civil-status?cache_bust=1")
        .add_header("host", "internal-notary:8080")
        .add_header("x-forwarded-host", "127.0.0.1:4325")
        .add_header("x-forwarded-proto", "http")
        .await;
    query_response.assert_status_ok();
    let query_body: Value = query_response.json();
    assert_eq!(
        query_body["vct"],
        json!("http://127.0.0.1:4325/credentials/civil-status")
    );

    let head = server
        .method(Method::HEAD, "/credentials/civil-status")
        .add_header("host", "internal-notary:8080")
        .add_header("x-forwarded-host", "127.0.0.1:4325")
        .add_header("x-forwarded-proto", "http")
        .await;
    head.assert_status_ok();
    assert_eq!(
        head.headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );

    idp.stop().await;
}

#[tokio::test]
pub(super) async fn oid4vci_type_metadata_normalizes_forwarded_scheme_and_host_case() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oid4vci_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    let vct = "https://issuer.example.test/credentials/civil-status";
    config.oid4vci.credential_issuer = "https://issuer.example.test".to_string();
    config.oid4vci.credential_endpoint =
        "https://issuer.example.test/oid4vci/credential".to_string();
    config.oid4vci.offer_endpoint =
        "https://issuer.example.test/oid4vci/credential-offer".to_string();
    config.oid4vci.nonce_endpoint = Some("https://issuer.example.test/oid4vci/nonce".to_string());
    config
        .evidence
        .credential_profiles
        .get_mut("civil_status_sd_jwt")
        .expect("credential profile exists")
        .vct = vct.to_string();
    config
        .oid4vci
        .credential_configurations
        .get_mut("person_is_alive_sd_jwt")
        .expect("credential configuration exists")
        .vct = vct.to_string();
    // Forwarded host/proto are honored only from trusted proxies; the
    // axum-test client connects over loopback, so trust the loopback peer.
    config.server.trusted_proxy_ips = vec![
        "127.0.0.1".parse().expect("ipv4 loopback parses"),
        "::1".parse().expect("ipv6 loopback parses"),
    ];
    let app = standalone_router(config).expect("standalone router builds");
    // Serve with connect-info so the forwarded-host trust gate can see the
    // loopback peer; a plain `Router` over http_transport injects no
    // `ConnectInfo`, which would make the trust gate reject every request.
    let server = TestServer::builder()
        .http_transport()
        .build(app.into_make_service_with_connect_info::<std::net::SocketAddr>());

    let response = server
        .get("/credentials/civil-status")
        .add_header("host", "internal-notary:8080")
        .add_header("x-forwarded-host", "ISSUER.EXAMPLE.TEST")
        .add_header("x-forwarded-proto", "HTTPS")
        .await;
    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["vct"], json!(vct));

    idp.stop().await;
}

#[tokio::test]
pub(super) async fn oid4vci_type_metadata_supports_nested_paths_and_public_404s() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oid4vci_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    let nested_vct = "http://127.0.0.1:4325/credentials/dhis2/health-status/v1";
    config
        .evidence
        .credential_profiles
        .get_mut("civil_status_sd_jwt")
        .expect("credential profile exists")
        .vct = nested_vct.to_string();
    config
        .oid4vci
        .credential_configurations
        .get_mut("person_is_alive_sd_jwt")
        .expect("credential configuration exists")
        .vct = nested_vct.to_string();
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let nested = server
        .get("/credentials/dhis2/health-status/v1")
        .add_header("host", "127.0.0.1:4325")
        .add_header("x-forwarded-proto", "http")
        .await;
    nested.assert_status_ok();
    let body: Value = nested.json();
    assert_eq!(body["vct"], json!(nested_vct));

    let unknown = server
        .get("/credentials/dhis2/unknown/v1")
        .add_header("host", "127.0.0.1:4325")
        .add_header("x-forwarded-proto", "http")
        .await;
    unknown.assert_status(StatusCode::NOT_FOUND);

    idp.stop().await;
}

#[tokio::test]
pub(super) async fn oid4vci_type_metadata_supports_path_prefixed_issuer_behind_stripping_proxy() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oid4vci_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    let prefixed_vct = "http://127.0.0.1:4325/notary/credentials/civil-status";
    config.oid4vci.credential_issuer = "http://127.0.0.1:4325/notary".to_string();
    config.oid4vci.credential_endpoint =
        "http://127.0.0.1:4325/notary/oid4vci/credential".to_string();
    config.oid4vci.offer_endpoint =
        "http://127.0.0.1:4325/notary/oid4vci/credential-offer".to_string();
    config.oid4vci.nonce_endpoint = Some("http://127.0.0.1:4325/notary/oid4vci/nonce".to_string());
    config
        .evidence
        .credential_profiles
        .get_mut("civil_status_sd_jwt")
        .expect("credential profile exists")
        .vct = prefixed_vct.to_string();
    config
        .oid4vci
        .credential_configurations
        .get_mut("person_is_alive_sd_jwt")
        .expect("credential configuration exists")
        .vct = prefixed_vct.to_string();
    // Forwarded host/proto are honored only from trusted proxies; the
    // axum-test client connects over loopback, so trust the loopback peer.
    config.server.trusted_proxy_ips = vec![
        "127.0.0.1".parse().expect("ipv4 loopback parses"),
        "::1".parse().expect("ipv6 loopback parses"),
    ];
    let app = standalone_router(config).expect("standalone router builds");
    // Serve with connect-info so the forwarded-host trust gate can see the
    // loopback peer; a plain `Router` over http_transport injects no
    // `ConnectInfo`, which would make the trust gate reject every request.
    let server = TestServer::builder()
        .http_transport()
        .build(app.into_make_service_with_connect_info::<std::net::SocketAddr>());

    let response = server
        .get("/credentials/civil-status")
        .add_header("host", "internal-notary:8080")
        .add_header("x-forwarded-host", "127.0.0.1:4325")
        .add_header("x-forwarded-proto", "http")
        .await;
    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["vct"], json!(prefixed_vct));

    idp.stop().await;
}

#[tokio::test]
pub(super) async fn oid4vci_type_metadata_is_not_served_when_oid4vci_is_disabled() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oid4vci_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    config.oid4vci.enabled = false;
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    server
        .get("/credentials/civil-status")
        .add_header("host", "127.0.0.1:4325")
        .add_header("x-forwarded-proto", "http")
        .await
        .assert_status(StatusCode::NOT_FOUND);

    idp.stop().await;
}

#[tokio::test]
pub(super) async fn oid4vci_type_metadata_well_known_is_public_and_matches_configured_vct() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oid4vci_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    // Forwarded host/proto are honored only from trusted proxies; the
    // axum-test client connects over loopback, so trust the loopback peer.
    config.server.trusted_proxy_ips = vec![
        "127.0.0.1".parse().expect("ipv4 loopback parses"),
        "::1".parse().expect("ipv6 loopback parses"),
    ];
    let app = standalone_router(config).expect("standalone router builds");
    // Serve with connect-info so the forwarded-host trust gate can see the
    // loopback peer; a plain `Router` over http_transport injects no
    // `ConnectInfo`, which would make the trust gate reject every request.
    let server = TestServer::builder()
        .http_transport()
        .build(app.into_make_service_with_connect_info::<std::net::SocketAddr>());

    let response = server
        .get("/.well-known/vct/credentials/civil-status")
        .add_header("host", "internal-notary:8080")
        .add_header("x-forwarded-host", "127.0.0.1:4325")
        .add_header("x-forwarded-proto", "http")
        .await;
    response.assert_status_ok();
    assert_eq!(
        response
            .headers()
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    let body: Value = response.json();
    assert_eq!(
        body["vct"],
        json!("http://127.0.0.1:4325/credentials/civil-status")
    );
    assert_eq!(body["name"], json!("Person is alive"));
    assert_eq!(body["display"][0]["locale"], json!("en-US"));
    assert_eq!(body["display"][0]["name"], json!("Person is alive"));
    assert_eq!(body["claims"][0]["path"], json!(["person-is-alive"]));
    assert_eq!(body["claims"][0]["display"][0]["locale"], json!("en-US"));
    assert_eq!(
        body["claims"][0]["display"][0]["label"],
        json!("Person is alive")
    );
    assert_eq!(body["claims"][0]["sd"], json!("always"));
    assert_eq!(body["claims"][0]["mandatory"], json!(true));

    idp.stop().await;
}

#[tokio::test]
pub(super) async fn oid4vci_type_metadata_well_known_supports_nested_paths_and_public_404s() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oid4vci_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    let nested_vct = "http://127.0.0.1:4325/credentials/dhis2/health-status/v1";
    config
        .evidence
        .credential_profiles
        .get_mut("civil_status_sd_jwt")
        .expect("credential profile exists")
        .vct = nested_vct.to_string();
    config
        .oid4vci
        .credential_configurations
        .get_mut("person_is_alive_sd_jwt")
        .expect("credential configuration exists")
        .vct = nested_vct.to_string();
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let nested = server
        .get("/.well-known/vct/credentials/dhis2/health-status/v1")
        .add_header("host", "127.0.0.1:4325")
        .add_header("x-forwarded-proto", "http")
        .await;
    nested.assert_status_ok();
    let body: Value = nested.json();
    assert_eq!(body["vct"], json!(nested_vct));

    let unknown = server
        .get("/.well-known/vct/credentials/dhis2/unknown/v1")
        .add_header("host", "127.0.0.1:4325")
        .add_header("x-forwarded-proto", "http")
        .await;
    unknown.assert_status(StatusCode::NOT_FOUND);

    idp.stop().await;
}

#[tokio::test]
pub(super) async fn oid4vci_type_metadata_well_known_is_not_served_when_oid4vci_is_disabled() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oid4vci_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    config.oid4vci.enabled = false;
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    server
        .get("/.well-known/vct/credentials/civil-status")
        .add_header("host", "127.0.0.1:4325")
        .add_header("x-forwarded-proto", "http")
        .await
        .assert_status(StatusCode::NOT_FOUND);

    idp.stop().await;
}

#[tokio::test]
pub(super) async fn oid4vci_type_metadata_well_known_keeps_protected_routes_authenticated() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oid4vci_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    enable_credential_status(&mut config);
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    server
        .get("/.well-known/vct/credentials/civil-status")
        .add_header("host", "127.0.0.1:4325")
        .add_header("x-forwarded-proto", "http")
        .await
        .assert_status_ok();
    server
        .post("/v1/credentials")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    server
        .post("/admin/v1/credentials/urn:ulid:01HX0000000000000000000000/status")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);

    idp.stop().await;
}

#[tokio::test]
pub(super) async fn oid4vci_type_metadata_well_known_serves_wallet_cors() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oid4vci_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    config.server.cors.allowed_origins = vec!["https://ops.example.test".to_string()];
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let type_metadata = server
        .get("/.well-known/vct/credentials/civil-status")
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

    let preflight = server
        .method(Method::OPTIONS, "/.well-known/vct/credentials/civil-status")
        .add_header("origin", "https://wallet.example.gov")
        .add_header("access-control-request-method", "GET")
        .await;
    preflight.assert_status(StatusCode::NO_CONTENT);
    assert_eq!(
        preflight
            .headers()
            .get("access-control-allow-origin")
            .and_then(|value| value.to_str().ok()),
        Some("https://wallet.example.gov")
    );
    assert!(
        preflight
            .headers()
            .get("access-control-allow-methods")
            .and_then(|value| value.to_str().ok())
            .is_some_and(|methods| methods.split(',').any(|method| method.trim() == "GET")),
        "preflight response should allow GET"
    );

    idp.stop().await;
}

#[tokio::test]
pub(super) async fn public_probe_routes_remain_public_except_metrics() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oid4vci_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    enable_credential_status(&mut config);
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    server.get("/healthz").await.assert_status_ok();
    let ready = server.get("/ready").await;
    ready.assert_status(StatusCode::SERVICE_UNAVAILABLE);
    let ready_body: Value = ready.json();
    assert_eq!(ready_body["status"], json!(503));
    assert_eq!(ready_body["code"], json!("readiness.not_ready"));
    assert_eq!(ready_body["readiness_status"], json!("degraded"));
    assert_eq!(ready_body["checks"]["degraded"], json!(1));
    server
        .get("/.well-known/openid-credential-issuer")
        .await
        .assert_status_ok();
    server
        .get("/oid4vci/credential-offer")
        .await
        .assert_status_ok();
    server
        .post("/oid4vci/nonce")
        .json(&json!({}))
        .await
        .assert_status_ok();
    server
        .get("/v1/credentials/urn:ulid:01HX0000000000000000000000/status")
        .await
        .assert_status(StatusCode::NOT_FOUND);
    server
        .get("/v1/credentials/urn:ulid:01HX0000000000000000000000/history")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    server
        .post("/federation/v1/evaluations")
        .bytes(Bytes::from_static(b"not-mounted"))
        .await
        .assert_status(StatusCode::NOT_FOUND);

    server
        .get("/metrics")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    server
        .get("/credentials")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    server
        .post("/v1/credentials")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);

    idp.stop().await;
}

#[tokio::test]
pub(super) async fn manifest_public_protected_routes_are_mounted_behind_auth() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let manifest: ExposureManifest = serde_json::from_str(include_str!(
        "../../../../products/notary/security/exposure-manifest.json"
    ))
    .expect("security exposure manifest parses");
    let idp = MockIdp::start().await;
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oid4vci_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    enable_credential_status(&mut config);
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    for endpoint in manifest.endpoints.iter().filter(|endpoint| {
        endpoint.listener == "public" && endpoint.auth != "none" && endpoint.feature.is_none()
    }) {
        let method = Method::from_bytes(endpoint.method.as_bytes()).expect("method parses");
        let path = sample_manifest_path(&endpoint.path);
        let request = server.method(method, &path);
        let response = if endpoint.auth == "bearer" && endpoint.path == "/oid4vci/credential" {
            request
                .json(&json!({
                    "format": "dc+sd-jwt",
                    "credential_configuration_id": "person_is_alive_sd_jwt",
                    "proof": {
                        "proof_type": "jwt",
                        "jwt": sign_oid4vci_proof("http://127.0.0.1:4325", "nonce-1")
                    }
                }))
                .await
        } else {
            request.await
        };
        assert_eq!(
            response.status_code(),
            StatusCode::UNAUTHORIZED,
            "{} {} must be mounted behind auth on the public listener",
            endpoint.method,
            endpoint.path
        );
    }

    idp.stop().await;
}

#[tokio::test]
pub(super) async fn service_document_advertises_credential_status_when_enabled() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    enable_credential_status(&mut config);
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let response = server
        .get("/.well-known/evidence-service")
        .add_header("x-api-key", "api-token")
        .await;

    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(
        body["credential_capabilities"]["sd_jwt_vc"]["status_methods"],
        json!(["status_list"])
    );
    assert_eq!(
        body["credential_capabilities"]["sd_jwt_vc"]["credential_status_url"],
        json!("/v1/credentials/{credential_id}/status")
    );
    assert_eq!(
        body["credential_capabilities"]["sd_jwt_vc"]["credential_status_media_type"],
        json!("application/statuslist+jwt")
    );
    assert!(!body["credential_capabilities"]["unsupported_features"]
        .as_array()
        .expect("unsupported features is an array")
        .iter()
        .any(|feature| feature.as_str() == Some("credential_status")));
}

#[tokio::test]
pub(super) async fn credential_status_admin_edges_return_expected_http_statuses() {
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var(
        "TEST_EVIDENCE_ADMIN_KEY_HASH",
        "sha256:10a4c7c9fc5206d6f36dc6944a81bb6f4a3cb0e25014ae3b12e6c3e52712292a",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");

    let tmp = TempDir::new().expect("tempdir");
    let enabled_audit_path = tmp.path().join("enabled-audit.jsonl");
    let mut enabled_config = registry_data_api_config(
        "http://127.0.0.1:1",
        enabled_audit_path
            .to_str()
            .expect("enabled audit path is UTF-8"),
    );
    enable_shared_admin_listener(&mut enabled_config);
    enable_credential_status(&mut enabled_config);
    enabled_config.auth.api_keys.push(EvidenceCredentialConfig {
        id: "admin".to_string(),
        fingerprint: env_fingerprint_ref("TEST_EVIDENCE_ADMIN_KEY_HASH"),
        scopes: vec!["registry_notary:admin".to_string()],
        authorization_details: None,
    });
    let enabled_server = TestServer::builder()
        .http_transport()
        .build(standalone_router(enabled_config).expect("enabled router builds"));

    let invalid_status = enabled_server
        .post("/admin/v1/credentials/urn:ulid:01HX0000000000000000000000/status")
        .add_header("x-api-key", "admin-token")
        .json(&json!({ "status": "deleted" }))
        .await;
    invalid_status.assert_status(StatusCode::BAD_REQUEST);
    let invalid_body: Value = invalid_status.json();
    assert_eq!(
        invalid_body["code"],
        json!("credential_status.invalid_status")
    );

    let missing_admin_scope = enabled_server
        .post("/admin/v1/credentials/urn:ulid:01HX0000000000000000000000/status")
        .add_header("x-api-key", "api-token")
        .json(&json!({ "status": "revoked" }))
        .await;
    missing_admin_scope.assert_status(StatusCode::FORBIDDEN);

    let disabled_audit_path = tmp.path().join("disabled-audit.jsonl");
    let mut disabled_config = registry_data_api_config(
        "http://127.0.0.1:1",
        disabled_audit_path
            .to_str()
            .expect("disabled audit path is UTF-8"),
    );
    enable_shared_admin_listener(&mut disabled_config);
    disabled_config
        .auth
        .api_keys
        .push(EvidenceCredentialConfig {
            id: "admin".to_string(),
            fingerprint: env_fingerprint_ref("TEST_EVIDENCE_ADMIN_KEY_HASH"),
            scopes: vec!["registry_notary:admin".to_string()],
            authorization_details: None,
        });
    let disabled_server = TestServer::builder()
        .http_transport()
        .build(standalone_router(disabled_config).expect("disabled router builds"));

    let disabled = disabled_server
        .post("/admin/v1/credentials/urn:ulid:01HX0000000000000000000000/status")
        .add_header("x-api-key", "admin-token")
        .json(&json!({ "status": "revoked" }))
        .await;
    disabled.assert_status(StatusCode::NOT_FOUND);
    let disabled_body: Value = disabled.json();
    assert_eq!(disabled_body["code"], json!("credential_status.disabled"));

    let disabled_public = disabled_server
        .get("/v1/credentials/urn:ulid:01HX0000000000000000000000/status")
        .await;
    disabled_public.assert_status(StatusCode::NOT_FOUND);
}

#[tokio::test]
pub(super) async fn admin_scope_is_instance_global_across_credential_profiles() {
    // Pins the documented instance-global admin model (issue #58): the same
    // registry_notary:admin-scoped credential authorizes admin operations
    // against every credential profile hosted by this instance. Registry
    // Notary does not partition admin authority per credential profile /
    // issuer; the supported isolation boundary for separate administrative
    // domains is one Registry Notary instance per issuing authority.
    set_audit_secret();
    std::env::set_var(
        "TEST_EVIDENCE_API_KEY_HASH",
        "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51",
    );
    std::env::set_var(
        "TEST_EVIDENCE_ADMIN_KEY_HASH",
        "sha256:10a4c7c9fc5206d6f36dc6944a81bb6f4a3cb0e25014ae3b12e6c3e52712292a",
    );
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK_2", TEST_HOLDER_JWK);

    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = registry_data_api_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
    );
    enable_shared_admin_listener(&mut config);
    enable_credential_status(&mut config);
    config.auth.api_keys.push(EvidenceCredentialConfig {
        id: "admin".to_string(),
        fingerprint: env_fingerprint_ref("TEST_EVIDENCE_ADMIN_KEY_HASH"),
        scopes: vec!["registry_notary:admin".to_string()],
        authorization_details: None,
    });

    // Two credential profiles standing in for two distinct issuing
    // authorities hosted by this single instance.
    config.evidence.signing_keys.insert(
        "issuer-one-key".to_string(),
        local_jwk_signing_key(
            "TEST_SELF_ATTESTATION_ISSUER_JWK",
            "did:web:issuer-one.example#key-1",
        ),
    );
    config.evidence.signing_keys.insert(
        "issuer-two-key".to_string(),
        local_jwk_signing_key(
            "TEST_SELF_ATTESTATION_ISSUER_JWK_2",
            "did:web:issuer-two.example#key-1",
        ),
    );
    config.evidence.credential_profiles.insert(
        "issuer_one_sd_jwt".to_string(),
        CredentialProfileConfig {
            format: "application/dc+sd-jwt".to_string(),
            issuer: "did:web:issuer-one.example".to_string(),
            signing_key: "issuer-one-key".to_string(),
            vct: "http://127.0.0.1:4325/credentials/issuer-one".to_string(),
            validity_seconds: 600,
            holder_binding: Default::default(),
            allowed_claims: vec!["farmed-land-size".to_string()],
            disclosure: Default::default(),
        },
    );
    config.evidence.credential_profiles.insert(
        "issuer_two_sd_jwt".to_string(),
        CredentialProfileConfig {
            format: "application/dc+sd-jwt".to_string(),
            issuer: "did:web:issuer-two.example".to_string(),
            signing_key: "issuer-two-key".to_string(),
            vct: "http://127.0.0.1:4325/credentials/issuer-two".to_string(),
            validity_seconds: 600,
            holder_binding: Default::default(),
            allowed_claims: vec!["farmed-land-size".to_string()],
            disclosure: Default::default(),
        },
    );

    let server = TestServer::builder()
        .http_transport()
        .build(standalone_router(config).expect("standalone router builds"));

    // Credential ids standing in for credentials issued under each profile.
    // The admin credential-status route takes no profile parameter, so this
    // exercises the same route and token pair against resources nominally
    // tied to two different issuers hosted by the instance.
    let issuer_one_credential_id = "urn:ulid:01HX0000000000000000000AA1";
    let issuer_two_credential_id = "urn:ulid:01HX0000000000000000000AA2";

    for credential_id in [issuer_one_credential_id, issuer_two_credential_id] {
        let path = format!("/admin/v1/credentials/{credential_id}/status");

        // The non-admin caseworker key is denied for both profiles' credentials.
        let missing_admin_scope = server
            .post(&path)
            .add_header("x-api-key", "api-token")
            .json(&json!({ "status": "revoked" }))
            .await;
        missing_admin_scope.assert_status(StatusCode::FORBIDDEN);

        // The single admin-scoped key clears the scope check for both
        // profiles' credentials; the deliberately invalid status value below
        // proves the request reached past authorization (400, not 403).
        let admin_authorized = server
            .post(&path)
            .add_header("x-api-key", "admin-token")
            .json(&json!({ "status": "deleted" }))
            .await;
        admin_authorized.assert_status(StatusCode::BAD_REQUEST);
        let admin_authorized_body: Value = admin_authorized.json();
        assert_eq!(
            admin_authorized_body["code"],
            json!("credential_status.invalid_status")
        );
    }
}

#[tokio::test]
pub(super) async fn disabled_oid4vci_credential_route_stays_hidden_for_malformed_body() {
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

    let response = server
        .post("/oid4vci/credential")
        .add_header("content-type", "application/json")
        .text("{")
        .await;
    response.assert_status(StatusCode::NOT_FOUND);

    idp.stop().await;
}

#[tokio::test]
#[cfg(feature = "registry-notary-cel")]
pub(super) async fn oid4vci_credential_route_issues_holder_bound_sd_jwt() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/people/entities/person/records",
            get(self_attestation_registry_data_api),
        ));
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oid4vci_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    enable_shared_admin_listener(&mut config);
    enable_credential_status(&mut config);
    config
        .auth
        .oidc
        .as_mut()
        .expect("OIDC auth is configured")
        .scope_map
        .insert(
            "status_admin".to_string(),
            vec!["registry_notary:admin".to_string()],
        );
    config.self_attestation.allowed_operations.issue_credential = true;
    config
        .evidence
        .claims
        .first_mut()
        .expect("person-is-alive claim exists")
        .formats
        .push("application/dc+sd-jwt".to_string());
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let missing_status = server
        .get("/v1/credentials/urn:ulid:01HX0000000000000000000000/status")
        .await;
    missing_status.assert_status(StatusCode::NOT_FOUND);
    let missing_status_body: Value = missing_status.json();
    assert_eq!(
        missing_status_body["code"],
        json!("credential_status.not_found")
    );

    let nonce = server
        .post("/oid4vci/nonce")
        .json(&json!({"credential_configuration_id": "person_is_alive_sd_jwt"}))
        .await;
    nonce.assert_status_ok();
    let nonce_body: Value = nonce.json();
    let nonce = nonce_body["c_nonce"]
        .as_str()
        .expect("nonce is returned")
        .to_string();
    let proof = sign_oid4vci_proof("http://127.0.0.1:4325", &nonce);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let token = idp.mint_token(json!({
        "sub": "citizen-subject",
        "aud": "registry-notary-citizen",
        "azp": "citizen-portal",
        "scope": "self_attestation person-is-alive",
        "national_id": "person-1",
        "authorization_details": [{
            "type": registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_TYPE,
            "schema_version": registry_notary_core::tokens::NOTARY_AUTHORIZATION_DETAILS_SCHEMA_VERSION,
            "legal_basis_ref": "wallet-compat-context",
            "consent_ref": "wallet-compat-consent",
            "jurisdiction": "ZZ",
            "assurance_level": "substantial"
        }],
        "auth_time": now,
        "iat": now,
        "exp": now + 300,
        "nbf": now,
    }));

    let response = server
        .post("/oid4vci/credential")
        .add_header("authorization", format!("Bearer {token}"))
        .json(&json!({
            "format": "dc+sd-jwt",
            "credential_configuration_id": "person_is_alive_sd_jwt",
            "proof": {
                "proof_type": "jwt",
                "jwt": proof
            }
        }))
        .await;
    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["format"], json!("dc+sd-jwt"));
    let credential = body["credential"].as_str().expect("credential is a string");
    assert!(credential.contains('~'));
    let issuer_jws = credential
        .split('~')
        .next()
        .expect("SD-JWT contains an issuer JWS");
    let payload_segment = issuer_jws
        .split('.')
        .nth(1)
        .expect("issuer JWS contains a payload segment");
    let payload: Value = serde_json::from_slice(
        &URL_SAFE_NO_PAD
            .decode(payload_segment)
            .expect("issuer JWS payload is base64url"),
    )
    .expect("issuer JWS payload is JSON");
    assert_eq!(
        payload["exp"].as_i64().expect("credential has exp")
            - payload["iat"].as_i64().expect("credential has iat"),
        600
    );
    let credential_id = payload["jti"]
        .as_str()
        .expect("credential has jti")
        .to_string();
    assert_eq!(payload["id"], json!(credential_id));
    assert_eq!(
        payload["status"],
        json!({
            "status_list": {
                "idx": 0,
                "uri": format!("http://127.0.0.1:4325/v1/credentials/{credential_id}/status")
            }
        })
    );
    assert!(body["c_nonce"]
        .as_str()
        .is_some_and(|value| !value.is_empty()));

    let status = server
        .get(&format!("/v1/credentials/{credential_id}/status"))
        .await;
    status.assert_status_ok();
    let status_body: Value = status.json();
    assert_eq!(status_body["credential_id"], json!(credential_id));
    assert_eq!(status_body["status"], json!("valid"));
    assert_eq!(
        status_body["credential_profile"],
        json!("civil_status_sd_jwt")
    );
    let status_list = server
        .get(&format!("/v1/credentials/{credential_id}/status"))
        .add_header(header::ACCEPT, "application/statuslist+jwt")
        .await;
    status_list.assert_status_ok();
    assert_eq!(
        status_list
            .headers()
            .get(header::CONTENT_TYPE)
            .and_then(|value| value.to_str().ok()),
        Some("application/statuslist+jwt")
    );
    let status_list_jwt = status_list.text();
    assert_eq!(jwt_header(&status_list_jwt)["typ"], json!("statuslist+jwt"));
    let status_list_payload = jwt_payload(&status_list_jwt);
    assert_eq!(
        status_list_payload["sub"],
        json!(format!(
            "http://127.0.0.1:4325/v1/credentials/{credential_id}/status"
        ))
    );
    assert_eq!(status_list_payload["ttl"], json!(300));
    assert_eq!(status_list_payload["status_list"]["bits"], json!(8));
    assert_eq!(
        status_list_payload["status_list"]["lst"],
        json!("eJxjAAAAAQAB")
    );

    let admin_token = idp.mint_token(json!({
        "sub": "status-admin",
        "aud": "registry-notary-citizen",
        "azp": "citizen-portal",
        "scope": "status_admin",
        "iat": now,
        "exp": now + 300,
        "nbf": now,
    }));
    let revoked = server
        .post(&format!("/admin/v1/credentials/{credential_id}/status"))
        .add_header("authorization", format!("Bearer {admin_token}"))
        .json(&json!({ "status": "revoked" }))
        .await;
    revoked.assert_status_ok();
    let revoked_body: Value = revoked.json();
    assert_eq!(revoked_body["status"], json!("revoked"));

    let status_after_revoke = server
        .get(&format!("/v1/credentials/{credential_id}/status"))
        .await;
    status_after_revoke.assert_status_ok();
    let status_after_revoke_body: Value = status_after_revoke.json();
    assert_eq!(status_after_revoke_body["status"], json!("revoked"));
    let revoked_status_list = server
        .get(&format!("/v1/credentials/{credential_id}/status"))
        .add_header(header::ACCEPT, "application/statuslist+jwt")
        .await;
    revoked_status_list.assert_status_ok();
    let revoked_status_list_payload = jwt_payload(&revoked_status_list.text());
    assert_eq!(
        revoked_status_list_payload["status_list"]["lst"],
        json!("eJxjBAAAAgAC")
    );

    for attempted_status in ["valid", "suspended"] {
        let rejected = server
            .post(&format!("/admin/v1/credentials/{credential_id}/status"))
            .add_header("authorization", format!("Bearer {admin_token}"))
            .json(&json!({ "status": attempted_status }))
            .await;
        rejected.assert_status(StatusCode::CONFLICT);
        let rejected_body: Value = rejected.json();
        assert_eq!(
            rejected_body["code"],
            json!("credential_status.invalid_transition")
        );
    }

    let status_after_rejected_mutations = server
        .get(&format!("/v1/credentials/{credential_id}/status"))
        .await;
    status_after_rejected_mutations.assert_status_ok();
    let status_after_rejected_mutations_body: Value = status_after_rejected_mutations.json();
    assert_eq!(
        status_after_rejected_mutations_body["status"],
        json!("revoked")
    );

    let records = audit_envelopes(&audit_path)
        .into_iter()
        .map(|envelope| envelope.record)
        .collect::<Vec<_>>();
    let credential_audit = records
        .iter()
        .find(|record| {
            record["path"] == json!("/oid4vci/credential")
                && record["decision"] == json!("credential_issued")
                && record["status"] == json!(200)
        })
        .expect("OID4VCI credential audit record exists");
    assert_eq!(credential_audit["access_mode"], json!("self_attestation"));
    assert_eq!(
        credential_audit["purposes"],
        json!(["citizen_self_attestation"])
    );
    assert_eq!(credential_audit["protocol"], json!("openid4vci"));
    assert_eq!(
        credential_audit["credential_configuration_id"],
        json!("person_is_alive_sd_jwt")
    );
    assert_eq!(
        credential_audit["credential_profile"],
        json!("civil_status_sd_jwt")
    );
    assert_eq!(credential_audit["target_type"], json!("Person"));
    assert!(credential_audit["target_ref_hash"].as_str().is_some());
    assert_eq!(credential_audit["requester_type"], json!("Person"));
    assert!(credential_audit["requester_ref_hash"].as_str().is_some());

    idp.stop().await;
}

#[tokio::test]
#[cfg(feature = "registry-notary-cel")]
pub(super) async fn oid4vci_field_projection_issues_separate_disclosures() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/people/entities/person/records",
            get(self_attestation_registry_data_api),
        ));
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oid4vci_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    enable_oid4vci_field_projection(&mut config);
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let metadata = server
        .get("/credentials/civil-status")
        .add_header("host", "127.0.0.1:4325")
        .add_header("x-forwarded-proto", "http")
        .await;
    metadata.assert_status_ok();
    let metadata_body: Value = metadata.json();
    assert_eq!(metadata_body["claims"][0]["path"], json!(["given_name"]));
    assert_eq!(
        metadata_body["claims"][0]["display"][0]["label"],
        json!("Given name")
    );
    assert_eq!(metadata_body["claims"][0]["sd"], json!("always"));
    assert_eq!(metadata_body["claims"][0]["mandatory"], json!(true));
    assert_eq!(metadata_body["claims"][1]["path"], json!(["birth_date"]));
    assert_eq!(
        metadata_body["claims"][1]["display"][0]["label"],
        json!("Birth date")
    );
    assert_eq!(metadata_body["claims"][1]["mandatory"], json!(true));

    let nonce = server
        .post("/oid4vci/nonce")
        .json(&json!({"credential_configuration_id": "person_is_alive_sd_jwt"}))
        .await;
    nonce.assert_status_ok();
    let nonce = nonce.json::<Value>()["c_nonce"]
        .as_str()
        .expect("nonce is returned")
        .to_string();
    let proof = sign_oid4vci_proof("http://127.0.0.1:4325", &nonce);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let token = idp.mint_token(json!({
        "sub": "citizen-subject",
        "aud": "registry-notary-citizen",
        "azp": "citizen-portal",
        "scope": "self_attestation person-is-alive",
        "national_id": "person-1",
        "auth_time": now,
        "iat": now,
        "exp": now + 300,
        "nbf": now,
    }));

    let response = server
        .post("/oid4vci/credential")
        .add_header("authorization", format!("Bearer {token}"))
        .json(&json!({
            "format": "dc+sd-jwt",
            "credential_configuration_id": "person_is_alive_sd_jwt",
            "proof": {
                "proof_type": "jwt",
                "jwt": proof
            }
        }))
        .await;
    response.assert_status_ok();
    let body: Value = response.json();
    let credential = body["credential"].as_str().expect("credential issued");
    let payload = decode_sd_jwt_payload(credential);
    assert_eq!(
        payload["vct"],
        json!("http://127.0.0.1:4325/credentials/civil-status")
    );
    assert_eq!(
        payload["_sd"]
            .as_array()
            .expect("_sd digests are present")
            .len(),
        2
    );
    let payload_text = payload.to_string();
    assert!(!payload_text.contains("Miguel"));
    assert!(!payload_text.contains("2016-01-15"));

    assert_eq!(
        decode_disclosed_claim(credential, "given_name"),
        json!("Miguel")
    );
    assert_eq!(
        decode_disclosed_claim(credential, "birth_date"),
        json!("2016-01-15")
    );

    idp.stop().await;
}

#[tokio::test]
#[cfg(feature = "registry-notary-cel")]
pub(super) async fn oid4vci_credential_route_rejects_replayed_nonce() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let upstream = TestServer::builder()
        .http_transport()
        .build(Router::new().route(
            "/v1/datasets/people/entities/person/records",
            get(self_attestation_registry_data_api),
        ));
    let base_url = upstream
        .server_address()
        .expect("HTTP transport exposes upstream address")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oid4vci_config(
        base_url.trim_end_matches('/'),
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    config.self_attestation.allowed_operations.issue_credential = true;
    config
        .evidence
        .claims
        .first_mut()
        .expect("person-is-alive claim exists")
        .formats
        .push("application/dc+sd-jwt".to_string());
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let nonce = server
        .post("/oid4vci/nonce")
        .json(&json!({"credential_configuration_id": "person_is_alive_sd_jwt"}))
        .await;
    nonce.assert_status_ok();
    let nonce_body: Value = nonce.json();
    let nonce = nonce_body["c_nonce"]
        .as_str()
        .expect("nonce is returned")
        .to_string();
    let proof = sign_oid4vci_proof("http://127.0.0.1:4325", &nonce);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let token = idp.mint_token(json!({
        "sub": "citizen-subject",
        "aud": "registry-notary-citizen",
        "azp": "citizen-portal",
        "scope": "self_attestation person-is-alive",
        "national_id": "person-1",
        "auth_time": now,
        "iat": now,
        "exp": now + 300,
        "nbf": now,
    }));
    let credential_request = json!({
        "format": "dc+sd-jwt",
        "credential_configuration_id": "person_is_alive_sd_jwt",
        "proof": {
            "proof_type": "jwt",
            "jwt": proof
        }
    });

    let first = server
        .post("/oid4vci/credential")
        .add_header("authorization", format!("Bearer {token}"))
        .json(&credential_request)
        .await;
    first.assert_status_ok();

    let replay = server
        .post("/oid4vci/credential")
        .add_header("authorization", format!("Bearer {token}"))
        .json(&credential_request)
        .await;
    replay.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = replay.json();
    assert_eq!(body["error"], json!("invalid_proof"));

    idp.stop().await;
}

#[tokio::test]
pub(super) async fn oid4vci_malformed_proof_is_rejected_before_oidc_auth() {
    set_audit_secret();
    std::env::set_var("TEST_EVIDENCE_SOURCE_TOKEN", "source-token");
    std::env::set_var("TEST_SELF_ATTESTATION_ISSUER_JWK", TEST_ISSUER_JWK);

    let idp = MockIdp::start().await;
    let userinfo_hits = Arc::new(AtomicUsize::new(0));
    let userinfo_hits_for_route = Arc::clone(&userinfo_hits);
    let userinfo_app = Router::new().route(
        "/userinfo",
        get(move || {
            let userinfo_hits = Arc::clone(&userinfo_hits_for_route);
            async move {
                userinfo_hits.fetch_add(1, Ordering::SeqCst);
                StatusCode::NO_CONTENT
            }
        }),
    );
    let userinfo_server = TestServer::builder().http_transport().build(userinfo_app);
    let userinfo_endpoint = userinfo_server
        .server_url("/userinfo")
        .expect("userinfo URL builds")
        .to_string();
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");
    let mut config = self_attestation_oid4vci_config(
        "http://127.0.0.1:1",
        audit_path.to_str().expect("audit path is UTF-8"),
        &idp.issuer(),
        &idp.jwks_uri(),
    );
    config.self_attestation.subject_binding.claim_source = SelfAttestationClaimSource::Userinfo;
    config
        .auth
        .oidc
        .as_mut()
        .expect("oidc config exists")
        .userinfo_endpoint = Some(userinfo_endpoint);
    let app = standalone_router(config).expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let token = idp.mint_token(json!({
        "sub": "citizen-subject",
        "aud": "registry-notary-citizen",
        "azp": "citizen-portal",
        "scope": "self_attestation",
        "auth_time": now,
        "iat": now,
        "exp": now + 300,
        "nbf": now,
    }));

    let response = server
        .post("/oid4vci/credential")
        .add_header("authorization", format!("Bearer {token}"))
        .json(&json!({
            "format": "dc+sd-jwt",
            "credential_configuration_id": "person_is_alive_sd_jwt",
            "proof": {
                "proof_type": "jwt",
                "jwt": "not-a-compact-jwt"
            }
        }))
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = response.json();
    assert_eq!(body["error"], json!("invalid_proof"));
    assert!(body.get("code").is_none());
    assert_eq!(
        userinfo_hits.load(Ordering::SeqCst),
        0,
        "malformed proof must be rejected before the live UserInfo fetch"
    );

    let response = server
        .post("/oid4vci/credential")
        .json(&json!({
            "format": "dc+sd-jwt",
            "credential_configuration_id": "person_is_alive_sd_jwt",
            "target": person_target("person-2"),
            "proof": {
                "proof_type": "jwt",
                "jwt": "not-a-compact-jwt"
            }
        }))
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = response.json();
    assert_eq!(body["error"], json!("invalid_proof"));

    idp.stop().await;
}
