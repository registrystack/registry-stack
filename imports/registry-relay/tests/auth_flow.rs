// SPDX-License-Identifier: Apache-2.0
//! Integration tests for the V1 auth flow.
//!
//! Covers the auth wire contract (`auth.*` codes):
//!
//! * missing `Authorization` header -> `auth.missing_credential` / 401
//! * malformed header (wrong scheme, empty bearer) -> `auth.malformed_credential` / 401
//! * unknown bearer token -> `auth.invalid_credential` / 401
//! * valid bearer -> 200 with `Principal` available in request extensions
//! * scope check -> `auth.scope_denied` / 403 when scope absent
//!
//! Every test additionally asserts that the response body does not echo
//! the presented credential. Audit-side coverage (the audit middleware
//! observing `Principal`) lives in `tests/audit_record.rs` and is owned
//! by the audit track.

use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;

use axum::body::Body;
use axum::extract::Extension;
use axum::http::{Request, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use data_gate::auth::api_key::{ApiKeyAuth, ApiKeyEntry};
use data_gate::auth::middleware::auth_layer;
use data_gate::auth::scopes::{require_scope, ScopeSet};
use data_gate::auth::{AuthMode, AuthProvider, Principal};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tower::ServiceExt;

const VALID_KEY: &str = "test-bearer-token-abcdef-0123456789";
const OTHER_KEY: &str = "another-key-9876543210";
const CLIENT_ID: &str = "statistics_office";

fn make_fingerprint(plain: &str) -> String {
    format!("sha256:{}", hex_lower(&Sha256::digest(plain.as_bytes())))
}

fn build_provider() -> Arc<ApiKeyAuth> {
    let entries = vec![ApiKeyEntry::new(
        CLIENT_ID.to_string(),
        ScopeSet::from_iter(["social_registry:rows", "social_registry:metadata"]),
        make_fingerprint(VALID_KEY),
    )
    .expect("test fingerprint parses")];
    Arc::new(ApiKeyAuth::new(entries))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// Build a router that runs the auth middleware in front of two
/// handlers:
/// * `/whoami` returns the `Principal` as JSON so tests can assert its
///   contents from the wire (instead of poking at extensions).
/// * `/needs-admin` calls `require_scope(&principal, "admin")` so tests
///   can exercise scope denial without depending on the audit track.
fn router_with_provider(provider: Arc<ApiKeyAuth>) -> Router {
    auth_layer(
        Router::new()
            .route("/whoami", get(whoami_handler))
            .route("/needs-admin", get(needs_admin_handler)),
        provider,
    )
}

async fn whoami_handler(Extension(principal): Extension<Principal>) -> impl IntoResponse {
    let scopes: Vec<&str> = principal.scopes.iter().collect();
    let mode = match principal.auth_mode {
        AuthMode::ApiKey => "api_key",
        // AuthMode is #[non_exhaustive]; falling through here is a
        // V2 problem, not a V1 one. Default to a string the test
        // assertion does not match against so V2 wiring forces an
        // explicit decision.
        _ => "unknown",
    };
    axum::Json(serde_json::json!({
        "api_key_id": principal.api_key_id,
        "scopes": scopes,
        "auth_mode": mode,
    }))
}

async fn needs_admin_handler(
    Extension(principal): Extension<Principal>,
) -> Result<&'static str, data_gate::error::Error> {
    require_scope(&principal, "admin")?;
    Ok("ok")
}

/// Read the response body, parse it as JSON, and assert that neither
/// the field values nor any string anywhere in the document contain
/// the presented credential.
async fn assert_problem_response(
    response: axum::http::Response<Body>,
    expected_status: StatusCode,
    expected_code: &str,
    presented_credential: &str,
) -> Value {
    assert_eq!(response.status(), expected_status, "status mismatch");
    let ct = response
        .headers()
        .get("content-type")
        .expect("content-type header is set")
        .to_str()
        .expect("content-type is ASCII");
    assert!(
        ct.starts_with("application/problem+json"),
        "expected RFC 9457 content-type, got {ct}"
    );

    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body reads");
    let body_str = String::from_utf8(bytes.to_vec()).expect("body is utf-8");
    // `contains("")` is always true, so skip the leak check when no
    // credential was presented (e.g. missing-header tests).
    if !presented_credential.is_empty() {
        assert!(
            !body_str.contains(presented_credential),
            "response body must not contain the raw credential"
        );
    }

    let value: Value = serde_json::from_str(&body_str).expect("body is JSON");
    assert_eq!(value["code"].as_str(), Some(expected_code), "code mismatch");
    value
}

#[tokio::test]
async fn missing_header_returns_missing_credential() {
    let app = router_with_provider(build_provider());
    let response = app
        .oneshot(
            Request::builder()
                .uri("/whoami")
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("service responds");
    assert_problem_response(
        response,
        StatusCode::UNAUTHORIZED,
        "auth.missing_credential",
        "",
    )
    .await;
}

#[tokio::test]
async fn wrong_scheme_returns_malformed_credential() {
    let app = router_with_provider(build_provider());
    let response = app
        .oneshot(
            Request::builder()
                .uri("/whoami")
                .header("Authorization", format!("Basic {VALID_KEY}"))
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("service responds");
    assert_problem_response(
        response,
        StatusCode::UNAUTHORIZED,
        "auth.malformed_credential",
        VALID_KEY,
    )
    .await;
}

#[tokio::test]
async fn empty_bearer_returns_malformed_credential() {
    let app = router_with_provider(build_provider());
    let response = app
        .oneshot(
            Request::builder()
                .uri("/whoami")
                .header("Authorization", "Bearer ")
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("service responds");
    assert_problem_response(
        response,
        StatusCode::UNAUTHORIZED,
        "auth.malformed_credential",
        "",
    )
    .await;
}

#[tokio::test]
async fn unknown_key_returns_invalid_credential() {
    let app = router_with_provider(build_provider());
    let response = app
        .oneshot(
            Request::builder()
                .uri("/whoami")
                .header("Authorization", format!("Bearer {OTHER_KEY}"))
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("service responds");
    assert_problem_response(
        response,
        StatusCode::UNAUTHORIZED,
        "auth.invalid_credential",
        OTHER_KEY,
    )
    .await;
}

#[tokio::test]
async fn valid_key_admits_request_and_populates_principal() {
    let app = router_with_provider(build_provider());
    let response = app
        .oneshot(
            Request::builder()
                .uri("/whoami")
                .header("Authorization", format!("Bearer {VALID_KEY}"))
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("service responds");
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body reads");
    let body_str = String::from_utf8(bytes.to_vec()).expect("body utf-8");
    assert!(
        !body_str.contains(VALID_KEY),
        "successful response body must not contain the raw credential"
    );
    let value: Value = serde_json::from_str(&body_str).expect("JSON");
    assert_eq!(value["api_key_id"].as_str(), Some(CLIENT_ID));
    assert_eq!(value["auth_mode"].as_str(), Some("api_key"));
    let scopes: Vec<&str> = value["scopes"]
        .as_array()
        .expect("scopes array")
        .iter()
        .map(|v| v.as_str().expect("scope is string"))
        .collect();
    assert!(scopes.contains(&"social_registry:rows"));
    assert!(scopes.contains(&"social_registry:metadata"));
}

#[tokio::test]
async fn x_api_key_admits_request_and_populates_principal() {
    let app = router_with_provider(build_provider());
    let response = app
        .oneshot(
            Request::builder()
                .uri("/whoami")
                .header("X-Api-Key", VALID_KEY)
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("service responds");
    assert_eq!(response.status(), StatusCode::OK);
    let bytes = axum::body::to_bytes(response.into_body(), 64 * 1024)
        .await
        .expect("body reads");
    let body_str = String::from_utf8(bytes.to_vec()).expect("body utf-8");
    assert!(
        !body_str.contains(VALID_KEY),
        "successful response body must not contain the raw credential"
    );
    let value: Value = serde_json::from_str(&body_str).expect("JSON");
    assert_eq!(value["api_key_id"].as_str(), Some(CLIENT_ID));
    assert_eq!(value["auth_mode"].as_str(), Some("api_key"));
}

#[tokio::test]
async fn missing_scope_returns_scope_denied() {
    let app = router_with_provider(build_provider());
    let response = app
        .oneshot(
            Request::builder()
                .uri("/needs-admin")
                .header("Authorization", format!("Bearer {VALID_KEY}"))
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("service responds");
    let value = assert_problem_response(
        response,
        StatusCode::FORBIDDEN,
        "auth.scope_denied",
        VALID_KEY,
    )
    .await;
    // The required scope is operator-visible context; assert it
    // reached the response detail per the error taxonomy.
    let detail = value["detail"].as_str().expect("detail present");
    assert!(detail.contains("admin"), "detail mentions the scope");
}

#[tokio::test]
async fn require_scope_unit_returns_scope_denied_error() {
    let principal = Principal {
        api_key_id: "test".to_string(),
        scopes: ScopeSet::from_iter(["a", "b"]),
        auth_mode: AuthMode::ApiKey,
    };
    let err = require_scope(&principal, "c").expect_err("missing scope errors");
    assert_eq!(err.code(), "auth.scope_denied");
}

#[tokio::test]
async fn require_scope_unit_admits_present_scope() {
    let principal = Principal {
        api_key_id: "test".to_string(),
        scopes: ScopeSet::from_iter(["a", "b"]),
        auth_mode: AuthMode::ApiKey,
    };
    require_scope(&principal, "a").expect("present scope admitted");
}

#[tokio::test]
async fn provider_directly_authenticates_valid_bearer() {
    let provider = build_provider();
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::AUTHORIZATION,
        format!("Bearer {VALID_KEY}")
            .parse()
            .expect("header parses"),
    );
    let principal = provider
        .authenticate(&headers, IpAddr::V4(Ipv4Addr::LOCALHOST))
        .await
        .expect("valid bearer authenticates");
    assert_eq!(principal.api_key_id, CLIENT_ID);
}

#[tokio::test]
async fn provider_rejects_unknown_bearer() {
    let provider = build_provider();
    let mut headers = axum::http::HeaderMap::new();
    headers.insert(
        axum::http::header::AUTHORIZATION,
        format!("Bearer {OTHER_KEY}")
            .parse()
            .expect("header parses"),
    );
    let err = provider
        .authenticate(&headers, IpAddr::V4(Ipv4Addr::LOCALHOST))
        .await
        .expect_err("unknown bearer rejected");
    assert_eq!(
        data_gate::error::Error::from(err).code(),
        "auth.invalid_credential"
    );
}
