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
use axum::extract::{ConnectInfo, Extension};
use axum::http::{Request, Response, StatusCode};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use registry_relay::auth::api_key::{ApiKeyAuth, ApiKeyEntry};
use registry_relay::auth::failure_throttle::AuthFailureThrottle;
use registry_relay::auth::middleware::{auth_layer, auth_layer_with_failure_throttle};
use registry_relay::auth::scopes::{require_scope, ScopeSet};
use registry_relay::auth::{AuthMode, AuthProvider, AuthenticationResult, Principal};
use registry_relay::config::AuthFailureThrottleConfig;
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
/// * `/needs-admin` calls `require_scope(&principal, "registry_relay:admin")` so tests
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
        AuthMode::Oidc => "oidc",
    };
    axum::Json(serde_json::json!({
        "principal_id": principal.principal_id,
        "scopes": scopes,
        "auth_mode": mode,
    }))
}

async fn needs_admin_handler(
    Extension(principal): Extension<Principal>,
) -> Result<&'static str, registry_relay::error::Error> {
    require_scope(&principal, "registry_relay:admin")?;
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
    assert_eq!(value["principal_id"].as_str(), Some(CLIENT_ID));
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
    assert_eq!(value["principal_id"].as_str(), Some(CLIENT_ID));
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
    assert!(
        detail.contains("registry_relay:admin"),
        "detail mentions the scope"
    );
}

#[tokio::test]
async fn require_scope_unit_returns_scope_denied_error() {
    let principal = Principal {
        principal_id: "test".to_string(),
        scopes: ScopeSet::from_iter(["a", "b"]),
        auth_mode: AuthMode::ApiKey,
    };
    let err = require_scope(&principal, "c").expect_err("missing scope errors");
    assert_eq!(err.code(), "auth.scope_denied");
}

#[tokio::test]
async fn require_scope_unit_admits_present_scope() {
    let principal = Principal {
        principal_id: "test".to_string(),
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
    assert_eq!(principal.principal_id, CLIENT_ID);
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
        registry_relay::error::Error::from(err).code(),
        "auth.invalid_credential"
    );
}

// ---------------------------------------------------------------------------
// Auth-failure throttle (issue #78 relay backstop)
// ---------------------------------------------------------------------------

/// Build a router wired the same way as `router_with_provider`, but through
/// `auth_layer_with_failure_throttle` so tests can supply a throttle
/// (or `None`, which must behave identically to plain `auth_layer`).
fn router_with_provider_and_throttle(
    provider: Arc<ApiKeyAuth>,
    throttle: Option<Arc<AuthFailureThrottle>>,
) -> Router {
    router_with_auth_provider_and_throttle(provider, throttle)
}

fn router_with_auth_provider_and_throttle(
    provider: Arc<dyn AuthProvider>,
    throttle: Option<Arc<AuthFailureThrottle>>,
) -> Router {
    auth_layer_with_failure_throttle(
        Router::new()
            .route("/whoami", get(whoami_handler))
            .route("/needs-admin", get(needs_admin_handler)),
        provider,
        throttle,
        false,
        Vec::new(),
    )
}

fn throttle_config(max_failures: u32, window_seconds: u64) -> AuthFailureThrottleConfig {
    AuthFailureThrottleConfig {
        enabled: true,
        max_failures,
        window_seconds,
    }
}

struct JwksUnavailableAuth;

impl AuthProvider for JwksUnavailableAuth {
    fn authenticate<'a>(
        &'a self,
        _headers: &'a axum::http::HeaderMap,
        _remote_addr: IpAddr,
    ) -> std::pin::Pin<
        Box<
            dyn std::future::Future<
                    Output = Result<AuthenticationResult, registry_relay::error::AuthError>,
                > + Send
                + 'a,
        >,
    > {
        Box::pin(async { Err(registry_relay::error::AuthError::JwksUnavailable) })
    }
}

#[tokio::test]
async fn jwks_unavailable_does_not_count_toward_the_throttle() {
    let throttle = AuthFailureThrottle::new(&throttle_config(1, 60))
        .map(Arc::new)
        .expect("throttle enabled");
    let outage_app = router_with_auth_provider_and_throttle(
        Arc::new(JwksUnavailableAuth),
        Some(throttle.clone()),
    );

    for _ in 0..3 {
        let response = request_with_peer(
            &outage_app,
            "/whoami",
            Some(&format!("Bearer {VALID_KEY}")),
            "203.0.113.11:1",
        )
        .await;
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    }

    let recovered_app = router_with_provider_and_throttle(build_provider(), Some(throttle));
    let response = request_with_peer(
        &recovered_app,
        "/whoami",
        Some(&format!("Bearer {VALID_KEY}")),
        "203.0.113.11:1",
    )
    .await;
    assert_eq!(
        response.status(),
        StatusCode::OK,
        "JWKS outage responses must not consume the client's local failure budget"
    );
}

async fn request_with_peer(
    app: &Router,
    uri: &str,
    header: Option<&str>,
    peer: &str,
) -> Response<Body> {
    let mut builder = Request::builder().uri(uri);
    if let Some(header) = header {
        builder = builder.header("Authorization", header);
    }
    let mut req = builder.body(Body::empty()).expect("request builds");
    req.extensions_mut().insert(ConnectInfo(
        peer.parse::<std::net::SocketAddr>().expect("peer parses"),
    ));
    app.clone().oneshot(req).await.expect("service responds")
}

/// (a) A disabled throttle config yields `AuthFailureThrottle::new(..) ==
/// None`; repeated failures from the same address must never trip a 429.
/// This pins default-off behavior byte-for-byte against the pre-throttle
/// auth flow.
#[tokio::test]
async fn disabled_throttle_never_returns_rate_limited() {
    let mut config = throttle_config(2, 60);
    config.enabled = false;
    assert!(AuthFailureThrottle::new(&config).is_none());
    let throttle = AuthFailureThrottle::new(&config).map(Arc::new);
    let app = router_with_provider_and_throttle(build_provider(), throttle);

    for _ in 0..10 {
        let response = request_with_peer(
            &app,
            "/whoami",
            Some(&format!("Bearer {OTHER_KEY}")),
            "203.0.113.5:1",
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }
}

/// (b) With the throttle enabled, failures under the limit still pass
/// through as ordinary 401s; the failure that reaches (not just exceeds)
/// `max_failures` returns 429 with the stable `auth.rate_limited` code.
#[tokio::test]
async fn enabled_throttle_returns_401_under_limit_then_429_at_limit() {
    let throttle = AuthFailureThrottle::new(&throttle_config(2, 60)).map(Arc::new);
    let app = router_with_provider_and_throttle(build_provider(), throttle);

    for _ in 0..2 {
        let response = request_with_peer(
            &app,
            "/whoami",
            Some(&format!("Bearer {OTHER_KEY}")),
            "203.0.113.6:1",
        )
        .await;
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    let response = request_with_peer(
        &app,
        "/whoami",
        Some(&format!("Bearer {OTHER_KEY}")),
        "203.0.113.6:1",
    )
    .await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    let retry_after = response
        .headers()
        .get(axum::http::header::RETRY_AFTER)
        .expect("Retry-After header present")
        .to_str()
        .expect("Retry-After is ASCII")
        .to_string();
    assert!(
        retry_after.parse::<u64>().is_ok(),
        "Retry-After is a number"
    );
    assert_problem_response(
        response,
        StatusCode::TOO_MANY_REQUESTS,
        "auth.rate_limited",
        "",
    )
    .await;
}

/// (c) Once an address is over the limit, even a request presenting a
/// *valid* credential is short-circuited with 429 before `authenticate`
/// runs.
#[tokio::test]
async fn enabled_throttle_blocks_valid_credential_once_over_limit() {
    let throttle = AuthFailureThrottle::new(&throttle_config(1, 60)).map(Arc::new);
    let app = router_with_provider_and_throttle(build_provider(), throttle);

    let response = request_with_peer(
        &app,
        "/whoami",
        Some(&format!("Bearer {OTHER_KEY}")),
        "203.0.113.7:1",
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    let response = request_with_peer(
        &app,
        "/whoami",
        Some(&format!("Bearer {VALID_KEY}")),
        "203.0.113.7:1",
    )
    .await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
}

/// (d) A different client address is unaffected by another address's
/// throttled state.
#[tokio::test]
async fn enabled_throttle_does_not_affect_other_addresses() {
    let throttle = AuthFailureThrottle::new(&throttle_config(1, 60)).map(Arc::new);
    let app = router_with_provider_and_throttle(build_provider(), throttle);

    let response = request_with_peer(
        &app,
        "/whoami",
        Some(&format!("Bearer {OTHER_KEY}")),
        "203.0.113.8:1",
    )
    .await;
    assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

    // Same throttled address again: 429.
    let response = request_with_peer(
        &app,
        "/whoami",
        Some(&format!("Bearer {OTHER_KEY}")),
        "203.0.113.8:1",
    )
    .await;
    assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);

    // A different address with a valid credential still succeeds.
    let response = request_with_peer(
        &app,
        "/whoami",
        Some(&format!("Bearer {VALID_KEY}")),
        "203.0.113.9:1",
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
}

/// Successful auth neither counts against nor resets the failure window:
/// a burst of successes from an address does not itself trip the
/// throttle.
#[tokio::test]
async fn successful_auth_does_not_count_toward_the_throttle() {
    let throttle = AuthFailureThrottle::new(&throttle_config(1, 60)).map(Arc::new);
    let app = router_with_provider_and_throttle(build_provider(), throttle);

    for _ in 0..5 {
        let response = request_with_peer(
            &app,
            "/whoami",
            Some(&format!("Bearer {VALID_KEY}")),
            "203.0.113.10:1",
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
    }
}
