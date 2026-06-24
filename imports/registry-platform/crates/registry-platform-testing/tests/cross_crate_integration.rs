use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{header, HeaderValue, Method, Request, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::Router;
use registry_platform_audit::{ChainState, JsonlFileSink};
use registry_platform_httpsec::{
    body_limit_problem_response, corp_conditional, request_body_limit, security_headers,
    CorsPolicy, CspBuilder, Problem,
};
use registry_platform_httputil::FetchUrlPolicy;
use registry_platform_oidc::{
    fetch_discovery_with_policy, JwksFetcher, JwksFetcherConfig, OidcDiscoveryConfig, TokenVerifier,
};
use registry_platform_testing::{assert_chain_integrity, oidc_verifier_config, MockIdp};
use serde_json::json;
use tower::{service_fn, Layer, ServiceExt};

#[tokio::test]
async fn sample_axum_app_wires_middleware_oidc_and_audit_chain() {
    let app = Router::new()
        .route("/ok", get(|| async { "ok" }))
        .route(
            "/echo",
            post(|body: Body| async move {
                match to_bytes(body, usize::MAX).await {
                    Ok(_) => StatusCode::OK.into_response(),
                    Err(_) => body_limit_problem_response(Request::new(Body::empty())).await,
                }
            }),
        )
        .fallback(|| async {
            Problem::new("about:blank", "Not Found", StatusCode::NOT_FOUND).into_response()
        })
        .layer(
            CorsPolicy {
                allowed_origins: vec!["https://app.example.test".to_string()],
                allowed_methods: vec![Method::GET, Method::POST, Method::OPTIONS],
                allowed_headers: Vec::new(),
                allow_credentials: false,
            }
            .try_layer()
            .expect("valid CORS policy"),
        )
        .layer(corp_conditional())
        .layer(request_body_limit(4));

    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .method(Method::GET)
                .uri("/ok")
                .header(header::ORIGIN, "https://app.example.test")
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("app responds");
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        response.headers().get("cross-origin-resource-policy"),
        Some(&HeaderValue::from_static("cross-origin"))
    );

    let security_service = security_headers(CspBuilder::restrictive()).layer(service_fn(
        |_request: Request<Body>| async {
            Ok::<_, std::convert::Infallible>(
                axum::response::Response::builder()
                    .status(StatusCode::OK)
                    .body(Body::empty())
                    .expect("response builds"),
            )
        },
    ));
    let secured = security_service
        .oneshot(Request::new(Body::empty()))
        .await
        .expect("security header service responds");
    assert_eq!(
        secured.headers().get("content-security-policy"),
        Some(&CspBuilder::restrictive().header_value())
    );

    let oversized = app
        .oneshot(
            Request::builder()
                .method(Method::POST)
                .uri("/echo")
                .body(Body::from("12345"))
                .expect("request builds"),
        )
        .await
        .expect("body limit layer returns a response");
    assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(
        oversized.headers().get("content-type").unwrap(),
        "application/problem+json",
        "oversized body must receive an application/problem+json response"
    );
    let oversized_bytes = to_bytes(oversized.into_body(), 1024)
        .await
        .expect("oversized body reads");
    let oversized_value: serde_json::Value =
        serde_json::from_slice(&oversized_bytes).expect("oversized body is json");
    assert_eq!(oversized_value["status"], 413);
    assert_eq!(
        oversized_value["type"],
        "https://registry-platform.dev/problems/request/body-too-large"
    );
    assert_eq!(oversized_value["title"], "Payload Too Large");
    assert_eq!(
        oversized_value["detail"],
        "request body exceeds the configured limit"
    );

    let idp = MockIdp::start().await;
    let discovery = fetch_discovery_with_policy(
        &OidcDiscoveryConfig {
            issuer: idp.issuer(),
            jwks_uri_override: None,
            discovery_timeout: Duration::from_secs(5),
            max_doc_bytes: 16 * 1024,
        },
        &FetchUrlPolicy::dev(),
    )
    .await
    .expect("discovery fetch succeeds");
    let fetcher = Arc::new(JwksFetcher::new_with_fetch_url_policy(
        discovery.jwks_uri,
        JwksFetcherConfig {
            cache_ttl: Duration::from_secs(60),
            negative_cache_ttl: Duration::from_millis(10),
            refresh_cooldown: Duration::from_millis(10),
            max_doc_bytes: 16 * 1024,
            request_timeout: Duration::from_secs(5),
        },
        FetchUrlPolicy::dev(),
    ));
    let mut verifier_config = oidc_verifier_config(idp.issuer(), vec!["registry-api".to_string()]);
    verifier_config.allowed_clients = vec!["client-a".to_string()];
    let verifier = TokenVerifier::new(verifier_config, fetcher);
    let token = idp.mint_token(json!({
        "aud": "registry-api",
        "sub": "subject-1",
        "azp": "client-a",
        "client_id": "client-b",
        "scope": "evidence:submit",
    }));
    let verified = verifier.verify(&token).await.expect("token verifies");
    assert_eq!(verified.matched_client.as_deref(), Some("azp:client-a"));
    assert_eq!(verified.scopes, vec!["evidence:submit"]);
    idp.stop().await;

    let dir = tempfile::tempdir().expect("tempdir creates");
    let sink = JsonlFileSink::with_rotation(dir.path().join("audit.jsonl"), 0, 1);
    let chain = ChainState::bootstrap_unkeyed_dev_only(&sink)
        .await
        .expect("empty sink bootstraps");
    let first = chain
        .append(&sink, json!({ "event": "first" }))
        .await
        .expect("first audit append");
    let mut second = chain
        .append(&sink, json!({ "event": "second" }))
        .await
        .expect("second audit append");
    assert_chain_integrity(&[first.clone(), second.clone()]).expect("chain verifies");
    second.record["event"] = json!("tampered");
    assert!(assert_chain_integrity(&[first, second]).is_err());
}
