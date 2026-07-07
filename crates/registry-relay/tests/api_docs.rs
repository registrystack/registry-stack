// SPDX-License-Identifier: Apache-2.0
//! Tests for the `/docs` Scalar viewer and its vendored bundle.

use std::sync::Arc;

use axum::http::StatusCode;
use axum::Extension;
use axum_test::TestServer;
use registry_relay::api::docs_router;
use registry_relay::audit::{AuditPipeline, InMemorySink};
use registry_relay::auth::api_key::ApiKeyAuth;
use registry_relay::entity::EntityRegistry;
use registry_relay::server::build_app;
use serde_json::Value;

mod support;

fn server() -> TestServer {
    TestServer::new(docs_router::<()>())
}

fn full_app_server() -> TestServer {
    let config = full_app_config();
    let auth = Arc::new(ApiKeyAuth::new(Vec::new()));
    let sink: Arc<AuditPipeline> = AuditPipeline::from_sink(InMemorySink::new());
    TestServer::new(build_app(config, auth, sink).unwrap())
}

fn full_app_config() -> Arc<registry_relay::config::Config> {
    Arc::new(support::load_example_config_for_tests(
        "relay-api-docs-audit-secret-32-bytes",
    ))
}

#[tokio::test]
async fn docs_html_points_at_openapi_document_and_scalar_bundle() {
    let resp = server().get("/docs").await;

    resp.assert_status(StatusCode::OK);
    let content_type = resp
        .headers()
        .get("content-type")
        .expect("content-type header")
        .to_str()
        .expect("ascii content-type");
    assert!(
        content_type.starts_with("text/html"),
        "expected text/html, got {content_type}"
    );

    let body = resp.text();
    assert!(
        body.contains("/openapi.json"),
        "html should reference /openapi.json: {body}"
    );
    assert!(
        body.contains("/docs/scalar.js"),
        "html should load /docs/scalar.js: {body}"
    );
    assert!(
        body.contains("bearerAuth"),
        "html should pre-wire the bearerAuth scheme for Scalar: {body}"
    );
    assert!(
        body.contains("localStorage"),
        "html should persist the token in localStorage: {body}"
    );
}

#[tokio::test]
async fn docs_html_disables_caching() {
    let resp = server().get("/docs").await;

    resp.assert_status(StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("cache-control")
            .expect("cache-control header"),
        "no-store"
    );
}

#[tokio::test]
async fn docs_scalar_bundle_is_served_verbatim() {
    let resp = server().get("/docs/scalar.js").await;

    resp.assert_status(StatusCode::OK);
    assert_eq!(
        resp.headers()
            .get("content-type")
            .expect("content-type header"),
        "application/javascript; charset=utf-8"
    );
    assert_eq!(
        resp.headers()
            .get("cache-control")
            .expect("cache-control header"),
        "public, max-age=604800, immutable"
    );
    assert_eq!(
        resp.as_bytes().as_ref(),
        registry_relay::api::docs::SCALAR_BUNDLE
    );
}

#[tokio::test]
async fn docs_routes_are_public_but_openapi_json_stays_auth_gated() {
    // Locks the surface boundary: /docs and /docs/scalar.js must be
    // reachable without auth (so a browser can load the viewer cold),
    // while /openapi.json stays inside the auth-gated data-plane router.
    let server = full_app_server();

    server.get("/docs").await.assert_status(StatusCode::OK);
    server
        .get("/docs/scalar.js")
        .await
        .assert_status(StatusCode::OK);
    server
        .get("/openapi.json")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn openapi_json_can_be_moved_to_public_router_for_local_testing() {
    let mut config = (*full_app_config()).clone();
    config.server.openapi_requires_auth = false;
    let config = Arc::new(config);
    let registry = Arc::new(EntityRegistry::from_config(&config).expect("registry compiles"));
    let auth = Arc::new(ApiKeyAuth::new(Vec::new()));
    let sink: Arc<AuditPipeline> = AuditPipeline::from_sink(InMemorySink::new());
    let server = TestServer::new(
        build_app(Arc::clone(&config), auth, sink)
            .unwrap()
            .layer(Extension(registry)),
    );

    let response = server.get("/openapi.json").await;
    response.assert_status(StatusCode::OK);
    let body: Value = response.json();
    assert_eq!(body["openapi"], "3.1.0");
}
