// SPDX-License-Identifier: Apache-2.0
//! Focused route-shape tests for the admin reload API slice.

use axum::http::StatusCode;
use axum_test::TestServer;
use data_gate::api::admin_router;
use serde_json::Value;

fn server() -> TestServer {
    TestServer::new(admin_router::<()>())
}

#[tokio::test]
async fn table_reload_without_registry_returns_problem_response() {
    let resp = server()
        .post("/admin/datasets/social_registry/tables/beneficiaries/reload")
        .await;

    resp.assert_status(StatusCode::NOT_IMPLEMENTED);
    assert_eq!(resp.header("content-type"), "application/problem+json");

    let body: Value = resp.json();
    assert_eq!(body["code"], "admin.reload_unavailable");
    assert_eq!(body["status"], 501);
    assert_eq!(body["title"], "Admin reload unavailable");
    assert_eq!(
        body["detail"],
        "admin table reload route matched, but ingest registry is not installed"
    );
}

#[tokio::test]
async fn reload_all_route_exists_and_returns_explicit_501() {
    let resp = server().post("/admin/reload").await;

    resp.assert_status(StatusCode::NOT_IMPLEMENTED);
    assert_eq!(resp.header("content-type"), "application/problem+json");

    let body: Value = resp.json();
    assert_eq!(body["code"], "admin.reload_unavailable");
    assert_eq!(body["status"], 501);
    assert_eq!(
        body["detail"],
        "admin reload-all route matched, but registry-wide reload is not available"
    );
}

#[tokio::test]
async fn table_reload_requires_post() {
    let resp = server()
        .get("/admin/datasets/social_registry/tables/beneficiaries/reload")
        .await;

    resp.assert_status(StatusCode::METHOD_NOT_ALLOWED);
}
