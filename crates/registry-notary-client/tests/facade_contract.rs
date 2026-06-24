// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "json-facade")]

use std::net::SocketAddr;

use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use registry_notary_client::facade::NotaryClientHandle;
use registry_notary_client::{PortableErrorKind, RegistryNotaryClient};
use registry_notary_core::FORMAT_CLAIM_RESULT_JSON;
use serde_json::json;
use tokio::net::TcpListener;

#[tokio::test]
async fn facade_accepts_canonical_snake_case_json() {
    let app = Router::new().route("/v1/evaluations", post(evaluate_handler));
    let base = spawn(app).await;
    let client = RegistryNotaryClient::builder(base)
        .bearer_token("bearer-secret")
        .default_purpose("benefits")
        .build()
        .expect("client builds");
    let handle = NotaryClientHandle::new(client);

    let response = handle
        .evaluate_json(
            json!({
                "target": {
                    "type": "Person",
                    "identifiers": [{ "scheme": "NATIONAL_ID", "value": "subject-1" }]
                },
                "claims": ["claim-a"]
            }),
            json!({}),
        )
        .await
        .expect("facade evaluate succeeds");

    assert_eq!(response, json!({ "results": [] }));
}

#[tokio::test]
async fn facade_core_methods_share_typed_validation_and_wire_shape() {
    let app = Router::new()
        .route("/v1/batch-evaluations", post(batch_handler))
        .route(
            "/v1/evaluations/{evaluation_id}/render",
            post(render_handler),
        )
        .route("/v1/credentials", post(issue_handler))
        .route(
            "/v1/claims",
            get(|| async { Json(json!({ "data": [{ "id": "claim-a" }] })) }),
        )
        .route(
            "/v1/claims/claim-a",
            get(|| async { Json(json!({ "id": "claim-a" })) }),
        )
        .route(
            "/v1/credentials/cred-1/status",
            get(|| async { Json(credential_status("valid")) }),
        );
    let base = spawn(app).await;
    let client = RegistryNotaryClient::builder(base)
        .default_purpose("benefits")
        .build()
        .expect("client builds");
    let handle = NotaryClientHandle::new(client);

    let batch = handle
        .batch_evaluate_json(
            json!({
                "items": [{
                    "target": {
                        "type": "Person",
                        "identifiers": [{ "scheme": "NATIONAL_ID", "value": "subject-1" }]
                    }
                }],
                "claims": ["claim-a"]
            }),
            json!({ "idempotency_key": "batch-key" }),
        )
        .await
        .expect("facade batch succeeds");
    let rendered = handle
        .render_json(
            json!({ "evaluation_id": "eval-1", "format": FORMAT_CLAIM_RESULT_JSON }),
            json!({}),
        )
        .await
        .expect("facade render succeeds");
    let issued = handle
        .issue_credential_json(json!({ "evaluation_id": "eval-1" }), json!({}))
        .await
        .expect("facade issue succeeds");
    let claims = handle
        .list_claims_json(json!({}))
        .await
        .expect("facade list claims succeeds");
    let claim = handle
        .get_claim_json("claim-a".to_string(), json!({}))
        .await
        .expect("facade get claim succeeds");
    let status = handle
        .credential_status_json("cred-1".to_string(), json!({}))
        .await
        .expect("facade credential status succeeds");

    assert_eq!(batch["batch_id"], "batch-1");
    assert_eq!(rendered["rendered"], true);
    assert_eq!(issued["credential_id"], "cred-1");
    assert_eq!(claims["data"][0]["id"], "claim-a");
    assert_eq!(claim["id"], "claim-a");
    assert_eq!(status["status"], "valid");
}

#[tokio::test]
async fn facade_error_excludes_detail() {
    let app = Router::new().route("/v1/claims", get(problem_handler));
    let base = spawn(app).await;
    let client = RegistryNotaryClient::builder(base)
        .bearer_token("bearer-secret")
        .build()
        .expect("client builds");
    let handle = NotaryClientHandle::new(client);

    let error = handle
        .list_claims_json(json!({}))
        .await
        .expect_err("problem maps to portable error");

    assert_eq!(error.kind, PortableErrorKind::Problem);
    assert_eq!(error.status, Some(404));
    assert_eq!(error.code.as_deref(), Some("target.not_found"));
    assert_eq!(error.title, "Target not found");
    let rendered = serde_json::to_value(&error).expect("portable error serializes");
    assert!(rendered.get("detail").is_none());
}

async fn evaluate_handler(headers: HeaderMap) -> Response {
    assert_eq!(
        headers
            .get("data-purpose")
            .and_then(|value| value.to_str().ok()),
        Some("benefits")
    );
    assert_eq!(
        headers.get("accept").and_then(|value| value.to_str().ok()),
        Some(FORMAT_CLAIM_RESULT_JSON)
    );
    Json(json!({ "results": [] })).into_response()
}

async fn batch_handler(headers: HeaderMap) -> Response {
    assert_eq!(
        headers
            .get("idempotency-key")
            .and_then(|value| value.to_str().ok()),
        Some("batch-key")
    );
    Json(json!({
        "batch_id": "batch-1",
        "status": "completed",
        "claims": ["claim-a"],
        "items": [],
        "summary": { "succeeded": 0, "failed": 0 }
    }))
    .into_response()
}

async fn render_handler() -> Response {
    Json(json!({ "rendered": true })).into_response()
}

async fn issue_handler() -> Response {
    Json(json!({
        "credential_id": "cred-1",
        "credential_profile": "profile-1",
        "format": "application/dc+sd-jwt",
        "issuer": "did:web:notary.example",
        "expires_at": "2026-05-29T00:00:00Z",
        "credential": "issuer.jwt~disclosure~",
        "issuer_signed_jwt": "issuer.jwt",
        "disclosures": ["disclosure"]
    }))
    .into_response()
}

fn credential_status(status: &str) -> serde_json::Value {
    json!({
        "credential_id": "cred-1",
        "issuer": "did:web:notary.example",
        "credential_profile": "profile-1",
        "status": status,
        "issued_at": "2026-05-29T00:00:00Z",
        "expires_at": "2026-05-30T00:00:00Z",
        "updated_at": "2026-05-29T01:00:00Z"
    })
}

async fn problem_handler() -> Response {
    (
        StatusCode::NOT_FOUND,
        [("content-type", "application/problem+json")],
        Json(json!({
            "type": "https://docs.registry-notary.dev/problems/target/not-found",
            "title": "Target not found",
            "status": 404,
            "detail": "target identifier subj-sensitive was not found",
            "code": "target.not_found"
        })),
    )
        .into_response()
}

async fn spawn(app: Router) -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test server binds");
    let addr: SocketAddr = listener.local_addr().expect("local addr available");
    tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("test server serves");
    });
    format!("http://{addr}")
}
