// SPDX-License-Identifier: Apache-2.0
use axum::{
    body::Body,
    extract::State,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Router,
};
use base64::Engine as _;
use registry_render_client::{BearerToken, RenderClient, RenderClientConfig};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
const TRACE: &str = "1234567890abcdef1234567890abcdef";

async fn fixture(
    State((status, body)): State<(u16, Value)>,
    headers: HeaderMap,
    input: String,
) -> Response {
    assert_eq!(headers["authorization"], "Bearer canary-render-token");
    assert_eq!(headers["accept"], "application/json");
    assert_eq!(
        serde_json::from_str::<Value>(&input).unwrap()["issuedAt"],
        "2026-10-23T00:00:00Z"
    );
    let mut response = (
        StatusCode::from_u16(status).unwrap(),
        Body::from(serde_json::to_vec(&body).unwrap()),
    )
        .into_response();
    response.headers_mut().insert(
        "content-type",
        if status == 200 {
            "application/json"
        } else {
            "application/problem+json"
        }
        .parse()
        .unwrap(),
    );
    response.headers_mut().insert(
        "traceparent",
        format!("00-{TRACE}-1234567890abcdef-01").parse().unwrap(),
    );
    response
}
async fn client(status: u16, body: Value) -> (RenderClient, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("http://{}", listener.local_addr().unwrap());
    let app = Router::new()
        .route("/v1/render/receipt", post(fixture))
        .with_state((status, body));
    let task = tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    (
        RenderClient::new(RenderClientConfig::new(base)).unwrap(),
        task,
    )
}
fn request() -> Value {
    json!({"issuedAt":"2026-10-23T00:00:00Z","data":{"number":"R-1"}})
}
#[tokio::test]
async fn one_authenticated_document_and_integrity_refusal() {
    let pdf = b"%PDF-fixture";
    let mut body = json!({"pdfBase64":base64::engine::general_purpose::STANDARD.encode(pdf),"pdfSha256":hex::encode(Sha256::digest(pdf)),"dataSha256":"0".repeat(64),"documentVersion":"receipt v1","warnings":[]});
    let (client, task) = client(200, body.clone()).await;
    let result = client
        .render(
            &BearerToken::new("canary-render-token").unwrap(),
            "receipt",
            &request(),
        )
        .await
        .unwrap();
    assert_eq!(result.document_version, "receipt v1");
    task.abort();
    body["pdfSha256"] = json!("f".repeat(64));
    let (client, task) = self::client(200, body).await;
    assert_eq!(
        client
            .render(
                &BearerToken::new("canary-render-token").unwrap(),
                "receipt",
                &request()
            )
            .await
            .unwrap_err()
            .kind,
        "protocol"
    );
    task.abort();
}
#[tokio::test]
async fn bounded_product_problem_matches_status_and_trace() {
    let body = json!({"type":"https://render.registrystack.org/problems/unauthorized","title":"unauthorized","status":401,"detail":"Credential refused","code":"render.unauthorized","traceId":TRACE,"pointers":[]});
    let (client, task) = client(401, body.clone()).await;
    let error = client
        .render(
            &BearerToken::new("canary-render-token").unwrap(),
            "receipt",
            &request(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.code.as_deref(), Some("render.unauthorized"));
    assert_eq!(error.status, Some(401));
    task.abort();
    let mut invalid = body;
    invalid["traceId"] = json!("f".repeat(32));
    let (client, task) = self::client(401, invalid).await;
    assert_eq!(
        client
            .render(
                &BearerToken::new("canary-render-token").unwrap(),
                "receipt",
                &request()
            )
            .await
            .unwrap_err()
            .kind,
        "protocol"
    );
    task.abort();
}
#[test]
fn invalid_destination_and_arguments_are_local_and_value_free() {
    let error = RenderClient::new(RenderClientConfig::new("http://canary-secret@example.test"))
        .unwrap_err();
    assert!(!format!("{error:?}").contains("canary-secret"));
    for id in ["../receipt", "receipt/other", "receipt?x=1", ""] {
        assert!(RenderClient::validate_request(id, &request()).is_err());
    }
    assert!(RenderClient::validate_request("receipt", &json!({"data":{}})).is_err());
}

#[test]
fn known_request_refusals_are_local_before_token_acquisition() {
    for value in [
        json!({"issuedAt":"not-a-date","data":{}}),
        json!({"issuedAt":"2026-10-23T00:00:00Z","data":{},"assets":{"../private":"AAAA"}}),
        json!({"issuedAt":"2026-10-23T00:00:00Z","data":{},"assets":{"photo":"not-base64"}}),
        json!({"issuedAt":"2026-10-23T00:00:00Z","data":{},"assets":{"photo":"aGVsbG8="}}),
        json!({"issuedAt":"2026-10-23T00:00:00Z","data":{},"assets":{"photo":42}}),
    ] {
        assert!(
            RenderClient::validate_request("receipt", &value).is_err(),
            "known malformed request accepted"
        );
    }
    let mut png = vec![0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a];
    png.resize(1024 * 1024, 0);
    let accepted = json!({"issuedAt":"2026-10-23T00:00:00+01:00","data":{},"assets":{"photo":base64::engine::general_purpose::STANDARD.encode(&png)}});
    assert!(
        RenderClient::validate_request("receipt", &accepted)
            .unwrap()
            .len()
            > 1024 * 1024
    );
    png.resize(2 * 1024 * 1024 + 1, 0);
    let oversized = json!({"issuedAt":"2026-10-23T00:00:00Z","data":{},"assets":{"photo":base64::engine::general_purpose::STANDARD.encode(&png)}});
    assert!(RenderClient::validate_request("receipt", &oversized).is_err());
}

#[tokio::test]
async fn document_version_is_bound_to_the_requested_document_and_unsigned_version() {
    let pdf = b"%PDF-fixture";
    for version in [
        "another v1",
        "receipt v-1",
        "receipt v4294967296",
        "arbitrary",
    ] {
        let body = json!({"pdfBase64":base64::engine::general_purpose::STANDARD.encode(pdf),"pdfSha256":hex::encode(Sha256::digest(pdf)),"dataSha256":"0".repeat(64),"documentVersion":version,"warnings":[]});
        let (client, task) = client(200, body).await;
        assert_eq!(
            client
                .render(
                    &BearerToken::new("canary-render-token").unwrap(),
                    "receipt",
                    &request()
                )
                .await
                .unwrap_err()
                .kind,
            "protocol"
        );
        task.abort();
    }
}

#[tokio::test]
async fn refused_connection_exposes_transport_kind_and_no_completed_exchange() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let client = RenderClient::new(RenderClientConfig::new(origin)).unwrap();
    let error = client
        .render(
            &BearerToken::new("canary-render-token").unwrap(),
            "receipt",
            &request(),
        )
        .await
        .unwrap_err();
    let value = serde_json::to_value(error).unwrap();
    assert_eq!(value["transportKind"], "connect");
    assert_eq!(value["outcomeUnknown"], false);
}

#[tokio::test]
async fn incomplete_response_exposes_an_uncertain_exchange_without_retry() {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut bytes = [0; 4096];
        assert!(socket.read(&mut bytes).await.unwrap() > 0);
        socket.write_all(format!("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 10000\r\ntraceparent: 00-{TRACE}-1234567890abcdef-01\r\nConnection: close\r\n\r\n{{}}" ).as_bytes()).await.unwrap();
    });
    let client = RenderClient::new(RenderClientConfig::new(origin)).unwrap();
    let error = client
        .render(
            &BearerToken::new("canary-render-token").unwrap(),
            "receipt",
            &request(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind, "transport");
    assert!(error.outcome_unknown);
    assert_eq!(
        error.transport_kind,
        Some(registry_render_client::TransportKind::Exchange)
    );
    task.await.unwrap();
}

#[tokio::test]
async fn server_pointer_budget_remains_a_typed_problem() {
    // A 256-character pointer can occupy 1,021 UTF-8 bytes. The real server
    // permits 32 such pointers, so a legitimate refusal exceeds 16 KiB.
    let pointer = format!("/{}", "😀".repeat(255));
    let body = json!({"type":"https://render.registrystack.org/problems/data-invalid","title":"data-invalid","status":400,"detail":"The render request was refused","code":"render.data-invalid","traceId":TRACE,"pointers":vec![pointer;32]});
    assert!(serde_json::to_vec(&body).unwrap().len() > 16 * 1024);
    let (client, task) = client(400, body).await;
    let error = client
        .render(
            &BearerToken::new("canary-render-token").unwrap(),
            "receipt",
            &request(),
        )
        .await
        .unwrap_err();
    assert_eq!(error.kind, "problem");
    assert_eq!(error.code.as_deref(), Some("render.data-invalid"));
    assert_eq!(error.status, Some(400));
    assert!(!error.outcome_unknown);
    task.abort();
}
