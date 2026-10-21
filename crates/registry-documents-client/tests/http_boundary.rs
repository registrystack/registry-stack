// SPDX-License-Identifier: Apache-2.0

//! The client against a local fixture server: a healthy answer, a typed
//! problem, and every way an answer can break the pinned contract.

use axum::http::{header::CONTENT_TYPE, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::Router;
use registry_documents_client::{
    type_uri, DocumentsClient, DocumentsClientConfig, DocumentsClientError,
    DocumentsProtocolFailure, ProblemCode, HEALTH_PATH,
};

const TRACE_ID: &str = "0af7651916cd43dd8448eb211c80319c";
const TRACEPARENT: &str = "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01";

async fn client_for(answer: fn() -> Response) -> (DocumentsClient, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("a loopback listener");
    let address = listener.local_addr().expect("the listener address");
    let app = Router::new().route(HEALTH_PATH, get(move || async move { answer() }));
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("the fixture server");
    });
    let url = url::Url::parse(&format!("http://{address}/")).expect("a fixture URL");
    let client = DocumentsClient::new(DocumentsClientConfig::new(url)).expect("a client");
    (client, server)
}

fn problem(code: ProblemCode, status: u16, trace: &str) -> Response {
    let body = serde_json::json!({
        "type": type_uri(code.code()),
        "title": code.title(),
        "status": status,
        "detail": code.detail(),
        "code": code.code(),
        "traceId": trace,
    });
    (
        StatusCode::from_u16(status).unwrap(),
        [
            (CONTENT_TYPE, "application/problem+json"),
            (
                axum::http::header::HeaderName::from_static("traceparent"),
                TRACEPARENT,
            ),
        ],
        body.to_string(),
    )
        .into_response()
}

#[tokio::test]
async fn a_healthy_answer_carries_its_trace() {
    let (client, server) =
        client_for(|| ([("traceparent", TRACEPARENT)], StatusCode::OK).into_response()).await;
    let complete = client.health().await.expect("a healthy answer");
    assert_eq!(complete.trace_id, TRACE_ID);
    server.abort();
}

#[tokio::test]
async fn a_pinned_problem_is_surfaced_as_its_typed_code() {
    let (client, server) =
        client_for(|| problem(ProblemCode::ServiceUnavailable, 503, TRACE_ID)).await;
    let error = client.health().await.unwrap_err();
    assert!(
        matches!(
            error,
            DocumentsClientError::Problem {
                status: 503,
                code: ProblemCode::ServiceUnavailable,
                ..
            }
        ),
        "{error:?}"
    );
    server.abort();
}

#[tokio::test]
async fn a_problem_whose_status_disagrees_with_its_code_is_a_protocol_failure() {
    let (client, server) =
        client_for(|| problem(ProblemCode::RequestNotFound, 503, TRACE_ID)).await;
    let error = client.health().await.unwrap_err();
    assert!(
        matches!(
            error,
            DocumentsClientError::Protocol {
                failure: DocumentsProtocolFailure::Problem,
                ..
            }
        ),
        "{error:?}"
    );
    server.abort();
}

#[tokio::test]
async fn a_problem_whose_trace_disagrees_is_a_protocol_failure() {
    let (client, server) = client_for(|| {
        problem(
            ProblemCode::ServiceUnavailable,
            503,
            "11111111111111111111111111111111",
        )
    })
    .await;
    let error = client.health().await.unwrap_err();
    assert!(
        matches!(
            error,
            DocumentsClientError::Protocol {
                failure: DocumentsProtocolFailure::Problem,
                ..
            }
        ),
        "{error:?}"
    );
    server.abort();
}

#[tokio::test]
async fn a_failure_that_is_not_a_problem_is_a_protocol_failure() {
    let (client, server) = client_for(|| {
        (
            StatusCode::BAD_GATEWAY,
            [("traceparent", TRACEPARENT)],
            "upstream",
        )
            .into_response()
    })
    .await;
    let error = client.health().await.unwrap_err();
    assert!(
        matches!(
            error,
            DocumentsClientError::Protocol {
                failure: DocumentsProtocolFailure::Status,
                ..
            }
        ),
        "{error:?}"
    );
    server.abort();
}

#[tokio::test]
async fn a_healthy_answer_without_a_trace_is_a_protocol_failure() {
    let (client, server) = client_for(|| StatusCode::OK.into_response()).await;
    let error = client.health().await.unwrap_err();
    assert!(
        matches!(
            error,
            DocumentsClientError::Protocol {
                failure: DocumentsProtocolFailure::TraceContext,
                ..
            }
        ),
        "{error:?}"
    );
    server.abort();
}

#[tokio::test]
async fn a_healthy_answer_with_a_body_is_a_protocol_failure() {
    let (client, server) =
        client_for(|| (StatusCode::OK, [("traceparent", TRACEPARENT)], "ok").into_response()).await;
    let error = client.health().await.unwrap_err();
    assert!(
        matches!(
            error,
            DocumentsClientError::Protocol {
                failure: DocumentsProtocolFailure::Body,
                ..
            }
        ),
        "{error:?}"
    );
    server.abort();
}
