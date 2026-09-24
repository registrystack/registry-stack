// SPDX-License-Identifier: Apache-2.0

//! The client against an in-process HTTP fixture: the typed answers it
//! surfaces, and every way a response can fall outside the pinned contract.

use std::sync::{Arc, Mutex};

use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, Uri};
use axum::response::IntoResponse;
use axum::routing::get;
use axum::Router;
use registry_messaging_client::{
    type_uri, MessagingClient, MessagingClientConfig, MessagingClientError,
    MessagingProtocolFailure, ProblemCode, TransportKind, HEALTH_PATH, READY_PATH,
};
use url::Url;

const TRACEPARENT: &str = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01";
const TRACE_ID: &str = "0123456789abcdef0123456789abcdef";

/// One route's canned answer, plus the record of every request it received.
#[derive(Clone)]
struct Fixture {
    seen: Arc<Mutex<Vec<(String, HeaderMap)>>>,
    status: StatusCode,
    content_type: Option<&'static str>,
    body: String,
    traced: bool,
}

impl Fixture {
    fn new(status: StatusCode, content_type: Option<&'static str>, body: &str) -> Self {
        Self {
            seen: Arc::default(),
            status,
            content_type,
            body: body.to_owned(),
            traced: true,
        }
    }

    fn empty_ok() -> Self {
        Self::new(StatusCode::OK, None, "")
    }

    fn problem(code: ProblemCode) -> Self {
        Self::new(
            StatusCode::from_u16(code.http_status()).expect("a pinned status"),
            Some("application/problem+json"),
            &problem_body(code.code(), code.http_status()),
        )
    }

    fn untraced(mut self) -> Self {
        self.traced = false;
        self
    }
}

fn problem_body(code: &str, status: u16) -> String {
    let pinned = ProblemCode::from_code(code);
    format!(
        r#"{{"type":"{}","title":"{}","status":{status},"detail":"{}","code":"{code}","traceId":"{TRACE_ID}"}}"#,
        type_uri(code),
        pinned.map_or("Unknown", ProblemCode::title),
        pinned.map_or("Unknown.", ProblemCode::detail),
    )
}

async fn answer(State(fixture): State<Fixture>, uri: Uri, headers: HeaderMap) -> impl IntoResponse {
    fixture
        .seen
        .lock()
        .expect("observations")
        .push((uri.to_string(), headers));
    let mut response = HeaderMap::new();
    if let Some(content_type) = fixture.content_type {
        response.insert("content-type", HeaderValue::from_static(content_type));
    }
    if fixture.traced {
        response.insert("traceparent", HeaderValue::from_static(TRACEPARENT));
    }
    (fixture.status, response, fixture.body)
}

async fn serve(prefix: &str, fixture: &Fixture) -> (MessagingClient, tokio::task::JoinHandle<()>) {
    let app = Router::new()
        .route(&format!("{prefix}{HEALTH_PATH}"), get(answer))
        .route(&format!("{prefix}{READY_PATH}"), get(answer))
        .with_state(fixture.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixture");
    let address = listener.local_addr().expect("fixture address");
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve fixture");
    });
    let client = MessagingClient::new(MessagingClientConfig::new(
        Url::parse(&format!("http://{address}{prefix}/")).expect("fixture URL"),
    ))
    .expect("client");
    (client, server)
}

#[tokio::test]
async fn health_and_ready_answer_with_the_trace_and_send_no_credential() {
    let fixture = Fixture::empty_ok();
    let (client, server) = serve("", &fixture).await;

    let health = client.health().await.expect("health");
    assert_eq!(health.trace_id, TRACE_ID);
    let ready = client.ready().await.expect("ready");
    assert_eq!(ready.trace_id, TRACE_ID);

    let seen = fixture.seen.lock().expect("observations");
    let paths: Vec<&str> = seen.iter().map(|(path, _)| path.as_str()).collect();
    assert_eq!(paths, [HEALTH_PATH, READY_PATH]);
    assert!(seen
        .iter()
        .all(|(_, headers)| !headers.contains_key("authorization")));
    server.abort();
}

#[tokio::test]
async fn a_deployment_prefix_is_kept() {
    let fixture = Fixture::empty_ok();
    let (client, server) = serve("/messaging", &fixture).await;
    client.ready().await.expect("ready under a prefix");
    assert_eq!(
        fixture.seen.lock().expect("observations")[0].0,
        format!("/messaging{READY_PATH}")
    );
    server.abort();
}

#[tokio::test]
async fn a_runtime_that_is_not_ready_is_the_typed_service_unavailable() {
    let (client, server) = serve("", &Fixture::problem(ProblemCode::ServiceUnavailable)).await;
    match client.ready().await {
        Err(MessagingClientError::Problem {
            status: 503,
            code: ProblemCode::ServiceUnavailable,
            trace_id,
        }) => assert_eq!(trace_id.as_deref(), Some(TRACE_ID)),
        other => panic!("expected the typed service.unavailable problem, got {other:?}"),
    }
    server.abort();
}

#[tokio::test]
async fn a_problem_outside_the_closed_vocabulary_is_a_protocol_failure() {
    let fixture = Fixture::new(
        StatusCode::SERVICE_UNAVAILABLE,
        Some("application/problem+json"),
        &problem_body("service.overloaded", 503),
    );
    let (client, server) = serve("", &fixture).await;
    assert!(matches!(
        client.ready().await,
        Err(MessagingClientError::Protocol {
            status: 503,
            failure: MessagingProtocolFailure::Problem,
            ..
        })
    ));
    server.abort();
}

#[tokio::test]
async fn a_failure_that_is_not_a_problem_document_is_a_protocol_failure() {
    let fixture = Fixture::new(
        StatusCode::BAD_GATEWAY,
        Some("text/html"),
        "<html>bad gateway</html>",
    );
    let (client, server) = serve("", &fixture).await;
    assert!(matches!(
        client.health().await,
        Err(MessagingClientError::Protocol {
            status: 502,
            failure: MessagingProtocolFailure::Status,
            ..
        })
    ));
    server.abort();
}

#[tokio::test]
async fn a_success_with_a_body_is_a_protocol_failure() {
    let (client, server) = serve("", &Fixture::new(StatusCode::OK, None, "x")).await;
    assert!(matches!(
        client.health().await,
        Err(MessagingClientError::Protocol {
            status: 200,
            failure: MessagingProtocolFailure::Body,
            ..
        })
    ));
    server.abort();
}

#[tokio::test]
async fn a_success_without_trace_context_is_a_protocol_failure() {
    let (client, server) = serve("", &Fixture::empty_ok().untraced()).await;
    assert!(matches!(
        client.health().await,
        Err(MessagingClientError::Protocol {
            status: 200,
            failure: MessagingProtocolFailure::TraceContext,
            trace_id: None,
        })
    ));
    server.abort();
}

#[tokio::test]
async fn an_oversized_problem_stays_bounded() {
    let fixture = Fixture::new(
        StatusCode::SERVICE_UNAVAILABLE,
        Some("application/problem+json"),
        &"x".repeat(64 * 1024),
    );
    let (client, server) = serve("", &fixture).await;
    assert!(matches!(
        client.ready().await,
        Err(MessagingClientError::Transport {
            kind: TransportKind::ResponseTooLarge,
        })
    ));
    server.abort();
}

#[tokio::test]
async fn an_unreachable_service_is_a_transport_failure() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("a loopback port");
    let address = listener.local_addr().expect("the bound address");
    drop(listener);
    let client = MessagingClient::new(MessagingClientConfig::new(
        Url::parse(&format!("http://{address}/")).expect("fixture URL"),
    ))
    .expect("client");
    assert!(matches!(
        client.health().await,
        Err(MessagingClientError::Transport { .. })
    ));
}

#[test]
fn an_unprotected_remote_base_url_is_refused_before_any_client_exists() {
    let refused = MessagingClient::new(MessagingClientConfig::new(
        Url::parse("http://messaging.example.invalid/").expect("fixture URL"),
    ));
    assert!(matches!(
        refused,
        Err(MessagingClientError::Configuration { .. })
    ));
}
