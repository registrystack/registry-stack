// SPDX-License-Identifier: Apache-2.0

//! The bounded same-key retry of an idempotency-keyed submission, against a
//! mock service that answers each request with the next scripted answer.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::Router;
use registry_messaging_client::{
    type_uri, BearerToken, MessagingClient, MessagingClientConfig, MessagingClientError,
    ProblemCode, Recipient, SubmitMessageRequest, TemplateReference, TransportKind, MESSAGES_PATH,
    MESSAGE_CANCEL_PATH,
};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use url::Url;

const TRACEPARENT: &str = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01";
const TRACE_ID: &str = "0123456789abcdef0123456789abcdef";
const MESSAGE_ID: &str = "0f8c2a51-6d3e-4b7a-9c10-2e5f7a8b9c0d";
const IDEMPOTENCY_KEY: &str = "reminder-2026-09-25-0001";

const RECEIPT: &str = concat!(
    r#"{"id":"0f8c2a51-6d3e-4b7a-9c10-2e5f7a8b9c0d","status":"queued","links":"#,
    r#"{"self":"/v1/messages/0f8c2a51-6d3e-4b7a-9c10-2e5f7a8b9c0d","#,
    r#""cancel":"/v1/messages/0f8c2a51-6d3e-4b7a-9c10-2e5f7a8b9c0d/cancel"}}"#
);

#[derive(Clone)]
struct Captured {
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
}

#[derive(Clone, Copy)]
enum Answer {
    /// Holds the request past the client's timeout, so the client cannot
    /// know whether it took effect.
    Stall,
    /// An exact product problem, with an optional `Retry-After` field.
    Problem(ProblemCode, Option<&'static str>),
    /// A JSON answer with the given status.
    Json(StatusCode, &'static str),
}

#[derive(Clone)]
struct Script {
    observations: Arc<Mutex<Vec<Captured>>>,
    answers: Arc<Mutex<VecDeque<Answer>>>,
}

impl Script {
    fn observations(&self) -> Vec<Captured> {
        self.observations.lock().expect("observations").clone()
    }
}

async fn answer(
    State(script): State<Script>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    script
        .observations
        .lock()
        .expect("observations")
        .push(Captured {
            method,
            uri,
            headers,
            body,
        });
    let next = script.answers.lock().expect("answers").pop_front();
    match next {
        Some(Answer::Stall) => {
            tokio::time::sleep(Duration::from_secs(30)).await;
            StatusCode::INTERNAL_SERVER_ERROR.into_response()
        }
        Some(Answer::Problem(code, retry_after)) => {
            let document = serde_json::json!({
                "type": type_uri(code.code()),
                "title": code.title(),
                "status": code.http_status(),
                "detail": code.detail(),
                "code": code.code(),
                "traceId": TRACE_ID,
            })
            .to_string();
            let mut headers = traced("application/problem+json");
            if let Some(seconds) = retry_after {
                headers.insert("retry-after", HeaderValue::from_static(seconds));
            }
            let status = StatusCode::from_u16(code.http_status()).expect("problem status");
            (status, headers, document).into_response()
        }
        Some(Answer::Json(status, body)) => {
            (status, traced("application/json"), body.to_owned()).into_response()
        }
        None => StatusCode::IM_A_TEAPOT.into_response(),
    }
}

fn traced(content_type: &'static str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static(content_type));
    headers.insert("traceparent", HeaderValue::from_static(TRACEPARENT));
    headers
}

/// Serve the submission and cancellation routes from one script, in request
/// order.
async fn serve(answers: &[Answer]) -> (String, Script, tokio::task::JoinHandle<()>) {
    let script = Script {
        observations: Arc::new(Mutex::new(Vec::new())),
        answers: Arc::new(Mutex::new(answers.iter().copied().collect())),
    };
    let app = Router::new()
        .route(MESSAGES_PATH, post(answer))
        .route(MESSAGE_CANCEL_PATH, post(answer))
        .with_state(script.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixture");
    let address = listener.local_addr().expect("fixture address").to_string();
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve fixture");
    });
    (address, script, server)
}

fn config(address: &str) -> MessagingClientConfig {
    MessagingClientConfig::new(Url::parse(&format!("http://{address}/")).expect("fixture URL"))
}

fn client(config: MessagingClientConfig) -> MessagingClient {
    MessagingClient::new(config).expect("client")
}

fn token() -> BearerToken {
    BearerToken::new("fixture-secret").expect("fixture token")
}

fn submission() -> SubmitMessageRequest {
    SubmitMessageRequest {
        sender_profile: "reminders-sms".to_owned(),
        to: Recipient::Phone("+15550100".to_owned()),
        template: Some(TemplateReference {
            id: "appointment-reminder".to_owned(),
            version: "1".to_owned(),
        }),
        locale: Some("en".to_owned()),
        data: Some(serde_json::json!({"time": "10:00"})),
        content: None,
        not_before: None,
        expires_at: None,
        correlation_id: Some("case-42".to_owned()),
    }
}

/// Every resend is the same request: method, route, every header, and every
/// body byte, so the service can only replay it under the same key.
fn assert_identical_resends(observations: &[Captured]) {
    let first = &observations[0];
    assert_eq!(first.headers["idempotency-key"], IDEMPOTENCY_KEY);
    for resend in &observations[1..] {
        assert_eq!(resend.method, first.method);
        assert_eq!(resend.uri, first.uri);
        assert_eq!(resend.headers, first.headers);
        assert_eq!(resend.body, first.body);
    }
}

#[tokio::test]
async fn a_timed_out_submission_is_resent_identically_under_the_same_key() {
    let (address, script, server) =
        serve(&[Answer::Stall, Answer::Json(StatusCode::ACCEPTED, RECEIPT)]).await;
    let client = client(config(&address).with_request_timeout(Duration::from_millis(500)));

    let accepted = client
        .submit(&token(), IDEMPOTENCY_KEY, &submission())
        .await
        .expect("the resend settles the submission");
    assert_eq!(accepted.value.id, MESSAGE_ID);

    let observations = script.observations();
    assert_eq!(observations.len(), 2);
    assert_identical_resends(&observations);
    server.abort();
}

#[tokio::test]
async fn a_5xx_answer_is_resent_and_the_later_receipt_returned() {
    for unavailable in [
        Answer::Problem(ProblemCode::ServiceUnavailable, None),
        Answer::Json(StatusCode::BAD_GATEWAY, r#"{"edge":true}"#),
    ] {
        let (address, script, server) =
            serve(&[unavailable, Answer::Json(StatusCode::ACCEPTED, RECEIPT)]).await;
        let accepted = client(config(&address))
            .submit(&token(), IDEMPOTENCY_KEY, &submission())
            .await
            .expect("the resend settles the submission");
        assert_eq!(accepted.value.id, MESSAGE_ID);
        let observations = script.observations();
        assert_eq!(observations.len(), 2);
        assert_identical_resends(&observations);
        server.abort();
    }
}

#[tokio::test]
async fn a_bounded_retry_after_is_honored_before_the_resend() {
    let (address, script, server) = serve(&[
        Answer::Problem(ProblemCode::ServiceUnavailable, Some("1")),
        Answer::Json(StatusCode::ACCEPTED, RECEIPT),
    ])
    .await;
    let started = Instant::now();
    client(config(&address))
        .submit(&token(), IDEMPOTENCY_KEY, &submission())
        .await
        .expect("the resend settles the submission");
    assert!(started.elapsed() >= Duration::from_secs(1));
    assert_eq!(script.observations().len(), 2);
    server.abort();
}

#[tokio::test]
async fn a_retry_after_above_the_bound_ends_the_retries() {
    let (address, script, server) = serve(&[
        Answer::Problem(ProblemCode::ServiceUnavailable, Some("60")),
        Answer::Json(StatusCode::ACCEPTED, RECEIPT),
    ])
    .await;
    let error = client(config(&address))
        .submit(&token(), IDEMPOTENCY_KEY, &submission())
        .await
        .expect_err("the service asked for a longer wait than the client makes");
    assert!(error.is_outcome_unknown());
    assert_eq!(script.observations().len(), 1);
    server.abort();
}

/// An HTTP-date, a fraction, or any other value outside delta-seconds names a
/// wait the client cannot honor, so it ends the resends like a long wait.
#[tokio::test]
async fn an_unusable_retry_after_ends_the_retries() {
    for unusable in ["Wed, 21 Oct 2026 07:28:00 GMT", "soon", "1.5"] {
        let (address, script, server) = serve(&[
            Answer::Problem(ProblemCode::ServiceUnavailable, Some(unusable)),
            Answer::Json(StatusCode::ACCEPTED, RECEIPT),
        ])
        .await;
        let error = client(config(&address))
            .submit(&token(), IDEMPOTENCY_KEY, &submission())
            .await
            .expect_err("the service asked for a wait the client cannot read");
        assert!(
            matches!(
                error,
                MessagingClientError::Problem {
                    code: ProblemCode::ServiceUnavailable,
                    ..
                }
            ),
            "{unusable}"
        );
        assert!(error.is_outcome_unknown(), "{unusable}");
        assert_eq!(script.observations().len(), 1, "{unusable}");
        server.abort();
    }
}

#[tokio::test]
async fn a_deterministic_refusal_is_never_resent() {
    for code in [
        ProblemCode::AuthenticationRefused,
        ProblemCode::ProfileNotAuthorized,
        ProblemCode::IdempotencyKeyReused,
        ProblemCode::IdempotencyExpired,
        ProblemCode::TemplateDataInvalid,
        ProblemCode::RateLimitExceeded,
    ] {
        let (address, script, server) = serve(&[
            Answer::Problem(code, Some("2")),
            Answer::Json(StatusCode::ACCEPTED, RECEIPT),
        ])
        .await;
        let error = client(config(&address))
            .submit(&token(), IDEMPOTENCY_KEY, &submission())
            .await
            .expect_err("a refusal is returned");
        assert!(
            matches!(error, MessagingClientError::Problem { code: answered, .. } if answered == code)
        );
        assert!(!error.is_outcome_unknown(), "{code:?}");
        assert_eq!(script.observations().len(), 1, "{code:?}");
        server.abort();
    }
}

#[tokio::test]
async fn the_retry_count_is_honored() {
    for (retries, expected_attempts) in [(None, 3), (Some(2), 3), (Some(1), 2)] {
        let (address, script, server) = serve(&[
            Answer::Problem(ProblemCode::ServiceUnavailable, None),
            Answer::Problem(ProblemCode::ServiceUnavailable, None),
            Answer::Problem(ProblemCode::ServiceUnavailable, None),
            Answer::Json(StatusCode::ACCEPTED, RECEIPT),
        ])
        .await;
        let mut config = config(&address);
        if let Some(retries) = retries {
            config = config.with_max_mutation_retries(retries);
        }
        let error = client(config)
            .submit(&token(), IDEMPOTENCY_KEY, &submission())
            .await
            .expect_err("every attempt was unavailable");
        assert!(matches!(
            error,
            MessagingClientError::Problem {
                status: 503,
                code: ProblemCode::ServiceUnavailable,
                ..
            }
        ));
        assert!(error.is_outcome_unknown());
        let observations = script.observations();
        assert_eq!(observations.len(), expected_attempts, "{retries:?}");
        assert_identical_resends(&observations);
        server.abort();
    }
}

#[tokio::test]
async fn zero_retries_disables_the_resend() {
    let (address, script, server) =
        serve(&[Answer::Stall, Answer::Json(StatusCode::ACCEPTED, RECEIPT)]).await;
    let error = client(
        config(&address)
            .with_request_timeout(Duration::from_millis(500))
            .with_max_mutation_retries(0),
    )
    .submit(&token(), IDEMPOTENCY_KEY, &submission())
    .await
    .expect_err("the only attempt timed out");
    assert!(matches!(
        error,
        MessagingClientError::Transport {
            kind: TransportKind::Timeout
        }
    ));
    assert!(error.is_outcome_unknown());
    assert_eq!(script.observations().len(), 1);
    server.abort();
}

#[tokio::test]
async fn an_unkeyed_cancellation_is_never_resent() {
    let (address, script, server) = serve(&[
        Answer::Problem(ProblemCode::ServiceUnavailable, None),
        Answer::Json(StatusCode::OK, RECEIPT),
    ])
    .await;
    let error = client(config(&address))
        .cancel(&token(), MESSAGE_ID)
        .await
        .expect_err("the cancellation was unavailable");
    assert!(error.is_outcome_unknown());
    assert_eq!(script.observations().len(), 1);
    server.abort();
}

#[tokio::test]
async fn a_refusal_after_an_unknown_outcome_keeps_the_outcome_unknown() {
    // Messaging authorizes and renders a replay before it looks up the key,
    // so a refusal answering the resend says nothing about the first attempt.
    for refusal in [
        ProblemCode::AuthenticationRefused,
        ProblemCode::ProfileNotAuthorized,
        ProblemCode::TemplateDataInvalid,
    ] {
        let (address, script, server) = serve(&[
            Answer::Problem(ProblemCode::ServiceUnavailable, None),
            Answer::Problem(refusal, None),
            Answer::Json(StatusCode::ACCEPTED, RECEIPT),
        ])
        .await;
        let error = client(config(&address))
            .submit(&token(), IDEMPOTENCY_KEY, &submission())
            .await
            .expect_err("the resend was refused");
        assert!(
            matches!(
                error,
                MessagingClientError::Problem {
                    status: 503,
                    code: ProblemCode::ServiceUnavailable,
                    ..
                }
            ),
            "{refusal:?}"
        );
        assert!(error.is_outcome_unknown(), "{refusal:?}");
        assert_eq!(script.observations().len(), 2, "{refusal:?}");
        server.abort();
    }
}

/// How a raw 409 answer ends after its status line, its headers, and the
/// first bytes of its declared body.
#[derive(Clone, Copy, Debug)]
enum Unfinished {
    /// The server holds the connection open, so the client's timeout
    /// elapses while it reads the body.
    Stall,
    /// The server closes the connection, so the body ends early.
    Close,
}

/// Serve a 409 problem answer whose body never arrives in full, counting
/// the requests it answers.
async fn serve_unfinished_conflict(
    ending: Unfinished,
) -> (String, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fixture");
    let address = listener.local_addr().expect("fixture address").to_string();
    let requests = Arc::new(AtomicUsize::new(0));
    let answered = Arc::clone(&requests);
    let server = tokio::spawn(async move {
        let mut held = Vec::new();
        loop {
            let (mut stream, _) = listener.accept().await.expect("accept");
            read_request(&mut stream).await;
            answered.fetch_add(1, Ordering::SeqCst);
            let head = format!(
                "HTTP/1.1 409 Conflict\r\ncontent-type: application/problem+json\r\n\
                 traceparent: {TRACEPARENT}\r\ncache-control: no-store\r\n\
                 content-length: 400\r\n\r\n{{\"type\":"
            );
            stream.write_all(head.as_bytes()).await.expect("answer");
            match ending {
                Unfinished::Stall => held.push(stream),
                Unfinished::Close => drop(stream),
            }
        }
    });
    (address, requests, server)
}

/// Read one request's head and its declared body.
async fn read_request(stream: &mut tokio::net::TcpStream) {
    let mut received = Vec::new();
    let mut chunk = [0u8; 4096];
    let head_end = loop {
        if let Some(end) = received.windows(4).position(|window| window == b"\r\n\r\n") {
            break end + 4;
        }
        let read = stream.read(&mut chunk).await.expect("read request");
        assert!(read > 0, "the request ended early");
        received.extend_from_slice(&chunk[..read]);
    };
    let head = String::from_utf8_lossy(&received[..head_end]).to_ascii_lowercase();
    let body_length: usize = head
        .lines()
        .find_map(|line| line.strip_prefix("content-length:"))
        .map_or(0, |value| value.trim().parse().expect("content length"));
    while received.len() < head_end + body_length {
        let read = stream.read(&mut chunk).await.expect("read request body");
        assert!(read > 0, "the request body ended early");
        received.extend_from_slice(&chunk[..read]);
    }
}

/// Once the status line says 4xx, the service has answered, so the request
/// is never resent. A body that then fails to arrive leaves the refusal
/// unread, so the outcome is reported as unknown, like an unparseable 4xx.
#[tokio::test]
async fn an_unreadable_4xx_answer_is_unknown_but_never_resent() {
    for (ending, expected) in [
        (Unfinished::Stall, TransportKind::Timeout),
        (Unfinished::Close, TransportKind::Exchange),
    ] {
        let (address, requests, server) = serve_unfinished_conflict(ending).await;
        let client = client(config(&address).with_request_timeout(Duration::from_millis(500)));
        let error = client
            .submit(&token(), IDEMPOTENCY_KEY, &submission())
            .await
            .expect_err("the refusal body never arrives");
        assert!(
            matches!(error, MessagingClientError::Transport { kind } if kind == expected),
            "{ending:?}: {error:?}"
        );
        assert!(error.is_outcome_unknown(), "{ending:?}");
        assert_eq!(requests.load(Ordering::SeqCst), 1, "{ending:?}");
        server.abort();
    }
}
