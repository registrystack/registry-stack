// SPDX-License-Identifier: Apache-2.0

//! The bounded same-key retry of an idempotency-keyed mutation, against a
//! mock service that answers each request with the next scripted answer.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri};
use axum::response::{IntoResponse, Response};
use axum::routing::any;
use axum::Router;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use registry_breg_client::{
    BRegIdempotencyKey, BRegProblemCode, BRegReleaseStatus, BaseRegistryClient,
    BaseRegistryClientConfig, BaseRegistryClientError, StaticToken, TransportKind, Uuid,
};
use sha2::{Digest, Sha256};
use url::Url;

const TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";
const TRACE_ID: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
const IDEMPOTENCY_KEY: &str = "publish-2026-09-0001";
const PUBLISHED: &str = r#"{"dataset":"enrolments","version":1}"#;
const RUN_ID: &str = "00000000-0000-4000-8000-000000000001";

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
    Problem(BRegProblemCode, Option<&'static str>),
    /// A JSON answer with the given status and no product contract headers.
    Json(StatusCode, &'static str),
    /// The statistics publication the service answers on success.
    Published,
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
            let mut document = serde_json::json!({
                "type": format!(
                    "https://id.registrystack.org/problems/registry-breg/{}",
                    code.code().replace('.', "/")
                ),
                "title": problem_title(code.status()),
                "status": code.status(),
                "detail": code.detail(),
                "code": code.code(),
                "traceId": TRACE_ID,
            });
            if code == BRegProblemCode::StatisticalDatasetReleaseRefused {
                document["refusalCode"] = serde_json::json!("period-not-ended");
            }
            let mut headers = traced("application/problem+json");
            headers.insert("cache-control", HeaderValue::from_static("no-store"));
            if let Some(seconds) = retry_after {
                headers.insert("retry-after", HeaderValue::from_static(seconds));
            }
            let status = StatusCode::from_u16(code.status()).expect("problem status");
            (status, headers, document.to_string()).into_response()
        }
        Some(Answer::Json(status, body)) => {
            (status, traced("application/json"), body.to_owned()).into_response()
        }
        Some(Answer::Published) => {
            let mut headers = traced("application/json");
            headers.insert("cache-control", HeaderValue::from_static("no-store"));
            headers.insert("vary", HeaderValue::from_static("authorization, accept"));
            let digest = format!(
                "sha-256=:{}:",
                STANDARD.encode(Sha256::digest(PUBLISHED.as_bytes()))
            );
            headers.insert(
                "repr-digest",
                HeaderValue::from_str(&digest).expect("digest header"),
            );
            (StatusCode::CREATED, headers, PUBLISHED).into_response()
        }
        None => StatusCode::IM_A_TEAPOT.into_response(),
    }
}

fn problem_title(status: u16) -> &'static str {
    match status {
        401 => "Unauthorized",
        409 => "Conflict",
        410 => "Gone",
        422 => "Unprocessable Entity",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => panic!("unscripted problem status"),
    }
}

fn traced(content_type: &'static str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert("content-type", HeaderValue::from_static(content_type));
    headers.insert("traceparent", HeaderValue::from_static(TRACEPARENT));
    headers
}

/// Serve every route from one script, in request order.
async fn serve(answers: &[Answer]) -> (String, Script, tokio::task::JoinHandle<()>) {
    let script = Script {
        observations: Arc::new(Mutex::new(Vec::new())),
        answers: Arc::new(Mutex::new(answers.iter().copied().collect())),
    };
    let app = Router::new()
        .fallback(any(answer))
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

fn config(address: &str) -> BaseRegistryClientConfig {
    BaseRegistryClientConfig::new(
        Url::parse(&format!("http://{address}/tenant")).expect("fixture URL"),
    )
    .with_token_provider(Arc::new(
        StaticToken::new("fixture-secret").expect("fixture token"),
    ))
}

fn client(config: BaseRegistryClientConfig) -> BaseRegistryClient {
    BaseRegistryClient::new(config).expect("client")
}

fn key() -> BRegIdempotencyKey {
    BRegIdempotencyKey::parse(IDEMPOTENCY_KEY).expect("fixture key")
}

async fn publish(
    client: &BaseRegistryClient,
) -> Result<
    registry_breg_client::BRegComplete<registry_breg_client::BRegRawDocument>,
    BaseRegistryClientError,
> {
    client
        .statistics_publish(
            "enrolments",
            "2026-09",
            BRegReleaseStatus::Final,
            "publisher",
            &key(),
        )
        .await
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
async fn a_timed_out_mutation_is_resent_identically_under_the_same_key() {
    let (address, script, server) = serve(&[Answer::Stall, Answer::Published]).await;
    let client = client(config(&address).with_request_timeout(Duration::from_millis(500)));

    let published = publish(&client)
        .await
        .expect("the resend settles the publication");
    assert_eq!(published.value.as_bytes(), PUBLISHED.as_bytes());

    let observations = script.observations();
    assert_eq!(observations.len(), 2);
    assert_identical_resends(&observations);
    server.abort();
}

#[tokio::test]
async fn a_5xx_answer_is_resent_and_the_later_result_returned() {
    for unavailable in [
        Answer::Problem(BRegProblemCode::ServiceUnavailable, None),
        Answer::Problem(BRegProblemCode::ActionEvidenceFailed, None),
        Answer::Problem(BRegProblemCode::RequestTimeout, None),
        Answer::Json(StatusCode::BAD_GATEWAY, r#"{"edge":true}"#),
    ] {
        let (address, script, server) = serve(&[unavailable, Answer::Published]).await;
        let published = publish(&client(config(&address)))
            .await
            .expect("the resend settles the publication");
        assert_eq!(published.value.as_bytes(), PUBLISHED.as_bytes());
        let observations = script.observations();
        assert_eq!(observations.len(), 2);
        assert_identical_resends(&observations);
        server.abort();
    }
}

#[tokio::test]
async fn a_bounded_retry_after_is_honored_before_the_resend() {
    let (address, script, server) = serve(&[
        Answer::Problem(BRegProblemCode::ServiceUnavailable, Some("1")),
        Answer::Published,
    ])
    .await;
    let started = Instant::now();
    publish(&client(config(&address)))
        .await
        .expect("the resend settles the publication");
    assert!(started.elapsed() >= Duration::from_secs(1));
    assert_eq!(script.observations().len(), 2);
    server.abort();
}

#[tokio::test]
async fn a_retry_after_above_the_bound_ends_the_retries() {
    let (address, script, server) = serve(&[
        Answer::Problem(BRegProblemCode::ServiceUnavailable, Some("60")),
        Answer::Published,
    ])
    .await;
    let error = publish(&client(config(&address)))
        .await
        .expect_err("the service asked for a longer wait than the client makes");
    assert!(error.is_outcome_unknown());
    assert_eq!(script.observations().len(), 1);
    server.abort();
}

#[tokio::test]
async fn a_deterministic_refusal_is_never_resent() {
    for code in [
        BRegProblemCode::AuthenticationRefused,
        BRegProblemCode::IdempotencyConflict,
        BRegProblemCode::StatisticalDatasetVersionConflict,
        BRegProblemCode::StatisticalDatasetReleaseRefused,
    ] {
        let (address, script, server) =
            serve(&[Answer::Problem(code, Some("2")), Answer::Published]).await;
        let error = publish(&client(config(&address)))
            .await
            .expect_err("a refusal is returned");
        assert_eq!(error.problem_code(), Some(code));
        assert!(!error.is_outcome_unknown(), "{code}");
        assert_eq!(script.observations().len(), 1, "{code}");
        server.abort();
    }
}

/// The engine returns these two typed 5xx codes only with the attempt rolled
/// back, and a resend would meet the same failure, so the outcome is known.
/// The classification follows the code, whichever keyed route answers it.
#[tokio::test]
async fn a_5xx_failure_the_engine_rolls_back_is_known_and_never_resent() {
    for code in [
        BRegProblemCode::ActionHandlerFailed,
        BRegProblemCode::StatisticalDatasetDomainViolation,
    ] {
        let (address, script, server) =
            serve(&[Answer::Problem(code, None), Answer::Published]).await;
        let error = publish(&client(config(&address)))
            .await
            .expect_err("the rolled-back failure is returned");
        assert_eq!(error.problem_code(), Some(code));
        assert_eq!(error.status(), Some(500), "{code}");
        assert!(!error.is_outcome_unknown(), "{code}");
        assert_eq!(script.observations().len(), 1, "{code}");
        server.abort();
    }
}

#[tokio::test]
async fn the_retry_count_is_honored() {
    for (retries, expected_attempts) in [(None, 3), (Some(2), 3), (Some(1), 2)] {
        let (address, script, server) = serve(&[
            Answer::Problem(BRegProblemCode::ServiceUnavailable, None),
            Answer::Problem(BRegProblemCode::ServiceUnavailable, None),
            Answer::Problem(BRegProblemCode::ServiceUnavailable, None),
            Answer::Published,
        ])
        .await;
        let mut config = config(&address);
        if let Some(retries) = retries {
            config = config.with_max_mutation_retries(retries);
        }
        let error = publish(&client(config))
            .await
            .expect_err("every attempt was unavailable");
        assert_eq!(
            error.problem_code(),
            Some(BRegProblemCode::ServiceUnavailable)
        );
        assert!(error.is_outcome_unknown());
        let observations = script.observations();
        assert_eq!(observations.len(), expected_attempts, "{retries:?}");
        assert_identical_resends(&observations);
        server.abort();
    }
}

#[tokio::test]
async fn zero_retries_disables_the_resend() {
    let (address, script, server) = serve(&[Answer::Stall, Answer::Published]).await;
    let error = publish(&client(
        config(&address)
            .with_request_timeout(Duration::from_millis(500))
            .with_max_mutation_retries(0),
    ))
    .await
    .expect_err("the only attempt timed out");
    assert!(matches!(
        error,
        BaseRegistryClientError::Transport {
            kind: TransportKind::Timeout
        }
    ));
    assert!(error.is_outcome_unknown());
    assert_eq!(script.observations().len(), 1);
    server.abort();
}

#[tokio::test]
async fn an_unkeyed_mutation_is_never_resent() {
    let (address, script, server) = serve(&[
        Answer::Problem(BRegProblemCode::ServiceUnavailable, None),
        Answer::Published,
    ])
    .await;
    let error = client(config(&address))
        .cancel_ingestion_run(
            "companies",
            Uuid::parse_str(RUN_ID).expect("fixture run"),
            Some("importer.v1"),
        )
        .await
        .expect_err("the cancellation was unavailable");
    assert!(error.is_outcome_unknown());
    let observations = script.observations();
    assert_eq!(observations.len(), 1);
    assert!(observations[0].headers.get("idempotency-key").is_none());
    server.abort();
}

#[tokio::test]
async fn a_refusal_after_an_unknown_outcome_keeps_the_outcome_unknown() {
    let (address, script, server) = serve(&[
        Answer::Problem(BRegProblemCode::ServiceUnavailable, None),
        Answer::Problem(BRegProblemCode::AuthenticationRefused, None),
        Answer::Published,
    ])
    .await;
    let error = publish(&client(config(&address)))
        .await
        .expect_err("the resend was refused");
    assert_eq!(
        error.problem_code(),
        Some(BRegProblemCode::ServiceUnavailable)
    );
    assert!(error.is_outcome_unknown());
    assert_eq!(script.observations().len(), 2);
    server.abort();
}

#[tokio::test]
async fn an_unreadable_answer_below_500_is_unknown_but_not_resent() {
    let (address, script, server) =
        serve(&[Answer::Json(StatusCode::CONFLICT, "{}"), Answer::Published]).await;
    let error = publish(&client(config(&address)))
        .await
        .expect_err("the answer is not a product problem");
    assert!(matches!(error, BaseRegistryClientError::Protocol { .. }));
    assert!(error.is_outcome_unknown());
    assert_eq!(
        script.observations().len(),
        1,
        "the same request would draw the same unreadable answer"
    );
    server.abort();
}
