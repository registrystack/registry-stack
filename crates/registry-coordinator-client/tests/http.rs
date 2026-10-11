// SPDX-License-Identifier: Apache-2.0
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::{
    body::Bytes,
    extract::State,
    http::{HeaderMap, Method, StatusCode, Uri},
    response::IntoResponse,
    Router,
};
use registry_coordinator_client::{
    BearerToken, CoordinatorClient, CoordinatorClientConfig, CoordinatorClientError,
    StartRunRequest, Uuid,
};
use serde_json::{json, Value};
use tokio::task::JoinHandle;
use url::Url;

const RUN: &str = "7e367d42-b001-4d44-b94c-9447bfa182aa";

fn status() -> Value {
    json!({"runId":RUN,"workflowId":"nursing-notice","workflowVersion":"1","definitionDigest":"sha256:definition","bindingDigest":"sha256:binding","step":"notify","state":"pending","outcome":null,"output":null,"failureCode":null,"failurePath":null,"admittedAt":"2026-10-10T12:00:00Z","deadlineAt":"2026-10-10T12:05:00Z","nextDueAt":null,"uncertain":false,"restoreReviewRequired":false,"cancelRequested":false})
}
fn inspection() -> Value {
    json!({"run":status(),"steps":[{"step":"notify","state":"unknown","generation":1,"attempt":1,"nextDueAt":null,"leaseExpiresAt":null,"commandPrepared":true,"uncertain":true,"receiptExpired":false,"failureCode":"response-lost","failurePath":null}],"recovery":{"retryAllowed":true,"reason":null,"operation":{"id":"submit-message","version":1,"product":"messaging","effect":"mutation","keyRequirement":"required","requiresPreparation":false,"recovery":"same-command-and-receipt","readReceipt":true}}})
}
type Seen = Arc<Mutex<Vec<(Method, String, Option<String>, Bytes)>>>;
type Reply = (u16, String, String);
#[derive(Clone)]
struct Fixture {
    seen: Seen,
    reply: Arc<Mutex<Reply>>,
    script: Arc<Mutex<VecDeque<Reply>>>,
    wait: Duration,
}
async fn handle(
    State(f): State<Fixture>,
    method: Method,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    assert_eq!(
        headers.get("authorization").unwrap(),
        "Bearer fixture-token"
    );
    f.seen.lock().unwrap().push((
        method,
        uri.path_and_query().map_or("", |p| p.as_str()).to_string(),
        headers
            .get("idempotency-key")
            .map(|v| v.to_str().unwrap().to_string()),
        body,
    ));
    tokio::time::sleep(f.wait).await;
    let scripted = f.script.lock().unwrap().pop_front();
    let (status, media, body) = scripted.unwrap_or_else(|| f.reply.lock().unwrap().clone());
    (
        StatusCode::from_u16(status).unwrap(),
        [
            ("content-type", media),
            ("location", "/must-not-follow".to_string()),
        ],
        body,
    )
}
struct Server {
    url: Url,
    fixture: Fixture,
    task: JoinHandle<()>,
}
impl Server {
    async fn new(value: Value) -> Self {
        Self::with_wait(value, Duration::ZERO).await
    }
    async fn with_wait(value: Value, wait: Duration) -> Self {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = Url::parse(&format!(
            "http://{}/deployment",
            listener.local_addr().unwrap()
        ))
        .unwrap();
        let fixture = Fixture {
            seen: Arc::default(),
            reply: Arc::new(Mutex::new((
                200,
                "application/json".into(),
                value.to_string(),
            ))),
            script: Arc::default(),
            wait,
        };
        let app = Router::new().fallback(handle).with_state(fixture.clone());
        let task = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });
        Self { url, fixture, task }
    }
    fn client(&self) -> CoordinatorClient {
        CoordinatorClient::new(CoordinatorClientConfig::new(self.url.clone())).unwrap()
    }
    fn answer(&self, code: u16, media: &str, bytes: &str) {
        *self.fixture.reply.lock().unwrap() = (code, media.into(), bytes.into());
    }
    /// Answer the next requests with these replies, in order, before falling
    /// back to the standing answer.
    fn script(&self, replies: &[(u16, &str)]) {
        let mut script = self.fixture.script.lock().unwrap();
        for (code, bytes) in replies {
            script.push_back((*code, "application/json".into(), (*bytes).into()));
        }
    }
    fn client_with_retries(&self, retries: u8) -> CoordinatorClient {
        CoordinatorClient::new(
            CoordinatorClientConfig::new(self.url.clone()).with_max_mutation_retries(retries),
        )
        .unwrap()
    }
    fn count(&self) -> usize {
        self.fixture.seen.lock().unwrap().len()
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.task.abort();
    }
}
fn token() -> BearerToken {
    BearerToken::new("fixture-token".to_string()).unwrap()
}
fn request() -> StartRunRequest {
    StartRunRequest {
        flow: "nursing-notice".into(),
        input: json!({"requestId":"one", "values":[null,true,23]}),
    }
}

#[tokio::test]
async fn explicit_admission_preserves_prefix_key_input_and_single_exchange() {
    let server = Server::new(status()).await;
    let client = server.client();
    let outcome = client
        .start(&token(), "event start original", &request())
        .await
        .unwrap();
    assert_eq!(outcome.value.run_id.to_string(), RUN);
    assert_eq!(outcome.value.state, "pending");
    let seen = server.fixture.seen.lock().unwrap();
    assert_eq!(seen.len(), 1);
    assert_eq!(seen[0].0, Method::POST);
    assert_eq!(seen[0].1, "/deployment/v1/runs");
    assert_eq!(seen[0].2.as_deref(), Some("event start original"));
    assert_eq!(
        serde_json::from_slice::<Value>(&seen[0].3).unwrap(),
        serde_json::to_value(request()).unwrap()
    );
}

#[tokio::test]
async fn status_inspection_and_receipt_reconciliation_use_only_their_exact_routes() {
    let server = Server::new(status()).await;
    let client = server.client();
    let run = Uuid::parse_str(RUN).unwrap();
    client.status(&token(), run).await.unwrap();
    server.answer(200, "application/json", &inspection().to_string());
    let inspected = client.inspect(&token(), run).await.unwrap();
    assert!(inspected.value.steps[0].uncertain);
    let recovered = client
        .reconcile(&token(), run, "lost-notice-response")
        .await
        .unwrap();
    assert!(recovered.value.recovery.operation.unwrap().read_receipt);
    let seen = server.fixture.seen.lock().unwrap();
    assert_eq!(seen.len(), 3);
    assert_eq!(seen[0].0, Method::GET);
    assert_eq!(seen[1].1, format!("/deployment/v1/runs/{RUN}/inspect"));
    assert_eq!(seen[2].1, format!("/deployment/v1/runs/{RUN}/reconcile"));
    assert_eq!(
        serde_json::from_slice::<Value>(&seen[2].3).unwrap(),
        json!({"reason":"lost-notice-response"})
    );
    assert!(seen.iter().all(|s| s.2.is_none()));
}

fn retry_scheduled() -> Value {
    json!({"runId":RUN,"status":"retry-scheduled"})
}

#[tokio::test]
async fn listing_retry_and_cancellation_use_only_their_exact_routes() {
    let server = Server::new(json!({"runs":[status()]})).await;
    let client = server.client();
    let run = Uuid::parse_str(RUN).unwrap();
    let listed = client.list(&token(), 5).await.unwrap();
    assert_eq!(listed.value.runs.len(), 1);
    assert_eq!(listed.value.runs[0].run_id, run);
    server.answer(200, "application/json", &retry_scheduled().to_string());
    let scheduled = client
        .retry_same(&token(), run, "operator-ticket-4821")
        .await
        .unwrap();
    assert_eq!(scheduled.value.run_id, run);
    assert_eq!(scheduled.value.status, "retry-scheduled");
    let mut cancelled = status();
    cancelled["cancelRequested"] = json!(true);
    server.answer(200, "application/json", &cancelled.to_string());
    let cancelled = client
        .cancel(&token(), run, "caller-withdrew-request")
        .await
        .unwrap();
    assert!(cancelled.value.cancel_requested);
    let seen = server.fixture.seen.lock().unwrap();
    assert_eq!(seen.len(), 3);
    assert_eq!(seen[0].0, Method::GET);
    assert_eq!(seen[0].1, "/deployment/v1/runs?limit=5");
    assert!(seen[0].3.is_empty());
    assert_eq!(seen[1].0, Method::POST);
    assert_eq!(seen[1].1, format!("/deployment/v1/runs/{RUN}/retry-same"));
    assert_eq!(
        serde_json::from_slice::<Value>(&seen[1].3).unwrap(),
        json!({"reason":"operator-ticket-4821"})
    );
    assert_eq!(seen[2].0, Method::POST);
    assert_eq!(seen[2].1, format!("/deployment/v1/runs/{RUN}/cancel"));
    assert_eq!(
        serde_json::from_slice::<Value>(&seen[2].3).unwrap(),
        json!({"reason":"caller-withdrew-request"})
    );
    assert!(
        seen.iter().all(|s| s.2.is_none()),
        "no key is ever invented"
    );
}

#[tokio::test]
async fn a_limit_outside_one_to_one_hundred_is_refused_before_io() {
    let server = Server::new(json!({"runs":[]})).await;
    let client = server.client();
    for limit in [0, 101, u32::MAX] {
        assert!(matches!(
            client.list(&token(), limit).await,
            Err(CoordinatorClientError::InvalidRequest { .. })
        ));
    }
    assert_eq!(server.count(), 0);
    for limit in [1, 100] {
        assert!(client.list(&token(), limit).await.is_ok());
    }
    assert_eq!(server.count(), 2);
}

#[tokio::test]
async fn an_invalid_retry_or_cancellation_reason_is_refused_before_io() {
    let server = Server::new(status()).await;
    let client = server.client();
    let run = Uuid::parse_str(RUN).unwrap();
    for reason in ["", "contains\ncontrol", &"r".repeat(257), &"é".repeat(129)] {
        assert!(matches!(
            client.retry_same(&token(), run, reason).await,
            Err(CoordinatorClientError::InvalidRequest { .. })
        ));
        assert!(matches!(
            client.cancel(&token(), run, reason).await,
            Err(CoordinatorClientError::InvalidRequest { .. })
        ));
    }
    assert_eq!(server.count(), 0);
    assert!(client.cancel(&token(), run, &"r".repeat(256)).await.is_ok());
    assert_eq!(server.count(), 1);
}

#[tokio::test]
async fn a_refused_listing_retry_or_cancellation_keeps_the_status_and_code() {
    let server = Server::new(status()).await;
    let client = server.client();
    let run = Uuid::parse_str(RUN).unwrap();
    server.answer(
        400,
        "application/json",
        &json!({"code":"request.invalid","message":"sensitive-canary"}).to_string(),
    );
    let error = client.list(&token(), 20).await.err().unwrap();
    assert!(
        matches!(&error, CoordinatorClientError::Problem { status: 400, code } if code == "request.invalid")
    );
    server.answer(
        409,
        "application/json",
        &json!({"code":"retry-refused","message":"sensitive-canary","suggestedAction":"secret-recovery-canary"}).to_string(),
    );
    for error in [
        client
            .retry_same(&token(), run, "operator-ticket-4821")
            .await
            .err()
            .unwrap(),
        client
            .cancel(&token(), run, "caller-withdrew-request")
            .await
            .err()
            .unwrap(),
    ] {
        assert!(
            matches!(&error, CoordinatorClientError::Problem { status: 409, code } if code == "retry-refused")
        );
        assert!(!error.is_outcome_unknown());
        assert!(!format!("{error:?} {error}").contains("canary"));
    }
    assert_eq!(server.count(), 3);
}

#[tokio::test]
async fn listing_retry_and_cancellation_are_never_resent() {
    let server = Server::new(status()).await;
    server.answer(503, "application/json", &problem("store-unavailable"));
    let client = server.client_with_retries(2);
    let run = Uuid::parse_str(RUN).unwrap();
    assert!(client.list(&token(), 20).await.is_err());
    for error in [
        client
            .retry_same(&token(), run, "lost")
            .await
            .err()
            .unwrap(),
        client.cancel(&token(), run, "lost").await.err().unwrap(),
    ] {
        assert!(error.is_outcome_unknown());
    }
    assert_eq!(server.count(), 3, "each is sent exactly once");
}

#[tokio::test]
async fn a_lost_cancellation_reply_is_sent_once_and_left_unknown() {
    let server = Server::with_wait(status(), Duration::from_millis(250)).await;
    let client = CoordinatorClient::new(
        CoordinatorClientConfig::new(server.url.clone())
            .with_request_timeout(Duration::from_millis(70))
            .with_max_mutation_retries(2),
    )
    .unwrap();
    let run = Uuid::parse_str(RUN).unwrap();
    for error in [
        client.cancel(&token(), run, "lost").await.err().unwrap(),
        client
            .retry_same(&token(), run, "lost")
            .await
            .err()
            .unwrap(),
    ] {
        assert!(matches!(error, CoordinatorClientError::Transport { .. }));
        assert!(error.is_outcome_unknown());
    }
    assert_eq!(server.count(), 2, "neither is resent");
}

#[tokio::test]
async fn listing_retry_or_cancellation_answers_outside_the_request_are_refused() {
    let server = Server::new(status()).await;
    let client = server.client();
    let run = Uuid::parse_str(RUN).unwrap();
    server.answer(
        200,
        "application/json",
        &json!({"runs":[status(), status()]}).to_string(),
    );
    assert!(matches!(
        client.list(&token(), 1).await,
        Err(CoordinatorClientError::Protocol { .. })
    ));
    let mut other = status();
    other["runId"] = json!(Uuid::nil());
    for answer in [
        json!({"runId":Uuid::nil(),"status":"retry-scheduled"}),
        json!({"runId":RUN,"status":"scheduled"}),
        json!({"runId":RUN,"status":"retry-scheduled","extra":true}),
    ] {
        server.answer(200, "application/json", &answer.to_string());
        assert!(matches!(
            client.retry_same(&token(), run, "reason").await,
            Err(CoordinatorClientError::Protocol { .. })
        ));
    }
    server.answer(200, "application/json", &other.to_string());
    assert!(matches!(
        client.cancel(&token(), run, "reason").await,
        Err(CoordinatorClientError::Protocol { .. })
    ));
}

#[tokio::test]
async fn invalid_admission_and_recovery_fail_before_io() {
    let server = Server::new(status()).await;
    let client = server.client();
    for key in [
        "",
        "contains\tcontrol",
        "injected\r\nheader",
        &"a".repeat(257),
    ] {
        assert!(matches!(
            client.start(&token(), key, &request()).await,
            Err(CoordinatorClientError::InvalidRequest { .. })
        ));
    }
    let mut input = request();
    input.flow = "../other".into();
    assert!(client.start(&token(), "key", &input).await.is_err());
    input = request();
    input.input = json!({"tooMuch":"x".repeat(65_536)});
    assert!(client.start(&token(), "key", &input).await.is_err());
    for reason in ["", "contains\ncontrol", &"é".repeat(129)] {
        assert!(matches!(
            client
                .reconcile(&token(), Uuid::parse_str(RUN).unwrap(), reason)
                .await,
            Err(CoordinatorClientError::InvalidRequest { .. })
        ));
    }
    assert_eq!(server.count(), 0);
}

#[tokio::test]
async fn problems_are_product_owned_and_prose_is_never_released() {
    let server = Server::new(status()).await;
    for (code, status) in [
        ("access.unauthenticated", 401),
        ("access.denied", 403),
        ("run-absent", 404),
        ("start-conflict", 409),
        ("store-unavailable", 503),
    ] {
        server.answer(status, "application/json", &json!({"code":code,"message":"sensitive-canary","suggestedAction":"secret-recovery-canary"}).to_string());
        let error = server
            .client_with_retries(0)
            .start(&token(), "key", &request())
            .await
            .err()
            .unwrap();
        assert_eq!(error.is_outcome_unknown(), status >= 500);
        assert!(!format!("{error:?} {error}").contains("canary"));
        assert!(
            matches!(error, CoordinatorClientError::Problem { status: s, code:c } if s == status && c == code)
        );
    }
    assert_eq!(
        server.count(),
        5,
        "a disabled retry sends once, even after a 503"
    );
}

#[tokio::test]
async fn a_problem_keeps_the_answered_status_and_code_without_a_client_side_status_table() {
    let server = Server::new(status()).await;
    server.answer(
        403,
        "application/json",
        &json!({"code":"start-conflict","message":"refused","suggestedAction":null}).to_string(),
    );
    let error = server
        .client()
        .start(&token(), "key", &request())
        .await
        .err()
        .unwrap();
    assert!(
        matches!(&error, CoordinatorClientError::Problem { status: 403, code } if code == "start-conflict")
    );
    assert!(!error.is_outcome_unknown());
    assert_eq!(server.count(), 1, "a 4xx refusal is never resent");
}

#[tokio::test]
async fn a_flow_the_deployment_does_not_serve_is_refused_once_with_a_known_outcome() {
    let server = Server::new(status()).await;
    server.answer(
        404,
        "application/json",
        &json!({"code":"flow-absent","message":"sensitive-canary","suggestedAction":"secret-recovery-canary"}).to_string(),
    );
    let error = server
        .client()
        .start(&token(), "key", &request())
        .await
        .err()
        .unwrap();
    assert!(
        matches!(&error, CoordinatorClientError::Problem { status: 404, code } if code == "flow-absent")
    );
    assert!(!error.is_outcome_unknown());
    assert!(!format!("{error:?} {error}").contains("canary"));
    assert_eq!(server.count(), 1, "an absent flow is never resent");
}

#[tokio::test]
async fn a_run_of_a_flow_outside_the_caller_policy_reads_as_absent_on_every_run_action() {
    let server = Server::new(status()).await;
    server.answer(
        404,
        "application/json",
        &json!({"code":"run-absent","message":"run was not found","suggestedAction":null})
            .to_string(),
    );
    let client = server.client();
    let run = Uuid::parse_str(RUN).unwrap();
    for error in [
        client.status(&token(), run).await.err().unwrap(),
        client.inspect(&token(), run).await.err().unwrap(),
        client.reconcile(&token(), run, "lost").await.err().unwrap(),
        client
            .retry_same(&token(), run, "lost")
            .await
            .err()
            .unwrap(),
        client
            .cancel(&token(), run, "withdrawn")
            .await
            .err()
            .unwrap(),
    ] {
        assert!(
            matches!(&error, CoordinatorClientError::Problem { status: 404, code } if code == "run-absent")
        );
        assert!(!error.is_outcome_unknown());
    }
    assert_eq!(server.count(), 5, "each is sent exactly once");
}

fn problem(code: &str) -> String {
    json!({"code":code,"message":"withheld"}).to_string()
}

#[tokio::test]
async fn an_unknown_admission_outcome_is_resent_under_the_same_key_and_body() {
    let server = Server::new(status()).await;
    server.script(&[(503, &problem("store-unavailable"))]);
    let outcome = server
        .client()
        .start(&token(), "event start original", &request())
        .await
        .unwrap();
    assert_eq!(outcome.value.run_id.to_string(), RUN);
    let seen = server.fixture.seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    for attempt in seen.iter() {
        assert_eq!(attempt.0, Method::POST);
        assert_eq!(attempt.1, "/deployment/v1/runs");
        assert_eq!(attempt.2.as_deref(), Some("event start original"));
        assert_eq!(attempt.3, seen[0].3);
    }
}

#[tokio::test]
async fn admission_resends_at_most_the_configured_count_and_keeps_the_outcome_unknown() {
    for (retries, sent) in [(0, 1), (1, 2), (2, 3)] {
        let server = Server::new(status()).await;
        server.answer(503, "application/json", &problem("audit-unavailable"));
        let error = server
            .client_with_retries(retries)
            .start(&token(), "key", &request())
            .await
            .err()
            .unwrap();
        assert!(error.is_outcome_unknown());
        assert!(matches!(
            error,
            CoordinatorClientError::Problem { status: 503, .. }
        ));
        assert_eq!(server.count(), sent, "{retries} retries");
    }
    let server = Server::new(status()).await;
    server.answer(503, "application/json", &problem("audit-unavailable"));
    server
        .client()
        .start(&token(), "key", &request())
        .await
        .err();
    assert_eq!(server.count(), 3, "two retries by default");
}

#[tokio::test]
async fn a_refusal_after_an_unknown_admission_outcome_keeps_the_outcome_unknown() {
    let server = Server::new(status()).await;
    server.script(&[
        (503, &problem("store-unavailable")),
        (409, &problem("start-conflict")),
    ]);
    let error = server
        .client()
        .start(&token(), "key", &request())
        .await
        .err()
        .unwrap();
    assert!(error.is_outcome_unknown());
    assert!(matches!(
        error,
        CoordinatorClientError::Problem { status: 503, .. }
    ));
    assert_eq!(server.count(), 2);
}

#[tokio::test]
async fn an_answer_that_would_repeat_unchanged_is_not_resent() {
    let server = Server::new(status()).await;
    let mut other = status();
    other["workflowId"] = json!("other-flow");
    server.answer(200, "application/json", &other.to_string());
    let error = server
        .client()
        .start(&token(), "key", &request())
        .await
        .err()
        .unwrap();
    assert!(error.is_outcome_unknown());
    assert!(matches!(
        error,
        CoordinatorClientError::Protocol { status: 200, .. }
    ));
    assert_eq!(server.count(), 1);
}

#[tokio::test]
async fn reads_and_reconciliation_are_never_resent() {
    let server = Server::new(status()).await;
    server.answer(503, "application/json", &problem("store-unavailable"));
    let client = server.client();
    let run = Uuid::parse_str(RUN).unwrap();
    assert!(client.status(&token(), run).await.is_err());
    assert!(client.inspect(&token(), run).await.is_err());
    assert!(client.reconcile(&token(), run, "lost").await.is_err());
    assert_eq!(server.count(), 3);
}

#[tokio::test]
async fn malformed_ambiguous_redirected_or_wrong_run_answers_are_refused() {
    let server = Server::new(status()).await;
    let mut other = status();
    other["runId"] = json!(Uuid::nil());
    let mut duplicate = status().to_string();
    duplicate.insert_str(1, "\"state\":\"done\",");
    let cases = [
        (200, "application/json", duplicate),
        (200, "text/html", status().to_string()),
        (302, "application/json", status().to_string()),
        (200, "application/json", other.to_string()),
        (
            403,
            "application/json",
            json!({"code":"start-conflict","message":"refused","extra":true}).to_string(),
        ),
        (
            409,
            "application/json",
            json!({"code":"secret value","message":"refused"}).to_string(),
        ),
    ];
    for (code, media, bytes) in cases {
        server.answer(code, media, &bytes);
        assert!(matches!(
            server
                .client()
                .status(&token(), Uuid::parse_str(RUN).unwrap())
                .await,
            Err(CoordinatorClientError::Protocol { .. })
        ));
    }
    assert_eq!(server.count(), 6, "a redirect was never followed");
    server.answer(200, "application/json", &status().to_string());
    let bounded = CoordinatorClient::new(
        CoordinatorClientConfig::new(server.url.clone()).with_max_response_bytes(64),
    )
    .unwrap();
    assert!(matches!(
        bounded
            .status(&token(), Uuid::parse_str(RUN).unwrap())
            .await,
        Err(CoordinatorClientError::Transport { .. })
    ));
}

#[tokio::test]
async fn a_lost_admission_reply_is_unknown_and_resent_under_the_original_key() {
    let server = Server::with_wait(status(), Duration::from_millis(250)).await;
    let client = CoordinatorClient::new(
        CoordinatorClientConfig::new(server.url.clone())
            .with_request_timeout(Duration::from_millis(70))
            .with_max_mutation_retries(1),
    )
    .unwrap();
    let error = client
        .start(&token(), "original", &request())
        .await
        .err()
        .unwrap();
    assert!(error.is_outcome_unknown());
    assert!(matches!(error, CoordinatorClientError::Transport { .. }));
    let seen = server.fixture.seen.lock().unwrap();
    assert_eq!(seen.len(), 2);
    assert!(seen
        .iter()
        .all(|attempt| attempt.2.as_deref() == Some("original")));
}

#[test]
fn config_bounds_and_debug_do_not_expose_configured_values() {
    let config = CoordinatorClientConfig::new(
        Url::parse("https://private-canary.example/secret-canary").unwrap(),
    )
    .with_user_agent("agent-canary")
    .with_trusted_root_certificates(b"certificate-canary".to_vec());
    assert!(!format!("{config:?}").contains("canary"));
    for url in [
        "http://remote.example",
        "https://user:secret@example.test",
        "https://example.test?token=secret",
        "https://example.test#secret",
    ] {
        assert!(
            CoordinatorClient::new(CoordinatorClientConfig::new(Url::parse(url).unwrap())).is_err()
        );
    }
    let url = Url::parse("https://example.test").unwrap();
    assert!(CoordinatorClient::new(
        CoordinatorClientConfig::new(url.clone()).with_request_timeout(Duration::ZERO)
    )
    .is_err());
    assert!(CoordinatorClient::new(
        CoordinatorClientConfig::new(url.clone()).with_max_response_bytes(0)
    )
    .is_err());
    assert!(matches!(
        CoordinatorClient::new(
            CoordinatorClientConfig::new(url.clone()).with_max_mutation_retries(3)
        ),
        Err(CoordinatorClientError::Configuration { .. })
    ));
    for retries in 0..=2 {
        assert!(CoordinatorClient::new(
            CoordinatorClientConfig::new(url.clone()).with_max_mutation_retries(retries)
        )
        .is_ok());
    }
}

#[test]
fn dto_contract_tracks_the_runtime_generated_schema() {
    let api: Value = serde_json::from_str(include_str!(
        "../../../products/coordinator/generated/openapi/coordinator.openapi.json"
    ))
    .unwrap();
    let schemas = &api["components"]["schemas"];
    for (name, value) in [
        ("RunStatus", status()),
        ("RunInspection", inspection()),
        ("RunList", json!({"runs":[status()]})),
        ("RetryScheduled", retry_scheduled()),
    ] {
        for field in schemas[name]["required"].as_array().unwrap() {
            assert!(
                value.get(field.as_str().unwrap()).is_some(),
                "missing {name} field {field}"
            );
        }
    }
    // The DTOs refuse unknown fields, so a property the runtime adds must
    // reach the client in the same change.
    let properties = |schema: &Value| -> Vec<String> {
        let mut names: Vec<_> = schema["properties"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect();
        names.sort();
        names
    };
    let fields = |value: &Value| -> Vec<String> {
        let mut names: Vec<_> = value.as_object().unwrap().keys().cloned().collect();
        names.sort();
        names
    };
    for (schema, value) in [
        (&schemas["RunStatus"], status()),
        (&schemas["RunInspection"], inspection()),
        (&schemas["StepStatus"], inspection()["steps"][0].clone()),
        (
            &schemas["RunInspection"]["properties"]["recovery"],
            inspection()["recovery"].clone(),
        ),
        (
            &schemas["OperationIdentity"],
            inspection()["recovery"]["operation"].clone(),
        ),
        (&schemas["RunList"], json!({"runs":[status()]})),
        (&schemas["RetryScheduled"], retry_scheduled()),
        (
            &schemas["Problem"],
            json!({"code":"flow-absent","message":"withheld","suggestedAction":null}),
        ),
    ] {
        assert_eq!(properties(schema), fields(&value));
    }
    let _: registry_coordinator_client::RunStatus = serde_json::from_value(status()).unwrap();
    let _: registry_coordinator_client::RunInspection =
        serde_json::from_value(inspection()).unwrap();
    let _: registry_coordinator_client::RunList =
        serde_json::from_value(json!({"runs":[status()]})).unwrap();
    let _: registry_coordinator_client::RetryScheduled =
        serde_json::from_value(retry_scheduled()).unwrap();
}

#[test]
fn run_and_step_status_carry_the_failure_path_a_refused_call_input_names() {
    for (member, expected) in [
        (Some(json!("/recordId")), Some("/recordId")),
        (Some(Value::Null), None),
        (None, None),
    ] {
        let mut run = status();
        let mut step = inspection()["steps"][0].clone();
        if let Some(member) = member {
            run["failurePath"] = member.clone();
            step["failurePath"] = member;
        }
        let run: registry_coordinator_client::RunStatus = serde_json::from_value(run).unwrap();
        let step: registry_coordinator_client::StepStatus = serde_json::from_value(step).unwrap();
        assert_eq!(run.failure_path.as_deref(), expected);
        assert_eq!(step.failure_path.as_deref(), expected);
    }
}
