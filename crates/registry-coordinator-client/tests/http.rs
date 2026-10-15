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
    BearerToken, CoordinatorClient, CoordinatorClientConfig, CoordinatorClientError, RunListQuery,
    RunListState, StartRunRequest, Uuid,
};
use serde_json::{json, Value};
use tokio::task::JoinHandle;
use url::Url;

const RUN: &str = "7e367d42-b001-4d44-b94c-9447bfa182aa";
const PROBLEM_MEDIA: &str = "application/problem+json";
const TRACE: &str = "4bf92f3577b34da6a3ce929d0e0e4736";
const TRACEPARENT: &str = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01";

fn status() -> Value {
    json!({"runId":RUN,"workflow":"nursing-notice","workflowRevision":"sha256:0000000000000000000000000000000000000000000000000000000000000000","bindingDigest":"sha256:binding","step":"notify","state":"running","outcome":null,"output":null,"failureCode":null,"failurePath":null,"admittedAt":"2026-10-10T12:00:00Z","deadlineAt":"2026-10-10T12:05:00Z","nextDueAt":null,"uncertain":false,"restoreReviewRequired":false,"cancelRequested":false,"authoredCancelRequested":false})
}
fn inspection() -> Value {
    json!({"run":status(),"effects":[],"waits":[],"steps":[{"step":"notify","state":"unknown","generation":1,"attempt":1,"nextDueAt":null,"leaseExpiresAt":null,"commandPrepared":true,"uncertain":true,"receiptExpired":false,"failureCode":"response-lost","failurePath":null}],"recovery":{"retryAllowed":true,"reason":null,"operation":{"id":"submit-message","version":1,"product":"messaging","effect":"mutation","keyRequirement":"required","requiresPreparation":false,"recovery":"same-command-and-receipt","readReceipt":true}}})
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
            ("traceparent", TRACEPARENT.to_string()),
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
            let media = if *code == 200 {
                "application/json"
            } else {
                PROBLEM_MEDIA
            };
            script.push_back((*code, media.into(), (*bytes).into()));
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
        workflow: "nursing-notice".into(),
        workflow_revision: format!("sha256:{}", "0".repeat(64)),
        input: json!({"requestId":"one", "values":[null,true,23]}),
    }
}

async fn run_status_answers(
    server: &Server,
    run: Value,
    run_id: Uuid,
) -> Vec<(&'static str, Result<String, CoordinatorClientError>)> {
    let client = server.client();
    server.answer(200, "application/json", &run.to_string());
    let mut answers = vec![
        (
            "start",
            client
                .start(&token(), "original-admission", &request())
                .await
                .map(|answer| answer.value.state),
        ),
        (
            "status",
            client
                .status(&token(), run_id)
                .await
                .map(|answer| answer.value.state),
        ),
        (
            "cancel",
            client
                .cancel(&token(), run_id, "caller-withdrew")
                .await
                .map(|answer| answer.value.state),
        ),
    ];
    let mut inspected = inspection();
    inspected["run"] = run.clone();
    server.answer(200, "application/json", &inspected.to_string());
    answers.push((
        "inspect",
        client
            .inspect(&token(), run_id)
            .await
            .map(|answer| answer.value.run.state),
    ));
    answers.push((
        "reconcile",
        client
            .reconcile(&token(), run_id, "response-lost")
            .await
            .map(|answer| answer.value.run.state),
    ));
    server.answer(200, "application/json", &json!({"runs":[run]}).to_string());
    answers.push((
        "list",
        client
            .list(&token(), 1)
            .await
            .map(|mut answer| answer.value.runs.remove(0).state),
    ));
    answers.push((
        "list_page",
        client
            .list_page(&token(), &RunListQuery::new(1))
            .await
            .map(|mut answer| answer.value.runs.remove(0).state),
    ));
    answers
}

#[tokio::test]
async fn every_run_status_response_rejects_unknown_effective_states() {
    let server = Server::new(status()).await;
    for state in [
        json!("pending"),
        json!("waiting"),
        json!("Running"),
        json!(""),
        json!("protected-state-canary"),
        Value::Null,
        json!(1),
        json!({"running": null}),
    ] {
        let before = server.count();
        let mut run = status();
        run["state"] = state.clone();
        let invalid_answers: Vec<_> =
            run_status_answers(&server, run, Uuid::parse_str(RUN).unwrap())
                .await
                .into_iter()
                .filter_map(|(operation, answer)| {
                    (!matches!(
                        answer,
                        Err(CoordinatorClientError::Protocol {
                            status: 200,
                            failure: registry_coordinator_client::CoordinatorProtocolFailure::Body
                        })
                    ))
                    .then_some(operation)
                })
                .collect();
        assert!(
            invalid_answers.is_empty(),
            "state {state}: responses accepted by {invalid_answers:?}"
        );
        assert_eq!(server.count(), before + 7, "each operation sends once");
    }
}

#[tokio::test]
async fn every_run_status_response_preserves_each_closed_effective_state() {
    let server = Server::new(status()).await;
    for state in [
        "running",
        "finished",
        "failed",
        "cancelled",
        "cancelled-after-effect",
        "expired",
        "attention",
        "cancel-requested",
    ] {
        let before = server.count();
        let mut run = status();
        run["state"] = json!(state);
        for (operation, answer) in
            run_status_answers(&server, run, Uuid::parse_str(RUN).unwrap()).await
        {
            assert_eq!(
                answer.unwrap_or_else(|_| panic!("{operation} refused {state}")),
                state
            );
        }
        assert_eq!(server.count(), before + 7, "each operation sends once");
    }
}

#[tokio::test]
async fn every_run_response_rejects_a_nil_identity_without_resending() {
    let server = Server::new(status()).await;
    let mut run = status();
    run["runId"] = json!(Uuid::nil());
    // Request the same nil identity so correlation alone cannot reject it.
    for (operation, answer) in run_status_answers(&server, run, Uuid::nil()).await {
        let error = answer
            .err()
            .unwrap_or_else(|| panic!("{operation} accepted nil"));
        assert!(
            matches!(
                error,
                CoordinatorClientError::Protocol {
                    status: 200,
                    failure: registry_coordinator_client::CoordinatorProtocolFailure::Body,
                }
            ),
            "{operation}: {error:?}"
        );
        assert!(error.is_outcome_unknown(), "{operation}");
    }
    server.answer(
        200,
        "application/json",
        &json!({"runId":Uuid::nil(),"status":"retry-scheduled"}).to_string(),
    );
    let error = server
        .client()
        .retry_same(&token(), Uuid::nil(), "response-lost")
        .await
        .err()
        .unwrap();
    assert!(matches!(
        error,
        CoordinatorClientError::Protocol {
            status: 200,
            failure: registry_coordinator_client::CoordinatorProtocolFailure::Body,
        }
    ));
    assert!(error.is_outcome_unknown());
    assert_eq!(server.count(), 8, "each operation sends once");
}

#[tokio::test]
async fn every_run_status_response_preserves_nonnil_uuid_versions_and_spellings() {
    let server = Server::new(status()).await;
    for spelling in [
        "00000000-0000-0000-0000-000000000001",
        "f47ac10b-58cc-11cf-a447-001122334455",
        "F47AC10B-58CC-11CF-A447-001122334455",
        "f47ac10b58cc11cfa447001122334455",
        "{f47ac10b-58cc-11cf-a447-001122334455}",
        "urn:uuid:f47ac10b-58cc-11cf-a447-001122334455",
    ] {
        let id = Uuid::parse_str(spelling).unwrap();
        let mut run = status();
        run["runId"] = json!(spelling);
        let before = server.count();
        for (operation, answer) in run_status_answers(&server, run, id).await {
            assert_eq!(
                answer.unwrap_or_else(|_| panic!("{operation} refused nonnil")),
                "running"
            );
        }
        assert_eq!(server.count(), before + 7);
    }
}

#[tokio::test]
async fn every_run_status_response_requires_a_deadline_after_admission() {
    let server = Server::new(status()).await;
    for (admitted, deadline, valid) in [
        ("2026-10-10T12:00:00Z", "2026-10-10T12:00:00Z", false),
        ("2026-10-10T12:00:00Z", "2026-10-10T11:59:59Z", false),
        ("2026-10-10T12:00:00Z", "2026-10-10T19:00:00+07:00", false),
        ("2026-10-10T12:00:00Z", "2026-10-10T18:59:59+07:00", false),
        // Historical admissions remain readable, including exact start replay.
        ("2000-01-01T00:00:00Z", "2000-01-01T00:00:01Z", true),
        (
            "2026-10-10T12:00:00.000001Z",
            "2026-10-10T12:00:01.000001Z",
            true,
        ),
        ("2026-10-10T12:00:00Z", "2026-10-10T19:00:01+07:00", true),
    ] {
        let before = server.count();
        let mut run = status();
        run["admittedAt"] = json!(admitted);
        run["deadlineAt"] = json!(deadline);
        for (operation, answer) in
            run_status_answers(&server, run, Uuid::parse_str(RUN).unwrap()).await
        {
            if valid {
                assert_eq!(
                    answer.unwrap_or_else(|_| panic!("{operation} refused valid chronology")),
                    "running"
                );
            } else {
                let error = answer
                    .err()
                    .unwrap_or_else(|| panic!("{operation} accepted impossible chronology"));
                assert!(
                    matches!(
                        error,
                        CoordinatorClientError::Protocol {
                            status: 200,
                            failure: registry_coordinator_client::CoordinatorProtocolFailure::Body,
                        }
                    ),
                    "{operation}: {error:?}"
                );
                assert!(error.is_outcome_unknown(), "{operation}");
                assert!(!format!("{error:?}").contains(admitted));
            }
        }
        assert_eq!(server.count(), before + 7, "each operation sends once");
    }
}

#[tokio::test]
async fn inspection_and_reconciliation_require_one_consistent_recovery_decision() {
    let server = Server::new(inspection()).await;
    let client = server.client();
    let id = Uuid::parse_str(RUN).unwrap();
    for reason in [
        "not-recoverable",
        "deadline-reached",
        "receipt-expired",
        "binding-changed",
        "other-binding-live",
        "snapshot-incompatible",
        "cancelled",
        "restore-hold",
        "restore-review-required",
        "payload-erased",
        "evaluation-uncertain",
    ] {
        for operation_present in [false, true] {
            for (allowed, reason, valid) in [
                (true, Value::Null, true),
                (false, json!(reason), true),
                (true, json!(reason), false),
                (false, Value::Null, false),
            ] {
                let mut document = inspection();
                document["recovery"]["retryAllowed"] = json!(allowed);
                document["recovery"]["reason"] = reason;
                if !operation_present {
                    document["recovery"]
                        .as_object_mut()
                        .unwrap()
                        .remove("operation");
                }
                server.answer(200, "application/json", &document.to_string());
                let before = server.count();
                for answer in [
                    client.inspect(&token(), id).await,
                    client.reconcile(&token(), id, "response-lost").await,
                ] {
                    if valid {
                        assert_eq!(
                            serde_json::to_value(answer.unwrap().value).unwrap(),
                            document
                        );
                    } else {
                        let error = answer.err().expect("contradictory decision accepted");
                        assert!(matches!(
                            error,
                            CoordinatorClientError::Protocol {
                                status: 200,
                                failure:
                                    registry_coordinator_client::CoordinatorProtocolFailure::Body,
                            }
                        ));
                        assert!(error.is_outcome_unknown());
                    }
                }
                assert_eq!(server.count(), before + 2, "each operation sends once");
            }
        }
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
    assert_eq!(outcome.value.state, "running");
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
async fn a_list_page_carries_the_cursor_and_filters_without_interpreting_the_cursor() {
    let mut matching = status();
    matching["state"] = json!("attention");
    let server = Server::new(json!({"runs":[matching],"nextCursor":"cursor-next"})).await;
    let client = server.client();
    let mut query = RunListQuery::new(1);
    query.cursor = Some("cursor-before".into());
    query.state = Some(RunListState::Attention);
    query.attention = Some(true);

    let page = client.list_page(&token(), &query).await.unwrap().value;

    assert_eq!(page.next_cursor.as_deref(), Some("cursor-next"));
    let seen = server.fixture.seen.lock().unwrap();
    assert_eq!(
        seen[0].1,
        "/deployment/v1/runs?limit=1&cursor=cursor-before&state=attention&attention=true"
    );
}

#[tokio::test]
async fn list_responses_must_satisfy_the_requested_effective_state_and_attention() {
    let server = Server::new(json!({"runs":[]})).await;
    let client = server.client();
    let states = [
        RunListState::Running,
        RunListState::Finished,
        RunListState::Failed,
        RunListState::Cancelled,
        RunListState::CancelledAfterEffect,
        RunListState::Expired,
        RunListState::Attention,
        RunListState::CancelRequested,
    ];
    for state in states {
        let name = serde_json::to_value(state).unwrap();
        for selected in std::iter::once(None).chain(states.into_iter().map(Some)) {
            for attention in [None, Some(false), Some(true)] {
                let query = RunListQuery {
                    state: selected,
                    attention,
                    ..RunListQuery::new(1)
                };
                let mut run = status();
                run["state"] = name.clone();
                server.answer(200, "application/json", &json!({"runs":[run]}).to_string());
                let before = server.count();
                let result = client.list_page(&token(), &query).await;
                let matches = selected.is_none_or(|selected| selected == state)
                    && attention.is_none_or(|selected| {
                        selected == matches!(state, RunListState::Attention | RunListState::Failed)
                    });
                if matches {
                    assert!(result.is_ok(), "{state:?}, {selected:?}, {attention:?}");
                } else {
                    assert!(
                        matches!(result, Err(CoordinatorClientError::Protocol { .. })),
                        "{state:?}, {selected:?}, {attention:?}"
                    );
                }
                assert_eq!(server.count(), before + 1, "one caller-controlled read");
            }
        }
    }
    let query = RunListQuery {
        state: Some(RunListState::Running),
        attention: Some(true),
        ..RunListQuery::new(20)
    };
    server.answer(200, "application/json", "{\"runs\":[]}");
    assert!(
        client.list_page(&token(), &query).await.is_ok(),
        "an empty intersection has a valid empty page"
    );
}

#[tokio::test]
async fn invalid_list_cursors_are_refused_on_both_sides_of_the_wire() {
    let server = Server::new(json!({"runs":[]})).await;
    let client = server.client();
    for cursor in ["", "line\nbreak", &"x".repeat(4097)] {
        let mut query = RunListQuery::new(20);
        query.cursor = Some(cursor.into());
        assert!(matches!(
            client.list_page(&token(), &query).await,
            Err(CoordinatorClientError::InvalidRequest { .. })
        ));
    }
    assert_eq!(server.count(), 0);

    server.answer(
        200,
        "application/json",
        &json!({"runs":[status()],"nextCursor":"line\nbreak"}).to_string(),
    );
    assert!(matches!(
        client.list_page(&token(), &RunListQuery::new(1)).await,
        Err(CoordinatorClientError::Protocol { .. })
    ));
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
    server.answer(400, PROBLEM_MEDIA, &problem(400, "request.invalid"));
    let error = client.list(&token(), 20).await.err().unwrap();
    assert!(
        matches!(&error, CoordinatorClientError::Problem { status: 400, code } if code == "request.invalid")
    );
    server.answer(409, PROBLEM_MEDIA, &problem(409, "retry.refused"));
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
            matches!(&error, CoordinatorClientError::Problem { status: 409, code } if code == "retry.refused")
        );
        assert!(!error.is_outcome_unknown());
        assert!(!format!("{error:?} {error}").contains("canary"));
    }
    assert_eq!(server.count(), 3);
}

#[tokio::test]
async fn listing_retry_and_cancellation_are_never_resent() {
    let server = Server::new(status()).await;
    server.answer(503, PROBLEM_MEDIA, &problem(503, "service.unavailable"));
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
    input.workflow = "../other".into();
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
        ("authentication.refused", 401),
        ("operation.not-authorized", 403),
        ("run.not-visible", 404),
        ("idempotency.key-reused", 409),
        ("service.unavailable", 503),
    ] {
        server.answer(status, PROBLEM_MEDIA, &problem(status, code));
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
    server.answer(403, PROBLEM_MEDIA, &problem(403, "idempotency.key-reused"));
    let error = server
        .client()
        .start(&token(), "key", &request())
        .await
        .err()
        .unwrap();
    assert!(
        matches!(&error, CoordinatorClientError::Problem { status: 403, code } if code == "idempotency.key-reused")
    );
    assert!(!error.is_outcome_unknown());
    assert_eq!(server.count(), 1, "a 4xx refusal is never resent");
}

#[tokio::test]
async fn a_flow_the_deployment_does_not_serve_is_refused_once_with_a_known_outcome() {
    let server = Server::new(status()).await;
    server.answer(404, PROBLEM_MEDIA, &problem(404, "workflow.not-served"));
    let error = server
        .client()
        .start(&token(), "key", &request())
        .await
        .err()
        .unwrap();
    assert!(
        matches!(&error, CoordinatorClientError::Problem { status: 404, code } if code == "workflow.not-served")
    );
    assert!(!error.is_outcome_unknown());
    assert!(!format!("{error:?} {error}").contains("canary"));
    assert_eq!(server.count(), 1, "an absent workflow is never resent");
}

#[tokio::test]
async fn a_run_of_a_flow_outside_the_caller_policy_reads_as_absent_on_every_run_action() {
    let server = Server::new(status()).await;
    server.answer(404, PROBLEM_MEDIA, &problem(404, "run.not-visible"));
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
            matches!(&error, CoordinatorClientError::Problem { status: 404, code } if code == "run.not-visible")
        );
        assert!(!error.is_outcome_unknown());
    }
    assert_eq!(server.count(), 5, "each is sent exactly once");
}

/// A problem document as the runtime answers it, with prose the client must
/// never release.
fn problem_document(status: u16, code: &str) -> Value {
    json!({
        "type": format!(
            "https://id.registrystack.org/problems/registry-coordinator/{}",
            code.replace('.', "/")
        ),
        "title": "sensitive-canary title",
        "status": status,
        "detail": "sensitive-canary detail",
        "code": code,
        "traceId": TRACE,
    })
}
fn problem(status: u16, code: &str) -> String {
    problem_document(status, code).to_string()
}

#[tokio::test]
async fn an_unknown_admission_outcome_is_resent_under_the_same_key_and_body() {
    let server = Server::new(status()).await;
    server.script(&[(503, &problem(503, "service.unavailable"))]);
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
        server.answer(503, PROBLEM_MEDIA, &problem(503, "service.unavailable"));
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
    server.answer(
        503,
        PROBLEM_MEDIA,
        &problem(503, "audit.response-unavailable"),
    );
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
        (503, &problem(503, "service.unavailable")),
        (409, &problem(409, "idempotency.key-reused")),
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
    other["workflow"] = json!("other-workflow");
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
    server.answer(503, PROBLEM_MEDIA, &problem(503, "service.unavailable"));
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
    let altered = |member: &str, value: Value| {
        let mut document = problem_document(404, "run.not-visible");
        document[member] = value;
        document.to_string()
    };
    let mut extra = problem_document(404, "run.not-visible");
    extra["suggestedAction"] = json!("secret-recovery-canary");
    // Casework answers the same code under its own type.
    let mut foreign = problem_document(404, "request.not-found");
    foreign["type"] =
        json!("https://id.registrystack.org/problems/registry-casework/request/not-found");
    let mut duplicate_problem = problem(404, "run.not-visible");
    duplicate_problem.insert_str(1, "\"code\":\"run.not-visible\",");
    let cases = [
        (200, "application/json", duplicate),
        (200, "text/html", status().to_string()),
        (302, "application/json", status().to_string()),
        (200, "application/json", other.to_string()),
        // A problem is only ever the exact problem media type.
        (404, "application/json", problem(404, "run.not-visible")),
        (404, PROBLEM_MEDIA, extra.to_string()),
        (404, PROBLEM_MEDIA, duplicate_problem),
        (
            404,
            PROBLEM_MEDIA,
            json!({"code":"run.not-visible","message":"refused"}).to_string(),
        ),
        (404, PROBLEM_MEDIA, altered("code", json!("secret value"))),
        (404, PROBLEM_MEDIA, altered("code", json!("run-absent"))),
        // The document's status, type and trace must agree with the answer.
        (404, PROBLEM_MEDIA, altered("status", json!(409))),
        (404, PROBLEM_MEDIA, foreign.to_string()),
        (
            404,
            PROBLEM_MEDIA,
            altered("traceId", json!("0af7651916cd43dd8448eb211c80319c")),
        ),
    ];
    let sent = cases.len();
    for (code, media, bytes) in cases {
        server.answer(code, media, &bytes);
        let answer = server
            .client()
            .status(&token(), Uuid::parse_str(RUN).unwrap())
            .await;
        assert!(
            matches!(answer, Err(CoordinatorClientError::Protocol { .. })),
            "{code} {media} {bytes}"
        );
    }
    assert_eq!(server.count(), sent, "a redirect was never followed");
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
fn recovery_deserialization_preserves_optional_operation_and_rejects_missing_block_reason() {
    use registry_coordinator_client::RecoveryStatus;

    for document in [
        json!({"retryAllowed": true, "reason": null}),
        json!({"retryAllowed": false, "reason": "not-recoverable", "operation": null}),
    ] {
        assert!(serde_json::from_value::<RecoveryStatus>(document).is_ok());
    }
    for document in [
        json!({"retryAllowed": false}),
        json!({"retryAllowed": false, "reason": null}),
        json!({"retryAllowed": true, "reason": "not-recoverable"}),
        json!({"retryAllowed": true, "reason": null, "extra": 1}),
        json!({"retryAllowed": false, "reason": "unknown-reason"}),
    ] {
        assert!(serde_json::from_value::<RecoveryStatus>(document).is_err());
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
        (
            "RunList",
            json!({"runs":[status()],"nextCursor":"opaque-next"}),
        ),
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
        (
            &schemas["RunList"],
            json!({"runs":[status()],"nextCursor":"opaque-next"}),
        ),
        (&schemas["RetryScheduled"], retry_scheduled()),
        (
            &schemas["Problem"],
            problem_document(404, "workflow.not-served"),
        ),
    ] {
        assert_eq!(properties(schema), fields(&value));
    }
    // Every code these fixtures answer is one the runtime can return, under
    // the type the runtime pins for it.
    let problem_schema = &schemas["Problem"]["properties"];
    for code in [
        "audit.response-unavailable",
        "authentication.refused",
        "workflow.not-served",
        "idempotency.key-reused",
        "operation.not-authorized",
        "request.invalid",
        "retry.refused",
        "run.not-visible",
        "service.unavailable",
    ] {
        let document = problem_document(400, code);
        assert!(
            problem_schema["code"]["enum"]
                .as_array()
                .unwrap()
                .contains(&document["code"]),
            "{code}"
        );
        assert!(
            problem_schema["type"]["enum"]
                .as_array()
                .unwrap()
                .contains(&document["type"]),
            "{code}"
        );
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

#[tokio::test]
async fn workflow_contract_discovery_is_one_confined_read_with_a_revision_pin() {
    let contract = json!({"workflow":"nursing-notice", "workflowRevision":request().workflow_revision, "input":{"type":"object"}, "outcomes":{"sent":{"type":"object"}}, "reviewPolicy":null});
    let server = Server::new(contract.clone()).await;
    let client = server.client();
    let found = client.workflow(&token(), "nursing-notice").await.unwrap();
    assert_eq!(found.value.workflow_revision, request().workflow_revision);
    assert!(found.value.review_policy.is_none());
    {
        let seen = server.fixture.seen.lock().unwrap();
        assert_eq!(seen.len(), 1);
        assert_eq!(seen[0].0, Method::GET);
        assert_eq!(seen[0].1, "/deployment/v1/workflows/nursing-notice");
        assert!(seen[0].2.is_none());
        assert!(seen[0].3.is_empty());
    }
    assert!(client.workflow(&token(), "../elsewhere").await.is_err());
    assert_eq!(server.count(), 1);
    for (member, value) in [
        ("workflow", json!("other-workflow")),
        ("workflowRevision", json!("author-version-1")),
        ("outcomes", json!({})),
    ] {
        let mut malformed = contract.clone();
        malformed[member] = value;
        server.answer(200, "application/json", &malformed.to_string());
        assert!(matches!(
            client.workflow(&token(), "nursing-notice").await,
            Err(CoordinatorClientError::Protocol { .. })
        ));
    }
}

#[tokio::test]
async fn workflow_review_policy_reuses_shared_validation_and_pins_identity_and_revision() {
    let policy =
        json!({"id":"nursing-notice","version":"pilot-1","digest":request().workflow_revision});
    let contract = json!({"workflow":"nursing-notice", "workflowRevision":request().workflow_revision,
        "input":{"type":"object"}, "outcomes":{"sent":{"type":"object"}}, "reviewPolicy":policy});
    let server = Server::new(contract.clone()).await;
    let client = server.client();
    let found = client.workflow(&token(), "nursing-notice").await.unwrap();
    let retained = found.value.review_policy.unwrap();
    assert_eq!(serde_json::to_value(retained).unwrap(), policy);
    for (member, value) in [
        ("id", json!("other-workflow")),
        ("id", json!("")),
        ("version", json!("")),
        ("version", json!("untrusted\nversion")),
        ("digest", json!(format!("sha256:{}", "1".repeat(64)))),
        ("digest", json!("author-version-1")),
    ] {
        let mut malformed = contract.clone();
        malformed["reviewPolicy"][member] = value;
        server.answer(200, "application/json", &malformed.to_string());
        assert!(matches!(
            client.workflow(&token(), "nursing-notice").await,
            Err(CoordinatorClientError::Protocol { .. })
        ));
    }
    assert_eq!(
        server.count(),
        7,
        "metadata reads never retry a refused binding"
    );
}

#[tokio::test]
async fn admission_revision_is_required_before_io_and_bound_to_the_answer() {
    let server = Server::new(status()).await;
    let client = server.client();
    for revision in [
        "".into(),
        "1".into(),
        format!("sha256:{}", "A".repeat(64)),
        format!("sha256:{}", "0".repeat(63)),
    ] {
        let mut input = request();
        input.workflow_revision = revision;
        assert!(matches!(
            client.start(&token(), "pin-key", &input).await,
            Err(CoordinatorClientError::InvalidRequest { .. })
        ));
    }
    assert_eq!(server.count(), 0);
    let mut other = status();
    other["workflowRevision"] = json!(format!("sha256:{}", "1".repeat(64)));
    server.answer(200, "application/json", &other.to_string());
    let client = CoordinatorClient::new(
        CoordinatorClientConfig::new(server.url.clone()).with_max_mutation_retries(0),
    )
    .unwrap();
    assert!(matches!(
        client.start(&token(), "pin-key", &request()).await,
        Err(CoordinatorClientError::Protocol { .. })
    ));
    assert_eq!(server.count(), 1);
}

#[tokio::test]
async fn inspection_preserves_minimized_effects_and_waits_without_accepting_correlation_payloads() {
    const CANARY: &str = "protected-correlation-canary";
    let mut document = inspection();
    document["effects"] = json!([{"step":"submit","operation":document["recovery"]["operation"],"operationRevision":request().workflow_revision,"state":"accepted"}]);
    document["waits"] = json!([{"step":"observe","acceptedStep":"submit","completion":"result","completionRevision":request().workflow_revision,"timeoutAt":"2026-10-10T12:05:00Z","nextObservationAt":null,"notBefore":"2026-10-10T12:01:00Z","minimumIntervalSeconds":30,"observations":1,"observationLimit":10}]);
    let server = Server::new(document.clone()).await;
    let value = server
        .client()
        .inspect(&token(), RUN.parse().unwrap())
        .await
        .unwrap()
        .value;
    assert_eq!(
        value.effects[0].state,
        registry_coordinator_client::EffectState::Accepted
    );
    assert_eq!(value.waits[0].accepted_step, "submit");
    assert_eq!(value.waits[0].observation_limit, 10);
    assert!(value.waits[0].next_observation_at.is_none());
    document["waits"][0]["correlation"] = json!(CANARY);
    server.answer(200, "application/json", &document.to_string());
    let error = server
        .client()
        .inspect(&token(), RUN.parse().unwrap())
        .await
        .err()
        .unwrap();
    assert!(matches!(error, CoordinatorClientError::Protocol { .. }));
    assert!(!error.to_string().contains(CANARY));
}

#[tokio::test]
async fn inspection_wait_budgets_are_validated_for_inspect_and_reconcile() {
    let server = Server::new(inspection()).await;
    let client = server.client();
    for (interval, observations, limit, valid) in [
        (30, 0, 1, true),
        (86_400, 1, 1, true),
        (900, 9, 10, true),
        (29, 0, 1, false),
        (0, 0, 1, false),
        (86_401, 0, 1, false),
        (u32::MAX, 0, 1, false),
        (30, 0, 0, false),
        (30, 11, 10, false),
        (30, u32::MAX, 1, false),
    ] {
        let mut document = inspection();
        document["waits"] = json!([{
            "step": "observe", "acceptedStep": "submit", "completion": "result",
            "completionRevision": request().workflow_revision,
            "timeoutAt": "2026-10-10T12:05:00Z", "nextObservationAt": null,
            "notBefore": "2026-10-10T12:01:00Z",
            "minimumIntervalSeconds": interval, "observations": observations,
            "observationLimit": limit
        }]);
        server.answer(200, "application/json", &document.to_string());
        for reconcile in [false, true] {
            let before = server.count();
            let result = if reconcile {
                client
                    .reconcile(&token(), RUN.parse().unwrap(), "response-lost")
                    .await
            } else {
                client.inspect(&token(), RUN.parse().unwrap()).await
            };
            if valid {
                let wait = result.unwrap().value.waits.remove(0);
                assert_eq!(wait.minimum_interval_seconds, interval);
                assert_eq!(wait.observations, observations);
                assert_eq!(wait.observation_limit, limit);
            } else {
                let error = result
                    .err()
                    .expect("impossible wait budget must be refused");
                assert!(matches!(
                    error,
                    CoordinatorClientError::Protocol {
                        status: 200,
                        failure: registry_coordinator_client::CoordinatorProtocolFailure::Body,
                    }
                ));
                assert!(error.is_outcome_unknown());
                assert!(!error.to_string().contains("fixture-token"));
            }
            assert_eq!(
                server.count(),
                before + 1,
                "inspection and recovery never resend"
            );
        }
    }
}
