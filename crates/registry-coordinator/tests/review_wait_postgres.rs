// SPDX-License-Identifier: Apache-2.0
//! A wait-for step waits for a Casework review result. It reads the result
//! when the wait starts, again when an authentic completion event wakes it,
//! and on its own schedule otherwise; reads of one wait are at least thirty
//! seconds apart, and its correlation row ends with the wait. Isolated
//! synthetic PostgreSQL proof. Missing database configuration fails.
#![cfg(feature = "postgres-test")]
use async_trait::async_trait;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use chrono::Utc;
use registry_coordinator::{
    completion::receive_review_completion,
    definition::Definition,
    protocol::{AdapterSet, CallOutcome, CallRequest, Operation, ReviewRead},
    store::{Actor, RetryBlockReason, Store},
    worker::Worker,
};
use serde_json::{json, Value};
use std::{
    collections::VecDeque,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
};
use tokio::sync::{Notify, Semaphore};
use uuid::Uuid;

#[path = "support/database_clock.rs"]
mod database_clock;

const REQUEST: &str = "6f1d4c1e-2b7a-4c55-9a3e-1d2c3b4a5f60";
const RESULT: &str = "0b9e8d7c-6a5f-4e3d-8c2b-1a0f9e8d7c6b";
const MESSAGE: &str = "3c2b1a0f-9e8d-4c7b-a6f5-e4d3c2b1a0f9";
const APPLICATION: &str = "9a8b7c6d-5e4f-4a3b-8c2d-1e0f9a8b7c6d";
const TOKEN: &str = "synthetic-completion-token-canary-0123456789abcdef";
const RECIPIENT: &str = "coordinator-v1";

const FUNCTIONS: &str = r#"fn review_request(input) {
    #{
        kind: "application-review",
        subject: #{
            source: "applications",
            type: "application",
            id: input.applicationId,
            version: input.applicationVersion,
            digest: input.applicationDigest
        },
        requesterReference: input.applicationId,
        context: #{ strategy: "source", binding: #{ reference: input.applicationId } }
    }
}

fn notice_request(input, result) {
    #{
        senderProfile: "transactional",
        to: #{ email: input.email },
        template: #{ id: "application-approved", version: "1" },
        locale: "en",
        data: #{ applicationReference: input.applicationId, reviewResult: result.resultId }
    }
}
"#;

/// The reviewed-notice workflow. Without `on_timeout` the wait has no
/// timeout route, so a timeout fails the run.
fn workflow(on_timeout: bool) -> String {
    let mut workflow = String::from(
        r#"apiVersion: id.registrystack.org/formats/coordinator/project/v1alpha1
kind: CoordinatorProject
project:
  id: reviewed-notice
  version: "1"
input:
  type: object
  additionalProperties: false
  required: [applicationId, applicationVersion, applicationDigest, email]
  properties:
    applicationId: {type: string, format: uuid}
    applicationVersion: {type: string, minLength: 1, maxLength: 64}
    applicationDigest: {type: string, pattern: "^sha256:[0-9a-f]{64}$"}
    email: {type: string, format: email}
connections:
  review: casework
  notices: messaging
functionsFile: functions.rhai
deadlineSeconds: 2592000
start: submit-review
steps:
  submit-review:
    type: call
    connection: review
    operation: submit-review-request
    input: {type: function, function: review_request, arguments: [{type: input}]}
    next: await-review
  await-review:
    type: wait-for
    event: {type: review-result, request: submit-review}
    timeoutSeconds: 1209600
    next: decide
"#,
    );
    if on_timeout {
        workflow.push_str("    onTimeout: withdraw\n");
    }
    workflow.push_str(
        r#"  decide:
    type: choose
    choose: {type: step, step: await-review, path: /status}
    cases:
      approved: notify
      rejected: rejected
      changes-requested: not-decided
      answered: not-decided
      cancelled: not-decided
      superseded: not-decided
  notify:
    type: call
    connection: notices
    operation: submit-message
    input: {type: function, function: notice_request, arguments: [{type: input}, {type: step, step: await-review}]}
    next: notice-sent
  notice-sent:
    type: finish
    outcome: notice-sent
    output:
      type: fields
      fields:
        messageId: {type: step, step: notify, path: /id}
        resultId: {type: step, step: await-review, path: /resultId}
  rejected:
    type: finish
    outcome: rejected
    output:
      type: fields
      fields:
        resultId: {type: step, step: await-review, path: /resultId}
  not-decided:
    type: finish
    outcome: not-decided
    output:
      type: fields
      fields:
        status: {type: step, step: await-review, path: /status}
"#,
    );
    if on_timeout {
        workflow.push_str(
            r#"  withdraw:
    type: call
    connection: review
    operation: cancel-review-request
    input:
      type: fields
      fields:
        request: {type: step, step: submit-review}
        reason: {type: literal, value: "No decision within fourteen days."}
    next: withdrawn
  withdrawn:
    type: finish
    outcome: withdrawn
    output:
      type: fields
      fields:
        cancellation: {type: step, step: withdraw, path: /outcome}
"#,
        );
    }
    workflow.push_str(
        r#"outcomes:
  notice-sent:
    type: object
    additionalProperties: false
    required: [messageId, resultId]
    properties:
      messageId: {type: string, format: uuid}
      resultId: {type: string, format: uuid}
  rejected:
    type: object
    additionalProperties: false
    required: [resultId]
    properties:
      resultId: {type: string, format: uuid}
  not-decided:
    type: object
    additionalProperties: false
    required: [status]
    properties:
      status: {type: string}
"#,
    );
    if on_timeout {
        workflow.push_str(
            r#"  withdrawn:
    type: object
    additionalProperties: false
    required: [cancellation]
    properties:
      cancellation: {type: string}
"#,
        );
    }
    workflow
}

fn subject() -> Value {
    json!({"source": "applications", "type": "application", "id": APPLICATION,
        "version": "1", "digest": format!("sha256:{}", "a".repeat(64))})
}

fn accepted() -> Value {
    json!({
        "requestId": REQUEST,
        "subject": subject(),
        "policy": {"id": "application-review", "version": "1",
            "digest": format!("sha256:{}", "b".repeat(64))},
        "submissionDigest": format!("sha256:{}", "c".repeat(64)),
    })
}

fn result(status: &str) -> Value {
    let accepted = accepted();
    let mut result = json!({
        "resultId": RESULT,
        "requestId": REQUEST,
        "subject": accepted["subject"],
        "policy": accepted["policy"],
        "submissionDigest": accepted["submissionDigest"],
        "status": status,
        "completedAt": "2026-10-11T10:00:00Z",
        "availableUntil": "2026-11-11T10:00:00Z",
    });
    if status == "rejected" {
        result["outcome"] = json!("not-eligible");
    }
    result
}

struct Fake {
    reads: Mutex<VecDeque<ReviewRead>>,
    read_count: AtomicUsize,
    calls: Mutex<Vec<CallRequest>>,
    malformed_acceptance: bool,
    entered: Notify,
    release: Option<Semaphore>,
}

impl Fake {
    fn new(reads: Vec<ReviewRead>) -> Arc<Self> {
        Arc::new(Self::with(reads, false, None))
    }

    fn with(
        reads: Vec<ReviewRead>,
        malformed_acceptance: bool,
        release: Option<Semaphore>,
    ) -> Self {
        Self {
            reads: Mutex::new(reads.into()),
            read_count: AtomicUsize::new(0),
            calls: Mutex::new(vec![]),
            malformed_acceptance,
            entered: Notify::new(),
            release,
        }
    }

    fn reads(&self) -> usize {
        self.read_count.load(Ordering::SeqCst)
    }

    fn operations(&self) -> Vec<Operation> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|call| call.operation)
            .collect()
    }
}

#[async_trait]
impl AdapterSet for Fake {
    fn binding_digest(&self) -> &str {
        "binding-a"
    }

    async fn call(&self, request: &CallRequest) -> CallOutcome {
        self.calls.lock().unwrap().push(request.clone());
        match request.operation {
            Operation::SubmitReviewRequest if self.malformed_acceptance => {
                CallOutcome::Success(json!({"requestId": "not-an-identifier"}))
            }
            Operation::SubmitReviewRequest => CallOutcome::Success(accepted()),
            Operation::CancelReviewRequest => {
                assert_eq!(request.input["request"], accepted());
                CallOutcome::Success(json!({"outcome": "cancelled", "result": result("cancelled")}))
            }
            Operation::SubmitMessage => CallOutcome::Success(json!({"id": MESSAGE})),
            operation => panic!("unexpected operation {}", operation.as_str()),
        }
    }

    async fn read_review_result(&self, connection: &str, accepted_request: &Value) -> ReviewRead {
        assert_eq!(connection, "review");
        assert_eq!(accepted_request, &accepted());
        self.read_count.fetch_add(1, Ordering::SeqCst);
        if let Some(release) = &self.release {
            self.entered.notify_one();
            release.acquire().await.expect("release").forget();
        }
        self.reads
            .lock()
            .unwrap()
            .pop_front()
            .unwrap_or(ReviewRead::Pending)
    }

    fn result_check_seconds(&self, connection: &str) -> u32 {
        assert_eq!(connection, "review");
        900
    }

    fn review_completion(&self, token: &str, recipient: &str) -> Option<String> {
        (token == TOKEN && recipient == RECIPIENT).then(|| "review".to_owned())
    }
}

struct Harness {
    url: String,
    namespace: String,
    store: Arc<Store>,
    definition: Definition,
    _project: tempfile::TempDir,
}

async fn harness(on_timeout: bool) -> Harness {
    let url = std::env::var("COORDINATOR_TEST_DATABASE_URL").expect(
        "COORDINATOR_TEST_DATABASE_URL must name a disposable synthetic PostgreSQL 17+ database",
    );
    let namespace = format!("coordinator_{}", Uuid::new_v4().simple());
    let store = Arc::new(
        Store::connect(&url, &namespace)
            .await
            .expect("local disposable connection"),
    );
    store.migrate().await.expect("isolated migration");
    let project = tempfile::tempdir().expect("project");
    std::fs::write(project.path().join("workflow.yaml"), workflow(on_timeout)).expect("workflow");
    std::fs::write(project.path().join("functions.rhai"), FUNCTIONS).expect("functions");
    let definition = Definition::load(project.path()).expect("valid synthetic definition");
    Harness {
        url,
        namespace,
        store,
        definition,
        _project: project,
    }
}

fn operator() -> Actor {
    Actor {
        issuer: "https://issuer.example.invalid".into(),
        subject: "synthetic-operator".into(),
        client_id: "synthetic-operator-client".into(),
        operator: true,
    }
}

/// One wait row, as the database holds it.
struct WaitRow {
    woken: bool,
    read: bool,
    key_names_request: bool,
}

impl Harness {
    async fn admit(&self) -> Uuid {
        self.store
            .admit(
                &self.definition,
                json!({
                    "applicationId": APPLICATION,
                    "applicationVersion": "1",
                    "applicationDigest": format!("sha256:{}", "a".repeat(64)),
                    "email": "applicant@example.invalid",
                }),
                "synthetic-producer",
                &Uuid::new_v4().to_string(),
                "binding-a",
            )
            .await
            .expect("admit")
    }

    async fn client(&self) -> tokio_postgres::Client {
        let (client, connection) = tokio_postgres::connect(&self.url, tokio_postgres::NoTls)
            .await
            .expect("test connection");
        tokio::spawn(async move {
            connection.await.expect("test connection finishes");
        });
        client
    }

    async fn sql(&self, sql: &str) {
        self.client()
            .await
            .batch_execute(&sql.replace("{schema}", &self.namespace))
            .await
            .expect("synthetic test transition");
    }

    /// Seconds from the database clock until the waiting step is next due,
    /// while its job is pending.
    async fn due_in(&self, run: Uuid) -> Option<f64> {
        self.client()
            .await
            .query_opt(
                &format!("SELECT EXTRACT(EPOCH FROM next_attempt_at-clock_timestamp())::float8 FROM {}.jobs WHERE run_id=$1 AND step='await-review' AND state='pending'", self.namespace),
                &[&run],
            )
            .await
            .unwrap()
            .map(|row| row.get(0))
    }

    /// Make the waiting step due now, as the passing of its recheck time would.
    async fn make_due(&self, run: Uuid) {
        let changed = self
            .client()
            .await
            .execute(
                &format!("UPDATE {}.jobs SET next_attempt_at=clock_timestamp() WHERE run_id=$1 AND step='await-review' AND state='pending'", self.namespace),
                &[&run],
            )
            .await
            .unwrap();
        assert_eq!(changed, 1, "the waiting step is pending");
    }

    async fn wait_row(&self, run: Uuid) -> Option<WaitRow> {
        self.client()
            .await
            .query_opt(
                &format!("SELECT woken_at IS NOT NULL, read_at IS NOT NULL, position($2 in wait_key)>0 FROM {}.review_waits WHERE run_id=$1", self.namespace),
                &[&run, &REQUEST.replace('-', "")],
            )
            .await
            .unwrap()
            .map(|row| WaitRow {
                woken: row.get(0),
                read: row.get(1),
                key_names_request: row.get(2),
            })
    }

    async fn job_state(&self, run: Uuid) -> String {
        self.client()
            .await
            .query_one(
                &format!(
                    "SELECT state FROM {}.jobs WHERE run_id=$1 AND step='await-review'",
                    self.namespace
                ),
                &[&run],
            )
            .await
            .unwrap()
            .get(0)
    }

    /// Run the worker until it has nothing due.
    async fn drain(&self, worker: &Worker) {
        for _ in 0..16 {
            if !worker.tick().await.expect("worker progress") {
                return;
            }
        }
        panic!("the worker kept finding due work");
    }
}

fn completion_headers(token: &str, recipient: &str, event: Uuid) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        "authorization",
        HeaderValue::from_str(&format!("Bearer {token}")).unwrap(),
    );
    headers.insert(
        "registry-recipient-binding",
        HeaderValue::from_str(recipient).unwrap(),
    );
    headers.insert("content-type", HeaderValue::from_static("application/json"));
    headers.insert(
        "idempotency-key",
        HeaderValue::from_str(&event.to_string()).unwrap(),
    );
    headers
}

fn completion_body(event: Uuid, request: &str) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "type": "review.completed",
        "eventId": event,
        "requestId": request,
        "resultId": RESULT,
        "completedAt": Utc::now().to_rfc3339(),
    }))
    .unwrap()
}

/// Deliver one authentic completion event for `request`.
async fn complete(h: &Harness, adapters: &dyn AdapterSet, request: &str) -> StatusCode {
    let event = Uuid::new_v4();
    receive_review_completion(
        &h.store,
        adapters,
        &completion_headers(TOKEN, RECIPIENT, event),
        Some(&completion_body(event, request)),
    )
    .await
    .status()
}

async fn status(h: &Harness, run: Uuid) -> (String, Option<String>, Option<String>) {
    let status = h.store.status(run).await.expect("status");
    (status.state, status.outcome, status.failure_code)
}

#[tokio::test]
async fn the_first_read_catches_a_result_completed_before_the_wait_started() {
    let h = harness(true).await;
    let fake = Fake::new(vec![ReviewRead::Settled(result("approved"))]);
    let worker = Worker::new(h.store.clone(), fake.clone());
    let run = h.admit().await;
    // The event arrives before any wait for its request exists: it is
    // accepted and changes nothing.
    assert_eq!(
        complete(&h, fake.as_ref(), REQUEST).await,
        StatusCode::NO_CONTENT
    );
    assert!(worker.tick().await.unwrap(), "submit the review request");
    let row = h.wait_row(run).await.expect("the wait starts with its row");
    assert!(!row.woken && !row.read);
    assert!(
        !row.key_names_request,
        "the correlation key is a keyed hash, never the request identifier"
    );
    assert!(h.due_in(run).await.unwrap() <= 0.5, "read at wait start");
    h.drain(&worker).await;
    assert_eq!(fake.reads(), 1);
    assert_eq!(
        status(&h, run).await,
        ("finished".into(), Some("notice-sent".into()), None)
    );
    assert_eq!(
        fake.operations(),
        [Operation::SubmitReviewRequest, Operation::SubmitMessage]
    );
    assert!(
        h.wait_row(run).await.is_none(),
        "a settled wait ends its row"
    );
}

#[tokio::test]
async fn a_scheduled_read_settles_a_result_without_any_event() {
    let h = harness(true).await;
    let fake = Fake::new(vec![
        ReviewRead::Pending,
        ReviewRead::Settled(result("rejected")),
    ]);
    let worker = Worker::new(h.store.clone(), fake.clone());
    let run = h.admit().await;
    h.drain(&worker).await;
    assert_eq!(fake.reads(), 1);
    let due = h.due_in(run).await.expect("the wait is scheduled again");
    assert!(
        (895.0..=900.5).contains(&due),
        "the next read waits the configured check interval: {due}"
    );
    assert_eq!(status(&h, run).await.0, "running");
    assert!(h.wait_row(run).await.unwrap().read);
    h.make_due(run).await;
    h.drain(&worker).await;
    assert_eq!(fake.reads(), 2);
    assert_eq!(
        status(&h, run).await,
        ("finished".into(), Some("rejected".into()), None)
    );
    assert_eq!(fake.operations(), [Operation::SubmitReviewRequest]);
    assert!(h.wait_row(run).await.is_none());
}

#[tokio::test]
async fn a_burst_of_events_reads_at_most_once_in_thirty_seconds() {
    let h = harness(true).await;
    let fake = Fake::new(vec![]);
    let worker = Worker::new(h.store.clone(), fake.clone());
    let run = h.admit().await;
    h.drain(&worker).await;
    assert_eq!(fake.reads(), 1, "the wait read its result when it started");
    for _ in 0..12 {
        assert_eq!(
            complete(&h, fake.as_ref(), REQUEST).await,
            StatusCode::NO_CONTENT
        );
    }
    let due = h.due_in(run).await.unwrap();
    assert!(
        (25.0..=30.5).contains(&due),
        "a wake brings the read forward to thirty seconds after the last: {due}"
    );
    assert!(h.wait_row(run).await.unwrap().woken);
    h.drain(&worker).await;
    assert_eq!(fake.reads(), 1, "duplicate events never read early");
    h.make_due(run).await;
    h.drain(&worker).await;
    assert_eq!(fake.reads(), 2);
    // A wake that came before this read started is spent: the next read
    // waits the configured interval again.
    let due = h.due_in(run).await.unwrap();
    assert!((895.0..=900.5).contains(&due), "{due}");
    assert_eq!(status(&h, run).await.0, "running");
}

#[tokio::test]
async fn an_event_during_a_read_schedules_one_more_read_thirty_seconds_later() {
    let h = harness(true).await;
    let fake = Arc::new(Fake::with(vec![], false, Some(Semaphore::new(0))));
    let worker = Arc::new(Worker::new(h.store.clone(), fake.clone()));
    let run = h.admit().await;
    assert!(worker.tick().await.unwrap(), "submit the review request");
    let reading = tokio::spawn({
        let worker = worker.clone();
        async move { worker.tick().await }
    });
    fake.entered.notified().await;
    assert_eq!(
        complete(&h, fake.as_ref(), REQUEST).await,
        StatusCode::NO_CONTENT
    );
    fake.release.as_ref().unwrap().add_permits(1);
    assert!(reading.await.unwrap().unwrap());
    let due = h.due_in(run).await.unwrap();
    assert!(
        (25.0..=30.5).contains(&due),
        "the read in flight may have missed the result, so another follows: {due}"
    );
}

#[tokio::test]
async fn an_event_for_an_unknown_request_is_accepted_and_changes_nothing() {
    let h = harness(true).await;
    let fake = Fake::new(vec![]);
    let worker = Worker::new(h.store.clone(), fake.clone());
    let run = h.admit().await;
    h.drain(&worker).await;
    let before = h.due_in(run).await.unwrap();
    assert_eq!(
        complete(&h, fake.as_ref(), &Uuid::new_v4().to_string()).await,
        StatusCode::NO_CONTENT,
        "an authentic sender learns nothing about which requests exist"
    );
    assert!(!h.wait_row(run).await.unwrap().woken);
    assert!(h.due_in(run).await.unwrap() > before - 5.0);
}

#[tokio::test]
async fn an_inauthentic_or_malformed_event_is_refused_and_wakes_nothing() {
    let h = harness(true).await;
    let fake = Fake::new(vec![]);
    let worker = Worker::new(h.store.clone(), fake.clone());
    let run = h.admit().await;
    h.drain(&worker).await;
    let event = Uuid::new_v4();
    let body = completion_body(event, REQUEST);
    let mut cases: Vec<(&str, HeaderMap, Option<Vec<u8>>, StatusCode)> = vec![
        (
            "a forged token",
            completion_headers(
                "another-synthetic-token-canary-0123456789",
                RECIPIENT,
                event,
            ),
            Some(body.clone()),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "another recipient",
            completion_headers(TOKEN, "another-recipient", event),
            Some(body.clone()),
            StatusCode::UNAUTHORIZED,
        ),
        (
            "a replayed body under another event key",
            completion_headers(TOKEN, RECIPIENT, Uuid::new_v4()),
            Some(body.clone()),
            StatusCode::BAD_REQUEST,
        ),
    ];
    let mut missing = completion_headers(TOKEN, RECIPIENT, event);
    missing.remove("authorization");
    cases.push((
        "no credential",
        missing,
        Some(body.clone()),
        StatusCode::UNAUTHORIZED,
    ));
    let mut text = completion_headers(TOKEN, RECIPIENT, event);
    text.insert("content-type", HeaderValue::from_static("text/plain"));
    cases.push((
        "another media type",
        text,
        Some(body.clone()),
        StatusCode::UNSUPPORTED_MEDIA_TYPE,
    ));
    for (case, headers, body, expected) in cases {
        let response =
            receive_review_completion(&h.store, fake.as_ref(), &headers, body.as_deref()).await;
        assert_eq!(response.status(), expected, "{case}");
        assert_eq!(response.headers()["cache-control"], "no-store", "{case}");
        if expected == StatusCode::UNAUTHORIZED {
            assert_eq!(response.headers()["www-authenticate"], "Bearer", "{case}");
        }
        assert_eq!(
            response.headers()["content-type"],
            "application/problem+json",
            "{case}"
        );
        let problem: Value = serde_json::from_slice(
            &axum::body::to_bytes(response.into_body(), 4096)
                .await
                .unwrap(),
        )
        .unwrap();
        let code = match expected {
            StatusCode::UNAUTHORIZED => "authentication.refused",
            StatusCode::BAD_REQUEST => "request.invalid",
            _ => "request.unsupported-media-type",
        };
        assert_eq!(problem["code"], code, "{case}");
        assert_eq!(problem["status"], expected.as_u16(), "{case}");
        assert!(
            !problem.to_string().contains("canary"),
            "a refusal repeats no credential: {case}"
        );
    }
    assert!(!h.wait_row(run).await.unwrap().woken);
    let due = h.due_in(run).await.unwrap();
    assert!(due > 800.0, "no refused event moved the read: {due}");
    assert_eq!(fake.reads(), 1);
}

#[tokio::test]
async fn a_timeout_continues_at_its_timeout_route_and_withdraws_the_request() {
    let h = harness(true).await;
    let fake = Fake::new(vec![]);
    let worker = Worker::new(h.store.clone(), fake.clone());
    let run = h.admit().await;
    h.drain(&worker).await;
    h.sql("UPDATE {schema}.review_waits SET timeout_at=clock_timestamp()-interval '1 second'")
        .await;
    h.make_due(run).await;
    h.drain(&worker).await;
    assert_eq!(fake.reads(), 2, "a last read precedes the timeout");
    assert_eq!(
        status(&h, run).await,
        ("finished".into(), Some("withdrawn".into()), None)
    );
    assert_eq!(
        fake.operations(),
        [
            Operation::SubmitReviewRequest,
            Operation::CancelReviewRequest
        ]
    );
    assert!(h.wait_row(run).await.is_none());
}

#[tokio::test]
async fn a_result_found_by_the_last_read_wins_over_the_timeout() {
    let h = harness(true).await;
    let fake = Fake::new(vec![
        ReviewRead::Pending,
        ReviewRead::Settled(result("approved")),
    ]);
    let worker = Worker::new(h.store.clone(), fake.clone());
    let run = h.admit().await;
    h.drain(&worker).await;
    h.sql("UPDATE {schema}.review_waits SET timeout_at=clock_timestamp()-interval '1 second'")
        .await;
    h.make_due(run).await;
    h.drain(&worker).await;
    assert_eq!(
        status(&h, run).await,
        ("finished".into(), Some("notice-sent".into()), None)
    );
}

#[tokio::test]
async fn a_read_shortly_before_the_timeout_schedules_the_last_read_at_the_timeout() {
    let h = harness(true).await;
    let fake = Fake::new(vec![]);
    let worker = Worker::new(h.store.clone(), fake.clone());
    let run = h.admit().await;
    h.drain(&worker).await;
    h.sql("UPDATE {schema}.review_waits SET timeout_at=clock_timestamp()+interval '10 seconds'")
        .await;
    h.make_due(run).await;
    h.drain(&worker).await;
    assert_eq!(fake.reads(), 2);
    let due = h.due_in(run).await.expect("the wait is scheduled again");
    assert!(
        (0.0..=10.5).contains(&due),
        "the read spacing never carries the last read past the timeout: {due}"
    );
}

#[tokio::test]
async fn a_timeout_without_a_timeout_route_fails_the_run() {
    let h = harness(false).await;
    let fake = Fake::new(vec![]);
    let worker = Worker::new(h.store.clone(), fake.clone());
    let run = h.admit().await;
    h.drain(&worker).await;
    h.sql("UPDATE {schema}.review_waits SET timeout_at=clock_timestamp()-interval '1 second'")
        .await;
    h.make_due(run).await;
    h.drain(&worker).await;
    assert_eq!(
        status(&h, run).await,
        ("failed".into(), None, Some("wait-timed-out".into()))
    );
    assert!(h.wait_row(run).await.is_none());
    assert_eq!(fake.operations(), [Operation::SubmitReviewRequest]);
}

#[tokio::test]
async fn a_request_casework_no_longer_knows_or_an_expired_result_fails_with_its_own_code() {
    for (read, code) in [
        (ReviewRead::Unknown, "review-request-unknown"),
        (ReviewRead::Expired, "review-result-expired"),
    ] {
        let h = harness(true).await;
        let fake = Fake::new(vec![read]);
        let worker = Worker::new(h.store.clone(), fake.clone());
        let run = h.admit().await;
        h.drain(&worker).await;
        assert_eq!(
            status(&h, run).await,
            ("failed".into(), None, Some(code.into()))
        );
        assert!(h.wait_row(run).await.is_none(), "{code}");
        let inspection = h.store.inspect(run, "binding-a").await.unwrap();
        assert_eq!(
            inspection.recovery.reason,
            Some(RetryBlockReason::NotRecoverable),
            "{code}: an ended wait cannot read again"
        );
        let refused = h.store.retry_same(run, "binding-a").await.unwrap_err();
        assert_eq!(refused.code, "retry-refused", "{code}");
        assert_eq!(fake.reads(), 1, "{code}");
    }
}

#[tokio::test]
async fn a_failing_read_without_a_pause_waits_the_retry_ceiling_and_keeps_its_row() {
    let h = harness(true).await;
    let fake = Fake::new(vec![ReviewRead::Failed(CallOutcome::Retryable {
        code: "transport-unavailable".into(),
        retry_after: None,
    })]);
    let worker = Worker::new(h.store.clone(), fake.clone());
    let run = h.admit().await;
    h.drain(&worker).await;
    let due = h.due_in(run).await.unwrap();
    assert!(
        (295.0..=300.5).contains(&due),
        "the retry ceiling, under the 900-second check interval: {due}"
    );
    assert_eq!(status(&h, run).await.0, "running");
    assert!(h.wait_row(run).await.unwrap().read);
    h.make_due(run).await;
    h.drain(&worker).await;
    assert_eq!(fake.reads(), 2);
    assert_eq!(status(&h, run).await.0, "running");
}

#[tokio::test]
async fn failing_reads_before_the_timeout_keep_waiting_and_an_event_still_wakes_the_wait() {
    let h = harness(true).await;
    let unavailable = |retry_after| {
        ReviewRead::Failed(CallOutcome::Retryable {
            code: "transport-unavailable".into(),
            retry_after,
        })
    };
    let mut reads: Vec<ReviewRead> = (0..10).map(|_| unavailable(None)).collect();
    reads.push(unavailable(Some(std::time::Duration::from_secs(600))));
    reads.push(ReviewRead::Settled(result("approved")));
    let fake = Fake::new(reads);
    let worker = Worker::new(h.store.clone(), fake.clone());
    let run = h.admit().await;
    h.drain(&worker).await;
    for failures in 1..11 {
        assert_eq!(
            status(&h, run).await.0,
            "running",
            "{failures} failing reads spend no attempt budget"
        );
        let due = h.due_in(run).await.unwrap();
        assert!((295.0..=300.5).contains(&due), "{failures}: {due}");
        h.make_due(run).await;
        h.drain(&worker).await;
    }
    assert_eq!(fake.reads(), 11);
    assert_eq!(status(&h, run).await.0, "running");
    assert!(h.wait_row(run).await.unwrap().read);
    let due = h.due_in(run).await.unwrap();
    assert!(
        (595.0..=600.5).contains(&due),
        "a pause the product asks for is honoured: {due}"
    );
    assert_eq!(
        complete(&h, fake.as_ref(), REQUEST).await,
        StatusCode::NO_CONTENT
    );
    let due = h.due_in(run).await.unwrap();
    assert!(
        (25.0..=30.5).contains(&due),
        "a completion event brings the read forward after a failure: {due}"
    );
    h.make_due(run).await;
    h.drain(&worker).await;
    assert_eq!(fake.reads(), 12);
    assert_eq!(
        status(&h, run).await,
        ("finished".into(), Some("notice-sent".into()), None)
    );
    assert!(h.wait_row(run).await.is_none());
}

#[tokio::test]
async fn a_refused_read_holds_the_wait_for_an_operator_and_keeps_its_row() {
    let h = harness(true).await;
    let fake = Fake::new(vec![
        ReviewRead::Failed(CallOutcome::Refused {
            code: "product-forbidden".into(),
        }),
        ReviewRead::Settled(result("approved")),
    ]);
    let worker = Worker::new(h.store.clone(), fake.clone());
    let run = h.admit().await;
    h.drain(&worker).await;
    assert_eq!(
        status(&h, run).await,
        ("failed".into(), None, Some("product-forbidden".into()))
    );
    assert!(h.wait_row(run).await.is_some());
    let inspection = h.store.inspect(run, "binding-a").await.unwrap();
    assert!(inspection.recovery.retry_allowed);
    h.store.retry_same(run, "binding-a").await.unwrap();
    h.drain(&worker).await;
    assert_eq!(
        status(&h, run).await,
        ("finished".into(), Some("notice-sent".into()), None)
    );
    assert!(h.wait_row(run).await.is_none());
}

#[tokio::test]
async fn cancelling_a_waiting_run_ends_its_row() {
    let h = harness(true).await;
    let fake = Fake::new(vec![]);
    let worker = Worker::new(h.store.clone(), fake.clone());
    let run = h.admit().await;
    h.drain(&worker).await;
    assert!(h.wait_row(run).await.is_some());
    let cancelled = h
        .store
        .cancel_owned(run, &operator(), "synthetic-withdrawal")
        .await
        .unwrap();
    assert_eq!(cancelled.state, "cancelled");
    assert!(h.wait_row(run).await.is_none());
    assert_eq!(
        complete(&h, fake.as_ref(), REQUEST).await,
        StatusCode::NO_CONTENT
    );
    h.drain(&worker).await;
    assert_eq!(fake.reads(), 1);
}

#[tokio::test]
async fn cancelling_a_held_wait_ends_its_row() {
    let h = harness(true).await;
    let fake = Fake::new(vec![ReviewRead::Failed(CallOutcome::Refused {
        code: "product-forbidden".into(),
    })]);
    let worker = Worker::new(h.store.clone(), fake.clone());
    let run = h.admit().await;
    h.drain(&worker).await;
    assert_eq!(status(&h, run).await.0, "failed");
    assert!(h.wait_row(run).await.is_some());
    let cancelled = h
        .store
        .cancel_owned(run, &operator(), "synthetic-withdrawal")
        .await
        .unwrap();
    assert_eq!(cancelled.state, "cancelled");
    assert!(h.wait_row(run).await.is_none());
}

#[tokio::test]
async fn cancelling_during_a_read_ends_the_row_and_schedules_nothing() {
    let h = harness(true).await;
    let fake = Arc::new(Fake::with(vec![], false, Some(Semaphore::new(0))));
    let worker = Arc::new(Worker::new(h.store.clone(), fake.clone()));
    let run = h.admit().await;
    assert!(worker.tick().await.unwrap());
    let reading = tokio::spawn({
        let worker = worker.clone();
        async move { worker.tick().await }
    });
    fake.entered.notified().await;
    h.store
        .cancel_owned(run, &operator(), "synthetic-withdrawal")
        .await
        .unwrap();
    fake.release.as_ref().unwrap().add_permits(1);
    assert!(reading.await.unwrap().unwrap());
    assert_eq!(status(&h, run).await.0, "cancelled");
    assert!(h.wait_row(run).await.is_none());
    assert_eq!(h.job_state(run).await, "delivered", "no read is scheduled");
}

#[tokio::test]
async fn a_wait_that_reaches_the_run_deadline_expires_and_ends_its_row() {
    let h = harness(true).await;
    let fake = Fake::new(vec![]);
    let worker = Worker::new(h.store.clone(), fake.clone());
    let run = h.admit().await;
    h.drain(&worker).await;
    h.sql("UPDATE {schema}.runs SET deadline_at=clock_timestamp()-interval '1 second'")
        .await;
    h.drain(&worker).await;
    assert_eq!(
        status(&h, run).await,
        ("expired".into(), None, Some("deadline-reached".into()))
    );
    assert!(h.wait_row(run).await.is_none());
    assert_eq!(fake.reads(), 1);
}

#[tokio::test]
async fn retention_erases_a_row_that_outlived_its_run() {
    let h = harness(true).await;
    let fake = Fake::new(vec![ReviewRead::Settled(result("rejected"))]);
    let worker = Worker::new(h.store.clone(), fake.clone());
    let run = h.admit().await;
    h.drain(&worker).await;
    assert_eq!(status(&h, run).await.0, "finished");
    assert!(h.wait_row(run).await.is_none());
    // No current transition leaves a row behind a terminal run; retention
    // still erases one with the run's payload.
    h.sql("INSERT INTO {schema}.review_waits(run_id,step,wait_key,timeout_at) SELECT run_id,'await-review','outlived',clock_timestamp() FROM {schema}.runs")
        .await;
    assert!(h.wait_row(run).await.is_some());
    let cutoff = database_clock::retention_cutoff(&h.client().await).await;
    assert_eq!(
        h.store
            .retain_terminal(cutoff, 100, &operator())
            .await
            .unwrap(),
        1
    );
    assert!(h.wait_row(run).await.is_none());
}

#[tokio::test]
async fn attested_recovery_holds_a_waiting_run_and_ends_its_row_once_the_deadline_passed() {
    for past_deadline in [false, true] {
        let h = harness(true).await;
        let fake = Fake::new(vec![]);
        let worker = Worker::new(h.store.clone(), fake.clone());
        let run = h.admit().await;
        h.drain(&worker).await;
        assert!(h.wait_row(run).await.is_some());
        if past_deadline {
            h.sql("UPDATE {schema}.runs SET deadline_at=clock_timestamp()-interval '1 second'")
                .await;
        }
        h.store
            .set_restore_hold(&operator(), "synthetic-restore")
            .await
            .unwrap();
        h.store
            .complete_execution_recovery(&operator(), "synthetic-recovery", true, true)
            .await
            .unwrap();
        assert_eq!(
            status(&h, run).await,
            (
                "failed".into(),
                None,
                Some("restore-pre-command-held".into())
            ),
            "{past_deadline}"
        );
        assert_eq!(
            h.wait_row(run).await.is_some(),
            !past_deadline,
            "a held wait keeps its row only while its run can still resume"
        );
        if !past_deadline {
            h.store
                .release_restore_hold(&operator(), "synthetic-recovery")
                .await
                .unwrap();
            h.store.retry_same(run, "binding-a").await.unwrap();
            h.drain(&worker).await;
            assert_eq!(fake.reads(), 2, "the retried wait reads again");
            assert_eq!(status(&h, run).await.0, "running");
            assert!(h.wait_row(run).await.is_some());
        }
    }
}

#[tokio::test]
async fn an_acceptance_that_cannot_be_correlated_fails_the_run_before_any_wait() {
    let h = harness(true).await;
    let fake = Arc::new(Fake::with(vec![], true, None));
    let worker = Worker::new(h.store.clone(), fake.clone());
    let run = h.admit().await;
    h.drain(&worker).await;
    assert_eq!(
        status(&h, run).await,
        (
            "failed".into(),
            None,
            Some("protected-state-invalid".into())
        )
    );
    assert!(h.wait_row(run).await.is_none());
    assert_eq!(fake.reads(), 0);
}
