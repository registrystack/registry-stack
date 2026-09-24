// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
mod postgres_harness;

use std::collections::BTreeMap;
use std::io;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use axum::routing::{get, post};
use axum::{Json, Router};
use registry_breg::mutation::MutationError;
use registry_breg::review_store::{
    back_off_review_token_failure_for_test, install_review_storage_for_test, poll_one_result,
    receive_completion, reconcile_result, run_one_cancellation, run_one_submission,
    run_review_application_once_for_test, run_review_authority_once_for_test,
    schedule_cancellation_for_test, verify_retained_bindings, ReviewAuthorityClient,
    ReviewAuthorityRegistry, ReviewExecutorClient, ReviewExecutorRegistry, ReviewWorker,
};
use registry_review_client::{
    submission_digest, BearerToken, ContentDigest, PolicyBinding, ReviewAuth, ReviewClient,
    ReviewClientConfig, ReviewCompletion, ReviewCompletionType, ReviewContext, ReviewCreateRequest,
    ReviewRequestAccepted, ReviewResult, ReviewResultResponse, ReviewResultStatus,
    SourceContextBinding, SubjectBinding,
};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::sync::Notify;
use uuid::Uuid;
use zeroize::Zeroizing;

use postgres_harness::TestDatabase;

const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TRACEPARENT: &str = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01";
// The claim lease these tests pass to the one-shot executor helpers. It
// matches the production floor for a request timeout at or under two seconds.
const TEST_LEASE_SECONDS: i64 = 30;

struct SourceState {
    request_id: Uuid,
    job_id: Uuid,
    application_id: Uuid,
    malformed_first_response: bool,
    gets: AtomicUsize,
    posts: AtomicUsize,
}

struct ConvergenceState {
    denied_request_id: Uuid,
    applied_request_id: Uuid,
    application_id: Uuid,
    posts: AtomicUsize,
}

struct CompetingApplicationState {
    request_id: Uuid,
    application_id: Uuid,
    posts: AtomicUsize,
    first_entered: Notify,
    second_entered: Notify,
    release_first: Notify,
    release_second: Notify,
}

struct ExhaustedApplicationState {
    request_id: Uuid,
    discovery_status: StatusCode,
    gets: AtomicUsize,
    posts: AtomicUsize,
}

struct AuthorityState {
    producer_id: &'static str,
    expected_token: &'static str,
    expected_profile: &'static str,
    accepted_request_id: Uuid,
    requests: AtomicUsize,
    gate: Option<Arc<RemoteGate>>,
}

#[derive(Default)]
struct RemoteGate {
    entered: Notify,
    release: Notify,
}

#[derive(Clone, Default)]
struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

impl CapturedLogs {
    fn text(&self) -> String {
        String::from_utf8(self.0.lock().expect("captured logs").clone()).expect("UTF-8 logs")
    }
}

impl io::Write for CapturedLogs {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0
            .lock()
            .map_err(|_| io::Error::other("captured log buffer poisoned"))?
            .extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for CapturedLogs {
    type Writer = Self;

    fn make_writer(&'writer self) -> Self::Writer {
        self.clone()
    }
}

async fn accept_review_submission(
    State(state): State<Arc<AuthorityState>>,
    headers: HeaderMap,
    Json(request): Json<ReviewCreateRequest>,
) -> impl IntoResponse {
    assert_eq!(
        headers
            .get("authorization")
            .and_then(|value| value.to_str().ok()),
        Some(state.expected_token)
    );
    assert_eq!(
        headers
            .get("registry-casework-profile")
            .and_then(|value| value.to_str().ok()),
        Some(state.expected_profile)
    );
    state.requests.fetch_add(1, Ordering::SeqCst);
    if let Some(gate) = &state.gate {
        gate.entered.notify_one();
        gate.release.notified().await;
    }
    let digest = submission_digest(state.producer_id, &request.subject.source, &request)
        .expect("submission digest");
    (
        StatusCode::CREATED,
        [("traceparent", TRACEPARENT)],
        Json(json!({
            "requestId": state.accepted_request_id,
            "subject": request.subject,
            "policy": {"id":request.kind,"version":"1","digest":DIGEST},
            "submissionDigest": digest,
        })),
    )
}

async fn pending_review_result(
    State(state): State<Arc<AuthorityState>>,
    Path(request_id): Path<Uuid>,
) -> impl IntoResponse {
    assert_eq!(request_id, state.accepted_request_id);
    let gate = state.gate.as_ref().expect("remote gate");
    gate.entered.notify_one();
    gate.release.notified().await;
    (StatusCode::ACCEPTED, [("traceparent", TRACEPARENT)])
}

async fn serve_authority(
    state: Arc<AuthorityState>,
) -> (reqwest::Url, tokio::task::JoinHandle<()>) {
    let app = Router::new()
        .route("/v1/review-requests", post(accept_review_submission))
        .route(
            "/v1/review-requests/{request_id}/result",
            get(pending_review_result),
        )
        .with_state(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let endpoint = format!("http://{}/", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (endpoint, server)
}

async fn fail_review_submission(
    State(gate): State<Arc<RemoteGate>>,
    Json(_request): Json<ReviewCreateRequest>,
) -> StatusCode {
    gate.entered.notify_one();
    gate.release.notified().await;
    StatusCode::SERVICE_UNAVAILABLE
}

async fn serve_failing_authority(
    gate: Arc<RemoteGate>,
) -> (reqwest::Url, tokio::task::JoinHandle<()>) {
    let app = Router::new()
        .route("/v1/review-requests", post(fail_review_submission))
        .with_state(gate);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let endpoint = format!("http://{}/", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (endpoint, server)
}

async fn refuse_review_submission(Json(_request): Json<ReviewCreateRequest>) -> impl IntoResponse {
    (
        StatusCode::CONFLICT,
        [
            ("content-type", "application/problem+json"),
            ("traceparent", TRACEPARENT),
        ],
        Json(json!({
            "type": "https://id.registrystack.org/problems/registry-casework/review/submission-conflict",
            "title": "Conflicting request",
            "status": 409,
            "detail": "The review submission conflicts with retained work.",
            "code": "review.submission-conflict",
            "traceId": "0123456789abcdef0123456789abcdef"
        })),
    )
}

async fn serve_refusing_authority() -> (reqwest::Url, tokio::task::JoinHandle<()>) {
    let app = Router::new().route("/v1/review-requests", post(refuse_review_submission));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let endpoint = format!("http://{}/", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (endpoint, server)
}

async fn recover_review_submission_after_gateway_failure(
    State(attempts): State<Arc<AtomicUsize>>,
    headers: HeaderMap,
    Json(request): Json<ReviewCreateRequest>,
) -> axum::response::Response {
    let expected_idempotency_key = format!("submit-{}", request.subject.id);
    assert_eq!(
        headers
            .get("idempotency-key")
            .and_then(|value| value.to_str().ok()),
        Some(expected_idempotency_key.as_str())
    );
    if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
        return (
            StatusCode::BAD_GATEWAY,
            [("content-type", "text/html")],
            "<html>temporary gateway failure</html>",
        )
            .into_response();
    }
    let digest = submission_digest("producer-a", &request.subject.source, &request)
        .expect("submission digest");
    (
        StatusCode::CREATED,
        [("traceparent", TRACEPARENT)],
        Json(json!({
            "requestId": Uuid::from_u128(0xc9),
            "subject": request.subject,
            "policy": {"id":request.kind,"version":"1","digest":DIGEST},
            "submissionDigest": digest,
        })),
    )
        .into_response()
}

async fn serve_recovering_gateway_authority(
) -> (reqwest::Url, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let attempts = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route(
            "/v1/review-requests",
            post(recover_review_submission_after_gateway_failure),
        )
        .with_state(Arc::clone(&attempts));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let endpoint = format!("http://{}/", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (endpoint, attempts, server)
}

async fn recover_review_submission_after_rate_limit(
    State(attempts): State<Arc<AtomicUsize>>,
    headers: HeaderMap,
    Json(request): Json<ReviewCreateRequest>,
) -> axum::response::Response {
    let expected_idempotency_key = format!("submit-{}", request.subject.id);
    assert_eq!(
        headers
            .get("idempotency-key")
            .and_then(|value| value.to_str().ok()),
        Some(expected_idempotency_key.as_str())
    );
    if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
        return (
            StatusCode::TOO_MANY_REQUESTS,
            [
                ("content-type", "application/problem+json"),
                ("traceparent", TRACEPARENT),
            ],
            Json(json!({
                "type": "https://casework.example.test/problems/request-rate-limited",
                "title": "Request rate limited",
                "status": 429,
                "detail": "Retry the exact idempotent submission later.",
                "code": "request.rate-limited",
                "traceId": "0123456789abcdef0123456789abcdef"
            })),
        )
            .into_response();
    }
    let digest = submission_digest("producer-a", &request.subject.source, &request)
        .expect("submission digest");
    (
        StatusCode::CREATED,
        [("traceparent", TRACEPARENT)],
        Json(json!({
            "requestId": Uuid::from_u128(0xcb),
            "subject": request.subject,
            "policy": {"id":request.kind,"version":"1","digest":DIGEST},
            "submissionDigest": digest,
        })),
    )
        .into_response()
}

async fn serve_rate_limited_authority(
) -> (reqwest::Url, Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
    let attempts = Arc::new(AtomicUsize::new(0));
    let app = Router::new()
        .route(
            "/v1/review-requests",
            post(recover_review_submission_after_rate_limit),
        )
        .with_state(Arc::clone(&attempts));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let endpoint = format!("http://{}/", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (endpoint, attempts, server)
}

async fn fail_review_cancellation(
    State(gate): State<Arc<RemoteGate>>,
    Json(_request): Json<Value>,
) -> StatusCode {
    gate.entered.notify_one();
    gate.release.notified().await;
    StatusCode::SERVICE_UNAVAILABLE
}

async fn serve_failing_cancellation(
    gate: Arc<RemoteGate>,
) -> (reqwest::Url, tokio::task::JoinHandle<()>) {
    let app = Router::new()
        .route(
            "/v1/review-requests/{request_id}/cancel",
            post(fail_review_cancellation),
        )
        .with_state(gate);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let endpoint = format!("http://{}/", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (endpoint, server)
}

async fn accept_review_cancellation(
    State(accepted): State<Arc<Value>>,
    Path(request_id): Path<Uuid>,
    Json(cancellation): Json<Value>,
) -> impl IntoResponse {
    assert_eq!(accepted["requestId"], request_id.to_string());
    assert_eq!(cancellation["subject"], accepted["subject"]);
    (
        StatusCode::OK,
        [("traceparent", TRACEPARENT)],
        Json(json!({
            "outcome": "cancelled",
            "result": {
                "resultId": Uuid::from_u128(0xc7),
                "requestId": request_id,
                "subject": accepted["subject"].clone(),
                "policy": accepted["policy"].clone(),
                "submissionDigest": accepted["submissionDigest"].clone(),
                "status": "cancelled",
                "completedAt": "2026-09-20T00:00:00Z",
                "availableUntil": "2030-09-20T00:00:00Z"
            }
        })),
    )
}

async fn serve_successful_cancellation(
    accepted: Value,
) -> (reqwest::Url, tokio::task::JoinHandle<()>) {
    let app = Router::new()
        .route(
            "/v1/review-requests/{request_id}/cancel",
            post(accept_review_cancellation),
        )
        .with_state(Arc::new(accepted));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let endpoint = format!("http://{}/", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (endpoint, server)
}

struct AvailableResultState {
    accepted: Value,
    lookups: AtomicUsize,
}

async fn empty_result_feed() -> impl IntoResponse {
    (
        StatusCode::OK,
        [("traceparent", TRACEPARENT)],
        Json(json!({"items": [], "nextCursor": null})),
    )
}

async fn available_review_result(
    State(state): State<Arc<AvailableResultState>>,
    Path(request_id): Path<Uuid>,
) -> impl IntoResponse {
    assert_eq!(state.accepted["requestId"], request_id.to_string());
    state.lookups.fetch_add(1, Ordering::SeqCst);
    (
        StatusCode::OK,
        [("traceparent", TRACEPARENT)],
        Json(json!({
            "resultId": Uuid::from_u128(0xb3),
            "requestId": request_id,
            "subject": state.accepted["subject"].clone(),
            "policy": state.accepted["policy"].clone(),
            "submissionDigest": state.accepted["submissionDigest"].clone(),
            "status": "approved",
            "completedAt": "2026-09-20T00:00:00Z",
            "availableUntil": "2030-09-20T00:00:00Z"
        })),
    )
}

async fn serve_available_result_authority(
    accepted: Value,
) -> (
    reqwest::Url,
    Arc<AvailableResultState>,
    tokio::task::JoinHandle<()>,
) {
    let state = Arc::new(AvailableResultState {
        accepted,
        lookups: AtomicUsize::new(0),
    });
    let app = Router::new()
        .route("/v1/review-results", get(empty_result_feed))
        .route(
            "/v1/review-requests/{request_id}/result",
            get(available_review_result),
        )
        .with_state(Arc::clone(&state));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let endpoint = format!("http://{}/", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (endpoint, state, server)
}

async fn assert_backend_has_no_transaction_or_row_lock(
    observer: &tokio_postgres::Client,
    backend_pid: i32,
) {
    let activity = observer
        .query_one(
            "SELECT state,xact_start IS NULL,backend_xid IS NULL
               FROM pg_stat_activity WHERE pid=$1",
            &[&backend_pid],
        )
        .await
        .expect("worker backend remains observable during remote wait");
    assert_eq!(activity.get::<_, String>(0), "idle");
    assert!(
        activity.get::<_, bool>(1),
        "remote wait must not retain a transaction"
    );
    assert!(
        activity.get::<_, bool>(2),
        "remote wait must not retain a transaction ID"
    );
    let row_locks = observer
        .query_one(
            "SELECT count(*) FROM pg_locks
              WHERE pid=$1 AND granted AND locktype IN ('tuple','transactionid')",
            &[&backend_pid],
        )
        .await
        .expect("worker locks remain observable")
        .get::<_, i64>(0);
    assert_eq!(
        row_locks, 0,
        "remote wait must not retain a row or transaction lock"
    );
}

fn authority_client(endpoint: reqwest::Url, _profile: &str) -> ReviewClient {
    ReviewClient::new(
        ReviewClientConfig::new(endpoint).with_request_timeout(Duration::from_secs(2)),
    )
    .expect("review client")
}

fn authority_registry(
    authority: &str,
    producer_id: &str,
    completion_token: &str,
    completion_recipient: &str,
) -> Arc<ReviewAuthorityRegistry> {
    let client = ReviewClient::new(ReviewClientConfig::new(
        "http://127.0.0.1:9/".parse().expect("loopback URL"),
    ))
    .expect("review client");
    let configured = Arc::new(
        ReviewAuthorityClient::new(
            authority.to_owned(),
            client,
            Arc::new(
                registry_platform_httputil::StaticToken::new("outgoing-token".to_owned())
                    .expect("outgoing token"),
            ),
            "producer-profile".to_owned(),
            producer_id.to_owned(),
            7,
            Some(Zeroizing::new(completion_token.to_owned())),
            Some(completion_recipient.to_owned()),
        )
        .expect("review authority"),
    );
    Arc::new(
        ReviewAuthorityRegistry::new(BTreeMap::from([(authority.to_owned(), configured)]))
            .expect("authority registry"),
    )
}

fn create_request(request_id: Uuid, policy_id: &str) -> ReviewCreateRequest {
    ReviewCreateRequest {
        kind: policy_id.to_owned(),
        subject: SubjectBinding {
            source: "registry-a".to_owned(),
            subject_type: "change-request".to_owned(),
            id: request_id.to_string(),
            version: "1".to_owned(),
            digest: ContentDigest::parse(DIGEST).unwrap(),
        },
        requester_reference: format!("requester-{request_id}"),
        initiator: None,
        context: ReviewContext::Source {
            binding: SourceContextBinding {
                reference: format!("breg:registry-a:requests:{request_id}:1"),
            },
        },
        result_constraints: None,
    }
}

async fn seed_submission(
    client: &tokio_postgres::Client,
    request_id: Uuid,
    authority: &str,
    producer_id: &str,
    policy_id: &str,
) {
    let request = create_request(request_id, policy_id);
    let digest = submission_digest(producer_id, "registry-a", &request).unwrap();
    client
        .execute(
            "INSERT INTO registry_internal.registry_request_proposals VALUES ('requests',$1,1)",
            &[&request_id],
        )
        .await
        .expect("proposal");
    client
        .execute(
            "INSERT INTO registry_internal.registry_request_review_submissions
             (request_entity_id,request_id,proposal_version,proposal_digest,job_id,authority,
              producer_id,policy_id,idempotency_key,create_request,expected_submission_digest,
              on_approved_mode,executor,state)
             VALUES ('requests',$1,1,$2,$3,$4,$5,$6,$7,$8,$9,'manual',NULL,'pending')",
            &[
                &request_id,
                &DIGEST,
                &Uuid::new_v4(),
                &authority,
                &producer_id,
                &policy_id,
                &format!("submit-{request_id}"),
                &serde_json::to_value(request).unwrap(),
                &digest.as_str(),
            ],
        )
        .await
        .expect("review submission");
}

async fn read_request(
    State(state): State<Arc<SourceState>>,
    Path(request_id): Path<Uuid>,
    headers: HeaderMap,
) -> impl IntoResponse {
    assert_eq!(request_id, state.request_id);
    assert_eq!(
        headers
            .get("authorization")
            .and_then(|value| value.to_str().ok()),
        Some("Bearer ordinary-executor-token")
    );
    state.gets.fetch_add(1, Ordering::SeqCst);
    Json(json!({
        "data": {
            "recordIdentifier": request_id,
            "revisionIdentifier": "3",
            "domainData": {},
            "request": {
                "bregState": "submitted",
                "proposalVersion": 7,
                "effectDigest": DIGEST,
                "editable": false,
                "actions": [{
                    "operation": "apply_request",
                    "method": "POST",
                    "href": format!(
                        "/v1/records/requests/{request_id}/actions/apply?accessProfile=automatic-applier"
                    ),
                    "ifMatch": "\"breg-request-etag\"",
                    "proposalVersion": 7,
                    "effectDigest": DIGEST,
                }]
            }
        },
        "meta": {
            "registryIdentifier": "registry-a",
            "datasetIdentifier": "requests",
            "entityTypeIdentifier": "requests"
        }
    }))
}

async fn apply_request(
    State(state): State<Arc<SourceState>>,
    Path(request_id): Path<Uuid>,
    headers: HeaderMap,
    Json(body): Json<Value>,
) -> axum::response::Response {
    assert_eq!(request_id, state.request_id);
    assert_eq!(
        headers
            .get("authorization")
            .and_then(|value| value.to_str().ok()),
        Some("Bearer ordinary-executor-token")
    );
    assert_eq!(
        headers
            .get("idempotency-key")
            .and_then(|value| value.to_str().ok()),
        Some(format!("review-apply-{}", state.job_id).as_str())
    );
    assert_eq!(body, json!({"proposalVersion": 7, "effectDigest": DIGEST}));
    if state.posts.fetch_add(1, Ordering::SeqCst) == 0 {
        if state.malformed_first_response {
            return (StatusCode::OK, Json(json!({"unexpected": "response"}))).into_response();
        }
        // Model a source commit followed by a connection loss. The restart
        // must retry the exact idempotency key and recover this receipt without
        // rediscovering the action or consulting Casework.
        panic!("synthetic lost response after source commit");
    }
    (
        StatusCode::OK,
        Json(json!({
            "id": request_id,
            "revision": 4,
            "snapshot": "breg1_00000000-0000-4000-8000-000000000004",
            "actorReference": "ordinary-executor",
            "request": {
                "bregState": "applied",
                "proposalVersion": 7,
                "effectDigest": DIGEST,
                "application": {
                    "applicationId": state.application_id,
                    "proposalVersion": 7,
                    "effectDigest": DIGEST,
                    "appliedAt": "2026-09-20T00:00:00Z"
                }
            }
        })),
    )
        .into_response()
}

async fn read_convergence_request(
    State(state): State<Arc<ConvergenceState>>,
    Path(request_id): Path<Uuid>,
) -> axum::response::Response {
    if request_id == state.denied_request_id {
        return StatusCode::FORBIDDEN.into_response();
    }
    assert_eq!(request_id, state.applied_request_id);
    Json(json!({
        "data": {
            "recordIdentifier": request_id,
            "revisionIdentifier": "4",
            "domainData": {},
            "request": {
                "bregState": "applied",
                "proposalVersion": 7,
                "effectDigest": DIGEST,
                "editable": false,
                "application": {
                    "applicationId": state.application_id,
                    "proposalVersion": 7,
                    "reasonPresent": false
                }
            }
        },
        "meta": {
            "registryIdentifier": "registry-a",
            "datasetIdentifier": "requests",
            "entityTypeIdentifier": "requests"
        }
    }))
    .into_response()
}

async fn reject_unexpected_apply(State(state): State<Arc<ConvergenceState>>) -> impl IntoResponse {
    state.posts.fetch_add(1, Ordering::SeqCst);
    StatusCode::INTERNAL_SERVER_ERROR
}

async fn read_competing_application(
    State(state): State<Arc<CompetingApplicationState>>,
    Path(request_id): Path<Uuid>,
) -> impl IntoResponse {
    assert_eq!(request_id, state.request_id);
    Json(json!({
        "data": {
            "recordIdentifier": request_id,
            "revisionIdentifier": "3",
            "domainData": {},
            "request": {
                "bregState": "submitted",
                "proposalVersion": 7,
                "effectDigest": DIGEST,
                "editable": false,
                "actions": [{
                    "operation": "apply_request",
                    "method": "POST",
                    "href": format!(
                        "/v1/records/requests/{request_id}/actions/apply?accessProfile=automatic-applier"
                    ),
                    "ifMatch": "\"breg-request-etag\"",
                    "proposalVersion": 7,
                    "effectDigest": DIGEST,
                }]
            }
        },
        "meta": {
            "registryIdentifier": "registry-a",
            "datasetIdentifier": "requests",
            "entityTypeIdentifier": "requests"
        }
    }))
}

async fn apply_competing_application(
    State(state): State<Arc<CompetingApplicationState>>,
    Path(request_id): Path<Uuid>,
) -> axum::response::Response {
    assert_eq!(request_id, state.request_id);
    match state.posts.fetch_add(1, Ordering::SeqCst) {
        0 => {
            state.first_entered.notify_one();
            state.release_first.notified().await;
            StatusCode::FORBIDDEN.into_response()
        }
        1 => {
            state.second_entered.notify_one();
            state.release_second.notified().await;
            (
                StatusCode::OK,
                Json(json!({
                    "id": request_id,
                    "revision": 4,
                    "snapshot": "breg1_00000000-0000-4000-8000-000000000024",
                    "actorReference": "ordinary-executor",
                    "request": {
                        "bregState": "applied",
                        "proposalVersion": 7,
                        "effectDigest": DIGEST,
                        "application": {
                            "applicationId": state.application_id,
                            "proposalVersion": 7,
                            "effectDigest": DIGEST,
                            "appliedAt": "2026-09-20T00:00:00Z"
                        }
                    }
                })),
            )
                .into_response()
        }
        request => panic!("unexpected automatic application request {request}"),
    }
}

async fn read_exhausted_application(
    State(state): State<Arc<ExhaustedApplicationState>>,
    Path(request_id): Path<Uuid>,
) -> axum::response::Response {
    assert_eq!(request_id, state.request_id);
    state.gets.fetch_add(1, Ordering::SeqCst);
    if state.discovery_status != StatusCode::OK {
        return state.discovery_status.into_response();
    }
    Json(json!({
        "data": {
            "recordIdentifier": request_id,
            "revisionIdentifier": "3",
            "domainData": {},
            "request": {
                "bregState": "submitted",
                "proposalVersion": 7,
                "effectDigest": DIGEST,
                "editable": false,
                "actions": [{
                    "operation": "apply_request",
                    "method": "POST",
                    "href": format!(
                        "/v1/records/requests/{request_id}/actions/apply?accessProfile=automatic-applier"
                    ),
                    "ifMatch": "\"breg-request-etag\"",
                    "proposalVersion": 7,
                    "effectDigest": DIGEST,
                }]
            }
        },
        "meta": {
            "registryIdentifier": "registry-a",
            "datasetIdentifier": "requests",
            "entityTypeIdentifier": "requests"
        }
    }))
    .into_response()
}

async fn reject_exhausted_application(
    State(state): State<Arc<ExhaustedApplicationState>>,
) -> impl IntoResponse {
    state.posts.fetch_add(1, Ordering::SeqCst);
    StatusCode::PRECONDITION_FAILED
}

async fn read_transiently_unavailable(State(gets): State<Arc<AtomicUsize>>) -> impl IntoResponse {
    gets.fetch_add(1, Ordering::SeqCst);
    StatusCode::SERVICE_UNAVAILABLE
}

fn executor(endpoint: reqwest::Url) -> ReviewExecutorClient {
    executor_with_timeout(endpoint, Duration::from_secs(2))
}

fn executor_with_timeout(endpoint: reqwest::Url, timeout: Duration) -> ReviewExecutorClient {
    ReviewExecutorClient::new(
        "registry-automatic".to_owned(),
        endpoint,
        BearerToken::new("ordinary-executor-token").expect("token"),
        "registry-a".to_owned(),
        "automatic-applier".to_owned(),
        BTreeMap::from([("requests".to_owned(), "requests".to_owned())]),
        timeout,
    )
    .expect("executor")
}

async fn seed_application_job(
    client: &tokio_postgres::Client,
    request_id: Uuid,
    result_id: Uuid,
    job_id: Uuid,
) {
    client
        .execute(
            "INSERT INTO registry_internal.registry_request_proposals VALUES ('requests',$1,7)",
            &[&request_id],
        )
        .await
        .expect("proposal");
    client
        .execute(
            "INSERT INTO registry_internal.registry_request_review_submissions
         (request_entity_id,request_id,proposal_version,proposal_digest,job_id,authority,
          producer_id,policy_id,idempotency_key,create_request,expected_submission_digest,
          on_approved_mode,executor,state,accepted_binding)
         VALUES ('requests',$1,7,$2,$3,'casework-a','registry-producer','policy-a',
                 $4,'{}'::jsonb,$2,'automatic','registry-automatic','accepted','{}'::jsonb)",
            &[
                &request_id,
                &DIGEST,
                &Uuid::new_v4(),
                &format!("submission-{job_id}"),
            ],
        )
        .await
        .expect("submission");
    client
        .execute(
            "INSERT INTO registry_internal.registry_request_review_results
         (request_entity_id,request_id,proposal_version,authority,result_id,result,status,
          completed_at,available_until)
         VALUES ('requests',$1,7,'casework-a',$2,'{}'::jsonb,'approved',
                 transaction_timestamp(),transaction_timestamp()+interval '1 day')",
            &[&request_id, &result_id],
        )
        .await
        .expect("result");
    client
        .execute(
            "INSERT INTO registry_internal.registry_request_application_jobs
         (request_entity_id,request_id,proposal_version,job_id,proposal_digest,result_id,
          executor,state)
         VALUES ('requests',$1,7,$2,$3,$4,'registry-automatic','queued')",
            &[&request_id, &job_id, &DIGEST, &result_id],
        )
        .await
        .expect("application job");
}

#[tokio::test]
async fn real_postgres_lost_apply_response_recovers_source_receipt_before_rediscovery() {
    let mut database = TestDatabase::create(2).await;
    database
        .admin
        .batch_execute(
            "CREATE TABLE registry_internal.registry_request_state (
                request_entity_id text NOT NULL,
                request_id uuid NOT NULL,
                proposal_version bigint NOT NULL,
                state text NOT NULL,
                PRIMARY KEY (request_entity_id,request_id)
            );
            CREATE TABLE registry_internal.registry_request_proposals (
                request_entity_id text NOT NULL,
                request_id uuid NOT NULL,
                proposal_version bigint NOT NULL,
                PRIMARY KEY (request_entity_id,request_id,proposal_version)
            );",
        )
        .await
        .expect("proposal parent table");
    install_review_storage_for_test(&database.admin, &database.runtime_role)
        .await
        .expect("review storage");

    let request_id = Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap();
    let result_id = Uuid::parse_str("00000000-0000-4000-8000-000000000002").unwrap();
    let job_id = Uuid::parse_str("00000000-0000-4000-8000-000000000003").unwrap();
    let application_id = Uuid::parse_str("00000000-0000-4000-8000-000000000005").unwrap();
    database
        .admin
        .execute(
            "INSERT INTO registry_internal.registry_request_proposals VALUES ('requests',$1,7)",
            &[&request_id],
        )
        .await
        .expect("proposal");
    database
        .admin
        .execute(
            "INSERT INTO registry_internal.registry_request_review_submissions
         (request_entity_id,request_id,proposal_version,proposal_digest,job_id,authority,
          producer_id,policy_id,idempotency_key,create_request,expected_submission_digest,
          on_approved_mode,executor,state,accepted_binding)
         VALUES ('requests',$1,7,$2,$3,'casework-a','registry-producer','policy-a',
                 'submission-key','{}'::jsonb,$2::text,'automatic','registry-automatic',
                 'accepted','{}'::jsonb)",
            &[&request_id, &DIGEST, &Uuid::new_v4()],
        )
        .await
        .expect("submission");
    database
        .admin
        .execute(
            "INSERT INTO registry_internal.registry_request_review_results
         (request_entity_id,request_id,proposal_version,authority,result_id,result,status,
          completed_at,available_until)
         VALUES ('requests',$1,7,'casework-a',$2,'{}'::jsonb,'approved',
                 transaction_timestamp(),transaction_timestamp()+interval '1 day')",
            &[&request_id, &result_id],
        )
        .await
        .expect("result");
    database
        .admin
        .execute(
            "INSERT INTO registry_internal.registry_request_application_jobs
         (request_entity_id,request_id,proposal_version,job_id,proposal_digest,result_id,
          executor,state)
         VALUES ('requests',$1,7,$2,$3,$4,'registry-automatic','queued')",
            &[&request_id, &job_id, &DIGEST, &result_id],
        )
        .await
        .expect("application job");

    let source = Arc::new(SourceState {
        request_id,
        job_id,
        application_id,
        malformed_first_response: false,
        gets: AtomicUsize::new(0),
        posts: AtomicUsize::new(0),
    });
    let app = Router::new()
        .route("/v1/records/requests/{request_id}", get(read_request))
        .route(
            "/v1/records/requests/{request_id}/actions/apply",
            post(apply_request),
        )
        .with_state(Arc::clone(&source));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let endpoint: reqwest::Url = format!("http://{}/", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await });

    let first = executor(endpoint.clone());
    assert!(
        run_review_application_once_for_test(&mut database.admin, &first)
            .await
            .expect("first attempt claimed")
    );
    let row = database
        .admin
        .query_one(
            "SELECT state,action_href IS NOT NULL,action_if_match IS NOT NULL
           FROM registry_internal.registry_request_application_jobs WHERE job_id=$1",
            &[&job_id],
        )
        .await
        .expect("durable first attempt");
    assert_eq!(row.get::<_, String>(0), "applying");
    assert!(row.get::<_, bool>(1));
    assert!(row.get::<_, bool>(2));
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_request_application_jobs
            SET next_attempt_at=transaction_timestamp() WHERE job_id=$1",
            &[&job_id],
        )
        .await
        .expect("expire lease for restart");

    let restarted = executor(endpoint);
    assert!(
        run_review_application_once_for_test(&mut database.admin, &restarted)
            .await
            .expect("restart recovers receipt")
    );
    let row = database
        .admin
        .query_one(
            "SELECT state,application_id,attempt_count
           FROM registry_internal.registry_request_application_jobs WHERE job_id=$1",
            &[&job_id],
        )
        .await
        .expect("terminal job");
    assert_eq!(row.get::<_, String>(0), "applied");
    assert_eq!(row.get::<_, Uuid>(1), application_id);
    assert_eq!(row.get::<_, i32>(2), 2);
    assert_eq!(source.gets.load(Ordering::SeqCst), 1);
    assert_eq!(source.posts.load(Ordering::SeqCst), 2);

    server.abort();
    database.cleanup().await;
}

#[tokio::test]
async fn real_postgres_application_claims_size_the_lease_from_the_outbound_timeout() {
    let mut database = TestDatabase::create(2).await;
    database
        .admin
        .batch_execute(
            "CREATE TABLE registry_internal.registry_request_proposals (
                request_entity_id text NOT NULL,
                request_id uuid NOT NULL,
                proposal_version bigint NOT NULL,
                PRIMARY KEY (request_entity_id,request_id,proposal_version)
            );",
        )
        .await
        .expect("proposal parent table");
    install_review_storage_for_test(&database.admin, &database.runtime_role)
        .await
        .expect("review storage");

    let request_id = Uuid::from_u128(0x21);
    let job_id = Uuid::from_u128(0x22);
    seed_application_job(&database.admin, request_id, Uuid::new_v4(), job_id).await;

    // An unroutable endpoint fails the discovery read without a server: the
    // job stays claimed while the claim lease must cover a request timeout
    // configured above the previous fixed lease.
    let endpoint: reqwest::Url = "http://127.0.0.1:9/".parse().expect("unroutable endpoint");
    let configured = executor_with_timeout(endpoint, Duration::from_secs(60));
    assert!(
        run_review_application_once_for_test(&mut database.admin, &configured)
            .await
            .expect("claim starts one application")
    );
    let leased = database
        .admin
        .query_one(
            "SELECT state, next_attempt_at-transaction_timestamp() > interval '45 seconds'
           FROM registry_internal.registry_request_application_jobs WHERE job_id=$1",
            &[&job_id],
        )
        .await
        .expect("claimed application job");
    assert_eq!(leased.get::<_, String>(0), "applying");
    assert!(
        leased.get::<_, bool>(1),
        "the claim lease must outlive a 60 second outbound request"
    );

    database.cleanup().await;
}

#[tokio::test]
async fn real_postgres_nonconforming_successful_apply_response_remains_retryable() {
    let mut database = TestDatabase::create(2).await;
    database
        .admin
        .batch_execute(
            "CREATE TABLE registry_internal.registry_request_proposals (
                request_entity_id text NOT NULL,
                request_id uuid NOT NULL,
                proposal_version bigint NOT NULL,
                PRIMARY KEY (request_entity_id,request_id,proposal_version)
            );",
        )
        .await
        .expect("proposal parent table");
    install_review_storage_for_test(&database.admin, &database.runtime_role)
        .await
        .expect("review storage");

    let request_id = Uuid::from_u128(0x11);
    let job_id = Uuid::from_u128(0x12);
    let application_id = Uuid::from_u128(0x13);
    seed_application_job(&database.admin, request_id, Uuid::new_v4(), job_id).await;

    let source = Arc::new(SourceState {
        request_id,
        job_id,
        application_id,
        malformed_first_response: true,
        gets: AtomicUsize::new(0),
        posts: AtomicUsize::new(0),
    });
    let app = Router::new()
        .route("/v1/records/requests/{request_id}", get(read_request))
        .route(
            "/v1/records/requests/{request_id}/actions/apply",
            post(apply_request),
        )
        .with_state(Arc::clone(&source));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let endpoint: reqwest::Url = format!("http://{}/", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await });

    let configured = executor(endpoint.clone());
    assert!(
        run_review_application_once_for_test(&mut database.admin, &configured)
            .await
            .expect("ambiguous successful response remains handled")
    );
    let retryable = database
        .admin
        .query_one(
            "SELECT state,attempt_count,claim_token IS NOT NULL,last_error_code,
                    action_href IS NOT NULL,action_if_match IS NOT NULL
               FROM registry_internal.registry_request_application_jobs WHERE job_id=$1",
            &[&job_id],
        )
        .await
        .expect("retryable application job");
    assert_eq!(retryable.get::<_, String>(0), "applying");
    assert_eq!(retryable.get::<_, i32>(1), 1);
    assert!(retryable.get::<_, bool>(2));
    assert_eq!(retryable.get::<_, Option<String>>(3), None);
    assert!(retryable.get::<_, bool>(4));
    assert!(retryable.get::<_, bool>(5));

    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_request_application_jobs
                SET next_attempt_at=transaction_timestamp() WHERE job_id=$1",
            &[&job_id],
        )
        .await
        .expect("make the idempotent retry due");
    assert!(
        run_review_application_once_for_test(&mut database.admin, &executor(endpoint))
            .await
            .expect("idempotent retry recovers the receipt")
    );
    let applied = database
        .admin
        .query_one(
            "SELECT state,application_id,attempt_count
               FROM registry_internal.registry_request_application_jobs WHERE job_id=$1",
            &[&job_id],
        )
        .await
        .expect("applied job");
    assert_eq!(applied.get::<_, String>(0), "applied");
    assert_eq!(applied.get::<_, Uuid>(1), application_id);
    assert_eq!(applied.get::<_, i32>(2), 2);
    assert_eq!(source.gets.load(Ordering::SeqCst), 1);
    assert_eq!(source.posts.load(Ordering::SeqCst), 2);

    server.abort();
    database.cleanup().await;
}

#[tokio::test]
async fn real_postgres_automatic_application_claim_fences_stale_owner() {
    let database = TestDatabase::create(4).await;
    database
        .admin
        .batch_execute(
            "CREATE TABLE registry_internal.registry_request_proposals (
                request_entity_id text NOT NULL,
                request_id uuid NOT NULL,
                proposal_version bigint NOT NULL,
                PRIMARY KEY (request_entity_id,request_id,proposal_version)
            );",
        )
        .await
        .expect("proposal parent table");
    install_review_storage_for_test(&database.admin, &database.runtime_role)
        .await
        .expect("review storage");

    let request_id = Uuid::parse_str("00000000-0000-4000-8000-000000000021").unwrap();
    let job_id = Uuid::parse_str("00000000-0000-4000-8000-000000000022").unwrap();
    let application_id = Uuid::parse_str("00000000-0000-4000-8000-000000000023").unwrap();
    seed_application_job(&database.admin, request_id, Uuid::new_v4(), job_id).await;

    let source = Arc::new(CompetingApplicationState {
        request_id,
        application_id,
        posts: AtomicUsize::new(0),
        first_entered: Notify::new(),
        second_entered: Notify::new(),
        release_first: Notify::new(),
        release_second: Notify::new(),
    });
    let app = Router::new()
        .route(
            "/v1/records/requests/{request_id}",
            get(read_competing_application),
        )
        .route(
            "/v1/records/requests/{request_id}/actions/apply",
            post(apply_competing_application),
        )
        .with_state(Arc::clone(&source));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let endpoint: reqwest::Url = format!("http://{}/", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await });

    let (mut first_connection, first_connection_task) = database.connect_admin().await;
    let first_executor = executor(endpoint.clone());
    let first_worker = tokio::spawn(async move {
        let result =
            run_review_application_once_for_test(&mut first_connection, &first_executor).await;
        (first_connection, result)
    });
    source.first_entered.notified().await;
    let first_claim: Uuid = database
        .admin
        .query_one(
            "SELECT claim_token FROM registry_internal.registry_request_application_jobs
              WHERE job_id=$1",
            &[&job_id],
        )
        .await
        .expect("first worker claim")
        .get(0);
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_request_application_jobs
                SET next_attempt_at=transaction_timestamp()-interval '1 second'
              WHERE job_id=$1",
            &[&job_id],
        )
        .await
        .expect("expire first worker lease");

    let (mut second_connection, second_connection_task) = database.connect_admin().await;
    let second_executor = executor(endpoint);
    let second_worker = tokio::spawn(async move {
        let result =
            run_review_application_once_for_test(&mut second_connection, &second_executor).await;
        (second_connection, result)
    });
    source.second_entered.notified().await;
    let second_claim: Uuid = database
        .admin
        .query_one(
            "SELECT claim_token FROM registry_internal.registry_request_application_jobs
              WHERE job_id=$1",
            &[&job_id],
        )
        .await
        .expect("replacement worker claim")
        .get(0);
    assert_ne!(first_claim, second_claim);

    source.release_first.notify_one();
    let (_first_connection, first_result) = first_worker.await.expect("first worker joins");
    assert!(matches!(first_result, Err(MutationError::Unavailable)));
    let reclaimed = database
        .admin
        .query_one(
            "SELECT state,claim_token,last_error_code
               FROM registry_internal.registry_request_application_jobs WHERE job_id=$1",
            &[&job_id],
        )
        .await
        .expect("replacement claim survives stale terminal response");
    assert_eq!(reclaimed.get::<_, String>(0), "applying");
    assert_eq!(reclaimed.get::<_, Uuid>(1), second_claim);
    assert_eq!(reclaimed.get::<_, Option<String>>(2), None);

    source.release_second.notify_one();
    let (_second_connection, second_result) = second_worker.await.expect("second worker joins");
    assert!(second_result.expect("replacement worker applies"));
    let applied = database
        .admin
        .query_one(
            "SELECT state,claim_token,application_id,attempt_count
               FROM registry_internal.registry_request_application_jobs WHERE job_id=$1",
            &[&job_id],
        )
        .await
        .expect("replacement worker terminal result");
    assert_eq!(applied.get::<_, String>(0), "applied");
    assert_eq!(applied.get::<_, Option<Uuid>>(1), None);
    assert_eq!(applied.get::<_, Uuid>(2), application_id);
    assert_eq!(applied.get::<_, i32>(3), 2);
    assert_eq!(source.posts.load(Ordering::SeqCst), 2);

    first_connection_task.abort();
    second_connection_task.abort();
    server.abort();
    database.cleanup().await;
}

#[tokio::test]
async fn real_postgres_automatic_application_exhausts_transient_and_stale_retry_budgets() {
    for (name, discovery_status, expected_gets, expected_posts) in [
        ("transient", StatusCode::SERVICE_UNAVAILABLE, 1, 0),
        ("stale", StatusCode::OK, 1, 1),
    ] {
        let mut database = TestDatabase::create(2).await;
        database
            .admin
            .batch_execute(
                "CREATE TABLE registry_internal.registry_request_proposals (
                    request_entity_id text NOT NULL,
                    request_id uuid NOT NULL,
                    proposal_version bigint NOT NULL,
                    PRIMARY KEY (request_entity_id,request_id,proposal_version)
                );",
            )
            .await
            .expect("proposal parent table");
        install_review_storage_for_test(&database.admin, &database.runtime_role)
            .await
            .expect("review storage");
        let request_id = Uuid::new_v4();
        let job_id = Uuid::new_v4();
        seed_application_job(&database.admin, request_id, Uuid::new_v4(), job_id).await;
        database
            .admin
            .execute(
                "UPDATE registry_internal.registry_request_application_jobs
                    SET attempt_count=999 WHERE job_id=$1",
                &[&job_id],
            )
            .await
            .expect("job reaches its final available attempt");

        let source = Arc::new(ExhaustedApplicationState {
            request_id,
            discovery_status,
            gets: AtomicUsize::new(0),
            posts: AtomicUsize::new(0),
        });
        let app = Router::new()
            .route(
                "/v1/records/requests/{request_id}",
                get(read_exhausted_application),
            )
            .route(
                "/v1/records/requests/{request_id}/actions/apply",
                post(reject_exhausted_application),
            )
            .with_state(Arc::clone(&source));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let endpoint: reqwest::Url = format!("http://{}/", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await });
        let executor = executor(endpoint);

        assert!(
            run_review_application_once_for_test(&mut database.admin, &executor)
                .await
                .expect("final attempt settles")
        );
        let row = database
            .admin
            .query_one(
                "SELECT state,attempt_count,claim_token,last_error_code
                   FROM registry_internal.registry_request_application_jobs WHERE job_id=$1",
                &[&job_id],
            )
            .await
            .expect("exhausted job remains visible");
        assert_eq!(row.get::<_, String>(0), "blocked", "{name}");
        assert_eq!(row.get::<_, i32>(1), 1_000, "{name}");
        assert_eq!(row.get::<_, Option<Uuid>>(2), None, "{name}");
        assert_eq!(
            row.get::<_, Option<String>>(3).as_deref(),
            Some("application-attempts-exhausted"),
            "{name}"
        );
        assert!(
            !run_review_application_once_for_test(&mut database.admin, &executor)
                .await
                .expect("blocked job is not reclaimable"),
            "{name}"
        );
        assert_eq!(source.gets.load(Ordering::SeqCst), expected_gets, "{name}");
        assert_eq!(
            source.posts.load(Ordering::SeqCst),
            expected_posts,
            "{name}"
        );

        server.abort();
        database.cleanup().await;
    }
}

#[tokio::test]
async fn expired_automatic_approval_is_not_claimed_by_the_application_worker() {
    // "expired": the job has never been applied and its cached approval is
    // past `available_until`; the worker must leave it queued and untouched.
    // "unexpired" is the control: an ordinary due, queued job is still
    // claimed exactly as before.
    for (name, expired, expect_claimed) in [("expired", true, false), ("unexpired", false, true)] {
        let mut database = TestDatabase::create(2).await;
        database
            .admin
            .batch_execute(
                "CREATE TABLE registry_internal.registry_request_proposals (
                    request_entity_id text NOT NULL,
                    request_id uuid NOT NULL,
                    proposal_version bigint NOT NULL,
                    PRIMARY KEY (request_entity_id,request_id,proposal_version)
                );",
            )
            .await
            .expect("proposal parent table");
        install_review_storage_for_test(&database.admin, &database.runtime_role)
            .await
            .expect("review storage");
        let request_id = Uuid::new_v4();
        let job_id = Uuid::new_v4();
        seed_application_job(&database.admin, request_id, Uuid::new_v4(), job_id).await;
        if expired {
            database
                .admin
                .execute(
                    "UPDATE registry_internal.registry_request_review_results
                        SET completed_at=transaction_timestamp() - interval '2 days',
                            available_until=transaction_timestamp() - interval '1 day'
                      WHERE request_id=$1",
                    &[&request_id],
                )
                .await
                .expect("expire the cached approval");
        }

        let gets = Arc::new(AtomicUsize::new(0));
        let app = Router::new()
            .route(
                "/v1/records/requests/{request_id}",
                get(read_transiently_unavailable),
            )
            .with_state(Arc::clone(&gets));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let endpoint: reqwest::Url = format!("http://{}/", listener.local_addr().unwrap())
            .parse()
            .unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, app).await });
        let executor = executor(endpoint);

        let claimed = run_review_application_once_for_test(&mut database.admin, &executor)
            .await
            .expect("worker pass completes");
        assert_eq!(claimed, expect_claimed, "{name}");

        let row = database
            .admin
            .query_one(
                "SELECT state,attempt_count,claim_token
                   FROM registry_internal.registry_request_application_jobs WHERE job_id=$1",
                &[&job_id],
            )
            .await
            .expect("job row");
        if expect_claimed {
            assert_eq!(row.get::<_, String>(0), "applying", "{name}");
            assert_eq!(row.get::<_, i32>(1), 1, "{name}");
        } else {
            assert_eq!(row.get::<_, String>(0), "queued", "{name}");
            assert_eq!(row.get::<_, i32>(1), 0, "{name}");
            assert_eq!(row.get::<_, Option<Uuid>>(2), None, "{name}");
        }
        assert_eq!(
            gets.load(Ordering::SeqCst),
            usize::from(expect_claimed),
            "the executor endpoint must not be called for an unclaimed job: {name}"
        );

        // Mirrors the request-read projection's own predicate for the
        // `expired` application state (review_store::read_projection): a
        // queued job whose cached result is approved and past its
        // availability. It must hold only for the expired case, and the
        // worker pass above must not have disturbed it either way.
        let projects_expired: bool = database
            .admin
            .query_one(
                "SELECT j.state='queued' AND r.status='approved'
                        AND r.available_until <= transaction_timestamp()
                   FROM registry_internal.registry_request_application_jobs j
                   JOIN registry_internal.registry_request_review_results r
                     ON (r.request_entity_id,r.request_id,r.proposal_version)
                       =(j.request_entity_id,j.request_id,j.proposal_version)
                  WHERE j.job_id=$1",
                &[&job_id],
            )
            .await
            .expect("projection predicate")
            .get(0);
        assert_eq!(projects_expired, expired, "{name}");

        server.abort();
        database.cleanup().await;
    }
}

#[tokio::test]
async fn an_expired_automatic_approvals_queued_job_no_longer_retains_its_bindings() {
    // The activation check must treat a queued job over an expired automatic
    // approval as not durable work, the same as the application worker:
    // once such a job is inert, an operator may drop the review authority or
    // executor binding it used, separately or together, without database
    // intervention. "unexpired" is the control: an ordinary due, queued job
    // still retains both bindings and refuses activation.
    for (name, expired) in [("expired", true), ("unexpired", false)] {
        let database = TestDatabase::create(2).await;
        database
            .admin
            .batch_execute(
                "CREATE TABLE registry_internal.registry_request_state (
                    request_entity_id text NOT NULL,
                    request_id uuid NOT NULL,
                    proposal_version bigint NOT NULL,
                    state text NOT NULL,
                    PRIMARY KEY (request_entity_id,request_id)
                );
                CREATE TABLE registry_internal.registry_request_proposals (
                    request_entity_id text NOT NULL,
                    request_id uuid NOT NULL,
                    proposal_version bigint NOT NULL,
                    PRIMARY KEY (request_entity_id,request_id,proposal_version)
                );",
            )
            .await
            .expect("state and proposal parent tables");
        install_review_storage_for_test(&database.admin, &database.runtime_role)
            .await
            .expect("review storage");
        database
            .admin
            .batch_execute(&format!(
                "GRANT USAGE ON SCHEMA registry_internal TO \"{}\";
                 GRANT SELECT ON registry_internal.registry_request_state TO \"{}\";",
                database.runtime_role.as_str(),
                database.runtime_role.as_str()
            ))
            .await
            .expect("runtime review schema access");

        let request_id = Uuid::new_v4();
        let job_id = Uuid::new_v4();
        seed_application_job(&database.admin, request_id, Uuid::new_v4(), job_id).await;
        if expired {
            database
                .admin
                .execute(
                    "UPDATE registry_internal.registry_request_review_results
                        SET completed_at=transaction_timestamp() - interval '2 days',
                            available_until=transaction_timestamp() - interval '1 day'
                      WHERE request_id=$1",
                    &[&request_id],
                )
                .await
                .expect("expire the cached approval");
        }

        let pool = database.runtime_config.build_pool().expect("runtime pool");
        // Matches seed_application_job's authority and producer binding.
        let authorities =
            authority_registry("casework-a", "registry-producer", "sender", "registry-a");
        // Matches seed_application_job's executor and request-entity binding.
        let endpoint: reqwest::Url = "http://127.0.0.1:9/".parse().unwrap();
        let executors = ReviewExecutorRegistry::new(BTreeMap::from([(
            "registry-automatic".to_owned(),
            Arc::new(executor(endpoint)),
        )]))
        .expect("executor registry");

        let executor_removed = verify_retained_bindings(&pool, Some(&authorities), None).await;
        let authority_removed = verify_retained_bindings(&pool, None, Some(&executors)).await;
        let both_removed = verify_retained_bindings(&pool, None, None).await;

        if expired {
            executor_removed.unwrap_or_else(|error| {
                panic!("executor binding removed, job inert: {name}: {error:?}")
            });
            authority_removed.unwrap_or_else(|error| {
                panic!("authority binding removed, job inert: {name}: {error:?}")
            });
            both_removed.unwrap_or_else(|error| {
                panic!("both bindings removed, job inert: {name}: {error:?}")
            });
        } else {
            assert!(
                matches!(executor_removed, Err(MutationError::PreconditionFailed)),
                "{name}"
            );
            assert!(
                matches!(authority_removed, Err(MutationError::PreconditionFailed)),
                "{name}"
            );
            assert!(
                matches!(both_removed, Err(MutationError::PreconditionFailed)),
                "{name}"
            );
        }

        drop(pool);
        database.cleanup().await;
    }
}

#[tokio::test]
async fn real_postgres_review_feed_checkpoint_uses_the_client_uuid_cursor_contract() {
    let database = TestDatabase::create(2).await;
    database
        .admin
        .batch_execute(
            "CREATE TABLE registry_internal.registry_request_proposals (
                request_entity_id text NOT NULL,
                request_id uuid NOT NULL,
                proposal_version bigint NOT NULL,
                PRIMARY KEY (request_entity_id,request_id,proposal_version)
            );
            CREATE TABLE registry_internal.registry_request_review_feed_checkpoints (
                authority text PRIMARY KEY CHECK (authority <> '' AND octet_length(authority) <= 128),
                cursor text CHECK (cursor IS NULL OR (cursor <> '' AND octet_length(cursor) <= 4096)),
                updated_at timestamptz NOT NULL DEFAULT transaction_timestamp()
            );
            INSERT INTO registry_internal.registry_request_review_feed_checkpoints(authority,cursor)
            VALUES ('legacy-casework','opaque-trial-cursor');",
        )
        .await
        .expect("proposal parent and legacy checkpoint tables");
    install_review_storage_for_test(&database.admin, &database.runtime_role)
        .await
        .expect("review storage");
    let cursor_type = database
        .admin
        .query_one(
            "SELECT data_type FROM information_schema.columns
              WHERE table_schema='registry_internal'
                AND table_name='registry_request_review_feed_checkpoints'
                AND column_name='cursor'",
            &[],
        )
        .await
        .expect("checkpoint cursor type")
        .get::<_, String>(0);
    assert_eq!(cursor_type, "uuid");
    let reset_cursor = database
        .admin
        .query_one(
            "SELECT cursor FROM registry_internal.registry_request_review_feed_checkpoints
              WHERE authority='legacy-casework'",
            &[],
        )
        .await
        .expect("upgraded legacy checkpoint")
        .get::<_, Option<Uuid>>(0);
    assert_eq!(reset_cursor, None, "opaque trial cursor restarts safely");
    let accepted = Uuid::from_u128(0xc0ffee);
    database
        .admin
        .execute(
            "INSERT INTO registry_internal.registry_request_review_feed_checkpoints
             (authority,cursor) VALUES ('casework-a',$1)",
            &[&accepted],
        )
        .await
        .expect("the review client's UUID cursor persists");
    let stored = database
        .admin
        .query_one(
            "SELECT cursor FROM registry_internal.registry_request_review_feed_checkpoints
              WHERE authority='casework-a'",
            &[],
        )
        .await
        .expect("stored UUID cursor")
        .get::<_, Uuid>(0);
    assert_eq!(stored, accepted);

    install_review_storage_for_test(&database.admin, &database.runtime_role)
        .await
        .expect("review storage install is idempotent");
    let retained = database
        .admin
        .query_one(
            "SELECT cursor FROM registry_internal.registry_request_review_feed_checkpoints
              WHERE authority='casework-a'",
            &[],
        )
        .await
        .expect("current UUID checkpoint survives reinstall")
        .get::<_, Uuid>(0);
    assert_eq!(retained, accepted);

    database.cleanup().await;
}

#[tokio::test]
async fn real_postgres_executor_revocation_blocks_and_manual_apply_converges_without_post() {
    let mut database = TestDatabase::create(2).await;
    database
        .admin
        .batch_execute(
            "CREATE TABLE registry_internal.registry_request_proposals (
                request_entity_id text NOT NULL,
                request_id uuid NOT NULL,
                proposal_version bigint NOT NULL,
                PRIMARY KEY (request_entity_id,request_id,proposal_version)
            );",
        )
        .await
        .expect("proposal parent table");
    install_review_storage_for_test(&database.admin, &database.runtime_role)
        .await
        .expect("review storage");

    let denied_request_id = Uuid::parse_str("00000000-0000-4000-8000-000000000011").unwrap();
    let applied_request_id = Uuid::parse_str("00000000-0000-4000-8000-000000000012").unwrap();
    let denied_job_id = Uuid::parse_str("00000000-0000-4000-8000-000000000013").unwrap();
    let applied_job_id = Uuid::parse_str("00000000-0000-4000-8000-000000000014").unwrap();
    let application_id = Uuid::parse_str("00000000-0000-4000-8000-000000000015").unwrap();
    seed_application_job(
        &database.admin,
        denied_request_id,
        Uuid::new_v4(),
        denied_job_id,
    )
    .await;

    let source = Arc::new(ConvergenceState {
        denied_request_id,
        applied_request_id,
        application_id,
        posts: AtomicUsize::new(0),
    });
    let app = Router::new()
        .route(
            "/v1/records/requests/{request_id}",
            get(read_convergence_request),
        )
        .route(
            "/v1/records/requests/{request_id}/actions/apply",
            post(reject_unexpected_apply),
        )
        .with_state(Arc::clone(&source));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let endpoint: reqwest::Url = format!("http://{}/", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await });

    let configured = executor(endpoint);
    assert!(
        run_review_application_once_for_test(&mut database.admin, &configured)
            .await
            .expect("denied job claimed")
    );
    let denied = database
        .admin
        .query_one(
            "SELECT state,last_error_code FROM registry_internal.registry_request_application_jobs
              WHERE job_id=$1",
            &[&denied_job_id],
        )
        .await
        .expect("denied job");
    assert_eq!(denied.get::<_, String>(0), "blocked");
    assert_eq!(denied.get::<_, String>(1), "executor-denied");

    seed_application_job(
        &database.admin,
        applied_request_id,
        Uuid::new_v4(),
        applied_job_id,
    )
    .await;
    assert!(
        run_review_application_once_for_test(&mut database.admin, &configured)
            .await
            .expect("manual winner reconciled")
    );
    let applied = database
        .admin
        .query_one(
            "SELECT state,application_id,receipt_recovered
               FROM registry_internal.registry_request_application_jobs
              WHERE job_id=$1",
            &[&applied_job_id],
        )
        .await
        .expect("converged job");
    assert_eq!(applied.get::<_, String>(0), "applied");
    assert_eq!(applied.get::<_, Uuid>(1), application_id);
    assert!(applied.get::<_, bool>(2));
    assert_eq!(source.posts.load(Ordering::SeqCst), 0);

    server.abort();
    database.cleanup().await;
}

#[tokio::test]
async fn remote_review_submission_and_result_lookup_hold_no_postgres_transaction_or_row_lock() {
    let database = TestDatabase::create(3).await;
    database
        .admin
        .batch_execute(
            "CREATE TABLE registry_internal.registry_request_proposals (
                request_entity_id text NOT NULL,
                request_id uuid NOT NULL,
                proposal_version bigint NOT NULL,
                PRIMARY KEY (request_entity_id,request_id,proposal_version)
            );",
        )
        .await
        .expect("proposal parent table");
    install_review_storage_for_test(&database.admin, &database.runtime_role)
        .await
        .expect("review storage");
    let source_request_id = Uuid::from_u128(0xc1);
    seed_submission(
        &database.admin,
        source_request_id,
        "casework-a",
        "producer-a",
        "policy-a",
    )
    .await;

    let gate = Arc::new(RemoteGate::default());
    let authority = Arc::new(AuthorityState {
        producer_id: "producer-a",
        expected_token: "Bearer token-a",
        expected_profile: "producer-profile-a",
        accepted_request_id: Uuid::from_u128(0xc2),
        requests: AtomicUsize::new(0),
        gate: Some(Arc::clone(&gate)),
    });
    let (endpoint, server) = serve_authority(authority).await;
    let review_client = authority_client(endpoint, "producer-profile-a");
    let token = BearerToken::new("token-a").unwrap();
    let (worker, worker_task) = database.connect_admin().await;
    let worker_pid = worker
        .query_one("SELECT pg_backend_pid()", &[])
        .await
        .expect("worker backend pid")
        .get::<_, i32>(0);

    let submission = tokio::spawn(async move {
        let outcome = run_one_submission(
            &worker,
            "casework-a",
            &review_client,
            "producer-profile-a",
            &token,
            TEST_LEASE_SECONDS,
        )
        .await;
        (worker, review_client, token, outcome)
    });
    gate.entered.notified().await;
    assert_backend_has_no_transaction_or_row_lock(&database.admin, worker_pid).await;
    gate.release.notify_one();
    let (mut worker, review_client, token, outcome) = submission.await.expect("submission worker");
    assert!(outcome.expect("submission succeeds"));

    let lookup = tokio::spawn(async move {
        let outcome = poll_one_result(
            &mut worker,
            "casework-a",
            &review_client,
            "producer-profile-a",
            &token,
            TEST_LEASE_SECONDS,
        )
        .await;
        (worker, outcome)
    });
    gate.entered.notified().await;
    assert_backend_has_no_transaction_or_row_lock(&database.admin, worker_pid).await;
    gate.release.notify_one();
    let (_worker, outcome) = lookup.await.expect("result lookup worker");
    assert!(outcome.expect("pending result lookup succeeds"));

    worker_task.abort();
    server.abort();
    database.cleanup().await;
}

#[tokio::test]
async fn deterministic_review_submission_refusal_becomes_terminal() {
    let database = TestDatabase::create(2).await;
    database
        .admin
        .batch_execute(
            "CREATE TABLE registry_internal.registry_request_proposals (
                request_entity_id text NOT NULL,
                request_id uuid NOT NULL,
                proposal_version bigint NOT NULL,
                PRIMARY KEY (request_entity_id,request_id,proposal_version)
            );",
        )
        .await
        .expect("proposal parent table");
    install_review_storage_for_test(&database.admin, &database.runtime_role)
        .await
        .expect("review storage");
    let source_request_id = Uuid::from_u128(0xc8);
    seed_submission(
        &database.admin,
        source_request_id,
        "casework-a",
        "producer-a",
        "policy-a",
    )
    .await;

    let (endpoint, server) = serve_refusing_authority().await;
    assert!(run_one_submission(
        &database.admin,
        "casework-a",
        &authority_client(endpoint, "producer-profile-a"),
        "producer-profile-a",
        &BearerToken::new("token-a").unwrap(),
        TEST_LEASE_SECONDS,
    )
    .await
    .expect("refused submission is handled"));
    let submission = database
        .admin
        .query_one(
            "SELECT state,lease_until,last_error_code
               FROM registry_internal.registry_request_review_submissions
              WHERE request_id=$1",
            &[&source_request_id],
        )
        .await
        .expect("terminal submission");
    assert_eq!(submission.get::<_, String>(0), "failed");
    assert_eq!(
        submission.get::<_, Option<chrono::DateTime<chrono::Utc>>>(1),
        None
    );
    assert_eq!(submission.get::<_, String>(2), "remote-refused");

    server.abort();
    database.cleanup().await;
}

#[tokio::test]
async fn nonconforming_gateway_response_retries_the_exact_review_submission() {
    let database = TestDatabase::create(2).await;
    database
        .admin
        .batch_execute(
            "CREATE TABLE registry_internal.registry_request_proposals (
                request_entity_id text NOT NULL,
                request_id uuid NOT NULL,
                proposal_version bigint NOT NULL,
                PRIMARY KEY (request_entity_id,request_id,proposal_version)
            );",
        )
        .await
        .expect("proposal parent table");
    install_review_storage_for_test(&database.admin, &database.runtime_role)
        .await
        .expect("review storage");
    let source_request_id = Uuid::from_u128(0xca);
    seed_submission(
        &database.admin,
        source_request_id,
        "casework-a",
        "producer-a",
        "policy-a",
    )
    .await;

    let (endpoint, attempts, server) = serve_recovering_gateway_authority().await;
    let client = authority_client(endpoint, "producer-profile-a");
    let token = BearerToken::new("token-a").unwrap();
    assert!(run_one_submission(
        &database.admin,
        "casework-a",
        &client,
        "producer-profile-a",
        &token,
        TEST_LEASE_SECONDS,
    )
    .await
    .expect("nonconforming gateway response is retained for retry"));
    let uncertain = database
        .admin
        .query_one(
            "SELECT state,lease_until,last_error_code,attempt_count
               FROM registry_internal.registry_request_review_submissions
              WHERE request_id=$1",
            &[&source_request_id],
        )
        .await
        .expect("uncertain submission");
    assert_eq!(uncertain.get::<_, String>(0), "uncertain");
    assert_eq!(
        uncertain.get::<_, Option<chrono::DateTime<chrono::Utc>>>(1),
        None
    );
    assert_eq!(uncertain.get::<_, String>(2), "remote-uncertain");
    assert_eq!(uncertain.get::<_, i32>(3), 1);

    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_request_review_submissions
                SET next_attempt_at=transaction_timestamp()
              WHERE request_id=$1",
            &[&source_request_id],
        )
        .await
        .expect("make exact recovery retry due");
    assert!(run_one_submission(
        &database.admin,
        "casework-a",
        &client,
        "producer-profile-a",
        &token,
        TEST_LEASE_SECONDS,
    )
    .await
    .expect("exact idempotent retry recovers the accepted binding"));
    let recovered = database
        .admin
        .query_one(
            "SELECT state,accepted_binding->>'requestId',last_error_code,attempt_count
               FROM registry_internal.registry_request_review_submissions
              WHERE request_id=$1",
            &[&source_request_id],
        )
        .await
        .expect("recovered submission");
    assert_eq!(recovered.get::<_, String>(0), "accepted");
    assert_eq!(
        recovered.get::<_, String>(1),
        Uuid::from_u128(0xc9).to_string()
    );
    assert_eq!(recovered.get::<_, Option<String>>(2), None);
    assert_eq!(recovered.get::<_, i32>(3), 2);
    assert_eq!(attempts.load(Ordering::SeqCst), 2);

    server.abort();
    database.cleanup().await;
}

#[tokio::test]
async fn rate_limited_review_submission_retries_the_exact_idempotency_key() {
    let database = TestDatabase::create(2).await;
    database
        .admin
        .batch_execute(
            "CREATE TABLE registry_internal.registry_request_proposals (
                request_entity_id text NOT NULL,
                request_id uuid NOT NULL,
                proposal_version bigint NOT NULL,
                PRIMARY KEY (request_entity_id,request_id,proposal_version)
            );",
        )
        .await
        .expect("proposal parent table");
    install_review_storage_for_test(&database.admin, &database.runtime_role)
        .await
        .expect("review storage");
    let source_request_id = Uuid::from_u128(0xcc);
    seed_submission(
        &database.admin,
        source_request_id,
        "casework-a",
        "producer-a",
        "policy-a",
    )
    .await;

    let (endpoint, attempts, server) = serve_rate_limited_authority().await;
    let client = authority_client(endpoint, "producer-profile-a");
    let token = BearerToken::new("token-a").unwrap();
    assert!(run_one_submission(
        &database.admin,
        "casework-a",
        &client,
        "producer-profile-a",
        &token,
        TEST_LEASE_SECONDS,
    )
    .await
    .expect("rate-limited submission is retained for bounded retry"));
    let uncertain = database
        .admin
        .query_one(
            "SELECT state,lease_until,last_error_code,attempt_count
               FROM registry_internal.registry_request_review_submissions
              WHERE request_id=$1",
            &[&source_request_id],
        )
        .await
        .expect("rate-limited submission");
    assert_eq!(uncertain.get::<_, String>(0), "uncertain");
    assert_eq!(
        uncertain.get::<_, Option<chrono::DateTime<chrono::Utc>>>(1),
        None
    );
    assert_eq!(uncertain.get::<_, String>(2), "remote-uncertain");
    assert_eq!(uncertain.get::<_, i32>(3), 1);

    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_request_review_submissions
                SET next_attempt_at=transaction_timestamp()
              WHERE request_id=$1",
            &[&source_request_id],
        )
        .await
        .expect("make exact recovery retry due");
    assert!(run_one_submission(
        &database.admin,
        "casework-a",
        &client,
        "producer-profile-a",
        &token,
        TEST_LEASE_SECONDS,
    )
    .await
    .expect("exact idempotent retry recovers the accepted binding"));
    let recovered = database
        .admin
        .query_one(
            "SELECT state,accepted_binding->>'requestId',last_error_code,attempt_count
               FROM registry_internal.registry_request_review_submissions
              WHERE request_id=$1",
            &[&source_request_id],
        )
        .await
        .expect("recovered submission");
    assert_eq!(recovered.get::<_, String>(0), "accepted");
    assert_eq!(
        recovered.get::<_, String>(1),
        Uuid::from_u128(0xcb).to_string()
    );
    assert_eq!(recovered.get::<_, Option<String>>(2), None);
    assert_eq!(recovered.get::<_, i32>(3), 2);
    assert_eq!(attempts.load(Ordering::SeqCst), 2);

    server.abort();
    database.cleanup().await;
}

#[tokio::test]
async fn stale_submission_failure_cannot_replace_a_reclaimed_lease() {
    let database = TestDatabase::create(2).await;
    database
        .admin
        .batch_execute(
            "CREATE TABLE registry_internal.registry_request_proposals (
                request_entity_id text NOT NULL,
                request_id uuid NOT NULL,
                proposal_version bigint NOT NULL,
                PRIMARY KEY (request_entity_id,request_id,proposal_version)
            );",
        )
        .await
        .expect("proposal parent table");
    install_review_storage_for_test(&database.admin, &database.runtime_role)
        .await
        .expect("review storage");
    let source_request_id = Uuid::from_u128(0xc3);
    seed_submission(
        &database.admin,
        source_request_id,
        "casework-a",
        "producer-a",
        "policy-a",
    )
    .await;

    let gate = Arc::new(RemoteGate::default());
    let (endpoint, server) = serve_failing_authority(Arc::clone(&gate)).await;
    let review_client = authority_client(endpoint, "producer-profile-a");
    let token = BearerToken::new("token-a").unwrap();
    let (worker, worker_task) = database.connect_admin().await;
    let submission = tokio::spawn(async move {
        run_one_submission(
            &worker,
            "casework-a",
            &review_client,
            "producer-profile-a",
            &token,
            TEST_LEASE_SECONDS,
        )
        .await
    });
    gate.entered.notified().await;
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_request_review_submissions
                SET lease_until=lease_until+interval '1 second'
              WHERE request_id=$1 AND state='submitting'",
            &[&source_request_id],
        )
        .await
        .expect("simulate replacement lease owner");
    let replacement_lease = database
        .admin
        .query_one(
            "SELECT lease_until FROM registry_internal.registry_request_review_submissions
              WHERE request_id=$1",
            &[&source_request_id],
        )
        .await
        .expect("replacement lease")
        .get::<_, chrono::DateTime<chrono::Utc>>(0);
    gate.release.notify_one();
    assert!(submission
        .await
        .expect("submission worker joins")
        .expect("stale failed request is fenced"));
    let retained = database
        .admin
        .query_one(
            "SELECT state,lease_until,last_error_code
               FROM registry_internal.registry_request_review_submissions
              WHERE request_id=$1",
            &[&source_request_id],
        )
        .await
        .expect("retained replacement lease");
    assert_eq!(retained.get::<_, String>(0), "submitting");
    assert_eq!(
        retained.get::<_, chrono::DateTime<chrono::Utc>>(1),
        replacement_lease
    );
    assert_eq!(retained.get::<_, Option<String>>(2), None);

    worker_task.abort();
    server.abort();
    database.cleanup().await;
}

#[tokio::test]
async fn cancellation_transition_preserves_original_submission_recovery_deadline() {
    let mut database = TestDatabase::create(2).await;
    database
        .admin
        .batch_execute(
            "CREATE TABLE registry_internal.registry_request_proposals (
                request_entity_id text NOT NULL,
                request_id uuid NOT NULL,
                proposal_version bigint NOT NULL,
                PRIMARY KEY (request_entity_id,request_id,proposal_version)
            );",
        )
        .await
        .expect("proposal parent table");
    install_review_storage_for_test(&database.admin, &database.runtime_role)
        .await
        .expect("review storage");
    let request_id = Uuid::from_u128(0xcb);
    seed_submission(
        &database.admin,
        request_id,
        "casework-a",
        "producer-a",
        "policy-a",
    )
    .await;
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_request_review_submissions
                SET state='accepted',accepted_binding='{}'::jsonb,attempt_count=1000,
                    created_at=transaction_timestamp()-interval '8 days',
                    recovery_deadline=transaction_timestamp()-interval '1 day'
              WHERE request_id=$1",
            &[&request_id],
        )
        .await
        .expect("seed accepted submission with expired recovery state");
    let original_deadline = database
        .admin
        .query_one(
            "SELECT recovery_deadline
               FROM registry_internal.registry_request_review_submissions
              WHERE request_id=$1",
            &[&request_id],
        )
        .await
        .expect("original recovery deadline")
        .get::<_, chrono::DateTime<chrono::Utc>>(0);

    let transaction = database.admin.transaction().await.expect("transaction");
    schedule_cancellation_for_test(&transaction, "requests", request_id, 1)
        .await
        .expect("schedule cancellation");
    transaction.commit().await.expect("commit cancellation");
    let cancelled = database
        .admin
        .query_one(
            "SELECT state,attempt_count,recovery_deadline,
                    recovery_deadline < transaction_timestamp()
               FROM registry_internal.registry_request_review_submissions
              WHERE request_id=$1",
            &[&request_id],
        )
        .await
        .expect("cancellation recovery state");
    assert_eq!(cancelled.get::<_, String>(0), "cancelling");
    assert_eq!(cancelled.get::<_, i32>(1), 0);
    assert_eq!(
        cancelled.get::<_, chrono::DateTime<chrono::Utc>>(2),
        original_deadline
    );
    assert!(cancelled.get::<_, bool>(3));

    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_request_review_submissions
                SET attempt_count=4 WHERE request_id=$1",
            &[&request_id],
        )
        .await
        .expect("record cancellation attempts");
    let transaction = database.admin.transaction().await.expect("transaction");
    schedule_cancellation_for_test(&transaction, "requests", request_id, 1)
        .await
        .expect("repeat cancellation scheduling");
    transaction
        .commit()
        .await
        .expect("commit repeated scheduling");
    let retained = database
        .admin
        .query_one(
            "SELECT attempt_count,recovery_deadline
               FROM registry_internal.registry_request_review_submissions
              WHERE request_id=$1",
            &[&request_id],
        )
        .await
        .expect("existing cancellation budget");
    assert_eq!(retained.get::<_, i32>(0), 4);
    assert_eq!(
        retained.get::<_, chrono::DateTime<chrono::Utc>>(1),
        original_deadline
    );

    database.cleanup().await;
}

#[tokio::test]
async fn accepted_after_withdrawal_preserves_original_submission_recovery_deadline() {
    let mut database = TestDatabase::create(2).await;
    database
        .admin
        .batch_execute(
            "CREATE TABLE registry_internal.registry_request_proposals (
                request_entity_id text NOT NULL,
                request_id uuid NOT NULL,
                proposal_version bigint NOT NULL,
                PRIMARY KEY (request_entity_id,request_id,proposal_version)
            );",
        )
        .await
        .expect("proposal parent table");
    install_review_storage_for_test(&database.admin, &database.runtime_role)
        .await
        .expect("review storage");
    let request_id = Uuid::from_u128(0xd0);
    seed_submission(
        &database.admin,
        request_id,
        "casework-a",
        "producer-a",
        "policy-a",
    )
    .await;
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_request_review_submissions
                SET state='uncertain',attempt_count=3,
                    recovery_deadline=transaction_timestamp()+interval '2 hours'
              WHERE request_id=$1",
            &[&request_id],
        )
        .await
        .expect("seed recoverable uncertain submission");
    let original_deadline = database
        .admin
        .query_one(
            "SELECT recovery_deadline
               FROM registry_internal.registry_request_review_submissions
              WHERE request_id=$1",
            &[&request_id],
        )
        .await
        .expect("original recovery deadline")
        .get::<_, chrono::DateTime<chrono::Utc>>(0);
    let transaction = database.admin.transaction().await.expect("transaction");
    schedule_cancellation_for_test(&transaction, "requests", request_id, 1)
        .await
        .expect("withdraw uncertain submission");
    transaction.commit().await.expect("commit withdrawal");

    let authority = Arc::new(AuthorityState {
        producer_id: "producer-a",
        expected_token: "Bearer token-a",
        expected_profile: "producer-profile-a",
        accepted_request_id: Uuid::from_u128(0xd1),
        requests: AtomicUsize::new(0),
        gate: None,
    });
    let (endpoint, server) = serve_authority(authority).await;
    assert!(run_one_submission(
        &database.admin,
        "casework-a",
        &authority_client(endpoint, "producer-profile-a"),
        "producer-profile-a",
        &BearerToken::new("token-a").unwrap(),
        TEST_LEASE_SECONDS,
    )
    .await
    .expect("accepted submission is retained for cancellation"));
    let accepted = database
        .admin
        .query_one(
            "SELECT state,attempt_count,recovery_deadline,accepted_binding IS NOT NULL
               FROM registry_internal.registry_request_review_submissions
              WHERE request_id=$1",
            &[&request_id],
        )
        .await
        .expect("accepted withdrawn submission");
    assert_eq!(accepted.get::<_, String>(0), "cancelling");
    assert_eq!(accepted.get::<_, i32>(1), 0);
    assert_eq!(
        accepted.get::<_, chrono::DateTime<chrono::Utc>>(2),
        original_deadline
    );
    assert!(accepted.get::<_, bool>(3));

    server.abort();
    database.cleanup().await;
}

#[tokio::test]
async fn token_failure_backoff_cannot_clear_a_live_cancellation_lease() {
    let database = TestDatabase::create(2).await;
    database
        .admin
        .batch_execute(
            "CREATE TABLE registry_internal.registry_request_proposals (
                request_entity_id text NOT NULL,
                request_id uuid NOT NULL,
                proposal_version bigint NOT NULL,
                PRIMARY KEY (request_entity_id,request_id,proposal_version)
            );",
        )
        .await
        .expect("proposal parent table");
    install_review_storage_for_test(&database.admin, &database.runtime_role)
        .await
        .expect("review storage");
    let request_id = Uuid::from_u128(0xd2);
    seed_submission(
        &database.admin,
        request_id,
        "casework-a",
        "producer-a",
        "policy-a",
    )
    .await;
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_request_review_submissions
                SET state='cancelling',withdrawn=true,accepted_binding='{}'::jsonb,
                    lease_until=transaction_timestamp()+interval '30 seconds',
                    next_attempt_at=transaction_timestamp(),last_error_code=NULL
              WHERE request_id=$1",
            &[&request_id],
        )
        .await
        .expect("seed live cancellation claim");
    let original = database
        .admin
        .query_one(
            "SELECT lease_until,next_attempt_at
               FROM registry_internal.registry_request_review_submissions
              WHERE request_id=$1",
            &[&request_id],
        )
        .await
        .expect("live cancellation claim");
    let lease_until = original.get::<_, chrono::DateTime<chrono::Utc>>(0);
    let next_attempt_at = original.get::<_, chrono::DateTime<chrono::Utc>>(1);

    back_off_review_token_failure_for_test(&database.admin, "casework-a", &["cancelling"])
        .await
        .expect("token backoff is fenced");
    let retained = database
        .admin
        .query_one(
            "SELECT state,lease_until,next_attempt_at,last_error_code
               FROM registry_internal.registry_request_review_submissions
              WHERE request_id=$1",
            &[&request_id],
        )
        .await
        .expect("retained cancellation claim");
    assert_eq!(retained.get::<_, String>(0), "cancelling");
    assert_eq!(
        retained.get::<_, chrono::DateTime<chrono::Utc>>(1),
        lease_until
    );
    assert_eq!(
        retained.get::<_, chrono::DateTime<chrono::Utc>>(2),
        next_attempt_at
    );
    assert_eq!(retained.get::<_, Option<String>>(3), None);

    database.cleanup().await;
}

#[tokio::test]
async fn stale_cancellation_failure_cannot_replace_a_reclaimed_lease() {
    let database = TestDatabase::create(2).await;
    database
        .admin
        .batch_execute(
            "CREATE TABLE registry_internal.registry_request_proposals (
                request_entity_id text NOT NULL,
                request_id uuid NOT NULL,
                proposal_version bigint NOT NULL,
                PRIMARY KEY (request_entity_id,request_id,proposal_version)
            );",
        )
        .await
        .expect("proposal parent table");
    install_review_storage_for_test(&database.admin, &database.runtime_role)
        .await
        .expect("review storage");
    let source_request_id = Uuid::from_u128(0xc4);
    seed_submission(
        &database.admin,
        source_request_id,
        "casework-a",
        "producer-a",
        "policy-a",
    )
    .await;
    let request = create_request(source_request_id, "policy-a");
    let submission_digest = submission_digest("producer-a", "registry-a", &request).unwrap();
    let accepted = json!({
        "requestId": Uuid::from_u128(0xc5),
        "subject": request.subject,
        "policy": {"id":"policy-a","version":"1","digest":DIGEST},
        "submissionDigest": submission_digest,
    });
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_request_review_submissions
                SET state='cancelling',withdrawn=true,accepted_binding=$2
              WHERE request_id=$1",
            &[&source_request_id, &accepted],
        )
        .await
        .expect("seed cancellation");

    let gate = Arc::new(RemoteGate::default());
    let (endpoint, server) = serve_failing_cancellation(Arc::clone(&gate)).await;
    let review_client = authority_client(endpoint, "producer-profile-a");
    let token = BearerToken::new("token-a").unwrap();
    let (mut worker, worker_task) = database.connect_admin().await;
    let cancellation = tokio::spawn(async move {
        run_one_cancellation(
            &mut worker,
            "casework-a",
            &review_client,
            "producer-profile-a",
            &token,
            TEST_LEASE_SECONDS,
        )
        .await
    });
    gate.entered.notified().await;
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_request_review_submissions
                SET lease_until=lease_until+interval '1 second'
              WHERE request_id=$1 AND state='cancelling'",
            &[&source_request_id],
        )
        .await
        .expect("simulate replacement cancellation lease owner");
    let replacement_lease = database
        .admin
        .query_one(
            "SELECT lease_until FROM registry_internal.registry_request_review_submissions
              WHERE request_id=$1",
            &[&source_request_id],
        )
        .await
        .expect("replacement cancellation lease")
        .get::<_, chrono::DateTime<chrono::Utc>>(0);
    gate.release.notify_one();
    assert!(cancellation
        .await
        .expect("cancellation worker joins")
        .expect("stale cancellation failure is fenced"));
    let retained = database
        .admin
        .query_one(
            "SELECT state,lease_until,last_error_code
               FROM registry_internal.registry_request_review_submissions
              WHERE request_id=$1",
            &[&source_request_id],
        )
        .await
        .expect("retained replacement cancellation lease");
    assert_eq!(retained.get::<_, String>(0), "cancelling");
    assert_eq!(
        retained.get::<_, chrono::DateTime<chrono::Utc>>(1),
        replacement_lease
    );
    assert_eq!(retained.get::<_, Option<String>>(2), None);

    worker_task.abort();
    server.abort();
    database.cleanup().await;
}

#[tokio::test]
async fn successful_cancellation_reconciles_before_becoming_cancelled() {
    let database = TestDatabase::create(2).await;
    database
        .admin
        .batch_execute(
            "CREATE TABLE registry_internal.registry_request_proposals (
                request_entity_id text NOT NULL,
                request_id uuid NOT NULL,
                proposal_version bigint NOT NULL,
                PRIMARY KEY (request_entity_id,request_id,proposal_version)
            );",
        )
        .await
        .expect("proposal parent table");
    install_review_storage_for_test(&database.admin, &database.runtime_role)
        .await
        .expect("review storage");
    let source_request_id = Uuid::from_u128(0xc6);
    seed_submission(
        &database.admin,
        source_request_id,
        "casework-a",
        "producer-a",
        "policy-a",
    )
    .await;
    let request = create_request(source_request_id, "policy-a");
    let submission_digest = submission_digest("producer-a", "registry-a", &request).unwrap();
    let accepted = json!({
        "requestId": Uuid::from_u128(0xc7),
        "subject": request.subject,
        "policy": {"id":"policy-a","version":"1","digest":DIGEST},
        "submissionDigest": submission_digest,
    });
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_request_review_submissions
                SET state='cancelling',withdrawn=true,accepted_binding=$2
              WHERE request_id=$1",
            &[&source_request_id, &accepted],
        )
        .await
        .expect("seed cancellation");

    let (endpoint, server) = serve_successful_cancellation(accepted).await;
    let (mut worker, worker_task) = database.connect_admin().await;
    assert!(run_one_cancellation(
        &mut worker,
        "casework-a",
        &authority_client(endpoint, "producer-profile-a"),
        "producer-profile-a",
        &BearerToken::new("token-a").unwrap(),
        TEST_LEASE_SECONDS,
    )
    .await
    .expect("successful cancellation is reconciled"));
    let row = database
        .admin
        .query_one(
            "SELECT s.state,s.lease_until,r.status,r.result_id
               FROM registry_internal.registry_request_review_submissions s
               JOIN registry_internal.registry_request_review_results r
                 USING (request_entity_id,request_id,proposal_version)
              WHERE s.request_id=$1",
            &[&source_request_id],
        )
        .await
        .expect("cancelled submission and reconciled result");
    assert_eq!(row.get::<_, String>(0), "cancelled");
    assert_eq!(row.get::<_, Option<chrono::DateTime<chrono::Utc>>>(1), None);
    assert_eq!(row.get::<_, String>(2), "cancelled");
    assert_eq!(row.get::<_, Uuid>(3), Uuid::from_u128(0xc7));

    worker_task.abort();
    server.abort();
    database.cleanup().await;
}

#[tokio::test]
async fn expired_or_exhausted_cancellations_become_terminal_without_remote_io() {
    let database = TestDatabase::create(2).await;
    database
        .admin
        .batch_execute(
            "CREATE TABLE registry_internal.registry_request_proposals (
                request_entity_id text NOT NULL,
                request_id uuid NOT NULL,
                proposal_version bigint NOT NULL,
                PRIMARY KEY (request_entity_id,request_id,proposal_version)
            );",
        )
        .await
        .expect("proposal parent table");
    install_review_storage_for_test(&database.admin, &database.runtime_role)
        .await
        .expect("review storage");
    database
        .admin
        .batch_execute(&format!(
            "GRANT USAGE ON SCHEMA registry_internal TO \"{}\";",
            database.runtime_role.as_str()
        ))
        .await
        .expect("runtime review schema access");
    let expired = Uuid::from_u128(0xc6);
    let exhausted = Uuid::from_u128(0xc7);
    for request_id in [expired, exhausted] {
        seed_submission(
            &database.admin,
            request_id,
            "casework-a",
            "producer-a",
            "policy-a",
        )
        .await;
        let review_request_id = Uuid::from_u128(request_id.as_u128() + 100).to_string();
        database
            .admin
            .execute(
                "UPDATE registry_internal.registry_request_review_submissions
                    SET state='cancelling',withdrawn=true,
                        accepted_binding=jsonb_build_object('requestId',$2::text)
                  WHERE request_id=$1",
                &[&request_id, &review_request_id],
            )
            .await
            .expect("seed cancellation");
    }
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_request_review_submissions
                SET recovery_deadline=transaction_timestamp()-interval '1 second'
              WHERE request_id=$1",
            &[&expired],
        )
        .await
        .expect("expire cancellation recovery");
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_request_review_submissions
                SET attempt_count=1000 WHERE request_id=$1",
            &[&exhausted],
        )
        .await
        .expect("exhaust cancellation attempts");

    let pool = database.runtime_config.build_pool().expect("runtime pool");
    let authorities = authority_registry("casework-a", "producer-a", "sender", "registry-a");
    assert!(run_review_authority_once_for_test(&pool, &authorities)
        .await
        .expect("terminalize stranded cancellations"));
    let rows = database
        .admin
        .query(
            "SELECT request_id,state,accepted_binding,last_error_code
               FROM registry_internal.registry_request_review_submissions
              WHERE request_id=ANY($1) ORDER BY request_id",
            &[&vec![expired, exhausted]],
        )
        .await
        .expect("read terminal cancellations");
    assert_eq!(rows.len(), 2);
    for row in rows {
        assert_eq!(row.get::<_, String>(1), "failed");
        let request_id: Uuid = row.get(0);
        // The binding is preserved, not cleared: a late Casework settlement
        // must still be correlated to this row by an operator or by
        // `receive_completion`, exactly as the result-bearing sweep already
        // preserves it when a stored result converges cancellation to
        // `cancelled`.
        let binding: Value = row
            .get::<_, Option<Value>>(2)
            .expect("cancellation give-up must preserve the accepted binding");
        assert_eq!(
            binding["requestId"],
            Uuid::from_u128(request_id.as_u128() + 100).to_string()
        );
        assert_eq!(
            row.get::<_, String>(3),
            if request_id == expired {
                "cancellation-recovery-expired"
            } else {
                "cancellation-attempts-exhausted"
            }
        );
    }

    drop(pool);
    database.cleanup().await;
}

#[tokio::test]
async fn cancellation_recovery_expiry_leaves_a_live_lease_to_its_holder() {
    let database = TestDatabase::create(2).await;
    database
        .admin
        .batch_execute(
            "CREATE TABLE registry_internal.registry_request_proposals (
                request_entity_id text NOT NULL,
                request_id uuid NOT NULL,
                proposal_version bigint NOT NULL,
                PRIMARY KEY (request_entity_id,request_id,proposal_version)
            );",
        )
        .await
        .expect("proposal parent table");
    install_review_storage_for_test(&database.admin, &database.runtime_role)
        .await
        .expect("review storage");
    database
        .admin
        .batch_execute(&format!(
            "GRANT USAGE ON SCHEMA registry_internal TO \"{}\";",
            database.runtime_role.as_str()
        ))
        .await
        .expect("runtime review schema access");
    let leased = Uuid::from_u128(0xe1);
    let unleased = Uuid::from_u128(0xe2);
    for request_id in [leased, unleased] {
        seed_submission(
            &database.admin,
            request_id,
            "casework-a",
            "producer-a",
            "policy-a",
        )
        .await;
        let review_request_id = Uuid::from_u128(request_id.as_u128() + 100).to_string();
        database
            .admin
            .execute(
                "UPDATE registry_internal.registry_request_review_submissions
                    SET state='cancelling',withdrawn=true,
                        accepted_binding=jsonb_build_object('requestId',$2::text),
                        recovery_deadline=transaction_timestamp()-interval '1 second',
                        lease_until=CASE WHEN request_id=$3
                            THEN transaction_timestamp()+interval '20 seconds'
                            ELSE NULL END
                  WHERE request_id=$1",
                &[&request_id, &review_request_id, &leased],
            )
            .await
            .expect("seed cancellation recovery");
    }

    let pool = database.runtime_config.build_pool().expect("runtime pool");
    let authorities = authority_registry("casework-a", "producer-a", "sender", "registry-a");
    assert!(run_review_authority_once_for_test(&pool, &authorities)
        .await
        .expect("expire only unleased cancellation recovery"));
    let rows = database
        .admin
        .query(
            "SELECT request_id,state,lease_until,last_error_code
               FROM registry_internal.registry_request_review_submissions
              WHERE request_id=ANY($1) ORDER BY request_id",
            &[&vec![leased, unleased]],
        )
        .await
        .expect("read cancellation recovery outcomes");
    assert_eq!(rows.len(), 2);
    for row in rows {
        let request_id: Uuid = row.get(0);
        if request_id == leased {
            assert_eq!(row.get::<_, String>(1), "cancelling");
            assert!(row
                .get::<_, Option<chrono::DateTime<chrono::Utc>>>(2)
                .is_some());
            assert_eq!(row.get::<_, Option<String>>(3), None);
        } else {
            assert_eq!(row.get::<_, String>(1), "failed");
            assert_eq!(row.get::<_, Option<chrono::DateTime<chrono::Utc>>>(2), None);
            assert_eq!(row.get::<_, String>(3), "cancellation-recovery-expired");
        }
    }

    drop(pool);
    database.cleanup().await;
}

#[tokio::test]
async fn cancellation_give_up_preserves_the_binding_for_late_correlation() {
    let mut database = TestDatabase::create(2).await;
    database
        .admin
        .batch_execute(
            "CREATE TABLE registry_internal.registry_request_proposals (
                request_entity_id text NOT NULL,
                request_id uuid NOT NULL,
                proposal_version bigint NOT NULL,
                PRIMARY KEY (request_entity_id,request_id,proposal_version)
            );",
        )
        .await
        .expect("proposal parent table");
    install_review_storage_for_test(&database.admin, &database.runtime_role)
        .await
        .expect("review storage");
    database
        .admin
        .batch_execute(&format!(
            "GRANT USAGE ON SCHEMA registry_internal TO \"{}\";",
            database.runtime_role.as_str()
        ))
        .await
        .expect("runtime review schema access");

    let request_id = Uuid::from_u128(0xf1);
    let review_request_id = Uuid::from_u128(0xf2);
    seed_submission(
        &database.admin,
        request_id,
        "casework-a",
        "producer-a",
        "policy-a",
    )
    .await;
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_request_review_submissions
                SET state='cancelling',withdrawn=true,
                    accepted_binding=jsonb_build_object('requestId',$2::text),
                    recovery_deadline=transaction_timestamp()-interval '1 second'
              WHERE request_id=$1",
            &[&request_id, &review_request_id.to_string()],
        )
        .await
        .expect("seed stranded cancellation");

    let pool = database.runtime_config.build_pool().expect("runtime pool");
    let authorities = authority_registry("casework-a", "producer-a", "sender", "registry-a");
    assert!(run_review_authority_once_for_test(&pool, &authorities)
        .await
        .expect("terminalize the stranded cancellation"));
    let terminal = database
        .admin
        .query_one(
            "SELECT state,accepted_binding
               FROM registry_internal.registry_request_review_submissions
              WHERE request_id=$1",
            &[&request_id],
        )
        .await
        .expect("terminalized cancellation");
    assert_eq!(terminal.get::<_, String>(0), "failed");
    let binding: Value = terminal
        .get::<_, Option<Value>>(1)
        .expect("cancellation give-up must preserve the accepted binding for late correlation");
    assert_eq!(binding["requestId"], review_request_id.to_string());

    // `receive_completion` matches by `accepted_binding->>'requestId'` with no
    // state filter, so a late Casework settlement is still correlated to this
    // now-failed row instead of falling into 'unmatched'.
    let completion = ReviewCompletion {
        event_type: ReviewCompletionType::ReviewCompleted,
        event_id: Uuid::new_v4(),
        request_id: review_request_id,
        result_id: Uuid::new_v4(),
        completed_at: chrono::Utc::now(),
    };
    let transaction = database.admin.transaction().await.unwrap();
    receive_completion(
        &transaction,
        "casework-a",
        &completion,
        chrono::Utc::now() + chrono::Duration::days(7),
    )
    .await
    .expect("late completion still correlates to the failed row");
    transaction.commit().await.unwrap();
    let completion_state: String = database
        .admin
        .query_one(
            "SELECT state FROM registry_internal.registry_request_review_completions
              WHERE authority='casework-a' AND event_id=$1",
            &[&completion.event_id],
        )
        .await
        .expect("stored completion")
        .get(0);
    assert_eq!(completion_state, "pending");

    // `reconcile_result` explicitly restricts to `state IN ('accepted',
    // 'cancelling')`, so it refuses to reopen a terminal 'failed' row rather
    // than silently correlating a late result into it; the row remains
    // identifiable by hand through its preserved binding.
    let subject = SubjectBinding {
        source: "registry-a".to_owned(),
        subject_type: "change-request".to_owned(),
        id: request_id.to_string(),
        version: "1".to_owned(),
        digest: ContentDigest::parse(DIGEST).unwrap(),
    };
    let policy = PolicyBinding {
        id: "policy-a".to_owned(),
        version: "1".to_owned(),
        digest: ContentDigest::parse(DIGEST).unwrap(),
    };
    let submission_digest = ContentDigest::parse(DIGEST).unwrap();
    let accepted = ReviewRequestAccepted {
        request_id: review_request_id,
        subject: subject.clone(),
        policy: policy.clone(),
        submission_digest: submission_digest.clone(),
    };
    let result = ReviewResult {
        result_id: Uuid::new_v4(),
        request_id: review_request_id,
        subject,
        policy,
        submission_digest,
        status: ReviewResultStatus::Cancelled,
        outcome: None,
        result: None,
        completed_at: chrono::Utc::now(),
        available_until: chrono::Utc::now() + chrono::Duration::days(1),
    };
    let refusal_transaction = database.admin.transaction().await.unwrap();
    let refused = reconcile_result(&refusal_transaction, "casework-a", &accepted, &result).await;
    assert!(matches!(refused, Err(MutationError::PreconditionFailed)));
    refusal_transaction.rollback().await.unwrap();

    let after: Value = database
        .admin
        .query_one(
            "SELECT accepted_binding FROM registry_internal.registry_request_review_submissions
              WHERE request_id=$1",
            &[&request_id],
        )
        .await
        .expect("binding survives the refused reconciliation")
        .get(0);
    assert_eq!(after["requestId"], review_request_id.to_string());

    drop(pool);
    database.cleanup().await;
}

#[tokio::test]
async fn submission_claims_size_their_lease_from_the_request_timeout() {
    let database = TestDatabase::create(2).await;
    database
        .admin
        .batch_execute(
            "CREATE TABLE registry_internal.registry_request_proposals (
                request_entity_id text NOT NULL,
                request_id uuid NOT NULL,
                proposal_version bigint NOT NULL,
                PRIMARY KEY (request_entity_id,request_id,proposal_version)
            );",
        )
        .await
        .expect("proposal parent table");
    install_review_storage_for_test(&database.admin, &database.runtime_role)
        .await
        .expect("review storage");
    database
        .admin
        .batch_execute(&format!(
            "GRANT USAGE ON SCHEMA registry_internal TO \"{}\";",
            database.runtime_role.as_str()
        ))
        .await
        .expect("runtime review schema access");
    let source_request_id = Uuid::from_u128(0xe3);
    seed_submission(
        &database.admin,
        source_request_id,
        "casework-a",
        "producer-a",
        "policy-a",
    )
    .await;

    let gate = Arc::new(RemoteGate::default());
    let (endpoint, server) = serve_failing_authority(Arc::clone(&gate)).await;
    let slow_client = ReviewClient::new(
        ReviewClientConfig::new(endpoint).with_request_timeout(Duration::from_secs(60)),
    )
    .expect("review client");
    let configured = Arc::new(
        ReviewAuthorityClient::new(
            "casework-a".to_owned(),
            slow_client,
            Arc::new(registry_platform_httputil::StaticToken::new("token-a".to_owned()).unwrap()),
            "producer-profile-a".to_owned(),
            "producer-a".to_owned(),
            7,
            None,
            None,
        )
        .expect("review authority"),
    );
    let authorities = Arc::new(
        ReviewAuthorityRegistry::new(BTreeMap::from([("casework-a".to_owned(), configured)]))
            .expect("authority registry"),
    );
    let worker = tokio::spawn({
        let authorities = Arc::clone(&authorities);
        let pool = database.runtime_config.build_pool().expect("runtime pool");
        async move { run_review_authority_once_for_test(&pool, &authorities).await }
    });
    gate.entered.notified().await;
    let claimed = database
        .admin
        .query_one(
            "SELECT state,lease_until-transaction_timestamp() > interval '45 seconds'
               FROM registry_internal.registry_request_review_submissions
              WHERE request_id=$1",
            &[&source_request_id],
        )
        .await
        .expect("claimed submission lease");
    assert_eq!(claimed.get::<_, String>(0), "submitting");
    assert!(
        claimed.get::<_, bool>(1),
        "the claim lease must outlive the sixty second request timeout"
    );
    gate.release.notify_one();
    assert!(worker
        .await
        .expect("authority worker joins")
        .expect("uncertain submission is handled"));

    server.abort();
    database.cleanup().await;
}

#[tokio::test]
async fn a_live_result_poll_lease_keeps_the_lookup_to_its_holder() {
    let mut database = TestDatabase::create(2).await;
    database
        .admin
        .batch_execute(
            "CREATE TABLE registry_internal.registry_request_proposals (
                request_entity_id text NOT NULL,
                request_id uuid NOT NULL,
                proposal_version bigint NOT NULL,
                PRIMARY KEY (request_entity_id,request_id,proposal_version)
            );",
        )
        .await
        .expect("proposal parent table");
    install_review_storage_for_test(&database.admin, &database.runtime_role)
        .await
        .expect("review storage");
    let request_id = Uuid::from_u128(0xe4);
    seed_submission(
        &database.admin,
        request_id,
        "casework-a",
        "producer-a",
        "policy-a",
    )
    .await;
    let accepting = Arc::new(AuthorityState {
        producer_id: "producer-a",
        expected_token: "Bearer token-a",
        expected_profile: "producer-profile-a",
        accepted_request_id: Uuid::from_u128(0xe5),
        requests: AtomicUsize::new(0),
        gate: None,
    });
    let (endpoint, server) = serve_authority(accepting).await;
    let token = BearerToken::new("token-a").unwrap();
    assert!(run_one_submission(
        &database.admin,
        "casework-a",
        &authority_client(endpoint, "producer-profile-a"),
        "producer-profile-a",
        &token,
        TEST_LEASE_SECONDS,
    )
    .await
    .expect("accept the review submission"));

    let gate = Arc::new(RemoteGate::default());
    let polling = Arc::new(AuthorityState {
        producer_id: "producer-a",
        expected_token: "Bearer token-a",
        expected_profile: "producer-profile-a",
        accepted_request_id: Uuid::from_u128(0xe5),
        requests: AtomicUsize::new(0),
        gate: Some(Arc::clone(&gate)),
    });
    let (gated_endpoint, gated_server) = serve_authority(polling).await;
    let (mut worker, worker_task) = database.connect_admin().await;
    let lookup = tokio::spawn(async move {
        poll_one_result(
            &mut worker,
            "casework-a",
            &authority_client(gated_endpoint, "producer-profile-a"),
            "producer-profile-a",
            &token,
            TEST_LEASE_SECONDS,
        )
        .await
    });
    gate.entered.notified().await;
    let claimed = database
        .admin
        .query_one(
            "SELECT lease_until,result_poll_attempts
               FROM registry_internal.registry_request_review_submissions
              WHERE request_id=$1",
            &[&request_id],
        )
        .await
        .expect("claimed result lookup");
    let lease_until = claimed.get::<_, chrono::DateTime<chrono::Utc>>(0);
    assert_eq!(claimed.get::<_, i32>(1), 0);

    // The poll is made due again so only the live lease can keep the lookup
    // claimed; a second worker without that lease must find nothing to poll.
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_request_review_submissions
                SET next_result_poll_at=transaction_timestamp()
              WHERE request_id=$1",
            &[&request_id],
        )
        .await
        .expect("make the result poll due again");
    let unreachable = "http://127.0.0.1:9/"
        .parse()
        .expect("unroutable review authority URL");
    assert!(!poll_one_result(
        &mut database.admin,
        "casework-a",
        &authority_client(unreachable, "producer-profile-a"),
        "producer-profile-a",
        &BearerToken::new("token-a").unwrap(),
        TEST_LEASE_SECONDS,
    )
    .await
    .expect("a live lease leaves no result lookup to claim"));

    gate.release.notify_one();
    assert!(lookup
        .await
        .expect("result lookup worker joins")
        .expect("pending result lookup succeeds"));
    let settled = database
        .admin
        .query_one(
            "SELECT result_poll_attempts,lease_until
               FROM registry_internal.registry_request_review_submissions
              WHERE request_id=$1",
            &[&request_id],
        )
        .await
        .expect("settled result lookup");
    assert_eq!(settled.get::<_, i32>(0), 1);
    assert_eq!(
        settled.get::<_, chrono::DateTime<chrono::Utc>>(1),
        lease_until
    );

    worker_task.abort();
    server.abort();
    gated_server.abort();
    database.cleanup().await;
}

#[tokio::test]
async fn a_failed_result_lookup_records_the_attempt_and_error_without_terminalizing() {
    let mut database = TestDatabase::create(2).await;
    database
        .admin
        .batch_execute(
            "CREATE TABLE registry_internal.registry_request_proposals (
                request_entity_id text NOT NULL,
                request_id uuid NOT NULL,
                proposal_version bigint NOT NULL,
                PRIMARY KEY (request_entity_id,request_id,proposal_version)
            );",
        )
        .await
        .expect("proposal parent table");
    install_review_storage_for_test(&database.admin, &database.runtime_role)
        .await
        .expect("review storage");

    let request_id = Uuid::from_u128(0xf3);
    seed_submission(
        &database.admin,
        request_id,
        "casework-a",
        "producer-a",
        "policy-a",
    )
    .await;
    let accepting = Arc::new(AuthorityState {
        producer_id: "producer-a",
        expected_token: "Bearer token-a",
        expected_profile: "producer-profile-a",
        accepted_request_id: Uuid::from_u128(0xf4),
        requests: AtomicUsize::new(0),
        gate: None,
    });
    let (endpoint, server) = serve_authority(accepting).await;
    let token = BearerToken::new("token-a").unwrap();
    assert!(run_one_submission(
        &database.admin,
        "casework-a",
        &authority_client(endpoint, "producer-profile-a"),
        "producer-profile-a",
        &token,
        TEST_LEASE_SECONDS,
    )
    .await
    .expect("accept the review submission"));
    server.abort();

    // The result endpoint is unroutable: every lookup fails at the transport
    // layer without a mock server, exercising a Casework /result endpoint
    // that never returns a usable response.
    let unreachable: reqwest::Url = "http://127.0.0.1:9/".parse().expect("unroutable endpoint");
    let outcome = poll_one_result(
        &mut database.admin,
        "casework-a",
        &authority_client(unreachable, "producer-profile-a"),
        "producer-profile-a",
        &token,
        TEST_LEASE_SECONDS,
    )
    .await;
    assert!(matches!(outcome, Err(MutationError::Unavailable)));

    let row = database
        .admin
        .query_one(
            "SELECT state,result_poll_attempts,last_error_code,accepted_binding
               FROM registry_internal.registry_request_review_submissions
              WHERE request_id=$1",
            &[&request_id],
        )
        .await
        .expect("polled submission");
    assert_eq!(row.get::<_, String>(0), "accepted");
    assert_eq!(row.get::<_, i32>(1), 1);
    assert_eq!(
        row.get::<_, Option<String>>(2),
        Some("result-lookup-uncertain".to_owned())
    );
    assert!(row.get::<_, Option<Value>>(3).is_some());

    database.cleanup().await;
}

#[tokio::test]
async fn expired_recovery_leaves_a_live_submission_lease_to_its_holder() {
    let database = TestDatabase::create(2).await;
    database
        .admin
        .batch_execute(
            "CREATE TABLE registry_internal.registry_request_proposals (
                request_entity_id text NOT NULL,
                request_id uuid NOT NULL,
                proposal_version bigint NOT NULL,
                PRIMARY KEY (request_entity_id,request_id,proposal_version)
            );",
        )
        .await
        .expect("proposal parent table");
    install_review_storage_for_test(&database.admin, &database.runtime_role)
        .await
        .expect("review storage");
    database
        .admin
        .batch_execute(&format!(
            "GRANT USAGE ON SCHEMA registry_internal TO \"{}\";",
            database.runtime_role.as_str()
        ))
        .await
        .expect("runtime review schema access");
    let leased = Uuid::from_u128(0xd1);
    let expired_lease = Uuid::from_u128(0xd2);
    for request_id in [leased, expired_lease] {
        seed_submission(
            &database.admin,
            request_id,
            "casework-a",
            "producer-a",
            "policy-a",
        )
        .await;
        database
            .admin
            .execute(
                "UPDATE registry_internal.registry_request_review_submissions
                    SET state='submitting',
                        recovery_deadline=transaction_timestamp()-interval '1 second',
                        lease_until=CASE WHEN request_id=$2
                            THEN transaction_timestamp()+interval '20 seconds'
                            ELSE transaction_timestamp()-interval '1 second' END
                  WHERE request_id=$1",
                &[&request_id, &leased],
            )
            .await
            .expect("seed submitting submission");
    }

    let pool = database.runtime_config.build_pool().expect("runtime pool");
    let authorities = authority_registry("casework-a", "producer-a", "sender", "registry-a");
    assert!(run_review_authority_once_for_test(&pool, &authorities)
        .await
        .expect("expire only unleased recovery"));
    let rows = database
        .admin
        .query(
            "SELECT request_id,state,lease_until,last_error_code
               FROM registry_internal.registry_request_review_submissions
              WHERE request_id=ANY($1) ORDER BY request_id",
            &[&vec![expired_lease, leased]],
        )
        .await
        .expect("read recovery rows");
    assert_eq!(rows.len(), 2);
    for row in rows {
        let request_id: Uuid = row.get(0);
        if request_id == leased {
            // A live lease means another worker holds the submission mid
            // exchange; expiry must wait for that lease to lapse.
            assert_eq!(row.get::<_, String>(1), "submitting");
            assert!(row
                .get::<_, Option<chrono::DateTime<chrono::Utc>>>(2)
                .is_some());
            assert!(row.get::<_, Option<String>>(3).is_none());
        } else {
            assert_eq!(row.get::<_, String>(1), "failed");
            assert!(row
                .get::<_, Option<chrono::DateTime<chrono::Utc>>>(2)
                .is_none());
            assert_eq!(row.get::<_, String>(3), "submission-recovery-expired");
        }
    }

    drop(pool);
    database.cleanup().await;
}

#[tokio::test]
async fn accepted_recovery_expiry_and_poll_exhaustion_become_terminal_preserving_binding() {
    let database = TestDatabase::create(2).await;
    database
        .admin
        .batch_execute(
            "CREATE TABLE registry_internal.registry_request_proposals (
                request_entity_id text NOT NULL,
                request_id uuid NOT NULL,
                proposal_version bigint NOT NULL,
                PRIMARY KEY (request_entity_id,request_id,proposal_version)
            );",
        )
        .await
        .expect("proposal parent table");
    install_review_storage_for_test(&database.admin, &database.runtime_role)
        .await
        .expect("review storage");
    database
        .admin
        .batch_execute(&format!(
            "GRANT USAGE ON SCHEMA registry_internal TO \"{}\";",
            database.runtime_role.as_str()
        ))
        .await
        .expect("runtime review schema access");

    let expired = Uuid::from_u128(0xd6);
    let exhausted = Uuid::from_u128(0xd7);
    for request_id in [expired, exhausted] {
        seed_submission(
            &database.admin,
            request_id,
            "casework-a",
            "producer-a",
            "policy-a",
        )
        .await;
        let review_request_id = Uuid::from_u128(request_id.as_u128() + 100).to_string();
        database
            .admin
            .execute(
                "UPDATE registry_internal.registry_request_review_submissions
                    SET state='accepted',accepted_binding=jsonb_build_object('requestId',$2::text)
                  WHERE request_id=$1",
                &[&request_id, &review_request_id],
            )
            .await
            .expect("seed accepted submission");
    }
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_request_review_submissions
                SET recovery_deadline=transaction_timestamp()-interval '1 second'
              WHERE request_id=$1",
            &[&expired],
        )
        .await
        .expect("expire result recovery");
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_request_review_submissions
                SET result_poll_attempts=1000 WHERE request_id=$1",
            &[&exhausted],
        )
        .await
        .expect("exhaust result poll attempts");

    let pool = database.runtime_config.build_pool().expect("runtime pool");
    let authorities = authority_registry("casework-a", "producer-a", "sender", "registry-a");
    assert!(run_review_authority_once_for_test(&pool, &authorities)
        .await
        .expect("terminalize stranded accepted submissions"));
    let rows = database
        .admin
        .query(
            "SELECT request_id,state,accepted_binding,last_error_code
               FROM registry_internal.registry_request_review_submissions
              WHERE request_id=ANY($1) ORDER BY request_id",
            &[&vec![expired, exhausted]],
        )
        .await
        .expect("read terminal accepted rows");
    assert_eq!(rows.len(), 2);
    for row in rows {
        assert_eq!(row.get::<_, String>(1), "failed");
        let request_id: Uuid = row.get(0);
        let binding: Value = row
            .get::<_, Option<Value>>(2)
            .expect("result give-up must preserve the accepted binding for late correlation");
        assert_eq!(
            binding["requestId"],
            Uuid::from_u128(request_id.as_u128() + 100).to_string()
        );
        assert_eq!(
            row.get::<_, String>(3),
            if request_id == expired {
                "result-recovery-expired"
            } else {
                "result-poll-attempts-exhausted"
            }
        );
    }

    drop(pool);
    database.cleanup().await;
}

#[tokio::test]
async fn result_bearing_cancellations_converge_to_cancelled_without_remote_io() {
    let database = TestDatabase::create(2).await;
    database
        .admin
        .batch_execute(
            "CREATE TABLE registry_internal.registry_request_proposals (
                request_entity_id text NOT NULL,
                request_id uuid NOT NULL,
                proposal_version bigint NOT NULL,
                PRIMARY KEY (request_entity_id,request_id,proposal_version)
            );",
        )
        .await
        .expect("proposal parent table");
    install_review_storage_for_test(&database.admin, &database.runtime_role)
        .await
        .expect("review storage");
    database
        .admin
        .batch_execute(&format!(
            "GRANT USAGE ON SCHEMA registry_internal TO \"{}\";",
            database.runtime_role.as_str()
        ))
        .await
        .expect("runtime review schema access");
    let request_id = Uuid::from_u128(0xc6);
    seed_submission(
        &database.admin,
        request_id,
        "casework-a",
        "producer-a",
        "policy-a",
    )
    .await;
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_request_review_submissions
                SET state='cancelling',withdrawn=true,
                    accepted_binding=jsonb_build_object('requestId',$2::text),
                    recovery_deadline=transaction_timestamp()-interval '1 second'
              WHERE request_id=$1",
            &[
                &request_id,
                &Uuid::from_u128(request_id.as_u128() + 100).to_string(),
            ],
        )
        .await
        .expect("seed expired cancellation");
    database
        .admin
        .execute(
            "INSERT INTO registry_internal.registry_request_review_results
             (request_entity_id,request_id,proposal_version,authority,result_id,result,status,
              completed_at,available_until)
             VALUES ('requests',$1,1,'casework-a',$2,'{}'::jsonb,'cancelled',
                     transaction_timestamp(),transaction_timestamp()+interval '1 day')",
            &[&request_id, &Uuid::from_u128(0xc7)],
        )
        .await
        .expect("stored cancellation result");

    let pool = database.runtime_config.build_pool().expect("runtime pool");
    let authorities = authority_registry("casework-a", "producer-a", "sender", "registry-a");
    assert!(run_review_authority_once_for_test(&pool, &authorities)
        .await
        .expect("converge result-bearing cancellation"));
    let row = database
        .admin
        .query_one(
            "SELECT state,accepted_binding,last_error_code,lease_until
               FROM registry_internal.registry_request_review_submissions
              WHERE request_id=$1",
            &[&request_id],
        )
        .await
        .expect("converged submission");
    assert_eq!(row.get::<_, String>(0), "cancelled");
    assert!(row.get::<_, Option<Value>>(1).is_some());
    assert_eq!(row.get::<_, Option<String>>(2), None);
    assert_eq!(row.get::<_, Option<chrono::DateTime<chrono::Utc>>>(3), None);

    drop(pool);
    database.cleanup().await;
}

#[tokio::test(flavor = "current_thread")]
async fn real_postgres_completion_inbox_deduplicates_refuses_substitution_expires_and_redacts_diagnostics(
) {
    let mut database = TestDatabase::create(2).await;
    database
        .admin
        .batch_execute(
            "CREATE TABLE registry_internal.registry_request_proposals (
                request_entity_id text NOT NULL,
                request_id uuid NOT NULL,
                proposal_version bigint NOT NULL,
                PRIMARY KEY (request_entity_id,request_id,proposal_version)
            );",
        )
        .await
        .expect("proposal parent table");
    install_review_storage_for_test(&database.admin, &database.runtime_role)
        .await
        .expect("review storage");
    database
        .admin
        .batch_execute(&format!(
            "GRANT USAGE ON SCHEMA registry_internal TO \"{}\";",
            database.runtime_role.as_str()
        ))
        .await
        .expect("runtime review schema access");

    let authority_canary = "casework-authority-private-canary";
    let recipient_canary = "registry-recipient-private-canary";
    let bearer_canary = "completion-bearer-private-canary";
    let authorities = authority_registry(
        authority_canary,
        "registry-producer",
        bearer_canary,
        recipient_canary,
    );
    let matched_authority = authorities
        .completion_authority(bearer_canary, recipient_canary)
        .expect("exact completion sender and recipient binding");
    assert_eq!(matched_authority, authority_canary);
    let completion = ReviewCompletion {
        event_type: ReviewCompletionType::ReviewCompleted,
        event_id: Uuid::new_v4(),
        request_id: Uuid::new_v4(),
        result_id: Uuid::new_v4(),
        completed_at: chrono::Utc::now(),
    };
    let expires_at = chrono::Utc::now() + chrono::Duration::days(7);
    let transaction = database.admin.transaction().await.unwrap();
    receive_completion(&transaction, matched_authority, &completion, expires_at)
        .await
        .expect("early completion retained");
    receive_completion(&transaction, matched_authority, &completion, expires_at)
        .await
        .expect("exact redelivery is idempotent");
    let substituted = ReviewCompletion {
        result_id: Uuid::new_v4(),
        ..completion.clone()
    };
    let refusal = receive_completion(&transaction, matched_authority, &substituted, expires_at)
        .await
        .expect_err("substituted delivery is refused");
    assert!(matches!(refusal, MutationError::PreconditionFailed));
    let diagnostic = format!("{refusal:?}: {refusal}");
    for canary in [authority_canary, recipient_canary, bearer_canary] {
        assert!(
            !diagnostic.contains(canary),
            "completion refusal diagnostic exposed {canary}"
        );
    }
    let expired_unmatched = ReviewCompletion {
        event_id: Uuid::new_v4(),
        request_id: Uuid::new_v4(),
        result_id: Uuid::new_v4(),
        ..completion.clone()
    };
    receive_completion(
        &transaction,
        matched_authority,
        &expired_unmatched,
        expires_at,
    )
    .await
    .expect("expired unmatched completion retained until the worker pass");
    let retained = ReviewCompletion {
        event_id: Uuid::new_v4(),
        request_id: Uuid::new_v4(),
        result_id: Uuid::new_v4(),
        ..completion.clone()
    };
    receive_completion(&transaction, matched_authority, &retained, expires_at)
        .await
        .expect("unexpired unmatched completion retained");
    transaction
        .execute(
            "UPDATE registry_internal.registry_request_review_completions
                SET state='correlated'
              WHERE authority=$1 AND event_id=$2",
            &[&authority_canary, &completion.event_id],
        )
        .await
        .expect("represent a correlated completion delivery");
    transaction.commit().await.unwrap();

    let row = database
        .admin
        .query_one(
            "SELECT state,review_request_id,result_id,expires_at > received_at,
                    (SELECT count(*) FROM registry_internal.registry_request_review_completions
                      WHERE authority=$1)
               FROM registry_internal.registry_request_review_completions
              WHERE authority=$1 AND event_id=$2",
            &[&authority_canary, &completion.event_id],
        )
        .await
        .expect("retained unmatched completion");
    assert_eq!(row.get::<_, String>(0), "correlated");
    assert_eq!(row.get::<_, Uuid>(1), completion.request_id);
    assert_eq!(row.get::<_, Uuid>(2), completion.result_id);
    assert!(row.get::<_, bool>(3));
    assert_eq!(row.get::<_, i64>(4), 3);

    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_request_review_completions
                SET received_at=transaction_timestamp()-interval '2 days',
                    expires_at=transaction_timestamp()-interval '1 day'
              WHERE authority=$1 AND event_id IN ($2,$3)",
            &[
                &authority_canary,
                &completion.event_id,
                &expired_unmatched.event_id,
            ],
        )
        .await
        .expect("expire one correlated delivery and one unmatched completion");
    let logs = CapturedLogs::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_target(false)
        .with_current_span(false)
        .with_span_list(false)
        .with_max_level(tracing::Level::DEBUG)
        .with_writer(logs.clone())
        .finish();
    let capture = tracing::subscriber::set_default(subscriber);
    let pool = database.runtime_config.build_pool().expect("runtime pool");
    assert!(run_review_authority_once_for_test(&pool, &authorities)
        .await
        .expect("review worker retention pass"));
    drop(capture);
    let output = logs.text();
    assert!(output.contains("BReg review completion retention pass erased expired rows"));
    assert!(output.contains("\"erased\":2"));
    for canary in [
        authority_canary,
        recipient_canary,
        bearer_canary,
        &completion.event_id.to_string(),
        &completion.request_id.to_string(),
        &completion.result_id.to_string(),
        &expired_unmatched.event_id.to_string(),
        &expired_unmatched.request_id.to_string(),
        &expired_unmatched.result_id.to_string(),
    ] {
        assert!(
            !output.contains(canary),
            "review retention log exposed {canary}: {output}"
        );
    }
    let remaining = database
        .admin
        .query_one(
            "SELECT count(*),bool_and(event_id=$2),bool_and(state='unmatched')
               FROM registry_internal.registry_request_review_completions
              WHERE authority=$1",
            &[&authority_canary, &retained.event_id],
        )
        .await
        .expect("only unexpired unmatched delivery remains");
    assert_eq!(remaining.get::<_, i64>(0), 1);
    assert!(remaining.get::<_, bool>(1));
    assert!(remaining.get::<_, bool>(2));

    drop(pool);
    database.cleanup().await;
}

#[tokio::test(flavor = "current_thread")]
async fn completion_arriving_after_its_result_is_correlated_immediately() {
    let mut database = TestDatabase::create(2).await;
    database
        .admin
        .batch_execute(
            "CREATE TABLE registry_internal.registry_request_proposals (
                request_entity_id text NOT NULL,
                request_id uuid NOT NULL,
                proposal_version bigint NOT NULL,
                PRIMARY KEY (request_entity_id,request_id,proposal_version)
            );",
        )
        .await
        .expect("proposal parent table");
    install_review_storage_for_test(&database.admin, &database.runtime_role)
        .await
        .expect("review storage");

    let source_request_id = Uuid::new_v4();
    let review_request_id = Uuid::new_v4();
    let result_id = Uuid::new_v4();
    seed_submission(
        &database.admin,
        source_request_id,
        "casework-a",
        "producer-a",
        "policy-a",
    )
    .await;
    let accepted = json!({"requestId":review_request_id});
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_request_review_submissions
                SET state='accepted',accepted_binding=$2
              WHERE request_id=$1",
            &[&source_request_id, &accepted],
        )
        .await
        .unwrap();
    database
        .admin
        .execute(
            "INSERT INTO registry_internal.registry_request_review_results
             (request_entity_id,request_id,proposal_version,authority,result_id,result,status,
              completed_at,available_until)
             VALUES ('requests',$1,1,'casework-a',$2,$3,'approved',now(),now()+interval '1 day')",
            &[
                &source_request_id,
                &result_id,
                &json!({"requestId":review_request_id}),
            ],
        )
        .await
        .unwrap();
    let exponent_values = vec![1e100_f64; 400];
    assert!(serde_json::to_vec(&exponent_values).unwrap().len() < 32_768);
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_request_review_results
                SET result=jsonb_set(result,'{numericExpansionProbe}',$2::jsonb)
              WHERE request_id=$1",
            &[&source_request_id, &json!(exponent_values)],
        )
        .await
        .expect("store bounded result whose PostgreSQL numeric rendering exceeds 32 KiB");
    let stored_result_bytes: i32 = database
        .admin
        .query_one(
            "SELECT octet_length(result::text)
               FROM registry_internal.registry_request_review_results WHERE request_id=$1",
            &[&source_request_id],
        )
        .await
        .expect("measure PostgreSQL result representation")
        .get(0);
    assert!(stored_result_bytes > 32_768);
    let completion = ReviewCompletion {
        event_type: ReviewCompletionType::ReviewCompleted,
        event_id: Uuid::new_v4(),
        request_id: review_request_id,
        result_id,
        completed_at: chrono::Utc::now(),
    };
    let transaction = database.admin.transaction().await.unwrap();
    receive_completion(
        &transaction,
        "casework-a",
        &completion,
        chrono::Utc::now() + chrono::Duration::days(7),
    )
    .await
    .expect("late completion is accepted");
    transaction.commit().await.unwrap();
    let state: String = database
        .admin
        .query_one(
            "SELECT state FROM registry_internal.registry_request_review_completions
              WHERE authority='casework-a' AND event_id=$1",
            &[&completion.event_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(state, "correlated");

    database.cleanup().await;
}

#[tokio::test(flavor = "current_thread")]
async fn early_unmatched_completion_is_correlated_by_the_worker_after_result_commit() {
    let mut database = TestDatabase::create(2).await;
    database
        .admin
        .batch_execute(
            "CREATE TABLE registry_internal.registry_request_proposals (
                request_entity_id text NOT NULL,
                request_id uuid NOT NULL,
                proposal_version bigint NOT NULL,
                PRIMARY KEY (request_entity_id,request_id,proposal_version)
            );",
        )
        .await
        .expect("proposal parent table");
    install_review_storage_for_test(&database.admin, &database.runtime_role)
        .await
        .expect("review storage");
    database
        .admin
        .batch_execute(&format!(
            "GRANT USAGE ON SCHEMA registry_internal TO \"{}\";",
            database.runtime_role.as_str()
        ))
        .await
        .expect("runtime review schema access");

    let source_request_id = Uuid::new_v4();
    let review_request_id = Uuid::new_v4();
    let result_id = Uuid::new_v4();
    seed_submission(
        &database.admin,
        source_request_id,
        "casework-a",
        "producer-a",
        "policy-a",
    )
    .await;
    let completion = ReviewCompletion {
        event_type: ReviewCompletionType::ReviewCompleted,
        event_id: Uuid::new_v4(),
        request_id: review_request_id,
        result_id,
        completed_at: chrono::Utc::now(),
    };
    let transaction = database.admin.transaction().await.unwrap();
    receive_completion(
        &transaction,
        "casework-a",
        &completion,
        chrono::Utc::now() + chrono::Duration::days(7),
    )
    .await
    .expect("early completion is retained");
    transaction.commit().await.unwrap();

    let accepted = json!({"requestId":review_request_id});
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_request_review_submissions
                SET state='accepted',accepted_binding=$2
              WHERE request_id=$1",
            &[&source_request_id, &accepted],
        )
        .await
        .unwrap();
    database
        .admin
        .execute(
            "INSERT INTO registry_internal.registry_request_review_results
             (request_entity_id,request_id,proposal_version,authority,result_id,result,status,
              completed_at,available_until)
             VALUES ('requests',$1,1,'casework-a',$2,$3,'approved',now(),now()+interval '1 day')",
            &[
                &source_request_id,
                &result_id,
                &json!({"requestId":review_request_id}),
            ],
        )
        .await
        .unwrap();

    let pool = database.runtime_config.build_pool().expect("runtime pool");
    let authorities = authority_registry("casework-a", "producer-a", "sender", "registry-a");
    assert!(run_review_authority_once_for_test(&pool, &authorities)
        .await
        .expect("stored completion reconciliation"));
    let state: String = database
        .admin
        .query_one(
            "SELECT state FROM registry_internal.registry_request_review_completions
              WHERE authority='casework-a' AND event_id=$1",
            &[&completion.event_id],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(state, "correlated");

    drop(pool);
    database.cleanup().await;
}

#[tokio::test(flavor = "current_thread")]
async fn retained_review_work_refuses_startup_without_its_authority_binding() {
    let database = TestDatabase::create(2).await;
    database
        .admin
        .batch_execute(
            "CREATE TABLE registry_internal.registry_request_state (
                request_entity_id text NOT NULL,
                request_id uuid NOT NULL,
                proposal_version bigint NOT NULL,
                state text NOT NULL,
                PRIMARY KEY (request_entity_id,request_id)
            );
            CREATE TABLE registry_internal.registry_request_proposals (
                request_entity_id text NOT NULL,
                request_id uuid NOT NULL,
                proposal_version bigint NOT NULL,
                PRIMARY KEY (request_entity_id,request_id,proposal_version)
            );",
        )
        .await
        .expect("proposal parent table");
    install_review_storage_for_test(&database.admin, &database.runtime_role)
        .await
        .expect("review storage");
    database
        .admin
        .batch_execute(&format!(
            "GRANT USAGE ON SCHEMA registry_internal TO \"{}\";
             GRANT SELECT ON registry_internal.registry_request_state TO \"{}\";",
            database.runtime_role.as_str(),
            database.runtime_role.as_str()
        ))
        .await
        .expect("runtime review schema access");
    let request_id = Uuid::new_v4();
    seed_submission(
        &database.admin,
        request_id,
        "casework-retained",
        "producer-retained",
        "policy-retained",
    )
    .await;
    database
        .admin
        .execute(
            "INSERT INTO registry_internal.registry_request_state
             VALUES ('requests',$1,1,'submitted')",
            &[&request_id],
        )
        .await
        .expect("request state");
    let pool = database.runtime_config.build_pool().expect("runtime pool");
    assert!(matches!(
        verify_retained_bindings(&pool, None, None).await,
        Err(MutationError::PreconditionFailed)
    ));
    let mismatched = authority_registry(
        "casework-retained",
        "different-producer",
        "sender",
        "registry-a",
    );
    assert!(matches!(
        verify_retained_bindings(&pool, Some(&mismatched), None).await,
        Err(MutationError::PreconditionFailed)
    ));
    let authorities = authority_registry(
        "casework-retained",
        "producer-retained",
        "sender",
        "registry-a",
    );
    verify_retained_bindings(&pool, Some(&authorities), None)
        .await
        .expect("retained authority keeps its durable work serviceable");

    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_request_review_submissions
                SET state='accepted',accepted_binding='{}'::jsonb
              WHERE request_entity_id='requests' AND request_id=$1 AND proposal_version=1",
            &[&request_id],
        )
        .await
        .expect("submission accepted");
    database
        .admin
        .execute(
            "INSERT INTO registry_internal.registry_request_review_results
             (request_entity_id,request_id,proposal_version,authority,result_id,result,status,
              completed_at,available_until)
             VALUES ('requests',$1,1,'casework-retained',$2,'{}'::jsonb,'approved',
                     transaction_timestamp(),transaction_timestamp()+interval '1 day')",
            &[&request_id, &Uuid::new_v4()],
        )
        .await
        .expect("approved result");
    assert!(matches!(
        verify_retained_bindings(&pool, None, None).await,
        Err(MutationError::PreconditionFailed)
    ));

    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_request_state SET state='applied'
              WHERE request_entity_id='requests' AND request_id=$1",
            &[&request_id],
        )
        .await
        .expect("request applied");
    verify_retained_bindings(&pool, None, None)
        .await
        .expect("an applied manual request no longer retains its authority");

    drop(pool);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_authority_concurrent_workers_keep_clients_credentials_and_rows_isolated() {
    let database = TestDatabase::create(4).await;
    database
        .admin
        .batch_execute(
            "CREATE TABLE registry_internal.registry_request_proposals (
                request_entity_id text NOT NULL,
                request_id uuid NOT NULL,
                proposal_version bigint NOT NULL,
                PRIMARY KEY (request_entity_id,request_id,proposal_version)
            );",
        )
        .await
        .expect("proposal parent table");
    install_review_storage_for_test(&database.admin, &database.runtime_role)
        .await
        .expect("review storage");

    let request_a = Uuid::from_u128(0xa1);
    let request_b = Uuid::from_u128(0xb1);
    seed_submission(
        &database.admin,
        request_a,
        "casework-a",
        "producer-a",
        "policy-a",
    )
    .await;
    seed_submission(
        &database.admin,
        request_b,
        "casework-b",
        "producer-b",
        "policy-b",
    )
    .await;

    let state_a = Arc::new(AuthorityState {
        producer_id: "producer-a",
        expected_token: "Bearer token-a",
        expected_profile: "producer-profile-a",
        accepted_request_id: Uuid::from_u128(0xa2),
        requests: AtomicUsize::new(0),
        gate: None,
    });
    let state_b = Arc::new(AuthorityState {
        producer_id: "producer-b",
        expected_token: "Bearer token-b",
        expected_profile: "producer-profile-b",
        accepted_request_id: Uuid::from_u128(0xb2),
        requests: AtomicUsize::new(0),
        gate: None,
    });
    let (endpoint_a, server_a) = serve_authority(Arc::clone(&state_a)).await;
    let (endpoint_b, server_b) = serve_authority(Arc::clone(&state_b)).await;
    let client_a = authority_client(endpoint_a, "producer-profile-a");
    let client_b = authority_client(endpoint_b, "producer-profile-b");
    let token_a = BearerToken::new("token-a").unwrap();
    let token_b = BearerToken::new("token-b").unwrap();
    let (connection_a, connection_task_a) = database.connect_admin().await;
    let (connection_b, connection_task_b) = database.connect_admin().await;

    let first = run_one_submission(
        &connection_a,
        "casework-a",
        &client_a,
        "producer-profile-a",
        &token_a,
        TEST_LEASE_SECONDS,
    );
    let second = run_one_submission(
        &connection_b,
        "casework-b",
        &client_b,
        "producer-profile-b",
        &token_b,
        TEST_LEASE_SECONDS,
    );
    let (first, second) = tokio::join!(first, second);
    let first = first.expect("first concurrent worker");
    let second = second.expect("second concurrent worker");
    assert!(first);
    assert!(second);

    let rows = database
        .admin
        .query(
            "SELECT authority,request_id,accepted_binding->>'requestId'
               FROM registry_internal.registry_request_review_submissions
              ORDER BY authority",
            &[],
        )
        .await
        .expect("accepted authority bindings");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].get::<_, String>(0), "casework-a");
    assert_eq!(rows[0].get::<_, Uuid>(1), request_a);
    assert_eq!(
        rows[0].get::<_, String>(2),
        state_a.accepted_request_id.to_string()
    );
    assert_eq!(rows[1].get::<_, String>(0), "casework-b");
    assert_eq!(rows[1].get::<_, Uuid>(1), request_b);
    assert_eq!(
        rows[1].get::<_, String>(2),
        state_b.accepted_request_id.to_string()
    );
    assert_eq!(state_a.requests.load(Ordering::SeqCst), 1);
    assert_eq!(state_b.requests.load(Ordering::SeqCst), 1);

    connection_task_a.abort();
    connection_task_b.abort();
    server_a.abort();
    server_b.abort();
    database.cleanup().await;
}

#[tokio::test]
async fn unavailable_authority_does_not_starve_another_authoritys_result() {
    let database = TestDatabase::create(2).await;
    database
        .admin
        .batch_execute(
            "CREATE TABLE registry_internal.registry_request_proposals (
                request_entity_id text NOT NULL,
                request_id uuid NOT NULL,
                proposal_version bigint NOT NULL,
                PRIMARY KEY (request_entity_id,request_id,proposal_version)
            );",
        )
        .await
        .expect("proposal parent table");
    install_review_storage_for_test(&database.admin, &database.runtime_role)
        .await
        .expect("review storage");
    database
        .admin
        .batch_execute(&format!(
            "GRANT USAGE ON SCHEMA registry_internal TO \"{}\";",
            database.runtime_role.as_str()
        ))
        .await
        .expect("runtime review schema access");

    let request_a = Uuid::from_u128(0xa11);
    let request_b = Uuid::from_u128(0xb11);
    seed_submission(
        &database.admin,
        request_a,
        "casework-a",
        "producer-a",
        "policy-a",
    )
    .await;
    seed_submission(
        &database.admin,
        request_b,
        "casework-b",
        "producer-b",
        "policy-b",
    )
    .await;

    let submission_a = Arc::new(AuthorityState {
        producer_id: "producer-a",
        expected_token: "Bearer token-a",
        expected_profile: "producer-profile-a",
        accepted_request_id: Uuid::from_u128(0xa12),
        requests: AtomicUsize::new(0),
        gate: None,
    });
    let submission_b = Arc::new(AuthorityState {
        producer_id: "producer-b",
        expected_token: "Bearer token-b",
        expected_profile: "producer-profile-b",
        accepted_request_id: Uuid::from_u128(0xb12),
        requests: AtomicUsize::new(0),
        gate: None,
    });
    let (endpoint_a, server_a) = serve_authority(submission_a).await;
    let (submission_endpoint_b, submission_server_b) = serve_authority(submission_b).await;
    assert!(run_one_submission(
        &database.admin,
        "casework-a",
        &authority_client(endpoint_a.clone(), "producer-profile-a"),
        "producer-profile-a",
        &BearerToken::new("token-a").unwrap(),
        TEST_LEASE_SECONDS,
    )
    .await
    .expect("authority A submission"));
    assert!(run_one_submission(
        &database.admin,
        "casework-b",
        &authority_client(submission_endpoint_b, "producer-profile-b"),
        "producer-profile-b",
        &BearerToken::new("token-b").unwrap(),
        TEST_LEASE_SECONDS,
    )
    .await
    .expect("authority B submission"));
    server_a.abort();
    submission_server_b.abort();

    let accepted_b = database
        .admin
        .query_one(
            "SELECT accepted_binding
               FROM registry_internal.registry_request_review_submissions
              WHERE authority='casework-b'",
            &[],
        )
        .await
        .expect("accepted authority B binding")
        .get::<_, Value>(0);
    let (result_endpoint_b, result_state_b, result_server_b) =
        serve_available_result_authority(accepted_b.clone()).await;
    let accepted_b: ReviewRequestAccepted =
        serde_json::from_value(accepted_b).expect("typed authority B binding");
    assert!(matches!(
        authority_client(result_endpoint_b.clone(), "producer-profile-b")
            .result(
                ReviewAuth::new(&BearerToken::new("token-b").unwrap(), "producer-profile-b",),
                &accepted_b,
            )
            .await
            .expect("authority B result fixture"),
        ReviewResultResponse::Available(_)
    ));
    result_state_b.lookups.store(0, Ordering::SeqCst);
    let configured_a = Arc::new(
        ReviewAuthorityClient::new(
            "casework-a".to_owned(),
            authority_client(endpoint_a, "producer-profile-a"),
            Arc::new(registry_platform_httputil::StaticToken::new("token-a".to_owned()).unwrap()),
            "producer-profile-a".to_owned(),
            "producer-a".to_owned(),
            7,
            None,
            None,
        )
        .expect("authority A configuration"),
    );
    let configured_b = Arc::new(
        ReviewAuthorityClient::new(
            "casework-b".to_owned(),
            authority_client(result_endpoint_b, "producer-profile-b"),
            Arc::new(registry_platform_httputil::StaticToken::new("token-b".to_owned()).unwrap()),
            "producer-profile-b".to_owned(),
            "producer-b".to_owned(),
            7,
            None,
            None,
        )
        .expect("authority B configuration"),
    );
    let authorities = ReviewAuthorityRegistry::new(BTreeMap::from([
        ("casework-a".to_owned(), configured_a),
        ("casework-b".to_owned(), configured_b),
    ]))
    .expect("two-authority registry");
    let pool = database.runtime_config.build_pool().expect("runtime pool");

    assert!(run_review_authority_once_for_test(&pool, &authorities)
        .await
        .expect("authority B must progress while authority A is unavailable"));
    assert_eq!(result_state_b.lookups.load(Ordering::SeqCst), 1);
    let results = database
        .admin
        .query(
            "SELECT authority,request_id
               FROM registry_internal.registry_request_review_results
              ORDER BY authority",
            &[],
        )
        .await
        .expect("reconciled results");
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].get::<_, String>(0), "casework-b");
    assert_eq!(results[0].get::<_, Uuid>(1), request_b);
    let retry = database
        .admin
        .query_one(
            "SELECT next_result_poll_at > transaction_timestamp()
               FROM registry_internal.registry_request_review_submissions
              WHERE authority='casework-a'",
            &[],
        )
        .await
        .expect("authority A retry backoff")
        .get::<_, bool>(0);
    assert!(retry);

    result_server_b.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "current_thread")]
async fn sustained_application_backlog_does_not_starve_authority_result_polls() {
    let database = TestDatabase::create(3).await;
    database
        .admin
        .batch_execute(
            "CREATE TABLE registry_internal.registry_request_proposals (
                request_entity_id text NOT NULL,
                request_id uuid NOT NULL,
                proposal_version bigint NOT NULL,
                PRIMARY KEY (request_entity_id,request_id,proposal_version)
            );",
        )
        .await
        .expect("proposal parent table");
    install_review_storage_for_test(&database.admin, &database.runtime_role)
        .await
        .expect("review storage");
    database
        .admin
        .batch_execute(&format!(
            "GRANT USAGE ON SCHEMA registry_internal TO \"{}\";",
            database.runtime_role.as_str()
        ))
        .await
        .expect("runtime review schema access");

    // One accepted submission whose result is only discoverable through the
    // counting authority below.
    let request_id = Uuid::from_u128(0xe6);
    seed_submission(
        &database.admin,
        request_id,
        "casework-a",
        "producer-a",
        "policy-a",
    )
    .await;
    let accepting = Arc::new(AuthorityState {
        producer_id: "producer-a",
        expected_token: "Bearer token-a",
        expected_profile: "producer-profile-a",
        accepted_request_id: Uuid::from_u128(0xe7),
        requests: AtomicUsize::new(0),
        gate: None,
    });
    let (endpoint, server) = serve_authority(accepting).await;
    assert!(run_one_submission(
        &database.admin,
        "casework-a",
        &authority_client(endpoint, "producer-profile-a"),
        "producer-profile-a",
        &BearerToken::new("token-a").unwrap(),
        TEST_LEASE_SECONDS,
    )
    .await
    .expect("accept the review submission"));
    server.abort();
    let accepted: Value = database
        .admin
        .query_one(
            "SELECT accepted_binding
               FROM registry_internal.registry_request_review_submissions
              WHERE request_id=$1",
            &[&request_id],
        )
        .await
        .expect("accepted authority binding")
        .get(0);
    let (result_endpoint, result_state, result_server) =
        serve_available_result_authority(accepted).await;
    let counting = Arc::new(
        ReviewAuthorityClient::new(
            "casework-a".to_owned(),
            authority_client(result_endpoint, "producer-profile-a"),
            Arc::new(registry_platform_httputil::StaticToken::new("token-a".to_owned()).unwrap()),
            "producer-profile-a".to_owned(),
            "producer-a".to_owned(),
            7,
            None,
            None,
        )
        .expect("counting review authority"),
    );
    let authorities = Arc::new(
        ReviewAuthorityRegistry::new(BTreeMap::from([("casework-a".to_owned(), counting)]))
            .expect("authority registry"),
    );

    // A backlog of distinct due application jobs, each failing slowly, keeps
    // the application queue continuously due: every worker iteration finds
    // application work while the backlog drains.
    const BACKLOG_JOBS: u64 = 30;
    let mut job_ids = Vec::new();
    for _ in 0..BACKLOG_JOBS {
        let job_id = Uuid::new_v4();
        seed_application_job(&database.admin, Uuid::new_v4(), Uuid::new_v4(), job_id).await;
        job_ids.push(job_id);
    }
    let slow_source = Router::new().route(
        "/v1/records/requests/{request_id}",
        get(|| async {
            tokio::time::sleep(Duration::from_millis(200)).await;
            StatusCode::SERVICE_UNAVAILABLE
        }),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let slow_endpoint: reqwest::Url = format!("http://{}/", listener.local_addr().unwrap())
        .parse()
        .unwrap();
    let slow_server = tokio::spawn(async move { axum::serve(listener, slow_source).await });
    let executors = Arc::new(
        ReviewExecutorRegistry::new(BTreeMap::from([(
            "registry-automatic".to_owned(),
            Arc::new(executor(slow_endpoint)),
        )]))
        .expect("executor registry"),
    );

    let pool = database.runtime_config.build_pool().expect("runtime pool");
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let worker = ReviewWorker::new(pool.clone(), Some(authorities), Some(executors));
    let worker_task = tokio::spawn(worker.run(shutdown_rx));

    // Wait until the backlog is demonstrably draining, then require that the
    // authority result poll has already run: interleaving must not wait for
    // the application queue to empty.
    let mut attempts = 0;
    for _ in 0..200 {
        attempts = database
            .admin
            .query_one(
                "SELECT coalesce(sum(attempt_count),0)
                   FROM registry_internal.registry_request_application_jobs
                  WHERE job_id=ANY($1)",
                &[&job_ids],
            )
            .await
            .expect("backlog application attempts")
            .get::<_, i64>(0) as i32;
        if attempts >= 5 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let lookups = result_state.lookups.load(Ordering::SeqCst);
    shutdown_tx.send(true).expect("signal worker shutdown");
    worker_task.await.expect("worker joins");
    slow_server.abort();
    result_server.abort();
    assert!(
        attempts >= 5,
        "the application backlog must be draining for the observation to count"
    );
    assert!(
        lookups >= 1,
        "authority result polls were starved while a sustained application backlog drained"
    );

    drop(pool);
    database.cleanup().await;
}
