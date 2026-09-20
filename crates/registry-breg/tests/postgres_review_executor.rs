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
    install_review_storage_for_test, poll_one_result, receive_completion, run_one_submission,
    run_review_application_once_for_test, run_review_authority_once_for_test,
    verify_retained_bindings, ReviewAuthorityClient, ReviewAuthorityRegistry, ReviewExecutorClient,
};
use registry_review_client::{
    submission_digest, BearerToken, ContentDigest, ReviewClient, ReviewClientConfig,
    ReviewCompletion, ReviewCompletionType, ReviewContext, ReviewCreateRequest,
    ReviewRequestAccepted, ReviewResultResponse, SourceContextBinding, SubjectBinding,
};
use serde_json::{json, Value};
use tokio::net::TcpListener;
use tokio::sync::Notify;
use uuid::Uuid;
use zeroize::Zeroizing;

use postgres_harness::TestDatabase;

const DIGEST: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const TRACEPARENT: &str = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01";

struct SourceState {
    request_id: Uuid,
    application_id: Uuid,
    gets: AtomicUsize,
    posts: AtomicUsize,
}

struct ConvergenceState {
    denied_request_id: Uuid,
    applied_request_id: Uuid,
    application_id: Uuid,
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

fn authority_client(endpoint: reqwest::Url, profile: &str) -> ReviewClient {
    ReviewClient::new(
        ReviewClientConfig::new(endpoint)
            .with_profile(profile)
            .with_request_timeout(Duration::from_secs(2)),
    )
    .expect("review client")
}

fn authority_registry(
    authority: &str,
    producer_id: &str,
    completion_token: &str,
    completion_recipient: &str,
) -> Arc<ReviewAuthorityRegistry> {
    let client = ReviewClient::new(
        ReviewClientConfig::new("http://127.0.0.1:9/".parse().expect("loopback URL"))
            .with_profile("producer-profile"),
    )
    .expect("review client");
    let configured = Arc::new(
        ReviewAuthorityClient::new(
            authority.to_owned(),
            client,
            Arc::new(
                registry_platform_httputil::StaticToken::new("outgoing-token".to_owned())
                    .expect("outgoing token"),
            ),
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
) -> impl IntoResponse {
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
        Some("review-apply-00000000-0000-4000-8000-000000000003")
    );
    assert_eq!(body, json!({"proposalVersion": 7, "effectDigest": DIGEST}));
    if state.posts.fetch_add(1, Ordering::SeqCst) == 0 {
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

fn executor(endpoint: reqwest::Url) -> ReviewExecutorClient {
    ReviewExecutorClient::new(
        "registry-automatic".to_owned(),
        endpoint,
        BearerToken::new("ordinary-executor-token").expect("token"),
        "registry-a".to_owned(),
        "automatic-applier".to_owned(),
        BTreeMap::from([("requests".to_owned(), "requests".to_owned())]),
        Duration::from_secs(2),
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
        application_id,
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
            "SELECT state,application_id FROM registry_internal.registry_request_application_jobs
              WHERE job_id=$1",
            &[&applied_job_id],
        )
        .await
        .expect("converged job");
    assert_eq!(applied.get::<_, String>(0), "applied");
    assert_eq!(applied.get::<_, Uuid>(1), application_id);
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
        let outcome = run_one_submission(&worker, "casework-a", &review_client, &token).await;
        (worker, review_client, token, outcome)
    });
    gate.entered.notified().await;
    assert_backend_has_no_transaction_or_row_lock(&database.admin, worker_pid).await;
    gate.release.notify_one();
    let (mut worker, review_client, token, outcome) = submission.await.expect("submission worker");
    assert!(outcome.expect("submission succeeds"));

    let lookup = tokio::spawn(async move {
        let outcome = poll_one_result(&mut worker, "casework-a", &review_client, &token).await;
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
    seed_submission(
        &database.admin,
        Uuid::new_v4(),
        "casework-retained",
        "producer-retained",
        "policy-retained",
    )
    .await;
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

    let first = run_one_submission(&connection_a, "casework-a", &client_a, &token_a);
    let second = run_one_submission(&connection_b, "casework-b", &client_b, &token_b);
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
        &BearerToken::new("token-a").unwrap(),
    )
    .await
    .expect("authority A submission"));
    assert!(run_one_submission(
        &database.admin,
        "casework-b",
        &authority_client(submission_endpoint_b, "producer-profile-b"),
        &BearerToken::new("token-b").unwrap(),
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
            .result(&BearerToken::new("token-b").unwrap(), &accepted_b)
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
