// SPDX-License-Identifier: Apache-2.0
//! Conforming authenticated loopback Review authority with synthetic values.
use axum::{
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use registry_review_client::{
    PolicyBinding, ReviewCreateRequest, ReviewRequestAccepted, ReviewRequestLifecycle,
    ReviewRequestView, ReviewResult, ReviewResultStatus,
};
use serde_json::{json, Value};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};
use uuid::Uuid;

struct Token;
#[async_trait::async_trait]
impl registry_platform_httputil::TokenProvider for Token {
    async fn bearer_token(
        &self,
    ) -> Result<registry_platform_httputil::BearerToken, registry_platform_httputil::TokenError>
    {
        registry_platform_httputil::BearerToken::new("synthetic-loopback-review-token")
    }
}
struct StateData {
    policy: PolicyBinding,
    registry_id: String,
    accepted: Mutex<Option<ReviewRequestAccepted>>,
    result: Mutex<Option<ReviewResult>>,
    creates: AtomicUsize,
    reads: AtomicUsize,
    results: AtomicUsize,
    results_unavailable: AtomicBool,
}
pub struct LocalAuthority {
    pub registry: Arc<registry_breg::review_store::ReviewAuthorityRegistry>,
    state: Arc<StateData>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for LocalAuthority {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl LocalAuthority {
    pub async fn start(policy: PolicyBinding) -> Self {
        Self::start_for_registry(policy, "proposal-test").await
    }
    pub async fn start_for_registry(policy: PolicyBinding, registry_id: &str) -> Self {
        let state = Arc::new(StateData {
            policy,
            registry_id: registry_id.into(),
            accepted: Mutex::new(None),
            result: Mutex::new(None),
            creates: 0.into(),
            reads: 0.into(),
            results: 0.into(),
            results_unavailable: false.into(),
        });
        let router = Router::new()
            .route("/v1/review-requests", axum::routing::post(create))
            .route("/v1/review-requests/{id}", get(request))
            .route("/v1/review-requests/{id}/result", get(result))
            .route("/v1/review-results", get(feed))
            .with_state(state.clone());
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            axum::serve(listener, router).await.unwrap();
        });
        let client = registry_review_client::ReviewClient::new(
            registry_review_client::ReviewClientConfig::new(
                format!("http://{address}/").parse().unwrap(),
            ),
        )
        .unwrap();
        let authority = Arc::new(
            registry_breg::review_store::ReviewAuthorityClient::new(
                "local-review".into(),
                client,
                Arc::new(Token),
                "producer".into(),
                "proposal-producer".into(),
                7,
                None,
                None,
            )
            .unwrap(),
        );
        let registry = Arc::new(
            registry_breg::review_store::ReviewAuthorityRegistry::new(
                std::collections::BTreeMap::from([("local-review".into(), authority)]),
            )
            .unwrap(),
        );
        Self {
            registry,
            state,
            task,
        }
    }
    #[allow(
        dead_code,
        reason = "The reviewed-change target uses this outage control; other targets share the authority."
    )]
    pub fn set_results_unavailable(&self, unavailable: bool) {
        self.state
            .results_unavailable
            .store(unavailable, Ordering::SeqCst);
    }
    pub fn counts(&self) -> (usize, usize, usize) {
        (
            self.state.creates.load(Ordering::SeqCst),
            self.state.reads.load(Ordering::SeqCst),
            self.state.results.load(Ordering::SeqCst),
        )
    }

    pub fn replace_submission_digest_for_test(
        &self,
        digest: registry_review_client::SubmissionDigest,
    ) {
        self.state
            .accepted
            .lock()
            .unwrap()
            .as_mut()
            .expect("the authority retained an accepted request")
            .submission_digest = digest.clone();
        self.state
            .result
            .lock()
            .unwrap()
            .as_mut()
            .expect("the authority retained an approved result")
            .submission_digest = digest;
    }
}
fn authenticated(headers: &HeaderMap) -> bool {
    headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        == Some("Bearer synthetic-loopback-review-token")
        && headers
            .get(registry_review_protocol::REVIEW_PROFILE_HEADER)
            .and_then(|value| value.to_str().ok())
            == Some("producer")
}
fn response(status: StatusCode, value: Value) -> Response {
    let mut response = (status, Json(value)).into_response();
    response.headers_mut().insert(
        "traceparent",
        axum::http::HeaderValue::from_static(
            "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01",
        ),
    );
    response
}
async fn create(
    State(state): State<Arc<StateData>>,
    headers: HeaderMap,
    Json(request): Json<ReviewCreateRequest>,
) -> Response {
    assert!(authenticated(&headers));
    assert!(headers.contains_key("idempotency-key"));
    request.check().unwrap();
    assert!(
        request.policy.matches(&state.policy),
        "select the configured policy"
    );
    state.creates.fetch_add(1, Ordering::SeqCst);
    let digest = registry_review_client::submission_digest(
        "proposal-producer",
        &state.registry_id,
        &request,
    )
    .unwrap();
    let accepted = ReviewRequestAccepted {
        request_id: Uuid::new_v4(),
        subject: request.subject,
        policy: state.policy.clone(),
        submission_digest: digest,
    };
    let now = chrono::Utc::now();
    let result = ReviewResult {
        result_id: Uuid::new_v4(),
        request_id: accepted.request_id,
        subject: accepted.subject.clone(),
        policy: accepted.policy.clone(),
        submission_digest: accepted.submission_digest.clone(),
        status: ReviewResultStatus::Approved,
        outcome: Some("approved".to_owned()),
        public_reason: None,
        result: None,
        completed_at: now - chrono::Duration::seconds(1),
        available_until: now + chrono::Duration::minutes(30),
    };
    *state.accepted.lock().unwrap() = Some(accepted.clone());
    *state.result.lock().unwrap() = Some(result);
    response(StatusCode::CREATED, json!(accepted))
}
async fn request(
    State(state): State<Arc<StateData>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Response {
    assert!(authenticated(&headers));
    state.reads.fetch_add(1, Ordering::SeqCst);
    let accepted = state.accepted.lock().unwrap().clone().unwrap();
    assert_eq!(id, accepted.request_id);
    let completed = state.result.lock().unwrap().as_ref().unwrap().completed_at;
    response(
        StatusCode::OK,
        json!(ReviewRequestView {
            request_id: id,
            subject: accepted.subject,
            policy: accepted.policy,
            submission_digest: accepted.submission_digest,
            requester_reference: "synthetic-producer-reference".into(),
            lifecycle: ReviewRequestLifecycle::Approved,
            active_stage: None,
            created_at: completed,
            updated_at: completed
        }),
    )
}
async fn result(
    State(state): State<Arc<StateData>>,
    Path(id): Path<Uuid>,
    headers: HeaderMap,
) -> Response {
    assert!(authenticated(&headers));
    state.results.fetch_add(1, Ordering::SeqCst);
    if state.results_unavailable.load(Ordering::SeqCst) {
        return response(StatusCode::SERVICE_UNAVAILABLE, json!({}));
    }
    let result = state.result.lock().unwrap().clone().unwrap();
    assert_eq!(id, result.request_id);
    response(StatusCode::OK, json!(result))
}
async fn feed(headers: HeaderMap) -> Response {
    assert!(authenticated(&headers));
    response(StatusCode::OK, json!({"items":[]}))
}
