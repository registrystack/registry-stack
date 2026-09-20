#![cfg(feature = "postgres-test")]

use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    sync::{Arc, Mutex},
};

use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    routing::post,
    Json, Router,
};
use registry_casework::{
    router, CaseworkAuthenticator, CaseworkService, DatabaseConfig, HttpState, HumanIdentityConfig,
    PostgresStore, ReviewResultRead, ReviewTaskDecisionRequest,
};
use registry_casework_core::{
    AccessProfile, ActorContext, CaseworkIdentity, CaseworkProject, CaseworkRole, ContentDigest,
    InboxPolicy, IssuerPrincipal, QueuePolicy, ReviewCompletion, ReviewCompletionDestinationPolicy,
    ReviewCompletionType, ReviewContext, ReviewContextStrategy, ReviewCreateRequest,
    ReviewKindPolicy, ReviewKindPurpose, ReviewProducerPolicy, ReviewRequestAccepted, ReviewResult,
    ReviewResultFeedPage, ReviewResultStatus, ReviewRetentionPolicy, ReviewStagePolicy,
    ReviewTaskPage, ReviewerDecisionKind, SubjectBinding, CASEWORK_PROFILE_HEADER,
};
use registry_platform_config::{SecretProvider, SecretResolver};
use registry_platform_httputil::FetchUrlPolicy;
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig};
use registry_platform_testing::{oidc_verifier_config, MockIdp};
use serde_json::json;
use tokio::{net::TcpListener, sync::oneshot, task::JoinHandle};
use tokio_postgres::NoTls;
use uuid::Uuid;

const ISSUER: &str = "https://payments.example.test";
const BATCH_ID: &str = "batch-2026-09";
const AUDIENCE: &str = "urn:test:casework-payment-review";
const RECEIVER_TOKEN: &str = "payment-sender-secret-canary";
const RECEIVER_BINDING: &str = "payment-service-recipient-canary";
const PRIVATE_REFERENCE: &str = "private-payment-reference-canary";

#[derive(Clone, Debug, Eq, PartialEq)]
enum PaymentBatchState {
    Draft,
    Submitted,
    Released { receipt: String },
}

#[derive(Clone, Debug)]
struct PaymentBatch {
    id: String,
    version: String,
    digest: ContentDigest,
    amount_minor: u64,
    state: PaymentBatchState,
}

#[derive(Clone, Default)]
struct PaymentStore {
    batch: Arc<Mutex<Option<PaymentBatch>>>,
    completion_events: Arc<Mutex<BTreeSet<Uuid>>>,
}

#[derive(Clone, Default)]
struct ReceiverStore {
    inbox: Arc<Mutex<BTreeMap<Uuid, ReviewCompletion>>>,
    known_requests: Arc<Mutex<BTreeSet<Uuid>>>,
    lost_ack_events: Arc<Mutex<BTreeSet<Uuid>>>,
}

impl ReceiverStore {
    fn register_request(&self, request_id: Uuid) {
        self.known_requests
            .lock()
            .expect("receiver request lock")
            .insert(request_id);
    }

    fn unmatched_count(&self) -> usize {
        let known = self.known_requests.lock().expect("receiver request lock");
        self.inbox
            .lock()
            .expect("receiver inbox lock")
            .values()
            .filter(|event| !known.contains(&event.request_id))
            .count()
    }

    fn record_feed(&self, page: &ReviewResultFeedPage) {
        let mut inbox = self.inbox.lock().expect("receiver inbox lock");
        for entry in &page.items {
            inbox.entry(entry.event_id).or_insert(ReviewCompletion {
                event_type: ReviewCompletionType::ReviewCompleted,
                event_id: entry.event_id,
                request_id: entry.request_id,
                result_id: entry.result_id,
                completed_at: entry.completed_at,
            });
        }
    }

    fn diagnostics(&self) -> String {
        let accepted = self.inbox.lock().expect("receiver inbox lock").len();
        let unmatched = self.unmatched_count();
        format!("accepted={accepted} unmatched={unmatched}")
    }
}

#[derive(Clone)]
struct ReceiverHttpState {
    store: ReceiverStore,
}

async fn receive_completion(
    State(state): State<ReceiverHttpState>,
    headers: HeaderMap,
    Json(event): Json<ReviewCompletion>,
) -> impl IntoResponse {
    let authenticated = headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == format!("Bearer {RECEIVER_TOKEN}"));
    if !authenticated {
        return StatusCode::UNAUTHORIZED;
    }
    let intended_recipient = headers
        .get("registry-recipient-binding")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == RECEIVER_BINDING);
    if !intended_recipient {
        return StatusCode::FORBIDDEN;
    }
    let idempotency_matches = headers
        .get("idempotency-key")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value == event.event_id.to_string());
    if !idempotency_matches {
        return StatusCode::BAD_REQUEST;
    }

    let inserted = {
        let mut inbox = state.store.inbox.lock().expect("receiver inbox lock");
        match inbox.get(&event.event_id) {
            Some(existing) if existing == &event => false,
            Some(_) => return StatusCode::CONFLICT,
            None => {
                inbox.insert(event.event_id, event.clone());
                true
            }
        }
    };
    if inserted
        && state
            .store
            .lost_ack_events
            .lock()
            .expect("receiver lost acknowledgement lock")
            .insert(event.event_id)
    {
        return StatusCode::SERVICE_UNAVAILABLE;
    }
    StatusCode::NO_CONTENT
}

struct LoopbackServer {
    base_url: String,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl LoopbackServer {
    async fn start(app: Router) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("loopback server listener");
        let address = listener.local_addr().expect("loopback server address");
        let (shutdown, stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = stopped.await;
                })
                .await
                .expect("loopback server");
        });
        Self {
            base_url: format!("http://{address}"),
            shutdown: Some(shutdown),
            task,
        }
    }

    async fn stop(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.task.abort();
        let _ = self.task.await;
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PaymentError {
    InvalidBatch,
    NotSubmitted,
    NotAuthorized,
    ReviewMismatch,
    NotApproved,
}

impl PaymentStore {
    fn create(&self, amount_minor: u64) -> Result<(), PaymentError> {
        if amount_minor == 0 {
            return Err(PaymentError::InvalidBatch);
        }
        let digest = ContentDigest::for_bytes(format!("{BATCH_ID}:1:{amount_minor}").as_bytes());
        *self.batch.lock().expect("payment batch lock") = Some(PaymentBatch {
            id: BATCH_ID.to_owned(),
            version: "1".to_owned(),
            digest,
            amount_minor,
            state: PaymentBatchState::Draft,
        });
        Ok(())
    }

    fn submit_for_review(&self) -> Result<ReviewCreateRequest, PaymentError> {
        let mut guard = self.batch.lock().expect("payment batch lock");
        let batch = guard.as_mut().ok_or(PaymentError::InvalidBatch)?;
        if batch.state != PaymentBatchState::Draft || batch.amount_minor == 0 {
            return Err(PaymentError::InvalidBatch);
        }
        batch.state = PaymentBatchState::Submitted;
        Ok(ReviewCreateRequest {
            kind: "payment-batch".to_owned(),
            subject: SubjectBinding {
                source: "payments".to_owned(),
                subject_type: "payment_batch".to_owned(),
                id: batch.id.clone(),
                version: batch.version.clone(),
                digest: batch.digest.clone(),
            },
            requester_reference: PRIVATE_REFERENCE.to_owned(),
            initiator: None,
            context: ReviewContext::Submitted {
                snapshot: json!({
                    "batchId": batch.id,
                    "amountMinor": batch.amount_minor,
                    "currency": "USD"
                }),
            },
            result_constraints: None,
        })
    }

    /// A completion is only a deduplicated wake-up signal. It carries no
    /// approval evidence and cannot release a payment by itself.
    fn accept_completion(&self, completion: &ReviewCompletion) -> bool {
        self.completion_events
            .lock()
            .expect("completion inbox lock")
            .insert(completion.event_id)
    }

    fn release(
        &self,
        executor_is_currently_authorized: bool,
        result: &ReviewResult,
    ) -> Result<String, PaymentError> {
        if !executor_is_currently_authorized {
            return Err(PaymentError::NotAuthorized);
        }
        if result.status != ReviewResultStatus::Approved {
            return Err(PaymentError::NotApproved);
        }
        let mut guard = self.batch.lock().expect("payment batch lock");
        let batch = guard.as_mut().ok_or(PaymentError::InvalidBatch)?;
        if let PaymentBatchState::Released { receipt } = &batch.state {
            return Ok(receipt.clone());
        }
        if batch.state != PaymentBatchState::Submitted {
            return Err(PaymentError::NotSubmitted);
        }
        if result.subject.source != "payments"
            || result.subject.subject_type != "payment_batch"
            || result.subject.id != batch.id
            || result.subject.version != batch.version
            || result.subject.digest != batch.digest
            || result.policy.id != "payment-batch"
        {
            return Err(PaymentError::ReviewMismatch);
        }
        let receipt = format!("payment-release:{}:{}", batch.id, batch.version);
        batch.state = PaymentBatchState::Released {
            receipt: receipt.clone(),
        };
        Ok(receipt)
    }
}

fn profile(id: &str, role: CaseworkRole) -> AccessProfile {
    AccessProfile {
        id: id.to_owned(),
        principal_claim: "sub".to_owned(),
        required_scopes: vec![format!("casework:{id}")],
        role,
    }
}

fn actor(subject: &str, role: CaseworkRole, profile_id: &str) -> ActorContext {
    ActorContext {
        principal: IssuerPrincipal {
            issuer: ISSUER.to_owned(),
            subject: subject.to_owned(),
        },
        profile_id: profile_id.to_owned(),
        role,
    }
}

fn project(issuer: &str) -> CaseworkProject {
    CaseworkProject {
        api_version: registry_casework_core::CASEWORK_API_VERSION.to_owned(),
        kind: registry_casework_core::CASEWORK_KIND.to_owned(),
        casework: CaseworkIdentity {
            id: "payment-review-fixture".to_owned(),
            version: "1".to_owned(),
        },
        access_profiles: vec![
            profile("reviewer", CaseworkRole::Staff),
            profile("supervisor", CaseworkRole::Supervisor),
            profile("administrator", CaseworkRole::Administrator),
            profile("payments", CaseworkRole::Requester),
        ],
        queues: vec![QueuePolicy {
            id: "payment-review".to_owned(),
            label: "Payment review".to_owned(),
        }],
        sources: Vec::new(),
        review_kinds: vec![ReviewKindPolicy {
            id: "payment-batch".to_owned(),
            version: "1".to_owned(),
            purpose: ReviewKindPurpose::Approval,
            context_strategy: ReviewContextStrategy::Submitted,
            stages: vec![ReviewStagePolicy {
                id: "verification".to_owned(),
                queue: "payment-review".to_owned(),
                deciding_profiles: vec!["reviewer".to_owned()],
                required_approvals: 1,
                exclude_initiator: false,
                exclude_previous_stage_reviewers: false,
            }],
            clocks: Vec::new(),
            retention: ReviewRetentionPolicy {
                terminal_days: 30,
                accountability_days: 90,
            },
            display_schema: json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["batchId", "amountMinor", "currency"],
                "properties": {
                    "batchId": {"type": "string", "maxLength": 80},
                    "amountMinor": {"type": "integer", "minimum": 1},
                    "currency": {"type": "string", "enum": ["USD"]}
                }
            }),
            result_schema: None,
            outcomes: Vec::new(),
        }],
        review_producers: vec![ReviewProducerPolicy {
            id: "payments".to_owned(),
            profile: "payments".to_owned(),
            issuer: issuer.to_owned(),
            subject: "payment-service".to_owned(),
            trusted_initiator_issuer: None,
            source_namespaces: vec!["payments".to_owned()],
            kinds: vec!["payment-batch".to_owned()],
            recovery_days: 7,
            completion: Some(ReviewCompletionDestinationPolicy {
                destination_id: "payment-results".to_owned(),
                recipient_binding: RECEIVER_BINDING.to_owned(),
            }),
        }],
        calendars: Vec::new(),
        clocks: Vec::new(),
        inbox: InboxPolicy::default(),
        task_templates: Vec::new(),
    }
}

async fn fixture_for_issuer(
    issuer: &str,
) -> (
    CaseworkService,
    PostgresStore,
    tokio_postgres::Client,
    CaseworkProject,
) {
    let base = env::var("CASEWORK_REVIEW_TEST_DATABASE_URL")
        .expect("CASEWORK_REVIEW_TEST_DATABASE_URL is required for the payment fixture");
    let schema = format!("review_payment_{}", Uuid::new_v4().simple());
    let separator = if base.contains('?') { '&' } else { '?' };
    let scoped_url = format!("{base}{separator}options=-csearch_path%3D{schema}");
    let (admin, admin_connection) = tokio_postgres::connect(&base, NoTls)
        .await
        .expect("connect dedicated payment fixture database");
    tokio::spawn(async move { admin_connection.await.expect("admin connection") });
    admin
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .expect("create isolated payment schema");

    let secret_name =
        format!("CASEWORK_PAYMENT_SCHEMA_{}", Uuid::new_v4().simple()).to_ascii_uppercase();
    env::set_var(&secret_name, &scoped_url);
    let secrets = SecretResolver::new([SecretProvider::Environment], "/private/tmp")
        .expect("payment fixture secret resolver");
    let database_config = DatabaseConfig {
        runtime_url_ref: format!("secret:env/{secret_name}"),
        migration_url_ref: format!("secret:env/{secret_name}"),
        trusted_root_certificate_ref: None,
        test_only_plaintext: true,
    };
    PostgresStore::connect_migration(&database_config, &secrets)
        .expect("payment migration store")
        .migrate()
        .await
        .expect("payment fixture migrations");
    let store =
        PostgresStore::connect_runtime(&database_config, &secrets).expect("payment runtime store");
    let (database, connection) = tokio_postgres::connect(&scoped_url, NoTls)
        .await
        .expect("payment schema connection");
    tokio::spawn(async move { connection.await.expect("payment schema connection task") });
    database
        .batch_execute(
            "INSERT INTO casework_teams(team_id,revision) VALUES('payment-team',1);
             INSERT INTO casework_queue_service(queue_id,team_id,revision)
             VALUES('payment-review','payment-team',1);",
        )
        .await
        .expect("seed payment reviewer");
    database
        .execute(
            "INSERT INTO casework_memberships(team_id,issuer,subject,membership_kind)
             VALUES('payment-team',$1,'reviewer','staff')",
            &[&issuer],
        )
        .await
        .expect("bind payment reviewer issuer");
    let project = project(issuer);
    project.check().expect("payment review project");
    let service = CaseworkService::new(
        store.clone(),
        project.clone(),
        Vec::<Arc<dyn registry_casework_core::SourceAdapter>>::new(),
    )
    .expect("payment review service");
    (service, store, database, project)
}

async fn fixture() -> (CaseworkService, tokio_postgres::Client) {
    let (service, _, database, _) = fixture_for_issuer(ISSUER).await;
    (service, database)
}

#[tokio::test]
async fn independent_payment_source_uses_casework_but_retains_release_authority() {
    let (service, database) = fixture().await;
    let payments = PaymentStore::default();
    payments.create(12_500).expect("valid payment batch");
    let request = payments.submit_for_review().expect("freeze payment batch");
    let producer = actor("payment-service", CaseworkRole::Requester, "payments");
    let reviewer = actor("reviewer", CaseworkRole::Staff, "reviewer");
    let accepted = service
        .create_review_request(&producer, request, "submit-payment-batch")
        .await
        .expect("submit payment review")
        .accepted;
    let task_id: Uuid = database
        .query_one(
            "SELECT task_id FROM casework_review_tasks WHERE request_id=$1",
            &[&accepted.request_id],
        )
        .await
        .expect("payment review task")
        .get(0);
    service
        .claim_review_task(&reviewer, task_id, None, "", 1, "claim-payment-review")
        .await
        .expect("claim payment review");
    service
        .decide_review_task(
            &reviewer,
            task_id,
            ReviewTaskDecisionRequest {
                decision: ReviewerDecisionKind::Approve,
            },
            None,
            "",
            2,
            "approve-payment-review",
        )
        .await
        .expect("approve payment review");

    let result = match service
        .review_result(&producer, accepted.request_id)
        .await
        .expect("read payment result")
    {
        ReviewResultRead::Available(result) => *result,
        other => panic!("expected available payment result, got {other:?}"),
    };
    let completion = ReviewCompletion {
        event_type: ReviewCompletionType::ReviewCompleted,
        event_id: result.result_id,
        request_id: result.request_id,
        result_id: result.result_id,
        completed_at: result.completed_at,
    };
    assert!(payments.accept_completion(&completion));
    assert!(!payments.accept_completion(&completion));

    assert_eq!(
        payments.release(false, &result),
        Err(PaymentError::NotAuthorized)
    );
    let mut substituted = result.clone();
    substituted.subject.digest = ContentDigest::for_bytes(b"another payment batch");
    assert_eq!(
        payments.release(true, &substituted),
        Err(PaymentError::ReviewMismatch)
    );
    let receipt = payments
        .release(true, &result)
        .expect("authorized exact payment release");
    assert_eq!(
        payments
            .release(true, &result)
            .expect("recover payment receipt"),
        receipt
    );
}

#[tokio::test]
async fn payment_http_push_and_feed_recovery_preserve_receiver_and_release_boundaries() {
    let idp = MockIdp::start().await;
    let (service, _, database, project) = fixture_for_issuer(&idp.issuer()).await;
    let authenticator = CaseworkAuthenticator::new(
        &project,
        oidc_verifier_config(idp.issuer(), vec![AUDIENCE.to_owned()]),
        Arc::new(JwksFetcher::new_with_fetch_url_policy(
            idp.jwks_uri(),
            JwksFetcherConfig::defaults(),
            FetchUrlPolicy::dev(),
        )),
        HumanIdentityConfig::default(),
    );
    let casework = LoopbackServer::start(router(HttpState {
        service,
        authenticator: Arc::new(authenticator),
        project: Arc::new(project),
    }))
    .await;
    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("payment HTTP client");
    let producer_token = idp.mint_token(json!({
        "aud": AUDIENCE,
        "sub": "payment-service",
        "scope": "casework:payments",
        "registry_actor_kind": "service"
    }));
    let reviewer_token = idp.mint_token(json!({
        "aud": AUDIENCE,
        "sub": "reviewer",
        "scope": "casework:reviewer",
        "registry_actor_kind": "human"
    }));

    let payments = PaymentStore::default();
    payments.create(12_500).expect("valid payment batch");
    let request = payments.submit_for_review().expect("freeze payment batch");
    let created = client
        .post(format!("{}/v1/review-requests", casework.base_url))
        .bearer_auth(&producer_token)
        .header(CASEWORK_PROFILE_HEADER, "payments")
        .header("idempotency-key", "submit-payment-over-http")
        .json(&request)
        .send()
        .await
        .expect("submit payment review over HTTP");
    assert_eq!(created.status(), StatusCode::CREATED);
    let created: ReviewRequestAccepted = created
        .json()
        .await
        .expect("payment review accepted response");

    let mut withdrawn_request = request.clone();
    withdrawn_request.subject.id = "withdrawn-payment-batch".to_owned();
    withdrawn_request.subject.digest = ContentDigest::for_bytes(b"withdrawn-payment-batch");
    withdrawn_request.requester_reference = "withdrawn-payment-reference".to_owned();
    withdrawn_request.context = ReviewContext::Submitted {
        snapshot: json!({
            "batchId": "withdrawn-payment-batch",
            "amountMinor": 12500,
            "currency": "USD"
        }),
    };
    let withdrawn = client
        .post(format!("{}/v1/review-requests", casework.base_url))
        .bearer_auth(&producer_token)
        .header(CASEWORK_PROFILE_HEADER, "payments")
        .header("idempotency-key", "submit-withdrawn-payment")
        .json(&withdrawn_request)
        .send()
        .await
        .expect("submit payment that will be withdrawn");
    assert_eq!(withdrawn.status(), StatusCode::CREATED);
    let withdrawn: ReviewRequestAccepted = withdrawn
        .json()
        .await
        .expect("withdrawn payment accepted response");
    let cancelled = client
        .post(format!(
            "{}/v1/review-requests/{}/cancel",
            casework.base_url, withdrawn.request_id
        ))
        .bearer_auth(&producer_token)
        .header(CASEWORK_PROFILE_HEADER, "payments")
        .header("idempotency-key", "withdraw-payment-before-review")
        .json(&registry_casework_core::ReviewCancelRequest {
            subject: withdrawn_request.subject,
            reason: "Payment batch withdrawn before review".to_owned(),
        })
        .send()
        .await
        .expect("withdraw payment review");
    assert_eq!(cancelled.status(), StatusCode::OK);
    let cancelled_result = client
        .get(format!(
            "{}/v1/review-requests/{}/result",
            casework.base_url, withdrawn.request_id
        ))
        .bearer_auth(&producer_token)
        .header(CASEWORK_PROFILE_HEADER, "payments")
        .send()
        .await
        .expect("read withdrawn payment result");
    assert_eq!(cancelled_result.status(), StatusCode::OK);
    let cancelled_result: ReviewResult = cancelled_result
        .json()
        .await
        .expect("withdrawn payment result");
    assert_eq!(cancelled_result.status, ReviewResultStatus::Cancelled);
    assert_eq!(
        payments.release(true, &cancelled_result),
        Err(PaymentError::NotApproved)
    );

    let tasks = client
        .get(format!("{}/v1/review-tasks", casework.base_url))
        .bearer_auth(&reviewer_token)
        .header(CASEWORK_PROFILE_HEADER, "reviewer")
        .send()
        .await
        .expect("list payment review tasks");
    assert_eq!(tasks.status(), StatusCode::OK);
    let tasks: ReviewTaskPage = tasks.json().await.expect("payment review task page");
    assert_eq!(tasks.items.len(), 1);
    let task_id = tasks.items[0].task_id;
    let claimed = client
        .post(format!(
            "{}/v1/review-tasks/{task_id}/claim",
            casework.base_url
        ))
        .bearer_auth(&reviewer_token)
        .header(CASEWORK_PROFILE_HEADER, "reviewer")
        .header("if-match", "\"1\"")
        .header("idempotency-key", "claim-payment-over-http")
        .send()
        .await
        .expect("claim payment review over HTTP");
    assert_eq!(claimed.status(), StatusCode::OK);
    let decided = client
        .post(format!(
            "{}/v1/review-tasks/{task_id}/decisions",
            casework.base_url
        ))
        .bearer_auth(&reviewer_token)
        .header(CASEWORK_PROFILE_HEADER, "reviewer")
        .header("if-match", "\"2\"")
        .header("idempotency-key", "approve-payment-over-http")
        .json(&ReviewTaskDecisionRequest {
            decision: ReviewerDecisionKind::Approve,
        })
        .send()
        .await
        .expect("approve payment review over HTTP");
    assert_eq!(decided.status(), StatusCode::NO_CONTENT);
    let result = client
        .get(format!(
            "{}/v1/review-requests/{}/result",
            casework.base_url, created.request_id
        ))
        .bearer_auth(&producer_token)
        .header(CASEWORK_PROFILE_HEADER, "payments")
        .send()
        .await
        .expect("poll approved payment result");
    assert_eq!(result.status(), StatusCode::OK);
    let result: ReviewResult = result.json().await.expect("approved payment result");
    assert_eq!(result.status, ReviewResultStatus::Approved);
    let completion_event_id: Uuid = database
        .query_one(
            "SELECT event_id FROM casework_review_terminal_events WHERE request_id=$1",
            &[&result.request_id],
        )
        .await
        .expect("approved payment completion event")
        .get(0);

    let completion = ReviewCompletion {
        event_type: ReviewCompletionType::ReviewCompleted,
        event_id: completion_event_id,
        request_id: result.request_id,
        result_id: result.result_id,
        completed_at: result.completed_at,
    };
    let completion_body = serde_json::to_string(&completion).expect("completion JSON");
    for canary in [
        RECEIVER_TOKEN,
        RECEIVER_BINDING,
        PRIVATE_REFERENCE,
        BATCH_ID,
    ] {
        assert!(!completion_body.contains(canary));
    }

    let receiver_store = ReceiverStore::default();
    let receiver = LoopbackServer::start(
        Router::new()
            .route("/completion", post(receive_completion))
            .with_state(ReceiverHttpState {
                store: receiver_store.clone(),
            }),
    )
    .await;
    let wrong_sender = client
        .post(format!("{}/completion", receiver.base_url))
        .bearer_auth("wrong-sender-secret-canary")
        .header("registry-recipient-binding", RECEIVER_BINDING)
        .header("idempotency-key", completion.event_id.to_string())
        .json(&completion)
        .send()
        .await
        .expect("wrong sender completion response");
    assert_eq!(wrong_sender.status(), StatusCode::UNAUTHORIZED);
    assert!(wrong_sender
        .bytes()
        .await
        .expect("wrong sender body")
        .is_empty());
    let wrong_recipient = client
        .post(format!("{}/completion", receiver.base_url))
        .bearer_auth(RECEIVER_TOKEN)
        .header(
            "registry-recipient-binding",
            "different-payment-recipient-canary",
        )
        .header("idempotency-key", completion.event_id.to_string())
        .json(&completion)
        .send()
        .await
        .expect("wrong recipient completion response");
    assert_eq!(wrong_recipient.status(), StatusCode::FORBIDDEN);
    assert!(wrong_recipient
        .bytes()
        .await
        .expect("wrong recipient body")
        .is_empty());
    assert_eq!(
        receiver_store.inbox.lock().expect("receiver inbox").len(),
        0
    );

    let lost_ack = client
        .post(format!("{}/completion", receiver.base_url))
        .bearer_auth(RECEIVER_TOKEN)
        .header("registry-recipient-binding", RECEIVER_BINDING)
        .header("idempotency-key", completion.event_id.to_string())
        .json(&completion)
        .send()
        .await
        .expect("lost acknowledgement completion response");
    assert_eq!(lost_ack.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(receiver_store.unmatched_count(), 1);
    receiver.stop().await;

    let restarted_receiver = LoopbackServer::start(
        Router::new()
            .route("/completion", post(receive_completion))
            .with_state(ReceiverHttpState {
                store: receiver_store.clone(),
            }),
    )
    .await;
    let duplicate = client
        .post(format!("{}/completion", restarted_receiver.base_url))
        .bearer_auth(RECEIVER_TOKEN)
        .header("registry-recipient-binding", RECEIVER_BINDING)
        .header("idempotency-key", completion.event_id.to_string())
        .json(&completion)
        .send()
        .await
        .expect("duplicate completion after receiver restart");
    assert_eq!(duplicate.status(), StatusCode::NO_CONTENT);
    assert_eq!(
        receiver_store.inbox.lock().expect("receiver inbox").len(),
        1
    );

    receiver_store.register_request(created.request_id);
    assert_eq!(receiver_store.unmatched_count(), 0);
    assert!(payments.accept_completion(&completion));
    assert!(!payments.accept_completion(&completion));
    let receipt = payments
        .release(true, &result)
        .expect("release exact approved payment after unmatched reconciliation");
    assert_eq!(
        payments
            .release(true, &result)
            .expect("recover payment release after duplicate completion"),
        receipt
    );

    let events = database
        .query(
            "SELECT event_id,request_id FROM casework_review_terminal_events
             WHERE request_id=ANY($1) ORDER BY feed_position",
            &[&vec![created.request_id, withdrawn.request_id]],
        )
        .await
        .expect("read commit-stable payment feed order");
    assert_eq!(events.len(), 2);
    let first_event_id: Uuid = events[0].get(0);
    let first_request_id: Uuid = events[0].get(1);
    let second_request_id: Uuid = events[1].get(1);
    let first_feed = client
        .get(format!("{}/v1/review-results?limit=1", casework.base_url))
        .bearer_auth(&producer_token)
        .header(CASEWORK_PROFILE_HEADER, "payments")
        .send()
        .await
        .expect("read first payment result feed page");
    assert_eq!(first_feed.status(), StatusCode::OK);
    let first_feed_bytes = first_feed.bytes().await.expect("first feed bytes");
    let first_feed: ReviewResultFeedPage =
        serde_json::from_slice(&first_feed_bytes).expect("first payment feed page");
    assert_eq!(first_feed.items.len(), 1);
    assert_eq!(first_feed.items[0].event_id, first_event_id);
    receiver_store.record_feed(&first_feed);
    receiver_store.register_request(first_request_id);
    assert_eq!(
        receiver_store.inbox.lock().expect("receiver inbox").len(),
        if first_event_id == completion.event_id {
            1
        } else {
            2
        }
    );
    let cursor = first_feed.next_cursor.expect("payment feed cursor");

    database
        .execute(
            "UPDATE casework_review_terminal_events
             SET completed_at=now()-interval '2 seconds',
                 retained_until=now()-interval '1 second'
             WHERE event_id=$1",
            &[&first_event_id],
        )
        .await
        .expect("expire payment feed cursor event");
    let expired_cursor = client
        .get(format!(
            "{}/v1/review-results?limit=1&cursor={cursor}",
            casework.base_url
        ))
        .bearer_auth(&producer_token)
        .header(CASEWORK_PROFILE_HEADER, "payments")
        .send()
        .await
        .expect("read expired payment feed cursor");
    assert_eq!(expired_cursor.status(), StatusCode::GONE);
    let expired_cursor_body = expired_cursor
        .bytes()
        .await
        .expect("expired payment cursor body");
    let restarted_feed = client
        .get(format!("{}/v1/review-results?limit=1", casework.base_url))
        .bearer_auth(&producer_token)
        .header(CASEWORK_PROFILE_HEADER, "payments")
        .send()
        .await
        .expect("restart payment result feed");
    assert_eq!(restarted_feed.status(), StatusCode::OK);
    let restarted_feed_bytes = restarted_feed.bytes().await.expect("restarted feed bytes");
    let restarted_feed: ReviewResultFeedPage =
        serde_json::from_slice(&restarted_feed_bytes).expect("restarted payment feed page");
    assert_eq!(restarted_feed.items.len(), 1);
    assert_eq!(restarted_feed.items[0].request_id, second_request_id);
    receiver_store.record_feed(&restarted_feed);
    receiver_store.register_request(second_request_id);
    assert_eq!(
        receiver_store.inbox.lock().expect("receiver inbox").len(),
        2
    );
    assert_eq!(receiver_store.unmatched_count(), 0);

    let diagnostics = receiver_store.diagnostics();
    for canary in [
        RECEIVER_TOKEN,
        RECEIVER_BINDING,
        PRIVATE_REFERENCE,
        BATCH_ID,
        "wrong-sender-secret-canary",
        "different-payment-recipient-canary",
    ] {
        assert!(!String::from_utf8_lossy(&first_feed_bytes).contains(canary));
        assert!(!String::from_utf8_lossy(&expired_cursor_body).contains(canary));
        assert!(!String::from_utf8_lossy(&restarted_feed_bytes).contains(canary));
        assert!(!diagnostics.contains(canary));
    }

    drop(client);
    restarted_receiver.stop().await;
    casework.stop().await;
    drop(idp);
}
