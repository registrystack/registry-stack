#![cfg(feature = "postgres-test")]

use std::{
    collections::BTreeMap,
    env,
    sync::{
        atomic::{AtomicBool, AtomicU8, Ordering},
        Arc, Mutex,
    },
};

use async_trait::async_trait;
use axum::{
    body::{to_bytes, Body},
    http::{header::CONTENT_TYPE, Request, StatusCode},
};
use registry_casework::{
    router, CaseworkAuthenticator, CaseworkService, DatabaseConfig, HttpState, HumanIdentityConfig,
    PostgresStore, ReviewTaskDecisionRequest,
};
use registry_casework_client::{
    BearerToken, CaseworkAuth, CaseworkClient, CaseworkClientConfig, CaseworkClientError,
    ReviewTaskOwnership, ReviewTaskQuery, SupervisoryReviewTaskQuery,
};
use registry_casework_core::{
    AccessProfile, ActiveSubjectsPage, ActorContext, AuthoritativeObservation, CallerSubjectView,
    CaseworkIdentity, CaseworkProject, CaseworkRole, ContentDigest, DiscoveryCursor,
    EphemeralCredential, EventRequest, ExecutePreparedRequest, HumanIdentity, InboxPolicy,
    OccurrenceKind, OccurrenceState, PrepareActionRequest, PreparedSourceAttempt, QueuePolicy,
    ReviewContext, ReviewContextStrategy, ReviewCreateRequest, ReviewKindPolicy, ReviewKindPurpose,
    ReviewOutcomePolicy, ReviewOutcomeSettlement, ReviewProducerPolicy, ReviewRequestAccepted,
    ReviewResult, ReviewResultStatus, ReviewRetentionPolicy, ReviewStagePolicy, ReviewTaskPage,
    ReviewerDecisionKind, SourceAdapter, SourceAdapterError, SourceBinding, SourceContextBinding,
    SourceReceipt, SubjectBinding, SubjectRef, TransitionHint, CASEWORK_PROFILE_HEADER,
    SOURCE_PROFILE_HEADER, VALIDATION_PATH_HEADER, VALIDATION_REASON_HEADER,
};
use registry_platform_config::{SecretProvider, SecretResolver};
use registry_platform_httputil::FetchUrlPolicy;
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig};
use registry_platform_testing::{oidc_verifier_config, MockIdp};
use serde_json::{json, Value};
use tokio_postgres::NoTls;
use tower::ServiceExt;
use uuid::Uuid;

const AUDIENCE: &str = "urn:test:casework-review";

#[derive(Clone)]
struct ReviewSource {
    revoked: Arc<AtomicBool>,
    changed: Arc<AtomicBool>,
    failure: Arc<AtomicU8>,
    source_state: Arc<Mutex<OccurrenceState>>,
}

#[async_trait]
impl SourceAdapter for ReviewSource {
    fn source_id(&self) -> &str {
        "registry"
    }

    fn binding_generation(&self) -> &str {
        "review-http-source"
    }

    async fn verify_transition(
        &self,
        _request: EventRequest,
    ) -> Result<TransitionHint, SourceAdapterError> {
        Err(SourceAdapterError::Invalid)
    }

    async fn read_authoritative(
        &self,
        subject: &SubjectRef,
    ) -> Result<AuthoritativeObservation, SourceAdapterError> {
        Ok(AuthoritativeObservation {
            subject: subject.clone(),
            occurrence_key: format!("review:{}", subject.id),
            ordered_revision: 1,
            representation_etag: format!("\"{}\"", subject.id),
            binding: SourceBinding {
                source_revision: "source-revision-1".to_owned(),
                version: "1".to_owned(),
                integrity: Some(ContentDigest::for_bytes(subject.id.as_bytes()).to_string()),
                generation: self.binding_generation().to_owned(),
            },
            display_reference: None,
            occurrence_kind: OccurrenceKind::Review,
            stage: Some("review".to_owned()),
            submitted_at: None,
            stage_entered_at: None,
            review_timing: None,
            routing_context: None,
            state: *self.source_state.lock().expect("source state lock"),
            remaining_actions: Vec::new(),
        })
    }

    async fn discover_active(
        &self,
        _cursor: Option<&DiscoveryCursor>,
        _limit: usize,
    ) -> Result<ActiveSubjectsPage, SourceAdapterError> {
        Ok(ActiveSubjectsPage {
            subjects: Vec::new(),
            next_cursor: None,
        })
    }

    async fn read_for_caller(
        &self,
        subject: &SubjectRef,
        source_profile_id: &str,
        _credential: EphemeralCredential<'_>,
    ) -> Result<CallerSubjectView, SourceAdapterError> {
        match self.failure.load(Ordering::SeqCst) {
            1 => return Err(SourceAdapterError::Unavailable),
            2 => return Err(SourceAdapterError::Invalid),
            _ => {}
        }
        if self.revoked.load(Ordering::SeqCst)
            || subject.id.starts_with("concealed-")
            || source_profile_id != "reviewer-source"
        {
            return Err(SourceAdapterError::Concealed);
        }
        Ok(CallerSubjectView {
            subject: subject.clone(),
            binding: SourceBinding {
                source_revision: "source-revision-1".to_owned(),
                version: if self.changed.load(Ordering::SeqCst) {
                    "2".to_owned()
                } else {
                    "1".to_owned()
                },
                integrity: Some(ContentDigest::for_bytes(subject.id.as_bytes()).to_string()),
                generation: self.binding_generation().to_owned(),
            },
            display_reference: None,
            disclosed: BTreeMap::from([("summary".to_owned(), json!("Authorized source view"))]),
            permitted_operations: Vec::new(),
        })
    }

    async fn prepare_action(
        &self,
        _request: PrepareActionRequest<'_>,
    ) -> Result<PreparedSourceAttempt, SourceAdapterError> {
        Err(SourceAdapterError::Invalid)
    }

    async fn execute_prepared(
        &self,
        _request: ExecutePreparedRequest<'_>,
    ) -> Result<SourceReceipt, SourceAdapterError> {
        Err(SourceAdapterError::Invalid)
    }
}

fn profile(id: &str, role: CaseworkRole) -> AccessProfile {
    AccessProfile {
        id: id.to_owned(),
        principal_claim: "registry_principal".to_owned(),
        required_scopes: vec![format!("casework:{id}")],
        role,
    }
}

fn project(issuer: &str) -> CaseworkProject {
    CaseworkProject {
        api_version: registry_casework_core::CASEWORK_API_VERSION.to_owned(),
        kind: registry_casework_core::CASEWORK_KIND.to_owned(),
        casework: CaseworkIdentity {
            id: "review-http-test".to_owned(),
            version: "1".to_owned(),
        },
        access_profiles: vec![
            profile("staff", CaseworkRole::Staff),
            profile("supervisor", CaseworkRole::Supervisor),
            profile("administrator", CaseworkRole::Administrator),
            profile("producer", CaseworkRole::Requester),
            profile("producer-alternate", CaseworkRole::Requester),
            profile("initiator", CaseworkRole::Requester),
        ],
        queues: vec![QueuePolicy {
            id: "review".to_owned(),
            label: "Review".to_owned(),
        }],
        sources: Vec::new(),
        review_kinds: vec![
            ReviewKindPolicy {
                id: "registry-correction".to_owned(),
                version: "1".to_owned(),
                purpose: ReviewKindPurpose::Approval,
                context_strategy: ReviewContextStrategy::Source,
                stages: vec![ReviewStagePolicy {
                    id: "review".to_owned(),
                    queue: "review".to_owned(),
                    deciding_profiles: vec!["staff".to_owned()],
                    required_approvals: 1,
                    exclude_initiator: true,
                    exclude_previous_stage_reviewers: true,
                }],
                clocks: Vec::new(),
                retention: ReviewRetentionPolicy {
                    terminal_days: 90,
                    accountability_days: 365,
                },
                display_schema: json!({
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["summary"],
                    "properties": {"summary": {"type": "string", "maxLength": 160}}
                }),
                result_schema: None,
                outcomes: Vec::new(),
            },
            ReviewKindPolicy {
                id: "registry-answer".to_owned(),
                version: "1".to_owned(),
                purpose: ReviewKindPurpose::Answer,
                context_strategy: ReviewContextStrategy::Submitted,
                stages: vec![ReviewStagePolicy {
                    id: "answer".to_owned(),
                    queue: "review".to_owned(),
                    deciding_profiles: vec!["staff".to_owned()],
                    required_approvals: 1,
                    exclude_initiator: true,
                    exclude_previous_stage_reviewers: true,
                }],
                clocks: Vec::new(),
                retention: ReviewRetentionPolicy {
                    terminal_days: 90,
                    accountability_days: 365,
                },
                display_schema: json!({
                    "type": "object",
                    "additionalProperties": false,
                    "properties": {}
                }),
                result_schema: Some(json!({
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["answer"],
                    "properties": {"answer": {"type": "string", "maxLength": 160}}
                })),
                outcomes: vec![ReviewOutcomePolicy {
                    id: "found".to_owned(),
                    label: "Found".to_owned(),
                    settlement: ReviewOutcomeSettlement::Answered,
                    reason_required: false,
                    result_required: true,
                }],
            },
        ],
        review_producers: vec![
            ReviewProducerPolicy {
                id: "registry".to_owned(),
                profile: "producer".to_owned(),
                issuer: issuer.to_owned(),
                subject: "registry-service".to_owned(),
                trusted_initiator_issuer: Some(issuer.to_owned()),
                initiator_profile: Some("initiator".to_owned()),
                source_namespaces: vec!["registry".to_owned()],
                kinds: vec![
                    "registry-correction".to_owned(),
                    "registry-answer".to_owned(),
                ],
                recovery_days: 30,
                completion: None,
            },
            ReviewProducerPolicy {
                id: "registry-alternate".to_owned(),
                profile: "producer-alternate".to_owned(),
                issuer: issuer.to_owned(),
                subject: "registry-service".to_owned(),
                trusted_initiator_issuer: Some(issuer.to_owned()),
                initiator_profile: None,
                source_namespaces: vec!["registry".to_owned()],
                kinds: vec![
                    "registry-correction".to_owned(),
                    "registry-answer".to_owned(),
                ],
                recovery_days: 30,
                completion: None,
            },
        ],
        calendars: Vec::new(),
        clocks: Vec::new(),
        inbox: InboxPolicy::default(),
        task_templates: Vec::new(),
    }
}

fn review_request_for_subject(
    subject_id: &str,
    reference: &str,
    issuer: &str,
) -> ReviewCreateRequest {
    ReviewCreateRequest {
        kind: "registry-correction".to_owned(),
        subject: SubjectBinding {
            source: "registry".to_owned(),
            subject_type: "record".to_owned(),
            id: subject_id.to_owned(),
            version: "1".to_owned(),
            digest: ContentDigest::for_bytes(subject_id.as_bytes()),
        },
        requester_reference: reference.to_owned(),
        initiator: Some(HumanIdentity {
            issuer: issuer.to_owned(),
            subject: "initiator".to_owned(),
        }),
        context: ReviewContext::Source {
            binding: SourceContextBinding {
                reference: format!("registry:record:{subject_id}"),
            },
        },
        result_constraints: None,
    }
}

fn review_request(reference: &str, issuer: &str) -> ReviewCreateRequest {
    review_request_for_subject("record-1", reference, issuer)
}

async fn app_with_database(
    idp: &MockIdp,
) -> (
    axum::Router,
    CaseworkService,
    Arc<AtomicBool>,
    Arc<AtomicBool>,
    Arc<AtomicU8>,
    Arc<Mutex<OccurrenceState>>,
    tokio_postgres::Client,
) {
    let base = env::var("CASEWORK_REVIEW_TEST_DATABASE_URL")
        .expect("CASEWORK_REVIEW_TEST_DATABASE_URL is required for review HTTP tests");
    let schema = format!("review_http_{}", Uuid::new_v4().simple());
    let separator = if base.contains('?') { '&' } else { '?' };
    let scoped_url = format!("{base}{separator}options=-csearch_path%3D{schema}");
    let (admin, admin_connection) = tokio_postgres::connect(&base, NoTls)
        .await
        .expect("connect dedicated review HTTP test database");
    tokio::spawn(async move { admin_connection.await.expect("admin connection") });
    admin
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .expect("create isolated review HTTP schema");

    let secret_name =
        format!("CASEWORK_REVIEW_HTTP_{}", Uuid::new_v4().simple()).to_ascii_uppercase();
    env::set_var(&secret_name, &scoped_url);
    let secrets = SecretResolver::new([SecretProvider::Environment], "/private/tmp")
        .expect("test secret resolver");
    let database_config = DatabaseConfig {
        runtime_url_ref: format!("secret:env/{secret_name}"),
        migration_url_ref: format!("secret:env/{secret_name}"),
        trusted_root_certificate_ref: None,
        test_only_plaintext: true,
    };
    PostgresStore::connect_migration(&database_config, &secrets)
        .expect("migration store")
        .with_audit(registry_casework::CaseworkAudit::capture().0)
        .migrate()
        .await
        .expect("review HTTP migrations");
    let (database, connection) = tokio_postgres::connect(&scoped_url, NoTls)
        .await
        .expect("connect scoped review HTTP database");
    tokio::spawn(async move { connection.await.expect("review HTTP database connection") });
    database
        .batch_execute(
            "INSERT INTO casework_teams(team_id,revision) VALUES('review-team',1);
             INSERT INTO casework_queue_service(queue_id,team_id,revision)
             VALUES('review','review-team',1);
             INSERT INTO casework_memberships(team_id,issuer,subject,membership_kind)
             VALUES('review-team','https://placeholder.invalid','reviewer','staff'),
                   ('review-team','https://placeholder.invalid','colleague','staff'),
                   ('review-team','https://placeholder.invalid','supervisor','supervisor');",
        )
        .await
        .expect("seed review HTTP directory");
    database
        .execute(
            "UPDATE casework_memberships SET issuer=$1
             WHERE issuer='https://placeholder.invalid'",
            &[&idp.issuer()],
        )
        .await
        .expect("bind reviewer membership to test issuer");
    let store = PostgresStore::connect_runtime(&database_config, &secrets)
        .expect("runtime store")
        .with_audit(registry_casework::CaseworkAudit::capture().0);
    let project = project(&idp.issuer());
    project.check().expect("review HTTP project");
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
    let revoked = Arc::new(AtomicBool::new(false));
    let changed = Arc::new(AtomicBool::new(false));
    let failure = Arc::new(AtomicU8::new(0));
    let source_state = Arc::new(Mutex::new(OccurrenceState::Open));
    let service = CaseworkService::new(
        store,
        project.clone(),
        [Arc::new(ReviewSource {
            revoked: Arc::clone(&revoked),
            changed: Arc::clone(&changed),
            failure: Arc::clone(&failure),
            source_state: Arc::clone(&source_state),
        }) as Arc<dyn SourceAdapter>],
    )
    .expect("review HTTP service");
    (
        router(HttpState {
            service: service.clone(),
            authenticator: Arc::new(authenticator),
            project: Arc::new(project),
        }),
        service,
        revoked,
        changed,
        failure,
        source_state,
        database,
    )
}

async fn app(
    idp: &MockIdp,
) -> (
    axum::Router,
    CaseworkService,
    Arc<AtomicBool>,
    Arc<AtomicBool>,
    Arc<AtomicU8>,
    Arc<Mutex<OccurrenceState>>,
) {
    let (app, service, revoked, changed, failure, source_state, _) = app_with_database(idp).await;
    (app, service, revoked, changed, failure, source_state)
}

fn token(idp: &MockIdp) -> String {
    idp.mint_token(json!({
        "aud": AUDIENCE,
        "registry_principal": "registry-service",
        "scope": "casework:producer",
        "registry_actor_kind": "service"
    }))
}

fn alternate_producer_token(idp: &MockIdp) -> String {
    idp.mint_token(json!({
        "aud": AUDIENCE,
        "registry_principal": "registry-service",
        "scope": "casework:producer-alternate",
        "registry_actor_kind": "service"
    }))
}

fn reviewer_token(idp: &MockIdp) -> String {
    idp.mint_token(json!({
        "aud": AUDIENCE,
        "registry_principal": "reviewer",
        "scope": "casework:staff",
        "registry_actor_kind": "human"
    }))
}

fn colleague_token(idp: &MockIdp) -> String {
    idp.mint_token(json!({
        "aud": AUDIENCE,
        "registry_principal": "colleague",
        "scope": "casework:staff",
        "registry_actor_kind": "human"
    }))
}

fn human_token(idp: &MockIdp, principal: &str, profile: &str) -> BearerToken {
    BearerToken::new(idp.mint_token(json!({
        "aud": AUDIENCE,
        "registry_principal": principal,
        "scope": format!("casework:{profile}"),
        "registry_actor_kind": "human"
    })))
    .expect("synthetic human bearer")
}

async fn native_review_client(app: axum::Router) -> (CaseworkClient, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind owned Casework test listener");
    let address = listener.local_addr().expect("test listener address");
    let server = tokio::spawn(async move {
        axum::serve(listener, app)
            .await
            .expect("serve candidate Casework router");
    });
    let client = CaseworkClient::new(
        CaseworkClientConfig::new(
            format!("http://{address}/")
                .parse()
                .expect("test service URL"),
        )
        .with_max_mutation_retries(0),
    )
    .expect("candidate native client");
    (client, server)
}

async fn create_answer_task(
    app: &axum::Router,
    database: &tokio_postgres::Client,
    idp: &MockIdp,
    reference: &str,
) -> (ReviewRequestAccepted, Uuid) {
    let mut body = review_request_for_subject(reference, reference, &idp.issuer());
    body.kind = "registry-answer".to_owned();
    body.context = ReviewContext::Submitted {
        snapshot: json!({}),
    };
    create_task(app, database, idp, &body).await
}

async fn create_task(
    app: &axum::Router,
    database: &tokio_postgres::Client,
    idp: &MockIdp,
    body: &ReviewCreateRequest,
) -> (ReviewRequestAccepted, Uuid) {
    let mut request = create_http_request(body, Some(&token(idp)));
    request.headers_mut().insert(
        "idempotency-key",
        format!("create-{}", body.requester_reference)
            .parse()
            .expect("test key"),
    );
    let response = app.clone().oneshot(request).await.expect("create review");
    assert_eq!(response.status(), StatusCode::CREATED);
    let accepted: ReviewRequestAccepted = serde_json::from_slice(
        &to_bytes(response.into_body(), 32 * 1024)
            .await
            .expect("bounded create response"),
    )
    .expect("accepted review");
    let task_id = database
        .query_one(
            "SELECT task_id FROM casework_review_tasks WHERE request_id=$1",
            &[&accepted.request_id],
        )
        .await
        .expect("created task")
        .get(0);
    (accepted, task_id)
}

fn assert_client_status(error: CaseworkClientError, expected: u16) {
    assert!(
        matches!(error, CaseworkClientError::Problem { status, .. } if status == expected),
        "expected a typed HTTP {expected} refusal, got {error:?}"
    );
}

fn answer_decision() -> registry_casework_client::ReviewTaskDecisionRequest {
    registry_casework_client::ReviewTaskDecisionRequest {
        decision: ReviewerDecisionKind::Answer {
            outcome: "found".to_owned(),
            reason: Some("private-reason-canary".to_owned()),
            result: Some(json!({"answer": "producer-result-canary"})),
        },
    }
}

fn initiator_token(idp: &MockIdp, principal: &str) -> String {
    idp.mint_token(json!({
        "aud": AUDIENCE,
        "registry_principal": principal,
        "scope": "casework:initiator",
        "registry_actor_kind": "human"
    }))
}

fn create_http_request(body: &ReviewCreateRequest, token: Option<&str>) -> Request<Body> {
    let mut request = Request::builder()
        .method("POST")
        .uri("/v1/review-requests")
        .header(CONTENT_TYPE, "application/json")
        .header(CASEWORK_PROFILE_HEADER, "producer")
        .header("idempotency-key", "create-record-1");
    if let Some(token) = token {
        request = request.header("authorization", format!("Bearer {token}"));
    }
    request
        .body(Body::from(
            serde_json::to_vec(body).expect("serialize review request"),
        ))
        .expect("review HTTP request")
}

fn review_note_http_request(
    request_id: Uuid,
    token: &str,
    idempotency_key: &str,
    note: &str,
    source_profile: Option<&str>,
) -> Request<Body> {
    let mut request = Request::builder()
        .method("POST")
        .uri(format!("/v1/review-requests/{request_id}/notes"))
        .header("authorization", format!("Bearer {token}"))
        .header(CASEWORK_PROFILE_HEADER, "staff")
        .header(CONTENT_TYPE, "application/json")
        .header("idempotency-key", idempotency_key);
    if let Some(source_profile) = source_profile {
        request = request.header(SOURCE_PROFILE_HEADER, source_profile);
    }
    request
        .body(Body::from(
            serde_json::to_vec(&json!({
                "audience": "reviewers",
                "note": note,
            }))
            .expect("serialize review note"),
        ))
        .expect("review note HTTP request")
}

#[tokio::test]
async fn producer_http_create_recover_conflict_and_pending_result_are_closed() {
    let idp = MockIdp::start().await;
    let (app, _, source_revoked, source_changed, source_failure, source_state) = app(&idp).await;
    let request = review_request("producer-ref-1", &idp.issuer());

    let obsolete_hosted_route = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/hosted-items")
                .header(CONTENT_TYPE, "application/json")
                .body(Body::from("{}"))
                .expect("obsolete hosted route request"),
        )
        .await
        .expect("obsolete hosted route response");
    assert_eq!(obsolete_hosted_route.status(), StatusCode::NOT_FOUND);

    let unauthenticated = app
        .clone()
        .oneshot(create_http_request(&request, None))
        .await
        .expect("unauthenticated response");
    assert_eq!(unauthenticated.status(), StatusCode::UNAUTHORIZED);

    let token = token(&idp);
    let kinds = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/review-kinds")
                .header("authorization", format!("Bearer {token}"))
                .header(CASEWORK_PROFILE_HEADER, "producer")
                .body(Body::empty())
                .expect("review kind request"),
        )
        .await
        .expect("review kind response");
    assert_eq!(kinds.status(), StatusCode::OK);
    let kinds: Vec<registry_casework_core::ReviewKindPolicySnapshot> = serde_json::from_slice(
        &to_bytes(kinds.into_body(), 128 * 1024)
            .await
            .expect("bounded review kind response"),
    )
    .expect("review kind JSON");
    assert_eq!(kinds.len(), 2);
    assert!(kinds
        .iter()
        .any(|kind| kind.identity.id == "registry-correction"));

    let serialized = serde_json::to_string(&request).expect("serialize duplicate-key request");
    let duplicate_key_body = serialized.replacen('{', r#"{"kind":"registry-correction","#, 1);
    let duplicate_key = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/review-requests")
                .header(CONTENT_TYPE, "application/json")
                .header(CASEWORK_PROFILE_HEADER, "producer")
                .header("idempotency-key", "duplicate-kind-member")
                .header("authorization", format!("Bearer {token}"))
                .body(Body::from(duplicate_key_body))
                .expect("duplicate-key request"),
        )
        .await
        .expect("duplicate-key response");
    assert_eq!(duplicate_key.status(), StatusCode::UNPROCESSABLE_ENTITY);

    let lost_create_response = app
        .clone()
        .oneshot(create_http_request(&request, Some(&token)))
        .await
        .expect("created response");
    assert_eq!(lost_create_response.status(), StatusCode::CREATED);
    drop(lost_create_response);

    let reviewer_token = reviewer_token(&idp);
    let tasks_without_source_profile = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/review-tasks")
                .header("authorization", format!("Bearer {reviewer_token}"))
                .header(CASEWORK_PROFILE_HEADER, "staff")
                .body(Body::empty())
                .expect("task list without source profile"),
        )
        .await
        .expect("task list response without source profile");
    // Only source-backed candidates exist, so the absent header is named
    // rather than answered with a silent empty page.
    assert_eq!(
        tasks_without_source_profile.status(),
        StatusCode::BAD_REQUEST
    );
    let tasks_without_source_profile: Value = serde_json::from_slice(
        &to_bytes(tasks_without_source_profile.into_body(), 32 * 1024)
            .await
            .expect("bounded task list without source profile"),
    )
    .expect("task list without source profile JSON");
    assert_eq!(
        tasks_without_source_profile["code"],
        "source-profile.required"
    );

    let visible_tasks = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/review-tasks")
                .header("authorization", format!("Bearer {reviewer_token}"))
                .header(CASEWORK_PROFILE_HEADER, "staff")
                .header(SOURCE_PROFILE_HEADER, "reviewer-source")
                .body(Body::empty())
                .expect("source-authorized task list"),
        )
        .await
        .expect("source-authorized task list response");
    assert_eq!(visible_tasks.status(), StatusCode::OK);
    let visible_tasks: ReviewTaskPage = serde_json::from_slice(
        &to_bytes(visible_tasks.into_body(), 32 * 1024)
            .await
            .expect("bounded visible task list"),
    )
    .expect("visible task list JSON");
    assert_eq!(visible_tasks.items.len(), 1);
    let task_id = visible_tasks.items[0].task_id;

    source_failure.store(1, Ordering::SeqCst);
    let unavailable_tasks = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/review-tasks")
                .header("authorization", format!("Bearer {reviewer_token}"))
                .header(CASEWORK_PROFILE_HEADER, "staff")
                .header(SOURCE_PROFILE_HEADER, "reviewer-source")
                .body(Body::empty())
                .expect("source-unavailable task list"),
        )
        .await
        .expect("source-unavailable task list response");
    assert_eq!(unavailable_tasks.status(), StatusCode::SERVICE_UNAVAILABLE);
    source_failure.store(2, Ordering::SeqCst);
    let invalid_source_tasks = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/review-tasks")
                .header("authorization", format!("Bearer {reviewer_token}"))
                .header(CASEWORK_PROFILE_HEADER, "staff")
                .header(SOURCE_PROFILE_HEADER, "reviewer-source")
                .body(Body::empty())
                .expect("invalid-source task list"),
        )
        .await
        .expect("invalid-source task list response");
    assert_eq!(invalid_source_tasks.status(), StatusCode::BAD_GATEWAY);
    source_failure.store(0, Ordering::SeqCst);

    let missing_context_source_profile = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/review-tasks/{task_id}/context"))
                .header("authorization", format!("Bearer {reviewer_token}"))
                .header(CASEWORK_PROFILE_HEADER, "staff")
                .body(Body::empty())
                .expect("task context without source profile"),
        )
        .await
        .expect("task context response without source profile");
    assert_eq!(
        missing_context_source_profile.status(),
        StatusCode::BAD_REQUEST
    );
    let current_context = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/review-tasks/{task_id}/context"))
                .header("authorization", format!("Bearer {reviewer_token}"))
                .header(CASEWORK_PROFILE_HEADER, "staff")
                .header(SOURCE_PROFILE_HEADER, "reviewer-source")
                .body(Body::empty())
                .expect("source-authorized task context"),
        )
        .await
        .expect("source-authorized task context response");
    assert_eq!(current_context.status(), StatusCode::OK);
    let current_context: serde_json::Value = serde_json::from_slice(
        &to_bytes(current_context.into_body(), 64 * 1024)
            .await
            .expect("bounded current task context"),
    )
    .expect("current task context JSON");
    assert_eq!(current_context["context"]["bindingStatus"], "current");
    assert_eq!(
        current_context["context"]["projection"]["display"]["summary"],
        "Authorized source view"
    );
    assert!(current_context.get("initiator").is_none());

    source_changed.store(true, Ordering::SeqCst);
    let changed_context = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/review-tasks/{task_id}/context"))
                .header("authorization", format!("Bearer {reviewer_token}"))
                .header(CASEWORK_PROFILE_HEADER, "staff")
                .header(SOURCE_PROFILE_HEADER, "reviewer-source")
                .body(Body::empty())
                .expect("changed-binding task context"),
        )
        .await
        .expect("changed-binding task context response");
    assert_eq!(changed_context.status(), StatusCode::OK);
    let changed_context: serde_json::Value = serde_json::from_slice(
        &to_bytes(changed_context.into_body(), 64 * 1024)
            .await
            .expect("bounded changed-binding task context"),
    )
    .expect("changed-binding task context JSON");
    assert_eq!(
        changed_context["context"]["bindingStatus"],
        "binding_changed"
    );
    assert!(changed_context["context"].get("projection").is_none());
    source_changed.store(false, Ordering::SeqCst);

    *source_state.lock().expect("source state lock") = OccurrenceState::Cancelled;
    let terminal_task_read = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/review-tasks/{task_id}"))
                .header("authorization", format!("Bearer {reviewer_token}"))
                .header(CASEWORK_PROFILE_HEADER, "staff")
                .header(SOURCE_PROFILE_HEADER, "reviewer-source")
                .body(Body::empty())
                .expect("terminal-source task read"),
        )
        .await
        .expect("terminal-source task read response");
    assert_eq!(terminal_task_read.status(), StatusCode::NOT_FOUND);
    let terminal_claim = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/review-tasks/{task_id}/claim"))
                .header("authorization", format!("Bearer {reviewer_token}"))
                .header(CASEWORK_PROFILE_HEADER, "staff")
                .header(SOURCE_PROFILE_HEADER, "reviewer-source")
                .header("if-match", "\"1\"")
                .header("idempotency-key", "claim-terminal-source")
                .body(Body::empty())
                .expect("terminal-source claim"),
        )
        .await
        .expect("terminal-source claim response");
    assert_eq!(terminal_claim.status(), StatusCode::FORBIDDEN);
    // A completed occurrence stays reviewable: Casework's bounded retention
    // intentionally accepts fresh reviews for settled proposals, and the
    // source's pinned correlation, not this gate, refuses their results.
    *source_state.lock().expect("source state lock") = OccurrenceState::Completed;
    let completed_task_read = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/review-tasks/{task_id}"))
                .header("authorization", format!("Bearer {reviewer_token}"))
                .header(CASEWORK_PROFILE_HEADER, "staff")
                .header(SOURCE_PROFILE_HEADER, "reviewer-source")
                .body(Body::empty())
                .expect("completed-source task read"),
        )
        .await
        .expect("completed-source task read response");
    assert_eq!(completed_task_read.status(), StatusCode::OK);
    *source_state.lock().expect("source state lock") = OccurrenceState::Open;
    let active_context = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/review-tasks/{task_id}/context"))
                .header("authorization", format!("Bearer {reviewer_token}"))
                .header(CASEWORK_PROFILE_HEADER, "staff")
                .header(SOURCE_PROFILE_HEADER, "reviewer-source")
                .body(Body::empty())
                .expect("active-source task context"),
        )
        .await
        .expect("active-source task context response");
    assert_eq!(active_context.status(), StatusCode::OK);

    source_revoked.store(true, Ordering::SeqCst);
    let concealed_context = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/review-tasks/{task_id}/context"))
                .header("authorization", format!("Bearer {reviewer_token}"))
                .header(CASEWORK_PROFILE_HEADER, "staff")
                .header(SOURCE_PROFILE_HEADER, "reviewer-source")
                .body(Body::empty())
                .expect("concealed task context"),
        )
        .await
        .expect("concealed task context response");
    assert_eq!(concealed_context.status(), StatusCode::NOT_FOUND);
    let revoked_tasks = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/review-tasks")
                .header("authorization", format!("Bearer {reviewer_token}"))
                .header(CASEWORK_PROFILE_HEADER, "staff")
                .header(SOURCE_PROFILE_HEADER, "reviewer-source")
                .body(Body::empty())
                .expect("revoked task list"),
        )
        .await
        .expect("revoked task list response");
    assert_eq!(revoked_tasks.status(), StatusCode::OK);
    let revoked_tasks: ReviewTaskPage = serde_json::from_slice(
        &to_bytes(revoked_tasks.into_body(), 32 * 1024)
            .await
            .expect("bounded revoked task list"),
    )
    .expect("revoked task list JSON");
    assert!(revoked_tasks.items.is_empty());
    let revoked_task_read = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/review-tasks/{task_id}"))
                .header("authorization", format!("Bearer {reviewer_token}"))
                .header(CASEWORK_PROFILE_HEADER, "staff")
                .header(SOURCE_PROFILE_HEADER, "reviewer-source")
                .body(Body::empty())
                .expect("revoked task read"),
        )
        .await
        .expect("revoked task read response");
    assert_eq!(revoked_task_read.status(), StatusCode::NOT_FOUND);

    let recovered = app
        .clone()
        .oneshot(create_http_request(&request, Some(&token)))
        .await
        .expect("recovered response");
    assert_eq!(recovered.status(), StatusCode::OK);
    let created: ReviewRequestAccepted = serde_json::from_slice(
        &to_bytes(recovered.into_body(), 32 * 1024)
            .await
            .expect("bounded recovered create response"),
    )
    .expect("recovered create response JSON");

    let changed = app
        .clone()
        .oneshot(create_http_request(
            &review_request("changed-body", &idp.issuer()),
            Some(&token),
        ))
        .await
        .expect("conflict response");
    assert_eq!(changed.status(), StatusCode::CONFLICT);
    let changed: serde_json::Value = serde_json::from_slice(
        &to_bytes(changed.into_body(), 16 * 1024)
            .await
            .expect("bounded conflict response"),
    )
    .expect("conflict problem JSON");
    assert_eq!(changed["code"], "idempotency.key-reused");

    let pending = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/review-requests/{}/result", created.request_id))
                .header("authorization", format!("Bearer {token}"))
                .header(CASEWORK_PROFILE_HEADER, "producer")
                .body(Body::empty())
                .expect("pending result request"),
        )
        .await
        .expect("pending result response");
    assert_eq!(pending.status(), StatusCode::ACCEPTED);

    let source_scoped = app
        .oneshot(
            Request::builder()
                .uri(format!("/v1/review-requests/{}", created.request_id))
                .header("authorization", format!("Bearer {token}"))
                .header(CASEWORK_PROFILE_HEADER, "producer")
                .header(SOURCE_PROFILE_HEADER, "source-reader")
                .body(Body::empty())
                .expect("source-scoped request"),
        )
        .await
        .expect("source-scoped response");
    assert_eq!(source_scoped.status(), StatusCode::BAD_REQUEST);

    idp.stop().await;
}

#[tokio::test]
async fn requester_history_and_notes_require_the_admitted_producer_id_over_http() {
    let idp = MockIdp::start().await;
    let (app, _, _, _, _, _) = app(&idp).await;
    let producer_token = token(&idp);
    let created = app
        .clone()
        .oneshot(create_http_request(
            &review_request("producer-isolation", &idp.issuer()),
            Some(&producer_token),
        ))
        .await
        .expect("create producer-isolation review");
    assert_eq!(created.status(), StatusCode::CREATED);
    let created: ReviewRequestAccepted = serde_json::from_slice(
        &to_bytes(created.into_body(), 32 * 1024)
            .await
            .expect("bounded producer-isolation create response"),
    )
    .expect("producer-isolation create JSON");

    let alternate_token = alternate_producer_token(&idp);
    let cross_producer_history = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/review-requests/{}/history",
                    created.request_id
                ))
                .header("authorization", format!("Bearer {alternate_token}"))
                .header(CASEWORK_PROFILE_HEADER, "producer-alternate")
                .body(Body::empty())
                .expect("cross-producer history request"),
        )
        .await
        .expect("cross-producer history response");
    assert_eq!(cross_producer_history.status(), StatusCode::NOT_FOUND);

    let cross_producer_note = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/review-requests/{}/notes", created.request_id))
                .header("authorization", format!("Bearer {alternate_token}"))
                .header(CASEWORK_PROFILE_HEADER, "producer-alternate")
                .header(CONTENT_TYPE, "application/json")
                .header("idempotency-key", "cross-producer-note")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "audience": "requester",
                        "note": "cross-producer note must not be stored"
                    }))
                    .expect("serialize cross-producer note"),
                ))
                .expect("cross-producer note request"),
        )
        .await
        .expect("cross-producer note response");
    assert_eq!(cross_producer_note.status(), StatusCode::NOT_FOUND);

    let owner_history = app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/review-requests/{}/history",
                    created.request_id
                ))
                .header("authorization", format!("Bearer {producer_token}"))
                .header(CASEWORK_PROFILE_HEADER, "producer")
                .body(Body::empty())
                .expect("owning producer history request"),
        )
        .await
        .expect("owning producer history response");
    assert_eq!(owner_history.status(), StatusCode::OK);
    let owner_history = String::from_utf8(
        to_bytes(owner_history.into_body(), 64 * 1024)
            .await
            .expect("bounded owning producer history")
            .to_vec(),
    )
    .expect("owning producer history UTF-8");
    assert!(!owner_history.contains("cross-producer note must not be stored"));

    idp.stop().await;
}

#[tokio::test]
async fn source_context_review_history_notes_and_clocks_require_current_pinned_source_visibility_over_http(
) {
    let idp = MockIdp::start().await;
    let (app, _, source_revoked, _, _, _) = app(&idp).await;
    let producer_token = token(&idp);
    let created = app
        .clone()
        .oneshot(create_http_request(
            &review_request("source-history", &idp.issuer()),
            Some(&producer_token),
        ))
        .await
        .expect("create source-context review");
    assert_eq!(created.status(), StatusCode::CREATED);
    let created: ReviewRequestAccepted = serde_json::from_slice(
        &to_bytes(created.into_body(), 32 * 1024)
            .await
            .expect("bounded source-context create response"),
    )
    .expect("source-context create JSON");

    let requester_clocks = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/review-requests/{}/clocks", created.request_id))
                .header("authorization", format!("Bearer {producer_token}"))
                .header(CASEWORK_PROFILE_HEADER, "producer")
                .body(Body::empty())
                .expect("requester source-context clocks"),
        )
        .await
        .expect("requester source-context clocks response");
    assert_eq!(requester_clocks.status(), StatusCode::OK);
    let requester_clocks_with_source_profile = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/review-requests/{}/clocks", created.request_id))
                .header("authorization", format!("Bearer {producer_token}"))
                .header(CASEWORK_PROFILE_HEADER, "producer")
                .header(SOURCE_PROFILE_HEADER, "reviewer-source")
                .body(Body::empty())
                .expect("requester clocks with source profile"),
        )
        .await
        .expect("requester source-profile clocks response");
    assert_eq!(
        requester_clocks_with_source_profile.status(),
        StatusCode::BAD_REQUEST
    );

    let reviewer_token = reviewer_token(&idp);
    let missing_clock_source_profile = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/review-requests/{}/clocks", created.request_id))
                .header("authorization", format!("Bearer {reviewer_token}"))
                .header(CASEWORK_PROFILE_HEADER, "staff")
                .body(Body::empty())
                .expect("source clocks without source profile"),
        )
        .await
        .expect("source clocks response without source profile");
    assert_eq!(
        missing_clock_source_profile.status(),
        StatusCode::BAD_REQUEST
    );
    let authorized_clocks = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/review-requests/{}/clocks", created.request_id))
                .header("authorization", format!("Bearer {reviewer_token}"))
                .header(CASEWORK_PROFILE_HEADER, "staff")
                .header(SOURCE_PROFILE_HEADER, "reviewer-source")
                .body(Body::empty())
                .expect("authorized source clocks"),
        )
        .await
        .expect("authorized source clocks response");
    assert_eq!(authorized_clocks.status(), StatusCode::OK);
    let note_canary = "SOURCE_HISTORY_NOTE_CANARY";
    let missing_note_source_profile = app
        .clone()
        .oneshot(review_note_http_request(
            created.request_id,
            &reviewer_token,
            "source-history-note-missing-profile",
            "must not be stored",
            None,
        ))
        .await
        .expect("source note response without source profile");
    assert_eq!(
        missing_note_source_profile.status(),
        StatusCode::BAD_REQUEST
    );

    let note = app
        .clone()
        .oneshot(review_note_http_request(
            created.request_id,
            &reviewer_token,
            "source-history-note",
            note_canary,
            Some("reviewer-source"),
        ))
        .await
        .expect("source history note response");
    assert_eq!(note.status(), StatusCode::OK);

    let missing_source_profile = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/review-requests/{}/history",
                    created.request_id
                ))
                .header("authorization", format!("Bearer {reviewer_token}"))
                .header(CASEWORK_PROFILE_HEADER, "staff")
                .body(Body::empty())
                .expect("source history without source profile"),
        )
        .await
        .expect("source history response without source profile");
    assert_eq!(missing_source_profile.status(), StatusCode::BAD_REQUEST);

    let authorized = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/review-requests/{}/history",
                    created.request_id
                ))
                .header("authorization", format!("Bearer {reviewer_token}"))
                .header(CASEWORK_PROFILE_HEADER, "staff")
                .header(SOURCE_PROFILE_HEADER, "reviewer-source")
                .body(Body::empty())
                .expect("authorized source history"),
        )
        .await
        .expect("authorized source history response");
    assert_eq!(authorized.status(), StatusCode::OK);
    let authorized = String::from_utf8(
        to_bytes(authorized.into_body(), 64 * 1024)
            .await
            .expect("bounded authorized source history")
            .to_vec(),
    )
    .expect("authorized source history UTF-8");
    assert!(authorized.contains(note_canary));

    source_revoked.store(true, Ordering::SeqCst);
    let revoked_clocks = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/review-requests/{}/clocks", created.request_id))
                .header("authorization", format!("Bearer {reviewer_token}"))
                .header(CASEWORK_PROFILE_HEADER, "staff")
                .header(SOURCE_PROFILE_HEADER, "reviewer-source")
                .body(Body::empty())
                .expect("revoked source clocks"),
        )
        .await
        .expect("revoked source clocks response");
    assert_eq!(revoked_clocks.status(), StatusCode::FORBIDDEN);
    let revoked_note_canary = "REVOKED_SOURCE_NOTE_CANARY";
    let revoked_note = app
        .clone()
        .oneshot(review_note_http_request(
            created.request_id,
            &reviewer_token,
            "source-history-note-after-revocation",
            revoked_note_canary,
            Some("reviewer-source"),
        ))
        .await
        .expect("revoked source note response");
    assert_eq!(revoked_note.status(), StatusCode::FORBIDDEN);

    let revoked = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/review-requests/{}/history",
                    created.request_id
                ))
                .header("authorization", format!("Bearer {reviewer_token}"))
                .header(CASEWORK_PROFILE_HEADER, "staff")
                .header(SOURCE_PROFILE_HEADER, "reviewer-source")
                .body(Body::empty())
                .expect("revoked source history"),
        )
        .await
        .expect("revoked source history response");
    assert_eq!(revoked.status(), StatusCode::FORBIDDEN);
    let revoked = String::from_utf8(
        to_bytes(revoked.into_body(), 16 * 1024)
            .await
            .expect("bounded revoked source history problem")
            .to_vec(),
    )
    .expect("revoked source history problem UTF-8");
    assert!(!revoked.contains(note_canary));

    source_revoked.store(false, Ordering::SeqCst);
    let restored = app
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/review-requests/{}/history",
                    created.request_id
                ))
                .header("authorization", format!("Bearer {reviewer_token}"))
                .header(CASEWORK_PROFILE_HEADER, "staff")
                .header(SOURCE_PROFILE_HEADER, "reviewer-source")
                .body(Body::empty())
                .expect("restored source history"),
        )
        .await
        .expect("restored source history response");
    assert_eq!(restored.status(), StatusCode::OK);
    let restored = String::from_utf8(
        to_bytes(restored.into_body(), 64 * 1024)
            .await
            .expect("bounded restored source history")
            .to_vec(),
    )
    .expect("restored source history UTF-8");
    assert!(restored.contains(note_canary));
    assert!(!restored.contains(revoked_note_canary));

    idp.stop().await;
}

#[tokio::test]
async fn review_task_inbox_continues_after_the_configured_source_read_budget() {
    let idp = MockIdp::start().await;
    let (app, service, _, _, _, _) = app(&idp).await;
    let producer = ActorContext {
        principal: registry_casework_core::IssuerPrincipal {
            issuer: idp.issuer(),
            subject: "registry-service".to_owned(),
        },
        profile_id: "producer".to_owned(),
        role: CaseworkRole::Requester,
    };
    for index in 0..25 {
        service
            .create_review_request(
                &producer,
                review_request_for_subject(
                    &format!("concealed-{index:04}"),
                    &format!("concealed-reference-{index:04}"),
                    &idp.issuer(),
                ),
                &format!("concealed-create-{index:04}"),
            )
            .await
            .expect("create concealed review task");
    }
    let visible = service
        .create_review_request(
            &producer,
            review_request_for_subject(
                "visible-after-budget",
                "visible-after-budget-reference",
                &idp.issuer(),
            ),
            "visible-after-budget-create",
        )
        .await
        .expect("create visible review task");

    let reviewer_token = reviewer_token(&idp);
    let first = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/review-tasks?limit=1")
                .header("authorization", format!("Bearer {reviewer_token}"))
                .header(CASEWORK_PROFILE_HEADER, "staff")
                .header(SOURCE_PROFILE_HEADER, "reviewer-source")
                .body(Body::empty())
                .expect("first bounded task page"),
        )
        .await
        .expect("first bounded task page response");
    assert_eq!(first.status(), StatusCode::OK);
    let first: ReviewTaskPage = serde_json::from_slice(
        &to_bytes(first.into_body(), 32 * 1024)
            .await
            .expect("bounded first task page"),
    )
    .expect("first task page JSON");
    assert!(first.items.is_empty());
    // The short page says the source-read budget ran out, so a caller does
    // not read it as the end of the inbox.
    assert_eq!(
        first.status,
        registry_casework_core::PageStatus::BudgetExhausted
    );
    let continuation = first
        .next_cursor
        .expect("scan-budget page preserves a continuation");

    let second = app
        .oneshot(
            Request::builder()
                .uri(format!("/v1/review-tasks?limit=1&cursor={continuation}"))
                .header("authorization", format!("Bearer {reviewer_token}"))
                .header(CASEWORK_PROFILE_HEADER, "staff")
                .header(SOURCE_PROFILE_HEADER, "reviewer-source")
                .body(Body::empty())
                .expect("continued task page"),
        )
        .await
        .expect("continued task page response");
    assert_eq!(second.status(), StatusCode::OK);
    let second: ReviewTaskPage = serde_json::from_slice(
        &to_bytes(second.into_body(), 32 * 1024)
            .await
            .expect("bounded continued task page"),
    )
    .expect("continued task page JSON");
    assert_eq!(second.items.len(), 1);
    assert_eq!(second.items[0].request_id, visible.accepted.request_id);
    assert_eq!(second.status, registry_casework_core::PageStatus::Complete);

    idp.stop().await;
}

#[tokio::test]
async fn mixed_context_inbox_lists_submitted_and_source_tasks_together() {
    let idp = MockIdp::start().await;
    let (app, _, _, _, _, _) = app(&idp).await;
    let producer_token = token(&idp);
    let source_created = app
        .clone()
        .oneshot(create_http_request(
            &review_request("mixed-source-ref", &idp.issuer()),
            Some(&producer_token),
        ))
        .await
        .expect("create mixed source-context review");
    assert_eq!(source_created.status(), StatusCode::CREATED);
    let source_created: ReviewRequestAccepted = serde_json::from_slice(
        &to_bytes(source_created.into_body(), 32 * 1024)
            .await
            .expect("bounded mixed source create response"),
    )
    .expect("mixed source create JSON");

    let mut answer_request = review_request("mixed-answer-ref", &idp.issuer());
    answer_request.kind = "registry-answer".to_owned();
    answer_request.subject.id = "answer-record-1".to_owned();
    answer_request.subject.digest = ContentDigest::for_bytes(b"answer-record-1");
    answer_request.context = ReviewContext::Submitted {
        snapshot: json!({}),
    };
    let answer_created = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/review-requests")
                .header(CONTENT_TYPE, "application/json")
                .header(CASEWORK_PROFILE_HEADER, "producer")
                .header("idempotency-key", "create-mixed-answer")
                .header("authorization", format!("Bearer {producer_token}"))
                .body(Body::from(
                    serde_json::to_vec(&answer_request).expect("serialize mixed answer create"),
                ))
                .expect("mixed answer create request"),
        )
        .await
        .expect("create mixed submitted-context review");
    assert_eq!(answer_created.status(), StatusCode::CREATED);
    let answer_created: ReviewRequestAccepted = serde_json::from_slice(
        &to_bytes(answer_created.into_body(), 32 * 1024)
            .await
            .expect("bounded mixed answer create response"),
    )
    .expect("mixed answer create JSON");

    let reviewer_token = reviewer_token(&idp);
    // A supplied source profile declares the caller's source visibility; it
    // does not narrow the unified inbox to source-backed kinds, so one page
    // carries both the approval and the answer task.
    let listed = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/review-tasks")
                .header("authorization", format!("Bearer {reviewer_token}"))
                .header(CASEWORK_PROFILE_HEADER, "staff")
                .header(SOURCE_PROFILE_HEADER, "reviewer-source")
                .body(Body::empty())
                .expect("mixed inbox task page request"),
        )
        .await
        .expect("mixed inbox task page response");
    assert_eq!(listed.status(), StatusCode::OK);
    let listed: ReviewTaskPage = serde_json::from_slice(
        &to_bytes(listed.into_body(), 32 * 1024)
            .await
            .expect("bounded mixed inbox task page"),
    )
    .expect("mixed inbox task page JSON");
    let mut listed_requests: Vec<Uuid> = listed.items.iter().map(|task| task.request_id).collect();
    listed_requests.sort();
    let mut expected = vec![source_created.request_id, answer_created.request_id];
    expected.sort();
    assert_eq!(
        listed_requests, expected,
        "one inbox page must list both context strategies"
    );

    // Without the profile only the submitted-context task stays visible:
    // source-backed candidates require the caller-scoped source read.
    let submitted_only = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/review-tasks")
                .header("authorization", format!("Bearer {reviewer_token}"))
                .header(CASEWORK_PROFILE_HEADER, "staff")
                .body(Body::empty())
                .expect("profile-less inbox task page request"),
        )
        .await
        .expect("profile-less inbox task page response");
    assert_eq!(submitted_only.status(), StatusCode::OK);
    let submitted_only: ReviewTaskPage = serde_json::from_slice(
        &to_bytes(submitted_only.into_body(), 32 * 1024)
            .await
            .expect("bounded profile-less inbox task page"),
    )
    .expect("profile-less inbox task page JSON");
    assert_eq!(submitted_only.items.len(), 1);
    assert_eq!(
        submitted_only.items[0].request_id,
        answer_created.request_id
    );

    idp.stop().await;
}

#[tokio::test]
async fn standalone_structured_answer_can_be_claimed_decided_and_polled_over_http() {
    let idp = MockIdp::start().await;
    let (app, _, _, _, _, _) = app(&idp).await;
    let mut request = review_request("answer-ref-1", &idp.issuer());
    request.kind = "registry-answer".to_owned();
    request.subject.id = "answer-record-1".to_owned();
    request.subject.digest = ContentDigest::for_bytes(b"answer-record-1");
    request.context = ReviewContext::Submitted {
        snapshot: json!({}),
    };

    let producer_token = token(&idp);
    // An explicit JSON null must not be silently treated as an omitted field:
    // the protocol keeps it present so check() rejects the non-object shape.
    let mut null_constraints_body =
        serde_json::to_value(&request).expect("serialize null-constraints request");
    null_constraints_body["requesterReference"] = json!("answer-null-constraints");
    null_constraints_body["resultConstraints"] = Value::Null;
    let null_constraints = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/review-requests")
                .header("authorization", format!("Bearer {producer_token}"))
                .header(CASEWORK_PROFILE_HEADER, "producer")
                .header(CONTENT_TYPE, "application/json")
                .header("idempotency-key", "create-null-constraints")
                .body(Body::from(
                    serde_json::to_vec(&null_constraints_body)
                        .expect("serialize explicit-null constraints"),
                ))
                .expect("explicit-null constraints request"),
        )
        .await
        .expect("explicit-null constraints response");
    assert_eq!(null_constraints.status(), StatusCode::BAD_REQUEST);
    assert!(
        null_constraints
            .headers()
            .get(VALIDATION_PATH_HEADER)
            .is_none(),
        "the protocol rejects a non-object shape without structured detail"
    );
    let null_constraints_problem: Value = serde_json::from_slice(
        &to_bytes(null_constraints.into_body(), 32 * 1024)
            .await
            .expect("bounded explicit-null constraints problem"),
    )
    .expect("explicit-null constraints problem JSON");
    assert_eq!(null_constraints_problem["code"], "request.invalid");

    let created = app
        .clone()
        .oneshot(create_http_request(&request, Some(&producer_token)))
        .await
        .expect("create standalone answer response");
    assert_eq!(created.status(), StatusCode::CREATED);
    let created: ReviewRequestAccepted = serde_json::from_slice(
        &to_bytes(created.into_body(), 32 * 1024)
            .await
            .expect("bounded standalone answer create response"),
    )
    .expect("standalone answer create JSON");

    let reviewer_token = reviewer_token(&idp);
    let tasks = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/review-tasks")
                .header("authorization", format!("Bearer {reviewer_token}"))
                .header(CASEWORK_PROFILE_HEADER, "staff")
                .body(Body::empty())
                .expect("standalone answer task list request"),
        )
        .await
        .expect("standalone answer task list response");
    assert_eq!(tasks.status(), StatusCode::OK);
    let tasks: ReviewTaskPage = serde_json::from_slice(
        &to_bytes(tasks.into_body(), 32 * 1024)
            .await
            .expect("bounded standalone answer task list"),
    )
    .expect("standalone answer task list JSON");
    assert_eq!(tasks.items.len(), 1);
    let task_id = tasks.items[0].task_id;

    let submitted_history = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/review-requests/{}/history",
                    created.request_id
                ))
                .header("authorization", format!("Bearer {reviewer_token}"))
                .header(CASEWORK_PROFILE_HEADER, "staff")
                .body(Body::empty())
                .expect("submitted-context history request"),
        )
        .await
        .expect("submitted-context history response");
    assert_eq!(submitted_history.status(), StatusCode::OK);

    let submitted_history_with_source_profile = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!(
                    "/v1/review-requests/{}/history",
                    created.request_id
                ))
                .header("authorization", format!("Bearer {reviewer_token}"))
                .header(CASEWORK_PROFILE_HEADER, "staff")
                .header(SOURCE_PROFILE_HEADER, "reviewer-source")
                .body(Body::empty())
                .expect("submitted-context history with source profile"),
        )
        .await
        .expect("submitted-context source-profile response");
    assert_eq!(
        submitted_history_with_source_profile.status(),
        StatusCode::BAD_REQUEST
    );

    let submitted_clocks = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/review-requests/{}/clocks", created.request_id))
                .header("authorization", format!("Bearer {reviewer_token}"))
                .header(CASEWORK_PROFILE_HEADER, "staff")
                .body(Body::empty())
                .expect("submitted-context clocks request"),
        )
        .await
        .expect("submitted-context clocks response");
    assert_eq!(submitted_clocks.status(), StatusCode::OK);

    let submitted_clocks_with_source_profile = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/review-requests/{}/clocks", created.request_id))
                .header("authorization", format!("Bearer {reviewer_token}"))
                .header(CASEWORK_PROFILE_HEADER, "staff")
                .header(SOURCE_PROFILE_HEADER, "reviewer-source")
                .body(Body::empty())
                .expect("submitted-context clocks with source profile"),
        )
        .await
        .expect("submitted-context source-profile clocks response");
    assert_eq!(
        submitted_clocks_with_source_profile.status(),
        StatusCode::BAD_REQUEST
    );

    let submitted_note = app
        .clone()
        .oneshot(review_note_http_request(
            created.request_id,
            &reviewer_token,
            "submitted-note",
            "Submitted context note",
            None,
        ))
        .await
        .expect("submitted-context note response");
    assert_eq!(submitted_note.status(), StatusCode::OK);

    let submitted_note_with_source_profile = app
        .clone()
        .oneshot(review_note_http_request(
            created.request_id,
            &reviewer_token,
            "submitted-note-with-source-profile",
            "must not be stored",
            Some("reviewer-source"),
        ))
        .await
        .expect("submitted-context note response with source profile");
    assert_eq!(
        submitted_note_with_source_profile.status(),
        StatusCode::BAD_REQUEST
    );

    let maximum_utf8_note = "é".repeat(1_000);
    let maximum_utf8_note_response = app
        .clone()
        .oneshot(review_note_http_request(
            created.request_id,
            &reviewer_token,
            "submitted-note-maximum-utf8",
            &maximum_utf8_note,
            None,
        ))
        .await
        .expect("maximum UTF-8 note response");
    assert_eq!(maximum_utf8_note_response.status(), StatusCode::OK);

    for (idempotency_key, invalid_note) in [
        ("submitted-note-over-maximum-utf8", "é".repeat(1_001)),
        ("submitted-note-whitespace", " \u{00a0}\u{3000}".to_owned()),
        ("submitted-note-control", "safe\u{0085}unsafe".to_owned()),
    ] {
        let response = app
            .clone()
            .oneshot(review_note_http_request(
                created.request_id,
                &reviewer_token,
                idempotency_key,
                &invalid_note,
                None,
            ))
            .await
            .expect("invalid review note response");
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }

    let claimed = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/review-tasks/{task_id}/claim"))
                .header("authorization", format!("Bearer {reviewer_token}"))
                .header(CASEWORK_PROFILE_HEADER, "staff")
                .header("if-match", "\"1\"")
                .header("idempotency-key", "claim-answer-record-1")
                .body(Body::empty())
                .expect("claim standalone answer request"),
        )
        .await
        .expect("claim standalone answer response");
    assert_eq!(claimed.status(), StatusCode::OK);

    let null_result = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/review-tasks/{task_id}/decisions"))
                .header("authorization", format!("Bearer {reviewer_token}"))
                .header(CASEWORK_PROFILE_HEADER, "staff")
                .header(CONTENT_TYPE, "application/json")
                .header("if-match", "\"2\"")
                .header("idempotency-key", "answer-null-result")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "decision": {
                            "type": "answer",
                            "outcome": "found",
                            "result": null
                        }
                    }))
                    .expect("serialize explicit-null result"),
                ))
                .expect("explicit-null result request"),
        )
        .await
        .expect("explicit-null result response");
    assert_eq!(null_result.status(), StatusCode::BAD_REQUEST);
    assert_eq!(
        null_result
            .headers()
            .get(VALIDATION_PATH_HEADER)
            .and_then(|value| value.to_str().ok()),
        Some("$.result")
    );
    assert_eq!(
        null_result
            .headers()
            .get(VALIDATION_REASON_HEADER)
            .and_then(|value| value.to_str().ok()),
        Some("object_required")
    );
    let null_result_problem: Value = serde_json::from_slice(
        &to_bytes(null_result.into_body(), 32 * 1024)
            .await
            .expect("bounded explicit-null result problem"),
    )
    .expect("explicit-null result problem JSON");
    assert_eq!(null_result_problem["code"], "request.invalid");

    let decision = ReviewTaskDecisionRequest {
        decision: ReviewerDecisionKind::Answer {
            outcome: "found".to_owned(),
            reason: None,
            result: Some(json!({"answer":"The structured answer"})),
        },
    };
    let decided = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/review-tasks/{task_id}/decisions"))
                .header("authorization", format!("Bearer {reviewer_token}"))
                .header(CASEWORK_PROFILE_HEADER, "staff")
                .header(CONTENT_TYPE, "application/json")
                .header("if-match", "\"2\"")
                .header("idempotency-key", "answer-answer-record-1")
                .body(Body::from(
                    serde_json::to_vec(&decision).expect("serialize answer decision"),
                ))
                .expect("decide standalone answer request"),
        )
        .await
        .expect("decide standalone answer response");
    assert_eq!(decided.status(), StatusCode::NO_CONTENT);

    let result = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/review-requests/{}/result", created.request_id))
                .header("authorization", format!("Bearer {producer_token}"))
                .header(CASEWORK_PROFILE_HEADER, "producer")
                .body(Body::empty())
                .expect("poll standalone answer request"),
        )
        .await
        .expect("poll standalone answer response");
    assert_eq!(result.status(), StatusCode::OK);
    let result: ReviewResult = serde_json::from_slice(
        &to_bytes(result.into_body(), 32 * 1024)
            .await
            .expect("bounded standalone answer result"),
    )
    .expect("standalone answer result JSON");
    assert_eq!(result.status, ReviewResultStatus::Answered);
    assert_eq!(
        result.result,
        Some(json!({"answer":"The structured answer"}))
    );

    let unknown = app
        .oneshot(
            Request::builder()
                .uri(format!("/v1/review-requests/{}/result", Uuid::new_v4()))
                .header("authorization", format!("Bearer {producer_token}"))
                .header(CASEWORK_PROFILE_HEADER, "producer")
                .body(Body::empty())
                .expect("unknown review result request"),
        )
        .await
        .expect("unknown review result response");
    assert_eq!(unknown.status(), StatusCode::NOT_FOUND);
    assert!(to_bytes(unknown.into_body(), 1024)
        .await
        .expect("bounded unknown result body")
        .is_empty());

    idp.stop().await;
}

#[tokio::test]
async fn an_initiator_reads_only_the_requester_visible_history_of_their_own_request_over_http() {
    let idp = MockIdp::start().await;
    let (app, _, _, _, _, _) = app(&idp).await;
    let producer_token = token(&idp);
    let reviewer_token = reviewer_token(&idp);
    let own_token = initiator_token(&idp, "initiator");
    let send = |request: Request<Body>| {
        let app = app.clone();
        async move {
            let response = app.oneshot(request).await.expect("initiator test response");
            let status = response.status();
            let body = to_bytes(response.into_body(), 64 * 1024)
                .await
                .expect("bounded initiator test body");
            (
                status,
                String::from_utf8(body.to_vec()).expect("UTF-8 body"),
            )
        }
    };
    let read = |request_id: Uuid, token: &str, profile: &str| {
        Request::builder()
            .uri(format!("/v1/review-requests/{request_id}/history"))
            .header("authorization", format!("Bearer {token}"))
            .header(CASEWORK_PROFILE_HEADER, profile)
            .body(Body::empty())
            .expect("history request")
    };
    let note = |request_id: Uuid, token: &str, profile: &str, audience: &str, text: &str| {
        let mut request = Request::builder()
            .method("POST")
            .uri(format!("/v1/review-requests/{request_id}/notes"))
            .header("authorization", format!("Bearer {token}"))
            .header(CASEWORK_PROFILE_HEADER, profile)
            .header(CONTENT_TYPE, "application/json")
            .header("idempotency-key", format!("note-{profile}-{audience}"));
        if profile == "staff" {
            request = request.header(SOURCE_PROFILE_HEADER, "reviewer-source");
        }
        request
            .body(Body::from(
                serde_json::to_vec(&json!({"audience": audience, "note": text}))
                    .expect("serialize note"),
            ))
            .expect("note request")
    };

    let (status, body) = send(create_http_request(
        &review_request("initiator-history", &idp.issuer()),
        Some(&producer_token),
    ))
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let created: ReviewRequestAccepted = serde_json::from_str(&body).expect("create JSON");
    let request_id = created.request_id;
    let (status, _) = send(note(
        request_id,
        &reviewer_token,
        "staff",
        "requester",
        "REQUESTER_REASON_CANARY",
    ))
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = send(note(
        request_id,
        &reviewer_token,
        "staff",
        "reviewers",
        "REVIEWER_ONLY_CANARY",
    ))
    .await;
    assert_eq!(status, StatusCode::OK);

    // The same request, admitted by a producer that declares no initiator
    // profile, names the same person and stays closed to them.
    let (status, body) = send(
        Request::builder()
            .method("POST")
            .uri("/v1/review-requests")
            .header(CONTENT_TYPE, "application/json")
            .header(CASEWORK_PROFILE_HEADER, "producer-alternate")
            .header("idempotency-key", "create-alternate-initiator")
            .header(
                "authorization",
                format!("Bearer {}", alternate_producer_token(&idp)),
            )
            .body(Body::from(
                serde_json::to_vec(&review_request_for_subject(
                    "record-2",
                    "alternate-initiator-history",
                    &idp.issuer(),
                ))
                .expect("serialize alternate request"),
            ))
            .expect("alternate create request"),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let alternate: ReviewRequestAccepted = serde_json::from_str(&body).expect("alternate JSON");

    let (status, history) = send(read(request_id, &own_token, "initiator")).await;
    assert_eq!(status, StatusCode::OK, "{history}");
    assert!(history.contains("REQUESTER_REASON_CANARY"));
    assert!(history.contains("request_created"));
    assert!(!history.contains("REVIEWER_ONLY_CANARY"));
    let (_, producer_history) = send(read(request_id, &producer_token, "producer")).await;
    assert_eq!(
        serde_json::from_str::<Value>(&history).expect("initiator history JSON"),
        serde_json::from_str::<Value>(&producer_history).expect("producer history JSON"),
        "the initiator sees exactly the producer's view"
    );

    let other_person = initiator_token(&idp, "another-initiator");
    let (status, _) = send(read(request_id, &other_person, "initiator")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = send(read(alternate.request_id, &own_token, "initiator")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = send(read(Uuid::new_v4(), &own_token, "initiator")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    let (status, _) = send(read(
        request_id,
        &alternate_producer_token(&idp),
        "producer-alternate",
    ))
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "another requester");

    // The initiator reads as the person themselves: an agent acting for them,
    // a grant-bearing token, or a non-human token naming the same subject is
    // refused before any request is looked up.
    for (extra, expected) in [
        (
            json!({"act": {"sub": "assistant-agent"}}),
            StatusCode::UNAUTHORIZED,
        ),
        (
            json!({"registry_grant_request": "grant"}),
            StatusCode::UNAUTHORIZED,
        ),
        (
            json!({"registry_actor_kind": "service"}),
            StatusCode::FORBIDDEN,
        ),
    ] {
        let mut claims = json!({
            "aud": AUDIENCE,
            "registry_principal": "initiator",
            "scope": "casework:initiator",
            "registry_actor_kind": "human"
        });
        for (key, value) in extra.as_object().expect("extra claims") {
            claims[key] = value.clone();
        }
        let (status, body) = send(read(request_id, &idp.mint_token(claims), "initiator")).await;
        assert_eq!(status, expected, "{extra}");
        assert!(!body.contains("REQUESTER_REASON_CANARY"), "{extra}");
    }

    // Read only: the initiator profile carries no producer authority.
    let (status, _) = send(note(
        request_id,
        &own_token,
        "initiator",
        "requester",
        "INITIATOR_NOTE_CANARY",
    ))
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    for path in ["result", "clocks"] {
        let (status, _) = send(
            Request::builder()
                .uri(format!("/v1/review-requests/{request_id}/{path}"))
                .header("authorization", format!("Bearer {own_token}"))
                .header(CASEWORK_PROFILE_HEADER, "initiator")
                .body(Body::empty())
                .expect("initiator read request"),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{path}");
    }
    let (_, history) = send(read(request_id, &producer_token, "producer")).await;
    assert!(!history.contains("INITIATOR_NOTE_CANARY"));

    idp.stop().await;
}

async fn read_task_json(app: &axum::Router, task_id: Uuid, token: &str) -> Value {
    let response = app
        .clone()
        .oneshot(
            Request::builder()
                .uri(format!("/v1/review-tasks/{task_id}"))
                .header("authorization", format!("Bearer {token}"))
                .header(CASEWORK_PROFILE_HEADER, "staff")
                .body(Body::empty())
                .expect("review task read request"),
        )
        .await
        .expect("review task read response");
    assert_eq!(response.status(), StatusCode::OK);
    serde_json::from_slice(
        &to_bytes(response.into_body(), 32 * 1024)
            .await
            .expect("bounded review task read"),
    )
    .expect("review task read JSON")
}

#[tokio::test]
async fn a_reviewer_confirms_from_the_task_read_whether_they_decided_it_over_http() {
    let idp = MockIdp::start().await;
    let (app, _, _, _, _, _) = app(&idp).await;
    let mut request = review_request("decided-by-caller-ref", &idp.issuer());
    request.kind = "registry-answer".to_owned();
    request.subject.id = "decided-by-caller-record".to_owned();
    request.subject.digest = ContentDigest::for_bytes(b"decided-by-caller-record");
    request.context = ReviewContext::Submitted {
        snapshot: json!({}),
    };
    let created = app
        .clone()
        .oneshot(create_http_request(&request, Some(&token(&idp))))
        .await
        .expect("create review response");
    assert_eq!(created.status(), StatusCode::CREATED);

    let reviewer_token = reviewer_token(&idp);
    let colleague_token = colleague_token(&idp);
    let tasks = app
        .clone()
        .oneshot(
            Request::builder()
                .uri("/v1/review-tasks")
                .header("authorization", format!("Bearer {reviewer_token}"))
                .header(CASEWORK_PROFILE_HEADER, "staff")
                .body(Body::empty())
                .expect("task list request"),
        )
        .await
        .expect("task list response");
    let tasks: ReviewTaskPage = serde_json::from_slice(
        &to_bytes(tasks.into_body(), 32 * 1024)
            .await
            .expect("bounded task list"),
    )
    .expect("task list JSON");
    assert_eq!(tasks.items.len(), 1);
    let task_id = tasks.items[0].task_id;

    // Undecided work says nothing about who decided it.
    let open = read_task_json(&app, task_id, &reviewer_token).await;
    assert_eq!(open["state"], "open");
    assert!(open.get("decidedByCaller").is_none(), "{open}");

    let claimed = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/review-tasks/{task_id}/claim"))
                .header("authorization", format!("Bearer {reviewer_token}"))
                .header(CASEWORK_PROFILE_HEADER, "staff")
                .header("if-match", "\"1\"")
                .header("idempotency-key", "claim-decided-by-caller")
                .body(Body::empty())
                .expect("claim request"),
        )
        .await
        .expect("claim response");
    assert_eq!(claimed.status(), StatusCode::OK);
    let decided = app
        .clone()
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(format!("/v1/review-tasks/{task_id}/decisions"))
                .header("authorization", format!("Bearer {reviewer_token}"))
                .header(CASEWORK_PROFILE_HEADER, "staff")
                .header(CONTENT_TYPE, "application/json")
                .header("if-match", "\"2\"")
                .header("idempotency-key", "decide-decided-by-caller")
                .body(Body::from(
                    serde_json::to_vec(&json!({
                        "decision": {
                            "type": "answer",
                            "outcome": "found",
                            "result": {"answer": "Recorded"}
                        }
                    }))
                    .expect("serialize decision"),
                ))
                .expect("decide request"),
        )
        .await
        .expect("decide response");
    assert_eq!(decided.status(), StatusCode::NO_CONTENT);

    // The reviewer whose decide response was lost learns the decision is
    // theirs, while a colleague on the same queue learns only that it is
    // not theirs, and neither read names the decider.
    let own = read_task_json(&app, task_id, &reviewer_token).await;
    assert_eq!(own["state"], "decided");
    assert_eq!(own["decidedByCaller"], true);
    let other = read_task_json(&app, task_id, &colleague_token).await;
    assert_eq!(other["state"], "decided");
    assert_eq!(other["decidedByCaller"], false);
    assert_eq!(
        {
            let mut own = own.clone();
            own.as_object_mut()
                .expect("task object")
                .remove("decidedByCaller");
            own.as_object_mut()
                .expect("task object")
                .remove("decisionReceipt");
            own
        },
        {
            let mut other = other.clone();
            other
                .as_object_mut()
                .expect("task object")
                .remove("decidedByCaller");
            other
        },
        "the two reads differ only by caller-relative decision confirmation"
    );

    idp.stop().await;
}

#[tokio::test]
async fn reviewer_ownership_filters_precede_pagination_and_survive_state_changes_over_http() {
    let idp = MockIdp::start().await;
    let (app, _, _, _, _, _, database) = app_with_database(&idp).await;
    let (_, first) = create_answer_task(&app, &database, &idp, "ownership-first").await;
    let (_, held) = create_answer_task(&app, &database, &idp, "ownership-held").await;
    let (_, later) = create_answer_task(&app, &database, &idp, "ownership-later").await;
    let (_, assigned) = create_answer_task(&app, &database, &idp, "ownership-assigned").await;
    let (_, elsewhere) = create_answer_task(&app, &database, &idp, "ownership-elsewhere").await;
    database
        .batch_execute(
            "INSERT INTO casework_queue_service(queue_id,team_id,revision)
         VALUES('elsewhere','review-team',1);",
        )
        .await
        .expect("serve a second queue");
    database
        .execute(
            "UPDATE casework_review_tasks SET queue_id='elsewhere' WHERE task_id=$1",
            &[&elsewhere],
        )
        .await
        .expect("route a task to the second queue");
    let (client, server) = native_review_client(app.clone()).await;
    let reviewer = human_token(&idp, "reviewer", "staff");
    let colleague = human_token(&idp, "colleague", "staff");
    let supervisor = human_token(&idp, "supervisor", "supervisor");
    let auth = || CaseworkAuth::new(&reviewer, "staff");
    let colleague_auth = || CaseworkAuth::new(&colleague, "staff");
    client
        .claim_review_task(colleague_auth(), held, 1, "claim-other")
        .await
        .expect("other holder");
    for task in [assigned, elsewhere] {
        client
            .assign_review_task(
                CaseworkAuth::new(&supervisor, "supervisor"),
                task,
                1,
                &format!("assign-{task}"),
                &registry_casework_core::AssignmentRequest {
                    assignee: registry_casework_core::IssuerPrincipal {
                        issuer: idp.issuer(),
                        subject: "reviewer".to_owned(),
                    },
                    reason: None,
                },
            )
            .await
            .expect("supervisor assigns beyond the first unfiltered page");
    }
    let first_page = client
        .review_tasks(
            auth(),
            &ReviewTaskQuery {
                queue: Some("review".to_owned()),
                limit: Some(1),
                ..Default::default()
            },
        )
        .await
        .expect("default first page")
        .value;
    assert_eq!(first_page.items[0].task_id, first);
    let assigned_query = ReviewTaskQuery {
        queue: Some("review".to_owned()),
        ownership: Some(ReviewTaskOwnership::AssignedToMe),
        limit: Some(1),
        ..Default::default()
    };
    let mine = client
        .review_tasks(auth(), &assigned_query)
        .await
        .expect("assigned native view")
        .value;
    assert_eq!(mine.items.len(), 1);
    assert_eq!(mine.items[0].task_id, assigned);
    assert!(mine.next_cursor.is_none());
    let unclaimed = ReviewTaskQuery {
        queue: Some("review".to_owned()),
        ownership: Some(ReviewTaskOwnership::Unclaimed),
        limit: Some(1),
        ..Default::default()
    };
    let available = client
        .review_tasks(auth(), &unclaimed)
        .await
        .expect("available first page")
        .value;
    assert_eq!(available.items[0].task_id, first);
    let cursor = available.next_cursor.expect("more available work");
    client
        .claim_review_task(auth(), first, 1, "claim-cursor-anchor")
        .await
        .expect("claim anchor");
    let continuation = ReviewTaskQuery {
        cursor: Some(cursor),
        ..unclaimed.clone()
    };
    let after_claim = client
        .review_tasks(auth(), &continuation)
        .await
        .expect("claim keeps scan position")
        .value;
    assert_eq!(
        after_claim
            .items
            .iter()
            .map(|task| task.task_id)
            .collect::<Vec<_>>(),
        vec![later]
    );
    client
        .decide_review_task(auth(), first, 2, "decide-cursor-anchor", &answer_decision())
        .await
        .expect("decide anchor");
    let after_decision = client
        .review_tasks(auth(), &continuation)
        .await
        .expect("decision keeps scan position")
        .value;
    assert_eq!(
        after_decision
            .items
            .iter()
            .map(|task| task.task_id)
            .collect::<Vec<_>>(),
        vec![later]
    );
    // A delegated holder immediately leaves one person's view and enters the other's.
    client
        .delegate_review_task(
            auth(),
            assigned,
            2,
            "delegate-assigned",
            &registry_casework_core::DelegateRequest {
                delegate: registry_casework_core::IssuerPrincipal {
                    issuer: idp.issuer(),
                    subject: "colleague".to_owned(),
                },
                reason: None,
            },
        )
        .await
        .expect("delegate assigned task");
    assert!(client
        .review_tasks(auth(), &assigned_query)
        .await
        .expect("refresh mine")
        .value
        .items
        .is_empty());
    let colleagues = client
        .review_tasks(
            colleague_auth(),
            &ReviewTaskQuery {
                limit: Some(100),
                ..assigned_query.clone()
            },
        )
        .await
        .expect("refresh colleague")
        .value;
    assert_eq!(
        colleagues
            .items
            .iter()
            .map(|task| task.task_id)
            .collect::<Vec<_>>(),
        vec![held, assigned]
    );
    let held_cursor = client
        .review_tasks(colleague_auth(), &assigned_query)
        .await
        .expect("held first page")
        .value
        .next_cursor
        .expect("second holding");
    client
        .release_review_task(colleague_auth(), held, 2, "release-held-anchor")
        .await
        .expect("release cursor anchor");
    let after_release = client
        .review_tasks(
            colleague_auth(),
            &ReviewTaskQuery {
                cursor: Some(held_cursor),
                ..assigned_query.clone()
            },
        )
        .await
        .expect("released anchor keeps scan position")
        .value;
    assert_eq!(after_release.items[0].task_id, assigned);
    client
        .release_review_task(colleague_auth(), assigned, 3, "release-delegated")
        .await
        .expect("release delegated task");
    let refreshed = client
        .review_tasks(
            auth(),
            &ReviewTaskQuery {
                limit: Some(100),
                ..unclaimed.clone()
            },
        )
        .await
        .expect("refresh available")
        .value;
    assert_eq!(
        refreshed
            .items
            .iter()
            .map(|task| task.task_id)
            .collect::<Vec<_>>(),
        vec![held, later, assigned]
    );
    assert!(refreshed
        .items
        .iter()
        .all(|task| task.decision_receipt.is_none()));
    // Queue service and current membership remain authority checks for every ownership value.
    database
        .execute(
            "DELETE FROM casework_memberships WHERE subject='reviewer'",
            &[],
        )
        .await
        .expect("remove membership");
    assert!(client
        .review_tasks(auth(), &assigned_query)
        .await
        .expect("revoked first page")
        .value
        .items
        .is_empty());
    assert_client_status(
        client
            .review_tasks(auth(), &continuation)
            .await
            .expect_err("revoked cursor"),
        410,
    );
    assert!(client
        .review_tasks(
            CaseworkAuth::new(&supervisor, "supervisor"),
            &assigned_query
        )
        .await
        .expect("ineligible supervisor inbox")
        .value
        .items
        .is_empty());
    server.abort();
    idp.stop().await;
}

#[tokio::test]
async fn supervisors_discover_operational_reviews_without_decision_eligibility_over_http() {
    let idp = MockIdp::start().await;
    let (app, _, revoked, _, _, _, database) = app_with_database(&idp).await;
    let (_, assigned) = create_answer_task(&app, &database, &idp, "supervision-assignment").await;
    let (waiting_request, waiting) =
        create_answer_task(&app, &database, &idp, "supervision-waiting").await;
    let (_, unrelated) = create_answer_task(&app, &database, &idp, "supervision-unrelated").await;
    database.batch_execute(
        "INSERT INTO casework_teams(team_id,revision) VALUES('other-team',1);
         INSERT INTO casework_queue_service(queue_id,team_id,revision) VALUES('other','other-team',1);",
    ).await.expect("unrelated serving team");
    database
        .execute(
            "UPDATE casework_review_tasks SET queue_id='other' WHERE task_id=$1",
            &[&unrelated],
        )
        .await
        .expect("route unrelated task");
    let source_request =
        review_request_for_subject("supervision-source", "supervision-source", &idp.issuer());
    let (_, source_task) = create_task(&app, &database, &idp, &source_request).await;
    let (client, server) = native_review_client(app.clone()).await;
    let supervisor = human_token(&idp, "supervisor", "supervisor");
    let reviewer = human_token(&idp, "reviewer", "staff");
    let administrator = human_token(&idp, "administrator", "administrator");
    let auth = || CaseworkAuth::new(&supervisor, "supervisor");
    let query = SupervisoryReviewTaskQuery {
        queue: Some("review".to_owned()),
        limit: Some(1),
        ..Default::default()
    };
    assert!(client
        .review_tasks(auth(), &ReviewTaskQuery::default())
        .await
        .expect("supervisor remains ineligible as a reviewer")
        .value
        .items
        .is_empty());
    let first = client
        .supervisory_review_tasks(auth(), &query)
        .await
        .expect("supervisor discovery")
        .value;
    assert_eq!(first.items[0].task_id, assigned);
    let cursor = first.next_cursor.expect("bounded supervisor page");
    let assignment = client
        .assign_review_task(
            auth(),
            assigned,
            first.items[0].revision,
            "assign-discovered",
            &registry_casework_core::AssignmentRequest {
                assignee: registry_casework_core::IssuerPrincipal {
                    issuer: idp.issuer(),
                    subject: "reviewer".to_owned(),
                },
                reason: None,
            },
        )
        .await
        .expect("discover then assign")
        .value;
    assert!(assignment.decision_receipt.is_none());
    let claimed = client
        .supervisory_review_tasks(auth(), &query)
        .await
        .expect("claimed task discovery")
        .value;
    assert_eq!(
        serde_json::to_value(&claimed.items[0]).expect("claimed operational row"),
        json!({
            "taskId": assigned,
            "requestId": first.items[0].request_id,
            "queue": "review",
            "revision": 2,
            "state": "held"
        }),
        "claimed discovery omits holder issuer and subject"
    );
    let next = client
        .supervisory_review_tasks(
            auth(),
            &SupervisoryReviewTaskQuery {
                cursor: Some(cursor),
                ..query.clone()
            },
        )
        .await
        .expect("assignment keeps supervisor cursor usable")
        .value;
    assert_eq!(next.items[0].task_id, waiting);
    assert_client_status(
        client
            .claim_review_task(auth(), assigned, 2, "supervisor-claim")
            .await
            .expect_err("discovery grants no claim authority"),
        403,
    );
    assert_client_status(
        client
            .decide_review_task(
                auth(),
                assigned,
                2,
                "supervisor-decision",
                &answer_decision(),
            )
            .await
            .expect_err("discovery grants no decision authority"),
        403,
    );
    assert_client_status(
        client
            .review_task(auth(), assigned)
            .await
            .expect_err("no reviewer detail"),
        404,
    );
    assert_client_status(
        client
            .review_task_context(auth(), assigned)
            .await
            .expect_err("no submitted context"),
        404,
    );
    for (bearer, profile) in [(&reviewer, "staff"), (&administrator, "administrator")] {
        assert_client_status(
            client
                .supervisory_review_tasks(CaseworkAuth::new(bearer, profile), &query)
                .await
                .expect_err("only supervisors discover this projection"),
            403,
        );
    }
    client
        .decide_review_task(
            CaseworkAuth::new(&reviewer, "staff"),
            assigned,
            2,
            "decide-assigned",
            &answer_decision(),
        )
        .await
        .expect("assigned reviewer decides");
    let all = SupervisoryReviewTaskQuery {
        limit: Some(100),
        ..query.clone()
    };
    let without_source = client
        .supervisory_review_tasks(auth(), &all)
        .await
        .expect("submitted discovery")
        .value;
    assert_eq!(
        without_source
            .items
            .iter()
            .map(|task| task.task_id)
            .collect::<Vec<_>>(),
        vec![assigned, waiting]
    );
    let completed = &without_source.items[0];
    let event_id = completed
        .accountability_event_id
        .expect("accountability reference for decided work");
    let wire = serde_json::to_value(completed).expect("operational row");
    let mut fields = wire
        .as_object()
        .expect("discovery object")
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    fields.sort_unstable();
    assert_eq!(
        fields,
        vec![
            "accountabilityEventId",
            "queue",
            "requestId",
            "revision",
            "state",
            "taskId"
        ]
    );
    let producer = BearerToken::new(token(&idp)).expect("synthetic producer bearer");
    client
        .cancel_review_request(
            CaseworkAuth::new(&producer, "producer"),
            &waiting_request,
            "cancel-waiting-discovery",
            &registry_casework_core::ReviewCancelRequest {
                subject: waiting_request.subject.clone(),
                reason: "withdrawn".to_owned(),
            },
        )
        .await
        .expect("producer closes waiting work");
    let closed = client
        .supervisory_review_tasks(auth(), &all)
        .await
        .expect("retained closed discovery")
        .value;
    let closed = closed
        .items
        .iter()
        .find(|task| task.task_id == waiting)
        .expect("closed task reference");
    assert_eq!(
        closed.state,
        registry_casework_core::SupervisoryReviewTaskState::Decided
    );
    assert!(closed.accountability_event_id.is_none());
    let cancelled = client
        .review_task(CaseworkAuth::new(&reviewer, "staff"), waiting)
        .await
        .expect("closed task read")
        .value;
    assert_eq!(cancelled.decided_by_caller, Some(false));
    assert!(cancelled.decision_receipt.is_none());
    let accountability = client
        .review_accountability(auth(), event_id)
        .await
        .expect("existing accountability authority")
        .value;
    assert_eq!(
        accountability.private_reason.as_deref(),
        Some("private-reason-canary")
    );
    assert_client_status(
        client
            .review_accountability(CaseworkAuth::new(&reviewer, "staff"), event_id)
            .await
            .expect_err("private reasons stay supervisor-only"),
        403,
    );
    let visible = client
        .supervisory_review_tasks(auth().with_source_profile("reviewer-source"), &all)
        .await
        .expect("current source authority")
        .value;
    assert!(visible.items.iter().any(|task| task.task_id == source_task));
    assert!(visible.items.iter().all(|task| task.task_id != unrelated));
    revoked.store(true, Ordering::SeqCst);
    let concealed = client
        .supervisory_review_tasks(auth().with_source_profile("reviewer-source"), &all)
        .await
        .expect("source revocation conceals discovery")
        .value;
    assert!(concealed
        .items
        .iter()
        .all(|task| task.task_id != source_task));
    database
        .execute(
            "UPDATE casework_review_requests SET terminal_at=now()-interval '91 days',
         result_available_until=now()-interval '1 day' WHERE request_id=$1",
            &[&completed.request_id],
        )
        .await
        .expect("expire decided task");
    assert!(client
        .supervisory_review_tasks(auth(), &all)
        .await
        .expect("retention conceals discovery")
        .value
        .items
        .iter()
        .all(|task| task.task_id != assigned));
    database
        .execute(
            "DELETE FROM casework_memberships WHERE subject='supervisor'",
            &[],
        )
        .await
        .expect("remove supervision");
    assert!(client
        .supervisory_review_tasks(auth(), &all)
        .await
        .expect("current membership removal")
        .value
        .items
        .is_empty());
    assert_client_status(
        client
            .review_accountability(auth(), event_id)
            .await
            .expect_err("accountability revoked"),
        404,
    );
    server.abort();
    idp.stop().await;
}

#[tokio::test]
async fn decision_receipts_disclose_only_the_callers_retained_pinned_outcome_over_http() {
    let idp = MockIdp::start().await;
    let (app, service, revoked, _, _, _, database) = app_with_database(&idp).await;
    let (accepted, task) = create_answer_task(&app, &database, &idp, "own-receipt").await;
    let (client, server) = native_review_client(app.clone()).await;
    let reviewer = human_token(&idp, "reviewer", "staff");
    let colleague = human_token(&idp, "colleague", "staff");
    let auth = || CaseworkAuth::new(&reviewer, "staff");
    client
        .claim_review_task(auth(), task, 1, "claim-receipt")
        .await
        .expect("claim receipt task");
    assert_client_status(
        client
            .decide_review_task(auth(), task, 1, "stale-receipt", &answer_decision())
            .await
            .expect_err("stale attempt refused"),
        412,
    );
    assert!(client
        .review_task(auth(), task)
        .await
        .expect("read after refused decision")
        .value
        .decision_receipt
        .is_none());
    client
        .decide_review_task(auth(), task, 2, "decide-receipt", &answer_decision())
        .await
        .expect("commit exact answer");
    // A new bearer and client recover only the authoritative decision, independent of local attempts.
    let fresh_reviewer = human_token(&idp, "reviewer", "staff");
    let own = client
        .review_task(CaseworkAuth::new(&fresh_reviewer, "staff"), task)
        .await
        .expect("fresh session receipt")
        .value;
    assert_eq!(own.decided_by_caller, Some(true));
    let receipt = own.decision_receipt.as_ref().expect("own retained receipt");
    assert_eq!(receipt.policy, accepted.policy);
    assert_eq!(
        receipt.decision,
        registry_casework_core::ReviewDecisionType::Answer
    );
    assert_eq!(receipt.outcome.as_deref(), Some("found"));
    let receipt_wire = serde_json::to_value(receipt).expect("receipt wire");
    assert_eq!(receipt_wire.as_object().expect("receipt object").len(), 4);
    assert!(receipt_wire.get("privateReason").is_none());
    assert!(receipt_wire.get("reason").is_none());
    assert!(receipt_wire.get("result").is_none());
    let other = client
        .review_task(CaseworkAuth::new(&colleague, "staff"), task)
        .await
        .expect("colleague read")
        .value;
    assert_eq!(other.decided_by_caller, Some(false));
    assert!(other.decision_receipt.is_none());
    assert_client_status(
        client
            .decide_review_task(
                CaseworkAuth::new(&colleague, "staff"),
                task,
                2,
                "other-late-attempt",
                &answer_decision(),
            )
            .await
            .expect_err("another caller cannot replace decision"),
        404,
    );
    let source = review_request_for_subject("source-receipt", "source-receipt", &idp.issuer());
    let (_, source_task) = create_task(&app, &database, &idp, &source).await;
    client
        .claim_review_task(
            auth().with_source_profile("reviewer-source"),
            source_task,
            1,
            "claim-source-receipt",
        )
        .await
        .expect("source-authorized claim");
    client
        .decide_review_task(
            auth().with_source_profile("reviewer-source"),
            source_task,
            2,
            "approve-source-receipt",
            &registry_casework_client::ReviewTaskDecisionRequest {
                decision: ReviewerDecisionKind::Approve,
            },
        )
        .await
        .expect("source-authorized approval");
    let approved = client
        .review_task(auth().with_source_profile("reviewer-source"), source_task)
        .await
        .expect("own approval receipt")
        .value
        .decision_receipt
        .expect("approval receipt");
    assert_eq!(
        approved.decision,
        registry_casework_core::ReviewDecisionType::Approve
    );
    assert!(approved.outcome.is_none());
    revoked.store(true, Ordering::SeqCst);
    assert_client_status(
        client
            .review_task(auth().with_source_profile("reviewer-source"), source_task)
            .await
            .expect_err("source revocation conceals receipt"),
        404,
    );
    database
        .execute(
            "DELETE FROM casework_memberships WHERE subject='reviewer'",
            &[],
        )
        .await
        .expect("remove reviewer");
    assert_client_status(
        client
            .review_task(auth(), task)
            .await
            .expect_err("membership removal conceals receipt"),
        404,
    );
    database.execute("INSERT INTO casework_memberships(team_id,issuer,subject,membership_kind) VALUES('review-team',$1,'reviewer','staff')",
        &[&idp.issuer()]).await.expect("restore membership");
    database
        .execute(
            "UPDATE casework_review_requests SET terminal_at=now()-interval '91 days',
         result_available_until=now()-interval '1 day' WHERE request_id=$1",
            &[&accepted.request_id],
        )
        .await
        .expect("expire own result");
    assert_client_status(
        client
            .review_task(auth(), task)
            .await
            .expect_err("expiry conceals receipt"),
        404,
    );
    service
        .erase_expired_reviews()
        .await
        .expect("erase expired review payloads");
    let decisions: i64 = database
        .query_one(
            "SELECT count(*) FROM casework_review_decisions WHERE task_id=$1",
            &[&task],
        )
        .await
        .expect("erased decision count")
        .get(0);
    assert_eq!(decisions, 0);
    assert_client_status(
        client
            .review_task(auth(), task)
            .await
            .expect_err("erasure conceals receipt"),
        404,
    );
    server.abort();
    idp.stop().await;
}

#[tokio::test]
async fn an_excluded_initiator_and_a_missing_initiator_get_their_own_problem_codes_over_http() {
    let idp = MockIdp::start().await;
    let (app, _, _, _, _, _) = app(&idp).await;
    let send = |request: Request<Body>| {
        let app = app.clone();
        async move {
            let response = app
                .oneshot(request)
                .await
                .expect("initiator problem response");
            let status = response.status();
            let body: Value = serde_json::from_slice(
                &to_bytes(response.into_body(), 32 * 1024)
                    .await
                    .expect("bounded initiator problem body"),
            )
            .expect("initiator problem JSON");
            (status, body)
        }
    };
    let mut request = review_request("initiator-codes", &idp.issuer());
    request.kind = "registry-answer".to_owned();
    request.subject.id = "initiator-codes-record".to_owned();
    request.subject.digest = ContentDigest::for_bytes(b"initiator-codes-record");
    request.context = ReviewContext::Submitted {
        snapshot: json!({}),
    };

    // A kind that excludes its initiator cannot be admitted without one.
    let mut anonymous = request.clone();
    anonymous.initiator = None;
    let (status, problem) = send(create_http_request(&anonymous, Some(&token(&idp)))).await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{problem}");
    assert_eq!(problem["code"], "review.initiator-required");

    // The reviewer submitted this request, so the stage refuses their claim
    // with a code a UI can explain.
    request.initiator = Some(HumanIdentity {
        issuer: idp.issuer(),
        subject: "reviewer".to_owned(),
    });
    let (status, created) = send(create_http_request(&request, Some(&token(&idp)))).await;
    assert_eq!(status, StatusCode::CREATED, "{created}");
    let reviewer = reviewer_token(&idp);
    let (status, tasks) = send(
        Request::builder()
            .uri("/v1/review-tasks")
            .header("authorization", format!("Bearer {reviewer}"))
            .header(CASEWORK_PROFILE_HEADER, "staff")
            .body(Body::empty())
            .expect("initiator task list request"),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{tasks}");
    let task_id = tasks["items"][0]["taskId"]
        .as_str()
        .expect("listed initiator task")
        .to_owned();
    let claim = |token: String, key: &'static str| {
        Request::builder()
            .method("POST")
            .uri(format!("/v1/review-tasks/{task_id}/claim"))
            .header("authorization", format!("Bearer {token}"))
            .header(CASEWORK_PROFILE_HEADER, "staff")
            .header("if-match", "\"1\"")
            .header("idempotency-key", key)
            .body(Body::empty())
            .expect("initiator claim request")
    };
    let (status, problem) = send(claim(reviewer, "claim-own-request")).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{problem}");
    assert_eq!(problem["code"], "review.initiator-excluded");

    // Anyone else on the stage still claims it.
    let (status, claimed) = send(claim(colleague_token(&idp), "claim-colleague")).await;
    assert_eq!(status, StatusCode::OK, "{claimed}");

    idp.stop().await;
}

/// Insert a second, different value for the first member of `object` into
/// its serialized text, so the only defect is the duplicate member.
fn with_duplicate_member(object: &serde_json::Map<String, Value>) -> String {
    let text = serde_json::to_string(object).expect("serialize fixture object");
    match object.keys().next() {
        Some(first) => format!(
            "{{{}:\"smuggled\",{}",
            serde_json::to_string(first).expect("serialize member name"),
            &text[1..]
        ),
        None => r#"{"member":1,"member":2}"#.to_owned(),
    }
}

/// The first nested object member of `body` receives a duplicate member.
fn with_nested_duplicate_member(body: &Value) -> Option<String> {
    let object = body.as_object()?;
    let (name, nested) = object
        .iter()
        .find(|(_, value)| value.as_object().is_some_and(|nested| !nested.is_empty()))?;
    let mut rest = object.clone();
    rest.remove(name);
    let rest = serde_json::to_string(&rest).expect("serialize fixture object");
    let separator = if rest == "{}" { "" } else { "," };
    Some(format!(
        "{{{}:{}{separator}{}",
        serde_json::to_string(name).expect("serialize member name"),
        with_duplicate_member(nested.as_object().expect("nested object")),
        &rest[1..]
    ))
}

struct StrictJsonRoute {
    method: &'static str,
    path: String,
    body: Value,
    producer: bool,
    source_profile: bool,
    /// Hand-written bodies whose duplicate sits inside a free-form JSON
    /// member, which a typed field's own duplicate check never saw.
    free_form_duplicates: Vec<String>,
}

fn strict_route(method: &'static str, path: String, body: Value) -> StrictJsonRoute {
    StrictJsonRoute {
        method,
        path,
        body,
        producer: false,
        source_profile: false,
        free_form_duplicates: Vec::new(),
    }
}

async fn send_strict_json(
    app: &axum::Router,
    idp: &MockIdp,
    route: &StrictJsonRoute,
    body: String,
) -> (StatusCode, Value) {
    let (token, profile) = if route.producer {
        (token(idp), "producer")
    } else {
        (reviewer_token(idp), "staff")
    };
    let mut request = Request::builder()
        .method(route.method)
        .uri(&route.path)
        .header("authorization", format!("Bearer {token}"))
        .header(CASEWORK_PROFILE_HEADER, profile)
        .header(CONTENT_TYPE, "application/json")
        .header("if-match", "\"1\"")
        .header("idempotency-key", "strict-json");
    if route.source_profile {
        request = request.header(SOURCE_PROFILE_HEADER, "reviewer-source");
    }
    let response = app
        .clone()
        .oneshot(request.body(Body::from(body)).expect("strict JSON request"))
        .await
        .expect("strict JSON response");
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("bounded response");
    (
        status,
        serde_json::from_slice(&bytes).unwrap_or(Value::Null),
    )
}

/// Every route refuses a duplicate member at the top level and inside a
/// nested object with 422 request.unprocessable, while the same body without
/// the duplicate passes body parsing and closed-type validation.
async fn assert_duplicate_members_are_refused(routes: impl FnOnce(&str) -> Vec<StrictJsonRoute>) {
    let idp = MockIdp::start().await;
    let (app, ..) = app(&idp).await;
    for route in &routes(&idp.issuer()) {
        let label = format!("{} {}", route.method, route.path);
        let mut duplicated = vec![with_duplicate_member(
            route.body.as_object().expect("fixture bodies are objects"),
        )];
        duplicated.extend(with_nested_duplicate_member(&route.body));
        duplicated.extend(route.free_form_duplicates.iter().cloned());
        for body in duplicated {
            assert!(
                parse_json_strict_refuses(&body),
                "{label}: fixture {body} must carry a duplicate member"
            );
            let (status, problem) = send_strict_json(&app, &idp, route, body).await;
            assert_eq!(
                status,
                StatusCode::UNPROCESSABLE_ENTITY,
                "{label}: {problem}"
            );
            assert_eq!(problem["code"], "request.unprocessable", "{label}");
        }
        let (status, problem) = send_strict_json(&app, &idp, route, route.body.to_string()).await;
        assert!(
            !matches!(
                problem["code"].as_str(),
                Some("request.invalid" | "request.unprocessable")
            ),
            "{label}: the valid twin was refused as a body: {status} {problem}"
        );
    }
}

fn parse_json_strict_refuses(body: &str) -> bool {
    serde_json::from_str::<Value>(body).is_ok()
        && registry_platform_canonical_json::parse_json_strict(body.as_bytes()).is_err()
}

fn principal(subject: &str) -> Value {
    json!({"issuer": "https://issuer.example.test", "subject": subject})
}

fn source_binding() -> Value {
    json!({"sourceRevision": "revision-1", "version": "1", "generation": "review-http-source"})
}

#[tokio::test]
async fn review_request_routes_refuse_a_duplicate_member() {
    let id = Uuid::new_v4();
    let producer = |mut route: StrictJsonRoute| {
        route.producer = true;
        route
    };
    assert_duplicate_members_are_refused(|issuer| {
        let request = review_request("strict-json", issuer);
        let body = serde_json::to_value(&request).expect("serialize review request");
        let text = body.to_string();
        let mut create = producer(strict_route("POST", "/v1/review-requests".to_owned(), body));
        create.free_form_duplicates.push(format!(
            r#"{},"resultConstraints":{{"type":"object","type":"string"}}}}"#,
            &text[..text.len() - 1]
        ));
        vec![
            create,
            producer(strict_route(
                "POST",
                format!("/v1/review-requests/{id}/cancel"),
                json!({"subject": request.subject, "reason": "withdrawn"}),
            )),
            strict_route(
                "POST",
                format!("/v1/review-requests/{id}/notes"),
                json!({"audience": "reviewers", "note": "checked"}),
            ),
        ]
    })
    .await;
}

#[tokio::test]
async fn review_task_routes_refuse_a_duplicate_member() {
    let id = Uuid::new_v4();
    assert_duplicate_members_are_refused(|_issuer| {
        vec![
            strict_route(
                "POST",
                format!("/v1/review-tasks/{id}/assign"),
                json!({"assignee": principal("colleague"), "reason": "cover"}),
            ),
            strict_route(
                "POST",
                format!("/v1/review-tasks/{id}/delegate"),
                json!({"delegate": principal("colleague"), "reason": "cover"}),
            ),
            strict_route(
                "PUT",
                format!("/v1/review-tasks/{id}/draft"),
                json!({"body": {"summary": "draft"}}),
            ),
            StrictJsonRoute {
                free_form_duplicates: vec![concat!(
                    r#"{"decision":{"type":"reject","outcome":"returned","#,
                    r#""result":{"note":"a","note":"b"}}}"#
                )
                .to_owned()],
                ..strict_route(
                    "POST",
                    format!("/v1/review-tasks/{id}/decisions"),
                    json!({"decision": {"type": "approve"}}),
                )
            },
        ]
    })
    .await;
}

#[tokio::test]
async fn work_item_routes_refuse_a_duplicate_member() {
    let id = Uuid::new_v4();
    let source = |mut route: StrictJsonRoute| {
        route.source_profile = true;
        route
    };
    assert_duplicate_members_are_refused(|_issuer| {
        vec![
            source(strict_route(
                "PUT",
                format!("/v1/work-items/{id}/draft"),
                json!({"binding": source_binding(), "reason": "draft", "flaggedFields": []}),
            )),
            source(strict_route(
                "POST",
                format!("/v1/work-items/{id}/decisions"),
                json!({"displayedBinding": source_binding(), "operation": "approve"}),
            )),
        ]
    })
    .await;
}

#[tokio::test]
async fn attempt_recovery_routes_refuse_a_duplicate_member() {
    let id = Uuid::new_v4();
    let source = |mut route: StrictJsonRoute| {
        route.source_profile = true;
        route
    };
    assert_duplicate_members_are_refused(|_issuer| {
        vec![
            source(strict_route(
                "POST",
                format!("/v1/work-items/{id}/attempts/recover"),
                json!({}),
            )),
            source(strict_route(
                "POST",
                format!("/v1/work-items/{id}/attempts/{}/recover", Uuid::new_v4()),
                json!({}),
            )),
        ]
    })
    .await;
}

#[tokio::test]
async fn assignment_directory_and_absence_routes_refuse_a_duplicate_member() {
    let id = Uuid::new_v4();
    let absence = json!({
        "person": principal("reviewer"),
        "from": "2026-10-01T00:00:00Z",
        "until": "2026-10-02T00:00:00Z",
        "cover": principal("colleague"),
    });
    let movement = json!({
        "from": principal("reviewer"),
        "to": principal("colleague"),
        "reason": "rebalance",
    });
    assert_duplicate_members_are_refused(|_issuer| vec![
        strict_route(
            "POST",
            format!("/v1/work-items/{id}/assign"),
            json!({"assignee": principal("colleague")}),
        ),
        strict_route(
            "POST",
            format!("/v1/work-items/{id}/delegate"),
            json!({"delegate": principal("colleague")}),
        ),
        strict_route("POST", "/v1/directory/absences".to_owned(), absence.clone()),
        strict_route("PUT", format!("/v1/directory/absences/{id}"), absence),
        strict_route(
            "POST",
            "/v1/directory/caseload/preview".to_owned(),
            movement.clone(),
        ),
        strict_route(
            "POST",
            "/v1/directory/caseload/apply".to_owned(),
            json!({"movement": movement, "items": [{"itemId": id, "expectedRevision": 1}]}),
        ),
        strict_route(
            "PUT",
            "/v1/directory/teams/review-team".to_owned(),
            json!({"staff": [principal("reviewer")], "supervisors": [], "servedQueues": ["review"]}),
        ),
        strict_route(
            "POST",
            "/v1/directory/bootstrap".to_owned(),
            json!({"teamId": "review-team", "staff": [], "supervisors": [], "queueId": "review"}),
        ),
        strict_route(
            "POST",
            "/v1/directory/holidays".to_owned(),
            json!({"document": {"holidaySet": "office", "revision": 1, "dates": ["2026-09-07"]}}),
        ),
        strict_route(
            "POST",
            "/v1/directory/clocks/recompute/preview".to_owned(),
            json!({"clockId": "review-deadline", "holidaySet": "office", "holidayRevision": 1}),
        ),
        strict_route(
            "POST",
            "/v1/directory/clocks/recompute/apply".to_owned(),
            json!({"previewId": id}),
        ),
    ])
    .await;
}

#[tokio::test]
async fn task_grant_approval_routes_refuse_a_duplicate_member() {
    let id = Uuid::new_v4();
    let source = |mut route: StrictJsonRoute| {
        route.source_profile = true;
        route
    };
    let approval = json!({"templateId": "review-assistant", "templateVersion": "1"});
    assert_duplicate_members_are_refused(|_issuer| {
        vec![
            source(strict_route(
                "POST",
                format!("/v1/work-items/{id}/task-grants"),
                approval.clone(),
            )),
            source(strict_route(
                "POST",
                format!("/v1/review-tasks/{id}/task-grants"),
                approval,
            )),
        ]
    })
    .await;
}

#[tokio::test]
async fn a_review_request_with_a_duplicate_member_creates_nothing_and_its_twin_does() {
    let idp = MockIdp::start().await;
    let (app, ..) = app(&idp).await;
    let request = review_request("strict-json-twin", &idp.issuer());
    let body = serde_json::to_value(&request).expect("serialize review request");
    let object = body.as_object().expect("review request object");
    let mut smuggled = object.clone();
    smuggled.remove("requesterReference");
    let smuggled = format!(
        "{{\"requesterReference\":\"first\",\"requesterReference\":\"second\",{}",
        &serde_json::to_string(&smuggled).expect("serialize remaining members")[1..]
    );
    let producer = |body: String| {
        Request::builder()
            .method("POST")
            .uri("/v1/review-requests")
            .header(CONTENT_TYPE, "application/json")
            .header(CASEWORK_PROFILE_HEADER, "producer")
            .header("idempotency-key", "strict-json-twin")
            .header("authorization", format!("Bearer {}", token(&idp)))
            .body(Body::from(body))
            .expect("review HTTP request")
    };
    let refused = app.clone().oneshot(producer(smuggled)).await.unwrap();
    assert_eq!(refused.status(), StatusCode::UNPROCESSABLE_ENTITY);
    // The same idempotency key then creates the request: the refused body
    // reserved nothing.
    let created = app.oneshot(producer(body.to_string())).await.unwrap();
    assert_eq!(created.status(), StatusCode::CREATED);
}

#[tokio::test]
async fn every_paged_route_names_its_limit_range_when_refusing_it() {
    let idp = MockIdp::start().await;
    let (app, ..) = app(&idp).await;
    let id = Uuid::new_v4();
    // (method, path with query prefix, maximum, producer, source profile, body)
    type PagedRoute = (&'static str, String, usize, bool, bool, Option<Value>);
    let routes: [PagedRoute; 9] = [
        (
            "GET",
            "/v1/review-tasks?".to_owned(),
            100,
            false,
            false,
            None,
        ),
        (
            "GET",
            "/v1/review-results?".to_owned(),
            100,
            true,
            false,
            None,
        ),
        (
            "GET",
            format!("/v1/review-requests/{id}/history?"),
            100,
            false,
            false,
            None,
        ),
        (
            "GET",
            "/v1/work-items?view=my_teams&".to_owned(),
            100,
            false,
            true,
            None,
        ),
        (
            "GET",
            format!("/v1/work-items/{id}/history?"),
            100,
            false,
            true,
            None,
        ),
        ("GET", "/v1/holdings?".to_owned(), 100, false, true, None),
        (
            "GET",
            "/v1/directory/targets?purpose=absence_person&".to_owned(),
            100,
            false,
            false,
            None,
        ),
        (
            "GET",
            "/v1/directory/absences?".to_owned(),
            1_000,
            false,
            false,
            None,
        ),
        (
            "POST",
            "/v1/directory/caseload/preview?".to_owned(),
            100,
            false,
            false,
            Some(json!({
                "from": {"issuer": idp.issuer(), "subject": "reviewer"},
                "to": {"issuer": idp.issuer(), "subject": "colleague"},
                "reason": "rebalance",
            })),
        ),
    ];
    for (method, prefix, maximum, producer, source_profile, body) in routes {
        for (limit, refused) in [(0, true), (maximum + 1, true), (maximum, false)] {
            let (token, profile) = if producer {
                (token(&idp), "producer")
            } else {
                (reviewer_token(&idp), "staff")
            };
            let mut request = Request::builder()
                .method(method)
                .uri(format!("{prefix}limit={limit}"))
                .header("authorization", format!("Bearer {token}"))
                .header(CASEWORK_PROFILE_HEADER, profile);
            if source_profile {
                request = request.header(SOURCE_PROFILE_HEADER, "reviewer-source");
            }
            let body = match &body {
                Some(body) => {
                    request = request.header(CONTENT_TYPE, "application/json");
                    Body::from(body.to_string())
                }
                None => Body::empty(),
            };
            let response = app
                .clone()
                .oneshot(request.body(body).expect("paged request"))
                .await
                .expect("paged response");
            let status = response.status();
            let problem: Value = serde_json::from_slice(
                &to_bytes(response.into_body(), 1024 * 1024)
                    .await
                    .expect("bounded response"),
            )
            .unwrap_or(Value::Null);
            let label = format!("{method} {prefix}limit={limit}");
            if refused {
                assert_eq!(status, StatusCode::BAD_REQUEST, "{label}: {problem}");
                assert_eq!(problem["code"], "request.limit-out-of-range", "{label}");
                let detail = problem["detail"].as_str().expect("problem detail");
                assert!(detail.contains("limit"), "{label}");
                assert!(detail.contains("1 to 100"), "{label}");
                assert!(detail.contains("1 to 1000"), "{label}");
            } else {
                assert_ne!(
                    problem["code"], "request.limit-out-of-range",
                    "{label}: {status} {problem}"
                );
            }
        }
    }
    idp.stop().await;
}

#[tokio::test]
async fn an_inbox_emptied_only_by_the_missing_source_profile_says_so() {
    let idp = MockIdp::start().await;
    let (app, ..) = app(&idp).await;
    let created = app
        .clone()
        .oneshot(create_http_request(
            &review_request("source-only-ref", &idp.issuer()),
            Some(&token(&idp)),
        ))
        .await
        .expect("create source-context review");
    assert_eq!(created.status(), StatusCode::CREATED);
    let reviewer_token = reviewer_token(&idp);
    let list = |source_profile: Option<&str>| {
        let mut request = Request::builder()
            .uri("/v1/review-tasks")
            .header("authorization", format!("Bearer {reviewer_token}"))
            .header(CASEWORK_PROFILE_HEADER, "staff");
        if let Some(source_profile) = source_profile {
            request = request.header(SOURCE_PROFILE_HEADER, source_profile);
        }
        app.clone()
            .oneshot(request.body(Body::empty()).expect("inbox request"))
    };

    // Every candidate is source-backed, so the page is empty only because
    // the Registry-Source-Profile header is absent.
    let refused = list(None).await.expect("profile-less inbox response");
    assert_eq!(refused.status(), StatusCode::BAD_REQUEST);
    let problem: Value = serde_json::from_slice(
        &to_bytes(refused.into_body(), 32 * 1024)
            .await
            .expect("bounded problem"),
    )
    .expect("problem JSON");
    assert_eq!(problem["code"], "source-profile.required");
    assert_eq!(
        problem.as_object().expect("problem object").len(),
        6,
        "the refusal names no task: {problem}"
    );

    let listed = list(Some("reviewer-source"))
        .await
        .expect("profiled inbox response");
    assert_eq!(listed.status(), StatusCode::OK);
    let listed: ReviewTaskPage = serde_json::from_slice(
        &to_bytes(listed.into_body(), 32 * 1024)
            .await
            .expect("bounded page"),
    )
    .expect("page JSON");
    assert_eq!(listed.items.len(), 1);

    // A source profile that hides the task from this caller still yields an
    // ordinary empty page: only the absent header is refused.
    let hidden = list(Some("other-source-profile"))
        .await
        .expect("mismatched profile inbox response");
    assert_eq!(hidden.status(), StatusCode::OK);
    idp.stop().await;
}

#[tokio::test]
async fn an_inbox_page_short_only_of_its_source_read_budget_continues_without_a_source_profile() {
    let idp = MockIdp::start().await;
    let (app, service, _, _, _, _) = app(&idp).await;
    let producer = ActorContext {
        principal: registry_casework_core::IssuerPrincipal {
            issuer: idp.issuer(),
            subject: "registry-service".to_owned(),
        },
        profile_id: "producer".to_owned(),
        role: CaseworkRole::Requester,
    };
    // More source-backed candidates than the default source-read budget of
    // 25, then one submitted-context task the caller can see without a
    // source profile.
    for index in 0..30 {
        service
            .create_review_request(
                &producer,
                review_request_for_subject(
                    &format!("budget-source-{index:04}"),
                    &format!("budget-source-reference-{index:04}"),
                    &idp.issuer(),
                ),
                &format!("budget-source-create-{index:04}"),
            )
            .await
            .expect("create source-backed review task");
    }
    let mut answer_request = review_request_for_subject(
        "budget-answer-record",
        "budget-answer-reference",
        &idp.issuer(),
    );
    answer_request.kind = "registry-answer".to_owned();
    answer_request.context = ReviewContext::Submitted {
        snapshot: json!({}),
    };
    let answer = service
        .create_review_request(&producer, answer_request, "budget-answer-create")
        .await
        .expect("create submitted-context review task");

    let reviewer_token = reviewer_token(&idp);
    let list = |cursor: Option<Uuid>| {
        let uri = match cursor {
            Some(cursor) => format!("/v1/review-tasks?limit=10&cursor={cursor}"),
            None => "/v1/review-tasks?limit=10".to_owned(),
        };
        app.clone().oneshot(
            Request::builder()
                .uri(uri)
                .header("authorization", format!("Bearer {reviewer_token}"))
                .header(CASEWORK_PROFILE_HEADER, "staff")
                .body(Body::empty())
                .expect("profile-less inbox request"),
        )
    };

    // The first page is empty because the source-read budget ran out, not
    // because the inbox holds nothing this caller can see, so it is an
    // ordinary short page with its continuation rather than a refusal.
    let first = list(None).await.expect("first profile-less page response");
    assert_eq!(first.status(), StatusCode::OK);
    let first: ReviewTaskPage = serde_json::from_slice(
        &to_bytes(first.into_body(), 32 * 1024)
            .await
            .expect("bounded first page"),
    )
    .expect("first page JSON");
    assert!(first.items.is_empty());
    assert_eq!(
        first.status,
        registry_casework_core::PageStatus::BudgetExhausted
    );
    let continuation = first
        .next_cursor
        .expect("a budget-exhausted page keeps its continuation");

    let second = list(Some(continuation))
        .await
        .expect("continued profile-less page response");
    assert_eq!(second.status(), StatusCode::OK);
    let second: ReviewTaskPage = serde_json::from_slice(
        &to_bytes(second.into_body(), 32 * 1024)
            .await
            .expect("bounded continued page"),
    )
    .expect("continued page JSON");
    assert_eq!(second.items.len(), 1);
    assert_eq!(second.items[0].request_id, answer.accepted.request_id);
    assert_eq!(second.status, registry_casework_core::PageStatus::Complete);

    idp.stop().await;
}
