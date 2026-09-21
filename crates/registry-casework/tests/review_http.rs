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
    SOURCE_PROFILE_HEADER,
};
use registry_platform_config::{SecretProvider, SecretResolver};
use registry_platform_httputil::FetchUrlPolicy;
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig};
use registry_platform_testing::{oidc_verifier_config, MockIdp};
use serde_json::json;
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
             VALUES('review-team','https://placeholder.invalid','reviewer','staff');",
        )
        .await
        .expect("seed review HTTP directory");
    database
        .execute(
            "UPDATE casework_memberships SET issuer=$1 WHERE subject='reviewer'",
            &[&idp.issuer()],
        )
        .await
        .expect("bind reviewer membership to test issuer");
    let store = PostgresStore::connect_runtime(&database_config, &secrets).expect("runtime store");
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
    )
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
    assert_eq!(tasks_without_source_profile.status(), StatusCode::OK);
    let tasks_without_source_profile: ReviewTaskPage = serde_json::from_slice(
        &to_bytes(tasks_without_source_profile.into_body(), 32 * 1024)
            .await
            .expect("bounded task list without source profile"),
    )
    .expect("task list without source profile JSON");
    assert!(tasks_without_source_profile.items.is_empty());

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
