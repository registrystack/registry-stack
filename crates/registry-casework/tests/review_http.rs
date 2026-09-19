#![cfg(feature = "postgres-test")]

use std::{
    collections::BTreeMap,
    env,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
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
    AccessProfile, ActiveSubjectsPage, AuthoritativeObservation, CallerSubjectView,
    CaseworkIdentity, CaseworkProject, CaseworkRole, ContentDigest, DiscoveryCursor,
    EphemeralCredential, EventRequest, ExecutePreparedRequest, HumanIdentity, InboxPolicy,
    PrepareActionRequest, PreparedSourceAttempt, QueuePolicy, ReviewContext, ReviewContextStrategy,
    ReviewCreateRequest, ReviewKindPolicy, ReviewKindPurpose, ReviewOutcomePolicy,
    ReviewOutcomeSettlement, ReviewProducerPolicy, ReviewRequestAccepted, ReviewResult,
    ReviewResultStatus, ReviewRetentionPolicy, ReviewStagePolicy, ReviewTaskPage,
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
        _subject: &SubjectRef,
    ) -> Result<AuthoritativeObservation, SourceAdapterError> {
        Err(SourceAdapterError::Invalid)
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
        if self.revoked.load(Ordering::SeqCst) || source_profile_id != "reviewer-source" {
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
        review_producers: vec![ReviewProducerPolicy {
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
        }],
        calendars: Vec::new(),
        clocks: Vec::new(),
        inbox: InboxPolicy::default(),
        task_templates: Vec::new(),
    }
}

fn review_request(reference: &str, issuer: &str) -> ReviewCreateRequest {
    ReviewCreateRequest {
        kind: "registry-correction".to_owned(),
        subject: SubjectBinding {
            source: "registry".to_owned(),
            subject_type: "record".to_owned(),
            id: "record-1".to_owned(),
            version: "1".to_owned(),
            digest: ContentDigest::for_bytes(b"record-1"),
        },
        requester_reference: reference.to_owned(),
        initiator: Some(HumanIdentity {
            issuer: issuer.to_owned(),
            subject: "initiator".to_owned(),
        }),
        context: ReviewContext::Source {
            binding: SourceContextBinding {
                reference: "registry:record:record-1".to_owned(),
            },
        },
        result_constraints: None,
    }
}

async fn app(idp: &MockIdp) -> (axum::Router, Arc<AtomicBool>, Arc<AtomicBool>) {
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
    let service = CaseworkService::new(
        store,
        project.clone(),
        [Arc::new(ReviewSource {
            revoked: Arc::clone(&revoked),
            changed: Arc::clone(&changed),
        }) as Arc<dyn SourceAdapter>],
    )
    .expect("review HTTP service");
    (
        router(HttpState {
            service,
            authenticator: Arc::new(authenticator),
            project: Arc::new(project),
        }),
        revoked,
        changed,
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

#[tokio::test]
async fn producer_http_create_recover_conflict_and_pending_result_are_closed() {
    let idp = MockIdp::start().await;
    let (app, source_revoked, source_changed) = app(&idp).await;
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
    let missing_source_profile = app
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
    assert_eq!(missing_source_profile.status(), StatusCode::OK);
    let missing_source_profile: ReviewTaskPage = serde_json::from_slice(
        &to_bytes(missing_source_profile.into_body(), 32 * 1024)
            .await
            .expect("bounded concealed task list"),
    )
    .expect("concealed task list JSON");
    assert!(missing_source_profile.items.is_empty());

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
    assert_eq!(recovered.status(), StatusCode::CREATED);
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
async fn standalone_structured_answer_can_be_claimed_decided_and_polled_over_http() {
    let idp = MockIdp::start().await;
    let (app, _, _) = app(&idp).await;
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
