#![cfg(feature = "postgres-test")]

use std::{
    collections::BTreeMap,
    env,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
};

use async_trait::async_trait;
use axum::{extract::State, http::StatusCode, routing::post, Router};
use chrono::{TimeDelta, Utc};
use registry_casework::{
    dispatch_review_completions_once_for_test, CaseworkService, DatabaseConfig, PostgresStore,
    ReviewResultRead, ReviewRuntimeError, ReviewTaskDecisionRequest,
};
use registry_casework_core::{
    AccessProfile, ActiveSubjectsPage, ActivityClockAnchor, ActorContext, AssignmentRequest,
    AuthoritativeObservation, CalendarPolicy, CallerSubjectView, CaseworkIdentity, CaseworkProject,
    CaseworkRole, ClockPolicy, ClockReassignment, ClockReminder, ClockStep, ClockStepAction,
    ClockStepInstant, ContentDigest, DelegateRequest, DiscoveryCursor, ElapsedDuration,
    EphemeralCredential, EventRequest, ExecutePreparedRequest, HolidaySetDocument, HumanIdentity,
    InboxPolicy, IssuerPrincipal, OccurrenceKind, OccurrenceState, PrepareActionRequest,
    PreparedSourceAttempt, QueuePolicy, ReviewClockState, ReviewCompletionDestinationPolicy,
    ReviewContext, ReviewContextStrategy, ReviewCreateRequest, ReviewHistoryAudience,
    ReviewKindPolicy, ReviewKindPurpose, ReviewNoteRequest, ReviewOutcomePolicy,
    ReviewOutcomeSettlement, ReviewProducerPolicy, ReviewRequestLifecycle, ReviewResultStatus,
    ReviewRetentionPolicy, ReviewStagePolicy, ReviewTaskDraftInput, ReviewTransition,
    ReviewerDecisionKind, ReviewerTaskState, SourceAdapter, SourceAdapterError, SourceBinding,
    SourceContextBinding, SourceReceipt, SubjectBinding, SubjectClockAnchor,
    SubjectClockCompletion, SubjectClockPause, SubjectRef, TransitionHint, WorkingDaysAfter,
    WorkingWeekday,
};
use registry_platform_config::{SecretProvider, SecretResolver};
use serde_json::json;
use tokio::sync::Notify;
use tokio_postgres::NoTls;
use uuid::Uuid;

struct Fixture {
    service_v1: CaseworkService,
    service_v2: CaseworkService,
    store: PostgresStore,
    database: tokio_postgres::Client,
    producer: ActorContext,
    reviewer_a: ActorContext,
    reviewer_b: ActorContext,
    supervisor: ActorContext,
    source_revoked: Arc<AtomicBool>,
    source_state: Arc<Mutex<OccurrenceState>>,
    application_name: String,
}

#[derive(Clone)]
struct ReviewSource {
    revoked: Arc<AtomicBool>,
    state: Arc<Mutex<OccurrenceState>>,
}

#[async_trait]
impl SourceAdapter for ReviewSource {
    fn source_id(&self) -> &str {
        "registry"
    }

    fn binding_generation(&self) -> &str {
        "review-source-generation"
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
        if self.revoked.load(Ordering::SeqCst) {
            return Err(SourceAdapterError::Concealed);
        }
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
            state: *self.state.lock().expect("source state lock"),
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
        if self.revoked.load(Ordering::SeqCst) || source_profile_id != "staff" {
            return Err(SourceAdapterError::Concealed);
        }
        Ok(CallerSubjectView {
            subject: subject.clone(),
            binding: SourceBinding {
                source_revision: "source-revision-1".to_owned(),
                version: "1".to_owned(),
                integrity: Some(ContentDigest::for_bytes(subject.id.as_bytes()).to_string()),
                generation: self.binding_generation().to_owned(),
            },
            display_reference: None,
            disclosed: BTreeMap::new(),
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

fn actor(subject: &str, role: CaseworkRole, profile_id: &str) -> ActorContext {
    ActorContext {
        principal: IssuerPrincipal {
            issuer: "https://issuer.test".to_owned(),
            subject: subject.to_owned(),
        },
        profile_id: profile_id.to_owned(),
        role,
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

fn project(version: &str) -> CaseworkProject {
    CaseworkProject {
        api_version: registry_casework_core::CASEWORK_API_VERSION.to_owned(),
        kind: registry_casework_core::CASEWORK_KIND.to_owned(),
        casework: CaseworkIdentity {
            id: "review-test".to_owned(),
            version: version.to_owned(),
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
        review_kinds: vec![ReviewKindPolicy {
            id: "registry-correction".to_owned(),
            version: version.to_owned(),
            purpose: ReviewKindPurpose::Approval,
            context_strategy: ReviewContextStrategy::Submitted,
            stages: vec![
                ReviewStagePolicy {
                    id: "primary".to_owned(),
                    queue: "review".to_owned(),
                    deciding_profiles: vec!["staff".to_owned()],
                    required_approvals: 1,
                    exclude_initiator: true,
                    exclude_previous_stage_reviewers: false,
                },
                ReviewStagePolicy {
                    id: "secondary".to_owned(),
                    queue: "review".to_owned(),
                    deciding_profiles: vec!["staff".to_owned()],
                    required_approvals: 1,
                    exclude_initiator: true,
                    exclude_previous_stage_reviewers: true,
                },
            ],
            clocks: vec!["review-deadline".to_owned()],
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
            result_schema: Some(json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["correction"],
                "properties": {"correction": {"type": "string", "maxLength": 160}}
            })),
            outcomes: vec![
                ReviewOutcomePolicy {
                    id: "incorrect".to_owned(),
                    label: "Incorrect".to_owned(),
                    settlement: ReviewOutcomeSettlement::Rejected,
                    reason_required: true,
                    result_required: true,
                },
                ReviewOutcomePolicy {
                    id: "needs-correction".to_owned(),
                    label: "Needs correction".to_owned(),
                    settlement: ReviewOutcomeSettlement::ChangesRequested,
                    reason_required: true,
                    result_required: true,
                },
            ],
        }],
        review_producers: vec![ReviewProducerPolicy {
            id: "registry".to_owned(),
            profile: "producer".to_owned(),
            issuer: "https://issuer.test".to_owned(),
            subject: "registry-service".to_owned(),
            trusted_initiator_issuer: Some("https://issuer.test".to_owned()),
            source_namespaces: vec!["registry".to_owned()],
            kinds: vec!["registry-correction".to_owned()],
            recovery_days: 30,
            completion: Some(ReviewCompletionDestinationPolicy {
                destination_id: "registry-completion".to_owned(),
                recipient_binding: "registry-service".to_owned(),
            }),
        }],
        calendars: Vec::new(),
        clocks: vec![ClockPolicy::Subject {
            id: "review-deadline".to_owned(),
            anchor: SubjectClockAnchor::FirstSubmittedAt,
            complete_on: SubjectClockCompletion::ReviewCompleted,
            after: ElapsedDuration {
                elapsed: "PT1H".to_owned(),
            },
            pause_while: vec![SubjectClockPause::AwaitingApplicant],
        }],
        inbox: InboxPolicy::default(),
        task_templates: Vec::new(),
    }
}

fn answer_project(completion: bool) -> CaseworkProject {
    let mut project = project("answer-1");
    let kind = &mut project.review_kinds[0];
    kind.id = "registry-answer".to_owned();
    kind.purpose = ReviewKindPurpose::Answer;
    kind.stages.truncate(1);
    kind.outcomes = vec![ReviewOutcomePolicy {
        id: "found".to_owned(),
        label: "Found".to_owned(),
        settlement: ReviewOutcomeSettlement::Answered,
        reason_required: false,
        result_required: true,
    }];
    project.review_producers[0].kinds = vec!["registry-answer".to_owned()];
    if !completion {
        project.review_producers[0].completion = None;
    }
    project
}

fn activity_clock_project() -> CaseworkProject {
    let mut project = project("activity-clock-1");
    project.queues.push(QueuePolicy {
        id: "overdue-review".to_owned(),
        label: "Overdue review".to_owned(),
    });
    project.review_kinds[0].stages.truncate(1);
    project.review_kinds[0].clocks = vec!["review-deadline".to_owned()];
    project.calendars = vec![CalendarPolicy {
        id: "office".to_owned(),
        timezone: "UTC".to_owned(),
        working_weekdays: vec![
            WorkingWeekday::Monday,
            WorkingWeekday::Tuesday,
            WorkingWeekday::Wednesday,
            WorkingWeekday::Thursday,
            WorkingWeekday::Friday,
            WorkingWeekday::Saturday,
            WorkingWeekday::Sunday,
        ],
        holiday_set: "office-holidays".to_owned(),
    }];
    project.clocks = vec![ClockPolicy::Activity {
        id: "review-deadline".to_owned(),
        anchor: ActivityClockAnchor::StageEnteredAt,
        calendar: "office".to_owned(),
        after: WorkingDaysAfter { working_days: 1 },
        due_time: "17:00".to_owned(),
        at_risk: None,
        reminders: vec![ClockReminder {
            id: "due-soon".to_owned(),
            working_days_before: 1,
        }],
        steps: vec![ClockStep {
            id: "overdue".to_owned(),
            because: "The review deadline passed".to_owned(),
            at: ClockStepInstant::Due,
            action: ClockStepAction {
                reassign: ClockReassignment {
                    queue: "overdue-review".to_owned(),
                },
            },
        }],
    }];
    project
}

fn request(subject_id: &str, requester_reference: &str) -> ReviewCreateRequest {
    ReviewCreateRequest {
        kind: "registry-correction".to_owned(),
        subject: SubjectBinding {
            source: "registry".to_owned(),
            subject_type: "record".to_owned(),
            id: subject_id.to_owned(),
            version: "1".to_owned(),
            digest: ContentDigest::for_bytes(subject_id.as_bytes()),
        },
        requester_reference: requester_reference.to_owned(),
        initiator: Some(HumanIdentity {
            issuer: "https://issuer.test".to_owned(),
            subject: "initiator".to_owned(),
        }),
        context: ReviewContext::Submitted {
            snapshot: json!({"summary": format!("Review {subject_id}")}),
        },
        result_constraints: None,
    }
}

async fn fixture() -> Fixture {
    let base = env::var("CASEWORK_REVIEW_TEST_DATABASE_URL")
        .expect("CASEWORK_REVIEW_TEST_DATABASE_URL is required for review PostgreSQL tests");
    let schema = format!("review_{}", Uuid::new_v4().simple());
    let application_name = format!("casework-review-{}", Uuid::new_v4().simple());
    let separator = if base.contains('?') { '&' } else { '?' };
    let scoped_url = format!(
        "{base}{separator}options=-csearch_path%3D{schema}&application_name={application_name}"
    );
    let (admin, admin_connection) = tokio_postgres::connect(&base, NoTls)
        .await
        .expect("connect dedicated review test database");
    tokio::spawn(async move { admin_connection.await.expect("admin connection") });
    admin
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .expect("create isolated review test schema");

    let secret_name =
        format!("CASEWORK_REVIEW_SCHEMA_{}", Uuid::new_v4().simple()).to_ascii_uppercase();
    env::set_var(&secret_name, &scoped_url);
    let secrets = SecretResolver::new([SecretProvider::Environment], "/private/tmp")
        .expect("test secret resolver");
    let database_config = DatabaseConfig {
        runtime_url_ref: format!("secret:env/{secret_name}"),
        migration_url_ref: format!("secret:env/{secret_name}"),
        trusted_root_certificate_ref: None,
        test_only_plaintext: true,
    };
    let migration =
        PostgresStore::connect_migration(&database_config, &secrets).expect("migration store");
    migration.migrate().await.expect("review migrations");
    let store = PostgresStore::connect_runtime(&database_config, &secrets).expect("runtime store");
    let database = connect_scoped(&scoped_url).await;
    database
        .batch_execute(
            "INSERT INTO casework_teams(team_id,revision) VALUES('review-team',1);
             INSERT INTO casework_queue_service(queue_id,team_id,revision)
             VALUES('review','review-team',1);
             INSERT INTO casework_memberships(team_id,issuer,subject,membership_kind) VALUES
               ('review-team','https://issuer.test','reviewer-a','staff'),
               ('review-team','https://issuer.test','reviewer-b','staff'),
               ('review-team','https://issuer.test','supervisor','supervisor');",
        )
        .await
        .expect("seed review directory");
    let project_v1 = project("1");
    let mut project_v2 = project("2");
    project_v2.review_kinds[0].context_strategy = ReviewContextStrategy::Source;
    project_v1.check().expect("version one project");
    project_v2.check().expect("version two project");
    let source_revoked = Arc::new(AtomicBool::new(false));
    let source_state = Arc::new(Mutex::new(OccurrenceState::Open));
    Fixture {
        service_v1: CaseworkService::new(
            store.clone(),
            project_v1,
            Vec::<Arc<dyn registry_casework_core::SourceAdapter>>::new(),
        )
        .expect("version one service"),
        service_v2: CaseworkService::new(
            store.clone(),
            project_v2,
            [Arc::new(ReviewSource {
                revoked: Arc::clone(&source_revoked),
                state: Arc::clone(&source_state),
            }) as Arc<dyn SourceAdapter>],
        )
        .expect("version two service"),
        store,
        database,
        producer: actor("registry-service", CaseworkRole::Requester, "producer"),
        reviewer_a: actor("reviewer-a", CaseworkRole::Staff, "staff"),
        reviewer_b: actor("reviewer-b", CaseworkRole::Staff, "staff"),
        supervisor: actor("supervisor", CaseworkRole::Supervisor, "supervisor"),
        source_revoked,
        source_state,
        application_name,
    }
}

async fn connect_scoped(url: &str) -> tokio_postgres::Client {
    let (client, connection) = tokio_postgres::connect(url, NoTls)
        .await
        .expect("schema connection");
    tokio::spawn(async move { connection.await.expect("schema connection task") });
    client
}

async fn task_id(fixture: &Fixture, request_id: Uuid, stage_index: i32) -> Uuid {
    fixture
        .database
        .query_one(
            "SELECT task_id FROM casework_review_tasks
             WHERE request_id=$1 AND stage_index=$2 ORDER BY slot LIMIT 1",
            &[&request_id, &stage_index],
        )
        .await
        .expect("review task")
        .get(0)
}

async fn count_for_request(fixture: &Fixture, table: &str, request_id: Uuid) -> i64 {
    let query = format!("SELECT count(*) FROM {table} WHERE request_id=$1");
    fixture
        .database
        .query_one(&query, &[&request_id])
        .await
        .expect("count review rows")
        .get(0)
}

async fn assert_terminal_atomic(fixture: &Fixture, request_id: Uuid, completion_events: i64) {
    assert_eq!(
        count_for_request(fixture, "casework_review_results", request_id).await,
        1
    );
    assert_eq!(
        count_for_request(fixture, "casework_review_terminal_events", request_id).await,
        1
    );
    assert_eq!(
        count_for_request(fixture, "casework_review_completion_outbox", request_id).await,
        completion_events
    );
}

async fn assert_store_sessions_hold_no_transaction_or_row_lock(fixture: &Fixture) {
    let sessions = fixture
        .database
        .query_one(
            "SELECT count(*),
                    count(*) FILTER (WHERE xact_start IS NOT NULL),
                    count(*) FILTER (WHERE state <> 'idle')
             FROM pg_stat_activity
             WHERE datname=current_database() AND application_name=$1
               AND pid<>pg_backend_pid()",
            &[&fixture.application_name],
        )
        .await
        .expect("inspect completion dispatcher database sessions");
    assert!(sessions.get::<_, i64>(0) > 0, "observe the dispatcher pool");
    assert_eq!(
        sessions.get::<_, i64>(1),
        0,
        "completion delivery must not retain an open database transaction"
    );
    assert_eq!(
        sessions.get::<_, i64>(2),
        0,
        "completion delivery must leave its database sessions idle"
    );

    let row_locks: i64 = fixture
        .database
        .query_one(
            "SELECT count(*)
             FROM pg_locks l
             JOIN pg_stat_activity a ON a.pid=l.pid
             WHERE a.datname=current_database() AND a.application_name=$1
               AND a.pid<>pg_backend_pid() AND l.granted
               AND l.locktype IN ('tuple','transactionid')",
            &[&fixture.application_name],
        )
        .await
        .expect("inspect completion dispatcher row locks")
        .get(0);
    assert_eq!(
        row_locks, 0,
        "completion delivery must not retain a row or transaction-id lock"
    );
}

async fn block_completion_response(
    State((received, release)): State<(Arc<Notify>, Arc<Notify>)>,
) -> StatusCode {
    received.notify_one();
    release.notified().await;
    StatusCode::NO_CONTENT
}

#[tokio::test]
async fn recovery_pins_policy_and_terminal_settlement_emits_atomically() {
    let fixture = fixture().await;
    let create = request("record-1", "producer-ref-1");
    let first = fixture
        .service_v1
        .create_review_request(&fixture.producer, create.clone(), "create-record-1")
        .await
        .expect("create review");
    assert!(!first.recovered);
    assert_eq!(first.accepted.policy.version, "1");

    let recovered = fixture
        .service_v2
        .create_review_request(&fixture.producer, create.clone(), "create-record-1")
        .await
        .expect("recover review through changed active config");
    assert!(recovered.recovered);
    assert_eq!(recovered.accepted.request_id, first.accepted.request_id);
    assert_eq!(recovered.accepted.policy, first.accepted.policy);

    let changed = fixture
        .service_v2
        .create_review_request(
            &fixture.producer,
            request("record-1", "changed-body"),
            "changed-record-1",
        )
        .await;
    assert!(matches!(
        changed,
        Err(ReviewRuntimeError::SubmissionConflict)
    ));
    assert!(matches!(
        fixture
            .service_v1
            .review_result(&fixture.producer, first.accepted.request_id)
            .await,
        Ok(ReviewResultRead::Pending)
    ));
    fixture
        .database
        .execute(
            "UPDATE casework_review_submission_reservations
                SET recovery_deadline=now()-interval '2 seconds',
                    retained_until=now()-interval '1 second'
              WHERE request_id=$1",
            &[&first.accepted.request_id],
        )
        .await
        .expect("age the active review reservation past its creation-based retention");
    fixture
        .service_v1
        .erase_expired_reviews()
        .await
        .expect("run retention while the review remains active");
    let active_reservations: i64 = fixture
        .database
        .query_one(
            "SELECT count(*) FROM casework_review_submission_reservations WHERE request_id=$1",
            &[&first.accepted.request_id],
        )
        .await
        .expect("active review reservation remains")
        .get(0);
    assert_eq!(active_reservations, 1);

    let primary = task_id(&fixture, first.accepted.request_id, 0).await;
    assert!(matches!(
        fixture
            .service_v1
            .decide_review_task(
                &fixture.reviewer_a,
                primary,
                ReviewTaskDecisionRequest {
                    decision: ReviewerDecisionKind::Approve,
                },
                None,
                "",
                1,
                "unheld-decision",
            )
            .await,
        Err(ReviewRuntimeError::TaskNotHeld)
    ));
    fixture
        .service_v1
        .claim_review_task(&fixture.reviewer_a, primary, None, "", 1, "claim-primary")
        .await
        .expect("claim primary review");
    assert!(matches!(
        fixture
            .service_v1
            .decide_review_task(
                &fixture.reviewer_a,
                primary,
                ReviewTaskDecisionRequest {
                    decision: ReviewerDecisionKind::Approve,
                },
                None,
                "",
                2,
                "decide-primary",
            )
            .await,
        Ok(ReviewTransition::StageAdvanced { .. })
    ));

    let secondary = task_id(&fixture, first.accepted.request_id, 1).await;
    fixture
        .service_v1
        .claim_review_task(
            &fixture.reviewer_b,
            secondary,
            None,
            "",
            1,
            "claim-secondary",
        )
        .await
        .expect("claim secondary review");
    assert!(matches!(
        fixture
            .service_v1
            .decide_review_task(
                &fixture.reviewer_b,
                secondary,
                ReviewTaskDecisionRequest {
                    decision: ReviewerDecisionKind::Approve,
                },
                None,
                "",
                2,
                "decide-secondary",
            )
            .await,
        Ok(ReviewTransition::Settled { .. })
    ));
    let accountability_event: Uuid = fixture
        .database
        .query_one(
            "SELECT event_id FROM casework_review_accountability WHERE task_id=$1",
            &[&secondary],
        )
        .await
        .expect("protected accountability event")
        .get(0);
    let accountability = fixture
        .service_v1
        .review_accountability(&fixture.supervisor, accountability_event)
        .await
        .expect("supervisor accountability read");
    assert_eq!(accountability.actor, fixture.reviewer_b.principal);
    assert_eq!(accountability.request_id, first.accepted.request_id);
    assert!(matches!(
        fixture
            .service_v1
            .review_accountability(&fixture.reviewer_b, accountability_event)
            .await,
        Err(ReviewRuntimeError::Forbidden)
    ));

    let result = fixture
        .service_v1
        .review_result(&fixture.producer, first.accepted.request_id)
        .await
        .expect("read terminal result");
    assert!(matches!(
        result,
        ReviewResultRead::Available(result) if result.status == ReviewResultStatus::Approved
    ));
    let request_view = fixture
        .service_v1
        .review_request(&fixture.producer, first.accepted.request_id)
        .await
        .expect("read terminal request");
    assert_eq!(request_view.lifecycle, ReviewRequestLifecycle::Approved);
    let feed = fixture
        .service_v1
        .review_result_feed(&fixture.producer, None, 10)
        .await
        .expect("read result feed");
    assert_eq!(feed.items.len(), 1);
    assert_eq!(feed.items[0].request_id, first.accepted.request_id);
    assert_eq!(
        count_for_request(
            &fixture,
            "casework_review_terminal_events",
            first.accepted.request_id,
        )
        .await,
        1
    );
    assert_eq!(
        count_for_request(
            &fixture,
            "casework_review_completion_outbox",
            first.accepted.request_id,
        )
        .await,
        1
    );

    let received = Arc::new(Notify::new());
    let release = Arc::new(Notify::new());
    let completion_receiver = Router::new()
        .route("/completion", post(block_completion_response))
        .with_state((Arc::clone(&received), Arc::clone(&release)));
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind completion receiver");
    let completion_url = format!(
        "http://{}/completion",
        listener.local_addr().expect("completion receiver address")
    );
    let receiver = tokio::spawn(async move {
        axum::serve(listener, completion_receiver)
            .await
            .expect("serve completion receiver");
    });
    let dispatcher = tokio::spawn(dispatch_review_completions_once_for_test(
        fixture.store.clone(),
        "registry-completion",
        completion_url,
        "completion-secret",
    ));
    tokio::time::timeout(std::time::Duration::from_secs(5), received.notified())
        .await
        .expect("completion receiver observes the leased delivery");
    assert_store_sessions_hold_no_transaction_or_row_lock(&fixture).await;
    release.notify_one();
    dispatcher
        .await
        .expect("completion dispatcher task")
        .expect("completion dispatcher pass");
    receiver.abort();
    let delivered = fixture
        .database
        .query_one(
            "SELECT state,attempt_count,lease_until FROM casework_review_completion_outbox
             WHERE request_id=$1",
            &[&first.accepted.request_id],
        )
        .await
        .expect("delivered completion row");
    assert_eq!(delivered.get::<_, String>(0), "delivered");
    assert_eq!(delivered.get::<_, i32>(1), 1);
    assert!(delivered
        .get::<_, Option<chrono::DateTime<Utc>>>(2)
        .is_none());
    fixture
        .database
        .execute(
            "UPDATE casework_review_completion_outbox
             SET state='pending',attempt_count=0,next_attempt_at=now(),lease_until=NULL,
                 delivered_at=NULL,last_failure_class=NULL
             WHERE request_id=$1",
            &[&first.accepted.request_id],
        )
        .await
        .expect("reset delivery for lost-acknowledgement coverage");

    let first_lease = fixture
        .store
        .lease_review_completions_for_test(10, Utc::now() + TimeDelta::minutes(5))
        .await
        .expect("lease completion delivery");
    assert_eq!(first_lease.len(), 1);
    let event_id = first_lease[0].event_id;
    assert!(fixture
        .store
        .lease_review_completions_for_test(10, Utc::now() + TimeDelta::minutes(5))
        .await
        .expect("do not lease active delivery twice")
        .is_empty());
    fixture
        .database
        .execute(
            "UPDATE casework_review_completion_outbox
             SET lease_until=now() - interval '1 second' WHERE event_id=$1",
            &[&event_id],
        )
        .await
        .expect("expire completion lease after simulated lost acknowledgement");
    let recovered_lease = fixture
        .store
        .lease_review_completions_for_test(10, Utc::now() + TimeDelta::minutes(5))
        .await
        .expect("recover expired completion lease");
    assert_eq!(recovered_lease.len(), 1);
    assert_eq!(recovered_lease[0].event_id, event_id);
    assert_eq!(recovered_lease[0], first_lease[0]);
    fixture
        .store
        .finish_review_completion_for_test(event_id, false, 3, Utc::now() + TimeDelta::seconds(30))
        .await
        .expect("schedule bounded completion retry");
    let pending = fixture
        .database
        .query_one(
            "SELECT state,attempt_count FROM casework_review_completion_outbox WHERE event_id=$1",
            &[&event_id],
        )
        .await
        .expect("pending completion retry");
    assert_eq!(pending.get::<_, String>(0), "pending");
    assert_eq!(pending.get::<_, i32>(1), 2);
    fixture
        .database
        .execute(
            "UPDATE casework_review_completion_outbox SET next_attempt_at=now() WHERE event_id=$1",
            &[&event_id],
        )
        .await
        .expect("make final completion attempt due");
    let final_lease = fixture
        .store
        .lease_review_completions_for_test(10, Utc::now() + TimeDelta::minutes(5))
        .await
        .expect("lease final completion attempt");
    assert_eq!(final_lease.len(), 1);
    assert_eq!(final_lease[0].event_id, event_id);
    fixture
        .store
        .finish_review_completion_for_test(event_id, false, 3, Utc::now())
        .await
        .expect("exhaust bounded completion delivery");
    let exhausted = fixture
        .database
        .query_one(
            "SELECT state,attempt_count,lease_until FROM casework_review_completion_outbox
             WHERE event_id=$1",
            &[&event_id],
        )
        .await
        .expect("exhausted completion delivery");
    assert_eq!(exhausted.get::<_, String>(0), "exhausted");
    assert_eq!(exhausted.get::<_, i32>(1), 3);
    assert!(exhausted
        .get::<_, Option<chrono::DateTime<Utc>>>(2)
        .is_none());

    let now = Utc::now();
    fixture
        .database
        .execute(
            "UPDATE casework_review_results
             SET completed_at=$2,available_until=$3 WHERE request_id=$1",
            &[
                &first.accepted.request_id,
                &(now - TimeDelta::days(2)),
                &(now - TimeDelta::days(1)),
            ],
        )
        .await
        .expect("expire result");
    fixture
        .database
        .execute(
            "UPDATE casework_review_terminal_events
             SET completed_at=$2,retained_until=$3 WHERE request_id=$1",
            &[
                &first.accepted.request_id,
                &(now - TimeDelta::days(2)),
                &(now - TimeDelta::days(1)),
            ],
        )
        .await
        .expect("expire terminal event");
    fixture
        .database
        .execute(
            "UPDATE casework_review_completion_outbox
             SET next_attempt_at=$2,retained_until=$3 WHERE request_id=$1",
            &[
                &first.accepted.request_id,
                &(now - TimeDelta::days(2)),
                &(now - TimeDelta::days(1)),
            ],
        )
        .await
        .expect("expire completion outbox");
    fixture
        .database
        .execute(
            "UPDATE casework_review_requests
             SET terminal_at=$2,result_available_until=$3,
                 context_strategy='source',
                 context=jsonb_build_object('reference','breg:registry:record:expired:1')
             WHERE request_id=$1",
            &[
                &first.accepted.request_id,
                &(now - TimeDelta::days(2)),
                &(now - TimeDelta::days(1)),
            ],
        )
        .await
        .expect("expire request result");
    let exponent_values = vec![1e100_f64; 400];
    assert!(serde_json::to_vec(&exponent_values).unwrap().len() < 32_768);
    fixture
        .database
        .execute(
            "UPDATE casework_review_results
                SET result=jsonb_set(result,'{numericExpansionProbe}',$2::jsonb)
              WHERE request_id=$1",
            &[&first.accepted.request_id, &json!(exponent_values)],
        )
        .await
        .expect("store bounded result whose PostgreSQL numeric rendering exceeds 32 KiB");
    let stored_result_bytes: i32 = fixture
        .database
        .query_one(
            "SELECT octet_length(result::text) FROM casework_review_results WHERE request_id=$1",
            &[&first.accepted.request_id],
        )
        .await
        .expect("measure PostgreSQL result representation")
        .get(0);
    assert!(stored_result_bytes > 32_768);
    fixture
        .service_v1
        .erase_expired_reviews()
        .await
        .expect("erase expired review payloads");
    assert!(matches!(
        fixture
            .service_v1
            .review_result(&fixture.producer, first.accepted.request_id)
            .await,
        Ok(ReviewResultRead::Expired)
    ));
    let retained_recovery = fixture
        .service_v1
        .create_review_request(
            &fixture.producer,
            create.clone(),
            "recover-after-result-expiry",
        )
        .await
        .expect("recover retained creation after result expiry");
    assert!(retained_recovery.recovered);
    assert_eq!(
        retained_recovery.accepted.request_id,
        first.accepted.request_id
    );
    fixture
        .database
        .execute(
            "UPDATE casework_review_submission_reservations
             SET recovery_deadline=$2 WHERE request_id=$1",
            &[&first.accepted.request_id, &(now - TimeDelta::seconds(1))],
        )
        .await
        .expect("expire only the creation recovery window");
    assert!(matches!(
        fixture
            .service_v1
            .create_review_request(&fixture.producer, create.clone(), "recover-after-deadline",)
            .await,
        Err(ReviewRuntimeError::ResultExpired)
    ));
    assert_eq!(
        count_for_request(
            &fixture,
            "casework_review_terminal_events",
            first.accepted.request_id,
        )
        .await,
        0
    );
    let redacted_context: serde_json::Value = fixture
        .database
        .query_one(
            "SELECT context FROM casework_review_requests WHERE request_id=$1",
            &[&first.accepted.request_id],
        )
        .await
        .expect("retained accountability tombstone")
        .get(0);
    assert_eq!(redacted_context, json!({}));
    assert!(
        count_for_request(
            &fixture,
            "casework_review_accountability",
            first.accepted.request_id,
        )
        .await
            > 0
    );

    fixture
        .database
        .execute(
            "UPDATE casework_review_requests
             SET accountability_retained_until=$2 WHERE request_id=$1",
            &[&first.accepted.request_id, &(now - TimeDelta::seconds(1))],
        )
        .await
        .expect("expire accountability tombstone");
    fixture
        .database
        .execute(
            "UPDATE casework_review_accountability
             SET occurred_at=$2,retained_until=$3 WHERE request_id=$1",
            &[
                &first.accepted.request_id,
                &(now - TimeDelta::days(2)),
                &(now - TimeDelta::days(1)),
            ],
        )
        .await
        .expect("expire protected accountability");
    fixture
        .database
        .execute(
            "UPDATE casework_review_submission_reservations
             SET retained_until=$2,recovery_deadline=$2 WHERE request_id=$1",
            &[&first.accepted.request_id, &(now - TimeDelta::seconds(1))],
        )
        .await
        .expect("expire submission tombstone");
    fixture
        .service_v1
        .erase_expired_reviews()
        .await
        .expect("erase expired accountability state");
    assert_eq!(
        count_for_request(
            &fixture,
            "casework_review_clock_occurrences",
            first.accepted.request_id,
        )
        .await,
        0
    );
    assert_eq!(
        count_for_request(
            &fixture,
            "casework_review_requests",
            first.accepted.request_id,
        )
        .await,
        0
    );
}

#[tokio::test]
async fn accountability_read_requires_live_retention_and_a_committed_audit() {
    let fixture = fixture().await;
    let project = answer_project(false);
    project.check().expect("accountability test project");
    let service = CaseworkService::new(
        fixture.store.clone(),
        project,
        Vec::<Arc<dyn SourceAdapter>>::new(),
    )
    .expect("accountability test service");
    let mut answer_request = request("accountability-record", "accountability-ref");
    answer_request.kind = "registry-answer".to_owned();
    let created = service
        .create_review_request(&fixture.producer, answer_request, "create-accountability")
        .await
        .expect("create accountability review");
    let task = task_id(&fixture, created.accepted.request_id, 0).await;
    service
        .claim_review_task(
            &fixture.reviewer_a,
            task,
            None,
            "",
            1,
            "claim-accountability",
        )
        .await
        .expect("claim accountability review");
    service
        .decide_review_task(
            &fixture.reviewer_a,
            task,
            ReviewTaskDecisionRequest {
                decision: ReviewerDecisionKind::Answer {
                    outcome: "found".to_owned(),
                    reason: Some("private accountability reason".to_owned()),
                    result: Some(json!({"correction": "accountable answer"})),
                },
            },
            None,
            "",
            2,
            "decide-accountability",
        )
        .await
        .expect("decide accountability review");
    let accountability_event: Uuid = fixture
        .database
        .query_one(
            "SELECT event_id FROM casework_review_accountability WHERE task_id=$1",
            &[&task],
        )
        .await
        .expect("accountability event")
        .get(0);

    let accountability = service
        .review_accountability(&fixture.supervisor, accountability_event)
        .await
        .expect("audited accountability read");
    assert_eq!(accountability.actor, fixture.reviewer_a.principal);
    assert_eq!(
        accountability.private_reason.as_deref(),
        Some("private accountability reason")
    );
    let read_audit: serde_json::Value = fixture
        .database
        .query_one(
            "SELECT audit_record FROM casework_audit_outbox
             WHERE audit_record->>'event'='casework.review_accountability_read'
               AND audit_record->>'accountabilityEventId'=$1",
            &[&accountability_event.to_string()],
        )
        .await
        .expect("committed accountability read audit")
        .get(0);
    assert_eq!(
        read_audit["actor"]["subject"],
        fixture.supervisor.principal.subject
    );
    assert_eq!(read_audit["profileId"], fixture.supervisor.profile_id);

    fixture
        .database
        .batch_execute(
            "CREATE FUNCTION reject_accountability_read_audit() RETURNS trigger
             LANGUAGE plpgsql AS $$
             BEGIN
               IF NEW.audit_record->>'event'='casework.review_accountability_read' THEN
                 RAISE EXCEPTION 'accountability audit unavailable';
               END IF;
               RETURN NEW;
             END;
             $$;
             CREATE TRIGGER reject_accountability_read_audit
             BEFORE INSERT ON casework_audit_outbox
             FOR EACH ROW EXECUTE FUNCTION reject_accountability_read_audit();",
        )
        .await
        .expect("install accountability audit failure");
    assert!(matches!(
        service
            .review_accountability(&fixture.supervisor, accountability_event)
            .await,
        Err(ReviewRuntimeError::Store(_))
    ));
    let committed_reads: i64 = fixture
        .database
        .query_one(
            "SELECT count(*) FROM casework_audit_outbox
             WHERE audit_record->>'event'='casework.review_accountability_read'
               AND audit_record->>'accountabilityEventId'=$1",
            &[&accountability_event.to_string()],
        )
        .await
        .expect("count committed accountability reads")
        .get(0);
    assert_eq!(committed_reads, 1);
    fixture
        .database
        .batch_execute(
            "DROP TRIGGER reject_accountability_read_audit ON casework_audit_outbox;
             DROP FUNCTION reject_accountability_read_audit();",
        )
        .await
        .expect("remove accountability audit failure");

    let now = Utc::now();
    fixture
        .database
        .execute(
            "UPDATE casework_review_accountability
             SET occurred_at=$2,retained_until=$3 WHERE event_id=$1",
            &[
                &accountability_event,
                &(now - TimeDelta::days(2)),
                &(now - TimeDelta::days(1)),
            ],
        )
        .await
        .expect("expire accountability record");
    assert!(matches!(
        service
            .review_accountability(&fixture.supervisor, accountability_event)
            .await,
        Err(ReviewRuntimeError::NotFound)
    ));
    let reads_after_expiry: i64 = fixture
        .database
        .query_one(
            "SELECT count(*) FROM casework_audit_outbox
             WHERE audit_record->>'event'='casework.review_accountability_read'
               AND audit_record->>'accountabilityEventId'=$1",
            &[&accountability_event.to_string()],
        )
        .await
        .expect("count accountability reads after expiry")
        .get(0);
    assert_eq!(reads_after_expiry, 1);
}

#[tokio::test]
async fn standalone_structured_answers_support_polling_and_completion_modes() {
    let fixture = fixture().await;
    for (completion, subject) in [(false, "answer-poll"), (true, "answer-completion")] {
        let project = answer_project(completion);
        project.check().expect("answer project");
        let service = CaseworkService::new(
            fixture.store.clone(),
            project,
            Vec::<Arc<dyn SourceAdapter>>::new(),
        )
        .expect("answer service");
        let mut answer_request = request(subject, &format!("producer-ref-{subject}"));
        answer_request.kind = "registry-answer".to_owned();
        let created = service
            .create_review_request(
                &fixture.producer,
                answer_request,
                &format!("create-{subject}"),
            )
            .await
            .expect("create standalone answer");
        let task = task_id(&fixture, created.accepted.request_id, 0).await;
        service
            .claim_review_task(
                &fixture.reviewer_a,
                task,
                None,
                "",
                1,
                &format!("claim-{subject}"),
            )
            .await
            .expect("claim standalone answer");
        service
            .decide_review_task(
                &fixture.reviewer_a,
                task,
                ReviewTaskDecisionRequest {
                    decision: ReviewerDecisionKind::Answer {
                        outcome: "found".to_owned(),
                        reason: None,
                        result: Some(json!({"correction":format!("answer for {subject}")})),
                    },
                },
                None,
                "",
                2,
                &format!("answer-{subject}"),
            )
            .await
            .expect("settle standalone answer");
        let result = service
            .review_result(&fixture.producer, created.accepted.request_id)
            .await
            .expect("poll standalone answer");
        assert!(matches!(
            result,
            ReviewResultRead::Available(result)
                if result.status == ReviewResultStatus::Answered
                    && result.result == Some(json!({"correction":format!("answer for {subject}")}))
        ));
        assert_terminal_atomic(&fixture, created.accepted.request_id, i64::from(completion)).await;
    }
}

#[tokio::test]
async fn rejected_cancelled_and_superseded_results_commit_atomically() {
    let fixture = fixture().await;

    let rejected = fixture
        .service_v1
        .create_review_request(
            &fixture.producer,
            request("terminal-rejected", "terminal-rejected"),
            "create-terminal-rejected",
        )
        .await
        .expect("create rejected review");
    let rejected_task = task_id(&fixture, rejected.accepted.request_id, 0).await;
    fixture
        .service_v1
        .claim_review_task(
            &fixture.reviewer_a,
            rejected_task,
            None,
            "",
            1,
            "claim-terminal-rejected",
        )
        .await
        .expect("claim rejected review");
    fixture
        .service_v1
        .decide_review_task(
            &fixture.reviewer_a,
            rejected_task,
            ReviewTaskDecisionRequest {
                decision: ReviewerDecisionKind::Reject {
                    outcome: "incorrect".to_owned(),
                    reason: Some("Incorrect record".to_owned()),
                    result: Some(json!({"correction":"Replace the record"})),
                },
            },
            None,
            "",
            2,
            "reject-terminal",
        )
        .await
        .expect("settle rejected review");
    assert_terminal_atomic(&fixture, rejected.accepted.request_id, 1).await;

    let cancelled_request = request("terminal-cancelled", "terminal-cancelled");
    let cancelled = fixture
        .service_v1
        .create_review_request(
            &fixture.producer,
            cancelled_request.clone(),
            "create-terminal-cancelled",
        )
        .await
        .expect("create cancelled review");
    fixture
        .service_v1
        .cancel_review_request(
            &fixture.producer,
            cancelled.accepted.request_id,
            registry_casework_core::ReviewCancelRequest {
                subject: cancelled_request.subject,
                reason: "Requester withdrew".to_owned(),
            },
            "cancel-terminal",
        )
        .await
        .expect("cancel review");
    assert_terminal_atomic(&fixture, cancelled.accepted.request_id, 1).await;

    let first_request = request("terminal-superseded", "terminal-superseded-v1");
    let first = fixture
        .service_v1
        .create_review_request(
            &fixture.producer,
            first_request,
            "create-terminal-superseded-v1",
        )
        .await
        .expect("create first supersession round");
    let mut second_request = request("terminal-superseded", "terminal-superseded-v2");
    second_request.subject.version = "2".to_owned();
    second_request.subject.digest = ContentDigest::for_bytes(b"terminal-superseded-v2");
    fixture
        .service_v1
        .create_review_request(
            &fixture.producer,
            second_request,
            "create-terminal-superseded-v2",
        )
        .await
        .expect("create superseding round");
    let first_result = fixture
        .service_v1
        .review_result(&fixture.producer, first.accepted.request_id)
        .await
        .expect("read superseded result");
    assert!(matches!(
        first_result,
        ReviewResultRead::Available(result) if result.status == ReviewResultStatus::Superseded
    ));
    assert_terminal_atomic(&fixture, first.accepted.request_id, 1).await;
}

#[tokio::test]
async fn concurrent_round_creation_and_duplicate_vote_leave_one_current_state() {
    let fixture = fixture().await;
    let first_service = fixture.service_v1.clone();
    let second_service = fixture.service_v1.clone();
    let producer_a = fixture.producer.clone();
    let producer_b = fixture.producer.clone();
    let first_request = request("concurrent-round", "concurrent-round-v1");
    let mut second_request = request("concurrent-round", "concurrent-round-v2");
    second_request.subject.version = "2".to_owned();
    second_request.subject.digest = ContentDigest::for_bytes(b"concurrent-round-v2");
    let (first, second) = tokio::join!(
        first_service.create_review_request(
            &producer_a,
            first_request,
            "create-concurrent-round-v1",
        ),
        second_service.create_review_request(
            &producer_b,
            second_request,
            "create-concurrent-round-v2",
        )
    );
    let first = first.expect("create first concurrent round");
    let second = second.expect("create second concurrent round");
    assert_ne!(first.accepted.request_id, second.accepted.request_id);
    let lifecycles = fixture
        .database
        .query(
            "SELECT lifecycle,count(*)
             FROM casework_review_requests
             WHERE subject_id='concurrent-round'
             GROUP BY lifecycle ORDER BY lifecycle",
            &[],
        )
        .await
        .expect("read serialized concurrent rounds");
    assert_eq!(lifecycles.len(), 2);
    assert!(lifecycles
        .iter()
        .any(|row| row.get::<_, String>(0) == "reviewing" && row.get::<_, i64>(1) == 1));
    assert!(lifecycles
        .iter()
        .any(|row| row.get::<_, String>(0) == "superseded" && row.get::<_, i64>(1) == 1));

    let answer_service = CaseworkService::new(
        fixture.store.clone(),
        answer_project(false),
        Vec::<Arc<dyn SourceAdapter>>::new(),
    )
    .expect("answer service");
    let mut answer_request = request("duplicate-vote", "duplicate-vote");
    answer_request.kind = "registry-answer".to_owned();
    let answer = answer_service
        .create_review_request(&fixture.producer, answer_request, "create-duplicate-vote")
        .await
        .expect("create duplicate vote review");
    let task = task_id(&fixture, answer.accepted.request_id, 0).await;
    answer_service
        .claim_review_task(
            &fixture.reviewer_a,
            task,
            None,
            "",
            1,
            "claim-duplicate-vote",
        )
        .await
        .expect("claim duplicate vote review");
    let first_service = answer_service.clone();
    let second_service = answer_service.clone();
    let reviewer_a = fixture.reviewer_a.clone();
    let reviewer_b = fixture.reviewer_a.clone();
    let decision = || ReviewTaskDecisionRequest {
        decision: ReviewerDecisionKind::Answer {
            outcome: "found".to_owned(),
            reason: None,
            result: Some(json!({"correction":"single terminal answer"})),
        },
    };
    let (first_vote, second_vote) = tokio::join!(
        first_service.decide_review_task(
            &reviewer_a,
            task,
            decision(),
            None,
            "",
            2,
            "duplicate-vote-a",
        ),
        second_service.decide_review_task(
            &reviewer_b,
            task,
            decision(),
            None,
            "",
            2,
            "duplicate-vote-b",
        )
    );
    assert_eq!(
        usize::from(first_vote.is_ok()) + usize::from(second_vote.is_ok()),
        1
    );
    let failure = first_vote
        .err()
        .or_else(|| second_vote.err())
        .expect("one refusal");
    assert!(matches!(
        failure,
        ReviewRuntimeError::NotFound
            | ReviewRuntimeError::RevisionConflict
            | ReviewRuntimeError::TaskNotHeld
    ));
    assert_eq!(
        count_for_request(
            &fixture,
            "casework_review_decisions",
            answer.accepted.request_id,
        )
        .await,
        1
    );
    assert_terminal_atomic(&fixture, answer.accepted.request_id, 0).await;
}

#[tokio::test]
async fn prior_stage_identity_and_invalid_structured_result_emit_nothing() {
    let fixture = fixture().await;
    let first = fixture
        .service_v1
        .create_review_request(
            &fixture.producer,
            request("record-2", "producer-ref-2"),
            "create-record-2",
        )
        .await
        .expect("create identity review");
    let primary = task_id(&fixture, first.accepted.request_id, 0).await;
    fixture
        .service_v1
        .claim_review_task(
            &fixture.reviewer_a,
            primary,
            None,
            "",
            1,
            "claim-identity-primary",
        )
        .await
        .expect("claim primary");
    fixture
        .service_v1
        .decide_review_task(
            &fixture.reviewer_a,
            primary,
            ReviewTaskDecisionRequest {
                decision: ReviewerDecisionKind::Approve,
            },
            None,
            "",
            2,
            "decide-identity-primary",
        )
        .await
        .expect("approve primary");
    let secondary = task_id(&fixture, first.accepted.request_id, 1).await;
    assert!(matches!(
        fixture
            .service_v1
            .claim_review_task(
                &fixture.reviewer_a,
                secondary,
                None,
                "",
                1,
                "claim-excluded-secondary",
            )
            .await,
        Err(ReviewRuntimeError::Forbidden)
    ));
    assert_eq!(
        count_for_request(
            &fixture,
            "casework_review_terminal_events",
            first.accepted.request_id,
        )
        .await,
        0
    );

    let correction = fixture
        .service_v1
        .create_review_request(
            &fixture.producer,
            request("record-3", "producer-ref-3"),
            "create-record-3",
        )
        .await
        .expect("create correction review");
    let correction_task = task_id(&fixture, correction.accepted.request_id, 0).await;
    fixture
        .service_v1
        .claim_review_task(
            &fixture.reviewer_b,
            correction_task,
            None,
            "",
            1,
            "claim-correction",
        )
        .await
        .expect("claim correction review");
    assert!(matches!(
        fixture
            .service_v1
            .decide_review_task(
                &fixture.reviewer_b,
                correction_task,
                ReviewTaskDecisionRequest {
                    decision: ReviewerDecisionKind::Reject {
                        outcome: "incorrect".to_owned(),
                        reason: Some("The record needs a correction".to_owned()),
                        result: None,
                    },
                },
                None,
                "",
                2,
                "invalid-correction",
            )
            .await,
        Err(ReviewRuntimeError::Invalid)
    ));
    for table in [
        "casework_review_decisions",
        "casework_review_results",
        "casework_review_terminal_events",
        "casework_review_completion_outbox",
    ] {
        assert_eq!(
            count_for_request(&fixture, table, correction.accepted.request_id).await,
            0,
            "{table} must remain empty after a rejected transaction"
        );
    }
}

#[tokio::test]
async fn claim_and_decide_require_current_exact_queue_membership() {
    let fixture = fixture().await;
    let created = fixture
        .service_v1
        .create_review_request(
            &fixture.producer,
            request("record-membership", "producer-ref-membership"),
            "create-membership",
        )
        .await
        .expect("create membership review");
    let task = task_id(&fixture, created.accepted.request_id, 0).await;
    let same_profile_nonmember = actor("not-a-member", CaseworkRole::Staff, "staff");
    assert!(matches!(
        fixture
            .service_v1
            .claim_review_task(
                &same_profile_nonmember,
                task,
                None,
                "",
                1,
                "nonmember-claim",
            )
            .await,
        Err(ReviewRuntimeError::Forbidden)
    ));

    let assigned = fixture
        .service_v1
        .assign_review_task(
            &fixture.supervisor,
            task,
            None,
            "",
            1,
            AssignmentRequest {
                assignee: fixture.reviewer_a.principal.clone(),
                reason: Some("current member".to_owned()),
            },
            "membership-assignment",
        )
        .await
        .expect("assign current member");
    let delegated = fixture
        .service_v1
        .delegate_review_task(
            &fixture.reviewer_a,
            task,
            None,
            "",
            assigned.revision,
            DelegateRequest {
                delegate: fixture.reviewer_b.principal.clone(),
                reason: Some("membership handoff".to_owned()),
            },
            "membership-delegation",
        )
        .await
        .expect("delegate to current member");
    fixture
        .database
        .execute(
            "DELETE FROM casework_memberships
             WHERE team_id='review-team' AND issuer=$1 AND subject=$2 AND membership_kind='staff'",
            &[
                &fixture.reviewer_b.principal.issuer,
                &fixture.reviewer_b.principal.subject,
            ],
        )
        .await
        .expect("remove delegated holder membership");
    assert!(matches!(
        fixture
            .service_v1
            .decide_review_task(
                &fixture.reviewer_b,
                task,
                ReviewTaskDecisionRequest {
                    decision: ReviewerDecisionKind::Approve,
                },
                None,
                "",
                delegated.revision,
                "removed-holder-decision",
            )
            .await,
        Err(ReviewRuntimeError::Forbidden)
    ));
    assert_eq!(
        count_for_request(
            &fixture,
            "casework_review_decisions",
            created.accepted.request_id,
        )
        .await,
        0
    );
}

#[tokio::test]
async fn source_context_task_disclosure_requires_a_current_caller_source_read() {
    let fixture = fixture().await;
    let mut source_request = request("record-source-visible", "producer-ref-source-visible");
    source_request.context = ReviewContext::Source {
        binding: SourceContextBinding {
            reference: "registry:record:record-source-visible".to_owned(),
        },
    };
    let created = fixture
        .service_v2
        .create_review_request(&fixture.producer, source_request, "create-source-visible")
        .await
        .expect("create source-context review");
    let task = task_id(&fixture, created.accepted.request_id, 0).await;

    assert!(matches!(
        fixture
            .service_v2
            .review_tasks(&fixture.reviewer_a, None, "human-bearer", None, None, 10)
            .await,
        Err(ReviewRuntimeError::SourceProfileRequired)
    ));

    let visible = fixture
        .service_v2
        .review_tasks(
            &fixture.reviewer_a,
            Some("staff"),
            "human-bearer",
            None,
            None,
            10,
        )
        .await
        .expect("current caller source read");
    assert_eq!(visible.items.len(), 1);
    assert_eq!(visible.items[0].task_id, task);
    assert_eq!(
        fixture
            .service_v2
            .review_task(&fixture.reviewer_a, task, Some("staff"), "human-bearer")
            .await
            .expect("read source-context task")
            .task_id,
        task
    );

    fixture.source_revoked.store(true, Ordering::SeqCst);
    let concealed = fixture
        .service_v2
        .review_tasks(
            &fixture.reviewer_a,
            Some("staff"),
            "human-bearer",
            None,
            None,
            10,
        )
        .await
        .expect("revoked source visibility conceals list item");
    assert!(concealed.items.is_empty());
    assert!(matches!(
        fixture
            .service_v2
            .review_task(&fixture.reviewer_a, task, Some("staff"), "human-bearer")
            .await,
        Err(ReviewRuntimeError::NotFound)
    ));
}

#[tokio::test]
async fn subject_clock_pauses_and_continues_across_review_rounds() {
    let fixture = fixture().await;
    let first = fixture
        .service_v1
        .create_review_request(
            &fixture.producer,
            request("record-clock", "producer-ref-clock-1"),
            "create-clock-1",
        )
        .await
        .expect("create first clock round");
    let initial = fixture
        .service_v1
        .review_clocks(&fixture.producer, first.accepted.request_id)
        .await
        .expect("read initial review clocks");
    assert_eq!(initial.len(), 1);
    assert_eq!(initial[0].state, ReviewClockState::Running);
    let occurrence_id = initial[0].clock_occurrence_id;
    let anchor = initial[0].anchor_at;

    let task = task_id(&fixture, first.accepted.request_id, 0).await;
    fixture
        .service_v1
        .claim_review_task(&fixture.reviewer_a, task, None, "", 1, "claim-clock")
        .await
        .expect("claim first clock round");
    fixture
        .service_v1
        .decide_review_task(
            &fixture.reviewer_a,
            task,
            ReviewTaskDecisionRequest {
                decision: ReviewerDecisionKind::ChangesRequested {
                    outcome: "needs-correction".to_owned(),
                    reason: Some("Please correct the record".to_owned()),
                    result: Some(json!({"correction":"Update the legal name"})),
                },
            },
            None,
            "",
            2,
            "changes-clock",
        )
        .await
        .expect("request changes for first round");
    let paused = fixture
        .service_v1
        .review_clocks(&fixture.producer, first.accepted.request_id)
        .await
        .expect("read paused subject clock");
    assert_eq!(paused[0].state, ReviewClockState::Paused);
    assert_eq!(paused[0].clock_occurrence_id, occurrence_id);
    assert_terminal_atomic(&fixture, first.accepted.request_id, 1).await;

    let mut next_request = request("record-clock", "producer-ref-clock-2");
    next_request.subject.version = "2".to_owned();
    next_request.subject.digest = ContentDigest::for_bytes(b"record-clock-v2");
    let second = fixture
        .service_v1
        .create_review_request(&fixture.producer, next_request, "create-clock-2")
        .await
        .expect("create corrected clock round");
    let resumed = fixture
        .service_v1
        .review_clocks(&fixture.producer, second.accepted.request_id)
        .await
        .expect("read resumed subject clock");
    assert_eq!(resumed.len(), 1);
    assert_eq!(resumed[0].state, ReviewClockState::Running);
    assert_eq!(resumed[0].clock_occurrence_id, occurrence_id);
    assert_eq!(resumed[0].anchor_at, anchor);
    assert!(resumed[0].due_at >= initial[0].due_at);
}

#[tokio::test]
async fn review_activity_clock_recovers_after_holiday_publication_and_applies_effects_once() {
    let fixture = fixture().await;
    fixture
        .database
        .execute(
            "INSERT INTO casework_queue_service(queue_id,team_id,revision)
             VALUES('overdue-review','review-team',1)",
            &[],
        )
        .await
        .expect("serve overdue review queue");
    let project = activity_clock_project();
    project.check().expect("activity clock project");
    let service = CaseworkService::new(
        fixture.store.clone(),
        project,
        Vec::<Arc<dyn SourceAdapter>>::new(),
    )
    .expect("activity clock service");
    let created = service
        .create_review_request(
            &fixture.producer,
            request("record-activity-clock", "producer-ref-activity-clock"),
            "create-activity-clock",
        )
        .await
        .expect("create activity-clock review");
    let task = task_id(&fixture, created.accepted.request_id, 0).await;
    service
        .claim_review_task(
            &fixture.reviewer_a,
            task,
            None,
            "",
            1,
            "claim-activity-clock",
        )
        .await
        .expect("claim activity-clock task");
    let occurrence = fixture
        .database
        .query_one(
            "SELECT clock_occurrence_id,state
             FROM casework_review_clock_occurrences WHERE task_id=$1",
            &[&task],
        )
        .await
        .expect("activity clock occurrence");
    let occurrence_id: Uuid = occurrence.get(0);
    assert_eq!(occurrence.get::<_, String>(1), "source_facts_missing");
    fixture
        .database
        .execute(
            "UPDATE casework_review_clock_occurrences
             SET anchor_at='2020-01-06T09:00:00Z',updated_at='2020-01-06T09:00:00Z'
             WHERE clock_occurrence_id=$1",
            &[&occurrence_id],
        )
        .await
        .expect("place unresolved activity clock in the past");

    service
        .create_holiday_revision(
            &actor("admin", CaseworkRole::Administrator, "administrator"),
            &HolidaySetDocument {
                holiday_set: "office-holidays".to_owned(),
                revision: 1,
                dates: Vec::new(),
            },
            "publish-office-holidays",
        )
        .await
        .expect("publish holiday revision");
    assert_eq!(
        service
            .process_due_review_clocks(100)
            .await
            .expect("process recovered review clock"),
        2
    );

    let task_row = fixture
        .database
        .query_one(
            "SELECT queue_id,state,holder_issuer,revision
             FROM casework_review_tasks WHERE task_id=$1",
            &[&task],
        )
        .await
        .expect("reassigned review task");
    assert_eq!(task_row.get::<_, String>(0), "overdue-review");
    assert_eq!(task_row.get::<_, String>(1), "open");
    assert_eq!(task_row.get::<_, Option<String>>(2), None);
    assert_eq!(task_row.get::<_, i64>(3), 3);
    let clock_row = fixture
        .database
        .query_one(
            "SELECT state,next_action_at,holiday_document->>'revision'
             FROM casework_review_clock_occurrences WHERE clock_occurrence_id=$1",
            &[&occurrence_id],
        )
        .await
        .expect("processed review clock occurrence");
    assert_eq!(clock_row.get::<_, String>(0), "running");
    assert_eq!(clock_row.get::<_, Option<chrono::DateTime<Utc>>>(1), None);
    assert_eq!(clock_row.get::<_, String>(2), "1");
    assert_eq!(
        fixture
            .database
            .query_one(
                "SELECT count(*) FROM casework_review_clock_effects
                 WHERE clock_occurrence_id=$1",
                &[&occurrence_id],
            )
            .await
            .expect("count review clock effects")
            .get::<_, i64>(0),
        2
    );
    assert_eq!(
        fixture
            .database
            .query_one(
                "SELECT count(*) FROM casework_review_history
                 WHERE request_id=$1 AND kind IN ('clock_reminder','clock_step_applied')",
                &[&created.accepted.request_id],
            )
            .await
            .expect("count review clock history")
            .get::<_, i64>(0),
        2
    );
    assert_eq!(
        service
            .process_due_review_clocks(100)
            .await
            .expect("repeat review clock pass"),
        0
    );
}

#[tokio::test]
async fn source_review_clock_defers_effects_until_the_frozen_binding_is_current() {
    let fixture = fixture().await;
    fixture
        .database
        .execute(
            "INSERT INTO casework_queue_service(queue_id,team_id,revision)
             VALUES('overdue-review','review-team',1)",
            &[],
        )
        .await
        .expect("serve overdue review queue");
    let mut project = activity_clock_project();
    project.review_kinds[0].context_strategy = ReviewContextStrategy::Source;
    project.check().expect("source activity clock project");
    let service = CaseworkService::new(
        fixture.store.clone(),
        project,
        [Arc::new(ReviewSource {
            revoked: Arc::clone(&fixture.source_revoked),
            state: Arc::clone(&fixture.source_state),
        }) as Arc<dyn SourceAdapter>],
    )
    .expect("source activity clock service");
    let mut create = request("record-source-activity-clock", "source-clock-reference");
    create.context = ReviewContext::Source {
        binding: SourceContextBinding {
            reference: "breg:registry:record:record-source-activity-clock:1".to_owned(),
        },
    };
    let created = service
        .create_review_request(&fixture.producer, create, "create-source-activity-clock")
        .await
        .expect("create source activity-clock review");
    let task = task_id(&fixture, created.accepted.request_id, 0).await;
    service
        .claim_review_task(
            &fixture.reviewer_a,
            task,
            Some("staff"),
            "human-bearer",
            1,
            "claim-source-activity-clock",
        )
        .await
        .expect("claim source activity-clock task");
    service
        .create_holiday_revision(
            &actor("admin", CaseworkRole::Administrator, "administrator"),
            &HolidaySetDocument {
                holiday_set: "office-holidays".to_owned(),
                revision: 1,
                dates: Vec::new(),
            },
            "publish-source-clock-holidays",
        )
        .await
        .expect("publish source clock holiday revision");
    fixture
        .database
        .execute(
            "UPDATE casework_review_clock_occurrences
             SET anchor_at='2020-01-06T09:00:00Z',updated_at='2020-01-06T09:00:00Z'
             WHERE task_id=$1",
            &[&task],
        )
        .await
        .expect("place source activity clock in the past");

    fixture.source_revoked.store(true, Ordering::SeqCst);
    assert_eq!(
        service
            .process_due_review_clocks(100)
            .await
            .expect("defer stale source review clock"),
        0
    );
    let deferred_effects: i64 = fixture
        .database
        .query_one(
            "SELECT count(*) FROM casework_review_clock_effects e
              JOIN casework_review_clock_occurrences c USING(clock_occurrence_id)
             WHERE c.task_id=$1",
            &[&task],
        )
        .await
        .expect("count deferred source clock effects")
        .get(0);
    assert_eq!(deferred_effects, 0);

    fixture.source_revoked.store(false, Ordering::SeqCst);
    for state in [
        OccurrenceState::Cancelled,
        OccurrenceState::Completed,
        OccurrenceState::Superseded,
        OccurrenceState::Synchronizing,
    ] {
        *fixture.source_state.lock().expect("source state lock") = state;
        fixture
            .database
            .execute(
                "UPDATE casework_review_clock_occurrences
                 SET next_action_at='2020-01-06T09:00:00Z',updated_at='2020-01-06T09:00:00Z'
                 WHERE task_id=$1",
                &[&task],
            )
            .await
            .expect("make deferred source activity clock due");
        assert_eq!(
            service
                .process_due_review_clocks(100)
                .await
                .expect("defer inactive source review clock"),
            0
        );
    }

    *fixture.source_state.lock().expect("source state lock") = OccurrenceState::WaitingApplication;
    fixture
        .database
        .execute(
            "UPDATE casework_review_clock_occurrences
             SET next_action_at='2020-01-06T09:00:00Z',updated_at='2020-01-06T09:00:00Z'
             WHERE task_id=$1",
            &[&task],
        )
        .await
        .expect("make current source activity clock due");
    assert_eq!(
        service
            .process_due_review_clocks(100)
            .await
            .expect("apply current source review clock"),
        2
    );
}

#[tokio::test]
async fn later_stage_activity_clock_uses_the_current_requests_pinned_definition() {
    let fixture = fixture().await;
    fixture
        .database
        .execute(
            "INSERT INTO casework_queue_service(queue_id,team_id,revision)
             VALUES('overdue-review','review-team',1)",
            &[],
        )
        .await
        .expect("serve overdue review queue");
    let mut stage_project = project("clock-stages");
    let stages = stage_project.review_kinds.remove(0).stages;
    let mut old_project = activity_clock_project();
    old_project.review_kinds[0].stages.clone_from(&stages);
    old_project.check().expect("old activity clock project");
    let old_service = CaseworkService::new(
        fixture.store.clone(),
        old_project,
        Vec::<Arc<dyn SourceAdapter>>::new(),
    )
    .expect("old activity clock service");
    old_service
        .create_review_request(
            &fixture.producer,
            request("record-clock-definition", "old-clock-definition"),
            "create-old-clock-definition",
        )
        .await
        .expect("create old clock definition review");

    let mut current_project = activity_clock_project();
    current_project.casework.version = "activity-clock-2".to_owned();
    current_project.review_kinds[0].version = "activity-clock-2".to_owned();
    current_project.review_kinds[0].stages = stages;
    let ClockPolicy::Activity { due_time, .. } = &mut current_project.clocks[0] else {
        panic!("activity clock fixture changed shape");
    };
    *due_time = "18:00".to_owned();
    current_project
        .check()
        .expect("current activity clock project");
    let current_service = CaseworkService::new(
        fixture.store.clone(),
        current_project,
        Vec::<Arc<dyn SourceAdapter>>::new(),
    )
    .expect("current activity clock service");
    let mut current_request = request("record-clock-definition", "current-clock-definition");
    current_request.subject.version = "2".to_owned();
    current_request.subject.digest = ContentDigest::for_bytes(b"record-clock-definition-v2");
    let current = current_service
        .create_review_request(
            &fixture.producer,
            current_request,
            "create-current-clock-definition",
        )
        .await
        .expect("create current clock definition review");
    let first_task = task_id(&fixture, current.accepted.request_id, 0).await;
    current_service
        .claim_review_task(
            &fixture.reviewer_a,
            first_task,
            None,
            "",
            1,
            "claim-current-clock-definition",
        )
        .await
        .expect("claim current first stage");
    assert!(matches!(
        current_service
            .decide_review_task(
                &fixture.reviewer_a,
                first_task,
                ReviewTaskDecisionRequest {
                    decision: ReviewerDecisionKind::Approve,
                },
                None,
                "",
                2,
                "advance-current-clock-definition",
            )
            .await,
        Ok(ReviewTransition::StageAdvanced { .. })
    ));
    let second_task = task_id(&fixture, current.accepted.request_id, 1).await;
    let due_time: String = fixture
        .database
        .query_one(
            "SELECT policy->'clock'->>'dueTime'
               FROM casework_review_clock_occurrences
              WHERE request_id=$1 AND task_id=$2",
            &[&current.accepted.request_id, &second_task],
        )
        .await
        .expect("current later-stage activity clock")
        .get(0);
    assert_eq!(due_time, "18:00");
}

#[tokio::test]
async fn review_task_coordination_preserves_exclusions_drafts_history_and_absence_cover() {
    let fixture = fixture().await;
    let created = fixture
        .service_v1
        .create_review_request(
            &fixture.producer,
            request("record-coordination", "producer-ref-coordination"),
            "create-coordination",
        )
        .await
        .expect("create coordinated review");
    let task = task_id(&fixture, created.accepted.request_id, 0).await;
    fixture
        .database
        .execute(
            "UPDATE casework_review_requests SET context='{}'::jsonb WHERE request_id=$1",
            &[&created.accepted.request_id],
        )
        .await
        .expect("represent a valid live empty submitted snapshot");
    let listed = fixture
        .service_v1
        .review_tasks(&fixture.reviewer_a, None, "", Some("review"), None, 10)
        .await
        .expect("list review tasks");
    assert!(listed.items.iter().any(|item| item.task_id == task));
    assert_eq!(
        fixture
            .service_v1
            .review_task(&fixture.reviewer_a, task, None, "")
            .await
            .expect("read submitted-context task")
            .task_id,
        task
    );
    let context = fixture
        .service_v1
        .review_task_context(&fixture.reviewer_a, task, None, "")
        .await
        .expect("read frozen submitted task context");
    assert_eq!(context.task_id, task);
    assert_eq!(context.request_id, created.accepted.request_id);
    assert_eq!(context.policy, created.accepted.policy);
    assert_eq!(context.requester_reference, "producer-ref-coordination");
    assert!(matches!(
        context.context,
        registry_casework_core::ReviewTaskContextData::Submitted { snapshot }
            if snapshot == json!({})
    ));

    let initiator = IssuerPrincipal {
        issuer: "https://issuer.test".to_owned(),
        subject: "initiator".to_owned(),
    };
    assert!(matches!(
        fixture
            .service_v1
            .assign_review_task(
                &fixture.supervisor,
                task,
                None,
                "",
                1,
                AssignmentRequest {
                    assignee: initiator,
                    reason: Some("nominate initiator".to_owned()),
                },
                "assign-initiator",
            )
            .await,
        Err(ReviewRuntimeError::Forbidden)
    ));
    let assigned = fixture
        .service_v1
        .assign_review_task(
            &fixture.supervisor,
            task,
            None,
            "",
            1,
            AssignmentRequest {
                assignee: fixture.reviewer_a.principal.clone(),
                reason: Some("primary nomination".to_owned()),
            },
            "assign-reviewer-a",
        )
        .await
        .expect("assign review task");
    assert!(matches!(
        assigned.state,
        ReviewerTaskState::Held { holder } if holder == fixture.reviewer_a.principal
    ));
    assert!(matches!(
        fixture
            .service_v1
            .delegate_review_task(
                &fixture.reviewer_a,
                task,
                None,
                "",
                assigned.revision,
                DelegateRequest {
                    delegate: IssuerPrincipal {
                        issuer: "https://issuer.test".to_owned(),
                        subject: "initiator".to_owned(),
                    },
                    reason: Some("excluded handoff".to_owned()),
                },
                "delegate-initiator",
            )
            .await,
        Err(ReviewRuntimeError::Forbidden)
    ));
    let delegated = fixture
        .service_v1
        .delegate_review_task(
            &fixture.reviewer_a,
            task,
            None,
            "",
            assigned.revision,
            DelegateRequest {
                delegate: fixture.reviewer_b.principal.clone(),
                reason: Some("handoff".to_owned()),
            },
            "delegate-reviewer-b",
        )
        .await
        .expect("delegate review task");
    assert!(matches!(
        delegated.state,
        ReviewerTaskState::Held { holder } if holder == fixture.reviewer_b.principal
    ));

    let draft = fixture
        .service_v1
        .save_review_task_draft(
            &fixture.reviewer_b,
            task,
            None,
            "",
            delegated.revision,
            ReviewTaskDraftInput {
                body: json!({"private": "working notes"}),
            },
            "save-private-draft",
        )
        .await
        .expect("save private draft");
    assert_eq!(draft.body, json!({"private": "working notes"}));
    assert_eq!(
        fixture
            .service_v1
            .review_task_draft(&fixture.reviewer_b, task, None, "")
            .await
            .expect("read private draft")
            .expect("draft exists"),
        draft
    );
    assert!(fixture
        .service_v1
        .review_task_draft(&fixture.reviewer_a, task, None, "")
        .await
        .expect("other reviewer draft lookup")
        .is_none());

    fixture
        .service_v1
        .add_review_note(
            &fixture.reviewer_b,
            created.accepted.request_id,
            ReviewNoteRequest {
                audience: ReviewHistoryAudience::Reviewers,
                note: "reviewer-only note".to_owned(),
            },
            "reviewer-note",
        )
        .await
        .expect("add reviewer note");
    fixture
        .service_v1
        .add_review_note(
            &fixture.producer,
            created.accepted.request_id,
            ReviewNoteRequest {
                audience: ReviewHistoryAudience::Requester,
                note: "requester-visible note".to_owned(),
            },
            "requester-note",
        )
        .await
        .expect("add requester note");
    let requester_history = fixture
        .service_v1
        .review_history(&fixture.producer, created.accepted.request_id, None, 100)
        .await
        .expect("requester history");
    let requester_history_json =
        serde_json::to_string(&requester_history.items).expect("history JSON");
    assert!(requester_history_json.contains("requester-visible note"));
    assert!(!requester_history_json.contains("reviewer-only note"));
    assert!(!requester_history_json.contains("working notes"));

    let covered = fixture
        .service_v1
        .create_review_request(
            &fixture.producer,
            request("record-covered", "producer-ref-covered"),
            "create-covered",
        )
        .await
        .expect("create covered review");
    let covered_task = task_id(&fixture, covered.accepted.request_id, 0).await;
    let absence_id = Uuid::new_v4();
    fixture
        .database
        .execute(
            "INSERT INTO casework_absences(
                absence_id,person_issuer,person_subject,starts_at,ends_at,
                cover_issuer,cover_subject,revision)
             VALUES($1,$2,$3,$4,$5,$6,$7,1)",
            &[
                &absence_id,
                &fixture.reviewer_b.principal.issuer,
                &fixture.reviewer_b.principal.subject,
                &(Utc::now() - TimeDelta::hours(1)),
                &(Utc::now() + TimeDelta::hours(1)),
                &fixture.reviewer_a.principal.issuer,
                &fixture.reviewer_a.principal.subject,
            ],
        )
        .await
        .expect("record active absence");
    let assigned_cover = fixture
        .service_v1
        .assign_review_task(
            &fixture.supervisor,
            covered_task,
            None,
            "",
            1,
            AssignmentRequest {
                assignee: fixture.reviewer_b.principal.clone(),
                reason: Some("absence cover".to_owned()),
            },
            "assign-covered-review",
        )
        .await
        .expect("assign through active absence");
    assert!(matches!(
        assigned_cover.state,
        ReviewerTaskState::Held { holder } if holder == fixture.reviewer_a.principal
    ));
    let assignment_kind: String = fixture
        .database
        .query_one(
            "SELECT assignment_kind FROM casework_review_tasks WHERE task_id=$1",
            &[&covered_task],
        )
        .await
        .expect("covered task assignment")
        .get(0);
    assert_eq!(assignment_kind, "absence_cover");
    fixture
        .database
        .execute(
            "DELETE FROM casework_absences WHERE absence_id=$1",
            &[&absence_id],
        )
        .await
        .expect("end active absence");
    assert_eq!(
        fixture
            .service_v1
            .reconcile_review_absences(100)
            .await
            .expect("reconcile ended absence"),
        1
    );
    let restored = fixture
        .database
        .query_one(
            "SELECT holder_subject,assignment_kind FROM casework_review_tasks WHERE task_id=$1",
            &[&covered_task],
        )
        .await
        .expect("restored assignment");
    assert_eq!(restored.get::<_, String>(0), "reviewer-b");
    assert_eq!(restored.get::<_, String>(1), "nomination");
    let stale_scan_time = Utc::now() - TimeDelta::days(1);
    fixture
        .database
        .execute(
            "UPDATE casework_review_tasks SET updated_at=$2 WHERE task_id=$1",
            &[&covered_task, &stale_scan_time],
        )
        .await
        .expect("make unchanged assignment the oldest scan candidate");
    assert_eq!(
        fixture
            .service_v1
            .reconcile_review_absences(100)
            .await
            .expect("rotate unchanged absence candidate"),
        0
    );
    let rotated_at: chrono::DateTime<Utc> = fixture
        .database
        .query_one(
            "SELECT updated_at FROM casework_review_tasks WHERE task_id=$1",
            &[&covered_task],
        )
        .await
        .expect("read rotated absence candidate")
        .get(0);
    assert!(rotated_at > stale_scan_time);
}
