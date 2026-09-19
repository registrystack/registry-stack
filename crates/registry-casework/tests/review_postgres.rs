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
use chrono::{TimeDelta, Utc};
use registry_casework::{
    CaseworkService, DatabaseConfig, PostgresStore, ReviewResultRead, ReviewRuntimeError,
    ReviewTaskDecisionRequest,
};
use registry_casework_core::{
    AccessProfile, ActiveSubjectsPage, ActorContext, AssignmentRequest, AuthoritativeObservation,
    CallerSubjectView, CaseworkIdentity, CaseworkProject, CaseworkRole, ContentDigest,
    DelegateRequest, DiscoveryCursor, EphemeralCredential, EventRequest, ExecutePreparedRequest,
    HumanIdentity, InboxPolicy, IssuerPrincipal, PrepareActionRequest, PreparedSourceAttempt,
    QueuePolicy, ReviewCompletionDestinationPolicy, ReviewContext, ReviewContextStrategy,
    ReviewCreateRequest, ReviewHistoryAudience, ReviewKindPolicy, ReviewKindPurpose,
    ReviewNoteRequest, ReviewOutcomePolicy, ReviewOutcomeSettlement, ReviewProducerPolicy,
    ReviewRequestLifecycle, ReviewResultStatus, ReviewRetentionPolicy, ReviewStagePolicy,
    ReviewTaskDraftInput, ReviewTransition, ReviewerDecisionKind, ReviewerTaskState, SourceAdapter,
    SourceAdapterError, SourceBinding, SourceContextBinding, SourceReceipt, SubjectBinding,
    SubjectRef, TransitionHint,
};
use registry_platform_config::{SecretProvider, SecretResolver};
use serde_json::json;
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
}

#[derive(Clone)]
struct ReviewSource {
    revoked: Arc<AtomicBool>,
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
        kinds: Vec::new(),
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
        hosted_kinds: Vec::new(),
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
            result_schema: Some(json!({
                "type": "object",
                "additionalProperties": false,
                "required": ["correction"],
                "properties": {"correction": {"type": "string", "maxLength": 160}}
            })),
            outcomes: vec![ReviewOutcomePolicy {
                id: "incorrect".to_owned(),
                label: "Incorrect".to_owned(),
                settlement: ReviewOutcomeSettlement::Rejected,
                reason_required: true,
                result_required: true,
            }],
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
        clocks: Vec::new(),
        inbox: InboxPolicy::default(),
        task_templates: Vec::new(),
    }
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
    let separator = if base.contains('?') { '&' } else { '?' };
    let scoped_url = format!("{base}{separator}options=-csearch_path%3D{schema}");
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
             SET terminal_at=$2,result_available_until=$3 WHERE request_id=$1",
            &[
                &first.accepted.request_id,
                &(now - TimeDelta::days(2)),
                &(now - TimeDelta::days(1)),
            ],
        )
        .await
        .expect("expire request result");
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
    assert_eq!(
        count_for_request(
            &fixture,
            "casework_review_terminal_events",
            first.accepted.request_id,
        )
        .await,
        0
    );
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

    let without_source_credential = fixture
        .service_v2
        .review_tasks(&fixture.reviewer_a, None, "human-bearer", None, None, 10)
        .await
        .expect("missing source profile conceals source tasks");
    assert!(without_source_credential.items.is_empty());

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
            .review_task_draft(&fixture.reviewer_b, task)
            .await
            .expect("read private draft")
            .expect("draft exists"),
        draft
    );
    assert!(fixture
        .service_v1
        .review_task_draft(&fixture.reviewer_a, task)
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
}
