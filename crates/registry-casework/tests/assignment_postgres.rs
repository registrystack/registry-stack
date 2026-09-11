use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{TimeDelta, Utc};
use registry_casework::{CaseworkService, DatabaseConfig, PostgresStore, ServiceError, StoreError};
use registry_casework_core::{
    AbsenceInput, AccessProfile, ActiveSubjectsPage, ActorContext, AssignmentRequest,
    AuthoritativeObservation, BootstrapDirectoryRequest, CallerSubjectView, CaseloadApplyRequest,
    CaseloadItemOutcome, CaseloadItemSelection, CaseloadMoveRequest, CaseworkIdentity,
    CaseworkProject, CaseworkRole, DelegateRequest, DirectoryMember, DirectoryTargetPurpose,
    DirectoryTeamUpdateRequest, DiscoveryCursor, EphemeralCredential, EventRequest,
    ExecutePreparedRequest, HistoryKind, HostedCreateRequest, HostedHistoryKind, HostedKindPolicy,
    HostedOutcomePolicy, HostedRetentionPolicy, InboxPolicy, IssuerPrincipal, OccurrenceKind,
    OccurrenceState, OperationName, PageStatus, PrepareActionRequest, PreparedSourceAttempt,
    QueuePolicy, RecoveryEvidence, SourceAdapter, SourceAdapterError, SourceBinding, SourcePolicy,
    SourceReceipt, SourceRequestPolicy, StaffingDiagnostic, SubjectRef, TransitionHint,
    MAXIMUM_DIRECTORY_DISPLAY_NAME_BYTES, MAXIMUM_DIRECTORY_IDENTIFIER_BYTES,
    MAXIMUM_DIRECTORY_PRINCIPALS, MAXIMUM_DIRECTORY_PRINCIPAL_COMPONENT_BYTES,
};
use registry_platform_config::{SecretProvider, SecretResolver};
use serde_json::json;
use tokio_postgres::NoTls;
use uuid::Uuid;

const SOURCE_ID: &str = "source-a";
const SOURCE_KIND: &str = "request";
const QUEUE: &str = "review";
const GENERATION: &str = "generation-1";

#[derive(Clone, Copy)]
enum ReadMode {
    Visible,
    Concealed,
    Unavailable,
}

struct TestSource {
    reads: BTreeMap<String, ReadMode>,
}

#[async_trait]
impl SourceAdapter for TestSource {
    fn source_id(&self) -> &str {
        SOURCE_ID
    }

    fn binding_generation(&self) -> &str {
        GENERATION
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
        _source_profile_id: &str,
        _credential: EphemeralCredential<'_>,
    ) -> Result<CallerSubjectView, SourceAdapterError> {
        match self.reads.get(&subject.id).copied() {
            Some(ReadMode::Visible) => Ok(CallerSubjectView {
                display_reference: None,
                subject: subject.clone(),
                binding: binding(),
                disclosed: BTreeMap::from([("summary".to_owned(), json!("visible"))]),
                permitted_operations: Vec::new(),
            }),
            Some(ReadMode::Concealed) => Err(SourceAdapterError::Concealed),
            Some(ReadMode::Unavailable) => Err(SourceAdapterError::Unavailable),
            None => Err(SourceAdapterError::Invalid),
        }
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

struct Fixture {
    service: CaseworkService,
    store: PostgresStore,
    database: tokio_postgres::Client,
    scoped_url: String,
    requester: ActorContext,
    staff_a: ActorContext,
    staff_b: ActorContext,
    staff_c: ActorContext,
    supervisor: ActorContext,
}

fn principal(subject: &str) -> IssuerPrincipal {
    IssuerPrincipal {
        issuer: "https://issuer.test".to_owned(),
        subject: subject.to_owned(),
    }
}

fn member(principal: &IssuerPrincipal) -> DirectoryMember {
    principal.clone().into()
}

fn named_member(principal: &IssuerPrincipal, display_name: &str) -> DirectoryMember {
    DirectoryMember {
        issuer: principal.issuer.clone(),
        subject: principal.subject.clone(),
        display_name: Some(display_name.to_owned()),
    }
}

fn actor(subject: &str, role: CaseworkRole, profile_id: &str) -> ActorContext {
    ActorContext {
        principal: principal(subject),
        profile_id: profile_id.to_owned(),
        role,
    }
}

fn profile(id: &str, role: CaseworkRole, kinds: &[&str]) -> AccessProfile {
    AccessProfile {
        id: id.to_owned(),
        principal_claim: "sub".to_owned(),
        required_scopes: vec![format!("casework:{id}")],
        role,
        kinds: kinds.iter().map(|value| (*value).to_owned()).collect(),
    }
}

fn project() -> CaseworkProject {
    CaseworkProject {
        api_version: registry_casework_core::CASEWORK_API_VERSION.to_owned(),
        kind: registry_casework_core::CASEWORK_KIND.to_owned(),
        casework: CaseworkIdentity {
            id: "assignment-test".to_owned(),
            version: "1".to_owned(),
        },
        access_profiles: vec![
            profile("staff", CaseworkRole::Staff, &[]),
            profile("supervisor", CaseworkRole::Supervisor, &[]),
            profile("administrator", CaseworkRole::Administrator, &[]),
            profile("requester", CaseworkRole::Requester, &["task"]),
        ],
        queues: vec![QueuePolicy {
            id: QUEUE.to_owned(),
            label: "Review".to_owned(),
        }],
        sources: vec![SourcePolicy {
            id: SOURCE_ID.to_owned(),
            adapter: "test".to_owned(),
            description: "Assignment test source".to_owned(),
            requests: vec![SourceRequestPolicy {
                display_reference: None,
                entity: SOURCE_KIND.to_owned(),
                queue: QUEUE.to_owned(),
                projection: Vec::new(),
                routing: Vec::new(),
                clock: None,
                target: None,
            }],
        }],
        hosted_kinds: vec![HostedKindPolicy {
            id: "task".to_owned(),
            version: "1".to_owned(),
            queue: QUEUE.to_owned(),
            deciding_profiles: vec!["staff".to_owned()],
            retention: HostedRetentionPolicy {
                terminal_days: 30,
                accountability_days: 90,
            },
            display_schema: json!({
                "type":"object",
                "additionalProperties":false,
                "required":["summary"],
                "properties":{"summary":{"type":"string","maxLength":80}}
            }),
            outcomes: vec![HostedOutcomePolicy {
                id: "done".to_owned(),
                label: "Done".to_owned(),
                reason_required: false,
            }],
        }],
        calendars: Vec::new(),
        clocks: Vec::new(),
        inbox: InboxPolicy::default(),
    }
}

async fn fixture(reads: impl IntoIterator<Item = (Uuid, ReadMode)>) -> Fixture {
    let base = env::var("CASEWORK_ASSIGNMENT_TEST_DATABASE_URL")
        .expect("CASEWORK_ASSIGNMENT_TEST_DATABASE_URL is required");
    let schema = format!("assignment_{}", Uuid::new_v4().simple());
    let separator = if base.contains('?') { '&' } else { '?' };
    let scoped_url = format!("{base}{separator}options=-csearch_path%3D{schema}");
    let (admin, connection) = tokio_postgres::connect(&base, NoTls)
        .await
        .expect("connect assignment test database");
    tokio::spawn(async move { connection.await.expect("assignment admin connection") });
    admin
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .expect("create isolated assignment schema");
    let secret_name =
        format!("CASEWORK_ASSIGNMENT_SCHEMA_{}", Uuid::new_v4().simple()).to_ascii_uppercase();
    env::set_var(&secret_name, &scoped_url);
    let secrets = SecretResolver::new([SecretProvider::Environment], "/private/tmp")
        .expect("assignment test secret resolver");
    let config = DatabaseConfig {
        runtime_url_ref: format!("secret:env/{secret_name}"),
        migration_url_ref: format!("secret:env/{secret_name}"),
        trusted_root_certificate_ref: None,
        test_only_plaintext: true,
    };
    let migration = PostgresStore::connect_migration(&config, &secrets).expect("migration store");
    migration.migrate().await.expect("assignment migrations");
    let store = PostgresStore::connect_runtime(&config, &secrets).expect("runtime store");
    let administrator = actor(
        "administrator",
        CaseworkRole::Administrator,
        "administrator",
    );
    let staff_a = actor("staff-a", CaseworkRole::Staff, "staff");
    let staff_b = actor("staff-b", CaseworkRole::Staff, "staff");
    let staff_c = actor("staff-c", CaseworkRole::Staff, "staff");
    let supervisor = actor("supervisor", CaseworkRole::Supervisor, "supervisor");
    let source = Arc::new(TestSource {
        reads: reads
            .into_iter()
            .map(|(id, mode)| (id.to_string(), mode))
            .collect(),
    });
    let service =
        CaseworkService::new(store.clone(), project(), [source as Arc<dyn SourceAdapter>])
            .expect("assignment service");
    service
        .bootstrap_directory(
            &administrator,
            0,
            &BootstrapDirectoryRequest {
                team_id: "review-team".to_owned(),
                staff: vec![
                    staff_a.principal.clone(),
                    staff_b.principal.clone(),
                    staff_c.principal.clone(),
                ],
                supervisors: vec![supervisor.principal.clone()],
                queue_id: QUEUE.to_owned(),
            },
            "bootstrap",
        )
        .await
        .expect("bootstrap assignment directory");
    Fixture {
        service,
        store,
        database: connect_scoped(&scoped_url).await,
        scoped_url,
        requester: actor("requester", CaseworkRole::Requester, "requester"),
        staff_a,
        staff_b,
        staff_c,
        supervisor,
    }
}

#[tokio::test]
async fn directory_bootstrap_rejects_unconfigured_and_unbounded_memberships_before_mutation() {
    let fixture = fixture([]).await;
    let administrator = actor(
        "administrator",
        CaseworkRole::Administrator,
        "administrator",
    );
    assert_eq!(
        fixture
            .service
            .bootstrap_directory(
                &administrator,
                0,
                &BootstrapDirectoryRequest {
                    team_id: "review-team".to_owned(),
                    staff: vec![
                        fixture.staff_a.principal.clone(),
                        fixture.staff_b.principal.clone(),
                        fixture.staff_c.principal.clone(),
                    ],
                    supervisors: vec![fixture.supervisor.principal.clone()],
                    queue_id: QUEUE.to_owned(),
                },
                "bootstrap",
            )
            .await
            .expect("exact bootstrap replay"),
        1
    );
    let valid = BootstrapDirectoryRequest {
        team_id: "second-team".to_owned(),
        staff: vec![principal("second-staff")],
        supervisors: vec![principal("second-supervisor")],
        queue_id: QUEUE.to_owned(),
    };
    let invalid_requests = [
        BootstrapDirectoryRequest {
            queue_id: "unconfigured-queue".to_owned(),
            ..valid.clone()
        },
        BootstrapDirectoryRequest {
            team_id: "x".repeat(MAXIMUM_DIRECTORY_IDENTIFIER_BYTES + 1),
            ..valid.clone()
        },
        BootstrapDirectoryRequest {
            staff: vec![IssuerPrincipal {
                issuer: "x".repeat(MAXIMUM_DIRECTORY_PRINCIPAL_COMPONENT_BYTES + 1),
                subject: "bounded-subject".to_owned(),
            }],
            ..valid.clone()
        },
        BootstrapDirectoryRequest {
            staff: (0..=MAXIMUM_DIRECTORY_PRINCIPALS)
                .map(|index| principal(&format!("staff-{index}")))
                .collect(),
            ..valid
        },
    ];
    for (index, request) in invalid_requests.iter().enumerate() {
        assert!(matches!(
            fixture
                .service
                .bootstrap_directory(
                    &administrator,
                    1,
                    request,
                    &format!("invalid-bootstrap-{index}"),
                )
                .await,
            Err(ServiceError::Store(StoreError::Invalid))
        ));
    }

    let (revision, teams) = fixture
        .store
        .directory(&administrator)
        .await
        .expect("read unchanged directory");
    assert_eq!(revision, 1);
    assert_eq!(teams.len(), 1);
    assert_eq!(teams[0].id, "review-team");
}

#[tokio::test]
async fn directory_read_holds_one_revision_snapshot_through_all_content_reads() {
    let fixture = fixture([]).await;
    let administrator = actor(
        "administrator",
        CaseworkRole::Administrator,
        "administrator",
    );
    let mut blocker = connect_scoped(&fixture.scoped_url).await;
    let blocker_transaction = blocker.transaction().await.expect("blocker transaction");
    blocker_transaction
        .batch_execute("LOCK TABLE casework_memberships IN ACCESS EXCLUSIVE MODE")
        .await
        .expect("block directory membership read");

    let read_store = fixture.store.clone();
    let read_actor = administrator.clone();
    let directory_read = tokio::spawn(async move { read_store.directory(&read_actor).await });
    wait_for_blocked_query(
        &fixture.database,
        "SELECT issuer,subject,display_name FROM casework_memberships",
    )
    .await;

    let update_service = fixture.service.clone();
    let update_actor = administrator.clone();
    let staff_b = fixture.staff_b.principal.clone();
    let supervisor = fixture.supervisor.principal.clone();
    let directory_update = tokio::spawn(async move {
        update_service
            .update_directory_team(
                &update_actor,
                1,
                "review-team",
                &DirectoryTeamUpdateRequest {
                    staff: vec![member(&staff_b)],
                    supervisors: vec![member(&supervisor)],
                    served_queues: vec![QUEUE.to_owned()],
                },
                "concurrent-directory-update",
            )
            .await
    });
    wait_for_blocked_query(
        &fixture.database,
        "SELECT directory_revision FROM casework_meta WHERE singleton=true FOR UPDATE",
    )
    .await;

    blocker_transaction
        .commit()
        .await
        .expect("release membership read");
    let (revision, teams) = directory_read
        .await
        .expect("directory task")
        .expect("consistent directory snapshot");
    assert_eq!(revision, 1);
    assert_eq!(teams.len(), 1);
    assert_eq!(teams[0].members.len(), 3);
    assert_eq!(
        directory_update
            .await
            .expect("directory update task")
            .expect("directory update after reader"),
        2
    );
}

#[tokio::test]
async fn oversized_directory_update_rolls_back_every_effect() {
    let fixture = fixture([]).await;
    let administrator = actor(
        "administrator",
        CaseworkRole::Administrator,
        "administrator",
    );
    let people = large_directory_members(90);
    let accepted_revision = fixture
        .service
        .update_directory_team(
            &administrator,
            1,
            "large-a",
            &DirectoryTeamUpdateRequest {
                staff: people.clone(),
                supervisors: people.clone(),
                served_queues: Vec::new(),
            },
            "large-a",
        )
        .await
        .expect("directory below response byte limit");
    assert_eq!(accepted_revision, 2);
    let (revision, teams) = fixture
        .store
        .directory(&administrator)
        .await
        .expect("bounded accepted directory");
    let serialized =
        serde_json::to_vec(&registry_casework_core::DirectoryResponse { revision, teams })
            .expect("serialize accepted directory");
    assert!(serialized.len() <= 2 * 1024 * 1024);
    assert!(serialized.len() > 1024 * 1024);

    let event_count: i64 = fixture
        .database
        .query_one("SELECT count(*) FROM casework_directory_events", &[])
        .await
        .expect("count directory events")
        .get(0);
    let replay_count: i64 = fixture
        .database
        .query_one("SELECT count(*) FROM casework_idempotency", &[])
        .await
        .expect("count directory replays")
        .get(0);
    assert!(matches!(
        fixture
            .service
            .update_directory_team(
                &administrator,
                accepted_revision,
                "large-b",
                &DirectoryTeamUpdateRequest {
                    staff: people.clone(),
                    supervisors: people.clone(),
                    served_queues: Vec::new(),
                },
                "large-b",
            )
            .await,
        Err(ServiceError::Store(StoreError::Invalid))
    ));
    let bootstrap = BootstrapDirectoryRequest {
        team_id: "large-bootstrap".to_owned(),
        staff: people
            .iter()
            .map(|person| IssuerPrincipal {
                issuer: person.issuer.clone(),
                subject: person.subject.clone(),
            })
            .collect(),
        supervisors: people
            .iter()
            .map(|person| IssuerPrincipal {
                issuer: person.issuer.clone(),
                subject: person.subject.clone(),
            })
            .collect(),
        queue_id: "large-bootstrap-queue".to_owned(),
    };
    assert!(matches!(
        fixture
            .store
            .bootstrap_directory(
                &administrator,
                accepted_revision,
                &bootstrap,
                "large-bootstrap",
            )
            .await,
        Err(StoreError::Invalid)
    ));
    let row = fixture
        .database
        .query_one(
            "SELECT (SELECT directory_revision FROM casework_meta WHERE singleton=true),(SELECT count(*) FROM casework_teams WHERE team_id IN ('large-b','large-bootstrap')),(SELECT count(*) FROM casework_memberships WHERE team_id IN ('large-b','large-bootstrap')),(SELECT count(*) FROM casework_queue_service WHERE queue_id='large-bootstrap-queue'),(SELECT count(*) FROM casework_directory_events),(SELECT count(*) FROM casework_idempotency)",
            &[],
        )
        .await
        .expect("inspect rejected directory update");
    assert_eq!(row.get::<_, i64>(0), accepted_revision);
    assert_eq!(row.get::<_, i64>(1), 0);
    assert_eq!(row.get::<_, i64>(2), 0);
    assert_eq!(row.get::<_, i64>(3), 0);
    assert_eq!(row.get::<_, i64>(4), event_count);
    assert_eq!(row.get::<_, i64>(5), replay_count);
}

async fn wait_for_blocked_query(database: &tokio_postgres::Client, fragment: &str) {
    for _ in 0..200 {
        let blocked: bool = database
            .query_one(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND query LIKE '%' || $1 || '%')",
                &[&fragment],
            )
            .await
            .expect("inspect blocked directory query")
            .get(0);
        if blocked {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("query did not block at expected snapshot boundary: {fragment}");
}

fn large_directory_members(count: usize) -> Vec<DirectoryMember> {
    (0..count)
        .map(|index| DirectoryMember {
            issuer: format!("{}i{index:03}", "\"".repeat(2_042)),
            subject: format!("{}s{index:03}", "\\".repeat(2_042)),
            display_name: Some("\"".repeat(MAXIMUM_DIRECTORY_DISPLAY_NAME_BYTES)),
        })
        .collect()
}

async fn connect_scoped(url: &str) -> tokio_postgres::Client {
    let (client, connection) = tokio_postgres::connect(url, NoTls)
        .await
        .expect("connect scoped assignment database");
    tokio::spawn(async move { connection.await.expect("assignment schema connection") });
    client
}

fn binding() -> SourceBinding {
    SourceBinding {
        source_revision: "1".to_owned(),
        version: "1".to_owned(),
        integrity: None,
        generation: GENERATION.to_owned(),
    }
}

fn source_observation(
    subject_id: Uuid,
    ordered_revision: i64,
    representation_etag: &str,
    state: OccurrenceState,
) -> AuthoritativeObservation {
    AuthoritativeObservation {
        display_reference: None,
        subject: SubjectRef {
            source_id: SOURCE_ID.to_owned(),
            kind: SOURCE_KIND.to_owned(),
            id: subject_id.to_string(),
        },
        occurrence_key: "review:1".to_owned(),
        ordered_revision,
        representation_etag: representation_etag.to_owned(),
        binding: binding(),
        occurrence_kind: OccurrenceKind::Review,
        stage: Some("review".to_owned()),
        submitted_at: None,
        stage_entered_at: None,
        review_timing: None,
        routing_context: None,
        state,
        remaining_actions: Vec::new(),
    }
}

async fn add_source_item(fixture: &Fixture, subject_id: Uuid) -> registry_casework_core::WorkItem {
    fixture
        .store
        .apply_observation(
            &source_observation(
                subject_id,
                1,
                &format!("\"{subject_id}\""),
                OccurrenceState::Open,
            ),
            QUEUE,
            None,
        )
        .await
        .expect("store source observation")
        .expect("source observation opens an item")
}

async fn add_hosted_item(
    fixture: &Fixture,
    reference: &str,
) -> registry_casework_core::RequesterHostedItem {
    fixture
        .service
        .hosted_create(
            &fixture.requester,
            &HostedCreateRequest {
                kind: "task".to_owned(),
                requester_reference: reference.to_owned(),
                display: json!({"summary":reference}),
            },
            &format!("create-{reference}"),
        )
        .await
        .expect("create hosted assignment item")
}

#[tokio::test]
async fn active_absence_routes_assignment_to_eligible_cover_and_records_opaque_history() {
    let fixture = fixture([]).await;
    let item = add_hosted_item(&fixture, "covered").await;
    let absence = fixture
        .service
        .create_absence(
            &fixture.supervisor,
            1,
            &AbsenceInput {
                person: fixture.staff_a.principal.clone(),
                from: Utc::now() - TimeDelta::hours(1),
                until: Utc::now() + TimeDelta::hours(1),
                cover: fixture.staff_b.principal.clone(),
            },
            "absence-a",
        )
        .await
        .expect("record active absence");
    let assigned = fixture
        .service
        .assign_item(
            &fixture.supervisor,
            None,
            "unused",
            item.item_id,
            item.revision,
            &AssignmentRequest {
                assignee: fixture.staff_a.principal.clone(),
                reason: Some("temporary cover".to_owned()),
            },
            "assign-covered",
        )
        .await
        .expect("assign through current absence");
    assert_eq!(assigned.holder, Some(fixture.staff_b.principal.clone()));
    let context = assigned.assignment.expect("assignment context");
    assert_eq!(context.owner, Some(fixture.staff_a.principal.clone()));
    assert_eq!(context.absence_ids, vec![absence.absence_id]);
    assert_eq!(context.staffing_diagnostic, None);

    let retry = fixture
        .service
        .assign_item(
            &fixture.supervisor,
            None,
            "unused",
            item.item_id,
            item.revision,
            &AssignmentRequest {
                assignee: fixture.staff_a.principal.clone(),
                reason: Some("temporary cover".to_owned()),
            },
            "assign-covered",
        )
        .await
        .expect("exact assignment retry");
    assert_eq!(retry.revision, assigned.revision);
    let history = fixture
        .service
        .hosted_staff_history(&fixture.supervisor, item.item_id, 100, None)
        .await
        .expect("supervisor hosted history");
    let assignment_event = history
        .items
        .iter()
        .find(|event| event.kind == HostedHistoryKind::Assigned)
        .expect("assignment history event");
    assert!(assignment_event.actor_ref.is_some());
    assert_eq!(
        assignment_event
            .assignment
            .as_ref()
            .expect("assignment projection")
            .assigned_by,
        None
    );
    let event_count: i64 = fixture
        .database
        .query_one(
            "SELECT count(*) FROM casework_hosted_history WHERE item_id=$1 AND kind='assigned'",
            &[&item.item_id],
        )
        .await
        .expect("count assignment events")
        .get(0);
    assert_eq!(event_count, 1);

    let uncovered_item = add_hosted_item(&fixture, "uncovered").await;
    let uncovered_absence = fixture
        .service
        .create_absence(
            &fixture.supervisor,
            2,
            &AbsenceInput {
                person: fixture.staff_b.principal.clone(),
                from: Utc::now() - TimeDelta::hours(1),
                until: Utc::now() + TimeDelta::hours(1),
                cover: fixture.staff_c.principal.clone(),
            },
            "absence-b",
        )
        .await
        .expect("record second active absence");
    fixture.database.execute(
        "DELETE FROM casework_memberships WHERE issuer=$1 AND subject=$2 AND membership_kind='staff'",
        &[&fixture.staff_c.principal.issuer,&fixture.staff_c.principal.subject],
    ).await.expect("remove unavailable cover");
    let uncovered = fixture
        .service
        .assign_item(
            &fixture.supervisor,
            None,
            "unused",
            uncovered_item.item_id,
            uncovered_item.revision,
            &AssignmentRequest {
                assignee: fixture.staff_b.principal.clone(),
                reason: Some("cover unavailable".to_owned()),
            },
            "assign-uncovered",
        )
        .await
        .expect("retain uncovered assignment in queue");
    assert_eq!(uncovered.holder, None);
    let uncovered_context = uncovered.assignment.expect("uncovered assignment context");
    assert_eq!(
        uncovered_context.owner,
        Some(fixture.staff_b.principal.clone())
    );
    assert_eq!(
        uncovered_context.absence_ids,
        vec![uncovered_absence.absence_id]
    );
    assert_eq!(
        uncovered_context.staffing_diagnostic,
        Some(StaffingDiagnostic::NoCoverAvailable)
    );

    let removed_target_item = add_hosted_item(&fixture, "removed-target").await;
    fixture
        .database
        .execute(
            "DELETE FROM casework_memberships WHERE issuer=$1 AND subject=$2 AND membership_kind='staff'",
            &[
                &fixture.staff_b.principal.issuer,
                &fixture.staff_b.principal.subject,
            ],
        )
        .await
        .expect("remove selected target while its absence remains active");
    assert!(matches!(
        fixture
            .service
            .assign_item(
                &fixture.supervisor,
                None,
                "unused",
                removed_target_item.item_id,
                removed_target_item.revision,
                &AssignmentRequest {
                    assignee: fixture.staff_b.principal.clone(),
                    reason: Some("removed target".to_owned()),
                },
                "assign-removed-target",
            )
            .await,
        Err(ServiceError::Store(StoreError::Forbidden))
    ));
    let outsider = principal("out-of-team");
    assert!(matches!(
        fixture
            .service
            .assign_item(
                &fixture.supervisor,
                None,
                "unused",
                removed_target_item.item_id,
                removed_target_item.revision,
                &AssignmentRequest {
                    assignee: outsider,
                    reason: Some("out of team".to_owned()),
                },
                "assign-out-of-team-target",
            )
            .await,
        Err(ServiceError::Store(StoreError::Forbidden))
    ));
}

#[tokio::test]
async fn directory_targets_are_paged_query_bound_and_recheck_current_authority() {
    let fixture = fixture([]).await;

    let assignment = fixture
        .service
        .directory_targets(
            &fixture.supervisor,
            DirectoryTargetPurpose::Assignment,
            Some(QUEUE),
            None,
            2,
            None,
        )
        .await
        .expect("supervisor assignment targets");
    assert_eq!(assignment.items.len(), 2);
    let assignment_cursor = assignment.next_cursor.expect("assignment cursor");
    let staff_targets = fixture
        .service
        .directory_targets(
            &fixture.staff_a,
            DirectoryTargetPurpose::Assignment,
            Some(QUEUE),
            None,
            100,
            None,
        )
        .await
        .expect("staff assignment targets");
    assert_eq!(staff_targets.items.len(), 3);
    assert!(matches!(
        fixture
            .service
            .directory_targets(
                &fixture.staff_a,
                DirectoryTargetPurpose::Assignment,
                Some(QUEUE),
                None,
                2,
                Some(&assignment_cursor),
            )
            .await,
        Err(ServiceError::Store(StoreError::CursorInvalid))
    ));
    assert!(matches!(
        fixture
            .service
            .directory_targets(
                &fixture.supervisor,
                DirectoryTargetPurpose::AbsencePerson,
                None,
                None,
                2,
                Some(&assignment_cursor),
            )
            .await,
        Err(ServiceError::Store(StoreError::CursorInvalid))
    ));
    assert!(matches!(
        fixture
            .service
            .directory_targets(
                &fixture.requester,
                DirectoryTargetPurpose::Assignment,
                Some(QUEUE),
                None,
                100,
                None,
            )
            .await,
        Err(ServiceError::Store(StoreError::Forbidden))
    ));

    let bulk_a = (0..100)
        .map(|index| principal(&format!("bulk-a-{index:03}")))
        .collect::<Vec<_>>();
    let bulk_b = (0..5)
        .map(|index| principal(&format!("bulk-b-{index:03}")))
        .collect::<Vec<_>>();
    let administrator = actor(
        "administrator",
        CaseworkRole::Administrator,
        "administrator",
    );
    assert!(matches!(
        fixture
            .service
            .directory_targets(
                &administrator,
                DirectoryTargetPurpose::Assignment,
                Some(QUEUE),
                None,
                100,
                None,
            )
            .await,
        Err(ServiceError::Store(StoreError::Forbidden))
    ));
    let staff_absence_people = fixture
        .service
        .directory_targets(
            &fixture.staff_a,
            DirectoryTargetPurpose::AbsencePerson,
            None,
            None,
            100,
            None,
        )
        .await
        .expect("staff may select only self for absence management");
    assert_eq!(
        staff_absence_people.items,
        vec![member(&fixture.staff_a.principal)]
    );
    assert!(matches!(
        fixture
            .service
            .directory_targets(
                &fixture.staff_a,
                DirectoryTargetPurpose::AbsenceCover,
                None,
                Some(&fixture.staff_b.principal),
                100,
                None,
            )
            .await,
        Err(ServiceError::Store(StoreError::Forbidden))
    ));
    let revision = fixture
        .service
        .update_directory_team(
            &administrator,
            1,
            "bulk-a",
            &DirectoryTeamUpdateRequest {
                staff: bulk_a.iter().map(member).collect(),
                supervisors: vec![member(&fixture.supervisor.principal)],
                served_queues: Vec::new(),
            },
            "bulk-a",
        )
        .await
        .expect("add first supervised team");
    let revision = fixture
        .service
        .update_directory_team(
            &administrator,
            revision,
            "bulk-b",
            &DirectoryTeamUpdateRequest {
                staff: bulk_b.iter().map(member).collect(),
                supervisors: vec![member(&fixture.supervisor.principal)],
                served_queues: Vec::new(),
            },
            "bulk-b",
        )
        .await
        .expect("add second supervised team");

    let first = fixture
        .service
        .directory_targets(
            &fixture.supervisor,
            DirectoryTargetPurpose::AbsencePerson,
            None,
            None,
            100,
            None,
        )
        .await
        .expect("first supervised target page");
    assert_eq!(first.items.len(), 100);
    let cursor = first.next_cursor.expect("more than one target page");
    let second = fixture
        .service
        .directory_targets(
            &fixture.supervisor,
            DirectoryTargetPurpose::AbsencePerson,
            None,
            None,
            100,
            Some(&cursor),
        )
        .await
        .expect("second supervised target page");
    assert_eq!(second.items.len(), 8);
    assert!(second.next_cursor.is_none());
    let mut all = first.items;
    all.extend(second.items);
    assert_eq!(all.len(), 108);
    assert!(all.windows(2).all(|pair| pair[0] < pair[1]));

    let cover_targets = fixture
        .service
        .directory_targets(
            &fixture.supervisor,
            DirectoryTargetPurpose::AbsenceCover,
            None,
            Some(&fixture.staff_a.principal),
            100,
            None,
        )
        .await
        .expect("same-team absence covers");
    assert_eq!(
        cover_targets.items,
        vec![
            member(&fixture.staff_b.principal),
            member(&fixture.staff_c.principal)
        ]
    );

    let revision = fixture
        .service
        .update_directory_team(
            &administrator,
            revision,
            "review-team",
            &DirectoryTeamUpdateRequest {
                staff: vec![
                    member(&fixture.staff_a.principal),
                    member(&fixture.staff_b.principal),
                    member(&fixture.staff_c.principal),
                ],
                supervisors: Vec::new(),
                served_queues: vec![QUEUE.to_owned()],
            },
            "remove-review-supervisor",
        )
        .await
        .expect("remove supervisor from review team");
    let revision = fixture
        .service
        .update_directory_team(
            &administrator,
            revision,
            "bulk-a",
            &DirectoryTeamUpdateRequest {
                staff: bulk_a.iter().map(member).collect(),
                supervisors: Vec::new(),
                served_queues: Vec::new(),
            },
            "remove-bulk-a-supervisor",
        )
        .await
        .expect("remove supervisor from first bulk team");
    fixture
        .service
        .update_directory_team(
            &administrator,
            revision,
            "bulk-b",
            &DirectoryTeamUpdateRequest {
                staff: bulk_b.iter().map(member).collect(),
                supervisors: Vec::new(),
                served_queues: Vec::new(),
            },
            "remove-bulk-b-supervisor",
        )
        .await
        .expect("remove supervisor from second bulk team");
    let after_revocation = fixture
        .service
        .directory_targets(
            &fixture.supervisor,
            DirectoryTargetPurpose::AbsencePerson,
            None,
            None,
            100,
            Some(&cursor),
        )
        .await
        .expect("revoked supervisor has no remaining target scope");
    assert!(after_revocation.items.is_empty());
    assert!(matches!(
        fixture
            .service
            .directory_targets(
                &fixture.supervisor,
                DirectoryTargetPurpose::Assignment,
                Some(QUEUE),
                None,
                100,
                None,
            )
            .await,
        Err(ServiceError::Store(StoreError::Forbidden))
    ));
    let unrelated_supervisor = actor("unrelated", CaseworkRole::Supervisor, "supervisor");
    let empty = fixture
        .service
        .directory_targets(
            &unrelated_supervisor,
            DirectoryTargetPurpose::AbsencePerson,
            None,
            None,
            100,
            None,
        )
        .await
        .expect("supervisor with no teams has an empty scope");
    assert!(empty.items.is_empty());
}

#[tokio::test]
async fn absence_cover_targets_stay_inside_the_teams_the_actor_supervises() {
    let fixture = fixture([]).await;
    let administrator = actor(
        "administrator",
        CaseworkRole::Administrator,
        "administrator",
    );
    let unsupervised_staff = principal("unsupervised-staff");
    fixture
        .service
        .update_directory_team(
            &administrator,
            1,
            "other-team",
            &DirectoryTeamUpdateRequest {
                staff: vec![
                    member(&fixture.staff_a.principal),
                    member(&unsupervised_staff),
                ],
                supervisors: Vec::new(),
                served_queues: Vec::new(),
            },
            "add-team-without-the-review-supervisor",
        )
        .await
        .expect("add a second team the review supervisor does not supervise");

    let supervised = fixture
        .service
        .directory_targets(
            &fixture.supervisor,
            DirectoryTargetPurpose::AbsenceCover,
            None,
            Some(&fixture.staff_a.principal),
            100,
            None,
        )
        .await
        .expect("supervised absence covers");
    assert!(!supervised.items.contains(&member(&unsupervised_staff)));
    assert_eq!(
        supervised.items,
        vec![
            member(&fixture.staff_b.principal),
            member(&fixture.staff_c.principal)
        ]
    );

    let unscoped = fixture
        .service
        .directory_targets(
            &administrator,
            DirectoryTargetPurpose::AbsenceCover,
            None,
            Some(&fixture.staff_a.principal),
            100,
            None,
        )
        .await
        .expect("administrator absence covers");
    assert_eq!(
        unscoped.items,
        vec![
            member(&fixture.staff_b.principal),
            member(&fixture.staff_c.principal),
            member(&unsupervised_staff)
        ]
    );
}

#[tokio::test]
async fn directory_names_follow_authorized_memberships_without_duplicate_targets() {
    let fixture = fixture([]).await;
    let administrator = actor(
        "administrator",
        CaseworkRole::Administrator,
        "administrator",
    );
    assert!(matches!(
        fixture
            .service
            .update_directory_team(
                &administrator,
                1,
                "invalid-name-team",
                &DirectoryTeamUpdateRequest {
                    staff: vec![DirectoryMember {
                        issuer: fixture.staff_a.principal.issuer.clone(),
                        subject: fixture.staff_a.principal.subject.clone(),
                        display_name: Some(String::new()),
                    }],
                    supervisors: Vec::new(),
                    served_queues: Vec::new(),
                },
                "invalid-empty-name",
            )
            .await,
        Err(ServiceError::Store(StoreError::Invalid))
    ));
    let revision = fixture
        .service
        .update_directory_team(
            &administrator,
            1,
            "review-team",
            &DirectoryTeamUpdateRequest {
                staff: vec![
                    named_member(&fixture.staff_a.principal, "Review Officer"),
                    named_member(&fixture.staff_b.principal, "Cover Officer"),
                    member(&fixture.staff_c.principal),
                ],
                supervisors: vec![named_member(
                    &fixture.supervisor.principal,
                    "Review Supervisor",
                )],
                served_queues: vec![QUEUE.to_owned()],
            },
            "name-review-team",
        )
        .await
        .expect("name the review team memberships");
    fixture
        .service
        .update_directory_team(
            &administrator,
            revision,
            "other-team",
            &DirectoryTeamUpdateRequest {
                staff: vec![named_member(
                    &fixture.staff_a.principal,
                    "Alternate Officer",
                )],
                supervisors: Vec::new(),
                served_queues: Vec::new(),
            },
            "name-other-team",
        )
        .await
        .expect("store a team-specific name for the same principal");

    let (_, teams) = fixture
        .store
        .directory(&administrator)
        .await
        .expect("administrator reads the full directory");
    assert_eq!(teams.len(), 2);
    assert_eq!(
        teams[0].members[0].display_name.as_deref(),
        Some("Alternate Officer")
    );
    assert_eq!(
        teams[1].members[0].display_name.as_deref(),
        Some("Review Officer")
    );
    assert_eq!(
        teams[1].supervisors[0].display_name.as_deref(),
        Some("Review Supervisor")
    );

    let self_target = fixture
        .service
        .directory_targets(
            &fixture.staff_a,
            DirectoryTargetPurpose::AbsencePerson,
            None,
            None,
            100,
            None,
        )
        .await
        .expect("staff resolves one self target across memberships");
    assert_eq!(
        self_target.items,
        vec![named_member(
            &fixture.staff_a.principal,
            "Alternate Officer"
        )]
    );

    let supervised_target = fixture
        .service
        .directory_targets(
            &fixture.supervisor,
            DirectoryTargetPurpose::AbsencePerson,
            None,
            None,
            100,
            None,
        )
        .await
        .expect("supervisor resolves only names from supervised memberships");
    assert_eq!(
        supervised_target
            .items
            .iter()
            .find(|member| member.subject == fixture.staff_a.principal.subject)
            .and_then(|member| member.display_name.as_deref()),
        Some("Review Officer")
    );
}

#[tokio::test]
async fn supervisor_cannot_record_cover_from_an_unsupervised_shared_team() {
    let fixture = fixture([]).await;
    let administrator = actor(
        "administrator",
        CaseworkRole::Administrator,
        "administrator",
    );
    let unsupervised_cover = principal("unsupervised-cover");
    let revision = fixture
        .service
        .update_directory_team(
            &administrator,
            1,
            "other-team",
            &DirectoryTeamUpdateRequest {
                staff: vec![
                    member(&fixture.staff_a.principal),
                    member(&unsupervised_cover),
                ],
                supervisors: Vec::new(),
                served_queues: Vec::new(),
            },
            "add-unsupervised-shared-team",
        )
        .await
        .expect("add a shared team the supervisor does not lead");

    assert!(matches!(
        fixture
            .service
            .create_absence(
                &fixture.supervisor,
                revision,
                &AbsenceInput {
                    person: fixture.staff_a.principal.clone(),
                    from: Utc::now() - TimeDelta::hours(1),
                    until: Utc::now() + TimeDelta::hours(1),
                    cover: unsupervised_cover,
                },
                "unsupervised-shared-cover",
            )
            .await,
        Err(ServiceError::Store(StoreError::Forbidden))
    ));
}

#[tokio::test]
async fn caseload_preview_filters_concealed_source_items_and_propagates_source_outage() {
    let concealed_id = Uuid::new_v4();
    let unavailable_id = Uuid::new_v4();
    let fixture = fixture([
        (concealed_id, ReadMode::Concealed),
        (unavailable_id, ReadMode::Unavailable),
    ])
    .await;
    let concealed = add_source_item(&fixture, concealed_id).await;
    fixture
        .store
        .claim(
            &fixture.staff_a,
            concealed.item_id,
            concealed.revision,
            "claim-concealed",
        )
        .await
        .expect("claim concealed source item");
    let movement = CaseloadMoveRequest {
        from: fixture.staff_a.principal.clone(),
        to: fixture.staff_b.principal.clone(),
        queue_id: Some(QUEUE.to_owned()),
        reason: "rebalance".to_owned(),
    };
    let page = fixture
        .service
        .preview_caseload_move(
            &fixture.supervisor,
            Some("source-profile"),
            "token",
            &movement,
            10,
            None,
        )
        .await
        .expect("concealed preview");
    assert!(page.items.is_empty());
    assert_eq!(page.status, PageStatus::Complete);

    let unavailable = add_source_item(&fixture, unavailable_id).await;
    fixture
        .store
        .claim(
            &fixture.staff_a,
            unavailable.item_id,
            unavailable.revision,
            "claim-unavailable",
        )
        .await
        .expect("claim unavailable source item");
    assert!(matches!(
        fixture
            .service
            .preview_caseload_move(
                &fixture.supervisor,
                Some("source-profile"),
                "token",
                &movement,
                10,
                None
            )
            .await,
        Err(ServiceError::Adapter(SourceAdapterError::Unavailable))
    ));
}

#[tokio::test]
async fn caseload_apply_is_per_item_and_source_live_attempt_blocks_assignment() {
    let visible_id = Uuid::new_v4();
    let fixture = fixture([(visible_id, ReadMode::Visible)]).await;
    let hosted = add_hosted_item(&fixture, "move-hosted").await;
    let hosted = fixture
        .service
        .hosted_claim(
            &fixture.staff_a,
            hosted.item_id,
            hosted.revision,
            "claim-hosted",
        )
        .await
        .expect("claim hosted item");
    let claimed_at = hosted.held_since.expect("claim establishes heldSince");
    let source = add_source_item(&fixture, visible_id).await;
    let source = fixture
        .store
        .claim(
            &fixture.staff_a,
            source.item_id,
            source.revision,
            "claim-source",
        )
        .await
        .expect("claim source item");
    let unauthorized_delegate = DelegateRequest {
        delegate: fixture.staff_c.principal.clone(),
        reason: Some("not the holder".to_owned()),
    };
    assert!(matches!(
        fixture
            .service
            .delegate_item(
                &fixture.staff_b,
                Some("source-profile"),
                "token",
                source.item_id,
                source.revision,
                &unauthorized_delegate,
                "unauthorized-before-attempt",
            )
            .await,
        Err(ServiceError::Store(StoreError::Forbidden))
    ));
    fixture.database.execute(
        "INSERT INTO casework_attempts(attempt_id,item_id,actor_issuer,actor_subject,casework_profile_id,source_profile_id,item_revision,request_hash,operation,flagged_fields,idempotency_key,displayed_binding,recovery_evidence,state,execution_token,execution_lease_until,created_at,updated_at) VALUES($1,$2,$3,$4,'staff','source-profile',$5,'hash','approve','[]','live-attempt',$6,$7,'pending',$8,now()+interval '5 minutes',now(),now())",
        &[&Uuid::new_v4(),&source.item_id,&fixture.staff_a.principal.issuer,&fixture.staff_a.principal.subject,&source.revision,&serde_json::to_value(&source.binding).expect("binding json"),&b"evidence".as_slice(),&Uuid::new_v4()],
    ).await.expect("insert live source attempt");
    fixture
        .database
        .execute(
            "UPDATE casework_items SET state='synchronizing' WHERE item_id=$1",
            &[&source.item_id],
        )
        .await
        .expect("mark source attempt state");
    assert!(matches!(
        fixture
            .service
            .delegate_item(
                &fixture.staff_b,
                Some("source-profile"),
                "token",
                source.item_id,
                source.revision,
                &unauthorized_delegate,
                "unauthorized-after-attempt",
            )
            .await,
        Err(ServiceError::Store(StoreError::Forbidden))
    ));

    let results = fixture
        .service
        .apply_caseload_move(
            &fixture.supervisor,
            Some("source-profile"),
            "token",
            &CaseloadApplyRequest {
                movement: CaseloadMoveRequest {
                    from: fixture.staff_a.principal.clone(),
                    to: fixture.staff_c.principal.clone(),
                    queue_id: Some(QUEUE.to_owned()),
                    reason: "approved transfer".to_owned(),
                },
                items: vec![
                    CaseloadItemSelection {
                        item_id: hosted.item_id,
                        expected_revision: hosted.revision,
                    },
                    CaseloadItemSelection {
                        item_id: source.item_id,
                        expected_revision: source.revision,
                    },
                    CaseloadItemSelection {
                        item_id: Uuid::new_v4(),
                        expected_revision: 1,
                    },
                ],
            },
            "caseload-one",
        )
        .await
        .expect("apply explicit caseload selections");
    assert_eq!(results[0].result, CaseloadItemOutcome::Moved);
    assert_eq!(results[1].result, CaseloadItemOutcome::AttemptInProgress);
    assert_eq!(results[2].result, CaseloadItemOutcome::NotVisible);
    let moved = fixture
        .service
        .hosted_work_item(&fixture.supervisor, hosted.item_id)
        .await
        .expect("moved hosted item");
    assert_eq!(moved.holder, Some(fixture.staff_c.principal.clone()));
    assert!(moved
        .held_since
        .is_some_and(|moved_at| moved_at > claimed_at));
}

#[tokio::test]
async fn absence_update_preserves_owner_and_delete_replay_rechecks_current_authority() {
    let fixture = fixture([]).await;
    let empty = fixture
        .service
        .absences(&fixture.staff_a)
        .await
        .expect("staff reads current empty absence list");
    assert_eq!(empty.directory_revision, 1);
    assert!(empty.items.is_empty());
    let initial = AbsenceInput {
        person: fixture.staff_a.principal.clone(),
        from: Utc::now() + TimeDelta::hours(1),
        until: Utc::now() + TimeDelta::hours(2),
        cover: fixture.staff_c.principal.clone(),
    };
    let absence = fixture
        .service
        .create_absence(
            &fixture.staff_a,
            empty.directory_revision,
            &initial,
            "absence-owner",
        )
        .await
        .expect("staff records own absence");
    let replacement_owner = AbsenceInput {
        person: fixture.staff_b.principal.clone(),
        ..initial.clone()
    };
    assert!(matches!(
        fixture
            .service
            .update_absence(
                &fixture.staff_b,
                absence.absence_id,
                absence.revision,
                &replacement_owner,
                "replace-owner",
            )
            .await,
        Err(ServiceError::Store(StoreError::Invalid))
    ));
    let stored = fixture
        .service
        .absences(&fixture.staff_a)
        .await
        .expect("owner reads absence");
    assert_eq!(stored.directory_revision, absence.revision);
    assert_eq!(stored.items.len(), 1);
    assert_eq!(stored.items[0].person, fixture.staff_a.principal);

    let administrator = actor(
        "administrator",
        CaseworkRole::Administrator,
        "administrator",
    );
    let directory_revision = fixture
        .service
        .update_directory_team(
            &administrator,
            stored.directory_revision,
            "review-team",
            &DirectoryTeamUpdateRequest {
                staff: vec![
                    member(&fixture.staff_a.principal),
                    member(&fixture.staff_b.principal),
                    member(&fixture.staff_c.principal),
                ],
                supervisors: vec![member(&fixture.supervisor.principal)],
                served_queues: vec![QUEUE.to_owned()],
            },
            "unrelated-directory-change",
        )
        .await
        .expect("advance directory revision without changing absence");
    let current = fixture
        .service
        .absences(&fixture.staff_a)
        .await
        .expect("absence refresh carries current directory revision");
    assert_eq!(current.directory_revision, directory_revision);
    assert_eq!(current.items[0].revision, absence.revision);
    let revised = AbsenceInput {
        until: initial.until + TimeDelta::hours(1),
        ..initial.clone()
    };
    assert!(matches!(
        fixture
            .service
            .update_absence(
                &fixture.staff_a,
                absence.absence_id,
                absence.revision,
                &revised,
                "stale-directory-revision",
            )
            .await,
        Err(ServiceError::Store(StoreError::Conflict))
    ));
    let absence = fixture
        .service
        .update_absence(
            &fixture.staff_a,
            absence.absence_id,
            current.directory_revision,
            &revised,
            "current-directory-revision",
        )
        .await
        .expect("current list revision permits absence update");

    let deleted_revision = fixture
        .service
        .delete_absence(
            &fixture.staff_a,
            absence.absence_id,
            absence.revision,
            "delete-own-absence",
        )
        .await
        .expect("owner deletes absence");
    assert_eq!(
        fixture
            .service
            .delete_absence(
                &fixture.staff_a,
                absence.absence_id,
                absence.revision,
                "delete-own-absence",
            )
            .await
            .expect("authorized exact delete replay"),
        deleted_revision
    );
    fixture
        .database
        .execute(
            "DELETE FROM casework_memberships WHERE issuer=$1 AND subject=$2 AND membership_kind='staff'",
            &[
                &fixture.staff_a.principal.issuer,
                &fixture.staff_a.principal.subject,
            ],
        )
        .await
        .expect("revoke absence owner's membership");
    assert!(matches!(
        fixture
            .service
            .delete_absence(
                &fixture.staff_a,
                absence.absence_id,
                absence.revision,
                "delete-own-absence",
            )
            .await,
        Err(ServiceError::Store(StoreError::Forbidden))
    ));
}

#[tokio::test]
async fn caseload_outer_idempotency_key_binds_the_complete_selection() {
    let fixture = fixture([]).await;
    let first = add_hosted_item(&fixture, "outer-first").await;
    let first = fixture
        .service
        .hosted_claim(
            &fixture.staff_a,
            first.item_id,
            first.revision,
            "claim-outer-first",
        )
        .await
        .expect("claim first hosted item");
    let second = add_hosted_item(&fixture, "outer-second").await;
    let second = fixture
        .service
        .hosted_claim(
            &fixture.staff_a,
            second.item_id,
            second.revision,
            "claim-outer-second",
        )
        .await
        .expect("claim second hosted item");
    let movement = CaseloadMoveRequest {
        from: fixture.staff_a.principal.clone(),
        to: fixture.staff_b.principal.clone(),
        queue_id: Some(QUEUE.to_owned()),
        reason: "bounded selection".to_owned(),
    };
    let original = CaseloadApplyRequest {
        movement: movement.clone(),
        items: vec![CaseloadItemSelection {
            item_id: first.item_id,
            expected_revision: first.revision,
        }],
    };
    let first_result = fixture
        .service
        .apply_caseload_move(
            &fixture.supervisor,
            None,
            "unused",
            &original,
            "outer-selection",
        )
        .await
        .expect("apply first bounded selection");
    assert_eq!(first_result[0].result, CaseloadItemOutcome::Moved);
    let exact_retry = fixture
        .service
        .apply_caseload_move(
            &fixture.supervisor,
            None,
            "unused",
            &original,
            "outer-selection",
        )
        .await
        .expect("resume exact bounded selection");
    assert_eq!(exact_retry[0].result, CaseloadItemOutcome::Moved);

    let expanded = CaseloadApplyRequest {
        movement,
        items: vec![
            original.items[0].clone(),
            CaseloadItemSelection {
                item_id: second.item_id,
                expected_revision: second.revision,
            },
        ],
    };
    assert!(matches!(
        fixture
            .service
            .apply_caseload_move(
                &fixture.supervisor,
                None,
                "unused",
                &expanded,
                "outer-selection",
            )
            .await,
        Err(ServiceError::Store(StoreError::IdempotencyConflict))
    ));
    let untouched = fixture
        .service
        .hosted_work_item(&fixture.supervisor, second.item_id)
        .await
        .expect("read second hosted item");
    assert_eq!(untouched.holder, Some(fixture.staff_a.principal));
}

#[tokio::test]
async fn assignment_replay_rechecks_current_control_and_queue_authority() {
    let fixture = fixture([]).await;
    let item = add_hosted_item(&fixture, "replay-authority").await;
    let claimed = fixture
        .service
        .hosted_claim(
            &fixture.staff_a,
            item.item_id,
            item.revision,
            "claim-replay-authority",
        )
        .await
        .expect("claim replay authority item");
    let request = DelegateRequest {
        delegate: fixture.staff_b.principal.clone(),
        reason: Some("planned handoff".to_owned()),
    };
    let delegated = fixture
        .service
        .delegate_item(
            &fixture.staff_a,
            None,
            "unused",
            item.item_id,
            claimed.revision,
            &request,
            "delegate-replay-authority",
        )
        .await
        .expect("delegate while holder");
    fixture
        .service
        .assign_item(
            &fixture.supervisor,
            None,
            "unused",
            item.item_id,
            delegated.revision,
            &AssignmentRequest {
                assignee: fixture.staff_c.principal.clone(),
                reason: Some("replace assignment owner".to_owned()),
            },
            "replace-replay-authority",
        )
        .await
        .expect("supervisor replaces assignment control");
    assert!(matches!(
        fixture
            .service
            .delegate_item(
                &fixture.staff_a,
                None,
                "unused",
                item.item_id,
                claimed.revision,
                &request,
                "delegate-replay-authority",
            )
            .await,
        Err(ServiceError::Store(StoreError::Forbidden))
    ));
}

#[tokio::test]
async fn invalid_absence_and_duplicate_or_stale_apply_inputs_fail_closed() {
    let fixture = fixture([]).await;
    assert!(matches!(
        fixture
            .service
            .create_absence(
                &fixture.supervisor,
                1,
                &AbsenceInput {
                    person: fixture.staff_a.principal.clone(),
                    from: Utc::now(),
                    until: Utc::now() + TimeDelta::hours(1),
                    cover: fixture.staff_a.principal.clone(),
                },
                "self-cover",
            )
            .await,
        Err(ServiceError::Store(StoreError::Absence(
            registry_casework_core::AbsenceError::SelfCover
        )))
    ));
    let duplicate = Uuid::new_v4();
    let request = CaseloadApplyRequest {
        movement: CaseloadMoveRequest {
            from: fixture.staff_a.principal.clone(),
            to: fixture.staff_b.principal.clone(),
            queue_id: None,
            reason: "duplicate".to_owned(),
        },
        items: vec![
            CaseloadItemSelection {
                item_id: duplicate,
                expected_revision: 1,
            },
            CaseloadItemSelection {
                item_id: duplicate,
                expected_revision: 1,
            },
        ],
    };
    assert!(matches!(
        fixture
            .service
            .apply_caseload_move(
                &fixture.supervisor,
                None,
                "unused",
                &request,
                "duplicate-items"
            )
            .await,
        Err(ServiceError::Store(StoreError::Invalid))
    ));
    let invalid_revision = CaseloadApplyRequest {
        movement: request.movement,
        items: vec![CaseloadItemSelection {
            item_id: Uuid::new_v4(),
            expected_revision: 0,
        }],
    };
    assert!(matches!(
        fixture
            .service
            .apply_caseload_move(
                &fixture.supervisor,
                None,
                "unused",
                &invalid_revision,
                "invalid-revision"
            )
            .await,
        Err(ServiceError::Store(StoreError::Invalid))
    ));
    let unauthorized = CaseloadApplyRequest {
        movement: CaseloadMoveRequest {
            from: fixture.staff_a.principal.clone(),
            to: fixture.staff_b.principal.clone(),
            queue_id: None,
            reason: "unauthorized".to_owned(),
        },
        items: vec![CaseloadItemSelection {
            item_id: Uuid::new_v4(),
            expected_revision: 1,
        }],
    };
    assert!(matches!(
        fixture
            .service
            .apply_caseload_move(
                &fixture.staff_a,
                None,
                "unused",
                &unauthorized,
                "staff-caseload",
            )
            .await,
        Err(ServiceError::Store(StoreError::Forbidden))
    ));
}

#[tokio::test]
async fn assignment_cursor_retention_deletes_expired_rows_in_bounded_batches() {
    let fixture = fixture([]).await;
    for index in 0..101_i32 {
        fixture.database.execute(
            "INSERT INTO casework_assignment_cursors(cursor_id,issuer,subject,profile_id,context_hash,last_item_id,expires_at) VALUES($1,'issuer','subject','profile',$2,$3,now()-interval '1 minute')",
            &[&Uuid::new_v4(),&format!("context-{index}"),&Uuid::new_v4()],
        ).await.expect("insert expired assignment cursor");
    }
    assert_eq!(
        fixture
            .service
            .erase_expired_assignment_cursors()
            .await
            .expect("first bounded cursor sweep"),
        100
    );
    let remaining: i64 = fixture
        .database
        .query_one("SELECT count(*) FROM casework_assignment_cursors", &[])
        .await
        .expect("count retained assignment cursors")
        .get(0);
    assert_eq!(remaining, 1);
    assert_eq!(
        fixture
            .service
            .erase_expired_assignment_cursors()
            .await
            .expect("second bounded cursor sweep"),
        1
    );

    for index in 0..101_i32 {
        fixture.database.execute(
            "INSERT INTO casework_directory_target_cursors(cursor_id,issuer,subject,profile_id,context_hash,last_issuer,last_subject,expires_at) VALUES($1,'issuer','subject','profile',$2,'last-issuer',$3,now()-interval '1 minute')",
            &[&Uuid::new_v4(), &format!("target-context-{index}"), &format!("last-subject-{index}")],
        ).await.expect("insert expired directory target cursor");
    }
    assert_eq!(
        fixture
            .service
            .erase_expired_directory_target_cursors()
            .await
            .expect("first bounded target cursor sweep"),
        100
    );
    let remaining: i64 = fixture
        .database
        .query_one(
            "SELECT count(*) FROM casework_directory_target_cursors",
            &[],
        )
        .await
        .expect("count retained directory target cursors")
        .get(0);
    assert_eq!(remaining, 1);
    assert_eq!(
        fixture
            .service
            .erase_expired_directory_target_cursors()
            .await
            .expect("second bounded target cursor sweep"),
        1
    );

    for index in 0..101_i32 {
        fixture.database.execute(
            "INSERT INTO casework_absence_cursors(cursor_id,issuer,subject,profile_id,context_hash,directory_revision,last_starts_at,last_absence_id,expires_at) VALUES($1,'issuer','subject','profile',$2,1,now(),$3,now()-interval '1 minute')",
            &[&Uuid::new_v4(), &format!("absence-context-{index}"), &Uuid::new_v4()],
        ).await.expect("insert expired absence cursor");
    }
    assert_eq!(
        fixture
            .service
            .erase_expired_absence_cursors()
            .await
            .expect("first bounded absence cursor sweep"),
        100
    );
    let remaining: i64 = fixture
        .database
        .query_one("SELECT count(*) FROM casework_absence_cursors", &[])
        .await
        .expect("count retained absence cursors")
        .get(0);
    assert_eq!(remaining, 1);
    assert_eq!(
        fixture
            .service
            .erase_expired_absence_cursors()
            .await
            .expect("second bounded absence cursor sweep"),
        1
    );
}

#[tokio::test]
async fn absence_pages_are_complete_unique_and_bounded() {
    let fixture = fixture([]).await;
    insert_absences(&fixture, &fixture.staff_a.principal, 1_001, "complete").await;

    let first = fixture
        .service
        .absences(&fixture.staff_a)
        .await
        .expect("compatibility method returns the first bounded page");
    assert_eq!(first.items.len(), 1_000);
    let cursor = first.next_cursor.expect("first page cursor");
    let second = fixture
        .service
        .absences_page(&fixture.staff_a, 1_000, Some(&cursor))
        .await
        .expect("final absence page");
    assert_eq!(second.items.len(), 1);
    assert!(second.next_cursor.is_none());
    assert_eq!(first.directory_revision, second.directory_revision);
    let unique = first
        .items
        .iter()
        .chain(&second.items)
        .map(|absence| absence.absence_id)
        .collect::<BTreeSet<_>>();
    assert_eq!(unique.len(), 1_001);

    let small = fixture
        .service
        .absences_page(&fixture.staff_a, 7, None)
        .await
        .expect("smaller absence page");
    assert_eq!(small.items.len(), 7);
    assert!(small.next_cursor.is_some());
    assert!(matches!(
        fixture
            .service
            .absences_page(&fixture.staff_a, 0, None)
            .await,
        Err(ServiceError::Store(StoreError::Invalid))
    ));
    assert!(matches!(
        fixture
            .service
            .absences_page(&fixture.staff_a, 1_001, None)
            .await,
        Err(ServiceError::Store(StoreError::Invalid))
    ));
}

#[tokio::test]
async fn absence_pages_stop_at_the_serialized_response_budget_and_resume() {
    let fixture = fixture([]).await;
    let escaped = "\"\\".repeat(1_023);
    let person_issuer = format!("{escaped}a");
    let person_subject = format!("{escaped}b");
    let cover_issuer = format!("{escaped}c");
    let cover_subject = format!("{escaped}d");
    fixture
        .database
        .execute(
            "INSERT INTO casework_absences(absence_id,person_issuer,person_subject,starts_at,ends_at,cover_issuer,cover_subject,revision) SELECT md5('large-absence-' || series::text)::uuid,$1,$2,timestamptz '2030-01-01 00:00:00+00' + series * interval '1 minute',timestamptz '2030-01-01 00:00:30+00' + series * interval '1 minute',$3,$4,1 FROM generate_series(0,299) series",
            &[&person_issuer, &person_subject, &cover_issuer, &cover_subject],
        )
        .await
        .expect("insert large absence records");
    let administrator = actor(
        "administrator",
        CaseworkRole::Administrator,
        "administrator",
    );
    let mut cursor = None;
    let mut seen = BTreeSet::new();
    let mut pages = 0;
    loop {
        let page = fixture
            .service
            .absences_page(&administrator, 1_000, cursor.as_deref())
            .await
            .expect("bounded large absence page");
        assert!(
            serde_json::to_vec(&page)
                .expect("serialize absence page")
                .len()
                <= 2 * 1024 * 1024
        );
        seen.extend(page.items.iter().map(|absence| absence.absence_id));
        pages += 1;
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    assert!(pages > 1);
    assert_eq!(seen.len(), 300);
}

#[tokio::test]
async fn absence_cursors_refuse_changed_or_expired_context() {
    let fixture = fixture([]).await;
    insert_absences(&fixture, &fixture.staff_a.principal, 3, "context").await;

    let page = fixture
        .service
        .absences_page(&fixture.staff_a, 1, None)
        .await
        .expect("issue absence cursor");
    let cursor = page.next_cursor.expect("cursor");
    assert!(matches!(
        fixture
            .service
            .absences_page(&fixture.staff_a, 1, Some("tampered"))
            .await,
        Err(ServiceError::Store(StoreError::CursorInvalid))
    ));
    assert!(matches!(
        fixture
            .service
            .absences_page(&fixture.staff_b, 1, Some(&cursor))
            .await,
        Err(ServiceError::Store(StoreError::CursorInvalid))
    ));
    let mut other_profile = fixture.staff_a.clone();
    other_profile.profile_id = "other-staff-profile".to_owned();
    assert!(matches!(
        fixture
            .service
            .absences_page(&other_profile, 1, Some(&cursor))
            .await,
        Err(ServiceError::Store(StoreError::CursorInvalid))
    ));
    let mut other_role = fixture.staff_a.clone();
    other_role.role = CaseworkRole::Supervisor;
    assert!(matches!(
        fixture
            .service
            .absences_page(&other_role, 1, Some(&cursor))
            .await,
        Err(ServiceError::Store(StoreError::CursorInvalid))
    ));
    assert!(matches!(
        fixture
            .service
            .absences_page(&fixture.staff_a, 2, Some(&cursor))
            .await,
        Err(ServiceError::Store(StoreError::CursorInvalid))
    ));

    fixture
        .database
        .execute(
            "UPDATE casework_absence_cursors SET expires_at=now()-interval '1 minute' WHERE cursor_id=$1",
            &[&Uuid::parse_str(&cursor).expect("opaque UUID cursor")],
        )
        .await
        .expect("expire cursor");
    assert!(matches!(
        fixture
            .service
            .absences_page(&fixture.staff_a, 1, Some(&cursor))
            .await,
        Err(ServiceError::Store(StoreError::CursorExpired))
    ));

    let fresh = fixture
        .service
        .absences_page(&fixture.staff_a, 1, None)
        .await
        .expect("issue fresh cursor")
        .next_cursor
        .expect("fresh cursor");
    fixture
        .database
        .execute(
            "UPDATE casework_meta SET directory_revision=directory_revision+1 WHERE singleton=true",
            &[],
        )
        .await
        .expect("advance directory revision");
    assert!(matches!(
        fixture
            .service
            .absences_page(&fixture.staff_a, 1, Some(&fresh))
            .await,
        Err(ServiceError::Store(StoreError::CursorInvalid))
    ));
    assert_eq!(
        fixture
            .service
            .absences_page(&fixture.staff_a, 1, None)
            .await
            .expect("restart after directory change")
            .items
            .len(),
        1
    );
}

#[tokio::test]
async fn absence_pages_reapply_staff_and_supervisor_visibility() {
    let fixture = fixture([]).await;
    insert_absences(&fixture, &fixture.staff_a.principal, 2, "staff-a").await;
    insert_absences(&fixture, &fixture.staff_b.principal, 2, "staff-b").await;

    let staff = fixture
        .service
        .absences_page(&fixture.staff_a, 10, None)
        .await
        .expect("staff absence view");
    assert_eq!(staff.items.len(), 2);
    assert!(staff
        .items
        .iter()
        .all(|absence| absence.person == fixture.staff_a.principal));
    let staff_cursor = fixture
        .service
        .absences_page(&fixture.staff_a, 1, None)
        .await
        .expect("staff first page")
        .next_cursor
        .expect("staff cursor");
    let supervisor = fixture
        .service
        .absences_page(&fixture.supervisor, 1, None)
        .await
        .expect("supervisor absence view");
    assert_eq!(supervisor.items.len(), 1);
    let supervisor_cursor = supervisor.next_cursor.expect("supervisor cursor");

    let administrator = actor(
        "administrator",
        CaseworkRole::Administrator,
        "administrator",
    );
    fixture
        .service
        .update_directory_team(
            &administrator,
            staff.directory_revision,
            "review-team",
            &DirectoryTeamUpdateRequest {
                staff: vec![
                    member(&fixture.staff_b.principal),
                    member(&fixture.staff_c.principal),
                ],
                supervisors: Vec::new(),
                served_queues: vec![QUEUE.to_owned()],
            },
            "revoke-absence-page-access",
        )
        .await
        .expect("revoke staff and supervisor memberships");
    for (actor, cursor) in [
        (&fixture.staff_a, staff_cursor.as_str()),
        (&fixture.supervisor, supervisor_cursor.as_str()),
    ] {
        assert!(matches!(
            fixture.service.absences_page(actor, 1, Some(cursor)).await,
            Err(ServiceError::Store(StoreError::CursorInvalid))
        ));
        assert!(fixture
            .service
            .absences_page(actor, 10, None)
            .await
            .expect("fresh page reapplies current membership")
            .items
            .is_empty());
    }
}

async fn insert_absences(fixture: &Fixture, person: &IssuerPrincipal, count: i32, seed: &str) {
    fixture
        .database
        .execute(
            "INSERT INTO casework_absences(absence_id,person_issuer,person_subject,starts_at,ends_at,cover_issuer,cover_subject,revision) SELECT md5($1 || series::text)::uuid,$2,$3,timestamptz '2030-01-01 00:00:00+00' + series * interval '1 minute',timestamptz '2030-01-01 00:00:30+00' + series * interval '1 minute',$2,'cover',1 FROM generate_series(0,$4-1) series",
            &[&seed, &person.issuer, &person.subject, &count],
        )
        .await
        .expect("insert absence page fixtures");
}

#[tokio::test]
async fn team_reorganization_revokes_immediately_and_reconciliation_defers_live_source_attempts() {
    let source_id = Uuid::new_v4();
    let fixture = fixture([(source_id, ReadMode::Visible)]).await;
    let hosted = add_hosted_item(&fixture, "reorganization-hosted").await;
    let hosted = fixture
        .service
        .hosted_claim(
            &fixture.staff_a,
            hosted.item_id,
            hosted.revision,
            "claim-reorganization-hosted",
        )
        .await
        .expect("claim hosted item before reorganization");
    let source = add_source_item(&fixture, source_id).await;
    let source = fixture
        .store
        .claim(
            &fixture.staff_a,
            source.item_id,
            source.revision,
            "claim-reorganization-source",
        )
        .await
        .expect("claim source item before reorganization");
    let attempt_id = Uuid::new_v4();
    fixture.database.execute(
        "INSERT INTO casework_attempts(attempt_id,item_id,actor_issuer,actor_subject,casework_profile_id,source_profile_id,item_revision,request_hash,operation,flagged_fields,idempotency_key,displayed_binding,recovery_evidence,state,execution_token,execution_lease_until,created_at,updated_at) VALUES($1,$2,$3,$4,'staff','source-profile',$5,'hash','approve','[]','reorganization-attempt',$6,$7,'pending',$8,now()+interval '5 minutes',now(),now())",
        &[&attempt_id,&source.item_id,&fixture.staff_a.principal.issuer,&fixture.staff_a.principal.subject,&source.revision,&serde_json::to_value(&source.binding).expect("binding json"),&b"evidence".as_slice(),&Uuid::new_v4()],
    ).await.expect("insert pending source attempt");

    let replacement = DirectoryTeamUpdateRequest {
        staff: vec![
            member(&fixture.staff_b.principal),
            member(&fixture.staff_c.principal),
        ],
        supervisors: vec![member(&fixture.supervisor.principal)],
        served_queues: vec![QUEUE.to_owned()],
    };
    let administrator = actor(
        "administrator",
        CaseworkRole::Administrator,
        "administrator",
    );
    assert!(matches!(
        fixture
            .service
            .update_directory_team(
                &administrator,
                1,
                "backup-team",
                &replacement,
                "conflicting-queue-owner",
            )
            .await,
        Err(ServiceError::Store(StoreError::Conflict))
    ));
    let revision = fixture
        .service
        .update_directory_team(
            &administrator,
            1,
            "review-team",
            &replacement,
            "replace-review-team",
        )
        .await
        .expect("replace team membership");
    assert_eq!(revision, 2);
    assert!(matches!(
        fixture
            .service
            .hosted_work_item(&fixture.staff_a, hosted.item_id)
            .await,
        Err(ServiceError::Store(StoreError::NotFound))
    ));
    assert!(matches!(
        fixture
            .service
            .caller_item(&fixture.staff_a, source.item_id, "source-profile", "token",)
            .await,
        Err(ServiceError::NotFound)
    ));
    assert!(matches!(
        fixture
            .service
            .update_directory_team(
                &fixture.supervisor,
                revision,
                "invalid team id",
                &DirectoryTeamUpdateRequest {
                    served_queues: vec!["unknown-queue".to_owned()],
                    ..replacement.clone()
                },
                "supervisor-team-update",
            )
            .await,
        Err(ServiceError::Store(StoreError::Forbidden))
    ));
    assert_eq!(
        fixture
            .service
            .update_directory_team(
                &administrator,
                1,
                "review-team",
                &replacement,
                "replace-review-team",
            )
            .await
            .expect("exact team update replay"),
        revision
    );

    assert_eq!(
        fixture
            .service
            .reconcile_ineligible_assignments(100)
            .await
            .expect("first eligibility reconciliation"),
        1
    );
    let hosted_row = fixture
        .database
        .query_one(
            "SELECT state,holder_issuer,revision FROM casework_hosted_items WHERE item_id=$1",
            &[&hosted.item_id],
        )
        .await
        .expect("read reconciled hosted item");
    assert_eq!(hosted_row.get::<_, String>(0), "open");
    assert_eq!(hosted_row.get::<_, Option<String>>(1), None);
    assert_eq!(hosted_row.get::<_, i64>(2), hosted.revision + 1);
    let source_row = fixture
        .database
        .query_one(
            "SELECT state,holder_subject FROM casework_items WHERE item_id=$1",
            &[&source.item_id],
        )
        .await
        .expect("read deferred source item");
    assert_eq!(source_row.get::<_, String>(0), "claimed");
    assert_eq!(
        source_row.get::<_, Option<String>>(1),
        Some(fixture.staff_a.principal.subject.clone())
    );

    fixture
        .database
        .execute(
            "UPDATE casework_attempts SET state='refused',updated_at=now() WHERE attempt_id=$1",
            &[&attempt_id],
        )
        .await
        .expect("resolve pending source attempt");
    assert_eq!(
        fixture
            .service
            .reconcile_ineligible_assignments(100)
            .await
            .expect("retry deferred eligibility reconciliation"),
        1
    );
    let source_row = fixture
        .database
        .query_one(
            "SELECT state,holder_issuer,revision FROM casework_items WHERE item_id=$1",
            &[&source.item_id],
        )
        .await
        .expect("read reconciled source item");
    assert_eq!(source_row.get::<_, String>(0), "open");
    assert_eq!(source_row.get::<_, Option<String>>(1), None);
    assert_eq!(source_row.get::<_, i64>(2), source.revision + 1);
    for item_id in [hosted.item_id, source.item_id] {
        let releases: i64 = fixture
            .database
            .query_one(
                "SELECT (SELECT count(*) FROM casework_history WHERE item_id=$1 AND kind='released') + (SELECT count(*) FROM casework_hosted_history WHERE item_id=$1 AND kind='released')",
                &[&item_id],
            )
            .await
            .expect("count visible release history")
            .get(0);
        assert_eq!(releases, 1);
    }
}

#[tokio::test]
async fn source_observation_that_drops_the_holder_clears_the_assignment_and_records_the_release() {
    let subject_id = Uuid::new_v4();
    let fixture = fixture([(subject_id, ReadMode::Visible)]).await;
    let item = add_source_item(&fixture, subject_id).await;
    let absence = fixture
        .service
        .create_absence(
            &fixture.supervisor,
            1,
            &AbsenceInput {
                person: fixture.staff_a.principal.clone(),
                from: Utc::now() - TimeDelta::hours(1),
                until: Utc::now() + TimeDelta::hours(1),
                cover: fixture.staff_b.principal.clone(),
            },
            "absence-observed-open",
        )
        .await
        .expect("record active absence");
    let assigned = fixture
        .service
        .assign_item(
            &fixture.supervisor,
            Some("source-profile"),
            "token",
            item.item_id,
            item.revision,
            &AssignmentRequest {
                assignee: fixture.staff_a.principal.clone(),
                reason: Some("cover the review".to_owned()),
            },
            "assign-observed-open",
        )
        .await
        .expect("assign the source item through the active absence");
    assert_eq!(assigned.holder, Some(fixture.staff_b.principal.clone()));
    let context = assigned.assignment.clone().expect("assignment context");
    assert_eq!(context.owner, Some(fixture.staff_a.principal.clone()));
    assert_eq!(
        context.assigned_by,
        Some(fixture.supervisor.principal.clone())
    );
    assert_eq!(context.absence_ids, vec![absence.absence_id]);

    // An attempt that has already settled leaves the item synchronizing with
    // no execution in flight, which is the state a source observation may move
    // back to open.
    let prepared = PreparedSourceAttempt {
        source_binding: assigned.binding.clone(),
        recovery_evidence: RecoveryEvidence::new(b"inert recovery capsule".to_vec())
            .expect("bounded recovery evidence"),
    };
    let (attempt, execution_token) = fixture
        .store
        .reserve_attempt_for_execution(
            &fixture.staff_b,
            item.item_id,
            assigned.revision,
            "source-profile",
            OperationName::parse("approve").expect("approve operation"),
            None,
            &[],
            "attempt-observed-open",
            "sha256:request-observed-open",
            &prepared,
        )
        .await
        .expect("the holder reserves an attempt");
    fixture
        .store
        .complete_attempt(
            &fixture.staff_b,
            attempt.attempt_id,
            execution_token,
            &SourceReceipt {
                source_revision: "2".to_owned(),
                resulting_state: "approved".to_owned(),
                binding: assigned.binding.clone(),
                actor_reference: None,
                metadata: BTreeMap::new(),
            },
        )
        .await
        .expect("settle the attempt");
    let synchronizing = fixture
        .store
        .item(item.item_id)
        .await
        .expect("item after the settled attempt");
    assert_eq!(synchronizing.state, OccurrenceState::Synchronizing);
    assert_eq!(
        synchronizing.holder,
        Some(fixture.staff_b.principal.clone())
    );

    let observed = fixture
        .store
        .apply_observation(
            &source_observation(subject_id, 2, "\"reopened\"", OccurrenceState::Open),
            QUEUE,
            None,
        )
        .await
        .expect("apply the reopening observation")
        .expect("the observation updates the existing item");
    assert_eq!(observed.item_id, item.item_id);
    assert_eq!(observed.state, OccurrenceState::Open);
    assert_eq!(observed.holder, None);
    assert_eq!(observed.assignment, None);

    let row = fixture
        .database
        .query_one(
            "SELECT holder_issuer,holder_subject,assignment_owner_issuer,assignment_owner_subject,assigned_by_issuer,assigned_by_subject,assignment_absence_ids,staffing_diagnostic FROM casework_items WHERE item_id=$1",
            &[&item.item_id],
        )
        .await
        .expect("read the observed item row");
    for column in 0..6 {
        assert_eq!(row.get::<_, Option<String>>(column), None);
    }
    assert!(row.get::<_, Vec<Uuid>>(6).is_empty());
    assert_eq!(row.get::<_, Option<String>>(7), None);

    let history = fixture
        .store
        .history(&fixture.supervisor, item.item_id, 100)
        .await
        .expect("supervisor reads the item history");
    let observation_event = history
        .iter()
        .find(|event| {
            event.kind == HistoryKind::Observed && event.item_revision == observed.revision
        })
        .expect("the observation is recorded");
    assert_eq!(observation_event.detail["sourceRevision"], json!(2));
    let release = history
        .iter()
        .find(|event| {
            event.kind == HistoryKind::Released && event.item_revision == observed.revision
        })
        .expect("the displaced claim is recorded as a release");
    assert_eq!(
        release.detail["previousHolder"],
        json!(fixture.staff_b.principal)
    );
    assert_eq!(release.detail["reason"], json!("source_observation"));
    assert_eq!(release.detail["sourceRevision"], json!(2));
}
