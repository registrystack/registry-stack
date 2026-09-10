use std::collections::BTreeMap;
use std::env;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{TimeDelta, Utc};
use registry_casework::{CaseworkService, DatabaseConfig, PostgresStore, ServiceError, StoreError};
use registry_casework_core::{
    AbsenceInput, AccessProfile, ActiveSubjectsPage, ActorContext, AssignmentRequest,
    AuthoritativeObservation, BootstrapDirectoryRequest, CallerSubjectView, CaseloadApplyRequest,
    CaseloadItemOutcome, CaseloadItemSelection, CaseloadMoveRequest, CaseworkIdentity,
    CaseworkProject, CaseworkRole, DelegateRequest, DirectoryTargetPurpose,
    DirectoryTeamUpdateRequest, DiscoveryCursor, EphemeralCredential, EventRequest,
    ExecutePreparedRequest, HostedCreateRequest, HostedHistoryKind, HostedKindPolicy,
    HostedOutcomePolicy, HostedRetentionPolicy, InboxPolicy, IssuerPrincipal, OccurrenceKind,
    OccurrenceState, PageStatus, PrepareActionRequest, PreparedSourceAttempt, QueuePolicy,
    SourceAdapter, SourceAdapterError, SourceBinding, SourcePolicy, SourceReceipt,
    SourceRequestPolicy, StaffingDiagnostic, SubjectRef, TransitionHint,
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
    store
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
    let source = Arc::new(TestSource {
        reads: reads
            .into_iter()
            .map(|(id, mode)| (id.to_string(), mode))
            .collect(),
    });
    let service =
        CaseworkService::new(store.clone(), project(), [source as Arc<dyn SourceAdapter>])
            .expect("assignment service");
    Fixture {
        service,
        store,
        database: connect_scoped(&scoped_url).await,
        requester: actor("requester", CaseworkRole::Requester, "requester"),
        staff_a,
        staff_b,
        staff_c,
        supervisor,
    }
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

async fn add_source_item(fixture: &Fixture, subject_id: Uuid) -> registry_casework_core::WorkItem {
    fixture
        .store
        .apply_observation(
            &AuthoritativeObservation {
                subject: SubjectRef {
                    source_id: SOURCE_ID.to_owned(),
                    kind: SOURCE_KIND.to_owned(),
                    id: subject_id.to_string(),
                },
                occurrence_key: "review:1".to_owned(),
                ordered_revision: 1,
                representation_etag: format!("\"{subject_id}\""),
                binding: binding(),
                occurrence_kind: OccurrenceKind::Review,
                stage: Some("review".to_owned()),
                submitted_at: None,
                stage_entered_at: None,
                review_timing: None,
                routing_context: None,
                state: OccurrenceState::Open,
                remaining_actions: Vec::new(),
            },
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
        vec![fixture.staff_a.principal.clone()]
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
                staff: bulk_a.clone(),
                supervisors: vec![fixture.supervisor.principal.clone()],
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
                staff: bulk_b.clone(),
                supervisors: vec![fixture.supervisor.principal.clone()],
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
            fixture.staff_b.principal.clone(),
            fixture.staff_c.principal.clone()
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
                    fixture.staff_a.principal.clone(),
                    fixture.staff_b.principal.clone(),
                    fixture.staff_c.principal.clone(),
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
                staff: bulk_a,
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
                staff: bulk_b,
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
                    fixture.staff_a.principal.clone(),
                    fixture.staff_b.principal.clone(),
                    fixture.staff_c.principal.clone(),
                ],
                supervisors: vec![fixture.supervisor.principal.clone()],
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
            fixture.staff_b.principal.clone(),
            fixture.staff_c.principal.clone(),
        ],
        supervisors: vec![fixture.supervisor.principal.clone()],
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
