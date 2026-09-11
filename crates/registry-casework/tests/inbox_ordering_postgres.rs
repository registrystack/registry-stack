// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::env;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, TimeDelta, Timelike, Utc};
use registry_casework::{CaseworkService, DatabaseConfig, PostgresStore, ServiceError, StoreError};
use registry_casework_core::{
    AccessProfile, ActiveSubjectsPage, ActorContext, BootstrapDirectoryRequest, CallerSubjectView,
    CaseworkIdentity, CaseworkProject, CaseworkRole, ClockRuntimeState, DiscoveryCursor,
    DisplayReferencePolicy, EphemeralCredential, EventRequest, ExecutePreparedRequest, InboxPolicy,
    InboxSort, InboxView, IssuerPrincipal, PageStatus, PrepareActionRequest, PreparedSourceAttempt,
    QueuePolicy, SourceAdapter, SourceAdapterError, SourceBinding, SourcePolicy, SourceReceipt,
    SourceRequestPolicy, SubjectRef, TransitionHint,
};
use registry_platform_config::{SecretProvider, SecretResolver};
use tokio_postgres::NoTls;
use uuid::Uuid;

const DATABASE_ENV: &str = "CASEWORK_INBOX_TEST_DATABASE_URL";
const SOURCE_ID: &str = "inbox-source";
const SUBJECT_KIND: &str = "request";
const GENERATION: &str = "inbox-generation-1";

#[derive(Clone, Default)]
struct VisibleSource {
    discovery_unavailable: Arc<AtomicBool>,
}

impl VisibleSource {
    fn with_discovery_control() -> (Self, Arc<AtomicBool>) {
        let discovery_unavailable = Arc::new(AtomicBool::new(false));
        (
            Self {
                discovery_unavailable: Arc::clone(&discovery_unavailable),
            },
            discovery_unavailable,
        )
    }
}

#[async_trait]
impl SourceAdapter for VisibleSource {
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
    ) -> Result<registry_casework_core::AuthoritativeObservation, SourceAdapterError> {
        Err(SourceAdapterError::Invalid)
    }

    async fn discover_active(
        &self,
        _cursor: Option<&DiscoveryCursor>,
        _limit: usize,
    ) -> Result<ActiveSubjectsPage, SourceAdapterError> {
        if self.discovery_unavailable.load(Ordering::SeqCst) {
            return Err(SourceAdapterError::Unavailable);
        }
        Ok(ActiveSubjectsPage {
            subjects: vec![SubjectRef {
                source_id: SOURCE_ID.to_owned(),
                kind: SUBJECT_KIND.to_owned(),
                id: "remote-active".to_owned(),
            }],
            next_cursor: Some(DiscoveryCursor("more".to_owned())),
        })
    }

    async fn read_for_caller(
        &self,
        subject: &SubjectRef,
        _source_profile_id: &str,
        _credential: EphemeralCredential<'_>,
    ) -> Result<CallerSubjectView, SourceAdapterError> {
        if subject.id.starts_with("concealed-") {
            return Err(SourceAdapterError::Concealed);
        }
        Ok(CallerSubjectView {
            display_reference: match subject.id.as_str() {
                "reference-concealed" => None,
                "reference-moved" => Some("CASE-2026-MOVED".to_owned()),
                _ => Some("CASE-2026-0042".to_owned()),
            },
            subject: subject.clone(),
            binding: binding(),
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

fn principal(subject: &str) -> IssuerPrincipal {
    IssuerPrincipal {
        issuer: "https://issuer.example".to_owned(),
        subject: subject.to_owned(),
    }
}

fn actor(subject: &str, profile_id: &str, role: CaseworkRole) -> ActorContext {
    ActorContext {
        principal: principal(subject),
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

fn binding() -> SourceBinding {
    SourceBinding {
        source_revision: "1".to_owned(),
        version: "1".to_owned(),
        integrity: None,
        generation: GENERATION.to_owned(),
    }
}

fn project_with_inbox(inbox: InboxPolicy) -> CaseworkProject {
    CaseworkProject {
        api_version: registry_casework_core::CASEWORK_API_VERSION.to_owned(),
        kind: registry_casework_core::CASEWORK_KIND.to_owned(),
        casework: CaseworkIdentity {
            id: "inbox-ordering-test".to_owned(),
            version: "1".to_owned(),
        },
        access_profiles: vec![
            profile("staff", CaseworkRole::Staff),
            profile("supervisor", CaseworkRole::Supervisor),
            profile("administrator", CaseworkRole::Administrator),
        ],
        queues: ["default", "secondary"]
            .into_iter()
            .map(|id| QueuePolicy {
                id: id.to_owned(),
                label: id.to_owned(),
            })
            .collect(),
        sources: vec![SourcePolicy {
            id: SOURCE_ID.to_owned(),
            adapter: "test".to_owned(),
            description: "Focused inbox ordering source".to_owned(),
            requests: [SUBJECT_KIND, "appeal"]
                .into_iter()
                .map(|entity| SourceRequestPolicy {
                    display_reference: Some(DisplayReferencePolicy {
                        field: "case-number".to_owned(),
                    }),
                    entity: entity.to_owned(),
                    queue: "default".to_owned(),
                    projection: Vec::new(),
                    routing: Vec::new(),
                    clock: None,
                    target: None,
                })
                .collect(),
        }],
        hosted_kinds: Vec::new(),
        calendars: Vec::new(),
        clocks: Vec::new(),
        inbox,
    }
}

fn project() -> CaseworkProject {
    project_with_inbox(InboxPolicy {
        default_page_size: 2,
        maximum_candidate_scan: 100,
        maximum_source_reads: 100,
        maximum_concurrent_source_reads: 1,
        page_deadline_milliseconds: 5_000,
    })
}

async fn fixture_with_project(
    project: CaseworkProject,
) -> (PostgresStore, tokio_postgres::Client, CaseworkService) {
    fixture_with_source(project, VisibleSource::default()).await
}

async fn fixture_with_source(
    project: CaseworkProject,
    source: VisibleSource,
) -> (PostgresStore, tokio_postgres::Client, CaseworkService) {
    let base = env::var(DATABASE_ENV).expect("dedicated inbox test database URL");
    let schema = format!("inbox_{}", Uuid::new_v4().simple());
    let separator = if base.contains('?') { '&' } else { '?' };
    let scoped_url = format!("{base}{separator}options=-csearch_path%3D{schema}");
    let (admin, connection) = tokio_postgres::connect(&base, NoTls)
        .await
        .expect("connect inbox test database");
    tokio::spawn(async move { connection.await.expect("inbox admin connection") });
    admin
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .expect("create isolated inbox schema");
    let secret_name =
        format!("CASEWORK_INBOX_SCHEMA_{}", Uuid::new_v4().simple()).to_ascii_uppercase();
    env::set_var(&secret_name, &scoped_url);
    let secrets = SecretResolver::new([SecretProvider::Environment], "/private/tmp")
        .expect("inbox test secret resolver");
    let database_config = DatabaseConfig {
        runtime_url_ref: format!("secret:env/{secret_name}"),
        migration_url_ref: format!("secret:env/{secret_name}"),
        trusted_root_certificate_ref: None,
        test_only_plaintext: true,
    };
    let migration =
        PostgresStore::connect_migration(&database_config, &secrets).expect("migration store");
    migration.migrate().await.expect("casework migrations");
    let store = PostgresStore::connect_runtime(&database_config, &secrets).expect("runtime store");
    let (database, connection) = tokio_postgres::connect(&scoped_url, NoTls)
        .await
        .expect("connect scoped inbox database");
    tokio::spawn(async move { connection.await.expect("inbox schema connection") });
    let service = CaseworkService::new(
        store.clone(),
        project,
        [Arc::new(source) as Arc<dyn SourceAdapter>],
    )
    .expect("inbox service");
    (store, database, service)
}

async fn fixture() -> (PostgresStore, tokio_postgres::Client, CaseworkService) {
    fixture_with_project(project()).await
}

async fn insert_item(
    database: &tokio_postgres::Client,
    item_id: Uuid,
    subject_id: &str,
    first_observed_at: DateTime<Utc>,
    passive_due_at: Option<DateTime<Utc>>,
    holder: &IssuerPrincipal,
) {
    database.execute(
        "INSERT INTO casework_items(item_id,source_id,subject_kind,subject_id,occurrence_kind,occurrence_key,stage,binding,state,queue_id,holder_issuer,holder_subject,revision,first_observed_at,passive_due_at,updated_at) VALUES($1,$2,$3,$4,'review',$5,'review',$6,'claimed','default',$7,$8,1,$9,$10,$9)",
        &[&item_id,&SOURCE_ID,&SUBJECT_KIND,&subject_id,&format!("review:{subject_id}"),&serde_json::to_value(binding()).expect("binding JSON"),&holder.issuer,&holder.subject,&first_observed_at,&passive_due_at],
    ).await.expect("insert inbox item");
}

async fn insert_clock(
    database: &tokio_postgres::Client,
    item_id: Uuid,
    subject_id: &str,
    clock_id: &str,
    state: &str,
    due_at: Option<DateTime<Utc>>,
) {
    let occurrence_id = Uuid::new_v4();
    let generation = i64::from(due_at.is_some());
    database.execute(
        "INSERT INTO casework_clock_occurrences(clock_occurrence_id,source_id,subject_kind,subject_id,clock_id,scope,scope_key,item_id,state,policy_digest,current_calculation_generation,recompute_generation,source_binding_generation,source_revision,source_etag,next_action_at,created_at,updated_at) VALUES($1,$2,$3,$4,$5,'activity',$6,$7,$8,'sha256:clock-policy',$9,0,$10,1,'\"source-1\"',NULL,now(),now())",
        &[&occurrence_id,&SOURCE_ID,&SUBJECT_KIND,&subject_id,&clock_id,&format!("{subject_id}:{clock_id}"),&item_id,&state,&generation,&GENERATION],
    ).await.expect("insert clock occurrence");
    if let Some(due_at) = due_at {
        database.execute(
            "INSERT INTO casework_clock_calculations(clock_occurrence_id,generation,recompute_generation,policy_digest,policy,calendar,holiday_document,source_timing,anchor_at,started_at,due_at,at_risk_at,reminders,steps,completed_at,created_at) VALUES($1,1,0,'sha256:clock-policy','{}',NULL,NULL,NULL,$2,$2,$3,NULL,'[]','[]',NULL,now())",
            &[&occurrence_id,&(due_at-TimeDelta::days(5)),&due_at],
        ).await.expect("insert clock calculation");
    }
}

fn item_subjects(page: &registry_casework_core::WorkItemPage) -> Vec<&str> {
    page.items
        .iter()
        .map(|item| item.subject.id.as_str())
        .collect()
}

#[tokio::test]
async fn configured_scan_budget_reaches_visible_work_beyond_one_hundred_candidates() {
    let inbox = InboxPolicy {
        default_page_size: 1,
        maximum_candidate_scan: 150,
        maximum_source_reads: 150,
        maximum_concurrent_source_reads: 1,
        page_deadline_milliseconds: 5_000,
    };
    let (store, database, service) = fixture_with_project(project_with_inbox(inbox)).await;
    let staff = actor("staff", "staff", CaseworkRole::Staff);
    let administrator = actor(
        "administrator",
        "administrator",
        CaseworkRole::Administrator,
    );
    store
        .bootstrap_directory(
            &administrator,
            0,
            &BootstrapDirectoryRequest {
                team_id: "team".to_owned(),
                staff: vec![staff.principal.clone()],
                supervisors: Vec::new(),
                queue_id: "default".to_owned(),
            },
            "bootstrap-scan-budget",
        )
        .await
        .expect("bootstrap directory");
    store
        .set_source_status(SOURCE_ID, GENERATION, true, false)
        .await
        .expect("source is synchronized");

    let now = Utc::now();
    for index in 0..101_u128 {
        insert_item(
            &database,
            Uuid::from_u128(20_000 + index),
            &format!("concealed-{index:03}"),
            now + TimeDelta::seconds(i64::try_from(index).expect("index fits")),
            None,
            &staff.principal,
        )
        .await;
    }
    insert_item(
        &database,
        Uuid::from_u128(21_000),
        "visible-after-concealed",
        now + TimeDelta::seconds(101),
        None,
        &staff.principal,
    )
    .await;

    let page = service
        .inbox_for_view_query(
            &staff,
            "reader",
            "token",
            InboxView::MyTeams,
            1,
            None,
            None,
            None,
            InboxSort::Age,
            None,
        )
        .await
        .expect("scan configured candidate budget in one request");

    assert_eq!(item_subjects(&page), ["visible-after-concealed"]);
    assert_eq!(page.status, PageStatus::Complete);
    assert!(page.next_cursor.is_none());

    let capped = store
        .inbox_candidates(&staff, 150, None, None)
        .await
        .expect("public candidate page remains bounded");
    assert_eq!(capped.items.len(), 100);
    assert!(capped.next_cursor.is_some());
}

#[tokio::test]
async fn queue_filter_keeps_incomplete_source_discovery_relevant_after_reassignment() {
    let (source, discovery_unavailable) = VisibleSource::with_discovery_control();
    let (store, database, service) = fixture_with_source(project(), source).await;
    let staff = actor("staff", "staff", CaseworkRole::Staff);
    let administrator = actor(
        "administrator",
        "administrator",
        CaseworkRole::Administrator,
    );
    store
        .bootstrap_directory(
            &administrator,
            0,
            &BootstrapDirectoryRequest {
                team_id: "team".to_owned(),
                staff: vec![staff.principal.clone()],
                supervisors: Vec::new(),
                queue_id: "default".to_owned(),
            },
            "bootstrap-filtered-discovery",
        )
        .await
        .expect("bootstrap directory");
    database
        .execute(
            "INSERT INTO casework_queue_service(queue_id,team_id,revision) VALUES('secondary','team',1)",
            &[],
        )
        .await
        .expect("serve reassignment queue");

    let page = service
        .inbox_for_view(
            &staff,
            "reader",
            "token",
            InboxView::MyTeams,
            1,
            Some("secondary"),
            None,
            None,
        )
        .await
        .expect("filtered inbox retains source discovery state");

    assert!(page.items.is_empty());
    assert_eq!(page.status, PageStatus::BudgetExhausted);
    assert!(page.next_cursor.is_some());

    let source_status = database
        .query_one(
            "SELECT remote_complete,unavailable FROM casework_source_status WHERE source_id=$1 AND binding_generation=$2",
            &[&SOURCE_ID, &GENERATION],
        )
        .await
        .expect("source discovery status was assessed");
    let remote_complete: bool = source_status.get(0);
    let unavailable: bool = source_status.get(1);
    assert!(!remote_complete);
    assert!(!unavailable);

    discovery_unavailable.store(true, Ordering::SeqCst);
    let outage = service
        .inbox_for_view(
            &staff,
            "reader",
            "token",
            InboxView::MyTeams,
            1,
            Some("secondary"),
            None,
            None,
        )
        .await
        .expect("filtered inbox reports source outage");
    assert!(outage.items.is_empty());
    assert_eq!(outage.status, PageStatus::SourceUnavailable);
    let unavailable: bool = database
        .query_one(
            "SELECT unavailable FROM casework_source_status WHERE source_id=$1 AND binding_generation=$2",
            &[&SOURCE_ID, &GENERATION],
        )
        .await
        .expect("source outage status was retained")
        .get(0);
    assert!(unavailable);
}

async fn set_reference_and_type(
    database: &tokio_postgres::Client,
    item_id: Uuid,
    reference: &str,
    subject_kind: &str,
) {
    database
        .execute(
            "UPDATE casework_items SET display_reference=$2,subject_kind=$3 WHERE item_id=$1",
            &[&item_id, &reference, &subject_kind],
        )
        .await
        .expect("set retained display reference and request type");
}

#[tokio::test]
async fn reference_lookup_rechecks_caller_disclosure_and_binds_stable_sort_cursors() {
    let (store, database, service) = fixture().await;
    let staff = actor("staff", "staff", CaseworkRole::Staff);
    let administrator = actor(
        "administrator",
        "administrator",
        CaseworkRole::Administrator,
    );
    store
        .bootstrap_directory(
            &administrator,
            0,
            &BootstrapDirectoryRequest {
                team_id: "team".to_owned(),
                staff: vec![staff.principal.clone()],
                supervisors: Vec::new(),
                queue_id: "default".to_owned(),
            },
            "bootstrap-reference",
        )
        .await
        .expect("bootstrap directory");
    store
        .set_source_status(SOURCE_ID, GENERATION, true, false)
        .await
        .expect("source is synchronized");

    let now = Utc::now();
    for (offset, subject_id, subject_kind) in [
        (4, "reference-visible-old", SUBJECT_KIND),
        (3, "reference-concealed", SUBJECT_KIND),
        (2, "reference-moved", SUBJECT_KIND),
        (1, "reference-visible-new", "appeal"),
    ] {
        let item_id = Uuid::from_u128(10_000 + u128::try_from(offset).unwrap());
        insert_item(
            &database,
            item_id,
            subject_id,
            now - TimeDelta::days(offset),
            Some(now + TimeDelta::days(offset)),
            &staff.principal,
        )
        .await;
        set_reference_and_type(&database, item_id, "CASE-2026-0042", subject_kind).await;
    }

    let first = service
        .inbox_for_view_query(
            &staff,
            "reader",
            "token",
            InboxView::MyTeams,
            1,
            None,
            None,
            Some("CASE-2026-0042"),
            InboxSort::Age,
            None,
        )
        .await
        .expect("first reference page");
    assert_eq!(item_subjects(&first), ["reference-visible-old"]);
    assert_eq!(
        first.items[0].display_reference.as_deref(),
        Some("CASE-2026-0042")
    );
    let cursor = first.next_cursor.as_deref().expect("continuation cursor");
    let context: String = database
        .query_one(
            "SELECT context FROM casework_cursors WHERE cursor_id=$1",
            &[&Uuid::parse_str(cursor).unwrap()],
        )
        .await
        .expect("read cursor context")
        .get(0);
    assert!(!context.contains("CASE-2026-0042"));
    assert!(context.contains("referenceHash"));

    let wrong_sort = service
        .inbox_for_view_query(
            &staff,
            "reader",
            "token",
            InboxView::MyTeams,
            1,
            None,
            None,
            Some("CASE-2026-0042"),
            InboxSort::Type,
            Some(cursor),
        )
        .await;
    assert!(matches!(
        wrong_sort,
        Err(ServiceError::Store(StoreError::Invalid))
    ));

    let second = service
        .inbox_for_view_query(
            &staff,
            "reader",
            "token",
            InboxView::MyTeams,
            1,
            None,
            None,
            Some("CASE-2026-0042"),
            InboxSort::Age,
            Some(cursor),
        )
        .await
        .expect("second reference page");
    assert_eq!(item_subjects(&second), ["reference-visible-new"]);
    assert!(second.next_cursor.is_none());

    let wrong_case = service
        .inbox_for_view_query(
            &staff,
            "reader",
            "token",
            InboxView::MyTeams,
            10,
            None,
            None,
            Some("case-2026-0042"),
            InboxSort::Age,
            None,
        )
        .await
        .expect("case-sensitive lookup");
    assert!(wrong_case.items.is_empty());
    assert_eq!(wrong_case.status, PageStatus::Complete);

    let by_type = service
        .inbox_for_view_query(
            &staff,
            "reader",
            "token",
            InboxView::MyTeams,
            10,
            None,
            None,
            None,
            InboxSort::Type,
            None,
        )
        .await
        .expect("type-sorted inbox");
    assert_eq!(item_subjects(&by_type)[0], "reference-visible-new");
    assert_eq!(
        item_subjects(&by_type)[1..],
        [
            "reference-visible-old",
            "reference-concealed",
            "reference-moved"
        ]
    );
}

#[tokio::test]
async fn effective_due_selector_cursor_holdings_and_served_queues_share_current_scope() {
    let (store, database, service) = fixture().await;
    let staff = actor("staff", "staff", CaseworkRole::Staff);
    let supervisor = actor("supervisor", "supervisor", CaseworkRole::Supervisor);
    let administrator = actor(
        "administrator",
        "administrator",
        CaseworkRole::Administrator,
    );
    store
        .bootstrap_directory(
            &administrator,
            0,
            &BootstrapDirectoryRequest {
                team_id: "team".to_owned(),
                staff: vec![staff.principal.clone()],
                supervisors: vec![supervisor.principal.clone()],
                queue_id: "default".to_owned(),
            },
            "bootstrap",
        )
        .await
        .expect("bootstrap directory");
    database
        .execute(
            "INSERT INTO casework_queue_service(queue_id,team_id,revision) VALUES('secondary','team',1)",
            &[],
        )
        .await
        .expect("serve second queue");
    store
        .set_source_status(SOURCE_ID, GENERATION, true, false)
        .await
        .expect("source is synchronized");

    let now = Utc::now();
    let now = now
        .with_nanosecond(now.nanosecond() / 1_000 * 1_000)
        .expect("microsecond-aligned test time");
    let cases = [
        (
            Uuid::from_u128(1),
            "multi-real",
            now - TimeDelta::days(6),
            Some(now - TimeDelta::days(8)),
        ),
        (
            Uuid::from_u128(2),
            "real",
            now - TimeDelta::days(5),
            Some(now + TimeDelta::days(5)),
        ),
        (
            Uuid::from_u128(3),
            "passive",
            now - TimeDelta::days(4),
            Some(now - TimeDelta::days(1)),
        ),
        (
            Uuid::from_u128(4),
            "paused",
            now - TimeDelta::days(3),
            Some(now - TimeDelta::days(9)),
        ),
        (
            Uuid::from_u128(5),
            "facts-missing",
            now - TimeDelta::days(2),
            Some(now - TimeDelta::days(9)),
        ),
        (Uuid::from_u128(6), "no-due", now - TimeDelta::days(1), None),
    ];
    for (item_id, subject_id, first_observed_at, passive_due_at) in cases {
        insert_item(
            &database,
            item_id,
            subject_id,
            first_observed_at,
            passive_due_at,
            &staff.principal,
        )
        .await;
    }
    insert_clock(
        &database,
        Uuid::from_u128(1),
        "multi-real",
        "later",
        "running",
        Some(now - TimeDelta::days(2)),
    )
    .await;
    insert_clock(
        &database,
        Uuid::from_u128(1),
        "multi-real",
        "earlier",
        "running",
        Some(now - TimeDelta::days(4)),
    )
    .await;
    insert_clock(
        &database,
        Uuid::from_u128(1),
        "multi-real",
        "paused-independent",
        "paused",
        Some(now - TimeDelta::days(10)),
    )
    .await;
    insert_clock(
        &database,
        Uuid::from_u128(2),
        "real",
        "deadline",
        "verification_pending",
        Some(now - TimeDelta::days(3)),
    )
    .await;
    insert_clock(
        &database,
        Uuid::from_u128(4),
        "paused",
        "deadline",
        "paused",
        Some(now - TimeDelta::days(7)),
    )
    .await;
    insert_clock(
        &database,
        Uuid::from_u128(5),
        "facts-missing",
        "deadline",
        "source_facts_missing",
        None,
    )
    .await;

    let first = service
        .inbox_for_view(
            &staff,
            "reader",
            "token",
            InboxView::MyTeams,
            2,
            None,
            None,
            None,
        )
        .await
        .expect("first ordered page");
    assert_eq!(item_subjects(&first), ["facts-missing", "multi-real"]);
    assert_eq!(first.served_queues, ["default", "secondary"]);
    let second = service
        .inbox_for_view(
            &staff,
            "reader",
            "token",
            InboxView::MyTeams,
            2,
            None,
            None,
            first.next_cursor.as_deref(),
        )
        .await
        .expect("second ordered page");
    assert_eq!(item_subjects(&second), ["real", "passive"]);
    let third = service
        .inbox_for_view(
            &staff,
            "reader",
            "token",
            InboxView::MyTeams,
            2,
            None,
            None,
            second.next_cursor.as_deref(),
        )
        .await
        .expect("third ordered page");
    assert_eq!(item_subjects(&third), ["paused", "no-due"]);
    assert!(third.next_cursor.is_none());

    let overdue = service
        .inbox_for_view(
            &staff,
            "reader",
            "token",
            InboxView::Overdue,
            100,
            None,
            None,
            None,
        )
        .await
        .expect("effective overdue view");
    assert_eq!(
        item_subjects(&overdue),
        ["facts-missing", "multi-real", "real", "passive"]
    );

    let selected = service
        .inbox_for_view(
            &staff,
            "reader",
            "token",
            InboxView::MyTeams,
            100,
            None,
            Some(&SubjectRef {
                source_id: SOURCE_ID.to_owned(),
                kind: SUBJECT_KIND.to_owned(),
                id: "paused".to_owned(),
            }),
            None,
        )
        .await
        .expect("exact subject selector");
    assert_eq!(item_subjects(&selected), ["paused"]);
    assert_eq!(
        selected.items[0].passive_due_at,
        Some(now - TimeDelta::days(9)),
        "the retained passive target is historical and does not make a paused clock overdue"
    );

    let (paused_item, _) = service
        .caller_item(&staff, Uuid::from_u128(4), "reader", "token")
        .await
        .expect("the paused item is visible on its own");
    assert_eq!(paused_item.passive_due_at, Some(now - TimeDelta::days(9)));
    assert_eq!(paused_item.clock_occurrences.len(), 1);
    assert_eq!(
        paused_item.clock_occurrences[0].state,
        ClockRuntimeState::Paused
    );

    let stored_holdings = store.holdings(&supervisor).await.expect("stored holdings");
    assert_eq!(stored_holdings.len(), 1);
    assert_eq!(stored_holdings[0].active_items, 6);
    assert_eq!(stored_holdings[0].overdue_items, 4);
    let visible_holdings = service
        .caller_visible_holdings(&supervisor, "reader", "token", 100, None)
        .await
        .expect("caller-visible holdings");
    assert_eq!(visible_holdings.items.len(), 1);
    assert_eq!(visible_holdings.items[0].active_items, 6);
    assert_eq!(visible_holdings.items[0].overdue_items, 4);

    assert_eq!(
        store
            .served_queues(&staff)
            .await
            .expect("staff queue scope"),
        ["default", "secondary"]
    );
    assert_eq!(
        store
            .served_queues(&supervisor)
            .await
            .expect("supervisor queue scope"),
        ["default", "secondary"]
    );
    assert!(store
        .served_queues(&actor("outsider", "staff", CaseworkRole::Staff))
        .await
        .expect("outsider queue scope")
        .is_empty());
}

#[tokio::test]
async fn holdings_continue_truthfully_beyond_a_single_source_read_page() {
    let (store, database, service) = fixture().await;
    let staff = actor("staff", "staff", CaseworkRole::Staff);
    let supervisor = actor("supervisor", "supervisor", CaseworkRole::Supervisor);
    let administrator = actor(
        "administrator",
        "administrator",
        CaseworkRole::Administrator,
    );
    store
        .bootstrap_directory(
            &administrator,
            0,
            &BootstrapDirectoryRequest {
                team_id: "team".to_owned(),
                staff: vec![staff.principal.clone()],
                supervisors: vec![supervisor.principal.clone()],
                queue_id: "default".to_owned(),
            },
            "bootstrap",
        )
        .await
        .expect("bootstrap directory");
    store
        .set_source_status(SOURCE_ID, GENERATION, true, false)
        .await
        .expect("source is synchronized");

    let now = Utc::now();
    let held = 150_u128;
    let overdue = 70_u128;
    for index in 0..held {
        let passive_due_at = if index > 0 && index <= overdue {
            now - TimeDelta::days(1)
        } else {
            now + TimeDelta::days(1)
        };
        insert_item(
            &database,
            Uuid::from_u128(1_000 + index),
            &format!("held-{index}"),
            now - TimeDelta::minutes(i64::try_from(index).expect("index fits")),
            Some(passive_due_at),
            &staff.principal,
        )
        .await;
    }

    let stored = store.holdings(&supervisor).await.expect("stored holdings");
    assert_eq!(stored.len(), 1);
    assert_eq!(stored[0].active_items, 150);
    assert_eq!(stored[0].overdue_items, 70);

    let first = service
        .caller_visible_holdings(&supervisor, "reader", "token", 100, None)
        .await
        .expect("first caller-visible holdings page");
    assert_eq!(first.items.len(), 1);
    assert_eq!(first.items[0].active_items, 100);
    assert_eq!(first.items[0].overdue_items, 21);
    assert_eq!(first.status, PageStatus::BudgetExhausted);
    let cursor = first.next_cursor.expect("holdings continuation");

    // Changing a deadline must not move an unvisited holding behind the
    // continuation cursor. Holdings pages use immutable observation age.
    database
        .execute(
            "UPDATE casework_items SET passive_due_at=$1 WHERE item_id=$2",
            &[&(now + TimeDelta::hours(12)), &Uuid::from_u128(1_000)],
        )
        .await
        .expect("move an unvisited deadline across the prior due-order cursor");
    assert!(matches!(
        service
            .inbox_for_view(
                &supervisor,
                "reader",
                "token",
                InboxView::TeamHoldings,
                100,
                None,
                None,
                Some(&cursor),
            )
            .await,
        Err(ServiceError::Store(StoreError::Invalid))
    ));
    assert!(matches!(
        service
            .caller_visible_holdings(&supervisor, "different-reader", "token", 100, Some(&cursor),)
            .await,
        Err(ServiceError::Store(StoreError::Invalid))
    ));

    let second = service
        .caller_visible_holdings(&supervisor, "reader", "token", 100, Some(&cursor))
        .await
        .expect("second caller-visible holdings page");
    assert_eq!(second.items.len(), 1);
    assert_eq!(second.items[0].active_items, 50);
    assert_eq!(second.items[0].overdue_items, 49);
    assert!(second.next_cursor.is_none());
    assert_eq!(second.status, PageStatus::Complete);
    assert_eq!(
        first.items[0].active_items + second.items[0].active_items,
        150
    );
    assert_eq!(
        first.items[0].overdue_items + second.items[0].overdue_items,
        70
    );
}
