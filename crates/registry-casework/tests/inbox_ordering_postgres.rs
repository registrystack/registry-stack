// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::env;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, TimeDelta, Utc};
use registry_casework::{CaseworkService, DatabaseConfig, PostgresStore};
use registry_casework_core::{
    AccessProfile, ActiveSubjectsPage, ActorContext, BootstrapDirectoryRequest, CallerSubjectView,
    CaseworkIdentity, CaseworkProject, CaseworkRole, DiscoveryCursor, EphemeralCredential,
    EventRequest, ExecutePreparedRequest, InboxPolicy, InboxView, IssuerPrincipal,
    PrepareActionRequest, PreparedSourceAttempt, QueuePolicy, SourceAdapter, SourceAdapterError,
    SourceBinding, SourcePolicy, SourceReceipt, SourceRequestPolicy, SubjectRef, TransitionHint,
};
use registry_platform_config::{SecretProvider, SecretResolver};
use tokio_postgres::NoTls;
use uuid::Uuid;

const DATABASE_ENV: &str = "CASEWORK_INBOX_TEST_DATABASE_URL";
const SOURCE_ID: &str = "inbox-source";
const SUBJECT_KIND: &str = "request";
const GENERATION: &str = "inbox-generation-1";

#[derive(Clone)]
struct VisibleSource;

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
        Ok(CallerSubjectView {
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

fn project() -> CaseworkProject {
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
            requests: vec![SourceRequestPolicy {
                entity: SUBJECT_KIND.to_owned(),
                queue: "default".to_owned(),
                projection: Vec::new(),
                routing: Vec::new(),
                clock: None,
                target: None,
            }],
        }],
        hosted_kinds: Vec::new(),
        calendars: Vec::new(),
        clocks: Vec::new(),
        inbox: InboxPolicy {
            default_page_size: 2,
            maximum_candidate_scan: 100,
            maximum_source_reads: 100,
            maximum_concurrent_source_reads: 1,
            page_deadline_milliseconds: 5_000,
        },
    }
}

async fn fixture() -> (PostgresStore, tokio_postgres::Client, CaseworkService) {
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
        project(),
        [Arc::new(VisibleSource) as Arc<dyn SourceAdapter>],
    )
    .expect("inbox service");
    (store, database, service)
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
    assert_eq!(item_subjects(&first), ["multi-real", "real"]);
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
    assert_eq!(item_subjects(&second), ["passive", "paused"]);
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
    assert_eq!(item_subjects(&third), ["facts-missing", "no-due"]);
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
    assert_eq!(item_subjects(&overdue), ["multi-real", "real", "passive"]);

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

    let stored_holdings = store.holdings(&supervisor).await.expect("stored holdings");
    assert_eq!(stored_holdings.len(), 1);
    assert_eq!(stored_holdings[0].active_items, 6);
    assert_eq!(stored_holdings[0].overdue_items, 3);
    let visible_holdings = service
        .caller_visible_holdings(&supervisor, "reader", "token", None)
        .await
        .expect("caller-visible holdings");
    assert_eq!(visible_holdings.items.len(), 1);
    assert_eq!(visible_holdings.items[0].active_items, 6);
    assert_eq!(visible_holdings.items[0].overdue_items, 3);

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
