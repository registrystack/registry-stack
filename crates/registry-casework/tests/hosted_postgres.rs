use std::env;
use std::sync::Arc;

use chrono::Utc;
use registry_casework::{
    CaseworkService, DatabaseConfig, PostgresStore, ServiceError, StoreError,
    HOSTED_TERMINAL_CURSOR_CONTEXT,
};
use registry_casework_core::{
    AccessProfile, ActorContext, BootstrapDirectoryRequest, CaseworkIdentity, CaseworkProject,
    CaseworkRole, HostedCancelRequest, HostedCreateRequest, HostedDecisionRequest,
    HostedKindPolicy, HostedOutcomePolicy, HostedRetentionPolicy, InboxPolicy, IssuerPrincipal,
    QueuePolicy,
};
use registry_platform_config::{SecretProvider, SecretResolver};
use serde_json::json;
use tokio_postgres::NoTls;
use uuid::Uuid;

struct Fixture {
    service: CaseworkService,
    database: tokio_postgres::Client,
    requester: ActorContext,
    other_requester: ActorContext,
    staff: ActorContext,
    supervisor: ActorContext,
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

fn profile(id: &str, role: CaseworkRole, kinds: &[&str]) -> AccessProfile {
    AccessProfile {
        id: id.to_owned(),
        principal_claim: "sub".to_owned(),
        required_scopes: vec![format!("casework:{id}")],
        role,
        kinds: kinds.iter().map(|kind| (*kind).to_owned()).collect(),
    }
}

fn project(version: &str, outcomes: Vec<HostedOutcomePolicy>) -> CaseworkProject {
    CaseworkProject {
        api_version: registry_casework_core::CASEWORK_API_VERSION.to_owned(),
        kind: registry_casework_core::CASEWORK_KIND.to_owned(),
        casework: CaseworkIdentity {
            id: "standalone-test".to_owned(),
            version: version.to_owned(),
        },
        access_profiles: vec![
            profile("staff", CaseworkRole::Staff, &[]),
            profile("staff-other", CaseworkRole::Staff, &[]),
            profile("supervisor", CaseworkRole::Supervisor, &[]),
            profile("administrator", CaseworkRole::Administrator, &[]),
            profile("requester", CaseworkRole::Requester, &["batch-validation"]),
        ],
        queues: vec![QueuePolicy {
            id: "batch-review".to_owned(),
            label: "Batch review".to_owned(),
        }],
        sources: Vec::new(),
        hosted_kinds: vec![HostedKindPolicy {
            id: "batch-validation".to_owned(),
            version: version.to_owned(),
            queue: "batch-review".to_owned(),
            deciding_profiles: vec!["staff".to_owned()],
            retention: HostedRetentionPolicy {
                terminal_days: 90,
                accountability_days: 365,
            },
            display_schema: json!({
                "type":"object",
                "additionalProperties":false,
                "required":["summary","batchReference"],
                "properties":{
                    "summary":{"type":"string","maxLength":160},
                    "batchReference":{"type":"string","maxLength":120}
                }
            }),
            outcomes,
        }],
        inbox: InboxPolicy::default(),
    }
}

fn default_outcomes() -> Vec<HostedOutcomePolicy> {
    vec![
        HostedOutcomePolicy {
            id: "confirmed".to_owned(),
            label: "Confirm".to_owned(),
            reason_required: false,
        },
        HostedOutcomePolicy {
            id: "rejected".to_owned(),
            label: "Reject".to_owned(),
            reason_required: true,
        },
    ]
}

fn create_request(reference: &str) -> HostedCreateRequest {
    HostedCreateRequest {
        kind: "batch-validation".to_owned(),
        requester_reference: reference.to_owned(),
        display: json!({
            "summary": format!("Review {reference}"),
            "batchReference": reference
        }),
    }
}

async fn fixture() -> Fixture {
    let base = env::var("CASEWORK_HOSTED_TEST_DATABASE_URL")
        .expect("CASEWORK_HOSTED_TEST_DATABASE_URL is required for hosted PostgreSQL tests");
    let schema = format!("hosted_{}", Uuid::new_v4().simple());
    let separator = if base.contains('?') { '&' } else { '?' };
    let scoped_url = format!("{base}{separator}options=-csearch_path%3D{schema}");
    let (admin, admin_connection) = tokio_postgres::connect(&base, NoTls)
        .await
        .expect("connect dedicated hosted test database");
    tokio::spawn(async move { admin_connection.await.expect("admin connection") });
    admin
        .batch_execute(&format!("CREATE SCHEMA {schema}"))
        .await
        .expect("create isolated hosted test schema");
    let secret_name =
        format!("CASEWORK_HOSTED_SCHEMA_{}", Uuid::new_v4().simple()).to_ascii_uppercase();
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
    migration.migrate().await.expect("hosted migrations");
    let store = PostgresStore::connect_runtime(&database_config, &secrets).expect("runtime store");
    let requester = actor("requester", CaseworkRole::Requester, "requester");
    let other_requester = actor("other-requester", CaseworkRole::Requester, "requester");
    let staff = actor("staff", CaseworkRole::Staff, "staff");
    let supervisor = actor("supervisor", CaseworkRole::Supervisor, "supervisor");
    let administrator = actor(
        "administrator",
        CaseworkRole::Administrator,
        "administrator",
    );
    store
        .bootstrap_directory(
            &administrator,
            0,
            &BootstrapDirectoryRequest {
                team_id: "batch-team".to_owned(),
                staff: vec![staff.principal.clone()],
                supervisors: vec![supervisor.principal.clone()],
                queue_id: "batch-review".to_owned(),
            },
            "bootstrap",
        )
        .await
        .expect("bootstrap hosted directory");
    Fixture {
        service: CaseworkService::new(
            store,
            project("1", default_outcomes()),
            Vec::<Arc<dyn registry_casework_core::SourceAdapter>>::new(),
        )
        .expect("standalone service"),
        database: connect_scoped(&scoped_url).await,
        requester,
        other_requester,
        staff,
        supervisor,
    }
}

async fn connect_scoped(url: &str) -> tokio_postgres::Client {
    let (client, connection) = tokio_postgres::connect(url, NoTls)
        .await
        .expect("schema connection");
    tokio::spawn(async move { connection.await.expect("schema connection task") });
    client
}

#[tokio::test]
async fn ten_creates_and_two_retries_remain_one_item_per_key_and_requester() {
    let fixture = fixture().await;
    for index in 0..10 {
        let reference = format!("batch-{index:04}");
        let request = create_request(&reference);
        let key = format!("create-{index}");
        let first = fixture
            .service
            .hosted_create(&fixture.requester, &request, &key)
            .await
            .expect("create");
        let retry_one = fixture
            .service
            .hosted_create(&fixture.requester, &request, &key)
            .await
            .expect("first retry");
        let retry_two = fixture
            .service
            .hosted_create(&fixture.requester, &request, &key)
            .await
            .expect("second retry");
        assert_eq!(first.item_id, retry_one.item_id);
        assert_eq!(first.item_id, retry_two.item_id);
    }
    let changed = fixture
        .service
        .hosted_create(&fixture.requester, &create_request("changed"), "create-0")
        .await;
    assert!(matches!(
        changed,
        Err(ServiceError::Store(StoreError::IdempotencyConflict))
    ));
    let count: i64 = fixture
        .database
        .query_one("SELECT count(*) FROM casework_hosted_items", &[])
        .await
        .expect("count items")
        .get(0);
    assert_eq!(count, 10);
    let first_id: Uuid = fixture
        .database
        .query_one(
            "SELECT item_id FROM casework_hosted_items ORDER BY created_at,item_id LIMIT 1",
            &[],
        )
        .await
        .expect("first item")
        .get(0);
    assert!(matches!(
        fixture
            .service
            .hosted_requester_item(&fixture.other_requester, first_id)
            .await,
        Err(ServiceError::Store(StoreError::NotFound))
    ));
}

#[tokio::test]
async fn pinned_policy_and_commit_time_membership_control_decision() {
    let mut fixture = fixture().await;
    let original_request = create_request("batch-policy");
    let created = fixture
        .service
        .hosted_create(&fixture.requester, &original_request, "create-policy")
        .await
        .expect("create");
    let claimed = fixture
        .service
        .hosted_claim(
            &fixture.staff,
            created.item_id,
            created.revision,
            "claim-policy",
        )
        .await
        .expect("claim");
    let mut revised = project(
        "2",
        vec![HostedOutcomePolicy {
            id: "deferred".to_owned(),
            label: "Defer".to_owned(),
            reason_required: false,
        }],
    );
    revised.hosted_kinds[0].display_schema = json!({
        "type":"object","additionalProperties":false,"required":["different"],
        "properties":{"different":{"type":"string","maxLength":10}}
    });
    let revised_service = CaseworkService::new(
        fixture.service.store().clone(),
        revised,
        Vec::<Arc<dyn registry_casework_core::SourceAdapter>>::new(),
    )
    .expect("revised service");
    let replay = revised_service
        .hosted_create(&fixture.requester, &original_request, "create-policy")
        .await
        .expect("old exact create replay uses pinned response");
    assert_eq!(replay.item_id, created.item_id);
    assert!(matches!(
        revised_service
            .hosted_create(
                &fixture.requester,
                &original_request,
                "new-key-under-new-schema"
            )
            .await,
        Err(ServiceError::HostedValidation(_))
    ));
    let pinned = revised_service
        .hosted_work_item(&fixture.staff, created.item_id)
        .await
        .expect("pinned item");
    let hosted = pinned.hosted.expect("hosted context");
    assert_eq!(hosted.version, "1");
    assert!(hosted
        .outcomes
        .iter()
        .any(|outcome| outcome.id == "confirmed"));
    assert!(!hosted
        .outcomes
        .iter()
        .any(|outcome| outcome.id == "deferred"));

    let transaction = fixture
        .database
        .transaction()
        .await
        .expect("revocation transaction");
    transaction.execute(
        "DELETE FROM casework_memberships WHERE team_id='batch-team' AND issuer=$1 AND subject=$2 AND membership_kind='staff'",
        &[&fixture.staff.principal.issuer,&fixture.staff.principal.subject],
    ).await.expect("lock and remove membership");
    let service = revised_service.clone();
    let staff = fixture.staff.clone();
    let decision = tokio::spawn(async move {
        service
            .hosted_decide(
                &staff,
                created.item_id,
                claimed.revision,
                &HostedDecisionRequest {
                    outcome: "confirmed".to_owned(),
                    reason: Some("checked".to_owned()),
                },
                "decision-after-revoke",
            )
            .await
    });
    tokio::task::yield_now().await;
    transaction
        .commit()
        .await
        .expect("revocation commits first");
    assert!(matches!(
        decision.await.expect("decision task"),
        Err(ServiceError::Store(
            StoreError::NotFound | StoreError::Forbidden
        ))
    ));
}

#[tokio::test]
async fn cancel_and_decision_race_produces_one_stable_terminal_event() {
    let fixture = fixture().await;
    let created = fixture
        .service
        .hosted_create(
            &fixture.requester,
            &create_request("batch-race"),
            "create-race",
        )
        .await
        .expect("create");
    let claimed = fixture
        .service
        .hosted_claim(
            &fixture.staff,
            created.item_id,
            created.revision,
            "claim-race",
        )
        .await
        .expect("claim");
    let barrier = Arc::new(tokio::sync::Barrier::new(3));
    let cancel = {
        let service = fixture.service.clone();
        let actor = fixture.requester.clone();
        let barrier = barrier.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            service
                .hosted_cancel(
                    &actor,
                    created.item_id,
                    claimed.revision,
                    &HostedCancelRequest {
                        reason: "workflow stopped".to_owned(),
                    },
                    "cancel-race",
                )
                .await
        })
    };
    let decide = {
        let service = fixture.service.clone();
        let actor = fixture.staff.clone();
        let barrier = barrier.clone();
        tokio::spawn(async move {
            barrier.wait().await;
            service
                .hosted_decide(
                    &actor,
                    created.item_id,
                    claimed.revision,
                    &HostedDecisionRequest {
                        outcome: "confirmed".to_owned(),
                        reason: Some("checked".to_owned()),
                    },
                    "decide-race",
                )
                .await
        })
    };
    barrier.wait().await;
    let cancel = cancel.await.expect("cancel task");
    let decide = decide.await.expect("decide task");
    assert_eq!(usize::from(cancel.is_ok()) + usize::from(decide.is_ok()), 1);
    let page = fixture
        .service
        .hosted_terminal_page(&fixture.requester, 10, HOSTED_TERMINAL_CURSOR_CONTEXT, None)
        .await
        .expect("terminal page");
    assert_eq!(page.items.len(), 1);
    let replay = fixture
        .service
        .hosted_terminal_page(&fixture.requester, 10, HOSTED_TERMINAL_CURSOR_CONTEXT, None)
        .await
        .expect("terminal replay");
    assert_eq!(replay.items[0].event_id, page.items[0].event_id);
    assert!(serde_json::to_string(&page)
        .expect("serialize terminal")
        .find("checked")
        .is_none());
}

#[tokio::test]
async fn terminal_cursors_and_independent_retention_are_enforced_and_erased() {
    let mut fixture = fixture().await;
    let mut terminal_ids = Vec::new();
    for index in 0..3 {
        let created = fixture
            .service
            .hosted_create(
                &fixture.requester,
                &create_request(&format!("batch-terminal-{index}")),
                &format!("create-terminal-{index}"),
            )
            .await
            .expect("create");
        terminal_ids.push(
            fixture
                .service
                .hosted_cancel(
                    &fixture.requester,
                    created.item_id,
                    created.revision,
                    &HostedCancelRequest {
                        reason: "stopped".to_owned(),
                    },
                    &format!("cancel-terminal-{index}"),
                )
                .await
                .expect("cancel"),
        );
    }
    let first = fixture
        .service
        .hosted_terminal_page(&fixture.requester, 2, HOSTED_TERMINAL_CURSOR_CONTEXT, None)
        .await
        .expect("first terminal page");
    assert_eq!(first.items.len(), 2);
    let cursor = first.next_cursor.expect("next cursor");
    let second = fixture
        .service
        .hosted_terminal_page(
            &fixture.requester,
            2,
            HOSTED_TERMINAL_CURSOR_CONTEXT,
            Some(&cursor),
        )
        .await
        .expect("second terminal page");
    assert_eq!(second.items.len(), 1);
    assert!(matches!(
        fixture
            .service
            .hosted_terminal_page(
                &fixture.other_requester,
                2,
                HOSTED_TERMINAL_CURSOR_CONTEXT,
                Some(&cursor)
            )
            .await,
        Err(ServiceError::Store(StoreError::CursorInvalid))
    ));
    let revoked_open = fixture
        .service
        .hosted_create(
            &fixture.requester,
            &create_request("batch-revoked-open"),
            "create-revoked-open",
        )
        .await
        .expect("create item before kind grant revocation");
    let mut revoked_project = project("1", default_outcomes());
    let mut remaining_kind = revoked_project.hosted_kinds[0].clone();
    remaining_kind.id = "other-validation".to_owned();
    revoked_project.hosted_kinds.push(remaining_kind);
    revoked_project
        .access_profiles
        .iter_mut()
        .find(|profile| profile.id == "requester")
        .expect("requester profile")
        .kinds = vec!["other-validation".to_owned()];
    revoked_project
        .check()
        .expect("revoked-kind project remains loadable");
    let revoked_service = CaseworkService::new(
        fixture.service.store().clone(),
        revoked_project,
        Vec::<Arc<dyn registry_casework_core::SourceAdapter>>::new(),
    )
    .expect("revoked requester service");
    assert!(matches!(
        revoked_service
            .hosted_requester_item(&fixture.requester, terminal_ids[1].item_id)
            .await,
        Err(ServiceError::NotFound)
    ));
    let revoked_terminal = revoked_service
        .hosted_terminal_page(&fixture.requester, 10, HOSTED_TERMINAL_CURSOR_CONTEXT, None)
        .await
        .expect("terminal feed omits revoked kind");
    assert!(revoked_terminal.items.is_empty());
    assert!(matches!(
        revoked_service
            .hosted_requester_notes(&fixture.requester, revoked_open.item_id, 10, None)
            .await,
        Err(ServiceError::NotFound)
    ));
    assert!(matches!(
        revoked_service
            .hosted_note(
                &fixture.requester,
                revoked_open.item_id,
                revoked_open.revision,
                &registry_casework_core::HostedNoteRequest {
                    note: "refused after grant revocation".to_owned()
                },
                "note-revoked-open"
            )
            .await,
        Err(ServiceError::NotFound)
    ));
    assert!(matches!(
        revoked_service
            .hosted_cancel(
                &fixture.requester,
                revoked_open.item_id,
                revoked_open.revision,
                &HostedCancelRequest {
                    reason: "refused after grant revocation".to_owned()
                },
                "cancel-revoked-open"
            )
            .await,
        Err(ServiceError::NotFound)
    ));
    assert!(matches!(
        revoked_service
            .hosted_create(
                &fixture.requester,
                &create_request("batch-terminal-1"),
                "create-terminal-1"
            )
            .await,
        Err(ServiceError::HostedValidation(_))
    ));

    fixture.database.execute("UPDATE casework_hosted_items SET terminal_retained_until=now()-interval '1 second' WHERE item_id=$1",&[&terminal_ids[0].item_id]).await.expect("expire cancellation replay item");
    assert!(matches!(
        fixture
            .service
            .hosted_cancel(
                &fixture.requester,
                terminal_ids[0].item_id,
                1,
                &HostedCancelRequest {
                    reason: "stopped".to_owned()
                },
                "cancel-terminal-0"
            )
            .await,
        Err(ServiceError::Store(StoreError::IdempotencyExpired))
    ));
    fixture.database.execute("UPDATE casework_hosted_cursors SET expires_at=now()-interval '1 second' WHERE cursor_id=$1",&[&Uuid::parse_str(&cursor).expect("cursor uuid")]).await.expect("expire cursor");
    assert!(matches!(
        fixture
            .service
            .hosted_terminal_page(
                &fixture.requester,
                2,
                HOSTED_TERMINAL_CURSOR_CONTEXT,
                Some(&cursor)
            )
            .await,
        Err(ServiceError::Store(StoreError::CursorExpired))
    ));
    let erased = fixture
        .service
        .store()
        .erase_expired_hosted_at(Utc::now())
        .await
        .expect("erase expired cursor");
    assert_eq!(erased.expired_cursors, 1);
    assert!(matches!(
        fixture
            .service
            .hosted_terminal_page(
                &fixture.requester,
                2,
                HOSTED_TERMINAL_CURSOR_CONTEXT,
                Some(&cursor)
            )
            .await,
        Err(ServiceError::Store(StoreError::CursorInvalid))
    ));

    fixture.database.execute(
        "INSERT INTO casework_hosted_cursors(cursor_id,issuer,subject,profile_id,context,expires_at) SELECT md5(('bounded-'||value)::text)::uuid,'issuer','subject','profile','context',now()-interval '1 second' FROM generate_series(1,101) value",
        &[],
    ).await.expect("seed more than one retention batch");
    let first_batch = fixture
        .service
        .erase_expired_hosted()
        .await
        .expect("first bounded cursor batch");
    assert_eq!(first_batch.expired_cursors, 100);
    let second_batch = fixture
        .service
        .erase_expired_hosted()
        .await
        .expect("second bounded cursor batch");
    assert_eq!(second_batch.expired_cursors, 1);

    let created = fixture
        .service
        .hosted_create(
            &fixture.requester,
            &create_request("batch-retention"),
            "create-retention",
        )
        .await
        .expect("create retention item");
    let noted = fixture
        .service
        .hosted_note(
            &fixture.requester,
            created.item_id,
            created.revision,
            &registry_casework_core::HostedNoteRequest {
                note: "requester note".to_owned(),
            },
            "note-retention",
        )
        .await
        .expect("note retention item");
    let requester_notes = fixture
        .service
        .hosted_requester_notes(&fixture.requester, created.item_id, 10, None)
        .await
        .expect("requester reads own note");
    assert_eq!(requester_notes.items[0].note, "requester note");
    let claimed = fixture
        .service
        .hosted_claim(
            &fixture.staff,
            created.item_id,
            noted.revision,
            "claim-retention",
        )
        .await
        .expect("claim retention item");
    let decided = fixture
        .service
        .hosted_decide(
            &fixture.staff,
            created.item_id,
            claimed.revision,
            &HostedDecisionRequest {
                outcome: "confirmed".to_owned(),
                reason: Some("internal reason".to_owned()),
            },
            "decide-retention",
        )
        .await
        .expect("decide retention item");
    let history = fixture
        .service
        .hosted_staff_history(&fixture.staff, created.item_id, 20, None)
        .await
        .expect("staff hosted history");
    assert!(history
        .items
        .iter()
        .any(|entry| entry.note.as_deref() == Some("requester note")));
    assert!(history
        .items
        .iter()
        .any(|entry| entry.outcome.as_deref() == Some("confirmed")
            && entry.reason.as_deref() == Some("internal reason")
            && entry.actor_ref.is_some()));
    let history_json = serde_json::to_string(&history).expect("history JSON");
    assert!(!history_json.contains("https://issuer.test"));
    assert!(!history_json.contains("staff\""));
    fixture.database.execute("UPDATE casework_hosted_items SET terminal_retained_until=now()-interval '1 second',accountability_retained_until=now()+interval '1 day' WHERE item_id=$1",&[&created.item_id]).await.expect("set item retention boundaries");
    fixture.database.execute("UPDATE casework_hosted_terminal_events SET retained_until=now()-interval '1 second' WHERE item_id=$1",&[&created.item_id]).await.expect("expire terminal event");
    let unpublished_audit_before: i64=fixture.database.query_one("SELECT count(*) FROM casework_audit_outbox WHERE audit_record->>'itemId'=$1 AND published_at IS NULL",&[&created.item_id.to_string()]).await.expect("count unpublished hosted audit").get(0);
    assert!(unpublished_audit_before > 0);
    assert!(matches!(
        fixture
            .service
            .hosted_create(
                &fixture.requester,
                &create_request("batch-retention"),
                "create-retention"
            )
            .await,
        Err(ServiceError::Store(StoreError::IdempotencyExpired))
    ));
    assert!(matches!(
        fixture
            .service
            .hosted_note(
                &fixture.requester,
                created.item_id,
                created.revision,
                &registry_casework_core::HostedNoteRequest {
                    note: "requester note".to_owned()
                },
                "note-retention"
            )
            .await,
        Err(ServiceError::Store(StoreError::IdempotencyExpired))
    ));
    assert!(matches!(
        fixture
            .service
            .hosted_claim(
                &fixture.staff,
                created.item_id,
                noted.revision,
                "claim-retention"
            )
            .await,
        Err(ServiceError::Store(StoreError::IdempotencyExpired))
    ));
    fixture
        .service
        .erase_expired_hosted()
        .await
        .expect("erase terminal payload");
    let item_count_before_expired_replay: i64 = fixture
        .database
        .query_one("SELECT count(*) FROM casework_hosted_items", &[])
        .await
        .expect("count items before expired replay")
        .get(0);
    assert!(matches!(
        fixture
            .service
            .hosted_create(
                &fixture.requester,
                &create_request("batch-retention"),
                "create-retention"
            )
            .await,
        Err(ServiceError::Store(StoreError::IdempotencyExpired))
    ));
    assert!(matches!(
        fixture
            .service
            .hosted_create(
                &fixture.requester,
                &create_request("changed-after-expiry"),
                "create-retention"
            )
            .await,
        Err(ServiceError::Store(StoreError::IdempotencyConflict))
    ));
    assert!(matches!(
        fixture
            .service
            .hosted_note(
                &fixture.requester,
                created.item_id,
                created.revision,
                &registry_casework_core::HostedNoteRequest {
                    note: "requester note".to_owned()
                },
                "note-retention"
            )
            .await,
        Err(ServiceError::Store(StoreError::IdempotencyExpired))
    ));
    assert!(matches!(
        fixture
            .service
            .hosted_claim(
                &fixture.staff,
                created.item_id,
                noted.revision,
                "claim-retention"
            )
            .await,
        Err(ServiceError::Store(StoreError::IdempotencyExpired))
    ));
    assert!(matches!(
        fixture
            .service
            .hosted_decide(
                &fixture.staff,
                created.item_id,
                claimed.revision,
                &HostedDecisionRequest {
                    outcome: "confirmed".to_owned(),
                    reason: Some("internal reason".to_owned())
                },
                "decide-retention"
            )
            .await,
        Err(ServiceError::Store(StoreError::IdempotencyExpired))
    ));
    let item_count_after_expired_replay: i64 = fixture
        .database
        .query_one("SELECT count(*) FROM casework_hosted_items", &[])
        .await
        .expect("count items after expired replay")
        .get(0);
    assert_eq!(
        item_count_after_expired_replay,
        item_count_before_expired_replay
    );
    let tombstones: i64 = fixture
        .database
        .query_one(
            "SELECT count(*) FROM casework_hosted_idempotency_tombstones",
            &[],
        )
        .await
        .expect("count bounded idempotency tombstones")
        .get(0);
    assert!(tombstones > 0);
    let tombstone_json: String = fixture
        .database
        .query_one(
            "SELECT string_agg(to_jsonb(t)::text,'') FROM casework_hosted_idempotency_tombstones t",
            &[],
        )
        .await
        .expect("inspect payload-free tombstones")
        .get(0);
    assert!(!tombstone_json.contains("https://issuer.test"));
    assert!(!tombstone_json.contains("batch-retention"));
    assert!(!tombstone_json.contains("internal reason"));
    let unpublished_audit_after: i64=fixture.database.query_one("SELECT count(*) FROM casework_audit_outbox WHERE audit_record->>'itemId'=$1 AND published_at IS NULL",&[&created.item_id.to_string()]).await.expect("count retained unpublished hosted audit").get(0);
    assert_eq!(unpublished_audit_after, unpublished_audit_before);
    assert!(matches!(
        fixture
            .service
            .hosted_requester_item(&fixture.requester, created.item_id)
            .await,
        Err(ServiceError::Store(StoreError::NotFound))
    ));
    let accountability = fixture
        .service
        .hosted_accountability_record(&fixture.supervisor, decided.event_id)
        .await
        .expect("accountability outlives terminal feed");
    assert_eq!(accountability.actor, fixture.staff.principal);
    assert_eq!(accountability.reason.as_deref(), Some("internal reason"));
    let revocation = fixture
        .database
        .transaction()
        .await
        .expect("supervisor revocation transaction");
    revocation.execute(
        "DELETE FROM casework_memberships WHERE team_id='batch-team' AND issuer=$1 AND subject=$2 AND membership_kind='supervisor'",
        &[&fixture.supervisor.principal.issuer,&fixture.supervisor.principal.subject],
    ).await.expect("lock and remove supervisor membership");
    let service = fixture.service.clone();
    let supervisor = fixture.supervisor.clone();
    let accountability_event_id = decided.event_id;
    let accountability_after_revoke = tokio::spawn(async move {
        service
            .hosted_accountability_record(&supervisor, accountability_event_id)
            .await
    });
    tokio::task::yield_now().await;
    revocation
        .commit()
        .await
        .expect("supervisor revocation commits first");
    assert!(matches!(
        accountability_after_revoke
            .await
            .expect("accountability read task"),
        Err(ServiceError::Store(StoreError::NotFound))
    ));
    fixture.database.execute("UPDATE casework_hosted_accountability SET retained_until=now()-interval '1 second' WHERE event_id=$1",&[&decided.event_id]).await.expect("expire accountability");
    fixture.database.execute("UPDATE casework_hosted_items SET accountability_retained_until=now()-interval '1 second' WHERE item_id=$1",&[&created.item_id]).await.expect("expire idempotency tombstone boundary");
    fixture.database.execute("UPDATE casework_hosted_idempotency_tombstones SET retained_until=now()-interval '1 second'",&[]).await.expect("expire tombstones at outer boundary");
    fixture
        .service
        .erase_expired_hosted()
        .await
        .expect("erase accountability");
    assert!(matches!(
        fixture
            .service
            .hosted_accountability_record(&fixture.supervisor, decided.event_id)
            .await,
        Err(ServiceError::Store(StoreError::NotFound))
    ));
    let retained_tombstones: i64 = fixture
        .database
        .query_one(
            "SELECT count(*) FROM casework_hosted_idempotency_tombstones",
            &[],
        )
        .await
        .expect("count erased tombstones")
        .get(0);
    assert_eq!(retained_tombstones, 0);
    let recreated = fixture
        .service
        .hosted_create(
            &fixture.requester,
            &create_request("batch-retention"),
            "create-retention",
        )
        .await
        .expect("outer retention boundary permits key reuse");
    assert_ne!(recreated.item_id, created.item_id);
    let accountability_read_audit: serde_json::Value=fixture.database.query_one("SELECT audit_record FROM casework_audit_outbox WHERE audit_record->>'event'='casework.hosted_accountability_read' ORDER BY event_id DESC LIMIT 1",&[]).await.expect("accountability read audit remains").get(0);
    assert_eq!(
        accountability_read_audit["actor"]["subject"],
        fixture.supervisor.principal.subject
    );
    let sensitive_rows: i64=fixture.database.query_one("SELECT count(*) FROM casework_hosted_items WHERE item_id=$1 AND (requester_issuer IS NOT NULL OR requester_reference IS NOT NULL OR display IS NOT NULL)",&[&created.item_id]).await.expect("inspect erased item").get(0);
    assert_eq!(sensitive_rows, 0);
}
