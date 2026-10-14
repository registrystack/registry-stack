//! Directory, absence and cursor security without a parallel work lifecycle.
use chrono::{TimeDelta, Utc};
use registry_casework::{CaseworkService, DatabaseConfig, PostgresStore, ServiceError, StoreError};
use registry_casework_core::*;
use registry_platform_config::{SecretProvider, SecretResolver};
use serde_json::json;
use std::{collections::BTreeSet, env};
use tokio_postgres::NoTls;
use uuid::Uuid;
const QUEUE: &str = "review";
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

fn profile(id: &str, role: CaseworkRole) -> AccessProfile {
    AccessProfile {
        id: id.to_owned(),
        principal_claim: "sub".to_owned(),
        required_scopes: vec![format!("casework:{id}")],
        role,
    }
}

fn project() -> CaseworkProject {
    CaseworkProject {
        task_templates: Vec::new(),
        api_version: registry_casework_core::CASEWORK_API_VERSION.to_owned(),
        kind: registry_casework_core::CASEWORK_KIND.to_owned(),
        project: ProjectIdentity {
            id: "assignment-test".parse().unwrap(),
            version: "1".to_owned(),
        },
        access_profiles: vec![
            profile("staff", CaseworkRole::Staff),
            profile("supervisor", CaseworkRole::Supervisor),
            profile("administrator", CaseworkRole::Administrator),
            profile("requester", CaseworkRole::Requester),
        ],
        queues: vec![QueuePolicy {
            id: QUEUE.to_owned(),
            label: "Review".to_owned(),
        }],
        teams:vec![serde_json::from_value(json!({"id":"review-team","label":"Review team","serves":[QUEUE],"memberProfiles":["staff"],"supervisorProfiles":["supervisor"]})).unwrap()],
        context_providers:Vec::new(),review_policies:Vec::new(),trusted_producers:Vec::new(),
        calendars: Vec::new(),
        clocks: Vec::new(),
        inbox: InboxPolicy::default(),
    }
}

async fn fixture() -> Fixture {
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
    let migration = PostgresStore::connect_migration(&config, &secrets)
        .expect("migration store")
        .with_audit(registry_casework::CaseworkAudit::capture().0);
    migration.migrate().await.expect("assignment migrations");
    let store = PostgresStore::connect_runtime(&config, &secrets)
        .expect("runtime store")
        .with_audit(registry_casework::CaseworkAudit::capture().0);
    let administrator = actor(
        "administrator",
        CaseworkRole::Administrator,
        "administrator",
    );
    let staff_a = actor("staff-a", CaseworkRole::Staff, "staff");
    let staff_b = actor("staff-b", CaseworkRole::Staff, "staff");
    let staff_c = actor("staff-c", CaseworkRole::Staff, "staff");
    let supervisor = actor("supervisor", CaseworkRole::Supervisor, "supervisor");
    let service =
        CaseworkService::new(store.clone(), project(), Vec::new()).expect("directory service");
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
    let fixture = fixture().await;
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
    let fixture = fixture().await;
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
    let fixture = fixture().await;
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

#[tokio::test]
async fn directory_targets_are_paged_query_bound_and_recheck_current_authority() {
    let fixture = fixture().await;

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
    let fixture = fixture().await;
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
    let fixture = fixture().await;
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
    let fixture = fixture().await;
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
async fn absence_update_preserves_owner_and_delete_replay_rechecks_current_authority() {
    let fixture = fixture().await;
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
async fn invalid_absence_input_refuses_before_mutation() {
    let fixture = fixture().await;
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
}

#[tokio::test]
async fn directory_cursor_retention_deletes_expired_rows_in_bounded_batches() {
    let fixture = fixture().await;
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
    let fixture = fixture().await;
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
    let fixture = fixture().await;
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
    let fixture = fixture().await;
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
    let fixture = fixture().await;
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
