// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "../src/history_context.rs"]
mod history_context;
#[path = "../src/history_reference.rs"]
mod history_reference;
mod history_schema {
    pub use registry_server::history_schema::*;
}
mod model {
    pub use registry_server::model::*;
}
#[path = "../src/history_store.rs"]
#[allow(dead_code)]
mod history_store;
mod postgres {
    pub use registry_server::postgres::SqlIdentifier;
}
#[path = "../src/history_commit.rs"]
mod history_commit;
#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use serde_json::json;
use uuid::Uuid;

use history_commit::{
    allocate_revision_commit, capture_latest_snapshot_reference, install_empty_history_baseline,
    install_history_commit_schema, resolve_snapshot_reference, CommitAllocation,
    HistoryCommitError, RevisionCommitMember,
};
use history_context::{ChangeContext, CommitOrigin};
use history_reference::SnapshotReference;
use history_store::{install_history_schema_store, load_descriptor, retain_descriptor};
use postgres_harness::TestDatabase;
use registry_server::compiler::{compile_project, CompileProfile};
use registry_server::contract::parse_project_json;
use registry_server::mutation::install_mutation_schema;
use registry_server::postgres::{
    install_compiled_schema, managed_schema_fingerprint, ExpectedManagedCatalog,
    PostgresKernelError,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn history_schema_installs_append_only_runtime_privileges() {
    let database = TestDatabase::create(4).await;
    let (migration, migration_task) = database.connect_migration().await;
    install_mutation_schema(&migration, &database.runtime_role)
        .await
        .expect("mutation schema installs first");
    install_history_commit_schema(&migration, &database.runtime_role)
        .await
        .expect("history commit schema installs");
    install_history_commit_schema(&migration, &database.runtime_role)
        .await
        .expect("history commit schema is idempotent");

    let privileges = migration
        .query_one(
            "SELECT
                 has_table_privilege($1, 'registry_internal.registry_revisions', 'UPDATE'),
                 has_table_privilege($1, 'registry_internal.registry_revision_commits', 'INSERT'),
                 has_table_privilege($1, 'registry_internal.registry_revision_commits', 'UPDATE'),
                 has_table_privilege($1, 'registry_internal.registry_revision_commit_members', 'INSERT'),
                 has_column_privilege($1, 'registry_internal.registry_commit_head',
                     'latest_position', 'UPDATE'),
                 has_column_privilege($1, 'registry_internal.registry_commit_head',
                     'coverage_ready', 'UPDATE')",
            &[&database.runtime_role.as_str()],
        )
        .await
        .expect("migration can inspect runtime privileges");
    assert!(!privileges.get::<_, bool>(0));
    assert!(privileges.get::<_, bool>(1));
    assert!(!privileges.get::<_, bool>(2));
    assert!(privileges.get::<_, bool>(3));
    assert!(privileges.get::<_, bool>(4));
    assert!(!privileges.get::<_, bool>(5));

    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn catalog_column_acl_closure_rejects_extra_history_head_column_update() {
    let database = TestDatabase::create(4).await;
    let (migration, migration_task) = database.connect_migration().await;
    let registry = compiled_registry();
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("compiled schema installs with history foundation");
    let expected_catalog = ExpectedManagedCatalog::compiled(&registry);
    managed_schema_fingerprint(&migration, &database.runtime_role, &expected_catalog)
        .await
        .expect("exact history column grants are accepted");

    migration
        .batch_execute(&format!(
            "GRANT UPDATE (coverage_ready) ON registry_internal.registry_commit_head TO {}",
            quote_identifier(database.runtime_role.as_str())
        ))
        .await
        .expect("test can add an unexpected head column grant");
    assert!(matches!(
        managed_schema_fingerprint(&migration, &database.runtime_role, &expected_catalog).await,
        Err(PostgresKernelError::CatalogInvariant(
            "managed column privileges differ from the closed catalog"
        ))
    ));

    migration
        .batch_execute(&format!(
            "REVOKE UPDATE (coverage_ready) ON registry_internal.registry_commit_head FROM {role};
             GRANT UPDATE (snapshot) ON registry_internal.registry_revisions TO {role}",
            role = quote_identifier(database.runtime_role.as_str())
        ))
        .await
        .expect("test can attempt column-level journal mutation authority");
    assert!(matches!(
        managed_schema_fingerprint(&migration, &database.runtime_role, &expected_catalog).await,
        Err(PostgresKernelError::CatalogInvariant(
            "managed column privileges differ from the closed catalog"
        ))
    ));

    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn history_schema_store_is_runtime_select_only_and_retains_exact_bytes() {
    let database = TestDatabase::create(4).await;
    let (migration, migration_task) = database.connect_migration().await;
    install_history_schema_store(&migration, &database.runtime_role)
        .await
        .expect("history schema store installs");
    install_history_schema_store(&migration, &database.runtime_role)
        .await
        .expect("history schema store install is idempotent");

    let privileges = migration
        .query_one(
            "SELECT
                 has_table_privilege($1, 'registry_internal.registry_history_schemas', 'SELECT'),
                 has_table_privilege($1, 'registry_internal.registry_history_schemas', 'INSERT'),
                 has_table_privilege($1, 'registry_internal.registry_history_schemas', 'UPDATE'),
                 has_table_privilege($1, 'registry_internal.registry_history_schemas', 'DELETE')",
            &[&database.runtime_role.as_str()],
        )
        .await
        .expect("migration can inspect history schema privileges");
    assert!(privileges.get::<_, bool>(0));
    assert!(!privileges.get::<_, bool>(1));
    assert!(!privileges.get::<_, bool>(2));
    assert!(!privileges.get::<_, bool>(3));

    let registry = compiled_registry();
    let retained = retain_descriptor(&migration, &registry, "pkg-history-1")
        .await
        .expect("descriptor retention succeeds");
    let loaded = load_descriptor(&migration, "pkg-history-1")
        .await
        .expect("retained descriptor loads");
    assert_eq!(loaded, retained);
    retain_descriptor(&migration, &registry, "pkg-history-1")
        .await
        .expect("retaining identical bytes is idempotent");

    migration
        .execute(
            "UPDATE registry_internal.registry_history_schemas
                SET descriptor = '{}'::bytea
              WHERE package_revision = 'pkg-history-1'",
            &[],
        )
        .await
        .expect("migration can simulate a descriptor mismatch");
    assert!(
        retain_descriptor(&migration, &registry, "pkg-history-1")
            .await
            .is_err(),
        "descriptor retention must compare exact bytes and refuse overwrite"
    );

    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn empty_baseline_has_position_zero_reference_and_refuses_existing_rows() {
    let database = TestDatabase::create(4).await;
    let (mut migration, migration_task) = database.connect_migration().await;
    install_mutation_schema(&migration, &database.runtime_role)
        .await
        .expect("mutation schema installs first");
    install_history_commit_schema(&migration, &database.runtime_role)
        .await
        .expect("history commit schema installs");

    let existing_record_id = Uuid::parse_str("018feaa0-68f9-4a45-b9e3-58436df07af6").unwrap();
    let transaction = migration
        .transaction()
        .await
        .expect("migration can begin transaction");
    insert_revision(&transaction, "household_membership", existing_record_id, 1).await;
    assert_eq!(
        install_empty_history_baseline(&transaction, "pkg-1").await,
        Err(HistoryCommitError::NotReady)
    );
    transaction
        .rollback()
        .await
        .expect("existing-row baseline attempt rolls back");

    let transaction = migration
        .transaction()
        .await
        .expect("migration can begin transaction");
    let baseline = install_empty_history_baseline(&transaction, "pkg-1")
        .await
        .expect("empty baseline installs");
    assert_eq!(baseline.position, 0);
    assert_eq!(
        SnapshotReference::parse(&baseline.reference.to_string()).unwrap(),
        baseline.reference
    );
    let captured = capture_latest_snapshot_reference(&transaction)
        .await
        .expect("latest snapshot resolves to the empty baseline");
    assert_eq!(captured.position, 0);
    assert_eq!(captured.reference, baseline.reference);
    transaction
        .commit()
        .await
        .expect("baseline transaction commits");

    let transaction = migration
        .transaction()
        .await
        .expect("migration can begin transaction");
    assert_eq!(
        install_empty_history_baseline(&transaction, "pkg-1").await,
        Err(HistoryCommitError::InvalidInput)
    );
    transaction
        .rollback()
        .await
        .expect("second baseline attempt rolls back");

    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn commit_allocation_is_transactional_and_membership_fk_backed() {
    let database = TestDatabase::create(4).await;
    let (mut migration, migration_task) = database.connect_migration().await;
    install_foundation(&database, &mut migration).await;

    let record_id = Uuid::parse_str("018feaa0-68f9-4a45-b9e3-58436df07af7").unwrap();
    let transaction = migration
        .transaction()
        .await
        .expect("migration can begin transaction");
    insert_revision(&transaction, "household_membership", record_id, 1).await;
    let context = ChangeContext::parse_json(&json!({
        "kind": "correction",
        "reasonCode": "effective_date_corrected",
        "sourceReferences": ["case-document:review-204"]
    }))
    .unwrap();
    let member = RevisionCommitMember {
        entity_id: "household_membership",
        record_id,
        record_revision: 1,
    };
    let commit = allocate_revision_commit(
        &transaction,
        CommitAllocation {
            package_revision: "pkg-1",
            origin: CommitOrigin::Mutation {
                actor_reference: "actor:hash",
                request_reference: "request:hash",
            },
            change_context: Some(&context),
            members: &[member],
        },
    )
    .await
    .expect("commit allocation succeeds");
    assert_eq!(commit.position, 1);
    transaction
        .rollback()
        .await
        .expect("transaction with allocation can roll back");

    let counts = migration
        .query_one(
            "SELECT
                 (SELECT latest_position FROM registry_internal.registry_commit_head),
                 (SELECT count(*)::bigint FROM registry_internal.registry_revision_commits),
                 (SELECT count(*)::bigint FROM registry_internal.registry_revision_commit_members),
                 (SELECT count(*)::bigint FROM registry_internal.registry_revisions)",
            &[],
        )
        .await
        .expect("migration can inspect rollback state");
    assert_eq!(counts.get::<_, i64>(0), 0);
    assert_eq!(counts.get::<_, i64>(1), 1);
    assert_eq!(counts.get::<_, i64>(2), 0);
    assert_eq!(counts.get::<_, i64>(3), 0);

    let transaction = migration
        .transaction()
        .await
        .expect("migration can begin transaction");
    insert_revision(&transaction, "household_membership", record_id, 1).await;
    let member = RevisionCommitMember {
        entity_id: "household_membership",
        record_id,
        record_revision: 1,
    };
    let commit = allocate_revision_commit(
        &transaction,
        CommitAllocation {
            package_revision: "pkg-1",
            origin: CommitOrigin::Mutation {
                actor_reference: "actor:hash",
                request_reference: "request:hash",
            },
            change_context: Some(&context),
            members: &[member],
        },
    )
    .await
    .expect("commit allocation succeeds after rollback");
    let resolved = resolve_snapshot_reference(&transaction, commit.reference)
        .await
        .expect("fresh commit reference resolves in transaction");
    assert_eq!(resolved.position, 1);
    transaction
        .commit()
        .await
        .expect("commit allocation transaction commits");

    let stored_context = migration
        .query_one(
            "SELECT change_context, change_context_digest
               FROM registry_internal.registry_revision_commits
              WHERE commit_position = 1",
            &[],
        )
        .await
        .expect("migration can read stored context");
    assert_eq!(
        stored_context.get::<_, Vec<u8>>(0),
        context.canonical_bytes()
    );
    assert_eq!(
        stored_context.get::<_, Vec<u8>>(1),
        context.digest().to_vec()
    );

    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn paused_writer_cannot_enter_previously_captured_reference() {
    let database = TestDatabase::create(4).await;
    let (mut writer, writer_task) = database.connect_migration().await;
    install_foundation(&database, &mut writer).await;
    let (mut reader, reader_task) = database.connect_migration().await;

    let record_id = Uuid::parse_str("018feaa0-68f9-4a45-b9e3-58436df07af7").unwrap();
    let writer_transaction = writer
        .transaction()
        .await
        .expect("writer can begin transaction");
    insert_revision(&writer_transaction, "household_membership", record_id, 1).await;
    let member = RevisionCommitMember {
        entity_id: "household_membership",
        record_id,
        record_revision: 1,
    };
    let pending = allocate_revision_commit(
        &writer_transaction,
        CommitAllocation {
            package_revision: "pkg-1",
            origin: CommitOrigin::Mutation {
                actor_reference: "actor:hash",
                request_reference: "request:hash",
            },
            change_context: None,
            members: &[member],
        },
    )
    .await
    .expect("writer allocates an uncommitted commit");
    assert_eq!(pending.position, 1);

    let reader_transaction = reader
        .transaction()
        .await
        .expect("reader can begin transaction");
    let captured = capture_latest_snapshot_reference(&reader_transaction)
        .await
        .expect("reader captures latest committed reference");
    assert_eq!(captured.position, 0);
    reader_transaction
        .commit()
        .await
        .expect("reader transaction commits");

    writer_transaction
        .commit()
        .await
        .expect("paused writer commits later");
    let reader_transaction = reader
        .transaction()
        .await
        .expect("reader can begin transaction");
    let resolved = resolve_snapshot_reference(&reader_transaction, captured.reference)
        .await
        .expect("captured reference still resolves");
    assert_eq!(resolved.position, 0);
    let latest = capture_latest_snapshot_reference(&reader_transaction)
        .await
        .expect("latest now sees writer commit");
    assert_eq!(latest.position, 1);
    reader_transaction
        .commit()
        .await
        .expect("reader transaction commits");

    reader_task.abort();
    writer_task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_pilot_writers_keep_one_contiguous_committed_prefix() {
    const WRITERS: usize = 16;
    let database = TestDatabase::create(4).await;
    let (mut migration, migration_task) = database.connect_migration().await;
    install_foundation(&database, &mut migration).await;
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(WRITERS));
    let mut writers = Vec::new();
    for _ in 0..WRITERS {
        let (mut client, connection_task) = database.connect_migration().await;
        let barrier = barrier.clone();
        writers.push(tokio::spawn(async move {
            barrier.wait().await;
            let started = std::time::Instant::now();
            let transaction = client.transaction().await.expect("writer transaction");
            let record_id = Uuid::new_v4();
            insert_revision(&transaction, "household_membership", record_id, 1).await;
            let committed = allocate_revision_commit(
                &transaction,
                CommitAllocation {
                    package_revision: "pkg-1",
                    origin: CommitOrigin::Mutation {
                        actor_reference: "pilot:actor",
                        request_reference: "pilot:request",
                    },
                    change_context: None,
                    members: &[RevisionCommitMember {
                        entity_id: "household_membership",
                        record_id,
                        record_revision: 1,
                    }],
                },
            )
            .await
            .expect("competing writer allocates a commit");
            transaction
                .commit()
                .await
                .expect("competing writer commits");
            connection_task.abort();
            (committed.position, started.elapsed())
        }));
    }
    let mut positions = Vec::new();
    let mut durations = Vec::new();
    for writer in writers {
        let (position, duration) = tokio::time::timeout(std::time::Duration::from_secs(30), writer)
            .await
            .expect("bounded competing writer completion")
            .expect("writer task succeeds");
        positions.push(position);
        durations.push(duration);
    }
    positions.sort_unstable();
    durations.sort_unstable();
    assert_eq!(positions, (1..=WRITERS as i64).collect::<Vec<_>>());
    let state = migration
        .query_one(
            "SELECT latest_position,
                    (SELECT count(*) FROM registry_internal.registry_revision_commit_members)
               FROM registry_internal.registry_commit_head WHERE singleton",
            &[],
        )
        .await
        .expect("committed prefix can be checked");
    assert_eq!(state.get::<_, i64>(0), WRITERS as i64);
    assert_eq!(state.get::<_, i64>(1), WRITERS as i64);
    eprintln!(
        "history pilot: {WRITERS} concurrent one-record commits, median={}ms, max={}ms",
        durations[WRITERS / 2].as_millis(),
        durations[WRITERS - 1].as_millis()
    );
    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn reference_resolution_refuses_unknown_future_and_unavailable_history() {
    let database = TestDatabase::create(4).await;
    let (mut migration, migration_task) = database.connect_migration().await;
    install_foundation(&database, &mut migration).await;

    let transaction = migration
        .transaction()
        .await
        .expect("migration can begin transaction");
    assert_eq!(
        resolve_snapshot_reference(&transaction, SnapshotReference::new_random()).await,
        Err(HistoryCommitError::UnknownReference)
    );
    let head_lineage: Uuid = transaction
        .query_one(
            "SELECT history_lineage FROM registry_internal.registry_commit_head",
            &[],
        )
        .await
        .expect("head lineage is available")
        .get(0);
    let future_reference = SnapshotReference::new_random();
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_revision_commits
                 (commit_position, change_id, snapshot_reference, history_lineage,
                  originating_package_revision, origin_kind, system_origin,
                  establishes_baseline)
             VALUES (5, $1, $2, $3, 'pkg-1', 'baseline',
                     'registry-server-test-baseline', true)",
            &[&Uuid::new_v4(), &future_reference.uuid(), &head_lineage],
        )
        .await
        .expect("test can insert a future commit row");
    assert_eq!(
        resolve_snapshot_reference(&transaction, future_reference).await,
        Err(HistoryCommitError::FutureReference)
    );
    transaction.rollback().await.expect("future row rolls back");

    let record_id = Uuid::parse_str("018feaa0-68f9-4a45-b9e3-58436df07af7").unwrap();
    let transaction = migration
        .transaction()
        .await
        .expect("migration can begin transaction");
    insert_revision(&transaction, "household_membership", record_id, 1).await;
    let member = RevisionCommitMember {
        entity_id: "household_membership",
        record_id,
        record_revision: 1,
    };
    let committed = allocate_revision_commit(
        &transaction,
        CommitAllocation {
            package_revision: "pkg-1",
            origin: CommitOrigin::Mutation {
                actor_reference: "actor:hash",
                request_reference: "request:hash",
            },
            change_context: None,
            members: &[member],
        },
    )
    .await
    .expect("commit allocation succeeds");
    transaction
        .commit()
        .await
        .expect("commit allocation commits");

    let transaction = migration
        .transaction()
        .await
        .expect("migration can begin transaction");
    transaction
        .execute(
            "UPDATE registry_internal.registry_commit_head
                SET unavailable_after_position = 0
              WHERE singleton",
            &[],
        )
        .await
        .expect("maintenance can shrink availability");
    transaction
        .commit()
        .await
        .expect("availability update commits");
    let transaction = migration
        .transaction()
        .await
        .expect("migration can begin transaction");
    assert_eq!(
        resolve_snapshot_reference(&transaction, committed.reference).await,
        Err(HistoryCommitError::Unavailable)
    );
    let baseline_uuid: Uuid = transaction
        .query_one(
            "SELECT snapshot_reference
               FROM registry_internal.registry_revision_commits
              WHERE commit_position = 0",
            &[],
        )
        .await
        .expect("baseline reference can be loaded")
        .get(0);
    let baseline =
        resolve_snapshot_reference(&transaction, SnapshotReference::for_uuid(baseline_uuid))
            .await
            .expect("baseline remains available at boundary");
    assert_eq!(baseline.position, 0);
    assert_eq!(
        capture_latest_snapshot_reference(&transaction).await,
        Err(HistoryCommitError::Unavailable)
    );
    transaction
        .commit()
        .await
        .expect("baseline resolution commits");

    migration_task.abort();
    database.cleanup().await;
}

async fn install_foundation(database: &TestDatabase, migration: &mut tokio_postgres::Client) {
    install_mutation_schema(migration, &database.runtime_role)
        .await
        .expect("mutation schema installs");
    install_history_commit_schema(migration, &database.runtime_role)
        .await
        .expect("history commit schema installs");
    let transaction = migration
        .transaction()
        .await
        .expect("migration can begin transaction");
    install_empty_history_baseline(&transaction, "pkg-1")
        .await
        .expect("empty baseline installs");
    transaction
        .commit()
        .await
        .expect("baseline transaction commits");
}

async fn insert_revision(
    transaction: &tokio_postgres::Transaction<'_>,
    entity_id: &str,
    record_id: Uuid,
    revision: i64,
) {
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_revisions
                 (entity_id, record_id, record_reference, record_revision,
                  predecessor_revision, record_lifecycle, package_revision, operation_id,
                  mutation_kind, principal_reference, request_reference, snapshot)
             VALUES ($1, $2, $3, $4, NULL, 'active', 'pkg-1', 'op-1',
                     'create', 'actor:hash', 'request:hash', '{}'::bytea)",
            &[
                &entity_id,
                &record_id,
                &format!("{entity_id}:{record_id}"),
                &revision,
            ],
        )
        .await
        .expect("test revision inserts");
}

fn compiled_registry() -> registry_server::CompiledRegistry {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"history-store-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "entities":[{
            "id":"membership",
            "route":"memberships",
            "mutationMode":"mutable",
            "tombstone":true,
            "classification":"restricted",
            "fields":[
              {"id":"person","type":"uuid","required":true,"classification":"internal"},
              {"id":"household","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"},
              {"id":"valid-from","type":"date","required":true,"classification":"internal"},
              {"id":"valid-to","type":"date","required":false,"classification":"internal"}
            ],
            "temporal":{"startField":"valid-from","endField":"valid-to"}
          }],
          "accessProfiles":[{
            "id":"writer",
            "default":true,
            "principalClaim":"registry_principal",
            "requiredPurposes":["operations"],
            "grants":[{
              "entity":"membership",
              "operations":["create","get","list","patch"],
              "readableFields":["person","household","valid-from","valid-to"],
              "writableFields":["person","household","valid-from","valid-to"]
            }]
          }]
        }"#,
    )
    .expect("history store fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring)
        .expect("history store fixture compiles")
}

fn quote_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}
