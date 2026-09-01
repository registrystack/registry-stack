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
mod history_store;
mod postgres {
    pub use registry_server::postgres::{ClaimContext, SqlIdentifier};
}
#[path = "../src/history_commit.rs"]
mod history_commit;
#[path = "../src/idempotency.rs"]
mod idempotency;
#[path = "support/postgres_harness.rs"]
mod postgres_harness;

use std::time::Duration;

use registry_platform_audit::AuditProfile;
use serde_json::json;
use uuid::Uuid;

use history_commit::{
    allocate_revision_commit, install_empty_history_baseline, resolve_snapshot_reference,
    CommitAllocation, HistoryCommitError, RevisionCommitMember,
};
use history_context::{ChangeContext, CommitOrigin};
use history_reference::SnapshotReference;
use history_store::retain_descriptor;
use postgres_harness::TestDatabase;
use registry_server::compiler::{compile_project, CompileProfile};
use registry_server::contract::parse_project_json;
use registry_server::history_erasure::{
    erase_record_history, HistoryErasureRequest, HistoryErasureTimeouts, RecordHistoryErasureTarget,
};
use registry_server::mutation::install_mutation_schema;
use registry_server::postgres::{
    install_compiled_schema, managed_schema_fingerprint, ExpectedManagedCatalog,
    ExpectedRegistryIdentity, RegistryLockKey,
};

const ENTITY: &str = "membership";
const OLD_PACKAGE: &str = "pkg-erasure-old";
const CURRENT_PACKAGE: &str = "pkg-erasure-current";
const RECORD_CANARY: &str = "018feaa0-68f9-4a45-b9e3-58436df07af7";
const REASON_CANARY: &str = "source reason must not enter maintenance audit";
const OPERATOR_CANARY: &str = "operator secret must not enter maintenance audit";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn audited_erasure_deletes_targeted_history_and_makes_bookmark_unavailable() {
    let database = TestDatabase::create(4).await;
    let (mut migration, migration_task) = database.connect_migration().await;
    let registry = compiled_registry();
    let expected = install_ready_history_registry(&database, &mut migration, &registry).await;
    let lock_key = RegistryLockKey::derive(&expected.package_id).expect("lock key derives");
    let audit_profile = AuditProfile::production_from_secret_bytes(vec![0x71; 32].into())
        .expect("test owns a keyed audit profile");
    let record_id = Uuid::parse_str(RECORD_CANARY).unwrap();

    let transaction = migration
        .transaction()
        .await
        .expect("migration can begin transaction");
    insert_revision(&transaction, record_id, 1, OLD_PACKAGE, "create").await;
    insert_revision(&transaction, record_id, 2, CURRENT_PACKAGE, "patch").await;
    insert_outbox_payload(&transaction, record_id, 1).await;
    let first_context = ChangeContext::parse_json(&json!({
        "kind": "correction",
        "reasonCode": "effective_date_corrected",
        "reasonText": REASON_CANARY,
        "sourceReferences": ["case-document:erasure-proof"]
    }))
    .unwrap();
    let first_commit = allocate_revision_commit(
        &transaction,
        CommitAllocation {
            package_revision: OLD_PACKAGE,
            origin: CommitOrigin::Mutation {
                actor_reference: "actor:hash",
                request_reference: "request:hash",
            },
            change_context: Some(&first_context),
            members: &[RevisionCommitMember {
                entity_id: ENTITY,
                record_id,
                record_revision: 1,
            }],
        },
    )
    .await
    .expect("first commit is indexed");
    let second_commit = allocate_revision_commit(
        &transaction,
        CommitAllocation {
            package_revision: CURRENT_PACKAGE,
            origin: CommitOrigin::Mutation {
                actor_reference: "actor:hash",
                request_reference: "request:hash",
            },
            change_context: None,
            members: &[RevisionCommitMember {
                entity_id: ENTITY,
                record_id,
                record_revision: 2,
            }],
        },
    )
    .await
    .expect("second commit is indexed");
    insert_idempotency_response(
        &transaction,
        "record-key",
        "record-binding",
        "record",
        Some(&format!("{ENTITY}:{record_id}")),
        Some(1),
        None,
        json!({
            "id": record_id.to_string(),
            "revision": 1,
            "data": {"household": "cached-record-canary"}
        }),
    )
    .await;
    insert_idempotency_response(
        &transaction,
        "batch-snapshot-key",
        "batch-snapshot-binding",
        "batch",
        None,
        None,
        Some(1),
        json!({
            "snapshot": first_commit.reference.to_string(),
            "results": [{
                "id": record_id.to_string(),
                "revision": 1,
                "data": {"household": "cached-batch-snapshot-canary"}
            }]
        }),
    )
    .await;
    insert_idempotency_response(
        &transaction,
        "batch-prehistory-key",
        "batch-prehistory-binding",
        "batch",
        None,
        None,
        Some(1),
        json!({
            "results": [{
                "id": record_id.to_string(),
                "revision": 1,
                "data": {"household": "cached-batch-prehistory-canary"}
            }]
        }),
    )
    .await;
    transaction.commit().await.expect("history commits");

    let outcome = erase_record_history(
        &mut migration,
        HistoryErasureRequest {
            expected: &expected,
            migration_role: &database.migration_role,
            lock_key,
            timeouts: HistoryErasureTimeouts::new(Duration::from_secs(5), Duration::from_secs(5))
                .unwrap(),
            audit_profile: &audit_profile,
            operator_reference: OPERATOR_CANARY,
            reason: REASON_CANARY,
            target: RecordHistoryErasureTarget::new(ENTITY, record_id, 1),
        },
    )
    .await
    .expect("targeted erasure succeeds");

    assert!(outcome.coverage_ready);
    assert_eq!(outcome.unavailable_after_position, Some(0));
    assert_eq!(outcome.affected_commit_count, 1);
    assert_eq!(outcome.erased_revision_count, 1);
    assert_eq!(outcome.erased_commit_member_count, 1);
    assert_eq!(outcome.scrubbed_change_context_count, 1);
    assert_eq!(outcome.scrubbed_outbox_payload_count, 1);
    assert_eq!(outcome.scrubbed_cached_response_count, 3);
    assert_eq!(outcome.removed_descriptor_count, 1);

    let erased_response_body = b"{\"kind\":\"erased\"}".as_slice();
    let empty_response_headers = vec![0_u8, 0_u8];
    let state = migration
        .query_one(
            "SELECT
                 (SELECT count(*)::bigint FROM registry_internal.registry_revisions
                   WHERE entity_id = $1 AND record_id = $2 AND record_revision = 1),
                 (SELECT count(*)::bigint FROM registry_internal.registry_revision_commit_members
                   WHERE entity_id = $1 AND record_id = $2 AND record_revision = 1),
                 (SELECT change_context IS NULL AND change_context_digest IS NULL
                    FROM registry_internal.registry_revision_commits
                   WHERE commit_position = 1),
                 (SELECT payload IS NULL FROM registry_internal.registry_outbox
                   WHERE entity_id = $1 AND record_revision = 1),
                 (SELECT count(*)::bigint FROM registry_internal.registry_history_schemas
                   WHERE package_revision = $3),
                 (SELECT count(*)::bigint FROM registry_internal.registry_history_schemas
                   WHERE package_revision = $4),
                 (SELECT count(*)::bigint FROM registry_internal.registry_revisions
                   WHERE entity_id = $1 AND record_id = $2 AND record_revision = 2),
                 (SELECT count(*)::bigint FROM registry_internal.registry_idempotency
                   WHERE result_kind = 'erased'
                     AND record_reference IS NULL
                     AND record_revision IS NULL
                     AND result_count IS NULL
                     AND response_body = $5
                     AND response_headers = $6)",
            &[
                &ENTITY,
                &record_id,
                &OLD_PACKAGE,
                &CURRENT_PACKAGE,
                &erased_response_body,
                &empty_response_headers,
            ],
        )
        .await
        .expect("migration can inspect erasure result");
    assert_eq!(state.get::<_, i64>(0), 0);
    assert_eq!(state.get::<_, i64>(1), 0);
    assert!(state.get::<_, bool>(2));
    assert!(state.get::<_, bool>(3));
    assert_eq!(state.get::<_, i64>(4), 0);
    assert_eq!(state.get::<_, i64>(5), 1);
    assert_eq!(state.get::<_, i64>(6), 1);
    assert_eq!(state.get::<_, i64>(7), 3);

    let transaction = migration
        .transaction()
        .await
        .expect("migration can begin transaction");
    assert_eq!(
        resolve_snapshot_reference(&transaction, first_commit.reference).await,
        Err(HistoryCommitError::Unavailable),
        "the directly erased bookmark cannot resurrect deleted history"
    );
    assert_eq!(
        resolve_snapshot_reference(&transaction, second_commit.reference).await,
        Err(HistoryCommitError::Unavailable),
        "the coarse coverage cutoff refuses newer bookmarks until an exact retained boundary exists"
    );
    let baseline_uuid: Uuid = transaction
        .query_one(
            "SELECT snapshot_reference
               FROM registry_internal.registry_revision_commits
              WHERE commit_position = 0",
            &[],
        )
        .await
        .expect("baseline reference remains stored")
        .get(0);
    resolve_snapshot_reference(&transaction, SnapshotReference::for_uuid(baseline_uuid))
        .await
        .expect("baseline remains available");
    let replay = idempotency::lock_and_load(
        &transaction,
        &idempotency::ResolvedIdempotencyBinding {
            key_reference: "record-key".to_owned(),
            binding_reference: "record-binding".to_owned(),
            principal_reference: "principal".to_owned(),
            record_reference: format!("{ENTITY}:{record_id}"),
        },
    )
    .await;
    assert!(
        matches!(replay, Err(idempotency::IdempotencyError::Unavailable)),
        "erased idempotency tombstones refuse replay before releasing cached bytes"
    );
    transaction.commit().await.expect("resolution commits");

    assert_erasure_audit_is_minimized(&database, &audit_profile).await;

    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn erasure_uses_migration_authority_without_runtime_journal_mutation_grants() {
    let mut database = TestDatabase::create(4).await;
    let (mut migration, migration_task) = database.connect_migration().await;
    let registry = compiled_registry();
    let expected = install_ready_history_registry(&database, &mut migration, &registry).await;
    let lock_key = RegistryLockKey::derive(&expected.package_id).expect("lock key derives");
    let audit_profile = AuditProfile::production_from_secret_bytes(vec![0x72; 32].into())
        .expect("test owns a keyed audit profile");
    let record_id = Uuid::parse_str("018feaa0-68f9-4a45-b9e3-58436df07af8").unwrap();

    let transaction = migration
        .transaction()
        .await
        .expect("migration can begin transaction");
    insert_revision(&transaction, record_id, 1, CURRENT_PACKAGE, "create").await;
    allocate_revision_commit(
        &transaction,
        CommitAllocation {
            package_revision: CURRENT_PACKAGE,
            origin: CommitOrigin::Mutation {
                actor_reference: "actor:hash",
                request_reference: "request:hash",
            },
            change_context: None,
            members: &[RevisionCommitMember {
                entity_id: ENTITY,
                record_id,
                record_revision: 1,
            }],
        },
    )
    .await
    .expect("commit is indexed");
    transaction.commit().await.expect("history commits");

    let runtime_transaction = database
        .admin
        .transaction()
        .await
        .expect("admin can begin runtime-role inspection");
    runtime_transaction
        .batch_execute(&format!(
            "SET LOCAL ROLE \"{}\"",
            database.runtime_role.as_str()
        ))
        .await
        .expect("admin can inspect as runtime role");
    let runtime_privileges = runtime_transaction
        .query_one(
            "SELECT
                 has_table_privilege(current_user, 'registry_internal.registry_revisions', 'UPDATE'),
                 has_table_privilege(current_user, 'registry_internal.registry_revisions', 'DELETE'),
                 has_table_privilege(current_user, 'registry_internal.registry_revision_commits', 'UPDATE'),
                 has_table_privilege(current_user, 'registry_internal.registry_revision_commit_members', 'DELETE'),
                 has_table_privilege(current_user, 'registry_internal.registry_history_schemas', 'DELETE')",
            &[],
        )
        .await
        .expect("runtime can inspect its own privileges");
    for index in 0..5 {
        assert!(!runtime_privileges.get::<_, bool>(index));
    }
    assert!(
        runtime_transaction
            .execute(
                "DELETE FROM registry_internal.registry_revisions
                  WHERE entity_id = 'membership'",
                &[],
            )
            .await
            .is_err(),
        "runtime cannot perform the erasure journal delete"
    );
    runtime_transaction
        .rollback()
        .await
        .expect("runtime-role inspection rolls back");

    erase_record_history(
        &mut migration,
        HistoryErasureRequest {
            expected: &expected,
            migration_role: &database.migration_role,
            lock_key,
            timeouts: HistoryErasureTimeouts::new(Duration::from_secs(5), Duration::from_secs(5))
                .unwrap(),
            audit_profile: &audit_profile,
            operator_reference: "operator-run-2",
            reason: "test retention request",
            target: RecordHistoryErasureTarget::new(ENTITY, record_id, 1),
        },
    )
    .await
    .expect("migration authority can run the bounded erasure");

    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn erasing_baseline_member_marks_all_history_coverage_unready_and_allows_later_erasure() {
    let database = TestDatabase::create(4).await;
    let (mut migration, migration_task) = database.connect_migration().await;
    let registry = compiled_registry();
    let expected = install_ready_history_registry(&database, &mut migration, &registry).await;
    let lock_key = RegistryLockKey::derive(&expected.package_id).expect("lock key derives");
    let audit_profile = AuditProfile::production_from_secret_bytes(vec![0x73; 32].into())
        .expect("test owns a keyed audit profile");
    let record_id = Uuid::parse_str("018feaa0-68f9-4a45-b9e3-58436df07af9").unwrap();

    let transaction = migration
        .transaction()
        .await
        .expect("migration can begin transaction");
    insert_revision(&transaction, record_id, 1, OLD_PACKAGE, "migration").await;
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_revision_commit_members
                 (commit_position, member_index, entity_id, record_id, record_revision)
             VALUES (0, 0, $1, $2, 1)",
            &[&ENTITY, &record_id],
        )
        .await
        .expect("baseline member inserts");
    transaction.commit().await.expect("baseline member commits");

    let outcome = erase_record_history(
        &mut migration,
        HistoryErasureRequest {
            expected: &expected,
            migration_role: &database.migration_role,
            lock_key,
            timeouts: HistoryErasureTimeouts::new(Duration::from_secs(5), Duration::from_secs(5))
                .unwrap(),
            audit_profile: &audit_profile,
            operator_reference: "operator-run-3",
            reason: "baseline retention request",
            target: RecordHistoryErasureTarget::new(ENTITY, record_id, 1),
        },
    )
    .await
    .expect("baseline-member erasure succeeds");
    assert!(!outcome.coverage_ready);
    assert_eq!(outcome.unavailable_after_position, None);
    assert_eq!(outcome.affected_commit_count, 1);
    assert_eq!(outcome.erased_revision_count, 1);

    let transaction = migration
        .transaction()
        .await
        .expect("migration can begin transaction");
    let baseline_uuid: Uuid = transaction
        .query_one(
            "SELECT snapshot_reference
               FROM registry_internal.registry_revision_commits
              WHERE commit_position = 0",
            &[],
        )
        .await
        .expect("baseline reference remains stored")
        .get(0);
    assert_eq!(
        resolve_snapshot_reference(&transaction, SnapshotReference::for_uuid(baseline_uuid)).await,
        Err(HistoryCommitError::Unavailable),
        "coverage_ready=false refuses every exact bookmark after a baseline erasure"
    );
    insert_revision(&transaction, record_id, 2, CURRENT_PACKAGE, "patch").await;
    allocate_revision_commit(
        &transaction,
        CommitAllocation {
            package_revision: CURRENT_PACKAGE,
            origin: CommitOrigin::Mutation {
                actor_reference: "actor:hash",
                request_reference: "request:hash",
            },
            change_context: None,
            members: &[RevisionCommitMember {
                entity_id: ENTITY,
                record_id,
                record_revision: 2,
            }],
        },
    )
    .await
    .expect("future write can still allocate a commit");
    transaction.commit().await.expect("future commit persists");

    let follow_up = erase_record_history(
        &mut migration,
        HistoryErasureRequest {
            expected: &expected,
            migration_role: &database.migration_role,
            lock_key,
            timeouts: HistoryErasureTimeouts::new(Duration::from_secs(5), Duration::from_secs(5))
                .unwrap(),
            audit_profile: &audit_profile,
            operator_reference: "operator-run-3",
            reason: "follow-up retention request",
            target: RecordHistoryErasureTarget::new(ENTITY, record_id, 2),
        },
    )
    .await
    .expect("further erasure succeeds while coverage is unready");
    assert!(!follow_up.coverage_ready);
    assert_eq!(follow_up.erased_revision_count, 1);

    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn prebaseline_unindexed_revision_is_erased_and_marks_coverage_unready() {
    let database = TestDatabase::create(4).await;
    let (mut migration, migration_task) = database.connect_migration().await;
    let registry = compiled_registry();
    let expected = install_ready_history_registry(&database, &mut migration, &registry).await;
    let lock_key = RegistryLockKey::derive(&expected.package_id).expect("lock key derives");
    let audit_profile = AuditProfile::production_from_secret_bytes(vec![0x74; 32].into())
        .expect("test owns a keyed audit profile");
    let record_id = Uuid::parse_str("018feaa0-68f9-4a45-b9e3-58436df07afa").unwrap();

    let transaction = migration
        .transaction()
        .await
        .expect("migration can begin transaction");
    insert_revision(&transaction, record_id, 1, OLD_PACKAGE, "migration").await;
    transaction
        .commit()
        .await
        .expect("unindexed revision commits");

    let outcome = erase_record_history(
        &mut migration,
        HistoryErasureRequest {
            expected: &expected,
            migration_role: &database.migration_role,
            lock_key,
            timeouts: HistoryErasureTimeouts::new(Duration::from_secs(5), Duration::from_secs(5))
                .unwrap(),
            audit_profile: &audit_profile,
            operator_reference: "operator-run-4",
            reason: "prebaseline retention request",
            target: RecordHistoryErasureTarget::new(ENTITY, record_id, 1),
        },
    )
    .await
    .expect("unindexed prebaseline erasure succeeds");
    assert!(!outcome.coverage_ready);
    assert_eq!(outcome.unavailable_after_position, None);
    assert_eq!(outcome.affected_commit_count, 0);
    assert_eq!(outcome.erased_revision_count, 1);

    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sparse_high_revision_number_erases_when_actual_target_count_is_bounded() {
    let database = TestDatabase::create(4).await;
    let (mut migration, migration_task) = database.connect_migration().await;
    let registry = compiled_registry();
    let expected = install_ready_history_registry(&database, &mut migration, &registry).await;
    let lock_key = RegistryLockKey::derive(&expected.package_id).expect("lock key derives");
    let audit_profile = AuditProfile::production_from_secret_bytes(vec![0x75; 32].into())
        .expect("test owns a keyed audit profile");
    let record_id = Uuid::parse_str("018feaa0-68f9-4a45-b9e3-58436df07afb").unwrap();

    let transaction = migration
        .transaction()
        .await
        .expect("migration can begin transaction");
    insert_revision(&transaction, record_id, 10_001, OLD_PACKAGE, "migration").await;
    transaction
        .commit()
        .await
        .expect("sparse high revision commits");

    let outcome = erase_record_history(
        &mut migration,
        HistoryErasureRequest {
            expected: &expected,
            migration_role: &database.migration_role,
            lock_key,
            timeouts: HistoryErasureTimeouts::new(Duration::from_secs(5), Duration::from_secs(5))
                .unwrap(),
            audit_profile: &audit_profile,
            operator_reference: "operator-run-5",
            reason: "sparse high revision request",
            target: RecordHistoryErasureTarget::new(ENTITY, record_id, 10_001),
        },
    )
    .await
    .expect("sparse high revision erasure succeeds");
    assert!(!outcome.coverage_ready);
    assert_eq!(outcome.erased_revision_count, 1);

    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn erasure_refuses_more_than_ten_thousand_actual_target_revisions() {
    let database = TestDatabase::create(4).await;
    let (mut migration, migration_task) = database.connect_migration().await;
    let registry = compiled_registry();
    let expected = install_ready_history_registry(&database, &mut migration, &registry).await;
    let lock_key = RegistryLockKey::derive(&expected.package_id).expect("lock key derives");
    let audit_profile = AuditProfile::production_from_secret_bytes(vec![0x76; 32].into())
        .expect("test owns a keyed audit profile");
    let record_id = Uuid::parse_str("018feaa0-68f9-4a45-b9e3-58436df07afc").unwrap();

    let transaction = migration
        .transaction()
        .await
        .expect("migration can begin transaction");
    insert_revision_range(&transaction, record_id, 10_001).await;
    transaction
        .commit()
        .await
        .expect("large retained revision set commits");

    let result = erase_record_history(
        &mut migration,
        HistoryErasureRequest {
            expected: &expected,
            migration_role: &database.migration_role,
            lock_key,
            timeouts: HistoryErasureTimeouts::new(Duration::from_secs(5), Duration::from_secs(5))
                .unwrap(),
            audit_profile: &audit_profile,
            operator_reference: "operator-run-6",
            reason: "oversized actual revision request",
            target: RecordHistoryErasureTarget::new(ENTITY, record_id, 10_001),
        },
    )
    .await;
    assert_eq!(
        result,
        Err(registry_server::history_erasure::HistoryErasureError::InvalidInput)
    );
    let remaining: i64 = migration
        .query_one(
            "SELECT count(*)::bigint
               FROM registry_internal.registry_revisions
              WHERE entity_id = $1
                AND record_id = $2",
            &[&ENTITY, &record_id],
        )
        .await
        .expect("migration can inspect retained revisions")
        .get(0);
    assert_eq!(remaining, 10_001);

    migration_task.abort();
    database.cleanup().await;
}

async fn install_ready_history_registry(
    database: &TestDatabase,
    migration: &mut tokio_postgres::Client,
    registry: &registry_server::CompiledRegistry,
) -> ExpectedRegistryIdentity {
    install_compiled_schema(migration, registry, &database.runtime_role)
        .await
        .expect("compiled schema installs");
    retain_descriptor(migration, registry, OLD_PACKAGE)
        .await
        .expect("old descriptor is retained");
    retain_descriptor(migration, registry, CURRENT_PACKAGE)
        .await
        .expect("current descriptor is retained");
    install_mutation_schema(migration, &database.runtime_role)
        .await
        .expect("mutation and history commit schema are installed");
    let transaction = migration
        .transaction()
        .await
        .expect("migration can begin transaction");
    install_empty_history_baseline(&transaction, CURRENT_PACKAGE)
        .await
        .expect("empty baseline installs");
    transaction.commit().await.expect("baseline commits");

    let expected_catalog = ExpectedManagedCatalog::compiled(registry);
    let schema_fingerprint =
        managed_schema_fingerprint(migration, &database.runtime_role, &expected_catalog)
            .await
            .expect("managed schema fingerprint resolves");
    let expected = ExpectedRegistryIdentity {
        package_id: registry.registry_id().to_owned(),
        environment: "local".to_owned(),
        instance_id: "history-erasure-test".to_owned(),
        database_id: "history-erasure-db".to_owned(),
        package_revision: CURRENT_PACKAGE.to_owned(),
        schema_fingerprint,
        package_sequence: 1,
    };
    migration
        .execute(
            "INSERT INTO registry_internal.registry_state (
                 singleton, package_id, environment, instance_id, database_id,
                 active_package_revision, schema_fingerprint, package_sequence,
                 maintenance_status
             ) VALUES (true, $1, $2, $3, $4, $5, $6, $7, 'ready')",
            &[
                &expected.package_id,
                &expected.environment,
                &expected.instance_id,
                &expected.database_id,
                &expected.package_revision,
                &expected.schema_fingerprint,
                &expected.package_sequence,
            ],
        )
        .await
        .expect("registry state installs");
    expected
}

async fn insert_revision(
    transaction: &tokio_postgres::Transaction<'_>,
    record_id: Uuid,
    revision: i64,
    package_revision: &str,
    mutation_kind: &str,
) {
    let snapshot = json!({
        "person": "00000000-0000-4000-8000-000000000010",
        "household": format!("household-{revision}"),
        "valid-from": "2026-06-01",
        "valid-to": null
    });
    let snapshot = registry_platform_canonical_json::canonicalize_json(&snapshot)
        .expect("snapshot canonicalizes");
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_revisions
                 (entity_id, record_id, record_reference, record_revision,
                  predecessor_revision, record_lifecycle, package_revision, operation_id,
                  mutation_kind, principal_reference, request_reference, snapshot)
             VALUES ($1, $2, $3, $4, $5, 'active', $6, 'op-1',
                     $7, 'actor:hash', 'request:hash', $8)",
            &[
                &ENTITY,
                &record_id,
                &format!("{ENTITY}:{record_id}"),
                &revision,
                &(revision > 1).then_some(revision - 1),
                &package_revision,
                &mutation_kind,
                &snapshot,
            ],
        )
        .await
        .expect("test revision inserts");
}

async fn insert_revision_range(
    transaction: &tokio_postgres::Transaction<'_>,
    record_id: Uuid,
    count: i64,
) {
    let snapshot = json!({
        "person": "00000000-0000-4000-8000-000000000010",
        "household": "household-bulk",
        "valid-from": "2026-06-01",
        "valid-to": null
    });
    let snapshot = registry_platform_canonical_json::canonicalize_json(&snapshot)
        .expect("snapshot canonicalizes");
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_revisions
                 (entity_id, record_id, record_reference, record_revision,
                  predecessor_revision, record_lifecycle, package_revision, operation_id,
                  mutation_kind, principal_reference, request_reference, snapshot)
             SELECT $1, $2, $3, revision,
                    CASE WHEN revision > 1 THEN revision - 1 ELSE NULL END,
                    'active', $4, 'op-1', 'migration', 'actor:hash',
                    'request:hash', $5
               FROM generate_series(1::bigint, $6::bigint) AS revision",
            &[
                &ENTITY,
                &record_id,
                &format!("{ENTITY}:{record_id}"),
                &OLD_PACKAGE,
                &snapshot,
                &count,
            ],
        )
        .await
        .expect("bulk revisions insert");
}

async fn insert_outbox_payload(
    transaction: &tokio_postgres::Transaction<'_>,
    record_id: Uuid,
    revision: i64,
) {
    let payload = b"payload-canary".as_slice();
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_outbox
                 (event_id, event_type, trigger, entity_id, record_reference,
                  record_revision, package_revision, schema_fingerprint, payload,
                  payload_expires_at)
             VALUES ($1, 'membership.changed', 'created', $2, $3, $4,
                     $5, 'schema:hash', $6, transaction_timestamp() + interval '7 days')",
            &[
                &Uuid::new_v4(),
                &ENTITY,
                &format!("{ENTITY}:{record_id}"),
                &revision,
                &OLD_PACKAGE,
                &payload,
            ],
        )
        .await
        .expect("test outbox payload inserts");
}

async fn insert_idempotency_response(
    transaction: &tokio_postgres::Transaction<'_>,
    key_reference: &str,
    binding_reference: &str,
    result_kind: &str,
    record_reference: Option<&str>,
    record_revision: Option<i64>,
    result_count: Option<i16>,
    body: serde_json::Value,
) {
    let body =
        registry_platform_canonical_json::canonicalize_json(&body).expect("body canonicalizes");
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_idempotency
                 (key_reference, binding_reference, result_kind, record_reference,
                  record_revision, result_count, response_status, response_body,
                  response_headers)
             VALUES ($1, $2, $3, $4, $5, $6, 200, $7, $8)",
            &[
                &key_reference,
                &binding_reference,
                &result_kind,
                &record_reference,
                &record_revision,
                &result_count,
                &body,
                &vec![0_u8, 0_u8],
            ],
        )
        .await
        .expect("idempotency response inserts");
}

async fn assert_erasure_audit_is_minimized(database: &TestDatabase, profile: &AuditProfile) {
    let rows = database
        .admin
        .query(
            "SELECT record_hash, envelope FROM registry_internal.registry_audit",
            &[],
        )
        .await
        .expect("administrator can inspect audit");
    assert_eq!(rows.len(), 1);
    let envelope_value =
        registry_platform_canonical_json::parse_json_strict(&rows[0].get::<_, Vec<u8>>(1))
            .expect("audit envelope is canonical JSON");
    let envelope: registry_platform_audit::AuditEnvelope =
        serde_json::from_value(envelope_value).expect("audit envelope shape is valid");
    registry_platform_audit::verify_chain(std::slice::from_ref(&envelope), &profile.chain_hasher())
        .expect("single-envelope chain verifies");
    assert_eq!(
        rows[0].get::<_, Vec<u8>>(0),
        envelope.record_hash.as_slice()
    );
    let audit_text = String::from_utf8(rows[0].get::<_, Vec<u8>>(1)).expect("audit is utf8");
    assert!(audit_text.contains("registry-server-history-erasure-audit/v1"));
    assert!(audit_text.contains("history-erasure-maintenance"));
    assert!(audit_text.contains("saved_exports_event_consumers_and_backups"));
    assert!(!audit_text.contains(RECORD_CANARY));
    assert!(!audit_text.contains(REASON_CANARY));
    assert!(!audit_text.contains(OPERATOR_CANARY));
    assert!(!audit_text.contains("case-document:erasure-proof"));
}

fn compiled_registry() -> registry_server::CompiledRegistry {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"history-erasure-registry","version":"1","defaultLanguage":"en"},
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
              "operations":["create","get","list","patch","snapshot"],
              "readableFields":["person","household","valid-from","valid-to"],
              "writableFields":["person","household","valid-from","valid-to"]
            }]
          }]
        }"#,
    )
    .unwrap();
    compile_project(&project, &[], CompileProfile::Authoring).expect("fixture compiles")
}
