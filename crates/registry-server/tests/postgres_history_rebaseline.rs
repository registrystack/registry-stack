// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "../src/history_context.rs"]
#[allow(dead_code)]
mod history_context;
#[path = "../src/history_reference.rs"]
#[allow(dead_code)]
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
#[allow(dead_code)]
mod postgres {
    pub use registry_server::postgres::SqlIdentifier;
}
#[path = "../src/history_commit.rs"]
#[allow(dead_code)]
mod history_commit;
#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::time::Duration;

use registry_platform_audit::AuditProfile;
use registry_platform_canonical_json::canonicalize_json;
use serde_json::json;
use uuid::Uuid;

use history_commit::{
    allocate_revision_commit, capture_latest_snapshot_reference, install_empty_history_baseline,
    resolve_snapshot_reference, CommitAllocation, HistoryCommitError, RevisionCommitMember,
};
use history_context::CommitOrigin;
use history_store::retain_descriptor;
use postgres_harness::TestDatabase;
use registry_server::compiler::{compile_project, CompileProfile};
use registry_server::contract::parse_project_json;
use registry_server::history_erasure::{
    erase_record_history, HistoryErasureRequest, HistoryErasureTimeouts, RecordHistoryErasureTarget,
};
use registry_server::history_rebaseline::{
    rebaseline_history_coverage, HistoryRebaselineError, HistoryRebaselineRequest,
    HistoryRebaselineTimeouts,
};
use registry_server::mutation::install_mutation_schema;
use registry_server::postgres::{
    install_compiled_schema, managed_schema_fingerprint, ExpectedManagedCatalog,
    ExpectedRegistryIdentity, RegistryLockKey,
};

const ENTITY: &str = "membership";
const OLD_PACKAGE: &str = "pkg-rebaseline-old";
const CURRENT_PACKAGE: &str = "pkg-rebaseline-current";
const KEPT_RECORD: &str = "018feab0-68f9-4a45-b9e3-58436df07a01";
const ERASED_RECORD: &str = "018feab0-68f9-4a45-b9e3-58436df07a02";
const OPERATOR_CANARY: &str = "operator secret must not enter maintenance audit";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rebaseline_restores_snapshot_coverage_from_current_state_after_an_erasure() {
    let database = TestDatabase::create(4).await;
    let (mut migration, migration_task) = database.connect_migration().await;
    let registry = compiled_registry();
    let expected = install_ready_history_registry(&database, &mut migration, &registry).await;
    let lock_key = RegistryLockKey::derive(&expected.package_id).expect("lock key derives");
    let audit_profile = AuditProfile::production_from_secret_bytes(vec![0x81; 32].into())
        .expect("test owns a keyed audit profile");
    let kept = Uuid::parse_str(KEPT_RECORD).unwrap();
    let erased = Uuid::parse_str(ERASED_RECORD).unwrap();

    seed_two_records(&database.admin, &mut migration, &registry, kept, erased).await;

    let transaction = migration.transaction().await.expect("transaction begins");
    let pre_erase = capture_latest_snapshot_reference(&transaction)
        .await
        .expect("history covers the pre-erasure head");
    assert_eq!(pre_erase.position, 3);
    transaction.commit().await.expect("read commits");

    erase_record_history(
        &mut migration,
        HistoryErasureRequest {
            expected: &expected,
            migration_role: &database.migration_role,
            lock_key,
            timeouts: HistoryErasureTimeouts::new(Duration::from_secs(5), Duration::from_secs(5))
                .unwrap(),
            audit_profile: &audit_profile,
            operator_reference: "operator-run-1",
            reason: "approved retention request",
            target: RecordHistoryErasureTarget::new(ENTITY, erased, 1),
        },
    )
    .await
    .expect("targeted erasure succeeds");

    let transaction = migration.transaction().await.expect("transaction begins");
    assert_eq!(
        capture_latest_snapshot_reference(&transaction).await.err(),
        Some(HistoryCommitError::Unavailable),
        "an erasure leaves the latest state uncoverable until coverage is re-established"
    );
    transaction.commit().await.expect("read commits");

    let outcome = rebaseline_history_coverage(
        &mut migration,
        HistoryRebaselineRequest {
            expected: &expected,
            migration_role: &database.migration_role,
            lock_key,
            timeouts: HistoryRebaselineTimeouts::new(
                Duration::from_secs(5),
                Duration::from_secs(5),
            )
            .unwrap(),
            audit_profile: &audit_profile,
            operator_reference: OPERATOR_CANARY,
            registry: &registry,
        },
    )
    .await
    .expect("rebaseline restores coverage from the current state");
    assert_eq!(outcome.baseline_position, 4);
    assert_eq!(outcome.verified_entity_count, 1);
    assert_eq!(outcome.verified_record_count, 2);
    assert_eq!(outcome.previous_coverage_baseline_position, 0);
    assert_eq!(outcome.previous_unavailable_after_position, Some(1));

    let transaction = migration.transaction().await.expect("transaction begins");
    let restored = capture_latest_snapshot_reference(&transaction)
        .await
        .expect("a fresh reference resolves after the rebaseline");
    assert_eq!(restored.position, 4);
    assert_eq!(
        resolve_snapshot_reference(&transaction, pre_erase.reference).await,
        Err(HistoryCommitError::Unavailable),
        "a reference captured before the erasure stays refused"
    );
    let reconstructed = reconstruct_records(&transaction, restored.position).await;
    assert_eq!(
        reconstructed,
        vec![
            (kept, 1, "household-1".to_owned()),
            (erased, 2, "household-2".to_owned()),
        ],
        "the fresh reference reads the current rows, including the erased record"
    );
    transaction.commit().await.expect("read commits");

    assert_eq!(
        rebaseline_history_coverage(
            &mut migration,
            HistoryRebaselineRequest {
                expected: &expected,
                migration_role: &database.migration_role,
                lock_key,
                timeouts: HistoryRebaselineTimeouts::new(
                    Duration::from_secs(5),
                    Duration::from_secs(5),
                )
                .unwrap(),
                audit_profile: &audit_profile,
                operator_reference: OPERATOR_CANARY,
                registry: &registry,
            },
        )
        .await
        .err(),
        Some(HistoryRebaselineError::CoverageComplete),
        "a second rebaseline has nothing to do"
    );

    assert_rebaseline_audit_chains_and_is_minimized(&database, &audit_profile).await;

    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rebaseline_refuses_while_maintenance_is_not_ready() {
    let database = TestDatabase::create(4).await;
    let (mut migration, migration_task) = database.connect_migration().await;
    let registry = compiled_registry();
    let expected = install_ready_history_registry(&database, &mut migration, &registry).await;
    let lock_key = RegistryLockKey::derive(&expected.package_id).expect("lock key derives");
    let audit_profile = AuditProfile::production_from_secret_bytes(vec![0x82; 32].into())
        .expect("test owns a keyed audit profile");
    let kept = Uuid::parse_str(KEPT_RECORD).unwrap();
    let erased = Uuid::parse_str(ERASED_RECORD).unwrap();
    seed_two_records(&database.admin, &mut migration, &registry, kept, erased).await;
    erase_record_history(
        &mut migration,
        HistoryErasureRequest {
            expected: &expected,
            migration_role: &database.migration_role,
            lock_key,
            timeouts: HistoryErasureTimeouts::new(Duration::from_secs(5), Duration::from_secs(5))
                .unwrap(),
            audit_profile: &audit_profile,
            operator_reference: "operator-run-1",
            reason: "approved retention request",
            target: RecordHistoryErasureTarget::new(ENTITY, erased, 1),
        },
    )
    .await
    .expect("targeted erasure succeeds");
    migration
        .execute(
            "UPDATE registry_internal.registry_state
                SET maintenance_status = 'applying',
                    maintenance_target_revision = 'pkg-rebaseline-next'
              WHERE singleton",
            &[],
        )
        .await
        .expect("maintenance status changes");

    assert_eq!(
        rebaseline_history_coverage(
            &mut migration,
            HistoryRebaselineRequest {
                expected: &expected,
                migration_role: &database.migration_role,
                lock_key,
                timeouts: HistoryRebaselineTimeouts::new(
                    Duration::from_secs(5),
                    Duration::from_secs(5),
                )
                .unwrap(),
                audit_profile: &audit_profile,
                operator_reference: OPERATOR_CANARY,
                registry: &registry,
            },
        )
        .await
        .err(),
        Some(HistoryRebaselineError::Unavailable),
        "the shared maintenance interlock refuses a registry that is not ready"
    );

    let audit_count: i64 = database
        .admin
        .query_one(
            "SELECT count(*)::bigint FROM registry_internal.registry_audit",
            &[],
        )
        .await
        .expect("administrator can count audit records")
        .get(0);
    assert_eq!(
        audit_count, 1,
        "a refused rebaseline writes no audit record"
    );

    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rebaseline_refuses_while_retained_revisions_are_unindexed() {
    let database = TestDatabase::create(4).await;
    let (mut migration, migration_task) = database.connect_migration().await;
    let registry = compiled_registry();
    let expected = install_ready_history_registry(&database, &mut migration, &registry).await;
    let lock_key = RegistryLockKey::derive(&expected.package_id).expect("lock key derives");
    let audit_profile = AuditProfile::production_from_secret_bytes(vec![0x83; 32].into())
        .expect("test owns a keyed audit profile");
    let kept = Uuid::parse_str(KEPT_RECORD).unwrap();
    let erased = Uuid::parse_str(ERASED_RECORD).unwrap();
    seed_two_records(&database.admin, &mut migration, &registry, kept, erased).await;
    erase_record_history(
        &mut migration,
        HistoryErasureRequest {
            expected: &expected,
            migration_role: &database.migration_role,
            lock_key,
            timeouts: HistoryErasureTimeouts::new(Duration::from_secs(5), Duration::from_secs(5))
                .unwrap(),
            audit_profile: &audit_profile,
            operator_reference: "operator-run-1",
            reason: "approved retention request",
            target: RecordHistoryErasureTarget::new(ENTITY, erased, 1),
        },
    )
    .await
    .expect("targeted erasure succeeds");

    let transaction = migration.transaction().await.expect("transaction begins");
    transaction
        .execute(
            "DELETE FROM registry_internal.registry_revision_commit_members
              WHERE entity_id = $1 AND record_id = $2",
            &[&ENTITY, &kept],
        )
        .await
        .expect("commit member is removed for the fixture");
    transaction.commit().await.expect("fixture commits");

    assert_eq!(
        rebaseline_history_coverage(
            &mut migration,
            HistoryRebaselineRequest {
                expected: &expected,
                migration_role: &database.migration_role,
                lock_key,
                timeouts: HistoryRebaselineTimeouts::new(
                    Duration::from_secs(5),
                    Duration::from_secs(5),
                )
                .unwrap(),
                audit_profile: &audit_profile,
                operator_reference: OPERATOR_CANARY,
                registry: &registry,
            },
        )
        .await
        .err(),
        Some(HistoryRebaselineError::UnindexedRevisions),
        "a retained revision no commit indexes cannot be covered by a new baseline"
    );

    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rebaseline_refuses_when_a_live_row_has_no_matching_journal_head() {
    let database = TestDatabase::create(4).await;
    let (mut migration, migration_task) = database.connect_migration().await;
    let registry = compiled_registry();
    let expected = install_ready_history_registry(&database, &mut migration, &registry).await;
    let lock_key = RegistryLockKey::derive(&expected.package_id).expect("lock key derives");
    let audit_profile = AuditProfile::production_from_secret_bytes(vec![0x84; 32].into())
        .expect("test owns a keyed audit profile");
    let kept = Uuid::parse_str(KEPT_RECORD).unwrap();
    let erased = Uuid::parse_str(ERASED_RECORD).unwrap();
    seed_two_records(&database.admin, &mut migration, &registry, kept, erased).await;
    erase_record_history(
        &mut migration,
        HistoryErasureRequest {
            expected: &expected,
            migration_role: &database.migration_role,
            lock_key,
            timeouts: HistoryErasureTimeouts::new(Duration::from_secs(5), Duration::from_secs(5))
                .unwrap(),
            audit_profile: &audit_profile,
            operator_reference: "operator-run-1",
            reason: "approved retention request",
            target: RecordHistoryErasureTarget::new(ENTITY, erased, 2),
        },
    )
    .await
    .expect("erasing the whole retained record succeeds");

    assert_eq!(
        rebaseline_history_coverage(
            &mut migration,
            HistoryRebaselineRequest {
                expected: &expected,
                migration_role: &database.migration_role,
                lock_key,
                timeouts: HistoryRebaselineTimeouts::new(
                    Duration::from_secs(5),
                    Duration::from_secs(5),
                )
                .unwrap(),
                audit_profile: &audit_profile,
                operator_reference: OPERATOR_CANARY,
                registry: &registry,
            },
        )
        .await
        .err(),
        Some(HistoryRebaselineError::LiveHistoryMismatch),
        "a live row whose retained history is gone cannot be vouched for by a new baseline"
    );

    migration_task.abort();
    database.cleanup().await;
}

async fn seed_two_records(
    admin: &tokio_postgres::Client,
    migration: &mut tokio_postgres::Client,
    registry: &registry_server::CompiledRegistry,
    kept: Uuid,
    erased: Uuid,
) {
    let transaction = migration.transaction().await.expect("transaction begins");
    insert_revision(&transaction, kept, 1, OLD_PACKAGE, "create").await;
    allocate_revision_commit(
        &transaction,
        CommitAllocation {
            package_revision: OLD_PACKAGE,
            origin: CommitOrigin::Mutation {
                actor_reference: "actor:hash",
                request_reference: "request:hash",
            },
            change_context: None,
            members: &[RevisionCommitMember {
                entity_id: ENTITY,
                record_id: kept,
                record_revision: 1,
            }],
        },
    )
    .await
    .expect("kept record is indexed");
    insert_revision(&transaction, erased, 1, OLD_PACKAGE, "create").await;
    allocate_revision_commit(
        &transaction,
        CommitAllocation {
            package_revision: OLD_PACKAGE,
            origin: CommitOrigin::Mutation {
                actor_reference: "actor:hash",
                request_reference: "request:hash",
            },
            change_context: None,
            members: &[RevisionCommitMember {
                entity_id: ENTITY,
                record_id: erased,
                record_revision: 1,
            }],
        },
    )
    .await
    .expect("first erased revision is indexed");
    insert_revision(&transaction, erased, 2, CURRENT_PACKAGE, "patch").await;
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
                record_id: erased,
                record_revision: 2,
            }],
        },
    )
    .await
    .expect("second erased revision is indexed");
    transaction.commit().await.expect("fixture commits");
    // Entity tables force row-level security, so the fixture writes live rows
    // through the administrator the harness owns, as the migration fixtures do.
    insert_live_row(admin, registry, kept, 1, OLD_PACKAGE).await;
    insert_live_row(admin, registry, erased, 2, CURRENT_PACKAGE).await;
}

fn snapshot_json(revision: i64) -> serde_json::Value {
    json!({
        "person": "00000000-0000-4000-8000-000000000010",
        "household": format!("household-{revision}"),
        "valid-from": "2026-06-01",
        "valid-to": null
    })
}

async fn insert_live_row(
    client: &tokio_postgres::Client,
    registry: &registry_server::CompiledRegistry,
    record_id: Uuid,
    revision: i64,
    package_revision: &str,
) {
    let entity = &registry.entities()[ENTITY];
    let table = quote(&entity.physical_table);
    let person = quote(&entity.fields["person"].physical_name);
    let household = quote(&entity.fields["household"].physical_name);
    let valid_from = quote(&entity.fields["valid-from"].physical_name);
    client
        .execute(
            &format!(
                "INSERT INTO registry_data.{table}
                     (record_id, record_revision, record_lifecycle, active_package_revision,
                      {person}, {household}, {valid_from})
                 VALUES ($1, $2, 'active', $3, $4, $5, DATE '2026-06-01')"
            ),
            &[
                &record_id,
                &revision,
                &package_revision,
                &Uuid::parse_str("00000000-0000-4000-8000-000000000010").unwrap(),
                &format!("household-{revision}"),
            ],
        )
        .await
        .expect("live row inserts");
}

fn quote(identifier: &str) -> String {
    format!("\"{identifier}\"")
}

async fn reconstruct_records(
    transaction: &tokio_postgres::Transaction<'_>,
    position: i64,
) -> Vec<(Uuid, i64, String)> {
    transaction
        .query(
            "WITH latest AS (
                 SELECT DISTINCT ON (member.record_id)
                        member.record_id, member.record_revision
                   FROM registry_internal.registry_revision_commit_members AS member
                  WHERE member.entity_id = $1::text
                    AND member.commit_position <= $2::bigint
                  ORDER BY member.record_id, member.commit_position DESC,
                           member.record_revision DESC
             )
             SELECT revision.record_id, revision.record_revision,
                    convert_from(revision.snapshot, 'UTF8')
               FROM latest
               JOIN registry_internal.registry_revisions AS revision
                 ON revision.entity_id = $1::text
                AND revision.record_id = latest.record_id
                AND revision.record_revision = latest.record_revision
              WHERE revision.record_lifecycle = 'active'
                AND revision.snapshot IS NOT NULL
                AND revision.erased_at IS NULL
              ORDER BY revision.record_id",
            &[&ENTITY, &position],
        )
        .await
        .expect("snapshot reconstruction runs")
        .into_iter()
        .map(|row| {
            let snapshot: serde_json::Value =
                serde_json::from_str(&row.get::<_, String>(2)).expect("snapshot is JSON");
            (
                row.get::<_, Uuid>(0),
                row.get::<_, i64>(1),
                snapshot["household"]
                    .as_str()
                    .expect("household is a string")
                    .to_owned(),
            )
        })
        .collect()
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
    let transaction = migration.transaction().await.expect("transaction begins");
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
        instance_id: "history-rebaseline-test".to_owned(),
        database_id: "history-rebaseline-db".to_owned(),
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
    let snapshot = canonicalize_json(&snapshot_json(revision)).expect("snapshot canonicalizes");
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

async fn assert_rebaseline_audit_chains_and_is_minimized(
    database: &TestDatabase,
    profile: &AuditProfile,
) {
    let rows = database
        .admin
        .query(
            "SELECT record_hash, envelope FROM registry_internal.registry_audit
              ORDER BY created_at, envelope_id",
            &[],
        )
        .await
        .expect("administrator can inspect audit");
    assert_eq!(rows.len(), 2, "the erasure and the rebaseline are audited");
    let envelopes = rows
        .iter()
        .map(|row| {
            let value =
                registry_platform_canonical_json::parse_json_strict(&row.get::<_, Vec<u8>>(1))
                    .expect("audit envelope is canonical JSON");
            serde_json::from_value::<registry_platform_audit::AuditEnvelope>(value)
                .expect("audit envelope shape is valid")
        })
        .collect::<Vec<_>>();
    registry_platform_audit::verify_chain(&envelopes, &profile.chain_hasher())
        .expect("the rebaseline record extends the erasure chain");
    let audit_text = String::from_utf8(rows[1].get::<_, Vec<u8>>(1)).expect("audit is utf8");
    assert!(audit_text.contains("registry-server-history-rebaseline-audit/v1"));
    assert!(audit_text.contains("history-rebaseline-maintenance"));
    assert!(!audit_text.contains(OPERATOR_CANARY));
    assert!(!audit_text.contains(KEPT_RECORD));
    assert!(!audit_text.contains(ERASED_RECORD));
    assert!(!audit_text.contains("household-"));
}

fn compiled_registry() -> registry_server::CompiledRegistry {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"history-rebaseline-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "entities":[{
            "id":"membership",
            "primaryDataset":"test-dataset",
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
