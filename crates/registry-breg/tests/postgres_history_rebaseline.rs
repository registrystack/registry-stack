// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "../src/history_context.rs"]
#[allow(dead_code)]
mod history_context;
#[path = "../src/history_reference.rs"]
#[allow(dead_code)]
mod history_reference;
mod history_schema {
    pub use registry_breg::history_schema::*;
}
mod model {
    pub use registry_breg::model::*;
}
#[path = "../src/history_store.rs"]
#[allow(dead_code)]
mod history_store;
#[allow(dead_code)]
mod postgres {
    pub use registry_breg::postgres::{RuntimeRevoke, SqlIdentifier};
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
use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_json;
use registry_breg::history_erasure::{
    erase_record_history, HistoryErasureError, HistoryErasureRequest, HistoryErasureTimeouts,
    RecordHistoryErasureTarget, HISTORY_ERASURE_AUDIT_SCHEMA,
};
use registry_breg::history_rebaseline::{
    rebaseline_history_coverage, HistoryRebaselineError, HistoryRebaselineRequest,
    HistoryRebaselineTimeouts, HISTORY_REBASELINE_AUDIT_SCHEMA,
};
use registry_breg::mutation::install_mutation_schema;
use registry_breg::postgres::{
    install_compiled_schema, managed_schema_fingerprint, test_package_digest,
    ExpectedManagedCatalog, ExpectedRegistryIdentity, RegistryLockKey,
};

const ENTITY: &str = "membership";
const OLD_PACKAGE: &str = "pkg-rebaseline-old";
const CURRENT_PACKAGE: &str = "6d1f3a2b-8c4e-4f7a-9b0d-1e2f3a4b5c6d";
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
            audit: &database.audit(audit_profile.clone()),
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
            audit: &database.audit(audit_profile.clone()),
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
                audit: &database.audit(audit_profile.clone()),
                operator_reference: OPERATOR_CANARY,
                registry: &registry,
            },
        )
        .await
        .err(),
        Some(HistoryRebaselineError::CoverageComplete),
        "a second rebaseline has nothing to do"
    );

    assert_rebaseline_audit_is_minimized(&database);

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
            audit: &database.audit(audit_profile.clone()),
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
                    maintenance_target_package_digest = 'pkg-rebaseline-next'
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
                audit: &database.audit(audit_profile.clone()),
                operator_reference: OPERATOR_CANARY,
                registry: &registry,
            },
        )
        .await
        .err(),
        Some(HistoryRebaselineError::Unavailable),
        "the shared maintenance interlock refuses a registry that is not ready"
    );

    let rebaseline_entries = database
        .audit_entries()
        .into_iter()
        .filter(|entry| entry["schema"] == HISTORY_REBASELINE_AUDIT_SCHEMA)
        .map(|entry| entry["phase"].as_str().expect("phase").to_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        rebaseline_entries,
        ["request", "response"],
        "a refused rebaseline answers its request without a committed response"
    );
    let answer = database
        .audit_entries()
        .into_iter()
        .rfind(|entry| entry["schema"] == HISTORY_REBASELINE_AUDIT_SCHEMA)
        .expect("the refused rebaseline's answer");
    assert_eq!(answer["record"]["outcome"], "unfinished");

    migration_task.abort();
    database.cleanup().await;
}

/// A migration lock another session holds when an erasure or a rebaseline
/// takes it is reported as a held lock, never as unavailable storage, and
/// changes nothing: each answers its request entry as unfinished, and the
/// same erasure and a rebaseline both succeed once the lock releases.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn erasure_and_rebaseline_report_a_held_migration_lock_and_change_nothing() {
    let database = TestDatabase::create(4).await;
    let (mut migration, migration_task) = database.connect_migration().await;
    let registry = compiled_registry();
    let expected = install_ready_history_registry(&database, &mut migration, &registry).await;
    let lock_key = RegistryLockKey::derive(&expected.package_id).expect("lock key derives");
    let audit_profile = AuditProfile::production_from_secret_bytes(vec![0x88; 32].into())
        .expect("test owns a keyed audit profile");
    let kept = Uuid::parse_str(KEPT_RECORD).unwrap();
    let erased = Uuid::parse_str(ERASED_RECORD).unwrap();
    seed_two_records(&database.admin, &mut migration, &registry, kept, erased).await;
    let (holder, holder_task) = database.connect_admin().await;
    holder
        .execute("SELECT pg_catalog.pg_advisory_lock($1)", &[&lock_key.get()])
        .await
        .expect("a second session takes the migration lock");
    let erasure_audit = database.audit(audit_profile.clone());
    let erasure = |lock: Duration| HistoryErasureRequest {
        expected: &expected,
        migration_role: &database.migration_role,
        lock_key,
        timeouts: HistoryErasureTimeouts::new(lock, Duration::from_secs(5)).unwrap(),
        audit: &erasure_audit,
        operator_reference: "operator-run-1",
        reason: "approved retention request",
        target: RecordHistoryErasureTarget::new(ENTITY, erased, 1),
    };

    assert_eq!(
        erase_record_history(&mut migration, erasure(Duration::from_millis(200)))
            .await
            .err(),
        Some(HistoryErasureError::MigrationLockHeld),
        "an erasure that cannot take the held lock reports it as held"
    );
    assert_eq!(
        rebaseline_history_coverage(
            &mut migration,
            HistoryRebaselineRequest {
                expected: &expected,
                migration_role: &database.migration_role,
                lock_key,
                timeouts: HistoryRebaselineTimeouts::new(
                    Duration::from_millis(200),
                    Duration::from_secs(5),
                )
                .unwrap(),
                audit: &database.audit(audit_profile.clone()),
                operator_reference: OPERATOR_CANARY,
                registry: &registry,
            },
        )
        .await
        .err(),
        Some(HistoryRebaselineError::MigrationLockHeld),
        "a rebaseline that cannot take the held lock reports it as held"
    );
    for schema in [
        HISTORY_ERASURE_AUDIT_SCHEMA,
        HISTORY_REBASELINE_AUDIT_SCHEMA,
    ] {
        let entries = database
            .audit_entries()
            .into_iter()
            .filter(|entry| entry["schema"] == schema)
            .collect::<Vec<_>>();
        let phases = entries
            .iter()
            .map(|entry| entry["phase"].as_str().expect("phase"))
            .collect::<Vec<_>>();
        assert_eq!(
            phases,
            ["request", "response"],
            "{schema}: a refused run answers its request without a committed response"
        );
        assert_eq!(entries[1]["record"]["outcome"], "unfinished", "{schema}");
    }

    holder
        .execute(
            "SELECT pg_catalog.pg_advisory_unlock($1)",
            &[&lock_key.get()],
        )
        .await
        .expect("the second session releases the migration lock");
    erase_record_history(&mut migration, erasure(Duration::from_secs(5)))
        .await
        .expect("the same erasure succeeds once the lock releases");
    rebaseline(
        &mut migration,
        &database,
        &expected,
        lock_key,
        &audit_profile,
        &registry,
    )
    .await
    .expect("a rebaseline succeeds once the lock releases");

    holder_task.abort();
    migration_task.abort();
    database.cleanup().await;
}

/// A rebaseline appends its request entry before its transaction opens: a
/// writer that refuses that entry answers an outage and leaves coverage
/// exactly as the erasure left it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rebaseline_changes_nothing_when_the_audit_writer_refuses_its_request_entry() {
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
            audit: &database.audit(audit_profile.clone()),
            operator_reference: "operator-run-1",
            reason: "approved retention request",
            target: RecordHistoryErasureTarget::new(ENTITY, erased, 1),
        },
    )
    .await
    .expect("targeted erasure succeeds");
    let head = |row: tokio_postgres::Row| -> (i64, bool, Option<i64>, i64) {
        (row.get(0), row.get(1), row.get(2), row.get(3))
    };
    let head_query = "SELECT coverage_baseline_position, coverage_ready,
                             unavailable_after_position,
                             (SELECT count(*) FROM registry_internal.registry_revision_commits)
                        FROM registry_internal.registry_commit_head WHERE singleton";
    let before = head(
        migration
            .query_one(head_query, &[])
            .await
            .expect("coverage head reads"),
    );
    let accepted = database.audit_entries().len();

    database.audit_capture().fail_after(0);
    let refused = rebaseline_history_coverage(
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
            audit: &database.audit(audit_profile.clone()),
            operator_reference: OPERATOR_CANARY,
            registry: &registry,
        },
    )
    .await
    .err();
    database.audit_capture().restore();
    assert_eq!(refused, Some(HistoryRebaselineError::Unavailable));

    let after = head(
        migration
            .query_one(head_query, &[])
            .await
            .expect("coverage head reads"),
    );
    assert_eq!(after, before, "no baseline commit and no coverage change");
    assert_eq!(database.audit_entries().len(), accepted);

    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rebaseline_refuses_while_a_retained_journal_head_is_unindexed() {
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
            audit: &database.audit(audit_profile.clone()),
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
                audit: &database.audit(audit_profile.clone()),
                operator_reference: OPERATOR_CANARY,
                registry: &registry,
            },
        )
        .await
        .err(),
        Some(HistoryRebaselineError::UnindexedRevisions),
        "a retained journal head no commit indexes cannot be covered by a new baseline"
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
            audit: &database.audit(audit_profile.clone()),
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
                audit: &database.audit(audit_profile.clone()),
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rebaseline_restores_coverage_when_a_migration_baseline_indexed_only_journal_heads() {
    let database = TestDatabase::create(4).await;
    let (mut migration, migration_task) = database.connect_migration().await;
    let registry = compiled_registry();
    let expected = install_ready_history_registry(&database, &mut migration, &registry).await;
    let lock_key = RegistryLockKey::derive(&expected.package_id).expect("lock key derives");
    let audit_profile = AuditProfile::production_from_secret_bytes(vec![0x85; 32].into())
        .expect("test owns a keyed audit profile");
    let kept = Uuid::parse_str(KEPT_RECORD).unwrap();
    let erased = Uuid::parse_str(ERASED_RECORD).unwrap();

    seed_migrated_records(&database.admin, &mut migration, &registry, kept, erased).await;

    erase_record_history(
        &mut migration,
        HistoryErasureRequest {
            expected: &expected,
            migration_role: &database.migration_role,
            lock_key,
            timeouts: HistoryErasureTimeouts::new(Duration::from_secs(5), Duration::from_secs(5))
                .unwrap(),
            audit: &database.audit(audit_profile.clone()),
            operator_reference: "operator-run-1",
            reason: "approved retention request",
            target: RecordHistoryErasureTarget::new(ENTITY, erased, 1),
        },
    )
    .await
    .expect("erasing the pre-migration revision succeeds");

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
            audit: &database.audit(audit_profile.clone()),
            operator_reference: OPERATOR_CANARY,
            registry: &registry,
        },
    )
    .await
    .expect("revisions older than the migration baseline do not block the rebaseline");
    assert_eq!(outcome.baseline_position, 2);
    assert_eq!(outcome.verified_entity_count, 1);
    assert_eq!(outcome.verified_record_count, 2);
    assert_eq!(outcome.previous_coverage_baseline_position, 0);
    assert_eq!(outcome.previous_unavailable_after_position, None);

    let transaction = migration.transaction().await.expect("transaction begins");
    let restored = capture_latest_snapshot_reference(&transaction)
        .await
        .expect("a fresh reference resolves after the rebaseline");
    assert_eq!(restored.position, 2);
    assert_eq!(
        reconstruct_records(&transaction, restored.position).await,
        vec![
            (kept, 2, "household-2".to_owned()),
            (erased, 2, "household-2".to_owned()),
        ],
        "the fresh reference reads the current rows through the heads the migration indexed"
    );
    transaction.commit().await.expect("read commits");

    migration_task.abort();
    database.cleanup().await;
}

/// Live rows beyond what one history commit may index, so the rebaseline
/// verifies them page by page.
const MANY_RECORDS: usize = 1_201;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rebaseline_verifies_more_live_rows_than_one_commit_indexes() {
    let database = TestDatabase::create(4).await;
    let (mut migration, migration_task) = database.connect_migration().await;
    let registry = compiled_registry();
    let expected = install_ready_history_registry(&database, &mut migration, &registry).await;
    let lock_key = RegistryLockKey::derive(&expected.package_id).expect("lock key derives");
    let audit_profile = AuditProfile::production_from_secret_bytes(vec![0x86; 32].into())
        .expect("test owns a keyed audit profile");
    let many = seed_many_records(&database.admin, &mut migration, &registry).await;
    erase_one_superseded_revision(
        &database,
        &mut migration,
        &registry,
        &expected,
        lock_key,
        &audit_profile,
    )
    .await;

    let outcome = rebaseline(
        &mut migration,
        &database,
        &expected,
        lock_key,
        &audit_profile,
        &registry,
    )
    .await
    .expect("a registry larger than one commit is rebaselined");
    assert_eq!(
        outcome.verified_record_count,
        u64::try_from(many.len() + 2).unwrap()
    );
    let transaction = migration.transaction().await.expect("transaction begins");
    let restored = capture_latest_snapshot_reference(&transaction)
        .await
        .expect("a fresh reference resolves after the rebaseline");
    assert_eq!(
        reconstruct_records(&transaction, restored.position)
            .await
            .len(),
        many.len() + 2
    );
    transaction.commit().await.expect("read commits");

    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rebaseline_refuses_a_mismatch_on_a_later_page() {
    let database = TestDatabase::create(4).await;
    let (mut migration, migration_task) = database.connect_migration().await;
    let registry = compiled_registry();
    let expected = install_ready_history_registry(&database, &mut migration, &registry).await;
    let lock_key = RegistryLockKey::derive(&expected.package_id).expect("lock key derives");
    let audit_profile = AuditProfile::production_from_secret_bytes(vec![0x87; 32].into())
        .expect("test owns a keyed audit profile");
    let many = seed_many_records(&database.admin, &mut migration, &registry).await;
    erase_one_superseded_revision(
        &database,
        &mut migration,
        &registry,
        &expected,
        lock_key,
        &audit_profile,
    )
    .await;
    // The greatest record identifier is verified on the last page.
    let last = *many.iter().max().expect("records were seeded");
    let entity = &registry.entities()[ENTITY];
    database
        .admin
        .execute(
            &format!(
                "UPDATE registry_data.{} SET {} = 'changed-outside-history' WHERE record_id = $1",
                quote(&entity.physical_table),
                quote(&entity.fields["household"].physical_name)
            ),
            &[&last],
        )
        .await
        .expect("fixture diverges one live row from its journal head");

    assert_eq!(
        rebaseline(
            &mut migration,
            &database,
            &expected,
            lock_key,
            &audit_profile,
            &registry
        )
        .await
        .err(),
        Some(HistoryRebaselineError::LiveHistoryMismatch),
        "a live row on a later page that its journal head does not reproduce is refused"
    );

    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rebaseline_refuses_a_journal_head_with_no_live_row() {
    assert_a_journal_head_with_no_live_row_is_refused(0x88, Uuid::new_v4()).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rebaseline_refuses_a_journal_head_before_the_first_live_row() {
    assert_a_journal_head_with_no_live_row_is_refused(
        0x89,
        Uuid::parse_str("00000000-0000-4000-8000-000000000001").unwrap(),
    )
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rebaseline_refuses_a_journal_head_past_the_last_live_row() {
    assert_a_journal_head_with_no_live_row_is_refused(
        0x8a,
        Uuid::parse_str("ffffffff-ffff-4fff-bfff-ffffffffffff").unwrap(),
    )
    .await;
}

/// Seed more live rows than one verification page, add an indexed journal head
/// for `orphan` with no live row, and require the rebaseline to refuse it.
async fn assert_a_journal_head_with_no_live_row_is_refused(audit_byte: u8, orphan: Uuid) {
    let database = TestDatabase::create(4).await;
    let (mut migration, migration_task) = database.connect_migration().await;
    let registry = compiled_registry();
    let expected = install_ready_history_registry(&database, &mut migration, &registry).await;
    let lock_key = RegistryLockKey::derive(&expected.package_id).expect("lock key derives");
    let audit_profile = AuditProfile::production_from_secret_bytes(vec![audit_byte; 32].into())
        .expect("test owns a keyed audit profile");
    seed_many_records(&database.admin, &mut migration, &registry).await;
    erase_one_superseded_revision(
        &database,
        &mut migration,
        &registry,
        &expected,
        lock_key,
        &audit_profile,
    )
    .await;
    let transaction = migration.transaction().await.expect("transaction begins");
    insert_revision(&transaction, orphan, 1, CURRENT_PACKAGE, "create").await;
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
                record_id: orphan,
                record_revision: 1,
            }],
        },
    )
    .await
    .expect("the orphan journal head is indexed");
    transaction.commit().await.expect("fixture commits");

    assert_eq!(
        rebaseline(
            &mut migration,
            &database,
            &expected,
            lock_key,
            &audit_profile,
            &registry
        )
        .await
        .err(),
        Some(HistoryRebaselineError::LiveHistoryMismatch),
        "a retained journal head whose live row is gone cannot be vouched for"
    );

    migration_task.abort();
    database.cleanup().await;
}

async fn rebaseline(
    migration: &mut tokio_postgres::Client,
    database: &TestDatabase,
    expected: &ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    audit_profile: &AuditProfile,
    registry: &registry_breg::CompiledRegistry,
) -> Result<registry_breg::history_rebaseline::HistoryRebaselineOutcome, HistoryRebaselineError> {
    rebaseline_history_coverage(
        migration,
        HistoryRebaselineRequest {
            expected,
            migration_role: &database.migration_role,
            lock_key,
            timeouts: HistoryRebaselineTimeouts::new(
                Duration::from_secs(5),
                Duration::from_secs(30),
            )
            .unwrap(),
            audit: &database.audit(audit_profile.clone()),
            operator_reference: OPERATOR_CANARY,
            registry,
        },
    )
    .await
}

/// Seed the kept and erased records, then erase the erased record's
/// superseded first revision so coverage needs a rebaseline.
async fn erase_one_superseded_revision(
    database: &TestDatabase,
    migration: &mut tokio_postgres::Client,
    registry: &registry_breg::CompiledRegistry,
    expected: &ExpectedRegistryIdentity,
    lock_key: RegistryLockKey,
    audit_profile: &AuditProfile,
) {
    let kept = Uuid::parse_str(KEPT_RECORD).unwrap();
    let erased = Uuid::parse_str(ERASED_RECORD).unwrap();
    seed_two_records(&database.admin, migration, registry, kept, erased).await;
    erase_record_history(
        migration,
        HistoryErasureRequest {
            expected,
            migration_role: &database.migration_role,
            lock_key,
            timeouts: HistoryErasureTimeouts::new(Duration::from_secs(5), Duration::from_secs(5))
                .unwrap(),
            audit: &database.audit(audit_profile.clone()),
            operator_reference: "operator-run-1",
            reason: "approved retention request",
            target: RecordHistoryErasureTarget::new(ENTITY, erased, 1),
        },
    )
    .await
    .expect("targeted erasure succeeds");
}

/// Seed `MANY_RECORDS` live rows whose first revision is their journal head,
/// indexed by as many commits as the per-commit member cap requires.
async fn seed_many_records(
    admin: &tokio_postgres::Client,
    migration: &mut tokio_postgres::Client,
    registry: &registry_breg::CompiledRegistry,
) -> Vec<Uuid> {
    let ids = (0..MANY_RECORDS)
        .map(|_| Uuid::new_v4())
        .collect::<Vec<_>>();
    let snapshot = canonicalize_json(&snapshot_json(1)).expect("snapshot canonicalizes");
    let references = ids
        .iter()
        .map(|id| format!("{ENTITY}:{id}"))
        .collect::<Vec<_>>();
    let transaction = migration.transaction().await.expect("transaction begins");
    transaction
        .execute(
            "INSERT INTO registry_internal.registry_revisions
                 (entity_id, record_id, record_reference, record_revision,
                  predecessor_revision, record_lifecycle, package_revision, operation_id,
                  mutation_kind, principal_reference, request_reference, snapshot)
             SELECT $1, seeded.record_id, seeded.record_reference, 1, NULL, 'active', $2,
                    'op-1', 'create', 'actor:hash', 'request:hash', $3
               FROM unnest($4::uuid[], $5::text[]) AS seeded(record_id, record_reference)",
            &[&ENTITY, &OLD_PACKAGE, &snapshot, &ids, &references],
        )
        .await
        .expect("seeded revisions insert");
    for page in ids.chunks(1_000) {
        let members = page
            .iter()
            .map(|record_id| RevisionCommitMember {
                entity_id: ENTITY,
                record_id: *record_id,
                record_revision: 1,
            })
            .collect::<Vec<_>>();
        allocate_revision_commit(
            &transaction,
            CommitAllocation {
                package_revision: OLD_PACKAGE,
                origin: CommitOrigin::Mutation {
                    actor_reference: "actor:hash",
                    request_reference: "request:hash",
                },
                change_context: None,
                members: &members,
            },
        )
        .await
        .expect("seeded revisions are indexed");
    }
    transaction.commit().await.expect("fixture commits");
    let entity = &registry.entities()[ENTITY];
    admin
        .execute(
            &format!(
                "INSERT INTO registry_data.{}
                     (record_id, record_revision, record_lifecycle, active_package_revision,
                      {}, {}, {})
                 SELECT seeded, 1, 'active', $2, $3, 'household-1', DATE '2026-06-01'
                   FROM unnest($1::uuid[]) AS seeded",
                quote(&entity.physical_table),
                quote(&entity.fields["person"].physical_name),
                quote(&entity.fields["household"].physical_name),
                quote(&entity.fields["valid-from"].physical_name),
            ),
            &[
                &ids,
                &OLD_PACKAGE,
                &Uuid::parse_str("00000000-0000-4000-8000-000000000010").unwrap(),
            ],
        )
        .await
        .expect("seeded live rows insert");
    ids
}

async fn seed_two_records(
    admin: &tokio_postgres::Client,
    migration: &mut tokio_postgres::Client,
    registry: &registry_breg::CompiledRegistry,
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

/// Seed the journal an existing-data migration leaves behind. Such a migration
/// indexes the journal head of every live row as a member of one baseline
/// commit, so every revision the registry retained before that commit stays
/// outside the commit index.
async fn seed_migrated_records(
    admin: &tokio_postgres::Client,
    migration: &mut tokio_postgres::Client,
    registry: &registry_breg::CompiledRegistry,
    kept: Uuid,
    erased: Uuid,
) {
    let transaction = migration.transaction().await.expect("transaction begins");
    insert_revision(&transaction, kept, 1, OLD_PACKAGE, "create").await;
    insert_revision(&transaction, kept, 2, CURRENT_PACKAGE, "patch").await;
    insert_revision(&transaction, erased, 1, OLD_PACKAGE, "create").await;
    insert_revision(&transaction, erased, 2, CURRENT_PACKAGE, "patch").await;
    allocate_revision_commit(
        &transaction,
        CommitAllocation {
            package_revision: CURRENT_PACKAGE,
            origin: CommitOrigin::Baseline {
                system_origin: "breg-existing-history-baseline-v1",
                baseline_reference: None,
            },
            change_context: None,
            members: &[
                RevisionCommitMember {
                    entity_id: ENTITY,
                    record_id: kept,
                    record_revision: 2,
                },
                RevisionCommitMember {
                    entity_id: ENTITY,
                    record_id: erased,
                    record_revision: 2,
                },
            ],
        },
    )
    .await
    .expect("the migration baseline indexes the journal heads alone");
    transaction.commit().await.expect("fixture commits");
    insert_live_row(admin, registry, kept, 2, CURRENT_PACKAGE).await;
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
    registry: &registry_breg::CompiledRegistry,
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
    registry: &registry_breg::CompiledRegistry,
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
        database_id: "history-rebaseline-db".to_owned(),
        package_digest: test_package_digest("pkg-rebaseline-current"),
        activation_id: CURRENT_PACKAGE.to_owned(),
        schema_fingerprint,
    };
    migration
        .execute(
            "INSERT INTO registry_internal.registry_state (
                 singleton, package_id, database_id, active_package_digest,
                 active_activation_id, schema_fingerprint, maintenance_status
             ) VALUES (true, $1, $2, $3, $4::text::uuid, $5, 'ready')",
            &[
                &expected.package_id,
                &expected.database_id,
                &expected.package_digest,
                &expected.activation_id,
                &expected.schema_fingerprint,
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

fn assert_rebaseline_audit_is_minimized(database: &TestDatabase) {
    let entries = database.audit_entries();
    let shape = entries
        .iter()
        .map(|entry| {
            (
                entry["schema"].as_str().expect("schema"),
                entry["phase"].as_str().expect("phase"),
            )
        })
        .collect::<Vec<_>>();
    // The erasure, the completed rebaseline, and the second rebaseline that
    // had nothing to do each record their request and a response under the
    // same correlation; the one that had nothing to do answers unfinished.
    assert_eq!(
        shape,
        [
            (HISTORY_ERASURE_AUDIT_SCHEMA, "request"),
            (HISTORY_ERASURE_AUDIT_SCHEMA, "response"),
            (HISTORY_REBASELINE_AUDIT_SCHEMA, "request"),
            (HISTORY_REBASELINE_AUDIT_SCHEMA, "response"),
            (HISTORY_REBASELINE_AUDIT_SCHEMA, "request"),
            (HISTORY_REBASELINE_AUDIT_SCHEMA, "response"),
        ]
    );
    assert_eq!(entries[2]["correlation"], entries[3]["correlation"]);
    assert_ne!(entries[2]["correlation"], entries[4]["correlation"]);
    assert_eq!(entries[4]["correlation"], entries[5]["correlation"]);
    assert_eq!(entries[5]["record"]["outcome"], "unfinished");
    let audit_text = serde_json::Value::Array(entries[2..].to_vec()).to_string();
    assert!(audit_text.contains("history-rebaseline-maintenance"));
    assert!(!audit_text.contains(OPERATOR_CANARY));
    assert!(!audit_text.contains(KEPT_RECORD));
    assert!(!audit_text.contains(ERASED_RECORD));
    assert!(!audit_text.contains("household-"));
}

fn compiled_registry() -> registry_breg::CompiledRegistry {
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
            "requiredScopes":"unrestricted",
            "requiredPurposes":["operations"],
            "permissions":[{
              "entity":"membership",
              "operations":["create","get","list","patch","snapshot"],
              "readableFields":["person","household","valid-from","valid-to"],
              "writableFields":["person","household","valid-from","valid-to"],
              "rowBoundaries": "unrestricted"
            }]
          }]
        }"#,
    )
    .unwrap();
    compile_project(&project, &[], CompileProfile::Authoring).expect("fixture compiles")
}
