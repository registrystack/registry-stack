// SPDX-License-Identifier: Apache-2.0

#![cfg(all(feature = "postgres-test", feature = "tooling", unix))]

#[path = "support/postgres_harness.rs"]
mod postgres_harness;

use std::{fs, os::unix::fs::PermissionsExt as _, time::Duration};

use postgres_harness::TestDatabase;
use registry_platform_canonical_json::canonicalize_json;
use registry_server::compiler::{compile_project, module_digest, CompileProfile};
use registry_server::contract::{parse_module_yaml, parse_project_yaml};
use registry_server::migration::{
    apply_verified_package, ApplyPrecondition, ApplyRoles, ApplyTimeouts,
    ApplyVerifiedPackageRequest, DestructiveBackupEvidence, MigrationError,
    ReviewedMigrationFaultPoint,
};
use registry_server::migration_plan::{
    ArtifactDigestBinding, ChunkCursorProtocol, ExternalBackupBinding, MigrationRehearsalReceipt,
    RehearsalFixture, RehearsalProofs, RehearsalRowAssertion, ReviewedChangeCover,
    ReviewedMigrationAssertionDescriptor, ReviewedMigrationDescriptor, ReviewedMigrationFile,
    ReviewedMigrationObject, ReviewedMigrationObjectKind, ReviewedMigrationRecovery,
    ReviewedMigrationSource, ReviewedMigrationStepDescriptor,
};
use registry_server::package::{
    compiled_registry_change_set, load_package, prepare_package, CompiledRegistryChangeClass,
    CompiledRegistryChangeCode, PackageBuildRequest, PackageIntent, PackageLoadContext,
    PackageMigrationPlanInput, PackageModuleSource, PackageSourceFile, SignaturePolicy,
    VerifiedPackage,
};
use registry_server::postgres::{
    install_compiled_schema, managed_schema_fingerprint, ExpectedManagedCatalog,
    ExpectedRegistryIdentity,
};
use registry_server::CompiledRegistry;
use serde::Serialize;
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use uuid::Uuid;

const INSTANCE: &str = "migration-instance";
const DATABASE: &str = "migration-database";
const SOURCE_REVISION: &str = "migration-source-revision";
const FIXTURE_JOURNEYS: &[u8] = br#"apiVersion: registry.registrystack.org/server-journeys/v1
journeys:
  - id: asset-list
    steps:
      - id: list-assets
        entity: asset
        accessProfile: reader
        claims: {principal: package-reader}
        request: {operation: list}
        expect: {outcome: success, status: 200, count: 0}
"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_backfill_and_destructive_recovery_are_bounded_resumable_and_activation_closed(
) {
    let database = TestDatabase::create(1).await;
    let _unused_harness_configs = (&database.runtime_config, &database.tls_runtime_config);
    database
        .admin
        .batch_execute("CREATE EXTENSION btree_gist")
        .await
        .expect("administrator installs the required extension");

    let base = compile_variant(Variant::Base, 1);
    let initial_fingerprint = initial_fingerprint(&database, &base).await;
    let initial = prepare_and_load_initial(&base, &initial_fingerprint);
    let active = apply(&database, &initial, ApplyPrecondition::InitialActivation)
        .await
        .expect("initial package activates through the library coordinator");
    seed_backfill_rows(&database, &base, 5).await;

    let required = compile_variant(Variant::RankRequired, 2);
    let required_fingerprint = required_target_fingerprint(&database, &required).await;
    let backfill = backfill_source(BackfillSourceRequest {
        id: "rank-required",
        current: &active,
        prior: &base,
        candidate: &required,
        final_fingerprint: &required_fingerprint,
        pre: AssertionMode::True,
        post: AssertionMode::True,
        rehearsed_rows: 5,
    });
    let required_package = prepare_and_load_reviewed(
        2,
        &active,
        &base,
        Variant::RankRequired,
        &required_fingerprint,
        backfill,
    );

    let interrupted = apply_verified_package(
        request(
            &database,
            &required_package,
            ApplyPrecondition::Successor { current: &active },
        )
        .with_fault_for_test(ReviewedMigrationFaultPoint::AfterCommittedChunk(1)),
    )
    .await;
    assert_value_free(interrupted.err(), MigrationError::ApplyFailed);
    let first_checkpoint = step_snapshot(&database, &required_package, "backfill-rank").await;
    assert_eq!(first_checkpoint.0, "applying");
    assert_eq!(first_checkpoint.2, 2);
    assert!(first_checkpoint.1.is_some());
    assert_non_ready_target(&database, &active, &required_package, "applying").await;

    let wrong_source = backfill_source(BackfillSourceRequest {
        id: "wrong-recovery-target",
        current: &active,
        prior: &base,
        candidate: &required,
        final_fingerprint: &required_fingerprint,
        pre: AssertionMode::True,
        post: AssertionMode::True,
        rehearsed_rows: 5,
    });
    let wrong_package = prepare_and_load_reviewed(
        2,
        &active,
        &base,
        Variant::RankRequired,
        &required_fingerprint,
        wrong_source,
    );
    let wrong_resume = apply(
        &database,
        &wrong_package,
        ApplyPrecondition::Successor { current: &active },
    )
    .await;
    assert_value_free(wrong_resume.err(), MigrationError::ApplyFailed);
    assert_eq!(
        step_snapshot(&database, &required_package, "backfill-rank").await,
        first_checkpoint,
        "a different reviewed target cannot advance the exact durable checkpoint"
    );

    let required_active = apply(
        &database,
        &required_package,
        ApplyPrecondition::Successor { current: &active },
    )
    .await
    .expect("the exact interrupted target resumes");
    let completed = step_snapshot(&database, &required_package, "backfill-rank").await;
    assert_eq!(completed.0, "completed");
    assert_eq!(completed.2, 5);
    assert_all_ranks(&database, &required, 1).await;
    assert_ready_target(&database, &required_active).await;

    let ledger_before_destructive = ledger_snapshot(&database).await;
    assert_eq!(ledger_before_destructive.len(), 2);
    assert!(ledger_before_destructive
        .iter()
        .all(|entry| entry.2 == "applied"));
    let immutable_replay = apply(
        &database,
        &required_package,
        ApplyPrecondition::Successor { current: &active },
    )
    .await;
    assert_value_free(immutable_replay.err(), MigrationError::ApplyFailed);
    assert_eq!(
        ledger_snapshot(&database).await,
        ledger_before_destructive,
        "an applied reviewed migration and its step checkpoints are immutable"
    );

    let removed = compile_variant(Variant::LegacyRemoved, 3);
    let destructive_fingerprint = destructive_target_fingerprint(&database, &removed).await;
    let backup_bytes = synthetic_backup_sql(&required, &required_active, &database.runtime_role, 5);
    let backup_digest = digest(&backup_bytes);
    let now = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("current time formats");
    let binding = ExternalBackupBinding {
        database_id: DATABASE.to_owned(),
        prior_revision: required_active.package_revision.clone(),
        prior_schema_fingerprint: required_active.schema_fingerprint.clone(),
        sha256: backup_digest,
        byte_length: backup_bytes.len() as u64,
        created_at: now,
        max_age_seconds: 3_600,
    };
    let reviewed_destructive_source = destructive_recovery_source(
        "remove-legacy",
        &required_active,
        &required,
        &removed,
        &destructive_fingerprint,
        binding.clone(),
    );
    let destructive_package = prepare_and_load_reviewed(
        3,
        &required_active,
        &required,
        Variant::LegacyRemoved,
        &destructive_fingerprint,
        reviewed_destructive_source,
    );
    let view_transition = &destructive_package.manifest().migration_plan.statements;
    assert_eq!(view_transition.len(), 1);
    assert!(view_transition[0]
        .sql
        .starts_with("CREATE VIEW registry_source."));
    assert!(!view_transition[0].sql.contains("CASCADE"));
    let backup_root = tempfile::Builder::new()
        .prefix("registry-backup-canary-")
        .tempdir_in(
            std::env::temp_dir()
                .canonicalize()
                .expect("canonical temporary root"),
        )
        .expect("backup temporary directory creates");
    let backup_path = backup_root.path().join("path-record-sql-canary.backup");
    fs::write(&backup_path, &backup_bytes).expect("restorable backup artifact writes");
    fs::set_permissions(&backup_path, fs::Permissions::from_mode(0o600))
        .expect("backup evidence permissions close");
    let binding_path = destructive_package
        .reviewed_migration_plan()
        .expect("destructive plan remains validated")
        .migrations()[0]
        .descriptor
        .backup_binding_path
        .as_deref()
        .expect("destructive binding path exists");

    let missing = apply(
        &database,
        &destructive_package,
        ApplyPrecondition::Successor {
            current: &required_active,
        },
    )
    .await;
    assert_value_free(missing.err(), MigrationError::BackupEvidence);
    assert_ready_target(&database, &required_active).await;

    let wrong_target_evidence = [DestructiveBackupEvidence::new(
        "modules/core/migrations/wrong-target/backup.json",
        &backup_path,
    )];
    let wrong_target = apply_with_evidence(
        &database,
        &destructive_package,
        &required_active,
        &wrong_target_evidence,
    )
    .await;
    assert_value_free(wrong_target.err(), MigrationError::BackupEvidence);
    assert_ready_target(&database, &required_active).await;

    fs::set_permissions(&backup_path, fs::Permissions::from_mode(0o644))
        .expect("test opens backup permissions");
    let loose_evidence = [DestructiveBackupEvidence::new(binding_path, &backup_path)];
    let loose = apply_with_evidence(
        &database,
        &destructive_package,
        &required_active,
        &loose_evidence,
    )
    .await;
    assert_value_free(loose.err(), MigrationError::BackupEvidence);
    assert_ready_target(&database, &required_active).await;
    fs::set_permissions(&backup_path, fs::Permissions::from_mode(0o600))
        .expect("test restores backup permissions");

    let symlink_path = backup_root.path().join("backup-link");
    std::os::unix::fs::symlink(&backup_path, &symlink_path).expect("test symlink creates");
    let symlink_evidence = [DestructiveBackupEvidence::new(binding_path, &symlink_path)];
    let symlink = apply_with_evidence(
        &database,
        &destructive_package,
        &required_active,
        &symlink_evidence,
    )
    .await;
    assert_value_free(symlink.err(), MigrationError::BackupEvidence);
    assert_ready_target(&database, &required_active).await;

    let digest_source = destructive_source(
        "remove-legacy-wrong-digest",
        &required_active,
        &required,
        &removed,
        &destructive_fingerprint,
        ExternalBackupBinding {
            sha256: digest(b"different-backup"),
            ..binding.clone()
        },
    );
    let digest_package = prepare_and_load_reviewed(
        3,
        &required_active,
        &required,
        Variant::LegacyRemoved,
        &destructive_fingerprint,
        digest_source,
    );
    let digest_binding_path = digest_package
        .reviewed_migration_plan()
        .expect("digest plan validates")
        .migrations()[0]
        .descriptor
        .backup_binding_path
        .as_deref()
        .expect("digest binding path exists");
    let digest_evidence = [DestructiveBackupEvidence::new(
        digest_binding_path,
        &backup_path,
    )];
    let wrong_digest = apply_with_evidence(
        &database,
        &digest_package,
        &required_active,
        &digest_evidence,
    )
    .await;
    assert_value_free(wrong_digest.err(), MigrationError::BackupEvidence);
    assert_ready_target(&database, &required_active).await;

    let stale_source = destructive_source(
        "remove-legacy-stale",
        &required_active,
        &required,
        &removed,
        &destructive_fingerprint,
        ExternalBackupBinding {
            created_at: "2020-01-01T00:00:00Z".to_owned(),
            max_age_seconds: 60,
            ..binding.clone()
        },
    );
    let stale_package = prepare_and_load_reviewed(
        3,
        &required_active,
        &required,
        Variant::LegacyRemoved,
        &destructive_fingerprint,
        stale_source,
    );
    let stale_binding_path = stale_package
        .reviewed_migration_plan()
        .expect("stale package remains structurally valid")
        .migrations()[0]
        .descriptor
        .backup_binding_path
        .as_deref()
        .expect("stale binding path exists");
    let stale_evidence = [DestructiveBackupEvidence::new(
        stale_binding_path,
        &backup_path,
    )];
    let stale =
        apply_with_evidence(&database, &stale_package, &required_active, &stale_evidence).await;
    assert_value_free(stale.err(), MigrationError::BackupEvidence);
    assert_ready_target(&database, &required_active).await;

    let wrong_database_package = prepare_and_load_reviewed_for_database(
        3,
        &required_active,
        &required,
        Variant::LegacyRemoved,
        &destructive_fingerprint,
        destructive_source(
            "remove-legacy-wrong-database",
            &ExpectedRegistryIdentity {
                database_id: "other-database".to_owned(),
                ..required_active.clone()
            },
            &required,
            &removed,
            &destructive_fingerprint,
            ExternalBackupBinding {
                database_id: "other-database".to_owned(),
                ..binding.clone()
            },
        ),
        "other-database",
    );
    let wrong_database = apply(
        &database,
        &wrong_database_package,
        ApplyPrecondition::Successor {
            current: &required_active,
        },
    )
    .await;
    assert_value_free(wrong_database.err(), MigrationError::PackageBinding);
    assert_ready_target(&database, &required_active).await;

    let valid_evidence = [DestructiveBackupEvidence::new(binding_path, &backup_path)];
    let destructive_fault = apply_with_evidence(
        &database,
        &destructive_package,
        &required_active,
        &valid_evidence,
    )
    .await
    .expect_err("the second reviewed drop deterministically faults after the first committed drop");
    assert_value_free(Some(destructive_fault), MigrationError::ApplyFailed);
    assert_non_ready_target(&database, &required_active, &destructive_package, "failed").await;
    assert_eq!(
        step_snapshot(&database, &destructive_package, "drop-legacy")
            .await
            .0,
        "completed"
    );
    assert_eq!(
        step_snapshot(&database, &destructive_package, "drop-legacy-after-restore")
            .await
            .0,
        "pending"
    );
    assert_legacy_column_absent(&database, &required).await;

    restore_synthetic_backup(&database, &binding, &backup_path).await;
    assert_restored_prior_schema_and_rows(&database, &required, &required_active, 5).await;

    let active_noop = apply(
        &database,
        &required_package,
        ApplyPrecondition::Successor {
            current: &required_active,
        },
    )
    .await;
    assert_value_free(active_noop.err(), MigrationError::PackageBinding);
    assert_non_ready_target(&database, &required_active, &destructive_package, "failed").await;

    let substituted_source = destructive_source(
        "remove-legacy-substituted-target",
        &required_active,
        &required,
        &removed,
        &destructive_fingerprint,
        binding.clone(),
    );
    let substituted_package = prepare_and_load_reviewed(
        3,
        &required_active,
        &required,
        Variant::LegacyRemoved,
        &destructive_fingerprint,
        substituted_source,
    );
    let substituted_binding_path = substituted_package
        .reviewed_migration_plan()
        .expect("substituted plan validates")
        .migrations()[0]
        .descriptor
        .backup_binding_path
        .as_deref()
        .expect("substituted binding path exists");
    let substituted_evidence = [DestructiveBackupEvidence::new(
        substituted_binding_path,
        &backup_path,
    )];
    let substituted = apply_with_evidence(
        &database,
        &substituted_package,
        &required_active,
        &substituted_evidence,
    )
    .await;
    assert_value_free(substituted.err(), MigrationError::ApplyFailed);
    assert_non_ready_target(&database, &required_active, &destructive_package, "failed").await;
    assert_restored_prior_schema_and_rows(&database, &required, &required_active, 5).await;

    let destructive_active = apply_with_evidence(
        &database,
        &destructive_package,
        &required_active,
        &valid_evidence,
    )
    .await
    .expect("the exact reviewed failed target performs the bound fix-forward step and activates");
    assert_ready_target(&database, &destructive_active).await;
    assert_legacy_column_absent(&database, &required).await;
    assert_eq!(ledger_snapshot(&database).await.len(), 3);
    assert!(ledger_snapshot(&database)
        .await
        .iter()
        .all(|entry| entry.2 == "applied"));

    database.cleanup().await;

    false_assertion_refusals_are_closed().await;
    row_count_mismatch_is_closed().await;
    lock_timeout_is_bounded().await;
}

/// A field added with `required: true` reaches an entity that already holds
/// rows. The compiled successor DDL must add the column without `NOT NULL`,
/// let the reviewed backfill populate it, and only then constrain it, so the
/// activation completes instead of entering durable failed maintenance.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_added_required_field_backfills_before_the_column_is_constrained() {
    let database = TestDatabase::create(1).await;
    let _unused_harness_configs = (&database.runtime_config, &database.tls_runtime_config);
    database
        .admin
        .batch_execute("CREATE EXTENSION btree_gist")
        .await
        .expect("administrator installs the required extension");

    let base = compile_variant(Variant::Base, 1);
    let initial_fingerprint = initial_fingerprint(&database, &base).await;
    let initial = prepare_and_load_initial(&base, &initial_fingerprint);
    let active = apply(&database, &initial, ApplyPrecondition::InitialActivation)
        .await
        .expect("added required field scenario activates its initial package");
    seed_backfill_rows(&database, &base, 5).await;

    let candidate = compile_variant(Variant::BatchAddedRequired, 2);
    let change_set =
        compiled_registry_change_set(&base, &candidate, &active.package_revision).changes;
    assert!(
        change_set.iter().any(|change| {
            change.code == CompiledRegistryChangeCode::FieldAddedRequired
                && change.class == CompiledRegistryChangeClass::DataBackfillRequired
        }),
        "adding a required field stays a reviewable data backfill"
    );

    let target_fingerprint = added_required_target_fingerprint(&database, &candidate).await;
    let source = added_required_source(
        "add-required-batch",
        &active,
        &base,
        &candidate,
        &target_fingerprint,
        5,
    );
    let package = prepare_and_load_reviewed(
        2,
        &active,
        &base,
        Variant::BatchAddedRequired,
        &target_fingerprint,
        source,
    );

    let activated = apply(
        &database,
        &package,
        ApplyPrecondition::Successor { current: &active },
    )
    .await
    .expect("the reviewed backfill runs before the added column is constrained");
    assert_ready_target(&database, &activated).await;
    assert_added_required_column(&database, &candidate, "reviewed-batch").await;
    assert_eq!(
        activated.schema_fingerprint, target_fingerprint,
        "the upgraded managed schema matches the measured target schema"
    );

    database.cleanup().await;
}

#[derive(Clone, Copy)]
enum Variant {
    Base,
    RankRequired,
    LegacyRemoved,
    BatchAddedRequired,
}

#[derive(Clone, Copy)]
enum AssertionMode {
    True,
    False,
}

async fn false_assertion_refusals_are_closed() {
    for (pre, post) in [
        (AssertionMode::False, AssertionMode::True),
        (AssertionMode::True, AssertionMode::False),
    ] {
        let database = TestDatabase::create(1).await;
        database
            .admin
            .batch_execute("CREATE EXTENSION btree_gist")
            .await
            .expect("administrator installs extension");
        let base = compile_variant(Variant::Base, 1);
        let fingerprint = initial_fingerprint(&database, &base).await;
        let initial = prepare_and_load_initial(&base, &fingerprint);
        let active = apply(&database, &initial, ApplyPrecondition::InitialActivation)
            .await
            .expect("assertion scenario initial package activates");
        seed_backfill_rows(&database, &base, 1).await;
        let required = compile_variant(Variant::RankRequired, 2);
        let target_fingerprint = required_target_fingerprint(&database, &required).await;
        let source = backfill_source(BackfillSourceRequest {
            id: match pre {
                AssertionMode::False => "false-pre",
                AssertionMode::True => "false-post",
            },
            current: &active,
            prior: &base,
            candidate: &required,
            final_fingerprint: &target_fingerprint,
            pre,
            post,
            rehearsed_rows: 1,
        });
        let package = prepare_and_load_reviewed(
            2,
            &active,
            &base,
            Variant::RankRequired,
            &target_fingerprint,
            source,
        );
        let refused = apply(
            &database,
            &package,
            ApplyPrecondition::Successor { current: &active },
        )
        .await;
        assert_value_free(refused.err(), MigrationError::ApplyFailed);
        assert_non_ready_target(&database, &active, &package, "failed").await;
        let step = step_snapshot(&database, &package, "backfill-rank").await;
        if matches!(pre, AssertionMode::False) {
            assert_eq!(step.0, "pending");
        } else {
            assert_eq!(step.0, "completed");
        }
        database.cleanup().await;
    }
}

async fn row_count_mismatch_is_closed() {
    let database = TestDatabase::create(1).await;
    database
        .admin
        .batch_execute("CREATE EXTENSION btree_gist")
        .await
        .expect("administrator installs extension");
    let base = compile_variant(Variant::Base, 1);
    let fingerprint = initial_fingerprint(&database, &base).await;
    let initial = prepare_and_load_initial(&base, &fingerprint);
    let active = apply(&database, &initial, ApplyPrecondition::InitialActivation)
        .await
        .expect("row mismatch initial package activates");
    seed_backfill_rows(&database, &base, 2).await;
    let required = compile_variant(Variant::RankRequired, 2);
    let target_fingerprint = required_target_fingerprint(&database, &required).await;
    let source = backfill_source(BackfillSourceRequest {
        id: "row-count-mismatch",
        current: &active,
        prior: &base,
        candidate: &required,
        final_fingerprint: &target_fingerprint,
        pre: AssertionMode::True,
        post: AssertionMode::True,
        rehearsed_rows: 2,
    });
    let package = prepare_and_load_reviewed(
        2,
        &active,
        &base,
        Variant::RankRequired,
        &target_fingerprint,
        source,
    );
    let entity = &base.entities()["asset"];
    let table = quote(&entity.physical_table);
    let rank = quote(&entity.fields["rank"].physical_name);
    database
        .admin
        .batch_execute(&format!(
            "CREATE FUNCTION registry_data.migration_test_skip_update() RETURNS trigger
                 LANGUAGE plpgsql AS 'BEGIN RETURN NULL; END';
             CREATE TRIGGER migration_test_skip_update
                 BEFORE UPDATE OF {rank} ON registry_data.{table}
                 FOR EACH ROW EXECUTE FUNCTION registry_data.migration_test_skip_update()"
        ))
        .await
        .expect("administrator installs a row-count fault trigger");
    let refused = apply(
        &database,
        &package,
        ApplyPrecondition::Successor { current: &active },
    )
    .await;
    assert_value_free(refused.err(), MigrationError::ApplyFailed);
    assert_non_ready_target(&database, &active, &package, "failed").await;
    let step = step_snapshot(&database, &package, "backfill-rank").await;
    assert_eq!(step.0, "pending");
    assert_eq!(step.2, 0);
    database.cleanup().await;
}

async fn lock_timeout_is_bounded() {
    let database = TestDatabase::create(1).await;
    database
        .admin
        .batch_execute("CREATE EXTENSION btree_gist")
        .await
        .expect("administrator installs extension");
    let base = compile_variant(Variant::Base, 1);
    let fingerprint = initial_fingerprint(&database, &base).await;
    let initial = prepare_and_load_initial(&base, &fingerprint);
    let active = apply(&database, &initial, ApplyPrecondition::InitialActivation)
        .await
        .expect("timeout scenario initial package activates");
    seed_backfill_rows(&database, &base, 1).await;
    let required = compile_variant(Variant::RankRequired, 2);
    let target_fingerprint = required_target_fingerprint(&database, &required).await;
    let source = backfill_source(BackfillSourceRequest {
        id: "lock-timeout",
        current: &active,
        prior: &base,
        candidate: &required,
        final_fingerprint: &target_fingerprint,
        pre: AssertionMode::True,
        post: AssertionMode::True,
        rehearsed_rows: 1,
    });
    let package = prepare_and_load_reviewed(
        2,
        &active,
        &base,
        Variant::RankRequired,
        &target_fingerprint,
        source,
    );
    let table = quote(&base.entities()["asset"].physical_table);
    let (mut blocker_client, blocker_task) = database.connect_migration().await;
    let blocker = blocker_client
        .transaction()
        .await
        .expect("lock blocker transaction starts");
    blocker
        .batch_execute(&format!(
            "LOCK TABLE registry_data.{table} IN ACCESS EXCLUSIVE MODE"
        ))
        .await
        .expect("lock blocker holds the entity table");
    let refused = apply(
        &database,
        &package,
        ApplyPrecondition::Successor { current: &active },
    )
    .await;
    assert_value_free(refused.err(), MigrationError::ApplyFailed);
    blocker.rollback().await.expect("lock blocker rolls back");
    blocker_task.abort();
    assert_non_ready_target(&database, &active, &package, "failed").await;
    database.cleanup().await;
}

fn compile_variant(variant: Variant, sequence: u64) -> CompiledRegistry {
    let module_bytes = module_bytes(variant);
    let module = parse_module_yaml(&module_bytes).expect("test module parses");
    let project_bytes = project_bytes(sequence, &module_digest(&module));
    let project = parse_project_yaml(&project_bytes).expect("test project parses");
    compile_project(&project, &[module], CompileProfile::Production)
        .expect("test Registry compiles")
}

fn project_bytes(sequence: u64, digest: &str) -> Vec<u8> {
    format!(
        r#"{{"apiVersion":"registry.registrystack.org/v1alpha1","kind":"RegistryProject","registry":{{"id":"migration-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://migration.example.test"}},"package":{{"environment":"local","instanceId":"{INSTANCE}","sequence":{sequence},"sourceRevision":"{SOURCE_REVISION}"}},"manifestProjection":{{"accessProfile":"reader","classificationCeiling":"internal","catalog":{{"baseUrl":"https://migration.example.test","title":"Migration Registry","publisher":{{"id":"migration-registry-authority","name":"Migration Publisher"}}}},"publicService":{{"id":"migration-registry-service","title":"Migration Registry"}},"datasets":[{{"id":"migration-registry","title":"Migration Dataset","owner":"Migration Publisher","status":"active"}}],"dataServices":[{{"id":"migration-registry-data-service","title":"Migration Registry","endpointUrl":"https://migration.example.test","servesDatasets":["migration-registry"]}}]}},"modules":[{{"id":"core","version":"1","digest":"{digest}"}}]}}"#
    )
    .into_bytes()
}

fn module_bytes(variant: Variant) -> Vec<u8> {
    let rank_required = if matches!(variant, Variant::RankRequired | Variant::LegacyRemoved) {
        r#","required":true"#
    } else {
        ""
    };
    let legacy = if matches!(variant, Variant::LegacyRemoved) {
        ""
    } else {
        r#",{"id":"legacy","type":"string","maxLength":16,"classification":"internal"}"#
    };
    let batch = if matches!(variant, Variant::BatchAddedRequired) {
        r#",{"id":"batch","type":"string","maxLength":16,"classification":"internal","required":true}"#
    } else {
        ""
    };
    format!(
        r#"{{"id":"core","version":"1","entities":[{{"id":"asset","primaryDataset":"migration-registry","route":"assets","mutationMode":"create_only","fields":[{{"id":"code","type":"string","maxLength":8,"classification":"internal"}},{{"id":"rank","type":"int64","classification":"internal"{rank_required}}}{legacy}{batch}],"accessProfiles":[{{"id":"reader","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]}}]}}]}}"#
    )
    .into_bytes()
}

fn prepare_and_load_initial(registry: &CompiledRegistry, fingerprint: &str) -> VerifiedPackage {
    let prepared = prepare_package(build_request(
        Variant::Base,
        1,
        None,
        fingerprint,
        PackageMigrationPlanInput::InitialCompiledDdl,
        DATABASE,
    ))
    .expect("initial package prepares");
    let loaded = publish_and_load(
        prepared,
        local_context(DATABASE, PackageIntent::InitialActivation),
    );
    assert_eq!(loaded.registry(), registry);
    loaded
}

fn prepare_and_load_reviewed(
    sequence: u64,
    current: &ExpectedRegistryIdentity,
    prior: &CompiledRegistry,
    variant: Variant,
    fingerprint: &str,
    source: ReviewedMigrationSource,
) -> VerifiedPackage {
    prepare_and_load_reviewed_for_database(
        sequence,
        current,
        prior,
        variant,
        fingerprint,
        source,
        DATABASE,
    )
}

fn prepare_and_load_reviewed_for_database(
    sequence: u64,
    current: &ExpectedRegistryIdentity,
    prior: &CompiledRegistry,
    variant: Variant,
    fingerprint: &str,
    source: ReviewedMigrationSource,
    database_id: &str,
) -> VerifiedPackage {
    let prepared = prepare_package(build_request(
        variant,
        sequence,
        Some(&current.package_revision),
        fingerprint,
        PackageMigrationPlanInput::ReviewedSuccessor {
            prior_registry: Box::new(prior.clone()),
            prior_schema_fingerprint: current.schema_fingerprint.clone(),
            migrations: vec![source],
        },
        database_id,
    ))
    .expect("reviewed package prepares");
    publish_and_load(
        prepared,
        local_context(
            database_id,
            PackageIntent::Activation {
                active_revision: &current.package_revision,
                active_sequence: u64::try_from(current.package_sequence)
                    .expect("active sequence is positive"),
            },
        ),
    )
}

fn build_request(
    variant: Variant,
    sequence: u64,
    prior_revision: Option<&str>,
    schema_fingerprint: &str,
    migration_plan: PackageMigrationPlanInput,
    database_id: &str,
) -> PackageBuildRequest {
    let module_bytes = module_bytes(variant);
    let module = parse_module_yaml(&module_bytes).expect("package module parses");
    PackageBuildRequest {
        environment: "local".to_owned(),
        instance_id: INSTANCE.to_owned(),
        database_id: database_id.to_owned(),
        sequence,
        prior_revision: prior_revision.map(str::to_owned),
        compiler_source_revision: SOURCE_REVISION.to_owned(),
        schema_fingerprint: schema_fingerprint.to_owned(),
        signature_policy: SignaturePolicy {
            threshold: 0,
            key_ids: Vec::new(),
        },
        project: PackageSourceFile {
            path: "source/registry.yaml".to_owned(),
            bytes: project_bytes(sequence, &module_digest(&module)),
        },
        modules: vec![PackageModuleSource {
            id: "core".to_owned(),
            path: "source/modules/core/module.yaml".to_owned(),
            bytes: module_bytes,
            assets: Vec::new(),
        }],
        fixture_journeys: PackageSourceFile {
            path: "tests/journeys.yaml".to_owned(),
            bytes: FIXTURE_JOURNEYS.to_vec(),
        },
        migration_plan,
    }
}

fn publish_and_load(
    prepared: registry_server::package::PreparedPackage,
    context: PackageLoadContext<'_>,
) -> VerifiedPackage {
    let root = tempfile::Builder::new()
        .prefix("registry-reviewed-runtime-")
        .tempdir_in(
            std::env::temp_dir()
                .canonicalize()
                .expect("canonical temporary root"),
        )
        .expect("package temporary directory creates");
    let package = root.path().join("package");
    prepared
        .publish_to_directory(&package, Vec::new())
        .expect("package publishes");
    load_package(&package, &context).expect("published package loads with activation intent")
}

fn local_context<'a>(database_id: &'a str, intent: PackageIntent<'a>) -> PackageLoadContext<'a> {
    PackageLoadContext {
        environment: "local",
        instance_id: INSTANCE,
        database_id,
        database_initialization_environment: "local",
        compiler_source_revision: SOURCE_REVISION,
        trust_anchor: None,
        intent,
    }
}

struct BackfillSourceRequest<'a> {
    id: &'a str,
    current: &'a ExpectedRegistryIdentity,
    prior: &'a CompiledRegistry,
    candidate: &'a CompiledRegistry,
    final_fingerprint: &'a str,
    pre: AssertionMode,
    post: AssertionMode,
    rehearsed_rows: u64,
}

fn backfill_source(request: BackfillSourceRequest<'_>) -> ReviewedMigrationSource {
    let BackfillSourceRequest {
        id,
        current,
        prior,
        candidate,
        final_fingerprint,
        pre,
        post,
        rehearsed_rows,
    } = request;
    let change = compiled_registry_change_set(prior, candidate, &current.package_revision)
        .changes
        .into_iter()
        .find(|change| change.code == CompiledRegistryChangeCode::FieldRequirednessChanged)
        .expect("rank requiredness change is classified");
    let entity = &candidate.entities()["asset"];
    let field = &entity.fields["rank"];
    let base = format!("modules/core/migrations/{id}");
    let update_path = format!("{base}/steps/backfill-rank.sql");
    let alter_path = format!("{base}/steps/set-rank-not-null.sql");
    let pre_path = format!("{base}/assertions/pre.sql");
    let post_path = format!("{base}/assertions/post.sql");
    let update_sql = format!(
        "UPDATE registry_data.{} SET {} = 1 WHERE record_id = ANY($1::pg_catalog.uuid[])",
        entity.physical_table, field.physical_name
    );
    let alter_sql = format!(
        "ALTER TABLE registry_data.{} ALTER COLUMN {} SET NOT NULL",
        entity.physical_table, field.physical_name
    );
    let true_pre = format!(
        "SELECT pg_catalog.count(*) >= 0 FROM registry_data.{}",
        entity.physical_table
    );
    let true_post = format!(
        "SELECT pg_catalog.count(*) = pg_catalog.count({}) FROM registry_data.{}",
        field.physical_name, entity.physical_table
    );
    let pre_sql = match pre {
        AssertionMode::True => true_pre,
        AssertionMode::False => "SELECT false".to_owned(),
    };
    let post_sql = match post {
        AssertionMode::True => true_post,
        AssertionMode::False => "SELECT false".to_owned(),
    };
    let object = ReviewedMigrationObject {
        schema: "registry_data".to_owned(),
        table: entity.physical_table.clone(),
        entity_id: "asset".to_owned(),
        kind: ReviewedMigrationObjectKind::Field,
        member_id: Some("rank".to_owned()),
        physical_name: field.physical_name.clone(),
    };
    let descriptor = ReviewedMigrationDescriptor {
        id: id.to_owned(),
        change_class: CompiledRegistryChangeClass::DataBackfillRequired,
        covers: vec![ReviewedChangeCover::from(&change)],
        recovery: ReviewedMigrationRecovery::ExactTargetResume,
        lock_timeout_ms: 50,
        statement_timeout_ms: 5_000,
        steps: vec![
            ReviewedMigrationStepDescriptor::ChunkedBackfill {
                id: "backfill-rank".to_owned(),
                entity_id: "asset".to_owned(),
                sql_path: update_path.clone(),
                objects: vec![object.clone()],
                cursor: ChunkCursorProtocol::RecordIdUuidArray,
                chunk_size: 2,
                max_total_rows: 10,
                lock_timeout_ms: 50,
                statement_timeout_ms: 5_000,
                exact_affected_rows: true,
            },
            ReviewedMigrationStepDescriptor::TransactionalSql {
                id: "set-rank-not-null".to_owned(),
                sql_path: alter_path.clone(),
                objects: vec![object],
                affected_rows: None,
            },
        ],
        pre_assertions: vec![ReviewedMigrationAssertionDescriptor {
            id: "pre".to_owned(),
            sql_path: pre_path.clone(),
        }],
        post_assertions: vec![ReviewedMigrationAssertionDescriptor {
            id: "post".to_owned(),
            sql_path: post_path.clone(),
        }],
        rehearsal_receipt_path: format!("{base}/rehearsal.json"),
        backup_binding_path: None,
    };
    reviewed_source(ReviewedSourceRequest {
        descriptor,
        current,
        final_fingerprint,
        steps: vec![(update_path, update_sql), (alter_path, alter_sql)],
        pre: (pre_path, pre_sql),
        post: (post_path, post_sql),
        backup: None,
        row_assertions: vec![RehearsalRowAssertion {
            step_id: "backfill-rank".to_owned(),
            affected_rows: rehearsed_rows,
        }],
    })
}

fn added_required_source(
    id: &str,
    current: &ExpectedRegistryIdentity,
    prior: &CompiledRegistry,
    candidate: &CompiledRegistry,
    final_fingerprint: &str,
    rehearsed_rows: u64,
) -> ReviewedMigrationSource {
    let change = compiled_registry_change_set(prior, candidate, &current.package_revision)
        .changes
        .into_iter()
        .find(|change| change.code == CompiledRegistryChangeCode::FieldAddedRequired)
        .expect("the added required field is classified");
    let entity = &candidate.entities()["asset"];
    let field = &entity.fields["batch"];
    let base = format!("modules/core/migrations/{id}");
    let update_path = format!("{base}/steps/backfill-batch.sql");
    let pre_path = format!("{base}/assertions/pre.sql");
    let post_path = format!("{base}/assertions/post.sql");
    let update_sql = format!(
        "UPDATE registry_data.{} SET {} = 'reviewed-batch' WHERE record_id = ANY($1::pg_catalog.uuid[])",
        entity.physical_table, field.physical_name
    );
    let pre_sql = format!(
        "SELECT pg_catalog.count(*) >= 0 FROM registry_data.{}",
        entity.physical_table
    );
    let post_sql = format!(
        "SELECT pg_catalog.count(*) = pg_catalog.count({}) FROM registry_data.{}",
        field.physical_name, entity.physical_table
    );
    let descriptor = ReviewedMigrationDescriptor {
        id: id.to_owned(),
        change_class: CompiledRegistryChangeClass::DataBackfillRequired,
        covers: vec![ReviewedChangeCover::from(&change)],
        recovery: ReviewedMigrationRecovery::ExactTargetResume,
        lock_timeout_ms: 50,
        statement_timeout_ms: 5_000,
        steps: vec![ReviewedMigrationStepDescriptor::ChunkedBackfill {
            id: "backfill-batch".to_owned(),
            entity_id: "asset".to_owned(),
            sql_path: update_path.clone(),
            objects: vec![ReviewedMigrationObject {
                schema: "registry_data".to_owned(),
                table: entity.physical_table.clone(),
                entity_id: "asset".to_owned(),
                kind: ReviewedMigrationObjectKind::Field,
                member_id: Some("batch".to_owned()),
                physical_name: field.physical_name.clone(),
            }],
            cursor: ChunkCursorProtocol::RecordIdUuidArray,
            chunk_size: 2,
            max_total_rows: 10,
            lock_timeout_ms: 50,
            statement_timeout_ms: 5_000,
            exact_affected_rows: true,
        }],
        pre_assertions: vec![ReviewedMigrationAssertionDescriptor {
            id: "pre".to_owned(),
            sql_path: pre_path.clone(),
        }],
        post_assertions: vec![ReviewedMigrationAssertionDescriptor {
            id: "post".to_owned(),
            sql_path: post_path.clone(),
        }],
        rehearsal_receipt_path: format!("{base}/rehearsal.json"),
        backup_binding_path: None,
    };
    reviewed_source(ReviewedSourceRequest {
        descriptor,
        current,
        final_fingerprint,
        steps: vec![(update_path, update_sql)],
        pre: (pre_path, pre_sql),
        post: (post_path, post_sql),
        backup: None,
        row_assertions: vec![RehearsalRowAssertion {
            step_id: "backfill-batch".to_owned(),
            affected_rows: rehearsed_rows,
        }],
    })
}

fn destructive_source(
    id: &str,
    current: &ExpectedRegistryIdentity,
    prior: &CompiledRegistry,
    candidate: &CompiledRegistry,
    final_fingerprint: &str,
    backup: ExternalBackupBinding,
) -> ReviewedMigrationSource {
    destructive_source_with_recovery_fault(
        id,
        current,
        prior,
        candidate,
        final_fingerprint,
        backup,
        false,
    )
}

fn destructive_recovery_source(
    id: &str,
    current: &ExpectedRegistryIdentity,
    prior: &CompiledRegistry,
    candidate: &CompiledRegistry,
    final_fingerprint: &str,
    backup: ExternalBackupBinding,
) -> ReviewedMigrationSource {
    destructive_source_with_recovery_fault(
        id,
        current,
        prior,
        candidate,
        final_fingerprint,
        backup,
        true,
    )
}

fn destructive_source_with_recovery_fault(
    id: &str,
    current: &ExpectedRegistryIdentity,
    prior: &CompiledRegistry,
    candidate: &CompiledRegistry,
    final_fingerprint: &str,
    backup: ExternalBackupBinding,
    recovery_fault: bool,
) -> ReviewedMigrationSource {
    let change = compiled_registry_change_set(prior, candidate, &current.package_revision)
        .changes
        .into_iter()
        .find(|change| change.code == CompiledRegistryChangeCode::FieldRemoved)
        .expect("legacy removal is classified");
    let entity = &prior.entities()["asset"];
    let field = &entity.fields["legacy"];
    let base = format!("modules/core/migrations/{id}");
    let step_path = format!("{base}/steps/drop-legacy.sql");
    let recovery_step_path = format!("{base}/steps/drop-legacy-after-restore.sql");
    let pre_path = format!("{base}/assertions/pre.sql");
    let post_path = format!("{base}/assertions/post.sql");
    let assertion = format!(
        "SELECT pg_catalog.count(*) >= 0 FROM registry_data.{}",
        entity.physical_table
    );
    let object = ReviewedMigrationObject {
        schema: "registry_data".to_owned(),
        table: entity.physical_table.clone(),
        entity_id: "asset".to_owned(),
        kind: ReviewedMigrationObjectKind::Field,
        member_id: Some("legacy".to_owned()),
        physical_name: field.physical_name.clone(),
    };
    let mut steps = vec![ReviewedMigrationStepDescriptor::TransactionalSql {
        id: "drop-legacy".to_owned(),
        sql_path: step_path.clone(),
        objects: vec![object.clone()],
        affected_rows: None,
    }];
    let mut step_files = vec![(
        step_path,
        format!(
            "ALTER TABLE registry_data.{} DROP COLUMN {}",
            entity.physical_table, field.physical_name
        ),
    )];
    if recovery_fault {
        steps.push(ReviewedMigrationStepDescriptor::TransactionalSql {
            id: "drop-legacy-after-restore".to_owned(),
            sql_path: recovery_step_path.clone(),
            objects: vec![object],
            affected_rows: None,
        });
        step_files.push((
            recovery_step_path,
            format!(
                "ALTER TABLE registry_data.{} DROP COLUMN {}",
                entity.physical_table, field.physical_name
            ),
        ));
    }
    let descriptor = ReviewedMigrationDescriptor {
        id: id.to_owned(),
        change_class: CompiledRegistryChangeClass::DestructiveOrIrreversible,
        covers: vec![ReviewedChangeCover::from(&change)],
        recovery: ReviewedMigrationRecovery::ExactTargetResume,
        lock_timeout_ms: 50,
        statement_timeout_ms: 5_000,
        steps,
        pre_assertions: vec![ReviewedMigrationAssertionDescriptor {
            id: "pre".to_owned(),
            sql_path: pre_path.clone(),
        }],
        post_assertions: vec![ReviewedMigrationAssertionDescriptor {
            id: "post".to_owned(),
            sql_path: post_path.clone(),
        }],
        rehearsal_receipt_path: format!("{base}/rehearsal.json"),
        backup_binding_path: Some(format!("{base}/backup.json")),
    };
    reviewed_source(ReviewedSourceRequest {
        descriptor,
        current,
        final_fingerprint,
        steps: step_files,
        pre: (pre_path, assertion.clone()),
        post: (post_path, assertion),
        backup: Some(backup),
        row_assertions: Vec::new(),
    })
}

struct ReviewedSourceRequest<'a> {
    descriptor: ReviewedMigrationDescriptor,
    current: &'a ExpectedRegistryIdentity,
    final_fingerprint: &'a str,
    steps: Vec<(String, String)>,
    pre: (String, String),
    post: (String, String),
    backup: Option<ExternalBackupBinding>,
    row_assertions: Vec<RehearsalRowAssertion>,
}

fn reviewed_source(request: ReviewedSourceRequest<'_>) -> ReviewedMigrationSource {
    let ReviewedSourceRequest {
        descriptor,
        current,
        final_fingerprint,
        steps,
        pre,
        post,
        backup,
        row_assertions,
    } = request;
    let descriptor_path = format!("modules/core/migrations/{}/descriptor.json", descriptor.id);
    let descriptor_bytes = canonical(&descriptor);
    let fixture_path = format!(
        "modules/core/migrations/{}/fixtures/representative.jsonl",
        descriptor.id
    );
    let fixture_bytes = b"{\"fixture\":\"representative\"}\n".to_vec();
    let receipt = MigrationRehearsalReceipt {
        prior_revision: current.package_revision.clone(),
        prior_schema_fingerprint: current.schema_fingerprint.clone(),
        plan_sha256: digest(&descriptor_bytes),
        sql_sha256: steps
            .iter()
            .map(|(path, sql)| ArtifactDigestBinding {
                path: path.clone(),
                sha256: digest(sql.as_bytes()),
            })
            .collect(),
        assertion_sha256: vec![
            ArtifactDigestBinding {
                path: pre.0.clone(),
                sha256: digest(pre.1.as_bytes()),
            },
            ArtifactDigestBinding {
                path: post.0.clone(),
                sha256: digest(post.1.as_bytes()),
            },
        ],
        fixture_inventory: vec![RehearsalFixture {
            id: "representative".to_owned(),
            path: fixture_path.clone(),
            sha256: digest(&fixture_bytes),
            row_count: 1,
        }],
        postgres_major: 17,
        row_assertions,
        final_schema_fingerprint: final_fingerprint.to_owned(),
        proofs: RehearsalProofs {
            lock_timeout: true,
            chunk_resume: descriptor.steps.iter().any(|step| {
                matches!(
                    step,
                    ReviewedMigrationStepDescriptor::ChunkedBackfill { .. }
                )
            }),
            destructive_resume: backup.is_some(),
        },
    };
    let mut files = steps
        .into_iter()
        .map(|(path, sql)| ReviewedMigrationFile {
            path,
            bytes: sql.into_bytes(),
        })
        .collect::<Vec<_>>();
    files.extend([
        ReviewedMigrationFile {
            path: pre.0,
            bytes: pre.1.into_bytes(),
        },
        ReviewedMigrationFile {
            path: post.0,
            bytes: post.1.into_bytes(),
        },
        ReviewedMigrationFile {
            path: descriptor.rehearsal_receipt_path.clone(),
            bytes: canonical(&receipt),
        },
        ReviewedMigrationFile {
            path: fixture_path,
            bytes: fixture_bytes,
        },
    ]);
    if let (Some(path), Some(binding)) = (&descriptor.backup_binding_path, backup) {
        files.push(ReviewedMigrationFile {
            path: path.clone(),
            bytes: canonical(&binding),
        });
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));
    ReviewedMigrationSource {
        module_id: "core".to_owned(),
        descriptor: ReviewedMigrationFile {
            path: descriptor_path,
            bytes: descriptor_bytes,
        },
        files,
    }
}

async fn initial_fingerprint(database: &TestDatabase, registry: &CompiledRegistry) -> String {
    let (mut migration, task) = database.connect_migration().await;
    let transaction = migration
        .transaction()
        .await
        .expect("initial fingerprint transaction starts");
    install_compiled_schema(&transaction, registry, &database.runtime_role)
        .await
        .expect("initial schema rehearses");
    let fingerprint = managed_schema_fingerprint(
        &transaction,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(registry),
    )
    .await
    .expect("initial fingerprint computes");
    transaction
        .rollback()
        .await
        .expect("initial rehearsal rolls back");
    task.abort();
    fingerprint
}

async fn required_target_fingerprint(
    database: &TestDatabase,
    candidate: &CompiledRegistry,
) -> String {
    let entity = &candidate.entities()["asset"];
    let table = quote(&entity.physical_table);
    let rank = quote(&entity.fields["rank"].physical_name);
    let (mut migration, task) = database.connect_migration().await;
    let transaction = migration
        .transaction()
        .await
        .expect("required target fingerprint transaction starts");
    transaction
        .batch_execute(&format!(
            "ALTER TABLE registry_data.{table} NO FORCE ROW LEVEL SECURITY;
             UPDATE registry_data.{table} SET {rank} = 1 WHERE {rank} IS NULL;
             ALTER TABLE registry_data.{table} ALTER COLUMN {rank} SET NOT NULL;
             ALTER TABLE registry_data.{table} FORCE ROW LEVEL SECURITY"
        ))
        .await
        .expect("required target rehearses");
    let fingerprint = managed_schema_fingerprint(
        &transaction,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(candidate),
    )
    .await
    .expect("required target fingerprint computes");
    transaction
        .rollback()
        .await
        .expect("required target rehearsal rolls back");
    task.abort();
    fingerprint
}

/// Rehearses the added required column the way an adopter must: the column
/// arrives nullable, the reviewed backfill populates it, and only then does it
/// become `NOT NULL`. The compiler-owned read views are rebuilt because they
/// project the entity's columns.
async fn added_required_target_fingerprint(
    database: &TestDatabase,
    candidate: &CompiledRegistry,
) -> String {
    let entity = &candidate.entities()["asset"];
    let table = quote(&entity.physical_table);
    let batch = quote(&entity.fields["batch"].physical_name);
    let (mut migration, task) = database.connect_migration().await;
    let transaction = migration
        .transaction()
        .await
        .expect("added required target fingerprint transaction starts");
    drop_managed_views_for_fingerprint(&transaction).await;
    transaction
        .batch_execute(&format!(
            "ALTER TABLE registry_data.{table} ADD COLUMN {batch} varchar(16);
             ALTER TABLE registry_data.{table} NO FORCE ROW LEVEL SECURITY;
             UPDATE registry_data.{table} SET {batch} = 'reviewed-batch';
             ALTER TABLE registry_data.{table} FORCE ROW LEVEL SECURITY;
             ALTER TABLE registry_data.{table} ALTER COLUMN {batch} SET NOT NULL"
        ))
        .await
        .expect("added required target rehearses");
    create_candidate_views_for_fingerprint(&transaction, candidate, database.runtime_role.as_str())
        .await;
    let fingerprint = managed_schema_fingerprint(
        &transaction,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(candidate),
    )
    .await
    .expect("added required target fingerprint computes");
    transaction
        .rollback()
        .await
        .expect("added required target rehearsal rolls back");
    task.abort();
    fingerprint
}

async fn destructive_target_fingerprint(
    database: &TestDatabase,
    candidate: &CompiledRegistry,
) -> String {
    let entity = &candidate.entities()["asset"];
    let table = quote(&entity.physical_table);
    let prior = compile_variant(Variant::RankRequired, 2);
    let legacy = quote(&prior.entities()["asset"].fields["legacy"].physical_name);
    let (mut migration, task) = database.connect_migration().await;
    let transaction = migration
        .transaction()
        .await
        .expect("destructive fingerprint transaction starts");
    drop_managed_views_for_fingerprint(&transaction).await;
    transaction
        .batch_execute(&format!(
            "ALTER TABLE registry_data.{table} DROP COLUMN {legacy}"
        ))
        .await
        .expect("destructive target rehearses");
    create_candidate_views_for_fingerprint(&transaction, candidate, database.runtime_role.as_str())
        .await;
    let fingerprint = managed_schema_fingerprint(
        &transaction,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(candidate),
    )
    .await
    .expect("destructive target fingerprint computes");
    transaction
        .rollback()
        .await
        .expect("destructive target rehearsal rolls back");
    task.abort();
    fingerprint
}

async fn drop_managed_views_for_fingerprint(transaction: &tokio_postgres::Transaction<'_>) {
    let rows = transaction
        .query(
            "SELECT schemaname, viewname
               FROM pg_catalog.pg_views
              WHERE schemaname IN ('registry_derived', 'registry_source')
              ORDER BY CASE schemaname WHEN 'registry_derived' THEN 0 ELSE 1 END,
                       viewname",
            &[],
        )
        .await
        .expect("fingerprint rehearsal inventories compiler-owned views");
    for row in rows {
        let schema: String = row.get(0);
        let view: String = row.get(1);
        transaction
            .batch_execute(&format!(
                "DROP VIEW {}.{} RESTRICT",
                quote(&schema),
                quote(&view)
            ))
            .await
            .expect("fingerprint rehearsal drops the prior compiler-owned read view");
    }
}

async fn create_candidate_views_for_fingerprint(
    transaction: &tokio_postgres::Transaction<'_>,
    candidate: &CompiledRegistry,
    runtime_role: &str,
) {
    for statement in candidate.ddl().statements.iter().filter(|statement| {
        statement.kind == registry_server::generated_ddl::DdlStatementKind::View
    }) {
        transaction
            .batch_execute(&statement.sql)
            .await
            .expect("fingerprint rehearsal creates the candidate compiler-owned read view");
    }
    for view in &candidate.ddl().views {
        let schema = quote(&view.schema);
        let name = quote(&view.name);
        transaction
            .batch_execute(&format!(
                "REVOKE ALL ON TABLE {schema}.{name} FROM PUBLIC, {};",
                quote(runtime_role)
            ))
            .await
            .expect("fingerprint rehearsal revokes candidate view privileges");
        if !view.runtime_privileges.is_empty() {
            let privileges = view
                .runtime_privileges
                .iter()
                .map(|privilege| privilege.as_sql())
                .collect::<Vec<_>>()
                .join(", ");
            transaction
                .batch_execute(&format!(
                    "GRANT {privileges} ON TABLE {schema}.{name} TO {};",
                    quote(runtime_role)
                ))
                .await
                .expect("fingerprint rehearsal grants candidate view privileges");
        }
    }
}

async fn seed_backfill_rows(database: &TestDatabase, registry: &CompiledRegistry, count: u64) {
    let entity = &registry.entities()["asset"];
    let table = quote(&entity.physical_table);
    let code = quote(&entity.fields["code"].physical_name);
    let rank = quote(&entity.fields["rank"].physical_name);
    let legacy = quote(&entity.fields["legacy"].physical_name);
    let active_revision: String = database
        .admin
        .query_one(
            "SELECT active_package_revision
             FROM registry_internal.registry_state
             WHERE singleton",
            &[],
        )
        .await
        .expect("active revision reads for seed rows")
        .get(0);
    for index in 0..count {
        database
            .admin
            .execute(
                &format!(
                    "INSERT INTO registry_data.{table}
                         (record_id, active_package_revision, {code}, {rank}, {legacy})
                     VALUES ($1, $2, $3, NULL, $4)"
                ),
                &[
                    &Uuid::from_u128(index as u128 + 1),
                    &active_revision,
                    &format!("c{index}"),
                    &format!("legacy-{index}"),
                ],
            )
            .await
            .expect("administrator seeds a backfill row");
    }
}

fn synthetic_backup_sql(
    registry: &CompiledRegistry,
    active: &ExpectedRegistryIdentity,
    runtime_role: &registry_server::postgres::SqlIdentifier,
    count: u64,
) -> Vec<u8> {
    let entity = &registry.entities()["asset"];
    let table = quote(&entity.physical_table);
    let code = quote(&entity.fields["code"].physical_name);
    let rank = quote(&entity.fields["rank"].physical_name);
    let legacy = quote(&entity.fields["legacy"].physical_name);
    let values = (0..count)
        .map(|index| {
            format!(
                "('{}'::uuid, '{}', 'c{index}'::varchar(8), 1::bigint, 'legacy-{index}'::varchar(16))",
                Uuid::from_u128(index as u128 + 1)
                , active.package_revision.replace('\'', "''")
            )
        })
        .collect::<Vec<_>>()
        .join(",");
    let create = registry
        .ddl()
        .statements
        .iter()
        .find(|statement| statement.id == "entity.asset.table")
        .expect("compiled table DDL exists");
    let asset_views = registry
        .ddl()
        .views
        .iter()
        .filter(|view| view.id.starts_with("entity.asset."))
        .collect::<Vec<_>>();
    let mut sql = String::new();
    for schema in ["registry_derived", "registry_source"] {
        for view in asset_views.iter().filter(|view| view.schema == schema) {
            sql.push_str(&format!(
                "DROP VIEW IF EXISTS {}.{} RESTRICT;\n",
                quote(&view.schema),
                quote(&view.name)
            ));
        }
    }
    sql.push_str(&format!(
        "DROP TABLE registry_data.{table};\n{};\n\
         INSERT INTO registry_data.{table}\n\
             (record_id, active_package_revision, {code}, {rank}, {legacy})\n\
         VALUES {values};\n",
        create.sql
    ));
    for statement in registry.ddl().statements.iter().filter(|statement| {
        statement.id.starts_with("entity.asset.") && statement.id != "entity.asset.table"
    }) {
        sql.push_str(&statement.sql);
        sql.push_str(";\n");
    }
    sql.push_str(&format!(
        "REVOKE ALL ON TABLE registry_data.{table} FROM PUBLIC, {};\n\
         GRANT SELECT, INSERT ON TABLE registry_data.{table} TO {};\n",
        quote(runtime_role.as_str()),
        quote(runtime_role.as_str())
    ));
    for view in asset_views {
        let privileges = view
            .runtime_privileges
            .iter()
            .map(|privilege| privilege.as_sql())
            .collect::<Vec<_>>()
            .join(", ");
        sql.push_str(&format!(
            "REVOKE ALL ON TABLE {}.{} FROM PUBLIC, {};\n",
            quote(&view.schema),
            quote(&view.name),
            quote(runtime_role.as_str())
        ));
        if !privileges.is_empty() {
            sql.push_str(&format!(
                "GRANT {privileges} ON TABLE {}.{} TO {};\n",
                quote(&view.schema),
                quote(&view.name),
                quote(runtime_role.as_str())
            ));
        }
    }
    sql.into_bytes()
}

async fn restore_synthetic_backup(
    database: &TestDatabase,
    binding: &ExternalBackupBinding,
    backup_path: &std::path::Path,
) {
    let bytes = fs::read(backup_path).expect("operator reads the retained backup artifact");
    assert_eq!(bytes.len() as u64, binding.byte_length);
    assert_eq!(digest(&bytes), binding.sha256);
    let sql = std::str::from_utf8(&bytes).expect("synthetic backup is exact UTF-8 SQL");
    let (migration, migration_task) = database.connect_migration().await;
    migration
        .batch_execute(sql)
        .await
        .expect("operator executes the digest-verified restoration bytes");
    migration_task.abort();
}

async fn assert_restored_prior_schema_and_rows(
    database: &TestDatabase,
    registry: &CompiledRegistry,
    expected: &ExpectedRegistryIdentity,
    count: u64,
) {
    let (migration, migration_task) = database.connect_migration().await;
    let fingerprint = managed_schema_fingerprint(
        &migration,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(registry),
    )
    .await
    .expect("restored managed schema fingerprints");
    assert_eq!(fingerprint, expected.schema_fingerprint);
    migration_task.abort();
    let entity = &registry.entities()["asset"];
    let rows = database
        .admin
        .query(
            &format!(
                "SELECT record_id, {} FROM registry_data.{} ORDER BY record_id",
                quote(&entity.fields["legacy"].physical_name),
                quote(&entity.physical_table)
            ),
            &[],
        )
        .await
        .expect("restored rows read");
    assert_eq!(rows.len() as u64, count);
    for (index, row) in rows.iter().enumerate() {
        assert_eq!(row.get::<_, Uuid>(0), Uuid::from_u128(index as u128 + 1));
        assert_eq!(row.get::<_, String>(1), format!("legacy-{index}"));
    }
}

async fn assert_legacy_column_absent(database: &TestDatabase, prior: &CompiledRegistry) {
    let entity = &prior.entities()["asset"];
    let row = database
        .admin
        .query_one(
            "SELECT count(*)
             FROM information_schema.columns
             WHERE table_schema = 'registry_data'
               AND table_name = $1
               AND column_name = $2",
            &[
                &entity.physical_table,
                &entity.fields["legacy"].physical_name,
            ],
        )
        .await
        .expect("column absence reads");
    assert_eq!(row.get::<_, i64>(0), 0);
}

async fn apply(
    database: &TestDatabase,
    package: &VerifiedPackage,
    precondition: ApplyPrecondition<'_>,
) -> registry_server::migration::Result<ExpectedRegistryIdentity> {
    apply_verified_package(request(database, package, precondition)).await
}

fn request<'a>(
    database: &'a TestDatabase,
    package: &'a VerifiedPackage,
    precondition: ApplyPrecondition<'a>,
) -> ApplyVerifiedPackageRequest<'a> {
    ApplyVerifiedPackageRequest::new(
        &database.migration_config,
        package,
        precondition,
        ApplyRoles::new(&database.migration_role, &database.runtime_role),
        ApplyTimeouts::new(Duration::from_secs(1), Duration::from_secs(5))
            .expect("test timeouts are bounded"),
    )
}

async fn apply_with_evidence(
    database: &TestDatabase,
    package: &VerifiedPackage,
    current: &ExpectedRegistryIdentity,
    evidence: &[DestructiveBackupEvidence<'_>],
) -> registry_server::migration::Result<ExpectedRegistryIdentity> {
    apply_verified_package(
        request(database, package, ApplyPrecondition::Successor { current })
            .with_destructive_backup_evidence(evidence),
    )
    .await
}

async fn step_snapshot(
    database: &TestDatabase,
    package: &VerifiedPackage,
    step_id: &str,
) -> (String, Option<Uuid>, i64) {
    let row = database
        .admin
        .query_one(
            "SELECT outcome, checkpoint_record_id, affected_rows
             FROM registry_internal.registry_migration_steps
             WHERE target_package_revision = $1 AND step_id = $2",
            &[&package.manifest().package_revision, &step_id],
        )
        .await
        .expect("step state reads");
    (row.get(0), row.get(1), row.get(2))
}

async fn ledger_snapshot(database: &TestDatabase) -> Vec<(String, String, String)> {
    database
        .admin
        .query(
            "SELECT target_package_revision, plan_kind, outcome
             FROM registry_internal.registry_migrations
             ORDER BY package_sequence",
            &[],
        )
        .await
        .expect("ledger reads")
        .into_iter()
        .map(|row| (row.get(0), row.get(1), row.get(2)))
        .collect()
}

async fn assert_non_ready_target(
    database: &TestDatabase,
    active: &ExpectedRegistryIdentity,
    target: &VerifiedPackage,
    expected_status: &str,
) {
    let row = database
        .admin
        .query_one(
            "SELECT active_package_revision, maintenance_status, maintenance_target_revision
             FROM registry_internal.registry_state WHERE singleton",
            &[],
        )
        .await
        .expect("maintenance state reads");
    assert_eq!(row.get::<_, String>(0), active.package_revision);
    assert_eq!(row.get::<_, String>(1), expected_status);
    assert_eq!(
        row.get::<_, Option<String>>(2).as_deref(),
        Some(target.manifest().package_revision.as_str())
    );
}

async fn assert_ready_target(database: &TestDatabase, expected: &ExpectedRegistryIdentity) {
    let row = database
        .admin
        .query_one(
            "SELECT active_package_revision, schema_fingerprint, package_sequence,
                    maintenance_status, maintenance_target_revision
             FROM registry_internal.registry_state WHERE singleton",
            &[],
        )
        .await
        .expect("ready state reads");
    assert_eq!(row.get::<_, String>(0), expected.package_revision);
    assert_eq!(row.get::<_, String>(1), expected.schema_fingerprint);
    assert_eq!(row.get::<_, i64>(2), expected.package_sequence);
    assert_eq!(row.get::<_, String>(3), "ready");
    assert_eq!(row.get::<_, Option<String>>(4), None);
}

async fn assert_added_required_column(
    database: &TestDatabase,
    candidate: &CompiledRegistry,
    expected: &str,
) {
    let entity = &candidate.entities()["asset"];
    let column = database
        .admin
        .query_one(
            "SELECT is_nullable
             FROM information_schema.columns
             WHERE table_schema = 'registry_data'
               AND table_name = $1
               AND column_name = $2",
            &[
                &entity.physical_table,
                &entity.fields["batch"].physical_name,
            ],
        )
        .await
        .expect("added column nullability reads");
    assert_eq!(column.get::<_, String>(0), "NO");
    let rows = database
        .admin
        .query(
            &format!(
                "SELECT {} FROM registry_data.{} ORDER BY record_id",
                quote(&entity.fields["batch"].physical_name),
                quote(&entity.physical_table)
            ),
            &[],
        )
        .await
        .expect("added column values read");
    assert_eq!(rows.len(), 5);
    assert!(rows.iter().all(|row| row.get::<_, String>(0) == expected));
}

async fn assert_all_ranks(database: &TestDatabase, registry: &CompiledRegistry, expected: i64) {
    let entity = &registry.entities()["asset"];
    let rows = database
        .admin
        .query(
            &format!(
                "SELECT {} FROM registry_data.{} ORDER BY record_id",
                quote(&entity.fields["rank"].physical_name),
                quote(&entity.physical_table)
            ),
            &[],
        )
        .await
        .expect("backfilled values read");
    assert_eq!(rows.len(), 5);
    assert!(rows.iter().all(|row| row.get::<_, i64>(0) == expected));
}

fn assert_value_free(actual: Option<MigrationError>, expected: MigrationError) {
    let actual = actual.expect("operation must fail");
    assert_eq!(actual, expected);
    let diagnostic = format!("{actual:?} {actual}");
    for canary in ["path-record-sql-canary", "legacy-0", "registry_data"] {
        assert!(!diagnostic.contains(canary));
    }
}

fn canonical(value: &impl Serialize) -> Vec<u8> {
    canonicalize_json(&serde_json::to_value(value).expect("test value serializes"))
        .expect("test value canonicalizes")
}

fn digest(bytes: &[u8]) -> String {
    let mut result = String::from("sha256:");
    for byte in Sha256::digest(bytes) {
        use std::fmt::Write as _;
        write!(&mut result, "{byte:02x}").expect("writing to String cannot fail");
    }
    result
}

fn quote(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}
