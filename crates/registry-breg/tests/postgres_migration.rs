// SPDX-License-Identifier: Apache-2.0

#![cfg(all(feature = "postgres-test", feature = "tooling", unix))]

#[path = "support/postgres_harness.rs"]
mod postgres_harness;

use std::{collections::BTreeSet, fs, os::unix::fs::PermissionsExt as _, time::Duration};

use postgres_harness::TestDatabase;
use registry_breg::compiler::{compile_project, module_digest, CompileProfile};
use registry_breg::contract::{parse_module_yaml, parse_project_yaml};
use registry_breg::field_encryption::FieldEncryptionProvider;
use registry_breg::field_encryption_backfill::{
    preflight_field_encryption_backfill, FieldEncryptionBackfillPreflightRequest,
    FieldEncryptionBackfillTimeouts,
};
use registry_breg::migration::{
    apply_verified_package, AppliedFieldEncryptionKeySource, ApplyPrecondition, ApplyRoles,
    ApplyTimeouts, ApplyVerifiedPackageRequest, DestructiveBackupEvidence, MigrationError,
    ReviewedMigrationFaultPoint,
};
use registry_breg::migration_plan::{
    ArtifactDigestBinding, ChunkCursorProtocol, ExternalBackupBinding, MigrationRehearsalReceipt,
    RehearsalFixture, RehearsalProofs, RehearsalRowAssertion, ReviewedChangeCover,
    ReviewedFieldEncryptionHistory, ReviewedMigrationAssertionDescriptor,
    ReviewedMigrationDescriptor, ReviewedMigrationFile, ReviewedMigrationObject,
    ReviewedMigrationObjectKind, ReviewedMigrationRecovery, ReviewedMigrationSource,
    ReviewedMigrationStepDescriptor,
};
use registry_breg::migration_reconcile::{
    reconcile_failed_migration, ReconcileError, ReconcileOutcome, ReconcileReport,
    ReconcileRequest, ReconcileTimeouts, UNRESOLVABLE_CATALOG_UNMATCHED,
};
use registry_breg::package::{
    compiled_registry_change_set, load_package, prepare_package, CompiledRegistryChangeClass,
    CompiledRegistryChangeCode, CompiledRegistryMigrationBaseline, PackageBuildRequest,
    PackageIntent, PackageLoadContext, PackageMigrationPlanInput, PackageModuleSource,
    PackageSourceFile, SignaturePolicy, VerifiedPackage,
};
use registry_breg::postgres::{
    install_compiled_schema, managed_schema_fingerprint, ExpectedManagedCatalog,
    ExpectedRegistryIdentity,
};
use registry_breg::CompiledRegistry;
use registry_platform_audit::AuditProfile;
use registry_platform_canonical_json::canonicalize_json;
use registry_platform_config::{SecretProvider, SecretReference, SecretResolver};
use registry_platform_crypto::field_encryption::ENVELOPE_MEMBER_TAG;
use serde::Serialize;
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use uuid::Uuid;

const INSTANCE: &str = "migration-instance";
const DATABASE: &str = "migration-database";
const SOURCE_REVISION: &str = "migration-source-revision";
const RECONCILE_OPERATOR_CANARY: &str = "operator secret must not enter reconciliation audit";
const FIXTURE_JOURNEYS: &[u8] = br#"apiVersion: registry.registrystack.org/breg-journeys/v1
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

/// A failed activation pins its target, and fixing forward is not always
/// available. Reconciliation must say which of the two packages the live
/// managed catalog actually is, execute only the transition that reading
/// proves safe, and refuse everything else without changing the database.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_reconciliation_completes_reverts_or_refuses_a_pinned_target() {
    reconciliation_completes_a_target_the_catalog_already_reached().await;
    reconciliation_reverts_a_target_that_reached_no_durable_step().await;
    reconciliation_assessment_writes_nothing().await;
}

/// A reviewed apply whose every durable step closed, failing only because an
/// administrator left an unmanaged object behind. While the object is there
/// the reconciliation is unresolvable and refuses to execute; once it is gone
/// the same reconciliation completes the activation exactly as an apply would.
async fn reconciliation_completes_a_target_the_catalog_already_reached() {
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
        .expect("reconciliation scenario initial package activates");
    seed_backfill_rows(&database, &base, 5).await;
    let required = compile_variant(Variant::RankRequired, 2);
    let target_fingerprint = required_target_fingerprint(&database, &required).await;
    let package = prepare_and_load_reviewed(
        2,
        &active,
        &base,
        Variant::RankRequired,
        &target_fingerprint,
        backfill_source(BackfillSourceRequest {
            id: "reconcile-completable",
            current: &active,
            prior: &base,
            candidate: &required,
            final_fingerprint: &target_fingerprint,
            pre: AssertionMode::True,
            post: AssertionMode::True,
            rehearsed_rows: 5,
        }),
    );

    database
        .admin
        .batch_execute(
            "CREATE TABLE registry_data.reconcile_unmanaged_object (id integer PRIMARY KEY)",
        )
        .await
        .expect("administrator leaves an unmanaged object in a managed schema");
    let refused = apply(
        &database,
        &package,
        ApplyPrecondition::Successor { current: &active },
    )
    .await;
    assert_value_free(refused.err(), MigrationError::ApplyFailed);
    assert_non_ready_target(&database, &active, &package, "failed").await;
    assert_eq!(
        step_snapshot(&database, &package, "backfill-rank").await.0,
        "completed"
    );

    let unresolvable = reconcile(&database, &package, &active, &base, false)
        .await
        .expect("an unresolvable catalog is reported, not refused");
    assert_eq!(unresolvable.outcome, ReconcileOutcome::Unresolvable);
    assert_eq!(
        unresolvable.unresolvable_reason,
        Some(UNRESOLVABLE_CATALOG_UNMATCHED)
    );
    assert!(unresolvable.target_catalog_finding.is_some());
    assert!(unresolvable.active_catalog_finding.is_some());
    assert!(!unresolvable.executed);
    assert_eq!(
        reconcile(&database, &package, &active, &base, true)
            .await
            .expect_err("an unresolvable outcome is never executed"),
        ReconcileError::NotExecutable(ReconcileOutcome::Unresolvable)
    );
    assert_non_ready_target(&database, &active, &package, "failed").await;

    database
        .admin
        .batch_execute("DROP TABLE registry_data.reconcile_unmanaged_object")
        .await
        .expect("administrator removes the unmanaged object");
    let completable = reconcile(&database, &package, &active, &base, false)
        .await
        .expect("the catalog is now exactly the pinned target's");
    assert_eq!(completable.outcome, ReconcileOutcome::Completable);
    assert_eq!(completable.target_catalog_finding, None);
    assert_eq!(completable.reviewed_plan_closed, Some(true));
    assert!(!completable.executed);

    let completed = reconcile(&database, &package, &active, &base, true)
        .await
        .expect("the missing activation transition completes");
    assert_eq!(completed.outcome, ReconcileOutcome::Completable);
    assert!(completed.executed);
    let target = target_identity(&package);
    assert_ready_target(&database, &target).await;
    assert_eq!(
        ledger_snapshot(&database)
            .await
            .iter()
            .filter(|entry| entry.2 == "applied")
            .count(),
        2
    );
    assert_all_ranks(&database, &required, 1).await;
    assert_reconcile_audit_is_minimized(&database, "completed").await;
    database.cleanup().await;
}

/// A reviewed apply refused by its own pre-assertion changes nothing durable.
/// Reconciliation must abandon that target so a different successor can be
/// applied, without moving the active identity.
async fn reconciliation_reverts_a_target_that_reached_no_durable_step() {
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
        .expect("revert scenario initial package activates");
    seed_backfill_rows(&database, &base, 5).await;
    let required = compile_variant(Variant::RankRequired, 2);
    let target_fingerprint = required_target_fingerprint(&database, &required).await;
    let abandoned = prepare_and_load_reviewed(
        2,
        &active,
        &base,
        Variant::RankRequired,
        &target_fingerprint,
        backfill_source(BackfillSourceRequest {
            id: "reconcile-abandoned",
            current: &active,
            prior: &base,
            candidate: &required,
            final_fingerprint: &target_fingerprint,
            pre: AssertionMode::False,
            post: AssertionMode::True,
            rehearsed_rows: 5,
        }),
    );
    let refused = apply(
        &database,
        &abandoned,
        ApplyPrecondition::Successor { current: &active },
    )
    .await;
    assert_value_free(refused.err(), MigrationError::ApplyFailed);
    assert_non_ready_target(&database, &active, &abandoned, "failed").await;

    let revertible = reconcile(&database, &abandoned, &active, &base, false)
        .await
        .expect("a target that reached no durable step is assessed");
    assert_eq!(revertible.outcome, ReconcileOutcome::Revertible);
    assert_eq!(revertible.active_catalog_finding, None);
    assert!(revertible.target_catalog_finding.is_some());
    assert_eq!(revertible.durable_step_progress, Some(false));
    assert!(!revertible.executed);

    let reverted = reconcile(&database, &abandoned, &active, &base, true)
        .await
        .expect("the pinned target is abandoned");
    assert!(reverted.executed);
    assert_ready_target(&database, &active).await;
    assert_eq!(
        ledger_snapshot(&database)
            .await
            .iter()
            .find(|entry| entry.0 == abandoned.manifest().package_revision)
            .map(|entry| entry.2.clone()),
        Some("failed".to_owned())
    );
    assert_reconcile_audit_is_minimized(&database, "reverted").await;

    let successor = prepare_and_load_reviewed(
        2,
        &active,
        &base,
        Variant::RankRequired,
        &target_fingerprint,
        backfill_source(BackfillSourceRequest {
            id: "reconcile-successor",
            current: &active,
            prior: &base,
            candidate: &required,
            final_fingerprint: &target_fingerprint,
            pre: AssertionMode::True,
            post: AssertionMode::True,
            rehearsed_rows: 5,
        }),
    );
    let activated = apply(
        &database,
        &successor,
        ApplyPrecondition::Successor { current: &active },
    )
    .await
    .expect("a different successor applies once the abandoned target is released");
    assert_ready_target(&database, &activated).await;
    assert_all_ranks(&database, &required, 1).await;
    database.cleanup().await;
}

/// Assessment is the default, and it must leave the maintenance state, the
/// migration ledger, and the audit journal exactly as it found them.
async fn reconciliation_assessment_writes_nothing() {
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
        .expect("assessment scenario initial package activates");
    seed_backfill_rows(&database, &base, 5).await;
    let required = compile_variant(Variant::RankRequired, 2);
    let target_fingerprint = required_target_fingerprint(&database, &required).await;
    let package = prepare_and_load_reviewed(
        2,
        &active,
        &base,
        Variant::RankRequired,
        &target_fingerprint,
        backfill_source(BackfillSourceRequest {
            id: "reconcile-assessment",
            current: &active,
            prior: &base,
            candidate: &required,
            final_fingerprint: &target_fingerprint,
            pre: AssertionMode::False,
            post: AssertionMode::True,
            rehearsed_rows: 5,
        }),
    );
    let refused = apply(
        &database,
        &package,
        ApplyPrecondition::Successor { current: &active },
    )
    .await;
    assert_value_free(refused.err(), MigrationError::ApplyFailed);

    let before = durable_snapshot(&database).await;
    let assessed = reconcile(&database, &package, &active, &base, false)
        .await
        .expect("assessment reads the pinned target");
    assert_eq!(assessed.outcome, ReconcileOutcome::Revertible);
    assert!(!assessed.executed);
    assert_eq!(durable_snapshot(&database).await, before);
    database.cleanup().await;
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

/// A reviewed field-encryption flip over rows an active registry already
/// holds: the engine seals each keyset chunk under lock in one transaction
/// with its journal capture and durable cursor, an injected fault after one
/// committed chunk leaves the step resumable without double-sealing, the
/// draining chunk verifies the stored ciphertext and records the flip
/// boundary, and only after that does the reviewed `DROP COLUMN` remove the
/// plaintext column.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_field_encryption_flip_seals_resumes_and_drops_the_plaintext_column() {
    let database = TestDatabase::create(1).await;
    let _unused_harness_configs = (&database.runtime_config, &database.tls_runtime_config);
    database
        .admin
        .batch_execute("CREATE EXTENSION btree_gist")
        .await
        .expect("administrator installs the required extension");

    let prior = compile_variant(Variant::EncryptedBase, 1);
    let initial_fingerprint = initial_fingerprint(&database, &prior).await;
    let initial =
        prepare_and_load_initial_variant(Variant::EncryptedBase, &prior, &initial_fingerprint);
    let active = apply(&database, &initial, ApplyPrecondition::InitialActivation)
        .await
        .expect("flip scenario initial package activates");
    let secrets = (0..5)
        .map(|index| format!("flip-secret-{index}"))
        .collect::<Vec<_>>();
    seed_flip_rows(&database, &prior, &secrets, true).await;

    let candidate = compile_variant(Variant::EncryptedFlipOn, 2);
    let statements = flip_compiler_statements(
        &active,
        &prior,
        &candidate,
        ReviewedFieldEncryptionHistory::EraseAndRebaseline,
    );
    let target_fingerprint =
        encrypted_flip_target_fingerprint(&database, &prior, &candidate, &statements).await;
    let source = encrypted_flip_source(FlipSourceRequest {
        id: "encrypt-secret",
        current: &active,
        prior: &prior,
        candidate: &candidate,
        final_fingerprint: &target_fingerprint,
        history: ReviewedFieldEncryptionHistory::EraseAndRebaseline,
        rehearsed_rows: 5,
    });
    let package = prepare_and_load_reviewed(
        2,
        &active,
        &prior,
        Variant::EncryptedFlipOn,
        &target_fingerprint,
        source,
    );
    let predecessor_baseline =
        CompiledRegistryMigrationBaseline::from_compiled(&active.package_revision, &prior);
    let (mut migration, migration_task) = database.connect_migration().await;
    let report = preflight_field_encryption_backfill(
        &mut migration,
        FieldEncryptionBackfillPreflightRequest {
            expected: &active,
            migration_role: &database.migration_role,
            timeouts: FieldEncryptionBackfillTimeouts::new(
                Duration::from_secs(5),
                Duration::from_secs(5),
            )
            .expect("preflight timeouts are bounded"),
            registry: &candidate,
            plan: package
                .reviewed_migration_plan()
                .expect("the successor carries its reviewed plan"),
            predecessor_baseline: Some(&predecessor_baseline),
            target_package_revision: &package.manifest().package_revision,
        },
    )
    .await
    .expect("the operator preflight counts stored copies and normalized collisions");
    migration_task.abort();
    assert_eq!(report.steps.len(), 1);
    assert_eq!(report.steps[0].fields.len(), 1);
    let field = &report.steps[0].fields[0];
    assert_eq!(field.plaintext_row_count, 5);
    assert_eq!(field.journal_row_count, 5);
    assert!(field.duplicate_record_ids.is_empty());
    let keys = flip_key_source();

    // Model an existing deployment initialized before field-encryption control
    // tables shipped. Successor apply must install and reconcile these tables
    // before it changes maintenance state or activates key material.
    database
        .admin
        .batch_execute(
            "DROP TABLE registry_internal.registry_field_encryption_flips;
             DROP TABLE registry_internal.registry_field_encryption_keys;",
        )
        .await
        .expect("legacy deployment has no field-encryption control tables");

    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_commit_head
                SET coverage_ready = false, unavailable_after_position = 0
              WHERE singleton",
            &[],
        )
        .await
        .expect("test marks history coverage incomplete");
    let coverage_refusal = apply_flip(&database, &package, &active, &keys, None).await;
    assert_eq!(
        coverage_refusal.expect_err("incomplete coverage refuses successor begin"),
        MigrationError::ApplyFailed
    );
    let untouched = database
        .admin
        .query_one(
            "SELECT
                 (SELECT maintenance_status = 'ready'
                    AND maintenance_target_revision IS NULL
                    FROM registry_internal.registry_state WHERE singleton),
                 NOT EXISTS (
                     SELECT 1 FROM registry_internal.registry_migrations
                      WHERE target_package_revision = $1
                 ),
                 NOT EXISTS (
                     SELECT 1 FROM registry_internal.registry_field_encryption_flips
                      WHERE boundary_package_revision = $1
                 )",
            &[&package.manifest().package_revision],
        )
        .await
        .expect("refused successor leaves no durable migration state");
    assert!(untouched.get::<_, bool>(0));
    assert!(untouched.get::<_, bool>(1));
    assert!(untouched.get::<_, bool>(2));
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_commit_head
                SET coverage_ready = true, unavailable_after_position = NULL
              WHERE singleton",
            &[],
        )
        .await
        .expect("test restores complete history coverage");

    let interrupted = apply_flip(&database, &package, &active, &keys, Some(1)).await;
    let error = interrupted.expect_err("the injected fault interrupts the flip after one chunk");
    assert_eq!(error, MigrationError::ApplyFailed);
    assert_flip_value_free(&error, &secrets);
    let checkpoint = step_snapshot(&database, &package, "seal-secret").await;
    assert_eq!(checkpoint.0, "applying");
    assert_eq!(checkpoint.1, Some(Uuid::from_u128(2)));
    assert_eq!(checkpoint.2, 2);
    assert_non_ready_target(&database, &active, &package, "applying").await;
    assert_plaintext_column_present(&database, &prior).await;

    let target = apply_flip(&database, &package, &active, &keys, None)
        .await
        .expect("the exact interrupted flip target resumes and completes");
    assert_ready_target(&database, &target).await;
    assert_eq!(
        target.schema_fingerprint, target_fingerprint,
        "the sealed managed schema matches the measured flip target"
    );
    let sealed_step = step_snapshot(&database, &package, "seal-secret").await;
    assert_eq!(sealed_step.0, "completed");
    assert_eq!(
        sealed_step.2, 6,
        "the resume processes every valued or null row exactly once"
    );
    assert_eq!(
        step_snapshot(&database, &package, "drop-secret-plaintext")
            .await
            .0,
        "completed"
    );
    assert_flip_sealed_at_rest(&database, &prior, &candidate, 1).await;
    assert_flip_journal(&database, &target).await;
    assert_flip_boundary_row(&database, &target, "erase-and-rebaseline", 5, 5, 5).await;
    database.cleanup().await;
}

/// The retain-plaintext-history choice seals and drops exactly like the erase
/// choice; what changes is that pre-boundary journal revisions keep serving
/// their plaintext members, and the boundary row records both the choice and
/// the accepted plaintext count so operator tooling stays value-free.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_field_encryption_flip_retains_pre_boundary_plaintext_history() {
    let database = TestDatabase::create(1).await;
    database
        .admin
        .batch_execute("CREATE EXTENSION btree_gist")
        .await
        .expect("administrator installs the required extension");

    let prior = compile_variant(Variant::EncryptedBase, 1);
    let initial_fingerprint = initial_fingerprint(&database, &prior).await;
    let initial =
        prepare_and_load_initial_variant(Variant::EncryptedBase, &prior, &initial_fingerprint);
    let active = apply(&database, &initial, ApplyPrecondition::InitialActivation)
        .await
        .expect("retain scenario initial package activates");
    let secrets = (0..5)
        .map(|index| format!("retain-secret-{index}"))
        .collect::<Vec<_>>();
    seed_flip_rows(&database, &prior, &secrets, false).await;

    let candidate = compile_variant(Variant::EncryptedFlipOn, 2);
    let statements = flip_compiler_statements(
        &active,
        &prior,
        &candidate,
        ReviewedFieldEncryptionHistory::RetainPlaintextHistory,
    );
    let target_fingerprint =
        encrypted_flip_target_fingerprint(&database, &prior, &candidate, &statements).await;
    let source = encrypted_flip_source(FlipSourceRequest {
        id: "retain-secret",
        current: &active,
        prior: &prior,
        candidate: &candidate,
        final_fingerprint: &target_fingerprint,
        history: ReviewedFieldEncryptionHistory::RetainPlaintextHistory,
        rehearsed_rows: 5,
    });
    let package = prepare_and_load_reviewed(
        2,
        &active,
        &prior,
        Variant::EncryptedFlipOn,
        &target_fingerprint,
        source,
    );
    let keys = flip_key_source();

    // A pre-flip guard snapshot can retain plaintext even when neither the
    // proposal effects nor request-target snapshots mention the field.
    let request_id = Uuid::from_u128(0xFE71);
    let fingerprint = format!("sha256:{}", "7".repeat(64));
    let guard_plaintext = "retained-guard-plaintext-canary".to_owned();
    database
        .admin
        .execute(
            "INSERT INTO registry_internal.registry_request_state
                 (request_entity_id, request_id, owner_reference, state,
                  proposal_version, workflow_revision, review_completed_at)
             VALUES ('encryption-request', $1, 'owner:hash', 'canceled', 1, 1,
                     transaction_timestamp())",
            &[&request_id],
        )
        .await
        .expect("retained guard request state inserts");
    database
        .admin
        .execute(
            "INSERT INTO registry_internal.registry_request_proposals
                 (request_entity_id, request_id, proposal_version, request_record_revision,
                  contract_fingerprint, effect_digest, snapshot)
             VALUES ('encryption-request', $1, 1, 1, $2, $2, $3)",
            &[
                &request_id,
                &fingerprint,
                &serde_json::json!({
                    "originatingPackage": active.package_revision,
                    "effects": [],
                    "applicationPreconditions": {"targets": [{
                        "id": "guard-asset",
                        "entityId": "asset",
                        "recordId": Uuid::from_u128(1).to_string(),
                        "expectedRevision": 1,
                        "values": {"secret": guard_plaintext}
                    }]}
                }),
            ],
        )
        .await
        .expect("retained guard proposal inserts");

    let refused = apply_flip(&database, &package, &active, &keys, None)
        .await
        .expect_err("retain mode refuses frozen guard plaintext");
    assert_eq!(
        refused,
        MigrationError::FieldEncryptionRetainedRequestSnapshots {
            entity_id: "asset".to_owned(),
            field_id: "secret".to_owned(),
        }
    );
    assert_flip_value_free(&refused, std::slice::from_ref(&guard_plaintext));
    assert_plaintext_column_present(&database, &prior).await;
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_request_proposals
                SET snapshot = NULL, erased_at = transaction_timestamp()
              WHERE request_entity_id = 'encryption-request' AND request_id = $1",
            &[&request_id],
        )
        .await
        .expect("operator clears the retained guard snapshot");

    let target = apply_flip(&database, &package, &active, &keys, None)
        .await
        .expect("the retained-history flip applies");
    assert_ready_target(&database, &target).await;
    assert_eq!(target.schema_fingerprint, target_fingerprint);
    assert_flip_sealed_at_rest(&database, &prior, &candidate, 0).await;
    assert_flip_journal(&database, &target).await;
    assert_flip_boundary_row(&database, &target, "retain-plaintext-history", 5, 5, 5).await;
    let retained = database
        .admin
        .query_one(
            "SELECT count(*)::bigint
             FROM registry_internal.registry_revisions
             WHERE entity_id = 'asset'
               AND package_revision = $1
               AND jsonb_typeof(convert_from(snapshot, 'UTF8')::jsonb -> 'secret') = 'string'",
            &[&active.package_revision],
        )
        .await
        .expect("pre-boundary journal revisions read");
    assert_eq!(
        retained.get::<_, i64>(0),
        5,
        "pre-boundary revisions keep serving plaintext under the retain choice"
    );
    assert_eq!(
        step_snapshot(&database, &package, "drop-secret-plaintext")
            .await
            .0,
        "completed"
    );
    database.cleanup().await;
}

/// The normalized-duplicate preflight: two rows whose plaintexts collide only
/// after the declared blind-index normalization refuse the whole flip before
/// any chunk seals, naming the duplicate record ids and never the values. The
/// plaintext column and every value survive untouched, and no flip boundary
/// is recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_field_encryption_flip_refuses_normalized_duplicates_value_free() {
    let database = TestDatabase::create(1).await;
    database
        .admin
        .batch_execute("CREATE EXTENSION btree_gist")
        .await
        .expect("administrator installs the required extension");

    let prior = compile_variant(Variant::EncryptedBase, 1);
    let initial_fingerprint = initial_fingerprint(&database, &prior).await;
    let initial =
        prepare_and_load_initial_variant(Variant::EncryptedBase, &prior, &initial_fingerprint);
    let active = apply(&database, &initial, ApplyPrecondition::InitialActivation)
        .await
        .expect("duplicate scenario initial package activates");
    // Put the normalized collision on opposite sides of the 512-row scan
    // boundary so both operator and apply preflights prove cross-page state.
    let mut secrets = (0..513)
        .map(|index| format!("unique-secret-{index}"))
        .collect::<Vec<_>>();
    secrets[0] = "dup-canary".to_owned();
    secrets[512] = "DUP-CANARY".to_owned();
    seed_flip_rows(&database, &prior, &secrets, false).await;

    let candidate = compile_variant(Variant::EncryptedFlipOn, 2);
    let statements = flip_compiler_statements(
        &active,
        &prior,
        &candidate,
        ReviewedFieldEncryptionHistory::EraseAndRebaseline,
    );
    let target_fingerprint =
        encrypted_flip_target_fingerprint(&database, &prior, &candidate, &statements).await;
    let source = encrypted_flip_source(FlipSourceRequest {
        id: "duplicate-secret",
        current: &active,
        prior: &prior,
        candidate: &candidate,
        final_fingerprint: &target_fingerprint,
        history: ReviewedFieldEncryptionHistory::EraseAndRebaseline,
        rehearsed_rows: secrets.len() as u64,
    });
    let package = prepare_and_load_reviewed(
        2,
        &active,
        &prior,
        Variant::EncryptedFlipOn,
        &target_fingerprint,
        source,
    );
    let predecessor_baseline =
        CompiledRegistryMigrationBaseline::from_compiled(&active.package_revision, &prior);
    let (mut migration, migration_task) = database.connect_migration().await;
    let report = preflight_field_encryption_backfill(
        &mut migration,
        FieldEncryptionBackfillPreflightRequest {
            expected: &active,
            migration_role: &database.migration_role,
            timeouts: FieldEncryptionBackfillTimeouts::new(
                Duration::from_secs(5),
                Duration::from_secs(5),
            )
            .expect("preflight timeouts are bounded"),
            registry: &candidate,
            plan: package
                .reviewed_migration_plan()
                .expect("the successor carries its reviewed plan"),
            predecessor_baseline: Some(&predecessor_baseline),
            target_package_revision: &package.manifest().package_revision,
        },
    )
    .await
    .expect("the operator preflight reports normalized collisions");
    migration_task.abort();
    let field = &report.steps[0].fields[0];
    assert_eq!(field.plaintext_row_count, secrets.len() as u64);
    assert_eq!(field.journal_row_count, secrets.len() as u64);
    assert_eq!(
        field.duplicate_record_ids,
        vec![
            Uuid::from_u128(1).to_string(),
            Uuid::from_u128(513).to_string()
        ]
    );
    let keys = flip_key_source();

    let refused = apply_flip(&database, &package, &active, &keys, None).await;
    let error = refused.expect_err("the normalized duplicate refuses the flip");
    assert_eq!(
        error,
        MigrationError::FieldEncryptionLookupCollision {
            entity_id: "asset".to_owned(),
            record_ids: vec![
                Uuid::from_u128(1).to_string(),
                Uuid::from_u128(513).to_string()
            ],
        }
    );
    assert_flip_value_free(&error, &secrets);
    assert_non_ready_target(&database, &active, &package, "failed").await;
    let step = step_snapshot(&database, &package, "seal-secret").await;
    assert_eq!(step.0, "pending");
    assert_eq!(step.2, 0);
    assert_plaintext_column_present(&database, &prior).await;

    let entity = &candidate.entities()["asset"];
    let envelope = quote(&entity.fields["secret"].physical_name);
    let table = quote(&entity.physical_table);
    let unsealed = database
        .admin
        .query_one(
            &format!(
                "SELECT count(*) FILTER (WHERE {envelope} IS NOT NULL)::bigint,
                        count(*)::bigint
                 FROM registry_data.{table}"
            ),
            &[],
        )
        .await
        .expect("envelope column state reads");
    assert_eq!(unsealed.get::<_, i64>(0), 0, "no row was sealed");
    assert_eq!(
        unsealed.get::<_, i64>(1),
        secrets.len() as i64,
        "the compiler-added envelope column exists"
    );

    let plaintext_column = quote(&prior.entities()["asset"].fields["secret"].physical_name);
    let surviving = database
        .admin
        .query(
            &format!("SELECT {plaintext_column} FROM registry_data.{table} ORDER BY record_id"),
            &[],
        )
        .await
        .expect("surviving plaintext reads");
    let surviving = surviving
        .into_iter()
        .map(|row| row.get::<_, String>(0))
        .collect::<Vec<_>>();
    assert_eq!(
        surviving, secrets,
        "every plaintext value survives untouched"
    );
    assert_flip_boundary_absent(&database).await;
    database.cleanup().await;
}

/// The pre-drop content verification: an administrator who re-introduces
/// plaintext after the last sealing chunk but before the reviewed `DROP
/// COLUMN` must fail the resumed apply closed. The step keeps its durable
/// checkpoint, the plaintext column survives, and the refusal carries no
/// value.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_field_encryption_flip_fails_closed_when_plaintext_returns_before_the_drop() {
    let database = TestDatabase::create(1).await;
    database
        .admin
        .batch_execute("CREATE EXTENSION btree_gist")
        .await
        .expect("administrator installs the required extension");

    let prior = compile_variant(Variant::EncryptedBase, 1);
    let initial_fingerprint = initial_fingerprint(&database, &prior).await;
    let initial =
        prepare_and_load_initial_variant(Variant::EncryptedBase, &prior, &initial_fingerprint);
    let active = apply(&database, &initial, ApplyPrecondition::InitialActivation)
        .await
        .expect("pre-drop scenario initial package activates");
    let secrets = (0..5)
        .map(|index| format!("predrop-secret-{index}"))
        .collect::<Vec<_>>();
    seed_flip_rows(&database, &prior, &secrets, false).await;

    let candidate = compile_variant(Variant::EncryptedFlipOn, 2);
    let statements = flip_compiler_statements(
        &active,
        &prior,
        &candidate,
        ReviewedFieldEncryptionHistory::EraseAndRebaseline,
    );
    let target_fingerprint =
        encrypted_flip_target_fingerprint(&database, &prior, &candidate, &statements).await;
    let source = encrypted_flip_source(FlipSourceRequest {
        id: "predrop-secret",
        current: &active,
        prior: &prior,
        candidate: &candidate,
        final_fingerprint: &target_fingerprint,
        history: ReviewedFieldEncryptionHistory::EraseAndRebaseline,
        rehearsed_rows: 5,
    });
    let package = prepare_and_load_reviewed(
        2,
        &active,
        &prior,
        Variant::EncryptedFlipOn,
        &target_fingerprint,
        source,
    );
    let keys = flip_key_source();

    // Five rows in chunks of two: chunks 1-3 seal every row, and the fourth
    // chunk is the drain that verifies and would close the step.
    let interrupted = apply_flip(&database, &package, &active, &keys, Some(3)).await;
    let error = interrupted.expect_err("the injected fault interrupts after every sealing chunk");
    assert_eq!(error, MigrationError::ApplyFailed);
    let checkpoint = step_snapshot(&database, &package, "seal-secret").await;
    assert_eq!(checkpoint.0, "applying");
    assert_eq!(checkpoint.1, Some(Uuid::from_u128(5)));
    assert_eq!(checkpoint.2, 5);
    assert_non_ready_target(&database, &active, &package, "applying").await;

    let restored = "admin-restore-canary".to_owned();
    let entity = &prior.entities()["asset"];
    let table = quote(&entity.physical_table);
    let plaintext = quote(&entity.fields["secret"].physical_name);
    database
        .admin
        .execute(
            &format!(
                "UPDATE registry_data.{table} SET {plaintext} = $1
                 WHERE record_id = $2"
            ),
            &[&restored, &Uuid::from_u128(1)],
        )
        .await
        .expect("administrator re-introduces plaintext between chunks");

    let mut canaries = secrets.clone();
    canaries.push(restored);
    let refused = apply_flip(&database, &package, &active, &keys, None).await;
    let error = refused.expect_err("the drain verification refuses the returned plaintext");
    assert_eq!(error, MigrationError::ApplyFailed);
    assert_flip_value_free(&error, &canaries);
    assert_non_ready_target(&database, &active, &package, "failed").await;
    assert_eq!(
        step_snapshot(&database, &package, "seal-secret").await,
        checkpoint,
        "the failed drain leaves the durable checkpoint resumable"
    );
    assert_plaintext_column_present(&database, &prior).await;
    assert_flip_boundary_absent(&database).await;
    let envelope = quote(&candidate.entities()["asset"].fields["secret"].physical_name);
    let sealed = database
        .admin
        .query_one(
            &format!(
                "SELECT count(*) FILTER (WHERE {envelope} IS NOT NULL)::bigint
                 FROM registry_data.{table}"
            ),
            &[],
        )
        .await
        .expect("sealed envelope state reads");
    assert_eq!(
        sealed.get::<_, i64>(0),
        5,
        "the sealed envelopes survive the refusal"
    );
    database.cleanup().await;
}

fn assert_flip_value_free(error: &MigrationError, canaries: &[String]) {
    let diagnostic = format!("{error:?} {error}").to_lowercase();
    for canary in canaries {
        assert!(
            !diagnostic.contains(&canary.to_lowercase()),
            "the refusal must not echo a sealed value"
        );
    }
}

#[derive(Clone, Copy)]
enum Variant {
    Base,
    RankRequired,
    LegacyRemoved,
    BatchAddedRequired,
    PatternAdded,
    PatternTightened,
    PatternLoosened,
    PatternInvalid,
    PatternQuoted,
    EncryptedBase,
    EncryptedFlipOn,
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
    let pattern = match variant {
        Variant::PatternAdded => Some("^[0-9]+$"),
        Variant::PatternTightened => Some("^[0-9]{13}$"),
        Variant::PatternLoosened => Some("[0-9]"),
        Variant::PatternInvalid => Some("["),
        Variant::PatternQuoted => Some(r"^a'\\b$"),
        _ => None,
    };
    let legacy = if let Some(pattern) = pattern {
        format!(",{{\"id\":\"legacy\",\"type\":\"string\",\"maxLength\":16,\"classification\":\"internal\",\"pattern\":{}}}", serde_json::to_string(pattern).unwrap())
    } else {
        legacy.to_owned()
    };
    let secret = match variant {
        Variant::EncryptedBase => {
            r#",{"id":"secret","type":"string","maxLength":256,"classification":"restricted"}"#
        }
        Variant::EncryptedFlipOn => {
            r#",{"id":"secret","type":"string","maxLength":256,"classification":"restricted","encrypted":true,"lookup":{"normalization":["uppercase"],"unique":true}}"#
        }
        _ => "",
    };
    format!(
        r#"{{"id":"core","version":"1","entities":[{{"id":"asset","primaryDataset":"migration-registry","route":"assets","mutationMode":"create_only","fields":[{{"id":"code","type":"string","maxLength":8,"classification":"internal"}},{{"id":"rank","type":"int64","classification":"internal"{rank_required}}}{legacy}{batch}{secret}],"accessProfiles":[{{"rowBoundaries": [], "id":"reader","principalClaim":"principal","operations":["create","get","list"],"readableFields":["code"],"writableFields":["code"]}}]}}]}}"#
    )
    .into_bytes()
}

fn prepare_and_load_initial(registry: &CompiledRegistry, fingerprint: &str) -> VerifiedPackage {
    prepare_and_load_initial_variant(Variant::Base, registry, fingerprint)
}

fn prepare_and_load_initial_variant(
    variant: Variant,
    registry: &CompiledRegistry,
    fingerprint: &str,
) -> VerifiedPackage {
    let prepared = prepare_package(build_request(
        variant,
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
    prepared: registry_breg::package::PreparedPackage,
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
        history: None,
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
        history: None,
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

/// The reviewed flip plan the engine executes: one engine-run
/// `FieldEncryptionBackfill` step with no authored SQL, an explicit history
/// choice, and the reviewed `DROP COLUMN` of the sealed plaintext column as a
/// separate transactional step the pre-drop content verification guards.
struct FlipSourceRequest<'a> {
    id: &'a str,
    current: &'a ExpectedRegistryIdentity,
    prior: &'a CompiledRegistry,
    candidate: &'a CompiledRegistry,
    final_fingerprint: &'a str,
    history: ReviewedFieldEncryptionHistory,
    rehearsed_rows: u64,
}

fn encrypted_flip_source(request: FlipSourceRequest<'_>) -> ReviewedMigrationSource {
    let FlipSourceRequest {
        id,
        current,
        prior,
        candidate,
        final_fingerprint,
        history,
        rehearsed_rows,
    } = request;
    let change = compiled_registry_change_set(prior, candidate, &current.package_revision)
        .changes
        .into_iter()
        .find(|change| change.code == CompiledRegistryChangeCode::FieldEncryptionChanged)
        .expect("the encryption flip is classified");
    let prior_entity = &prior.entities()["asset"];
    let prior_secret = &prior_entity.fields["secret"];
    let entity = &candidate.entities()["asset"];
    let field = &entity.fields["secret"];
    let blind = field
        .encryption
        .as_ref()
        .and_then(|encryption| encryption.blind_index.as_ref())
        .expect("the flip candidate declares a blind index");
    assert_ne!(
        field.physical_name, prior_secret.physical_name,
        "the envelope column replaces the plaintext column under its own physical name"
    );
    let base = format!("modules/core/migrations/{id}");
    let drop_path = format!("{base}/steps/drop-secret-plaintext.sql");
    let pre_path = format!("{base}/assertions/pre.sql");
    let post_path = format!("{base}/assertions/post.sql");
    let drop_sql = format!(
        "ALTER TABLE registry_data.{} DROP COLUMN {}",
        entity.physical_table, prior_secret.physical_name
    );
    let assertion_sql = format!(
        "SELECT pg_catalog.count(*) >= 0 FROM registry_data.{}",
        entity.physical_table
    );
    let descriptor = ReviewedMigrationDescriptor {
        id: id.to_owned(),
        change_class: change.class,
        covers: vec![ReviewedChangeCover::from(&change)],
        recovery: ReviewedMigrationRecovery::ExactTargetResume,
        lock_timeout_ms: 50,
        statement_timeout_ms: 5_000,
        steps: vec![
            ReviewedMigrationStepDescriptor::FieldEncryptionBackfill {
                id: "seal-secret".to_owned(),
                entity_id: "asset".to_owned(),
                objects: vec![
                    ReviewedMigrationObject {
                        schema: "registry_data".to_owned(),
                        table: entity.physical_table.clone(),
                        entity_id: "asset".to_owned(),
                        kind: ReviewedMigrationObjectKind::Field,
                        member_id: Some("secret".to_owned()),
                        physical_name: field.physical_name.clone(),
                    },
                    ReviewedMigrationObject {
                        schema: "registry_data".to_owned(),
                        table: entity.physical_table.clone(),
                        entity_id: "asset".to_owned(),
                        kind: ReviewedMigrationObjectKind::Field,
                        member_id: Some("secret#lookup".to_owned()),
                        physical_name: blind.physical_name.clone(),
                    },
                ],
                cursor: ChunkCursorProtocol::RecordIdUuidArray,
                chunk_size: 2,
                max_total_rows: 10_000,
                lock_timeout_ms: 50,
                statement_timeout_ms: 5_000,
            },
            ReviewedMigrationStepDescriptor::TransactionalSql {
                id: "drop-secret-plaintext".to_owned(),
                sql_path: drop_path.clone(),
                objects: vec![ReviewedMigrationObject {
                    schema: "registry_data".to_owned(),
                    table: entity.physical_table.clone(),
                    entity_id: "asset".to_owned(),
                    kind: ReviewedMigrationObjectKind::Field,
                    member_id: Some("secret".to_owned()),
                    physical_name: prior_secret.physical_name.clone(),
                }],
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
        history: Some(history),
    };
    reviewed_source(ReviewedSourceRequest {
        descriptor,
        current,
        final_fingerprint,
        steps: vec![(drop_path, drop_sql)],
        pre: (pre_path, assertion_sql.clone()),
        post: (post_path, assertion_sql),
        backup: None,
        row_assertions: vec![RehearsalRowAssertion {
            step_id: "seal-secret".to_owned(),
            affected_rows: rehearsed_rows,
        }],
    })
}

/// The compiler delta a reviewed flip package carries: the same statement list
/// the apply executes around its reviewed steps. A probe package prepared
/// against a placeholder fingerprint is the cheapest way to read it, because
/// the statements are a pure function of the prior and candidate registries.
fn flip_compiler_statements(
    current: &ExpectedRegistryIdentity,
    prior: &CompiledRegistry,
    candidate: &CompiledRegistry,
    history: ReviewedFieldEncryptionHistory,
) -> Vec<(
    String,
    String,
    registry_breg::generated_ddl::DdlStatementKind,
)> {
    let placeholder = format!("sha256:{}", "0".repeat(64));
    let source = encrypted_flip_source(FlipSourceRequest {
        id: "encrypt-secret-probe",
        current,
        prior,
        candidate,
        final_fingerprint: &placeholder,
        history,
        rehearsed_rows: 5,
    });
    let probe = prepare_and_load_reviewed(
        2,
        current,
        prior,
        Variant::EncryptedFlipOn,
        &placeholder,
        source,
    );
    probe
        .manifest()
        .migration_plan
        .statements
        .iter()
        .map(|statement| (statement.id.clone(), statement.sql.clone(), statement.kind))
        .collect()
}

/// Rehearses the flip target the way the apply reaches it: the compiler's
/// non-view statements (envelope column, blind-index column, unique index)
/// arrive first, the managed read views drop, the sealed plaintext column
/// leaves, and the candidate read views are rebuilt.
async fn encrypted_flip_target_fingerprint(
    database: &TestDatabase,
    prior: &CompiledRegistry,
    candidate: &CompiledRegistry,
    statements: &[(
        String,
        String,
        registry_breg::generated_ddl::DdlStatementKind,
    )],
) -> String {
    use registry_breg::generated_ddl::DdlStatementKind;
    let entity = &candidate.entities()["asset"];
    let table = quote(&entity.physical_table);
    let plaintext = quote(&prior.entities()["asset"].fields["secret"].physical_name);
    let (mut migration, task) = database.connect_migration().await;
    let transaction = migration
        .transaction()
        .await
        .expect("flip target fingerprint transaction starts");
    for (id, sql, _kind) in statements
        .iter()
        .filter(|(_, _, kind)| *kind != DdlStatementKind::View)
    {
        transaction
            .batch_execute(sql)
            .await
            .unwrap_or_else(|error| panic!("flip target rehearses {id}: {error}"));
    }
    drop_managed_views_for_fingerprint(&transaction).await;
    transaction
        .batch_execute(&format!(
            "ALTER TABLE registry_data.{table} DROP COLUMN {plaintext}"
        ))
        .await
        .expect("flip target rehearses the sealed plaintext column drop");
    create_candidate_views_for_fingerprint(&transaction, candidate, database.runtime_role.as_str())
        .await;
    let fingerprint = managed_schema_fingerprint(
        &transaction,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(candidate),
    )
    .await
    .expect("flip target fingerprint computes");
    transaction
        .rollback()
        .await
        .expect("flip target rehearsal rolls back");
    task.abort();
    fingerprint
}

/// The local-file data-key fixture one flip apply resolves its key through,
/// mirroring the owner-only deployment shape the runtime documents.
struct FlipKeySource {
    provider: FieldEncryptionProvider,
    secrets: SecretResolver,
    _root: tempfile::TempDir,
}

fn flip_key_source() -> FlipKeySource {
    let root = tempfile::Builder::new()
        .prefix("registry-flip-dek-")
        .tempdir_in(
            std::env::temp_dir()
                .canonicalize()
                .expect("canonical temporary root"),
        )
        .expect("DEK temporary directory creates");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
        .expect("DEK root is owner-only");
    let dek_path = root.path().join("breg-field-dek");
    fs::write(&dek_path, b"Xl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl5eXl4=\n")
        .expect("DEK file writes");
    fs::set_permissions(&dek_path, fs::Permissions::from_mode(0o600))
        .expect("DEK file is owner-only");
    let dek_ref =
        SecretReference::parse("secret:file/breg-field-dek").expect("DEK reference parses");
    FlipKeySource {
        provider: FieldEncryptionProvider::LocalFile { dek_ref },
        secrets: SecretResolver::new([SecretProvider::File], root.path())
            .expect("DEK resolver builds"),
        _root: root,
    }
}

async fn apply_flip(
    database: &TestDatabase,
    package: &VerifiedPackage,
    current: &ExpectedRegistryIdentity,
    keys: &FlipKeySource,
    fault_after_chunks: Option<u64>,
) -> registry_breg::migration::Result<ExpectedRegistryIdentity> {
    let mut request = request(database, package, ApplyPrecondition::Successor { current })
        .with_field_encryption_key_source(AppliedFieldEncryptionKeySource::new(
            &keys.provider,
            &keys.secrets,
        ));
    if let Some(chunks) = fault_after_chunks {
        request =
            request.with_fault_for_test(ReviewedMigrationFaultPoint::AfterCommittedChunk(chunks));
    }
    apply_verified_package(request).await
}

/// Seeds plaintext rows the flip must seal, each with the journal revision a
/// live registry would already hold for it, so the sealing journals a real
/// pre-boundary binding instead of fabricating one mid-apply.
async fn seed_flip_rows(
    database: &TestDatabase,
    registry: &CompiledRegistry,
    secrets: &[String],
    include_null_secret: bool,
) {
    let entity = &registry.entities()["asset"];
    let table = quote(&entity.physical_table);
    let code = quote(&entity.fields["code"].physical_name);
    let secret = quote(&entity.fields["secret"].physical_name);
    let active_revision: String = database
        .admin
        .query_one(
            "SELECT active_package_revision
             FROM registry_internal.registry_state
             WHERE singleton",
            &[],
        )
        .await
        .expect("active revision reads for flip seed rows")
        .get(0);
    for (index, value) in secrets.iter().enumerate() {
        database
            .admin
            .execute(
                &format!(
                    "INSERT INTO registry_data.{table}
                         (record_id, active_package_revision, {code}, {secret})
                     VALUES ($1, $2, $3, $4)"
                ),
                &[
                    &Uuid::from_u128(index as u128 + 1),
                    &active_revision,
                    &format!("c{index}"),
                    value,
                ],
            )
            .await
            .expect("administrator seeds a flip row");
    }
    if include_null_secret {
        let index = secrets.len();
        database
            .admin
            .execute(
                &format!(
                    "INSERT INTO registry_data.{table}
                         (record_id, active_package_revision, {code}, {secret})
                     VALUES ($1, $2, $3, NULL)"
                ),
                &[
                    &Uuid::from_u128(index as u128 + 1),
                    &active_revision,
                    &format!("c{index}"),
                ],
            )
            .await
            .expect("administrator seeds a null flip row");
    }
    let (mut migration, migration_task) = database.connect_migration().await;
    let transaction = migration
        .transaction()
        .await
        .expect("flip seed journal transaction starts");
    for (index, value) in secrets.iter().enumerate() {
        let record_id = Uuid::from_u128(index as u128 + 1);
        let snapshot = canonical(&serde_json::json!({
            "code": format!("c{index}"),
            "secret": value,
        }));
        transaction
            .execute(
                "INSERT INTO registry_internal.registry_revisions
                     (entity_id, record_id, record_reference, record_revision,
                      predecessor_revision, record_lifecycle, package_revision, operation_id,
                      mutation_kind, principal_reference, request_reference, snapshot)
                 VALUES ('asset', $1, $2, 1, NULL, 'active', $3, 'op-1',
                         'create', 'actor:hash', 'request:hash', $4)",
                &[
                    &record_id,
                    &format!("asset:{record_id}"),
                    &active_revision,
                    &snapshot,
                ],
            )
            .await
            .expect("flip seed revision inserts");
    }
    if include_null_secret {
        let index = secrets.len();
        let record_id = Uuid::from_u128(index as u128 + 1);
        let snapshot = canonical(&serde_json::json!({"code": format!("c{index}")}));
        transaction
            .execute(
                "INSERT INTO registry_internal.registry_revisions
                     (entity_id, record_id, record_reference, record_revision,
                      predecessor_revision, record_lifecycle, package_revision, operation_id,
                      mutation_kind, principal_reference, request_reference, snapshot)
                 VALUES ('asset', $1, $2, 1, NULL, 'active', $3, 'op-1',
                         'create', 'actor:hash', 'request:hash', $4)",
                &[
                    &record_id,
                    &format!("asset:{record_id}"),
                    &active_revision,
                    &snapshot,
                ],
            )
            .await
            .expect("null flip seed revision inserts");
    }
    transaction
        .commit()
        .await
        .expect("flip seed revisions commit");
    migration_task.abort();
}

async fn assert_plaintext_column_present(database: &TestDatabase, prior: &CompiledRegistry) {
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
                &entity.fields["secret"].physical_name,
            ],
        )
        .await
        .expect("plaintext column presence reads");
    assert_eq!(row.get::<_, i64>(0), 1);
}

/// Ciphertext at rest: every row carries a versioned envelope and a 32-byte
/// blind index, blind indexes stay pairwise distinct, and the plaintext column
/// is gone.
async fn assert_flip_sealed_at_rest(
    database: &TestDatabase,
    prior: &CompiledRegistry,
    candidate: &CompiledRegistry,
    expected_null_rows: usize,
) {
    let entity = &candidate.entities()["asset"];
    let table = quote(&entity.physical_table);
    let envelope = quote(&entity.fields["secret"].physical_name);
    let blind = quote(
        &entity.fields["secret"]
            .encryption
            .as_ref()
            .and_then(|encryption| encryption.blind_index.as_ref())
            .expect("the candidate declares a blind index")
            .physical_name,
    );
    let rows = database
        .admin
        .query(
            &format!("SELECT {envelope}, {blind} FROM registry_data.{table} ORDER BY record_id"),
            &[],
        )
        .await
        .expect("sealed rows read");
    assert!(!rows.is_empty());
    let mut blind_indexes = BTreeSet::new();
    let mut null_rows = 0;
    for row in &rows {
        let envelope: Option<Vec<u8>> = row.get(0);
        let blind: Option<Vec<u8>> = row.get(1);
        let (envelope, blind) = match (envelope, blind) {
            (Some(envelope), Some(blind)) => (envelope, blind),
            (None, None) => {
                null_rows += 1;
                continue;
            }
            _ => panic!("an absent envelope cannot retain a blind index"),
        };
        assert_eq!(
            envelope.first(),
            Some(&1),
            "the envelope carries its version byte"
        );
        let key_version = u32::from_be_bytes(
            envelope[1..5]
                .try_into()
                .expect("the envelope header carries the key version"),
        );
        assert_eq!(key_version, 1);
        assert_eq!(
            blind.len(),
            32,
            "the blind index is one HMAC-SHA-256 output"
        );
        assert!(
            blind_indexes.insert(blind),
            "distinct plaintexts keep distinct blind indexes"
        );
    }
    assert_eq!(
        null_rows, expected_null_rows,
        "a null plaintext remains an absent envelope and blind index"
    );
    let prior_entity = &prior.entities()["asset"];
    let dropped = database
        .admin
        .query_one(
            "SELECT count(*)
             FROM information_schema.columns
             WHERE table_schema = 'registry_data'
               AND table_name = $1
               AND column_name = $2",
            &[
                &prior_entity.physical_table,
                &prior_entity.fields["secret"].physical_name,
            ],
        )
        .await
        .expect("plaintext column absence reads");
    assert_eq!(dropped.get::<_, i64>(0), 0);
}

/// The boundary journal holds exactly one sealed revision per record, every
/// one of them a tagged envelope member rather than plaintext.
async fn assert_flip_journal(database: &TestDatabase, target: &ExpectedRegistryIdentity) {
    let row = database
        .admin
        .query_one(
            "SELECT count(DISTINCT record_id)::bigint,
                    count(*)::bigint,
                    count(*) FILTER (
                        WHERE convert_from(snapshot, 'UTF8')::jsonb
                                  -> 'secret' ->> $2 IS NOT NULL
                    )::bigint
             FROM registry_internal.registry_revisions
             WHERE entity_id = 'asset'
               AND package_revision = $1
               AND convert_from(snapshot, 'UTF8')::jsonb ? 'secret'",
            &[&target.package_revision, &ENVELOPE_MEMBER_TAG],
        )
        .await
        .expect("flip journal reads");
    assert_eq!(row.get::<_, i64>(0), 5, "every sealed record is journalled");
    assert_eq!(
        row.get::<_, i64>(1),
        5,
        "no record is journalled twice across the resume"
    );
    assert_eq!(
        row.get::<_, i64>(2),
        5,
        "every boundary journal member is a tagged envelope"
    );
}

async fn assert_flip_boundary_row(
    database: &TestDatabase,
    target: &ExpectedRegistryIdentity,
    history_choice: &str,
    sealed_rows: i64,
    sealed_journal_rows: i64,
    accepted_plaintext_journal_rows: i64,
) {
    let row = database
        .admin
        .query_one(
            "SELECT boundary_package_revision, history_choice, sealed_row_count,
                    sealed_journal_row_count, accepted_plaintext_journal_row_count,
                    history_commit_position
             FROM registry_internal.registry_field_encryption_flips
             WHERE entity_id = 'asset' AND field_id = 'secret'",
            &[],
        )
        .await
        .expect("the flip boundary row exists");
    assert_eq!(row.get::<_, String>(0), target.package_revision);
    assert_eq!(row.get::<_, String>(1), history_choice);
    assert_eq!(row.get::<_, i64>(2), sealed_rows);
    assert_eq!(row.get::<_, i64>(3), sealed_journal_rows);
    assert_eq!(row.get::<_, i64>(4), accepted_plaintext_journal_rows);
    assert!(
        row.get::<_, i64>(5) > 0,
        "the flip records a positive exclusive history cutoff"
    );
}

async fn assert_flip_boundary_absent(database: &TestDatabase) {
    let row = database
        .admin
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_field_encryption_flips",
            &[],
        )
        .await
        .expect("flip boundary absence reads");
    assert_eq!(row.get::<_, i64>(0), 0);
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
        history: None,
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
                        | ReviewedMigrationStepDescriptor::FieldEncryptionBackfill { .. }
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
    for statement in
        candidate.ddl().statements.iter().filter(|statement| {
            statement.kind == registry_breg::generated_ddl::DdlStatementKind::View
        })
    {
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
    runtime_role: &registry_breg::postgres::SqlIdentifier,
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
) -> registry_breg::migration::Result<ExpectedRegistryIdentity> {
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
) -> registry_breg::migration::Result<ExpectedRegistryIdentity> {
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

async fn reconcile(
    database: &TestDatabase,
    package: &VerifiedPackage,
    current: &ExpectedRegistryIdentity,
    current_registry: &CompiledRegistry,
    execute: bool,
) -> Result<ReconcileReport, ReconcileError> {
    let audit_profile = AuditProfile::production_from_secret_bytes(vec![0x63; 32].into())
        .expect("test owns a keyed audit profile");
    reconcile_failed_migration(ReconcileRequest {
        config: &database.migration_config,
        target_package: package,
        current,
        current_registry,
        migration_role: &database.migration_role,
        runtime_role: &database.runtime_role,
        timeouts: ReconcileTimeouts::new(Duration::from_secs(1), Duration::from_secs(5))
            .expect("test timeouts are bounded"),
        audit_profile: &audit_profile,
        operator_reference: RECONCILE_OPERATOR_CANARY,
        execute,
    })
    .await
}

fn target_identity(package: &VerifiedPackage) -> ExpectedRegistryIdentity {
    let manifest = package.manifest();
    ExpectedRegistryIdentity {
        package_id: manifest.package_id.clone(),
        environment: manifest.environment.clone(),
        instance_id: manifest.instance_id.clone(),
        database_id: manifest.database_id.clone(),
        package_revision: manifest.package_revision.clone(),
        schema_fingerprint: manifest.schema_fingerprint.clone(),
        package_sequence: i64::try_from(manifest.sequence).expect("test sequence is bounded"),
    }
}

/// The whole durable maintenance record an assessment must leave untouched:
/// the state row, every ledger row and step, and the audit journal.
async fn durable_snapshot(
    database: &TestDatabase,
) -> (
    Vec<(String, String, String)>,
    Vec<(String, Option<Uuid>, i64)>,
    Vec<Vec<u8>>,
    (String, String, Option<String>),
) {
    let steps = database
        .admin
        .query(
            "SELECT outcome, checkpoint_record_id, affected_rows
             FROM registry_internal.registry_migration_steps
             ORDER BY target_package_revision, step_ordinal",
            &[],
        )
        .await
        .expect("step states read")
        .into_iter()
        .map(|row| (row.get(0), row.get(1), row.get(2)))
        .collect();
    let audit = database
        .admin
        .query(
            "SELECT record_hash FROM registry_internal.registry_audit ORDER BY record_hash",
            &[],
        )
        .await
        .expect("audit journal reads")
        .into_iter()
        .map(|row| row.get(0))
        .collect();
    let state = database
        .admin
        .query_one(
            "SELECT active_package_revision, maintenance_status, maintenance_target_revision
             FROM registry_internal.registry_state WHERE singleton",
            &[],
        )
        .await
        .expect("maintenance state reads");
    (
        ledger_snapshot(database).await,
        steps,
        audit,
        (state.get(0), state.get(1), state.get(2)),
    )
}

/// The reconciliation audit record carries identities, the plan shape, and
/// counts. The operator's own reference must reach it only as a keyed hash.
async fn assert_reconcile_audit_is_minimized(database: &TestDatabase, action: &str) {
    let envelopes = database
        .admin
        .query("SELECT envelope FROM registry_internal.registry_audit", &[])
        .await
        .expect("audit journal reads");
    let mut matched = 0;
    for row in &envelopes {
        let bytes: Vec<u8> = row.get(0);
        let text = String::from_utf8(bytes).expect("audit envelopes are UTF-8");
        assert!(!text.contains(RECONCILE_OPERATOR_CANARY));
        if text.contains("breg-migration-reconcile-audit/v1") {
            assert!(text.contains(&format!("\"action\":\"{action}\"")));
            matched += 1;
        }
    }
    assert_eq!(matched, 1);
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_patterns_validate_empty_tables_existing_rows_and_exact_target_recovery() {
    use registry_breg::generated_ddl::field_pattern_constraint_name;
    let database = TestDatabase::create(1).await;
    let base = compile_variant(Variant::Base, 1);
    let added = compile_variant(Variant::PatternAdded, 2);
    let tightened = compile_variant(Variant::PatternTightened, 3);
    let loosened = compile_variant(Variant::PatternLoosened, 4);
    let removed = compile_variant(Variant::Base, 5);
    let base_fp = initial_fingerprint(&database, &base).await;
    let added_fp = initial_fingerprint(&database, &added).await;
    let tightened_fp = initial_fingerprint(&database, &tightened).await;
    let loosened_fp = initial_fingerprint(&database, &loosened).await;
    let removed_fp = initial_fingerprint(&database, &removed).await;
    assert_ne!(base_fp, added_fp);
    assert_ne!(added_fp, tightened_fp);
    assert_eq!(base_fp, removed_fp);

    // This is the installer used by pre-sign schema-test. A native syntax error
    // must fail before any fixture value exists to exercise its CHECK.
    let invalid = compile_variant(Variant::PatternInvalid, 1);
    let (mut migration, task) = database.connect_migration().await;
    let transaction = migration.transaction().await.unwrap();
    let error = install_compiled_schema(&transaction, &invalid, &database.runtime_role).await;
    assert!(
        matches!(error, Err(registry_breg::postgres::PostgresKernelError::FieldPatternSyntax { entity_id, field_id }) if entity_id == "asset" && field_id == "legacy"),
        "invalid ARE syntax is addressed even with empty tables"
    );
    transaction.rollback().await.unwrap();
    task.abort();

    let initial = prepare_and_load_initial(&base, &base_fp);
    let active = apply(&database, &initial, ApplyPrecondition::InitialActivation)
        .await
        .unwrap();
    let table = quote(&base.entities()["asset"].physical_table);
    let field = quote(&base.entities()["asset"].fields["legacy"].physical_name);
    database
        .admin
        .execute(
            &format!("INSERT INTO registry_data.{table} (record_id, {field}, active_package_revision) VALUES ($1, $2, $3)"),
            &[&Uuid::from_u128(91), &"invalid", &active.package_revision],
        )
        .await
        .unwrap();
    let prepared = prepare_package(build_request(
        Variant::PatternAdded,
        2,
        Some(&active.package_revision),
        &added_fp,
        PackageMigrationPlanInput::Successor {
            prior_registry: Box::new(base.clone()),
        },
        DATABASE,
    ))
    .unwrap();
    let addition = publish_and_load(
        prepared,
        local_context(
            DATABASE,
            PackageIntent::Activation {
                active_revision: &active.package_revision,
                active_sequence: 1,
            },
        ),
    );
    assert_value_free(
        apply(
            &database,
            &addition,
            ApplyPrecondition::Successor { current: &active },
        )
        .await
        .err(),
        MigrationError::FieldPatternExistingRows {
            entity_id: "asset".to_owned(),
            field_id: "legacy".to_owned(),
        },
    );
    assert_non_ready_target(&database, &active, &addition, "failed").await;
    database
        .admin
        .execute(
            &format!("UPDATE registry_data.{table} SET {field} = $1"),
            &[&"12"],
        )
        .await
        .unwrap();
    let mut active = apply(
        &database,
        &addition,
        ApplyPrecondition::Successor { current: &active },
    )
    .await
    .expect("corrected existing data admits exact pinned successor");
    assert_ready_target(&database, &active).await;

    // Changed/removal constraints remain reviewed operations under the existing
    // evolution contract, with exact object coverage and backup binding.
    let mut prior = added;
    for (sequence, variant, candidate, target_fp) in [
        (3, Variant::PatternTightened, tightened, tightened_fp),
        (4, Variant::PatternLoosened, loosened, loosened_fp),
        (5, Variant::Base, removed, removed_fp),
    ] {
        let id = format!("pattern-{sequence}");
        let backup_bytes = format!(
            "-- Synthetic pattern migration recovery evidence for {}\n",
            active.package_revision
        )
        .into_bytes();
        let backup = ExternalBackupBinding {
            database_id: DATABASE.to_owned(),
            prior_revision: active.package_revision.clone(),
            prior_schema_fingerprint: active.schema_fingerprint.clone(),
            sha256: digest(&backup_bytes),
            byte_length: backup_bytes.len() as u64,
            created_at: OffsetDateTime::now_utc().format(&Rfc3339).unwrap(),
            max_age_seconds: 3600,
        };
        let source = pattern_reviewed_source(&id, &active, &prior, &candidate, &target_fp, backup);
        let package =
            prepare_and_load_reviewed(sequence, &active, &prior, variant, &target_fp, source);
        let directory = tempfile::tempdir().unwrap();
        let backup_path = directory.path().join("pattern.backup");
        fs::write(&backup_path, backup_bytes).unwrap();
        fs::set_permissions(&backup_path, fs::Permissions::from_mode(0o600)).unwrap();
        let binding = package.reviewed_migration_plan().unwrap().migrations()[0]
            .descriptor
            .backup_binding_path
            .as_deref()
            .unwrap();
        let evidence = [DestructiveBackupEvidence::new(binding, &backup_path)];
        if sequence == 3 {
            assert_value_free(
                apply_with_evidence(&database, &package, &active, &evidence)
                    .await
                    .err(),
                MigrationError::FieldPatternExistingRows {
                    entity_id: "asset".to_owned(),
                    field_id: "legacy".to_owned(),
                },
            );
            assert_non_ready_target(&database, &active, &package, "failed").await;
            database
                .admin
                .execute(
                    &format!("UPDATE registry_data.{table} SET {field} = $1"),
                    &[&"0123456789012"],
                )
                .await
                .unwrap();
        }
        active = apply_with_evidence(&database, &package, &active, &evidence)
            .await
            .expect("reviewed native pattern transition activates validated catalog");
        assert_ready_target(&database, &active).await;
        assert_eq!(active.schema_fingerprint, target_fp);
        let names: Vec<String> = database.admin.query("SELECT conname FROM pg_catalog.pg_constraint WHERE conrelid = $1::text::regclass AND conname LIKE 'breg_pattern_%'", &[&format!("registry_data.{table}")]).await.unwrap().iter().map(|row| row.get(0)).collect();
        if sequence == 5 {
            assert!(names.is_empty(), "removal leaves no orphan check");
        } else {
            assert_eq!(names, [field_pattern_constraint_name("asset", "legacy")]);
        }
        if sequence == 3 {
            for invalid in [
                "012345678901",
                "01234567890123",
                "٠١٢٣٤٥٦٧٨٩٠١٢",
                " 123456789012",
                "0123456789012\n",
                "012345\n789012",
                "",
            ] {
                let error = database
                    .admin
                    .execute(
                        &format!("UPDATE registry_data.{table} SET {field} = $1"),
                        &[&invalid],
                    )
                    .await
                    .unwrap_err();
                assert_eq!(
                    error.code(),
                    Some(&tokio_postgres::error::SqlState::CHECK_VIOLATION)
                );
                assert_eq!(
                    error.as_db_error().unwrap().constraint(),
                    Some(field_pattern_constraint_name("asset", "legacy").as_str())
                );
            }
            let stored: String = database
                .admin
                .query_one(&format!("SELECT {field} FROM registry_data.{table}"), &[])
                .await
                .unwrap()
                .get(0);
            assert_eq!(
                stored, "0123456789012",
                "native text integrity preserves the leading zero"
            );
            database
                .admin
                .execute(
                    &format!("UPDATE registry_data.{table} SET {field} = NULL"),
                    &[],
                )
                .await
                .unwrap();
            database
                .admin
                .execute(
                    &format!("UPDATE registry_data.{table} SET {field} = $1"),
                    &[&"0123456789012"],
                )
                .await
                .unwrap();
        } else if sequence == 4 {
            database
                .admin
                .execute(
                    &format!("UPDATE registry_data.{table} SET {field} = $1"),
                    &[&"prefix1suffix"],
                )
                .await
                .expect("native regex remains unanchored when authored unanchored");
        } else {
            database
                .admin
                .execute(
                    &format!("UPDATE registry_data.{table} SET {field} = $1"),
                    &[&"arbitrary"],
                )
                .await
                .expect("removed pattern no longer enforces its old rule");
        }
        prior = candidate;
    }
    database.cleanup().await;
}

fn pattern_reviewed_source(
    id: &str,
    current: &ExpectedRegistryIdentity,
    prior: &CompiledRegistry,
    candidate: &CompiledRegistry,
    final_fingerprint: &str,
    backup: ExternalBackupBinding,
) -> ReviewedMigrationSource {
    use registry_breg::generated_ddl::field_pattern_constraint_name;
    let change = compiled_registry_change_set(prior, candidate, &current.package_revision)
        .changes
        .into_iter()
        .find(|change| {
            matches!(
                change.code,
                CompiledRegistryChangeCode::FieldPatternChanged
                    | CompiledRegistryChangeCode::FieldPatternRemoved
            )
        })
        .unwrap();
    let entity = &prior.entities()["asset"];
    let name = field_pattern_constraint_name("asset", "legacy");
    let base = format!("modules/core/migrations/{id}");
    let step_path = format!("{base}/steps/pattern.sql");
    let pre_path = format!("{base}/assertions/pre.sql");
    let post_path = format!("{base}/assertions/post.sql");
    let mut sql = format!(
        "ALTER TABLE registry_data.{} DROP CONSTRAINT {}",
        entity.physical_table, name
    );
    if let Some(statement) = candidate
        .ddl()
        .statements
        .iter()
        .find(|s| s.id == "entity.asset.field.legacy.pattern")
    {
        // Expression syntax was independently validated by the candidate installer.
        // Reviewed SQL owns only the managed constraint replacement.
        sql.push_str(", ");
        sql.push_str(
            statement
                .sql
                .split_once(" ADD CONSTRAINT ")
                .map(|(_, body)| format!("ADD CONSTRAINT {body}"))
                .unwrap()
                .as_str(),
        );
    }
    let assertion = format!(
        "SELECT pg_catalog.count(*) >= 0 FROM registry_data.{}",
        entity.physical_table
    );
    let descriptor = ReviewedMigrationDescriptor {
        id: id.to_owned(),
        change_class: CompiledRegistryChangeClass::DestructiveOrIrreversible,
        covers: vec![ReviewedChangeCover::from(&change)],
        recovery: ReviewedMigrationRecovery::ExactTargetResume,
        lock_timeout_ms: 1000,
        statement_timeout_ms: 5000,
        steps: vec![ReviewedMigrationStepDescriptor::TransactionalSql {
            id: "pattern".to_owned(),
            sql_path: step_path.clone(),
            objects: vec![ReviewedMigrationObject {
                schema: "registry_data".to_owned(),
                table: entity.physical_table.clone(),
                entity_id: "asset".to_owned(),
                kind: ReviewedMigrationObjectKind::Constraint,
                member_id: Some("pattern:legacy".to_owned()),
                physical_name: name,
            }],
            affected_rows: None,
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
        backup_binding_path: Some(format!("{base}/backup.json")),
        history: None,
    };
    reviewed_source(ReviewedSourceRequest {
        descriptor,
        current,
        final_fingerprint,
        steps: vec![(step_path, sql)],
        pre: (pre_path, assertion.clone()),
        post: (post_path, assertion),
        backup: Some(backup),
        row_assertions: Vec::new(),
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_patterns_quote_apostrophes_and_backslashes_independent_of_session_settings() {
    let database = TestDatabase::create(1).await;
    let registry = compile_variant(Variant::PatternQuoted, 1);
    let (mut migration, task) = database.connect_migration().await;
    let transaction = migration.transaction().await.unwrap();
    transaction
        .batch_execute("SET LOCAL standard_conforming_strings = off")
        .await
        .unwrap();
    install_compiled_schema(&transaction, &registry, &database.runtime_role)
        .await
        .expect("generated native expression is safely quoted");
    transaction.commit().await.unwrap();
    task.abort();
    let entity = &registry.entities()["asset"];
    let table = quote(&entity.physical_table);
    let field = quote(&entity.fields["legacy"].physical_name);
    let accepted = r"a'\b";
    database.admin.execute(&format!("INSERT INTO registry_data.{table} (record_id, {field}, active_package_revision) VALUES ($1, $2, 'synthetic-package')"), &[&Uuid::from_u128(92), &accepted]).await.expect("quoted pattern keeps literal apostrophe and backslash semantics");
    let actual: String = database
        .admin
        .query_one(&format!("SELECT {field} FROM registry_data.{table}"), &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(actual, accepted);
    let rejected = database
        .admin
        .execute(
            &format!("UPDATE registry_data.{table} SET {field} = $1"),
            &[&"a'b"],
        )
        .await
        .unwrap_err();
    assert_eq!(
        rejected.code(),
        Some(&tokio_postgres::error::SqlState::CHECK_VIOLATION)
    );
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_patterns_invalid_initial_activation_fails_closed_in_maintenance() {
    let database = TestDatabase::create(1).await;
    let base = compile_variant(Variant::Base, 1);
    let fingerprint = initial_fingerprint(&database, &base).await;
    // The local unsigned test policy permits exercising the activation defense
    // independently of the production pre-sign schema-test refusal.
    let prepared = prepare_package(build_request(
        Variant::PatternInvalid,
        1,
        None,
        &fingerprint,
        PackageMigrationPlanInput::InitialCompiledDdl,
        DATABASE,
    ))
    .unwrap();
    let invalid = publish_and_load(
        prepared,
        local_context(DATABASE, PackageIntent::InitialActivation),
    );
    assert_value_free(
        apply(&database, &invalid, ApplyPrecondition::InitialActivation)
            .await
            .err(),
        MigrationError::FieldPatternSyntax {
            entity_id: "asset".to_owned(),
            field_id: "legacy".to_owned(),
        },
    );
    let row = database.admin.query_one("SELECT maintenance_status, maintenance_target_revision FROM registry_internal.registry_state WHERE singleton", &[]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "failed");
    assert_eq!(
        row.get::<_, Option<String>>(1).as_deref(),
        Some(invalid.manifest().package_revision.as_str())
    );
    let tables: i64 = database
        .admin
        .query_one(
            "SELECT count(*) FROM pg_catalog.pg_tables WHERE schemaname = 'registry_data'",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        tables, 0,
        "invalid constraint activation commits no current-row schema"
    );
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_patterns_invalid_successors_report_the_field_for_additive_and_reviewed_paths() {
    for reviewed in [false, true] {
        let database = TestDatabase::create(1).await;
        let variant = if reviewed {
            Variant::PatternAdded
        } else {
            Variant::Base
        };
        let prior = compile_variant(variant, 1);
        let fingerprint = initial_fingerprint(&database, &prior).await;
        let prepared = prepare_package(build_request(
            variant,
            1,
            None,
            &fingerprint,
            PackageMigrationPlanInput::InitialCompiledDdl,
            DATABASE,
        ))
        .unwrap();
        let initial = publish_and_load(
            prepared,
            local_context(DATABASE, PackageIntent::InitialActivation),
        );
        let active = apply(&database, &initial, ApplyPrecondition::InitialActivation)
            .await
            .unwrap();
        let invalid = compile_variant(Variant::PatternInvalid, 2);
        // An unsigned test package supplies a synthetic fingerprint to reach
        // activation independently of the pre-sign native syntax refusal.
        let target_fingerprint = format!("sha256:{}", "f".repeat(64));
        let (package, error) = if reviewed {
            let bytes = b"-- Synthetic pre-activation pattern backup\n";
            let backup = ExternalBackupBinding {
                database_id: DATABASE.to_owned(),
                prior_revision: active.package_revision.clone(),
                prior_schema_fingerprint: active.schema_fingerprint.clone(),
                sha256: digest(bytes),
                byte_length: bytes.len() as u64,
                created_at: OffsetDateTime::now_utc().format(&Rfc3339).unwrap(),
                max_age_seconds: 3600,
            };
            let source = pattern_reviewed_source(
                "invalid-pattern",
                &active,
                &prior,
                &invalid,
                &target_fingerprint,
                backup,
            );
            let package = prepare_and_load_reviewed(
                2,
                &active,
                &prior,
                Variant::PatternInvalid,
                &target_fingerprint,
                source,
            );
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("pattern.backup");
            fs::write(&path, bytes).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            let binding = package.reviewed_migration_plan().unwrap().migrations()[0]
                .descriptor
                .backup_binding_path
                .as_deref()
                .unwrap();
            let error = apply_with_evidence(
                &database,
                &package,
                &active,
                &[DestructiveBackupEvidence::new(binding, &path)],
            )
            .await
            .err();
            (package, error)
        } else {
            let prepared = prepare_package(build_request(
                Variant::PatternInvalid,
                2,
                Some(&active.package_revision),
                &target_fingerprint,
                PackageMigrationPlanInput::Successor {
                    prior_registry: Box::new(prior.clone()),
                },
                DATABASE,
            ))
            .unwrap();
            let package = publish_and_load(
                prepared,
                local_context(
                    DATABASE,
                    PackageIntent::Activation {
                        active_revision: &active.package_revision,
                        active_sequence: 1,
                    },
                ),
            );
            let error = apply(
                &database,
                &package,
                ApplyPrecondition::Successor { current: &active },
            )
            .await
            .err();
            (package, error)
        };
        assert_value_free(
            error,
            MigrationError::FieldPatternSyntax {
                entity_id: "asset".to_owned(),
                field_id: "legacy".to_owned(),
            },
        );
        assert_non_ready_target(&database, &active, &package, "failed").await;
        let (migration, task) = database.connect_migration().await;
        assert_eq!(
            managed_schema_fingerprint(
                &migration,
                &database.runtime_role,
                &ExpectedManagedCatalog::compiled(&prior)
            )
            .await
            .unwrap(),
            fingerprint,
            "syntax refusal preserves the pre-activation catalog on an empty table"
        );
        task.abort();
        database.cleanup().await;
    }
}
