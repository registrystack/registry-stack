// SPDX-License-Identifier: Apache-2.0

#![cfg(all(feature = "postgres-test", feature = "tooling", unix))]

#[path = "support/postgres_harness.rs"]
mod postgres_harness;
#[path = "support/source_bytes.rs"]
mod source_bytes;

use std::{collections::BTreeSet, fs, os::unix::fs::PermissionsExt as _, time::Duration};

use postgres_harness::TestDatabase;
use registry_breg::compiler::{
    compile_project, compile_project_with_assets, module_digest, CompileProfile,
};
use registry_breg::contract::{
    parse_module_yaml, parse_project_yaml, ModuleAssetSource, RegistryProject,
};
use registry_breg::field_encryption::FieldEncryptionProvider;
use registry_breg::field_encryption_backfill::{
    preflight_field_encryption_backfill, FieldEncryptionBackfillPreflightRequest,
    FieldEncryptionBackfillTimeouts,
};
use registry_breg::migration::{
    apply_verified_package, bind_active_package, plan_verified_package, read_activation_status,
    read_recorded_registry_state, successor_plan_is_empty, successor_plan_is_empty_for_predecessor,
    ActivationDeployment, ActivationPlan, AppliedFieldEncryptionKeySource, ApplyPrecondition,
    ApplyRoles, ApplyTimeouts, ApplyVerifiedPackageRequest, DestructiveBackupEvidence,
    MigrationError, PlannedActivation, RecordedRegistryState, ReviewedMigrationFaultPoint,
};
use registry_breg::migration_plan::{
    ArtifactDigestBinding, ChunkCursorProtocol, ExternalBackupBinding, MigrationRehearsalReceipt,
    RehearsalFixture, RehearsalRowAssertion, ReviewedChangeCover, ReviewedFieldEncryptionHistory,
    ReviewedMigrationAssertionDescriptor, ReviewedMigrationDescriptor, ReviewedMigrationFile,
    ReviewedMigrationObject, ReviewedMigrationObjectKind, ReviewedMigrationRecovery,
    ReviewedMigrationSource, ReviewedMigrationStepDescriptor,
};
use registry_breg::migration_reconcile::{
    reconcile_failed_migration, ReconcileAudit, ReconcileError, ReconcileOutcome, ReconcileReport,
    ReconcileRequest, ReconcileTimeouts, UNRESOLVABLE_CATALOG_UNMATCHED,
};
use registry_breg::package::{
    compiled_registry_change_set, compiled_registry_change_set_from_baseline, load_package,
    load_predecessor_package, prepare_package, prepare_package_with_project_assets,
    CompiledRegistryChangeClass, CompiledRegistryChangeCode, CompiledRegistryMigrationBaseline,
    PackageBuildRequest, PackageEngineFeature, PackageLoadContext, PackageMigrationPlanInput,
    PackageModuleSource, PackageSourceFile, PreparedPackage, VerifiedPackage,
    VerifiedPredecessorPackage,
};
use registry_breg::postgres::{
    install_compiled_schema, managed_schema_fingerprint, rehearse_successor_migration,
    verify_catalog_identity_for_catalog, ExpectedManagedCatalog, ExpectedRegistryIdentity,
    MigrationRehearsalError, PostgresFailure, RehearsalAssertionPhase, RehearsalOutcome,
    SuccessorMigrationRehearsal,
};
use registry_breg::CompiledRegistry;
use registry_platform_audit::AuditProfile;
use registry_platform_canonical_json::canonicalize_json;
use registry_platform_config::package::{write_sum_file, PackageLimits, SUM_FILE};
use registry_platform_config::{SecretProvider, SecretReference, SecretResolver};
use registry_platform_crypto::field_encryption::ENVELOPE_MEMBER_TAG;
use serde::Serialize;
use sha2::{Digest, Sha256};
use time::{format_description::well_known::Rfc3339, OffsetDateTime};
use uuid::Uuid;

const ENVIRONMENT: &str = "local";
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

/// An existing activation gains the product-owned access-log storage through
/// normal successor apply. Later disabling collection retains its rows and the
/// bounded expiry authority instead of treating the log as disposable schema.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn subject_access_log_upgrades_an_existing_catalog_and_survives_disabled_collection() {
    let database = TestDatabase::create(1).await;
    let (prior, fingerprint, active, _old_package) =
        activate_before_subject_access_log(&database).await;

    let enabled = compile_variant(Variant::SubjectWithLog);
    // The log policy changes the package contract, not its entity DDL; the
    // fresh catalog fingerprint includes the new product-owned log objects.
    let target_fingerprint = fingerprint;
    let successor = publish_and_load(
        prepare_package(build_request(
            Variant::SubjectWithLog,
            Some(&active.package_digest),
            &target_fingerprint,
            PackageMigrationPlanInput::Successor {
                prior_registry: Box::new(prior.clone()),
            },
        ))
        .unwrap(),
        local_context(),
    );
    let enabled_active = apply(
        &database,
        &successor,
        ApplyPrecondition::Successor { current: &active },
    )
    .await
    .unwrap();
    database.admin.execute("INSERT INTO registry_internal.registry_subject_access_log
        (event_id,entity_id,record_id,requester,operation_id,authority_entity,access_profile,package_revision,request_id,visible_after,expires_at)
        VALUES ($1,'asset',$2,'requesting-service','records.asset.get','asset','reader',$3,$4,transaction_timestamp(),transaction_timestamp()+interval '1 day')",
        &[&Uuid::new_v4(),&Uuid::new_v4(),&enabled_active.activation_id,&Uuid::new_v4()]).await.unwrap();

    let disabled = publish_and_load(
        prepare_package(build_request(
            Variant::SubjectWithoutLog,
            Some(&enabled_active.package_digest),
            &target_fingerprint,
            PackageMigrationPlanInput::Successor {
                prior_registry: Box::new(enabled),
            },
        ))
        .unwrap(),
        local_context(),
    );
    let disabled_active = apply(
        &database,
        &disabled,
        ApplyPrecondition::Successor {
            current: &enabled_active,
        },
    )
    .await
    .unwrap();
    assert_ready_target(&database, &disabled_active).await;
    let pool = database.runtime_config.build_pool().unwrap();
    let runtime = pool.get_for_test().await.unwrap();
    let retained: i64 = runtime
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_subject_access_log",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert_eq!(retained, 1);
    let removed: i64 = runtime
        .query_one("SELECT registry_internal.expire_subject_access_log()", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        removed, 0,
        "disabling collection never erases unexpired entries"
    );
    database.admin.batch_execute("UPDATE registry_internal.registry_subject_access_log SET accessed_at=accessed_at-interval '2 days',visible_after=visible_after-interval '2 days',expires_at=expires_at-interval '2 days'").await.unwrap();
    let removed: i64 = runtime
        .query_one("SELECT registry_internal.expire_subject_access_log()", &[])
        .await
        .unwrap()
        .get(0);
    assert_eq!(
        removed, 1,
        "the runtime retains only expired-entry erasure authority"
    );
    drop(runtime);
    drop(pool);
    database.cleanup().await;
}

/// A database an earlier release activated holds no subject access-log
/// storage until its next apply installs it. Until then the upgraded runtime
/// and operator tooling verify its active package as it stands, and applying
/// that package again is refused as already active rather than activated.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_catalog_from_before_the_subject_access_log_keeps_its_active_package_until_the_next_apply(
) {
    let database = TestDatabase::create(1).await;
    let (prior, _fingerprint, active, old_package) =
        activate_before_subject_access_log(&database).await;

    let pool = database.runtime_config.build_pool().unwrap();
    let runtime = pool.get_for_test().await.unwrap();
    verify_catalog_identity_for_catalog(
        &**runtime,
        &active,
        &ExpectedManagedCatalog::compiled(&prior),
        &database.migration_role,
        &database.runtime_role,
    )
    .await
    .expect("the upgraded catalog check accepts the storage-free catalog it inherits");
    // A registry that collects the log is never served without its storage.
    verify_catalog_identity_for_catalog(
        &**runtime,
        &active,
        &ExpectedManagedCatalog::compiled(&compile_variant(Variant::SubjectWithLog)),
        &database.migration_role,
        &database.runtime_role,
    )
    .await
    .expect_err("a collecting registry requires the access-log storage");
    drop(runtime);
    drop(pool);

    assert_value_free(
        apply(
            &database,
            &old_package,
            ApplyPrecondition::RoleChange { current: &active },
        )
        .await
        .err(),
        MigrationError::AlreadyActive,
    );
    assert_ready_target(&database, &active).await;
    let installed: bool = database
        .admin
        .query_one(
            "SELECT pg_catalog.to_regclass('registry_internal.registry_subject_access_log') IS NOT NULL",
            &[],
        )
        .await
        .unwrap()
        .get(0);
    assert!(!installed, "only a new activation installs the storage");
    database.cleanup().await;
}

/// Activate the storage-free variant, then reproduce the exact catalog and
/// recorded package binding a release before subject access-log storage
/// left behind. This fixture surgery stands in for the older binary; every
/// later step uses the maintained APIs. Returns the compiled registry, the
/// fingerprint of a fresh catalog, the active identity, and the active
/// package.
async fn activate_before_subject_access_log(
    database: &TestDatabase,
) -> (
    CompiledRegistry,
    String,
    ExpectedRegistryIdentity,
    VerifiedPackage,
) {
    database
        .admin
        .batch_execute("CREATE EXTENSION btree_gist")
        .await
        .unwrap();
    let prior = compile_variant(Variant::SubjectWithoutLog);
    let fingerprint = initial_fingerprint(database, &prior).await;
    let initial =
        prepare_and_load_initial_variant(Variant::SubjectWithoutLog, &prior, &fingerprint);
    let mut active = apply(database, &initial, ApplyPrecondition::InitialActivation)
        .await
        .unwrap();

    let (migration, task) = database.connect_migration().await;
    migration.batch_execute("DROP FUNCTION registry_internal.expire_subject_access_log(); DROP TABLE registry_internal.registry_subject_access_log;").await.unwrap();
    let old_fingerprint = managed_schema_fingerprint(
        &migration,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(&prior).without_subject_access_log_for_test(),
    )
    .await
    .unwrap();
    let old_package =
        prepare_and_load_initial_variant(Variant::SubjectWithoutLog, &prior, &old_fingerprint);
    active.schema_fingerprint = old_fingerprint;
    active.package_digest = old_package.package_digest().to_owned();
    migration.execute("UPDATE registry_internal.registry_state SET active_package_digest=$1, schema_fingerprint=$2 WHERE singleton", &[&active.package_digest,&active.schema_fingerprint]).await.unwrap();
    migration.execute("UPDATE registry_internal.registry_migrations SET package_digest=$1 WHERE activation_id=$2::text::uuid", &[&active.package_digest,&active.activation_id]).await.unwrap();
    drop(migration);
    task.abort();
    (prior, fingerprint, active, old_package)
}

/// An active package written before the statistics release store existed must
/// remain recoverable after a successor enters failed maintenance. The current
/// binary compares the active catalog with the capability declared by the
/// committed predecessor package, releases the failed target, and can then
/// apply a corrected successor that installs the store.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pre_statistics_active_package_recovers_a_failed_successor_and_applies_the_next_one() {
    let database = TestDatabase::create(1).await;
    database
        .admin
        .batch_execute("CREATE EXTENSION btree_gist")
        .await
        .expect("administrator installs the required extension");

    let predecessor = load_person_pre_statistics_package();
    assert!(!predecessor.statistical_release_store_present());
    let assets = person_registration_assets();
    let prior_project = person_registration_project(false);
    let candidate_project = person_registration_project(true);
    let prior = compile_person_registration(&prior_project, &assets);
    let candidate = compile_person_registration(&candidate_project, &assets);
    assert_eq!(predecessor.package_id(), prior.registry_id());

    // Both target fingerprints are measured before activation, while this
    // isolated database still has no managed objects.
    let prior_fingerprint = initial_fingerprint(&database, &prior).await;
    let candidate_fingerprint = initial_fingerprint(&database, &candidate).await;
    let initial = prepare_and_load_person_registration(
        &prior_project,
        &assets,
        &prior_fingerprint,
        None,
        PackageMigrationPlanInput::InitialCompiledDdl,
    );
    let mut active = apply(&database, &initial, ApplyPrecondition::InitialActivation)
        .await
        .expect("the current package establishes the fixture catalog");

    // Reproduce the catalog and exact package identity retained by the
    // committed pre-statistics fixture. Later calls use only maintained APIs.
    let (migration, task) = database.connect_migration().await;
    migration
        .batch_execute(
            "DROP FUNCTION registry_internal.withdraw_statistical_release(text, text, bigint, text);
             DROP TABLE registry_internal.registry_statistical_release_contents;
             DROP TABLE registry_internal.registry_statistical_release_withdrawals;
             DROP TABLE registry_internal.registry_statistical_release_versions;",
        )
        .await
        .expect("the fixture removes the later engine-owned store");
    let active_catalog = ExpectedManagedCatalog::compiled_predecessor(&prior, false);
    let legacy_fingerprint =
        managed_schema_fingerprint(&migration, &database.runtime_role, &active_catalog)
            .await
            .expect("the pre-statistics catalog fingerprints against its closed shape");
    active.package_digest = predecessor.package_digest().to_owned();
    active.schema_fingerprint.clone_from(&legacy_fingerprint);
    migration
        .execute(
            "UPDATE registry_internal.registry_state
                SET active_package_digest = $1, schema_fingerprint = $2
              WHERE singleton",
            &[&active.package_digest, &active.schema_fingerprint],
        )
        .await
        .expect("the fixture records the committed predecessor identity");
    migration
        .execute(
            "UPDATE registry_internal.registry_migrations
                SET package_digest = $1
              WHERE activation_id = $2::text::uuid",
            &[&active.package_digest, &active.activation_id],
        )
        .await
        .expect("the activation ledger names the committed predecessor");
    drop(migration);
    task.abort();

    let abandoned_source = person_action_metadata_source(
        &active,
        predecessor.migration_baseline(),
        &candidate,
        &candidate_fingerprint,
        false,
    );

    let abandoned = prepare_and_load_person_registration(
        &candidate_project,
        &assets,
        &candidate_fingerprint,
        Some(predecessor.package_digest()),
        PackageMigrationPlanInput::ReviewedSuccessorFromBaseline {
            prior_baseline: Box::new(predecessor.migration_baseline().clone()),
            prior_schema_fingerprint: legacy_fingerprint.clone(),
            migrations: vec![abandoned_source],
        },
    );
    let failed = apply(
        &database,
        &abandoned,
        ApplyPrecondition::Successor { current: &active },
    )
    .await;
    assert_value_free(failed.err(), MigrationError::ApplyFailed);
    assert_non_ready_target(&database, &active, &abandoned, "failed").await;

    let assessed = reconcile_with_catalog(&database, &abandoned, &active, &active_catalog, false)
        .await
        .expect("the current binary assesses the exact legacy catalog");
    assert_eq!(
        assessed.outcome,
        ReconcileOutcome::Revertible,
        "legacy reconciliation assessment: {assessed:?}"
    );
    assert_eq!(assessed.active_catalog_finding, None);
    assert!(assessed.target_catalog_finding.is_some());
    assert_eq!(assessed.durable_step_progress, Some(false));

    let reverted = reconcile_with_catalog(&database, &abandoned, &active, &active_catalog, true)
        .await
        .expect("the failed successor is safely released");
    assert!(reverted.executed);
    assert_ready_target(&database, &active).await;

    let successor_source = person_action_metadata_source(
        &active,
        predecessor.migration_baseline(),
        &candidate,
        &candidate_fingerprint,
        true,
    );
    let successor = prepare_and_load_person_registration(
        &candidate_project,
        &assets,
        &candidate_fingerprint,
        Some(predecessor.package_digest()),
        PackageMigrationPlanInput::ReviewedSuccessorFromBaseline {
            prior_baseline: Box::new(predecessor.migration_baseline().clone()),
            prior_schema_fingerprint: legacy_fingerprint,
            migrations: vec![successor_source],
        },
    );
    let upgraded = apply(
        &database,
        &successor,
        ApplyPrecondition::Successor { current: &active },
    )
    .await
    .expect("the corrected successor applies after reconciliation");
    assert_ready_target(&database, &upgraded).await;
    let store_present: bool = database
        .admin
        .query_one(
            "SELECT pg_catalog.to_regclass(
                 'registry_internal.registry_statistical_release_versions'
             ) IS NOT NULL",
            &[],
        )
        .await
        .expect("the upgraded catalog exposes the release store")
        .get(0);
    assert!(store_present);
    let candidate_entity = &candidate.entities()["person"];
    let added_field = &candidate_entity.fields["migration-note"];
    let field_present: bool = database
        .admin
        .query_one(
            "SELECT EXISTS (
                 SELECT 1 FROM information_schema.columns
                  WHERE table_schema = 'registry_data'
                    AND table_name = $1
                    AND column_name = $2
             )",
            &[&candidate_entity.physical_table, &added_field.physical_name],
        )
        .await
        .expect("the corrected successor installs its governed field")
        .get(0);
    assert!(field_present);
    database.cleanup().await;
}

/// A verified package from before engine capability declarations may have no
/// authored model delta while the current compiler adds the statistical
/// release store to its closed catalog. That one capability transition is
/// real apply work; omitting the verified predecessor binding remains an
/// ordinary empty-plan refusal.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pre_statistics_empty_successor_installs_the_release_store_once() {
    let database = TestDatabase::create(1).await;
    database
        .admin
        .batch_execute("CREATE EXTENSION btree_gist")
        .await
        .expect("administrator installs the required extension");

    let predecessor = load_person_pre_statistics_package();
    assert!(!predecessor.statistical_release_store_present());
    let assets = person_registration_assets();
    let project = person_registration_project(false);
    let registry = compile_person_registration(&project, &assets);
    assert_eq!(predecessor.package_id(), registry.registry_id());
    let target_fingerprint = initial_fingerprint(&database, &registry).await;
    let initial = prepare_and_load_person_registration(
        &project,
        &assets,
        &target_fingerprint,
        None,
        PackageMigrationPlanInput::InitialCompiledDdl,
    );
    let mut active = apply(&database, &initial, ApplyPrecondition::InitialActivation)
        .await
        .expect("the current package establishes the fixture catalog");

    let (migration, task) = database.connect_migration().await;
    migration
        .batch_execute(
            "DROP FUNCTION registry_internal.withdraw_statistical_release(text, text, bigint, text);
             DROP TABLE registry_internal.registry_statistical_release_contents;
             DROP TABLE registry_internal.registry_statistical_release_withdrawals;
             DROP TABLE registry_internal.registry_statistical_release_versions;",
        )
        .await
        .expect("the fixture removes the later engine-owned store");
    let legacy_catalog = ExpectedManagedCatalog::compiled_predecessor(&registry, false);
    let legacy_fingerprint =
        managed_schema_fingerprint(&migration, &database.runtime_role, &legacy_catalog)
            .await
            .expect("the pre-statistics catalog fingerprints against its closed shape");
    active.package_digest = predecessor.package_digest().to_owned();
    active.schema_fingerprint = legacy_fingerprint;
    migration
        .execute(
            "UPDATE registry_internal.registry_state
                SET active_package_digest = $1, schema_fingerprint = $2
              WHERE singleton",
            &[&active.package_digest, &active.schema_fingerprint],
        )
        .await
        .expect("the fixture records the predecessor identity");
    migration
        .execute(
            "UPDATE registry_internal.registry_migrations
                SET package_digest = $1
              WHERE activation_id = $2::text::uuid",
            &[&active.package_digest, &active.activation_id],
        )
        .await
        .expect("the activation ledger names the predecessor package");
    drop(migration);
    task.abort();

    let successor = prepare_and_load_person_registration(
        &project,
        &assets,
        &target_fingerprint,
        Some(predecessor.package_digest()),
        PackageMigrationPlanInput::Successor {
            prior_registry: Box::new(registry.clone()),
        },
    );
    assert!(successor_plan_is_empty(&successor));
    assert!(!successor_plan_is_empty_for_predecessor(
        &successor,
        &predecessor
    ));
    assert_value_free(
        apply(
            &database,
            &successor,
            ApplyPrecondition::Successor { current: &active },
        )
        .await
        .err(),
        MigrationError::EmptyPlan,
    );

    let history = predecessor.history_schema_descriptor();
    let plan = plan_verified_package(
        request(
            &database,
            &successor,
            ApplyPrecondition::Successor { current: &active },
        )
        .with_predecessor_migration_baseline(predecessor.migration_baseline())
        .with_predecessor_history_descriptor(&history)
        .with_predecessor_engine_capabilities(&predecessor),
    )
    .await
    .expect("the verified legacy capability transition plans");
    assert_eq!(plan.activation, PlannedActivation::Successor);
    let upgraded = apply_verified_package(
        request(
            &database,
            &successor,
            ApplyPrecondition::Successor { current: &active },
        )
        .with_predecessor_migration_baseline(predecessor.migration_baseline())
        .with_predecessor_history_descriptor(&history)
        .with_predecessor_engine_capabilities(&predecessor),
    )
    .await
    .expect("the verified legacy capability transition applies");
    assert_ready_target(&database, &upgraded).await;
    verify_catalog_identity_for_catalog(
        &database.admin,
        &upgraded,
        &ExpectedManagedCatalog::compiled(&registry),
        &database.migration_role,
        &database.runtime_role,
    )
    .await
    .expect("the activated catalog is the exact current catalog");
    database.cleanup().await;
}

/// A package built before caller-scoped idempotency declares only the
/// statistical release store, and its engine found spent keys by an
/// audit-keyed digest. The current compiler's rebuild has no authored model
/// delta, yet installing the caller-keyed shape is real apply work: the plan is
/// not empty, and the apply keeps the spent keys the earlier engine wrote as
/// tombstones no caller can find, with their held responses removed.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pre_caller_scoped_empty_successor_tombstones_audit_keyed_spent_keys() {
    let database = TestDatabase::create(1).await;
    database
        .admin
        .batch_execute("CREATE EXTENSION btree_gist")
        .await
        .expect("administrator installs the required extension");

    // The package loader refuses a path through a symbolic link, so the copy
    // lives under the canonical temporary root.
    let predecessor_root = tempfile::Builder::new()
        .prefix("registry-pre-caller-scoped-package-")
        .tempdir_in(
            std::env::temp_dir()
                .canonicalize()
                .expect("the temporary root canonicalizes"),
        )
        .expect("a temporary package root is created");
    let predecessor = load_person_pre_caller_scoped_package(predecessor_root.path());
    assert!(predecessor.statistical_release_store_present());
    assert!(!predecessor
        .engine_features()
        .contains(&PackageEngineFeature::CallerScopedIdempotency));
    let assets = person_registration_assets();
    let project = person_registration_project(false);
    let registry = compile_person_registration(&project, &assets);
    assert_eq!(predecessor.package_id(), registry.registry_id());
    let target_fingerprint = initial_fingerprint(&database, &registry).await;
    let initial = prepare_and_load_person_registration(
        &project,
        &assets,
        &target_fingerprint,
        None,
        PackageMigrationPlanInput::InitialCompiledDdl,
    );
    let mut active = apply(&database, &initial, ApplyPrecondition::InitialActivation)
        .await
        .expect("the current package establishes the fixture catalog");

    let (migration, task) = database.connect_migration().await;
    migration
        .batch_execute(
            "ALTER TABLE registry_internal.registry_idempotency
                 DROP CONSTRAINT registry_idempotency_caller_shape,
                 DROP CONSTRAINT registry_idempotency_erasure_shape;
             DROP INDEX registry_internal.registry_idempotency_caller_key;
             ALTER TABLE registry_internal.registry_idempotency
                 DROP COLUMN caller_issuer,
                 DROP COLUMN caller_subject,
                 DROP COLUMN key_scope,
                 DROP COLUMN idempotency_key,
                 DROP COLUMN receipt_expires_at,
                 DROP COLUMN receipt_dropped_at;
             ALTER TABLE registry_internal.registry_idempotency
                 ADD CONSTRAINT registry_idempotency_erasure_shape
                     CHECK ((response_body IS NULL) = (erased_at IS NOT NULL));
             INSERT INTO registry_internal.registry_idempotency
                 (key_reference, binding_reference, result_kind, result_count,
                  response_status, response_body, response_headers)
             VALUES
                 ('hmac-sha256:held', 'hmac-sha256:held-binding', 'immediate_action', 0,
                  200, '{}', '\\x0000');",
        )
        .await
        .expect("the fixture restores the audit-keyed spent-key shape with a held row");
    let legacy_catalog = ExpectedManagedCatalog::compiled_predecessor(&registry, true);
    let legacy_fingerprint =
        managed_schema_fingerprint(&migration, &database.runtime_role, &legacy_catalog)
            .await
            .expect("the audit-keyed catalog fingerprints against its closed shape");
    active.package_digest = predecessor.package_digest().to_owned();
    active.schema_fingerprint = legacy_fingerprint;
    migration
        .execute(
            "UPDATE registry_internal.registry_state
                SET active_package_digest = $1, schema_fingerprint = $2
              WHERE singleton",
            &[&active.package_digest, &active.schema_fingerprint],
        )
        .await
        .expect("the fixture records the predecessor identity");
    migration
        .execute(
            "UPDATE registry_internal.registry_migrations
                SET package_digest = $1
              WHERE activation_id = $2::text::uuid",
            &[&active.package_digest, &active.activation_id],
        )
        .await
        .expect("the activation ledger names the predecessor package");
    drop(migration);
    task.abort();

    let successor = prepare_and_load_person_registration(
        &project,
        &assets,
        &target_fingerprint,
        Some(predecessor.package_digest()),
        PackageMigrationPlanInput::Successor {
            prior_registry: Box::new(registry.clone()),
        },
    );
    assert!(successor_plan_is_empty(&successor));
    assert!(!successor_plan_is_empty_for_predecessor(
        &successor,
        &predecessor
    ));

    let history = predecessor.history_schema_descriptor();
    let upgraded = apply_verified_package(
        request(
            &database,
            &successor,
            ApplyPrecondition::Successor { current: &active },
        )
        .with_predecessor_migration_baseline(predecessor.migration_baseline())
        .with_predecessor_history_descriptor(&history)
        .with_predecessor_engine_capabilities(&predecessor),
    )
    .await
    .expect("the verified caller-scoped capability transition applies");
    assert_ready_target(&database, &upgraded).await;
    let row = database
        .admin
        .query_one(
            "SELECT (SELECT count(*) FROM registry_internal.registry_idempotency),
                    EXISTS (
                        SELECT 1 FROM information_schema.columns
                         WHERE table_schema = 'registry_internal'
                           AND table_name = 'registry_idempotency'
                           AND column_name = 'caller_issuer'
                    )",
            &[],
        )
        .await
        .expect("administrator reads the spent-key table");
    assert_eq!(
        row.get::<_, i64>(0),
        1,
        "the upgrade keeps audit-keyed spent keys"
    );
    assert!(
        row.get::<_, bool>(1),
        "the upgrade installs the caller shape"
    );
    let tombstone = database
        .admin
        .query_one(
            "SELECT caller_issuer IS NULL AND caller_subject IS NULL
                        AND idempotency_key IS NULL,
                    key_scope, response_body IS NULL, receipt_dropped_at IS NOT NULL
               FROM registry_internal.registry_idempotency
              WHERE key_reference = 'hmac-sha256:held'",
            &[],
        )
        .await
        .expect("administrator reads the converted spent key");
    assert!(tombstone.get::<_, bool>(0), "no raw caller or key is kept");
    assert_eq!(tombstone.get::<_, String>(1), "mutation");
    assert!(tombstone.get::<_, bool>(2), "no held response survives");
    assert!(tombstone.get::<_, bool>(3), "the receipt is dropped");
    verify_catalog_identity_for_catalog(
        &database.admin,
        &upgraded,
        &ExpectedManagedCatalog::compiled(&registry),
        &database.migration_role,
        &database.runtime_role,
    )
    .await
    .expect("the activated catalog is the exact current catalog");
    database.cleanup().await;
}

/// The current frozen person-registration package as an engine that predates
/// caller-scoped idempotency wrote it: the same bytes, with a manifest that
/// declares only the statistical release store.
fn load_person_pre_caller_scoped_package(root: &std::path::Path) -> VerifiedPredecessorPackage {
    let frozen = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/person-registration-rhai-package");
    copy_package_tree(&frozen, root);
    let manifest_path = root.join("package.json");
    let mut envelope: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest_path).expect("the package manifest reads"))
            .expect("the package manifest parses");
    envelope["manifest"]["engineFeatures"] = serde_json::json!(["statistical_release_store"]);
    fs::write(
        &manifest_path,
        canonicalize_json(&envelope).expect("the rewritten envelope canonicalizes"),
    )
    .expect("the rewritten manifest is written");
    fs::remove_file(root.join(SUM_FILE)).expect("the stale sum file is removed");
    write_sum_file(
        root,
        None,
        &PackageLimits {
            max_files: 1_026,
            max_file_bytes: 16 * 1024 * 1024,
            max_total_bytes: 64 * 1024 * 1024,
            max_depth: 16,
            max_path_bytes: 512,
        },
        "test package",
    )
    .expect("the rewritten package closes");
    load_predecessor_package(root, &local_context())
        .expect("the pre-caller-scoped package verifies as a predecessor")
}

fn copy_package_tree(source: &std::path::Path, destination: &std::path::Path) {
    for entry in fs::read_dir(source).expect("the frozen package directory reads") {
        let entry = entry.expect("the frozen package entry reads");
        let target = destination.join(entry.file_name());
        if entry
            .file_type()
            .expect("the frozen package entry type reads")
            .is_dir()
        {
            fs::create_dir(&target).expect("the package subdirectory is created");
            copy_package_tree(&entry.path(), &target);
        } else {
            fs::copy(entry.path(), &target).expect("the package file is copied");
        }
    }
}

fn person_registration_acceptance_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/breg/acceptance/person-registration-rhai")
}

fn person_registration_project(with_migration_note: bool) -> RegistryProject {
    let mut project = serde_json::to_value(
        parse_project_yaml(
            &fs::read(person_registration_acceptance_root().join("registry.yaml"))
                .expect("the person-registration acceptance project is present"),
        )
        .expect("the person-registration acceptance project parses"),
    )
    .expect("the project serializes");
    project["package"]["sourceRevision"] = serde_json::json!(SOURCE_REVISION);
    if with_migration_note {
        project["entities"][0]["fields"]
            .as_array_mut()
            .expect("person fields are an array")
            .push(serde_json::json!({
                "id": "migration-note",
                "type": "string",
                "required": false,
                "maxLength": 32,
                "classification": "internal"
            }));
    }
    serde_json::from_value(project).expect("the test project remains valid source")
}

fn person_registration_assets() -> Vec<PackageSourceFile> {
    [
        "scripts/register-person.rhai",
        "scripts/register-person-with-registration.rhai",
    ]
    .into_iter()
    .map(|path| PackageSourceFile {
        path: path.to_owned(),
        bytes: fs::read(person_registration_acceptance_root().join(path))
            .unwrap_or_else(|error| panic!("the handler script {path} is present: {error}")),
    })
    .collect()
}

fn compile_person_registration(
    project: &RegistryProject,
    assets: &[PackageSourceFile],
) -> CompiledRegistry {
    let compiler_assets = assets
        .iter()
        .map(|asset| ModuleAssetSource {
            module: None,
            path: asset.path.clone(),
            bytes: asset.bytes.clone(),
        })
        .collect::<Vec<_>>();
    compile_project_with_assets(project, &[], &compiler_assets, CompileProfile::Production)
        .expect("the person-registration project compiles")
}

fn person_action_metadata_source(
    current: &ExpectedRegistryIdentity,
    baseline: &CompiledRegistryMigrationBaseline,
    candidate: &CompiledRegistry,
    final_fingerprint: &str,
    precondition_succeeds: bool,
) -> ReviewedMigrationSource {
    let changes =
        compiled_registry_change_set_from_baseline(baseline, candidate, &current.package_digest);
    let mut covers = changes
        .changes
        .iter()
        .filter(|change| change.code == CompiledRegistryChangeCode::ActionChanged)
        .map(ReviewedChangeCover::from)
        .collect::<Vec<_>>();
    covers.sort();
    assert_eq!(
        covers.len(),
        2,
        "the current compiler identifies both predecessor action metadata changes"
    );
    assert!(changes.changes.iter().all(|change| {
        change.class == CompiledRegistryChangeClass::CompatibleAdditive
            || change.code == CompiledRegistryChangeCode::ActionChanged
    }));
    let id = if precondition_succeeds {
        "legacy-actions-successor"
    } else {
        "legacy-actions-abandoned"
    };
    let base = format!("modules/core/migrations/{id}");
    let pre_path = format!("{base}/assertions/pre.sql");
    let post_path = format!("{base}/assertions/post.sql");
    let descriptor = ReviewedMigrationDescriptor {
        id: id.to_owned(),
        change_class: CompiledRegistryChangeClass::AccessOrDisclosureChange,
        covers,
        recovery: ReviewedMigrationRecovery::ExactTargetResume,
        lock_timeout_ms: 50,
        statement_timeout_ms: 5_000,
        steps: Vec::new(),
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
        steps: Vec::new(),
        pre: (
            pre_path,
            if precondition_succeeds {
                "SELECT true".to_owned()
            } else {
                "SELECT false".to_owned()
            },
        ),
        post: (post_path, "SELECT true".to_owned()),
        row_assertions: Vec::new(),
    })
}

fn load_person_pre_statistics_package() -> VerifiedPredecessorPackage {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/person-registration-rhai-package-pre-statistics");
    load_predecessor_package(&root, &local_context())
        .expect("the committed pre-statistics package verifies as a predecessor")
}

fn prepare_and_load_person_registration(
    project: &RegistryProject,
    assets: &[PackageSourceFile],
    fingerprint: &str,
    from_package_digest: Option<&str>,
    migration_plan: PackageMigrationPlanInput,
) -> VerifiedPackage {
    let prepared = prepare_package_with_project_assets(
        PackageBuildRequest {
            from_package_digest: from_package_digest.map(str::to_owned),
            compiler_source_revision: SOURCE_REVISION.to_owned(),
            schema_fingerprint: fingerprint.to_owned(),
            project: PackageSourceFile {
                path: "source/registry.yaml".to_owned(),
                bytes: source_bytes::source_bytes(project),
            },
            modules: Vec::new(),
            fixture_journeys: PackageSourceFile {
                path: "tests/journeys.yaml".to_owned(),
                bytes: fs::read(person_registration_acceptance_root().join("tests/journeys.yaml"))
                    .expect("the person-registration fixture journeys are present"),
            },
            migration_plan,
        },
        assets.to_vec(),
    )
    .unwrap_or_else(|error| {
        panic!(
            "the person-registration package prepares (from {:?}): {error:?}",
            from_package_digest
        )
    });
    publish_and_load(prepared, local_context())
}

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

    let base = compile_variant(Variant::Base);
    let initial_fingerprint = initial_fingerprint(&database, &base).await;
    let initial = prepare_and_load_initial(&base, &initial_fingerprint);
    let active = apply(&database, &initial, ApplyPrecondition::InitialActivation)
        .await
        .expect("initial package activates through the library coordinator");
    seed_backfill_rows(&database, &base, 5).await;

    let required = compile_variant(Variant::RankRequired);
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
    assert_eq!(
        reviewed_migration_history(&database).await,
        (2, vec![2]),
        "the committed chunk appended one revision per row it changed in one commit"
    );
    assert_non_ready_target(&database, &active, &required_package, "applying").await;
    let interrupted_activation = activation_at(&database, 2).await;
    assert_ne!(interrupted_activation, active.activation_id);
    // The durable state shows the target still applying, so the attempt's
    // audit request is answered unfinished rather than failed.
    let interrupted_audit = activation_audit_records(&database, &interrupted_activation);
    assert_eq!(interrupted_audit.len(), 2, "{interrupted_audit:?}");
    assert_eq!(interrupted_audit[1].0, "response");
    assert_eq!(interrupted_audit[1].1["outcome"], "unfinished");

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
    // The resumed run is the interrupted activation, not a second one, and
    // every chunk either run committed is scoped to that one activation id.
    assert_eq!(required_active.activation_id, interrupted_activation);
    let chunk_scopes = database
        .admin
        .query(
            "SELECT DISTINCT originating_package_revision
               FROM registry_internal.registry_revision_commits
              WHERE system_origin = 'breg-reviewed-migration-v1'",
            &[],
        )
        .await
        .expect("reviewed migration commit scopes read")
        .iter()
        .map(|row| row.get::<_, String>(0))
        .collect::<Vec<_>>();
    assert_eq!(chunk_scopes, vec![interrupted_activation.clone()]);
    let completed = step_snapshot(&database, &required_package, "backfill-rank").await;
    assert_eq!(completed.0, "completed");
    assert_eq!(completed.2, 5);
    assert_all_ranks(&database, &required, 1).await;
    assert_eq!(
        reviewed_migration_history(&database).await,
        (5, vec![2, 2, 1]),
        "every chunk commit journals its own rows once, and the resumed run does not \
         journal the committed chunk again"
    );
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

    let removed = compile_variant(Variant::LegacyRemoved);
    let destructive_fingerprint = destructive_target_fingerprint(&database, &removed).await;
    let backup_bytes = synthetic_backup_sql(&required, &required_active, &database.runtime_role, 5);
    let backup_digest = digest(&backup_bytes);
    let now = OffsetDateTime::now_utc()
        .format(&Rfc3339)
        .expect("current time formats");
    let reviewed_destructive_source = destructive_recovery_source(
        "remove-legacy",
        &required_active,
        &required,
        &removed,
        &destructive_fingerprint,
    );
    let destructive_package = prepare_and_load_reviewed(
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
    let binding = ExternalBackupBinding {
        database_id: DATABASE.to_owned(),
        prior_package_digest: required_active.package_digest.clone(),
        prior_schema_fingerprint: required_active.schema_fingerprint.clone(),
        backup_file: backup_path.to_str().expect("UTF-8 backup path").to_owned(),
        sha256: backup_digest,
        byte_length: backup_bytes.len() as u64,
        created_at: now,
        max_age_seconds: 3_600,
    };
    let binding_file = write_backup_binding(backup_root.path(), "binding.json", &binding);

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
        &binding_file,
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
    let loose_evidence = [DestructiveBackupEvidence::new(binding_path, &binding_file)];
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
    let symlink_binding = write_backup_binding(
        backup_root.path(),
        "symlink-binding.json",
        &ExternalBackupBinding {
            backup_file: symlink_path.to_str().expect("UTF-8 link path").to_owned(),
            ..binding.clone()
        },
    );
    let symlink_evidence = [DestructiveBackupEvidence::new(
        binding_path,
        &symlink_binding,
    )];
    let symlink = apply_with_evidence(
        &database,
        &destructive_package,
        &required_active,
        &symlink_evidence,
    )
    .await;
    assert_value_free(symlink.err(), MigrationError::BackupEvidence);
    assert_ready_target(&database, &required_active).await;

    // A binding describes one database's backup, so every refusal below is of
    // the binding an operator supplies, never of the package.
    for (name, refused) in [
        (
            "wrong-digest.json",
            ExternalBackupBinding {
                sha256: digest(b"different-backup"),
                ..binding.clone()
            },
        ),
        (
            "stale.json",
            ExternalBackupBinding {
                created_at: "2020-01-01T00:00:00Z".to_owned(),
                max_age_seconds: 60,
                ..binding.clone()
            },
        ),
        (
            "other-database.json",
            ExternalBackupBinding {
                database_id: "other-database".to_owned(),
                ..binding.clone()
            },
        ),
        (
            "other-package.json",
            ExternalBackupBinding {
                prior_package_digest: active.package_digest.clone(),
                ..binding.clone()
            },
        ),
    ] {
        let refused_file = write_backup_binding(backup_root.path(), name, &refused);
        let evidence = [DestructiveBackupEvidence::new(binding_path, &refused_file)];
        let outcome =
            apply_with_evidence(&database, &destructive_package, &required_active, &evidence).await;
        assert_value_free(outcome.err(), MigrationError::BackupEvidence);
        assert_ready_target(&database, &required_active).await;
    }

    // The runtime identity names the database; a package names none.
    let wrong_database = apply_verified_package(
        request_for_deployment(
            &database,
            &destructive_package,
            ApplyPrecondition::Successor {
                current: &required_active,
            },
            ActivationDeployment::new(ENVIRONMENT, INSTANCE, "other-database"),
        )
        .with_destructive_backup_evidence(&[DestructiveBackupEvidence::new(
            binding_path,
            &binding_file,
        )]),
    )
    .await;
    assert_value_free(wrong_database.err(), MigrationError::DatabaseMismatch);
    assert_ready_target(&database, &required_active).await;

    let valid_evidence = [DestructiveBackupEvidence::new(binding_path, &binding_file)];
    let destructive_fault = apply_with_evidence(
        &database,
        &destructive_package,
        &required_active,
        &valid_evidence,
    )
    .await
    .expect_err("the second reviewed drop deterministically faults after the first committed drop");
    // The second drop names the column the first already dropped, so the
    // refusal carries PostgreSQL's undefined-column SQLSTATE.
    assert_value_free(
        Some(destructive_fault),
        MigrationError::StatementFailed(PostgresFailure {
            sqlstate: Some("42703".to_owned()),
            ..PostgresFailure::default()
        }),
    );
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
    assert_value_free(active_noop.err(), MigrationError::AlreadyActive);
    assert_non_ready_target(&database, &required_active, &destructive_package, "failed").await;

    let substituted_source = destructive_source(
        "remove-legacy-substituted-target",
        &required_active,
        &required,
        &removed,
        &destructive_fingerprint,
    );
    let substituted_package = prepare_and_load_reviewed(
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
        &binding_file,
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

    // The retry verifies a backup of its own, taken after the restore, so the
    // ledger must name that backup rather than the one the failed attempt
    // started with.
    let retry_backup_path = backup_root.path().join("retry-canary.backup");
    fs::write(&retry_backup_path, &backup_bytes).expect("retry backup artifact writes");
    fs::set_permissions(&retry_backup_path, fs::Permissions::from_mode(0o600))
        .expect("retry backup evidence permissions close");
    let retry_binding = ExternalBackupBinding {
        backup_file: retry_backup_path
            .to_str()
            .expect("UTF-8 retry backup path")
            .to_owned(),
        ..binding.clone()
    };
    let retry_binding_file =
        write_backup_binding(backup_root.path(), "retry-binding.json", &retry_binding);
    let retry_evidence = [DestructiveBackupEvidence::new(
        binding_path,
        &retry_binding_file,
    )];
    let destructive_active = apply_with_evidence(
        &database,
        &destructive_package,
        &required_active,
        &retry_evidence,
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
    // The destructive activation records the backup the applying attempt was
    // bound to, as the binding described it, so the ledger names what a
    // restore would use.
    let backup_references: serde_json::Value = database
        .admin
        .query_one(
            "SELECT backup_references FROM registry_internal.registry_migrations
              WHERE apply_order = 3",
            &[],
        )
        .await
        .expect("the ledger reads")
        .get(0);
    assert_eq!(
        backup_references,
        serde_json::json!([{
            "bindingPath": binding_path,
            "backupFile": retry_binding.backup_file,
            "sha256": retry_binding.sha256,
            "byteLength": retry_binding.byte_length,
            "createdAt": retry_binding.created_at,
        }])
    );

    database.cleanup().await;

    false_assertion_refusals_are_closed().await;
    row_count_mismatch_is_closed().await;
    lock_timeout_is_bounded().await;
    refused_step_reports_its_sqlstate().await;
}

/// Applying the active package again is refused as already active before
/// maintenance begins, and writes nothing. What the database records, read
/// under the exclusive apply lock, binds a package only when it names the
/// runtime identity's database and the exact active package digest, and
/// reports a registry held in maintenance as not ready.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_refuses_the_active_package_again_and_binds_only_the_recorded_package() {
    let ActivePackageFixture {
        database,
        root,
        initial,
        active,
    } = ActivePackageFixture::activate().await;

    let before = durable_snapshot(&database).await;
    assert_value_free(
        apply(
            &database,
            &initial,
            ApplyPrecondition::Successor { current: &active },
        )
        .await
        .err(),
        MigrationError::AlreadyActive,
    );
    assert_eq!(durable_snapshot(&database).await, before);

    let recorded = recorded_state(&database, &initial)
        .await
        .expect("the recorded state reads")
        .expect("an activated database records its state");
    assert_eq!(
        recorded,
        RecordedRegistryState {
            identity: active.clone(),
            ready: true,
            activation_applied: true,
        }
    );
    bind_active_package(&recorded.identity, initial.package_digest(), deployment())
        .expect("the recorded active package binds");
    assert_eq!(durable_snapshot(&database).await, before);

    // Another package of the same registry is not the active package.
    let other_root = root.path().join("other-package");
    let other = prepare_package(build_request(
        Variant::Base,
        None,
        &digest(b"another schema of the same registry"),
        PackageMigrationPlanInput::InitialCompiledDdl,
    ))
    .expect("another package prepares");
    other
        .publish_to_directory(&other_root)
        .expect("another package publishes");
    let other = load_package(&other_root, &local_context()).expect("another package loads");
    assert_value_free(
        bind_active_package(&recorded.identity, other.package_digest(), deployment()).err(),
        MigrationError::ActivePackageMismatch,
    );
    assert_value_free(
        bind_active_package(
            &recorded.identity,
            initial.package_digest(),
            ActivationDeployment::new(ENVIRONMENT, INSTANCE, "other-database"),
        )
        .err(),
        MigrationError::DatabaseMismatch,
    );

    // A registry held in maintenance is not ready, even for its own active
    // identity.
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_state
             SET maintenance_status = 'failed', maintenance_target_package_digest = $1
             WHERE singleton",
            &[&other.package_digest()],
        )
        .await
        .expect("administrator pins a failed maintenance target");
    let before = durable_snapshot(&database).await;
    let held = recorded_state(&database, &initial)
        .await
        .expect("the recorded state reads")
        .expect("a held database records its state");
    assert!(!held.ready, "a failed maintenance target is not ready");
    assert_eq!(durable_snapshot(&database).await, before);
    database.cleanup().await;
}

/// An unreachable database or a migration lock another session holds, before
/// maintenance begins, changes nothing, so it is never reported as a failed
/// migration that needs reconciliation. An unreachable database is reported
/// as unavailable and a held lock as held, never one as the other. This
/// holds for an activation and for reading the recorded registry state
/// alike, while the lock-free status read still answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_reports_an_unavailable_database_before_maintenance_as_unchanged() {
    let ActivePackageFixture {
        database,
        root: _root,
        initial,
        active: _,
    } = ActivePackageFixture::activate().await;
    let before = durable_snapshot(&database).await;

    let unreachable =
        database.migration_config_for_database(&format!("missing_{}", Uuid::new_v4().simple()));
    assert_value_free(
        apply_verified_package(ApplyVerifiedPackageRequest::new(
            &unreachable,
            &initial,
            deployment(),
            ApplyPrecondition::InitialActivation,
            ApplyRoles::new(&database.migration_role, &database.runtime_role),
            ApplyTimeouts::new(Duration::from_secs(1), Duration::from_secs(5))
                .expect("test timeouts are bounded"),
            database.activation_audit(),
        ))
        .await
        .err(),
        MigrationError::DatabaseUnavailable,
    );
    assert_value_free(
        recorded_state_with(&unreachable, &database, &initial)
            .await
            .err(),
        MigrationError::DatabaseUnavailable,
    );

    let lock_key = registry_breg::postgres::RegistryLockKey::derive(&initial.manifest().package_id)
        .expect("package lock key derives");
    let (holder, holder_task) = database.connect_admin().await;
    holder
        .execute("SELECT pg_catalog.pg_advisory_lock($1)", &[&lock_key.get()])
        .await
        .expect("another session holds the apply lock");
    assert_value_free(
        apply(&database, &initial, ApplyPrecondition::InitialActivation)
            .await
            .err(),
        MigrationError::MigrationLockHeld,
    );
    assert_value_free(
        recorded_state(&database, &initial).await.err(),
        MigrationError::MigrationLockHeld,
    );
    read_activation_status(
        &database.migration_config,
        &database.migration_role,
        ApplyTimeouts::new(Duration::from_secs(1), Duration::from_secs(5))
            .expect("test timeouts are bounded"),
    )
    .await
    .expect("the lock-free status read answers while the lock is held")
    .expect("the database records an activation");
    holder
        .execute(
            "SELECT pg_catalog.pg_advisory_unlock($1)",
            &[&lock_key.get()],
        )
        .await
        .expect("the other session releases the apply lock");
    holder_task.abort();

    assert_eq!(durable_snapshot(&database).await, before);
    database.cleanup().await;
}

/// A provisioned database that was never activated holds no registry state.
/// Reading it, which is what an apply without `--initial` does first, reports
/// no recorded state and creates none. It is never reported as a database
/// that is unavailable, because retrying cannot create the missing state.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_reads_no_recorded_state_from_a_never_activated_database() {
    let PublishedInitialPackage {
        database,
        root: _root,
        initial,
    } = PublishedInitialPackage::publish().await;

    assert_eq!(
        recorded_state(&database, &initial)
            .await
            .expect("a never-activated database reads"),
        None
    );

    let (migration, task) = database.connect_migration().await;
    let state_table: Option<String> = migration
        .query_one(
            "SELECT pg_catalog.to_regclass('registry_internal.registry_state')::text",
            &[],
        )
        .await
        .expect("registry state lookup runs")
        .get(0);
    task.abort();
    assert_eq!(state_table, None, "the refusal created no registry state");
    database.cleanup().await;
}

/// One registry whose initial package is active.
struct ActivePackageFixture {
    database: TestDatabase,
    root: tempfile::TempDir,
    initial: VerifiedPackage,
    active: ExpectedRegistryIdentity,
}

impl ActivePackageFixture {
    async fn activate() -> Self {
        let PublishedInitialPackage {
            database,
            root,
            initial,
        } = PublishedInitialPackage::publish().await;
        let active = apply(&database, &initial, ApplyPrecondition::InitialActivation)
            .await
            .expect("initial package activates");
        Self {
            database,
            root,
            initial,
            active,
        }
    }
}

/// A provisioned database that has never been activated, with its initial
/// package published and loaded for activation.
struct PublishedInitialPackage {
    database: TestDatabase,
    root: tempfile::TempDir,
    initial: VerifiedPackage,
}

impl PublishedInitialPackage {
    async fn publish() -> Self {
        let database = TestDatabase::create(1).await;
        database
            .admin
            .batch_execute("CREATE EXTENSION btree_gist")
            .await
            .expect("administrator installs extension");
        let base = compile_variant(Variant::Base);
        let fingerprint = initial_fingerprint(&database, &base).await;
        let root = tempfile::Builder::new()
            .prefix("registry-active-package-")
            .tempdir_in(
                std::env::temp_dir()
                    .canonicalize()
                    .expect("canonical temporary root"),
            )
            .expect("package temporary directory creates");
        let package_root = root.path().join("package");
        prepare_package(build_request(
            Variant::Base,
            None,
            &fingerprint,
            PackageMigrationPlanInput::InitialCompiledDdl,
        ))
        .expect("initial package prepares")
        .publish_to_directory(&package_root)
        .expect("initial package publishes");
        let initial = load_package(&package_root, &local_context())
            .expect("initial package loads for activation");
        Self {
            database,
            root,
            initial,
        }
    }
}

async fn recorded_state(
    database: &TestDatabase,
    package: &VerifiedPackage,
) -> registry_breg::migration::Result<Option<RecordedRegistryState>> {
    recorded_state_with(&database.migration_config, database, package).await
}

async fn recorded_state_with(
    config: &registry_breg::postgres::ConnectionConfig,
    database: &TestDatabase,
    package: &VerifiedPackage,
) -> registry_breg::migration::Result<Option<RecordedRegistryState>> {
    read_recorded_registry_state(
        config,
        &package.manifest().package_id,
        &database.migration_role,
        ApplyTimeouts::new(Duration::from_secs(1), Duration::from_secs(5))
            .expect("test timeouts are bounded"),
    )
    .await
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

/// Reconciliation executes a maintenance transition, so its request entry must
/// be accepted before that transition runs. A writer that refuses the request
/// entry leaves the pinned target, the ledger, and the journal as they were,
/// and a later writer can still revert the same target.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_reconciliation_changes_nothing_when_the_audit_writer_refuses_its_request_entry(
) {
    let database = TestDatabase::create(1).await;
    database
        .admin
        .batch_execute("CREATE EXTENSION btree_gist")
        .await
        .expect("administrator installs extension");
    let base = compile_variant(Variant::Base);
    let fingerprint = initial_fingerprint(&database, &base).await;
    let initial = prepare_and_load_initial(&base, &fingerprint);
    let active = apply(&database, &initial, ApplyPrecondition::InitialActivation)
        .await
        .expect("refusal scenario initial package activates");
    seed_backfill_rows(&database, &base, 5).await;
    let required = compile_variant(Variant::RankRequired);
    let target_fingerprint = required_target_fingerprint(&database, &required).await;
    let package = prepare_and_load_reviewed(
        &active,
        &base,
        Variant::RankRequired,
        &target_fingerprint,
        backfill_source(BackfillSourceRequest {
            id: "reconcile-refused-request",
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
    database.audit_capture().fail_after(0);
    assert_eq!(
        reconcile(&database, &package, &active, &base, true)
            .await
            .expect_err("a refused request entry stops the revert"),
        ReconcileError::Unavailable
    );
    assert_eq!(durable_snapshot(&database).await, before);
    assert_non_ready_target(&database, &active, &package, "failed").await;

    database.audit_capture().restore();
    let reverted = reconcile(&database, &package, &active, &base, true)
        .await
        .expect("a later writer reverts the same target");
    assert!(reverted.executed);
    assert_ready_target(&database, &active).await;
    assert_reconcile_audit_is_minimized(&database, "reverted").await;
    database.cleanup().await;
}

/// Another session holding the exclusive migration lock is an apply in
/// progress, not an unreachable database. Assessment reports it as the
/// `in_progress` outcome, execution refuses with that outcome instead of
/// reporting success, and the lock-free read of the recorded activation still
/// answers while the lock is held. Nothing changes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_reconciliation_reports_a_held_migration_lock_as_in_progress() {
    let database = TestDatabase::create(1).await;
    database
        .admin
        .batch_execute("CREATE EXTENSION btree_gist")
        .await
        .expect("administrator installs extension");
    let base = compile_variant(Variant::Base);
    let fingerprint = initial_fingerprint(&database, &base).await;
    let initial = prepare_and_load_initial(&base, &fingerprint);
    let active = apply(&database, &initial, ApplyPrecondition::InitialActivation)
        .await
        .expect("in-progress scenario initial package activates");
    seed_backfill_rows(&database, &base, 5).await;
    let required = compile_variant(Variant::RankRequired);
    let target_fingerprint = required_target_fingerprint(&database, &required).await;
    let package = prepare_and_load_reviewed(
        &active,
        &base,
        Variant::RankRequired,
        &target_fingerprint,
        backfill_source(BackfillSourceRequest {
            id: "reconcile-in-progress",
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

    let lock_key = registry_breg::postgres::RegistryLockKey::derive(&package.manifest().package_id)
        .expect("package lock key derives");
    let (holder, holder_task) = database.connect_admin().await;
    holder
        .execute("SELECT pg_catalog.pg_advisory_lock($1)", &[&lock_key.get()])
        .await
        .expect("another session holds the migration lock");

    let status = read_activation_status(
        &database.migration_config,
        &database.migration_role,
        ApplyTimeouts::new(Duration::from_secs(1), Duration::from_secs(5))
            .expect("test timeouts are bounded"),
    )
    .await
    .expect("the lock-free read answers while the lock is held")
    .expect("the database records an activation");
    assert_eq!(status.identity, active);
    assert_eq!(status.maintenance_status, "failed");

    let assessed = reconcile(&database, &package, &active, &base, false)
        .await
        .expect("assessment reports the held lock as an outcome");
    assert_eq!(assessed.outcome, ReconcileOutcome::InProgress);
    assert!(!assessed.executed);
    assert_eq!(
        reconcile(&database, &package, &active, &base, true)
            .await
            .expect_err("execution refuses while another session holds the lock"),
        ReconcileError::NotExecutable(ReconcileOutcome::InProgress)
    );

    holder
        .execute(
            "SELECT pg_catalog.pg_advisory_unlock($1)",
            &[&lock_key.get()],
        )
        .await
        .expect("the other session releases the migration lock");
    holder_task.abort();
    assert_eq!(durable_snapshot(&database).await, before);
    assert_non_ready_target(&database, &active, &package, "failed").await;
    database.cleanup().await;
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
    let base = compile_variant(Variant::Base);
    let fingerprint = initial_fingerprint(&database, &base).await;
    let initial = prepare_and_load_initial(&base, &fingerprint);
    let active = apply(&database, &initial, ApplyPrecondition::InitialActivation)
        .await
        .expect("reconciliation scenario initial package activates");
    seed_backfill_rows(&database, &base, 5).await;
    let required = compile_variant(Variant::RankRequired);
    let target_fingerprint = required_target_fingerprint(&database, &required).await;
    let package = prepare_and_load_reviewed(
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

    let before_refusal = durable_snapshot(&database).await;
    database.audit_capture().fail_after(0);
    assert_eq!(
        reconcile(&database, &package, &active, &base, true)
            .await
            .expect_err("a refused request entry stops the completion"),
        ReconcileError::Unavailable
    );
    assert_eq!(durable_snapshot(&database).await, before_refusal);
    database.audit_capture().restore();

    // A transition that fails after its request entry answers that entry
    // with a failed response under the same correlation.
    database
        .admin
        .batch_execute(
            "BEGIN; SELECT 1 FROM registry_internal.registry_state WHERE singleton FOR UPDATE",
        )
        .await
        .expect("administrator holds the Registry state row");
    let entries_before = database.audit_entries().len();
    reconcile(&database, &package, &active, &base, true)
        .await
        .expect_err("the activation cannot take the held Registry state row");
    database
        .admin
        .batch_execute("ROLLBACK")
        .await
        .expect("administrator releases the Registry state row");
    let failed = database.audit_entries().split_off(entries_before);
    assert_eq!(
        failed
            .iter()
            .map(|entry| (
                entry["phase"].as_str().expect("phase"),
                entry["record"]["outcome"].as_str().expect("outcome")
            ))
            .collect::<Vec<_>>(),
        [("request", "started"), ("response", "failed")],
        "{failed:?}"
    );
    assert_eq!(failed[0]["correlation"], failed[1]["correlation"]);
    assert!(!failed[1].to_string().contains(RECONCILE_OPERATOR_CANARY));

    let completed = reconcile(&database, &package, &active, &base, true)
        .await
        .expect("the missing activation transition completes");
    assert_eq!(completed.outcome, ReconcileOutcome::Completable);
    assert!(completed.executed);
    let mut target = target_identity(&package);
    target.activation_id = activation_at(&database, 2).await;
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
    let base = compile_variant(Variant::Base);
    let fingerprint = initial_fingerprint(&database, &base).await;
    let initial = prepare_and_load_initial(&base, &fingerprint);
    let active = apply(&database, &initial, ApplyPrecondition::InitialActivation)
        .await
        .expect("revert scenario initial package activates");
    seed_backfill_rows(&database, &base, 5).await;
    let required = compile_variant(Variant::RankRequired);
    let target_fingerprint = required_target_fingerprint(&database, &required).await;
    let abandoned = prepare_and_load_reviewed(
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
            .find(|entry| entry.0 == abandoned.package_digest())
            .map(|entry| entry.2.clone()),
        Some("reverted".to_owned()),
        "an abandoned target closes as reverted, freeing its digest"
    );
    assert_reconcile_audit_is_minimized(&database, "reverted").await;

    let successor = prepare_and_load_reviewed(
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
    let base = compile_variant(Variant::Base);
    let fingerprint = initial_fingerprint(&database, &base).await;
    let initial = prepare_and_load_initial(&base, &fingerprint);
    let active = apply(&database, &initial, ApplyPrecondition::InitialActivation)
        .await
        .expect("assessment scenario initial package activates");
    seed_backfill_rows(&database, &base, 5).await;
    let required = compile_variant(Variant::RankRequired);
    let target_fingerprint = required_target_fingerprint(&database, &required).await;
    let package = prepare_and_load_reviewed(
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

    let base = compile_variant(Variant::Base);
    let initial_fingerprint = initial_fingerprint(&database, &base).await;
    let initial = prepare_and_load_initial(&base, &initial_fingerprint);
    let active = apply(&database, &initial, ApplyPrecondition::InitialActivation)
        .await
        .expect("added required field scenario activates its initial package");
    seed_backfill_rows(&database, &base, 5).await;

    let candidate = compile_variant(Variant::BatchAddedRequired);
    let change_set =
        compiled_registry_change_set(&base, &candidate, &active.package_digest).changes;
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

/// Every activation is one ledger row keyed by its own activation id, in the
/// database's apply order. The registry state names the active package digest
/// and the activation that made it active, and carries the physical claim the
/// initial activation recorded; no separate claim table exists.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_each_activation_is_one_ledger_row_in_apply_order() {
    let database = TestDatabase::create(1).await;
    database
        .admin
        .batch_execute("CREATE EXTENSION btree_gist")
        .await
        .expect("administrator installs the required extension");
    let base = compile_variant(Variant::Base);
    let initial_fingerprint = initial_fingerprint(&database, &base).await;
    let initial = prepare_and_load_initial(&base, &initial_fingerprint);
    let active = apply(&database, &initial, ApplyPrecondition::InitialActivation)
        .await
        .expect("the initial package activates");
    assert_eq!(active.package_digest, initial.package_digest());
    let initial_activation =
        Uuid::parse_str(&active.activation_id).expect("the activation id is a UUID");

    let candidate = compile_variant(Variant::BatchAddedRequired);
    let target_fingerprint = added_required_target_fingerprint(&database, &candidate).await;
    let source = added_required_source(
        "add-required-ledger",
        &active,
        &base,
        &candidate,
        &target_fingerprint,
        0,
    );
    let package = prepare_and_load_reviewed(
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
    .expect("the successor activates");
    let successor_activation =
        Uuid::parse_str(&activated.activation_id).expect("the activation id is a UUID");
    assert_ne!(initial_activation, successor_activation);

    let rows = database
        .admin
        .query(
            "SELECT activation_id, apply_order, package_digest, predecessor_package_digest,
                    registry_revision, plan_kind, migration_kind, outcome, role_mode,
                    runtime_role, operator_reference_hash, backup_references, applied_at IS NOT NULL
             FROM registry_internal.registry_migrations
             ORDER BY apply_order",
            &[],
        )
        .await
        .expect("the ledger reads");
    assert_eq!(rows.len(), 2);
    let expected = [
        (
            initial_activation,
            1_i64,
            initial.package_digest(),
            None,
            initial.registry().revision(),
            "initial",
            "compiled_additive",
        ),
        (
            successor_activation,
            2_i64,
            package.package_digest(),
            Some(initial.package_digest()),
            package.registry().revision(),
            "successor",
            "reviewed",
        ),
    ];
    for (row, expected) in rows.iter().zip(expected) {
        assert_eq!(row.get::<_, Uuid>(0), expected.0);
        assert_eq!(row.get::<_, i64>(1), expected.1);
        assert_eq!(row.get::<_, String>(2), expected.2);
        assert_eq!(row.get::<_, Option<String>>(3).as_deref(), expected.3);
        assert_eq!(row.get::<_, String>(4), expected.4);
        assert_eq!(row.get::<_, String>(5), expected.5);
        assert_eq!(row.get::<_, String>(6), expected.6);
        assert_eq!(row.get::<_, String>(7), "applied");
        assert_eq!(row.get::<_, String>(8), "split");
        assert_eq!(row.get::<_, String>(9), database.runtime_role.as_str());
        assert_eq!(row.get::<_, Option<String>>(10), None);
        assert_eq!(row.get::<_, serde_json::Value>(11), serde_json::json!([]));
        assert!(row.get::<_, bool>(12));
    }

    let state = database
        .admin
        .query_one(
            "SELECT active_package_digest, active_activation_id, schema_fingerprint,
                    maintenance_status, maintenance_target_package_digest,
                    database_oid IS NOT NULL, epoch
             FROM registry_internal.registry_state WHERE singleton",
            &[],
        )
        .await
        .expect("the registry state reads");
    assert_eq!(state.get::<_, String>(0), package.package_digest());
    assert_eq!(state.get::<_, Uuid>(1), successor_activation);
    assert_eq!(state.get::<_, String>(2), target_fingerprint);
    assert_eq!(state.get::<_, String>(3), "ready");
    assert_eq!(state.get::<_, Option<String>>(4), None);
    assert!(
        state.get::<_, bool>(5),
        "the initial activation records the claim"
    );
    assert_eq!(state.get::<_, i64>(6), 1);
    let claim_table: Option<String> = database
        .admin
        .query_one(
            "SELECT pg_catalog.to_regclass('registry_internal.registry_instance_claim')::text",
            &[],
        )
        .await
        .expect("the catalog reads")
        .get(0);
    assert_eq!(claim_table, None);

    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_an_operator_reference_is_recorded_only_as_its_keyed_hash() {
    const REFERENCE: &str = "change ticket that must not reach the ledger";
    let (database, initial) = initial_package_database().await;
    let active = apply_verified_package(
        request(&database, &initial, ApplyPrecondition::InitialActivation)
            .with_operator_reference(REFERENCE),
    )
    .await
    .expect("the initial package activates with an operator reference");

    let row = database
        .admin
        .query_one(
            "SELECT operator_reference_hash, row_to_json(migration)::text
             FROM registry_internal.registry_migrations AS migration
             WHERE activation_id = $1::text::uuid",
            &[&active.activation_id],
        )
        .await
        .expect("the activation's ledger row reads");
    let expected = AuditProfile::production_from_secret_bytes(vec![7; 32].into())
        .expect("the activation audit key is valid")
        .key_hasher()
        .audit_reference_hash(
            "breg-activation-operator-reference-v1",
            &active.activation_id,
            REFERENCE,
        )
        .expect("the reference hashes");
    assert_eq!(row.get::<_, Option<String>>(0), Some(expected));
    assert!(!row.get::<_, String>(1).contains(REFERENCE));
}

/// A retry resumes the activation its first attempt recorded. The retry
/// must serve with the roles that activation records, or the ledger would
/// name roles the registry does not serve with; its operator reference is
/// the one the ledger keeps, as the audit of the attempt that applies it does.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_a_resumed_activation_keeps_its_roles_and_records_its_operator_reference() {
    const FIRST: &str = "change ticket of the interrupted attempt";
    const RESUMED: &str = "change ticket of the resumed attempt";
    let database = TestDatabase::create(1).await;
    database
        .admin
        .batch_execute("CREATE EXTENSION btree_gist")
        .await
        .expect("administrator installs extension");
    let base = compile_variant(Variant::Base);
    let fingerprint = initial_fingerprint(&database, &base).await;
    let initial = prepare_and_load_initial(&base, &fingerprint);
    let active = apply(&database, &initial, ApplyPrecondition::InitialActivation)
        .await
        .expect("the initial package activates in split mode");
    seed_backfill_rows(&database, &base, 5).await;
    let required = compile_variant(Variant::RankRequired);
    let target_fingerprint = required_target_fingerprint(&database, &required).await;
    let package = prepare_and_load_reviewed(
        &active,
        &base,
        Variant::RankRequired,
        &target_fingerprint,
        backfill_source(BackfillSourceRequest {
            id: "resumed-roles",
            current: &active,
            prior: &base,
            candidate: &required,
            final_fingerprint: &target_fingerprint,
            pre: AssertionMode::True,
            post: AssertionMode::True,
            rehearsed_rows: 5,
        }),
    );
    let interrupted = apply_verified_package(
        request(
            &database,
            &package,
            ApplyPrecondition::Successor { current: &active },
        )
        .with_operator_reference(FIRST)
        .with_fault_for_test(ReviewedMigrationFaultPoint::AfterCommittedChunk(1)),
    )
    .await;
    assert_value_free(interrupted.err(), MigrationError::ApplyFailed);
    let interrupted_activation = activation_at(&database, 2).await;

    let other_roles = apply_verified_package(ApplyVerifiedPackageRequest::new(
        &database.migration_config,
        &package,
        deployment(),
        ApplyPrecondition::Successor { current: &active },
        ApplyRoles::new(&database.migration_role, &database.migration_role),
        ApplyTimeouts::new(Duration::from_secs(1), Duration::from_secs(5))
            .expect("test timeouts are bounded"),
        database.activation_audit(),
    ))
    .await
    .expect_err("a retry with other roles does not resume the activation");
    assert_eq!(
        other_roles,
        MigrationError::ResumeRolesDiffer {
            role_mode: "split".to_owned(),
            runtime_role: database.runtime_role.as_str().to_owned(),
        }
    );
    assert!(other_roles
        .to_string()
        .contains("rerun the apply with the database roles it started with"));

    let resumed = apply_verified_package(
        request(
            &database,
            &package,
            ApplyPrecondition::Successor { current: &active },
        )
        .with_operator_reference(RESUMED),
    )
    .await
    .expect("the retry with the recorded roles resumes the activation");
    assert_eq!(resumed.activation_id, interrupted_activation);
    let row = database
        .admin
        .query_one(
            "SELECT operator_reference_hash, role_mode, runtime_role
             FROM registry_internal.registry_migrations
             WHERE activation_id = $1::text::uuid AND outcome = 'applied'",
            &[&interrupted_activation],
        )
        .await
        .expect("the resumed activation's ledger row reads");
    let applied_audit = activation_audit_records(&database, &interrupted_activation);
    let applied_response = applied_audit
        .iter()
        .rev()
        .find(|(phase, record)| phase == "response" && record["outcome"] == "applied")
        .expect("the resumed attempt audits its applied response");
    let resumed_hash = AuditProfile::production_from_secret_bytes(vec![7; 32].into())
        .expect("the activation audit key is valid")
        .key_hasher()
        .audit_reference_hash(
            "breg-activation-operator-reference-v1",
            &interrupted_activation,
            RESUMED,
        )
        .expect("the reference hashes");
    assert_eq!(row.get::<_, Option<String>>(0), Some(resumed_hash.clone()));
    assert_eq!(applied_response.1["operatorReference"], resumed_hash);
    assert_eq!(row.get::<_, String>(1), "split");
    assert_eq!(row.get::<_, String>(2), database.runtime_role.as_str());
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_a_refused_operator_reference_leaves_the_database_unactivated() {
    let (database, initial) = initial_package_database().await;
    let too_long = "r".repeat(513);
    for (reference, audit) in [
        ("", database.activation_audit()),
        (too_long.as_str(), database.activation_audit()),
        ("line one\nline two", database.activation_audit()),
        (
            "change-1",
            database
                .activation_audit_capture()
                .audit(AuditProfile::unkeyed_dev_only()),
        ),
    ] {
        let refused = apply_verified_package(
            ApplyVerifiedPackageRequest::new(
                &database.migration_config,
                &initial,
                deployment(),
                ApplyPrecondition::InitialActivation,
                ApplyRoles::new(&database.migration_role, &database.runtime_role),
                ApplyTimeouts::new(Duration::from_secs(1), Duration::from_secs(5))
                    .expect("test timeouts are bounded"),
                audit,
            )
            .with_operator_reference(reference),
        )
        .await
        .expect_err("the operator reference is refused");
        assert!(matches!(refused, MigrationError::OperatorReference));
    }
    let ledger = database
        .admin
        .query_one(
            "SELECT to_regclass('registry_internal.registry_migrations') IS NULL",
            &[],
        )
        .await
        .expect("the catalog reads");
    assert!(
        ledger.get::<_, bool>(0),
        "no refused apply creates the ledger"
    );
    assert!(database.activation_audit_entries().is_empty());
}

/// Each activation records its request before the terminal work and its
/// applied response once the activation commits, both under its activation
/// id. The operator's reference appears only as its keyed hash.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_each_activation_audits_its_request_and_its_applied_response() {
    const REFERENCE: &str = "change ticket that must not reach the activation audit";
    let (database, package) = initial_package_database().await;
    let initial = apply_verified_package(
        request(&database, &package, ApplyPrecondition::InitialActivation)
            .with_operator_reference(REFERENCE),
    )
    .await
    .expect("the initial package activates with an operator reference");
    let single = apply_verified_package(ApplyVerifiedPackageRequest::new(
        &database.migration_config,
        &package,
        deployment(),
        ApplyPrecondition::RoleChange { current: &initial },
        ApplyRoles::new(&database.migration_role, &database.migration_role),
        ApplyTimeouts::new(Duration::from_secs(1), Duration::from_secs(5))
            .expect("test timeouts are bounded"),
        database.activation_audit(),
    ))
    .await
    .expect("serving with one role is its own activation");

    let reference_hash = AuditProfile::production_from_secret_bytes(vec![7; 32].into())
        .expect("the activation audit key is valid")
        .key_hasher()
        .audit_reference_hash(
            "breg-activation-operator-reference-v1",
            &initial.activation_id,
            REFERENCE,
        )
        .expect("the reference hashes");
    let initial_record = serde_json::json!({
        "operationId": "breg.activation",
        "activationId": initial.activation_id,
        "priorActivationId": null,
        "packageDigest": package.package_digest(),
        "predecessorPackageDigest": null,
        "registryRevision": package.registry().revision(),
        "planKind": "initial",
        "databaseId": DATABASE,
        "environment": ENVIRONMENT,
        "instanceId": INSTANCE,
        "roleMode": "split",
        "operatorReference": reference_hash,
    });
    assert_eq!(
        activation_audit_records(&database, &initial.activation_id),
        vec![
            (
                "request".to_owned(),
                with_outcome(&initial_record, "attempt", "started")
            ),
            (
                "response".to_owned(),
                with_outcome(&initial_record, "terminal", "applied")
            ),
        ]
    );
    let single_record = serde_json::json!({
        "operationId": "breg.activation",
        "activationId": single.activation_id,
        "priorActivationId": initial.activation_id,
        "packageDigest": package.package_digest(),
        "predecessorPackageDigest": package.package_digest(),
        "registryRevision": package.registry().revision(),
        "planKind": "successor",
        "databaseId": DATABASE,
        "environment": ENVIRONMENT,
        "instanceId": INSTANCE,
        "roleMode": "single",
        "operatorReference": null,
    });
    assert_eq!(
        activation_audit_records(&database, &single.activation_id),
        vec![
            (
                "request".to_owned(),
                with_outcome(&single_record, "attempt", "started")
            ),
            (
                "response".to_owned(),
                with_outcome(&single_record, "terminal", "applied")
            ),
        ]
    );
    let journal = serde_json::to_string(&database.activation_audit_entries())
        .expect("the journal serializes");
    assert!(!journal.contains(REFERENCE));
    database.cleanup().await;
}

/// An activation that fails after its request was recorded answers it with
/// the failed outcome once the durable state shows the target failed, and
/// one interrupted mid-plan leaves it unfinished.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_a_failed_activation_audits_its_failed_response() {
    let database = TestDatabase::create(1).await;
    database
        .admin
        .batch_execute("CREATE EXTENSION btree_gist")
        .await
        .expect("administrator installs extension");
    let base = compile_variant(Variant::Base);
    let fingerprint = initial_fingerprint(&database, &base).await;
    let initial = prepare_and_load_initial(&base, &fingerprint);
    let active = apply(&database, &initial, ApplyPrecondition::InitialActivation)
        .await
        .expect("the initial package activates");
    seed_backfill_rows(&database, &base, 5).await;
    let required = compile_variant(Variant::RankRequired);
    let target_fingerprint = required_target_fingerprint(&database, &required).await;
    let package = prepare_and_load_reviewed(
        &active,
        &base,
        Variant::RankRequired,
        &target_fingerprint,
        backfill_source(BackfillSourceRequest {
            id: "audited-failure",
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
    assert_non_ready_target(&database, &active, &package, "failed").await;

    let failed = activation_at(&database, 2).await;
    let records = activation_audit_records(&database, &failed);
    assert_eq!(records.len(), 2, "{records:?}");
    assert_eq!(records[0].0, "request");
    assert_eq!(records[0].1["outcome"], "started");
    assert_eq!(records[0].1["priorActivationId"], active.activation_id);
    assert_eq!(records[0].1["packageDigest"], package.package_digest());
    assert_eq!(
        records[0].1["predecessorPackageDigest"],
        active.package_digest
    );
    assert_eq!(records[1].0, "response");
    assert_eq!(
        records[1].1,
        with_outcome(&records[0].1, "terminal", "failed")
    );
    database.cleanup().await;
}

/// The request entry is written before any activation state: an audit that
/// refuses it leaves the database exactly as the apply found it and names
/// the refusal, not a failed activation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_a_refused_activation_request_entry_changes_nothing() {
    let (database, package) = initial_package_database().await;
    database.activation_audit_capture().fail_after(0);
    let refused = apply(&database, &package, ApplyPrecondition::InitialActivation)
        .await
        .expect_err("the refused request entry stops the initial activation");
    assert_eq!(refused, MigrationError::ActivationAuditUnavailable);
    let ledger = database
        .admin
        .query_one(
            "SELECT to_regclass('registry_internal.registry_state') IS NULL",
            &[],
        )
        .await
        .expect("the catalog reads");
    assert!(ledger.get::<_, bool>(0), "no registry state was created");
    assert!(database.activation_audit_entries().is_empty());

    database.activation_audit_capture().restore();
    let active = apply(&database, &package, ApplyPrecondition::InitialActivation)
        .await
        .expect("a later writer activates the same package");
    let before = durable_snapshot(&database).await;
    database.activation_audit_capture().fail_after(0);
    let refused = apply_verified_package(ApplyVerifiedPackageRequest::new(
        &database.migration_config,
        &package,
        deployment(),
        ApplyPrecondition::RoleChange { current: &active },
        ApplyRoles::new(&database.migration_role, &database.migration_role),
        ApplyTimeouts::new(Duration::from_secs(1), Duration::from_secs(5))
            .expect("test timeouts are bounded"),
        database.activation_audit(),
    ))
    .await
    .expect_err("the refused request entry stops the role change");
    assert_eq!(refused, MigrationError::ActivationAuditUnavailable);
    assert_eq!(durable_snapshot(&database).await, before);
    assert_ready_target(&database, &active).await;
    database.cleanup().await;
}

/// The activation audit entries recorded under one activation id, oldest
/// first, as their envelope phase and record.
fn activation_audit_records(
    database: &TestDatabase,
    activation_id: &str,
) -> Vec<(String, serde_json::Value)> {
    database
        .activation_audit_entries()
        .into_iter()
        .filter(|entry| {
            entry["schema"] == "breg-activation-audit/v1" && entry["correlation"] == activation_id
        })
        .map(|mut entry| {
            let phase = entry["phase"]
                .as_str()
                .expect("an entry has a phase")
                .to_owned();
            (phase, entry["record"].take())
        })
        .collect()
}

fn with_outcome(record: &serde_json::Value, phase: &str, outcome: &str) -> serde_json::Value {
    let mut record = record.clone();
    record["phase"] = phase.into();
    record["outcome"] = outcome.into();
    record
}

/// A role change whose activation fails keeps serving with the role the
/// ledger still names: the runtime grants it reconciles and the retirement
/// of the old runtime role commit with the activation or not at all.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_a_failed_role_change_activation_keeps_the_serving_runtime_grants() {
    let (database, package) = initial_package_database().await;
    let initial = apply(&database, &package, ApplyPrecondition::InitialActivation)
        .await
        .expect("the initial package activates in split mode");
    let runtime = database.runtime_role.as_str();
    let granted = retired_role_privileges(&database, runtime).await;
    assert!(granted > 0, "the split runtime role holds its grants");
    let table = first_model_table(&database).await;
    // The closed catalog check the activation runs refuses a trigger no
    // compiled migration creates, after the grants are reconciled.
    database
        .admin
        .batch_execute(&format!(
            "CREATE FUNCTION public.refuse_activation() RETURNS trigger LANGUAGE plpgsql \
             AS 'BEGIN RETURN NEW; END'; \
             CREATE TRIGGER refuse_activation BEFORE INSERT ON {table} \
             FOR EACH ROW EXECUTE FUNCTION public.refuse_activation()"
        ))
        .await
        .expect("the administrator adds a foreign trigger");

    let refused = apply_verified_package(ApplyVerifiedPackageRequest::new(
        &database.migration_config,
        &package,
        deployment(),
        ApplyPrecondition::RoleChange { current: &initial },
        ApplyRoles::new(&database.migration_role, &database.migration_role),
        ApplyTimeouts::new(Duration::from_secs(1), Duration::from_secs(5))
            .expect("test timeouts are bounded"),
        database.activation_audit(),
    ))
    .await
    .expect_err("the activation refuses the foreign trigger");
    assert_eq!(refused, MigrationError::ApplyFailed);

    assert_eq!(
        retired_role_privileges(&database, runtime).await,
        granted,
        "the runtime role the ledger still names keeps every grant"
    );
    let applied = ledger_roles(&database)
        .await
        .into_iter()
        .filter(|row| row.0 == initial.activation_id)
        .collect::<Vec<_>>();
    assert_eq!(applied.len(), 1);
    assert_eq!(applied[0].5, runtime);
    database.cleanup().await;
}

/// A role change refused before it enters maintenance leaves the runtime
/// role it would have served with no grant, so the registry keeps the exact
/// catalog its serving roles verify.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_a_role_change_refused_before_maintenance_grants_the_new_runtime_role_nothing(
) {
    let (database, package) = initial_package_database().await;
    let single = apply_verified_package(ApplyVerifiedPackageRequest::new(
        &database.migration_config,
        &package,
        deployment(),
        ApplyPrecondition::InitialActivation,
        ApplyRoles::new(&database.migration_role, &database.migration_role),
        ApplyTimeouts::new(Duration::from_secs(1), Duration::from_secs(5))
            .expect("test timeouts are bounded"),
        database.activation_audit(),
    ))
    .await
    .expect("the initial package activates with one role");
    let runtime = database.runtime_role.as_str();
    assert_eq!(retired_role_privileges(&database, runtime).await, 0);
    // The successor begin refuses an unready history coverage before its
    // first write.
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_commit_head
                SET coverage_ready = false
              WHERE singleton",
            &[],
        )
        .await
        .expect("administrator marks history coverage unready");

    let refused = apply(
        &database,
        &package,
        ApplyPrecondition::RoleChange { current: &single },
    )
    .await
    .expect_err("the role change refuses the unready coverage");
    assert_eq!(refused, MigrationError::HistoryCoverage);

    assert_eq!(
        retired_role_privileges(&database, runtime).await,
        0,
        "the runtime role the refused activation would have served with holds nothing"
    );
    let applied = ledger_roles(&database)
        .await
        .into_iter()
        .filter(|row| row.0 == single.activation_id)
        .collect::<Vec<_>>();
    assert_eq!(applied.len(), 1);
    assert_eq!(applied[0].4, "single");
    database.cleanup().await;
}

/// A role change still activates when the runtime role the ledger names no
/// longer exists under that name, as after an administrator renames it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_a_role_change_activates_when_the_recorded_runtime_role_is_gone() {
    let (database, package) = initial_package_database().await;
    let initial = apply(&database, &package, ApplyPrecondition::InitialActivation)
        .await
        .expect("the initial package activates in split mode");
    let recorded = database.runtime_role.as_str();
    let renamed = registry_breg::postgres::SqlIdentifier::parse(&format!("{recorded}_renamed"))
        .expect("the renamed runtime role is an identifier");
    database
        .admin
        .batch_execute(&format!(
            "ALTER ROLE \"{recorded}\" RENAME TO \"{}\"",
            renamed.as_str()
        ))
        .await
        .expect("administrator renames the runtime role");

    let changed = apply_verified_package(ApplyVerifiedPackageRequest::new(
        &database.migration_config,
        &package,
        deployment(),
        ApplyPrecondition::RoleChange { current: &initial },
        ApplyRoles::new(&database.migration_role, &renamed),
        ApplyTimeouts::new(Duration::from_secs(1), Duration::from_secs(5))
            .expect("test timeouts are bounded"),
        database.activation_audit(),
    ))
    .await;

    database
        .admin
        .batch_execute(&format!(
            "ALTER ROLE \"{}\" RENAME TO \"{recorded}\"",
            renamed.as_str()
        ))
        .await
        .expect("administrator restores the runtime role name");
    let changed = changed.expect("the role change activates under the renamed role");
    assert_ne!(changed.activation_id, initial.activation_id);
    let rows = ledger_roles(&database).await;
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[1].5, renamed.as_str());
    database.cleanup().await;
}

/// A successor serves with the roles the active activation records. Only a
/// role change retires a recorded runtime role, so a successor configured
/// with other roles is refused before maintenance, and the registry stays
/// active for the same successor applied with the recorded roles.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_a_successor_with_other_roles_is_refused_before_maintenance() {
    let database = TestDatabase::create(1).await;
    database
        .admin
        .batch_execute("CREATE EXTENSION btree_gist")
        .await
        .expect("administrator installs the required extension");
    let base = compile_variant(Variant::Base);
    let base_fingerprint = initial_fingerprint(&database, &base).await;
    let added = compile_variant(Variant::PatternAdded);
    let added_fingerprint = initial_fingerprint(&database, &added).await;
    let active = apply(
        &database,
        &prepare_and_load_initial(&base, &base_fingerprint),
        ApplyPrecondition::InitialActivation,
    )
    .await
    .expect("the initial package activates in split mode");
    let successor = publish_and_load(
        prepare_package(build_request(
            Variant::PatternAdded,
            Some(&active.package_digest),
            &added_fingerprint,
            PackageMigrationPlanInput::Successor {
                prior_registry: Box::new(base.clone()),
            },
        ))
        .expect("successor package prepares"),
        local_context(),
    );

    let refused = apply_verified_package(ApplyVerifiedPackageRequest::new(
        &database.migration_config,
        &successor,
        deployment(),
        ApplyPrecondition::Successor { current: &active },
        ApplyRoles::new(&database.migration_role, &database.migration_role),
        ApplyTimeouts::new(Duration::from_secs(1), Duration::from_secs(5))
            .expect("test timeouts are bounded"),
        database.activation_audit(),
    ))
    .await
    .expect_err("a successor with other roles is refused");
    assert_eq!(
        refused,
        MigrationError::SuccessorRolesDiffer {
            role_mode: "split".to_owned(),
            runtime_role: database.runtime_role.as_str().to_owned(),
        }
    );
    assert!(refused
        .to_string()
        .contains("apply the active package with the new roles first"));
    let activations: i64 = database
        .admin
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_migrations",
            &[],
        )
        .await
        .expect("administrator reads the ledger")
        .get(0);
    assert_eq!(activations, 1, "the refusal records no activation");

    apply(
        &database,
        &successor,
        ApplyPrecondition::Successor { current: &active },
    )
    .await
    .expect("the successor with the recorded roles activates");
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_a_role_change_reapply_of_the_active_package_is_its_own_activation() {
    let (database, package) = initial_package_database().await;
    let initial = apply(&database, &package, ApplyPrecondition::InitialActivation)
        .await
        .expect("the initial package activates in split mode");

    let unchanged = apply(
        &database,
        &package,
        ApplyPrecondition::RoleChange { current: &initial },
    )
    .await
    .expect_err("the same roles leave nothing to activate");
    assert!(matches!(unchanged, MigrationError::AlreadyActive));
    assert_eq!(ledger_roles(&database).await.len(), 1);

    let single = apply_verified_package(ApplyVerifiedPackageRequest::new(
        &database.migration_config,
        &package,
        deployment(),
        ApplyPrecondition::RoleChange { current: &initial },
        ApplyRoles::new(&database.migration_role, &database.migration_role),
        ApplyTimeouts::new(Duration::from_secs(1), Duration::from_secs(5))
            .expect("test timeouts are bounded"),
        database.activation_audit(),
    ))
    .await
    .expect("serving with one role is its own activation");
    assert_eq!(single.package_digest, initial.package_digest);
    assert_ne!(single.activation_id, initial.activation_id);
    assert_eq!(
        retired_role_privileges(&database, database.runtime_role.as_str()).await,
        0,
        "the runtime role the activation retired keeps no privilege"
    );

    let split = apply(
        &database,
        &package,
        ApplyPrecondition::RoleChange { current: &single },
    )
    .await
    .expect("serving with a separate runtime role again is its own activation");
    assert_ne!(split.activation_id, single.activation_id);

    let digest = package.package_digest().to_owned();
    assert_eq!(
        ledger_roles(&database).await,
        vec![
            (
                initial.activation_id.clone(),
                "initial".to_owned(),
                "compiled_additive".to_owned(),
                None,
                "split".to_owned(),
                database.runtime_role.as_str().to_owned(),
            ),
            (
                single.activation_id.clone(),
                "successor".to_owned(),
                "metadata_only".to_owned(),
                Some(digest.clone()),
                "single".to_owned(),
                database.migration_role.as_str().to_owned(),
            ),
            (
                split.activation_id.clone(),
                "successor".to_owned(),
                "metadata_only".to_owned(),
                Some(digest),
                "split".to_owned(),
                database.runtime_role.as_str().to_owned(),
            ),
        ]
    );
    let state = read_recorded_registry_state(
        &database.migration_config,
        &package.manifest().package_id,
        &database.migration_role,
        ApplyTimeouts::new(Duration::from_secs(1), Duration::from_secs(5))
            .expect("test timeouts are bounded"),
    )
    .await
    .expect("the recorded state reads")
    .expect("the database is activated");
    assert_eq!(state.identity, split);
}

/// Threat: a split-role runtime role that owns a registry table can add a
/// deferred constraint trigger that runs as the migration role when an apply
/// commits and writes the activation ledger. Enforcement: split apply refuses
/// that ownership before the registry enters maintenance, naming the
/// reassignment and then the apply that reissues the runtime grants the
/// reassignment strips.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_split_apply_refuses_a_runtime_role_that_owns_a_model_table() {
    let (database, package) = initial_package_database().await;
    let initial = apply(&database, &package, ApplyPrecondition::InitialActivation)
        .await
        .expect("the initial package activates in split mode");
    let table = first_model_table(&database).await;
    let runtime = database.runtime_role.as_str();
    let migration = database.migration_role.as_str();
    database
        .admin
        .batch_execute(&format!("ALTER TABLE {table} OWNER TO {runtime}"))
        .await
        .expect("the administrator hands a model table to the runtime role");
    let before = split_refusal_state(&database).await;

    let refusal = apply(
        &database,
        &package,
        ApplyPrecondition::RoleChange { current: &initial },
    )
    .await
    .expect_err("a runtime role that owns a model table is refused");
    let MigrationError::RuntimeWriteAuthority(finding) = refusal else {
        panic!("ownership is named as runtime write authority: {refusal:?}");
    };
    let message = finding.to_string();
    assert!(message.contains(&format!("TABLE {table}")), "{message}");
    assert!(
        message.contains(&format!("`REASSIGN OWNED BY {runtime} TO {migration}`")),
        "{message}"
    );
    assert!(
        message.ends_with("then `bregctl apply --package DIR` to reissue the runtime grants"),
        "{message}"
    );
    assert_eq!(split_refusal_state(&database).await, before);

    database
        .admin
        .batch_execute(&format!("REASSIGN OWNED BY {runtime} TO {migration}"))
        .await
        .expect("the administrator runs the named reassignment");
    let reissued = apply(
        &database,
        &package,
        ApplyPrecondition::RoleChange { current: &initial },
    )
    .await
    .expect("the apply after the reassignment reissues the runtime grants");
    assert_ne!(reissued.activation_id, initial.activation_id);
    assert!(matches!(
        apply(
            &database,
            &package,
            ApplyPrecondition::RoleChange { current: &reissued },
        )
        .await,
        Err(MigrationError::AlreadyActive)
    ));
    database.cleanup().await;
}

/// Threat: a split-role runtime role that may create objects in a registry
/// schema can add objects apply then runs beside. Enforcement: split apply
/// refuses CREATE on a registry schema whether the runtime role or PUBLIC
/// holds it, naming the exact revoke.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_split_apply_refuses_a_runtime_role_that_holds_schema_create() {
    let (database, package) = initial_package_database().await;
    let initial = apply(&database, &package, ApplyPrecondition::InitialActivation)
        .await
        .expect("the initial package activates in split mode");
    let runtime = database.runtime_role.as_str();
    let before = split_refusal_state(&database).await;

    for (grantee, fix) in [
        (
            runtime.to_owned(),
            format!("`REVOKE CREATE ON SCHEMA registry_data FROM {runtime}`"),
        ),
        (
            "PUBLIC".to_owned(),
            "`REVOKE CREATE ON SCHEMA registry_data FROM PUBLIC`".to_owned(),
        ),
    ] {
        database
            .admin
            .batch_execute(&format!(
                "GRANT CREATE ON SCHEMA registry_data TO {grantee}"
            ))
            .await
            .expect("the administrator grants schema CREATE");
        let refusal = apply(
            &database,
            &package,
            ApplyPrecondition::RoleChange { current: &initial },
        )
        .await
        .expect_err("schema CREATE is refused");
        let MigrationError::RuntimeWriteAuthority(finding) = refusal else {
            panic!("schema CREATE is named as runtime write authority: {refusal:?}");
        };
        let message = finding.to_string();
        assert!(message.contains(&fix), "{message}");
        assert!(
            message.ends_with("then rerun the refused command"),
            "{message}"
        );
        assert_eq!(split_refusal_state(&database).await, before);
        database
            .admin
            .batch_execute(&format!(
                "REVOKE CREATE ON SCHEMA registry_data FROM {grantee}"
            ))
            .await
            .expect("the administrator runs the named revoke");
    }
    assert!(matches!(
        apply(
            &database,
            &package,
            ApplyPrecondition::RoleChange { current: &initial },
        )
        .await,
        Err(MigrationError::AlreadyActive)
    ));
    database.cleanup().await;
}

/// Each remaining way a split-role runtime role could write the activation
/// ledger or the registry state is refused by split apply before maintenance,
/// naming the one statement that removes it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_split_apply_names_the_fix_for_every_runtime_write_authority() {
    let (database, package) = initial_package_database().await;
    let initial = apply(&database, &package, ApplyPrecondition::InitialActivation)
        .await
        .expect("the initial package activates in split mode");
    let table = first_model_table(&database).await;
    let runtime = database.runtime_role.as_str();
    let migration = database.migration_role.as_str();
    let intruder = database.intruder_role.as_str();
    let before = split_refusal_state(&database).await;

    let cases = [
        (
            format!("ALTER ROLE {runtime} SUPERUSER"),
            format!("ALTER ROLE {runtime} NOSUPERUSER"),
            format!("`ALTER ROLE {runtime} NOSUPERUSER`, then rerun the refused command"),
        ),
        (
            format!("GRANT {migration} TO {runtime}"),
            format!("REVOKE {migration} FROM {runtime}"),
            format!("`REVOKE {migration} FROM {runtime}`, then rerun the refused command"),
        ),
        (
            format!("ALTER ROLE {intruder} SUPERUSER; GRANT {intruder} TO {runtime}"),
            format!("REVOKE {intruder} FROM {runtime}; ALTER ROLE {intruder} NOSUPERUSER"),
            format!("`REVOKE {intruder} FROM {runtime}`, then rerun the refused command"),
        ),
        (
            format!("GRANT pg_write_all_data TO {runtime}"),
            format!("REVOKE pg_write_all_data FROM {runtime}"),
            format!("`REVOKE pg_write_all_data FROM {runtime}`, then rerun the refused command"),
        ),
        (
            format!(
                "CREATE FUNCTION registry_data.foreign_helper() RETURNS integer \
                 LANGUAGE sql AS 'SELECT 1'; \
                 ALTER FUNCTION registry_data.foreign_helper() OWNER TO {runtime}"
            ),
            "DROP FUNCTION registry_data.foreign_helper()".to_owned(),
            format!(
                "FUNCTION registry_data.foreign_helper() and can write the activation ledger \
                 through it; run `REASSIGN OWNED BY {runtime} TO {migration}`, then \
                 `bregctl apply --package DIR` to reissue the runtime grants"
            ),
        ),
        (
            format!("ALTER TABLE {table} OWNER TO {intruder}; GRANT {intruder} TO {runtime}"),
            format!("REVOKE {intruder} FROM {runtime}; ALTER TABLE {table} OWNER TO {migration}"),
            format!("`REVOKE {intruder} FROM {runtime}`, then rerun the refused command"),
        ),
        (
            format!("GRANT INSERT ON registry_internal.registry_migrations TO {runtime}"),
            format!("REVOKE INSERT ON registry_internal.registry_migrations FROM {runtime}"),
            format!(
                "`REVOKE INSERT ON TABLE registry_internal.registry_migrations FROM {runtime}`, \
                 then rerun the refused command"
            ),
        ),
        (
            "GRANT UPDATE ON registry_internal.registry_state TO PUBLIC".to_owned(),
            "REVOKE UPDATE ON registry_internal.registry_state FROM PUBLIC".to_owned(),
            "`REVOKE UPDATE ON TABLE registry_internal.registry_state FROM PUBLIC`, then rerun \
             the refused command"
                .to_owned(),
        ),
        (
            format!(
                "GRANT UPDATE (maintenance_status) ON registry_internal.registry_state TO {runtime}"
            ),
            format!(
                "REVOKE UPDATE (maintenance_status) ON registry_internal.registry_state \
                 FROM {runtime}"
            ),
            format!(
                "`REVOKE UPDATE (maintenance_status) ON TABLE registry_internal.registry_state \
                 FROM {runtime}`, then rerun the refused command"
            ),
        ),
        (
            format!("GRANT TRIGGER ON {table} TO {runtime}"),
            format!("REVOKE TRIGGER ON {table} FROM {runtime}"),
            format!(
                "`REVOKE TRIGGER ON TABLE {table} FROM {runtime}`, then rerun the refused command"
            ),
        ),
        (
            format!(
                "CREATE TABLE registry_data.foreign_partitioned (id integer) \
                 PARTITION BY RANGE (id); \
                 GRANT TRIGGER ON registry_data.foreign_partitioned TO {runtime}"
            ),
            "DROP TABLE registry_data.foreign_partitioned".to_owned(),
            format!(
                "`REVOKE TRIGGER ON TABLE registry_data.foreign_partitioned FROM {runtime}`, \
                 then rerun the refused command"
            ),
        ),
        (
            format!(
                "CREATE FOREIGN DATA WRAPPER foreign_wrapper; \
                 CREATE SERVER foreign_server FOREIGN DATA WRAPPER foreign_wrapper; \
                 CREATE FOREIGN TABLE registry_data.foreign_rows (id integer) \
                 SERVER foreign_server; \
                 GRANT TRIGGER ON registry_data.foreign_rows TO {runtime}"
            ),
            "DROP FOREIGN TABLE registry_data.foreign_rows; \
             DROP SERVER foreign_server; DROP FOREIGN DATA WRAPPER foreign_wrapper"
                .to_owned(),
            format!(
                "`REVOKE TRIGGER ON TABLE registry_data.foreign_rows FROM {runtime}`, \
                 then rerun the refused command"
            ),
        ),
        (
            format!(
                "CREATE FUNCTION public.foreign_trigger() RETURNS trigger LANGUAGE plpgsql \
                 AS 'BEGIN RETURN NEW; END'; \
                 CREATE TRIGGER foreign_trigger BEFORE INSERT ON {table} \
                 FOR EACH ROW EXECUTE FUNCTION public.foreign_trigger()"
            ),
            format!(
                "DROP TRIGGER foreign_trigger ON {table}; DROP FUNCTION public.foreign_trigger()"
            ),
            format!("`DROP TRIGGER foreign_trigger ON {table}`, then rerun the refused command"),
        ),
    ];
    for (grant, undo, fix) in cases {
        database
            .admin
            .batch_execute(&grant)
            .await
            .unwrap_or_else(|error| panic!("the administrator runs {grant}: {error}"));
        let refusal = apply(
            &database,
            &package,
            ApplyPrecondition::RoleChange { current: &initial },
        )
        .await
        .expect_err("runtime write authority is refused");
        let MigrationError::RuntimeWriteAuthority(finding) = refusal else {
            panic!("{grant} is named as runtime write authority: {refusal:?}");
        };
        let message = finding.to_string();
        assert!(message.ends_with(&fix), "{grant}: {message}");
        assert_eq!(split_refusal_state(&database).await, before, "{grant}");
        database
            .admin
            .batch_execute(&undo)
            .await
            .unwrap_or_else(|error| panic!("the administrator runs {undo}: {error}"));
    }
    database.cleanup().await;
}

/// One registry model table, schema-qualified as a fix names it.
async fn first_model_table(database: &TestDatabase) -> String {
    database
        .admin
        .query_one(
            "SELECT format('%I.%I', schemaname, tablename)
             FROM pg_catalog.pg_tables
             WHERE schemaname = 'registry_data'
             ORDER BY tablename
             LIMIT 1",
            &[],
        )
        .await
        .expect("the registry has a model table")
        .get(0)
}

/// What a refused split apply must leave as it was: the ledger rows and the
/// maintenance state.
async fn split_refusal_state(database: &TestDatabase) -> (i64, String) {
    let row = database
        .admin
        .query_one(
            "SELECT (SELECT count(*) FROM registry_internal.registry_migrations),
                    (SELECT maintenance_status FROM registry_internal.registry_state
                      WHERE singleton)",
            &[],
        )
        .await
        .expect("the ledger and state read");
    (row.get(0), row.get(1))
}

/// A registry whose state row records no claim, as one upgraded from a release
/// before the claim does, is claimed by its next activation, so an in-place
/// upgrade starts without an operator adopting the database.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_an_activation_records_the_claim_a_database_has_never_recorded() {
    let (database, active, _, package) = successor_over_an_open_import_authority().await;
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_state
                SET system_identifier = NULL, database_oid = NULL,
                    claimed_at = NULL, epoch = 0
              WHERE singleton",
            &[],
        )
        .await
        .expect("the administrator removes the claim");
    apply(
        &database,
        &package,
        ApplyPrecondition::Successor { current: &active },
    )
    .await
    .expect("the successor activates");
    assert_eq!(
        recorded_claim(&database).await,
        (Some(live_database_oid(&database).await), 1),
        "the activation records the database it ran in as the claim"
    );
}

/// A claim that names another database is kept by every activation: a
/// restored copy stays a copy until an operator adopts it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_an_activation_keeps_a_claim_that_names_another_database() {
    let (database, active, _, package) = successor_over_an_open_import_authority().await;
    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_state
                SET database_oid = 1, epoch = 3
              WHERE singleton",
            &[],
        )
        .await
        .expect("the administrator points the claim at another database");
    apply(
        &database,
        &package,
        ApplyPrecondition::Successor { current: &active },
    )
    .await
    .expect("the successor activates");
    assert_eq!(
        recorded_claim(&database).await,
        (Some(1), 3),
        "the activation leaves the recorded claim in place"
    );
}

/// A field an earlier release encrypted before it adopted a pre-ledger
/// database keeps its erase-history lifecycle: the flip boundary and the
/// originating package of a pre-flip proposal name revisions only the order
/// that adoption kept, and erasure still orders them and scrubs the plaintext
/// the proposal holds.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_erasure_orders_the_revisions_an_adoption_kept() {
    let (database, package) = initial_package_database().await;
    let current = apply(&database, &package, ApplyPrecondition::InitialActivation)
        .await
        .expect("the package the deployed release installed activates");
    let request_id = Uuid::from_u128(0xAD01);
    database
        .admin
        .execute(
            "INSERT INTO registry_internal.registry_request_state
                 (request_entity_id, request_id, owner_reference, state,
                  proposal_version, workflow_revision)
             VALUES ('asset-request', $1, 'owner:hash', 'cancelled', 1, 1)",
            &[&request_id],
        )
        .await
        .expect("a pre-flip request state inserts");
    database
        .admin
        .execute(
            "INSERT INTO registry_internal.registry_request_proposals
                 (request_entity_id, request_id, proposal_version, request_record_revision,
                  contract_fingerprint, effect_digest, snapshot)
             VALUES ('asset-request', $1, 1, 1, $2, $2, $3)",
            &[
                &request_id,
                &format!("sha256:{}", "7".repeat(64)),
                &serde_json::json!({
                    "originatingPackage": "pre-ledger-origin",
                    "effects": [{
                        "id": "create-asset",
                        "operation": "create",
                        "target": {"kind": "ReservedCreate", "entityId": "asset"},
                        "fieldChanges": [{
                            "field": "code",
                            "before": {"kind": "Missing"},
                            "after": {"kind": "Present", "value": "pre-flip-plaintext"}
                        }]
                    }]
                }),
            ],
        )
        .await
        .expect("a pre-flip proposal inserts");
    database
        .admin
        .execute(
            "INSERT INTO registry_internal.registry_field_encryption_flips
                 (entity_id, field_id, boundary_package_revision, history_choice,
                  history_commit_position,
                  sealed_row_count, sealed_journal_row_count,
                  accepted_plaintext_journal_row_count,
                  accepted_request_target_row_count,
                  accepted_request_proposal_row_count,
                  accepted_idempotency_row_count, accepted_outbox_row_count)
             SELECT 'asset', 'code', 'pre-ledger-revision', 'erase-and-rebaseline',
                    latest_position + 1, 0, 0, 0, 0, 0, 0, 0
               FROM registry_internal.registry_commit_head
              WHERE singleton",
            &[],
        )
        .await
        .expect("the pre-adoption flip inserts");
    // The adoption ordered the flip's boundary after the revision the
    // proposal originated under, both before the ledger's first activation.
    database
        .admin
        .execute(
            "INSERT INTO registry_internal.registry_pre_ledger_package_positions
                 (package_revision, package_sequence)
             VALUES ('pre-ledger-origin', -1), ('pre-ledger-revision', 0)",
            &[],
        )
        .await
        .expect("the order the adoption kept inserts");

    let (mut migration, migration_task) = database.connect_migration().await;
    let registry = compile_variant(Variant::Base);
    let outcome = registry_breg::field_encryption_backfill::erase_field_encryption_history(
        &mut migration,
        registry_breg::field_encryption_backfill::FieldEncryptionHistoryErasureRequest {
            expected: &current,
            migration_role: &database.migration_role,
            lock_key: registry_breg::postgres::RegistryLockKey::derive(&current.package_id)
                .expect("lock key derives"),
            timeouts: registry_breg::history_erasure::HistoryErasureTimeouts::new(
                Duration::from_secs(5),
                Duration::from_secs(5),
            )
            .expect("erasure timeouts are bounded"),
            audit: &database.audit(
                AuditProfile::production_from_secret_bytes(vec![0x76; 32].into())
                    .expect("test owns a keyed audit profile"),
            ),
            operator_reference: "field-encryption-operator",
            reason: "destroy pre-flip request snapshots",
            registry: &registry,
        },
    )
    .await
    .expect("erasure orders the revisions the adoption kept");

    assert_eq!(outcome.scrubbed_request_proposal_count, 1);
    let erased: bool = database
        .admin
        .query_one(
            "SELECT snapshot IS NULL AND erased_at IS NOT NULL
               FROM registry_internal.registry_request_proposals
              WHERE request_id = $1",
            &[&request_id],
        )
        .await
        .expect("the proposal reads")
        .get(0);
    assert!(erased, "the pre-flip proposal's plaintext is scrubbed");
    migration_task.abort();
    database.cleanup().await;
}

/// Threat: a database whose registry state this release does not recognise,
/// such as one a release before the activation ledger installed, could be
/// served, applied over, planned, or read as though the ledger recorded it.
/// Enforcement: the kernel state-shape check refuses it before any read,
/// plan, or apply touches it, with one generic refusal, and nothing changes.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_an_unrecognised_registry_state_is_refused_and_changes_nothing() {
    let (database, package) = initial_package_database().await;
    let current = apply(&database, &package, ApplyPrecondition::InitialActivation)
        .await
        .expect("the initial package activates");
    downgrade_to_pre_ledger_kernel(&database).await;
    let tables = model_table_oids(&database).await;
    let audit = database.activation_audit_entries().len();

    assert_eq!(
        recorded_state(&database, &package)
            .await
            .expect_err("the recorded state is refused"),
        MigrationError::UnrecognizedDatabase
    );
    assert_eq!(
        read_activation_status(
            &database.migration_config,
            &database.migration_role,
            timeouts()
        )
        .await
        .expect_err("status is refused"),
        MigrationError::UnrecognizedDatabase
    );
    assert_eq!(
        plan(
            &database,
            &package,
            ApplyPrecondition::InitialActivation,
            false
        )
        .await
        .expect_err("a plan is refused"),
        MigrationError::UnrecognizedDatabase
    );
    assert_eq!(
        apply(&database, &package, ApplyPrecondition::InitialActivation)
            .await
            .expect_err("an initial activation is refused"),
        MigrationError::UnrecognizedDatabase
    );
    let role_change = ApplyPrecondition::RoleChange { current: &current };
    assert_eq!(
        plan(&database, &package, role_change, true)
            .await
            .expect_err("a role change is refused"),
        MigrationError::UnrecognizedDatabase
    );

    assert_pre_ledger_kernel(&database).await;
    assert_eq!(model_table_oids(&database).await, tables);
    assert_eq!(database.activation_audit_entries().len(), audit);
    database.cleanup().await;
}

/// Threat: an operator previewing an activation could change the database
/// the preview describes, or be told an activation would pass that apply
/// refuses. Enforcement: a plan runs apply's own checks inside transactions
/// it rolls back and never opens the activation audit, so every activation
/// kind reports what apply would do and the ledger, the maintenance state,
/// the catalog, and the audit are unchanged afterwards.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_a_plan_reports_each_pending_activation_and_writes_nothing() {
    let database = TestDatabase::create(1).await;
    database
        .admin
        .batch_execute("CREATE EXTENSION btree_gist")
        .await
        .expect("administrator installs the required extension");
    let base = compile_variant(Variant::Base);
    let initial_fingerprint = initial_fingerprint(&database, &base).await;
    let initial = prepare_and_load_initial(&base, &initial_fingerprint);

    let first = plan(
        &database,
        &initial,
        ApplyPrecondition::InitialActivation,
        false,
    )
    .await
    .expect("the first package plans");
    assert_eq!(first.activation, PlannedActivation::Initial);
    assert!(first.activation.is_pending());
    assert_eq!(first.role_mode, "split");
    assert_eq!(first.resumes_activation_id, None);
    assert!(first.checks.contains(&"uninitializedDatabase"));
    assert_eq!(
        registry_state_table(&database).await,
        None,
        "planning the first package installs nothing"
    );
    assert!(database.activation_audit_entries().is_empty());

    let active = apply(&database, &initial, ApplyPrecondition::InitialActivation)
        .await
        .expect("the planned first package activates");
    let before = plan_durable_state(&database).await;

    let unchanged = plan(
        &database,
        &initial,
        ApplyPrecondition::RoleChange { current: &active },
        false,
    )
    .await
    .expect("the active package plans");
    assert_eq!(unchanged.activation, PlannedActivation::AlreadyActive);
    assert!(!unchanged.activation.is_pending());

    let single = plan(
        &database,
        &initial,
        ApplyPrecondition::RoleChange { current: &active },
        true,
    )
    .await
    .expect("serving with one role plans");
    assert_eq!(single.activation, PlannedActivation::RoleChange);
    assert_eq!(single.role_mode, "single");

    let candidate = compile_variant(Variant::BatchAddedRequired);
    let target_fingerprint = added_required_target_fingerprint(&database, &candidate).await;
    let source = added_required_source(
        "add-required-plan",
        &active,
        &base,
        &candidate,
        &target_fingerprint,
        0,
    );
    let successor = prepare_and_load_reviewed(
        &active,
        &base,
        Variant::BatchAddedRequired,
        &target_fingerprint,
        source,
    );
    let planned = plan(
        &database,
        &successor,
        ApplyPrecondition::Successor { current: &active },
        false,
    )
    .await
    .expect("the successor plans");
    assert_eq!(planned.activation, PlannedActivation::Successor);
    assert!(planned.checks.contains(&"historyCoverage"));
    assert_eq!(
        plan_durable_state(&database).await,
        before,
        "no plan changed the ledger, the state, the catalog, or the audit"
    );

    let activated = apply(
        &database,
        &successor,
        ApplyPrecondition::Successor { current: &active },
    )
    .await
    .expect("the planned successor activates");
    assert_eq!(activated.package_digest, successor.package_digest());
    database.cleanup().await;
}

/// A plan refuses what apply refuses, with the same value-free error, and
/// leaves the database as it found it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_a_plan_refuses_what_apply_refuses_and_changes_nothing() {
    let (database, package) = initial_package_database().await;
    let initial = apply(&database, &package, ApplyPrecondition::InitialActivation)
        .await
        .expect("the initial package activates in split mode");
    let table = first_model_table(&database).await;
    let runtime = database.runtime_role.as_str();
    database
        .admin
        .batch_execute(&format!("ALTER TABLE {table} OWNER TO {runtime}"))
        .await
        .expect("the administrator hands a model table to the runtime role");
    let before = plan_durable_state(&database).await;

    let refusal = plan(
        &database,
        &package,
        ApplyPrecondition::RoleChange { current: &initial },
        false,
    )
    .await
    .expect_err("a runtime role that owns a model table is refused");
    assert!(
        matches!(refusal, MigrationError::RuntimeWriteAuthority(_)),
        "{refusal:?}"
    );
    assert_eq!(plan_durable_state(&database).await, before);
    database.cleanup().await;
}

/// Status reads the active identity and every ledger entry in apply order as
/// the migration role, and answers while another session holds the apply
/// lock.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_status_reads_the_ledger_without_the_apply_lock() {
    let (database, package) = initial_package_database().await;
    assert_eq!(
        read_activation_status(
            &database.migration_config,
            &database.migration_role,
            timeouts()
        )
        .await
        .expect("a never-activated database reads"),
        None
    );
    let initial = apply(&database, &package, ApplyPrecondition::InitialActivation)
        .await
        .expect("the initial package activates");
    let single = apply_verified_package(ApplyVerifiedPackageRequest::new(
        &database.migration_config,
        &package,
        deployment(),
        ApplyPrecondition::RoleChange { current: &initial },
        ApplyRoles::new(&database.migration_role, &database.migration_role),
        timeouts(),
        database.activation_audit(),
    ))
    .await
    .expect("serving with one role is its own activation");

    let lock_key = registry_breg::postgres::RegistryLockKey::derive(&package.manifest().package_id)
        .expect("the lock key derives");
    database
        .admin
        .execute("SELECT pg_catalog.pg_advisory_lock($1)", &[&lock_key.get()])
        .await
        .expect("another session holds the apply lock");
    let status = read_activation_status(
        &database.migration_config,
        &database.migration_role,
        timeouts(),
    )
    .await
    .expect("status reads")
    .expect("the database is activated");
    database
        .admin
        .execute(
            "SELECT pg_catalog.pg_advisory_unlock($1)",
            &[&lock_key.get()],
        )
        .await
        .expect("the apply lock releases");

    assert_eq!(status.identity, single);
    assert_eq!(status.maintenance_status, "ready");
    assert_eq!(status.maintenance_target_package_digest, None);
    assert_eq!(status.ledger.len(), 2);
    let entries = status
        .ledger
        .iter()
        .map(|entry| {
            (
                entry.activation_id.as_str(),
                entry.apply_order,
                entry.plan_kind.as_str(),
                entry.outcome.as_str(),
                entry.role_mode.as_str(),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        entries,
        vec![
            (
                initial.activation_id.as_str(),
                1,
                "initial",
                "applied",
                "split"
            ),
            (
                single.activation_id.as_str(),
                2,
                "successor",
                "applied",
                "single"
            ),
        ]
    );
    let active = status.active_entry().expect("the active entry is recorded");
    assert_eq!(active.package_digest, package.package_digest());
    assert_eq!(active.registry_revision, package.registry().revision());
    assert!(active.applied_at.is_some());
    OffsetDateTime::parse(&active.started_at, &Rfc3339).expect("started_at is RFC 3339");
    database.cleanup().await;
}

/// A database an earlier release adopted keeps an `adopted` row at the head
/// of its ledger, and no release rewrites it. Status reports the row as
/// recorded, the recorded state binds the active package and its catalog
/// verifies as startup verifies it, and a successor activates over it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_a_ledger_an_earlier_release_adopted_is_served_and_succeeded() {
    let (database, initial) = initial_package_database().await;
    let base = compile_variant(Variant::Base);
    let active = apply(&database, &initial, ApplyPrecondition::InitialActivation)
        .await
        .expect("the initial package activates");
    let adopted_activation =
        Uuid::parse_str(&active.activation_id).expect("the activation id is a UUID");
    let adopted = database
        .admin
        .execute(
            "UPDATE registry_internal.registry_migrations
             SET plan_kind = 'adopted'
             WHERE activation_id = $1 AND predecessor_package_digest IS NULL",
            &[&adopted_activation],
        )
        .await
        .expect("administrator records the activation as an adoption");
    assert_eq!(adopted, 1);

    let status = read_activation_status(
        &database.migration_config,
        &database.migration_role,
        timeouts(),
    )
    .await
    .expect("status reads")
    .expect("the database is activated");
    assert_eq!(status.identity, active);
    assert_eq!(status.maintenance_status, "ready");
    assert_eq!(status.ledger.len(), 1);
    let entry = status.active_entry().expect("the active entry is recorded");
    assert_eq!(entry.plan_kind, "adopted");
    assert_eq!(entry.predecessor_package_digest, None);
    assert_eq!(entry.package_digest, initial.package_digest());

    let recorded = recorded_state(&database, &initial)
        .await
        .expect("the recorded state reads")
        .expect("an adopted database records its state");
    assert_eq!(
        recorded,
        RecordedRegistryState {
            identity: active.clone(),
            ready: true,
            activation_applied: true,
        }
    );
    bind_active_package(&recorded.identity, initial.package_digest(), deployment())
        .expect("the adopted active package binds");
    let pool = database.runtime_config.build_pool().unwrap();
    let runtime = pool.get_for_test().await.unwrap();
    verify_catalog_identity_for_catalog(
        &**runtime,
        &active,
        &ExpectedManagedCatalog::compiled(&base),
        &database.migration_role,
        &database.runtime_role,
    )
    .await
    .expect("the adopted catalog verifies");
    drop(runtime);
    drop(pool);

    let candidate = compile_variant(Variant::BatchAddedRequired);
    let target_fingerprint = added_required_target_fingerprint(&database, &candidate).await;
    let source = added_required_source(
        "add-required-over-adoption",
        &active,
        &base,
        &candidate,
        &target_fingerprint,
        0,
    );
    let package = prepare_and_load_reviewed(
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
    .expect("a successor activates over the adopted package");
    assert_eq!(activated.package_digest, package.package_digest());

    let rows = database
        .admin
        .query(
            "SELECT plan_kind, predecessor_package_digest, outcome
             FROM registry_internal.registry_migrations
             ORDER BY apply_order",
            &[],
        )
        .await
        .expect("the ledger reads");
    let ledger = rows
        .iter()
        .map(|row| {
            (
                row.get::<_, String>(0),
                row.get::<_, Option<String>>(1),
                row.get::<_, String>(2),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        ledger,
        vec![
            ("adopted".to_owned(), None, "applied".to_owned()),
            (
                "successor".to_owned(),
                Some(initial.package_digest().to_owned()),
                "applied".to_owned()
            ),
        ]
    );
    database.cleanup().await;
}

async fn plan(
    database: &TestDatabase,
    package: &VerifiedPackage,
    precondition: ApplyPrecondition<'_>,
    single_role: bool,
) -> registry_breg::migration::Result<ActivationPlan> {
    let runtime_role = if single_role {
        &database.migration_role
    } else {
        &database.runtime_role
    };
    plan_verified_package(ApplyVerifiedPackageRequest::plan(
        &database.migration_config,
        package,
        deployment(),
        precondition,
        ApplyRoles::new(&database.migration_role, runtime_role),
        timeouts(),
    ))
    .await
}

fn timeouts() -> ApplyTimeouts {
    ApplyTimeouts::new(Duration::from_secs(1), Duration::from_secs(5))
        .expect("test timeouts are bounded")
}

async fn registry_state_table(database: &TestDatabase) -> Option<String> {
    database
        .admin
        .query_one(
            "SELECT pg_catalog.to_regclass('registry_internal.registry_state')::text",
            &[],
        )
        .await
        .expect("the catalog reads")
        .get(0)
}

/// What a plan must leave as it found it: the ledger, the state row, the
/// managed relations and their owners and privileges, and the activation
/// audit.
async fn plan_durable_state(
    database: &TestDatabase,
) -> (
    Vec<(String, String, String)>,
    Vec<String>,
    Vec<String>,
    usize,
) {
    let state = database
        .admin
        .query_one(
            "SELECT row_to_json(state)::text FROM registry_internal.registry_state AS state",
            &[],
        )
        .await
        .expect("the state row reads")
        .get::<_, String>(0);
    let catalog = database
        .admin
        .query(
            "SELECT format('%s.%s %s %s %s', namespace.nspname, class.relname, class.relkind,
                           pg_catalog.pg_get_userbyid(class.relowner),
                           COALESCE(class.relacl::text, ''))
             FROM pg_catalog.pg_class AS class
             JOIN pg_catalog.pg_namespace AS namespace ON namespace.oid = class.relnamespace
             WHERE namespace.nspname IN ('registry_internal', 'registry_data')
             ORDER BY 1",
            &[],
        )
        .await
        .expect("the catalog reads")
        .into_iter()
        .map(|row| row.get(0))
        .collect();
    (
        ledger_snapshot(database).await,
        vec![state],
        catalog,
        database.activation_audit_entries().len(),
    )
}

/// Rewrite the kernel tables of an activated database into the shapes the
/// release before the activation ledger kept, as an in-place upgrade finds
/// them: the state row names a package revision, the claim lives in its own
/// table, the ledger is keyed by revision, and import authorities name the
/// revision they were opened under.
async fn downgrade_to_pre_ledger_kernel(database: &TestDatabase) {
    let migration = format!("\"{}\"", database.migration_role.as_str());
    let runtime = format!("\"{}\"", database.runtime_role.as_str());
    database
        .admin
        .batch_execute(&format!(
            "DROP TABLE registry_internal.registry_migration_steps;
             DROP TABLE registry_internal.registry_migrations;
             CREATE TABLE registry_internal.registry_migrations (
                 target_package_revision text PRIMARY KEY,
                 source_package_revision text,
                 package_sequence bigint NOT NULL,
                 plan_kind text NOT NULL,
                 outcome text NOT NULL
             );
             INSERT INTO registry_internal.registry_migrations
                 VALUES ('pre-ledger-revision', NULL, 1, 'compiled_additive', 'applied');
             CREATE TABLE registry_internal.registry_migration_steps (
                 target_package_revision text NOT NULL,
                 step_id text NOT NULL,
                 PRIMARY KEY (target_package_revision, step_id)
             );
             CREATE TABLE registry_internal.registry_instance_claim (
                 singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
                 system_identifier bigint,
                 database_oid oid NOT NULL,
                 epoch bigint NOT NULL DEFAULT 1 CHECK (epoch >= 1),
                 claimed_at timestamptz NOT NULL DEFAULT transaction_timestamp()
             );
             INSERT INTO registry_internal.registry_instance_claim
                 SELECT true, system_identifier, database_oid, 2, claimed_at
                   FROM registry_internal.registry_state;
             ALTER TABLE registry_internal.registry_state RENAME TO registry_state_ledger;
             CREATE TABLE registry_internal.registry_state (
                 singleton boolean PRIMARY KEY DEFAULT true
                     CONSTRAINT registry_state_singleton_true CHECK (singleton),
                 environment text NOT NULL
                     CONSTRAINT registry_state_environment_nonempty CHECK (environment <> ''),
                 package_id text NOT NULL
                     CONSTRAINT registry_state_package_id_nonempty CHECK (package_id <> ''),
                 instance_id text NOT NULL
                     CONSTRAINT registry_state_instance_id_nonempty CHECK (instance_id <> ''),
                 database_id text NOT NULL
                     CONSTRAINT registry_state_database_id_nonempty CHECK (database_id <> ''),
                 active_package_revision text NOT NULL
                     CONSTRAINT registry_state_package_revision_nonempty
                     CHECK (active_package_revision <> ''),
                 schema_fingerprint text NOT NULL
                     CONSTRAINT registry_state_schema_fingerprint_nonempty
                     CHECK (schema_fingerprint <> ''),
                 package_sequence bigint NOT NULL
                     CONSTRAINT registry_state_package_sequence_nonnegative
                     CHECK (package_sequence >= 0),
                 maintenance_status text NOT NULL
                     CONSTRAINT registry_state_maintenance_status_closed
                     CHECK (maintenance_status IN ('ready', 'applying', 'failed')),
                 maintenance_target_revision text,
                 CONSTRAINT registry_state_maintenance_target_consistent CHECK (
                     (maintenance_status = 'ready' AND maintenance_target_revision IS NULL)
                     OR (maintenance_status IN ('applying', 'failed')
                         AND maintenance_target_revision IS NOT NULL)
                 ),
                 updated_at timestamptz NOT NULL DEFAULT transaction_timestamp()
             );
             INSERT INTO registry_internal.registry_state (
                 singleton, environment, package_id, instance_id, database_id,
                 active_package_revision, schema_fingerprint, package_sequence,
                 maintenance_status, maintenance_target_revision
             )
             SELECT true, '{ENVIRONMENT}', package_id, '{INSTANCE}', database_id,
                    'pre-ledger-revision', schema_fingerprint, 1, 'ready', NULL
               FROM registry_internal.registry_state_ledger;
             DROP TABLE registry_internal.registry_state_ledger;
             UPDATE registry_internal.registry_history_schemas
                SET package_revision = 'pre-ledger-revision';
             ALTER TABLE registry_internal.registry_import_authorities
                 RENAME COLUMN activation_id TO activation_revision;
             ALTER TABLE registry_internal.registry_import_authorities
                 ALTER COLUMN activation_revision TYPE text;
             UPDATE registry_internal.registry_import_authorities
                SET activation_revision = 'pre-ledger-revision';
             ALTER TABLE registry_internal.registry_import_authorities
                 ADD CHECK (activation_revision <> '');
             ALTER TABLE registry_internal.registry_state OWNER TO {migration};
             ALTER TABLE registry_internal.registry_instance_claim OWNER TO {migration};
             ALTER TABLE registry_internal.registry_migrations OWNER TO {migration};
             ALTER TABLE registry_internal.registry_migration_steps OWNER TO {migration};
             GRANT SELECT ON registry_internal.registry_state,
                 registry_internal.registry_instance_claim,
                 registry_internal.registry_migrations,
                 registry_internal.registry_migration_steps TO {runtime};",
        ))
        .await
        .expect("the administrator rewrites the kernel into its pre-ledger shape");
}

/// The kernel still has the shape the deployed release kept.
async fn assert_pre_ledger_kernel(database: &TestDatabase) {
    let row = database
        .admin
        .query_one(
            "SELECT
                 (SELECT active_package_revision FROM registry_internal.registry_state),
                 to_regclass('registry_internal.registry_instance_claim') IS NOT NULL,
                 (SELECT count(*) FROM registry_internal.registry_migrations
                   WHERE target_package_revision = 'pre-ledger-revision'),
                 (SELECT format_type(atttypid, atttypmod) FROM pg_attribute
                   WHERE attrelid = 'registry_internal.registry_import_authorities'::regclass
                     AND attname = 'activation_revision')",
            &[],
        )
        .await
        .expect("the pre-ledger kernel reads");
    assert_eq!(row.get::<_, String>(0), "pre-ledger-revision");
    assert!(row.get::<_, bool>(1));
    assert_eq!(row.get::<_, i64>(2), 1);
    assert_eq!(row.get::<_, String>(3), "text");
}

/// The model tables, by oid, so a test can tell no DDL replaced them.
async fn model_table_oids(database: &TestDatabase) -> Vec<(String, i64)> {
    database
        .admin
        .query(
            "SELECT class.relname::text, class.oid::bigint
               FROM pg_class AS class
               JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
              WHERE namespace.nspname = 'registry_data' AND class.relkind = 'r'
              ORDER BY 1",
            &[],
        )
        .await
        .expect("the model tables read")
        .into_iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect()
}

async fn recorded_claim(database: &TestDatabase) -> (Option<i64>, i64) {
    let row = database
        .admin
        .query_one(
            "SELECT database_oid::bigint, epoch::bigint
               FROM registry_internal.registry_state WHERE singleton",
            &[],
        )
        .await
        .expect("the claim reads");
    (row.get(0), row.get(1))
}

async fn live_database_oid(database: &TestDatabase) -> i64 {
    database
        .admin
        .query_one(
            "SELECT oid::bigint FROM pg_catalog.pg_database WHERE datname = current_database()",
            &[],
        )
        .await
        .expect("the live database reads")
        .get(0)
}

async fn ledger_roles(
    database: &TestDatabase,
) -> Vec<(String, String, String, Option<String>, String, String)> {
    database
        .admin
        .query(
            "SELECT activation_id::text, plan_kind, migration_kind, predecessor_package_digest,
                    role_mode, runtime_role
             FROM registry_internal.registry_migrations
             WHERE outcome = 'applied'
             ORDER BY apply_order",
            &[],
        )
        .await
        .expect("the ledger reads")
        .into_iter()
        .map(|row| {
            (
                row.get(0),
                row.get(1),
                row.get(2),
                row.get(3),
                row.get(4),
                row.get(5),
            )
        })
        .collect()
}

async fn retired_role_privileges(database: &TestDatabase, role: &str) -> i64 {
    database
        .admin
        .query_one(
            "SELECT
                 (SELECT count(*) FROM pg_class AS class
                  JOIN pg_namespace AS namespace ON namespace.oid = class.relnamespace
                  CROSS JOIN LATERAL aclexplode(class.relacl) AS acl
                  WHERE namespace.nspname LIKE 'registry\\_%'
                    AND acl.grantee = to_regrole($1))
               + (SELECT count(*) FROM pg_namespace AS namespace
                  CROSS JOIN LATERAL aclexplode(namespace.nspacl) AS acl
                  WHERE namespace.nspname LIKE 'registry\\_%'
                    AND acl.grantee = to_regrole($1))
               + (SELECT count(*) FROM pg_proc AS function
                  JOIN pg_namespace AS namespace ON namespace.oid = function.pronamespace
                  CROSS JOIN LATERAL aclexplode(function.proacl) AS acl
                  WHERE namespace.nspname LIKE 'registry\\_%'
                    AND acl.grantee = to_regrole($1))",
            &[&role],
        )
        .await
        .expect("the catalog reads")
        .get(0)
}

async fn initial_package_database() -> (TestDatabase, VerifiedPackage) {
    let database = TestDatabase::create(1).await;
    database
        .admin
        .batch_execute("CREATE EXTENSION btree_gist")
        .await
        .expect("administrator installs the required extension");
    let base = compile_variant(Variant::Base);
    let initial_fingerprint = initial_fingerprint(&database, &base).await;
    let initial = prepare_and_load_initial(&base, &initial_fingerprint);
    (database, initial)
}

/// A successor activation supersedes every open import authority in the
/// transaction that makes it active, and each supersession is recorded
/// under the successor's activation id once that transaction commits. The
/// authority keeps the activation id it was opened under.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_a_successor_activation_supersedes_every_open_import_authority() {
    let (database, active, authority_id, package) = successor_over_an_open_import_authority().await;
    let activated = apply(
        &database,
        &package,
        ApplyPrecondition::Successor { current: &active },
    )
    .await
    .expect("the successor activates");

    assert_eq!(
        import_authority_status(&database, authority_id).await,
        ("superseded".to_owned(), true)
    );
    let records = import_authority_records(&database, authority_id);
    assert_eq!(records.len(), 1, "{records:?}");
    assert_eq!(records[0]["transition"], "superseded");
    assert_eq!(records[0]["activationId"], active.activation_id);
    assert_eq!(records[0]["packageRevision"], activated.activation_id);
    assert!(records[0].get("activationRevision").is_none());
    database.cleanup().await;
}

/// When the audit refuses a supersession record after the activation
/// committed, the activation stands and apply reports the audit trail as
/// incomplete rather than as a failed activation.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_a_refused_supersession_record_reports_the_activation_audit_incomplete() {
    let (database, active, authority_id, package) = successor_over_an_open_import_authority().await;
    // The audit accepts the activation's request and applied response,
    // then refuses the supersession record this activation owes it.
    database.activation_audit_capture().fail_after(2);
    let refused = apply(
        &database,
        &package,
        ApplyPrecondition::Successor { current: &active },
    )
    .await
    .expect_err("the refused record is reported");
    assert_eq!(refused, MigrationError::ActivationAuditIncomplete);
    assert_eq!(
        import_authority_status(&database, authority_id).await,
        ("superseded".to_owned(), true)
    );
    let activated = ExpectedRegistryIdentity {
        activation_id: activation_at(&database, 2).await,
        ..target_identity(&package)
    };
    assert_ready_target(&database, &activated).await;
    database.cleanup().await;
}

/// An initial activation, one import authority opened under it, and a
/// reviewed successor ready to apply.
async fn successor_over_an_open_import_authority() -> (
    TestDatabase,
    ExpectedRegistryIdentity,
    Uuid,
    VerifiedPackage,
) {
    let database = TestDatabase::create(1).await;
    database
        .admin
        .batch_execute("CREATE EXTENSION btree_gist")
        .await
        .expect("administrator installs the required extension");
    let base = compile_variant(Variant::Base);
    let initial_fingerprint = initial_fingerprint(&database, &base).await;
    let initial = prepare_and_load_initial(&base, &initial_fingerprint);
    let active = apply(&database, &initial, ApplyPrecondition::InitialActivation)
        .await
        .expect("the initial package activates");
    let authority_id = open_raw_import_authority(&database, &active.activation_id).await;

    let candidate = compile_variant(Variant::BatchAddedRequired);
    let target_fingerprint = added_required_target_fingerprint(&database, &candidate).await;
    let source = added_required_source(
        "add-required-supersede",
        &active,
        &base,
        &candidate,
        &target_fingerprint,
        0,
    );
    let package = prepare_and_load_reviewed(
        &active,
        &base,
        Variant::BatchAddedRequired,
        &target_fingerprint,
        source,
    );
    (database, active, authority_id, package)
}

/// A successor activation that fails supersedes nothing: the authority it
/// would have retired stays open and no supersession is recorded.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_a_failed_successor_activation_supersedes_no_import_authority() {
    let database = TestDatabase::create(1).await;
    database
        .admin
        .batch_execute("CREATE EXTENSION btree_gist")
        .await
        .expect("administrator installs extension");
    let base = compile_variant(Variant::Base);
    let fingerprint = initial_fingerprint(&database, &base).await;
    let initial = prepare_and_load_initial(&base, &fingerprint);
    let active = apply(&database, &initial, ApplyPrecondition::InitialActivation)
        .await
        .expect("the initial package activates");
    seed_backfill_rows(&database, &base, 1).await;
    let authority_id = open_raw_import_authority(&database, &active.activation_id).await;
    let required = compile_variant(Variant::RankRequired);
    let target_fingerprint = required_target_fingerprint(&database, &required).await;
    let entity = &required.entities()["asset"];
    let source = backfill_source_with_steps(
        BackfillSourceRequest {
            id: "rank-uncastable-supersede",
            current: &active,
            prior: &base,
            candidate: &required,
            final_fingerprint: &target_fingerprint,
            pre: AssertionMode::True,
            post: AssertionMode::True,
            rehearsed_rows: 1,
        },
        Some(format!(
            "UPDATE registry_data.{} SET {} = 'uncastable' WHERE record_id = ANY($1::pg_catalog.uuid[])",
            entity.physical_table, entity.fields["rank"].physical_name
        )),
        true,
    );
    let package = prepare_and_load_reviewed(
        &active,
        &base,
        Variant::RankRequired,
        &target_fingerprint,
        source,
    );
    apply(
        &database,
        &package,
        ApplyPrecondition::Successor { current: &active },
    )
    .await
    .expect_err("PostgreSQL refuses the reviewed step's constant");

    assert_eq!(
        import_authority_status(&database, authority_id).await,
        ("open".to_owned(), false)
    );
    assert!(import_authority_records(&database, authority_id).is_empty());
    database.cleanup().await;
}

/// `bregctl test` rehearses a successor over an empty reproduction of the
/// verified predecessor schema before it measures the candidate. The rehearsal
/// accepts the plan activation accepts, refuses the plans activation would
/// refuse with a value-free PostgreSQL class and object, and rolls back so the
/// schema-test database is still clean afterward.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_rehearsal_refuses_a_reviewed_plan_activation_would_refuse() {
    let database = TestDatabase::create(1).await;
    let _unused_harness_configs = (&database.runtime_config, &database.tls_runtime_config);
    database
        .admin
        .batch_execute("CREATE EXTENSION btree_gist")
        .await
        .expect("administrator installs the required extension");

    let base = compile_variant(Variant::Base);
    let base_fingerprint = initial_fingerprint(&database, &base).await;
    let initial = prepare_and_load_initial(&base, &base_fingerprint);
    let active = target_identity(&initial);
    let candidate = compile_variant(Variant::RankRequired);
    // A package's fingerprint is the fresh-install fingerprint of its registry,
    // and activation holds the migrated catalog to it.
    let target_fingerprint = initial_fingerprint(&database, &candidate).await;
    let rehearsal_request = |id: &'static str| BackfillSourceRequest {
        id,
        current: &active,
        prior: &base,
        candidate: &candidate,
        final_fingerprint: &target_fingerprint,
        pre: AssertionMode::True,
        post: AssertionMode::True,
        rehearsed_rows: 0,
    };

    let accepted = prepare_reviewed_candidate(
        &active,
        &base,
        &target_fingerprint,
        backfill_source(rehearsal_request("rank-reviewed")),
    );
    let outcome = rehearse(&database, &base, &base_fingerprint, &accepted)
        .await
        .expect("the reviewed plan activation accepts also rehearses");
    assert!(
        outcome.baseline_fingerprint_drift.is_none(),
        "a reproduced baseline carries no drift warning"
    );
    assert_rehearsal_database_clean(&database).await;

    // Comments, a line break after UPDATE, and statement words inside a
    // comment or a plain literal leave a chunk the journal can record.
    let entity = &candidate.entities()["asset"];
    let rank = &entity.fields["rank"].physical_name;
    let commented = prepare_reviewed_candidate(
        &active,
        &base,
        &target_fingerprint,
        backfill_source_with_steps(
            rehearsal_request("rank-commented"),
            Some(format!(
                "-- SPDX-License-Identifier: Apache-2.0\nUPDATE\n  registry_data.{}\n   SET {rank} = CASE WHEN 'never drop a row' = 'x' THEN 1 ELSE 1 END /* never drop a row */\n WHERE record_id = ANY($1::pg_catalog.uuid[]);\n",
                entity.physical_table
            )),
            true,
        ),
    );
    rehearse(&database, &base, &base_fingerprint, &commented)
        .await
        .expect("a commented chunk activation accepts also rehearses");
    assert_rehearsal_database_clean(&database).await;

    let unconstrained = prepare_reviewed_candidate(
        &active,
        &base,
        &target_fingerprint,
        backfill_source_with_steps(rehearsal_request("rank-unconstrained"), None, false),
    );
    let refused = rehearse(&database, &base, &base_fingerprint, &unconstrained)
        .await
        .expect_err("a plan that leaves the column nullable misses the candidate schema");
    assert_eq!(refused, MigrationRehearsalError::FinalSchemaMismatch);
    assert_rehearsal_database_clean(&database).await;

    let canary = "rehearsal-canary-value";
    let uncastable = prepare_reviewed_candidate(
        &active,
        &base,
        &target_fingerprint,
        backfill_source_with_steps(
            rehearsal_request("rank-uncastable"),
            Some(format!(
                "UPDATE registry_data.{} SET {rank} = '{canary}' WHERE record_id = ANY($1::pg_catalog.uuid[])",
                entity.physical_table
            )),
            true,
        ),
    );
    let refused = rehearse(&database, &base, &base_fingerprint, &uncastable)
        .await
        .expect_err("PostgreSQL refuses the reviewed step's constant");
    let MigrationRehearsalError::Step {
        migration_id,
        step_id,
        failure,
    } = &refused
    else {
        panic!("the refusal names the reviewed step: {refused:?}");
    };
    assert_eq!(migration_id, "rank-uncastable");
    assert_eq!(step_id, "backfill-rank");
    assert_eq!(failure.sqlstate.as_deref(), Some("22P02"));
    let rendered = format!("{refused} {refused:?}");
    assert!(
        rendered.contains("data exception"),
        "the refusal names the PostgreSQL error class: {rendered}"
    );
    assert!(
        !rendered.contains(canary),
        "the refusal carries no value from the statement: {rendered}"
    );
    assert_rehearsal_database_clean(&database).await;

    // The package accepts a chunk whose parsed statement is a plain UPDATE,
    // but activation also refuses a reviewed update whose text names a
    // refused statement word inside a dollar-quoted body, which the lexical
    // check reads as written, before the chunk runs.
    let metadata_writer = prepare_reviewed_candidate(
        &active,
        &base,
        &target_fingerprint,
        backfill_source_with_steps(
            rehearsal_request("rank-dollar-quoted"),
            Some(format!(
                "UPDATE registry_data.{} SET {rank} = CASE WHEN $$never drop a row$$ = $$x$$ THEN 1 ELSE 1 END WHERE record_id = ANY($1::pg_catalog.uuid[])",
                entity.physical_table
            )),
            true,
        ),
    );
    let refused = rehearse(&database, &base, &base_fingerprint, &metadata_writer)
        .await
        .expect_err("a chunk activation would refuse before it runs is refused");
    assert!(
        matches!(
            &refused,
            MigrationRehearsalError::HistoryStep { migration_id, step_id, .. }
                if migration_id == "rank-dollar-quoted" && step_id == "backfill-rank"
        ),
        "the refusal names the reviewed step the journal refuses: {refused:?}"
    );
    assert_rehearsal_database_clean(&database).await;

    // A predecessor signed by another engine release measures differently
    // under this one; the drift is reported and the rehearsal continues to
    // the strict final fingerprint check.
    let drifted = rehearse(&database, &base, &target_fingerprint, &accepted)
        .await
        .expect("a baseline that does not reproduce still rehearses the successor");
    let drift = drifted
        .baseline_fingerprint_drift
        .expect("a baseline that does not reproduce is reported as drift");
    assert_eq!(drift.signed, target_fingerprint);
    assert_eq!(drift.measured, base_fingerprint);
    assert_rehearsal_database_clean(&database).await;

    // Drift does not relax the final check: a candidate that does not reach
    // its own fingerprint is still refused.
    let unreachable = prepare_reviewed_candidate(
        &active,
        &base,
        &base_fingerprint,
        backfill_source(BackfillSourceRequest {
            final_fingerprint: &base_fingerprint,
            ..rehearsal_request("rank-unreachable")
        }),
    );
    let refused = rehearse(&database, &base, &target_fingerprint, &unreachable)
        .await
        .expect_err("a drifted baseline does not relax the final fingerprint check");
    assert_eq!(refused, MigrationRehearsalError::FinalSchemaMismatch);
    assert_rehearsal_database_clean(&database).await;

    database.cleanup().await;
}

/// The rehearsal runs a reviewed migration's assertions and steps under the
/// lock and statement timeouts its descriptor declares, the ones activation
/// sets, so an assertion that outlasts the declared statement timeout is
/// refused by the rehearsal as activation refuses it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_rehearsal_holds_a_reviewed_migration_to_its_declared_timeouts() {
    let database = TestDatabase::create(1).await;
    let _unused_harness_configs = (&database.runtime_config, &database.tls_runtime_config);
    database
        .admin
        .batch_execute("CREATE EXTENSION btree_gist")
        .await
        .expect("administrator installs the required extension");

    let base = compile_variant(Variant::Base);
    let base_fingerprint = initial_fingerprint(&database, &base).await;
    let initial = prepare_and_load_initial(&base, &base_fingerprint);
    let active = target_identity(&initial);
    let candidate = compile_variant(Variant::RankRequired);
    let target_fingerprint = initial_fingerprint(&database, &candidate).await;
    let request = |current| BackfillSourceRequest {
        id: "rank-outlasts-timeout",
        current,
        prior: &base,
        candidate: &candidate,
        final_fingerprint: &target_fingerprint,
        pre: AssertionMode::OutlastsStatementTimeout,
        post: AssertionMode::True,
        rehearsed_rows: 0,
    };
    let prepared = prepare_reviewed_candidate(
        &active,
        &base,
        &target_fingerprint,
        backfill_source(request(&active)),
    );
    let refused = rehearse(&database, &base, &base_fingerprint, &prepared)
        .await
        .expect_err("an assertion that outlasts the declared statement timeout is refused");
    let MigrationRehearsalError::Assertion {
        migration_id,
        phase,
        assertion_id,
        failure,
    } = &refused
    else {
        panic!("the refusal names the reviewed assertion: {refused:?}");
    };
    assert_eq!(migration_id, "rank-outlasts-timeout");
    assert_eq!(*phase, RehearsalAssertionPhase::Pre);
    assert_eq!(assertion_id, "pre");
    assert_eq!(failure.sqlstate.as_deref(), Some("57014"));
    assert_rehearsal_database_clean(&database).await;

    // Activation sets the same declared timeout and refuses the same plan.
    let active = apply(&database, &initial, ApplyPrecondition::InitialActivation)
        .await
        .expect("the timeout scenario's initial package activates");
    let package = prepare_and_load_reviewed(
        &active,
        &base,
        Variant::RankRequired,
        &target_fingerprint,
        backfill_source(request(&active)),
    );
    let refused = apply(
        &database,
        &package,
        ApplyPrecondition::Successor { current: &active },
    )
    .await;
    assert_value_free(refused.err(), MigrationError::ApplyFailed);

    database.cleanup().await;
}

/// A predecessor whose schema the current compiler cannot install is refused;
/// only a fingerprint difference is advisory.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_rehearsal_refuses_a_predecessor_it_cannot_install() {
    let database = TestDatabase::create(1).await;
    let _unused_harness_configs = (&database.runtime_config, &database.tls_runtime_config);
    // Without CREATE on the data schema, the predecessor schema cannot be
    // installed.
    database
        .admin
        .batch_execute(&format!(
            "REVOKE CREATE ON SCHEMA registry_data FROM \"{}\"",
            database.migration_role.as_str()
        ))
        .await
        .expect("administrator revokes the data schema privilege");
    let fingerprint = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    let base = compile_variant(Variant::Base);
    let initial = prepare_and_load_initial(&base, fingerprint);
    let active = target_identity(&initial);
    let candidate = compile_variant(Variant::RankRequired);
    let prepared = prepare_reviewed_candidate(
        &active,
        &base,
        fingerprint,
        backfill_source(BackfillSourceRequest {
            id: "rank-uninstallable",
            current: &active,
            prior: &base,
            candidate: &candidate,
            final_fingerprint: fingerprint,
            pre: AssertionMode::True,
            post: AssertionMode::True,
            rehearsed_rows: 0,
        }),
    );

    let refused = rehearse(&database, &base, fingerprint, &prepared)
        .await
        .expect_err("a predecessor schema that cannot be installed is refused");
    assert_eq!(refused, MigrationRehearsalError::BaselineNotReproducible);
    assert_rehearsal_database_clean(&database).await;

    database.cleanup().await;
}

/// A reviewed plan that also carries compiler DDL rehearses it in activation
/// order: the added column arrives nullable, the managed read views are
/// rebuilt, and the deferred `SET NOT NULL` runs after the reviewed backfill.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_rehearsal_runs_compiler_ddl_around_the_reviewed_steps() {
    let database = TestDatabase::create(1).await;
    let _unused_harness_configs = (&database.runtime_config, &database.tls_runtime_config);
    database
        .admin
        .batch_execute("CREATE EXTENSION btree_gist")
        .await
        .expect("administrator installs the required extension");

    let base = compile_variant(Variant::Base);
    let base_fingerprint = initial_fingerprint(&database, &base).await;
    let active = target_identity(&prepare_and_load_initial(&base, &base_fingerprint));
    let candidate = compile_variant(Variant::BatchAddedRequired);
    let target_fingerprint = initial_fingerprint(&database, &candidate).await;
    let prepared = prepare_package(build_request(
        Variant::BatchAddedRequired,
        Some(&active.package_digest),
        &target_fingerprint,
        PackageMigrationPlanInput::ReviewedSuccessor {
            prior_registry: Box::new(base.clone()),
            prior_schema_fingerprint: active.schema_fingerprint.clone(),
            migrations: vec![added_required_source(
                "add-required-rehearsal",
                &active,
                &base,
                &candidate,
                &target_fingerprint,
                0,
            )],
        },
    ))
    .expect("reviewed candidate prepares");
    assert!(
        !prepared.manifest().migration_plan.statements.is_empty(),
        "the candidate carries compiler DDL around its reviewed step"
    );
    rehearse(&database, &base, &base_fingerprint, &prepared)
        .await
        .expect("compiler DDL and the reviewed backfill rehearse in activation order");
    assert_rehearsal_database_clean(&database).await;

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

    let prior = compile_variant(Variant::EncryptedBase);
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

    let candidate = compile_variant(Variant::EncryptedFlipOn);
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
        &active,
        &prior,
        Variant::EncryptedFlipOn,
        &target_fingerprint,
        source,
    );
    let predecessor_baseline =
        CompiledRegistryMigrationBaseline::from_compiled(&active.package_digest, &prior);
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
            target_package_revision: package.package_digest(),
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
        MigrationError::HistoryCoverage
    );
    let untouched = database
        .admin
        .query_one(
            "SELECT
                 (SELECT maintenance_status = 'ready'
                    AND maintenance_target_package_digest IS NULL
                    FROM registry_internal.registry_state WHERE singleton),
                 NOT EXISTS (
                     SELECT 1 FROM registry_internal.registry_migrations
                      WHERE package_digest = $1
                 ),
                 NOT EXISTS (
                     SELECT 1 FROM registry_internal.registry_field_encryption_flips
                 )",
            &[&package.package_digest()],
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

    let prior = compile_variant(Variant::EncryptedBase);
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

    let candidate = compile_variant(Variant::EncryptedFlipOn);
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
                  proposal_version, workflow_revision)
             VALUES ('encryption-request', $1, 'owner:hash', 'cancelled', 1, 1)",
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
                    "originatingPackage": active.activation_id,
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
            &[&active.activation_id],
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

    let prior = compile_variant(Variant::EncryptedBase);
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

    let candidate = compile_variant(Variant::EncryptedFlipOn);
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
        &active,
        &prior,
        Variant::EncryptedFlipOn,
        &target_fingerprint,
        source,
    );
    let predecessor_baseline =
        CompiledRegistryMigrationBaseline::from_compiled(&active.package_digest, &prior);
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
            target_package_revision: package.package_digest(),
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

    let prior = compile_variant(Variant::EncryptedBase);
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

    let candidate = compile_variant(Variant::EncryptedFlipOn);
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
    SubjectWithoutLog,
    SubjectWithLog,
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
    /// True, but only after it outlasts the statement timeout the migration
    /// declares, so activation cancels it.
    OutlastsStatementTimeout,
}

/// The statement timeout a backfill source declares, and the shorter one it
/// declares when an assertion is written to outlast it.
fn declared_statement_timeout_ms(pre: AssertionMode, post: AssertionMode) -> u64 {
    if matches!(pre, AssertionMode::OutlastsStatementTimeout)
        || matches!(post, AssertionMode::OutlastsStatementTimeout)
    {
        200
    } else {
        5_000
    }
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
        let base = compile_variant(Variant::Base);
        let fingerprint = initial_fingerprint(&database, &base).await;
        let initial = prepare_and_load_initial(&base, &fingerprint);
        let active = apply(&database, &initial, ApplyPrecondition::InitialActivation)
            .await
            .expect("assertion scenario initial package activates");
        seed_backfill_rows(&database, &base, 1).await;
        let required = compile_variant(Variant::RankRequired);
        let target_fingerprint = required_target_fingerprint(&database, &required).await;
        let source = backfill_source(BackfillSourceRequest {
            id: if matches!(pre, AssertionMode::False) {
                "false-pre"
            } else {
                "false-post"
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
    let base = compile_variant(Variant::Base);
    let fingerprint = initial_fingerprint(&database, &base).await;
    let initial = prepare_and_load_initial(&base, &fingerprint);
    let active = apply(&database, &initial, ApplyPrecondition::InitialActivation)
        .await
        .expect("row mismatch initial package activates");
    seed_backfill_rows(&database, &base, 2).await;
    let required = compile_variant(Variant::RankRequired);
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
        &active,
        &base,
        Variant::RankRequired,
        &target_fingerprint,
        source,
    );
    let entity = &base.entities()["asset"];
    let table = quote(&entity.physical_table);
    // A split apply refuses a trigger its migrations do not create before
    // any step runs, so the fault that makes the backfill update touch no row
    // is a rule the administrator installs.
    database
        .admin
        .batch_execute(&format!(
            "CREATE RULE migration_test_skip_update AS
                 ON UPDATE TO registry_data.{table} DO INSTEAD NOTHING"
        ))
        .await
        .expect("administrator installs a row-count fault rule");
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
    let base = compile_variant(Variant::Base);
    let fingerprint = initial_fingerprint(&database, &base).await;
    let initial = prepare_and_load_initial(&base, &fingerprint);
    let active = apply(&database, &initial, ApplyPrecondition::InitialActivation)
        .await
        .expect("timeout scenario initial package activates");
    seed_backfill_rows(&database, &base, 1).await;
    let required = compile_variant(Variant::RankRequired);
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

/// A reviewed step PostgreSQL refuses fails `apply` with the SQLSTATE and the
/// object names the server reported, never its message or a statement value.
async fn refused_step_reports_its_sqlstate() {
    let database = TestDatabase::create(1).await;
    database
        .admin
        .batch_execute("CREATE EXTENSION btree_gist")
        .await
        .expect("administrator installs extension");
    let base = compile_variant(Variant::Base);
    let fingerprint = initial_fingerprint(&database, &base).await;
    let initial = prepare_and_load_initial(&base, &fingerprint);
    let active = apply(&database, &initial, ApplyPrecondition::InitialActivation)
        .await
        .expect("refused-step scenario initial package activates");
    seed_backfill_rows(&database, &base, 1).await;
    let required = compile_variant(Variant::RankRequired);
    let target_fingerprint = required_target_fingerprint(&database, &required).await;
    let entity = &required.entities()["asset"];
    let canary = "apply-statement-canary";
    let source = backfill_source_with_steps(
        BackfillSourceRequest {
            id: "rank-uncastable",
            current: &active,
            prior: &base,
            candidate: &required,
            final_fingerprint: &target_fingerprint,
            pre: AssertionMode::True,
            post: AssertionMode::True,
            rehearsed_rows: 1,
        },
        Some(format!(
            "UPDATE registry_data.{} SET {} = '{canary}' WHERE record_id = ANY($1::pg_catalog.uuid[])",
            entity.physical_table, entity.fields["rank"].physical_name
        )),
        true,
    );
    let package = prepare_and_load_reviewed(
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
    .await
    .expect_err("PostgreSQL refuses the reviewed step's constant");
    let MigrationError::StatementFailed(failure) = &refused else {
        panic!("the refusal carries the PostgreSQL failure: {refused:?}");
    };
    assert_eq!(failure.sqlstate.as_deref(), Some("22P02"));
    let rendered = format!("{refused} {refused:?}");
    assert!(
        rendered.contains("SQLSTATE 22P02 (data exception)"),
        "the refusal names the SQLSTATE and its class: {rendered}"
    );
    assert!(
        !rendered.contains(canary),
        "the refusal carries no value from the statement: {rendered}"
    );
    assert_value_free(Some(refused.clone()), refused);
    assert_non_ready_target(&database, &active, &package, "failed").await;
    database.cleanup().await;
}

/// Open one import authority under the named activation, as an operator
/// would have before the activation under test.
async fn open_raw_import_authority(database: &TestDatabase, activation_id: &str) -> Uuid {
    let authority_id = Uuid::new_v4();
    database
        .admin
        .execute(
            "INSERT INTO registry_internal.registry_import_authorities
                 (authority_id, entity_id, profile_id, operation, max_items,
                  activation_id, expires_at, operator_reference, reason_reference)
             VALUES ($1, 'asset', 'loader', 'create', 5, $2::text::uuid,
                     now() + interval '1 day', 'operator-hash', 'reason-hash')",
            &[&authority_id, &activation_id],
        )
        .await
        .expect("administrator opens an import authority");
    authority_id
}

async fn import_authority_status(database: &TestDatabase, authority_id: Uuid) -> (String, bool) {
    let row = database
        .admin
        .query_one(
            "SELECT status, closed_at IS NOT NULL
               FROM registry_internal.registry_import_authorities
              WHERE authority_id = $1",
            &[&authority_id],
        )
        .await
        .expect("administrator reads the import authority");
    (row.get(0), row.get(1))
}

/// The import authority transitions the activation recorded for one
/// authority, oldest first.
fn import_authority_records(database: &TestDatabase, authority_id: Uuid) -> Vec<serde_json::Value> {
    database
        .activation_audit_entries()
        .into_iter()
        .filter(|entry| {
            entry["schema"] == "breg-import-authority-audit/v1"
                && entry["correlation"] == authority_id.to_string()
        })
        .map(|mut entry| {
            assert_eq!(entry["phase"], "response");
            entry["record"].take()
        })
        .collect()
}

fn compile_variant(variant: Variant) -> CompiledRegistry {
    let module_bytes = module_bytes(variant);
    let module = parse_module_yaml(&module_bytes).expect("test module parses");
    let project_bytes = project_bytes(&module_digest(&module));
    let project = parse_project_yaml(&project_bytes).expect("test project parses");
    compile_project(&project, &[module], CompileProfile::Production)
        .expect("test Registry compiles")
}

fn project_bytes(digest: &str) -> Vec<u8> {
    format!(
        r#"{{"apiVersion":"registry.registrystack.org/v1alpha1","kind":"RegistryProject","registry":{{"id":"migration-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://migration.example.test"}},"package":{{"sourceRevision":"{SOURCE_REVISION}"}},"manifestProjection":{{"accessProfile":"reader","classificationCeiling":"internal","catalog":{{"baseUrl":"https://migration.example.test","title":"Migration Registry","publisher":{{"id":"migration-registry-authority","name":"Migration Publisher"}}}},"publicService":{{"id":"migration-registry-service","title":"Migration Registry"}},"datasets":[{{"id":"migration-registry","title":"Migration Dataset","owner":"Migration Publisher","status":"active"}}],"dataServices":[{{"id":"migration-registry-data-service","title":"Migration Registry","endpointUrl":"https://migration.example.test","servesDatasets":["migration-registry"]}}]}},"modules":[{{"id":"core","version":"1","digest":"{digest}"}}]}}"#
    )
    .into_bytes()
}

fn module_bytes(variant: Variant) -> Vec<u8> {
    if matches!(
        variant,
        Variant::SubjectWithoutLog | Variant::SubjectWithLog
    ) {
        let mut source: serde_json::Value =
            serde_json::from_slice(&module_bytes(Variant::Base)).unwrap();
        source["entities"][0]["fields"][0]["required"] = serde_json::json!(true);
        if matches!(variant, Variant::SubjectWithLog) {
            source["entities"][0]["accessLog"] = serde_json::json!({"subjectField":"code"});
        }
        return serde_json::to_vec(&source).unwrap();
    }
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
        None,
        fingerprint,
        PackageMigrationPlanInput::InitialCompiledDdl,
    ))
    .expect("initial package prepares");
    let loaded = publish_and_load(prepared, local_context());
    assert_eq!(loaded.registry(), registry);
    loaded
}

fn prepare_and_load_reviewed(
    current: &ExpectedRegistryIdentity,
    prior: &CompiledRegistry,
    variant: Variant,
    fingerprint: &str,
    source: ReviewedMigrationSource,
) -> VerifiedPackage {
    let prepared = prepare_package(build_request(
        variant,
        Some(&current.package_digest),
        fingerprint,
        PackageMigrationPlanInput::ReviewedSuccessor {
            prior_registry: Box::new(prior.clone()),
            prior_schema_fingerprint: current.schema_fingerprint.clone(),
            migrations: vec![source],
        },
    ))
    .expect("reviewed package prepares");
    publish_and_load(prepared, local_context())
}

fn build_request(
    variant: Variant,
    prior_revision: Option<&str>,
    schema_fingerprint: &str,
    migration_plan: PackageMigrationPlanInput,
) -> PackageBuildRequest {
    let module_bytes = module_bytes(variant);
    let module = parse_module_yaml(&module_bytes).expect("package module parses");
    PackageBuildRequest {
        from_package_digest: prior_revision.map(str::to_owned),
        compiler_source_revision: SOURCE_REVISION.to_owned(),
        schema_fingerprint: schema_fingerprint.to_owned(),
        project: PackageSourceFile {
            path: "source/registry.yaml".to_owned(),
            bytes: project_bytes(&module_digest(&module)),
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
        .publish_to_directory(&package)
        .expect("package publishes");
    load_package(&package, &context).expect("published package loads with activation intent")
}

fn local_context() -> PackageLoadContext<'static> {
    PackageLoadContext {
        database_initialization_environment: "local",
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
    backfill_source_with_steps(request, None, true)
}

/// The rank backfill with its update statement optionally replaced and its
/// `SET NOT NULL` step optionally left out, so a rehearsal can be handed a
/// plan PostgreSQL or activation would refuse.
fn backfill_source_with_steps(
    request: BackfillSourceRequest<'_>,
    update_sql_override: Option<String>,
    constrain_rank: bool,
) -> ReviewedMigrationSource {
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
    let change = compiled_registry_change_set(prior, candidate, &current.package_digest)
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
    let update_sql = update_sql_override.unwrap_or_else(|| {
        format!(
            "UPDATE registry_data.{} SET {} = 1 WHERE record_id = ANY($1::pg_catalog.uuid[])",
            entity.physical_table, field.physical_name
        )
    });
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
    // The assertion grammar admits no sleep, so the slow assertion counts a
    // hundred million rows of a cross join over literal values.
    let values = "(VALUES (1), (2), (3), (4), (5), (6), (7), (8), (9), (10))";
    let outlasting = format!(
        "SELECT pg_catalog.count(*) > 0 FROM {}",
        ["a", "b", "c", "d", "e", "f", "g", "h"]
            .map(|alias| format!("{values} AS {alias} (v)"))
            .join(", ")
    );
    let pre_sql = match pre {
        AssertionMode::True => true_pre,
        AssertionMode::False => "SELECT false".to_owned(),
        AssertionMode::OutlastsStatementTimeout => outlasting.clone(),
    };
    let post_sql = match post {
        AssertionMode::True => true_post,
        AssertionMode::False => "SELECT false".to_owned(),
        AssertionMode::OutlastsStatementTimeout => outlasting,
    };
    let statement_timeout_ms = declared_statement_timeout_ms(pre, post);
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
        statement_timeout_ms,
        steps: std::iter::once(ReviewedMigrationStepDescriptor::ChunkedBackfill {
            id: "backfill-rank".to_owned(),
            entity_id: "asset".to_owned(),
            sql_path: update_path.clone(),
            objects: vec![object.clone()],
            cursor: ChunkCursorProtocol::RecordIdUuidArray,
            chunk_size: 2,
            max_total_rows: 10,
            lock_timeout_ms: 50,
            statement_timeout_ms,
            exact_affected_rows: true,
        })
        .chain(
            constrain_rank.then(|| ReviewedMigrationStepDescriptor::TransactionalSql {
                id: "set-rank-not-null".to_owned(),
                sql_path: alter_path.clone(),
                objects: vec![object],
                affected_rows: None,
            }),
        )
        .collect(),
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
        steps: std::iter::once((update_path, update_sql))
            .chain(constrain_rank.then_some((alter_path, alter_sql)))
            .collect(),
        pre: (pre_path, pre_sql),
        post: (post_path, post_sql),
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
    let change = compiled_registry_change_set(prior, candidate, &current.package_digest)
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
    let change = compiled_registry_change_set(prior, candidate, &current.package_digest)
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
            "SELECT active_activation_id::text
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
            &[&target.activation_id, &ENVELOPE_MEMBER_TAG],
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
    assert_eq!(row.get::<_, String>(0), target.activation_id);
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
) -> ReviewedMigrationSource {
    destructive_source_with_recovery_fault(id, current, prior, candidate, final_fingerprint, false)
}

fn destructive_recovery_source(
    id: &str,
    current: &ExpectedRegistryIdentity,
    prior: &CompiledRegistry,
    candidate: &CompiledRegistry,
    final_fingerprint: &str,
) -> ReviewedMigrationSource {
    destructive_source_with_recovery_fault(id, current, prior, candidate, final_fingerprint, true)
}

fn destructive_source_with_recovery_fault(
    id: &str,
    current: &ExpectedRegistryIdentity,
    prior: &CompiledRegistry,
    candidate: &CompiledRegistry,
    final_fingerprint: &str,
    recovery_fault: bool,
) -> ReviewedMigrationSource {
    let change = compiled_registry_change_set(prior, candidate, &current.package_digest)
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
        prior_package_digest: current.package_digest.clone(),
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
        proofs: None,
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

fn prepare_reviewed_candidate(
    current: &ExpectedRegistryIdentity,
    prior: &CompiledRegistry,
    fingerprint: &str,
    source: ReviewedMigrationSource,
) -> PreparedPackage {
    prepare_package(build_request(
        Variant::RankRequired,
        Some(&current.package_digest),
        fingerprint,
        PackageMigrationPlanInput::ReviewedSuccessor {
            prior_registry: Box::new(prior.clone()),
            prior_schema_fingerprint: current.schema_fingerprint.clone(),
            migrations: vec![source],
        },
    ))
    .expect("reviewed candidate prepares")
}

async fn rehearse(
    database: &TestDatabase,
    predecessor: &CompiledRegistry,
    predecessor_schema_fingerprint: &str,
    candidate: &PreparedPackage,
) -> Result<RehearsalOutcome, MigrationRehearsalError> {
    rehearse_successor_migration(
        &database.migration_config,
        &database.migration_role,
        &database.runtime_role,
        SuccessorMigrationRehearsal {
            predecessor,
            predecessor_schema_fingerprint,
            candidate,
        },
    )
    .await
}

async fn assert_rehearsal_database_clean(database: &TestDatabase) {
    let managed = database
        .admin
        .query_one(
            "SELECT pg_catalog.count(*)
               FROM pg_catalog.pg_class c
               JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
              WHERE n.nspname IN ('registry_internal', 'registry_data', 'registry_source',
                                  'registry_derived', 'registry_context')",
            &[],
        )
        .await
        .expect("managed schemas are counted")
        .get::<_, i64>(0);
    assert_eq!(managed, 0, "the rehearsal rolls back every managed object");
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
    let prior = compile_variant(Variant::RankRequired);
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
            "SELECT active_activation_id::text
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
    // Every live row carries its journal head, as rows written through the
    // runtime do, so a reviewed chunk can append the next revision.
    let (mut migration, migration_task) = database.connect_migration().await;
    let transaction = migration
        .transaction()
        .await
        .expect("backfill seed journal transaction starts");
    for index in 0..count {
        let record_id = Uuid::from_u128(index as u128 + 1);
        let snapshot = canonical(&serde_json::json!({
            "code": format!("c{index}"),
            "legacy": format!("legacy-{index}"),
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
            .expect("backfill seed revision inserts");
    }
    transaction
        .commit()
        .await
        .expect("backfill seed revisions commit");
    migration_task.abort();
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
                , active.activation_id.replace('\'', "''")
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

/// Writes one backup binding file, as an operator supplies it to `bregctl
/// apply --backup`, and returns its path.
fn write_backup_binding(
    directory: &std::path::Path,
    name: &str,
    binding: &ExternalBackupBinding,
) -> std::path::PathBuf {
    let path = directory.join(name);
    fs::write(&path, canonical(binding)).expect("backup binding writes");
    path
}

/// Writes an owner-only synthetic backup of the active registry beside its
/// fresh binding, and returns the binding file.
fn write_synthetic_backup(
    directory: &std::path::Path,
    current: &ExpectedRegistryIdentity,
    bytes: &[u8],
) -> std::path::PathBuf {
    let backup_path = directory.join("pattern.backup");
    fs::write(&backup_path, bytes).expect("synthetic backup writes");
    fs::set_permissions(&backup_path, fs::Permissions::from_mode(0o600))
        .expect("synthetic backup permissions close");
    write_backup_binding(
        directory,
        "pattern-binding.json",
        &ExternalBackupBinding {
            database_id: DATABASE.to_owned(),
            prior_package_digest: current.package_digest.clone(),
            prior_schema_fingerprint: current.schema_fingerprint.clone(),
            backup_file: backup_path.to_str().expect("UTF-8 backup path").to_owned(),
            sha256: digest(bytes),
            byte_length: bytes.len() as u64,
            created_at: OffsetDateTime::now_utc().format(&Rfc3339).unwrap(),
            max_age_seconds: 3600,
        },
    )
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
    request_for_deployment(database, package, precondition, deployment())
}

fn deployment() -> ActivationDeployment<'static> {
    ActivationDeployment::new(ENVIRONMENT, INSTANCE, DATABASE)
}

fn request_for_deployment<'a>(
    database: &'a TestDatabase,
    package: &'a VerifiedPackage,
    precondition: ApplyPrecondition<'a>,
    deployment: ActivationDeployment<'a>,
) -> ApplyVerifiedPackageRequest<'a> {
    ApplyVerifiedPackageRequest::new(
        &database.migration_config,
        package,
        deployment,
        precondition,
        ApplyRoles::new(&database.migration_role, &database.runtime_role),
        ApplyTimeouts::new(Duration::from_secs(1), Duration::from_secs(5))
            .expect("test timeouts are bounded"),
        database.activation_audit(),
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
             WHERE activation_id = (
                       SELECT activation_id FROM registry_internal.registry_migrations
                        WHERE package_digest = $1
                        ORDER BY apply_order DESC LIMIT 1
                   )
               AND step_id = $2",
            &[&package.package_digest(), &step_id],
        )
        .await
        .expect("step state reads");
    (row.get(0), row.get(1), row.get(2))
}

async fn ledger_snapshot(database: &TestDatabase) -> Vec<(String, String, String)> {
    database
        .admin
        .query(
            "SELECT package_digest, plan_kind, outcome
             FROM registry_internal.registry_migrations
             ORDER BY apply_order",
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
            "SELECT active_activation_id::text, maintenance_status,
                    maintenance_target_package_digest
             FROM registry_internal.registry_state WHERE singleton",
            &[],
        )
        .await
        .expect("maintenance state reads");
    assert_eq!(row.get::<_, String>(0), active.activation_id);
    assert_eq!(row.get::<_, String>(1), expected_status);
    assert_eq!(
        row.get::<_, Option<String>>(2).as_deref(),
        Some(target.package_digest())
    );
}

async fn assert_ready_target(database: &TestDatabase, expected: &ExpectedRegistryIdentity) {
    let row = database
        .admin
        .query_one(
            "SELECT state.active_activation_id::text, state.active_package_digest,
                    state.schema_fingerprint, state.maintenance_status,
                    state.maintenance_target_package_digest, ledger.outcome
             FROM registry_internal.registry_state AS state
             JOIN registry_internal.registry_migrations AS ledger
               ON ledger.activation_id = state.active_activation_id
             WHERE state.singleton",
            &[],
        )
        .await
        .expect("ready state reads");
    assert_eq!(row.get::<_, String>(0), expected.activation_id);
    assert_eq!(row.get::<_, String>(1), expected.package_digest);
    assert_eq!(row.get::<_, String>(2), expected.schema_fingerprint);
    assert_eq!(row.get::<_, String>(3), "ready");
    assert_eq!(row.get::<_, Option<String>>(4), None);
    assert_eq!(row.get::<_, String>(5), "applied");
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

/// The reviewed-migration history a backfill appended: how many records reached
/// revision 2 and the member count of each reviewed-migration commit, in
/// commit order.
async fn reviewed_migration_history(database: &TestDatabase) -> (i64, Vec<i64>) {
    let revised: i64 = database
        .admin
        .query_one(
            "SELECT count(*)
               FROM registry_internal.registry_revisions
              WHERE entity_id = 'asset'
                AND record_revision = 2
                AND predecessor_revision = 1",
            &[],
        )
        .await
        .expect("migration revisions count")
        .get(0);
    let commits = database
        .admin
        .query(
            "SELECT count(member.record_id)
               FROM registry_internal.registry_revision_commits AS commit
               JOIN registry_internal.registry_revision_commit_members AS member
                 ON member.commit_position = commit.commit_position
              WHERE commit.system_origin = 'breg-reviewed-migration-v1'
              GROUP BY commit.commit_position
              ORDER BY commit.commit_position",
            &[],
        )
        .await
        .expect("migration commits read")
        .iter()
        .map(|row| row.get::<_, i64>(0))
        .collect();
    (revised, commits)
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
    let current_catalog =
        registry_breg::postgres::ExpectedManagedCatalog::compiled(current_registry);
    reconcile_with_catalog(database, package, current, &current_catalog, execute).await
}

async fn reconcile_with_catalog(
    database: &TestDatabase,
    package: &VerifiedPackage,
    current: &ExpectedRegistryIdentity,
    current_catalog: &ExpectedManagedCatalog,
    execute: bool,
) -> Result<ReconcileReport, ReconcileError> {
    let audit = database.audit(
        AuditProfile::production_from_secret_bytes(vec![0x63; 32].into())
            .expect("test owns a keyed audit profile"),
    );
    reconcile_failed_migration(ReconcileRequest {
        config: &database.migration_config,
        target_package: package,
        current,
        current_catalog,
        migration_role: &database.migration_role,
        runtime_role: &database.runtime_role,
        timeouts: ReconcileTimeouts::new(Duration::from_secs(1), Duration::from_secs(5))
            .expect("test timeouts are bounded"),
        audit: if execute {
            ReconcileAudit::Execute(&audit)
        } else {
            ReconcileAudit::Assess(audit.profile())
        },
        operator_reference: RECONCILE_OPERATOR_CANARY,
    })
    .await
}

/// The identity one package activates to in this test's deployment. The
/// activation id is a deterministic stand-in; a test that asserts the active
/// identity replaces it with the id the ledger recorded.
fn target_identity(package: &VerifiedPackage) -> ExpectedRegistryIdentity {
    let manifest = package.manifest();
    ExpectedRegistryIdentity {
        package_id: manifest.package_id.clone(),
        database_id: DATABASE.to_owned(),
        package_digest: package.package_digest().to_owned(),
        activation_id: registry_breg::postgres::test_activation_id(package.package_digest()),
        schema_fingerprint: manifest.schema_fingerprint.clone(),
    }
}

/// The activation id the ledger recorded at one apply order.
async fn activation_at(database: &TestDatabase, apply_order: i64) -> String {
    database
        .admin
        .query_one(
            "SELECT activation_id::text FROM registry_internal.registry_migrations
             WHERE apply_order = $1",
            &[&apply_order],
        )
        .await
        .expect("the ledger records that apply order")
        .get(0)
}

/// The whole durable maintenance record an assessment must leave untouched:
/// the state row, every ledger row and step, and the audit entries.
async fn durable_snapshot(
    database: &TestDatabase,
) -> (
    Vec<(String, String, String)>,
    Vec<(String, Option<Uuid>, i64)>,
    Vec<String>,
    (String, String, Option<String>),
) {
    let steps = database
        .admin
        .query(
            "SELECT step.outcome, step.checkpoint_record_id, step.affected_rows
             FROM registry_internal.registry_migration_steps AS step
             JOIN registry_internal.registry_migrations AS ledger
               ON ledger.activation_id = step.activation_id
             ORDER BY ledger.apply_order, step.migration_ordinal, step.step_ordinal",
            &[],
        )
        .await
        .expect("step states read")
        .into_iter()
        .map(|row| (row.get(0), row.get(1), row.get(2)))
        .collect();
    let audit = database
        .audit_entries()
        .iter()
        .map(serde_json::Value::to_string)
        .collect();
    let state = database
        .admin
        .query_one(
            "SELECT active_activation_id::text, maintenance_status,
                    maintenance_target_package_digest
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

/// The reconciliation audit records carry identities, the plan shape, and
/// counts: every execution of `action` writes a request entry before its
/// transition and one correlated response entry after it, and the last
/// execution committed. The operator's own reference must reach them only as
/// a keyed hash.
async fn assert_reconcile_audit_is_minimized(database: &TestDatabase, action: &str) {
    let mut matched = Vec::new();
    for entry in database.audit_entries() {
        let text = entry.to_string();
        assert!(!text.contains(RECONCILE_OPERATOR_CANARY));
        if entry["schema"] == "breg-migration-reconcile-audit/v3" {
            assert!(text.contains(&format!("\"action\":\"{action}\"")));
            matched.push(entry);
        }
    }
    // Every execution is a request answered by one response under its
    // correlation; the last one committed.
    assert!(!matched.is_empty() && matched.len() % 2 == 0, "{matched:?}");
    for pair in matched.chunks(2) {
        assert_eq!(pair[0]["phase"], "request");
        assert_eq!(pair[1]["phase"], "response");
        assert_eq!(pair[0]["correlation"], pair[1]["correlation"]);
    }
    assert_eq!(matched[matched.len() - 1]["record"]["outcome"], "committed");
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
    let base = compile_variant(Variant::Base);
    let added = compile_variant(Variant::PatternAdded);
    let tightened = compile_variant(Variant::PatternTightened);
    let loosened = compile_variant(Variant::PatternLoosened);
    let removed = compile_variant(Variant::Base);
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
    let invalid = compile_variant(Variant::PatternInvalid);
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
            &[&Uuid::from_u128(91), &"invalid", &active.activation_id],
        )
        .await
        .unwrap();
    let prepared = prepare_package(build_request(
        Variant::PatternAdded,
        Some(&active.package_digest),
        &added_fp,
        PackageMigrationPlanInput::Successor {
            prior_registry: Box::new(base.clone()),
        },
    ))
    .unwrap();
    let addition = publish_and_load(prepared, local_context());
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
            active.package_digest
        )
        .into_bytes();
        let source = pattern_reviewed_source(&id, &active, &prior, &candidate, &target_fp);
        let package = prepare_and_load_reviewed(&active, &prior, variant, &target_fp, source);
        let directory = tempfile::tempdir().unwrap();
        let binding_file = write_synthetic_backup(directory.path(), &active, &backup_bytes);
        let binding = package.reviewed_migration_plan().unwrap().migrations()[0]
            .descriptor
            .backup_binding_path
            .as_deref()
            .unwrap();
        let evidence = [DestructiveBackupEvidence::new(binding, &binding_file)];
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
) -> ReviewedMigrationSource {
    use registry_breg::generated_ddl::field_pattern_constraint_name;
    let change = compiled_registry_change_set(prior, candidate, &current.package_digest)
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
        row_assertions: Vec::new(),
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn native_patterns_quote_apostrophes_and_backslashes_independent_of_session_settings() {
    let database = TestDatabase::create(1).await;
    let registry = compile_variant(Variant::PatternQuoted);
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
    let base = compile_variant(Variant::Base);
    let fingerprint = initial_fingerprint(&database, &base).await;
    // The local unsigned test policy permits exercising the activation defense
    // independently of the production pre-sign schema-test refusal.
    let prepared = prepare_package(build_request(
        Variant::PatternInvalid,
        None,
        &fingerprint,
        PackageMigrationPlanInput::InitialCompiledDdl,
    ))
    .unwrap();
    let invalid = publish_and_load(prepared, local_context());
    assert_value_free(
        apply(&database, &invalid, ApplyPrecondition::InitialActivation)
            .await
            .err(),
        MigrationError::FieldPatternSyntax {
            entity_id: "asset".to_owned(),
            field_id: "legacy".to_owned(),
        },
    );
    let row = database.admin.query_one("SELECT maintenance_status, maintenance_target_package_digest FROM registry_internal.registry_state WHERE singleton", &[]).await.unwrap();
    assert_eq!(row.get::<_, String>(0), "failed");
    assert_eq!(
        row.get::<_, Option<String>>(1).as_deref(),
        Some(invalid.package_digest())
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
        let prior = compile_variant(variant);
        let fingerprint = initial_fingerprint(&database, &prior).await;
        let prepared = prepare_package(build_request(
            variant,
            None,
            &fingerprint,
            PackageMigrationPlanInput::InitialCompiledDdl,
        ))
        .unwrap();
        let initial = publish_and_load(prepared, local_context());
        let active = apply(&database, &initial, ApplyPrecondition::InitialActivation)
            .await
            .unwrap();
        let invalid = compile_variant(Variant::PatternInvalid);
        // An unsigned test package supplies a synthetic fingerprint to reach
        // activation independently of the pre-sign native syntax refusal.
        let target_fingerprint = format!("sha256:{}", "f".repeat(64));
        let (package, error) = if reviewed {
            let bytes = b"-- Synthetic pre-activation pattern backup\n";
            let source = pattern_reviewed_source(
                "invalid-pattern",
                &active,
                &prior,
                &invalid,
                &target_fingerprint,
            );
            let package = prepare_and_load_reviewed(
                &active,
                &prior,
                Variant::PatternInvalid,
                &target_fingerprint,
                source,
            );
            let directory = tempfile::tempdir().unwrap();
            let path = write_synthetic_backup(directory.path(), &active, bytes);
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
                Some(&active.package_digest),
                &target_fingerprint,
                PackageMigrationPlanInput::Successor {
                    prior_registry: Box::new(prior.clone()),
                },
            ))
            .unwrap();
            let package = publish_and_load(prepared, local_context());
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
