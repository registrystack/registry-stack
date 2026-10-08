// SPDX-License-Identifier: Apache-2.0

#![cfg(all(feature = "postgres-test", feature = "runtime", feature = "tooling"))]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;
#[path = "support/source_bytes.rs"]
mod source_bytes;

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::http::{HeaderName, HeaderValue, Method, Request, StatusCode};
use postgres_harness::TestDatabase;
use registry_breg::api::{
    router, HttpService, ReadRuntimeIdentity, ReadinessProbe, ServiceFuture, VerifiedClaimValue,
    VerifiedRequestClaims,
};
use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_json;
use registry_breg::cursor::CursorCodec;
use registry_breg::migration::{
    apply_verified_package, ActivationDeployment, ApplyPrecondition, ApplyRoles, ApplyTimeouts,
    ApplyVerifiedPackageRequest,
};
use registry_breg::migration_plan::{
    MigrationRehearsalReceipt, ReviewedChangeCover, ReviewedMigrationDescriptor,
    ReviewedMigrationFile, ReviewedMigrationRecovery, ReviewedMigrationSource,
};
use registry_breg::package::{
    compiled_registry_change_set, load_package, prepare_package, CompiledRegistryChangeClass,
    CompiledRegistryChangeCode, PackageBuildRequest, PackageLoadContext, PackageMigrationPlanInput,
    PackageSourceFile, VerifiedPackage, FIXTURE_JOURNEYS_PATH,
};
use registry_breg::postgres::{
    managed_schema_fingerprint, reconcile_compiled_runtime_acl_for_test,
    rehearse_successor_migration, BaselineFingerprintDrift, ExpectedManagedCatalog,
    ExpectedRegistryIdentity, PostgresRecordMutationService, PostgresRecordReadService,
    RegistryLockKey, SuccessorMigrationRehearsal,
};
use registry_breg::startup::prepare_startup;
use registry_breg::CompiledRegistry;
use registry_platform_audit::AuditProfile;
use registry_platform_canonical_json::canonicalize_json;
use serde::Serialize;
use serde_json::{json, Value};
use tempfile::TempDir;
use tower::Service as _;
use uuid::Uuid;
use zeroize::Zeroizing;

const PACKAGE_ID: &str = "immediate-action-activation-registry";
const INSTANCE_ID: &str = "immediate-action-activation-instance";
const DATABASE_ID: &str = "immediate-action-activation-database";
const ENVIRONMENT: &str = "production";
const SOURCE_REVISION: &str = "immediate-action-activation-source";
const HOUSEHOLD_ID: &str = "00000000-0000-4000-8000-000000000100";
const FIXTURE_JOURNEYS: &[u8] = br#"apiVersion: id.registrystack.org/formats/breg/journeys/v1
kind: BRegJourneys
journeys: []
"#;
const ACTION_RESULTS_PRIMARY_KEY: &str = "registry_immediate_action_results_pkey";
const ACTION_RESULTS_TARGET_INDEX: &str = "registry_immediate_action_results_target_idx";

/// The legacy action-revision lookup reads immediate-action results by target
/// record revision under the history statement budget. A Registry that
/// declares immediate actions installs the index that lookup uses, and its
/// recorded fingerprint binds it. A Registry that declares none keeps exactly
/// the catalog it had before the index existed, so its fingerprint is
/// unchanged.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn action_result_target_index_follows_declared_immediate_actions() {
    let database = TestDatabase::create(4).await;
    let action_registry = Arc::new(compiled_registry(Variant::ActionV1));
    let action_fingerprint = initial_schema_fingerprint(&database, &action_registry).await;
    let action_package = publish_and_load(
        build_request(
            Variant::ActionV1,
            None,
            &action_fingerprint,
            PackageMigrationPlanInput::InitialCompiledDdl,
        ),
        package_context(),
    );
    let active_action = apply_package(
        &database,
        &action_package.package,
        ApplyPrecondition::InitialActivation,
    )
    .await;
    let indexes = action_result_indexes(&database).await;
    assert_eq!(
        indexes
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>(),
        vec![ACTION_RESULTS_PRIMARY_KEY, ACTION_RESULTS_TARGET_INDEX],
    );
    assert!(
        indexes[1]
            .1
            .ends_with("USING btree (target_entity_id, target_record_id, target_record_revision)"),
        "the target index covers the legacy lookup predicate: {}",
        indexes[1].1
    );
    drop_action_result_target_index(&database).await;
    assert_ne!(
        live_schema_fingerprint(&database, &action_registry).await,
        active_action.schema_fingerprint,
        "the recorded fingerprint binds the target index"
    );
    drop(action_package);
    database.cleanup().await;

    let database = TestDatabase::create(4).await;
    let plain_registry = Arc::new(compiled_registry(Variant::NoAction));
    let plain_package = prepare_initial_package(&database, &plain_registry).await;
    let active_plain = apply_package(
        &database,
        &plain_package.package,
        ApplyPrecondition::InitialActivation,
    )
    .await;
    assert_eq!(
        action_result_indexes(&database)
            .await
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>(),
        vec![ACTION_RESULTS_PRIMARY_KEY],
        "a Registry that declares no immediate action installs no target index"
    );
    // The catalog an earlier release installed has no target index; removing
    // it, if present, leaves the recorded fingerprint intact.
    drop_action_result_target_index(&database).await;
    assert_eq!(
        live_schema_fingerprint(&database, &plain_registry).await,
        active_plain.schema_fingerprint,
        "a Registry that declares no immediate action keeps its earlier fingerprint"
    );
    prepare_startup_for(&database, &plain_package)
        .await
        .expect("a Registry without immediate actions starts against its recorded catalog");
    drop(plain_package);
    database.cleanup().await;
}

/// A database an earlier release activated for a Registry that declares
/// immediate actions has no target index. The upgraded runtime keeps serving
/// it without an apply; a successor built with this code rehearses with the
/// advisory baseline drift, and that apply installs the index and reaches the
/// successor's fresh-install fingerprint.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn action_result_target_index_reaches_an_existing_activation_at_its_next_apply() {
    let database = TestDatabase::create(8).await;
    let initial_project = consent_project_bytes(false);
    let registry = Arc::new(compile_bytes(&initial_project));
    let fingerprint = initial_schema_fingerprint(&database, &registry).await;
    let initial = publish_and_load(
        build_request_for_project(
            initial_project.clone(),
            None,
            &fingerprint,
            PackageMigrationPlanInput::InitialCompiledDdl,
        ),
        package_context(),
    );
    let mut active = apply_package(
        &database,
        &initial.package,
        ApplyPrecondition::InitialActivation,
    )
    .await;

    // Reproduce the exact pre-index catalog and recorded package binding.
    // This fixture surgery represents an already deployed older binary; the
    // upgrade below uses the maintained rehearsal and apply APIs.
    drop_action_result_target_index(&database).await;
    let old_fingerprint = live_schema_fingerprint(&database, &registry).await;
    assert_ne!(old_fingerprint, fingerprint);
    let old_package = publish_and_load(
        build_request_for_project(
            initial_project,
            None,
            &old_fingerprint,
            PackageMigrationPlanInput::InitialCompiledDdl,
        ),
        package_context(),
    );
    active.schema_fingerprint = old_fingerprint.clone();
    active.package_digest = old_package.package.package_digest().to_owned();
    let (migration, task) = database.connect_migration().await;
    migration
        .execute(
            "UPDATE registry_internal.registry_state
                SET active_package_digest = $1, schema_fingerprint = $2
              WHERE singleton",
            &[&active.package_digest, &active.schema_fingerprint],
        )
        .await
        .expect("fixture rebinds the earlier package");
    migration
        .execute(
            "UPDATE registry_internal.registry_migrations
                SET package_digest = $1
              WHERE activation_id = $2::text::uuid",
            &[&active.package_digest, &active.activation_id],
        )
        .await
        .expect("fixture rebinds the earlier activation");
    drop(migration);
    task.abort();
    drop(initial);

    prepare_startup_for(&database, &old_package)
        .await
        .expect("the upgraded runtime serves the earlier catalog without an apply");
    assert_eq!(
        action_result_indexes(&database).await.len(),
        1,
        "startup installs nothing"
    );

    let successor_project = consent_project_bytes(true);
    let successor_registry = Arc::new(compile_bytes(&successor_project));
    let fresh = TestDatabase::create(2).await;
    let fresh_fingerprint = initial_schema_fingerprint(&fresh, &successor_registry).await;
    fresh.cleanup().await;
    let successor_request = || {
        build_request_for_project(
            successor_project.clone(),
            Some(active.package_digest.as_str()),
            &fresh_fingerprint,
            PackageMigrationPlanInput::Successor {
                prior_registry: Box::new((*registry).clone()),
            },
        )
    };
    let candidate = prepare_package(successor_request()).expect("successor package prepares");
    let rehearsal = TestDatabase::create(2).await;
    let outcome = rehearse_successor_migration(
        &rehearsal.migration_config,
        &rehearsal.migration_role,
        &rehearsal.runtime_role,
        SuccessorMigrationRehearsal {
            predecessor: &registry,
            predecessor_schema_fingerprint: &old_fingerprint,
            candidate: &candidate,
        },
    )
    .await
    .expect("the successor rehearses over the earlier baseline");
    assert_eq!(
        outcome.baseline_fingerprint_drift,
        Some(BaselineFingerprintDrift {
            signed: old_fingerprint.clone(),
            measured: fingerprint.clone(),
        }),
        "the earlier baseline drifts by the target index alone"
    );
    rehearsal.cleanup().await;
    drop(candidate);

    let successor = publish_and_load(successor_request(), package_context());
    let upgraded = apply_package(
        &database,
        &successor.package,
        ApplyPrecondition::Successor { current: &active },
    )
    .await;
    assert_eq!(upgraded.schema_fingerprint, fresh_fingerprint);
    assert_exact_catalog(&database, &successor_registry, &upgraded).await;
    assert_eq!(
        action_result_indexes(&database)
            .await
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>(),
        vec![ACTION_RESULTS_PRIMARY_KEY, ACTION_RESULTS_TARGET_INDEX],
    );
    prepare_startup_for(&database, &successor)
        .await
        .expect("the successor starts against the upgraded catalog");

    drop(successor);
    drop(old_package);
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reviewed_activation_updates_immediate_action_policies_and_consumed_keys() {
    let database = TestDatabase::create(8).await;

    let initial_registry = Arc::new(compiled_registry(Variant::NoAction));
    let initial = prepare_initial_package(&database, &initial_registry).await;
    let active_initial = apply_package(
        &database,
        &initial.package,
        ApplyPrecondition::InitialActivation,
    )
    .await;
    seed_household(&database, &initial_registry, &active_initial).await;

    let action_registry = Arc::new(compiled_registry(Variant::ActionV1));
    let action_package = prepare_reviewed_successor_package(
        &database,
        &initial_registry,
        &active_initial,
        &action_registry,
    )
    .await;
    assert!(
        action_package
            .package
            .manifest()
            .migration_plan
            .statements
            .iter()
            .any(|statement| statement.sql.starts_with("CREATE POLICY ")),
        "reviewed action-add activation must carry compiler-owned policy creates"
    );
    let active_action = apply_package(
        &database,
        &action_package.package,
        ApplyPrecondition::Successor {
            current: &active_initial,
        },
    )
    .await;
    assert_exact_catalog(&database, &action_registry, &active_action).await;
    assert_eq!(
        action_result_indexes(&database).await.len(),
        2,
        "adding the first immediate action installs the target index"
    );

    let action_app = action_router(&database, action_registry.clone(), active_action.clone());
    let claims_v1 = action_claims("registry:contact:register");
    let condition = condition_for(&action_app, claims_v1.clone()).await;
    let first = invoke_action(
        &action_app,
        claims_v1,
        "upgrade-stable-key",
        "Alex Example",
        &condition,
    )
    .await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.body);
    assert_eq!(entity_count(&database, &action_registry, "person").await, 1);
    assert_eq!(
        entity_count(&database, &action_registry, "group-membership").await,
        1
    );
    assert_eq!(receipt_count(&database).await, 1);

    let changed_registry = Arc::new(compiled_registry(Variant::ActionV2));
    let changed_package = prepare_reviewed_successor_package(
        &database,
        &action_registry,
        &active_action,
        &changed_registry,
    )
    .await;
    let changed_sql = changed_package
        .package
        .manifest()
        .migration_plan
        .statements
        .iter()
        .map(|statement| statement.sql.as_str())
        .collect::<Vec<_>>();
    assert!(changed_sql
        .iter()
        .any(|sql| sql.starts_with("DROP POLICY ")));
    assert!(changed_sql
        .iter()
        .any(|sql| sql.starts_with("CREATE POLICY ")));
    let active_changed = apply_package(
        &database,
        &changed_package.package,
        ApplyPrecondition::Successor {
            current: &active_action,
        },
    )
    .await;
    assert_exact_catalog(&database, &changed_registry, &active_changed).await;

    let stale_old_app = invoke_action(
        &action_app,
        action_claims("registry:contact:register"),
        "old-package-after-upgrade",
        "Old Runtime",
        &condition,
    )
    .await;
    assert_eq!(
        stale_old_app.status,
        StatusCode::SERVICE_UNAVAILABLE,
        "old runtime identity must be unavailable after successor activation"
    );

    let changed_app = action_router(&database, changed_registry.clone(), active_changed.clone());
    let same_key_after_contract_change = invoke_action(
        &changed_app,
        action_claims("registry:contact:register.v2"),
        "upgrade-stable-key",
        "Changed Contract",
        &condition,
    )
    .await;
    assert_eq!(
        same_key_after_contract_change.status,
        StatusCode::CONFLICT,
        "a consumed immediate-action key must not replay across a changed action contract"
    );
    assert_eq!(
        entity_count(&database, &changed_registry, "person").await,
        1
    );
    assert_eq!(
        entity_count(&database, &changed_registry, "group-membership").await,
        1
    );
    assert_eq!(receipt_count(&database).await, 1);

    let removed_registry = Arc::new(compiled_registry(Variant::NoAction));
    let removed_package = prepare_reviewed_successor_package(
        &database,
        &changed_registry,
        &active_changed,
        &removed_registry,
    )
    .await;
    let removed_sql = removed_package
        .package
        .manifest()
        .migration_plan
        .statements
        .iter()
        .map(|statement| statement.sql.as_str())
        .collect::<Vec<_>>();
    assert!(removed_sql
        .iter()
        .any(|sql| sql.starts_with("DROP POLICY ")));
    assert!(!removed_sql
        .iter()
        .any(|sql| sql.starts_with("CREATE POLICY ")));
    let active_removed = apply_package(
        &database,
        &removed_package.package,
        ApplyPrecondition::Successor {
            current: &active_changed,
        },
    )
    .await;
    assert_exact_catalog(&database, &removed_registry, &active_removed).await;
    assert_eq!(
        action_result_indexes(&database)
            .await
            .iter()
            .map(|(name, _)| name.as_str())
            .collect::<Vec<_>>(),
        vec![ACTION_RESULTS_PRIMARY_KEY],
        "removing the last immediate action removes the target index"
    );
    prepare_startup_for(&database, &removed_package)
        .await
        .expect("removed-action package starts against the exact candidate catalog");

    drop(removed_package);
    drop(changed_package);
    drop(action_package);
    drop(initial);
    database.cleanup().await;
}

/// A recipient organization added in a successor widens the recipient input
/// of every consent-issuing action without review. The activated catalog must
/// be exactly a fresh install of the successor, the action must accept the new
/// recipient, and a key consumed under the prior contract must not replay.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn recipient_added_successor_matches_fresh_install_and_refuses_consumed_keys() {
    let database = TestDatabase::create(8).await;

    let initial_project = consent_project_bytes(false);
    let initial_registry = Arc::new(compile_bytes(&initial_project));
    let initial_fingerprint = initial_schema_fingerprint(&database, &initial_registry).await;
    let initial = publish_and_load(
        build_request_for_project(
            initial_project,
            None,
            &initial_fingerprint,
            PackageMigrationPlanInput::InitialCompiledDdl,
        ),
        package_context(),
    );
    let active_initial = apply_package(
        &database,
        &initial.package,
        ApplyPrecondition::InitialActivation,
    )
    .await;

    let initial_app = action_router(&database, initial_registry.clone(), active_initial.clone());
    let subject = create_consent_subject(&initial_app).await;
    let before_add =
        record_consent(&initial_app, "unknown-recipient", &subject, NEW_RECIPIENT).await;
    assert_eq!(
        before_add.status,
        StatusCode::BAD_REQUEST,
        "the prior package must refuse a recipient it does not declare: {}",
        before_add.body
    );
    let first = record_consent(&initial_app, "consent-stable-key", &subject, "wfp").await;
    assert_eq!(first.status, StatusCode::OK, "{}", first.body);
    assert_eq!(receipt_count(&database).await, 1);

    let successor_project = consent_project_bytes(true);
    let successor_registry = Arc::new(compile_bytes(&successor_project));
    let changes = compiled_registry_change_set(
        &initial_registry,
        &successor_registry,
        &active_initial.package_digest,
    );
    let action_changes = changes
        .changes
        .iter()
        .filter(|change| change.target.member_id.as_deref() == Some("record-consent"))
        .map(|change| (change.code, change.class))
        .collect::<Vec<_>>();
    assert_eq!(
        action_changes,
        vec![(
            CompiledRegistryChangeCode::ActionVocabularyCodesAdded,
            CompiledRegistryChangeClass::CompatibleAdditive
        )],
        "{:#?}",
        changes.changes
    );
    // A fresh install of the successor measures the catalog the successor
    // binds, so activation succeeds only if the upgraded catalog is exactly
    // that fresh install.
    let fresh = TestDatabase::create(2).await;
    let fresh_fingerprint = initial_schema_fingerprint(&fresh, &successor_registry).await;
    fresh.cleanup().await;
    let successor = publish_and_load(
        build_request_for_project(
            successor_project,
            Some(active_initial.package_digest.as_str()),
            &fresh_fingerprint,
            PackageMigrationPlanInput::Successor {
                prior_registry: Box::new((*initial_registry).clone()),
            },
        ),
        package_context(),
    );
    let statements = successor
        .package
        .manifest()
        .migration_plan
        .statements
        .iter()
        .map(|statement| statement.id.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        statements,
        vec![
            "entity.consent-decision.policy.registry_action_rls_insert_18c2deac1df83f2bbf7c42e1.drop",
            "entity.consent-decision.policy.registry_action_rls_select_f13c1f2f332145d8ba2b99c4.drop",
            "entity.person.policy.registry_action_link_rls_lock_update_f8ce4ad62f29d16690131d38.drop",
            "entity.person.policy.registry_action_link_rls_select_28ce629670ff4cb963953600.drop",
            "entity.consent-decision.field.recipient.vocabulary",
        ],
        "a recipient addition retires changed action policies before replacing the recipient check"
    );
    // The recipient widens the action contract, whose fingerprint the action
    // policies embed, so the rehearsal must reconcile policies as activation
    // does to measure the same catalog as the fresh install.
    assert_eq!(
        successor_schema_fingerprint(&database, &successor.package).await,
        fresh_fingerprint
    );
    let active_successor = apply_package(
        &database,
        &successor.package,
        ApplyPrecondition::Successor {
            current: &active_initial,
        },
    )
    .await;
    assert_eq!(active_successor.schema_fingerprint, fresh_fingerprint);
    assert_exact_catalog(&database, &successor_registry, &active_successor).await;

    let successor_app = action_router(
        &database,
        successor_registry.clone(),
        active_successor.clone(),
    );
    let added = record_consent(&successor_app, "new-recipient", &subject, NEW_RECIPIENT).await;
    assert_eq!(added.status, StatusCode::OK, "{}", added.body);
    assert_eq!(receipt_count(&database).await, 2);

    let replay = record_consent(&successor_app, "consent-stable-key", &subject, "wfp").await;
    assert_eq!(
        replay.status,
        StatusCode::CONFLICT,
        "a key consumed under the prior package must not replay under the successor: {}",
        replay.body
    );
    assert_eq!(receipt_count(&database).await, 2);
    assert_eq!(
        entity_count(&database, &successor_registry, "consent-decision").await,
        2
    );

    drop(successor);
    drop(initial);
    database.cleanup().await;
}

#[derive(Clone, Copy, Debug)]
enum Variant {
    NoAction,
    ActionV1,
    ActionV2,
}

struct PublishedPackage {
    _root: TempDir,
    package_root: PathBuf,
    package: VerifiedPackage,
}

async fn prepare_initial_package(
    database: &TestDatabase,
    registry: &Arc<CompiledRegistry>,
) -> PublishedPackage {
    let fingerprint = initial_schema_fingerprint(database, registry).await;
    publish_and_load(
        build_request(
            Variant::NoAction,
            None,
            &fingerprint,
            PackageMigrationPlanInput::InitialCompiledDdl,
        ),
        package_context(),
    )
}

async fn prepare_reviewed_successor_package(
    database: &TestDatabase,
    prior: &Arc<CompiledRegistry>,
    active: &ExpectedRegistryIdentity,
    candidate: &Arc<CompiledRegistry>,
) -> PublishedPackage {
    let variant = variant_for(candidate);
    let provisional = publish_and_load(
        build_request(
            variant,
            Some(active.package_digest.as_str()),
            &active.schema_fingerprint,
            PackageMigrationPlanInput::ReviewedSuccessor {
                prior_registry: Box::new((**prior).clone()),
                prior_schema_fingerprint: active.schema_fingerprint.clone(),
                migrations: vec![metadata_only_source(
                    prior,
                    candidate,
                    &active.package_digest,
                    &active.schema_fingerprint,
                    &active.schema_fingerprint,
                )],
            },
        ),
        package_context(),
    );
    let target_fingerprint = successor_schema_fingerprint(database, &provisional.package).await;
    drop(provisional);
    publish_and_load(
        build_request(
            variant,
            Some(active.package_digest.as_str()),
            &target_fingerprint,
            PackageMigrationPlanInput::ReviewedSuccessor {
                prior_registry: Box::new((**prior).clone()),
                prior_schema_fingerprint: active.schema_fingerprint.clone(),
                migrations: vec![metadata_only_source(
                    prior,
                    candidate,
                    &active.package_digest,
                    &active.schema_fingerprint,
                    &target_fingerprint,
                )],
            },
        ),
        package_context(),
    )
}

fn build_request(
    variant: Variant,
    prior_revision: Option<&str>,
    schema_fingerprint: &str,
    migration_plan: PackageMigrationPlanInput,
) -> PackageBuildRequest {
    build_request_for_project(
        project_bytes(variant),
        prior_revision,
        schema_fingerprint,
        migration_plan,
    )
}

fn build_request_for_project(
    project: Vec<u8>,
    prior_revision: Option<&str>,
    schema_fingerprint: &str,
    migration_plan: PackageMigrationPlanInput,
) -> PackageBuildRequest {
    PackageBuildRequest {
        from_package_digest: prior_revision.map(str::to_owned),
        compiler_source_revision: SOURCE_REVISION.to_owned(),
        schema_fingerprint: schema_fingerprint.to_owned(),
        project: PackageSourceFile {
            path: "registry.json".to_owned(),
            bytes: project,
        },
        modules: Vec::new(),
        fixture_journeys: PackageSourceFile {
            path: FIXTURE_JOURNEYS_PATH.to_owned(),
            bytes: FIXTURE_JOURNEYS.to_vec(),
        },
        migration_plan,
    }
}

fn publish_and_load(
    request: PackageBuildRequest,
    context: PackageLoadContext<'_>,
) -> PublishedPackage {
    let prepared = prepare_package(request).expect("package prepares");
    let root = tempfile::Builder::new()
        .prefix("registry-immediate-action-activation-package-")
        .tempdir_in(
            std::env::temp_dir()
                .canonicalize()
                .expect("canonical temporary root"),
        )
        .expect("package tempdir creates");
    let package_root = root.path().join("package");
    prepared
        .publish_to_directory(&package_root)
        .expect("package publishes");
    let package = load_package(&package_root, &context).expect("package loads and verifies");
    PublishedPackage {
        _root: root,
        package_root,
        package,
    }
}

async fn apply_package(
    database: &TestDatabase,
    package: &VerifiedPackage,
    precondition: ApplyPrecondition<'_>,
) -> ExpectedRegistryIdentity {
    apply_verified_package(ApplyVerifiedPackageRequest::new(
        &database.migration_config,
        package,
        ActivationDeployment::new(ENVIRONMENT, INSTANCE_ID, DATABASE_ID),
        precondition,
        ApplyRoles::new(&database.migration_role, &database.runtime_role),
        ApplyTimeouts::new(Duration::from_secs(1), Duration::from_secs(5))
            .expect("test apply timeouts are bounded"),
        database.activation_audit(),
    ))
    .await
    .expect("verified package applies")
}

async fn initial_schema_fingerprint(
    database: &TestDatabase,
    registry: &CompiledRegistry,
) -> String {
    let (mut migration, task) = database.connect_migration().await;
    let transaction = migration
        .transaction()
        .await
        .expect("initial fingerprint transaction starts");
    registry_breg::postgres::install_compiled_schema(
        &transaction,
        registry,
        &database.runtime_role,
    )
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
        .expect("initial fingerprint transaction rolls back");
    task.abort();
    fingerprint
}

async fn successor_schema_fingerprint(
    database: &TestDatabase,
    package: &VerifiedPackage,
) -> String {
    let (mut migration, task) = database.connect_migration().await;
    let transaction = migration
        .transaction()
        .await
        .expect("successor fingerprint transaction starts");
    for statement in &package.manifest().migration_plan.statements {
        transaction
            .batch_execute(&statement.sql)
            .await
            .expect("successor DDL rehearses");
    }
    reconcile_compiled_runtime_acl_for_test(
        &transaction,
        package.registry(),
        &database.runtime_role,
    )
    .await
    .expect("successor fingerprint reconciles the production runtime ACL");
    let fingerprint = managed_schema_fingerprint(
        &transaction,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(package.registry()),
    )
    .await
    .expect("successor fingerprint computes");
    transaction
        .rollback()
        .await
        .expect("successor fingerprint transaction rolls back");
    task.abort();
    fingerprint
}

async fn assert_exact_catalog(
    database: &TestDatabase,
    registry: &CompiledRegistry,
    identity: &ExpectedRegistryIdentity,
) {
    let (migration, task) = database.connect_migration().await;
    let fingerprint = managed_schema_fingerprint(
        &migration,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(registry),
    )
    .await
    .expect("activated schema matches the exact candidate catalog");
    assert_eq!(fingerprint, identity.schema_fingerprint);
    task.abort();
}

async fn live_schema_fingerprint(database: &TestDatabase, registry: &CompiledRegistry) -> String {
    let (migration, task) = database.connect_migration().await;
    let fingerprint = managed_schema_fingerprint(
        &migration,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(registry),
    )
    .await
    .expect("live fingerprint computes");
    task.abort();
    fingerprint
}

async fn action_result_indexes(database: &TestDatabase) -> Vec<(String, String)> {
    database
        .admin
        .query(
            "SELECT index_class.relname::text, pg_catalog.pg_get_indexdef(index_class.oid)
               FROM pg_catalog.pg_index AS x
               JOIN pg_catalog.pg_class AS index_class ON index_class.oid = x.indexrelid
              WHERE x.indrelid = 'registry_internal.registry_immediate_action_results'::regclass
              ORDER BY index_class.relname",
            &[],
        )
        .await
        .expect("action result indexes read")
        .iter()
        .map(|row| (row.get(0), row.get(1)))
        .collect()
}

async fn drop_action_result_target_index(database: &TestDatabase) {
    let (migration, task) = database.connect_migration().await;
    migration
        .batch_execute(&format!(
            "DROP INDEX IF EXISTS registry_internal.{ACTION_RESULTS_TARGET_INDEX}"
        ))
        .await
        .expect("fixture drops the target index");
    task.abort();
}

fn metadata_only_source(
    prior: &CompiledRegistry,
    candidate: &CompiledRegistry,
    prior_revision: &str,
    prior_schema_fingerprint: &str,
    final_schema_fingerprint: &str,
) -> ReviewedMigrationSource {
    let change_set = compiled_registry_change_set(prior, candidate, prior_revision);
    let mut covers = change_set
        .changes
        .iter()
        .filter(|change| {
            change.class != registry_breg::package::CompiledRegistryChangeClass::CompatibleAdditive
        })
        .map(ReviewedChangeCover::from)
        .collect::<Vec<_>>();
    covers.sort();
    let base = "modules/core/migrations/action-policy";
    let descriptor = ReviewedMigrationDescriptor {
        id: "action-policy".to_owned(),
        change_class: registry_breg::package::CompiledRegistryChangeClass::AccessOrDisclosureChange,
        covers,
        recovery: ReviewedMigrationRecovery::ExactTargetResume,
        history: None,
        lock_timeout_ms: 10_000,
        statement_timeout_ms: 60_000,
        steps: Vec::new(),
        pre_assertions: Vec::new(),
        post_assertions: Vec::new(),
        rehearsal_receipt_path: format!("{base}/rehearsal.json"),
        backup_binding_path: None,
    };
    let descriptor_bytes = canonical(&descriptor);
    let receipt = MigrationRehearsalReceipt {
        prior_package_digest: prior_revision.to_owned(),
        prior_schema_fingerprint: prior_schema_fingerprint.to_owned(),
        plan_sha256: digest(&descriptor_bytes),
        sql_sha256: Vec::new(),
        assertion_sha256: Vec::new(),
        fixture_inventory: Vec::new(),
        postgres_major: 16,
        row_assertions: Vec::new(),
        final_schema_fingerprint: final_schema_fingerprint.to_owned(),
        proofs: None,
    };
    ReviewedMigrationSource {
        module_id: "core".to_owned(),
        descriptor: ReviewedMigrationFile {
            path: format!("{base}/descriptor.json"),
            bytes: descriptor_bytes,
        },
        files: vec![ReviewedMigrationFile {
            path: descriptor.rehearsal_receipt_path,
            bytes: canonical(&receipt),
        }],
    }
}

async fn prepare_startup_for(
    database: &TestDatabase,
    package: &PublishedPackage,
) -> registry_breg::startup::Result<registry_breg::startup::VerifiedStartup> {
    let pool = database
        .runtime_config
        .build_pool()
        .expect("runtime pool builds");
    let mut runtime = pool.get_for_test().await.expect("runtime connects");
    prepare_startup(
        &package.package_root,
        &package_context(),
        DATABASE_ID,
        &mut runtime,
        &database.migration_role,
        &database.runtime_role,
    )
    .await
}

fn package_context() -> PackageLoadContext<'static> {
    PackageLoadContext {
        database_initialization_environment: ENVIRONMENT,
    }
}

fn action_router(
    database: &TestDatabase,
    registry: Arc<CompiledRegistry>,
    identity: ExpectedRegistryIdentity,
) -> axum::Router {
    let pool = database.runtime_config.build_pool().expect("pool builds");
    let lock_key = RegistryLockKey::derive(PACKAGE_ID).expect("lock key derives");
    let audit = database.audit(
        AuditProfile::production_from_secret_bytes(vec![0x8d; 32].into())
            .expect("test audit profile is keyed"),
    );
    let cursors = Arc::new(
        CursorCodec::new(Zeroizing::new(vec![0x51; 32]), Duration::from_secs(300))
            .expect("cursor codec builds"),
    );
    let reads = Arc::new(PostgresRecordReadService::new(
        pool.clone(),
        registry.clone(),
        identity.clone(),
        lock_key,
        Duration::from_secs(2),
        audit.clone(),
        cursors.clone(),
    ));
    let mutations = Arc::new(PostgresRecordMutationService::new(
        pool,
        registry.clone(),
        identity.clone(),
        INSTANCE_ID,
        lock_key,
        Duration::from_secs(2),
        audit,
    ));
    router(Arc::new(
        HttpService::new(
            registry,
            ReadRuntimeIdentity {
                package_revision: identity.activation_id,
                schema_fingerprint: identity.schema_fingerprint,
            },
            reads,
            Arc::new(AlwaysReady),
            cursors,
        )
        .with_postgres_mutations(mutations),
    ))
}

async fn condition_for(app: &axum::Router, claims: VerifiedRequestClaims) -> Value {
    let response = response_parts(
        send(
            app,
            Method::POST,
            "/v1/actions/register-household-contact/target-conditions",
            Some(claims),
            &[("content-type", "application/json")],
            serde_json::to_vec(&json!({"input": {"householdId": HOUSEHOLD_ID}}))
                .expect("condition request serializes"),
        )
        .await,
    )
    .await;
    assert_eq!(response.status, StatusCode::OK, "{}", response.body);
    response.body["preconditions"].clone()
}

async fn invoke_action(
    app: &axum::Router,
    claims: VerifiedRequestClaims,
    key: &str,
    legal_name: &str,
    preconditions: &Value,
) -> ResponseParts {
    response_parts(
        send(
            app,
            Method::POST,
            "/v1/actions/register-household-contact",
            Some(claims),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", key),
            ],
            serde_json::to_vec(&json!({
                "input": {
                    "householdId": HOUSEHOLD_ID,
                    "personCode": "P-001",
                    "legalName": legal_name,
                    "jurisdiction": "zone-a"
                },
                "preconditions": preconditions
            }))
            .expect("action request serializes"),
        )
        .await,
    )
    .await
}

async fn seed_household(
    database: &TestDatabase,
    registry: &CompiledRegistry,
    identity: &ExpectedRegistryIdentity,
) {
    let household = &registry.entities()["household"];
    let table = &household.physical_table;
    let code = &household.fields["household-code"].physical_name;
    let jurisdiction = &household.fields["jurisdiction"].physical_name;
    database
        .admin
        .execute(
            &format!(
                "INSERT INTO registry_data.{table}
                    (record_id, record_revision, record_lifecycle, active_package_revision, {code}, {jurisdiction})
                 VALUES ($1, 1, 'active', $2, 'H-001', 'zone-a')",
                table = quote(table),
                code = quote(code),
                jurisdiction = quote(jurisdiction),
            ),
            &[
                &Uuid::parse_str(HOUSEHOLD_ID).expect("household UUID"),
                &identity.activation_id,
            ],
        )
        .await
        .expect("administrator seeds an existing household target");
}

async fn entity_count(
    database: &TestDatabase,
    registry: &CompiledRegistry,
    entity_id: &str,
) -> i64 {
    let entity = &registry.entities()[entity_id];
    database
        .admin
        .query_one(
            &format!(
                "SELECT count(*) FROM registry_data.{}",
                quote(&entity.physical_table)
            ),
            &[],
        )
        .await
        .expect("administrator counts entity rows")
        .get(0)
}

async fn receipt_count(database: &TestDatabase) -> i64 {
    database
        .admin
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_idempotency
              WHERE result_kind = 'immediate_action'",
            &[],
        )
        .await
        .expect("administrator counts immediate-action receipts")
        .get(0)
}

async fn send(
    app: &axum::Router,
    method: Method,
    uri: &str,
    claims: Option<VerifiedRequestClaims>,
    headers: &[(&str, &str)],
    body: Vec<u8>,
) -> axum::response::Response {
    let mut request = Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::from(body))
        .expect("request builds");
    for (name, value) in headers {
        request.headers_mut().append(
            HeaderName::from_bytes(name.as_bytes()).expect("test header name"),
            HeaderValue::from_str(value).expect("test header value"),
        );
    }
    if let Some(claims) = claims {
        request.extensions_mut().insert(claims);
    }
    let mut app = app.clone();
    app.call(request).await.expect("router returns response")
}

struct ResponseParts {
    status: StatusCode,
    body: Value,
}

async fn response_parts(response: axum::response::Response) -> ResponseParts {
    let status = response.status();
    let bytes = to_bytes(response.into_body(), 2 * 1024 * 1024)
        .await
        .expect("response body is bounded")
        .to_vec();
    let body = if bytes.is_empty() {
        json!({})
    } else {
        serde_json::from_slice(&bytes).expect("response body is JSON")
    };
    ResponseParts { status, body }
}

fn action_claims(scope: &str) -> VerifiedRequestClaims {
    let mut direct_claims = BTreeMap::new();
    direct_claims.insert(
        "jurisdiction".to_owned(),
        VerifiedClaimValue::direct_string("zone-a").expect("direct claim"),
    );
    VerifiedRequestClaims::authenticated(
        "registry_principal",
        "registrar-principal",
        BTreeSet::from([scope.to_owned()]),
        Some("contact-registration".to_owned()),
        direct_claims,
    )
    .expect("authenticated action claims are valid")
}

fn compiled_registry(variant: Variant) -> CompiledRegistry {
    let project = parse_project_json(&project_bytes(variant)).expect("activation project parses");
    compile_project(&project, &[], CompileProfile::Production).expect("activation project compiles")
}

fn variant_for(registry: &CompiledRegistry) -> Variant {
    match registry
        .actions()
        .actions
        .first()
        .and_then(|action| action.permissions.first())
        .and_then(|grant| grant.required_scopes.iter().next())
        .map(String::as_str)
    {
        Some("registry:contact:register") => Variant::ActionV1,
        Some("registry:contact:register.v2") => Variant::ActionV2,
        _ => Variant::NoAction,
    }
}

fn project_bytes(variant: Variant) -> Vec<u8> {
    let required_scope = match variant {
        Variant::ActionV1 => Some("registry:contact:register"),
        Variant::ActionV2 => Some("registry:contact:register.v2"),
        Variant::NoAction => None,
    };
    let actions = if required_scope.is_some() {
        r#""actions":[{
            "id":"register-household-contact",
            "inputs":[
              {"id":"household","apiName":"householdId","type":"reference","target":"household","required":true,"classification":"restricted"},
              {"id":"person-code","apiName":"personCode","type":"string","maxLength":64,"required":true,"classification":"restricted"},
              {"id":"legal-name","apiName":"legalName","type":"string","maxLength":160,"required":true,"classification":"restricted"},
              {"id":"jurisdiction","apiName":"jurisdiction","type":"string","maxLength":64,"required":true,"classification":"restricted"}
            ],
            "effects":[
              {"id":"person","target":{"entity":"person"},"operation":"create",
                "set":{"person-code":{"fromField":"person-code"},"legal-name":{"fromField":"legal-name"},"jurisdiction":{"fromField":"jurisdiction"}}},
              {"id":"membership","target":{"entity":"group-membership"},"operation":"create",
                "set":{"person":{"fromEffect":"person"},"household":{"fromField":"household"},"jurisdiction":{"fromField":"jurisdiction"}}},
              {"id":"household","target":{"fromField":"household"},"operation":"patch",
                "set":{"contact-person":{"fromEffect":"person"}}}
            ]
          }],"#
            .to_owned()
    } else {
        String::new()
    };
    let access_profiles = required_scope.map_or_else(
        || r#""accessProfiles":[]"#.to_owned(),
        |scope| {
            format!(
                r#""accessProfiles":[{{
                  "id":"contact-registrar",
                  "default":true,
                  "principalClaim":"registry_principal",
                  "requiredScopes":["{scope}"],
                  "requiredPurposes":["contact-registration"],
                  "permissions":[{{
                    "action":"register-household-contact",
                    "operations":["invoke"],
                    "targets":[
                      {{"entity":"household","rowBoundaries":[{{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}}]}},
                      {{"entity":"person","rowBoundaries":[{{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}}]}},
                      {{"entity":"group-membership","rowBoundaries":[{{"field":"jurisdiction","claim":"jurisdiction","operator":"equals"}}]}}
                    ],
                    "results":["person","membership","household"]
                  }}]
                }}]"#
            )
        },
    );
    format!(
        r#"{{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{{"id":"{PACKAGE_ID}","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"}},
          "package":{{"sourceRevision":"{SOURCE_REVISION}"}},
          "entities":[{{
            "id":"person","primaryDataset":"test-dataset","route":"people","mutationMode":"mutable",
            "constraints":[{{"kind":"unique","fields":["person-code"]}}],
            "fields":[
              {{"id":"person-code","apiName":"personCode","type":"string","maxLength":64,"required":true,"classification":"restricted"}},
              {{"id":"legal-name","apiName":"legalName","type":"string","maxLength":160,"required":true,"classification":"restricted"}},
              {{"id":"jurisdiction","apiName":"jurisdiction","type":"string","maxLength":64,"required":true,"classification":"restricted"}}
            ]
          }},{{
            "id":"household","primaryDataset":"test-dataset","route":"households","mutationMode":"mutable",
            "fields":[
              {{"id":"household-code","type":"string","maxLength":64,"required":true,"classification":"restricted"}},
              {{"id":"jurisdiction","apiName":"jurisdiction","type":"string","maxLength":64,"required":true,"classification":"restricted"}},
              {{"id":"contact-person","apiName":"contactPerson","type":"reference","target":"person","classification":"restricted"}}
            ]
          }},{{
            "id":"group-membership","primaryDataset":"test-dataset","route":"group-memberships","mutationMode":"mutable",
            "fields":[
              {{"id":"person","type":"reference","target":"person","required":true,"classification":"restricted"}},
              {{"id":"household","type":"reference","target":"household","required":true,"classification":"restricted"}},
              {{"id":"jurisdiction","apiName":"jurisdiction","type":"string","maxLength":64,"required":true,"classification":"restricted"}}
            ]
          }}],
          {actions}
          {access_profiles}
        }}"#
    )
    .into_bytes()
}

const CONSENT_PROJECT: &str = include_str!("fixtures/consent-access.yaml");
const NEW_RECIPIENT: &str = "ngo-gamma";

/// The consent enforcement fixture bound to this test's package identity,
/// optionally with one more recipient organization.
fn consent_project_bytes(with_new_recipient: bool) -> Vec<u8> {
    let mut project: serde_json::Value = serde_json::from_slice(&source_bytes::source_bytes(
        &registry_breg::contract::parse_project_yaml(CONSENT_PROJECT.as_bytes())
            .expect("consent fixture parses"),
    ))
    .expect("consent fixture source is JSON");
    project["registry"]["id"] = json!(PACKAGE_ID);
    project["package"] = json!({
        "sourceRevision": SOURCE_REVISION,
    });
    if with_new_recipient {
        project["recipients"]["organizations"]
            .as_array_mut()
            .expect("the fixture declares recipient organizations")
            .push(json!({
                "id": NEW_RECIPIENT,
                "name": "NGO Gamma",
                "contact": "privacy@ngo-gamma.example.test",
                "clients": [],
            }));
    }
    serde_json::to_vec(&project).expect("consent project serializes")
}

fn compile_bytes(project: &[u8]) -> CompiledRegistry {
    let project = parse_project_json(project).expect("project parses");
    compile_project(&project, &[], CompileProfile::Production).expect("project compiles")
}

fn steward_claims() -> VerifiedRequestClaims {
    VerifiedRequestClaims::authenticated(
        "principal",
        "steward",
        BTreeSet::from(["records:manage".to_owned()]),
        None,
        BTreeMap::new(),
    )
    .expect("authenticated steward claims are valid")
}

async fn create_consent_subject(app: &axum::Router) -> String {
    let response = response_parts(
        send(
            app,
            Method::POST,
            "/v1/records/persons?accessProfile=steward",
            Some(steward_claims()),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", "consent-subject"),
            ],
            serde_json::to_vec(&json!({"data": {"givenName": "Alex", "district": "north"}}))
                .expect("person request serializes"),
        )
        .await,
    )
    .await;
    assert_eq!(response.status, StatusCode::CREATED, "{}", response.body);
    response.body["data"]["recordIdentifier"]
        .as_str()
        .expect("a created record carries its identifier")
        .to_owned()
}

async fn record_consent(
    app: &axum::Router,
    key: &str,
    subject: &str,
    recipient: &str,
) -> ResponseParts {
    response_parts(
        send(
            app,
            Method::POST,
            "/v1/actions/record-consent?accessProfile=steward",
            Some(steward_claims()),
            &[
                ("content-type", "application/json"),
                ("idempotency-key", key),
            ],
            serde_json::to_vec(&json!({"input": {
                "subject": subject,
                "recipient": recipient,
                "purpose": "food-assistance",
                "scope": "food-targeting",
                "decision": "given",
                "effectiveAt": "2026-01-01T00:00:00Z",
            }}))
            .expect("consent request serializes"),
        )
        .await,
    )
    .await
}

fn canonical<T: Serialize>(value: &T) -> Vec<u8> {
    canonicalize_json(&serde_json::to_value(value).expect("value serializes"))
        .expect("value canonicalizes")
}

fn digest(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};

    let digest = Sha256::digest(bytes);
    format!("sha256:{}", hex(&digest))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn quote(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

#[cfg(not(unix))]
fn set_private_permissions(_path: &std::path::Path) {}

struct AlwaysReady;

impl ReadinessProbe for AlwaysReady {
    fn is_ready(&self) -> ServiceFuture<'_, bool> {
        Box::pin(async { true })
    }
}
