// SPDX-License-Identifier: Apache-2.0

use super::derived_upgrade_tests::assert_startup;
use super::policy_upgrade_tests::fresh_fingerprint;
use super::*;
use registry_breg::mutation::{MutationBody, MutationPlan, MutationRequest, MutationTransaction};
use registry_breg::package::{
    CompiledRegistryChange, CompiledRegistryChangeTarget, CompiledRegistryChangeTargetKind,
    CompiledRegistryMigrationBaseline, FIXTURE_JOURNEYS_PATH,
};
use registry_platform_audit::AuditProfile;
use serde_json::Map;

const INDEX_STATEMENT: &str = "entity.neutral-record.index.code-idx";
const INDEX_DROP_STATEMENT: &str = "entity.neutral-record.index.code-idx.drop";
const INDEXED_SOURCE_VIEW: &str = "entity.neutral-record.source-view";
const OTHER_SOURCE_VIEW: &str = "entity.second-record.source-view";
const CURRENT_VIEW_OPTIONS: &str = "WITH (security_invoker=true)";
const EARLIER_VIEW_OPTIONS: &str = "WITH (security_invoker=true, security_barrier=true)";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn governed_successor_installs_the_record_timer_store_for_the_exact_baseline_package() {
    let legacy = BaselinePreTimerStoreRegistry::activate().await;
    assert_eq!(
        load_package(&legacy.root, &local_context()).err(),
        Some(PackageError::EngineFeatureUpgradeRequired)
    );
    assert_timer_store_absent(&legacy.database).await;

    let (successor_root, successor) = legacy.successor(legacy.current_fingerprint.clone());
    assert!(
        successor.manifest().migration_plan.statements.is_empty(),
        "the immediately preceding compiler already emits this compiler's project DDL"
    );
    assert_eq!(
        successor.manifest().migration_plan.changes,
        vec![CompiledRegistryChange {
            class: CompiledRegistryChangeClass::CompatibleAdditive,
            code: CompiledRegistryChangeCode::RecordTimerStoreAdded,
            target: CompiledRegistryChangeTarget {
                kind: CompiledRegistryChangeTargetKind::Registry,
                record_type_id: None,
                member_id: None,
            },
        }]
    );

    let upgraded = apply_package(
        &legacy.database,
        &successor,
        ApplyPrecondition::Successor {
            current: &legacy.active,
        },
        Duration::from_secs(1),
        Duration::from_secs(5),
    )
    .await
    .expect("the governed successor installs the engine-owned timer store");
    assert_eq!(upgraded.schema_fingerprint, legacy.current_fingerprint);
    assert_empty_timer_store(&legacy.database).await;
    assert_startup(&legacy.database, &successor_root, &successor).await;
    assert_ordinary_record_write(&legacy.database, &successor, &upgraded).await;

    legacy.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn record_timer_store_upgrade_rolls_back_when_the_target_catalog_does_not_match() {
    let legacy = BaselinePreTimerStoreRegistry::activate().await;
    let wrong_fingerprint = fingerprint(250);
    let (_successor_root, successor) = legacy.successor(wrong_fingerprint.clone());

    let error = apply_package(
        &legacy.database,
        &successor,
        ApplyPrecondition::Successor {
            current: &legacy.active,
        },
        Duration::from_secs(1),
        Duration::from_secs(5),
    )
    .await
    .expect_err("a target fingerprint mismatch refuses the upgrade");
    assert_eq!(
        error,
        MigrationError::SchemaFingerprintMismatchAfterMaintenance {
            declared: wrong_fingerprint,
            measured: legacy.current_fingerprint.clone(),
        }
    );
    assert_timer_store_absent(&legacy.database).await;
    let active_digest: String = legacy
        .database
        .admin
        .query_one(
            "SELECT active_package_digest FROM registry_internal.registry_state WHERE singleton",
            &[],
        )
        .await
        .expect("active package identity remains readable")
        .get(0);
    assert_eq!(active_digest, legacy.active.package_digest);
    let outcome: String = legacy
        .database
        .admin
        .query_one(
            "SELECT outcome FROM registry_internal.registry_migrations
              WHERE package_digest=$1",
            &[&successor.package_digest()],
        )
        .await
        .expect("the refused engine-feature activation remains in the ledger")
        .get(0);
    assert_eq!(outcome, "failed");

    legacy.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn engine_transition_composes_with_a_governed_compiler_ddl_refresh() {
    let earlier = EarlierCompilerRegistry::activate_before_record_timer_store().await;
    assert_timer_store_absent(&earlier.database).await;
    let mut request = indexed_request(indexed_module_bytes(OtherEntity::Unchanged));
    request.from_package_digest = Some(earlier.active.package_digest.clone());
    request
        .schema_fingerprint
        .clone_from(&earlier.current_fingerprint);
    request.migration_plan = PackageMigrationPlanInput::SuccessorFromBaseline {
        prior_baseline: Box::new(earlier.predecessor.migration_baseline().clone()),
    };
    let (successor_root, successor) = publish_and_load(request);
    assert!(
        !successor.manifest().migration_plan.statements.is_empty(),
        "the concrete earlier compiler boundary requires its governed DDL refresh"
    );
    assert_eq!(
        successor.manifest().migration_plan.changes,
        vec![CompiledRegistryChange {
            class: CompiledRegistryChangeClass::CompatibleAdditive,
            code: CompiledRegistryChangeCode::RecordTimerStoreAdded,
            target: CompiledRegistryChangeTarget {
                kind: CompiledRegistryChangeTargetKind::Registry,
                record_type_id: None,
                member_id: None,
            },
        }]
    );

    let upgraded = apply_package(
        &earlier.database,
        &successor,
        ApplyPrecondition::Successor {
            current: &earlier.active,
        },
        Duration::from_secs(1),
        Duration::from_secs(5),
    )
    .await
    .expect("the governed refresh and engine transition install together");
    assert_eq!(upgraded.schema_fingerprint, earlier.current_fingerprint);
    assert!(earlier
        .authored_index_definition()
        .await
        .ends_with(", record_id)"));
    assert_eq!(
        earlier.source_view_options().await,
        ["security_invoker=true"; 2]
    );
    assert_empty_timer_store(&earlier.database).await;
    assert_startup(&earlier.database, &successor_root, &successor).await;

    earlier.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn immutable_legacy_package_refuses_when_its_catalog_predates_current_collations() {
    let legacy = ImmutableLegacyRegistry::activate().await;
    assert_eq!(
        load_package(&legacy.root, &local_context()).err(),
        Some(PackageError::EngineFeatureUpgradeRequired)
    );
    let (_successor_root, successor) = legacy.successor(legacy.current_fingerprint.clone());
    let error = apply_package(
        &legacy.database,
        &successor,
        ApplyPrecondition::Successor {
            current: &legacy.active,
        },
        Duration::from_secs(1),
        Duration::from_secs(5),
    )
    .await
    .expect_err("the old collation contract cannot be represented as a timer-only upgrade");
    let (declared, measured) = match error {
        MigrationError::SchemaFingerprintMismatchAfterMaintenance { declared, measured } => {
            (declared, measured)
        }
        error => panic!("unexpected immutable-legacy refusal: {error:?}"),
    };
    assert_eq!(declared, legacy.current_fingerprint);
    assert_ne!(measured, declared);
    assert_timer_store_absent(&legacy.database).await;

    legacy.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unchanged_successor_over_an_earlier_compilers_package_refreshes_compiler_owned_ddl_once(
) {
    let earlier = EarlierCompilerRegistry::activate().await;
    assert!(!earlier
        .authored_index_definition()
        .await
        .contains("record_id"));
    assert_eq!(
        earlier.source_view_options().await,
        ["security_barrier=true,security_invoker=true"; 2]
    );

    let mut request = indexed_request(indexed_module_bytes(OtherEntity::Unchanged));
    request.from_package_digest = Some(earlier.active.package_digest.clone());
    request
        .schema_fingerprint
        .clone_from(&earlier.current_fingerprint);
    request.migration_plan = PackageMigrationPlanInput::SuccessorFromBaseline {
        prior_baseline: Box::new(earlier.predecessor.migration_baseline().clone()),
    };
    let (successor_root, successor) = publish_and_load(request);
    let plan = &successor.manifest().migration_plan;
    assert!(plan.changes.is_empty(), "the project did not change");
    assert_eq!(
        statement_ids(&successor),
        [
            INDEX_DROP_STATEMENT,
            INDEX_STATEMENT,
            INDEXED_SOURCE_VIEW,
            OTHER_SOURCE_VIEW,
        ]
    );
    assert!(
        !registry_breg::migration::successor_plan_is_empty(&successor),
        "the refresh is work an apply accepts"
    );

    let upgraded = apply_package(
        &earlier.database,
        &successor,
        ApplyPrecondition::Successor {
            current: &earlier.active,
        },
        Duration::from_secs(1),
        Duration::from_secs(5),
    )
    .await
    .expect("the unchanged successor refreshes the earlier compiler's DDL");
    assert_eq!(upgraded.schema_fingerprint, earlier.current_fingerprint);
    assert!(earlier
        .authored_index_definition()
        .await
        .ends_with(", record_id)"));
    assert_eq!(
        earlier.source_view_options().await,
        ["security_invoker=true"; 2]
    );
    assert_startup(&earlier.database, &successor_root, &successor).await;

    // The applied successor is this compiler's package, so the packages
    // planned over it owe the database no refresh.
    let same_compiler = load_predecessor_package(successor_root.path(), &local_context())
        .expect("the applied successor is a readable predecessor");
    assert_eq!(
        same_compiler.migration_baseline().generated_ddl_sha256,
        Some(script_digest(&successor.registry().ddl().script()))
    );
    let mut unchanged = indexed_request(indexed_module_bytes(OtherEntity::Unchanged));
    unchanged.from_package_digest = Some(upgraded.package_digest.clone());
    unchanged
        .schema_fingerprint
        .clone_from(&earlier.current_fingerprint);
    unchanged.migration_plan = PackageMigrationPlanInput::SuccessorFromBaseline {
        prior_baseline: Box::new(same_compiler.migration_baseline().clone()),
    };
    let (_unchanged_root, unchanged) = publish_and_load(unchanged);
    assert!(unchanged.manifest().migration_plan.statements.is_empty());
    assert!(registry_breg::migration::successor_plan_is_empty(
        &unchanged
    ));

    let mut changed = indexed_request(indexed_module_bytes(OtherEntity::GainsAField));
    let changed_fingerprint = fresh_fingerprint(
        prepare_package(changed.clone())
            .expect("changed model compiles")
            .registry(),
    )
    .await;
    changed.from_package_digest = Some(upgraded.package_digest.clone());
    changed.schema_fingerprint.clone_from(&changed_fingerprint);
    changed.migration_plan = PackageMigrationPlanInput::SuccessorFromBaseline {
        prior_baseline: Box::new(same_compiler.migration_baseline().clone()),
    };
    let (changed_root, changed) = publish_and_load(changed);
    let changed_ids = statement_ids(&changed);
    assert!(changed_ids.contains(&OTHER_SOURCE_VIEW));
    for id in &changed_ids {
        assert!(
            id.starts_with("entity.second-record."),
            "{id} is not part of the change to the other entity"
        );
    }
    let index_before = earlier.authored_index_oid().await;
    let advanced = apply_package(
        &earlier.database,
        &changed,
        ApplyPrecondition::Successor { current: &upgraded },
        Duration::from_secs(1),
        Duration::from_secs(5),
    )
    .await
    .expect("the same-compiler successor applies its own change only");
    assert_eq!(advanced.schema_fingerprint, changed_fingerprint);
    assert_eq!(
        earlier.authored_index_oid().await,
        index_before,
        "the authored index is not built again"
    );
    assert_startup(&earlier.database, &changed_root, &changed).await;

    earlier.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_model_change_over_an_earlier_compilers_package_carries_the_refresh_too() {
    let earlier = EarlierCompilerRegistry::activate().await;

    let mut request = indexed_request(indexed_module_bytes(OtherEntity::GainsAField));
    let changed_fingerprint = fresh_fingerprint(
        prepare_package(request.clone())
            .expect("changed model compiles")
            .registry(),
    )
    .await;
    request.from_package_digest = Some(earlier.active.package_digest.clone());
    request.schema_fingerprint.clone_from(&changed_fingerprint);
    request.migration_plan = PackageMigrationPlanInput::SuccessorFromBaseline {
        prior_baseline: Box::new(earlier.predecessor.migration_baseline().clone()),
    };
    let (successor_root, successor) = publish_and_load(request);
    let ids = statement_ids(&successor);
    // The other entity gains its column, and the entity the change does not
    // touch still has its index rebuilt and its source view replaced.
    for id in [
        INDEX_DROP_STATEMENT,
        INDEX_STATEMENT,
        INDEXED_SOURCE_VIEW,
        OTHER_SOURCE_VIEW,
    ] {
        assert_eq!(
            ids.iter().filter(|planned| **planned == id).count(),
            1,
            "{id} is planned once"
        );
    }
    assert!(ids
        .iter()
        .any(|id| id.starts_with("entity.second-record.") && *id != OTHER_SOURCE_VIEW));

    let upgraded = apply_package(
        &earlier.database,
        &successor,
        ApplyPrecondition::Successor {
            current: &earlier.active,
        },
        Duration::from_secs(1),
        Duration::from_secs(5),
    )
    .await
    .expect("the changed successor refreshes the earlier compiler's DDL");
    assert_eq!(upgraded.schema_fingerprint, changed_fingerprint);
    assert!(earlier
        .authored_index_definition()
        .await
        .ends_with(", record_id)"));
    assert_eq!(
        earlier.source_view_options().await,
        ["security_invoker=true"; 2]
    );
    assert_startup(&earlier.database, &successor_root, &successor).await;

    let same_compiler = load_predecessor_package(successor_root.path(), &local_context())
        .expect("the applied successor is a readable predecessor");
    let mut unchanged = indexed_request(indexed_module_bytes(OtherEntity::GainsAField));
    unchanged.from_package_digest = Some(upgraded.package_digest.clone());
    unchanged
        .schema_fingerprint
        .clone_from(&changed_fingerprint);
    unchanged.migration_plan = PackageMigrationPlanInput::SuccessorFromBaseline {
        prior_baseline: Box::new(same_compiler.migration_baseline().clone()),
    };
    let (_unchanged_root, unchanged) = publish_and_load(unchanged);
    assert!(registry_breg::migration::successor_plan_is_empty(
        &unchanged
    ));

    earlier.finish().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_reviewed_change_over_an_earlier_compilers_package_carries_the_refresh_too() {
    let earlier = EarlierCompilerRegistry::activate().await;

    let mut request = indexed_request(indexed_module_bytes(OtherEntity::Rerouted));
    let candidate = prepare_package(request.clone())
        .expect("changed model compiles")
        .registry()
        .clone();
    // A route is not part of the schema, so the reviewed successor ends at
    // the fingerprint this compiler gives the unchanged model.
    assert_eq!(
        fresh_fingerprint(&candidate).await,
        earlier.current_fingerprint
    );
    let baseline = earlier.predecessor.migration_baseline();
    let changes = registry_breg::package::compiled_registry_change_set_from_baseline(
        baseline,
        &candidate,
        &earlier.active.package_digest,
    );
    request.from_package_digest = Some(earlier.active.package_digest.clone());
    request
        .schema_fingerprint
        .clone_from(&earlier.current_fingerprint);
    request.migration_plan = PackageMigrationPlanInput::ReviewedSuccessorFromBaseline {
        prior_baseline: Box::new(baseline.clone()),
        prior_schema_fingerprint: earlier.active.schema_fingerprint.clone(),
        migrations: vec![metadata_only_review_source(
            &changes.changes,
            &earlier.active.package_digest,
            &earlier.active.schema_fingerprint,
            &earlier.current_fingerprint,
        )],
    };
    let (successor_root, successor) = publish_and_load(request);
    // The reviewed executor drops every managed read view once the plan
    // carries a view statement, so the plan creates the complete view set.
    let ids = statement_ids(&successor);
    assert_eq!(ids[..2], [INDEX_DROP_STATEMENT, INDEX_STATEMENT]);
    for id in [INDEXED_SOURCE_VIEW, OTHER_SOURCE_VIEW] {
        assert_eq!(
            ids.iter().filter(|planned| **planned == id).count(),
            1,
            "{id} is planned once"
        );
    }

    let upgraded = apply_package(
        &earlier.database,
        &successor,
        ApplyPrecondition::Successor {
            current: &earlier.active,
        },
        Duration::from_secs(1),
        Duration::from_secs(5),
    )
    .await
    .expect("the reviewed successor refreshes the earlier compiler's DDL");
    assert_eq!(upgraded.schema_fingerprint, earlier.current_fingerprint);
    assert!(earlier
        .authored_index_definition()
        .await
        .ends_with(", record_id)"));
    assert_eq!(
        earlier.source_view_options().await,
        ["security_invoker=true"; 2]
    );
    assert_startup(&earlier.database, &successor_root, &successor).await;

    earlier.finish().await;
}

const PRE_TIMER_STORE_BASELINE_REVISION: &str = "9623438128e700ebd14f346bd01a231c2be990df";

/// Exact package bytes from the immediately preceding compiler, with a
/// database bootstrapped from the same source and compiler-owned DDL.
struct BaselinePreTimerStoreRegistry {
    database: TestDatabase,
    migration_task: tokio::task::JoinHandle<()>,
    root: PathBuf,
    predecessor: registry_breg::package::VerifiedPredecessorPackage,
    active: ExpectedRegistryIdentity,
    current_fingerprint: String,
}

impl BaselinePreTimerStoreRegistry {
    async fn activate() -> Self {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/pre-record-timer-store-package/package");
        let predecessor = load_predecessor_package(&root, &local_context())
            .expect("the exact baseline package is a governed predecessor");
        let package_document: Value = serde_json::from_slice(
            &fs::read(root.join("package.json")).expect("baseline package manifest reads"),
        )
        .expect("baseline package manifest parses");
        assert_eq!(
            package_document["manifest"]["compiler"]["sourceRevision"],
            PRE_TIMER_STORE_BASELINE_REVISION
        );
        let baseline_ddl =
            fs::read_to_string(root.join("database/ddl.sql")).expect("baseline DDL reads");
        assert_eq!(
            predecessor
                .migration_baseline()
                .generated_ddl_sha256
                .as_deref(),
            Some(script_digest(&baseline_ddl).as_str()),
            "the predecessor baseline is bound to the exact generated DDL"
        );

        let project_bytes =
            fs::read(root.join("source/registry.yaml")).expect("baseline source reads");
        let fixture_journeys =
            fs::read(root.join(FIXTURE_JOURNEYS_PATH)).expect("baseline journeys read");
        let mut request = PackageBuildRequest {
            from_package_digest: None,
            compiler_source_revision: PRE_TIMER_STORE_BASELINE_REVISION.to_owned(),
            schema_fingerprint: predecessor.schema_fingerprint().to_owned(),
            project: PackageSourceFile {
                path: "source/registry.yaml".to_owned(),
                bytes: project_bytes,
            },
            modules: Vec::new(),
            fixture_journeys: PackageSourceFile {
                path: FIXTURE_JOURNEYS_PATH.to_owned(),
                bytes: fixture_journeys,
            },
            migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
        };
        let registry = prepare_package(request.clone())
            .expect("the current compiler accepts the timer-free baseline source")
            .registry()
            .clone();
        let current_fingerprint = fresh_fingerprint(&registry).await;
        let current_ddl_sha256 = script_digest(&registry.ddl().script());
        assert_eq!(
            predecessor
                .migration_baseline()
                .generated_ddl_sha256
                .as_deref(),
            Some(current_ddl_sha256.as_str()),
            "the immediately preceding compiler already emits the same project DDL"
        );
        request.schema_fingerprint.clone_from(&current_fingerprint);
        let (_bootstrap_root, current_package) = publish_and_load(request);
        let database = TestDatabase::create(1).await;
        let mut active = apply_package(
            &database,
            &current_package,
            ApplyPrecondition::InitialActivation,
            Duration::from_secs(1),
            Duration::from_secs(5),
        )
        .await
        .expect("the current timer-free package bootstraps the exact source");

        let (migration, migration_task) = database.connect_migration().await;
        migration
            .batch_execute(
                "DROP FUNCTION registry_internal.prune_record_timer_retention(integer);
                 DROP TABLE registry_internal.registry_record_timer_attempts;
                 DROP TABLE registry_internal.registry_record_timer_current;
                 DROP TABLE registry_internal.registry_record_timer_generations;
                 DROP TABLE registry_internal.registry_record_timer_bindings;
                 DROP TABLE registry_internal.registry_record_timer_control;",
            )
            .await
            .expect("the fixture removes only the engine store the predecessor predates");
        active.package_digest = predecessor.package_digest().to_owned();
        active.schema_fingerprint = predecessor.schema_fingerprint().to_owned();
        migration
            .execute(
                "UPDATE registry_internal.registry_state
                    SET active_package_digest=$1, schema_fingerprint=$2
                  WHERE singleton",
                &[&active.package_digest, &active.schema_fingerprint],
            )
            .await
            .expect("fixture records the exact baseline package identity");
        migration
            .execute(
                "UPDATE registry_internal.registry_migrations
                    SET package_digest=$1
                  WHERE activation_id=$2::text::uuid",
                &[&active.package_digest, &active.activation_id],
            )
            .await
            .expect("fixture activation ledger names the exact baseline package");
        drop(migration);

        Self {
            database,
            migration_task,
            root,
            predecessor,
            active,
            current_fingerprint,
        }
    }

    fn successor(
        &self,
        schema_fingerprint: String,
    ) -> (TempRoot, registry_breg::package::VerifiedPackage) {
        self.successor_with_baseline(
            schema_fingerprint,
            self.predecessor.migration_baseline().clone(),
        )
    }

    fn successor_with_baseline(
        &self,
        schema_fingerprint: String,
        prior_baseline: CompiledRegistryMigrationBaseline,
    ) -> (TempRoot, registry_breg::package::VerifiedPackage) {
        let project_bytes =
            fs::read(self.root.join("source/registry.yaml")).expect("baseline source reads");
        let fixture_journeys =
            fs::read(self.root.join(FIXTURE_JOURNEYS_PATH)).expect("baseline journeys read");
        publish_and_load(PackageBuildRequest {
            from_package_digest: Some(self.active.package_digest.clone()),
            compiler_source_revision: PRE_TIMER_STORE_BASELINE_REVISION.to_owned(),
            schema_fingerprint,
            project: PackageSourceFile {
                path: "source/registry.yaml".to_owned(),
                bytes: project_bytes,
            },
            modules: Vec::new(),
            fixture_journeys: PackageSourceFile {
                path: FIXTURE_JOURNEYS_PATH.to_owned(),
                bytes: fixture_journeys,
            },
            migration_plan: PackageMigrationPlanInput::SuccessorFromBaseline {
                prior_baseline: Box::new(prior_baseline),
            },
        })
    }

    async fn finish(self) {
        self.migration_task.abort();
        self.database.cleanup().await;
    }
}

/// Exact immutable predecessor bytes with a synthetic database bootstrap.
/// The bootstrap uses the same source, generated entity DDL, package identity,
/// and recorded fingerprint, then removes only the engine store that release
/// predates.
struct ImmutableLegacyRegistry {
    database: TestDatabase,
    migration_task: tokio::task::JoinHandle<()>,
    root: PathBuf,
    predecessor: registry_breg::package::VerifiedPredecessorPackage,
    active: ExpectedRegistryIdentity,
    current_fingerprint: String,
}

impl ImmutableLegacyRegistry {
    async fn activate() -> Self {
        let root =
            PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/native-minimal-package");
        let predecessor = load_predecessor_package(&root, &local_context())
            .expect("the immutable legacy package is a governed predecessor");
        let project_bytes =
            fs::read(root.join("source/registry.yaml")).expect("fixture source reads");
        let fixture_journeys =
            fs::read(root.join(FIXTURE_JOURNEYS_PATH)).expect("fixture journeys read");
        let mut request = PackageBuildRequest {
            from_package_digest: None,
            compiler_source_revision: "native-minimal-format-fixture".to_owned(),
            schema_fingerprint: predecessor.schema_fingerprint().to_owned(),
            project: PackageSourceFile {
                path: "source/registry.yaml".to_owned(),
                bytes: project_bytes,
            },
            modules: Vec::new(),
            fixture_journeys: PackageSourceFile {
                path: FIXTURE_JOURNEYS_PATH.to_owned(),
                bytes: fixture_journeys,
            },
            migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
        };
        let registry = prepare_package(request.clone())
            .expect("timer-free package compiles")
            .registry()
            .clone();
        let legacy_ddl = fs::read_to_string(root.join("database/ddl.sql"))
            .expect("the immutable predecessor DDL reads");
        let legacy_ddl_sha256 = script_digest(&legacy_ddl);
        let package_document: Value = serde_json::from_slice(
            &fs::read(root.join("package.json")).expect("the immutable package manifest reads"),
        )
        .expect("the immutable package manifest is JSON");
        let legacy_statements = package_document["manifest"]["migrationPlan"]["statements"]
            .as_array()
            .expect("the immutable migration statements are present")
            .iter()
            .filter(|statement| statement["kind"] != "schema")
            .map(|statement| {
                statement["sql"]
                    .as_str()
                    .expect("the immutable migration statement carries SQL")
                    .to_owned()
            })
            .collect::<Vec<_>>();
        assert_eq!(
            predecessor
                .migration_baseline()
                .generated_ddl_sha256
                .as_deref(),
            Some(legacy_ddl_sha256.as_str()),
            "the synthetic database bootstrap uses the immutable predecessor's hash-bound DDL"
        );
        let current_fingerprint = fresh_fingerprint(&registry).await;
        request.schema_fingerprint.clone_from(&current_fingerprint);
        let (_bootstrap_root, current_package) = publish_and_load(request);
        let database = TestDatabase::create(1).await;
        let mut active = apply_package(
            &database,
            &current_package,
            ApplyPrecondition::InitialActivation,
            Duration::from_secs(1),
            Duration::from_secs(5),
        )
        .await
        .expect("the current timer-free package applies before fixture downgrade");

        let (migration, migration_task) = database.connect_migration().await;
        let table = quote_identifier(&registry.entities()["contact"].physical_table);
        migration
            .batch_execute(&format!(
                "DROP VIEW registry_source.\"contact\";
                 DROP TABLE registry_data.{table} CASCADE;
                 DROP FUNCTION registry_internal.prune_record_timer_retention(integer);
                 DROP TABLE registry_internal.registry_record_timer_attempts;
                 DROP TABLE registry_internal.registry_record_timer_current;
                 DROP TABLE registry_internal.registry_record_timer_generations;
                 DROP TABLE registry_internal.registry_record_timer_bindings;
                 DROP TABLE registry_internal.registry_record_timer_control;"
            ))
            .await
            .expect("fixture removes only the platform tables the legacy engine predates");
        for statement in legacy_statements {
            migration
                .batch_execute(&statement)
                .await
                .expect("the immutable predecessor statement installs");
        }
        active.package_digest = predecessor.package_digest().to_owned();
        active.schema_fingerprint = predecessor.schema_fingerprint().to_owned();
        migration
            .execute(
                "UPDATE registry_internal.registry_state
                    SET active_package_digest=$1, schema_fingerprint=$2
                  WHERE singleton",
                &[&active.package_digest, &active.schema_fingerprint],
            )
            .await
            .expect("fixture records the legacy active package");
        migration
            .execute(
                "UPDATE registry_internal.registry_migrations
                    SET package_digest=$1
                  WHERE activation_id=$2::text::uuid",
                &[&active.package_digest, &active.activation_id],
            )
            .await
            .expect("fixture activation ledger names the legacy package");
        drop(migration);

        Self {
            database,
            migration_task,
            root,
            predecessor,
            active,
            current_fingerprint,
        }
    }

    fn successor(
        &self,
        schema_fingerprint: String,
    ) -> (TempRoot, registry_breg::package::VerifiedPackage) {
        let project_bytes =
            fs::read(self.root.join("source/registry.yaml")).expect("fixture source reads");
        let fixture_journeys =
            fs::read(self.root.join(FIXTURE_JOURNEYS_PATH)).expect("fixture journeys read");
        publish_and_load(PackageBuildRequest {
            from_package_digest: Some(self.active.package_digest.clone()),
            compiler_source_revision: "native-minimal-format-fixture".to_owned(),
            schema_fingerprint,
            project: PackageSourceFile {
                path: "source/registry.yaml".to_owned(),
                bytes: project_bytes,
            },
            modules: Vec::new(),
            fixture_journeys: PackageSourceFile {
                path: FIXTURE_JOURNEYS_PATH.to_owned(),
                bytes: fixture_journeys,
            },
            migration_plan: PackageMigrationPlanInput::SuccessorFromBaseline {
                prior_baseline: Box::new(self.predecessor.migration_baseline().clone()),
            },
        })
    }
}

async fn timer_store_exists(database: &TestDatabase) -> bool {
    database
        .admin
        .query_one(
            "SELECT to_regclass('registry_internal.registry_record_timer_control') IS NOT NULL",
            &[],
        )
        .await
        .expect("timer control catalog state reads")
        .get(0)
}

async fn assert_timer_store_absent(database: &TestDatabase) {
    let absent: bool = database
        .admin
        .query_one(
            "SELECT to_regclass('registry_internal.registry_record_timer_control') IS NULL
                    AND to_regclass('registry_internal.registry_record_timer_bindings') IS NULL
                    AND to_regclass('registry_internal.registry_record_timer_generations') IS NULL
                    AND to_regclass('registry_internal.registry_record_timer_current') IS NULL
                    AND to_regclass('registry_internal.registry_record_timer_attempts') IS NULL
                    AND to_regprocedure('registry_internal.prune_record_timer_retention(integer)') IS NULL",
            &[],
        )
        .await
        .expect("pre-timer engine catalog absence reads")
        .get(0);
    assert!(
        absent,
        "the pre-timer fixture and a rolled-back upgrade must omit every timer table and the retention function"
    );
}

async fn assert_empty_timer_store(database: &TestDatabase) {
    assert!(timer_store_exists(database).await);
    let retention_function_exists: bool = database
        .admin
        .query_one(
            "SELECT to_regprocedure('registry_internal.prune_record_timer_retention(integer)') IS NOT NULL",
            &[],
        )
        .await
        .expect("timer retention function catalog state reads")
        .get(0);
    assert!(
        retention_function_exists,
        "the governed engine-feature upgrade installs the timer retention function"
    );
    for table in [
        "registry_record_timer_bindings",
        "registry_record_timer_generations",
        "registry_record_timer_current",
        "registry_record_timer_attempts",
    ] {
        let count: i64 = database
            .admin
            .query_one(
                &format!("SELECT count(*)::bigint FROM registry_internal.{table}"),
                &[],
            )
            .await
            .expect("timer ledger table reads")
            .get(0);
        assert_eq!(count, 0, "{table}");
    }
    let control_rows: i64 = database
        .admin
        .query_one(
            "SELECT count(*)::bigint FROM registry_internal.registry_record_timer_control",
            &[],
        )
        .await
        .expect("timer control reads")
        .get(0);
    assert_eq!(control_rows, 1);
}

async fn assert_ordinary_record_write(
    database: &TestDatabase,
    package: &registry_breg::package::VerifiedPackage,
    identity: &ExpectedRegistryIdentity,
) {
    let before = database
        .admin
        .query_one(
            "SELECT
               (SELECT count(*)::bigint FROM registry_internal.registry_revisions),
               (SELECT count(*)::bigint FROM registry_internal.registry_idempotency),
               (SELECT count(*)::bigint FROM registry_internal.registry_revision_commits),
               (SELECT count(*)::bigint FROM registry_internal.registry_revision_commit_members),
               (SELECT count(*)::bigint FROM registry_internal.registry_record_timer_generations)",
            &[],
        )
        .await
        .expect("the post-upgrade durability baseline reads");
    let claims = ClaimContext::for_compiled(
        package.registry(),
        "contact",
        Some("upgrade-test-principal".to_owned()),
        "directory-editor",
        Some("directory-administration".to_owned()),
        vec![registry_breg::postgres::RowBoundaryContext::Equals {
            field: "jurisdiction".to_owned(),
            value: "upgrade-test".to_owned(),
        }],
    )
    .expect("the immutable package's writer profile admits exact claims");
    let pool = database
        .runtime_config
        .build_pool()
        .expect("runtime pool builds after upgrade");
    let mut client = pool
        .get_for_test()
        .await
        .expect("runtime connects after upgrade");
    let lock_key = RegistryLockKey::derive(&identity.package_id)
        .expect("the upgraded package lock key derives");
    let coordinator = MutationTransaction::new(
        lock_key,
        Duration::from_secs(1),
        identity.clone(),
        "historical-upgrade-test",
        database.audit(
            AuditProfile::production_from_secret_bytes(vec![0x6b; 32].into())
                .expect("the test audit key is valid"),
        ),
    );
    let plan = MutationPlan::from_compiled(package.registry(), "records.contact.create")
        .expect("the ordinary create route is compiler-bound");
    let outcome = coordinator
        .execute(
            &mut client,
            MutationRequest {
                plan: &plan,
                idempotency_key: "historical-upgrade-create",
                claims: &claims,
                record_id: None,
                expected_etag: None,
                body: MutationBody::Create(Map::from_iter([
                    ("name".to_owned(), Value::String("Upgrade test".to_owned())),
                    (
                        "email".to_owned(),
                        Value::String("upgrade@example.test".to_owned()),
                    ),
                    (
                        "jurisdiction".to_owned(),
                        Value::String("upgrade-test".to_owned()),
                    ),
                ])),
                response_fields: BTreeSet::from([
                    "name".to_owned(),
                    "email".to_owned(),
                    "jurisdiction".to_owned(),
                ]),
                representation: registry_breg::record_profile::RecordRepresentation::Json,
                correlation: registry_breg::correlation::RequestCorrelation::breg_created(),
            },
        )
        .await
        .expect("ordinary MutationTransaction create commits after upgrade");
    assert_eq!(outcome.response().status(), 201);
    assert!(!outcome.replayed());
    let entity = &package.registry().entities()["contact"];
    let table = quote_identifier(&entity.physical_table);
    let body: Value =
        serde_json::from_slice(outcome.response().body()).expect("the mutation response is JSON");
    let record_id = Uuid::parse_str(
        body["data"]["recordIdentifier"]
            .as_str()
            .expect("the mutation response names its Record"),
    )
    .expect("the mutation response Record identifier is a UUID");
    let durable = database
            .admin
            .query_one(
                &format!(
                    "SELECT
                       (SELECT count(*)::bigint FROM registry_data.{table}
                         WHERE record_id=$1::uuid),
                       (SELECT count(*)::bigint FROM registry_internal.registry_revisions),
                       (SELECT count(*)::bigint FROM registry_internal.registry_idempotency),
                       (SELECT count(*)::bigint FROM registry_internal.registry_revision_commits),
                       (SELECT count(*)::bigint FROM registry_internal.registry_revision_commit_members),
                       (SELECT count(*)::bigint FROM registry_internal.registry_record_timer_generations)"
                ),
                &[&record_id],
            )
            .await
            .expect("the complete post-upgrade mutation packet is durable");
    assert_eq!(durable.get::<_, i64>(0), 1, "current Record");
    assert_eq!(
        durable.get::<_, i64>(1),
        before.get::<_, i64>(0) + 1,
        "history revision"
    );
    assert_eq!(
        durable.get::<_, i64>(2),
        before.get::<_, i64>(1) + 1,
        "idempotency receipt"
    );
    assert_eq!(
        durable.get::<_, i64>(3),
        before.get::<_, i64>(2) + 1,
        "revision commit"
    );
    assert_eq!(
        durable.get::<_, i64>(4),
        before.get::<_, i64>(3) + 1,
        "commit member"
    );
    assert_eq!(
        durable.get::<_, i64>(5),
        before.get::<_, i64>(4),
        "no timer is staged"
    );
}

impl ImmutableLegacyRegistry {
    async fn finish(self) {
        self.migration_task.abort();
        self.database.cleanup().await;
    }
}

/// A database activated by the package of a compiler that generated the
/// authored index without its trailing `record_id` and the source views with
/// `security_barrier`.
///
/// The source and effective model were compiled by this test build, so the
/// fixture freezes the affected DDL boundary rather than claiming to be every
/// byte of a released package. Package loading, planning, and apply use the
/// maintained paths.
struct EarlierCompilerRegistry {
    database: TestDatabase,
    migration_task: tokio::task::JoinHandle<()>,
    /// Held so the earlier package stays on disk for the test.
    _root: TempRoot,
    predecessor: registry_breg::package::VerifiedPredecessorPackage,
    active: ExpectedRegistryIdentity,
    /// The fingerprint of the unchanged project's schema under this compiler.
    current_fingerprint: String,
    index_name: String,
}

impl EarlierCompilerRegistry {
    async fn activate() -> Self {
        Self::activate_with_engine_feature_boundary(false).await
    }

    async fn activate_before_record_timer_store() -> Self {
        Self::activate_with_engine_feature_boundary(true).await
    }

    async fn activate_with_engine_feature_boundary(before_record_timer_store: bool) -> Self {
        let mut request = indexed_request(indexed_module_bytes(OtherEntity::Unchanged));
        let registry = prepare_package(request.clone())
            .expect("indexed model compiles")
            .registry()
            .clone();
        let current_fingerprint = fresh_fingerprint(&registry).await;
        request.schema_fingerprint.clone_from(&current_fingerprint);
        let (root, current_package) = publish_and_load(request);

        let database = TestDatabase::create(1).await;
        let mut active = apply_package(
            &database,
            &current_package,
            ApplyPrecondition::InitialActivation,
            Duration::from_secs(1),
            Duration::from_secs(5),
        )
        .await
        .expect("initial package applies");

        let statement = |id: &str| {
            registry
                .ddl()
                .statements
                .iter()
                .find(|statement| statement.id == id)
                .expect("compiled statement exists")
                .sql
                .clone()
        };
        let current_index = statement(INDEX_STATEMENT);
        let earlier_index = current_index
            .strip_suffix(", record_id)")
            .map(|declared| format!("{declared})"))
            .expect("the authored index ends with the record id");
        let index_name =
            registry.physical_names().entities["neutral-record"].indexes["code-idx"].clone();
        let current_views = [statement(INDEXED_SOURCE_VIEW), statement(OTHER_SOURCE_VIEW)];
        let earlier_views = current_views
            .each_ref()
            .map(|view| view.replacen(CURRENT_VIEW_OPTIONS, EARLIER_VIEW_OPTIONS, 1));

        let (migration, migration_task) = database.connect_migration().await;
        migration
            .batch_execute(&format!(
                "DROP INDEX registry_data.{}; {earlier_index}",
                quote_identifier(&index_name)
            ))
            .await
            .expect("the earlier authored index replaces the current one");
        for (current, earlier) in current_views.iter().zip(&earlier_views) {
            assert_ne!(
                current, earlier,
                "the earlier source view names the barrier"
            );
            migration
                .batch_execute(&earlier.replacen("CREATE VIEW ", "CREATE OR REPLACE VIEW ", 1))
                .await
                .expect("the earlier source view replaces the current one");
        }
        let earlier_fingerprint = managed_schema_fingerprint(
            &migration,
            &database.runtime_role,
            &ExpectedManagedCatalog::compiled(&registry),
        )
        .await
        .expect("earlier schema fingerprint derives");
        assert_ne!(earlier_fingerprint, current_fingerprint);

        let ddl_path = root.path().join("database/ddl.sql");
        let current_ddl = fs::read_to_string(&ddl_path).expect("generated DDL reads");
        let mut earlier_ddl = current_ddl.replacen(&current_index, &earlier_index, 1);
        for (current, earlier) in current_views.iter().zip(&earlier_views) {
            earlier_ddl = earlier_ddl.replacen(current, earlier, 1);
        }
        assert_eq!(
            earlier_ddl.matches(EARLIER_VIEW_OPTIONS).count(),
            2,
            "the frozen DDL changes both source views"
        );
        assert!(!earlier_ddl.contains(&current_index));
        write_signed_files(
            root.path(),
            [("database/ddl.sql", earlier_ddl.clone().into_bytes())],
        );
        rewrite_unsigned(root.path(), |manifest| {
            manifest.schema_fingerprint.clone_from(&earlier_fingerprint);
            if before_record_timer_store {
                manifest.engine_features = BTreeSet::from([
                    registry_breg::package::PackageEngineFeature::StatisticalReleaseStore,
                    registry_breg::package::PackageEngineFeature::CallerScopedIdempotency,
                ]);
            }
        });
        assert_eq!(
            load_package(root.path(), &local_context()).err(),
            Some(if before_record_timer_store {
                PackageError::EngineFeatureUpgradeRequired
            } else {
                PackageError::Derivation
            }),
            "this runtime refuses the concrete earlier-compiler boundary"
        );
        let predecessor = load_predecessor_package(root.path(), &local_context())
            .expect("the earlier package remains usable as a planning baseline");
        assert_eq!(
            predecessor.migration_baseline().generated_ddl_sha256,
            Some(script_digest(&earlier_ddl)),
            "the baseline states the script the earlier compiler packaged"
        );
        assert_ne!(script_digest(&earlier_ddl), script_digest(&current_ddl));

        if before_record_timer_store {
            migration
                .batch_execute(
                    "DROP FUNCTION registry_internal.prune_record_timer_retention(integer);
                     DROP TABLE registry_internal.registry_record_timer_attempts;
                     DROP TABLE registry_internal.registry_record_timer_current;
                     DROP TABLE registry_internal.registry_record_timer_generations;
                     DROP TABLE registry_internal.registry_record_timer_bindings;
                     DROP TABLE registry_internal.registry_record_timer_control;",
                )
                .await
                .expect("the earlier engine boundary predates only the timer store");
        }

        active.package_digest = predecessor.package_digest().to_owned();
        active.schema_fingerprint.clone_from(&earlier_fingerprint);
        migration
            .execute(
                "UPDATE registry_internal.registry_state
                    SET active_package_digest = $1, schema_fingerprint = $2
                  WHERE singleton",
                &[&active.package_digest, &active.schema_fingerprint],
            )
            .await
            .expect("fixture records the earlier active package");
        migration
            .execute(
                "UPDATE registry_internal.registry_migrations
                    SET package_digest = $1
                  WHERE activation_id = $2::text::uuid",
                &[&active.package_digest, &active.activation_id],
            )
            .await
            .expect("fixture activation ledger names the earlier package");
        drop(migration);

        Self {
            database,
            migration_task,
            _root: root,
            predecessor,
            active,
            current_fingerprint,
            index_name,
        }
    }

    async fn authored_index_definition(&self) -> String {
        self.database
            .admin
            .query_one(
                "SELECT indexdef FROM pg_catalog.pg_indexes
                  WHERE schemaname = 'registry_data' AND indexname = $1",
                &[&self.index_name],
            )
            .await
            .expect("authored index reads")
            .get(0)
    }

    async fn authored_index_oid(&self) -> u32 {
        self.database
            .admin
            .query_one(
                "SELECT class.oid
                   FROM pg_catalog.pg_class class
                   JOIN pg_catalog.pg_namespace namespace ON namespace.oid = class.relnamespace
                  WHERE namespace.nspname = 'registry_data' AND class.relname = $1",
                &[&self.index_name],
            )
            .await
            .expect("authored index identity reads")
            .get(0)
    }

    /// The options of every source view, each sorted, in view-name order.
    async fn source_view_options(&self) -> Vec<String> {
        self.database
            .admin
            .query(
                "SELECT COALESCE(
                            (SELECT string_agg(option, ',' ORDER BY option)
                               FROM unnest(class.reloptions) AS option),
                            '')
                   FROM pg_catalog.pg_class class
                   JOIN pg_catalog.pg_namespace namespace ON namespace.oid = class.relnamespace
                  WHERE namespace.nspname = 'registry_source' AND class.relkind = 'v'
                  ORDER BY class.relname",
                &[],
            )
            .await
            .expect("source view options read")
            .iter()
            .map(|row| row.get(0))
            .collect()
    }

    async fn finish(self) {
        self.migration_task.abort();
        self.database.cleanup().await;
    }
}

/// What the candidate does to the entity that has no authored index.
#[derive(Clone, Copy)]
enum OtherEntity {
    Unchanged,
    /// A change the compiler applies without review.
    GainsAField,
    /// A change that needs review and owes the database no statement.
    Rerouted,
}

/// One entity with an authored index and one without.
fn indexed_module_bytes(other: OtherEntity) -> Vec<u8> {
    let added = match other {
        OtherEntity::GainsAField => {
            r#",{"id":"label","type":"string","maximumLength":16,"classification":"internal"}"#
        }
        OtherEntity::Unchanged | OtherEntity::Rerouted => "",
    };
    let route = match other {
        OtherEntity::Rerouted => "other-records",
        OtherEntity::Unchanged | OtherEntity::GainsAField => "second-records",
    };
    format!(
        r#"{{"apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1","kind":"BRegModule","id":"core","version":"1","recordTypes":[{{"id":"neutral-record","primaryDataset":"neutral-registry","route":"neutral-records","mutationMode":"create-only","fields":[{{"id":"code","type":"string","maximumLength":8,"classification":"internal"}}],"indexes":[{{"id":"code-idx","fields":["code"]}}],"accessProfiles":[{{"requiredScopes":"unrestricted","rowBoundaries":"unrestricted","id":"reader","principalClaim":"principal","operations":["get","list"],"readableFields":["code"]}}]}},{{"id":"second-record","primaryDataset":"neutral-registry","route":"{route}","mutationMode":"create-only","fields":[{{"id":"code","type":"string","maximumLength":8,"classification":"internal"}}{added}],"accessProfiles":[{{"id":"writer","principalClaim":"principal","operations":["get","create"],"readableFields":["code"],"writableFields":["code"],"requiredScopes":"unrestricted","rowBoundaries":"unrestricted"}}]}}]}}"#
    )
    .into_bytes()
}

fn indexed_request(module_bytes: Vec<u8>) -> PackageBuildRequest {
    let module = parse_module_yaml(&module_bytes).expect("fixture module parses");
    build_request(BuildRequestParts {
        prior_revision: None,
        schema_fingerprint: fingerprint(1),
        project_bytes: project_bytes(&module_digest(&module)),
        module_bytes,
        migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
    })
}

fn publish_and_load(
    request: PackageBuildRequest,
) -> (TempRoot, registry_breg::package::VerifiedPackage) {
    let root = TempRoot::create();
    prepare_package(request)
        .expect("package prepares")
        .publish_to_directory(root.path())
        .expect("package publishes");
    let verified = load_package(root.path(), &local_context()).expect("package rederives exactly");
    (root, verified)
}

fn statement_ids(package: &registry_breg::package::VerifiedPackage) -> Vec<&str> {
    package
        .manifest()
        .migration_plan
        .statements
        .iter()
        .map(|statement| statement.id.as_str())
        .collect()
}

fn script_digest(script: &str) -> String {
    format!("sha256:{}", hex(&Sha256::digest(script.as_bytes())))
}
