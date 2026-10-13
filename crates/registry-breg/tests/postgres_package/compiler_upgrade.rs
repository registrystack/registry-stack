// SPDX-License-Identifier: Apache-2.0

use super::derived_upgrade_tests::assert_startup;
use super::policy_upgrade_tests::fresh_fingerprint;
use super::*;

const INDEX_STATEMENT: &str = "entity.neutral-record.index.code-idx";
const INDEX_DROP_STATEMENT: &str = "entity.neutral-record.index.code-idx.drop";
const INDEXED_SOURCE_VIEW: &str = "entity.neutral-record.source-view";
const OTHER_SOURCE_VIEW: &str = "entity.second-record.source-view";
const CURRENT_VIEW_OPTIONS: &str = "WITH (security_invoker=true)";
const EARLIER_VIEW_OPTIONS: &str = "WITH (security_invoker=true, security_barrier=true)";

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
        });
        assert_eq!(
            load_package(root.path(), &local_context()).err(),
            Some(PackageError::Derivation),
            "this runtime refuses a package whose generated DDL no longer rederives"
        );
        let predecessor = load_predecessor_package(root.path(), &local_context())
            .expect("the earlier package remains usable as a planning baseline");
        assert_eq!(
            predecessor.migration_baseline().generated_ddl_sha256,
            Some(script_digest(&earlier_ddl)),
            "the baseline states the script the earlier compiler packaged"
        );
        assert_ne!(script_digest(&earlier_ddl), script_digest(&current_ddl));

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
        r#"{{"apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1","kind":"BRegModule","id":"core","version":"1","entities":[{{"id":"neutral-record","primaryDataset":"neutral-registry","route":"neutral-records","mutationMode":"create-only","fields":[{{"id":"code","type":"string","maximumLength":8,"classification":"internal"}}],"indexes":[{{"id":"code-idx","fields":["code"]}}],"accessProfiles":[{{"requiredScopes":"unrestricted","rowBoundaries":"unrestricted","id":"reader","principalClaim":"principal","operations":["get","list"],"readableFields":["code"]}}]}},{{"id":"second-record","primaryDataset":"neutral-registry","route":"{route}","mutationMode":"create-only","fields":[{{"id":"code","type":"string","maximumLength":8,"classification":"internal"}}{added}],"accessProfiles":[{{"id":"writer","principalClaim":"principal","operations":["get","create"],"readableFields":["code"],"writableFields":["code"],"requiredScopes":"unrestricted","rowBoundaries":"unrestricted"}}]}}]}}"#
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
