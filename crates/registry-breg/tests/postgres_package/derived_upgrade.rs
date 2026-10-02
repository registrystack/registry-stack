// SPDX-License-Identifier: Apache-2.0

use super::*;
use std::collections::BTreeMap;

const DERIVED_SQL: &[u8] =
    b"SELECT n.id AS id, n.code AS summary FROM registry_source.neutral_record n";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_unchanged_successor_replaces_an_older_derived_wrapper() {
    let database = TestDatabase::create(1).await;
    let legacy_root = TempRoot::create();
    let initial = prepare_package(derived_asset_request(DERIVED_SQL))
        .expect("initial derived package prepares");
    initial
        .publish_to_directory(legacy_root.path())
        .expect("initial derived package publishes");
    let provisional = load_package(legacy_root.path(), &local_context())
        .expect("provisional package loads before exact fingerprinting");

    let (mut migration, migration_task) = database.connect_migration().await;
    let fingerprint_transaction = migration
        .transaction()
        .await
        .expect("fingerprint transaction starts");
    install_compiled_schema(
        &fingerprint_transaction,
        provisional.registry(),
        &database.runtime_role,
    )
    .await
    .expect("current derived schema installs for fingerprinting");
    let expected_catalog = ExpectedManagedCatalog::compiled(provisional.registry());
    let current_fingerprint = managed_schema_fingerprint(
        &fingerprint_transaction,
        &database.runtime_role,
        &expected_catalog,
    )
    .await
    .expect("current derived schema fingerprint derives");
    fingerprint_transaction
        .rollback()
        .await
        .expect("fingerprint transaction rolls back");
    rewrite_unsigned(legacy_root.path(), |manifest| {
        manifest.schema_fingerprint.clone_from(&current_fingerprint);
    });
    let current_package = load_package(legacy_root.path(), &local_context())
        .expect("initial package loads with its exact fingerprint");
    let mut active = apply_package(
        &database,
        &current_package,
        ApplyPrecondition::InitialActivation,
        Duration::from_secs(1),
        Duration::from_secs(5),
    )
    .await
    .expect("initial package applies");

    // Reproduce the generated DDL and live view shape emitted before the
    // derived-value contract wrapper. The source and effective model were
    // compiled by this test build, so this freezes the affected historical DDL
    // boundary rather than claiming to be every byte of a released package.
    // Package loading and the successor apply below use the maintained paths.
    let view_statement = current_package
        .registry()
        .ddl()
        .statements
        .iter()
        .find(|statement| statement.id == "entity.neutral-record.derived.summary.view")
        .expect("compiled derived view exists");
    let legacy_view_sql = legacy_derived_view_sql(&view_statement.sql);
    migration
        .batch_execute(&legacy_view_sql.replacen("CREATE VIEW ", "CREATE OR REPLACE VIEW ", 1))
        .await
        .expect("legacy derived wrapper replaces the current view");
    let legacy_fingerprint = managed_schema_fingerprint(
        &migration,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(current_package.registry()),
    )
    .await
    .expect("legacy derived schema fingerprint derives");
    assert_ne!(legacy_fingerprint, current_fingerprint);

    let ddl_path = legacy_root.path().join("database/ddl.sql");
    let current_ddl = fs::read_to_string(&ddl_path).expect("generated DDL reads");
    let legacy_ddl = current_ddl.replacen(&view_statement.sql, &legacy_view_sql, 1);
    assert_ne!(legacy_ddl, current_ddl, "the frozen DDL changes one view");
    write_signed_files(
        legacy_root.path(),
        [("database/ddl.sql", legacy_ddl.into_bytes())],
    );
    rewrite_unsigned(legacy_root.path(), |manifest| {
        manifest.schema_fingerprint.clone_from(&legacy_fingerprint);
    });
    assert_eq!(
        load_package(legacy_root.path(), &local_context()).err(),
        Some(PackageError::Derivation),
        "the new runtime refuses an old package whose generated view no longer rederives"
    );
    let predecessor = load_predecessor_package(legacy_root.path(), &local_context())
        .expect("the verified old package remains usable as a planning baseline");
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
        .expect("fixture records the legacy active package");
    migration
        .execute(
            "UPDATE registry_internal.registry_migrations
                SET package_digest = $1
              WHERE activation_id = $2::text::uuid",
            &[&active.package_digest, &active.activation_id],
        )
        .await
        .expect("fixture activation ledger names the legacy package");
    let legacy_package_bytes = snapshot_package_bytes(legacy_root.path());
    let state_before_refusal = recorded_state(&database).await;
    let pool = database
        .runtime_config
        .build_pool()
        .expect("runtime pool builds");
    let mut runtime = pool
        .get_for_test()
        .await
        .expect("runtime connection checks out");
    assert_eq!(
        prepare_startup(
            legacy_root.path(),
            &local_context(),
            DATABASE,
            &mut runtime,
            &database.migration_role,
            &database.runtime_role,
        )
        .await
        .err(),
        Some(StartupError::PackageRefused(PackageError::Derivation)),
        "the runtime refuses the old package before consulting or changing the database"
    );
    drop(runtime);
    drop(pool);
    assert_eq!(recorded_state(&database).await, state_before_refusal);

    let mut successor_request = derived_asset_request(DERIVED_SQL);
    successor_request.from_package_digest = Some(active.package_digest.clone());
    successor_request.schema_fingerprint = current_fingerprint.clone();
    successor_request.migration_plan = PackageMigrationPlanInput::SuccessorFromBaseline {
        prior_baseline: Box::new(predecessor.migration_baseline().clone()),
    };
    let successor = prepare_package(successor_request)
        .expect("unchanged project prepares a compiler-upgrade successor");
    let [replacement] = successor.manifest().migration_plan.statements.as_slice() else {
        panic!("the successor carries one retained derived-view replacement");
    };
    assert_eq!(replacement.id, "entity.neutral-record.derived.summary.view");
    assert!(replacement.sql.starts_with("CREATE OR REPLACE VIEW "));
    let successor_root = TempRoot::create();
    successor
        .publish_to_directory(successor_root.path())
        .expect("successor package publishes");
    let verified_successor = load_package(successor_root.path(), &local_context())
        .expect("successor package rederives exactly");
    let upgraded = apply_package(
        &database,
        &verified_successor,
        ApplyPrecondition::Successor { current: &active },
        Duration::from_secs(1),
        Duration::from_secs(5),
    )
    .await
    .expect("successor replaces the old wrapper under the fingerprint fence");
    assert_eq!(upgraded.schema_fingerprint, current_fingerprint);
    assert_eq!(
        snapshot_package_bytes(legacy_root.path()),
        legacy_package_bytes,
        "upgrade planning and apply never rewrite the predecessor package"
    );
    assert_startup(&database, &successor_root, &verified_successor).await;

    migration_task.abort();
    database.cleanup().await;
}

fn snapshot_package_bytes(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let envelope = read_envelope(root);
    envelope
        .manifest
        .files
        .iter()
        .map(|entry| {
            (
                entry.path.clone(),
                fs::read(root.join(&entry.path)).expect("package closure file reads"),
            )
        })
        .chain([
            (
                "package.json".to_owned(),
                fs::read(root.join("package.json")).expect("package manifest reads"),
            ),
            (
                SUM_FILE.to_owned(),
                fs::read(root.join(SUM_FILE)).expect("package sum file reads"),
            ),
        ])
        .collect()
}

async fn recorded_state(database: &TestDatabase) -> (String, String) {
    let row = database
        .admin
        .query_one(
            "SELECT active_package_digest, schema_fingerprint
               FROM registry_internal.registry_state
              WHERE singleton",
            &[],
        )
        .await
        .expect("recorded registry state reads");
    (row.get(0), row.get(1))
}

fn legacy_derived_view_sql(current: &str) -> String {
    let projection_prefix = "\"__registry$derived$key\" AS \"id\", ";
    let projection_suffix = " AS \"summary\"\n                        FROM (";
    let start = current
        .find(projection_prefix)
        .map(|index| index + projection_prefix.len())
        .expect("derived projection prefix exists");
    let end = current[start..]
        .find(projection_suffix)
        .map(|index| start + index)
        .expect("derived projection suffix exists");
    format!(
        "{}\"summary\"::varchar(64){}",
        &current[..start],
        &current[end..]
    )
}

async fn assert_startup(
    database: &TestDatabase,
    package_root: &TempRoot,
    package: &registry_breg::package::VerifiedPackage,
) {
    let pool = database
        .runtime_config
        .build_pool()
        .expect("runtime pool builds");
    let mut runtime = pool
        .get_for_test()
        .await
        .expect("runtime connection checks out");
    prepare_startup(
        package_root.path(),
        &local_context(),
        DATABASE,
        &mut runtime,
        &database.migration_role,
        &database.runtime_role,
    )
    .await
    .expect("upgraded package starts against its exact catalog");
    assert_eq!(package.package_digest(), recorded_state(database).await.0);
}
