// SPDX-License-Identifier: Apache-2.0

use super::*;
use registry_server::postgres::legacy_schema_fingerprint_for_test;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn signed_legacy_fingerprint_starts_and_upgrades_without_rewriting_package_bytes() {
    let database = TestDatabase::create(1).await;
    let (mut migration, task) = database.connect_migration().await;
    let registry = compile_fixture_registry("production", 1, PlanChoice::Schema);
    let transaction = migration.transaction().await.unwrap();
    install_compiled_schema(&transaction, &registry, &database.runtime_role)
        .await
        .unwrap();
    let legacy = legacy_schema_fingerprint_for_test(&transaction, &database.runtime_role)
        .await
        .unwrap();
    let named = managed_schema_fingerprint(
        &transaction,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(&registry),
    )
    .await
    .unwrap();
    assert_ne!(legacy, named, "the algorithms have distinct hash domains");
    transaction.rollback().await.unwrap();

    let signing = generate_private_jwk(GeneratedKeyAlgorithm::Es384).unwrap();
    let baseline = PackageFixture::build(
        "production",
        1,
        None,
        legacy.clone(),
        PlanChoice::Schema,
        Some(&signing),
    );
    let original_bytes = fs::read(baseline.root.path().join("package.json")).unwrap();
    let package = load_package(
        baseline.root.path(),
        &baseline.context(PackageIntent::InitialActivation),
    )
    .unwrap();
    let active = apply_package(
        &database,
        &package,
        ApplyPrecondition::InitialActivation,
        Duration::from_secs(1),
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!(active.schema_fingerprint, legacy);
    assert_startup_and_drift_refusal(&database, &baseline, &package).await;

    // A real successor moves from the old fingerprint to the named-column
    // algorithm. Measurement uses a fresh isolated database, not live DDL.
    let rehearsal = TestDatabase::create(1).await;
    let (target_connection, target_task) = rehearsal.connect_migration().await;
    let target = compile_fixture_registry("production", 2, PlanChoice::SecondTable);
    install_compiled_schema(&target_connection, &target, &rehearsal.runtime_role)
        .await
        .unwrap();
    let target_fingerprint = managed_schema_fingerprint(
        &target_connection,
        &rehearsal.runtime_role,
        &ExpectedManagedCatalog::compiled(&target),
    )
    .await
    .unwrap();
    target_task.abort();
    rehearsal.cleanup().await;
    let successor = PackageFixture::build(
        "production",
        2,
        Some(&active.package_revision),
        target_fingerprint.clone(),
        PlanChoice::SecondTable,
        Some(&signing),
    );
    let successor_package = load_package(
        successor.root.path(),
        &successor.context(PackageIntent::Activation {
            active_revision: &active.package_revision,
            active_sequence: 1,
        }),
    )
    .unwrap();
    let upgraded = apply_package(
        &database,
        &successor_package,
        ApplyPrecondition::Successor { current: &active },
        Duration::from_secs(1),
        Duration::from_secs(5),
    )
    .await
    .unwrap();
    assert_eq!(upgraded.schema_fingerprint, target_fingerprint);
    assert_startup_and_drift_refusal(&database, &successor, &successor_package).await;
    assert_eq!(
        fs::read(baseline.root.path().join("package.json")).unwrap(),
        original_bytes
    );
    assert_startup(&database, &baseline, &package, false).await;
    task.abort();
    database.cleanup().await;
}

async fn assert_startup_and_drift_refusal(
    database: &TestDatabase,
    fixture: &PackageFixture,
    package: &registry_server::package::VerifiedPackage,
) {
    assert_startup(database, fixture, package, true).await;
    let entity = &package.registry().entities()["neutral-record"];
    let table = format!("registry_data.{}", quote_identifier(&entity.physical_table));
    let code = quote_identifier(&entity.fields["code"].physical_name);
    let view = format!(
        "registry_source.{}",
        quote_identifier(&entity.source_relation.sql_name)
    );
    let (migration, task) = database.connect_migration().await;
    for (alter, restore) in [
        (
            format!("ALTER TABLE {table} ADD COLUMN unexpected text"),
            format!("ALTER TABLE {table} DROP COLUMN unexpected"),
        ),
        (
            format!("ALTER TABLE {table} ALTER COLUMN {code} SET DEFAULT 'drift'"),
            format!("ALTER TABLE {table} ALTER COLUMN {code} DROP DEFAULT"),
        ),
        (
            format!("ALTER TABLE {table} ALTER COLUMN {code} SET NOT NULL"),
            format!("ALTER TABLE {table} ALTER COLUMN {code} DROP NOT NULL"),
        ),
        (
            format!("ALTER TABLE {table} RENAME COLUMN {code} TO renamed_code"),
            format!("ALTER TABLE {table} RENAME COLUMN renamed_code TO {code}"),
        ),
        (
            format!("ALTER TABLE {table} DISABLE ROW LEVEL SECURITY"),
            format!("ALTER TABLE {table} ENABLE ROW LEVEL SECURITY"),
        ),
        (
            format!(
                "GRANT SELECT ON {table} TO {}",
                quote_identifier(database.intruder_role.as_str())
            ),
            format!(
                "REVOKE SELECT ON {table} FROM {}",
                quote_identifier(database.intruder_role.as_str())
            ),
        ),
        (
            format!("ALTER VIEW {view} SET (security_invoker = false)"),
            format!("ALTER VIEW {view} SET (security_invoker = true, security_barrier = true)"),
        ),
    ] {
        migration.batch_execute(&alter).await.unwrap();
        assert_startup(database, fixture, package, false).await;
        migration.batch_execute(&restore).await.unwrap();
        assert_startup(database, fixture, package, true).await;
    }
    task.abort();
}

async fn assert_startup(
    database: &TestDatabase,
    fixture: &PackageFixture,
    package: &registry_server::package::VerifiedPackage,
    allowed: bool,
) {
    let pool = database.runtime_config.build_pool().unwrap();
    let mut runtime = pool.get_for_test().await.unwrap();
    let context = fixture.context(PackageIntent::Startup {
        active_revision: &package.manifest().package_revision,
        active_sequence: package.manifest().sequence,
    });
    let result = prepare_startup(
        fixture.root.path(),
        &context,
        &mut runtime,
        &database.migration_role,
        &database.runtime_role,
    )
    .await;
    if allowed {
        assert!(
            result.is_ok(),
            "exact legacy or named-column catalog must start: {:?}",
            result.err()
        );
    } else {
        assert_eq!(result.err(), Some(StartupError::DatabaseUnready));
    }
}
