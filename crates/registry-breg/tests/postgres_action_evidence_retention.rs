// SPDX-License-Identifier: Apache-2.0
#![cfg(all(feature = "postgres-test", feature = "tooling"))]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use postgres_harness::TestDatabase;
use registry_breg::{
    action_evidence_maintenance::ActionEvidenceRetentionOperatorService,
    compiler::{compile_project_with_assets, CompileProfile},
    contract::{parse_project_yaml, ModuleAssetSource},
    postgres::{
        initialize_registry_state_for_catalog_test, install_compiled_schema, ConnectionConfig,
        ExpectedManagedCatalog, ExpectedRegistryIdentity, RegistryLockKey,
        RegistryStateTestIdentity,
    },
    CompiledRegistry,
};
use std::{sync::Arc, time::Duration};

const PACKAGE: &str = "farmer-landholding-evidence";
fn registry() -> CompiledRegistry {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/breg/acceptance/farmer-landholding-evidence");
    let project = parse_project_yaml(&std::fs::read(root.join("registry.yaml")).unwrap()).unwrap();
    let assets = [
        "scripts/register-landholding.rhai",
        "scripts/check-procedure.rhai",
        "evidence/farmer-contracts.json",
    ]
    .map(|path| ModuleAssetSource {
        module: None,
        path: path.into(),
        bytes: std::fs::read(root.join(path)).unwrap(),
    });
    compile_project_with_assets(&project, &[], &assets, CompileProfile::Authoring).unwrap()
}

async fn install(
    database: &TestDatabase,
    database_name: Option<&str>,
    registry: &CompiledRegistry,
    runtime_role: &registry_breg::postgres::SqlIdentifier,
    identity: &str,
) -> ExpectedRegistryIdentity {
    let (client, task) = match database_name {
        Some(name) => database.connect_migration_to(name).await,
        None => database.connect_migration().await,
    };
    install_compiled_schema(&client, registry, runtime_role)
        .await
        .unwrap();
    let expected = initialize_registry_state_for_catalog_test(
        &client,
        runtime_role,
        &ExpectedManagedCatalog::compiled(registry),
        RegistryStateTestIdentity {
            package_id: PACKAGE,
            environment: "local",
            instance_id: identity,
            database_id: identity,
            package_revision: "retention-1",
            package_sequence: 1,
        },
    )
    .await
    .unwrap();
    drop(client);
    task.abort();
    expected
}

fn service(
    database: &TestDatabase,
    registry: &CompiledRegistry,
    expected: &ExpectedRegistryIdentity,
    connection: ConnectionConfig,
) -> Arc<ActionEvidenceRetentionOperatorService> {
    Arc::new(ActionEvidenceRetentionOperatorService::new_for_test(
        expected.clone(),
        ExpectedManagedCatalog::compiled(registry),
        RegistryLockKey::derive(PACKAGE).unwrap(),
        connection,
        database.migration_role.clone(),
        database.runtime_role.clone(),
    ))
}

async fn sentinel(database: &TestDatabase) {
    database.admin.batch_execute("INSERT INTO registry_internal.registry_idempotency
        (key_reference,binding_reference,result_kind,result_count,response_status,response_body,response_headers)
        VALUES ('retention-test','retention-binding','immediate_action',0,200,'{}','{}');
        INSERT INTO registry_internal.registry_immediate_action_applications
        (key_reference,binding_reference,application_id,action_id,action_contract_fingerprint,package_revision,principal_reference,result_count)
        VALUES ('retention-test','retention-binding','00000000-0000-4000-8000-000000000001','check-procedure',
        'sha256:1111111111111111111111111111111111111111111111111111111111111111','retention-1','synthetic-principal',0);
        INSERT INTO registry_internal.registry_action_evidence_uses
        (application_id,ordinal,retained,created_at,expires_at) VALUES
        ('00000000-0000-4000-8000-000000000001',0,'{\"synthetic\":\"retained-sentinel\"}',
        CURRENT_TIMESTAMP-INTERVAL '2 days',CURRENT_TIMESTAMP-INTERVAL '1 day');").await.unwrap();
}
async fn count(database: &TestDatabase) -> i64 {
    database
        .admin
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_action_evidence_uses",
            &[],
        )
        .await
        .unwrap()
        .get(0)
}
fn cutoff() -> chrono::DateTime<chrono::Utc> {
    chrono::Utc::now() - chrono::Duration::seconds(1)
}

#[tokio::test]
async fn retention_refuses_misbound_database_with_identical_roles_and_catalog_drift() {
    let original = TestDatabase::create(1).await;
    let other = TestDatabase::create(1).await;
    let registry = registry();
    let expected = install(
        &original,
        None,
        &registry,
        &original.runtime_role,
        "intended",
    )
    .await;
    let name: String = other
        .admin
        .query_one("SELECT current_database()", &[])
        .await
        .unwrap()
        .get(0);
    other
        .admin
        .batch_execute(&format!(
            "GRANT CONNECT ON DATABASE \"{name}\" TO \"{}\", \"{}\";",
            original.migration_role.as_str(),
            original.runtime_role.as_str()
        ))
        .await
        .unwrap();
    for schema in [
        "registry_internal",
        "registry_data",
        "registry_source",
        "registry_derived",
        "registry_context",
    ] {
        other
            .admin
            .batch_execute(&format!(
                "ALTER SCHEMA {schema} OWNER TO \"{}\";",
                original.migration_role.as_str()
            ))
            .await
            .unwrap();
    }
    let other_connection = original.migration_config_for_database(&name);
    let other_expected = install(
        &original,
        Some(&name),
        &registry,
        &original.runtime_role,
        "different-registry",
    )
    .await;
    assert_eq!(
        expected.schema_fingerprint, other_expected.schema_fingerprint,
        "the wrong endpoint has the same managed catalog and exact role names"
    );
    sentinel(&other).await;
    let wrong = service(&original, &registry, &expected, other_connection.clone());
    assert!(wrong.erase_expired(cutoff()).await.is_err(), "a verified runtime identity cannot authorize deletion in another database sharing its role names");
    assert_eq!(count(&other).await, 1);
    let correct = service(&original, &registry, &other_expected, other_connection);
    other
        .admin
        .batch_execute(&format!(
            "GRANT SELECT ON registry_internal.registry_action_evidence_uses TO \"{}\"",
            original.runtime_role.as_str()
        ))
        .await
        .unwrap();
    assert!(
        correct.erase_expired(cutoff()).await.is_err(),
        "catalog ACL drift must refuse deletion"
    );
    assert_eq!(count(&other).await, 1);
    other
        .admin
        .batch_execute(&format!(
            "REVOKE SELECT ON registry_internal.registry_action_evidence_uses FROM \"{}\"",
            original.runtime_role.as_str()
        ))
        .await
        .unwrap();
    assert_eq!(correct.erase_expired(cutoff()).await.unwrap(), 1);
    assert_eq!(count(&other).await, 0);
    drop((wrong, correct));
    other.cleanup().await;
    original.cleanup().await;
}

async fn wait_for_lock(database: &TestDatabase) {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            database
                .admin
                .execute("SELECT pg_stat_clear_snapshot()", &[])
                .await
                .unwrap();
            let count: i64 = database
                .admin
                .query_one(
                    "SELECT count(*) FROM pg_stat_activity
                WHERE datname=current_database() AND usename=$1 AND wait_event_type='Lock'",
                    &[&database.migration_role.as_str()],
                )
                .await
                .unwrap()
                .get(0);
            if count > 0 {
                break;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("erasure reaches the expected database lock wait");
}

#[tokio::test]
async fn retention_serializes_activation_and_holds_identity_lock_through_deletion() {
    let database = TestDatabase::create(1).await;
    let registry = registry();
    let expected = install(
        &database,
        None,
        &registry,
        &database.runtime_role,
        "intended",
    )
    .await;
    sentinel(&database).await;
    let operator = service(
        &database,
        &registry,
        &expected,
        database.migration_config.clone(),
    );
    let key = RegistryLockKey::derive(PACKAGE).unwrap().get();
    for change in [
        "UPDATE registry_internal.registry_state SET active_package_revision='successor' WHERE singleton",
        "UPDATE registry_internal.registry_state SET maintenance_status='failed', maintenance_target_revision='successor' WHERE singleton",
    ] {
        database.admin.batch_execute("BEGIN").await.unwrap();
        database.admin.execute("SELECT pg_advisory_xact_lock($1)", &[&key]).await.unwrap();
        let task_operator = operator.clone();
        let erase = tokio::spawn(async move { task_operator.erase_expired(cutoff()).await });
        wait_for_lock(&database).await;
        database.admin.batch_execute(change).await.unwrap();
        database.admin.batch_execute("COMMIT").await.unwrap();
        assert!(erase.await.unwrap().is_err(), "authority must be checked after the activation lock wait");
        assert_eq!(count(&database).await, 1);
        database.admin.batch_execute("UPDATE registry_internal.registry_state SET active_package_revision='retention-1',maintenance_status='ready',maintenance_target_revision=NULL WHERE singleton").await.unwrap();
    }
    // Block the DELETE itself, then prove an activation cannot acquire the
    // registry lock while the verified erasure transaction is still running.
    database
        .admin
        .batch_execute(
            "BEGIN; SELECT 1 FROM registry_internal.registry_action_evidence_uses FOR UPDATE",
        )
        .await
        .unwrap();
    let task_operator = operator.clone();
    let erase = tokio::spawn(async move { task_operator.erase_expired(cutoff()).await });
    wait_for_lock(&database).await;
    let acquired: bool = database
        .admin
        .query_one("SELECT pg_try_advisory_xact_lock($1)", &[&key])
        .await
        .unwrap()
        .get(0);
    assert!(
        !acquired,
        "activation remains serialized until protected deletion commits"
    );
    database.admin.batch_execute("COMMIT").await.unwrap();
    assert_eq!(erase.await.unwrap().unwrap(), 1);
    assert_eq!(count(&database).await, 0);
    drop(operator);
    database.cleanup().await;
}
