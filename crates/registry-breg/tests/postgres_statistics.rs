// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use postgres_harness::TestDatabase;
use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_json;
use registry_breg::postgres::{
    initialize_compiled_registry_state_for_test, install_compiled_schema,
    install_statistics_store_for_test, verify_catalog_identity_for_catalog, ExpectedManagedCatalog,
    RegistryStateTestIdentity,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn statistics_catalog_refuses_extra_grants_and_withdrawal_function_tampering() {
    let database = TestDatabase::create(2).await;
    let (migration, migration_task) = database.connect_migration().await;
    let registry = compiled_registry();
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("compiled schema installs with statistical release storage");
    let catalog = ExpectedManagedCatalog::compiled(&registry);
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &registry,
        RegistryStateTestIdentity {
            package_id: "statistics-catalog",
            database_id: "statistics-catalog-database",
            label: "statistics-catalog-package-1",
        },
    )
    .await
    .expect("exact statistical catalog identity initializes");
    let verify = || async {
        verify_catalog_identity_for_catalog(
            &migration,
            &identity,
            &catalog,
            &database.migration_role,
            &database.runtime_role,
        )
        .await
    };
    verify()
        .await
        .expect("the installed statistical catalog is exact");

    migration
        .batch_execute(&format!(
            "GRANT UPDATE ON registry_internal.registry_statistical_release_versions TO {}",
            quote_identifier(database.runtime_role.as_str())
        ))
        .await
        .expect("fixture adds excess release mutation authority");
    assert!(
        verify().await.is_err(),
        "an extra release-table grant must refuse the active catalog"
    );
    migration
        .batch_execute(&format!(
            "REVOKE UPDATE ON registry_internal.registry_statistical_release_versions FROM {}",
            quote_identifier(database.runtime_role.as_str())
        ))
        .await
        .expect("fixture restores the exact release-table ACL");
    verify()
        .await
        .expect("revoking the excess grant restores the active catalog");

    migration
        .batch_execute(
            "ALTER FUNCTION registry_internal.withdraw_statistical_release(text, text, bigint, text)
                 SECURITY INVOKER",
        )
        .await
        .expect("fixture removes the withdrawal security boundary");
    assert!(
        verify().await.is_err(),
        "a withdrawal security-shape change must refuse the active catalog"
    );
    migration
        .batch_execute(
            "ALTER FUNCTION registry_internal.withdraw_statistical_release(text, text, bigint, text)
                 SECURITY DEFINER",
        )
        .await
        .expect("fixture restores the withdrawal security boundary");
    verify()
        .await
        .expect("restoring the security shape restores the active catalog");

    migration
        .batch_execute(
            "CREATE OR REPLACE FUNCTION registry_internal.withdraw_statistical_release(
                 text, text, bigint, text
             ) RETURNS boolean LANGUAGE sql VOLATILE SECURITY DEFINER
                SET search_path = pg_catalog, registry_internal AS 'SELECT false'",
        )
        .await
        .expect("fixture tampers with the withdrawal function body");
    assert!(
        verify().await.is_err(),
        "a withdrawal body change must refuse the active catalog fingerprint"
    );

    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn statistics_store_has_exact_runtime_acl_and_withdrawal_function_shape() {
    let database = TestDatabase::create(2).await;
    let (migration, migration_task) = database.connect_migration().await;
    install_store(&migration, &database).await;
    install_statistics_store_for_test(&migration, &database.runtime_role)
        .await
        .expect("statistics store installation is idempotent");

    let snapshot_nullable = migration
        .query_one(
            "SELECT is_nullable
               FROM information_schema.columns
              WHERE table_schema = 'registry_internal'
                AND table_name = 'registry_statistical_release_versions'
                AND column_name = 'snapshot_reference'",
            &[],
        )
        .await
        .expect("snapshot column contract is inspectable")
        .get::<_, String>(0);
    assert_eq!(snapshot_nullable, "YES");

    let row = migration
        .query_one(
            "SELECT
                 has_table_privilege($1, 'registry_internal.registry_statistical_release_versions', 'SELECT'),
                 has_table_privilege($1, 'registry_internal.registry_statistical_release_versions', 'INSERT'),
                 has_table_privilege($1, 'registry_internal.registry_statistical_release_versions', 'UPDATE'),
                 has_table_privilege($1, 'registry_internal.registry_statistical_release_versions', 'DELETE'),
                 has_table_privilege($1, 'registry_internal.registry_statistical_release_contents', 'SELECT'),
                 has_table_privilege($1, 'registry_internal.registry_statistical_release_contents', 'INSERT'),
                 has_table_privilege($1, 'registry_internal.registry_statistical_release_contents', 'UPDATE'),
                 has_table_privilege($1, 'registry_internal.registry_statistical_release_contents', 'DELETE'),
                 has_table_privilege($1, 'registry_internal.registry_statistical_release_withdrawals', 'SELECT'),
                 has_table_privilege($1, 'registry_internal.registry_statistical_release_withdrawals', 'INSERT'),
                 has_table_privilege($1, 'registry_internal.registry_statistical_release_withdrawals', 'UPDATE'),
                 has_table_privilege($1, 'registry_internal.registry_statistical_release_withdrawals', 'DELETE'),
                 has_function_privilege($1,
                    'registry_internal.withdraw_statistical_release(text,text,bigint,text)', 'EXECUTE')",
            &[&database.runtime_role.as_str()],
        )
        .await
        .expect("migration role can inspect runtime privileges");
    let actual = (0..13)
        .map(|index| row.get::<_, bool>(index))
        .collect::<Vec<_>>();
    assert_eq!(
        actual,
        vec![true, true, false, false, true, true, false, false, true, false, false, false, true,]
    );

    let function = migration
        .query_one(
            "SELECT p.prosecdef, p.provolatile, l.lanname,
                    pg_catalog.pg_get_function_identity_arguments(p.oid),
                    p.prorettype = 'boolean'::regtype,
                    p.proconfig = ARRAY['search_path=pg_catalog, registry_internal'],
                    pg_catalog.pg_get_userbyid(p.proowner),
                    pg_catalog.pg_get_functiondef(p.oid),
                    NOT EXISTS (
                        SELECT 1
                        FROM pg_catalog.aclexplode(
                            COALESCE(p.proacl, pg_catalog.acldefault('f', p.proowner))
                        ) acl
                        WHERE acl.grantee = 0 AND acl.privilege_type = 'EXECUTE'
                    )
               FROM pg_catalog.pg_proc p
               JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
               JOIN pg_catalog.pg_language l ON l.oid = p.prolang
              WHERE n.nspname = 'registry_internal'
                AND p.proname = 'withdraw_statistical_release'",
            &[],
        )
        .await
        .expect("withdrawal function exists");
    assert!(function.get::<_, bool>(0));
    assert_eq!(function.get::<_, i8>(1) as u8 as char, 'v');
    assert_eq!(function.get::<_, String>(2), "sql");
    assert_eq!(function.get::<_, String>(3), "text, text, bigint, text");
    assert!(function.get::<_, bool>(4));
    assert!(function.get::<_, bool>(5));
    assert_eq!(
        function.get::<_, String>(6),
        database.migration_role.as_str()
    );
    let definition = function.get::<_, String>(7);
    assert!(definition
        .contains("INSERT INTO registry_internal.registry_statistical_release_withdrawals"));
    assert!(
        definition.contains("ON CONFLICT (dataset_id, period_code, release_version) DO NOTHING")
    );
    assert!(
        definition.contains("DELETE FROM registry_internal.registry_statistical_release_contents")
    );
    assert!(
        function.get::<_, bool>(8),
        "PUBLIC has no execute authority"
    );

    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn withdrawal_records_reason_and_removes_only_content_atomically() {
    let database = TestDatabase::create(2).await;
    let (migration, migration_task) = database.connect_migration().await;
    install_store(&migration, &database).await;
    insert_release(&migration, 1).await;

    set_role(&database, database.runtime_role.as_str()).await;
    assert!(database
        .admin
        .query_one(
            "SELECT registry_internal.withdraw_statistical_release(
                 'households', '2026-08', 1, 'source-data-error')",
            &[],
        )
        .await
        .expect("runtime can invoke the exact function")
        .get::<_, bool>(0));
    assert!(!database
        .admin
        .query_one(
            "SELECT registry_internal.withdraw_statistical_release(
                 'households', '2026-08', 1, 'source-data-error')",
            &[],
        )
        .await
        .expect("a repeated withdrawal is a closed refusal")
        .get::<_, bool>(0));
    reset_role(&database).await;

    let state = migration
        .query_one(
            "SELECT
                 EXISTS (SELECT 1 FROM registry_internal.registry_statistical_release_versions),
                 EXISTS (SELECT 1 FROM registry_internal.registry_statistical_release_contents),
                 (SELECT reason_code FROM registry_internal.registry_statistical_release_withdrawals)",
            &[],
        )
        .await
        .expect("migration role can inspect atomic withdrawal state");
    assert!(state.get::<_, bool>(0), "immutable header remains");
    assert!(!state.get::<_, bool>(1), "only content is removed");
    assert_eq!(state.get::<_, String>(2), "source-data-error");

    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_withdrawal_reason_leaves_content_and_journal_unchanged() {
    let database = TestDatabase::create(2).await;
    let (migration, migration_task) = database.connect_migration().await;
    install_store(&migration, &database).await;
    insert_release(&migration, 1).await;

    set_role(&database, database.runtime_role.as_str()).await;
    assert!(database
        .admin
        .query_one(
            "SELECT registry_internal.withdraw_statistical_release(
                 'households', '2026-08', 1, 'free-text-reason')",
            &[],
        )
        .await
        .is_err());
    reset_role(&database).await;

    let state = migration
        .query_one(
            "SELECT
                 EXISTS (SELECT 1 FROM registry_internal.registry_statistical_release_contents),
                 EXISTS (SELECT 1 FROM registry_internal.registry_statistical_release_withdrawals)",
            &[],
        )
        .await
        .expect("failed function call is atomic");
    assert!(state.get::<_, bool>(0));
    assert!(!state.get::<_, bool>(1));

    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn release_header_persists_an_absent_history_snapshot() {
    let database = TestDatabase::create(2).await;
    let (migration, migration_task) = database.connect_migration().await;
    install_store(&migration, &database).await;

    let digest = format!("sha256:{}", "0".repeat(64));
    migration
        .execute(
            "INSERT INTO registry_internal.registry_statistical_release_versions
                 (dataset_id, period_code, release_version, release_status,
                  history_head_position, snapshot_reference, computed_at,
                  package_digest, definition_digest, content_digest)
             VALUES ('households', '2026-08', 1, 'final', 7, NULL,
                     transaction_timestamp(), $1, $1, $1)",
            &[&digest],
        )
        .await
        .expect("release header accepts an absent snapshot");
    let row = migration
        .query_one(
            "SELECT history_head_position, snapshot_reference
               FROM registry_internal.registry_statistical_release_versions",
            &[],
        )
        .await
        .expect("release header remains readable");
    assert_eq!(row.get::<_, i64>(0), 7);
    assert_eq!(row.get::<_, Option<uuid::Uuid>>(1), None);

    migration_task.abort();
    database.cleanup().await;
}

async fn insert_release(client: &tokio_postgres::Client, version: i64) {
    client
        .execute(
            "INSERT INTO registry_internal.registry_statistical_release_versions
                 (dataset_id, period_code, release_version, release_status,
                  history_head_position, snapshot_reference, computed_at,
                  package_digest, definition_digest, content_digest)
             VALUES ('households', '2026-08', $1, 'final', 0,
                     '018feaa0-68f9-4a45-b9e3-58436df07af6', transaction_timestamp(),
                     $2, $2, $2)",
            &[&version, &format!("sha256:{}", "0".repeat(64))],
        )
        .await
        .expect("release header inserts");
    client
        .execute(
            "INSERT INTO registry_internal.registry_statistical_release_contents
                 (dataset_id, period_code, release_version, document)
             VALUES ('households', '2026-08', $1, '{}'::bytea)",
            &[&version],
        )
        .await
        .expect("release content inserts");
}

async fn install_store(client: &tokio_postgres::Client, database: &TestDatabase) {
    install_statistics_store_for_test(client, &database.runtime_role)
        .await
        .expect("statistics store installs");
    client
        .batch_execute(&format!(
            "GRANT USAGE ON SCHEMA registry_internal TO \"{}\"",
            database.runtime_role.as_str()
        ))
        .await
        .expect("fixture grants the schema usage the complete runtime install provides");
}

async fn set_role(database: &TestDatabase, role: &str) {
    database
        .admin
        .batch_execute(&format!("SET ROLE {}", quote_identifier(role)))
        .await
        .expect("administrator can assume runtime role");
}

async fn reset_role(database: &TestDatabase) {
    database
        .admin
        .batch_execute("RESET ROLE")
        .await
        .expect("administrator resets runtime role");
}

fn quote_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn compiled_registry() -> registry_breg::CompiledRegistry {
    let project = parse_project_json(
        br#"{
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"statistics-catalog","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://statistics.example.test"},
          "entities":[{
            "id":"entry","primaryDataset":"statistics-catalog","route":"entries",
            "mutationMode":"mutable","classification":"internal",
            "fields":[{"id":"code","type":"string","maximumLength":32,"required":true,"classification":"internal"}]
          }],
          "accessProfiles":[{
            "id":"reader","default":true,"principalClaim":"registry_principal","requiredScopes":"unrestricted",
            "permissions":{"entities":[{
              "entity":"entry","operations":["get"],"readableFields":["code"],"rowBoundaries":"unrestricted"
            }]}
          }]
        }"#,
    )
    .expect("statistics catalog fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring)
        .expect("statistics catalog fixture compiles")
}
