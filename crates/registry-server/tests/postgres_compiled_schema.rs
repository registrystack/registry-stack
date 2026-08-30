// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::time::Duration;

use postgres_harness::TestDatabase;
use registry_server::compiler::{compile_project, compile_project_with_assets, CompileProfile};
use registry_server::contract::{parse_project_json, parse_project_yaml, ModuleAssetSource};
use registry_server::postgres::{
    begin_record_transaction, initialize_registry_state_for_catalog_test, install_compiled_schema,
    verify_catalog_identity_for_catalog, ClaimContext, ExpectedManagedCatalog, RegistryLockKey,
    RegistryStateTestIdentity, RowBoundaryContext,
};

const RECORD_ALPHA: &str = "00000000-0000-0000-0000-000000000201";
const RECORD_BETA: &str = "00000000-0000-0000-0000-000000000202";
const PACKAGE_ID: &str = "compiled-registry";
const INSTANCE_ID: &str = "compiled-instance";
const DATABASE_ID: &str = "compiled-database";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn compiled_postgres_schema_enforces_context_rls_and_exact_catalog() {
    let registry = compiled_registry();
    let database = TestDatabase::create(1).await;
    database
        .admin
        .batch_execute("CREATE EXTENSION btree_gist")
        .await
        .expect("administrator installs the declared prerequisite");
    let (migration, migration_task) = database.connect_migration().await;
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("one product installer applies the exact compiled inventory");
    let catalog = ExpectedManagedCatalog::compiled(&registry);
    let identity = initialize_registry_state_for_catalog_test(
        &migration,
        &database.runtime_role,
        &catalog,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            environment: "local",
            instance_id: INSTANCE_ID,
            database_id: DATABASE_ID,
            package_revision: "compiled-package-1",
            package_sequence: 1,
        },
    )
    .await
    .expect("compiled catalog binds the active Registry identity");
    verify_catalog_identity_for_catalog(
        &migration,
        &identity,
        &catalog,
        &database.migration_role,
        &database.runtime_role,
    )
    .await
    .expect("the exact installed catalog passes startup verification");

    let entity = &registry.entities()["entry"];
    let table = quote_identifier(&entity.physical_table);
    let tenant = quote_identifier(&entity.fields["tenant"].physical_name);
    let region = quote_identifier(&entity.fields["region"].physical_name);
    let label = quote_identifier(&entity.fields["label"].physical_name);
    let event_table = &registry.entities()["event"].physical_table;
    migration_task.abort();

    let pool = database
        .runtime_config
        .build_pool()
        .expect("bounded runtime pool builds");
    let runtime = pool
        .get_for_test()
        .await
        .expect("runtime connection is available");
    for schema in ["registry_source", "registry_derived", "registry_context"] {
        let usage: bool = runtime
            .query_one(
                "SELECT has_schema_privilege(current_user, $1, 'USAGE')
                    AND NOT has_schema_privilege(current_user, $1, 'CREATE')",
                &[&schema],
            )
            .await
            .expect("runtime schema privilege probe succeeds")
            .get(0);
        assert!(usage, "runtime has only USAGE on {schema}");
    }
    let missing: i64 = runtime
        .query_one(&format!("SELECT count(*) FROM registry_data.{table}"), &[])
        .await
        .expect("missing context is an empty RLS view")
        .get(0);
    assert_eq!(missing, 0);
    assert!(runtime
        .execute(
            &format!(
                "INSERT INTO registry_data.{table} (record_id, {tenant}, {region}, {label})
                 VALUES ($1::text::uuid, $2, $3, $4)"
            ),
            &[&RECORD_ALPHA, &"tenant-a", &"north", &"forbidden"],
        )
        .await
        .is_err());
    let update_allowed: bool = runtime
        .query_one(
            "SELECT has_table_privilege(current_user, $1, 'UPDATE')",
            &[&format!("registry_data.{event_table}")],
        )
        .await
        .expect("create-only privilege probe succeeds")
        .get(0);
    assert!(!update_allowed, "create-only tables omit UPDATE privilege");
    drop(runtime);

    let lock_key = RegistryLockKey::derive("compiled-schema-test").expect("lock key is bounded");
    let alpha = context(
        &registry,
        "writer",
        "operations",
        "tenant-a",
        &["north", "south"],
    );
    let beta = context(&registry, "writer", "operations", "tenant-b", &["north"]);
    let reviewer = context(&registry, "reviewer", "review", "tenant-b", &["north"]);
    assert!(ClaimContext::for_compiled(
        &registry,
        "entry",
        Some("principal".to_owned()),
        "writer",
        Some("wrong-purpose".to_owned()),
        boundaries("tenant-a", &["north"]),
    )
    .is_err());

    let mut client = pool
        .get_for_test()
        .await
        .expect("pooled runtime client is available");
    insert_row(
        &mut client,
        lock_key,
        &identity,
        &alpha,
        entity,
        RECORD_ALPHA,
        "tenant-a",
    )
    .await;
    insert_row(
        &mut client,
        lock_key,
        &identity,
        &beta,
        entity,
        RECORD_BETA,
        "tenant-b",
    )
    .await;

    let transaction = begin_record_transaction(
        &mut client,
        lock_key,
        Duration::from_secs(1),
        &identity,
        &alpha,
    )
    .await
    .expect("exact writer context starts");
    let visible: Vec<String> = transaction
        .transaction_for_test()
        .query(
            &format!("SELECT record_id::text FROM registry_data.{table} ORDER BY record_id"),
            &[],
        )
        .await
        .expect("matching read succeeds")
        .into_iter()
        .map(|row| row.get(0))
        .collect();
    assert_eq!(visible, [RECORD_ALPHA]);
    assert!(transaction
        .transaction_for_test()
        .execute(
            &format!(
                "INSERT INTO registry_data.{table} (record_id, {tenant}, {region}, {label})
                 VALUES ('00000000-0000-0000-0000-000000000203', 'tenant-b', 'north', 'denied')"
            ),
            &[],
        )
        .await
        .is_err());
    transaction
        .rollback()
        .await
        .expect("WITH CHECK refusal transaction rolls back");

    let transaction = begin_record_transaction(
        &mut client,
        lock_key,
        Duration::from_secs(1),
        &identity,
        &alpha,
    )
    .await
    .expect("matching update context starts");
    let updated = transaction
        .transaction_for_test()
        .execute(
            &format!(
                "UPDATE registry_data.{table}
                 SET {label} = 'updated', updated_at = transaction_timestamp()
                 WHERE record_id = $1::text::uuid"
            ),
            &[&RECORD_ALPHA],
        )
        .await
        .expect("matching update succeeds");
    assert_eq!(updated, 1);
    transaction.commit().await.expect("update commits");

    let transaction = begin_record_transaction(
        &mut client,
        lock_key,
        Duration::from_secs(1),
        &identity,
        &reviewer,
    )
    .await
    .expect("read-only profile context starts");
    assert!(transaction
        .transaction_for_test()
        .execute(
            &format!(
                "INSERT INTO registry_data.{table} (record_id, {tenant}, {region}, {label})
                 VALUES ('00000000-0000-0000-0000-000000000204', 'tenant-b', 'north', 'denied')"
            ),
            &[],
        )
        .await
        .is_err());
    transaction
        .rollback()
        .await
        .expect("wrong-profile INSERT refusal rolls back");

    for denied in [&reviewer, &beta] {
        let transaction = begin_record_transaction(
            &mut client,
            lock_key,
            Duration::from_secs(1),
            &identity,
            denied,
        )
        .await
        .expect("complete but nonmatching context starts");
        let count: i64 = transaction
            .transaction_for_test()
            .query_one(
                &format!(
                    "SELECT count(*) FROM registry_data.{table} WHERE record_id = $1::text::uuid"
                ),
                &[&RECORD_ALPHA],
            )
            .await
            .expect("nonmatching context receives an empty view")
            .get(0);
        assert_eq!(count, 0);
        transaction.rollback().await.expect("read proof rolls back");
    }

    let clean: bool = client
        .query_one(
            "SELECT NULLIF(current_setting('registry.principal', true), '') IS NULL
                 AND NULLIF(current_setting('registry.access_profile', true), '') IS NULL
                 AND NULLIF(current_setting('registry.purpose', true), '') IS NULL
                 AND NULLIF(current_setting('registry.row_boundaries', true), '') IS NULL
                 AND NULLIF(current_setting('registry.active_package_revision', true), '') IS NULL",
            &[],
        )
        .await
        .expect("pool context probe succeeds")
        .get(0);
    assert!(
        clean,
        "transaction-local generic context is clean after reuse"
    );
    client
        .batch_execute(
            "BEGIN;
             SELECT set_config('registry.principal', 'principal', true);
             SELECT set_config('registry.access_profile', 'writer', true);
             SELECT set_config('registry.purpose', 'operations', true);
             SELECT set_config('registry.row_boundaries', '{malformed', true);",
        )
        .await
        .expect("malformed context can be seeded only by the database credential holder");
    assert!(client
        .query_one(&format!("SELECT count(*) FROM registry_data.{table}"), &[])
        .await
        .is_err());
    client
        .batch_execute("ROLLBACK")
        .await
        .expect("malformed context transaction rolls back");
    drop(client);

    assert_catalog_drift_is_rejected(&database, &catalog, &identity, &table).await;
    database.cleanup().await;

    install_derived_view_fixture().await;
    install_asset_fixture().await;
}

async fn install_derived_view_fixture() {
    let registry = derived_registry();
    let database = TestDatabase::create(1).await;
    let (migration, migration_task) = database.connect_migration().await;
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("derived PostgreSQL schema installs");
    let catalog = ExpectedManagedCatalog::compiled(&registry);
    let identity = initialize_registry_state_for_catalog_test(
        &migration,
        &database.runtime_role,
        &catalog,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            environment: "local",
            instance_id: INSTANCE_ID,
            database_id: DATABASE_ID,
            package_revision: "derived-package-1",
            package_sequence: 1,
        },
    )
    .await
    .expect("derived catalog binds active Registry identity");
    verify_catalog_identity_for_catalog(
        &migration,
        &identity,
        &catalog,
        &database.migration_role,
        &database.runtime_role,
    )
    .await
    .expect("derived catalog passes exact verification");

    let entity = &registry.entities()["household"];
    let table = quote_identifier(&entity.physical_table);
    let tenant = quote_identifier(&entity.fields["tenant"].physical_name);
    let size = quote_identifier(&entity.fields["size"].physical_name);
    let source_view = quote_identifier(&entity.source_relation.sql_name);
    let derived_view_name = registry
        .ddl()
        .views
        .iter()
        .find(|view| view.id == "entity.household.derived.facts")
        .expect("derived view is in compiled DDL inventory")
        .name
        .clone();
    let derived_view = quote_identifier(&derived_view_name);

    let pool = database
        .runtime_config
        .build_pool()
        .expect("bounded runtime pool builds");
    let lock_key = RegistryLockKey::derive("derived-schema-test").expect("lock key is bounded");
    let claims = ClaimContext::for_compiled(
        &registry,
        "household",
        Some("principal".to_owned()),
        "operator",
        None,
        vec![RowBoundaryContext::Equals {
            field: "tenant".to_owned(),
            value: "north".to_owned(),
        }],
    )
    .expect("derived claims match profile");
    let mut client = pool
        .get_for_test()
        .await
        .expect("runtime connection is available");
    let transaction = begin_record_transaction(
        &mut client,
        lock_key,
        Duration::from_secs(1),
        &identity,
        &claims,
    )
    .await
    .expect("runtime transaction starts");
    transaction
        .transaction_for_test()
        .execute(
            &format!(
                "INSERT INTO registry_data.{table} (record_id, {tenant}, {size})
                 VALUES ('00000000-0000-4000-8000-000000000301', 'north', 3)"
            ),
            &[],
        )
        .await
        .expect("matching derived seed row is accepted");
    transaction.commit().await.expect("seed commits");

    let transaction = begin_record_transaction(
        &mut client,
        lock_key,
        Duration::from_secs(1),
        &identity,
        &claims,
    )
    .await
    .expect("read transaction starts");
    transaction
        .transaction_for_test()
        .execute(
            "SELECT set_config('registry.evaluation_date', '2026-08-30', true)",
            &[],
        )
        .await
        .expect("test installs explicit evaluation date");
    let options: String = transaction
        .transaction_for_test()
        .query_one(
            "SELECT COALESCE(array_to_string(reloptions, ','), '')
             FROM pg_catalog.pg_class c
             JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
             WHERE n.nspname = 'registry_derived' AND c.relname = $1",
            &[&derived_view_name],
        )
        .await
        .expect("derived view options are inspectable")
        .get(0);
    assert!(options.contains("security_invoker=true"));
    assert!(options.contains("security_barrier=true"));
    let row = transaction
        .transaction_for_test()
        .query_one(
            &format!(
                "SELECT pg_typeof(child_count)::text, child_count, observed_on::text
                 FROM registry_derived.{derived_view}"
            ),
            &[],
        )
        .await
        .expect("derived wrapper casts declared output types");
    assert_eq!(row.get::<_, String>(0), "bigint");
    assert_eq!(row.get::<_, i64>(1), 3);
    assert_eq!(row.get::<_, String>(2), "2026-08-30");
    let source_visible: i64 = transaction
        .transaction_for_test()
        .query_one(
            &format!("SELECT count(*) FROM registry_source.{source_view}"),
            &[],
        )
        .await
        .expect("source view remains RLS confined")
        .get(0);
    assert_eq!(source_visible, 1);
    assert!(transaction
        .transaction_for_test()
        .execute(
            &format!("UPDATE registry_derived.{derived_view} SET child_count = 5"),
            &[],
        )
        .await
        .is_err());
    transaction.rollback().await.expect("proof rolls back");

    let duplicate_transaction = begin_record_transaction(
        &mut client,
        lock_key,
        Duration::from_secs(1),
        &identity,
        &claims,
    )
    .await
    .expect("duplicate-key seed transaction starts");
    duplicate_transaction
        .transaction_for_test()
        .execute(
            &format!(
                "INSERT INTO registry_data.{table} (record_id, {tenant}, {size})
                 VALUES ('00000000-0000-4000-8000-000000000302', 'north', 4)"
            ),
            &[],
        )
        .await
        .expect("second matching source row is accepted");
    duplicate_transaction
        .commit()
        .await
        .expect("duplicate-key seed commits");

    let duplicate_read = begin_record_transaction(
        &mut client,
        lock_key,
        Duration::from_secs(1),
        &identity,
        &claims,
    )
    .await
    .expect("duplicate-key read transaction starts");
    duplicate_read
        .transaction_for_test()
        .execute(
            "SELECT set_config('registry.evaluation_date', '2026-08-30', true)",
            &[],
        )
        .await
        .expect("duplicate-key proof installs explicit evaluation date");
    assert!(duplicate_read
        .transaction_for_test()
        .query(
            &format!("SELECT * FROM registry_derived.{derived_view}"),
            &[]
        )
        .await
        .is_err());
    duplicate_read
        .rollback()
        .await
        .expect("duplicate-key refusal rolls back");

    let denied_claims = ClaimContext::for_compiled(
        &registry,
        "household",
        Some("principal".to_owned()),
        "operator",
        None,
        vec![RowBoundaryContext::Equals {
            field: "tenant".to_owned(),
            value: "south".to_owned(),
        }],
    )
    .expect("denied derived claims match profile shape");
    let denied_transaction = begin_record_transaction(
        &mut client,
        lock_key,
        Duration::from_secs(1),
        &identity,
        &denied_claims,
    )
    .await
    .expect("denied read transaction starts");
    denied_transaction
        .transaction_for_test()
        .execute(
            "SELECT set_config('registry.evaluation_date', '2026-08-30', true)",
            &[],
        )
        .await
        .expect("test installs explicit evaluation date for denied read");
    let source_denied: i64 = denied_transaction
        .transaction_for_test()
        .query_one(
            &format!("SELECT count(*) FROM registry_source.{source_view}"),
            &[],
        )
        .await
        .expect("source view can be queried through denied RLS")
        .get(0);
    let derived_denied: i64 = denied_transaction
        .transaction_for_test()
        .query_one(
            &format!("SELECT count(*) FROM registry_derived.{derived_view}"),
            &[],
        )
        .await
        .expect("derived view can be queried through denied RLS")
        .get(0);
    assert_eq!(source_denied, 0);
    assert_eq!(derived_denied, 0);
    denied_transaction
        .rollback()
        .await
        .expect("denied proof rolls back");
    migration_task.abort();
    database.cleanup().await;
}

async fn insert_row(
    client: &mut deadpool_postgres::Client,
    lock_key: RegistryLockKey,
    identity: &registry_server::postgres::ExpectedRegistryIdentity,
    context: &ClaimContext,
    entity: &registry_server::model::CompiledEntity,
    record_id: &str,
    tenant_value: &str,
) {
    let table = quote_identifier(&entity.physical_table);
    let tenant = quote_identifier(&entity.fields["tenant"].physical_name);
    let region = quote_identifier(&entity.fields["region"].physical_name);
    let label = quote_identifier(&entity.fields["label"].physical_name);
    let transaction =
        begin_record_transaction(client, lock_key, Duration::from_secs(1), identity, context)
            .await
            .expect("complete context starts an insert transaction");
    transaction
        .transaction_for_test()
        .execute(
            &format!(
                "INSERT INTO registry_data.{table} (record_id, {tenant}, {region}, {label})
                 VALUES ($1::text::uuid, $2, $3, $4)"
            ),
            &[&record_id, &tenant_value, &"north", &"created"],
        )
        .await
        .expect("matching INSERT policy permits the row");
    transaction.commit().await.expect("insert commits");
}

async fn assert_catalog_drift_is_rejected(
    database: &TestDatabase,
    catalog: &ExpectedManagedCatalog,
    identity: &registry_server::postgres::ExpectedRegistryIdentity,
    table: &str,
) {
    let (migration, task) = database.connect_migration().await;
    database
        .admin
        .batch_execute(&format!("GRANT SELECT ON registry_data.{table} TO PUBLIC"))
        .await
        .expect("test administrator introduces PUBLIC grant drift");
    assert!(verify_catalog_identity_for_catalog(
        &migration,
        identity,
        catalog,
        &database.migration_role,
        &database.runtime_role,
    )
    .await
    .is_err());
    database
        .admin
        .batch_execute(&format!(
            "REVOKE SELECT ON registry_data.{table} FROM PUBLIC;
             CREATE POLICY registry_unexpected_policy ON registry_data.{table} FOR SELECT USING (true)"
        ))
        .await
        .expect("test administrator introduces policy drift");
    assert!(verify_catalog_identity_for_catalog(
        &migration,
        identity,
        catalog,
        &database.migration_role,
        &database.runtime_role,
    )
    .await
    .is_err());
    database
        .admin
        .batch_execute(&format!(
            "DROP POLICY registry_unexpected_policy ON registry_data.{table};
             CREATE TABLE registry_data.registry_unexpected_table (id integer)"
        ))
        .await
        .expect("test administrator introduces table drift");
    assert!(verify_catalog_identity_for_catalog(
        &migration,
        identity,
        catalog,
        &database.migration_role,
        &database.runtime_role,
    )
    .await
    .is_err());
    database
        .admin
        .batch_execute(&format!(
            "DROP TABLE registry_data.registry_unexpected_table;
             ALTER TABLE registry_data.{table} OWNER TO \"{}\"",
            database.intruder_role.as_str(),
        ))
        .await
        .expect("test administrator introduces owner drift");
    assert!(verify_catalog_identity_for_catalog(
        &migration,
        identity,
        catalog,
        &database.migration_role,
        &database.runtime_role,
    )
    .await
    .is_err());
    database
        .admin
        .batch_execute(&format!(
            "ALTER TABLE registry_data.{table} OWNER TO \"{}\"",
            database.migration_role.as_str(),
        ))
        .await
        .expect("test administrator restores owner");

    database
        .admin
        .batch_execute(&format!(
            "CREATE FUNCTION registry_internal.registry_unexpected_trigger()
                 RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN NEW; END';
             CREATE TRIGGER registry_unexpected_trigger
                 BEFORE INSERT ON registry_data.{table}
                 FOR EACH ROW EXECUTE FUNCTION registry_internal.registry_unexpected_trigger()"
        ))
        .await
        .expect("test administrator introduces trigger and routine drift");
    assert!(verify_catalog_identity_for_catalog(
        &migration,
        identity,
        catalog,
        &database.migration_role,
        &database.runtime_role,
    )
    .await
    .is_err());
    database
        .admin
        .batch_execute(&format!(
            "DROP TRIGGER registry_unexpected_trigger ON registry_data.{table}"
        ))
        .await
        .expect("test administrator removes trigger drift");
    assert!(verify_catalog_identity_for_catalog(
        &migration,
        identity,
        catalog,
        &database.migration_role,
        &database.runtime_role,
    )
    .await
    .is_err());
    database
        .admin
        .batch_execute("DROP FUNCTION registry_internal.registry_unexpected_trigger()")
        .await
        .expect("test administrator removes routine drift");

    database
        .admin
        .batch_execute(&format!(
            "CREATE RULE registry_unexpected_rule AS
                 ON UPDATE TO registry_data.{table} DO ALSO NOTHING"
        ))
        .await
        .expect("test administrator introduces rewrite-rule drift");
    assert!(verify_catalog_identity_for_catalog(
        &migration,
        identity,
        catalog,
        &database.migration_role,
        &database.runtime_role,
    )
    .await
    .is_err());
    database
        .admin
        .batch_execute(&format!(
            "DROP RULE registry_unexpected_rule ON registry_data.{table}"
        ))
        .await
        .expect("test administrator removes rewrite-rule drift");

    database
        .admin
        .batch_execute("CREATE VIEW registry_data.registry_unexpected_view AS SELECT 1 AS value")
        .await
        .expect("test administrator introduces unsupported relation drift");
    assert!(verify_catalog_identity_for_catalog(
        &migration,
        identity,
        catalog,
        &database.migration_role,
        &database.runtime_role,
    )
    .await
    .is_err());
    database
        .admin
        .batch_execute("DROP VIEW registry_data.registry_unexpected_view")
        .await
        .expect("test administrator removes unsupported relation drift");

    database
        .admin
        .batch_execute(&format!(
            "CREATE PUBLICATION registry_unexpected_publication FOR TABLE registry_data.{table}"
        ))
        .await
        .expect("test PostgreSQL supports table publication drift");
    assert!(verify_catalog_identity_for_catalog(
        &migration,
        identity,
        catalog,
        &database.migration_role,
        &database.runtime_role,
    )
    .await
    .is_err());
    database
        .admin
        .batch_execute("DROP PUBLICATION registry_unexpected_publication")
        .await
        .expect("test administrator removes publication drift");

    verify_catalog_identity_for_catalog(
        &migration,
        identity,
        catalog,
        &database.migration_role,
        &database.runtime_role,
    )
    .await
    .expect("restored exact catalog verifies");
    task.abort();
}

async fn install_asset_fixture() {
    let project = parse_project_yaml(include_bytes!(
        "../../../products/registry-server/acceptance/asset-site-placement/registry.yaml"
    ))
    .expect("actual asset fixture parses");
    let registry = compile_project(&project, &[], CompileProfile::Authoring)
        .expect("actual asset fixture compiles");
    assert!(registry.ddl().requires_btree_gist);
    let database = TestDatabase::create(1).await;
    database
        .admin
        .batch_execute("CREATE EXTENSION btree_gist")
        .await
        .expect("asset database receives btree_gist");
    let (migration, task) = database.connect_migration().await;
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("actual fixture DDL installs without production fixture types");
    let catalog = ExpectedManagedCatalog::compiled(&registry);
    let identity = initialize_registry_state_for_catalog_test(
        &migration,
        &database.runtime_role,
        &catalog,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            environment: "local",
            instance_id: INSTANCE_ID,
            database_id: DATABASE_ID,
            package_revision: "asset-package-1",
            package_sequence: 1,
        },
    )
    .await
    .expect("actual fixture catalog is fingerprinted");
    verify_catalog_identity_for_catalog(
        &migration,
        &identity,
        &catalog,
        &database.migration_role,
        &database.runtime_role,
    )
    .await
    .expect("actual fixture passes exact catalog startup");
    task.abort();
    database.cleanup().await;
}

fn context(
    registry: &registry_server::CompiledRegistry,
    profile: &str,
    purpose: &str,
    tenant: &str,
    regions: &[&str],
) -> ClaimContext {
    ClaimContext::for_compiled(
        registry,
        "entry",
        Some("verified-principal".to_owned()),
        profile,
        Some(purpose.to_owned()),
        boundaries(tenant, regions),
    )
    .expect("test context exactly matches the compiled profile")
}

fn boundaries(tenant: &str, regions: &[&str]) -> Vec<RowBoundaryContext> {
    vec![
        RowBoundaryContext::Equals {
            field: "tenant".to_owned(),
            value: tenant.to_owned(),
        },
        RowBoundaryContext::In {
            field: "region".to_owned(),
            values: regions.iter().map(|value| (*value).to_owned()).collect(),
        },
    ]
}

fn quote_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn compiled_registry() -> registry_server::CompiledRegistry {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"compiled-postgres","version":"1","defaultLanguage":"en"},
          "entities":[
            {
              "id":"entry","route":"entries","mutationMode":"mutable",
              "fields":[
                {"id":"tenant","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"},
                {"id":"region","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"},
                {"id":"label","type":"string","minLength":1,"maxLength":128,"required":true,"classification":"internal"}
              ],
              "accessProfiles":[
                {
                  "id":"writer","default":true,"principalClaim":"registry_principal",
                  "requiredPurposes":["operations"],
                  "operations":["create","get","list","patch"],
                  "readableFields":["tenant","region","label"],
                  "writableFields":["tenant","region","label"],
                  "rowBoundaries":[
                    {"field":"tenant","claim":"tenant_claim","operator":"equals"},
                    {"field":"region","claim":"region_claim","operator":"in"}
                  ]
                },
                {
                  "id":"reviewer","principalClaim":"registry_principal",
                  "requiredPurposes":["review"],
                  "operations":["get","list"],
                  "readableFields":["tenant","region","label"],
                  "rowBoundaries":[
                    {"field":"tenant","claim":"tenant_claim","operator":"equals"},
                    {"field":"region","claim":"region_claim","operator":"in"}
                  ]
                }
              ]
            },
            {
              "id":"event","route":"events","mutationMode":"create_only",
              "fields":[
                {"id":"tenant","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"}
              ],
              "accessProfiles":[{
                "id":"writer","default":true,"principalClaim":"registry_principal",
                "requiredPurposes":["operations"],
                "operations":["create","get","list"],
                "readableFields":["tenant"],"writableFields":["tenant"]
              }]
            }
          ]
        }"#,
    )
    .expect("compiled PostgreSQL fixture parses");
    compile_project(&project, &[], CompileProfile::Authoring)
        .expect("compiled PostgreSQL fixture compiles")
}

fn derived_registry() -> registry_server::CompiledRegistry {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"derived-postgres","version":"1","defaultLanguage":"en"},
          "entities":[{
            "id":"household","route":"households","mutationMode":"mutable",
            "fields":[
              {"id":"tenant","type":"string","minLength":1,"maxLength":64,"required":true,"classification":"internal"},
              {"id":"size","type":"int64","required":true,"classification":"internal"}
            ],
            "derived":[{
              "id":"facts","sql":"sql/facts.sql","key":"id","execution":"live",
              "fields":[
                {"id":"child-count","type":"int64","classification":"internal"},
                {"id":"observed-on","type":"date","classification":"internal"}
              ]
            }],
            "accessProfiles":[{
              "id":"operator","default":true,"principalClaim":"registry_principal",
              "operations":["create","get","list"],
              "readableFields":["tenant","size","child-count","observed-on"],
              "writableFields":["tenant","size"],
              "filterableFields":["child-count"],
              "sortableFields":["child-count"],
              "rowBoundaries":[{"field":"tenant","claim":"tenant_claim","operator":"equals"}]
            }]
          }]
        }"#,
    )
    .expect("derived PostgreSQL fixture parses");
    compile_project_with_assets(
        &project,
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "sql/facts.sql".to_owned(),
            bytes: b"SELECT h.id AS id, h.size AS child_count, registry_context.evaluation_date() AS observed_on FROM registry_source.household h JOIN registry_source.household sibling ON sibling.tenant = h.tenant".to_vec(),
        }],
        CompileProfile::Authoring,
    )
    .expect("derived PostgreSQL fixture compiles")
}
