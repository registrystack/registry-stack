// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::collections::BTreeSet;
use std::io;
use std::sync::{Arc, Mutex};

use postgres_harness::TestDatabase;
use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_json;
use registry_breg::mutation::{
    install_generated_identifier_schema_for_test, reserve_generated_identifiers_for_test,
    MutationError,
};
use registry_breg::postgres::install_compiled_schema;
use serde_json::{json, Map, Value};
use tracing::instrument::WithSubscriber;
use uuid::Uuid;

fn registry() -> registry_breg::model::CompiledRegistry {
    registry_with_limits(16, 32, true)
}

fn registry_with_limits(
    max_scope_length: u32,
    max_generated_length: u32,
    scoped: bool,
) -> registry_breg::model::CompiledRegistry {
    let mut source: Value = serde_json::from_slice(
        br#"{
          "apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1",
          "kind":"BRegProject",
          "project":{"id":"generated-identifiers","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://identifiers.example.test"},
          "datasets":[{"id":"records"}],
          "recordTypes":[{
            "id":"entry","primaryDataset":"records","route":"entries","mutationMode":"mutable",
            "fields":[
              {"id":"jurisdiction","type":"string","minimumLength":1,"maximumLength":16,"required":true,"classification":"internal"},
              {"id":"issued-at","type":"timestamp","required":true,"classification":"internal"},
              {"id":"public-id","type":"string","minimumLength":1,"maximumLength":32,"required":true,"classification":"internal",
               "generate":{"type":"sequence","prefix":"P-","minimumDigits":4,"scope":["jurisdiction"]}},
              {"id":"daily-id","type":"string","minimumLength":1,"maximumLength":32,"required":true,"classification":"internal",
               "generate":{"type":"sequence","prefix":"D-","minimumDigits":4,"scope":["issued-at"]}},
              {"id":"receipt-code","type":"string","minimumLength":1,"maximumLength":32,"required":true,"classification":"internal",
               "generate":{"type":"random","prefix":"R-","length":12}}
            ]
          }],
          "accessProfiles":[{
            "id":"writer","default":true,"principalClaim":"sub","requiredScopes":"unrestricted",
            "permissions":{"records":[{
              "recordType":"entry","operations":["create","get"],
              "readableFields":["jurisdiction","issued-at","public-id","daily-id","receipt-code"],
              "writableFields":["jurisdiction","issued-at"],"rowBoundaries":"unrestricted"
            }]}
          }]
        }"#,
    )
    .expect("generated identifier project is JSON");
    source["recordTypes"][0]["fields"][0]["maximumLength"] = json!(max_scope_length);
    source["recordTypes"][0]["fields"][2]["maximumLength"] = json!(max_generated_length);
    if !scoped {
        source["recordTypes"][0]["fields"][2]["generate"]["scope"] = json!([]);
    }
    let project = parse_project_json(&serde_json::to_vec(&source).expect("project serializes"))
        .expect("generated identifier project parses");
    compile_project(&project, &[], CompileProfile::Authoring)
        .expect("generated identifier project compiles")
}

fn create_fields(jurisdiction: &str) -> Map<String, Value> {
    Map::from_iter([
        (
            "jurisdiction".to_owned(),
            Value::String(jurisdiction.to_owned()),
        ),
        (
            "issued-at".to_owned(),
            Value::String("2026-10-22T00:00:00Z".to_owned()),
        ),
    ])
}

async fn assert_allocator_acl(database: &TestDatabase) {
    let row = database
        .admin
        .query_one(
            "SELECT
                 has_function_privilege(
                     $1, 'registry_internal.allocate_generated_identifier_sequence(text,text,jsonb)', 'EXECUTE'
                 ),
                 has_function_privilege(
                     $1, 'registry_internal.reserve_generated_identifier(text,text,jsonb,text)', 'EXECUTE'
                 ),
                 has_table_privilege(
                     $1, 'registry_internal.registry_generated_identifier_counters', 'SELECT'
                 ),
                 has_table_privilege(
                     $1, 'registry_internal.registry_generated_identifier_counters', 'UPDATE'
                 ),
                 has_table_privilege(
                     $1, 'registry_internal.registry_generated_identifier_reservations', 'SELECT'
                 ),
                 has_table_privilege(
                     $1, 'registry_internal.registry_generated_identifier_reservations', 'UPDATE'
                 )",
            &[&database.runtime_role.as_str()],
        )
        .await
        .expect("allocator privileges are inspectable");
    assert!(row.get::<_, bool>(0));
    assert!(row.get::<_, bool>(1));
    assert!(!row.get::<_, bool>(2));
    assert!(!row.get::<_, bool>(3));
    assert!(!row.get::<_, bool>(4));
    assert!(!row.get::<_, bool>(5));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sequence_allocation_is_scoped_concurrent_and_rollback_safe() {
    let database = TestDatabase::create(12).await;
    let (migration, migration_task) = database.connect_migration().await;
    install_generated_identifier_schema_for_test(&migration, &database.runtime_role)
        .await
        .expect("allocation schema installs");
    assert_allocator_acl(&database).await;
    migration_task.abort();
    let pool = database
        .runtime_config
        .build_pool()
        .expect("runtime pool builds");

    let entity = Arc::new(registry().entities()["entry"].clone());
    let mut rolled_back = pool.get_for_test().await.expect("runtime connection");
    let transaction = rolled_back.transaction().await.expect("transaction");
    let mut fields = create_fields("north");
    reserve_generated_identifiers_for_test(&transaction, &entity, &mut fields)
        .await
        .expect("allocation succeeds");
    assert_eq!(fields["public-id"], "P-0001");
    transaction.rollback().await.expect("rollback succeeds");

    let mut tasks = Vec::new();
    for _ in 0..10 {
        let pool = pool.clone();
        let entity = Arc::clone(&entity);
        tasks.push(tokio::spawn(async move {
            let mut client = pool.get_for_test().await.expect("runtime connection");
            let transaction = client.transaction().await.expect("transaction");
            let mut fields = create_fields("north");
            reserve_generated_identifiers_for_test(&transaction, &entity, &mut fields)
                .await
                .expect("allocation succeeds");
            transaction.commit().await.expect("allocation commits");
            (
                fields["public-id"].as_str().unwrap().to_owned(),
                fields["receipt-code"].as_str().unwrap().to_owned(),
            )
        }));
    }
    let mut sequences = BTreeSet::new();
    let mut randoms = BTreeSet::new();
    for task in tasks {
        let (sequence, random) = task.await.expect("allocator task joins");
        assert!(sequences.insert(sequence));
        assert!(randoms.insert(random.clone()));
        assert!(random.starts_with("R-"));
        assert_eq!(random.len(), 14);
    }
    assert_eq!(
        sequences,
        (1..=10).map(|value| format!("P-{value:04}")).collect()
    );

    let mut south = pool.get_for_test().await.expect("runtime connection");
    let transaction = south.transaction().await.expect("transaction");
    let mut fields = create_fields("south");
    reserve_generated_identifiers_for_test(&transaction, &entity, &mut fields)
        .await
        .expect("other scope allocates independently");
    assert_eq!(fields["public-id"], "P-0001");
    transaction.commit().await.expect("allocation commits");

    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn maximum_utf8_scope_fits_reservation_and_record_unique_indexes() {
    let registry = registry_with_limits(224, 32, true);
    let entity = &registry.entities()["entry"];
    let database = TestDatabase::create(2).await;
    let (mut migration, migration_task) = database.connect_migration().await;
    install_generated_identifier_schema_for_test(&migration, &database.runtime_role)
        .await
        .expect("allocation schema installs");
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("compiled schema installs");

    let transaction = migration.transaction().await.expect("transaction");
    let scope = "🧩".repeat(224);
    let mut fields = create_fields(&scope);
    reserve_generated_identifiers_for_test(&transaction, entity, &mut fields)
        .await
        .expect("maximum UTF-8 scope reserves");
    let table = quote_identifier(&entity.physical_table);
    let jurisdiction = quote_identifier(&entity.fields["jurisdiction"].physical_name);
    let issued_at = quote_identifier(&entity.fields["issued-at"].physical_name);
    let public_id = quote_identifier(&entity.fields["public-id"].physical_name);
    let daily_id = quote_identifier(&entity.fields["daily-id"].physical_name);
    let receipt_code = quote_identifier(&entity.fields["receipt-code"].physical_name);
    transaction
        .batch_execute(&format!(
            "ALTER TABLE registry_data.{table} NO FORCE ROW LEVEL SECURITY"
        ))
        .await
        .expect("migration owner can seed a retained row");
    transaction
        .execute(
            &format!(
                "INSERT INTO registry_data.{table}
                     (record_id, active_package_revision, {jurisdiction}, {issued_at}, {public_id}, {daily_id}, {receipt_code})
                 VALUES ($1::uuid, 'scope-budget-test', $2, $3::text::timestamptz, $4, $5, $6)"
            ),
            &[
                &Uuid::new_v4(),
                &scope,
                &fields["issued-at"].as_str().unwrap(),
                &fields["public-id"].as_str().unwrap(),
                &fields["daily-id"].as_str().unwrap(),
                &fields["receipt-code"].as_str().unwrap(),
            ],
        )
        .await
        .expect("maximum UTF-8 scope fits the record uniqueness index");
    transaction
        .batch_execute(&format!(
            "ALTER TABLE registry_data.{table} FORCE ROW LEVEL SECURITY"
        ))
        .await
        .expect("row security is restored");
    transaction.commit().await.expect("scope and record commit");

    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn maximum_retained_identifier_fits_migration_reservation_index() {
    let registry = registry_with_limits(16, 256, false);
    let entity = &registry.entities()["entry"];
    let database = TestDatabase::create(2).await;
    let (mut migration, migration_task) = database.connect_migration().await;
    install_generated_identifier_schema_for_test(&migration, &database.runtime_role)
        .await
        .expect("allocation schema installs");
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("compiled schema installs");

    let table = quote_identifier(&entity.physical_table);
    let jurisdiction = quote_identifier(&entity.fields["jurisdiction"].physical_name);
    let issued_at = quote_identifier(&entity.fields["issued-at"].physical_name);
    let public_id = quote_identifier(&entity.fields["public-id"].physical_name);
    let daily_id = quote_identifier(&entity.fields["daily-id"].physical_name);
    let receipt_code = quote_identifier(&entity.fields["receipt-code"].physical_name);
    let retained = "🧩".repeat(256);
    let transaction = migration.transaction().await.expect("transaction");
    transaction
        .batch_execute(&format!(
            "ALTER TABLE registry_data.{table} NO FORCE ROW LEVEL SECURITY"
        ))
        .await
        .expect("migration owner can seed a retained row");
    transaction
        .execute(
            &format!(
                "INSERT INTO registry_data.{table}
                     (record_id, active_package_revision, {jurisdiction}, {issued_at}, {public_id}, {daily_id}, {receipt_code})
                 VALUES ($1::uuid, 'retained-budget-test', $2, $3::text::timestamptz, $4, $5, $6)"
            ),
            &[
                &Uuid::new_v4(),
                &"north",
                &"2026-10-22T00:00:00Z",
                &retained,
                &"D-0001",
                &"R-EXISTING",
            ],
        )
        .await
        .expect("maximum retained identifier fits the record uniqueness index");
    transaction
        .batch_execute(&format!(
            "ALTER TABLE registry_data.{table} FORCE ROW LEVEL SECURITY"
        ))
        .await
        .expect("row security is restored");
    transaction.commit().await.expect("retained row commits");

    let seed = registry
        .ddl()
        .statements
        .iter()
        .find(|statement| statement.id == "entity.entry.field.public-id.generated-identifiers.seed")
        .expect("retained identifier seed exists");
    migration
        .batch_execute(&seed.sql)
        .await
        .expect("maximum retained identifier fits the reservation index");
    let row = migration
        .query_one(
            "SELECT count(*) FROM registry_internal.registry_generated_identifier_reservations
              WHERE entity_id = 'entry' AND field_id = 'public-id' AND generated_value = $1",
            &[&retained],
        )
        .await
        .expect("retained reservation is inspectable");
    assert_eq!(row.get::<_, i64>(0), 1);

    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn supplied_values_are_refused_and_migration_seed_advances_sequence_state() {
    let registry = registry();
    let entity = registry.entities()["entry"].clone();
    let database = TestDatabase::create(2).await;
    let (migration, migration_task) = database.connect_migration().await;
    install_generated_identifier_schema_for_test(&migration, &database.runtime_role)
        .await
        .expect("allocation schema installs");
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("compiled schema installs");
    assert_allocator_acl(&database).await;

    let table = quote_identifier(&entity.physical_table);
    let jurisdiction = quote_identifier(&entity.fields["jurisdiction"].physical_name);
    let public_id = quote_identifier(&entity.fields["public-id"].physical_name);
    let receipt_code = quote_identifier(&entity.fields["receipt-code"].physical_name);
    let issued_at = quote_identifier(&entity.fields["issued-at"].physical_name);
    let daily_id = quote_identifier(&entity.fields["daily-id"].physical_name);
    let insert = format!(
        "INSERT INTO registry_data.{table}
             (record_id, active_package_revision, {jurisdiction}, {issued_at}, {public_id}, {daily_id}, {receipt_code})
         VALUES ($1::uuid, 'seed-package', $2, $3::text::timestamptz, $4, $5, $6)"
    );
    for (record_id, jurisdiction_value, code, daily_code) in [
        (
            "00000000-0000-0000-0000-000000000001",
            "north",
            "P-0007",
            "D-0013",
        ),
        (
            "00000000-0000-0000-0000-000000000002",
            "north",
            "legacy-north",
            "legacy-daily",
        ),
        (
            "00000000-0000-0000-0000-000000000003",
            "north",
            "P-0008",
            "D-0014",
        ),
        (
            "00000000-0000-0000-0000-000000000004",
            "exhausted",
            "P-9223372036854775807",
            "legacy-exhausted-daily",
        ),
        (
            "00000000-0000-0000-0000-000000000005",
            "oversized",
            "P-9999999999999999999999999999",
            "legacy-oversized-daily",
        ),
    ] {
        let record_id = Uuid::parse_str(record_id).expect("fixture UUID is valid");
        database
            .admin
            .execute(
                &insert,
                &[
                    &record_id,
                    &jurisdiction_value,
                    &"2026-10-22T00:00:00Z",
                    &code,
                    &daily_code,
                    &format!("R-{code}"),
                ],
            )
            .await
            .expect("retained row inserts");
    }
    migration
        .batch_execute("SET TIME ZONE 'Asia/Bangkok'")
        .await
        .expect("migration session uses a non-UTC zone");
    let seed = registry
        .ddl()
        .statements
        .iter()
        .find(|statement| statement.id == "entity.entry.field.public-id.generated-identifiers.seed")
        .expect("sequence seed statement exists");
    assert!(seed.sql.starts_with("SET LOCAL TimeZone = 'UTC';"));
    migration
        .batch_execute(&seed.sql)
        .await
        .expect("retained identifiers seed allocation state");
    assert!(!seed.sql.contains("suffix::numeric"));
    let daily_seed = registry
        .ddl()
        .statements
        .iter()
        .find(|statement| statement.id == "entity.entry.field.daily-id.generated-identifiers.seed")
        .expect("timestamp-scoped seed statement exists");
    migration
        .batch_execute(&daily_seed.sql)
        .await
        .expect("timestamp-scoped identifiers seed in UTC");
    migration_task.abort();
    let pool = database
        .runtime_config
        .build_pool()
        .expect("runtime pool builds");

    let mut client = pool.get_for_test().await.expect("runtime connection");
    let transaction = client.transaction().await.expect("transaction");
    let mut fields = create_fields("north");
    reserve_generated_identifiers_for_test(&transaction, &entity, &mut fields)
        .await
        .expect("allocation follows seeded high-water state");
    assert_eq!(fields["public-id"], "P-0009");
    assert_eq!(fields["daily-id"], "D-0015");
    transaction.commit().await.expect("allocation commits");

    let transaction = client.transaction().await.expect("transaction");
    let mut fields = create_fields("exhausted");
    assert_eq!(
        reserve_generated_identifiers_for_test(&transaction, &entity, &mut fields).await,
        Err(MutationError::Conflict),
        "a retained i64::MAX suffix leaves the sequence exhausted"
    );
    transaction.rollback().await.expect("refusal rolls back");

    let transaction = client.transaction().await.expect("transaction");
    let mut fields = create_fields("oversized");
    reserve_generated_identifiers_for_test(&transaction, &entity, &mut fields)
        .await
        .expect("an oversized retained suffix is ignored without numeric conversion");
    assert_eq!(fields["public-id"], "P-0001");
    transaction.commit().await.expect("allocation commits");

    database
        .admin
        .execute(
            "UPDATE registry_internal.registry_generated_identifier_counters
                SET next_value = 9
              WHERE entity_id = 'entry' AND field_id = 'public-id'",
            &[],
        )
        .await
        .expect("test can simulate a stale recovered sequence head");
    let transaction = client.transaction().await.expect("transaction");
    let mut fields = create_fields("north");
    reserve_generated_identifiers_for_test(&transaction, &entity, &mut fields)
        .await
        .expect("reservation ledger skips the already issued value");
    assert_eq!(fields["public-id"], "P-0010");
    transaction.commit().await.expect("allocation commits");

    let transaction = client.transaction().await.expect("transaction");
    let mut supplied = create_fields("north");
    supplied.insert("public-id".to_owned(), json!("P-9999"));
    assert_eq!(
        reserve_generated_identifiers_for_test(&transaction, &entity, &mut supplied).await,
        Err(MutationError::InvalidRequest)
    );
    transaction.rollback().await.expect("refusal rolls back");

    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn allocator_database_failures_log_a_value_free_sqlstate() {
    let database = TestDatabase::create(2).await;
    let (migration, migration_task) = database.connect_migration().await;
    install_generated_identifier_schema_for_test(&migration, &database.runtime_role)
        .await
        .expect("allocation schema installs");
    migration
        .batch_execute(&format!(
            "REVOKE EXECUTE ON FUNCTION
                 registry_internal.reserve_generated_identifier(text, text, jsonb, text)
             FROM {}",
            quote_identifier(database.runtime_role.as_str())
        ))
        .await
        .expect("migration role revokes the reservation function");
    migration_task.abort();
    let pool = database
        .runtime_config
        .build_pool()
        .expect("runtime pool builds");

    let entity = registry().entities()["entry"].clone();
    let logs = Logs::default();
    let subscriber = tracing_subscriber::fmt()
        .json()
        .with_writer(logs.clone())
        .finish();
    let mut client = pool.get_for_test().await.expect("runtime connection");
    let transaction = client.transaction().await.expect("transaction");
    let mut fields = create_fields("scope-canary");
    assert_eq!(
        reserve_generated_identifiers_for_test(&transaction, &entity, &mut fields)
            .with_subscriber(subscriber)
            .await,
        Err(MutationError::Unavailable)
    );
    transaction.rollback().await.expect("failure rolls back");

    let output = String::from_utf8(logs.0.lock().unwrap().clone()).unwrap();
    assert!(output.contains("SQLSTATE 42501"), "{output}");
    for canary in ["scope-canary", "P-0001"] {
        assert!(
            !output.contains(canary),
            "allocator failure logs carry no record values: {output}"
        );
    }

    database.cleanup().await;
}

#[derive(Clone, Default)]
struct Logs(Arc<Mutex<Vec<u8>>>);
impl io::Write for Logs {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Logs {
    type Writer = Self;
    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn quote_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}
