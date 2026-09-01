// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use postgres_harness::TestDatabase;
use registry_server::compiler::{compile_project, CompileProfile};
use registry_server::contract::parse_project_json;
use registry_server::postgres::{
    initialize_compiled_registry_state_for_test, install_compiled_schema,
    verify_catalog_identity_for_catalog, ExpectedManagedCatalog, RegistryStateTestIdentity,
};

const PACKAGE_ID: &str = "partial-unique-registry";
const INSTANCE_ID: &str = "partial-unique-instance";
const DATABASE_ID: &str = "partial-unique-database";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_postgres_partial_unique_index_enforces_only_the_closed_predicate() {
    let project = parse_project_json(
        br#"{
          "apiVersion":"registry.registrystack.org/v1alpha1",
          "kind":"RegistryProject",
          "registry":{"id":"partial-unique","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://authoring.example.test"},
          "entities":[{
            "id":"entry","primaryDataset":"test-dataset","route":"entries","mutationMode":"mutable",
            "fields":[
              {"id":"code","type":"string","maxLength":32,"required":true,"classification":"internal"},
              {"id":"status","type":"vocabulary-code","vocabulary":"status","classification":"internal"},
              {"id":"ended-on","type":"date","classification":"internal"}
            ],
            "constraints":[{
              "kind":"unique","fields":["code"],
              "when":[
                {"kind":"field_equals","field":"status","value":"active"},
                {"kind":"field_is_null","field":"ended-on"},
                {"kind":"active_lifecycle"}
              ]
            }]
          }],
          "accessProfiles":[{
            "id":"operator","default":true,"principalClaim":"principal","grants":[{
              "entity":"entry","operations":["get"],"readableFields":["code","status","ended-on"]
            }]
          }],
          "vocabularies":[{"id":"status","values":["active","closed"]}]
        }"#,
    )
    .expect("partial unique source parses");
    let registry = compile_project(&project, &[], CompileProfile::Authoring)
        .expect("partial unique source compiles");
    let database = TestDatabase::create(1).await;
    let (migration, migration_task) = database.connect_migration().await;
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("partial unique DDL installs");
    let catalog = ExpectedManagedCatalog::compiled(&registry);
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &registry,
        RegistryStateTestIdentity {
            package_id: PACKAGE_ID,
            environment: "local",
            instance_id: INSTANCE_ID,
            database_id: DATABASE_ID,
            package_revision: "partial-unique-package-1",
            package_sequence: 1,
        },
    )
    .await
    .expect("partial unique catalog identity initializes");
    verify_catalog_identity_for_catalog(
        &migration,
        &identity,
        &catalog,
        &database.migration_role,
        &database.runtime_role,
    )
    .await
    .expect("partial unique index is included in the exact catalog fingerprint");
    migration_task.abort();

    let entity = &registry.entities()["entry"];
    let table = quote_identifier(&entity.physical_table);
    let code = quote_identifier(&entity.fields["code"].physical_name);
    let status = quote_identifier(&entity.fields["status"].physical_name);
    let ended_on = quote_identifier(&entity.fields["ended-on"].physical_name);
    let indexdef: String = database
        .admin
        .query_one(
            "SELECT indexdef FROM pg_catalog.pg_indexes
             WHERE schemaname = 'registry_data' AND tablename = $1 AND indexdef LIKE '% WHERE %'",
            &[&entity.physical_table],
        )
        .await
        .expect("partial unique index is visible in the PostgreSQL catalog")
        .get(0);
    assert!(indexdef.starts_with("CREATE UNIQUE INDEX "));
    assert!(indexdef.contains("record_lifecycle = 'active'::text"));

    let insert = format!(
        "INSERT INTO registry_data.{table}
            (record_id, active_package_revision, record_lifecycle, {code}, {status}, {ended_on})
         VALUES ($1::text::uuid, 'partial-unique-package-1', $2, $3, $4, $5::text::date)"
    );
    database
        .admin
        .execute(
            &insert,
            &[
                &"00000000-0000-0000-0000-000000000701",
                &"active",
                &"A-1",
                &"active",
                &Option::<&str>::None,
            ],
        )
        .await
        .expect("first active open row inserts");
    assert!(database
        .admin
        .execute(
            &insert,
            &[
                &"00000000-0000-0000-0000-000000000702",
                &"active",
                &"A-1",
                &"active",
                &Option::<&str>::None,
            ],
        )
        .await
        .is_err());
    for (record_id, lifecycle, status_value, ended_value) in [
        (
            "00000000-0000-0000-0000-000000000703",
            "active",
            "closed",
            None,
        ),
        (
            "00000000-0000-0000-0000-000000000704",
            "active",
            "active",
            Some("2026-08-29"),
        ),
        (
            "00000000-0000-0000-0000-000000000705",
            "tombstoned",
            "active",
            None,
        ),
    ] {
        database
            .admin
            .execute(
                &insert,
                &[&record_id, &lifecycle, &"A-1", &status_value, &ended_value],
            )
            .await
            .expect("rows outside the closed partial predicate may reuse the key");
    }
    database.cleanup().await;
}

fn quote_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}
