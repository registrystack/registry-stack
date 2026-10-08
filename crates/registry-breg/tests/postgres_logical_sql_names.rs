// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "postgres-test")]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use registry_breg::compiler::{compile_project, compile_project_with_assets, CompileProfile};
use registry_breg::contract::{parse_project_json, ModuleAssetSource};
use registry_breg::postgres::{
    initialize_compiled_registry_state_for_test, install_compiled_schema,
    verify_catalog_identity_for_catalog, ExpectedManagedCatalog, RegistryStateTestIdentity,
};
use serde_json::{json, Value};

fn compile(
    source: Value,
) -> Result<registry_breg::CompiledRegistry, registry_breg::diagnostics::CompileFailure> {
    let project = parse_project_json(&serde_json::to_vec(&source).expect("source serializes"))
        .expect("source parses");
    compile_project(&project, &[], CompileProfile::Authoring)
}

fn project_with_entities(entities: Value) -> Value {
    json!({
        "apiVersion": "registry.registrystack.org/v1alpha1",
        "kind": "RegistryProject",
        "registry": {
            "id": "logical-sql-names",
            "version": "1",
            "defaultLanguage": "en",
            "canonicalBaseIri": "https://logical-sql-names.example.test"
        },
        "entities": entities
    })
}

#[test]
fn fields_that_only_differ_after_postgres_identifier_limit_are_refused() {
    let prefix = format!("f{}", "x".repeat(62));
    let failure = compile(project_with_entities(json!([{
        "id": "record",
        "route": "records",
        "primaryDataset": "records",
        "mutationMode": "mutable",
        "fields": [
            {"id": format!("{prefix}a"), "type": "boolean", "classification": "internal"},
            {"id": format!("{prefix}b"), "type": "boolean", "classification": "internal"}
        ]
    }])))
    .expect_err("PostgreSQL would collapse the two source-view columns");

    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "breg.field.sql-name-duplicate"));
}

#[test]
fn entities_that_only_differ_after_postgres_identifier_limit_are_refused() {
    let prefix = format!("e{}", "x".repeat(62));
    let failure = compile(project_with_entities(json!([
        {
            "id": format!("{prefix}a"),
            "route": "records-a",
            "primaryDataset": "records-a",
            "mutationMode": "mutable",
            "fields": [{"id": "flag", "type": "boolean", "classification": "internal"}]
        },
        {
            "id": format!("{prefix}b"),
            "route": "records-b",
            "primaryDataset": "records-b",
            "mutationMode": "mutable",
            "fields": [{"id": "flag", "type": "boolean", "classification": "internal"}]
        }
    ])))
    .expect_err("PostgreSQL would collapse the two source-view names");

    assert!(failure
        .diagnostics()
        .iter()
        .any(|diagnostic| diagnostic.code == "breg.entity.sql-name-duplicate"));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_64_byte_entity_and_field_install_with_exact_canonical_catalog_names() {
    let entity_id = format!("e{}", "x".repeat(63));
    let field_id = format!("f{}", "x".repeat(63));
    let source = project_with_entities(json!([{
        "id": entity_id,
        "route": "records",
        "primaryDataset": "records",
        "mutationMode": "mutable",
        "fields": [{"id": field_id, "type": "boolean", "classification": "internal"}],
        "derived": [{
            "id": "copy",
            "sql": "sql/copy.sql",
            "key": "id",
            "execution": "live",
            "fields": [{"id": "copied", "type": "boolean", "classification": "internal"}]
        }]
    }]));
    let project = parse_project_json(&serde_json::to_vec(&source).expect("source serializes"))
        .expect("source parses");
    let sql = format!(
        "SELECT source.id AS id, source.{field_id} AS copied FROM registry_source.{entity_id} AS source"
    );
    let compiled = compile_project_with_assets(
        &project,
        &[],
        &[ModuleAssetSource {
            module: None,
            path: "sql/copy.sql".to_owned(),
            bytes: sql.into_bytes(),
        }],
        CompileProfile::Authoring,
    )
    .unwrap_or_else(|failure| {
        panic!(
            "64-byte authored SQL names compile: {:?}",
            failure.diagnostics()
        )
    });

    let entity = &compiled.entities()[&entity_id];
    let canonical_entity = &entity_id[..63];
    let canonical_field = &field_id[..63];
    assert_eq!(entity.source_relation.sql_name, canonical_entity);
    assert_eq!(entity.stored_fields[0].logical.id, field_id);
    assert_eq!(entity.stored_fields[0].logical.sql_name, canonical_field);
    assert_eq!(
        entity.derived_relations["copy"].source_entities,
        [entity_id.clone()].into(),
        "the parser-canonicalized source relation retains its authored dependency identity"
    );

    let database = postgres_harness::TestDatabase::create(2).await;
    let (migration, migration_task) = database.connect_migration().await;
    install_compiled_schema(&migration, &compiled, &database.runtime_role)
        .await
        .expect("compiled schema with canonical source names installs");
    let identity = initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &compiled,
        RegistryStateTestIdentity {
            package_id: "logical-sql-names",
            database_id: "logical-sql-names-db",
            label: "logical-sql-names-64",
        },
    )
    .await
    .expect("runtime identity initializes");
    verify_catalog_identity_for_catalog(
        &migration,
        &identity,
        &ExpectedManagedCatalog::compiled(&compiled),
        &database.migration_role,
        &database.runtime_role,
    )
    .await
    .expect("exact catalog verification uses the canonical 63-byte names");
    let installed: bool = migration
        .query_one(
            "SELECT EXISTS (
                 SELECT 1
                   FROM pg_catalog.pg_class AS relation
                   JOIN pg_catalog.pg_namespace AS namespace
                     ON namespace.oid = relation.relnamespace
                   JOIN pg_catalog.pg_attribute AS attribute
                     ON attribute.attrelid = relation.oid
                  WHERE namespace.nspname = 'registry_source'
                    AND relation.relname = $1
                    AND attribute.attname = $2
                    AND attribute.attnum > 0
                    AND NOT attribute.attisdropped
             )",
            &[&canonical_entity, &canonical_field],
        )
        .await
        .expect("installed source catalog reads")
        .get(0);
    assert!(installed);

    migration_task.abort();
    database.cleanup().await;
}
