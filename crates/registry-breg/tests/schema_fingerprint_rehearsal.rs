// SPDX-License-Identifier: Apache-2.0

#![cfg(all(feature = "postgres-test", feature = "tooling"))]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use postgres_harness::TestDatabase;
use registry_breg::compiler::{compile_project, CompileProfile};
use registry_breg::contract::parse_project_json;
use registry_breg::package::{
    prepare_package, PackageBuildRequest, PackageError, PackageMigrationPlanInput,
    PackageSourceFile, PreparedPackage,
};
use registry_breg::postgres::{
    install_compiled_schema, managed_schema_fingerprint, verify_catalog_identity_for_catalog,
    ExpectedManagedCatalog, ExpectedRegistryIdentity, PostgresKernelError,
};
use registry_breg::runtime_config::{parse_runtime_config, RuntimeConfig};
use registry_breg::startup::{
    prepare_schema_test_database_with_connection_configs_for_test, rehearse_schema_fingerprint,
    rehearse_schema_fingerprint_with_connection_config_for_test, StartupError,
};
use registry_breg::CompiledRegistry;

const ENVIRONMENT: &str = "production";
const INSTANCE: &str = "rehearsal-instance";
const DATABASE: &str = "rehearsal-database";
const SOURCE_REVISION: &str = "rehearsal-source-revision";
// Includes the runtime Evidence expiry function and both expires_at indexes.
const PORTABLE_SCHEMA_FINGERPRINT: &str =
    "sha256:a1af7c639b023a4f67e3028be90d8cbf5fce028e25664f6561fc60d4ccf3e798";
const FIXTURE_JOURNEYS: &[u8] = br#"apiVersion: id.registrystack.org/formats/breg/journeys/v1
kind: BRegJourneys
journeys: []
"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rehearsal_rolls_back_and_matches_committed_schema_test_preparation() {
    let registry = compiled_registry(SOURCE_REVISION);
    let database = TestDatabase::create(1).await;
    let config = runtime_config(&database, ENVIRONMENT, INSTANCE);

    let fingerprint = rehearse_schema_fingerprint_with_connection_config_for_test(
        &config,
        &registry,
        &database.migration_config,
    )
    .await
    .expect("schema fingerprint rehearsal succeeds on an empty disposable database");
    assert_eq!(fingerprint, PORTABLE_SCHEMA_FINGERPRINT);

    assert!(
        managed_schemas_empty_by_restrict(&database).await,
        "successful rehearsal rolls back every managed schema dependency"
    );
    assert!(
        registry_state_table(&database).await.is_none(),
        "successful rehearsal never leaves active package state behind"
    );

    let package = prepared_package(&fingerprint);
    prepare_schema_test_database_with_connection_configs_for_test(
        &config,
        &package,
        &database.migration_config,
        &database.runtime_config,
    )
    .await
    .expect("schema-test preparation can commit into the same database after rehearsal");
    assert_eq!(
        active_schema_fingerprint(&database).await,
        fingerprint,
        "committed schema-test state carries the rehearsed fingerprint"
    );
    assert_generated_text_collation(&database).await;
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn catalog_verification_refuses_non_portable_text_collation() {
    let registry = compiled_registry(SOURCE_REVISION);
    let database = TestDatabase::create(1).await;
    let config = runtime_config(&database, ENVIRONMENT, INSTANCE);
    let fingerprint = rehearse_schema_fingerprint_with_connection_config_for_test(
        &config,
        &registry,
        &database.migration_config,
    )
    .await
    .expect("schema fingerprint rehearsal succeeds");
    let package = prepared_package(&fingerprint);
    prepare_schema_test_database_with_connection_configs_for_test(
        &config,
        &package,
        &database.migration_config,
        &database.runtime_config,
    )
    .await
    .expect("schema-test preparation succeeds");
    let state = database
        .admin
        .query_one(
            "SELECT package_id, database_id, active_package_digest,
                    active_activation_id::text, schema_fingerprint
               FROM registry_internal.registry_state
              WHERE singleton",
            &[],
        )
        .await
        .expect("active registry state is readable");
    let expected = ExpectedRegistryIdentity {
        package_id: state.get(0),
        database_id: state.get(1),
        package_digest: state.get(2),
        activation_id: state.get(3),
        schema_fingerprint: state.get(4),
    };
    let entity = &registry.entities()["case"];
    database
        .admin
        .batch_execute(&format!(
            "ALTER TABLE registry_data.\"{}\"
                 ALTER COLUMN active_package_revision TYPE text COLLATE \"C\"",
            entity.physical_table,
        ))
        .await
        .expect("test can introduce a non-portable collation");
    let (migration, migration_task) = database.connect_migration().await;
    assert!(
        verify_catalog_identity_for_catalog(
            &migration,
            &expected,
            &ExpectedManagedCatalog::compiled(&registry),
            &database.migration_role,
            &database.runtime_role,
        )
        .await
        .is_err(),
        "catalog verification refuses a text column outside pg_catalog.pg_c_utf8"
    );
    drop(migration);
    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn activation_refuses_a_non_utf8_database_with_fresh_install_recovery() {
    let registry = compiled_registry(SOURCE_REVISION);
    let database = TestDatabase::create_with_encoding(1, "SQL_ASCII").await;
    let (migration, migration_task) = database.connect_migration().await;
    let refusal = install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect_err("a non-UTF8 database is not an activation target");
    assert!(matches!(
        refusal,
        PostgresKernelError::Configuration(message)
            if message.contains("server_encoding must be UTF8")
                && message.contains("fresh UTF8 database")
                && message.contains("CREATE DATABASE <name> ENCODING 'UTF8' TEMPLATE template0")
    ));
    drop(migration);
    migration_task.abort();
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fingerprint_refuses_an_unvalidated_not_null_constraint() {
    let registry = compiled_registry(SOURCE_REVISION);
    let database = TestDatabase::create(1).await;
    let (migration, migration_task) = database.connect_migration().await;
    let server_version_num: i32 = migration
        .query_one("SELECT current_setting('server_version_num')::integer", &[])
        .await
        .expect("the PostgreSQL server version is readable")
        .get(0);
    if server_version_num < 180_000 {
        assert!(
            (170_000..180_000).contains(&server_version_num),
            "the compatibility lane uses PostgreSQL 17: {server_version_num}"
        );
        drop(migration);
        migration_task.abort();
        database.cleanup().await;
        return;
    }
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("the compiled schema installs before the catalog is tampered");
    let entity = &registry.entities()["case"];
    let code = &entity.fields["code"];
    migration
        .batch_execute(&format!(
            "ALTER TABLE registry_data.\"{}\"
                 ADD CONSTRAINT breg_unvalidated_not_null
                 NOT NULL \"{}\" NOT VALID",
            entity.physical_table, code.physical_name,
        ))
        .await
        .expect("PostgreSQL 18 accepts an unvalidated NOT NULL constraint");
    let refusal = managed_schema_fingerprint(
        &migration,
        &database.runtime_role,
        &ExpectedManagedCatalog::compiled(&registry),
    )
    .await
    .expect_err("an unvalidated NOT NULL constraint is never excluded from the fingerprint");
    assert!(matches!(
        refusal,
        PostgresKernelError::CatalogInvariant(message)
            if message.contains("NOT NULL constraint is not validated")
                && message.contains("validate it before applying")
    ));
    drop(migration);
    migration_task.abort();
    database.cleanup().await;
}

async fn assert_generated_text_collation(database: &TestDatabase) {
    let database_collation: String = database
        .admin
        .query_one(
            "SELECT datcollate FROM pg_catalog.pg_database WHERE datname = current_database()",
            &[],
        )
        .await
        .expect("database collation is readable")
        .get(0);
    assert!(
        !matches!(database_collation.as_str(), "C" | "POSIX"),
        "the proof database uses a locale default: {database_collation}"
    );
    let row = database
        .admin
        .query_one(
            "SELECT count(*)::bigint,
                    count(*) FILTER (
                        WHERE cn.nspname = 'pg_catalog' AND coll.collname = 'pg_c_utf8'
                    )::bigint
               FROM pg_catalog.pg_attribute a
               JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
               JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
               JOIN pg_catalog.pg_collation coll ON coll.oid = a.attcollation
               JOIN pg_catalog.pg_namespace cn ON cn.oid = coll.collnamespace
              WHERE n.nspname = 'registry_data'
                AND c.relkind = 'r'
                AND a.attnum > 0
                AND NOT a.attisdropped",
            &[],
        )
        .await
        .expect("generated text collations are readable");
    let collatable = row.get::<_, i64>(0);
    assert!(collatable > 0, "fixture installs collatable columns");
    assert_eq!(
        row.get::<_, i64>(1),
        collatable,
        "every generated collatable column uses pg_catalog.pg_c_utf8"
    );
    let row = database
        .admin
        .query_one(
            "SELECT count(*)::bigint,
                    count(*) FILTER (
                        WHERE cn.nspname = 'pg_catalog' AND coll.collname = 'pg_c_utf8'
                    )::bigint
               FROM pg_catalog.pg_index i
               JOIN pg_catalog.pg_class c ON c.oid = i.indrelid
               JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
               CROSS JOIN LATERAL unnest(i.indcollation::oid[]) AS index_collation(oid)
               JOIN pg_catalog.pg_collation coll ON coll.oid = index_collation.oid
               JOIN pg_catalog.pg_namespace cn ON cn.oid = coll.collnamespace
              WHERE n.nspname = 'registry_data'",
            &[],
        )
        .await
        .expect("generated index collations are readable");
    let collatable_indexes = row.get::<_, i64>(0);
    assert!(collatable_indexes > 0, "fixture installs a text index");
    assert_eq!(
        row.get::<_, i64>(1),
        collatable_indexes,
        "generated text indexes inherit pg_catalog.pg_c_utf8 under a locale database default"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rehearsal_and_schema_test_prepare_refuse_dirty_text_search_configuration() {
    let registry = compiled_registry(SOURCE_REVISION);
    let database = TestDatabase::create(1).await;
    database
        .admin
        .batch_execute(
            "CREATE TEXT SEARCH CONFIGURATION registry_data.dirty_canary
                 ( COPY = pg_catalog.simple )",
        )
        .await
        .expect("test can create a dirty managed text search configuration");
    let config = runtime_config(&database, ENVIRONMENT, INSTANCE);

    assert_eq!(
        rehearse_schema_fingerprint_with_connection_config_for_test(
            &config,
            &registry,
            &database.migration_config,
        )
        .await
        .err(),
        Some(StartupError::DatabaseUnready)
    );
    assert!(
        registry_state_table(&database).await.is_none(),
        "dirty-database refusal happens before the installer creates managed state"
    );
    assert!(
        text_search_configuration_exists(&database).await,
        "rehearsal refusal preserves the dirty managed text search configuration"
    );
    assert!(
        !managed_schemas_empty_by_restrict(&database).await,
        "dirty-database refusal does not erase the polluted managed schema"
    );

    let package =
        prepared_package("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    assert_eq!(
        prepare_schema_test_database_with_connection_configs_for_test(
            &config,
            &package,
            &database.migration_config,
            &database.runtime_config,
        )
        .await
        .err(),
        Some(StartupError::DatabaseUnready)
    );
    assert!(
        text_search_configuration_exists(&database).await,
        "schema-test preparation also preserves the dirty managed text search configuration"
    );
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rehearsal_refuses_migration_connection_using_the_runtime_role() {
    let registry = compiled_registry(SOURCE_REVISION);
    let database = TestDatabase::create(1).await;
    let config = runtime_config(&database, ENVIRONMENT, INSTANCE);

    assert_eq!(
        rehearse_schema_fingerprint_with_connection_config_for_test(
            &config,
            &registry,
            &database.runtime_config,
        )
        .await
        .err(),
        Some(StartupError::DatabaseUnready)
    );
    assert!(
        managed_schemas_empty_by_restrict(&database).await,
        "wrong migration role is refused before any managed schema dependency is installed"
    );
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn injected_rehearsal_seam_does_not_read_runtime_database_secret() {
    let registry = compiled_registry(SOURCE_REVISION);
    let database = TestDatabase::create(1).await;
    let config = runtime_config(&database, ENVIRONMENT, INSTANCE);

    rehearse_schema_fingerprint_with_connection_config_for_test(
        &config,
        &registry,
        &database.migration_config,
    )
    .await
    .expect("injected migration rehearsal does not require the runtime database secret");
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rehearsal_binding_is_refused_before_database_secret_resolution() {
    // A rehearsal needs a production candidate. An authoring compile carries
    // no package identity, so it is refused before any database secret.
    let project = parse_project_json(&project_bytes(SOURCE_REVISION)).unwrap();
    let mut authoring = project.clone();
    authoring.package = None;
    let registry = compile_project(&authoring, &[], CompileProfile::Authoring)
        .expect("authoring project compiles");
    let config = runtime_config_with_roles(
        ENVIRONMENT,
        INSTANCE,
        "registry_migration",
        "registry_runtime",
    );

    assert_eq!(
        rehearse_schema_fingerprint(&config, &registry).await.err(),
        Some(StartupError::PackageRefused(PackageError::Binding)),
        "the candidate binding is checked before missing database secrets can be resolved"
    );
}

async fn active_schema_fingerprint(database: &TestDatabase) -> String {
    database
        .admin
        .query_one(
            "SELECT schema_fingerprint FROM registry_internal.registry_state WHERE singleton",
            &[],
        )
        .await
        .expect("active schema fingerprint can be inspected")
        .get(0)
}

async fn registry_state_table(database: &TestDatabase) -> Option<String> {
    database
        .admin
        .query_one(
            "SELECT to_regclass('registry_internal.registry_state')::text",
            &[],
        )
        .await
        .expect("registry_state table presence can be inspected")
        .get(0)
}

async fn text_search_configuration_exists(database: &TestDatabase) -> bool {
    database
        .admin
        .query_one(
            "SELECT EXISTS (
                 SELECT 1
                   FROM pg_catalog.pg_ts_config c
                   JOIN pg_catalog.pg_namespace n ON n.oid = c.cfgnamespace
                  WHERE n.nspname = 'registry_data'
                    AND c.cfgname = 'dirty_canary'
             )",
            &[],
        )
        .await
        .expect("managed text search configuration can be inspected")
        .get(0)
}

async fn managed_schemas_empty_by_restrict(database: &TestDatabase) -> bool {
    database
        .admin
        .batch_execute("BEGIN")
        .await
        .expect("empty-schema probe transaction starts");
    let empty = database
        .admin
        .batch_execute("DROP SCHEMA registry_internal RESTRICT; DROP SCHEMA registry_data RESTRICT")
        .await
        .is_ok();
    database
        .admin
        .batch_execute("ROLLBACK")
        .await
        .expect("empty-schema probe transaction rolls back");
    empty
}

fn runtime_config(database: &TestDatabase, environment: &str, instance_id: &str) -> RuntimeConfig {
    runtime_config_with_roles(
        environment,
        instance_id,
        database.migration_role.as_str(),
        database.runtime_role.as_str(),
    )
}

fn runtime_config_with_roles(
    environment: &str,
    instance_id: &str,
    migration_role: &str,
    runtime_role: &str,
) -> RuntimeConfig {
    parse_runtime_config(&format!(
        r#"apiVersion: id.registrystack.org/formats/breg/runtime/v1alpha1
kind: BRegRuntimeConfig
listener:
  bind: 127.0.0.1:8080
identity:
  environment: {environment}
  instanceId: {instance_id}
  databaseId: {DATABASE}
  databaseInitializationEnvironment: {environment}
secretProviders:
  environment: {{}}
database:
  runtimeUrlRef: secret:env/BREG_REHEARSAL_RUNTIME_URL
  migrationUrlRef: secret:env/BREG_REHEARSAL_MIGRATION_URL
  pool:
    maximumConnections: 2
    waitTimeoutMilliseconds: 1000
    createTimeoutMilliseconds: 1000
    recycleTimeoutMilliseconds: 1000
  roles:
    migration: {migration_role}
    runtime: {runtime_role}
package:
  root: /tmp/breg-rehearsal-package
authentication:
  oidc:
    issuer: https://issuer.example
    audience: urn:breg:rehearsal
    allowedAlgorithm: EdDSA
    accessTokenType: JWT
    scopeClaim: scope
    scopeSeparator: " "
    allowedClients: [registry-client]
    maximumTokenLifetimeSeconds: 300
    leewayMilliseconds: 60000
    jwksCache:
      cacheTtlSeconds: 600
      negativeCacheTtlSeconds: 60
      refreshCooldownSeconds: 30
      maximumDocumentBytes: 65536
      attemptTimeoutMilliseconds: 5000
      outageToleranceSeconds: 900
  authorityClaims:
    principal: registry_principal
    purpose: registry_purpose
audit:
  hashKeyRef: secret:env/BREG_REHEARSAL_AUDIT_KEY
  path: /tmp/breg-rehearsal-audit/audit.jsonl
cursor:
  secretRef: secret:env/BREG_REHEARSAL_CURSOR_KEY
  maximumAgeSeconds: 300
destinations:
  hooks: {{}}
operationalTimeouts:
  httpRequestMilliseconds: 10000
  shutdownGraceMilliseconds: 30000
  recordLockMilliseconds: 5000
  migrationLockMilliseconds: 30000
  migrationStatementMilliseconds: 60000
"#
    ))
    .expect("test runtime config parses")
}

fn prepared_package(schema_fingerprint: &str) -> PreparedPackage {
    prepared_package_with_source(schema_fingerprint, project_bytes(SOURCE_REVISION))
}

fn prepared_package_with_source(schema_fingerprint: &str, project: Vec<u8>) -> PreparedPackage {
    prepare_package(PackageBuildRequest {
        from_package_digest: None,
        compiler_source_revision: SOURCE_REVISION.to_owned(),
        schema_fingerprint: schema_fingerprint.to_owned(),
        project: PackageSourceFile {
            path: "source/registry.json".to_owned(),
            bytes: project,
        },
        modules: vec![],
        fixture_journeys: PackageSourceFile {
            path: "tests/journeys.yaml".to_owned(),
            bytes: FIXTURE_JOURNEYS.to_vec(),
        },
        migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
    })
    .expect("prepared package builds around rehearsed fingerprint")
}

fn compiled_registry(source_revision: &str) -> CompiledRegistry {
    let project = project_bytes(source_revision);
    let parsed = parse_project_json(&project).expect("production project parses");
    compile_project(&parsed, &[], CompileProfile::Production).expect("production project compiles")
}

fn project_bytes(source_revision: &str) -> Vec<u8> {
    let project = format!(
        r#"{{"datasets":[{{"id": "test-dataset"}}],
  "apiVersion": "id.registrystack.org/formats/breg/project/v1alpha1",
  "kind": "BRegProject",
  "project": {{"id": "rehearsal-registry", "version": "1", "defaultLanguage": "en", "canonicalBaseIri": "https://authoring.example.test"}},
  "package": {{
    "sourceRevision": "{source_revision}"
  }},
  "manifestProjection": {{
    "accessProfile": "reader",
    "classificationCeiling": "internal",
    "catalog": {{
      "baseUrl": "https://rehearsal.example.test",
      "title": "Rehearsal Registry",
      "publisher": {{"id": "rehearsal-authority", "name": "Rehearsal Publisher"}}
    }},
    "publicService": {{"id": "rehearsal-service", "title": "Rehearsal Registry"}},
    "datasets": [{{
      "id": "test-dataset", "title": "Rehearsal Dataset",
      "owner": "Rehearsal Publisher", "status": "active"
    }}],
    "dataServices": [{{
      "id": "rehearsal-data-service", "title": "Rehearsal Registry",
      "endpointUrl": "https://rehearsal.example.test",
      "servesDatasets": ["test-dataset"]
    }}],
    "distributions": []
  }},
  "recordTypes": [{{
    "id": "case",
    "primaryDataset": "test-dataset",
    "route": "cases",
    "mutationMode": "create-only",
    "fields": [{{
      "id": "code",
      "type": "string",
      "maximumLength": 32,
      "classification": "internal"
    }}],
    "indexes": [{{"id": "by-code", "fields": ["code"]}}]
  }}],
  "accessProfiles": [{{
    "id": "reader",
    "principalClaim": "principal",
    "requiredScopes": "unrestricted",
    "permissions": {{"records": [{{
      "rowBoundaries": "unrestricted", "recordType": "case",
      "operations": ["get", "list"],
      "readableFields": ["code"]
    }}]}}
  }}]
}}"#
    );
    project.into_bytes()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_native_pattern_reports_authored_field_and_rolls_back_empty_schema_rehearsal() {
    let database = TestDatabase::create(1).await;
    let config = runtime_config(&database, ENVIRONMENT, INSTANCE);
    let mut project = parse_project_json(&project_bytes(SOURCE_REVISION)).unwrap();
    project.entities[0].fields[0].pattern = Some("[private-expression-canary".to_owned());
    let registry = compile_project(&project, &[], CompileProfile::Production)
        .expect("offline authoring does not emulate PostgreSQL regex syntax");
    let error = rehearse_schema_fingerprint_with_connection_config_for_test(
        &config,
        &registry,
        &database.migration_config,
    )
    .await
    .expect_err("empty-table native syntax is validated by PostgreSQL");
    assert_eq!(
        error,
        StartupError::FieldPatternSyntax {
            entity_id: "case".to_owned(),
            field_id: "code".to_owned()
        }
    );
    assert!(!format!("{error:?}").contains("private-expression-canary"));
    assert!(!format!("{error:?}").contains("registry_data"));
    assert!(managed_schemas_empty_by_restrict(&database).await);
    assert!(registry_state_table(&database).await.is_none());
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn fresh_schema_test_installs_exactly_one_validated_native_pattern_constraint() {
    let database = TestDatabase::create(1).await;
    let config = runtime_config(&database, ENVIRONMENT, INSTANCE);
    let mut project: serde_json::Value =
        serde_json::from_slice(&project_bytes(SOURCE_REVISION)).unwrap();
    project["recordTypes"][0]["fields"][0]["pattern"] = serde_json::json!("^[A-Z]+$");
    let project = serde_json::to_vec(&project).unwrap();
    let registry = compile_project(
        &parse_project_json(&project).unwrap(),
        &[],
        CompileProfile::Production,
    )
    .unwrap();
    let fingerprint = rehearse_schema_fingerprint_with_connection_config_for_test(
        &config,
        &registry,
        &database.migration_config,
    )
    .await
    .unwrap();
    let package = prepared_package_with_source(&fingerprint, project);
    prepare_schema_test_database_with_connection_configs_for_test(
        &config,
        &package,
        &database.migration_config,
        &database.runtime_config,
    )
    .await
    .unwrap();

    let constraints = database
        .admin
        .query(
            "SELECT conname, contype::text, convalidated, pg_catalog.pg_get_constraintdef(oid)
         FROM pg_catalog.pg_constraint
         WHERE connamespace = 'registry_data'::regnamespace AND conname LIKE 'breg_pattern_%'",
            &[],
        )
        .await
        .unwrap();
    assert_eq!(
        constraints.len(),
        1,
        "fresh installation creates exactly the compiled pattern inventory"
    );
    let constraint = &constraints[0];
    assert_eq!(
        constraint.get::<_, String>(0),
        registry.physical_names().entities["case"].constraints["pattern:code"]
    );
    assert_eq!(constraint.get::<_, String>(1), "c");
    assert!(
        constraint.get::<_, bool>(2),
        "the CHECK validates all existing rows"
    );
    let definition: String = constraint.get(3);
    assert!(definition.contains(&registry.entities()["case"].fields["code"].physical_name));
    assert!(definition.contains(" ~ "));
    assert!(definition.contains("^[A-Z]+$"));
    assert_eq!(active_schema_fingerprint(&database).await, fingerprint);
    database.cleanup().await;
}
