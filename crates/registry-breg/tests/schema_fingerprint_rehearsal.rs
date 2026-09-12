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
    PackageSourceFile, PreparedPackage, SignaturePolicy,
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
const FIXTURE_JOURNEYS: &[u8] = br#"apiVersion: registry.registrystack.org/breg-journeys/v1
journeys: []
"#;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rehearsal_rolls_back_and_matches_committed_schema_test_preparation() {
    let registry = compiled_registry(ENVIRONMENT, INSTANCE, SOURCE_REVISION);
    let database = TestDatabase::create(1).await;
    let config = runtime_config(&database, ENVIRONMENT, INSTANCE, SOURCE_REVISION);

    let fingerprint = rehearse_schema_fingerprint_with_connection_config_for_test(
        &config,
        &registry,
        &database.migration_config,
    )
    .await
    .expect("schema fingerprint rehearsal succeeds on an empty disposable database");

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
    database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rehearsal_and_schema_test_prepare_refuse_dirty_text_search_configuration() {
    let registry = compiled_registry(ENVIRONMENT, INSTANCE, SOURCE_REVISION);
    let database = TestDatabase::create(1).await;
    database
        .admin
        .batch_execute(
            "CREATE TEXT SEARCH CONFIGURATION registry_data.dirty_canary
                 ( COPY = pg_catalog.simple )",
        )
        .await
        .expect("test can create a dirty managed text search configuration");
    let config = runtime_config(&database, ENVIRONMENT, INSTANCE, SOURCE_REVISION);

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
    let registry = compiled_registry(ENVIRONMENT, INSTANCE, SOURCE_REVISION);
    let database = TestDatabase::create(1).await;
    let config = runtime_config(&database, ENVIRONMENT, INSTANCE, SOURCE_REVISION);

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
    let registry = compiled_registry(ENVIRONMENT, INSTANCE, SOURCE_REVISION);
    let database = TestDatabase::create(1).await;
    let config = runtime_config(&database, ENVIRONMENT, INSTANCE, SOURCE_REVISION);

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
    let registry = compiled_registry(ENVIRONMENT, INSTANCE, SOURCE_REVISION);
    let config = runtime_config_with_roles(
        "wrong-environment",
        INSTANCE,
        SOURCE_REVISION,
        "registry_migration",
        "registry_runtime",
    );

    assert_eq!(
        rehearse_schema_fingerprint(&config, &registry).await.err(),
        Some(StartupError::PackageRefused(PackageError::Binding)),
        "identity binding is checked before missing database secrets can be resolved"
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

fn runtime_config(
    database: &TestDatabase,
    environment: &str,
    instance_id: &str,
    source_revision: &str,
) -> RuntimeConfig {
    runtime_config_with_roles(
        environment,
        instance_id,
        source_revision,
        database.migration_role.as_str(),
        database.runtime_role.as_str(),
    )
}

fn runtime_config_with_roles(
    environment: &str,
    instance_id: &str,
    source_revision: &str,
    migration_role: &str,
    runtime_role: &str,
) -> RuntimeConfig {
    parse_runtime_config(&format!(
        r#"apiVersion: registry.registrystack.org/breg-runtime/v1alpha1
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
    maxSize: 2
    waitTimeoutMilliseconds: 1000
    createTimeoutMilliseconds: 1000
    recycleTimeoutMilliseconds: 1000
  roles:
    migration: {migration_role}
    runtime: {runtime_role}
package:
  root: /tmp/breg-rehearsal-package
  trustAnchorPath: /tmp/breg-rehearsal-trust-anchor.json
  compilerSourceRevision: {source_revision}
  activeRevision: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
  activeSequence: 1
authentication:
  oidc:
    issuer: https://issuer.example
    audience: urn:breg:rehearsal
    allowedAlgorithm: EdDSA
    accessTokenType: JWT
    scopeClaim: scope
    scopeSeparator: " "
    allowedClients: [registry-client]
    deniedKids: []
    maxTokenLifetimeSeconds: 300
    leewayMilliseconds: 60000
    jwksCache:
      cacheTtlSeconds: 600
      negativeCacheTtlSeconds: 60
      refreshCooldownSeconds: 30
      maxDocumentBytes: 65536
      requestTimeoutMilliseconds: 5000
      outageToleranceSeconds: 900
  authorityClaims:
    principal: registry_principal
    purpose: registry_purpose
audit:
  hashKeyRef: secret:env/BREG_REHEARSAL_AUDIT_KEY
cursor:
  secretRef: secret:env/BREG_REHEARSAL_CURSOR_KEY
  maxAgeSeconds: 300
eventDestinations: {{}}
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
    prepared_package_with_source(
        schema_fingerprint,
        project_bytes(ENVIRONMENT, INSTANCE, SOURCE_REVISION),
    )
}

fn prepared_package_with_source(schema_fingerprint: &str, project: Vec<u8>) -> PreparedPackage {
    prepare_package(PackageBuildRequest {
        environment: ENVIRONMENT.to_owned(),
        instance_id: INSTANCE.to_owned(),
        database_id: DATABASE.to_owned(),
        sequence: 1,
        prior_revision: None,
        compiler_source_revision: SOURCE_REVISION.to_owned(),
        schema_fingerprint: schema_fingerprint.to_owned(),
        signature_policy: SignaturePolicy {
            threshold: 1,
            key_ids: vec!["rehearsal-key".to_owned()],
        },
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

fn compiled_registry(
    environment: &str,
    instance_id: &str,
    source_revision: &str,
) -> CompiledRegistry {
    let project = project_bytes(environment, instance_id, source_revision);
    let parsed = parse_project_json(&project).expect("production project parses");
    compile_project(&parsed, &[], CompileProfile::Production).expect("production project compiles")
}

fn project_bytes(environment: &str, instance_id: &str, source_revision: &str) -> Vec<u8> {
    let project = format!(
        r#"{{
  "apiVersion": "registry.registrystack.org/v1alpha1",
  "kind": "RegistryProject",
  "registry": {{"id": "rehearsal-registry", "version": "1", "defaultLanguage": "en", "canonicalBaseIri": "https://authoring.example.test"}},
  "package": {{
    "environment": "{environment}",
    "instanceId": "{instance_id}",
    "sequence": 1,
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
  "entities": [{{
    "id": "case",
    "primaryDataset": "test-dataset",
    "route": "cases",
    "mutationMode": "create_only",
    "fields": [{{
      "id": "code",
      "type": "string",
      "maxLength": 32,
      "classification": "internal"
    }}]
  }}],
  "accessProfiles": [{{
    "id": "reader",
    "principalClaim": "principal",
    "permissions": [{{
      "rowBoundaries": [], "entity": "case",
      "operations": ["get", "list"],
      "readableFields": ["code"]
    }}]
  }}]
}}"#
    );
    project.into_bytes()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn invalid_native_pattern_reports_authored_field_and_rolls_back_empty_schema_rehearsal() {
    let database = TestDatabase::create(1).await;
    let config = runtime_config(&database, ENVIRONMENT, INSTANCE, SOURCE_REVISION);
    let mut project =
        parse_project_json(&project_bytes(ENVIRONMENT, INSTANCE, SOURCE_REVISION)).unwrap();
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
    let config = runtime_config(&database, ENVIRONMENT, INSTANCE, SOURCE_REVISION);
    let mut project: serde_json::Value =
        serde_json::from_slice(&project_bytes(ENVIRONMENT, INSTANCE, SOURCE_REVISION)).unwrap();
    project["entities"][0]["fields"][0]["pattern"] = serde_json::json!("^[A-Z]+$");
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
