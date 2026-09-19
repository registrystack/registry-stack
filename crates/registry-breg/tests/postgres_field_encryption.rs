// SPDX-License-Identifier: Apache-2.0
//! Field-encryption key state over real PostgreSQL: the local-file data key
//! activates without a key row, a package with encrypted fields but no
//! configured provider refuses startup, and the Transit provider creates and
//! re-derives the wrapped key row through a scripted Unix-socket provider.

#![cfg(all(feature = "postgres-test", feature = "tooling", unix))]

#[path = "support/postgres_harness.rs"]
#[allow(dead_code)]
mod postgres_harness;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use axum::body::Body;
use axum::http::{Method, Request, StatusCode};
use base64::Engine as _;
use postgres_harness::TestDatabase;
use registry_breg::compiler::{compile_project, module_digest, CompileProfile};
use registry_breg::contract::{parse_module_yaml, parse_project_yaml};
use registry_breg::package::{
    load_package, prepare_package, PackageBuildRequest, PackageIntent, PackageLoadContext,
    PackageMigrationPlanInput, PackageModuleSource, PackageSourceFile, SignaturePolicy,
    VerifiedPackage, FIXTURE_JOURNEYS_PATH,
};
use registry_breg::postgres::{
    initialize_compiled_registry_state_for_test, install_compiled_schema,
    managed_schema_fingerprint, ExpectedManagedCatalog, RegistryStateTestIdentity,
};
use registry_breg::startup::{
    prepare_with_connection_config_for_test, PreparedServer, StartupError,
};
use registry_breg::CompiledRegistry;
use registry_platform_testing::{
    fixtures as testing_fixtures, jwks_from_private_jwk, sign_ed25519_compact_jwt,
};
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixListener;
use tokio::task::JoinHandle;
use tower::ServiceExt as _;
use uuid::Uuid;

const COMPILER_SOURCE_REVISION: &str = "field-encryption-source";
const INSTANCE_ID: &str = "field-encryption-instance";
const DATABASE_ID: &str = "field-encryption-database";
const MODULE_ID: &str = "field-encryption-core";
const KEY_TABLE: &str = "registry_internal.registry_field_encryption_keys";
/// The one data key the scripted Transit provider hands out.
const DEK: [u8; 32] = [0x42; 32];
/// Its wrapped form, naming Transit key version 3.
const WRAPPED: &str = "vault:v3:QpQ=";
const METADATA_PATH: &str = "/v1/transit/keys/breg-field-dek";
const DATAKEY_PATH: &str = "/v1/transit/datakey/plaintext/breg-field-dek";
const DECRYPT_PATH: &str = "/v1/transit/decrypt/breg-field-dek";

const MODULE_SOURCE: &str = "id: field-encryption-core\nversion: 1.0.0\n";

const PROJECT_TEMPLATE: &str = r#"apiVersion: registry.registrystack.org/v1alpha1
kind: RegistryProject
registry:
  id: field-encryption-fixture
  canonicalBaseIri: https://field-encryption.invalid
  version: 1.0.0
  defaultLanguage: en
package:
  environment: local
  instanceId: field-encryption-instance
  sequence: 1
  sourceRevision: field-encryption-source
manifestProjection:
  accessProfile: operator
  classificationCeiling: public
  catalog:
    baseUrl: https://field-encryption.invalid
    title: Field Encryption Fixture Registry
    publisher: {id: field-encryption-authority, name: Fixture Publisher}
  publicService: {id: field-encryption-service, title: Field Encryption Fixture Registry}
  datasets:
    - id: fixture-registry
      title: Fixture Dataset
      owner: Fixture Publisher
      status: active
  dataServices:
    - id: fixture-data-service
      title: Field Encryption Fixture Registry
      endpointUrl: https://field-encryption.invalid
      servesDatasets: [fixture-registry]
  distributions: []
modules:
  - id: field-encryption-core
    version: 1.0.0
    digest: MODULE_DIGEST
entities:
  - id: holder
    primaryDataset: fixture-registry
    route: holders
    mutationMode: mutable
    tombstone: true
    classification: restricted
    batch: {maximumItems: 10, maximumBytes: 65536}
    selectorProfiles:
      - {id: by-secret, fields: [secret]}
    fields:
      - {id: jurisdiction, type: string, maxLength: 32, required: true, classification: public}
      - {id: label, type: string, maxLength: 128, required: true, classification: public}
      - {id: secret, type: string, maxLength: 256, required: true, classification: restricted, encrypted: true,
         lookup: {normalization: [trim, uppercase], unique: true}}
      - {id: code, type: string, maxLength: 32, classification: restricted, encrypted: true, pattern: '^[A-Z]{3}-[0-9]{4}$'}
      - {id: big, type: string, maxLength: 1000000, classification: restricted, encrypted: true}
    constraints:
      - {kind: unique, fields: [label]}
  - id: note
    primaryDataset: fixture-registry
    route: notes
    mutationMode: create_only
    classification: restricted
    fields:
      - {id: text, type: string, maxLength: 200, required: true, classification: restricted}
  - id: dossier
    primaryDataset: fixture-registry
    route: dossiers
    mutationMode: mutable
    changeControl: {requiredFor: [patch]}
    classification: restricted
    fields:
      - {id: jurisdiction, type: string, maxLength: 32, required: true, classification: public}
      - {id: label, type: string, maxLength: 128, required: true, classification: public}
      - {id: code, type: string, maxLength: 32, classification: restricted, encrypted: true}
  - id: dossier-request
    primaryDataset: fixture-registry
    route: dossier-requests
    mutationMode: mutable
    classification: restricted
    fields:
      - {id: jurisdiction, type: string, maxLength: 32, required: true, classification: public}
      - {id: reason, type: string, maxLength: 128, required: true, classification: public}
      - {id: dossier, type: reference, target: dossier, required: true, classification: public}
      - {id: code, type: string, maxLength: 32, required: true, classification: public}
      - {id: secret, type: string, maxLength: 32, required: true, classification: restricted, encrypted: true}
    attachments:
      - {id: evidence, required: true, maximumBytes: 1024, contentTypes: [application/octet-stream], classification: restricted}
    changeRequest:
      effects:
        - id: correct-label
          target: {fromField: dossier}
          operation: patch
          set: {label: {fromField: reason}}
      review:
        stages:
          - {id: review, approvals: 1}
      retention: {mode: operator_erase}
accessProfiles:
  - id: operator
    default: true
    principalClaim: registry_principal
    requiredPurposes: [case-management]
    permissions:
      - entity: holder
        operations: [create, get, list, patch, batch, lookup, revisions, snapshot]
        revisionAccess: true
        allowCount: true
        readableFields: [jurisdiction, label, secret, code, big]
        writableFields: [jurisdiction, label, secret, code, big]
        lookups:
          - {selector: by-secret, valueOrigin: request}
        rowBoundaries:
          - {field: jurisdiction, claim: jurisdiction, operator: equals}
      - entity: note
        rowBoundaries: []
        operations: [create, get, list]
        readableFields: [text]
        writableFields: [text]
      - entity: dossier
        operations: [create, get, list]
        readableFields: [jurisdiction, label, code]
        writableFields: [jurisdiction, label, code]
        rowBoundaries:
          - {field: jurisdiction, claim: jurisdiction, operator: equals}
      - entity: dossier-request
        operations: [create, get, list, patch, submit_request, cancel_request, apply_request]
        readableFields: [jurisdiction, reason, dossier, code, secret, evidence]
        writableFields: [jurisdiction, reason, dossier, code, secret, evidence]
        rowBoundaries:
          - {field: jurisdiction, claim: jurisdiction, operator: equals}
        requestVisibility: owner
        applyTargets:
          - entity: dossier
            rowBoundaries:
              - {field: jurisdiction, claim: jurisdiction, operator: equals}
  - id: reviewer
    principalClaim: registry_principal
    requiredPurposes: [case-management]
    permissions:
      - entity: dossier-request
        operations: [get, approve_request, reject_request, request_revision]
        readableFields: [jurisdiction, reason, dossier, secret, evidence]
        writableFields: []
        rowBoundaries:
          - {field: jurisdiction, claim: jurisdiction, operator: equals}
        reviewStages:
          - stage: review
            targets:
              - entity: dossier
                readableFields: [jurisdiction, label, code]
                rowBoundaries:
                  - {field: jurisdiction, claim: jurisdiction, operator: equals}
              - entity: dossier-request
                readableFields: [evidence]
                rowBoundaries: []
"#;

const JOURNEY_SOURCE: &str = r#"journeys:
  - id: holder-list
    steps:
      - id: list-holders
        entity: holder
        accessProfile: operator
        claims: {registry_principal: operator, jurisdiction: area-a}
        request: {operation: list}
        expect: {outcome: success, status: 200, count: 0}
"#;

/// One installed unsigned local package whose registry declares an encrypted
/// field. The temporary directory keeps the published package alive.
struct EncryptedFixture {
    _root: TempDir,
    package_root: PathBuf,
    anchor: PathBuf,
    revision: String,
    package: VerifiedPackage,
}

fn project_source(module_digest_value: &str) -> Vec<u8> {
    PROJECT_TEMPLATE
        .replace("MODULE_DIGEST", module_digest_value)
        .into_bytes()
}

fn encrypted_fixture(schema_fingerprint: &str, project: &[u8]) -> EncryptedFixture {
    let prepared = prepare_package(PackageBuildRequest {
        environment: "local".to_owned(),
        instance_id: INSTANCE_ID.to_owned(),
        database_id: DATABASE_ID.to_owned(),
        sequence: 1,
        prior_revision: None,
        compiler_source_revision: COMPILER_SOURCE_REVISION.to_owned(),
        schema_fingerprint: schema_fingerprint.to_owned(),
        signature_policy: SignaturePolicy {
            threshold: 0,
            key_ids: Vec::new(),
        },
        project: PackageSourceFile {
            path: "sources/project.yaml".to_owned(),
            bytes: project.to_vec(),
        },
        modules: vec![PackageModuleSource {
            id: MODULE_ID.to_owned(),
            path: "sources/modules/field-encryption-core/module.yaml".to_owned(),
            bytes: MODULE_SOURCE.as_bytes().to_vec(),
            assets: Vec::new(),
        }],
        fixture_journeys: PackageSourceFile {
            path: FIXTURE_JOURNEYS_PATH.to_owned(),
            bytes: JOURNEY_SOURCE.as_bytes().to_vec(),
        },
        migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
    })
    .expect("local encrypted package prepares");
    let root = tempfile::tempdir().expect("temporary package root creates");
    let directory = root
        .path()
        .canonicalize()
        .expect("temporary package root canonicalizes");
    let package_root = directory.join("package");
    let revision = prepared.package_revision().to_owned();
    prepared
        .publish_to_directory(&package_root, Vec::new())
        .expect("local encrypted package publishes");
    let anchor = directory.join("trust-anchor.json");
    let package = load_package(
        &package_root,
        &PackageLoadContext {
            environment: "local",
            instance_id: INSTANCE_ID,
            database_id: DATABASE_ID,
            database_initialization_environment: "local",
            compiler_source_revision: COMPILER_SOURCE_REVISION,
            trust_anchor: None,
            intent: PackageIntent::InitialActivation,
        },
    )
    .expect("local encrypted package closure rederives into VerifiedPackage");
    EncryptedFixture {
        _root: root,
        package_root,
        anchor,
        revision,
        package,
    }
}

/// The installed database an encrypted package is activated on: schema
/// installed, fingerprint measured, package built with that fingerprint, and
/// registry state initialized. The compiled registry stays with it so tests
/// can name physical columns for their direct-SQL assertions.
struct BootedDatabase {
    database: TestDatabase,
    fixture: EncryptedFixture,
    directory: PathBuf,
    registry: Arc<CompiledRegistry>,
}

async fn boot_encrypted_database() -> BootedDatabase {
    let database = TestDatabase::create(4).await;
    let (migration, migration_task) = database.connect_migration().await;
    let module = parse_module_yaml(MODULE_SOURCE.as_bytes()).expect("fixture module parses");
    let project_bytes = project_source(&module_digest(&module));
    let project = parse_project_yaml(&project_bytes).expect("fixture project parses");
    let registry = Arc::new(
        compile_project(&project, &[module], CompileProfile::Production)
            .expect("encrypted fixture project compiles in Production"),
    );
    install_compiled_schema(&migration, &registry, &database.runtime_role)
        .await
        .expect("administrator installs the compiler-owned schema");
    let expected_catalog = ExpectedManagedCatalog::compiled(&registry);
    let schema_fingerprint =
        managed_schema_fingerprint(&migration, &database.runtime_role, &expected_catalog)
            .await
            .expect("closed managed schema fingerprint computes");
    let fixture = encrypted_fixture(&schema_fingerprint, &project_bytes);
    let manifest = fixture.package.manifest();
    initialize_compiled_registry_state_for_test(
        &migration,
        &database.runtime_role,
        &registry,
        RegistryStateTestIdentity {
            package_id: &manifest.package_id,
            environment: &manifest.environment,
            instance_id: &manifest.instance_id,
            database_id: &manifest.database_id,
            package_revision: &manifest.package_revision,
            package_sequence: 1,
        },
    )
    .await
    .expect("administrator activates the exact verified package identity");
    drop(migration);
    migration_task.abort();
    let directory = fixture
        .package_root
        .parent()
        .expect("package root has a parent")
        .to_path_buf();
    BootedDatabase {
        database,
        fixture,
        directory,
        registry,
    }
}

/// Write one strict local runtime configuration. `field_encryption` is the
/// already-rendered `fieldEncryption:` YAML block, or `None` to omit it.
fn write_runtime_config(booted: &BootedDatabase, field_encryption: Option<String>) -> PathBuf {
    let secrets = booted.directory.join("secrets");
    fs::create_dir_all(&secrets).expect("fixture secret root creates");
    write_private(&secrets.join("database-url"), b"unused-by-test-startup");
    write_private(&secrets.join("audit-key"), &[0x71; 32]);
    write_private(&secrets.join("cursor-key"), &[0x52; 32]);
    write_private(
        &secrets.join("oidc-jwks"),
        &serde_json::to_vec(&jwks_from_private_jwk(
            &registry_platform_crypto::PrivateJwk::parse(testing_fixtures::ED25519_PRIVATE_JWK)
                .expect("test IdP key parses"),
        ))
        .expect("static JWKS serializes"),
    );
    let field_encryption = field_encryption.unwrap_or_default();
    let path = booted.directory.join("runtime.yaml");
    fs::write(
        &path,
        format!(
            r#"apiVersion: registry.registrystack.org/breg-runtime/v1alpha1
kind: BRegRuntimeConfig
listener:
  bind: 127.0.0.1:9
identity:
  environment: local
  instanceId: {INSTANCE_ID}
  databaseId: {DATABASE_ID}
  databaseInitializationEnvironment: local
secretProviders:
  file:
    root: {}
database:
  runtimeUrlRef: secret:file/database-url
  migrationUrlRef: secret:file/migration-database-url
  pool:
    maxSize: 4
    waitTimeoutMilliseconds: 2000
    createTimeoutMilliseconds: 2000
    recycleTimeoutMilliseconds: 2000
  roles:
    migration: {}
    runtime: {}
package:
  root: {}
  trustAnchorPath: {}
  compilerSourceRevision: {COMPILER_SOURCE_REVISION}
  activeRevision: {}
  activeSequence: 1
authentication:
  oidc:
    issuer: https://auth.example.test
    audience: urn:breg:field-encryption
    allowedAlgorithm: EdDSA
    accessTokenType: JWT
    scopeClaim: scope
    scopeSeparator: " "
    maxTokenLifetimeSeconds: 3600
    leewayMilliseconds: 60000
    jwksSource:
      kind: static
      documentRef: secret:file/oidc-jwks
    jwksCache:
      cacheTtlSeconds: 60
      negativeCacheTtlSeconds: 1
      refreshCooldownSeconds: 1
      maxDocumentBytes: 65536
      requestTimeoutMilliseconds: 5000
      outageToleranceSeconds: 0
  authorityClaims:
    principal: registry_principal
    purpose: purpose
audit:
  hashKeyRef: secret:file/audit-key
cursor:
  secretRef: secret:file/cursor-key
  maxAgeSeconds: 300
operationalTimeouts:
  httpRequestMilliseconds: 5000
  shutdownGraceMilliseconds: 1000
  recordLockMilliseconds: 2000
  migrationLockMilliseconds: 2000
  migrationStatementMilliseconds: 5000
{field_encryption}"#,
            secrets.display(),
            booted.database.migration_role.as_str(),
            booted.database.runtime_role.as_str(),
            booted.fixture.package_root.display(),
            booted.fixture.anchor.display(),
            booted.fixture.revision,
        ),
    )
    .expect("strict fixture runtime configuration writes");
    set_private_permissions(&path);
    path
}

fn write_private(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("private fixture file writes");
    set_private_permissions(path);
}

fn set_private_permissions(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .expect("private fixture permissions set");
}

async fn assert_ready(prepared: &PreparedServer, expected: StatusCode) {
    let response = prepared
        .app()
        .oneshot(
            Request::builder()
                .uri("/ready")
                .body(Body::empty())
                .expect("request builds"),
        )
        .await
        .expect("router responds");
    assert_eq!(response.status(), expected);
}

async fn key_row_count(client: &tokio_postgres::Client) -> i64 {
    client
        .query_one(&format!("SELECT count(*) FROM {KEY_TABLE}"), &[])
        .await
        .expect("key row count reads")
        .get(0)
}

/// The runtime role holds exactly SELECT and INSERT on the key table, and the
/// public pseudo-role holds nothing.
async fn assert_key_table_grants(client: &tokio_postgres::Client, runtime_role: &str) {
    let privileges = ["SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE"];
    for privilege in privileges {
        let expected = matches!(privilege, "SELECT" | "INSERT");
        let granted: bool = client
            .query_one(
                "SELECT has_table_privilege($1, $2, $3)",
                &[&runtime_role, &KEY_TABLE, &privilege],
            )
            .await
            .expect("runtime role privilege reads")
            .get(0);
        assert_eq!(
            granted, expected,
            "runtime role {privilege} on the key table"
        );
        let public_granted: bool = client
            .query_one(
                "SELECT has_table_privilege('public', $1, $2)",
                &[&KEY_TABLE, &privilege],
            )
            .await
            .expect("public privilege reads")
            .get(0);
        assert!(!public_granted, "public holds {privilege} on the key table");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn local_file_data_key_prepares_ready_and_never_writes_a_key_row() {
    let booted = boot_encrypted_database().await;
    let (migration, migration_task) = booted.database.connect_migration().await;
    assert_key_table_grants(&migration, booted.database.runtime_role.as_str()).await;

    let secrets = booted.directory.join("secrets");
    fs::create_dir_all(&secrets).expect("fixture secret root creates");
    write_private(
        &secrets.join("field-dek"),
        format!(
            "{}\n",
            base64::engine::general_purpose::STANDARD.encode(DEK)
        )
        .as_bytes(),
    );
    let config = write_runtime_config(
        &booted,
        Some(
            "fieldEncryption:\n  provider:\n    kind: localFile\n    dekRef: secret:file/field-dek\n"
                .to_owned(),
        ),
    );
    let prepared =
        prepare_with_connection_config_for_test(&config, booted.database.runtime_config.clone())
            .await
            .expect("local file key state prepares the encrypted registry");
    assert_ready(&prepared, StatusCode::OK).await;

    // The local-file provider keeps key version 1 implicit in the file, so
    // first activation leaves the key table empty.
    assert_eq!(key_row_count(&migration).await, 0);
    drop(prepared);
    migration_task.abort();
    booted.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn missing_field_encryption_provider_refuses_startup() {
    let booted = boot_encrypted_database().await;
    let (migration, migration_task) = booted.database.connect_migration().await;

    let config = write_runtime_config(&booted, None);
    assert_eq!(
        prepare_with_connection_config_for_test(&config, booted.database.runtime_config.clone())
            .await
            .err(),
        Some(StartupError::FieldEncryption),
        "an active package with encrypted fields refuses to run without key state"
    );

    // Nothing was activated: the key table stays empty.
    assert_eq!(key_row_count(&migration).await, 0);
    migration_task.abort();
    booted.database.cleanup().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn transit_provider_activates_the_first_key_row_and_restart_unwraps_it() {
    let booted = boot_encrypted_database().await;
    let (migration, migration_task) = booted.database.connect_migration().await;

    // First activation: the provider answers custody validation (metadata,
    // generate, unwrap self-test) and then the activation generate.
    let first = spawn_transit_mock(vec![
        metadata_reply(),
        datakey_reply(),
        decrypt_reply(),
        datakey_reply(),
    ]);
    let config = write_runtime_config(
        &booted,
        Some(format!(
            "fieldEncryption:\n  provider:\n    kind: transit\n    unixSocketPath: {}\n    mount: transit\n    keyName: breg-field-dek\n    timeoutMilliseconds: 2000\n",
            first.socket_path.display()
        )),
    );
    let prepared =
        prepare_with_connection_config_for_test(&config, booted.database.runtime_config.clone())
            .await
            .expect("Transit key state activates the encrypted registry");
    assert_ready(&prepared, StatusCode::OK).await;
    drop(prepared);

    let row = migration
        .query_one(
            &format!(
                "SELECT key_version, provider_kind, algorithm, wrapped_dek, transit_key_version,
                        activated_package_revision
                 FROM {KEY_TABLE}"
            ),
            &[],
        )
        .await
        .expect("activated key row reads");
    assert_eq!(row.get::<_, i32>(0), 1, "first activation is key version 1");
    assert_eq!(row.get::<_, String>(1), "transit_datakey");
    assert_eq!(row.get::<_, String>(2), "aes-256-gcm");
    assert_eq!(row.get::<_, String>(3), WRAPPED);
    assert_eq!(
        row.get::<_, i32>(4),
        3,
        "the wrapped form names Transit key version 3"
    );
    assert_eq!(
        row.get::<_, String>(5),
        booted.fixture.revision,
        "the row records the activating package revision"
    );

    // Restart against the same database: custody validation again, then the
    // stored row is unwrapped instead of a second row being written.
    let second = spawn_transit_mock(vec![
        metadata_reply(),
        datakey_reply(),
        decrypt_reply(),
        decrypt_reply(),
    ]);
    let restart_config = write_runtime_config(
        &booted,
        Some(format!(
            "fieldEncryption:\n  provider:\n    kind: transit\n    unixSocketPath: {}\n    mount: transit\n    keyName: breg-field-dek\n    timeoutMilliseconds: 2000\n",
            second.socket_path.display()
        )),
    );
    let restarted = prepare_with_connection_config_for_test(
        &restart_config,
        booted.database.runtime_config.clone(),
    )
    .await
    .expect("stored Transit key row re-derives the key state");
    assert_ready(&restarted, StatusCode::OK).await;
    drop(restarted);
    assert_eq!(
        key_row_count(&migration).await,
        1,
        "restart unwraps the stored row instead of inserting another"
    );

    // An unreachable provider is a fail-closed refusal, not a degraded start.
    let unreachable = write_runtime_config(
        &booted,
        Some(
            "fieldEncryption:\n  provider:\n    kind: transit\n    unixSocketPath: /nonexistent/transit-proxy.sock\n    mount: transit\n    keyName: breg-field-dek\n"
                .to_owned(),
        ),
    );
    assert_eq!(
        prepare_with_connection_config_for_test(
            &unreachable,
            booted.database.runtime_config.clone()
        )
        .await
        .err(),
        Some(StartupError::FieldEncryption),
        "a provider that does not answer refuses startup"
    );

    drop(first.directory);
    drop(second.directory);
    migration_task.abort();
    booted.database.cleanup().await;
}

/// One scripted reply for the mock Transit provider.
struct TransitReply {
    method: &'static str,
    path: &'static str,
    body: Option<Value>,
    response: Value,
}

struct MockTransit {
    directory: TempDir,
    socket_path: PathBuf,
    _server: JoinHandle<()>,
}

/// Serve one Unix-socket Transit provider that answers each reply to exactly
/// one request, in order, asserting the method, path, JSON body, and the
/// trusted-proxy header the client must send.
fn spawn_transit_mock(replies: Vec<TransitReply>) -> MockTransit {
    let directory = tempfile::tempdir().expect("temporary Transit directory");
    let socket_path = directory.path().join("transit.sock");
    let listener = UnixListener::bind(&socket_path).expect("mock Transit socket binds");
    let server = tokio::spawn(async move {
        for reply in replies {
            let (mut stream, _) = listener.accept().await.expect("mock Transit accept");
            let mut request = Vec::new();
            let header_end = loop {
                let mut chunk = [0_u8; 4096];
                let read = stream.read(&mut chunk).await.expect("request reads");
                assert_ne!(read, 0, "request ended before its headers");
                request.extend_from_slice(&chunk[..read]);
                if let Some(position) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                    break position + 4;
                }
            };
            let headers = String::from_utf8_lossy(&request[..header_end]).into_owned();
            let mut lines = headers.lines();
            let request_line = lines.next().expect("request line");
            let mut parts = request_line.split_whitespace();
            assert_eq!(parts.next(), Some(reply.method));
            assert_eq!(parts.next(), Some(reply.path));
            assert!(
                headers
                    .to_ascii_lowercase()
                    .contains("x-vault-request: true"),
                "Transit request marks the trusted proxy hop"
            );
            let content_length = lines
                .filter_map(|line| line.split_once(':'))
                .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .map(|(_, value)| value.trim().parse::<usize>().expect("content length"))
                .unwrap_or(0);
            while request.len() < header_end + content_length {
                let mut chunk = [0_u8; 4096];
                let read = stream.read(&mut chunk).await.expect("request body reads");
                assert_ne!(read, 0, "request body ended early");
                request.extend_from_slice(&chunk[..read]);
            }
            match reply.body {
                Some(expected) => {
                    let actual: Value =
                        serde_json::from_slice(&request[header_end..header_end + content_length])
                            .expect("request JSON parses");
                    assert_eq!(actual, expected);
                }
                None => assert!(content_length == 0, "no body was expected"),
            }
            let body = serde_json::to_vec(&reply.response).expect("mock response serializes");
            let head = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(head.as_bytes()).await;
            let _ = stream.write_all(&body).await;
        }
    });
    MockTransit {
        directory,
        socket_path,
        _server: server,
    }
}

fn metadata_reply() -> TransitReply {
    TransitReply {
        method: "GET",
        path: METADATA_PATH,
        body: None,
        response: json!({
            "data": {
                "type": "aes256-gcm",
                "supports_encryption": true,
                "exportable": false,
                "derived": false,
                "allow_plaintext_backup": false,
                "latest_version": 3,
                "min_decryption_version": 1,
                "min_encryption_version": 1,
            }
        }),
    }
}

fn datakey_reply() -> TransitReply {
    TransitReply {
        method: "POST",
        path: DATAKEY_PATH,
        body: Some(json!({ "bits": 256 })),
        response: json!({
            "data": {
                "plaintext": base64::engine::general_purpose::STANDARD.encode(DEK),
                "ciphertext": WRAPPED,
            }
        }),
    }
}

fn decrypt_reply() -> TransitReply {
    TransitReply {
        method: "POST",
        path: DECRYPT_PATH,
        body: Some(json!({ "ciphertext": WRAPPED })),
        response: json!({ "data": { "plaintext": base64::engine::general_purpose::STANDARD.encode(DEK) } }),
    }
}

// ---------------------------------------------------------------------------
// Write and current-read path over live key state
// ---------------------------------------------------------------------------

const LOCAL_FILE_FIELD_ENCRYPTION: &str =
    "fieldEncryption:\n  provider:\n    kind: localFile\n    dekRef: secret:file/field-dek\n";
const AUTHORITY_KID: &str = "registry-platform-testing-ed25519-1";

/// A prepared runtime over the encrypted fixture with local-file key state.
/// The booted database stays alive with it: the package directory and the
/// administrator connection the ciphertext-at-rest assertions need both live
/// on it.
struct LiveServer {
    prepared: PreparedServer,
    booted: BootedDatabase,
}

impl LiveServer {
    fn registry(&self) -> &CompiledRegistry {
        &self.booted.registry
    }

    async fn shutdown(self) {
        let LiveServer { prepared, booted } = self;
        drop(prepared);
        booted.database.cleanup().await;
    }
}

async fn boot_live_server() -> LiveServer {
    let booted = boot_encrypted_database().await;
    let secrets = booted.directory.join("secrets");
    fs::create_dir_all(&secrets).expect("fixture secret root creates");
    write_private(
        &secrets.join("field-dek"),
        format!(
            "{}\n",
            base64::engine::general_purpose::STANDARD.encode(DEK)
        )
        .as_bytes(),
    );
    let config = write_runtime_config(&booted, Some(LOCAL_FILE_FIELD_ENCRYPTION.to_owned()));
    let prepared =
        prepare_with_connection_config_for_test(&config, booted.database.runtime_config.clone())
            .await
            .expect("local file key state prepares the encrypted registry");
    assert_ready(&prepared, StatusCode::OK).await;
    LiveServer { prepared, booted }
}

/// One access token for the full authenticated router: issuer, audience, and
/// authority claims match the fixture runtime configuration.
fn token_for(principal: &str, jurisdiction: &str) -> String {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock follows epoch")
        .as_secs();
    sign_ed25519_compact_jwt(
        testing_fixtures::ED25519_PRIVATE_JWK,
        "JWT",
        AUTHORITY_KID,
        json!({
            "iss": "https://auth.example.test",
            "aud": "urn:breg:field-encryption",
            "iat": now,
            "nbf": now,
            "exp": now + 600,
            "registry_actor_kind": "service",
            "registry_principal": principal,
            "jurisdiction": jurisdiction,
            "purpose": "case-management",
        }),
    )
}

/// The default operator principal, inside the area-a row boundary.
fn operator_token() -> String {
    token_for("operator", "area-a")
}

async fn send(
    server: &LiveServer,
    method: Method,
    uri: &str,
    headers: &[(&'static str, String)],
    body: Option<Value>,
) -> axum::response::Response {
    send_as(server, method, uri, headers, body, &operator_token()).await
}

async fn send_as(
    server: &LiveServer,
    method: Method,
    uri: &str,
    headers: &[(&'static str, String)],
    body: Option<Value>,
    token: &str,
) -> axum::response::Response {
    let body = body.map(|value| serde_json::to_vec(&value).expect("request serializes"));
    send_bytes_as(server, method, uri, headers, body, token).await
}

async fn send_bytes_as(
    server: &LiveServer,
    method: Method,
    uri: &str,
    headers: &[(&'static str, String)],
    body: Option<Vec<u8>>,
    token: &str,
) -> axum::response::Response {
    let mut builder = Request::builder()
        .method(method)
        .uri(uri)
        .header("authorization", format!("Bearer {token}"));
    for (name, value) in headers {
        builder = builder.header(*name, value.as_str());
    }
    let request = match body {
        Some(bytes) => builder.body(Body::from(bytes)),
        None => builder.body(Body::empty()),
    }
    .expect("request builds");
    server
        .prepared
        .app()
        .oneshot(request)
        .await
        .expect("router returns a response")
}

async fn body_json(response: axum::response::Response) -> Value {
    serde_json::from_slice(&body_bytes(response).await).expect("response body is JSON")
}

async fn body_bytes(response: axum::response::Response) -> Vec<u8> {
    axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .expect("response body is bounded")
        .to_vec()
}

fn response_etag(response: &axum::response::Response) -> String {
    response
        .headers()
        .get("etag")
        .expect("response carries an ETag")
        .to_str()
        .expect("ETag is text")
        .to_owned()
}

/// Create one holder and return its status, body, and ETag. `key` is the
/// per-call idempotency key, so replays stay distinguishable.
#[allow(clippy::type_complexity)]
async fn create_holder(
    server: &LiveServer,
    key: &str,
    data: Value,
) -> (StatusCode, Value, Option<String>) {
    let response = send(
        server,
        Method::POST,
        "/v1/records/holders",
        &[
            ("content-type", "application/json".to_owned()),
            ("idempotency-key", key.to_owned()),
        ],
        Some(json!({ "data": data })),
    )
    .await;
    let etag = response
        .headers()
        .get("etag")
        .and_then(|value| value.to_str().ok())
        .map(str::to_owned);
    let status = response.status();
    (status, body_json(response).await, etag)
}

/// The physical envelope column of one encrypted holder field.
fn envelope_column(registry: &CompiledRegistry, field_id: &str) -> String {
    registry
        .entities()
        .get("holder")
        .expect("holder entity compiles")
        .fields
        .get(field_id)
        .unwrap_or_else(|| panic!("holder field {field_id} compiles"))
        .physical_name
        .clone()
}

/// The physical blind-index column of one encrypted holder field.
fn blind_column(registry: &CompiledRegistry, field_id: &str) -> String {
    registry
        .entities()
        .get("holder")
        .expect("holder entity compiles")
        .fields
        .get(field_id)
        .unwrap_or_else(|| panic!("holder field {field_id} compiles"))
        .encryption
        .as_ref()
        .and_then(|encryption| encryption.blind_index.as_ref())
        .unwrap_or_else(|| panic!("holder field {field_id} declares a blind index"))
        .physical_name
        .clone()
}

fn holder_table(registry: &CompiledRegistry) -> String {
    registry
        .entities()
        .get("holder")
        .expect("holder entity compiles")
        .physical_table
        .clone()
}

/// Count the holder rows currently at rest.
async fn holder_row_count(server: &LiveServer) -> i64 {
    server
        .booted
        .database
        .admin
        .query_one(
            &format!(
                "SELECT count(*) FROM registry_data.{}",
                holder_table(server.registry())
            ),
            &[],
        )
        .await
        .expect("holder row count reads")
        .get(0)
}

/// The stored bytes of one encrypted column of one record.
async fn stored_column(server: &LiveServer, column: &str, record_id: &str) -> Vec<u8> {
    server
        .booted
        .database
        .admin
        .query_one(
            &format!(
                "SELECT {} FROM registry_data.{} WHERE record_id = $1",
                column,
                holder_table(server.registry())
            ),
            &[&Uuid::parse_str(record_id).expect("record id is a UUID")],
        )
        .await
        .unwrap_or_else(|error| panic!("stored column {column} reads: {error}"))
        .get(0)
}

/// The stored snapshot bytes of one revision journal row.
async fn revision_snapshot(
    server: &LiveServer,
    entity_id: &str,
    record_id: &str,
    revision: i64,
) -> Vec<u8> {
    server
        .booted
        .database
        .admin
        .query_one(
            "SELECT snapshot FROM registry_internal.registry_revisions
             WHERE entity_id = $1 AND record_id = $2 AND record_revision = $3",
            &[
                &entity_id,
                &Uuid::parse_str(record_id).expect("record id is a UUID"),
                &revision,
            ],
        )
        .await
        .unwrap_or_else(|error| panic!("revision {revision} snapshot reads: {error}"))
        .get(0)
}

/// Corrupt one base64 character of the first tagged envelope member in a
/// stored snapshot without touching any other byte, so the tamper targets the
/// envelope alone.
fn tamper_encrypted_member(snapshot: &[u8]) -> Vec<u8> {
    let text = String::from_utf8(snapshot.to_vec()).expect("snapshot is UTF-8");
    let tag = "\"__bregEncryptedV1\":\"";
    let start = text.find(tag).expect("snapshot carries a tagged member");
    let payload_start = start + tag.len();
    let payload_end = text[payload_start..].find('"').expect("member value ends") + payload_start;
    assert!(payload_end > payload_start, "member carries base64 bytes");
    let mut tampered = text.into_bytes();
    let flipped = if tampered[payload_start] == b'A' {
        b'B'
    } else {
        b'A'
    };
    tampered[payload_start] = flipped;
    tampered
}

/// One action link of a request record, by operation name.
fn find_action<'a>(record: &'a Value, operation: &str) -> &'a Value {
    record["data"]["request"]["actions"]
        .as_array()
        .unwrap_or_else(|| panic!("request exposes actions: {record}"))
        .iter()
        .find(|action| action["operation"] == operation)
        .unwrap_or_else(|| panic!("request exposes the {operation} action: {record}"))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn encrypted_fields_round_trip_and_store_only_envelopes() {
    let server = boot_live_server().await;

    // The mutation response decrypts at the response edge.
    let (status, created, etag) = create_holder(
        &server,
        "round-trip-create",
        json!({
            "jurisdiction": "area-a",
            "label": "round-trip",
            "secret": "gamma-seven",
            "code": "ABC-1234",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(created["data"]["domainData"]["secret"], "gamma-seven");
    assert_eq!(created["data"]["domainData"]["code"], "ABC-1234");
    assert!(etag.is_some(), "the create response carries an ETag");
    let record_id = created["data"]["recordIdentifier"]
        .as_str()
        .expect("record identifier is present")
        .to_owned();

    // Current reads decrypt at the response edge too.
    let fetched = send(
        &server,
        Method::GET,
        &format!("/v1/records/holders/{record_id}"),
        &[],
        None,
    )
    .await;
    assert_eq!(fetched.status(), StatusCode::OK);
    let fetched = body_json(fetched).await;
    assert_eq!(fetched["data"]["domainData"]["secret"], "gamma-seven");
    assert_eq!(fetched["data"]["domainData"]["code"], "ABC-1234");
    assert_eq!(fetched["data"]["domainData"]["big"], Value::Null);

    let listed = send(
        &server,
        Method::GET,
        "/v1/records/holders?$select=jurisdiction,label,secret,code,big",
        &[],
        None,
    )
    .await;
    assert_eq!(listed.status(), StatusCode::OK);
    let listed = body_json(listed).await;
    let items = listed["items"].as_array().expect("list items");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["domainData"]["secret"], "gamma-seven");

    // At rest, only envelope and blind-index bytes exist.
    let secret_envelope = stored_column(
        &server,
        &envelope_column(server.registry(), "secret"),
        &record_id,
    )
    .await;
    assert!(
        !secret_envelope
            .windows(b"gamma-seven".len())
            .any(|window| window == b"gamma-seven"),
        "the secret envelope does not contain its plaintext"
    );
    assert!(
        secret_envelope.len() > 32,
        "the envelope carries nonce, ciphertext, and tag"
    );
    let blind = stored_column(
        &server,
        &blind_column(server.registry(), "secret"),
        &record_id,
    )
    .await;
    assert_eq!(blind.len(), 32, "the blind index is one HMAC-SHA256 digest");
    let code_envelope = stored_column(
        &server,
        &envelope_column(server.registry(), "code"),
        &record_id,
    )
    .await;
    assert!(
        !code_envelope
            .windows(b"ABC-1234".len())
            .any(|window| window == b"ABC-1234"),
        "the code envelope does not contain its plaintext"
    );

    // The registry_source view exposes neither the envelopes nor the indexes.
    let registry = server.registry();
    let holder = registry.entities().get("holder").expect("holder compiles");
    let view_name = holder.source_relation.sql_name.clone();
    let encrypted_columns = vec![
        envelope_column(registry, "secret"),
        envelope_column(registry, "code"),
        envelope_column(registry, "big"),
        blind_column(registry, "secret"),
    ];
    let exposed: i64 = server
        .booted
        .database
        .admin
        .query_one(
            "SELECT count(*) FROM information_schema.columns
             WHERE table_schema = 'registry_source' AND table_name = $1
               AND column_name = ANY($2)",
            &[&view_name, &encrypted_columns],
        )
        .await
        .expect("source view columns read")
        .get(0);
    assert_eq!(exposed, 0, "the source view excludes encrypted columns");

    // The revision snapshot keeps the tagged member, so journal comparison
    // canonicalizes byte-identically without decryption.
    let snapshot: Vec<u8> = server
        .booted
        .database
        .admin
        .query_one(
            "SELECT snapshot FROM registry_internal.registry_revisions
             WHERE entity_id = 'holder' AND record_id = $1 AND record_revision = 1",
            &[&Uuid::parse_str(&record_id).expect("record id is a UUID")],
        )
        .await
        .expect("revision 1 snapshot exists")
        .get(0);
    let snapshot = String::from_utf8(snapshot).expect("snapshot is UTF-8");
    assert!(
        snapshot.contains("__bregEncryptedV1"),
        "the snapshot carries the tagged member: {snapshot}"
    );
    assert!(!snapshot.contains("gamma-seven"));
    assert!(!snapshot.contains("ABC-1234"));

    // The idempotency cache stores the sealed body the replay path serves
    // from: no plaintext member ever lands in registry_idempotency.
    let cached = cached_response_body(&server, "record").await;
    assert!(
        cached.contains("__bregEncryptedV1"),
        "the cached create response keeps the tagged member: {cached}"
    );
    assert!(!cached.contains("gamma-seven"));
    assert!(!cached.contains("ABC-1234"));

    server.shutdown().await;
}

/// The single stored idempotency body of one result kind, as UTF-8 text.
async fn cached_response_body(server: &LiveServer, result_kind: &str) -> String {
    let rows = server
        .booted
        .database
        .admin
        .query(
            "SELECT convert_from(response_body, 'UTF8')
               FROM registry_internal.registry_idempotency
              WHERE result_kind = $1",
            &[&result_kind],
        )
        .await
        .expect("cached responses read");
    assert_eq!(
        rows.len(),
        1,
        "exactly one {result_kind} response is cached"
    );
    rows.first().expect("row exists").get(0)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn sealed_idempotency_bodies_serve_plaintext_and_replay_exactly() {
    let server = boot_live_server().await;

    // Direct mutation: the served create opens the sealed members while the
    // cached row keeps them tagged.
    let (status, created, etag) = create_holder(
        &server,
        "sealed-idempotency-create",
        json!({
            "jurisdiction": "area-a",
            "label": "sealed-create",
            "secret": "omega-three",
            "code": "QRS-7777",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(created["data"]["domainData"]["secret"], "omega-three");
    assert_eq!(created["data"]["domainData"]["code"], "QRS-7777");
    let record_id = created["data"]["recordIdentifier"]
        .as_str()
        .expect("record identifier is present")
        .to_owned();
    let cached_create = cached_response_body(&server, "record").await;
    assert!(
        cached_create.contains("__bregEncryptedV1"),
        "the cached create keeps the tagged member: {cached_create}"
    );
    assert!(!cached_create.contains("omega-three"));
    assert!(!cached_create.contains("QRS-7777"));

    // The replay serves the identical opened plaintext from that sealed row.
    let replayed = send(
        &server,
        Method::POST,
        "/v1/records/holders",
        &[
            ("content-type", "application/json".to_owned()),
            ("idempotency-key", "sealed-idempotency-create".to_owned()),
        ],
        Some(json!({ "data": {
            "jurisdiction": "area-a",
            "label": "sealed-create",
            "secret": "omega-three",
            "code": "QRS-7777",
        }})),
    )
    .await;
    assert_eq!(replayed.status(), StatusCode::CREATED);
    assert_eq!(body_json(replayed).await, created);
    assert_eq!(
        cached_response_body(&server, "record").await,
        cached_create,
        "the replay does not rewrite the cached sealed body"
    );

    // Batch import: the same contract over the batch body, whose snapshot and
    // per-item id and revision sit beside the sealed data members.
    let batch_body = json!({
        "changeContext": {
            "kind": "correction",
            "reasonCode": "holder-corrected",
            "sourceReferences": ["holder:sealed"]
        },
        "items": [
            {"operation": "create", "data": {
                "jurisdiction": "area-a",
                "label": "sealed-batch-created",
                "secret": "sigma-five",
                "code": "TUV-8888"
            }},
            {"operation": "patch", "recordId": record_id,
             "ifMatch": etag.expect("the create carries an ETag"),
             "patch": [{"op": "replace", "path": "/data/secret", "value": "omega-four"}]}
        ]
    });
    let batch = send(
        &server,
        Method::POST,
        "/v1/records/holders:batch",
        &[
            ("content-type", "application/json".to_owned()),
            ("idempotency-key", "sealed-idempotency-batch".to_owned()),
        ],
        Some(batch_body.clone()),
    )
    .await;
    assert_eq!(batch.status(), StatusCode::OK);
    let batch_served = body_bytes(batch).await;
    let batch_json: Value = serde_json::from_slice(&batch_served).expect("batch response is JSON");
    assert!(batch_json["snapshot"]
        .as_str()
        .is_some_and(|snapshot| !snapshot.is_empty()));
    assert_eq!(batch_json["results"][0]["operation"], "create");
    assert_eq!(batch_json["results"][0]["data"]["secret"], "sigma-five");
    assert_eq!(batch_json["results"][0]["data"]["code"], "TUV-8888");
    assert_eq!(batch_json["results"][1]["operation"], "patch");
    assert_eq!(batch_json["results"][1]["id"], json!(record_id));
    assert_eq!(batch_json["results"][1]["data"]["secret"], "omega-four");
    let cached_batch = cached_response_body(&server, "batch").await;
    assert!(
        cached_batch.contains("__bregEncryptedV1"),
        "the cached batch keeps the tagged members: {cached_batch}"
    );
    assert!(!cached_batch.contains("sigma-five"));
    assert!(!cached_batch.contains("TUV-8888"));
    assert!(!cached_batch.contains("omega-four"));

    // The batch replay serves byte-identical opened plaintext.
    let batch_replay = send(
        &server,
        Method::POST,
        "/v1/records/holders:batch",
        &[
            ("content-type", "application/json".to_owned()),
            ("idempotency-key", "sealed-idempotency-batch".to_owned()),
        ],
        Some(batch_body),
    )
    .await;
    assert_eq!(batch_replay.status(), StatusCode::OK);
    assert_eq!(body_bytes(batch_replay).await, batch_served);

    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blind_index_lookup_resolves_normalized_equality() {
    let server = boot_live_server().await;
    let (status, created, _) = create_holder(
        &server,
        "lookup-create",
        json!({
            "jurisdiction": "area-a",
            "label": "lookup-target",
            "secret": "gamma-seven",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let record_id = created["data"]["recordIdentifier"]
        .as_str()
        .expect("record identifier is present")
        .to_owned();

    let lookup = send(
        &server,
        Method::POST,
        "/v1/records/holders:lookup?$select=jurisdiction,label,secret",
        &[
            ("content-type", "application/json".to_owned()),
            ("idempotency-key", "lookup-hit".to_owned()),
        ],
        Some(json!({"selector": "by-secret", "values": {"secret": "  GAMMA-SEVEN "}})),
    )
    .await;
    assert_eq!(lookup.status(), StatusCode::OK);
    let lookup = body_json(lookup).await;
    assert_eq!(lookup["data"]["recordIdentifier"], record_id);
    assert_eq!(lookup["data"]["domainData"]["secret"], "gamma-seven");

    // A value nothing normalizes to leaves the lookup unresolved and the
    // response value-free.
    let unresolved = send(
        &server,
        Method::POST,
        "/v1/records/holders:lookup?$select=jurisdiction,label,secret",
        &[
            ("content-type", "application/json".to_owned()),
            ("idempotency-key", "lookup-miss".to_owned()),
        ],
        Some(json!({"selector": "by-secret", "values": {"secret": "unknown-value"}})),
    )
    .await;
    assert_eq!(unresolved.status(), StatusCode::NOT_FOUND);
    let unresolved = body_json(unresolved).await;
    assert_eq!(unresolved["code"], "lookup.unresolved");
    assert!(!unresolved.to_string().contains("unknown-value"));

    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn blind_index_unique_violation_maps_to_conflict() {
    let server = boot_live_server().await;
    let (status, _, _) = create_holder(
        &server,
        "unique-first",
        json!({
            "jurisdiction": "area-a",
            "label": "unique-first",
            "secret": "alpha-one",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);

    // The trim-and-uppercase normalization makes "ALPHA-ONE" collide on the
    // unique blind index, and the violation surfaces as an ordinary conflict.
    let (status, body, _) = create_holder(
        &server,
        "unique-second",
        json!({
            "jurisdiction": "area-a",
            "label": "unique-second",
            "secret": "ALPHA-ONE",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "mutation.conflict");
    assert!(!body.to_string().contains("ALPHA-ONE"));
    assert_eq!(holder_row_count(&server).await, 1);

    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn encrypted_pattern_is_enforced_in_rust_before_sealing() {
    let server = boot_live_server().await;
    let (status, body, _) = create_holder(
        &server,
        "pattern-violation",
        json!({
            "jurisdiction": "area-a",
            "label": "pattern-violation",
            "secret": "gamma-seven",
            "code": "nope",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(body["code"], "mutation.conflict");
    assert_eq!(body["entityId"], "holder");
    assert_eq!(body["fieldId"], "code");
    assert_eq!(holder_row_count(&server).await, 0, "no row was written");

    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn oversized_encrypted_plaintext_is_refused() {
    let server = boot_live_server().await;
    let (status, body, _) = create_holder(
        &server,
        "oversize",
        json!({
            "jurisdiction": "area-a",
            "label": "oversize",
            "secret": "gamma-seven",
            "big": "x".repeat(70_000),
        }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body["code"], "request.invalid");
    assert_eq!(holder_row_count(&server).await, 0, "no row was written");

    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tampered_envelope_fails_closed_and_sibling_entity_serves() {
    let server = boot_live_server().await;

    // A sibling entity without encrypted fields keeps serving.
    let note = send(
        &server,
        Method::POST,
        "/v1/records/notes",
        &[
            ("content-type", "application/json".to_owned()),
            ("idempotency-key", "tamper-note".to_owned()),
        ],
        Some(json!({"data": {"text": "plain note"}})),
    )
    .await;
    assert_eq!(note.status(), StatusCode::CREATED);

    let (status, created, _) = create_holder(
        &server,
        "tamper-create",
        json!({
            "jurisdiction": "area-a",
            "label": "tamper-target",
            "secret": "gamma-seven",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let record_id = created["data"]["recordIdentifier"]
        .as_str()
        .expect("record identifier is present")
        .to_owned();

    // Corrupt one tag byte of the stored envelope directly in the database.
    let envelope = envelope_column(server.registry(), "secret");
    server
        .booted
        .database
        .admin
        .execute(
            &format!(
                "UPDATE registry_data.{table}
                 SET {envelope} = set_byte(
                     {envelope},
                     octet_length({envelope}) - 1,
                     get_byte({envelope}, octet_length({envelope}) - 1) # 1)
                 WHERE record_id = $1",
                table = holder_table(server.registry()),
            ),
            &[&Uuid::parse_str(&record_id).expect("record id is a UUID")],
        )
        .await
        .expect("tampered envelope writes");

    let fetched = send(
        &server,
        Method::GET,
        &format!("/v1/records/holders/{record_id}"),
        &[],
        None,
    )
    .await;
    assert_eq!(fetched.status(), StatusCode::SERVICE_UNAVAILABLE);
    let fetched = body_json(fetched).await;
    assert_eq!(fetched["code"], "runtime.field_encryption.unavailable");
    assert!(
        !fetched.to_string().contains("gamma"),
        "the refusal stays value-free"
    );

    let listed = send(
        &server,
        Method::GET,
        "/v1/records/holders?$select=jurisdiction,label,secret",
        &[],
        None,
    )
    .await;
    assert_eq!(
        listed.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "a listing that would surface the tampered row fails closed too"
    );

    let notes = send(
        &server,
        Method::GET,
        "/v1/records/notes?$select=text",
        &[],
        None,
    )
    .await;
    assert_eq!(notes.status(), StatusCode::OK);
    let notes = body_json(notes).await;
    let items = notes["items"].as_array().expect("note items");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["domainData"]["text"], "plain note");

    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn aad_binds_the_record_row() {
    let server = boot_live_server().await;
    let (_, first, _) = create_holder(
        &server,
        "aad-first",
        json!({
            "jurisdiction": "area-a",
            "label": "aad-first",
            "secret": "alpha-secret",
        }),
    )
    .await;
    let (_, second, _) = create_holder(
        &server,
        "aad-second",
        json!({
            "jurisdiction": "area-a",
            "label": "aad-second",
            "secret": "beta-secret",
        }),
    )
    .await;
    let first_id = first["data"]["recordIdentifier"]
        .as_str()
        .expect("first record identifier is present")
        .to_owned();
    let second_id = second["data"]["recordIdentifier"]
        .as_str()
        .expect("second record identifier is present")
        .to_owned();

    // Move the first record's envelope onto the second row. The envelope's
    // AAD names the first record, so it must not open there. The blind index
    // stays per-row: its unique index would refuse the copy anyway.
    let envelope = envelope_column(server.registry(), "secret");
    server
        .booted
        .database
        .admin
        .execute(
            &format!(
                "UPDATE registry_data.{table} AS target
                 SET {envelope} = source.{envelope}
                 FROM registry_data.{table} AS source
                 WHERE source.record_id = $1 AND target.record_id = $2",
                table = holder_table(server.registry()),
            ),
            &[
                &Uuid::parse_str(&first_id).expect("first record id is a UUID"),
                &Uuid::parse_str(&second_id).expect("second record id is a UUID"),
            ],
        )
        .await
        .expect("row-move tamper writes");

    let moved = send(
        &server,
        Method::GET,
        &format!("/v1/records/holders/{second_id}"),
        &[],
        None,
    )
    .await;
    assert_eq!(moved.status(), StatusCode::SERVICE_UNAVAILABLE);
    let moved = body_json(moved).await;
    assert_eq!(moved["code"], "runtime.field_encryption.unavailable");
    assert!(
        !moved.to_string().contains("secret"),
        "the refusal stays value-free"
    );

    let original = send(
        &server,
        Method::GET,
        &format!("/v1/records/holders/{first_id}"),
        &[],
        None,
    )
    .await;
    assert_eq!(original.status(), StatusCode::OK);
    let original = body_json(original).await;
    assert_eq!(original["data"]["domainData"]["secret"], "alpha-secret");

    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn patch_replaces_the_envelope_and_test_op_is_refused() {
    let server = boot_live_server().await;
    let (status, created, create_etag) = create_holder(
        &server,
        "patch-create",
        json!({
            "jurisdiction": "area-a",
            "label": "patch-target",
            "secret": "gamma-seven",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let record_id = created["data"]["recordIdentifier"]
        .as_str()
        .expect("record identifier is present")
        .to_owned();
    let before = stored_column(
        &server,
        &envelope_column(server.registry(), "secret"),
        &record_id,
    )
    .await;

    let patched = send(
        &server,
        Method::PATCH,
        &format!("/v1/records/holders/{record_id}"),
        &[
            ("content-type", "application/json-patch+json".to_owned()),
            ("idempotency-key", "patch-replace".to_owned()),
            ("if-match", create_etag.expect("create carries an ETag")),
        ],
        Some(json!([
            {"op": "replace", "path": "/data/secret", "value": "delta-two"},
        ])),
    )
    .await;
    assert_eq!(patched.status(), StatusCode::OK);
    let patched_etag = response_etag(&patched);
    let patched = body_json(patched).await;
    assert_eq!(patched["data"]["domainData"]["secret"], "delta-two");

    // The stored envelope was resealed, not edited in place.
    let after = stored_column(
        &server,
        &envelope_column(server.registry(), "secret"),
        &record_id,
    )
    .await;
    assert_ne!(before, after);

    let fetched = send(
        &server,
        Method::GET,
        &format!("/v1/records/holders/{record_id}"),
        &[],
        None,
    )
    .await;
    assert_eq!(fetched.status(), StatusCode::OK);
    let fetched = body_json(fetched).await;
    assert_eq!(fetched["data"]["domainData"]["secret"], "delta-two");

    // The blind index followed the new value.
    let lookup = send(
        &server,
        Method::POST,
        "/v1/records/holders:lookup?$select=label,secret",
        &[
            ("content-type", "application/json".to_owned()),
            ("idempotency-key", "patch-lookup".to_owned()),
        ],
        Some(json!({"selector": "by-secret", "values": {"secret": "delta-two"}})),
    )
    .await;
    assert_eq!(lookup.status(), StatusCode::OK);

    // A JSON-Patch test against an opaque envelope can neither pass nor fail
    // honestly, so the operation is refused instead of compared.
    let tested = send(
        &server,
        Method::PATCH,
        &format!("/v1/records/holders/{record_id}"),
        &[
            ("content-type", "application/json-patch+json".to_owned()),
            ("idempotency-key", "patch-test-op".to_owned()),
            ("if-match", patched_etag),
        ],
        Some(json!([
            {"op": "test", "path": "/data/secret", "value": "delta-two"},
        ])),
    )
    .await;
    assert_eq!(tested.status(), StatusCode::BAD_REQUEST);
    let tested = body_json(tested).await;
    assert_eq!(tested["code"], "request.invalid");

    server.shutdown().await;
}

// ---------------------------------------------------------------------------
// History, revision, review-snapshot, and attachment read edges
// ---------------------------------------------------------------------------

/// Create one holder, patch its secret, and return the record id. The holder
/// ends at revision 2 with `delta-nine` sealed in place of `gamma-seven`.
async fn holder_at_revision_two(server: &LiveServer, key: &str) -> String {
    let (status, created, etag) = create_holder(
        server,
        key,
        json!({
            "jurisdiction": "area-a",
            "label": "history-target",
            "secret": "gamma-seven",
        }),
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let record_id = created["data"]["recordIdentifier"]
        .as_str()
        .expect("record identifier is present")
        .to_owned();
    let patched = send(
        server,
        Method::PATCH,
        &format!("/v1/records/holders/{record_id}"),
        &[
            ("content-type", "application/json-patch+json".to_owned()),
            ("idempotency-key", format!("{key}-patch")),
            ("if-match", etag.expect("create carries an ETag")),
        ],
        Some(json!([
            {"op": "replace", "path": "/data/secret", "value": "delta-nine"},
        ])),
    )
    .await;
    assert_eq!(patched.status(), StatusCode::OK);
    record_id
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revision_and_history_reads_decrypt_at_the_response_edge() {
    // The decoder keeps its own copy of the envelope tag because it cannot
    // link the runtime-only crypto crate; this pins the two together.
    assert_eq!(
        registry_breg::history_schema::ENVELOPE_MEMBER_TAG,
        registry_platform_crypto::field_encryption::ENVELOPE_MEMBER_TAG
    );
    let server = boot_live_server().await;
    let record_id = holder_at_revision_two(&server, "history-edge").await;

    // The revision list serves both revisions with opened members.
    let listed = send(
        &server,
        Method::GET,
        &format!("/v1/records/holders/{record_id}/revisions"),
        &[],
        None,
    )
    .await;
    assert_eq!(listed.status(), StatusCode::OK);
    let listed = body_json(listed).await;
    let items = listed["items"].as_array().expect("revision items");
    assert_eq!(items.len(), 2);
    assert_eq!(items[0]["revisionIdentifier"], "2");
    assert_eq!(items[0]["domainData"]["secret"], "delta-nine");
    assert_eq!(items[1]["domainData"]["secret"], "gamma-seven");

    // The revision detail read opens the same stored member.
    let detail = send(
        &server,
        Method::GET,
        &format!("/v1/records/holders/{record_id}/revisions/1"),
        &[],
        None,
    )
    .await;
    assert_eq!(detail.status(), StatusCode::OK);
    let detail = body_json(detail).await;
    assert_eq!(detail["data"]["domainData"]["secret"], "gamma-seven");

    // The stored-record snapshot query surface opens the latest revision.
    let snapshot = send(
        &server,
        Method::GET,
        "/v1/records/holders:snapshot?$select=jurisdiction,label,secret&$count=true",
        &[],
        None,
    )
    .await;
    assert_eq!(snapshot.status(), StatusCode::OK);
    let snapshot = body_json(snapshot).await;
    let items = snapshot["items"].as_array().expect("snapshot items");
    assert_eq!(items.len(), 1);
    assert_eq!(items[0]["domainData"]["secret"], "delta-nine");

    // Every stored revision snapshot keeps only the tagged member.
    for revision in [1, 2] {
        let bytes = revision_snapshot(&server, "holder", &record_id, revision).await;
        let text = String::from_utf8(bytes).expect("snapshot is UTF-8");
        assert!(
            text.contains("__bregEncryptedV1"),
            "revision {revision} keeps the tagged member: {text}"
        );
        assert!(!text.contains("gamma-seven"));
        assert!(!text.contains("delta-nine"));
    }

    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tampered_revision_snapshot_fails_closed_and_sibling_surfaces_serve() {
    let server = boot_live_server().await;

    let note = send(
        &server,
        Method::POST,
        "/v1/records/notes",
        &[
            ("content-type", "application/json".to_owned()),
            ("idempotency-key", "history-tamper-note".to_owned()),
        ],
        Some(json!({"data": {"text": "plain note"}})),
    )
    .await;
    assert_eq!(note.status(), StatusCode::CREATED);

    let record_id = holder_at_revision_two(&server, "history-tamper").await;

    // Corrupt revision 1's tagged envelope directly in the journal.
    let stored = revision_snapshot(&server, "holder", &record_id, 1).await;
    let tampered = tamper_encrypted_member(&stored);
    server
        .booted
        .database
        .admin
        .execute(
            "UPDATE registry_internal.registry_revisions SET snapshot = $1
             WHERE entity_id = 'holder' AND record_id = $2 AND record_revision = 1",
            &[
                &tampered,
                &Uuid::parse_str(&record_id).expect("record id is a UUID"),
            ],
        )
        .await
        .expect("tampered revision snapshot writes");

    // The listing that would surface the tampered revision refuses closed,
    // value-free.
    let listed = send(
        &server,
        Method::GET,
        &format!("/v1/records/holders/{record_id}/revisions"),
        &[],
        None,
    )
    .await;
    assert_eq!(listed.status(), StatusCode::SERVICE_UNAVAILABLE);
    let listed = body_json(listed).await;
    assert_eq!(listed["code"], "runtime.field_encryption.unavailable");
    assert!(
        !listed.to_string().contains("gamma"),
        "the refusal stays value-free"
    );

    // The tampered revision's own detail read refuses the same way, while the
    // untampered revision beside it still serves.
    let tampered_detail = send(
        &server,
        Method::GET,
        &format!("/v1/records/holders/{record_id}/revisions/1"),
        &[],
        None,
    )
    .await;
    assert_eq!(tampered_detail.status(), StatusCode::SERVICE_UNAVAILABLE);
    let tampered_detail = body_json(tampered_detail).await;
    assert_eq!(
        tampered_detail["code"],
        "runtime.field_encryption.unavailable"
    );

    let intact_detail = send(
        &server,
        Method::GET,
        &format!("/v1/records/holders/{record_id}/revisions/2"),
        &[],
        None,
    )
    .await;
    assert_eq!(intact_detail.status(), StatusCode::OK);
    let intact_detail = body_json(intact_detail).await;
    assert_eq!(intact_detail["data"]["domainData"]["secret"], "delta-nine");

    // The live row and the latest-revision snapshot surface never read the
    // tampered journal row, and the sibling entity keeps serving.
    let fetched = send(
        &server,
        Method::GET,
        &format!("/v1/records/holders/{record_id}"),
        &[],
        None,
    )
    .await;
    assert_eq!(fetched.status(), StatusCode::OK);

    let snapshot = send(
        &server,
        Method::GET,
        "/v1/records/holders:snapshot?$select=jurisdiction,label,secret",
        &[],
        None,
    )
    .await;
    assert_eq!(snapshot.status(), StatusCode::OK);

    let notes = send(
        &server,
        Method::GET,
        "/v1/records/notes?$select=text",
        &[],
        None,
    )
    .await;
    assert_eq!(notes.status(), StatusCode::OK);

    server.shutdown().await;
}

/// One submitted dossier-request with an uploaded attachment: the draft, its
/// evidence file, and the submission that freezes proposal version 1.
async fn submitted_dossier_request(server: &LiveServer, dossier_id: &str) -> String {
    let response = send(
        server,
        Method::POST,
        "/v1/records/dossier-requests",
        &[
            ("content-type", "application/json".to_owned()),
            ("idempotency-key", "dossier-request-create".to_owned()),
        ],
        Some(json!({ "data": {
            "jurisdiction": "area-a",
            "reason": "correct the label",
            "dossier": dossier_id,
            "code": "XYZ-9999",
            "secret": "delta-nine",
        }})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED, "the draft creates");
    let created = body_json(response).await;
    let request_id = created["data"]["recordIdentifier"]
        .as_str()
        .expect("request identifier is present")
        .to_owned();

    let before = send(
        server,
        Method::GET,
        &format!("/v1/records/dossier-requests/{request_id}"),
        &[],
        None,
    )
    .await;
    assert_eq!(before.status(), StatusCode::OK);
    let etag = response_etag(&before);

    let uploaded = send_bytes_as(
        server,
        Method::PATCH,
        &format!("/v1/records/dossier-requests/{request_id}/attachments/evidence"),
        &[
            ("content-type", "application/octet-stream".to_owned()),
            ("idempotency-key", "dossier-evidence-upload".to_owned()),
            ("if-match", etag),
        ],
        Some(b"dossier evidence".to_vec()),
        &operator_token(),
    )
    .await;
    assert_eq!(uploaded.status(), StatusCode::OK, "the attachment uploads");

    // The upload advanced the record revision, so the submit action and its
    // precondition come from a fresh read.
    let after = send(
        server,
        Method::GET,
        &format!("/v1/records/dossier-requests/{request_id}"),
        &[],
        None,
    )
    .await;
    assert_eq!(after.status(), StatusCode::OK);
    let after = body_json(after).await;
    let submit = find_action(&after, "submit_request");
    let submitted = send_as(
        server,
        Method::POST,
        submit["href"].as_str().expect("submit href"),
        &[
            ("content-type", "application/json".to_owned()),
            ("idempotency-key", "dossier-request-submit".to_owned()),
            (
                "if-match",
                submit["ifMatch"].as_str().expect("submit etag").to_owned(),
            ),
        ],
        Some(json!({})),
        &operator_token(),
    )
    .await;
    assert_eq!(submitted.status(), StatusCode::OK, "the request submits");
    request_id
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn review_snapshot_opens_target_before_for_the_reviewer() {
    let server = boot_live_server().await;

    let response = send(
        &server,
        Method::POST,
        "/v1/records/dossiers",
        &[
            ("content-type", "application/json".to_owned()),
            ("idempotency-key", "review-dossier-create".to_owned()),
        ],
        Some(json!({ "data": {
            "jurisdiction": "area-a",
            "label": "review-target",
            "code": "ABC-1234",
        }})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let created = body_json(response).await;
    let dossier_id = created["data"]["recordIdentifier"]
        .as_str()
        .expect("dossier identifier is present")
        .to_owned();

    let request_id = submitted_dossier_request(&server, &dossier_id).await;

    // The reviewer sees the captured target row opened at the display edge.
    let reviewed = send_as(
        &server,
        Method::GET,
        &format!("/v1/records/dossier-requests/{request_id}?accessProfile=reviewer"),
        &[],
        None,
        &token_for("reviewer", "area-a"),
    )
    .await;
    assert_eq!(reviewed.status(), StatusCode::OK);
    let reviewed = body_json(reviewed).await;
    let approve = find_action(&reviewed, "approve_request");
    let targets = approve["review"]["targets"]
        .as_array()
        .expect("the approve action carries review targets");
    let target = targets
        .iter()
        .find(|target| target["entityId"] == "dossier")
        .expect("the dossier target is reviewed");
    assert_eq!(
        target["before"]["code"], "ABC-1234",
        "the captured before row opens for the reviewer"
    );
    // Phase 1 refuses encrypted change-request targets, so the effect changes
    // the plaintext label; the encrypted code member travels sealed in both
    // captured rows and opens here unchanged.
    assert_eq!(target["after"]["label"], "correct the label");
    assert_eq!(target["after"]["code"], "ABC-1234");

    // The stored target reference keeps the tagged member.
    let base_snapshot: String = server
        .booted
        .database
        .admin
        .query_one(
            "SELECT base_snapshot::text FROM registry_internal.registry_request_targets
             WHERE request_entity_id = 'dossier-request' AND request_id = $1
               AND target_entity_id = 'dossier'",
            &[&Uuid::parse_str(&request_id).expect("request id is a UUID")],
        )
        .await
        .expect("the stored target base snapshot reads")
        .get(0);
    assert!(
        base_snapshot.contains("__bregEncryptedV1"),
        "the stored base snapshot keeps the tagged member: {base_snapshot}"
    );
    assert!(!base_snapshot.contains("ABC-1234"));

    server.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn attachment_authorization_over_encrypted_records_fails_closed() {
    let server = boot_live_server().await;

    let response = send(
        &server,
        Method::POST,
        "/v1/records/dossiers",
        &[
            ("content-type", "application/json".to_owned()),
            ("idempotency-key", "attachment-dossier-create".to_owned()),
        ],
        Some(json!({ "data": {
            "jurisdiction": "area-a",
            "label": "attachment-target",
            "code": "ABC-1234",
        }})),
    )
    .await;
    assert_eq!(response.status(), StatusCode::CREATED);
    let created = body_json(response).await;
    let dossier_id = created["data"]["recordIdentifier"]
        .as_str()
        .expect("dossier identifier is present")
        .to_owned();

    let request_id = submitted_dossier_request(&server, &dossier_id).await;
    let download = format!(
        "/v1/records/dossier-requests/{request_id}/attachments/evidence?proposalVersion=1&accessProfile=reviewer"
    );

    // An authorized reviewer downloads the retained attachment.
    let authorized = send_as(
        &server,
        Method::GET,
        &download,
        &[],
        None,
        &token_for("reviewer", "area-a"),
    )
    .await;
    assert_eq!(authorized.status(), StatusCode::OK);
    let bytes = body_bytes(authorized).await;
    assert_eq!(bytes, b"dossier evidence");

    // A reviewer outside the row boundary is refused without the bytes.
    let unauthorized = send_as(
        &server,
        Method::GET,
        &download,
        &[],
        None,
        &token_for("reviewer", "area-b"),
    )
    .await;
    assert_eq!(
        unauthorized.status(),
        StatusCode::NOT_FOUND,
        "an excluded row cannot authorize attachment disclosure"
    );

    // Corrupt the tagged envelope in every revision snapshot of the request
    // record, so whichever revision the retained-attachment guard froze as its
    // intake refuses to open.
    let record_uuid = Uuid::parse_str(&request_id).expect("request id is a UUID");
    let revisions: Vec<i64> = server
        .booted
        .database
        .admin
        .query(
            "SELECT record_revision FROM registry_internal.registry_revisions
             WHERE entity_id = 'dossier-request' AND record_id = $1
             ORDER BY record_revision",
            &[&record_uuid],
        )
        .await
        .expect("the request record revisions read")
        .into_iter()
        .map(|row| row.get(0))
        .collect();
    assert!(!revisions.is_empty(), "the request record has revisions");
    for revision in revisions {
        let stored = revision_snapshot(&server, "dossier-request", &request_id, revision).await;
        let Ok(text) = String::from_utf8(stored) else {
            continue;
        };
        if !text.contains("__bregEncryptedV1") {
            continue;
        }
        let tampered = tamper_encrypted_member(text.as_bytes());
        server
            .booted
            .database
            .admin
            .execute(
                "UPDATE registry_internal.registry_revisions SET snapshot = $1
                 WHERE entity_id = 'dossier-request' AND record_id = $2 AND record_revision = $3",
                &[&tampered, &record_uuid, &revision],
            )
            .await
            .expect("tampered intake snapshot writes");
    }

    // The tampered envelope refuses the disclosure closed instead of
    // authorizing it, value-free.
    let refused = send_as(
        &server,
        Method::GET,
        &download,
        &[],
        None,
        &token_for("reviewer", "area-a"),
    )
    .await;
    assert_eq!(refused.status(), StatusCode::SERVICE_UNAVAILABLE);
    let refused = body_json(refused).await;
    assert_eq!(refused["code"], "runtime.field_encryption.unavailable");
    assert!(
        !refused.to_string().contains("delta"),
        "the refusal stays value-free"
    );

    server.shutdown().await;
}
