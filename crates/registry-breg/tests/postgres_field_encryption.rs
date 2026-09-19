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

use axum::body::Body;
use axum::http::{Request, StatusCode};
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
use registry_platform_testing::{fixtures as testing_fixtures, jwks_from_private_jwk};
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::UnixListener;
use tokio::task::JoinHandle;
use tower::ServiceExt as _;

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
    fields:
      - {id: jurisdiction, type: string, maxLength: 32, required: true, classification: public}
      - {id: label, type: string, maxLength: 128, required: true, classification: public}
      - {id: secret, type: string, maxLength: 256, required: true, classification: restricted, encrypted: true,
         lookup: {normalization: [trim, uppercase], unique: true}}
    constraints:
      - {kind: unique, fields: [label]}
  - id: note
    primaryDataset: fixture-registry
    route: notes
    mutationMode: create_only
    classification: restricted
    fields:
      - {id: text, type: string, maxLength: 200, required: true, classification: restricted}
accessProfiles:
  - id: operator
    default: true
    principalClaim: registry_principal
    requiredPurposes: [case-management]
    permissions:
      - entity: holder
        operations: [create, get, list, patch]
        readableFields: [jurisdiction, label, secret]
        writableFields: [jurisdiction, label, secret]
        rowBoundaries:
          - {field: jurisdiction, claim: jurisdiction, operator: equals}
      - entity: note
        rowBoundaries: []
        operations: [get, list]
        readableFields: [text]
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
/// registry state initialized. The migration connection stays open for the
/// caller's row and privilege assertions.
struct BootedDatabase {
    database: TestDatabase,
    fixture: EncryptedFixture,
    directory: PathBuf,
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
