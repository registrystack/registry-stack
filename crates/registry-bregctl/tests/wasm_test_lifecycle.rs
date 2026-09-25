// SPDX-License-Identifier: Apache-2.0

//! Public pre-sign lifecycle regression for WASM action fixtures. The test
//! launches `bregctl test` as a child process so no in-process test can have
//! populated the process-wide executor before the command starts.

#![cfg(all(feature = "wasm", unix))]

use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use registry_breg::postgres::{provision_managed_schemas, SqlIdentifier};
use registry_platform_crypto::PrivateJwk;
use registry_platform_testing::{fixtures, jwks_from_private_jwk, MockIdp};
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio::task::JoinHandle;
use tokio_postgres::{config::SslMode, Client, Config};
use tokio_postgres_rustls::MakeRustlsConnect;

const INSTANCE_ID: &str = "wasm-schema-test-instance";
const DATABASE_ID: &str = "wasm-schema-test-database";
const SOURCE_REVISION: &str = "wasm-schema-test-source";
const AUDIENCE: &str = "urn:breg:wasm-schema-test";
const JOURNEY_ID: &str = "wasm-fixed-output";

#[test]
#[ignore = "requires BREG_TEST_DATABASE_URL and a PostgreSQL administrator"]
fn public_bregctl_test_executes_fixed_output_wasm_and_emits_receipt() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime builds");
    let mut database = runtime.block_on(TestDatabase::create());
    let idp = runtime.block_on(MockIdp::start());
    let project = ProjectFixture::write(&database, &idp);

    let output = Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .args([
            "--format",
            "json",
            "test",
            path(&project.project_root),
            "--database-id",
            DATABASE_ID,
            "--runtime-config",
            path(&project.runtime_config),
            "--credentials",
            path(&project.credentials),
            "--output",
            path(&project.receipt),
        ])
        .output()
        .expect("bregctl test starts in a fresh process");

    let stdout = serde_json::from_slice::<Value>(&output.stdout);
    let receipt = fs::read(&project.receipt)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<Value>(&bytes).ok());

    runtime.block_on(idp.stop());
    runtime.block_on(database.cleanup());

    assert_command_succeeded(&output);
    let stdout = stdout.expect("successful command output is JSON");
    assert_eq!(stdout["command"], "test");
    assert_eq!(stdout["successfulJourneyIds"], json!([JOURNEY_ID]));
    let receipt = receipt.expect("the successful schema test publishes its receipt");
    assert_eq!(receipt["kind"], "SchemaTestReceipt");
    assert_eq!(receipt["successfulJourneyIds"], json!([JOURNEY_ID]));
}

fn assert_command_succeeded(output: &Output) {
    assert!(
        output.status.success(),
        "bregctl test failed\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

struct ProjectFixture {
    _root: TempDir,
    project_root: PathBuf,
    runtime_config: PathBuf,
    credentials: PathBuf,
    receipt: PathBuf,
}

impl ProjectFixture {
    fn write(database: &TestDatabase, idp: &MockIdp) -> Self {
        let root = tempfile::tempdir().expect("fixture directory creates");
        let root_path = root.path().canonicalize().expect("fixture path resolves");
        let handlers = root_path.join("handlers");
        let tests = root_path.join("tests");
        let secrets = root_path.join("secrets");
        let empty_package = root_path.join("empty-package");
        fs::create_dir_all(&handlers).expect("handler directory creates");
        fs::create_dir_all(&tests).expect("journey directory creates");
        fs::create_dir_all(&secrets).expect("secret directory creates");
        fs::create_dir_all(&empty_package).expect("empty package directory creates");

        fs::write(root_path.join("registry.yaml"), project_source())
            .expect("project source writes");
        fs::write(
            handlers.join("fixed-output.wasm"),
            outcome_guest(r#"{"effects":[{"id":"record","set":{"code":"WASM-FIXED"}}]}"#),
        )
        .expect("WASM handler writes");
        fs::write(tests.join("journeys.yaml"), journey_source()).expect("journey source writes");

        write_secret(
            &secrets.join("runtime-url"),
            database.runtime_url.as_bytes(),
        );
        write_secret(
            &secrets.join("migration-url"),
            database.migration_url.as_bytes(),
        );
        write_secret(&secrets.join("audit-key"), &[0x71; 32]);
        write_secret(&secrets.join("cursor-key"), &[0x52; 32]);
        write_secret(
            &secrets.join("oidc-jwks"),
            &serde_json::to_vec(&jwks_from_private_jwk(
                &PrivateJwk::parse(fixtures::ED25519_PRIVATE_JWK).expect("test signing key parses"),
            ))
            .expect("test JWKS serializes"),
        );
        write_secret(
            &secrets.join("operator-token"),
            idp.mint_token(json!({
                "aud": AUDIENCE,
                "registry_actor_kind": "service",
                "registry_principal": "wasm-fixture-operator",
                "registry_purpose": "fixture-assurance",
                "scope": "registry:wasm-fixture:invoke",
            }))
            .as_bytes(),
        );

        let trust_anchor = root_path.join("trust-anchor.json");
        fs::write(&trust_anchor, b"{}").expect("unused local trust anchor writes");
        let runtime_config = root_path.join("runtime.yaml");
        fs::write(
            &runtime_config,
            runtime_source(&secrets, &empty_package, &trust_anchor, database, idp),
        )
        .expect("runtime configuration writes");
        set_private(&runtime_config);
        registry_breg::runtime_config::load_runtime_config(&runtime_config)
            .expect("runtime configuration loads")
            .secret_resolver()
            .expect("runtime secret resolver builds")
            .resolve("secret:file/operator-token")
            .expect("operator token resolves through the public runtime configuration");

        let credentials = root_path.join("credentials.yaml");
        fs::write(
            &credentials,
            format!(
                r#"apiVersion: registry.registrystack.org/breg-schema-test-credentials/v1
kind: SchemaTestCredentials
bindings:
  - journeyId: {JOURNEY_ID}
    stepId: invoke-fixed-output
    credential: {{type: bearer, tokenRef: secret:file/operator-token}}
"#,
            ),
        )
        .expect("schema-test credentials write");
        set_private(&credentials);
        let receipt = root_path.join("schema-test-receipt.json");
        Self {
            _root: root,
            project_root: root_path,
            runtime_config,
            credentials,
            receipt,
        }
    }
}

fn project_source() -> &'static str {
    r#"apiVersion: registry.registrystack.org/v1alpha1
kind: RegistryProject
registry:
  id: wasm-schema-test
  canonicalBaseIri: https://wasm-schema-test.invalid
  version: 0.1.0
  defaultLanguage: en
package:
  environment: local
  instanceId: wasm-schema-test-instance
  sequence: 1
  sourceRevision: wasm-schema-test-source
manifestProjection:
  accessProfile: operator
  classificationCeiling: public
  catalog:
    baseUrl: https://wasm-schema-test.invalid
    title: WASM Schema Test
    publisher: {id: wasm-schema-test-authority, name: Synthetic Publisher}
  publicService: {id: wasm-schema-test-service, title: WASM Schema Test}
  datasets:
    - {id: wasm-schema-test, title: WASM Schema Test, owner: Synthetic Publisher, status: active}
  dataServices:
    - {id: wasm-schema-test-data, title: WASM Schema Test, endpointUrl: https://wasm-schema-test.invalid, servesDatasets: [wasm-schema-test]}
  distributions: []
entities:
  - id: record
    primaryDataset: wasm-schema-test
    route: records
    mutationMode: create_only
    classification: public
    fields:
      - {id: code, type: string, required: true, maxLength: 32, classification: public}
actions:
  - id: create-fixed-record
    inputs:
      - {id: request, type: string, required: true, maxLength: 32, classification: public}
    handler:
      kind: wasm
      module: handlers/fixed-output.wasm
      abi: registry.action-handler/v1
      writes:
        - id: record
          target: {entity: record}
          operation: create
          fields: [code]
accessProfiles:
  - id: operator
    default: true
    principalClaim: registry_principal
    requiredScopes: [registry:wasm-fixture:invoke]
    requiredPurposes: [fixture-assurance]
    permissions:
      - action: create-fixed-record
        operations: [invoke]
        targets: [{entity: record, rowBoundaries: []}]
        results: [record]
      - {entity: record, operations: [get, list], readableFields: [code], rowBoundaries: []}
"#
}

fn journey_source() -> &'static str {
    r#"apiVersion: registry.registrystack.org/breg-journeys/v1
journeys:
  - id: wasm-fixed-output
    steps:
      - id: invoke-fixed-output
        action: create-fixed-record
        accessProfile: operator
        claims:
          principal: wasm-fixture-operator
          scopes: [registry:wasm-fixture:invoke]
          purpose: fixture-assurance
        request:
          operation: invoke
          idempotencyKey: wasm-fixed-output
          input: {request: ignored-by-fixed-output}
        expect: {outcome: success, status: 200}
        captureResults: {record: fixed-record}
"#
}

fn runtime_source(
    root: &Path,
    package: &Path,
    trust_anchor: &Path,
    database: &TestDatabase,
    idp: &MockIdp,
) -> String {
    let audit_path = root
        .with_file_name("audit")
        .join("audit.jsonl")
        .display()
        .to_string();
    format!(
        r#"apiVersion: registry.registrystack.org/breg-runtime/v1alpha1
kind: BRegRuntimeConfig
listener: {{bind: 127.0.0.1:0}}
identity:
  environment: local
  instanceId: {INSTANCE_ID}
  databaseId: {DATABASE_ID}
  databaseInitializationEnvironment: local
secretProviders:
  file: {{root: {}}}
database:
  runtimeUrlRef: secret:file/runtime-url
  migrationUrlRef: secret:file/migration-url
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
  compilerSourceRevision: {SOURCE_REVISION}
  activeRevision: sha256:1111111111111111111111111111111111111111111111111111111111111111
  activeSequence: 1
authentication:
  oidc:
    issuer: {}
    audience: {AUDIENCE}
    allowedAlgorithm: EdDSA
    accessTokenType: JWT
    scopeClaim: scope
    scopeSeparator: " "
    maxTokenLifetimeSeconds: 3600
    leewayMilliseconds: 60000
    jwksSource: {{kind: static, documentRef: secret:file/oidc-jwks}}
    jwksCache:
      cacheTtlSeconds: 60
      negativeCacheTtlSeconds: 1
      refreshCooldownSeconds: 1
      maxDocumentBytes: 65536
      requestTimeoutMilliseconds: 5000
      outageToleranceSeconds: 0
  authorityClaims:
    principal: registry_principal
    purpose: registry_purpose
audit: {{hashKeyRef: secret:file/audit-key, path: {audit_path}}}
cursor: {{secretRef: secret:file/cursor-key, maxAgeSeconds: 300}}
wasmExecution:
  backend: pulley
  maxModuleBytes: 2097152
  maxGuestMemoryBytes: 33554432
operationalTimeouts:
  httpRequestMilliseconds: 5000
  shutdownGraceMilliseconds: 1000
  recordLockMilliseconds: 2000
  migrationLockMilliseconds: 2000
  migrationStatementMilliseconds: 5000
"#,
        root.display(),
        database.migration_role.as_str(),
        database.runtime_role.as_str(),
        package.display(),
        trust_anchor.display(),
        idp.issuer(),
    )
}

fn outcome_guest(document: &str) -> Vec<u8> {
    let document = document.as_bytes();
    let escaped = document
        .iter()
        .map(|byte| format!("\\{byte:02x}"))
        .collect::<String>();
    wat::parse_str(format!(
        r#"(module
  (memory (export "memory") 1)
  (data (i32.const 1024) "{escaped}")
  (func (export "alloc") (param i32) (result i32) (i32.const 4096))
  (func (export "handle") (param i32 i32) (result i32) (i32.const 0))
  (func (export "result_ptr") (result i32) (i32.const 1024))
  (func (export "result_len") (result i32) (i32.const {length})))"#,
        length = document.len(),
    ))
    .expect("fixed-output guest compiles")
}

struct TestDatabase {
    admin_url: String,
    database: SqlIdentifier,
    migration_role: SqlIdentifier,
    runtime_role: SqlIdentifier,
    migration_url: String,
    runtime_url: String,
    cleaned: bool,
}

impl TestDatabase {
    async fn create() -> Self {
        let root_url = env::var("BREG_TEST_DATABASE_URL")
            .expect("BREG_TEST_DATABASE_URL is required for this ignored test");
        let suffix = unique_suffix();
        let database = SqlIdentifier::parse(&format!("breg_wasm_{suffix}"))
            .expect("generated database identifier validates");
        let migration_role = SqlIdentifier::parse(&format!("breg_wasm_migration_{suffix}"))
            .expect("generated migration role validates");
        let runtime_role = SqlIdentifier::parse(&format!("breg_wasm_runtime_{suffix}"))
            .expect("generated runtime role validates");
        let password = format!("rs{suffix}password");

        let (root, _root_connection) = connect(&root_url).await;
        root.batch_execute(&format!(
            "CREATE ROLE \"{}\" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '{}';\n\
             CREATE ROLE \"{}\" LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOBYPASSRLS PASSWORD '{}';",
            migration_role.as_str(),
            password,
            runtime_role.as_str(),
            password,
        ))
        .await
        .expect("test administrator provisions isolated roles");
        root.batch_execute(&format!("CREATE DATABASE \"{}\";", database.as_str()))
            .await
            .expect("test administrator provisions an isolated database");

        let (admin, _admin_connection) = connect(&database_url(&root_url, &database)).await;
        admin
            .batch_execute(&format!(
                "REVOKE ALL ON DATABASE \"{}\" FROM PUBLIC;\n\
                 GRANT CONNECT ON DATABASE \"{}\" TO \"{}\", \"{}\";",
                database.as_str(),
                database.as_str(),
                migration_role.as_str(),
                runtime_role.as_str(),
            ))
            .await
            .expect("test database privileges are constrained");
        provision_managed_schemas(&admin, &migration_role)
            .await
            .expect("managed schemas are provisioned");

        let migration_url = role_url(&root_url, &database, &migration_role, &password);
        let runtime_url = role_url(&root_url, &database, &runtime_role, &password);
        verify_role_connection(&migration_url, &migration_role).await;
        verify_role_connection(&runtime_url, &runtime_role).await;

        Self {
            migration_url,
            runtime_url,
            admin_url: root_url,
            database,
            migration_role,
            runtime_role,
            cleaned: false,
        }
    }

    async fn cleanup(&mut self) {
        if self.cleaned {
            return;
        }
        let (root, _root_connection) = connect(&self.admin_url).await;
        root.batch_execute(&format!(
            "DROP DATABASE \"{}\" WITH (FORCE);",
            self.database.as_str(),
        ))
        .await
        .expect("isolated WASM schema-test database drops");
        root.batch_execute(&format!(
            "DROP ROLE \"{}\"; DROP ROLE \"{}\";",
            self.runtime_role.as_str(),
            self.migration_role.as_str(),
        ))
        .await
        .expect("isolated WASM schema-test roles drop");
        self.cleaned = true;
    }
}

async fn verify_role_connection(url: &str, expected: &SqlIdentifier) {
    let (client, _connection) = connect(url).await;
    let current: String = client
        .query_one("SELECT current_user", &[])
        .await
        .expect("generated role can query its disposable database")
        .get(0);
    assert_eq!(current, expected.as_str());
}

fn role_url(root: &str, database: &SqlIdentifier, role: &SqlIdentifier, password: &str) -> String {
    let mut url = url::Url::parse(root).expect("PostgreSQL URL parses as a URL");
    url.set_username(role.as_str())
        .expect("generated role is URL-safe");
    url.set_password(Some(password))
        .expect("generated password is URL-safe");
    url.set_path(database.as_str());
    url.to_string()
}

fn database_url(root: &str, database: &SqlIdentifier) -> String {
    let mut url = url::Url::parse(root).expect("PostgreSQL URL parses as a URL");
    url.set_path(database.as_str());
    url.to_string()
}

async fn connect(url: &str) -> (Client, JoinHandle<()>) {
    let provider = rustls::crypto::ring::default_provider();
    assert!(
        provider.install_default().is_ok()
            || rustls::crypto::CryptoProvider::get_default().is_some(),
        "Rustls crypto provider installs",
    );
    let (connector, _) =
        MakeRustlsConnect::with_native_certs().expect("native TLS certificate roots are available");
    let mut config = Config::from_str(url).expect("PostgreSQL URL parses");
    config.ssl_mode(SslMode::Require);
    let (client, connection) = config
        .connect(connector)
        .await
        .expect("TLS PostgreSQL connection succeeds");
    let task = tokio::spawn(async move {
        connection
            .await
            .expect("TLS PostgreSQL connection remains healthy");
    });
    (client, task)
}

fn unique_suffix() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system time follows the Unix epoch")
        .as_nanos();
    format!(
        "{}_{}_{}",
        std::process::id(),
        nanos,
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

fn write_secret(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).expect("fixture secret writes");
    set_private(path);
}

fn set_private(path: &Path) {
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .expect("fixture file permissions restrict access");
}

fn path(path: &Path) -> &str {
    path.to_str().expect("fixture path is UTF-8")
}
