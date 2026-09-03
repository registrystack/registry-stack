// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "runtime")]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use registry_platform_canonical_json::canonicalize_json;
use registry_platform_crypto::{generate_private_jwk, sign, GeneratedKeyAlgorithm};
use registry_server::compiler::{module_digest, CompileProfile};
use registry_server::contract::{parse_module_yaml, parse_project_yaml};
use registry_server::package::{
    prepare_package, PackageBuildRequest, PackageFileRole, PackageMigrationPlanInput,
    PackageModuleSource, PackageSignature, PackageSourceFile, PackageTrustAnchor, SignaturePolicy,
    TrustAnchorKey, TRUST_ANCHOR_API_VERSION,
};
use registry_server::startup::{prepare, StartupError};
use serde::Serialize;

const INSTANCE: &str = "instance-under-test";
const DATABASE: &str = "database-under-test";
const SOURCE_REVISION: &str = "compiler-source-revision";
const FIXTURE_JOURNEYS: &[u8] = br#"apiVersion: registry.registrystack.org/server-journeys/v1
journeys:
  - id: neutral-record-list
    steps:
      - id: list-neutral-records
        entity: neutral-record
        accessProfile: reader
        claims: {principal: package-reader}
        request: {operation: list}
        expect: {outcome: success, status: 200, count: 0}
"#;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[tokio::test]
async fn tampered_package_refuses_before_database_audit_oidc_or_listener_access() {
    let fixture = StartupFixture::new();
    let package = PackageFixture::build(&fixture.root);
    fs::write(
        first_generated_path(&package.root),
        b"tampered-before-startup",
    )
    .expect("test tampers package artifact");
    let config_path = fixture.write_config(&package);

    let error = match prepare(&config_path).await {
        Ok(_) => panic!("tampered package prepared"),
        Err(error) => error,
    };

    assert_eq!(error, StartupError::PackageRefused);
}

struct StartupFixture {
    root: PathBuf,
    secret_root: PathBuf,
}

impl StartupFixture {
    fn new() -> Self {
        let parent = std::env::temp_dir()
            .canonicalize()
            .expect("temporary parent canonicalizes");
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock follows epoch")
            .as_nanos();
        let ordinal = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
        let root = parent.join(format!(
            "registry-server-startup-ordering-{}-{suffix}-{ordinal}",
            std::process::id(),
        ));
        fs::create_dir(&root).expect("fixture root creates");
        let secret_root = root.join("secrets");
        fs::create_dir(&secret_root).expect("secret root creates");
        Self { root, secret_root }
    }

    fn write_config(&self, package: &PackageFixture) -> PathBuf {
        let path = self.root.join("runtime.yaml");
        fs::write(
            &path,
            format!(
                r#"apiVersion: registry.registrystack.org/server-runtime/v1alpha1
kind: RegistryServerRuntimeConfig
listener:
  bind: 127.0.0.1:9
identity:
  environment: production
  instanceId: {INSTANCE}
  databaseId: {DATABASE}
  databaseInitializationEnvironment: production
secretProviders:
  environment: {{}}
  file:
    root: {}
database:
  runtimeUrlRef: secret:env/REGISTRY_SERVER_STARTUP_TEST_DATABASE_URL
  migrationUrlRef: secret:env/REGISTRY_SERVER_STARTUP_TEST_MIGRATION_DATABASE_URL
  pool:
    maxSize: 1
    waitTimeoutMilliseconds: 1000
    createTimeoutMilliseconds: 1000
    recycleTimeoutMilliseconds: 1000
  roles:
    migration: registry_migration
    runtime: registry_runtime
package:
  root: {}
  trustAnchorPath: {}
  compilerSourceRevision: {SOURCE_REVISION}
  activeRevision: {}
  activeSequence: 1
authentication:
  oidc:
    issuer: http://127.0.0.1:9
    audience: urn:registry-server:test
    allowedAlgorithm: EdDSA
    accessTokenType: JWT
    scopeClaim: scope
    scopeSeparator: " "
    maxTokenLifetimeSeconds: 300
    leewayMilliseconds: 60000
    jwksCache:
      cacheTtlSeconds: 600
      negativeCacheTtlSeconds: 60
      refreshCooldownSeconds: 30
      maxDocumentBytes: 65536
      requestTimeoutMilliseconds: 10
      outageToleranceSeconds: 0
  authorityClaims:
    principal: principal
audit:
  hashKeyRef: secret:file/missing-audit-key
cursor:
  secretRef: secret:file/missing-cursor-key
  maxAgeSeconds: 300
operationalTimeouts:
  httpRequestMilliseconds: 1000
  shutdownGraceMilliseconds: 1000
  recordLockMilliseconds: 1000
  migrationLockMilliseconds: 1000
  migrationStatementMilliseconds: 1000
"#,
                self.secret_root.display(),
                package.root.display(),
                package.anchor.display(),
                package.revision
            ),
        )
        .expect("runtime config writes");
        path
    }
}

impl Drop for StartupFixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

struct PackageFixture {
    root: PathBuf,
    anchor: PathBuf,
    revision: String,
}

impl PackageFixture {
    fn build(parent: &Path) -> Self {
        let root = parent.join("package");
        let signing = generate_private_jwk(GeneratedKeyAlgorithm::Es384)
            .expect("fixture signing key generates");
        let module_bytes = module_bytes();
        let module = parse_module_yaml(&module_bytes).expect("fixture module parses");
        let project_bytes = project_bytes(&module_digest(&module));
        let project = parse_project_yaml(&project_bytes).expect("fixture project parses");
        registry_server::compiler::compile_project(
            &project,
            std::slice::from_ref(&module),
            CompileProfile::Production,
        )
        .expect("fixture project compiles in production");
        let key_id = signing.public().kid.expect("generated key has kid");
        let prepared = prepare_package(PackageBuildRequest {
            environment: "production".to_owned(),
            instance_id: INSTANCE.to_owned(),
            database_id: DATABASE.to_owned(),
            sequence: 1,
            prior_revision: None,
            compiler_source_revision: SOURCE_REVISION.to_owned(),
            schema_fingerprint: fingerprint(1),
            signature_policy: SignaturePolicy {
                threshold: 1,
                key_ids: vec![key_id.clone()],
            },
            project: PackageSourceFile {
                path: "source/registry.yaml".to_owned(),
                bytes: project_bytes,
            },
            modules: vec![PackageModuleSource {
                id: "core".to_owned(),
                path: "source/modules/core/module.yaml".to_owned(),
                bytes: module_bytes,
                assets: Vec::new(),
            }],
            fixture_journeys: PackageSourceFile {
                path: "tests/journeys.yaml".to_owned(),
                bytes: FIXTURE_JOURNEYS.to_vec(),
            },
            migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
        })
        .expect("fixture package prepares");
        let signature =
            sign(prepared.canonical_signed_bytes(), &signing).expect("fixture package signs");
        prepared
            .publish_to_directory(
                &root,
                vec![PackageSignature {
                    key_id: key_id.clone(),
                    signature_hex: hex(&signature),
                }],
            )
            .expect("fixture package publishes");
        let anchor = parent.join("trust-anchor.json");
        write_json(
            &anchor,
            &PackageTrustAnchor {
                api_version: TRUST_ANCHOR_API_VERSION.to_owned(),
                environment: "production".to_owned(),
                instance_id: INSTANCE.to_owned(),
                database_id: DATABASE.to_owned(),
                threshold: 1,
                keys: vec![TrustAnchorKey {
                    key_id,
                    jwk: serde_json::to_value(signing.public()).expect("public JWK serializes"),
                }],
            },
        );
        Self {
            root,
            anchor,
            revision: prepared.package_revision().to_owned(),
        }
    }
}

fn project_bytes(module_digest: &str) -> Vec<u8> {
    format!(
        r#"{{"apiVersion":"registry.registrystack.org/v1alpha1","kind":"RegistryProject","registry":{{"id":"neutral-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://package.example.test"}},"package":{{"environment":"production","instanceId":"{INSTANCE}","sequence":1,"sourceRevision":"{SOURCE_REVISION}"}},"manifestProjection":{{"accessProfile":"reader","classificationCeiling":"internal","catalog":{{"baseUrl":"https://package.example.test","title":"Neutral Registry Catalog","publisher":{{"id":"neutral-registry-authority","name":"Package Test Publisher"}}}},"publicService":{{"id":"neutral-registry-service","title":"Neutral Registry Catalog"}},"datasets":[{{"id":"neutral-registry","title":"Neutral Registry Dataset","owner":"Package Test Publisher","status":"active"}}],"dataServices":[{{"id":"neutral-registry-data-service","title":"Neutral Registry Catalog","endpointUrl":"https://package.example.test","servesDatasets":["neutral-registry"]}}]}},"modules":[{{"id":"core","version":"1","digest":"{module_digest}"}}]}}"#
    )
    .into_bytes()
}

fn module_bytes() -> Vec<u8> {
    br#"{"id":"core","version":"1","entities":[{"id":"neutral-record","primaryDataset":"neutral-registry","route":"neutral-records","mutationMode":"create_only","fields":[{"id":"code","type":"string","maxLength":8,"classification":"internal"}],"accessProfiles":[{"id":"reader","principalClaim":"principal","operations":["get","list"],"readableFields":["code"]}]}]}"#.to_vec()
}

fn first_generated_path(root: &Path) -> PathBuf {
    let envelope: registry_server::package::PackageEnvelope =
        serde_json::from_slice(&fs::read(root.join("package.json")).expect("manifest reads"))
            .expect("manifest parses");
    root.join(
        &envelope
            .signed
            .files
            .iter()
            .find(|entry| entry.role == PackageFileRole::GeneratedOpenapi)
            .expect("generated entry exists")
            .path,
    )
}

fn write_json(path: &Path, value: &impl Serialize) {
    let bytes = canonicalize_json(&serde_json::to_value(value).expect("value serializes"))
        .expect("value canonicalizes");
    fs::write(path, bytes).expect("fixture JSON writes");
}

fn fingerprint(byte: u8) -> String {
    format!("sha256:{}", format!("{byte:02x}").repeat(32))
}

fn hex(bytes: &[u8]) -> String {
    let mut result = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        write!(&mut result, "{byte:02x}").expect("writing to String succeeds");
    }
    result
}
