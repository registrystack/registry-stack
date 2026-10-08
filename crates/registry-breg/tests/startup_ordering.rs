// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "runtime")]

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use registry_breg::compiler::{module_digest, CompileProfile};
use registry_breg::contract::{parse_module_yaml, parse_project_yaml};
use registry_breg::package::{
    prepare_package, PackageBuildRequest, PackageError, PackageFileRole, PackageMigrationPlanInput,
    PackageModuleSource, PackageSourceFile, PACKAGE_API_VERSION, PACKAGE_KIND,
    RETIRED_PACKAGE_API_VERSION,
};
use registry_breg::startup::{prepare, StartupError};
use registry_platform_config::package::{write_sum_file, PackageLimits, SUM_FILE};

const INSTANCE: &str = "instance-under-test";
const DATABASE: &str = "database-under-test";
const SOURCE_REVISION: &str = "compiler-source-revision";
const SHARED_PACKAGE_TAMPER: &str = "the package at package.root does not match its SHA256SUMS; \
changed: openapi/openapi.json; rebuild the package with `bregctl package` and deploy the whole \
directory";
const FIXTURE_JOURNEYS: &[u8] = br#"apiVersion: id.registrystack.org/formats/breg/journeys/v1
kind: BRegJourneys
journeys:
  - id: neutral-record-list
    steps:
      - id: list-neutral-records
        entity: neutral-record
        accessProfile: reader
        claims: {principal: package-reader}
        request: {type: list}
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

    assert_eq!(
        error,
        StartupError::PackageEnvelopeRefused(SHARED_PACKAGE_TAMPER.to_owned())
    );
}

#[tokio::test]
async fn a_refused_package_keeps_the_cause_that_refused_it() {
    // Startup discloses no value, but it must not collapse every package
    // fault into one refusal: an operator's diagnosis names the cause, so
    // two different faults have to arrive as two different causes.
    let fixture = StartupFixture::new();
    let package = PackageFixture::build(&fixture.root);
    fs::write(
        first_generated_path(&package.root),
        b"tampered-before-startup",
    )
    .expect("test tampers package artifact");
    let tampered = match prepare(&fixture.write_config(&package)).await {
        Ok(_) => panic!("tampered package prepared"),
        Err(error) => error,
    };

    let other = StartupFixture::new();
    let unknown = PackageFixture::build(&other.root);
    unknown.rewrite_with_unknown_api_version();
    let refused = match prepare(&other.write_config(&unknown)).await {
        Ok(_) => panic!("package with an unknown manifest api version prepared"),
        Err(error) => error,
    };

    assert_eq!(
        tampered,
        StartupError::PackageEnvelopeRefused(SHARED_PACKAGE_TAMPER.to_owned())
    );
    assert_eq!(
        refused,
        StartupError::PackageRefused(PackageError::Integrity)
    );
    assert_ne!(tampered, refused);
}

#[tokio::test]
async fn a_package_with_the_retired_api_version_is_refused_as_retired() {
    // CFG-CHANGE-2: a package an earlier release built names the retired
    // apiVersion and no kind. The runtime refuses it as retired, a cause of
    // its own, so the operator is told to rebuild rather than that the
    // package was tampered with.
    let fixture = StartupFixture::new();
    let package = PackageFixture::build(&fixture.root);
    package.rewrite_with_retired_api_version();

    let refused = match prepare(&fixture.write_config(&package)).await {
        Ok(_) => panic!("package with the retired manifest api version prepared"),
        Err(error) => error,
    };

    assert_eq!(
        refused,
        StartupError::PackageRefused(PackageError::RetiredApiVersion)
    );
    let message = PackageError::RetiredApiVersion.to_string();
    assert!(message.contains(RETIRED_PACKAGE_API_VERSION), "{message}");
    assert!(message.contains(PACKAGE_API_VERSION), "{message}");
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
            "breg-startup-ordering-{}-{suffix}-{ordinal}",
            std::process::id(),
        ));
        fs::create_dir(&root).expect("fixture root creates");
        let secret_root = root.join("secrets");
        fs::create_dir(&secret_root).expect("secret root creates");
        Self { root, secret_root }
    }

    fn write_config(&self, package: &PackageFixture) -> PathBuf {
        let path = self.root.join("runtime.yaml");
        let audit_path = self
            .root
            .join("audit")
            .join("audit.jsonl")
            .display()
            .to_string();
        fs::write(
            &path,
            format!(
                r#"apiVersion: registry.registrystack.org/breg-runtime/v1alpha1
kind: BRegRuntimeConfig
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
  runtimeUrlRef: secret:env/BREG_STARTUP_TEST_DATABASE_URL
  migrationUrlRef: secret:env/BREG_STARTUP_TEST_MIGRATION_DATABASE_URL
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
authentication:
  oidc:
    issuer: http://127.0.0.1:9
    audience: urn:breg:test
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
  path: {audit_path}
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
}

impl PackageFixture {
    fn build(parent: &Path) -> Self {
        let root = parent.join("package");
        let module_bytes = module_bytes();
        let module = parse_module_yaml(&module_bytes).expect("fixture module parses");
        let project_bytes = project_bytes(&module_digest(&module));
        let project = parse_project_yaml(&project_bytes).expect("fixture project parses");
        registry_breg::compiler::compile_project(
            &project,
            std::slice::from_ref(&module),
            CompileProfile::Production,
        )
        .expect("fixture project compiles in production");
        let prepared = prepare_package(PackageBuildRequest {
            from_package_digest: None,
            compiler_source_revision: SOURCE_REVISION.to_owned(),
            schema_fingerprint: fingerprint(1),
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
        prepared
            .publish_to_directory(&root)
            .expect("fixture package publishes");
        Self { root }
    }

    /// Rewrite the published manifest under an api version this release does
    /// not read and reseal the sum file, so only the manifest format differs.
    fn rewrite_with_unknown_api_version(&self) {
        self.rewrite_envelope(
            &format!(r#""apiVersion":"{PACKAGE_API_VERSION}""#),
            r#""apiVersion":"id.registrystack.org/formats/breg/package/v1""#,
        );
    }

    /// Rewrite the published manifest into the envelope an earlier release
    /// wrote, the retired api version and no kind, and reseal the sum file.
    fn rewrite_with_retired_api_version(&self) {
        self.rewrite_envelope(
            &format!(r#""apiVersion":"{PACKAGE_API_VERSION}","kind":"{PACKAGE_KIND}""#),
            &format!(r#""apiVersion":"{RETIRED_PACKAGE_API_VERSION}""#),
        );
    }

    fn rewrite_envelope(&self, from: &str, to: &str) {
        let manifest_path = self.root.join("package.json");
        let manifest = fs::read_to_string(&manifest_path).expect("manifest reads");
        let rewritten = manifest.replacen(from, to, 1);
        assert_ne!(rewritten, manifest, "the manifest names its api version");
        fs::remove_file(&manifest_path).expect("manifest removes");
        fs::write(&manifest_path, rewritten).expect("rewritten manifest writes");
        fs::remove_file(self.root.join(SUM_FILE)).expect("sum file removes");
        write_sum_file(
            &self.root,
            None,
            &PackageLimits::default(),
            "bregctl package",
        )
        .expect("sum file reseals the rewritten manifest");
    }
}

fn project_bytes(module_digest: &str) -> Vec<u8> {
    format!(
        r#"{{"apiVersion":"registry.registrystack.org/v1alpha1","kind":"RegistryProject","registry":{{"id":"neutral-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://package.example.test"}},"package":{{"sourceRevision":"{SOURCE_REVISION}"}},"manifestProjection":{{"accessProfile":"reader","classificationCeiling":"internal","catalog":{{"baseUrl":"https://package.example.test","title":"Neutral Registry Catalog","publisher":{{"id":"neutral-registry-authority","name":"Package Test Publisher"}}}},"publicService":{{"id":"neutral-registry-service","title":"Neutral Registry Catalog"}},"datasets":[{{"id":"neutral-registry","title":"Neutral Registry Dataset","owner":"Package Test Publisher","status":"active"}}],"dataServices":[{{"id":"neutral-registry-data-service","title":"Neutral Registry Catalog","endpointUrl":"https://package.example.test","servesDatasets":["neutral-registry"]}}]}},"modules":[{{"id":"core","version":"1","digest":"{module_digest}"}}]}}"#
    )
    .into_bytes()
}

fn module_bytes() -> Vec<u8> {
    br#"{"id":"core","version":"1","entities":[{"id":"neutral-record","primaryDataset":"neutral-registry","route":"neutral-records","mutationMode":"create_only","fields":[{"id":"code","type":"string","maxLength":8,"classification":"internal"}],"accessProfiles":[{"id":"reader","principalClaim":"principal","operations":["get","list"],"readableFields":["code"], "rowBoundaries": []}]}]}"#.to_vec()
}

fn first_generated_path(root: &Path) -> PathBuf {
    let envelope: registry_breg::package::PackageEnvelope =
        serde_json::from_slice(&fs::read(root.join("package.json")).expect("manifest reads"))
            .expect("manifest parses");
    root.join(
        &envelope
            .manifest
            .files
            .iter()
            .find(|entry| entry.role == PackageFileRole::GeneratedOpenapi)
            .expect("generated entry exists")
            .path,
    )
}

fn fingerprint(byte: u8) -> String {
    format!("sha256:{}", format!("{byte:02x}").repeat(32))
}
