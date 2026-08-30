// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::fs;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use registry_platform_canonical_json::canonicalize_json;
use registry_platform_crypto::{generate_private_jwk, sign, GeneratedKeyAlgorithm, PrivateJwk};
use registry_server::compiler::{compile_project, module_digest, CompileProfile};
use registry_server::contract::{parse_module_json, parse_module_yaml, parse_project_yaml};
use registry_server::fixtures::{
    validate_fixture_journeys, validate_schema_test_receipt_for_package,
};
use registry_server::package::{
    prepare_package, PackageBuildRequest, PackageMigrationPlanInput, PackageModuleSource,
    PackageSignature, PackageSourceFile, PackageTrustAnchor, PreparedPackage, SignaturePolicy,
    TrustAnchorKey, FIXTURE_JOURNEYS_PATH, MAX_PACKAGE_SOURCE_FILE_BYTES, TRUST_ANCHOR_API_VERSION,
};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

static TEMPORARY_COUNTER: AtomicU64 = AtomicU64::new(0);
const PACKAGE_INSTANCE: &str = "verify-instance";
const PACKAGE_DATABASE: &str = "verify-database";
const PACKAGE_SOURCE_REVISION: &str = "verify-compiler-source";
const PACKAGE_VALUE_CANARY: &str = "verify-path-trust-secret-sql-canary";
const SCHEMA_TEST_AUTHORED_SOURCE_CEILING_BYTES: usize = 1024 * 1024;
const PACKAGE_FIXTURE_JOURNEYS: &[u8] =
    br#"apiVersion: registry.registrystack.org/server-journeys/v1
journeys:
  - id: package-record-list
    steps:
      - id: list-records
        entity: record
        accessProfile: reader
        claims: {principal: package-reader}
        request: {operation: list}
        expect: {outcome: success, status: 200, count: 0}
"#;
const DATA_FIXTURE_JOURNEYS: &[u8] = br#"apiVersion: registry.registrystack.org/server-journeys/v1
journeys:
  - id: data-record-list
    steps:
      - id: list-records
        entity: record
        accessProfile: operator
        claims: {principal: data-operator}
        request: {operation: list}
        expect: {outcome: success, status: 200, count: 0}
"#;

struct TestProject {
    root: PathBuf,
}

impl TestProject {
    fn asset_fixture() -> Self {
        Self::from_registry_source(asset_fixture())
    }

    fn from_registry_source(source: &[u8]) -> Self {
        let temporary_parent = std::env::current_dir().expect("current directory is available");
        let root = temporary_parent.join(format!(
            "registry-serverctl-test-{}-{}",
            std::process::id(),
            TEMPORARY_COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("test directory is created");
        fs::write(root.join("registry.yaml"), source).expect("fixture is copied");
        Self { root }
    }

    fn path(&self) -> &Path {
        &self.root
    }
}

impl Drop for TestProject {
    fn drop(&mut self) {
        if self.root.exists() {
            fs::remove_dir_all(&self.root).expect("test directory is removed");
        }
    }
}

struct RuntimePackageFixture {
    directory: TestProject,
    package: PathBuf,
    anchor: PathBuf,
    runtime_config: PathBuf,
    package_revision: String,
}

impl RuntimePackageFixture {
    fn production(bind: SocketAddr) -> Self {
        let directory = TestProject::from_registry_source(authoring_fixture());
        let signing = generate_private_jwk(GeneratedKeyAlgorithm::Es384)
            .expect("production package signing key generates");
        let module_bytes = package_module_bytes();
        let module = parse_module_json(&module_bytes).expect("package module parses");
        let project_bytes = package_project_bytes(&module_digest(&module));
        let key_id = signing.public().kid.expect("generated key has an id");
        let prepared =
            prepare_package(PackageBuildRequest {
                environment: "production".to_owned(),
                instance_id: PACKAGE_INSTANCE.to_owned(),
                database_id: PACKAGE_DATABASE.to_owned(),
                sequence: 1,
                prior_revision: None,
                compiler_source_revision: PACKAGE_SOURCE_REVISION.to_owned(),
                schema_fingerprint:
                    "sha256:2222222222222222222222222222222222222222222222222222222222222222"
                        .to_owned(),
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
                }],
                fixture_journeys: PackageSourceFile {
                    path: "tests/journeys.yaml".to_owned(),
                    bytes: PACKAGE_FIXTURE_JOURNEYS.to_vec(),
                },
                migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
            })
            .expect("package prepares");
        validate_fixture_journeys(PACKAGE_FIXTURE_JOURNEYS, prepared.registry())
            .expect("package fixture journeys resolve against the packaged registry");
        let signature = sign(prepared.canonical_signed_bytes(), &signing)
            .expect("package canonical bytes sign");
        let package = directory.path().join("package");
        let package_revision = prepared.package_revision().to_owned();
        prepared
            .publish_to_directory(
                &package,
                vec![PackageSignature {
                    key_id: key_id.clone(),
                    signature_hex: hex(&signature),
                }],
            )
            .expect("package publishes");
        let anchor = directory.path().join("trust.json");
        write_anchor(&anchor, &signing);
        let runtime_config =
            write_runtime_config(directory.path(), &package, &anchor, &package_revision, bind);
        Self {
            directory,
            package,
            anchor,
            runtime_config,
            package_revision,
        }
    }

    fn variant(&self, name: &str, from: &str, to: &str) -> PathBuf {
        let target = self.directory.path().join(format!("{name}.yaml"));
        let source = fs::read_to_string(&self.runtime_config).expect("runtime config reads");
        assert!(source.contains(from), "runtime replacement is exact");
        fs::write(&target, source.replacen(from, to, 1)).expect("runtime variant writes");
        target
    }
}

fn asset_fixture() -> &'static [u8] {
    include_bytes!(
        "../../../products/registry-server/acceptance/asset-site-placement/registry.yaml"
    )
}

fn authoring_fixture() -> &'static [u8] {
    br#"apiVersion: registry.registrystack.org/v1alpha1
kind: RegistryProject
registry:
  id: cli-authoring-fixture
  version: 1
  defaultLanguage: en
entities:
  - id: record
    route: records
    mutationMode: create_only
    fields:
      - id: code
        type: string
        maxLength: 64
        classification: internal
"#
}

fn packaging_project() -> (TestProject, PrivateJwk, String) {
    let signing = generate_private_jwk(GeneratedKeyAlgorithm::Es384)
        .expect("production package signing key generates");
    let key_id = signing
        .public()
        .kid
        .clone()
        .expect("generated key has an id");
    let module_bytes = package_module_bytes();
    let module = parse_module_json(&module_bytes).expect("package module parses");
    let project =
        TestProject::from_registry_source(&package_project_bytes(&module_digest(&module)));
    let module_directory = project.path().join("modules/core");
    fs::create_dir_all(&module_directory).expect("package module directory creates");
    fs::write(module_directory.join("module.yaml"), module_bytes).expect("package module writes");
    let tests_directory = project.path().join("tests");
    fs::create_dir(&tests_directory).expect("package tests directory creates");
    fs::write(
        tests_directory.join("journeys.yaml"),
        PACKAGE_FIXTURE_JOURNEYS,
    )
    .expect("package fixture journeys write");
    (project, signing, key_id)
}

fn prepare_packaging_candidate(
    project: &TestProject,
    database_id: &str,
    schema_fingerprint: &str,
    signature_threshold: u16,
    signature_key_ids: Vec<String>,
) -> PreparedPackage {
    let project_bytes =
        fs::read(project.path().join("registry.yaml")).expect("package project reads");
    let project_source = parse_project_yaml(&project_bytes).expect("package project parses");
    let identity = project_source
        .package
        .as_ref()
        .expect("package identity exists");
    let module_bytes =
        fs::read(project.path().join("modules/core/module.yaml")).expect("package module reads");
    let journey_bytes =
        fs::read(project.path().join(FIXTURE_JOURNEYS_PATH)).expect("package journey reads");
    prepare_package(PackageBuildRequest {
        environment: identity.environment.clone(),
        instance_id: identity.instance_id.clone(),
        database_id: database_id.to_owned(),
        sequence: identity.sequence,
        prior_revision: None,
        compiler_source_revision: identity.source_revision.clone(),
        schema_fingerprint: schema_fingerprint.to_owned(),
        signature_policy: SignaturePolicy {
            threshold: signature_threshold,
            key_ids: signature_key_ids,
        },
        project: PackageSourceFile {
            path: "source/registry.yaml".to_owned(),
            bytes: project_bytes,
        },
        modules: vec![PackageModuleSource {
            id: "core".to_owned(),
            path: "source/modules/core/module.yaml".to_owned(),
            bytes: module_bytes,
        }],
        fixture_journeys: PackageSourceFile {
            path: FIXTURE_JOURNEYS_PATH.to_owned(),
            bytes: journey_bytes,
        },
        migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
    })
    .expect("package candidate prepares")
}

/// Test-only raw construction of the receipt shape emitted by a successful
/// rehearsal. Public production code only validates receipts and deliberately
/// exposes no unchecked constructor.
fn schema_test_receipt_bytes(prepared: &PreparedPackage, journey_ids: &[&str]) -> Vec<u8> {
    let manifest = prepared.manifest();
    let files = prepared.file_bytes();
    let project_bytes = files
        .get(&manifest.sources.project)
        .expect("captured project exists");
    let project = parse_project_yaml(project_bytes).expect("captured project parses");
    let project_identity = project.package.expect("captured project identity exists");
    let journeys = files
        .get(FIXTURE_JOURNEYS_PATH)
        .expect("captured journeys exist");
    let migration_plan = files
        .get("database/migration-plan.json")
        .expect("captured migration plan exists");
    let mut source_closure = Sha256::new();
    source_closure.update(b"registry-server-schema-test-source-closure-v2\0");
    digest_part(
        &mut source_closure,
        manifest.sources.project.as_bytes(),
        project_bytes,
    );
    for module in &manifest.sources.modules {
        let bytes = files.get(&module.path).expect("captured module exists");
        digest_part(
            &mut source_closure,
            module.id.as_bytes(),
            module.path.as_bytes(),
        );
        digest_part(&mut source_closure, module.path.as_bytes(), bytes);
    }
    digest_part(
        &mut source_closure,
        FIXTURE_JOURNEYS_PATH.as_bytes(),
        journeys,
    );
    let mut receipt = json!({
        "apiVersion": "registry.registrystack.org/server-schema-test-receipt/v1",
        "kind": "SchemaTestReceipt",
        "registryRevision": prepared.registry().revision(),
        "projectSourceRevision": project_identity.source_revision,
        "compilerSourceRevision": manifest.compiler.source_revision,
        "environment": manifest.environment,
        "instanceId": manifest.instance_id,
        "databaseId": manifest.database_id,
        "sequence": manifest.sequence,
        "candidatePackageRevision": manifest.package_revision,
        "sourceClosureSha256": prefixed_digest(source_closure.finalize().as_slice()),
        "migrationPlanSha256": sha256_prefixed(migration_plan),
        "signingInputSha256": sha256_prefixed(prepared.canonical_signed_bytes()),
        "postgresMajor": 16,
        "targetManagedSchemaFingerprint": manifest.schema_fingerprint,
        "successfulJourneyIds": journey_ids,
        "journeyFileSha256": sha256_prefixed(journeys),
    });
    if let Some(prior) = &manifest.prior_revision {
        receipt
            .as_object_mut()
            .expect("receipt is an object")
            .insert("priorPackageRevision".to_owned(), json!(prior));
    }
    let bytes = canonicalize_json(&receipt).expect("test receipt canonicalizes");
    let suite = validate_fixture_journeys(journeys, prepared.registry())
        .expect("packaged journeys validate");
    validate_schema_test_receipt_for_package(&bytes, prepared, &suite)
        .expect("test receipt binds to candidate");
    bytes
}

fn digest_part(digest: &mut Sha256, name: &[u8], bytes: &[u8]) {
    digest.update((name.len() as u64).to_be_bytes());
    digest.update(name);
    digest.update((bytes.len() as u64).to_be_bytes());
    digest.update(bytes);
}

fn sha256_prefixed(bytes: &[u8]) -> String {
    prefixed_digest(Sha256::digest(bytes).as_slice())
}

fn prefixed_digest(bytes: &[u8]) -> String {
    format!("sha256:{}", hex(bytes))
}

fn registry_serverctl(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_registry-serverctl"))
        .args(arguments)
        .output()
        .expect("registry-serverctl starts")
}

fn package_candidate_command(
    project: &TestProject,
    database_id: &str,
    schema_fingerprint: &str,
    signature_threshold: u16,
    signature_key_ids: &[String],
    receipt: &Path,
    output: &Path,
) -> Output {
    let mut arguments = vec![
        "--format".to_owned(),
        "json".to_owned(),
        "package".to_owned(),
        path(project.path()).to_owned(),
        "--database-id".to_owned(),
        database_id.to_owned(),
        "--schema-fingerprint".to_owned(),
        schema_fingerprint.to_owned(),
        "--signature-threshold".to_owned(),
        signature_threshold.to_string(),
    ];
    for key_id in signature_key_ids {
        arguments.push(format!("--signature-key-id={key_id}"));
    }
    arguments.extend([
        "--test-receipt".to_owned(),
        path(receipt).to_owned(),
        "--output".to_owned(),
        path(output).to_owned(),
    ]);
    let arguments = arguments.iter().map(String::as_str).collect::<Vec<_>>();
    registry_serverctl(&arguments)
}

fn test_candidate_command(
    project: &TestProject,
    signature_threshold: u16,
    signature_key_ids: &[String],
    runtime_config: &Path,
    credentials: &Path,
    output: &Path,
) -> Output {
    test_candidate_command_for_database(
        project,
        PACKAGE_DATABASE,
        signature_threshold,
        signature_key_ids,
        runtime_config,
        credentials,
        output,
    )
}

fn test_candidate_command_for_database(
    project: &TestProject,
    database_id: &str,
    signature_threshold: u16,
    signature_key_ids: &[String],
    runtime_config: &Path,
    credentials: &Path,
    output: &Path,
) -> Output {
    let mut arguments = vec![
        "--format".to_owned(),
        "json".to_owned(),
        "test".to_owned(),
        path(project.path()).to_owned(),
        "--database-id".to_owned(),
        database_id.to_owned(),
        "--signature-threshold".to_owned(),
        signature_threshold.to_string(),
    ];
    for key_id in signature_key_ids {
        arguments.push(format!("--signature-key-id={key_id}"));
    }
    arguments.extend([
        "--runtime-config".to_owned(),
        path(runtime_config).to_owned(),
        "--credentials".to_owned(),
        path(credentials).to_owned(),
        "--output".to_owned(),
        path(output).to_owned(),
    ]);
    let arguments = arguments.iter().map(String::as_str).collect::<Vec<_>>();
    registry_serverctl(&arguments)
}

fn json_stdout(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).expect("command stdout is JSON")
}

fn assert_tool_diagnostic(diagnostic: &Value, artifact: &str, suggested_action: &str) {
    let keys = diagnostic
        .as_object()
        .expect("diagnostic is an object")
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        keys,
        std::collections::BTreeSet::from([
            "artifact",
            "code",
            "message",
            "path",
            "severity",
            "suggestedAction",
        ])
    );
    assert_eq!(diagnostic["artifact"], artifact);
    assert_eq!(diagnostic["suggestedAction"], suggested_action);
}

#[test]
fn authored_project_findings_use_the_tool_diagnostic_schema() {
    let project = TestProject::from_registry_source(authoring_fixture());
    let output = registry_serverctl(&[
        "--format",
        "json",
        "check",
        project.path().to_str().expect("path is UTF-8"),
    ]);

    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty());
    let report = json_stdout(&output);
    assert_eq!(report["ok"], true);
    assert_eq!(report["command"], "check");
    assert_eq!(report["profile"], "authoring");
    assert!(report["findings"]
        .as_array()
        .expect("findings is an array")
        .iter()
        .any(|finding| finding["code"] == "package.identity.missing"));
    for finding in report["findings"].as_array().expect("findings is an array") {
        assert_tool_diagnostic(finding, "registry_project", "review_authoring_finding");
    }
}

#[test]
fn production_profile_refuses_missing_package_closure() {
    let project = TestProject::from_registry_source(authoring_fixture());
    let output = registry_serverctl(&[
        "--format",
        "json",
        "check",
        project.path().to_str().expect("path is UTF-8"),
        "--production",
    ]);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let report = json_stdout(&output);
    assert_eq!(report["ok"], false);
    let codes: Vec<_> = report["diagnostics"]
        .as_array()
        .expect("diagnostics is an array")
        .iter()
        .filter_map(|diagnostic| diagnostic["code"].as_str())
        .collect();
    assert!(codes.contains(&"package.identity.required"));
    for diagnostic in report["diagnostics"]
        .as_array()
        .expect("diagnostics is an array")
    {
        assert_tool_diagnostic(diagnostic, "registry_project", "correct_authoring_source");
    }
}

#[test]
fn generation_is_byte_stable_and_reports_the_exact_artifact_inventory() {
    let project = TestProject::asset_fixture();
    let first = project.path().join("first-output");
    let second = project.path().join("second-output");
    let first_output = registry_serverctl(&[
        "--format",
        "json",
        "generate",
        "schemas",
        project.path().to_str().expect("path is UTF-8"),
        "--output",
        first.to_str().expect("path is UTF-8"),
    ]);
    let second_output = registry_serverctl(&[
        "--format",
        "json",
        "generate",
        "schemas",
        project.path().to_str().expect("path is UTF-8"),
        "--output",
        second.to_str().expect("path is UTF-8"),
    ]);

    assert!(first_output.status.success(), "{first_output:?}");
    assert!(second_output.status.success(), "{second_output:?}");
    let first_tree = tree(&first);
    assert_eq!(first_tree, tree(&second));

    let report = json_stdout(&first_output);
    let paths: Vec<_> = report["artifacts"]
        .as_array()
        .expect("artifacts is an array")
        .iter()
        .filter_map(|artifact| artifact["path"].as_str())
        .collect();
    assert_eq!(
        paths,
        first_tree.keys().map(String::as_str).collect::<Vec<_>>()
    );
}

#[test]
fn init_creates_a_domain_neutral_project_that_checks_immediately() {
    let project = TestProject::asset_fixture();
    let destination = project.path().join("initialized");

    let output = registry_serverctl(&[
        "--format",
        "json",
        "init",
        destination.to_str().expect("path is UTF-8"),
    ]);

    assert!(output.status.success(), "{output:?}");
    assert!(destination.join("registry.yaml").is_file());
    assert!(destination.join("modules/core/module.yaml").is_file());
    assert!(destination.join("tests/journeys.yaml").is_file());
    let journeys = fs::read_to_string(destination.join("tests/journeys.yaml"))
        .expect("initialized fixture journeys read");
    assert!(journeys.contains("entity: record"));
    assert!(journeys.contains("accessProfile: operator"));
    assert!(journeys.contains("purpose: registry-operations"));
    assert!(!journeys.contains("token"));
    let initialized_project = parse_project_yaml(
        &fs::read(destination.join("registry.yaml")).expect("initialized project reads"),
    )
    .expect("initialized project parses");
    let initialized_module = parse_module_yaml(
        &fs::read(destination.join("modules/core/module.yaml")).expect("initialized module reads"),
    )
    .expect("initialized module parses");
    let compiled = compile_project(
        &initialized_project,
        &[initialized_module],
        CompileProfile::Authoring,
    )
    .expect("initialized project compiles");
    validate_fixture_journeys(journeys.as_bytes(), &compiled)
        .expect("initialized fixture journeys resolve against the compiled project");
    let report = json_stdout(&output);
    assert_eq!(report["ok"], true);
    assert_eq!(report["command"], "init");
    assert!(report["findings"]
        .as_array()
        .expect("findings is an array")
        .iter()
        .any(|finding| finding["code"] == "package.identity.missing"));

    let check = registry_serverctl(&[
        "--format",
        "json",
        "check",
        destination.to_str().expect("path is UTF-8"),
    ]);
    assert!(check.status.success(), "{check:?}");
    assert_eq!(json_stdout(&check)["ok"], true);
}

#[test]
fn init_and_generate_missing_output_parents_have_exact_logical_diagnostics() {
    const PATH_CANARY: &str = "registry-serverctl-missing-parent-canary";

    let project = TestProject::asset_fixture();
    let missing_parent = project.path().join(PATH_CANARY);
    let init_destination = missing_parent.join("initialized");
    let init_output = registry_serverctl(&[
        "--format",
        "json",
        "init",
        init_destination.to_str().expect("path is UTF-8"),
    ]);
    assert_eq!(init_output.status.code(), Some(1));
    assert!(init_output.stderr.is_empty());
    assert_eq!(
        json_stdout(&init_output),
        json!({
            "ok": false,
            "command": "init",
            "diagnostics": [{
                "severity": "error",
                "code": "output.parent.invalid",
                "artifact": "project_initialization",
                "path": "output.parent",
                "message": "the output parent directory is not available",
                "suggestedAction": "choose_safe_output_directory"
            }]
        })
    );
    assert!(!String::from_utf8_lossy(&init_output.stdout).contains(PATH_CANARY));

    let generate_destination = missing_parent.join("generated");
    let generate_output = registry_serverctl(&[
        "--format",
        "json",
        "generate",
        "openapi",
        project.path().to_str().expect("path is UTF-8"),
        "--output",
        generate_destination.to_str().expect("path is UTF-8"),
    ]);
    assert_eq!(generate_output.status.code(), Some(1));
    assert!(generate_output.stderr.is_empty());
    assert_eq!(
        json_stdout(&generate_output),
        json!({
            "ok": false,
            "command": "generate",
            "diagnostics": [{
                "severity": "error",
                "code": "output.parent.invalid",
                "artifact": "generated_artifacts",
                "path": "output.parent",
                "message": "the output parent directory is not available",
                "suggestedAction": "retry_artifact_generation"
            }]
        })
    );
    assert!(!String::from_utf8_lossy(&generate_output.stdout).contains(PATH_CANARY));
}

#[test]
fn generate_selectors_publish_only_selected_artifacts() {
    let project = TestProject::asset_fixture();
    let output_root = project.path().join("selected-output");

    let output = registry_serverctl(&[
        "--format",
        "json",
        "generate",
        "openapi",
        project.path().to_str().expect("path is UTF-8"),
        "--output",
        output_root.to_str().expect("path is UTF-8"),
    ]);

    assert!(output.status.success(), "{output:?}");
    assert!(output_root.join("generated/openapi.json").is_file());
    assert!(!output_root.join("generated/postgres/schema.sql").exists());
    assert_eq!(
        tree(&output_root).keys().cloned().collect::<Vec<_>>(),
        vec!["generated/openapi.json"]
    );
    let report = json_stdout(&output);
    let artifacts = report["artifacts"]
        .as_array()
        .expect("artifacts is an array");
    assert_eq!(artifacts.len(), 1);
    assert_eq!(artifacts[0]["path"], "generated/openapi.json");
}

#[test]
fn manifest_selector_requires_the_compiled_manifest_projection() {
    let project = TestProject::asset_fixture();
    let output_root = project.path().join("manifest-output");

    let output = registry_serverctl(&[
        "--format",
        "json",
        "generate",
        "manifest",
        project.path().to_str().expect("path is UTF-8"),
        "--output",
        output_root.to_str().expect("path is UTF-8"),
    ]);

    assert!(output.status.success(), "{output:?}");
    assert!(output_root
        .join("generated/manifest/registry-manifest.json")
        .is_file());
    let report = json_stdout(&output);
    assert_eq!(
        report["artifacts"][0]["path"],
        "generated/manifest/registry-manifest.json"
    );
}

#[test]
fn metadata_selector_publishes_only_registry_metadata() {
    let project = TestProject::asset_fixture();
    let output_root = project.path().join("metadata-output");

    let output = registry_serverctl(&[
        "--format",
        "json",
        "generate",
        "metadata",
        project.path().to_str().expect("path is UTF-8"),
        "--output",
        output_root.to_str().expect("path is UTF-8"),
    ]);

    assert!(output.status.success(), "{output:?}");
    assert!(output_root
        .join("generated/metadata/registry.json")
        .is_file());
    assert!(!output_root.join("generated/openapi.json").exists());
    assert!(!output_root.join("generated/postgres/schema.sql").exists());
    assert_eq!(
        tree(&output_root).keys().cloned().collect::<Vec<_>>(),
        vec!["generated/metadata/registry.json"]
    );
    let report = json_stdout(&output);
    let artifacts = report["artifacts"]
        .as_array()
        .expect("artifacts is an array");
    assert_eq!(artifacts.len(), 1);
    assert_eq!(artifacts[0]["path"], "generated/metadata/registry.json");
}

#[test]
fn explain_reports_are_derived_from_compiled_inventories() {
    let project = TestProject::asset_fixture();

    let routes = registry_serverctl(&[
        "--format",
        "json",
        "explain",
        "routes",
        project.path().to_str().expect("path is UTF-8"),
    ]);
    let access = registry_serverctl(&[
        "--format",
        "json",
        "explain",
        "access",
        project.path().to_str().expect("path is UTF-8"),
    ]);
    let model = registry_serverctl(&[
        "--format",
        "json",
        "explain",
        "model",
        project.path().to_str().expect("path is UTF-8"),
    ]);

    assert!(routes.status.success(), "{routes:?}");
    assert!(access.status.success(), "{access:?}");
    assert!(model.status.success(), "{model:?}");
    assert_eq!(
        json_stdout(&routes)["explanation"]["routes"][0]["entityId"],
        "asset-item"
    );
    assert_eq!(
        json_stdout(&access)["explanation"]["entries"][0]["entityId"],
        "asset-item"
    );
    assert_eq!(
        json_stdout(&model)["explanation"]["registryId"],
        "asset-site-placement"
    );
}

#[test]
fn explain_events_is_empty_for_outbox_only_and_deterministic_for_webhooks() {
    let no_events = TestProject::asset_fixture();
    let empty = registry_serverctl(&[
        "--format",
        "json",
        "explain",
        "events",
        no_events.path().to_str().expect("path is UTF-8"),
    ]);
    assert!(empty.status.success(), "{empty:?}");
    assert_eq!(json_stdout(&empty)["explanation"]["deliveries"], json!([]));

    let outbox_only = TestProject::from_registry_source(
        br#"apiVersion: registry.registrystack.org/v1alpha1
kind: RegistryProject
registry:
  id: event-explain-outbox
  version: 1
  defaultLanguage: en
entities:
  - id: case
    route: cases
    mutationMode: mutable
    fields:
      - id: label
        type: string
        maxLength: 64
        classification: public
    events:
      - id: case-created
        trigger: created
        projection: [label]
"#,
    );
    let outbox = registry_serverctl(&[
        "--format",
        "json",
        "explain",
        "events",
        outbox_only.path().to_str().expect("path is UTF-8"),
    ]);
    assert!(outbox.status.success(), "{outbox:?}");
    assert_eq!(json_stdout(&outbox)["explanation"]["deliveries"], json!([]));

    let webhook = TestProject::from_registry_source(
        br#"apiVersion: registry.registrystack.org/v1alpha1
kind: RegistryProject
registry:
  id: event-explain-webhook
  version: 1
  defaultLanguage: en
entities:
  - id: case
    route: cases
    mutationMode: mutable
    fields:
      - id: label
        type: string
        maxLength: 64
        classification: public
    events:
      - id: case-created
        trigger: created
        projection: [label]
        webhook:
          destinationId: case-operations
          classificationCeiling: public
          authenticationProfile: hmac_sha256_v1
          delivery:
            attemptTimeoutMs: 5000
            initialBackoffMs: 250
            maximumBackoffMs: 2000
            maximumAttempts: 5
            deadLetter: required
            operatorReplay: false
"#,
    );
    let arguments = [
        "--format",
        "json",
        "explain",
        "events",
        webhook.path().to_str().expect("path is UTF-8"),
    ];
    let first = registry_serverctl(&arguments);
    let second = registry_serverctl(&arguments);
    assert!(first.status.success(), "{first:?}");
    assert_eq!(
        first.stdout, second.stdout,
        "event explanation is byte stable"
    );
    let report = json_stdout(&first);
    assert_eq!(
        report["explanation"]["deliveries"][0]["id"],
        "events.case.case-created.webhook"
    );
    assert_eq!(
        report["explanation"]["deliveries"][0]["destinationId"],
        "case-operations"
    );
    let delivery_keys = report["explanation"]["deliveries"][0]
        .as_object()
        .expect("delivery is an object")
        .keys()
        .map(String::as_str)
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        delivery_keys,
        std::collections::BTreeSet::from([
            "attemptTimeoutMs",
            "authenticationProfile",
            "classificationCeiling",
            "deadLetter",
            "deliveryMode",
            "destinationId",
            "entityId",
            "eventId",
            "exponentialBackoffMultiplier",
            "id",
            "initialBackoffMs",
            "maximumAttempts",
            "maximumBackoffMs",
            "maximumPayloadBytes",
            "operatorReplay",
            "projectionFields",
            "retryDelaysMs",
            "trigger",
        ])
    );
    let rendered = String::from_utf8(first.stdout).expect("report is UTF-8");
    for forbidden in [
        "http://",
        "https://",
        "destinationUrl",
        "secretRef",
        "secretValue",
        "tlsCertificate",
    ] {
        assert!(!rendered.contains(forbidden));
    }
}

#[test]
fn production_package_emits_exact_signing_input_and_publishes_only_external_signatures() {
    let (project, signing, key_id) = packaging_project();
    let build = project.path().join("build");
    let fingerprint = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    let expected = prepare_packaging_candidate(
        &project,
        PACKAGE_DATABASE,
        fingerprint,
        1,
        vec![key_id.clone()],
    );
    let receipt = project.path().join("schema-test-receipt.json");
    let receipt_bytes = schema_test_receipt_bytes(&expected, &["package-record-list"]);
    fs::write(&receipt, &receipt_bytes).expect("schema-test receipt writes");
    let common = vec![
        "--format".to_owned(),
        "json".to_owned(),
        "package".to_owned(),
        path(project.path()).to_owned(),
        "--database-id".to_owned(),
        PACKAGE_DATABASE.to_owned(),
        "--schema-fingerprint".to_owned(),
        fingerprint.to_owned(),
        "--signature-threshold".to_owned(),
        "1".to_owned(),
        format!("--signature-key-id={key_id}"),
        "--test-receipt".to_owned(),
        path(&receipt).to_owned(),
        "--output".to_owned(),
        path(&build).to_owned(),
    ];
    let common_args = common.iter().map(String::as_str).collect::<Vec<_>>();

    let prepared = registry_serverctl(&common_args);
    assert!(prepared.status.success(), "{prepared:?}");
    assert!(prepared.stderr.is_empty());
    let report = json_stdout(&prepared);
    assert_eq!(report["command"], "package");
    assert_eq!(report["profile"], "production");
    assert_eq!(report["state"], "awaiting_signatures");
    assert_eq!(report["signatureThreshold"], 1);
    assert_eq!(report["providedSignatures"], 0);
    assert!(build.join("signing-input.json").is_file());
    assert_eq!(
        fs::read(build.join("schema-test-receipt.json")).expect("reviewer receipt reads"),
        receipt_bytes
    );
    assert!(!build.join("package").exists());

    let signing_input =
        fs::read(build.join("signing-input.json")).expect("canonical signing input reads");
    let signature = sign(&signing_input, &signing).expect("external signer signs exact bytes");
    let signatures = project.path().join("signatures.json");
    write_canonical(
        &signatures,
        &json!({
            "signatures": [{"keyId": key_id, "signatureHex": hex(&signature)}]
        }),
    );
    let mut final_arguments = common.clone();
    final_arguments.extend(["--signatures".to_owned(), path(&signatures).to_owned()]);
    let final_arguments = final_arguments
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>();
    let published = registry_serverctl(&final_arguments);
    assert!(published.status.success(), "{published:?}");
    assert!(published.stderr.is_empty());
    let published_report = json_stdout(&published);
    assert_eq!(published_report["state"], "published");
    assert_eq!(
        published_report["packageRevision"],
        report["packageRevision"]
    );
    assert_eq!(published_report["signingInput"], report["signingInput"]);
    assert_eq!(published_report["providedSignatures"], 1);
    assert!(build.join("package/package.json").is_file());
    assert!(!tree(&build.join("package"))
        .keys()
        .any(|entry| entry.contains("schema-test-receipt")));
    let envelope: Value = serde_json::from_slice(
        &fs::read(build.join("package/package.json")).expect("package envelope reads"),
    )
    .expect("package envelope parses");
    assert!(!envelope["signed"]["files"]
        .as_array()
        .expect("package files are an array")
        .iter()
        .any(|entry| entry["path"] == "schema-test-receipt.json"));

    let anchor = project.path().join("trust.json");
    write_anchor(&anchor, &signing);
    let runtime = write_runtime_config(
        project.path(),
        &build.join("package"),
        &anchor,
        published_report["packageRevision"].as_str().unwrap(),
        "127.0.0.1:1".parse().unwrap(),
    );
    let verified = registry_serverctl(&[
        "--format",
        "json",
        "verify",
        "--runtime-config",
        path(&runtime),
    ]);
    assert!(verified.status.success(), "{verified:?}");
    assert_eq!(
        json_stdout(&verified)["packageRevision"],
        published_report["packageRevision"]
    );

    let rendered = String::from_utf8(published.stdout).expect("package report is UTF-8");
    for forbidden in [
        path(project.path()),
        path(&signatures),
        &hex(&signature),
        PACKAGE_VALUE_CANARY,
    ] {
        assert!(!rendered.contains(forbidden));
    }
}

#[test]
fn package_refuses_missing_noncanonical_and_stale_receipts_before_output() {
    let (project, _signing, key_id) = packaging_project();
    let fingerprint = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    let prepared = prepare_packaging_candidate(
        &project,
        PACKAGE_DATABASE,
        fingerprint,
        1,
        vec![key_id.clone()],
    );
    let valid_receipt = schema_test_receipt_bytes(&prepared, &["package-record-list"]);
    let receipt = project.path().join("candidate-receipt.json");
    let key_ids = vec![key_id.clone()];

    let missing_build = project.path().join("missing-receipt-build");
    let missing = package_candidate_command(
        &project,
        PACKAGE_DATABASE,
        fingerprint,
        1,
        &key_ids,
        &receipt,
        &missing_build,
    );
    assert_eq!(missing.status.code(), Some(1), "{missing:?}");
    let missing_report = json_stdout(&missing);
    assert_eq!(
        missing_report["diagnostics"][0]["code"],
        "package.test_receipt.missing"
    );
    assert_tool_diagnostic(
        &missing_report["diagnostics"][0],
        "schema_test_receipt",
        "supply_schema_test_receipt",
    );
    assert!(!missing_build.exists());

    fs::write(&receipt, [&valid_receipt[..], b"\n"].concat()).expect("noncanonical receipt writes");
    let refused_build = project.path().join("noncanonical-receipt-build");
    let refused = package_candidate_command(
        &project,
        PACKAGE_DATABASE,
        fingerprint,
        1,
        &key_ids,
        &receipt,
        &refused_build,
    );
    assert_eq!(refused.status.code(), Some(1), "{refused:?}");
    let refused_report = json_stdout(&refused);
    assert_eq!(
        refused_report["diagnostics"][0]["code"],
        "package.test_receipt.refused"
    );
    assert_tool_diagnostic(
        &refused_report["diagnostics"][0],
        "schema_test_receipt",
        "supply_schema_test_receipt",
    );
    assert!(!refused_build.exists());

    for rendered in [
        String::from_utf8(missing.stdout).expect("missing diagnostic is UTF-8"),
        String::from_utf8(refused.stdout).expect("refused diagnostic is UTF-8"),
    ] {
        assert!(!rendered.contains(path(project.path())));
        assert!(!rendered.contains("candidate-receipt"));
        assert!(!rendered.contains(PACKAGE_DATABASE));
    }
}

#[test]
fn package_receipt_is_stale_for_every_candidate_binding_change() {
    let (project, _signing, key_id) = packaging_project();
    let fingerprint = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    let prepared = prepare_packaging_candidate(
        &project,
        PACKAGE_DATABASE,
        fingerprint,
        1,
        vec![key_id.clone()],
    );
    let receipt = project.path().join("exact-receipt.json");
    fs::write(
        &receipt,
        schema_test_receipt_bytes(&prepared, &["package-record-list"]),
    )
    .expect("schema-test receipt writes");
    let original_project =
        fs::read(project.path().join("registry.yaml")).expect("original package project reads");
    let original_module = fs::read(project.path().join("modules/core/module.yaml"))
        .expect("original package module reads");
    let original_journeys = fs::read(project.path().join(FIXTURE_JOURNEYS_PATH))
        .expect("original package journeys read");
    let original_project_text =
        String::from_utf8(original_project.clone()).expect("project is UTF-8");
    let original_module_model =
        parse_module_json(&original_module).expect("original package module parses");
    let original_module_digest = module_digest(&original_module_model);
    let alternate_signing = generate_private_jwk(GeneratedKeyAlgorithm::Es384)
        .expect("alternate signing key generates");
    let alternate_key_id = alternate_signing
        .public()
        .kid
        .expect("alternate signing key has an id");

    let altered_module = String::from_utf8(original_module.clone())
        .expect("module is UTF-8")
        .replace("\"maxLength\":16", "\"maxLength\":17")
        .into_bytes();
    let altered_module_model =
        parse_module_json(&altered_module).expect("altered package module parses");
    let altered_module_digest = module_digest(&altered_module_model);
    let cases = [
        (
            "database",
            original_project.clone(),
            original_module.clone(),
            original_journeys.clone(),
            "alternate-database".to_owned(),
            fingerprint.to_owned(),
            vec![key_id.clone()],
        ),
        (
            "fingerprint",
            original_project.clone(),
            original_module.clone(),
            original_journeys.clone(),
            PACKAGE_DATABASE.to_owned(),
            "sha256:4444444444444444444444444444444444444444444444444444444444444444".to_owned(),
            vec![key_id.clone()],
        ),
        (
            "signature-policy",
            original_project.clone(),
            original_module.clone(),
            original_journeys.clone(),
            PACKAGE_DATABASE.to_owned(),
            fingerprint.to_owned(),
            vec![alternate_key_id],
        ),
        (
            "project",
            original_project_text
                .replace(PACKAGE_SOURCE_REVISION, "alternate-source")
                .into_bytes(),
            original_module.clone(),
            original_journeys.clone(),
            PACKAGE_DATABASE.to_owned(),
            fingerprint.to_owned(),
            vec![key_id.clone()],
        ),
        (
            "module",
            original_project_text
                .replace(&original_module_digest, &altered_module_digest)
                .into_bytes(),
            altered_module,
            original_journeys.clone(),
            PACKAGE_DATABASE.to_owned(),
            fingerprint.to_owned(),
            vec![key_id.clone()],
        ),
        (
            "environment",
            original_project_text
                .replace(
                    "\"environment\":\"production\"",
                    "\"environment\":\"pilot\"",
                )
                .into_bytes(),
            original_module.clone(),
            original_journeys.clone(),
            PACKAGE_DATABASE.to_owned(),
            fingerprint.to_owned(),
            vec![key_id.clone()],
        ),
        (
            "instance",
            original_project_text
                .replace(PACKAGE_INSTANCE, "alternate-instance")
                .into_bytes(),
            original_module.clone(),
            original_journeys.clone(),
            PACKAGE_DATABASE.to_owned(),
            fingerprint.to_owned(),
            vec![key_id.clone()],
        ),
        (
            "journey",
            original_project.clone(),
            original_module.clone(),
            String::from_utf8(original_journeys.clone())
                .expect("journeys are UTF-8")
                .replace("package-record-list", "package-record-list-alternate")
                .into_bytes(),
            PACKAGE_DATABASE.to_owned(),
            fingerprint.to_owned(),
            vec![key_id.clone()],
        ),
    ];

    for (name, project_bytes, module_bytes, journeys, database, fingerprint, keys) in cases {
        fs::write(project.path().join("registry.yaml"), project_bytes)
            .expect("altered project writes");
        fs::write(
            project.path().join("modules/core/module.yaml"),
            module_bytes,
        )
        .expect("altered module writes");
        fs::write(project.path().join(FIXTURE_JOURNEYS_PATH), journeys)
            .expect("altered journeys write");
        let build = project.path().join(format!("stale-{name}-build"));
        let output = package_candidate_command(
            &project,
            &database,
            &fingerprint,
            1,
            &keys,
            &receipt,
            &build,
        );
        assert_eq!(output.status.code(), Some(1), "{name}: {output:?}");
        let report = json_stdout(&output);
        assert_eq!(
            report["diagnostics"][0]["code"], "package.test_receipt.refused",
            "{name}"
        );
        assert!(!build.exists(), "{name}");
        let rendered = String::from_utf8(output.stdout).expect("diagnostic is UTF-8");
        assert!(!rendered.contains(path(project.path())), "{name}");
    }

    fs::write(
        project.path().join("registry.yaml"),
        original_project_text
            .replace("\"sequence\":1", "\"sequence\":2")
            .into_bytes(),
    )
    .expect("successor project writes");
    fs::write(
        project.path().join("modules/core/module.yaml"),
        &original_module,
    )
    .expect("original module restores");
    fs::write(
        project.path().join(FIXTURE_JOURNEYS_PATH),
        &original_journeys,
    )
    .expect("original journeys restore");
    let baseline = RuntimePackageFixture::production("127.0.0.1:1".parse().unwrap());
    let sequence_build = project.path().join("stale-sequence-build");
    let signature_key_arg = format!("--signature-key-id={key_id}");
    let sequence = registry_serverctl(&[
        "--format",
        "json",
        "package",
        path(project.path()),
        "--database-id",
        PACKAGE_DATABASE,
        "--schema-fingerprint",
        fingerprint,
        "--signature-threshold",
        "1",
        &signature_key_arg,
        "--baseline-runtime-config",
        path(&baseline.runtime_config),
        "--test-receipt",
        path(&receipt),
        "--output",
        path(&sequence_build),
    ]);
    assert_eq!(sequence.status.code(), Some(1), "{sequence:?}");
    assert_eq!(
        json_stdout(&sequence)["diagnostics"][0]["code"],
        "package.test_receipt.refused"
    );
    assert!(!sequence_build.exists());
}

#[test]
fn package_resume_requires_the_exact_receipt_evidence() {
    let (project, _signing, key_id) = packaging_project();
    let fingerprint = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    let prepared = prepare_packaging_candidate(
        &project,
        PACKAGE_DATABASE,
        fingerprint,
        1,
        vec![key_id.clone()],
    );
    let receipt = project.path().join("resume-receipt.json");
    let receipt_bytes = schema_test_receipt_bytes(&prepared, &["package-record-list"]);
    fs::write(&receipt, &receipt_bytes).expect("schema-test receipt writes");
    let build = project.path().join("resume-build");
    let key_ids = vec![key_id];

    let first = package_candidate_command(
        &project,
        PACKAGE_DATABASE,
        fingerprint,
        1,
        &key_ids,
        &receipt,
        &build,
    );
    assert!(first.status.success(), "{first:?}");
    assert!(!build.join("package").exists());

    fs::remove_file(build.join("schema-test-receipt.json"))
        .expect("build receipt evidence removes");
    let missing = package_candidate_command(
        &project,
        PACKAGE_DATABASE,
        fingerprint,
        1,
        &key_ids,
        &receipt,
        &build,
    );
    assert_eq!(missing.status.code(), Some(1), "{missing:?}");
    assert_eq!(
        json_stdout(&missing)["diagnostics"][0]["code"],
        "package.test_receipt.refused"
    );
    assert!(!build.join("package").exists());

    fs::write(build.join("schema-test-receipt.json"), b"substituted")
        .expect("substituted receipt evidence writes");
    let substituted = package_candidate_command(
        &project,
        PACKAGE_DATABASE,
        fingerprint,
        1,
        &key_ids,
        &receipt,
        &build,
    );
    assert_eq!(substituted.status.code(), Some(1), "{substituted:?}");
    assert_eq!(
        json_stdout(&substituted)["diagnostics"][0]["code"],
        "package.test_receipt.refused"
    );
    assert!(!build.join("package").exists());

    fs::write(build.join("schema-test-receipt.json"), receipt_bytes)
        .expect("exact receipt evidence restores");
    let resumed = package_candidate_command(
        &project,
        PACKAGE_DATABASE,
        fingerprint,
        1,
        &key_ids,
        &receipt,
        &build,
    );
    assert!(resumed.status.success(), "{resumed:?}");
    assert_eq!(json_stdout(&resumed)["state"], "awaiting_signatures");
}

#[test]
fn local_package_requires_a_receipt_and_publishes_without_external_signatures() {
    let (project, _signing, _key_id) = packaging_project();
    let project_path = project.path().join("registry.yaml");
    let local_source = String::from_utf8(fs::read(&project_path).expect("project reads"))
        .expect("project is UTF-8")
        .replace(
            "\"environment\":\"production\"",
            "\"environment\":\"local\"",
        );
    fs::write(&project_path, local_source).expect("local project writes");
    let fingerprint = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    let prepared = prepare_packaging_candidate(&project, PACKAGE_DATABASE, fingerprint, 0, vec![]);
    let receipt = project.path().join("local-receipt.json");
    let receipt_bytes = schema_test_receipt_bytes(&prepared, &["package-record-list"]);
    fs::write(&receipt, &receipt_bytes).expect("local receipt writes");
    let build = project.path().join("local-build");

    let output = package_candidate_command(
        &project,
        PACKAGE_DATABASE,
        fingerprint,
        0,
        &[],
        &receipt,
        &build,
    );
    assert!(output.status.success(), "{output:?}");
    assert_eq!(json_stdout(&output)["state"], "published");
    assert_eq!(
        fs::read(build.join("schema-test-receipt.json")).expect("reviewer receipt reads"),
        receipt_bytes
    );
    assert!(build.join("package/package.json").is_file());
    assert!(!tree(&build.join("package"))
        .keys()
        .any(|entry| entry.contains("schema-test-receipt")));
}

#[test]
fn test_help_requires_test_inputs_and_exposes_no_package_or_apply_authority() {
    let help = registry_serverctl(&["test", "--help"]);
    assert!(help.status.success(), "{help:?}");
    let rendered = String::from_utf8(help.stdout).expect("help is UTF-8");
    for required in [
        "--runtime-config",
        "--credentials",
        "--output",
        "--database-id",
    ] {
        assert!(rendered.contains(required), "help omits {required}");
    }
    for forbidden in [
        "--test-receipt",
        "--signatures",
        "--schema-fingerprint",
        "--package",
        "--initial",
        "--backup",
    ] {
        assert!(!rendered.contains(forbidden), "help exposes {forbidden}");
    }

    let missing = registry_serverctl(&["--format", "json", "test"]);
    assert_eq!(missing.status.code(), Some(2), "{missing:?}");
    assert_eq!(
        json_stdout(&missing)["diagnostics"][0]["code"],
        "usage.invalid"
    );

    let project = TestProject::from_registry_source(authoring_fixture());
    let rejected_schema_fingerprint = registry_serverctl(&[
        "--format",
        "json",
        "test",
        path(project.path()),
        "--database-id",
        PACKAGE_DATABASE,
        "--schema-fingerprint",
        "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        "--runtime-config",
        path(&project.path().join("runtime.yaml")),
        "--credentials",
        path(&project.path().join("credentials.yaml")),
        "--output",
        path(&project.path().join("receipt.json")),
    ]);
    assert_eq!(rejected_schema_fingerprint.status.code(), Some(2));
    assert_eq!(
        json_stdout(&rejected_schema_fingerprint)["diagnostics"][0]["code"],
        "usage.invalid"
    );

    let package_requires_schema_fingerprint = registry_serverctl(&[
        "--format",
        "json",
        "package",
        path(project.path()),
        "--database-id",
        PACKAGE_DATABASE,
        "--test-receipt",
        path(&project.path().join("receipt.json")),
        "--output",
        path(&project.path().join("build")),
    ]);
    assert_eq!(package_requires_schema_fingerprint.status.code(), Some(2));
    assert_eq!(
        json_stdout(&package_requires_schema_fingerprint)["diagnostics"][0]["code"],
        "usage.invalid"
    );
}

#[test]
fn test_credentials_are_strict_secret_refs_and_preflight_before_database() {
    let (project, _signing, key_id) = packaging_project();
    let runtime = test_runtime_config(&project);
    write_test_secret(&project, "operator-token", b"aaa.bbb.ccc");
    let key_ids = vec![key_id.clone()];

    let cases = [
        (
            "duplicate-field",
            r#"apiVersion: registry.registrystack.org/server-schema-test-credentials/v1
apiVersion: registry.registrystack.org/server-schema-test-credentials/v1
kind: SchemaTestCredentials
bindings: []
"#
            .to_owned(),
        ),
        (
            "unknown-field",
            r#"apiVersion: registry.registrystack.org/server-schema-test-credentials/v1
kind: SchemaTestCredentials
bindings: []
literal: aaa.bbb.ccc
"#
            .to_owned(),
        ),
        (
            "literal-token",
            credential_source("type: bearer\n      token: aaa.bbb.ccc\n"),
        ),
        ("missing-token-ref", credential_source("type: bearer\n")),
        (
            "extra-token-ref",
            credential_source("type: anonymous\n      tokenRef: secret:file/operator-token\n"),
        ),
        (
            "wrong-discriminator",
            credential_source("mode: bearer\n      tokenRef: secret:file/operator-token\n"),
        ),
        (
            "literal-ref",
            credential_source("type: bearer\n      tokenRef: aaa.bbb.ccc\n"),
        ),
        (
            "unknown-provider",
            credential_source("type: bearer\n      tokenRef: secret:literal/operator-token\n"),
        ),
        (
            "missing-coverage",
            r#"apiVersion: registry.registrystack.org/server-schema-test-credentials/v1
kind: SchemaTestCredentials
bindings: []
"#
            .to_owned(),
        ),
        (
            "duplicate-binding",
            r#"apiVersion: registry.registrystack.org/server-schema-test-credentials/v1
kind: SchemaTestCredentials
bindings:
  - journeyId: package-record-list
    stepId: list-records
    credential:
      type: bearer
      tokenRef: secret:file/operator-token
  - journeyId: package-record-list
    stepId: list-records
    credential:
      type: bearer
      tokenRef: secret:file/operator-token
"#
            .to_owned(),
        ),
    ];

    for (name, source) in cases {
        let credentials = project.path().join(format!("credentials-{name}.yaml"));
        fs::write(&credentials, source).expect("credential fixture writes");
        let output = project.path().join(format!("receipt-{name}.json"));
        let result = test_candidate_command(&project, 1, &key_ids, &runtime, &credentials, &output);
        assert_schema_test_refusal(
            result,
            "test.credentials.refused",
            "schema_test_credentials",
            "supply_schema_test_credentials",
            &output,
            &[
                path(&credentials),
                "aaa.bbb.ccc",
                "secret:file/operator-token",
            ],
        );
    }
}

#[test]
fn test_credentials_secret_value_failures_are_preflight_and_value_free() {
    let (project, _signing, key_id) = packaging_project();
    let runtime = test_runtime_config(&project);
    let key_ids = vec![key_id.clone()];
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("utf8", vec![0xff, b'.', b'a', b'.', b'b']),
        ("empty", Vec::new()),
        ("oversized", vec![b'a'; 65 * 1024]),
        ("malformed-token", b"not.a-token!".to_vec()),
    ];

    for (name, secret) in cases {
        let secret_name = format!("operator-token-{name}");
        write_test_secret(&project, &secret_name, &secret);
        let credentials = project
            .path()
            .join(format!("secret-credentials-{name}.yaml"));
        fs::write(
            &credentials,
            credential_source(&format!(
                "type: bearer\n      tokenRef: secret:file/{secret_name}\n"
            )),
        )
        .expect("credential fixture writes");
        let output = project.path().join(format!("secret-receipt-{name}.json"));
        let result = test_candidate_command(&project, 1, &key_ids, &runtime, &credentials, &output);
        assert_schema_test_refusal(
            result,
            "test.credentials.refused",
            "schema_test_credentials",
            "supply_schema_test_credentials",
            &output,
            &[path(&credentials), &secret_name, "not.a-token!"],
        );
    }
}

#[test]
fn test_valid_credentials_reach_database_and_never_publish_partial_receipts() {
    let (project, _signing, key_id) = packaging_project();
    let runtime = test_runtime_config(&project);
    write_test_secret(&project, "operator-token", b"aaa.bbb.ccc");
    let credentials = project.path().join("valid-credentials.yaml");
    fs::write(
        &credentials,
        credential_source("type: bearer\n      tokenRef: secret:file/operator-token\n"),
    )
    .expect("credential fixture writes");
    let output = project.path().join("schema-test-receipt.json");
    let result = test_candidate_command(&project, 1, &[key_id], &runtime, &credentials, &output);

    assert_schema_test_refusal(
        result,
        "test.database.unavailable",
        "schema_test_database",
        "recreate_disposable_database",
        &output,
        &[
            path(project.path()),
            path(&runtime),
            path(&credentials),
            "aaa.bbb.ccc",
            "secret:file/operator-token",
            PACKAGE_VALUE_CANARY,
        ],
    );
    assert!(!project.path().join("signing-input.json").exists());
    assert!(!project.path().join("package").exists());
    assert!(!project.path().join("apply").exists());
    assert!(
        fs::read_dir(project.path())
            .expect("project directory reads")
            .all(|entry| !entry
                .expect("entry reads")
                .file_name()
                .to_string_lossy()
                .starts_with(".registry-serverctl-test-receipt-")),
        "temporary receipt files are cleaned up"
    );
}

#[test]
fn test_runtime_database_id_mismatch_is_candidate_refused_before_rehearsal() {
    let (project, _signing, key_id) = packaging_project();
    let runtime = test_runtime_config(&project);
    write_test_secret(&project, "operator-token", b"aaa.bbb.ccc");
    let credentials = project.path().join("database-mismatch-credentials.yaml");
    fs::write(
        &credentials,
        credential_source("type: bearer\n      tokenRef: secret:file/operator-token\n"),
    )
    .expect("credential fixture writes");
    let output = project.path().join("database-mismatch-receipt.json");
    let result = test_candidate_command_for_database(
        &project,
        "wrong-database",
        1,
        &[key_id],
        &runtime,
        &credentials,
        &output,
    );

    assert_schema_test_refusal(
        result,
        "test.candidate.refused",
        "schema_test_candidate",
        "correct_schema_test_candidate",
        &output,
        &[
            path(&runtime),
            path(&credentials),
            "wrong-database",
            PACKAGE_DATABASE,
            "aaa.bbb.ccc",
            "secret:file/operator-token",
            PACKAGE_VALUE_CANARY,
            "VERIFY_MIGRATION_DATABASE_SECRET_IS_NOT_OPENED",
        ],
    );
}

#[test]
fn test_deterministic_candidate_errors_are_refused_before_rehearsal() {
    let (project, _signing, key_id) = packaging_project();
    let runtime = test_runtime_config(&project);
    write_test_secret(&project, "operator-token", b"aaa.bbb.ccc");
    let credentials = project.path().join("invalid-policy-credentials.yaml");
    fs::write(
        &credentials,
        credential_source("type: bearer\n      tokenRef: secret:file/operator-token\n"),
    )
    .expect("credential fixture writes");
    let output = project.path().join("invalid-policy-receipt.json");
    let result = test_candidate_command(&project, 2, &[key_id], &runtime, &credentials, &output);

    assert_schema_test_refusal(
        result,
        "test.candidate.refused",
        "schema_test_candidate",
        "correct_schema_test_candidate",
        &output,
        &[
            path(&runtime),
            path(&credentials),
            "aaa.bbb.ccc",
            "secret:file/operator-token",
            PACKAGE_VALUE_CANARY,
            "VERIFY_MIGRATION_DATABASE_SECRET_IS_NOT_OPENED",
        ],
    );
}

#[test]
fn authoring_and_test_candidate_sources_are_read_once_and_bounded() {
    let oversized_yaml_comment = vec![b'#'; SCHEMA_TEST_AUTHORED_SOURCE_CEILING_BYTES + 1];

    let (project, _signing, key_id) = packaging_project();
    fs::write(
        project.path().join("registry.yaml"),
        &oversized_yaml_comment,
    )
    .expect("oversized project source writes");
    let check_project = registry_serverctl(&["--format", "json", "check", path(project.path())]);
    assert_eq!(check_project.status.code(), Some(1), "{check_project:?}");
    assert_eq!(
        json_stdout(&check_project)["diagnostics"][0]["code"],
        "source.file.bounds"
    );
    let test_project = test_candidate_command(
        &project,
        1,
        &[key_id],
        &project.path().join("unused-runtime.yaml"),
        &project.path().join("unused-credentials.yaml"),
        &project.path().join("oversized-project-receipt.json"),
    );
    assert_schema_test_refusal(
        test_project,
        "source.file.bounds",
        "registry_project",
        "correct_authoring_source",
        &project.path().join("oversized-project-receipt.json"),
        &[path(project.path()), "unused-runtime", "unused-credentials"],
    );

    let (project, _signing, key_id) = packaging_project();
    fs::write(
        project.path().join("modules/core/module.yaml"),
        oversized_yaml_comment,
    )
    .expect("oversized module source writes");
    let check_module = registry_serverctl(&["--format", "json", "check", path(project.path())]);
    assert_eq!(check_module.status.code(), Some(1), "{check_module:?}");
    assert_eq!(
        json_stdout(&check_module)["diagnostics"][0]["code"],
        "source.file.bounds"
    );
    let test_module = test_candidate_command(
        &project,
        1,
        &[key_id],
        &project.path().join("unused-runtime.yaml"),
        &project.path().join("unused-credentials.yaml"),
        &project.path().join("oversized-module-receipt.json"),
    );
    assert_schema_test_refusal(
        test_module,
        "source.file.bounds",
        "registry_project",
        "correct_authoring_source",
        &project.path().join("oversized-module-receipt.json"),
        &[path(project.path()), "unused-runtime", "unused-credentials"],
    );
}

#[test]
fn test_output_target_is_absolute_new_and_under_existing_non_symlink_parent() {
    let project = TestProject::from_registry_source(authoring_fixture());
    let missing_parent = project.path().join("missing").join("receipt.json");
    let existing = project.path().join("existing-receipt.json");
    fs::write(&existing, b"operator-owned").expect("existing output writes");
    let credentials = project.path().join("unused-credentials.yaml");
    let runtime = project.path().join("unused-runtime.yaml");

    for output in [
        Path::new("relative-receipt.json"),
        missing_parent.as_path(),
        &existing,
    ] {
        let result = registry_serverctl(&[
            "--format",
            "json",
            "test",
            path(project.path()),
            "--database-id",
            PACKAGE_DATABASE,
            "--runtime-config",
            path(&runtime),
            "--credentials",
            path(&credentials),
            "--output",
            path(output),
        ]);
        assert_eq!(result.status.code(), Some(1), "{result:?}");
        assert_eq!(
            json_stdout(&result)["diagnostics"][0]["code"],
            "test.output.refused"
        );
    }
    assert_eq!(
        fs::read(&existing).expect("existing output remains"),
        b"operator-owned"
    );
}

#[cfg(unix)]
#[test]
fn test_output_symlink_parent_is_refused_before_candidate_or_database_work() {
    use std::os::unix::fs::symlink;

    let project = TestProject::from_registry_source(authoring_fixture());
    let real = project.path().join("real-parent");
    let linked = project.path().join("linked-parent");
    fs::create_dir(&real).expect("real parent creates");
    symlink(&real, &linked).expect("symlink parent creates");
    let output = linked.join("receipt.json");
    let result = registry_serverctl(&[
        "--format",
        "json",
        "test",
        path(project.path()),
        "--database-id",
        PACKAGE_DATABASE,
        "--runtime-config",
        path(&project.path().join("runtime.yaml")),
        "--credentials",
        path(&project.path().join("credentials.yaml")),
        "--output",
        path(&output),
    ]);

    assert_eq!(result.status.code(), Some(1), "{result:?}");
    assert_eq!(
        json_stdout(&result)["diagnostics"][0]["code"],
        "test.output.refused"
    );
    assert!(!real.join("receipt.json").exists());
}

#[cfg(unix)]
#[test]
fn package_fixture_journey_source_is_required_regular_bounded_and_value_free() {
    use std::os::unix::fs::symlink;

    let (project, _signing, _key_id) = packaging_project();
    let journey_path = project.path().join("tests/journeys.yaml");
    let build = project.path().join("fixture-source-build");
    let missing_receipt = project.path().join("missing-receipt.json");
    let arguments = [
        "--format",
        "json",
        "package",
        path(project.path()),
        "--database-id",
        PACKAGE_DATABASE,
        "--schema-fingerprint",
        "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        "--test-receipt",
        path(&missing_receipt),
        "--output",
        path(&build),
    ];

    fs::remove_file(&journey_path).expect("fixture journeys remove");
    let missing = registry_serverctl(&arguments);
    assert_eq!(missing.status.code(), Some(1), "{missing:?}");
    assert_eq!(
        json_stdout(&missing)["diagnostics"][0]["code"],
        "source.fixture_journeys.missing"
    );

    let target = project.path().join("journey-source-canary.yaml");
    fs::write(&target, b"journey-source-value-canary").expect("symlink target writes");
    symlink(&target, &journey_path).expect("fixture journey symlink creates");
    let linked = registry_serverctl(&arguments);
    assert_eq!(linked.status.code(), Some(1), "{linked:?}");
    assert_eq!(
        json_stdout(&linked)["diagnostics"][0]["code"],
        "source.file.invalid"
    );
    fs::remove_file(&journey_path).expect("fixture journey symlink removes");

    fs::write(
        &journey_path,
        vec![b'x'; usize::try_from(MAX_PACKAGE_SOURCE_FILE_BYTES).unwrap() + 1],
    )
    .expect("oversized fixture journey writes");
    let oversized = registry_serverctl(&arguments);
    assert_eq!(oversized.status.code(), Some(1), "{oversized:?}");
    assert_eq!(
        json_stdout(&oversized)["diagnostics"][0]["code"],
        "source.file.bounds"
    );

    for output in [missing, linked, oversized] {
        let rendered = String::from_utf8(output.stdout).expect("diagnostic is UTF-8");
        assert!(!rendered.contains(path(project.path())));
        assert!(!rendered.contains("journey-source-value-canary"));
    }
    assert!(!build.exists());
}

#[test]
fn package_always_uses_production_compilation_and_never_offers_a_signing_command() {
    let project = TestProject::from_registry_source(authoring_fixture());
    let build = project.path().join("build");
    let missing_receipt = project.path().join("missing-receipt.json");
    let output = registry_serverctl(&[
        "--format",
        "json",
        "package",
        path(project.path()),
        "--database-id",
        PACKAGE_DATABASE,
        "--schema-fingerprint",
        "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        "--test-receipt",
        path(&missing_receipt),
        "--output",
        path(&build),
    ]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let report = json_stdout(&output);
    assert!(report["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .any(|diagnostic| diagnostic["code"] == "package.identity.required"));
    assert!(!build.exists());

    let help = registry_serverctl(&["--help"]);
    let help = String::from_utf8(help.stdout).expect("help is UTF-8");
    assert!(!help
        .lines()
        .any(|line| line.trim_start().starts_with("sign")));
}

#[test]
fn apply_verifies_package_intent_before_database_authority_and_stays_value_free() {
    let relative = registry_serverctl(&[
        "--format",
        "json",
        "apply",
        "--runtime-config",
        PACKAGE_VALUE_CANARY,
        "--package",
        PACKAGE_VALUE_CANARY,
    ]);
    assert_eq!(relative.status.code(), Some(1), "{relative:?}");
    assert_eq!(
        json_stdout(&relative)["diagnostics"][0]["code"],
        "apply.runtime_config.path_invalid"
    );
    assert!(!String::from_utf8_lossy(&relative.stdout).contains(PACKAGE_VALUE_CANARY));

    let fixture = RuntimePackageFixture::production("127.0.0.1:1".parse().unwrap());
    let malformed_backup = registry_serverctl(&[
        "--format",
        "json",
        "apply",
        "--runtime-config",
        path(&fixture.runtime_config),
        "--package",
        path(&fixture.package),
        "--initial",
        "--backup",
        PACKAGE_VALUE_CANARY,
    ]);
    assert_eq!(
        malformed_backup.status.code(),
        Some(1),
        "{malformed_backup:?}"
    );
    assert_eq!(
        json_stdout(&malformed_backup)["diagnostics"][0]["code"],
        "apply.backup_evidence.refused"
    );
    assert!(!String::from_utf8_lossy(&malformed_backup.stdout).contains(PACKAGE_VALUE_CANARY));

    let output = registry_serverctl(&[
        "--format",
        "json",
        "apply",
        "--runtime-config",
        path(&fixture.runtime_config),
        "--package",
        path(&fixture.package),
    ]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stderr.is_empty());
    let report = json_stdout(&output);
    assert_eq!(report["diagnostics"][0]["code"], "apply.package.refused");
    assert_tool_diagnostic(
        &report["diagnostics"][0],
        "verified_package",
        "verify_package_binding",
    );
    let rendered = String::from_utf8(output.stdout).expect("apply refusal is UTF-8");
    for forbidden in [
        path(&fixture.runtime_config),
        path(&fixture.package),
        path(&fixture.anchor),
        PACKAGE_VALUE_CANARY,
        "VERIFY_DATABASE_SECRET_IS_NOT_OPENED",
    ] {
        assert!(!rendered.contains(forbidden));
    }

    let database_refusal = registry_serverctl(&[
        "--format",
        "json",
        "apply",
        "--runtime-config",
        path(&fixture.runtime_config),
        "--package",
        path(&fixture.package),
        "--initial",
    ]);
    assert_eq!(
        database_refusal.status.code(),
        Some(1),
        "{database_refusal:?}"
    );
    assert_eq!(
        json_stdout(&database_refusal)["diagnostics"][0]["code"],
        "apply.database_configuration.refused"
    );
    assert!(!String::from_utf8_lossy(&database_refusal.stdout)
        .contains("VERIFY_DATABASE_SECRET_IS_NOT_OPENED"));
}

#[test]
fn verify_is_runtime_bound_deterministic_and_listener_free() {
    let occupied = TcpListener::bind("127.0.0.1:0").expect("listener proof binds one local port");
    let fixture = RuntimePackageFixture::production(
        occupied
            .local_addr()
            .expect("listener proof address is available"),
    );
    let arguments = [
        "--format",
        "json",
        "verify",
        "--runtime-config",
        path(&fixture.runtime_config),
    ];
    let first = registry_serverctl(&arguments);
    let second = registry_serverctl(&arguments);

    assert!(first.status.success(), "{first:?}");
    assert!(first.stderr.is_empty());
    assert_eq!(first.stdout, second.stdout, "verify output is byte stable");
    let report = json_stdout(&first);
    assert_eq!(
        report,
        json!({
            "ok": true,
            "command": "verify",
            "assurance": "runtime_bound",
            "packageRevision": fixture.package_revision,
            "registry": {
                "id": "verify-registry",
                "version": "1",
                "revision": report["registry"]["revision"],
            },
            "inventory": {
                "modules": 1,
                "entities": 1,
                "routes": 2,
                "accessEntries": 2,
                "queries": 1,
                "eventDeliveries": 0,
                "ddlStatements": report["inventory"]["ddlStatements"],
                "generatedArtifacts": report["inventory"]["generatedArtifacts"],
            }
        })
    );
    assert!(report["inventory"]["ddlStatements"].as_u64().unwrap() > 0);
    assert!(report["inventory"]["generatedArtifacts"].as_u64().unwrap() > 0);
    let rendered = String::from_utf8(first.stdout).expect("verify JSON is UTF-8");
    for forbidden in [
        PACKAGE_VALUE_CANARY,
        path(&fixture.runtime_config),
        path(&fixture.package),
        path(&fixture.anchor),
        "oidc-is-not-opened.invalid",
        "VERIFY_DATABASE_SECRET_IS_NOT_OPENED",
    ] {
        assert!(!rendered.contains(forbidden));
    }

    let human = registry_serverctl(&["verify", "--runtime-config", path(&fixture.runtime_config)]);
    assert!(human.status.success(), "{human:?}");
    assert!(human.stderr.is_empty());
    let human = String::from_utf8(human.stdout).expect("verify human report is UTF-8");
    assert!(human.starts_with("verify succeeded\nassurance: runtime_bound\n"));
    assert!(human.contains(&format!("package revision: {}\n", fixture.package_revision)));
    assert!(human.contains("registry id: verify-registry\n"));
    assert!(!human.contains(path(&fixture.runtime_config)));
}

#[test]
fn migration_explain_is_runtime_bound_deterministic_and_listener_free() {
    let occupied = TcpListener::bind("127.0.0.1:0").expect("listener proof binds one local port");
    let fixture = RuntimePackageFixture::production(
        occupied
            .local_addr()
            .expect("listener proof address is available"),
    );
    let arguments = [
        "--format",
        "json",
        "migration",
        "explain",
        "--runtime-config",
        path(&fixture.runtime_config),
    ];
    let first = registry_serverctl(&arguments);
    let second = registry_serverctl(&arguments);

    assert!(first.status.success(), "{first:?}");
    assert!(first.stderr.is_empty());
    assert_eq!(first.stdout, second.stdout, "report output is byte stable");
    let report = json_stdout(&first);
    assert!(report["plan"]["generatedStatementCount"]
        .as_u64()
        .is_some_and(|count| count > 0));
    assert_eq!(
        report,
        json!({
            "ok": true,
            "command": "migration explain",
            "assurance": "runtime_bound",
            "packageRevision": fixture.package_revision,
            "plan": {
                "planKind": "initial",
                "hasPriorRevision": false,
                "hasPriorBaseline": false,
                "changeCount": 0,
                "changeCounts": {
                    "compatibleAdditive": 0,
                    "dataBackfillRequired": 0,
                    "accessOrDisclosureChange": 0,
                    "destructiveOrIrreversible": 0,
                    "unsupported": 0,
                },
                "generatedStatementCount": report["plan"]["generatedStatementCount"],
                "reviewedMigrations": [],
            }
        })
    );
    let rendered = String::from_utf8(first.stdout).expect("migration JSON is UTF-8");
    for forbidden in [
        PACKAGE_VALUE_CANARY,
        path(&fixture.runtime_config),
        path(&fixture.package),
        path(&fixture.anchor),
        "CREATE TABLE",
        "signature",
    ] {
        assert!(!rendered.contains(forbidden));
    }

    let human = registry_serverctl(&[
        "migration",
        "explain",
        "--runtime-config",
        path(&fixture.runtime_config),
    ]);
    assert!(human.status.success(), "{human:?}");
    assert!(human.stderr.is_empty());
    let human = String::from_utf8(human.stdout).expect("migration report is UTF-8");
    assert!(human.starts_with("migration explain succeeded\nassurance: runtime_bound\n"));
    assert!(human.contains("plan kind: initial\n"));
    assert!(human.contains("change count: 0\n"));
    assert!(human.contains("reviewed migration count: 0\n"));
    assert!(!human.contains(path(&fixture.runtime_config)));
}

#[test]
fn lifecycle_parser_surfaces_are_exact_and_value_free() {
    let help = registry_serverctl(&["--help"]);
    assert!(help.status.success());
    let rendered = String::from_utf8(help.stdout).expect("top-level help is UTF-8");
    for available in ["package", "apply", "verify", "migration", "data"] {
        assert!(rendered
            .lines()
            .any(|line| line.trim_start().starts_with(available)));
    }
    assert!(!rendered
        .lines()
        .any(|line| line.trim_start().starts_with("webhook")));

    for arguments in [
        vec!["verify", "--help"],
        vec!["migration", "explain", "--help"],
        vec!["data", "validate", "--help"],
        vec!["data", "import", "--help"],
        vec!["data", "export", "--help"],
    ] {
        let output = registry_serverctl(&arguments);
        assert!(output.status.success(), "{output:?}");
        let help = String::from_utf8(output.stdout).expect("command help is UTF-8");
        if arguments.first() == Some(&"data") {
            assert!(help.contains("--package <ABSOLUTE_DIRECTORY>"));
            assert!(!help.contains("runtime-config"));
            assert!(!help.contains("database"));
        } else {
            assert!(help.contains("--runtime-config <ABSOLUTE_FILE>"));
        }
    }
    let migration_help = registry_serverctl(&["migration", "--help"]);
    let migration_help = String::from_utf8(migration_help.stdout).expect("migration help is UTF-8");
    assert!(migration_help
        .lines()
        .any(|line| line.trim_start().starts_with("explain")));
    let package_help = registry_serverctl(&["package", "--help"]);
    let package_help = String::from_utf8(package_help.stdout).expect("package help is UTF-8");
    for required in [
        "--database-id <ID>",
        "--schema-fingerprint <SHA256>",
        "--test-receipt <ABSOLUTE_FILE>",
        "--output <DIRECTORY>",
        "--signatures <FILE>",
    ] {
        assert!(package_help.contains(required));
    }
    let apply_help = registry_serverctl(&["apply", "--help"]);
    let apply_help = String::from_utf8(apply_help.stdout).expect("apply help is UTF-8");
    for required in [
        "--runtime-config <ABSOLUTE_FILE>",
        "--package <ABSOLUTE_DIRECTORY>",
        "--initial",
        "--backup <BINDING_PATH=ABSOLUTE_FILE>",
    ] {
        assert!(apply_help.contains(required));
    }

    for arguments in [
        vec!["--format", "json", "package", PACKAGE_VALUE_CANARY],
        vec![
            "--format",
            "json",
            "apply",
            "--runtime-config",
            PACKAGE_VALUE_CANARY,
        ],
        vec!["--format", "json", "verify"],
        vec![
            "--format",
            "json",
            "verify",
            "--runtime-config",
            PACKAGE_VALUE_CANARY,
            "--package",
            PACKAGE_VALUE_CANARY,
        ],
        vec!["--format", "json", "migration"],
        vec![
            "--format",
            "json",
            "migration",
            "explain",
            "--runtime-config",
            PACKAGE_VALUE_CANARY,
            "--package",
            PACKAGE_VALUE_CANARY,
        ],
        vec!["--format", "json", "data"],
        vec![
            "--format",
            "json",
            "data",
            "validate",
            "--runtime-config",
            PACKAGE_VALUE_CANARY,
        ],
    ] {
        let output = registry_serverctl(&arguments);
        assert_eq!(output.status.code(), Some(2));
        assert!(output.stderr.is_empty());
        let rendered = String::from_utf8(output.stdout).expect("usage refusal is UTF-8");
        assert!(!rendered.contains(PACKAGE_VALUE_CANARY));
        assert_eq!(
            serde_json::from_str::<Value>(&rendered).unwrap()["diagnostics"][0]["code"],
            "usage.invalid"
        );
    }
}

#[test]
fn runtime_bound_package_refusals_are_exact_and_value_free_for_both_commands() {
    let fixture = RuntimePackageFixture::production("127.0.0.1:1".parse().unwrap());

    for (prefix, command) in [
        ("verify", vec!["verify"]),
        ("migration.explain", vec!["migration", "explain"]),
    ] {
        let mut arguments = vec!["--format", "json"];
        arguments.extend(command);
        arguments.extend(["--runtime-config", PACKAGE_VALUE_CANARY]);
        assert_inspection_refusal(
            &arguments,
            &format!("{prefix}.runtime_config.path_invalid"),
            "runtime_configuration",
            "correct_runtime_configuration",
            &[PACKAGE_VALUE_CANARY],
        );
    }

    let wrong =
        generate_private_jwk(GeneratedKeyAlgorithm::Es384).expect("wrong trust key generates");
    let wrong_anchor = fixture
        .directory
        .path()
        .join(format!("{PACKAGE_VALUE_CANARY}.json"));
    write_anchor(&wrong_anchor, &wrong);
    let wrong_trust = fixture.variant("wrong-trust", path(&fixture.anchor), path(&wrong_anchor));
    let wrong_binding = fixture.variant(
        "wrong-binding",
        &format!("activeRevision: {}", fixture.package_revision),
        &format!("activeRevision: {PACKAGE_VALUE_CANARY}"),
    );

    for (runtime, suffix, action) in [
        (&wrong_trust, "signature_refused", "verify_package_trust"),
        (&wrong_binding, "binding_refused", "verify_package_binding"),
    ] {
        for (prefix, command) in [
            ("verify", vec!["verify"]),
            ("migration.explain", vec!["migration", "explain"]),
        ] {
            let mut arguments = vec!["--format", "json"];
            arguments.extend(command);
            arguments.extend(["--runtime-config", path(runtime)]);
            assert_inspection_refusal(
                &arguments,
                &format!("{prefix}.package.{suffix}"),
                "verified_package",
                action,
                &[
                    PACKAGE_VALUE_CANARY,
                    path(runtime),
                    path(&fixture.package),
                    path(&wrong_anchor),
                ],
            );
        }
    }
}

#[test]
fn canonical_package_tampering_is_refused_without_rendering_package_values() {
    let fixture = RuntimePackageFixture::production("127.0.0.1:1".parse().unwrap());
    let manifest = fixture.package.join("package.json");
    let mut bytes = fs::read(&manifest).expect("package manifest reads");
    bytes.push(b'\n');
    set_owner_writable(&manifest);
    fs::write(&manifest, bytes).expect("package manifest tampers");
    set_owner_read_only(&manifest);

    for (prefix, command) in [
        ("verify", vec!["verify"]),
        ("migration.explain", vec!["migration", "explain"]),
    ] {
        let mut arguments = vec!["--format", "json"];
        arguments.extend(command);
        arguments.extend(["--runtime-config", path(&fixture.runtime_config)]);
        assert_inspection_refusal(
            &arguments,
            &format!("{prefix}.package.integrity_refused"),
            "verified_package",
            "verify_package_integrity",
            &[
                PACKAGE_VALUE_CANARY,
                path(&fixture.runtime_config),
                path(&fixture.package),
            ],
        );
    }
}

#[cfg(unix)]
#[test]
fn unsafe_package_permissions_are_refused_without_rendering_paths() {
    let fixture = RuntimePackageFixture::production("127.0.0.1:1".parse().unwrap());
    let manifest = fixture.package.join("package.json");
    set_group_writable(&manifest);
    for (prefix, command) in [
        ("verify", vec!["verify"]),
        ("migration.explain", vec!["migration", "explain"]),
    ] {
        let mut arguments = vec!["--format", "json"];
        arguments.extend(command);
        arguments.extend(["--runtime-config", path(&fixture.runtime_config)]);
        assert_inspection_refusal(
            &arguments,
            &format!("{prefix}.package.permissions_refused"),
            "verified_package",
            "verify_package_permissions",
            &[path(&fixture.runtime_config), path(&fixture.package)],
        );
    }
}

#[test]
fn unknown_source_is_refused_without_echoing_source_values() {
    const SOURCE_VALUE_CANARY: &str = "registry-serverctl-source-value-canary";

    let project = TestProject::asset_fixture();
    let mut source = String::from_utf8(asset_fixture().to_vec()).expect("fixture is UTF-8");
    source.push_str(&format!("\nunexpectedSetting: {SOURCE_VALUE_CANARY}\n"));
    fs::write(project.path().join("registry.yaml"), source).expect("unknown source is written");

    let output = registry_serverctl(&[
        "--format",
        "json",
        "check",
        project.path().to_str().expect("path is UTF-8"),
    ]);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    assert!(!String::from_utf8_lossy(&output.stdout).contains(SOURCE_VALUE_CANARY));
    let report = json_stdout(&output);
    assert_eq!(report["diagnostics"][0]["code"], "source.yaml.invalid");
    assert_tool_diagnostic(
        &report["diagnostics"][0],
        "registry_project",
        "correct_authoring_source",
    );
}

#[test]
fn json_usage_errors_are_machine_readable_and_value_free() {
    const ARGUMENT_CANARY: &str = "registry-serverctl-argument-canary";

    let output = registry_serverctl(&["--format", "json", "check", ARGUMENT_CANARY, "--unknown"]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    assert!(!String::from_utf8_lossy(&output.stdout).contains(ARGUMENT_CANARY));
    let report = json_stdout(&output);
    assert_eq!(report["command"], "usage");
    assert_eq!(report["diagnostics"][0]["code"], "usage.invalid");
    assert_tool_diagnostic(
        &report["diagnostics"][0],
        "command_arguments",
        "correct_command_usage",
    );
}

#[test]
fn data_validate_uses_a_closed_package_plan_and_value_free_usage() {
    const DATA_CANARY: &str = "registry-serverctl-data-value-canary";

    let (directory, package) = data_package_fixture();
    let input = directory.path().join("input.jsonl");
    fs::write(
        &input,
        r#"{"operation":"create","data":{"code":"AA"}}"#.to_owned() + "\n",
    )
    .expect("data input writes");

    let output = registry_serverctl(&[
        "--format",
        "json",
        "data",
        "validate",
        "--package",
        path(&package),
        "--entity",
        "record",
        "--profile",
        "operator",
        "--operation",
        "create",
        "--input",
        path(&input),
    ]);

    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("AA"));
    let report = json_stdout(&output);
    assert_eq!(report["ok"], true);
    assert_eq!(report["command"], "data validate");
    assert_eq!(report["entityId"], "record");
    assert_eq!(report["profileId"], "operator");
    assert_eq!(report["operation"], "create");
    assert_eq!(report["itemCount"], 1);
    assert_eq!(report["chunkCount"], 1);

    let refused = registry_serverctl(&[
        "--format",
        "json",
        "data",
        "validate",
        "--runtime-config",
        DATA_CANARY,
    ]);
    assert_eq!(refused.status.code(), Some(2));
    assert!(refused.stderr.is_empty());
    let rendered = String::from_utf8(refused.stdout).expect("usage response is UTF-8");
    assert!(!rendered.contains(DATA_CANARY));
    assert_eq!(
        serde_json::from_str::<Value>(&rendered).unwrap()["diagnostics"][0]["code"],
        "usage.invalid"
    );
}

#[cfg(unix)]
#[test]
fn generation_refuses_a_broken_symlink_destination_without_publishing_output() {
    use std::os::unix::fs::symlink;

    let project = TestProject::asset_fixture();
    let destination = project.path().join("linked-output");
    symlink("not-present", &destination).expect("broken output symlink is created");
    let output = registry_serverctl(&[
        "--format",
        "json",
        "generate",
        "openapi",
        project.path().to_str().expect("path is UTF-8"),
        "--output",
        destination.to_str().expect("path is UTF-8"),
    ]);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    let report = json_stdout(&output);
    assert_eq!(
        report["diagnostics"][0]["code"],
        "output.destination.invalid"
    );
    assert_tool_diagnostic(
        &report["diagnostics"][0],
        "generated_artifacts",
        "retry_artifact_generation",
    );
    assert!(fs::symlink_metadata(destination)
        .expect("symlink remains intact")
        .file_type()
        .is_symlink());
}

fn package_project_bytes(module_digest: &str) -> Vec<u8> {
    format!(
        r#"{{"apiVersion":"registry.registrystack.org/v1alpha1","kind":"RegistryProject","registry":{{"id":"verify-registry","version":"1","defaultLanguage":"en"}},"package":{{"environment":"production","instanceId":"{PACKAGE_INSTANCE}","sequence":1,"sourceRevision":"{PACKAGE_SOURCE_REVISION}"}},"manifestProjection":{{"accessProfile":"reader","classificationCeiling":"restricted","catalog":{{"baseUrl":"https://package.example.test","title":"Verify Registry Catalog","publisher":{{"name":"Verify Publisher"}}}},"dataset":{{"title":"Verify Registry Dataset","owner":"Verify Publisher","status":"active"}}}},"modules":[{{"id":"core","version":"1","digest":"{module_digest}"}}]}}"#
    )
    .into_bytes()
}

fn package_module_bytes() -> Vec<u8> {
    br#"{"id":"core","version":"1","entities":[{"id":"record","route":"records","mutationMode":"create_only","fields":[{"id":"code","type":"string","maxLength":16,"classification":"internal"}],"accessProfiles":[{"id":"reader","principalClaim":"principal","operations":["get","list"],"readableFields":["code"]}]}]}"#
        .to_vec()
}

fn data_package_fixture() -> (TestProject, PathBuf) {
    let module_bytes = br#"{"id":"core","version":"1","entities":[{"id":"record","route":"records","mutationMode":"create_only","batch":{"maximumItems":2,"maximumBytes":400},"fields":[{"id":"code","type":"string","minLength":2,"maxLength":16,"required":true,"classification":"internal"}],"accessProfiles":[{"id":"operator","principalClaim":"principal","operations":["create","batch","list"],"readableFields":["code"],"writableFields":["code"],"allowDataExport":true}]}]}"#.to_vec();
    let module = parse_module_json(&module_bytes).expect("data module parses");
    let module_digest = module_digest(&module);
    let project = TestProject::from_registry_source(
        format!(
            r#"{{"apiVersion":"registry.registrystack.org/v1alpha1","kind":"RegistryProject","registry":{{"id":"data-registry","version":"1","defaultLanguage":"en"}},"package":{{"environment":"local","instanceId":"data-instance","sequence":1,"sourceRevision":"data-source"}},"manifestProjection":{{"accessProfile":"operator","classificationCeiling":"restricted","catalog":{{"baseUrl":"https://data.example.test","title":"Data Registry Catalog","publisher":{{"name":"Data Publisher"}}}},"dataset":{{"title":"Data Registry Dataset","owner":"Data Publisher","status":"active"}}}},"modules":[{{"id":"core","version":"1","digest":"{module_digest}"}}]}}"#
        )
        .as_bytes(),
    );
    let package = project.path().join("data-package");
    let prepared = prepare_package(PackageBuildRequest {
        environment: "local".to_owned(),
        instance_id: "data-instance".to_owned(),
        database_id: "data-database".to_owned(),
        sequence: 1,
        prior_revision: None,
        compiler_source_revision: "data-source".to_owned(),
        schema_fingerprint:
            "sha256:3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
        signature_policy: SignaturePolicy {
            threshold: 0,
            key_ids: vec![],
        },
        project: PackageSourceFile {
            path: "source/registry.yaml".to_owned(),
            bytes: fs::read(project.path().join("registry.yaml")).expect("data project reads"),
        },
        modules: vec![PackageModuleSource {
            id: "core".to_owned(),
            path: "source/modules/core/module.yaml".to_owned(),
            bytes: module_bytes,
        }],
        fixture_journeys: PackageSourceFile {
            path: "tests/journeys.yaml".to_owned(),
            bytes: DATA_FIXTURE_JOURNEYS.to_vec(),
        },
        migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
    })
    .expect("data package prepares");
    validate_fixture_journeys(DATA_FIXTURE_JOURNEYS, prepared.registry())
        .expect("data fixture journeys resolve against the packaged registry");
    prepared
        .publish_to_directory(&package, vec![])
        .expect("data package publishes");
    (project, package)
}

fn write_anchor(path: &Path, key: &PrivateJwk) {
    let public = key.public();
    write_canonical(
        path,
        &PackageTrustAnchor {
            api_version: TRUST_ANCHOR_API_VERSION.to_owned(),
            environment: "production".to_owned(),
            instance_id: PACKAGE_INSTANCE.to_owned(),
            database_id: PACKAGE_DATABASE.to_owned(),
            threshold: 1,
            keys: vec![TrustAnchorKey {
                key_id: public.kid.clone().expect("generated key has an id"),
                jwk: serde_json::to_value(public).expect("public key serializes"),
            }],
        },
    );
}

fn write_canonical(path: &Path, value: &impl Serialize) {
    let value = serde_json::to_value(value).expect("value serializes");
    let bytes = canonicalize_json(&value).expect("value canonicalizes");
    fs::write(path, bytes).expect("canonical file writes");
}

fn write_runtime_config(
    parent: &Path,
    package: &Path,
    trust_anchor: &Path,
    revision: &str,
    bind: SocketAddr,
) -> PathBuf {
    let secret_root = parent.join("secrets");
    fs::create_dir_all(&secret_root).expect("secret root creates");
    let path = parent.join("runtime.yaml");
    fs::write(
        &path,
        format!(
            r#"listener:
  bind: {bind}
  trustedProxy: direct
identity:
  environment: production
  instanceId: {PACKAGE_INSTANCE}
  databaseId: {PACKAGE_DATABASE}
  databaseInitializationEnvironment: production
secretProviders:
  environment: {{}}
  file:
    root: {secret_root}
database:
  runtimeUrlRef: secret:env/VERIFY_RUNTIME_DATABASE_SECRET_IS_NOT_OPENED
  migrationUrlRef: secret:env/VERIFY_MIGRATION_DATABASE_SECRET_IS_NOT_OPENED
  pool:
    maxSize: 1
    waitTimeoutMilliseconds: 1000
    createTimeoutMilliseconds: 1000
    recycleTimeoutMilliseconds: 1000
  roles:
    migration: registry_migration
    runtime: registry_runtime
package:
  root: {package}
  trustAnchorPath: {trust_anchor}
  compilerSourceRevision: {PACKAGE_SOURCE_REVISION}
  activeRevision: {revision}
  activeSequence: 1
authentication:
  oidc:
    issuer: https://oidc-is-not-opened.invalid
    audience: urn:registry-server:verify
    allowedAlgorithm: EdDSA
    accessTokenType: JWT
    scopeClaim: scope
    scopeSeparator: " "
    allowedClients: [verify-client]
    deniedKids: []
    maxTokenLifetimeSeconds: 300
    leewayMilliseconds: 60000
    jwksCache:
      cacheTtlSeconds: 600
      negativeCacheTtlSeconds: 60
      refreshCooldownSeconds: 30
      maxDocumentBytes: 65536
      requestTimeoutMilliseconds: 1
      outageToleranceSeconds: 900
  authorityClaims:
    principal: registry_principal
    purpose: registry_purpose
    rowBoundaryClaims: []
audit:
  hashKeyRef: secret:file/{PACKAGE_VALUE_CANARY}
cursor:
  secretRef: secret:file/{PACKAGE_VALUE_CANARY}
  maxAgeSeconds: 300
operationalTimeouts:
  httpRequestMilliseconds: 10000
  shutdownGraceMilliseconds: 30000
  recordLockMilliseconds: 5000
  migrationLockMilliseconds: 30000
  migrationStatementMilliseconds: 60000
"#,
            secret_root = secret_root.display(),
            package = package.display(),
            trust_anchor = trust_anchor.display(),
        ),
    )
    .expect("runtime configuration writes");
    path
}

fn test_runtime_config(project: &TestProject) -> PathBuf {
    let package_root = project.path().join("runtime-package-root");
    fs::create_dir(&package_root).expect("runtime package root creates");
    let trust_anchor = project.path().join("runtime-trust-anchor.json");
    fs::write(&trust_anchor, b"{}").expect("runtime trust anchor writes");
    write_runtime_config(
        project.path(),
        &package_root,
        &trust_anchor,
        "schema-test-active-revision",
        "127.0.0.1:1".parse().expect("loopback address parses"),
    )
}

fn credential_source(credential: &str) -> String {
    format!(
        r#"apiVersion: registry.registrystack.org/server-schema-test-credentials/v1
kind: SchemaTestCredentials
bindings:
  - journeyId: package-record-list
    stepId: list-records
    credential:
      {credential}"#
    )
}

fn write_test_secret(project: &TestProject, name: &str, bytes: &[u8]) {
    let path = project.path().join("secrets").join(name);
    fs::write(&path, bytes).expect("test secret writes");
    set_owner_read_only(&path);
}

fn assert_schema_test_refusal(
    output: Output,
    expected_code: &str,
    artifact: &str,
    action: &str,
    receipt: &Path,
    forbidden: &[&str],
) {
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stderr.is_empty());
    assert!(!receipt.exists(), "receipt was not published on refusal");
    let rendered = String::from_utf8(output.stdout).expect("refusal JSON is UTF-8");
    for canary in forbidden {
        assert!(!rendered.contains(canary), "refusal leaked {canary}");
    }
    let report: Value = serde_json::from_str(&rendered).expect("refusal JSON parses");
    assert_eq!(report["command"], "test");
    assert_eq!(report["diagnostics"][0]["code"], expected_code);
    assert_tool_diagnostic(&report["diagnostics"][0], artifact, action);
}

fn assert_inspection_refusal(
    arguments: &[&str],
    expected_code: &str,
    artifact: &str,
    action: &str,
    forbidden: &[&str],
) {
    let output = registry_serverctl(arguments);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stderr.is_empty());
    let rendered = String::from_utf8(output.stdout).expect("refusal JSON is UTF-8");
    for canary in forbidden {
        assert!(!rendered.contains(canary), "refusal leaked {canary}");
    }
    let report: Value = serde_json::from_str(&rendered).expect("refusal JSON parses");
    assert_eq!(report["diagnostics"][0]["code"], expected_code);
    assert_tool_diagnostic(&report["diagnostics"][0], artifact, action);
}

fn path(path: &Path) -> &str {
    path.to_str().expect("test path is UTF-8")
}

#[cfg(unix)]
fn set_owner_writable(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))
        .expect("test package file becomes owner-writable");
}

#[cfg(not(unix))]
fn set_owner_writable(_path: &Path) {}

#[cfg(unix)]
fn set_owner_read_only(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(path, fs::Permissions::from_mode(0o400))
        .expect("test package file becomes read-only");
}

#[cfg(not(unix))]
fn set_owner_read_only(_path: &Path) {}

#[cfg(unix)]
fn set_group_writable(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(path, fs::Permissions::from_mode(0o660))
        .expect("test package file becomes group-writable");
}

fn hex(bytes: &[u8]) -> String {
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;

        write!(&mut encoded, "{byte:02x}").expect("hex writes to String");
    }
    encoded
}

fn tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut files = BTreeMap::new();
    collect_tree(root, root, &mut files);
    files
}

fn collect_tree(root: &Path, directory: &Path, files: &mut BTreeMap<String, Vec<u8>>) {
    for entry in fs::read_dir(directory).expect("directory is readable") {
        let entry = entry.expect("directory entry is readable");
        let path = entry.path();
        if path.is_dir() {
            collect_tree(root, &path, files);
        } else {
            files.insert(
                path.strip_prefix(root)
                    .expect("generated path is under root")
                    .to_str()
                    .expect("generated path is UTF-8")
                    .replace(std::path::MAIN_SEPARATOR, "/"),
                fs::read(&path).expect("generated artifact is readable"),
            );
        }
    }
}
