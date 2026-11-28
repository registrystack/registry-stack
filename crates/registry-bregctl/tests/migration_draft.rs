// SPDX-License-Identifier: Apache-2.0

//! `bregctl migration draft` refuses before it opens any database, and never
//! overwrites a reviewed migration it already wrote.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use registry_breg::compiler::module_digest;
use registry_breg::contract::parse_module_json;
use registry_breg::fixtures::validate_fixture_journeys;
use registry_breg::package::{
    prepare_package, PackageBuildRequest, PackageMigrationPlanInput, PackageModuleSource,
    PackageSourceFile,
};
use serde_json::Value;

const SOURCE_REVISION: &str = "compiler-source-revision";
const FIXTURE_JOURNEYS: &[u8] = br#"apiVersion: id.registrystack.org/formats/breg/journeys/v1
kind: BRegJourneys
journeys:
  - id: draft-record-list
    steps:
      - id: list-records
        recordType: record
        accessProfile: reader
        claims: {principal: draft-reader}
        request: {type: list}
        expect: {outcome: success, status: 200, count: 0}
"#;
// Refusals happen before the runtime configuration is read, so a path that
// does not exist proves no refusal opened a database.
const UNREAD_RUNTIME_CONFIG: &str = "/nonexistent-runtime-config-is-never-read.yaml";
static TEMPORARY_COUNTER: AtomicU64 = AtomicU64::new(0);

struct TestDirectory {
    path: PathBuf,
}

impl TestDirectory {
    fn create() -> Self {
        let path = std::env::current_dir()
            .expect("current directory is available")
            .join(format!(
                "bregctl-draft-test-{}-{}",
                std::process::id(),
                TEMPORARY_COUNTER.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir(&path).expect("test directory is created");
        Self { path }
    }
}

impl Drop for TestDirectory {
    fn drop(&mut self) {
        if self
            .path
            .file_name()
            .and_then(|name| name.to_str())
            .is_some_and(|name| name.starts_with("bregctl-draft-test-"))
            && self.path.exists()
        {
            fs::remove_dir_all(&self.path).expect("test directory is removed");
        }
    }
}

fn publish_package(parent: &Path, name: &str, classification: &str) -> PublishedPackage {
    let module_bytes = module_bytes(classification);
    let module = parse_module_json(&module_bytes).expect("package module parses");
    let project_bytes = project_bytes(&module_digest(&module));
    let prepared = prepare_package(PackageBuildRequest {
        from_package_digest: None,
        compiler_source_revision: SOURCE_REVISION.to_owned(),
        schema_fingerprint:
            "sha256:2222222222222222222222222222222222222222222222222222222222222222".to_owned(),
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
    .expect("package prepares");
    validate_fixture_journeys(FIXTURE_JOURNEYS, prepared.registry())
        .expect("diff fixture journeys resolve against the packaged registry");
    let package = parent.join(name);
    prepared
        .publish_to_directory(&package)
        .expect("package publishes");
    PublishedPackage { package }
}

fn write_project(parent: &Path, name: &str, classification: &str) -> PathBuf {
    write_project_with_module(parent, name, module_bytes(classification))
}

fn write_project_with_module(parent: &Path, name: &str, module: Vec<u8>) -> PathBuf {
    let root = parent.join(name);
    let parsed = parse_module_json(&module).expect("candidate module parses");
    fs::create_dir_all(root.join("modules/core")).expect("candidate directories create");
    fs::write(
        root.join("registry.yaml"),
        project_bytes(&module_digest(&parsed)),
    )
    .expect("candidate project writes");
    fs::write(root.join("modules/core/module.yaml"), module).expect("candidate module writes");
    root
}

fn project_bytes(module_digest: &str) -> Vec<u8> {
    format!(
        r#"{{"apiVersion":"id.registrystack.org/formats/breg/project/v1alpha1","kind":"BRegProject","project":{{"id":"neutral-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://package.example.test"}},"package":{{"sourceRevision":"{SOURCE_REVISION}"}},"datasets":{{"neutral-registry": {{}}}},"manifestProjection":{{"accessProfile":"reader","classificationCeiling":"restricted","catalog":{{"baseUrl":"https://package.example.test","title":"Neutral Registry Catalog","publisher":{{"id":"neutral-registry-authority","name":"Package Test Publisher"}}}},"authorities":[{{"id":"neutral-registry-authority","name":"Package Test Publisher"}}],"publicService":{{"id":"neutral-registry-service","title":"Neutral Registry Catalog","competentAuthority":"neutral-registry-authority"}},"datasets":[{{"id":"neutral-registry","title":"Neutral Registry Dataset","owner":"Package Test Publisher","status":"active"}}],"dataServices":[{{"id":"neutral-registry-data-service","title":"Neutral Registry Catalog","endpointUrl":"https://package.example.test","servesDatasets":["neutral-registry"]}}]}},"modules":{{"core":{{"version":"1","digest":"{module_digest}"}}}}}}"#
    )
    .into_bytes()
}

fn module_bytes(classification: &str) -> Vec<u8> {
    format!(
        r#"{{"apiVersion":"id.registrystack.org/formats/breg/module/v1alpha1","kind":"BRegModule","id":"core","version":"1","recordTypes":{{"record":{{"primaryDataset":"neutral-registry","route":"records","mutationMode":"create-only","fields":[{{"id":"code","type":"string","maximumLength":16,"classification":"{classification}"}}],"accessProfiles":{{"reader":{{"requiredScopes":"unrestricted","rowBoundaries":"unrestricted","principalClaim":"principal","operations":["get","list"],"readableFields":["code"]}}}}}}}}}}"#
    )
    .into_bytes()
}

fn run(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .env_remove("REGISTRY_STACK_POSTURE")
        .args(arguments)
        .output()
        .expect("bregctl starts")
}

fn json_stdout(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).expect("stdout is JSON")
}

fn path(path: &Path) -> &str {
    path.to_str().expect("test path is UTF-8")
}

struct PublishedPackage {
    package: PathBuf,
}

fn draft(arguments: &[&str]) -> Output {
    let mut command = vec!["--format", "json", "migration", "draft"];
    command.extend_from_slice(arguments);
    run(&command)
}

fn refusal_code(output: &Output) -> String {
    assert!(!output.status.success(), "{output:?}");
    json_stdout(output)["diagnostics"][0]["code"]
        .as_str()
        .expect("the refusal names a code")
        .to_owned()
}

#[test]
fn a_change_that_needs_sql_is_refused_before_any_database_access() {
    let directory = TestDirectory::create();
    let baseline = publish_package(&directory.path, "baseline", "internal");
    let module = String::from_utf8(module_bytes("internal"))
        .expect("module is UTF-8")
        .replacen(r#""id":"code""#, r#""id":"label""#, 1)
        .replacen(
            r#""readableFields":["code"]"#,
            r#""readableFields":["label"]"#,
            1,
        );
    let removal = write_project_with_module(&directory.path, "removal", module.into_bytes());
    let output = directory.path.join("reviewed");

    let refused = draft(&[
        path(&removal),
        "--baseline-package",
        path(&baseline.package),
        "--runtime-config",
        UNREAD_RUNTIME_CONFIG,
        "--output",
        path(&output),
        "--module",
        "core",
        "--id",
        "label-rename",
    ]);
    assert_eq!(refusal_code(&refused), "migration.draft.sql-required");
    let message = json_stdout(&refused)["diagnostics"][0]["message"]
        .as_str()
        .expect("message is text")
        .to_owned();
    assert!(message.contains("field-removed"), "{message}");
    assert!(!output.exists(), "a refusal writes nothing");
}

#[test]
fn a_project_with_nothing_to_review_is_refused() {
    let directory = TestDirectory::create();
    let baseline = publish_package(&directory.path, "baseline", "internal");
    let unchanged = write_project(&directory.path, "unchanged", "internal");
    let output = directory.path.join("reviewed");

    let refused = draft(&[
        path(&unchanged),
        "--baseline-package",
        path(&baseline.package),
        "--runtime-config",
        UNREAD_RUNTIME_CONFIG,
        "--output",
        path(&output),
        "--module",
        "core",
        "--id",
        "nothing",
    ]);
    assert_eq!(refusal_code(&refused), "migration.draft.nothing-to-review");
    assert!(!output.exists(), "a refusal writes nothing");
}

#[test]
fn an_unknown_module_is_refused() {
    let directory = TestDirectory::create();
    let baseline = publish_package(&directory.path, "baseline", "internal");
    let widening = write_project(&directory.path, "widening", "public");
    let output = directory.path.join("reviewed");

    let refused = draft(&[
        path(&widening),
        "--baseline-package",
        path(&baseline.package),
        "--runtime-config",
        UNREAD_RUNTIME_CONFIG,
        "--output",
        path(&output),
        "--module",
        "no-such-module",
        "--id",
        "widen",
    ]);
    assert_eq!(refusal_code(&refused), "migration.draft.module-unknown");
    assert!(!output.exists(), "a refusal writes nothing");
}

#[test]
fn an_existing_reviewed_migration_is_never_overwritten() {
    let directory = TestDirectory::create();
    let baseline = publish_package(&directory.path, "baseline", "internal");
    let widening = write_project(&directory.path, "widening", "public");
    let output = directory.path.join("reviewed");
    let existing = output.join("modules/core/migrations/widen");
    fs::create_dir_all(&existing).expect("the earlier migration directory creates");
    fs::write(existing.join("descriptor.json"), b"reviewed by hand")
        .expect("the earlier descriptor writes");

    let refused = draft(&[
        path(&widening),
        "--baseline-package",
        path(&baseline.package),
        "--runtime-config",
        UNREAD_RUNTIME_CONFIG,
        "--output",
        path(&output),
        "--module",
        "core",
        "--id",
        "widen",
    ]);
    assert_eq!(refusal_code(&refused), "migration.draft.output-exists");
    assert_eq!(
        fs::read(existing.join("descriptor.json")).expect("the descriptor still reads"),
        b"reviewed by hand"
    );
    assert!(!existing.join("rehearsal.json").exists());
}

#[test]
fn identifiers_and_paths_are_checked_before_the_project_is_read() {
    let directory = TestDirectory::create();
    let baseline = publish_package(&directory.path, "baseline", "internal");
    let widening = write_project(&directory.path, "widening", "public");
    let output = directory.path.join("reviewed");

    let bad_id = draft(&[
        path(&widening),
        "--baseline-package",
        path(&baseline.package),
        "--runtime-config",
        UNREAD_RUNTIME_CONFIG,
        "--output",
        path(&output),
        "--module",
        "core",
        "--id",
        "Not A Local Id",
    ]);
    assert_eq!(refusal_code(&bad_id), "migration.draft.id-invalid");

    let relative_output = draft(&[
        path(&widening),
        "--baseline-package",
        path(&baseline.package),
        "--runtime-config",
        UNREAD_RUNTIME_CONFIG,
        "--output",
        "reviewed",
        "--module",
        "core",
        "--id",
        "widen",
    ]);
    assert_eq!(
        refusal_code(&relative_output),
        "migration.draft.output-invalid"
    );

    // Every input is required: a missing --id is a usage error.
    let usage = run(&[
        "migration",
        "draft",
        path(&widening),
        "--baseline-package",
        path(&baseline.package),
        "--runtime-config",
        UNREAD_RUNTIME_CONFIG,
        "--output",
        path(&output),
        "--module",
        "core",
    ]);
    assert_eq!(usage.status.code(), Some(2), "{usage:?}");
}
