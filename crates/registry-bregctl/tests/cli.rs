// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeMap;
use std::fs;
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};

use registry_breg::compiler::{
    compile_project, module_digest, module_digest_with_assets, CompileProfile,
};
use registry_breg::contract::{
    parse_module_json, parse_module_yaml, parse_project_yaml, ModuleAssetSource,
};
use registry_breg::fixtures::{
    validate_fixture_journeys, validate_schema_test_receipt_for_package,
};
use registry_breg::package::{
    load_predecessor_package, prepare_package, PackageBuildRequest, PackageFileRole,
    PackageLoadContext, PackageMigrationPlanInput, PackageModuleSource, PackageSourceFile,
    PreparedPackage, FIXTURE_JOURNEYS_PATH, MAX_PACKAGE_SOURCE_FILE_BYTES,
};
use registry_platform_canonical_json::canonicalize_json;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

static TEMPORARY_COUNTER: AtomicU64 = AtomicU64::new(0);

#[path = "cli/history_erase.rs"]
mod history_erase_tests;

#[path = "cli/history_rebaseline.rs"]
mod history_rebaseline_tests;

#[path = "cli/reviewed_migrations.rs"]
mod reviewed_migration_tests;

#[path = "cli/module_consent.rs"]
mod module_consent_tests;

#[path = "cli/file_check.rs"]
mod file_check_tests;

#[test]
fn check_reports_native_patterns_as_unverified_until_postgres_schema_test() {
    let source = String::from_utf8(authoring_fixture().to_vec())
        .unwrap()
        .replace(
            "        maxLength: 64",
            "        maxLength: 64\n        pattern: '[native-pattern-expression-canary'",
        );
    let project = TestProject::from_registry_source(source.as_bytes());
    let output = bregctl(&["--format", "json", "check", path(project.path())]);
    assert!(output.status.success(), "{output:?}");
    let report = json_stdout(&output);
    let finding = report["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .find(|finding| finding["code"] == "breg.field.pattern-unverified-offline")
        .expect("offline success must identify native syntax as unverified");
    assert_eq!(finding["severity"], "warning");
    assert_check_diagnostic(finding, Some("RegistryProject"));
    let pointer = finding["path"].as_str().unwrap();
    assert!(
        pointer.starts_with("/entities/") && pointer.ends_with("/pattern"),
        "{finding}"
    );
    assert_eq!(
        finding["source"]["file"],
        project.path().join("registry.yaml").display().to_string()
    );
    assert!(finding["source"]["line"].as_u64().is_some(), "{finding}");
    assert!(finding["message"]
        .as_str()
        .unwrap()
        .contains("bregctl test"));
    assert!(finding["suggestedAction"]
        .as_str()
        .unwrap()
        .contains("bregctl test"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("native-pattern-expression-canary"));

    let denied = bregctl(&[
        "--format",
        "json",
        "check",
        path(project.path()),
        "--deny-warnings",
    ]);
    assert_eq!(denied.status.code(), Some(1));
    let denied_report = json_stdout(&denied);
    assert_eq!(denied_report["ok"], false);
    let denied_finding = denied_report["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .find(|diagnostic| diagnostic["code"] == "breg.field.pattern-unverified-offline")
        .expect("denied warning remains in the refusal diagnostics");
    assert_eq!(denied_finding, finding);
}

#[test]
fn explain_access_names_membership_constraints_instead_of_unrestricted_rows() {
    let project = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/breg/fixtures/organization-membership-access")
        .canonicalize()
        .unwrap();
    let output = bregctl(&["explain", "access", path(&project)]);
    assert!(output.status.success(), "{output:?}");
    let human = String::from_utf8(output.stdout).unwrap();
    let member = human
        .split("profile member")
        .nth(1)
        .expect("the member profile is explained")
        .split("profile steward")
        .next()
        .unwrap();
    let aligned = member.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(aligned.contains("row restrictions (all) governed membership required"));
    assert!(aligned.contains("membership restrictions (all)"));
    assert!(aligned.contains("membershipEntity"));
    assert!(!aligned.contains("row restrictions (all) unrestricted"));
}

#[test]
fn explain_access_states_consent_gates_recipients_and_the_ungated_client() {
    let project = TestProject::from_registry_source(include_bytes!(
        "../../registry-breg/tests/fixtures/consent-access.yaml"
    ));
    let path = project.path().to_str().unwrap();
    let output = bregctl(&["explain", "access", path]);
    assert!(output.status.success(), "{output:?}");
    let human = String::from_utf8(output.stdout).unwrap();
    let aligned = human.split_whitespace().collect::<Vec<_>>().join(" ");
    for expected in [
        "breg.access.consent-ungated-client entities[id=person].accessProfiles[id=steward].requesterClients",
        "consent required (all) [{\"on\":\"id\",\"record\":\"consent-decision\"}]",
        "Consent:",
        "permission food-targeting over person",
        "whose scope is `food-targeting`",
        "record consent-decision",
        "scope food-targeting",
        "max duration P365D",
        "readable fields district (internal), given-name (restricted)",
        "issuing actions record-consent (steward)",
        "client wfp-scope wfp: referral-network, wfp",
        "group referral-network wfp, ngo-alpha: ngo-alpha-portal, wfp-scope",
        "organization ngo-beta retired",
        "consent issuers record-consent (steward)",
        "retiredConsentScopes",
    ] {
        assert!(aligned.contains(expected), "{expected:?} in {human}");
    }

    let scenario = project.path().join("scenario.json");
    fs::write(
        &scenario,
        serde_json::to_vec(&json!({
            "entity": "person",
            "accessProfile": "food-targeting",
            "operation": "get",
            "claims": {
                "principalClaim": "principal",
                "principal": "synthetic-caseworker",
                "scopes": ["records:read"],
                "purpose": "food-assistance",
                "actorKind": "service",
                "requesterClient": "wfp-scope"
            }
        }))
        .unwrap(),
    )
    .unwrap();
    let output = bregctl(&[
        "explain",
        "access",
        path,
        "--scenario",
        scenario.to_str().unwrap(),
    ]);
    assert!(output.status.success(), "{output:?}");
    let human = String::from_utf8(output.stdout).unwrap();
    let aligned = human.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        aligned.contains("Synthetic profile admission: allowed"),
        "{human}"
    );
    assert!(
        aligned.contains("recipients referral-network, wfp"),
        "{human}"
    );

    fs::write(&scenario, br#"{"entity":"person","accessProfile":"food-targeting","operation":"get","claims":{"requester":"wfp-scope"}}"#).unwrap();
    let output = bregctl(&[
        "--format",
        "json",
        "explain",
        "access",
        path,
        "--scenario",
        scenario.to_str().unwrap(),
    ]);
    assert!(!output.status.success());
    let message = json_stdout(&output)["diagnostics"][0]["message"].clone();
    assert!(
        message
            .as_str()
            .unwrap()
            .contains("actorKind, requesterClient"),
        "{message}"
    );
}

#[test]
fn missing_action_script_identifies_action_and_safe_relative_path() {
    let project = TestProject::from_registry_source(include_bytes!(
        "../../../products/breg/acceptance/person-registration-rhai/registry.yaml"
    ));
    fs::create_dir(project.path().join("scripts")).unwrap();
    fs::write(
        project.path().join("scripts/register-person-with-registration.rhai"),
        include_bytes!("../../../products/breg/acceptance/person-registration-rhai/scripts/register-person-with-registration.rhai"),
    )
    .unwrap();
    let output = bregctl(&["--format", "json", "check", path(project.path())]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let report = json_stdout(&output);
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(diagnostic["code"], "breg.source.planner-asset-missing");
    assert_eq!(diagnostic["path"], "/actions/0/handler/script");
    assert_eq!(
        diagnostic["source"]["file"],
        project.path().join("registry.yaml").display().to_string()
    );
    assert!(diagnostic["message"]
        .as_str()
        .unwrap()
        .contains("scripts/register-person.rhai"));
    assert_check_diagnostic(diagnostic, Some("RegistryProject"));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("fn handle"));
}

#[test]
fn access_review_example_explains_simulates_and_refuses_footguns_without_live_data() {
    let project = TestProject::from_registry_source(include_bytes!(
        "../../../products/breg/examples/access-review/registry.yaml"
    ));
    let path = project.path().to_str().unwrap();
    let check = bregctl(&["--format", "json", "check", path, "--deny-warnings"]);
    assert!(check.status.success(), "{check:?}");
    let human = bregctl(&["explain", "access", path]);
    assert!(human.status.success());
    let text = String::from_utf8(human.stdout).unwrap();
    for expected in [
        "required scopes (all)",
        "allowed purposes (any)",
        "row restrictions (all)",
        "  entity record (internal)\n",
        "    profile district-reader\n",
        "principal claim         registry_principal",
    ] {
        assert!(text.contains(expected), "{text}");
    }
    let scenario_path = project.path().join("scenario.json");
    for (source, expected, reason) in [
        (
            &include_bytes!("../../../products/breg/examples/access-review/allowed.json")[..],
            true,
            "profile_requirements_satisfied",
        ),
        (
            &include_bytes!("../../../products/breg/examples/access-review/missing-scope.json")[..],
            false,
            "required_scope_missing",
        ),
    ] {
        fs::write(&scenario_path, source).unwrap();
        let output = bregctl(&[
            "--format",
            "json",
            "explain",
            "access",
            path,
            "--scenario",
            scenario_path.to_str().unwrap(),
        ]);
        assert!(output.status.success(), "{output:?}");
        let report = json_stdout(&output);
        assert_eq!(report["explanation"]["admitted"], expected);
        assert_eq!(report["explanation"]["reason"], reason);
        assert_eq!(report["explanation"]["recordAccess"], "not_evaluated");
        assert!(!String::from_utf8_lossy(&output.stdout).contains("synthetic-reader"));
        assert!(!String::from_utf8_lossy(&output.stdout).contains("synthetic-district"));
    }
    for malformed in [
        r#"{"entity":"record","entity":"other","secret":"private-scenario-canary"}"#,
        r#"{"unexpected":"private-scenario-canary"}"#,
    ] {
        fs::write(&scenario_path, malformed).unwrap();
        let output = bregctl(&[
            "--format",
            "json",
            "explain",
            "access",
            path,
            "--scenario",
            scenario_path.to_str().unwrap(),
        ]);
        assert!(!output.status.success());
        assert!(!String::from_utf8_lossy(&output.stdout).contains("private-scenario-canary"));
        assert!(!String::from_utf8_lossy(&output.stderr).contains("private-scenario-canary"));
    }
    let mut source: Value = serde_norway::from_slice(include_bytes!(
        "../../../products/breg/examples/access-review/registry.yaml"
    ))
    .unwrap();
    source["accessProfiles"][0]["permissions"][0]["rowBoundaries"] = serde_json::json!([]);
    fs::write(
        project.path().join("registry.yaml"),
        serde_json::to_vec(&source).unwrap(),
    )
    .unwrap();
    let refused = bregctl(&["--format", "json", "check", path]);
    assert!(!refused.status.success());
    assert!(json_stdout(&refused)["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .any(|d| d["code"] == "breg.access.requirements-row-boundary-missing"));
    source["entities"][0]
        .as_object_mut()
        .unwrap()
        .remove("accessRequirements");
    fs::write(
        project.path().join("registry.yaml"),
        serde_json::to_vec(&source).unwrap(),
    )
    .unwrap();
    assert!(bregctl(&["check", path]).status.success());
    assert!(!bregctl(&["check", path, "--deny-warnings"])
        .status
        .success());
}
const PACKAGE_INSTANCE: &str = "verify-instance";
const PACKAGE_DATABASE: &str = "verify-database";
const PACKAGE_SOURCE_REVISION: &str = "verify-compiler-source";
const PACKAGE_VALUE_CANARY: &str = "verify-path-trust-secret-sql-canary";
const VERIFY_RUNTIME_DATABASE_SECRET_CANARY: &str = "VERIFY_RUNTIME_DATABASE_SECRET_IS_NOT_OPENED";
const VERIFY_MIGRATION_DATABASE_SECRET_CANARY: &str =
    "VERIFY_MIGRATION_DATABASE_SECRET_IS_NOT_OPENED";
const SCHEMA_TEST_AUTHORED_SOURCE_CEILING_BYTES: usize = 1024 * 1024;
const PACKAGE_FIXTURE_JOURNEYS: &[u8] =
    br#"apiVersion: id.registrystack.org/formats/breg/journeys/v1
kind: BRegJourneys
journeys:
  - id: package-record-list
    steps:
      - id: list-records
        entity: record
        accessProfile: reader
        claims: {principal: package-reader}
        request: {type: list}
        expect: {outcome: success, status: 200, count: 0}
"#;
const DATA_FIXTURE_JOURNEYS: &[u8] = br#"apiVersion: id.registrystack.org/formats/breg/journeys/v1
kind: BRegJourneys
journeys:
  - id: data-record-list
    steps:
      - id: list-records
        entity: record
        accessProfile: operator
        claims: {principal: data-operator}
        request: {type: list}
        expect: {outcome: success, status: 200, count: 0}
"#;

struct TestProject {
    root: PathBuf,
}

impl TestProject {
    fn asset_fixture() -> Self {
        let project = Self::from_registry_source(asset_fixture());
        // The acceptance project locks a module, so its source travels with the
        // registry document; a lock without a source is a deleted module.
        let module_directory = project.path().join("modules/asset-site-placement-core");
        fs::create_dir_all(&module_directory).expect("module directory is created");
        fs::write(module_directory.join("module.yaml"), asset_fixture_module())
            .expect("module source is copied");
        project
    }

    fn from_registry_source(source: &[u8]) -> Self {
        let temporary_parent = std::env::current_dir().expect("current directory is available");
        let root = temporary_parent.join(format!(
            "bregctl-test-{}-{}",
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
    runtime_config: PathBuf,
    package_digest: String,
}

impl RuntimePackageFixture {
    fn production(bind: SocketAddr) -> Self {
        Self::production_with_module(bind, package_module_bytes())
    }

    fn production_with_module(bind: SocketAddr, module_bytes: Vec<u8>) -> Self {
        let directory = TestProject::from_registry_source(authoring_fixture());
        let module = parse_module_json(&module_bytes).expect("package module parses");
        let project_bytes = package_project_bytes(&module_digest(&module));
        let prepared =
            prepare_package(PackageBuildRequest {
                from_package_digest: None,
                compiler_source_revision: PACKAGE_SOURCE_REVISION.to_owned(),
                schema_fingerprint:
                    "sha256:2222222222222222222222222222222222222222222222222222222222222222"
                        .to_owned(),
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
                    bytes: PACKAGE_FIXTURE_JOURNEYS.to_vec(),
                },
                migration_plan: PackageMigrationPlanInput::InitialCompiledDdl,
            })
            .expect("package prepares");
        validate_fixture_journeys(PACKAGE_FIXTURE_JOURNEYS, prepared.registry())
            .expect("package fixture journeys resolve against the packaged registry");
        let package = directory.path().join("package");
        let package_digest = prepared
            .package_digest()
            .expect("the package digest derives");
        prepared
            .publish_to_directory(&package)
            .expect("package publishes");
        let runtime_config = write_runtime_config(directory.path(), &package, bind);
        Self {
            directory,
            package,
            runtime_config,
            package_digest,
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
    include_bytes!("../../../products/breg/acceptance/asset-site-placement/registry.yaml")
}

fn asset_fixture_module() -> &'static [u8] {
    include_bytes!(
        "../../../products/breg/acceptance/asset-site-placement/modules/asset-site-placement-core/module.yaml"
    )
}

fn authoring_fixture() -> &'static [u8] {
    br#"apiVersion: registry.registrystack.org/v1alpha1
kind: RegistryProject
registry:
  id: cli-authoring-fixture
  version: "1"
  defaultLanguage: en
  canonicalBaseIri: https://cli-authoring-fixture.example.test
entities:
  - id: record
    primaryDataset: test-dataset
    route: records
    mutationMode: create_only
    fields:
      - id: code
        type: string
        maxLength: 64
        classification: internal
"#
}

fn action_fixture() -> &'static [u8] {
    br#"apiVersion: registry.registrystack.org/v1alpha1
kind: RegistryProject
registry:
  id: action-fixture
  version: "1"
  defaultLanguage: en
  canonicalBaseIri: https://action-fixture.example.test
entities:
  - id: household
    primaryDataset: test-dataset
    route: households
    mutationMode: mutable
    fields:
      - {id: household-code, apiName: householdCode, type: string, required: true, maxLength: 64, classification: internal}
      - {id: contact-person, apiName: contactPerson, type: reference, target: person, required: false, classification: restricted}
  - id: person
    primaryDataset: test-dataset
    route: people
    mutationMode: mutable
    fields:
      - {id: person-code, apiName: personCode, type: string, required: true, maxLength: 64, classification: restricted}
      - {id: legal-name, apiName: legalName, type: string, required: true, maxLength: 160, classification: restricted}
  - id: group-membership
    primaryDataset: test-dataset
    route: group-memberships
    mutationMode: create_only
    fields:
      - {id: person, type: reference, target: person, required: true, classification: restricted}
      - {id: household, type: reference, target: household, required: true, classification: restricted}
actions:
  - id: register-household-contact
    inputs:
      - {id: household, apiName: householdId, type: reference, target: household, required: true, classification: restricted}
      - {id: person-code, apiName: personCode, type: string, required: true, maxLength: 64, classification: restricted}
      - {id: legal-name, apiName: legalName, type: string, required: true, maxLength: 160, classification: restricted}
    effects:
      - id: person
        target: {entity: person}
        operation: create
        set:
          person-code: {fromField: person-code}
          legal-name: {fromField: legal-name}
      - id: membership
        target: {entity: group-membership}
        operation: create
        set:
          person: {fromEffect: person}
          household: {fromField: household}
      - id: household
        target: {fromField: household}
        operation: patch
        set:
          contact-person: {fromEffect: person}
accessProfiles:
  - id: contact-registrar
    default: true
    principalClaim: private_claim_name
    requiredScopes: [registry:contact:register]
    requiredPurposes: [contact-registration]
    permissions:
      - action: register-household-contact
        operations: [invoke]
        targets:
          - {entity: household, rowBoundaries: []}
          - {entity: person, rowBoundaries: []}
          - {entity: group-membership, rowBoundaries: []}
        results: [person, membership, household]
  - id: contact-auditor
    principalClaim: other_private_claim
    requiredScopes: [registry:contact:audit]
    requiredPurposes: [contact-audit]
    permissions:
      - action: register-household-contact
        operations: [invoke]
        targets:
          - {entity: household, rowBoundaries: []}
          - {entity: person, rowBoundaries: []}
          - {entity: group-membership, rowBoundaries: []}
        results: [household]
"#
}

/// Unlike `action_fixture`, whose access profiles grant only action permissions
/// (see `explain_access_includes_action_only_grants_and_target_reach`), this project
/// grants both an entity-level operation and an action invocation, so `explain routes`
/// serves a genuinely mixed list: entity routes and action routes side by side.
fn mixed_entity_and_action_route_fixture() -> &'static [u8] {
    br#"apiVersion: registry.registrystack.org/v1alpha1
kind: RegistryProject
registry:
  id: mixed-route-fixture
  version: "1"
  defaultLanguage: en
  canonicalBaseIri: https://mixed-route-fixture.example.test
entities:
  - id: household
    primaryDataset: test-dataset
    route: households
    mutationMode: mutable
    fields:
      - {id: household-code, apiName: householdCode, type: string, required: true, maxLength: 64, classification: internal}
actions:
  - id: archive-household
    inputs:
      - {id: household, apiName: householdId, type: reference, target: household, required: true, classification: restricted}
      - {id: household-code, apiName: householdCode, type: string, required: true, maxLength: 64, classification: internal}
    effects:
      - id: household
        target: {fromField: household}
        operation: patch
        set:
          household-code: {fromField: household-code}
accessProfiles:
  - id: household-reader
    default: true
    principalClaim: registry_principal
    requiredPurposes: [household-read]
    permissions:
      - entity: household
        rowBoundaries: []
        operations: [get, list]
        readableFields: [household-code]
        writableFields: []
  - id: household-archiver
    principalClaim: registry_principal
    requiredPurposes: [household-archive]
    permissions:
      - action: archive-household
        operations: [invoke]
        targets:
          - {entity: household, rowBoundaries: []}
        results: [household]
"#
}

fn packaging_project() -> TestProject {
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
    project
}

fn prepare_packaging_candidate(project: &TestProject, schema_fingerprint: &str) -> PreparedPackage {
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
        from_package_digest: None,
        compiler_source_revision: identity.source_revision.clone(),
        schema_fingerprint: schema_fingerprint.to_owned(),
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
    source_closure.update(b"breg-schema-test-source-closure-v2\0");
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
    for file in &manifest.files {
        if matches!(
            file.role,
            PackageFileRole::ReviewedMigrationDescriptor
                | PackageFileRole::ReviewedMigrationStepSql
                | PackageFileRole::ReviewedMigrationAssertionSql
                | PackageFileRole::MigrationRehearsalReceipt
                | PackageFileRole::MigrationRehearsalFixture
        ) {
            digest_part(
                &mut source_closure,
                file.path.as_bytes(),
                file.sha256.as_bytes(),
            );
        }
    }
    let mut receipt = json!({
        "apiVersion": "id.registrystack.org/formats/breg/schema-test-receipt/v2",
        "kind": "BRegSchemaTestReceipt",
        "registryRevision": prepared.registry().revision(),
        "projectSourceRevision": project_identity.source_revision,
        "compilerSourceRevision": manifest.compiler.source_revision,
        "sourceClosureSha256": prefixed_digest(source_closure.finalize().as_slice()),
        "migrationPlanSha256": sha256_prefixed(migration_plan),
        "postgresMajor": 16,
        "targetManagedSchemaFingerprint": manifest.schema_fingerprint,
        "successfulJourneyIds": journey_ids,
        "journeyFileSha256": sha256_prefixed(journeys),
    });
    if let Some(prior) = &manifest.migration_plan.from_package_digest {
        receipt
            .as_object_mut()
            .expect("receipt is an object")
            .insert("priorPackageDigest".to_owned(), json!(prior));
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

fn bregctl(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .args(arguments)
        .output()
        .expect("bregctl starts")
}

fn package_candidate_command(
    project: &TestProject,
    schema_fingerprint: &str,
    receipt: &Path,
    output: &Path,
) -> Output {
    bregctl(&[
        "--format",
        "json",
        "package",
        path(project.path()),
        "--schema-fingerprint",
        schema_fingerprint,
        "--test-receipt",
        path(receipt),
        "--output",
        path(output),
    ])
}

fn test_candidate_command(
    project: &TestProject,
    runtime_config: &Path,
    credentials: &Path,
    output: &Path,
) -> Output {
    bregctl(&[
        "--format",
        "json",
        "test",
        path(project.path()),
        "--runtime-config",
        path(runtime_config),
        "--credentials",
        path(credentials),
        "--output",
        path(output),
    ])
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

/// A `bregctl check` diagnostic in the shared shape (CFG-DIAG-1): a JSON
/// pointer path, an `error` or `warning` severity, the document's kind as
/// the artifact, and a sentence the reader can act on.
fn assert_check_diagnostic(diagnostic: &Value, artifact: Option<&str>) {
    let object = diagnostic.as_object().expect("diagnostic is an object");
    for key in object.keys() {
        assert!(
            [
                "severity",
                "code",
                "artifact",
                "path",
                "message",
                "suggestedAction",
                "source",
                "related",
            ]
            .contains(&key.as_str()),
            "{key} in {diagnostic}"
        );
    }
    assert!(
        matches!(diagnostic["severity"].as_str(), Some("error" | "warning")),
        "{diagnostic}"
    );
    let pointer = diagnostic["path"].as_str().expect("path is a string");
    assert!(
        pointer.is_empty() || pointer.starts_with('/'),
        "{diagnostic}"
    );
    assert!(
        diagnostic["suggestedAction"]
            .as_str()
            .is_some_and(|action| action.ends_with('.')),
        "{diagnostic}"
    );
    match artifact {
        Some(artifact) => assert_eq!(diagnostic["artifact"], artifact),
        None => assert!(diagnostic.get("artifact").is_none(), "{diagnostic}"),
    }
}

#[test]
fn authored_project_findings_use_the_tool_finding_schema() {
    let project = TestProject::from_registry_source(authoring_fixture());
    let output = bregctl(&[
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
    let diagnostics = report["diagnostics"]
        .as_array()
        .expect("diagnostics is an array");
    assert!(diagnostics
        .iter()
        .any(|finding| finding["code"] == "breg.package.identity-missing"));
    for finding in diagnostics {
        assert_eq!(finding["severity"], "warning", "{finding}");
        assert_check_diagnostic(finding, Some("RegistryProject"));
    }
}

#[test]
fn production_profile_refuses_missing_package_closure() {
    let project = TestProject::from_registry_source(authoring_fixture());
    let output = bregctl(&[
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
    assert!(codes.contains(&"breg.package.identity-required"));
    for diagnostic in report["diagnostics"]
        .as_array()
        .expect("diagnostics is an array")
    {
        assert_check_diagnostic(diagnostic, Some("RegistryProject"));
    }
}

#[test]
fn generation_is_byte_stable_and_reports_the_exact_artifact_inventory() {
    let project = TestProject::asset_fixture();
    let first = project.path().join("first-output");
    let second = project.path().join("second-output");
    let first_output = bregctl(&[
        "--format",
        "json",
        "generate",
        "schemas",
        project.path().to_str().expect("path is UTF-8"),
        "--output",
        first.to_str().expect("path is UTF-8"),
    ]);
    let second_output = bregctl(&[
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

    let output = bregctl(&[
        "--format",
        "json",
        "init",
        destination.to_str().expect("path is UTF-8"),
    ]);

    assert!(output.status.success(), "{output:?}");
    for relative in [
        "README.md",
        "modules/record-notes/module.yaml",
        "registry.yaml",
        "runtime.example.yaml",
        "tests/journeys.yaml",
    ] {
        assert!(
            destination.join(relative).is_file(),
            "init writes {relative}"
        );
    }
    let registry =
        fs::read_to_string(destination.join("registry.yaml")).expect("initialized project reads");
    assert!(registry.contains("manifestProjection:"));
    assert!(registry.contains("modules:"));
    assert!(registry.contains("vocabularies:"));
    assert!(registry.contains("declare `hooks`"));
    assert!(registry.contains("hook declares `phase: after`"));
    assert!(registry.contains("{kind: url, destinationId: registry-events}"));
    assert!(!registry.contains("declare `events`"));
    let journeys = fs::read_to_string(destination.join("tests/journeys.yaml"))
        .expect("initialized fixture journeys read");
    assert!(journeys.contains("entity: record"));
    assert!(journeys.contains("accessProfile: operator"));
    assert!(journeys.contains("scopes: [registry:generic:operate]"));
    assert!(journeys.contains("purpose: registry-operations"));
    assert!(journeys.contains("{recordCapture: example-group}"));
    assert!(journeys.contains("status: active"));
    assert!(registry.contains("type: reference"));
    assert!(registry.contains("type: vocabulary-code"));
    assert!(registry.contains("id: record-group-code-unique"));
    assert!(registry.contains("id: record-code-unique"));
    assert!(!journeys.contains("token"));
    let initialized_project = parse_project_yaml(
        &fs::read(destination.join("registry.yaml")).expect("initialized project bytes read"),
    )
    .expect("initialized project parses");
    assert!(initialized_project.manifest_projection.is_some());
    assert!(initialized_project.package.is_some());
    let module = parse_module_yaml(
        &fs::read(destination.join("modules/record-notes/module.yaml"))
            .expect("initialized module bytes read"),
    )
    .expect("initialized module parses");
    let locks = &initialized_project.modules;
    assert_eq!(locks.len(), 1);
    assert_eq!(locks[0].id, module.id);
    assert_eq!(locks[0].version, module.version);
    assert_eq!(
        locks[0].digest.as_deref(),
        Some(module_digest(&module).as_str())
    );
    for profile in [CompileProfile::Authoring, CompileProfile::Production] {
        let compiled =
            compile_project(&initialized_project, std::slice::from_ref(&module), profile)
                .expect("initialized project compiles");
        validate_fixture_journeys(journeys.as_bytes(), &compiled)
            .expect("initialized fixture journeys resolve against the compiled project");
    }
    let report = json_stdout(&output);
    assert_eq!(report["ok"], true);
    assert_eq!(report["command"], "init");
    let findings = report["findings"]
        .as_array()
        .expect("findings is an array")
        .iter()
        .map(|finding| {
            finding["code"]
                .as_str()
                .expect("code is a string")
                .to_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        findings,
        vec![
            "breg.access.profile-unrestricted-collection",
            "breg.access.profile-unrestricted-rows"
        ]
    );
    let artifacts = report["artifacts"]
        .as_array()
        .expect("artifacts is an array")
        .iter()
        .map(|artifact| {
            (
                artifact["path"].as_str().expect("path is a string"),
                artifact["mediaType"]
                    .as_str()
                    .expect("media type is a string"),
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(
        artifacts,
        vec![
            ("README.md", "text/markdown"),
            ("dev-clients.yaml", "text/yaml"),
            ("modules/record-notes/module.yaml", "text/yaml"),
            ("registry.yaml", "text/yaml"),
            ("runtime.example.yaml", "text/yaml"),
            ("tests/journeys.yaml", "text/yaml"),
        ]
    );

    let check = bregctl(&[
        "--format",
        "json",
        "check",
        destination.to_str().expect("path is UTF-8"),
    ]);
    assert!(check.status.success(), "{check:?}");
    let check_report = json_stdout(&check);
    assert_eq!(check_report["ok"], true);
    let warnings = check_report["diagnostics"]
        .as_array()
        .expect("diagnostics is an array");
    assert_eq!(warnings.len(), 2, "{check_report}");
    assert!(warnings
        .iter()
        .all(|warning| warning["severity"] == "warning"));

    let locked = bregctl(&[
        "--format",
        "json",
        "project",
        "lock",
        destination.to_str().expect("path is UTF-8"),
    ]);
    assert!(locked.status.success(), "{locked:?}");
    assert_eq!(json_stdout(&locked)["explanation"]["changed"], false);
    assert_eq!(
        fs::read_to_string(destination.join("registry.yaml")).expect("project rereads"),
        registry,
        "an immediate project lock leaves the initialized project byte-identical"
    );
}

#[test]
fn project_lock_writes_module_digests_and_is_idempotent() {
    let project = TestProject::from_registry_source(modular_project_without_locks());
    let module_directory = project.path().join("modules/core");
    fs::create_dir_all(&module_directory).expect("module directory creates");
    fs::write(
        module_directory.join("module.yaml"),
        modular_project_module(),
    )
    .expect("module source writes");
    let module = parse_module_yaml(modular_project_module()).expect("module parses");
    let expected_digest = module_digest(&module);

    let locked = bregctl(&["--format", "json", "project", "lock", path(project.path())]);

    assert!(locked.status.success(), "{locked:?}");
    assert!(locked.stderr.is_empty());
    let report = json_stdout(&locked);
    assert_eq!(report["command"], "project lock");
    assert_eq!(report["explanation"]["changed"], true);
    assert_eq!(report["explanation"]["modules"][0]["id"], "core");
    assert_eq!(report["explanation"]["modules"][0]["status"], "added");
    assert_eq!(
        report["explanation"]["modules"][0]["digest"],
        expected_digest
    );
    assert_eq!(report["artifacts"][0]["path"], "registry.yaml");
    let project_source = fs::read(project.path().join("registry.yaml")).expect("project reads");
    let parsed = parse_project_yaml(&project_source).expect("locked project parses");
    assert_eq!(parsed.modules.len(), 1);
    assert_eq!(parsed.modules[0].id, "core");
    assert_eq!(parsed.modules[0].version, "1");
    assert_eq!(
        parsed.modules[0].digest.as_deref(),
        Some(expected_digest.as_str())
    );

    let check = bregctl(&["--format", "json", "check", path(project.path())]);
    assert!(check.status.success(), "{check:?}");

    let second = bregctl(&["--format", "json", "project", "lock", path(project.path())]);
    assert!(second.status.success(), "{second:?}");
    let second_report = json_stdout(&second);
    assert_eq!(second_report["explanation"]["changed"], false);
    assert_eq!(
        second_report["explanation"]["modules"][0]["status"],
        "unchanged"
    );
    assert!(second_report.get("artifacts").is_none());

    let unchanged = bregctl(&["project", "lock", path(project.path())]);
    assert!(unchanged.status.success(), "{unchanged:?}");
    let rendered = String::from_utf8(unchanged.stdout).expect("lock report is UTF-8");
    assert!(
        rendered.starts_with("Locked the project modules.\n  revision  sha256:"),
        "a lock that wrote nothing counts no artifact: {rendered}"
    );

    let check_only = bregctl(&[
        "--format",
        "json",
        "project",
        "lock",
        path(project.path()),
        "--check",
    ]);
    assert!(check_only.status.success(), "{check_only:?}");
    assert_eq!(json_stdout(&check_only)["explanation"]["changed"], false);
}

#[test]
fn project_lock_check_refuses_stale_digest_without_rewriting() {
    let project = TestProject::from_registry_source(modular_project_without_locks());
    let module_directory = project.path().join("modules/core");
    fs::create_dir_all(&module_directory).expect("module directory creates");
    fs::write(
        module_directory.join("module.yaml"),
        modular_project_module(),
    )
    .expect("module source writes");
    let locked = bregctl(&["--format", "json", "project", "lock", path(project.path())]);
    assert!(locked.status.success(), "{locked:?}");
    let locked_project = fs::read(project.path().join("registry.yaml")).expect("project reads");

    fs::write(
        module_directory.join("module.yaml"),
        String::from_utf8(modular_project_module().to_vec())
            .expect("module is UTF-8")
            .replace("maxLength: 16", "maxLength: 17"),
    )
    .expect("module source changes");
    let stale = bregctl(&[
        "--format",
        "json",
        "project",
        "lock",
        path(project.path()),
        "--check",
    ]);

    assert_eq!(stale.status.code(), Some(1), "{stale:?}");
    assert!(stale.stderr.is_empty());
    let report = json_stdout(&stale);
    assert_eq!(report["diagnostics"][0]["code"], "breg.module.lock-stale");
    assert_tool_diagnostic(
        &report["diagnostics"][0],
        "registry_project",
        "update_module_locks",
    );
    assert_eq!(
        fs::read(project.path().join("registry.yaml")).expect("project rereads"),
        locked_project
    );
}

#[test]
fn project_lock_keeps_comments_written_inside_the_modules_block() {
    let project = TestProject::from_registry_source(
        br#"apiVersion: registry.registrystack.org/v1alpha1
kind: RegistryProject
registry:
  id: modular-lock-fixture
  version: "1"
  defaultLanguage: en
  canonicalBaseIri: https://modular-lock-fixture.example.test
modules:
  # The core module owns the record entity.
  - id: core
    version: "1"
    # Refreshed by project lock after every module edit.
    digest: sha256:1111111111111111111111111111111111111111111111111111111111111111
"#,
    );
    let module_directory = project.path().join("modules/core");
    fs::create_dir_all(&module_directory).expect("module directory creates");
    fs::write(
        module_directory.join("module.yaml"),
        modular_project_module(),
    )
    .expect("module source writes");
    let module = parse_module_yaml(modular_project_module()).expect("module parses");
    let expected_digest = module_digest(&module);

    let locked = bregctl(&["--format", "json", "project", "lock", path(project.path())]);

    assert!(locked.status.success(), "{locked:?}");
    let report = json_stdout(&locked);
    assert_eq!(report["explanation"]["changed"], true);
    assert_eq!(report["explanation"]["modules"][0]["status"], "updated");
    let rewritten =
        fs::read_to_string(project.path().join("registry.yaml")).expect("project reads");
    assert!(
        rewritten.contains("  # The core module owns the record entity."),
        "{rewritten}"
    );
    assert!(
        rewritten.contains("    # Refreshed by project lock after every module edit."),
        "{rewritten}"
    );
    let parsed = parse_project_yaml(rewritten.as_bytes()).expect("locked project parses");
    assert_eq!(
        parsed.modules[0].digest.as_deref(),
        Some(expected_digest.as_str())
    );

    let check_only = bregctl(&[
        "--format",
        "json",
        "project",
        "lock",
        path(project.path()),
        "--check",
    ]);
    assert!(check_only.status.success(), "{check_only:?}");
    assert_eq!(json_stdout(&check_only)["explanation"]["changed"], false);
}

#[test]
fn project_lock_replaces_the_modules_block_when_a_module_is_added() {
    let project = TestProject::from_registry_source(modular_project_without_locks());
    let core_directory = project.path().join("modules/core");
    fs::create_dir_all(&core_directory).expect("module directory creates");
    fs::write(core_directory.join("module.yaml"), modular_project_module())
        .expect("module source writes");
    let locked = bregctl(&["--format", "json", "project", "lock", path(project.path())]);
    assert!(locked.status.success(), "{locked:?}");

    let extra_directory = project.path().join("modules/extra");
    fs::create_dir_all(&extra_directory).expect("module directory creates");
    fs::write(
        extra_directory.join("module.yaml"),
        modular_project_extra_module(),
    )
    .expect("module source writes");

    let relocked = bregctl(&["--format", "json", "project", "lock", path(project.path())]);

    assert!(relocked.status.success(), "{relocked:?}");
    let report = json_stdout(&relocked);
    assert_eq!(report["explanation"]["changed"], true);
    assert_eq!(report["explanation"]["modules"][0]["id"], "core");
    assert_eq!(report["explanation"]["modules"][0]["status"], "unchanged");
    assert_eq!(report["explanation"]["modules"][1]["id"], "extra");
    assert_eq!(report["explanation"]["modules"][1]["status"], "added");
    let parsed =
        parse_project_yaml(&fs::read(project.path().join("registry.yaml")).expect("project reads"))
            .expect("locked project parses");
    assert_eq!(
        parsed
            .modules
            .iter()
            .map(|lock| lock.id.as_str())
            .collect::<Vec<_>>(),
        ["core", "extra"]
    );
    let core = parse_module_yaml(modular_project_module()).expect("core module parses");
    let extra = parse_module_yaml(modular_project_extra_module()).expect("extra module parses");
    assert_eq!(
        parsed.modules[0].digest.as_deref(),
        Some(module_digest(&core).as_str())
    );
    assert_eq!(
        parsed.modules[1].digest.as_deref(),
        Some(module_digest(&extra).as_str())
    );

    let check_only = bregctl(&[
        "--format",
        "json",
        "project",
        "lock",
        path(project.path()),
        "--check",
    ]);
    assert!(check_only.status.success(), "{check_only:?}");
    assert_eq!(json_stdout(&check_only)["explanation"]["changed"], false);
}

#[test]
fn project_lock_sorts_module_locks_authored_out_of_order() {
    let project = TestProject::from_registry_source(
        br#"apiVersion: registry.registrystack.org/v1alpha1
kind: RegistryProject
registry:
  id: modular-lock-fixture
  version: "1"
  defaultLanguage: en
  canonicalBaseIri: https://modular-lock-fixture.example.test
modules:
  - id: extra
    version: "1"
    digest: sha256:1111111111111111111111111111111111111111111111111111111111111111
  - id: core
    version: "1"
    digest: sha256:2222222222222222222222222222222222222222222222222222222222222222
"#,
    );
    for (id, source) in [
        ("core", modular_project_module()),
        ("extra", modular_project_extra_module()),
    ] {
        let directory = project.path().join("modules").join(id);
        fs::create_dir_all(&directory).expect("module directory creates");
        fs::write(directory.join("module.yaml"), source).expect("module source writes");
    }

    let locked = bregctl(&["--format", "json", "project", "lock", path(project.path())]);

    assert!(locked.status.success(), "{locked:?}");
    let parsed =
        parse_project_yaml(&fs::read(project.path().join("registry.yaml")).expect("project reads"))
            .expect("locked project parses");
    assert_eq!(
        parsed
            .modules
            .iter()
            .map(|lock| lock.id.as_str())
            .collect::<Vec<_>>(),
        ["core", "extra"],
        "a refresh sorts the lock entries so a later check has nothing left to change"
    );

    let check_only = bregctl(&[
        "--format",
        "json",
        "project",
        "lock",
        path(project.path()),
        "--check",
    ]);
    assert!(check_only.status.success(), "{check_only:?}");
    assert_eq!(json_stdout(&check_only)["explanation"]["changed"], false);
}

#[test]
fn check_refuses_a_deleted_or_renamed_module_source_like_the_lock_check() {
    for (case, break_source) in [
        (
            "breg.module.lock-source-missing",
            Box::new(|module_directory: &Path| {
                fs::remove_dir_all(module_directory).expect("module directory removes");
            }) as Box<dyn Fn(&Path)>,
        ),
        (
            "breg.source.module-id-mismatch",
            Box::new(|module_directory: &Path| {
                fs::write(
                    module_directory.join("module.yaml"),
                    String::from_utf8(modular_project_module().to_vec())
                        .expect("module is UTF-8")
                        .replace("id: core", "id: renamed"),
                )
                .expect("renamed module source writes");
            }),
        ),
    ] {
        let project = TestProject::from_registry_source(modular_project_without_locks());
        let module_directory = project.path().join("modules/core");
        fs::create_dir_all(&module_directory).expect("module directory creates");
        fs::write(
            module_directory.join("module.yaml"),
            modular_project_module(),
        )
        .expect("module source writes");
        let locked = bregctl(&["--format", "json", "project", "lock", path(project.path())]);
        assert!(locked.status.success(), "{locked:?}");

        break_source(&module_directory);

        let checked = bregctl(&["--format", "json", "check", path(project.path())]);
        let lock_checked = bregctl(&[
            "--format",
            "json",
            "project",
            "lock",
            path(project.path()),
            "--check",
        ]);

        assert_eq!(checked.status.code(), Some(1), "{case}: {checked:?}");
        assert_eq!(
            lock_checked.status.code(),
            Some(1),
            "{case}: {lock_checked:?}"
        );
        let report = json_stdout(&checked);
        assert_eq!(report["command"], "check");
        let diagnostic = &report["diagnostics"][0];
        assert_eq!(diagnostic["code"], case);
        // A missing module is a problem of the project's lock; a renamed one
        // is a problem of the module file.
        let artifact = if case == "breg.module.lock-source-missing" {
            "RegistryProject"
        } else {
            "BRegModule"
        };
        assert_check_diagnostic(diagnostic, Some(artifact));
        // The check places the lock check's refusal in the source; the code
        // and the sentence are the lock check's own.
        let lock_diagnostic = &json_stdout(&lock_checked)["diagnostics"][0];
        assert_eq!(diagnostic["code"], lock_diagnostic["code"], "{case}");
        assert_eq!(diagnostic["message"], lock_diagnostic["message"], "{case}");
    }
}

#[test]
fn project_lock_refuses_missing_locked_source_without_rendering_values() {
    const MODULE_CANARY: &str = "missing-module-canary";
    let project = TestProject::from_registry_source(
        format!(
            r#"apiVersion: registry.registrystack.org/v1alpha1
kind: RegistryProject
registry:
  id: modular-lock-missing
  version: "1"
  defaultLanguage: en
  canonicalBaseIri: https://modular-lock-missing.example.test
modules:
  - id: {MODULE_CANARY}
    version: "1"
    digest: sha256:1111111111111111111111111111111111111111111111111111111111111111
"#
        )
        .as_bytes(),
    );
    let original = fs::read(project.path().join("registry.yaml")).expect("project reads");

    let refused = bregctl(&["--format", "json", "project", "lock", path(project.path())]);

    assert_eq!(refused.status.code(), Some(1), "{refused:?}");
    assert!(refused.stderr.is_empty());
    let rendered = String::from_utf8(refused.stdout).expect("diagnostic is UTF-8");
    assert!(!rendered.contains(MODULE_CANARY));
    let report: Value = serde_json::from_str(&rendered).expect("diagnostic JSON parses");
    assert_eq!(
        report["diagnostics"][0]["code"],
        "breg.module.lock-source-missing"
    );
    assert_eq!(
        fs::read(project.path().join("registry.yaml")).expect("project rereads"),
        original
    );
}

#[test]
fn deny_warnings_refuses_on_the_warnings_that_refused_it() {
    let project = TestProject::asset_fixture();
    let destination = project.path().join("initialized");
    assert!(bregctl(&["init", path(&destination)]).status.success());

    let passed = bregctl(&["check", path(&destination)]);
    assert_eq!(passed.status.code(), Some(0), "{passed:?}");
    let passed = String::from_utf8(passed.stdout).expect("report is UTF-8");
    assert!(
        passed.starts_with("Authoring check passed; registry revision sha256:"),
        "{passed}"
    );

    let refused = bregctl(&["check", path(&destination), "--deny-warnings"]);

    assert_eq!(refused.status.code(), Some(1), "{refused:?}");
    assert!(refused.stdout.is_empty(), "{refused:?}");
    let rendered = String::from_utf8(refused.stderr).expect("refusal is UTF-8");
    assert!(
        rendered
            .starts_with("bregctl check refused the project: --deny-warnings refuses a warning.\n"),
        "a refusal names what refused it: {rendered}"
    );
    let registry = destination.join("registry.yaml");
    assert!(
        rendered.contains(&format!(
            "\nwarning[breg.access.profile-unrestricted-collection] {}:",
            registry.display()
        )),
        "{rendered}"
    );
    assert!(
        rendered.ends_with("\n0 errors, 2 warnings in 2 files\n"),
        "{rendered}"
    );
    // The warnings are the ones the passing check reported, in its words.
    let warnings = |text: &str| text.lines().skip(1).map(str::to_owned).collect::<Vec<_>>();
    assert_eq!(warnings(&rendered), warnings(&passed));
}

/// The committed minimal example: a project and the runtime file that runs it.
fn minimal_example() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/breg/examples/minimal")
        .canonicalize()
        .expect("the minimal example exists")
}

/// The minimal example's runtime file with `edit` applied, written into a
/// scratch directory so the check reads it from a path the test chose.
fn edited_runtime_config(scratch: &TestProject, edit: impl Fn(&str) -> String) -> PathBuf {
    let source = fs::read_to_string(minimal_example().join("runtime.yaml"))
        .expect("the minimal runtime file reads");
    let edited = edit(&source);
    assert_ne!(edited, source, "the edit changes the runtime file");
    let runtime = scratch.path().join("runtime.yaml");
    fs::write(&runtime, edited).expect("the edited runtime file writes");
    runtime
}

#[test]
fn check_reads_a_runtime_configuration_beside_the_project() {
    let example = minimal_example();
    let runtime = example.join("runtime.yaml");

    let human = bregctl(&["check", path(&example), "--runtime-config", path(&runtime)]);
    assert_eq!(human.status.code(), Some(0), "{human:?}");
    let rendered = String::from_utf8(human.stdout).expect("report is UTF-8");
    assert!(
        rendered.starts_with("Authoring check passed; registry revision sha256:"),
        "{rendered}"
    );
    // The project's two files and the runtime file.
    assert!(
        rendered.ends_with("\n0 errors, 0 warnings in 3 files\n"),
        "{rendered}"
    );

    let json = bregctl(&[
        "--format",
        "json",
        "check",
        path(&example),
        "--runtime-config",
        path(&runtime),
        "--deny-warnings",
    ]);
    assert_eq!(json.status.code(), Some(0), "{json:?}");
    let report = json_stdout(&json);
    assert_eq!(report["ok"], true);
    assert_eq!(report["diagnostics"], json!([]));
}

#[test]
fn check_refuses_a_runtime_configuration_in_the_reader_words() {
    let scratch = TestProject::asset_fixture();
    let runtime = edited_runtime_config(&scratch, |source| {
        source.replace("listener:\n", "unexpectedSetting: true\nlistener:\n")
    });
    let example = minimal_example();

    let json = bregctl(&[
        "--format",
        "json",
        "check",
        path(&example),
        "--runtime-config",
        path(&runtime),
    ]);
    assert_eq!(json.status.code(), Some(1), "{json:?}");
    let report = json_stdout(&json);
    assert_eq!(report["ok"], false);
    assert!(report.get("registryRevision").is_none(), "{report}");
    let diagnostics = report["diagnostics"].as_array().expect("diagnostics list");
    assert_eq!(diagnostics.len(), 1, "{report}");
    let diagnostic = &diagnostics[0];
    assert_check_diagnostic(diagnostic, Some("BRegRuntimeConfig"));
    assert_eq!(diagnostic["severity"], "error");
    assert_eq!(diagnostic["code"], "config.unknown-key");
    assert_eq!(diagnostic["path"], "/unexpectedSetting");
    assert_eq!(diagnostic["source"]["file"], path(&runtime));
    assert!(diagnostic["source"]["line"].is_u64(), "{diagnostic}");

    let human = bregctl(&["check", path(&example), "--runtime-config", path(&runtime)]);
    assert_eq!(human.status.code(), Some(1), "{human:?}");
    assert!(human.stdout.is_empty(), "{human:?}");
    let rendered = String::from_utf8(human.stderr).expect("refusal is UTF-8");
    assert!(
        rendered.starts_with(&format!(
            "bregctl check refused the project or its runtime configuration.\n\
             error[config.unknown-key] {}:",
            runtime.display()
        )),
        "{rendered}"
    );
    assert!(
        rendered.ends_with("\n1 error, 0 warnings in 3 files\n"),
        "{rendered}"
    );
}

#[test]
fn check_cannot_read_a_missing_runtime_configuration() {
    let scratch = TestProject::asset_fixture();
    let missing = scratch.path().join("missing-runtime.yaml");
    let example = minimal_example();

    let json = bregctl(&[
        "--format",
        "json",
        "check",
        path(&example),
        "--runtime-config",
        path(&missing),
    ]);
    assert_eq!(json.status.code(), Some(3), "{json:?}");
    let report = json_stdout(&json);
    assert_eq!(report["ok"], false);
    let diagnostic = &report["diagnostics"][0];
    // A file that cannot be read has no document kind to name.
    assert_check_diagnostic(diagnostic, None);
    assert_eq!(diagnostic["severity"], "error");
    assert_eq!(diagnostic["source"]["file"], path(&missing));

    let human = bregctl(&["check", path(&example), "--runtime-config", path(&missing)]);
    assert_eq!(human.status.code(), Some(3), "{human:?}");
    let rendered = String::from_utf8(human.stderr).expect("refusal is UTF-8");
    assert!(
        rendered.starts_with(
            "bregctl check could not read the project or its runtime configuration.\n"
        ),
        "{rendered}"
    );
}

#[test]
fn check_substitutes_the_environment_only_when_asked_and_never_repeats_a_value() {
    const CANARY: &str = "runtime-check-value-canary";
    let scratch = TestProject::asset_fixture();
    let runtime = edited_runtime_config(&scratch, |source| {
        source.replace("bind: 127.0.0.1:8080", "bind: ${BREG_CHECK_TEST_BIND}")
    });
    let example = minimal_example();
    let check = |environment: bool, bind: Option<&str>| {
        let mut command = Command::new(env!("CARGO_BIN_EXE_bregctl"));
        command.args([
            "--format",
            "json",
            "check",
            path(&example),
            "--runtime-config",
            path(&runtime),
        ]);
        if environment {
            command.arg("--environment");
        }
        command.env_remove("BREG_CHECK_TEST_BIND");
        if let Some(bind) = bind {
            command.env("BREG_CHECK_TEST_BIND", bind);
        }
        command.output().expect("bregctl starts")
    };

    // Without --environment, the expression is checked by its syntax and
    // position only, so an unset variable is not a finding.
    let deferred = check(false, None);
    assert_eq!(deferred.status.code(), Some(0), "{deferred:?}");

    let unset = check(true, None);
    assert_eq!(unset.status.code(), Some(1), "{unset:?}");
    let diagnostic = &json_stdout(&unset)["diagnostics"][0];
    assert_check_diagnostic(diagnostic, Some("BRegRuntimeConfig"));
    assert_eq!(diagnostic["path"], "/listener/bind");
    assert!(
        diagnostic["message"]
            .as_str()
            .is_some_and(|message| message.contains("BREG_CHECK_TEST_BIND")),
        "{diagnostic}"
    );

    let invalid = check(true, Some(CANARY));
    assert_eq!(invalid.status.code(), Some(1), "{invalid:?}");
    let diagnostic = &json_stdout(&invalid)["diagnostics"][0];
    assert_check_diagnostic(diagnostic, Some("BRegRuntimeConfig"));
    assert_eq!(diagnostic["path"], "/listener/bind");
    for stream in [&invalid.stdout, &invalid.stderr] {
        assert!(
            !String::from_utf8_lossy(stream).contains(CANARY),
            "a diagnostic never repeats a substituted value: {invalid:?}"
        );
    }

    let filled = check(true, Some("127.0.0.1:9"));
    assert_eq!(filled.status.code(), Some(0), "{filled:?}");
}

/// One numbered step, read back out of the rendering: the ordinal line and the
/// continuation lines hanging under it, checked for the column the renderer
/// folds them into and rejoined into the sentence the step states.
fn numbered_step(rendered: &str, ordinal: usize) -> String {
    let prefix = format!("  {ordinal}. ");
    let mut lines = rendered
        .lines()
        .skip_while(|line| !line.starts_with(&prefix));
    let first = lines
        .next()
        .unwrap_or_else(|| panic!("step {ordinal} is not rendered: {rendered}"));
    let mut sentence = first[prefix.len()..].to_owned();
    for line in lines {
        let Some(continuation) = line.strip_prefix(&" ".repeat(prefix.len())) else {
            break;
        };
        assert!(
            !continuation.starts_with(' '),
            "a continuation of step {ordinal} left its hanging column: {line:?}"
        );
        sentence.push(' ');
        sentence.push_str(continuation);
    }
    sentence
}

#[test]
fn an_authored_claim_name_cannot_forge_a_line_of_the_access_report() {
    // The entity, field, and profile identifiers a report prints are held to
    // the closed identifier grammar, so a claim name is the authored value
    // that reaches a rendered line with nothing removed from it.
    let project = TestProject::from_registry_source(
        br#"apiVersion: registry.registrystack.org/v1alpha1
kind: RegistryProject
registry:
  id: forged-line-fixture
  version: "1"
  defaultLanguage: en
  canonicalBaseIri: https://forged-line-fixture.example.test
entities:
  - id: record
    primaryDataset: test-dataset
    route: records
    mutationMode: create_only
    fields:
      - id: code
        type: string
        maxLength: 64
        classification: internal
accessProfiles:
  - id: reader
    principalClaim: "registry_principal\n  error  forged.code  forged"
    permissions:
      - entity: record
        operations: [get]
        readableFields: [code]
        rowBoundaries: []
"#,
    );

    let explained = bregctl(&["explain", "access", path(project.path())]);

    assert!(explained.status.success(), "{explained:?}");
    let rendered = String::from_utf8(explained.stdout).expect("access report is UTF-8");
    assert!(
        rendered.contains(
            "      principal claim         registry_principal\\n  error  forged.code  forged\n"
        ),
        "the authored claim name stays escaped on the line it was given: {rendered}"
    );
    assert!(
        !rendered
            .lines()
            .any(|line| line.trim_start().starts_with("error  forged.code")),
        "an authored claim name forged a report line: {rendered}"
    );
    assert!(
        rendered
            .lines()
            .filter(|line| line.contains("forged.code"))
            .count()
            == 1,
        "the authored claim name reached more than one line: {rendered}"
    );
}

#[test]
fn init_from_publicschema_starter_writes_a_derived_project_that_checks_immediately() {
    let project = TestProject::asset_fixture();
    let destination = project.path().join("derived");

    let output = bregctl(&[
        "--format",
        "json",
        "init",
        path(&destination),
        "--from",
        "publicschema",
        "--starter",
        "household",
    ]);

    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).expect("init reports JSON");
    assert_eq!(report["ok"], true);
    assert_eq!(report["command"], "init");
    let artifacts: Vec<&str> = report["artifacts"]
        .as_array()
        .expect("artifacts")
        .iter()
        .map(|artifact| artifact["path"].as_str().expect("path"))
        .collect();
    assert_eq!(
        artifacts,
        [
            "README.md",
            "dev-clients.yaml",
            "model/selection.yaml",
            "registry.yaml",
            "runtime.example.yaml",
            "tests/journeys.yaml",
        ]
    );
    for relative in &artifacts {
        assert!(
            destination.join(relative).is_file(),
            "init writes {relative}"
        );
    }
    assert!(
        !destination.join("modules").exists(),
        "a derived project locks no module"
    );
    let codes: Vec<&str> = report["findings"]
        .as_array()
        .expect("findings")
        .iter()
        .map(|finding| finding["code"].as_str().expect("code"))
        .collect();
    assert!(
        codes.contains(&"breg.access.profile-unrestricted-collection"),
        "{codes:?}"
    );
    assert!(
        codes.contains(&"breg.access.profile-higher-classification"),
        "{codes:?}"
    );
    let next_steps = report["nextSteps"].as_array().expect("next steps");
    assert!(next_steps.iter().any(|step| step
        .as_str()
        .is_some_and(|step| step.contains("model/selection.yaml"))));

    let registry =
        fs::read_to_string(destination.join("registry.yaml")).expect("derived project reads");
    assert!(registry.contains("id: household-registry"));
    assert!(registry.contains("conceptUri: https://publicschema.org/Person"));
    assert!(registry.contains("route: group-memberships"));
    assert!(registry
        .contains("{id: person, type: reference, target: person, classification: restricted}"));
    assert!(!registry.contains("generic-registry"));
    let initialized_project =
        parse_project_yaml(registry.as_bytes()).expect("derived project parses");
    for profile in [CompileProfile::Authoring, CompileProfile::Production] {
        compile_project(&initialized_project, &[], profile).expect("derived project compiles");
    }

    let check = bregctl(&["--format", "json", "check", path(&destination)]);
    assert!(check.status.success(), "{check:?}");
    let journeys =
        fs::read_to_string(destination.join("tests/journeys.yaml")).expect("derived journeys read");
    assert!(journeys.contains("scopes: [registry:household-registry:operate]"));
    assert!(journeys.contains("person: {recordCapture: example-person}"));
    assert!(!journeys.contains("token"));
    let selection =
        fs::read_to_string(destination.join("model/selection.yaml")).expect("selection echo reads");
    assert!(selection.contains(
        "\napiVersion: id.registrystack.org/formats/breg/model-selection/v1alpha1\nkind: BRegModelSelection\n"
    ));
    assert!(selection.contains("concept: GroupMembership"));
}

#[test]
fn init_from_publicschema_reports_the_derived_project_in_the_report_shape() {
    let project = TestProject::asset_fixture();
    let destination = project.path().join("derived");

    let output = bregctl(&[
        "init",
        path(&destination),
        "--from",
        "publicschema",
        "--starter",
        "household",
    ]);

    assert!(output.status.success(), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).expect("init stdout is UTF-8");
    assert!(
        stdout.starts_with(
            "Initialized a registry project. 6 artifacts written.\n  revision  sha256:"
        ),
        "a derived project opens with the report lead sentence: {stdout}"
    );
    assert!(
        stdout.contains("  finding  breg.access.profile-unrestricted-collection  6 paths\n"),
        "a repeated code counts the paths it collapsed: {stdout}"
    );
    assert!(
        stdout.contains("\n0 errors, 8 findings.\n"),
        "the report closes with the count to act on: {stdout}"
    );
    assert!(
        numbered_step(&stdout, 5).starts_with(&format!(
            "keep {}/model/selection.yaml beside the project",
            destination.display()
        )),
        "the derived project names its selection in a numbered step: {stdout}"
    );
}

#[test]
fn init_from_publicschema_reads_a_selection_file_and_refuses_a_bad_one() {
    let project = TestProject::asset_fixture();
    let selection = project.path().join("selection.yaml");
    fs::write(
        &selection,
        b"apiVersion: id.registrystack.org/formats/breg/model-selection/v1alpha1
kind: BRegModelSelection
model: publicschema
registry:
  id: places
  title: Places
entities:
  - concept: Location
    properties:
      - name: location_name
      - name: latitude
      - name: longitude
",
    )
    .expect("selection writes");
    let destination = project.path().join("places");

    let output = bregctl(&[
        "--format",
        "json",
        "init",
        path(&destination),
        "--from",
        "publicschema",
        "--selection",
        path(&selection),
    ]);

    assert!(output.status.success(), "{output:?}");
    let registry = fs::read_to_string(destination.join("registry.yaml")).expect("project reads");
    assert!(registry.contains("route: locations"));
    assert!(registry.contains(
        "{id: latitude, type: decimal, precision: 18, scale: 6, classification: internal}"
    ));
    assert!(!registry.contains("vocabulary-code"));

    fs::write(
        &selection,
        b"apiVersion: id.registrystack.org/formats/breg/model-selection/v1alpha1
kind: BRegModelSelection
model: publicschema
registry:
  id: places
  title: Places
entities:
  - concept: Location
    properties:
      - name: altitude
",
    )
    .expect("selection rewrites");
    let refused_destination = project.path().join("places-again");
    let output = bregctl(&[
        "--format",
        "json",
        "init",
        path(&refused_destination),
        "--from",
        "publicschema",
        "--selection",
        path(&selection),
    ]);

    assert!(!output.status.success(), "{output:?}");
    assert!(
        !refused_destination.exists(),
        "a refused selection writes nothing"
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("failure reports JSON");
    assert_eq!(report["ok"], false);
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(diagnostic["code"], "init.selection.property_unknown");
    assert_eq!(diagnostic["artifact"], "model_selection");
    assert_eq!(diagnostic["suggestedAction"], "correct_model_selection");
    assert!(diagnostic["message"]
        .as_str()
        .expect("message")
        .contains("location_name"));
}

#[test]
fn init_from_publicschema_prints_the_reader_diagnostics_for_a_selection_an_earlier_bregctl_wrote() {
    let project = TestProject::asset_fixture();
    let selection = project.path().join("selection.yaml");
    fs::write(
        &selection,
        b"apiVersion: registry.registrystack.org/breg-model-selection/v1alpha1
kind: ModelSelection
model: publicschema
registry:
  id: places
  title: Places
entities:
  - concept: Location
",
    )
    .expect("selection writes");
    let destination = project.path().join("places");
    let init = |format: &[&str]| {
        let mut arguments = format.to_vec();
        arguments.extend([
            "init",
            path(&destination),
            "--from",
            "publicschema",
            "--selection",
            path(&selection),
        ]);
        bregctl(&arguments)
    };

    let output = init(&["--format", "json"]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stderr.is_empty(), "{output:?}");
    let report = json_stdout(&output);
    assert_eq!(report["ok"], false);
    assert_eq!(report["command"], "init");
    let diagnostics = report["diagnostics"].as_array().expect("diagnostics");
    assert_eq!(diagnostics.len(), 1, "{report}");
    assert_eq!(diagnostics[0]["code"], "config.wrong-kind");
    assert_eq!(diagnostics[0]["path"], "/kind");
    assert_eq!(diagnostics[0]["source"]["file"], path(&selection));
    assert_eq!(diagnostics[0]["source"]["line"], 2);
    assert!(!destination.exists(), "a refused selection writes nothing");

    let output = init(&[]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stdout.is_empty(), "{output:?}");
    let rendered = String::from_utf8(output.stderr).expect("refusal is UTF-8");
    assert!(
        rendered.starts_with("bregctl init refused the model selection.\n"),
        "{rendered}"
    );
    assert!(rendered.contains("config.wrong-kind"), "{rendered}");
    assert!(rendered.contains("BRegModelSelection"), "{rendered}");
    assert!(!destination.exists(), "a refused selection writes nothing");
}

#[test]
fn init_from_publicschema_without_a_terminal_names_the_two_other_ways_in() {
    let project = TestProject::asset_fixture();
    let destination = project.path().join("derived");

    let output = bregctl(&[
        "--format",
        "json",
        "init",
        path(&destination),
        "--from",
        "publicschema",
    ]);

    assert!(!output.status.success(), "{output:?}");
    assert!(!destination.exists());
    let report: Value = serde_json::from_slice(&output.stdout).expect("failure reports JSON");
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(diagnostic["code"], "init.selection.missing");
    assert_eq!(diagnostic["suggestedAction"], "correct_command_usage");
    let message = diagnostic["message"].as_str().expect("message");
    assert!(message.contains("--selection"), "{message}");
    assert!(message.contains("--starter"), "{message}");
    assert!(message.contains("`household`"), "{message}");

    let output = bregctl(&[
        "--format",
        "json",
        "init",
        path(&destination),
        "--from",
        "publicschema",
        "--starter",
        "missing",
    ]);
    assert!(!output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).expect("failure reports JSON");
    assert_eq!(report["diagnostics"][0]["code"], "init.starter.unknown");
    assert!(report["diagnostics"][0]["message"]
        .as_str()
        .expect("message")
        .contains("`household`"));
}

#[test]
fn init_selection_flags_require_from() {
    let project = TestProject::asset_fixture();
    let destination = project.path().join("derived");

    let output = bregctl(&["init", path(&destination), "--starter", "household"]);

    assert_eq!(output.status.code(), Some(2), "{output:?}");
    assert!(!destination.exists());
    let stderr = String::from_utf8(output.stderr).expect("usage error is UTF-8");
    assert!(stderr.contains("--from"), "{stderr}");
}

#[test]
fn init_prints_the_next_command_and_what_the_example_leaves_open() {
    let project = TestProject::asset_fixture();
    let destination = project.path().join("initialized");
    let destination_argument = path(&destination).to_owned();

    let output = bregctl(&["init", &destination_argument]);

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8(output.stdout).expect("init stdout is UTF-8");
    let readme = destination.join("README.md");
    let registry = destination.join("registry.yaml");
    assert!(
        stdout.contains("\nNext:\n"),
        "init opens the steps with a heading: {stdout}"
    );
    assert_eq!(
        numbered_step(&stdout, 1),
        format!(
            "read {}, then run 'bregctl check {destination_argument}'",
            readme.display()
        ),
        "init names the next command: {stdout}"
    );
    assert!(
        numbered_step(&stdout, 2).starts_with("leave the findings above as they are;"),
        "init says the reported findings belong to the example: {stdout}"
    );
    assert!(
        numbered_step(&stdout, 3).starts_with(&format!(
            "replace canonicalBaseIri in {} before you build a production package;",
            registry.display()
        )),
        "init says the example base IRI is not shippable: {stdout}"
    );

    let json_destination = project.path().join("initialized-json");
    let reported = bregctl(&["--format", "json", "init", path(&json_destination)]);
    assert!(reported.status.success(), "{reported:?}");
    let report = json_stdout(&reported);
    let steps = report["nextSteps"]
        .as_array()
        .expect("nextSteps is an array")
        .iter()
        .map(|step| step.as_str().expect("step is a string").to_owned())
        .collect::<Vec<_>>();
    assert_eq!(steps.len(), 3, "{report}");

    let checked = bregctl(&["--format", "json", "check", &destination_argument]);
    assert!(checked.status.success(), "{checked:?}");
    assert!(
        json_stdout(&checked).get("nextSteps").is_none(),
        "only init carries next steps"
    );
}

#[test]
fn the_scaffold_links_only_documentation_pages_that_ship() {
    let project = TestProject::asset_fixture();
    let destination = project.path().join("initialized");

    let output = bregctl(&["init", path(&destination)]);
    assert!(output.status.success(), "{output:?}");

    let documentation =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/site/src/content/docs");
    let mut checked = 0usize;
    for relative in [
        "README.md",
        "modules/record-notes/module.yaml",
        "registry.yaml",
        "runtime.example.yaml",
        "tests/journeys.yaml",
    ] {
        let content = fs::read_to_string(destination.join(relative))
            .unwrap_or_else(|error| panic!("{relative} reads: {error}"));
        for link in documentation_links(&content) {
            checked += 1;
            let (route, anchor) = match link.split_once('#') {
                Some((route, anchor)) => (route, Some(anchor)),
                None => (link.as_str(), None),
            };
            let route = route.trim_matches('/');
            let page = [
                documentation.join(format!("{route}.mdx")),
                documentation.join(format!("{route}.md")),
                documentation.join(route).join("index.mdx"),
            ]
            .into_iter()
            .find(|candidate| candidate.is_file())
            .unwrap_or_else(|| panic!("{relative} links {link}, which has no page"));
            let source = fs::read_to_string(&page).expect("documentation page reads");
            let frontmatter = source
                .split("---")
                .nth(1)
                .expect("documentation page has frontmatter");
            assert!(
                !frontmatter.contains("draft: true"),
                "{relative} links {link}, whose page is not published"
            );
            if let Some(anchor) = anchor {
                assert!(
                    source
                        .lines()
                        .filter(|line| line.starts_with('#'))
                        .any(|line| heading_slug(line) == anchor),
                    "{relative} links {link}, whose page has no such heading"
                );
            }
        }
    }
    assert!(checked > 0, "the scaffold links the documentation");
}

/// Collects every published documentation URL a scaffold file carries.
fn documentation_links(content: &str) -> Vec<String> {
    const PREFIX: &str = "https://docs.registrystack.org/";
    let mut links = Vec::new();
    let mut rest = content;
    while let Some(start) = rest.find(PREFIX) {
        rest = &rest[start + PREFIX.len()..];
        let end = rest
            .find(|character: char| character.is_whitespace() || ">)\"'".contains(character))
            .unwrap_or(rest.len());
        links.push(rest[..end].to_owned());
        rest = &rest[end..];
    }
    links
}

/// Renders a Markdown heading the way the documentation site anchors it.
fn heading_slug(heading: &str) -> String {
    let mut slug = String::new();
    for character in heading.trim_start_matches('#').trim().chars() {
        if character.is_ascii_alphanumeric() {
            slug.push(character.to_ascii_lowercase());
        } else if !slug.ends_with('-') {
            slug.push('-');
        }
    }
    slug.trim_matches('-').to_owned()
}

#[test]
fn init_writes_a_bare_relative_destination_into_the_working_directory() {
    let project = TestProject::asset_fixture();
    let output = Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .args(["--format", "json", "init", "initialized"])
        .current_dir(project.path())
        .output()
        .expect("bregctl runs");

    assert!(output.status.success(), "{output:?}");
    for relative in [
        "initialized/README.md",
        "initialized/modules/record-notes/module.yaml",
        "initialized/registry.yaml",
        "initialized/runtime.example.yaml",
        "initialized/tests/journeys.yaml",
    ] {
        assert!(
            project.path().join(relative).is_file(),
            "init writes {relative}"
        );
    }
    assert_eq!(json_stdout(&output)["command"], "init");
}

#[test]
fn init_and_generate_missing_output_parents_have_exact_logical_diagnostics() {
    const PATH_CANARY: &str = "bregctl-missing-parent-canary";

    let project = TestProject::asset_fixture();
    let missing_parent = project.path().join(PATH_CANARY);
    let init_destination = missing_parent.join("initialized");
    let init_output = bregctl(&[
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
                "message": "the output parent directory is not available; create it, or give a destination inside a directory that exists",
                "suggestedAction": "choose_safe_output_directory"
            }]
        })
    );
    assert!(!String::from_utf8_lossy(&init_output.stdout).contains(PATH_CANARY));

    let generate_destination = missing_parent.join("generated");
    let generate_output = bregctl(&[
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
                "message": "the output parent directory is not available; create it, or give a destination inside a directory that exists",
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

    let output = bregctl(&[
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
fn unavailable_artifact_selections_name_the_selection_and_the_alternatives() {
    let project = TestProject::asset_fixture();
    let output_root = project.path().join("unknown-artifact-output");

    let unknown = bregctl(&[
        "--format",
        "json",
        "generate",
        "actoins",
        project.path().to_str().expect("path is UTF-8"),
        "--output",
        output_root.to_str().expect("path is UTF-8"),
    ]);

    assert_eq!(unknown.status.code(), Some(2), "{unknown:?}");
    let report = json_stdout(&unknown);
    assert_eq!(report["diagnostics"][0]["code"], "usage.invalid");
    let message = report["diagnostics"][0]["message"]
        .as_str()
        .expect("usage message is a string");
    // The rejected selection is the operator's own token and is not repeated.
    assert!(!message.contains("actoins"), "{message}");
    assert!(message.contains("<ARTIFACT>"), "{message}");
    for selection in [
        "openapi", "schemas", "actions", "manifest", "metadata", "sql",
    ] {
        assert!(message.contains(selection), "{message}");
    }
    assert!(!output_root.exists());

    let empty = bregctl(&[
        "--format",
        "json",
        "generate",
        "actions",
        project.path().to_str().expect("path is UTF-8"),
        "--output",
        output_root.to_str().expect("path is UTF-8"),
    ]);

    assert_eq!(empty.status.code(), Some(1), "{empty:?}");
    let report = json_stdout(&empty);
    assert_eq!(report["diagnostics"][0]["code"], "artifact.selection.empty");
    let message = report["diagnostics"][0]["message"]
        .as_str()
        .expect("selection message is a string");
    assert!(message.contains("actions"), "{message}");
    assert!(message.contains("openapi"), "{message}");
    assert!(!output_root.exists());
}

#[test]
fn action_artifact_selector_publishes_only_compiled_action_surfaces() {
    let project = TestProject::from_registry_source(action_fixture());
    let output_root = project.path().join("action-output");

    let output = bregctl(&[
        "--format",
        "json",
        "generate",
        "actions",
        project.path().to_str().expect("path is UTF-8"),
        "--output",
        output_root.to_str().expect("path is UTF-8"),
    ]);

    assert!(output.status.success(), "{output:?}");
    assert!(output_root.join("compiled/actions.json").is_file());
    assert!(output_root
        .join("generated/action-schemas/register-household-contact.invoke.input.schema.json")
        .is_file());
    assert!(output_root
        .join("generated/action-schemas/register-household-contact.invoke.response.schema.json")
        .is_file());
    assert!(output_root
        .join(
            "generated/action-schemas/register-household-contact.target-conditions.input.schema.json"
        )
        .is_file());
    assert!(output_root
        .join(
            "generated/action-schemas/register-household-contact.target-conditions.response.schema.json"
        )
        .is_file());
    assert!(!output_root.join("generated/openapi.json").exists());
    assert!(!output_root
        .join("generated/schemas/household.schema.json")
        .exists());
    assert_eq!(
        tree(&output_root).keys().cloned().collect::<Vec<_>>(),
        vec![
            "compiled/actions.json",
            "generated/action-schemas/register-household-contact.invoke.input.schema.json",
            "generated/action-schemas/register-household-contact.invoke.response.schema.json",
            "generated/action-schemas/register-household-contact.target-conditions.input.schema.json",
            "generated/action-schemas/register-household-contact.target-conditions.response.schema.json",
        ]
    );
}

#[test]
fn schema_selector_includes_action_input_output_schemas() {
    let project = TestProject::from_registry_source(action_fixture());
    let output_root = project.path().join("schema-output");

    let output = bregctl(&[
        "--format",
        "json",
        "generate",
        "schemas",
        project.path().to_str().expect("path is UTF-8"),
        "--output",
        output_root.to_str().expect("path is UTF-8"),
    ]);

    assert!(output.status.success(), "{output:?}");
    assert!(output_root
        .join("generated/schemas/household.schema.json")
        .is_file());
    assert!(output_root
        .join("generated/action-schemas/register-household-contact.invoke.input.schema.json")
        .is_file());
    assert!(output_root
        .join("generated/action-schemas/register-household-contact.invoke.response.schema.json")
        .is_file());
}

#[test]
fn metadata_selector_publishes_action_metadata_without_private_grant_details() {
    let project = TestProject::from_registry_source(action_fixture());
    let output_root = project.path().join("metadata-output");

    let output = bregctl(&[
        "--format",
        "json",
        "generate",
        "metadata",
        project.path().to_str().expect("path is UTF-8"),
        "--output",
        output_root.to_str().expect("path is UTF-8"),
    ]);

    assert!(output.status.success(), "{output:?}");
    let metadata = fs::read_to_string(output_root.join("generated/metadata/registry.json"))
        .expect("metadata artifact reads");
    assert!(metadata.contains("register-household-contact"));
    assert!(metadata.contains("householdId"));
    assert!(!metadata.contains("private_claim_name"));
    assert!(!metadata.contains("other_private_claim"));
    assert!(!metadata.contains("rowBoundaries"));
}

#[test]
fn manifest_selector_requires_the_compiled_manifest_projection() {
    let project = TestProject::asset_fixture();
    let output_root = project.path().join("manifest-output");

    let output = bregctl(&[
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
    assert!(output_root.join("generated/manifest/dcat.jsonld").is_file());
    let report = json_stdout(&output);
    let artifacts = report["artifacts"]
        .as_array()
        .expect("artifacts is an array");
    assert_eq!(
        artifacts
            .iter()
            .map(|artifact| artifact["path"].as_str().expect("artifact path"))
            .collect::<Vec<_>>(),
        vec![
            "generated/manifest/dcat.jsonld",
            "generated/manifest/registry-manifest.json"
        ]
    );
}

#[test]
fn module_discovery_ignores_only_regular_finder_metadata() {
    let project = TestProject::asset_fixture();
    fs::write(project.path().join("modules/.DS_Store"), b"finder metadata")
        .expect("Finder metadata writes");
    let accepted = bregctl(&[
        "--format",
        "json",
        "check",
        project.path().to_str().expect("path is UTF-8"),
    ]);
    assert!(accepted.status.success(), "{accepted:?}");

    fs::write(project.path().join("modules/notes.txt"), b"unexpected")
        .expect("unexpected entry writes");
    let refused = bregctl(&[
        "--format",
        "json",
        "check",
        project.path().to_str().expect("path is UTF-8"),
    ]);
    assert_eq!(refused.status.code(), Some(1));
    assert_eq!(
        json_stdout(&refused)["diagnostics"][0]["code"],
        "breg.source.modules-invalid"
    );
}

#[test]
fn metadata_selector_publishes_only_registry_metadata() {
    let project = TestProject::asset_fixture();
    let output_root = project.path().join("metadata-output");

    let output = bregctl(&[
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

    let routes = bregctl(&[
        "--format",
        "json",
        "explain",
        "routes",
        project.path().to_str().expect("path is UTF-8"),
    ]);
    let access = bregctl(&[
        "--format",
        "json",
        "explain",
        "access",
        project.path().to_str().expect("path is UTF-8"),
    ]);
    let model = bregctl(&[
        "--format",
        "json",
        "explain",
        "model",
        project.path().to_str().expect("path is UTF-8"),
    ]);
    let queries = bregctl(&[
        "--format",
        "json",
        "explain",
        "queries",
        project.path().to_str().expect("path is UTF-8"),
    ]);

    assert!(routes.status.success(), "{routes:?}");
    assert!(access.status.success(), "{access:?}");
    assert!(model.status.success(), "{model:?}");
    assert!(queries.status.success(), "{queries:?}");
    assert_eq!(
        json_stdout(&routes)["explanation"]["routes"][0]["entityId"],
        "asset-item"
    );
    assert_eq!(
        json_stdout(&access)["explanation"]["routes"]["entries"][0]["entityId"],
        "asset-item"
    );
    assert_eq!(
        json_stdout(&model)["explanation"]["registryId"],
        "asset-site-placement"
    );
    let queries_json = json_stdout(&queries);
    let operations = queries_json["explanation"]["operations"]
        .as_array()
        .expect("query operations are an array");
    assert!(operations
        .windows(2)
        .all(|window| window[0]["id"].as_str().expect("left id")
            <= window[1]["id"].as_str().expect("right id")));
    let planner_list = operations
        .iter()
        .find(|operation| operation["id"] == "records.asset-item.site-planner.list")
        .expect("site planner list query is explained");
    assert_eq!(planner_list["profile"], "site-planner");
    assert_eq!(planner_list["routeId"], "records.asset-item.list");
    assert_eq!(planner_list["apiFields"][0]["apiName"], "assetCode");
    assert_eq!(planner_list["apiFields"][0]["field"], "asset-code");
    assert_eq!(planner_list["apiFields"][0]["sourceKind"], "stored");
    assert_eq!(planner_list["filterable"][0]["apiName"], "assetCode");
    assert_eq!(planner_list["filterable"][0]["field"], "asset-code");
    assert_eq!(
        planner_list["filterable"][0]["operators"],
        json!([
            "equals",
            "in",
            "is_null",
            "is_not_null",
            "prefix",
            "contains"
        ])
    );
    assert_eq!(
        planner_list["filterable"][0]["wireOperators"],
        json!([
            "contains",
            "eq",
            "eq null",
            "in",
            "ne",
            "ne null",
            "startswith"
        ])
    );
    assert!(planner_list["filterable"][0]["examples"]
        .as_array()
        .expect("filter examples are an array")
        .iter()
        .any(|example| example == "$filter=assetCode eq 'example'"));
    assert!(planner_list["sortable"]
        .as_array()
        .expect("sortable is an array")
        .is_empty());
    assert_eq!(planner_list["wire"]["filter"], "$filter");
    assert_eq!(planner_list["wire"]["orderBy"], "$orderby");
    assert_eq!(planner_list["bounds"]["maxPageSize"], 100);
    assert_eq!(planner_list["bounds"]["maxInValues"], 100);
    assert!(!String::from_utf8(queries.stdout)
        .expect("queries JSON is UTF-8")
        .contains("registry_data"));
}

#[test]
fn explain_routes_preserves_action_free_output_shape() {
    let project = TestProject::asset_fixture();

    let output = bregctl(&[
        "--format",
        "json",
        "explain",
        "routes",
        project.path().to_str().expect("path is UTF-8"),
    ]);

    assert!(output.status.success(), "{output:?}");
    let explanation = json_stdout(&output)["explanation"].clone();
    assert_eq!(
        explanation
            .as_object()
            .expect("routes explanation is an object")
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        vec!["apiVersion", "kind", "routes"]
    );
    let routes = explanation["routes"].as_array().expect("routes are listed");
    assert!(!routes.is_empty());
    assert!(routes.iter().all(|route| route.get("actionId").is_none()));
    assert!(routes.iter().all(|route| route["kind"] == "entity"));
}

#[test]
fn explain_routes_includes_served_immediate_action_routes() {
    let project = TestProject::from_registry_source(action_fixture());

    let output = bregctl(&[
        "--format",
        "json",
        "explain",
        "routes",
        project.path().to_str().expect("path is UTF-8"),
    ]);

    assert!(output.status.success(), "{output:?}");
    let explanation = json_stdout(&output)["explanation"].clone();
    let all_routes = explanation["routes"].as_array().expect("routes are listed");
    assert!(!all_routes.is_empty());
    // Every route must carry a discriminator that matches which shape it actually is:
    // entity routes carry entityId and no actionId, action routes carry actionId and no
    // entityId, and no route is missing both or carrying both.
    assert!(all_routes.iter().all(|route| {
        match (route.get("entityId"), route.get("actionId")) {
            (Some(_), None) => route["kind"] == "entity",
            (None, Some(_)) => route["kind"] == "action",
            (None, None) | (Some(_), Some(_)) => false,
        }
    }));
    let action_routes = all_routes
        .iter()
        .filter(|route| route["actionId"] == "register-household-contact")
        .collect::<Vec<_>>();
    assert_eq!(action_routes.len(), 2);
    assert!(action_routes.iter().any(|route| {
        let profiles = route["accessProfiles"]
            .as_array()
            .expect("action route lists access profiles");
        route["kind"] == "action"
            && route["actionRouteKind"] == "invoke"
            && route["path"] == "/v1/actions/register-household-contact"
            && route["operation"] == "invoke"
            && route["requiresIdempotencyKey"] == true
            && profiles.len() == 2
            && profiles.contains(&json!("contact-registrar"))
            && profiles.contains(&json!("contact-auditor"))
            && route["defaultAccessProfile"] == "contact-registrar"
    }));
    assert!(action_routes.iter().any(|route| {
        // Pin that `kind` is a record-shape discriminator distinct from `actionRouteKind`:
        // a target_conditions route is still `kind: "action"`.
        route["kind"] == "action"
            && route["actionRouteKind"] == "target_conditions"
            && route["path"] == "/v1/actions/register-household-contact/target-conditions"
            && route["operation"] == "invoke"
            && route["requiresIdempotencyKey"] == false
    }));
    let rendered = serde_json::to_string(&explanation).expect("routes explanation serializes");
    assert!(!rendered.contains("private_claim_name"));
    assert!(!rendered.contains("other_private_claim"));
    assert!(!rendered.contains("rowBoundaries"));
}

#[test]
fn explain_routes_discriminates_mixed_entity_and_action_route_shapes() {
    let project = TestProject::from_registry_source(mixed_entity_and_action_route_fixture());

    let output = bregctl(&[
        "--format",
        "json",
        "explain",
        "routes",
        project.path().to_str().expect("path is UTF-8"),
    ]);

    assert!(output.status.success(), "{output:?}");
    let explanation = json_stdout(&output)["explanation"].clone();
    let routes = explanation["routes"].as_array().expect("routes are listed");

    // Prove the fixture actually mixes both record shapes; otherwise the assertions
    // below would pass vacuously.
    let entity_routes = routes
        .iter()
        .filter(|route| route.get("entityId").is_some())
        .count();
    let action_routes = routes
        .iter()
        .filter(|route| route.get("actionId").is_some())
        .count();
    assert!(entity_routes > 0, "expected at least one entity route");
    assert!(action_routes > 0, "expected at least one action route");
    assert_eq!(entity_routes + action_routes, routes.len());

    for route in routes {
        match (route.get("entityId"), route.get("actionId")) {
            (Some(_), None) => assert_eq!(route["kind"], "entity", "{route:?}"),
            (None, Some(_)) => assert_eq!(route["kind"], "action", "{route:?}"),
            (None, None) => panic!("route has neither entityId nor actionId: {route:?}"),
            (Some(_), Some(_)) => panic!("route carries both entityId and actionId: {route:?}"),
        }
    }
}

#[test]
fn explain_access_includes_action_only_grants_and_target_reach() {
    let project = TestProject::from_registry_source(action_fixture());
    let output = bregctl(&[
        "--format",
        "json",
        "explain",
        "access",
        project.path().to_str().expect("path is UTF-8"),
    ]);
    assert!(output.status.success(), "{output:?}");
    let report = json_stdout(&output);
    let explanation = &report["explanation"];
    assert!(explanation["entities"]
        .as_array()
        .unwrap()
        .iter()
        .all(|entity| entity["profiles"].as_array().unwrap().is_empty()));
    let action = &explanation["actions"]["actions"][0];
    assert_eq!(action["id"], "register-household-contact");
    let registrar = action["permissions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|grant| grant["profileId"] == "contact-registrar")
        .unwrap();
    assert_eq!(
        registrar["requiredScopes"],
        json!(["registry:contact:register"])
    );
    assert_eq!(
        registrar["requiredPurposes"],
        json!(["contact-registration"])
    );
    assert_eq!(
        explanation["actions"]["routes"].as_array().unwrap().len(),
        2
    );
    assert!(explanation["claimContract"]["purposeRequired"]
        .as_bool()
        .unwrap());
    let targets = explanation["rowReach"].as_array().unwrap();
    assert_eq!(targets.len(), 6);
    assert!(targets
        .iter()
        .all(|target| target["surface"] == "action_target" && target["rows"] == "all"));
    assert!(report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|finding| finding["code"] == "breg.access.target-unrestricted-rows"));
}

#[test]
fn explain_actions_reports_compiled_effects_conditions_results_and_grants() {
    let project = TestProject::from_registry_source(action_fixture());

    let output = bregctl(&[
        "--format",
        "json",
        "explain",
        "actions",
        project.path().to_str().expect("path is UTF-8"),
    ]);

    assert!(output.status.success(), "{output:?}");
    let report = json_stdout(&output);
    let actions = report["explanation"]["actions"]
        .as_array()
        .expect("actions are listed");
    assert_eq!(actions.len(), 1);
    let action = &actions[0];
    assert_eq!(action["id"], "register-household-contact");
    assert_eq!(action["inputs"][0]["input"], "household");
    assert_eq!(action["inputs"][0]["apiName"], "householdId");
    assert_eq!(action["requiredConditionKeys"], json!(["householdId"]));
    assert_eq!(
        action["routes"][0]["path"],
        "/v1/actions/register-household-contact"
    );
    assert_eq!(
        action["routes"][1]["path"],
        "/v1/actions/register-household-contact/target-conditions"
    );
    assert_eq!(action["effects"][0]["id"], "person");
    assert_eq!(
        action["effects"][1]["fields"][0]["value"]["kind"],
        "from_effect"
    );
    assert_eq!(action["targets"][0]["conditionRequired"], false);
    assert!(action["targets"]
        .as_array()
        .expect("targets are listed")
        .iter()
        .any(|target| target["conditionRequired"] == true
            && target["source"]["input"]["apiName"] == "householdId"));
    assert!(action["permissions"]
        .as_array()
        .expect("permissions are listed")
        .iter()
        .any(|grant| grant["profile"] == "contact-registrar"
            && grant["results"]
                .as_array()
                .expect("results are listed")
                .len()
                == 3));
    assert!(action["results"]
        .as_array()
        .expect("results are listed")
        .iter()
        .any(|result| result["effect"] == "household"));
}

#[test]
fn explain_actions_reports_reference_acceptance_conditions() {
    let project = fs::canonicalize(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/breg/acceptance/person-registration-rhai"),
    )
    .expect("authored person-registration fixture resolves");
    let output = bregctl(&[
        "--format",
        "json",
        "explain",
        "actions",
        project.to_str().expect("path is UTF-8"),
    ]);
    assert!(output.status.success(), "{output:?}");
    let report = json_stdout(&output);
    let action = report["explanation"]["actions"]
        .as_array()
        .expect("actions are listed")
        .iter()
        .find(|action| action["id"] == "register-person-with-registration")
        .expect("registration action is explained");
    let requirement = &action["requires"][0];
    assert_eq!(requirement["input"]["apiName"], "registerId");
    assert_eq!(requirement["entity"], "register");
    assert_eq!(requirement["field"]["field"], "active");
    assert_eq!(requirement["equals"], true);
    assert_eq!(requirement["evaluated"], "before_effects_under_target_lock");
    // A Rhai handler's server contract is the baseline: no compatibility
    // member, which the WASM summary alone carries.
    assert_eq!(action["handler"]["kind"], "rhai");
    assert!(action["handler"]["compatibility"].is_null());
    assert!(!String::from_utf8(output.stdout)
        .expect("explanation is UTF-8")
        .contains("registry_data"));
}

/// The minimal conforming guest ABI, mirroring the wasm admission suite's
/// fixture: the five required exports and nothing else.
#[cfg(feature = "wasm")]
const MINIMAL_ABI_WAT: &str = r#"
    (module
      (memory (export "memory") 1)
      (func (export "alloc") (param i32) (result i32) i32.const 0)
      (func (export "handle") (param i32 i32) (result i32) i32.const 0)
      (func (export "result_ptr") (result i32) i32.const 0)
      (func (export "result_len") (result i32) i32.const 0)
    )
"#;

#[test]
#[cfg(feature = "wasm")]
fn check_collects_project_and_module_hook_handler_assets() {
    let module_source = br#"id: hook-module
version: "1"
extendEntities:
  - entity: record
    hooks:
      - id: record-patched-local
        phase: after
        trigger: patched
        projection: [label]
        handler:
          kind: wasm
          module: hooks/record-patched.wasm
          abi: registry.hook-handler/v1
"#;
    let module = parse_module_yaml(module_source).expect("hook module parses");
    let wasm_module = wat::parse_str(MINIMAL_ABI_WAT).expect("the hook WAT fixture assembles");
    let module_assets = [ModuleAssetSource {
        module: Some(module.id.clone()),
        path: "hooks/record-patched.wasm".to_owned(),
        bytes: wasm_module.clone(),
    }];
    let project_source = format!(
        r#"apiVersion: registry.registrystack.org/v1alpha1
kind: RegistryProject
registry:
  id: hook-asset-fixture
  version: "1"
  defaultLanguage: en
  canonicalBaseIri: https://hook-asset-fixture.example.test
modules:
  - id: hook-module
    version: "1"
    digest: {}
entities:
  - id: record
    primaryDataset: test-dataset
    route: records
    mutationMode: mutable
    fields:
      - id: label
        type: string
        maxLength: 64
        classification: internal
    hooks:
      - id: record-created-local
        phase: after
        trigger: created
        projection: [label]
        handler:
          kind: rhai
          script: hooks/record-created.rhai
          abi: registry.hook-handler/v1
"#,
        module_digest_with_assets(&module, &module_assets)
    );
    let project = TestProject::from_registry_source(project_source.as_bytes());
    fs::create_dir_all(project.path().join("hooks")).expect("project hook directory creates");
    fs::write(
        project.path().join("hooks/record-created.rhai"),
        b"fn handle(ctx) { #{\"answer\": \"none\"} }\n",
    )
    .expect("project Rhai hook writes");
    let module_directory = project.path().join("modules/hook-module");
    fs::create_dir_all(module_directory.join("hooks")).expect("module hook directory creates");
    fs::write(module_directory.join("module.yaml"), module_source)
        .expect("hook module source writes");
    fs::write(
        module_directory.join("hooks/record-patched.wasm"),
        wasm_module,
    )
    .expect("module WASM hook writes");

    let checked = bregctl(&[
        "--format",
        "json",
        "check",
        project.path().to_str().expect("path is UTF-8"),
    ]);

    assert!(checked.status.success(), "{checked:?}");
    assert_eq!(json_stdout(&checked)["ok"], true);
}

#[cfg(feature = "wasm")]
fn wasm_action_fixture() -> &'static [u8] {
    br#"apiVersion: registry.registrystack.org/v1alpha1
kind: RegistryProject
registry:
  id: wasm-explain-fixture
  version: "1"
  defaultLanguage: en
  canonicalBaseIri: https://wasm-explain-fixture.example.test
entities:
  - id: person
    primaryDataset: test-dataset
    route: people
    mutationMode: mutable
    fields:
      - {id: person-code, apiName: personCode, type: string, required: true, maxLength: 64, classification: restricted}
      - {id: legal-name, apiName: legalName, type: string, required: true, maxLength: 160, classification: restricted}
actions:
  - id: register-person
    inputs:
      - {id: person-code, apiName: personCode, type: string, required: true, maxLength: 64, classification: restricted}
      - {id: legal-name, apiName: legalName, type: string, required: true, maxLength: 160, classification: restricted}
    handler:
      kind: wasm
      module: wasm/handler.wasm
      abi: registry.action-handler/v1
      writes:
        - id: person
          target: {entity: person}
          operation: create
          fields: [person-code, legal-name]
accessProfiles:
  - id: registrar
    default: true
    principalClaim: registry_principal
    permissions:
      - action: register-person
        operations: [invoke]
        targets:
          - {entity: person, rowBoundaries: []}
        results: [person]
"#
}

/// A WASM handler summary carries its server-compatibility contract: the
/// minimum server that runs it, and the load-time refusals older or
/// feature-off servers produce. Rhai handlers carry no such member; their
/// server contract is the baseline.
#[test]
#[cfg(feature = "wasm")]
fn explain_actions_reports_wasm_handler_server_compatibility() {
    let project = TestProject::from_registry_source(wasm_action_fixture());
    let module_directory = project.path().join("wasm");
    fs::create_dir_all(&module_directory).expect("module directory is created");
    let module = wat::parse_str(MINIMAL_ABI_WAT).expect("the wat fixture assembles");
    fs::write(module_directory.join("handler.wasm"), module).expect("module file is written");

    let output = bregctl(&[
        "--format",
        "json",
        "explain",
        "actions",
        project.path().to_str().expect("path is UTF-8"),
    ]);

    assert!(output.status.success(), "{output:?}");
    let report = json_stdout(&output);
    let handler = &report["explanation"]["actions"][0]["handler"];
    assert_eq!(handler["kind"], "wasm");
    let compatibility = &handler["compatibility"];
    assert_eq!(
        compatibility["minimumServer"],
        "registry-breg built with the wasm feature"
    );
    assert_eq!(
        compatibility["serversBeforeWasmSupport"],
        "refuse the package at load with a typed handler error and no state change"
    );
    assert_eq!(
        compatibility["serversBuiltWithoutTheFeature"],
        "refuse the package during load because handler rederivation requires WASM support"
    );
    assert_eq!(
        compatibility["moduleSha256"], handler["moduleSha256"],
        "the compatibility member names the exact module it describes"
    );
}

#[test]
fn explain_change_requests_reports_compiled_effects_actions_and_controlled_writes() {
    let project = fs::canonicalize(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/breg/acceptance/asset-site-placement-change-requests"),
    )
    .expect("committed change request fixture path resolves");
    let output = bregctl(&[
        "--format",
        "json",
        "explain",
        "change-requests",
        project.to_str().expect("path is UTF-8"),
    ]);

    assert!(output.status.success(), "{output:?}");
    let report = json_stdout(&output);
    let explanation = &report["explanation"];
    let requests = explanation["requests"]
        .as_array()
        .expect("change requests are listed");
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request["requestEntity"], "placement-correction-request");
    assert_eq!(request["effects"][0]["operation"], "patch");
    assert_eq!(request["effects"][0]["target"]["entity"], "asset-placement");
    assert_eq!(
        request["effects"][0]["fields"][0]["target"]["field"],
        "site"
    );
    assert_eq!(
        request["effects"][0]["fields"][0]["target"]["apiName"],
        "site"
    );
    assert_eq!(
        request["effects"][0]["fields"][0]["value"]["field"]["field"],
        "proposed-site"
    );
    assert_eq!(
        request["review"],
        json!({
            "authority": "casework",
            "policyId": "asset-placement-correction"
        })
    );
    assert_eq!(request["onApproved"], json!({"mode": "manual"}));
    let apply = request["actions"]
        .as_array()
        .expect("actions are listed")
        .iter()
        .find(|action| action["operation"] == "apply_request")
        .expect("source-owned apply action is explained");
    assert_eq!(
        apply["preconditions"],
        json!([
            "Idempotency-Key",
            "If-Match",
            "proposalVersion",
            "effectDigest"
        ])
    );
    assert_eq!(
        explanation["controlledWrites"][0]["directWriteRestriction"],
        "controlled operations are absent from ordinary permissions and require compiled apply_request context"
    );
    assert_eq!(
        explanation["controlledWrites"][0]["eligibleRequestTypes"],
        json!(["placement-correction-request"])
    );
}

#[test]
fn explain_query_filter_examples_match_field_types() {
    let project = TestProject::from_registry_source(
        br#"apiVersion: registry.registrystack.org/v1alpha1
kind: RegistryProject
registry:
  id: typed-query-examples
  version: "1"
  defaultLanguage: en
  canonicalBaseIri: https://typed-query-examples.example.test
entities:
  - id: typed-record
    primaryDataset: test-dataset
    route: typed-records
    mutationMode: create_only
    fields:
      - id: label
        type: string
        maxLength: 64
        classification: internal
      - id: score
        type: int64
        classification: internal
      - id: enabled
        type: boolean
        classification: internal
      - id: observed-on
        type: date
        classification: internal
      - id: observed-at
        type: timestamp
        classification: internal
accessProfiles:
  - id: reader
    principalClaim: principal
    permissions:
      - entity: typed-record
        rowBoundaries: []
        operations: [list]
        readableFields: [label, score, enabled, observed-on, observed-at]
        filterableFields: [label, score, enabled, observed-on, observed-at]
"#,
    );

    let output = bregctl(&[
        "--format",
        "json",
        "explain",
        "queries",
        path(project.path()),
    ]);

    assert!(output.status.success(), "{output:?}");
    let report = json_stdout(&output);
    let operation = report["explanation"]["operations"]
        .as_array()
        .expect("operations are an array")
        .iter()
        .find(|operation| operation["id"] == "records.typed-record.reader.list")
        .expect("typed query operation is explained");
    assert_filter_example(operation, "label", "$filter=label eq 'example'");
    assert_filter_example(operation, "score", "$filter=score eq 1");
    assert_filter_example(operation, "score", "$filter=score ge 1");
    assert_filter_example(operation, "enabled", "$filter=enabled eq true");
    assert_filter_example(operation, "enabled", "$filter=enabled in (true,false)");
    assert_filter_example(
        operation,
        "observedOn",
        "$filter=observedOn eq '2026-01-02'",
    );
    assert_filter_example(
        operation,
        "observedOn",
        "$filter=observedOn ge '2026-01-02'",
    );
    assert_filter_example(
        operation,
        "observedAt",
        "$filter=observedAt eq '2026-01-02T03:04:05Z'",
    );
    assert_filter_example(
        operation,
        "observedAt",
        "$filter=observedAt ge '2026-01-02T03:04:05Z'",
    );
}

#[test]
fn explain_spatial_queries_maps_the_exact_profile_and_api_geometry() {
    let project = TestProject::from_registry_source(
        br#"apiVersion: registry.registrystack.org/v1alpha1
kind: RegistryProject
registry: {id: map-explanation, version: "1", defaultLanguage: en, canonicalBaseIri: https://map-explanation.example.test}
entities:
  - id: service-site
    primaryDataset: test-dataset
    route: service-sites
    mutationMode: create_only
    geojson: {geometryField: location}
    fields:
      - {id: location, apiName: position, type: crs84-point, precision: 9, classification: internal}
accessProfiles:
  - id: map-reader
    default: true
    principalClaim: principal
    permissions:
      - entity: service-site
        rowBoundaries: []
        operations: [get, list]
        readableFields: [location]
        spatialQueries:
          bbox: {maximumLongitudeSpanDegrees: 0.5, maximumLatitudeSpanDegrees: 0.25}
  - id: geometry-reader
    principalClaim: principal
    permissions:
      - {entity: service-site, operations: [get, list], readableFields: [location], rowBoundaries: []}
"#,
    );
    let output = bregctl(&[
        "--format",
        "json",
        "explain",
        "queries",
        path(project.path()),
    ]);
    assert!(output.status.success(), "{output:?}");
    let report = json_stdout(&output);
    let operations = report["explanation"]["operations"].as_array().unwrap();
    let map = operations
        .iter()
        .find(|operation| operation["profile"] == "map-reader")
        .unwrap();
    assert_eq!(map["spatialQueries"]["bbox"]["apiName"], "position");
    assert_eq!(
        map["spatialQueries"]["bbox"]["maximumLatitudeSpanDegrees"],
        0.25
    );
    assert_eq!(map["spatialQueries"]["bbox"]["requiresPostgis"], true);
    assert_eq!(map["gis"]["collectionId"], "service-site.map-reader");
    assert_eq!(map["gis"]["accessProfile"], "map-reader");
    assert_eq!(
        map["gis"]["itemsPath"],
        "/v1/gis/collections/service-site.map-reader/items"
    );
    assert!(map["filterable"].as_array().unwrap().is_empty());
    let plain = operations
        .iter()
        .find(|operation| operation["profile"] == "geometry-reader")
        .unwrap();
    assert!(plain.get("gis").is_none());
    assert!(plain.get("spatialQueries").is_none());
}

#[test]
fn check_reports_derived_sql_module_path_without_sql_values() {
    let project = TestProject::from_registry_source(
        br#"apiVersion: registry.registrystack.org/v1alpha1
kind: RegistryProject
registry:
  id: derived-diagnostic-fixture
  version: "1"
  defaultLanguage: en
  canonicalBaseIri: https://derived-diagnostic-fixture.example.test
modules:
  - id: core
    version: "1"
"#,
    );
    let module_dir = project.path().join("modules/core");
    fs::create_dir_all(module_dir.join("sql")).expect("module SQL directory creates");
    fs::write(
        module_dir.join("module.yaml"),
        br#"id: core
version: "1"
entities:
  - id: record
    primaryDataset: test-dataset
    route: records
    mutationMode: create_only
    fields:
      - id: code
        type: string
        maxLength: 16
        classification: internal
    derived:
      - id: summary
        sql: sql/summary.sql
        key: id
        fields:
          - id: summary
            type: string
            maxLength: 16
            classification: internal
    accessProfiles:
      - rowBoundaries: []
        id: reader
        principalClaim: principal
        operations: [list]
        readableFields: [code, summary]
"#,
    )
    .expect("module fixture writes");
    fs::write(
        module_dir.join("sql/summary.sql"),
        b"SELECT SQL_VALUE_CANARY FROM",
    )
    .expect("SQL fixture writes");

    let check = bregctl(&["--format", "json", "check", path(project.path())]);

    assert_eq!(check.status.code(), Some(1), "{check:?}");
    let rendered = String::from_utf8_lossy(&check.stdout);
    assert!(!rendered.contains("SQL_VALUE_CANARY"));
    assert!(!rendered.contains("SELECT"));
    let report = json_stdout(&check);
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(diagnostic["code"], "breg.derived.sql-invalid");
    assert_eq!(diagnostic["path"], "/entities/0/derived/0/sql");
    assert_eq!(
        diagnostic["source"]["file"],
        project
            .path()
            .join("modules/core/module.yaml")
            .display()
            .to_string()
    );
    assert!(diagnostic["source"]["line"].as_u64().is_some());
    assert_check_diagnostic(diagnostic, Some("BRegModule"));
}

#[test]
fn explain_events_is_empty_for_outbox_only_and_deterministic_for_webhooks() {
    let no_events = TestProject::asset_fixture();
    let empty = bregctl(&[
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
  version: "1"
  defaultLanguage: en
  canonicalBaseIri: https://event-explain-outbox.example.test
entities:
  - id: case
    primaryDataset: test-dataset
    route: cases
    mutationMode: mutable
    fields:
      - id: label
        type: string
        maxLength: 64
        classification: public
    hooks:
      - id: case-created
        phase: after
        trigger: created
        projection: [label]
"#,
    );
    let outbox = bregctl(&[
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
  version: "1"
  defaultLanguage: en
  canonicalBaseIri: https://event-explain-webhook.example.test
entities:
  - id: case
    primaryDataset: test-dataset
    route: cases
    mutationMode: mutable
    fields:
      - id: label
        type: string
        maxLength: 64
        classification: public
    hooks:
      - id: case-created
        phase: after
        trigger: created
        projection: [label]
        handler:
          kind: url
          destinationId: case-operations
"#,
    );
    let arguments = [
        "--format",
        "json",
        "explain",
        "events",
        webhook.path().to_str().expect("path is UTF-8"),
    ];
    let first = bregctl(&arguments);
    let second = bregctl(&arguments);
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
            "dataSchema",
            "dataSchemaArtifactPath",
            "dataSchemaFingerprint",
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
            "retryProfile",
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
fn production_package_publishes_the_unsigned_package_in_one_step() {
    let project = packaging_project();
    let build = project.path().join("build");
    let fingerprint = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    let expected = prepare_packaging_candidate(&project, fingerprint);
    let receipt = project.path().join("schema-test-receipt.json");
    let receipt_bytes = schema_test_receipt_bytes(&expected, &["package-record-list"]);
    fs::write(&receipt, &receipt_bytes).expect("schema-test receipt writes");

    let published = package_candidate_command(&project, fingerprint, &receipt, &build);
    assert!(published.status.success(), "{published:?}");
    assert!(published.stderr.is_empty());
    let report = json_stdout(&published);
    assert_eq!(report["command"], "package");
    assert_eq!(report["profile"], "production");
    assert_eq!(
        report["packageDigest"],
        expected
            .package_digest()
            .expect("the package digest derives")
    );
    assert_eq!(report["registryRevision"], expected.registry().revision());
    for retired in [
        "state",
        "signatureThreshold",
        "providedSignatures",
        "signingInput",
        "packageRevision",
    ] {
        assert!(report.get(retired).is_none(), "{retired} is not reported");
    }
    assert_eq!(
        fs::read(build.join("schema-test-receipt.json")).expect("reviewer receipt reads"),
        receipt_bytes
    );
    assert!(!build.join("signing-input.json").exists());
    assert!(build.join("package/package.json").is_file());
    assert!(build.join("package/SHA256SUMS").is_file());
    assert!(!build.join("package/signatures.json").exists());
    assert!(!tree(&build.join("package"))
        .keys()
        .any(|entry| entry.contains("schema-test-receipt")));
    let envelope: Value = serde_json::from_slice(
        &fs::read(build.join("package/package.json")).expect("package envelope reads"),
    )
    .expect("package envelope parses");
    assert!(envelope.get("signed").is_none());
    assert!(envelope.get("signatures").is_none());
    assert!(!envelope["manifest"]["files"]
        .as_array()
        .expect("package files are an array")
        .iter()
        .any(|entry| entry["path"] == "schema-test-receipt.json"));

    let runtime = write_runtime_config(
        project.path(),
        &build.join("package"),
        "127.0.0.1:1".parse().unwrap(),
    );
    let verified = bregctl(&[
        "--format",
        "json",
        "verify",
        "--runtime-config",
        path(&runtime),
    ]);
    assert!(verified.status.success(), "{verified:?}");
    assert_eq!(
        json_stdout(&verified)["packageDigest"],
        report["packageDigest"]
    );

    let rendered = String::from_utf8(published.stdout).expect("package report is UTF-8");
    for forbidden in [path(project.path()), PACKAGE_VALUE_CANARY] {
        assert!(!rendered.contains(forbidden));
    }
}

#[test]
fn package_refuses_missing_noncanonical_and_stale_receipts_before_output() {
    let project = packaging_project();
    let fingerprint = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    let prepared = prepare_packaging_candidate(&project, fingerprint);
    let valid_receipt = schema_test_receipt_bytes(&prepared, &["package-record-list"]);
    let receipt = project.path().join("candidate-receipt.json");

    let missing_build = project.path().join("missing-receipt-build");
    let missing = package_candidate_command(&project, fingerprint, &receipt, &missing_build);
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
    let refused = package_candidate_command(&project, fingerprint, &receipt, &refused_build);
    assert_eq!(refused.status.code(), Some(1), "{refused:?}");
    let refused_report = json_stdout(&refused);
    assert_eq!(refused_report["ok"], false);
    assert_eq!(refused_report["command"], "package");
    let refused_diagnostics = refused_report["diagnostics"]
        .as_array()
        .expect("diagnostics are a list");
    assert_eq!(refused_diagnostics.len(), 1, "{refused_report}");
    assert_eq!(refused_diagnostics[0]["code"], "breg.receipt.not-canonical");
    assert_eq!(refused_diagnostics[0]["artifact"], "BRegSchemaTestReceipt");
    assert_eq!(refused_diagnostics[0]["path"], "");
    assert_eq!(
        refused_diagnostics[0]["source"]["file"],
        path(&receipt),
        "the receipt is named as the command was given it"
    );
    assert_eq!(refused_diagnostics[0]["source"]["line"], 1);
    assert!(refused_diagnostics[0]["suggestedAction"]
        .as_str()
        .is_some_and(|action| action.contains("bregctl test")));
    assert!(!refused_build.exists());

    let missing_rendered = String::from_utf8(missing.stdout).expect("missing diagnostic is UTF-8");
    assert!(!missing_rendered.contains(path(project.path())));
    assert!(!missing_rendered.contains("candidate-receipt"));
    let refused_rendered = String::from_utf8(refused.stdout).expect("refused diagnostic is UTF-8");
    for rendered in [missing_rendered, refused_rendered] {
        assert!(!rendered.contains(PACKAGE_DATABASE));
    }
}

#[test]
fn package_receipt_is_stale_for_every_candidate_binding_change() {
    let project = packaging_project();
    let fingerprint = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    let prepared = prepare_packaging_candidate(&project, fingerprint);
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
    let altered_module = String::from_utf8(original_module.clone())
        .expect("module is UTF-8")
        .replace("\"maxLength\":16", "\"maxLength\":17")
        .into_bytes();
    let altered_module_model =
        parse_module_json(&altered_module).expect("altered package module parses");
    let altered_module_digest = module_digest(&altered_module_model);
    let cases = [
        (
            "fingerprint",
            "package.test_receipt.fingerprint_mismatch",
            original_project.clone(),
            original_module.clone(),
            original_journeys.clone(),
            "sha256:4444444444444444444444444444444444444444444444444444444444444444".to_owned(),
        ),
        (
            "project",
            "package.test_receipt.candidate_mismatch",
            original_project_text
                .replace(PACKAGE_SOURCE_REVISION, "alternate-source")
                .into_bytes(),
            original_module.clone(),
            original_journeys.clone(),
            fingerprint.to_owned(),
        ),
        (
            "module",
            "package.test_receipt.candidate_mismatch",
            original_project_text
                .replace(&original_module_digest, &altered_module_digest)
                .into_bytes(),
            altered_module,
            original_journeys.clone(),
            fingerprint.to_owned(),
        ),
        (
            "journey",
            "package.test_receipt.candidate_mismatch",
            original_project.clone(),
            original_module.clone(),
            String::from_utf8(original_journeys.clone())
                .expect("journeys are UTF-8")
                .replace("package-record-list", "package-record-list-alternate")
                .into_bytes(),
            fingerprint.to_owned(),
        ),
    ];

    for (name, expected_code, project_bytes, module_bytes, journeys, fingerprint) in cases {
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
        let output = package_candidate_command(&project, &fingerprint, &receipt, &build);
        assert_eq!(output.status.code(), Some(1), "{name}: {output:?}");
        let report = json_stdout(&output);
        assert_eq!(report["diagnostics"][0]["code"], expected_code, "{name}");
        assert!(!build.exists(), "{name}");
        let rendered = String::from_utf8(output.stdout).expect("diagnostic is UTF-8");
        assert!(!rendered.contains(path(project.path())), "{name}");
    }

    // The same sources packaged as a successor of another package bind a
    // predecessor digest the receipt does not record.
    fs::write(project.path().join("registry.yaml"), &original_project)
        .expect("original project restores");
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
    let successor_build = project.path().join("stale-predecessor-build");
    let successor = bregctl(&[
        "--format",
        "json",
        "package",
        path(project.path()),
        "--schema-fingerprint",
        fingerprint,
        "--baseline-package",
        path(&baseline.package),
        "--test-receipt",
        path(&receipt),
        "--output",
        path(&successor_build),
    ]);
    assert_eq!(successor.status.code(), Some(1), "{successor:?}");
    let diagnostic = &json_stdout(&successor)["diagnostics"][0];
    assert_eq!(
        diagnostic["code"],
        "package.test_receipt.candidate_mismatch"
    );
    assert_eq!(diagnostic["path"], "testReceipt.priorPackageDigest");
    assert!(!successor_build.exists());
}

#[test]
fn package_takes_the_schema_fingerprint_from_the_receipt_and_refuses_disagreement() {
    let project = packaging_project();
    let fingerprint = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    let disagreeing = "sha256:3333333333333333333333333333333333333333333333333333333333333333";
    let prepared = prepare_packaging_candidate(&project, fingerprint);
    let receipt = project.path().join("fingerprint-receipt.json");
    fs::write(
        &receipt,
        schema_test_receipt_bytes(&prepared, &["package-record-list"]),
    )
    .expect("schema-test receipt writes");
    let derived_build = project.path().join("derived-fingerprint-build");

    let derived = bregctl(&[
        "--format",
        "json",
        "package",
        path(project.path()),
        "--test-receipt",
        path(&receipt),
        "--output",
        path(&derived_build),
    ]);

    assert!(derived.status.success(), "{derived:?}");
    let report = json_stdout(&derived);
    assert_eq!(
        report["packageDigest"],
        prepared
            .package_digest()
            .expect("the package digest derives")
    );
    assert!(derived_build.join("package/package.json").is_file());
    assert!(derived_build.join("schema-test-receipt.json").is_file());

    let disagreeing_build = project.path().join("disagreeing-fingerprint-build");
    let refused = package_candidate_command(&project, disagreeing, &receipt, &disagreeing_build);

    assert_eq!(refused.status.code(), Some(1), "{refused:?}");
    let report = json_stdout(&refused);
    assert_eq!(
        report["diagnostics"][0]["code"],
        "package.test_receipt.fingerprint_mismatch"
    );
    let message = report["diagnostics"][0]["message"]
        .as_str()
        .expect("fingerprint message is a string");
    assert!(message.contains(fingerprint), "{message}");
    assert!(message.contains(disagreeing), "{message}");
    assert!(!disagreeing_build.exists());
}

#[test]
fn package_resume_requires_the_exact_receipt_evidence() {
    let project = packaging_project();
    let fingerprint = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
    let prepared = prepare_packaging_candidate(&project, fingerprint);
    let receipt = project.path().join("resume-receipt.json");
    let receipt_bytes = schema_test_receipt_bytes(&prepared, &["package-record-list"]);
    fs::write(&receipt, &receipt_bytes).expect("schema-test receipt writes");
    let build = project.path().join("resume-build");

    let first = package_candidate_command(&project, fingerprint, &receipt, &build);
    assert!(first.status.success(), "{first:?}");
    assert!(build.join("package/package.json").is_file());

    // A build directory that already holds a published package is never
    // written again.
    let republished = package_candidate_command(&project, fingerprint, &receipt, &build);
    assert_eq!(republished.status.code(), Some(1), "{republished:?}");
    assert_eq!(
        json_stdout(&republished)["diagnostics"][0]["code"],
        "package.output.refused"
    );

    // A run interrupted before it published leaves only the reviewer evidence,
    // and resuming it requires that exact evidence.
    fs::remove_dir_all(build.join("package")).expect("published package removes");
    fs::remove_file(build.join("schema-test-receipt.json"))
        .expect("build receipt evidence removes");
    let missing = package_candidate_command(&project, fingerprint, &receipt, &build);
    assert_eq!(missing.status.code(), Some(1), "{missing:?}");
    assert_eq!(
        json_stdout(&missing)["diagnostics"][0]["code"],
        "package.test_receipt.evidence_mismatch"
    );
    assert!(!build.join("package").exists());

    fs::write(build.join("schema-test-receipt.json"), b"substituted")
        .expect("substituted receipt evidence writes");
    let substituted = package_candidate_command(&project, fingerprint, &receipt, &build);
    assert_eq!(substituted.status.code(), Some(1), "{substituted:?}");
    assert_eq!(
        json_stdout(&substituted)["diagnostics"][0]["code"],
        "package.test_receipt.evidence_mismatch"
    );
    assert!(!build.join("package").exists());

    fs::write(build.join("schema-test-receipt.json"), receipt_bytes)
        .expect("exact receipt evidence restores");
    let resumed = package_candidate_command(&project, fingerprint, &receipt, &build);
    assert!(resumed.status.success(), "{resumed:?}");
    assert_eq!(
        json_stdout(&resumed)["packageDigest"],
        json_stdout(&first)["packageDigest"]
    );
}

#[test]
fn test_help_requires_test_inputs_and_exposes_no_package_or_apply_authority() {
    let help = bregctl(&["test", "--help"]);
    assert!(help.status.success(), "{help:?}");
    let rendered = String::from_utf8(help.stdout).expect("help is UTF-8");
    for required in ["--runtime-config", "--credentials", "--output"] {
        assert!(rendered.contains(required), "help omits {required}");
    }
    for forbidden in [
        "--test-receipt",
        "--signatures",
        "--schema-fingerprint",
        "--package ",
        "--initial",
        "--backup",
        "--database-id",
        "--baseline-runtime-config",
        "--signature-threshold",
        "--signature-key-id",
    ] {
        assert!(!rendered.contains(forbidden), "help exposes {forbidden}");
    }

    let missing = bregctl(&["--format", "json", "test"]);
    assert_eq!(missing.status.code(), Some(2), "{missing:?}");
    assert_eq!(
        json_stdout(&missing)["diagnostics"][0]["code"],
        "usage.invalid"
    );

    let project = TestProject::from_registry_source(authoring_fixture());
    let rejected_schema_fingerprint = bregctl(&[
        "--format",
        "json",
        "test",
        path(project.path()),
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

    let package_reads_the_receipt_fingerprint = bregctl(&[
        "--format",
        "json",
        "package",
        path(project.path()),
        "--test-receipt",
        path(&project.path().join("receipt.json")),
        "--output",
        path(&project.path().join("build")),
    ]);
    assert_eq!(package_reads_the_receipt_fingerprint.status.code(), Some(1));
    assert_eq!(
        json_stdout(&package_reads_the_receipt_fingerprint)["diagnostics"][0]["code"],
        "package.test_receipt.missing"
    );
}

#[test]
fn test_fingerprint_only_needs_only_the_runtime_configuration() {
    let help = bregctl(&["test", "--help"]);
    assert!(help.status.success(), "{help:?}");
    assert!(String::from_utf8(help.stdout)
        .expect("help is UTF-8")
        .contains("--fingerprint-only"));

    let project = TestProject::from_registry_source(authoring_fixture());
    let project_path = path(project.path());
    let runtime_config = project.path().join("runtime.yaml");
    let credentials = project.path().join("credentials.yaml");
    let output = project.path().join("receipt.json");
    let baseline = project.path().join("baseline");
    for (flag, value) in [
        ("--credentials", path(&credentials)),
        ("--output", path(&output)),
        ("--baseline-package", path(&baseline)),
    ] {
        let conflicting = bregctl(&[
            "--format",
            "json",
            "test",
            project_path,
            "--fingerprint-only",
            "--runtime-config",
            path(&runtime_config),
            flag,
            value,
        ]);
        assert_eq!(
            conflicting.status.code(),
            Some(2),
            "{flag}: {conflicting:?}"
        );
        assert_eq!(
            json_stdout(&conflicting)["diagnostics"][0]["code"],
            "usage.invalid",
            "{flag}"
        );
    }

    let without_receipt_inputs = bregctl(&[
        "--format",
        "json",
        "test",
        project_path,
        "--runtime-config",
        path(&runtime_config),
    ]);
    assert_eq!(without_receipt_inputs.status.code(), Some(2));
    assert_eq!(
        json_stdout(&without_receipt_inputs)["diagnostics"][0]["code"],
        "usage.invalid"
    );

    // Without credentials or an output, the measurement still reaches the
    // configured database; the fixture names one that is unavailable.
    let candidate = packaging_project();
    let candidate_runtime = test_runtime_config(&candidate);
    let measured = bregctl(&[
        "--format",
        "json",
        "test",
        path(candidate.path()),
        "--fingerprint-only",
        "--runtime-config",
        path(&candidate_runtime),
    ]);
    assert_eq!(measured.status.code(), Some(1), "{measured:?}");
    let report = json_stdout(&measured);
    assert_eq!(report["command"], "test");
    assert_eq!(
        report["diagnostics"][0]["code"],
        "test.database.unavailable"
    );
    assert!(!candidate.path().join("schema-test-receipt.json").exists());
}

#[test]
fn refused_fixture_journeys_name_the_journey_file_and_the_refusal() {
    let project = packaging_project();
    let runtime = test_runtime_config(&project);
    write_test_secret(&project, "operator-token", b"aaa.bbb.ccc");
    let credentials = project.path().join("journey-credentials.yaml");
    fs::write(
        &credentials,
        credential_source("type: bearer\n      tokenRef: secret:file/operator-token\n"),
    )
    .expect("credential fixture writes");
    fs::write(
        project.path().join("tests/journeys.yaml"),
        br#"apiVersion: id.registrystack.org/formats/breg/journeys/v0
kind: BRegJourneys
journeys:
  - id: package-record-list
    steps:
      - id: list-records
        entity: record
        accessProfile: reader
        claims: {principal: package-reader}
        request: {type: list}
        expect: {outcome: success, status: 200, count: 0}
"#,
    )
    .expect("refused journey suite writes");
    let output = project.path().join("journey-receipt.json");

    let result = test_candidate_command(&project, &runtime, &credentials, &output);

    let rendered = String::from_utf8(result.stdout.clone()).expect("refusal JSON is UTF-8");
    let report: Value = serde_json::from_str(&rendered).expect("refusal JSON parses");
    assert_eq!(result.status.code(), Some(1), "{rendered}");
    assert_eq!(report["command"], "test");
    let diagnostics = report["diagnostics"]
        .as_array()
        .expect("diagnostics are a list");
    assert_eq!(diagnostics.len(), 1, "{rendered}");
    assert_eq!(diagnostics[0]["code"], "config.unsupported-api-version");
    assert_eq!(diagnostics[0]["artifact"], "BRegJourneys");
    assert_eq!(diagnostics[0]["path"], "/apiVersion");
    assert_eq!(
        diagnostics[0]["source"]["file"],
        project
            .path()
            .join("tests/journeys.yaml")
            .display()
            .to_string()
    );
    assert_eq!(diagnostics[0]["source"]["line"], 1);
    let message = diagnostics[0]["message"]
        .as_str()
        .expect("journey message is a string");
    assert!(
        message.contains("id.registrystack.org/formats/breg/journeys/v1"),
        "{message}"
    );
    assert!(!output.exists());
}

#[test]
fn refused_credentials_name_the_document_path_and_the_journey() {
    let project = packaging_project();
    let runtime = test_runtime_config(&project);
    write_test_secret(&project, "operator-token", b"aaa.bbb.ccc");
    let credentials = project.path().join("unknown-journey-credentials.yaml");
    fs::write(
        &credentials,
        r#"apiVersion: id.registrystack.org/formats/breg/schema-test-credentials/v1
kind: BRegSchemaTestCredentials
bindings:
  - journeyId: package-record-lists
    stepId: list-records
    credential:
      type: bearer
      tokenRef: secret:file/operator-token
"#,
    )
    .expect("credential fixture writes");
    let output = project.path().join("unknown-journey-receipt.json");

    let result = test_candidate_command(&project, &runtime, &credentials, &output);

    let rendered = String::from_utf8(result.stdout.clone()).expect("refusal JSON is UTF-8");
    let report: Value = serde_json::from_str(&rendered).expect("refusal JSON parses");
    assert_eq!(result.status.code(), Some(1), "{rendered}");
    assert_eq!(report["ok"], false);
    assert_eq!(report["command"], "test");
    assert_eq!(report["diagnostics"].as_array().map(Vec::len), Some(1));
    assert_eq!(
        report["diagnostics"][0]["code"],
        "breg.credentials.unknown-journey"
    );
    assert_eq!(report["diagnostics"][0]["path"], "/bindings/0/journeyId");
    assert_eq!(
        report["diagnostics"][0]["source"],
        json!({"file": path(&credentials), "line": 4, "column": 16})
    );
    let message = report["diagnostics"][0]["message"]
        .as_str()
        .expect("credential message is a string");
    assert!(!message.contains("package-record-list"), "{message}");
    assert!(
        !rendered.contains("secret:file/operator-token"),
        "{rendered}"
    );
    assert!(!rendered.contains("aaa.bbb.ccc"), "{rendered}");
    assert!(!output.exists());

    let duplicate = project.path().join("duplicate-credentials.yaml");
    fs::write(
        &duplicate,
        r#"apiVersion: id.registrystack.org/formats/breg/schema-test-credentials/v1
kind: BRegSchemaTestCredentials
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
"#,
    )
    .expect("credential fixture writes");
    let duplicate_output = project.path().join("duplicate-receipt.json");

    let result = test_candidate_command(&project, &runtime, &duplicate, &duplicate_output);

    let rendered = String::from_utf8(result.stdout.clone()).expect("refusal JSON is UTF-8");
    let report: Value = serde_json::from_str(&rendered).expect("refusal JSON parses");
    assert_eq!(result.status.code(), Some(1), "{rendered}");
    assert_eq!(
        report["diagnostics"][0]["code"],
        "breg.credentials.duplicate-binding"
    );
    assert_eq!(report["diagnostics"][0]["path"], "/bindings/1");
    assert_eq!(report["diagnostics"][0]["source"]["line"], 9);
    let message = report["diagnostics"][0]["message"]
        .as_str()
        .expect("credential message is a string");
    assert!(!message.contains("package-record-list"), "{message}");
    assert!(!message.contains("list-records"), "{message}");
    assert!(
        !rendered.contains("secret:file/operator-token"),
        "{rendered}"
    );
    assert!(!duplicate_output.exists());
}

#[test]
fn test_credentials_are_strict_secret_refs_and_preflight_before_database() {
    let project = packaging_project();
    let runtime = test_runtime_config(&project);
    write_test_secret(&project, "operator-token", b"aaa.bbb.ccc");

    let cases = [
        (
            "duplicate-field",
            "yaml.duplicate-key",
            "/apiVersion",
            r#"apiVersion: id.registrystack.org/formats/breg/schema-test-credentials/v1
apiVersion: id.registrystack.org/formats/breg/schema-test-credentials/v1
kind: BRegSchemaTestCredentials
bindings: []
"#
            .to_owned(),
        ),
        (
            "unknown-field",
            "config.unknown-key",
            "/literal",
            r#"apiVersion: id.registrystack.org/formats/breg/schema-test-credentials/v1
kind: BRegSchemaTestCredentials
bindings: []
literal: aaa.bbb.ccc
"#
            .to_owned(),
        ),
        (
            "literal-token",
            "config.unknown-key",
            "/bindings/0/credential/token",
            credential_source("type: bearer\n      token: aaa.bbb.ccc\n"),
        ),
        (
            "missing-token-ref",
            "config.missing-key",
            "/bindings/0/credential",
            credential_source("type: bearer\n"),
        ),
        (
            "extra-token-ref",
            "config.unknown-key",
            "/bindings/0/credential/tokenRef",
            credential_source("type: anonymous\n      tokenRef: secret:file/operator-token\n"),
        ),
        (
            "wrong-discriminator",
            "config.missing-key",
            "/bindings/0/credential",
            credential_source("mode: bearer\n      tokenRef: secret:file/operator-token\n"),
        ),
        (
            "literal-ref",
            "config.invalid-value",
            "/bindings/0/credential/tokenRef",
            credential_source("type: bearer\n      tokenRef: aaa.bbb.ccc\n"),
        ),
        (
            "unknown-provider",
            "config.invalid-value",
            "/bindings/0/credential/tokenRef",
            credential_source("type: bearer\n      tokenRef: secret:literal/operator-token\n"),
        ),
        (
            "missing-coverage",
            "breg.credentials.incomplete-bindings",
            "/bindings",
            r#"apiVersion: id.registrystack.org/formats/breg/schema-test-credentials/v1
kind: BRegSchemaTestCredentials
bindings: []
"#
            .to_owned(),
        ),
        (
            "duplicate-binding",
            "breg.credentials.duplicate-binding",
            "/bindings/1",
            r#"apiVersion: id.registrystack.org/formats/breg/schema-test-credentials/v1
kind: BRegSchemaTestCredentials
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

    for (name, code, pointer, source) in cases {
        let credentials = project.path().join(format!("credentials-{name}.yaml"));
        fs::write(&credentials, source).expect("credential fixture writes");
        let output = project.path().join(format!("receipt-{name}.json"));
        let result = test_candidate_command(&project, &runtime, &credentials, &output);
        assert_credentials_document_refusal(
            result,
            &credentials,
            code,
            pointer,
            &output,
            &["aaa.bbb.ccc", "secret:file/operator-token"],
        );
    }
}

#[test]
fn test_credentials_secret_value_failures_are_preflight_and_value_free() {
    let project = packaging_project();
    let runtime = test_runtime_config(&project);
    let unresolved = "breg.credentials.unresolved-secret";
    let token_ref = "/bindings/0/credential/tokenRef";
    let cases: Vec<(&str, &str, &str, Vec<u8>)> = vec![
        (
            "utf8",
            unresolved,
            token_ref,
            vec![0xff, b'.', b'a', b'.', b'b'],
        ),
        ("empty", unresolved, token_ref, Vec::new()),
        ("oversized", unresolved, token_ref, vec![b'a'; 65 * 1024]),
        (
            "malformed-token",
            "breg.credentials.incomplete-bindings",
            "/bindings",
            b"not.a-token!".to_vec(),
        ),
    ];

    for (name, code, pointer, secret) in cases {
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
        let result = test_candidate_command(&project, &runtime, &credentials, &output);
        assert_credentials_document_refusal(
            result,
            &credentials,
            code,
            pointer,
            &output,
            &[&secret_name, "not.a-token!"],
        );
    }
}

#[test]
fn test_valid_credentials_reach_database_and_never_publish_partial_receipts() {
    let project = packaging_project();
    let runtime = test_runtime_config(&project);
    write_test_secret(&project, "operator-token", b"aaa.bbb.ccc");
    let credentials = project.path().join("valid-credentials.yaml");
    fs::write(
        &credentials,
        credential_source("type: bearer\n      tokenRef: secret:file/operator-token\n"),
    )
    .expect("credential fixture writes");
    let output = project.path().join("schema-test-receipt.json");
    let result = test_candidate_command(&project, &runtime, &credentials, &output);

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
    assert!(!project.path().join("package").exists());
    assert!(!project.path().join("apply").exists());
    assert!(
        fs::read_dir(project.path())
            .expect("project directory reads")
            .all(|entry| !entry
                .expect("entry reads")
                .file_name()
                .to_string_lossy()
                .starts_with(".bregctl-test-receipt-")),
        "temporary receipt files are cleaned up"
    );
}

#[test]
fn authoring_and_test_candidate_sources_are_read_once_and_bounded() {
    let oversized_yaml_comment = vec![b'#'; SCHEMA_TEST_AUTHORED_SOURCE_CEILING_BYTES + 1];

    let project = packaging_project();
    fs::write(
        project.path().join("registry.yaml"),
        &oversized_yaml_comment,
    )
    .expect("oversized project source writes");
    let check_project = bregctl(&["--format", "json", "check", path(project.path())]);
    assert_eq!(check_project.status.code(), Some(1), "{check_project:?}");
    let project_report = json_stdout(&check_project);
    assert_eq!(project_report["diagnostics"][0]["code"], "yaml.too-large");
    assert_eq!(
        project_report["diagnostics"][0]["source"]["file"],
        project.path().join("registry.yaml").display().to_string()
    );
    let test_project = test_candidate_command(
        &project,
        &project.path().join("unused-runtime.yaml"),
        &project.path().join("unused-credentials.yaml"),
        &project.path().join("oversized-project-receipt.json"),
    );
    assert_schema_test_refusal(
        test_project,
        "breg.source.file-bounds",
        "registry_project",
        "correct_authoring_source",
        &project.path().join("oversized-project-receipt.json"),
        &[path(project.path()), "unused-runtime", "unused-credentials"],
    );

    let project = packaging_project();
    fs::write(
        project.path().join("modules/core/module.yaml"),
        oversized_yaml_comment,
    )
    .expect("oversized module source writes");
    let check_module = bregctl(&["--format", "json", "check", path(project.path())]);
    assert_eq!(check_module.status.code(), Some(1), "{check_module:?}");
    let module_report = json_stdout(&check_module);
    assert_eq!(module_report["diagnostics"][0]["code"], "yaml.too-large");
    assert_eq!(
        module_report["diagnostics"][0]["source"]["file"],
        project
            .path()
            .join("modules/core/module.yaml")
            .display()
            .to_string()
    );
    let test_module = test_candidate_command(
        &project,
        &project.path().join("unused-runtime.yaml"),
        &project.path().join("unused-credentials.yaml"),
        &project.path().join("oversized-module-receipt.json"),
    );
    assert_schema_test_refusal(
        test_module,
        "breg.source.file-bounds",
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
        let result = bregctl(&[
            "--format",
            "json",
            "test",
            path(project.path()),
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
    let result = bregctl(&[
        "--format",
        "json",
        "test",
        path(project.path()),
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

    let project = packaging_project();
    let journey_path = project.path().join("tests/journeys.yaml");
    let build = project.path().join("fixture-source-build");
    let missing_receipt = project.path().join("missing-receipt.json");
    let arguments = [
        "--format",
        "json",
        "package",
        path(project.path()),
        "--schema-fingerprint",
        "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        "--test-receipt",
        path(&missing_receipt),
        "--output",
        path(&build),
    ];

    fs::remove_file(&journey_path).expect("fixture journeys remove");
    let missing = bregctl(&arguments);
    assert_eq!(missing.status.code(), Some(1), "{missing:?}");
    let missing_report = json_stdout(&missing);
    assert_eq!(
        missing_report["diagnostics"][0]["code"],
        "breg.source.fixture-journeys-missing"
    );
    assert_eq!(
        missing_report["diagnostics"][0]["path"],
        "tests/journeys.yaml"
    );

    let target = project.path().join("journey-source-canary.yaml");
    fs::write(&target, b"journey-source-value-canary").expect("symlink target writes");
    symlink(&target, &journey_path).expect("fixture journey symlink creates");
    let linked = bregctl(&arguments);
    assert_eq!(linked.status.code(), Some(1), "{linked:?}");
    let linked_report = json_stdout(&linked);
    assert_eq!(
        linked_report["diagnostics"][0]["code"],
        "breg.source.file-invalid"
    );
    assert_eq!(
        linked_report["diagnostics"][0]["path"],
        "tests/journeys.yaml"
    );
    fs::remove_file(&journey_path).expect("fixture journey symlink removes");

    fs::write(
        &journey_path,
        vec![b'x'; usize::try_from(MAX_PACKAGE_SOURCE_FILE_BYTES).unwrap() + 1],
    )
    .expect("oversized fixture journey writes");
    let oversized = bregctl(&arguments);
    assert_eq!(oversized.status.code(), Some(1), "{oversized:?}");
    let oversized_report = json_stdout(&oversized);
    assert_eq!(
        oversized_report["diagnostics"][0]["code"],
        "breg.source.file-bounds"
    );
    assert_eq!(
        oversized_report["diagnostics"][0]["path"],
        "tests/journeys.yaml"
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
    let output = bregctl(&[
        "--format",
        "json",
        "package",
        path(project.path()),
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
        .any(|diagnostic| diagnostic["code"] == "breg.package.identity-required"));
    assert!(!build.exists());

    let help = bregctl(&["--help"]);
    let help = String::from_utf8(help.stdout).expect("help is UTF-8");
    assert!(!help
        .lines()
        .any(|line| line.trim_start().starts_with("sign")));
}

#[test]
fn apply_verifies_package_intent_before_database_authority_and_stays_value_free() {
    let relative = bregctl(&[
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
    let malformed_backup = bregctl(&[
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

    let control_reference = format!("{PACKAGE_VALUE_CANARY}\u{7}");
    let long_reference = format!("{PACKAGE_VALUE_CANARY}{}", "r".repeat(512));
    for reference in [control_reference.as_str(), long_reference.as_str()] {
        let refused = bregctl(&[
            "--format",
            "json",
            "apply",
            "--runtime-config",
            path(&fixture.runtime_config),
            "--package",
            path(&fixture.package),
            "--initial",
            "--operator-reference",
            reference,
        ]);
        assert_eq!(refused.status.code(), Some(1), "{refused:?}");
        assert_eq!(
            json_stdout(&refused)["diagnostics"][0]["code"],
            "apply.operator_reference.refused"
        );
        assert!(!String::from_utf8_lossy(&refused.stdout).contains(PACKAGE_VALUE_CANARY));
        assert!(!String::from_utf8_lossy(&refused.stderr).contains(PACKAGE_VALUE_CANARY));
    }

    // A package names no place in the apply order, so whether another package
    // follows the active one is the database's answer: it reaches database
    // authority, and the refusal stays value free.
    let other = RuntimePackageFixture::production_with_module(
        "127.0.0.1:1".parse().unwrap(),
        String::from_utf8(package_module_bytes())
            .unwrap()
            .replace(r#""maxLength":16"#, r#""maxLength":32"#)
            .into_bytes(),
    );
    assert_ne!(other.package_digest, fixture.package_digest);
    let output = bregctl(&[
        "--format",
        "json",
        "apply",
        "--runtime-config",
        path(&fixture.runtime_config),
        "--package",
        path(&other.package),
    ]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stderr.is_empty());
    let report = json_stdout(&output);
    assert_eq!(
        report["diagnostics"][0]["code"],
        "apply.database_configuration.refused"
    );
    let rendered = String::from_utf8(output.stdout).expect("apply refusal is UTF-8");
    for forbidden in [
        path(&fixture.runtime_config),
        path(&fixture.package),
        path(&other.package),
        fixture.package_digest.as_str(),
        other.package_digest.as_str(),
        PACKAGE_VALUE_CANARY,
        VERIFY_RUNTIME_DATABASE_SECRET_CANARY,
        VERIFY_MIGRATION_DATABASE_SECRET_CANARY,
    ] {
        assert!(!rendered.contains(forbidden));
    }

    // The active package itself is verified in full and then needs the
    // database to confirm it is active and ready, so it too reaches database
    // authority.
    let already_active = bregctl(&[
        "--format",
        "json",
        "apply",
        "--runtime-config",
        path(&fixture.runtime_config),
        "--package",
        path(&fixture.package),
    ]);
    assert_eq!(already_active.status.code(), Some(1), "{already_active:?}");
    assert_eq!(
        json_stdout(&already_active)["diagnostics"][0]["code"],
        "apply.database_configuration.refused"
    );
    let rendered = String::from_utf8_lossy(&already_active.stdout);
    assert!(!rendered.contains(VERIFY_RUNTIME_DATABASE_SECRET_CANARY));
    assert!(!rendered.contains(VERIFY_MIGRATION_DATABASE_SECRET_CANARY));

    let database_refusal = bregctl(&[
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
    let rendered = String::from_utf8_lossy(&database_refusal.stdout);
    assert!(!rendered.contains(VERIFY_RUNTIME_DATABASE_SECRET_CANARY));
    assert!(!rendered.contains(VERIFY_MIGRATION_DATABASE_SECRET_CANARY));
}

#[test]
fn plan_and_status_refuse_before_database_authority_and_name_the_next_command() {
    let help = bregctl(&["--help"]);
    let rendered = String::from_utf8(help.stdout).expect("top-level help is UTF-8");
    for available in ["plan", "status"] {
        assert!(
            rendered
                .lines()
                .any(|line| line.trim_start().starts_with(available)),
            "{rendered}"
        );
    }
    let plan_help = bregctl(&["plan", "--help"]);
    let plan_help = String::from_utf8(plan_help.stdout).expect("plan help is UTF-8");
    for required in [
        "--runtime-config <ABSOLUTE_FILE>",
        "--package <ABSOLUTE_DIRECTORY>",
        "--backup <BINDING_PATH=BINDING_FILE>",
    ] {
        assert!(plan_help.contains(required), "{plan_help}");
    }
    for refused in ["--initial", "--operator-reference", "--acknowledge"] {
        assert!(!plan_help.contains(refused), "{plan_help}");
    }
    let status_help = bregctl(&["status", "--help"]);
    let status_help = String::from_utf8(status_help.stdout).expect("status help is UTF-8");
    assert!(status_help.contains("--runtime-config <ABSOLUTE_FILE>"));
    assert!(!status_help.contains("--package"));

    let relative = bregctl(&[
        "--format",
        "json",
        "plan",
        "--runtime-config",
        PACKAGE_VALUE_CANARY,
        "--package",
        PACKAGE_VALUE_CANARY,
    ]);
    assert_eq!(relative.status.code(), Some(1), "{relative:?}");
    let report = json_stdout(&relative);
    assert_eq!(report["ok"], false);
    assert_eq!(report["command"], "plan");
    assert_eq!(
        report["diagnostics"][0]["code"],
        "apply.runtime_config.path_invalid"
    );
    assert!(!String::from_utf8_lossy(&relative.stdout).contains(PACKAGE_VALUE_CANARY));

    let relative = bregctl(&[
        "--format",
        "json",
        "status",
        "--runtime-config",
        PACKAGE_VALUE_CANARY,
    ]);
    assert_eq!(relative.status.code(), Some(1), "{relative:?}");
    let report = json_stdout(&relative);
    assert_eq!(report["command"], "status");
    assert_eq!(
        report["diagnostics"][0]["code"],
        "status.runtime_config.path_invalid"
    );

    // Both commands are read-only, yet each needs the migration credential
    // the runtime file names; this fixture's is never opened, and the
    // refusal names the fix and stays value free.
    let fixture = RuntimePackageFixture::production("127.0.0.1:1".parse().unwrap());
    let planned = bregctl(&[
        "--format",
        "json",
        "plan",
        "--runtime-config",
        path(&fixture.runtime_config),
        "--package",
        path(&fixture.package),
    ]);
    let status = bregctl(&[
        "--format",
        "json",
        "status",
        "--runtime-config",
        path(&fixture.runtime_config),
    ]);
    for (output, command, code) in [
        (&planned, "plan", "apply.database_configuration.refused"),
        (&status, "status", "status.database_configuration.refused"),
    ] {
        assert_eq!(output.status.code(), Some(1), "{output:?}");
        assert!(output.stderr.is_empty(), "{output:?}");
        let report = json_stdout(output);
        assert_eq!(report["command"], command);
        assert_eq!(report["diagnostics"][0]["code"], code);
        let rendered = String::from_utf8_lossy(&output.stdout);
        for forbidden in [
            path(&fixture.runtime_config),
            path(&fixture.package),
            VERIFY_RUNTIME_DATABASE_SECRET_CANARY,
            VERIFY_MIGRATION_DATABASE_SECRET_CANARY,
        ] {
            assert!(!rendered.contains(forbidden), "{rendered}");
        }
    }

    let malformed_backup = bregctl(&[
        "--format",
        "json",
        "plan",
        "--runtime-config",
        path(&fixture.runtime_config),
        "--package",
        path(&fixture.package),
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
}

/// Runs bregctl with the fixture's migration credential set to a database
/// URL nothing listens on, so a refusal that reaches database contact reports
/// the database as unavailable.
fn bregctl_with_unreachable_database(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .env(
            VERIFY_MIGRATION_DATABASE_SECRET_CANARY,
            "postgresql://registry_migration@127.0.0.1:1/breg",
        )
        .args(arguments)
        .output()
        .expect("bregctl starts")
}

#[test]
fn apply_and_plan_refuse_a_package_other_than_the_expected_digest_before_database_contact() {
    let fixture = RuntimePackageFixture::production("127.0.0.1:1".parse().unwrap());
    // A successor reads the database's activation ledger before anything
    // else an apply opens, so reaching the database is the first refusal
    // after the package checks for both commands.
    let successor = RuntimePackageFixture::production_with_module(
        "127.0.0.1:1".parse().unwrap(),
        String::from_utf8(package_module_bytes())
            .unwrap()
            .replace(r#""maxLength":16"#, r#""maxLength":32"#)
            .into_bytes(),
    );
    let other_digest = fixture.package_digest.as_str();
    assert_ne!(other_digest, successor.package_digest);

    for command in ["apply", "plan"] {
        let run = |expected: Option<&str>| {
            let mut arguments = vec![
                "--format",
                "json",
                command,
                "--runtime-config",
                path(&fixture.runtime_config),
                "--package",
                path(&successor.package),
            ];
            if let Some(expected) = expected {
                arguments.extend(["--expected-digest", expected]);
            }
            bregctl_with_unreachable_database(&arguments)
        };

        // Without the flag, and with the digest of the package named, the
        // command reaches the database, which nothing serves.
        for reached in [run(None), run(Some(successor.package_digest.as_str()))] {
            assert_eq!(reached.status.code(), Some(1), "{reached:?}");
            assert_eq!(
                json_stdout(&reached)["diagnostics"][0]["code"],
                "apply.database.unavailable",
                "{command}"
            );
        }

        let refused = run(Some(other_digest));
        assert_eq!(refused.status.code(), Some(1), "{refused:?}");
        assert!(refused.stderr.is_empty(), "{refused:?}");
        let report = json_stdout(&refused);
        assert_eq!(report["ok"], false);
        assert_eq!(report["command"], command);
        let diagnostic = &report["diagnostics"][0];
        assert_eq!(diagnostic["code"], "apply.package.digest_mismatch");
        assert_eq!(diagnostic["path"], "package");
        assert_tool_diagnostic(
            diagnostic,
            "verified_package",
            "rerun_plan_on_intended_package",
        );
        let message = diagnostic["message"].as_str().expect("message is text");
        assert!(message.contains(other_digest), "{message}");
        assert!(message.contains(&successor.package_digest), "{message}");
        let rendered = String::from_utf8_lossy(&refused.stdout);
        for forbidden in [
            path(&fixture.runtime_config),
            path(&fixture.package),
            path(&successor.package),
            VERIFY_RUNTIME_DATABASE_SECRET_CANARY,
            VERIFY_MIGRATION_DATABASE_SECRET_CANARY,
        ] {
            assert!(!rendered.contains(forbidden), "{rendered}");
        }
    }
}

#[test]
fn apply_and_plan_take_the_expected_digest_only_as_a_sha256_label() {
    let fixture = RuntimePackageFixture::production("127.0.0.1:1".parse().unwrap());
    let digest_hex = fixture
        .package_digest
        .strip_prefix("sha256:")
        .expect("the package digest is a sha256 label");
    let uppercase = format!("sha256:{}", digest_hex.to_ascii_uppercase());
    let short = format!("sha256:{}", &digest_hex[1..]);
    let other_algorithm = format!("sha512:{digest_hex}");
    for command in ["apply", "plan"] {
        for malformed in [
            "",
            digest_hex,
            uppercase.as_str(),
            short.as_str(),
            other_algorithm.as_str(),
        ] {
            let output = bregctl(&[
                "--format",
                "json",
                command,
                "--runtime-config",
                path(&fixture.runtime_config),
                "--package",
                path(&fixture.package),
                "--expected-digest",
                malformed,
            ]);
            assert_eq!(output.status.code(), Some(2), "{command} {malformed:?}");
            assert!(output.stderr.is_empty(), "{output:?}");
            let report = json_stdout(&output);
            let diagnostic = &report["diagnostics"][0];
            assert_eq!(
                diagnostic["code"], "usage.invalid",
                "{command} {malformed:?}"
            );
            let message = diagnostic["message"].as_str().expect("message is text");
            assert!(
                message.contains("--expected-digest")
                    && message.contains("sha256: followed by 64 lowercase hex digits"),
                "{message}"
            );
        }
    }
}

#[test]
fn apply_refuses_a_stale_shared_envelope_before_database_authority() {
    let fixture = RuntimePackageFixture::production("127.0.0.1:1".parse().unwrap());
    fs::write(fixture.package.join("SHA256SUMS"), b"stale\n").expect("shared sum file is replaced");

    let refused = bregctl(&[
        "--format",
        "json",
        "apply",
        "--runtime-config",
        path(&fixture.runtime_config),
        "--package",
        path(&fixture.package),
        "--initial",
    ]);
    assert_eq!(refused.status.code(), Some(1), "{refused:?}");
    assert_eq!(
        json_stdout(&refused)["diagnostics"][0]["code"],
        "apply.package.refused"
    );
    let rendered = String::from_utf8(refused.stdout).expect("diagnostic is UTF-8");
    assert!(!rendered.contains(VERIFY_RUNTIME_DATABASE_SECRET_CANARY));
    assert!(!rendered.contains(VERIFY_MIGRATION_DATABASE_SECRET_CANARY));
}

#[test]
fn apply_requires_safe_field_encryption_custody_before_database_authority() {
    let fixture = RuntimePackageFixture::production_with_module(
        "127.0.0.1:1".parse().unwrap(),
        encrypted_package_module_bytes(),
    );
    let missing_provider = bregctl(&[
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
        missing_provider.status.code(),
        Some(1),
        "{missing_provider:?}"
    );
    assert_eq!(
        json_stdout(&missing_provider)["diagnostics"][0]["code"],
        "apply.field_encryption.configuration_refused"
    );

    let local_file_runtime = fixture.directory.path().join("local-file-runtime.yaml");
    let runtime = fs::read_to_string(&fixture.runtime_config).expect("runtime config reads");
    fs::write(
        &local_file_runtime,
        format!(
            "{runtime}\nfieldEncryption:\n  provider:\n    kind: localFile\n    dekRef: secret:file/field-encryption-dek\n"
        ),
    )
    .expect("runtime variant writes");
    let unsafe_custody = bregctl(&[
        "--format",
        "json",
        "apply",
        "--runtime-config",
        path(&local_file_runtime),
        "--package",
        path(&fixture.package),
        "--initial",
    ]);
    assert_eq!(unsafe_custody.status.code(), Some(1), "{unsafe_custody:?}");
    assert_eq!(
        json_stdout(&unsafe_custody)["diagnostics"][0]["code"],
        "apply.field_encryption.custody_refused"
    );
    let rendered = String::from_utf8(unsafe_custody.stdout).expect("apply refusal is UTF-8");
    assert!(!rendered.contains("field-encryption-dek"));
    assert!(!rendered.contains("VERIFY_MIGRATION_DATABASE_SECRET_IS_NOT_OPENED"));
}

#[test]
fn migration_reconcile_verifies_intent_before_database_authority_and_stays_value_free() {
    let relative = bregctl(&[
        "--format",
        "json",
        "migration",
        "reconcile",
        "--runtime-config",
        PACKAGE_VALUE_CANARY,
        "--package",
        PACKAGE_VALUE_CANARY,
        "--operator-reference",
        "change-1",
    ]);
    assert_eq!(relative.status.code(), Some(1), "{relative:?}");
    assert_eq!(
        json_stdout(&relative)["diagnostics"][0]["code"],
        "migration.reconcile.runtime_config.path_invalid"
    );
    assert!(!String::from_utf8_lossy(&relative.stdout).contains(PACKAGE_VALUE_CANARY));

    let fixture = RuntimePackageFixture::production("127.0.0.1:1".parse().unwrap());
    let relative_package = bregctl(&[
        "--format",
        "json",
        "migration",
        "reconcile",
        "--runtime-config",
        path(&fixture.runtime_config),
        "--package",
        PACKAGE_VALUE_CANARY,
        "--operator-reference",
        "change-1",
    ]);
    assert_eq!(
        relative_package.status.code(),
        Some(1),
        "{relative_package:?}"
    );
    assert_eq!(
        json_stdout(&relative_package)["diagnostics"][0]["code"],
        "migration.reconcile.package.path_invalid"
    );

    let empty_reference = bregctl(&[
        "--format",
        "json",
        "migration",
        "reconcile",
        "--runtime-config",
        path(&fixture.runtime_config),
        "--package",
        path(&fixture.package),
        "--operator-reference",
        "",
    ]);
    assert_eq!(
        empty_reference.status.code(),
        Some(1),
        "{empty_reference:?}"
    );
    assert_eq!(
        json_stdout(&empty_reference)["diagnostics"][0]["code"],
        "migration.reconcile.operator_reference.refused"
    );

    // The active package is never its own successor, so the pinned target is
    // refused before any database secret is resolved.
    let output = bregctl(&[
        "--format",
        "json",
        "migration",
        "reconcile",
        "--runtime-config",
        path(&fixture.runtime_config),
        "--package",
        path(&fixture.package),
        "--operator-reference",
        "change-1",
        "--execute",
    ]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stderr.is_empty());
    let report = json_stdout(&output);
    assert_eq!(
        report["diagnostics"][0]["code"],
        "migration.reconcile.package.refused"
    );
    assert_tool_diagnostic(
        &report["diagnostics"][0],
        "verified_package",
        "verify_package_binding",
    );
    let rendered = String::from_utf8(output.stdout).expect("reconcile refusal is UTF-8");
    for forbidden in [
        path(&fixture.runtime_config),
        path(&fixture.package),
        PACKAGE_VALUE_CANARY,
        VERIFY_RUNTIME_DATABASE_SECRET_CANARY,
        VERIFY_MIGRATION_DATABASE_SECRET_CANARY,
    ] {
        assert!(!rendered.contains(forbidden));
    }
}

#[test]
fn field_encryption_preflight_refuses_a_package_that_does_not_succeed_the_active_package() {
    let fixture = RuntimePackageFixture::production("127.0.0.1:1".parse().unwrap());
    let preflight = |package: &Path| {
        bregctl(&[
            "--format",
            "json",
            "field-encryption",
            "preflight",
            "--runtime-config",
            path(&fixture.runtime_config),
            "--package",
            path(package),
        ])
    };

    // The counts describe the state an apply starts from, so a package built
    // from any other predecessor is refused before its plan is read.
    let unbound = publish_unchanged_successor(
        &fixture,
        "unbound-successor",
        "sha256:4444444444444444444444444444444444444444444444444444444444444444",
    );
    let output = preflight(&unbound);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    let report = json_stdout(&output);
    assert_eq!(
        report["diagnostics"][0]["code"],
        "field_encryption.preflight.package.refused"
    );
    assert_tool_diagnostic(
        &report["diagnostics"][0],
        "verified_package",
        "verify_package_binding",
    );

    // The active package is never its own successor.
    let output = preflight(&fixture.package);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(
        json_stdout(&output)["diagnostics"][0]["code"],
        "field_encryption.preflight.package.refused"
    );

    // The same package built from the active package passes the binding and
    // stops only because it plans no backfill.
    let bound = publish_unchanged_successor(&fixture, "bound-successor", &fixture.package_digest);
    let output = preflight(&bound);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(
        json_stdout(&output)["diagnostics"][0]["code"],
        "field_encryption.preflight.plan.no_backfill"
    );
}

/// Publishes the fixture's registry again as a successor that names
/// `from_package_digest` as its predecessor and changes nothing else.
fn publish_unchanged_successor(
    fixture: &RuntimePackageFixture,
    name: &str,
    from_package_digest: &str,
) -> PathBuf {
    let module_bytes = package_module_bytes();
    let module = parse_module_json(&module_bytes).expect("package module parses");
    let project_bytes = package_project_bytes(&module_digest(&module));
    let request = |from_package_digest: Option<String>, migration_plan| PackageBuildRequest {
        from_package_digest,
        compiler_source_revision: PACKAGE_SOURCE_REVISION.to_owned(),
        schema_fingerprint:
            "sha256:2222222222222222222222222222222222222222222222222222222222222222".to_owned(),
        project: PackageSourceFile {
            path: "source/registry.yaml".to_owned(),
            bytes: project_bytes.clone(),
        },
        modules: vec![PackageModuleSource {
            id: "core".to_owned(),
            path: "source/modules/core/module.yaml".to_owned(),
            bytes: module_bytes.clone(),
            assets: Vec::new(),
        }],
        fixture_journeys: PackageSourceFile {
            path: "tests/journeys.yaml".to_owned(),
            bytes: PACKAGE_FIXTURE_JOURNEYS.to_vec(),
        },
        migration_plan,
    };
    let prior_registry =
        prepare_package(request(None, PackageMigrationPlanInput::InitialCompiledDdl))
            .expect("prior package prepares")
            .registry()
            .clone();
    let package = fixture.directory.path().join(name);
    prepare_package(request(
        Some(from_package_digest.to_owned()),
        PackageMigrationPlanInput::Successor {
            prior_registry: Box::new(prior_registry),
        },
    ))
    .expect("successor package prepares")
    .publish_to_directory(&package)
    .expect("successor package publishes");
    package
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
    let first = bregctl(&arguments);
    let second = bregctl(&arguments);

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
            "packageDigest": fixture.package_digest,
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
        "oidc-is-not-opened.invalid",
        VERIFY_RUNTIME_DATABASE_SECRET_CANARY,
        VERIFY_MIGRATION_DATABASE_SECRET_CANARY,
    ] {
        assert!(!rendered.contains(forbidden));
    }

    let human = bregctl(&["verify", "--runtime-config", path(&fixture.runtime_config)]);
    assert!(human.status.success(), "{human:?}");
    assert!(human.stderr.is_empty());
    let human = String::from_utf8(human.stdout).expect("verify human report is UTF-8");
    assert!(human.starts_with(
        "Verified the package against the runtime it is bound to.\n  assurance            runtime_bound\n"
    ));
    assert!(human.contains(&format!(
        "package digest       {}\n",
        fixture.package_digest
    )));
    assert!(human.contains("registry id          verify-registry\n"));
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
    let first = bregctl(&arguments);
    let second = bregctl(&arguments);

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
            "packageDigest": fixture.package_digest,
            "plan": {
                "planKind": "initial",
                "hasPredecessor": false,
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
        "CREATE TABLE",
        "signature",
    ] {
        assert!(!rendered.contains(forbidden));
    }

    let human = bregctl(&[
        "migration",
        "explain",
        "--runtime-config",
        path(&fixture.runtime_config),
    ]);
    assert!(human.status.success(), "{human:?}");
    assert!(human.stderr.is_empty());
    let human = String::from_utf8(human.stdout).expect("migration report is UTF-8");
    assert!(human.starts_with(
        "Explained the migration plan. 0 changes, 0 reviewed migrations.\n  assurance                            runtime_bound\n"
    ));
    assert!(human.contains("plan kind                            initial\n"));
    assert!(human.contains("change count                         0\n"));
    assert!(human.contains("reviewed migration count             0\n"));
    assert!(!human.contains(path(&fixture.runtime_config)));
}

#[test]
fn retired_package_flags_are_refused_as_unknown_arguments() {
    for (command, flag, value) in [
        ("package", "--database-id", "db-1"),
        ("test", "--database-id", "db-1"),
        ("package", "--baseline-runtime-config", "/runtime.yaml"),
        ("test", "--baseline-runtime-config", "/runtime.yaml"),
        ("package", "--signature-threshold", "1"),
        ("package", "--signature-key-id", "key-1"),
        ("package", "--signatures", "/signatures.json"),
    ] {
        for arguments in [
            vec![command, PACKAGE_VALUE_CANARY, flag, value],
            vec![command, PACKAGE_VALUE_CANARY, flag],
        ] {
            let output = bregctl(&arguments);
            assert_eq!(output.status.code(), Some(2), "{arguments:?}: {output:?}");
            let stderr = String::from_utf8(output.stderr).expect("usage error is UTF-8");
            assert!(
                stderr.contains(&format!("unexpected argument {flag}")),
                "{arguments:?}: {stderr}"
            );
            assert!(!stderr.contains("is removed"), "{arguments:?}: {stderr}");
        }
    }
    let output = bregctl(&[
        "package",
        PACKAGE_VALUE_CANARY,
        "--reviewed-migrations",
        "/review",
        "--test-receipt",
        "/receipt.json",
        "--output",
        "/build",
    ]);
    assert_eq!(output.status.code(), Some(2), "{output:?}");
    let stderr = String::from_utf8(output.stderr).expect("usage error is UTF-8");
    assert!(stderr.contains("--baseline-package"), "{stderr}");
}

#[test]
fn lifecycle_parser_surfaces_are_exact_and_value_free() {
    let help = bregctl(&["--help"]);
    assert!(help.status.success());
    let rendered = String::from_utf8(help.stdout).expect("top-level help is UTF-8");
    for available in ["package", "apply", "verify", "migration", "data", "webhook"] {
        assert!(rendered
            .lines()
            .any(|line| line.trim_start().starts_with(available)));
    }

    for arguments in [
        vec!["verify", "--help"],
        vec!["migration", "explain", "--help"],
        vec!["migration", "reconcile", "--help"],
        vec!["data", "validate", "--help"],
        vec!["data", "import", "--help"],
        vec!["data", "export", "--help"],
    ] {
        let output = bregctl(&arguments);
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
    let migration_help = bregctl(&["migration", "--help"]);
    let migration_help = String::from_utf8(migration_help.stdout).expect("migration help is UTF-8");
    for available in ["explain", "reconcile"] {
        assert!(migration_help
            .lines()
            .any(|line| line.trim_start().starts_with(available)));
    }
    let reconcile_help = bregctl(&["migration", "reconcile", "--help"]);
    let reconcile_help =
        String::from_utf8(reconcile_help.stdout).expect("migration reconcile help is UTF-8");
    for required in [
        "--runtime-config <ABSOLUTE_FILE>",
        "--package <ABSOLUTE_DIRECTORY>",
        "--operator-reference <REFERENCE>",
        "--execute",
    ] {
        assert!(reconcile_help.contains(required));
    }
    let package_help = bregctl(&["package", "--help"]);
    let package_help = String::from_utf8(package_help.stdout).expect("package help is UTF-8");
    for required in [
        "--baseline-package <ABSOLUTE_DIRECTORY>",
        "--schema-fingerprint <SHA256>",
        "--test-receipt <ABSOLUTE_FILE>",
        "--output <DIRECTORY>",
        "The package is the promotable unit `bregctl apply` activates",
        "`caseworkctl package` is a different verb",
    ] {
        assert!(package_help.contains(required), "{package_help}");
    }
    for retired in [
        "--database-id",
        "--baseline-runtime-config",
        "--signature-threshold",
        "--signature-key-id",
        "--signatures",
    ] {
        assert!(!package_help.contains(retired), "{package_help}");
    }
    let apply_help = bregctl(&["apply", "--help"]);
    let apply_help = String::from_utf8(apply_help.stdout).expect("apply help is UTF-8");
    for required in [
        "--runtime-config <ABSOLUTE_FILE>",
        "--package <ABSOLUTE_DIRECTORY>",
        "--initial",
        "--backup <BINDING_PATH=BINDING_FILE>",
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
            "reconcile",
            "--runtime-config",
            PACKAGE_VALUE_CANARY,
        ],
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
        let output = bregctl(&arguments);
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

    let wrong_pin = fixture.variant(
        PACKAGE_VALUE_CANARY,
        &format!("  root: {}", path(&fixture.package)),
        &format!(
            "  root: {}\n  expectedDigest: sha256:{}",
            path(&fixture.package),
            "0".repeat(64)
        ),
    );
    for (prefix, command) in [
        ("verify", vec!["verify"]),
        ("migration.explain", vec!["migration", "explain"]),
    ] {
        let mut arguments = vec!["--format", "json"];
        arguments.extend(command);
        arguments.extend(["--runtime-config", path(&wrong_pin)]);
        assert_inspection_refusal(
            &arguments,
            &format!("{prefix}.package.integrity_refused"),
            "verified_package",
            "verify_package_integrity",
            &[
                PACKAGE_VALUE_CANARY,
                path(&wrong_pin),
                path(&fixture.package),
            ],
        );
    }
}

#[test]
fn apply_names_both_digests_when_the_active_package_misses_its_pin() {
    let fixture = RuntimePackageFixture::production("127.0.0.1:1".parse().unwrap());
    let pinned = format!("sha256:{}", "0".repeat(64));
    let wrong_pin = fixture.variant(
        "wrong-pin",
        &format!("  root: {}", path(&fixture.package)),
        &format!(
            "  root: {}\n  expectedDigest: {pinned}",
            path(&fixture.package)
        ),
    );
    let successor = RuntimePackageFixture::production_with_module(
        "127.0.0.1:1".parse().unwrap(),
        String::from_utf8(package_module_bytes())
            .unwrap()
            .replace(r#""maxLength":16"#, r#""maxLength":32"#)
            .into_bytes(),
    );

    let output = bregctl(&[
        "--format",
        "json",
        "apply",
        "--runtime-config",
        path(&wrong_pin),
        "--package",
        path(&successor.package),
    ]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stderr.is_empty());
    let report = json_stdout(&output);
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(diagnostic["code"], "apply.package.refused");
    assert_eq!(diagnostic["path"], "package.root");
    assert_eq!(diagnostic["suggestedAction"], "verify_package_integrity");
    assert_eq!(
        diagnostic["message"],
        format!(
            "package.expectedDigest is {pinned} but the package at package.root is {}; deploy the pinned package or update package.expectedDigest",
            fixture.package_digest
        )
    );
    let rendered = String::from_utf8(output.stdout).expect("apply refusal is UTF-8");
    for forbidden in [
        path(&wrong_pin),
        path(&fixture.package),
        path(&successor.package),
        VERIFY_RUNTIME_DATABASE_SECRET_CANARY,
        VERIFY_MIGRATION_DATABASE_SECRET_CANARY,
    ] {
        assert!(!rendered.contains(forbidden));
    }
}

/// Run one operator command against a runtime file whose
/// `package.expectedDigest` pins another package than the one at
/// `package.root`, and require the refusal to name both digests under the
/// command's package code before any database is reached.
fn assert_operator_command_names_both_digests_of_a_package_pin_mismatch(
    command: &[&str],
    arguments: &[&str],
    code: &str,
) {
    let fixture = RuntimePackageFixture::production("127.0.0.1:1".parse().unwrap());
    let pinned = format!("sha256:{}", "0".repeat(64));
    let wrong_pin = fixture.variant(
        "wrong-pin",
        &format!("  root: {}", path(&fixture.package)),
        &format!(
            "  root: {}\n  expectedDigest: {pinned}",
            path(&fixture.package)
        ),
    );
    let mut invocation = vec!["--format", "json"];
    invocation.extend_from_slice(command);
    invocation.extend_from_slice(&["--runtime-config", path(&wrong_pin)]);
    invocation.extend_from_slice(arguments);

    let output = bregctl(&invocation);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stderr.is_empty());
    let report = json_stdout(&output);
    let diagnostic = &report["diagnostics"][0];
    assert_eq!(diagnostic["code"], code, "{report}");
    assert_eq!(diagnostic["path"], "package");
    assert_tool_diagnostic(diagnostic, "verified_package", "verify_package_integrity");
    assert_eq!(
        diagnostic["message"],
        format!(
            "package.expectedDigest is {pinned} but the package at package.root is {}; deploy the pinned package or update package.expectedDigest",
            fixture.package_digest
        )
    );
    let rendered = String::from_utf8(output.stdout).expect("operator refusal is UTF-8");
    for forbidden in [
        path(&wrong_pin),
        path(&fixture.package),
        VERIFY_RUNTIME_DATABASE_SECRET_CANARY,
        VERIFY_MIGRATION_DATABASE_SECRET_CANARY,
    ] {
        assert!(!rendered.contains(forbidden));
    }
}

#[test]
fn webhook_operations_name_both_digests_when_the_active_package_misses_its_pin() {
    assert_operator_command_names_both_digests_of_a_package_pin_mismatch(
        &["webhook", "list"],
        &[],
        "webhook.package.refused",
    );
}

#[test]
fn request_retention_names_both_digests_when_the_active_package_misses_its_pin() {
    assert_operator_command_names_both_digests_of_a_package_pin_mismatch(
        &["request-retention", "list"],
        &[],
        "request_retention.package.refused",
    );
}

#[test]
fn import_authority_names_both_digests_when_the_active_package_misses_its_pin() {
    assert_operator_command_names_both_digests_of_a_package_pin_mismatch(
        &["import-authority", "list"],
        &[],
        "import_authority.package.refused",
    );
}

#[test]
fn evidence_retention_names_both_digests_when_the_active_package_misses_its_pin() {
    assert_operator_command_names_both_digests_of_a_package_pin_mismatch(
        &["evidence-retention", "erase-expired"],
        &["--before", "2020-01-01T00:00:00Z"],
        "evidence_retention.package.refused",
    );
}

#[test]
fn idempotency_retention_names_both_digests_when_the_active_package_misses_its_pin() {
    assert_operator_command_names_both_digests_of_a_package_pin_mismatch(
        &["idempotency-retention", "erase-expired"],
        &["--before", "2020-01-01T00:00:00Z"],
        "idempotency_retention.package.refused",
    );
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

#[test]
fn a_directory_without_the_shared_envelope_is_refused_as_not_a_package() {
    let fixture = RuntimePackageFixture::production("127.0.0.1:1".parse().unwrap());
    strip_shared_package_envelope(&fixture.package);

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
            &[path(&fixture.runtime_config), path(&fixture.package)],
        );
        let report = json_stdout(&bregctl(&arguments));
        let message = report["diagnostics"][0]["message"]
            .as_str()
            .expect("refusal message is a string");
        assert!(message.contains("SHA256SUMS"), "{message}");
        assert!(message.contains("bregctl package"), "{message}");
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
    const SOURCE_VALUE_CANARY: &str = "bregctl-source-value-canary";

    let project = TestProject::asset_fixture();
    let mut source = String::from_utf8(asset_fixture().to_vec()).expect("fixture is UTF-8");
    source.push_str(&format!("\nunexpectedSetting: {SOURCE_VALUE_CANARY}\n"));
    fs::write(project.path().join("registry.yaml"), source).expect("unknown source is written");

    let output = bregctl(&[
        "--format",
        "json",
        "check",
        project.path().to_str().expect("path is UTF-8"),
    ]);

    assert_eq!(output.status.code(), Some(1));
    assert!(output.stderr.is_empty());
    assert!(!String::from_utf8_lossy(&output.stdout).contains(SOURCE_VALUE_CANARY));
    let report = json_stdout(&output);
    assert_eq!(report["diagnostics"][0]["code"], "config.unknown-key");
    assert_eq!(report["diagnostics"][0]["path"], "/unexpectedSetting");
    assert!(report["diagnostics"][0]["source"]["line"]
        .as_u64()
        .is_some());
    assert_check_diagnostic(&report["diagnostics"][0], Some("RegistryProject"));
}

#[test]
fn json_usage_errors_are_machine_readable_and_value_free() {
    const ARGUMENT_CANARY: &str = "bregctl-argument-canary";

    let output = bregctl(&["--format", "json", "check", ARGUMENT_CANARY, "--unknown"]);

    assert_eq!(output.status.code(), Some(2));
    assert!(output.stderr.is_empty());
    assert!(!String::from_utf8_lossy(&output.stdout).contains(ARGUMENT_CANARY));
    let report = json_stdout(&output);
    assert_eq!(report["command"], "usage");
    assert_eq!(report["diagnostics"][0]["code"], "usage.invalid");
    let message = report["diagnostics"][0]["message"]
        .as_str()
        .expect("usage message is a string");
    assert!(message.contains("--unknown"), "{message}");
    assert!(!message.contains('\u{1b}'), "{message}");
    assert_tool_diagnostic(
        &report["diagnostics"][0],
        "command_arguments",
        "correct_command_usage",
    );
}

#[test]
fn usage_errors_never_repeat_a_rejected_operator_reference() {
    const REFERENCE_CANARY: &str = "bregctl-operator-reference-canary";
    let attached = format!("--operator-reference={REFERENCE_CANARY}");
    let option_shaped = format!("--{REFERENCE_CANARY}");

    for arguments in [
        // A command that takes no operator reference refuses the attached value.
        vec!["check", "/project", attached.as_str()],
        // A value shaped like a long option is refused as an unknown argument.
        vec![
            "apply",
            "--package",
            "/package",
            "--operator-reference",
            option_shaped.as_str(),
        ],
        // An unquoted reference whose second word is shaped like a long option.
        vec![
            "apply",
            "--package",
            "/package",
            "--operator-reference",
            "change",
            option_shaped.as_str(),
        ],
        // An unquoted reference of two words leaves the second one unexpected.
        vec![
            "apply",
            "--package",
            "/package",
            "--operator-reference",
            "change",
            REFERENCE_CANARY,
        ],
    ] {
        for machine in [false, true] {
            let mut invocation = Vec::new();
            if machine {
                invocation.extend(["--format", "json"]);
            }
            invocation.extend(arguments.iter().copied());
            let output = bregctl(&invocation);

            assert_eq!(output.status.code(), Some(2), "{invocation:?}: {output:?}");
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            assert!(
                !stdout.contains(REFERENCE_CANARY) && !stderr.contains(REFERENCE_CANARY),
                "{invocation:?} repeated the operator reference: {stdout}{stderr}"
            );
            let rendered = if machine {
                assert!(output.stderr.is_empty(), "{stderr}");
                let report = json_stdout(&output);
                assert_eq!(report["diagnostics"][0]["code"], "usage.invalid");
                report["diagnostics"][0]["message"]
                    .as_str()
                    .expect("usage message is a string")
                    .to_owned()
            } else {
                assert!(output.stdout.is_empty(), "{stdout}");
                stderr.into_owned()
            };
            assert!(rendered.contains("unexpected argument"), "{rendered}");
        }
    }
}

#[test]
fn human_usage_errors_name_the_offending_argument() {
    let unknown_flag = bregctl(&["check", "--unknwon"]);

    assert_eq!(unknown_flag.status.code(), Some(2));
    assert!(unknown_flag.stdout.is_empty());
    let rendered = String::from_utf8_lossy(&unknown_flag.stderr).into_owned();
    assert!(rendered.contains("--unknwon"), "{rendered}");

    let missing_argument = bregctl(&["check"]);

    assert_eq!(missing_argument.status.code(), Some(2));
    assert!(missing_argument.stdout.is_empty());
    let rendered = String::from_utf8_lossy(&missing_argument.stderr).into_owned();
    assert!(
        rendered.contains("<PROJECT|--package <DIRECTORY>|--file <FILE>>"),
        "{rendered}"
    );
}

#[test]
fn data_validate_uses_a_closed_package_plan_and_value_free_usage() {
    const DATA_CANARY: &str = "bregctl-data-value-canary";

    let (directory, package) = data_package_fixture();
    let input = directory.path().join("input.jsonl");
    let input_bytes = r#"{"operation":"create","data":{"code":"AA"}}"#.to_owned() + "\n";
    fs::write(&input, &input_bytes).expect("data input writes");

    let output = bregctl(&[
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
    // The digest an operator pins with `import-authority open --input-sha256`.
    assert_eq!(
        report["inputDigest"],
        hex(Sha256::digest(input_bytes.as_bytes()).as_slice())
    );

    let refused = bregctl(&[
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

#[test]
fn data_export_prints_the_reader_diagnostics_for_a_checkpoint_an_earlier_bregctl_wrote() {
    let (directory, package) = data_package_fixture();
    let token = directory.path().join("access-token");
    fs::write(&token, "data-token-canary\n").expect("token writes");
    let output_file = directory.path().join("records.jsonl");
    fs::write(&output_file, b"").expect("export output writes");
    let checkpoint = directory.path().join("records.checkpoint.json");
    fs::write(
        &checkpoint,
        br#"{"apiVersion":"registry.registrystack.org/v1alpha1","kind":"RegistryDataExportCheckpoint"}"#,
    )
    .expect("earlier checkpoint writes");
    let export = |format: &[&str]| {
        let mut arguments = format.to_vec();
        arguments.extend([
            "data",
            "export",
            "--package",
            path(&package),
            "--breg-url",
            "http://127.0.0.1:1",
            "--access-token-file",
            path(&token),
            "--entity",
            "record",
            "--profile",
            "operator",
            "--field",
            "code",
            "--output",
            path(&output_file),
            "--checkpoint",
            path(&checkpoint),
        ]);
        bregctl(&arguments)
    };

    let output = export(&["--format", "json"]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stderr.is_empty());
    let report = json_stdout(&output);
    assert_eq!(report["ok"], false);
    assert_eq!(report["command"], "data export");
    let diagnostics = report["diagnostics"].as_array().expect("diagnostics");
    let wrong_kind = diagnostics
        .iter()
        .find(|diagnostic| diagnostic["code"] == "config.wrong-kind")
        .expect("the earlier kind is refused");
    assert_eq!(wrong_kind["source"]["file"], path(&checkpoint));
    assert_eq!(wrong_kind["source"]["line"], 1);

    let output = export(&[]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert!(output.stdout.is_empty());
    let rendered = String::from_utf8(output.stderr).expect("refusal is UTF-8");
    assert!(
        rendered.starts_with("bregctl data export refused the data export checkpoint.\n"),
        "{rendered}"
    );
    assert!(rendered.contains("config.wrong-kind"), "{rendered}");
    assert!(!rendered.contains("data-token-canary"));
}

#[cfg(unix)]
#[test]
fn generation_refuses_a_broken_symlink_destination_without_publishing_output() {
    use std::os::unix::fs::symlink;

    let project = TestProject::asset_fixture();
    let destination = project.path().join("linked-output");
    symlink("not-present", &destination).expect("broken output symlink is created");
    let output = bregctl(&[
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
        r#"{{"apiVersion":"registry.registrystack.org/v1alpha1","kind":"RegistryProject","registry":{{"id":"verify-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://package.example.test"}},"package":{{"sourceRevision":"{PACKAGE_SOURCE_REVISION}"}},"manifestProjection":{{"accessProfile":"reader","classificationCeiling":"restricted","catalog":{{"baseUrl":"https://package.example.test","title":"Verify Registry Catalog","publisher":{{"id":"verify-registry-authority","name":"Verify Publisher"}}}},"publicService":{{"id":"verify-registry-service","title":"Verify Registry Catalog"}},"datasets":[{{"id":"verify-registry","title":"Verify Registry Dataset","owner":"Verify Publisher","status":"active"}}],"dataServices":[{{"id":"verify-registry-data-service","title":"Verify Registry Catalog","endpointUrl":"https://package.example.test","servesDatasets":["verify-registry"]}}]}},"modules":[{{"id":"core","version":"1","digest":"{module_digest}"}}]}}"#
    )
    .into_bytes()
}

fn modular_project_without_locks() -> &'static [u8] {
    br#"apiVersion: registry.registrystack.org/v1alpha1
kind: RegistryProject
registry:
  id: modular-lock-fixture
  version: "1"
  defaultLanguage: en
  canonicalBaseIri: https://modular-lock-fixture.example.test
"#
}

fn modular_project_extra_module() -> &'static [u8] {
    br#"id: extra
version: "1"
entities:
  - id: extra-record
    primaryDataset: test-dataset
    route: extra-records
    mutationMode: create_only
    fields:
      - id: code
        type: string
        maxLength: 16
        classification: internal
    accessProfiles:
      - rowBoundaries: []
        id: reader
        principalClaim: principal
        operations: [get, list]
        readableFields: [code]
"#
}

fn modular_project_module() -> &'static [u8] {
    br#"id: core
version: "1"
entities:
  - id: record
    primaryDataset: test-dataset
    route: records
    mutationMode: create_only
    fields:
      - id: code
        type: string
        maxLength: 16
        classification: internal
    accessProfiles:
      - rowBoundaries: []
        id: reader
        principalClaim: principal
        operations: [get, list]
        readableFields: [code]
"#
}

fn package_module_bytes() -> Vec<u8> {
    br#"{"id":"core","version":"1","entities":[{"id":"record","primaryDataset":"verify-registry","route":"records","mutationMode":"create_only","fields":[{"id":"code","type":"string","maxLength":16,"classification":"internal"}],"accessProfiles":[{"id":"reader","principalClaim":"principal","operations":["get","list"],"readableFields":["code"], "rowBoundaries": []}]}]}"#
        .to_vec()
}

fn encrypted_package_module_bytes() -> Vec<u8> {
    br#"{"id":"core","version":"1","entities":[{"id":"record","primaryDataset":"verify-registry","route":"records","mutationMode":"create_only","fields":[{"id":"code","type":"string","maxLength":16,"classification":"restricted","encrypted":true}],"accessProfiles":[{"id":"reader","principalClaim":"principal","operations":["get","list"],"readableFields":["code"], "rowBoundaries": []}]}]}"#
        .to_vec()
}

fn data_package_fixture() -> (TestProject, PathBuf) {
    let module_bytes = br#"{"id":"core","version":"1","entities":[{"id":"record","primaryDataset":"data-registry","route":"records","mutationMode":"create_only","batch":{"maximumItems":2,"maximumBytes":400},"fields":[{"id":"code","type":"string","minLength":2,"maxLength":16,"required":true,"classification":"internal"}],"accessProfiles":[{"id":"operator","principalClaim":"principal","operations":["create","batch","list"],"readableFields":["code"],"writableFields":["code"],"allowDataExport":true, "rowBoundaries": []}]}]}"#.to_vec();
    let module = parse_module_json(&module_bytes).expect("data module parses");
    let module_digest = module_digest(&module);
    let project = TestProject::from_registry_source(
        format!(
            r#"{{"apiVersion":"registry.registrystack.org/v1alpha1","kind":"RegistryProject","registry":{{"id":"data-registry","version":"1","defaultLanguage":"en","canonicalBaseIri":"https://data.example.test"}},"package":{{"sourceRevision":"data-source"}},"manifestProjection":{{"accessProfile":"operator","classificationCeiling":"restricted","catalog":{{"baseUrl":"https://data.example.test","title":"Data Registry Catalog","publisher":{{"id":"data-registry-authority","name":"Data Publisher"}}}},"publicService":{{"id":"data-registry-service","title":"Data Registry Catalog"}},"datasets":[{{"id":"data-registry","title":"Data Registry Dataset","owner":"Data Publisher","status":"active"}}],"dataServices":[{{"id":"data-registry-data-service","title":"Data Registry Catalog","endpointUrl":"https://data.example.test","servesDatasets":["data-registry"]}}]}},"modules":[{{"id":"core","version":"1","digest":"{module_digest}"}}]}}"#
        )
        .as_bytes(),
    );
    let package = project.path().join("data-package");
    let prepared = prepare_package(PackageBuildRequest {
        from_package_digest: None,
        compiler_source_revision: "data-source".to_owned(),
        schema_fingerprint:
            "sha256:3333333333333333333333333333333333333333333333333333333333333333".to_owned(),
        project: PackageSourceFile {
            path: "source/registry.yaml".to_owned(),
            bytes: fs::read(project.path().join("registry.yaml")).expect("data project reads"),
        },
        modules: vec![PackageModuleSource {
            id: "core".to_owned(),
            path: "source/modules/core/module.yaml".to_owned(),
            bytes: module_bytes,
            assets: Vec::new(),
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
        .publish_to_directory(&package)
        .expect("data package publishes");
    (project, package)
}

fn write_runtime_config(parent: &Path, package: &Path, bind: SocketAddr) -> PathBuf {
    let secret_root = parent.join("secrets");
    fs::create_dir_all(&secret_root).expect("secret root creates");
    let path = parent.join("runtime.yaml");
    let audit_path = secret_root
        .with_file_name("audit")
        .join("audit.jsonl")
        .display()
        .to_string();
    fs::write(
        &path,
        format!(
            r#"apiVersion: registry.registrystack.org/breg-runtime/v1alpha1
kind: BRegRuntimeConfig
listener:
  bind: {bind}
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
  runtimeUrlRef: secret:env/{VERIFY_RUNTIME_DATABASE_SECRET_CANARY}
  migrationUrlRef: secret:env/{VERIFY_MIGRATION_DATABASE_SECRET_CANARY}
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
authentication:
  oidc:
    issuer: https://oidc-is-not-opened.invalid
    audience: urn:breg:verify
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
audit:
  hashKeyRef: secret:file/{PACKAGE_VALUE_CANARY}
  path: {audit_path}
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
        ),
    )
    .expect("runtime configuration writes");
    path
}

fn test_runtime_config(project: &TestProject) -> PathBuf {
    let package_root = project.path().join("runtime-package-root");
    fs::create_dir(&package_root).expect("runtime package root creates");
    write_runtime_config(
        project.path(),
        &package_root,
        "127.0.0.1:1".parse().expect("loopback address parses"),
    )
}

fn credential_source(credential: &str) -> String {
    format!(
        r#"apiVersion: id.registrystack.org/formats/breg/schema-test-credentials/v1
kind: BRegSchemaTestCredentials
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

/// A refused credentials file is reported in the reader's diagnostic shape,
/// naming the file as given and never a value it holds (CFG-SEC-3).
fn assert_credentials_document_refusal(
    output: Output,
    credentials: &Path,
    expected_code: &str,
    expected_pointer: &str,
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
    assert_eq!(report["ok"], false);
    assert_eq!(report["command"], "test");
    let diagnostics = report["diagnostics"]
        .as_array()
        .expect("refusal diagnostics are a list");
    assert!(
        diagnostics.iter().any(|diagnostic| {
            diagnostic["code"] == expected_code && diagnostic["path"] == expected_pointer
        }),
        "{rendered}"
    );
    for diagnostic in diagnostics {
        assert_eq!(diagnostic["artifact"], "BRegSchemaTestCredentials");
        assert_eq!(diagnostic["source"]["file"], path(credentials));
        assert!(diagnostic["source"]["line"].is_u64(), "{rendered}");
        assert!(
            diagnostic["suggestedAction"]
                .as_str()
                .is_some_and(|action| !action.is_empty()),
            "{rendered}"
        );
    }
}

fn assert_inspection_refusal(
    arguments: &[&str],
    expected_code: &str,
    artifact: &str,
    action: &str,
    forbidden: &[&str],
) {
    let output = bregctl(arguments);
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

fn assert_filter_example(operation: &Value, api_name: &str, example: &str) {
    let field = operation["filterable"]
        .as_array()
        .expect("filterable is an array")
        .iter()
        .find(|field| field["apiName"] == api_name)
        .unwrap_or_else(|| panic!("{api_name} filter field is present"));
    assert!(field["examples"]
        .as_array()
        .expect("examples is an array")
        .iter()
        .any(|candidate| candidate == example));
}

fn path(path: &Path) -> &str {
    path.to_str().expect("test path is UTF-8")
}

fn strip_shared_package_envelope(root: &Path) {
    fs::remove_file(root.join("SHA256SUMS")).expect("shared package checksum file removes");
    let revision = root.join("REVISION");
    if revision.exists() {
        fs::remove_file(revision).expect("shared package revision file removes");
    }
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
