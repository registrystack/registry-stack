// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

#[path = "../src/project_authoring/knowledge.rs"]
mod knowledge;
#[path = "../src/project_authoring/required_product_action.rs"]
mod required_product_action;
pub use required_product_action::RequiredProductAction;
#[path = "../src/project_authoring/report_contract.rs"]
mod report_contract;

pub use report_contract::Sha256Digest;

#[path = "../src/project_authoring/fixture_coverage.rs"]
mod fixture_coverage;

use std::{
    collections::BTreeSet,
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::OnceLock,
};

use registryctl::{
    FixtureCapability, FixtureCoverageChangeKind, FixtureCoverageComparisonInput,
    FixtureCoverageDimensions, FixtureCoverageEvidenceKind, FixtureCoverageGapReason,
    FixtureCoverageNotApplicableReason, FixtureCoverageNotEvaluatedReason,
    FixtureCoverageRequirementState, FixtureCoverageTarget, FixtureCoverageTargetComparisonInput,
    FixtureCoverageTargetSetState, FixturePassState, FixtureRequirementCoverage, FixtureSafeCode,
    GeneratedRecipeApplicability, GeneratorRecipeId, ProjectFixtureCoverageReportV1,
    RequiredFixtureCoverageRequirement, Sha256Digest as RegistrySha256Digest,
};
use serde_json::{json, Value};

const SCHEMA: &str =
    include_str!("../schemas/project-reports/registry.project.fixture_coverage.v1.schema.json");
const REPRESENTATIVE_FIXTURE: &str =
    include_str!("fixtures/project-reports/registry.project.fixture_coverage.v1.json");
const NO_TARGET_FIXTURE: &str =
    include_str!("fixtures/project-reports/registry.project.fixture_coverage.no-target.v1.json");

fn parse(input: &str) -> Value {
    serde_json::from_str(input).expect("JSON parses")
}

fn validator() -> jsonschema::JSONSchema {
    jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&parse(SCHEMA))
        .expect("fixture coverage schema compiles as Draft 2020-12")
}

fn assert_schema_valid(document: &Value) {
    if let Err(errors) = validator().validate(document) {
        panic!(
            "document should validate: {:?}",
            errors.map(|error| error.to_string()).collect::<Vec<_>>()
        );
    }
}

fn assert_schema_invalid(document: &Value) {
    assert!(
        validator().validate(document).is_err(),
        "schema should reject the document"
    );
}

fn assert_typed_invalid(document: Value) {
    assert!(
        serde_json::from_value::<ProjectFixtureCoverageReportV1>(document).is_err(),
        "strict DTO should reject the document"
    );
}

fn replace_requirement(document: &mut Value, requirement: &str, replacement: Value) {
    let requirements = document["targets"][0]["requirements"]
        .as_array_mut()
        .expect("requirements are an array");
    let coverage = requirements
        .iter_mut()
        .find(|coverage| coverage["requirement"] == requirement)
        .expect("requirement exists");
    let old_state = coverage["state"]
        .as_str()
        .expect("coverage state is a string")
        .to_owned();
    let new_state = replacement["state"]
        .as_str()
        .expect("replacement state is a string")
        .to_owned();
    *coverage = replacement;
    if old_state != new_state {
        let counts = document["summary"]["requirements"]
            .as_object_mut()
            .expect("summary counts are an object");
        let old = counts
            .get(&old_state)
            .and_then(Value::as_u64)
            .expect("old count is numeric");
        let new = counts
            .get(&new_state)
            .and_then(Value::as_u64)
            .expect("new count is numeric");
        counts.insert(old_state, json!(old - 1));
        counts.insert(new_state, json!(new + 1));
    }
}

fn requirement(document: &Value, requirement: &str) -> Value {
    document["targets"][0]["requirements"]
        .as_array()
        .expect("requirements are an array")
        .iter()
        .find(|coverage| coverage["requirement"] == requirement)
        .expect("requirement exists")
        .clone()
}

fn project_root(name: &str) -> std::path::PathBuf {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    if name == "bounded-http-starter" {
        manifest.join("assets/project-starters/bounded-http")
    } else {
        manifest.join("tests/fixtures/project-authoring").join(name)
    }
}

fn copy_project_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("destination directory is created");
    for entry in fs::read_dir(source).expect("source project directory is readable") {
        let entry = entry.expect("source project entry is readable");
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if entry.file_type().expect("entry type is readable").is_dir() {
            copy_project_tree(&source_path, &destination_path);
        } else {
            fs::copy(&source_path, &destination_path).expect("project file is copied");
        }
    }
}

fn replace_authored_text(project: &Path, relative_path: &str, old: &str, new: &str) {
    let path = project.join(relative_path);
    let authored = fs::read_to_string(&path).expect("authored project file is readable");
    assert!(
        authored.contains(old),
        "sentinel source text is present in {}",
        path.display()
    );
    fs::write(path, authored.replace(old, new)).expect("sentinel is planted");
}

fn registryctl_executable() -> &'static Path {
    static STABLE_EXECUTABLE: OnceLock<(tempfile::TempDir, PathBuf)> = OnceLock::new();
    &STABLE_EXECUTABLE
        .get_or_init(|| {
            let directory = tempfile::tempdir().expect("stable executable directory is created");
            let executable = directory.path().join("registryctl");
            fs::copy(env!("CARGO_BIN_EXE_registryctl"), &executable)
                .expect("registryctl executable is copied before fixture execution");
            (directory, executable)
        })
        .1
}

fn generated_coverage_project(name: &str) -> registryctl::ProjectFixtureCoverageReportV1 {
    let context = registryctl::ProjectExecutionContext::new(registryctl_executable())
        .expect("Cargo provides registryctl");
    registryctl::test_registry_project_with_context(
        &registryctl::ProjectTestOptions {
            project_directory: project_root(name),
            environment: None,
        },
        &context,
    )
    .expect("coverage fixtures execute")
    .fixture_coverage
    .expect("full project test produces coverage")
}

fn executable_fixture_coverage(project: &Path) -> ProjectFixtureCoverageReportV1 {
    let output = Command::new(registryctl_executable())
        .args(["test", "--project-dir"])
        .arg(project)
        .args(["--format", "json"])
        .output()
        .expect("registryctl test executes");
    assert!(
        output.status.success(),
        "registryctl test failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: registryctl::ProjectCommandReportV1 =
        serde_json::from_slice(&output.stdout).expect("registryctl test emits JSON");
    report
        .fixture_coverage
        .expect("full project test emits fixture coverage")
}

fn only_target(report: &registryctl::ProjectFixtureCoverageReportV1) -> &FixtureCoverageTarget {
    assert_eq!(report.targets.len(), 1);
    &report.targets[0]
}

fn contains_key(value: &Value, forbidden: &str) -> bool {
    match value {
        Value::Array(values) => values.iter().any(|value| contains_key(value, forbidden)),
        Value::Object(object) => {
            object.contains_key(forbidden)
                || object.values().any(|value| contains_key(value, forbidden))
        }
        _ => false,
    }
}

fn empty_dimensions() -> FixtureCoverageDimensions {
    FixtureCoverageDimensions {
        input_ids: Vec::new(),
        output_ids: Vec::new(),
        status_mappings: Vec::new(),
        protocol_helpers: Vec::new(),
        limits: Vec::new(),
        script_branch_ids: Vec::new(),
    }
}

fn comparison_input_for(targets: &[FixtureCoverageTarget]) -> FixtureCoverageComparisonInput {
    FixtureCoverageComparisonInput {
        baseline_digest: RegistrySha256Digest::new(format!("sha256:{}", "1".repeat(64))).unwrap(),
        candidate_digest: RegistrySha256Digest::new(format!("sha256:{}", "2".repeat(64))).unwrap(),
        targets: targets
            .iter()
            .map(|target| FixtureCoverageTargetComparisonInput {
                integration: target.identity.integration.clone(),
                changed_input_ids: target
                    .declared
                    .input_ids
                    .first()
                    .cloned()
                    .into_iter()
                    .collect(),
                changed_output_ids: target
                    .declared
                    .output_ids
                    .first()
                    .cloned()
                    .into_iter()
                    .collect(),
                source_contract_changed: true,
            })
            .collect(),
    }
}

#[test]
fn canonical_representative_fixture_validates_and_roundtrips_exactly() {
    let document = parse(REPRESENTATIVE_FIXTURE);
    assert_schema_valid(&document);
    let decoded: ProjectFixtureCoverageReportV1 =
        serde_json::from_value(document.clone()).expect("canonical fixture decodes");
    assert_eq!(serde_json::to_value(&decoded).unwrap(), document);
    assert_eq!(decoded.targets.len(), 1);
    assert_eq!(
        decoded.summary.target_set_state,
        FixtureCoverageTargetSetState::TargetsPresent
    );
    assert_eq!(
        decoded.summary.requirements.total as usize,
        RequiredFixtureCoverageRequirement::ALL.len()
    );
    assert_eq!(
        decoded.targets[0].requirements.len(),
        RequiredFixtureCoverageRequirement::ALL.len()
    );
    assert!(!decoded.targets[0].fixture_inventory.is_empty());
    assert!(!decoded.targets[0].generated_cases.is_empty());
    assert!(decoded.targets[0]
        .requirements
        .iter()
        .skip(RequiredFixtureCoverageRequirement::ALL.len() - FixtureCoverageChangeKind::ALL.len(),)
        .all(|coverage| {
            matches!(
                coverage,
                FixtureRequirementCoverage::NotEvaluated {
                    reason: FixtureCoverageNotEvaluatedReason::ComparisonInputAbsent,
                    evidence,
                    ..
                } if evidence.is_empty()
            )
        }));
}

#[test]
fn canonical_representative_fixture_is_byte_reproducible_from_the_executable() {
    let generated = executable_fixture_coverage(&project_root("bounded-http-starter"));
    let canonical: ProjectFixtureCoverageReportV1 =
        serde_json::from_str(REPRESENTATIVE_FIXTURE).expect("canonical fixture decodes");
    assert_eq!(generated, canonical);
    assert_eq!(
        format!("{}\n", serde_json::to_string_pretty(&generated).unwrap()),
        REPRESENTATIVE_FIXTURE
    );
}

#[test]
#[ignore = "explicit maintainer regeneration; byte-exact reproduction runs by default"]
fn regenerate_canonical_representative_fixture_from_the_executable() {
    let generated = executable_fixture_coverage(&project_root("bounded-http-starter"));
    let bytes = format!("{}\n", serde_json::to_string_pretty(&generated).unwrap());
    fs::write(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/project-reports/registry.project.fixture_coverage.v1.json"),
        bytes,
    )
    .expect("canonical representative fixture writes");
}

#[test]
fn explicit_no_target_fixture_validates_and_roundtrips_exactly() {
    let document = parse(NO_TARGET_FIXTURE);
    assert_schema_valid(&document);
    let decoded: ProjectFixtureCoverageReportV1 =
        serde_json::from_value(document.clone()).expect("no-target fixture decodes");
    assert_eq!(serde_json::to_value(&decoded).unwrap(), document);
    assert!(decoded.targets.is_empty());
    assert_eq!(
        decoded.summary.target_set_state,
        FixtureCoverageTargetSetState::NoTargets
    );
    assert_eq!(decoded.summary.requirements.total, 0);
}

#[test]
fn generated_targets_have_exact_ordered_requirement_contracts() {
    for (project, capability) in [
        ("bounded-http-starter", FixtureCapability::DeclarativeHttp),
        ("dhis2-script", FixtureCapability::Script),
        ("snapshot-exact", FixtureCapability::Snapshot),
        ("opencrvs", FixtureCapability::Script),
        ("opencrvs-events-api", FixtureCapability::Script),
    ] {
        let report = generated_coverage_project(project);
        let document = serde_json::to_value(&report).unwrap();
        assert_schema_valid(&document);
        assert_eq!(
            report.summary.target_set_state,
            FixtureCoverageTargetSetState::TargetsPresent
        );
        let target = only_target(&report);
        assert_eq!(target.identity.capability, capability);
        assert_eq!(
            target.requirements.len(),
            RequiredFixtureCoverageRequirement::ALL.len()
        );
        assert_eq!(
            target
                .requirements
                .iter()
                .map(FixtureRequirementCoverage::requirement)
                .collect::<Vec<_>>(),
            RequiredFixtureCoverageRequirement::ALL
        );
        assert_eq!(
            target
                .requirements
                .iter()
                .map(FixtureRequirementCoverage::requirement)
                .collect::<BTreeSet<_>>()
                .len(),
            RequiredFixtureCoverageRequirement::ALL.len()
        );
        for requirement in target.requirements.iter().skip(
            RequiredFixtureCoverageRequirement::ALL.len() - FixtureCoverageChangeKind::ALL.len(),
        ) {
            assert!(matches!(
                requirement,
                FixtureRequirementCoverage::NotEvaluated {
                    reason: FixtureCoverageNotEvaluatedReason::ComparisonInputAbsent,
                    evidence,
                    ..
                } if evidence.is_empty()
            ));
        }
        assert_eq!(
            report.summary.requirements.total as usize,
            RequiredFixtureCoverageRequirement::ALL.len()
        );
    }
}

#[test]
fn generated_cases_remain_executable_and_isolated_under_their_target() {
    for project in [
        "bounded-http-starter",
        "dhis2-script",
        "snapshot-exact",
        "opencrvs",
        "opencrvs-events-api",
    ] {
        let report = generated_coverage_project(project);
        let target = only_target(&report);
        assert!(!target.fixture_inventory.is_empty());
        assert!(target
            .fixture_inventory
            .iter()
            .all(|fixture| fixture.pass_state == FixturePassState::Passed));
        assert_eq!(
            target.generated_cases.len(),
            target.fixture_inventory.len() * GeneratorRecipeId::ALL.len()
        );
        for case in &target.generated_cases {
            assert!(target
                .fixture_inventory
                .iter()
                .any(
                    |fixture| fixture.fixture_id == case.source_fixture.fixture_id
                        && fixture.fixture_digest == case.source_fixture.fixture_digest
                ));
            assert_eq!(
                case.evidence.kind,
                FixtureCoverageEvidenceKind::GeneratedCase
            );
            assert!(case
                .evidence
                .id
                .starts_with(&format!("target/{}/fixture/", target.identity.integration)));
        }
    }
}

#[test]
fn synthetic_opencrvs_events_api_covers_the_bounded_relay_source_contract() {
    let report = generated_coverage_project("opencrvs-events-api");
    let target = only_target(&report);
    assert_eq!(target.identity.integration, "birth-event-search");
    assert_eq!(target.identity.capability, FixtureCapability::Script);
    assert_eq!(
        target
            .fixture_inventory
            .iter()
            .map(|fixture| fixture.fixture_id.as_str())
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "birth-event-ambiguous",
            "birth-event-match",
            "birth-event-no-match",
            "birth-event-source-malformed",
            "birth-event-source-rejected",
            "birth-event-source-timeout",
            "birth-event-subject-mismatch",
            "oauth-token-expiry-rejected",
            "oauth-token-extra-member-rejected",
            "oauth-token-media-type-rejected",
            "oauth-token-redirect-rejected",
            "oauth-token-type-rejected",
        ])
    );
    assert!(target
        .fixture_inventory
        .iter()
        .all(|fixture| fixture.pass_state == FixturePassState::Passed));

    let matched = target
        .fixture_inventory
        .iter()
        .find(|fixture| fixture.fixture_id == "birth-event-match")
        .expect("passing exact-selector fixture is present");
    assert_eq!(matched.output_ids, ["event_type", "registered"]);

    for (recipe, safe_code) in [
        (
            GeneratorRecipeId::MalformedDecode,
            Some(FixtureSafeCode::SourceResponseMalformed),
        ),
        (
            GeneratorRecipeId::ByteCeiling,
            Some(FixtureSafeCode::SourceResponseTooLarge),
        ),
        (
            GeneratorRecipeId::Timeout,
            Some(FixtureSafeCode::SourceDeadlineExceeded),
        ),
        (GeneratorRecipeId::OutputMinimization, None),
    ] {
        let generated = target
            .generated_cases
            .iter()
            .find(|case| {
                case.source_fixture.fixture_id == "birth-event-match" && case.recipe.id == recipe
            })
            .unwrap_or_else(|| panic!("generated {recipe:?} case is present"));
        assert!(matches!(
            generated.applicability,
            GeneratedRecipeApplicability::Applicable {}
        ));
        assert_eq!(generated.actual_safe_code, safe_code);
        assert_eq!(generated.pass_state, FixturePassState::Passed);
    }
}

#[test]
fn no_targets_and_a_fixtureless_target_are_distinct_states() {
    let no_targets: ProjectFixtureCoverageReportV1 =
        serde_json::from_str(NO_TARGET_FIXTURE).unwrap();
    assert_eq!(no_targets.summary.target_count, 0);
    assert_eq!(no_targets.summary.fixtureless_target_count, 0);

    let mut target = generated_coverage_project("dhis2-script")
        .targets
        .into_iter()
        .next()
        .unwrap();
    target.fixture_inventory.clear();
    target.generated_cases.clear();
    target.exercised = empty_dimensions();
    target.comparison = None;
    target.fixture_set_state = registryctl::FixtureSetState::Fixtureless;
    target.refresh_requirements(FixtureCoverageNotEvaluatedReason::ComparisonInputAbsent);
    let report = ProjectFixtureCoverageReportV1::from_targets(
        "fixtureless-project".to_owned(),
        None,
        vec![target],
    )
    .expect("fixtureless target remains a valid explicit gap report");
    assert_eq!(report.summary.target_count, 1);
    assert_eq!(report.summary.fixture_bearing_target_count, 0);
    assert_eq!(report.summary.fixtureless_target_count, 1);
    assert_eq!(
        report.summary.target_set_state,
        FixtureCoverageTargetSetState::TargetsPresent
    );
    assert_eq!(
        report.targets[0].requirements.len(),
        RequiredFixtureCoverageRequirement::ALL.len()
    );
}

#[test]
fn declared_and_exercised_dimensions_do_not_relabel_semantics_as_coverage() {
    let script_report = generated_coverage_project("dhis2-script");
    let script = only_target(&script_report);
    assert_eq!(script.identity.capability, FixtureCapability::Script);
    assert!(script.declared.script_branch_ids.is_empty());
    assert!(script.exercised.script_branch_ids.is_empty());
    assert!(matches!(
        script
            .requirements
            .iter()
            .find(|coverage| coverage.requirement()
                == RequiredFixtureCoverageRequirement::ScriptBranches),
        Some(FixtureRequirementCoverage::Missing {
            reason: FixtureCoverageGapReason::ScriptBranchContractNotDeclared,
            ..
        })
    ));
    assert!(script.declared.limits.len() > script.exercised.limits.len());
}

#[test]
fn boundary_evidence_and_not_applicable_states_preserve_supported_truth() {
    let script_report = generated_coverage_project("dhis2-script");
    let script = only_target(&script_report);
    assert!(matches!(
        script
            .requirements
            .iter()
            .find(|coverage| coverage.requirement()
                == RequiredFixtureCoverageRequirement::TimeoutClassification),
        Some(FixtureRequirementCoverage::Covered { .. })
    ));
    assert!(matches!(
        script
            .requirements
            .iter()
            .find(|coverage| coverage.requirement()
                == RequiredFixtureCoverageRequirement::NumericDeadlineEnforcement),
        Some(FixtureRequirementCoverage::Missing {
            reason: FixtureCoverageGapReason::NumericBoundaryNotExercised,
            ..
        })
    ));
    assert!(matches!(
        script
            .requirements
            .iter()
            .find(|coverage| coverage.requirement()
                == RequiredFixtureCoverageRequirement::RequestBytes),
        Some(FixtureRequirementCoverage::Missing {
            reason: FixtureCoverageGapReason::NumericBoundaryNotExercised,
            ..
        })
    ));

    let snapshot_report = generated_coverage_project("snapshot-exact");
    let snapshot = only_target(&snapshot_report);
    for requirement in [
        RequiredFixtureCoverageRequirement::RequestRendering,
        RequiredFixtureCoverageRequirement::ResponseBytes,
        RequiredFixtureCoverageRequirement::TimeoutClassification,
        RequiredFixtureCoverageRequirement::OutputMinimization,
    ] {
        assert!(matches!(
            snapshot
                .requirements
                .iter()
                .find(|coverage| coverage.requirement() == requirement),
            Some(FixtureRequirementCoverage::NotApplicable {
                reason: FixtureCoverageNotApplicableReason::NoRemoteSourceCapability,
                ..
            })
        ));
    }
}

#[test]
fn multi_target_evidence_cannot_cross_integration_boundaries() {
    let mut targets = vec![
        generated_coverage_project("bounded-http-starter")
            .targets
            .into_iter()
            .next()
            .unwrap(),
        generated_coverage_project("dhis2-script")
            .targets
            .into_iter()
            .next()
            .unwrap(),
    ];
    targets.sort_by(|left, right| left.identity.integration.cmp(&right.identity.integration));
    let report =
        ProjectFixtureCoverageReportV1::from_targets("multi-target".to_owned(), None, targets)
            .expect("disjoint targets form one valid report");
    assert_eq!(report.targets.len(), 2);
    assert_eq!(
        report.summary.requirements.total as usize,
        RequiredFixtureCoverageRequirement::ALL.len() * 2
    );

    let mut document = serde_json::to_value(report).unwrap();
    let foreign_evidence = document["targets"][1]["fixture_inventory"][0]["evidence"].clone();
    let covered = document["targets"][0]["requirements"]
        .as_array()
        .unwrap()
        .iter()
        .position(|coverage| coverage["state"] == "covered")
        .unwrap();
    document["targets"][0]["requirements"][covered]["evidence"] = json!([foreign_evidence]);
    assert_typed_invalid(document);
}

#[test]
fn exact_requirement_order_uniqueness_and_derived_summary_fail_closed() {
    let report = generated_coverage_project("dhis2-script");
    let mut wrong_order = serde_json::to_value(&report).unwrap();
    wrong_order["targets"][0]["requirements"]
        .as_array_mut()
        .unwrap()
        .swap(0, 1);
    assert_schema_invalid(&wrong_order);
    assert_typed_invalid(wrong_order);

    let mut duplicate = serde_json::to_value(&report).unwrap();
    duplicate["targets"][0]["requirements"][1] = duplicate["targets"][0]["requirements"][0].clone();
    assert_schema_invalid(&duplicate);
    assert_typed_invalid(duplicate);

    let mut false_summary = serde_json::to_value(report).unwrap();
    false_summary["summary"]["requirements"]["covered"] = json!(
        false_summary["summary"]["requirements"]["covered"]
            .as_u64()
            .unwrap()
            + 1
    );
    assert_typed_invalid(false_summary);
}

#[test]
fn root_and_deep_nested_unknown_fields_are_rejected() {
    let report = generated_coverage_project("dhis2-script");
    let pointers = [
        "",
        "/targets/0",
        "/targets/0/identity",
        "/targets/0/compiled_contract",
        "/targets/0/fixture_inventory/0",
        "/targets/0/fixture_inventory/0/evidence",
        "/targets/0/generated_cases/0",
        "/targets/0/generated_cases/0/recipe",
        "/targets/0/generated_cases/0/source_fixture",
        "/targets/0/generated_cases/0/applicability",
        "/targets/0/platform_cases/0",
        "/targets/0/declared",
        "/targets/0/exercised",
        "/targets/0/requirements/0",
        "/summary",
        "/summary/requirements",
    ];
    for pointer in pointers {
        let mut document = serde_json::to_value(&report).unwrap();
        document
            .pointer_mut(pointer)
            .and_then(Value::as_object_mut)
            .expect("test pointer is an object")
            .insert("runtime_value".to_owned(), json!("not reportable"));
        assert_schema_invalid(&document);
        assert_typed_invalid(document);
    }
}

#[test]
fn fixed_scope_sentinels_and_evidence_kinds_cannot_claim_live_compatibility() {
    let report = generated_coverage_project("dhis2-script");
    for (field, value) in [
        ("evidence_scope", json!("live_country_source")),
        ("compatibility_claim", json!("source_interoperable")),
        ("live_compatibility", json!("compatible")),
    ] {
        let mut document = serde_json::to_value(&report).unwrap();
        document[field] = value;
        assert_schema_invalid(&document);
        assert_typed_invalid(document);
    }

    let mut wrong_kind = serde_json::to_value(report).unwrap();
    wrong_kind["targets"][0]["fixture_inventory"][0]["evidence"]["kind"] =
        json!("semantic_comparison");
    assert_typed_invalid(wrong_kind);
}

#[test]
fn report_has_no_value_path_or_secret_bearing_fields() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = temporary.path().join("sentinel-project");
    copy_project_tree(&project_root("bounded-http-starter"), &project);
    replace_authored_text(
        &project,
        "environments/local.yaml",
        "FICTIONAL_REGISTRY_TOKEN",
        "SECRET_REFERENCE_SENTINEL",
    );
    replace_authored_text(
        &project,
        "environments/local.yaml",
        "https://citizen-registry.invalid",
        "https://ORIGIN-SENTINEL.invalid",
    );
    replace_authored_text(
        &project,
        "integrations/person-record/fixtures/active.yaml",
        "AB-123456",
        "FIXTURE-INPUT-SENTINEL",
    );
    replace_authored_text(
        &project,
        "integrations/person-record/fixtures/active.yaml",
        "body: { active: true }",
        "body: { active: true, private: TOP-SECRET-CREDENTIAL }",
    );

    let context = registryctl::ProjectExecutionContext::new(registryctl_executable())
        .expect("Cargo provides registryctl");
    let report = registryctl::test_registry_project_with_context(
        &registryctl::ProjectTestOptions {
            project_directory: project,
            environment: Some("local".to_owned()),
        },
        &context,
    )
    .expect("sentinel-bearing authored project executes offline")
    .fixture_coverage
    .expect("full project test produces coverage");
    let document = serde_json::to_value(report).unwrap();
    for forbidden_key in [
        "input",
        "inputs",
        "request",
        "requests",
        "path",
        "fixture_path",
        "origin",
        "url",
        "cidr",
        "client_id",
        "client_secret",
        "authorization",
        "headers",
        "query",
        "body",
        "outputs",
        "values",
        "cel",
        "generated_at",
        "country",
    ] {
        assert!(
            !contains_key(&document, forbidden_key),
            "forbidden report field: {forbidden_key}"
        );
    }
    let bytes = serde_json::to_vec(&document).unwrap();
    for sentinel in [
        b"SECRET_REFERENCE_SENTINEL".as_slice(),
        b"FIXTURE-INPUT-SENTINEL".as_slice(),
        b"TOP-SECRET-CREDENTIAL".as_slice(),
        b"https://ORIGIN-SENTINEL.invalid".as_slice(),
    ] {
        assert!(!bytes
            .windows(sentinel.len())
            .any(|window| window == sentinel));
    }
}

#[test]
fn repeated_execution_is_byte_deterministic() {
    for project in ["bounded-http-starter", "dhis2-script", "snapshot-exact"] {
        let left = serde_json::to_vec(&generated_coverage_project(project)).unwrap();
        let right = serde_json::to_vec(&generated_coverage_project(project)).unwrap();
        assert_eq!(left, right, "{project} coverage bytes drifted");
    }
}

#[test]
fn comparison_input_is_strict_and_default_reports_do_not_fake_affected_sets() {
    let valid = json!({
        "baseline_digest": format!("sha256:{}", "1".repeat(64)),
        "candidate_digest": format!("sha256:{}", "2".repeat(64)),
        "targets": [{
            "integration": "health",
            "changed_input_ids": ["person_id"],
            "changed_output_ids": [],
            "source_contract_changed": true
        }]
    });
    let _: FixtureCoverageComparisonInput =
        serde_json::from_value(valid.clone()).expect("strict comparison input decodes");

    let mut unknown = valid.clone();
    unknown["targets"][0]["country_value"] = json!("private");
    assert!(serde_json::from_value::<FixtureCoverageComparisonInput>(unknown).is_err());

    let mut unsorted = valid;
    unsorted["targets"][0]["changed_input_ids"] = json!(["z", "a"]);
    assert!(serde_json::from_value::<FixtureCoverageComparisonInput>(unsorted).is_err());

    let target_report = generated_coverage_project("dhis2-script");
    let target = only_target(&target_report);
    assert!(target.comparison.is_none());
    assert!(target
        .requirements
        .iter()
        .skip(RequiredFixtureCoverageRequirement::ALL.len() - FixtureCoverageChangeKind::ALL.len(),)
        .all(|coverage| {
            coverage.state() == FixtureCoverageRequirementState::NotEvaluated
                && coverage.evidence().is_empty()
        }));
}

#[test]
fn requirement_states_and_evidence_fail_closed_across_all_evidence_classes() {
    let report = generated_coverage_project("bounded-http-starter");
    let original = serde_json::to_value(&report).unwrap();
    let compiled_contract = original["targets"][0]["compiled_contract"].clone();

    let semantic_match = requirement(&original, "semantic_match");
    assert_eq!(semantic_match["state"], "covered");
    let mut forged_authored_missing = original.clone();
    replace_requirement(
        &mut forged_authored_missing,
        "semantic_match",
        json!({
            "state": "missing",
            "requirement": "semantic_match",
            "reason": "required_evidence_missing",
            "evidence": semantic_match["evidence"].clone()
        }),
    );
    assert_schema_valid(&forged_authored_missing);
    assert_typed_invalid(forged_authored_missing);

    let response_bytes = requirement(&original, "response_bytes");
    assert_eq!(response_bytes["state"], "covered");
    let mut forged_generated_evidence = original.clone();
    replace_requirement(
        &mut forged_generated_evidence,
        "response_bytes",
        json!({
            "state": "covered",
            "requirement": "response_bytes",
            "evidence": [compiled_contract.clone()]
        }),
    );
    assert_schema_valid(&forged_generated_evidence);
    assert_typed_invalid(forged_generated_evidence);

    let output_fields = requirement(&original, "output_fields");
    assert_eq!(output_fields["state"], "covered");
    let mut forged_declared_missing = original.clone();
    replace_requirement(
        &mut forged_declared_missing,
        "output_fields",
        json!({
            "state": "missing",
            "requirement": "output_fields",
            "reason": "required_evidence_missing",
            "evidence": output_fields["evidence"].clone()
        }),
    );
    assert_schema_valid(&forged_declared_missing);
    assert_typed_invalid(forged_declared_missing);

    let request_bytes = requirement(&original, "request_bytes");
    assert_eq!(request_bytes["state"], "missing");
    let mut forged_missing_evidence = original.clone();
    replace_requirement(
        &mut forged_missing_evidence,
        "request_bytes",
        json!({
            "state": "missing",
            "requirement": "request_bytes",
            "reason": "numeric_boundary_not_exercised",
            "evidence": response_bytes["evidence"].clone()
        }),
    );
    assert_schema_valid(&forged_missing_evidence);
    assert_typed_invalid(forged_missing_evidence);

    let mut forged_boundary_covered = original;
    replace_requirement(
        &mut forged_boundary_covered,
        "request_bytes",
        json!({
            "state": "covered",
            "requirement": "request_bytes",
            "evidence": [compiled_contract]
        }),
    );
    assert_schema_valid(&forged_boundary_covered);
    assert_typed_invalid(forged_boundary_covered);
}

#[test]
fn comparison_enabled_generation_validates_all_impacts_and_keeps_targets_isolated() {
    let mut targets = vec![
        generated_coverage_project("bounded-http-starter")
            .targets
            .into_iter()
            .next()
            .unwrap(),
        generated_coverage_project("dhis2-script")
            .targets
            .into_iter()
            .next()
            .unwrap(),
    ];
    targets.sort_by(|left, right| left.identity.integration.cmp(&right.identity.integration));
    let input = comparison_input_for(&targets);
    let report = ProjectFixtureCoverageReportV1::from_targets(
        "comparison-project".to_owned(),
        None,
        targets,
    )
    .expect("base multi-target report validates")
    .with_comparison(&input)
    .expect("comparison-enabled report generation validates");
    let document = serde_json::to_value(&report).unwrap();
    assert_schema_valid(&document);
    let roundtrip: ProjectFixtureCoverageReportV1 =
        serde_json::from_value(document.clone()).expect("all three impacts roundtrip");
    assert_eq!(roundtrip, report);

    for target in &report.targets {
        let comparison = target.comparison.as_ref().expect("target was compared");
        assert_eq!(
            comparison
                .impacts
                .iter()
                .map(|impact| impact.kind)
                .collect::<Vec<_>>(),
            FixtureCoverageChangeKind::ALL
        );
        let local_fixture_ids = target
            .fixture_inventory
            .iter()
            .map(|fixture| fixture.fixture_id.as_str())
            .collect::<BTreeSet<_>>();
        for impact in &comparison.impacts {
            assert!(impact
                .affected_fixture_ids
                .iter()
                .all(|fixture_id| local_fixture_ids.contains(fixture_id.as_str())));
            assert!(impact.evidence.id.starts_with(&format!(
                "target/{}/semantic-comparison/",
                target.identity.integration
            )));
        }
        assert!(target
            .requirements
            .iter()
            .skip(
                RequiredFixtureCoverageRequirement::ALL.len()
                    - FixtureCoverageChangeKind::ALL.len(),
            )
            .all(|coverage| {
                !matches!(coverage, FixtureRequirementCoverage::NotEvaluated { .. })
                    && coverage.evidence().len() == 1
                    && coverage.evidence()[0].kind
                        == FixtureCoverageEvidenceKind::SemanticComparison
            }));
    }

    let mut forged_comparison_state = document;
    let changed_input = requirement(&forged_comparison_state, "changed_input_affected_fixtures");
    assert_eq!(changed_input["state"], "covered");
    replace_requirement(
        &mut forged_comparison_state,
        "changed_input_affected_fixtures",
        json!({
            "state": "missing",
            "requirement": "changed_input_affected_fixtures",
            "reason": "required_evidence_missing",
            "evidence": changed_input["evidence"].clone()
        }),
    );
    assert_schema_valid(&forged_comparison_state);
    assert_typed_invalid(forged_comparison_state);
}

#[test]
fn recipe_applicability_does_not_promote_inapplicable_cases_to_coverage() {
    for project in [
        "bounded-http-starter",
        "dhis2-script",
        "snapshot-exact",
        "opencrvs",
        "opencrvs-events-api",
    ] {
        let report = generated_coverage_project(project);
        let target = only_target(&report);
        for case in &target.generated_cases {
            if matches!(
                case.applicability,
                GeneratedRecipeApplicability::NotApplicable { .. }
            ) {
                assert_eq!(case.pass_state, FixturePassState::NotExecuted);
                assert!(case.actual_safe_code.is_none());
            }
        }
    }
}
