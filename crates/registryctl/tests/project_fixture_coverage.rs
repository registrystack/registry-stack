// SPDX-License-Identifier: Apache-2.0

#![allow(dead_code)]

#[path = "../src/project_authoring/knowledge.rs"]
mod knowledge;
#[path = "../src/project_authoring/report_contract.rs"]
mod report_contract;

pub use report_contract::Sha256Digest;

#[path = "../src/project_authoring/fixture_coverage.rs"]
mod fixture_coverage;

use std::collections::BTreeSet;

use registryctl::{
    FixtureCapability, FixtureCoverageComparisonInput, FixtureCoverageDimensions,
    FixtureCoverageEvidenceKind, FixtureCoverageGapReason, FixtureCoverageNotApplicableReason,
    FixtureCoverageNotEvaluatedReason, FixtureCoverageRequirementState, FixtureCoverageTarget,
    FixtureCoverageTargetSetState, FixturePassState, FixtureRequirementCoverage,
    GeneratedRecipeApplicability, GeneratorRecipeId, ProjectFixtureCoverageReportV1,
    RequiredFixtureCoverageRequirement,
};
use serde_json::{json, Value};

const SCHEMA: &str =
    include_str!("../schemas/project-reports/registry.project.fixture_coverage.v1.schema.json");
const FIXTURE: &str =
    include_str!("fixtures/project-reports/registry.project.fixture_coverage.v1.json");

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

fn project_root(name: &str) -> std::path::PathBuf {
    let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    if name == "bounded-http-starter" {
        manifest.join("assets/project-starters/bounded-http")
    } else {
        manifest.join("tests/fixtures/project-authoring").join(name)
    }
}

fn generated_coverage_project(name: &str) -> registryctl::ProjectFixtureCoverageReportV1 {
    let context = registryctl::ProjectExecutionContext::new(env!("CARGO_BIN_EXE_registryctl"))
        .expect("Cargo provides registryctl");
    registryctl::test_registry_project_with_context(
        &registryctl::ProjectTestOptions {
            project_directory: project_root(name),
            environment: None,
            live: false,
        },
        &context,
    )
    .expect("coverage fixtures execute")
    .fixture_coverage
    .expect("full project test produces coverage")
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
        claim_ids: Vec::new(),
        disclosure_modes: Vec::new(),
        status_mappings: Vec::new(),
        protocol_helpers: Vec::new(),
        limits: Vec::new(),
        script_branch_ids: Vec::new(),
    }
}

#[test]
fn canonical_no_target_fixture_validates_and_roundtrips_exactly() {
    let document = parse(FIXTURE);
    assert_schema_valid(&document);
    let decoded: ProjectFixtureCoverageReportV1 =
        serde_json::from_value(document.clone()).expect("canonical fixture decodes");
    assert_eq!(serde_json::to_value(&decoded).unwrap(), document);
    assert!(decoded.targets.is_empty());
    assert_eq!(
        decoded.summary.target_set_state,
        FixtureCoverageTargetSetState::NoTargets
    );
    assert_eq!(decoded.summary.requirements.total, 0);
}

#[test]
fn generated_targets_have_exact_ordered_34_requirement_contracts() {
    for (project, capability) in [
        ("bounded-http-starter", FixtureCapability::DeclarativeHttp),
        ("dhis2-script", FixtureCapability::Script),
        ("snapshot-exact", FixtureCapability::Snapshot),
        ("opencrvs", FixtureCapability::Script),
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
        assert_eq!(target.requirements.len(), 34);
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
            34
        );
        for requirement in target.requirements.iter().skip(30) {
            assert!(matches!(
                requirement,
                FixtureRequirementCoverage::NotEvaluated {
                    reason: FixtureCoverageNotEvaluatedReason::ComparisonInputAbsent,
                    evidence,
                    ..
                } if evidence.is_empty()
            ));
        }
        assert_eq!(report.summary.requirements.total, 34);
    }
}

#[test]
fn generated_cases_remain_executable_and_isolated_under_their_target() {
    for project in [
        "bounded-http-starter",
        "dhis2-script",
        "snapshot-exact",
        "opencrvs",
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
fn no_targets_and_a_fixtureless_target_are_distinct_states() {
    let no_targets: ProjectFixtureCoverageReportV1 = serde_json::from_str(FIXTURE).unwrap();
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
    target.requirements = RequiredFixtureCoverageRequirement::ALL
        .into_iter()
        .map(|requirement| {
            if matches!(
                requirement,
                RequiredFixtureCoverageRequirement::ChangedInputAffectedFixtures
                    | RequiredFixtureCoverageRequirement::ChangedOutputAffectedFixtures
                    | RequiredFixtureCoverageRequirement::ChangedClaimAffectedFixtures
                    | RequiredFixtureCoverageRequirement::ChangedSourceContractAffectedFixtures
            ) {
                FixtureRequirementCoverage::NotEvaluated {
                    requirement,
                    reason: FixtureCoverageNotEvaluatedReason::ComparisonInputAbsent,
                    evidence: Vec::new(),
                }
            } else {
                FixtureRequirementCoverage::Missing {
                    requirement,
                    reason: FixtureCoverageGapReason::TargetHasNoFixtures,
                    evidence: Vec::new(),
                }
            }
        })
        .collect();
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
    assert_eq!(report.targets[0].requirements.len(), 34);
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
    if !script.declared.claim_ids.is_empty() {
        assert!(!script.declared.disclosure_modes.is_empty());
        assert!(script.exercised.disclosure_modes.is_empty());
        assert!(matches!(
            script
                .requirements
                .iter()
                .find(|coverage| coverage.requirement()
                    == RequiredFixtureCoverageRequirement::ExercisedDisclosureModes),
            Some(FixtureRequirementCoverage::Missing {
                reason: FixtureCoverageGapReason::RuntimeDimensionNotObserved,
                ..
            })
        ));
    }
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
    assert_eq!(report.summary.requirements.total, 68);

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
    let document = serde_json::to_value(generated_coverage_project("opencrvs")).unwrap();
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
        "claims",
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
        b"TOP-SECRET-CREDENTIAL".as_slice(),
        b"Bearer secret".as_slice(),
        b"/Users/operator/private".as_slice(),
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
            "changed_claim_ids": [],
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
    assert!(target.requirements.iter().skip(30).all(|coverage| {
        coverage.state() == FixtureCoverageRequirementState::NotEvaluated
            && coverage.evidence().is_empty()
    }));
}

#[test]
fn recipe_applicability_does_not_promote_inapplicable_cases_to_coverage() {
    for project in [
        "bounded-http-starter",
        "dhis2-script",
        "snapshot-exact",
        "opencrvs",
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
