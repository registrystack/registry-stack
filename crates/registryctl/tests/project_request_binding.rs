// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};

use registryctl::{
    test_registry_project_with_context, FixtureRequirementCoverage, GovernedRequestEvidence,
    ProjectExecutionContext, ProjectTestOptions, RequiredFixtureCoverageRequirement,
};
use serde_norway::Value;

fn fixture_root(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/project-authoring")
        .join(name)
}

fn copy_tree(source: &Path, destination: &Path) {
    fs::create_dir_all(destination).expect("destination creates");
    let mut entries = fs::read_dir(source)
        .expect("source reads")
        .collect::<std::io::Result<Vec<_>>>()
        .expect("entries read");
    entries.sort_by_key(|entry| entry.file_name());
    for entry in entries {
        let source = entry.path();
        let destination = destination.join(entry.file_name());
        if entry.file_type().expect("type reads").is_dir() {
            copy_tree(&source, &destination);
        } else {
            fs::copy(source, destination).expect("file copies");
        }
    }
}

fn read_yaml(path: &Path) -> Value {
    serde_norway::from_slice(&fs::read(path).expect("YAML reads")).expect("YAML parses")
}

fn write_yaml(path: &Path, value: &Value) {
    fs::write(
        path,
        serde_norway::to_string(value).expect("YAML serializes"),
    )
    .expect("YAML writes");
}

fn test_project(path: &Path) -> anyhow::Result<registryctl::ProjectCommandReport> {
    test_registry_project_with_context(
        &ProjectTestOptions {
            project_directory: path.to_path_buf(),
            environment: None,
        },
        &ProjectExecutionContext::new(env!("CARGO_BIN_EXE_registryctl"))
            .expect("Cargo provides registryctl"),
    )
}

fn custom_project() -> (tempfile::TempDir, PathBuf) {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = temporary.path().join("project");
    copy_tree(&fixture_root("custom-system"), &project);
    (temporary, project)
}

fn set_mapping_scheme(project: &Path, scheme: &str) {
    let path = project.join("registry-stack.yaml");
    let mut document = read_yaml(&path);
    document["services"]["household-eligibility"]["consultations"]["household"]["input"]
        ["household_reference"] = Value::String(format!("request.target.identifiers.{scheme}"));
    write_yaml(&path, &document);
}

fn set_request_scheme(project: &Path, scheme: &str) {
    let path = project.join("integrations/eligibility/fixtures/source-approved.yaml");
    let mut fixture = read_yaml(&path);
    fixture["request"]["target"]["identifiers"][0]["scheme"] = Value::String(scheme.to_owned());
    write_yaml(&path, &fixture);
}

fn assert_zero_call_binding_failure(project: &Path) -> String {
    let error = test_project(project).expect_err("binding mismatch must fail");
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains("request_to_consultation_binding_invalid: relay_consultations=0"),
        "{rendered}"
    );
    rendered
}

#[test]
fn governed_request_binding_fails_closed_for_either_one_sided_scheme_change() {
    let (_temporary, project) = custom_project();
    set_mapping_scheme(&project, "country_household_id");
    assert_zero_call_binding_failure(&project);

    let (_temporary, project) = custom_project();
    set_request_scheme(&project, "country_household_id");
    assert_zero_call_binding_failure(&project);
}

#[test]
fn governed_request_binding_remains_country_configurable_when_both_sides_change() {
    let (_temporary, project) = custom_project();
    set_mapping_scheme(&project, "country_household_id");
    set_request_scheme(&project, "country_household_id");

    let report = test_project(&project).expect("consistent country binding passes");
    let witness = report
        .fixtures
        .iter()
        .find(|fixture| {
            fixture
                .fixture
                .ends_with("::derived/request_to_consultation_binding")
        })
        .expect("independent request witness is reported");
    assert!(witness.passed);
    assert_eq!(witness.calls, ["notary-relay-consultation"]);
    assert_eq!(
        witness.source_access,
        Some(true),
        "an entered Relay consultation must not be reported as zero source access"
    );
    assert_eq!(witness.claims, ["household-record-exists"]);
}

#[test]
fn governed_request_coverage_requires_every_reachable_consultation() {
    let (_temporary, project) = custom_project();
    let path = project.join("registry-stack.yaml");
    let mut document = read_yaml(&path);
    let service = &mut document["services"]["household-eligibility"];
    service["consultations"]["alternate"] = serde_norway::from_str(
        "{ integration: eligibility, input: { household_reference: request.target.identifiers.household_reference } }",
    )
    .expect("alternate consultation parses");
    service["claims"]["alternate-record-exists"] =
        serde_norway::from_str("{ cel: alternate.matched, disclosure: predicate }")
            .expect("alternate claim parses");
    service["credential_profiles"]["household-eligibility"]["claims"]
        .as_sequence_mut()
        .expect("credential claims are a sequence")
        .push(Value::String("alternate-record-exists".to_owned()));
    write_yaml(&path, &document);
    let fixture_path = project.join("integrations/eligibility/fixtures/source-approved.yaml");
    let mut fixture = read_yaml(&fixture_path);
    fixture["expect"]["claims"]["alternate-record-exists"] = Value::Bool(true);
    write_yaml(&fixture_path, &fixture);
    let no_match_path = project.join("integrations/eligibility/fixtures/no-match.yaml");
    let mut no_match = read_yaml(&no_match_path);
    no_match["expect"]["claims"]["alternate-record-exists"] = Value::Bool(false);
    write_yaml(&no_match_path, &no_match);

    let report = test_project(&project).expect("project test remains executable");
    let coverage = report
        .fixture_coverage
        .expect("fixture coverage is reported");
    assert_eq!(
        coverage.governed_request_evidence,
        GovernedRequestEvidence::PerConsultationAuthoredRequestWitnessEvaluation,
        "the root marker describes the proof method, not a false global pass state"
    );
    let target = coverage.targets.first().expect("target is reported");
    assert_eq!(target.contract.registry_backed_consultations.len(), 2);
    assert_eq!(
        target
            .fixture_inventory
            .iter()
            .flat_map(|fixture| { fixture.request_to_consultation_binding.consultations.iter() })
            .count(),
        1,
        "one request witness must not claim both reachable consultations"
    );
    assert!(matches!(
        target.requirements.iter().find(|coverage| {
            coverage.requirement()
                == RequiredFixtureCoverageRequirement::RequestToConsultationBinding
        }),
        Some(FixtureRequirementCoverage::Missing { .. })
    ));
}

#[test]
fn governed_request_boundary_rejects_closed_contract_mismatches_before_relay() {
    type Mutation = (&'static str, Box<dyn Fn(&mut Value)>);
    let mutations: Vec<Mutation> = vec![
        (
            "target type",
            Box::new(|fixture| {
                fixture["request"]["target"]["type"] = Value::String("Household".to_owned());
            }),
        ),
        (
            "purpose",
            Box::new(|fixture| {
                fixture["request"]["purpose"] = Value::String("unknown-purpose".to_owned());
            }),
        ),
        (
            "claim",
            Box::new(|fixture| {
                fixture["request"]["claims"][0] = Value::String("unknown-claim".to_owned());
            }),
        ),
        (
            "disclosure",
            Box::new(|fixture| {
                fixture["request"]["disclosure"] = Value::String("value".to_owned());
            }),
        ),
        (
            "format",
            Box::new(|fixture| {
                fixture["request"]["format"] = Value::String("application/json".to_owned());
            }),
        ),
        (
            "missing identifier",
            Box::new(|fixture| {
                fixture["request"]["target"]["identifiers"] = Value::Sequence(Vec::new());
            }),
        ),
        (
            "extra identifier",
            Box::new(|fixture| {
                fixture["request"]["target"]["identifiers"]
                    .as_sequence_mut()
                    .expect("identifiers are a sequence")
                    .push(
                        serde_norway::from_str("{ scheme: extra, value: synthetic }")
                            .expect("identifier parses"),
                    );
            }),
        ),
    ];

    for (name, mutate) in mutations {
        let (_temporary, project) = custom_project();
        let path = project.join("integrations/eligibility/fixtures/source-approved.yaml");
        let mut fixture = read_yaml(&path);
        mutate(&mut fixture);
        write_yaml(&path, &fixture);
        let failure = assert_zero_call_binding_failure(&project);
        assert!(
            !failure.contains("HH-AB12CD34"),
            "{name} leaked fixture data"
        );
    }
}

#[test]
fn governed_request_requires_synthetic_classification_and_rejects_secret_references() {
    for replacement in ["classification: reviewed", "classification: production"] {
        let (_temporary, project) = custom_project();
        let path = project.join("integrations/eligibility/fixtures/source-approved.yaml");
        let fixture = fs::read_to_string(&path).expect("fixture reads");
        fs::write(
            &path,
            fixture.replace("classification: synthetic", replacement),
        )
        .expect("fixture writes");
        assert!(test_project(&project).is_err());
    }

    let (_temporary, project) = custom_project();
    let integration_path = project.join("integrations/eligibility/integration.yaml");
    let mut integration = read_yaml(&integration_path);
    let household_reference = integration["input"]["household_reference"]
        .as_mapping_mut()
        .expect("household reference contract is an object");
    household_reference.remove("pattern");
    household_reference.insert("maxLength".into(), Value::Number(128.into()));
    write_yaml(&integration_path, &integration);

    let path = project.join("integrations/eligibility/fixtures/source-approved.yaml");
    let mut fixture = read_yaml(&path);
    fixture["request"]["target"]["identifiers"][0]["value"] =
        Value::String("${COUNTRY_IDENTIFIER}".to_owned());
    write_yaml(&path, &fixture);
    let rendered = format!(
        "{:#}",
        test_project(&project).expect_err("secret ref must fail")
    );
    assert!(
        rendered.contains("fixture governed request contains a forbidden credential-like field"),
        "{rendered}"
    );
    assert!(!rendered.contains("COUNTRY_IDENTIFIER"));
}

#[test]
fn governed_request_witness_executes_for_http_script_and_snapshot() {
    for project in ["custom-system", "dhis2-script", "snapshot-exact"] {
        let report = test_project(&fixture_root(project))
            .unwrap_or_else(|error| panic!("{project} request witness failed: {error:#}"));
        assert!(
            report.fixtures.iter().any(|fixture| {
                fixture
                    .fixture
                    .ends_with("::derived/request_to_consultation_binding")
                    && fixture.passed
            }),
            "{project} lacks a passing request witness"
        );
    }
}
