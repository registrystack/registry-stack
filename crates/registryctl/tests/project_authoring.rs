// SPDX-License-Identifier: Apache-2.0

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use registry_platform_config::ProductAcceptanceLaneV1;
use registryctl::{
    build_registry_project_with_baselines_and_context, build_registry_project_with_context,
    check_registry_project_with_context, create_trust_anchor, init_registry_project,
    inspect_project_capabilities, preflight_registry_project, render_project_authoring_diagnostics,
    setup_registry_project_editor, sign_product_bundle,
    test_registry_project_selected_with_context, test_registry_project_with_context,
    verify_config_bundle_cli, ClassifierSafeReportedValue, InitSource, ProductBundleSignOptions,
    ProjectAuthoringDiagnostics, ProjectBuildBaselineSetOptions, ProjectBuildOptions,
    ProjectCapabilityOptions, ProjectCheckOptions, ProjectEditorSetupOptions,
    ProjectExecutionContext, ProjectExplanationReportV1, ProjectFieldAddress,
    ProjectFieldExplanation, ProjectInitOptions, ProjectPreflightOptions, ProjectSchemaKind,
    ProjectStarter, ProjectTestOptions, ProjectTestSelection, TrustAnchorCreateOptions,
};
use serde::Deserialize;
use sha2::{Digest as _, Sha256};

const TEST_PRIVATE_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"registryctl-test-private-key"}"#;
const TEST_PUBLIC_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"registryctl-test-private-key"}"#;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectAuthoringJourneyCatalog {
    version: u8,
    workspaces: Vec<ProjectAuthoringJourney>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProjectAuthoringJourney {
    id: String,
    label: String,
    summary: String,
    source: String,
    classification: String,
    #[serde(default)]
    focus: Option<String>,
    topology: String,
    #[serde(default)]
    evidence: Option<String>,
    #[serde(default)]
    starter: Option<String>,
    project_dir: String,
    #[serde(default)]
    focused_fixture_file: Option<String>,
    steps: Vec<String>,
    environment: String,
    check_explain: bool,
}

fn golden(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/project-authoring")
        .join(name)
}

fn project_execution_context() -> ProjectExecutionContext {
    ProjectExecutionContext::new(env!("CARGO_BIN_EXE_registryctl"))
        .expect("Cargo provides the real registryctl executable")
}

fn test_registry_project(
    options: &ProjectTestOptions,
) -> anyhow::Result<registryctl::ProjectCommandReport> {
    test_registry_project_with_context(options, &project_execution_context())
}

fn test_registry_project_selected(
    options: &ProjectTestOptions,
    selection: &ProjectTestSelection,
) -> anyhow::Result<registryctl::ProjectCommandReport> {
    test_registry_project_selected_with_context(options, selection, &project_execution_context())
}

fn check_registry_project(
    options: &ProjectCheckOptions,
) -> anyhow::Result<registryctl::ProjectCommandReport> {
    check_registry_project_with_context(options, &project_execution_context())
}

fn build_registry_project(
    options: &ProjectBuildOptions,
) -> anyhow::Result<registryctl::ProjectCommandReport> {
    build_registry_project_with_context(options, &project_execution_context())
}

fn project_explanation_field<'a>(
    report: &'a ProjectExplanationReportV1,
    path: &str,
) -> &'a ProjectFieldExplanation {
    report
        .fields
        .iter()
        .find(|field| {
            matches!(
                &field.address,
                ProjectFieldAddress::Project { path: actual } if actual.as_str() == path
            )
        })
        .unwrap_or_else(|| panic!("project explanation field {path} exists"))
}

fn integration_explanation_field<'a>(
    report: &'a ProjectExplanationReportV1,
    integration: &str,
    path: &str,
) -> &'a ProjectFieldExplanation {
    report
        .fields
        .iter()
        .find(|field| {
            matches!(
                &field.address,
                ProjectFieldAddress::Integration {
                    integration: actual_integration,
                    path: actual_path,
                } if actual_integration == integration && actual_path.as_str() == path
            )
        })
        .unwrap_or_else(|| panic!("integration explanation field {integration}{path} exists"))
}

fn environment_explanation_field<'a>(
    report: &'a ProjectExplanationReportV1,
    environment: &str,
    path: &str,
) -> &'a ProjectFieldExplanation {
    report
        .fields
        .iter()
        .find(|field| {
            matches!(
                &field.address,
                ProjectFieldAddress::Environment {
                    environment: actual_environment,
                    path: actual_path,
                } if actual_environment == environment && actual_path.as_str() == path
            )
        })
        .unwrap_or_else(|| panic!("environment explanation field {environment}{path} exists"))
}

fn public_explanation_value(field: &ProjectFieldExplanation) -> &serde_json::Value {
    let ClassifierSafeReportedValue::Public { value } = &field.reported_value else {
        panic!("expected classifier-approved explanation value");
    };
    value.as_value()
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn project_authoring_journey_catalog() -> ProjectAuthoringJourneyCatalog {
    serde_norway::from_slice(
        &std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/project-authoring-journeys.yaml"),
        )
        .expect("project-authoring journey catalog reads"),
    )
    .expect("project-authoring journey catalog parses")
}

fn catalog_workspace(journey: &ProjectAuthoringJourney) -> PathBuf {
    repository_root().join(&journey.source)
}

fn catalog_focused_selection(journey: &ProjectAuthoringJourney) -> (String, String) {
    let workspace = catalog_workspace(journey);
    let project = read_yaml(&workspace.join("registry-stack.yaml"));
    let integrations = project["integrations"]
        .as_mapping()
        .expect("a focused catalog journey has integrations");
    assert_eq!(
        integrations.len(),
        1,
        "{} must derive one focused integration from its workspace",
        journey.id
    );
    let (integration_id, integration_reference) = integrations
        .iter()
        .next()
        .expect("one integration reference");
    let integration_id = integration_id
        .as_str()
        .expect("integration id is a string")
        .to_string();
    let integration_file = integration_reference["file"]
        .as_str()
        .expect("integration reference has a file");
    let fixture_file = journey
        .focused_fixture_file
        .as_deref()
        .expect("focused catalog journey names a fixture file");
    let fixture_path = workspace
        .join(integration_file)
        .parent()
        .expect("integration file has a parent")
        .join("fixtures")
        .join(fixture_file);
    let fixture = read_yaml(&fixture_path);
    let fixture_name = fixture["name"]
        .as_str()
        .expect("focused fixture has a name")
        .to_string();
    (integration_id, fixture_name)
}

fn catalog_has_authored_fixtures(
    journey: &ProjectAuthoringJourney,
    project: &serde_norway::Value,
) -> bool {
    let Some(integrations) = project["integrations"].as_mapping() else {
        return false;
    };
    integrations.values().any(|reference| {
        let Some(file) = reference["file"].as_str() else {
            return false;
        };
        let fixture_directory = catalog_workspace(journey)
            .join(file)
            .parent()
            .expect("integration file has a parent")
            .join("fixtures");
        fixture_directory.is_dir()
            && std::fs::read_dir(fixture_directory)
                .expect("fixture directory reads")
                .any(|entry| {
                    entry
                        .expect("fixture entry reads")
                        .path()
                        .extension()
                        .is_some_and(|extension| extension == "yaml")
                })
    })
}

fn catalog_starter(id: &str) -> ProjectStarter {
    match id {
        "http" => ProjectStarter::Http,
        "dhis2-tracker" => ProjectStarter::Dhis2Tracker,
        "opencrvs-dci" => ProjectStarter::OpencrvsDci,
        "fhir-r4" => ProjectStarter::FhirR4,
        "snapshot" => ProjectStarter::Snapshot,
        _ => panic!("unknown catalog starter {id}"),
    }
}

fn validate_public_starter_entries(
    workspaces: &[ProjectAuthoringJourney],
) -> std::result::Result<(), String> {
    let expected = BTreeSet::from([
        "dhis2-tracker",
        "fhir-r4",
        "http",
        "opencrvs-dci",
        "snapshot",
    ]);
    let entries = workspaces
        .iter()
        .filter_map(|journey| journey.starter.as_deref())
        .collect::<Vec<_>>();
    if entries.len() != expected.len() {
        return Err(format!(
            "expected exactly {} starter entries, found {}",
            expected.len(),
            entries.len()
        ));
    }
    let starters = entries.iter().copied().collect::<BTreeSet<_>>();
    if starters.len() != entries.len() {
        return Err("duplicate starter entry".to_string());
    }
    if starters != expected {
        return Err(format!("unexpected starter entries: {starters:?}"));
    }
    Ok(())
}

fn authoring_diagnostics(project: &Path) -> ProjectAuthoringDiagnostics {
    check_registry_project(&ProjectCheckOptions {
        project_directory: project.to_path_buf(),
        environment: "local".to_string(),
        explain: false,
        against: None,
        anchor: None,
    })
    .expect_err("invalid project returns typed authoring diagnostics")
    .downcast::<ProjectAuthoringDiagnostics>()
    .expect("error is the typed authoring diagnostics report")
}

fn assert_authoring_diagnostic(error: &anyhow::Error, code: &str) {
    let report = error
        .downcast_ref::<ProjectAuthoringDiagnostics>()
        .expect("error is a typed authoring diagnostics report");
    assert!(
        report
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == code),
        "missing {code}: {report:#?}"
    );
}

#[test]
fn project_check_aggregates_script_host_call_and_environment_diagnostics_safely() {
    const ARGUMENT_MARKER: &str = "argument-marker-383";
    const ENVIRONMENT_MARKER: &str = "environment-secret-marker-383";
    const FIXTURE_MARKER: &str = "fixture-value-marker-383";
    const RESPONSE_MARKER: &str = "source-response-marker-383";

    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("dhis2-script", temporary.path());
    let script_path = project.join("integrations/health-record/adapter.rhai");
    std::fs::write(
        &script_path,
        format!(
            "fn consult(ctx) {{\n    let response = source.gett(\"{ARGUMENT_MARKER}\");\n    result.no_match()\n}}\n"
        ),
    )
    .expect("invalid Script writes");

    let environment_path = project.join("environments/local.yaml");
    let mut environment = read_yaml(&environment_path);
    environment["integrations"]["health-record"]["source"]["credential"]["generation"] =
        serde_norway::Value::Number(0.into());
    environment["integrations"]["health-record"]["source"]["credential"]["username"]["secret"] =
        serde_norway::Value::String(ENVIRONMENT_MARKER.to_string());
    write_yaml(&environment_path, &environment);

    let fixture_path = project.join("integrations/health-record/fixtures/match.yaml");
    let mut fixture = read_yaml(&fixture_path);
    fixture["variables"]["diagnostic_marker"] =
        serde_norway::Value::String(FIXTURE_MARKER.to_string());
    fixture["interactions"][0]["respond"]["body"]["diagnostic_marker"] =
        serde_norway::Value::String(RESPONSE_MARKER.to_string());
    write_yaml(&fixture_path, &fixture);

    let report = authoring_diagnostics(&project);
    assert_eq!(report.status, "invalid");
    assert_eq!(report.diagnostics.len(), 2, "{report:#?}");
    let script = report
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code == "registryctl.authoring.script.unknown_function")
        .expect("one Script diagnostic");
    assert_eq!(script.file, "integrations/health-record/adapter.rhai");
    assert_eq!(script.field, Some("capability.script.file"));
    assert_eq!((script.line, script.column), (Some(2), Some(20)));
    assert_eq!(
        script.suggestion,
        Some("source.get(target: string) -> response")
    );
    assert_eq!(
        report
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code.starts_with("registryctl.authoring.script."))
            .count(),
        1
    );
    assert_eq!(
        report
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code == "registryctl.authoring.environment.invalid")
            .count(),
        1
    );
    assert!(!project.join(".registry-stack/build").exists());

    let human = render_project_authoring_diagnostics(&report);
    let json = serde_json::to_string_pretty(&report).expect("diagnostics serialize");
    let debug = format!("{report:#?}");
    assert_eq!(
        human
            .matches("registryctl.authoring.script.unknown_function")
            .count(),
        1,
        "{human}"
    );
    for rendered in [&human, &json, &debug] {
        for forbidden in [
            ARGUMENT_MARKER,
            ENVIRONMENT_MARKER,
            FIXTURE_MARKER,
            RESPONSE_MARKER,
            "https://health-registry.invalid",
            "HEALTH_REGISTRY_PASSWORD",
            "Engine",
            "EvalAltResult",
            &project.display().to_string(),
        ] {
            assert!(
                !rendered.contains(forbidden),
                "leaked {forbidden}: {rendered}"
            );
        }
    }
}

#[test]
fn project_check_keeps_script_probe_stable_across_metadata_and_ignores_non_calls() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("dhis2-script", temporary.path());
    let script_path = project.join("integrations/health-record/adapter.rhai");
    replace_in_file(
        &script_path,
        "fn consult(ctx) {\n",
        "fn consult(ctx) {\n    let text = \"source.gett(argument-marker)\";\n    // source.gett(\"argument-marker\")\n",
    );
    check_registry_project(&ProjectCheckOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        explain: false,
        against: None,
        anchor: None,
    })
    .expect("valid source.get and non-call text remain clean");

    std::fs::write(
        &script_path,
        r#"fn consult(ctx) {
    let first = source.gett("first-argument-marker");
    let second = source.publish("second-argument-marker");
    result.no_match()
}
"#,
    )
    .expect("two invalid calls write");
    let baseline = authoring_diagnostics(&project);
    let script = baseline
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.code.starts_with("registryctl.authoring.script."))
        .expect("Script diagnostic");
    assert_eq!((script.line, script.column), (Some(2), Some(17)));
    assert_eq!(
        script.suggestion,
        Some("source.get(target: string) -> response")
    );

    let integration_path = project.join("integrations/health-record/integration.yaml");
    let mut integration = read_yaml(&integration_path);
    integration["source"]["product"] =
        serde_norway::Value::String("unrelated-product-metadata".to_string());
    integration["source"]["versions"] =
        serde_norway::from_str("unverified: ['9.9']\n").expect("version metadata");
    write_yaml(&integration_path, &integration);
    assert_eq!(authoring_diagnostics(&project), baseline);
}

#[test]
fn project_check_root_parse_gates_references_but_keeps_selected_environment_syntax() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    std::fs::write(project.join("registry-stack.yaml"), "version: [\n")
        .expect("invalid project root writes");
    std::fs::write(project.join("environments/local.yaml"), "version: [\n")
        .expect("invalid environment writes");
    std::fs::write(
        project.join("integrations/eligibility/integration.yaml"),
        "also: [\n",
    )
    .expect("invalid integration writes");

    let report = authoring_diagnostics(&project);
    assert_eq!(report.diagnostics.len(), 2, "{report:#?}");
    assert_eq!(report.diagnostics[0].file, "environments/local.yaml");
    assert_eq!(report.diagnostics[1].file, "registry-stack.yaml");
    assert!(report
        .diagnostics
        .iter()
        .all(|diagnostic| diagnostic.code == "registryctl.authoring.yaml.invalid_syntax"));
}

#[test]
fn project_check_reports_two_schema_valid_environment_errors_once_each() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    let environment_path = project.join("environments/local.yaml");
    let mut environment = read_yaml(&environment_path);
    environment["integrations"]["eligibility"]["source"]["origin"] =
        serde_norway::Value::String("https://user@unsafe-origin-marker.invalid".to_string());
    environment["integrations"]["eligibility"]["source"]["credential"] =
        serde_norway::from_str("token: { secret: HOUSEHOLD_TOKEN }\ngeneration: 1\n")
            .expect("schema-valid incompatible credential");
    write_yaml(&environment_path, &environment);

    let report = authoring_diagnostics(&project);
    assert_eq!(report.diagnostics.len(), 2, "{report:#?}");
    assert_eq!(
        report
            .diagnostics
            .iter()
            .map(|diagnostic| diagnostic.field)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            Some("integrations.source.credential"),
            Some("integrations.source.origin"),
        ])
    );
    assert!(report
        .diagnostics
        .iter()
        .all(|diagnostic| diagnostic.code == "registryctl.authoring.environment.invalid"));
    assert!(!serde_json::to_string(&report)
        .expect("environment diagnostics serialize")
        .contains("unsafe-origin-marker"));
}

#[test]
fn project_check_orders_independent_fixture_errors_and_caps_deterministically() {
    let make = |root: &Path, reverse: bool, count: usize| {
        let project = copy_project("custom-system", root);
        let directory = project.join("integrations/eligibility/fixtures");
        let indices: Vec<_> = if reverse {
            (0..count).rev().collect()
        } else {
            (0..count).collect()
        };
        for index in indices {
            std::fs::write(
                directory.join(format!("broken-{index:03}.yaml")),
                "name: [\n",
            )
            .expect("broken fixture writes");
        }
        project
    };
    let first_root = tempfile::tempdir().expect("first temporary directory");
    let second_root = tempfile::tempdir().expect("second temporary directory");
    let first_project = make(first_root.path(), false, 70);
    let second_project = make(second_root.path(), true, 70);
    reverse_yaml_mapping(
        &second_project.join("integrations/eligibility/integration.yaml"),
        &["outputs"],
    );
    reverse_yaml_mapping(
        &second_project.join("registry-stack.yaml"),
        &["services", "household-eligibility", "claims"],
    );
    let first = authoring_diagnostics(&first_project);
    let repeated = authoring_diagnostics(&first_project);
    let second = authoring_diagnostics(&second_project);
    assert_eq!(first, repeated);
    assert_eq!(first, second);
    assert_eq!(first.diagnostics.len(), 64);
    assert_eq!(
        first
            .diagnostics
            .last()
            .expect("truncation diagnostic")
            .code,
        "registryctl.authoring.diagnostics.truncated"
    );
    assert_eq!(
        serde_json::to_vec(&first).expect("first diagnostics serialize"),
        serde_json::to_vec(&second).expect("second diagnostics serialize")
    );
    assert_eq!(
        render_project_authoring_diagnostics(&first),
        render_project_authoring_diagnostics(&second)
    );
}

#[test]
fn project_check_collects_separate_integration_and_fixture_yaml_errors() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    duplicate_project_integration(&project, "eligibility", "secondary");
    std::fs::write(
        project.join("integrations/secondary/integration.yaml"),
        "version: [\n",
    )
    .expect("invalid integration writes");
    let fixture_path = project.join("integrations/eligibility/fixtures/source-approved.yaml");
    let mut fixture = std::fs::read_to_string(&fixture_path).expect("fixture reads");
    fixture.push_str("unknown_authoring_field: true\n");
    std::fs::write(&fixture_path, fixture).expect("unknown fixture field writes");

    let report = authoring_diagnostics(&project);
    assert_eq!(report.diagnostics.len(), 2, "{report:#?}");
    let integration = report
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.file == "integrations/secondary/integration.yaml")
        .expect("integration syntax diagnostic");
    assert_eq!(
        integration.code,
        "registryctl.authoring.yaml.invalid_syntax"
    );
    assert!(integration.line.is_some());
    assert!(integration.column.is_some());
    assert_eq!(
        integration.schema_hint,
        Some("registryctl authoring schema --kind integration > integration.schema.json")
    );
    let fixture = report
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.file.ends_with("fixtures/source-approved.yaml"))
        .expect("fixture unknown-field diagnostic");
    assert_eq!(fixture.code, "registryctl.authoring.yaml.unknown_field");
    assert!(fixture.line.is_some());
    assert!(fixture.column.is_some());
    assert_eq!(
        fixture.schema_hint,
        Some("registryctl authoring schema --kind fixture > fixture.schema.json")
    );
}

#[test]
fn project_check_single_error_report_is_concise_and_typed() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    let fixture = project.join("integrations/eligibility/fixtures/source-approved.yaml");
    std::fs::write(&fixture, "name: [\n").expect("invalid fixture writes");
    let report = authoring_diagnostics(&project);
    assert_eq!(report.diagnostics.len(), 1, "{report:#?}");
    let human = render_project_authoring_diagnostics(&report);
    assert!(human.starts_with("Registry Stack project is invalid: 1 authoring diagnostic\n"));
    assert_eq!(
        human
            .matches("registryctl.authoring.yaml.invalid_syntax")
            .count(),
        1
    );
}

#[test]
fn project_check_cli_renders_the_same_typed_diagnostic_in_human_and_json() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    std::fs::write(
        project.join("integrations/eligibility/fixtures/source-approved.yaml"),
        "name: [\n",
    )
    .expect("invalid fixture writes");
    let run = |format: &str| {
        std::process::Command::new(env!("CARGO_BIN_EXE_registryctl"))
            .args([
                "check",
                "--project-dir",
                project.to_str().expect("project path is Unicode"),
                "--environment",
                "local",
                "--format",
                format,
            ])
            .output()
            .expect("registryctl check executes")
    };
    let human = run("human");
    let json = run("json");
    assert!(!human.status.success());
    assert!(!json.status.success());
    assert!(
        human.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&human.stderr)
    );
    assert!(
        json.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&json.stderr)
    );
    let human = String::from_utf8(human.stdout).expect("human output is UTF-8");
    let json: serde_json::Value =
        serde_json::from_slice(&json.stdout).expect("JSON output is typed diagnostics");
    assert_eq!(json["schema_version"], "registryctl.project_diagnostics.v1");
    let diagnostics = json["diagnostics"]
        .as_array()
        .expect("diagnostics is an array");
    assert_eq!(diagnostics.len(), 1);
    let code = diagnostics[0]["code"]
        .as_str()
        .expect("diagnostic code is a string");
    assert_eq!(human.matches(code).count(), 1);
    let report = authoring_diagnostics(&project);
    assert_eq!(
        human.trim_end(),
        render_project_authoring_diagnostics(&report)
    );
}

#[cfg(unix)]
#[test]
fn project_check_cli_rejects_an_unselected_environment_symlink_with_typed_output() {
    use std::os::unix::fs::symlink;

    const TARGET_MARKER: &str = "unselected-environment-target-marker";
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    let target = temporary.path().join(format!("{TARGET_MARKER}.yaml"));
    std::fs::write(&target, "version: 1\n").expect("symlink target writes");
    symlink(&target, project.join("environments/zzz.yaml"))
        .expect("unselected environment symlink creates");

    let fixture_path = project.join("integrations/eligibility/fixtures/source-approved.yaml");
    let mut fixture = read_yaml(&fixture_path);
    fixture["expect"]["outputs"]["approved"] = serde_norway::Value::Bool(false);
    write_yaml(&fixture_path, &fixture);

    let run = |format: &str| {
        std::process::Command::new(env!("CARGO_BIN_EXE_registryctl"))
            .args([
                "check",
                "--project-dir",
                project.to_str().expect("project path is Unicode"),
                "--environment",
                "local",
                "--format",
                format,
            ])
            .output()
            .expect("registryctl check executes")
    };
    let human = run("human");
    let json = run("json");
    assert!(!human.status.success());
    assert!(!json.status.success());
    assert!(human.stderr.is_empty());
    assert!(json.stderr.is_empty());

    let human = String::from_utf8(human.stdout).expect("human output is UTF-8");
    let json_text = String::from_utf8(json.stdout).expect("JSON output is UTF-8");
    let json: serde_json::Value =
        serde_json::from_str(&json_text).expect("invalid project output is typed JSON");
    assert_eq!(json["status"], "invalid");
    assert_eq!(
        json["diagnostics"]
            .as_array()
            .expect("diagnostic list")
            .len(),
        1
    );
    assert_eq!(
        json["diagnostics"][0]["code"],
        "registryctl.authoring.path.unsafe"
    );
    assert_eq!(json["diagnostics"][0]["file"], "environments/zzz.yaml");
    for rendered in [&human, &json_text] {
        assert!(!rendered.contains("Error:"), "{rendered}");
        assert!(!rendered.contains(TARGET_MARKER), "{rendered}");
        assert!(
            !rendered.contains(&temporary.path().display().to_string()),
            "{rendered}"
        );
    }
    assert_eq!(
        human.matches("registryctl.authoring.path.unsafe").count(),
        1
    );
    assert!(!project.join(".registry-stack/build").exists());
}

#[cfg(unix)]
#[test]
fn project_check_cli_reports_malformed_root_before_unselected_environment_boundary() {
    use std::os::unix::fs::symlink;

    const TARGET_MARKER: &str = "unselected-root-order-target-marker";
    const REFERENCE_MARKER: &str = "reference-chasing-marker";
    const FIXTURE_MARKER: &str = "fixture-execution-marker";
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    std::fs::write(project.join("registry-stack.yaml"), "version: [\n")
        .expect("malformed project root writes");
    std::fs::write(
        project.join("integrations/eligibility/integration.yaml"),
        format!("{REFERENCE_MARKER}: [\n"),
    )
    .expect("malformed referenced integration writes");
    std::fs::write(
        project.join("integrations/eligibility/fixtures/source-approved.yaml"),
        format!("{FIXTURE_MARKER}: [\n"),
    )
    .expect("malformed fixture writes");
    let target = temporary.path().join(format!("{TARGET_MARKER}.yaml"));
    std::fs::write(&target, "version: 1\n").expect("symlink target writes");
    symlink(&target, project.join("environments/zzz.yaml"))
        .expect("unselected environment symlink creates");

    let run = |format: &str| {
        std::process::Command::new(env!("CARGO_BIN_EXE_registryctl"))
            .args([
                "check",
                "--project-dir",
                project.to_str().expect("project path is Unicode"),
                "--environment",
                "local",
                "--format",
                format,
            ])
            .output()
            .expect("registryctl check executes")
    };
    let human = run("human");
    let json = run("json");
    let repeated_json = run("json");
    assert!(!human.status.success());
    assert!(!json.status.success());
    assert!(!repeated_json.status.success());
    assert!(human.stderr.is_empty());
    assert!(json.stderr.is_empty());
    assert!(repeated_json.stderr.is_empty());
    assert_eq!(json.stdout, repeated_json.stdout);

    let human = String::from_utf8(human.stdout).expect("human output is UTF-8");
    let json_text = String::from_utf8(json.stdout).expect("JSON output is UTF-8");
    let json: serde_json::Value =
        serde_json::from_str(&json_text).expect("malformed root output is typed JSON");
    let diagnostics = json["diagnostics"].as_array().expect("diagnostic list");
    assert_eq!(diagnostics.len(), 1, "{json:#}");
    assert_eq!(
        diagnostics[0]["code"],
        "registryctl.authoring.yaml.invalid_syntax"
    );
    assert_eq!(diagnostics[0]["file"], "registry-stack.yaml");
    for rendered in [&human, &json_text] {
        assert!(!rendered.contains("Error:"), "{rendered}");
        assert!(!rendered.contains("environments/zzz.yaml"), "{rendered}");
        assert!(!rendered.contains(TARGET_MARKER), "{rendered}");
        assert!(!rendered.contains(REFERENCE_MARKER), "{rendered}");
        assert!(!rendered.contains(FIXTURE_MARKER), "{rendered}");
        assert!(
            !rendered.contains(&temporary.path().display().to_string()),
            "{rendered}"
        );
    }
    assert_eq!(
        human
            .matches("registryctl.authoring.yaml.invalid_syntax")
            .count(),
        1
    );
    assert!(!project.join(".registry-stack/build").exists());
}

#[test]
fn project_check_collects_all_safe_missing_integration_references_without_cascades() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    let project_path = project.join("registry-stack.yaml");
    let mut authored = read_yaml(&project_path);
    authored["integrations"]["eligibility"]["file"] =
        serde_norway::Value::String("integrations/zeta/missing.yaml".to_string());
    authored["integrations"]
        .as_mapping_mut()
        .expect("integration map")
        .insert(
            serde_norway::Value::String("alpha".to_string()),
            serde_norway::from_str("file: integrations/alpha/missing.yaml\n")
                .expect("missing integration reference"),
        );
    write_yaml(&project_path, &authored);

    let report = authoring_diagnostics(&project);
    assert_eq!(report, authoring_diagnostics(&project));
    assert_eq!(report.diagnostics.len(), 2, "{report:#?}");
    assert_eq!(
        report
            .diagnostics
            .iter()
            .map(|diagnostic| diagnostic.file.as_str())
            .collect::<Vec<_>>(),
        vec![
            "integrations/alpha/missing.yaml",
            "integrations/zeta/missing.yaml",
        ]
    );
    assert!(report.diagnostics.iter().all(|diagnostic| {
        diagnostic.code == "registryctl.authoring.file.unreadable"
            && diagnostic.field == Some("integrations.file")
            && diagnostic.line.is_none()
            && diagnostic.column.is_none()
    }));
    let json = serde_json::to_string(&report).expect("missing references serialize");
    assert!(!json.contains("project.invalid"));
    assert!(!json.contains("environment.invalid"));
    assert!(!json.contains(&temporary.path().display().to_string()));
}

#[test]
fn project_check_collects_missing_entity_and_integration_references_together() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("snapshot-exact", temporary.path());
    std::fs::remove_file(project.join("entities/people.yaml")).expect("referenced entity removes");
    std::fs::remove_file(project.join("integrations/person-snapshot/integration.yaml"))
        .expect("referenced integration removes");

    let report = authoring_diagnostics(&project);
    assert_eq!(report.diagnostics.len(), 2, "{report:#?}");
    assert_eq!(
        report
            .diagnostics
            .iter()
            .map(|diagnostic| (diagnostic.file.as_str(), diagnostic.field))
            .collect::<Vec<_>>(),
        vec![
            ("entities/people.yaml", Some("entities.file")),
            (
                "integrations/person-snapshot/integration.yaml",
                Some("integrations.file"),
            ),
        ]
    );
    assert!(report
        .diagnostics
        .iter()
        .all(|diagnostic| diagnostic.code == "registryctl.authoring.file.unreadable"));
}

#[test]
fn project_check_unsafe_inputs_are_terminal_and_value_free() {
    let traversal_root = tempfile::tempdir().expect("traversal temporary directory");
    let traversal = copy_project("custom-system", traversal_root.path());
    let project_path = traversal.join("registry-stack.yaml");
    let mut project = read_yaml(&project_path);
    project["integrations"]["eligibility"]["file"] =
        serde_norway::Value::String("../unsafe-marker/integration.yaml".to_string());
    write_yaml(&project_path, &project);
    let traversal_report = authoring_diagnostics(&traversal);
    assert_eq!(traversal_report.diagnostics.len(), 1);
    assert_eq!(
        traversal_report.diagnostics[0].code,
        "registryctl.authoring.path.unsafe"
    );
    assert!(!format!("{traversal_report:#?}").contains("unsafe-marker"));

    let missing_root = tempfile::tempdir().expect("missing temporary directory");
    let missing = copy_project("custom-system", missing_root.path());
    std::fs::remove_file(missing.join("integrations/eligibility/integration.yaml"))
        .expect("referenced file removes");
    let missing_report = authoring_diagnostics(&missing);
    assert_eq!(missing_report.diagnostics.len(), 1);
    assert_eq!(
        missing_report.diagnostics[0].code,
        "registryctl.authoring.file.unreadable"
    );

    let oversized_root = tempfile::tempdir().expect("oversized temporary directory");
    let oversized = copy_project("custom-system", oversized_root.path());
    std::fs::write(
        oversized.join("integrations/eligibility/integration.yaml"),
        vec![b' '; 1024 * 1024 + 1],
    )
    .expect("oversized authored file writes");
    let oversized_report = authoring_diagnostics(&oversized);
    assert_eq!(oversized_report.diagnostics.len(), 1);
    assert_eq!(
        oversized_report.diagnostics[0].code,
        "registryctl.authoring.file.too_large"
    );

    #[cfg(unix)]
    {
        use std::os::unix::fs::symlink;

        let symlink_root = tempfile::tempdir().expect("symlink temporary directory");
        let symlinked = copy_project("custom-system", symlink_root.path());
        let integration = symlinked.join("integrations/eligibility/integration.yaml");
        let target = symlinked.join("integrations/eligibility/integration-target.yaml");
        std::fs::rename(&integration, &target).expect("integration target renames");
        symlink(&target, &integration).expect("integration symlink creates");
        let symlink_report = authoring_diagnostics(&symlinked);
        assert_eq!(symlink_report.diagnostics.len(), 1);
        assert_eq!(
            symlink_report.diagnostics[0].code,
            "registryctl.authoring.path.unsafe"
        );
    }
}

#[test]
fn project_authoring_catalog_classifies_every_golden_and_only_five_starters() {
    const GOLDEN_SOURCE_PREFIX: &str = "crates/registryctl/tests/fixtures/project-authoring/";
    const SUPPORTED_STEPS: [&str; 8] = [
        "init", "editor", "trace", "watch", "test", "check", "compare", "build",
    ];
    let catalog = project_authoring_journey_catalog();
    assert_eq!(catalog.version, 1);

    let mut ids = BTreeSet::new();
    let mut sources = BTreeSet::new();
    let mut catalog_goldens = BTreeSet::new();
    for journey in &catalog.workspaces {
        assert!(
            ids.insert(journey.id.as_str()),
            "duplicate id {}",
            journey.id
        );
        assert!(
            sources.insert(journey.source.as_str()),
            "duplicate source {}",
            journey.source
        );
        assert!(!journey.label.trim().is_empty(), "{} label", journey.id);
        assert!(!journey.summary.trim().is_empty(), "{} summary", journey.id);
        assert!(
            matches!(
                journey.classification.as_str(),
                "maintained" | "conformance-only"
            ),
            "{} classification",
            journey.id
        );
        assert!(
            matches!(
                journey.topology.as_str(),
                "combined" | "relay-only" | "notary-only"
            ),
            "{} topology",
            journey.id
        );
        assert!(
            !journey.project_dir.trim().is_empty(),
            "{} project_dir",
            journey.id
        );
        assert_eq!(journey.environment, "local", "{} environment", journey.id);
        assert!(journey.check_explain, "{} check explanation", journey.id);
        assert!(catalog_workspace(journey).is_dir(), "{} source", journey.id);
        assert!(
            journey
                .steps
                .iter()
                .all(|step| SUPPORTED_STEPS.contains(&step.as_str())),
            "{} supported steps",
            journey.id
        );
        assert_eq!(
            journey.steps.iter().collect::<BTreeSet<_>>().len(),
            journey.steps.len(),
            "{} duplicate steps",
            journey.id
        );
        assert!(
            journey.steps.contains(&"check".to_string()),
            "{} check",
            journey.id
        );
        let project = read_yaml(&catalog_workspace(journey).join("registry-stack.yaml"));
        let has_integrations = project["integrations"]
            .as_mapping()
            .is_some_and(|values| !values.is_empty());
        let has_entities = project["entities"]
            .as_mapping()
            .is_some_and(|values| !values.is_empty());
        let services = project["services"]
            .as_mapping()
            .expect("catalog workspace services are a mapping");
        let has_notary = services
            .values()
            .any(|service| service["kind"].as_str() == Some("evidence"));
        let has_relay = has_integrations
            || has_entities
            || services
                .values()
                .any(|service| service["kind"].as_str() == Some("records_api"));
        let derived_topology = match (has_relay, has_notary) {
            (true, true) => "combined",
            (true, false) => "relay-only",
            (false, true) => "notary-only",
            (false, false) => panic!("{} has no product topology", journey.id),
        };
        assert_eq!(
            journey.topology, derived_topology,
            "{} topology",
            journey.id
        );
        if derived_topology == "combined" {
            assert!(
                journey.steps.contains(&"build".to_string()),
                "{} combined governed build",
                journey.id
            );
        } else {
            assert!(
                !journey.steps.contains(&"build".to_string()),
                "{} partial topology must not advertise a governed build",
                journey.id
            );
            if journey.classification == "maintained" {
                assert!(
                    journey.steps.contains(&"test".to_string()),
                    "{} maintained partial topology keeps offline test",
                    journey.id
                );
            }
        }

        let has_authored_fixtures = catalog_has_authored_fixtures(journey, &project);
        if !has_authored_fixtures {
            assert!(
                !journey
                    .steps
                    .iter()
                    .any(|step| step == "trace" || step == "watch"),
                "{} is fixtureless and must not invent trace or watch journeys",
                journey.id
            );
            assert!(
                journey.focused_fixture_file.is_none(),
                "{} fixture",
                journey.id
            );
        }
        if has_authored_fixtures && journey.classification == "maintained" {
            assert!(
                journey.steps.contains(&"watch".to_string()),
                "{} maintained fixture journey must exercise watch",
                journey.id
            );
        }
        if journey
            .steps
            .iter()
            .any(|step| step == "trace" || step == "watch")
        {
            let (integration, fixture) = catalog_focused_selection(journey);
            assert!(!integration.is_empty(), "{} integration", journey.id);
            assert!(!fixture.is_empty(), "{} fixture", journey.id);
        }

        if let Some(starter) = &journey.starter {
            assert_eq!(journey.steps, SUPPORTED_STEPS, "{starter} starter steps");
        } else {
            assert_eq!(
                journey.project_dir, journey.source,
                "{} non-starter commands must target the committed workspace",
                journey.id
            );
            assert!(
                !journey.steps.contains(&"init".to_string()),
                "{} non-starter cannot initialize",
                journey.id
            );
            assert!(
                !journey.steps.contains(&"compare".to_string()),
                "{} non-starter has no embedded-starter baseline",
                journey.id
            );
        }
        if let Some(name) = journey.source.strip_prefix(GOLDEN_SOURCE_PREFIX) {
            catalog_goldens.insert(name);
        }
    }

    let golden_root =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/project-authoring");
    let actual_goldens = std::fs::read_dir(golden_root)
        .expect("golden directory reads")
        .map(|entry| entry.expect("golden entry reads"))
        .filter(|entry| entry.file_type().expect("golden type reads").is_dir())
        .map(|entry| {
            entry
                .file_name()
                .into_string()
                .expect("golden name is Unicode")
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        catalog_goldens
            .into_iter()
            .map(str::to_string)
            .collect::<BTreeSet<_>>(),
        actual_goldens,
        "adding or removing a golden requires an explicit catalog decision"
    );
    validate_public_starter_entries(&catalog.workspaces)
        .expect("catalog has exactly five unique public starter entries");

    let dhis2_script = catalog
        .workspaces
        .iter()
        .find(|journey| journey.id == "dhis2-script")
        .expect("DHIS2 Script catalog entry");
    assert_eq!(dhis2_script.classification, "conformance-only");
    assert!(dhis2_script.starter.is_none());
    assert_eq!(dhis2_script.steps, ["test", "check", "build"]);
    let nia = catalog
        .workspaces
        .iter()
        .find(|journey| journey.id == "nia-attribute-release")
        .expect("NIA attribute-release catalog entry");
    assert_eq!(nia.classification, "conformance-only");
    assert_eq!(nia.focus.as_deref(), Some("solmara"));
    assert!(nia.starter.is_none());
    let openspp = catalog
        .workspaces
        .iter()
        .find(|journey| journey.id == "openspp-exact")
        .expect("OpenSPP catalog entry");
    assert_eq!(
        openspp.evidence.as_deref(),
        Some("offline-fixture-validation")
    );
}

#[test]
fn project_authoring_catalog_rejects_a_duplicate_starter_entry() {
    let mut catalog = project_authoring_journey_catalog();
    let fhir = catalog
        .workspaces
        .iter_mut()
        .find(|journey| journey.starter.as_deref() == Some("fhir-r4"))
        .expect("FHIR starter entry");
    fhir.starter = Some("http".to_string());

    let error = validate_public_starter_entries(&catalog.workspaces)
        .expect_err("a duplicate starter value must fail closed");
    assert!(error.contains("duplicate starter"), "{error}");
}

#[test]
fn project_authoring_catalog_rejects_fewer_than_five_starter_entries() {
    let mut catalog = project_authoring_journey_catalog();
    let fhir = catalog
        .workspaces
        .iter_mut()
        .find(|journey| journey.starter.as_deref() == Some("fhir-r4"))
        .expect("FHIR starter entry");
    fhir.starter = None;

    let error = validate_public_starter_entries(&catalog.workspaces)
        .expect_err("fewer than five starter entries must fail closed");
    assert!(
        error.contains("expected exactly 5 starter entries"),
        "{error}"
    );
}

#[test]
fn every_cataloged_supported_project_authoring_command_is_automated() {
    for journey in project_authoring_journey_catalog().workspaces {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = temporary.path().join(&journey.project_dir);
        if let Some(starter) = &journey.starter {
            let report = init_registry_project(&ProjectInitOptions {
                starter: catalog_starter(starter),
                directory: project.clone(),
            })
            .unwrap_or_else(|error| panic!("{} init failed: {error:#}", journey.id));
            assert_eq!(report.status, "initialized", "{} init", journey.id);
        } else {
            std::fs::create_dir_all(project.parent().expect("project path has a parent"))
                .expect("project parent creates");
            copy_tree(&catalog_workspace(&journey), &project);
        }

        if journey.steps.contains(&"editor".to_string()) {
            let report = setup_registry_project_editor(&ProjectEditorSetupOptions {
                project_directory: project.clone(),
            })
            .unwrap_or_else(|error| panic!("{} editor setup failed: {error:#}", journey.id));
            assert_eq!(report.status, "configured", "{} editor", journey.id);
        }

        if journey.steps.contains(&"trace".to_string()) {
            let (integration, fixture) = catalog_focused_selection(&journey);
            let report = test_registry_project_selected(
                &ProjectTestOptions {
                    project_directory: project.clone(),
                    environment: None,
                },
                &ProjectTestSelection {
                    integration: Some(integration),
                    fixture: Some(fixture.clone()),
                    trace: true,
                },
            )
            .unwrap_or_else(|error| panic!("{} trace failed: {error:#}", journey.id));
            assert_eq!(report.status, "passed", "{} trace", journey.id);
            assert!(
                report
                    .fixtures
                    .iter()
                    .any(|result| result.fixture == fixture && result.passed),
                "{} focused fixture",
                journey.id
            );
        }
        if journey.steps.contains(&"test".to_string()) {
            let report = test_registry_project(&ProjectTestOptions {
                project_directory: project.clone(),
                environment: None,
            })
            .unwrap_or_else(|error| panic!("{} offline test failed: {error:#}", journey.id));
            assert_eq!(report.status, "passed", "{} test", journey.id);
            if journey.topology == "combined" {
                assert!(!report.fixtures.is_empty(), "{} fixtures", journey.id);
            }
            assert!(
                report.fixtures.iter().all(|fixture| fixture.passed),
                "{} fixtures",
                journey.id
            );
        }

        let check = check_registry_project(&ProjectCheckOptions {
            project_directory: project.clone(),
            environment: journey.environment.clone(),
            explain: journey.check_explain,
            against: None,
            anchor: None,
        })
        .unwrap_or_else(|error| panic!("{} check failed: {error:#}", journey.id));
        assert_eq!(check.status, "valid", "{} check", journey.id);
        assert!(check.explanation.is_some(), "{} explanation", journey.id);

        if !journey.steps.contains(&"build".to_string()) {
            let error = build_registry_project(&ProjectBuildOptions {
                project_directory: project,
                environment: journey.environment.clone(),
                against: None,
                anchor: None,
            })
            .expect_err("partial product topology must not publish a governed build");
            let message = format!("{error:#}");
            assert!(message.contains("project test"), "{message}");
            assert!(message.contains("project check"), "{message}");
            assert!(message.contains("before project build"), "{message}");
            continue;
        }

        let build = build_registry_project(&ProjectBuildOptions {
            project_directory: project.clone(),
            environment: journey.environment.clone(),
            against: None,
            anchor: None,
        })
        .unwrap_or_else(|error| panic!("{} build failed: {error:#}", journey.id));
        assert_eq!(build.status, "built", "{} build", journey.id);
        let output = resolve_build_output(&project, build.output.expect("catalog build output"));
        let relay = output.join("private/relay-public");
        let notary = output.join("private/notary");
        match journey.topology.as_str() {
            "relay-only" => {
                assert!(relay.is_dir(), "{} Relay inputs", journey.id);
                assert!(!notary.exists(), "{} Notary inputs", journey.id);
            }
            "notary-only" => {
                assert!(notary.is_dir(), "{} Notary inputs", journey.id);
                assert!(!relay.exists(), "{} Relay inputs", journey.id);
            }
            "combined" => {
                assert!(relay.is_dir(), "{} Relay inputs", journey.id);
                assert!(notary.is_dir(), "{} Notary inputs", journey.id);
                let notary_config = read_yaml(&notary.join("config/notary.yaml"));
                assert_eq!(
                    notary_config["state"]["storage"].as_str(),
                    Some("in_memory"),
                    "{} Notary correctness state",
                    journey.id
                );
                assert!(
                    notary_config["evidence"]["relay"].is_mapping(),
                    "{} compiler-pinned Relay consultation",
                    journey.id
                );
                let rendered = serde_norway::to_string(&notary_config)
                    .expect("generated Notary config serializes");
                assert!(
                    rendered.contains("contract_hash:"),
                    "{} compiler-pinned consultation hash",
                    journey.id
                );
                for forbidden in ["redis:", "direct_source:", "source_credential:"] {
                    assert!(!rendered.contains(forbidden), "{} {forbidden}", journey.id);
                }
            }
            _ => unreachable!("catalog topology is validated"),
        }
    }
}

#[test]
fn country_variant_and_snapshot_records_keep_their_closed_outcome_sets() {
    for (project, expected) in [
        (
            "opencrvs-country-variant",
            [
                ("provincial-birth-match", "match"),
                ("provincial-birth-no-match", "no_match"),
                ("provincial-birth-ambiguous", "ambiguous"),
            ]
            .as_slice(),
        ),
        (
            "snapshot-with-records",
            [
                ("snapshot-match", "match"),
                ("snapshot-no-match", "no_match"),
            ]
            .as_slice(),
        ),
    ] {
        let report = test_registry_project(&ProjectTestOptions {
            project_directory: golden(project),
            environment: None,
        })
        .unwrap_or_else(|error| panic!("{project} outcome journey failed: {error:#}"));
        for (fixture, outcome) in expected {
            let result = report
                .fixtures
                .iter()
                .find(|result| result.fixture == *fixture)
                .unwrap_or_else(|| panic!("{project} missing {fixture}"));
            assert_eq!(result.outcome.as_deref(), Some(*outcome), "{project}");
            assert!(result.passed, "{project} {fixture}");
        }
    }
}

#[test]
fn fhir_r4_coverage_active_passes_the_closed_bundle_matrix() {
    let report = test_registry_project(&ProjectTestOptions {
        project_directory: golden("fhir-r4-coverage-active"),
        environment: None,
    })
    .expect("FHIR R4 Coverage-active golden passes");
    assert_eq!(report.status, "passed");
    assert!(
        report.fixtures.len() >= 5,
        "the five authored journeys and their derived security cases must execute"
    );
    assert!(report
        .fixtures
        .iter()
        .any(|fixture| fixture.fixture.ends_with("::derived/request_authority")));
    assert!(report.fixtures.iter().any(|fixture| fixture
        .fixture
        .ends_with("::derived/authorization_before_source")));
    assert!(report.fixtures.iter().all(|fixture| fixture.passed));
}

#[test]
fn approved_opencrvs_and_dhis2_claim_sets_execute_offline() {
    for project in ["opencrvs", "opencrvs-country-variant", "dhis2-tracker"] {
        let report = test_registry_project(&ProjectTestOptions {
            project_directory: golden(project),
            environment: None,
        })
        .unwrap_or_else(|error| panic!("{project} approved claims failed: {error:#}"));
        assert!(report.fixtures.iter().all(|fixture| fixture.passed));
    }
}

#[test]
fn synthetic_opencrvs_events_api_executes_the_closed_offline_matrix() {
    let project = golden("opencrvs-events-api");
    let report = test_registry_project(&ProjectTestOptions {
        project_directory: project.clone(),
        environment: None,
    })
    .expect("synthetic OpenCRVS Events API case study passes offline");
    assert_eq!(report.status, "passed");
    assert!(report.fixtures.iter().all(|fixture| fixture.passed));

    for (fixture_name, outcome) in [
        ("birth-event-match", "match"),
        ("birth-event-no-match", "no_match"),
        ("birth-event-ambiguous", "ambiguous"),
    ] {
        let fixture = report
            .fixtures
            .iter()
            .find(|fixture| fixture.fixture.as_str() == fixture_name)
            .unwrap_or_else(|| panic!("missing {fixture_name}"));
        assert_eq!(fixture.outcome.as_deref(), Some(outcome));
    }
    for (fixture_name, safe_code) in [
        ("birth-event-source-malformed", "source.status_rejected"),
        ("birth-event-source-rejected", "source.status_rejected"),
        ("birth-event-source-timeout", "source.deadline_exceeded"),
        ("birth-event-subject-mismatch", "failure.subject_mismatch"),
        ("oauth-token-expiry-rejected", "source.response_malformed"),
        (
            "oauth-token-extra-member-rejected",
            "source.response_malformed",
        ),
        (
            "oauth-token-media-type-rejected",
            "source.response_malformed",
        ),
        ("oauth-token-redirect-rejected", "source.status_rejected"),
        ("oauth-token-type-rejected", "source.response_malformed"),
    ] {
        let fixture = report
            .fixtures
            .iter()
            .find(|fixture| fixture.fixture.as_str() == fixture_name)
            .unwrap_or_else(|| panic!("missing {fixture_name}"));
        assert_eq!(fixture.expected_error.as_deref(), Some(safe_code));
        assert!(fixture.outputs.is_empty());
        assert!(fixture.claims.is_empty());
    }

    let matched = report
        .fixtures
        .iter()
        .find(|fixture| fixture.fixture.as_str() == "birth-event-match")
        .expect("exact-selector match fixture");
    assert_eq!(matched.outputs, ["event_type", "registered"]);
    assert_eq!(
        matched.claims,
        ["birth-event-found", "birth-event-registered"]
    );
    assert_eq!(matched.calls.len(), 2);

    for (recipe, safe_code) in [
        ("malformed_decode", Some("source.response_malformed")),
        ("byte_ceiling", Some("source.response_too_large")),
        ("timeout", Some("source.deadline_exceeded")),
        ("authorization_before_source", Some("authorization.denied")),
        ("output_minimization", None),
    ] {
        let fixture_id = format!("birth-event-match::derived/{recipe}");
        let fixture = report
            .fixtures
            .iter()
            .find(|fixture| fixture.fixture.as_str() == fixture_id.as_str())
            .unwrap_or_else(|| panic!("missing {fixture_id}"));
        assert_eq!(fixture.expected_error.as_deref(), safe_code);
        assert!(fixture.passed);
        if recipe == "authorization_before_source" {
            assert_eq!(fixture.source_access, Some(false));
            assert!(fixture.calls.is_empty());
        }
    }

    let serialized = serde_json::to_string(&report).expect("fixture report serializes");
    for source_only_value in [
        "TRK-SYNTH000001",
        "SYNTHETIC_FIXTURE_TOKEN",
        "Synthetic Source-Only Name",
        "synthetic-source-only",
    ] {
        assert!(
            !serialized.contains(source_only_value),
            "reports must not expose source-only fixture values"
        );
    }

    let environment = read_yaml(&project.join("environments/local.yaml"));
    assert_eq!(
        environment["development"]["default_integration"].as_str(),
        Some("birth-event-search")
    );
    assert_eq!(
        environment["development"]["default_fixture"].as_str(),
        Some("birth-event-match")
    );

    let integration = read_yaml(&project.join("integrations/birth-event-search/integration.yaml"));
    assert_eq!(
        integration["source"]["auth"]["type"].as_str(),
        Some("oauth2_client_credentials")
    );
    assert_eq!(
        integration["source"]["auth"]["response_profile"].as_str(),
        Some("oauth2_bearer_no_expiry")
    );
    assert_eq!(
        integration["source"]["allow"][0]["method"].as_str(),
        Some("POST")
    );
    assert_eq!(
        integration["source"]["allow"][0]["path"].as_str(),
        Some("/api/events/events/search")
    );
    assert_eq!(
        integration["input"]["tracking_id"]["role"].as_str(),
        Some("selector")
    );

    let passing_fixture =
        read_yaml(&project.join("integrations/birth-event-search/fixtures/match.yaml"));
    let oauth_response = passing_fixture["interactions"][0]["respond"]["body"]
        .as_mapping()
        .expect("OAuth response is a mapping");
    assert_eq!(
        oauth_response.len(),
        2,
        "no-expiry profile response has exactly two members"
    );
    assert_eq!(
        passing_fixture["interactions"][0]["respond"]["body"]["token_type"].as_str(),
        Some("Bearer")
    );
    assert_eq!(
        passing_fixture["interactions"][1]["expect"]["path"].as_str(),
        Some("/api/events/events/search")
    );
    assert_eq!(
        passing_fixture["interactions"][1]["expect"]["body"]["query"]["clauses"][0]["trackingId"]
            ["type"]
            .as_str(),
        Some("exact")
    );
    assert_eq!(
        passing_fixture["interactions"][1]["expect"]["body"]["query"]["clauses"][0]["trackingId"]
            ["term"]
            .as_str(),
        Some("TRK-SYNTH000001")
    );
    assert_eq!(
        passing_fixture["interactions"][1]["expect"]["body"]["limit"].as_i64(),
        Some(2)
    );

    let authored = read_yaml(&project.join("registry-stack.yaml"));
    let service = &authored["services"]["birth-event-verification"];
    assert_eq!(
        service["consultations"]
            .as_mapping()
            .expect("consultations are a mapping")
            .len(),
        1
    );
    assert_eq!(
        service["consultations"]["event"]["input"]["tracking_id"].as_str(),
        Some("request.target.identifiers.opencrvs_tracking_id")
    );
    for claim in ["birth-event-found", "birth-event-registered"] {
        assert!(
            service["claims"][claim]["cel"]
                .as_str()
                .expect("claim CEL is a string")
                .contains("event."),
            "{claim} must derive from the single Relay consultation"
        );
    }
}

#[test]
fn dhis2_health_evidence_journey_preserves_distinct_results() {
    let project = golden("dhis2-tracker");
    let report = test_registry_project(&ProjectTestOptions {
        project_directory: project.clone(),
        environment: None,
    })
    .expect("DHIS2 health evidence journey passes offline");
    assert_eq!(report.status, "passed");

    let expected_outputs = [
        "bcg_birth_dose_recorded",
        "child_health_visit_recorded",
        "child_program_active",
        "date_of_birth",
        "first_name",
        "last_name",
        "maternal_postnatal_active",
        "measles_dose_recorded",
        "opv_birth_dose_recorded",
        "programme_code",
        "reconciliation_reference",
        "tb_program_active",
    ]
    .map(String::from);
    let expected_claims = [
        "bcg-birth-dose-recorded",
        "child-age-band",
        "child-health-visit-recorded",
        "child-program-active",
        "maternal-postnatal-care-active",
        "measles-dose-recorded",
        "opv-birth-dose-recorded",
        "programme-code",
        "reconciliation-reference",
        "tb-program-active",
        "tracked-entity-first-name",
        "tracked-entity-last-name",
    ]
    .map(String::from);

    for fixture_name in [
        "complete-child-health-evidence",
        "partial-child-health-evidence",
        "no-child-program-enrollment",
    ] {
        let fixture = report
            .fixtures
            .iter()
            .find(|fixture| fixture.fixture == fixture_name)
            .unwrap_or_else(|| panic!("missing {fixture_name}"));
        assert_eq!(fixture.outcome.as_deref(), Some("match"));
        assert_eq!(fixture.outputs, expected_outputs);
        assert_eq!(fixture.claims, expected_claims);
        assert!(fixture.passed, "{fixture:#?}");
    }

    let no_match = report
        .fixtures
        .iter()
        .find(|fixture| fixture.fixture == "health-no-match")
        .expect("no-match fixture report");
    assert_eq!(no_match.outcome.as_deref(), Some("no_match"));
    assert!(no_match.outputs.is_empty());
    assert_eq!(no_match.claims, expected_claims);
    assert!(no_match.passed, "{no_match:#?}");

    for (fixture_name, expected_error) in [
        ("health-source-rejected", "source.status_rejected"),
        ("health-subject-mismatch", "failure.subject_mismatch"),
    ] {
        let fixture = report
            .fixtures
            .iter()
            .find(|fixture| fixture.fixture == fixture_name)
            .unwrap_or_else(|| panic!("missing {fixture_name}"));
        assert_eq!(fixture.expected_error.as_deref(), Some(expected_error));
        assert_eq!(fixture.source_access, Some(true));
        assert!(fixture.outputs.is_empty());
        assert!(fixture.claims.is_empty());
        assert!(fixture.passed, "{fixture:#?}");
    }

    let malformed = report
        .fixtures
        .iter()
        .find(|fixture| fixture.fixture.ends_with("::derived/malformed_decode"))
        .expect("derived malformed-source fixture report");
    assert_eq!(
        malformed.expected_error.as_deref(),
        Some("source.response_malformed")
    );
    assert_eq!(malformed.source_access, Some(true));
    assert!(malformed.passed, "{malformed:#?}");

    let fixtures = project.join("integrations/health-record/fixtures");
    let complete = read_yaml(&fixtures.join("match.yaml"));
    for claim in [
        "child-program-active",
        "bcg-birth-dose-recorded",
        "opv-birth-dose-recorded",
        "measles-dose-recorded",
    ] {
        assert_eq!(complete["expect"]["claims"][claim].as_bool(), Some(true));
    }

    let partial = read_yaml(&fixtures.join("partial.yaml"));
    assert_eq!(
        partial["expect"]["claims"]["child-program-active"].as_bool(),
        Some(false)
    );
    assert_eq!(
        partial["expect"]["claims"]["bcg-birth-dose-recorded"].as_bool(),
        Some(false)
    );
    assert!(partial["expect"]["claims"]["opv-birth-dose-recorded"].is_null());
    assert_eq!(
        partial["expect"]["claims"]["measles-dose-recorded"].as_bool(),
        Some(true)
    );

    for fixture_name in ["no-enrollment.yaml", "no-match.yaml"] {
        let fixture = read_yaml(&fixtures.join(fixture_name));
        for claim in [
            "child-program-active",
            "bcg-birth-dose-recorded",
            "opv-birth-dose-recorded",
            "measles-dose-recorded",
        ] {
            assert!(
                fixture["expect"]["claims"][claim].is_null(),
                "{fixture_name} must keep {claim} unknown"
            );
        }
    }

    let authored = read_yaml(&project.join("registry-stack.yaml"));
    assert!(!yaml_contains_string(&authored, "eligible"));
    assert!(!yaml_contains_string(&authored, "outreach"));
}

#[test]
fn successful_negative_fixtures_report_the_closed_denial_assertion() {
    let report = test_registry_project(&ProjectTestOptions {
        project_directory: golden("custom-system"),
        environment: None,
    })
    .expect("custom system golden passes");
    let serialized = serde_json::to_string(&report).expect("fixture report serializes");
    assert!(!serialized.contains("HH-AB12CD34"));
    assert!(!serialized.contains("synthetic-key-1"));

    let denied_before_access = report
        .fixtures
        .iter()
        .find(|fixture| {
            fixture
                .fixture
                .ends_with("::derived/authorization_before_source")
        })
        .expect("derived authorization fixture report");
    assert!(denied_before_access.passed);
    assert_eq!(
        denied_before_access.expected_error.as_deref(),
        Some("authorization.denied")
    );
    assert_eq!(denied_before_access.source_access, Some(false));

    let denied_after_access = report
        .fixtures
        .iter()
        .find(|fixture| fixture.fixture.ends_with("::derived/malformed_decode"))
        .expect("derived malformed-response fixture report");
    assert!(denied_after_access.passed);
    assert_eq!(
        denied_after_access.expected_error.as_deref(),
        Some("source.response_malformed")
    );
    assert_eq!(denied_after_access.source_access, Some(true));

    let successful = report
        .fixtures
        .iter()
        .find(|fixture| fixture.fixture == "source-approved-household")
        .expect("source-approved fixture report");
    assert_eq!(successful.expected_error, None);
    assert_eq!(successful.source_access, None);
}

#[test]
fn exact_sources_report_reviewable_ambiguity_not_applicable_evidence() {
    for (project, integration, fixture) in [
        (
            "dhis2-tracker",
            "health-record",
            "complete-child-health-evidence",
        ),
        ("openspp-exact", "individual", "social-registry-match"),
        ("snapshot-exact", "person-snapshot", "snapshot-match"),
    ] {
        let report = check_registry_project(&ProjectCheckOptions {
            project_directory: golden(project),
            environment: "local".to_string(),
            explain: true,
            against: None,
            anchor: None,
        })
        .unwrap_or_else(|error| panic!("{project} check failed: {error:#}"));
        let explanation = report.explanation.as_ref().expect("explanation");
        for path in [
            "/not_applicable/ambiguity/request_fixture",
            "/not_applicable/ambiguity/rationale",
        ] {
            assert!(
                matches!(
                    integration_explanation_field(explanation, integration, path).reported_value,
                    ClassifierSafeReportedValue::Redacted { .. }
                ),
                "{project} must retain the reviewable field address without reporting its value"
            );
        }
        assert!(
            !fixture.is_empty(),
            "{project} keeps the request fixture in authored input"
        );
        assert!(!report
            .fixtures
            .iter()
            .any(|fixture| fixture.outcome.as_deref() == Some("ambiguous")));
    }

    let fhir = test_registry_project(&ProjectTestOptions {
        project_directory: golden("fhir-r4-coverage-active"),
        environment: None,
    })
    .expect("genuinely ambiguous collection source remains covered");
    assert!(fhir
        .fixtures
        .iter()
        .any(|fixture| fixture.outcome.as_deref() == Some("ambiguous")));
}

#[test]
fn response_contracts_without_comparable_identifiers_report_subject_mismatch_evidence() {
    for (project, integration, fixture) in [
        ("custom-system", "eligibility", "source-approved-household"),
        ("openspp-exact", "individual", "social-registry-match"),
        ("snapshot-exact", "person-snapshot", "snapshot-match"),
    ] {
        let report = check_registry_project(&ProjectCheckOptions {
            project_directory: golden(project),
            environment: "local".to_string(),
            explain: true,
            against: None,
            anchor: None,
        })
        .unwrap_or_else(|error| panic!("{project} check failed: {error:#}"));
        let explanation = report.explanation.as_ref().expect("explanation");
        for path in [
            "/not_applicable/subject_mismatch/request_fixture",
            "/not_applicable/subject_mismatch/rationale",
        ] {
            assert!(
                matches!(
                    integration_explanation_field(explanation, integration, path).reported_value,
                    ClassifierSafeReportedValue::Redacted { .. }
                ),
                "{project} must retain the reviewable field address without reporting its value"
            );
        }
        assert!(
            !fixture.is_empty(),
            "{project} keeps the request fixture in authored input"
        );
        assert!(!report.fixtures.iter().any(|fixture| {
            fixture.expected_error.as_deref() == Some("failure.subject_mismatch")
        }));
    }
}

#[test]
fn ambiguity_not_applicable_requires_a_real_request_fixture() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("openspp-exact", temporary.path());
    replace_in_file(
        &project.join("integrations/individual/integration.yaml"),
        "request_fixture: social-registry-match",
        "request_fixture: missing-request-proof",
    );
    let error = test_registry_project(&ProjectTestOptions {
        project_directory: project,
        environment: None,
    })
    .expect_err("missing not-applicable request evidence must fail");
    assert!(format!("{error:#}").contains("references missing fixture"));
}

#[test]
fn maintained_script_starter_exercises_explicit_result_fail() {
    let report = test_registry_project_selected(
        &ProjectTestOptions {
            project_directory: golden("dhis2-tracker"),
            environment: None,
        },
        &ProjectTestSelection {
            integration: Some("health-record".to_string()),
            fixture: Some("health-source-rejected".to_string()),
            trace: true,
        },
    )
    .expect("result.fail fixture passes its closed error assertion");
    let fixture = report
        .fixtures
        .iter()
        .find(|fixture| fixture.fixture == "health-source-rejected")
        .expect("authored failure fixture report");
    assert_eq!(
        fixture.expected_error.as_deref(),
        Some("source.status_rejected")
    );
    assert_eq!(fixture.source_access, Some(true));
    assert_eq!(fixture.calls.len(), 1);
    assert!(fixture.calls[0].contains("operation=script-source-call"));
    assert!(fixture.calls[0].contains("method=GET"));
    assert!(!fixture.calls[0].contains("A0000000001"));
    assert!(!fixture.calls[0].contains("B0000000002"));
    assert!(fixture.passed);
}

#[test]
fn maintained_script_starter_rejects_echoed_subject_mismatch() {
    let report = test_registry_project_selected(
        &ProjectTestOptions {
            project_directory: golden("dhis2-tracker"),
            environment: None,
        },
        &ProjectTestSelection {
            integration: Some("health-record".to_string()),
            fixture: Some("health-subject-mismatch".to_string()),
            trace: true,
        },
    )
    .expect("subject mismatch fixture passes its closed failure assertion");
    let fixture = report
        .fixtures
        .iter()
        .find(|fixture| fixture.fixture == "health-subject-mismatch")
        .expect("authored mismatch fixture report");
    assert_eq!(
        fixture.expected_error.as_deref(),
        Some("failure.subject_mismatch")
    );
    assert_eq!(fixture.source_access, Some(true));
    assert_eq!(fixture.calls.len(), 1);
    assert!(fixture.calls[0].contains("operation=script-source-call"));
    assert!(fixture.calls[0].contains("method=GET"));
    assert!(!fixture.calls[0].contains("A0000000001"));
    assert!(!fixture.calls[0].contains("B0000000002"));
    assert!(fixture.passed);
}

#[test]
fn script_subject_comparison_requires_a_mismatch_fixture() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("dhis2-tracker", temporary.path());
    std::fs::remove_file(project.join("integrations/health-record/fixtures/subject-mismatch.yaml"))
        .expect("mismatch fixture removes");
    let error = test_registry_project(&ProjectTestOptions {
        project_directory: project,
        environment: None,
    })
    .expect_err("reviewed subject comparison without a mismatch fixture must fail");
    assert!(
        format!("{error:#}").contains("must provide a fixture expecting failure.subject_mismatch")
    );
}

#[test]
fn subject_mismatch_not_applicable_rejects_comparable_response_evidence() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("openspp-exact", temporary.path());
    let fixture = project.join("integrations/individual/fixtures/match.yaml");
    replace_in_file(
        &fixture,
        "body: { active: true, programme_code: SUPPORT, household_reference: HH-0001 }",
        "body: { individual_id: IND-AB12CD34, active: true, programme_code: SUPPORT, household_reference: HH-0001 }",
    );
    let error = test_registry_project(&ProjectTestOptions {
        project_directory: project,
        environment: None,
    })
    .expect_err("a comparable echoed identifier must make mismatch applicable");
    assert!(format!("{error:#}").contains(
        "subject mismatch request evidence contains a selector-comparable response identifier"
    ));
}

#[test]
fn subject_mismatch_not_applicable_rejects_comparable_output_contract() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("snapshot-exact", temporary.path());
    replace_in_file(
        &project.join("integrations/person-snapshot/integration.yaml"),
        "outputs: [registration_status, residency_confirmed]",
        "outputs: [person_id, registration_status, residency_confirmed]",
    );
    let error = test_registry_project(&ProjectTestOptions {
        project_directory: project,
        environment: None,
    })
    .expect_err("a comparable projected identifier must make mismatch applicable");
    assert!(format!("{error:#}")
        .contains("reviewed response contract has no selector-comparable identifier"));
}

#[test]
fn script_source_byte_budget_rejects_two_call_underprovisioning_before_execution() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("fhir-r4-coverage-active", temporary.path());
    replace_in_file(
        &project.join("integrations/coverage/integration.yaml"),
        "limits: { calls: 4, source_bytes: 512KiB, request_bytes: 8KiB, deadline: 12s }",
        "limits: { calls: 2, source_bytes: 200KiB, request_bytes: 8KiB, deadline: 12s }",
    );
    let error = test_registry_project_selected(
        &ProjectTestOptions {
            project_directory: project,
            environment: None,
        },
        &ProjectTestSelection {
            integration: Some("coverage".to_string()),
            fixture: Some("coverage-active".to_string()),
            trace: true,
        },
    )
    .expect_err("two source responses must not bypass the aggregate source-byte budget");
    let diagnostic = format!("{error:#}");
    assert!(diagnostic.contains("InvalidLimits"), "{diagnostic}");
}

#[test]
fn signed_dci_rejects_wrong_jwks_algorithm_and_key_use() {
    for (field, value) in [("alg", "RS512"), ("use", "enc")] {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = copy_project("opencrvs", temporary.path());
        let jwks_path = project.join("integrations/birth-record/fixtures/bodies/jwks.json");
        let mut jwks: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&jwks_path).expect("JWKS reads"))
                .expect("JWKS parses");
        jwks["keys"][0][field] = serde_json::Value::String(value.to_string());
        std::fs::write(
            &jwks_path,
            serde_json::to_vec_pretty(&jwks).expect("JWKS serializes"),
        )
        .expect("mutated JWKS writes");
        let error = test_registry_project_selected(
            &ProjectTestOptions {
                project_directory: project,
                environment: None,
            },
            &ProjectTestSelection {
                integration: Some("birth-record".to_string()),
                fixture: Some("birth-record-match".to_string()),
                trace: true,
            },
        )
        .expect_err("wrong signing-key metadata must fail closed");
        assert!(
            format!("{error:#}").contains("source.response_malformed"),
            "{error:#}"
        );
    }
}

#[test]
fn partial_relay_project_tests_and_checks_but_cannot_ship_a_governed_build() {
    let relay_root = tempfile::tempdir().expect("Relay-only temporary directory");
    let relay = copy_project("relay-only-records", relay_root.path());
    test_registry_project(&ProjectTestOptions {
        project_directory: relay.clone(),
        environment: None,
    })
    .expect("Relay-only project tests");
    check_registry_project(&ProjectCheckOptions {
        project_directory: relay.clone(),
        environment: "local".to_string(),
        explain: true,
        against: None,
        anchor: None,
    })
    .expect("Relay-only project explains");
    let relay_build = build_registry_project(&ProjectBuildOptions {
        project_directory: relay,
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect_err("Relay-only project cannot ship a partial governed signed set");
    let relay_message = format!("{relay_build:#}");
    assert!(relay_message.contains("governed build requires"));
    assert!(relay_message.contains("project test"));
    assert!(relay_message.contains("project check"));
    assert!(relay_message.contains("add deployment.notary before project build"));
}

#[test]
fn authored_rhai_script_compiles_under_the_production_surface() {
    let script = std::fs::read_to_string(
        golden("dhis2-script").join("integrations/health-record/adapter.rhai"),
    )
    .expect("authored Rhai script");
    registry_relay::rhai_worker::probe_script(
        &script,
        "consult",
        registry_relay::rhai_worker::WorkerLimits {
            max_call_levels: 16,
            max_expr_depth: 16,
            max_memory_bytes: 64 * 1024 * 1024,
            wall_time_ms: 5_000,
            ..registry_relay::rhai_worker::WorkerLimits::default()
        },
    )
    .expect("authored Rhai script compiles under the production language surface");
}

#[cfg(target_os = "linux")]
#[test]
fn local_rhai_modules_are_a_static_hash_covered_closure() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("dhis2-script", temporary.path());
    let integration_directory = project.join("integrations/health-record");
    std::fs::create_dir(integration_directory.join("lib")).expect("module directory creates");
    let module = integration_directory.join("lib/normalize.rhai");
    std::fs::write(&module, "fn normalize_status(value) { value }\n").expect("local module writes");
    let integration_path = integration_directory.join("integration.yaml");
    let mut integration = read_yaml(&integration_path);
    integration["capability"]["script"]["modules"] =
        serde_norway::from_str("[lib/normalize.rhai]").expect("module list");
    write_yaml(&integration_path, &integration);

    let options = ProjectBuildOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        against: None,
        anchor: None,
    };
    let first = build_registry_project(&options).expect("project with local module builds");
    let first_output = resolve_build_output(&project, first.output.expect("first build output"));
    let compiled_path =
        first_output.join("private/relay-consultation/config/artifacts/rhai/health-record.rhai");
    let compiled = std::fs::read_to_string(&compiled_path).expect("compiled closure reads");
    assert!(compiled.contains("registry-local-module:lib/normalize.rhai"));
    assert!(compiled.contains("fn normalize_status(value)"));
    assert!(compiled.contains("registry-entrypoint:adapter.rhai"));
    let first_closure = directory_closure(&first_output);

    std::fs::write(&module, "fn normalize_status(value) { value == () }\n")
        .expect("local module changes");
    let second = build_registry_project(&options).expect("changed local module builds");
    let second_output = resolve_build_output(&project, second.output.expect("second build output"));
    assert_ne!(
        closure_digest(&first_closure),
        closure_digest(&directory_closure(&second_output)),
        "changing a local module must change the generated project closure"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn public_rhai_commands_accept_the_released_contract_for_an_unknown_product() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let baseline_root = temporary.path().join("baseline");
    let changed_root = temporary.path().join("changed");
    let absent_root = temporary.path().join("absent");
    std::fs::create_dir(&baseline_root).expect("baseline root creates");
    std::fs::create_dir(&changed_root).expect("changed root creates");
    std::fs::create_dir(&absent_root).expect("absent root creates");
    let baseline = copy_project("dhis2-script", &baseline_root);
    let project = copy_project("dhis2-script", &changed_root);
    replace_in_file(
        &project.join("integrations/health-record/integration.yaml"),
        "product: dhis2",
        "product: fictional-health-registry",
    );
    replace_in_file(
        &project.join("integrations/health-record/integration.yaml"),
        "versions: { unverified: [2.41.9] }",
        "versions: { unverified: ['7.3'] }",
    );

    let metadata_free = copy_project("dhis2-script", &absent_root);
    let metadata_free_integration =
        metadata_free.join("integrations/health-record/integration.yaml");
    let mut integration = read_yaml(&metadata_free_integration);
    let source = integration["source"]
        .as_mapping_mut()
        .expect("Rhai source mapping");
    source.remove(serde_norway::Value::String("product".to_string()));
    source.remove(serde_norway::Value::String("versions".to_string()));
    write_yaml(&metadata_free_integration, &integration);

    let exercise = |project_directory: PathBuf| {
        let test_report = test_registry_project(&ProjectTestOptions {
            project_directory: project_directory.clone(),
            environment: None,
        })
        .expect("released Rhai contract tests independent of product metadata");
        assert_eq!(test_report.status, "passed");

        let check_report = check_registry_project(&ProjectCheckOptions {
            project_directory: project_directory.clone(),
            environment: "local".to_string(),
            explain: false,
            against: None,
            anchor: None,
        })
        .expect("product-neutral Rhai project checks");
        assert_eq!(check_report.status, "valid");

        let build_report = build_registry_project(&ProjectBuildOptions {
            project_directory: project_directory.clone(),
            environment: "local".to_string(),
            against: None,
            anchor: None,
        })
        .expect("product-neutral Rhai project builds");
        assert_eq!(build_report.status, "built");
        let output = resolve_build_output(
            &project_directory,
            build_report.output.expect("build output"),
        );
        let pack: serde_json::Value = serde_json::from_slice(
            &std::fs::read(output.join(
                "private/relay-consultation/config/artifacts/integration-packs/health-record.json",
            ))
            .expect("Rhai integration pack reads"),
        )
        .expect("Rhai integration pack parses");
        (
            serde_json::to_value(test_report.fixtures).expect("fixture reports serialize"),
            pack["spec"]["plan"]["kind"].clone(),
            pack["spec"]["plan"]["rhai"]["script_hash"].clone(),
        )
    };

    let baseline_dispatch = exercise(baseline);
    let changed_dispatch = exercise(project);
    let absent_dispatch = exercise(metadata_free);
    assert_eq!(baseline_dispatch, changed_dispatch);
    assert_eq!(baseline_dispatch, absent_dispatch);
}

#[test]
fn project_authoring_rhai_commands_are_portable_offline() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("dhis2-script", temporary.path());

    let test_report = test_registry_project(&ProjectTestOptions {
        project_directory: project.clone(),
        environment: None,
    })
    .expect("portable offline Rhai test passes without production activation");
    assert_eq!(test_report.status, "passed");

    let check_report = check_registry_project(&ProjectCheckOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        explain: false,
        against: None,
        anchor: None,
    })
    .expect("portable project check compiles the reviewed Rhai program");
    assert_eq!(check_report.status, "valid");

    let build_report = build_registry_project(&ProjectBuildOptions {
        project_directory: project,
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect("portable project build compiles product inputs");
    assert_eq!(build_report.status, "built");
}

#[test]
fn rhai_conformance_controls_are_code_only_and_deny_ambient_capabilities() {
    let limits = registry_relay::rhai_worker::WorkerLimits {
        max_call_levels: 16,
        max_expr_depth: 16,
        max_memory_bytes: 128 * 1024 * 1024,
        wall_time_ms: 5_000,
        ..registry_relay::rhai_worker::WorkerLimits::default()
    };
    let worker =
        registry_relay::rhai_worker::WorkerProcess::with_program(env!("CARGO_BIN_EXE_registryctl"));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime builds");
    for script in [
        "fn consult(input, prior) { http_get(\"https://example.invalid\") }",
        "fn consult(input, prior) { read_file(\"/etc/passwd\") }",
        "fn consult(input, prior) { exec(\"id\") }",
        "fn consult(input, prior) { env_var(\"HOME\") }",
        "fn consult(input, prior) { timestamp() }",
    ] {
        let request = registry_relay::rhai_worker::WorkerRequest::v1(script, "consult", limits);
        assert_eq!(
            runtime.block_on(worker.evaluate(&request)),
            Err(registry_relay::rhai_worker::WorkerError::ScriptRejected)
        );
    }

    let request = registry_relay::rhai_worker::WorkerRequest::v1(
        "fn consult(input) { result.no_match() }",
        "consult",
        limits,
    );
    let serialized = serde_json::to_value(request).expect("worker request serializes");
    for forbidden in [
        "caller",
        "scopes",
        "purpose",
        "disclosure",
        "credential",
        "provenance",
    ] {
        assert!(serialized.get(forbidden).is_none());
    }
}

#[test]
fn production_cel_worker_evaluates_project_date_policy() {
    let mut config =
        registry_notary_server::cel_worker::CelWorkerConfig::for_current_exe_subcommand();
    config.command = env!("CARGO_BIN_EXE_registryctl").into();
    config.command_args = vec!["__registryctl-cel-worker-v1".into()];
    config.startup_timeout = std::time::Duration::from_secs(10);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("test runtime builds");
    let worker = registry_notary_server::cel_worker::CelWorker::lazy(config);
    let value = runtime
        .block_on(worker.evaluate(
            "health.exists && health.date_of_birth != null\n  ? date.age_on(health.date_of_birth, as_of_date)\n  : null",
            serde_json::json!({
                "health": {
                    "exists": true,
                    "first_name": "Nia",
                    "last_name": "Example",
                    "date_of_birth": "2017-06-15",
                    "child_program_active": true,
                    "programme_code": "CHILD",
                    "reconciliation_reference": "REF-0001",
                    "maternal_postnatal_active": true,
                    "child_health_visit_recorded": true,
                    "tb_program_active": false
                },
                "as_of_date": "2026-01-01"
            }),
        ))
        .expect("production CEL worker evaluates the project date policy");
    assert_eq!(value, serde_json::json!(8));

    let age_band = runtime
        .block_on(worker.evaluate(
            "health.exists && health.date_of_birth != null\n  ? (date.age_on(health.date_of_birth, as_of_date) < 5\n      ? \"0-4\"\n      : (date.age_on(health.date_of_birth, as_of_date) < 18 ? \"5-17\" : \"18+\"))\n  : null",
            serde_json::json!({
                "health": {
                    "exists": true,
                    "date_of_birth": "2017-06-15"
                },
                "as_of_date": "2026-01-01"
            }),
        ))
        .expect("production CEL worker evaluates the approved age band");
    assert_eq!(age_band, serde_json::json!("5-17"));

    let absent = runtime
        .block_on(worker.evaluate(
            "health.exists && health.date_of_birth != null\n  ? date.age_on(health.date_of_birth, as_of_date)\n  : null",
            serde_json::json!({
                "health": { "exists": false, "date_of_birth": null },
                "as_of_date": "2026-01-01"
            }),
        ))
        .expect("production CEL worker preserves a successful null result");
    assert_eq!(absent, serde_json::Value::Null);
}

#[test]
fn all_advertised_starters_initialize_and_test_without_source_access() {
    for starter in [
        ProjectStarter::Http,
        ProjectStarter::Spreadsheet,
        ProjectStarter::Dhis2Tracker,
        ProjectStarter::OpencrvsDci,
        ProjectStarter::FhirR4,
        ProjectStarter::Snapshot,
    ] {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = temporary.path().join("registry-project");
        let initialized = init_registry_project(&ProjectInitOptions {
            starter,
            directory: project.clone(),
        })
        .expect("starter initializes");
        assert_eq!(initialized.status, "initialized");
        let InitSource::Starter {
            id,
            release,
            content_state,
            ..
        } = initialized.source;
        assert!(!id.is_empty());
        assert_eq!(release, env!("CARGO_PKG_VERSION"));
        assert_eq!(content_state, "matches");
        assert_eq!(
            initialized.artifacts.editor_manifest,
            Some(project.join(".registry-stack-editor/manifest.json"))
        );
        for path in [
            ".registry-stack-editor/manifest.json",
            ".vscode/settings.json",
            ".vscode/extensions.json",
            ".zed/settings.json",
        ] {
            assert!(project.join(path).is_file(), "{starter:?} missing {path}");
        }
        let tested = test_registry_project(&ProjectTestOptions {
            project_directory: project,
            environment: None,
        })
        .expect("initialized starter passes offline tests");
        assert_eq!(tested.status, "passed");
    }
}

#[test]
fn spreadsheet_starter_builds_sensitive_projected_fields_without_emitting_project_file() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = temporary.path().join("spreadsheet-project");
    init_registry_project(&ProjectInitOptions {
        starter: ProjectStarter::Spreadsheet,
        directory: project.clone(),
    })
    .expect("spreadsheet starter initializes");

    let check = check_registry_project(&ProjectCheckOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        explain: false,
        against: None,
        anchor: None,
    })
    .expect("spreadsheet starter check executes");
    assert_eq!(check.status, "valid");
    let preflight = preflight_registry_project(&ProjectPreflightOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
    })
    .expect("spreadsheet starter preflight executes");
    assert_eq!(
        preflight.status,
        registryctl::PreflightStatus::NotReady,
        "authoring and deterministic build remain available without pretending missing local runtime inputs are ready"
    );
    assert!(
        !preflight.diagnostics.is_empty(),
        "offline preflight must explain the missing local runtime inputs"
    );
    let repeated_preflight = preflight_registry_project(&ProjectPreflightOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
    })
    .expect("spreadsheet starter preflight repeats");
    assert_eq!(
        serde_json::to_value(&preflight).expect("preflight serializes"),
        serde_json::to_value(&repeated_preflight).expect("repeated preflight serializes")
    );
    let build = build_registry_project(&ProjectBuildOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect("spreadsheet starter builds");
    let output = resolve_build_output(&project, build.output.expect("build output"));
    let relay = read_yaml(&output.join("private/relay-public/config/relay.yaml"));
    assert_eq!(relay["auth"]["mode"], "api_key");
    let api_keys = relay["auth"]["api_keys"]
        .as_sequence()
        .expect("local Relay API keys compile");
    assert_eq!(api_keys.len(), 2);
    for (principal, fingerprint_env) in [
        ("pw_001", "REGISTRYCTL_LOCAL_RELAY_MATCH_KEY_HASH"),
        (
            "registryctl_local_no_match",
            "REGISTRYCTL_LOCAL_RELAY_NO_MATCH_KEY_HASH",
        ),
    ] {
        let key = api_keys
            .iter()
            .find(|key| key["id"] == principal)
            .expect("synthetic principal compiles");
        assert_eq!(key["fingerprint"]["provider"], "env");
        assert_eq!(key["fingerprint"]["name"], fingerprint_env);
        assert_eq!(
            key["scopes"],
            serde_norway::from_str::<serde_norway::Value>("[projects:metadata, projects:rows]")
                .expect("expected scopes parse")
        );
    }
    let relay_text = std::fs::read_to_string(output.join("private/relay-public/config/relay.yaml"))
        .expect("Relay config reads");
    assert!(!relay_text.contains("_RAW"));
    assert!(!relay_text.contains("pw_001="));
    let table = &relay["datasets"][0]["tables"][0];
    assert_eq!(
        table["source"]["path"],
        "/var/lib/registry/public_works_projects.xlsx"
    );
    assert!(table["source"].get("project_file").is_none());
    assert!(table["schema"]["fields"]
        .as_sequence()
        .is_some_and(|fields| fields
            .iter()
            .all(|field| field["sensitive"].as_bool() == Some(true))));
    assert!(relay["datasets"][0]["entities"][0]["fields"]
        .as_sequence()
        .is_some_and(|fields| fields
            .iter()
            .all(|field| field["sensitive"].as_bool() == Some(true))));
    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(output.join("artifact-manifest.json"))
            .expect("spreadsheet artifact manifest reads"),
    )
    .expect("spreadsheet artifact manifest parses");
    let workbook_inputs = manifest["inputs"]
        .as_array()
        .expect("spreadsheet manifest inputs")
        .iter()
        .filter(|input| input["classification"] == "operator_owned_source_data")
        .collect::<Vec<_>>();
    assert_eq!(workbook_inputs.len(), 1);
    assert_eq!(
        workbook_inputs[0]["path"],
        "data/public_works_projects.xlsx"
    );
    assert_eq!(
        workbook_inputs[0]["digest"],
        test_sha256_uri(
            &std::fs::read(project.join("data/public_works_projects.xlsx"))
                .expect("spreadsheet source reads")
        )
    );
    assert!(manifest["inputs"]
        .as_array()
        .expect("spreadsheet manifest inputs")
        .iter()
        .filter(|input| input["path"] != "data/public_works_projects.xlsx")
        .all(|input| input["classification"] == "authored_project_input"));
    assert!(manifest["artifacts"]
        .as_array()
        .expect("spreadsheet generated artifacts")
        .iter()
        .all(|artifact| artifact["path"] != "data/public_works_projects.xlsx"));
    let first_relay_bytes = std::fs::read(output.join("private/relay-public/config/relay.yaml"))
        .expect("first Relay output reads");
    let repeated_build = build_registry_project(&ProjectBuildOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect("spreadsheet starter build repeats");
    let repeated_output = resolve_build_output(
        &project,
        repeated_build.output.expect("repeated build output"),
    );
    assert_eq!(
        first_relay_bytes,
        std::fs::read(repeated_output.join("private/relay-public/config/relay.yaml"))
            .expect("repeated Relay output reads")
    );
}

#[test]
fn spreadsheet_commands_reject_invalid_complete_workbooks_without_writing_or_replacing_output() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = temporary.path().join("spreadsheet-project");
    init_registry_project(&ProjectInitOptions {
        starter: ProjectStarter::Spreadsheet,
        directory: project.clone(),
    })
    .expect("spreadsheet starter initializes");
    let build_options = ProjectBuildOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        against: None,
        anchor: None,
    };
    let build = build_registry_project(&build_options).expect("valid workbook builds");
    let output = resolve_build_output(&project, build.output.expect("build output"));
    let valid_output = directory_closure(&output);
    let workbook = project.join("data/public_works_projects.xlsx");
    let relay_fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("../registry-relay/tests");

    for (fixture, expected_code) in [
        (
            "fixtures_xlsx/formula_outside_projection.xlsx",
            "ingest.source_unreadable",
        ),
        (
            "fixtures_xlsx/duplicate_primary_key_after_1000.xlsx",
            "ingest.schema_mismatch",
        ),
    ] {
        std::fs::copy(relay_fixtures.join(fixture), &workbook)
            .expect("invalid workbook fixture copies");
        let before_commands = directory_closure(&project);
        let check = check_registry_project(&ProjectCheckOptions {
            project_directory: project.clone(),
            environment: "local".to_string(),
            explain: false,
            against: None,
            anchor: None,
        })
        .expect_err("invalid workbook must fail check");
        assert_eq!(
            format!("{check:#}"),
            format!("workbook validation failed ({expected_code})")
        );
        assert_eq!(before_commands, directory_closure(&project));

        let preflight = preflight_registry_project(&ProjectPreflightOptions {
            project_directory: project.clone(),
            environment: "local".to_string(),
        })
        .expect_err("invalid workbook must fail preflight");
        assert_eq!(
            format!("{preflight:#}"),
            format!("workbook validation failed ({expected_code})")
        );
        assert_eq!(before_commands, directory_closure(&project));

        let build = build_registry_project(&build_options)
            .expect_err("invalid workbook must fail before build publication");
        assert_eq!(
            format!("{build:#}"),
            format!("workbook validation failed ({expected_code})")
        );
        assert_eq!(valid_output, directory_closure(&output));
    }

    std::fs::write(&workbook, b"not an XLSX workbook").expect("corrupt workbook writes");
    for error in [
        check_registry_project(&ProjectCheckOptions {
            project_directory: project.clone(),
            environment: "local".to_string(),
            explain: false,
            against: None,
            anchor: None,
        })
        .expect_err("corrupt workbook must fail check"),
        preflight_registry_project(&ProjectPreflightOptions {
            project_directory: project.clone(),
            environment: "local".to_string(),
        })
        .expect_err("corrupt workbook must fail preflight"),
        build_registry_project(&build_options).expect_err("corrupt workbook must fail build"),
    ] {
        assert_eq!(
            format!("{error:#}"),
            "workbook validation failed (ingest.source_unreadable)"
        );
    }
    assert_eq!(valid_output, directory_closure(&output));

    std::fs::remove_file(&workbook).expect("workbook removes");
    for error in [
        check_registry_project(&ProjectCheckOptions {
            project_directory: project.clone(),
            environment: "local".to_string(),
            explain: false,
            against: None,
            anchor: None,
        })
        .expect_err("missing workbook must fail check"),
        preflight_registry_project(&ProjectPreflightOptions {
            project_directory: project.clone(),
            environment: "local".to_string(),
        })
        .expect_err("missing workbook must fail preflight"),
        build_registry_project(&build_options).expect_err("missing workbook must fail build"),
    ] {
        assert_eq!(
            format!("{error:#}"),
            "workbook source input is missing or unreadable"
        );
    }
    assert_eq!(valid_output, directory_closure(&output));
}

#[test]
fn spreadsheet_commands_enforce_the_entity_materialization_record_limit() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = temporary.path().join("spreadsheet-project");
    init_registry_project(&ProjectInitOptions {
        starter: ProjectStarter::Spreadsheet,
        directory: project.clone(),
    })
    .expect("spreadsheet starter initializes");
    let entity_path = project.join("entities/projects.yaml");
    let entity = std::fs::read_to_string(&entity_path)
        .expect("entity reads")
        .replace("max_records: 10000", "max_records: 1");
    std::fs::write(&entity_path, entity).expect("entity writes");
    let build_options = ProjectBuildOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        against: None,
        anchor: None,
    };

    for error in [
        check_registry_project(&ProjectCheckOptions {
            project_directory: project.clone(),
            environment: "local".to_string(),
            explain: false,
            against: None,
            anchor: None,
        })
        .expect_err("check rejects a workbook above the authored record limit"),
        preflight_registry_project(&ProjectPreflightOptions {
            project_directory: project.clone(),
            environment: "local".to_string(),
        })
        .expect_err("preflight rejects a workbook above the authored record limit"),
        build_registry_project(&build_options)
            .expect_err("build rejects a workbook above the authored record limit"),
    ] {
        assert_eq!(
            format!("{error:#}"),
            "workbook validation failed (ingest.materialization_failed)"
        );
    }
    assert!(!project.join(".registry-stack/build").exists());
}

#[test]
fn spreadsheet_local_api_keys_are_rejected_outside_the_local_profile() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = temporary.path().join("spreadsheet-project");
    init_registry_project(&ProjectInitOptions {
        starter: ProjectStarter::Spreadsheet,
        directory: project.clone(),
    })
    .expect("spreadsheet starter initializes");
    let environment_path = project.join("environments/local.yaml");
    let environment = std::fs::read_to_string(&environment_path)
        .expect("environment reads")
        .replace("profile: local", "profile: hosted_lab");
    std::fs::write(&environment_path, environment).expect("environment writes");

    let error = check_registry_project(&ProjectCheckOptions {
        project_directory: project,
        environment: "local".to_string(),
        explain: false,
        against: None,
        anchor: None,
    })
    .expect_err("local API keys must not validate outside the local profile");
    assert_authoring_diagnostic(&error, "registryctl.authoring.environment.invalid");
}

#[cfg(unix)]
#[test]
fn spreadsheet_project_file_rejects_traversal_and_symlink_components() {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir().expect("temporary directory");
    let traversal = temporary.path().join("traversal");
    init_registry_project(&ProjectInitOptions {
        starter: ProjectStarter::Spreadsheet,
        directory: traversal.clone(),
    })
    .expect("spreadsheet starter initializes");
    let environment_path = traversal.join("environments/local.yaml");
    let authored = std::fs::read_to_string(&environment_path)
        .expect("spreadsheet environment reads")
        .replace(
            "project_file: data/public_works_projects.xlsx",
            "project_file: ../outside.xlsx",
        );
    std::fs::write(&environment_path, authored).expect("traversal environment writes");
    let error = check_registry_project(&ProjectCheckOptions {
        project_directory: traversal,
        environment: "local".to_string(),
        explain: false,
        against: None,
        anchor: None,
    })
    .expect_err("project_file traversal must fail closed");
    assert_authoring_diagnostic(&error, "registryctl.authoring.environment.invalid");

    let symlinked = temporary.path().join("symlinked");
    init_registry_project(&ProjectInitOptions {
        starter: ProjectStarter::Spreadsheet,
        directory: symlinked.clone(),
    })
    .expect("spreadsheet starter initializes");
    let external = temporary.path().join("external-data");
    std::fs::create_dir(&external).expect("external directory creates");
    std::fs::remove_dir_all(symlinked.join("data")).expect("starter data removes");
    symlink(&external, symlinked.join("data")).expect("data symlink creates");
    let error = check_registry_project(&ProjectCheckOptions {
        project_directory: symlinked,
        environment: "local".to_string(),
        explain: false,
        against: None,
        anchor: None,
    })
    .expect_err("project_file symlink component must fail closed");
    assert_authoring_diagnostic(&error, "registryctl.authoring.project.invalid");
}

#[test]
fn typed_target_attribute_executes_through_the_offline_notary_journey() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = temporary.path().join("typed-target-attribute");
    copy_tree(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("assets/project-starters/bounded-http"),
        &project,
    );

    let integration = project.join("integrations/person-record/integration.yaml");
    let integration_document = std::fs::read_to_string(&integration).expect("integration file");
    std::fs::write(
        &integration,
        integration_document.replace(
            "    type: string\n    maxLength: 64",
            "    type: integer\n    minimum: 0\n    maximum: 10",
        ),
    )
    .expect("typed integration writes");

    let fixture_directory = project.join("integrations/person-record/fixtures");
    for entry in std::fs::read_dir(&fixture_directory).expect("starter fixtures") {
        let path = entry.expect("fixture entry").path();
        let fixture = std::fs::read_to_string(&path).expect("fixture file");
        let fixture = fixture.replace(
            "    identifiers: [{ scheme: registry_person_id, value: AB-123456 }]",
            "    attributes: { person_sequence: 1 }",
        );
        std::fs::write(&path, fixture.replace("AB-123456", "1")).expect("typed fixture writes");
    }

    let project_file = project.join("registry-stack.yaml");
    let project_document = std::fs::read_to_string(&project_file).expect("project file");
    std::fs::write(
        &project_file,
        project_document.replace(
            "request.target.identifiers.registry_person_id",
            "request.target.attributes.person_sequence",
        ),
    )
    .expect("target attribute mapping writes");

    let report = test_registry_project(&ProjectTestOptions {
        project_directory: project,
        environment: None,
    })
    .expect("typed target attribute passes the offline journey");
    assert_eq!(report.status, "passed");
    assert!(report.fixtures.iter().all(|fixture| fixture.passed));
}

#[test]
fn malformed_target_attribute_mapping_preserves_typed_authoring_diagnostics() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("dhis2-tracker", temporary.path());
    replace_in_file(
        &project.join("registry-stack.yaml"),
        "request.target.attributes.include_inactive",
        "request.target.attributes.IncludeInactive",
    );

    let report = authoring_diagnostics(&project);
    assert_eq!(report.status, "invalid");
    assert_eq!(report.diagnostics.len(), 1, "{report:#?}");
    assert_eq!(
        report.diagnostics[0].code,
        "registryctl.authoring.project.invalid"
    );
    assert_eq!(report.diagnostics[0].file, "registry-stack.yaml");
    assert_eq!(
        report.diagnostics[0].schema_hint,
        Some("registryctl authoring schema --kind project > project.schema.json")
    );
}

#[test]
fn editor_setup_writes_exact_local_schema_mappings_and_manifest() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = temporary.path().join("editor-project");
    std::fs::create_dir(&project).expect("project directory creates");
    std::fs::write(project.join("registry-stack.yaml"), b"[not: valid: yaml")
        .expect("invalid authored YAML marker writes");

    let report = setup_registry_project_editor(&ProjectEditorSetupOptions {
        project_directory: project.clone(),
    })
    .expect("editor setup does not require valid authored YAML");
    assert_eq!(report.status, "configured");
    assert_eq!(report.files.len(), 9);

    let expected_mappings = ProjectSchemaKind::ALL
        .into_iter()
        .map(|kind| {
            (
                format!("./.registry-stack-editor/schemas/{}", kind.filename()),
                kind.file_glob().to_string(),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let vscode: serde_json::Value = serde_json::from_slice(
        &std::fs::read(project.join(".vscode/settings.json")).expect("VS Code settings read"),
    )
    .expect("VS Code settings are JSON");
    let zed: serde_json::Value = serde_json::from_slice(
        &std::fs::read(project.join(".zed/settings.json")).expect("Zed settings read"),
    )
    .expect("Zed settings are JSON");
    let expected_mappings = serde_json::to_value(&expected_mappings).expect("mappings serialize");
    assert_eq!(vscode["yaml.schemas"], expected_mappings);
    assert_eq!(
        zed.pointer("/lsp/yaml-language-server/settings/yaml/schemas")
            .expect("Zed YAML schema settings use the required nested shape"),
        &expected_mappings
    );
    assert_eq!(
        vscode.as_object().expect("VS Code settings object").len(),
        1,
        "SchemaStore and formatter settings must remain untouched"
    );

    let extensions: serde_json::Value = serde_json::from_slice(
        &std::fs::read(project.join(".vscode/extensions.json")).expect("extensions read"),
    )
    .expect("extensions are JSON");
    assert_eq!(
        extensions,
        serde_json::json!({ "recommendations": ["redhat.vscode-yaml"] })
    );

    let schema_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("schemas/project-authoring");
    for kind in ProjectSchemaKind::ALL {
        let generated = std::fs::read(
            project
                .join(".registry-stack-editor/schemas")
                .join(kind.filename()),
        )
        .expect("generated schema reads");
        assert_eq!(generated, kind.document().as_bytes(), "{kind:?}");
        assert_eq!(
            generated,
            std::fs::read(schema_root.join(kind.filename())).expect("source schema reads"),
            "{kind:?} must use the exact release schema bytes"
        );
    }

    let manifest: serde_json::Value = serde_json::from_slice(
        &std::fs::read(project.join(".registry-stack-editor/manifest.json"))
            .expect("manifest reads"),
    )
    .expect("manifest is JSON");
    assert_eq!(
        manifest["format"], "registry.stack.editor-manifest",
        "manifest format is a stable refresh boundary"
    );
    assert_eq!(manifest["version"], 1);
    assert_eq!(manifest["registryctl_version"], env!("CARGO_PKG_VERSION"));
    let schemas = manifest["schemas"].as_array().expect("manifest schemas");
    assert_eq!(schemas.len(), ProjectSchemaKind::ALL.len());
    for kind in ProjectSchemaKind::ALL {
        let relative = format!("schemas/{}", kind.filename());
        let schema = schemas
            .iter()
            .find(|schema| schema["path"] == relative)
            .expect("schema has one manifest entry");
        assert_eq!(schema["file_glob"], kind.file_glob());
        assert_eq!(
            schema["sha256"],
            format!(
                "sha256:{}",
                hex::encode(Sha256::digest(kind.document().as_bytes()))
            )
        );
    }

    for settings_path in [
        ".registry-stack-editor/manifest.json",
        ".vscode/settings.json",
        ".vscode/extensions.json",
        ".zed/settings.json",
    ] {
        let contents =
            std::fs::read_to_string(project.join(settings_path)).expect("generated JSON reads");
        assert!(!contents.contains(&project.display().to_string()));
        assert!(!contents.contains("$HOME"));
        assert!(!contents.contains("secret"));
        assert!(!contents.contains("\"tasks\""));
        assert!(!contents.contains("\"command\""));
    }
}

#[test]
fn editor_setup_refreshes_a_verified_prior_schema_bundle() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = temporary.path().join("editor-project");
    std::fs::create_dir(&project).expect("project directory creates");
    std::fs::write(project.join("registry-stack.yaml"), b"invalid-yaml: [")
        .expect("project marker writes");
    let options = ProjectEditorSetupOptions {
        project_directory: project.clone(),
    };
    setup_registry_project_editor(&options).expect("initial editor setup passes");

    let schema_path = project.join(".registry-stack-editor/schemas/project.schema.json");
    let mut prior_schema = std::fs::read(&schema_path).expect("schema reads");
    prior_schema.extend_from_slice(b"\n");
    std::fs::write(&schema_path, &prior_schema).expect("prior schema writes");
    let manifest_path = project.join(".registry-stack-editor/manifest.json");
    let mut prior_manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).expect("manifest reads"))
            .expect("manifest parses");
    prior_manifest["registryctl_version"] = serde_json::json!("0.9.0");
    let schema = prior_manifest["schemas"]
        .as_array_mut()
        .expect("manifest schemas")
        .iter_mut()
        .find(|schema| schema["path"] == "schemas/project.schema.json")
        .expect("project schema manifest entry");
    schema["sha256"] = serde_json::json!(format!(
        "sha256:{}",
        hex::encode(Sha256::digest(&prior_schema))
    ));
    let mut prior_manifest_bytes =
        serde_json::to_vec_pretty(&prior_manifest).expect("prior manifest serializes");
    prior_manifest_bytes.push(b'\n');
    std::fs::write(&manifest_path, prior_manifest_bytes).expect("prior manifest writes");

    setup_registry_project_editor(&options).expect("verified prior bundle refreshes");
    assert_eq!(
        std::fs::read(&schema_path).expect("refreshed schema reads"),
        ProjectSchemaKind::Project.document().as_bytes()
    );
    let refreshed: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).expect("refreshed manifest reads"))
            .expect("refreshed manifest parses");
    assert_eq!(refreshed["registryctl_version"], env!("CARGO_PKG_VERSION"));
    assert_eq!(
        refreshed["schemas"]
            .as_array()
            .expect("refreshed schemas")
            .iter()
            .find(|schema| schema["path"] == "schemas/project.schema.json")
            .expect("refreshed project schema")["sha256"],
        format!(
            "sha256:{}",
            hex::encode(Sha256::digest(
                ProjectSchemaKind::Project.document().as_bytes()
            ))
        )
    );
}

#[test]
fn editor_setup_refuses_tampered_schema_or_manifest_evidence() {
    let temporary = tempfile::tempdir().expect("temporary directory");

    let tampered_schema_project = temporary.path().join("tampered-schema");
    std::fs::create_dir(&tampered_schema_project).expect("project directory creates");
    std::fs::write(
        tampered_schema_project.join("registry-stack.yaml"),
        b"invalid-yaml: [",
    )
    .expect("project marker writes");
    let schema_options = ProjectEditorSetupOptions {
        project_directory: tampered_schema_project.clone(),
    };
    let schema_report =
        setup_registry_project_editor(&schema_options).expect("initial editor setup passes");
    let schema_path =
        tampered_schema_project.join(".registry-stack-editor/schemas/project.schema.json");
    let mut tampered_schema = std::fs::read(&schema_path).expect("schema reads");
    tampered_schema.extend_from_slice(b"tampered");
    std::fs::write(&schema_path, &tampered_schema).expect("tampered schema writes");
    let before_schema_failure = schema_report
        .files
        .iter()
        .map(|path| {
            (
                path.clone(),
                std::fs::read(tampered_schema_project.join(path)).expect("managed file reads"),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let error = setup_registry_project_editor(&schema_options)
        .expect_err("schema changed without its manifest must be preserved");
    assert!(
        format!("{error:#}").contains("project.schema.json"),
        "{error:#}"
    );
    for (path, expected) in before_schema_failure {
        assert_eq!(
            std::fs::read(tampered_schema_project.join(path)).expect("managed file still reads"),
            expected
        );
    }

    let tampered_manifest_project = temporary.path().join("tampered-manifest");
    std::fs::create_dir(&tampered_manifest_project).expect("project directory creates");
    std::fs::write(
        tampered_manifest_project.join("registry-stack.yaml"),
        b"invalid-yaml: [",
    )
    .expect("project marker writes");
    let manifest_options = ProjectEditorSetupOptions {
        project_directory: tampered_manifest_project.clone(),
    };
    setup_registry_project_editor(&manifest_options).expect("initial editor setup passes");
    let manifest_path = tampered_manifest_project.join(".registry-stack-editor/manifest.json");
    let mut tampered_manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest_path).expect("manifest reads"))
            .expect("manifest parses");
    tampered_manifest["registryctl_version"] = serde_json::json!("0.9.0");
    tampered_manifest["schemas"][0]["sha256"] =
        serde_json::json!(format!("sha256:{}", "0".repeat(64)));
    let mut tampered_manifest_bytes =
        serde_json::to_vec_pretty(&tampered_manifest).expect("tampered manifest serializes");
    tampered_manifest_bytes.push(b'\n');
    std::fs::write(&manifest_path, &tampered_manifest_bytes).expect("tampered manifest writes");
    let project_schema_before = std::fs::read(
        tampered_manifest_project.join(".registry-stack-editor/schemas/project.schema.json"),
    )
    .expect("project schema reads");
    let error = setup_registry_project_editor(&manifest_options)
        .expect_err("manifest hash without matching schema must be preserved");
    assert!(format!("{error:#}").contains("manifest hash"), "{error:#}");
    assert_eq!(
        std::fs::read(&manifest_path).expect("tampered manifest still reads"),
        tampered_manifest_bytes
    );
    assert_eq!(
        std::fs::read(
            tampered_manifest_project.join(".registry-stack-editor/schemas/project.schema.json")
        )
        .expect("project schema still reads"),
        project_schema_before
    );
}

#[test]
fn editor_setup_is_byte_identical_on_explicit_rerun() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = temporary.path().join("editor-project");
    std::fs::create_dir(&project).expect("project directory creates");
    std::fs::write(
        project.join("registry-stack.yaml"),
        b"invalid-yaml-is-accepted: [",
    )
    .expect("project marker writes");
    let options = ProjectEditorSetupOptions {
        project_directory: project.clone(),
    };
    let first = setup_registry_project_editor(&options).expect("initial editor setup passes");
    let before = first
        .files
        .iter()
        .map(|path| {
            (
                path.clone(),
                std::fs::read(project.join(path)).expect("generated file reads"),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();

    let second = setup_registry_project_editor(&options).expect("identical rerun passes");
    assert_eq!(second.files, first.files);
    for (path, expected) in before {
        assert_eq!(
            std::fs::read(project.join(&path)).expect("rerun output reads"),
            expected,
            "{path} changed on rerun"
        );
    }
}

#[test]
fn editor_setup_conflicts_are_preflighted_without_partial_writes() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = temporary.path().join("editor-project");
    std::fs::create_dir_all(project.join(".vscode")).expect("VS Code directory creates");
    std::fs::create_dir_all(project.join(".zed")).expect("Zed directory creates");
    std::fs::write(project.join("registry-stack.yaml"), b"not-valid-yaml: [")
        .expect("project marker writes");
    let vscode = b"{\n  \"editor.formatOnSave\": true\n}\n";
    let zed = b"{\n  \"format_on_save\": \"on\"\n}\n";
    std::fs::write(project.join(".vscode/settings.json"), vscode)
        .expect("conflicting VS Code settings write");
    std::fs::write(project.join(".zed/settings.json"), zed)
        .expect("conflicting Zed settings write");

    let error = setup_registry_project_editor(&ProjectEditorSetupOptions {
        project_directory: project.clone(),
    })
    .expect_err("nonmatching settings must require a manual merge");
    let diagnostic = error.to_string();
    assert!(diagnostic.contains(".vscode/settings.json"), "{diagnostic}");
    assert!(diagnostic.contains(".zed/settings.json"), "{diagnostic}");
    assert!(diagnostic.contains("manually"), "{diagnostic}");
    assert_eq!(
        std::fs::read(project.join(".vscode/settings.json")).expect("VS Code settings preserved"),
        vscode
    );
    assert_eq!(
        std::fs::read(project.join(".zed/settings.json")).expect("Zed settings preserved"),
        zed
    );
    assert!(!project.join(".registry-stack-editor").exists());
    assert!(!project.join(".vscode/extensions.json").exists());
}

#[cfg(unix)]
#[test]
fn editor_setup_rejects_symlinked_output_ancestors_without_writes() {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = temporary.path().join("editor-project");
    let outside = temporary.path().join("outside");
    std::fs::create_dir(&project).expect("project directory creates");
    std::fs::create_dir(&outside).expect("outside directory creates");
    std::fs::write(project.join("registry-stack.yaml"), b"not-valid-yaml: [")
        .expect("project marker writes");
    symlink(&outside, project.join(".zed")).expect("Zed ancestor symlink creates");

    let error = setup_registry_project_editor(&ProjectEditorSetupOptions {
        project_directory: project.clone(),
    })
    .expect_err("symlinked output ancestor must fail closed");
    let diagnostic = error.to_string();
    assert!(diagnostic.contains("symlink"), "{diagnostic}");
    assert!(diagnostic.contains(".zed"), "{diagnostic}");
    assert!(!project.join(".registry-stack-editor").exists());
    assert!(!project.join(".vscode").exists());
    assert!(
        std::fs::read_dir(outside)
            .expect("outside directory reads")
            .next()
            .is_none(),
        "symlink destination must remain untouched"
    );
}

#[test]
fn check_explain_reports_adapted_identity_and_effective_http_contract() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = temporary.path().join("registry-project");
    init_registry_project(&ProjectInitOptions {
        starter: ProjectStarter::Http,
        directory: project.clone(),
    })
    .expect("starter initializes");

    let project_file = project.join("registry-stack.yaml");
    let authored = std::fs::read_to_string(&project_file).expect("project file");
    std::fs::write(
        &project_file,
        authored.replace("fictional-citizen-registry", "adapted-citizen-registry"),
    )
    .expect("project identity is adapted");

    let checked = check_registry_project(&ProjectCheckOptions {
        project_directory: project,
        environment: "local".to_string(),
        explain: true,
        against: None,
        anchor: None,
    })
    .expect("adapted starter remains valid");
    let explanation = checked.explanation.expect("explanation");
    assert_eq!(explanation.project, "adapted-citizen-registry");
    assert_eq!(
        public_explanation_value(integration_explanation_field(
            &explanation,
            "person-record",
            "/capability/type",
        )),
        &serde_json::json!("http")
    );
    let request_bytes =
        integration_explanation_field(&explanation, "person-record", "/limits/request_bytes");
    assert!(request_bytes
        .default
        .as_ref()
        .is_some_and(|default| default.applied));
    assert!(matches!(
        project_explanation_field(&explanation, "/registry/id").reported_value,
        ClassifierSafeReportedValue::Redacted { .. }
    ));
}

#[test]
fn check_explain_reports_environment_binding_without_origin_value() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = temporary.path().join("registry-project");
    init_registry_project(&ProjectInitOptions {
        starter: ProjectStarter::Http,
        directory: project.clone(),
    })
    .expect("starter initializes");

    let environment_file = project.join("environments/local.yaml");
    let environment = std::fs::read_to_string(&environment_file).expect("environment file");
    std::fs::write(
        &environment_file,
        environment.replace(
            "https://citizen-registry.invalid",
            "https://adapted-citizen-registry.invalid",
        ),
    )
    .expect("source origin is adapted");

    let checked = check_registry_project(&ProjectCheckOptions {
        project_directory: project,
        environment: "local".to_string(),
        explain: true,
        against: None,
        anchor: None,
    })
    .expect("adapted environment remains valid");
    let explanation = checked.explanation.expect("explanation");
    assert_eq!(explanation.environment, "local");
    assert!(matches!(
        environment_explanation_field(
            &explanation,
            "local",
            "/integrations/person-record/source/origin",
        )
        .reported_value,
        ClassifierSafeReportedValue::Redacted { .. }
    ));
    let serialized = serde_json::to_string(&explanation).expect("explanation serializes");
    assert!(!serialized.contains("adapted-citizen-registry.invalid"));
}

#[test]
fn offline_preflight_reports_missing_local_requirements_without_leaking_references() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = temporary.path().join("registry-project");
    init_registry_project(&ProjectInitOptions {
        starter: ProjectStarter::Http,
        directory: project.clone(),
    })
    .expect("starter initializes");

    let report = preflight_registry_project(&ProjectPreflightOptions {
        project_directory: project,
        environment: "local".to_owned(),
    })
    .expect("offline preflight produces a bounded report");
    assert_eq!(report.status, registryctl::PreflightStatus::NotReady);
    assert_eq!(report.static_checks.len(), 4);
    assert_eq!(report.product_validators.len(), 2);
    assert!(!report.secret_checks.is_empty());
    assert!(!report.runtime_files.is_empty());
    assert_eq!(
        report.execution,
        registryctl::PreflightExecutionBoundary::default()
    );

    let serialized = serde_json::to_string(&report).expect("preflight report serializes");
    for forbidden in [
        "FICTIONAL_REGISTRY_TOKEN",
        "REGISTRY_NOTARY_ISSUER_JWK",
        "EVIDENCE_CLIENT_TOKEN_HASH",
        "/run/secrets/relay-workload-token",
        "citizen-registry.invalid",
        "fictional-registry-notary",
    ] {
        assert!(
            !serialized.contains(forbidden),
            "preflight report must not contain {forbidden}"
        );
    }
}

#[test]
fn capability_inventory_separates_static_support_from_runtime_and_image_evidence() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = temporary.path().join("registry-project");
    init_registry_project(&ProjectInitOptions {
        starter: ProjectStarter::Http,
        directory: project.clone(),
    })
    .expect("starter initializes");

    let report = inspect_project_capabilities(&ProjectCapabilityOptions {
        project_directory: project,
        environment: "local".to_owned(),
    })
    .expect("capability inventory builds from validated local facts");
    let http = report
        .capabilities
        .iter()
        .find(|record| record.capability == registryctl::CapabilityId::SourceHttp)
        .expect("HTTP capability is inventoried");
    assert_eq!(
        http.project_declaration,
        registryctl::ProjectDeclarationState::Declared
    );
    assert_eq!(
        http.environment_enablement,
        registryctl::EnvironmentEnablementState::Enabled
    );
    assert_eq!(http.disposition, registryctl::CapabilityDisposition::Used);
    let script = report
        .capabilities
        .iter()
        .find(|record| record.capability == registryctl::CapabilityId::SourceScript)
        .expect("script capability is inventoried");
    assert_eq!(
        script.installed_evidence,
        registryctl::InstalledCapabilityEvidence::EmbeddedCompiler
    );
    assert_eq!(
        report.runtime_activation,
        registryctl::RuntimeActivationEvaluation::NotEvaluated
    );
    for image in [
        registryctl::SupportComponent::RegistryRelayImage,
        registryctl::SupportComponent::RegistryNotaryImage,
    ] {
        let support = report
            .support
            .iter()
            .find(|entry| entry.component == image)
            .expect("image support is represented");
        assert_eq!(support.state, registryctl::SupportState::NotEvaluated);
        assert_eq!(support.evidence, registryctl::SupportEvidence::NoEvidence);
    }

    let report_value = serde_json::to_value(&report).expect("capability report serializes");
    let schema = serde_json::from_str(include_str!(
        "../schemas/project-reports/registry.project.capability_inventory.v1.schema.json"
    ))
    .expect("capability schema parses");
    let validator = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .expect("capability schema compiles");
    if let Err(errors) = validator.validate(&report_value) {
        let details = errors.map(|error| error.to_string()).collect::<Vec<_>>();
        panic!("real command report should validate: {details:?}");
    }
    let decoded: registryctl::ProjectCapabilityInventoryReportV1 =
        serde_json::from_value(report_value).expect("real command report passes strict ingress");
    assert_eq!(decoded, report);
}

#[test]
fn http_trace_marks_the_redacted_dynamic_path_segment() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = temporary.path().join("registry-project");
    init_registry_project(&ProjectInitOptions {
        starter: ProjectStarter::Http,
        directory: project.clone(),
    })
    .expect("starter initializes");

    let report = test_registry_project_selected(
        &ProjectTestOptions {
            project_directory: project,
            environment: None,
        },
        &ProjectTestSelection {
            integration: Some("person-record".to_string()),
            fixture: Some("active-person".to_string()),
            trace: true,
        },
    )
    .expect("focused trace passes");
    let fixture = report
        .fixtures
        .iter()
        .find(|fixture| fixture.fixture == "active-person")
        .expect("authored fixture report");
    assert_eq!(fixture.calls.len(), 1);
    assert!(fixture.calls[0].contains("path=/people/*"));
    assert!(!fixture.calls[0].contains("AB-123456"));
}

#[test]
fn focused_test_selector_errors_name_the_selection_and_available_ids() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = temporary.path().join("registry-project");
    init_registry_project(&ProjectInitOptions {
        starter: ProjectStarter::Http,
        directory: project.clone(),
    })
    .expect("starter initializes");
    let options = ProjectTestOptions {
        project_directory: project,
        environment: None,
    };

    let integration_error = test_registry_project_selected(
        &options,
        &ProjectTestSelection {
            integration: Some("missing-source".to_string()),
            fixture: None,
            trace: false,
        },
    )
    .expect_err("an absent integration fails");
    let integration_message = format!("{integration_error:#}");
    assert!(integration_message.contains("selected integration missing-source does not exist"));
    assert!(integration_message.contains("available integration ids: person-record"));

    let fixture_error = test_registry_project_selected(
        &options,
        &ProjectTestSelection {
            integration: Some("person-record".to_string()),
            fixture: Some("missing-case".to_string()),
            trace: false,
        },
    )
    .expect_err("an absent fixture fails");
    let fixture_message = format!("{fixture_error:#}");
    assert!(fixture_message.contains("selected fixture person-record.missing-case does not exist"));
    for available in [
        "person-record.active-person",
        "person-record.ambiguous-person",
        "person-record.no-person",
    ] {
        assert!(
            fixture_message.contains(available),
            "{available} is missing from {fixture_message}"
        );
    }
}

#[test]
fn http_starter_adapts_to_a_structurally_different_source_api() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = temporary.path().join("adapted-registry-api");
    copy_tree(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("assets/project-starters/bounded-http"),
        &project,
    );
    let integration = project.join("integrations/person-record/integration.yaml");
    std::fs::write(
        &integration,
        r#"version: 1
id: fictional-municipal-person-record
revision: 1
source:
  product: unanticipated-municipal-api
  versions: { unverified: [municipal-contract-v3] }
  auth: { type: static_bearer }
input:
  municipal_reference:
    role: selector
    type: string
    maxLength: 9
    pattern: "^[A-Z]{2}-[0-9]{6}$"
capability:
  http:
    request:
      method: GET
      path: /municipal/registry/lookup
      query:
        reference: { input: municipal_reference }
        include: status,category
    response:
      no_match: [404]
      ambiguous: [409]
outputs:
  status: { type: [string, "null"], maxLength: 24, x-registry-source: /record/status }
  category: { type: [string, "null"], maxLength: 32, x-registry-source: /record/category }
not_applicable:
  subject_mismatch:
    rationale: The selected response projection contains no identifier comparable with the requested municipal reference.
    request_fixture: adapted-active-person
"#,
    )
    .expect("adapted integration writes");
    let fixture_directory = project.join("integrations/person-record/fixtures");
    for entry in std::fs::read_dir(&fixture_directory).expect("starter fixtures") {
        let path = entry.expect("fixture entry").path();
        if path.file_name().and_then(|name| name.to_str()) != Some("active.yaml") {
            std::fs::remove_file(path).expect("unused fixture removes");
        }
    }
    std::fs::write(
        fixture_directory.join("active.yaml"),
        r#"name: adapted-active-person
classification: synthetic
input: { municipal_reference: AB-123456 }
interactions:
  - expect:
      method: GET
      path: /municipal/registry/lookup
      query: { reference: AB-123456, include: "status,category" }
    respond:
      status: 200
      body: { record: { status: ACTIVE, category: RESIDENT, ignored_additive_field: safe } }
expect:
  outcome: match
  outputs: { status: ACTIVE, category: RESIDENT }
  claims: { person-record-exists: true, person-status: ACTIVE }
"#,
    )
    .expect("adapted fixture writes");
    std::fs::write(
        fixture_directory.join("ambiguous.yaml"),
        r#"name: adapted-ambiguous-person
classification: synthetic
input: { municipal_reference: AB-123456 }
interactions:
  - expect:
      method: GET
      path: /municipal/registry/lookup
      query: { reference: AB-123456, include: "status,category" }
    respond: { status: 409, body: {} }
expect: { outcome: ambiguous, outputs: {}, claims: {} }
"#,
    )
    .expect("adapted ambiguity fixture writes");
    let project_file = project.join("registry-stack.yaml");
    let mut project_document = read_yaml(&project_file);
    let service = &mut project_document["services"]["person-verification"];
    service["purpose"] = serde_norway::Value::String("municipal-benefit-screening".to_string());
    service["consultations"]["person_record"]["input"] = serde_norway::from_str(
        "municipal_reference: request.target.identifiers.registry_person_id\n",
    )
    .expect("adapted consultation input");
    service["claims"]
        .as_mapping_mut()
        .expect("starter claims")
        .remove(serde_norway::Value::String("person-active".to_string()));
    service["claims"]
        .as_mapping_mut()
        .expect("starter claims")
        .insert(
            serde_norway::Value::String("person-status".to_string()),
            serde_norway::from_str("output: person_record.status\ndisclosure: value\n")
                .expect("adapted status claim"),
        );
    service["credential_profiles"]["person-status"]["claims"]
        .as_sequence_mut()
        .expect("starter credential claims")
        .iter_mut()
        .for_each(|claim| {
            if claim.as_str() == Some("person-active") {
                *claim = serde_norway::Value::String("person-status".to_string());
            }
        });
    write_yaml(&project_file, &project_document);

    let report = check_registry_project(&ProjectCheckOptions {
        project_directory: project,
        environment: "local".to_string(),
        explain: false,
        against: None,
        anchor: None,
    })
    .expect("structurally adapted starter compiles and executes");
    assert!(report
        .semantic_changes
        .iter()
        .any(|change| change.dimension == "integration"));
    assert!(report
        .semantic_changes
        .iter()
        .any(|change| change.dimension == "service_policy"));
}

#[test]
fn source_product_is_metadata_not_runtime_dispatch() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    for (name, integration, product) in [
        (
            "fhir-r4-coverage-active",
            "integrations/coverage/integration.yaml",
            "project-fhir-server",
        ),
        (
            "opencrvs",
            "integrations/birth-record/integration.yaml",
            "opencrvs",
        ),
    ] {
        let case_root = temporary.path().join(format!("case-{name}"));
        std::fs::create_dir(&case_root).expect("case root creates");
        let case = copy_project(name, &case_root);
        replace_in_file(
            &case.join(integration),
            &format!("product: {product}"),
            "product: previously-unknown-source-system",
        );
        let report = test_registry_project(&ProjectTestOptions {
            project_directory: case,
            environment: None,
        })
        .unwrap_or_else(|error| panic!("{name} selected behavior by product id: {error:#}"));
        assert_eq!(report.status, "passed", "{name}");
    }

    let project = copy_project("custom-system", temporary.path());
    replace_in_file(
        &project.join("integrations/eligibility/integration.yaml"),
        "product: aurora-household-service",
        "product: previously-unknown-source-system",
    );
    replace_in_file(
        &project.join("integrations/eligibility/integration.yaml"),
        "unverified: [fixture-contract-v2]",
        "unverified: [project-contract-99]",
    );
    let offline = test_registry_project(&ProjectTestOptions {
        project_directory: project.clone(),
        environment: None,
    })
    .expect("unknown product uses the generic bounded HTTP executor");
    assert_eq!(offline.status, "passed");

    let check = check_registry_project(&ProjectCheckOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        explain: true,
        against: None,
        anchor: None,
    })
    .expect("unknown product compiles through the generic authoring contract");
    assert_eq!(check.status, "valid");

    let build = build_registry_project(&ProjectBuildOptions {
        project_directory: project,
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect("unknown product builds generic Relay and Notary inputs");
    assert_eq!(build.status, "built");

    let metadata_free_root = tempfile::tempdir().expect("metadata-free temporary directory");
    let metadata_free = copy_project("custom-system", metadata_free_root.path());
    let integration_path = metadata_free.join("integrations/eligibility/integration.yaml");
    let mut integration = read_yaml(&integration_path);
    let source = integration["source"]
        .as_mapping_mut()
        .expect("authored source mapping");
    source.remove(serde_norway::Value::String("product".to_string()));
    source.remove(serde_norway::Value::String("versions".to_string()));
    write_yaml(&integration_path, &integration);
    let report = test_registry_project(&ProjectTestOptions {
        project_directory: metadata_free,
        environment: None,
    })
    .expect("product and version metadata are optional for generic HTTP");
    assert_eq!(report.status, "passed");
}

#[test]
fn code_owned_rhai_conformance_uses_the_injected_worker_and_is_deterministic() {
    let options = |project_directory| ProjectTestOptions {
        project_directory,
        environment: None,
    };
    let bounded = test_registry_project(&options(golden("dhis2-tracker")))
        .expect("bounded DHIS2 conformance passes")
        .fixtures;
    let rhai_project = golden("dhis2-script");
    let rhai = test_registry_project(&options(rhai_project.clone()))
        .expect("Rhai DHIS2 conformance passes")
        .fixtures;
    let repeated = test_registry_project(&options(rhai_project.clone()))
        .expect("repeated Rhai DHIS2 conformance passes")
        .fixtures;

    let temporary = tempfile::tempdir().expect("temporary directory");
    let unknown_product = copy_project("dhis2-script", temporary.path());
    replace_in_file(
        &unknown_product.join("integrations/health-record/integration.yaml"),
        "product: dhis2",
        "product: previously-unknown-source-system",
    );
    let unknown_product_report = test_registry_project(&options(unknown_product))
        .expect("unknown product uses the same Rhai authoring contract")
        .fixtures;
    assert_eq!(
        serde_json::to_value(&unknown_product_report).expect("unknown-product report serializes"),
        serde_json::to_value(&rhai).expect("Rhai report serializes"),
        "source.product may alter provenance but not Rhai fixture behavior"
    );
    assert_eq!(
        serde_json::to_value(&rhai).expect("first Rhai report serializes"),
        serde_json::to_value(&repeated).expect("repeated Rhai report serializes"),
        "fresh one-shot workers must produce deterministic fixture reports"
    );

    let rhai_by_name = rhai
        .iter()
        .map(|fixture| (fixture.fixture.as_str(), fixture))
        .collect::<std::collections::BTreeMap<_, _>>();
    for expected in &bounded {
        let actual = rhai_by_name
            .get(expected.fixture.as_str())
            .unwrap_or_else(|| panic!("Rhai omitted fixture {}", expected.fixture));
        assert_eq!(
            actual.inputs, expected.inputs,
            "{} inputs",
            expected.fixture
        );
        assert_eq!(actual.calls, expected.calls, "{} calls", expected.fixture);
        assert_eq!(
            actual.outputs, expected.outputs,
            "{} outputs",
            expected.fixture
        );
        assert_eq!(
            actual.claims, expected.claims,
            "{} claims",
            expected.fixture
        );
        assert_eq!(
            actual.outcome, expected.outcome,
            "{} outcome",
            expected.fixture
        );
        assert_eq!(
            actual.passed, expected.passed,
            "{} result",
            expected.fixture
        );
    }

    let traced = test_registry_project_selected(
        &options(rhai_project),
        &ProjectTestSelection {
            integration: Some("health-record".to_string()),
            fixture: Some("complete-child-health-evidence".to_string()),
            trace: true,
        },
    )
    .expect("focused Rhai trace passes");
    let calls = &traced.fixtures[0].calls;
    assert_eq!(
        calls,
        &["call=1 operation=script-source-call method=GET path=/api/tracker/trackedEntities/* query=[fields,includeDeleted] headers=[] body=none"]
    );
    for sensitive in ["A0000000001", "Nia", "REF-0001"] {
        assert!(!calls[0].contains(sensitive));
    }
    let serialized = serde_json::to_string(&traced).expect("trace report serializes");
    assert!(
        !serialized.contains(env!("CARGO_BIN_EXE_registryctl")),
        "the injected worker path must not enter project reports"
    );
}

#[test]
fn project_integrations_share_one_logical_source_without_conflating_protocol_helpers() {
    let shared_root = tempfile::tempdir().expect("shared-source temporary directory");
    let shared = copy_project("custom-system", shared_root.path());
    duplicate_project_integration(&shared, "eligibility", "secondary");
    check_registry_project(&ProjectCheckOptions {
        project_directory: shared,
        environment: "local".to_string(),
        explain: false,
        against: None,
        anchor: None,
    })
    .expect("two integrations over the same source pass");

    let product_root = tempfile::tempdir().expect("independent-product temporary directory");
    let independent_product = copy_project("custom-system", product_root.path());
    duplicate_project_integration(&independent_product, "eligibility", "secondary");
    replace_in_file(
        &independent_product.join("integrations/secondary/integration.yaml"),
        "product: aurora-household-service",
        "product: unrelated-registry",
    );
    check_registry_project(&ProjectCheckOptions {
        project_directory: independent_product,
        environment: "local".to_string(),
        explain: false,
        against: None,
        anchor: None,
    })
    .expect("product evidence never defines or dispatches the project source");

    let origin_root = tempfile::tempdir().expect("independent-origin temporary directory");
    let independent_origin = copy_project("custom-system", origin_root.path());
    duplicate_project_integration(&independent_origin, "eligibility", "secondary");
    let environment_path = independent_origin.join("environments/local.yaml");
    let mut environment = read_yaml(&environment_path);
    environment["integrations"]["secondary"]["source"]["origin"] =
        serde_norway::Value::String("https://unrelated-registry.invalid".to_string());
    write_yaml(&environment_path, &environment);
    let error = check_registry_project(&ProjectCheckOptions {
        project_directory: independent_origin,
        environment: "local".to_string(),
        explain: false,
        against: None,
        anchor: None,
    })
    .expect_err("two source data origins in one project fail closed");
    assert_authoring_diagnostic(&error, "registryctl.authoring.environment.invalid");

    let helper_root = tempfile::tempdir().expect("protocol-helper temporary directory");
    let protocol_helper = copy_project("opencrvs", helper_root.path());
    duplicate_project_integration(&protocol_helper, "birth-record", "secondary");
    let environment_path = protocol_helper.join("environments/local.yaml");
    let mut environment = read_yaml(&environment_path);
    environment["integrations"]["secondary"]["source"]["oauth"]["origin"] =
        serde_norway::Value::String("https://oauth-helper.invalid".to_string());
    write_yaml(&environment_path, &environment);
    check_registry_project(&ProjectCheckOptions {
        project_directory: protocol_helper,
        environment: "local".to_string(),
        explain: false,
        against: None,
        anchor: None,
    })
    .expect("a distinct protocol helper is not a second registry source");
}

#[test]
fn pre_freeze_fact_authoring_keys_are_rejected_without_aliases() {
    let integration_root = tempfile::tempdir().expect("integration-key temporary directory");
    let integration = copy_project("custom-system", integration_root.path());
    replace_in_file(
        &integration.join("integrations/eligibility/integration.yaml"),
        "\noutputs:\n",
        "\nfacts:\n",
    );
    let error = test_registry_project(&ProjectTestOptions {
        project_directory: integration,
        environment: None,
    })
    .expect_err("integration facts alias must be rejected");
    let rendered = format!("{error:#}");
    assert!(rendered.contains("canonical schema validation"));
    assert!(!rendered.contains("facts"));

    let claim_root = tempfile::tempdir().expect("claim-key temporary directory");
    let claim = copy_project("custom-system", claim_root.path());
    replace_in_file(
        &claim.join("registry-stack.yaml"),
        "output: household.category",
        "fact: household.category",
    );
    let error = test_registry_project(&ProjectTestOptions {
        project_directory: claim,
        environment: None,
    })
    .expect_err("claim fact alias must be rejected");
    let rendered = format!("{error:#}");
    assert!(rendered.contains("canonical schema validation"));
    assert!(!rendered.contains("fact:"));

    let fixture_root = tempfile::tempdir().expect("fixture-key temporary directory");
    let fixture = copy_project("custom-system", fixture_root.path());
    let fixture_path = fixture.join("integrations/eligibility/fixtures/source-approved.yaml");
    replace_in_file(&fixture_path, "  outputs:", "  facts:");
    let error = test_registry_project(&ProjectTestOptions {
        project_directory: fixture,
        environment: None,
    })
    .expect_err("fixture facts alias must be rejected");
    let rendered = format!("{error:#}");
    assert!(rendered.contains("canonical schema validation"));
    assert!(!rendered.contains("facts"));
}

#[test]
fn init_accepts_an_existing_empty_directory_and_rejects_authored_content() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let empty = temporary.path().join("empty");
    std::fs::create_dir(&empty).expect("empty destination creates");
    init_registry_project(&ProjectInitOptions {
        starter: ProjectStarter::Http,
        directory: empty,
    })
    .expect("empty destination initializes");

    let occupied = temporary.path().join("occupied");
    std::fs::create_dir(&occupied).expect("occupied destination creates");
    std::fs::write(occupied.join("owned.txt"), b"user content").expect("user content writes");
    let error = init_registry_project(&ProjectInitOptions {
        starter: ProjectStarter::Http,
        directory: occupied,
    })
    .expect_err("occupied destination must be preserved");
    assert!(error
        .to_string()
        .contains("absent or an empty real directory"));
}

#[test]
fn authored_unknown_fields_and_traversal_fail_closed() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let unknown = temporary.path().join("unknown");
    init_registry_project(&ProjectInitOptions {
        starter: ProjectStarter::Http,
        directory: unknown.clone(),
    })
    .expect("starter initializes");
    let project_path = unknown.join("registry-stack.yaml");
    let mut project = std::fs::read_to_string(&project_path).expect("project reads");
    project.push_str("unexpected_authority: true\n");
    std::fs::write(&project_path, project).expect("invalid project writes");
    let error = test_registry_project(&ProjectTestOptions {
        project_directory: unknown,
        environment: None,
    })
    .expect_err("unknown field must fail");
    let diagnostic = format!("{error:#}");
    assert!(diagnostic.contains("registry-stack.yaml:"), "{diagnostic}");
    assert!(diagnostic.contains("unknown field"), "{diagnostic}");
    assert!(
        diagnostic.contains("registryctl authoring schema --kind project"),
        "{diagnostic}"
    );

    let conformance_escape = copy_project("dhis2-script", temporary.path());
    let fixture_path = conformance_escape.join("integrations/health-record/fixtures/match.yaml");
    let mut fixture = read_yaml(&fixture_path);
    fixture["worker_probe"] = serde_norway::Value::String("network".to_string());
    write_yaml(&fixture_path, &fixture);
    let error = test_registry_project(&ProjectTestOptions {
        project_directory: conformance_escape,
        environment: None,
    })
    .expect_err("implementation conformance mode must not be authored");
    let diagnostic = format!("{error:#}");
    assert!(diagnostic.contains("unknown field"), "{diagnostic}");
    assert!(
        !diagnostic.contains("worker_probe"),
        "unknown country-authored field names remain value-free"
    );

    let traversal = temporary.path().join("traversal");
    init_registry_project(&ProjectInitOptions {
        starter: ProjectStarter::Http,
        directory: traversal.clone(),
    })
    .expect("starter initializes");
    let project_path = traversal.join("registry-stack.yaml");
    let project = std::fs::read_to_string(&project_path)
        .expect("project reads")
        .replace(
            "integrations/person-record/integration.yaml",
            "../outside/integration.yaml",
        );
    std::fs::write(&project_path, project).expect("traversal project writes");
    let error = test_registry_project(&ProjectTestOptions {
        project_directory: traversal,
        environment: None,
    })
    .expect_err("path traversal must fail");
    assert!(format!("{error:#}").contains("cannot traverse"));
}

#[test]
fn fixture_failure_reports_safe_validation_error_without_input_value() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    let fixture_path = project.join("integrations/eligibility/fixtures/source-approved.yaml");
    replace_in_file(&fixture_path, "HH-AB12CD34", "invalid-reference");

    let error = test_registry_project(&ProjectTestOptions {
        project_directory: project,
        environment: None,
    })
    .expect_err("invalid positive fixture must fail");
    let diagnostic = format!("{error:#}");
    assert!(
        diagnostic.contains("fixture input household_reference violates its pattern"),
        "{diagnostic}"
    );
    assert!(
        diagnostic.contains("integrations/eligibility/fixtures/source-approved.yaml"),
        "{diagnostic}"
    );
    assert!(
        diagnostic.contains("input.household_reference"),
        "{diagnostic}"
    );
    assert!(
        diagnostic.contains(
            "correct the value to satisfy integration eligibility input.household_reference"
        ),
        "{diagnostic}"
    );
    assert!(!diagnostic.contains("invalid-reference"));
}

#[cfg(unix)]
#[test]
fn authored_fixture_symlinks_fail_closed() {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = temporary.path().join("registry-project");
    init_registry_project(&ProjectInitOptions {
        starter: ProjectStarter::Http,
        directory: project.clone(),
    })
    .expect("starter initializes");
    let fixtures = project.join("integrations/person-record/fixtures");
    let fixture = std::fs::read_dir(&fixtures)
        .expect("fixtures read")
        .next()
        .expect("fixture exists")
        .expect("fixture entry")
        .path();
    let external = temporary.path().join("external.yaml");
    std::fs::rename(&fixture, &external).expect("fixture moves");
    symlink(&external, &fixture).expect("fixture symlink creates");
    let error = test_registry_project(&ProjectTestOptions {
        project_directory: project,
        environment: None,
    })
    .expect_err("fixture symlink must fail");
    assert!(format!("{error:#}").contains("symlink"));
}

#[cfg(unix)]
#[test]
fn generated_build_refuses_a_symlinked_private_output_ancestor() {
    use std::os::unix::fs::symlink;

    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    let outside = temporary.path().join("outside");
    std::fs::create_dir(&outside).expect("outside directory creates");
    symlink(&outside, project.join(".registry-stack")).expect("output ancestor symlink creates");
    let error = build_registry_project(&ProjectBuildOptions {
        project_directory: project,
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect_err("symlinked private output ancestor must fail");
    assert!(format!("{error:#}").contains("symlink"));
    assert!(std::fs::read_dir(outside)
        .expect("outside directory reads")
        .next()
        .is_none());
}

#[test]
fn project_authoring_schemas_keep_editor_annotations_and_valid_examples() {
    const SCHEMAS: &[&str] = &[
        "project.schema.json",
        "environment.schema.json",
        "integration.schema.json",
        "fixture.schema.json",
        "entity.schema.json",
    ];

    fn schema_annotation_counts(value: &serde_json::Value) -> (usize, usize, usize) {
        let Some(object) = value.as_object() else {
            return (0, 0, 0);
        };
        let is_schema = [
            "$ref",
            "type",
            "const",
            "enum",
            "oneOf",
            "anyOf",
            "allOf",
            "properties",
        ]
        .iter()
        .any(|keyword| object.contains_key(*keyword));
        let mut counts = (
            usize::from(
                object
                    .get("description")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|description| description.len() >= 16),
            ),
            usize::from(is_schema && object.contains_key("default")),
            usize::from(
                is_schema
                    && object
                        .get("examples")
                        .and_then(serde_json::Value::as_array)
                        .is_some_and(|examples| !examples.is_empty()),
            ),
        );
        for child in object.values() {
            let child_counts = match child {
                serde_json::Value::Array(values) => values
                    .iter()
                    .map(schema_annotation_counts)
                    .fold((0, 0, 0), |totals, counts| {
                        (
                            totals.0 + counts.0,
                            totals.1 + counts.1,
                            totals.2 + counts.2,
                        )
                    }),
                _ => schema_annotation_counts(child),
            };
            counts.0 += child_counts.0;
            counts.1 += child_counts.1;
            counts.2 += child_counts.2;
        }
        counts
    }

    let schema_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("schemas/project-authoring");
    for schema_name in SCHEMAS {
        let schema: serde_json::Value = serde_json::from_slice(
            &std::fs::read(schema_root.join(schema_name)).expect("schema reads"),
        )
        .expect("schema is JSON");
        let description = schema
            .get("description")
            .and_then(serde_json::Value::as_str)
            .expect("schema has a top-level description");
        assert!(
            description.len() >= 32,
            "{schema_name} needs a meaningful top-level description"
        );

        let properties = schema["properties"]
            .as_object()
            .expect("schema has root properties");
        for (name, property) in properties {
            assert!(
                property
                    .get("description")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|description| description.len() >= 16),
                "{schema_name} root property {name} needs a meaningful description"
            );
        }
        let definitions = schema["$defs"].as_object().expect("schema has definitions");
        for (name, definition) in definitions {
            assert!(
                definition
                    .get("description")
                    .and_then(serde_json::Value::as_str)
                    .is_some_and(|description| description.len() >= 16),
                "{schema_name} definition {name} needs a meaningful description"
            );
        }

        let (descriptions, _defaults, examples) = schema_annotation_counts(&schema);
        assert!(
            descriptions > properties.len() + definitions.len(),
            "{schema_name} description coverage regressed"
        );
        assert!(examples >= 1, "{schema_name} needs at least one example");

        let compiled = jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&schema)
            .unwrap_or_else(|error| panic!("{schema_name} did not compile: {error}"));
        for example in schema["examples"]
            .as_array()
            .expect("schema has top-level examples")
        {
            if let Err(errors) = compiled.validate(example) {
                let messages = errors.map(|error| error.to_string()).collect::<Vec<_>>();
                panic!("{schema_name} has an invalid example: {messages:?}");
            }
        }
    }
}

#[test]
fn strict_project_authoring_schemas_compile_and_accept_every_golden() {
    let schema_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("schemas/project-authoring");
    let compile = |schema_name: &str| {
        let schema: serde_json::Value = serde_json::from_slice(
            &std::fs::read(schema_root.join(schema_name)).expect("schema reads"),
        )
        .expect("schema is JSON");
        jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&schema)
            .unwrap_or_else(|error| panic!("{schema_name} did not compile: {error}"))
    };
    let project_schema = compile("project.schema.json");
    let environment_schema = compile("environment.schema.json");
    let integration_schema = compile("integration.schema.json");
    let fixture_schema = compile("fixture.schema.json");
    let entity_schema = compile("entity.schema.json");
    let projects = project_authoring_journey_catalog()
        .workspaces
        .iter()
        .map(catalog_workspace)
        .collect::<Vec<_>>();
    for project in projects {
        validate_yaml(&project_schema, &project.join("registry-stack.yaml"));
        validate_yaml(
            &environment_schema,
            &project.join("environments/local.yaml"),
        );
        let entities = project.join("entities");
        if entities.is_dir() {
            for definition in std::fs::read_dir(entities).expect("entities directory reads") {
                let definition = definition.expect("entity entry").path();
                if definition.extension().and_then(|value| value.to_str()) == Some("yaml") {
                    validate_yaml(&entity_schema, &definition);
                }
            }
        }
        let integrations = project.join("integrations");
        if integrations.is_dir() {
            for integration_dir in
                std::fs::read_dir(integrations).expect("integration directory reads")
            {
                let integration_dir = integration_dir.expect("integration entry").path();
                validate_yaml(
                    &integration_schema,
                    &integration_dir.join("integration.yaml"),
                );
                for fixture in std::fs::read_dir(integration_dir.join("fixtures"))
                    .expect("fixture directory reads")
                {
                    let fixture = fixture.expect("fixture entry").path();
                    if fixture.extension().and_then(|value| value.to_str()) == Some("yaml") {
                        validate_yaml(&fixture_schema, &fixture);
                    }
                }
            }
        }
    }
}

#[test]
fn project_schema_keeps_attribute_release_source_metadata_private() {
    let schema: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("schemas/project-authoring/project.schema.json"),
        )
        .expect("project schema reads"),
    )
    .expect("project schema is JSON");
    let schema = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .expect("project schema compiles");
    let mut project = serde_json::to_value(read_yaml(
        &golden("nia-attribute-release").join("registry-stack.yaml"),
    ))
    .expect("NIA project converts to JSON");
    assert!(schema.is_valid(&project));
    project["services"]["nia-population-records"]["api"]["attribute_release_profiles"]
        ["solmara-nia-userinfo"]["response"]["include_source_metadata"] = serde_json::json!(true);
    assert!(
        !schema.is_valid(&project),
        "project authors cannot opt released identity responses into source metadata disclosure"
    );
}

#[test]
fn project_check_field_addresses_records_scope_collisions() {
    for (metadata_scope, expected_field, expected_cause) in [
        (
            "population:aggregate",
            "services.api.scopes",
            "Effective records API authorization scopes collide.",
        ),
        (
            "population:identity_release",
            "services.api.attribute_release_profiles.release_scope",
            "An attribute release scope collides with a records API authorization scope.",
        ),
    ] {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = copy_project("nia-attribute-release", temporary.path());
        let project_file = project.join("registry-stack.yaml");
        let mut document = read_yaml(&project_file);
        document["services"]["nia-population-records"]["api"]["scopes"]["metadata"] =
            serde_norway::Value::String(metadata_scope.to_string());
        write_yaml(&project_file, &document);

        let report = authoring_diagnostics(&project);
        let diagnostic = report
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == "registryctl.authoring.project.scope_collision")
            .expect("scope collision diagnostic");
        assert_eq!(diagnostic.field, Some(expected_field));
        assert_eq!(diagnostic.cause, expected_cause);
    }
}

#[test]
fn project_check_preserves_both_exact_sides_of_cross_file_failures() {
    let assert_addresses = |project: &Path, code: &str, expected: &[(&str, &str)]| {
        let report = authoring_diagnostics(project);
        let diagnostic = report
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.code == code)
            .unwrap_or_else(|| panic!("missing {code}: {report:#?}"));
        let addresses = diagnostic
            .addresses
            .iter()
            .map(|address| (address.file.as_str(), address.pointer.as_str()))
            .collect::<BTreeSet<_>>();
        assert_eq!(addresses, expected.iter().copied().collect(), "{report:#?}");
        let serialized = serde_json::to_string(&report).expect("diagnostics serialize");
        assert!(!serialized.contains(&project.display().to_string()));
    };

    let service_root = tempfile::tempdir().expect("service temporary directory");
    let service_project = copy_project("custom-system", service_root.path());
    let service_path = service_project.join("registry-stack.yaml");
    let mut service = read_yaml(&service_path);
    let input = service["services"]["household-eligibility"]["consultations"]["household"]["input"]
        .as_mapping_mut()
        .expect("consultation input");
    let value = input
        .remove(serde_norway::Value::String(
            "household_reference".to_string(),
        ))
        .expect("selector exists");
    input.insert(
        serde_norway::Value::String("unrelated_selector".to_string()),
        value,
    );
    write_yaml(&service_path, &service);
    assert_addresses(
        &service_project,
        "registryctl.authoring.project.invalid",
        &[
            ("integrations/eligibility/integration.yaml", "/input"),
            (
                "registry-stack.yaml",
                "/services/household-eligibility/consultations/household/input",
            ),
        ],
    );

    let entity_root = tempfile::tempdir().expect("entity temporary directory");
    let entity_project = copy_project("snapshot-with-records", entity_root.path());
    let entity_project_path = entity_project.join("registry-stack.yaml");
    let mut entity_project_document = read_yaml(&entity_project_path);
    entity_project_document["services"]["people-records"]["api"]["projection"]
        .as_sequence_mut()
        .expect("records projection")
        .push(serde_norway::Value::String("unknown_field".to_string()));
    write_yaml(&entity_project_path, &entity_project_document);
    assert_addresses(
        &entity_project,
        "registryctl.authoring.project.invalid",
        &[
            ("entities/people.yaml", "/schema"),
            ("registry-stack.yaml", "/services/people-records/api"),
        ],
    );

    let fixture_root = tempfile::tempdir().expect("fixture temporary directory");
    let fixture_project = copy_project("custom-system", fixture_root.path());
    let fixture_path =
        fixture_project.join("integrations/eligibility/fixtures/source-approved.yaml");
    let mut fixture = read_yaml(&fixture_path);
    fixture["input"]
        .as_mapping_mut()
        .expect("fixture input")
        .clear();
    fixture["input"]["unrelated_input"] =
        serde_norway::Value::String("schema-valid-mismatch".to_string());
    write_yaml(&fixture_path, &fixture);
    assert_addresses(
        &fixture_project,
        "registryctl.authoring.fixture.invalid",
        &[
            (
                "integrations/eligibility/fixtures/source-approved.yaml",
                "/input",
            ),
            ("integrations/eligibility/integration.yaml", "/input"),
        ],
    );

    let not_applicable_root = tempfile::tempdir().expect("not-applicable temporary directory");
    let not_applicable_project = copy_project("custom-system", not_applicable_root.path());
    let not_applicable_fixture =
        not_applicable_project.join("integrations/eligibility/fixtures/source-approved.yaml");
    let mut fixture = read_yaml(&not_applicable_fixture);
    fixture["expect"]["error"] = serde_norway::Value::String("source.timeout".to_string());
    write_yaml(&not_applicable_fixture, &fixture);
    assert_addresses(
        &not_applicable_project,
        "registryctl.authoring.fixture.invalid",
        &[
            (
                "integrations/eligibility/fixtures/source-approved.yaml",
                "/expect/error",
            ),
            (
                "integrations/eligibility/integration.yaml",
                "/not_applicable/subject_mismatch/request_fixture",
            ),
        ],
    );

    let environment_root = tempfile::tempdir().expect("environment temporary directory");
    let environment_project = copy_project("custom-system", environment_root.path());
    let environment_path = environment_project.join("environments/local.yaml");
    let mut environment = read_yaml(&environment_path);
    environment["integrations"]
        .as_mapping_mut()
        .expect("environment integrations")
        .clear();
    write_yaml(&environment_path, &environment);
    assert_addresses(
        &environment_project,
        "registryctl.authoring.environment.invalid",
        &[
            ("environments/local.yaml", "/integrations"),
            ("integrations/eligibility/integration.yaml", "/capability"),
        ],
    );
}

#[test]
fn project_check_points_to_representative_semantic_reference_and_value_failures() {
    let assert_exact_pointer =
        |project: &Path, cause: &str, expected_file: &str, expected_pointer: &str| {
            let report = authoring_diagnostics(project);
            let diagnostic = report
                .diagnostics
                .iter()
                .find(|diagnostic| diagnostic.cause == cause)
                .unwrap_or_else(|| panic!("missing {cause}: {report:#?}"));
            assert!(
                diagnostic.addresses.iter().any(|address| {
                    address.file == expected_file && address.pointer == expected_pointer
                }),
                "missing {expected_file}#{expected_pointer}: {diagnostic:#?}"
            );
            assert!(
                diagnostic
                    .addresses
                    .iter()
                    .all(|address| !address.pointer.is_empty()),
                "a precise semantic diagnostic degraded to a document-root address: {diagnostic:#?}"
            );
        };

    let integration_root = tempfile::tempdir().expect("integration temporary directory");
    let integration_project = copy_project("custom-system", integration_root.path());
    let project_path = integration_project.join("registry-stack.yaml");
    let mut project = read_yaml(&project_path);
    project["services"]["household-eligibility"]["consultations"]["household"]["integration"] =
        serde_norway::Value::String("missing-integration".to_string());
    write_yaml(&project_path, &project);
    assert_exact_pointer(
        &integration_project,
        "A service consultation references an unknown integration.",
        "registry-stack.yaml",
        "/services/household-eligibility/consultations/household/integration",
    );

    let credential_root = tempfile::tempdir().expect("credential temporary directory");
    let credential_project = copy_project("custom-system", credential_root.path());
    let project_path = credential_project.join("registry-stack.yaml");
    let mut project = read_yaml(&project_path);
    project["services"]["household-eligibility"]["credential_profiles"]["household-eligibility"]
        ["claims"][0] = serde_norway::Value::String("missing-claim".to_string());
    write_yaml(&project_path, &project);
    assert_exact_pointer(
        &credential_project,
        "A credential profile references an unknown claim.",
        "registry-stack.yaml",
        "/services/household-eligibility/credential_profiles/household-eligibility/claims/0",
    );

    let cel_root = tempfile::tempdir().expect("CEL temporary directory");
    let cel_project = copy_project("custom-system", cel_root.path());
    let project_path = cel_project.join("registry-stack.yaml");
    let mut project = read_yaml(&project_path);
    project["services"]["household-eligibility"]["claims"]["household-record-exists"]["cel"] =
        serde_norway::Value::String("missing_consultation.matched".to_string());
    project["services"]["household-eligibility"]["claims"]["household-record-exists"]["value"] =
        serde_norway::from_str("{ type: boolean }").expect("claim value YAML parses");
    write_yaml(&project_path, &project);
    assert_exact_pointer(
        &cel_project,
        "A claim evaluation does not resolve to a declared consultation.",
        "registry-stack.yaml",
        "/services/household-eligibility/claims/household-record-exists/cel",
    );

    let validity_root = tempfile::tempdir().expect("validity temporary directory");
    let validity_project = copy_project("custom-system", validity_root.path());
    let project_path = validity_project.join("registry-stack.yaml");
    let mut project = read_yaml(&project_path);
    project["services"]["household-eligibility"]["credential_profiles"]["household-eligibility"]
        ["validity"] = serde_norway::Value::String("ten-minutes".to_string());
    write_yaml(&project_path, &project);
    assert_exact_pointer(
        &validity_project,
        "The YAML document does not satisfy its canonical authoring schema.",
        "registry-stack.yaml",
        "/services/household-eligibility/credential_profiles/household-eligibility/validity",
    );

    let disclosure_root = tempfile::tempdir().expect("disclosure temporary directory");
    let disclosure_project = copy_project("custom-system", disclosure_root.path());
    let project_path = disclosure_project.join("registry-stack.yaml");
    let mut project = read_yaml(&project_path);
    project["services"]["household-eligibility"]["claims"]["household-record-exists"]
        ["disclosure"] = serde_norway::Value::String("unsupported-mode".to_string());
    write_yaml(&project_path, &project);
    assert_exact_pointer(
        &disclosure_project,
        "The YAML document does not satisfy its canonical authoring schema.",
        "registry-stack.yaml",
        "/services/household-eligibility/claims/household-record-exists/disclosure",
    );
}

#[test]
fn project_check_moves_unknown_direct_outputs_into_exact_typed_diagnostics() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    let project_path = project.join("registry-stack.yaml");
    let mut authored = read_yaml(&project_path);
    authored["services"]["household-eligibility"]["claims"]["household-category"]["output"] =
        serde_norway::Value::String("household.unknown-output".to_string());
    write_yaml(&project_path, &authored);

    let report = authoring_diagnostics(&project);
    let diagnostic = report
        .diagnostics
        .iter()
        .find(|diagnostic| {
            diagnostic.cause == "A direct claim references an unknown integration output."
        })
        .unwrap_or_else(|| panic!("missing direct-output diagnostic: {report:#?}"));
    assert_eq!(
        diagnostic
            .addresses
            .iter()
            .map(|address| (address.file.as_str(), address.pointer.as_str()))
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            ("integrations/eligibility/integration.yaml", "/outputs"),
            (
                "registry-stack.yaml",
                "/services/household-eligibility/claims/household-category/output",
            ),
        ])
    );
}

#[test]
fn project_check_rejects_unresolvable_request_paths_and_string_source_type_mismatches() {
    let path_root = tempfile::tempdir().expect("path temporary directory");
    let path_project = copy_project("custom-system", path_root.path());
    let project_path = path_project.join("registry-stack.yaml");
    let mut project = read_yaml(&project_path);
    project["services"]["household-eligibility"]["consultations"]["household"]["input"]
        ["household_reference"] = serde_norway::Value::String("request.ghost_field".to_string());
    write_yaml(&project_path, &project);
    let report = authoring_diagnostics(&path_project);
    assert!(
        report.diagnostics.iter().any(|diagnostic| {
            diagnostic.addresses.iter().any(|address| {
                address.pointer
                    == "/services/household-eligibility/consultations/household/input/household_reference"
            })
        }),
        "{report:#?}"
    );

    let type_root = tempfile::tempdir().expect("type temporary directory");
    let type_project = copy_project("custom-system", type_root.path());
    let integration_path = type_project.join("integrations/eligibility/integration.yaml");
    let mut integration = read_yaml(&integration_path);
    integration["input"]["household_reference"]["type"] =
        serde_norway::Value::String("boolean".to_string());
    integration["input"]["household_reference"]
        .as_mapping_mut()
        .expect("input schema is a map")
        .remove(serde_norway::Value::String("maxLength".to_string()));
    integration["input"]["household_reference"]
        .as_mapping_mut()
        .expect("input schema is a map")
        .remove(serde_norway::Value::String("pattern".to_string()));
    write_yaml(&integration_path, &integration);
    for fixture in std::fs::read_dir(type_project.join("integrations/eligibility/fixtures"))
        .expect("fixture directory reads")
    {
        let path = fixture.expect("fixture entry").path();
        if path.extension().and_then(|extension| extension.to_str()) != Some("yaml") {
            continue;
        }
        let mut fixture = read_yaml(&path);
        fixture["input"]["household_reference"] = serde_norway::Value::Bool(true);
        write_yaml(&path, &fixture);
    }

    let report = authoring_diagnostics(&type_project);
    let diagnostic = report
        .diagnostics
        .iter()
        .find(|diagnostic| {
            diagnostic.cause
                == "A governed request string source is incompatible with its integration input."
        })
        .unwrap_or_else(|| panic!("missing source-type diagnostic: {report:#?}"));
    assert_eq!(
        diagnostic
            .addresses
            .iter()
            .map(|address| (address.file.as_str(), address.pointer.as_str()))
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            (
                "integrations/eligibility/integration.yaml",
                "/input/household_reference/type",
            ),
            (
                "registry-stack.yaml",
                "/services/household-eligibility/consultations/household/input/household_reference",
            ),
        ])
    );
}

#[test]
fn project_check_keeps_same_legacy_cross_file_failures_distinct_by_address() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("snapshot-with-records", temporary.path());
    let project_path = project.join("registry-stack.yaml");
    let mut document = read_yaml(&project_path);
    for service_id in ["benefits-eligibility", "emergency-assistance"] {
        let input = document["services"][service_id]["consultations"]["person"]["input"]
            .as_mapping_mut()
            .expect("consultation input");
        let target = input
            .remove(serde_norway::Value::String("person_id".to_string()))
            .expect("person selector exists");
        input.insert(
            serde_norway::Value::String("unknown_input".to_string()),
            target,
        );
    }
    write_yaml(&project_path, &document);

    let report = authoring_diagnostics(&project);
    assert_eq!(report, authoring_diagnostics(&project));
    let diagnostics = report
        .diagnostics
        .iter()
        .filter(|diagnostic| {
            diagnostic.code == "registryctl.authoring.project.invalid"
                && diagnostic.field == Some("services.consultations")
        })
        .collect::<Vec<_>>();
    assert_eq!(diagnostics.len(), 2, "{report:#?}");
    let project_pointers = diagnostics
        .iter()
        .map(|diagnostic| {
            assert_eq!(
                diagnostic
                    .addresses
                    .iter()
                    .map(|address| (address.file.as_str(), address.pointer.as_str()))
                    .collect::<BTreeSet<_>>()
                    .len(),
                diagnostic.addresses.len(),
                "one diagnostic must not duplicate exact addresses"
            );
            diagnostic
                .addresses
                .iter()
                .find(|address| address.file == "registry-stack.yaml")
                .expect("project-side address")
                .pointer
                .as_str()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        project_pointers,
        vec![
            "/services/benefits-eligibility/consultations/person/input",
            "/services/emergency-assistance/consultations/person/input",
        ]
    );
}

#[test]
fn project_check_addresses_an_unknown_snapshot_entity_without_fabricating_a_file() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("snapshot-with-records", temporary.path());
    let integration_path = project.join("integrations/person-snapshot/integration.yaml");
    let mut integration = read_yaml(&integration_path);
    integration["capability"]["snapshot"]["entity"] =
        serde_norway::Value::String("missing-entity".to_string());
    write_yaml(&integration_path, &integration);

    let report = authoring_diagnostics(&project);
    let matching = report
        .diagnostics
        .iter()
        .filter(|diagnostic| {
            diagnostic.code == "registryctl.authoring.project.invalid"
                && diagnostic.field == Some("capability.snapshot.entity")
        })
        .collect::<Vec<_>>();
    assert_eq!(matching.len(), 1, "{report:#?}");
    assert_eq!(
        matching[0]
            .addresses
            .iter()
            .map(|address| (address.file.as_str(), address.pointer.as_str()))
            .collect::<Vec<_>>(),
        vec![
            (
                "integrations/person-snapshot/integration.yaml",
                "/capability/snapshot/entity",
            ),
            ("registry-stack.yaml", "/entities"),
        ]
    );
    assert!(
        report
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.file != "entities/missing-entity.yaml"),
        "diagnostics must not fabricate a target entity file"
    );
    assert!(
        report.diagnostics.iter().all(|diagnostic| {
            !(diagnostic.file == "registry-stack.yaml"
                && diagnostic.field == Some("services")
                && diagnostic.cause == "A project entity reference is inconsistent.")
        }),
        "the exact unknown-entity diagnostic must not degrade to the generic fallback"
    );
}

#[test]
fn project_schema_accepts_sixteen_consultation_inputs_and_rejects_seventeen() {
    let schema: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("schemas/project-authoring/project.schema.json"),
        )
        .expect("project schema reads"),
    )
    .expect("project schema is JSON");
    let schema = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .expect("project schema compiles");
    let mut project = serde_json::to_value(read_yaml(
        &golden("custom-system").join("registry-stack.yaml"),
    ))
    .expect("project converts to JSON");
    {
        let input = project
            .pointer_mut("/services/household-eligibility/consultations/household/input")
            .and_then(serde_json::Value::as_object_mut)
            .expect("consultation input map exists");
        input.clear();
        for index in 0..16 {
            input.insert(
                format!("input_{index}"),
                serde_json::Value::String(format!("request.target.identifiers.identifier_{index}")),
            );
        }
    }
    assert!(schema.is_valid(&project));
    project
        .pointer_mut("/services/household-eligibility/consultations/household/input")
        .and_then(serde_json::Value::as_object_mut)
        .expect("consultation input map exists")
        .insert(
            "input_16".to_string(),
            serde_json::Value::String("request.target.identifiers.identifier_16".to_string()),
        );
    assert!(!schema.is_valid(&project));
}

#[test]
fn project_schema_accepts_only_bounded_scalar_target_attribute_mappings() {
    let schema: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("schemas/project-authoring/project.schema.json"),
        )
        .expect("project schema reads"),
    )
    .expect("project schema is JSON");
    let schema = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .expect("project schema compiles");
    let mut project = serde_json::to_value(read_yaml(
        &golden("custom-system").join("registry-stack.yaml"),
    ))
    .expect("project converts to JSON");
    let mapping = project
        .pointer_mut(
            "/services/household-eligibility/consultations/household/input/household_reference",
        )
        .expect("consultation input mapping exists");
    *mapping = serde_json::json!("request.target.attributes.person_sequence");
    assert!(schema.is_valid(&project));

    for invalid in [
        serde_json::json!("request.target.attributes."),
        serde_json::json!("request.target.attributes.Person_sequence"),
        serde_json::json!("request.target.attributes.person.sequence"),
        serde_json::json!(format!("request.target.attributes.{}", "a".repeat(65))),
        serde_json::json!({ "path": "request.target.attributes.person_sequence" }),
        serde_json::json!(["request.target.attributes.person_sequence"]),
        serde_json::json!("x".repeat(129)),
    ] {
        *project
            .pointer_mut(
                "/services/household-eligibility/consultations/household/input/household_reference",
            )
            .expect("consultation input mapping exists") = invalid;
        assert!(
            !schema.is_valid(&project),
            "malformed, nested, or unbounded target attribute mappings fail closed"
        );
    }

    *project
        .pointer_mut("/services/household-eligibility/consultations/household")
        .expect("consultation exists") = serde_json::json!({
        "integration": "eligibility",
        "input": { "household_reference": "request.target.attributes.person_sequence" },
        "authenticated_identifier": "person_sequence",
    });
    assert!(
        !schema.is_valid(&project),
        "the closed consultation shape has no attribute-to-authenticated-identifier switch"
    );
}

#[test]
fn environment_schema_tracks_local_loopback_signing_kid_and_postgresql_state() {
    let schema: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("schemas/project-authoring/environment.schema.json"),
        )
        .expect("environment schema reads"),
    )
    .expect("environment schema is JSON");
    let schema = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .expect("environment schema compiles");
    let local = serde_json::json!({
        "version": 1,
        "issuance": {
            "issuer": "did:web:authority.invalid",
            "signing_key": { "secret": "NOTARY_ISSUER_JWK" },
            "signing_kid": "did:web:authority.invalid#issuer-key-1",
            "generation": 1,
        },
        "relay": {
            "origin": "HTTP://127.0.0.1:8080",
            "issuer": "HTTP://[::1]:8090",
            "jwks_url": "HTTP://127.0.0.1:8090/.well-known/jwks.json",
            "audience": "registry-relay",
            "allowed_clients": [],
        },
        "notary_relay": {
            "base_url": "HTTP://127.0.0.1:8080",
            "workload_client_id": "authority-notary",
            "token_file": "/run/secrets/authority-notary-relay-token",
        },
        "relay_state": {
            "postgresql": {
                "root_certificate_path": "/run/secrets/relay-postgres-ca.pem",
            },
        },
        "notary_state": {
            "postgresql": {
                "root_certificate_path": "/run/secrets/notary-postgres-ca.pem",
            },
        },
        "notary_cel": {
            "worker_memory_bytes": 1073741824,
        },
        "deployment": {
            "profile": "local",
            "relay": { "service": "authority-relay" },
            "notary": { "service": "authority-notary" },
        },
    });
    assert!(schema.is_valid(&local));

    let mut hosted_loopback = local.clone();
    hosted_loopback["deployment"]["profile"] = serde_json::json!("hosted_lab");
    assert!(!schema.is_valid(&hosted_loopback));

    let mut private_network_http = local.clone();
    private_network_http["relay"]["origin"] = serde_json::json!("http://10.42.0.8:8080");
    assert!(!schema.is_valid(&private_network_http));

    let mut relative_root = local.clone();
    relative_root["notary_state"]["postgresql"]["root_certificate_path"] =
        serde_json::json!("notary-postgres-ca.pem");
    assert!(!schema.is_valid(&relative_root));

    let mut relative_relay_root = local.clone();
    relative_relay_root["relay_state"]["postgresql"]["root_certificate_path"] =
        serde_json::json!("relay-postgres-ca.pem");
    assert!(!schema.is_valid(&relative_relay_root));

    let mut undersized_cel_worker = local.clone();
    undersized_cel_worker["notary_cel"]["worker_memory_bytes"] = serde_json::json!(33_554_431);
    assert!(!schema.is_valid(&undersized_cel_worker));

    let mut oversized_cel_worker = local.clone();
    oversized_cel_worker["notary_cel"]["worker_memory_bytes"] =
        serde_json::json!(1_073_741_825_u64);
    assert!(!schema.is_valid(&oversized_cel_worker));

    let mut relay_only_cel_worker = local.clone();
    relay_only_cel_worker["deployment"]
        .as_object_mut()
        .expect("deployment is an object")
        .remove("notary");
    assert!(!schema.is_valid(&relay_only_cel_worker));

    let mut whitespace_kid = local.clone();
    whitespace_kid["issuance"]["signing_kid"] =
        serde_json::json!("did:web:authority.invalid#bad kid");
    assert!(!schema.is_valid(&whitespace_kid));
}

#[test]
fn environment_schema_types_the_closed_oid4vci_authority_binding() {
    let schema: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("schemas/project-authoring/environment.schema.json"),
        )
        .expect("environment schema reads"),
    )
    .expect("environment schema is JSON");
    let schema = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .expect("environment schema compiles");
    let environment = serde_json::json!({
        "version": 1,
        "issuance": {
            "issuer": "did:web:notary.example.invalid",
            "signing_key": { "secret": "NOTARY_ISSUER_JWK" },
            "signing_kid": "did:web:notary.example.invalid#issuer-key-1",
            "generation": 1,
        },
        "notary_state": {
            "postgresql": {
                "root_certificate_path": "/run/secrets/notary-postgres-ca.pem",
            },
        },
        "oid4vci": {
            "public_base_url": "https://notary.example.invalid",
            "credential": {
                "service": "citizen-status",
                "profile": "citizen-status",
            },
            "authorization_server": {
                "issuer": "https://esignet.example.invalid",
                "jwks_url": "https://esignet.example.invalid/jwks.json",
                "userinfo_url": "https://esignet.example.invalid/userinfo",
                "authorize_url": "https://esignet-ui.example.invalid/authorize",
                "token_url": "https://esignet.example.invalid/token",
            },
            "client": {
                "id": "citizen-wallet",
                "signing_key": { "secret": "ESIGNET_CLIENT_JWK" },
                "signing_kid": "citizen-wallet-key-1",
            },
            "access_token": {
                "signing_key": { "secret": "NOTARY_ACCESS_TOKEN_JWK" },
                "signing_kid": "did:web:notary.example.invalid#access-token-key-1",
            },
            "sensitive_state_key": { "secret": "NOTARY_SENSITIVE_STATE_KEY" },
            "subject": {
                "token_claim": "individual_id",
                "id_type": "solmara_uin",
            },
            "redirect_uri": "https://notary.example.invalid/oid4vci/offer/callback",
            "allowed_wallet_origins": ["https://wallet.example.invalid"],
            "representative_issuance": {
                "relationship": "parent",
                "proof_claim": "parent-link",
                "target_id_type": "solmara_uin",
            },
        },
        "deployment": {
            "profile": "hosted_lab",
            "notary": { "service": "citizen-notary" },
        },
    });
    assert!(schema.is_valid(&environment));

    let mut empty_callers = environment.clone();
    empty_callers["callers"] = serde_json::json!({});
    assert!(schema.is_valid(&empty_callers));

    let mut with_callers = environment.clone();
    with_callers["callers"] = serde_json::json!({
        "portal": {
            "api_key_fingerprint": { "secret": "PORTAL_KEY_HASH" },
            "scopes": ["evidence:read"],
        },
    });
    assert!(schema.is_valid(&with_callers));

    let mut authored_scope = environment.clone();
    authored_scope["oid4vci"]["credential"]["scope"] = serde_json::json!("credential:issue");
    assert!(!schema.is_valid(&authored_scope));

    let mut missing_state = environment.clone();
    missing_state
        .as_object_mut()
        .expect("environment object")
        .remove("notary_state");
    assert!(!schema.is_valid(&missing_state));

    let mut relative_redirect = environment.clone();
    relative_redirect["oid4vci"]["redirect_uri"] = serde_json::json!("/oid4vci/offer/callback");
    assert!(!schema.is_valid(&relative_redirect));

    let mut hosted_loopback = environment.clone();
    hosted_loopback["oid4vci"]["public_base_url"] = serde_json::json!("http://127.0.0.1:8081");
    assert!(!schema.is_valid(&hosted_loopback));

    let mut stale_relationship_proof = environment.clone();
    stale_relationship_proof["oid4vci"]["representative_issuance"]["max_proof_age_seconds"] =
        serde_json::json!(0);
    assert!(!schema.is_valid(&stale_relationship_proof));

    let mut unknown_key_field = environment;
    unknown_key_field["oid4vci"]["access_token"]["value"] = serde_json::json!("secret-material");
    assert!(!schema.is_valid(&unknown_key_field));
}

#[test]
fn project_authoring_schemas_reject_incoherent_product_topologies() {
    let schema_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("schemas/project-authoring");
    let compile = |schema_name: &str| {
        let schema: serde_json::Value = serde_json::from_slice(
            &std::fs::read(schema_root.join(schema_name)).expect("schema reads"),
        )
        .expect("schema is JSON");
        jsonschema::JSONSchema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .compile(&schema)
            .unwrap_or_else(|error| panic!("{schema_name} did not compile: {error}"))
    };
    let project_schema = compile("project.schema.json");
    assert!(!project_schema.is_valid(&serde_json::json!({
        "version": 1,
        "registry": { "id": "empty-registry" },
        "services": {},
    })));

    let environment_schema = compile("environment.schema.json");
    let relay_binding = serde_json::json!({
        "origin": "https://relay.internal.invalid",
        "issuer": "https://issuer.internal.invalid",
        "jwks_url": "https://issuer.internal.invalid/.well-known/jwks.json",
        "audience": "registry-relay",
        "allowed_clients": ["registry-client"],
    });
    let connection = serde_json::json!({
        "base_url": "http://127.0.0.1:8080",
        "workload_client_id": "registry-notary",
        "token_file": "/run/secrets/notary-relay-token",
    });
    for (name, environment) in [
        (
            "Relay deployment without Relay bindings",
            serde_json::json!({
                "version": 1,
                "deployment": { "profile": "local", "relay": { "service": "relay" } },
            }),
        ),
        (
            "Notary-only deployment with Relay bindings",
            serde_json::json!({
                "version": 1,
                "relay": relay_binding.clone(),
                "deployment": { "profile": "local", "notary": { "service": "notary" } },
            }),
        ),
        (
            "Relay-only deployment with a Notary-to-Relay connection",
            serde_json::json!({
                "version": 1,
                "relay": relay_binding.clone(),
                "notary_relay": connection,
                "deployment": { "profile": "local", "relay": { "service": "relay" } },
            }),
        ),
    ] {
        assert!(
            !environment_schema.is_valid(&environment),
            "schema accepted {name}"
        );
    }
    assert!(environment_schema.is_valid(&serde_json::json!({
        "version": 1,
        "relay": relay_binding,
        "deployment": {
            "profile": "local",
            "relay": { "service": "relay" },
            "notary": { "service": "notary" },
        },
    })));
    assert!(!environment_schema.is_valid(&serde_json::json!({
        "version": 1,
        "relay": {
            "origin": "https://relay.internal.invalid",
            "issuer": "https://issuer.internal.invalid",
            "jwks_url": "https://issuer.internal.invalid/.well-known/jwks.json",
            "audience": "registry-relay",
            "workload_client_id": "obsolete-overloaded-client",
        },
        "deployment": { "profile": "local", "relay": { "service": "relay" } },
    })));
}

#[test]
fn relay_authorization_bindings_follow_authored_service_topology() {
    let missing_workload_root = tempfile::tempdir().expect("temporary directory");
    let missing_workload = copy_project("custom-system", missing_workload_root.path());
    let environment_path = missing_workload.join("environments/local.yaml");
    let mut environment = read_yaml(&environment_path);
    environment
        .as_mapping_mut()
        .expect("environment mapping")
        .remove(serde_norway::Value::String("notary_relay".to_string()));
    write_yaml(&environment_path, &environment);
    let error = check_registry_project(&ProjectCheckOptions {
        project_directory: missing_workload,
        environment: "local".to_string(),
        explain: false,
        against: None,
        anchor: None,
    })
    .expect_err("Relay consultation without a Notary workload must fail");
    assert_authoring_diagnostic(&error, "registryctl.authoring.environment.invalid");

    let missing_records_client_root = tempfile::tempdir().expect("temporary directory");
    let missing_records_client =
        copy_project("relay-only-records", missing_records_client_root.path());
    let environment_path = missing_records_client.join("environments/local.yaml");
    let mut environment = read_yaml(&environment_path);
    environment["relay"]["allowed_clients"] =
        serde_norway::from_str("[]\n").expect("empty allowed client list");
    write_yaml(&environment_path, &environment);
    let error = check_registry_project(&ProjectCheckOptions {
        project_directory: missing_records_client,
        environment: "local".to_string(),
        explain: false,
        against: None,
        anchor: None,
    })
    .expect_err("records publication without an admitted client must fail");
    assert_authoring_diagnostic(&error, "registryctl.authoring.environment.invalid");
}

#[test]
fn exact_selector_sizes_one_through_eight_compile_for_http_and_snapshot() {
    for size in 1..=8 {
        let temporary = tempfile::tempdir().expect("temporary directory");
        for golden_name in ["custom-system", "snapshot-exact"] {
            let project = copy_project(golden_name, temporary.path());
            if golden_name == "custom-system" {
                remove_custom_cel_claim(&project);
            }
            extend_exact_selector(&project, golden_name, size);
            check_registry_project(&ProjectCheckOptions {
                project_directory: project,
                environment: "local".to_string(),
                explain: false,
                against: None,
                anchor: None,
            })
            .unwrap_or_else(|error| {
                panic!("{golden_name} exact selector size {size} failed: {error:#}")
            });
        }
    }
}

#[test]
fn integration_input_bounds_match_the_production_compiler_limit() {
    let accepted_root = tempfile::tempdir().expect("accepted temporary directory");
    let accepted = copy_project("custom-system", accepted_root.path());
    remove_custom_cel_claim(&accepted);
    replace_in_file(
        &accepted.join("integrations/eligibility/integration.yaml"),
        "maxLength: 18",
        "maxLength: 64",
    );
    let report = build_registry_project(&ProjectBuildOptions {
        project_directory: accepted.clone(),
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect("256-byte input builds through the production Relay compiler closure");
    let output = resolve_build_output(&accepted, report.output.expect("build output"));
    let pack: serde_json::Value = serde_json::from_slice(
        &std::fs::read(output.join(
            "private/relay-consultation/config/artifacts/integration-packs/eligibility.json",
        ))
        .expect("generated integration pack reads"),
    )
    .expect("generated integration pack parses");
    assert_eq!(
        pack["spec"]["input_slots"]["household_reference"]["x-registry-max-bytes"],
        256
    );

    let rejected_root = tempfile::tempdir().expect("rejected temporary directory");
    let rejected = copy_project("custom-system", rejected_root.path());
    replace_in_file(
        &rejected.join("integrations/eligibility/integration.yaml"),
        "maxLength: 18",
        "maxLength: 1025",
    );
    let error = test_registry_project(&ProjectTestOptions {
        project_directory: rejected,
        environment: None,
    })
    .expect_err("selector above the aggregate byte ceiling must be rejected before source access");
    let error = format!("{error:#}");
    assert!(
        error.contains("authored document failed canonical schema validation"),
        "{error}"
    );
    assert!(error.contains("keyword=maximum"), "{error}");
}

#[test]
fn integration_input_names_match_the_wire_grammar() {
    let accepted_root = tempfile::tempdir().expect("accepted temporary directory");
    let accepted = copy_project("custom-system", accepted_root.path());
    remove_custom_cel_claim(&accepted);
    let boundary_name = format!("a{}", "0".repeat(63));
    rename_custom_input(&accepted, &boundary_name);
    let report = build_registry_project(&ProjectBuildOptions {
        project_directory: accepted.clone(),
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect("64-byte input name builds through the production Relay compiler closure");
    let output = resolve_build_output(&accepted, report.output.expect("build output"));
    let pack: serde_json::Value = serde_json::from_slice(
        &std::fs::read(output.join(
            "private/relay-consultation/config/artifacts/integration-packs/eligibility.json",
        ))
        .expect("generated integration pack reads"),
    )
    .expect("generated integration pack parses");
    assert_eq!(
        pack["spec"]["input_slots"]
            .as_object()
            .expect("input slots")
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        vec![boundary_name]
    );

    for invalid_name in [
        format!("a{}", "0".repeat(64)),
        "bad-name".to_string(),
        "bad.name".to_string(),
    ] {
        let rejected_root = tempfile::tempdir().expect("rejected temporary directory");
        let rejected = copy_project("custom-system", rejected_root.path());
        rename_custom_input(&rejected, &invalid_name);
        let error = test_registry_project(&ProjectTestOptions {
            project_directory: rejected,
            environment: None,
        })
        .expect_err("invalid input name must be rejected before source access");
        let error = format!("{error:#}");
        assert!(error.contains("canonical schema validation"), "{error}");
        assert!(!error.contains(&invalid_name), "{error}");
    }
}

#[test]
fn integration_input_pattern_schema_matches_the_wire_limit() {
    let schema: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("schemas/project-authoring/integration.schema.json"),
        )
        .expect("integration schema reads"),
    )
    .expect("integration schema parses");
    let schema = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .expect("integration schema compiles");
    let authored: serde_norway::Value = serde_norway::from_slice(
        &std::fs::read(golden("custom-system").join("integrations/eligibility/integration.yaml"))
            .expect("integration reads"),
    )
    .expect("integration parses");
    let mut authored = serde_json::to_value(authored).expect("integration converts to JSON");
    authored["input"]["household_reference"]["pattern"] =
        serde_json::Value::String("a".repeat(16_384));
    assert!(schema.validate(&authored).is_ok());
    authored["input"]["household_reference"]["pattern"] =
        serde_json::Value::String("a".repeat(16_385));
    assert!(schema.validate(&authored).is_err());
}

#[test]
fn integration_output_schema_accepts_only_bounded_closed_recursive_shapes() {
    let schema: serde_json::Value = serde_json::from_slice(
        &std::fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("schemas/project-authoring/integration.schema.json"),
        )
        .expect("integration schema reads"),
    )
    .expect("integration schema parses");
    let schema = jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .expect("integration schema compiles");
    let authored: serde_norway::Value = serde_norway::from_slice(
        &std::fs::read(golden("opencrvs").join("integrations/birth-record/integration.yaml"))
            .expect("OpenCRVS integration reads"),
    )
    .expect("OpenCRVS integration parses");
    let authored = serde_json::to_value(authored).expect("integration converts to JSON");
    assert!(
        schema.validate(&authored).is_ok(),
        "bounded recursive output is public authoring"
    );

    let mut missing_item_ceiling = authored.clone();
    missing_item_ceiling["outputs"]["parents"]
        .as_object_mut()
        .expect("parents schema")
        .remove("max_items");
    assert!(schema.validate(&missing_item_ceiling).is_err());

    let mut open_object = authored.clone();
    open_object["outputs"]["parents"]["items"]["additionalProperties"] =
        serde_json::Value::Bool(true);
    assert!(schema.validate(&open_object).is_err());

    let mut empty_object = authored.clone();
    empty_object["outputs"]["parents"]["items"]["fields"] = serde_json::json!({});
    assert!(schema.validate(&empty_object).is_err());

    let mut nested_source_pointer = authored.clone();
    nested_source_pointer["outputs"]["parents"]["items"]["fields"]["name"]["schema"]
        ["x-registry-source"] = serde_json::json!("/name");
    assert!(schema.validate(&nested_source_pointer).is_err());

    let mut excessive_array = authored;
    excessive_array["outputs"]["parents"]["max_items"] = serde_json::json!(257);
    assert!(schema.validate(&excessive_array).is_err());
}

#[test]
fn exact_selector_authored_member_order_is_canonical() {
    let first_root = tempfile::tempdir().expect("first temporary directory");
    let second_root = tempfile::tempdir().expect("second temporary directory");
    let first = copy_project("custom-system", first_root.path());
    let second = copy_project("custom-system", second_root.path());
    remove_custom_cel_claim(&first);
    remove_custom_cel_claim(&second);
    extend_exact_selector(&first, "custom-system", 3);
    extend_exact_selector(&second, "custom-system", 3);

    reverse_yaml_mapping(
        &second.join("integrations/eligibility/integration.yaml"),
        &["input"],
    );
    reverse_yaml_mapping(
        &second.join("registry-stack.yaml"),
        &[
            "services",
            "household-eligibility",
            "consultations",
            "household",
            "input",
        ],
    );
    for fixture in std::fs::read_dir(second.join("integrations/eligibility/fixtures"))
        .expect("fixture directory")
    {
        reverse_yaml_mapping(&fixture.expect("fixture entry").path(), &["input"]);
    }

    let build = |project_directory: &Path| {
        let report = build_registry_project(&ProjectBuildOptions {
            project_directory: project_directory.to_path_buf(),
            environment: "local".to_string(),
            against: None,
            anchor: None,
        })
        .expect("ordered selector project builds");
        resolve_build_output(
            project_directory,
            report.output.expect("ordered selector build output"),
        )
    };
    let first = build(&first);
    let second = build(&second);
    for relative in [
        "private/relay-consultation/config/artifacts/integration-packs/eligibility.json",
        "private/relay-consultation/config/artifacts/consultation-contracts/household-eligibility-household.json",
        "private/relay-consultation/config/artifacts/private-bindings/household-eligibility-household.json",
    ] {
        assert_eq!(
            std::fs::read(first.join(relative)).expect("first canonical artifact"),
            std::fs::read(second.join(relative)).expect("second canonical artifact"),
            "{relative}"
        );
    }
}

#[test]
fn api_key_interfaces_keep_values_environment_only_and_use_the_stable_auth_type() {
    for (credential_type, name) in [
        ("api_key_header", "x-project-api-key"),
        ("api_key_query", "apiKey"),
    ] {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = copy_project("custom-system", temporary.path());
        remove_custom_cel_claim(&project);
        let integration = project.join("integrations/eligibility/integration.yaml");
        let mut document = read_yaml(&integration);
        document["source"]["auth"] = serde_norway::from_str(&format!(
            "type: {credential_type}\nname: {name}\nmax_value_bytes: 128\n"
        ))
        .expect("API-key interface YAML");
        write_yaml(&integration, &document);

        let environment = project.join("environments/local.yaml");
        let mut document = read_yaml(&environment);
        document["integrations"]["eligibility"]["source"]["credential"] =
            serde_norway::from_str("value: { secret: PROJECT_SOURCE_API_KEY }\ngeneration: 1\n")
                .expect("API-key environment YAML");
        write_yaml(&environment, &document);

        let report = build_registry_project(&ProjectBuildOptions {
            project_directory: project.clone(),
            environment: "local".to_string(),
            against: None,
            anchor: None,
        })
        .unwrap_or_else(|error| panic!("{credential_type} failed: {error:#}"));
        let output = resolve_build_output(&project, report.output.expect("build output"));
        let closure = directory_closure(&output);
        let joined = closure
            .iter()
            .flat_map(|(_, bytes)| bytes.iter().copied())
            .collect::<Vec<_>>();
        let generated = String::from_utf8_lossy(&joined);
        assert!(generated.contains("PROJECT_SOURCE_API_KEY"));
        assert!(!generated.contains("secret: PROJECT_SOURCE_API_KEY"));
        assert!(!generated.contains("registry-source-secret-value"));
    }

    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    let integration = project.join("integrations/eligibility/integration.yaml");
    let mut document = read_yaml(&integration);
    document["source"]["auth"] =
        serde_norway::from_str("type: api_key_header\nname: authorization\nmax_value_bytes: 128\n")
            .expect("invalid API-key header interface");
    write_yaml(&integration, &document);
    let error = test_registry_project(&ProjectTestOptions {
        project_directory: project,
        environment: None,
    })
    .expect_err("security-sensitive header must fail");
    assert!(format!("{error:#}").contains("security-sensitive"));

    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    let integration = project.join("integrations/eligibility/integration.yaml");
    let mut document = read_yaml(&integration);
    document["source"]["auth"] =
        serde_norway::from_str("type: api_key_query\nname: fields\nmax_value_bytes: 128\n")
            .expect("colliding API-key query interface");
    write_yaml(&integration, &document);
    let error = test_registry_project(&ProjectTestOptions {
        project_directory: project,
        environment: None,
    })
    .expect_err("query-name collision must fail");
    assert!(format!("{error:#}").contains("collides"));

    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    let integration = project.join("integrations/eligibility/integration.yaml");
    let mut document = read_yaml(&integration);
    document["source"]["auth"] =
        serde_norway::from_str("type: api_key_query\nname: apiKey\nmax_value_bytes: 128\n")
            .expect("API-key query interface");
    write_yaml(&integration, &document);
    let environment = project.join("environments/local.yaml");
    replace_in_file(
        &environment,
        "username: { secret: HOUSEHOLD_USERNAME }\n        password: { secret: HOUSEHOLD_PASSWORD }",
        "type: api_key_query\n        value: { secret: PROJECT_SOURCE_API_KEY }",
    );
    let error = check_registry_project(&ProjectCheckOptions {
        project_directory: project,
        environment: "local".to_string(),
        explain: false,
        against: None,
        anchor: None,
    })
    .expect_err("environment auth-type compatibility alias must fail");
    assert_authoring_diagnostic(&error, "registryctl.authoring.environment.invalid");
}

#[test]
fn dci_exact_and_and_full_date_inputs_fail_closed_before_source_access() {
    let cases = [
        (
            "response_pointer: /identifier/0/identifier_value",
            "response_pointer: /identifier/00/identifier_value",
            "canonical",
        ),
        (
            "response_pointer: /identifier/0/identifier_value",
            "response_pointer: /identifier/0/missing",
            "outside the signed record schema",
        ),
    ];
    for (from, to, expected) in cases {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = copy_project("opencrvs", temporary.path());
        replace_in_file(
            &project.join("integrations/birth-record/integration.yaml"),
            from,
            to,
        );
        let error = test_registry_project(&ProjectTestOptions {
            project_directory: project,
            environment: None,
        })
        .expect_err("invalid DCI exact conjunction must fail");
        assert!(format!("{error:#}").contains(expected), "{error:#}");
    }

    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("opencrvs", temporary.path());
    let integration_path = project.join("integrations/birth-record/integration.yaml");
    let mut integration = read_yaml(&integration_path);
    let selectors = integration["source"]["protocol"]["signed_dci"]["selectors"]
        .as_mapping_mut()
        .expect("DCI selectors");
    let uin = selectors
        .remove(serde_norway::Value::String("uin".to_string()))
        .expect("UIN selector");
    selectors.insert(serde_norway::Value::String("other".to_string()), uin);
    write_yaml(&integration_path, &integration);
    let error = test_registry_project(&ProjectTestOptions {
        project_directory: project,
        environment: None,
    })
    .expect_err("DCI must bind every authored selector exactly once");
    assert!(format!("{error:#}").contains("bind every selector exactly once"));

    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    extend_exact_selector(&project, "custom-system", 4);
    let fixture = project.join("integrations/eligibility/fixtures/source-approved.yaml");
    replace_in_file(&fixture, "2017-06-15", "2017-02-31");
    let error = test_registry_project(&ProjectTestOptions {
        project_directory: project,
        environment: None,
    })
    .expect_err("nonexistent full date must fail before source access");
    assert!(format!("{error:#}").contains("fixture full-date input selector_4 is not canonical"));

    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    extend_exact_selector(&project, "custom-system", 3);
    let fixture = project.join("integrations/eligibility/fixtures/source-approved.yaml");
    let mut document = read_yaml(&fixture);
    document["input"]
        .as_mapping_mut()
        .expect("fixture inputs")
        .remove(serde_norway::Value::String("selector_3".to_string()));
    write_yaml(&fixture, &document);
    let error = test_registry_project(&ProjectTestOptions {
        project_directory: project,
        environment: None,
    })
    .expect_err("missing composite component must fail before source access");
    assert!(format!("{error:#}").contains("must bind every"));
}

#[test]
fn opencrvs_composite_dci_uses_unified_exact_predicates_canonically() {
    let first_root = tempfile::tempdir().expect("first temporary directory");
    let second_root = tempfile::tempdir().expect("second temporary directory");
    let first = copy_project("opencrvs", first_root.path());
    let second = copy_project("opencrvs", second_root.path());
    make_opencrvs_composite_dci(&first);
    make_opencrvs_composite_dci(&second);
    reverse_yaml_mapping(
        &second.join("integrations/birth-record/integration.yaml"),
        &["input"],
    );

    let journey = test_registry_project(&ProjectTestOptions {
        project_directory: first.clone(),
        environment: None,
    })
    .expect("composite DCI fixtures execute through the offline production decoder");
    let ambiguous = journey
        .fixtures
        .iter()
        .find(|fixture| fixture.fixture == "birth-record-ambiguous")
        .expect("composite ambiguous fixture executes");
    assert_eq!(ambiguous.outcome.as_deref(), Some("ambiguous"));
    assert!(ambiguous.outputs.is_empty());
    assert!(ambiguous.claims.is_empty());
    reverse_yaml_mapping(
        &second.join("integrations/birth-record/integration.yaml"),
        &["source", "protocol", "signed_dci", "selectors"],
    );

    let build = |project_directory: &Path| {
        let report = build_registry_project(&ProjectBuildOptions {
            project_directory: project_directory.to_path_buf(),
            environment: "local".to_string(),
            against: None,
            anchor: None,
        })
        .expect("composite DCI project builds");
        resolve_build_output(
            project_directory,
            report.output.expect("composite DCI build output"),
        )
    };
    let first = build(&first);
    let second = build(&second);
    let relative =
        "private/relay-consultation/config/artifacts/integration-packs/birth-record.json";
    let first_pack = std::fs::read(first.join(relative)).expect("first DCI pack");
    let second_pack = std::fs::read(second.join(relative)).expect("second DCI pack");
    assert_eq!(first_pack, second_pack);
    let pack: serde_json::Value = serde_json::from_slice(&first_pack).expect("DCI pack JSON");
    assert!(pack["spec"]["reviewed_acquisition"]["selector"].is_null());
    let exact_and = &pack["spec"]["plan"]["script_authority"]["signed_dci"]["exact_and"];
    assert_eq!(exact_and.as_object().map(|map| map.len()), Some(3));
    assert!(exact_and
        .as_object()
        .expect("signed DCI exact predicates")
        .values()
        .all(
            |component| component["field"].is_string() && component["response_pointer"].is_string()
        ));
}

#[test]
fn oauth_refresh_skew_accepts_explicit_default_and_safe_ceiling() {
    for (authored, expected_ms) in [("30s", 30_000), ("59999ms", 59_999)] {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = copy_project("opencrvs", temporary.path());
        replace_in_file(
            &project.join("integrations/birth-record/integration.yaml"),
            "    response_profile: oauth2_bearer_no_expiry",
            &format!("    response_profile: oauth2_bearer\n    refresh_skew: {authored}"),
        );
        for fixture_name in ["match.yaml", "no-match.yaml", "ambiguous.yaml"] {
            let fixture = project
                .join("integrations/birth-record/fixtures")
                .join(fixture_name);
            let mut document = read_yaml(&fixture);
            document["interactions"][0]["respond"]["body"]["expires_in"] =
                serde_norway::from_str("60").expect("OAuth fixture expiry");
            write_yaml(&fixture, &document);
        }
        let report = build_registry_project(&ProjectBuildOptions {
            project_directory: project.clone(),
            environment: "local".to_string(),
            against: None,
            anchor: None,
        })
        .unwrap_or_else(|error| panic!("OAuth refresh skew {authored} builds: {error:#}"));
        let output =
            resolve_build_output(&project, report.output.expect("OAuth build output exists"));
        let pack: serde_json::Value = serde_json::from_slice(
            &std::fs::read(output.join(
                "private/relay-consultation/config/artifacts/integration-packs/birth-record.json",
            ))
            .expect("generated OpenCRVS integration pack reads"),
        )
        .expect("generated OpenCRVS integration pack is JSON");
        assert_eq!(
            pack["spec"]["plan"]["credential_operation"]["response"]["expiry_safety_skew_ms"],
            expected_ms
        );
    }
}

#[test]
fn oauth_no_expiry_profile_is_exact_and_disables_token_caching() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("opencrvs", temporary.path());
    test_registry_project(&ProjectTestOptions {
        project_directory: project.clone(),
        environment: None,
    })
    .expect("strict two-member OAuth fixtures execute");

    let report = build_registry_project(&ProjectBuildOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect("no-expiry OAuth project builds through the Relay compiler");
    let output = resolve_build_output(
        &project,
        report.output.expect("no-expiry OAuth build output"),
    );
    let pack: serde_json::Value = serde_json::from_slice(
        &std::fs::read(output.join(
            "private/relay-consultation/config/artifacts/integration-packs/birth-record.json",
        ))
        .expect("generated OpenCRVS integration pack reads"),
    )
    .expect("generated OpenCRVS integration pack is JSON");
    assert_eq!(
        pack["spec"]["plan"]["credential_operation"]["response"],
        serde_json::json!({
            "max_bytes": 8192,
            "accepted_statuses": [200],
            "schema": "strict_access_token_bearer_no_expiry",
            "access_token_max_bytes": 4096,
            "token_type": "Bearer",
            "cache_mode": "disabled"
        })
    );
    let binding: serde_json::Value =
        serde_json::from_slice(
            &std::fs::read(output.join(
                "private/relay-consultation/config/artifacts/private-bindings/birth-verification-birth.json",
            ))
            .expect("generated OpenCRVS private binding reads"),
        )
        .expect("generated OpenCRVS private binding is JSON");
    assert!(
        binding["limits"].get("max_token_lifetime_ms").is_none(),
        "a no-expiry token must not gain a cache lifetime from private configuration"
    );

    let skew_root = tempfile::tempdir().expect("temporary directory");
    let skew_project = copy_project("opencrvs", skew_root.path());
    replace_in_file(
        &skew_project.join("integrations/birth-record/integration.yaml"),
        "    response_profile: oauth2_bearer_no_expiry",
        "    response_profile: oauth2_bearer_no_expiry\n    refresh_skew: 20s",
    );
    let error = test_registry_project(&ProjectTestOptions {
        project_directory: skew_project,
        environment: None,
    })
    .expect_err("no-expiry profile rejects refresh skew");
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains("schema_path=/properties/source/properties/auth/oneOf keyword=oneOf"),
        "unexpected no-expiry refresh-skew diagnostic: {rendered}"
    );
    assert!(!rendered.contains("oauth2_bearer_no_expiry"));
    assert!(!rendered.contains("20s"));
}

#[test]
fn oauth_no_expiry_offline_fixtures_reject_non_production_response_shapes() {
    const EXACT_BODY: &str = "{ access_token: SYNTHETIC_FIXTURE_TOKEN, token_type: Bearer }\n";
    for (case, body, content_type) in [
        (
            "lowercase token type",
            "{ access_token: SYNTHETIC_FIXTURE_TOKEN, token_type: bearer }\n",
            Some("application/json"),
        ),
        (
            "unexpected expiry",
            "{ access_token: SYNTHETIC_FIXTURE_TOKEN, token_type: Bearer, expires_in: 60 }\n",
            Some("application/json"),
        ),
        ("missing content type", EXACT_BODY, None),
        ("wrong content type", EXACT_BODY, Some("text/plain")),
    ] {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = copy_project("opencrvs", temporary.path());
        let fixture = project.join("integrations/birth-record/fixtures/ambiguous.yaml");
        let mut document = read_yaml(&fixture);
        document["interactions"][0]["respond"]["body"] =
            serde_norway::from_str(body).expect("OAuth response fixture");
        if let Some(content_type) = content_type {
            document["interactions"][0]["respond"]["headers"]["Content-Type"] =
                serde_norway::Value::String(content_type.to_owned());
        } else {
            document["interactions"][0]["respond"]
                .as_mapping_mut()
                .expect("OAuth fixture response")
                .remove(serde_norway::Value::String("headers".to_owned()));
        }
        write_yaml(&fixture, &document);

        let error = test_registry_project_selected(
            &ProjectTestOptions {
                project_directory: project,
                environment: None,
            },
            &ProjectTestSelection {
                integration: Some("birth-record".to_string()),
                fixture: Some("birth-record-ambiguous".to_string()),
                trace: true,
            },
        )
        .unwrap_err();
        let rendered = format!("{error:#}");
        assert!(
            rendered.contains("source.response_malformed"),
            "{case} must fail through the production OAuth response contract: {rendered}"
        );
    }
}

fn validate_yaml(schema: &jsonschema::JSONSchema, path: &Path) {
    let authored: serde_norway::Value = serde_norway::from_slice(
        &std::fs::read(path).unwrap_or_else(|error| panic!("{}: {error}", path.display())),
    )
    .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    let authored = serde_json::to_value(authored).expect("YAML converts to JSON");
    if let Err(errors) = schema.validate(&authored) {
        let messages = errors.map(|error| error.to_string()).collect::<Vec<_>>();
        panic!("schema rejected {}: {messages:?}", path.display());
    };
}

#[test]
fn check_and_build_produce_deterministic_product_inputs() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    let check = check_registry_project(&ProjectCheckOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        explain: true,
        against: None,
        anchor: None,
    })
    .expect("golden project checks");
    assert_eq!(check.status, "valid");
    assert_eq!(check.semantic_changes.len(), 5);
    assert_eq!(
        check
            .semantic_changes
            .iter()
            .map(|change| change.dimension)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "claim",
            "disclosure",
            "integration",
            "operator_security",
            "service_policy",
        ])
    );
    let explanation = check.explanation.expect("explanation is present");
    assert_eq!(
        public_explanation_value(integration_explanation_field(
            &explanation,
            "eligibility",
            "/capability/type",
        )),
        &serde_json::json!("http")
    );
    assert_eq!(
        public_explanation_value(project_explanation_field(
            &explanation,
            "/services/household-eligibility/consultation_count",
        )),
        &serde_json::json!(1)
    );
    assert!(matches!(
        project_explanation_field(
            &explanation,
            "/services/household-eligibility/claims/source-household-approval-decision/cel",
        )
        .reported_value,
        ClassifierSafeReportedValue::Redacted { .. }
    ));
    assert!(matches!(
        environment_explanation_field(
            &explanation,
            "local",
            "/integrations/eligibility/source/origin",
        )
        .reported_value,
        ClassifierSafeReportedValue::Redacted { .. }
    ));
    let serialized_explanation =
        serde_json::to_string(&explanation).expect("typed explanation serializes");
    for forbidden in [
        "household-authority.invalid",
        "HOUSEHOLD_USERNAME",
        "HOUSEHOLD_PASSWORD",
        "household.matched &&",
        "BENEFITS_CLIENT_TOKEN_HASH",
    ] {
        assert!(
            !serialized_explanation.contains(forbidden),
            "explanation must not report {forbidden}"
        );
    }
    assert!(
        !serialized_explanation.contains("generated_pack")
            && !serialized_explanation.contains("policy_hash")
            && !serialized_explanation.contains("contract_hash"),
        "explanation reports authored/effective intent, not generated configuration"
    );

    let options = ProjectBuildOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        against: None,
        anchor: None,
    };
    let first = build_registry_project(&options).expect("first build");
    let output = resolve_build_output(&project, first.output.expect("build output"));
    let notary_config = std::fs::read_to_string(output.join("private/notary/config/notary.yaml"))
        .expect("generated Notary config");
    let notary_document: serde_norway::Value =
        serde_norway::from_str(&notary_config).expect("generated Notary config parses");
    assert!(
        notary_document.get("cel").is_none(),
        "absent authoring must preserve the Notary product default"
    );
    assert!(notary_config.contains("type: consultation_output"));
    assert!(notary_config.contains("consultation: household"));
    assert!(notary_config.contains("output: category"));
    assert!(!notary_config.contains("type: extract"));
    assert!(!notary_config.contains("type: exists"));
    let public_contract: serde_json::Value = serde_json::from_slice(
        &std::fs::read(output.join(
            "private/relay-consultation/config/artifacts/consultation-contracts/household-eligibility-household.json",
        ))
        .expect("generated public contract reads"),
    )
    .expect("generated public contract parses");
    assert_eq!(
        public_contract["spec"]["integration"],
        serde_json::json!({
            "id": "fictional-household-authority.fictional-household-eligibility",
            "revision": 1,
        })
    );
    assert!(public_contract["spec"].get("integration_pack").is_none());
    let first_closure = directory_closure(&output);
    build_registry_project(&options).expect("second build");
    assert_eq!(first_closure, directory_closure(&output));
    assert_eq!(
        closure_digest(&first_closure),
        "421d7552007ed5cb2501c93f303ea6358ba78516b6e769d51749416cbbec2005",
        "project output, including its deterministic manifest, must match the cross-machine golden digest"
    );
}

#[test]
fn build_artifact_manifest_is_complete_relative_private_and_deterministic() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    let options = ProjectBuildOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        against: None,
        anchor: None,
    };

    let first = build_registry_project(&options).expect("first manifest build");
    let first_report = serde_json::to_value(&first).expect("first build report serializes");
    let output_relative = first_report["output"]
        .as_str()
        .expect("build output is reported");
    assert_eq!(output_relative, ".registry-stack/build/local");
    assert!(!Path::new(output_relative).is_absolute());
    let manifest_reference = first_report["artifact_manifest"]
        .as_object()
        .expect("build report references its artifact manifest");
    let manifest_relative = manifest_reference["path"]
        .as_str()
        .expect("manifest reference path");
    assert_eq!(
        manifest_relative,
        ".registry-stack/build/local/artifact-manifest.json"
    );
    assert!(!Path::new(manifest_relative).is_absolute());

    let output = project.join(output_relative);
    let manifest_path = project.join(manifest_relative);
    let first_manifest_bytes = std::fs::read(&manifest_path).expect("artifact manifest reads");
    assert_eq!(
        manifest_reference["digest"],
        test_sha256_uri(&first_manifest_bytes)
    );
    assert_eq!(first_manifest_bytes.last(), Some(&b'\n'));
    let manifest: serde_json::Value =
        serde_json::from_slice(&first_manifest_bytes).expect("artifact manifest parses");
    assert_eq!(
        manifest["schema_version"],
        "registry.project.artifact_manifest.v1"
    );
    assert_eq!(
        manifest["format_version"],
        "registry.project.artifact_manifest.format.v1"
    );
    assert_eq!(manifest["environment"], "local");
    assert_eq!(manifest["generator"]["name"], "registryctl");

    let inputs = manifest["inputs"]
        .as_array()
        .expect("manifest authored inputs");
    assert!(!inputs.is_empty());
    let input_paths = inputs
        .iter()
        .map(|input| input["path"].as_str().expect("input path"))
        .collect::<Vec<_>>();
    assert!(input_paths.windows(2).all(|pair| pair[0] < pair[1]));
    for input in inputs {
        let relative = input["path"].as_str().expect("input path");
        assert!(!Path::new(relative).is_absolute());
        assert!(!relative.starts_with(".registry-stack/"));
        assert_eq!(
            input["digest"],
            test_sha256_uri(
                &std::fs::read(project.join(relative)).expect("authored manifest input reads")
            )
        );
        assert_eq!(input["classification"], "authored_project_input");
    }

    let artifacts = manifest["artifacts"]
        .as_array()
        .expect("manifest generated artifacts");
    let artifact_paths = artifacts
        .iter()
        .map(|artifact| artifact["path"].as_str().expect("artifact path"))
        .collect::<Vec<_>>();
    assert!(artifact_paths.windows(2).all(|pair| pair[0] < pair[1]));
    assert!(!artifact_paths.contains(&manifest_relative));
    for artifact in artifacts {
        let relative = artifact["path"].as_str().expect("generated artifact path");
        let payload_relative = relative
            .strip_prefix(&format!("{output_relative}/"))
            .expect("artifact is under the reported environment output");
        assert_eq!(
            artifact["digest"],
            test_sha256_uri(
                &std::fs::read(output.join(payload_relative))
                    .expect("manifest payload artifact reads")
            )
        );
        assert!(artifact["format_version"].as_str().is_some());
        assert!(!artifact["classes"]
            .as_array()
            .expect("artifact classes")
            .is_empty());
        assert!(artifact["sensitivity"].as_str().is_some());
        assert!(artifact["publication"].as_str().is_some());
        assert_eq!(artifact["edit"], "generated_do_not_edit");
        assert_eq!(artifact["version_control"], "ignore");
        assert!(artifact["review"].as_str().is_some());
        assert_eq!(artifact["lifecycle"], "unsigned_non_deployable");
        let actions = artifact["actions"].as_array().expect("artifact actions");
        assert!(actions.iter().any(|action| action == "regenerate"));
        assert!(actions.iter().any(|action| action == "compare"));
        assert!(actions.iter().any(|action| action == "validate"));
        assert!(actions.iter().any(|action| action == "discard"));
        let consumers = artifact["consumers"]
            .as_array()
            .expect("artifact consumers");
        assert!(!consumers.is_empty());
        if payload_relative.starts_with("private/relay-public/")
            || payload_relative.starts_with("private/relay-consultation/")
        {
            assert!(!consumers
                .iter()
                .any(|consumer| consumer == "registry_notary"));
        }
        if payload_relative.starts_with("private/notary/") {
            assert!(!consumers
                .iter()
                .any(|consumer| consumer == "registry_relay"));
        }
        if matches!(
            payload_relative,
            "private/relay-public/config/relay.yaml"
                | "private/relay-consultation/config/relay.yaml"
                | "private/notary/config/notary.yaml"
        ) {
            assert_eq!(artifact["sensitivity"], "topology_sensitive");
            assert_eq!(artifact["publication"], "never_publish");
            assert!(consumers
                .iter()
                .any(|consumer| consumer == "deployment_tooling"));
        }
    }

    let filesystem_payloads = directory_closure(&output)
        .into_iter()
        .filter_map(|(path, _)| {
            (path != Path::new("artifact-manifest.json")).then(|| {
                format!(
                    "{output_relative}/{}",
                    path.to_str().expect("generated path is Unicode")
                )
            })
        })
        .collect::<Vec<_>>();
    assert_eq!(
        artifact_paths.iter().copied().collect::<BTreeSet<_>>(),
        filesystem_payloads
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
    );

    let report_json = serde_json::to_vec(&first).expect("build report serializes");
    let project_absolute = project.to_string_lossy();
    assert!(!String::from_utf8_lossy(&first_manifest_bytes).contains(project_absolute.as_ref()));
    assert!(!String::from_utf8_lossy(&report_json).contains(project_absolute.as_ref()));
    assert!(!String::from_utf8_lossy(&first_manifest_bytes).contains(".tmp-"));

    let second = build_registry_project(&options).expect("second manifest build");
    let second_report = serde_json::to_value(&second).expect("second build report serializes");
    let second_manifest_bytes =
        std::fs::read(&manifest_path).expect("second artifact manifest reads");
    assert_eq!(first_manifest_bytes, second_manifest_bytes);
    assert_eq!(
        first_report["artifact_manifest"],
        second_report["artifact_manifest"]
    );
}

#[cfg(feature = "relay-contract-test-support")]
#[test]
fn generated_relay_contract_activates_through_notary_exactly_and_rejects_a_stale_pin() {
    use registry_notary_core::{ClaimEvidenceMode, StandaloneRegistryNotaryConfig};

    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    let integration_path = project.join("integrations/eligibility/integration.yaml");
    let mut integration = read_yaml(&integration_path);
    integration["limits"] = serde_norway::from_str("deadline: 20s\n")
        .expect("reviewed deadline boundary is valid YAML");
    write_yaml(&integration_path, &integration);
    let build = build_registry_project(&ProjectBuildOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect("combined project builds");
    let output = resolve_build_output(&project, build.output.expect("build output"));
    let contract_path = output.join(
        "private/relay-consultation/config/artifacts/consultation-contracts/household-eligibility-household.json",
    );
    let contract_bytes = std::fs::read(&contract_path).expect("Relay contract artifact reads");
    let contract: serde_json::Value =
        serde_json::from_slice(&contract_bytes).expect("Relay contract artifact parses");
    assert_eq!(contract["spec"]["bounds"]["timeout_ms"], 20_000);
    let notary: StandaloneRegistryNotaryConfig = serde_norway::from_slice(
        &std::fs::read(output.join("private/notary/config/notary.yaml"))
            .expect("Notary config reads"),
    )
    .expect("generated Notary config parses through its production model");
    let relay = notary
        .evidence
        .relay
        .as_ref()
        .expect("combined deployment has one Relay workload");
    let claim = notary
        .evidence
        .claims
        .iter()
        .find(|claim| claim.id == "household-category")
        .expect("registry-backed claim");
    let ClaimEvidenceMode::RegistryBacked { consultations } = &claim.evidence_mode else {
        panic!("household category remains registry-backed");
    };
    let consultation = consultations
        .values()
        .next()
        .expect("claim has one Relay consultation");
    let input_names = consultation.inputs.keys().cloned().collect::<Vec<_>>();
    let purpose = claim.purpose.as_deref().expect("claim purpose is explicit");

    assert!(
        registry_notary_server::relay_contract_test_support::verifies_contract_artifact(
            &contract_bytes,
            &consultation.profile.contract_hash,
            &consultation.profile.id,
            &relay.workload_client_id,
            purpose,
            &input_names,
            &consultation.outputs,
        ),
        "Notary must activate the exact compiler-produced contract and pin"
    );

    let mut mutated: serde_json::Value =
        serde_json::from_slice(&contract_bytes).expect("contract artifact parses");
    mutated["spec"]["output"]["category"]["max_bytes"] = serde_json::json!(84);
    let mutated = serde_json::to_vec(&mutated).expect("mutated envelope serializes");
    assert!(
        !registry_notary_server::relay_contract_test_support::verifies_contract_artifact(
            &mutated,
            &consultation.profile.contract_hash,
            &consultation.profile.id,
            &relay.workload_client_id,
            purpose,
            &input_names,
            &consultation.outputs,
        ),
        "a contract mutation cannot activate under the prior Notary pin"
    );
}

#[cfg(feature = "relay-contract-test-support")]
#[test]
fn generated_snapshot_contracts_activate_through_notary_at_the_authoring_bound() {
    use registry_notary_core::{ClaimEvidenceMode, StandaloneRegistryNotaryConfig};

    for (authored_max_bytes, expected_max_bytes) in [
        ("256MiB", 256 * 1_024 * 1_024_u64),
        ("512MiB", 512 * 1_024 * 1_024_u64),
        ("1024MiB", 1_024 * 1_024 * 1_024_u64),
    ] {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = copy_project("snapshot-exact", temporary.path());
        let entity_path = project.join("entities/people.yaml");
        let mut entity = read_yaml(&entity_path);
        entity["materialization"]["max_bytes"] =
            serde_norway::Value::String(authored_max_bytes.to_string());
        write_yaml(&entity_path, &entity);

        let build = build_registry_project(&ProjectBuildOptions {
            project_directory: project.clone(),
            environment: "local".to_string(),
            against: None,
            anchor: None,
        })
        .expect("snapshot project builds within the authored materialization bound");
        let output = resolve_build_output(&project, build.output.expect("build output"));
        let contract_bytes = std::fs::read(output.join(
            "private/relay-consultation/config/artifacts/consultation-contracts/benefits-eligibility-person.json",
        ))
        .expect("snapshot Relay contract reads");
        let contract: serde_json::Value =
            serde_json::from_slice(&contract_bytes).expect("snapshot Relay contract parses");
        assert_eq!(
            contract["spec"]["materialization"]["footprint"]["max_source_bytes"].as_u64(),
            Some(expected_max_bytes)
        );

        let notary: StandaloneRegistryNotaryConfig = serde_norway::from_slice(
            &std::fs::read(output.join("private/notary/config/notary.yaml"))
                .expect("Notary config reads"),
        )
        .expect("generated Notary config parses");
        let relay = notary.evidence.relay.as_ref().expect("Relay workload");
        let claim = notary
            .evidence
            .claims
            .iter()
            .find(|claim| claim.id == "population-registration-status")
            .expect("registry-backed snapshot claim");
        let ClaimEvidenceMode::RegistryBacked { consultations } = &claim.evidence_mode else {
            panic!("snapshot claim remains registry-backed");
        };
        let consultation = consultations
            .values()
            .next()
            .expect("one snapshot consultation");
        let input_names = consultation.inputs.keys().cloned().collect::<Vec<_>>();
        let purpose = claim.purpose.as_deref().expect("claim purpose");
        assert!(
            registry_notary_server::relay_contract_test_support::verifies_contract_artifact(
                &contract_bytes,
                &consultation.profile.contract_hash,
                &consultation.profile.id,
                &relay.workload_client_id,
                purpose,
                &input_names,
                &consultation.outputs,
            ),
            "Notary must activate the {authored_max_bytes} compiler-produced snapshot contract"
        );
    }
}

#[cfg(feature = "relay-contract-test-support")]
#[test]
fn script_only_change_moves_the_relay_closure_without_forking_the_public_contract() {
    use registry_notary_core::{ClaimEvidenceMode, StandaloneRegistryNotaryConfig};

    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("dhis2-script", temporary.path());
    let options = ProjectBuildOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        against: None,
        anchor: None,
    };
    let first = build_registry_project(&options).expect("initial Script project builds");
    let first_output = resolve_build_output(&project, first.output.expect("initial build output"));
    let contract_relative =
        "private/relay-consultation/config/artifacts/consultation-contracts/health-verification-health.json";
    let pack_relative =
        "private/relay-consultation/config/artifacts/integration-packs/health-record.json";
    let binding_relative =
        "private/relay-consultation/config/artifacts/private-bindings/health-verification-health.json";
    let first_contract =
        std::fs::read(first_output.join(contract_relative)).expect("initial contract reads");
    let first_pack =
        std::fs::read(first_output.join(pack_relative)).expect("initial integration pack reads");
    let first_binding =
        std::fs::read(first_output.join(binding_relative)).expect("initial private binding reads");
    let notary: StandaloneRegistryNotaryConfig = serde_norway::from_slice(
        &std::fs::read(first_output.join("private/notary/config/notary.yaml"))
            .expect("initial Notary config reads"),
    )
    .expect("initial Notary config parses");
    let relay = notary.evidence.relay.as_ref().expect("Relay workload");
    let claim = notary
        .evidence
        .claims
        .iter()
        .find(|claim| claim.id == "tracked-entity-first-name")
        .expect("registry-backed Script claim");
    let ClaimEvidenceMode::RegistryBacked { consultations } = &claim.evidence_mode else {
        panic!("Script claim remains registry-backed");
    };
    let consultation = consultations.values().next().expect("one consultation");
    let first_hash = consultation.profile.contract_hash.clone();
    let input_names = consultation.inputs.keys().cloned().collect::<Vec<_>>();
    let purpose = claim.purpose.as_deref().expect("claim purpose");
    assert!(
        registry_notary_server::relay_contract_test_support::verifies_contract_artifact(
            &first_contract,
            &first_hash,
            &consultation.profile.id,
            &relay.workload_client_id,
            purpose,
            &input_names,
            &consultation.outputs,
        ),
        "Notary accepts the initial Script contract under its generated pin"
    );

    let script_path = project.join("integrations/health-record/adapter.rhai");
    let mut script = std::fs::read_to_string(&script_path).expect("Script reads");
    script.push_str("\n// reviewed script-only contract change\n");
    std::fs::write(&script_path, script).expect("Script change writes");
    let second = build_registry_project(&options).expect("changed Script project builds");
    let second_output =
        resolve_build_output(&project, second.output.expect("changed build output"));
    let second_contract =
        std::fs::read(second_output.join(contract_relative)).expect("changed contract reads");
    let second_pack =
        std::fs::read(second_output.join(pack_relative)).expect("changed integration pack reads");
    let second_binding =
        std::fs::read(second_output.join(binding_relative)).expect("changed private binding reads");
    let second_notary: StandaloneRegistryNotaryConfig = serde_norway::from_slice(
        &std::fs::read(second_output.join("private/notary/config/notary.yaml"))
            .expect("changed Notary config reads"),
    )
    .expect("changed Notary config parses");
    let second_claim = second_notary
        .evidence
        .claims
        .iter()
        .find(|claim| claim.id == "tracked-entity-first-name")
        .expect("changed Script claim");
    let ClaimEvidenceMode::RegistryBacked {
        consultations: second_consultations,
    } = &second_claim.evidence_mode
    else {
        panic!("changed Script claim remains registry-backed");
    };
    let second_hash = &second_consultations
        .values()
        .next()
        .expect("changed consultation")
        .profile
        .contract_hash;
    assert_eq!(
        first_hash.as_str(),
        second_hash,
        "a script-only implementation change must preserve an unchanged public semantic contract"
    );
    assert_eq!(
        first_contract, second_contract,
        "the public consultation contract contains semantics, not Relay implementation bytes"
    );
    assert_ne!(
        first_pack, second_pack,
        "reviewed Script bytes must remain hash-covered by the Relay integration pack"
    );
    assert_ne!(
        first_binding, second_binding,
        "the Relay private binding must move with its hash-covered integration pack"
    );
    assert!(
        registry_notary_server::relay_contract_test_support::verifies_contract_artifact(
            &second_contract,
            &first_hash,
            &consultation.profile.id,
            &relay.workload_client_id,
            purpose,
            &input_names,
            &consultation.outputs,
        ),
        "Notary verifies the unchanged public semantics while Relay verifies the changed private closure"
    );
}

#[test]
fn records_and_snapshot_share_one_generated_materialization() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("snapshot-with-records", temporary.path());
    let build = build_registry_project(&ProjectBuildOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect("records plus evidence golden builds through production validation");
    let output = resolve_build_output(&project, build.output.expect("build output"));
    let relay_root = output.join("private/relay-public");
    let relay: serde_json::Value = serde_norway::from_slice(
        &std::fs::read(relay_root.join("config/relay.yaml")).expect("Relay config reads"),
    )
    .expect("Relay config parses");
    let datasets = relay["datasets"]
        .as_array()
        .expect("datasets are generated");
    assert_eq!(datasets.len(), 1);
    let dataset = &datasets[0];
    assert_eq!(dataset["id"], "people");
    let tables = dataset["tables"].as_array().expect("private table exists");
    assert_eq!(tables.len(), 1, "one source must produce one ingest plan");
    let resource = tables[0]["id"].as_str().expect("resource id");
    let provider = format!("people__{resource}");
    assert_eq!(
        dataset["entities"].as_array().expect("entity exists").len(),
        1
    );
    let entity = &dataset["entities"][0];
    assert_eq!(entity["table"], resource);
    assert_eq!(entity["api"]["default_limit"], 50);
    assert_eq!(entity["api"]["max_limit"], 100);
    assert_eq!(entity["api"]["require_purpose_header"], true);
    assert_eq!(
        entity["api"]["required_filter_bindings"][0]["source"],
        "principal_id"
    );
    assert!(entity["api"]["allowed_filters"]
        .as_array()
        .is_some_and(|filters| filters.len() == 1));
    assert!(entity["relationships"]
        .as_array()
        .is_some_and(Vec::is_empty));
    assert!(entity["aggregates"].as_array().is_some_and(Vec::is_empty));

    let binding_root = output.join("private/relay-consultation/config/artifacts/private-bindings");
    let mut binding_count = 0;
    for entry in std::fs::read_dir(binding_root).expect("private bindings read") {
        let binding: serde_json::Value = serde_json::from_slice(
            &std::fs::read(entry.expect("binding entry").path()).expect("binding reads"),
        )
        .expect("binding parses");
        assert_eq!(binding["materialization"]["table_provider"], provider);
        binding_count += 1;
    }
    assert_eq!(
        binding_count, 2,
        "both evidence purposes share the provider"
    );

    let review: serde_json::Value = serde_json::from_slice(
        &std::fs::read(output.join("reviewable/review.json")).expect("review reads"),
    )
    .expect("review parses");
    assert_eq!(
        review["entity_materializations"]["people"]["materialization_identity"],
        resource
    );
    assert_eq!(
        review["entity_materializations"]["people"]["table_provider"],
        provider
    );
    assert!(review["entity_materializations"]["people"]["provider"].is_object());
    assert!(review["entity_materializations"]["people"]["columns"].is_object());
    assert!(review["entity_materializations"]["people"]
        .get("provider_digest")
        .is_none());
}

#[test]
fn materialization_size_boundary_accepts_integer_ceiling_and_rejects_human_above() {
    let at_boundary = tempfile::tempdir().expect("boundary temporary directory");
    let boundary_project = copy_project("snapshot-exact", at_boundary.path());
    let boundary_entity_path = boundary_project.join("entities/people.yaml");
    let mut boundary_entity = read_yaml(&boundary_entity_path);
    boundary_entity["materialization"]["max_bytes"] =
        serde_norway::Value::Number(1_073_741_824_u64.into());
    write_yaml(&boundary_entity_path, &boundary_entity);
    build_registry_project(&ProjectBuildOptions {
        project_directory: boundary_project,
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect("integer materialization size at 1 GiB builds");

    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("snapshot-exact", temporary.path());
    let entity_path = project.join("entities/people.yaml");
    let mut entity = read_yaml(&entity_path);
    entity["materialization"]["max_bytes"] = serde_norway::Value::String("1025MiB".to_string());
    write_yaml(&entity_path, &entity);

    let error = build_registry_project(&ProjectBuildOptions {
        project_directory: project,
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect_err("human-readable materialization size above 1 GiB rejects");
    let rendered = format!("{error:#}");
    assert!(
        rendered.contains("authored document failed canonical schema validation")
            && rendered.contains("keyword=oneOf"),
        "unexpected error: {rendered}"
    );
}

#[test]
fn materialization_only_project_checks_but_emits_no_partial_governed_build() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("relay-only-materialization", temporary.path());
    check_registry_project(&ProjectCheckOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        explain: true,
        against: None,
        anchor: None,
    })
    .expect("materialization-only Relay project checks");
    let error = build_registry_project(&ProjectBuildOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect_err("materialization-only Relay project cannot emit a partial governed build");
    let message = format!("{error:#}");
    assert!(message.contains("governed build requires"));
    assert!(message.contains("add deployment.notary before project build"));
    assert!(
        !project.join(".registry-stack/build/local").exists(),
        "a rejected partial topology must not leave deployable-looking output"
    );
}

#[test]
fn relay_oidc_clients_are_separate_from_the_notary_consultation_workload() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    let build = build_registry_project(&ProjectBuildOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect("combined project builds with separate Relay identities");
    let output = resolve_build_output(&project, build.output.expect("build output"));
    let relay = read_yaml(&output.join("private/relay-public/config/relay.yaml"));
    let consultation_relay =
        read_yaml(&output.join("private/relay-consultation/config/relay.yaml"));
    let allowed_clients = relay["auth"]["oidc"]["allowed_clients"]
        .as_sequence()
        .expect("Relay OIDC allowed clients");
    assert!(allowed_clients
        .iter()
        .any(|client| client.as_str() == Some("household-relay-client")));
    assert!(!allowed_clients
        .iter()
        .any(|client| client.as_str() == Some("household-notary")));
    let consultation_allowed_clients = consultation_relay["auth"]["oidc"]["allowed_clients"]
        .as_sequence()
        .expect("consultation Relay OIDC allowed clients");
    assert_eq!(
        consultation_allowed_clients
            .iter()
            .filter_map(serde_norway::Value::as_str)
            .collect::<Vec<_>>(),
        vec!["household-notary"]
    );
    assert_eq!(
        consultation_relay["consultation"]["authorized_workload"]["client_value"].as_str(),
        Some("household-notary")
    );
    assert_eq!(
        consultation_relay["consultation"]["authorized_workload"]["principal_id"].as_str(),
        Some("household-notary")
    );
    assert_ne!(
        consultation_relay["consultation"]["authorized_workload"]["client_value"].as_str(),
        Some("household-relay-client")
    );
}

#[test]
fn local_loopback_relay_topology_is_explicit_and_nonportable() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    let environment_path = project.join("environments/local.yaml");
    let mut environment = read_yaml(&environment_path);
    environment["relay"]["origin"] =
        serde_norway::Value::String("HTTP://127.0.0.1:18080".to_string());
    environment["relay"]["issuer"] =
        serde_norway::Value::String("HTTP://127.0.0.1:18090".to_string());
    environment["relay"]["jwks_url"] =
        serde_norway::Value::String("HTTP://127.0.0.1:18090/jwks.json".to_string());
    environment["notary_relay"]["base_url"] =
        serde_norway::Value::String("HTTP://127.0.0.1:18081".to_string());
    environment["notary_state"] = serde_norway::from_str(
        "postgresql:\n  root_certificate_path: /run/secrets/notary-postgres-ca.pem\n",
    )
    .expect("Notary state binding parses");
    environment["relay_state"] = serde_norway::from_str(
        "postgresql:\n  root_certificate_path: /run/secrets/relay-postgres-ca.pem\n",
    )
    .expect("Relay state binding parses");
    environment["notary_cel"] = serde_norway::from_str("worker_memory_bytes: 1073741824\n")
        .expect("Notary CEL binding parses");
    write_yaml(&environment_path, &environment);

    let build = build_registry_project(&ProjectBuildOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect("local IP-loopback Relay, issuer, and JWKS build");
    let output = resolve_build_output(&project, build.output.expect("build output"));
    let relay = read_yaml(&output.join("private/relay-public/config/relay.yaml"));
    assert_eq!(
        relay["auth"]["oidc"]["allow_dev_insecure_fetch_urls"].as_bool(),
        Some(true)
    );
    let consultation_relay =
        read_yaml(&output.join("private/relay-consultation/config/relay.yaml"));
    assert_eq!(
        consultation_relay["consultation"]["state_plane"]["root_certificate_path"].as_str(),
        Some("/run/secrets/relay-postgres-ca.pem")
    );
    let notary = read_yaml(&output.join("private/notary/config/notary.yaml"));
    assert_eq!(notary["state"]["storage"].as_str(), Some("postgresql"));
    assert_eq!(
        notary["state"]["postgresql"]["url_env"].as_str(),
        Some("REGISTRY_NOTARY_POSTGRES_URL")
    );
    assert!(notary["state"]["postgresql"]
        .get("connect_timeout_ms")
        .is_none());
    assert!(notary["state"]["postgresql"]
        .get("operation_timeout_ms")
        .is_none());
    assert!(notary["state"]["postgresql"]
        .get("max_connections")
        .is_none());
    assert_eq!(
        notary["state"]["postgresql"]["root_certificate_path"].as_str(),
        Some("/run/secrets/notary-postgres-ca.pem")
    );
    assert_eq!(
        notary["cel"]["worker_memory_bytes"].as_u64(),
        Some(1_073_741_824)
    );
    assert_eq!(
        notary["evidence"]["relay"]["allow_insecure_localhost"].as_bool(),
        Some(true)
    );
    assert_eq!(
        notary["evidence"]["relay"]["base_url"].as_str(),
        Some("http://127.0.0.1:18081")
    );

    for (name, profile, origin, issuer, jwks_url, expected) in [
        (
            "hosted loopback",
            "hosted_lab",
            "http://127.0.0.1:18080",
            "http://127.0.0.1:18090",
            "http://127.0.0.1:18090/jwks.json",
            "Relay origin must be an exact HTTPS origin",
        ),
        (
            "local private-network",
            "local",
            "http://10.42.0.8:18080",
            "http://10.42.0.9:18090",
            "http://10.42.0.9:18090/jwks.json",
            "Relay origin must be an exact HTTPS origin",
        ),
    ] {
        let rejected_root = tempfile::tempdir().expect("rejected temporary directory");
        let rejected = copy_project("custom-system", rejected_root.path());
        let environment_path = rejected.join("environments/local.yaml");
        let mut environment = read_yaml(&environment_path);
        environment["deployment"]["profile"] = serde_norway::Value::String(profile.to_string());
        environment["relay"]["origin"] = serde_norway::Value::String(origin.to_string());
        environment["relay"]["issuer"] = serde_norway::Value::String(issuer.to_string());
        environment["relay"]["jwks_url"] = serde_norway::Value::String(jwks_url.to_string());
        write_yaml(&environment_path, &environment);
        let error = check_registry_project(&ProjectCheckOptions {
            project_directory: rejected,
            environment: "local".to_string(),
            explain: false,
            against: None,
            anchor: None,
        })
        .unwrap_err();
        let _ = (name, expected);
        assert_authoring_diagnostic(&error, "registryctl.authoring.environment.invalid");
    }
}

#[test]
fn hosted_notary_can_use_an_explicit_loopback_relay_connection() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    let environment_path = project.join("environments/local.yaml");
    let mut environment = read_yaml(&environment_path);
    environment["deployment"]["profile"] = serde_norway::Value::String("hosted_lab".to_string());
    environment["notary_relay"]["base_url"] =
        serde_norway::Value::String("http://127.0.0.1:18080".to_string());
    environment["notary_state"] = serde_norway::from_str(
        "postgresql:\n  root_certificate_path: /run/secrets/notary-postgres-ca.pem\n",
    )
    .expect("hosted Notary state binding parses");
    write_yaml(&environment_path, &environment);

    let build = build_registry_project(&ProjectBuildOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect("hosted project builds with a private loopback Notary-to-Relay connection");
    let output = resolve_build_output(&project, build.output.expect("build output"));
    let relay = read_yaml(&output.join("private/relay-public/config/relay.yaml"));
    assert_eq!(
        relay["catalog"]["base_url"].as_str(),
        Some("https://household-relay.internal.invalid")
    );
    let notary = read_yaml(&output.join("private/notary/config/notary.yaml"));
    assert_eq!(
        notary["evidence"]["relay"]["base_url"].as_str(),
        Some("http://127.0.0.1:18080")
    );
    assert_eq!(
        notary["evidence"]["relay"]["allow_insecure_localhost"].as_bool(),
        Some(true)
    );

    let rejected_root = tempfile::tempdir().expect("rejected temporary directory");
    let rejected = copy_project("custom-system", rejected_root.path());
    let rejected_environment_path = rejected.join("environments/local.yaml");
    let mut rejected_environment = read_yaml(&rejected_environment_path);
    rejected_environment["notary_relay"]["base_url"] =
        serde_norway::Value::String("http://10.42.0.8:8080".to_string());
    write_yaml(&rejected_environment_path, &rejected_environment);
    let error = check_registry_project(&ProjectCheckOptions {
        project_directory: rejected,
        environment: "local".to_string(),
        explain: false,
        against: None,
        anchor: None,
    })
    .expect_err("private-network cleartext Notary-to-Relay URL must fail");
    assert_authoring_diagnostic(&error, "registryctl.authoring.environment.invalid");
}

#[test]
fn issuance_accepts_a_full_verification_method_kid() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    let environment_path = project.join("environments/local.yaml");
    let mut environment = read_yaml(&environment_path);
    let kid = "did:web:household-notary.invalid#issuer-key-1";
    environment["issuance"]["signing_kid"] = serde_norway::Value::String(kid.to_string());
    write_yaml(&environment_path, &environment);

    let build = build_registry_project(&ProjectBuildOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect("a full verification-method kid builds");
    let output = resolve_build_output(&project, build.output.expect("build output"));
    let notary = read_yaml(&output.join("private/notary/config/notary.yaml"));
    assert_eq!(
        notary["evidence"]["signing_keys"]["project-issuer"]["kid"].as_str(),
        Some(kid)
    );

    let rejected_root = tempfile::tempdir().expect("rejected temporary directory");
    let rejected = copy_project("custom-system", rejected_root.path());
    let environment_path = rejected.join("environments/local.yaml");
    let mut environment = read_yaml(&environment_path);
    environment["issuance"]["signing_kid"] =
        serde_norway::Value::String("did:web:issuer.invalid#bad kid".to_string());
    write_yaml(&environment_path, &environment);
    let error = check_registry_project(&ProjectCheckOptions {
        project_directory: rejected,
        environment: "local".to_string(),
        explain: false,
        against: None,
        anchor: None,
    })
    .unwrap_err();
    assert_authoring_diagnostic(&error, "registryctl.authoring.environment.invalid");
}

#[test]
fn authored_oid4vci_binding_generates_the_complete_notary_owned_issuer() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    let project_path = project.join("registry-stack.yaml");
    let mut document = read_yaml(&project_path);
    document["services"]["household-eligibility"]["credential_profiles"]["household-eligibility"]
        ["claims"] = serde_norway::from_str("[household-record-exists]")
        .expect("single registry-backed credential claim");
    write_yaml(&project_path, &document);
    author_oid4vci_binding(
        &project,
        "household-eligibility",
        "household-eligibility",
        "household_reference",
    );
    let baseline_build = build_registry_project(&ProjectBuildOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect("OID4VCI project without registrar clients remains compatible");
    let baseline_output = resolve_build_output(
        &project,
        baseline_build.output.expect("baseline build output"),
    );
    let baseline_approval: serde_json::Value = serde_json::from_slice(
        &std::fs::read(baseline_output.join("private/notary/approval/project-state.json"))
            .expect("baseline approval state reads"),
    )
    .expect("baseline approval state parses");
    merge_environment_yaml(
        &project.join("environments/local.yaml"),
        "oid4vci:\n  registrar_clients: [benefits-service]\n",
    );

    let build = build_registry_project(&ProjectBuildOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect("typed OID4VCI authority project builds through the production validator");
    let output = resolve_build_output(&project, build.output.expect("build output"));
    let notary = read_yaml(&output.join("private/notary/config/notary.yaml"));
    let approval: serde_json::Value = serde_json::from_slice(
        &std::fs::read(output.join("private/notary/approval/project-state.json"))
            .expect("registrar approval state reads"),
    )
    .expect("registrar approval state parses");

    assert_ne!(
        baseline_approval["semantic_digests"]["operator_security"],
        approval["semantic_digests"]["operator_security"],
        "registrar trust must alter operator-security review semantics"
    );
    assert_eq!(
        baseline_approval["semantic_digests"]["claim"], approval["semantic_digests"]["claim"],
        "registrar trust must not alter claim semantics"
    );
    let baseline_trust = baseline_approval["promotion_projection"]["fields"]
        .as_array()
        .expect("baseline promotion fields are an array")
        .iter()
        .find(|field| field["kind"].as_str() == Some("trust"))
        .expect("baseline trust promotion field exists");
    let registrar_trust = approval["promotion_projection"]["fields"]
        .as_array()
        .expect("registrar promotion fields are an array")
        .iter()
        .find(|field| field["kind"].as_str() == Some("trust"))
        .expect("registrar trust promotion field exists");
    assert_ne!(
        baseline_trust["digest"], registrar_trust["digest"],
        "registrar clients must be projected as trust"
    );
    assert_eq!(
        registrar_trust["authority_members"]
            .as_array()
            .expect("registrar trust authority members")
            .len(),
        baseline_trust["authority_members"]
            .as_array()
            .expect("baseline trust authority members")
            .len()
            + 1
    );

    assert_eq!(
        notary["instance"]["public_base_url"].as_str(),
        Some("https://notary.example.invalid")
    );
    assert_eq!(
        notary["evidence"]["api_base_url"].as_str(),
        Some("https://notary.example.invalid")
    );
    assert!(notary["auth"].get("mode").is_none());
    assert_eq!(
        notary["auth"]["api_keys"][0]["id"].as_str(),
        Some("benefits-service")
    );
    assert_eq!(
        notary["auth"]["oidc"]["issuer"].as_str(),
        Some("https://esignet.example.invalid")
    );
    assert_eq!(
        notary["auth"]["oidc"]["audiences"],
        serde_norway::from_str::<serde_norway::Value>(
            "[example-wallet-client, https://notary.example.invalid]"
        )
        .expect("OIDC audiences parse")
    );
    assert_eq!(
        notary["auth"]["oidc"]["allowed_clients"],
        serde_norway::from_str::<serde_norway::Value>("[example-wallet-client, benefits-service]")
            .expect("OIDC clients parse")
    );
    assert_eq!(
        notary["auth"]["oidc"]["allowed_token_types"],
        serde_norway::from_str::<serde_norway::Value>("[JWT]")
            .expect("OIDC access-token types parse")
    );
    assert_eq!(
        notary["auth"]["access_token_signing"]["signing_key_id"].as_str(),
        Some("oid4vci-access-token")
    );
    assert_eq!(
        notary["evidence"]["signing_keys"]["oid4vci-access-token"]["private_jwk_env"].as_str(),
        Some("OID4VCI_ACCESS_TOKEN_JWK")
    );
    assert_eq!(
        notary["evidence"]["signing_keys"]["project-issuer"]["alg"].as_str(),
        Some("EdDSA")
    );
    assert_eq!(
        notary["evidence"]["signing_keys"]["oid4vci-esignet-client"]["alg"].as_str(),
        Some("RS256")
    );
    assert_eq!(
        notary["state"]["postgresql"]["sensitive_state_key_env"].as_str(),
        Some("OID4VCI_SENSITIVE_STATE_KEY")
    );
    assert_eq!(
        notary["evidence"]["credential_profiles"]["household-eligibility.household-eligibility"]
            ["holder_binding"]["proof_of_possession"]
            .as_str(),
        Some("required")
    );
    let registry_claim = notary["evidence"]["claims"]
        .as_sequence()
        .expect("generated claims")
        .iter()
        .find(|claim| claim["id"].as_str() == Some("household-record-exists"))
        .expect("selected registry-backed claim");
    assert_eq!(
        registry_claim["evidence_mode"]["type"].as_str(),
        Some("registry_backed")
    );
    assert_eq!(
        registry_claim["evidence_mode"]["consultations"]["household"]["inputs"]
            ["household_reference"]
            .as_str(),
        Some("request.target.identifiers.household_reference")
    );
    assert_eq!(
        notary["subject_access"]["allowed_claims"][0].as_str(),
        Some("household-record-exists")
    );
    assert_eq!(
        notary["subject_access"]["allowed_formats"],
        serde_norway::from_str::<serde_norway::Value>(
            "[application/vnd.registry-notary.claim-result+json]"
        )
        .expect("canonical evaluation format parses")
    );
    assert_eq!(
        notary["subject_access"]["allowed_wallet_origins"][0].as_str(),
        Some("https://wallet.example.invalid")
    );
    assert_eq!(
        notary["subject_access"]["citizen_clients"]["allowed_client_ids"],
        serde_norway::from_str::<serde_norway::Value>("[example-wallet-client]")
            .expect("citizen client ids parse")
    );
    assert_eq!(
        notary["subject_access"]["citizen_clients"]["allowed_audiences"],
        serde_norway::from_str::<serde_norway::Value>("[example-wallet-client]")
            .expect("citizen audiences parse")
    );
    assert_eq!(
        notary["subject_access"]["allowed_operations"]["evaluate"].as_bool(),
        Some(false)
    );
    assert_eq!(
        notary["oid4vci"]["credential_endpoint"].as_str(),
        Some("https://notary.example.invalid/oid4vci/credential")
    );
    assert_eq!(
        notary["oid4vci"]["pre_authorized_code"]["esignet"]["redirect_uri"].as_str(),
        Some("https://notary.example.invalid/oid4vci/offer/callback")
    );
    assert_eq!(
        notary["oid4vci"]["pre_authorized_code"]["tx_code"]["required"].as_bool(),
        Some(true)
    );
    assert_eq!(
        notary["oid4vci"]["credential_configurations"]
            ["household-eligibility.household-eligibility"]["vct"]
            .as_str(),
        Some("https://notary.example.invalid/credentials/household-eligibility/v1")
    );
    assert_eq!(
        notary["oid4vci"]["credential_configurations"]
            ["household-eligibility.household-eligibility"]["scope"]
            .as_str(),
        Some("evidence:household:read")
    );
}

#[test]
fn authored_oid4vci_walt_profile_is_explicit_and_keeps_the_bearer_window_bounded() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    let project_path = project.join("registry-stack.yaml");
    let mut document = read_yaml(&project_path);
    document["services"]["household-eligibility"]["credential_profiles"]["household-eligibility"]
        ["claims"] =
        serde_norway::from_str("[household-record-exists]").expect("single registry-backed claim");
    write_yaml(&project_path, &document);
    author_oid4vci_binding(
        &project,
        "household-eligibility",
        "household-eligibility",
        "household_reference",
    );
    merge_environment_yaml(
        &project.join("environments/local.yaml"),
        "issuance:\n  algorithm: ES256\noid4vci:\n  tx_code:\n    required: false\n",
    );

    let build = build_registry_project(&ProjectBuildOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect("explicit Walt-compatible binding builds");
    let output = resolve_build_output(&project, build.output.expect("build output"));
    let notary = read_yaml(&output.join("private/notary/config/notary.yaml"));
    assert_eq!(
        notary["evidence"]["signing_keys"]["project-issuer"]["alg"].as_str(),
        Some("ES256")
    );
    assert_eq!(
        notary["oid4vci"]["pre_authorized_code"]["tx_code"]["required"].as_bool(),
        Some(false)
    );
    assert_eq!(
        notary["oid4vci"]["pre_authorized_code"]["pre_authorized_code_ttl_seconds"].as_u64(),
        Some(300)
    );
}

#[test]
fn authored_representative_oid4vci_builds_the_exact_status_enabled_policy() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    author_oid4vci_binding(
        &project,
        "household-eligibility",
        "household-eligibility",
        "representative_reference",
    );
    author_representative_oid4vci_binding(&project, "representative_reference");
    merge_environment_yaml(
        &project.join("environments/local.yaml"),
        "oid4vci:\n  representative_issuance:\n    max_proof_age_seconds: 180\n",
    );

    let tested = test_registry_project(&ProjectTestOptions {
        project_directory: project.clone(),
        environment: Some("local".to_string()),
    })
    .expect("representative requester fixture passes the offline developer journey");
    assert_eq!(tested.status, "passed");

    let build = build_registry_project(&ProjectBuildOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect("representative OID4VCI golden project builds through the production validator");
    let output = resolve_build_output(&project, build.output.expect("build output"));
    let notary = read_yaml(&output.join("private/notary/config/notary.yaml"));
    let relationship = &notary["subject_access"]["delegation"]["allowed_relationships"][0];
    assert!(
        notary["subject_access"]["allowed_claims"]
            .as_sequence()
            .is_some_and(Vec::is_empty),
        "a representative-only root must not become subject-bound authority"
    );
    assert_eq!(
        relationship["relationship_type"].as_str(),
        Some("authorized-representative")
    );
    assert_eq!(
        relationship["proof_claim"].as_str(),
        Some("household-record-exists")
    );
    assert_eq!(
        relationship["target_id_type"].as_str(),
        Some("household_reference")
    );
    assert_eq!(relationship["max_proof_age_seconds"].as_u64(), Some(180));
    assert_eq!(
        notary["subject_access"]["token_policy"]["max_evaluation_age_seconds"].as_u64(),
        Some(300),
        "a narrower relationship-proof window must not narrow unrelated evaluation policy"
    );
    assert_eq!(
        notary["subject_access"]["allowed_operations"]["evaluate"].as_bool(),
        Some(true)
    );
    assert_eq!(
        notary["oid4vci"]["credential_configurations"]
            ["household-eligibility.household-eligibility"]["representative_issuance"]["ceremony"]
            .as_str(),
        Some("digitally_authenticated_representative")
    );
    assert_eq!(
        notary["oid4vci"]["credential_configurations"]
            ["household-eligibility.household-eligibility"]["representative_issuance"]
            ["relationship"]
            .as_str(),
        Some("authorized-representative")
    );
    assert_eq!(notary["credential_status"]["enabled"].as_bool(), Some(true));
    assert_eq!(
        notary["credential_status"]["base_url"].as_str(),
        Some("https://notary.example.invalid")
    );
    let root = notary["evidence"]["claims"]
        .as_sequence()
        .expect("generated claims")
        .iter()
        .find(|claim| claim["id"].as_str() == Some("source-household-approval-decision"))
        .expect("representative credential root");
    assert_eq!(
        root["depends_on"],
        serde_norway::from_str::<serde_norway::Value>("[household-record-exists]")
            .expect("claim dependency parses")
    );
}

#[test]
fn authored_representative_oid4vci_rejects_non_person_requester_fixtures() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    author_oid4vci_binding(
        &project,
        "household-eligibility",
        "household-eligibility",
        "representative_reference",
    );
    author_representative_oid4vci_binding(&project, "representative_reference");

    let mut changed_fixture = false;
    for entry in std::fs::read_dir(project.join("integrations/eligibility/fixtures"))
        .expect("fixture directory reads")
    {
        let path = entry.expect("fixture entry").path();
        let mut fixture = read_yaml(&path);
        if fixture.get("request").is_none() {
            continue;
        }
        fixture["request"]["requester"]["type"] =
            serde_norway::Value::String("Organisation".to_string());
        write_yaml(&path, &fixture);
        changed_fixture = true;
        break;
    }
    assert!(changed_fixture, "representative request fixture exists");

    let error = test_registry_project(&ProjectTestOptions {
        project_directory: project,
        environment: Some("local".to_string()),
    })
    .expect_err("non-person representative requester must be rejected");
    assert!(
        format!("{error:#}").contains("request_to_consultation_binding_invalid"),
        "{error:#}"
    );
}

#[test]
fn representative_oid4vci_rejects_registrar_clients_with_a_clear_fix() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    author_oid4vci_binding(
        &project,
        "household-eligibility",
        "household-eligibility",
        "representative_reference",
    );
    author_representative_oid4vci_binding(&project, "representative_reference");
    merge_environment_yaml(
        &project.join("environments/local.yaml"),
        "oid4vci:\n  registrar_clients: [benefits-service]\n",
    );

    let error = check_registry_project(&ProjectCheckOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        explain: false,
        against: None,
        anchor: None,
    })
    .expect_err("one Registryctl credential binding cannot use both authorities");
    assert!(
        format!("{error:#}").contains(
            "Representative issuance and registrar-created offers select incompatible authorities"
        ),
        "{error:#}"
    );

    let report = authoring_diagnostics(&project);
    let diagnostic = report
        .diagnostics
        .iter()
        .find(|diagnostic| {
            diagnostic.cause
                == "Representative issuance and registrar-created offers select incompatible authorities in Registryctl's single-credential binding."
        })
        .unwrap_or_else(|| panic!("missing authority diagnostic: {report:#?}"));
    assert_eq!(
        diagnostic.remediation,
        "Remove registrar_clients, or use a separate environment and Notary deployment for the registrar-created credential."
    );
    for pointer in [
        "/oid4vci/registrar_clients",
        "/oid4vci/representative_issuance",
    ] {
        assert!(
            diagnostic
                .addresses
                .iter()
                .any(|address| address.file == "environments/local.yaml"
                    && address.pointer == pointer)
        );
    }
}

#[test]
fn representative_oid4vci_diagnostics_name_the_invalid_authoring_field_and_fix() {
    let prepare = || {
        let temporary = tempfile::tempdir().expect("representative diagnostic directory");
        let project = copy_project("custom-system", temporary.path());
        author_oid4vci_binding(
            &project,
            "household-eligibility",
            "household-eligibility",
            "household_reference",
        );
        author_representative_oid4vci_binding(&project, "household_reference");
        (temporary, project)
    };

    let (unknown_root, unknown_project) = prepare();
    let environment_path = unknown_project.join("environments/local.yaml");
    let mut environment = read_yaml(&environment_path);
    environment["oid4vci"]["representative_issuance"]["proof_claim"] =
        serde_norway::Value::String("missing-relationship-proof".to_string());
    write_yaml(&environment_path, &environment);
    let report = authoring_diagnostics(&unknown_project);
    let diagnostic = report
        .diagnostics
        .iter()
        .find(|diagnostic| {
            diagnostic.cause
                == "The representative proof claim does not exist in the selected credential service."
        })
        .unwrap_or_else(|| panic!("missing proof-claim diagnostic: {report:#?}"));
    assert_eq!(
        diagnostic.remediation,
        "Set proof_claim to a registry-backed claim in the same service as the credential profile."
    );
    assert!(diagnostic.addresses.iter().any(|address| {
        address.file == "environments/local.yaml"
            && address.pointer == "/oid4vci/representative_issuance/proof_claim"
    }));
    drop(unknown_root);

    let (_mapping_root, mapping_project) = prepare();
    let project_path = mapping_project.join("registry-stack.yaml");
    let mut project = read_yaml(&project_path);
    project["services"]["household-eligibility"]["consultations"]["household"]["input"]
        .as_mapping_mut()
        .expect("consultation input")
        .remove(serde_norway::Value::String(
            "representative_reference".to_string(),
        ));
    write_yaml(&project_path, &project);
    let report = authoring_diagnostics(&mapping_project);
    let diagnostic = report
        .diagnostics
        .iter()
        .find(|diagnostic| {
            diagnostic.cause
                == "The relationship-proof consultation does not bind the authenticated representative."
        })
        .unwrap_or_else(|| panic!("missing requester-binding diagnostic: {report:#?}"));
    assert!(diagnostic
        .remediation
        .contains("request.requester.identifiers.<oid4vci subject id_type>"));
    assert!(diagnostic.addresses.iter().any(|address| {
        address.file == "registry-stack.yaml"
            && address.pointer == "/services/household-eligibility/consultations/household/input"
    }));

    let (_target_root, target_project) = prepare();
    let project_path = target_project.join("registry-stack.yaml");
    let mut project = read_yaml(&project_path);
    project["services"]["household-eligibility"]["consultations"]["household"]["input"]
        .as_mapping_mut()
        .expect("consultation input")
        .remove(serde_norway::Value::String(
            "household_reference".to_string(),
        ));
    write_yaml(&project_path, &project);
    let report = authoring_diagnostics(&target_project);
    let diagnostic = report
        .diagnostics
        .iter()
        .find(|diagnostic| {
            diagnostic.cause
                == "The relationship-proof consultation does not bind the represented subject."
        })
        .unwrap_or_else(|| panic!("missing target-binding diagnostic: {report:#?}"));
    assert!(diagnostic
        .remediation
        .contains("request.target.identifiers.<representative_issuance target_id_type>"));
    assert!(diagnostic.addresses.iter().any(|address| {
        address.file == "environments/local.yaml"
            && address.pointer == "/oid4vci/representative_issuance/target_id_type"
    }));

    let (_extra_input_root, extra_input_project) = prepare();
    let project_path = extra_input_project.join("registry-stack.yaml");
    let mut project = read_yaml(&project_path);
    project["services"]["household-eligibility"]["consultations"]["household"]["input"]
        ["relationship_kind"] =
        serde_norway::Value::String("request.target.attributes.relationship_kind".to_string());
    write_yaml(&project_path, &project);
    let report = authoring_diagnostics(&extra_input_project);
    let diagnostic = report
        .diagnostics
        .iter()
        .find(|diagnostic| {
            diagnostic.cause
                == "The relationship-proof consultation requires an input that the target-selection ceremony cannot supply."
        })
        .unwrap_or_else(|| panic!("unavailable ceremony-input diagnostic: {report:#?}"));
    assert!(diagnostic.remediation.contains("exactly two"));
    assert!(diagnostic.addresses.iter().any(|address| {
        address.file == "registry-stack.yaml"
            && address.pointer
                == "/services/household-eligibility/consultations/household/input/relationship_kind"
    }));

    let (_shared_root, shared_project) = prepare();
    let project_path = shared_project.join("registry-stack.yaml");
    let mut project = read_yaml(&project_path);
    project["services"]["household-eligibility"]["credential_profiles"]["ordinary-household"] =
        serde_norway::from_str(
            r#"format: dc+sd-jwt
type: https://notary.example.invalid/credentials/ordinary-household/v1
validity: 5m
claims: [source-household-approval-decision]
"#,
        )
        .expect("shared credential profile");
    write_yaml(&project_path, &project);
    let report = authoring_diagnostics(&shared_project);
    let diagnostic = report
        .diagnostics
        .iter()
        .find(|diagnostic| {
            diagnostic.cause
                == "The representative credential claim is shared by another credential profile."
        })
        .unwrap_or_else(|| panic!("shared representative-root diagnostic: {report:#?}"));
    assert!(diagnostic.remediation.contains("exclusive"));
    assert!(diagnostic.addresses.iter().any(|address| {
        address.file == "environments/local.yaml"
            && address.pointer == "/oid4vci/credential/profile"
    }));
    assert!(diagnostic.addresses.iter().any(|address| {
        address.file == "registry-stack.yaml"
            && address.pointer
                == "/services/household-eligibility/credential_profiles/ordinary-household/claims"
    }));
}

#[test]
fn authored_oid4vci_binding_rejects_open_or_incoherent_trust_topologies() {
    for (name, mutate, expected) in [
        (
            "unknown credential profile",
            "oid4vci:\n  credential:\n    profile: absent-profile\n",
            "OID4VCI references an unknown credential profile",
        ),
        (
            "cross-origin token endpoint",
            "oid4vci:\n  authorization_server:\n    token_url: https://attacker.invalid/token\n",
            "OID4VCI authorization server token URL must use its bound origin",
        ),
        (
            "non-callback redirect",
            "oid4vci:\n  redirect_uri: https://notary.example.invalid/other-callback\n",
            "OID4VCI redirect URI must be the public Notary offer callback",
        ),
        (
            "reused issuer key",
            "oid4vci:\n  access_token:\n    signing_key: { secret: REGISTRY_NOTARY_ISSUER_JWK }\n",
            "OID4VCI issuer, client, and access-token signing keys must be distinct",
        ),
        (
            "missing PostgreSQL state",
            "notary_state: null\n",
            "OID4VCI requires a Notary PostgreSQL state binding",
        ),
        (
            "invalid registrar client",
            "oid4vci:\n  registrar_clients: ['']\n",
            "OID4VCI registrar client id must not be empty",
        ),
        (
            "duplicate registrar client",
            "oid4vci:\n  registrar_clients: [registrar-a, registrar-a]\n",
            "OID4VCI registrar_clients must not contain duplicates",
        ),
        (
            "citizen client reused as registrar",
            "oid4vci:\n  registrar_clients: [example-wallet-client]\n",
            "OID4VCI registrar_clients must not contain the citizen client id",
        ),
    ] {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = copy_project("custom-system", temporary.path());
        let project_path = project.join("registry-stack.yaml");
        let mut document = read_yaml(&project_path);
        document["services"]["household-eligibility"]["credential_profiles"]
            ["household-eligibility"]["claims"] =
            serde_norway::from_str("[household-record-exists]")
                .expect("single registry-backed credential claim");
        write_yaml(&project_path, &document);
        author_oid4vci_binding(
            &project,
            "household-eligibility",
            "household-eligibility",
            "household_reference",
        );
        merge_environment_yaml(&project.join("environments/local.yaml"), mutate);
        let error = check_registry_project(&ProjectCheckOptions {
            project_directory: project,
            environment: "local".to_string(),
            explain: false,
            against: None,
            anchor: None,
        })
        .expect_err("incoherent OID4VCI binding must fail closed");
        let _ = (name, expected);
        assert_authoring_diagnostic(&error, "registryctl.authoring.environment.invalid");
    }

    let temporary = tempfile::tempdir().expect("oversized registrar-client temporary directory");
    let project = copy_project("custom-system", temporary.path());
    let project_path = project.join("registry-stack.yaml");
    let mut document = read_yaml(&project_path);
    document["services"]["household-eligibility"]["credential_profiles"]["household-eligibility"]
        ["claims"] = serde_norway::from_str("[household-record-exists]")
        .expect("single registry-backed credential claim");
    write_yaml(&project_path, &document);
    author_oid4vci_binding(
        &project,
        "household-eligibility",
        "household-eligibility",
        "household_reference",
    );
    let registrar_clients = (0..65)
        .map(|index| serde_norway::Value::String(format!("registrar-{index}")))
        .collect::<Vec<_>>();
    let environment_path = project.join("environments/local.yaml");
    let mut environment = read_yaml(&environment_path);
    environment["oid4vci"]["registrar_clients"] = serde_norway::Value::Sequence(registrar_clients);
    write_yaml(&environment_path, &environment);
    let error = check_registry_project(&ProjectCheckOptions {
        project_directory: project,
        environment: "local".to_string(),
        explain: false,
        against: None,
        anchor: None,
    })
    .expect_err("oversized registrar-client trust must fail closed");
    assert_authoring_diagnostic(&error, "registryctl.authoring.environment.invalid");

    for (name, scopes, expected) in [
        (
            "no access scope",
            "[]",
            "caller scopes must contain between one and 16 entries",
        ),
        (
            "multiple access scopes",
            "[evidence:household:read, evidence:household:issue]",
            "OID4VCI credential service must declare exactly one access scope",
        ),
    ] {
        let temporary = tempfile::tempdir().expect("access-scope temporary directory");
        let project = copy_project("custom-system", temporary.path());
        let project_path = project.join("registry-stack.yaml");
        let mut document = read_yaml(&project_path);
        document["services"]["household-eligibility"]["credential_profiles"]
            ["household-eligibility"]["claims"] =
            serde_norway::from_str("[household-record-exists]")
                .expect("single registry-backed claim");
        document["services"]["household-eligibility"]["access"]["scopes"] =
            serde_norway::from_str(scopes).expect("access scopes");
        write_yaml(&project_path, &document);
        author_oid4vci_binding(
            &project,
            "household-eligibility",
            "household-eligibility",
            "household_reference",
        );
        let environment_path = project.join("environments/local.yaml");
        let mut environment = read_yaml(&environment_path);
        environment
            .as_mapping_mut()
            .expect("environment mapping")
            .remove(serde_norway::Value::String("callers".to_string()));
        write_yaml(&environment_path, &environment);
        let error = check_registry_project(&ProjectCheckOptions {
            project_directory: project,
            environment: "local".to_string(),
            explain: false,
            against: None,
            anchor: None,
        })
        .expect_err("OID4VCI service without exactly one access scope must fail closed");
        let _ = expected;
        assert_authoring_diagnostic(
            &error,
            if name == "no access scope" {
                "registryctl.authoring.project.invalid"
            } else {
                "registryctl.authoring.environment.invalid"
            },
        );
    }
}

#[test]
fn records_standards_share_the_validated_materialization() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("snapshot-with-records", temporary.path());
    let entity_path = project.join("entities/people.yaml");
    let mut entity = read_yaml(&entity_path);
    entity["schema"]["properties"]["longitude"] =
        serde_norway::from_str("type: [integer, 'null']\nminimum: -180\nmaximum: 180\n")
            .expect("longitude field");
    entity["schema"]["properties"]["latitude"] =
        serde_norway::from_str("type: [integer, 'null']\nminimum: -90\nmaximum: 90\n")
            .expect("latitude field");
    entity["schema"]["required"]
        .as_sequence_mut()
        .expect("entity required fields")
        .extend([
            serde_norway::Value::String("longitude".to_string()),
            serde_norway::Value::String("latitude".to_string()),
        ]);
    write_yaml(&entity_path, &entity);

    let project_path = project.join("registry-stack.yaml");
    let mut authored_project = read_yaml(&project_path);
    authored_project["services"]["people-records"]["api"]["standards"]["ogc_features"] =
        serde_norway::from_str(
            r#"collection_id: people
title: Population locations
geometry:
  kind: point
  longitude_field: longitude
  latitude_field: latitude
  crs: http://www.opengis.net/def/crs/OGC/1.3/CRS84
max_bbox_degrees: 5
max_geometry_vertices: 1
"#,
        )
        .expect("OGC spatial mapping");
    authored_project["services"]["people-records"]["api"]["standards"]["sp_dci"] =
        serde_norway::from_str(
            r#"registry: population
registry_type: civil-registry
record_type: person
identifiers: { person_id: person_id }
expression_fields: { registration_status: registration_status }
response_fields: { residency_confirmed: residency_confirmed }
"#,
        )
        .expect("SP DCI mapping");
    write_yaml(&project_path, &authored_project);

    let error = check_registry_project(&ProjectCheckOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        explain: false,
        against: None,
        anchor: None,
    })
    .expect_err("standards must not widen the explicit records projection");
    assert_authoring_diagnostic(&error, "registryctl.authoring.project.invalid");

    authored_project["services"]["people-records"]["api"]["projection"]
        .as_sequence_mut()
        .expect("records projection")
        .extend([
            serde_norway::Value::String("longitude".to_string()),
            serde_norway::Value::String("latitude".to_string()),
        ]);
    authored_project["services"]["people-records"]["api"]["filters"]["registration_status"] =
        serde_norway::from_str("[eq]").expect("SP DCI expression filter");
    write_yaml(&project_path, &authored_project);

    let environment_path = project.join("environments/local.yaml");
    let mut environment = read_yaml(&environment_path);
    environment["entities"]["people"]["columns"]["longitude"] =
        serde_norway::Value::String("longitude_deg".to_string());
    environment["entities"]["people"]["columns"]["latitude"] =
        serde_norway::Value::String("latitude_deg".to_string());
    write_yaml(&environment_path, &environment);

    let build = build_registry_project(&ProjectBuildOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect("enabled records standards build through Relay production validation");
    let output = resolve_build_output(&project, build.output.expect("build output"));
    let relay: serde_json::Value = serde_norway::from_slice(
        &std::fs::read(output.join("private/relay-public/config/relay.yaml"))
            .expect("Relay config reads"),
    )
    .expect("Relay config parses");
    let dataset = &relay["datasets"][0];
    assert_eq!(dataset["tables"].as_array().map(Vec::len), Some(1));
    assert_eq!(dataset["entities"][0]["table"], dataset["tables"][0]["id"]);
    assert_eq!(
        dataset["entities"][0]["spatial"]["geometry"]["kind"],
        "point"
    );
    assert_eq!(
        relay["standards"]["spdci"]["registries"]["population"]["dataset"],
        "people"
    );
    assert_eq!(
        relay["standards"]["spdci"]["registries"]["population"]["entity"],
        "people"
    );
}

#[test]
fn records_environment_mapping_fails_closed() {
    let temporary = tempfile::tempdir().expect("temporary directory");

    let duplicate = copy_project("snapshot-exact", temporary.path());
    replace_in_file(
        &duplicate.join("environments/local.yaml"),
        "guardian_id: guardian_key",
        "guardian_id: subject_key",
    );
    let error = check_registry_project(&ProjectCheckOptions {
        project_directory: duplicate,
        environment: "local".to_string(),
        explain: false,
        against: None,
        anchor: None,
    })
    .expect_err("non-injective physical mapping must fail");
    assert_authoring_diagnostic(&error, "registryctl.authoring.environment.invalid");

    let missing = temporary.path().join("missing");
    copy_tree(&golden("snapshot-exact"), &missing);
    replace_in_file(
        &missing.join("environments/local.yaml"),
        "      guardian_id: guardian_key\n",
        "",
    );
    let error = check_registry_project(&ProjectCheckOptions {
        project_directory: missing,
        environment: "local".to_string(),
        explain: false,
        against: None,
        anchor: None,
    })
    .expect_err("missing logical field mapping must fail");
    assert_authoring_diagnostic(&error, "registryctl.authoring.environment.invalid");

    let physical = temporary.path().join("physical");
    copy_tree(&golden("snapshot-exact"), &physical);
    let entity = physical.join("entities/people.yaml");
    let mut authored = std::fs::read_to_string(&entity).expect("entity reads");
    authored.push_str("path: /private/people.csv\n");
    std::fs::write(&entity, authored).expect("hostile entity writes");
    let error = check_registry_project(&ProjectCheckOptions {
        project_directory: physical,
        environment: "local".to_string(),
        explain: false,
        against: None,
        anchor: None,
    })
    .expect_err("physical provider member in logical records must fail");
    assert_authoring_diagnostic(&error, "registryctl.authoring.yaml.unknown_field");
}

#[test]
fn records_provider_change_requires_a_new_generation() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("snapshot-exact", temporary.path());
    let initial = build_registry_project(&ProjectBuildOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect("initial records build passes");
    let output = resolve_build_output(&project, initial.output.expect("initial output"));
    let private_key = temporary.path().join("records-private.jwk");
    let public_key = temporary.path().join("records-public.jwk");
    write_test_signing_key_pair(&private_key, &public_key);
    let (baseline, anchor) = create_and_sign_test_lane_baseline(
        temporary.path(),
        "records",
        ProductAcceptanceLaneV1::Notary,
        &output.join("signing-inputs/notary"),
        &private_key,
        &public_key,
    );

    let environment = project.join("environments/local.yaml");
    replace_in_file(
        &environment,
        "/var/lib/registry/population.csv",
        "/var/lib/registry/population-next.csv",
    );
    let error = check_registry_project(&ProjectCheckOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        explain: false,
        against: Some(baseline.clone()),
        anchor: Some(anchor.clone()),
    })
    .expect_err("provider change with reused generation must fail");
    let rendered = format!("{error:#}");
    assert!(rendered.contains("without a new generation"), "{rendered}");

    replace_in_file(
        &environment,
        "generation: 2026-07-12",
        "generation: 2026-07-13",
    );
    let report = check_registry_project(&ProjectCheckOptions {
        project_directory: project,
        environment: "local".to_string(),
        explain: false,
        against: Some(baseline),
        anchor: Some(anchor),
    })
    .expect("provider change with a new generation checks");
    assert!(report
        .semantic_changes
        .iter()
        .any(|change| change.dimension == "operator_security"));
}

#[test]
fn every_required_golden_builds_registry_backed_notary_without_transitional_sources() {
    let project_names = [
        "custom-system",
        "dhis2-tracker",
        "dhis2-script",
        "fhir-r4-coverage-active",
        "opencrvs",
        "opencrvs-events-api",
        "opencrvs-country-variant",
        "openspp-exact",
        "snapshot-exact",
        "snapshot-with-records",
    ];
    for project_name in project_names {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = copy_project(project_name, temporary.path());
        let check = check_registry_project(&ProjectCheckOptions {
            project_directory: project.clone(),
            environment: "local".to_string(),
            explain: true,
            against: None,
            anchor: None,
        })
        .unwrap_or_else(|error| panic!("{project_name} check failed: {error:#}"));
        assert_eq!(check.status, "valid", "{project_name}");
        assert_eq!(check.baseline, "initial_without_baseline", "{project_name}");
        assert!(check.explanation.is_some(), "{project_name}");

        let build = build_registry_project(&ProjectBuildOptions {
            project_directory: project.clone(),
            environment: "local".to_string(),
            against: None,
            anchor: None,
        })
        .unwrap_or_else(|error| panic!("{project_name} build failed: {error:#}"));
        let output = resolve_build_output(&project, build.output.expect("build output"));
        assert!(output.join("reviewable/review.json").is_file());
        assert!(output
            .join("private/relay-public/approval/project-state.json")
            .is_file());
        assert!(output
            .join("private/relay-public/config/relay.yaml")
            .is_file());
        assert!(output
            .join("private/relay-consultation/approval/project-state.json")
            .is_file());
        assert!(output
            .join("private/relay-consultation/config/relay.yaml")
            .is_file());
        let notary_config_path = output.join("private/notary/config/notary.yaml");
        let notary_config = std::fs::read_to_string(&notary_config_path)
            .unwrap_or_else(|error| panic!("{}: {error}", notary_config_path.display()));
        for forbidden in [
            "transitional_direct",
            "source_connections",
            "source_bindings",
        ] {
            assert!(
                !notary_config.contains(forbidden),
                "{project_name} generated Notary config must not contain {forbidden}"
            );
        }
        for product in ["relay-public", "relay-consultation", "notary"] {
            assert!(output
                .join(format!("private/{product}/descriptors/operations.json"))
                .is_file());
            assert!(output
                .join(format!(
                    "private/{product}/descriptors/secret-consumers.json"
                ))
                .is_file());
        }
        let review_bytes =
            std::fs::read(output.join("reviewable/review.json")).expect("human review reads");
        let review: serde_json::Value =
            serde_json::from_slice(&review_bytes).expect("human review parses");
        assert_public_review_has_only_contract_hashes(&review);
        for product in ["relay-public", "relay-consultation", "notary"] {
            assert_eq!(
                std::fs::read(output.join(format!("private/{product}/approval/review.json")))
                    .expect("signed review input reads"),
                review_bytes,
                "{project_name} {product} approval carries the exact human review"
            );
        }
        assert_eq!(
            std::fs::read(output.join("private/relay-public/approval/project-state.json"))
                .expect("Relay approval state reads"),
            std::fs::read(output.join("private/relay-consultation/approval/project-state.json"))
                .expect("consultation Relay approval state reads"),
            "{project_name} Relay instances carry identical approval state"
        );
        assert_eq!(
            std::fs::read(output.join("private/relay-public/approval/project-state.json"))
                .expect("Relay approval state reads"),
            std::fs::read(output.join("private/notary/approval/project-state.json"))
                .expect("Notary approval state reads"),
            "{project_name} products carry identical approval state"
        );
        let relay_descriptor: serde_json::Value = serde_json::from_slice(
            &std::fs::read(output.join("private/relay-public/descriptors/secret-consumers.json"))
                .expect("Relay secret descriptor reads"),
        )
        .expect("Relay secret descriptor parses");
        assert!(relay_descriptor["consumers"]
            .as_array()
            .is_some_and(|consumers| {
                consumers
                    .iter()
                    .any(|consumer| consumer["locator"] == "REGISTRY_RELAY_AUDIT_HASH_SECRET")
                    && consumers.iter().all(|consumer| {
                        !matches!(
                            consumer["locator"].as_str(),
                            Some(
                                "REGISTRY_RELAY_AUDIT_PSEUDONYM_EPOCH_1"
                                    | "REGISTRY_RELAY_CONSULTATION_DATABASE_URL"
                            )
                        )
                    })
            }));
        let consultation_descriptor: serde_json::Value = serde_json::from_slice(
            &std::fs::read(
                output.join("private/relay-consultation/descriptors/secret-consumers.json"),
            )
            .expect("consultation Relay secret descriptor reads"),
        )
        .expect("consultation Relay secret descriptor parses");
        assert!(consultation_descriptor["consumers"]
            .as_array()
            .is_some_and(|consumers| {
                consumers
                    .iter()
                    .any(|consumer| consumer["locator"] == "REGISTRY_RELAY_AUDIT_PSEUDONYM_EPOCH_1")
                    && consumers.iter().any(|consumer| {
                        consumer["locator"] == "REGISTRY_RELAY_CONSULTATION_DATABASE_URL"
                    })
            }));
        let notary_descriptor: serde_json::Value = serde_json::from_slice(
            &std::fs::read(output.join("private/notary/descriptors/secret-consumers.json"))
                .expect("Notary secret descriptor reads"),
        )
        .expect("Notary secret descriptor parses");
        assert!(notary_descriptor["consumers"]
            .as_array()
            .is_some_and(|consumers| {
                consumers.iter().any(|consumer| {
                    consumer["locator"]
                        .as_str()
                        .is_some_and(|locator| locator.ends_with("_TOKEN_HASH"))
                })
            }));
        assert!(notary_descriptor["consumers"]
            .as_array()
            .is_some_and(|consumers| {
                consumers
                    .iter()
                    .all(|consumer| consumer["locator"] != "REGISTRY_NOTARY_POSTGRES_URL")
            }));
    }
}

#[test]
fn generated_product_inputs_sign_and_verify_without_secret_values() {
    const SECRET_SENTINEL: &str = "project-authoring-secret-sentinel-8f9d7537";

    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    std::env::set_var("HOUSEHOLD_PASSWORD", SECRET_SENTINEL);
    let build = build_registry_project(&ProjectBuildOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect("project builds");
    std::env::remove_var("HOUSEHOLD_PASSWORD");
    let output = resolve_build_output(&project, build.output.expect("build output"));
    assert!(directory_closure(&output).iter().all(|(_, bytes)| !bytes
        .windows(SECRET_SENTINEL.len())
        .any(|window| window == SECRET_SENTINEL.as_bytes())));

    let private_key = temporary.path().join("private.jwk");
    let public_key = temporary.path().join("public.jwk");
    std::fs::write(&private_key, TEST_PRIVATE_JWK).expect("private test key writes");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let mut permissions = std::fs::metadata(&private_key)
            .expect("private key metadata reads")
            .permissions();
        permissions.set_mode(0o600);
        std::fs::set_permissions(&private_key, permissions)
            .expect("private key becomes owner-only");
    }
    std::fs::write(&public_key, TEST_PUBLIC_JWK).expect("public test key writes");
    let signing_inputs = output.join("signing-inputs");
    let mut lanes = std::fs::read_dir(&signing_inputs)
        .expect("signing inputs enumerate")
        .map(|entry| {
            entry
                .expect("lane entry reads")
                .file_name()
                .into_string()
                .expect("lane name is UTF-8")
        })
        .collect::<Vec<_>>();
    lanes.sort();
    assert_eq!(
        lanes,
        ["notary", "relay-consultation", "relay-public"],
        "governed build publishes exactly the three approved lanes"
    );

    for (label, product, lane, expected_instance) in [
        (
            "relay-public",
            "registry-relay",
            ProductAcceptanceLaneV1::RelayPublic,
            "household-relay",
        ),
        (
            "relay-consultation",
            "registry-relay",
            ProductAcceptanceLaneV1::RelayConsultation,
            "household-relay-consultation",
        ),
        (
            "notary",
            "registry-notary",
            ProductAcceptanceLaneV1::Notary,
            "household-notary",
        ),
    ] {
        let input = signing_inputs.join(label);
        let marker_bytes =
            std::fs::read(input.join("signing-input.v1.json")).expect("lane marker reads");
        let marker: registryctl::SigningInputMarkerV1 =
            serde_json::from_slice(&marker_bytes).expect("lane marker parses");
        assert_eq!(marker.schema_id, "registry.stack.signing_input");
        assert_eq!(marker.schema_version, "1.0");
        assert_eq!(
            marker.acceptance_identity.project,
            "fictional-household-authority"
        );
        assert_eq!(marker.acceptance_identity.environment, "local");
        assert_eq!(marker.acceptance_identity.lane, lane);
        assert_eq!(
            marker.acceptance_identity.stream,
            "fictional-household-authority"
        );
        assert_eq!(marker.acceptance_identity.instance, expected_instance);

        let anchor = temporary.path().join(format!("{label}-anchor.json"));
        create_trust_anchor(&TrustAnchorCreateOptions {
            lane,
            input: input.clone(),
            public_keys: vec![public_key.clone()],
            threshold: 1,
            output_file: anchor.clone(),
        })
        .expect("lane anchor creates");
        let signed_output = temporary.path().join(format!("{label}-signed"));
        sign_product_bundle(&ProductBundleSignOptions {
            lane,
            input,
            anchor,
            preceding_approved_set: None,
            keys: vec![format!("file:{}", private_key.display())],
            output_dir: signed_output.clone(),
        })
        .expect("generated lane input signs");
        let verified = verify_config_bundle_cli(
            &signed_output.join("bundle"),
            &signed_output.join("anchor.json"),
        )
        .expect("signed lane bundle verifies");
        assert_eq!(verified.product, product);
        assert_eq!(verified.signer_kids.len(), 1);
    }

    let first_markers = ["relay-public", "relay-consultation", "notary"].map(|lane| {
        std::fs::read(
            output
                .join("signing-inputs")
                .join(lane)
                .join("signing-input.v1.json"),
        )
        .expect("first marker reads")
    });
    let repeated = build_registry_project(&ProjectBuildOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect("repeated project build succeeds");
    let repeated_output =
        resolve_build_output(&project, repeated.output.expect("repeated build output"));
    let repeated_markers = ["relay-public", "relay-consultation", "notary"].map(|lane| {
        std::fs::read(
            repeated_output
                .join("signing-inputs")
                .join(lane)
                .join("signing-input.v1.json"),
        )
        .expect("repeated marker reads")
    });
    assert_eq!(first_markers, repeated_markers);
}

#[cfg(unix)]
#[test]
fn generated_project_output_is_owner_only() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    let build = build_registry_project(&ProjectBuildOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect("project builds");
    let output = resolve_build_output(&project, build.output.expect("build output"));
    assert_owner_only(&output);
}

#[test]
fn authored_request_literals_cannot_smuggle_secret_material() {
    const SECRET_SENTINEL: &str = "project-authoring-request-secret-4e198da1";

    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    let integration_path = project.join("integrations/eligibility/integration.yaml");
    let mut integration = read_yaml(&integration_path);
    integration["capability"]["http"]["request"]["query"]["password"] =
        serde_norway::Value::String(SECRET_SENTINEL.to_string());
    write_yaml(&integration_path, &integration);
    let error = check_registry_project(&ProjectCheckOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        explain: false,
        against: None,
        anchor: None,
    })
    .expect_err("secret-shaped request field must fail closed");
    let diagnostic = format!("{error:#}");
    assert_authoring_diagnostic(&error, "registryctl.authoring.integration.invalid");
    assert!(!diagnostic.contains(SECRET_SENTINEL));
    assert!(!project.join(".registry-stack/build").exists());

    for header in ["X-API-Key", "X-Auth-Token", "api_key_2"] {
        let temporary = tempfile::tempdir().expect("temporary directory");
        let project = copy_project("custom-system", temporary.path());
        let integration_path = project.join("integrations/eligibility/integration.yaml");
        let mut integration = read_yaml(&integration_path);
        integration["capability"]["http"]["request"]["headers"][header] =
            serde_norway::Value::String(SECRET_SENTINEL.to_string());
        write_yaml(&integration_path, &integration);
        let error = check_registry_project(&ProjectCheckOptions {
            project_directory: project.clone(),
            environment: "local".to_string(),
            explain: false,
            against: None,
            anchor: None,
        })
        .expect_err("credential-bearing header must fail closed");
        let diagnostic = format!("{error:#}");
        assert_authoring_diagnostic(&error, "registryctl.authoring.integration.invalid");
        assert!(!diagnostic.contains(SECRET_SENTINEL));
        assert!(!project.join(".registry-stack/build").exists());
    }
}

#[test]
fn verified_signed_baseline_classifies_semantic_review_dimensions_independently() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = copy_project("custom-system", temporary.path());
    let integration_file = project.join("integrations/eligibility/integration.yaml");
    let integration = std::fs::read_to_string(&integration_file)
        .expect("integration reads")
        .replace(
            "unverified: [fixture-contract-v2]",
            "unverified: [fixture-contract-v2, fixture-contract-v3]",
        );
    std::fs::write(&integration_file, integration).expect("second reviewed version writes");
    let initial = build_registry_project(&ProjectBuildOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        against: None,
        anchor: None,
    })
    .expect("initial project build passes");
    let output = resolve_build_output(&project, initial.output.expect("initial build output"));
    let private_key = temporary.path().join("baseline-private.jwk");
    let public_key = temporary.path().join("baseline-public.jwk");
    write_test_signing_key_pair(&private_key, &public_key);
    let (baseline, anchor) = create_and_sign_test_lane_baseline(
        temporary.path(),
        "notary-baseline",
        ProductAcceptanceLaneV1::Notary,
        &output.join("signing-inputs/notary"),
        &private_key,
        &public_key,
    );
    let (relay_baseline, relay_anchor) = create_and_sign_test_lane_baseline(
        temporary.path(),
        "relay-baseline",
        ProductAcceptanceLaneV1::RelayPublic,
        &output.join("signing-inputs/relay-public"),
        &private_key,
        &public_key,
    );
    let (relay_consultation_baseline, relay_consultation_anchor) =
        create_and_sign_test_lane_baseline(
            temporary.path(),
            "relay-consultation-baseline",
            ProductAcceptanceLaneV1::RelayConsultation,
            &output.join("signing-inputs/relay-consultation"),
            &private_key,
            &public_key,
        );

    for relative in ["approval/review.json", "approval/project-state.json"] {
        let tampered = temporary
            .path()
            .join(format!("tampered-{}", relative.replace(['/', '.'], "-")));
        copy_tree(&baseline, &tampered);
        let path = tampered.join(relative);
        let mut bytes = std::fs::read(&path).expect("signed approval payload reads");
        bytes.push(b' ');
        std::fs::write(&path, bytes).expect("signed approval payload tampers");
        let error = check_registry_project(&ProjectCheckOptions {
            project_directory: project.clone(),
            environment: "local".to_string(),
            explain: false,
            against: Some(tampered),
            anchor: Some(anchor.clone()),
        })
        .expect_err("post-signature approval payload tamper must fail");
        assert!(format!("{error:#}").contains("failed to verify config bundle"));
    }

    let initial_review: serde_json::Value = serde_json::from_slice(
        &std::fs::read(output.join("reviewable/review.json")).expect("initial review reads"),
    )
    .expect("initial review parses");
    let initial_state: serde_json::Value = serde_json::from_slice(
        &std::fs::read(output.join("private/notary/approval/project-state.json"))
            .expect("initial approval state reads"),
    )
    .expect("initial approval state parses");
    assert_eq!(initial_review["baseline"], "initial_without_baseline");
    assert!(initial_review["disclosure_profiles"].is_object());
    assert_public_review_has_only_contract_hashes(&initial_review);
    assert!(initial_state["semantic_digests"].is_object());
    assert!(initial_state["generated_closure_digests"]["notary"].is_string());
    assert!(initial_state["report_digest"].is_string());

    let reviewed_build = build_registry_project_with_baselines_and_context(
        &ProjectBuildOptions {
            project_directory: project.clone(),
            environment: "local".to_string(),
            against: None,
            anchor: None,
        },
        &ProjectBuildBaselineSetOptions {
            relay_against: Some(relay_baseline),
            relay_anchor: Some(relay_anchor),
            relay_consultation_against: Some(relay_consultation_baseline),
            relay_consultation_anchor: Some(relay_consultation_anchor),
            notary_against: Some(baseline.clone()),
            notary_anchor: Some(anchor.clone()),
        },
        &project_execution_context(),
    )
    .expect("verified-baseline build passes");
    let reviewed_output = resolve_build_output(
        &project,
        reviewed_build.output.expect("reviewed build output"),
    );
    let reviewed_record: serde_json::Value = serde_json::from_slice(
        &std::fs::read(reviewed_output.join("reviewable/review.json"))
            .expect("reviewed record reads"),
    )
    .expect("reviewed record parses");
    let reviewed_state: serde_json::Value = serde_json::from_slice(
        &std::fs::read(reviewed_output.join("private/notary/approval/project-state.json"))
            .expect("reviewed approval state reads"),
    )
    .expect("reviewed approval state parses");
    assert_eq!(reviewed_record["baseline"], "verified_signed_bundle");
    assert_public_review_has_only_contract_hashes(&reviewed_record);
    assert_eq!(
        reviewed_state["baseline"]["verified_manifests"]["notary"]["schema"],
        "registry.platform.config_bundle.v1"
    );
    assert_eq!(
        reviewed_state["baseline"]["verified_manifests"]["relay"]["schema"],
        "registry.platform.config_bundle.v1"
    );
    assert_eq!(
        reviewed_state["baseline"]["verified_manifests"]["relay_consultation"]["schema"],
        "registry.platform.config_bundle.v1"
    );
    let signed_paths = reviewed_state["baseline"]["verified_manifests"]["notary"]["files"]
        .as_array()
        .expect("verified manifest files")
        .iter()
        .filter_map(|file| file["path"].as_str())
        .collect::<BTreeSet<_>>();
    assert!(signed_paths.contains("approval/review.json"));
    assert!(signed_paths.contains("approval/project-state.json"));

    let unchanged = check_registry_project(&ProjectCheckOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        explain: false,
        against: Some(baseline.clone()),
        anchor: Some(anchor.clone()),
    })
    .expect("unchanged project checks against signed baseline");
    assert_eq!(unchanged.baseline, "verified_signed_bundle");
    assert!(unchanged.semantic_changes.is_empty());

    let mismatched_input = temporary.path().join("mismatched-baseline-input");
    copy_tree(&output.join("signing-inputs/notary"), &mismatched_input);
    let mismatched_config = mismatched_input.join("config/notary.yaml");
    let mut mismatched_bytes = std::fs::read(&mismatched_config).expect("Notary config reads");
    mismatched_bytes.push(b'\n');
    std::fs::write(&mismatched_config, mismatched_bytes).expect("Notary config changes");
    let mismatched_bundle = sign_test_lane_bundle(
        temporary.path(),
        "mismatched-baseline",
        ProductAcceptanceLaneV1::Notary,
        &mismatched_input,
        &private_key,
        &anchor,
    );
    let mismatch = check_registry_project(&ProjectCheckOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        explain: false,
        against: Some(mismatched_bundle),
        anchor: Some(anchor.clone()),
    })
    .expect_err("signed product closure must match the signed review");
    assert!(format!("{mismatch:#}").contains("lane closure does not match"));

    let report_mismatch_input = temporary.path().join("report-mismatch-input");
    copy_tree(
        &output.join("signing-inputs/notary"),
        &report_mismatch_input,
    );
    let report_mismatch_path = report_mismatch_input.join("approval/review.json");
    let mut mismatched_report: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&report_mismatch_path).expect("approval review reads"),
    )
    .expect("approval review parses");
    mismatched_report["semantic_changes"] = serde_json::Value::Array(Vec::new());
    std::fs::write(
        &report_mismatch_path,
        serde_json::to_vec(&mismatched_report).expect("mismatched review serializes"),
    )
    .expect("mismatched approval review writes");
    let report_mismatch_bundle = sign_test_lane_bundle(
        temporary.path(),
        "report-mismatch",
        ProductAcceptanceLaneV1::Notary,
        &report_mismatch_input,
        &private_key,
        &anchor,
    );
    let report_mismatch = check_registry_project(&ProjectCheckOptions {
        project_directory: project.clone(),
        environment: "local".to_string(),
        explain: false,
        against: Some(report_mismatch_bundle),
        anchor: Some(anchor.clone()),
    })
    .expect_err("signed report/state binding mismatch must fail");
    assert!(format!("{report_mismatch:#}").contains("does not bind the signed review"));

    let scenarios = temporary.path().join("scenarios");
    std::fs::create_dir(&scenarios).expect("scenario root creates");
    let claim_project = scenarios.join("claim");
    let source_version_project = scenarios.join("source-version");
    let operator_project = scenarios.join("operator");
    let notary_cel_project = scenarios.join("notary-cel");
    let policy_project = scenarios.join("policy");
    let consultation_project = scenarios.join("consultation");
    for destination in [
        &claim_project,
        &source_version_project,
        &operator_project,
        &notary_cel_project,
        &policy_project,
        &consultation_project,
    ] {
        copy_tree(&project, destination);
    }

    let project_file = claim_project.join("registry-stack.yaml");
    let authored = std::fs::read_to_string(&project_file)
        .expect("project reads")
        .replace(
            "household.matched && household.approved != null ? household.approved : null",
            "household.matched && household.approved != null ? household.approved == true : null",
        );
    std::fs::write(&project_file, authored).expect("claim-only edit writes");
    let changed = check_registry_project(&ProjectCheckOptions {
        project_directory: claim_project.clone(),
        environment: "local".to_string(),
        explain: false,
        against: Some(baseline.clone()),
        anchor: Some(anchor.clone()),
    })
    .expect("claim-only edit checks against signed baseline");
    assert_eq!(
        changed
            .semantic_changes
            .iter()
            .map(|change| change.dimension)
            .collect::<BTreeSet<_>>(),
        BTreeSet::from(["claim"])
    );

    let compiler_input = temporary.path().join("compiler-baseline-input");
    copy_tree(&output.join("signing-inputs/notary"), &compiler_input);
    let compiler_state_path = compiler_input.join("approval/project-state.json");
    let mut compiler_state: serde_json::Value = serde_json::from_slice(
        &std::fs::read(&compiler_state_path).expect("compiler baseline approval state reads"),
    )
    .expect("compiler baseline approval state parses");
    compiler_state["compiler_version"] = serde_json::Value::String("0.0.0".to_string());
    std::fs::write(
        &compiler_state_path,
        serde_json::to_vec(&compiler_state).expect("compiler baseline state serializes"),
    )
    .expect("compiler baseline approval state writes");
    let compiler_baseline = sign_test_lane_bundle(
        temporary.path(),
        "compiler-baseline",
        ProductAcceptanceLaneV1::Notary,
        &compiler_input,
        &private_key,
        &anchor,
    );
    let compiler_mismatch = check_registry_project(&ProjectCheckOptions {
        project_directory: claim_project,
        environment: "local".to_string(),
        explain: false,
        against: Some(compiler_baseline),
        anchor: Some(anchor.clone()),
    })
    .expect_err("signed report and approval-state mismatch must fail");
    assert!(format!("{compiler_mismatch:#}").contains("disagree on compiler version"));

    replace_in_file(
        &source_version_project.join("integrations/eligibility/integration.yaml"),
        "unverified: [fixture-contract-v2, fixture-contract-v3]",
        "unverified: [fixture-contract-v2, fixture-contract-v3, fixture-contract-v4]",
    );
    assert_change_dimensions(
        source_version_project,
        &baseline,
        &anchor,
        BTreeSet::from(["integration"]),
    );

    replace_in_file(
        &operator_project.join("environments/local.yaml"),
        "https://household-authority.invalid",
        "https://household-authority-two.invalid",
    );
    assert_change_dimensions(
        operator_project,
        &baseline,
        &anchor,
        BTreeSet::from(["operator_security"]),
    );

    let notary_cel_environment = notary_cel_project.join("environments/local.yaml");
    let mut environment = read_yaml(&notary_cel_environment);
    environment["notary_cel"] = serde_norway::from_str("worker_memory_bytes: 1073741824\n")
        .expect("Notary CEL binding parses");
    write_yaml(&notary_cel_environment, &environment);
    assert_change_dimensions(
        notary_cel_project,
        &baseline,
        &anchor,
        BTreeSet::from(["operator_security"]),
    );

    replace_in_file(
        &policy_project.join("registry-stack.yaml"),
        "legal_basis: public-service-delivery",
        "legal_basis: statutory-benefit-screening",
    );
    assert_change_dimensions(
        policy_project,
        &baseline,
        &anchor,
        BTreeSet::from(["service_policy"]),
    );

    replace_in_file(
        &consultation_project.join("registry-stack.yaml"),
        "request.target.identifiers.household_reference",
        "request.target.identifiers.household_case_number",
    );
    replace_in_file(
        &consultation_project.join("integrations/eligibility/fixtures/source-approved.yaml"),
        "scheme: household_reference",
        "scheme: household_case_number",
    );
    assert_change_dimensions(
        consultation_project,
        &baseline,
        &anchor,
        BTreeSet::from(["integration"]),
    );
}

fn assert_change_dimensions(
    project: PathBuf,
    baseline: &Path,
    anchor: &Path,
    expected: BTreeSet<&str>,
) {
    let report = check_registry_project(&ProjectCheckOptions {
        project_directory: project,
        environment: "local".to_string(),
        explain: false,
        against: Some(baseline.to_path_buf()),
        anchor: Some(anchor.to_path_buf()),
    })
    .expect("semantic review scenario checks against signed baseline");
    assert_eq!(
        report
            .semantic_changes
            .iter()
            .map(|change| change.dimension)
            .collect::<BTreeSet<_>>(),
        expected
    );
}

fn assert_public_review_has_only_contract_hashes(review: &serde_json::Value) {
    fn visit(value: &serde_json::Value, contract_hashes: &mut usize) {
        match value {
            serde_json::Value::Object(object) => {
                for (key, value) in object {
                    let lower = key.to_ascii_lowercase();
                    if lower.contains("hash") || lower.contains("digest") {
                        assert_eq!(
                            key, "contract_hash",
                            "human review exposes lower-level field {key}"
                        );
                        let contract_hash =
                            value.as_str().expect("generated contract_hash is a string");
                        assert!(contract_hash.starts_with("sha256:"));
                        *contract_hashes += 1;
                    }
                    visit(value, contract_hashes);
                }
            }
            serde_json::Value::Array(values) => {
                for value in values {
                    visit(value, contract_hashes);
                }
            }
            serde_json::Value::Null
            | serde_json::Value::Bool(_)
            | serde_json::Value::Number(_)
            | serde_json::Value::String(_) => {}
        }
    }

    let mut contract_hashes = 0;
    visit(review, &mut contract_hashes);
    assert!(
        contract_hashes > 0,
        "registry-backed human review exposes its generated contract_hash"
    );
}

fn replace_in_file(path: &Path, from: &str, to: &str) {
    let contents = std::fs::read_to_string(path).expect("scenario file reads");
    assert!(contents.contains(from), "replacement source must exist");
    std::fs::write(path, contents.replace(from, to)).expect("scenario file writes");
}

fn extend_exact_selector(project: &Path, golden_name: &str, size: usize) {
    let (integration_relative, alias, original_input) = match golden_name {
        "custom-system" => (
            "integrations/eligibility/integration.yaml",
            "eligibility",
            "household_reference",
        ),
        "snapshot-exact" => (
            "integrations/person-snapshot/integration.yaml",
            "person-snapshot",
            "person_id",
        ),
        _ => panic!("unsupported selector test golden"),
    };
    let integration_path = project.join(integration_relative);
    let mut integration = read_yaml(&integration_path);
    for component in 2..=size {
        let name = format!("selector_{component}");
        let declaration = if component == 4 {
            serde_norway::from_str(
                "role: selector\ntype: string\nformat: date\nminLength: 10\nmaxLength: 10\n",
            )
            .expect("full-date input declaration")
        } else {
            serde_norway::from_str(&format!(
                "role: selector\ntype: string\nmaxLength: 8\npattern: '^S{component}$'\n"
            ))
            .expect("string input declaration")
        };
        integration["input"]
            .as_mapping_mut()
            .expect("integration input mapping")
            .insert(serde_norway::Value::String(name.clone()), declaration);
        if golden_name == "custom-system" {
            integration["capability"]["http"]["request"]["query"]
                .as_mapping_mut()
                .expect("HTTP query mapping")
                .insert(
                    serde_norway::Value::String(name.clone()),
                    serde_norway::from_str(&format!("input: {name}\n"))
                        .expect("query input expression"),
                );
        } else {
            integration["capability"]["snapshot"]["exact"]
                .as_mapping_mut()
                .expect("snapshot exact mapping")
                .insert(
                    serde_norway::Value::String(name.clone()),
                    serde_norway::from_str(&format!("input: {name}\n"))
                        .expect("snapshot input expression"),
                );
        }
    }
    write_yaml(&integration_path, &integration);

    let project_path = project.join("registry-stack.yaml");
    let mut project_document = read_yaml(&project_path);
    let services: &[(&str, &str)] = if golden_name == "custom-system" {
        &[("household-eligibility", "household")]
    } else {
        &[
            ("benefits-eligibility", "person"),
            ("emergency-assistance", "person"),
        ]
    };
    for (service, consultation) in services {
        let mapping =
            &mut project_document["services"][*service]["consultations"][*consultation]["input"];
        for component in 2..=size {
            let name = format!("selector_{component}");
            mapping
                .as_mapping_mut()
                .expect("consultation input mapping")
                .insert(
                    serde_norway::Value::String(name.clone()),
                    serde_norway::Value::String(format!("request.target.identifiers.{name}")),
                );
        }
    }
    write_yaml(&project_path, &project_document);

    let fixture_directory = integration_path
        .parent()
        .expect("integration parent")
        .join("fixtures");
    for fixture in std::fs::read_dir(fixture_directory).expect("fixture directory") {
        let path = fixture.expect("fixture entry").path();
        if path.extension().and_then(|value| value.to_str()) != Some("yaml") {
            continue;
        }
        let mut document = read_yaml(&path);
        for component in 2..=size {
            let value = if component == 4 {
                "2017-06-15".to_string()
            } else {
                format!("S{component}")
            };
            document["input"]
                .as_mapping_mut()
                .expect("fixture input mapping")
                .insert(
                    serde_norway::Value::String(format!("selector_{component}")),
                    serde_norway::Value::String(value.clone()),
                );
            if let Some(identifiers) = document
                .get_mut("request")
                .and_then(|request| request.get_mut("target"))
                .and_then(|target| target.get_mut("identifiers"))
                .and_then(serde_norway::Value::as_sequence_mut)
            {
                identifiers.push(
                    serde_norway::from_str(&format!(
                        "{{ scheme: selector_{component}, value: {value:?} }}"
                    ))
                    .expect("fixture request selector"),
                );
            }
            if golden_name == "custom-system" {
                if let Some(interactions) = document
                    .get_mut("interactions")
                    .and_then(serde_norway::Value::as_sequence_mut)
                {
                    for interaction in interactions {
                        let query = interaction["expect"]["query"]
                            .as_mapping_mut()
                            .expect("fixture expected query mapping");
                        query.insert(
                            serde_norway::Value::String(format!("selector_{component}")),
                            serde_norway::Value::String(value.clone()),
                        );
                    }
                }
            }
        }
        write_yaml(&path, &document);
    }

    if golden_name == "snapshot-exact" {
        let entity_path = project.join("entities/people.yaml");
        let mut entity = read_yaml(&entity_path);
        let environment_path = project.join("environments/local.yaml");
        let mut environment = read_yaml(&environment_path);
        for component in 2..=size {
            let name = format!("selector_{component}");
            entity["schema"]["properties"]
                .as_mapping_mut()
                .expect("entity properties")
                .insert(
                    serde_norway::Value::String(name.clone()),
                    if component == 4 {
                        // Full-date canonicalization belongs to the consultation input.
                        // Snapshot exact keys remain physical UTF-8 binary values.
                        serde_norway::from_str("type: string\nmaxLength: 10\n")
                            .expect("full-date snapshot key field")
                    } else {
                        serde_norway::from_str("type: string\nmaxLength: 8\n")
                            .expect("string entity selector field")
                    },
                );
            entity["schema"]["required"]
                .as_sequence_mut()
                .expect("entity required fields")
                .push(serde_norway::Value::String(name.clone()));
            environment["entities"]["people"]["columns"]
                .as_mapping_mut()
                .expect("entity columns")
                .insert(
                    serde_norway::Value::String(name),
                    serde_norway::Value::String(format!("selector_col_{component}")),
                );
        }
        write_yaml(&entity_path, &entity);
        write_yaml(&environment_path, &environment);
    }

    assert!(integration["input"].get(original_input).is_some());
    assert!(integration["id"].as_str().is_some(), "{alias}");
}

fn duplicate_project_integration(project: &Path, source_alias: &str, target_alias: &str) {
    copy_tree(
        &project.join("integrations").join(source_alias),
        &project.join("integrations").join(target_alias),
    );
    let integration_path = project
        .join("integrations")
        .join(target_alias)
        .join("integration.yaml");
    let mut integration = read_yaml(&integration_path);
    integration["id"] = serde_norway::Value::String(format!("{target_alias}-integration"));
    write_yaml(&integration_path, &integration);

    let project_path = project.join("registry-stack.yaml");
    let mut project_document = read_yaml(&project_path);
    project_document["integrations"]
        .as_mapping_mut()
        .expect("project integrations mapping")
        .insert(
            serde_norway::Value::String(target_alias.to_string()),
            serde_norway::from_str(&format!(
                "file: integrations/{target_alias}/integration.yaml\n"
            ))
            .expect("project integration reference"),
        );
    let (service_name, consultation_name, duplicated_consultation) = project_document["services"]
        .as_mapping()
        .and_then(|services| {
            services.iter().find_map(|(service_name, service)| {
                service["consultations"]
                    .as_mapping()
                    .and_then(|consultations| {
                        consultations
                            .iter()
                            .find_map(|(consultation_name, consultation)| {
                                (consultation["integration"].as_str() == Some(source_alias)).then(
                                    || {
                                        (
                                            service_name.clone(),
                                            consultation_name.clone(),
                                            consultation.clone(),
                                        )
                                    },
                                )
                            })
                    })
            })
        })
        .expect("source integration consultation");
    let mut duplicated_consultation = duplicated_consultation;
    duplicated_consultation["integration"] = serde_norway::Value::String(target_alias.to_string());
    let service = project_document["services"]
        .as_mapping_mut()
        .and_then(|services| services.get_mut(&service_name))
        .expect("project service");
    service["consultations"]
        .as_mapping_mut()
        .expect("project consultations mapping")
        .insert(
            serde_norway::Value::String(target_alias.to_string()),
            duplicated_consultation,
        );
    let consultation_name = consultation_name
        .as_str()
        .expect("consultation name is a string");
    let reference = format!("{consultation_name}.");
    let duplicated_claims = service["claims"]
        .as_mapping()
        .map(|claims| {
            claims
                .iter()
                .filter_map(|(name, claim)| {
                    let source_claim = name.as_str()?;
                    if !yaml_contains_string(claim, &reference) {
                        return None;
                    }
                    let mut duplicated_claim = claim.clone();
                    replace_yaml_strings(
                        &mut duplicated_claim,
                        &reference,
                        &format!("{target_alias}."),
                    );
                    Some((
                        source_claim.to_string(),
                        format!("{target_alias}-{source_claim}"),
                        duplicated_claim,
                    ))
                })
                .collect::<Vec<_>>()
        })
        .filter(|claims| !claims.is_empty())
        .expect("source consultation claims");
    for (_, target_claim, duplicated_claim) in &duplicated_claims {
        service["claims"]
            .as_mapping_mut()
            .expect("project claims mapping")
            .insert(
                serde_norway::Value::String(target_claim.clone()),
                duplicated_claim.clone(),
            );
    }
    for credential in service["credential_profiles"]
        .as_mapping_mut()
        .expect("project credential profiles")
        .values_mut()
    {
        credential["claims"]
            .as_sequence_mut()
            .expect("credential profile claims")
            .extend(
                duplicated_claims
                    .iter()
                    .map(|(_, target_claim, _)| serde_norway::Value::String(target_claim.clone())),
            );
    }
    write_yaml(&project_path, &project_document);
    let claim_translations = duplicated_claims
        .iter()
        .map(|(source, target, _)| (source.clone(), target.clone()))
        .collect::<Vec<_>>();
    rewrite_duplicated_fixture_claims(
        &project
            .join("integrations")
            .join(target_alias)
            .join("fixtures"),
        &claim_translations,
    );

    let environment_path = project.join("environments/local.yaml");
    let mut environment = read_yaml(&environment_path);
    let mut source_binding = environment["integrations"][source_alias].clone();
    namespace_secret_references(&mut source_binding, target_alias);
    environment["integrations"]
        .as_mapping_mut()
        .expect("environment integrations mapping")
        .insert(
            serde_norway::Value::String(target_alias.to_string()),
            source_binding,
        );
    write_yaml(&environment_path, &environment);
}

fn rewrite_duplicated_fixture_claims(fixtures: &Path, translations: &[(String, String)]) {
    let translate = |claim: &str| {
        translations
            .iter()
            .find_map(|(source, target)| (source == claim).then_some(target.as_str()))
    };
    for entry in std::fs::read_dir(fixtures).expect("duplicated fixtures directory reads") {
        let path = entry.expect("duplicated fixture entry reads").path();
        if path.extension().and_then(std::ffi::OsStr::to_str) != Some("yaml") {
            continue;
        }
        let mut fixture = read_yaml(&path);
        if let Some(claims) = fixture["expect"]["claims"].as_mapping_mut() {
            let rewritten = claims
                .iter()
                .map(|(claim, expected)| {
                    let claim = claim.as_str().expect("fixture claim is a string");
                    (
                        serde_norway::Value::String(translate(claim).unwrap_or(claim).to_string()),
                        expected.clone(),
                    )
                })
                .collect::<serde_norway::Mapping>();
            *claims = rewritten;
        }
        if let Some(request_claims) = fixture
            .get_mut("request")
            .and_then(|request| request.get_mut("claims"))
            .and_then(serde_norway::Value::as_sequence_mut)
        {
            for claim in request_claims {
                let source_claim = claim.as_str().expect("request claim is a string");
                if let Some(target_claim) = translate(source_claim) {
                    *claim = serde_norway::Value::String(target_claim.to_string());
                }
            }
        }
        write_yaml(&path, &fixture);
    }
}

fn yaml_contains_string(value: &serde_norway::Value, needle: &str) -> bool {
    match value {
        serde_norway::Value::String(value) => value.contains(needle),
        serde_norway::Value::Mapping(mapping) => mapping.iter().any(|(key, value)| {
            yaml_contains_string(key, needle) || yaml_contains_string(value, needle)
        }),
        serde_norway::Value::Sequence(sequence) => sequence
            .iter()
            .any(|value| yaml_contains_string(value, needle)),
        _ => false,
    }
}

fn replace_yaml_strings(value: &mut serde_norway::Value, from: &str, to: &str) {
    match value {
        serde_norway::Value::String(value) => *value = value.replace(from, to),
        serde_norway::Value::Mapping(mapping) => {
            for value in mapping.values_mut() {
                replace_yaml_strings(value, from, to);
            }
        }
        serde_norway::Value::Sequence(sequence) => {
            for value in sequence {
                replace_yaml_strings(value, from, to);
            }
        }
        _ => {}
    }
}

fn namespace_secret_references(value: &mut serde_norway::Value, namespace: &str) {
    let namespace = namespace.replace('-', "_").to_ascii_uppercase();
    namespace_secret_references_with_suffix(value, &namespace);
}

fn namespace_secret_references_with_suffix(value: &mut serde_norway::Value, namespace: &str) {
    match value {
        serde_norway::Value::Mapping(mapping) => {
            if let Some(secret) = mapping
                .get_mut(serde_norway::Value::String("secret".to_string()))
                .and_then(|value| value.as_str().map(ToOwned::to_owned))
            {
                mapping.insert(
                    serde_norway::Value::String("secret".to_string()),
                    serde_norway::Value::String(format!("{secret}_{namespace}")),
                );
                return;
            }
            for nested in mapping.values_mut() {
                namespace_secret_references_with_suffix(nested, namespace);
            }
        }
        serde_norway::Value::Sequence(sequence) => {
            for nested in sequence {
                namespace_secret_references_with_suffix(nested, namespace);
            }
        }
        _ => {}
    }
}

fn read_yaml(path: &Path) -> serde_norway::Value {
    serde_norway::from_slice(&std::fs::read(path).expect("YAML reads")).expect("YAML parses")
}

fn write_yaml(path: &Path, document: &serde_norway::Value) {
    std::fs::write(
        path,
        serde_norway::to_string(document).expect("YAML serializes"),
    )
    .expect("YAML writes");
}

fn reverse_yaml_mapping(path: &Path, keys: &[&str]) {
    let mut document = read_yaml(path);
    let mut current = &mut document;
    for key in keys {
        current = &mut current[*key];
    }
    let mapping = current.as_mapping_mut().expect("selected YAML mapping");
    let mut entries = mapping
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect::<Vec<_>>();
    entries.reverse();
    *mapping = entries.into_iter().collect();
    write_yaml(path, &document);
}

fn remove_custom_cel_claim(project: &Path) {
    let project_path = project.join("registry-stack.yaml");
    let mut document = read_yaml(&project_path);
    let service = &mut document["services"]["household-eligibility"];
    service["claims"]
        .as_mapping_mut()
        .expect("custom claims")
        .remove(serde_norway::Value::String(
            "source-household-approval-decision".to_string(),
        ));
    service["credential_profiles"]["household-eligibility"]["claims"]
        .as_sequence_mut()
        .expect("custom credential claims")
        .retain(|claim| claim.as_str() != Some("source-household-approval-decision"));
    write_yaml(&project_path, &document);
    for fixture in std::fs::read_dir(project.join("integrations/eligibility/fixtures"))
        .expect("custom fixture directory")
    {
        let path = fixture.expect("fixture entry").path();
        let mut document = read_yaml(&path);
        let claims = document
            .get_mut("expect")
            .and_then(serde_norway::Value::as_mapping_mut)
            .and_then(|expect| expect.get_mut("claims"))
            .and_then(serde_norway::Value::as_mapping_mut);
        if let Some(claims) = claims {
            claims.remove(serde_norway::Value::String(
                "source-household-approval-decision".to_string(),
            ));
        }
        write_yaml(&path, &document);
    }
}

fn make_opencrvs_composite_dci(project: &Path) {
    let integration_path = project.join("integrations/birth-record/integration.yaml");
    let mut integration = read_yaml(&integration_path);
    integration["input"] = serde_norway::from_str(
        r#"uin:
  role: selector
  type: string
  maxLength: 16
  pattern: "^[0-9]{10}$"
family:
  role: selector
  type: string
  maxLength: 80
  pattern: "^Example$"
place:
  role: selector
  type: string
  maxLength: 120
  pattern: "^Fictional District$"
"#,
    )
    .expect("composite DCI inputs");
    integration["source"]["protocol"]["signed_dci"]["selectors"] = serde_norway::from_str(
        r#"uin: { field: identifier_value, response_pointer: /identifier/0/identifier_value }
family: { field: family_name, response_pointer: /child/family_name }
place: { field: place_of_birth, response_pointer: /place_of_birth }
"#,
    )
    .expect("composite DCI predicates");
    write_yaml(&integration_path, &integration);
    replace_in_file(
        &project.join("integrations/birth-record/adapter.rhai"),
        "selectors: #{ uin: ctx.input.uin }",
        "selectors: #{\n            uin: ctx.input.uin,\n            family: ctx.input.family,\n            place: ctx.input.place\n        }",
    );

    let project_path = project.join("registry-stack.yaml");
    let mut project_document = read_yaml(&project_path);
    project_document["services"]["birth-verification"]["consultations"]["birth"]["input"] =
        serde_norway::from_str(
            r#"uin: request.target.identifiers.uin
family: request.target.identifiers.family
place: request.target.identifiers.place
"#,
        )
        .expect("composite DCI consultation mapping");
    let service = &mut project_document["services"]["birth-verification"];
    service["claims"]
        .as_mapping_mut()
        .expect("OpenCRVS claims")
        .remove(serde_norway::Value::String("age-band".to_string()));
    service["credential_profiles"]["birth-summary"]["claims"]
        .as_sequence_mut()
        .expect("OpenCRVS credential claims")
        .retain(|claim| claim.as_str() != Some("age-band"));
    write_yaml(&project_path, &project_document);

    let fixture_directory = project.join("integrations/birth-record/fixtures");
    for entry in std::fs::read_dir(&fixture_directory).expect("OpenCRVS fixture directory") {
        let path = entry.expect("OpenCRVS fixture entry").path();
        if !path.is_file() {
            continue;
        }
        let retained = matches!(
            path.file_name().and_then(|name| name.to_str()),
            Some("match.yaml" | "ambiguous.yaml")
        );
        if !retained {
            std::fs::remove_file(path).expect("unused OpenCRVS fixture removes");
            continue;
        }
        let mut fixture = read_yaml(&path);
        fixture["input"] = serde_norway::from_str(
            "uin: '0000000001'\nfamily: Example\nplace: Fictional District\n",
        )
        .expect("composite DCI fixture inputs");
        if fixture.get("request").is_some() {
            fixture["request"]["target"]["identifiers"] = serde_norway::from_str(
                r#"- { scheme: uin, value: "0000000001" }
- { scheme: family, value: Example }
- { scheme: place, value: Fictional District }
"#,
            )
            .expect("composite DCI request identifiers");
        }
        let data_interaction = fixture["interactions"]
            .as_sequence_mut()
            .and_then(|interactions| {
                interactions.iter_mut().find(|interaction| {
                    interaction["expect"]["path"].as_str() == Some("/dci/v1/birth/search")
                })
            })
            .expect("DCI data interaction");
        data_interaction["expect"]["body"]["message"]["search_request"][0]["search_criteria"]
            ["query"]["predicates"] = serde_norway::from_str(
            r#"- { field: family_name, operator: eq, value: Example }
- { field: place_of_birth, operator: eq, value: Fictional District }
- { field: identifier_value, operator: eq, value: "0000000001" }
"#,
        )
        .expect("composite DCI request predicates");
        if let Some(claims) = fixture
            .get_mut("expect")
            .and_then(serde_norway::Value::as_mapping_mut)
            .and_then(|expect| expect.get_mut("claims"))
            .and_then(serde_norway::Value::as_mapping_mut)
        {
            claims.remove(serde_norway::Value::String("age-band".to_string()));
        }
        write_yaml(&path, &fixture);
    }
}

fn copy_project(name: &str, temporary: &Path) -> PathBuf {
    let destination = temporary.join(name);
    copy_tree(&golden(name), &destination);
    destination
}

fn write_test_signing_key_pair(private_key: &Path, public_key: &Path) {
    std::fs::write(private_key, TEST_PRIVATE_JWK).expect("private test key writes");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        let mut permissions = std::fs::metadata(private_key)
            .expect("private test key metadata reads")
            .permissions();
        permissions.set_mode(0o600);
        std::fs::set_permissions(private_key, permissions)
            .expect("private test key becomes owner-only");
    }
    std::fs::write(public_key, TEST_PUBLIC_JWK).expect("public test key writes");
}

fn create_and_sign_test_lane_baseline(
    root: &Path,
    label: &str,
    lane: ProductAcceptanceLaneV1,
    input: &Path,
    private_key: &Path,
    public_key: &Path,
) -> (PathBuf, PathBuf) {
    let anchor = root.join(format!("{label}-anchor.json"));
    create_trust_anchor(&TrustAnchorCreateOptions {
        lane,
        input: input.to_path_buf(),
        public_keys: vec![public_key.to_path_buf()],
        threshold: 1,
        output_file: anchor.clone(),
    })
    .expect("lane trust anchor creates");
    let bundle = sign_test_lane_bundle(root, label, lane, input, private_key, &anchor);
    (bundle, anchor)
}

fn sign_test_lane_bundle(
    root: &Path,
    label: &str,
    lane: ProductAcceptanceLaneV1,
    input: &Path,
    private_key: &Path,
    anchor: &Path,
) -> PathBuf {
    let output = root.join(format!("{label}-signed"));
    sign_product_bundle(&ProductBundleSignOptions {
        lane,
        input: input.to_path_buf(),
        anchor: anchor.to_path_buf(),
        preceding_approved_set: None,
        keys: vec![format!("file:{}", private_key.display())],
        output_dir: output.clone(),
    })
    .expect("lane baseline signs");
    output.join("bundle")
}

fn author_oid4vci_binding(project: &Path, service: &str, profile: &str, id_type: &str) {
    let project_path = project.join("registry-stack.yaml");
    let mut authored_project = read_yaml(&project_path);
    authored_project["services"][service]["credential_profiles"][profile]["type"] =
        serde_norway::Value::String(format!(
            "https://notary.example.invalid/credentials/{profile}/v1"
        ));
    write_yaml(&project_path, &authored_project);

    let environment_path = project.join("environments/local.yaml");
    let mut environment = read_yaml(&environment_path);
    environment["notary_state"] = serde_norway::from_str(
        "postgresql:\n  root_certificate_path: /run/secrets/notary-postgres-ca.pem\n",
    )
    .expect("Notary PostgreSQL state binding");
    environment["oid4vci"] = serde_norway::from_str(&format!(
        r#"public_base_url: https://notary.example.invalid
credential:
  service: {service}
  profile: {profile}
authorization_server:
  issuer: https://esignet.example.invalid
  jwks_url: https://esignet.example.invalid/.well-known/jwks.json
  userinfo_url: https://esignet.example.invalid/userinfo
  authorize_url: https://esignet-ui.example.invalid/authorize
  token_url: https://esignet.example.invalid/token
client:
  id: example-wallet-client
  signing_key: {{ secret: OID4VCI_ESIGNET_CLIENT_JWK }}
  signing_kid: example-wallet-client-key-1
access_token:
  signing_key: {{ secret: OID4VCI_ACCESS_TOKEN_JWK }}
  signing_kid: did:web:notary.example.invalid#access-token-key-1
sensitive_state_key: {{ secret: OID4VCI_SENSITIVE_STATE_KEY }}
subject:
  token_claim: individual_id
  id_type: {id_type}
redirect_uri: https://notary.example.invalid/oid4vci/offer/callback
allowed_wallet_origins: [https://wallet.example.invalid]
"#
    ))
    .expect("OID4VCI binding");
    write_yaml(&environment_path, &environment);
}

fn author_representative_oid4vci_binding(project: &Path, requester_id_type: &str) {
    let project_path = project.join("registry-stack.yaml");
    let mut authored_project = read_yaml(&project_path);
    let service = &mut authored_project["services"]["household-eligibility"];
    service["consultations"]["household"]["input"]["representative_reference"] =
        serde_norway::Value::String(format!("request.requester.identifiers.{requester_id_type}"));
    service["credential_profiles"]["household-eligibility"]["claims"] =
        serde_norway::from_str("[source-household-approval-decision]")
            .expect("single representative credential root");
    write_yaml(&project_path, &authored_project);

    let integration_path = project.join("integrations/eligibility/integration.yaml");
    let mut integration = read_yaml(&integration_path);
    integration["input"]["representative_reference"] = serde_norway::from_str(
        r#"role: selector
type: string
maxLength: 18
pattern: "^HH-[A-Z0-9]{8}$"
"#,
    )
    .expect("representative selector input");
    integration["capability"]["http"]["request"]["query"]["representative"] =
        serde_norway::from_str("{ input: representative_reference }")
            .expect("representative query binding");
    write_yaml(&integration_path, &integration);

    for entry in std::fs::read_dir(project.join("integrations/eligibility/fixtures"))
        .expect("fixture directory reads")
    {
        let path = entry.expect("fixture entry").path();
        let mut fixture = read_yaml(&path);
        fixture["input"]["representative_reference"] =
            serde_norway::Value::String("HH-ZZ99YY88".to_string());
        fixture["interactions"][0]["expect"]["query"]["representative"] =
            serde_norway::Value::String("HH-ZZ99YY88".to_string());
        if fixture.get("request").is_some() {
            fixture["request"]["requester"] = serde_norway::from_str(&format!(
                r#"type: Person
identifiers:
  - scheme: {requester_id_type}
    value: HH-ZZ99YY88
"#
            ))
            .expect("fixture requester");
            fixture["request"]["claims"] =
                serde_norway::from_str("[source-household-approval-decision]")
                    .expect("fixture representative claim");
        }
        write_yaml(&path, &fixture);
    }

    let environment_path = project.join("environments/local.yaml");
    let mut environment = read_yaml(&environment_path);
    environment["oid4vci"]["representative_issuance"] = serde_norway::from_str(
        r#"relationship: authorized-representative
proof_claim: household-record-exists
target_id_type: household_reference
"#,
    )
    .expect("representative issuance binding");
    write_yaml(&environment_path, &environment);
}

fn merge_environment_yaml(path: &Path, patch: &str) {
    fn merge(target: &mut serde_norway::Value, patch: serde_norway::Value) {
        match (target, patch) {
            (serde_norway::Value::Mapping(target), serde_norway::Value::Mapping(patch)) => {
                for (key, value) in patch {
                    if let Some(target) = target.get_mut(&key) {
                        merge(target, value);
                    } else {
                        target.insert(key, value);
                    }
                }
            }
            (target, patch) => *target = patch,
        }
    }

    let mut environment = read_yaml(path);
    merge(
        &mut environment,
        serde_norway::from_str(patch).expect("environment patch"),
    );
    write_yaml(path, &environment);
}

fn rename_custom_input(project: &Path, name: &str) {
    let mut paths = vec![
        project.join("registry-stack.yaml"),
        project.join("integrations/eligibility/integration.yaml"),
    ];
    paths.extend(
        std::fs::read_dir(project.join("integrations/eligibility/fixtures"))
            .expect("fixture directory reads")
            .map(|entry| entry.expect("fixture entry").path()),
    );
    for path in paths {
        let contents = std::fs::read_to_string(&path).expect("authored file reads");
        let replaced = contents.replace("household_reference", name);
        assert_ne!(
            contents,
            replaced,
            "{} did not bind the input",
            path.display()
        );
        std::fs::write(path, replaced).expect("renamed authored input writes");
    }
}

fn copy_tree(source: &Path, destination: &Path) {
    std::fs::create_dir(destination).expect("copy destination creates");
    for entry in std::fs::read_dir(source).expect("copy source reads") {
        let entry = entry.expect("copy entry");
        if entry.file_name() == ".registry-stack" {
            continue;
        }
        let source_path = entry.path();
        let destination_path = destination.join(entry.file_name());
        if source_path.is_dir() {
            copy_tree(&source_path, &destination_path);
        } else {
            std::fs::copy(&source_path, &destination_path).expect("project file copies");
        }
    }
}

fn resolve_build_output(project: &Path, reported: String) -> PathBuf {
    let relative = Path::new(&reported);
    assert!(
        !relative.is_absolute(),
        "build output must be project-relative: {reported}"
    );
    assert!(
        reported.starts_with(".registry-stack/build/"),
        "build output must remain under the project build root: {reported}"
    );
    project.join(relative)
}

fn directory_closure(root: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut files = Vec::new();
    walkdir(root, root, &mut files);
    files.sort_by(|left, right| left.0.cmp(&right.0));
    files
}

fn test_sha256_uri(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

fn closure_digest(files: &[(PathBuf, Vec<u8>)]) -> String {
    use std::fmt::Write as _;

    let mut hasher = Sha256::new();
    for (path, bytes) in files {
        let path = path
            .to_str()
            .expect("generated relative paths are UTF-8")
            .as_bytes();
        hasher.update(
            u64::try_from(path.len())
                .expect("path length fits u64")
                .to_be_bytes(),
        );
        hasher.update(path);
        hasher.update(
            u64::try_from(bytes.len())
                .expect("file length fits u64")
                .to_be_bytes(),
        );
        hasher.update(bytes);
    }
    let digest = hasher.finalize();
    let mut encoded = String::with_capacity(digest.len() * 2);
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing to String cannot fail");
    }
    encoded
}

fn walkdir(root: &Path, directory: &Path, output: &mut Vec<(PathBuf, Vec<u8>)>) {
    for entry in std::fs::read_dir(directory).expect("build directory reads") {
        let path = entry.expect("directory entry").path();
        if path.is_dir() {
            walkdir(root, &path, output);
        } else {
            output.push((
                path.strip_prefix(root)
                    .expect("generated path is rooted")
                    .to_path_buf(),
                std::fs::read(path).expect("generated file reads"),
            ));
        }
    }
}

#[cfg(unix)]
fn assert_owner_only(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;

    let metadata = std::fs::metadata(path).expect("generated metadata reads");
    let expected = if metadata.is_dir() { 0o700 } else { 0o600 };
    assert_eq!(
        metadata.permissions().mode() & 0o777,
        expected,
        "{}",
        path.display()
    );
    if metadata.is_dir() {
        for entry in std::fs::read_dir(path).expect("generated directory reads") {
            assert_owner_only(&entry.expect("generated entry reads").path());
        }
    }
}
