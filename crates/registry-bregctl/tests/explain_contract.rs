// SPDX-License-Identifier: Apache-2.0

//! Gate for the `bregctl explain` wire contract described in
//! `products/breg/contracts/explain/README.md`.
//!
//! For every tracked fixture and every `explain` subject, this runs the real
//! `bregctl` binary, then validates the `explanation` object it prints
//! against the matching JSON Schema contract file. A drift between
//! `explain_*` in `lib.rs` and the schemas under
//! `products/breg/contracts/explain/` fails here before it reaches an
//! adopter.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use jsonschema::{Draft, JSONSchema};
use serde_json::Value;

const API_VERSION: &str = "registry.registrystack.org/breg-explain/v1alpha1";

/// Fixture directories the gate replays, each an on-disk registry project
/// under `products/breg/`. Chosen to cover every subject's optional
/// branches: `farmer-landholding-evidence` is the only fixture with an
/// `action-handler/v2` handler (exercises `actions[].evidence`), and
/// `spatial-service-sites` is the only fixture with spatial queries
/// (exercises `spatialQueries` and `gis`).
const FIXTURES: &[(&str, &str)] = &[
    (
        "asset-site-placement",
        "products/breg/acceptance/asset-site-placement",
    ),
    (
        "business-establishments",
        "products/breg/acceptance/business-establishments",
    ),
    (
        "asset-site-placement-change-requests",
        "products/breg/acceptance/asset-site-placement-change-requests",
    ),
    (
        "publicschema-household-change-requests",
        "products/breg/acceptance/publicschema-household-change-requests",
    ),
    (
        "person-name-change-rhai",
        "products/breg/acceptance/person-name-change-rhai",
    ),
    (
        "person-registration-rhai",
        "products/breg/acceptance/person-registration-rhai",
    ),
    (
        "request-attachments",
        "products/breg/acceptance/request-attachments",
    ),
    (
        "asset-registration-actions",
        "products/breg/fixtures/asset-registration-actions",
    ),
    (
        "household-contact-actions",
        "products/breg/fixtures/household-contact-actions",
    ),
    (
        "farmer-landholding-evidence",
        "products/breg/acceptance/farmer-landholding-evidence",
    ),
    (
        "spatial-service-sites",
        "products/breg/acceptance/spatial-service-sites",
    ),
];

/// Access-review scenario files, replayed through `explain access --scenario`.
const ACCESS_SCENARIOS: &[(&str, &str)] = &[
    (
        "allowed",
        "products/breg/examples/access-review/allowed.json",
    ),
    (
        "missing-scope",
        "products/breg/examples/access-review/missing-scope.json",
    ),
];

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repository root resolves")
}

fn bregctl(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .args(arguments)
        .output()
        .expect("bregctl starts")
}

fn json_stdout(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).expect("command stdout is JSON")
}

fn explain(subject: &str, project: &Path) -> Value {
    let output = bregctl(&[
        "--format",
        "json",
        "explain",
        subject,
        project.to_str().expect("fixture path is UTF-8"),
    ]);
    assert!(
        output.status.success(),
        "bregctl explain {subject} {project:?} failed: {output:?}"
    );
    let report = json_stdout(&output);
    assert_eq!(
        report["ok"],
        Value::Bool(true),
        "bregctl explain {subject} {project:?} reported ok=false: {report:#?}"
    );
    report["explanation"].clone()
}

fn explain_with_scenario(project: &Path, scenario: &Path) -> Value {
    let output = bregctl(&[
        "--format",
        "json",
        "explain",
        "access",
        project.to_str().expect("fixture path is UTF-8"),
        "--scenario",
        scenario.to_str().expect("scenario path is UTF-8"),
    ]);
    assert!(
        output.status.success(),
        "bregctl explain access {project:?} --scenario {scenario:?} failed: {output:?}"
    );
    let report = json_stdout(&output);
    assert_eq!(
        report["ok"],
        Value::Bool(true),
        "bregctl explain access {project:?} --scenario {scenario:?} reported ok=false: {report:#?}"
    );
    report["explanation"].clone()
}

fn load_schema(kind: &str) -> JSONSchema {
    let path = repo_root()
        .join("products/breg/contracts/explain")
        .join(format!("{kind}.schema.json"));
    let bytes =
        std::fs::read(&path).unwrap_or_else(|error| panic!("schema {path:?} reads: {error}"));
    let schema: Value = serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("schema {path:?} parses: {error}"));
    JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&schema)
        .unwrap_or_else(|error| panic!("schema {path:?} compiles: {error}"))
}

/// Asserts `explanation` carries the envelope for `kind`, then validates it
/// in full against that kind's schema file. On a schema violation, every
/// validation error is printed with its `instance_path` before panicking, so
/// a single failing fixture shows the complete list of what is wrong rather
/// than only the first mismatch.
fn assert_matches_contract(label: &str, kind: &str, explanation: &Value) {
    assert_eq!(
        explanation["apiVersion"],
        Value::String(API_VERSION.to_owned()),
        "{label}: unexpected apiVersion in {explanation:#?}"
    );
    assert_eq!(
        explanation["kind"],
        Value::String(kind.to_owned()),
        "{label}: unexpected kind in {explanation:#?}"
    );

    let schema = load_schema(kind);
    let result = schema.validate(explanation);
    if let Err(errors) = result {
        let mut report = format!("{label}: {kind} does not satisfy its schema contract:\n");
        for error in errors {
            report.push_str(&format!("  - {}: {error}\n", error.instance_path));
        }
        panic!("{report}");
    }
}

fn fixture_path(relative: &str) -> PathBuf {
    let path = repo_root().join(relative);
    assert!(path.is_dir(), "fixture directory {path:?} exists");
    path
}

#[test]
fn explain_model_matches_contract() {
    for (name, relative) in FIXTURES {
        let explanation = explain("model", &fixture_path(relative));
        assert_matches_contract(name, "ModelExplanation", &explanation);
    }
}

#[test]
fn explain_access_matches_contract() {
    for (name, relative) in FIXTURES {
        let explanation = explain("access", &fixture_path(relative));
        assert_matches_contract(name, "AccessExplanation", &explanation);
    }
}

#[test]
fn explain_access_scenario_matches_contract() {
    let project = fixture_path("products/breg/examples/access-review");
    for (name, relative) in ACCESS_SCENARIOS {
        let scenario = repo_root().join(relative);
        assert!(scenario.is_file(), "scenario file {scenario:?} exists");
        let explanation = explain_with_scenario(&project, &scenario);
        assert_matches_contract(name, "AccessPreview", &explanation);
    }
}

#[test]
fn explain_routes_matches_contract() {
    for (name, relative) in FIXTURES {
        let explanation = explain("routes", &fixture_path(relative));
        assert_matches_contract(name, "RoutesExplanation", &explanation);
    }
}

#[test]
fn explain_queries_matches_contract() {
    for (name, relative) in FIXTURES {
        let explanation = explain("queries", &fixture_path(relative));
        assert_matches_contract(name, "QueriesExplanation", &explanation);
    }
}

#[test]
fn explain_actions_matches_contract() {
    for (name, relative) in FIXTURES {
        let explanation = explain("actions", &fixture_path(relative));
        assert_matches_contract(name, "ActionsExplanation", &explanation);
    }
}

#[test]
fn explain_change_requests_matches_contract() {
    for (name, relative) in FIXTURES {
        let explanation = explain("change-requests", &fixture_path(relative));
        assert_matches_contract(name, "ChangeRequestsExplanation", &explanation);
    }
}

#[test]
fn explain_events_matches_contract() {
    for (name, relative) in FIXTURES {
        let explanation = explain("events", &fixture_path(relative));
        assert_matches_contract(name, "EventsExplanation", &explanation);
    }
}

/// `explain lifecycle` is the one subject that takes no PROJECT, so it needs
/// its own runner rather than the fixture loop above. It returns the whole
/// report, not just `explanation`, because the absent `revision` is part of
/// what this contract states.
fn explain_lifecycle_report() -> Value {
    let output = bregctl(&["--format", "json", "explain", "lifecycle"]);
    assert!(
        output.status.success(),
        "bregctl explain lifecycle failed: {output:?}"
    );
    let report = json_stdout(&output);
    assert_eq!(
        report["ok"],
        Value::Bool(true),
        "bregctl explain lifecycle reported ok=false: {report:#?}"
    );
    report
}

#[test]
fn explain_lifecycle_matches_contract() {
    let report = explain_lifecycle_report();
    assert_matches_contract("lifecycle", "LifecycleExplanation", &report["explanation"]);
}

/// The request machine does not vary by project, so its identifiers are wire
/// contract and the schema pins them. Without that, renaming a state or an
/// event and updating the Rust unit tests in the same change would leave this
/// contract test green, which is exactly the drift "pinned in full" denies.
#[test]
fn renaming_a_lifecycle_state_or_event_fails_the_contract() {
    let report = explain_lifecycle_report();
    let schema = load_schema("LifecycleExplanation");

    let renamed_state: Value = serde_json::from_str(
        &report["explanation"]
            .to_string()
            .replace("\"submitted\"", "\"in_review\""),
    )
    .expect("renamed explanation is JSON");
    assert!(
        schema.validate(&renamed_state).is_err(),
        "renaming the submitted state must fail the schema: {renamed_state:#?}"
    );

    let renamed_event: Value = serde_json::from_str(
        &report["explanation"]
            .to_string()
            .replace("\"event\":\"apply\"", "\"event\":\"commit\""),
    )
    .expect("renamed explanation is JSON");
    assert!(
        schema.validate(&renamed_event).is_err(),
        "renaming the apply event must fail the schema: {renamed_event:#?}"
    );

    let extra_edge = {
        let mut explanation = report["explanation"].clone();
        let transitions = explanation["lifecycles"][0]["transitions"]
            .as_array_mut()
            .expect("transitions array");
        let duplicate = transitions[0].clone();
        transitions.push(duplicate);
        explanation
    };
    assert!(
        schema.validate(&extra_edge).is_err(),
        "an eighth edge must fail the schema: {extra_edge:#?}"
    );
}

/// The lifecycle report names no revision, because no project produced it.
/// Every other subject does, so this also asserts the contrast rather than
/// just the absence.
#[test]
fn explain_lifecycle_reports_no_revision_while_other_subjects_do() {
    let report = explain_lifecycle_report();
    assert_eq!(
        report.get("revision"),
        None,
        "explain lifecycle carries no compiled project, so it names no revision: {report:#?}"
    );

    let project = fixture_path("products/breg/acceptance/business-establishments");
    let output = bregctl(&[
        "--format",
        "json",
        "explain",
        "model",
        project.to_str().expect("fixture path is UTF-8"),
    ]);
    let model_report = json_stdout(&output);
    assert!(
        model_report["revision"].is_string(),
        "explain model names the compiled revision: {model_report:#?}"
    );
}

/// `--production` asks for the production package-closure check. This subject
/// compiles nothing and so runs no such check, and reporting
/// `profile: production` anyway would state that a check had passed when it
/// never ran. Refused for the same reason PROJECT is.
#[test]
fn explain_lifecycle_refuses_the_production_profile() {
    let output = bregctl(&["--format", "json", "explain", "lifecycle", "--production"]);
    assert!(
        !output.status.success(),
        "bregctl explain lifecycle --production is refused: {output:?}"
    );
    let report = json_stdout(&output);
    assert_eq!(report["ok"], Value::Bool(false), "{report:#?}");
    assert_eq!(
        report["diagnostics"][0]["code"],
        Value::String("lifecycle.profile.unused".to_owned()),
        "{report:#?}"
    );
}

/// The human lead every other `explain` subject prints announces a compiled
/// inventory. This subject has none, so it must not borrow that sentence.
#[test]
fn explain_lifecycle_does_not_announce_a_compiled_inventory() {
    let output = bregctl(&["explain", "lifecycle"]);
    assert!(
        output.status.success(),
        "bregctl explain lifecycle failed: {output:?}"
    );
    let stdout = String::from_utf8(output.stdout).expect("bregctl writes UTF-8");
    assert!(
        !stdout.contains("Explained the compiled inventory."),
        "explain lifecycle compiles nothing: {stdout}"
    );
    assert!(
        stdout.contains("No project was compiled."),
        "explain lifecycle says so in its lead: {stdout}"
    );
}

/// A PROJECT is refused rather than ignored, so that nothing teaches a reader
/// the lifecycle might vary by project.
#[test]
fn explain_lifecycle_refuses_a_project() {
    let project = fixture_path("products/breg/acceptance/business-establishments");
    let output = bregctl(&[
        "--format",
        "json",
        "explain",
        "lifecycle",
        project.to_str().expect("fixture path is UTF-8"),
    ]);
    assert!(
        !output.status.success(),
        "bregctl explain lifecycle <project> is refused: {output:?}"
    );
    let report = json_stdout(&output);
    assert_eq!(report["ok"], Value::Bool(false), "{report:#?}");
    assert_eq!(
        report["diagnostics"][0]["code"],
        Value::String("lifecycle.project.unused".to_owned()),
        "{report:#?}"
    );
}

/// PROJECT stayed required for every other subject: making it optional in
/// clap moved the refusal from clap to `explain`, it did not remove it.
#[test]
fn explain_refuses_a_missing_project_for_every_other_subject() {
    for subject in [
        "model",
        "access",
        "routes",
        "queries",
        "actions",
        "change-requests",
        "events",
    ] {
        let output = bregctl(&["--format", "json", "explain", subject]);
        assert!(
            !output.status.success(),
            "bregctl explain {subject} with no project is refused: {output:?}"
        );
        let report = json_stdout(&output);
        assert_eq!(
            report["diagnostics"][0]["code"],
            Value::String("explain.project.missing".to_owned()),
            "explain {subject}: {report:#?}"
        );
    }
}
