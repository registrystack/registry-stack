// SPDX-License-Identifier: Apache-2.0
//! A choose step may name the case an author expects readers to notice. The
//! hint is checked presentation metadata: it survives a snapshot and explain,
//! but does not change the graph, evaluation, scenarios or semantic revision.

use registry_coordinator::{authoring, definition::Definition, CoordinatorError};
use serde_json::{json, Value};
use std::{collections::BTreeMap, fs, path::Path, process::Command};

fn enum_project(expected: Option<Value>) -> Value {
    let mut project = json!({
        "apiVersion": "id.registrystack.org/formats/coordinator/project/v1alpha1",
        "kind": "CoordinatorProject",
        "project": {"id": "expected-enum", "version": "1"},
        "workflow": {
            "input": {
                "type": "object",
                "additionalProperties": false,
                "required": ["decision"],
                "properties": {"decision": {"type": "string", "enum": ["approved", "rejected"]}}
            },
            "deadlineSeconds": 60,
            "start": "route",
            "steps": {
                "route": {
                    "type": "choose",
                    "choose": {"type": "input", "path": "/decision"},
                    "cases": {"approved": "approved", "rejected": "rejected"}
                },
                "approved": {"type": "finish", "outcome": "approved"},
                "rejected": {"type": "finish", "outcome": "rejected"}
            },
            "outcomes": {"approved": {"type": "null"}, "rejected": {"type": "null"}}
        }
    });
    if let Some(expected) = expected {
        project["workflow"]["steps"]["route"]["expected"] = expected;
    }
    project
}

fn compare_project(expected: Option<Value>) -> Value {
    let mut project = json!({
        "apiVersion": "id.registrystack.org/formats/coordinator/project/v1alpha1",
        "kind": "CoordinatorProject",
        "project": {"id": "expected-compare", "version": "1"},
        "workflow": {
            "input": {
                "type": "object",
                "additionalProperties": false,
                "required": ["score"],
                "properties": {"score": {"type": "number"}}
            },
            "deadlineSeconds": 60,
            "start": "route",
            "steps": {
                "route": {
                    "type": "choose",
                    "choose": {
                        "type": "compare",
                        "all": [{"value": {"type": "input", "path": "/score"}, "greater": 5}]
                    },
                    "cases": {"matched": "high", "unmatched": "low"}
                },
                "high": {"type": "finish", "outcome": "high"},
                "low": {"type": "finish", "outcome": "low"}
            },
            "outcomes": {"high": {"type": "null"}, "low": {"type": "null"}}
        }
    });
    if let Some(expected) = expected {
        project["workflow"]["steps"]["route"]["expected"] = expected;
    }
    project
}

fn write_project(root: &Path, project: &Value) {
    fs::write(
        root.join("workflow.yaml"),
        serde_norway::to_string(project).unwrap(),
    )
    .unwrap();
}

fn load(project: &Value) -> registry_coordinator::Result<Definition> {
    let root = tempfile::tempdir().unwrap();
    write_project(root.path(), project);
    Definition::load(root.path())
}

fn refused(project: &Value) -> CoordinatorError {
    match load(project) {
        Ok(_) => panic!("the project must be refused"),
        Err(error) => error,
    }
}

fn parse_refused(project: &Value) -> CoordinatorError {
    let source = serde_norway::to_string(project).unwrap();
    match authoring::parse_project(Path::new("workflow.yaml"), source) {
        Ok(_) => panic!("the project must be refused"),
        Err(error) => error,
    }
}

fn explained_step<'a>(explain: &'a Value, id: &str) -> &'a Value {
    explain["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|step| step["id"] == id)
        .unwrap_or_else(|| panic!("no explained step {id}: {explain}"))
}

#[test]
fn expected_is_snapshot_presentation_without_execution_or_revision_meaning() {
    let legacy = load(&compare_project(None)).unwrap();
    let mut annotated = compare_project(Some(json!("unmatched")));
    annotated["workflow"]["steps"]["route"]["title"] = json!("Classify score");
    annotated["workflow"]["steps"]["route"]["description"] =
        json!("Routes scores above five to high.");
    let expected = load(&annotated).unwrap();
    let mut changed = annotated.clone();
    changed["workflow"]["steps"]["route"]["expected"] = json!("matched");
    let changed = load(&changed).unwrap();
    let mut removed = annotated.clone();
    removed["workflow"]["steps"]["route"]
        .as_object_mut()
        .unwrap()
        .remove("expected");
    let removed = load(&removed).unwrap();

    assert_eq!(expected.digest, legacy.digest);
    assert_eq!(changed.digest, legacy.digest);
    assert_eq!(removed.digest, legacy.digest);
    for definition in [&expected, &changed, &removed] {
        let metadata = &definition.workflow.presentation.steps["route"];
        assert_eq!(metadata["title"], "Classify score");
        assert_eq!(metadata["description"], "Routes scores above five to high.");
    }
    assert_eq!(
        changed.workflow.presentation.steps["route"]["expected"],
        "matched"
    );
    assert!(removed.workflow.presentation.steps["route"]
        .get("expected")
        .is_none());
    for (input, choice) in [
        (json!({"score": 8}), "matched"),
        (json!({"score": 2}), "unmatched"),
    ] {
        assert_eq!(
            expected
                .evaluate("route", &input, &BTreeMap::new())
                .unwrap(),
            json!(choice)
        );
        assert_eq!(
            expected
                .evaluate("route", &input, &BTreeMap::new())
                .unwrap(),
            legacy.evaluate("route", &input, &BTreeMap::new()).unwrap()
        );
    }

    let legacy_explain = legacy.explain().unwrap();
    let expected_explain = expected.explain().unwrap();
    assert_eq!(
        legacy_explain["steps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|step| &step["id"])
            .collect::<Vec<_>>(),
        expected_explain["steps"]
            .as_array()
            .unwrap()
            .iter()
            .map(|step| &step["id"])
            .collect::<Vec<_>>()
    );
    let legacy_route = explained_step(&legacy_explain, "route");
    let expected_route = explained_step(&expected_explain, "route");
    assert_eq!(expected_route["next"], legacy_route["next"]);
    assert_eq!(expected_route["cases"], legacy_route["cases"]);
    assert!(legacy_route.get("expected").is_none());
    assert_eq!(expected_route["expected"], "unmatched");
    assert_eq!(
        expected_explain["references"]["/workflow/steps/route/expected"]["target"],
        "/workflow/steps/route/cases/unmatched"
    );

    let snapshot = expected.snapshot().unwrap();
    let frozen: Value = serde_json::from_str(&snapshot).unwrap();
    assert_eq!(
        frozen["workflow"]["presentation"]["steps"]["route"]["expected"],
        "unmatched"
    );
    let restored = Definition::from_snapshot(&snapshot).unwrap();
    assert_eq!(restored.digest, legacy.digest);
    assert_eq!(
        explained_step(&restored.explain().unwrap(), "route")["expected"],
        "unmatched"
    );
}

#[cfg(feature = "schema")]
#[test]
fn only_the_choose_schema_has_an_optional_expected_local_id() {
    let schema: Value = serde_json::from_str(&authoring::project_schema().unwrap()).unwrap();
    let variants = schema["$defs"]["AuthoredStep"]["oneOf"].as_array().unwrap();
    let choose = variants
        .iter()
        .find(|variant| variant["properties"]["type"]["const"] == "choose")
        .expect("the choose step schema");
    assert_eq!(choose["properties"]["expected"]["$ref"], "#/$defs/LocalId");
    assert!(!choose["required"]
        .as_array()
        .unwrap()
        .contains(&json!("expected")));
    assert!(variants.iter().all(|variant| {
        variant["properties"]["type"]["const"] == "choose"
            || variant["properties"].get("expected").is_none()
    }));
}

#[test]
fn any_declared_string_case_can_be_the_expected_case() {
    let definition = load(&enum_project(Some(json!("approved")))).unwrap();
    assert_eq!(
        definition
            .evaluate("route", &json!({"decision": "approved"}), &BTreeMap::new(),)
            .unwrap(),
        "approved"
    );
    assert_eq!(
        definition
            .evaluate("route", &json!({"decision": "rejected"}), &BTreeMap::new(),)
            .unwrap(),
        "rejected"
    );
    assert_eq!(
        explained_step(&definition.explain().unwrap(), "route")["expected"],
        "approved"
    );
}

#[test]
fn expected_must_name_a_declared_case_with_a_located_repair() {
    let error = refused(&enum_project(Some(json!("missing"))));
    let finding = error
        .diagnostics
        .iter()
        .find(|finding| finding.path == "/workflow/steps/route/expected")
        .unwrap_or_else(|| panic!("no expected-case finding: {:#?}", error.diagnostics));
    assert!(
        finding.message.contains("case") || finding.suggested_action.contains("case"),
        "{finding:#?}"
    );
    assert!(!finding.suggested_action.is_empty(), "{finding:#?}");
    let source = finding.source.as_ref().expect("a source location");
    assert!(source.file.ends_with("workflow.yaml"), "{finding:#?}");
    assert!(source.line.is_some(), "{finding:#?}");
}

#[test]
fn expected_is_forbidden_on_non_choose_steps() {
    let mut project = compare_project(None);
    project["workflow"]["steps"]["high"]["expected"] = json!("high");
    let error = parse_refused(&project);
    let finding = &error.diagnostics[0];
    assert_eq!(finding.code, "config.unknown-key");
    assert_eq!(finding.path, "/workflow/steps/high/expected");
    assert!(!finding.suggested_action.is_empty());
    assert!(finding.source.as_ref().unwrap().line.is_some());
}

#[test]
fn expected_uses_shared_yaml_string_and_local_id_rules() {
    for (value, code) in [
        (json!(7), "config.expected-string"),
        (Value::Null, "config.null-value"),
        (json!(""), "config.invalid-value"),
    ] {
        let error = parse_refused(&compare_project(Some(value)));
        let finding = error
            .diagnostics
            .iter()
            .find(|finding| finding.path == "/workflow/steps/route/expected")
            .unwrap_or_else(|| panic!("no expected finding: {:#?}", error.diagnostics));
        assert_eq!(finding.code, code, "{finding:#?}");
        assert!(!finding.suggested_action.is_empty(), "{finding:#?}");
        assert!(
            finding.source.as_ref().unwrap().line.is_some(),
            "{finding:#?}"
        );
    }
}

#[test]
fn json_check_explain_and_offline_scenarios_preserve_both_branches() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().canonicalize().unwrap();
    write_project(&root, &compare_project(Some(json!("unmatched"))));

    let checked = Command::new(env!("CARGO_BIN_EXE_coordinatorctl"))
        .args([
            "--format",
            "json",
            "check",
            "--project",
            root.to_str().unwrap(),
            "--explain",
        ])
        .output()
        .unwrap();
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stdout)
    );
    let explain: Value = serde_json::from_slice(&checked.stdout).unwrap();
    assert_eq!(explained_step(&explain, "route")["expected"], "unmatched");

    let scenarios = json!({
        "apiVersion": "id.registrystack.org/formats/coordinator/scenarios/v1alpha1",
        "kind": "CoordinatorScenarios",
        "cases": [
            {
                "id": "matched-branch",
                "admittedAt": "2026-10-10T09:00:00Z",
                "input": {"score": 8},
                "replies": {},
                "expect": {
                    "path": ["route", "high"],
                    "state": "completed",
                    "outcome": {"type": "named", "value": "high"}
                }
            },
            {
                "id": "unmatched-branch",
                "admittedAt": "2026-10-10T09:00:00Z",
                "input": {"score": 2},
                "replies": {},
                "expect": {
                    "path": ["route", "low"],
                    "state": "completed",
                    "outcome": {"type": "named", "value": "low"}
                }
            }
        ]
    });
    fs::write(
        root.join("scenarios.yaml"),
        serde_norway::to_string(&scenarios).unwrap(),
    )
    .unwrap();
    let tested = Command::new(env!("CARGO_BIN_EXE_coordinatorctl"))
        .args([
            "--format",
            "json",
            "test",
            "--project",
            root.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert!(
        tested.status.success(),
        "{}",
        String::from_utf8_lossy(&tested.stdout)
    );
    let report: Value = serde_json::from_slice(&tested.stdout).unwrap();
    assert_eq!(report["status"], "passed");
    assert_eq!(report["passed"], 2);
    assert_eq!(report["failed"], 0);
    assert_eq!(report["scenarios"][0]["path"], json!(["route", "high"]));
    assert_eq!(report["scenarios"][1]["path"], json!(["route", "low"]));
}
