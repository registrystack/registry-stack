// SPDX-License-Identifier: Apache-2.0
//! Declarative mappings: references, paths, literals and field-built inputs
//! carry plumbing without a Rhai function.
use registry_coordinator::{authoring, definition::Definition, CoordinatorError};
use registry_platform_yaml::Diagnostic;
use serde_json::{json, Value};
use std::{collections::BTreeMap, fs, path::Path};

const CANARY: &str = "private-canary-value";

fn project() -> Value {
    json!({
        "apiVersion": "id.registrystack.org/formats/coordinator/project/v1alpha1",
        "kind": "CoordinatorProject",
        "project": {
            "id": "declarative",
            "version": "1"
        },
        "operations": {
            "read-record": {
                "uses": "breg.read-record/v1",
                "connection": "applications"
            }
        },
        "workflow": {
            "input": {
                "type": "object",
                "additionalProperties": false,
                "required": [
                    "applicationId",
                    "sendAfter",
                    "route"
                ],
                "properties": {
                    "applicationId": {
                        "type": "string"
                    },
                    "sendAfter": {
                        "type": "string",
                        "format": "date-time"
                    },
                    "route": {
                        "type": "string",
                        "enum": [
                            "send",
                            "skip"
                        ]
                    }
                }
            },
            "deadlineSeconds": 86400,
            "start": "due",
            "steps": {
                "due": {
                    "type": "wait-until",
                    "waitUntil": {
                        "type": "input",
                        "path": "/sendAfter"
                    },
                    "next": "read"
                },
                "read": {
                    "type": "call",
                    "operation": "read-record",
                    "input": {
                        "type": "fields",
                        "fields": {
                            "collection": {
                                "type": "literal",
                                "value": "applications"
                            },
                            "recordId": {
                                "type": "input",
                                "path": "/applicationId"
                            }
                        }
                    },
                    "next": "route"
                },
                "route": {
                    "type": "choose",
                    "choose": {
                        "type": "input",
                        "path": "/route"
                    },
                    "cases": {
                        "send": "done",
                        "skip": "skipped"
                    }
                },
                "done": {
                    "type": "finish",
                    "outcome": "accepted",
                    "output": {
                        "type": "fields",
                        "fields": {
                            "record": {
                                "type": "step",
                                "step": "read",
                                "path": "/data/recordIdentifier"
                            },
                            "note": {
                                "type": "literal",
                                "value": null
                            }
                        }
                    }
                },
                "skipped": {
                    "type": "finish",
                    "outcome": "skipped"
                }
            },
            "outcomes": {
                "accepted": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": [
                        "record",
                        "note"
                    ],
                    "properties": {
                        "record": {
                            "type": "string"
                        },
                        "note": {
                            "type": "null"
                        }
                    }
                },
                "skipped": {
                    "type": "null"
                }
            }
        }
    })
}

fn input() -> Value {
    json!({"applicationId": "application-1", "sendAfter": "2026-10-10T09:00:00Z", "route": "send"})
}

fn record() -> Value {
    json!({
        "data": {"recordIdentifier": "record-1", "revisionIdentifier": "1", "domainData": {}},
        "meta": {"registryIdentifier": "r", "datasetIdentifier": "d", "entityTypeIdentifier": "e"}
    })
}

fn load(project: &Value, source: &str) -> registry_coordinator::Result<Definition> {
    let project = declare_test_functions(project);
    let root = tempfile::tempdir().unwrap();
    fs::write(
        root.path().join("workflow.yaml"),
        serde_json::to_string(&project).unwrap(),
    )
    .unwrap();
    fs::write(root.path().join("functions.rhai"), source).unwrap();
    Definition::load(root.path())
}

fn refused(result: registry_coordinator::Result<Definition>) -> CoordinatorError {
    match result {
        Ok(_) => panic!("the project must be refused"),
        Err(error) => error,
    }
}

fn finding_at<'a>(error: &'a CoordinatorError, path: &str) -> &'a Diagnostic {
    error
        .diagnostics
        .iter()
        .find(|finding| finding.path == path)
        .unwrap_or_else(|| panic!("no finding at {path}: {:#?}", error.diagnostics))
}

fn parse_refused(project: &Value) -> CoordinatorError {
    match authoring::parse_project(Path::new("workflow.yaml"), project.to_string()) {
        Ok(_) => panic!("the project must be refused"),
        Err(error) => error,
    }
}

#[test]
fn references_and_fields_carry_plumbing_without_a_function() {
    let definition = load(&project(), "").unwrap();
    let input = input();
    let none = BTreeMap::new();
    assert_eq!(
        definition.evaluate("due", &input, &none).unwrap(),
        json!("2026-10-10T09:00:00Z")
    );
    assert_eq!(
        definition
            .initial_due(&input, "2026-10-09T09:00:00Z".parse().unwrap())
            .unwrap(),
        Some("2026-10-10T09:00:00Z".parse().unwrap())
    );
    assert_eq!(
        definition.evaluate("read", &input, &none).unwrap(),
        json!({"collection": "applications", "recordId": "application-1"})
    );
    assert_eq!(
        definition.evaluate("route", &input, &none).unwrap(),
        json!("send")
    );
    let outputs = BTreeMap::from([("read".to_owned(), record())]);
    assert_eq!(
        definition.evaluate("done", &input, &outputs).unwrap(),
        json!({"record": "record-1", "note": null})
    );
}

#[test]
fn function_arguments_accept_paths_and_literals() {
    let mut project = project();
    project["workflow"]["steps"]["done"]["output"] = json!({"type": "function", "function": "combine", "inputs": {"arg0": {"type": "input", "path": "/applicationId"}, "arg1": {"type": "literal", "value": {"nested": [1, true, null]}}, "arg2": {"type": "step", "step": "read", "path": "/data"}, "arg3": {"type": "step", "step": "read"}}});
    let definition = load(
        &project,
        "fn combine(__named) { let id = __named.arg0; let literal = __named.arg1; let data = __named.arg2; let whole = __named.arg3;  let count = if literal.nested.len() == 3 && literal.nested[1] { \"3\" } else { \"?\" }; #{ record: data.recordIdentifier + \":\" + id + \":\" + count + \":\" + whole.meta.datasetIdentifier, note: () } }",
    )
    .unwrap();
    let outputs = BTreeMap::from([("read".to_owned(), record())]);
    assert_eq!(
        definition.evaluate("done", &input(), &outputs).unwrap(),
        json!({"record": "record-1:application-1:3:d", "note": null})
    );
}

#[test]
fn a_path_selects_through_escaped_members_and_indexes() {
    let mut project = project();
    project["workflow"]["input"]["properties"]["tags"] = json!({"type": "object"});
    project["workflow"]["steps"]["route"]["choose"] =
        json!({"type": "input", "path": "/tags/a~1b~0c/1"});
    let definition = load(&project, "").unwrap();
    let mut input = input();
    input["tags"] = json!({"a/b~c": ["skip", "send"]});
    assert_eq!(
        definition
            .evaluate("route", &input, &BTreeMap::new())
            .unwrap(),
        json!("send")
    );
}

#[test]
fn declarative_mappings_survive_the_snapshot_and_explain() {
    let definition = load(&project(), "").unwrap();
    let snapshot: Value = serde_json::from_str(&definition.snapshot().unwrap()).unwrap();
    assert_eq!(
        snapshot["workflow"]["steps"]["read"]["input"],
        json!({"fields": {
            "collection": {"type": "literal", "value": "applications"},
            "recordId": {"type": "input", "path": "/applicationId"}
        }})
    );
    assert_eq!(
        snapshot["workflow"]["steps"]["done"]["output"]["fields"]["note"],
        json!({"type": "literal", "value": null})
    );
    assert_eq!(
        snapshot["workflow"]["steps"]["due"]["waitUntil"],
        json!({"type": "input", "path": "/sendAfter"})
    );
    let restored = Definition::from_snapshot(&definition.snapshot().unwrap()).unwrap();
    assert_eq!(restored.digest, definition.digest);
    assert_eq!(
        restored
            .evaluate("read", &input(), &BTreeMap::new())
            .unwrap(),
        json!({"collection": "applications", "recordId": "application-1"})
    );
    let explained = definition.explain().unwrap();
    let steps = explained["steps"].as_array().unwrap();
    let step = |id: &str| steps.iter().find(|step| step["id"] == id).unwrap().clone();
    assert_eq!(
        step("route")["mapping"],
        json!({"type": "input", "path": "/route"})
    );
    assert_eq!(
        step("read")["mapping"]["fields"]["recordId"],
        json!({"type": "input", "path": "/applicationId"})
    );
}

#[test]
fn a_malformed_pointer_is_refused_at_its_member() {
    for pointer in [
        "applicationId".to_owned(),
        String::new(),
        "/a~2".to_owned(),
        "/a~".to_owned(),
        format!("/{}", "a".repeat(256)),
    ] {
        let mut project = project();
        project["workflow"]["steps"]["read"]["input"]["fields"]["recordId"]["path"] =
            json!(pointer);
        let error = parse_refused(&project);
        let finding = &error.diagnostics[0];
        assert_eq!(finding.code, "config.invalid-value", "{pointer}");
        assert_eq!(
            finding.path,
            "/workflow/steps/read/input/fields/recordId/path"
        );
        assert_eq!(
            finding.message,
            "expected a JSON Pointer of at most 256 characters, such as /member/0"
        );
        assert_eq!(
            finding.suggested_action,
            "Start the path with /, write ~0 for ~ and ~1 for / inside a member name, or omit path to use the whole value."
        );
        assert!(finding.source.as_ref().unwrap().line.is_some());
    }
}

#[test]
fn an_input_names_its_form_function_or_fields() {
    for (value, path, code, message, action) in [
        (
            json!({"function": "f", "inputs": {}}),
            "/workflow/steps/read/input",
            "config.missing-key",
            "the member `type` is missing; it names which form this mapping takes",
            "Add `type` with one of `function`, `fields`, `compare`, `input`, `step`, `literal`.",
        ),
        (
            json!({"type": "unknown"}),
            "/workflow/steps/read/input/type",
            "config.unknown-variant",
            "expected one of `function`, `fields`, `compare`, `input`, `step`, `literal`",
            "Use one of `function`, `fields`, `compare`, `input`, `step`, `literal`.",
        ),
        (
            json!({"type": "function", "function": "f"}),
            "/workflow/steps/read/input",
            "config.missing-key",
            "the required member `inputs` is missing",
            "Add `inputs`.",
        ),
        (
            json!({"type": "fields"}),
            "/workflow/steps/read/input",
            "config.missing-key",
            "the required member `fields` is missing",
            "Add `fields`.",
        ),
        (
            json!({"type": "function", "function": "f", "inputs": {}, "fields": {}}),
            "/workflow/steps/read/input/fields",
            "config.unknown-key",
            "`fields` is not a member of this mapping",
            "Remove `fields`; the accepted keys are `type`, `function`, `inputs`.",
        ),
    ] {
        let mut project = project();
        project["workflow"]["steps"]["read"]["input"] = value.clone();
        let error = parse_refused(&project);
        let finding = finding_at(&error, path);
        assert_eq!(finding.code, code, "{value}");
        assert_eq!(finding.message, message, "{value}");
        assert_eq!(finding.suggested_action, action, "{value}");
    }
}

#[test]
fn a_selector_names_its_form_function_or_one_reference() {
    for (value, path, code, message, action) in [
        (
            json!({"function": "f", "inputs": {}}),
            "/workflow/steps/route/choose",
            "config.missing-key",
            "the member `type` is missing; it names which form this mapping takes",
            "Add `type` with one of `function`, `fields`, `compare`, `input`, `step`, `literal`.",
        ),
        (
            json!({"type": "unknown"}),
            "/workflow/steps/route/choose/type",
            "config.unknown-variant",
            "expected one of `function`, `fields`, `compare`, `input`, `step`, `literal`",
            "Use one of `function`, `fields`, `compare`, `input`, `step`, `literal`.",
        ),
        (
            json!({"type": "step"}),
            "/workflow/steps/route/choose",
            "config.missing-key",
            "the required member `step` is missing",
            "Add `step`.",
        ),
        (
            json!({"type": "literal"}),
            "/workflow/steps/route/choose",
            "config.missing-key",
            "the required member `value` is missing",
            "Add `value`.",
        ),
        (
            json!({"type": "input", "step": "read"}),
            "/workflow/steps/route/choose/step",
            "config.unknown-key",
            "`step` is not a member of this mapping",
            "Remove `step`; the accepted keys are `type`, `path`.",
        ),
        (
            json!({"type": "literal", "value": "send", "path": "/x"}),
            "/workflow/steps/route/choose/path",
            "config.unknown-key",
            "`path` is not a member of this mapping",
            "Remove `path`; the accepted keys are `type`, `value`.",
        ),
        (
            json!({"type": "function", "function": "f", "inputs": {}, "path": "/x"}),
            "/workflow/steps/route/choose/path",
            "config.unknown-key",
            "`path` is not a member of this mapping",
            "Remove `path`; the accepted keys are `type`, `function`, `inputs`.",
        ),
    ] {
        let mut project = project();
        project["workflow"]["steps"]["route"]["choose"] = value.clone();
        let error = parse_refused(&project);
        let finding = finding_at(&error, path);
        assert_eq!(finding.code, code, "{value}");
        assert_eq!(finding.message, message, "{value}");
        assert_eq!(finding.suggested_action, action, "{value}");
    }
}

#[test]
fn field_names_and_counts_are_bounded() {
    let mut project = project();
    project["workflow"]["steps"]["read"]["input"]["fields"]["bad.name"] = json!({"type": "input"});
    let error = parse_refused(&project);
    let finding = &error.diagnostics[0];
    assert_eq!(finding.code, "config.invalid-value");
    assert_eq!(finding.path, "/workflow/steps/read/input/fields/bad.name");
    assert_eq!(
        finding.message,
        "expected a field name of 1 to 64 ASCII letters, digits, hyphens or underscores, starting with a letter"
    );

    let mut project = self::project();
    let fields = (0..65)
        .map(|index| (format!("f{index}"), json!({"type": "input"})))
        .collect::<serde_json::Map<_, _>>();
    project["workflow"]["steps"]["read"]["input"]["fields"] = Value::Object(fields);
    let error = refused(load(&project, ""));
    let finding = &error.diagnostics[0];
    assert_eq!(finding.code, "coordinator.mapping.fields-count");
    // The 65th member in name order.
    assert_eq!(finding.path, "/workflow/steps/read/input/fields/f9");
    assert_eq!(
        finding.message,
        "This fields mapping builds more than 64 members across its levels."
    );
    assert_eq!(
        finding.suggested_action,
        "Remove members, or build part of the value in an earlier step."
    );
}

#[test]
fn a_literal_must_fit_the_structured_value_bounds() {
    let mut project = project();
    project["workflow"]["steps"]["read"]["input"]["fields"]["collection"]["value"] =
        json!("x".repeat(16_385));
    let error = refused(load(&project, ""));
    let finding = &error.diagnostics[0];
    assert_eq!(finding.code, "coordinator.mapping.literal");
    assert_eq!(
        finding.path,
        "/workflow/steps/read/input/fields/collection/value"
    );
    assert_eq!(
        finding.message,
        "the literal exceeds the structured value bounds"
    );
}

#[test]
fn a_step_reference_must_precede_on_every_path() {
    let mut project = project();
    // route is a choose, not a call, so its output is never available.
    project["workflow"]["steps"]["done"]["output"]["fields"]["record"] =
        json!({"type": "step", "step": "route"});
    let error = refused(load(&project, ""));
    let finding = &error.diagnostics[0];
    assert_eq!(finding.code, "coordinator.mapping.dominance");
    assert_eq!(finding.path, "/workflow/steps/done/output/fields/record");

    let mut project = self::project();
    project["workflow"]["steps"]["route"]["choose"] = json!({"type": "step", "step": "done"});
    let error = refused(load(&project, ""));
    let finding = &error.diagnostics[0];
    assert_eq!(finding.code, "coordinator.mapping.dominance");
    assert_eq!(finding.path, "/workflow/steps/route/choose");
}

#[test]
fn an_absent_path_fails_at_run_time_without_values() {
    let definition = load(&project(), "").unwrap();
    let mut output = record();
    output["data"]
        .as_object_mut()
        .unwrap()
        .remove("recordIdentifier");
    output["data"]["domainData"] = json!({"secret": CANARY});
    let outputs = BTreeMap::from([("read".to_owned(), output)]);
    let error = definition.evaluate("done", &input(), &outputs).unwrap_err();
    assert_eq!(error.code, "mapping.path");
    assert_eq!(
        error.field.as_deref(),
        Some("steps.done.output.fields.record")
    );
    assert!(!error.to_string().contains(CANARY));
    assert!(!format!("{error:?}").contains(CANARY));

    let error = definition
        .evaluate("done", &input(), &BTreeMap::new())
        .unwrap_err();
    assert_eq!(error.code, "mapping.missing_output");
    assert_eq!(
        error.field.as_deref(),
        Some("steps.done.output.fields.record")
    );
}

#[test]
fn reference_selectors_keep_their_result_contracts() {
    let mut input = input();
    input["route"] = json!("elsewhere");
    let mut project = project();
    project["workflow"]["input"]["properties"]["route"] = json!({"type": "string"});
    let definition = load(&project, "").unwrap();
    assert_eq!(
        definition
            .evaluate("route", &input, &BTreeMap::new())
            .unwrap_err()
            .code,
        "mapping.branch"
    );
    // A string without a format may hold any text, so the run decides.
    let mut project = self::project();
    project["workflow"]["steps"]["due"]["waitUntil"] =
        json!({"type": "input", "path": "/applicationId"});
    let definition = load(&project, "").unwrap();
    assert_eq!(
        definition
            .evaluate("due", &self::input(), &BTreeMap::new())
            .unwrap_err()
            .code,
        "mapping.timestamp"
    );
}

fn declare_test_functions(project: &Value) -> Value {
    fn mapping(value: &Value, functions: &mut serde_json::Map<String, Value>) {
        if let Some(object) = value.as_object() {
            if object.get("type") == Some(&json!("function")) {
                if let (Some(name), Some(inputs)) = (
                    object.get("function").and_then(Value::as_str),
                    object.get("inputs").and_then(Value::as_object),
                ) {
                    let signature = inputs
                        .keys()
                        .map(|name| (name.clone(), json!({})))
                        .collect::<serde_json::Map<_, _>>();
                    functions.insert(name.into(),json!({"runtime":"rhai","source":"functions.rhai","entrypoint":name,"inputs":signature,"output":{}}));
                }
            }
            for value in object.values() {
                mapping(value, functions);
            }
        } else if let Some(items) = value.as_array() {
            for value in items {
                mapping(value, functions);
            }
        }
    }
    let mut project = project.clone();
    let mut functions = serde_json::Map::new();
    mapping(&project["workflow"]["steps"], &mut functions);
    project["functions"] = Value::Object(functions);
    project
}
