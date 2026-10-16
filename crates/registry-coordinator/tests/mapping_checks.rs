// SPDX-License-Identifier: Apache-2.0
//! Static mapping checks: before any run, a reference path must resolve in
//! the schema of the value it reads, and a mapping must fit what it feeds.
//! Only mismatches the schemas decide are refused.
use registry_coordinator::{definition::Definition, CoordinatorError};
use registry_platform_yaml::Diagnostic;
use serde_json::{json, Value};
use std::{collections::BTreeMap, fs};

fn project() -> Value {
    json!({
        "apiVersion": "id.registrystack.org/formats/coordinator/project/v1alpha1",
        "kind": "CoordinatorProject",
        "project": {
            "id": "checked",
            "version": "1"
        },
        "operations": {
            "read-record": {
                "uses": "breg.read-record/v1",
                "connection": "applications"
            },
            "read-scheduling": {
                "uses": "scheduling.read-service/v1",
                "connection": "catalogue"
            },
            "external-get": {
                "uses": "external.get/v1",
                "connection": "directory"
            }
        },
        "workflow": {
            "input": {
                "type": "object",
                "additionalProperties": false,
                "required": [
                    "applicationId",
                    "sendAfter",
                    "route",
                    "count"
                ],
                "$defs": {
                    "Route": {
                        "type": "string",
                        "enum": [
                            "send",
                            "skip"
                        ]
                    },
                    "Node": {
                        "type": "object",
                        "properties": {
                            "name": {
                                "type": "string"
                            },
                            "child": {
                                "$ref": "#/$defs/Node"
                            }
                        }
                    }
                },
                "properties": {
                    "applicationId": {
                        "type": "string",
                        "format": "uuid"
                    },
                    "sendAfter": {
                        "type": "string",
                        "format": "date-time"
                    },
                    "route": {
                        "anyOf": [
                            {
                                "$ref": "#/$defs/Route"
                            },
                            {
                                "type": "null"
                            }
                        ]
                    },
                    "count": {
                        "type": "integer"
                    },
                    "note": {
                        "type": "string"
                    },
                    "labels": {
                        "type": "object",
                        "patternProperties": {
                            "^l": {
                                "type": "string"
                            }
                        }
                    },
                    "tree": {
                        "$ref": "#/$defs/Node"
                    },
                    "slots": {
                        "type": "array",
                        "items": {
                            "type": "string",
                            "format": "date-time"
                        }
                    },
                    "extra": {
                        "type": "object"
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
                    "next": "metadata"
                },
                "metadata": {
                    "type": "call",
                    "operation": "read-scheduling",
                    "input": {
                        "type": "fields",
                        "fields": {}
                    },
                    "next": "lookup"
                },
                "lookup": {
                    "type": "call",
                    "operation": "external-get",
                    "input": {
                        "type": "fields",
                        "fields": {
                            "path": {
                                "type": "literal",
                                "value": "/people"
                            },
                            "query": {
                                "type": "literal",
                                "value": {
                                    "page": "1"
                                }
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
                            "revision": {
                                "type": "step",
                                "step": "metadata",
                                "path": "/policyRevision"
                            },
                            "region": {
                                "type": "step",
                                "step": "read",
                                "path": "/data/domainData/address/region"
                            },
                            "directory": {
                                "type": "step",
                                "step": "lookup",
                                "path": "/body/entries/0/name"
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
                        "revision",
                        "note"
                    ],
                    "properties": {
                        "record": {
                            "type": "string"
                        },
                        "revision": {
                            "type": "integer"
                        },
                        "region": {},
                        "directory": {},
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

fn refused(project: &Value) -> CoordinatorError {
    match load(
        project,
        "fn combine(__named) { let a = __named.arg0; let b = __named.arg1;  #{} }",
    ) {
        Ok(_) => panic!("the project must be refused"),
        Err(error) => error,
    }
}

/// The one finding a static check reports, with its exact wording.
fn assert_finding(error: &CoordinatorError, code: &str, path: &str, message: &str, action: &str) {
    assert_eq!(error.diagnostics.len(), 1, "{:#?}", error.diagnostics);
    let finding: &Diagnostic = &error.diagnostics[0];
    assert_eq!(finding.code, code, "{finding:#?}");
    assert_eq!(finding.path, path, "{finding:#?}");
    assert_eq!(finding.message, message);
    assert_eq!(finding.suggested_action, action);
    assert!(finding.source.as_ref().unwrap().line.is_some());
}

const INPUT_PATH_ACTION: &str =
    "Correct the path to a member the workflow input schema declares, or omit path to use the whole value.";

#[test]
fn a_mapping_that_fits_every_schema_loads() {
    load(&project(), "").unwrap();
}

#[test]
fn open_members_accept_any_path_beneath_them() {
    let mut project = project();
    project["workflow"]["steps"]["done"]["output"] = json!({"type": "function", "function": "combine", "inputs": {"arg0": {"type": "input", "path": "/labels/lname"}, "arg1": {"type": "input", "path": "/labels/other"}, "arg2": {"type": "input", "path": "/tree/child/child/child/name"}, "arg3": {"type": "input", "path": "/slots/3"}, "arg4": {"type": "input", "path": "/extra/any/depth"}, "arg5": {"type": "step", "step": "read", "path": "/data/domainData/any/0/depth"}, "arg6": {"type": "step", "step": "read", "path": "/data/extension"}, "arg7": {"type": "step", "step": "read", "path": "/links/self"}, "arg8": {"type": "step", "step": "lookup", "path": "/body/0/a~1b"}}});
    load(&project, "fn combine(__named) { let a = __named.arg0; let b = __named.arg1; let c = __named.arg2; let d = __named.arg3; let e = __named.arg4; let f = __named.arg5; let g = __named.arg6; let h = __named.arg7; let i = __named.arg8;  () }").unwrap();
}

#[test]
fn a_path_the_input_schema_does_not_declare_is_refused() {
    let mut project = project();
    project["workflow"]["steps"]["read"]["input"]["fields"]["recordId"]["path"] =
        json!("/applicationID");
    assert_finding(
        &refused(&project),
        "coordinator.mapping.path",
        "/workflow/steps/read/input/fields/recordId/path",
        "expected a path that the workflow input schema declares; it declares nothing at /applicationID",
        INPUT_PATH_ACTION,
    );
}

#[test]
fn a_path_the_operation_output_does_not_declare_is_refused() {
    let mut project = project();
    project["workflow"]["steps"]["done"]["output"]["fields"]["revision"]["path"] =
        json!("/policyRevison");
    assert_finding(
        &refused(&project),
        "coordinator.mapping.path",
        "/workflow/steps/done/output/fields/revision/path",
        "expected a path that the scheduling.read-service/v1 output of step metadata declares; it declares nothing at /policyRevison",
        "Correct the path to a member the scheduling.read-service/v1 output of step metadata declares, or omit path to use the whole value.",
    );

    let mut project = self::project();
    project["workflow"]["steps"]["done"]["output"]["fields"]["record"]["path"] =
        json!("/data/recordIdentifier/0");
    assert_finding(
        &refused(&project),
        "coordinator.mapping.path",
        "/workflow/steps/done/output/fields/record/path",
        "expected a path that the breg.read-record/v1 output of step read declares; it declares nothing at /data/recordIdentifier/0",
        "Correct the path to a member the breg.read-record/v1 output of step read declares, or omit path to use the whole value.",
    );
}

#[test]
fn function_arguments_have_their_paths_checked_and_nothing_else() {
    let mut project = project();
    project["workflow"]["steps"]["done"]["output"] = json!({"type": "function", "function": "combine", "inputs": {"arg0": {"type": "input", "path": "/count"}, "arg1": {"type": "input", "path": "/tree/child/nmae"}}});
    assert_finding(
        &refused(&project),
        "coordinator.mapping.path",
        "/workflow/steps/done/output/inputs/arg1/path",
        "expected a path that the workflow input schema declares; it declares nothing at /tree/child/nmae",
        INPUT_PATH_ACTION,
    );

    project["workflow"]["steps"]["done"]["output"]["inputs"]["arg1"]["path"] =
        json!("/tree/child/name");
    load(
        &project,
        "fn combine(__named) { let a = __named.arg0; let b = __named.arg1;  () }",
    )
    .unwrap();
}

#[test]
fn a_field_the_target_does_not_declare_is_refused() {
    let mut project = project();
    project["workflow"]["steps"]["read"]["input"]["fields"]["colection"] =
        json!({"type": "literal", "value": "applications"});
    assert_finding(
        &refused(&project),
        "coordinator.mapping.field",
        "/workflow/steps/read/input/fields/colection",
        "expected a member the breg.read-record/v1 input declares; it declares no colection",
        "Remove colection, or rename it to a member the breg.read-record/v1 input declares.",
    );

    let mut project = self::project();
    project["workflow"]["steps"]["done"]["output"]["fields"]["extra"] =
        json!({"type": "literal", "value": 1});
    assert_finding(
        &refused(&project),
        "coordinator.mapping.field",
        "/workflow/steps/done/output/fields/extra",
        "expected a member the accepted outcome declares; it declares no extra",
        "Remove extra, or rename it to a member the accepted outcome declares.",
    );
}

#[test]
fn a_required_field_left_unset_is_refused() {
    let mut project = project();
    project["workflow"]["steps"]["read"]["input"]["fields"]
        .as_object_mut()
        .unwrap()
        .remove("collection");
    assert_finding(
        &refused(&project),
        "coordinator.mapping.field",
        "/workflow/steps/read/input/fields",
        "expected every member the breg.read-record/v1 input requires; fields does not set collection",
        "Add a collection field with a reference or a literal.",
    );

    let mut project = self::project();
    project["workflow"]["steps"]["done"]["output"]["fields"]
        .as_object_mut()
        .unwrap()
        .remove("note");
    assert_finding(
        &refused(&project),
        "coordinator.mapping.field",
        "/workflow/steps/done/output/fields",
        "expected every member the accepted outcome requires; fields does not set note",
        "Add a note field with a reference or a literal.",
    );
}

#[test]
fn a_literal_that_fails_its_member_schema_is_refused() {
    let mut project = project();
    project["workflow"]["steps"]["read"]["input"]["fields"]["collection"]["value"] = json!(7);
    assert_finding(
        &refused(&project),
        "coordinator.mapping.literal",
        "/workflow/steps/read/input/fields/collection/value",
        "expected a value of type string for collection, as the breg.read-record/v1 input declares; the literal does not match",
        "Correct the literal to match what the breg.read-record/v1 input declares, or select the value with a reference.",
    );

    let mut project = self::project();
    project["workflow"]["steps"]["lookup"]["input"]["fields"]["query"]["value"] =
        json!({"page": 2});
    assert_finding(
        &refused(&project),
        "coordinator.mapping.literal",
        "/workflow/steps/lookup/input/fields/query/value",
        "expected a value of type string at /page inside query, as the external.get/v1 input declares; the literal does not match",
        "Correct the literal to match what the external.get/v1 input declares, or select the value with a reference.",
    );

    let mut project = self::project();
    project["workflow"]["steps"]["done"]["output"]["fields"]["note"]["value"] = json!("text");
    assert_finding(
        &refused(&project),
        "coordinator.mapping.literal",
        "/workflow/steps/done/output/fields/note/value",
        "expected a value of type null for note, as the accepted outcome declares; the literal does not match",
        "Correct the literal to match what the accepted outcome declares, or select the value with a reference.",
    );
}

#[test]
fn a_reference_of_another_type_or_format_is_refused() {
    let action = "Select a member of the declared type, or convert the value in a function.";
    let mut project = project();
    project["workflow"]["steps"]["read"]["input"]["fields"]["recordId"]["path"] = json!("/count");
    assert_finding(
        &refused(&project),
        "coordinator.mapping.type",
        "/workflow/steps/read/input/fields/recordId",
        "expected a string for recordId, as the breg.read-record/v1 input declares; the reference reads an integer",
        action,
    );

    let mut project = self::project();
    project["workflow"]["steps"]["read"]["input"]["fields"]["recordId"] = json!({"type": "input"});
    assert_finding(
        &refused(&project),
        "coordinator.mapping.type",
        "/workflow/steps/read/input/fields/recordId",
        "expected a string for recordId, as the breg.read-record/v1 input declares; the reference reads an object",
        action,
    );

    let mut project = self::project();
    project["workflow"]["outcomes"]["accepted"]["properties"]["record"] =
        json!({"type": "string", "format": "uuid"});
    project["workflow"]["steps"]["done"]["output"]["fields"]["record"] =
        json!({"type": "input", "path": "/sendAfter"});
    assert_finding(
        &refused(&project),
        "coordinator.mapping.type",
        "/workflow/steps/done/output/fields/record",
        "expected a uuid string for record, as the accepted outcome declares; the reference reads a date-time string",
        action,
    );

    // A plain string may hold any format, and an integer is a number.
    project["workflow"]["steps"]["done"]["output"]["fields"]["record"] =
        json!({"type": "input", "path": "/note"});
    project["workflow"]["outcomes"]["accepted"]["properties"]["revision"] =
        json!({"type": "number"});
    load(&project, "").unwrap();
}

#[test]
fn fields_cannot_feed_an_outcome_that_is_not_an_object() {
    let mut project = project();
    project["workflow"]["outcomes"]["accepted"] = json!({"type": "string"});
    assert_finding(
        &refused(&project),
        "coordinator.mapping.type",
        "/workflow/steps/done/output",
        "expected a string, as the accepted outcome declares; fields builds an object",
        "Build the output with a function, or declare an object outcome.",
    );
}

#[test]
fn wait_until_reads_only_a_date_time_string() {
    let action = "Select a date-time member, or compute the instant in a function.";
    for (path, reads) in [
        ("/count", "an integer"),
        ("/applicationId", "a uuid string"),
    ] {
        let mut project = project();
        project["workflow"]["steps"]["due"]["waitUntil"]["path"] = json!(path);
        assert_finding(
            &refused(&project),
            "coordinator.mapping.type",
            "/workflow/steps/due/waitUntil",
            &format!("expected a date-time string for waitUntil; the reference reads {reads}"),
            action,
        );
    }

    let mut project = project();
    project["workflow"]["steps"]["due"]["waitUntil"] =
        json!({"type": "literal", "value": "not an instant"});
    assert_finding(
        &refused(&project),
        "coordinator.mapping.literal",
        "/workflow/steps/due/waitUntil/value",
        "expected a date-time string for waitUntil; the literal does not match",
        "Write the literal as an RFC 3339 date-time, such as 2026-10-10T09:00:00Z, or select the instant with a reference.",
    );

    project["workflow"]["steps"]["due"]["waitUntil"]["value"] = json!("2026-10-10T09:00:00Z");
    load(&project, "").unwrap();
}

#[test]
fn a_plain_string_instant_is_left_to_the_run() {
    let mut project = project();
    project["workflow"]["steps"]["due"]["waitUntil"]["path"] = json!("/note");
    let definition = load(&project, "").unwrap();
    let input = json!({"applicationId": "00000000-0000-4000-8000-000000000000",
        "sendAfter": "2026-10-10T09:00:00Z", "route": "send", "count": 1, "note": "soon"});
    assert_eq!(
        definition
            .evaluate("due", &input, &BTreeMap::new())
            .unwrap_err()
            .code,
        "mapping.timestamp"
    );
}

#[test]
fn choose_reads_a_string_with_a_case_for_every_value() {
    let mut project = project();
    project["workflow"]["steps"]["route"]["choose"]["path"] = json!("/count");
    assert_finding(
        &refused(&project),
        "coordinator.mapping.type",
        "/workflow/steps/route/choose",
        "expected a string naming a case; the reference reads an integer",
        "Select a string member, or compute the label in a function.",
    );

    let mut project = self::project();
    project["workflow"]["input"]["$defs"]["Route"]["enum"] = json!(["send", "skip", "hold"]);
    assert_finding(
        &refused(&project),
        "coordinator.mapping.cases",
        "/workflow/steps/route/cases",
        "expected a case for every value the reference can read; there is no case for hold",
        "Add a case for hold.",
    );

    let mut project = self::project();
    project["workflow"]["steps"]["route"]["cases"]["later"] = json!("skipped");
    assert_finding(
        &refused(&project),
        "coordinator.mapping.cases",
        "/workflow/steps/route/cases/later",
        "expected only cases the reference can read; it never reads later",
        "Remove the later case.",
    );

    let mut project = self::project();
    project["workflow"]["steps"]["route"]["choose"] =
        json!({"type": "literal", "value": "elsewhere"});
    assert_finding(
        &refused(&project),
        "coordinator.mapping.literal",
        "/workflow/steps/route/choose/value",
        "expected a string naming a case; the literal names none",
        "Write the label of a declared case, or select the label with a reference.",
    );

    // A string without an enum may name any case, so the run decides.
    let mut project = self::project();
    project["workflow"]["input"]["properties"]["route"] = json!({"type": "string"});
    project["workflow"]["steps"]["route"]["cases"]["later"] = json!("skipped");
    load(&project, "").unwrap();
}

#[test]
fn each_step_reports_its_refusal_in_step_order() {
    let mut project = project();
    project["workflow"]["steps"]["read"]["input"]["fields"]["recordId"]["path"] =
        json!("/applicationID");
    project["workflow"]["steps"]["due"]["waitUntil"]["path"] = json!("/count");
    let error = refused(&project);
    let paths = error
        .diagnostics
        .iter()
        .map(|diagnostic| diagnostic.path.as_str())
        .collect::<Vec<_>>();
    assert_eq!(
        paths,
        [
            "/workflow/steps/due/waitUntil",
            "/workflow/steps/read/input/fields/recordId/path"
        ],
        "{error:?}"
    );
}

#[test]
fn an_admitted_snapshot_is_not_held_to_the_static_checks() {
    let definition = load(&project(), "").unwrap();
    let snapshot = definition
        .snapshot()
        .unwrap()
        .replace("\"/applicationId\"", "\"/applicationID\"");
    let restored = Definition::from_snapshot(&snapshot).unwrap();
    let input = json!({"applicationId": "00000000-0000-4000-8000-000000000000",
        "sendAfter": "2026-10-10T09:00:00Z", "route": "send", "count": 1});
    let error = restored
        .evaluate("read", &input, &BTreeMap::new())
        .unwrap_err();
    assert_eq!(error.code, "mapping.path");
    assert_eq!(
        error.field.as_deref(),
        Some("steps.read.input.fields.recordId")
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
