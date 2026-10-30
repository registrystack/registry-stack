// SPDX-License-Identifier: Apache-2.0
//! Nested `fields` mappings: a member is a reference or a further `fields`
//! mapping, four levels deep at most and 64 members across the mapping, so a
//! Workflow builds a structured input without a Function.
use registry_coordinator::{authoring, definition::Definition, CoordinatorError};
use registry_platform_yaml::Diagnostic;
use serde_json::{json, Value};
use std::{collections::BTreeMap, fs, path::Path};

fn project() -> Value {
    json!({
        "apiVersion": "id.registrystack.org/formats/coordinator/project/v1alpha1",
        "kind": "CoordinatorProject",
        "project": {"id": "nested", "version": "1"},
        "operations": {
            "read-record": {"uses": "breg.read-record/v1", "connection": "applications"},
            "external-get": {"uses": "external.get/v1", "connection": "directory"}
        },
        "workflow": {
            "input": {
                "type": "object",
                "additionalProperties": false,
                "required": ["applicationId", "page", "count"],
                "properties": {
                    "applicationId": {"type": "string"},
                    "page": {"type": "string"},
                    "count": {"type": "integer"}
                }
            },
            "deadlineSeconds": 86400,
            "start": "read",
            "steps": {
                "read": {
                    "type": "call",
                    "operation": "read-record",
                    "input": {"type": "fields", "fields": {
                        "collection": {"type": "literal", "value": "applications"},
                        "recordId": {"type": "input", "path": "/applicationId"}
                    }},
                    "next": "lookup"
                },
                "lookup": {
                    "type": "call",
                    "operation": "external-get",
                    "input": {"type": "fields", "fields": {
                        "path": {"type": "literal", "value": "/people"},
                        "query": {"type": "fields", "fields": {
                            "page": {"type": "input", "path": "/page"},
                            "record": {"type": "step", "step": "read", "path": "/data/recordIdentifier"}
                        }}
                    }},
                    "next": "done"
                },
                "done": {
                    "type": "finish",
                    "outcome": "accepted",
                    "output": {"type": "fields", "fields": {
                        "record": {"type": "step", "step": "read", "path": "/data/recordIdentifier"},
                        "a": {"type": "fields", "fields": {
                            "b": {"type": "fields", "fields": {
                                "c": {"type": "fields", "fields": {
                                    "d": {"type": "input", "path": "/applicationId"},
                                    "n": {"type": "literal", "value": 3}
                                }}
                            }}
                        }}
                    }}
                }
            },
            "outcomes": {
                "accepted": {
                    "type": "object",
                    "additionalProperties": false,
                    "required": ["record", "a"],
                    "properties": {
                        "record": {"type": "string"},
                        "a": {"type": "object", "additionalProperties": false, "properties": {
                            "b": {"type": "object", "additionalProperties": false, "properties": {
                                "c": {"type": "object", "additionalProperties": false, "properties": {
                                    "d": {"type": "string"},
                                    "n": {"type": "integer"}
                                }}
                            }}
                        }}
                    }
                }
            }
        }
    })
}

fn input() -> Value {
    json!({"applicationId": "application-1", "page": "2", "count": 7})
}

fn record() -> Value {
    json!({
        "data": {"recordIdentifier": "record-1", "revisionIdentifier": "1", "domainData": {}},
        "meta": {"registryIdentifier": "r", "datasetIdentifier": "d", "recordTypeIdentifier": "e"}
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
    match load(project, "") {
        Ok(_) => panic!("the project must be refused"),
        Err(error) => error,
    }
}

fn parse_refused(project: &Value) -> CoordinatorError {
    match authoring::parse_project(Path::new("workflow.yaml"), project.to_string()) {
        Ok(_) => panic!("the project must be refused"),
        Err(error) => error,
    }
}

fn only(error: &CoordinatorError) -> &Diagnostic {
    assert_eq!(error.diagnostics.len(), 1, "{:#?}", error.diagnostics);
    let finding = &error.diagnostics[0];
    assert!(finding.source.as_ref().unwrap().line.is_some());
    finding
}

/// Declare every Function a mapping names, with open inputs and output.
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
                    functions.insert(name.into(), json!({"runtime":"rhai","source":"functions.rhai","entrypoint":name,"inputs":signature,"output":{}}));
                }
            }
            for value in object.values() {
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

/// A `fields` mapping nested `levels` deep, counting the outermost as 1,
/// whose innermost level reads the application id.
fn nested(levels: usize) -> Value {
    let mut mapping = json!({"type": "fields", "fields": {
        "d": {"type": "input", "path": "/applicationId"}
    }});
    for _ in 1..levels {
        mapping = json!({"type": "fields", "fields": {"m": mapping}});
    }
    mapping
}

#[test]
fn four_levels_are_accepted_and_a_fifth_is_refused_at_its_member() {
    let mut project = project();
    project["workflow"]["outcomes"]["accepted"] = json!({"type": "object"});
    project["workflow"]["steps"]["done"]["output"] = nested(4);
    let definition = load(&project, "").unwrap();
    assert_eq!(
        definition
            .evaluate("done", &input(), &BTreeMap::new())
            .unwrap(),
        json!({"m": {"m": {"m": {"d": "application-1"}}}})
    );

    project["workflow"]["steps"]["done"]["output"] = nested(5);
    let error = refused(&project);
    let finding = only(&error);
    assert_eq!(finding.code, "coordinator.mapping.fields-depth");
    assert_eq!(
        finding.path,
        "/workflow/steps/done/output/fields/m/fields/m/fields/m/fields/m"
    );
    assert_eq!(
        finding.message,
        "This fields mapping nests deeper than 4 levels."
    );
    assert_eq!(
        finding.suggested_action,
        "Flatten it, or build the inner value in an earlier step."
    );
}

/// An outer member `a` holding `inner` members, so the mapping counts
/// `inner + 1` members across its levels.
fn counted(inner: usize) -> Value {
    let members = (0..inner)
        .map(|index| {
            (
                format!("m{index:02}"),
                json!({"type": "literal", "value": index}),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    json!({"type": "fields", "fields": {"a": {"type": "fields", "fields": members}}})
}

#[test]
fn sixty_four_members_across_levels_are_accepted_and_a_sixty_fifth_is_refused() {
    let mut project = project();
    project["workflow"]["outcomes"]["accepted"] = json!({"type": "object"});
    project["workflow"]["steps"]["done"]["output"] = counted(63);
    let definition = load(&project, "").unwrap();
    let value = definition
        .evaluate("done", &input(), &BTreeMap::new())
        .unwrap();
    assert_eq!(value["a"].as_object().unwrap().len(), 63);

    project["workflow"]["steps"]["done"]["output"] = counted(64);
    let error = refused(&project);
    let finding = only(&error);
    assert_eq!(finding.code, "coordinator.mapping.fields-count");
    assert_eq!(
        finding.path,
        "/workflow/steps/done/output/fields/a/fields/m63"
    );
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
fn a_flat_mapping_of_sixty_five_members_is_refused_by_count() {
    let mut project = project();
    project["workflow"]["outcomes"]["accepted"] = json!({"type": "object"});
    let members = (0..65)
        .map(|index| {
            (
                format!("m{index:02}"),
                json!({"type": "literal", "value": index}),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    project["workflow"]["steps"]["done"]["output"] = json!({"type": "fields", "fields": members});
    let error = refused(&project);
    let finding = only(&error);
    assert_eq!(finding.code, "coordinator.mapping.fields-count");
    assert_eq!(finding.path, "/workflow/steps/done/output/fields/m64");
}

#[test]
fn a_nested_member_of_the_wrong_type_is_refused_at_its_path() {
    // external.get/v1 declares query as an object of strings.
    let mut project = project();
    project["workflow"]["steps"]["lookup"]["input"]["fields"]["query"]["fields"]["page"] =
        json!({"type": "input", "path": "/count"});
    let error = refused(&project);
    let finding = only(&error);
    assert_eq!(finding.code, "coordinator.mapping.type");
    assert_eq!(
        finding.path,
        "/workflow/steps/lookup/input/fields/query/fields/page"
    );
    assert_eq!(
        finding.message,
        "expected a string for page, as the external.get/v1 input declares; the reference reads an integer"
    );

    let mut project = self::project();
    project["workflow"]["steps"]["done"]["output"]["fields"]["a"]["fields"]["b"]["fields"]["c"]
        ["fields"]["n"] = json!({"type": "literal", "value": "three"});
    let error = refused(&project);
    let finding = only(&error);
    assert_eq!(finding.code, "coordinator.mapping.literal");
    assert_eq!(
        finding.path,
        "/workflow/steps/done/output/fields/a/fields/b/fields/c/fields/n/value"
    );

    let mut project = self::project();
    project["workflow"]["steps"]["done"]["output"]["fields"]["a"]["fields"]["b"]["fields"]["x"] =
        json!({"type": "literal", "value": 1});
    let error = refused(&project);
    let finding = only(&error);
    assert_eq!(finding.code, "coordinator.mapping.field");
    assert_eq!(
        finding.path,
        "/workflow/steps/done/output/fields/a/fields/b/fields/x"
    );

    // A nested member builds an object, so its target must accept one.
    let mut project = self::project();
    project["workflow"]["steps"]["done"]["output"]["fields"]["record"] =
        json!({"type": "fields", "fields": {}});
    let error = refused(&project);
    let finding = only(&error);
    assert_eq!(finding.code, "coordinator.mapping.type");
    assert_eq!(finding.path, "/workflow/steps/done/output/fields/record");

    // A required member of a nested object must be set.
    let mut project = self::project();
    project["workflow"]["outcomes"]["accepted"]["properties"]["a"]["required"] = json!(["b", "z"]);
    let error = refused(&project);
    let finding = only(&error);
    assert_eq!(finding.code, "coordinator.mapping.field");
    assert_eq!(finding.path, "/workflow/steps/done/output/fields/a/fields");
}

#[test]
fn a_nested_member_reads_only_outputs_available_on_every_route() {
    let mut project = project();
    project["workflow"]["steps"]["lookup"]["input"]["fields"]["query"]["fields"]["record"] =
        json!({"type": "step", "step": "done"});
    let error = refused(&project);
    let finding = only(&error);
    assert_eq!(finding.code, "coordinator.mapping.dominance");
    assert_eq!(
        finding.path,
        "/workflow/steps/lookup/input/fields/query/fields/record"
    );
}

#[test]
fn a_nested_member_never_holds_a_function() {
    let mut project = project();
    project["workflow"]["steps"]["lookup"]["input"]["fields"]["query"]["fields"]["page"] =
        json!({"type": "function", "function": "page", "inputs": {}});
    let error = parse_refused(&project);
    let finding = &error.diagnostics[0];
    assert_eq!(finding.code, "config.unknown-variant");
    assert_eq!(
        finding.path,
        "/workflow/steps/lookup/input/fields/query/fields/page/type"
    );
    assert_eq!(
        finding.message,
        "expected one of `input`, `step`, `literal`, `fields`"
    );

    // Function inputs stay plain references.
    let mut project = self::project();
    project["workflow"]["steps"]["lookup"]["input"] = json!({"type": "function", "function": "build", "inputs": {
        "page": {"type": "fields", "fields": {}}
    }});
    let error = parse_refused(&project);
    let finding = &error.diagnostics[0];
    assert_eq!(finding.code, "config.unknown-variant");
    assert_eq!(
        finding.path,
        "/workflow/steps/lookup/input/inputs/page/type"
    );
    assert_eq!(
        finding.message,
        "expected one of `input`, `step`, `literal`"
    );
}

#[test]
fn a_nested_mapping_freezes_the_input_a_function_would_build() {
    let declarative = load(&project(), "").unwrap();
    let mut computed = project();
    computed["workflow"]["steps"]["lookup"]["input"] = json!({"type": "function", "function": "build_query", "inputs": {
        "page": {"type": "input", "path": "/page"},
        "record": {"type": "step", "step": "read", "path": "/data/recordIdentifier"}
    }});
    computed["workflow"]["steps"]["done"]["output"] = json!({"type": "function", "function": "build_outcome", "inputs": {
        "id": {"type": "input", "path": "/applicationId"},
        "record": {"type": "step", "step": "read", "path": "/data/recordIdentifier"}
    }});
    let computed = load(
        &computed,
        "fn build_query(__named) { #{ path: \"/people\", query: #{ page: __named.page, record: __named.record } } }\n\
         fn build_outcome(__named) { #{ record: __named.record, a: #{ b: #{ c: #{ d: __named.id, n: 3 } } } } }",
    )
    .unwrap();
    let outputs = BTreeMap::from([("read".to_owned(), record())]);
    for step in ["lookup", "done"] {
        let built = declarative.evaluate(step, &input(), &outputs).unwrap();
        let rhai = computed.evaluate(step, &input(), &outputs).unwrap();
        assert_eq!(built, rhai, "{step}");
        assert_eq!(
            serde_json::to_vec(&built).unwrap(),
            serde_json::to_vec(&rhai).unwrap(),
            "{step}"
        );
    }
    assert_eq!(
        declarative.evaluate("lookup", &input(), &outputs).unwrap(),
        json!({"path": "/people", "query": {"page": "2", "record": "record-1"}})
    );

    // A nested reference that resolves to nothing fails at its own path.
    let error = declarative
        .evaluate("lookup", &input(), &BTreeMap::new())
        .unwrap_err();
    assert_eq!(error.code, "mapping.missing_output");
    assert_eq!(
        error.field.as_deref(),
        Some("steps.lookup.input.fields.query.fields.record")
    );
}

#[test]
fn a_nested_mapping_survives_the_snapshot() {
    let definition = load(&project(), "").unwrap();
    let snapshot: Value = serde_json::from_str(&definition.snapshot().unwrap()).unwrap();
    assert_eq!(
        snapshot["workflow"]["steps"]["lookup"]["input"],
        json!({"fields": {
            "path": {"type": "literal", "value": "/people"},
            "query": {"type": "fields", "fields": {
                "page": {"type": "input", "path": "/page"},
                "record": {"type": "step", "step": "read", "path": "/data/recordIdentifier"}
            }}
        }})
    );
    let restored = Definition::from_snapshot(&definition.snapshot().unwrap()).unwrap();
    assert_eq!(restored.digest, definition.digest);
    let outputs = BTreeMap::from([("read".to_owned(), record())]);
    assert_eq!(
        restored.evaluate("done", &input(), &outputs).unwrap(),
        definition.evaluate("done", &input(), &outputs).unwrap()
    );
}

/// A flat mapping compiles to the same definition, digest included, as it
/// did before members could nest.
#[test]
fn a_flat_mapping_is_unchanged() {
    let mut project = project();
    project["workflow"]["steps"]["lookup"]["input"]["fields"]["query"] =
        json!({"type": "literal", "value": {"page": "1"}});
    project["workflow"]["steps"]["done"]["output"]["fields"]["a"] =
        json!({"type": "literal", "value": {"b": {"c": {"d": "x", "n": 1}}}});
    let definition = load(&project, "").unwrap();
    let snapshot: Value = serde_json::from_str(&definition.snapshot().unwrap()).unwrap();
    assert_eq!(
        snapshot["workflow"]["steps"]["lookup"]["input"],
        json!({"fields": {
            "path": {"type": "literal", "value": "/people"},
            "query": {"type": "literal", "value": {"page": "1"}}
        }})
    );
    assert_eq!(
        definition.digest,
        "sha256:f50dbad620b01d86d3f6214c4acfe82f92e8db4c81442e3beb8c807a2a0c0801"
    );
}

#[test]
fn a_snapshot_refuses_unknown_members_of_a_nested_mapping() {
    let definition = load(&project(), "").unwrap();
    let snapshot: Value = serde_json::from_str(&definition.snapshot().unwrap()).unwrap();
    let query = &snapshot["workflow"]["steps"]["lookup"]["input"]["fields"]["query"];
    let mut extra = query.clone();
    extra["extra"] = json!(1);
    let mut untagged = query.clone();
    untagged.as_object_mut().unwrap().remove("type");
    let mut reference_with_fields = query.clone();
    reference_with_fields["fields"]["page"]["fields"] = json!({});
    let mut function_shaped = query.clone();
    function_shaped["fields"]["page"] =
        json!({"type": "function", "function": "page", "inputs": {}});
    let mut wrong_case = query.clone();
    wrong_case["type"] = json!("Fields");
    for (case, query) in [
        ("an unknown key", extra),
        ("a nested object without type", untagged),
        ("a reference carrying fields", reference_with_fields),
        ("a Function-shaped member", function_shaped),
        ("a wrong-case tag", wrong_case),
    ] {
        let mut snapshot = snapshot.clone();
        snapshot["workflow"]["steps"]["lookup"]["input"]["fields"]["query"] = query;
        match Definition::from_snapshot(&snapshot.to_string()) {
            Ok(_) => panic!("{case}: the snapshot must be refused"),
            Err(error) => assert_eq!(error.code, "definition.snapshot", "{case}"),
        }
    }
}

/// A project whose event trigger builds the Workflow input, including a
/// nested `applicant` object, from the event envelope.
fn triggered(applicant: Value) -> Value {
    let mut project = project();
    project["workflow"]["input"]["properties"]["applicant"] = json!({"type": "object"});
    project["workflow"]["eventTriggers"] = json!({"application-received": {
        "source": "applications",
        "eventType": "application-received-v1",
        "dataSchema": "urn:example:application-received:v1",
        "event": {
            "type": "object",
            "required": ["data"],
            "properties": {"data": {
                "type": "object",
                "required": ["id", "name"],
                "properties": {"id": {"type": "string"}, "name": {"type": "string"}}
            }}
        },
        "input": {"type": "fields", "fields": {
            "applicationId": {"type": "input", "path": "/data/id"},
            "page": {"type": "literal", "value": "1"},
            "count": {"type": "literal", "value": 1},
            "applicant": applicant
        }}
    }});
    project
}

#[test]
fn an_event_trigger_input_nests_within_the_same_bounds() {
    let applicant = json!({"type": "fields", "fields": {
        "name": {"type": "input", "path": "/data/name"}
    }});
    let definition = load(&triggered(applicant.clone()), "").unwrap();
    let snapshot: Value = serde_json::from_str(&definition.snapshot().unwrap()).unwrap();
    assert_eq!(
        snapshot["workflow"]["eventTriggers"]["application-received"]["input"]["fields"]
            ["applicant"],
        applicant
    );

    // The trigger input is the outermost level, so applicant opens level 2
    // and a fourth nested level below it opens level 5.
    let mut deep = nested(3);
    deep["fields"]["m"]["fields"]["m"]["fields"]["m"] = json!({"type": "fields", "fields": {}});
    let error = refused(&triggered(deep));
    let finding = only(&error);
    assert_eq!(finding.code, "coordinator.mapping.fields-depth");
    assert_eq!(
        finding.path,
        "/workflow/eventTriggers/application-received/input/fields/applicant/fields/m/fields/m/fields/m"
    );
}

/// The authored `Member` repeats every `Reference` form, so the generated
/// schema must list each of them, word for word, beside `fields`.
#[test]
fn the_member_schema_holds_every_reference_form_and_fields() {
    let schema: Value = serde_json::from_str(
        &fs::read_to_string(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("../../products/coordinator/generated/project/project.schema.json"),
        )
        .unwrap(),
    )
    .unwrap();
    let references = schema["$defs"]["Reference"]["oneOf"].as_array().unwrap();
    let members = schema["$defs"]["Member"]["oneOf"].as_array().unwrap();
    for reference in references {
        assert!(members.contains(reference), "Member lacks {reference}");
    }
    let tags = members
        .iter()
        .filter(|member| !references.contains(member))
        .map(|member| member["properties"]["type"]["const"].clone())
        .collect::<Vec<_>>();
    assert_eq!(tags, [json!("fields")]);
}
