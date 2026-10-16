// SPDX-License-Identifier: Apache-2.0
//! The portable authoring layer preserves the persisted execution representation.
use registry_coordinator::{authoring, definition::Definition};
use serde_json::{json, Value};
use std::{fs, path::Path};

fn project() -> Value {
    json!({
        "apiVersion": "id.registrystack.org/formats/coordinator/project/v1alpha1",
        "kind": "CoordinatorProject",
        "project": {
            "id": "tiny",
            "version": "1"
        },
        "workflow": {
            "input": {
                "type": "object",
                "properties": {
                    "optional": {
                        "const": null
                    }
                }
            },
            "deadlineSeconds": 60,
            "start": "done",
            "steps": {
                "done": {
                    "type": "finish",
                    "outcome": "accepted",
                    "output": {
                        "type": "function",
                        "function": "identity",
                        "inputs": {
                            "arg0": {
                                "type": "input"
                            }
                        }
                    }
                }
            },
            "outcomes": {
                "accepted": {}
            }
        }
    })
}

fn declared_refusal_project() -> Value {
    json!({
        "apiVersion": "id.registrystack.org/formats/coordinator/project/v1alpha1",
        "kind": "CoordinatorProject",
        "project": {
            "id": "declared-refusal",
            "version": "1"
        },
        "contracts":{"registry":{"type":"breg","source":"action-contracts.json"}},
        "operations": {
            "invoke-breg-action": {
                "uses": "breg.invoke-action/v1",
                "connection": "registry",
                "action":{"contract":"registry","id":"request-information"}
            }
        },
        "workflow": {
            "input": {},
            "deadlineSeconds": 60,
            "start": "act",
            "steps": {
                "act": {
                    "type": "call",
                    "operation": "invoke-breg-action",
                    "input": {
                        "type": "function",
                        "function": "command",
                        "inputs": {
                            "arg0": {
                                "type": "input"
                            }
                        }
                    },
                    "next": "accepted",
                    "onDeclaredRefusal": "refused"
                },
                "accepted": {
                    "type": "finish",
                    "outcome": "accepted"
                },
                "refused": {
                    "type": "finish",
                    "outcome": "refused",
                    "output": {
                        "type": "fields",
                        "fields": {
                            "refusalCode": {
                                "type": "step",
                                "step": "act",
                                "path": "/refusalCode"
                            }
                        }
                    }
                }
            },
            "outcomes": {
                "accepted": {
                    "type": "null"
                },
                "refused": {
                    "type": "object",
                    "required": [
                        "refusalCode"
                    ],
                    "properties": {
                        "refusalCode": {
                            "type": "string"
                        }
                    },
                    "additionalProperties": false
                }
            }
        }
    })
}

fn write_project(root: &Path, project: &Value, source: &str) {
    let project = declare_test_functions(project);
    fs::write(
        root.join("workflow.yaml"),
        serde_json::to_string(&project).unwrap(),
    )
    .unwrap();
    fs::write(root.join("functions.rhai"), source).unwrap();
    if project.get("contracts").is_some() {
        fs::write(root.join("action-contracts.json"), include_str!(
            "../../../products/coordinator/examples/governed-action-follow-up/generated/applications.contract.json"
        )).unwrap();
    }
}

#[test]
fn authored_project_converts_to_the_versioned_snapshot_abi() {
    let root = tempfile::tempdir().unwrap();
    write_project(
        root.path(),
        &project(),
        "fn identity(__named) { let input = __named.arg0;  input }",
    );
    let definition = Definition::load(root.path()).unwrap();
    let snapshot = definition.snapshot().unwrap();
    let frozen: Value = serde_json::from_str(&snapshot).unwrap();
    assert_eq!(frozen["workflow"]["kind"], "Workflow");
    assert_eq!(
        frozen["workflow"]["apiVersion"],
        "id.registrystack.org/formats/coordinator/definition-snapshot/v1alpha1"
    );
    assert_eq!(frozen["workflow"]["steps"]["done"]["outcome"], "accepted");
    assert_eq!(frozen["workflow"]["steps"]["done"]["type"], "finish");
    assert_eq!(
        frozen["workflow"]["steps"]["done"]["output"]["inputs"],
        json!({"arg0":{"type": "input"}})
    );
    assert_eq!(frozen["adapterAbi"], "coordinator/product-operations/v1");
    let restored = Definition::from_snapshot(&snapshot).unwrap();
    assert_eq!(restored.digest, definition.digest);
    assert_eq!(restored.workflow, definition.workflow);
    assert_eq!(
        restored
            .evaluate("done", &json!({"optional":null}), &Default::default())
            .unwrap(),
        json!({"optional":null})
    );
}

#[test]
fn declared_refusal_edge_is_frozen_in_the_snapshot_and_restores_exactly() {
    let root = tempfile::tempdir().unwrap();
    let project = declared_refusal_project();
    write_project(
        root.path(),
        &project,
        "fn command(__named) { let input = __named.arg0;  input }",
    );
    let definition = Definition::load(root.path()).unwrap();
    let snapshot = definition.snapshot().unwrap();
    let frozen: Value = serde_json::from_str(&snapshot).unwrap();
    assert_eq!(frozen["adapterAbi"], "coordinator/product-operations/v1");
    assert_eq!(
        frozen["workflow"]["steps"]["act"]["onDeclaredRefusal"],
        "refused"
    );
    let explained = definition.explain().unwrap();
    let act = explained["steps"]
        .as_array()
        .unwrap()
        .iter()
        .find(|step| step["id"] == "act")
        .unwrap();
    assert_eq!(act["onDeclaredRefusal"], "refused");
    assert_eq!(
        Definition::from_snapshot(&snapshot)
            .unwrap()
            .snapshot()
            .unwrap(),
        snapshot
    );

    // The step decoder is closed: an edge it does not know is refused, never
    // dropped, so a snapshot cannot lose its refusal route on restore.
    let mut unknown_edge = frozen.clone();
    let act = unknown_edge["workflow"]["steps"]["act"]
        .as_object_mut()
        .unwrap();
    let target = act.remove("onDeclaredRefusal").unwrap();
    act.insert("onUndeclaredEdge".into(), target);
    assert_eq!(
        Definition::from_snapshot(&unknown_edge.to_string())
            .err()
            .expect("an unknown step member must refuse")
            .code,
        "definition.snapshot"
    );

    let mut other_abi = frozen;
    other_abi["adapterAbi"] = json!("coordinator/product-operations/v2");
    assert_eq!(
        Definition::from_snapshot(&other_abi.to_string())
            .err()
            .expect("another adapter ABI must refuse")
            .code,
        "definition.abi"
    );
}

#[test]
fn a_snapshot_using_a_removed_operation_names_it_and_asks_for_a_reseal() {
    let root = tempfile::tempdir().unwrap();
    write_project(
        root.path(),
        &declared_refusal_project(),
        "fn command(__named) { let input = __named.arg0;  input }",
    );
    let snapshot = Definition::load(root.path()).unwrap().snapshot().unwrap();
    assert!(snapshot.contains("\"breg.invoke-action/v1\""));
    let removed = snapshot.replace("\"breg.invoke-action/v1\"", "\"breg.submit-proposal/v1\"");
    let error = Definition::from_snapshot(&removed)
        .err()
        .expect("a removed operation must refuse");
    assert_eq!(error.code, "definition.operation_removed");
    assert!(
        error.message.contains("`breg.submit-proposal/v1`"),
        "{}",
        error.message
    );
    let next = error.suggested_action.as_deref().unwrap();
    assert!(next.contains("reseal"), "{next}");
}

#[test]
fn declared_refusal_is_available_only_on_its_edge_and_not_after_a_mixed_join() {
    let root = tempfile::tempdir().unwrap();
    let source = "fn command(__named) { let input = __named.arg0;  input } fn identity(__named) { let value = __named.arg0;  value }";
    let project = declared_refusal_project();
    write_project(root.path(), &project, source);
    Definition::load(root.path()).expect("the refusal edge reads its declared output");

    let mut success_reads_refusal = project.clone();
    success_reads_refusal["workflow"]["steps"]["accepted"]["output"] = json!({
        "type":"fields", "fields":{"refusalCode":{
            "type":"step", "step":"act", "path":"/refusalCode"
        }}
    });
    success_reads_refusal["workflow"]["outcomes"]["accepted"] =
        success_reads_refusal["workflow"]["outcomes"]["refused"].clone();
    write_project(root.path(), &success_reads_refusal, source);
    assert_eq!(
        Definition::load(root.path()).err().unwrap().code,
        "coordinator.mapping.path"
    );

    let mut refusal_reads_success = project.clone();
    refusal_reads_success["workflow"]["steps"]["refused"]["output"]["fields"]["refusalCode"]
        ["path"] = json!("/applicationId");
    write_project(root.path(), &refusal_reads_success, source);
    assert_eq!(
        Definition::load(root.path()).err().unwrap().code,
        "coordinator.mapping.path"
    );

    let mut joined = project;
    joined["workflow"]["steps"]["act"]["next"] = json!("joined");
    joined["workflow"]["steps"]["act"]["onDeclaredRefusal"] = json!("joined");
    joined["workflow"]["steps"]
        .as_object_mut()
        .unwrap()
        .remove("accepted");
    joined["workflow"]["steps"]
        .as_object_mut()
        .unwrap()
        .remove("refused");
    joined["workflow"]["steps"]["joined"] = json!({
        "type":"finish", "outcome":"joined", "output":{
            "type":"function", "function":"identity", "inputs": {"arg0": {"type":"step", "step":"act"}}
        }
    });
    joined["workflow"]["outcomes"] = json!({"joined":{}});
    write_project(root.path(), &joined, source);
    assert_eq!(
        Definition::load(root.path()).err().unwrap().code,
        "coordinator.mapping.dominance"
    );
}

#[test]
fn operations_without_a_declared_refusal_contract_reject_the_edge() {
    let root = tempfile::tempdir().unwrap();
    let mut project = declared_refusal_project();
    project["operations"]["invoke-breg-action"] =
        json!({"uses":"breg.read-record/v1","connection":"registry"});
    write_project(
        root.path(),
        &project,
        "fn command(__named) { let input = __named.arg0;  input }",
    );
    let error = Definition::load(root.path()).err().unwrap();
    assert_eq!(error.code, "coordinator.definition.operation");
    assert_eq!(
        error.field.as_deref(),
        Some("/workflow/steps/act/onDeclaredRefusal")
    );
}

#[test]
fn a_snapshot_cannot_carry_the_refusal_edge_on_an_operation_without_it() {
    let root = tempfile::tempdir().unwrap();
    let mut project = declared_refusal_project();
    project["operations"]["invoke-breg-action"] =
        json!({"uses":"breg.read-record/v1","connection":"registry"});
    let steps = project["workflow"]["steps"].as_object_mut().unwrap();
    steps["act"]
        .as_object_mut()
        .unwrap()
        .remove("onDeclaredRefusal");
    steps.remove("refused");
    project["workflow"]["outcomes"]
        .as_object_mut()
        .unwrap()
        .remove("refused");
    write_project(
        root.path(),
        &project,
        "fn command(__named) { let input = __named.arg0;  input }",
    );
    let snapshot = Definition::load(root.path()).unwrap().snapshot().unwrap();
    let mut frozen: Value = serde_json::from_str(&snapshot).unwrap();
    // A call without the edge freezes no member for it.
    assert_eq!(
        frozen["workflow"]["steps"]["act"].get("onDeclaredRefusal"),
        None
    );
    frozen["workflow"]["steps"]["act"]["onDeclaredRefusal"] = json!("accepted");
    assert_eq!(
        Definition::from_snapshot(&frozen.to_string())
            .err()
            .expect("the restored edge must refuse")
            .code,
        "definition.operation"
    );
}

#[test]
fn function_compile_diagnostics_keep_the_function_file_and_position() {
    let root = tempfile::tempdir().unwrap();
    write_project(
        root.path(),
        &project(),
        "fn identity(__named) { let input = __named.arg0; \n    let broken = ;\n}\n",
    );
    let error = Definition::load(root.path())
        .err()
        .expect("must refuse syntax");
    let finding = &error.diagnostics[0];
    assert_eq!(finding.code, "coordinator.function.definition");
    assert_eq!(finding.path, "");
    let source = finding.source.as_ref().unwrap();
    assert!(source.file.ends_with("functions.rhai"));
    assert_eq!(source.line, Some(2));
    assert!(source.column.is_some());
}

#[test]
fn authored_project_structural_errors_keep_the_authored_member_position() {
    let mut project = project();
    project["workflow"]["steps"]["done"]["unexpected"] = json!("private-marker-value");
    let error = authoring::parse_project(Path::new("workflow.yaml"), project.to_string())
        .expect_err("unknown member must refuse");
    let finding = error
        .diagnostics
        .iter()
        .find(|finding| finding.code == "config.unknown-key")
        .unwrap();
    assert_eq!(finding.path, "/workflow/steps/done/unexpected");
    assert!(finding.source.as_ref().unwrap().line.is_some());
    assert!(!error.to_string().contains("private-marker-value"));
}

#[cfg(unix)]
#[test]
fn linked_function_source_refusal_points_to_the_authored_reference() {
    let root = tempfile::tempdir().unwrap();
    write_project(
        root.path(),
        &project(),
        "fn identity(__named) { let input = __named.arg0;  input }",
    );
    fs::remove_file(root.path().join("functions.rhai")).unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();
    std::os::unix::fs::symlink(outside.path(), root.path().join("functions.rhai")).unwrap();
    let error = Definition::load(root.path())
        .err()
        .expect("a linked source must refuse");
    let finding = error.diagnostics.first().expect("a positioned finding");
    assert_eq!(finding.path, "/functions/identity/source");
    assert!(finding
        .source
        .as_ref()
        .unwrap()
        .file
        .ends_with("workflow.yaml"));
    assert!(finding.source.as_ref().unwrap().line.is_some());
    assert!(finding.source.as_ref().unwrap().column.is_some());
}

#[test]
fn missing_function_source_keeps_the_operational_exit_and_authored_position() {
    let root = tempfile::tempdir().unwrap();
    write_project(
        root.path(),
        &project(),
        "fn identity(__named) { let input = __named.arg0;  input }",
    );
    fs::remove_file(root.path().join("functions.rhai")).unwrap();
    let error = Definition::load(root.path())
        .err()
        .expect("missing source must refuse");
    assert_eq!(error.exit_code, 3);
    assert_eq!(error.diagnostics[0].path, "/functions/identity/source");
    assert!(error.diagnostics[0]
        .source
        .as_ref()
        .unwrap()
        .file
        .ends_with("workflow.yaml"));
}

#[test]
fn execution_member_diagnostics_preserve_authored_step_names() {
    let root = tempfile::tempdir().unwrap();
    for name in ["finish", "finish-next", "call"] {
        let mut project = project();
        project["workflow"]["start"] = json!(name);
        project["workflow"]["steps"] = json!({name: {
            "type":"wait-until", "waitUntil":{"type":"function", "function":"identity", "inputs": {"arg0": {"type":"input"}}},
            "next":"missing"
        }});
        write_project(
            root.path(),
            &project,
            "fn identity(__named) { let input = __named.arg0;  input }",
        );
        let Err(error) = Definition::load(root.path()) else {
            panic!("missing target must be refused");
        };
        assert_eq!(
            error.field.as_deref(),
            Some(format!("/workflow/steps/{name}/next").as_str())
        );
        let source = error.diagnostics[0].source.as_ref().unwrap();
        assert!(source.line.is_some() && source.column.is_some());
    }
}

#[test]
fn project_file_encoding_is_reported_by_the_shared_reader() {
    let root = tempfile::tempdir().unwrap();
    write_project(
        root.path(),
        &project(),
        "fn identity(__named) { let input = __named.arg0;  input }",
    );
    fs::write(root.path().join("workflow.yaml"), b"\xff\xfe").unwrap();
    let error = Definition::load(root.path()).err().expect("invalid UTF-8");
    assert_eq!(error.code, "yaml.not-utf8");
    assert!(error.diagnostics[0]
        .source
        .as_ref()
        .unwrap()
        .file
        .ends_with("workflow.yaml"));
}

#[test]
fn oversized_project_file_is_reported_by_the_shared_reader() {
    let root = tempfile::tempdir().unwrap();
    write_project(
        root.path(),
        &project(),
        "fn identity(__named) { let input = __named.arg0;  input }",
    );
    let padded = format!("{}\n#{}\n", project(), "x".repeat(1_048_576));
    fs::write(root.path().join("workflow.yaml"), padded).unwrap();
    let error = Definition::load(root.path()).err().expect("oversized file");
    assert_eq!(error.code, "yaml.too-large");
    assert!(error.diagnostics[0]
        .source
        .as_ref()
        .unwrap()
        .file
        .ends_with("workflow.yaml"));
}

#[cfg(feature = "schema")]
#[test]
fn project_version_schema_and_execution_grammar_agree() {
    let schema: Value = serde_json::from_str(&authoring::project_schema().unwrap()).unwrap();
    let validator = jsonschema::JSONSchema::compile(&schema).unwrap();
    let root = tempfile::tempdir().unwrap();
    for (version, accepted) in [
        ("release_A-1".to_owned(), true),
        ("a".repeat(64), true),
        (String::new(), false),
        ("a".repeat(65), false),
        ("1.2".to_owned(), false),
        ("version value".to_owned(), false),
    ] {
        let mut project = project();
        project["project"]["version"] = json!(version);
        assert_eq!(validator.is_valid(&project), accepted, "schema: {version}");
        write_project(
            root.path(),
            &project,
            "fn identity(__named) { let input = __named.arg0;  input }",
        );
        assert_eq!(
            Definition::load(root.path()).is_ok(),
            accepted,
            "runtime: {version}"
        );
    }
}

#[cfg(feature = "schema")]
#[test]
fn project_schema_matches_local_keys_bounds_and_foreign_schema_members() {
    let schema: Value = serde_json::from_str(&authoring::project_schema().unwrap()).unwrap();
    assert!(schema["properties"].get("input").is_none());
    assert!(schema["properties"].get("functionsFile").is_none());
    for (pointer, minimum, maximum) in [
        ("/properties/operations", 0, 64),
        ("/properties/functions", 0, 128),
        ("/properties/types", 0, 128),
        ("/$defs/AuthoredWorkflow/properties/steps", 1, 64),
        ("/$defs/AuthoredWorkflow/properties/outcomes", 1, 64),
    ] {
        let mapping = schema.pointer(pointer).unwrap();
        assert_eq!(mapping["propertyNames"]["$ref"], "#/$defs/LocalId");
        assert_eq!(mapping["minProperties"], minimum);
        assert_eq!(mapping["maxProperties"], maximum);
        assert!(mapping.get("patternProperties").is_none());
        assert!(mapping["additionalProperties"].is_object());
    }
    let variants = schema["$defs"]["AuthoredMapping"]["oneOf"]
        .as_array()
        .unwrap();
    let tags = variants
        .iter()
        .map(|variant| variant["properties"]["type"]["const"].as_str().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(tags, ["function", "fields", "input", "step", "literal"]);
    let function = variants
        .iter()
        .find(|variant| variant["properties"]["type"]["const"] == "function")
        .unwrap();
    assert_eq!(function["properties"]["inputs"]["maxProperties"], 16);
    assert_eq!(schema["$defs"]["Fields"]["maxProperties"], 64);
    assert_eq!(schema["$defs"]["JsonPointer"]["maxLength"], 256);
    let mut references = Vec::new();
    local_references(&schema, &mut references);
    for reference in references {
        assert!(
            schema.pointer(&reference[1..]).is_some(),
            "{reference} names no definition"
        );
    }
}

/// The tiny project with one call that feeds `input` to `operation`.
#[cfg(feature = "schema")]
fn call_project(operation: &str, input: Value) -> Value {
    let mut project = project();
    let catalog = match operation {
        "read-record" => "breg.read-record/v1",
        "read-scheduling" => "scheduling.read-service/v1",
        "external-get" => "external.get/v1",
        "submit-message" => "messaging.submit-message/v1",
        _ => operation,
    };
    project["operations"] = json!({"source-call":{"uses":catalog,"connection":"source"}});
    project["workflow"]["start"] = json!("call");
    project["workflow"]["input"] = json!({"type":"object"});
    project["workflow"]["steps"]["call"] =
        json!({"type":"call","operation":"source-call","input":input,"next":"done"});
    project
}

#[cfg(feature = "schema")]
#[test]
fn project_schema_holds_each_fields_mapping_to_its_operation_input_members() {
    // The schema exposes catalog choices. Alias-dependent schema fit is checked
    // by the same canonical compiler, rather than a duplicated schema catalogue.
    let schema: Value = serde_json::from_str(&authoring::project_schema().unwrap()).unwrap();
    let choices = schema["$defs"]["Operation"]["enum"].as_array().unwrap();
    for descriptor in registry_coordinator::operations::descriptors() {
        assert!(choices.contains(&json!(descriptor.id)));
    }
    let literal = json!({"type":"literal","value":"applications"});
    let input = |path: &str| json!({"type":"input","path":path});
    let root = tempfile::tempdir().unwrap();
    for (operation, mapping, accepted) in [
        (
            "read-record",
            json!({"type":"fields","fields":{"collection":literal,"recordId":input("/id")}}),
            true,
        ),
        (
            "read-record",
            json!({"type":"fields","fields":{"collection":literal,"recordId":input("/id"),"resource":input("/id")}}),
            false,
        ),
        (
            "read-record",
            json!({"type":"fields","fields":{"collection":literal}}),
            false,
        ),
        (
            "read-scheduling",
            json!({"type":"fields","fields":{}}),
            true,
        ),
        (
            "read-scheduling",
            json!({"type":"fields","fields":{"collection":literal}}),
            false,
        ),
        (
            "external-get",
            json!({"type":"fields","fields":{"path":{"type":"literal","value":"/status"},"query":input("/query")}}),
            true,
        ),
        (
            "external-get",
            json!({"type":"fields","fields":{"query":input("/query")}}),
            false,
        ),
    ] {
        write_project(
            root.path(),
            &call_project(operation, mapping.clone()),
            "fn identity(inputs) { inputs.arg0 }",
        );
        assert_eq!(
            Definition::load(root.path()).is_ok(),
            accepted,
            "{operation} {mapping}"
        );
    }
}

#[cfg(feature = "schema")]
#[test]
fn every_example_workflow_satisfies_the_project_schema() {
    let schema: Value = serde_json::from_str(&authoring::project_schema().unwrap()).unwrap();
    let validator = jsonschema::JSONSchema::compile(&schema).unwrap();
    let examples =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/coordinator/examples");
    let mut checked = 0;
    for entry in fs::read_dir(examples).unwrap() {
        let workflow = entry.unwrap().path().join("workflow.yaml");
        if !workflow.is_file() {
            continue;
        }
        let document = registry_platform_yaml::Reader::new(workflow.to_string_lossy())
            .scan(&fs::read(&workflow).unwrap())
            .unwrap()
            .unwrap()
            .to_json_value();
        let errors: Vec<String> = match validator.validate(&document) {
            Ok(()) => Vec::new(),
            Err(errors) => errors
                .map(|error| format!("{} {error}", error.instance_path))
                .collect(),
        };
        assert!(errors.is_empty(), "{}: {errors:?}", workflow.display());
        checked += 1;
    }
    assert!(checked >= 7, "found {checked} example workflows");
}

#[cfg(feature = "schema")]
fn local_references(value: &Value, found: &mut Vec<String>) {
    match value {
        Value::Object(members) => {
            for (name, member) in members {
                match (name.as_str(), member) {
                    ("$ref", Value::String(target)) => found.push(target.clone()),
                    _ => local_references(member, found),
                }
            }
        }
        Value::Array(items) => items.iter().for_each(|item| local_references(item, found)),
        _ => {}
    }
}

/// Every authored member a project or scenarios file may write, and every
/// form a tagged member may take, carries a description an editor shows on
/// hover. A variant's `type` tag is described by its variant, and the
/// per-operation `if`/`then` rules only narrow members described elsewhere.
#[cfg(feature = "schema")]
#[test]
fn authoring_schemas_describe_every_member_and_form() {
    fn undescribed(value: &Value, at: &str, found: &mut Vec<String>) {
        let Value::Object(members) = value else {
            if let Value::Array(items) = value {
                for (index, item) in items.iter().enumerate() {
                    undescribed(item, &format!("{at}/{index}"), found);
                }
            }
            return;
        };
        for (name, member) in members {
            let here = format!("{at}/{name}");
            match name.as_str() {
                "if" | "then" => continue,
                "properties" => {
                    for (key, property) in member.as_object().into_iter().flatten() {
                        let tag = key == "type" && property.get("const").is_some();
                        if !tag && property.get("description").is_none() {
                            found.push(format!("{here}/{key}"));
                        }
                    }
                }
                "oneOf" => {
                    for (index, form) in member.as_array().into_iter().flatten().enumerate() {
                        if form.get("description").is_none() {
                            found.push(format!("{here}/{index}"));
                        }
                    }
                }
                _ => {}
            }
            undescribed(member, &here, found);
        }
    }
    for (name, text) in [
        ("project", authoring::project_schema().unwrap()),
        (
            "scenarios",
            registry_coordinator::scenarios::scenario_schema().unwrap(),
        ),
    ] {
        let schema: Value = serde_json::from_str(&text).unwrap();
        let mut found = Vec::new();
        undescribed(&schema, "", &mut found);
        assert!(
            found.is_empty(),
            "{name} schema lacks descriptions at {found:#?}"
        );
    }
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
