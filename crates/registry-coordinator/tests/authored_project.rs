// SPDX-License-Identifier: Apache-2.0
//! The portable authoring layer preserves the persisted execution representation.
use registry_coordinator::{authoring, definition::Definition};
use serde_json::{json, Value};
use std::{fs, path::Path};

fn project() -> Value {
    json!({
        "apiVersion": authoring::API_VERSION, "kind": authoring::KIND,
        "project": {"id":"tiny", "version":"1"},
        "input": {"type":"object", "properties":{"optional":{"const":null}}},
        "connections": {}, "functionsFile":"functions.rhai", "deadlineSeconds":60,
        "start":"done", "steps":{"done":{"type":"finish", "outcome":"accepted", "output":{"type":"function", "function":"identity", "arguments":[{"type":"input"}]}}},
        "outcomes":{"accepted":{}}
    })
}

fn declared_refusal_project() -> Value {
    json!({
        "apiVersion": authoring::API_VERSION, "kind": authoring::KIND,
        "project": {"id":"declared-refusal", "version":"1"},
        "input": {}, "connections": {"registry":"breg"},
        "functionsFile":"functions.rhai", "deadlineSeconds":60,
        "start":"act",
        "steps": {
            "act": {"type":"call", "connection":"registry", "operation":"invoke-breg-action",
                "input":{"type":"function", "function":"command", "arguments":[{"type":"input"}]},
                "next":"accepted", "onDeclaredRefusal":"refused"},
            "accepted": {"type":"finish", "outcome":"accepted"},
            "refused": {"type":"finish", "outcome":"refused", "output":{
                "type":"fields", "fields":{"refusalCode":{"type":"step", "step":"act", "path":"/refusalCode"}}
            }}
        },
        "outcomes": {
            "accepted":{"type":"null"},
            "refused":{"type":"object", "required":["refusalCode"],
                "properties":{"refusalCode":{"type":"string"}}, "additionalProperties":false}
        }
    })
}

fn write_project(root: &Path, project: &Value, source: &str) {
    fs::write(
        root.join("workflow.yaml"),
        serde_json::to_string(project).unwrap(),
    )
    .unwrap();
    fs::write(root.join("functions.rhai"), source).unwrap();
}

#[test]
fn authored_project_converts_to_the_versioned_snapshot_abi() {
    let root = tempfile::tempdir().unwrap();
    write_project(root.path(), &project(), "fn identity(input) { input }");
    let definition = Definition::load(root.path()).unwrap();
    let snapshot = definition.snapshot().unwrap();
    let frozen: Value = serde_json::from_str(&snapshot).unwrap();
    assert_eq!(frozen["workflow"]["kind"], "Workflow");
    assert_eq!(
        frozen["workflow"]["apiVersion"],
        "id.registrystack.org/formats/coordinator/definition-snapshot/v1alpha1"
    );
    assert_eq!(frozen["workflow"]["steps"]["done"]["finish"], "accepted");
    assert!(frozen["workflow"]["steps"]["done"].get("type").is_none());
    assert_eq!(
        frozen["workflow"]["steps"]["done"]["output"]["arguments"],
        json!([{"type": "input"}])
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
fn declared_refusal_opt_in_uses_v2_and_restores_only_with_its_shape() {
    let root = tempfile::tempdir().unwrap();
    let project = declared_refusal_project();
    write_project(root.path(), &project, "fn command(input) { input }");
    let definition = Definition::load(root.path()).unwrap();
    let snapshot = definition.snapshot().unwrap();
    let frozen: Value = serde_json::from_str(&snapshot).unwrap();
    assert_eq!(frozen["adapterAbi"], "coordinator/product-operations/v2");
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

    for changed in [
        {
            let mut changed = frozen.clone();
            changed["adapterAbi"] = json!("coordinator/product-operations/v1");
            changed
        },
        {
            let mut changed = frozen.clone();
            changed["workflow"]["steps"]["act"]
                .as_object_mut()
                .unwrap()
                .remove("onDeclaredRefusal");
            changed
        },
    ] {
        let error = Definition::from_snapshot(&changed.to_string())
            .err()
            .expect("ABI and feature shape must agree");
        assert_eq!(error.code, "definition.abi");
    }
}

#[test]
fn declared_refusal_is_available_only_on_its_edge_and_not_after_a_mixed_join() {
    let root = tempfile::tempdir().unwrap();
    let source = "fn command(input) { input } fn identity(value) { value }";
    let project = declared_refusal_project();
    write_project(root.path(), &project, source);
    Definition::load(root.path()).expect("the refusal edge reads its declared output");

    let mut success_reads_refusal = project.clone();
    success_reads_refusal["steps"]["accepted"]["output"] = json!({
        "type":"fields", "fields":{"refusalCode":{
            "type":"step", "step":"act", "path":"/refusalCode"
        }}
    });
    success_reads_refusal["outcomes"]["accepted"] =
        success_reads_refusal["outcomes"]["refused"].clone();
    write_project(root.path(), &success_reads_refusal, source);
    assert_eq!(
        Definition::load(root.path()).err().unwrap().code,
        "coordinator.mapping.path"
    );

    let mut refusal_reads_success = project.clone();
    refusal_reads_success["steps"]["refused"]["output"]["fields"]["refusalCode"]["path"] =
        json!("/applicationId");
    write_project(root.path(), &refusal_reads_success, source);
    assert_eq!(
        Definition::load(root.path()).err().unwrap().code,
        "coordinator.mapping.path"
    );

    let mut joined = project;
    joined["steps"]["act"]["next"] = json!("joined");
    joined["steps"]["act"]["onDeclaredRefusal"] = json!("joined");
    joined["steps"].as_object_mut().unwrap().remove("accepted");
    joined["steps"].as_object_mut().unwrap().remove("refused");
    joined["steps"]["joined"] = json!({
        "type":"finish", "outcome":"joined", "output":{
            "type":"function", "function":"identity", "arguments":[{"type":"step", "step":"act"}]
        }
    });
    joined["outcomes"] = json!({"joined":{}});
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
    project["steps"]["act"]["operation"] = json!("read-record");
    write_project(root.path(), &project, "fn command(input) { input }");
    let error = Definition::load(root.path()).err().unwrap();
    assert_eq!(error.code, "coordinator.definition.operation");
    assert_eq!(error.field.as_deref(), Some("/steps/act/onDeclaredRefusal"));
}

#[test]
fn function_compile_diagnostics_keep_the_function_file_and_position() {
    let root = tempfile::tempdir().unwrap();
    write_project(
        root.path(),
        &project(),
        "fn identity(input) {\n    let broken = ;\n}\n",
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
    project["steps"]["done"]["unexpected"] = json!("private-marker-value");
    let error = authoring::parse_project(Path::new("workflow.yaml"), project.to_string())
        .expect_err("unknown member must refuse");
    let finding = error
        .diagnostics
        .iter()
        .find(|finding| finding.code == "config.unknown-key")
        .unwrap();
    assert_eq!(finding.path, "/steps/done/unexpected");
    assert!(finding.source.as_ref().unwrap().line.is_some());
    assert!(!error.to_string().contains("private-marker-value"));
}

#[cfg(unix)]
#[test]
fn linked_function_source_refusal_points_to_the_authored_reference() {
    let root = tempfile::tempdir().unwrap();
    write_project(root.path(), &project(), "fn identity(input) { input }");
    fs::remove_file(root.path().join("functions.rhai")).unwrap();
    let outside = tempfile::NamedTempFile::new().unwrap();
    std::os::unix::fs::symlink(outside.path(), root.path().join("functions.rhai")).unwrap();
    let error = Definition::load(root.path())
        .err()
        .expect("a linked source must refuse");
    let finding = error.diagnostics.first().expect("a positioned finding");
    assert_eq!(finding.path, "/functionsFile");
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
    write_project(root.path(), &project(), "fn identity(input) { input }");
    fs::remove_file(root.path().join("functions.rhai")).unwrap();
    let error = Definition::load(root.path())
        .err()
        .expect("missing source must refuse");
    assert_eq!(error.exit_code, 3);
    assert_eq!(error.diagnostics[0].path, "/functionsFile");
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
        project["start"] = json!(name);
        project["steps"] = json!({name: {
            "type":"wait-until", "waitUntil":{"type":"function", "function":"identity", "arguments":[{"type":"input"}]},
            "next":"missing"
        }});
        write_project(root.path(), &project, "fn identity(input) { input }");
        let Err(error) = Definition::load(root.path()) else {
            panic!("missing target must be refused");
        };
        assert_eq!(
            error.field.as_deref(),
            Some(format!("/steps/{name}/next").as_str())
        );
        let source = error.diagnostics[0].source.as_ref().unwrap();
        assert!(source.line.is_some() && source.column.is_some());
    }
}

#[test]
fn project_file_encoding_is_reported_by_the_shared_reader() {
    let root = tempfile::tempdir().unwrap();
    write_project(root.path(), &project(), "fn identity(input) { input }");
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
    write_project(root.path(), &project(), "fn identity(input) { input }");
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
        write_project(root.path(), &project, "fn identity(input) { input }");
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
    assert_eq!(
        schema["properties"]["input"]["x-registry-foreign"],
        "json-schema-2020-12"
    );
    assert_eq!(
        schema["properties"]["outcomes"]["additionalProperties"]["x-registry-foreign"],
        "json-schema-2020-12"
    );
    for (field, minimum, maximum) in [
        ("connections", 0, 16),
        ("steps", 1, 64),
        ("outcomes", 1, 64),
    ] {
        assert_eq!(
            schema["properties"][field]["propertyNames"]["$ref"],
            "#/$defs/LocalId"
        );
        assert_eq!(schema["properties"][field]["minProperties"], minimum);
        assert_eq!(schema["properties"][field]["maxProperties"], maximum);
        assert!(schema["properties"][field]
            .get("patternProperties")
            .is_none());
        assert!(schema["properties"][field]["additionalProperties"].is_object());
    }
    // Every mapping form is named by its `type` member.
    for (union, forms) in [
        ("AuthoredInput", vec!["function", "fields"]),
        (
            "AuthoredSelector",
            vec!["function", "input", "step", "literal"],
        ),
    ] {
        let variants = schema["$defs"][union]["oneOf"].as_array().unwrap();
        let tags: Vec<&str> = variants
            .iter()
            .map(|variant| variant["properties"]["type"]["const"].as_str().unwrap())
            .collect();
        assert_eq!(tags, forms, "{union}");
        for variant in variants {
            assert!(variant["required"]
                .as_array()
                .unwrap()
                .contains(&json!("type")));
            if variant["properties"]["type"]["const"] == "function" {
                assert_eq!(variant["properties"]["arguments"]["maxItems"], 16);
            }
        }
    }
    // A fields key is a member name the operation input or outcome issues,
    // so it is an external identifier, held to the field-name grammar.
    let fields = &schema["$defs"]["Fields"];
    assert_eq!(
        fields["propertyNames"],
        json!({"allOf": [{"$ref": "#/$defs/ExternalId"}, {"$ref": "#/$defs/FieldName"}]})
    );
    assert_eq!(
        schema["$defs"]["ExternalId"],
        serde_json::to_value(
            <registry_platform_yaml::ExternalId as schemars::JsonSchema>::json_schema(
                &mut schemars::SchemaGenerator::default()
            )
        )
        .unwrap()
    );
    assert_eq!(
        schema["$defs"]["FieldName"]["pattern"],
        "^[A-Za-z][A-Za-z0-9_-]{0,63}$"
    );
    let mut references = Vec::new();
    local_references(&schema, &mut references);
    for reference in references {
        assert!(
            schema
                .pointer(&reference[1..])
                .is_some_and(|target| !target.is_null()),
            "{reference} names no definition"
        );
    }
    assert_eq!(fields["maxProperties"], 64);
    assert!(fields.get("patternProperties").is_none());
    assert_eq!(fields["additionalProperties"]["$ref"], "#/$defs/Reference");
    assert_eq!(schema["$defs"]["JsonPointer"]["maxLength"], 256);
    assert_eq!(
        schema["properties"]["functionsFile"]["const"],
        "functions.rhai"
    );
}

/// The tiny project with one call that feeds `input` to `operation`.
#[cfg(feature = "schema")]
fn call_project(operation: &str, input: Value) -> Value {
    let mut project = project();
    project["connections"] = json!({"source": "breg"});
    project["start"] = json!("call");
    project["steps"]["call"] = json!({"type": "call", "connection": "source",
        "operation": operation, "input": input, "next": "done"});
    project
}

#[cfg(feature = "schema")]
#[test]
fn project_schema_holds_each_fields_mapping_to_its_operation_input_members() {
    let schema: Value = serde_json::from_str(&authoring::project_schema().unwrap()).unwrap();
    let validator = jsonschema::JSONSchema::compile(&schema).unwrap();
    let input = |path: &str| json!({"type": "input", "path": path});
    let literal = json!({"type": "literal", "value": "applications"});
    let function =
        json!({"type": "function", "function": "identity", "arguments": [{"type": "input"}]});
    for (operation, mapping, accepted) in [
        (
            "read-record",
            json!({"type": "fields", "fields": {"collection": literal, "recordId": input("/id")}}),
            true,
        ),
        (
            "read-record",
            json!({"type": "fields", "fields": {"collection": literal, "recordId": input("/id"),
                "grant": input("/grant")}}),
            true,
        ),
        (
            "read-record",
            json!({"type": "fields", "fields": {"collection": literal, "recordId": input("/id"),
                "resource": input("/id")}}),
            false,
        ),
        (
            "read-record",
            json!({"type": "fields", "fields": {"collection": literal}}),
            false,
        ),
        ("read-record", function.clone(), true),
        (
            "read-scheduling",
            json!({"type": "fields", "fields": {}}),
            true,
        ),
        (
            "read-scheduling",
            json!({"type": "fields", "fields": {"collection": literal}}),
            false,
        ),
        (
            "external-get",
            json!({"type": "fields", "fields": {"path": literal, "query": input("/query")}}),
            true,
        ),
        (
            "external-get",
            json!({"type": "fields", "fields": {"query": input("/query")}}),
            false,
        ),
        (
            "submit-message",
            json!({"type": "fields", "fields": {"senderProfile": literal, "to": input("/to")}}),
            true,
        ),
        (
            "submit-message",
            json!({"type": "fields", "fields": {"senderProfile": literal, "recipient": input("/to")}}),
            false,
        ),
        ("submit-message", function.clone(), true),
        (
            "read-record",
            json!({"fields": {"collection": literal, "recordId": input("/id")}}),
            false,
        ),
        (
            "read-record",
            json!({"function": "identity", "arguments": [{"type": "input"}]}),
            false,
        ),
    ] {
        let project = call_project(operation, mapping.clone());
        assert_eq!(
            validator.is_valid(&project),
            accepted,
            "{operation} {mapping}"
        );
    }
    // A finish output is not an operation input, so its members stay open.
    let mut finish = project();
    finish["steps"]["done"]["output"] =
        json!({"type": "fields", "fields": {"resource": input("/id")}});
    assert!(validator.is_valid(&finish));

    let call = schema["$defs"]["AuthoredStep"]["oneOf"]
        .as_array()
        .unwrap()
        .iter()
        .find(|variant| variant["properties"]["type"]["const"] == "call")
        .unwrap();
    let constrained: Vec<&str> = call["allOf"]
        .as_array()
        .unwrap()
        .iter()
        .map(|rule| {
            rule["if"]["properties"]["operation"]["const"]
                .as_str()
                .unwrap()
        })
        .collect();
    let catalog: Vec<&str> = registry_coordinator::operations::descriptors()
        .iter()
        .map(|descriptor| descriptor.id)
        .collect();
    assert_eq!(constrained, catalog);

    let function =
        json!({"type": "function", "function": "identity", "arguments": [{"type": "input"}]});
    let mut supported = call_project("invoke-breg-action", function.clone());
    supported["steps"]["call"]["onDeclaredRefusal"] = json!("done");
    assert!(validator.is_valid(&supported));
    let mut unsupported = call_project("read-record", function);
    unsupported["steps"]["call"]["onDeclaredRefusal"] = json!("done");
    assert!(!validator.is_valid(&unsupported));
    assert!(call["properties"]["onDeclaredRefusal"]
        .get("default")
        .is_none());
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
