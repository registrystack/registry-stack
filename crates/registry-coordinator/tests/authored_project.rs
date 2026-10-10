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
        "start":"done", "steps":{"done":{"type":"finish", "outcome":"accepted", "output":{"function":"identity", "arguments":[{"type":"input"}]}}},
        "outcomes":{"accepted":{}}
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
    assert_eq!(
        frozen["apiVersion"],
        "id.registrystack.org/formats/coordinator/definition-snapshot/v1alpha1"
    );
    assert_eq!(frozen["kind"], "CoordinatorDefinitionSnapshot");
    assert!(frozen["workflow"].get("apiVersion").is_none());
    assert!(frozen["workflow"].get("kind").is_none());
    assert_eq!(frozen["workflow"]["steps"]["done"]["finish"], "accepted");
    assert!(frozen["workflow"]["steps"]["done"].get("type").is_none());
    assert_eq!(
        frozen["workflow"]["steps"]["done"]["output"]["arguments"],
        json!(["input"])
    );
    assert_eq!(frozen["adapterAbi"], "coordinator/product-operations/v4");
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
fn a_snapshot_without_its_envelope_is_refused() {
    let root = tempfile::tempdir().unwrap();
    write_project(root.path(), &project(), "fn identity(input) { input }");
    let snapshot = Definition::load(root.path()).unwrap().snapshot().unwrap();
    let frozen: Value = serde_json::from_str(&snapshot).unwrap();
    let refused = |change: &dyn Fn(&mut Value)| {
        let mut changed = frozen.clone();
        change(&mut changed);
        let error = Definition::from_snapshot(&changed.to_string())
            .err()
            .expect("the envelope is required");
        assert_eq!(error.code, "definition.snapshot");
    };
    refused(&|value| {
        value.as_object_mut().unwrap().remove("apiVersion");
    });
    refused(&|value| {
        value.as_object_mut().unwrap().remove("kind");
    });
    refused(&|value| value["apiVersion"] = json!(authoring::API_VERSION));
    refused(&|value| value["kind"] = json!(authoring::KIND));
    refused(&|value| value["workflow"]["kind"] = json!("Workflow"));
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
            "type":"wait-until", "waitUntil":{"function":"identity", "arguments":[{"type":"input"}]},
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
    assert_eq!(
        schema["$defs"]["AuthoredMapping"]["properties"]["arguments"]["maxItems"],
        16
    );
    assert_eq!(
        schema["properties"]["functionsFile"]["const"],
        "functions.rhai"
    );
}
