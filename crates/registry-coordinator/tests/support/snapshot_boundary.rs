// SPDX-License-Identifier: Apache-2.0
//! Authored fixtures at the existing persisted snapshot byte boundary.
use registry_coordinator::definition::Definition;
use serde_json::{json, Value};
use std::{fs, path::Path};

pub const SNAPSHOT_BOUND: usize = 393_216;

pub fn project_at_snapshot_size(path: &Path, size: usize) {
    fs::create_dir_all(path).unwrap();
    let schema = json!({"type": "null", "minimum": 0.000001, "$defs": {
        "first": {"description": "\"".repeat(16_000)},
        "second": {"description": "\"".repeat(16_000)}
    }});
    let mut workflow = json!({
        "apiVersion": "id.registrystack.org/formats/coordinator/project/v1alpha1",
        "kind": "CoordinatorProject", "project": {"id": "snapshot-boundary", "version": "1"},
        "input": schema, "connections": {}, "functionsFile": "functions.rhai",
        "deadlineSeconds": 3600, "start": "select",
        "steps": {
            "select": {"type": "choose", "choose": {"function": "branch", "arguments": [{"type": "input"}]},
                "cases": {"one": "first", "two": "second", "three": "third"}},
            "first": {"type": "finish", "outcome": "one"}, "second": {"type": "finish", "outcome": "two"},
            "third": {"type": "finish", "outcome": "three"}
        },
        "outcomes": {"one": schema, "two": schema, "three": schema}
    });
    workflow["input"]["description"] = json!("");
    // Valid Rhai with a referenced function and an escaping-heavy comment.
    // Authored YAML/source and each schema remain inside their own limits.
    let source = format!("fn branch(input) {{ \"one\" }}\n//{}", "\t".repeat(65_000));
    assert!(source.len() <= 65_536);
    fs::write(path.join("functions.rhai"), source).unwrap();
    write_workflow(path, &workflow);
    let baseline = Definition::load(path).unwrap().snapshot().unwrap().len();
    let padding = size.checked_sub(baseline).unwrap();
    assert!(padding <= 16_384);
    workflow["input"]["description"] = json!("x".repeat(padding));
    for schema in std::iter::once(&workflow["input"])
        .chain(workflow["outcomes"].as_object().unwrap().values())
    {
        assert!(
            registry_platform_canonical_json::canonicalize_json(schema)
                .unwrap()
                .len()
                <= 131_072
        );
    }
    write_workflow(path, &workflow);
}

fn write_workflow(path: &Path, workflow: &Value) {
    let text = serde_norway::to_string(workflow).unwrap();
    assert!(text.len() <= 262_144);
    fs::write(path.join("workflow.yaml"), text).unwrap();
}
