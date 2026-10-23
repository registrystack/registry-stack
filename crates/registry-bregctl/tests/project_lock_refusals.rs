// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::process::{Command, Output};

use serde_json::Value;

#[test]
fn project_lock_preserves_registry_when_module_rhai_refuses_compilation() {
    let project = tempfile::tempdir().expect("temporary project creates");
    let module_directory = project.path().join("modules/core");
    fs::create_dir_all(module_directory.join("plans")).expect("module directory creates");
    fs::write(project.path().join("registry.yaml"), stale_project())
        .expect("project source writes");
    fs::write(module_directory.join("module.yaml"), module_source()).expect("module source writes");
    fs::write(
        module_directory.join("plans/update-record.rhai"),
        "fn plan(ctx) { let = ctx.inputs; }\n",
    )
    .expect("malformed function source writes");
    let original = fs::read(project.path().join("registry.yaml")).expect("project source reads");

    let refused = bregctl(&[
        "--format",
        "json",
        "project",
        "lock",
        project.path().to_str().expect("temporary path is UTF-8"),
    ]);

    assert_eq!(refused.status.code(), Some(1), "{refused:?}");
    assert!(refused.stderr.is_empty(), "{refused:?}");
    let report: Value = serde_json::from_slice(&refused.stdout).expect("refusal is JSON");
    assert_eq!(report["command"], "project lock");
    assert!(
        report["diagnostics"]
            .as_array()
            .expect("diagnostics is an array")
            .iter()
            .any(|diagnostic| diagnostic["code"] == "breg.action.handler-parse"),
        "{report}"
    );
    assert_eq!(
        fs::read(project.path().join("registry.yaml")).expect("project source rereads"),
        original,
        "a refused lock must leave the authored project byte-identical"
    );
}

fn bregctl(arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .args(arguments)
        .output()
        .expect("bregctl starts")
}

fn stale_project() -> &'static [u8] {
    br#"apiVersion: id.registrystack.org/formats/breg/project/v1alpha1
kind: BRegProject
project:
  id: lock-refusal-fixture
  version: "1"
  defaultLanguage: en
  canonicalBaseIri: https://lock-refusal-fixture.example.test
datasets:
  - id: test-dataset
modules:
  - id: core
    version: "1"
    digest: sha256:1111111111111111111111111111111111111111111111111111111111111111
"#
}

fn module_source() -> &'static [u8] {
    br#"apiVersion: id.registrystack.org/formats/breg/module/v1alpha1
kind: BRegModule
id: core
version: "1"
recordTypes:
  - id: record
    primaryDataset: test-dataset
    route: records
    mutationMode: mutable
    fields:
      - id: code
        type: string
        maximumLength: 16
        classification: internal
functions:
  - id: update-record-plan
    runtime: rhai
    source: plans/update-record.rhai
    entrypoint: plan
    abi: registry.action-plan/v1
actions:
  - id: update-record
    execution: {mode: immediate}
    inputs:
      - {id: record, type: reference, target: record, required: true, classification: internal}
      - {id: code, type: string, maximumLength: 16, required: true, classification: internal}
    plan:
      type: function
      function: update-record-plan
      inputs: [record, code]
      writes:
        - id: record
          target: {fromInput: record}
          operation: patch
          fields: [code]
"#
}
