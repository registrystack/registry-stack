// SPDX-License-Identifier: Apache-2.0

use serde_json::Value;
use std::{
    fs,
    path::Path,
    process::{Command, Output},
};

fn export(output: &Path, fields: &str) -> Output {
    let project = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/breg/evidence/registry")
        .canonicalize()
        .unwrap();
    Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .args(["--format", "json", "generate", "evidence-source"])
        .arg(project)
        .args([
            "--access-profile",
            "evidence-source",
            "--entity",
            "record",
            "--selector",
            "by-code",
            "--selector",
            "by-registration-number",
            "--fields",
            fields,
            "--source-id",
            "registry-status",
            "--connection",
            "registry",
            "--output",
        ])
        .arg(output)
        .output()
        .unwrap()
}

#[test]
fn native_export_is_create_only_and_reports_selected_contract() {
    let temp = tempfile::tempdir().unwrap();
    let destination = temp.path().canonicalize().unwrap().join("export");
    let result = export(&destination, "status");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["explanation"]["connection"], "registry");
    assert_eq!(
        report["explanation"]["selectorProfiles"]
            .as_object()
            .unwrap()
            .len(),
        2
    );
    let manifest = fs::read(destination.join("source-export.json")).unwrap();
    let source: Value = serde_norway::from_slice(
        &fs::read(destination.join("sources/registry-status.yaml")).unwrap(),
    )
    .unwrap();
    assert_eq!(
        source["request"]["selectorInputs"][0]["alternatives"]
            .as_array()
            .unwrap()
            .len(),
        2
    );
    assert_eq!(source["request"]["projection"].as_array().unwrap().len(), 3);
    assert!(!String::from_utf8_lossy(&manifest).contains("SYNTHETIC-PRIVATE-LABEL"));
    fs::write(destination.join("author-note"), "preserve this work").unwrap();
    assert!(!export(&destination, "status").status.success());
    assert_eq!(
        fs::read(destination.join("source-export.json")).unwrap(),
        manifest
    );
    assert_eq!(
        fs::read_to_string(destination.join("author-note")).unwrap(),
        "preserve this work"
    );
}

#[test]
fn native_export_refuses_unreadable_facts_without_publishing_partial_files() {
    let temp = tempfile::tempdir().unwrap();
    let destination = temp.path().canonicalize().unwrap().join("refused");
    let result = export(&destination, "label");
    assert!(!result.status.success());
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["ok"], false);
    assert_eq!(report["diagnostics"][0]["code"], "evidence_source.refused");
    assert!(!destination.exists());
}
