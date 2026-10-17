#![allow(
    clippy::disallowed_methods,
    reason = "tests read back the YAML the code under test wrote, or a published contract or fixture, to assert on it; they read no operator configuration"
)]
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
    export_project(&project, output, fields)
}

fn export_project(project: &Path, output: &Path, fields: &str) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .args(["--format", "json", "generate", "evidence-source"])
        .arg(project)
        .args([
            "--access-profile",
            "evidence-source",
            "--record-type",
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
    assert_eq!(
        report["diagnostics"][0]["code"],
        "breg.evidence-source.refused"
    );
    assert!(!destination.exists());
}

#[test]
fn an_explicit_lookup_project_exports_an_evidence_source_without_edits() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let project = root.join("registry");
    fs::create_dir(&project).unwrap();
    fs::copy(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/breg/evidence/registry/registry.yaml"),
        project.join("registry.yaml"),
    )
    .unwrap();

    let destination = root.join("export");
    let result = Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .args(["--format", "json", "generate", "evidence-source"])
        .arg(&project)
        .args([
            "--access-profile",
            "evidence-source",
            "--record-type",
            "record",
            "--selector",
            "by-code",
            "--fields",
            "status",
            "--source-id",
            "registry-status",
            "--connection",
            "registry",
            "--output",
        ])
        .arg(&destination)
        .output()
        .unwrap();

    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(
        report["explanation"]["selectorProfiles"]
            .as_object()
            .unwrap()
            .len(),
        1
    );
    assert!(destination.join("sources/registry-status.yaml").exists());
}

/// The `breg/evidence-source-export` format's example is the manifest this
/// export writes, committed as written. Rewrite it from the repository root:
///
/// ```text
/// bregctl generate evidence-source products/breg/evidence/registry \
///   --access-profile evidence-source --record-type record \
///   --selector by-code --selector by-registration-number --fields status \
///   --source-id registry-status --connection registry --output "$export"
/// cp "$export/source-export.json" products/breg/examples/formats/
/// ```
#[test]
fn committed_example_is_the_manifest_bregctl_writes() {
    let temp = tempfile::tempdir().unwrap();
    let destination = temp.path().canonicalize().unwrap().join("export");
    let result = export(&destination, "status");
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
    let example = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/breg/examples/formats/source-export.json");
    assert!(
        fs::read(destination.join("source-export.json")).unwrap() == fs::read(&example).unwrap(),
        "{example:?} is not the manifest `bregctl generate evidence-source` writes now; \
         rewrite it with the command in this test's comment"
    );
}

fn check_prior_export(project: &Path, manifest: &Path, deny_warnings: bool) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_bregctl"));
    command
        .args(["--format", "json", "check"])
        .arg(project)
        .arg("--prior-evidence-export")
        .arg(manifest);
    if deny_warnings {
        command.arg("--deny-warnings");
    }
    command.output().unwrap()
}

#[test]
fn prior_export_comparison_warns_on_renames_and_supports_deny_warnings() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let destination = root.join("export");
    assert!(export(&destination, "status").status.success());
    let manifest = destination.join("source-export.json");
    let project = root.join("registry");
    fs::create_dir(&project).unwrap();
    let original = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/breg/evidence/registry/registry.yaml"),
    )
    .unwrap();
    fs::write(project.join("registry.yaml"), &original).unwrap();
    let unchanged = check_prior_export(&project, &manifest, false);
    assert!(
        unchanged.status.success(),
        "{}",
        String::from_utf8_lossy(&unchanged.stderr)
    );
    let unchanged: Value = serde_json::from_slice(&unchanged.stdout).unwrap();
    let baseline_diagnostics = unchanged["diagnostics"].clone();

    fs::write(
        project.join("registry.yaml"),
        original.replace("Synthetic record registry", "Unrelated title"),
    )
    .unwrap();
    let unrelated = check_prior_export(&project, &manifest, false);
    assert!(unrelated.status.success());
    let unrelated: Value = serde_json::from_slice(&unrelated.stdout).unwrap();
    assert_eq!(unrelated["diagnostics"], baseline_diagnostics);

    let renamed = original
        .replace("id: status\n", "id: state\n")
        .replace("- status\n", "- state\n");
    fs::write(project.join("registry.yaml"), renamed).unwrap();
    let warning = check_prior_export(&project, &manifest, false);
    assert!(
        warning.status.success(),
        "a removed exported field warns without denying by default"
    );
    let warning: Value = serde_json::from_slice(&warning.stdout).unwrap();
    assert!(warning["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["severity"] == "warning"
            && item["code"] == "breg.evidence-source.field-removed"));
    assert_eq!(
        check_prior_export(&project, &manifest, true).status.code(),
        Some(1)
    );
}

#[test]
fn prior_export_comparison_warns_on_removed_fields_and_refuses_wrong_identity() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let destination = root.join("export");
    assert!(export(&destination, "status").status.success());
    let manifest = destination.join("source-export.json");
    let project = root.join("registry");
    fs::create_dir(&project).unwrap();
    let original = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/breg/evidence/registry/registry.yaml"),
    )
    .unwrap();
    let removed = original.replace("  - id: status\n    type: vocabulary-code\n    vocabulary: record-status\n    classification: internal\n", "").replace("      - status\n", "");
    fs::write(project.join("registry.yaml"), removed).unwrap();
    let result = check_prior_export(&project, &manifest, false);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stdout)
    );
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert!(report["diagnostics"]
        .as_array()
        .unwrap()
        .iter()
        .any(|item| item["code"] == "breg.evidence-source.field-removed"));
    fs::write(project.join("registry.yaml"), original).unwrap();
    let original: Value = serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
    for member in ["registryId", "entity"] {
        let mut wrong = original.clone();
        wrong["provenance"][member] = "other".into();
        fs::write(&manifest, serde_json::to_vec(&wrong).unwrap()).unwrap();
        let result = check_prior_export(&project, &manifest, false);
        assert_eq!(result.status.code(), Some(1));
        let report: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert!(report["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["code"] == "breg.evidence-source.refused"));
    }
}

#[test]
fn prior_export_comparison_warns_on_api_name_rename_and_denies_warnings() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path().canonicalize().unwrap();
    let project = root.join("registry");
    fs::create_dir(&project).unwrap();
    let original = fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/breg/evidence/registry/registry.yaml"),
    )
    .unwrap();
    let mut source: Value = serde_norway::from_str(&original).unwrap();
    // Remove unrelated unrestricted-row findings so --deny-warnings proves this change.
    for profile in source["accessProfiles"].as_array_mut().unwrap() {
        for permission in profile["permissions"]["records"].as_array_mut().unwrap() {
            permission["rowBoundaries"] = serde_json::json!([
                {"field":"code", "claim":"registry_principal", "operator":"equals"}
            ]);
        }
    }
    fs::write(
        project.join("registry.yaml"),
        serde_norway::to_string(&source).unwrap(),
    )
    .unwrap();
    let destination = root.join("export");
    assert!(export_project(&project, &destination, "status")
        .status
        .success());
    let manifest = destination.join("source-export.json");
    let unchanged = check_prior_export(&project, &manifest, true);
    assert!(
        unchanged.status.success(),
        "{}",
        String::from_utf8_lossy(&unchanged.stdout)
    );
    source["recordTypes"][0]["fields"][1]["apiName"] = "registrationCode".into();
    fs::write(
        project.join("registry.yaml"),
        serde_norway::to_string(&source).unwrap(),
    )
    .unwrap();
    let warning = check_prior_export(&project, &manifest, false);
    assert!(
        warning.status.success(),
        "{}",
        String::from_utf8_lossy(&warning.stdout)
    );
    let report: Value = serde_json::from_slice(&warning.stdout).unwrap();
    assert!(
        report["diagnostics"]
            .as_array()
            .unwrap()
            .iter()
            .any(|item| item["severity"] == "warning"
                && item["code"] == "breg.evidence-source.field-removed"),
        "an API-name-only rename must warn: {report}"
    );
    assert_eq!(
        check_prior_export(&project, &manifest, true).status.code(),
        Some(1)
    );
}
