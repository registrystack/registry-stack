// SPDX-License-Identifier: Apache-2.0
#![allow(
    clippy::disallowed_methods,
    reason = "tests read back generated artifacts and author synthetic project fixtures"
)]

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use serde_json::{json, Value};

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/breg/examples/minimal")
}

fn run(project: &Path, output: &Path, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_bregctl"))
        .args(["--format", "json", "generate", "odrl"])
        .arg(project)
        .arg("--output")
        .arg(output)
        .args(extra)
        .output()
        .expect("run bregctl")
}

fn read(path: &Path) -> Value {
    serde_json::from_slice(&std::fs::read(path).expect("generated file")).expect("valid JSON")
}

#[test]
fn odrl_cli_exports_supported_reads_and_reports_omissions() {
    let temporary = tempfile::tempdir().expect("temporary directory");
    let project = temporary.path().join("project");
    std::fs::create_dir(&project).unwrap();
    let bytes = std::fs::read(fixture().join("registry.yaml")).unwrap();
    let mut source = registry_platform_yaml::Reader::new("registry.yaml")
        .scan(&bytes)
        .unwrap()
        .unwrap()
        .to_json_value();
    source["accessProfiles"][0]["permissions"]["records"][0]["rowBoundaries"] =
        json!("unrestricted");
    std::fs::write(
        project.join("registry.yaml"),
        serde_norway::to_string(&source).unwrap(),
    )
    .unwrap();

    let output = temporary.path().join("output");
    let result = run(&project, &output, &["--access-profile", "directory-editor"]);
    assert!(result.status.success(), "{result:?}");
    assert!(result.stderr.is_empty(), "{result:?}");
    let report: Value = serde_json::from_slice(&result.stdout).unwrap();
    assert_eq!(report["ok"], true);
    let coverage = read(&output.join("generated/odrl/coverage.json"));
    assert_eq!(coverage["kind"], "BRegOdrlCoverage");
    assert_eq!(coverage["partial"], true);
    assert_eq!(
        coverage["totals"],
        json!({"considered": 4, "exported": 2, "omitted": 2})
    );
    let policies = read(&output.join("generated/odrl/policies.jsonld"));
    assert!(!policies["@graph"].as_array().unwrap().is_empty());
    assert!(output.join("generated/odrl/profile.jsonld").is_file());
    assert!(!output.join("generated/manifest").exists());

    let second = temporary.path().join("second");
    assert!(
        run(&project, &second, &["--access-profile", "directory-editor"])
            .status
            .success()
    );
    for file in ["policies.jsonld", "coverage.json", "profile.jsonld"] {
        assert_eq!(
            std::fs::read(output.join("generated/odrl").join(file)).unwrap(),
            std::fs::read(second.join("generated/odrl").join(file)).unwrap()
        );
    }
}

#[test]
fn odrl_cli_zero_coverage_is_explicit_and_does_not_fabricate_permissions() {
    let temporary = tempfile::tempdir().unwrap();
    let output = temporary.path().join("output");
    let result = run(&fixture(), &output, &[]);
    assert!(result.status.success(), "{result:?}");
    assert!(result.stderr.is_empty(), "{result:?}");
    let coverage = read(&output.join("generated/odrl/coverage.json"));
    assert_eq!(coverage["totals"]["exported"], 0);
    assert!(coverage["totals"]["omitted"].as_u64().unwrap() > 0);
    let policies = read(&output.join("generated/odrl/policies.jsonld"));
    assert_eq!(policies["@graph"], json!([]));
}

#[test]
fn odrl_cli_unknown_profile_and_irrelevant_flags_refuse_before_writing() {
    let temporary = tempfile::tempdir().unwrap();
    for (extra, expected_code) in [
        (
            vec!["--access-profile", "not-a-profile"],
            "breg.odrl.unknown-access-profile",
        ),
        (vec!["--record-type", "contact"], "odrl.arguments"),
    ] {
        let output = temporary.path().join("absent");
        let result = run(&fixture(), &output, &extra);
        assert!(!result.status.success());
        let report: Value = serde_json::from_slice(&result.stdout).expect("structured refusal");
        assert_eq!(report["ok"], false);
        assert_eq!(report["command"], "generate");
        assert_eq!(report["diagnostics"][0]["code"], expected_code);
        assert_eq!(report["diagnostics"][0]["artifact"], "command-arguments");
        assert_eq!(
            report["diagnostics"][0]["suggestedAction"],
            "correct-command-usage"
        );
        assert!(result.stderr.is_empty(), "{result:?}");
        assert!(!output.exists());
    }
}
