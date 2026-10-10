// SPDX-License-Identifier: Apache-2.0
//! First project journey through the public executable, entirely offline.
use serde_json::Value;
use std::{fs, process::Command};

fn cli(arguments: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_coordinatorctl"))
        .args(arguments)
        .env_remove("COORDINATOR_TEST_DATABASE_URL")
        .output()
        .unwrap()
}

#[test]
fn runtime_check_is_offline_until_environment_is_explicitly_requested() {
    let root = tempfile::tempdir().unwrap();
    let file = root.path().canonicalize().unwrap().join("runtime.yaml");
    let text =
        include_str!("../../../products/coordinator/examples/delayed-follow-up/runtime.yaml")
            .replace(
                "namespace: coordinator_demo",
                "namespace: ${COORDINATOR_CHECK_NAMESPACE}",
            );
    fs::write(&file, text).unwrap();
    let arguments = [
        "--format",
        "json",
        "--runtime-config",
        file.to_str().unwrap(),
        "check",
    ];
    let unchecked = cli(&arguments);
    assert!(
        unchecked.status.success(),
        "{}",
        String::from_utf8_lossy(&unchecked.stdout)
    );
    let report: Value = serde_json::from_slice(&unchecked.stdout).unwrap();
    assert_eq!(report["kind"], "CoordinatorCtlReport");
    assert_eq!(report["ok"], true);
    // A valid stand-in permits the surrounding document to be checked.
    assert_eq!(report["diagnostics"], serde_json::json!([]));
    let denied = cli(&[arguments.as_slice(), &["--deny-warnings"]].concat());
    assert!(denied.status.success());
    for (value, exit) in [("coordinator_example", 0), ("PRIVATE-NAMESPACE-CANARY", 1)] {
        let output = Command::new(env!("CARGO_BIN_EXE_coordinatorctl"))
            .args(arguments)
            .arg("--environment")
            .env("COORDINATOR_CHECK_NAMESPACE", value)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(exit),
            "{}",
            String::from_utf8_lossy(&output.stdout)
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains("PRIVATE-NAMESPACE-CANARY"));
    }
    // A product discriminator cannot decode its generic stand-in. The common
    // reader explicitly warns that the remainder could not be checked.
    let text = fs::read_to_string(&file)
        .unwrap()
        .replace("product: breg", "product: ${COORDINATOR_CHECK_PRODUCT}");
    fs::write(&file, text).unwrap();
    let incomplete = cli(&arguments);
    assert!(incomplete.status.success());
    let report: Value = serde_json::from_slice(&incomplete.stdout).unwrap();
    assert_eq!(report["diagnostics"][0]["severity"], "warning");
    assert_eq!(
        report["diagnostics"][0]["path"],
        "/connections/applications/product"
    );
    let denied = cli(&[arguments.as_slice(), &["--deny-warnings"]].concat());
    assert_eq!(denied.status.code(), Some(1));
}

#[test]
fn checking_reports_distinct_refusal_usage_and_unavailable_exits() {
    let empty = cli(&["--format", "json", "check"]);
    assert_eq!(empty.status.code(), Some(2));
    let empty: Value = serde_json::from_slice(&empty.stdout).unwrap();
    assert_eq!(empty["diagnostics"][0]["code"], "coordinator.command.usage");
    let root = tempfile::tempdir().unwrap();
    let missing = root.path().canonicalize().unwrap().join("missing.yaml");
    let unavailable = cli(&[
        "--format",
        "json",
        "--runtime-config",
        missing.to_str().unwrap(),
        "check",
    ]);
    assert_eq!(unavailable.status.code(), Some(3));
    let report: Value = serde_json::from_slice(&unavailable.stdout).unwrap();
    assert_eq!(report["status"], "operational-failure");
    let usage = cli(&["--format", "json", "check", "--PRIVATE-ARGUMENT-CANARY"]);
    assert_eq!(usage.status.code(), Some(2));
    assert!(!String::from_utf8_lossy(&usage.stdout).contains("PRIVATE-ARGUMENT-CANARY"));
    let invalid = root.path().canonicalize().unwrap().join("runtime.yaml");
    let text =
        include_str!("../../../products/coordinator/examples/delayed-follow-up/runtime.yaml")
            .replace(
                "namespace: coordinator_demo",
                "namespace: coordinator_demo\nunknownRoot: PRIVATE-PRODUCT-CANARY",
            )
            .replace(
                "product: breg",
                "product: breg\n    unknownConnection: PRIVATE-PRODUCT-CANARY",
            );
    fs::write(&invalid, text).unwrap();
    let refusal = cli(&[
        "--format",
        "json",
        "--runtime-config",
        invalid.to_str().unwrap(),
        "check",
    ]);
    assert_eq!(refusal.status.code(), Some(1));
    let bytes = String::from_utf8(refusal.stdout).unwrap();
    assert!(!bytes.contains("PRIVATE-PRODUCT-CANARY"));
    let report: Value = serde_json::from_str(&bytes).unwrap();
    let findings = report["diagnostics"].as_array().unwrap();
    assert!(findings.len() >= 2);
    assert!(findings.iter().all(|finding| finding["source"]["line"]
        .as_u64()
        .is_some_and(|line| line > 0)));
}

#[test]
fn init_check_and_explain_work_without_database_or_signing_keys() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().canonicalize().unwrap().join("first-workflow");
    let directory = path.to_str().unwrap();
    let initialized = cli(&["--format", "json", "init", "--directory", directory]);
    assert!(
        initialized.status.success(),
        "{}",
        String::from_utf8_lossy(&initialized.stderr)
    );
    let result: Value = serde_json::from_slice(&initialized.stdout).unwrap();
    assert_eq!(result["status"], "initialized");
    assert_eq!(fs::read_dir(&path).unwrap().count(), 3);
    let runtime = path.join("runtime.yaml");
    let checked = cli(&[
        "--format",
        "json",
        "--runtime-config",
        runtime.to_str().unwrap(),
        "check",
        "--project",
        directory,
    ]);
    assert!(
        checked.status.success(),
        "{}",
        String::from_utf8_lossy(&checked.stderr)
    );
    let result: Value = serde_json::from_slice(&checked.stdout).unwrap();
    assert_eq!(result["status"], "valid");
    assert!(result["definitionDigest"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    let explained = cli(&[
        "--format",
        "json",
        "check",
        "--project",
        directory,
        "--explain",
    ]);
    assert!(explained.status.success());
    let result: Value = serde_json::from_slice(&explained.stdout).unwrap();
    assert_eq!(result["networkAccess"], false);
    assert_eq!(result["databaseAccess"], false);
    assert_eq!(result["secretResolution"], false);
    assert_eq!(result["limits"]["operations"], 100000);
    assert_eq!(result["steps"].as_array().unwrap().len(), 6);
    let text = cli(&["check", "--project", directory]);
    assert!(text.status.success());
    assert!(String::from_utf8(text.stdout)
        .unwrap()
        .contains("Valid workflow"));
    let refused = cli(&["--format", "json", "init", "--directory", directory]);
    assert!(!refused.status.success());
    let result: Value = serde_json::from_slice(&refused.stdout).unwrap();
    assert_eq!(result["diagnostics"][0]["code"], "coordinator.project.init");
    assert!(result["diagnostics"][0]["suggestedAction"]
        .as_str()
        .unwrap()
        .contains("never overwritten"));
}

#[test]
fn check_locates_a_missing_binding_without_printing_configured_values() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().canonicalize().unwrap().join("first-workflow");
    let directory = path.to_str().unwrap();
    assert!(cli(&["init", "--directory", directory]).status.success());
    let runtime = path.join("runtime.yaml");
    let mut document: Value = registry_platform_config::RuntimeConfigLoader::new(
        registry_platform_config::RuntimeEnvelope {
            api_version: registry_coordinator::runtime::API_VERSION,
            kind: registry_coordinator::runtime::KIND,
        },
    )
    .parse_str::<Value>(&fs::read_to_string(&runtime).unwrap(), |_| None)
    .unwrap()
    .config;
    let original = document["connections"]
        .as_object_mut()
        .unwrap()
        .remove("applications")
        .unwrap();
    document["connections"]["wrong-name"] = original;
    document["connections"]["wrong-name"]["authorization"]["resource"] =
        Value::String("urn:example:configured-value-canary".into());
    fs::write(&runtime, serde_norway::to_string(&document).unwrap()).unwrap();
    let refused = cli(&[
        "--format",
        "json",
        "--runtime-config",
        runtime.to_str().unwrap(),
        "check",
        "--project",
        directory,
    ]);
    assert!(!refused.status.success());
    let report = String::from_utf8(refused.stdout).unwrap();
    assert!(!report.contains("configured-value-canary"));
    let result: Value = serde_json::from_str(&report).unwrap();
    assert_eq!(
        result["diagnostics"][0]["code"],
        "coordinator.runtime.workflow-binding"
    );
    assert_eq!(
        result["diagnostics"][0]["path"],
        "/connections/applications"
    );
    assert!(result["diagnostics"][0]["suggestedAction"]
        .as_str()
        .unwrap()
        .contains("same logical name"));
}

#[path = "support/snapshot_boundary.rs"]
mod snapshot_boundary;

#[test]
fn check_and_package_refuse_oversized_canonical_snapshot_before_writing() {
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("project");
    snapshot_boundary::project_at_snapshot_size(&project, snapshot_boundary::SNAPSHOT_BOUND + 1);
    let output = root.path().join("package");
    for arguments in [
        vec![
            "--format",
            "json",
            "check",
            "--project",
            project.to_str().unwrap(),
        ],
        vec![
            "--format",
            "json",
            "package",
            "--project",
            project.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
        ],
    ] {
        let refused = cli(&arguments);
        assert!(
            !refused.status.success(),
            "oversized project must be refused"
        );
        assert!(refused.stderr.is_empty());
        let error: Value = serde_json::from_slice(&refused.stdout).unwrap();
        assert_eq!(
            error["diagnostics"][0]["code"],
            "coordinator.definition.snapshot-limit"
        );
        assert!(error["diagnostics"][0]["suggestedAction"]
            .as_str()
            .unwrap()
            .contains("393216"));
        assert!(!output.exists());
    }
    snapshot_boundary::project_at_snapshot_size(&project, snapshot_boundary::SNAPSHOT_BOUND);
    assert!(cli(&["check", "--project", project.to_str().unwrap()])
        .status
        .success());
    let packaged = cli(&[
        "--format",
        "json",
        "package",
        "--project",
        project.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
    ]);
    assert!(
        packaged.status.success(),
        "{}",
        String::from_utf8_lossy(&packaged.stderr)
    );
    let report: Value = serde_json::from_slice(&packaged.stdout).unwrap();
    assert!(report["packageDigest"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    let bytes = fs::read_to_string(output.join("definition.json")).unwrap();
    assert_eq!(bytes.len(), snapshot_boundary::SNAPSHOT_BOUND);
    registry_coordinator::definition::Definition::from_snapshot(&bytes).unwrap();
}
