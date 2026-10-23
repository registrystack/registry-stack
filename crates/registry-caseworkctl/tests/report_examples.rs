// SPDX-License-Identifier: Apache-2.0
//! Hold one committed CLI report to its producing command and validate other
//! current offline commands against the generated, command-tagged report
//! schema. A temporary copy excludes local `.casework` session state.
//!
//! Regenerate the representative report after an intentional change:
//! `CASEWORKCTL_WRITE_REPORT_EXAMPLE=1 cargo test -p registry-caseworkctl --test report_examples`.

use std::path::{Path, PathBuf};
use std::process::Command;

use jsonschema::{Draft, JSONSchema};
use serde_json::Value;

const STANDALONE: &str = "products/casework/examples/standalone-decision";
const ADVANCED: &str = "products/casework/examples/multi-stage-routing-clocks";

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repository root resolves")
}

fn stage_project(root: &Path, staging: &Path, project: &str) {
    fn copy(from: &Path, to: &Path) {
        std::fs::create_dir_all(to).expect("staging directory is created");
        for entry in std::fs::read_dir(from).expect("example directory reads") {
            let entry = entry.expect("example entry reads");
            if entry.file_name() == ".casework" {
                continue;
            }
            let target = to.join(entry.file_name());
            if entry.file_type().expect("entry type reads").is_dir() {
                copy(&entry.path(), &target);
            } else {
                std::fs::copy(entry.path(), target).expect("example file is copied");
            }
        }
    }
    copy(&root.join(project), &staging.join(project));
}

fn output(root: &Path, arguments: &[&str], expected_exit: i32) -> (Value, Vec<u8>) {
    let scratch = tempfile::tempdir().expect("temporary directory");
    for project in [STANDALONE, ADVANCED] {
        stage_project(root, scratch.path(), project);
    }
    let output = Command::new(env!("CARGO_BIN_EXE_caseworkctl"))
        .arg("--format")
        .arg("json")
        .args(arguments)
        .current_dir(scratch.path())
        .output()
        .expect("caseworkctl starts");
    assert_eq!(output.status.code(), Some(expected_exit), "{arguments:?}");
    assert!(
        output.stderr.is_empty(),
        "caseworkctl {arguments:?} wrote stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("report is JSON");
    (report, output.stdout)
}

#[test]
fn current_offline_reports_match_the_typed_contract_and_committed_check_example() {
    let root = repo_root();
    let schema: Value = serde_json::from_slice(
        &std::fs::read(root.join("products/casework/contracts/cli/report.schema.json"))
            .expect("generated report schema reads"),
    )
    .expect("generated report schema parses");
    let validator = JSONSchema::options()
        .with_draft(Draft::Draft202012)
        .compile(&schema)
        .expect("generated report schema compiles");
    let commands: [(&[&str], i32, &str); 6] = [
        (&["check", STANDALONE], 0, "check"),
        (&["explain", ADVANCED], 0, "explain"),
        (&["test", ADVANCED], 0, "test"),
        (&["lifecycle"], 0, "lifecycle"),
        (&["package", STANDALONE, "--dry-run"], 0, "package"),
        (&["--not-a-real-argument"], 2, "usage"),
    ];
    for (arguments, exit, command) in commands {
        let (report, bytes) = output(&root, arguments, exit);
        if let Err(errors) = validator.validate(&report) {
            panic!(
                "{command} report violates schema: {}\n{report}",
                errors
                    .map(|error| format!("{} at {}", error, error.instance_path))
                    .collect::<Vec<_>>()
                    .join("\n")
            );
        }
        assert_eq!(report["command"], command);
        assert_eq!(report["ok"], exit == 0);
        if exit == 0 {
            assert_eq!(report["status"], "complete");
            assert_eq!(report["diagnostics"].as_array().map(Vec::len), Some(0));
        } else {
            assert_eq!(report["status"], "usage-error");
            assert!(report["diagnostics"]
                .as_array()
                .is_some_and(|items| !items.is_empty()));
        }
        if command == "check" {
            let path = root.join("products/casework/examples/formats/reports/check-report.json");
            if std::env::var_os("CASEWORKCTL_WRITE_REPORT_EXAMPLE").is_some() {
                std::fs::write(&path, &bytes).expect("representative report is written");
            } else {
                assert_eq!(
                    bytes,
                    std::fs::read(&path).expect("committed check report reads"),
                    "committed check report drifted; regenerate and review it"
                );
            }
        }
    }
}

#[test]
fn advanced_calendar_revision_example_is_readable() {
    let path = repo_root().join(
        "products/casework/examples/multi-stage-routing-clocks/holiday-sets/office-holidays-7.yaml",
    );
    let bytes = std::fs::read(&path).expect("holiday revision example reads");
    let decoded =
        registry_casework_core::CaseworkHolidaySet::read(&path.display().to_string(), &bytes)
            .expect("holiday revision example is valid");
    let document = decoded.value.to_document();
    assert_eq!(document.holiday_set, "office-holidays");
    assert_eq!(document.revision, 7);
}

#[test]
fn explain_reports_policy_usage_and_project_level_resources() {
    let root = repo_root();
    let (report, _) = output(&root, &["explain", ADVANCED], 0);
    let data = &report["data"];
    let policy = &data["reviewPolicies"][0];

    assert_eq!(policy["label"], "Regional review");
    assert_eq!(policy["stages"][0]["label"], "Technical review");
    assert_eq!(policy["routing"][0]["label"], "Northern requests");
    assert_eq!(
        policy["usedQueues"],
        serde_json::json!(["northern-review", "overdue-review", "signoff", "triage"])
    );
    assert_eq!(
        policy["decidingProfiles"],
        serde_json::json!(["staff", "supervisor"])
    );
    assert_eq!(
        policy["eligibleDecidingProfiles"],
        serde_json::json!(["staff", "supervisor"])
    );
    assert_eq!(data["clocks"].as_array().map(Vec::len), Some(2));
    assert_eq!(data["calendars"].as_array().map(Vec::len), Some(1));
    assert_eq!(data["trustedProducers"].as_array().map(Vec::len), Some(1));

    let (unlabelled, _) = output(&root, &["explain", STANDALONE], 0);
    assert!(unlabelled["data"]["reviewPolicies"][0]
        .get("label")
        .is_none());
    assert!(unlabelled["data"]["reviewPolicies"][0]["stages"][0]
        .get("label")
        .is_none());
}
