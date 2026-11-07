// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use registry_adapter_job::cli::Cli;
#[cfg(all(feature = "direct-breg", feature = "signed-coordinator-event"))]
use std::path::PathBuf;
#[cfg(all(feature = "direct-breg", feature = "signed-coordinator-event"))]
use std::process::Command;

#[test]
fn dry_run_loop_is_rejected_before_opening_the_store() {
    let error = Cli::try_parse_from([
        "adapter-job",
        "pass",
        "job.yaml",
        "--pack",
        "pack.yaml",
        "--runtime",
        "runtime.yaml",
        "--loop",
        "--dry-run",
    ])
    .err()
    .expect("a preview cannot advance the persistent loop schedule");
    assert_eq!(error.kind(), clap::error::ErrorKind::ArgumentConflict);
}

#[test]
fn pass_and_rescan_accept_explicit_workspace_artifacts() {
    for command in ["pass", "rescan"] {
        Cli::try_parse_from([
            "adapter-job",
            command,
            "job.yaml",
            "--pack",
            "pack.yaml",
            "--runtime",
            "runtime.yaml",
            "--profile",
            "profile.yaml",
            "--project",
            "project.yaml",
            "--dry-run",
        ])
        .unwrap_or_else(|error| panic!("{command} must accept separate artifacts: {error}"));
    }
}

#[test]
#[cfg(all(feature = "direct-breg", feature = "signed-coordinator-event"))]
fn check_compiles_the_maintained_job_examples_with_explicit_artifacts() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    for source in ["kobotoolbox", "odk-central"] {
        let example = root.join(format!("products/adapter/examples/{source}-job"));
        let output = Command::new(env!("CARGO_BIN_EXE_adapter-job"))
            .env("KOBO_TOKEN", "canary-token")
            .env("ODK_EMAIL", "canary@example.invalid")
            .env("ODK_PASSWORD", "canary-password")
            .arg("check")
            .arg(example.join("job.yaml"))
            .arg("--pack")
            .arg(root.join(format!("products/adapter/packs/{source}/pack.yaml")))
            .arg("--runtime")
            .arg(example.join("job-runtime.example.yaml"))
            .arg("--profile")
            .arg(example.join("profile.yaml"))
            .arg("--project")
            .arg(example.join("project.yaml"))
            .output()
            .expect("run adapter-job check");
        assert!(
            output.status.success(),
            "{source} check failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value =
            serde_json::from_slice(&output.stdout).expect("the check report is JSON");
        assert_eq!(report["ok"], true);
    }
}
