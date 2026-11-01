// SPDX-License-Identifier: Apache-2.0

use clap::Parser;
use registry_adapter_job::cli::Cli;
use std::path::PathBuf;
use std::process::Command;

#[path = "support/job_fixture.rs"]
mod job_fixture;

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
fn check_compiles_the_maintained_job_examples_with_explicit_artifacts() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    for source in ["kobotoolbox", "odk-central"] {
        let example = root.join(format!("products/adapter/examples/{source}-job"));
        let output = Command::new(env!("CARGO_BIN_EXE_adapter-job"))
            .env("KOBO_USERNAME", "canary-user")
            .env("KOBO_PASSWORD", "canary-password")
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

/// The host serves http-shaped sources only: a pack that declares a
/// file, sftp, or postgres endpoint is refused by the host itself, so a
/// build that unifies the engine's source features with another binary's
/// still never reads a file or a database from this executable.
#[tokio::test]
async fn check_refuses_a_pack_with_a_source_this_host_does_not_serve() {
    for component in ["file", "sftp", "postgres"] {
        let endpoint = format!(
            "  - id: dropbox\n    component: {component}\n    authentication:\n      type: none\n    attemptTimeoutMilliseconds: 10000\n    maximumResponseBytes: 65536\n"
        );
        let fixture = job_fixture::JobFixture::start_with_endpoints(
            job_fixture::PAGE_SCRIPT,
            vec![(200, job_fixture::reply_page())],
            job_fixture::Edits::Ordered,
            &endpoint,
        )
        .await;
        let output = tokio::task::spawn_blocking(move || {
            let output = Command::new(env!("CARGO_BIN_EXE_adapter-job"))
                .arg("check")
                .arg(&fixture.job)
                .arg("--pack")
                .arg(&fixture.pack)
                .arg("--runtime")
                .arg(&fixture.runtime)
                .output()
                .expect("run adapter-job check");
            drop(fixture);
            output
        })
        .await
        .expect("the check run joins");
        assert!(!output.status.success(), "a {component} endpoint refuses");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("adapter.job.component-unavailable at /endpoints/dropbox")
                && stderr.contains("this host serves no file, sftp, or postgres source"),
            "the host names the unserved {component} endpoint: {stderr}"
        );
    }
}
