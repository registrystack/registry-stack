// SPDX-License-Identifier: Apache-2.0
//! The `registry-session` binary's offline `check` and its receipt
//! cross-check.

mod support;

use std::path::PathBuf;
use std::process::Command;

use serde_json::json;
use support::{Harness, CASEWORK_AUDIENCE, PERSON_AUDIENCE};

fn runtime_file(harness: &Harness) -> PathBuf {
    harness
        .directory
        .path()
        .canonicalize()
        .expect("canonical")
        .join("runtime.yaml")
}

fn receipt(directory: &std::path::Path, casework: &str) -> PathBuf {
    let path = directory.join("identity-receipt.json");
    std::fs::write(
        &path,
        json!({
            "personAudience": {"audience": PERSON_AUDIENCE, "products": ["breg", "documents"]},
            "sessionApps": {
                "citizen-app": {"products": ["breg"], "audiences": [PERSON_AUDIENCE]},
                "staff-app": {
                    "products": ["breg", "casework"],
                    "audiences": [PERSON_AUDIENCE, casework]
                }
            }
        })
        .to_string(),
    )
    .expect("write receipt");
    path
}

fn run(runtime: &std::path::Path, extra: &[&str]) -> (i32, String, String) {
    let output = Command::new(env!("CARGO_BIN_EXE_registry-session"))
        .arg("--runtime-config")
        .arg(runtime)
        .arg("check")
        .args(extra)
        .output()
        .expect("run the binary");
    (
        output.status.code().expect("exit code"),
        String::from_utf8_lossy(&output.stdout).into_owned(),
        String::from_utf8_lossy(&output.stderr).into_owned(),
    )
}

#[tokio::test]
async fn the_offline_check_passes_a_good_file_and_reports_json() {
    let harness = Harness::start().await;
    let (code, stdout, stderr) = run(&runtime_file(&harness), &["--format", "json"]);
    assert_eq!(code, 0, "{stderr}");
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("json report");
    assert_eq!(report["ok"], true);
    assert_eq!(report["kind"], "PlatformSessionCtlReport");
}

#[tokio::test]
async fn a_receipt_that_matches_passes_and_a_typo_fails_naming_the_kind() {
    let harness = Harness::start().await;
    let runtime = runtime_file(&harness);
    let directory = tempfile::tempdir().expect("directory");
    let good = receipt(directory.path(), CASEWORK_AUDIENCE);
    let (code, _, stderr) = run(
        &runtime,
        &["--identity-receipt", good.to_str().expect("utf-8")],
    );
    assert_eq!(code, 0, "{stderr}");

    let typo = receipt(directory.path(), "https://casework.example/apj");
    let (code, _, stderr) = run(
        &runtime,
        &["--identity-receipt", typo.to_str().expect("utf-8")],
    );
    assert_eq!(code, 1);
    assert!(stderr.contains("audience-set-mismatch"), "{stderr}");
    assert!(stderr.contains("staff"), "{stderr}");
}

#[tokio::test]
async fn an_unreadable_receipt_is_an_operational_failure() {
    let harness = Harness::start().await;
    let (code, _, _) = run(
        &runtime_file(&harness),
        &["--identity-receipt", "/nonexistent/receipt.json"],
    );
    assert_eq!(code, 3);
}

#[tokio::test]
async fn the_check_reports_a_refused_file_without_serving() {
    let harness = Harness::start().await;
    let broken = harness
        .directory
        .path()
        .canonicalize()
        .expect("canonical")
        .join("broken.yaml");
    std::fs::write(
        &broken,
        "apiVersion: nope\nkind: PlatformSessionRuntimeConfig\n",
    )
    .expect("write");
    let (code, _, stderr) = run(&broken, &[]);
    assert_eq!(code, 1);
    assert!(stderr.contains("refused"), "{stderr}");
}
