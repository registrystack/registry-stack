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

const GATEWAY_FIXTURE: &str = include_str!("gateway/runtime.yaml");

/// Run `gateway envoy` on `runtime_text`, with the sentinel secrets in the
/// process environment and in the file provider's directory. Returns the exit
/// code, everything the command printed, and the content of every file it
/// wrote.
fn gateway_with_secrets(runtime_text: &str, extra: &[&str]) -> (i32, String, String) {
    let directory = tempfile::tempdir().expect("directory");
    let root = directory.path().canonicalize().expect("canonical");
    let secrets = root.join("secrets");
    std::fs::create_dir(&secrets).expect("secrets directory");
    for name in ["citizen-secret", "staff-secret"] {
        std::fs::write(secrets.join(name), "SENTINEL-FILE-SECRET").expect("secret file");
    }
    let runtime = root.join("runtime.yaml");
    std::fs::write(
        &runtime,
        runtime_text.replacen(
            "root: /run/secrets",
            &format!("root: {}", secrets.display()),
            1,
        ),
    )
    .expect("runtime file");
    let out = root.join("out");
    let output = Command::new(env!("CARGO_BIN_EXE_registry-session"))
        .arg("--runtime-config")
        .arg(&runtime)
        .args(["gateway", "envoy", "--out"])
        .arg(&out)
        .args(extra)
        .env("SESSION_AUDIT_KEY", "SENTINEL-ENVIRONMENT-SECRET")
        .env("SESSION_TEST_GATEWAY_HOST", "SENTINEL-ENVIRONMENT-HOST")
        .output()
        .expect("run the binary");
    let mut written = String::new();
    if let Ok(entries) = std::fs::read_dir(&out) {
        for entry in entries {
            written.push_str(
                &std::fs::read_to_string(entry.expect("entry").path()).expect("generated file"),
            );
        }
    }
    let printed = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (output.status.code().expect("exit code"), printed, written)
}

#[test]
fn the_gateway_fragments_carry_no_secret_the_process_can_reach() {
    let (code, printed, written) = gateway_with_secrets(GATEWAY_FIXTURE, &[]);
    assert_eq!(code, 0, "{printed}");
    assert!(
        written.contains("registry-session.check"),
        "files were written"
    );
    for text in [&printed, &written] {
        for needle in [
            "SENTINEL-FILE-SECRET",
            "SENTINEL-ENVIRONMENT-SECRET",
            "citizen-secret",
            "SESSION_AUDIT_KEY",
        ] {
            assert!(!text.contains(needle), "{needle} reached the output");
        }
    }
}

#[test]
fn an_environment_value_never_reaches_the_fragments_through_a_gateway_member() {
    let text = GATEWAY_FIXTURE.replacen(
        "host: registry-session",
        "host: ${SESSION_TEST_GATEWAY_HOST}",
        1,
    );
    let (code, printed, written) = gateway_with_secrets(&text, &[]);
    assert_eq!(code, 1, "{printed}");
    assert!(printed.contains("/gateway"), "{printed}");
    assert!(written.is_empty(), "nothing was written");
    assert!(!printed.contains("SENTINEL"), "{printed}");
}

#[test]
fn verifying_an_assembled_file_needs_the_runtime_file() {
    let output = Command::new(env!("CARGO_BIN_EXE_registry-session"))
        .args([
            "gateway",
            "envoy",
            "--verify-assembled",
            "/nonexistent/envoy.yaml",
        ])
        .output()
        .expect("run the binary");
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("--runtime-config is required"));
}
