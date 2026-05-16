// SPDX-License-Identifier: Apache-2.0
//! Operator-facing external VC verifier coverage.
//!
//! These tests exercise the same Node script an operator can run from a
//! shell. The fixture corpus is static and signed outside the
//! `registry_relay` signer code, so it protects the public VC-JWT wire
//! contract from drifting around implementation internals.

use std::path::PathBuf;
use std::process::{Command, Output};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde_json::Value;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn fixture_dir() -> PathBuf {
    repo_root().join("tests/fixtures/vc/verify-result-v1")
}

fn verifier_output(extra_args: &[&str]) -> Output {
    let script = repo_root().join("scripts/verify_vc_jwt.mjs");
    Command::new("node")
        .arg(script)
        .args(extra_args)
        .output()
        .expect("node verifier runs")
}

fn golden_args() -> Vec<String> {
    let fixture = fixture_dir();
    vec![
        "--jwt-file".to_string(),
        fixture.join("credential.jwt").display().to_string(),
        "--did-document".to_string(),
        fixture.join("did.json").display().to_string(),
        "--issuer".to_string(),
        "did:web:fixture.example".to_string(),
        "--claim-type".to_string(),
        "VerifyResult".to_string(),
        "--schema-id".to_string(),
        "https://fixture.example/schemas/verify-result/v1.json".to_string(),
        "--schema".to_string(),
        fixture.join("schema.json").display().to_string(),
        "--now".to_string(),
        "2026-05-16T09:31:00Z".to_string(),
        "--quiet".to_string(),
    ]
}

fn run_with_owned_args(args: &[String]) -> Output {
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    verifier_output(&borrowed)
}

#[test]
fn fixture_payload_matches_decoded_compact_vc_jwt() {
    let fixture = fixture_dir();
    let jws = std::fs::read_to_string(fixture.join("credential.jwt")).expect("fixture jwt");
    let parts: Vec<&str> = jws.trim().split('.').collect();
    assert_eq!(parts.len(), 3, "compact fixture shape");
    let decoded_payload_bytes = URL_SAFE_NO_PAD
        .decode(parts[1])
        .expect("payload is base64url");
    let decoded_payload: Value =
        serde_json::from_slice(&decoded_payload_bytes).expect("payload json");
    let stored_payload: Value =
        serde_json::from_str(&std::fs::read_to_string(fixture.join("payload.json")).unwrap())
            .expect("stored payload json");
    assert_eq!(decoded_payload, stored_payload);
}

#[test]
fn node_verifier_accepts_golden_verify_result_fixture() {
    let args = golden_args();
    let output = run_with_owned_args(&args);
    assert!(
        output.status.success(),
        "verifier failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn node_verifier_accepts_golden_fixture_against_published_verify_schema() {
    let mut args = golden_args();
    let schema = args
        .iter()
        .position(|arg| arg == "--schema")
        .expect("schema arg")
        + 1;
    args[schema] = repo_root()
        .join("resources/schemas/verify-result/v1.json")
        .display()
        .to_string();
    let output = run_with_owned_args(&args);
    assert!(
        output.status.success(),
        "verifier failed against published schema\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn node_verifier_rejects_unexpected_claim_type() {
    let mut args = golden_args();
    let claim_type = args
        .iter()
        .position(|arg| arg == "--claim-type")
        .expect("claim type arg")
        + 1;
    args[claim_type] = "AggregateResult".to_string();
    let output = run_with_owned_args(&args);
    assert!(
        !output.status.success(),
        "verifier must fail for wrong claim type"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("payload type[1] must be AggregateResult"),
        "unexpected stderr: {stderr}"
    );
}
