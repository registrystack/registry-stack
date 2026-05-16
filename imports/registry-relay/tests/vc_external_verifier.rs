// SPDX-License-Identifier: Apache-2.0
//! Operator-facing external VC verifier coverage.
//!
//! These tests exercise the same Node script an operator can run from a
//! shell. The fixture corpus is static and signed outside the
//! `registry_relay` signer code, so it protects the public VC-JWT wire
//! contract from drifting around implementation internals.

use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Output};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use serde_json::Value;
use tempfile::NamedTempFile;

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

struct VcFixture {
    dir: &'static str,
    issuer: &'static str,
    claim_type: &'static str,
    schema_id: &'static str,
    schema_path: &'static str,
}

const FIXTURES: &[VcFixture] = &[
    VcFixture {
        dir: "verify-result-v1",
        issuer: "did:web:fixture.example",
        claim_type: "VerifyResult",
        schema_id: "https://fixture.example/schemas/verify-result/v1.json",
        schema_path: "tests/fixtures/vc/verify-result-v1/schema.json",
    },
    VcFixture {
        dir: "aggregate-result-v1",
        issuer: "did:web:aggregate.fixture.example",
        claim_type: "AggregateResult",
        schema_id: "https://schemas.registry-relay.org/aggregate-result/v1.json",
        schema_path: "resources/schemas/aggregate-result/v1.json",
    },
    VcFixture {
        dir: "entity-record-v1",
        issuer: "did:web:entity.fixture.example",
        claim_type: "EntityRecord",
        schema_id: "https://schemas.registry-relay.org/entity-record/v1.json",
        schema_path: "resources/schemas/entity-record/v1.json",
    },
];

fn fixture_path(fixture: &VcFixture) -> PathBuf {
    repo_root().join("tests/fixtures/vc").join(fixture.dir)
}

fn verifier_output(extra_args: &[&str]) -> Output {
    let script = repo_root().join("scripts/verify_vc_jwt.mjs");
    Command::new("node")
        .arg(script)
        .args(extra_args)
        .output()
        .expect("node verifier runs")
}

fn fixture_args(fixture: &VcFixture) -> Vec<String> {
    let fixture_path = fixture_path(fixture);
    vec![
        "--jwt-file".to_string(),
        fixture_path.join("credential.jwt").display().to_string(),
        "--did-document".to_string(),
        fixture_path.join("did.json").display().to_string(),
        "--issuer".to_string(),
        fixture.issuer.to_string(),
        "--claim-type".to_string(),
        fixture.claim_type.to_string(),
        "--schema-id".to_string(),
        fixture.schema_id.to_string(),
        "--schema".to_string(),
        repo_root().join(fixture.schema_path).display().to_string(),
        "--now".to_string(),
        "2026-05-16T09:31:00Z".to_string(),
        "--quiet".to_string(),
    ]
}

fn run_with_owned_args(args: &[String]) -> Output {
    let borrowed: Vec<&str> = args.iter().map(String::as_str).collect();
    verifier_output(&borrowed)
}

fn replace_arg(args: &mut [String], flag: &str, value: impl Into<String>) {
    let index = args
        .iter()
        .position(|arg| arg == flag)
        .unwrap_or_else(|| panic!("{flag} arg"))
        + 1;
    args[index] = value.into();
}

fn remove_arg(args: &mut Vec<String>, flag: &str) {
    let index = args
        .iter()
        .position(|arg| arg == flag)
        .unwrap_or_else(|| panic!("{flag} arg"));
    args.drain(index..=index + 1);
}

#[test]
fn fixture_payloads_match_decoded_compact_vc_jwts() {
    for fixture in FIXTURES {
        let fixture_path = fixture_path(fixture);
        let jws =
            std::fs::read_to_string(fixture_path.join("credential.jwt")).expect("fixture jwt");
        let parts: Vec<&str> = jws.trim().split('.').collect();
        assert_eq!(parts.len(), 3, "{} compact fixture shape", fixture.dir);
        let decoded_payload_bytes = URL_SAFE_NO_PAD
            .decode(parts[1])
            .expect("payload is base64url");
        let decoded_payload: Value =
            serde_json::from_slice(&decoded_payload_bytes).expect("payload json");
        let stored_payload: Value = serde_json::from_str(
            &std::fs::read_to_string(fixture_path.join("payload.json")).unwrap(),
        )
        .expect("stored payload json");
        assert_eq!(decoded_payload, stored_payload, "{}", fixture.dir);
    }
}

#[test]
fn node_verifier_accepts_golden_fixtures() {
    for fixture in FIXTURES {
        let args = fixture_args(fixture);
        let output = run_with_owned_args(&args);
        assert!(
            output.status.success(),
            "{} verifier failed\nstdout:\n{}\nstderr:\n{}",
            fixture.dir,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
    }
}

#[test]
fn node_verifier_accepts_golden_fixture_against_published_verify_schema() {
    let mut args = fixture_args(&FIXTURES[0]);
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
    let mut args = fixture_args(&FIXTURES[0]);
    replace_arg(&mut args, "--claim-type", "AggregateResult");
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

#[test]
fn node_verifier_rejects_unexpected_schema_id() {
    let mut args = fixture_args(&FIXTURES[1]);
    replace_arg(
        &mut args,
        "--schema-id",
        "https://schemas.registry-relay.org/entity-record/v1.json",
    );
    let output = run_with_owned_args(&args);
    assert!(
        !output.status.success(),
        "verifier must fail for wrong schema id"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(
            "credentialSchema.id must be https://schemas.registry-relay.org/entity-record/v1.json"
        ),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn node_verifier_rejects_tampered_signature() {
    let fixture = &FIXTURES[0];
    let fixture_path = fixture_path(fixture);
    let mut args = fixture_args(fixture);
    let jws = std::fs::read_to_string(fixture_path.join("credential.jwt")).expect("fixture jwt");
    let mut parts: Vec<String> = jws.trim().split('.').map(str::to_string).collect();
    assert_eq!(parts.len(), 3, "compact fixture shape");
    let last = parts[2].pop().expect("signature is non-empty");
    parts[2].push(if last == 'A' { 'B' } else { 'A' });
    let tampered = parts.join(".");
    remove_arg(&mut args, "--jwt-file");
    args.push("--jwt".to_string());
    args.push(tampered);

    let output = run_with_owned_args(&args);
    assert!(
        !output.status.success(),
        "verifier must fail for a tampered signature"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("JWS signature did not verify"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn node_verifier_rejects_expired_credential() {
    let mut args = fixture_args(&FIXTURES[0]);
    replace_arg(&mut args, "--now", "2026-05-16T09:35:00Z");
    let output = run_with_owned_args(&args);
    assert!(
        !output.status.success(),
        "verifier must fail once now reaches exp"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("credential expired at exp"),
        "unexpected stderr: {stderr}"
    );
}

#[test]
fn node_verifier_rejects_private_key_material_in_did_public_jwk() {
    let fixture = &FIXTURES[0];
    let fixture_path = fixture_path(fixture);
    let mut did: Value =
        serde_json::from_str(&std::fs::read_to_string(fixture_path.join("did.json")).unwrap())
            .expect("did fixture json");
    did["verificationMethod"][0]["publicKeyJwk"]["d"] =
        Value::String("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".to_string());

    let mut did_file = NamedTempFile::new().expect("did temp file");
    write!(
        did_file,
        "{}",
        serde_json::to_string_pretty(&did).expect("did serializes")
    )
    .expect("did temp write");

    let mut args = fixture_args(fixture);
    replace_arg(
        &mut args,
        "--did-document",
        did_file.path().display().to_string(),
    );
    let output = run_with_owned_args(&args);
    assert!(
        !output.status.success(),
        "verifier must fail when DID publicKeyJwk leaks d"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("must not contain private parameter d"),
        "unexpected stderr: {stderr}"
    );
}
