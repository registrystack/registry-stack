//! `evidence-oid4vp check` as an operator runs it (CFG-CHECK-1): the
//! committed example passes, every refusal is reported in the shared
//! diagnostic shape, and the exit status tells a refused file from one that
//! could not be read.

use std::{
    path::{Path, PathBuf},
    process::{Command, Output},
};

use serde_json::Value;

/// The committed minimal deployment the platform registry names.
fn example() -> String {
    std::fs::read_to_string(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/evidence/examples/oid4vp-runtime/runtime.yaml"),
    )
    .expect("the committed example is readable")
}

fn canonical_tempdir() -> tempfile::TempDir {
    // The reader refuses a path through a symbolic link, and the system
    // temporary directory is one on some hosts.
    let base = std::env::temp_dir()
        .canonicalize()
        .expect("the temporary directory resolves");
    tempfile::tempdir_in(base).expect("a temporary directory")
}

fn write(text: &str) -> (tempfile::TempDir, PathBuf) {
    let root = canonical_tempdir();
    let path = root.path().join("runtime.yaml");
    std::fs::write(&path, text).expect("the runtime file is written");
    (root, path)
}

fn check(path: &Path, extra: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_evidence-oid4vp"))
        .arg("check")
        .arg("--runtime-config")
        .arg(path)
        .args(extra)
        .env_remove("EVIDENCE_OID4VP_CONFIG")
        .env_remove("EVIDENCE_OID4VP_RUNTIME_CONFIG")
        .output()
        .expect("the binary runs")
}

fn json(output: &Output) -> Value {
    let document: Value = serde_json::from_slice(&output.stdout)
        .expect("check --format json prints one JSON document");
    assert_eq!(
        document["apiVersion"],
        "id.registrystack.org/formats/evidence/ctl-report/v1alpha1"
    );
    assert_eq!(document["kind"], "EvidenceCtlReport");
    document
}

fn codes(document: &Value) -> Vec<String> {
    document["diagnostics"]
        .as_array()
        .expect("a diagnostics list")
        .iter()
        .map(|diagnostic| diagnostic["code"].as_str().unwrap().to_owned())
        .collect()
}

#[test]
fn the_committed_example_passes_in_both_formats() {
    let (_root, path) = write(&example());

    let output = check(&path, &["--format", "json"]);
    assert_eq!(output.status.code(), Some(0));
    let document = json(&output);
    assert_eq!(document["ok"], true);
    assert_eq!(document["command"], "check");
    assert_eq!(document["status"], "complete");
    assert_eq!(document["filesChecked"], 1);
    assert_eq!(document["diagnostics"], serde_json::json!([]));

    let output = check(&path, &[]);
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stdout.is_empty());
    assert_eq!(
        String::from_utf8(output.stderr).unwrap(),
        "0 errors, 0 warnings in 1 file\n"
    );
}

#[test]
fn a_refused_file_exits_one_with_positioned_diagnostics_that_repeat_no_value() {
    let text = example()
        .replace(
            "    signingKeyRef: secret:file/verifier-signing.jwk.json",
            "    signingKeyFile: /run/secrets/planted-marker.jwk",
        )
        .replace("  - id: national-id", "  - id: \"planted marker\"");
    let (_root, path) = write(&text);

    let output = check(&path, &["--format", "json"]);
    assert_eq!(output.status.code(), Some(1));
    let document = json(&output);
    assert_eq!(document["ok"], false);
    assert_eq!(document["status"], "domain-refusal");
    assert_eq!(document["filesChecked"], 1);
    let codes = codes(&document);
    assert!(!codes.is_empty(), "{codes:?}");
    for diagnostic in document["diagnostics"].as_array().unwrap() {
        assert!(diagnostic["source"]["line"].is_u64(), "{diagnostic}");
        assert!(diagnostic["suggestedAction"].is_string());
    }

    let output = check(&path, &[]);
    assert_eq!(output.status.code(), Some(1));
    let human = String::from_utf8(output.stderr).unwrap();
    assert!(human.contains("error["), "{human}");
    let machine = String::from_utf8(check(&path, &["--format", "json"]).stdout).unwrap();
    for stream in [&human, &machine] {
        assert!(
            !stream.contains("planted"),
            "a value was repeated: {stream}"
        );
    }
}

#[test]
fn a_file_that_cannot_be_read_exits_three() {
    let root = canonical_tempdir();
    let output = check(&root.path().join("absent.yaml"), &["--format", "json"]);
    assert_eq!(output.status.code(), Some(3));
    let document = json(&output);
    assert_eq!(document["ok"], false);
    assert_eq!(document["status"], "operational-failure");
    assert_eq!(document["filesChecked"], 0);
    assert_eq!(codes(&document), ["platform.runtime-config.unavailable"]);
}

#[test]
fn an_invalid_command_line_exits_two() {
    let output = Command::new(env!("CARGO_BIN_EXE_evidence-oid4vp"))
        .args(["check", "--format", "yaml"])
        .env_remove("EVIDENCE_OID4VP_CONFIG")
        .env_remove("EVIDENCE_OID4VP_RUNTIME_CONFIG")
        .output()
        .expect("the binary runs");
    assert_eq!(output.status.code(), Some(2));
}

#[test]
fn the_check_reads_no_secret_material() {
    // The example names a file secret under a root that does not exist on
    // this host; the check passes because it never resolves the reference.
    let (_root, path) = write(&example());
    assert!(!Path::new("/run/secrets/evidence-oid4vp/verifier-signing.jwk.json").exists());
    let output = check(&path, &["--format", "json"]);
    assert_eq!(output.status.code(), Some(0));
}

#[test]
fn only_the_runtime_config_environment_variable_selects_the_file() {
    let (_root, path) = write(&example());
    let output = Command::new(env!("CARGO_BIN_EXE_evidence-oid4vp"))
        .args(["check", "--format", "json"])
        .env_remove("EVIDENCE_OID4VP_CONFIG")
        .env_remove("EVIDENCE_OID4VP_RUNTIME_CONFIG")
        .env("EVIDENCE_OID4VP_RUNTIME_CONFIG", &path)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert_eq!(json(&output)["ok"], true);
    let output = Command::new(env!("CARGO_BIN_EXE_evidence-oid4vp"))
        .arg("check")
        .env_remove("EVIDENCE_OID4VP_RUNTIME_CONFIG")
        .env("EVIDENCE_OID4VP_CONFIG", &path)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
}

/// The first policy of the committed example, with its `claims` member
/// replaced by `replacement` (empty to drop the member).
fn with_first_claims(replacement: &str) -> String {
    let claims = "        claims:\n          - path: [given_name]\n          - path: [family_name]\n          - path: [birthdate]\n";
    assert!(example().contains(claims));
    example().replacen(claims, replacement, 1)
}

#[test]
fn a_credential_query_without_claims_passes() {
    let (_root, path) = write(&with_first_claims(""));
    let output = check(&path, &["--format", "json"]);
    assert_eq!(output.status.code(), Some(0), "{output:?}");
    let document = json(&output);
    assert_eq!(document["ok"], true);
    assert_eq!(document["diagnostics"], serde_json::json!([]));
}

#[test]
fn an_explicitly_empty_claims_list_is_refused() {
    let (_root, path) = write(&with_first_claims("        claims: []\n"));
    let output = check(&path, &["--format", "json"]);
    assert_eq!(output.status.code(), Some(1), "{output:?}");
    assert_eq!(json(&output)["ok"], false);
}
