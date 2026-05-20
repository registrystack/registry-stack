// SPDX-License-Identifier: Apache-2.0

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn bin() -> &'static str {
    env!("CARGO_BIN_EXE_registry-metadata")
}

fn workspace_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("workspace root")
        .to_path_buf()
}

fn temp_dir(name: &str) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_nanos();
    let path = std::env::temp_dir().join(format!("registry-metadata-{name}-{nonce}"));
    fs::create_dir_all(&path).expect("temp dir");
    path
}

#[test]
fn render_rejects_undeclared_dcat_profile() {
    let manifest = workspace_root().join("profiles/example-person-schema/fixtures/metadata.yaml");
    let output = Command::new(bin())
        .args([
            "render",
            manifest.to_str().unwrap(),
            "--format",
            "dcat",
            "--profile",
            "bregdcat-ap",
        ])
        .output()
        .expect("run cli");

    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("metadata.manifest.unsupported_application_profile"));
}

#[test]
fn validate_reports_stable_manifest_error_codes() {
    let dir = temp_dir("validate-errors");
    let unsupported = dir.join("unsupported.yaml");
    fs::write(
        &unsupported,
        r#"
schema_version: registry-metadata/v0
catalog:
  id: demo
  base_url: https://metadata.example.test/
  title: Demo
  publisher:
    name: Publisher
datasets: []
"#,
    )
    .expect("write unsupported manifest");
    let output = Command::new(bin())
        .args(["validate", unsupported.to_str().unwrap()])
        .output()
        .expect("run cli");
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("metadata.manifest.version_unsupported"));

    let invalid = dir.join("invalid.yaml");
    fs::write(
        &invalid,
        r#"
schema_version: registry-metadata/v1
catalog:
  id: demo
  base_url: metadata.example.test
  title: Demo
  publisher:
    name: Publisher
datasets: []
"#,
    )
    .expect("write invalid manifest");
    let output = Command::new(bin())
        .args(["validate", invalid.to_str().unwrap()])
        .output()
        .expect("run cli");
    assert!(!output.status.success());
    let stderr = String::from_utf8(output.stderr).expect("stderr utf8");
    assert!(stderr.contains("metadata.manifest.validation_failed"));
    assert!(stderr.contains("catalog.base_url"));
}

#[test]
fn publish_writes_every_indexed_artifact_without_undeclared_profiles() {
    let manifest = workspace_root().join("profiles/example-person-schema/fixtures/metadata.yaml");
    let out = temp_dir("publish-example-person-schema");
    let output = Command::new(bin())
        .args([
            "publish",
            manifest.to_str().unwrap(),
            "--out",
            out.to_str().unwrap(),
        ])
        .output()
        .expect("run cli");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!out.join("dcat.bregdcat-ap.jsonld").exists());

    let index: serde_json::Value =
        serde_json::from_slice(&fs::read(out.join("index.json")).expect("index reads"))
            .expect("index json");
    assert_eq!(index["dcat_profiles"], serde_json::json!([]));
    assert_index_urls_exist(&out, &index);
}

#[test]
fn validate_profiles_checks_descriptors_and_fixtures() {
    let profiles = workspace_root().join("profiles");
    let output = Command::new(bin())
        .args(["validate-profiles", profiles.to_str().unwrap()])
        .output()
        .expect("run cli");

    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8(output.stdout).expect("stdout utf8");
    assert!(stdout.contains("validated 4 profile descriptors and fixtures"));
}

fn assert_index_urls_exist(out: &Path, index: &serde_json::Value) {
    for key in ["manifest", "catalog", "dcat", "shacl"] {
        assert_url_exists(out, index[key].as_str().expect("url"));
    }
    for entry in index["schemas"].as_array().expect("schemas") {
        assert_url_exists(out, entry["url"].as_str().expect("schema url"));
    }
    for entry in index["profiles"].as_array().expect("profiles") {
        assert_url_exists(out, entry["url"].as_str().expect("profile url"));
    }
    for entry in index["dcat_profiles"].as_array().expect("dcat profiles") {
        assert_url_exists(out, entry["url"].as_str().expect("profile url"));
    }
}

fn assert_url_exists(out: &Path, url: &str) {
    let relative = url
        .strip_prefix("/metadata/")
        .unwrap_or_else(|| panic!("unexpected metadata URL: {url}"));
    assert!(
        out.join(relative).exists(),
        "missing indexed artifact: {url}"
    );
}
