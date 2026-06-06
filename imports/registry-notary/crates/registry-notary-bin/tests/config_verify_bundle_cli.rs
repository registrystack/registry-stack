// SPDX-License-Identifier: Apache-2.0
//! Binary-level coverage for governed configuration bundle verification.

use std::collections::BTreeSet;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::process::Command;

use chrono::Utc;
use registry_platform_config::sha256_uri;
use registry_platform_ops::internal_config_hash;
use serde_json::{json, Value};
use tempfile::TempDir;
use tough::editor::signed::PathExists;
use tough::editor::RepositoryEditor;
use tough::key_source::{KeySource, LocalKeySource};
use tough::schema::Target;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TEST_ISSUER_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA"}"#;
const TEST_TOKEN_HASH: &str =
    "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51";
const TEST_AUDIT_SECRET: &str = "notary-cli-audit-secret-32-bytes-min";
const TUF_TARGETS_SIGNER_KID: &str =
    "8ec3a843a0f9328c863cac4046ab1cacbbc67888476ac7acf73d9bcd9a223ada";

struct SignedConfigFixture {
    root_path: PathBuf,
    metadata_dir: PathBuf,
    targets_dir: PathBuf,
    datastore_dir: PathBuf,
    target_name: String,
}

fn tough_fixture(name: &str) -> PathBuf {
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")))
        .expect("CARGO_HOME or HOME is set");
    let src_root = cargo_home.join("registry/src");
    let registry = std::fs::read_dir(&src_root)
        .expect("cargo registry src exists")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.join("tough-0.22.0/tests/data").is_dir())
        .expect("tough-0.22.0 source fixture directory exists");
    registry.join("tough-0.22.0/tests/data").join(name)
}

fn config_yaml(tmp: &TempDir, signer_kid: &str) -> String {
    let root_sha = sha256_uri(
        &std::fs::read(tough_fixture("simple-rsa").join("root.json"))
            .expect("trusted TUF root fixture reads"),
    );
    let allowed_change_classes = BTreeSet::from(["public_metadata"]);
    let change_classes = allowed_change_classes
        .iter()
        .map(|class| format!("            - {class}"))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        r#"
instance:
  id: notary-cli
  environment: development
server:
  bind: 127.0.0.1:0
  admin_listener:
    mode: dedicated
    bind: 127.0.0.1:1
auth:
  mode: api_key
  api_keys:
    - id: test-key
      fingerprint:
        provider: env
        name: TEST_TOKEN_HASH
        commitment: sha256:a185ffbb208d5b11fc66f149bd880882de96256b0dfe5357a78b78ed13c17fed
audit:
  sink: stdout
  hash_secret_env: TEST_AUDIT_SECRET
evidence:
  enabled: true
  signing_keys:
    issuer-key:
      provider: local_jwk_env
      private_jwk_env: ISSUER_KEY
      alg: EdDSA
      kid: did:web:issuer.example#key-1
      status: active
config_trust:
  antirollback_state_path: "{}"
  local_approval_state_path: "{}"
  accepted_roots:
    - root_id: ops-root
      production: false
      tuf_root_sha256: "{}"
      high_risk_change_classes: []
      signers:
        {}:
          kid: {}
          enabled: true
      roles:
        - name: config-admin
          threshold: 1
          signer_kids:
            - {}
          allowed_change_classes:
{}
"#,
        tmp.path().join("antirollback.json").display(),
        tmp.path().join("local-approvals.json").display(),
        root_sha,
        signer_kid,
        signer_kid,
        signer_kid,
        change_classes
    )
}

fn write_config(tmp: &TempDir, signer_kid: &str) -> PathBuf {
    let config_path = tmp.path().join("current.yaml");
    std::fs::write(&config_path, config_yaml(tmp, signer_kid)).expect("config writes");
    config_path
}

async fn write_signed_notary_config_tuf_fixture(
    tmp: &TempDir,
    current_config_hash: &str,
    config_yaml: &str,
) -> SignedConfigFixture {
    let repo_dir = tmp.path().join("signed-notary-config");
    let source_dir = repo_dir.join("source");
    let metadata_dir = repo_dir.join("metadata");
    let targets_dir = repo_dir.join("targets");
    let datastore_dir = repo_dir.join("datastore");
    std::fs::create_dir_all(&source_dir).expect("source dir");
    std::fs::create_dir_all(&datastore_dir).expect("datastore dir");
    let target_name = "registry-notary.yaml";
    let target_path = source_dir.join(target_name);
    std::fs::write(&target_path, config_yaml).expect("target config writes");

    let mut target = Target::from_path(&target_path)
        .await
        .expect("target metadata builds");
    let custom = json!({
        "product": "registry-notary",
        "instance_id": "notary-cli",
        "environment": "development",
        "stream_id": "notary-test-stream",
        "bundle_id": "notary-test-bundle",
        "sequence": 1,
        "previous_config_hash": current_config_hash,
        "config_hash": sha256_uri(config_yaml.as_bytes()),
        "change_classes": ["public_metadata"],
        "signer_kids": [TUF_TARGETS_SIGNER_KID],
        "apply_policy": "restart_required"
    });
    target.custom = custom
        .as_object()
        .expect("custom target metadata is an object")
        .iter()
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();

    let root_path = tough_fixture("simple-rsa").join("root.json");
    let key_path = tough_fixture("snakeoil.pem");
    let keys: Vec<Box<dyn KeySource>> = vec![Box::new(LocalKeySource { path: key_path })];
    let version = NonZeroU64::new(1).expect("nonzero version");
    let mut editor = RepositoryEditor::new(&root_path)
        .await
        .expect("repository editor builds");
    editor
        .targets_expires(Utc::now() + chrono::Duration::days(13))
        .expect("targets expiration");
    editor.targets_version(version).expect("targets version");
    editor.snapshot_expires(Utc::now() + chrono::Duration::days(21));
    editor.snapshot_version(version);
    editor.timestamp_expires(Utc::now() + chrono::Duration::days(3));
    editor.timestamp_version(version);
    editor
        .add_target(target_name, target)
        .expect("target added");
    let signed_repo = editor.sign(&keys).await.expect("repository signs");
    signed_repo
        .write(&metadata_dir)
        .await
        .expect("metadata writes");
    signed_repo
        .copy_targets(&source_dir, &targets_dir, PathExists::Fail)
        .await
        .expect("targets write");

    SignedConfigFixture {
        root_path: metadata_dir.join("1.root.json"),
        metadata_dir,
        targets_dir,
        datastore_dir,
        target_name: target_name.to_string(),
    }
}

async fn serve_signed_tuf_fixture(signed: &SignedConfigFixture) -> MockServer {
    let server = MockServer::start().await;
    mount_directory_files(&server, "/metadata", &signed.metadata_dir).await;
    mount_directory_files(&server, "/targets", &signed.targets_dir).await;
    Mock::given(method("GET"))
        .and(path("/metadata/2.root.json"))
        .respond_with(ResponseTemplate::new(404))
        .mount(&server)
        .await;
    server
}

async fn mount_directory_files(server: &MockServer, url_prefix: &str, dir: &Path) {
    for entry in std::fs::read_dir(dir).expect("directory reads") {
        let entry = entry.expect("directory entry reads");
        let path_on_disk = entry.path();
        if !path_on_disk.is_file() {
            continue;
        }
        let filename = path_on_disk
            .file_name()
            .and_then(|name| name.to_str())
            .expect("fixture filename is UTF-8");
        Mock::given(method("GET"))
            .and(path(format!("{url_prefix}/{filename}")))
            .respond_with(
                ResponseTemplate::new(200).set_body_bytes(
                    std::fs::read(path_on_disk).expect("generated repo file reads"),
                ),
            )
            .mount(server)
            .await;
    }
}

fn verify_bundle_command(config_path: &Path, signed: &SignedConfigFixture) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_registry-notary"));
    command
        .arg("--config")
        .arg(config_path)
        .arg("config")
        .arg("verify-bundle")
        .arg("--root-path")
        .arg(&signed.root_path)
        .arg("--metadata-dir")
        .arg(&signed.metadata_dir)
        .arg("--targets-dir")
        .arg(&signed.targets_dir)
        .arg("--datastore-dir")
        .arg(&signed.datastore_dir)
        .arg("--target-name")
        .arg(&signed.target_name)
        .env("ISSUER_KEY", TEST_ISSUER_JWK)
        .env("TEST_TOKEN_HASH", TEST_TOKEN_HASH)
        .env("TEST_AUDIT_SECRET", TEST_AUDIT_SECRET);
    command
}

fn remote_verify_bundle_command(
    config_path: &Path,
    signed: &SignedConfigFixture,
    server: &MockServer,
) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_registry-notary"));
    command
        .arg("--config")
        .arg(config_path)
        .arg("config")
        .arg("verify-bundle")
        .arg("--root-path")
        .arg(&signed.root_path)
        .arg("--metadata-base-url")
        .arg(format!("{}/metadata", server.uri()))
        .arg("--targets-base-url")
        .arg(format!("{}/targets", server.uri()))
        .arg("--datastore-dir")
        .arg(&signed.datastore_dir)
        .arg("--target-name")
        .arg(&signed.target_name)
        .arg("--allow-dev-insecure-fetch-urls")
        .env("ISSUER_KEY", TEST_ISSUER_JWK)
        .env("TEST_TOKEN_HASH", TEST_TOKEN_HASH)
        .env("TEST_AUDIT_SECRET", TEST_AUDIT_SECRET);
    command
}

#[tokio::test]
async fn config_verify_bundle_cli_reports_verified_signed_bundle() {
    let tmp = TempDir::new().expect("tempdir");
    let current_config = write_config(&tmp, TUF_TARGETS_SIGNER_KID);
    let candidate_yaml = config_yaml(&tmp, TUF_TARGETS_SIGNER_KID);
    let current_hash = internal_config_hash(std::fs::read(&current_config).unwrap().as_slice());
    let signed = write_signed_notary_config_tuf_fixture(&tmp, &current_hash, &candidate_yaml).await;

    let output = verify_bundle_command(&current_config, &signed)
        .output()
        .expect("verify-bundle command runs");

    assert!(
        output.status.success(),
        "verify-bundle failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value =
        serde_json::from_slice(&output.stdout).expect("verify-bundle emits JSON report");
    assert_eq!(report["result"], "verified");
    assert_eq!(report["source"], "signed_bundle_file");
    assert_eq!(report["bundle_id"], "notary-test-bundle");
    assert_eq!(report["stream_id"], "notary-test-stream");
    assert_eq!(report["sequence"], 1);
    assert_eq!(report["target_name"], signed.target_name);
    assert_eq!(report["change_classes"], json!(["public_metadata"]));
    assert_eq!(report["signer_kids"], json!([TUF_TARGETS_SIGNER_KID]));
    assert_eq!(
        report["config_hash"],
        internal_config_hash(candidate_yaml.as_bytes())
    );
}

#[tokio::test]
async fn config_verify_bundle_cli_reports_verified_remote_signed_bundle() {
    let tmp = TempDir::new().expect("tempdir");
    let current_config = write_config(&tmp, TUF_TARGETS_SIGNER_KID);
    let candidate_yaml = config_yaml(&tmp, TUF_TARGETS_SIGNER_KID);
    let current_hash = internal_config_hash(std::fs::read(&current_config).unwrap().as_slice());
    let signed = write_signed_notary_config_tuf_fixture(&tmp, &current_hash, &candidate_yaml).await;
    let server = serve_signed_tuf_fixture(&signed).await;

    let output = remote_verify_bundle_command(&current_config, &signed, &server)
        .output()
        .expect("remote verify-bundle command runs");

    assert!(
        output.status.success(),
        "remote verify-bundle failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value =
        serde_json::from_slice(&output.stdout).expect("verify-bundle emits JSON report");
    assert_eq!(report["result"], "verified");
    assert_eq!(report["source"], "signed_bundle_endpoint");
    assert_eq!(report["bundle_id"], "notary-test-bundle");
    assert_eq!(report["stream_id"], "notary-test-stream");
    assert_eq!(report["sequence"], 1);
    assert_eq!(report["target_name"], signed.target_name);
    assert_eq!(report["change_classes"], json!(["public_metadata"]));
    assert_eq!(report["signer_kids"], json!([TUF_TARGETS_SIGNER_KID]));
    assert_eq!(
        report["config_hash"],
        internal_config_hash(candidate_yaml.as_bytes())
    );
    assert!(!tmp.path().join("antirollback.json").exists());
    assert!(!tmp.path().join("local-approvals.json").exists());
}

#[tokio::test]
async fn config_verify_bundle_cli_rejects_ambiguous_local_and_remote_tuf_source() {
    let tmp = TempDir::new().expect("tempdir");
    let current_config = write_config(&tmp, TUF_TARGETS_SIGNER_KID);
    let candidate_yaml = config_yaml(&tmp, TUF_TARGETS_SIGNER_KID);
    let current_hash = internal_config_hash(std::fs::read(&current_config).unwrap().as_slice());
    let signed = write_signed_notary_config_tuf_fixture(&tmp, &current_hash, &candidate_yaml).await;
    let mut command = verify_bundle_command(&current_config, &signed);
    command
        .arg("--metadata-base-url")
        .arg("https://config.example.gov/metadata")
        .arg("--targets-base-url")
        .arg("https://config.example.gov/targets");

    let output = command.output().expect("verify-bundle command runs");

    assert!(
        !output.status.success(),
        "ambiguous verify-bundle unexpectedly succeeded: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("TUF request must choose exactly one local or remote source shape"),
        "stderr did not explain ambiguous TUF source:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!tmp.path().join("antirollback.json").exists());
}

#[tokio::test]
async fn config_verify_bundle_cli_rejects_unauthorized_local_trust_root() {
    let tmp = TempDir::new().expect("tempdir");
    let current_config = write_config(&tmp, "unauthorized-signer");
    let candidate_yaml = config_yaml(&tmp, TUF_TARGETS_SIGNER_KID);
    let current_hash = internal_config_hash(std::fs::read(&current_config).unwrap().as_slice());
    let signed = write_signed_notary_config_tuf_fixture(&tmp, &current_hash, &candidate_yaml).await;

    let output = verify_bundle_command(&current_config, &signed)
        .output()
        .expect("verify-bundle command runs");

    assert!(
        !output.status.success(),
        "verify-bundle unexpectedly succeeded: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("not authorized"),
        "stderr did not explain authorization failure:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
