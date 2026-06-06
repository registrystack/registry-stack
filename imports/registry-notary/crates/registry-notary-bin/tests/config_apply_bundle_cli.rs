// SPDX-License-Identifier: Apache-2.0
//! Binary-level coverage for governed configuration bundle apply.

use std::net::{SocketAddr, TcpListener};
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

use chrono::Utc;
use registry_platform_config::sha256_uri;
use registry_platform_ops::{
    internal_config_hash, AntiRollbackKey, AntiRollbackRecord, BreakGlassRateLimit,
    FileAntiRollbackStore, LocalOperatorApproval,
};
use serde_json::{json, Value};
use tempfile::TempDir;
use tough::editor::signed::PathExists;
use tough::editor::RepositoryEditor;
use tough::key_source::{KeySource, LocalKeySource};
use tough::schema::Target;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const TEST_ISSUER_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA"}"#;
const TEST_ADMIN_BEARER_HASH: &str =
    "sha256:10a4c7c9fc5206d6f36dc6944a81bb6f4a3cb0e25014ae3b12e6c3e52712292a";
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

struct LiveNotaryServer {
    child: Child,
    admin_url: String,
}

impl Drop for LiveNotaryServer {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

fn apply_bundle_command(server: &MockServer) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_registry-notary"));
    command
        .arg("config")
        .arg("apply-bundle")
        .arg("--admin-url")
        .arg(server.uri())
        .arg("--allow-insecure-admin-url")
        .arg("--admin-token-env")
        .arg("NOTARY_ADMIN_TOKEN_TEST")
        .arg("--root-path")
        .arg("/etc/registry-notary/tuf/metadata/1.root.json")
        .arg("--metadata-dir")
        .arg("/etc/registry-notary/tuf/metadata")
        .arg("--targets-dir")
        .arg("/etc/registry-notary/tuf/targets")
        .arg("--datastore-dir")
        .arg("/var/lib/registry-notary/tuf")
        .arg("--target-name")
        .arg("registry-notary.yaml")
        .arg("--local-approval-reference")
        .arg("ROOT-2026-Q2")
        .env("NOTARY_ADMIN_TOKEN_TEST", "operator-token")
        .env_remove("REGISTRY_NOTARY_CONFIG");
    command
}

fn live_apply_bundle_command(server: &LiveNotaryServer, signed: &SignedConfigFixture) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_registry-notary"));
    command
        .arg("config")
        .arg("apply-bundle")
        .arg("--admin-url")
        .arg(&server.admin_url)
        .arg("--allow-insecure-admin-url")
        .arg("--admin-token-env")
        .arg("NOTARY_ADMIN_TOKEN_TEST")
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
        .arg("--local-approval-reference")
        .arg("ROOT-2026-Q2")
        .env("NOTARY_ADMIN_TOKEN_TEST", "admin-token")
        .env_remove("REGISTRY_NOTARY_CONFIG");
    command
}

fn remote_live_apply_bundle_command(
    server: &LiveNotaryServer,
    signed: &SignedConfigFixture,
    remote: &MockServer,
) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_registry-notary"));
    command
        .arg("config")
        .arg("apply-bundle")
        .arg("--admin-url")
        .arg(&server.admin_url)
        .arg("--allow-insecure-admin-url")
        .arg("--admin-token-env")
        .arg("NOTARY_ADMIN_TOKEN_TEST")
        .arg("--root-path")
        .arg(&signed.root_path)
        .arg("--metadata-base-url")
        .arg(format!("{}/metadata", remote.uri()))
        .arg("--targets-base-url")
        .arg(format!("{}/targets", remote.uri()))
        .arg("--datastore-dir")
        .arg(&signed.datastore_dir)
        .arg("--target-name")
        .arg(&signed.target_name)
        .arg("--allow-dev-insecure-fetch-urls")
        .arg("--local-approval-reference")
        .arg("ROOT-2026-Q2")
        .env("NOTARY_ADMIN_TOKEN_TEST", "admin-token")
        .env_remove("REGISTRY_NOTARY_CONFIG");
    command
}

fn remote_apply_bundle_command(server: &MockServer) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_registry-notary"));
    command
        .arg("config")
        .arg("apply-bundle")
        .arg("--admin-url")
        .arg(server.uri())
        .arg("--allow-insecure-admin-url")
        .arg("--admin-token-env")
        .arg("NOTARY_ADMIN_TOKEN_TEST")
        .arg("--root-path")
        .arg("/etc/registry-notary/tuf/metadata/1.root.json")
        .arg("--metadata-base-url")
        .arg("https://config.example.gov/metadata")
        .arg("--targets-base-url")
        .arg("https://config.example.gov/targets")
        .arg("--datastore-dir")
        .arg("/var/lib/registry-notary/tuf")
        .arg("--target-name")
        .arg("registry-notary.yaml")
        .arg("--allow-dev-insecure-fetch-urls")
        .env("NOTARY_ADMIN_TOKEN_TEST", "operator-token")
        .env_remove("REGISTRY_NOTARY_CONFIG");
    command
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

fn root_transition_config_yaml(tmp: &TempDir, bind: SocketAddr, include_next_root: bool) -> String {
    let root_sha = sha256_uri(
        &std::fs::read(tough_fixture("simple-rsa").join("root.json"))
            .expect("trusted TUF root fixture reads"),
    );
    let next_root = if include_next_root {
        format!(
            r#"
    - root_id: ops-root-next
      production: false
      tuf_root_sha256: "{root_sha}"
      high_risk_change_classes: []
      signers:
        {TUF_TARGETS_SIGNER_KID}:
          kid: {TUF_TARGETS_SIGNER_KID}
          enabled: true
      roles:
        - name: config-admin
          threshold: 1
          signer_kids:
            - {TUF_TARGETS_SIGNER_KID}
          allowed_change_classes:
            - public_metadata
"#
        )
    } else {
        String::new()
    };
    format!(
        r#"
instance:
  id: notary-cli
  environment: development
server:
  bind: {bind}
auth:
  mode: api_key
  bearer_tokens:
    - id: admin-bearer
      hash_env: TEST_ADMIN_BEARER_HASH
      scopes: [registry_notary:admin, registry_notary:ops_read]
audit:
  sink: file
  path: "{}"
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
      tuf_root_sha256: "{root_sha}"
      high_risk_change_classes: []
      signers:
        {TUF_TARGETS_SIGNER_KID}:
          kid: {TUF_TARGETS_SIGNER_KID}
          enabled: true
      roles:
        - name: config-admin
          threshold: 1
          signer_kids:
            - {TUF_TARGETS_SIGNER_KID}
          allowed_change_classes:
            - root_transition
{next_root}"#,
        tmp.path().join("audit.jsonl").display(),
        tmp.path().join("antirollback.json").display(),
        tmp.path().join("local-approvals.json").display()
    )
}

fn write_current_config(tmp: &TempDir, config_yaml: &str) -> PathBuf {
    let config_path = tmp.path().join("current.yaml");
    std::fs::write(&config_path, config_yaml).expect("current config writes");
    config_path
}

async fn write_signed_root_transition_fixture(
    tmp: &TempDir,
    current_config_hash: &str,
    candidate_yaml: &str,
) -> SignedConfigFixture {
    let repo_dir = tmp.path().join("signed-root-transition");
    let source_dir = repo_dir.join("source");
    let metadata_dir = repo_dir.join("metadata");
    let targets_dir = repo_dir.join("targets");
    let datastore_dir = repo_dir.join("datastore");
    std::fs::create_dir_all(&source_dir).expect("source dir");
    std::fs::create_dir_all(&datastore_dir).expect("datastore dir");
    let target_name = "registry-notary.yaml";
    let target_path = source_dir.join(target_name);
    std::fs::write(&target_path, candidate_yaml).expect("target config writes");

    let mut target = Target::from_path(&target_path)
        .await
        .expect("target metadata builds");
    let custom = json!({
        "product": "registry-notary",
        "instance_id": "notary-cli",
        "environment": "development",
        "stream_id": "notary-test-stream",
        "bundle_id": "notary-root-transition-bundle",
        "sequence": 2,
        "previous_config_hash": current_config_hash,
        "config_hash": sha256_uri(candidate_yaml.as_bytes()),
        "change_classes": ["root_transition"],
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
    let version = NonZeroU64::new(2).expect("nonzero version");
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

fn initialize_antirollback_state(path: &Path, config_yaml: &str) {
    FileAntiRollbackStore::new(path)
        .initialize(AntiRollbackRecord {
            key: AntiRollbackKey {
                product: "registry-notary".to_string(),
                instance_id: "notary-cli".to_string(),
                environment: "development".to_string(),
                stream_id: "notary-test-stream".to_string(),
            },
            last_sequence: 1,
            last_config_hash: internal_config_hash(config_yaml.as_bytes()),
            root_version: None,
            break_glass: Default::default(),
            local_approvals: Default::default(),
        })
        .expect("anti-rollback state initializes");
}

fn write_local_approval_state(path: &Path, candidate_yaml: &str, previous_config_hash: &str) {
    let approval = LocalOperatorApproval {
        approved_by: "ops@example.test".to_string(),
        reason: "approve Notary root transition".to_string(),
        approval_reference: "ROOT-2026-Q2".to_string(),
        change_class: "root_transition".to_string(),
        config_hash: internal_config_hash(candidate_yaml.as_bytes()),
        previous_config_hash: Some(previous_config_hash.to_string()),
        expires_at_unix_seconds: Utc::now().timestamp() as u64 + 3600,
        rate_limit_identity: "registry-notary/notary-cli/development/notary-test-stream"
            .to_string(),
        rate_limit: BreakGlassRateLimit {
            max_accepted: 1,
            window_seconds: 3600,
        },
    };
    std::fs::write(
        path,
        serde_json::to_vec_pretty(&json!({ "approvals": [approval] }))
            .expect("local approval state serializes"),
    )
    .expect("local approval state writes");
}

fn config_audit_record(path: &Path, request_path: &str) -> Value {
    std::fs::read_to_string(path)
        .expect("audit jsonl is readable")
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("audit line is JSON"))
        .filter_map(|envelope| envelope.get("record").cloned())
        .find(|record| record["path"] == request_path && record.get("config").is_some())
        .unwrap_or_else(|| panic!("missing config audit record for {request_path}"))
}

fn allocate_loopback_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("ephemeral bind succeeds");
    listener.local_addr().expect("ephemeral local addr")
}

async fn start_live_notary_server(config_path: &Path, bind: SocketAddr) -> LiveNotaryServer {
    let mut child = Command::new(env!("CARGO_BIN_EXE_registry-notary"))
        .arg("--config")
        .arg(config_path)
        .env("ISSUER_KEY", TEST_ISSUER_JWK)
        .env("TEST_ADMIN_BEARER_HASH", TEST_ADMIN_BEARER_HASH)
        .env("TEST_AUDIT_SECRET", TEST_AUDIT_SECRET)
        .env_remove("REGISTRY_NOTARY_CONFIG")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("registry-notary server starts");
    let admin_url = format!("http://{bind}");
    let health_url = format!("{admin_url}/healthz");
    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("health client builds");
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().expect("server child status checks") {
            panic!("registry-notary server exited before readiness: {status}");
        }
        if client
            .get(&health_url)
            .send()
            .await
            .is_ok_and(|response| response.status().is_success())
        {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "registry-notary server did not become ready at {health_url}"
        );
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    LiveNotaryServer { child, admin_url }
}

#[tokio::test]
async fn config_apply_bundle_cli_posts_local_tuf_request_to_admin_apply() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/admin/v1/config/apply"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": "accepted",
            "bundle_id": "notary-test-bundle"
        })))
        .mount(&server)
        .await;

    let output = apply_bundle_command(&server)
        .output()
        .expect("apply-bundle command runs");

    assert!(
        output.status.success(),
        "apply-bundle failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let response: Value =
        serde_json::from_slice(&output.stdout).expect("apply-bundle emits server JSON");
    assert_eq!(response["result"], "accepted");
    assert_eq!(response["bundle_id"], "notary-test-bundle");

    let requests = server
        .received_requests()
        .await
        .expect("request recording is enabled");
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.method.as_str(), "POST");
    assert_eq!(request.url.path(), "/admin/v1/config/apply");
    assert_eq!(
        request
            .headers
            .get("authorization")
            .expect("authorization header is present")
            .to_str()
            .expect("authorization header is valid"),
        "Bearer operator-token"
    );
    let body: Value = request.body_json().expect("request body is JSON");
    assert_eq!(
        body,
        json!({
            "tuf": {
                "root_path": path_string("/etc/registry-notary/tuf/metadata/1.root.json"),
                "metadata_dir": path_string("/etc/registry-notary/tuf/metadata"),
                "targets_dir": path_string("/etc/registry-notary/tuf/targets"),
                "datastore_dir": path_string("/var/lib/registry-notary/tuf"),
                "target_name": "registry-notary.yaml"
            },
            "local_approval_reference": "ROOT-2026-Q2"
        })
    );
}

#[tokio::test]
async fn config_apply_bundle_cli_rejects_http_admin_url_without_dev_opt_in() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/admin/v1/config/apply"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": "accepted",
            "bundle_id": "notary-test-bundle"
        })))
        .mount(&server)
        .await;

    let mut command = Command::new(env!("CARGO_BIN_EXE_registry-notary"));
    command
        .arg("config")
        .arg("apply-bundle")
        .arg("--admin-url")
        .arg(server.uri())
        .arg("--admin-token-env")
        .arg("NOTARY_ADMIN_TOKEN_TEST")
        .arg("--root-path")
        .arg("/etc/registry-notary/tuf/metadata/1.root.json")
        .arg("--metadata-dir")
        .arg("/etc/registry-notary/tuf/metadata")
        .arg("--targets-dir")
        .arg("/etc/registry-notary/tuf/targets")
        .arg("--datastore-dir")
        .arg("/var/lib/registry-notary/tuf")
        .arg("--target-name")
        .arg("registry-notary.yaml")
        .env("NOTARY_ADMIN_TOKEN_TEST", "operator-token")
        .env_remove("REGISTRY_NOTARY_CONFIG");

    let output = command
        .output()
        .expect("apply-bundle command runs far enough to validate URL");

    assert!(
        !output.status.success(),
        "apply-bundle unexpectedly succeeded: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("--allow-insecure-admin-url"),
        "stderr did not explain the insecure admin URL opt-in:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let requests = server
        .received_requests()
        .await
        .expect("request recording is enabled");
    assert_eq!(requests.len(), 0);
}

#[tokio::test]
async fn config_apply_bundle_cli_drives_live_admin_root_transition_with_local_approval() {
    let tmp = TempDir::new().expect("tempdir");
    let bind = allocate_loopback_addr();
    let current_yaml = root_transition_config_yaml(&tmp, bind, false);
    let current_config = write_current_config(&tmp, &current_yaml);
    let antirollback_path = tmp.path().join("antirollback.json");
    let local_approval_path = tmp.path().join("local-approvals.json");
    let audit_path = tmp.path().join("audit.jsonl");
    initialize_antirollback_state(&antirollback_path, &current_yaml);
    let current_config_hash = internal_config_hash(current_yaml.as_bytes());

    let candidate_yaml = root_transition_config_yaml(&tmp, bind, true);
    write_local_approval_state(&local_approval_path, &candidate_yaml, &current_config_hash);
    let signed =
        write_signed_root_transition_fixture(&tmp, &current_config_hash, &candidate_yaml).await;
    let server = start_live_notary_server(&current_config, bind).await;

    let output = live_apply_bundle_command(&server, &signed)
        .output()
        .expect("live root transition apply-bundle command runs");

    assert!(
        output.status.success(),
        "live root transition apply-bundle failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let response: Value =
        serde_json::from_slice(&output.stdout).expect("apply-bundle emits server JSON");
    assert_eq!(response["result"], "applied");
    assert_eq!(response["bundle_id"], "notary-root-transition-bundle");
    assert_eq!(response["applied"], true);
    assert_eq!(response["restart_required"], false);

    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("posture client builds");
    let posture: Value = client
        .get(format!(
            "{}/admin/v1/posture?tier=restricted",
            server.admin_url
        ))
        .bearer_auth("admin-token")
        .send()
        .await
        .expect("posture request succeeds")
        .error_for_status()
        .expect("posture response succeeds")
        .json()
        .await
        .expect("posture response is JSON");
    assert_eq!(posture["configuration"]["source"], "signed_bundle_file");
    assert_eq!(
        posture["configuration"]["last_bundle_id"],
        "notary-root-transition-bundle"
    );
    assert_eq!(posture["configuration"]["last_bundle_sequence"], 2);
    assert_eq!(posture["configuration"]["last_apply_result"], "accepted");
    assert_eq!(posture["configuration"]["restart_required"], false);

    let antirollback = FileAntiRollbackStore::new(&antirollback_path)
        .load(&AntiRollbackKey {
            product: "registry-notary".to_string(),
            instance_id: "notary-cli".to_string(),
            environment: "development".to_string(),
            stream_id: "notary-test-stream".to_string(),
        })
        .expect("anti-rollback state loads");
    assert_eq!(antirollback.last_sequence, 2);
    assert_eq!(
        antirollback.last_config_hash,
        internal_config_hash(candidate_yaml.as_bytes())
    );
    assert_eq!(antirollback.local_approvals.accepted.len(), 1);
    assert_eq!(
        antirollback.local_approvals.accepted[0].approval_reference,
        "ROOT-2026-Q2"
    );

    let audit_record = config_audit_record(&audit_path, "/admin/v1/config/apply");
    let config_audit = &audit_record["config"];
    assert_eq!(config_audit["source"], "signed_bundle_file");
    assert_eq!(config_audit["bundle_id"], "notary-root-transition-bundle");
    assert_eq!(config_audit["bundle_sequence"], 2);
    assert_eq!(config_audit["change_classes"], json!(["root_transition"]));
    assert_eq!(config_audit["local_approval_reference"], "ROOT-2026-Q2");
    assert_eq!(
        config_audit["local_approval_change_class"],
        "root_transition"
    );
    assert_eq!(config_audit["apply_result"], "applied");
    assert_eq!(config_audit["posture_result"], "accepted");
    assert_eq!(config_audit["applied"], true);
    assert_eq!(config_audit["restart_required"], false);
}

#[tokio::test]
async fn config_apply_bundle_cli_drives_live_admin_remote_root_transition_with_local_approval() {
    let tmp = TempDir::new().expect("tempdir");
    let bind = allocate_loopback_addr();
    let current_yaml = root_transition_config_yaml(&tmp, bind, false);
    let current_config = write_current_config(&tmp, &current_yaml);
    let antirollback_path = tmp.path().join("antirollback.json");
    let local_approval_path = tmp.path().join("local-approvals.json");
    let audit_path = tmp.path().join("audit.jsonl");
    initialize_antirollback_state(&antirollback_path, &current_yaml);
    let current_config_hash = internal_config_hash(current_yaml.as_bytes());

    let candidate_yaml = root_transition_config_yaml(&tmp, bind, true);
    write_local_approval_state(&local_approval_path, &candidate_yaml, &current_config_hash);
    let signed =
        write_signed_root_transition_fixture(&tmp, &current_config_hash, &candidate_yaml).await;
    let remote = serve_signed_tuf_fixture(&signed).await;
    let server = start_live_notary_server(&current_config, bind).await;

    let output = remote_live_apply_bundle_command(&server, &signed, &remote)
        .output()
        .expect("live remote root transition apply-bundle command runs");

    assert!(
        output.status.success(),
        "live remote root transition apply-bundle failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let response: Value =
        serde_json::from_slice(&output.stdout).expect("apply-bundle emits server JSON");
    assert_eq!(response["result"], "applied");
    assert_eq!(response["bundle_id"], "notary-root-transition-bundle");
    assert_eq!(response["applied"], true);
    assert_eq!(response["restart_required"], false);

    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("posture client builds");
    let posture: Value = client
        .get(format!(
            "{}/admin/v1/posture?tier=restricted",
            server.admin_url
        ))
        .bearer_auth("admin-token")
        .send()
        .await
        .expect("posture request succeeds")
        .error_for_status()
        .expect("posture response succeeds")
        .json()
        .await
        .expect("posture response is JSON");
    assert_eq!(posture["configuration"]["source"], "signed_bundle_endpoint");
    assert_eq!(
        posture["configuration"]["last_bundle_id"],
        "notary-root-transition-bundle"
    );
    assert_eq!(posture["configuration"]["last_bundle_sequence"], 2);
    assert_eq!(posture["configuration"]["last_apply_result"], "accepted");
    assert_eq!(posture["configuration"]["restart_required"], false);

    let antirollback = FileAntiRollbackStore::new(&antirollback_path)
        .load(&AntiRollbackKey {
            product: "registry-notary".to_string(),
            instance_id: "notary-cli".to_string(),
            environment: "development".to_string(),
            stream_id: "notary-test-stream".to_string(),
        })
        .expect("anti-rollback state loads");
    assert_eq!(antirollback.last_sequence, 2);
    assert_eq!(
        antirollback.last_config_hash,
        internal_config_hash(candidate_yaml.as_bytes())
    );
    assert_eq!(antirollback.local_approvals.accepted.len(), 1);
    assert_eq!(
        antirollback.local_approvals.accepted[0].approval_reference,
        "ROOT-2026-Q2"
    );

    let audit_record = config_audit_record(&audit_path, "/admin/v1/config/apply");
    let config_audit = &audit_record["config"];
    assert_eq!(config_audit["source"], "signed_bundle_endpoint");
    assert_eq!(config_audit["bundle_id"], "notary-root-transition-bundle");
    assert_eq!(config_audit["bundle_sequence"], 2);
    assert_eq!(config_audit["change_classes"], json!(["root_transition"]));
    assert_eq!(config_audit["local_approval_reference"], "ROOT-2026-Q2");
    assert_eq!(
        config_audit["local_approval_change_class"],
        "root_transition"
    );
    assert_eq!(config_audit["apply_result"], "applied");
    assert_eq!(config_audit["posture_result"], "accepted");
    assert_eq!(config_audit["applied"], true);
    assert_eq!(config_audit["restart_required"], false);
}

#[tokio::test]
async fn config_apply_bundle_cli_posts_remote_tuf_request_to_admin_apply() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/admin/v1/config/apply"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "result": "accepted",
            "bundle_id": "notary-remote-bundle"
        })))
        .mount(&server)
        .await;

    let output = remote_apply_bundle_command(&server)
        .output()
        .expect("remote apply-bundle command runs");

    assert!(
        output.status.success(),
        "remote apply-bundle failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let response: Value =
        serde_json::from_slice(&output.stdout).expect("apply-bundle emits server JSON");
    assert_eq!(response["result"], "accepted");
    assert_eq!(response["bundle_id"], "notary-remote-bundle");

    let requests = server
        .received_requests()
        .await
        .expect("request recording is enabled");
    assert_eq!(requests.len(), 1);
    let request = &requests[0];
    assert_eq!(request.method.as_str(), "POST");
    assert_eq!(request.url.path(), "/admin/v1/config/apply");
    assert_eq!(
        request
            .headers
            .get("authorization")
            .expect("authorization header is present")
            .to_str()
            .expect("authorization header is valid"),
        "Bearer operator-token"
    );
    let body: Value = request.body_json().expect("request body is JSON");
    assert_eq!(
        body,
        json!({
            "tuf": {
                "root_path": path_string("/etc/registry-notary/tuf/metadata/1.root.json"),
                "metadata_base_url": "https://config.example.gov/metadata",
                "targets_base_url": "https://config.example.gov/targets",
                "datastore_dir": path_string("/var/lib/registry-notary/tuf"),
                "target_name": "registry-notary.yaml",
                "allow_dev_insecure_fetch_urls": true
            }
        })
    );
}

#[tokio::test]
async fn config_apply_bundle_cli_exits_nonzero_on_admin_apply_error() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/admin/v1/config/apply"))
        .respond_with(ResponseTemplate::new(409).set_body_json(json!({
            "result": "restart_required",
            "detail": "candidate requires restart"
        })))
        .mount(&server)
        .await;

    let output = apply_bundle_command(&server)
        .output()
        .expect("apply-bundle command runs");

    assert!(
        !output.status.success(),
        "apply-bundle unexpectedly succeeded: {}",
        String::from_utf8_lossy(&output.stdout)
    );
    let response: Value =
        serde_json::from_slice(&output.stdout).expect("apply-bundle emits server JSON");
    assert_eq!(response["result"], "restart_required");
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("admin config apply returned HTTP 409"),
        "stderr did not report non-2xx status:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn path_string(path: &str) -> String {
    Path::new(path).to_string_lossy().into_owned()
}
