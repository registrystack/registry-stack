// SPDX-License-Identifier: Apache-2.0
//! Live operator CLI coverage for governed configuration bundle apply.

use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use chrono::Utc;
use registry_platform_authcommon::fingerprint_api_key;
use registry_platform_config::sha256_uri;
use registry_platform_ops::{
    internal_config_hash, AntiRollbackKey, AntiRollbackRecord, FileAntiRollbackStore,
};
use serde_json::{json, Value};
use tempfile::TempDir;
use tough::editor::signed::PathExists;
use tough::editor::RepositoryEditor;
use tough::key_source::{KeySource, LocalKeySource};
use tough::schema::Target;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

const ADMIN_TOKEN: &str = "relay-live-admin-token";
const OPS_TOKEN: &str = "relay-live-ops-token";
const ADMIN_TOKEN_HASH_ENV: &str = "REGISTRY_RELAY_LIVE_ADMIN_TOKEN_HASH";
const OPS_TOKEN_HASH_ENV: &str = "REGISTRY_RELAY_LIVE_OPS_TOKEN_HASH";
const ADMIN_TOKEN_ENV: &str = "REGISTRY_RELAY_LIVE_ADMIN_TOKEN";
const AUDIT_HASH_SECRET_ENV: &str = "REGISTRY_RELAY_LIVE_AUDIT_HASH_SECRET";
const AUDIT_HASH_SECRET: &str = "relay-live-audit-secret-32-bytes!!";
const TUF_TARGETS_SIGNER_KID: &str =
    "8ec3a843a0f9328c863cac4046ab1cacbbc67888476ac7acf73d9bcd9a223ada";

struct SignedConfigFixture {
    root_path: PathBuf,
    metadata_dir: PathBuf,
    targets_dir: PathBuf,
    datastore_dir: PathBuf,
    target_name: String,
}

struct LiveRelayServer {
    child: Child,
    admin_url: String,
}

impl Drop for LiveRelayServer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn allocate_loopback_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").expect("loopback listener binds");
    listener.local_addr().expect("loopback listener has addr")
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

fn current_config_yaml(tmp: &TempDir, public_bind: SocketAddr, admin_bind: SocketAddr) -> String {
    config_yaml(tmp, public_bind, admin_bind, false)
}

fn candidate_config_yaml(tmp: &TempDir, public_bind: SocketAddr, admin_bind: SocketAddr) -> String {
    config_yaml(tmp, public_bind, admin_bind, true)
}

fn config_yaml(
    tmp: &TempDir,
    public_bind: SocketAddr,
    admin_bind: SocketAddr,
    include_next_root: bool,
) -> String {
    let tuf_root_sha256 = sha256_uri(
        &std::fs::read(tough_fixture("simple-rsa").join("root.json"))
            .expect("trusted TUF root fixture reads"),
    );
    let next_root = if include_next_root {
        format!(
            r#"
    - root_id: ops-root-next
      production: false
      tuf_root_sha256: "{tuf_root_sha256}"
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
"#
        )
    } else {
        String::new()
    };
    format!(
        r#"
instance:
  id: relay-live-cli
  environment: lab
server:
  bind: {public_bind}
  admin_bind: {admin_bind}
  cache_dir: "{}"
catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test
vocabularies: {{}}
auth:
  mode: api_key
  api_keys:
    - id: admin
      hash_env: {ADMIN_TOKEN_HASH_ENV}
      scopes:
        - registry_relay:admin
    - id: ops
      hash_env: {OPS_TOKEN_HASH_ENV}
      scopes:
        - registry_relay:ops_read
datasets: []
audit:
  sink: stdout
  format: jsonl
  hash_secret_env: {AUDIT_HASH_SECRET_ENV}
config_trust:
  antirollback_state_path: "{}"
  local_approval_state_path: "{}"
  accepted_roots:
    - root_id: ops-root
      production: false
      tuf_root_sha256: "{tuf_root_sha256}"
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
        tmp.path().join("cache").display(),
        tmp.path().join("antirollback.json").display(),
        tmp.path().join("local-approvals.json").display(),
    )
}

fn write_local_approval(
    tmp: &TempDir,
    candidate_hash: &str,
    previous_config_hash: &str,
) -> PathBuf {
    let path = tmp.path().join("local-approvals.json");
    let expires_at_unix_seconds = Utc::now().timestamp() as u64 + 3600;
    let state = json!({
        "approvals": [{
            "approved_by": "ops@example.test",
            "reason": "approve relay root transition",
            "approval_reference": "ROOT-2026-Q2",
            "change_class": "root_transition",
            "config_hash": candidate_hash,
            "previous_config_hash": previous_config_hash,
            "expires_at_unix_seconds": expires_at_unix_seconds,
            "rate_limit_identity": "registry-relay/relay-live-cli/lab/test-stream/root-transition",
            "rate_limit": {
                "max_accepted": 1,
                "window_seconds": 3600
            }
        }]
    });
    std::fs::write(
        &path,
        serde_json::to_vec_pretty(&state).expect("local approval state serializes"),
    )
    .expect("local approval state writes");
    path
}

fn initialize_antirollback_state(path: &Path, current_config_hash: &str) {
    FileAntiRollbackStore::new(path)
        .initialize(AntiRollbackRecord {
            key: AntiRollbackKey {
                product: "registry-relay".to_string(),
                instance_id: "relay-live-cli".to_string(),
                environment: "lab".to_string(),
                stream_id: "test-stream".to_string(),
            },
            last_sequence: 0,
            last_config_hash: current_config_hash.to_string(),
            root_version: None,
            break_glass: Default::default(),
            local_approvals: Default::default(),
        })
        .expect("antirollback state initializes");
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
    let target_name = "registry-relay.yaml";
    let target_path = source_dir.join(target_name);
    std::fs::write(&target_path, candidate_yaml).expect("target config writes");

    let mut target = Target::from_path(&target_path)
        .await
        .expect("target metadata builds");
    let custom = json!({
        "product": "registry-relay",
        "instance_id": "relay-live-cli",
        "environment": "lab",
        "stream_id": "test-stream",
        "bundle_id": "relay-root-transition-bundle",
        "sequence": 2,
        "previous_config_hash": current_config_hash,
        "config_hash": sha256_uri(candidate_yaml.as_bytes()),
        "change_classes": ["root_transition"],
        "signer_kids": [TUF_TARGETS_SIGNER_KID],
        "apply_policy": "live"
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
    let version = std::num::NonZeroU64::new(2).expect("nonzero version");
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

async fn start_live_relay(config_path: &Path, admin_addr: SocketAddr) -> LiveRelayServer {
    let mut child = Command::new(env!("CARGO_BIN_EXE_registry-relay"))
        .arg("--config")
        .arg(config_path)
        .env(ADMIN_TOKEN_HASH_ENV, fingerprint_api_key(ADMIN_TOKEN))
        .env(OPS_TOKEN_HASH_ENV, fingerprint_api_key(OPS_TOKEN))
        .env(AUDIT_HASH_SECRET_ENV, AUDIT_HASH_SECRET)
        .env("REGISTRY_RELAY_LOG_FORMAT", "json")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("registry-relay process starts");
    let admin_url = format!("http://{admin_addr}");
    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("health client builds");
    for _ in 0..300 {
        match client.get(format!("{admin_url}/healthz")).send().await {
            Ok(response) if response.status().is_success() => {
                return LiveRelayServer { child, admin_url };
            }
            _ => {
                if let Some(_status) = child.try_wait().expect("child status checks") {
                    let output = child
                        .wait_with_output()
                        .expect("exited registry-relay output reads");
                    panic!(
                        "registry-relay exited before readiness: {}\nstdout:\n{}\nstderr:\n{}",
                        output.status,
                        String::from_utf8_lossy(&output.stdout),
                        String::from_utf8_lossy(&output.stderr)
                    );
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
    let _ = child.kill();
    let _ = child.wait();
    panic!("registry-relay did not become ready");
}

fn local_apply_bundle_command(server: &LiveRelayServer, signed: &SignedConfigFixture) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_registry-relay"));
    command
        .arg("config")
        .arg("apply-bundle")
        .arg("--admin-url")
        .arg(&server.admin_url)
        .arg("--admin-token-env")
        .arg(ADMIN_TOKEN_ENV)
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
        .env(ADMIN_TOKEN_ENV, ADMIN_TOKEN)
        .env_remove("REGISTRY_RELAY_CONFIG");
    command
}

fn remote_apply_bundle_command(
    server: &LiveRelayServer,
    signed: &SignedConfigFixture,
    remote: &MockServer,
) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_registry-relay"));
    command
        .arg("config")
        .arg("apply-bundle")
        .arg("--admin-url")
        .arg(&server.admin_url)
        .arg("--admin-token-env")
        .arg(ADMIN_TOKEN_ENV)
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
        .env(ADMIN_TOKEN_ENV, ADMIN_TOKEN)
        .env_remove("REGISTRY_RELAY_CONFIG");
    command
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

#[tokio::test]
async fn config_apply_bundle_cli_drives_live_admin_root_transition_with_local_approval() {
    #[allow(unused_unsafe)]
    unsafe {
        std::env::set_var(ADMIN_TOKEN_HASH_ENV, fingerprint_api_key(ADMIN_TOKEN));
        std::env::set_var(OPS_TOKEN_HASH_ENV, fingerprint_api_key(OPS_TOKEN));
        std::env::set_var(AUDIT_HASH_SECRET_ENV, AUDIT_HASH_SECRET);
    }
    let tmp = TempDir::new().expect("tempdir");
    let public_bind = allocate_loopback_addr();
    let admin_bind = allocate_loopback_addr();
    let current_yaml = current_config_yaml(&tmp, public_bind, admin_bind);
    let current_config_path = tmp.path().join("current.yaml");
    std::fs::write(&current_config_path, &current_yaml).expect("current config writes");
    registry_relay::config::load(&current_config_path).expect("current config validates");
    let current_config_hash = internal_config_hash(current_yaml.as_bytes());
    let antirollback_path = tmp.path().join("antirollback.json");
    initialize_antirollback_state(&antirollback_path, &current_config_hash);

    let candidate_yaml = candidate_config_yaml(&tmp, public_bind, admin_bind);
    let candidate_hash = internal_config_hash(candidate_yaml.as_bytes());
    write_local_approval(&tmp, &candidate_hash, &current_config_hash);
    let signed =
        write_signed_root_transition_fixture(&tmp, &current_config_hash, &candidate_yaml).await;
    let server = start_live_relay(&current_config_path, admin_bind).await;

    let output = local_apply_bundle_command(&server, &signed)
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
    assert_eq!(response["bundle_id"], "relay-root-transition-bundle");
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
        .bearer_auth(OPS_TOKEN)
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
        "relay-root-transition-bundle"
    );
    assert_eq!(posture["configuration"]["last_bundle_sequence"], 2);
    assert_eq!(posture["configuration"]["last_apply_result"], "accepted");
    assert_eq!(posture["configuration"]["restart_required"], false);

    let antirollback = FileAntiRollbackStore::new(&antirollback_path)
        .load(&AntiRollbackKey {
            product: "registry-relay".to_string(),
            instance_id: "relay-live-cli".to_string(),
            environment: "lab".to_string(),
            stream_id: "test-stream".to_string(),
        })
        .expect("antirollback state loads");
    assert_eq!(antirollback.last_sequence, 2);
    assert_eq!(antirollback.last_config_hash, candidate_hash);
    assert_eq!(antirollback.local_approvals.accepted.len(), 1);
    assert_eq!(
        antirollback.local_approvals.accepted[0].approval_reference,
        "ROOT-2026-Q2"
    );
    assert_eq!(
        antirollback.local_approvals.accepted[0].change_class,
        "root_transition"
    );
}

#[tokio::test]
async fn config_apply_bundle_cli_drives_live_admin_remote_root_transition_with_local_approval() {
    #[allow(unused_unsafe)]
    unsafe {
        std::env::set_var(ADMIN_TOKEN_HASH_ENV, fingerprint_api_key(ADMIN_TOKEN));
        std::env::set_var(OPS_TOKEN_HASH_ENV, fingerprint_api_key(OPS_TOKEN));
        std::env::set_var(AUDIT_HASH_SECRET_ENV, AUDIT_HASH_SECRET);
    }
    let tmp = TempDir::new().expect("tempdir");
    let public_bind = allocate_loopback_addr();
    let admin_bind = allocate_loopback_addr();
    let current_yaml = current_config_yaml(&tmp, public_bind, admin_bind);
    let current_config_path = tmp.path().join("current.yaml");
    std::fs::write(&current_config_path, &current_yaml).expect("current config writes");
    registry_relay::config::load(&current_config_path).expect("current config validates");
    let current_config_hash = internal_config_hash(current_yaml.as_bytes());
    let antirollback_path = tmp.path().join("antirollback.json");
    initialize_antirollback_state(&antirollback_path, &current_config_hash);

    let candidate_yaml = candidate_config_yaml(&tmp, public_bind, admin_bind);
    let candidate_hash = internal_config_hash(candidate_yaml.as_bytes());
    write_local_approval(&tmp, &candidate_hash, &current_config_hash);
    let signed =
        write_signed_root_transition_fixture(&tmp, &current_config_hash, &candidate_yaml).await;
    let remote = serve_signed_tuf_fixture(&signed).await;
    let server = start_live_relay(&current_config_path, admin_bind).await;

    let output = remote_apply_bundle_command(&server, &signed, &remote)
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
    assert_eq!(response["bundle_id"], "relay-root-transition-bundle");
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
        .bearer_auth(OPS_TOKEN)
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
        "relay-root-transition-bundle"
    );
    assert_eq!(posture["configuration"]["last_bundle_sequence"], 2);
    assert_eq!(posture["configuration"]["last_apply_result"], "accepted");
    assert_eq!(posture["configuration"]["restart_required"], false);

    let antirollback = FileAntiRollbackStore::new(&antirollback_path)
        .load(&AntiRollbackKey {
            product: "registry-relay".to_string(),
            instance_id: "relay-live-cli".to_string(),
            environment: "lab".to_string(),
            stream_id: "test-stream".to_string(),
        })
        .expect("antirollback state loads");
    assert_eq!(antirollback.last_sequence, 2);
    assert_eq!(antirollback.last_config_hash, candidate_hash);
    assert_eq!(antirollback.local_approvals.accepted.len(), 1);
    assert_eq!(
        antirollback.local_approvals.accepted[0].approval_reference,
        "ROOT-2026-Q2"
    );
    assert_eq!(
        antirollback.local_approvals.accepted[0].change_class,
        "root_transition"
    );
}
