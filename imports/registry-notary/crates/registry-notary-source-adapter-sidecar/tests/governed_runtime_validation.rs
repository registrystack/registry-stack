// SPDX-License-Identifier: Apache-2.0

//! Engine-agnostic governed-startup security coverage for the source-adapter
//! sidecar. These tests exercise the signed-TUF startup loader, assurance
//! reporting, and anti-rollback enforcement that gate a real governed startup.
//!
//! The OpenFn engine that previously backed this file was retired; the governed
//! runtime target, the TUF signing harness, and the anti-rollback/identity/
//! change-class/apply-policy enforcement are NOT OpenFn-specific and remain a
//! supported feature. The governed source here uses the `http_json` engine and
//! is backed by a mock upstream so the startup smoke lookup performs a real
//! request, just as a production governed startup would.

use axum::{extract::Query, http::StatusCode, routing::get, Json, Router};
use axum_test::TestServer;
use chrono::{TimeDelta, Utc};
use registry_notary_source_adapter_sidecar::{
    create_local_tuf_demo_repo_report_json, load_startup_config, load_startup_config_with_options,
    render_governed_runtime_target_json, sidecar_router, verify_governed_bundle_report_json,
    CreateLocalTufRepoOptions, LocalTufBundleVerifyOptions,
};
use registry_platform_config::{
    sha256_uri, LocalTufRepositoryInput, TufConfigVerifier, VerificationContext,
};
use registry_platform_ops::{
    AntiRollbackKey, AntiRollbackRecord, BreakGlassState, FileAntiRollbackStore, LocalApprovalState,
};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::fs;
use std::num::NonZeroU64;
use std::path::{Path, PathBuf};
use tempfile::TempDir;
use tokio::sync::Mutex;
use tough::editor::signed::PathExists;
use tough::editor::RepositoryEditor;
use tough::key_source::{KeySource, LocalKeySource};
use tough::schema::Target;

const TOKEN_HASH_ENV: &str = "GOVERNED_RUNTIME_VALIDATION_TOKEN_HASH";
const TOKEN: &str = "contract-sidecar-token";
const TOKEN_HASH: &str = "sha256:98808b694f3b431dcc2459db07bbfb61b8e3287ad0ab7364a2ff510d35e21418";
const AUDIT_HASH_SECRET_ENV: &str = "GOVERNED_RUNTIME_VALIDATION_AUDIT_HASH_SECRET";
const AUDIT_HASH_SECRET: &str = "0123456789abcdef0123456789abcdef";
const CREDENTIAL_ENV: &str = "GOVERNED_RUNTIME_VALIDATION_CREDENTIAL_JSON";
const PRODUCT: &str = "registry-notary-source-adapter-sidecar";
const INSTANCE_ID: &str = "demo";
const ENVIRONMENT: &str = "staging";
const STREAM_ID: &str = "openfn-sidecar-runtime";
const TARGET_NAME: &str = "openfn-sidecar-runtime.json";
const CHANGE_CLASS: &str = "openfn_sidecar_workflow_bundle";
const SOURCE_ID: &str = "http_people";

// The governed-startup tests mutate process-wide environment variables and rely
// on a per-test mock upstream. Serialize env mutation across tests so the token
// hash and credential JSON stay coherent for the source under test.
static ENV_LOCK: Mutex<()> = Mutex::const_new(());

/// Mock upstream record endpoint. The governed http_json source projects
/// `body.results` into the RDA `data` array; the startup smoke lookup succeeds
/// when a record's `national_id` matches the configured smoke value.
async fn person_lookup(Query(query): Query<HashMap<String, String>>) -> Json<Value> {
    let id = query.get("id").cloned().unwrap_or_default();
    let results = match id.as_str() {
        "smoke-person" => json!([
            {
                "national_id": "smoke-person",
                "birth_date": "1990-01-01"
            }
        ]),
        _ => json!([]),
    };
    Json(json!({ "results": results }))
}

fn server_base_url(server: &TestServer) -> String {
    server
        .server_address()
        .expect("HTTP transport exposes server address")
        .to_string()
        .trim_end_matches('/')
        .to_string()
}

/// Test harness owning the live mock upstream and the serialized env guard.
/// Every governed test stands up a real upstream so the startup smoke lookup
/// performs an actual request against the signed `allowed_base_urls`.
struct Harness {
    _env_guard: tokio::sync::MutexGuard<'static, ()>,
    _upstream: TestServer,
    upstream_url: String,
}

impl Harness {
    async fn new() -> Self {
        let env_guard = ENV_LOCK.lock().await;
        let upstream = TestServer::builder()
            .http_transport()
            .build(Router::new().route("/people", get(person_lookup)));
        let upstream_url = server_base_url(&upstream);
        std::env::set_var(TOKEN_HASH_ENV, TOKEN_HASH);
        std::env::set_var(AUDIT_HASH_SECRET_ENV, AUDIT_HASH_SECRET);
        std::env::set_var(
            CREDENTIAL_ENV,
            json!({ "baseUrl": upstream_url, "apiToken": "fixture-token" }).to_string(),
        );
        Self {
            _env_guard: env_guard,
            _upstream: upstream,
            upstream_url,
        }
    }

    /// Governed http_json manifest pointing the source at the live mock
    /// upstream. This is rendered into the signed runtime target, so the mock
    /// URL is baked into the target's `allowed_base_urls`.
    fn governed_manifest(&self) -> String {
        format!(
            r#"
server:
  bind: "127.0.0.1:0"
auth:
  bearer_tokens:
    - id: notary-contract
      hash_env: {token_hash_env}
limits:
  max_workers: 1
  worker_timeout_ms: 250
  max_output_bytes: 4096
  max_request_bytes: 2048
  max_query_parameter_bytes: 128
  liveness_window_ms: 30000
  max_batch_items: 100
sources:
  {source_id}:
    engine: http_json
    dataset: civil_registry
    entity: civil_person
    credential_env: {credential_env}
    credential_public_fields:
      - baseUrl
    allowed_base_urls:
      - {base_url}
    allow_insecure_localhost: true
    http_json:
      method: GET
      base_url:
        cel: credential_public.baseUrl
      path: "/people"
      query:
        id:
          cel: lookup.value
      response:
        records:
          cel: body.results
    smoke_lookup:
      field: national_id
      value: smoke-person
      fields:
        - national_id
      purpose: startup-smoke
"#,
            token_hash_env = yaml_string(TOKEN_HASH_ENV),
            source_id = SOURCE_ID,
            credential_env = yaml_string(CREDENTIAL_ENV),
            base_url = yaml_string(&self.upstream_url),
        )
    }

    /// Render the governed runtime target bytes from the manifest. These are the
    /// exact bytes that get signed into the TUF target and re-parsed at startup,
    /// keeping the config hash consistent end to end.
    fn governed_runtime_target_bytes(&self) -> Vec<u8> {
        render_governed_runtime_target_json(&self.governed_manifest())
            .expect("governed http_json runtime target renders")
    }
}

struct SignedRepo {
    root_path: PathBuf,
    metadata_dir: PathBuf,
    targets_dir: PathBuf,
    datastore_dir: PathBuf,
    tuf_root_sha256: String,
    signer_kids: Vec<String>,
    config_hash: String,
}

#[tokio::test]
async fn governed_target_renders_http_json_only_without_openfn_runtime() {
    let harness = Harness::new().await;
    let target_bytes = harness.governed_runtime_target_bytes();
    let target: Value = serde_json::from_slice(&target_bytes).expect("target is JSON");

    assert_eq!(
        target["schema"],
        "registry.notary.openfn_sidecar.runtime.v1"
    );
    assert!(target["openfn"].is_null());
    assert!(target["worker"].is_null());
    assert!(target["jobs_root"].is_null());
    assert!(target["limits"]["max_worker_memory_mb"].is_null());
    assert_eq!(target["sources"][SOURCE_ID]["engine"], "http_json");
    assert!(target["sources"][SOURCE_ID]["workflow"].is_null());

    let verify_report = verify_governed_bundle_report_json(Some(&target_bytes), None)
        .await
        .expect("plain http_json-only target verifies");
    assert_eq!(verify_report["verified"], true);
    assert_eq!(verify_report["config_hash"], sha256_uri(&target_bytes));
    assert!(verify_report["tuf"].is_null());
}

#[tokio::test]
async fn release_helper_verify_bundle_reports_local_tuf_metadata() {
    let harness = Harness::new().await;
    let previous_config_hash =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111".to_string();
    let repo = signed_runtime_repo(&harness, 12, "restart_required", &previous_config_hash).await;

    let report = verify_governed_bundle_report_json(
        None,
        Some(LocalTufBundleVerifyOptions {
            product: PRODUCT.to_string(),
            instance_id: INSTANCE_ID.to_string(),
            environment: ENVIRONMENT.to_string(),
            stream_id: STREAM_ID.to_string(),
            root_path: repo.root_path.clone(),
            metadata_dir: repo.metadata_dir.clone(),
            targets_dir: repo.targets_dir.clone(),
            datastore_dir: repo.datastore_dir.clone(),
            target_name: TARGET_NAME.to_string(),
        }),
    )
    .await
    .expect("local TUF target verifies");

    assert_eq!(report["verified"], true);
    assert_eq!(report["target_name"], TARGET_NAME);
    assert_eq!(report["config_hash"], repo.config_hash);
    assert_eq!(report["tuf"]["root_sha256"], repo.tuf_root_sha256);
    assert_eq!(report["tuf"]["targets_version"], 12);
    assert_eq!(report["metadata"]["apply_policy"], "restart_required");
    assert_eq!(report["metadata"]["change_classes"], json!([CHANGE_CLASS]));
}

#[tokio::test]
async fn startup_loader_rejects_unsigned_manifest_without_dev_escape_hatch() {
    let harness = Harness::new().await;
    let error = load_startup_config(&harness.governed_manifest())
        .await
        .expect_err("unsigned startup manifest is rejected");

    assert!(error.to_string().contains("config_trust is required"));
}

#[tokio::test]
async fn startup_loader_accepts_unsigned_manifest_only_with_dev_escape_hatch() {
    let harness = Harness::new().await;
    let config = load_startup_config_with_options(&harness.governed_manifest(), true)
        .await
        .expect("unsigned dev manifest parses with explicit escape hatch");

    assert!(config.config_trust.is_none());
    assert!(config.assurance.is_none());
}

#[tokio::test]
async fn release_helper_create_local_tuf_demo_repo_signs_and_verifies() {
    let harness = Harness::new().await;
    let target_bytes = harness.governed_runtime_target_bytes();
    let tmp = TempDir::new().expect("repo temp dir");
    let target_path = tmp.path().join("rendered-runtime.json");
    fs::write(&target_path, &target_bytes).expect("target writes");
    let datastore_dir = tmp.path().join("datastore");
    fs::create_dir_all(&datastore_dir).expect("datastore dir");

    let report = create_local_tuf_demo_repo_report_json(CreateLocalTufRepoOptions {
        target_path: target_path.clone(),
        target_name: TARGET_NAME.to_string(),
        root_path: tough_fixture_dir("").join("simple-rsa").join("root.json"),
        signing_key_path: tough_fixture_dir("").join("snakeoil.pem"),
        metadata_dir: tmp.path().join("metadata"),
        targets_dir: tmp.path().join("targets"),
        product: PRODUCT.to_string(),
        instance_id: INSTANCE_ID.to_string(),
        environment: ENVIRONMENT.to_string(),
        stream_id: STREAM_ID.to_string(),
        bundle_id: "sidecar-cli-demo".to_string(),
        sequence: 13,
        previous_config_hash:
            "sha256:1111111111111111111111111111111111111111111111111111111111111111".to_string(),
        change_classes: vec![CHANGE_CLASS.to_string()],
        declared_signer_kids: vec!["declared-non-authoritative".to_string()],
        apply_policy: "restart_required".to_string(),
        targets_expiration_days: 30,
        snapshot_expiration_days: 30,
        timestamp_expiration_days: 30,
    })
    .await
    .expect("local TUF repo is created");

    assert_eq!(report["created"], true);
    assert_eq!(report["target_name"], TARGET_NAME);
    assert_eq!(report["config_hash"], sha256_uri(&target_bytes));
    let copied_targets = fs::read_dir(tmp.path().join("targets"))
        .expect("targets dir reads")
        .count();
    assert!(copied_targets > 0);

    let verify_report = verify_governed_bundle_report_json(
        None,
        Some(LocalTufBundleVerifyOptions {
            product: PRODUCT.to_string(),
            instance_id: INSTANCE_ID.to_string(),
            environment: ENVIRONMENT.to_string(),
            stream_id: STREAM_ID.to_string(),
            root_path: tough_fixture_dir("").join("simple-rsa").join("root.json"),
            metadata_dir: tmp.path().join("metadata"),
            targets_dir: tmp.path().join("targets"),
            datastore_dir,
            target_name: TARGET_NAME.to_string(),
        }),
    )
    .await
    .expect("created repo verifies");
    assert_eq!(verify_report["verified"], true);
    assert_eq!(verify_report["metadata"]["sequence"], 13);
    assert_eq!(verify_report["config_hash"], sha256_uri(&target_bytes));
}

#[tokio::test]
async fn governed_startup_loads_signed_tuf_target_reports_assurance_and_accepts_antirollback() {
    let harness = Harness::new().await;
    let previous_config_hash =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111".to_string();
    let repo = signed_runtime_repo(&harness, 12, "restart_required", &previous_config_hash).await;
    initialize_antirollback(&repo, &previous_config_hash, 11);
    let raw = bootstrap_yaml(&repo);

    let config = load_startup_config(&raw)
        .await
        .expect("signed startup config loads");
    let app = sidecar_router(config)
        .await
        .expect("signed governed sidecar starts");
    let server = TestServer::builder().http_transport().build(app);

    let ready = server.get("/ready").await;
    ready.assert_status_ok();
    let ready_body: Value = ready.json();
    assert_eq!(ready_body["status"], "ready");
    assert_eq!(ready_body["config_hash"], repo.config_hash);
    assert_eq!(ready_body["expression_hashes_verified"], true);
    assert_eq!(ready_body["runtime_verified"], true);
    assert_eq!(ready_body["smoke_verified"], true);

    server
        .get("/v1/assurance")
        .await
        .assert_status(StatusCode::UNAUTHORIZED);
    let assurance = server
        .get("/v1/assurance")
        .add_header("authorization", format!("Bearer {TOKEN}"))
        .await;
    assurance.assert_status_ok();
    let assurance_body: Value = assurance.json();
    assert_eq!(assurance_body["product"], PRODUCT);
    assert_eq!(assurance_body["instance_id"], INSTANCE_ID);
    assert_eq!(assurance_body["environment"], ENVIRONMENT);
    assert_eq!(assurance_body["stream_id"], STREAM_ID);
    assert_eq!(assurance_body["sequence"], 12);
    assert_eq!(assurance_body["config_hash"], repo.config_hash);
    assert_eq!(assurance_body["tuf_root_sha256"], repo.tuf_root_sha256);
    assert_eq!(assurance_body["apply_policy"], "restart_required");
    assert!(!assurance.text().contains("fixture-token"));
    assert!(!assurance.text().contains(CREDENTIAL_ENV));

    let accepted: AntiRollbackRecord =
        serde_json::from_slice(&fs::read(repo.datastore_dir.join("antirollback.json")).unwrap())
            .expect("antirollback state parses");
    assert_eq!(accepted.last_sequence, 12);
    assert_eq!(accepted.last_config_hash, repo.config_hash);

    let restarted_config = load_startup_config(&raw)
        .await
        .expect("signed startup config reloads");
    let restarted_app = sidecar_router(restarted_config)
        .await
        .expect("same signed governed sidecar restarts");
    let restarted_server = TestServer::builder().http_transport().build(restarted_app);

    let restarted_ready = restarted_server.get("/ready").await;
    restarted_ready.assert_status_ok();
    let restarted_ready_body: Value = restarted_ready.json();
    assert_eq!(restarted_ready_body["status"], "ready");
    assert_eq!(restarted_ready_body["config_hash"], repo.config_hash);

    let replayed: AntiRollbackRecord =
        serde_json::from_slice(&fs::read(repo.datastore_dir.join("antirollback.json")).unwrap())
            .expect("antirollback state parses after restart");
    assert_eq!(replayed, accepted);
}

#[tokio::test]
async fn governed_startup_rejects_non_restart_required_apply_policy() {
    let harness = Harness::new().await;
    let previous_config_hash =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111".to_string();
    let repo = signed_runtime_repo(&harness, 12, "hot_swap", &previous_config_hash).await;
    initialize_antirollback(&repo, &previous_config_hash, 11);
    let raw = bootstrap_yaml(&repo);

    let error = load_startup_config(&raw)
        .await
        .expect_err("hot_swap policy must fail for startup-only sidecar");

    assert!(error
        .to_string()
        .contains("apply_policy must be restart_required"));
}

#[tokio::test]
async fn governed_startup_rejects_signed_target_identity_mismatches() {
    let harness = Harness::new().await;
    let previous_config_hash =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111".to_string();
    for (product, instance_id, environment, stream_id) in [
        ("wrong-product", INSTANCE_ID, ENVIRONMENT, STREAM_ID),
        (PRODUCT, "wrong-instance", ENVIRONMENT, STREAM_ID),
        (PRODUCT, INSTANCE_ID, "wrong-environment", STREAM_ID),
        (PRODUCT, INSTANCE_ID, ENVIRONMENT, "wrong-stream"),
    ] {
        let repo = signed_runtime_repo_with_metadata(
            &harness,
            12,
            "restart_required",
            &previous_config_hash,
            product,
            instance_id,
            environment,
            stream_id,
            vec![CHANGE_CLASS],
        )
        .await;
        let raw = bootstrap_yaml(&repo);

        let error = load_startup_config(&raw)
            .await
            .expect_err("wrong signed identity must fail");

        assert!(
            error.to_string().contains("TUF target verification failed")
                || error.to_string().contains("stream_id does not match"),
            "{error}"
        );
    }
}

#[tokio::test]
async fn governed_startup_rejects_unauthorized_change_class() {
    let harness = Harness::new().await;
    let previous_config_hash =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111".to_string();
    let repo = signed_runtime_repo_with_metadata(
        &harness,
        12,
        "restart_required",
        &previous_config_hash,
        PRODUCT,
        INSTANCE_ID,
        ENVIRONMENT,
        STREAM_ID,
        vec!["openfn_sidecar_runtime"],
    )
    .await;
    let raw = bootstrap_yaml(&repo);

    let error = load_startup_config(&raw)
        .await
        .expect_err("unauthorized change class must fail");

    assert!(error
        .to_string()
        .contains("signed config target was not authorized"));
}

#[tokio::test]
async fn governed_startup_rejects_lower_antirollback_sequence() {
    let harness = Harness::new().await;
    let previous_config_hash =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111".to_string();
    let repo = signed_runtime_repo(&harness, 12, "restart_required", &previous_config_hash).await;
    initialize_antirollback(&repo, &repo.config_hash, 13);
    let raw = bootstrap_yaml(&repo);
    let config = load_startup_config(&raw)
        .await
        .expect("signed startup config loads");

    let error = sidecar_router(config)
        .await
        .expect_err("lower antirollback sequence must fail");

    assert!(error
        .to_string()
        .contains("anti-rollback acceptance failed"));
}

#[tokio::test]
async fn governed_startup_rejects_antirollback_previous_hash_mismatch() {
    let harness = Harness::new().await;
    let previous_config_hash =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111".to_string();
    let repo = signed_runtime_repo(&harness, 13, "restart_required", &previous_config_hash).await;
    initialize_antirollback(
        &repo,
        "sha256:2222222222222222222222222222222222222222222222222222222222222222",
        12,
    );
    let raw = bootstrap_yaml(&repo);
    let config = load_startup_config(&raw)
        .await
        .expect("signed startup config loads");

    let error = sidecar_router(config)
        .await
        .expect_err("antirollback previous hash mismatch must fail");

    assert!(error
        .to_string()
        .contains("anti-rollback acceptance failed"));
}

#[tokio::test]
async fn governed_startup_smoke_failure_does_not_accept_antirollback() {
    let harness = Harness::new().await;
    let previous_config_hash =
        "sha256:1111111111111111111111111111111111111111111111111111111111111111".to_string();
    let repo = signed_runtime_repo(&harness, 12, "restart_required", &previous_config_hash).await;
    initialize_antirollback(&repo, &previous_config_hash, 11);
    let raw = bootstrap_yaml(&repo);
    let mut config = load_startup_config(&raw)
        .await
        .expect("signed startup config loads");
    config.limits.liveness_window_ms = 1;
    config
        .sources
        .get_mut(SOURCE_ID)
        .expect("source exists")
        .smoke_lookup
        .as_mut()
        .expect("smoke lookup exists")
        .value = "missing-person".to_string();

    let error = sidecar_router(config)
        .await
        .expect_err("smoke failure must fail before antirollback acceptance");

    assert!(error.to_string().contains("smoke lookup"));
    let accepted: AntiRollbackRecord =
        serde_json::from_slice(&fs::read(repo.datastore_dir.join("antirollback.json")).unwrap())
            .expect("antirollback state parses");
    assert_eq!(accepted.last_sequence, 11);
    assert_eq!(accepted.last_config_hash, previous_config_hash);
}

fn yaml_path(path: &Path) -> String {
    yaml_string(path.to_str().expect("fixture path is UTF-8"))
}

fn yaml_string(value: &str) -> String {
    serde_json::to_string(value).expect("string serializes")
}

async fn signed_runtime_repo(
    harness: &Harness,
    sequence: u64,
    apply_policy: &str,
    previous_config_hash: &str,
) -> SignedRepo {
    signed_runtime_repo_with_metadata(
        harness,
        sequence,
        apply_policy,
        previous_config_hash,
        PRODUCT,
        INSTANCE_ID,
        ENVIRONMENT,
        STREAM_ID,
        vec![CHANGE_CLASS],
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn signed_runtime_repo_with_metadata(
    harness: &Harness,
    sequence: u64,
    apply_policy: &str,
    previous_config_hash: &str,
    product: &str,
    instance_id: &str,
    environment: &str,
    stream_id: &str,
    change_classes: Vec<&str>,
) -> SignedRepo {
    let repo = TempDir::new().expect("repo temp dir");
    let datastore = TempDir::new().expect("datastore temp dir");
    let source_targets = repo.path().join("source-targets");
    fs::create_dir_all(&source_targets).expect("source targets dir");
    let target_path = source_targets.join(TARGET_NAME);
    let target_bytes = harness.governed_runtime_target_bytes();
    fs::write(&target_path, &target_bytes).expect("target writes");
    let config_hash = sha256_uri(&target_bytes);
    let custom = json!({
        "product": product,
        "instance_id": instance_id,
        "environment": environment,
        "stream_id": stream_id,
        "bundle_id": "sidecar-test",
        "sequence": sequence,
        "previous_config_hash": previous_config_hash,
        "config_hash": config_hash,
        "change_classes": change_classes,
        "signer_kids": ["declared-non-authoritative"],
        "apply_policy": apply_policy
    });

    let root_path = tough_fixture_dir("").join("simple-rsa").join("root.json");
    let key_path = tough_fixture_dir("").join("snakeoil.pem");
    let metadata_dir = repo.path().join("metadata");
    let targets_dir = repo.path().join("targets");
    let expiry = Utc::now()
        .checked_add_signed(TimeDelta::try_days(30).expect("duration"))
        .expect("future expiration");
    let version = NonZeroU64::new(sequence.max(1)).expect("non-zero version");
    let mut editor = RepositoryEditor::new(&root_path)
        .await
        .expect("editor loads root");
    editor.targets_expires(expiry).expect("targets expiration");
    editor.targets_version(version).expect("targets version");
    editor.snapshot_expires(expiry);
    editor.snapshot_version(version);
    editor.timestamp_expires(expiry);
    editor.timestamp_version(version);

    let mut target = Target::from_path(&target_path)
        .await
        .expect("target metadata builds");
    let Value::Object(custom) = custom else {
        panic!("custom metadata object");
    };
    target.custom = custom.into_iter().collect::<HashMap<_, _>>();
    editor
        .add_target(TARGET_NAME.to_string(), target)
        .expect("target metadata added");
    let keys: Vec<Box<dyn KeySource>> = vec![Box::new(LocalKeySource { path: key_path })];
    let signed = editor.sign(&keys).await.expect("repository signs");
    signed.write(&metadata_dir).await.expect("metadata writes");
    signed
        .link_targets(&source_targets, &targets_dir, PathExists::Skip)
        .await
        .expect("targets link");

    let input = LocalTufRepositoryInput {
        root_path: root_path.clone(),
        metadata_dir: metadata_dir.clone(),
        targets_dir: targets_dir.clone(),
        datastore_dir: datastore.path().to_path_buf(),
        target_name: TARGET_NAME.to_string(),
    };
    let verified = TufConfigVerifier::verify_config_target(
        &input,
        &VerificationContext {
            product: product.to_string(),
            instance_id: instance_id.to_string(),
            environment: environment.to_string(),
        },
    )
    .await
    .expect("generated repo verifies");
    let repo_path = repo.keep();
    let datastore_path = datastore.keep();
    SignedRepo {
        root_path,
        metadata_dir: repo_path.join("metadata"),
        targets_dir: repo_path.join("targets"),
        datastore_dir: datastore_path,
        tuf_root_sha256: verified.tuf.root_sha256,
        signer_kids: verified.tuf.signer_kids,
        config_hash,
    }
}

fn initialize_antirollback(repo: &SignedRepo, config_hash: &str, sequence: u64) {
    FileAntiRollbackStore::new(repo.datastore_dir.join("antirollback.json"))
        .initialize(AntiRollbackRecord {
            key: AntiRollbackKey {
                product: PRODUCT.to_string(),
                instance_id: INSTANCE_ID.to_string(),
                environment: ENVIRONMENT.to_string(),
                stream_id: STREAM_ID.to_string(),
            },
            last_sequence: sequence,
            last_config_hash: config_hash.to_string(),
            root_version: Some(1),
            break_glass: BreakGlassState::default(),
            local_approvals: LocalApprovalState::default(),
        })
        .expect("antirollback initializes");
}

fn bootstrap_yaml(repo: &SignedRepo) -> String {
    let signers = repo
        .signer_kids
        .iter()
        .map(|kid| {
            format!(
                r#"        {kid}:
          kid: {kid}
          enabled: true"#,
                kid = yaml_string(kid)
            )
        })
        .collect::<Vec<_>>()
        .join("\n");
    let role_signers = repo
        .signer_kids
        .iter()
        .map(|kid| format!("          - {}", yaml_string(kid)))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        r#"
server:
  bind: "127.0.0.1:0"
auth:
  bearer_tokens:
    - id: notary-contract
      hash_env: {token_hash_env}
audit:
  sink: file
  path: {audit_path}
  hash_secret_env: {audit_hash_secret_env}
config_trust:
  product: {product}
  instance_id: {instance_id}
  environment: {environment}
  stream_id: {stream_id}
  root_path: {root_path}
  metadata_dir: {metadata_dir}
  targets_dir: {targets_dir}
  datastore_dir: {datastore_dir}
  target_name: {target_name}
  antirollback_state_path: {antirollback_state_path}
  accepted_roots:
    - root_id: "test-root"
      production: false
      tuf_root_sha256: {tuf_root_sha256}
      high_risk_change_classes:
        - {change_class}
      signers:
{signers}
      roles:
        - name: "workflow"
          threshold: 1
          signer_kids:
{role_signers}
          allowed_change_classes:
            - {change_class}
"#,
        token_hash_env = yaml_string(TOKEN_HASH_ENV),
        audit_path = yaml_path(&repo.datastore_dir.join("sidecar-audit.jsonl")),
        audit_hash_secret_env = yaml_string(AUDIT_HASH_SECRET_ENV),
        product = yaml_string(PRODUCT),
        instance_id = yaml_string(INSTANCE_ID),
        environment = yaml_string(ENVIRONMENT),
        stream_id = yaml_string(STREAM_ID),
        root_path = yaml_path(&repo.root_path),
        metadata_dir = yaml_path(&repo.metadata_dir),
        targets_dir = yaml_path(&repo.targets_dir),
        datastore_dir = yaml_path(&repo.datastore_dir),
        target_name = yaml_string(TARGET_NAME),
        antirollback_state_path = yaml_path(&repo.datastore_dir.join("antirollback.json")),
        tuf_root_sha256 = yaml_string(&repo.tuf_root_sha256),
        change_class = CHANGE_CLASS,
        signers = signers,
        role_signers = role_signers,
    )
}

fn tough_fixture_dir(name: &str) -> PathBuf {
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cargo")))
        .expect("CARGO_HOME or HOME is set");
    let src_root = cargo_home.join("registry/src");
    let registry = fs::read_dir(&src_root)
        .expect("cargo registry src exists")
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .find(|path| path.join("tough-0.22.0/tests/data").is_dir())
        .expect("tough-0.22.0 source fixture directory exists");
    registry.join("tough-0.22.0/tests/data").join(name)
}
