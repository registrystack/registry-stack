// SPDX-License-Identifier: Apache-2.0
//! Focused production-wiring tests for the admin reload API slice.

use std::path::Path;
use std::sync::Arc;

use axum::http::StatusCode;
use axum_test::TestServer;
use datafusion::execution::context::SessionContext;
use registry_relay::audit::{AuditSink, InMemorySink};
use registry_relay::auth::api_key::{ApiKeyAuth, ApiKeyEntry};
use registry_relay::auth::ScopeSet;
use registry_relay::config::{self, Config};
use registry_relay::format::FormatRegistry;
use registry_relay::ingest::{IngestRegistry, ReadinessSnapshot};
use registry_relay::server::build_admin_app;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::sync::watch;

const ADMIN_KEY: &str = "admin-test-token-0123456789";
const NON_ADMIN_KEY: &str = "non-admin-test-token-0123456789";

struct AdminFixture {
    _tmp: TempDir,
    server: TestServer,
}

fn fixture(name: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(name)
        .to_string_lossy()
        .into_owned()
}

fn make_fingerprint(plain: &str) -> String {
    format!("sha256:{}", hex_lower(&Sha256::digest(plain.as_bytes())))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn write_config(tmp: &TempDir) -> std::path::PathBuf {
    let cache_dir = tmp.path().join("cache");
    let source_path = fixture("social_registry.csv");
    let yaml = format!(
        r#"
server:
  bind: 127.0.0.1:0
  admin_bind: 127.0.0.1:0
  cache_dir: "{cache_dir}"

catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test Ministry

vocabularies: {{}}

auth:
  mode: api_key
  api_keys: []

datasets:
  - id: social_registry
    title: Social Registry
    description: Synthetic registry
    owner: Test
    sensitivity: personal
    access_rights: restricted
    update_frequency: monthly
    defaults:
      refresh:
        mode: manual
    tables:
      - id: beneficiaries_csv
        source:
          type: file
          path: "{source_path}"
          format:
            csv:
              header_row: 1
        primary_key: beneficiary_id
        schema:
          strict: true
          fields:
            - name: beneficiary_id
              type: integer
              nullable: false
            - name: household_size
              type: integer
              nullable: false
            - name: municipality_code
              type: string
              nullable: false
            - name: program
              type: string
              nullable: false
            - name: amount_eur
              type: number
              nullable: false
            - name: joined_date
              type: date
              nullable: false
            - name: last_updated
              type: date
              nullable: true
        access:
          metadata_scope: social_registry:metadata
          aggregate_scope: social_registry:aggregate
          row_scope: social_registry:rows
        api:
          default_limit: 100
          max_limit: 1000
      - id: beneficiaries_copy_csv
        source:
          type: file
          path: "{source_path}"
          format:
            csv:
              header_row: 1
        primary_key: beneficiary_id
        schema:
          strict: true
          fields:
            - name: beneficiary_id
              type: integer
              nullable: false
            - name: household_size
              type: integer
              nullable: false
            - name: municipality_code
              type: string
              nullable: false
            - name: program
              type: string
              nullable: false
            - name: amount_eur
              type: number
              nullable: false
            - name: joined_date
              type: date
              nullable: false
            - name: last_updated
              type: date
              nullable: true
        access:
          metadata_scope: social_registry:metadata
          aggregate_scope: social_registry:aggregate
          row_scope: social_registry:rows
        api:
          default_limit: 100
          max_limit: 1000

audit:
  sink: stdout
  format: jsonl
"#,
        cache_dir = cache_dir.to_string_lossy(),
    );
    let path = tmp.path().join("admin-reload.yaml");
    std::fs::write(&path, yaml).expect("write config");
    path
}

fn build_auth() -> Arc<ApiKeyAuth> {
    let entries = vec![
        ApiKeyEntry::new(
            "admin".to_string(),
            ScopeSet::from_iter(["admin"]),
            make_fingerprint(ADMIN_KEY),
        )
        .expect("admin fingerprint parses"),
        ApiKeyEntry::new(
            "reader".to_string(),
            ScopeSet::from_iter(["social_registry:metadata"]),
            make_fingerprint(NON_ADMIN_KEY),
        )
        .expect("reader fingerprint parses"),
    ];
    Arc::new(ApiKeyAuth::new(entries))
}

fn build_fixture() -> AdminFixture {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config(&tmp);
    let config: Arc<Config> = Arc::new(config::load(&config_path).expect("config loads"));
    let df_ctx = Arc::new(SessionContext::new());
    let ingest = Arc::new(
        IngestRegistry::from_config(
            &config,
            Arc::new(FormatRegistry::with_v1_defaults()),
            Arc::from(config.server.cache_dir.as_path()),
            df_ctx,
        )
        .expect("ingest registry builds"),
    );
    let (readiness_tx, readiness_rx) = watch::channel::<ReadinessSnapshot>(ingest.snapshot());
    let sink: Arc<dyn AuditSink> = Arc::new(InMemorySink::new());
    let app = build_admin_app(
        config,
        build_auth(),
        sink,
        readiness_rx,
        readiness_tx,
        ingest,
    );

    AdminFixture {
        _tmp: tmp,
        server: TestServer::new(app),
    }
}

async fn assert_problem(resp: axum_test::TestResponse, status: StatusCode, code: &str) -> Value {
    resp.assert_status(status);
    assert!(resp
        .header("content-type")
        .to_str()
        .expect("content-type is ASCII")
        .starts_with("application/problem+json"));
    let body: Value = resp.json();
    assert_eq!(body["code"], code);
    body
}

#[tokio::test]
async fn health_remains_unauthenticated_on_admin_app() {
    let fixture = build_fixture();

    let resp = fixture.server.get("/health").await;

    resp.assert_status(StatusCode::OK);
    assert_eq!(resp.json::<Value>(), serde_json::json!({"status": "ok"}));
}

#[tokio::test]
async fn table_reload_without_credential_is_rejected() {
    let fixture = build_fixture();

    let resp = fixture
        .server
        .post("/admin/datasets/social_registry/tables/beneficiaries_csv/reload")
        .await;

    assert_problem(resp, StatusCode::UNAUTHORIZED, "auth.missing_credential").await;
}

#[tokio::test]
async fn table_reload_with_non_admin_key_is_rejected() {
    let fixture = build_fixture();

    let resp = fixture
        .server
        .post("/admin/datasets/social_registry/tables/beneficiaries_csv/reload")
        .add_header("Authorization", format!("Bearer {NON_ADMIN_KEY}"))
        .await;

    let body = assert_problem(resp, StatusCode::FORBIDDEN, "auth.scope_denied").await;
    assert_eq!(body["detail"], "required scope: admin");
}

#[tokio::test]
async fn table_reload_with_admin_key_reaches_registry_reload_path() {
    let fixture = build_fixture();

    let resp = fixture
        .server
        .post("/admin/datasets/social_registry/tables/beneficiaries_csv/reload")
        .add_header("Authorization", format!("Bearer {ADMIN_KEY}"))
        .await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["dataset_id"], "social_registry");
    assert_eq!(body["table_id"], "beneficiaries_csv");
}

#[tokio::test]
async fn table_reload_publishes_updated_readiness_snapshot() {
    let fixture = build_fixture();

    let before = fixture.server.get("/ready").await;
    let before_body = assert_problem(
        before,
        StatusCode::SERVICE_UNAVAILABLE,
        "schema.resource_unavailable",
    )
    .await;
    assert_eq!(before_body["not_ready_count"], 2);

    fixture
        .server
        .post("/admin/datasets/social_registry/tables/beneficiaries_csv/reload")
        .add_header("Authorization", format!("Bearer {ADMIN_KEY}"))
        .await
        .assert_status(StatusCode::OK);

    let after = fixture.server.get("/ready").await;
    let after_body = assert_problem(
        after,
        StatusCode::SERVICE_UNAVAILABLE,
        "schema.resource_unavailable",
    )
    .await;
    assert_eq!(after_body["not_ready_count"], 1);
}

#[tokio::test]
async fn reload_all_without_credential_is_rejected() {
    let fixture = build_fixture();

    let resp = fixture.server.post("/admin/reload").await;

    assert_problem(resp, StatusCode::UNAUTHORIZED, "auth.missing_credential").await;
}

#[tokio::test]
async fn reload_all_with_non_admin_key_is_rejected() {
    let fixture = build_fixture();

    let resp = fixture
        .server
        .post("/admin/reload")
        .add_header("Authorization", format!("Bearer {NON_ADMIN_KEY}"))
        .await;

    let body = assert_problem(resp, StatusCode::FORBIDDEN, "auth.scope_denied").await;
    assert_eq!(body["detail"], "required scope: admin");
}

#[tokio::test]
async fn reload_all_with_admin_key_reloads_every_configured_resource() {
    let fixture = build_fixture();

    let resp = fixture
        .server
        .post("/admin/reload")
        .add_header("Authorization", format!("Bearer {ADMIN_KEY}"))
        .await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["counts"]["total"], 2);
    assert_eq!(body["counts"]["succeeded"], 2);
    assert_eq!(body["counts"]["failed"], 0);

    let resources = body["resources"].as_array().expect("resources array");
    assert_eq!(resources.len(), 2);
    assert!(resources.iter().any(|resource| {
        resource["dataset_id"] == "social_registry"
            && resource["resource_id"] == "beneficiaries_csv"
            && resource["status"] == "ok"
            && resource.get("error_code").is_none()
    }));
    assert!(resources.iter().any(|resource| {
        resource["dataset_id"] == "social_registry"
            && resource["resource_id"] == "beneficiaries_copy_csv"
            && resource["status"] == "ok"
            && resource.get("error_code").is_none()
    }));
}

#[tokio::test]
async fn reload_all_publishes_ready_snapshot() {
    let fixture = build_fixture();

    fixture
        .server
        .post("/admin/reload")
        .add_header("Authorization", format!("Bearer {ADMIN_KEY}"))
        .await
        .assert_status(StatusCode::OK);

    let resp = fixture.server.get("/ready").await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(body["status"], "ok");
    assert_eq!(
        body["resources"].as_array().expect("resources array").len(),
        2
    );
}
