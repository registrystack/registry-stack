// SPDX-License-Identifier: Apache-2.0
//! Focused production-wiring tests for the admin reload API slice.

use std::path::Path;
use std::sync::Arc;

use argon2::password_hash::SaltString;
use argon2::{Argon2, PasswordHasher};
use axum::http::StatusCode;
use axum_test::TestServer;
use data_gate::audit::{AuditSink, InMemorySink};
use data_gate::auth::api_key::{ApiKeyAuth, ApiKeyEntry};
use data_gate::auth::ScopeSet;
use data_gate::config::{self, Config};
use data_gate::format::FormatRegistry;
use data_gate::ingest::{IngestRegistry, ReadinessSnapshot};
use data_gate::server::build_admin_app;
use datafusion::execution::context::SessionContext;
use serde_json::Value;
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

fn make_phc(plain: &str) -> String {
    let salt =
        SaltString::from_b64("YWRtaW5yZWxvYWRmaXh0dXJl").expect("static test salt parses as b64");
    Argon2::default()
        .hash_password(plain.as_bytes(), &salt)
        .expect("argon2 hash should succeed for a test fixture")
        .to_string()
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
    source:
      type: file
      path: "{source_path}"
      header_row: 1
    refresh:
      mode: manual
    resources:
      - id: beneficiaries_csv
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
            make_phc(ADMIN_KEY),
        )
        .expect("admin PHC parses"),
        ApiKeyEntry::new(
            "reader".to_string(),
            ScopeSet::from_iter(["social_registry:metadata"]),
            make_phc(NON_ADMIN_KEY),
        )
        .expect("reader PHC parses"),
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
    let (_readiness_tx, readiness_rx) = watch::channel::<ReadinessSnapshot>(ingest.snapshot());
    let sink: Arc<dyn AuditSink> = Arc::new(InMemorySink::new());
    let app = build_admin_app(config, build_auth(), sink, readiness_rx, ingest);

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
async fn reload_all_with_admin_key_returns_not_implemented() {
    let fixture = build_fixture();

    let resp = fixture
        .server
        .post("/admin/reload")
        .add_header("Authorization", format!("Bearer {ADMIN_KEY}"))
        .await;

    // The endpoint is authenticated but not yet implemented; it returns
    // 501 once the scope check passes.
    assert_problem(
        resp,
        StatusCode::NOT_IMPLEMENTED,
        "admin.reload_unavailable",
    )
    .await;
}
