// SPDX-License-Identifier: Apache-2.0
//! Bounded observability tests for the admin-only Prometheus metrics surface.

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
use registry_relay::ingest::{IngestRegistry, ReadinessSnapshot, ReadyResource};
use registry_relay::observability::{observe_live_datasource_scan, LiveScanObservation};
use registry_relay::server::{build_admin_app, build_app, build_app_with_readiness};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::sync::watch;
use ulid::Ulid;

const ADMIN_TOKEN: &str = "metrics-admin-token-0123456789";
const SENSITIVE_QUERY_VALUE: &str = "secret-query-value-7788";
const SENSITIVE_REQUEST_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const SENSITIVE_KEY_ID: &str = "metrics_sensitive_key_id";
const SENSITIVE_PURPOSE: &str = "benefits-fraud-investigation-case-123";

struct MetricsFixture {
    _tmp: TempDir,
    public: TestServer,
    admin: TestServer,
}

fn fixture(name: &str) -> String {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(name)
        .to_string_lossy()
        .into_owned()
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

fn make_fingerprint(plain: &str) -> String {
    format!("sha256:{}", hex_lower(&Sha256::digest(plain.as_bytes())))
}

fn id<T: serde::de::DeserializeOwned>(value: &str) -> T {
    serde_json::from_str(&format!(r#""{value}""#)).expect("id deserializes")
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

audit:
  sink: stdout
  format: jsonl
"#,
        cache_dir = cache_dir.to_string_lossy(),
    );
    let path = tmp.path().join("metrics.yaml");
    std::fs::write(&path, yaml).expect("write config");
    path
}

fn build_auth() -> Arc<ApiKeyAuth> {
    let entry = ApiKeyEntry::new(
        SENSITIVE_KEY_ID.to_string(),
        ScopeSet::from_iter(["admin"]),
        make_fingerprint(ADMIN_TOKEN),
    )
    .expect("admin fingerprint parses");
    Arc::new(ApiKeyAuth::new(vec![entry]))
}

fn ready_snapshot() -> ReadinessSnapshot {
    let mut snapshot = ReadinessSnapshot::default();
    snapshot.ready.insert(
        (id("social_registry"), id("beneficiaries_csv")),
        ReadyResource {
            ingest_ulid: Ulid::from_string("01BX5ZZKBKACTAV9WEVGEMMVS0").unwrap(),
            registered_at: time::OffsetDateTime::now_utc(),
        },
    );
    snapshot
}

fn build_fixture() -> MetricsFixture {
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
    let (readiness_tx, readiness_rx) = watch::channel::<ReadinessSnapshot>(ready_snapshot());
    let sink: Arc<dyn AuditSink> = Arc::new(InMemorySink::new());
    let public = TestServer::new(
        build_app_with_readiness(
            Arc::clone(&config),
            build_auth(),
            Arc::clone(&sink),
            readiness_rx.clone(),
        )
        .unwrap(),
    );
    let admin = TestServer::new(build_admin_app(
        config,
        build_auth(),
        sink,
        readiness_rx,
        readiness_tx,
        ingest,
    ));

    MetricsFixture {
        _tmp: tmp,
        public,
        admin,
    }
}

fn assert_prometheus_text(body: &str) {
    assert!(
        body.contains("# HELP") && body.contains("# TYPE"),
        "metrics response should include Prometheus HELP/TYPE lines:\n{body}"
    );
    assert!(
        body.lines().any(|line| line.contains("_total")),
        "metrics response should include a counter-style _total metric:\n{body}"
    );
}

fn assert_contains_request_metrics(body: &str) {
    assert!(
        body.contains("requests_total"),
        "metrics response should include a low-cardinality request counter:\n{body}"
    );
    assert!(
        body.contains("request_duration") || body.contains("request_seconds"),
        "metrics response should include a low-cardinality request duration metric:\n{body}"
    );
}

fn assert_contains_readiness_gauge(body: &str) {
    assert!(
        body.contains("readiness") || body.contains("ready"),
        "metrics response should include readiness gauge metrics:\n{body}"
    );
}

fn assert_contains_live_datasource_metrics(body: &str) {
    assert!(
        body.contains("registry_relay_datasource_live_scans_total"),
        "metrics response should include live datasource scan counters:\n{body}"
    );
    assert!(
        body.contains("registry_relay_datasource_live_scan_duration_seconds"),
        "metrics response should include live datasource scan duration histograms:\n{body}"
    );
    assert!(
        body.contains("datasource=\"postgres\"") && body.contains("projection_pushdown=\"yes\""),
        "metrics response should include bounded live scan labels:\n{body}"
    );
}

#[tokio::test]
async fn metrics_is_admin_only() {
    let fixture = build_fixture();

    let public_resp = fixture.public.get("/metrics").await;
    assert!(
        !public_resp.status_code().is_success(),
        "public listener must not expose /metrics"
    );

    fixture
        .admin
        .get("/metrics")
        .await
        .assert_status(StatusCode::OK);
}

#[tokio::test]
async fn metrics_response_is_plain_prometheus_text_with_request_and_readiness_metrics() {
    let fixture = build_fixture();
    observe_live_datasource_scan(LiveScanObservation {
        datasource: "postgres",
        status: "success",
        projection_pushdown: true,
        duration_seconds: 0.042,
        wait_seconds: 0.001,
        rows: 3,
        bytes: 128,
    });

    fixture
        .public
        .get("/health")
        .await
        .assert_status(StatusCode::OK);
    fixture
        .public
        .get("/ready")
        .await
        .assert_status(StatusCode::OK);
    fixture
        .admin
        .get("/health")
        .await
        .assert_status(StatusCode::OK);

    let resp = fixture.admin.get("/metrics").await;
    resp.assert_status(StatusCode::OK);
    let content_type = resp
        .headers()
        .get("content-type")
        .expect("content-type header")
        .to_str()
        .expect("content-type is ASCII");
    assert!(
        content_type.starts_with("text/plain"),
        "expected text/plain metrics response, got {content_type}"
    );

    let body = resp.text();
    assert_prometheus_text(&body);
    assert_contains_request_metrics(&body);
    assert_contains_readiness_gauge(&body);
    assert_contains_live_datasource_metrics(&body);
}

#[tokio::test]
async fn metrics_do_not_expose_sensitive_or_high_cardinality_values() {
    let fixture = build_fixture();

    fixture
        .admin
        .post(&format!("/admin/reload?raw={SENSITIVE_QUERY_VALUE}"))
        .add_header("Authorization", format!("Bearer {ADMIN_TOKEN}"))
        .add_header("Data-Purpose", SENSITIVE_PURPOSE)
        .add_header("x-request-id", SENSITIVE_REQUEST_ID)
        .await
        .assert_status(StatusCode::OK);
    fixture
        .public
        .get(&format!(
            "/health?request_id={SENSITIVE_REQUEST_ID}&purpose={SENSITIVE_PURPOSE}"
        ))
        .await
        .assert_status(StatusCode::OK);

    let resp = fixture.admin.get("/metrics").await;
    resp.assert_status(StatusCode::OK);
    let body = resp.text();
    for forbidden in [
        SENSITIVE_QUERY_VALUE,
        SENSITIVE_REQUEST_ID,
        ADMIN_TOKEN,
        SENSITIVE_KEY_ID,
        SENSITIVE_PURPOSE,
    ] {
        assert!(
            !body.contains(forbidden),
            "metrics response must not expose sensitive value {forbidden:?}:\n{body}"
        );
    }
}

#[tokio::test]
async fn bare_public_app_does_not_mount_metrics() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config(&tmp);
    let config: Arc<Config> = Arc::new(config::load(&config_path).expect("config loads"));
    let sink: Arc<dyn AuditSink> = Arc::new(InMemorySink::new());
    let public = TestServer::new(build_app(config, build_auth(), sink).unwrap());

    let resp = public.get("/metrics").await;
    assert!(
        !resp.status_code().is_success(),
        "public listener must not expose /metrics"
    );
}
