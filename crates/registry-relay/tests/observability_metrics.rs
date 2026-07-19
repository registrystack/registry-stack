// SPDX-License-Identifier: Apache-2.0
//! Bounded observability tests for the admin-only Prometheus metrics surface.

use std::path::Path;
use std::sync::Arc;

use axum::http::StatusCode;
use axum_test::TestServer;
use datafusion::execution::context::SessionContext;
use registry_relay::audit::{AuditPipeline, InMemorySink};
use registry_relay::auth::api_key::{ApiKeyAuth, ApiKeyEntry};
use registry_relay::auth::ScopeSet;
use registry_relay::config::{self, Config};
use registry_relay::format::FormatRegistry;
use registry_relay::ingest::{IngestRegistry, ReadinessSnapshot, ReadyResource};
use registry_relay::server::{build_admin_app, build_app, build_app_with_readiness};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::sync::watch;
use ulid::Ulid;

const ADMIN_TOKEN: &str = "metrics-admin-token-0123456789";
const METRICS_TOKEN: &str = "metrics-read-token-0123456789";
const OPS_TOKEN: &str = "ops-read-token-0123456789";
const SENSITIVE_QUERY_VALUE: &str = "secret-query-value-7788";
const SENSITIVE_REQUEST_ID: &str = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
const SENSITIVE_KEY_ID: &str = "metrics_sensitive_key_id";
const SENSITIVE_PURPOSE: &str = "benefits-fraud-investigation-case-123";

struct MetricsFixture {
    _tmp: TempDir,
    public: TestServer,
    admin: TestServer,
    audit_sink: InMemorySink,
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

deployment:
  profile: local

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

audit:
  sink: stdout
  format: jsonl
  hash_secret_env: REGISTRY_RELAY_TEST_AUDIT_HASH_SECRET
"#,
        cache_dir = cache_dir.to_string_lossy(),
    );
    let path = tmp.path().join("metrics.yaml");
    std::fs::write(&path, yaml).expect("write config");
    path
}

fn build_auth() -> Arc<ApiKeyAuth> {
    let admin_entry = ApiKeyEntry::new(
        SENSITIVE_KEY_ID.to_string(),
        ScopeSet::from_iter(["registry_relay:admin"]),
        make_fingerprint(ADMIN_TOKEN),
    )
    .expect("admin fingerprint parses");
    let metrics_entry = ApiKeyEntry::new(
        "metrics_reader".to_string(),
        ScopeSet::from_iter(["registry_relay:metrics_read"]),
        make_fingerprint(METRICS_TOKEN),
    )
    .expect("metrics fingerprint parses");
    let ops_entry = ApiKeyEntry::new(
        "ops_reader".to_string(),
        ScopeSet::from_iter(["registry_relay:ops_read"]),
        make_fingerprint(OPS_TOKEN),
    )
    .expect("ops fingerprint parses");
    Arc::new(ApiKeyAuth::new(vec![admin_entry, metrics_entry, ops_entry]))
}

fn ready_snapshot() -> ReadinessSnapshot {
    let mut snapshot = ReadinessSnapshot::default();
    snapshot.ready.insert(
        (id("social_registry"), id("beneficiaries_csv")),
        ReadyResource {
            ingest_ulid: Ulid::from_string("01BX5ZZKBKACTAV9WEVGEMMVS0").unwrap(),
            registered_at: time::OffsetDateTime::now_utc(),
            consecutive_refresh_failures: 2,
        },
    );
    snapshot
}

fn build_fixture() -> MetricsFixture {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config(&tmp);
    std::env::set_var(
        "REGISTRY_RELAY_TEST_AUDIT_HASH_SECRET",
        "relay-observability-audit-secret-32-bytes",
    );
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
    let audit_sink = InMemorySink::new();
    let sink: Arc<AuditPipeline> = AuditPipeline::from_sink(audit_sink.clone());
    let public = TestServer::new(
        build_app_with_readiness(
            Arc::clone(&config),
            build_auth(),
            Arc::clone(&sink),
            readiness_rx.clone(),
        )
        .unwrap(),
    );
    let admin = TestServer::new(
        build_admin_app(
            config,
            build_auth(),
            sink,
            readiness_rx,
            readiness_tx,
            ingest,
        )
        .expect("admin app builds"),
    );

    MetricsFixture {
        _tmp: tmp,
        public,
        admin,
        audit_sink,
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

fn assert_contains_request_series(
    body: &str,
    method: &str,
    endpoint_kind: &str,
    status_code: u16,
    error_code: &str,
) {
    let expected = format!(
        "registry_relay_http_requests_total{{method=\"{method}\",endpoint_kind=\"{endpoint_kind}\",status_code=\"{status_code}\",status_class=\"4xx\",error_code=\"{error_code}\"}}"
    );
    assert!(
        body.lines().any(|line| line.starts_with(&expected)),
        "metrics response should include bounded request series {expected:?}:\n{body}"
    );
}

fn audit_record_from_platform_envelope(line: &str) -> serde_json::Value {
    let envelope: serde_json::Value =
        serde_json::from_str(line.trim_end()).expect("valid platform audit envelope");
    envelope["record"].clone()
}

fn assert_auth_denial_body(label: &str, body: &str, code: &str) {
    assert!(
        body.contains(code),
        "{label} denial should carry stable auth code {code}:\n{body}"
    );
    assert_denial_body_does_not_expose_admin_state(body);
}

fn assert_denied_audit_record(
    records: &[serde_json::Value],
    path: &str,
    endpoint_kind: &str,
    status_code: u16,
    error_code: &str,
) {
    let record = records
        .iter()
        .find(|record| {
            record["path"] == path
                && record["status_code"] == status_code
                && record["error_code"] == error_code
        })
        .unwrap_or_else(|| panic!("denied audit record is present for {path} {error_code}"));
    assert_eq!(record["endpoint_kind"], endpoint_kind);
}

fn assert_denial_body_does_not_expose_admin_state(body: &str) {
    for forbidden in [
        "# HELP",
        "registry_relay_http_requests_total",
        "registry_relay_readiness_ready_resources",
        "registry_relay_datasource_live_scans_total",
        "reloaded",
        "succeeded",
        "failed",
        "beneficiaries_csv",
        "01BX5ZZKBKACTAV9WEVGEMMVS0",
        ADMIN_TOKEN,
        METRICS_TOKEN,
        OPS_TOKEN,
        SENSITIVE_KEY_ID,
    ] {
        assert!(
            !body.contains(forbidden),
            "denial response must not expose privileged value {forbidden:?}:\n{body}"
        );
    }
}

#[tokio::test]
async fn metrics_requires_metrics_scope_on_admin_listener() {
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
        .assert_status(StatusCode::UNAUTHORIZED);
    fixture
        .admin
        .get("/metrics")
        .add_header("x-api-key", ADMIN_TOKEN)
        .await
        .assert_status(StatusCode::FORBIDDEN);
    fixture
        .admin
        .get("/metrics")
        .add_header("x-api-key", METRICS_TOKEN)
        .await
        .assert_status(StatusCode::OK);
}

#[tokio::test]
async fn denied_admin_and_metrics_requests_do_not_leak_privileged_surfaces() {
    let fixture = build_fixture();

    let unauthenticated_capabilities = fixture.admin.get("/admin/v1/capabilities").await;
    unauthenticated_capabilities.assert_status(StatusCode::UNAUTHORIZED);
    let unauthenticated_capabilities_body = unauthenticated_capabilities.text();
    assert_auth_denial_body(
        "unauthenticated capabilities",
        &unauthenticated_capabilities_body,
        "auth.missing_credential",
    );

    let denied_capabilities = fixture
        .admin
        .get("/admin/v1/capabilities")
        .add_header("x-api-key", METRICS_TOKEN)
        .await;
    denied_capabilities.assert_status(StatusCode::FORBIDDEN);
    let denied_capabilities_body = denied_capabilities.text();
    assert_auth_denial_body(
        "capabilities",
        &denied_capabilities_body,
        "auth.scope_denied",
    );

    let unauthenticated_posture = fixture.admin.get("/admin/v1/posture?tier=restricted").await;
    unauthenticated_posture.assert_status(StatusCode::UNAUTHORIZED);
    let unauthenticated_posture_body = unauthenticated_posture.text();
    assert_auth_denial_body(
        "unauthenticated posture",
        &unauthenticated_posture_body,
        "auth.missing_credential",
    );

    let denied_posture = fixture
        .admin
        .get("/admin/v1/posture?tier=restricted")
        .add_header("x-api-key", METRICS_TOKEN)
        .await;
    denied_posture.assert_status(StatusCode::FORBIDDEN);
    let denied_posture_body = denied_posture.text();
    assert_auth_denial_body("posture", &denied_posture_body, "auth.scope_denied");

    let unauthenticated_reload = fixture.admin.post("/admin/v1/reload").await;
    unauthenticated_reload.assert_status(StatusCode::UNAUTHORIZED);
    let unauthenticated_reload_body = unauthenticated_reload.text();
    assert_auth_denial_body(
        "unauthenticated reload",
        &unauthenticated_reload_body,
        "auth.missing_credential",
    );

    let denied_reload = fixture
        .admin
        .post("/admin/v1/reload")
        .add_header("x-api-key", METRICS_TOKEN)
        .await;
    denied_reload.assert_status(StatusCode::FORBIDDEN);
    let denied_reload_body = denied_reload.text();
    assert_auth_denial_body("reload", &denied_reload_body, "auth.scope_denied");

    let unauthenticated_table_reload = fixture
        .admin
        .post("/admin/v1/datasets/social_registry/tables/beneficiaries_csv/reload")
        .await;
    unauthenticated_table_reload.assert_status(StatusCode::UNAUTHORIZED);
    let unauthenticated_table_reload_body = unauthenticated_table_reload.text();
    assert_auth_denial_body(
        "unauthenticated table reload",
        &unauthenticated_table_reload_body,
        "auth.missing_credential",
    );

    let denied_table_reload = fixture
        .admin
        .post("/admin/v1/datasets/social_registry/tables/beneficiaries_csv/reload")
        .add_header("x-api-key", METRICS_TOKEN)
        .await;
    denied_table_reload.assert_status(StatusCode::FORBIDDEN);
    let denied_table_reload_body = denied_table_reload.text();
    assert_auth_denial_body(
        "table reload",
        &denied_table_reload_body,
        "auth.scope_denied",
    );

    let unauthenticated_metrics = fixture.admin.get("/metrics").await;
    unauthenticated_metrics.assert_status(StatusCode::UNAUTHORIZED);
    let unauthenticated_metrics_body = unauthenticated_metrics.text();
    assert_auth_denial_body(
        "unauthenticated metrics",
        &unauthenticated_metrics_body,
        "auth.missing_credential",
    );

    let denied_metrics = fixture
        .admin
        .get("/metrics")
        .add_header("x-api-key", ADMIN_TOKEN)
        .await;
    denied_metrics.assert_status(StatusCode::FORBIDDEN);
    let denied_metrics_body = denied_metrics.text();
    assert_auth_denial_body("metrics", &denied_metrics_body, "auth.scope_denied");

    let audit_lines = fixture.audit_sink.snapshot();
    assert!(
        audit_lines.len() >= 10,
        "denied admin and metrics requests should be auditable: {audit_lines:?}"
    );
    let records = audit_lines
        .iter()
        .map(|line| audit_record_from_platform_envelope(line))
        .collect::<Vec<_>>();
    for (path, endpoint_kind) in [
        ("/admin/v1/capabilities", "admin"),
        ("/admin/v1/posture", "admin"),
        ("/admin/v1/reload", "admin"),
        (
            "/admin/v1/datasets/social_registry/tables/beneficiaries_csv/reload",
            "admin",
        ),
        ("/metrics", "other"),
    ] {
        assert_denied_audit_record(
            &records,
            path,
            endpoint_kind,
            401,
            "auth.missing_credential",
        );
        assert_denied_audit_record(&records, path, endpoint_kind, 403, "auth.scope_denied");
    }

    let metrics = fixture
        .admin
        .get("/metrics")
        .add_header("x-api-key", METRICS_TOKEN)
        .await;
    metrics.assert_status(StatusCode::OK);
    let body = metrics.text();
    assert_contains_request_series(&body, "POST", "admin", 401, "auth.missing_credential");
    assert_contains_request_series(&body, "POST", "admin", 403, "auth.scope_denied");
    assert_contains_request_series(&body, "GET", "admin", 401, "auth.missing_credential");
    assert_contains_request_series(&body, "GET", "admin", 403, "auth.scope_denied");
}

#[tokio::test]
async fn metrics_response_is_plain_prometheus_text_with_request_and_readiness_metrics() {
    let fixture = build_fixture();
    fixture
        .public
        .get("/healthz")
        .await
        .assert_status(StatusCode::OK);
    fixture
        .public
        .get("/ready")
        .await
        .assert_status(StatusCode::OK);
    fixture
        .admin
        .get("/healthz")
        .await
        .assert_status(StatusCode::OK);

    let resp = fixture
        .admin
        .get("/metrics")
        .add_header("x-api-key", METRICS_TOKEN)
        .await;
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
    assert!(body.contains(
        "registry_relay_ingest_consecutive_refresh_failures{dataset_id=\"social_registry\",resource_id=\"beneficiaries_csv\"} 2"
    ));
    assert!(body.contains(
        "registry_relay_ingest_last_successful_refresh_timestamp_seconds{dataset_id=\"social_registry\",resource_id=\"beneficiaries_csv\"} "
    ));
    assert_eq!(
        body.lines()
            .filter(|line| line.starts_with("registry_relay_ingest_consecutive_refresh_failures{"))
            .count(),
        1,
        "refresh-failure series cardinality is bounded by configured ready resources"
    );
}

#[tokio::test]
async fn per_resource_refresh_health_is_restricted_to_authorized_posture() {
    let fixture = build_fixture();

    let default = fixture
        .admin
        .get("/admin/v1/posture")
        .add_header("x-api-key", OPS_TOKEN)
        .await;
    default.assert_status(StatusCode::OK);
    let default: serde_json::Value = default.json();
    assert!(default["relay"].get("refresh_health").is_none());

    let restricted = fixture
        .admin
        .get("/admin/v1/posture?tier=restricted")
        .add_header("x-api-key", OPS_TOKEN)
        .await;
    restricted.assert_status(StatusCode::OK);
    let restricted: serde_json::Value = restricted.json();
    assert_eq!(restricted["tier"], "restricted");
    assert_eq!(
        restricted["relay"]["refresh_health"][0]["dataset_id"],
        "social_registry"
    );
    assert_eq!(
        restricted["relay"]["refresh_health"][0]["resource_id"],
        "beneficiaries_csv"
    );
    assert_eq!(
        restricted["relay"]["refresh_health"][0]["consecutive_refresh_failures"],
        2
    );
    assert_eq!(
        restricted["relay"]["refresh_health"][0]["serving_last_good"],
        true
    );
}

#[tokio::test]
async fn metrics_do_not_expose_sensitive_or_high_cardinality_values() {
    let fixture = build_fixture();

    fixture
        .admin
        .post(&format!("/admin/v1/reload?raw={SENSITIVE_QUERY_VALUE}"))
        .add_header("Authorization", format!("Bearer {ADMIN_TOKEN}"))
        .add_header("Data-Purpose", SENSITIVE_PURPOSE)
        .add_header("x-request-id", SENSITIVE_REQUEST_ID)
        .await
        .assert_status(StatusCode::OK);
    fixture
        .public
        .get(&format!(
            "/healthz?request_id={SENSITIVE_REQUEST_ID}&purpose={SENSITIVE_PURPOSE}"
        ))
        .await
        .assert_status(StatusCode::OK);

    let resp = fixture
        .admin
        .get("/metrics")
        .add_header("x-api-key", METRICS_TOKEN)
        .await;
    resp.assert_status(StatusCode::OK);
    let body = resp.text();
    for forbidden in [
        SENSITIVE_QUERY_VALUE,
        SENSITIVE_REQUEST_ID,
        ADMIN_TOKEN,
        OPS_TOKEN,
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
    std::env::set_var(
        "REGISTRY_RELAY_TEST_AUDIT_HASH_SECRET",
        "relay-observability-audit-secret-32-bytes",
    );
    let config: Arc<Config> = Arc::new(config::load(&config_path).expect("config loads"));
    let sink: Arc<AuditPipeline> = AuditPipeline::from_sink(InMemorySink::new());
    let public = TestServer::new(build_app(config, build_auth(), sink).unwrap());

    let resp = public.get("/metrics").await;
    assert!(
        !resp.status_code().is_success(),
        "public listener must not expose /metrics"
    );
}
