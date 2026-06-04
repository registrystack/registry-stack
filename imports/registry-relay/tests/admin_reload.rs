// SPDX-License-Identifier: Apache-2.0
//! Focused production-wiring tests for the admin reload API slice.

use std::path::Path;
use std::sync::Arc;

use axum::http::StatusCode;
use axum_test::TestServer;
use datafusion::execution::context::SessionContext;
use registry_relay::audit::{AuditPipeline, InMemorySink};
use registry_relay::auth::api_key::{ApiKeyAuth, ApiKeyEntry};
use registry_relay::auth::ScopeSet;
use registry_relay::config::{self, Config};
use registry_relay::entity::EntityRegistry;
use registry_relay::format::FormatRegistry;
use registry_relay::ingest::{IngestRegistry, ReadinessSnapshot};
use registry_relay::query::{AggregateQueryEngine, EntityQueryEngine};
use registry_relay::server::{build_admin_app, build_app_with_entity_query};
use serde_json::Value;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::sync::watch;

const ADMIN_KEY: &str = "admin-test-token-0123456789";
const NON_ADMIN_KEY: &str = "non-admin-test-token-0123456789";
const OPS_KEY: &str = "ops-test-token-0123456789";
const AUDIT_SECRET_VALUE: &str = "relay-admin-reload-audit-secret-32-bytes";
const PRIVATE_JWK_VALUE: &str = r#"{"kty":"OKP","crv":"Ed25519","kid":"relay-private-key","d":"private-jwk-material","x":"public-jwk-material"}"#;

struct AdminFixture {
    _tmp: TempDir,
    server: TestServer,
    public_server: TestServer,
    source_path: std::path::PathBuf,
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

fn assert_matches_posture_schema(body: &Value) {
    let schema: Value = serde_json::from_str(registry_platform_ops::POSTURE_SCHEMA_V1)
        .expect("posture schema parses");
    let compiled = jsonschema::JSONSchema::compile(&schema).expect("posture schema compiles");
    let errors = compiled
        .validate(body)
        .err()
        .map(|errors| errors.map(|error| error.to_string()).collect::<Vec<_>>())
        .unwrap_or_default();
    assert!(
        errors.is_empty(),
        "posture response did not match registry.ops.posture.v1: {errors:?}\n{body:#}"
    );
}

fn write_config(tmp: &TempDir) -> std::path::PathBuf {
    write_config_with_instance(
        tmp,
        Some(
            r#"instance:
  id: relay-test-instance
  environment: lab
  owner: Test Ministry
  jurisdiction: ZZ
"#,
        ),
    )
}

fn write_config_with_instance(tmp: &TempDir, instance_block: Option<&str>) -> std::path::PathBuf {
    let cache_dir = tmp.path().join("cache");
    let source_path = tmp.path().join("social_registry.csv");
    std::fs::copy(fixture("social_registry.csv"), &source_path).expect("copy source fixture");
    let instance_block = instance_block.unwrap_or("");
    let yaml = format!(
        r#"
{instance_block}
server:
  bind: 127.0.0.1:0
  admin_bind: 127.0.0.1:0
  cache_dir: "{cache_dir}"

metadata:
  manifest_path: metadata.yaml

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
        api:
          default_limit: 100
          max_limit: 1000
    entities:
      - name: beneficiary
        table: beneficiaries_csv
        fields:
          - name: id
            from: beneficiary_id
          - name: household_size
            from: household_size
          - name: municipality_code
            from: municipality_code
          - name: program
            from: program
          - name: amount_eur
            from: amount_eur
          - name: joined_date
            from: joined_date
          - name: last_updated
            from: last_updated
        access:
          metadata_scope: social_registry:metadata
          aggregate_scope: social_registry:aggregate
          read_scope: social_registry:rows
        api:
          default_limit: 100
          max_limit: 1000

audit:
  sink: stdout
  format: jsonl
  hash_secret_env: REGISTRY_RELAY_TEST_AUDIT_HASH_SECRET

provenance:
  enabled: false
  accepted_media_types:
    - application/vc+jwt
  schema_base_url: https://data.example.test/schemas
  context_base_url: https://data.example.test/contexts
  claim_validity:
    aggregate_result: 10m
    entity_record: 10m
  issuer:
    mode: gateway
    did: did:web:data.example.test
    verification_method_id: did:web:data.example.test#relay-public-key
    signer:
      kind: software
      jwk_env: REGISTRY_RELAY_TEST_PRIVATE_JWK
      signing_algorithm: EdDSA
"#,
        instance_block = instance_block,
        cache_dir = cache_dir.to_string_lossy(),
        source_path = source_path.to_string_lossy(),
    );
    let path = tmp.path().join("admin-reload.yaml");
    std::fs::write(&path, yaml).expect("write config");
    path
}

fn build_fixture_from_config_path(tmp: TempDir, config_path: std::path::PathBuf) -> AdminFixture {
    #[allow(unused_unsafe)]
    unsafe {
        std::env::set_var("REGISTRY_RELAY_TEST_AUDIT_HASH_SECRET", AUDIT_SECRET_VALUE);
        std::env::set_var("REGISTRY_RELAY_TEST_PRIVATE_JWK", PRIVATE_JWK_VALUE);
    }
    let config: Arc<Config> = Arc::new(config::load(&config_path).expect("config loads"));
    let df_ctx = Arc::new(SessionContext::new());
    let ingest = Arc::new(
        IngestRegistry::from_config(
            &config,
            Arc::new(FormatRegistry::with_v1_defaults()),
            Arc::from(config.server.cache_dir.as_path()),
            Arc::clone(&df_ctx),
        )
        .expect("ingest registry builds"),
    );
    let (readiness_tx, readiness_rx) = watch::channel::<ReadinessSnapshot>(ingest.snapshot());
    let sink: Arc<AuditPipeline> = AuditPipeline::from_sink(InMemorySink::new());
    let auth = build_auth();
    let entity_registry = Arc::new(EntityRegistry::from_config(&config).expect("registry builds"));
    let entity_query = Arc::new(EntityQueryEngine::new(
        Arc::clone(&df_ctx),
        Arc::clone(&entity_registry),
    ));
    let aggregate_query = Arc::new(AggregateQueryEngine::new(
        Arc::clone(&df_ctx),
        Arc::clone(&entity_registry),
        Arc::clone(&config),
    ));
    let public_app = build_app_with_entity_query(
        Arc::clone(&config),
        auth.clone(),
        Arc::clone(&sink),
        readiness_rx.clone(),
        entity_registry,
        entity_query,
        aggregate_query,
    )
    .expect("public app builds");
    let app = build_admin_app(config, auth, sink, readiness_rx, readiness_tx, ingest)
        .expect("admin app builds");

    AdminFixture {
        _tmp: tmp,
        server: TestServer::new(app),
        public_server: TestServer::new(public_app),
        source_path: config_path
            .parent()
            .expect("config path has parent")
            .join("social_registry.csv"),
    }
}

fn build_auth() -> Arc<ApiKeyAuth> {
    let entries = vec![
        ApiKeyEntry::new(
            "admin".to_string(),
            ScopeSet::from_iter(["admin", "social_registry:metadata", "social_registry:rows"]),
            make_fingerprint(ADMIN_KEY),
        )
        .expect("admin fingerprint parses"),
        ApiKeyEntry::new(
            "reader".to_string(),
            ScopeSet::from_iter(["social_registry:metadata"]),
            make_fingerprint(NON_ADMIN_KEY),
        )
        .expect("reader fingerprint parses"),
        ApiKeyEntry::new(
            "ops".to_string(),
            ScopeSet::from_iter(["registry_relay:ops_read"]),
            make_fingerprint(OPS_KEY),
        )
        .expect("ops fingerprint parses"),
    ];
    Arc::new(ApiKeyAuth::new(entries))
}

fn build_fixture() -> AdminFixture {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config(&tmp);
    build_fixture_from_config_path(tmp, config_path)
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

fn assert_not_contains_any(haystack: &str, forbidden: &[&str]) {
    for needle in forbidden {
        assert!(
            !haystack.contains(needle),
            "posture response leaked forbidden material: {needle}"
        );
    }
}

#[tokio::test]
async fn health_remains_unauthenticated_on_admin_app() {
    let fixture = build_fixture();

    let resp = fixture.server.get("/healthz").await;

    resp.assert_status(StatusCode::OK);
    assert_eq!(resp.json::<Value>(), serde_json::json!({"status": "ok"}));
}

#[tokio::test]
async fn table_reload_without_credential_is_rejected() {
    let fixture = build_fixture();

    let resp = fixture
        .server
        .post("/admin/v1/datasets/social_registry/tables/beneficiaries_csv/reload")
        .await;

    assert_problem(resp, StatusCode::UNAUTHORIZED, "auth.missing_credential").await;
}

#[tokio::test]
async fn table_reload_with_non_admin_key_is_rejected() {
    let fixture = build_fixture();

    let resp = fixture
        .server
        .post("/admin/v1/datasets/social_registry/tables/beneficiaries_csv/reload")
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
        .post("/admin/v1/datasets/social_registry/tables/beneficiaries_csv/reload")
        .add_header("Authorization", format!("Bearer {ADMIN_KEY}"))
        .await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["counts"]["reloaded"], 1);
    assert!(body.get("dataset_id").is_none());
    assert!(body.get("table_id").is_none());
    let dump = body.to_string();
    assert!(!dump.contains("social_registry"));
    assert!(!dump.contains("beneficiaries_csv"));
}

#[tokio::test]
async fn posture_requires_ops_read_scope() {
    let fixture = build_fixture();

    let missing = fixture.server.get("/admin/v1/posture").await;
    assert_problem(missing, StatusCode::UNAUTHORIZED, "auth.missing_credential").await;

    let admin_only = fixture
        .server
        .get("/admin/v1/posture")
        .add_header("Authorization", format!("Bearer {ADMIN_KEY}"))
        .await;
    let body = assert_problem(admin_only, StatusCode::FORBIDDEN, "auth.scope_denied").await;
    assert_eq!(body["detail"], "required scope: registry_relay:ops_read");

    let ops = fixture
        .server
        .get("/admin/v1/posture")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;
    ops.assert_status(StatusCode::OK);
}

#[tokio::test]
async fn ops_read_key_cannot_reload() {
    let fixture = build_fixture();

    for route in [
        "/admin/v1/reload",
        "/admin/v1/datasets/social_registry/tables/beneficiaries_csv/reload",
    ] {
        let resp = fixture
            .server
            .post(route)
            .add_header("Authorization", format!("Bearer {OPS_KEY}"))
            .await;

        let body = assert_problem(resp, StatusCode::FORBIDDEN, "auth.scope_denied").await;
        assert_eq!(body["detail"], "required scope: admin", "route: {route}");
    }
}

#[tokio::test]
async fn posture_uses_stable_instance_defaults_when_instance_block_is_omitted() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config_with_instance(&tmp, None);
    let fixture = build_fixture_from_config_path(tmp, config_path);

    let resp = fixture
        .server
        .get("/admin/v1/posture")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_matches_posture_schema(&body);
    assert_eq!(body["instance"]["id"], "registry-relay-local");
    assert_eq!(body["instance"]["environment"], "development");
    assert!(body["instance"].get("owner").is_none());
    assert!(body["instance"].get("jurisdiction").is_none());
}

#[tokio::test]
async fn posture_response_has_schema_metadata_and_redacted_public_summaries() {
    let fixture = build_fixture();

    let resp = fixture
        .server
        .get("/admin/v1/posture")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;

    resp.assert_status(StatusCode::OK);
    let raw = resp.text();
    assert_not_contains_any(
        &raw,
        &[
            AUDIT_SECRET_VALUE,
            PRIVATE_JWK_VALUE,
            "private-jwk-material",
            "REGISTRY_RELAY_TEST_AUDIT_HASH_SECRET",
            "REGISTRY_RELAY_TEST_PRIVATE_JWK",
            "hash_secret_env",
            "api_keys",
            "fingerprint",
            "token_env",
            "jwk_env",
            "private_jwk",
            r#""d""#,
            "beneficiary_id",
            "food_subsidy",
            r#""id":1654"#,
            "social_registry.csv",
            "admin_bind",
            "cache_dir",
            "trusted_roots",
        ],
    );
    let body: Value = serde_json::from_str(&raw).expect("posture is JSON");
    assert_matches_posture_schema(&body);
    assert_eq!(body["schema"], "registry.ops.posture.v1");
    assert_eq!(body["component"], "registry-relay");
    assert_eq!(body["instance"]["id"], "relay-test-instance");
    assert_eq!(body["build"]["package"], "registry-relay");
    assert!(body["build"]["version"]
        .as_str()
        .is_some_and(|version| !version.is_empty()));
    assert!(body["build"].get("git_sha").is_none());
    assert!(body["build"].get("features").is_none());
    assert_eq!(body["runtime"]["auth_mode"], "api_key");
    assert_eq!(body["configuration"]["source"], "local_file");
    assert_eq!(body["configuration"]["dynamic_reload_supported"], false);
    assert!(body["configuration"]["last_config_hash"]
        .as_str()
        .is_some_and(|hash| hash.starts_with("sha256:")));
    assert!(body["standards_artifacts"]["metadata_index"]
        .get("url")
        .is_none());
    assert_eq!(
        body["standards_artifacts"]["bregdcat_ap"]["observed_status"],
        "configured_not_checked"
    );
    assert_eq!(body["relay"]["metadata_manifest"]["configured"], true);
    assert!(body["relay"]["provenance"]["enabled"].is_boolean());
    assert!(body["relay"]["provenance"].get("issuer").is_none());
    assert!(body["relay"]["provenance"].get("active_kid").is_none());
    assert!(body["relay"]["provenance"].get("retired_kids").is_none());
    assert!(body["relay"]["provenance"].get("jwk_env").is_none());
    assert!(body["relay"]["provenance"].get("private_jwk").is_none());
}

#[tokio::test]
async fn posture_warns_when_audit_checkpoint_unavailable() {
    let fixture = build_fixture();

    let resp = fixture
        .server
        .get("/admin/v1/posture")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_matches_posture_schema(&body);
    assert_eq!(body["posture"]["audit"]["checkpoint_status"], "unavailable");
    assert!(body["posture"]["warnings"]
        .as_array()
        .expect("warnings array")
        .iter()
        .any(|warning| warning == "relay.audit_checkpoint_unavailable"));
}

#[tokio::test]
async fn posture_is_not_mounted_on_public_app() {
    let fixture = build_fixture();

    let resp = fixture
        .public_server
        .get("/admin/v1/posture")
        .add_header("Authorization", format!("Bearer {OPS_KEY}"))
        .await;

    resp.assert_status(StatusCode::NOT_FOUND);
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
        .post("/admin/v1/datasets/social_registry/tables/beneficiaries_csv/reload")
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

    let resp = fixture.server.post("/admin/v1/reload").await;

    assert_problem(resp, StatusCode::UNAUTHORIZED, "auth.missing_credential").await;
}

#[tokio::test]
async fn reload_all_with_non_admin_key_is_rejected() {
    let fixture = build_fixture();

    let resp = fixture
        .server
        .post("/admin/v1/reload")
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
        .post("/admin/v1/reload")
        .add_header("Authorization", format!("Bearer {ADMIN_KEY}"))
        .await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["counts"]["total"], 2);
    assert_eq!(body["counts"]["succeeded"], 2);
    assert_eq!(body["counts"]["failed"], 0);

    assert!(body.get("resources").is_none());
    let dump = body.to_string();
    assert!(!dump.contains("social_registry"));
    assert!(!dump.contains("beneficiaries_csv"));
    assert!(!dump.contains("beneficiaries_copy_csv"));
}

#[tokio::test]
async fn reload_all_publishes_ready_snapshot() {
    let fixture = build_fixture();

    fixture
        .server
        .post("/admin/v1/reload")
        .add_header("Authorization", format!("Bearer {ADMIN_KEY}"))
        .await
        .assert_status(StatusCode::OK);

    let resp = fixture.server.get("/ready").await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(body["status"], "ok");
    assert_eq!(body["counts"]["ready"], 2);
    assert!(body.get("resources").is_none());
}

#[tokio::test]
async fn table_reload_invalidates_public_entity_collection_etag_after_source_change() {
    let fixture = build_fixture();

    fixture
        .server
        .post("/admin/v1/reload")
        .add_header("Authorization", format!("Bearer {ADMIN_KEY}"))
        .await
        .assert_status(StatusCode::OK);

    let before = fixture
        .public_server
        .get("/v1/datasets/social_registry/entities/beneficiary/records?limit=1000")
        .add_header("Authorization", format!("Bearer {ADMIN_KEY}"))
        .await;
    before.assert_status(StatusCode::OK);
    let before_etag = before.header("etag").to_str().expect("etag").to_string();
    let before_body: Value = before.json();
    assert_eq!(program_for_beneficiary(&before_body, 1654), "food_subsidy");

    let updated_csv = "\
beneficiary_id,household_size,municipality_code,program,amount_eur,joined_date,last_updated
1654,2,AA001,emergency_cash,760.07,2020-07-03,2019-02-24
";
    std::fs::write(&fixture.source_path, updated_csv).expect("rewrite source fixture");

    fixture
        .server
        .post("/admin/v1/datasets/social_registry/tables/beneficiaries_csv/reload")
        .add_header("Authorization", format!("Bearer {ADMIN_KEY}"))
        .await
        .assert_status(StatusCode::OK);

    let stale_revalidation = fixture
        .public_server
        .get("/v1/datasets/social_registry/entities/beneficiary/records?limit=1000")
        .add_header("Authorization", format!("Bearer {ADMIN_KEY}"))
        .add_header("if-none-match", &before_etag)
        .await;
    stale_revalidation.assert_status(StatusCode::OK);
    let after_etag = stale_revalidation
        .header("etag")
        .to_str()
        .expect("etag")
        .to_string();
    assert_ne!(after_etag, before_etag);
    let after_body: Value = stale_revalidation.json();
    assert_eq!(program_for_beneficiary(&after_body, 1654), "emergency_cash");
}

fn program_for_beneficiary(body: &Value, id: i64) -> &str {
    body["data"]
        .as_array()
        .expect("collection data is an array")
        .iter()
        .find(|row| row["id"] == id)
        .and_then(|row| row["program"].as_str())
        .expect("beneficiary row present")
}
