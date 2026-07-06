// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "attribute-release")]

//! Cross-cutting `Cache-Control` coverage for the protected data-plane surface.
//!
//! Relay's protected router mixes handlers that set their own caching
//! directives (`attribute_release`, `metadata`) with handlers that set none
//! (`entity`, `aggregates`, `datasets`). `server::build_app*` installs a
//! router-level default so every response leaving the protected sub-router
//! carries `Cache-Control: private, no-store`, without duplicating the
//! header where a handler already set it. These tests drive the full
//! `build_app_with_entity_query` stack (real auth layer, real router
//! composition) rather than an individual family's router in isolation, since
//! the behaviour under test lives in the composition, not in any one handler.
//!
//! Coverage:
//! * Each of the five protected route families (entity, aggregates, datasets,
//!   metadata, attribute_release) returns exactly one `Cache-Control: private,
//!   no-store` header, with no duplication for the two families that already
//!   set it explicitly.
//! * An unauthenticated request to a protected route is denied but still
//!   carries the header (auth denials are principal-shaped responses too).
//! * `/healthz` on the public surface does not carry the header.

use std::env;
use std::sync::Arc;

use axum::http::header;
use axum_test::TestServer;
use datafusion::arrow::array::StringArray;
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::datasource::MemTable;
use datafusion::execution::context::SessionContext;
use registry_relay::audit::{AuditPipeline, InMemorySink};
use registry_relay::auth::api_key::{ApiKeyAuth, ApiKeyEntry};
use registry_relay::auth::{AuthProvider, ScopeSet};
use registry_relay::config::{self, DatasetId, ResourceId};
use registry_relay::entity::EntityRegistry;
use registry_relay::ingest::{table_name, ReadinessSnapshot};
use registry_relay::query::{AggregateQueryEngine, EntityQueryEngine};
use registry_relay::server::build_app_with_entity_query;
use serde_json::json;
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::sync::watch;

const AUDIT_SECRET_ENV: &str = "REGISTRY_RELAY_TEST_CACHE_CONTROL_AUDIT_SECRET";
const API_KEY: &str = "cache-control-test-token-0123456789";

const CONFIG: &str = r#"
server:
  bind: 127.0.0.1:0

catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test

vocabularies: {}

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
      - id: households_table
        source:
          type: file
          path: fixtures/social_registry.csv
        primary_key: household_id
        schema:
          strict: true
          fields:
            - name: household_id
              type: string
              nullable: false
      - id: individuals_table
        source:
          type: file
          path: fixtures/social_registry.csv
        primary_key: individual_id
        schema:
          strict: true
          fields:
            - name: individual_id
              type: string
              nullable: false
            - name: household_id
              type: string
              nullable: false
            - name: municipality_code
              type: string
              nullable: true
    aggregates:
      - id: by_municipality
        title: Individuals by municipality
        description: Number of individuals by municipality
        source_entity: individual
        default_group_by:
          - municipality_code
        dimensions:
          - id: municipality_code
            label: Municipality
            field: municipality_code
        indicators:
          - id: individual_count
            label: Individuals
            function: count
            column: id
            unit_measure: people
        disclosure_control:
          min_group_size: 1
          suppression: omit
          report_suppressed_rows: true
    entities:
      - name: household
        table: households_table
        fields:
          - name: id
            from: household_id
        access:
          metadata_scope: social_registry:metadata
          aggregate_scope: social_registry:aggregate
          read_scope: social_registry:rows
        api:
          default_limit: 100
          max_limit: 1000
      - name: individual
        table: individuals_table
        fields:
          - name: id
            from: individual_id
          - name: household_id
          - name: municipality_code
        access:
          metadata_scope: social_registry:metadata
          aggregate_scope: social_registry:aggregate
          read_scope: social_registry:rows
        api:
          default_limit: 100
          max_limit: 1000
        attribute_release_profiles:
          - id: individual_identity
            version: v1
            title: Individual identity bundle
            description: Minimal bundle for cache-control coverage.
            release_scope: social_registry:identity_release
            subject:
              input: subject_token
              source_field: id
              id_type: INDIVIDUAL_ID
            release_conditions:
              expression:
                cel: "source.municipality_code != ''"
            claims:
              - name: municipality
                source_field: municipality_code
                required: true
            response:
              include_source_metadata: true

audit:
  sink: stdout
  format: jsonl
  hash_secret_env: REGISTRY_RELAY_TEST_CACHE_CONTROL_AUDIT_SECRET
"#;

fn fingerprint(plain: &str) -> String {
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

fn id<T: serde::de::DeserializeOwned>(value: &str) -> T {
    serde_json::from_str(&format!(r#""{value}""#)).expect("id deserializes")
}

/// Assemble the full production router (`build_app_with_entity_query`) over
/// a config that exercises all five protected route families, with a single
/// API key scoped for all of them. Real auth headers drive every request so
/// the test proves the production auth + router composition, not a
/// hand-wired test harness.
fn build_server() -> TestServer {
    let _ = tracing_subscriber::fmt::try_init();
    unsafe {
        env::set_var(
            AUDIT_SECRET_ENV,
            "relay-cache-control-test-audit-secret-32-bytes-minimum",
        );
    }
    let tmp = TempDir::new().expect("tempdir");
    let config_path = tmp.path().join("protected_cache_control.yaml");
    std::fs::write(&config_path, CONFIG).expect("write config");
    let config =
        Arc::new(config::load(&config_path).unwrap_or_else(|err| panic!("config loads: {err:?}")));

    let registry = Arc::new(EntityRegistry::from_config(&config).expect("registry"));
    let ctx = Arc::new(SessionContext::new());

    let household_schema = Arc::new(Schema::new(vec![Field::new(
        "household_id",
        DataType::Utf8,
        false,
    )]));
    let household_batch = RecordBatch::try_new(
        Arc::clone(&household_schema),
        vec![Arc::new(StringArray::from(vec!["hh-1"]))],
    )
    .expect("household batch");
    let household_table =
        MemTable::try_new(household_schema, vec![vec![household_batch]]).expect("household table");
    let dataset: DatasetId = id("social_registry");
    let households: ResourceId = id("households_table");
    ctx.register_table(table_name(&dataset, &households), Arc::new(household_table))
        .expect("register households");

    let individual_schema = Arc::new(Schema::new(vec![
        Field::new("individual_id", DataType::Utf8, false),
        Field::new("household_id", DataType::Utf8, false),
        Field::new("municipality_code", DataType::Utf8, true),
    ]));
    let individual_batch = RecordBatch::try_new(
        Arc::clone(&individual_schema),
        vec![
            Arc::new(StringArray::from(vec!["ind-1"])),
            Arc::new(StringArray::from(vec!["hh-1"])),
            Arc::new(StringArray::from(vec!["mun-1"])),
        ],
    )
    .expect("individual batch");
    let individual_table = MemTable::try_new(individual_schema, vec![vec![individual_batch]])
        .expect("individual table");
    let individuals: ResourceId = id("individuals_table");
    ctx.register_table(
        table_name(&dataset, &individuals),
        Arc::new(individual_table),
    )
    .expect("register individuals");

    let query = Arc::new(EntityQueryEngine::new(
        Arc::clone(&ctx),
        Arc::clone(&registry),
    ));
    let aggregate_query = Arc::new(AggregateQueryEngine::new(
        Arc::clone(&ctx),
        Arc::clone(&registry),
        Arc::clone(&config),
    ));

    let entry = ApiKeyEntry::new(
        "cache-control-test".to_string(),
        ScopeSet::from_iter([
            "social_registry:metadata",
            "social_registry:aggregate",
            "social_registry:rows",
            "social_registry:identity_release",
        ]),
        fingerprint(API_KEY),
    )
    .expect("api key fingerprint parses");
    let auth: Arc<dyn AuthProvider> = Arc::new(ApiKeyAuth::new(vec![entry]));

    let sink: Arc<AuditPipeline> = AuditPipeline::from_sink(InMemorySink::new());
    let (_tx, readiness) = watch::channel(ReadinessSnapshot::default());

    let app = build_app_with_entity_query(
        config,
        auth,
        sink,
        readiness,
        registry,
        query,
        aggregate_query,
    )
    .expect("app builds");
    TestServer::new(app)
}

fn bearer(server: &TestServer, method_path: &str) -> axum_test::TestRequest {
    server
        .get(method_path)
        .add_header("Authorization", format!("Bearer {API_KEY}"))
}

/// Assert the response carries exactly one `Cache-Control: private, no-store`
/// header: present (the router-level default or a handler's own explicit
/// value), and not duplicated by the two combining.
fn assert_single_private_no_store(resp: &axum_test::TestResponse) {
    let values: Vec<&str> = resp
        .iter_headers_by_name(header::CACHE_CONTROL)
        .map(|value| value.to_str().expect("cache-control is ASCII"))
        .collect();
    assert_eq!(
        values,
        vec!["private, no-store"],
        "expected exactly one private, no-store Cache-Control header, got {values:?}"
    );
}

#[tokio::test]
async fn datasets_family_carries_single_cache_control_header() {
    let server = build_server();
    let resp = bearer(&server, "/v1/datasets").await;
    resp.assert_status_ok();
    assert_single_private_no_store(&resp);
}

#[tokio::test]
async fn entity_family_carries_single_cache_control_header() {
    let server = build_server();
    let resp = bearer(
        &server,
        "/v1/datasets/social_registry/entities/household/records",
    )
    .await;
    resp.assert_status_ok();
    assert_single_private_no_store(&resp);
}

#[tokio::test]
async fn aggregates_family_carries_single_cache_control_header() {
    let server = build_server();
    let resp = bearer(&server, "/v1/datasets/social_registry/aggregates").await;
    resp.assert_status_ok();
    assert_single_private_no_store(&resp);
}

#[tokio::test]
async fn metadata_family_carries_single_cache_control_header() {
    // metadata.rs already sets Cache-Control explicitly; this proves the
    // router-level default does not duplicate it.
    let server = build_server();
    let resp = bearer(&server, "/metadata").await;
    resp.assert_status_ok();
    assert_single_private_no_store(&resp);
}

#[tokio::test]
async fn attribute_release_family_carries_single_cache_control_header() {
    // attribute_release.rs already sets Cache-Control explicitly; this
    // proves the router-level default does not duplicate it.
    let server = build_server();
    let resp = server
        .post("/v1/attribute-releases/individual_identity/versions/v1/resolve")
        .add_header("Authorization", format!("Bearer {API_KEY}"))
        .json(&json!({ "subject": { "id_type": "INDIVIDUAL_ID", "value": "ind-1" } }))
        .await;
    resp.assert_status_ok();
    assert_single_private_no_store(&resp);
}

#[tokio::test]
async fn unauthenticated_protected_request_still_carries_cache_control_header() {
    // Denials are principal-shaped responses too: a request with no
    // credential at all must still get the protected-surface default.
    let server = build_server();
    let resp = server.get("/v1/datasets").await;
    resp.assert_status_unauthorized();
    assert_single_private_no_store(&resp);
}

#[tokio::test]
async fn healthz_does_not_carry_protected_cache_control_header() {
    // The public surface (health/ready) sits outside the protected
    // sub-router and must not inherit its caching default.
    let server = build_server();
    let resp = server.get("/healthz").await;
    resp.assert_status_ok();
    assert!(
        resp.maybe_header(header::CACHE_CONTROL).is_none(),
        "healthz must not carry a Cache-Control header"
    );
}
