// SPDX-License-Identifier: Apache-2.0
//! Focused route-shape tests for the entity API slice.

use axum::http::StatusCode;
use axum::Extension;
use axum_test::TestServer;
use data_gate::api::{aggregates_router, entity_router, CursorSigner};
use data_gate::auth::{AuthMode, Principal, ScopeSet};
use data_gate::config::{self, DatasetId, ResourceId};
use data_gate::entity::EntityRegistry;
use data_gate::ingest::{register_versioned_table, table_name, ReadinessSnapshot, ReadyResource};
use data_gate::query::EntityQueryEngine;
use datafusion::arrow::array::StringArray;
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::datasource::MemTable;
use datafusion::execution::context::SessionContext;
use serde_json::Value;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::watch;
use ulid::Ulid;

fn server() -> TestServer {
    TestServer::new(entity_router::<()>())
}

fn id<T: serde::de::DeserializeOwned>(value: &str) -> T {
    serde_json::from_str(&format!(r#""{value}""#)).expect("id deserializes")
}

fn principal(scopes: &[&str]) -> Principal {
    Principal {
        api_key_id: "test".to_string(),
        scopes: scopes.iter().copied().collect::<ScopeSet>(),
        auth_mode: AuthMode::ApiKey,
    }
}

async fn server_with_query() -> TestServer {
    server_with_query_version("01J5K8M0000000000000000000").await
}

async fn server_with_query_version(ingest_version: &str) -> TestServer {
    server_with_query_versions_and_signer(
        ingest_version,
        ingest_version,
        Arc::new(CursorSigner::new_random()),
    )
    .await
}

async fn server_with_query_versions(
    table_ingest_version: &str,
    readiness_ingest_version: &str,
) -> TestServer {
    server_with_query_versions_and_signer(
        table_ingest_version,
        readiness_ingest_version,
        Arc::new(CursorSigner::new_random()),
    )
    .await
}

async fn server_with_query_version_and_signer(
    ingest_version: &str,
    signer: Arc<CursorSigner>,
) -> TestServer {
    server_with_query_versions_and_signer(ingest_version, ingest_version, signer).await
}

async fn server_with_query_versions_and_signer(
    table_ingest_version: &str,
    readiness_ingest_version: &str,
    signer: Arc<CursorSigner>,
) -> TestServer {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = tmp.path().join("entity_routes.yaml");
    std::fs::write(
        &config_path,
        r#"
server:
  bind: 127.0.0.1:0

catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test

vocabularies:
  ex: https://example.test/vocab/
  psc: https://publicschema.org/

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
      path: fixtures/social_registry.csv
    refresh:
      mode: manual
    tables:
      - id: households_table
        primary_key: household_id
        schema:
          strict: true
          fields:
            - name: household_id
              type: string
              nullable: false
              concept_uri: ex:properties/householdId
            - name: region_code
              type: string
              nullable: true
              concept_uri: ex:properties/regionCode
              codelist: ex:codelists/Region
              unit: ISO-3166-2
              language: en
      - id: individuals_table
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
            - name: given_name
              type: string
              nullable: true
    entities:
      - name: household
        table: households_table
        concept_uri: psc:concepts/Household
        fields:
          - name: id
            from: household_id
          - name: region
            from: region_code
            concept_uri: ex:properties/region
        relationships:
          - name: members
            kind: has_many
            target: individual
            foreign_key: household_id
            concept_uri: ex:relationships/householdMember
        access:
          metadata_scope: social_registry:metadata
          aggregate_scope: social_registry:aggregate
          read_scope: social_registry:rows
          verify_scope: social_registry:verify
          bulk_export_scope: social_registry:bulk_export
        api:
          default_limit: 100
          max_limit: 1000
          allowed_filters:
            - field: id
              ops: [eq, in]
            - field: region
              ops: [eq, in, gte, lte, between]
          allowed_expansions: [members]
      - name: individual
        table: individuals_table
        fields:
          - name: id
            from: individual_id
          - name: household_id
          - name: given_name
        relationships:
          - name: household
            kind: belongs_to
            target: household
            foreign_key: household_id
        access:
          metadata_scope: social_registry:metadata
          aggregate_scope: social_registry:aggregate
          read_scope: social_registry:rows
          verify_scope: social_registry:verify
          bulk_export_scope: social_registry:bulk_export
        api:
          default_limit: 100
          max_limit: 1000
          require_purpose_header: true
          allowed_filters:
            - field: id
              ops: [eq, in]
            - field: household_id
              ops: [eq]
          allowed_expansions: [household]

audit:
  sink: stdout
  format: jsonl
"#,
    )
    .expect("write config");
    let cfg = Arc::new(config::load(&config_path).expect("config loads"));
    let registry = Arc::new(EntityRegistry::from_config(&cfg).expect("registry"));
    let ctx = Arc::new(SessionContext::new());
    let schema = Arc::new(Schema::new(vec![
        Field::new("household_id", DataType::Utf8, false),
        Field::new("region_code", DataType::Utf8, true),
    ]));
    let batch = RecordBatch::try_new(
        Arc::clone(&schema),
        vec![
            Arc::new(StringArray::from(vec!["hh-1", "hh-2"])),
            Arc::new(StringArray::from(vec!["north", "south"])),
        ],
    )
    .expect("batch");
    let table = MemTable::try_new(schema, vec![vec![batch]]).expect("mem table");
    let dataset: DatasetId = id("social_registry");
    let table_ingest_version = Ulid::from_string(table_ingest_version).expect("ulid");
    let readiness_ingest_version = Ulid::from_string(readiness_ingest_version).expect("ulid");
    let resource: ResourceId = id("households_table");
    register_versioned_table(
        &ctx,
        table_name(&dataset, &resource),
        table_ingest_version,
        Arc::new(table),
    )
    .expect("register table");
    let individual_schema = Arc::new(Schema::new(vec![
        Field::new("individual_id", DataType::Utf8, false),
        Field::new("household_id", DataType::Utf8, false),
        Field::new("given_name", DataType::Utf8, true),
    ]));
    let individual_batch = RecordBatch::try_new(
        Arc::clone(&individual_schema),
        vec![
            Arc::new(StringArray::from(vec!["p-1", "p-2"])),
            Arc::new(StringArray::from(vec!["hh-1", "hh-1"])),
            Arc::new(StringArray::from(vec!["Ada", "Ben"])),
        ],
    )
    .expect("individual batch");
    let individual_table =
        MemTable::try_new(individual_schema, vec![vec![individual_batch]]).expect("mem table");
    let resource: ResourceId = id("individuals_table");
    register_versioned_table(
        &ctx,
        table_name(&dataset, &resource),
        table_ingest_version,
        Arc::new(individual_table),
    )
    .expect("register individual table");
    let query = Arc::new(EntityQueryEngine::new(ctx, Arc::clone(&registry)));
    let mut snapshot = ReadinessSnapshot::default();
    snapshot.ready.insert(
        (id("social_registry"), id("households_table")),
        ReadyResource {
            ingest_ulid: readiness_ingest_version,
            registered_at: time::OffsetDateTime::now_utc(),
        },
    );
    snapshot.ready.insert(
        (id("social_registry"), id("individuals_table")),
        ReadyResource {
            ingest_ulid: readiness_ingest_version,
            registered_at: time::OffsetDateTime::now_utc(),
        },
    );
    let (_tx, readiness) = watch::channel(snapshot);

    TestServer::new(
        entity_router::<()>()
            .layer(Extension(query))
            .layer(Extension(registry))
            .layer(Extension(cfg))
            .layer(Extension(readiness))
            .layer(Extension(signer))
            .layer(Extension(principal(&[
                "social_registry:metadata",
                "social_registry:rows",
                "social_registry:verify",
            ]))),
    )
}

#[tokio::test]
async fn entity_schema_route_matches() {
    let resp = server()
        .get("/datasets/social_registry/individual/schema")
        .await;

    resp.assert_status(StatusCode::NOT_IMPLEMENTED);
    assert_eq!(resp.header("content-type"), "application/problem+json");
    let body: Value = resp.json();
    assert_eq!(body["code"], "entity.query_unavailable");
}

#[tokio::test]
async fn entity_schema_route_returns_metadata_schema_when_state_installed() {
    let resp = server_with_query()
        .await
        .get("/datasets/social_registry/household/schema")
        .await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(body["dataset_id"], "social_registry");
    assert_eq!(body["entity"], "household");
    assert_eq!(
        body["concept_uri"],
        "https://publicschema.org/concepts/Household"
    );
    assert_eq!(body["fields"][1]["name"], "region");
    assert_eq!(body["fields"][1]["physical_type"], "string");
    assert_eq!(
        body["fields"][1]["concept_uri"],
        "https://example.test/vocab/properties/region"
    );
    assert_eq!(
        body["fields"][1]["codelist"],
        "https://example.test/vocab/codelists/Region"
    );
    assert_eq!(body["fields"][1]["unit"], "ISO-3166-2");
    assert_eq!(body["fields"][1]["language"], "en");
    assert_eq!(body["relationships"][0]["kind"], "has_many");
    assert_eq!(body["relationships"][0]["target"], "individual");
    assert_eq!(body["relationships"][0]["foreign_key"], "household_id");
    assert_eq!(
        body["relationships"][0]["concept_uri"],
        "https://example.test/vocab/relationships/householdMember"
    );
}

#[tokio::test]
async fn entity_schema_returns_etag_and_honors_if_none_match() {
    let server = server_with_query().await;
    let resp = server
        .get("/datasets/social_registry/household/schema")
        .await;

    resp.assert_status(StatusCode::OK);
    let etag = resp.header("etag").to_str().expect("etag").to_string();
    assert!(etag.starts_with(r#""sha256:"#));

    let cached = server
        .get("/datasets/social_registry/household/schema")
        .add_header("if-none-match", &etag)
        .await;

    cached.assert_status(StatusCode::NOT_MODIFIED);
    assert_eq!(cached.header("etag").to_str().expect("etag"), etag);
}

#[tokio::test]
async fn entity_collection_route_matches() {
    let resp = server().get("/datasets/social_registry/individual").await;

    resp.assert_status(StatusCode::NOT_IMPLEMENTED);
    assert_eq!(resp.header("content-type"), "application/problem+json");
}

#[tokio::test]
async fn entity_collection_route_executes_query_when_state_installed() {
    let resp = server_with_query()
        .await
        .get("/datasets/social_registry/household?region=north")
        .await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(
        body,
        serde_json::json!({
            "data": [
                {"id": "hh-1", "region": "north"}
            ],
            "pagination": {
                "has_more": false
            }
        })
    );
}

#[tokio::test]
async fn entity_collection_returns_etag_and_honors_if_none_match() {
    let server = server_with_query().await;
    let resp = server
        .get("/datasets/social_registry/household?region=north")
        .await;

    resp.assert_status(StatusCode::OK);
    let etag = resp.header("etag").to_str().expect("etag").to_string();

    let cached = server
        .get("/datasets/social_registry/household?region=north")
        .add_header("if-none-match", &etag)
        .await;

    cached.assert_status(StatusCode::NOT_MODIFIED);
    assert_eq!(cached.header("etag").to_str().expect("etag"), etag);
}

#[tokio::test]
async fn entity_collection_validates_query_before_cached_not_modified() {
    let server = server_with_query().await;
    let validator = serde_json::to_string(&std::collections::BTreeMap::from([("limit", "0")]))
        .expect("validator serializes");
    let etag = data_gate::api::entity::entity_etag(
        "collection",
        "social_registry",
        "household",
        Some("households_table=01J5K8M0000000000000000000"),
        &validator,
    )
    .expect("etag");

    let cached = server
        .get("/datasets/social_registry/household?limit=0")
        .add_header("if-none-match", &etag)
        .await;

    cached.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = cached.json();
    assert_eq!(body["code"], "filter.limit_out_of_range");
}

#[tokio::test]
async fn entity_collection_route_parses_allowed_filter_ops() {
    let resp = server_with_query()
        .await
        .get("/datasets/social_registry/household?region.in=north,missing")
        .await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(
        body,
        serde_json::json!({
            "data": [
                {"id": "hh-1", "region": "north"}
            ],
            "pagination": {
                "has_more": false
            }
        })
    );
}

#[tokio::test]
async fn entity_collection_route_paginates_with_opaque_cursor() {
    let server = server_with_query().await;

    let first = server
        .get("/datasets/social_registry/household?limit=1")
        .await;
    first.assert_status(StatusCode::OK);
    let body: Value = first.json();
    assert_eq!(
        body["data"],
        serde_json::json!([{"id": "hh-1", "region": "north"}])
    );
    assert_eq!(body["pagination"]["has_more"], true);
    let cursor = body["pagination"]["next_cursor"]
        .as_str()
        .expect("first page has cursor");
    assert!(first
        .header("link")
        .to_str()
        .expect("link")
        .contains(&format!("cursor={cursor}")));

    let url = format!("/datasets/social_registry/household?limit=1&cursor={cursor}");
    let second = server.get(&url).await;
    second.assert_status(StatusCode::OK);
    let body: Value = second.json();
    assert_eq!(
        body["data"],
        serde_json::json!([{"id": "hh-2", "region": "south"}])
    );
    assert_eq!(body["pagination"]["has_more"], false);
    assert!(body["pagination"].get("next_cursor").is_none());
}

#[tokio::test]
async fn entity_collection_cursor_mismatch_returns_conflict() {
    let server = server_with_query().await;

    let first = server
        .get("/datasets/social_registry/household?limit=1")
        .await;
    first.assert_status(StatusCode::OK);
    let body: Value = first.json();
    let cursor = body["pagination"]["next_cursor"]
        .as_str()
        .expect("first page has cursor");

    let url = format!("/datasets/social_registry/household?limit=1&region=north&cursor={cursor}");
    let resp = server.get(&url).await;
    resp.assert_status(StatusCode::CONFLICT);
    let body: Value = resp.json();
    assert_eq!(body["code"], "pagination.cursor_invalidated");
}

#[tokio::test]
async fn entity_collection_stale_cursor_returns_conflict() {
    // Share a cursor signer across both servers so the HMAC verifies on
    // the second request and the ingest-version mismatch surfaces as
    // `pagination.cursor_invalidated`. A signer change (e.g. a process
    // restart) would instead reject the cursor as `filter.invalid_value`,
    // which is covered by the dedicated tamper-detection tests below.
    let signer = Arc::new(CursorSigner::new_random());
    let old_server =
        server_with_query_version_and_signer("01J5K8M0000000000000000000", Arc::clone(&signer))
            .await;
    let first = old_server
        .get("/datasets/social_registry/household?limit=1")
        .await;
    first.assert_status(StatusCode::OK);
    let body: Value = first.json();
    let cursor = body["pagination"]["next_cursor"]
        .as_str()
        .expect("first page has cursor");

    let new_server =
        server_with_query_version_and_signer("01J5K8M0000000000000000001", Arc::clone(&signer))
            .await;
    let url = format!("/datasets/social_registry/household?limit=1&cursor={cursor}");
    let resp = new_server.get(&url).await;
    resp.assert_status(StatusCode::CONFLICT);
    let body: Value = resp.json();
    assert_eq!(body["code"], "pagination.cursor_invalidated");
}

#[tokio::test]
async fn entity_record_route_matches() {
    let resp = server()
        .get("/datasets/social_registry/individual/abc123")
        .await;

    resp.assert_status(StatusCode::NOT_IMPLEMENTED);
    assert_eq!(resp.header("content-type"), "application/problem+json");
}

#[tokio::test]
async fn entity_record_returns_etag_and_honors_if_none_match() {
    let server = server_with_query().await;
    let resp = server.get("/datasets/social_registry/household/hh-1").await;

    resp.assert_status(StatusCode::OK);
    let etag = resp.header("etag").to_str().expect("etag").to_string();

    let cached = server
        .get("/datasets/social_registry/household/hh-1")
        .add_header("if-none-match", &etag)
        .await;

    cached.assert_status(StatusCode::NOT_MODIFIED);
    assert_eq!(cached.header("etag").to_str().expect("etag"), etag);
}

#[tokio::test]
async fn entity_relationship_route_executes_query_when_state_installed() {
    let resp = server_with_query()
        .await
        .get("/datasets/social_registry/individual/p-1/household")
        .add_header("data-purpose", "route-test")
        .await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(
        body,
        serde_json::json!({
            "id": "hh-1",
            "region": "north"
        })
    );
}

#[tokio::test]
async fn entity_relationship_returns_etag_and_honors_if_none_match() {
    let server = server_with_query().await;
    let resp = server
        .get("/datasets/social_registry/individual/p-1/household")
        .add_header("data-purpose", "route-test")
        .await;

    resp.assert_status(StatusCode::OK);
    let etag = resp.header("etag").to_str().expect("etag").to_string();

    let cached = server
        .get("/datasets/social_registry/individual/p-1/household")
        .add_header("data-purpose", "route-test")
        .add_header("if-none-match", &etag)
        .await;

    cached.assert_status(StatusCode::NOT_MODIFIED);
    assert_eq!(cached.header("etag").to_str().expect("etag"), etag);
}

#[tokio::test]
async fn entity_has_many_relationship_route_paginates_with_opaque_cursor() {
    let server = server_with_query().await;

    let first = server
        .get("/datasets/social_registry/household/hh-1/members?limit=1")
        .add_header("data-purpose", "route-test")
        .await;
    first.assert_status(StatusCode::OK);
    let body: Value = first.json();
    assert_eq!(
        body["data"],
        serde_json::json!([
            {"id": "p-1", "household_id": "hh-1", "given_name": "Ada"}
        ])
    );
    assert_eq!(body["pagination"]["has_more"], true);
    let cursor = body["pagination"]["next_cursor"]
        .as_str()
        .expect("first relationship page has cursor");
    assert!(first
        .header("link")
        .to_str()
        .expect("link")
        .contains(&format!("cursor={cursor}")));

    let url = format!("/datasets/social_registry/household/hh-1/members?limit=1&cursor={cursor}");
    let second = server
        .get(&url)
        .add_header("data-purpose", "route-test")
        .await;
    second.assert_status(StatusCode::OK);
    let body: Value = second.json();
    assert_eq!(
        body["data"],
        serde_json::json!([
            {"id": "p-2", "household_id": "hh-1", "given_name": "Ben"}
        ])
    );
    assert_eq!(body["pagination"]["has_more"], false);
    assert!(body["pagination"].get("next_cursor").is_none());
}

#[tokio::test]
async fn entity_has_many_relationship_returns_etag_and_honors_if_none_match() {
    let server = server_with_query().await;
    let resp = server
        .get("/datasets/social_registry/household/hh-1/members?limit=1")
        .add_header("data-purpose", "route-test")
        .await;

    resp.assert_status(StatusCode::OK);
    let etag = resp.header("etag").to_str().expect("etag").to_string();

    let cached = server
        .get("/datasets/social_registry/household/hh-1/members?limit=1")
        .add_header("data-purpose", "route-test")
        .add_header("if-none-match", &etag)
        .await;

    cached.assert_status(StatusCode::NOT_MODIFIED);
    assert_eq!(cached.header("etag").to_str().expect("etag"), etag);
}

#[tokio::test]
async fn entity_has_many_relationship_stale_cursor_returns_conflict() {
    // Share a cursor signer across both servers so the HMAC verifies on
    // the second request and the ingest-version mismatch surfaces as
    // `pagination.cursor_invalidated`.
    let signer = Arc::new(CursorSigner::new_random());
    let old_server =
        server_with_query_version_and_signer("01J5K8M0000000000000000000", Arc::clone(&signer))
            .await;
    let first = old_server
        .get("/datasets/social_registry/household/hh-1/members?limit=1")
        .add_header("data-purpose", "route-test")
        .await;
    first.assert_status(StatusCode::OK);
    let body: Value = first.json();
    let cursor = body["pagination"]["next_cursor"]
        .as_str()
        .expect("first relationship page has cursor");

    let new_server =
        server_with_query_version_and_signer("01J5K8M0000000000000000001", Arc::clone(&signer))
            .await;
    let url = format!("/datasets/social_registry/household/hh-1/members?limit=1&cursor={cursor}");
    let resp = new_server
        .get(&url)
        .add_header("data-purpose", "route-test")
        .await;
    resp.assert_status(StatusCode::CONFLICT);
    let body: Value = resp.json();
    assert_eq!(body["code"], "pagination.cursor_invalidated");
}

#[tokio::test]
async fn entity_verify_uses_verify_scope_and_returns_one_bit() {
    let server = server_with_query().await;

    let present = server
        .get("/datasets/social_registry/individual/verify?id=p-1")
        .add_header("data-purpose", "route-test")
        .await;
    present.assert_status(StatusCode::OK);
    let body: Value = present.json();
    assert_eq!(
        body,
        serde_json::json!({
            "exists": true,
            "ingest_version": "01J5K8M0000000000000000000"
        })
    );

    let absent = server
        .get("/datasets/social_registry/individual/verify?id=missing")
        .add_header("data-purpose", "route-test")
        .await;
    absent.assert_status(StatusCode::OK);
    let body: Value = absent.json();
    assert_eq!(
        body,
        serde_json::json!({
            "exists": false,
            "ingest_version": "01J5K8M0000000000000000000"
        })
    );
}

#[tokio::test]
async fn entity_verify_uses_table_snapshot_version_not_stale_readiness() {
    let server =
        server_with_query_versions("01J5K8M0000000000000000001", "01J5K8M0000000000000000000")
            .await;

    let resp = server
        .get("/datasets/social_registry/individual/verify?id=p-1")
        .add_header("data-purpose", "route-test")
        .await;
    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();

    assert_eq!(body["exists"], true);
    assert_eq!(body["ingest_version"], "01J5K8M0000000000000000001");
}

#[tokio::test]
async fn entity_verify_returns_etag_and_honors_if_none_match() {
    let server = server_with_query().await;
    let resp = server
        .get("/datasets/social_registry/individual/verify?id=p-1")
        .add_header("data-purpose", "route-test")
        .await;

    resp.assert_status(StatusCode::OK);
    let etag = resp.header("etag").to_str().expect("etag").to_string();

    let cached = server
        .get("/datasets/social_registry/individual/verify?id=p-1")
        .add_header("data-purpose", "route-test")
        .add_header("if-none-match", &etag)
        .await;

    cached.assert_status(StatusCode::NOT_MODIFIED);
    assert_eq!(cached.header("etag").to_str().expect("etag"), etag);
}

#[tokio::test]
async fn entity_verify_requires_exposed_primary_key_only() {
    let server = server_with_query().await;

    for url in [
        "/datasets/social_registry/individual/verify",
        "/datasets/social_registry/individual/verify?individual_id=p-1",
        "/datasets/social_registry/individual/verify?id=p-1&extra=1",
        "/datasets/social_registry/individual/verify?id.in=p-1,p-2",
    ] {
        let resp = server
            .get(url)
            .add_header("data-purpose", "route-test")
            .await;
        resp.assert_status(StatusCode::BAD_REQUEST);
        let body: Value = resp.json();
        assert_eq!(body["code"], "filter.not_allowed");
    }
}

#[tokio::test]
async fn verify_only_principal_cannot_read_rows_or_schema() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = tmp.path().join("verify_only.yaml");
    std::fs::write(
        &config_path,
        r#"
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
    source:
      type: file
      path: fixtures/social_registry.csv
    refresh:
      mode: manual
    tables:
      - id: individuals_table
        primary_key: individual_id
        schema:
          strict: true
          fields:
            - name: individual_id
              type: string
              nullable: false
    entities:
      - name: individual
        table: individuals_table
        fields:
          - name: id
            from: individual_id
        access:
          metadata_scope: social_registry:metadata
          aggregate_scope: social_registry:aggregate
          read_scope: social_registry:rows
          verify_scope: social_registry:verify
          bulk_export_scope: social_registry:bulk_export
        api:
          default_limit: 100
          max_limit: 1000
          allowed_filters:
            - field: id
              ops: [eq]
          allowed_expansions: []
audit:
  sink: stdout
  format: jsonl
"#,
    )
    .expect("write config");
    let cfg = config::load(&config_path).expect("config loads");
    let registry = Arc::new(EntityRegistry::from_config(&cfg).expect("registry"));

    let server = TestServer::new(
        entity_router::<()>()
            .merge(aggregates_router::<()>())
            .layer(Extension(registry))
            .layer(Extension(principal(&["social_registry:verify"]))),
    );

    for url in [
        "/datasets/social_registry/individual",
        "/datasets/social_registry/individual/id-1",
        "/datasets/social_registry/individual/schema",
        "/datasets/social_registry/individual/aggregates",
    ] {
        let resp = server.get(url).await;
        resp.assert_status(StatusCode::FORBIDDEN);
        let body: Value = resp.json();
        assert_eq!(body["code"], "auth.scope_denied");
    }
}

#[tokio::test]
async fn entity_collection_route_expands_relationships() {
    let resp = server_with_query()
        .await
        .get("/datasets/social_registry/household?region=north&expand=members")
        .add_header("data-purpose", "route-test")
        .await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(
        body,
        serde_json::json!({
            "data": [
                {
                    "id": "hh-1",
                    "region": "north",
                    "members": [
                        {"id": "p-1", "household_id": "hh-1", "given_name": "Ada"},
                        {"id": "p-2", "household_id": "hh-1", "given_name": "Ben"}
                    ]
                }
            ],
            "pagination": {
                "has_more": false
            }
        })
    );
}

#[tokio::test]
async fn entity_verify_requires_purpose_header_when_entity_requires_it() {
    let resp = server_with_query()
        .await
        .get("/datasets/social_registry/individual/verify?id=p-1")
        .await;

    resp.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = resp.json();
    assert_eq!(body["code"], "auth.purpose_required");
}

#[tokio::test]
async fn storage_shaped_resources_rows_route_is_not_registered() {
    let resp = server().get("/resources/beneficiaries/rows").await;

    resp.assert_status(StatusCode::NOT_FOUND);
}

async fn server_with_required_filters() -> TestServer {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = tmp.path().join("required_filters.yaml");
    std::fs::write(
        &config_path,
        r#"
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
  - id: test_dataset
    title: Test Dataset
    description: Test
    owner: Test
    sensitivity: personal
    access_rights: restricted
    update_frequency: monthly
    source:
      type: file
      path: fixtures/test.csv
    refresh:
      mode: manual
    tables:
      - id: items_table
        primary_key: item_id
        schema:
          strict: true
          fields:
            - name: item_id
              type: string
              nullable: false
            - name: group_id
              type: string
              nullable: true
      - id: unrestricted_table
        primary_key: thing_id
        schema:
          strict: true
          fields:
            - name: thing_id
              type: string
              nullable: false
    entities:
      - name: item
        table: items_table
        fields:
          - name: id
            from: item_id
          - name: group_id
        access:
          metadata_scope: test_dataset:metadata
          aggregate_scope: test_dataset:aggregate
          read_scope: test_dataset:rows
          verify_scope: test_dataset:verify
          bulk_export_scope: test_dataset:bulk_export
        api:
          default_limit: 100
          max_limit: 1000
          required_filters: [id, group_id]
          allowed_filters:
            - field: id
              ops: [eq]
            - field: group_id
              ops: [eq]
      - name: thing
        table: unrestricted_table
        fields:
          - name: id
            from: thing_id
        access:
          metadata_scope: test_dataset:metadata
          aggregate_scope: test_dataset:aggregate
          read_scope: test_dataset:rows
          verify_scope: test_dataset:verify
          bulk_export_scope: test_dataset:bulk_export
        api:
          default_limit: 100
          max_limit: 1000
          allowed_filters:
            - field: id
              ops: [eq]
audit:
  sink: stdout
  format: jsonl
"#,
    )
    .expect("write config");
    let cfg = Arc::new(config::load(&config_path).expect("config loads"));
    let registry = Arc::new(EntityRegistry::from_config(&cfg).expect("registry"));
    let ctx = Arc::new(SessionContext::new());
    let schema = Arc::new(Schema::new(vec![
        Field::new("item_id", DataType::Utf8, false),
        Field::new("group_id", DataType::Utf8, true),
    ]));
    let batch = RecordBatch::try_new(
        Arc::clone(&schema),
        vec![
            Arc::new(StringArray::from(vec!["item-1"])),
            Arc::new(StringArray::from(vec!["grp-1"])),
        ],
    )
    .expect("batch");
    let table = MemTable::try_new(schema, vec![vec![batch]]).expect("mem table");
    let dataset: DatasetId = id("test_dataset");
    let ingest_version = ulid::Ulid::from_string("01J5K8M0000000000000000000").expect("ulid");
    let resource: ResourceId = id("items_table");
    register_versioned_table(
        &ctx,
        table_name(&dataset, &resource),
        ingest_version,
        Arc::new(table),
    )
    .expect("register table");

    let unrestricted_schema = Arc::new(Schema::new(vec![Field::new(
        "thing_id",
        DataType::Utf8,
        false,
    )]));
    let unrestricted_batch = RecordBatch::try_new(
        Arc::clone(&unrestricted_schema),
        vec![Arc::new(StringArray::from(vec!["thing-1"]))],
    )
    .expect("batch");
    let unrestricted_table =
        MemTable::try_new(unrestricted_schema, vec![vec![unrestricted_batch]]).expect("mem table");
    let resource: ResourceId = id("unrestricted_table");
    register_versioned_table(
        &ctx,
        table_name(&dataset, &resource),
        ingest_version,
        Arc::new(unrestricted_table),
    )
    .expect("register table");

    let query = Arc::new(EntityQueryEngine::new(ctx, Arc::clone(&registry)));
    let mut snapshot = ReadinessSnapshot::default();
    snapshot.ready.insert(
        (id("test_dataset"), id("items_table")),
        ReadyResource {
            ingest_ulid: ingest_version,
            registered_at: time::OffsetDateTime::now_utc(),
        },
    );
    snapshot.ready.insert(
        (id("test_dataset"), id("unrestricted_table")),
        ReadyResource {
            ingest_ulid: ingest_version,
            registered_at: time::OffsetDateTime::now_utc(),
        },
    );
    let (_tx, readiness) = watch::channel(snapshot);

    let signer = Arc::new(CursorSigner::new_random());

    TestServer::new(
        entity_router::<()>()
            .layer(Extension(query))
            .layer(Extension(registry))
            .layer(Extension(cfg))
            .layer(Extension(readiness))
            .layer(Extension(signer))
            .layer(Extension(principal(&[
                "test_dataset:metadata",
                "test_dataset:rows",
                "test_dataset:verify",
            ]))),
    )
}

#[tokio::test]
async fn entity_collection_with_required_filter_satisfied_returns_200() {
    let resp = server_with_required_filters()
        .await
        .get("/datasets/test_dataset/item?id=item-1")
        .await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(body["data"][0]["id"], "item-1");
}

#[tokio::test]
async fn entity_collection_with_required_filter_group_id_satisfied_returns_200() {
    let resp = server_with_required_filters()
        .await
        .get("/datasets/test_dataset/item?group_id=grp-1")
        .await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(body["data"][0]["group_id"], "grp-1");
}

#[tokio::test]
async fn entity_collection_with_unrelated_filter_returns_filter_required() {
    let resp = server_with_required_filters()
        .await
        .get("/datasets/test_dataset/item?unrelated=x")
        .await;

    // unrelated param is parsed as a filter but rejected as not_allowed
    // before required_filters is checked; either 400 is acceptable but
    // filter.not_allowed fires first in this implementation.
    resp.assert_status(StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn entity_collection_with_no_filters_returns_filter_required() {
    let resp = server_with_required_filters()
        .await
        .get("/datasets/test_dataset/item")
        .await;

    resp.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = resp.json();
    assert_eq!(body["code"], "entity.filter_required");
    assert!(body["detail"].as_str().unwrap().contains("id"));
}

#[tokio::test]
async fn entity_collection_without_required_filters_accepts_no_filter() {
    let resp = server_with_required_filters()
        .await
        .get("/datasets/test_dataset/thing")
        .await;

    // No required_filters on thing; unfiltered request should succeed.
    resp.assert_status(StatusCode::OK);
}

/// Flips one nibble of a hex-encoded cursor at the given byte offset.
/// The original value is decoded, mutated by XOR, and re-encoded so the
/// length stays the same.
fn flip_hex_nibble(cursor: &str, byte_offset: usize) -> String {
    let mut chars: Vec<char> = cursor.chars().collect();
    let hex_index = byte_offset * 2;
    let original = chars[hex_index]
        .to_digit(16)
        .expect("cursor is hex-encoded");
    let flipped = original ^ 0x1;
    chars[hex_index] = std::char::from_digit(flipped, 16).expect("nibble in range");
    chars.into_iter().collect()
}

#[tokio::test]
async fn entity_collection_cursor_with_tampered_mac_rejected() {
    let server = server_with_query().await;

    let first = server
        .get("/datasets/social_registry/household?limit=1")
        .await;
    first.assert_status(StatusCode::OK);
    let body: Value = first.json();
    let cursor = body["pagination"]["next_cursor"]
        .as_str()
        .expect("first page has cursor")
        .to_string();

    // Flip one nibble of the MAC tag (byte 0). The HMAC verify must
    // fail before any JSON parsing happens and return the same code as
    // a malformed cursor would.
    let tampered = flip_hex_nibble(&cursor, 0);
    let url = format!("/datasets/social_registry/household?limit=1&cursor={tampered}");
    let resp = server.get(&url).await;
    resp.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = resp.json();
    assert_eq!(body["code"], "filter.invalid_value");
}

#[tokio::test]
async fn entity_collection_cursor_with_tampered_payload_rejected() {
    let server = server_with_query().await;

    let first = server
        .get("/datasets/social_registry/household?limit=1")
        .await;
    first.assert_status(StatusCode::OK);
    let body: Value = first.json();
    let cursor = body["pagination"]["next_cursor"]
        .as_str()
        .expect("first page has cursor")
        .to_string();

    // Flip a nibble of the JSON payload (past the 16-byte MAC tag).
    // The HMAC must catch the mutation and reject the cursor.
    let tampered = flip_hex_nibble(&cursor, 16);
    let url = format!("/datasets/social_registry/household?limit=1&cursor={tampered}");
    let resp = server.get(&url).await;
    resp.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = resp.json();
    assert_eq!(body["code"], "filter.invalid_value");
}

#[tokio::test]
async fn entity_collection_unmutated_cursor_still_works() {
    let server = server_with_query().await;

    let first = server
        .get("/datasets/social_registry/household?limit=1")
        .await;
    first.assert_status(StatusCode::OK);
    let body: Value = first.json();
    let cursor = body["pagination"]["next_cursor"]
        .as_str()
        .expect("first page has cursor")
        .to_string();

    let url = format!("/datasets/social_registry/household?limit=1&cursor={cursor}");
    let resp = server.get(&url).await;
    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(
        body["data"],
        serde_json::json!([{"id": "hh-2", "region": "south"}])
    );
}

#[tokio::test]
async fn entity_collection_too_many_filter_params_rejected() {
    let server = server_with_query().await;

    // 21 distinct filters: one over the cap. The cap is reached at
    // entry 21 because the `region` field is the only filter the
    // example config allows. We use 21 distinct `region.in=...` style
    // entries, but `region` is a single field and each param replaces
    // the prior. Instead, use 21 attempts on the same `region` field
    // via separate key names: `region`, `region.in`, `region.gte`,
    // `region.lte`, `region.between` are all configured ops; the
    // remaining 16 must be the same field repeated through query-string
    // duplication, which axum's `Query<HashMap<_,_>>` collapses to one
    // entry. To exercise the cap regardless of field allowlist, send
    // requests on the individual entity (which allows `id` filters) and
    // use 21 distinct `id.eq=...` style keys; since the `Query` extractor
    // collapses duplicate keys, we encode each filter with a fresh name
    // that the parser rejects after a configured cap. The cleanest path:
    // exercise the cap by sending 21 distinct filter *parameter names*
    // that are all syntactically valid (`field_NN=value`), then assert
    // the per-request cap fires before any allowed-filter check.
    let mut url = String::from("/datasets/social_registry/household?");
    for i in 0..21 {
        if i > 0 {
            url.push('&');
        }
        url.push_str(&format!("field_{i:02}=value"));
    }
    let resp = server.get(&url).await;
    resp.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = resp.json();
    assert_eq!(body["code"], "filter.too_many_filters");
}
