// SPDX-License-Identifier: Apache-2.0
//! Focused route-shape tests for the entity API slice.

use axum::http::StatusCode;
use axum::Extension;
use axum_test::TestServer;
use data_gate::api::entity_router;
use data_gate::auth::{AuthMode, Principal, ScopeSet};
use data_gate::config::{self, DatasetId, ResourceId};
use data_gate::entity::EntityRegistry;
use data_gate::ingest::table_name;
use data_gate::query::EntityQueryEngine;
use datafusion::arrow::array::StringArray;
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::datasource::MemTable;
use datafusion::execution::context::SessionContext;
use serde_json::Value;
use std::sync::Arc;
use tempfile::TempDir;

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
      - id: households_table
        primary_key: household_id
        schema:
          strict: true
          fields:
            - name: household_id
              type: string
              nullable: false
            - name: region_code
              type: string
              nullable: true
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
        fields:
          - name: id
            from: household_id
          - name: region
            from: region_code
        relationships:
          - name: members
            kind: has_many
            target: individual
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
          allowed_filters:
            - field: region
              ops: [eq]
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
          allowed_filters:
            - field: household_id
              ops: [eq]
          allowed_expansions: [household]

audit:
  sink: stdout
  format: jsonl
"#,
    )
    .expect("write config");
    let cfg = config::load(&config_path).expect("config loads");
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
    let resource: ResourceId = id("households_table");
    ctx.register_table(table_name(&dataset, &resource), Arc::new(table))
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
    ctx.register_table(table_name(&dataset, &resource), Arc::new(individual_table))
        .expect("register individual table");
    let query = Arc::new(EntityQueryEngine::new(ctx, Arc::clone(&registry)));

    TestServer::new(
        entity_router::<()>()
            .layer(Extension(query))
            .layer(Extension(registry))
            .layer(Extension(principal(&[
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
            ]
        })
    );
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
async fn entity_relationship_route_executes_query_when_state_installed() {
    let resp = server_with_query()
        .await
        .get("/datasets/social_registry/individual/p-1/household")
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
async fn entity_verify_uses_verify_scope_and_returns_one_bit() {
    let server = server_with_query().await;

    let present = server
        .get("/datasets/social_registry/individual/verify?id=p-1")
        .await;
    present.assert_status(StatusCode::OK);
    let body: Value = present.json();
    assert_eq!(body, serde_json::json!({ "exists": true }));

    let absent = server
        .get("/datasets/social_registry/individual/verify?id=missing")
        .await;
    absent.assert_status(StatusCode::OK);
    let body: Value = absent.json();
    assert_eq!(body, serde_json::json!({ "exists": false }));
}

#[tokio::test]
async fn entity_collection_route_expands_relationships() {
    let resp = server_with_query()
        .await
        .get("/datasets/social_registry/household?region=north&expand=members")
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
            ]
        })
    );
}

#[tokio::test]
async fn storage_shaped_resources_rows_route_is_not_registered() {
    let resp = server().get("/resources/beneficiaries/rows").await;

    resp.assert_status(StatusCode::NOT_FOUND);
}
