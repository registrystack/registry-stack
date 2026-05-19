// SPDX-License-Identifier: Apache-2.0
//! Focused tests for entity aggregate listing and execution.

use std::sync::Arc;

use axum::Extension;
use axum_test::TestServer;
use datafusion::arrow::array::{Float64Array, StringArray};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::datasource::MemTable;
use datafusion::execution::context::SessionContext;
use registry_relay::api::aggregates_router;
use registry_relay::auth::{AuthMode, Principal, ScopeSet};
use registry_relay::config::{self, DatasetId, ResourceId};
use registry_relay::entity::EntityRegistry;
use registry_relay::ingest::table_name;
use registry_relay::query::AggregateQueryEngine;
use serde_json::{json, Value};
use tempfile::TempDir;

fn id<T: serde::de::DeserializeOwned>(value: &str) -> T {
    serde_json::from_str(&format!(r#""{value}""#)).expect("id deserializes")
}

fn principal(scopes: &[&str]) -> Principal {
    Principal {
        principal_id: "test".to_string(),
        scopes: scopes.iter().copied().collect::<ScopeSet>(),
        auth_mode: AuthMode::ApiKey,
    }
}

async fn server_with_aggregates() -> TestServer {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = tmp.path().join("aggregates_entity.yaml");
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
            - name: region_code
              type: string
              nullable: true
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
            - name: payment_amount
              type: number
              nullable: true
    entities:
      - name: household
        table: households_table
        fields:
          - name: id
            from: household_id
          - name: region
            from: region_code
        access:
          metadata_scope: social_registry:metadata
          aggregate_scope: social_registry:aggregate
          read_scope: social_registry:rows
          verify_scope: social_registry:verify
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
          - name: payment_amount
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
        api:
          default_limit: 100
          max_limit: 1000
        aggregates:
          - id: by_municipality
            description: Number of individuals by municipality
            group_by:
              - municipality_code
            measures:
              - name: individual_count
                function: count
                column: id
              - name: min_payment
                function: min
                column: payment_amount
              - name: max_payment
                function: max
                column: payment_amount
            disclosure_control:
              min_group_size: 1
              suppression: omit
          - id: by_municipality_masked
            description: Masked number of individuals by municipality
            group_by:
              - municipality_code
            measures:
              - name: individual_count
                function: count
                column: id
            disclosure_control:
              min_group_size: 2
              suppression: mask
          - id: by_household_region
            description: Number of individuals by household region
            joins:
              - relationship: household
            group_by:
              - household.region
            measures:
              - name: individual_count
                function: count
                column: id
            disclosure_control:
              min_group_size: 2
              suppression: omit

audit:
  sink: stdout
  format: jsonl
"#,
    )
    .expect("write config");
    let cfg = Arc::new(config::load(&config_path).expect("config loads"));
    let registry = Arc::new(EntityRegistry::from_config(&cfg).expect("registry"));
    let ctx = Arc::new(SessionContext::new());

    register_households(&ctx);
    register_individuals(&ctx);

    let query = Arc::new(AggregateQueryEngine::new(
        Arc::clone(&ctx),
        Arc::clone(&registry),
        Arc::clone(&cfg),
    ));

    TestServer::new(
        aggregates_router::<()>()
            .layer(Extension(query))
            .layer(Extension(registry))
            .layer(Extension(principal(&["social_registry:aggregate"]))),
    )
}

fn register_households(ctx: &SessionContext) {
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
    .expect("household batch");
    let table = MemTable::try_new(schema, vec![vec![batch]]).expect("household table");
    let dataset: DatasetId = id("social_registry");
    let resource: ResourceId = id("households_table");
    ctx.register_table(table_name(&dataset, &resource), Arc::new(table))
        .expect("register households");
}

fn register_individuals(ctx: &SessionContext) {
    let schema = Arc::new(Schema::new(vec![
        Field::new("individual_id", DataType::Utf8, false),
        Field::new("household_id", DataType::Utf8, false),
        Field::new("municipality_code", DataType::Utf8, true),
        Field::new("payment_amount", DataType::Float64, true),
    ]));
    let batch = RecordBatch::try_new(
        Arc::clone(&schema),
        vec![
            Arc::new(StringArray::from(vec!["ind-1", "ind-2", "ind-3"])),
            Arc::new(StringArray::from(vec!["hh-1", "hh-1", "hh-2"])),
            Arc::new(StringArray::from(vec!["mun-1", "mun-1", "mun-2"])),
            Arc::new(Float64Array::from(vec![10.0, 20.0, 30.0])),
        ],
    )
    .expect("individual batch");
    let table = MemTable::try_new(schema, vec![vec![batch]]).expect("individual table");
    let dataset: DatasetId = id("social_registry");
    let resource: ResourceId = id("individuals_table");
    ctx.register_table(table_name(&dataset, &resource), Arc::new(table))
        .expect("register individuals");
}

#[tokio::test]
async fn lists_configured_entity_aggregates() {
    let resp = server_with_aggregates()
        .await
        .get("/datasets/social_registry/individual/aggregates")
        .await;

    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["data"].as_array().expect("data array").len(), 3);
    assert_eq!(body["data"][0]["aggregate_id"], "by_municipality");
    assert_eq!(body["data"][0]["measures"][0]["function"], "count");
    assert_eq!(body["data"][0]["measures"][1]["function"], "min");
    assert_eq!(body["data"][0]["measures"][2]["function"], "max");
}

#[tokio::test]
async fn executes_single_entity_count_aggregate() {
    let resp = server_with_aggregates()
        .await
        .get("/datasets/social_registry/individual/aggregates/by_municipality")
        .await;

    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["suppressed_groups"], 0);
    assert_eq!(
        sorted_rows(&body),
        vec![
            json!({
                "municipality_code": "mun-1",
                "individual_count": 2,
                "min_payment": 10.0,
                "max_payment": 20.0
            }),
            json!({
                "municipality_code": "mun-2",
                "individual_count": 1,
                "min_payment": 30.0,
                "max_payment": 30.0
            }),
        ]
    );
}

#[tokio::test]
async fn masks_measures_below_min_group_size_without_removing_group_keys() {
    let resp = server_with_aggregates()
        .await
        .get("/datasets/social_registry/individual/aggregates/by_municipality_masked")
        .await;

    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["min_group_size"], 2);
    assert_eq!(body["suppressed_groups"], 1);
    assert_eq!(
        sorted_rows(&body),
        vec![
            json!({"municipality_code": "mun-1", "individual_count": 2}),
            json!({"municipality_code": "mun-2", "individual_count": null}),
        ]
    );
}

#[tokio::test]
async fn executes_direct_relationship_group_by_with_min_group_size() {
    let resp = server_with_aggregates()
        .await
        .get("/datasets/social_registry/individual/aggregates/by_household_region")
        .await;

    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["min_group_size"], 2);
    assert_eq!(body["suppressed_groups"], 1);
    assert_eq!(
        sorted_rows(&body),
        vec![json!({"household.region": "north", "individual_count": 2})]
    );
}

fn sorted_rows(body: &Value) -> Vec<Value> {
    let mut rows = body["rows"].as_array().expect("rows array").clone();
    rows.sort_by_key(|row| {
        row.get("municipality_code")
            .or_else(|| row.get("household.region"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    });
    rows
}
