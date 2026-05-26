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
            - name: enrolled_on
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
          - id: min_payment
            label: Minimum payment
            function: min
            column: payment_amount
            unit_measure: currency
          - id: max_payment
            label: Maximum payment
            function: max
            column: payment_amount
            unit_measure: currency
        temporal_field: enrolled_on
        allowed_filters:
          - field: enrolled_on
            ops: [gte, lte, between]
        disclosure_control:
          min_group_size: 1
          suppression: omit
          report_suppressed_rows: true
      - id: by_municipality_masked
        title: Masked individuals by municipality
        description: Masked number of individuals by municipality
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
          min_group_size: 2
          suppression: null
          report_suppressed_rows: true
      - id: by_required_municipality
        title: Required municipality aggregate
        description: Number of individuals by a required municipality filter
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
        allowed_filters:
          - field: municipality_code
            ops: [eq, in]
        required_filters:
          - municipality_code
        disclosure_control:
          min_group_size: 1
          suppression: omit
          report_suppressed_rows: true
      - id: by_household_region
        title: Individuals by household region
        description: Number of individuals by household region
        source_entity: individual
        default_group_by:
          - household_region
        dimensions:
          - id: household_region
            label: Household region
            field: household.region
        indicators:
          - id: individual_count
            label: Individuals
            function: count
            column: id
            unit_measure: people
        disclosure_control:
          min_group_size: 2
          suppression: omit
          report_suppressed_rows: true
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
          - name: enrolled_on
        relationships:
          - name: household
            kind: belongs_to
            target: household
            foreign_key: household_id
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
            .layer(Extension(principal(&[
                "social_registry:metadata",
                "social_registry:aggregate",
            ]))),
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
        Field::new("enrolled_on", DataType::Utf8, true),
    ]));
    let batch = RecordBatch::try_new(
        Arc::clone(&schema),
        vec![
            Arc::new(StringArray::from(vec!["ind-1", "ind-2", "ind-3"])),
            Arc::new(StringArray::from(vec!["hh-1", "hh-1", "hh-2"])),
            Arc::new(StringArray::from(vec!["mun-1", "mun-1", "mun-2"])),
            Arc::new(Float64Array::from(vec![10.0, 20.0, 30.0])),
            Arc::new(StringArray::from(vec![
                "2024-01-10",
                "2024-02-10",
                "2025-01-10",
            ])),
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
async fn lists_configured_dataset_aggregates() {
    let resp = server_with_aggregates()
        .await
        .get("/datasets/social_registry/aggregates")
        .await;

    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["data"].as_array().expect("data array").len(), 4);
    assert_eq!(body["data"][0]["aggregate_id"], "by_municipality");
    assert_eq!(
        body["data"][0]["indicators"][0]["aggregation_method"],
        "count"
    );
    assert_eq!(
        body["data"][0]["indicators"][1]["aggregation_method"],
        "min"
    );
    assert_eq!(
        body["data"][0]["indicators"][2]["aggregation_method"],
        "max"
    );
}

#[tokio::test]
async fn required_filters_are_enforced_for_aggregate_queries() {
    let server = server_with_aggregates().await;

    let missing = server
        .get("/datasets/social_registry/aggregates/by_required_municipality")
        .await;
    missing.assert_status_bad_request();
    let body: Value = missing.json();
    assert_eq!(body["code"], "aggregate.filter_required");

    let satisfied = server
        .post("/datasets/social_registry/aggregates/by_required_municipality/query")
        .json(&json!({
            "filters": { "municipality_code": "mun-1" }
        }))
        .await;
    satisfied.assert_status_ok();
    let body: Value = satisfied.json();
    assert_eq!(
        sorted_rows(&body),
        vec![json!({
            "municipality_code": "mun-1",
            "individual_count": 2
        })]
    );
}

#[tokio::test]
async fn executes_single_entity_count_aggregate() {
    let resp = server_with_aggregates()
        .await
        .get("/datasets/social_registry/aggregates/by_municipality")
        .await;

    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["disclosure_control"]["suppressed_rows"], 0);
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
async fn post_query_applies_temporal_filter_when_configured() {
    let resp = server_with_aggregates()
        .await
        .post("/datasets/social_registry/aggregates/by_municipality/query")
        .json(&json!({
            "indicators": ["individual_count"],
            "group_by": ["municipality_code"],
            "temporal": {
                "from": "2024-01-01",
                "to": "2024-12-31"
            }
        }))
        .await;

    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(
        sorted_rows(&body),
        vec![json!({
            "municipality_code": "mun-1",
            "individual_count": 2
        })]
    );
}

#[tokio::test]
async fn masks_measures_below_min_group_size_without_removing_group_keys() {
    let resp = server_with_aggregates()
        .await
        .get("/datasets/social_registry/aggregates/by_municipality_masked")
        .await;

    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["disclosure_control"]["min_cell_size"], 2);
    assert_eq!(body["disclosure_control"]["suppressed_rows"], 1);
    assert_eq!(
        sorted_rows(&body),
        vec![
            json!({"municipality_code": "mun-1", "individual_count": 2}),
            json!({"municipality_code": "mun-2", "individual_count": null, "attributes": {"individual_count$status": "S"}}),
        ]
    );
}

#[tokio::test]
async fn executes_direct_relationship_group_by_with_min_group_size() {
    let resp = server_with_aggregates()
        .await
        .get("/datasets/social_registry/aggregates/by_household_region")
        .await;

    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["disclosure_control"]["min_cell_size"], 2);
    assert_eq!(body["disclosure_control"]["suppressed_rows"], 1);
    assert_eq!(
        sorted_rows(&body),
        vec![json!({"household_region": "north", "individual_count": 2})]
    );
}

fn sorted_rows(body: &Value) -> Vec<Value> {
    let mut rows = body["data"].as_array().expect("data array").clone();
    rows.sort_by_key(|row| {
        row.get("municipality_code")
            .or_else(|| row.get("household.region"))
            .or_else(|| row.get("household_region"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string()
    });
    rows
}
