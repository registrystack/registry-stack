// SPDX-License-Identifier: Apache-2.0
//! Focused tests for entity aggregate listing and execution.

use std::sync::Arc;

use axum::middleware::from_fn;
use axum::{Extension, Router};
use axum_test::TestServer;
use datafusion::arrow::array::{Float64Array, StringArray};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::datasource::MemTable;
use datafusion::execution::context::SessionContext;
use registry_relay::api::{aggregates_router, entity_router};
use registry_relay::audit::{audit_layer, AuditPipeline, InMemorySink};
use registry_relay::auth::{AuthMode, Principal, ScopeSet};
use registry_relay::config::{self, DatasetId, ResourceId};
use registry_relay::entity::EntityRegistry;
use registry_relay::ingest::table_name;
use registry_relay::query::{
    AggregateFilter, AggregateFilterOp, AggregateQueryEngine, AggregateQueryRequest,
    EntityQueryEngine,
};
use serde_json::{json, Value};
use tempfile::TempDir;

const SDMX_JSON_DATA_SCHEMA_2_1: &str =
    include_str!("../resources/schemas/sdmx-json/2.1/sdmx-json-data-schema.json");

fn id<T: serde::de::DeserializeOwned>(value: &str) -> T {
    serde_json::from_str(&format!(r#""{value}""#)).expect("id deserializes")
}

fn principal(scopes: &[&str]) -> Principal {
    principal_with_id(scopes, "test")
}

fn principal_with_id(scopes: &[&str], principal_id: &str) -> Principal {
    Principal {
        principal_id: principal_id.to_string(),
        scopes: scopes.iter().copied().collect::<ScopeSet>(),
        auth_mode: AuthMode::ApiKey,
    }
}

const AGGREGATE_CONFIG: &str = r#"
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
        required_filter_bindings:
          - field: municipality_code
            source: principal_id
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
  hash_secret_env: REGISTRY_RELAY_AUDIT_HASH_SECRET
"#;

async fn server_with_aggregates() -> TestServer {
    server_with_aggregate_scopes(&[
        "social_registry:metadata",
        "social_registry:aggregate",
        "social_registry:rows",
    ])
    .await
}

async fn server_with_aggregates_and_principal_id(principal_id: &str) -> TestServer {
    server_with_aggregate_config_and_principal_id(
        AGGREGATE_CONFIG.to_string(),
        &[
            "social_registry:metadata",
            "social_registry:aggregate",
            "social_registry:rows",
        ],
        principal_id,
    )
    .await
}

async fn server_with_aggregate_scopes(scopes: &[&str]) -> TestServer {
    server_with_aggregate_config(AGGREGATE_CONFIG.to_string(), scopes).await
}

async fn server_with_aggregate_config(config_yaml: String, scopes: &[&str]) -> TestServer {
    server_with_aggregate_config_and_principal_id(config_yaml, scopes, "test").await
}

async fn server_with_aggregate_config_and_principal_id(
    config_yaml: String,
    scopes: &[&str],
    principal_id: &str,
) -> TestServer {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = tmp.path().join("aggregates_entity.yaml");
    std::fs::write(&config_path, config_yaml).expect("write config");
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
            .layer(Extension(principal_with_id(scopes, principal_id))),
    )
}

async fn aggregate_query_engine(config_yaml: String) -> AggregateQueryEngine {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = tmp.path().join("aggregates_entity.yaml");
    std::fs::write(&config_path, config_yaml).expect("write config");
    let cfg = Arc::new(config::load(&config_path).expect("config loads"));
    let registry = Arc::new(EntityRegistry::from_config(&cfg).expect("registry"));
    let ctx = Arc::new(SessionContext::new());

    register_households(&ctx);
    register_individuals(&ctx);

    AggregateQueryEngine::new(Arc::clone(&ctx), Arc::clone(&registry), Arc::clone(&cfg))
}

async fn server_with_aggregate_config_and_audit(
    config_yaml: String,
    scopes: &[&str],
) -> (TestServer, InMemorySink) {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = tmp.path().join("aggregates_entity.yaml");
    std::fs::write(&config_path, config_yaml).expect("write config");
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
    let audit_sink = InMemorySink::new();
    let audit_pipeline: Arc<AuditPipeline> = AuditPipeline::from_sink(audit_sink.clone());

    let app = aggregates_router::<()>()
        .layer(Extension(query))
        .layer(Extension(registry))
        .layer(Extension(principal(scopes)))
        .layer(from_fn(audit_layer))
        .layer(Extension(audit_pipeline));

    (TestServer::new(app), audit_sink)
}

fn audit_record_from_envelope(line: &str) -> Value {
    let envelope: Value = serde_json::from_str(line.trim_end()).expect("valid audit envelope JSON");
    envelope["record"].clone()
}

async fn server_with_formula_cells() -> TestServer {
    server_with_municipalities(&["=cmd", "+cmd", "-cmd", "@cmd", "\tcmd", "\rcmd"]).await
}

async fn server_with_municipalities(municipality_codes: &[&str]) -> TestServer {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = tmp.path().join("aggregates_entity.yaml");
    std::fs::write(&config_path, AGGREGATE_CONFIG).expect("write config");
    let cfg = Arc::new(config::load(&config_path).expect("config loads"));
    let registry = Arc::new(EntityRegistry::from_config(&cfg).expect("registry"));
    let ctx = Arc::new(SessionContext::new());

    register_households(&ctx);
    register_individuals_with_municipalities(&ctx, municipality_codes);

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
                "social_registry:rows",
            ]))),
    )
}

async fn server_with_restricted_aggregate_metadata(scopes: &[&str]) -> TestServer {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = tmp.path().join("aggregates_entity.yaml");
    let config = AGGREGATE_CONFIG.replace(
        "      - id: by_household_region\n",
        "      - id: by_household_region\n        access:\n          metadata_scope: social_registry:region_metadata\n",
    );
    std::fs::write(&config_path, config).expect("write config");
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
            .layer(Extension(principal(scopes))),
    )
}

async fn protected_router_with_aggregates() -> TestServer {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = tmp.path().join("aggregates_entity.yaml");
    std::fs::write(&config_path, AGGREGATE_CONFIG).expect("write config");
    let cfg = Arc::new(config::load(&config_path).expect("config loads"));
    let registry = Arc::new(EntityRegistry::from_config(&cfg).expect("registry"));
    let ctx = Arc::new(SessionContext::new());

    register_households(&ctx);
    register_individuals(&ctx);

    let entity_query = Arc::new(EntityQueryEngine::new(
        Arc::clone(&ctx),
        Arc::clone(&registry),
    ));
    let aggregate_query = Arc::new(AggregateQueryEngine::new(
        Arc::clone(&ctx),
        Arc::clone(&registry),
        Arc::clone(&cfg),
    ));
    let app = Router::new()
        .merge(aggregates_router::<()>())
        .merge(entity_router())
        .layer(Extension(aggregate_query))
        .layer(Extension(entity_query))
        .layer(Extension(registry))
        .layer(Extension(principal(&[
            "social_registry:metadata",
            "social_registry:aggregate",
            "social_registry:rows",
        ])));

    TestServer::new(app)
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
    register_individuals_with_municipalities(ctx, &["mun-1", "mun-1", "mun-2"]);
}

fn register_individuals_with_municipalities(ctx: &SessionContext, municipality_codes: &[&str]) {
    let len = municipality_codes.len();
    let schema = Arc::new(Schema::new(vec![
        Field::new("individual_id", DataType::Utf8, false),
        Field::new("household_id", DataType::Utf8, false),
        Field::new("municipality_code", DataType::Utf8, true),
        Field::new("payment_amount", DataType::Float64, true),
        Field::new("enrolled_on", DataType::Utf8, true),
    ]));
    let individual_ids = (0..len)
        .map(|idx| format!("ind-{}", idx + 1))
        .collect::<Vec<_>>();
    let household_ids = (0..len)
        .map(|idx| if idx < 2 { "hh-1" } else { "hh-2" })
        .collect::<Vec<_>>();
    let payment_amounts = (0..len)
        .map(|idx| Some(((idx + 1) * 10) as f64))
        .collect::<Vec<_>>();
    let enrolled_on = (0..len)
        .map(|idx| {
            if idx == 0 {
                "2024-01-10"
            } else if idx == 1 {
                "2024-02-10"
            } else {
                "2025-01-10"
            }
        })
        .collect::<Vec<_>>();
    let batch = RecordBatch::try_new(
        Arc::clone(&schema),
        vec![
            Arc::new(StringArray::from(individual_ids)),
            Arc::new(StringArray::from(household_ids)),
            Arc::new(StringArray::from(municipality_codes.to_vec())),
            Arc::new(Float64Array::from(payment_amounts)),
            Arc::new(StringArray::from(enrolled_on)),
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
        .get("/v1/datasets/social_registry/aggregates")
        .await;

    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["data"].as_array().expect("data array").len(), 4);
    assert_eq!(body["data"][0]["aggregate_id"], "by_municipality");
    assert!(body["data"][0].get("indicators").is_none());
    assert_eq!(
        body["data"][0]["measures"][0]["aggregation_method"],
        "count"
    );
    assert_eq!(body["data"][0]["measures"][1]["aggregation_method"], "min");
    assert_eq!(body["data"][0]["measures"][2]["aggregation_method"], "max");
}

#[tokio::test]
async fn aggregate_structure_route_returns_dimensions_and_measures() {
    let resp = server_with_aggregates()
        .await
        .get("/v1/datasets/social_registry/aggregates/by_municipality/structure")
        .await;

    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["aggregate_id"], "by_municipality");
    assert_eq!(body["dimensions"][0]["id"], "municipality_code");
    assert_eq!(body["measures"][0]["id"], "individual_count");
    assert_eq!(body["measures"][1]["aggregation_method"], "min");
    assert!(body.get("indicators").is_none());
    assert_eq!(
        body["links"][0]["href"],
        "/v1/datasets/social_registry/aggregates/by_municipality/structure"
    );
}

#[tokio::test]
async fn lists_dataset_measure_and_dimension_discovery() {
    let server = server_with_aggregates().await;

    let measures = server.get("/v1/datasets/social_registry/measures").await;
    measures.assert_status_ok();
    let body: Value = measures.json();
    let data = body["data"].as_array().expect("measure data");
    assert_eq!(data.len(), 3);
    let individual_count = data
        .iter()
        .find(|item| item["id"] == "individual_count")
        .expect("individual count measure");
    assert_eq!(individual_count["aggregation_method"], "count");
    assert_eq!(
        individual_count["valid_dimensions"],
        json!(["household_region", "municipality_code"])
    );
    assert!(individual_count["queryable_via"]
        .as_array()
        .expect("queryable_via")
        .iter()
        .any(|value| value == "aggregates:by_municipality"));

    let measure = server
        .get("/v1/datasets/social_registry/measures/min_payment")
        .await;
    measure.assert_status_ok();
    let body: Value = measure.json();
    assert_eq!(body["id"], "min_payment");
    assert_eq!(body["unit_measure"], "currency");
    assert!(
        body.as_object()
            .expect("measure object")
            .contains_key("unit_multiplier"),
        "measure discovery must use the unit_multiplier spelling"
    );
    assert!(
        body.get("unit_mult").is_none(),
        "legacy unit_mult spelling must be dropped from measure discovery"
    );

    let dimensions = server.get("/v1/datasets/social_registry/dimensions").await;
    dimensions.assert_status_ok();
    let body: Value = dimensions.json();
    assert_eq!(body["data"].as_array().expect("dimension data").len(), 2);

    let dimension = server
        .get("/v1/datasets/social_registry/dimensions/municipality_code")
        .await;
    dimension.assert_status_ok();
    let body: Value = dimension.json();
    assert_eq!(body["id"], "municipality_code");
    assert_eq!(body["field"], "municipality_code");
}

#[tokio::test]
async fn aggregate_discovery_filters_by_aggregate_metadata_scope() {
    let server = server_with_restricted_aggregate_metadata(&[
        "social_registry:metadata",
        "social_registry:aggregate",
        "social_registry:rows",
    ])
    .await;

    let aggregates = server.get("/v1/datasets/social_registry/aggregates").await;
    aggregates.assert_status_ok();
    let body: Value = aggregates.json();
    let data = body["data"].as_array().expect("aggregate data");
    assert_eq!(data.len(), 3);
    assert!(
        !data
            .iter()
            .any(|item| item["aggregate_id"] == "by_household_region"),
        "aggregate list must omit aggregate-specific metadata the principal lacks"
    );

    let measures = server.get("/v1/datasets/social_registry/measures").await;
    measures.assert_status_ok();
    let body: Value = measures.json();
    let individual_count = body["data"]
        .as_array()
        .expect("measure data")
        .iter()
        .find(|item| item["id"] == "individual_count")
        .expect("individual count measure");
    assert_eq!(
        individual_count["valid_dimensions"],
        json!(["municipality_code"])
    );
    assert!(individual_count["aggregates"]
        .as_array()
        .expect("aggregates")
        .iter()
        .all(|item| item["aggregate_id"] != "by_household_region"));

    let hidden_dimension = server
        .get("/v1/datasets/social_registry/dimensions/household_region")
        .await;
    hidden_dimension.assert_status_bad_request();
}

#[tokio::test]
async fn aggregate_execution_requires_source_entity_read_scope() {
    let server =
        server_with_aggregate_scopes(&["social_registry:metadata", "social_registry:aggregate"])
            .await;

    let resp = server
        .get("/v1/datasets/social_registry/aggregates/by_municipality")
        .await;

    resp.assert_status_forbidden();
    assert_eq!(resp.json::<Value>()["code"], "auth.scope_denied");
}

#[tokio::test]
async fn aggregate_execution_enforces_source_entity_governed_purpose() {
    let config = AGGREGATE_CONFIG.replace(
        "          max_limit: 1000\naudit:",
        r#"          max_limit: 1000
          governed_policy:
            permitted_purposes:
              - capacity planning
            trusted_context: {}
audit:"#,
    );
    let server = server_with_aggregate_config(
        config,
        &[
            "social_registry:metadata",
            "social_registry:aggregate",
            "social_registry:rows",
        ],
    )
    .await;

    let get = server
        .get("/v1/datasets/social_registry/aggregates/by_municipality")
        .add_header("data-purpose", "casework")
        .await;
    get.assert_status_forbidden();
    assert_eq!(get.json::<Value>()["code"], "pdp.purpose_not_permitted");

    let post = server
        .post("/v1/datasets/social_registry/aggregates/by_municipality/query")
        .add_header("data-purpose", "casework")
        .json(&json!({ "group_by": ["municipality_code"] }))
        .await;
    post.assert_status_forbidden();
    assert_eq!(post.json::<Value>()["code"], "pdp.purpose_not_permitted");
}

#[tokio::test]
async fn aggregate_governed_denial_audit_records_pdp_provenance() {
    let config = AGGREGATE_CONFIG.replace(
        "          max_limit: 1000\naudit:",
        r#"          max_limit: 1000
          governed_policy:
            permitted_purposes:
              - capacity planning
            trusted_context: {}
audit:"#,
    );
    let (server, audit_sink) = server_with_aggregate_config_and_audit(
        config,
        &[
            "social_registry:metadata",
            "social_registry:aggregate",
            "social_registry:rows",
        ],
    )
    .await;

    let response = server
        .get("/v1/datasets/social_registry/aggregates/by_municipality")
        .add_header("data-purpose", "casework")
        .await;

    response.assert_status_forbidden();
    assert_eq!(
        response.json::<Value>()["code"],
        "pdp.purpose_not_permitted"
    );

    let records = audit_sink.snapshot();
    assert_eq!(
        records.len(),
        1,
        "denied governed aggregate request emits one audit record"
    );
    let record = audit_record_from_envelope(&records[0]);
    assert_eq!(
        record["path"],
        "/v1/datasets/social_registry/aggregates/by_municipality"
    );
    assert_eq!(record["dataset_id"], "social_registry");
    assert_eq!(record["aggregate_id"], "by_municipality");
    assert_eq!(record["purpose"], "casework");
    assert_eq!(record["status_code"], 403);
    assert_eq!(record["error_code"], "pdp.purpose_not_permitted");
    assert_eq!(
        record["pdp_policy_id"],
        "relay.entity.individual.purpose-required"
    );
    assert!(
        record["pdp_policy_hash"]
            .as_str()
            .is_some_and(|hash| hash.starts_with("sha256:") && hash.len() == 71),
        "audit record should include a stable sha256 PDP policy hash: {record}"
    );
    assert_eq!(
        record["pdp_evaluated_rule_ids"],
        json!([
            "entity-purpose-required:individual.policy_identity",
            "entity-purpose-required:individual.purpose"
        ])
    );
}

#[tokio::test]
async fn aggregate_scope_denial_happens_before_governed_pdp() {
    let config = AGGREGATE_CONFIG.replace(
        "          max_limit: 1000\naudit:",
        r#"          max_limit: 1000
          governed_policy:
            permitted_purposes:
              - capacity planning
            trusted_context: {}
audit:"#,
    );
    let (server, audit_sink) = server_with_aggregate_config_and_audit(
        config,
        &["social_registry:metadata", "social_registry:rows"],
    )
    .await;

    let response = server
        .get("/v1/datasets/social_registry/aggregates/by_municipality")
        .add_header("data-purpose", "casework")
        .await;

    response.assert_status_forbidden();
    assert_eq!(response.json::<Value>()["code"], "auth.scope_denied");

    let records = audit_sink.snapshot();
    assert_eq!(
        records.len(),
        1,
        "aggregate scope denial emits one audit record"
    );
    let record = audit_record_from_envelope(&records[0]);
    assert_eq!(record["status_code"], 403);
    assert_eq!(record["error_code"], "auth.scope_denied");
    assert!(
        record.get("pdp_policy_id").is_none_or(Value::is_null),
        "aggregate auth denial must not expose PDP policy provenance: {record}"
    );
    assert!(
        record
            .get("pdp_evaluated_rule_ids")
            .is_none_or(Value::is_null),
        "aggregate auth denial must not evaluate governed PDP rules: {record}"
    );
}

#[tokio::test]
async fn aggregate_source_read_scope_denial_happens_before_governed_pdp() {
    let config = AGGREGATE_CONFIG.replace(
        "          max_limit: 1000\naudit:",
        r#"          max_limit: 1000
          governed_policy:
            permitted_purposes:
              - capacity planning
            trusted_context: {}
audit:"#,
    );
    let (server, audit_sink) = server_with_aggregate_config_and_audit(
        config,
        &["social_registry:metadata", "social_registry:aggregate"],
    )
    .await;

    let response = server
        .get("/v1/datasets/social_registry/aggregates/by_municipality")
        .add_header("data-purpose", "capacity planning")
        .await;

    response.assert_status_forbidden();
    assert_eq!(response.json::<Value>()["code"], "auth.scope_denied");

    let records = audit_sink.snapshot();
    assert_eq!(
        records.len(),
        1,
        "source read scope denial emits one audit record"
    );
    let record = audit_record_from_envelope(&records[0]);
    assert_eq!(record["status_code"], 403);
    assert_eq!(record["error_code"], "auth.scope_denied");
    assert!(
        record.get("pdp_policy_id").is_none_or(Value::is_null),
        "source read auth denial must not expose PDP policy provenance: {record}"
    );
    assert!(
        record
            .get("pdp_evaluated_rule_ids")
            .is_none_or(Value::is_null),
        "source read auth denial must not evaluate governed PDP rules: {record}"
    );
}

#[tokio::test]
async fn aggregate_only_governed_execution_uses_aggregate_scope_for_pdp() {
    let config = AGGREGATE_CONFIG
        .replace(
            "      - id: by_municipality_masked\n",
            "      - id: by_municipality_masked\n        access:\n          aggregate_only_execution: true\n",
        )
        .replace(
            "          max_limit: 1000\naudit:",
            r#"          max_limit: 1000
          governed_policy:
            permitted_purposes:
              - capacity planning
            trusted_context: {}
audit:"#,
        );
    let server = server_with_aggregate_config(
        config,
        &["social_registry:metadata", "social_registry:aggregate"],
    )
    .await;

    let response = server
        .get("/v1/datasets/social_registry/aggregates/by_municipality_masked")
        .add_header("data-purpose", "capacity planning")
        .await;

    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["aggregate_id"], "by_municipality_masked");
}

#[tokio::test]
async fn aggregate_execution_applies_governed_redaction_to_observations_and_structure() {
    let config = AGGREGATE_CONFIG.replace(
        "          max_limit: 1000\naudit:",
        r#"          max_limit: 1000
          governed_policy:
            permitted_purposes:
              - capacity planning
            redaction_fields: [municipality_code]
            trusted_context: {}
audit:"#,
    );
    let server = server_with_aggregate_config(
        config,
        &[
            "social_registry:metadata",
            "social_registry:aggregate",
            "social_registry:rows",
        ],
    )
    .await;

    let response = server
        .get("/v1/datasets/social_registry/aggregates/by_municipality")
        .add_header("data-purpose", "capacity planning")
        .await;

    response.assert_status_ok();
    let body: Value = response.json();
    let observations = body["observations"].as_array().expect("observations");
    assert!(!observations.is_empty());
    assert!(
        observations
            .iter()
            .all(|row| row.get("municipality_code").is_none()),
        "redacted aggregate dimension must not be present in observations: {observations:?}"
    );
    assert_eq!(body["structure"]["dimensions"], json!([]));
    assert_eq!(observations[0]["individual_count"], 2);
}

#[tokio::test]
async fn aggregate_only_execution_requires_explicit_opt_in() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = tmp.path().join("aggregates_entity.yaml");
    let config = AGGREGATE_CONFIG.replace(
        "      - id: by_municipality_masked\n",
        "      - id: by_municipality_masked\n        access:\n          aggregate_only_execution: true\n",
    );
    std::fs::write(&config_path, config).expect("write config");
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
    let app = Router::new()
        .merge(aggregates_router::<()>())
        .merge(entity_router())
        .layer(Extension(query))
        .layer(Extension(Arc::new(EntityQueryEngine::new(
            Arc::clone(&ctx),
            Arc::clone(&registry),
        ))))
        .layer(Extension(registry))
        .layer(Extension(principal(&[
            "social_registry:metadata",
            "social_registry:aggregate",
        ])));
    let server = TestServer::new(app);

    let not_opted_in = server
        .get("/v1/datasets/social_registry/aggregates/by_municipality")
        .await;
    not_opted_in.assert_status_forbidden();

    let opted_in = server
        .get("/v1/datasets/social_registry/aggregates/by_municipality_masked")
        .await;
    opted_in.assert_status_ok();
    let body: Value = opted_in.json();
    assert_eq!(body["aggregate_id"], "by_municipality_masked");
    assert_eq!(body["disclosure_control"]["min_cell_size"], 2);

    let rows = server
        .get("/v1/datasets/social_registry/entities/individual/records")
        .await;
    rows.assert_status_forbidden();
}

fn aggregate_only_config_with_sensitivity(sensitivity: &str) -> String {
    AGGREGATE_CONFIG
        .replace("    sensitivity: personal\n", &format!("    sensitivity: {sensitivity}\n"))
        .replace(
            "      - id: by_municipality\n",
            "      - id: by_municipality\n        access:\n          aggregate_only_execution: true\n",
        )
}

#[tokio::test]
async fn aggregate_only_execution_on_confidential_dataset_requires_min_cell_size_two() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = tmp.path().join("aggregates_entity.yaml");
    std::fs::write(
        &config_path,
        aggregate_only_config_with_sensitivity("confidential"),
    )
    .expect("write config");

    let err = config::load(&config_path)
        .expect_err("confidential aggregate-only dataset with min_cell_size 1 must be rejected");
    assert_eq!(err.code(), "config.validation_error");
}

#[tokio::test]
async fn aggregate_only_execution_on_secret_dataset_requires_min_cell_size_two() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = tmp.path().join("aggregates_entity.yaml");
    std::fs::write(
        &config_path,
        aggregate_only_config_with_sensitivity("secret"),
    )
    .expect("write config");

    let err = config::load(&config_path)
        .expect_err("secret aggregate-only dataset with min_cell_size 1 must be rejected");
    assert_eq!(err.code(), "config.validation_error");
}

#[tokio::test]
async fn aggregate_required_filters_require_principal_bindings_in_config() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = tmp.path().join("aggregates_entity.yaml");
    let config = AGGREGATE_CONFIG.replace(
        r#"        required_filter_bindings:
          - field: municipality_code
            source: principal_id
"#,
        "",
    );
    std::fs::write(&config_path, config).expect("write config");

    let err = config::load(&config_path)
        .expect_err("aggregate required_filters without bindings must be rejected");
    assert_eq!(err.code(), "config.validation_error");
}

#[tokio::test]
async fn caller_filters_do_not_satisfy_aggregate_required_filters() {
    let query = aggregate_query_engine(AGGREGATE_CONFIG.to_string()).await;

    let err = query
        .execute_aggregate(
            "social_registry",
            "by_required_municipality",
            AggregateQueryRequest {
                filters: vec![AggregateFilter {
                    field: "municipality_code".to_string(),
                    op: AggregateFilterOp::Eq,
                    value: json!("mun-1"),
                }],
                ..AggregateQueryRequest::default()
            },
        )
        .await
        .expect_err("caller filter alone must not satisfy required aggregate filters");
    assert_eq!(err.code(), "aggregate.filter_required");

    let result = query
        .execute_aggregate(
            "social_registry",
            "by_required_municipality",
            AggregateQueryRequest {
                principal_bound_filters: vec![AggregateFilter {
                    field: "municipality_code".to_string(),
                    op: AggregateFilterOp::Eq,
                    value: json!("mun-1"),
                }],
                ..AggregateQueryRequest::default()
            },
        )
        .await
        .expect("principal-bound filter satisfies required aggregate filters");
    assert_eq!(
        result.data,
        vec![json!({
            "municipality_code": "mun-1",
            "individual_count": 2
        })]
    );
}

#[tokio::test]
async fn aggregate_route_binds_required_filters_to_principal_identity() {
    let server = server_with_aggregates_and_principal_id("mun-1").await;

    let scoped = server
        .get("/v1/datasets/social_registry/aggregates/by_required_municipality")
        .await;
    scoped.assert_status_ok();
    let body: Value = scoped.json();
    assert_eq!(
        sorted_rows(&body),
        vec![json!({
            "municipality_code": "mun-1",
            "individual_count": 2
        })]
    );

    let narrowed_away = server
        .post("/v1/datasets/social_registry/aggregates/by_required_municipality/query")
        .json(&json!({
            "filters": { "municipality_code": "mun-2" }
        }))
        .await;
    narrowed_away.assert_status_ok();
    let body: Value = narrowed_away.json();
    assert!(sorted_rows(&body).is_empty());
}

#[tokio::test]
async fn csv_response_carries_metadata_headers_and_status_columns() {
    let resp = server_with_aggregates()
        .await
        .get("/v1/datasets/social_registry/aggregates/by_municipality_masked?f=csv")
        .await;

    resp.assert_status_ok();
    assert!(resp
        .header("content-type")
        .to_str()
        .expect("content-type")
        .starts_with("text/csv"));
    assert!(resp
        .header("x-registry-relay-disclosure-control")
        .to_str()
        .expect("registry disclosure header")
        .contains("min_cell_size"));
    assert!(resp
        .header("x-spdci-disclosure-control")
        .to_str()
        .expect("spdci disclosure header")
        .contains("min_cell_size"));
    assert!(resp
        .header("x-spdci-freshness")
        .to_str()
        .expect("freshness header")
        .contains("computed_at"));
    assert!(resp
        .header("link")
        .to_str()
        .expect("link header")
        .contains("</v1/datasets/social_registry/aggregates/by_municipality_masked/structure>; rel=\"describedby\""));

    let body = resp.text();
    assert_eq!(
        body.lines().next(),
        Some("municipality_code,individual_count,individual_count$status")
    );
    assert!(body.contains("mun-1,2,"));
    assert!(body.contains("mun-2,,S"));
}

#[tokio::test]
async fn aggregate_csv_escapes_formula_leading_string_cells() {
    let resp = server_with_formula_cells()
        .await
        .get("/v1/datasets/social_registry/aggregates/by_municipality?f=csv")
        .await;

    resp.assert_status_ok();
    let body = resp.text();
    let mut reader = csv::Reader::from_reader(body.as_bytes());
    let mut municipality_codes = reader
        .records()
        .map(|record| {
            record
                .expect("csv record")
                .get(0)
                .expect("municipality column")
                .to_string()
        })
        .collect::<Vec<_>>();
    municipality_codes.sort();

    assert_eq!(
        municipality_codes,
        vec![
            "'\tcmd".to_string(),
            "'\rcmd".to_string(),
            "'+cmd".to_string(),
            "'-cmd".to_string(),
            "'=cmd".to_string(),
            "'@cmd".to_string(),
        ]
    );
}

#[tokio::test]
async fn executes_single_entity_count_aggregate() {
    let resp = server_with_aggregates()
        .await
        .get("/v1/datasets/social_registry/aggregates/by_municipality")
        .await;

    resp.assert_status_ok();
    let body: Value = resp.json();
    assert!(body.get("data").is_none());
    assert!(body.get("schema").is_none());
    assert_eq!(
        body["structure"]["dimensions"][0]["id"],
        "municipality_code"
    );
    assert_eq!(body["structure"]["measures"][0]["id"], "individual_count");
    assert!(body["structure"].get("indicators").is_none());
    assert_eq!(body["disclosure_control"]["suppressed_observations"], 0);
    assert!(
        body["disclosure_control"].get("suppressed_rows").is_none(),
        "legacy suppressed_rows alias must be dropped from the native response"
    );
    let links = body["links"].as_array().expect("links array");
    let alternate = links
        .iter()
        .find(|link| link["rel"] == "alternate")
        .expect("native response advertises the SDMX representation");
    assert_eq!(
        alternate["href"],
        "/v1/datasets/social_registry/aggregates/by_municipality?f=sdmx-json"
    );
    assert_eq!(
        alternate["type"],
        "application/vnd.sdmx.data+json;version=2.1"
    );
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
async fn aggregate_detail_route_is_not_captured_by_entity_relationship() {
    let resp = protected_router_with_aggregates()
        .await
        .get("/v1/datasets/social_registry/aggregates/by_municipality")
        .await;

    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["aggregate_id"], "by_municipality");
    assert_eq!(body["disclosure_control"]["suppressed_observations"], 0);
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
        .post("/v1/datasets/social_registry/aggregates/by_municipality/query")
        .json(&json!({
            "measures": ["individual_count"],
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
async fn aggregate_sdmx_applies_temporal_filter_when_configured() {
    let resp = server_with_aggregates()
        .await
        .post("/v1/datasets/social_registry/aggregates/by_municipality/query?f=sdmx-json")
        .json(&json!({
            "measures": ["individual_count"],
            "group_by": ["municipality_code"],
            "temporal": {
                "from": "2024-01-01",
                "to": "2024-12-31"
            }
        }))
        .await;

    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_valid_sdmx_data_message(&body);
    let observations = body["data"]["dataSets"][0]["observations"]
        .as_object()
        .expect("observations");
    assert_eq!(observations.len(), 1);
    assert_eq!(observations["0"], json!([2]));
}

#[tokio::test]
async fn aggregate_supports_sdmx_json_query_format() {
    let resp = server_with_aggregates()
        .await
        .get("/v1/datasets/social_registry/aggregates/by_municipality?f=sdmx-json")
        .await;

    resp.assert_status_ok();
    assert!(resp
        .header("content-type")
        .to_str()
        .expect("content-type")
        .starts_with("application/vnd.sdmx.data+json;version=2.1"));
    assert_eq!(resp.header("vary"), "Accept");
    let body: Value = resp.json();
    assert_valid_sdmx_data_message(&body);
    assert_eq!(
        body["meta"]["schema"],
        "https://json.sdmx.org/2.1/sdmx-json-data-schema.json"
    );
    assert_eq!(body["meta"]["id"], "social_registry$by_municipality");
    assert_eq!(
        body["data"]["structures"][0]["dimensions"]["observation"][0]["id"],
        "municipality_code"
    );
    assert_eq!(
        body["data"]["structures"][0]["measures"]["observation"][0]["id"],
        "individual_count"
    );
    assert_eq!(
        body["data"]["dataSets"][0]["observations"]["0"],
        json!([2, 10.0, 20.0])
    );
    assert_eq!(
        body["data"]["dataSets"][0]["observations"]["1"],
        json!([1, 30.0, 30.0])
    );
}

#[tokio::test]
async fn aggregate_sdmx_marks_truncated_results() {
    let resp = server_with_aggregates()
        .await
        .post("/v1/datasets/social_registry/aggregates/by_municipality/query?f=sdmx-json")
        .json(&json!({
            "measures": ["individual_count"],
            "group_by": ["municipality_code"],
            "max_rows": 1
        }))
        .await;

    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_valid_sdmx_data_message(&body);
    assert_eq!(body["meta"]["x-completeness"]["complete"], false);
    assert_eq!(body["meta"]["x-completeness"]["truncated"], true);
    assert_eq!(
        body["data"]["dataSets"][0]["observations"]
            .as_object()
            .expect("observations")
            .len(),
        1
    );
}

#[tokio::test]
async fn aggregate_supports_sdmx_json_accept_negotiation_for_post_query() {
    let resp = server_with_aggregates()
        .await
        .post("/v1/datasets/social_registry/aggregates/by_municipality/query")
        .add_header("accept", "application/vnd.sdmx.data+json;version=2.1")
        .json(&json!({
            "measures": ["individual_count"],
            "group_by": ["municipality_code"]
        }))
        .await;

    resp.assert_status_ok();
    assert!(resp
        .header("content-type")
        .to_str()
        .expect("content-type")
        .starts_with("application/vnd.sdmx.data+json;version=2.1"));
    let body: Value = resp.json();
    assert_valid_sdmx_data_message(&body);
    assert_eq!(
        body["data"]["structures"][0]["measures"]["observation"]
            .as_array()
            .expect("measures")
            .len(),
        1
    );
    assert_eq!(body["data"]["dataSets"][0]["observations"]["0"], json!([2]));
}

#[tokio::test]
async fn aggregate_supports_sdmx_json_query_parameter_for_post_query() {
    let resp = server_with_aggregates()
        .await
        .post("/v1/datasets/social_registry/aggregates/by_municipality/query?f=sdmx-json")
        .json(&json!({
            "measures": ["individual_count"],
            "group_by": ["municipality_code"]
        }))
        .await;

    resp.assert_status_ok();
    assert!(resp
        .header("content-type")
        .to_str()
        .expect("content-type")
        .starts_with("application/vnd.sdmx.data+json;version=2.1"));
    let body: Value = resp.json();
    assert_valid_sdmx_data_message(&body);
    assert_eq!(body["data"]["dataSets"][0]["observations"]["0"], json!([2]));
}

#[tokio::test]
async fn aggregate_sdmx_dimension_value_ids_do_not_collapse_observations() {
    let resp = server_with_municipalities(&["a b", "a_x20_b"])
        .await
        .get("/v1/datasets/social_registry/aggregates/by_municipality?f=sdmx-json")
        .await;

    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_valid_sdmx_data_message(&body);
    let observations = body["data"]["dataSets"][0]["observations"]
        .as_object()
        .expect("observations");
    assert_eq!(
        observations.len(),
        2,
        "distinct dimension values must not collide into one SDMX observation key"
    );
    let dimension_values = body["data"]["structures"][0]["dimensions"]["observation"][0]["values"]
        .as_array()
        .expect("dimension values");
    assert_eq!(dimension_values.len(), 2);
    assert_ne!(dimension_values[0]["id"], dimension_values[1]["id"]);
}

#[tokio::test]
async fn aggregate_sdmx_carries_suppression_status_as_observation_attribute() {
    let resp = server_with_aggregates()
        .await
        .get("/v1/datasets/social_registry/aggregates/by_municipality_masked?f=sdmx-json")
        .await;

    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_valid_sdmx_data_message(&body);
    assert_eq!(
        body["data"]["structures"][0]["attributes"]["observation"][0]["id"],
        "OBS_STATUS"
    );
    assert_eq!(
        body["data"]["dataSets"][0]["observations"]["0"],
        json!([2, null])
    );
    assert_eq!(
        body["data"]["dataSets"][0]["observations"]["1"],
        json!([null, "S"])
    );
}

#[tokio::test]
async fn aggregate_accept_negotiation_ignores_sdmx_json_with_zero_quality() {
    let resp = server_with_aggregates()
        .await
        .post("/v1/datasets/social_registry/aggregates/by_municipality/query")
        .add_header(
            "accept",
            "application/vnd.sdmx.data+json;q=0, application/json;q=1",
        )
        .json(&json!({
            "measures": ["individual_count"],
            "group_by": ["municipality_code"]
        }))
        .await;

    resp.assert_status_ok();
    assert!(resp
        .header("content-type")
        .to_str()
        .expect("content-type")
        .starts_with("application/json"));
    let body: Value = resp.json();
    assert!(body.get("observations").is_some());
    assert!(body.get("structure").is_some());
}

#[tokio::test]
async fn aggregate_accept_negotiates_csv() {
    let resp = server_with_aggregates()
        .await
        .post("/v1/datasets/social_registry/aggregates/by_municipality/query")
        .add_header("accept", "text/csv")
        .json(&json!({
            "measures": ["individual_count"],
            "group_by": ["municipality_code"]
        }))
        .await;

    resp.assert_status_ok();
    assert!(resp
        .header("content-type")
        .to_str()
        .expect("content-type")
        .starts_with("text/csv"));
    assert_eq!(resp.header("vary"), "Accept");
}

#[tokio::test]
async fn aggregate_rejects_unsupported_accept_format() {
    let resp = server_with_aggregates()
        .await
        .post("/v1/datasets/social_registry/aggregates/by_municipality/query")
        .add_header("accept", "application/vnd.sdmx.data+json;version=2.0")
        .json(&json!({
            "measures": ["individual_count"],
            "group_by": ["municipality_code"]
        }))
        .await;

    resp.assert_status_bad_request();
    let body: Value = resp.json();
    assert_eq!(body["code"], "aggregate.format_unsupported");
}

#[tokio::test]
async fn aggregate_query_format_overrides_accept_header() {
    let resp = server_with_aggregates()
        .await
        .get("/v1/datasets/social_registry/aggregates/by_municipality?f=json")
        .add_header("accept", "application/vnd.sdmx.data+json")
        .await;

    resp.assert_status_ok();
    assert!(resp
        .header("content-type")
        .to_str()
        .expect("content-type")
        .starts_with("application/json"));
    let body: Value = resp.json();
    assert!(body.get("observations").is_some());
    assert!(body.get("structure").is_some());
    assert!(body.get("data").is_none());
}

#[tokio::test]
async fn aggregate_query_parameter_overrides_post_body_format() {
    let resp = server_with_aggregates()
        .await
        .post("/v1/datasets/social_registry/aggregates/by_municipality/query?f=sdmx-json")
        .json(&json!({
            "format": "json",
            "measures": ["individual_count"],
            "group_by": ["municipality_code"]
        }))
        .await;

    resp.assert_status_ok();
    assert!(resp
        .header("content-type")
        .to_str()
        .expect("content-type")
        .starts_with("application/vnd.sdmx.data+json;version=2.1"));
    let body: Value = resp.json();
    assert_valid_sdmx_data_message(&body);
    assert!(body.get("data").is_some());
}

#[tokio::test]
async fn aggregate_rejects_unknown_response_format() {
    let resp = server_with_aggregates()
        .await
        .get("/v1/datasets/social_registry/aggregates/by_municipality?f=xml")
        .await;

    resp.assert_status_bad_request();
    let body: Value = resp.json();
    assert_eq!(body["code"], "aggregate.format_unsupported");
}

#[tokio::test]
async fn masks_measures_below_min_group_size_without_removing_group_keys() {
    let resp = server_with_aggregates()
        .await
        .get("/v1/datasets/social_registry/aggregates/by_municipality_masked")
        .await;

    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["disclosure_control"]["min_cell_size"], 2);
    assert_eq!(body["disclosure_control"]["suppressed_observations"], 1);
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
        .get("/v1/datasets/social_registry/aggregates/by_household_region")
        .await;

    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["disclosure_control"]["min_cell_size"], 2);
    assert_eq!(body["disclosure_control"]["suppressed_observations"], 1);
    assert_eq!(
        sorted_rows(&body),
        vec![json!({"household_region": "north", "individual_count": 2})]
    );
}

fn sorted_rows(body: &Value) -> Vec<Value> {
    let mut rows = body["observations"]
        .as_array()
        .expect("observations array")
        .clone();
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

fn assert_valid_sdmx_data_message(body: &Value) {
    let schema: Value =
        serde_json::from_str(SDMX_JSON_DATA_SCHEMA_2_1).expect("SDMX schema parses");
    let compiled = jsonschema::JSONSchema::compile(&schema).expect("SDMX contract schema compiles");
    if let Err(errors) = compiled.validate(body) {
        let messages = errors.map(|error| error.to_string()).collect::<Vec<_>>();
        panic!(
            "SDMX data message must match official SDMX-JSON 2.1 schema: {messages:?}\nbody: {body}"
        );
    };
}
