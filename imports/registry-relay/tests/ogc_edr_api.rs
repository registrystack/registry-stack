// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "ogcapi-edr")]

use std::sync::Arc;

use axum::http::StatusCode;
use axum::Extension;
use axum_test::TestServer;
use datafusion::arrow::array::StringArray;
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::datasource::MemTable;
use datafusion::execution::context::SessionContext;
use registry_relay::api::edr_router;
use registry_relay::auth::{AuthMode, Principal, ScopeSet};
use registry_relay::config::{self, DatasetId, ResourceId};
use registry_relay::entity::EntityRegistry;
use registry_relay::ingest::table_name;
use registry_relay::query::{AggregateQueryEngine, EntityQueryEngine};
use serde_json::{json, Value};
use tempfile::TempDir;

fn principal(scopes: &[&str]) -> Principal {
    Principal {
        principal_id: "test-principal".to_string(),
        scopes: scopes.iter().copied().collect::<ScopeSet>(),
        auth_mode: AuthMode::ApiKey,
    }
}

fn id<T: serde::de::DeserializeOwned>(value: &str) -> T {
    serde_json::from_str(&format!(r#""{value}""#)).expect("id deserializes")
}

fn server(scopes: &[&str]) -> TestServer {
    server_with_options(scopes, false, true, 100)
}

fn server_with_options(
    scopes: &[&str],
    require_purpose_header: bool,
    include_spatial_filter: bool,
    max_geometry_vertices: u32,
) -> TestServer {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = tmp.path().join("ogc_edr.yaml");
    std::fs::write(
        &config_path,
        edr_config_yaml(
            require_purpose_header,
            include_spatial_filter,
            max_geometry_vertices,
        ),
    )
    .expect("write config");
    let cfg = Arc::new(
        config::load(&config_path)
            .unwrap_or_else(|err| panic!("config loads for {}: {err:?}", config_path.display())),
    );
    std::mem::forget(tmp);

    let registry = Arc::new(EntityRegistry::from_config(&cfg).expect("registry"));
    let ctx = Arc::new(SessionContext::new());
    register_individuals(&ctx);
    register_municipalities(&ctx);

    let entity_query = Arc::new(EntityQueryEngine::new(
        Arc::clone(&ctx),
        Arc::clone(&registry),
    ));
    let aggregate_query = Arc::new(AggregateQueryEngine::new(
        Arc::clone(&ctx),
        Arc::clone(&registry),
        Arc::clone(&cfg),
    ));

    TestServer::new(
        edr_router::<()>()
            .layer(Extension(entity_query))
            .layer(Extension(aggregate_query))
            .layer(Extension(registry))
            .layer(Extension(cfg))
            .layer(Extension(principal(scopes))),
    )
}

fn edr_config_yaml(
    require_purpose_header: bool,
    include_spatial_filter: bool,
    max_geometry_vertices: u32,
) -> String {
    let spatial_filter = if include_spatial_filter {
        r#"          - field: municipality
            ops: [eq, in]"#
    } else {
        "          []"
    };
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

audit:
  sink: stdout
  format: jsonl

datasets:
  - id: social_registry
    title: Social Registry
    description: Synthetic social registry
    owner: Test
    sensitivity: personal
    access_rights: restricted
    update_frequency: monthly
    defaults:
      refresh:
        mode: manual
    tables:
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
            - name: municipality_code
              type: string
              nullable: false
      - id: municipalities_table
        source:
          type: file
          path: fixtures/municipalities.csv
        primary_key: code
        schema:
          strict: true
          fields:
            - name: code
              type: string
              nullable: false
            - name: geometry
              type: string
              nullable: false
    aggregates:
      - id: beneficiaries_by_municipality
        title: Beneficiaries by municipality
        description: Beneficiary count by municipality
        source_entity: individual
        default_group_by:
          - municipality
        dimensions:
          - id: municipality
            label: Municipality
            field: municipality
        indicators:
          - id: individual_count
            label: Individuals
            function: count
            column: id
            unit_measure: people
        allowed_filters:
__SPATIAL_FILTER__
        disclosure_control:
          min_group_size: 1
          suppression: "null"
        spatial:
          mode: admin_area
          dimension: municipality
          geometry_entity: municipality
          geometry_id_field: code
          geometry_field: geometry
          max_geometry_vertices: __MAX_GEOMETRY_VERTICES__
    entities:
      - name: individual
        table: individuals_table
        fields:
          - name: id
            from: individual_id
          - name: municipality
            from: municipality_code
        access:
          metadata_scope: social_registry:metadata
          aggregate_scope: social_registry:aggregate
          read_scope: social_registry:rows
        api:
          default_limit: 100
          max_limit: 10000
          require_purpose_header: __REQUIRE_PURPOSE_HEADER__
      - name: municipality
        table: municipalities_table
        fields:
          - name: code
          - name: geometry
        access:
          metadata_scope: social_registry:metadata
          aggregate_scope: social_registry:aggregate
          read_scope: social_registry:rows
        api:
          default_limit: 100
          max_limit: 10000
"#
    .replace("__SPATIAL_FILTER__", spatial_filter)
    .replace(
        "__MAX_GEOMETRY_VERTICES__",
        &max_geometry_vertices.to_string(),
    )
    .replace(
        "__REQUIRE_PURPOSE_HEADER__",
        if require_purpose_header {
            "true"
        } else {
            "false"
        },
    )
}

fn register_individuals(ctx: &SessionContext) {
    let schema = Arc::new(Schema::new(vec![
        Field::new("individual_id", DataType::Utf8, false),
        Field::new("municipality_code", DataType::Utf8, false),
    ]));
    let batch = RecordBatch::try_new(
        Arc::clone(&schema),
        vec![
            Arc::new(StringArray::from(vec!["ind-1", "ind-2", "ind-3"])),
            Arc::new(StringArray::from(vec!["mun-1", "mun-1", "mun-2"])),
        ],
    )
    .expect("individual batch");
    let table = MemTable::try_new(schema, vec![vec![batch]]).expect("individual table");
    let dataset: DatasetId = id("social_registry");
    let resource: ResourceId = id("individuals_table");
    ctx.register_table(table_name(&dataset, &resource), Arc::new(table))
        .expect("register individuals");
}

fn register_municipalities(ctx: &SessionContext) {
    let schema = Arc::new(Schema::new(vec![
        Field::new("code", DataType::Utf8, false),
        Field::new("geometry", DataType::Utf8, false),
    ]));
    let batch = RecordBatch::try_new(
        Arc::clone(&schema),
        vec![
            Arc::new(StringArray::from(vec!["mun-1", "mun-2"])),
            Arc::new(StringArray::from(vec![
                r#"{"type":"Polygon","coordinates":[[[0,0],[1,0],[1,1],[0,1],[0,0]]]}"#,
                r#"{"type":"Polygon","coordinates":[[[2,0],[3,0],[3,1],[2,1],[2,0]]]}"#,
            ])),
        ],
    )
    .expect("municipality batch");
    let table = MemTable::try_new(schema, vec![vec![batch]]).expect("municipality table");
    let dataset: DatasetId = id("social_registry");
    let resource: ResourceId = id("municipalities_table");
    ctx.register_table(table_name(&dataset, &resource), Arc::new(table))
        .expect("register municipalities");
}

#[tokio::test]
async fn landing_conformance_and_collections_are_metadata_scoped() {
    let server = server(&["social_registry:metadata"]);

    let landing = server.get("/ogc/edr/v1").await;
    landing.assert_status_ok();
    let body: Value = landing.json();
    assert_eq!(body["title"], "Registry Relay OGC EDR API");

    let conformance = server.get("/ogc/edr/v1/conformance").await;
    conformance.assert_status_ok();
    let body: Value = conformance.json();
    let conforms_to = body["conformsTo"].as_array().expect("conformsTo");
    assert!(conforms_to.iter().any(|value| value
        .as_str()
        .is_some_and(|uri| uri.ends_with("/conf/area"))));
    assert!(!conforms_to.iter().any(|value| value
        .as_str()
        .is_some_and(|uri| uri.ends_with("/conf/position") || uri.ends_with("/conf/radius"))));

    let collections = server.get("/ogc/edr/v1/collections").await;
    collections.assert_status_ok();
    let body: Value = collections.json();
    assert_eq!(
        body["collections"][0]["id"],
        "social_registry_beneficiaries_by_municipality"
    );
}

#[tokio::test]
async fn area_get_wkt_returns_grouped_admin_features() {
    let server = server(&[
        "social_registry:metadata",
        "social_registry:aggregate",
        "social_registry:rows",
    ]);

    let resp = server
        .get("/ogc/edr/v1/collections/social_registry_beneficiaries_by_municipality/area")
        .add_query_param(
            "coords",
            "POLYGON ((-0.5 -0.5, 1.5 -0.5, 1.5 1.5, -0.5 1.5, -0.5 -0.5))",
        )
        .add_query_param("parameter-name", "individual_count")
        .add_query_param("group_by", "municipality")
        .add_query_param("f", "geojson")
        .await;

    if !resp.status_code().is_success() {
        panic!("unexpected area GET response: {}", resp.text());
    }
    assert_eq!(
        resp.header("content-type").to_str().unwrap_or(""),
        "application/geo+json"
    );
    let body: Value = resp.json();
    assert_eq!(body["type"], "FeatureCollection");
    assert_eq!(body["dataset_id"], "social_registry");
    assert_eq!(body["aggregate_id"], "beneficiaries_by_municipality");
    assert!(body.get("crs").is_none());
    let features = body["features"].as_array().expect("features");
    assert_eq!(features.len(), 1);
    assert_eq!(features[0]["properties"]["municipality"], "mun-1");
    assert_eq!(features[0]["properties"]["individual_count"], 2);
    assert_eq!(features[0]["properties"]["_min_cell_size"], 1);
    assert_eq!(features[0]["geometry"]["type"], "Polygon");
}

#[tokio::test]
async fn area_post_geojson_returns_single_submitted_geometry_feature() {
    let server = server(&[
        "social_registry:metadata",
        "social_registry:aggregate",
        "social_registry:rows",
    ]);

    let resp = server
        .post("/ogc/edr/v1/collections/social_registry_beneficiaries_by_municipality/area")
        .json(&json!({
            "type": "Feature",
            "properties": {
                "indicators": ["individual_count"],
                "filters": { "municipality": "mun-2" }
            },
            "geometry": {
            "type": "Polygon",
            "coordinates": [[[-0.5, -0.5], [3.5, -0.5], [3.5, 1.5], [-0.5, 1.5], [-0.5, -0.5]]]
            }
        }))
        .await;

    if !resp.status_code().is_success() {
        panic!("unexpected area POST response: {}", resp.text());
    }
    let body: Value = resp.json();
    assert!(body.get("crs").is_none());
    let features = body["features"].as_array().expect("features");
    assert_eq!(features.len(), 1);
    assert_eq!(features[0]["geometry"]["type"], "Polygon");
    assert_eq!(features[0]["properties"]["individual_count"], 1);
    assert_eq!(features[0]["properties"]["_suppressed"], false);
}

#[tokio::test]
async fn area_enforces_source_entity_purpose_header() {
    let server = server_with_options(
        &[
            "social_registry:metadata",
            "social_registry:aggregate",
            "social_registry:rows",
        ],
        true,
        true,
        100,
    );

    let missing = server
        .get("/ogc/edr/v1/collections/social_registry_beneficiaries_by_municipality/area")
        .add_query_param("coords", "POLYGON ((0 0, 1 0, 1 1, 0 1, 0 0))")
        .await;
    missing.assert_status_bad_request();
    assert_eq!(missing.json::<Value>()["code"], "auth.purpose_required");

    let blank = server
        .get("/ogc/edr/v1/collections/social_registry_beneficiaries_by_municipality/area")
        .add_query_param("coords", "POLYGON ((0 0, 1 0, 1 1, 0 1, 0 0))")
        .add_header("data-purpose", "   ")
        .await;
    blank.assert_status_bad_request();
    assert_eq!(blank.json::<Value>()["code"], "auth.purpose_required");

    let ok = server
        .get("/ogc/edr/v1/collections/social_registry_beneficiaries_by_municipality/area")
        .add_query_param("coords", "POLYGON ((0 0, 1 0, 1 1, 0 1, 0 0))")
        .add_header("data-purpose", "capacity planning")
        .await;
    ok.assert_status_ok();
}

#[tokio::test]
async fn area_rejects_oversized_request_geometry() {
    let server = server_with_options(
        &[
            "social_registry:metadata",
            "social_registry:aggregate",
            "social_registry:rows",
        ],
        false,
        true,
        5,
    );

    let resp = server
        .post("/ogc/edr/v1/collections/social_registry_beneficiaries_by_municipality/area")
        .json(&json!({
            "type": "Polygon",
            "coordinates": [[
                [0.0, 0.0],
                [1.0, 0.0],
                [1.0, 1.0],
                [0.5, 1.5],
                [0.0, 1.0],
                [0.0, 0.0]
            ]]
        }))
        .await;

    resp.assert_status(StatusCode::PAYLOAD_TOO_LARGE);
    assert_eq!(resp.json::<Value>()["code"], "spatial.geometry_too_large");
}

#[tokio::test]
async fn area_no_matching_admin_geometry_returns_empty_feature_collection() {
    let server = server(&[
        "social_registry:metadata",
        "social_registry:aggregate",
        "social_registry:rows",
    ]);

    let resp = server
        .get("/ogc/edr/v1/collections/social_registry_beneficiaries_by_municipality/area")
        .add_query_param("coords", "POLYGON ((10 10, 11 10, 11 11, 10 11, 10 10))")
        .add_query_param("parameter-name", "individual_count")
        .add_query_param("group_by", "municipality")
        .await;

    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["type"], "FeatureCollection");
    assert!(body["features"].as_array().expect("features").is_empty());
}

#[test]
fn spatial_aggregate_requires_in_filter_on_area_dimension() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = tmp.path().join("ogc_edr_invalid.yaml");
    std::fs::write(&config_path, edr_config_yaml(false, false, 100)).expect("write config");

    config::load(&config_path).expect_err("spatial aggregate without in filter is rejected");
}

#[tokio::test]
async fn area_requires_aggregate_scope() {
    let server = server(&["social_registry:metadata"]);

    let resp = server
        .get("/ogc/edr/v1/collections/social_registry_beneficiaries_by_municipality/area")
        .add_query_param("coords", "POLYGON ((0 0, 1 0, 1 1, 0 1, 0 0))")
        .await;

    resp.assert_status_forbidden();
    let body: Value = resp.json();
    assert_eq!(body["code"], "auth.scope_denied");
}

#[tokio::test]
async fn area_requires_source_entity_read_scope() {
    let server = server(&["social_registry:metadata", "social_registry:aggregate"]);

    let resp = server
        .get("/ogc/edr/v1/collections/social_registry_beneficiaries_by_municipality/area")
        .add_query_param("coords", "POLYGON ((0 0, 1 0, 1 1, 0 1, 0 0))")
        .await;

    resp.assert_status_forbidden();
    let body: Value = resp.json();
    assert_eq!(body["code"], "auth.scope_denied");
}
