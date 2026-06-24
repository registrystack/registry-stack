// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "ogcapi-features")]

use std::sync::Arc;

use axum::Extension;
use axum_test::TestServer;
use datafusion::arrow::array::{Float64Array, StringArray};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::datasource::MemTable;
use datafusion::execution::context::SessionContext;
use registry_relay::api::{ogc_router, CursorSigner};
use registry_relay::auth::{AuthMode, Principal, ScopeSet};
use registry_relay::config::{self, DatasetId, ResourceId, CRS84};
use registry_relay::entity::EntityRegistry;
use registry_relay::ingest::table_name;
use registry_relay::query::EntityQueryEngine;
use serde_json::Value;
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

fn write_config_with_entity_api_extra(
    tmp: &TempDir,
    require_purpose_header: bool,
    entity_api_extra: &str,
) -> std::path::PathBuf {
    let path = tmp.path().join("ogc_api.yaml");
    std::fs::write(
        &path,
        format!(
            r#"
server:
  bind: 127.0.0.1:0

catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test

vocabularies: {{}}

auth:
  mode: api_key
  api_keys: []

datasets:
  - id: civic_registry
    title: Civic Registry
    description: Synthetic civic registry
    owner: Test
    sensitivity: personal
    access_rights: restricted
    update_frequency: monthly
    defaults:
      refresh:
        mode: manual
    tables:
      - id: facilities_table
        source:
          type: file
          path: fixtures/civic.csv
        primary_key: facility_id
        schema:
          strict: true
          fields:
            - name: facility_id
              type: string
              nullable: false
            - name: lon
              type: number
              nullable: true
            - name: lat
              type: number
              nullable: true
            - name: name
              type: string
              nullable: true
            - name: facility_type
              type: string
              nullable: true
    entities:
      - name: facility
        table: facilities_table
        fields:
          - name: id
            from: facility_id
          - name: lon
          - name: lat
          - name: name
          - name: facility_type
        access:
          metadata_scope: civic_registry:metadata
          aggregate_scope: civic_registry:aggregate
          read_scope: civic_registry:rows
        api:
          default_limit: 100
          max_limit: 1000
          require_purpose_header: {require_purpose_header}
{entity_api_extra}
          required_filters: [facility_type]
          allowed_filters:
            - field: facility_type
              ops: [eq]
        spatial:
          collection_id: facilities
          title: Public facilities
          geometry:
            kind: point
            longitude_field: lon
            latitude_field: lat
            crs: {CRS84}
          max_bbox_degrees: 5.0
          max_geometry_vertices: 10000

audit:
  sink: stdout
  format: jsonl
"#
        ),
    )
    .expect("write config");
    path
}

async fn server_with_purpose(scopes: &[&str], require_purpose_header: bool) -> TestServer {
    server_with_purpose_and_entity_api_extra(scopes, require_purpose_header, "").await
}

async fn server_with_purpose_and_entity_api_extra(
    scopes: &[&str],
    require_purpose_header: bool,
    entity_api_extra: &str,
) -> TestServer {
    let tmp = TempDir::new().expect("tempdir");
    let cfg = Arc::new(
        config::load(&write_config_with_entity_api_extra(
            &tmp,
            require_purpose_header,
            entity_api_extra,
        ))
        .expect("config loads"),
    );
    let registry = Arc::new(EntityRegistry::from_config(&cfg).expect("registry compiles"));
    let ctx = Arc::new(SessionContext::new());

    let schema = Arc::new(Schema::new(vec![
        Field::new("facility_id", DataType::Utf8, false),
        Field::new("lon", DataType::Float64, true),
        Field::new("lat", DataType::Float64, true),
        Field::new("name", DataType::Utf8, true),
        Field::new("facility_type", DataType::Utf8, true),
    ]));
    let batch = RecordBatch::try_new(
        Arc::clone(&schema),
        vec![
            Arc::new(StringArray::from(vec![
                "FAC-001", "FAC-002", "FAC-003", "FAC/004",
            ])),
            Arc::new(Float64Array::from(vec![
                Some(100.61),
                Some(100.72),
                None,
                Some(101.50),
            ])),
            Arc::new(Float64Array::from(vec![
                Some(13.76),
                Some(13.80),
                None,
                Some(13.75),
            ])),
            Arc::new(StringArray::from(vec![
                Some("Bang Rak Health Center"),
                Some("District School"),
                Some("Mobile Clinic"),
                Some("Encoded Facility"),
            ])),
            Arc::new(StringArray::from(vec![
                Some("clinic"),
                Some("school"),
                Some("clinic"),
                Some("clinic & urgent"),
            ])),
        ],
    )
    .expect("record batch");
    let table = MemTable::try_new(schema, vec![vec![batch]]).expect("mem table");
    let dataset: DatasetId = id("civic_registry");
    let resource: ResourceId = id("facilities_table");
    ctx.register_table(table_name(&dataset, &resource), Arc::new(table))
        .expect("register table");
    let query = Arc::new(EntityQueryEngine::new(ctx, Arc::clone(&registry)));

    TestServer::new(
        ogc_router::<()>()
            .layer(Extension(Arc::new(CursorSigner::new_random())))
            .layer(Extension(query))
            .layer(Extension(registry))
            .layer(Extension(cfg))
            .layer(Extension(principal(scopes))),
    )
}

async fn server(scopes: &[&str]) -> TestServer {
    server_with_purpose(scopes, false).await
}

#[tokio::test]
async fn landing_and_conformance_use_ogc_contract_names() {
    let server = server(&["civic_registry:metadata"]).await;

    let landing = server.get("/ogc/v1").await;
    landing.assert_status_ok();
    let body: Value = landing.json();
    assert_eq!(body["title"], "Registry Relay OGC API");
    assert!(body["links"]
        .as_array()
        .unwrap()
        .iter()
        .any(|link| { link["rel"] == "service-desc" && link["href"] == "/openapi.json" }));

    let conformance = server.get("/ogc/v1/conformance").await;
    conformance.assert_status_ok();
    let body: Value = conformance.json();
    assert!(body["conformsTo"]
        .as_array()
        .unwrap()
        .iter()
        .any(|uri| uri == "http://www.opengis.net/spec/ogcapi-features-1/1.0/conf/core"));
}

#[tokio::test]
async fn collection_metadata_is_dataset_scoped_and_discoverable() {
    let server = server(&["civic_registry:metadata"]).await;

    let response = server
        .get("/ogc/v1/datasets/civic_registry/collections/facilities")
        .await;
    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["id"], "civic_registry.facilities");
    assert_eq!(body["crs"][0], CRS84);
    assert_eq!(body["storageCrs"], CRS84);
    assert!(body["properties"]["propertyNames"]
        .as_array()
        .unwrap()
        .iter()
        .all(|field| field != "lon" && field != "lat"));
}

#[tokio::test]
async fn items_apply_required_filters_bbox_and_geometry_mapping() {
    let server = server(&["civic_registry:metadata", "civic_registry:rows"]).await;

    let response = server
        .get("/ogc/v1/datasets/civic_registry/collections/facilities/items?facility_type=clinic&bbox=100.5,13.7,100.7,13.9&limit=10")
        .await;
    response.assert_status_ok();
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "application/geo+json"
    );
    let body: Value = response.json();
    assert_eq!(body["type"], "FeatureCollection");
    assert_eq!(body["numberReturned"], 1);
    assert!(body.get("numberMatched").is_none());
    assert_eq!(body["features"][0]["id"], "FAC-001");
    assert_eq!(body["features"][0]["geometry"]["type"], "Point");
    assert!(body["features"][0]["properties"].get("lon").is_none());
    assert!(body["features"][0]["properties"].get("lat").is_none());
    assert!(body["features"][0]["links"]
        .as_array()
        .unwrap()
        .iter()
        .any(|link| {
            link["rel"] == "self"
                && link["href"]
                    .as_str()
                    .unwrap()
                    .contains("facility_type=clinic")
        }));
}

#[tokio::test]
async fn bbox_alone_does_not_satisfy_required_filters() {
    let server = server(&["civic_registry:metadata", "civic_registry:rows"]).await;

    let response = server
        .get("/ogc/v1/datasets/civic_registry/collections/facilities/items?bbox=100.5,13.7,100.7,13.9")
        .await;
    response.assert_status_bad_request();
    let body: Value = response.json();
    assert_eq!(body["code"], "entity.filter_required");
}

#[tokio::test]
async fn broad_ogc_required_filter_ops_return_filter_required() {
    let server = server(&["civic_registry:metadata", "civic_registry:rows"]).await;

    let response = server
        .get("/ogc/v1/datasets/civic_registry/collections/facilities/items?facility_type.in=clinic,hospital")
        .await;

    response.assert_status_bad_request();
    let body: Value = response.json();
    assert_eq!(body["code"], "entity.filter_required");
}

#[tokio::test]
async fn item_by_id_preserves_required_filter_context_and_null_geometry() {
    let server = server(&["civic_registry:metadata", "civic_registry:rows"]).await;

    let missing_filter = server
        .get("/ogc/v1/datasets/civic_registry/collections/facilities/items/FAC-001")
        .await;
    missing_filter.assert_status_bad_request();
    assert_eq!(
        missing_filter.json::<Value>()["code"],
        "entity.filter_required"
    );

    let response = server
        .get("/ogc/v1/datasets/civic_registry/collections/facilities/items/FAC-003?facility_type=clinic")
        .await;
    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["id"], "FAC-003");
    assert!(body["geometry"].is_null());

    let response = server
        .get("/ogc/v1/datasets/civic_registry/collections/facilities/items/FAC-003?facility_type=clinic&after=not-a-collection-cursor")
        .await;
    response.assert_status_bad_request();
    assert_eq!(
        response.json::<Value>()["code"],
        "spatial.filter_unsupported"
    );
}

#[tokio::test]
async fn ogc_items_and_features_enforce_required_purpose_header() {
    let policy = r#"          governed_policy:
            permitted_purposes:
              - capacity planning
"#;
    let server = server_with_purpose_and_entity_api_extra(
        &["civic_registry:metadata", "civic_registry:rows"],
        true,
        policy,
    )
    .await;

    let response = server
        .get("/ogc/v1/datasets/civic_registry/collections/facilities/items?facility_type=clinic")
        .await;
    response.assert_status_bad_request();
    assert_eq!(response.json::<Value>()["code"], "auth.purpose_required");

    let response = server
        .get("/ogc/v1/datasets/civic_registry/collections/facilities/items?facility_type=clinic")
        .add_header("data-purpose", "   ")
        .await;
    response.assert_status_bad_request();
    assert_eq!(response.json::<Value>()["code"], "auth.purpose_required");

    let response = server
        .get("/ogc/v1/datasets/civic_registry/collections/facilities/items?facility_type=clinic")
        .add_header("data-purpose", "capacity planning")
        .await;
    response.assert_status_ok();

    let response = server
        .get("/ogc/v1/datasets/civic_registry/collections/facilities/items/FAC-001?facility_type=clinic")
        .await;
    response.assert_status_bad_request();
    assert_eq!(response.json::<Value>()["code"], "auth.purpose_required");

    let response = server
        .get("/ogc/v1/datasets/civic_registry/collections/facilities/items/FAC-001?facility_type=clinic")
        .add_header("data-purpose", "capacity planning")
        .await;
    response.assert_status_ok();
}

#[tokio::test]
async fn ogc_items_enforce_governed_purpose_and_redaction() {
    let policy = r#"          governed_policy:
            permitted_purposes:
              - capacity planning
            redaction_fields: [name]
"#;
    let server = server_with_purpose_and_entity_api_extra(
        &["civic_registry:metadata", "civic_registry:rows"],
        true,
        policy,
    )
    .await;

    let denied = server
        .get("/ogc/v1/datasets/civic_registry/collections/facilities/items?facility_type=clinic")
        .add_header("data-purpose", "casework")
        .await;
    denied.assert_status_forbidden();
    assert_eq!(denied.json::<Value>()["code"], "pdp.purpose_not_permitted");

    let collection = server
        .get("/ogc/v1/datasets/civic_registry/collections/facilities/items?facility_type=clinic")
        .add_header("data-purpose", "capacity planning")
        .await;
    collection.assert_status_ok();
    let body: Value = collection.json();
    assert!(body["features"][0]["properties"].get("name").is_none());
    assert_eq!(body["features"][0]["properties"]["facility_type"], "clinic");

    let item = server
        .get("/ogc/v1/datasets/civic_registry/collections/facilities/items/FAC-001?facility_type=clinic")
        .add_header("data-purpose", "capacity planning")
        .await;
    item.assert_status_ok();
    let body: Value = item.json();
    assert!(body["properties"].get("name").is_none());
    assert_eq!(body["properties"]["facility_type"], "clinic");
}

#[tokio::test]
async fn bbox_crs_and_antimeridian_errors_are_problem_json() {
    let server = server(&["civic_registry:metadata", "civic_registry:rows"]).await;

    let response = server
        .get("/ogc/v1/datasets/civic_registry/collections/facilities/items?facility_type=clinic&bbox-crs=EPSG:4326")
        .await;
    response.assert_status_bad_request();
    assert_eq!(response.json::<Value>()["code"], "spatial.crs_unsupported");

    let response = server
        .get("/ogc/v1/datasets/civic_registry/collections/facilities/items?facility_type=clinic&bbox=170,-10,-170,10")
        .await;
    response.assert_status_bad_request();
    let body: Value = response.json();
    assert_eq!(body["code"], "spatial.bbox_invalid");
    assert!(body["detail"].as_str().unwrap().contains("antimeridian"));
}

#[tokio::test]
async fn signed_cursor_is_bound_to_query_context() {
    let server = server(&["civic_registry:metadata", "civic_registry:rows"]).await;

    let first_page = server
        .get("/ogc/v1/datasets/civic_registry/collections/facilities/items?facility_type=clinic&limit=1")
        .await;
    first_page.assert_status_ok();
    let body: Value = first_page.json();
    assert_eq!(body["numberReturned"], 1);
    assert_eq!(body["features"][0]["id"], "FAC-001");
    let next_href = body["links"]
        .as_array()
        .unwrap()
        .iter()
        .find(|link| link["rel"] == "next")
        .and_then(|link| link["href"].as_str())
        .expect("next link is present");

    let second_page = server.get(next_href).await;
    second_page.assert_status_ok();
    let body: Value = second_page.json();
    assert_eq!(body["numberReturned"], 1);
    assert_eq!(body["features"][0]["id"], "FAC-003");

    let tampered = next_href.replace("facility_type=clinic", "facility_type=school");
    let response = server.get(&tampered).await;
    response.assert_status_bad_request();
    assert_eq!(response.json::<Value>()["code"], "query.cursor_invalid");
}

#[tokio::test]
async fn feature_links_percent_encode_query_values_and_path_segments() {
    let server = server(&["civic_registry:metadata", "civic_registry:rows"]).await;

    let response = server
        .get("/ogc/v1/datasets/civic_registry/collections/facilities/items?facility_type=clinic%20%26%20urgent")
        .await;
    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["numberReturned"], 1);
    assert_eq!(body["features"][0]["id"], "FAC/004");
    let self_href = body["features"][0]["links"]
        .as_array()
        .unwrap()
        .iter()
        .find(|link| link["rel"] == "self")
        .and_then(|link| link["href"].as_str())
        .expect("feature self link");
    assert!(self_href.contains("/items/FAC%2F004?"));
    assert!(self_href.contains("facility_type=clinic%20%26%20urgent"));
}
