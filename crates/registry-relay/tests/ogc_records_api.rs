// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "ogcapi-records")]

use std::sync::Arc;

use axum::Extension;
use axum_test::TestServer;
use registry_relay::api::{records_router, CursorSigner};
use registry_relay::auth::{AuthMode, Principal, ScopeSet};
use registry_relay::config;
use registry_relay::entity::EntityRegistry;
use serde_json::Value;
use tempfile::TempDir;

fn write_config(tmp: &TempDir) -> std::path::PathBuf {
    let path = tmp.path().join("ogc_records.yaml");
    std::fs::write(
        &path,
        r#"
server:
  bind: 127.0.0.1:0

catalog:
  title: Program Data Catalog
  base_url: https://data.example.test/
  publisher: Ministry of Delivery

deployment:
  profile: local

vocabularies:
  ex: https://example.test/vocab/

auth:
  mode: api_key
  api_keys: []

datasets:
  - id: social_registry
    title: Social Registry
    description: Synthetic registry
    owner: Social Ministry
    sensitivity: personal
    access_rights: restricted
    update_frequency: monthly
    conforms_to:
      - ex:profiles/social
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
            - name: region
              type: string
              nullable: true
    entities:
      - name: household
        title: Household
        description: Registered household
        table: households_table
        fields:
          - name: id
            from: household_id
          - name: region
        access:
          metadata_scope: social_registry:metadata
          aggregate_scope: social_registry:aggregate
          read_scope: social_registry:rows
        api:
          default_limit: 100
          max_limit: 1000

  - id: payments
    title: Payments
    description: Payment records
    owner: Finance Ministry
    sensitivity: confidential
    access_rights: non_public
    update_frequency: weekly
    defaults:
      refresh:
        mode: manual
    tables:
      - id: payments_table
        source:
          type: file
          path: fixtures/payments.csv
        primary_key: payment_id
        schema:
          strict: true
          fields:
            - name: payment_id
              type: string
              nullable: false
    entities:
      - name: payment
        table: payments_table
        fields:
          - name: id
            from: payment_id
        access:
          metadata_scope: payments:metadata
          aggregate_scope: payments:aggregate
          read_scope: payments:rows
        api:
          default_limit: 100
          max_limit: 1000

audit:
  sink: stdout
  format: jsonl
"#,
    )
    .expect("write config");
    path
}

fn server(scopes: &[&str]) -> TestServer {
    let tmp = TempDir::new().expect("tempdir");
    let cfg = Arc::new(config::load(&write_config(&tmp)).expect("config loads"));
    let registry = Arc::new(EntityRegistry::from_config(&cfg).expect("registry compiles"));

    TestServer::new(
        records_router::<()>()
            .layer(Extension(registry))
            .layer(Extension(cfg))
            .layer(Extension(Arc::new(CursorSigner::new_random())))
            .layer(Extension(principal(scopes))),
    )
}

fn write_split_metadata_manifest(tmp: &TempDir) {
    std::fs::write(
        tmp.path().join("metadata.yaml"),
        r#"
schema_version: registry-manifest/v1
catalog:
  id: split-ogc
  base_url: https://metadata.example.test/
  title: Split OGC Catalog
  publisher:
    name: Metadata Ministry
datasets:
  - id: social_registry
    title: Portable Social Registry
    description: Portable registry description
    owner: Metadata Ministry
    sensitivity: personal
    access_rights: restricted
    update_frequency: monthly
    entities:
      - name: household
        title: Portable Household
        identifiers:
          - name: id
            kind: primary
        fields:
          - name: id
            type: string
            required: true
          - name: region
            type: string
  - id: payments
    title: Portable Payments
    description: Portable payment records
    owner: Metadata Ministry
    sensitivity: confidential
    access_rights: non_public
    update_frequency: weekly
    entities:
      - name: payment
        title: Portable Payment
        identifiers:
          - name: id
            kind: primary
        fields:
          - name: id
            type: string
            required: true
"#,
    )
    .expect("write metadata manifest");
}

fn write_split_config(tmp: &TempDir) -> std::path::PathBuf {
    write_split_metadata_manifest(tmp);
    let path = write_config(tmp);
    let raw = std::fs::read_to_string(&path).expect("read runtime config");
    std::fs::write(
        &path,
        raw.replacen(
            "catalog:\n",
            "metadata:\n  source:\n    path: metadata.yaml\n\ncatalog:\n",
            1,
        ),
    )
    .expect("write split runtime config");
    path
}

fn split_server(scopes: &[&str]) -> TestServer {
    let tmp = TempDir::new().expect("tempdir");
    let loaded = config::load_with_metadata(&write_split_config(&tmp)).expect("split config loads");
    let metadata = Arc::new(loaded.metadata.expect("metadata compiles"));
    let cfg = Arc::new(loaded.runtime);
    let registry = Arc::new(EntityRegistry::from_config(&cfg).expect("registry compiles"));

    TestServer::new(
        records_router::<()>()
            .layer(Extension(metadata))
            .layer(Extension(registry))
            .layer(Extension(cfg))
            .layer(Extension(Arc::new(CursorSigner::new_random())))
            .layer(Extension(principal(scopes))),
    )
}

fn principal(scopes: &[&str]) -> Principal {
    Principal {
        principal_id: "test".to_string(),
        scopes: scopes.iter().copied().collect::<ScopeSet>(),
        auth_mode: AuthMode::ApiKey,
    }
}

#[tokio::test]
async fn landing_and_conformance_advertise_records_contract() {
    let server = server(&["social_registry:metadata"]);

    let landing = server.get("/ogc/v1/records").await;
    landing.assert_status_ok();
    let body: Value = landing.json();
    assert_eq!(body["title"], "Registry Relay OGC API Records");
    assert!(body["links"]
        .as_array()
        .expect("links")
        .iter()
        .any(|link| link["rel"] == "data"
            && link["href"] == "https://data.example.test/ogc/v1/records/collections"));

    let conformance = server.get("/ogc/v1/records/conformance").await;
    conformance.assert_status_ok();
    let body: Value = conformance.json();
    assert!(body["conformsTo"]
        .as_array()
        .expect("conformance")
        .iter()
        .any(|uri| uri == "http://www.opengis.net/spec/ogcapi-records-1/1.0/conf/record-core"));
    assert!(body["conformsTo"]
        .as_array()
        .expect("conformance")
        .iter()
        .any(|uri| uri == "http://www.opengis.net/spec/ogcapi-records-1/1.0/conf/oas30"));
    assert!(!body["conformsTo"]
        .as_array()
        .expect("conformance")
        .iter()
        .any(
            |uri| uri == "http://www.opengis.net/spec/ogcapi-records-1/1.0/conf/searchable-catalog"
        ));
}

#[tokio::test]
async fn records_collection_lists_visible_dataset_records_only() {
    let server = server(&["social_registry:metadata"]);

    let collection = server.get("/ogc/v1/records/collections/datasets").await;
    collection.assert_status_ok();
    let body: Value = collection.json();
    assert_eq!(body["id"], "datasets");
    assert_eq!(body["itemType"], "record");
    assert_eq!(body["extent"]["temporal"]["interval"][0][0], Value::Null);
    assert!(body["links"]
        .as_array()
        .expect("links")
        .iter()
        .all(|link| link["href"].as_str().expect("href").starts_with("https://")));

    let items = server
        .get("/ogc/v1/records/collections/datasets/items")
        .await;
    items.assert_status_ok();
    assert_eq!(
        items.headers().get("content-type").unwrap(),
        "application/geo+json"
    );
    let body: Value = items.json();
    assert_eq!(body["type"], "FeatureCollection");
    assert_eq!(body["numberMatched"], 1);
    assert_eq!(body["numberReturned"], 1);
    assert_eq!(body["features"][0]["id"], "social_registry");
    assert_eq!(body["features"][0]["type"], "Feature");
    assert!(body["features"][0]["geometry"].is_null());
    assert_eq!(body["features"][0]["properties"]["type"], "Record");
    assert_eq!(
        body["features"][0]["properties"]["resourceType"],
        "dcat:Dataset"
    );
    assert!(body["features"][0]["properties"].get("publisher").is_none());
    assert_eq!(
        body["features"][0]["properties"]["entities"][0]["schema"],
        "https://data.example.test/metadata/schema/social_registry/household/schema.json"
    );
    assert!(body["features"]
        .as_array()
        .expect("features")
        .iter()
        .all(|record| record["id"] != "payments"));
}

#[tokio::test]
async fn record_item_respects_metadata_visibility() {
    let server = server(&["social_registry:metadata"]);

    let response = server
        .get("/ogc/v1/records/collections/datasets/items/social_registry")
        .await;
    response.assert_status_ok();
    assert_eq!(
        response.headers().get("content-type").unwrap(),
        "application/geo+json"
    );
    let body: Value = response.json();
    assert_eq!(body["id"], "social_registry");
    assert_eq!(body["properties"]["type"], "Record");
    assert_eq!(body["properties"]["resourceType"], "dcat:Dataset");
    assert_eq!(body["properties"]["entityCount"], 1);
    assert!(body["properties"].get("publisher").is_none());
    assert_eq!(
        body["properties"]["entities"][0]["collection"],
        "https://data.example.test/v1/datasets/social_registry/entities/household/records"
    );
    assert!(body["links"]
        .as_array()
        .expect("links")
        .iter()
        .any(|link| link["rel"] == "self"
            && link["href"]
                == "https://data.example.test/ogc/v1/records/collections/datasets/items/social_registry"));

    let response = server
        .get("/ogc/v1/records/collections/datasets/items/payments")
        .await;
    response.assert_status_not_found();
    assert_eq!(response.json::<Value>()["code"], "ogc.record_not_found");
}

#[tokio::test]
async fn records_items_prefer_split_metadata_manifest_extension() {
    let server = split_server(&["social_registry:metadata"]);

    let response = server
        .get("/ogc/v1/records/collections/datasets/items/social_registry")
        .await;
    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["properties"]["title"], "Portable Social Registry");
    assert_eq!(
        body["properties"]["description"],
        "Portable registry description"
    );
    assert_eq!(
        body["properties"]["entities"][0]["title"],
        "Portable Household"
    );
    assert_eq!(
        body["properties"]["entities"][0]["schema"],
        "https://data.example.test/metadata/schema/social_registry/household/schema.json"
    );
}

#[tokio::test]
async fn records_items_support_q_limit_and_signed_after_cursor() {
    let server = server(&["social_registry:metadata", "payments:metadata"]);

    let response = server
        .get("/ogc/v1/records/collections/datasets/items?q=finance")
        .await;
    response.assert_status_ok();
    let body: Value = response.json();
    assert_eq!(body["numberMatched"], 1);
    assert_eq!(body["numberReturned"], 1);
    assert_eq!(body["features"][0]["id"], "payments");

    let first_page = server
        .get("/ogc/v1/records/collections/datasets/items?limit=1")
        .await;
    first_page.assert_status_ok();
    let body: Value = first_page.json();
    assert_eq!(body["numberMatched"], 2);
    assert_eq!(body["numberReturned"], 1);
    assert_eq!(body["features"][0]["id"], "payments");
    let next_href = body["links"]
        .as_array()
        .expect("links")
        .iter()
        .find(|link| link["rel"] == "next")
        .and_then(|link| link["href"].as_str())
        .expect("next link")
        .to_string();
    assert!(next_href.starts_with("https://data.example.test/"));

    let next_path = next_href
        .strip_prefix("https://data.example.test")
        .expect("local path");
    let second_page = server.get(next_path).await;
    second_page.assert_status_ok();
    let body: Value = second_page.json();
    assert_eq!(body["numberMatched"], 2);
    assert_eq!(body["numberReturned"], 1);
    assert_eq!(body["features"][0]["id"], "social_registry");
}

#[tokio::test]
async fn records_require_at_least_one_metadata_scope() {
    let server = server(&["social_registry:rows"]);

    let response = server.get("/ogc/v1/records/collections").await;
    response.assert_status_forbidden();
    assert_eq!(response.json::<Value>()["code"], "auth.scope_denied");
}
