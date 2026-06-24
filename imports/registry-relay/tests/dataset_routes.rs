// SPDX-License-Identifier: Apache-2.0
//! Focused route tests for dataset summary endpoints.

use std::sync::Arc;

use axum::http::StatusCode;
use axum::Extension;
use axum_test::TestServer;
use registry_relay::api::datasets_router;
use registry_relay::auth::{AuthMode, Principal, ScopeSet};
use registry_relay::config;
use serde_json::Value;
use tempfile::TempDir;

fn write_config(tmp: &TempDir) -> std::path::PathBuf {
    let path = tmp.path().join("dataset_routes.yaml");
    std::fs::write(
        &path,
        r#"
server:
  bind: 127.0.0.1:0

catalog:
  title: Test Catalog
  base_url: https://data.example.test
  publisher: Test Publisher

vocabularies: {}

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
      - https://example.test/profile/social
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
            - name: lon
              type: number
              nullable: true
            - name: lat
              type: number
              nullable: true
    entities:
      - name: household
        table: households_table
        fields:
          - name: id
            from: household_id
          - name: lon
          - name: lat
        access:
          metadata_scope: social_registry:metadata
          aggregate_scope: social_registry:aggregate
          read_scope: social_registry:rows
          evidence_verification_scope: social_registry:evidence_verification
        api:
          default_limit: 100
          max_limit: 1000
          allowed_filters:
            - field: id
              ops: [eq]
      - name: individual
        table: households_table
        fields:
          - name: id
            from: household_id
        access:
          metadata_scope: social_registry:individual:metadata
          aggregate_scope: social_registry:aggregate
          read_scope: social_registry:rows
          evidence_verification_scope: social_registry:evidence_verification
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
    let config = Arc::new(config::load(&write_config(&tmp)).expect("config loads"));

    TestServer::new(
        datasets_router::<()>()
            .layer(Extension(config))
            .layer(Extension(principal(scopes))),
    )
}

#[cfg(feature = "ogcapi-features")]
fn ogc_server(scopes: &[&str]) -> TestServer {
    let tmp = TempDir::new().expect("tempdir");
    let path = write_config(&tmp);
    let mut body = std::fs::read_to_string(&path).expect("read config");
    body = body.replace(
        "          - name: lon\n          - name: lat\n        access:\n",
        "          - name: lon\n          - name: lat\n        spatial:\n          collection_id: households\n          title: Household locations\n          geometry:\n            kind: point\n            longitude_field: lon\n            latitude_field: lat\n            crs: http://www.opengis.net/def/crs/OGC/1.3/CRS84\n        access:\n",
    );
    std::fs::write(&path, body).expect("write OGC config");
    let config = Arc::new(config::load(&path).expect("config loads"));

    TestServer::new(
        datasets_router::<()>()
            .layer(Extension(config))
            .layer(Extension(principal(scopes))),
    )
}

#[cfg(feature = "spdci-api-standards")]
fn spdci_server(scopes: &[&str]) -> TestServer {
    let tmp = TempDir::new().expect("tempdir");
    let path = write_config(&tmp);
    let mut body = std::fs::read_to_string(&path).expect("read config");
    body = body.replace(
        "auth:\n  mode: api_key\n  api_keys: []\n",
        "auth:\n  mode: api_key\n  api_keys: []\n\nstandards:\n  spdci:\n    registries:\n      sr:\n        dataset: social_registry\n        entity: household\n        registry_type: ns:org:RegistryType:SR\n        record_type: spdci-extensions-social:Group\n        identifiers:\n          HOUSEHOLD_ID: id\n        expression_fields:\n          household_id: id\n",
    );
    std::fs::write(&path, body).expect("write SP DCI config");
    let config = Arc::new(config::load(&path).expect("config loads"));

    TestServer::new(
        datasets_router::<()>()
            .layer(Extension(config))
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
async fn datasets_lists_only_datasets_with_entity_metadata_scope() {
    let resp = server(&["social_registry:metadata"])
        .get("/v1/datasets")
        .await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    let data = body["data"].as_array().expect("data array");
    assert_eq!(data.len(), 1);
    assert_eq!(data[0]["dataset_id"], "social_registry");
    assert_eq!(data[0]["title"], "Social Registry");
    assert_eq!(data[0]["description"], "Synthetic registry");
    assert_eq!(data[0]["owner"], "Social Ministry");
    assert_eq!(data[0]["sensitivity"], "personal");
    assert_eq!(data[0]["access_rights"], "restricted");
    assert_eq!(data[0]["update_frequency"], "monthly");
    assert_eq!(
        data[0]["conforms_to"][0],
        "https://example.test/profile/social"
    );
    assert_eq!(data[0]["links"]["self"], "/v1/datasets/social_registry");
    assert_eq!(data[0]["entities"], serde_json::json!(["household"]));
}

#[tokio::test]
async fn datasets_filter_entities_inside_visible_dataset_by_metadata_scope() {
    let resp = server(&["social_registry:individual:metadata"])
        .get("/v1/datasets")
        .await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    let data = body["data"].as_array().expect("data array");
    assert_eq!(data.len(), 1);
    assert_eq!(data[0]["dataset_id"], "social_registry");
    assert_eq!(data[0]["entities"], serde_json::json!(["individual"]));
}

#[tokio::test]
async fn evidence_verification_only_scope_cannot_read_datasets() {
    let resp = server(&["social_registry:evidence_verification"])
        .get("/v1/datasets")
        .await;

    resp.assert_status(StatusCode::FORBIDDEN);
    let body: Value = resp.json();
    assert_eq!(body["code"], "auth.scope_denied");
}

#[tokio::test]
async fn datasets_returns_scope_denied_when_no_dataset_is_visible() {
    let resp = server(&["social_registry:rows"]).get("/v1/datasets").await;

    resp.assert_status(StatusCode::FORBIDDEN);
    let body: Value = resp.json();
    assert_eq!(body["code"], "auth.scope_denied");
}

#[tokio::test]
async fn dataset_returns_single_summary_when_scope_matches_entity_in_dataset() {
    let resp = server(&["payments:metadata"])
        .get("/v1/datasets/payments")
        .await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(body["dataset_id"], "payments");
    assert_eq!(body["title"], "Payments");
    assert_eq!(body["sensitivity"], "confidential");
    assert_eq!(body["access_rights"], "non_public");
    assert_eq!(body["update_frequency"], "weekly");
    assert_eq!(body["links"]["self"], "/v1/datasets/payments");
    assert_eq!(body["entities"], serde_json::json!(["payment"]));
}

#[cfg(feature = "ogcapi-features")]
#[tokio::test]
async fn dataset_summary_advertises_visible_ogc_standard_service() {
    let resp = ogc_server(&["social_registry:metadata"])
        .get("/v1/datasets/social_registry")
        .await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(
        body["links"]["ogc_collections"],
        "/ogc/v1/datasets/social_registry/collections"
    );
    assert_eq!(body["standards"]["ogc_api_features"]["landing"], "/ogc/v1");
    assert_eq!(
        body["standards"]["ogc_api_features"]["collections"],
        "/ogc/v1/datasets/social_registry/collections"
    );
}

#[cfg(not(feature = "ogcapi-features"))]
#[tokio::test]
async fn dataset_summary_hides_ogc_standard_service_when_feature_is_disabled() {
    let resp = server(&["social_registry:metadata"])
        .get("/v1/datasets/social_registry")
        .await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert!(body["links"].get("ogc_collections").is_none());
    assert!(body.get("standards").is_none());
}

#[cfg(feature = "spdci-api-standards")]
#[tokio::test]
async fn dataset_summary_advertises_visible_spdci_standard_service() {
    let resp = spdci_server(&["social_registry:metadata"])
        .get("/v1/datasets/social_registry")
        .await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    let registry = &body["standards"]["spdci"]["registries"][0];
    assert_eq!(registry["registry"], "sr");
    assert_eq!(registry["entity"], "household");
    assert_eq!(registry["sync_search"], "/dci/sr/registry/sync/search");
}

#[tokio::test]
async fn dataset_denies_without_metadata_scope_for_that_dataset() {
    let resp = server(&["social_registry:metadata"])
        .get("/v1/datasets/payments")
        .await;

    resp.assert_status(StatusCode::FORBIDDEN);
    let body: Value = resp.json();
    assert_eq!(body["code"], "auth.scope_denied");
}

#[tokio::test]
async fn dataset_returns_unknown_dataset_for_missing_id() {
    let resp = server(&["social_registry:metadata"])
        .get("/v1/datasets/missing")
        .await;

    resp.assert_status(StatusCode::NOT_FOUND);
    let body: Value = resp.json();
    assert_eq!(body["code"], "schema.unknown_dataset");
}
