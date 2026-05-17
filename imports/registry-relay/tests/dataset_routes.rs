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
          verify_scope: social_registry:verify
          bulk_export_scope: social_registry:bulk_export
        api:
          default_limit: 100
          max_limit: 1000
      - name: individual
        table: households_table
        fields:
          - name: id
            from: household_id
        access:
          metadata_scope: social_registry:individual:metadata
          aggregate_scope: social_registry:aggregate
          read_scope: social_registry:rows
          verify_scope: social_registry:verify
          bulk_export_scope: social_registry:bulk_export
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
    source:
      type: file
      path: fixtures/payments.csv
    refresh:
      mode: manual
    tables:
      - id: payments_table
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
          verify_scope: payments:verify
          bulk_export_scope: payments:bulk_export
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

fn principal(scopes: &[&str]) -> Principal {
    Principal {
        principal_id: "test".to_string(),
        scopes: scopes.iter().copied().collect::<ScopeSet>(),
        auth_mode: AuthMode::ApiKey,
    }
}

#[tokio::test]
async fn datasets_lists_only_datasets_with_entity_metadata_scope() {
    let resp = server(&["social_registry:metadata"]).get("/datasets").await;

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
    assert_eq!(data[0]["entities"], serde_json::json!(["household"]));
}

#[tokio::test]
async fn datasets_filter_entities_inside_visible_dataset_by_metadata_scope() {
    let resp = server(&["social_registry:individual:metadata"])
        .get("/datasets")
        .await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    let data = body["data"].as_array().expect("data array");
    assert_eq!(data.len(), 1);
    assert_eq!(data[0]["dataset_id"], "social_registry");
    assert_eq!(data[0]["entities"], serde_json::json!(["individual"]));
}

#[tokio::test]
async fn verify_only_scope_cannot_read_datasets() {
    let resp = server(&["social_registry:verify"]).get("/datasets").await;

    resp.assert_status(StatusCode::FORBIDDEN);
    let body: Value = resp.json();
    assert_eq!(body["code"], "auth.scope_denied");
}

#[tokio::test]
async fn datasets_returns_scope_denied_when_no_dataset_is_visible() {
    let resp = server(&["social_registry:rows"]).get("/datasets").await;

    resp.assert_status(StatusCode::FORBIDDEN);
    let body: Value = resp.json();
    assert_eq!(body["code"], "auth.scope_denied");
}

#[tokio::test]
async fn dataset_returns_single_summary_when_scope_matches_entity_in_dataset() {
    let resp = server(&["payments:metadata"])
        .get("/datasets/payments")
        .await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(body["dataset_id"], "payments");
    assert_eq!(body["title"], "Payments");
    assert_eq!(body["sensitivity"], "confidential");
    assert_eq!(body["access_rights"], "non_public");
    assert_eq!(body["update_frequency"], "weekly");
    assert_eq!(body["entities"], serde_json::json!(["payment"]));
}

#[tokio::test]
async fn dataset_denies_without_metadata_scope_for_that_dataset() {
    let resp = server(&["social_registry:metadata"])
        .get("/datasets/payments")
        .await;

    resp.assert_status(StatusCode::FORBIDDEN);
    let body: Value = resp.json();
    assert_eq!(body["code"], "auth.scope_denied");
}

#[tokio::test]
async fn dataset_returns_unknown_dataset_for_missing_id() {
    let resp = server(&["social_registry:metadata"])
        .get("/datasets/missing")
        .await;

    resp.assert_status(StatusCode::NOT_FOUND);
    let body: Value = resp.json();
    assert_eq!(body["code"], "schema.unknown_dataset");
}
