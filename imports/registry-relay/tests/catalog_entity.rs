// SPDX-License-Identifier: Apache-2.0
//! Catalog metadata tests for entity-grain JSON and JSON-LD outputs.

use std::sync::Arc;

use axum::http::StatusCode;
use axum::Extension;
use axum_test::TestServer;
use data_gate::api::catalog_router;
use data_gate::auth::{AuthMode, Principal, ScopeSet};
use data_gate::config;
use data_gate::entity::EntityRegistry;
use serde_json::Value;
use tempfile::TempDir;

fn write_config(tmp: &TempDir) -> std::path::PathBuf {
    let path = tmp.path().join("catalog_entity.yaml");
    std::fs::write(
        &path,
        r#"
server:
  bind: 127.0.0.1:0

catalog:
  title: Program Data Catalog
  base_url: https://data.example.test/
  publisher: Ministry of Delivery

vocabularies:
  psc: https://publicschema.org/
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
            - name: internal_note
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
            - name: age
              type: integer
              nullable: true
    entities:
      - name: household
        title: Household
        description: Registered household
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
            - field: region
              ops: [eq]
          allowed_expansions: [members]
      - name: individual
        table: individuals_table
        fields:
          - name: id
            from: individual_id
          - name: household_id
          - name: age
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
    path
}

fn server() -> TestServer {
    let tmp = TempDir::new().expect("tempdir");
    let cfg = Arc::new(config::load(&write_config(&tmp)).expect("config loads"));
    let registry = Arc::new(EntityRegistry::from_config(&cfg).expect("registry compiles"));

    TestServer::new(
        catalog_router::<()>()
            .layer(Extension(registry))
            .layer(Extension(cfg))
            .layer(Extension(principal(&["social_registry:metadata"]))),
    )
}

fn principal(scopes: &[&str]) -> Principal {
    Principal {
        api_key_id: "test".to_string(),
        scopes: scopes.iter().copied().collect::<ScopeSet>(),
        auth_mode: AuthMode::ApiKey,
    }
}

fn entity<'a>(body: &'a Value, name: &str) -> &'a Value {
    body["datasets"][0]["entities"]
        .as_array()
        .expect("entities array")
        .iter()
        .find(|entity| entity["name"] == name)
        .expect("entity present")
}

#[tokio::test]
async fn catalog_lists_entity_grain_metadata_without_hidden_columns() {
    let resp = server().get("/catalog").await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(body["base_url"], "https://data.example.test");
    assert_eq!(
        body["links"]["dcat_ap"],
        "https://data.example.test/catalog/dcat-ap.jsonld"
    );
    assert_eq!(body["datasets"][0]["dataset_id"], "social_registry");
    assert_eq!(
        body["datasets"][0]["conforms_to"][0],
        "https://example.test/vocab/profiles/social"
    );

    let household = entity(&body, "household");
    assert_eq!(household["primary_key"], "id");
    assert_eq!(
        household["concept_uri"],
        "https://publicschema.org/concepts/Household"
    );
    assert_eq!(
        household["links"]["collection"],
        "https://data.example.test/datasets/social_registry/household"
    );
    assert_eq!(household["fields"].as_array().expect("fields").len(), 2);
    assert_eq!(household["fields"][1]["name"], "region");
    assert_eq!(household["fields"][1]["type"], "string");
    assert_eq!(household["fields"][1]["nullable"], true);
    assert_eq!(
        household["fields"][1]["concept_uri"],
        "https://example.test/vocab/properties/region"
    );
    assert_eq!(
        household["fields"][1]["codelist"],
        "https://example.test/vocab/codelists/Region"
    );
    assert!(household["fields"]
        .as_array()
        .expect("fields")
        .iter()
        .all(|field| field["name"] != "internal_note"));
    assert_eq!(household["relationships"][0]["kind"], "has_many");
    assert_eq!(household["relationships"][0]["target"], "individual");
}

#[tokio::test]
async fn dcat_ap_jsonld_embeds_entity_shacl_shapes() {
    let resp = server().get("/catalog/dcat-ap.jsonld").await;

    resp.assert_status(StatusCode::OK);
    assert_eq!(resp.header("content-type"), "application/ld+json");
    let body: Value = resp.json();
    assert_eq!(body["@type"], "dcat:Catalog");
    assert_eq!(body["dcat:dataset"][0]["@type"], "dcat:Dataset");

    let shapes = body["sh:shapesGraph"].as_array().expect("shapes graph");
    let household = shapes
        .iter()
        .find(|shape| shape["sh:name"] == "household")
        .expect("household shape");
    assert_eq!(
        household["sh:targetClass"],
        "https://publicschema.org/concepts/Household"
    );
    assert_eq!(household["data_gate:primaryKey"], "id");
    assert!(household["sh:property"]
        .as_array()
        .expect("properties")
        .iter()
        .any(|property| {
            property["sh:path"] == "https://example.test/vocab/properties/region"
                && property["sh:name"] == "region"
        }));
    assert!(household["sh:property"]
        .as_array()
        .expect("properties")
        .iter()
        .any(|property| {
            property["sh:path"] == "https://example.test/vocab/relationships/householdMember"
                && property["data_gate:targetEntity"] == "individual"
        }));
}

#[tokio::test]
async fn single_entity_schema_jsonld_returns_schema_and_shape() {
    let resp = server()
        .get("/catalog/datasets/social_registry/household/schema.jsonld")
        .await;

    resp.assert_status(StatusCode::OK);
    assert_eq!(resp.header("content-type"), "application/ld+json");
    let body: Value = resp.json();
    assert_eq!(body["schema"]["dataset_id"], "social_registry");
    assert_eq!(body["schema"]["entity"], "household");
    assert_eq!(body["schema"]["relationships"][0]["target"], "individual");
    assert_eq!(body["shape"]["@type"], "sh:NodeShape");
}

#[tokio::test]
async fn single_entity_schema_returns_not_found_for_unknown_entity() {
    let resp = server()
        .get("/catalog/datasets/social_registry/missing/schema.jsonld")
        .await;

    resp.assert_status(StatusCode::NOT_FOUND);
    let body: Value = resp.json();
    assert_eq!(body["code"], "schema.unknown_resource");
}
