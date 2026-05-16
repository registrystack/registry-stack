// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "spdci-api-standards")]

//! SP DCI Disability Registry adapter coverage.

use std::env;
use std::path::PathBuf;
use std::sync::Arc;

use axum::http::StatusCode;
use axum::Extension;
use axum_test::TestServer;
use datafusion::arrow::array::StringArray;
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::datasource::MemTable;
use datafusion::execution::context::SessionContext;
use registry_relay::api::spdci_router;
use registry_relay::auth::{AuthMode, Principal, ScopeSet};
use registry_relay::config::{self, DatasetId, ResourceId};
use registry_relay::entity::EntityRegistry;
use registry_relay::ingest::{
    register_versioned_table, table_name, ReadinessSnapshot, ReadyResource,
};
use registry_relay::query::EntityQueryEngine;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::sync::watch;
use ulid::Ulid;

fn id<T: serde::de::DeserializeOwned>(value: &str) -> T {
    serde_json::from_str(&format!(r#""{value}""#)).expect("id deserializes")
}

fn make_fingerprint(plaintext: &[u8]) -> String {
    format!("sha256:{}", hex_lower(&Sha256::digest(plaintext)))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn demo_config(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("demo/config")
        .join(name)
}

fn principal(scopes: &[&str]) -> Principal {
    Principal {
        api_key_id: "test".to_string(),
        scopes: scopes.iter().copied().collect::<ScopeSet>(),
        auth_mode: AuthMode::ApiKey,
    }
}

async fn server() -> TestServer {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = tmp.path().join("spdci.yaml");
    std::fs::write(
        &config_path,
        r#"
server:
  bind: 127.0.0.1:0

catalog:
  title: Test
  base_url: https://gw.example
  publisher: Test

vocabularies: {}

auth:
  mode: api_key
  api_keys: []

audit:
  sink: stdout
  format: jsonl

standards:
  spdci:
    disability_registry:
      dataset: disability_registry
      entity: disabled_person
      query_key: member.member_identifier
      query_field: id
      disabled_status_field: disability_status
      disabled_positive_values: [approved]
    registries:
      dr:
        dataset: disability_registry
        entity: disabled_person
        registry_type: ns:org:RegistryType:DR
        record_type: spdci-extensions-dci:DisabledPerson
        identifiers:
          DISABILITY_ID: id
          MEMBER_ID: id
        expression_fields:
          disability_status: disability_status
          disability_details.impairment_type: impairment_type

datasets:
  - id: disability_registry
    title: Disability Registry
    description: Synthetic registry
    owner: Test
    sensitivity: personal
    access_rights: restricted
    update_frequency: monthly
    source:
      type: file
      path: fixtures/disability_registry.xlsx
      format:
        xlsx:
          sheet: DisabledPeople
    refresh:
      mode: manual
    tables:
      - id: disabled_people_table
        primary_key: person_id
        schema:
          strict: true
          fields:
            - name: person_id
              type: string
              nullable: false
            - name: disability_status
              type: string
              nullable: false
            - name: impairment_type
              type: string
              nullable: true
    entities:
      - name: disabled_person
        table: disabled_people_table
        fields:
          - name: id
            from: person_id
          - name: disability_status
          - name: impairment_type
        access:
          metadata_scope: disability_registry:metadata
          aggregate_scope: disability_registry:aggregate
          read_scope: disability_registry:rows
          verify_scope: disability_registry:verify
          bulk_export_scope: disability_registry:bulk_export
        api:
          default_limit: 100
          max_limit: 1000
          allowed_filters:
            - field: id
              ops: [eq]
            - field: disability_status
              ops: [eq, in]
            - field: impairment_type
              ops: [eq, in]
"#,
    )
    .expect("write config");
    let config = Arc::new(config::load(&config_path).expect("config loads"));
    let registry = Arc::new(EntityRegistry::from_config(&config).expect("entity registry"));
    let ctx = Arc::new(SessionContext::new());
    let dataset: DatasetId = id("disability_registry");
    let resource: ResourceId = id("disabled_people_table");
    let schema = Arc::new(Schema::new(vec![
        Field::new("person_id", DataType::Utf8, false),
        Field::new("disability_status", DataType::Utf8, false),
        Field::new("impairment_type", DataType::Utf8, true),
    ]));
    let batch = RecordBatch::try_new(
        Arc::clone(&schema),
        vec![
            Arc::new(StringArray::from(vec!["ABC451123"])),
            Arc::new(StringArray::from(vec!["Approved"])),
            Arc::new(StringArray::from(vec!["mobility"])),
        ],
    )
    .expect("batch");
    let ingest_ulid = Ulid::from_string("01J5K8M0000000000000000000").expect("ulid");
    register_versioned_table(
        &ctx,
        table_name(&dataset, &resource),
        ingest_ulid,
        Arc::new(MemTable::try_new(schema, vec![vec![batch]]).expect("memtable")),
    )
    .expect("register");
    let mut snapshot = ReadinessSnapshot::default();
    snapshot.ready.insert(
        (dataset, resource),
        ReadyResource {
            ingest_ulid,
            registered_at: time::OffsetDateTime::now_utc(),
        },
    );
    let (_tx, readiness) = watch::channel(snapshot);
    let query = Arc::new(EntityQueryEngine::new(
        Arc::clone(&ctx),
        Arc::clone(&registry),
    ));
    TestServer::new(
        spdci_router::<()>()
            .layer(Extension(principal(&[
                "disability_registry:verify",
                "disability_registry:rows",
            ])))
            .layer(Extension(readiness))
            .layer(Extension(query))
            .layer(Extension(registry))
            .layer(Extension(config)),
    )
}

#[test]
fn disability_registry_demo_config_loads_with_spdci_feature() {
    for name in [
        "CATALOG_VIEWER_HASH",
        "PLANNING_ANALYST_HASH",
        "CASEWORK_SYSTEM_HASH",
        "VERIFICATION_SERVICE_HASH",
        "OPERATIONS_ADMIN_HASH",
    ] {
        env::set_var(name, make_fingerprint(name.as_bytes()));
    }

    let config_path = demo_config("disability_registry.yaml");
    let config = config::load(&config_path).expect("disability_registry.yaml failed to load");
    assert_eq!(config.datasets.len(), 1);
    assert!(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("demo/data/disability_registry.xlsx")
            .is_file(),
        "disability registry demo workbook should be committed"
    );
    let spdci = config
        .standards
        .spdci
        .as_ref()
        .expect("demo should configure SP DCI");
    let disability_registry = spdci
        .disability_registry
        .as_ref()
        .expect("demo should configure the disability registry");
    assert_eq!(
        disability_registry.query_key,
        "personal_details.member_identifier"
    );
}

#[tokio::test]
async fn sync_disabled_returns_spdci_status_from_entity_row() {
    let server = server().await;
    let response = server
        .post("/dci/dr/registry/sync/disabled")
        .json(&json!({
            "header": {
                "message_id": "msg-1",
                "action": "search"
            },
            "message": {
                "transaction_id": "txn-1",
                "disabled_criteria": {
                    "query": {
                        "member.member_identifier": {
                            "eq": "ABC451123"
                        }
                    }
                }
            }
        }))
        .await;
    response.assert_status(StatusCode::OK);
    let body: Value = response.json();
    assert_eq!(body["header"]["status"], "succ");
    assert_eq!(body["message"]["transaction_id"], "txn-1");
    assert_eq!(
        body["message"]["disabled_response"][0]["disabled_status"],
        "yes"
    );
}

#[tokio::test]
async fn sync_search_returns_spdci_search_response_from_configured_registry() {
    let server = server().await;
    let response = server
        .post("/dci/dr/registry/sync/search")
        .json(&json!({
            "header": {
                "message_id": "msg-search-1",
                "action": "search"
            },
            "message": {
                "transaction_id": "txn-search-1",
                "search_request": [{
                    "reference_id": "ref-search-1",
                    "timestamp": "2026-01-01T00:00:00Z",
                    "search_criteria": {
                        "query_type": "idtype-value",
                        "query": {
                            "type": "DISABILITY_ID",
                            "value": "ABC451123"
                        }
                    }
                }]
            }
        }))
        .await;
    response.assert_status(StatusCode::OK);
    let body: Value = response.json();
    assert_eq!(body["header"]["status"], "succ");
    assert_eq!(body["message"]["transaction_id"], "txn-search-1");
    assert_eq!(
        body["message"]["search_response"][0]["data"]["reg_record_type"],
        "spdci-extensions-dci:DisabledPerson"
    );
    assert_eq!(
        body["message"]["search_response"][0]["data"]["reg_records"]["id"],
        "ABC451123"
    );
}

#[tokio::test]
async fn sync_search_supports_named_dci_registry_path() {
    let server = server().await;
    let response = server
        .post("/dci/dr/registry/sync/search")
        .json(&json!({
            "message": {
                "transaction_id": "txn-search-2",
                "search_request": [{
                    "reference_id": "ref-search-2",
                    "timestamp": "2026-01-01T00:00:00Z",
                    "search_criteria": {
                        "query_type": "expression",
                        "query": {
                            "type": "ns:org:QueryType:expression",
                            "value": {
                                "expression": {
                                    "query": {
                                        "disability_status": { "$eq": "Approved" }
                                    }
                                }
                            }
                        }
                    }
                }]
            }
        }))
        .await;
    response.assert_status(StatusCode::OK);
    let body: Value = response.json();
    assert_eq!(
        body["message"]["search_response"][0]["data"]["reg_records"]["impairment_type"],
        "mobility"
    );
}

#[tokio::test]
async fn sync_disability_details_returns_entity_record() {
    let server = server().await;
    let response = server
        .post("/dci/dr/registry/sync/get-disability-details")
        .json(&json!({
            "message": {
                "transaction_id": "txn-2",
                "disabled_criteria": {
                    "query": {
                        "member": {
                            "member_identifier": {
                                "eq": "ABC451123"
                            }
                        }
                    }
                }
            }
        }))
        .await;
    response.assert_status(StatusCode::OK);
    let body: Value = response.json();
    assert_eq!(body["header"]["status"], "succ");
    assert_eq!(
        body["message"]["search_response"][0]["data"]["reg_records"][0]["impairment_type"],
        "mobility"
    );
}
