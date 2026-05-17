// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "spdci-api-standards")]

//! SP DCI Disability Registry adapter coverage.

#[cfg(feature = "standards-cel-mapping")]
use std::env;
#[cfg(feature = "standards-cel-mapping")]
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
use registry_relay::error::Error;
use registry_relay::ingest::{
    register_versioned_table, table_name, ReadinessSnapshot, ReadyResource,
};
use registry_relay::query::EntityQueryEngine;
use registry_relay::spdci::build_spdci_response_mapper;
use serde_json::{json, Value};
#[cfg(feature = "standards-cel-mapping")]
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::sync::watch;
use ulid::Ulid;

fn id<T: serde::de::DeserializeOwned>(value: &str) -> T {
    serde_json::from_str(&format!(r#""{value}""#)).expect("id deserializes")
}

#[cfg(feature = "standards-cel-mapping")]
fn make_fingerprint(plaintext: &[u8]) -> String {
    format!("sha256:{}", hex_lower(&Sha256::digest(plaintext)))
}

#[cfg(feature = "standards-cel-mapping")]
fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(feature = "standards-cel-mapping")]
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

#[derive(Debug)]
struct TestServerBuildError {
    code: &'static str,
    message: String,
}

impl From<Error> for TestServerBuildError {
    fn from(error: Error) -> Self {
        Self {
            code: error.code(),
            message: error.to_string(),
        }
    }
}

fn spdci_config(registry_extra: &str) -> String {
    format!(
        r#"
server:
  bind: 127.0.0.1:0

catalog:
  title: Test
  base_url: https://gw.example
  publisher: Test

vocabularies: {{}}

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
{registry_extra}

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
"#
    )
}

async fn try_server_with_registry_extra(
    registry_extra: &str,
) -> Result<TestServer, TestServerBuildError> {
    try_server_with_options(registry_extra, true).await
}

async fn try_server_without_response_mapper(
    registry_extra: &str,
) -> Result<TestServer, TestServerBuildError> {
    try_server_with_options(registry_extra, false).await
}

async fn try_server_with_options(
    registry_extra: &str,
    install_response_mapper: bool,
) -> Result<TestServer, TestServerBuildError> {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = tmp.path().join("spdci.yaml");
    std::fs::write(&config_path, spdci_config(registry_extra)).expect("write config");
    let config = Arc::new(config::load(&config_path)?);
    let response_mapper = build_spdci_response_mapper(&config)?.map(Arc::new);
    let registry = Arc::new(EntityRegistry::from_config(&config)?);
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
    let mut app = spdci_router::<()>()
        .layer(Extension(principal(&[
            "disability_registry:verify",
            "disability_registry:rows",
        ])))
        .layer(Extension(readiness))
        .layer(Extension(query))
        .layer(Extension(registry))
        .layer(Extension(config));
    if install_response_mapper {
        if let Some(response_mapper) = response_mapper {
            app = app.layer(Extension(response_mapper));
        }
    }
    Ok(TestServer::new(app))
}

async fn server() -> TestServer {
    try_server_with_registry_extra("")
        .await
        .expect("test server builds")
}

fn response_mapping_runtime_unavailable(error: &TestServerBuildError) -> bool {
    error.code == "spdci.config.mapping_feature_disabled"
        || (error.code == "config.parse_error"
            && (error.message.contains("response_fields")
                || error.message.contains("response_mapping_path")
                || error.message.contains("response_schema_path")))
}

#[cfg(feature = "standards-cel-mapping")]
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

fn valid_header(message_id: &str) -> Value {
    json!({
        "message_id": message_id,
        "message_ts": "2026-01-01T00:00:00Z",
        "action": "search",
        "sender_id": "spp.example.org",
        "total_count": 1,
    })
}

#[tokio::test]
async fn sync_disabled_returns_spdci_status_from_entity_row() {
    let server = server().await;
    let response = server
        .post("/dci/dr/registry/sync/disabled")
        .json(&json!({
            "header": valid_header("msg-1"),
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
async fn sync_search_rejects_request_without_header() {
    let server = server().await;
    let response = server
        .post("/dci/dr/registry/sync/search")
        .json(&json!({
            "message": {
                "transaction_id": "txn-no-header",
                "search_request": [{
                    "reference_id": "ref-no-header",
                    "timestamp": "2026-01-01T00:00:00Z",
                    "search_criteria": {
                        "query_type": "idtype-value",
                        "query": {"type": "DISABILITY_ID", "value": "ABC451123"}
                    }
                }]
            }
        }))
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = response.json();
    assert_eq!(body["code"], "spdci.request.invalid_header");
}

#[tokio::test]
async fn sync_search_rejects_request_with_incomplete_header() {
    let server = server().await;
    let response = server
        .post("/dci/dr/registry/sync/search")
        .json(&json!({
            "header": {"message_id": "msg-only"},
            "message": {
                "transaction_id": "txn-incomplete",
                "search_request": [{
                    "reference_id": "ref-incomplete",
                    "timestamp": "2026-01-01T00:00:00Z",
                    "search_criteria": {
                        "query_type": "idtype-value",
                        "query": {"type": "DISABILITY_ID", "value": "ABC451123"}
                    }
                }]
            }
        }))
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = response.json();
    assert_eq!(body["code"], "spdci.request.invalid_header");
}

#[tokio::test]
async fn sync_search_rejects_request_without_message() {
    let server = server().await;
    let response = server
        .post("/dci/dr/registry/sync/search")
        .json(&json!({
            "header": valid_header("msg-no-message"),
        }))
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = response.json();
    assert_eq!(body["code"], "spdci.request.invalid_message");
}

#[tokio::test]
async fn sync_search_rejects_request_without_transaction_id() {
    let server = server().await;
    let response = server
        .post("/dci/dr/registry/sync/search")
        .json(&json!({
            "header": valid_header("msg-no-txn"),
            "message": {
                "search_request": [{
                    "reference_id": "ref-no-txn",
                    "timestamp": "2026-01-01T00:00:00Z",
                    "search_criteria": {
                        "query_type": "idtype-value",
                        "query": {"type": "DISABILITY_ID", "value": "ABC451123"}
                    }
                }]
            }
        }))
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = response.json();
    assert_eq!(body["code"], "spdci.request.missing_transaction_id");
}

#[tokio::test]
async fn sync_disabled_rejects_request_without_transaction_id() {
    let server = server().await;
    let response = server
        .post("/dci/dr/registry/sync/disabled")
        .json(&json!({
            "header": valid_header("msg-disabled-no-txn"),
            "message": {
                "disabled_criteria": {
                    "query": {"member.member_identifier": {"eq": "ABC451123"}}
                }
            }
        }))
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = response.json();
    assert_eq!(body["code"], "spdci.request.missing_transaction_id");
}

#[tokio::test]
async fn sync_search_returns_spdci_search_response_from_configured_registry() {
    let server = server().await;
    let response = server
        .post("/dci/dr/registry/sync/search")
        .json(&json!({
            "header": valid_header("msg-search-1"),
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
    // header.total_count must reflect the actual record count, not a constant.
    assert_eq!(body["header"]["total_count"], 1);
    assert_eq!(body["message"]["transaction_id"], "txn-search-1");
    assert_eq!(
        body["message"]["search_response"][0]["data"]["reg_record_type"],
        "spdci-extensions-dci:DisabledPerson"
    );
    // reg_records is always a JSON array, regardless of registry.
    assert_eq!(
        body["message"]["search_response"][0]["data"]["reg_records"][0]["id"],
        "ABC451123"
    );
}

#[tokio::test]
async fn sync_search_supports_named_dci_registry_path() {
    let server = server().await;
    let response = server
        .post("/dci/dr/registry/sync/search")
        .json(&json!({
            "header": valid_header("msg-search-2"),
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
        body["message"]["search_response"][0]["data"]["reg_records"][0]["impairment_type"],
        "mobility"
    );
}

#[tokio::test]
async fn sync_search_rejects_unsupported_expression_operator() {
    let server = server().await;
    let response = server
        .post("/dci/dr/registry/sync/search")
        .json(&json!({
            "header": valid_header("msg-search-unsupported-expression"),
            "message": {
                "transaction_id": "txn-search-unsupported-expression",
                "search_request": [{
                    "reference_id": "ref-search-unsupported-expression",
                    "timestamp": "2026-01-01T00:00:00Z",
                    "search_criteria": {
                        "query_type": "expression",
                        "query": {
                            "type": "ns:org:QueryType:expression",
                            "value": {
                                "expression": {
                                    "query": {
                                        "disability_status": { "$ne": "Approved" }
                                    }
                                }
                            }
                        }
                    }
                }]
            }
        }))
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = response.json();
    assert_eq!(body["code"], "filter.unsupported_op");
}

#[tokio::test]
async fn sync_search_rejects_unsupported_predicate_operator() {
    let server = server().await;
    let response = server
        .post("/dci/dr/registry/sync/search")
        .json(&json!({
            "header": valid_header("msg-search-unsupported-predicate"),
            "message": {
                "transaction_id": "txn-search-unsupported-predicate",
                "search_request": [{
                    "reference_id": "ref-search-unsupported-predicate",
                    "timestamp": "2026-01-01T00:00:00Z",
                    "search_criteria": {
                        "query_type": "predicate",
                        "query": [{
                            "seq_num": 1,
                            "expression1": {
                                "attribute_name": "disability_status",
                                "operator": "gt",
                                "attribute_value": "Approved"
                            }
                        }]
                    }
                }]
            }
        }))
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = response.json();
    assert_eq!(body["code"], "filter.unsupported_op");
}

#[tokio::test]
async fn sync_search_projects_response_fields_into_nested_reg_record_when_available() {
    let server = match try_server_with_registry_extra(
        r#"        response_fields:
          personal_details.member_identifier: id
          disability_details.impairment_type: impairment_type
"#,
    )
    .await
    {
        Ok(server) => server,
        Err(error) if response_mapping_runtime_unavailable(&error) => return,
        Err(error) => panic!("test server should build: {error:?}"),
    };

    let response = server
        .post("/dci/dr/registry/sync/search")
        .json(&json!({
            "header": valid_header("msg-search-response-fields"),
            "message": {
                "transaction_id": "txn-search-response-fields",
                "search_request": [{
                    "reference_id": "ref-search-response-fields",
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
    let record = &body["message"]["search_response"][0]["data"]["reg_records"][0];
    assert_eq!(record["personal_details"]["member_identifier"], "ABC451123");
    assert_eq!(record["disability_details"]["impairment_type"], "mobility");
    assert!(
        record.get("impairment_type").is_none(),
        "response_fields should project the configured SP DCI shape, not the raw entity row"
    );
}

#[cfg(feature = "standards-cel-mapping")]
#[tokio::test]
async fn sync_search_uses_cel_mapping_when_configured() {
    let tmp = TempDir::new().expect("tempdir");
    let mapping_path = tmp.path().join("dr-mapping.yaml");
    std::fs::write(
        &mapping_path,
        r#"
version: "0.1"
name: spdci-dr
records:
  disabled_person:
    fields:
      personal_details: '{"member_identifier": source.id}'
      disability_details: '{"impairment_type": source.impairment_type, "status": source.disability_status}'
"#,
    )
    .expect("write mapping");
    let extra = format!(
        r#"        response_fields:
          ignored.by.mapping: id
        response_mapping_path: {}
"#,
        serde_json::to_string(&mapping_path.display().to_string()).expect("path serializes")
    );
    let server = try_server_with_registry_extra(&extra)
        .await
        .expect("test server should build");

    let response = server
        .post("/dci/dr/registry/sync/search")
        .json(&json!({
            "header": valid_header("msg-search-cel-mapping"),
            "message": {
                "transaction_id": "txn-search-cel-mapping",
                "search_request": [{
                    "reference_id": "ref-search-cel-mapping",
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
    let record = &body["message"]["search_response"][0]["data"]["reg_records"][0];
    assert_eq!(record["personal_details"]["member_identifier"], "ABC451123");
    assert_eq!(record["disability_details"]["impairment_type"], "mobility");
    assert!(
        record.get("ignored").is_none(),
        "CEL mapping should win over direct response_fields"
    );
}

#[tokio::test]
async fn sync_search_returns_scrubbed_server_error_for_invalid_mapped_output_when_available() {
    let tmp = TempDir::new().expect("tempdir");
    let schema_path = tmp.path().join("mapped-record.schema.json");
    std::fs::write(
        &schema_path,
        r#"{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "type": "object",
  "required": ["required_by_schema"],
  "properties": {
    "required_by_schema": { "type": "string" }
  }
}"#,
    )
    .expect("write schema");
    let extra = format!(
        r#"        response_fields:
          personal_details.member_identifier: id
        response_schema_path: "{}"
"#,
        schema_path.display()
    );
    let server = match try_server_with_registry_extra(&extra).await {
        Ok(server) => server,
        Err(error) if response_mapping_runtime_unavailable(&error) => return,
        Err(error) => panic!("test server should build: {error:?}"),
    };

    let response = server
        .post("/dci/dr/registry/sync/search")
        .json(&json!({
            "header": valid_header("msg-search-invalid-mapping-output"),
            "message": {
                "transaction_id": "txn-search-invalid-mapping-output",
                "search_request": [{
                    "reference_id": "ref-search-invalid-mapping-output",
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
    assert!(
        response.status_code().is_server_error(),
        "invalid mapped output should be reported as a server-side runtime failure"
    );
    let body: Value = response.json();
    assert!(
        !body.to_string().contains("ABC451123"),
        "mapped-output failures must not leak row values"
    );
}

#[tokio::test]
async fn sync_disability_details_returns_entity_record() {
    let server = server().await;
    let response = server
        .post("/dci/dr/registry/sync/get-disability-details")
        .json(&json!({
            "header": valid_header("msg-details-1"),
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
    // header.total_count must reflect the actual row count returned.
    assert_eq!(body["header"]["total_count"], 1);
    assert_eq!(
        body["message"]["search_response"][0]["data"]["reg_records"][0]["impairment_type"],
        "mobility"
    );
}

#[tokio::test]
async fn sync_disability_details_passes_response_mapping_when_configured() {
    let server = match try_server_with_registry_extra(
        r#"        response_fields:
          personal_details.member_identifier: id
          disability_details.impairment_type: impairment_type
"#,
    )
    .await
    {
        Ok(server) => server,
        Err(error) if response_mapping_runtime_unavailable(&error) => return,
        Err(error) => panic!("test server should build: {error:?}"),
    };
    let response = server
        .post("/dci/dr/registry/sync/get-disability-details")
        .json(&json!({
            "header": valid_header("msg-details-mapping"),
            "message": {
                "transaction_id": "txn-details-mapping",
                "disabled_criteria": {
                    "query": {
                        "member": {
                            "member_identifier": {"eq": "ABC451123"}
                        }
                    }
                }
            }
        }))
        .await;
    response.assert_status(StatusCode::OK);
    let body: Value = response.json();
    let record = &body["message"]["search_response"][0]["data"]["reg_records"][0];
    assert_eq!(record["personal_details"]["member_identifier"], "ABC451123");
    assert_eq!(record["disability_details"]["impairment_type"], "mobility");
    assert!(
        record.get("impairment_type").is_none(),
        "DR detail handler should apply response_fields, not return raw entity rows"
    );
}

#[tokio::test]
async fn sync_search_surfaces_mapper_unavailable_when_mapping_configured_but_extension_missing() {
    let server = match try_server_without_response_mapper(
        r#"        response_fields:
          personal_details.member_identifier: id
"#,
    )
    .await
    {
        Ok(server) => server,
        Err(error) if response_mapping_runtime_unavailable(&error) => return,
        Err(error) => panic!("test server should build: {error:?}"),
    };
    let response = server
        .post("/dci/dr/registry/sync/search")
        .json(&json!({
            "header": valid_header("msg-mapper-missing"),
            "message": {
                "transaction_id": "txn-mapper-missing",
                "search_request": [{
                    "reference_id": "ref-mapper-missing",
                    "timestamp": "2026-01-01T00:00:00Z",
                    "search_criteria": {
                        "query_type": "idtype-value",
                        "query": {"type": "DISABILITY_ID", "value": "ABC451123"}
                    }
                }]
            }
        }))
        .await;
    assert_eq!(response.status_code(), StatusCode::INTERNAL_SERVER_ERROR);
    let body: Value = response.json();
    assert_eq!(body["code"], "spdci.mapper.unavailable");
    assert!(
        !body.to_string().contains("ABC451123"),
        "mapper-unavailable failures must not leak row data"
    );
}

#[tokio::test]
async fn unknown_named_registry_returns_404_on_all_dr_endpoints() {
    let server = server().await;
    for path in [
        "/dci/no-such/registry/sync/search",
        "/dci/no-such/registry/sync/disabled",
        "/dci/no-such/registry/sync/get-disability-details",
        "/dci/no-such/registry/sync/get-disability-support",
    ] {
        let response = server
            .post(path)
            .json(&json!({
                "header": valid_header("msg-404"),
                "message": {
                    "transaction_id": "txn-404",
                    "disabled_criteria": {
                        "query": {"member.member_identifier": {"eq": "ABC451123"}}
                    },
                    "search_request": [{
                        "reference_id": "ref-404",
                        "timestamp": "2026-01-01T00:00:00Z",
                        "search_criteria": {
                            "query_type": "idtype-value",
                            "query": {"type": "DISABILITY_ID", "value": "ABC451123"}
                        }
                    }]
                }
            }))
            .await;
        assert_eq!(
            response.status_code(),
            StatusCode::NOT_FOUND,
            "{path} should 404 for an unknown registry binding"
        );
    }
}

// ---------------------------------------------------------------------------
// Full production middleware stack coverage (finding 6).
//
// These tests build the SP DCI router through `build_app_with_entity_query`
// (the production assembly used by `main.rs`), so auth, audit, body limits,
// request-id, timeout, and CORS all run in front of the handler. The
// `spdci_router::<()>()`-only tests above do not exercise that wiring; a
// refactor that silently dropped SP DCI from `merge_spdci_routes` or moved
// it outside the auth layer would slip past those.
// ---------------------------------------------------------------------------

mod full_stack {
    use super::{id, spdci_config, valid_header};
    use std::sync::Arc;

    use axum::http::StatusCode;
    use axum_test::TestServer;
    use datafusion::arrow::array::StringArray;
    use datafusion::arrow::datatypes::{DataType, Field, Schema};
    use datafusion::arrow::record_batch::RecordBatch;
    use datafusion::datasource::MemTable;
    use datafusion::execution::context::SessionContext;
    use registry_relay::audit::{AuditSink, InMemorySink};
    use registry_relay::auth::api_key::{ApiKeyAuth, ApiKeyEntry};
    use registry_relay::auth::ScopeSet;
    use registry_relay::config::{self, DatasetId, ResourceId};
    use registry_relay::entity::EntityRegistry;
    use registry_relay::ingest::{
        register_versioned_table, table_name, ReadinessSnapshot, ReadyResource,
    };
    use registry_relay::query::{AggregateQueryEngine, EntityQueryEngine};
    use registry_relay::server::build_app_with_entity_query_and_provenance;
    use registry_relay::spdci::build_spdci_response_mapper;
    use serde_json::{json, Value};
    use sha2::{Digest, Sha256};
    use tempfile::TempDir;
    use tokio::sync::watch;
    use ulid::Ulid;

    /// Raw bearer token presented by tests with valid credentials. The
    /// `ApiKeyAuth` keyring stores its sha256 fingerprint.
    const VALID_KEY: &str = "spdci-full-stack-integration-test-key";
    const CLIENT_ID: &str = "spdci-full-stack-client";

    fn hex_lower(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0x0f) as usize] as char);
        }
        out
    }

    fn fingerprint(raw: &str) -> String {
        format!("sha256:{}", hex_lower(&Sha256::digest(raw.as_bytes())))
    }

    struct FullStackHarness {
        server: TestServer,
        audit_sink: InMemorySink,
    }

    /// Build the production application (`build_app_with_entity_query_and_provenance`)
    /// with `scopes` minted into the keyring for `VALID_KEY`. The SP DCI
    /// disability registry under the `dr` registry name is wired exactly
    /// like in production: data is registered through
    /// `register_versioned_table`, the response mapper extension is
    /// installed when the config asks for it, and an `InMemorySink`
    /// captures one audit record per request.
    async fn build_harness(scopes: &[&str]) -> FullStackHarness {
        let tmp = TempDir::new().expect("tempdir");
        let config_path = tmp.path().join("spdci.yaml");
        std::fs::write(&config_path, spdci_config("")).expect("write config");
        let config = Arc::new(config::load(&config_path).expect("config loads"));

        // Mirror `main.rs`: build the response mapper if the config asks
        // for one, then install it as an extension below.
        let response_mapper = build_spdci_response_mapper(&config)
            .expect("response mapper builds")
            .map(Arc::new);

        let registry = Arc::new(EntityRegistry::from_config(&config).expect("registry"));
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
        let (_readiness_tx, readiness) = watch::channel(snapshot);

        let query = Arc::new(EntityQueryEngine::new(
            Arc::clone(&ctx),
            Arc::clone(&registry),
        ));
        let aggregate_query = Arc::new(AggregateQueryEngine::new(
            Arc::clone(&ctx),
            Arc::clone(&registry),
            Arc::clone(&config),
        ));

        let entry = ApiKeyEntry::new(
            CLIENT_ID.to_string(),
            scopes.iter().copied().collect::<ScopeSet>(),
            fingerprint(VALID_KEY),
        )
        .expect("fingerprint parses");
        let auth = Arc::new(ApiKeyAuth::new(vec![entry]));

        let audit_sink = InMemorySink::new();
        let sink_arc: Arc<dyn AuditSink> = Arc::new(audit_sink.clone());

        // Production assembly. `provenance` stays `None` because the SP
        // DCI surface does not interact with VC issuance.
        let mut app = build_app_with_entity_query_and_provenance(
            Arc::clone(&config),
            auth,
            sink_arc,
            readiness,
            registry,
            query,
            aggregate_query,
            None,
        );
        // Mirror the `if let Some(...) { app.layer(...) }` block in
        // `main.rs`: when the config configures response mapping, the
        // extension must be installed before the request reaches the
        // SP DCI handlers. The current SP DCI config under test does
        // not configure mapping, so this is a no-op, but matching the
        // production wiring keeps the harness honest if mapping is
        // added to `spdci_config` later.
        if let Some(mapper) = response_mapper {
            app = app.layer(axum::Extension(mapper));
        }

        FullStackHarness {
            server: TestServer::new(app),
            audit_sink,
        }
    }

    /// Find the most recent audit record for the given path. Panics if
    /// none was emitted; the audit layer is supposed to emit exactly one
    /// record per request, so a missing record means the layer never ran
    /// for that request (and that is the load-bearing assertion).
    fn audit_record_for(sink: &InMemorySink, path: &str) -> Value {
        let lines = sink.snapshot();
        let line = lines
            .iter()
            .rev()
            .find(|line| {
                serde_json::from_str::<Value>(line)
                    .ok()
                    .and_then(|v| v["path"].as_str().map(|p| p == path))
                    .unwrap_or(false)
            })
            .unwrap_or_else(|| panic!("no audit record for path {path}; got {lines:?}"));
        serde_json::from_str(line).expect("audit line is JSON")
    }

    fn search_body() -> Value {
        json!({
            "header": valid_header("msg-full-stack-search"),
            "message": {
                "transaction_id": "txn-full-stack-search",
                "search_request": [{
                    "reference_id": "ref-full-stack-search",
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
        })
    }

    /// Unauthenticated POST to `/dci/{registry}/registry/sync/search`
    /// must surface the auth wire contract (`auth.missing_credential` /
    /// 401) and never reach the SP DCI handler. A refactor that mounted
    /// SP DCI outside the auth layer would silently regress this.
    #[tokio::test]
    async fn search_without_authorization_returns_401() {
        let harness = build_harness(&["disability_registry:rows"]).await;

        let response = harness
            .server
            .post("/dci/dr/registry/sync/search")
            .json(&search_body())
            .await;

        assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response.header("content-type"),
            "application/problem+json",
            "auth failures must use RFC 9457 problem details"
        );
        let body: Value = response.json();
        assert_eq!(body["code"], "auth.missing_credential");
        // The bearer credential was never presented, but the audit
        // record must still land with the auth-error code so security
        // operators can see the unauthenticated probe. This also
        // double-checks that the audit layer wraps SP DCI routes.
        let record = audit_record_for(&harness.audit_sink, "/dci/dr/registry/sync/search");
        assert_eq!(record["status_code"], 401);
        assert_eq!(record["error_code"], "auth.missing_credential");
        assert_eq!(record["api_key_id"], Value::Null);
    }

    /// Authenticated POST with a key that lacks the entity's `read_scope`
    /// must be rejected with `auth.scope_denied` / 403 by the SP DCI
    /// handler. The handler delegates to `require_scope` and the audit
    /// middleware records the taxonomy code. The `disability_registry:rows`
    /// scope is what `route.entity.access.read_scope` resolves to for the
    /// configured DR entity.
    #[tokio::test]
    async fn search_with_wrong_scope_returns_403() {
        // Issue a key with a scope that is real but not the read scope
        // the handler enforces. Auth admits the request; the handler
        // rejects on scope.
        let harness = build_harness(&["disability_registry:metadata"]).await;

        let response = harness
            .server
            .post("/dci/dr/registry/sync/search")
            .add_header("authorization", format!("Bearer {VALID_KEY}"))
            .json(&search_body())
            .await;

        assert_eq!(response.status_code(), StatusCode::FORBIDDEN);
        let body: Value = response.json();
        assert_eq!(body["code"], "auth.scope_denied");
        assert!(
            !body.to_string().contains(VALID_KEY),
            "scope-denied response must not echo the raw credential"
        );

        let record = audit_record_for(&harness.audit_sink, "/dci/dr/registry/sync/search");
        assert_eq!(record["status_code"], 403);
        assert_eq!(record["error_code"], "auth.scope_denied");
        assert_eq!(record["api_key_id"], CLIENT_ID);
    }

    /// Authenticated POST with the correct read scope must reach the SP
    /// DCI handler and emit a 200 with an audit record whose
    /// `dataset_id`/`entity_name`/`table_id` come from the SP DCI
    /// `AuditContextExt` the handler installs on the response.
    #[tokio::test]
    async fn search_with_correct_scope_returns_200_and_audits_dataset_context() {
        let harness = build_harness(&["disability_registry:rows"]).await;

        let response = harness
            .server
            .post("/dci/dr/registry/sync/search")
            .add_header("authorization", format!("Bearer {VALID_KEY}"))
            .json(&search_body())
            .await;

        assert_eq!(response.status_code(), StatusCode::OK);
        let body: Value = response.json();
        assert_eq!(body["header"]["status"], "succ");
        assert_eq!(body["message"]["transaction_id"], "txn-full-stack-search");

        let record = audit_record_for(&harness.audit_sink, "/dci/dr/registry/sync/search");
        assert_eq!(record["status_code"], 200);
        assert_eq!(record["api_key_id"], CLIENT_ID);
        assert_eq!(record["auth_mode"], "api_key");
        // The SP DCI handlers attach `AuditContextExt` so the audit
        // layer can record which dataset and entity served the row.
        assert_eq!(record["dataset_id"], "disability_registry");
        assert_eq!(record["entity_name"], "disabled_person");
        assert_eq!(record["table_id"], "disabled_people_table");
        assert_eq!(record["row_count"], 1);
        assert!(
            record["error_code"].is_null(),
            "successful request must not record an error code"
        );
    }

    /// Authenticated POST with the correct scope but an invalid request
    /// envelope must still attach the SP DCI audit context (dataset /
    /// entity / table) on the error response. This is the regression
    /// guard for finding 3: the response mapper attached the audit
    /// context only on the success path before the fix; the fix moved
    /// it onto the error path too. Without that fix, this record's
    /// `dataset_id` would be null even though the route is bound to the
    /// disability registry.
    #[tokio::test]
    async fn search_with_invalid_envelope_records_audit_context_on_error_path() {
        let harness = build_harness(&["disability_registry:rows"]).await;

        // Header is present but missing required fields, so the SP DCI
        // envelope validator returns `spdci.request.invalid_header`.
        let response = harness
            .server
            .post("/dci/dr/registry/sync/search")
            .add_header("authorization", format!("Bearer {VALID_KEY}"))
            .json(&json!({
                "header": {"message_id": "msg-only"},
                "message": {
                    "transaction_id": "txn-invalid-envelope",
                    "search_request": [{
                        "reference_id": "ref-invalid-envelope",
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
        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
        let body: Value = response.json();
        assert_eq!(body["code"], "spdci.request.invalid_header");

        let record = audit_record_for(&harness.audit_sink, "/dci/dr/registry/sync/search");
        assert_eq!(record["status_code"], 400);
        assert_eq!(record["error_code"], "spdci.request.invalid_header");
        assert_eq!(record["api_key_id"], CLIENT_ID);
        // Finding 3 regression guard: audit context must be present on
        // the error path, not only on the 200 path.
        assert_eq!(
            record["dataset_id"], "disability_registry",
            "audit context (dataset_id) must be attached on the error response path"
        );
        assert_eq!(
            record["entity_name"], "disabled_person",
            "audit context (entity_name) must be attached on the error response path"
        );
        assert_eq!(
            record["table_id"], "disabled_people_table",
            "audit context (table_id) must be attached on the error response path"
        );
    }

    /// Cross-route coverage: the DR detail endpoint goes through the
    /// same auth layer and emits the same audit context. This stops a
    /// future refactor from accidentally exempting one DR-specific
    /// route from auth or the audit context.
    #[tokio::test]
    async fn disability_details_without_authorization_returns_401_with_audit_record() {
        let harness = build_harness(&["disability_registry:rows"]).await;

        let response = harness
            .server
            .post("/dci/dr/registry/sync/get-disability-details")
            .json(&json!({
                "header": valid_header("msg-full-stack-details"),
                "message": {
                    "transaction_id": "txn-full-stack-details",
                    "disabled_criteria": {
                        "query": {
                            "member": {
                                "member_identifier": {"eq": "ABC451123"}
                            }
                        }
                    }
                }
            }))
            .await;

        assert_eq!(response.status_code(), StatusCode::UNAUTHORIZED);
        let body: Value = response.json();
        assert_eq!(body["code"], "auth.missing_credential");

        let record = audit_record_for(
            &harness.audit_sink,
            "/dci/dr/registry/sync/get-disability-details",
        );
        assert_eq!(record["status_code"], 401);
        assert_eq!(record["error_code"], "auth.missing_credential");
    }
}
