// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "spdci-api-standards")]

//! Focused validation coverage for SP DCI registry response mapping config.

use std::path::{Path, PathBuf};

use registry_platform_testing::MockHttpUpstream;
use registry_relay::config;
use registry_relay::spdci::{build_spdci_response_mapper, SpdciResponseMappingError};
use serde_json::{json, Value};
use tempfile::TempDir;

fn yaml_path(path: &Path) -> String {
    serde_json::to_string(&path.display().to_string()).expect("path serializes")
}

fn write_config(tmp: &TempDir, registry_extra: &str) -> PathBuf {
    let path = tmp.path().join("spdci.yaml");
    let body = format!(
        r#"
server:
  bind: 127.0.0.1:0

catalog:
  title: Test
  base_url: https://gw.example
  publisher: Test

deployment:
  profile: local

vocabularies: {{}}

auth:
  mode: api_key
  api_keys: []

audit:
  sink: stdout
  format: jsonl

standards:
  spdci:
    registries:
      dr:
        dataset: disability_registry
        entity: disabled_person
        registry_type: ns:org:RegistryType:DR
        record_type: spdci-extensions-dci:DisabledPerson
        identifiers:
          DISABILITY_ID: id
        expression_fields:
          disability_status: disability_status
{registry_extra}

datasets:
  - id: disability_registry
    title: Disability Registry
    description: Synthetic registry
    owner: Test
    sensitivity: public
    access_rights: restricted
    update_frequency: monthly
    defaults:
      refresh:
        mode: manual
    tables:
      - id: disabled_people_table
        source:
          type: file
          path: fixtures/disability_registry.xlsx
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
            - name: full_name
              type: string
              nullable: true
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
          - name: full_name
          - name: impairment_type
        access:
          metadata_scope: disability_registry:metadata
          aggregate_scope: disability_registry:aggregate
          read_scope: disability_registry:rows
          evidence_verification_scope: disability_registry:evidence_verification
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
    );
    std::fs::write(&path, body).expect("write config");
    path
}

#[track_caller]
fn assert_config_code(path: &Path, expected_code: &str) {
    let err = config::load(path).expect_err("config must fail");
    assert_eq!(err.code(), expected_code);
}

/// Writes `schema` as the single registry's `response_schema_path` document and
/// returns the config path.
fn write_schema_config(tmp: &TempDir, schema: &Value) -> PathBuf {
    let schema_path = tmp.path().join("response.schema.json");
    std::fs::write(
        &schema_path,
        serde_json::to_string(schema).expect("schema serializes"),
    )
    .expect("write schema");
    write_config(
        tmp,
        &format!(
            r#"        response_schema_path: {}
"#,
            yaml_path(&schema_path)
        ),
    )
}

/// Loads a config carrying `schema` and runs `record` through the response
/// mapper, which is the path that applies a compiled response schema.
fn project_under_schema(
    tmp: &TempDir,
    schema: &Value,
    record: Value,
) -> Result<Value, SpdciResponseMappingError> {
    let config_path = write_schema_config(tmp, schema);
    let cfg = config::load(&config_path).expect("config loads");
    let mapper = build_spdci_response_mapper(&cfg)
        .expect("response mapper builds")
        .expect("response mapper is installed");
    let registry = &cfg
        .standards
        .spdci
        .as_ref()
        .expect("spdci config")
        .registries["dr"];
    mapper.project_record("dr", registry, record)
}

#[test]
fn spdci_response_fields_and_schema_config_load() {
    let tmp = TempDir::new().expect("tempdir");
    let schema_path = tmp.path().join("response.schema.json");
    std::fs::write(
        &schema_path,
        r#"{"type":"object","properties":{"personal_details":{"type":"object"}}}"#,
    )
    .expect("write schema");
    let config_path = write_config(
        &tmp,
        &format!(
            r#"        response_fields:
          id: id
          personal_details.name: full_name
        response_schema_path: {}
"#,
            yaml_path(&schema_path)
        ),
    );

    let cfg = config::load(&config_path).expect("config loads");
    let registry = &cfg
        .standards
        .spdci
        .as_ref()
        .expect("spdci config")
        .registries["dr"];
    assert_eq!(
        registry.response_fields.get("personal_details.name"),
        Some(&"full_name".to_string())
    );
    assert_eq!(
        registry.response_schema_path.as_deref(),
        Some(schema_path.as_path())
    );
}

#[test]
fn spdci_response_fields_reject_unknown_source_field() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config(
        &tmp,
        r#"        response_fields:
          personal_details.name: missing_field
"#,
    );

    assert_config_code(&config_path, "config.validation_error");
}

#[test]
fn spdci_response_schema_path_rejects_invalid_json() {
    let tmp = TempDir::new().expect("tempdir");
    let schema_path = tmp.path().join("invalid.schema.json");
    std::fs::write(&schema_path, "{not json").expect("write schema");
    let config_path = write_config(
        &tmp,
        &format!(
            r#"        response_schema_path: {}
"#,
            yaml_path(&schema_path)
        ),
    );

    assert_config_code(&config_path, "config.validation_error");
}

#[test]
#[cfg(not(feature = "standards-cel-mapping"))]
fn spdci_response_mapping_path_requires_standards_cel_mapping_feature() {
    let tmp = TempDir::new().expect("tempdir");
    let mapping_path = tmp.path().join("missing.yaml");
    let config_path = write_config(
        &tmp,
        &format!(
            r#"        response_mapping_path: {}
"#,
            yaml_path(&mapping_path)
        ),
    );

    assert_config_code(&config_path, "spdci.config.mapping_feature_disabled");
}

#[test]
#[cfg(feature = "standards-cel-mapping")]
fn spdci_response_mapping_path_rejects_missing_file() {
    let tmp = TempDir::new().expect("tempdir");
    let mapping_path = tmp.path().join("missing.yaml");
    let config_path = write_config(
        &tmp,
        &format!(
            r#"        response_mapping_path: {}
"#,
            yaml_path(&mapping_path)
        ),
    );

    assert_config_code(&config_path, "config.validation_error");
}

#[test]
fn spdci_response_schema_path_rejects_an_uncompilable_schema() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_schema_config(&tmp, &json!({"type": "objekt"}));

    assert_config_code(&config_path, "config.validation_error");
}

#[tokio::test]
async fn spdci_response_schema_never_requests_a_remote_reference() {
    let upstream = MockHttpUpstream::start().await;
    // The served document accepts the record below, so a resolved reference
    // would let the record through.
    upstream
        .expect("GET", "/person.schema.json")
        .respond_json(200, json!({"type": "object", "required": ["id"]}))
        .await;
    let schema = json!({
        "type": "object",
        "properties": {
            "person": {"$ref": format!("{}/person.schema.json", upstream.url())}
        }
    });

    let tmp = TempDir::new().expect("tempdir");
    let result = project_under_schema(&tmp, &schema, json!({"person": {"id": "p-1"}}));

    assert!(
        matches!(
            result,
            Err(SpdciResponseMappingError::SchemaValidationFailed)
        ),
        "an unresolvable remote reference must refuse every record, got {result:?}"
    );
    assert!(
        upstream
            .wiremock_server()
            .received_requests()
            .await
            .expect("upstream records requests")
            .is_empty(),
        "neither config validation nor response validation may request a remote schema"
    );
}

#[test]
fn spdci_response_schema_never_reads_a_file_reference() {
    let tmp = TempDir::new().expect("tempdir");
    let referenced = tmp.path().join("person.schema.json");
    // The referenced document accepts the record below, so a resolved reference
    // would let the record through.
    std::fs::write(&referenced, r#"{"type":"object","required":["id"]}"#)
        .expect("write referenced schema");
    let schema = json!({
        "type": "object",
        "properties": {
            "person": {"$ref": format!("file://{}", referenced.display())}
        }
    });

    let result = project_under_schema(&tmp, &schema, json!({"person": {"id": "p-1"}}));

    assert!(
        matches!(
            result,
            Err(SpdciResponseMappingError::SchemaValidationFailed)
        ),
        "an unresolvable file reference must refuse every record, got {result:?}"
    );
}

#[test]
fn spdci_response_schema_resolves_internal_pointer_references() {
    let schema = json!({
        "type": "object",
        "properties": {"person": {"$ref": "#/definitions/person"}},
        "definitions": {"person": {"type": "object", "required": ["id"]}}
    });

    let tmp = TempDir::new().expect("tempdir");
    project_under_schema(&tmp, &schema, json!({"person": {"id": "p-1"}}))
        .expect("a record satisfying the referenced definition passes");
    project_under_schema(&tmp, &schema, json!({"person": {}}))
        .expect_err("the referenced definition is enforced");
}

#[test]
fn spdci_response_schema_enforces_draft_2020_12_keywords() {
    let schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {"codes": {"type": "array", "prefixItems": [{"type": "string"}]}}
    });

    let tmp = TempDir::new().expect("tempdir");
    project_under_schema(&tmp, &schema, json!({"codes": ["a"]}))
        .expect("a record matching the leading prefixItems entry passes");
    project_under_schema(&tmp, &schema, json!({"codes": [42]}))
        .expect_err("prefixItems is enforced rather than ignored as an unknown keyword");
}

#[test]
fn spdci_response_schema_does_not_assert_format_under_draft_2020_12() {
    let schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "type": "object",
        "properties": {"born_on": {"type": "string", "format": "date"}}
    });

    let tmp = TempDir::new().expect("tempdir");
    project_under_schema(&tmp, &schema, json!({"born_on": "not-a-date"}))
        .expect("format is an annotation under 2020-12");
}

#[test]
fn spdci_response_schema_asserts_format_under_draft_7() {
    let schema = json!({
        "$schema": "http://json-schema.org/draft-07/schema#",
        "type": "object",
        "properties": {"born_on": {"type": "string", "format": "date"}}
    });

    let tmp = TempDir::new().expect("tempdir");
    project_under_schema(&tmp, &schema, json!({"born_on": "2026-08-05"}))
        .expect("a record matching the declared format passes");
    project_under_schema(&tmp, &schema, json!({"born_on": "not-a-date"}))
        .expect_err("format is an assertion under draft 7");
}

#[test]
fn spdci_response_schema_falls_back_to_draft_7_for_an_uncarried_draft() {
    // 2019-09 is not carried, so this schema compiles under draft 7 and its
    // `format` becomes an assertion.
    let schema = json!({
        "$schema": "https://json-schema.org/draft/2019-09/schema",
        "type": "object",
        "properties": {"born_on": {"type": "string", "format": "date"}}
    });

    let tmp = TempDir::new().expect("tempdir");
    project_under_schema(&tmp, &schema, json!({"born_on": "not-a-date"}))
        .expect_err("an uncarried draft falls back to draft 7, which asserts format");
}
