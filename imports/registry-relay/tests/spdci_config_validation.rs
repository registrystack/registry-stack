// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "spdci-api-standards")]

//! Focused validation coverage for SP DCI registry response mapping config.

use std::path::{Path, PathBuf};

use registry_relay::config;
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
    sensitivity: personal
    access_rights: restricted
    update_frequency: monthly
    source:
      type: file
      path: fixtures/disability_registry.xlsx
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
          verify_scope: disability_registry:verify
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
