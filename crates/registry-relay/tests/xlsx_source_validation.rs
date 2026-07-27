// SPDX-License-Identifier: Apache-2.0
//! Composed coverage for Relay's no-cache XLSX source validation API.

mod support;

use std::fs;
use std::path::Path;

use registry_relay::config::ResourceConfig;
use registry_relay::error::IngestError;
use registry_relay::ingest::validate_xlsx_source_bytes;

fn fixture_bytes(name: &str) -> Vec<u8> {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures_xlsx")
        .join(name);
    fs::read(&path).unwrap_or_else(|error| panic!("could not read {name}: {error}"))
}

fn resource(schema: &str, data_range: Option<&str>) -> ResourceConfig {
    let data_range = data_range
        .map(|value| format!("      data_range: {value}\n"))
        .unwrap_or_default();
    serde_saphyr::from_str(&format!(
        r#"
id: workbook
source:
  type: file
  path: /runtime/workbook.xlsx
  format:
    xlsx:
      sheet: data
      header_row: 1
{data_range}primary_key: id
schema:
{schema}
"#
    ))
    .expect("resource config parses")
}

fn simple_resource() -> ResourceConfig {
    resource(
        r#"  strict: true
  fields:
    - name: id
      type: integer
      nullable: false
    - name: name
      type: string
      nullable: false
    - name: amount
      type: number
      nullable: false
    - name: active
      type: boolean
      nullable: false
    - name: joined
      type: date
      nullable: false"#,
        None,
    )
}

fn id_resource(data_range: Option<&str>) -> ResourceConfig {
    resource(
        r#"  strict: true
  fields:
    - name: id
      type: integer
      nullable: false"#,
        data_range,
    )
}

fn projects_resource(data_range: Option<&str>) -> ResourceConfig {
    let data_range = data_range
        .map(|value| format!("      data_range: {value}\n"))
        .unwrap_or_default();
    serde_saphyr::from_str(&format!(
        r#"
id: projects
source:
  type: file
  path: /runtime/public_works_projects.xlsx
  format:
    xlsx:
      sheet: Projects
      header_row: 1
{data_range}primary_key: project_id
schema:
  strict: true
  fields:
    - name: project_id
      type: string
      nullable: false
    - name: district_code
      type: string
      nullable: false
    - name: sector
      type: string
      nullable: false
    - name: status
      type: string
      nullable: false
"#
    ))
    .expect("projects resource config parses")
}

#[tokio::test]
async fn valid_workbook_passes_complete_no_cache_validation() {
    let config = support::load_example_config_for_tests("xlsx-validation-valid");
    validate_xlsx_source_bytes(&config, &simple_resource(), &fixture_bytes("simple.xlsx"))
        .await
        .expect("valid workbook passes");
}

#[tokio::test]
async fn corrupt_workbook_returns_stable_value_free_code() {
    let config = support::load_example_config_for_tests("xlsx-validation-corrupt");
    let error = validate_xlsx_source_bytes(&config, &id_resource(None), b"not an xlsx")
        .await
        .expect_err("corrupt workbook fails");
    assert!(matches!(error, IngestError::SourceUnreadable));
    assert_eq!(error.code(), "ingest.source_unreadable");
    assert!(!error.to_string().contains("not an xlsx"));
}

#[tokio::test]
async fn formula_anywhere_in_selected_sheet_returns_stable_value_free_code() {
    let config = support::load_example_config_for_tests("xlsx-validation-formula");
    let bytes = fixture_bytes("formula_outside_projection.xlsx");
    let error = validate_xlsx_source_bytes(&config, &projects_resource(Some("A1:D2")), &bytes)
        .await
        .expect_err("formula outside the configured data range still fails");
    assert!(matches!(error, IngestError::SourceUnreadable));
    assert_eq!(error.code(), "ingest.source_unreadable");
    assert!(!error.to_string().contains("=1+1"));
}

#[tokio::test]
async fn duplicate_primary_key_after_row_one_thousand_returns_stable_code() {
    let config = support::load_example_config_for_tests("xlsx-validation-duplicate");
    let bytes = fixture_bytes("duplicate_primary_key_after_1000.xlsx");
    let error = validate_xlsx_source_bytes(&config, &projects_resource(None), &bytes)
        .await
        .expect_err("full materialization detects late duplicate key");
    assert!(matches!(error, IngestError::SchemaMismatch));
    assert_eq!(error.code(), "ingest.schema_mismatch");
}

#[tokio::test]
async fn both_configured_byte_caps_are_enforced() {
    let bytes = fixture_bytes("simple.xlsx");
    let resource = simple_resource();

    let mut xlsx_limited = support::load_example_config_for_tests("xlsx-validation-xlsx-cap");
    xlsx_limited.server.xlsx_max_file_bytes = bytes.len() as u64 - 1;
    let error = validate_xlsx_source_bytes(&xlsx_limited, &resource, &bytes)
        .await
        .expect_err("xlsx byte cap rejects workbook");
    assert_eq!(error.code(), "ingest.source_unreadable");

    let mut source_limited = support::load_example_config_for_tests("xlsx-validation-source-cap");
    source_limited.server.max_source_file_bytes = bytes.len() as u64 - 1;
    let error = validate_xlsx_source_bytes(&source_limited, &resource, &bytes)
        .await
        .expect_err("source byte cap rejects workbook");
    assert_eq!(error.code(), "ingest.source_unreadable");
}
