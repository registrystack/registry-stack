// SPDX-License-Identifier: Apache-2.0
#![cfg(not(feature = "spdci-api-standards"))]

//! Guardrail for binaries built without the optional SP DCI adapter.

use std::io::Write;
use std::path::PathBuf;

use registry_relay::config;
use tempfile::NamedTempFile;

fn write_yaml(body: &str) -> PathBuf {
    let mut file = NamedTempFile::new().expect("tempfile");
    file.write_all(body.as_bytes()).expect("write yaml");
    let (_, path) = file.keep().expect("persist tempfile");
    path
}

#[test]
fn spdci_config_requires_spdci_api_standards_feature() {
    let yaml = r#"
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
      path: fixtures/social_registry.csv
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
    entities:
      - name: disabled_person
        table: disabled_people_table
        fields:
          - name: id
            from: person_id
          - name: disability_status
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
"#;
    let path = write_yaml(yaml);
    let err = config::load(&path).expect_err("feature-disabled binary must reject spdci config");
    assert_eq!(err.code(), "spdci.config.feature_disabled");
}
