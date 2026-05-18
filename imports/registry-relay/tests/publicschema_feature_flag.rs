// SPDX-License-Identifier: Apache-2.0
#![cfg(not(feature = "publicschema-cel"))]

//! Guardrail for binaries built without the optional PublicSchema CEL mapper.

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
fn publicschema_config_requires_publicschema_cel_feature() {
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

datasets:
  - id: social_registry
    title: Social Registry
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
      - id: individuals_table
        primary_key: individual_id
        schema:
          strict: true
          fields:
            - name: individual_id
              type: string
              nullable: false
    entities:
      - name: individual
        table: individuals_table
        fields:
          - name: id
            from: individual_id
        access:
          metadata_scope: social_registry:metadata
          aggregate_scope: social_registry:aggregate
          read_scope: social_registry:rows
          verify_scope: social_registry:verify
        api:
          default_limit: 100
          max_limit: 1000
        publicschema:
          target: Person
          mapping_path: mappings/individual-person.publicschema.yaml
"#;
    let path = write_yaml(yaml);
    let err = config::load(&path).expect_err("feature-disabled binary must reject mapping config");
    assert_eq!(err.code(), "publicschema.config.feature_disabled");
}
