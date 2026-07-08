// SPDX-License-Identifier: Apache-2.0
#![cfg(not(feature = "attribute-release"))]

//! Guardrail for binaries built without the CEL-backed attribute-release adapter
//! (`cargo build`, the 1.0 default feature shape). The
//! `attribute_release_profiles` field is parsed in every build, but profiles are
//! rejected unless the `attribute-release` feature is explicitly enabled so the
//! default binary cannot accept config for routes it does not mount.

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
fn attribute_release_profile_requires_feature() {
    // The profile is otherwise valid (snake-case id, exposed subject/claim fields,
    // one required claim) so the reason load fails is the feature-disabled
    // rejection of the attribute-release config surface.
    let yaml = r#"
server:
  bind: 127.0.0.1:0

catalog:
  title: Test
  base_url: https://gw.example
  publisher: Test

deployment:
  profile: local

vocabularies: {}

auth:
  mode: api_key
  api_keys: []

audit:
  sink: stdout
  format: jsonl

datasets:
  - id: civil_registry
    title: Civil Registry
    description: Synthetic registry
    owner: Test
    sensitivity: personal
    access_rights: restricted
    update_frequency: monthly
    defaults:
      refresh:
        mode: manual
    tables:
      - id: persons_table
        source:
          type: file
          path: fixtures/social_registry.csv
        primary_key: person_id
        schema:
          strict: true
          fields:
            - name: person_id
              type: string
              nullable: false
            - name: national_id
              type: string
              nullable: false
            - name: given_name
              type: string
              nullable: false
            - name: surname
              type: string
              nullable: false
            - name: deceased
              type: string
              nullable: false
    entities:
      - name: person
        table: persons_table
        fields:
          - name: id
            from: person_id
          - name: national_id
          - name: given_name
          - name: surname
          - name: deceased
        access:
          metadata_scope: civil_registry:metadata
          aggregate_scope: civil_registry:aggregate
          read_scope: civil_registry:rows
        api:
          default_limit: 100
          max_limit: 1000
          allowed_filters:
            - field: national_id
              ops: [eq]
        attribute_release_profiles:
          - id: civil_identity
            version: v1
            title: Civil identity bundle
            description: Minimised identity claims.
            purpose: identity
            release_scope: civil_registry:release
            subject:
              input: subject_token
              source_field: national_id
              id_type: NATIONAL_ID
            claims:
              - name: given_name
                source_field: given_name
                required: true
"#;
    let path = write_yaml(yaml);
    let err = config::load(&path)
        .expect_err("feature-disabled binary must reject an attribute-release profile");
    assert_eq!(err.code(), "config.validation_error");
}
