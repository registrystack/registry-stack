// SPDX-License-Identifier: Apache-2.0
//! Entity-layer config validation tests.

use data_gate::entity::EntityRegistry;
use tempfile::TempDir;

fn write_config(tmp: &TempDir, body: &str) -> std::path::PathBuf {
    let path = tmp.path().join("entity.yaml");
    std::fs::write(&path, body).expect("write config");
    path
}

fn base_config(dataset_body: &str) -> String {
    format!(
        r#"
server:
  bind: 127.0.0.1:0

catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test

vocabularies: {{}}

auth:
  mode: api_key
  api_keys: []

datasets:
{dataset_body}

audit:
  sink: stdout
  format: jsonl
"#
    )
}

fn valid_dataset() -> String {
    r#"
  - id: social_registry
    title: Social Registry
    description: Synthetic registry
    owner: Test
    sensitivity: personal
    access_rights: restricted
    update_frequency: monthly
    source:
      type: file
      path: fixtures/social_registry.xlsx
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
            - name: region_code
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
            - name: municipality_code
              type: string
              nullable: true
    entities:
      - name: household
        table: households_table
        fields:
          - name: id
            from: household_id
          - name: region
            from: region_code
        relationships:
          - name: members
            kind: has_many
            target: individual
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
            - field: id
              ops: [eq]
          allowed_expansions: [members]
      - name: individual
        table: individuals_table
        fields:
          - name: id
            from: individual_id
          - name: household_id
          - name: municipality_code
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
"#
    .to_string()
}

#[test]
fn valid_household_individual_entities_load_and_compile() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = write_config(&tmp, &base_config(&valid_dataset()));
    let config = data_gate::config::load(&config_path).expect("config loads");
    let registry = EntityRegistry::from_config(&config).expect("entity registry compiles");

    let dataset = registry.dataset("social_registry").expect("dataset");
    let household = dataset.entity("household").expect("household entity");
    assert_eq!(household.table_id, "households_table");
    assert_eq!(household.primary_key.name, "id");
    assert!(household.relationships.contains_key("members"));
}

#[test]
fn entity_referencing_missing_table_is_rejected() {
    let tmp = TempDir::new().expect("tempdir");
    let invalid = valid_dataset().replace("table: households_table", "table: missing_table");
    let config_path = write_config(&tmp, &base_config(&invalid));
    let err = data_gate::config::load(&config_path).expect_err("config rejects missing table");
    assert_eq!(err.code(), "config.validation_error");
}

#[test]
fn relationship_foreign_key_type_mismatch_is_rejected() {
    let tmp = TempDir::new().expect("tempdir");
    let valid = valid_dataset();
    let first = "            - name: household_id\n              type: string\n              nullable: false";
    let first_at = valid.find(first).expect("household table key");
    let second_at = valid[first_at + first.len()..]
        .find(first)
        .map(|idx| first_at + first.len() + idx)
        .expect("individual foreign key");
    let mut invalid = valid;
    invalid.replace_range(
        second_at..second_at + first.len(),
        "            - name: household_id\n              type: integer\n              nullable: false",
    );
    let config_path = write_config(&tmp, &base_config(&invalid));
    let err = data_gate::config::load(&config_path).expect_err("config rejects FK mismatch");
    assert_eq!(err.code(), "config.validation_error");
}
