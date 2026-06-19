// SPDX-License-Identifier: Apache-2.0
//! Entity-layer config validation tests.

use registry_relay::entity::EntityRegistry;
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
    defaults:
      refresh:
        mode: manual
    tables:
      - id: households_table
        source:
          type: file
          path: fixtures/social_registry.xlsx
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
        source:
          type: file
          path: fixtures/social_registry.xlsx
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
    let config = registry_relay::config::load(&config_path).expect("config loads");
    let registry = EntityRegistry::from_config(&config).expect("entity registry compiles");

    let dataset = registry.dataset("social_registry").expect("dataset");
    let household = dataset.entity("household").expect("household entity");
    assert_eq!(household.table_id, "households_table");
    assert_eq!(household.primary_key.name, "id");
    assert!(household.relationships.contains_key("members"));
}

#[test]
fn governed_redaction_field_must_be_top_level_projectable_path() {
    let tmp = TempDir::new().expect("tempdir");
    let invalid = valid_dataset().replace(
        "          allowed_filters:\n            - field: household_id",
        "          governed_policy:\n            permitted_purposes: [testing]\n            redaction_fields: [profile.birthdate]\n            trusted_context: {}\n          allowed_filters:\n            - field: household_id",
    );
    let config_path = write_config(&tmp, &base_config(&invalid));
    let err = registry_relay::config::load(&config_path)
        .expect_err("config rejects unprojectable governed redaction field");
    assert_eq!(err.code(), "config.validation_error");
}

#[test]
fn governed_policy_rejects_static_trusted_source_freshness() {
    let tmp = TempDir::new().expect("tempdir");
    let invalid = valid_dataset().replace(
        "          allowed_filters:\n            - field: household_id",
        "          governed_policy:\n            permitted_purposes: [testing]\n            max_source_age_seconds: 30\n            trusted_context:\n              source_observed_age_seconds: 5\n          allowed_filters:\n            - field: household_id",
    );
    let config_path = write_config(&tmp, &base_config(&invalid));
    let err = registry_relay::config::load(&config_path)
        .expect_err("config rejects static governed freshness context");
    assert_eq!(err.code(), "config.validation_error");
}

#[test]
fn governed_policy_rejects_inert_policy_block() {
    let tmp = TempDir::new().expect("tempdir");
    let invalid = valid_dataset().replace(
        "          allowed_filters:\n            - field: household_id",
        "          governed_policy:\n            trusted_context: {}\n          allowed_filters:\n            - field: household_id",
    );
    let config_path = write_config(&tmp, &base_config(&invalid));
    let err = registry_relay::config::load(&config_path)
        .expect_err("config rejects governed policy with no enforced gates");
    assert_eq!(err.code(), "config.validation_error");
}

#[test]
fn entity_referencing_missing_table_is_rejected() {
    let tmp = TempDir::new().expect("tempdir");
    let invalid = valid_dataset().replace("table: households_table", "table: missing_table");
    let config_path = write_config(&tmp, &base_config(&invalid));
    let err = registry_relay::config::load(&config_path).expect_err("config rejects missing table");
    assert_eq!(err.code(), "config.validation_error");
}

#[test]
fn entity_access_scopes_must_be_bound_to_enclosing_dataset() {
    let tmp = TempDir::new().expect("tempdir");
    let invalid = valid_dataset().replace(
        "          read_scope: social_registry:rows",
        "          read_scope: shared_rows",
    );
    let config_path = write_config(&tmp, &base_config(&invalid));
    let err = registry_relay::config::load(&config_path)
        .expect_err("config rejects unbound entity read scope");
    assert_eq!(err.code(), "config.validation_error");
}

#[test]
fn entity_access_scopes_must_not_use_reserved_ops_namespace() {
    let tmp = TempDir::new().expect("tempdir");
    let invalid = valid_dataset().replace("id: social_registry", "id: registry_relay");
    let config_path = write_config(&tmp, &base_config(&invalid));
    let err = registry_relay::config::load(&config_path)
        .expect_err("config rejects data-plane scope in reserved ops namespace");
    assert_eq!(err.code(), "config.validation_error");
}

fn dataset_with_one_table(dataset_id: &str, table_id: &str, entity_name: &str) -> String {
    format!(
        r#"
  - id: {dataset_id}
    title: Dataset {dataset_id}
    description: Synthetic registry
    owner: Test
    sensitivity: personal
    access_rights: restricted
    update_frequency: monthly
    defaults:
      refresh:
        mode: manual
    tables:
      - id: {table_id}
        source:
          type: file
          path: fixtures/{dataset_id}.csv
        primary_key: record_id
        schema:
          strict: true
          fields:
            - name: record_id
              type: string
              nullable: false
    entities:
      - name: {entity_name}
        table: {table_id}
        fields:
          - name: id
            from: record_id
        access:
          metadata_scope: "{dataset_id}:metadata"
          aggregate_scope: "{dataset_id}:aggregate"
          read_scope: "{dataset_id}:rows"
        api:
          default_limit: 100
          max_limit: 1000
          allowed_filters:
            - field: id
              ops: [eq]
"#
    )
}

#[test]
fn derived_table_names_must_be_globally_unique() {
    let tmp = TempDir::new().expect("tempdir");
    let datasets = format!(
        "{}{}",
        dataset_with_one_table("aa", "bb__cc", "first"),
        dataset_with_one_table("aa__bb", "cc", "second")
    );
    let config_path = write_config(&tmp, &base_config(&datasets));
    let err = registry_relay::config::load(&config_path)
        .expect_err("config rejects colliding derived DataFusion table names");
    assert_eq!(err.code(), "config.duplicate_id");
}

fn dataset_with_required_filters(required_filters: &str) -> String {
    format!(
        r#"
  - id: my_dataset
    title: My Dataset
    description: Test
    owner: Test
    sensitivity: personal
    access_rights: restricted
    update_frequency: monthly
    defaults:
      refresh:
        mode: manual
    tables:
      - id: records_table
        source:
          type: file
          path: fixtures/my_dataset.xlsx
        primary_key: record_id
        schema:
          strict: true
          fields:
            - name: record_id
              type: string
              nullable: false
            - name: group_id
              type: string
              nullable: true
    entities:
      - name: record
        table: records_table
        fields:
          - name: id
            from: record_id
          - name: group_id
        access:
          metadata_scope: my_dataset:metadata
          aggregate_scope: my_dataset:aggregate
          read_scope: my_dataset:rows
        api:
          default_limit: 100
          max_limit: 1000
          required_filters: {required_filters}
          allowed_filters:
            - field: id
              ops: [eq]
            - field: group_id
              ops: [eq]
"#
    )
}

#[test]
fn required_filters_not_in_allowed_filters_is_rejected() {
    let tmp = TempDir::new().expect("tempdir");
    let dataset = dataset_with_required_filters("[id, unknown_field]");
    let config_path = write_config(&tmp, &base_config(&dataset));
    let err = registry_relay::config::load(&config_path)
        .expect_err("config rejects required_filters with unknown field");
    assert_eq!(err.code(), "config.validation_error");
}

#[test]
fn required_filters_all_in_allowed_filters_loads_cleanly() {
    let tmp = TempDir::new().expect("tempdir");
    let dataset = dataset_with_required_filters("[id, group_id]");
    let config_path = write_config(&tmp, &base_config(&dataset));
    let config = registry_relay::config::load(&config_path).expect("config loads");
    let registry = EntityRegistry::from_config(&config).expect("entity registry compiles");
    let dataset = registry.dataset("my_dataset").expect("dataset");
    let entity = dataset.entity("record").expect("entity");
    assert_eq!(entity.api.required_filters, ["id", "group_id"]);
}

#[test]
fn required_filters_empty_is_accepted() {
    let tmp = TempDir::new().expect("tempdir");
    let dataset = dataset_with_required_filters("[]");
    let config_path = write_config(&tmp, &base_config(&dataset));
    let config = registry_relay::config::load(&config_path).expect("config loads");
    let registry = EntityRegistry::from_config(&config).expect("entity registry compiles");
    let dataset = registry.dataset("my_dataset").expect("dataset");
    let entity = dataset.entity("record").expect("entity");
    assert!(entity.api.required_filters.is_empty());
}

#[test]
fn governed_entity_policy_rejects_blank_policy_terms() {
    let tmp = TempDir::new().expect("tempdir");
    let dataset = dataset_with_required_filters("[]").replace(
        "          allowed_filters:\n",
        r#"          governed_policy:
            permitted_purposes: [" "]
            permitted_jurisdictions: [ZZ]
            allowed_assurance: [substantial]
            trusted_context:
              jurisdiction: ZZ
          allowed_filters:
"#,
    );
    let config_path = write_config(&tmp, &base_config(&dataset));
    let err = registry_relay::config::load(&config_path)
        .expect_err("config rejects blank governed policy terms");

    assert_eq!(err.code(), "config.validation_error");
}

#[test]
fn allowed_expansions_without_matching_relationship_are_rejected() {
    let tmp = TempDir::new().expect("tempdir");
    let dataset = dataset_with_required_filters("[]").replace(
        "          max_limit: 1000\n",
        "          max_limit: 1000\n          allowed_expansions: [ghost]\n",
    );
    let config_path = write_config(&tmp, &base_config(&dataset));
    let err = registry_relay::config::load(&config_path)
        .expect_err("config rejects expansion without relationship");
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
    let err = registry_relay::config::load(&config_path).expect_err("config rejects FK mismatch");
    assert_eq!(err.code(), "config.validation_error");
}
