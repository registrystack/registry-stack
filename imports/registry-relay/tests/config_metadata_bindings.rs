// SPDX-License-Identifier: Apache-2.0
//! Split metadata manifest loading and runtime binding validation.

use std::sync::Arc;

use axum::Extension;
use axum_test::TestServer;
use registry_relay::api::metadata_router;
use registry_relay::auth::{AuthMode, Principal, ScopeSet};
use registry_relay::config;
use registry_relay::entity::EntityRegistry;
use serde_json::Value;
use tempfile::TempDir;

fn write_runtime_config(tmp: &TempDir, metadata_name: &str) -> std::path::PathBuf {
    let path = tmp.path().join("relay.yaml");
    std::fs::write(
        &path,
        format!(
            r#"
server:
  bind: 127.0.0.1:0

metadata:
  manifest_path: {metadata_name}

catalog:
  title: Runtime Catalog
  base_url: https://runtime.example.test/
  publisher: Runtime Ministry

auth:
  mode: api_key
  api_keys: []

datasets:
  - id: social_registry
    title: Runtime Social Registry
    description: Runtime registry description
    owner: Runtime Ministry
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
          path: fixtures/social_registry.csv
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
    entities:
      - name: household
        table: households_table
        fields:
          - name: id
            from: household_id
          - name: region
            from: region_code
        access:
          metadata_scope: social_registry:metadata
          aggregate_scope: social_registry:aggregate
          read_scope: social_registry:rows
        api:
          default_limit: 100
          max_limit: 1000
          allowed_filters:
            - field: region
              ops: [eq]

audit:
  sink: stdout
  format: jsonl
"#
        ),
    )
    .expect("write runtime config");
    path
}

fn write_metadata_manifest(tmp: &TempDir, include_region: bool) {
    let region_field = if include_region {
        r#"
          - name: region
            type: string
"#
    } else {
        ""
    };
    std::fs::write(
        tmp.path().join("metadata.yaml"),
        format!(
            r#"
schema_version: registry-metadata/v1
catalog:
  id: split-demo
  base_url: https://metadata.example.test/
  title: Split Metadata Catalog
  publisher:
    name: Metadata Ministry
  standards:
    dcat: "3.0"
    shacl: "1.1"
    json_schema: "2020-12"
  application_profiles:
    - id: bregdcat-ap
      version: "3.0"
datasets:
  - id: social_registry
    title: Split Social Registry
    description: Split registry description
    owner: Metadata Ministry
    sensitivity: personal
    access_rights: restricted
    update_frequency: monthly
    policy:
      uid: https://metadata.example.test/datasets/social_registry#offer
      assigner: did:web:metadata.example.test
      profile:
        - https://metadata.example.test/odrl/profile/data-sharing
      permissions:
        - action: odrl:use
          constraints:
            - left_operand: odrl:purpose
              operator: odrl:isA
              right_operand:
                iri: https://metadata.example.test/purpose/social-protection-planning
    entities:
      - name: household
        title: Household
        identifiers:
          - name: id
            kind: primary
        fields:
          - name: id
            type: string
            required: true
{region_field}
"#
        ),
    )
    .expect("write metadata manifest");
}

fn write_evidence_runtime_config(tmp: &TempDir) -> std::path::PathBuf {
    let path = tmp.path().join("relay.yaml");
    std::fs::write(
        &path,
        r#"
server:
  bind: 127.0.0.1:0

metadata:
  manifest_path: metadata.yaml

catalog:
  title: Runtime Catalog
  base_url: https://runtime.example.test/
  publisher: Runtime Ministry

auth:
  mode: api_key
  api_keys: []

evidence:
  enabled: true
  claims:
    - id: farmed-land-size
      title: Farmed land size
      version: v1
      subject_type: person
      value:
        type: number
        unit: hectare
      source_bindings:
        farmer:
          connector: registry_data_api
          dataset: farmer_registry
          entity: farmer
          lookup:
            input: subject_id
            field: id
          fields:
            total_farmed_area:
              field: total_farmed_area
              type: number
              unit: hectare
              required: true
      rule:
        type: extract
        source: farmer
        field: total_farmed_area

datasets:
  - id: farmer_registry
    title: Runtime Farmer Registry
    description: Runtime farmer registry description
    owner: Runtime Ministry
    sensitivity: personal
    access_rights: restricted
    update_frequency: monthly
    defaults:
      refresh:
        mode: manual
    tables:
      - id: farmers_table
        source:
          type: file
          path: fixtures/farmers.csv
        primary_key: id
        schema:
          strict: true
          fields:
            - name: id
              type: string
              nullable: false
            - name: total_farmed_area
              type: number
              nullable: false
    entities:
      - name: farmer
        table: farmers_table
        fields:
          - name: id
          - name: total_farmed_area
        access:
          metadata_scope: farmer_registry:metadata
          aggregate_scope: farmer_registry:aggregate
          read_scope: farmer_registry:rows
        api:
          default_limit: 100
          max_limit: 1000

audit:
  sink: stdout
  format: jsonl
"#,
    )
    .expect("write runtime config");
    path
}

fn write_evidence_metadata_manifest(tmp: &TempDir, field_type: &str, unit: &str, required: bool) {
    std::fs::write(
        tmp.path().join("metadata.yaml"),
        format!(
            r#"
schema_version: registry-metadata/v1
catalog:
  id: evidence-demo
  base_url: https://metadata.example.test/
  title: Evidence Metadata Catalog
  publisher:
    name: Metadata Ministry
datasets:
  - id: farmer_registry
    title: Farmer Registry
    entities:
      - name: farmer
        title: Farmer
        identifiers:
          - name: id
            kind: primary
        fields:
          - name: id
            type: string
            required: true
          - name: total_farmed_area
            type: {field_type}
            required: {required}
            unit: {unit}
"#
        ),
    )
    .expect("write metadata manifest");
}

#[test]
fn load_with_metadata_loads_manifest_relative_to_runtime_config() {
    let tmp = TempDir::new().expect("tempdir");
    write_metadata_manifest(&tmp, true);
    let runtime_path = write_runtime_config(&tmp, "metadata.yaml");

    let loaded = config::load_with_metadata(&runtime_path).expect("split config loads");
    let metadata = loaded.metadata.expect("metadata is compiled");

    assert_eq!(loaded.runtime.catalog.title, "Runtime Catalog");
    assert_eq!(metadata.catalog().title, "Split Metadata Catalog");
    assert_eq!(metadata.catalog().base_url, "https://metadata.example.test");
}

#[test]
fn load_with_metadata_rejects_runtime_field_missing_from_manifest() {
    let tmp = TempDir::new().expect("tempdir");
    write_metadata_manifest(&tmp, false);
    let runtime_path = write_runtime_config(&tmp, "metadata.yaml");

    let err = config::load_with_metadata(&runtime_path)
        .expect_err("missing metadata field should fail binding validation");
    assert_eq!(err.code(), "runtime.binding.field_missing");
}

#[test]
fn load_with_metadata_validates_evidence_source_binding_metadata() {
    let tmp = TempDir::new().expect("tempdir");
    write_evidence_metadata_manifest(&tmp, "number", "hectare", true);
    let runtime_path = write_evidence_runtime_config(&tmp);

    config::load_with_metadata(&runtime_path).expect("evidence metadata binding loads");
}

#[test]
fn load_with_metadata_rejects_evidence_source_binding_type_or_unit_drift() {
    let tmp = TempDir::new().expect("tempdir");
    write_evidence_metadata_manifest(&tmp, "string", "hectare", true);
    let runtime_path = write_evidence_runtime_config(&tmp);
    let err = config::load_with_metadata(&runtime_path)
        .expect_err("evidence metadata type drift should fail binding validation");
    assert_eq!(err.code(), "runtime.binding.field_missing");

    let tmp = TempDir::new().expect("tempdir");
    write_evidence_metadata_manifest(&tmp, "number", "acre", true);
    let runtime_path = write_evidence_runtime_config(&tmp);
    let err = config::load_with_metadata(&runtime_path)
        .expect_err("evidence metadata unit drift should fail binding validation");
    assert_eq!(err.code(), "runtime.binding.field_missing");

    let tmp = TempDir::new().expect("tempdir");
    write_evidence_metadata_manifest(&tmp, "number", "hectare", false);
    let runtime_path = write_evidence_runtime_config(&tmp);
    let err = config::load_with_metadata(&runtime_path)
        .expect_err("required evidence source field not required in metadata should fail");
    assert_eq!(err.code(), "runtime.binding.field_missing");
}

#[test]
fn load_with_metadata_rejects_relationship_target_mismatch() {
    let tmp = TempDir::new().expect("tempdir");
    std::fs::write(
        tmp.path().join("metadata.yaml"),
        r#"
schema_version: registry-metadata/v1
catalog:
  id: split-demo
  base_url: https://metadata.example.test/
  title: Split Metadata Catalog
  publisher:
    name: Metadata Ministry
datasets:
  - id: social_registry
    title: Split Social Registry
    entities:
      - name: household
        identifiers:
          - name: id
            kind: primary
        fields:
          - name: id
            type: string
        relationships:
          - name: members
            target_entity: school
            cardinality: many
      - name: member
        identifiers:
          - name: id
            kind: primary
        fields:
          - name: id
            type: string
          - name: household_id
            type: string
      - name: school
        identifiers:
          - name: id
            kind: primary
        fields:
          - name: id
            type: string
"#,
    )
    .expect("write metadata manifest");
    let runtime_path = tmp.path().join("relay.yaml");
    std::fs::write(
        &runtime_path,
        r#"
server:
  bind: 127.0.0.1:0

metadata:
  manifest_path: metadata.yaml

catalog:
  title: Runtime Catalog
  base_url: https://runtime.example.test/
  publisher: Runtime Ministry

auth:
  mode: api_key
  api_keys: []

datasets:
  - id: social_registry
    title: Runtime Social Registry
    description: Runtime registry description
    owner: Runtime Ministry
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
          path: fixtures/social_registry.csv
        primary_key: household_id
        schema:
          strict: true
          fields:
            - name: household_id
              type: string
              nullable: false
      - id: members_table
        source:
          type: file
          path: fixtures/members.csv
        primary_key: member_id
        schema:
          strict: true
          fields:
            - name: member_id
              type: string
              nullable: false
            - name: household_id
              type: string
              nullable: false
    entities:
      - name: household
        table: households_table
        fields:
          - name: id
            from: household_id
        relationships:
          - name: members
            kind: has_many
            target: member
            foreign_key: household_id
        access:
          metadata_scope: social_registry:metadata
          aggregate_scope: social_registry:aggregate
          read_scope: social_registry:rows
        api:
          default_limit: 100
          max_limit: 1000
      - name: member
        table: members_table
        fields:
          - name: id
            from: member_id
          - name: household_id
        access:
          metadata_scope: social_registry:metadata
          aggregate_scope: social_registry:aggregate
          read_scope: social_registry:rows
        api:
          default_limit: 100
          max_limit: 1000

audit:
  sink: stdout
  format: jsonl
"#,
    )
    .expect("write runtime config");

    let err = config::load_with_metadata(&runtime_path)
        .expect_err("relationship target mismatch should fail binding validation");
    assert_eq!(err.code(), "runtime.binding.relationship_missing");
}

#[test]
fn load_with_metadata_uses_metadata_manifest_error_codes() {
    let tmp = TempDir::new().expect("tempdir");
    let missing_path = write_runtime_config(&tmp, "missing.metadata.yaml");
    let missing_err = config::load_with_metadata(&missing_path)
        .expect_err("missing manifest should fail metadata loading");
    assert_eq!(missing_err.code(), "metadata.manifest.file_not_found");

    std::fs::write(tmp.path().join("bad.metadata.yaml"), "schema_version: [")
        .expect("write invalid manifest");
    let parse_path = write_runtime_config(&tmp, "bad.metadata.yaml");
    let parse_err = config::load_with_metadata(&parse_path)
        .expect_err("invalid manifest YAML should fail metadata parsing");
    assert_eq!(parse_err.code(), "metadata.manifest.parse_failed");

    std::fs::write(
        tmp.path().join("unsupported.metadata.yaml"),
        r#"
schema_version: registry-metadata/v0
catalog:
  id: split-demo
  base_url: https://metadata.example.test/
  title: Split Metadata Catalog
  publisher:
    name: Metadata Ministry
datasets: []
"#,
    )
    .expect("write unsupported manifest");
    let unsupported_path = write_runtime_config(&tmp, "unsupported.metadata.yaml");
    let unsupported_err = config::load_with_metadata(&unsupported_path)
        .expect_err("unsupported manifest version should fail metadata loading");
    assert_eq!(
        unsupported_err.code(),
        "metadata.manifest.version_unsupported"
    );
}

#[tokio::test]
async fn metadata_routes_prefer_split_manifest_extension() {
    let tmp = TempDir::new().expect("tempdir");
    write_metadata_manifest(&tmp, true);
    let runtime_path = write_runtime_config(&tmp, "metadata.yaml");
    let loaded = config::load_with_metadata(&runtime_path).expect("split config loads");
    let metadata = Arc::new(loaded.metadata.expect("metadata is compiled"));
    let runtime = Arc::new(loaded.runtime);
    let registry = Arc::new(EntityRegistry::from_config(&runtime).expect("registry compiles"));
    let server = TestServer::new(
        metadata_router()
            .layer(Extension(metadata))
            .layer(Extension(registry))
            .layer(Extension(runtime))
            .layer(Extension(principal(&["social_registry:metadata"]))),
    );

    let resp = server.get("/metadata/catalog").await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["id"], "split-demo");
    assert_eq!(body["title"], "Split Metadata Catalog");
    assert_eq!(body["base_url"], "https://metadata.example.test");
}

#[tokio::test]
async fn metadata_dcat_profile_uses_split_manifest_policy_when_available() {
    let tmp = TempDir::new().expect("tempdir");
    write_metadata_manifest(&tmp, true);
    let runtime_path = write_runtime_config(&tmp, "metadata.yaml");
    let loaded = config::load_with_metadata(&runtime_path).expect("split config loads");
    let metadata = Arc::new(loaded.metadata.expect("metadata is compiled"));
    let runtime = Arc::new(loaded.runtime);
    let registry = Arc::new(EntityRegistry::from_config(&runtime).expect("registry compiles"));
    let server = TestServer::new(
        metadata_router()
            .layer(Extension(metadata))
            .layer(Extension(registry))
            .layer(Extension(runtime))
            .layer(Extension(principal(&["social_registry:metadata"]))),
    );

    let resp = server.get("/metadata/dcat/bregdcat-ap").await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    let dataset = &body["dcat:dataset"][0];
    let policy = &dataset["odrl:hasPolicy"];

    assert_eq!(
        policy["odrl:uid"],
        "https://metadata.example.test/datasets/social_registry#offer"
    );
    assert_eq!(
        policy["odrl:profile"][0]["@id"],
        "https://metadata.example.test/odrl/profile/data-sharing"
    );
    assert_eq!(
        policy["odrl:permission"][0]["odrl:target"]["@id"],
        "https://metadata.example.test/datasets/social_registry"
    );
    assert_eq!(
        policy["odrl:permission"][0]["odrl:constraint"][0]["odrl:rightOperand"]["@id"],
        "https://metadata.example.test/purpose/social-protection-planning"
    );
}

fn principal(scopes: &[&str]) -> Principal {
    Principal {
        principal_id: "test".to_string(),
        scopes: scopes.iter().copied().collect::<ScopeSet>(),
        auth_mode: AuthMode::ApiKey,
    }
}
