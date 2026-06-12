// SPDX-License-Identifier: Apache-2.0
//! Split metadata manifest loading and runtime binding validation.

use std::sync::Arc;

use axum::Extension;
use axum_test::TestServer;
use registry_relay::api::{metadata_router, well_known_router};
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
  source:
    path: {metadata_name}

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

fn insert_metadata_digest(path: &std::path::Path, digest: &str) {
    let yaml = std::fs::read_to_string(path).expect("runtime config reads");
    std::fs::write(
        path,
        yaml.replace(
            "    path: metadata.yaml\n",
            &format!("    path: metadata.yaml\n    digest: {digest}\n"),
        ),
    )
    .expect("runtime config rewrites");
}

fn insert_config_trust(path: &std::path::Path, tmp: &TempDir) {
    let yaml = std::fs::read_to_string(path).expect("runtime config reads");
    let trust = format!(
        r#"
config_trust:
  antirollback_state_path: "{}"
  local_approval_state_path: "{}"
  accepted_roots:
    - root_id: test-root
      production: false
      tuf_root_sha256: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
      high_risk_change_classes: []
      signers:
        signer-a:
          kid: signer-a
          enabled: true
      roles:
        - name: metadata
          threshold: 1
          signer_kids:
            - signer-a
          allowed_change_classes:
            - public_metadata
"#,
        tmp.path().join("antirollback.json").display(),
        tmp.path().join("local-approvals.json").display()
    );
    std::fs::write(
        path,
        yaml.replace("\naudit:\n", &format!("{trust}\naudit:\n")),
    )
    .expect("runtime config rewrites");
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
schema_version: registry-manifest/v1
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
    assert!(
        loaded
            .metadata_source_digest
            .as_deref()
            .is_some_and(|digest| digest.starts_with("sha256:")),
        "loader records the active metadata source digest"
    );
}

#[test]
fn load_with_metadata_rejects_pinned_manifest_digest_mismatch() {
    let tmp = TempDir::new().expect("tempdir");
    write_metadata_manifest(&tmp, true);
    let runtime_path = write_runtime_config(&tmp, "metadata.yaml");
    insert_metadata_digest(
        &runtime_path,
        "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
    );

    let err = config::load_with_metadata(&runtime_path)
        .expect_err("wrong metadata digest should fail startup");
    assert_eq!(err.code(), "metadata.manifest.digest_mismatch");
}

#[test]
fn load_with_metadata_requires_digest_for_governed_config() {
    let tmp = TempDir::new().expect("tempdir");
    write_metadata_manifest(&tmp, true);
    let runtime_path = write_runtime_config(&tmp, "metadata.yaml");
    insert_config_trust(&runtime_path, &tmp);

    let err = config::load_with_metadata(&runtime_path)
        .expect_err("governed metadata must pin source digest");
    assert_eq!(err.code(), "metadata.manifest.digest_required");
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
fn load_with_metadata_rejects_relationship_target_mismatch() {
    let tmp = TempDir::new().expect("tempdir");
    std::fs::write(
        tmp.path().join("metadata.yaml"),
        r#"
schema_version: registry-manifest/v1
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
  source:
    path: metadata.yaml

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
schema_version: registry-manifest/v0
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
async fn well_known_router_exposes_api_catalog_discovery() {
    let server = TestServer::new(well_known_router());

    let resp = server.get("/.well-known/api-catalog").await;
    resp.assert_status_ok();
    assert!(
        resp.header("content-type")
            .to_str()
            .expect("content-type")
            .starts_with("application/linkset+json"),
        "api-catalog must use Linkset JSON"
    );
    assert!(
        resp.header("link")
            .to_str()
            .expect("link")
            .contains("rel=\"api-catalog\""),
        "GET api-catalog must advertise the api-catalog link relation"
    );
    let body: Value = resp.json();
    let linkset = body["linkset"].as_array().expect("linkset");
    assert_eq!(linkset[0]["anchor"], "/.well-known/api-catalog");
    assert_eq!(linkset[0]["describedby"][0]["href"], "/metadata");
    let item_hrefs = linkset[0]["item"]
        .as_array()
        .expect("items")
        .iter()
        .map(|item| item["href"].as_str().expect("item href"))
        .collect::<Vec<_>>();
    assert!(item_hrefs.contains(&"/openapi.json"));
    assert!(item_hrefs.contains(&"/metadata/catalog"));
    assert!(item_hrefs.contains(&"/metadata/dcat"));
    assert!(item_hrefs.contains(&"/metadata/dcat/bregdcat-ap"));

    let head = server
        .method(axum::http::Method::HEAD, "/.well-known/api-catalog")
        .await;
    head.assert_status_ok();
    assert!(
        head.header("content-type")
            .to_str()
            .expect("head content-type")
            .starts_with("application/linkset+json"),
        "HEAD api-catalog must use Linkset JSON"
    );
    assert!(
        head.header("link")
            .to_str()
            .expect("head link")
            .contains("rel=\"api-catalog\""),
        "HEAD api-catalog must advertise the api-catalog link relation"
    );
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
        "#dataset-social_registry"
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
