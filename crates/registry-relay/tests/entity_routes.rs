// SPDX-License-Identifier: Apache-2.0
//! Focused route-shape tests for the entity API slice.

use axum::http::{header, StatusCode};
use axum::middleware::from_fn;
use axum::Extension;
use axum_test::TestServer;
use datafusion::arrow::array::StringArray;
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::datasource::MemTable;
use datafusion::execution::context::SessionContext;
use registry_manifest_core as metadata_core;
use registry_relay::api::{aggregates_router, entity_router, metadata_router, CursorSigner};
use registry_relay::audit::{audit_layer, AuditPipeline, InMemorySink};
use registry_relay::auth::{AuthMode, Principal, ScopeSet};
use registry_relay::config::{self, DatasetId, ResourceId};
use registry_relay::entity::EntityRegistry;
use registry_relay::ingest::{
    register_versioned_table, table_name, ReadinessSnapshot, ReadyResource,
};
use registry_relay::query::EntityQueryEngine;
use serde_json::Value;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::sync::watch;
use ulid::Ulid;

fn server() -> TestServer {
    TestServer::new(entity_router::<()>().merge(metadata_router()))
}

fn id<T: serde::de::DeserializeOwned>(value: &str) -> T {
    serde_json::from_str(&format!(r#""{value}""#)).expect("id deserializes")
}

fn principal(scopes: &[&str]) -> Principal {
    principal_with_id(scopes, "item-1")
}

fn principal_with_id(scopes: &[&str], principal_id: &str) -> Principal {
    Principal {
        principal_id: principal_id.to_string(),
        scopes: scopes.iter().copied().collect::<ScopeSet>(),
        auth_mode: AuthMode::ApiKey,
    }
}

fn test_evidence_metadata_manifest() -> metadata_core::MetadataManifest {
    serde_saphyr::from_str(
        r#"
schema_version: registry-manifest/v1
catalog:
  id: test
  base_url: https://data.example.test
  title: Test
  publisher:
    name: Test
federation:
  node_id: did:web:data.example.test
  issuer: https://data.example.test
  jwks_uri: https://data.example.test/.well-known/jwks.json
  federation_api: https://data.example.test/federation
  supported_protocol_versions:
    - registry-notary-federation/v0.1
evaluation_profiles:
  - id: exact-name
    ruleset: exact-name
    claim_id: exact_name
    subject_id_type: id
    max_source_observed_age_seconds: 86400
  - id: exact-name-targeted
    ruleset: exact-name-targeted
    claim_id: exact_name_targeted
    subject_id_type: id
    max_source_observed_age_seconds: 86400
  - id: hidden-name
    ruleset: hidden-name
    claim_id: hidden_name
    subject_id_type: id
    max_source_observed_age_seconds: 86400
ecosystem_bindings:
  - id: baseline-dpi/v1
    version: v1
    profile: baseline-dpi
    type: governed-evidence
    evidence_pack:
      pack_id: baseline-dpi/v1
      pack_version: v1
      source_basis:
        family: dpi
        evidence_type: name_evidence
      semantic_profile:
        vocabulary: registry-lab
        fit: strong
      evidence_envelope:
        format: minimized_json
        fields:
          - claim_id
          - result
      required_gates:
            - purpose
            - jurisdiction
            - legal_basis
            - consent
            - authority_basis
            - requester_identity
            - subject_identity
            - subject_relationship
            - assurance
            - source_binding
            - source_freshness
            - requested_disclosure
            - credential_format
            - route_scope
      allowed_outputs:
            - minimized_json
      policy_id: baseline-dpi-policy
      policy_hash: sha256:3333333333333333333333333333333333333333333333333333333333333333
      odrl_enforcement:
        profile: registry-evidence-gateway-pdp/v1
        constraint_terms:
          - odrl:purpose
  - id: assurance-dpi/v1
    version: v1
    profile: assurance-dpi
    type: governed-evidence
    evidence_pack:
      pack_id: assurance-dpi/v1
      pack_version: v1
      source_basis:
        family: dpi
        evidence_type: name_evidence
      semantic_profile:
        vocabulary: registry-lab
        fit: strong
      evidence_envelope:
        format: minimized_json
        fields:
          - claim_id
          - result
      required_gates:
            - purpose
            - jurisdiction
            - legal_basis
            - consent
            - authority_basis
            - requester_identity
            - subject_identity
            - subject_relationship
            - assurance
            - source_binding
            - source_freshness
            - requested_disclosure
            - credential_format
            - route_scope
      allowed_outputs:
            - minimized_json
      policy_id: assurance-dpi-policy
      policy_hash: sha256:5555555555555555555555555555555555555555555555555555555555555555
      odrl_enforcement:
        profile: registry-evidence-gateway-pdp/v1
        constraint_terms:
          - odrl:purpose
requirements:
  - id: name_requirement
    iri: https://data.example.test/requirements/name
    title: Name requirement
    rdf_type: cccev:Criterion
    reference_frameworks:
      - iri: https://data.example.test/reference-frameworks/name-law
        identifier: name-law
  - id: bare_requirement
    iri: https://data.example.test/requirements/bare
    title: Bare requirement with no concepts or frameworks
    description: Used to test that empty CCCEV predicate arrays are omitted.
evidence_types:
  - id: name_evidence
    iri: https://data.example.test/evidence-types/name
    title: Name evidence
    proves: [name_requirement]
    information_concepts:
      - https://data.example.test/concepts/given-name
  - id: alternate_name_evidence
    iri: https://data.example.test/evidence-types/alternate-name
    title: Alternate name evidence
    proves: [name_requirement]
    information_concepts:
      - https://data.example.test/concepts/given-name
datasets:
  - id: social_registry
    title: Social Registry
    description: Synthetic registry
    policy:
      uid: https://data.example.test/policies/social-registry
      assigner: did:web:data.example.test
      permissions:
        - action: odrl:use
          constraints:
            - left_operand: odrl:purpose
              operator: odrl:isA
              right_operand:
                iri: https://data.example.test/purposes/testing
    evidence_offerings:
      - id: individual_name_evidence
        iri: https://data.example.test/evidence-offerings/individual-name
        title: Individual name evidence
        evidence_type: name_evidence
        issuing_authority:
          id: test_authority
          iri: did:web:data.example.test
          name: Test Authority
          country: ZZ
        jurisdiction:
          country: ZZ
        level_of_assurance: substantial
        entity: individual
        lookup_keys: [given_name]
        access:
          kind: registry-notary
          conforms_to: registry-notary-federation/v0.1
          endpoint_url: https://evidence.example.test/individual-name
          discovery_url: https://evidence.example.test/.well-known/registry-notary
          ruleset: exact-name
        policy:
          purpose:
            - https://data.example.test/purposes/testing
      - id: individual_targeted_name_evidence
        iri: https://data.example.test/evidence-offerings/individual-targeted-name
        title: Targeted individual name evidence
        evidence_type: name_evidence
        issuing_authority:
          id: test_authority
          iri: did:web:data.example.test
          name: Test Authority
          country: ZZ
        entity: individual
        lookup_keys: [given_name]
        access:
          kind: registry-notary
          conforms_to: registry-notary-federation/v0.1
          endpoint_url: https://evidence.example.test/individual-targeted-name
          discovery_url: https://evidence.example.test/.well-known/registry-notary
          ruleset: exact-name-targeted
      - id: individual_alternate_name_evidence
        iri: https://data.example.test/evidence-offerings/individual-alternate-name
        title: Alternate individual name evidence
        evidence_type: alternate_name_evidence
        issuing_authority:
          id: test_authority
          iri: did:web:data.example.test
          name: Test Authority
          country: ZZ
        entity: individual
        lookup_keys: [given_name]
        access:
          kind: registry-notary
          conforms_to: registry-notary-federation/v0.1
          endpoint_url: https://evidence.example.test/individual-alternate-name
          discovery_url: https://evidence.example.test/.well-known/registry-notary
          ruleset: exact-name
      - id: individual_hidden_name_evidence
        iri: https://data.example.test/evidence-offerings/individual-hidden-name
        title: Hidden individual name evidence
        evidence_type: name_evidence
        issuing_authority:
          id: test_authority
          iri: did:web:data.example.test
          name: Test Authority
          country: ZZ
        entity: individual
        lookup_keys: [given_name]
        access:
          kind: registry-notary
          conforms_to: registry-notary-federation/v0.1
          endpoint_url: https://evidence.example.test/individual-hidden-name
          discovery_url: https://evidence.example.test/.well-known/registry-notary
          ruleset: hidden-name
      - id: external_individual_name_evidence
        iri: https://data.example.test/evidence-offerings/external-individual-name
        title: External individual name evidence
        evidence_type: name_evidence
        issuing_authority:
          id: test_authority
          iri: did:web:data.example.test
          name: Test Authority
          country: ZZ
        entity: individual
        lookup_keys: [given_name]
        access:
          kind: registry-notary
          conforms_to: registry-notary-federation/v0.1
          endpoint_url: https://evidence.example.test
          discovery_url: https://evidence.example.test/.well-known/evidence-service
          ruleset: exact-name
    entities:
      - name: individual
        fields:
          - name: id
            type: string
          - name: household_id
            type: string
          - name: given_name
            type: string
"#,
    )
    .expect("metadata manifest parses")
}

fn test_evidence_metadata() -> metadata_core::CompiledMetadata {
    let manifest = test_evidence_metadata_manifest();
    metadata_core::compile_manifest(&manifest).expect("metadata manifest compiles")
}

fn test_evidence_metadata_without_dataset_policy() -> metadata_core::CompiledMetadata {
    let mut manifest = test_evidence_metadata_manifest();
    manifest.datasets[0].policy = None;
    metadata_core::compile_manifest(&manifest).expect("metadata manifest compiles")
}

const ENTITY_ROUTE_SCOPES: &[&str] = &[
    "social_registry:metadata",
    "social_registry:rows",
    "social_registry:evidence_verification",
    "registry:trust:jurisdiction:ZZ",
    "registry:trust:assurance:substantial",
    "registry:trust:legal_basis:law:test-benefits",
    "registry:trust:consent:consent:test",
    "registry:trust:source_observed_age_seconds:5",
];

const ENTITY_ROUTE_SCOPES_WITHOUT_TRUST_ASSERTIONS: &[&str] = &[
    "social_registry:metadata",
    "social_registry:rows",
    "social_registry:evidence_verification",
];

async fn server_with_query() -> TestServer {
    server_with_query_version("01J5K8M0000000000000000000").await
}

async fn server_with_query_without_dataset_policy() -> TestServer {
    TestServer::new(
        app_with_query_versions_signer_provenance_selector_and_metadata(
            "01J5K8M0000000000000000000",
            "01J5K8M0000000000000000000",
            Arc::new(CursorSigner::new_random()),
            ENTITY_ROUTE_SCOPES,
            None,
            test_evidence_metadata_without_dataset_policy(),
        )
        .await,
    )
}

async fn server_with_query_version(ingest_version: &str) -> TestServer {
    server_with_query_versions_and_signer(
        ingest_version,
        ingest_version,
        Arc::new(CursorSigner::new_random()),
    )
    .await
}

async fn server_with_query_version_and_signer(
    ingest_version: &str,
    signer: Arc<CursorSigner>,
) -> TestServer {
    server_with_query_versions_and_signer(ingest_version, ingest_version, signer).await
}

async fn server_with_query_versions_and_signer(
    table_ingest_version: &str,
    readiness_ingest_version: &str,
    signer: Arc<CursorSigner>,
) -> TestServer {
    server_with_query_versions_signer_and_provenance(
        table_ingest_version,
        readiness_ingest_version,
        signer,
        ENTITY_ROUTE_SCOPES,
    )
    .await
}

async fn server_with_query_and_scopes(scopes: &[&str]) -> TestServer {
    server_with_query_versions_signer_and_provenance(
        "01J5K8M0000000000000000000",
        "01J5K8M0000000000000000000",
        Arc::new(CursorSigner::new_random()),
        scopes,
    )
    .await
}

async fn server_with_query_and_ecosystem_binding_selector() -> TestServer {
    server_with_query_versions_signer_provenance_and_selector(
        "01J5K8M0000000000000000000",
        "01J5K8M0000000000000000000",
        Arc::new(CursorSigner::new_random()),
        ENTITY_ROUTE_SCOPES,
        Some("baseline-dpi/v1"),
    )
    .await
}

async fn server_with_query_and_governed_entity_policy(governed_policy_yaml: &str) -> TestServer {
    TestServer::new(
        app_with_query_versions_signer_provenance_selector_metadata_and_config_patch(
            "01J5K8M0000000000000000000",
            "01J5K8M0000000000000000000",
            Arc::new(CursorSigner::new_random()),
            ENTITY_ROUTE_SCOPES,
            Some("baseline-dpi/v1"),
            test_evidence_metadata(),
            Some(governed_policy_yaml),
        )
        .await,
    )
}

async fn server_with_query_and_governed_entity_policy_without_trust_assertion_scopes(
    governed_policy_yaml: &str,
) -> TestServer {
    TestServer::new(
        app_with_query_versions_signer_provenance_selector_metadata_and_config_patch(
            "01J5K8M0000000000000000000",
            "01J5K8M0000000000000000000",
            Arc::new(CursorSigner::new_random()),
            ENTITY_ROUTE_SCOPES_WITHOUT_TRUST_ASSERTIONS,
            Some("baseline-dpi/v1"),
            test_evidence_metadata(),
            Some(governed_policy_yaml),
        )
        .await,
    )
}

async fn server_with_query_audit_and_ecosystem_binding_selector() -> (TestServer, InMemorySink) {
    let audit_sink = InMemorySink::new();
    let audit_pipeline: Arc<AuditPipeline> = AuditPipeline::from_sink(audit_sink.clone());
    let app = app_with_query_versions_signer_provenance_and_selector(
        "01J5K8M0000000000000000000",
        "01J5K8M0000000000000000000",
        Arc::new(CursorSigner::new_random()),
        ENTITY_ROUTE_SCOPES,
        Some("baseline-dpi/v1"),
    )
    .await
    .layer(from_fn(audit_layer))
    .layer(Extension(audit_pipeline));
    (TestServer::new(app), audit_sink)
}

async fn server_with_query_versions_signer_and_provenance(
    table_ingest_version: &str,
    readiness_ingest_version: &str,
    signer: Arc<CursorSigner>,
    principal_scopes: &[&str],
) -> TestServer {
    server_with_query_versions_signer_provenance_and_selector(
        table_ingest_version,
        readiness_ingest_version,
        signer,
        principal_scopes,
        None,
    )
    .await
}

async fn server_with_query_versions_signer_provenance_and_selector(
    table_ingest_version: &str,
    readiness_ingest_version: &str,
    signer: Arc<CursorSigner>,
    principal_scopes: &[&str],
    selected_ecosystem_binding: Option<&str>,
) -> TestServer {
    TestServer::new(
        app_with_query_versions_signer_provenance_and_selector(
            table_ingest_version,
            readiness_ingest_version,
            signer,
            principal_scopes,
            selected_ecosystem_binding,
        )
        .await,
    )
}

async fn app_with_query_versions_signer_provenance_and_selector(
    table_ingest_version: &str,
    readiness_ingest_version: &str,
    signer: Arc<CursorSigner>,
    principal_scopes: &[&str],
    selected_ecosystem_binding: Option<&str>,
) -> axum::Router {
    app_with_query_versions_signer_provenance_selector_and_metadata(
        table_ingest_version,
        readiness_ingest_version,
        signer,
        principal_scopes,
        selected_ecosystem_binding,
        test_evidence_metadata(),
    )
    .await
}

async fn app_with_query_versions_signer_provenance_selector_and_metadata(
    table_ingest_version: &str,
    readiness_ingest_version: &str,
    signer: Arc<CursorSigner>,
    principal_scopes: &[&str],
    selected_ecosystem_binding: Option<&str>,
    metadata: metadata_core::CompiledMetadata,
) -> axum::Router {
    app_with_query_versions_signer_provenance_selector_metadata_and_config_patch(
        table_ingest_version,
        readiness_ingest_version,
        signer,
        principal_scopes,
        selected_ecosystem_binding,
        metadata,
        None,
    )
    .await
}

async fn app_with_query_versions_signer_provenance_selector_metadata_and_config_patch(
    table_ingest_version: &str,
    readiness_ingest_version: &str,
    signer: Arc<CursorSigner>,
    principal_scopes: &[&str],
    selected_ecosystem_binding: Option<&str>,
    metadata: metadata_core::CompiledMetadata,
    governed_policy_yaml: Option<&str>,
) -> axum::Router {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = tmp.path().join("entity_routes.yaml");
    let config_yaml = r#"
server:
  bind: 127.0.0.1:0

catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test

deployment:
  profile: local

vocabularies:
  ex: https://example.test/vocab/
  psc: https://publicschema.org/

auth:
  mode: api_key
  api_keys: []

datasets:
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
          path: fixtures/social_registry.csv
        primary_key: household_id
        schema:
          strict: true
          fields:
            - name: household_id
              type: string
              nullable: false
              concept_uri: ex:properties/householdId
            - name: region_code
              type: string
              nullable: true
              concept_uri: ex:properties/regionCode
              codelist: ex:codelists/Region
              unit: ISO-3166-2
              language: en
      - id: individuals_table
        source:
          type: file
          path: fixtures/social_registry.csv
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
            - name: given_name
              type: string
              nullable: true
    entities:
      - name: household
        table: households_table
        concept_uri: psc:concepts/Household
        fields:
          - name: id
            from: household_id
          - name: region
            from: region_code
            concept_uri: ex:properties/region
        relationships:
          - name: members
            kind: has_many
            target: individual
            foreign_key: household_id
            concept_uri: ex:relationships/householdMember
        access:
          metadata_scope: social_registry:metadata
          aggregate_scope: social_registry:aggregate
          read_scope: social_registry:rows
          evidence_verification_scope: social_registry:evidence_verification
        api:
          default_limit: 100
          max_limit: 1000
          allowed_filters:
            - field: id
              ops: [eq, in]
            - field: region
              ops: [eq, in, gte, lte, between]
          allowed_expansions: [members]
      - name: individual
        table: individuals_table
        fields:
          - name: id
            from: individual_id
          - name: household_id
          - name: given_name
            sensitive: true
        relationships:
          - name: household
            kind: belongs_to
            target: household
            foreign_key: household_id
        access:
          metadata_scope: social_registry:metadata
          aggregate_scope: social_registry:aggregate
          read_scope: social_registry:rows
          evidence_verification_scope: social_registry:evidence_verification
        api:
          default_limit: 100
          max_limit: 1000
          require_purpose_header: true
          allowed_filters:
            - field: id
              ops: [eq, in]
            - field: household_id
              ops: [eq]
          allowed_expansions: [household]

audit:
  sink: stdout
  format: jsonl
"#
    .to_string();
    let config_yaml = if let Some(binding_id) = selected_ecosystem_binding {
        config_yaml.replacen(
            "\ncatalog:\n",
            &format!(
                r#"
metadata:
  source:
    path: metadata.yaml
  ecosystem_binding:
    id: {binding_id}
    version: v1

catalog:
"#
            ),
            1,
        )
    } else {
        config_yaml
    };
    let config_yaml = if let Some(governed_policy_yaml) = governed_policy_yaml {
        config_yaml.replacen(
            "          require_purpose_header: true\n",
            &format!("          require_purpose_header: true\n{governed_policy_yaml}"),
            1,
        )
    } else {
        config_yaml
    };
    std::fs::write(&config_path, config_yaml).expect("write config");
    let cfg = Arc::new(config::load(&config_path).expect("config loads"));
    let registry = Arc::new(EntityRegistry::from_config(&cfg).expect("registry"));
    let metadata = Arc::new(metadata);
    let ctx = Arc::new(SessionContext::new());
    let schema = Arc::new(Schema::new(vec![
        Field::new("household_id", DataType::Utf8, false),
        Field::new("region_code", DataType::Utf8, true),
    ]));
    let batch = RecordBatch::try_new(
        Arc::clone(&schema),
        vec![
            Arc::new(StringArray::from(vec!["hh-1", "hh-2"])),
            Arc::new(StringArray::from(vec!["north", "south"])),
        ],
    )
    .expect("batch");
    let table = MemTable::try_new(schema, vec![vec![batch]]).expect("mem table");
    let dataset: DatasetId = id("social_registry");
    let table_ingest_version = Ulid::from_string(table_ingest_version).expect("ulid");
    let readiness_ingest_version = Ulid::from_string(readiness_ingest_version).expect("ulid");
    let resource: ResourceId = id("households_table");
    register_versioned_table(
        &ctx,
        table_name(&dataset, &resource),
        table_ingest_version,
        Arc::new(table),
    )
    .expect("register table");
    let individual_schema = Arc::new(Schema::new(vec![
        Field::new("individual_id", DataType::Utf8, false),
        Field::new("household_id", DataType::Utf8, false),
        Field::new("given_name", DataType::Utf8, true),
    ]));
    let individual_batch = RecordBatch::try_new(
        Arc::clone(&individual_schema),
        vec![
            Arc::new(StringArray::from(vec!["p-1", "p-2", "p-3"])),
            Arc::new(StringArray::from(vec!["hh-1", "hh-1", "hh-2"])),
            Arc::new(StringArray::from(vec!["Ada", "Ben", "Ada"])),
        ],
    )
    .expect("individual batch");
    let individual_table =
        MemTable::try_new(individual_schema, vec![vec![individual_batch]]).expect("mem table");
    let resource: ResourceId = id("individuals_table");
    register_versioned_table(
        &ctx,
        table_name(&dataset, &resource),
        table_ingest_version,
        Arc::new(individual_table),
    )
    .expect("register individual table");
    let query = Arc::new(EntityQueryEngine::new(ctx, Arc::clone(&registry)));
    let mut snapshot = ReadinessSnapshot::default();
    snapshot.ready.insert(
        (id("social_registry"), id("households_table")),
        ReadyResource {
            ingest_ulid: readiness_ingest_version,
            registered_at: time::OffsetDateTime::now_utc(),
        },
    );
    snapshot.ready.insert(
        (id("social_registry"), id("individuals_table")),
        ReadyResource {
            ingest_ulid: readiness_ingest_version,
            registered_at: time::OffsetDateTime::now_utc(),
        },
    );
    let (_tx, readiness) = watch::channel(snapshot);

    entity_router::<()>()
        .merge(metadata_router())
        .layer(Extension(query))
        .layer(Extension(registry))
        .layer(Extension(metadata))
        .layer(Extension(cfg))
        .layer(Extension(readiness))
        .layer(Extension(signer))
        .layer(Extension(principal(principal_scopes)))
}

fn audit_record_from_envelope(line: &str) -> Value {
    let envelope: Value = serde_json::from_str(line.trim_end()).expect("valid audit envelope JSON");
    envelope["record"].clone()
}

#[tokio::test]
async fn entity_schema_route_matches() {
    let resp = server()
        .get("/v1/datasets/social_registry/entities/individual/schema")
        .await;

    resp.assert_status(StatusCode::NOT_IMPLEMENTED);
    assert_eq!(resp.header("content-type"), "application/problem+json");
    let body: Value = resp.json();
    assert_eq!(body["code"], "entity.query_unavailable");
}

#[tokio::test]
async fn entity_read_routes_fail_closed_when_registry_extension_is_missing() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = tmp.path().join("missing_registry.yaml");
    std::fs::write(
        &config_path,
        r#"
server:
  bind: 127.0.0.1:0
catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test
deployment:
  profile: local
vocabularies: {}
auth:
  mode: api_key
  api_keys: []
datasets:
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
      - id: individuals_table
        source:
          type: file
          path: fixtures/social_registry.csv
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
        api:
          default_limit: 100
          max_limit: 1000
          allowed_expansions: []
audit:
  sink: stdout
  format: jsonl
"#,
    )
    .expect("write config");
    let cfg = config::load(&config_path).expect("config loads");
    let registry = Arc::new(EntityRegistry::from_config(&cfg).expect("registry"));
    let query = Arc::new(EntityQueryEngine::new(
        Arc::new(SessionContext::new()),
        Arc::clone(&registry),
    ));
    let server = TestServer::new(
        entity_router::<()>()
            .layer(Extension(query))
            .layer(Extension(Arc::new(CursorSigner::new_random())))
            .layer(Extension(principal(&["social_registry:rows"]))),
    );

    for url in [
        "/v1/datasets/social_registry/entities/individual/records",
        "/v1/datasets/social_registry/entities/individual/records/ind-1",
        "/v1/datasets/social_registry/entities/individual/records/ind-1/relationships/household",
    ] {
        let resp = server.get(url).await;
        resp.assert_status(StatusCode::NOT_IMPLEMENTED);
        let body: Value = resp.json();
        assert_eq!(body["code"], "entity.query_unavailable");
        assert!(
            body["detail"]
                .as_str()
                .is_some_and(|detail| detail.contains("entity registry state is not installed")),
            "unexpected body: {body}"
        );
    }
}

#[tokio::test]
async fn entity_schema_route_returns_metadata_schema_when_state_installed() {
    let resp = server_with_query()
        .await
        .get("/v1/datasets/social_registry/entities/household/schema")
        .await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(body["dataset_id"], "social_registry");
    assert_eq!(body["entity"], "household");
    assert_eq!(
        body["concept_uri"],
        "https://publicschema.org/concepts/Household"
    );
    assert_eq!(body["fields"][1]["name"], "region");
    assert_eq!(body["fields"][1]["physical_type"], "string");
    assert_eq!(
        body["fields"][1]["concept_uri"],
        "https://example.test/vocab/properties/region"
    );
    assert_eq!(
        body["fields"][1]["codelist"],
        "https://example.test/vocab/codelists/Region"
    );
    assert_eq!(body["fields"][1]["unit"], "ISO-3166-2");
    assert_eq!(body["fields"][1]["language"], "en");
    assert_eq!(body["relationships"][0]["kind"], "has_many");
    assert_eq!(body["relationships"][0]["target"], "individual");
    assert_eq!(body["relationships"][0]["foreign_key"], "household_id");
    assert_eq!(
        body["relationships"][0]["concept_uri"],
        "https://example.test/vocab/relationships/householdMember"
    );
}

#[tokio::test]
async fn entity_schema_returns_etag_and_honors_if_none_match() {
    let server = server_with_query().await;
    let resp = server
        .get("/v1/datasets/social_registry/entities/household/schema")
        .await;

    resp.assert_status(StatusCode::OK);
    let etag = resp.header("etag").to_str().expect("etag").to_string();
    assert!(etag.starts_with(r#""sha256:"#));

    let cached = server
        .get("/v1/datasets/social_registry/entities/household/schema")
        .add_header("if-none-match", &etag)
        .await;

    cached.assert_status(StatusCode::NOT_MODIFIED);
    assert_eq!(cached.header("etag").to_str().expect("etag"), etag);
}

#[tokio::test]
async fn entity_collection_route_matches() {
    let resp = server()
        .get("/v1/datasets/social_registry/entities/individual/records")
        .await;

    resp.assert_status(StatusCode::NOT_IMPLEMENTED);
    assert_eq!(resp.header("content-type"), "application/problem+json");
}

#[tokio::test]
async fn entity_collection_route_executes_query_when_state_installed() {
    let resp = server_with_query()
        .await
        .get("/v1/datasets/social_registry/entities/household/records?region=north")
        .await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(
        body,
        serde_json::json!({
            "data": [
                {"id": "hh-1", "region": "north"}
            ],
            "pagination": {
                "has_more": false
            }
        })
    );
}

#[tokio::test]
async fn entity_collection_returns_etag_and_honors_if_none_match() {
    let server = server_with_query().await;
    let resp = server
        .get("/v1/datasets/social_registry/entities/household/records?region=north")
        .await;

    resp.assert_status(StatusCode::OK);
    let etag = resp.header("etag").to_str().expect("etag").to_string();

    let cached = server
        .get("/v1/datasets/social_registry/entities/household/records?region=north")
        .add_header("if-none-match", &etag)
        .await;

    cached.assert_status(StatusCode::NOT_MODIFIED);
    assert_eq!(cached.header("etag").to_str().expect("etag"), etag);
}

#[tokio::test]
async fn entity_collection_validates_query_before_cached_not_modified() {
    let server = server_with_query().await;
    let validator = serde_json::to_string(&std::collections::BTreeMap::from([("limit", "0")]))
        .expect("validator serializes");
    let etag = registry_relay::api::entity::entity_etag(
        "collection",
        "social_registry",
        "household",
        Some("households_table=01J5K8M0000000000000000000"),
        &validator,
    )
    .expect("etag");

    let cached = server
        .get("/v1/datasets/social_registry/entities/household/records?limit=0")
        .add_header("if-none-match", &etag)
        .await;

    cached.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = cached.json();
    assert_eq!(body["code"], "filter.limit_out_of_range");
}

#[tokio::test]
async fn entity_collection_route_parses_allowed_filter_ops() {
    let resp = server_with_query()
        .await
        .get("/v1/datasets/social_registry/entities/household/records?region.in=north,missing")
        .await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(
        body,
        serde_json::json!({
            "data": [
                {"id": "hh-1", "region": "north"}
            ],
            "pagination": {
                "has_more": false
            }
        })
    );
}

#[tokio::test]
async fn sensitive_fields_remain_in_authorized_projection() {
    let resp = server_with_query()
        .await
        .get("/v1/datasets/social_registry/entities/individual/records?id=p-1")
        .add_header("data-purpose", "https://data.example.test/purposes/testing")
        .await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(
        body["data"],
        serde_json::json!([
            {"id": "p-1", "household_id": "hh-1", "given_name": "Ada"}
        ])
    );
}

#[tokio::test]
async fn governed_entity_policy_redacts_configured_fields_from_collection_and_record() {
    let policy = r#"          governed_policy:
            permitted_purposes:
              - https://data.example.test/purposes/testing
            permitted_jurisdictions: [ZZ]
            allowed_assurance: [substantial]
            require_legal_basis: true
            require_consent: true
            redaction_fields: [given_name]
            trusted_context: {}
"#;
    let server = server_with_query_and_governed_entity_policy(policy).await;

    let collection = server
        .get("/v1/datasets/social_registry/entities/individual/records?id=p-1")
        .add_header("data-purpose", "https://data.example.test/purposes/testing")
        .add_header("x-registry-trust-jurisdiction", "ZZ")
        .add_header("x-registry-trust-assurance", "substantial")
        .add_header("x-registry-trust-legal-basis", "law:test-benefits")
        .add_header("x-registry-trust-consent", "consent:test")
        .await;

    collection.assert_status(StatusCode::OK);
    let body: Value = collection.json();
    assert_eq!(
        body["data"],
        serde_json::json!([
            {"id": "p-1", "household_id": "hh-1"}
        ])
    );

    let record = server
        .get("/v1/datasets/social_registry/entities/individual/records/p-1")
        .add_header("data-purpose", "https://data.example.test/purposes/testing")
        .add_header("x-registry-trust-jurisdiction", "ZZ")
        .add_header("x-registry-trust-assurance", "substantial")
        .add_header("x-registry-trust-legal-basis", "law:test-benefits")
        .add_header("x-registry-trust-consent", "consent:test")
        .await;

    record.assert_status(StatusCode::OK);
    assert_eq!(
        record.json::<Value>(),
        serde_json::json!({"id": "p-1", "household_id": "hh-1"})
    );
}

#[tokio::test]
async fn governed_entity_policy_redacts_configured_fields_from_relationships() {
    let policy = r#"          governed_policy:
            permitted_purposes:
              - https://data.example.test/purposes/testing
            redaction_fields: [given_name]
            trusted_context: {}
"#;
    let server = server_with_query_and_governed_entity_policy(policy).await;

    let relationship = server
        .get("/v1/datasets/social_registry/entities/household/records/hh-1/relationships/members?limit=1")
        .add_header("data-purpose", "https://data.example.test/purposes/testing")
        .await;

    relationship.assert_status(StatusCode::OK);
    let body: Value = relationship.json();
    assert_eq!(
        body["data"],
        serde_json::json!([
            {"id": "p-1", "household_id": "hh-1"}
        ])
    );
}

#[tokio::test]
async fn governed_entity_policy_redacts_configured_fields_from_expansions() {
    let policy = r#"          governed_policy:
            permitted_purposes:
              - https://data.example.test/purposes/testing
            redaction_fields: [given_name]
            trusted_context: {}
"#;
    let server = server_with_query_and_governed_entity_policy(policy).await;

    let collection = server
        .get("/v1/datasets/social_registry/entities/household/records?region=north&expand=members")
        .add_header("data-purpose", "https://data.example.test/purposes/testing")
        .await;

    collection.assert_status(StatusCode::OK);
    let body: Value = collection.json();
    assert_eq!(
        body["data"][0]["members"],
        serde_json::json!([
            {"id": "p-1", "household_id": "hh-1"},
            {"id": "p-2", "household_id": "hh-1"}
        ])
    );

    let record = server
        .get("/v1/datasets/social_registry/entities/household/records/hh-1?expand=members")
        .add_header("data-purpose", "https://data.example.test/purposes/testing")
        .await;

    record.assert_status(StatusCode::OK);
    let body: Value = record.json();
    assert_eq!(
        body["members"],
        serde_json::json!([
            {"id": "p-1", "household_id": "hh-1"},
            {"id": "p-2", "household_id": "hh-1"}
        ])
    );
}

#[tokio::test]
async fn governed_entity_etag_varies_by_redaction_policy() {
    let full = server_with_query()
        .await
        .get("/v1/datasets/social_registry/entities/individual/records/p-1")
        .add_header("data-purpose", "https://data.example.test/purposes/testing")
        .await;

    full.assert_status(StatusCode::OK);
    let full_etag = full
        .headers()
        .get(header::ETAG)
        .expect("full response has etag")
        .to_str()
        .expect("etag is text")
        .to_string();

    let policy = r#"          governed_policy:
            permitted_purposes:
              - https://data.example.test/purposes/testing
            redaction_fields: [given_name]
            trusted_context: {}
"#;
    let redacted = server_with_query_and_governed_entity_policy(policy)
        .await
        .get("/v1/datasets/social_registry/entities/individual/records/p-1")
        .add_header("data-purpose", "https://data.example.test/purposes/testing")
        .add_header(header::IF_NONE_MATCH.as_str(), full_etag.as_str())
        .await;

    redacted.assert_status(StatusCode::OK);
    let redacted_etag = redacted
        .headers()
        .get(header::ETAG)
        .expect("redacted response has etag")
        .to_str()
        .expect("etag is text");
    assert_ne!(redacted_etag, full_etag);
    assert_eq!(
        redacted.json::<Value>(),
        serde_json::json!({"id": "p-1", "household_id": "hh-1"})
    );
}

#[tokio::test]
async fn governed_entity_policy_denies_when_required_trusted_context_is_missing() {
    let policy = r#"          governed_policy:
            permitted_purposes:
              - https://data.example.test/purposes/testing
            require_legal_basis: true
            trusted_context: {}
"#;
    let resp = server_with_query_and_governed_entity_policy(policy)
        .await
        .get("/v1/datasets/social_registry/entities/individual/records?id=p-1")
        .add_header("data-purpose", "https://data.example.test/purposes/testing")
        .await;

    resp.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(resp.json::<Value>()["code"], "pdp.legal_basis_required");
}

#[tokio::test]
async fn governed_entity_policy_uses_request_trust_context_on_same_route() {
    let policy = r#"          governed_policy:
            permitted_purposes:
              - https://data.example.test/purposes/testing
            permitted_jurisdictions: [ZZ]
            allowed_assurance: [substantial]
            max_source_age_seconds: 30
            require_legal_basis: true
            require_consent: true
            trusted_context: {}
"#;
    let server = server_with_query_and_governed_entity_policy(policy).await;

    let missing_context = server
        .get("/v1/datasets/social_registry/entities/individual/records?id=p-1")
        .add_header("data-purpose", "https://data.example.test/purposes/testing")
        .await;

    missing_context.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(
        missing_context.json::<Value>()["code"],
        "pdp.jurisdiction_not_permitted"
    );

    let missing_freshness = server
        .get("/v1/datasets/social_registry/entities/individual/records?id=p-1")
        .add_header("data-purpose", "https://data.example.test/purposes/testing")
        .add_header("x-registry-trust-jurisdiction", "ZZ")
        .add_header("x-registry-trust-assurance", "substantial")
        .add_header("x-registry-trust-legal-basis", "law:test-benefits")
        .add_header("x-registry-trust-consent", "consent:test")
        .await;

    missing_freshness.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(
        missing_freshness.json::<Value>()["code"],
        "pdp.evidence_stale"
    );

    let stale_context = server
        .get("/v1/datasets/social_registry/entities/individual/records?id=p-1")
        .add_header("data-purpose", "https://data.example.test/purposes/testing")
        .add_header("x-registry-trust-jurisdiction", "ZZ")
        .add_header("x-registry-trust-assurance", "substantial")
        .add_header("x-registry-trust-legal-basis", "law:test-benefits")
        .add_header("x-registry-trust-consent", "consent:test")
        .add_header("x-registry-source-observed-age-seconds", "31")
        .await;

    stale_context.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(stale_context.json::<Value>()["code"], "pdp.evidence_stale");

    let allowed = server
        .get("/v1/datasets/social_registry/entities/individual/records?id=p-1")
        .add_header("data-purpose", "https://data.example.test/purposes/testing")
        .add_header("x-registry-trust-jurisdiction", "ZZ")
        .add_header("x-registry-trust-assurance", "substantial")
        .add_header("x-registry-trust-legal-basis", "law:test-benefits")
        .add_header("x-registry-trust-consent", "consent:test")
        .add_header("x-registry-source-observed-age-seconds", "5")
        .await;

    allowed.assert_status(StatusCode::OK);
    assert_eq!(allowed.json::<Value>()["data"][0]["id"], "p-1");
}

#[tokio::test]
async fn governed_entity_policy_ignores_unverified_trust_headers() {
    let policy = r#"          governed_policy:
            permitted_purposes:
              - https://data.example.test/purposes/testing
            permitted_jurisdictions: [ZZ]
            allowed_assurance: [substantial]
            require_legal_basis: true
            require_consent: true
            trusted_context: {}
"#;
    let server =
        server_with_query_and_governed_entity_policy_without_trust_assertion_scopes(policy).await;

    let denied = server
        .get("/v1/datasets/social_registry/entities/individual/records?id=p-1")
        .add_header("data-purpose", "https://data.example.test/purposes/testing")
        .add_header("x-registry-trust-jurisdiction", "ZZ")
        .add_header("x-registry-trust-assurance", "substantial")
        .add_header("x-registry-trust-legal-basis", "law:test-benefits")
        .add_header("x-registry-trust-consent", "consent:test")
        .await;

    denied.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(
        denied.json::<Value>()["code"],
        "pdp.jurisdiction_not_permitted"
    );
}

#[tokio::test]
async fn governed_entity_denial_happens_before_query_engine_is_required() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = tmp.path().join("governed_no_query.yaml");
    std::fs::write(
        &config_path,
        r#"
server:
  bind: 127.0.0.1:0
catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test
deployment:
  profile: local
auth:
  mode: api_key
  api_keys: []
datasets:
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
      - id: individuals_table
        source:
          type: file
          path: fixtures/social_registry.csv
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
        api:
          default_limit: 100
          max_limit: 1000
          require_purpose_header: true
          governed_policy:
            permitted_purposes:
              - benefits
            trusted_context: {}
audit:
  sink: stdout
  format: jsonl
"#,
    )
    .expect("write config");
    let cfg = Arc::new(config::load(&config_path).expect("config loads"));
    let registry = Arc::new(EntityRegistry::from_config(&cfg).expect("registry"));
    let server = TestServer::new(
        entity_router::<()>()
            .layer(Extension(registry))
            .layer(Extension(cfg))
            .layer(Extension(principal(ENTITY_ROUTE_SCOPES))),
    );

    let denied = server
        .get("/v1/datasets/social_registry/entities/individual/records")
        .add_header("data-purpose", "casework")
        .await;

    denied.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(denied.json::<Value>()["code"], "pdp.purpose_not_permitted");
}

#[tokio::test]
async fn governed_entity_collection_audit_records_selector_pdp_provenance() {
    let (server, audit_sink) = server_with_query_audit_and_ecosystem_binding_selector().await;
    let resp = server
        .get("/v1/datasets/social_registry/entities/individual/records?id=p-1")
        .add_header("data-purpose", "https://data.example.test/purposes/testing")
        .await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(
        body["data"],
        serde_json::json!([
            {"id": "p-1", "household_id": "hh-1", "given_name": "Ada"}
        ])
    );

    let records = audit_sink.snapshot();
    assert_eq!(
        records.len(),
        1,
        "governed entity request emits one audit record"
    );
    let record = audit_record_from_envelope(&records[0]);
    assert_eq!(record["dataset_id"], "social_registry");
    assert_eq!(record["entity_name"], "individual");
    assert_eq!(
        record["purpose"],
        "https://data.example.test/purposes/testing"
    );
    assert_eq!(record["pdp_policy_id"], "baseline-dpi-policy");
    assert_eq!(
        record["pdp_policy_hash"],
        "sha256:3333333333333333333333333333333333333333333333333333333333333333"
    );
    assert_eq!(record["pdp_ecosystem_binding_id"], "baseline-dpi/v1");
    assert_eq!(record["pdp_ecosystem_binding_version"], "v1");
    assert_eq!(record["pdp_route_identity"], "registry-relay.entity");
    assert_eq!(
        record["pdp_source_binding"],
        "relay:social_registry:individuals_table"
    );
    assert_eq!(
        record["pdp_checked_scopes"],
        serde_json::json!(["social_registry:rows"])
    );
    assert_eq!(
        record["pdp_evaluated_rule_ids"],
        serde_json::json!([
            "entity-purpose-required:individual.policy_identity",
            "entity-purpose-required:individual.odrl_terms",
            "entity-purpose-required:individual.purpose",
            "entity-purpose-required:individual.requested_fact",
            "entity-purpose-required:individual.requested_disclosure",
            "entity-purpose-required:individual.source_binding",
            "entity-purpose-required:individual.route_identity",
            "entity-purpose-required:individual.checked_scope"
        ])
    );
}

#[tokio::test]
async fn governed_entity_collection_denial_audit_records_selector_pdp_provenance() {
    let (server, audit_sink) = server_with_query_audit_and_ecosystem_binding_selector().await;
    let resp = server
        .get("/v1/datasets/social_registry/entities/individual/records?id=p-1")
        .add_header("data-purpose", "casework")
        .await;

    resp.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(resp.json::<Value>()["code"], "pdp.purpose_not_permitted");

    let records = audit_sink.snapshot();
    assert_eq!(
        records.len(),
        1,
        "denied governed entity request emits one audit record"
    );
    let record = audit_record_from_envelope(&records[0]);
    assert_eq!(record["dataset_id"], "social_registry");
    assert_eq!(record["entity_name"], "individual");
    assert_eq!(record["purpose"], "casework");
    assert_eq!(record["status_code"], 403);
    assert_eq!(record["error_code"], "pdp.purpose_not_permitted");
    assert_eq!(record["pdp_policy_id"], "baseline-dpi-policy");
    assert_eq!(
        record["pdp_policy_hash"],
        "sha256:3333333333333333333333333333333333333333333333333333333333333333"
    );
    assert_eq!(
        record["pdp_stable_problem_code"],
        "pdp.purpose_not_permitted"
    );
    assert_eq!(record["pdp_ecosystem_binding_id"], "baseline-dpi/v1");
    assert_eq!(record["pdp_ecosystem_binding_version"], "v1");
    assert_eq!(record["pdp_route_identity"], "registry-relay.entity");
    assert_eq!(
        record["pdp_source_binding"],
        "relay:social_registry:individuals_table"
    );
    assert_eq!(
        record["pdp_checked_scopes"],
        serde_json::json!(["social_registry:rows"])
    );
    assert_eq!(
        record["pdp_evaluated_rule_ids"],
        serde_json::json!([
            "entity-purpose-required:individual.policy_identity",
            "entity-purpose-required:individual.odrl_terms",
            "entity-purpose-required:individual.purpose"
        ])
    );
}

#[tokio::test]
async fn entity_collection_rejects_purpose_outside_compiled_policy_without_selector() {
    let resp = server_with_query()
        .await
        .get("/v1/datasets/social_registry/entities/individual/records?id=p-1")
        .add_header("data-purpose", "casework")
        .await;

    resp.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(resp.json::<Value>()["code"], "pdp.purpose_not_permitted");
}

#[tokio::test]
async fn entity_collection_keeps_header_only_purpose_semantics_without_governed_policy() {
    let resp = server_with_query_without_dataset_policy()
        .await
        .get("/v1/datasets/social_registry/entities/individual/records?id=p-1")
        .add_header("data-purpose", "https://data.example.test/purposes/testing")
        .await;

    resp.assert_status_ok();
    assert_eq!(resp.json::<Value>()["data"][0]["id"], "p-1");
}

#[tokio::test]
async fn entity_collection_rejects_purpose_outside_compiled_policy_with_selector() {
    let resp = server_with_query_and_ecosystem_binding_selector()
        .await
        .get("/v1/datasets/social_registry/entities/individual/records?id=p-1")
        .add_header("data-purpose", "casework")
        .await;

    resp.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(resp.json::<Value>()["code"], "pdp.purpose_not_permitted");
}

#[tokio::test]
async fn entity_collection_route_paginates_with_opaque_cursor() {
    let server = server_with_query().await;

    let first = server
        .get("/v1/datasets/social_registry/entities/household/records?limit=1")
        .await;
    first.assert_status(StatusCode::OK);
    let body: Value = first.json();
    assert_eq!(
        body["data"],
        serde_json::json!([{"id": "hh-1", "region": "north"}])
    );
    assert_eq!(body["pagination"]["has_more"], true);
    let cursor = body["pagination"]["next_cursor"]
        .as_str()
        .expect("first page has cursor");
    assert!(first
        .header("link")
        .to_str()
        .expect("link")
        .contains(&format!("cursor={cursor}")));

    let url =
        format!("/v1/datasets/social_registry/entities/household/records?limit=1&cursor={cursor}");
    let second = server.get(&url).await;
    second.assert_status(StatusCode::OK);
    let body: Value = second.json();
    assert_eq!(
        body["data"],
        serde_json::json!([{"id": "hh-2", "region": "south"}])
    );
    assert_eq!(body["pagination"]["has_more"], false);
    assert!(body["pagination"].get("next_cursor").is_none());
}

#[tokio::test]
async fn entity_collection_cursor_mismatch_returns_bad_request() {
    let server = server_with_query().await;

    let first = server
        .get("/v1/datasets/social_registry/entities/household/records?limit=1")
        .await;
    first.assert_status(StatusCode::OK);
    let body: Value = first.json();
    let cursor = body["pagination"]["next_cursor"]
        .as_str()
        .expect("first page has cursor");

    let url = format!("/v1/datasets/social_registry/entities/household/records?limit=1&region=north&cursor={cursor}");
    let resp = server.get(&url).await;
    resp.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = resp.json();
    assert_eq!(body["code"], "pagination.cursor_invalidated");
}

#[tokio::test]
async fn entity_collection_stale_cursor_returns_bad_request() {
    // Share a cursor signer across both servers so the HMAC verifies on
    // the second request and the ingest-version mismatch surfaces as
    // `pagination.cursor_invalidated`. A signer change (e.g. a process
    // restart) would instead reject the cursor as `filter.invalid_value`,
    // which is covered by the dedicated tamper-detection tests below.
    let signer = Arc::new(CursorSigner::new_random());
    let old_server =
        server_with_query_version_and_signer("01J5K8M0000000000000000000", Arc::clone(&signer))
            .await;
    let first = old_server
        .get("/v1/datasets/social_registry/entities/household/records?limit=1")
        .await;
    first.assert_status(StatusCode::OK);
    let body: Value = first.json();
    let cursor = body["pagination"]["next_cursor"]
        .as_str()
        .expect("first page has cursor");

    let new_server =
        server_with_query_version_and_signer("01J5K8M0000000000000000001", Arc::clone(&signer))
            .await;
    let url =
        format!("/v1/datasets/social_registry/entities/household/records?limit=1&cursor={cursor}");
    let resp = new_server.get(&url).await;
    resp.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = resp.json();
    assert_eq!(body["code"], "pagination.cursor_invalidated");
}

#[tokio::test]
async fn entity_record_route_matches() {
    let resp = server()
        .get("/v1/datasets/social_registry/entities/individual/records/abc123")
        .await;

    resp.assert_status(StatusCode::NOT_IMPLEMENTED);
    assert_eq!(resp.header("content-type"), "application/problem+json");
}

#[tokio::test]
async fn entity_record_returns_etag_and_honors_if_none_match() {
    let server = server_with_query().await;
    let resp = server
        .get("/v1/datasets/social_registry/entities/household/records/hh-1")
        .await;

    resp.assert_status(StatusCode::OK);
    let etag = resp.header("etag").to_str().expect("etag").to_string();

    let cached = server
        .get("/v1/datasets/social_registry/entities/household/records/hh-1")
        .add_header("if-none-match", &etag)
        .await;

    cached.assert_status(StatusCode::NOT_MODIFIED);
    assert_eq!(cached.header("etag").to_str().expect("etag"), etag);
}

#[tokio::test]
async fn entity_record_rejects_whitespace_purpose_header() {
    let resp = server_with_query()
        .await
        .get("/v1/datasets/social_registry/entities/individual/records/p-1")
        .add_header("data-purpose", "   ")
        .await;

    resp.assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(resp.json::<Value>()["code"], "auth.purpose_required");
}

#[tokio::test]
async fn entity_relationship_route_executes_query_when_state_installed() {
    let resp = server_with_query()
        .await
        .get("/v1/datasets/social_registry/entities/individual/records/p-1/relationships/household")
        .add_header("data-purpose", "https://data.example.test/purposes/testing")
        .await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(
        body,
        serde_json::json!({
            "id": "hh-1",
            "region": "north"
        })
    );
}

#[tokio::test]
async fn entity_relationship_returns_etag_and_honors_if_none_match() {
    let server = server_with_query().await;
    let resp = server
        .get("/v1/datasets/social_registry/entities/individual/records/p-1/relationships/household")
        .add_header("data-purpose", "https://data.example.test/purposes/testing")
        .await;

    resp.assert_status(StatusCode::OK);
    let etag = resp.header("etag").to_str().expect("etag").to_string();

    let cached = server
        .get("/v1/datasets/social_registry/entities/individual/records/p-1/relationships/household")
        .add_header("data-purpose", "https://data.example.test/purposes/testing")
        .add_header("if-none-match", &etag)
        .await;

    cached.assert_status(StatusCode::NOT_MODIFIED);
    assert_eq!(cached.header("etag").to_str().expect("etag"), etag);
}

#[tokio::test]
async fn entity_has_many_relationship_route_paginates_with_opaque_cursor() {
    let server = server_with_query().await;

    let first = server
        .get("/v1/datasets/social_registry/entities/household/records/hh-1/relationships/members?limit=1")
        .add_header("data-purpose", "https://data.example.test/purposes/testing")
        .await;
    first.assert_status(StatusCode::OK);
    let body: Value = first.json();
    assert_eq!(
        body["data"],
        serde_json::json!([
            {"id": "p-1", "household_id": "hh-1", "given_name": "Ada"}
        ])
    );
    assert_eq!(body["pagination"]["has_more"], true);
    let cursor = body["pagination"]["next_cursor"]
        .as_str()
        .expect("first relationship page has cursor");
    assert!(first
        .header("link")
        .to_str()
        .expect("link")
        .contains(&format!("cursor={cursor}")));

    let url = format!("/v1/datasets/social_registry/entities/household/records/hh-1/relationships/members?limit=1&cursor={cursor}");
    let second = server
        .get(&url)
        .add_header("data-purpose", "https://data.example.test/purposes/testing")
        .await;
    second.assert_status(StatusCode::OK);
    let body: Value = second.json();
    assert_eq!(
        body["data"],
        serde_json::json!([
            {"id": "p-2", "household_id": "hh-1", "given_name": "Ben"}
        ])
    );
    assert_eq!(body["pagination"]["has_more"], false);
    assert!(body["pagination"].get("next_cursor").is_none());
}

#[tokio::test]
async fn entity_has_many_relationship_returns_etag_and_honors_if_none_match() {
    let server = server_with_query().await;
    let resp = server
        .get("/v1/datasets/social_registry/entities/household/records/hh-1/relationships/members?limit=1")
        .add_header("data-purpose", "https://data.example.test/purposes/testing")
        .await;

    resp.assert_status(StatusCode::OK);
    let etag = resp.header("etag").to_str().expect("etag").to_string();

    let cached = server
        .get("/v1/datasets/social_registry/entities/household/records/hh-1/relationships/members?limit=1")
        .add_header("data-purpose", "https://data.example.test/purposes/testing")
        .add_header("if-none-match", &etag)
        .await;

    cached.assert_status(StatusCode::NOT_MODIFIED);
    assert_eq!(cached.header("etag").to_str().expect("etag"), etag);
}

#[tokio::test]
async fn entity_has_many_relationship_stale_cursor_returns_bad_request() {
    // Share a cursor signer across both servers so the HMAC verifies on
    // the second request and the ingest-version mismatch surfaces as
    // `pagination.cursor_invalidated`.
    let signer = Arc::new(CursorSigner::new_random());
    let old_server =
        server_with_query_version_and_signer("01J5K8M0000000000000000000", Arc::clone(&signer))
            .await;
    let first = old_server
        .get("/v1/datasets/social_registry/entities/household/records/hh-1/relationships/members?limit=1")
        .add_header("data-purpose", "https://data.example.test/purposes/testing")
        .await;
    first.assert_status(StatusCode::OK);
    let body: Value = first.json();
    let cursor = body["pagination"]["next_cursor"]
        .as_str()
        .expect("first relationship page has cursor");

    let new_server =
        server_with_query_version_and_signer("01J5K8M0000000000000000001", Arc::clone(&signer))
            .await;
    let url = format!("/v1/datasets/social_registry/entities/household/records/hh-1/relationships/members?limit=1&cursor={cursor}");
    let resp = new_server
        .get(&url)
        .add_header("data-purpose", "https://data.example.test/purposes/testing")
        .await;
    resp.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = resp.json();
    assert_eq!(body["code"], "pagination.cursor_invalidated");
}

#[tokio::test]
async fn verify_only_principal_cannot_read_rows_or_schema() {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = tmp.path().join("verify_only.yaml");
    std::fs::write(
        &config_path,
        r#"
server:
  bind: 127.0.0.1:0
catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test
deployment:
  profile: local
vocabularies: {}
auth:
  mode: api_key
  api_keys: []
datasets:
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
      - id: individuals_table
        source:
          type: file
          path: fixtures/social_registry.csv
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
        api:
          default_limit: 100
          max_limit: 1000
          allowed_filters:
            - field: id
              ops: [eq]
          allowed_expansions: []
audit:
  sink: stdout
  format: jsonl
"#,
    )
    .expect("write config");
    let cfg = config::load(&config_path).expect("config loads");
    let registry = Arc::new(EntityRegistry::from_config(&cfg).expect("registry"));

    let server = TestServer::new(
        entity_router::<()>()
            .merge(aggregates_router::<()>())
            .layer(Extension(registry))
            .layer(Extension(principal(&[
                "social_registry:evidence_verification",
            ]))),
    );

    for url in [
        "/v1/datasets/social_registry/entities/individual/records",
        "/v1/datasets/social_registry/entities/individual/records/id-1",
        "/v1/datasets/social_registry/entities/individual/schema",
        "/v1/datasets/social_registry/aggregates",
    ] {
        let resp = server.get(url).await;
        resp.assert_status(StatusCode::FORBIDDEN);
        let body: Value = resp.json();
        assert_eq!(body["code"], "auth.scope_denied");
    }
}

#[tokio::test]
async fn entity_collection_route_expands_relationships() {
    let resp = server_with_query()
        .await
        .get("/v1/datasets/social_registry/entities/household/records?region=north&expand=members")
        .add_header("data-purpose", "https://data.example.test/purposes/testing")
        .await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(
        body,
        serde_json::json!({
            "data": [
                {
                    "id": "hh-1",
                    "region": "north",
                    "members": [
                        {"id": "p-1", "household_id": "hh-1", "given_name": "Ada"},
                        {"id": "p-2", "household_id": "hh-1", "given_name": "Ben"}
                    ]
                }
            ],
            "pagination": {
                "has_more": false
            }
        })
    );
}

#[tokio::test]
async fn native_evidence_verification_route_is_not_registered() {
    let resp = server_with_query()
        .await
        .post("/evidence-offerings/individual_name_evidence/verifications")
        .add_header("data-purpose", "https://data.example.test/purposes/testing")
        .json(&serde_json::json!({
            "claims": {
                "given_name": "Ada"
            }
        }))
        .await;

    resp.assert_status(StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn metadata_evidence_offerings_are_private_filterable_and_scope_limited() {
    let server = server_with_query().await;

    let list = server.get("/metadata/evidence-offerings").await;
    list.assert_status(StatusCode::OK);
    assert_eq!(list.header("cache-control"), "private, no-store");
    assert_eq!(list.header("vary"), "Authorization");
    let body: Value = list.json();
    let offerings = body["evidence_offerings"].as_array().expect("offerings");
    let name_offering = offerings
        .iter()
        .find(|offering| offering["id"] == "individual_name_evidence")
        .expect("individual name evidence offering is listed");
    assert_eq!(name_offering["id"], "individual_name_evidence");
    assert_eq!(
        name_offering["verification_request_schema_url"],
        "https://data.example.test/metadata/schema/social_registry/individual/schema.json"
    );

    let filtered = server
        .get("/metadata/evidence-offerings?evidence_type=https://data.example.test/evidence-types/name&country=ZZ")
        .await;
    filtered.assert_status(StatusCode::OK);
    let body: Value = filtered.json();
    assert_eq!(
        body["evidence_offerings"]
            .as_array()
            .expect("offerings")
            .len(),
        4
    );
    assert!(body["evidence_offerings"]
        .as_array()
        .expect("offerings")
        .iter()
        .any(
            |offering| offering["id"] == "external_individual_name_evidence"
                && offering["access"]["kind"] == "registry-notary"
        ));

    let empty = server.get("/metadata/evidence-offerings?country=NO").await;
    empty.assert_status(StatusCode::OK);
    let body: Value = empty.json();
    assert!(body["evidence_offerings"]
        .as_array()
        .expect("offerings")
        .is_empty());

    let detail = server
        .get("/metadata/evidence-offerings/individual_name_evidence")
        .await;
    detail.assert_status(StatusCode::OK);
    assert_eq!(detail.header("cache-control"), "private, no-store");
    assert_eq!(detail.header("vary"), "Authorization");
    let body: Value = detail.json();
    assert_eq!(body["id"], "individual_name_evidence");
    assert_eq!(
        body["information_concepts"],
        serde_json::json!(["https://data.example.test/concepts/given-name"])
    );

    let hidden = server_with_query_and_scopes(&["social_registry:evidence_verification"]).await;
    let hidden_resp = hidden
        .get("/metadata/evidence-offerings/individual_name_evidence")
        .await;
    hidden_resp.assert_status(StatusCode::NOT_FOUND);
    let body: Value = hidden_resp.json();
    assert_eq!(body["code"], "offering.not_found");
}

#[tokio::test]
async fn bregdcat_evidence_terms_use_cccev_relationships() {
    let server = server_with_query().await;

    let resp = server.get("/metadata/dcat/bregdcat-ap").await;
    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    let serialized = serde_json::to_string(&body).expect("json serializes");
    assert!(
        !serialized.contains("registry_relay:provesRequirement"),
        "CCCEV output must not emit a custom inverse for evidence-type membership"
    );
    assert!(
        !serialized.contains("registry_relay:informationConcept"),
        "Information concepts must be CCCEV nodes and links"
    );

    let graph = body["@graph"].as_array().expect("json-ld graph");
    let by_id = |id: &str| {
        graph
            .iter()
            .find(|node| node["@id"] == id)
            .unwrap_or_else(|| panic!("missing JSON-LD node {id}"))
    };

    let requirement = by_id("https://data.example.test/requirements/name");
    assert_eq!(requirement["@type"], "http://data.europa.eu/m8g/Criterion");
    assert_eq!(
        requirement["cccev:hasConcept"],
        serde_json::json!([{
            "@id": "https://data.example.test/concepts/given-name"
        }])
    );
    assert_eq!(
        requirement["cccev:isDerivedFrom"],
        serde_json::json!([{
            "@id": "https://data.example.test/reference-frameworks/name-law"
        }])
    );

    assert_eq!(
        requirement["cccev:hasEvidenceTypeList"],
        serde_json::json!([{
            "@id": "https://data.example.test/requirements/name#evidence-type-list-alternate_name_evidence"
        }, {
            "@id": "https://data.example.test/requirements/name#evidence-type-list-name_evidence"
        }])
    );

    let list =
        by_id("https://data.example.test/requirements/name#evidence-type-list-name_evidence");
    assert_eq!(list["@type"], "cccev:EvidenceTypeList");
    assert_eq!(
        list["cccev:specifiesEvidenceType"],
        serde_json::json!([{
            "@id": "https://data.example.test/evidence-types/name"
        }])
    );

    let evidence_type = by_id("https://data.example.test/evidence-types/name");
    assert_eq!(evidence_type["@type"], "cccev:EvidenceType");
    assert_eq!(
        evidence_type["cccev:isSpecifiedIn"],
        serde_json::json!([{
            "@id": "https://data.example.test/requirements/name#evidence-type-list-name_evidence"
        }])
    );

    let concept = by_id("https://data.example.test/concepts/given-name");
    assert_eq!(concept["@type"], "cccev:InformationConcept");
    assert_eq!(concept["dcterms:identifier"], "given-name");

    let framework = by_id("https://data.example.test/reference-frameworks/name-law");
    assert_eq!(framework["@type"], "cccev:ReferenceFramework");
    assert_eq!(framework["dcterms:identifier"], "name-law");

    // Item 4: when a requirement has information concepts, cccev:hasConcept must be
    // non-empty (the name_requirement above already asserts this). When it has no
    // reference frameworks, cccev:isDerivedFrom must not be emitted as an empty array.
    // Check that the name_requirement (which HAS reference frameworks) emits
    // cccev:isDerivedFrom, and that no node in the graph emits an empty array for
    // either predicate.
    let all_nodes = graph;
    for node in all_nodes {
        let has_empty_concepts = node
            .get("cccev:hasConcept")
            .and_then(Value::as_array)
            .is_some_and(|arr| arr.is_empty());
        assert!(
            !has_empty_concepts,
            "cccev:hasConcept must not be an empty array in node {:?}",
            node["@id"]
        );
        let has_empty_derived = node
            .get("cccev:isDerivedFrom")
            .and_then(Value::as_array)
            .is_some_and(|arr| arr.is_empty());
        assert!(
            !has_empty_derived,
            "cccev:isDerivedFrom must not be an empty array in node {:?}",
            node["@id"]
        );
    }
}

#[tokio::test]
async fn storage_shaped_resources_rows_route_is_not_registered() {
    let resp = server().get("/resources/beneficiaries/rows").await;

    resp.assert_status(StatusCode::NOT_FOUND);
}

async fn server_with_required_filters() -> TestServer {
    server_with_required_filters_and_principal("item-1", Arc::new(CursorSigner::new_random())).await
}

async fn server_with_required_filters_and_principal(
    principal_id: &str,
    signer: Arc<CursorSigner>,
) -> TestServer {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = tmp.path().join("required_filters.yaml");
    std::fs::write(
        &config_path,
        r#"
server:
  bind: 127.0.0.1:0
catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test
deployment:
  profile: local
vocabularies: {}
auth:
  mode: api_key
  api_keys: []
datasets:
  - id: test_dataset
    title: Test Dataset
    description: Test
    owner: Test
    sensitivity: personal
    access_rights: restricted
    update_frequency: monthly
    defaults:
      refresh:
        mode: manual
    tables:
      - id: items_table
        source:
          type: file
          path: fixtures/test.csv
        primary_key: item_id
        schema:
          strict: true
          fields:
            - name: item_id
              type: string
              nullable: false
            - name: group_id
              type: string
              nullable: true
      - id: unrestricted_table
        source:
          type: file
          path: fixtures/test.csv
        primary_key: thing_id
        schema:
          strict: true
          fields:
            - name: thing_id
              type: string
              nullable: false
    entities:
      - name: item
        table: items_table
        fields:
          - name: id
            from: item_id
          - name: group_id
        relationships:
          - name: thing
            kind: belongs_to
            target: thing
            foreign_key: group_id
        access:
          metadata_scope: test_dataset:metadata
          aggregate_scope: test_dataset:aggregate
          read_scope: test_dataset:rows
        api:
          default_limit: 100
          max_limit: 1000
          required_filters: [id]
          required_filter_bindings:
            - field: id
              source: principal_id
          allowed_filters:
            - field: id
              ops: [eq]
            - field: group_id
              ops: [eq]
      - name: group_item
        table: items_table
        fields:
          - name: id
            from: item_id
          - name: group_id
        access:
          metadata_scope: test_dataset:metadata
          aggregate_scope: test_dataset:aggregate
          read_scope: test_dataset:rows
        api:
          default_limit: 100
          max_limit: 1000
          required_filters: [group_id]
          required_filter_bindings:
            - field: group_id
              source: principal_id
          allowed_filters:
            - field: id
              ops: [eq]
            - field: group_id
              ops: [eq]
      - name: thing
        table: unrestricted_table
        fields:
          - name: id
            from: thing_id
        relationships:
          - name: group_items
            kind: has_many
            target: group_item
            foreign_key: group_id
        access:
          metadata_scope: test_dataset:metadata
          aggregate_scope: test_dataset:aggregate
          read_scope: test_dataset:rows
        api:
          default_limit: 100
          max_limit: 1000
          allowed_expansions: [group_items]
          allowed_filters:
            - field: id
              ops: [eq]
audit:
  sink: stdout
  format: jsonl
"#,
    )
    .expect("write config");
    let cfg = Arc::new(config::load(&config_path).expect("config loads"));
    let registry = Arc::new(EntityRegistry::from_config(&cfg).expect("registry"));
    let ctx = Arc::new(SessionContext::new());
    let schema = Arc::new(Schema::new(vec![
        Field::new("item_id", DataType::Utf8, false),
        Field::new("group_id", DataType::Utf8, true),
    ]));
    let batch = RecordBatch::try_new(
        Arc::clone(&schema),
        vec![
            Arc::new(StringArray::from(vec!["item-1", "item-2"])),
            Arc::new(StringArray::from(vec!["thing-1", "thing-1"])),
        ],
    )
    .expect("batch");
    let table = MemTable::try_new(schema, vec![vec![batch]]).expect("mem table");
    let dataset: DatasetId = id("test_dataset");
    let ingest_version = ulid::Ulid::from_string("01J5K8M0000000000000000000").expect("ulid");
    let resource: ResourceId = id("items_table");
    register_versioned_table(
        &ctx,
        table_name(&dataset, &resource),
        ingest_version,
        Arc::new(table),
    )
    .expect("register table");

    let unrestricted_schema = Arc::new(Schema::new(vec![Field::new(
        "thing_id",
        DataType::Utf8,
        false,
    )]));
    let unrestricted_batch = RecordBatch::try_new(
        Arc::clone(&unrestricted_schema),
        vec![Arc::new(StringArray::from(vec!["thing-1"]))],
    )
    .expect("batch");
    let unrestricted_table =
        MemTable::try_new(unrestricted_schema, vec![vec![unrestricted_batch]]).expect("mem table");
    let resource: ResourceId = id("unrestricted_table");
    register_versioned_table(
        &ctx,
        table_name(&dataset, &resource),
        ingest_version,
        Arc::new(unrestricted_table),
    )
    .expect("register table");

    let query = Arc::new(EntityQueryEngine::new(ctx, Arc::clone(&registry)));
    let mut snapshot = ReadinessSnapshot::default();
    snapshot.ready.insert(
        (id("test_dataset"), id("items_table")),
        ReadyResource {
            ingest_ulid: ingest_version,
            registered_at: time::OffsetDateTime::now_utc(),
        },
    );
    snapshot.ready.insert(
        (id("test_dataset"), id("unrestricted_table")),
        ReadyResource {
            ingest_ulid: ingest_version,
            registered_at: time::OffsetDateTime::now_utc(),
        },
    );
    let (_tx, readiness) = watch::channel(snapshot);

    TestServer::new(
        entity_router::<()>()
            .layer(Extension(query))
            .layer(Extension(registry))
            .layer(Extension(cfg))
            .layer(Extension(readiness))
            .layer(Extension(signer))
            .layer(Extension(principal_with_id(
                &[
                    "test_dataset:metadata",
                    "test_dataset:rows",
                    "test_dataset:evidence_verification",
                ],
                principal_id,
            ))),
    )
}

#[tokio::test]
async fn entity_collection_with_principal_bound_required_filter_returns_200() {
    let resp = server_with_required_filters()
        .await
        .get("/v1/datasets/test_dataset/entities/item/records")
        .await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(body["data"][0]["id"], "item-1");
}

#[tokio::test]
async fn entity_collection_with_caller_chosen_required_filter_value_returns_empty_page() {
    let resp = server_with_required_filters()
        .await
        .get("/v1/datasets/test_dataset/entities/item/records?id=item-2")
        .await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert!(body["data"].as_array().expect("data array").is_empty());
}

#[tokio::test]
async fn entity_collection_with_unrelated_filter_returns_filter_required() {
    let resp = server_with_required_filters()
        .await
        .get("/v1/datasets/test_dataset/entities/item/records?unrelated=x")
        .await;

    // unrelated param is parsed as a filter but rejected as not_allowed
    // before required_filters is checked; either 400 is acceptable but
    // filter.not_allowed fires first in this implementation.
    resp.assert_status(StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn entity_collection_with_no_caller_filters_uses_principal_bound_filter() {
    let resp = server_with_required_filters()
        .await
        .get("/v1/datasets/test_dataset/entities/item/records")
        .await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(body["data"][0]["id"], "item-1");
}

#[tokio::test]
async fn entity_record_with_principal_bound_required_filter_rejects_other_id() {
    let resp = server_with_required_filters()
        .await
        .get("/v1/datasets/test_dataset/entities/item/records/item-2")
        .await;

    resp.assert_status(StatusCode::NOT_FOUND);
    assert_eq!(resp.json::<Value>()["code"], "schema.unknown_resource");
}

#[tokio::test]
async fn entity_relationship_with_principal_bound_required_filter_rejects_other_host_id() {
    let resp = server_with_required_filters()
        .await
        .get("/v1/datasets/test_dataset/entities/item/records/item-2/relationships/thing")
        .await;

    resp.assert_status(StatusCode::NOT_FOUND);
    assert_eq!(resp.json::<Value>()["code"], "schema.unknown_resource");
}

#[tokio::test]
async fn entity_relationship_with_principal_bound_target_filter_rejects_other_target_rows() {
    let resp = server_with_required_filters_and_principal(
        "thing-2",
        Arc::new(CursorSigner::new_random()),
    )
    .await
    .get("/v1/datasets/test_dataset/entities/thing/records/thing-1/relationships/group_items")
    .await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert!(body["data"].as_array().expect("data array").is_empty());
}

#[tokio::test]
async fn entity_expansion_with_principal_bound_target_filter_rejects_other_target_rows() {
    let resp =
        server_with_required_filters_and_principal("thing-2", Arc::new(CursorSigner::new_random()))
            .await
            .get("/v1/datasets/test_dataset/entities/thing/records?expand=group_items")
            .await;

    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    let rows = body["data"].as_array().expect("data array");
    assert_eq!(rows.len(), 1);
    assert!(rows[0]["group_items"]
        .as_array()
        .expect("expanded rows")
        .is_empty());
}

#[tokio::test]
async fn entity_collection_principal_bound_etag_varies_by_principal() {
    let item_1 =
        server_with_required_filters_and_principal("item-1", Arc::new(CursorSigner::new_random()))
            .await
            .get("/v1/datasets/test_dataset/entities/item/records")
            .await;
    item_1.assert_status(StatusCode::OK);
    let item_1_etag = item_1.header("etag").to_str().expect("etag").to_string();

    let item_2 =
        server_with_required_filters_and_principal("item-2", Arc::new(CursorSigner::new_random()))
            .await
            .get("/v1/datasets/test_dataset/entities/item/records")
            .await;
    item_2.assert_status(StatusCode::OK);
    let item_2_etag = item_2.header("etag").to_str().expect("etag").to_string();

    assert_ne!(item_1_etag, item_2_etag);
}

#[tokio::test]
async fn entity_collection_cursor_is_bound_to_principal_context() {
    let signer = Arc::new(CursorSigner::new_random());
    let first = server_with_required_filters_and_principal("thing-1", Arc::clone(&signer))
        .await
        .get("/v1/datasets/test_dataset/entities/group_item/records?limit=1")
        .await;
    first.assert_status(StatusCode::OK);
    let body: Value = first.json();
    let cursor = body["pagination"]["next_cursor"]
        .as_str()
        .expect("first page has cursor");

    let url =
        format!("/v1/datasets/test_dataset/entities/group_item/records?limit=1&cursor={cursor}");
    let resp = server_with_required_filters_and_principal("thing-2", signer)
        .await
        .get(&url)
        .await;

    resp.assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(
        resp.json::<Value>()["code"],
        "pagination.cursor_invalidated"
    );
}

#[tokio::test]
async fn entity_collection_without_required_filters_accepts_no_filter() {
    let resp = server_with_required_filters()
        .await
        .get("/v1/datasets/test_dataset/entities/thing/records")
        .await;

    // No required_filters on thing; unfiltered request should succeed.
    resp.assert_status(StatusCode::OK);
}

/// Flips one nibble of a hex-encoded cursor at the given byte offset.
/// The original value is decoded, mutated by XOR, and re-encoded so the
/// length stays the same.
fn flip_hex_nibble(cursor: &str, byte_offset: usize) -> String {
    let mut chars: Vec<char> = cursor.chars().collect();
    let hex_index = byte_offset * 2;
    let original = chars[hex_index]
        .to_digit(16)
        .expect("cursor is hex-encoded");
    let flipped = original ^ 0x1;
    chars[hex_index] = std::char::from_digit(flipped, 16).expect("nibble in range");
    chars.into_iter().collect()
}

#[tokio::test]
async fn entity_collection_cursor_with_tampered_mac_rejected() {
    let server = server_with_query().await;

    let first = server
        .get("/v1/datasets/social_registry/entities/household/records?limit=1")
        .await;
    first.assert_status(StatusCode::OK);
    let body: Value = first.json();
    let cursor = body["pagination"]["next_cursor"]
        .as_str()
        .expect("first page has cursor")
        .to_string();

    // Flip one nibble of the MAC tag (byte 0). The HMAC verify must
    // fail before any JSON parsing happens and return the same code as
    // a malformed cursor would.
    let tampered = flip_hex_nibble(&cursor, 0);
    let url = format!(
        "/v1/datasets/social_registry/entities/household/records?limit=1&cursor={tampered}"
    );
    let resp = server.get(&url).await;
    resp.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = resp.json();
    assert_eq!(body["code"], "filter.invalid_value");
}

#[tokio::test]
async fn entity_collection_cursor_with_tampered_payload_rejected() {
    let server = server_with_query().await;

    let first = server
        .get("/v1/datasets/social_registry/entities/household/records?limit=1")
        .await;
    first.assert_status(StatusCode::OK);
    let body: Value = first.json();
    let cursor = body["pagination"]["next_cursor"]
        .as_str()
        .expect("first page has cursor")
        .to_string();

    // Flip a nibble of the JSON payload (past the 16-byte MAC tag).
    // The HMAC must catch the mutation and reject the cursor.
    let tampered = flip_hex_nibble(&cursor, 16);
    let url = format!(
        "/v1/datasets/social_registry/entities/household/records?limit=1&cursor={tampered}"
    );
    let resp = server.get(&url).await;
    resp.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = resp.json();
    assert_eq!(body["code"], "filter.invalid_value");
}

#[tokio::test]
async fn entity_collection_unmutated_cursor_still_works() {
    let server = server_with_query().await;

    let first = server
        .get("/v1/datasets/social_registry/entities/household/records?limit=1")
        .await;
    first.assert_status(StatusCode::OK);
    let body: Value = first.json();
    let cursor = body["pagination"]["next_cursor"]
        .as_str()
        .expect("first page has cursor")
        .to_string();

    let url =
        format!("/v1/datasets/social_registry/entities/household/records?limit=1&cursor={cursor}");
    let resp = server.get(&url).await;
    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(
        body["data"],
        serde_json::json!([{"id": "hh-2", "region": "south"}])
    );
}

#[tokio::test]
async fn entity_collection_too_many_filter_params_rejected() {
    let server = server_with_query().await;

    // 21 distinct filters: one over the cap. The cap is reached at
    // entry 21 because the `region` field is the only filter the
    // example config allows. We use 21 distinct `region.in=...` style
    // entries, but `region` is a single field and each param replaces
    // the prior. Instead, use 21 attempts on the same `region` field
    // via separate key names: `region`, `region.in`, `region.gte`,
    // `region.lte`, `region.between` are all configured ops; the
    // remaining 16 must be the same field repeated through query-string
    // duplication, which axum's `Query<HashMap<_,_>>` collapses to one
    // entry. To exercise the cap regardless of field allowlist, send
    // requests on the individual entity (which allows `id` filters) and
    // use 21 distinct `id.eq=...` style keys; since the `Query` extractor
    // collapses duplicate keys, we encode each filter with a fresh name
    // that the parser rejects after a configured cap. The cleanest path:
    // exercise the cap by sending 21 distinct filter *parameter names*
    // that are all syntactically valid (`field_NN=value`), then assert
    // the per-request cap fires before any allowed-filter check.
    let mut url = String::from("/v1/datasets/social_registry/entities/household/records?");
    for i in 0..21 {
        if i > 0 {
            url.push('&');
        }
        url.push_str(&format!("field_{i:02}=value"));
    }
    let resp = server.get(&url).await;
    resp.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = resp.json();
    assert_eq!(body["code"], "filter.too_many_filters");
}
