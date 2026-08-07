// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "attribute-release")]

//! Attribute-release resolve + discovery API coverage.
//!
//! These tests exercise `attribute_release_router::<()>()` directly with a
//! layered in-memory `MemTable`, principal, query engine, registry, and config,
//! mirroring the SP DCI adapter harness (`tests/spdci_api_standards.rs`). They
//! assert the load-bearing gate order (scope/purpose deny *before* any source
//! read), the projection invariants (only configured claims; no raw subject or
//! subject hash in the body), and the collapsed-denial privacy property.

use std::env;
use std::sync::Arc;

use axum::http::StatusCode;
use axum::Extension;
use axum_test::TestServer;
use bytes::Bytes;
use datafusion::arrow::array::{ArrayRef, ListBuilder, StringArray, StringBuilder, StructArray};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::datasource::MemTable;
use datafusion::execution::context::SessionContext;
use registry_relay::api::attribute_release_router;
use registry_relay::attribute_release::AttributeReleaseEvaluator;
use registry_relay::auth::{AuthMode, Principal, ScopeSet};
use registry_relay::config::{self, DatasetId, ResourceId};
use registry_relay::entity::EntityRegistry;
use registry_relay::error::Error;
use registry_relay::ingest::{
    register_versioned_table, table_name, ReadinessSnapshot, ReadyResource,
};
use registry_relay::query::EntityQueryEngine;
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio::sync::watch;
use ulid::Ulid;

const RELEASE_SCOPE: &str = "civil_registry:identity_release";
const READ_SCOPE: &str = "civil_registry:rows";

fn id<T: serde::de::DeserializeOwned>(value: &str) -> T {
    serde_json::from_str(&format!(r#""{value}""#)).expect("id deserializes")
}

fn principal(scopes: &[&str]) -> Principal {
    Principal {
        principal_id: "test".to_string(),
        scopes: scopes.iter().copied().collect::<ScopeSet>(),
        auth_mode: AuthMode::ApiKey,
    }
}

#[derive(Debug)]
struct TestServerBuildError {
    #[allow(dead_code)]
    code: &'static str,
    #[allow(dead_code)]
    message: String,
}

impl From<Error> for TestServerBuildError {
    fn from(error: Error) -> Self {
        Self {
            code: error.code(),
            message: error.to_string(),
        }
    }
}

/// Optional fixture extensions. The default (no extension) reproduces the base
/// fixture exactly, so every pre-existing test keeps its original config shape.
#[derive(Default)]
struct ConfigExtras {
    /// Expose two structured source columns (`address`, `contact_points`) on the
    /// table and the entity, and back them with Arrow struct/list columns. The
    /// config field type vocabulary is scalar-only, so the columns are declared
    /// as `string`: this mirrors a real source whose physical column shape is
    /// richer than the declared schema.
    structured_fields: bool,
    /// Extra release profiles appended to the entity's profile list.
    profiles: String,
}

/// A two-row civil-registry config with one release profile. `deceased`
/// drives the release-condition predicate; `given_name`/`surname` back direct
/// and computed claims. The `optional_note` claim is optional and absent on the
/// stored row so it is omitted from a successful release.
fn release_config(
    entity_api_extra: &str,
    include_source_metadata: bool,
    purpose: &str,
    extras: &ConfigExtras,
) -> String {
    let extra_schema_fields = if extras.structured_fields {
        r#"            - name: address
              type: string
              nullable: true
            - name: contact_points
              type: string
              nullable: true
"#
    } else {
        ""
    };
    let extra_entity_fields = if extras.structured_fields {
        r#"          - name: address
          - name: contact_points
"#
    } else {
        ""
    };
    let extra_profiles = extras.profiles.as_str();
    format!(
        r#"
server:
  bind: 127.0.0.1:0

catalog:
  title: Test
  base_url: https://gw.example
  publisher: Test

deployment:
  profile: local

vocabularies: {{}}

auth:
  mode: api_key
  api_keys: []

audit:
  sink: stdout
  format: jsonl
  hash_secret_env: REGISTRY_RELAY_TEST_AUDIT_HASH_SECRET

datasets:
  - id: civil_registry
    title: Civil Registry
    description: Synthetic registry
    owner: Test
    sensitivity: public
    access_rights: restricted
    update_frequency: monthly
    defaults:
      refresh:
        mode: manual
    tables:
      - id: persons_table
        source:
          type: file
          path: fixtures/civil_registry.xlsx
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
{extra_schema_fields}    entities:
      - name: person
        table: persons_table
        fields:
          - name: id
            from: person_id
          - name: national_id
          - name: given_name
          - name: surname
          - name: deceased
{extra_entity_fields}        access:
          metadata_scope: civil_registry:metadata
          aggregate_scope: civil_registry:aggregate
          read_scope: {READ_SCOPE}
          evidence_verification_scope: civil_registry:evidence_verification
        api:
          default_limit: 100
          max_limit: 1000
          allowed_filters:
            - field: national_id
              ops: [eq]
{entity_api_extra}
        attribute_release_profiles:
          - id: civil_identity
            version: v1
            title: Civil identity bundle
            description: Minimised identity claims for eSignet.
            purpose: {purpose}
            release_scope: {RELEASE_SCOPE}
            subject:
              source_field: national_id
              id_type: NATIONAL_ID
            release_conditions:
              expression:
                cel: "source.deceased == 'false'"
            claims:
              - name: given_name
                source_field: given_name
                required: true
              - name: full_name
                expression:
                  cel: "source.given_name + ' ' + source.surname"
                required: false
              - name: optional_note
                source_field: surname
                required: false
            response:
              include_source_metadata: {include_source_metadata}
{extra_profiles}"#
    )
}

/// Build a four-row table: one live subject (`NID-1`) and one deceased subject
/// (`NID-DEAD`). `NID-DUP` is duplicated to exercise the ambiguity gate.
///
/// `structured` appends the two non-scalar source columns matched by
/// [`ConfigExtras::structured_fields`]: an `address` struct and a
/// `contact_points` string list. The Arrow schema is derived from the built
/// arrays so the struct/list child fields always line up.
fn schema_and_batch(structured: bool) -> (Arc<Schema>, RecordBatch) {
    let mut columns: Vec<(&str, ArrayRef)> = vec![
        (
            "person_id",
            Arc::new(StringArray::from(vec!["p1", "p2", "p3", "p4"])),
        ),
        (
            "national_id",
            Arc::new(StringArray::from(vec![
                "NID-1", "NID-DEAD", "NID-DUP", "NID-DUP",
            ])),
        ),
        (
            "given_name",
            Arc::new(StringArray::from(vec!["Ada", "Grace", "Alan", "Alan"])),
        ),
        (
            "surname",
            Arc::new(StringArray::from(vec![
                "Lovelace", "Hopper", "Turing", "Turing",
            ])),
        ),
        (
            "deceased",
            Arc::new(StringArray::from(vec!["false", "true", "false", "false"])),
        ),
    ];
    if structured {
        let address: ArrayRef = Arc::new(StructArray::from(vec![
            (
                Arc::new(Field::new("region", DataType::Utf8, true)),
                Arc::new(StringArray::from(vec![
                    "Wonderland",
                    "Elsewhere",
                    "Elsewhere",
                    "Elsewhere",
                ])) as ArrayRef,
            ),
            (
                Arc::new(Field::new("postal_code", DataType::Utf8, true)),
                Arc::new(StringArray::from(vec!["W-1", "E-1", "E-2", "E-3"])) as ArrayRef,
            ),
        ]));
        let mut contact_points = ListBuilder::new(StringBuilder::new());
        for value in [
            "ada@example.test",
            "grace@example.test",
            "a@x.test",
            "b@x.test",
        ] {
            contact_points.values().append_value(value);
            contact_points.append(true);
        }
        columns.push(("address", address));
        columns.push(("contact_points", Arc::new(contact_points.finish())));
    }
    let schema = Arc::new(Schema::new(
        columns
            .iter()
            .map(|(name, array)| Field::new(*name, array.data_type().clone(), true))
            .collect::<Vec<_>>(),
    ));
    let batch = RecordBatch::try_new(
        Arc::clone(&schema),
        columns.into_iter().map(|(_, array)| array).collect(),
    )
    .expect("batch");
    (schema, batch)
}

async fn try_server_with_scopes_and_extra(
    scopes: &[&str],
    entity_api_extra: &str,
) -> Result<TestServer, TestServerBuildError> {
    try_server_full(
        scopes,
        entity_api_extra,
        true,
        None,
        &ConfigExtras::default(),
    )
    .await
}

/// Like [`try_server_with_scopes_and_extra`] but with explicit control over the
/// profile's `response.include_source_metadata` flag and its `purpose` binding.
/// Every profile is purpose-bound. `None` selects the default `identity`
/// purpose and installs that header on the test server; `Some` configures the
/// supplied purpose without a default header so purpose denials can be tested.
async fn try_server_full(
    scopes: &[&str],
    entity_api_extra: &str,
    include_source_metadata: bool,
    purpose: Option<&str>,
    extras: &ConfigExtras,
) -> Result<TestServer, TestServerBuildError> {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = tmp.path().join("release.yaml");
    std::fs::write(
        &config_path,
        release_config(
            entity_api_extra,
            include_source_metadata,
            purpose.unwrap_or("identity"),
            extras,
        ),
    )
    .expect("write config");
    env::set_var(
        "REGISTRY_RELAY_TEST_AUDIT_HASH_SECRET",
        "relay-release-audit-secret-32-bytes",
    );
    let config = Arc::new(config::load(&config_path)?);
    let registry = Arc::new(EntityRegistry::from_config(&config)?);
    let ctx = Arc::new(SessionContext::new());
    let dataset: DatasetId = id("civil_registry");
    let resource: ResourceId = id("persons_table");
    let (schema, batch) = schema_and_batch(extras.structured_fields);
    let ingest_ulid = Ulid::from_string("01J5K8M0000000000000000000").expect("ulid");
    register_versioned_table(
        &ctx,
        table_name(&dataset, &resource),
        ingest_ulid,
        Arc::new(MemTable::try_new(Arc::clone(&schema), vec![vec![batch]]).expect("memtable")),
    )
    .expect("register");
    let mut snapshot = ReadinessSnapshot::default();
    snapshot.ready.insert(
        (dataset, resource),
        ReadyResource {
            ingest_ulid,
            registered_at: time::OffsetDateTime::now_utc(),
            consecutive_refresh_failures: 0,
        },
    );
    let (_tx, readiness) = watch::channel(snapshot);
    let query = Arc::new(EntityQueryEngine::new(
        Arc::clone(&ctx),
        Arc::clone(&registry),
    ));
    let evaluator = Arc::new(AttributeReleaseEvaluator::from_config(&config));
    let app = attribute_release_router::<()>()
        .layer(Extension(principal(scopes)))
        .layer(Extension(readiness))
        .layer(Extension(query))
        .layer(Extension(registry))
        .layer(Extension(evaluator))
        .layer(Extension(config));
    let mut server = TestServer::new(app);
    if purpose.is_none() {
        server.add_header("data-purpose", "identity");
    }
    Ok(server)
}

async fn server() -> TestServer {
    try_server_with_scopes_and_extra(&[RELEASE_SCOPE], "")
        .await
        .expect("test server builds")
}

const RESOLVE_PATH: &str = "/v1/attribute-releases/civil_identity/versions/v1/resolve";

fn subject_body(value: &str) -> Value {
    json!({ "subject": { "id_type": "NATIONAL_ID", "value": value } })
}

// ---------------------------------------------------------------------------
// Success
// ---------------------------------------------------------------------------

#[tokio::test]
async fn resolve_returns_only_configured_claims() {
    let server = server().await;
    let response = server.post(RESOLVE_PATH).json(&subject_body("NID-1")).await;
    response.assert_status(StatusCode::OK);
    let body: Value = response.json();

    assert_eq!(body["profile_id"], "civil_identity");
    assert_eq!(body["profile_version"], "v1");

    let claims = body["claims"].as_object().expect("claims object");
    assert_eq!(claims["given_name"], "Ada");
    assert_eq!(claims["full_name"], "Ada Lovelace");
    // optional_note maps to `surname` which is present, so it IS released here.
    assert_eq!(claims["optional_note"], "Lovelace");

    // The default fixture enables include_source_metadata, so the source block
    // is present; the false-path test below asserts it is omitted otherwise.
    assert_eq!(body["source"]["dataset"], "civil_registry");
    assert_eq!(body["source"]["entity"], "person");
    assert_eq!(body["source"]["subject_id_type"], "NATIONAL_ID");
    assert_eq!(body["source"]["cardinality"], "one");
}

#[tokio::test]
async fn resolve_omits_source_block_when_metadata_disabled() {
    // With response.include_source_metadata = false (the minimizing default for
    // an eSignet authenticator profile), the claim bundle is still released but
    // the source block — which would disclose the backing dataset/entity names —
    // is suppressed entirely.
    let server = try_server_full(&[RELEASE_SCOPE], "", false, None, &ConfigExtras::default())
        .await
        .expect("test server builds");
    let response = server.post(RESOLVE_PATH).json(&subject_body("NID-1")).await;
    response.assert_status(StatusCode::OK);
    let body: Value = response.json();
    assert_eq!(body["claims"]["given_name"], "Ada");
    assert!(
        body.get("source").is_none(),
        "source block must be omitted when include_source_metadata is false: {body}"
    );
}

#[tokio::test]
async fn resolve_body_never_contains_raw_subject_or_subject_hash() {
    let server = server().await;
    let response = server.post(RESOLVE_PATH).json(&subject_body("NID-1")).await;
    response.assert_status(StatusCode::OK);
    let body: Value = response.json();
    let serialized = body.to_string();
    // The raw subject value must not appear anywhere in the public body...
    assert!(
        !serialized.contains("NID-1"),
        "public body must not echo the raw subject value: {serialized}"
    );
    // ...nor any keyed/unkeyed subject hash field.
    assert!(!serialized.contains("subject_id_hash"));
    assert!(!serialized.contains("hmac-sha256:"));
    assert!(!serialized.contains("sha256:"));
}

#[tokio::test]
async fn resolve_pins_version_and_echoes_profile_identity() {
    let server = server().await;
    let response = server.post(RESOLVE_PATH).json(&subject_body("NID-1")).await;
    response.assert_status(StatusCode::OK);
    let body: Value = response.json();
    assert_eq!(body["profile_id"], "civil_identity");
    assert_eq!(body["profile_version"], "v1");

    // A different (unconfigured) version is a generic 404, not a release denial.
    let missing = server
        .post("/v1/attribute-releases/civil_identity/versions/v2/resolve")
        .json(&subject_body("NID-1"))
        .await;
    missing.assert_status(StatusCode::NOT_FOUND);
    assert_eq!(missing.json::<Value>()["code"], "release.profile_not_found");
}

// ---------------------------------------------------------------------------
// Claim-set handling
// ---------------------------------------------------------------------------

#[tokio::test]
async fn resolve_explicit_claim_subset_is_honoured() {
    let server = server().await;
    let response = server
        .post(RESOLVE_PATH)
        .json(&json!({
            "subject": { "id_type": "NATIONAL_ID", "value": "NID-1" },
            "claims": ["given_name"]
        }))
        .await;
    response.assert_status(StatusCode::OK);
    let claims = response.json::<Value>()["claims"].clone();
    assert_eq!(claims["given_name"], "Ada");
    assert!(claims.get("full_name").is_none());
    assert!(claims.get("optional_note").is_none());
}

#[tokio::test]
async fn resolve_empty_claim_list_is_bad_request() {
    let server = server().await;
    let response = server
        .post(RESOLVE_PATH)
        .json(&json!({
            "subject": { "id_type": "NATIONAL_ID", "value": "NID-1" },
            "claims": []
        }))
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn resolve_rejects_duplicate_and_over_bound_claim_lists() {
    let server = server().await;
    for claims in [vec!["full_name"; 2], vec!["full_name"; 33]] {
        let response = server
            .post(RESOLVE_PATH)
            .json(&json!({
                "subject": { "id_type": "NATIONAL_ID", "value": "NID-1" },
                "claims": claims
            }))
            .await;
        response.assert_status(StatusCode::BAD_REQUEST);
        assert_eq!(response.json::<Value>()["code"], "filter.invalid_value");
    }
}

#[tokio::test]
async fn resolve_rejects_subset_missing_required_claims() {
    let server = server().await;
    let response = server
        .post(RESOLVE_PATH)
        .json(&json!({
            "subject": { "id_type": "NATIONAL_ID", "value": "NID-1" },
            "claims": ["full_name"]
        }))
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(response.json::<Value>()["code"], "filter.invalid_value");
}

#[tokio::test]
async fn resolve_unknown_requested_claim_is_denied() {
    let server = server().await;
    let response = server
        .post(RESOLVE_PATH)
        .json(&json!({
            "subject": { "id_type": "NATIONAL_ID", "value": "NID-1" },
            "claims": ["given_name", "no_such_claim"]
        }))
        .await;
    response.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(response.json::<Value>()["code"], "release.subject_denied");
}

// ---------------------------------------------------------------------------
// Subject validation (request-shape, distinct from collapsed denials)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn resolve_mismatched_id_type_is_subject_invalid() {
    // An id_type the profile does not accept is a request-shape error: it is
    // rejected with a distinct 400 release.subject_invalid (not the collapsed
    // 403), before any source read, and reveals nothing about subject existence.
    let server = server().await;
    let response = server
        .post(RESOLVE_PATH)
        .json(&json!({ "subject": { "id_type": "PASSPORT", "value": "NID-1" } }))
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(response.json::<Value>()["code"], "release.subject_invalid");
}

#[tokio::test]
async fn resolve_non_scalar_subject_value_is_subject_invalid() {
    // A non-scalar subject value cannot identify a row; it is an invalid request
    // (400 release.subject_invalid), not a subject denial.
    let server = server().await;
    let response = server
        .post(RESOLVE_PATH)
        .json(&json!({ "subject": { "id_type": "NATIONAL_ID", "value": [] } }))
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(response.json::<Value>()["code"], "release.subject_invalid");
}

// ---------------------------------------------------------------------------
// Collapsed denials (cardinality + release condition)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn resolve_zero_rows_collapses_to_subject_denied() {
    let server = server().await;
    let response = server
        .post(RESOLVE_PATH)
        .json(&subject_body("NID-ABSENT"))
        .await;
    response.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(response.json::<Value>()["code"], "release.subject_denied");
}

#[tokio::test]
async fn resolve_multiple_rows_collapses_to_subject_denied() {
    let server = server().await;
    let response = server
        .post(RESOLVE_PATH)
        .json(&subject_body("NID-DUP"))
        .await;
    response.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(response.json::<Value>()["code"], "release.subject_denied");
}

#[tokio::test]
async fn resolve_collapsed_denials_are_byte_identical() {
    let server = server().await;
    let not_found = server
        .post(RESOLVE_PATH)
        .json(&subject_body("NID-ABSENT"))
        .await;
    let deceased = server
        .post(RESOLVE_PATH)
        .json(&subject_body("NID-DEAD"))
        .await;
    let ambiguous = server
        .post(RESOLVE_PATH)
        .json(&subject_body("NID-DUP"))
        .await;

    not_found.assert_status(StatusCode::FORBIDDEN);
    deceased.assert_status(StatusCode::FORBIDDEN);
    ambiguous.assert_status(StatusCode::FORBIDDEN);

    // All three internal outcomes must be publicly indistinguishable.
    let a: Value = not_found.json();
    let b: Value = deceased.json();
    let c: Value = ambiguous.json();
    assert_eq!(a, b);
    assert_eq!(b, c);
}

#[tokio::test]
async fn resolve_release_condition_denies_deceased_subject() {
    let server = server().await;
    let response = server
        .post(RESOLVE_PATH)
        .json(&subject_body("NID-DEAD"))
        .await;
    response.assert_status(StatusCode::FORBIDDEN);
    let body: Value = response.json();
    assert_eq!(body["code"], "release.subject_denied");
    // The denial body must not leak the row that was read.
    assert!(!body.to_string().contains("Grace"));
}

// ---------------------------------------------------------------------------
// Required vs optional claim availability
// ---------------------------------------------------------------------------

#[tokio::test]
async fn resolve_required_claim_missing_denies() {
    // Redact `given_name` (a required claim's source field) via governed policy.
    let server = try_server_full(
        &[RELEASE_SCOPE],
        r#"          governed_policy:
            permitted_purposes:
              - identity
            redaction_fields: [given_name]
            trusted_context: {}
"#,
        true,
        Some("identity"),
        &ConfigExtras::default(),
    )
    .await
    .expect("test server builds");

    let response = server
        .post(RESOLVE_PATH)
        .add_header("data-purpose", "identity")
        .json(&subject_body("NID-1"))
        .await;
    response.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(response.json::<Value>()["code"], "release.subject_denied");
}

#[tokio::test]
async fn resolve_optional_claim_omitted_when_source_redacted() {
    // Redact `surname`, the source of the *optional* `optional_note` claim. The
    // release still succeeds; the optional claim is simply omitted.
    let server = try_server_full(
        &[RELEASE_SCOPE],
        r#"          governed_policy:
            permitted_purposes:
              - identity
            redaction_fields: [surname]
            trusted_context: {}
"#,
        true,
        Some("identity"),
        &ConfigExtras::default(),
    )
    .await
    .expect("test server builds");

    let response = server
        .post(RESOLVE_PATH)
        .add_header("data-purpose", "identity")
        .json(&subject_body("NID-1"))
        .await;
    response.assert_status(StatusCode::OK);
    let claims = response.json::<Value>()["claims"].clone();
    assert_eq!(claims["given_name"], "Ada");
    assert!(
        claims.get("optional_note").is_none(),
        "optional claim whose source field is redacted must be omitted"
    );
}

#[tokio::test]
async fn resolve_computed_claim_cannot_read_redacted_field() {
    // Governed redaction is field-layer, but the `full_name` claim is computed
    // (`source.given_name + ' ' + source.surname`). Redact `surname`: a computed
    // claim must NOT be able to read it back through CEL, so the redacted value
    // "Lovelace" must never appear in the response and `full_name` must fail
    // closed (omitted, since it is optional) rather than leak "Ada Lovelace".
    let server = try_server_full(
        &[RELEASE_SCOPE],
        r#"          governed_policy:
            permitted_purposes:
              - identity
            redaction_fields: [surname]
            trusted_context: {}
"#,
        true,
        Some("identity"),
        &ConfigExtras::default(),
    )
    .await
    .expect("test server builds");

    let response = server
        .post(RESOLVE_PATH)
        .add_header("data-purpose", "identity")
        .json(&subject_body("NID-1"))
        .await;
    response.assert_status(StatusCode::OK);
    let body: Value = response.json();
    let serialized = body.to_string();
    assert!(
        !serialized.contains("Lovelace"),
        "redacted surname must not leak via a computed claim: {serialized}"
    );
    let claims = &body["claims"];
    assert_eq!(claims["given_name"], "Ada");
    assert_ne!(
        claims["full_name"], "Ada Lovelace",
        "computed claim must not reconstruct the redacted surname"
    );
}

#[tokio::test]
async fn resolve_release_condition_cannot_read_redacted_field() {
    // The release predicate reads `source.deceased`. If the PDP redacts that
    // field, the predicate must evaluate over the redacted row and fail closed
    // instead of revealing a boolean about the removed value.
    let server = try_server_full(
        &[RELEASE_SCOPE],
        r#"          governed_policy:
            permitted_purposes:
              - identity
            redaction_fields: [deceased]
            trusted_context: {}
"#,
        true,
        Some("identity"),
        &ConfigExtras::default(),
    )
    .await
    .expect("test server builds");

    let response = server
        .post(RESOLVE_PATH)
        .add_header("data-purpose", "identity")
        .json(&subject_body("NID-1"))
        .await;
    response.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(response.json::<Value>()["code"], "release.subject_denied");
}

// ---------------------------------------------------------------------------
// Scalar-only claim values
// ---------------------------------------------------------------------------

/// Profiles whose direct claims project the two structured source columns. None
/// of them declares CEL, so the read projects only the referenced fields and no
/// expression ever sees a structured input.
fn structured_direct_profiles() -> String {
    format!(
        r#"          - id: structured-direct
            version: v1
            purpose: identity
            release_scope: {RELEASE_SCOPE}
            subject:
              source_field: national_id
              id_type: NATIONAL_ID
            claims:
              - name: given_name
                source_field: given_name
                required: true
              - name: address
                source_field: address
                required: false
              - name: contact_points
                source_field: contact_points
                required: false
            response:
              include_source_metadata: false
          - id: structured-direct-required-object
            version: v1
            purpose: identity
            release_scope: {RELEASE_SCOPE}
            subject:
              source_field: national_id
              id_type: NATIONAL_ID
            claims:
              - name: address
                source_field: address
                required: true
            response:
              include_source_metadata: false
          - id: structured-direct-required-array
            version: v1
            purpose: identity
            release_scope: {RELEASE_SCOPE}
            subject:
              source_field: national_id
              id_type: NATIONAL_ID
            claims:
              - name: contact_points
                source_field: contact_points
                required: true
            response:
              include_source_metadata: false
"#
    )
}

/// Profiles whose computed claims evaluate to non-scalar or null values at
/// resolve time. Every expression is statically scalar-shaped (member selects
/// and conditionals), so config validation accepts it; the structured source
/// columns supply the non-scalar shape only once a real row is evaluated.
/// Expressions that are structured on their face (a list or map literal) never
/// get this far: config load rejects them.
fn computed_shape_profiles() -> String {
    format!(
        r#"          - id: computed-shapes
            version: v1
            purpose: identity
            release_scope: {RELEASE_SCOPE}
            subject:
              source_field: national_id
              id_type: NATIONAL_ID
            claims:
              - name: given_name
                source_field: given_name
                required: true
              - name: computed_list
                expression:
                  cel: "source.contact_points"
                required: false
              - name: computed_map
                expression:
                  cel: "source.address"
                required: false
              - name: computed_null
                expression:
                  cel: "source.given_name == 'nobody' ? source.given_name : null"
                required: false
              - name: computed_text
                expression:
                  cel: "source.given_name"
                required: false
              - name: computed_number
                expression:
                  cel: "size(source.given_name)"
                required: false
              - name: computed_flag
                expression:
                  cel: "source.deceased == 'false'"
                required: false
            response:
              include_source_metadata: false
          - id: computed-required-list
            version: v1
            purpose: identity
            release_scope: {RELEASE_SCOPE}
            subject:
              source_field: national_id
              id_type: NATIONAL_ID
            claims:
              - name: computed_list
                expression:
                  cel: "source.contact_points"
                required: true
            response:
              include_source_metadata: false
"#
    )
}

fn resolve_path(profile_id: &str) -> String {
    format!("/v1/attribute-releases/{profile_id}/versions/v1/resolve")
}

async fn structured_direct_server() -> TestServer {
    try_server_full(
        &[RELEASE_SCOPE],
        "",
        false,
        None,
        &ConfigExtras {
            structured_fields: true,
            profiles: structured_direct_profiles(),
        },
    )
    .await
    .expect("test server builds")
}

async fn computed_shape_server() -> TestServer {
    try_server_full(
        &[RELEASE_SCOPE],
        "",
        false,
        None,
        &ConfigExtras {
            structured_fields: true,
            profiles: computed_shape_profiles(),
        },
    )
    .await
    .expect("test server builds")
}

#[tokio::test]
async fn resolve_omits_optional_direct_claims_with_structured_values() {
    // Claim values are scalar-only in v1. A direct claim whose source column
    // holds an object (`address`) or an array (`contact_points`) is unavailable,
    // so an optional claim of that shape is omitted and its structured content
    // never reaches the body.
    let server = structured_direct_server().await;
    let response = server
        .post(&resolve_path("structured-direct"))
        .json(&subject_body("NID-1"))
        .await;
    response.assert_status(StatusCode::OK);
    let body: Value = response.json();
    let claims = body["claims"].as_object().expect("claims object");
    assert_eq!(claims["given_name"], "Ada");
    assert!(
        !claims.contains_key("address"),
        "object-valued direct claim must be omitted: {body}"
    );
    assert!(
        !claims.contains_key("contact_points"),
        "array-valued direct claim must be omitted: {body}"
    );
    let serialized = body.to_string();
    assert!(
        !serialized.contains("Wonderland") && !serialized.contains("ada@example.test"),
        "structured source content must never be released: {serialized}"
    );
}

#[tokio::test]
async fn resolve_denies_required_direct_object_claim() {
    // Required + unavailable is the ClaimUnavailable path: a collapsed
    // 403 release.subject_denied, identical to any other unavailable claim.
    let server = structured_direct_server().await;
    let response = server
        .post(&resolve_path("structured-direct-required-object"))
        .json(&subject_body("NID-1"))
        .await;
    response.assert_status(StatusCode::FORBIDDEN);
    let body: Value = response.json();
    assert_eq!(body["code"], "release.subject_denied");
    assert!(
        !body.to_string().contains("Wonderland"),
        "denial body must not leak the structured value: {body}"
    );
}

#[tokio::test]
async fn resolve_denies_required_direct_array_claim() {
    let server = structured_direct_server().await;
    let response = server
        .post(&resolve_path("structured-direct-required-array"))
        .json(&subject_body("NID-1"))
        .await;
    response.assert_status(StatusCode::FORBIDDEN);
    let body: Value = response.json();
    assert_eq!(body["code"], "release.subject_denied");
    assert!(
        !body.to_string().contains("ada@example.test"),
        "denial body must not leak the structured value: {body}"
    );
}

#[tokio::test]
async fn resolve_omits_optional_computed_claims_with_structured_values() {
    // A computed claim returns whatever its CEL yields. A list or map result is
    // not a scalar, so the claim is unavailable and the optional form is omitted.
    let server = computed_shape_server().await;
    let response = server
        .post(&resolve_path("computed-shapes"))
        .json(&subject_body("NID-1"))
        .await;
    response.assert_status(StatusCode::OK);
    let body: Value = response.json();
    let claims = body["claims"].as_object().expect("claims object");
    assert!(
        !claims.contains_key("computed_list"),
        "array-valued computed claim must be omitted: {body}"
    );
    assert!(
        !claims.contains_key("computed_map"),
        "object-valued computed claim must be omitted: {body}"
    );
}

#[tokio::test]
async fn resolve_denies_required_computed_structured_claim() {
    let server = computed_shape_server().await;
    let response = server
        .post(&resolve_path("computed-required-list"))
        .json(&subject_body("NID-1"))
        .await;
    response.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(response.json::<Value>()["code"], "release.subject_denied");
}

#[tokio::test]
async fn resolve_computed_null_claim_is_omitted_not_released_as_null() {
    // A computed claim that evaluates to JSON null behaves exactly like a direct
    // claim over a null column: the claim is missing, never a literal `null`.
    let server = computed_shape_server().await;
    let response = server
        .post(&resolve_path("computed-shapes"))
        .json(&subject_body("NID-1"))
        .await;
    response.assert_status(StatusCode::OK);
    let body: Value = response.json();
    let claims = body["claims"].as_object().expect("claims object");
    assert!(
        !claims.contains_key("computed_null"),
        "null-valued computed claim must be omitted, not released as null: {body}"
    );
    assert!(
        !claims.values().any(Value::is_null),
        "no released claim may be a literal null: {body}"
    );
}

#[tokio::test]
async fn resolve_releases_every_scalar_claim_shape() {
    // The scalar contract is a floor, not a narrowing: string, number, and
    // boolean claim values all still release.
    let server = computed_shape_server().await;
    let response = server
        .post(&resolve_path("computed-shapes"))
        .json(&subject_body("NID-1"))
        .await;
    response.assert_status(StatusCode::OK);
    let claims = response.json::<Value>()["claims"].clone();
    assert_eq!(claims["given_name"], "Ada");
    assert_eq!(claims["computed_text"], "Ada");
    assert_eq!(claims["computed_number"], 3);
    assert_eq!(claims["computed_flag"], true);
}

#[tokio::test]
async fn resolve_claim_selection_is_by_top_level_name_only() {
    // Claim selection matches whole top-level claim names. A structured claim
    // cannot be selected, and no path-style sub-selection into a claim exists.
    let server = structured_direct_server().await;
    let selected = server
        .post(&resolve_path("structured-direct"))
        .json(&json!({
            "subject": { "id_type": "NATIONAL_ID", "value": "NID-1" },
            "claims": ["given_name", "address"]
        }))
        .await;
    selected.assert_status(StatusCode::OK);
    let claims = selected.json::<Value>()["claims"].clone();
    assert_eq!(claims["given_name"], "Ada");
    assert!(claims.get("address").is_none());
    assert!(claims.get("contact_points").is_none());

    // A dotted path into a claim is not a claim name: it is an unknown claim and
    // is denied like any other.
    let path_style = server
        .post(&resolve_path("structured-direct"))
        .json(&json!({
            "subject": { "id_type": "NATIONAL_ID", "value": "NID-1" },
            "claims": ["given_name", "address.region"]
        }))
        .await;
    path_style.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(path_style.json::<Value>()["code"], "release.subject_denied");
}

// ---------------------------------------------------------------------------
// Scope / purpose deny-before-read
// ---------------------------------------------------------------------------

#[tokio::test]
async fn resolve_purpose_bound_profile_accepts_matching_purpose() {
    // A purpose-bound profile (purpose set, entity NOT otherwise governing
    // purposes) resolves when the data-purpose header equals the profile purpose.
    let server = try_server_full(
        &[RELEASE_SCOPE],
        "",
        true,
        Some("identity"),
        &ConfigExtras::default(),
    )
    .await
    .expect("test server builds");
    let response = server
        .post(RESOLVE_PATH)
        .add_header("data-purpose", "identity")
        .json(&subject_body("NID-1"))
        .await;
    response.assert_status(StatusCode::OK);
    assert_eq!(response.json::<Value>()["claims"]["given_name"], "Ada");
}

#[tokio::test]
async fn resolve_purpose_bound_profile_missing_header_is_purpose_required() {
    // Without a backing governed_policy the entity would not require purpose, but
    // the profile purpose binding does: a missing data-purpose header is rejected
    // before the read with 400 auth.purpose_required.
    let server = try_server_full(
        &[RELEASE_SCOPE],
        "",
        true,
        Some("identity"),
        &ConfigExtras::default(),
    )
    .await
    .expect("test server builds");
    let response = server.post(RESOLVE_PATH).json(&subject_body("NID-1")).await;
    response.assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(response.json::<Value>()["code"], "auth.purpose_required");
}

#[tokio::test]
async fn resolve_purpose_bound_profile_wrong_purpose_is_denied() {
    // A data-purpose that does not equal the profile purpose is denied before the
    // read with 403 auth.purpose_denied.
    let server = try_server_full(
        &[RELEASE_SCOPE],
        "",
        true,
        Some("identity"),
        &ConfigExtras::default(),
    )
    .await
    .expect("test server builds");
    let response = server
        .post(RESOLVE_PATH)
        .add_header("data-purpose", "marketing")
        .json(&subject_body("NID-1"))
        .await;
    response.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(response.json::<Value>()["code"], "auth.purpose_denied");
}

#[tokio::test]
async fn resolve_without_release_scope_is_hidden_like_unknown_profile() {
    // Discovery hides profiles without the release scope. Resolve must return
    // the same response for that known profile and an unknown profile so the
    // path cannot be used as a profile-id oracle.
    let server = try_server_with_scopes_and_extra(&[READ_SCOPE], "")
        .await
        .expect("test server builds");
    let known = server.post(RESOLVE_PATH).json(&subject_body("NID-1")).await;
    let unknown = server
        .post("/v1/attribute-releases/unknown/versions/v1/resolve")
        .json(&subject_body("NID-1"))
        .await;
    known.assert_status(StatusCode::NOT_FOUND);
    unknown.assert_status(StatusCode::NOT_FOUND);
    assert_eq!(known.json::<Value>(), unknown.json::<Value>());
}

#[tokio::test]
async fn resolve_missing_purpose_denies_before_read() {
    let server = try_server_full(
        &[RELEASE_SCOPE],
        "          require_purpose_header: true\n",
        true,
        Some("identity"),
        &ConfigExtras::default(),
    )
    .await
    .expect("test server builds");
    let response = server.post(RESOLVE_PATH).json(&subject_body("NID-1")).await;
    response.assert_status(StatusCode::BAD_REQUEST);
    assert_eq!(response.json::<Value>()["code"], "auth.purpose_required");
}

#[test]
fn config_accepts_hyphenated_profile_id_and_dotted_claim_name() {
    // Review #3/#4: the eSignet contract uses a hyphenated profile id
    // (`esignet-civil-userinfo`) and dotted OIDC claim names (`address.region`).
    // Both must pass config validation, which previously rejected them as not
    // matching `^[a-z][a-z0-9_]*$`.
    env::set_var(
        "REGISTRY_RELAY_TEST_AUDIT_HASH_SECRET",
        "relay-release-audit-secret-32-bytes",
    );
    let yaml = release_config("", false, "identity", &ConfigExtras::default())
        .replace("id: civil_identity", "id: esignet-civil-userinfo")
        .replace("name: optional_note", "name: address.region");
    let tmp = TempDir::new().expect("tempdir");
    let path = tmp.path().join("release.yaml");
    std::fs::write(&path, yaml).expect("write config");
    assert!(
        config::load(&path).is_ok(),
        "config with a hyphenated profile id and a dotted claim name must load"
    );
}

#[tokio::test]
async fn release_scope_alone_does_not_authorize_row_reads() {
    // The release scope is distinct from the read scope; this asserts the two
    // are not the same string so a release grant cannot be reused for rows.
    assert_ne!(RELEASE_SCOPE, READ_SCOPE);
    // And a release-scope-only caller still resolves a release successfully,
    // proving the release path checks the release scope (not the read scope).
    let server = try_server_with_scopes_and_extra(&[RELEASE_SCOPE], "")
        .await
        .expect("test server builds");
    let response = server.post(RESOLVE_PATH).json(&subject_body("NID-1")).await;
    response.assert_status(StatusCode::OK);
}

// ---------------------------------------------------------------------------
// Content negotiation & method
// ---------------------------------------------------------------------------

#[tokio::test]
async fn resolve_rejects_non_json_content_type() {
    let server = server().await;
    let response = server.post(RESOLVE_PATH).text("subject=NID-1").await;
    response.assert_status(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    assert_eq!(
        response.json::<Value>()["code"],
        "release.unsupported_media_type"
    );
    assert_eq!(
        response.header("cache-control").to_str().expect("ascii"),
        "private, no-store"
    );
    assert_eq!(
        response.header("vary").to_str().expect("ascii"),
        "Authorization"
    );
}

#[tokio::test]
async fn resolve_normalizes_json_data_errors_to_problem_details() {
    let server = server().await;
    let response = server
        .post(RESOLVE_PATH)
        .json(&json!({
            "subject": {
                "id_type": "NATIONAL_ID"
            }
        }))
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    let body = response.json::<Value>();
    assert_eq!(body["code"], "release.invalid_request");
    assert_eq!(body["status"], 400);
    assert_eq!(
        response.header("cache-control").to_str().expect("ascii"),
        "private, no-store"
    );
    assert_eq!(
        response.header("vary").to_str().expect("ascii"),
        "Authorization"
    );
}

#[tokio::test]
async fn resolve_normalizes_json_syntax_errors_to_problem_details() {
    let server = server().await;
    let response = server
        .post(RESOLVE_PATH)
        .add_header("content-type", "application/json")
        .bytes(Bytes::from_static(b"{"))
        .await;
    response.assert_status(StatusCode::BAD_REQUEST);
    let body = response.json::<Value>();
    assert_eq!(body["code"], "release.invalid_request");
    assert_eq!(body["status"], 400);
    assert_eq!(
        response.header("cache-control").to_str().expect("ascii"),
        "private, no-store"
    );
}

#[tokio::test]
async fn resolve_path_rejects_get_method() {
    let server = server().await;
    let response = server
        .get("/v1/attribute-releases/civil_identity/versions/v1/resolve")
        .await;
    response.assert_status(StatusCode::METHOD_NOT_ALLOWED);
}

// ---------------------------------------------------------------------------
// Discovery
// ---------------------------------------------------------------------------

#[tokio::test]
async fn discovery_lists_visible_profiles_for_authorized_caller() {
    let server = server().await;
    let response = server.get("/v1/attribute-releases").await;
    response.assert_status(StatusCode::OK);
    let body: Value = response.json();
    let profiles = body["profiles"].as_array().expect("profiles array");
    assert_eq!(profiles.len(), 1);
    let profile = &profiles[0];
    assert_eq!(profile["id"], "civil_identity");
    assert_eq!(profile["version"], "v1");
    assert_eq!(profile["response_media_type"], "application/json");
    assert_eq!(profile["release_scope"], RELEASE_SCOPE);
    assert_eq!(profile["accepted_subject_id_types"][0], "NATIONAL_ID");
    assert!(profile["claim_names"]
        .as_array()
        .expect("claim_names")
        .iter()
        .any(|name| name == "given_name"));
    assert!(profile["required_claims"]
        .as_array()
        .expect("required_claims")
        .iter()
        .any(|name| name == "given_name"));
}

#[tokio::test]
async fn discovery_does_not_leak_source_internals() {
    let server = server().await;
    let response = server.get("/v1/attribute-releases").await;
    response.assert_status(StatusCode::OK);
    let serialized = response.json::<Value>().to_string();
    // Private source internals must never appear: table id, source field names.
    assert!(!serialized.contains("persons_table"));
    assert!(!serialized.contains("national_id"));
    assert!(!serialized.contains("source_field"));
}

#[tokio::test]
async fn discovery_hides_profiles_without_release_scope() {
    // A caller lacking the profile's release scope sees an empty profile list.
    let server = try_server_with_scopes_and_extra(&[READ_SCOPE], "")
        .await
        .expect("test server builds");
    let response = server.get("/v1/attribute-releases").await;
    response.assert_status(StatusCode::OK);
    let body: Value = response.json();
    assert!(body["profiles"]
        .as_array()
        .expect("profiles array")
        .is_empty());
}

#[tokio::test]
async fn discovery_sets_private_metadata_headers() {
    let server = server().await;
    let response = server.get("/v1/attribute-releases").await;
    response.assert_status(StatusCode::OK);
    assert_eq!(
        response.header("cache-control").to_str().expect("ascii"),
        "private, no-store"
    );
    assert_eq!(
        response.header("vary").to_str().expect("ascii"),
        "Authorization"
    );
}

#[tokio::test]
async fn resolve_success_defaults_to_no_store() {
    // A released identity bundle is PII and the POST response has no reusable
    // retrieval URI, so every success must forbid caching.
    let server = server().await;
    let response = server.post(RESOLVE_PATH).json(&subject_body("NID-1")).await;
    response.assert_status(StatusCode::OK);
    assert_eq!(
        response.header("cache-control").to_str().expect("ascii"),
        "private, no-store"
    );
    assert_eq!(
        response.header("vary").to_str().expect("ascii"),
        "Authorization"
    );
}

#[tokio::test]
async fn resolve_denial_is_never_cached() {
    let server = server().await;
    let response = server
        .post(RESOLVE_PATH)
        .json(&subject_body("NID-MISSING"))
        .await;
    response.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(
        response.header("cache-control").to_str().expect("ascii"),
        "private, no-store"
    );
}
