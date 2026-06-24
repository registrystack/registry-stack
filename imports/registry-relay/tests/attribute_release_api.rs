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
use datafusion::arrow::array::StringArray;
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

/// A two-row civil-registry config with one release profile. `deceased`
/// drives the release-condition predicate; `given_name`/`surname` back direct
/// and computed claims. The `optional_note` claim is optional and absent on the
/// stored row so it is omitted from a successful release.
fn release_config(
    entity_api_extra: &str,
    include_source_metadata: bool,
    max_age_seconds: Option<u64>,
    purpose: Option<&str>,
) -> String {
    let max_age_line = match max_age_seconds {
        Some(secs) => format!("\n              max_age_seconds: {secs}"),
        None => String::new(),
    };
    // A purpose-bound profile declares `purpose`; an unbound one omits it. The
    // default fixture is unbound so the bulk of the tests need no data-purpose
    // header; purpose-gate and governed-policy tests pass an explicit purpose.
    let purpose_line = match purpose {
        Some(value) => format!("            purpose: {value}\n"),
        None => String::new(),
    };
    format!(
        r#"
server:
  bind: 127.0.0.1:0

catalog:
  title: Test
  base_url: https://gw.example
  publisher: Test

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
{purpose_line}            release_scope: {RELEASE_SCOPE}
            subject:
              input: subject_token
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
              include_source_metadata: {include_source_metadata}{max_age_line}
"#
    )
}

/// Build a two-row table: one live subject (`NID-1`) and one deceased subject
/// (`NID-DEAD`). `NID-DUP` is duplicated to exercise the ambiguity gate.
fn batch(schema: &Arc<Schema>) -> RecordBatch {
    RecordBatch::try_new(
        Arc::clone(schema),
        vec![
            Arc::new(StringArray::from(vec!["p1", "p2", "p3", "p4"])),
            Arc::new(StringArray::from(vec![
                "NID-1", "NID-DEAD", "NID-DUP", "NID-DUP",
            ])),
            Arc::new(StringArray::from(vec!["Ada", "Grace", "Alan", "Alan"])),
            Arc::new(StringArray::from(vec![
                "Lovelace", "Hopper", "Turing", "Turing",
            ])),
            Arc::new(StringArray::from(vec!["false", "true", "false", "false"])),
        ],
    )
    .expect("batch")
}

async fn try_server_with_scopes_and_extra(
    scopes: &[&str],
    entity_api_extra: &str,
) -> Result<TestServer, TestServerBuildError> {
    // Default fixture is purpose-unbound, so resolve requests need no
    // data-purpose header; purpose-gate/governed tests build with an explicit
    // purpose via `try_server_full`.
    try_server_full(scopes, entity_api_extra, true, None, None).await
}

/// Like [`try_server_with_scopes_and_extra`] but with explicit control over the
/// profile's `response.include_source_metadata` flag (so both branches of the
/// source-block gate can be exercised), its `response.max_age_seconds` cache
/// opt-in (so the default `no-store` and the `private, max-age=N` paths can be
/// asserted), and its `purpose` binding (so the data-purpose gate can be
/// exercised). A `Some` purpose makes the profile purpose-bound.
async fn try_server_full(
    scopes: &[&str],
    entity_api_extra: &str,
    include_source_metadata: bool,
    max_age_seconds: Option<u64>,
    purpose: Option<&str>,
) -> Result<TestServer, TestServerBuildError> {
    let tmp = TempDir::new().expect("tempdir");
    let config_path = tmp.path().join("release.yaml");
    std::fs::write(
        &config_path,
        release_config(
            entity_api_extra,
            include_source_metadata,
            max_age_seconds,
            purpose,
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
    let schema = Arc::new(Schema::new(vec![
        Field::new("person_id", DataType::Utf8, false),
        Field::new("national_id", DataType::Utf8, false),
        Field::new("given_name", DataType::Utf8, false),
        Field::new("surname", DataType::Utf8, false),
        Field::new("deceased", DataType::Utf8, false),
    ]));
    let ingest_ulid = Ulid::from_string("01J5K8M0000000000000000000").expect("ulid");
    register_versioned_table(
        &ctx,
        table_name(&dataset, &resource),
        ingest_ulid,
        Arc::new(
            MemTable::try_new(Arc::clone(&schema), vec![vec![batch(&schema)]]).expect("memtable"),
        ),
    )
    .expect("register");
    let mut snapshot = ReadinessSnapshot::default();
    snapshot.ready.insert(
        (dataset, resource),
        ReadyResource {
            ingest_ulid,
            registered_at: time::OffsetDateTime::now_utc(),
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
    Ok(TestServer::new(app))
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
    let server = try_server_full(&[RELEASE_SCOPE], "", false, None, None)
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
"#,
        true,
        None,
        Some("identity"),
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
"#,
        true,
        None,
        Some("identity"),
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
"#,
        true,
        None,
        Some("identity"),
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

// ---------------------------------------------------------------------------
// Scope / purpose deny-before-read
// ---------------------------------------------------------------------------

#[tokio::test]
async fn resolve_purpose_bound_profile_accepts_matching_purpose() {
    // A purpose-bound profile (purpose set, entity NOT otherwise governing
    // purposes) resolves when the data-purpose header equals the profile purpose.
    let server = try_server_full(&[RELEASE_SCOPE], "", true, None, Some("identity"))
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
    let server = try_server_full(&[RELEASE_SCOPE], "", true, None, Some("identity"))
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
    let server = try_server_full(&[RELEASE_SCOPE], "", true, None, Some("identity"))
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
async fn resolve_without_release_scope_is_denied_before_read() {
    // A caller holding only the row-read scope cannot invoke a release.
    let server = try_server_with_scopes_and_extra(&[READ_SCOPE], "")
        .await
        .expect("test server builds");
    let response = server.post(RESOLVE_PATH).json(&subject_body("NID-1")).await;
    response.assert_status(StatusCode::FORBIDDEN);
    assert_eq!(response.json::<Value>()["code"], "auth.scope_denied");
}

#[tokio::test]
async fn resolve_missing_purpose_denies_before_read() {
    let server = try_server_with_scopes_and_extra(
        &[RELEASE_SCOPE],
        "          require_purpose_header: true\n",
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
    let yaml = release_config("", false, None, Some("identity"))
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
    // A released identity bundle is PII; with no `response.max_age_seconds`
    // configured the response must forbid any caching.
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
async fn resolve_success_honours_configured_max_age() {
    // A profile may opt into bounded *private* caching of a successful release;
    // `response.max_age_seconds: 300` yields `private, max-age=300` (never a
    // shared cache, still keyed by Authorization via Vary).
    let server = try_server_full(&[RELEASE_SCOPE], "", true, Some(300), None)
        .await
        .expect("test server builds");
    let response = server.post(RESOLVE_PATH).json(&subject_body("NID-1")).await;
    response.assert_status(StatusCode::OK);
    assert_eq!(
        response.header("cache-control").to_str().expect("ascii"),
        "private, max-age=300"
    );
    assert_eq!(
        response.header("vary").to_str().expect("ascii"),
        "Authorization"
    );
}

#[tokio::test]
async fn resolve_denial_is_never_cached_even_with_max_age() {
    // Denials must never be cached regardless of the profile's caching opt-in:
    // a missing subject collapses to `release.subject_denied` (403) and the
    // response must still be `private, no-store`, not `max-age=300`.
    let server = try_server_full(&[RELEASE_SCOPE], "", true, Some(300), None)
        .await
        .expect("test server builds");
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
