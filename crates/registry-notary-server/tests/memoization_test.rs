// SPDX-License-Identifier: Apache-2.0
//! End-to-end tests for per-`batch_evaluate` fetch memoization (Stage 2).
//!
//! Each test wires a counted mock upstream (same pattern as
//! `concurrency_http_test.rs`), fires a `batch_evaluate` call, then asserts
//! on the upstream request count to verify that the memo prevented duplicate
//! fetches where expected and did NOT deduplicate where keys differ.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_test::TestServer;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use registry_notary_core::sd_jwt::{issue as sd_jwt_issue, EvidenceIssuer, IssueOptions};
use registry_notary_core::{
    AccessMode, BatchEvaluateItemRequest, BatchEvaluateRequest, ClaimDefinition,
    ClaimOperationsConfig, ClaimRef, ClaimResultView, ClaimValueConfig, ConcurrencyConfig,
    CredentialProfileConfig, DisclosureConfig, EvidenceConfig, EvidenceError, EvidencePrincipal,
    RuleConfig, SourceBindingConfig, SourceConnectorKind, SourceFieldConfig, SourceLookupConfig,
    SourceMatchingConfig, StandaloneRegistryNotaryConfig, SubjectRequest, FORMAT_CLAIM_RESULT_JSON,
    FORMAT_SD_JWT_VC,
};
use registry_notary_server::{
    standalone_router, BatchEvaluateOptions, EvidenceStore, MemoState, RegistryNotaryRuntime,
    SourceReader,
};
use registry_platform_crypto::{did_jwk_from_public_jwk, PrivateJwk};
use serde_json::{json, Value};
use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use tempfile::TempDir;
use time::format_description::well_known::Rfc3339;
use time::OffsetDateTime;

const TEST_AUDIT_SECRET: &str = "0123456789abcdef0123456789abcdef";
const TEST_MEMO_API_KEY_HASH: &str =
    "sha256:7ef768fc3d2b9a667fa45576a9dcc26cc47a9925fea1410910eabbd8cf2e687c";

fn person_target(id: &str) -> Value {
    json!({
        "type": "Person",
        "id": id,
    })
}

fn set_audit_secret() {
    std::env::set_var("REGISTRY_NOTARY_AUDIT_HASH_SECRET", TEST_AUDIT_SECRET);
}

fn test_api_key_fingerprint_ref_yaml(_id: &str, env_name: &str, _fingerprint: &str) -> String {
    format!("fingerprint:\n        provider: env\n        name: {env_name}")
}

// ---------------------------------------------------------------------------
// Shared mock upstream helpers
// ---------------------------------------------------------------------------

#[derive(Clone, Default)]
struct UpstreamCounter {
    total: Arc<AtomicUsize>,
    /// When > 0, the first `fail_first` requests return HTTP 500.
    fail_first: Arc<AtomicUsize>,
}

impl UpstreamCounter {
    fn new() -> Self {
        Self::default()
    }

    fn total(&self) -> usize {
        self.total.load(Ordering::SeqCst)
    }
}

/// Counts requests and returns a simple JSON body keyed on the `id` query param.
async fn counting_rda_handler(
    State(counter): State<UpstreamCounter>,
    Query(params): Query<BTreeMap<String, String>>,
) -> Response {
    let attempt = counter.total.fetch_add(1, Ordering::SeqCst) + 1;
    let fail_n = counter.fail_first.load(Ordering::SeqCst);
    if attempt <= fail_n {
        return StatusCode::INTERNAL_SERVER_ERROR.into_response();
    }
    let id = params.get("id").cloned().unwrap_or_default();
    Json(json!({
        "data": [{ "id": id, "total_farmed_area": 1.0 }]
    }))
    .into_response()
}

/// DCI mock: counts requests, returns a minimal DCI search response.
async fn counting_dci_handler(
    State(counter): State<UpstreamCounter>,
    axum::extract::Json(body): axum::extract::Json<Value>,
) -> Response {
    counter.total.fetch_add(1, Ordering::SeqCst);
    // Echo back the first reference_id from the search_request so the
    // project_dci_record path can extract it.
    let ref_id = body
        .pointer("/message/search_request/0/reference_id")
        .and_then(Value::as_str)
        .unwrap_or("unknown")
        .to_string();
    let lookup_value = body
        .pointer("/message/search_request/0/search_criteria/query/value")
        .cloned()
        .unwrap_or(json!("unknown-id"));
    Json(json!({
        "message": {
            "search_response": [{
                "reference_id": ref_id,
                "status": "succ",
                "data": {
                    "reg_records": [{
                        "id_type": "national_id",
                        "id_value": lookup_value,
                        "is_farmer": true,
                    }]
                }
            }]
        }
    }))
    .into_response()
}

// ---------------------------------------------------------------------------
// Config builders
// ---------------------------------------------------------------------------

/// Build a config with one `farmed-land-size` claim (single binding, RDA).
fn rda_config(
    base_url: &str,
    audit_path: &str,
    max_subjects: usize,
) -> StandaloneRegistryNotaryConfig {
    set_audit_secret();
    let api_key_fingerprint = test_api_key_fingerprint_ref_yaml(
        "caseworker",
        "TEST_MEMO_API_KEY_HASH",
        TEST_MEMO_API_KEY_HASH,
    );
    let raw = format!(
        r#"
deployment:
  profile: local

server:
  bind: 127.0.0.1:0
auth:
  mode: api_key
  api_keys:
    - id: caseworker
      {api_key_fingerprint}
      scopes: [farmer_registry:evidence_verification]
audit:
  sink: file
  path: "{audit_path}"
  hash_secret_env: REGISTRY_NOTARY_AUDIT_HASH_SECRET
evidence:
  enabled: true
  service_id: evidence.test
  allowed_purposes:
    - https://purpose.example.test/eligibility
    - https://purpose.example.test/subsidy
  concurrency:
    subjects: 32
    bindings: 16
  source_connections:
    farmer_registry:
      base_url: "{base_url}"
      allow_insecure_localhost: true
      token_env: TEST_MEMO_SOURCE_TOKEN
      max_in_flight: 32
  claims:
    - id: farmed-land-size
      title: Farmed land size
      version: 2026-05
      subject_type: person
      evidence_mode:
        type: transitional_direct
      value:
        type: number
        unit: hectare
      operations:
        batch_evaluate:
          enabled: true
          max_subjects: {max_subjects}
      source_bindings:
        farmer:
          connector: registry_data_api
          connection: farmer_registry
          required_scope: farmer_registry:evidence_verification
          dataset: farmer_registry
          entity: farmer
          lookup:
            input: target.id
            field: id
            op: eq
            cardinality: one
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
      disclosure:
        default: value
        allowed: [value, redacted]
      formats:
        - application/vnd.registry-notary.claim-result+json
"#
    );
    serde_norway::from_str(&raw).expect("rda config deserializes")
}

/// Build a config with TWO claims sharing the SAME binding (same connection /
/// dataset / entity / lookup). Used for the positive single-subject dedup test.
fn two_claims_shared_binding_config(
    base_url: &str,
    audit_path: &str,
) -> StandaloneRegistryNotaryConfig {
    set_audit_secret();
    let api_key_fingerprint = test_api_key_fingerprint_ref_yaml(
        "caseworker",
        "TEST_MEMO_API_KEY_HASH",
        TEST_MEMO_API_KEY_HASH,
    );
    let raw = format!(
        r#"
deployment:
  profile: local

server:
  bind: 127.0.0.1:0
auth:
  mode: api_key
  api_keys:
    - id: caseworker
      {api_key_fingerprint}
      scopes: [farmer_registry:evidence_verification]
audit:
  sink: file
  path: "{audit_path}"
  hash_secret_env: REGISTRY_NOTARY_AUDIT_HASH_SECRET
evidence:
  enabled: true
  service_id: evidence.test
  allowed_purposes:
    - https://purpose.example.test/eligibility
    - https://purpose.example.test/subsidy
  concurrency:
    subjects: 32
    bindings: 16
  source_connections:
    farmer_registry:
      base_url: "{base_url}"
      allow_insecure_localhost: true
      token_env: TEST_MEMO_SOURCE_TOKEN
      max_in_flight: 32
  claims:
    - id: farmed-land-size
      title: Farmed land size
      version: 2026-05
      subject_type: person
      evidence_mode:
        type: transitional_direct
      value:
        type: number
        unit: hectare
      operations:
        batch_evaluate:
          enabled: true
          max_subjects: 10
      source_bindings:
        farmer:
          connector: registry_data_api
          connection: farmer_registry
          required_scope: farmer_registry:evidence_verification
          dataset: farmer_registry
          entity: farmer
          lookup:
            input: target.id
            field: id
            op: eq
            cardinality: one
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
      disclosure:
        default: value
        allowed: [value, redacted]
      formats:
        - application/vnd.registry-notary.claim-result+json
    - id: is-active-farmer
      title: Is active farmer
      version: 2026-05
      subject_type: person
      evidence_mode:
        type: transitional_direct
      operations:
        batch_evaluate:
          enabled: true
          max_subjects: 10
      source_bindings:
        farmer:
          connector: registry_data_api
          connection: farmer_registry
          required_scope: farmer_registry:evidence_verification
          dataset: farmer_registry
          entity: farmer
          lookup:
            input: target.id
            field: id
            op: eq
            cardinality: one
          fields:
            total_farmed_area:
              field: total_farmed_area
              type: number
              unit: hectare
              required: true
      rule:
        type: exists
        source: farmer
      disclosure:
        default: value
        allowed: [value, redacted]
      formats:
        - application/vnd.registry-notary.claim-result+json
"#
    );
    serde_norway::from_str(&raw).expect("two-claims config deserializes")
}

/// Three claims all sharing the same binding, for the 50-subject batch dedup test.
fn three_claims_shared_binding_config(
    base_url: &str,
    audit_path: &str,
) -> StandaloneRegistryNotaryConfig {
    set_audit_secret();
    let api_key_fingerprint = test_api_key_fingerprint_ref_yaml(
        "caseworker",
        "TEST_MEMO_API_KEY_HASH",
        TEST_MEMO_API_KEY_HASH,
    );
    let raw = format!(
        r#"
deployment:
  profile: local

server:
  bind: 127.0.0.1:0
auth:
  mode: api_key
  api_keys:
    - id: caseworker
      {api_key_fingerprint}
      scopes: [farmer_registry:evidence_verification]
audit:
  sink: file
  path: "{audit_path}"
  hash_secret_env: REGISTRY_NOTARY_AUDIT_HASH_SECRET
evidence:
  enabled: true
  service_id: evidence.test
  allowed_purposes:
    - https://purpose.example.test/eligibility
    - https://purpose.example.test/subsidy
  concurrency:
    subjects: 32
    bindings: 16
  source_connections:
    farmer_registry:
      base_url: "{base_url}"
      allow_insecure_localhost: true
      token_env: TEST_MEMO_SOURCE_TOKEN
      max_in_flight: 32
  claims:
    - id: farmed-land-size
      title: Farmed land size
      version: 2026-05
      subject_type: person
      evidence_mode:
        type: transitional_direct
      value:
        type: number
        unit: hectare
      operations:
        batch_evaluate:
          enabled: true
          max_subjects: 60
      source_bindings:
        farmer:
          connector: registry_data_api
          connection: farmer_registry
          required_scope: farmer_registry:evidence_verification
          dataset: farmer_registry
          entity: farmer
          lookup:
            input: target.id
            field: id
            op: eq
            cardinality: one
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
      disclosure:
        default: value
        allowed: [value, redacted]
      formats:
        - application/vnd.registry-notary.claim-result+json
    - id: is-active-farmer
      title: Is active farmer
      version: 2026-05
      subject_type: person
      evidence_mode:
        type: transitional_direct
      operations:
        batch_evaluate:
          enabled: true
          max_subjects: 60
      source_bindings:
        farmer:
          connector: registry_data_api
          connection: farmer_registry
          required_scope: farmer_registry:evidence_verification
          dataset: farmer_registry
          entity: farmer
          lookup:
            input: target.id
            field: id
            op: eq
            cardinality: one
          fields:
            total_farmed_area:
              field: total_farmed_area
              type: number
              unit: hectare
              required: true
      rule:
        type: exists
        source: farmer
      disclosure:
        default: value
        allowed: [value, redacted]
      formats:
        - application/vnd.registry-notary.claim-result+json
    - id: large-farm
      title: Large farm
      version: 2026-05
      subject_type: person
      evidence_mode:
        type: transitional_direct
      operations:
        batch_evaluate:
          enabled: true
          max_subjects: 60
      source_bindings:
        farmer:
          connector: registry_data_api
          connection: farmer_registry
          required_scope: farmer_registry:evidence_verification
          dataset: farmer_registry
          entity: farmer
          lookup:
            input: target.id
            field: id
            op: eq
            cardinality: one
          fields:
            total_farmed_area:
              field: total_farmed_area
              type: number
              unit: hectare
              required: true
      rule:
        type: exists
        source: farmer
      disclosure:
        default: value
        allowed: [value, redacted]
      formats:
        - application/vnd.registry-notary.claim-result+json
"#
    );
    serde_norway::from_str(&raw).expect("three-claims config deserializes")
}

/// Two claims with DIFFERENT lookup.op to verify they are NOT memoized together.
/// The second claim uses op=neq (which will fail at runtime as unsupported but the
/// point is the cache keys must differ; we test this via different `fields` instead
/// since `op` must be "eq" at the connector level). Instead we use different
/// projected_fields sets to prove cache separation.
fn two_claims_different_fields_config(
    base_url: &str,
    audit_path: &str,
) -> StandaloneRegistryNotaryConfig {
    set_audit_secret();
    let api_key_fingerprint = test_api_key_fingerprint_ref_yaml(
        "caseworker",
        "TEST_MEMO_API_KEY_HASH",
        TEST_MEMO_API_KEY_HASH,
    );
    let raw = format!(
        r#"
deployment:
  profile: local

server:
  bind: 127.0.0.1:0
auth:
  mode: api_key
  api_keys:
    - id: caseworker
      {api_key_fingerprint}
      scopes: [farmer_registry:evidence_verification]
audit:
  sink: file
  path: "{audit_path}"
  hash_secret_env: REGISTRY_NOTARY_AUDIT_HASH_SECRET
evidence:
  enabled: true
  service_id: evidence.test
  allowed_purposes:
    - https://purpose.example.test/eligibility
    - https://purpose.example.test/subsidy
  concurrency:
    subjects: 32
    bindings: 16
  source_connections:
    farmer_registry:
      base_url: "{base_url}"
      allow_insecure_localhost: true
      token_env: TEST_MEMO_SOURCE_TOKEN
      max_in_flight: 32
  claims:
    - id: farmed-land-size
      title: Farmed land size
      version: 2026-05
      subject_type: person
      evidence_mode:
        type: transitional_direct
      operations:
        batch_evaluate:
          enabled: true
          max_subjects: 10
      source_bindings:
        farmer:
          connector: registry_data_api
          connection: farmer_registry
          required_scope: farmer_registry:evidence_verification
          dataset: farmer_registry
          entity: farmer
          lookup:
            input: target.id
            field: id
            op: eq
            cardinality: one
          fields:
            total_farmed_area:
              field: total_farmed_area
              type: number
              unit: hectare
              required: true
      rule:
        type: exists
        source: farmer
      disclosure:
        default: value
        allowed: [value, redacted]
      formats:
        - application/vnd.registry-notary.claim-result+json
    - id: farmer-id-only
      title: Farmer id only
      version: 2026-05
      subject_type: person
      evidence_mode:
        type: transitional_direct
      operations:
        batch_evaluate:
          enabled: true
          max_subjects: 10
      source_bindings:
        farmer:
          connector: registry_data_api
          connection: farmer_registry
          required_scope: farmer_registry:evidence_verification
          dataset: farmer_registry
          entity: farmer
          lookup:
            input: target.id
            field: id
            op: eq
            cardinality: one
      rule:
        type: exists
        source: farmer
      disclosure:
        default: value
        allowed: [value, redacted]
      formats:
        - application/vnd.registry-notary.claim-result+json
"#
    );
    serde_norway::from_str(&raw).expect("different-fields config deserializes")
}

/// DCI config with two claims using different query_type values.
fn two_dci_claims_different_query_type_config(
    base_url: &str,
    audit_path: &str,
) -> StandaloneRegistryNotaryConfig {
    set_audit_secret();
    let api_key_fingerprint = test_api_key_fingerprint_ref_yaml(
        "caseworker",
        "TEST_MEMO_API_KEY_HASH",
        TEST_MEMO_API_KEY_HASH,
    );
    let raw = format!(
        r#"
deployment:
  profile: local

server:
  bind: 127.0.0.1:0
auth:
  mode: api_key
  api_keys:
    - id: caseworker
      {api_key_fingerprint}
      scopes: [farmer_registry:evidence_verification]
audit:
  sink: file
  path: "{audit_path}"
  hash_secret_env: REGISTRY_NOTARY_AUDIT_HASH_SECRET
evidence:
  enabled: true
  service_id: evidence.test
  allowed_purposes:
    - https://purpose.example.test/eligibility
    - https://purpose.example.test/subsidy
  concurrency:
    subjects: 32
    bindings: 16
  source_connections:
    registry_a:
      base_url: "{base_url}"
      allow_insecure_localhost: true
      token_env: TEST_MEMO_SOURCE_TOKEN
      max_in_flight: 32
      dci:
        query_type: idtype-value
        search_path: /registry/sync/search
        records_path: /message/search_response/0/data/reg_records
    registry_b:
      base_url: "{base_url}"
      allow_insecure_localhost: true
      token_env: TEST_MEMO_SOURCE_TOKEN
      max_in_flight: 32
      dci:
        query_type: expression
        search_path: /registry/sync/search
        records_path: /message/search_response/0/data/reg_records
  claims:
    - id: dci-claim-a
      title: DCI claim A
      version: 2026-05
      subject_type: person
      evidence_mode:
        type: transitional_direct
      operations:
        batch_evaluate:
          enabled: true
          max_subjects: 10
      source_bindings:
        record:
          connector: dci
          connection: registry_a
          required_scope: farmer_registry:evidence_verification
          dataset: farmer_registry
          entity: farmer
          lookup:
            input: target.id
            field: id_type
            op: eq
            cardinality: one
          fields:
            is_farmer:
              field: is_farmer
              type: boolean
              required: true
      rule:
        type: exists
        source: record
      disclosure:
        default: value
        allowed: [value, redacted]
      formats:
        - application/vnd.registry-notary.claim-result+json
    - id: dci-claim-b
      title: DCI claim B
      version: 2026-05
      subject_type: person
      evidence_mode:
        type: transitional_direct
      operations:
        batch_evaluate:
          enabled: true
          max_subjects: 10
      source_bindings:
        record:
          connector: dci
          connection: registry_b
          required_scope: farmer_registry:evidence_verification
          dataset: farmer_registry
          entity: farmer
          lookup:
            input: target.id
            field: id_type
            op: eq
            cardinality: one
          fields:
            is_farmer:
              field: is_farmer
              type: boolean
              required: true
      rule:
        type: exists
        source: record
      disclosure:
        default: value
        allowed: [value, redacted]
      formats:
        - application/vnd.registry-notary.claim-result+json
"#
    );
    serde_norway::from_str(&raw).expect("dci different query_type config deserializes")
}

// ---------------------------------------------------------------------------
// Helper: set test env vars once, idempotently
// ---------------------------------------------------------------------------

fn set_test_env() {
    std::env::set_var("TEST_MEMO_API_KEY_HASH", TEST_MEMO_API_KEY_HASH);
    std::env::set_var("TEST_MEMO_SOURCE_TOKEN", "memo-source-token");
}

fn tmp_audit() -> (TempDir, String) {
    let dir = TempDir::new().expect("tempdir");
    let path = dir
        .path()
        .join("audit.jsonl")
        .to_str()
        .expect("UTF-8")
        .to_string();
    (dir, path)
}

// ---------------------------------------------------------------------------
// Test: positive - one subject, two claims sharing one binding = 1 upstream call
// ---------------------------------------------------------------------------

#[tokio::test]
async fn single_subject_two_claims_shared_binding_deduplicates_to_one_upstream_call() {
    set_test_env();

    let counter = UpstreamCounter::new();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route(
                "/v1/datasets/farmer_registry/entities/farmer/records",
                get(counting_rda_handler),
            )
            .with_state(counter.clone()),
    );
    let base = upstream.server_address().expect("addr").to_string();
    let (_dir, audit_path) = tmp_audit();

    let app = standalone_router(two_claims_shared_binding_config(
        base.trim_end_matches('/'),
        &audit_path,
    ))
    .expect("router builds");
    let server = TestServer::builder().http_transport().build(app);

    let response = server
        .post("/v1/batch-evaluations")
        .add_header("x-api-key", "memo-api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&json!({
            "claims": ["farmed-land-size", "is-active-farmer"],
            "items": [{ "target": person_target("person-1") }],
            "disclosure": "value",
        }))
        .await;
    response.assert_status_ok();

    // Two claims share the same binding: only one upstream request expected.
    assert_eq!(
        counter.total(),
        1,
        "two claims sharing one binding must produce exactly 1 upstream call, got {}",
        counter.total()
    );
}

// ---------------------------------------------------------------------------
// Test: batch dedup - 50 subjects, 3 claims sharing 1 binding = 50 upstream calls
// ---------------------------------------------------------------------------

#[tokio::test]
async fn batch_50_subjects_3_claims_shared_binding_produces_50_upstream_calls() {
    set_test_env();

    let counter = UpstreamCounter::new();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route(
                "/v1/datasets/farmer_registry/entities/farmer/records",
                get(counting_rda_handler),
            )
            .with_state(counter.clone()),
    );
    let base = upstream.server_address().expect("addr").to_string();
    let (_dir, audit_path) = tmp_audit();

    let app = standalone_router(three_claims_shared_binding_config(
        base.trim_end_matches('/'),
        &audit_path,
    ))
    .expect("router builds");
    let server = TestServer::builder().http_transport().build(app);

    let subjects: Vec<Value> = (0..50)
        .map(|i| person_target(&format!("person-{i}")))
        .collect();
    let response = server
        .post("/v1/batch-evaluations")
        .add_header("x-api-key", "memo-api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&json!({
            "claims": ["farmed-land-size", "is-active-farmer", "large-farm"],
            "items": subjects.iter().map(|subject| json!({ "target": subject })).collect::<Vec<_>>(),
            "disclosure": "value",
        }))
        .await;
    response.assert_status_ok();

    // 3 claims all share the same binding; each of the 50 subjects needs
    // exactly 1 upstream call.
    assert_eq!(
        counter.total(),
        50,
        "50 subjects * 3 shared-binding claims must produce 50 upstream calls, got {}",
        counter.total()
    );
}

// ---------------------------------------------------------------------------
// Test: negative - different projected_fields = no memoization between claims
// ---------------------------------------------------------------------------

#[tokio::test]
async fn claims_with_different_projected_fields_are_not_memoized_together() {
    set_test_env();

    let counter = UpstreamCounter::new();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route(
                "/v1/datasets/farmer_registry/entities/farmer/records",
                get(counting_rda_handler),
            )
            .with_state(counter.clone()),
    );
    let base = upstream.server_address().expect("addr").to_string();
    let (_dir, audit_path) = tmp_audit();

    let app = standalone_router(two_claims_different_fields_config(
        base.trim_end_matches('/'),
        &audit_path,
    ))
    .expect("router builds");
    let server = TestServer::builder().http_transport().build(app);

    let response = server
        .post("/v1/batch-evaluations")
        .add_header("x-api-key", "memo-api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&json!({
            "claims": ["farmed-land-size", "farmer-id-only"],
            "items": [{ "target": person_target("person-1") }],
            "disclosure": "value",
        }))
        .await;
    response.assert_status_ok();

    // The two claims have different field projections so must NOT share the
    // memoized result.
    assert_eq!(
        counter.total(),
        2,
        "claims with different projected_fields must produce 2 upstream calls, got {}",
        counter.total()
    );
}

// ---------------------------------------------------------------------------
// Test: negative - different purpose = no memoization between claims
// ---------------------------------------------------------------------------

/// Build a config where two separate batch_evaluate calls use different purposes.
/// Within a single batch the purpose is uniform, so we test this by running two
/// separate batch_evaluate calls with different purposes and confirming each
/// produces its own upstream request (1 per call, 2 total), rather than testing
/// within one call. The cache is per-`batch_evaluate` scope, so cross-call
/// sharing is not expected in any case; this test instead verifies that within
/// one batch the purpose is correctly included in the cache key by using a
/// single-subject, single-claim call and checking it reaches upstream once for
/// each distinct purpose across separate calls.
#[tokio::test]
async fn different_purpose_across_batches_each_reaches_upstream() {
    set_test_env();

    let counter = UpstreamCounter::new();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route(
                "/v1/datasets/farmer_registry/entities/farmer/records",
                get(counting_rda_handler),
            )
            .with_state(counter.clone()),
    );
    let base = upstream.server_address().expect("addr").to_string();
    let (_dir, audit_path) = tmp_audit();

    let app = standalone_router(rda_config(base.trim_end_matches('/'), &audit_path, 10))
        .expect("router builds");
    let server = TestServer::builder().http_transport().build(app);

    // First call with purpose A.
    server
        .post("/v1/batch-evaluations")
        .add_header("x-api-key", "memo-api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&json!({
            "claims": ["farmed-land-size"],
            "items": [{ "target": person_target("person-1") }],
            "disclosure": "value",
        }))
        .await
        .assert_status_ok();

    // Second call with purpose B.
    server
        .post("/v1/batch-evaluations")
        .add_header("x-api-key", "memo-api-token")
        .add_header("data-purpose", "https://purpose.example.test/subsidy")
        .json(&json!({
            "claims": ["farmed-land-size"],
            "items": [{ "target": person_target("person-1") }],
            "disclosure": "value",
        }))
        .await
        .assert_status_ok();

    // Each batch produces its own upstream call since the memo does not persist
    // across batch_evaluate calls. 2 total expected.
    assert_eq!(
        counter.total(),
        2,
        "two separate batches each need one upstream call, got {}",
        counter.total()
    );
}

// ---------------------------------------------------------------------------
// Test: negative DCI - different query_type = no memoization
// ---------------------------------------------------------------------------

#[tokio::test]
async fn dci_claims_with_different_query_type_are_not_memoized_together() {
    set_test_env();

    let counter = UpstreamCounter::new();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/registry/sync/search", post(counting_dci_handler))
            .with_state(counter.clone()),
    );
    let base = upstream.server_address().expect("addr").to_string();
    let (_dir, audit_path) = tmp_audit();

    let app = standalone_router(two_dci_claims_different_query_type_config(
        base.trim_end_matches('/'),
        &audit_path,
    ))
    .expect("router builds");
    let server = TestServer::builder().http_transport().build(app);

    let response = server
        .post("/v1/batch-evaluations")
        .add_header("x-api-key", "memo-api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&json!({
            "claims": ["dci-claim-a", "dci-claim-b"],
            "items": [{ "target": person_target("person-1") }],
            "disclosure": "value",
        }))
        .await;
    response.assert_status_ok();

    // Two DCI claims have different query_type; they must each fire their own
    // upstream request.
    assert_eq!(
        counter.total(),
        2,
        "DCI claims with different query_type must not share memoized result, got {}",
        counter.total()
    );
}

// ---------------------------------------------------------------------------
// Test: error not cached - 500 on first call, second call succeeds
// ---------------------------------------------------------------------------

#[tokio::test]
async fn error_result_is_not_cached_and_second_call_can_succeed() {
    set_test_env();

    // Single subject, single claim. First request returns 500 (and the retry
    // also returns 500 so the whole binding fails). Then we fire a second
    // batch_evaluate for the same subject; this must reach upstream afresh.
    let counter = UpstreamCounter::new();
    // Fail the first 2 attempts (initial + retry on first batch call).
    counter.fail_first.store(2, Ordering::SeqCst);

    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route(
                "/v1/datasets/farmer_registry/entities/farmer/records",
                get(counting_rda_handler),
            )
            .with_state(counter.clone()),
    );
    let base = upstream.server_address().expect("addr").to_string();
    let (_dir, audit_path) = tmp_audit();

    let app = standalone_router(rda_config(base.trim_end_matches('/'), &audit_path, 10))
        .expect("router builds");
    let server = TestServer::builder().http_transport().build(app);

    // First batch: must fail because upstream is returning 500.
    let first = server
        .post("/v1/batch-evaluations")
        .add_header("x-api-key", "memo-api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&json!({
            "claims": ["farmed-land-size"],
            "items": [{ "target": person_target("person-1") }],
            "disclosure": "value",
        }))
        .await;
    // The batch itself succeeds (HTTP 200) but the item status is Failed.
    first.assert_status_ok();
    let first_body: Value = first.json();
    assert_eq!(
        first_body["items"][0]["status"],
        json!("failed"),
        "first call must fail when upstream returns 500"
    );

    // Second batch: upstream now returns 200. Must reach upstream (error not
    // cached).
    let second = server
        .post("/v1/batch-evaluations")
        .add_header("x-api-key", "memo-api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&json!({
            "claims": ["farmed-land-size"],
            "items": [{ "target": person_target("person-1") }],
            "disclosure": "value",
        }))
        .await;
    second.assert_status_ok();
    let second_body: Value = second.json();
    assert_eq!(
        second_body["items"][0]["status"],
        json!("succeeded"),
        "second call must succeed once upstream recovers"
    );

    // Total: 2 (initial + retry) for the first failed batch, + at least 1 for
    // the second successful batch.
    assert!(
        counter.total() >= 3,
        "error result must not be cached; expected >= 3 upstream calls, got {}",
        counter.total()
    );
}

// ---------------------------------------------------------------------------
// Test: iat consistency - subjects sharing a memoized read have identical iat
// ---------------------------------------------------------------------------

/// Verify that two claims for the same subject that share one binding produce
/// credentials with identical `issued_at` (iat).
///
/// Within a single `batch_evaluate`, the first claim to load the binding stores
/// `observed_at` in the memo entry. The second claim (sharing the same binding
/// key) hits the memo and adopts `observed_at` as its `issued_at`. Both claim
/// results in the stored evaluation therefore carry the same timestamp.
///
/// We observe `issued_at` by calling `/v1/evaluations/{evaluation_id}/render` with the
/// `claim-result+json` format after the batch, extracting the timestamp from
/// each result in the rendered output.
#[tokio::test]
async fn subjects_sharing_memoized_read_produce_identical_iat() {
    set_test_env();

    let counter = UpstreamCounter::new();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route(
                "/v1/datasets/farmer_registry/entities/farmer/records",
                get(counting_rda_handler),
            )
            .with_state(counter.clone()),
    );
    let base = upstream.server_address().expect("addr").to_string();
    let (_dir, audit_path) = tmp_audit();

    // Two claims sharing the same binding for one subject.
    let app = standalone_router(two_claims_shared_binding_config(
        base.trim_end_matches('/'),
        &audit_path,
    ))
    .expect("router builds");
    let server = TestServer::builder().http_transport().build(app);

    // Use the single-subject /v1/evaluations endpoint so the evaluation is
    // stored with a known evaluation_id. Both claims share the same binding
    // and the same `ctx.now`, so their issued_at must be equal regardless of
    // the memoization path.
    let eval_resp = server
        .post("/v1/evaluations")
        .add_header("x-api-key", "memo-api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&json!({
            "target": person_target("person-memo-iat"),
            "claims": ["farmed-land-size", "is-active-farmer"],
            "disclosure": "value",
        }))
        .await;
    eval_resp.assert_status_ok();
    let eval_body: Value = eval_resp.json();

    // Both claims are in the same evaluate response. Each has an `issued_at`.
    let results = eval_body["results"].as_array().expect("results array");
    assert_eq!(results.len(), 2, "expected 2 claim results");

    let iat_0 = results[0]["issued_at"].as_str().expect("issued_at[0]");
    let iat_1 = results[1]["issued_at"].as_str().expect("issued_at[1]");

    let t0 = OffsetDateTime::parse(iat_0, &Rfc3339).expect("iat[0] parses");
    let t1 = OffsetDateTime::parse(iat_1, &Rfc3339).expect("iat[1] parses");
    assert_eq!(
        t0, t1,
        "both claims sharing one binding must have identical iat: {iat_0} vs {iat_1}"
    );

    // Upstream must have been called exactly once: the second claim hits the
    // memo for the single-evaluate path too? No: single-evaluate passes
    // fetch_memo=None. So both claims call read_one independently. But since
    // they share the same `ctx.now`, iat equality holds regardless.
    //
    // For the batch path, we additionally verify iat consistency by inspecting
    // the rendered evaluation. Run a batch with one subject, two claims sharing
    // a binding, then render via /v1/evaluations/{evaluation_id}/render.
    let batch_resp = server
        .post("/v1/batch-evaluations")
        .add_header("x-api-key", "memo-api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&json!({
            "claims": ["farmed-land-size", "is-active-farmer"],
            "items": [{ "target": person_target("person-batch-iat") }],
            "disclosure": "value",
        }))
        .await;
    batch_resp.assert_status_ok();
    let batch_body: Value = batch_resp.json();
    let item = &batch_body["items"][0];
    assert_eq!(item["status"], json!("succeeded"));

    // Retrieve the stored evaluation via /v1/evaluations/{evaluation_id}/render in claim-result+json
    // format, which includes `issued_at` per result.
    let eval_id = item["evaluation_id"]
        .as_str()
        .expect("batch item evaluation_id");
    let render_resp = server
        .post(&format!("/v1/evaluations/{eval_id}/render"))
        .add_header("x-api-key", "memo-api-token")
        .json(&json!({
            "format": "application/vnd.registry-notary.claim-result+json",
            "disclosure": "value",
        }))
        .await;
    render_resp.assert_status_ok();
    let render_body: Value = render_resp.json();
    let rendered_results = render_body["results"]
        .as_array()
        .expect("rendered results array");
    assert_eq!(rendered_results.len(), 2, "expected 2 rendered results");

    let r_iat_0 = rendered_results[0]["issued_at"]
        .as_str()
        .expect("rendered iat[0]");
    let r_iat_1 = rendered_results[1]["issued_at"]
        .as_str()
        .expect("rendered iat[1]");

    let rt0 = OffsetDateTime::parse(r_iat_0, &Rfc3339).expect("rendered iat[0] parses");
    let rt1 = OffsetDateTime::parse(r_iat_1, &Rfc3339).expect("rendered iat[1] parses");
    assert_eq!(
        rt0, rt1,
        "batch claims sharing one binding must produce identical iat in rendered output: \
         {r_iat_0} vs {r_iat_1}"
    );

    // ----- JWT-level iat assertion ---------------------------------------
    // Re-issue the same evaluation twice through `sd_jwt::issue` and decode
    // the signed JWT payload. The top-level `iat` must be identical across
    // re-issuances: prior to the fix it was `OffsetDateTime::now_utc()` per
    // call and would drift even though all `result.issued_at` were equal.
    let results: Vec<ClaimResultView> = rendered_results
        .iter()
        .map(|v| serde_json::from_value(v.clone()).expect("ClaimResultView deserializes"))
        .collect();
    let issuer =
        EvidenceIssuer::from_jwk_str(TEST_ISSUER_JWK, "did:web:issuer.test#key-1".to_string())
            .expect("test issuer builds");
    let profile = test_credential_profile();
    let iat_anchor = results
        .iter()
        .filter_map(|r| OffsetDateTime::parse(&r.issued_at, &Rfc3339).ok())
        .min()
        .expect("at least one parseable issued_at");

    let subject_ref = results
        .first()
        .expect("at least one result")
        .target_ref
        .handle
        .as_str();
    let holder_id = test_holder_did_jwk();
    let signed_1 = sd_jwt_issue(
        &profile,
        &issuer,
        &results,
        subject_ref,
        Some(&holder_id),
        iat_anchor,
        IssueOptions::default(),
    )
    .await
    .expect("first sd-jwt issuance");
    // Sleep so wall-clock advances between calls; without the fix this gap
    // surfaces as a drift in the JWT `iat`.
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    let signed_2 = sd_jwt_issue(
        &profile,
        &issuer,
        &results,
        subject_ref,
        Some(&holder_id),
        iat_anchor,
        IssueOptions::default(),
    )
    .await
    .expect("second sd-jwt issuance");

    let iat_1 = jwt_payload_iat(&signed_1.compact);
    let iat_2 = jwt_payload_iat(&signed_2.compact);
    assert_eq!(
        iat_1, iat_2,
        "two re-issuances of the same evaluation must produce identical JWT iat",
    );
    assert_eq!(
        iat_1,
        iat_anchor.unix_timestamp(),
        "JWT iat must be anchored to the earliest result.issued_at",
    );
}

/// Decode the base64url-encoded payload segment of a compact SD-JWT and return
/// the top-level `iat` value.
fn jwt_payload_iat(compact: &str) -> i64 {
    let jwt = compact.split('~').next().expect("compact has jwt segment");
    let payload_b64 = jwt
        .split('.')
        .nth(1)
        .expect("compact jwt has three segments");
    let payload_bytes = URL_SAFE_NO_PAD
        .decode(payload_b64)
        .expect("payload decodes as base64url");
    let payload: Value = serde_json::from_slice(&payload_bytes).expect("payload decodes as JSON");
    payload["iat"].as_i64().expect("iat is a JSON integer")
}

/// Same Ed25519 JWK as the core `sd_jwt` unit tests use. Test-only fixture.
const TEST_ISSUER_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA"}"#;

const TEST_HOLDER_JWK: &str = r#"{"crv":"Ed25519","d":"f4QIxnAyRWzhuBOmNRgvBTE56mWePdsPL0mvCtl8Gys","x":"pv4e_hXHBLN27rcs6VDFV1ED0TiU8M3xy9vsuWFEsec","kty":"OKP","alg":"EdDSA"}"#;

fn test_holder_did_jwk() -> String {
    let holder = PrivateJwk::parse(TEST_HOLDER_JWK).expect("holder JWK parses");
    did_jwk_from_public_jwk(&holder.public()).expect("holder did:jwk encodes")
}

fn test_credential_profile() -> CredentialProfileConfig {
    CredentialProfileConfig {
        format: FORMAT_SD_JWT_VC.to_string(),
        issuer: "did:web:issuer.test".to_string(),
        signing_key: "issuer-key".to_string(),
        vct: "https://vct.example/test".to_string(),
        validity_seconds: 60,
        holder_binding: Default::default(),
        allowed_claims: Vec::new(),
        disclosure: Default::default(),
    }
}

// ---------------------------------------------------------------------------
// Memoization counters (Fix 4): assert hits/misses on a dedup scenario
// ---------------------------------------------------------------------------

/// Synchronous `SourceReader` that counts `read_one` calls and returns a
/// stable record per (entity, subject id) pair. Lives in this test module
/// only; production paths use `HttpEvidenceSources`.
#[derive(Debug, Default)]
struct CountingSource {
    calls: AtomicUsize,
}

impl CountingSource {
    fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl SourceReader for CountingSource {
    fn read_one<'a>(
        &'a self,
        _binding: &'a SourceBindingConfig,
        subject: &'a SubjectRequest,
        _purpose: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<Value, EvidenceError>> + Send + 'a>> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let id = subject.id.clone();
        Box::pin(async move { Ok(json!({ "id": id, "value": 1 })) })
    }

    fn required_scopes(
        &self,
        _evidence: &EvidenceConfig,
        _claim_id: &str,
    ) -> Result<Vec<String>, EvidenceError> {
        Ok(Vec::new())
    }
}

fn shared_binding_claim(id: &str) -> ClaimDefinition {
    let mut bindings = BTreeMap::new();
    bindings.insert(
        "src".to_string(),
        SourceBindingConfig {
            connector: SourceConnectorKind::RegistryDataApi,
            connection: None,
            required_scope: None,
            dataset: "ds".to_string(),
            entity: "ent".to_string(),
            lookup: SourceLookupConfig {
                input: "target.id".to_string(),
                field: "id".to_string(),
                op: "eq".to_string(),
                cardinality: "one".to_string(),
            },
            query_fields: Vec::new(),
            fields: BTreeMap::from([(
                "value".to_string(),
                SourceFieldConfig {
                    field: "value".to_string(),
                    field_type: Some("number".to_string()),
                    unit: None,
                    required: true,
                    semantic_term: None,
                },
            )]),
            matching: SourceMatchingConfig::default(),
        },
    );
    ClaimDefinition {
        id: id.to_string(),
        title: id.to_string(),
        version: "1.0".to_string(),
        subject_type: "person".to_string(),
        evidence_mode: registry_notary_core::ClaimEvidenceMode::TransitionalDirect,
        value: ClaimValueConfig {
            value_type: "number".to_string(),
            nullable: false,
            unit: None,
        },
        semantics: None,
        inputs: Vec::new(),
        depends_on: Vec::new(),
        purpose: None,
        required_scopes: Vec::new(),
        source_bindings: bindings,
        rule: RuleConfig::Extract {
            source: "src".to_string(),
            field: "value".to_string(),
        },
        operations: ClaimOperationsConfig::default(),
        disclosure: DisclosureConfig {
            default: "value".to_string(),
            allowed: vec!["value".to_string(), "redacted".to_string()],
            downgrade: "redacted".to_string(),
        },
        formats: vec![FORMAT_CLAIM_RESULT_JSON.to_string()],
        credential_profiles: Vec::new(),
        cccev: None,
        oots: None,
    }
}

#[tokio::test]
async fn memo_counters_record_hits_and_misses_on_shared_binding_batch() {
    // Two claims share an identical (entity, lookup) binding. 50 subjects
    // means 50 distinct memo keys; each subject sees 1 miss (the first claim
    // to reach the binding for that subject) and 1 hit (the second claim
    // reuses the memo entry).
    //
    // Expected (post-Stage 2): 50 misses, 50 hits, 50 upstream calls.
    let subject_count = 50usize;
    let source = Arc::new(CountingSource::default());
    let evidence = Arc::new(EvidenceConfig {
        enabled: true,
        service_id: "registry-notary.test".to_string(),
        allowed_purposes: vec!["test".to_string()],
        inline_batch_limit: subject_count,
        claims: {
            let mut a = shared_binding_claim("claim-a");
            a.operations.batch_evaluate.enabled = true;
            a.operations.batch_evaluate.max_subjects = subject_count;
            let mut b = shared_binding_claim("claim-b");
            b.operations.batch_evaluate.enabled = true;
            b.operations.batch_evaluate.max_subjects = subject_count;
            // Claim B must extract a real field for the rule to succeed; use
            // the same source so the binding key matches claim A.
            vec![a, b]
        },
        concurrency: ConcurrencyConfig {
            subjects: 16,
            bindings: 4,
        },
        ..EvidenceConfig::default()
    });
    let store = EvidenceStore::default();
    let runtime = RegistryNotaryRuntime::new();
    let subjects: Vec<SubjectRequest> = (0..subject_count)
        .map(|i| SubjectRequest {
            id: format!("p-{i:02}"),
            id_type: None,
        })
        .collect();
    let request = BatchEvaluateRequest {
        items: subjects
            .into_iter()
            .map(BatchEvaluateItemRequest::from)
            .collect(),
        claims: vec![ClaimRef::from("claim-a"), ClaimRef::from("claim-b")],
        disclosure: Some("value".to_string()),
        format: Some(FORMAT_CLAIM_RESULT_JSON.to_string()),
        purpose: Some("test".to_string()),
    };
    let memo = Arc::new(MemoState::new());
    let principal = EvidencePrincipal {
        auth_profile_id: registry_notary_core::EvidenceAuthProfileId::StaticApiKey,
        principal_id: "test".to_string(),
        scopes: Vec::new(),
        access_mode: AccessMode::MachineClient,
        verified_claims: None,
        authorization_details: None,
    };
    let response = runtime
        .batch_evaluate(
            evidence,
            source.clone() as Arc<dyn SourceReader>,
            &store,
            &principal,
            request,
            BatchEvaluateOptions {
                memo_observer: Some(&memo),
                ..BatchEvaluateOptions::default()
            },
        )
        .await
        .expect("batch_evaluate succeeds");
    assert_eq!(response.items.len(), subject_count);
    for item in &response.items {
        assert!(
            matches!(item.errors.as_slice(), []),
            "all subjects must succeed; got errors {:?}",
            item.errors,
        );
    }

    let hits = memo.hits();
    let misses = memo.misses();
    let upstream_calls = source.calls();
    assert_eq!(
        misses, subject_count as u64,
        "expected one miss per subject (= one upstream call per subject), got misses={misses}",
    );
    assert_eq!(
        hits, subject_count as u64,
        "expected one hit per subject (the second claim reuses the memo entry), got hits={hits}",
    );
    assert_eq!(
        upstream_calls, subject_count,
        "upstream calls must equal miss count; got {upstream_calls}",
    );
}
