// SPDX-License-Identifier: Apache-2.0
//! End-to-end tests for Stage 3 bulk `read_many` specializations.
//!
//! Each test stands up an axum upstream that records every request it
//! observes (URL, query, body) and asserts on the wire shape and request
//! count for both the RDA `.in`-filter bulk path and the DCI batched
//! `search_request` bulk path.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use axum_test::TestServer;
use registry_notary_core::StandaloneRegistryNotaryConfig;
use registry_notary_server::standalone_router;
use serde_json::{json, Value};
use std::collections::BTreeMap;
use tempfile::TempDir;

const TEST_AUDIT_SECRET: &str = "0123456789abcdef0123456789abcdef";
const TEST_BULK_API_KEY_HASH: &str =
    "sha256:a00cf33cd46d9ef96c1eff33df1c9cca20b1a02468cd78ec6a4b2887d1640b51";

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
// Counted upstream fixtures
// ---------------------------------------------------------------------------

/// One captured upstream HTTP request: a (method, path, query, body) tuple.
///
/// The `body` is `None` for GETs (since axum's `Json<Value>` extractor only
/// fires for requests that carried a body). Used by the `bulk_mode: none`
/// regression guard to assert per-request byte-equivalence with the
/// per-subject `read_one` baseline.
#[derive(Clone, Debug, PartialEq, Eq)]
struct CapturedRequest {
    method: String,
    path: String,
    query: BTreeMap<String, String>,
    body: Option<Value>,
}

#[derive(Clone, Default)]
struct UpstreamRecorder {
    total_requests: Arc<AtomicUsize>,
    last_query: Arc<Mutex<BTreeMap<String, String>>>,
    last_body: Arc<Mutex<Option<Value>>>,
    /// Append-only log of every request the handler observed, in arrival
    /// order. Other tests on this recorder ignore the log.
    requests: Arc<Mutex<Vec<CapturedRequest>>>,
}

impl UpstreamRecorder {
    fn new() -> Self {
        Self::default()
    }
    fn total(&self) -> usize {
        self.total_requests.load(Ordering::SeqCst)
    }
    fn last_query(&self) -> BTreeMap<String, String> {
        self.last_query.lock().unwrap().clone()
    }
    fn last_body(&self) -> Option<Value> {
        self.last_body.lock().unwrap().clone()
    }
    fn record(&self, req: CapturedRequest) {
        self.requests.lock().unwrap().push(req);
    }
    fn snapshot(&self) -> Vec<CapturedRequest> {
        self.requests.lock().unwrap().clone()
    }
}

/// RDA collection endpoint: records the query string and returns one row per
/// id in the `id.in=<csv>` filter, plus `total_farmed_area` projection.
async fn rda_collection_handler(
    State(rec): State<UpstreamRecorder>,
    Query(params): Query<BTreeMap<String, String>>,
) -> Response {
    rec.total_requests.fetch_add(1, Ordering::SeqCst);
    *rec.last_query.lock().unwrap() = params.clone();
    let csv = params.get("id.in").cloned().unwrap_or_default();
    let data: Vec<Value> = csv
        .split(',')
        .filter(|s| !s.is_empty())
        .map(|id| json!({ "id": id, "total_farmed_area": 1.0 }))
        .collect();
    Json(json!({ "data": data })).into_response()
}

/// RDA collection that duplicates one id in the response to trigger the
/// `bulk_collision_fallback` path.
async fn rda_collision_handler(
    State(rec): State<UpstreamRecorder>,
    Query(params): Query<BTreeMap<String, String>>,
) -> Response {
    let attempt = rec.total_requests.fetch_add(1, Ordering::SeqCst) + 1;
    *rec.last_query.lock().unwrap() = params.clone();
    // First call (the bulk attempt) returns N+1 rows so notary must fall
    // back. Subsequent calls (per-subject reads) return one row each.
    if attempt == 1 {
        let csv = params.get("id.in").cloned().unwrap_or_default();
        let ids: Vec<&str> = csv.split(',').filter(|s| !s.is_empty()).collect();
        let mut data: Vec<Value> = ids
            .iter()
            .map(|id| json!({ "id": id, "total_farmed_area": 1.0 }))
            .collect();
        if let Some(first) = ids.first() {
            // Duplicate the first id to force rows > N.
            data.push(json!({ "id": first, "total_farmed_area": 1.0 }));
        }
        return Json(json!({ "data": data })).into_response();
    }
    // Per-subject fallback path: relay's eq filter is `id=<value>` or no
    // filter; we honor either by echoing back the value the notary sent.
    let id = params
        .iter()
        .find(|(k, _)| k.as_str() == "id" || k.as_str() == "id.eq")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    Json(json!({ "data": [{ "id": id, "total_farmed_area": 1.0 }] })).into_response()
}

/// DCI search endpoint: records the POST body and returns one
/// `search_response` entry per `search_request`, echoing each `reference_id`
/// and producing a single `reg_records` row built from the request's lookup
/// value.
async fn dci_batched_handler(
    State(rec): State<UpstreamRecorder>,
    axum::extract::Json(body): axum::extract::Json<Value>,
) -> Response {
    rec.total_requests.fetch_add(1, Ordering::SeqCst);
    *rec.last_body.lock().unwrap() = Some(body.clone());
    let entries = body
        .pointer("/message/search_request")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let response_entries: Vec<Value> = entries
        .iter()
        .map(|e| {
            let rid = e
                .get("reference_id")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string();
            let lookup_value = e
                .pointer("/search_criteria/query/value")
                .cloned()
                .unwrap_or(json!("unknown"));
            json!({
                "reference_id": rid,
                "status": "succ",
                "data": {
                    "reg_records": [{
                        "id_type": "national_id",
                        "id_value": lookup_value,
                        "is_farmer": true,
                    }]
                }
            })
        })
        .collect();
    Json(json!({
        "message": {
            "search_response": response_entries,
        }
    }))
    .into_response()
}

/// source-adapter sidecar batchMatch endpoint: records the POST body and returns one
/// successful item per request item, echoing the query values into the record.
async fn source_adapter_batch_match_handler(
    State(rec): State<UpstreamRecorder>,
    method: axum::http::Method,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
    axum::extract::Json(body): axum::extract::Json<Value>,
) -> Response {
    rec.total_requests.fetch_add(1, Ordering::SeqCst);
    *rec.last_body.lock().unwrap() = Some(body.clone());
    rec.record(CapturedRequest {
        method: method.as_str().to_string(),
        path: uri.path().to_string(),
        query: BTreeMap::new(),
        body: Some(body.clone()),
    });
    let items = body
        .get("items")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let response_items: Vec<Value> = items
        .iter()
        .map(|item| {
            let id = item.get("id").and_then(Value::as_str).unwrap_or_default();
            let values = item
                .get("values")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default();
            if values.len() == 1 {
                let national_id = values.first().cloned().unwrap_or(Value::Null);
                return json!({
                    "id": id,
                    "data": [{
                        "national_id": national_id,
                        "birth_date": "1990-01-01",
                        "unrequested_secret": "must not reach notary",
                    }]
                });
            }
            let given_name = values.first().cloned().unwrap_or(Value::Null);
            let family_name = values.get(1).cloned().unwrap_or(Value::Null);
            let birth_date = values.get(2).cloned().unwrap_or(Value::Null);
            json!({
                "id": id,
                "data": [{
                    "given_name": given_name,
                    "family_name": family_name,
                    "birth_date": birth_date,
                    "unrequested_secret": "must not reach notary",
                }]
            })
        })
        .collect();
    Json(json!({ "items": response_items })).into_response()
}

/// DCI search that DROPS one entry from the response (the first one) so the
/// notary must surface SourceNotFound for that subject only.
async fn dci_partial_handler(
    State(rec): State<UpstreamRecorder>,
    axum::extract::Json(body): axum::extract::Json<Value>,
) -> Response {
    rec.total_requests.fetch_add(1, Ordering::SeqCst);
    *rec.last_body.lock().unwrap() = Some(body.clone());
    let entries = body
        .pointer("/message/search_request")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();
    let response_entries: Vec<Value> = entries
        .iter()
        .skip(1)
        .map(|e| {
            let rid = e
                .get("reference_id")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
                .to_string();
            json!({
                "reference_id": rid,
                "status": "succ",
                "data": {
                    "reg_records": [{
                        "id_type": "national_id",
                        "id_value": "x",
                        "is_farmer": true,
                    }]
                }
            })
        })
        .collect();
    Json(json!({
        "message": { "search_response": response_entries }
    }))
    .into_response()
}

/// Per-subject (non-bulk) RDA handler that counts every call and records the
/// (method, path, query, body) tuple for each request it observes. Path and
/// method are constant for this route, so only the query varies per call.
async fn rda_per_subject_handler(
    State(rec): State<UpstreamRecorder>,
    method: axum::http::Method,
    axum::extract::OriginalUri(uri): axum::extract::OriginalUri,
    Query(params): Query<BTreeMap<String, String>>,
) -> Response {
    rec.total_requests.fetch_add(1, Ordering::SeqCst);
    rec.record(CapturedRequest {
        method: method.as_str().to_string(),
        path: uri.path().to_string(),
        query: params.clone(),
        body: None,
    });
    let id = params
        .iter()
        .find(|(k, _)| k.as_str() == "id" || k.as_str() == "id.eq")
        .map(|(_, v)| v.clone())
        .unwrap_or_default();
    if id.is_empty() {
        return StatusCode::BAD_REQUEST.into_response();
    }
    Json(json!({ "data": [{ "id": id, "total_farmed_area": 1.0 }] })).into_response()
}

// ---------------------------------------------------------------------------
// Config builders
// ---------------------------------------------------------------------------

fn rda_bulk_config(
    base_url: &str,
    audit_path: &str,
    bulk_mode: &str,
) -> StandaloneRegistryNotaryConfig {
    set_audit_secret();
    let api_key_fingerprint = test_api_key_fingerprint_ref_yaml(
        "caseworker",
        "TEST_BULK_API_KEY_HASH",
        TEST_BULK_API_KEY_HASH,
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
  concurrency:
    subjects: 256
    bindings: 32
  source_connections:
    farmer_registry:
      base_url: "{base_url}"
      allow_insecure_localhost: true
      token_env: TEST_BULK_SOURCE_TOKEN
      max_in_flight: 64
      bulk_mode: {bulk_mode}
      bulk_mode_lookup_unique: true
  claims:
    - id: farmed-land-size
      title: Farmed land size
      version: 2026-05
      subject_type: person
      value:
        type: number
        unit: hectare
      operations:
        batch_evaluate:
          enabled: true
          max_subjects: 200
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
    serde_norway::from_str(&raw).expect("rda bulk config deserializes")
}

fn dci_bulk_config(
    base_url: &str,
    audit_path: &str,
    bulk_mode: &str,
) -> StandaloneRegistryNotaryConfig {
    set_audit_secret();
    let api_key_fingerprint = test_api_key_fingerprint_ref_yaml(
        "caseworker",
        "TEST_BULK_API_KEY_HASH",
        TEST_BULK_API_KEY_HASH,
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
  concurrency:
    subjects: 256
    bindings: 32
  source_connections:
    registry_a:
      base_url: "{base_url}"
      allow_insecure_localhost: true
      token_env: TEST_BULK_SOURCE_TOKEN
      max_in_flight: 64
      bulk_mode: {bulk_mode}
      bulk_mode_lookup_unique: true
      dci:
        query_type: idtype-value
        search_path: /registry/sync/search
        records_path: /message/search_response/0/data/reg_records
        bulk_records_path: /data/reg_records
  claims:
    - id: dci-claim
      title: DCI claim
      version: 2026-05
      subject_type: person
      operations:
        batch_evaluate:
          enabled: true
          max_subjects: 200
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
"#
    );
    serde_norway::from_str(&raw).expect("dci bulk config deserializes")
}

fn source_adapter_sidecar_bulk_config(
    base_url: &str,
    audit_path: &str,
) -> StandaloneRegistryNotaryConfig {
    set_audit_secret();
    let api_key_fingerprint = test_api_key_fingerprint_ref_yaml(
        "caseworker",
        "TEST_BULK_API_KEY_HASH",
        TEST_BULK_API_KEY_HASH,
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
      scopes: [civil_registry:evidence_verification]
audit:
  sink: file
  path: "{audit_path}"
  hash_secret_env: REGISTRY_NOTARY_AUDIT_HASH_SECRET
evidence:
  enabled: true
  service_id: evidence.test
  allowed_purposes:
    - https://purpose.example.test/eligibility
  concurrency:
    subjects: 256
    bindings: 32
  source_connections:
    source_adapter_crvs:
      base_url: "{base_url}"
      allow_insecure_localhost: true
      token_env: TEST_BULK_SOURCE_TOKEN
      max_in_flight: 64
      retry_on_5xx: false
      bulk_mode: source_adapter_sidecar_batch
  claims:
    - id: date-of-birth
      title: Date of birth
      version: 2026-05
      subject_type: person
      operations:
        batch_evaluate:
          enabled: true
          max_subjects: 200
      source_bindings:
        crvs:
          connector: source_adapter_sidecar
          connection: source_adapter_crvs
          required_scope: civil_registry:evidence_verification
          dataset: civil_registry
          entity: civil_person
          lookup:
            input: target.id
            field: national_id
            op: eq
            cardinality: one
          query_fields:
            - input: target.attributes.given_name
              field: given_name
              op: eq
            - input: target.attributes.family_name
              field: family_name
              op: eq
            - input: target.attributes.birth_date
              field: birth_date
              op: eq
          fields:
            birth_date:
              field: birth_date
              type: string
              required: true
      rule:
        type: extract
        source: crvs
        field: birth_date
      disclosure:
        default: value
        allowed: [value, redacted]
      formats:
        - application/vnd.registry-notary.claim-result+json
"#
    );
    serde_norway::from_str(&raw).expect("source-adapter sidecar bulk config deserializes")
}

fn source_adapter_sidecar_identifier_bulk_config(
    base_url: &str,
    audit_path: &str,
) -> StandaloneRegistryNotaryConfig {
    set_audit_secret();
    let api_key_fingerprint = test_api_key_fingerprint_ref_yaml(
        "caseworker",
        "TEST_BULK_API_KEY_HASH",
        TEST_BULK_API_KEY_HASH,
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
      scopes: [civil_registry:evidence_verification]
audit:
  sink: file
  path: "{audit_path}"
  hash_secret_env: REGISTRY_NOTARY_AUDIT_HASH_SECRET
evidence:
  enabled: true
  service_id: evidence.test
  allowed_purposes:
    - https://purpose.example.test/eligibility
  concurrency:
    subjects: 256
    bindings: 32
  source_connections:
    source_adapter_crvs:
      base_url: "{base_url}"
      allow_insecure_localhost: true
      token_env: TEST_BULK_SOURCE_TOKEN
      max_in_flight: 64
      retry_on_5xx: false
      bulk_mode: source_adapter_sidecar_batch
  claims:
    - id: date-of-birth
      title: Date of birth
      version: 2026-05
      subject_type: person
      operations:
        batch_evaluate:
          enabled: true
          max_subjects: 200
      source_bindings:
        crvs:
          connector: source_adapter_sidecar
          connection: source_adapter_crvs
          required_scope: civil_registry:evidence_verification
          dataset: civil_registry
          entity: civil_person
          lookup:
            input: target.id
            field: national_id
            op: eq
            cardinality: one
          fields:
            birth_date:
              field: birth_date
              type: string
              required: true
      rule:
        type: extract
        source: crvs
        field: birth_date
      disclosure:
        default: value
        allowed: [value, redacted]
      formats:
        - application/vnd.registry-notary.claim-result+json
"#
    );
    serde_norway::from_str(&raw).expect("source-adapter sidecar identifier config deserializes")
}

fn source_adapter_sidecar_relationship_bulk_config(
    base_url: &str,
    audit_path: &str,
) -> StandaloneRegistryNotaryConfig {
    set_audit_secret();
    let api_key_fingerprint = test_api_key_fingerprint_ref_yaml(
        "caseworker",
        "TEST_BULK_API_KEY_HASH",
        TEST_BULK_API_KEY_HASH,
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
      scopes: [civil_registry:evidence_verification]
audit:
  sink: file
  path: "{audit_path}"
  hash_secret_env: REGISTRY_NOTARY_AUDIT_HASH_SECRET
evidence:
  enabled: true
  service_id: evidence.test
  allowed_purposes:
    - https://purpose.example.test/eligibility
  concurrency:
    subjects: 256
    bindings: 32
  source_connections:
    source_adapter_crvs:
      base_url: "{base_url}"
      allow_insecure_localhost: true
      token_env: TEST_BULK_SOURCE_TOKEN
      max_in_flight: 64
      retry_on_5xx: false
      bulk_mode: source_adapter_sidecar_batch
  claims:
    - id: date-of-birth
      title: Date of birth
      version: 2026-05
      subject_type: person
      operations:
        batch_evaluate:
          enabled: true
          max_subjects: 200
      source_bindings:
        crvs:
          connector: source_adapter_sidecar
          connection: source_adapter_crvs
          required_scope: civil_registry:evidence_verification
          dataset: civil_registry
          entity: civil_person
          lookup:
            input: target.id
            field: national_id
            op: eq
            cardinality: one
          query_fields:
            - input: relationship.attributes.case_id
              field: case_id
              op: eq
          fields:
            birth_date:
              field: birth_date
              type: string
              required: true
      rule:
        type: extract
        source: crvs
        field: birth_date
      disclosure:
        default: value
        allowed: [value, redacted]
      formats:
        - application/vnd.registry-notary.claim-result+json
"#
    );
    serde_norway::from_str(&raw).expect("source-adapter sidecar relationship config deserializes")
}

fn source_adapter_sidecar_requester_bulk_config(
    base_url: &str,
    audit_path: &str,
) -> StandaloneRegistryNotaryConfig {
    set_audit_secret();
    let api_key_fingerprint = test_api_key_fingerprint_ref_yaml(
        "caseworker",
        "TEST_BULK_API_KEY_HASH",
        TEST_BULK_API_KEY_HASH,
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
      scopes: [civil_registry:evidence_verification]
audit:
  sink: file
  path: "{audit_path}"
  hash_secret_env: REGISTRY_NOTARY_AUDIT_HASH_SECRET
evidence:
  enabled: true
  service_id: evidence.test
  allowed_purposes:
    - https://purpose.example.test/eligibility
  concurrency:
    subjects: 256
    bindings: 32
  source_connections:
    source_adapter_crvs:
      base_url: "{base_url}"
      allow_insecure_localhost: true
      token_env: TEST_BULK_SOURCE_TOKEN
      max_in_flight: 64
      retry_on_5xx: false
      bulk_mode: source_adapter_sidecar_batch
  claims:
    - id: date-of-birth
      title: Date of birth
      version: 2026-05
      subject_type: person
      operations:
        batch_evaluate:
          enabled: true
          max_subjects: 200
      source_bindings:
        crvs:
          connector: source_adapter_sidecar
          connection: source_adapter_crvs
          required_scope: civil_registry:evidence_verification
          dataset: civil_registry
          entity: civil_person
          lookup:
            input: target.id
            field: national_id
            op: eq
            cardinality: one
          query_fields:
            - input: requester.identifiers.worker_id
              field: worker_id
              op: eq
          fields:
            birth_date:
              field: birth_date
              type: string
              required: true
      rule:
        type: extract
        source: crvs
        field: birth_date
      disclosure:
        default: value
        allowed: [value, redacted]
      formats:
        - application/vnd.registry-notary.claim-result+json
"#
    );
    serde_norway::from_str(&raw).expect("source-adapter sidecar requester config deserializes")
}

// ---------------------------------------------------------------------------
// Test scaffolding
// ---------------------------------------------------------------------------

fn setup_env() {
    std::env::set_var("TEST_BULK_API_KEY_HASH", TEST_BULK_API_KEY_HASH);
    std::env::set_var("TEST_BULK_SOURCE_TOKEN", "source-token");
}

fn build_subjects(n: usize) -> Vec<Value> {
    (0..n)
        .map(|i| person_target(&format!("person-{i:03}")))
        .collect()
}

fn person_target_with_attributes(
    id: &str,
    given_name: &str,
    family_name: &str,
    birth_date: &str,
) -> Value {
    json!({
        "type": "Person",
        "id": id,
        "attributes": {
            "given_name": given_name,
            "family_name": family_name,
            "birth_date": birth_date,
        }
    })
}

// ---------------------------------------------------------------------------
// RDA bulk specialization
// ---------------------------------------------------------------------------

#[tokio::test]
async fn rda_bulk_collapses_100_subjects_into_one_in_filter_request() {
    setup_env();
    let recorder = UpstreamRecorder::new();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route(
                "/v1/datasets/farmer_registry/entities/farmer/records",
                get(rda_collection_handler),
            )
            .with_state(recorder.clone()),
    );
    let base_url = upstream.server_address().expect("upstream address");
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");

    let app = standalone_router(rda_bulk_config(
        base_url.to_string().trim_end_matches('/'),
        audit_path.to_str().expect("utf-8 path"),
        "rda_in_filter",
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let subjects = build_subjects(100);
    let body = json!({
        "claims": ["farmed-land-size"],
        "items": subjects.iter().map(|subject| json!({ "target": subject })).collect::<Vec<_>>(),
        "disclosure": "value",
    });
    let response = server
        .post("/v1/batch-evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&body)
        .await;
    response.assert_status_ok();

    // Exactly one upstream request for the 100-subject batch.
    assert_eq!(
        recorder.total(),
        1,
        "expected exactly one bulk upstream call, observed {}",
        recorder.total(),
    );

    // The query must use the `id.in=<csv>` filter shape and include all 100
    // lookup values.
    let q = recorder.last_query();
    let in_csv = q.get("id.in").cloned().expect("query has id.in filter");
    let ids: Vec<&str> = in_csv.split(',').collect();
    assert_eq!(
        ids.len(),
        100,
        "expected 100 lookup values in id.in, got {}",
        ids.len(),
    );
    assert!(ids.contains(&"person-000"));
    assert!(ids.contains(&"person-099"));
}

#[tokio::test]
async fn rda_bulk_falls_back_to_per_subject_on_collision() {
    setup_env();
    let recorder = UpstreamRecorder::new();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route(
                "/v1/datasets/farmer_registry/entities/farmer/records",
                get(rda_collision_handler),
            )
            .with_state(recorder.clone()),
    );
    let base_url = upstream.server_address().expect("upstream address");
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");

    let app = standalone_router(rda_bulk_config(
        base_url.to_string().trim_end_matches('/'),
        audit_path.to_str().expect("utf-8 path"),
        "rda_in_filter",
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let subjects = build_subjects(4);
    let body = json!({
        "claims": ["farmed-land-size"],
        "items": subjects.iter().map(|subject| json!({ "target": subject })).collect::<Vec<_>>(),
        "disclosure": "value",
    });
    let response = server
        .post("/v1/batch-evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&body)
        .await;
    response.assert_status_ok();

    // 1 bulk attempt that observed a collision, then 4 per-subject reads.
    assert_eq!(
        recorder.total(),
        5,
        "expected 1 bulk + 4 per-subject = 5 total upstream calls, got {}",
        recorder.total(),
    );
}

// ---------------------------------------------------------------------------
// source-adapter sidecar batchMatch specialization
// ---------------------------------------------------------------------------

#[tokio::test]
async fn source_adapter_sidecar_batch_by_identifier_posts_one_batch_match_request() {
    setup_env();
    let recorder = UpstreamRecorder::new();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route(
                "/v1/datasets/civil_registry/entities/civil_person/records:batchMatch",
                post(source_adapter_batch_match_handler),
            )
            .with_state(recorder.clone()),
    );
    let base_url = upstream.server_address().expect("upstream address");
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");

    let app = standalone_router(source_adapter_sidecar_identifier_bulk_config(
        base_url.to_string().trim_end_matches('/'),
        audit_path.to_str().expect("utf-8 path"),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let subjects = build_subjects(3);
    let body = json!({
        "claims": ["date-of-birth"],
        "items": subjects.iter().map(|subject| json!({ "target": subject })).collect::<Vec<_>>(),
        "disclosure": "value",
    });
    let response = server
        .post("/v1/batch-evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&body)
        .await;
    response.assert_status_ok();

    assert_eq!(
        recorder.total(),
        1,
        "expected exactly one source-adapter identifier batchMatch POST, got {}",
        recorder.total(),
    );
    let requests = recorder.snapshot();
    assert_eq!(requests.len(), 1, "one upstream request is captured");
    assert_eq!(requests[0].method, "POST");
    assert_eq!(
        requests[0].path,
        "/v1/datasets/civil_registry/entities/civil_person/records:batchMatch"
    );

    let last_body = recorder.last_body().expect("body recorded");
    assert_eq!(last_body["fields"], json!(["birth_date", "national_id"]));
    assert_eq!(
        last_body["query_signature"],
        json!([{ "field": "national_id", "op": "eq" }])
    );
    assert_eq!(
        last_body["items"],
        json!([
            { "id": "0", "values": ["person-000"] },
            { "id": "1", "values": ["person-001"] },
            { "id": "2", "values": ["person-002"] }
        ])
    );
    assert!(last_body.get("target").is_none());
    assert!(last_body.get("requester").is_none());
    assert!(last_body.get("relationship").is_none());
    assert!(last_body.get("claims").is_none());
    assert!(last_body.get("disclosure").is_none());

    let response_body: Value = response.json();
    let items = response_body["items"].as_array().expect("items array");
    assert_eq!(items.len(), 3);
    for (idx, item) in items.iter().enumerate() {
        assert_eq!(item["status"], "succeeded", "item {idx} should succeed");
        // The batch claim result carries the frozen v1 provenance shape on the
        // wire, with computed_by gone.
        let provenance = &item["claim_results"][0]["provenance"];
        assert_eq!(
            provenance["schema_version"],
            json!("registry-notary-claim-provenance/v1"),
            "item {idx} provenance must be v1"
        );
        assert_eq!(
            provenance["generated_by"]["type"],
            json!("claim_evaluation")
        );
        assert!(provenance["used"]["source_count"].is_number());
        assert!(
            !provenance.to_string().contains("computed_by"),
            "computed_by must not appear in batch provenance"
        );
    }
}

#[tokio::test]
async fn source_adapter_sidecar_batch_groups_query_fields_into_one_batch_match_post() {
    setup_env();
    let recorder = UpstreamRecorder::new();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route(
                "/v1/datasets/civil_registry/entities/civil_person/records:batchMatch",
                post(source_adapter_batch_match_handler),
            )
            .with_state(recorder.clone()),
    );
    let base_url = upstream.server_address().expect("upstream address");
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");

    let app = standalone_router(source_adapter_sidecar_bulk_config(
        base_url.to_string().trim_end_matches('/'),
        audit_path.to_str().expect("utf-8 path"),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let subjects = [
        person_target_with_attributes("person-001", "Amina", "Diallo", "1990-01-01"),
        person_target_with_attributes("person-002", "Bao", "Tran", "1988-02-03"),
        person_target_with_attributes("person-003", "Carla", "Ndiaye", "1992-04-05"),
    ];
    let body = json!({
        "claims": ["date-of-birth"],
        "items": subjects.iter().map(|subject| json!({ "target": subject })).collect::<Vec<_>>(),
        "disclosure": "value",
    });
    let response = server
        .post("/v1/batch-evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&body)
        .await;
    response.assert_status_ok();

    assert_eq!(
        recorder.total(),
        1,
        "expected exactly one source-adapter sidecar batchMatch POST, got {}",
        recorder.total(),
    );
    let requests = recorder.snapshot();
    assert_eq!(requests.len(), 1, "one upstream request is captured");
    assert_eq!(requests[0].method, "POST");
    assert_eq!(
        requests[0].path,
        "/v1/datasets/civil_registry/entities/civil_person/records:batchMatch"
    );

    let last_body = recorder.last_body().expect("body recorded");
    assert_eq!(
        last_body["query_signature"],
        json!([
            { "field": "given_name", "op": "eq" },
            { "field": "family_name", "op": "eq" },
            { "field": "birth_date", "op": "eq" }
        ])
    );
    assert_eq!(
        last_body["items"],
        json!([
            { "id": "0", "values": ["Amina", "Diallo", "1990-01-01"] },
            { "id": "1", "values": ["Bao", "Tran", "1988-02-03"] },
            { "id": "2", "values": ["Carla", "Ndiaye", "1992-04-05"] }
        ])
    );
    assert!(last_body.get("target").is_none());
    assert!(last_body.get("requester").is_none());
    assert!(last_body.get("relationship").is_none());
    assert!(last_body.get("assurance").is_none());

    let response_body: Value = response.json();
    let items = response_body["items"].as_array().expect("items array");
    assert_eq!(items.len(), 3);
    for (idx, item) in items.iter().enumerate() {
        assert_eq!(item["status"], "succeeded", "item {idx} should succeed");
    }
    assert!(
        !response_body.to_string().contains("unrequested_secret"),
        "source-adapter sidecar response must be projected before Notary uses it"
    );
}

#[tokio::test]
async fn source_adapter_sidecar_batch_supports_relationship_derived_query_fields() {
    setup_env();
    let recorder = UpstreamRecorder::new();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route(
                "/v1/datasets/civil_registry/entities/civil_person/records:batchMatch",
                post(source_adapter_batch_match_handler),
            )
            .with_state(recorder.clone()),
    );
    let base_url = upstream.server_address().expect("upstream address");
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");

    let app = standalone_router(source_adapter_sidecar_relationship_bulk_config(
        base_url.to_string().trim_end_matches('/'),
        audit_path.to_str().expect("utf-8 path"),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let subjects = build_subjects(2);
    let body = json!({
        "claims": ["date-of-birth"],
        "items": subjects.iter().enumerate().map(|(idx, subject)| {
            json!({
                "target": subject,
                "relationship": {
                    "type": "case_worker",
                    "attributes": {
                        "case_id": format!("case-{idx:03}"),
                        "internal_note": "must-not-reach-sidecar"
                    }
                }
            })
        }).collect::<Vec<_>>(),
        "disclosure": "value",
    });
    let response = server
        .post("/v1/batch-evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&body)
        .await;
    response.assert_status_ok();

    assert_eq!(
        recorder.total(),
        1,
        "relationship query fields should still use one source-adapter sidecar batchMatch POST"
    );
    let last_body = recorder.last_body().expect("body recorded");
    assert_eq!(
        last_body["query_signature"],
        json!([{ "field": "case_id", "op": "eq" }])
    );
    assert_eq!(
        last_body["items"],
        json!([
            { "id": "0", "values": ["case-000"] },
            { "id": "1", "values": ["case-001"] }
        ])
    );
    assert!(last_body.get("relationship").is_none());
    assert!(
        !last_body.to_string().contains("internal_note"),
        "only configured query values should leave Notary"
    );
}

#[tokio::test]
async fn source_adapter_sidecar_batch_supports_requester_derived_query_fields() {
    setup_env();
    let recorder = UpstreamRecorder::new();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route(
                "/v1/datasets/civil_registry/entities/civil_person/records:batchMatch",
                post(source_adapter_batch_match_handler),
            )
            .with_state(recorder.clone()),
    );
    let base_url = upstream.server_address().expect("upstream address");
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");

    let app = standalone_router(source_adapter_sidecar_requester_bulk_config(
        base_url.to_string().trim_end_matches('/'),
        audit_path.to_str().expect("utf-8 path"),
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let subjects = build_subjects(2);
    let body = json!({
        "claims": ["date-of-birth"],
        "items": subjects.iter().enumerate().map(|(idx, subject)| {
            json!({
                "target": subject,
                "requester": {
                    "type": "Person",
                    "identifiers": [{
                        "scheme": "worker_id",
                        "value": format!("worker-{idx:03}")
                    }],
                    "attributes": {
                        "office": "district-7",
                        "private_note": "must-not-reach-sidecar"
                    }
                }
            })
        }).collect::<Vec<_>>(),
        "disclosure": "value",
    });
    let response = server
        .post("/v1/batch-evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&body)
        .await;
    response.assert_status_ok();

    assert_eq!(
        recorder.total(),
        1,
        "requester query fields should still use one source-adapter sidecar batchMatch POST"
    );
    let last_body = recorder.last_body().expect("body recorded");
    assert_eq!(
        last_body["query_signature"],
        json!([{ "field": "worker_id", "op": "eq" }])
    );
    assert_eq!(
        last_body["items"],
        json!([
            { "id": "0", "values": ["worker-000"] },
            { "id": "1", "values": ["worker-001"] }
        ])
    );
    assert!(last_body.get("requester").is_none());
    assert!(
        !last_body.to_string().contains("private_note"),
        "only configured requester query values should leave Notary"
    );
}

// ---------------------------------------------------------------------------
// DCI bulk specialization
// ---------------------------------------------------------------------------

#[tokio::test]
async fn dci_bulk_collapses_100_subjects_into_one_search_post() {
    setup_env();
    let recorder = UpstreamRecorder::new();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/registry/sync/search", post(dci_batched_handler))
            .with_state(recorder.clone()),
    );
    let base_url = upstream.server_address().expect("upstream address");
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");

    let app = standalone_router(dci_bulk_config(
        base_url.to_string().trim_end_matches('/'),
        audit_path.to_str().expect("utf-8 path"),
        "dci_batched_search",
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let subjects = build_subjects(100);
    let body = json!({
        "claims": ["dci-claim"],
        "items": subjects.iter().map(|subject| json!({ "target": subject })).collect::<Vec<_>>(),
        "disclosure": "value",
    });
    let response = server
        .post("/v1/batch-evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&body)
        .await;
    response.assert_status_ok();

    assert_eq!(
        recorder.total(),
        1,
        "expected exactly one bulk DCI POST, got {}",
        recorder.total(),
    );

    let last_body = recorder.last_body().expect("body recorded");
    let entries = last_body
        .pointer("/message/search_request")
        .and_then(Value::as_array)
        .expect("search_request is an array");
    assert_eq!(
        entries.len(),
        100,
        "expected 100 search_request entries, got {}",
        entries.len(),
    );
    // Each entry has a unique reference_id and a pagination.page_size >= 100.
    let page_size = entries[0]
        .pointer("/search_criteria/pagination/page_size")
        .and_then(Value::as_u64)
        .expect("page_size present");
    let page_number = entries[0]
        .pointer("/search_criteria/pagination/page_number")
        .and_then(Value::as_u64)
        .expect("page_number present");
    assert!(
        page_size >= 100,
        "page_size {page_size} should be >= batch size",
    );
    assert_eq!(page_number, 1);
    let mut ref_ids: Vec<&str> = entries
        .iter()
        .map(|e| {
            e.get("reference_id")
                .and_then(Value::as_str)
                .expect("reference_id is a string")
        })
        .collect();
    ref_ids.sort();
    ref_ids.dedup();
    assert_eq!(ref_ids.len(), 100, "reference_ids must be unique per entry",);
}

#[tokio::test]
async fn dci_bulk_missing_response_entry_surfaces_source_not_found_for_that_subject() {
    setup_env();
    let recorder = UpstreamRecorder::new();
    let upstream = TestServer::builder().http_transport().build(
        Router::new()
            .route("/registry/sync/search", post(dci_partial_handler))
            .with_state(recorder.clone()),
    );
    let base_url = upstream.server_address().expect("upstream address");
    let tmp = TempDir::new().expect("tempdir");
    let audit_path = tmp.path().join("audit.jsonl");

    let app = standalone_router(dci_bulk_config(
        base_url.to_string().trim_end_matches('/'),
        audit_path.to_str().expect("utf-8 path"),
        "dci_batched_search",
    ))
    .expect("standalone router builds");
    let server = TestServer::builder().http_transport().build(app);

    let subjects = build_subjects(3);
    let body = json!({
        "claims": ["dci-claim"],
        "items": subjects.iter().map(|subject| json!({ "target": subject })).collect::<Vec<_>>(),
        "disclosure": "value",
    });
    let response = server
        .post("/v1/batch-evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&body)
        .await;
    response.assert_status_ok();
    // 1 bulk POST + 1 per-subject retry for subject 0 (errors are NOT memoized
    // by the bulk prefetch, so the missing reference_id retries through the
    // regular per-subject `read_one` path; subjects 1 and 2 are cache hits).
    assert_eq!(
        recorder.total(),
        2,
        "expected 1 bulk + 1 per-subject retry, got {}",
        recorder.total(),
    );

    // The response body should contain 3 items in input order: subject 0
    // is failed with target.not_found, 1 and 2 succeed.
    let body: Value = response.json();
    let items = body["items"].as_array().expect("items array");
    assert_eq!(items.len(), 3, "expected 3 batch items");
    let item0 = &items[0];
    assert_eq!(
        item0["status"], "failed",
        "subject 0 must be failed; got item={item0:?}",
    );
    let codes: Vec<String> = item0["errors"]
        .as_array()
        .cloned()
        .unwrap_or_default()
        .iter()
        .filter_map(|e| e["code"].as_str().map(|s| s.to_string()))
        .collect();
    // The bulk path surfaces `target.not_found` for the missing reference_id.
    // The per-subject retry then hits the same partial handler (which still
    // drops index 0 of a 1-entry request, producing an empty search_response)
    // and re-runs through the per-subject parser; depending on which retry
    // wins last, either `target.not_found` or `source.unavailable` is fine
    // since both correctly signal "subject 0 has no record".
    assert!(
        codes
            .iter()
            .any(|c| c == "target.not_found" || c == "source.unavailable"),
        "subject 0 expected target.not_found or source.unavailable; got {codes:?}",
    );
    // Subjects 1 and 2 must succeed.
    for (idx, item) in items.iter().enumerate().take(3).skip(1) {
        assert_eq!(
            item["status"], "succeeded",
            "subject {idx} must be succeeded; got {item:?}",
        );
    }
}

// ---------------------------------------------------------------------------
// bulk_mode: none preserves the per-subject sequence (regression guard)
// ---------------------------------------------------------------------------

#[tokio::test]
async fn bulk_mode_none_falls_back_to_per_subject_reads() {
    setup_env();

    // --- Pass A: batch-evaluate with bulk_mode=none ------------------------
    let recorder_a = UpstreamRecorder::new();
    let upstream_a = TestServer::builder().http_transport().build(
        Router::new()
            .route(
                "/v1/datasets/farmer_registry/entities/farmer/records",
                get(rda_per_subject_handler),
            )
            .with_state(recorder_a.clone()),
    );
    let base_url_a = upstream_a.server_address().expect("upstream address");
    let tmp_a = TempDir::new().expect("tempdir");
    let audit_path_a = tmp_a.path().join("audit.jsonl");

    // bulk_mode: none on the connection means the runtime must dispatch one
    // upstream read per subject.
    let app_a = standalone_router(rda_bulk_config(
        base_url_a.to_string().trim_end_matches('/'),
        audit_path_a.to_str().expect("utf-8 path"),
        "none",
    ))
    .expect("standalone router builds");
    let server_a = TestServer::builder().http_transport().build(app_a);

    let subjects = build_subjects(8);
    let response_a = server_a
        .post("/v1/batch-evaluations")
        .add_header("x-api-key", "api-token")
        .add_header("data-purpose", "https://purpose.example.test/eligibility")
        .json(&json!({
            "claims": ["farmed-land-size"],
            "items": subjects.iter().map(|subject| json!({ "target": subject })).collect::<Vec<_>>(),
            "disclosure": "value",
        }))
        .await;
    response_a.assert_status_ok();

    assert_eq!(
        recorder_a.total(),
        8,
        "bulk_mode=none must produce one upstream call per subject; got {}",
        recorder_a.total(),
    );

    // --- Pass B: per-subject /v1/evaluations baseline ---------------------
    // Run /v1/evaluations (single-subject) for each subject in turn. The
    // per-subject `read_one` code path is what bulk_mode=none must mirror
    // byte-for-byte at the wire level.
    let recorder_b = UpstreamRecorder::new();
    let upstream_b = TestServer::builder().http_transport().build(
        Router::new()
            .route(
                "/v1/datasets/farmer_registry/entities/farmer/records",
                get(rda_per_subject_handler),
            )
            .with_state(recorder_b.clone()),
    );
    let base_url_b = upstream_b.server_address().expect("upstream address");
    let tmp_b = TempDir::new().expect("tempdir");
    let audit_path_b = tmp_b.path().join("audit.jsonl");
    let app_b = standalone_router(rda_bulk_config(
        base_url_b.to_string().trim_end_matches('/'),
        audit_path_b.to_str().expect("utf-8 path"),
        "none",
    ))
    .expect("standalone router builds");
    let server_b = TestServer::builder().http_transport().build(app_b);
    for subject in &subjects {
        let r = server_b
            .post("/v1/evaluations")
            .add_header("x-api-key", "api-token")
            .add_header("data-purpose", "https://purpose.example.test/eligibility")
            .json(&json!({
                "target": subject,
                "claims": ["farmed-land-size"],
                "disclosure": "value",
            }))
            .await;
        r.assert_status_ok();
    }
    assert_eq!(
        recorder_b.total(),
        8,
        "per-subject baseline must produce one call per subject; got {}",
        recorder_b.total(),
    );

    // --- Compare wire shapes -----------------------------------------------
    // Concurrent dispatch in Pass A means arrival order is non-deterministic.
    // Sort both sequences by the lookup `id` query parameter, then assert
    // tuple-by-tuple equality.
    let sort_key = |req: &CapturedRequest| -> String {
        req.query
            .iter()
            .find(|(k, _)| k.as_str() == "id" || k.as_str() == "id.eq")
            .map(|(_, v)| v.clone())
            .unwrap_or_default()
    };
    let mut a = recorder_a.snapshot();
    let mut b = recorder_b.snapshot();
    a.sort_by_key(sort_key);
    b.sort_by_key(sort_key);
    assert_eq!(
        a, b,
        "bulk_mode=none must emit byte-equivalent wire requests to the per-subject baseline; \
         drift here indicates a regression in the bulk_mode=none fallback path",
    );
}
