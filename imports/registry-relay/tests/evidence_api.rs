// SPDX-License-Identifier: Apache-2.0
//! Focused Evidence Server v0 route tests.

use std::env;
use std::sync::{Arc, OnceLock};

use axum::http::StatusCode;
use axum::middleware::from_fn;
use axum::Extension;
use axum_test::TestServer;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use datafusion::arrow::array::{Float64Array, StringArray};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::datasource::MemTable;
use datafusion::execution::context::SessionContext;
use ed25519_dalek::{SigningKey, SECRET_KEY_LENGTH};
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{crypto, decode, Algorithm, DecodingKey, EncodingKey, Validation};
use rand_core::OsRng;
use registry_relay::api::evidence_router;
use registry_relay::audit::{audit_layer, AuditSettings, AuditSink, InMemorySink};
use registry_relay::auth::{AuthMode, Principal};
use registry_relay::config::{self, DatasetId, ResourceId};
use registry_relay::entity::EntityRegistry;
use registry_relay::evidence::EvidenceStore;
use registry_relay::ingest::table_name;
use registry_relay::query::EntityQueryEngine;
use serde_json::{json, Value};
use tempfile::TempDir;
use time::OffsetDateTime;
use ulid::Ulid;

fn id<T: serde::de::DeserializeOwned>(value: &str) -> T {
    serde_json::from_str(&format!(r#""{value}""#)).expect("id deserializes")
}

fn principal() -> Principal {
    Principal {
        principal_id: "benefits-caseworker".to_string(),
        scopes: [
            "civil_registry:evidence_verification",
            "farmer_registry:evidence_verification",
        ]
        .into_iter()
        .collect(),
        auth_mode: AuthMode::ApiKey,
    }
}

fn export_jwk(env_name: &'static str) {
    static EXPORTED: OnceLock<()> = OnceLock::new();
    EXPORTED.get_or_init(|| {
        let jwk = test_issuer_jwk();
        env::set_var(
            env_name,
            serde_json::to_string(&jwk).expect("test issuer jwk serializes"),
        );
    });
}

fn test_issuer_jwk() -> Value {
    let sk = SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key();
    let d_bytes: [u8; SECRET_KEY_LENGTH] = sk.to_bytes();
    json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "d": URL_SAFE_NO_PAD.encode(d_bytes),
        "x": URL_SAFE_NO_PAD.encode(vk.to_bytes()),
        "alg": "EdDSA",
    })
}

fn holder_did_and_proof(
    evaluation_id: &str,
    credential_profile: &str,
    disclosure: &str,
    claims: &[&str],
) -> (String, String) {
    holder_did_and_proof_with_options(evaluation_id, credential_profile, disclosure, claims, false)
}

fn holder_did_and_proof_with_options(
    evaluation_id: &str,
    credential_profile: &str,
    disclosure: &str,
    claims: &[&str],
    include_private_key_in_did: bool,
) -> (String, String) {
    let sk = SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key();
    let d_bytes: [u8; SECRET_KEY_LENGTH] = sk.to_bytes();
    let mut public_jwk = json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "x": URL_SAFE_NO_PAD.encode(vk.to_bytes()),
        "alg": "EdDSA",
    });
    if include_private_key_in_did {
        public_jwk["d"] = json!(URL_SAFE_NO_PAD.encode(d_bytes));
    }
    let holder_id = format!(
        "did:jwk:{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&public_jwk).unwrap())
    );
    let now = OffsetDateTime::now_utc();
    let header = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "alg": "EdDSA",
            "typ": "JWT",
            "kid": holder_id,
        }))
        .unwrap(),
    );
    let payload = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "sub": holder_id.clone(),
            "aud": "evidence-server",
            "exp": (now + time::Duration::minutes(5)).unix_timestamp(),
            "iat": now.unix_timestamp(),
            "jti": Ulid::new().to_string(),
            "evaluation_id": evaluation_id,
            "credential_profile": credential_profile,
            "disclosure": disclosure,
            "claims": claims,
        }))
        .unwrap(),
    );
    let signing_input = format!("{header}.{payload}");
    let signature = crypto::sign(
        signing_input.as_bytes(),
        &EncodingKey::from_ed_der(&ed25519_pkcs8_seed(&d_bytes)),
        Algorithm::EdDSA,
    )
    .unwrap();
    (holder_id, format!("{signing_input}.{signature}"))
}

fn ed25519_pkcs8_seed(seed: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(48);
    out.extend_from_slice(&[
        0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04,
        0x20,
    ]);
    out.extend_from_slice(seed);
    out
}

fn write_config(tmp: &TempDir) -> std::path::PathBuf {
    let path = tmp.path().join("evidence_server.yaml");
    std::fs::write(
        &path,
        r#"
server:
  bind: 127.0.0.1:0

catalog:
  title: Test
  base_url: https://data.example.test
  publisher: Test

vocabularies: {}

auth:
  mode: api_key
  api_keys: []

evidence:
  enabled: true
  service_id: evidence.test
  inline_batch_limit: 10
  credential_profiles:
    farmer_status_sd_jwt:
      format: application/dc+sd-jwt
      issuer: did:web:farmer.example.test
      issuer_key_env: EVIDENCE_SERVER_TEST_JWK
      issuer_kid: did:web:farmer.example.test#key-1
      vct: https://farmer.example.test/credentials/farmer-status/v1
      validity_seconds: 3600
      allowed_claims: [farmer-under-4ha]
      holder_binding:
        mode: did
        proof_of_possession: required
        allowed_did_methods: [did:jwk]
      disclosure:
        allowed: [predicate]
    farmer_status_redacted_sd_jwt:
      format: application/dc+sd-jwt
      issuer: did:web:farmer.example.test
      issuer_key_env: EVIDENCE_SERVER_TEST_JWK
      issuer_kid: did:web:farmer.example.test#key-1
      vct: https://farmer.example.test/credentials/farmer-status/v1
      validity_seconds: 3600
      allowed_claims: [farmer-under-4ha]
      holder_binding:
        mode: none
      disclosure:
        allowed: [redacted]
  claims:
    - id: date-of-birth
      title: Date of birth
      version: 2026-05
      subject_type: person
      value:
        type: string
      source_bindings:
        crvs:
          connector: dci
          connection: crvs
          dataset: civil_registry
          entity: person
          lookup:
            input: subject_id
            field: PERSON_ID
            op: eq
            cardinality: one
          fields:
            date_of_birth:
              field: date_of_birth
              type: string
      rule:
        type: extract
        source: crvs
        field: date_of_birth
      disclosure:
        default: value
        allowed: [value, redacted]
      formats:
        - application/vnd.evidence-server.claim-result+json
        - application/ld+json; profile="cccev"
    - id: farmed-land-size
      title: Farmed land size
      version: 2026-05
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
            op: eq
            cardinality: one
          fields:
            total_farmed_area:
              field: total_farmed_area
              type: number
              unit: hectare
      rule:
        type: extract
        source: farmer
        field: total_farmed_area
      disclosure:
        default: value
        allowed: [value, redacted]
      formats:
        - application/vnd.evidence-server.claim-result+json
    - id: farmer-under-4ha
      title: Farmer under four hectares
      version: 2026-05
      subject_type: person
      value:
        type: boolean
      depends_on: [farmed-land-size]
      rule:
        type: cel
        expression: "claims.farmed_land_size.value < 4"
        bindings:
          claims:
            farmed_land_size:
              claim: farmed-land-size
      operations:
        evaluate:
          enabled: true
        batch_evaluate:
          enabled: true
          max_subjects: 10
      disclosure:
        default: predicate
        allowed: [predicate, value]
      formats:
        - application/vnd.evidence-server.claim-result+json
        - application/ld+json; profile="cccev"
        - application/dc+sd-jwt
      credential_profiles:
        - farmer_status_sd_jwt
      oots:
        enabled: true
        requirement: https://example.test/requirements/farmer-status
        reference_framework: https://example.test/frameworks/agriculture
        evidence_type_classification: https://example.test/evidence-types/farmer-status
        evidence_type_list: https://example.test/evidence-type-lists/agriculture
        languages: [en]
        authentication_level_of_assurance: substantial
    - id: farmer-regex-test
      title: Farmer regex test
      version: 2026-05
      subject_type: person
      value:
        type: boolean
      depends_on: [farmed-land-size]
      rule:
        type: cel
        expression: "claims.farmed_land_size.value.matches('.*')"
        bindings:
          claims:
            farmed_land_size:
              claim: farmed-land-size
      formats:
        - application/vnd.evidence-server.claim-result+json
    - id: farmer-text-regex-test
      title: Farmer text regex test
      version: 2026-05
      subject_type: person
      value:
        type: boolean
      depends_on: [farmed-land-size]
      rule:
        type: cel
        expression: "text_matches(string(claims.farmed_land_size.value), '.*')"
        bindings:
          claims:
            farmed_land_size:
              claim: farmed-land-size
      formats:
        - application/vnd.evidence-server.claim-result+json
    - id: farmer-record-exists
      title: Farmer record exists
      version: 2026-05
      subject_type: person
      value:
        type: boolean
      source_bindings:
        farmer:
          connector: registry_data_api
          dataset: farmer_registry
          entity: farmer
          lookup:
            input: subject_id
            field: id
      rule:
        type: exists
        source: farmer
      disclosure:
        default: predicate
        allowed: [predicate, redacted]
      formats:
        - application/vnd.evidence-server.claim-result+json
    - id: farmer-under-variable-limit
      title: Farmer under variable limit
      version: 2026-05
      subject_type: person
      value:
        type: boolean
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
      rule:
        type: cel
        expression: "source.farmer.total_farmed_area < vars.limit && ctx.subject.id == 'person-1'"
        bindings:
          vars:
            limit: 4
      disclosure:
        default: predicate
        allowed: [predicate]
      formats:
        - application/vnd.evidence-server.claim-result+json
    - id: farmer-meta-service
      title: Farmer meta service check
      version: 2026-05
      subject_type: person
      value:
        type: boolean
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
      rule:
        type: cel
        expression: "meta.service_id == 'evidence.test' && meta.claim.id == 'farmer-meta-service' && meta.sources.farmer.dataset == 'farmer_registry'"
      disclosure:
        default: predicate
        allowed: [predicate]
      formats:
        - application/vnd.evidence-server.claim-result+json
    - id: farmer-unknown-source-field
      title: Farmer unknown source field
      version: 2026-05
      subject_type: person
      value:
        type: boolean
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
      rule:
        type: cel
        expression: "source.farmer.missing_field == 1"
      disclosure:
        default: predicate
        allowed: [predicate]
      formats:
        - application/vnd.evidence-server.claim-result+json

standards:
  spdci:
    registries:
      crvs:
        dataset: civil_registry
        entity: person
        registry_type: ns:org:RegistryType:CRVS
        record_type: spdci-extensions-crvs:Person
        identifiers:
          PERSON_ID: id
        expression_fields:
          birth_date: date_of_birth

datasets:
  - id: civil_registry
    title: Civil Registry
    description: CRVS fixture
    owner: Civil Authority
    sensitivity: personal
    access_rights: restricted
    update_frequency: daily
    defaults:
      refresh:
        mode: manual
    tables:
      - id: people_table
        source:
          type: file
          path: fixtures/crvs.csv
        primary_key: id
        schema:
          strict: true
          fields:
            - name: id
              type: string
              nullable: false
            - name: date_of_birth
              type: string
              nullable: false
    entities:
      - name: person
        table: people_table
        fields:
          - name: id
          - name: date_of_birth
        access:
          metadata_scope: crvs:metadata
          aggregate_scope: crvs:aggregate
          read_scope: crvs:rows
          evidence_verification_scope: civil_registry:evidence_verification
        api:
          default_limit: 100
          max_limit: 1000
          allowed_filters:
            - field: id
              ops: [eq, in]
            - field: date_of_birth
              ops: [eq]
  - id: farmer_registry
    title: Farmer Registry
    description: Farmer fixture
    owner: Agriculture
    sensitivity: personal
    access_rights: restricted
    update_frequency: daily
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
          metadata_scope: farmer:metadata
          aggregate_scope: farmer:aggregate
          read_scope: farmer:rows
          evidence_verification_scope: farmer_registry:evidence_verification
        api:
          default_limit: 100
          max_limit: 1000
          allowed_filters:
            - field: id
              ops: [eq, in]

audit:
  sink: stdout
  format: jsonl
"#,
    )
    .expect("write config");
    path
}

fn server() -> TestServer {
    server_with_principal(principal())
}

fn server_with_principal(principal: Principal) -> TestServer {
    build_server(principal, None).0
}

fn server_without_principal() -> TestServer {
    build_server_with_farmer_rows_maybe(None, None, vec![("person-1", 3.5), ("person-2", 6.0)]).0
}

fn server_with_audit() -> (TestServer, InMemorySink) {
    let sink = InMemorySink::new();
    build_server(principal(), Some(sink))
}

fn build_server(
    principal: Principal,
    audit_sink: Option<InMemorySink>,
) -> (TestServer, InMemorySink) {
    build_server_with_farmer_rows(
        principal,
        audit_sink,
        vec![("person-1", 3.5), ("person-2", 6.0)],
    )
}

fn server_with_farmer_rows(rows: Vec<(&'static str, f64)>) -> TestServer {
    build_server_with_farmer_rows(principal(), None, rows).0
}

fn build_server_with_farmer_rows(
    principal: Principal,
    audit_sink: Option<InMemorySink>,
    farmer_rows: Vec<(&'static str, f64)>,
) -> (TestServer, InMemorySink) {
    build_server_with_farmer_rows_maybe(Some(principal), audit_sink, farmer_rows)
}

fn build_server_with_farmer_rows_maybe(
    principal: Option<Principal>,
    audit_sink: Option<InMemorySink>,
    farmer_rows: Vec<(&'static str, f64)>,
) -> (TestServer, InMemorySink) {
    let audit_enabled = audit_sink.is_some();
    export_jwk("EVIDENCE_SERVER_TEST_JWK");
    let tmp = TempDir::new().expect("tempdir");
    let cfg = config::load(&write_config(&tmp)).expect("config loads");
    let registry = Arc::new(EntityRegistry::from_config(&cfg).expect("registry"));
    let ctx = Arc::new(SessionContext::new());
    let dataset: DatasetId = id("civil_registry");
    let resource: ResourceId = id("people_table");
    let crvs_schema = Arc::new(Schema::new(vec![
        Field::new("id", DataType::Utf8, false),
        Field::new("date_of_birth", DataType::Utf8, false),
    ]));
    let crvs_batch = RecordBatch::try_new(
        Arc::clone(&crvs_schema),
        vec![
            Arc::new(StringArray::from(vec!["person-1", "person-2"])),
            Arc::new(StringArray::from(vec!["1980-01-01", "2000-02-02"])),
        ],
    )
    .expect("crvs batch");
    let crvs = MemTable::try_new(crvs_schema, vec![vec![crvs_batch]]).expect("crvs table");
    ctx.register_table(table_name(&dataset, &resource), Arc::new(crvs))
        .expect("register crvs");

    let dataset: DatasetId = id("farmer_registry");
    let resource: ResourceId = id("farmers_table");
    let farmer_schema = Arc::new(Schema::new(vec![
        Field::new("id", DataType::Utf8, false),
        Field::new("total_farmed_area", DataType::Float64, false),
    ]));
    let farmer_batch = RecordBatch::try_new(
        Arc::clone(&farmer_schema),
        vec![
            Arc::new(StringArray::from(
                farmer_rows.iter().map(|(id, _)| *id).collect::<Vec<_>>(),
            )),
            Arc::new(Float64Array::from(
                farmer_rows
                    .iter()
                    .map(|(_, area)| *area)
                    .collect::<Vec<_>>(),
            )),
        ],
    )
    .expect("farmer batch");
    let farmers = MemTable::try_new(farmer_schema, vec![vec![farmer_batch]]).expect("farmer table");
    ctx.register_table(table_name(&dataset, &resource), Arc::new(farmers))
        .expect("register farmers");

    let query = Arc::new(EntityQueryEngine::new(ctx, Arc::clone(&registry)));
    let sink = audit_sink.unwrap_or_default();
    let mut router = evidence_router::<()>()
        .layer(Extension(Arc::new(EvidenceStore::default())))
        .layer(Extension(query))
        .layer(Extension(registry))
        .layer(Extension(Arc::new(cfg)));
    if audit_enabled {
        let sink_arc: Arc<dyn AuditSink> = Arc::new(sink.clone());
        router = router
            .layer(from_fn(audit_layer))
            .layer(Extension(AuditSettings::default()))
            .layer(Extension(sink_arc));
    }
    if let Some(principal) = principal {
        router = router.layer(Extension(principal));
    }
    (TestServer::new(router), sink)
}

fn audit_record_for(sink: &InMemorySink, path: &str) -> Value {
    let lines = sink.snapshot();
    let line = lines
        .iter()
        .rev()
        .find(|line| {
            serde_json::from_str::<Value>(line)
                .ok()
                .and_then(|record| record["path"].as_str().map(|candidate| candidate == path))
                .unwrap_or(false)
        })
        .unwrap_or_else(|| panic!("no audit record for {path}; got {lines:?}"));
    serde_json::from_str(line).expect("audit line is JSON")
}

fn assert_no_audit_leaks(record: &Value, forbidden: &[&str]) {
    let line = record.to_string();
    for value in forbidden {
        assert!(
            !line.contains(value),
            "audit record leaked forbidden value {value:?}: {line}"
        );
    }
}

#[tokio::test]
async fn discovery_lists_claims_and_formats() {
    let server = server();
    let resp = server.get("/.well-known/evidence-service").await;
    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(body["operations"]["evaluate"], true);
    assert_eq!(body["operations"]["credential_issue"], true);
    assert_eq!(body["identity"]["mapper"], "common_subject_id");
    assert_eq!(body["identity"]["production_mapper"], false);

    let resp = server.get("/claims").await;
    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(body["data"].as_array().unwrap().len(), 9);
    let farmer_claim = body["data"]
        .as_array()
        .unwrap()
        .iter()
        .find(|claim| claim["id"] == "farmer-under-4ha")
        .expect("farmer claim listed");
    assert_eq!(
        farmer_claim["oots"]["requirement"],
        "https://example.test/requirements/farmer-status"
    );
    assert!(body["operations"].get("oots_wire_exchange").is_none());

    let resp = server.get("/formats").await;
    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert!(body["data"]
        .as_array()
        .unwrap()
        .iter()
        .any(|format| format["format"] == "application/dc+sd-jwt"));
}

#[tokio::test]
async fn discovery_requires_authentication() {
    let server = server_without_principal();

    for path in ["/.well-known/evidence-service", "/claims", "/formats"] {
        let resp = server.get(path).await;
        resp.assert_status(StatusCode::UNAUTHORIZED);
        let body: Value = resp.json();
        assert_eq!(body["code"], "auth.missing_credential");
    }
}

#[tokio::test]
async fn discovery_filters_claims_by_caller_authorization() {
    let mut limited = principal();
    limited.scopes = ["civil_registry:evidence_verification"]
        .into_iter()
        .collect();
    let server = server_with_principal(limited);

    let resp = server.get("/claims").await;
    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    let claims = body["data"].as_array().unwrap();
    assert_eq!(claims.len(), 1);
    assert_eq!(claims[0]["id"], "date-of-birth");

    let hidden = server.get("/claims/farmer-under-4ha").await;
    hidden.assert_status(StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn evaluate_emits_useful_redacted_audit_record() {
    let (server, sink) = server_with_audit();
    let resp = server
        .post("/claims/evaluate")
        .add_header("data-purpose", "https://purpose.example.test/subsidy")
        .json(&json!({
            "subject": {"id": "person-1"},
            "claims": ["farmer-under-4ha"],
            "disclosure": "predicate"
        }))
        .await;
    resp.assert_status(StatusCode::OK);

    let record = audit_record_for(&sink, "/claims/evaluate");
    assert_eq!(record["endpoint_kind"], "evidence_verification");
    assert_eq!(record["principal_id"], "benefits-caseworker");
    assert_eq!(record["auth_mode"], "api_key");
    assert_eq!(record["purpose"], "https://purpose.example.test/subsidy");
    assert_eq!(record["verification_decision"], "evaluate");
    assert!(record["verification_id"].as_str().unwrap().len() > 10);
    assert!(record["claim_hash"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    assert_eq!(record["row_count"], 1);
    assert_no_audit_leaks(
        &record,
        &[
            "person-1",
            "1980-01-01",
            "3.5",
            "total_farmed_area",
            "EVIDENCE_SERVER_TEST_JWK",
        ],
    );
}

#[tokio::test]
async fn issuer_jwks_publishes_public_key_only() {
    let server = server();
    let resp = server.get("/.well-known/evidence/jwks.json").await;
    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    let key = &body["keys"][0];
    assert_eq!(key["kid"], "did:web:farmer.example.test#key-1");
    assert_eq!(key["alg"], "EdDSA");
    assert_eq!(key["kty"], "OKP");
    assert!(key.get("d").is_none());
}

#[tokio::test]
async fn evaluate_computes_cel_claim_from_registry_data() {
    let server = server();
    let resp = server
        .post("/claims/evaluate")
        .add_header("data-purpose", "https://purpose.example.test/subsidy")
        .json(&json!({
            "subject": {"id": "person-1"},
            "claims": ["farmer-under-4ha"],
            "disclosure": "predicate"
        }))
        .await;
    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    let result = &body["results"][0];
    assert_eq!(result["claim_id"], "farmer-under-4ha");
    assert_eq!(result["satisfied"], true);
    assert_eq!(result["value"], true);
    assert!(result["subject_ref"]
        .as_str()
        .unwrap()
        .starts_with("urn:subject:sha256:"));
}

#[tokio::test]
async fn evaluate_computes_exists_and_cel_source_ctx_vars_claims() {
    let server = server();
    let exists = server
        .post("/claims/evaluate")
        .add_header("data-purpose", "https://purpose.example.test/subsidy")
        .json(&json!({
            "subject": {"id": "person-1"},
            "claims": ["farmer-record-exists"],
            "disclosure": "predicate"
        }))
        .await;
    exists.assert_status(StatusCode::OK);
    let body: Value = exists.json();
    assert_eq!(body["results"][0]["satisfied"], true);

    let cel = server
        .post("/claims/evaluate")
        .add_header("data-purpose", "https://purpose.example.test/subsidy")
        .json(&json!({
            "subject": {"id": "person-1"},
            "claims": ["farmer-under-variable-limit"],
            "disclosure": "predicate"
        }))
        .await;
    cel.assert_status(StatusCode::OK);
    let body: Value = cel.json();
    assert_eq!(body["results"][0]["satisfied"], true);

    let meta = server
        .post("/claims/evaluate")
        .add_header("data-purpose", "https://purpose.example.test/subsidy")
        .json(&json!({
            "subject": {"id": "person-1"},
            "claims": ["farmer-meta-service"],
            "disclosure": "predicate"
        }))
        .await;
    meta.assert_status(StatusCode::OK);
    let body: Value = meta.json();
    assert_eq!(body["results"][0]["satisfied"], true);
}

#[tokio::test]
async fn evaluate_reads_date_of_birth_through_dci_crvs_binding() {
    let server = server();
    let resp = server
        .post("/claims/evaluate")
        .add_header("data-purpose", "https://purpose.example.test/identity")
        .json(&json!({
            "subject": {"id": "person-1", "id_type": "common_subject_id"},
            "claims": ["date-of-birth"],
            "disclosure": "value"
        }))
        .await;
    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    let result = &body["results"][0];
    assert_eq!(result["claim_id"], "date-of-birth");
    assert_eq!(result["value"], "1980-01-01");
}

#[tokio::test]
async fn evaluate_enforces_source_evidence_scope() {
    let mut limited = principal();
    limited.scopes = ["civil_registry:evidence_verification"]
        .into_iter()
        .collect();
    let server = server_with_principal(limited);
    let resp = server
        .post("/claims/evaluate")
        .add_header("data-purpose", "https://purpose.example.test/subsidy")
        .json(&json!({
            "subject": {"id": "person-1"},
            "claims": ["farmer-under-4ha"],
            "disclosure": "predicate",
            "format": "application/ld+json; profile=\"cccev\""
        }))
        .await;
    resp.assert_status(StatusCode::FORBIDDEN);
    let body: Value = resp.json();
    assert_eq!(body["code"], "auth.scope_denied");
}

#[tokio::test]
async fn evaluate_rejects_minimal_alias_blank_purpose_and_unsupported_format() {
    let server = server();
    let minimal = server
        .post("/claims/evaluate")
        .add_header("data-purpose", "https://purpose.example.test/subsidy")
        .json(&json!({
            "subject": {"id": "person-1"},
            "claims": ["farmer-under-4ha"],
            "disclosure": "minimal"
        }))
        .await;
    minimal.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = minimal.json();
    assert_eq!(body["code"], "request.invalid");

    let blank_purpose = server
        .post("/claims/evaluate")
        .add_header("data-purpose", "   ")
        .json(&json!({
            "subject": {"id": "person-1"},
            "claims": ["farmer-under-4ha"],
            "disclosure": "predicate"
        }))
        .await;
    blank_purpose.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = blank_purpose.json();
    assert_eq!(body["code"], "request.invalid");

    let unsupported_format = server
        .post("/claims/evaluate")
        .add_header("data-purpose", "https://purpose.example.test/subsidy")
        .json(&json!({
            "subject": {"id": "person-1"},
            "claims": ["farmed-land-size"],
            "disclosure": "value",
            "format": "application/ld+json; profile=\"cccev\""
        }))
        .await;
    unsupported_format.assert_status(StatusCode::NOT_IMPLEMENTED);
    let body: Value = unsupported_format.json();
    assert_eq!(body["code"], "format.unsupported");
}

#[tokio::test]
async fn evaluate_rejects_unknown_claim_and_disallowed_cel_regex() {
    let server = server();
    let unknown = server
        .post("/claims/evaluate")
        .add_header("data-purpose", "https://purpose.example.test/subsidy")
        .json(&json!({
            "subject": {"id": "person-1"},
            "claims": ["missing-claim"],
            "disclosure": "predicate"
        }))
        .await;
    unknown.assert_status(StatusCode::NOT_FOUND);
    let body: Value = unknown.json();
    assert_eq!(body["code"], "claim.not_found");

    let regex = server
        .post("/claims/evaluate")
        .add_header("data-purpose", "https://purpose.example.test/subsidy")
        .json(&json!({
            "subject": {"id": "person-1"},
            "claims": ["farmer-regex-test"],
            "disclosure": "predicate"
        }))
        .await;
    regex.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = regex.json();
    assert_eq!(body["code"], "request.invalid");

    let text_regex = server
        .post("/claims/evaluate")
        .add_header("data-purpose", "https://purpose.example.test/subsidy")
        .json(&json!({
            "subject": {"id": "person-1"},
            "claims": ["farmer-text-regex-test"],
            "disclosure": "predicate"
        }))
        .await;
    text_regex.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = text_regex.json();
    assert_eq!(body["code"], "request.invalid");

    let undeclared_field = server
        .post("/claims/evaluate")
        .add_header("data-purpose", "https://purpose.example.test/subsidy")
        .json(&json!({
            "subject": {"id": "person-1"},
            "claims": ["farmer-unknown-source-field"],
            "disclosure": "predicate"
        }))
        .await;
    undeclared_field.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = undeclared_field.json();
    assert_eq!(body["code"], "request.invalid");
}

#[tokio::test]
async fn evaluate_reports_source_ambiguity() {
    let server = server_with_farmer_rows(vec![("person-1", 3.5), ("person-1", 2.5)]);
    let resp = server
        .post("/claims/evaluate")
        .add_header("data-purpose", "https://purpose.example.test/subsidy")
        .json(&json!({
            "subject": {"id": "person-1"},
            "claims": ["farmed-land-size"],
            "disclosure": "value"
        }))
        .await;
    resp.assert_status(StatusCode::CONFLICT);
    let body: Value = resp.json();
    assert_eq!(body["code"], "source.ambiguous");
}

#[tokio::test]
async fn batch_returns_per_subject_partial_failure() {
    let server = server();
    let resp = server
        .post("/claims/batch-evaluate")
        .add_header("data-purpose", "https://purpose.example.test/subsidy")
        .json(&json!({
            "subjects": [{"id": "person-1"}, {"id": "missing"}],
            "claims": ["farmer-under-4ha"],
            "disclosure": "predicate"
        }))
        .await;
    resp.assert_status(StatusCode::OK);
    let body: Value = resp.json();
    assert_eq!(body["items"][0]["status"], "ok");
    assert!(body["items"][0]["results"][0]["evaluation_id"]
        .as_str()
        .is_some_and(|value| value.len() == 26));
    assert_eq!(body["items"][1]["status"], "error");
    assert_eq!(body["items"][1]["code"], "source.not_found");
}

#[tokio::test]
async fn batch_rejects_too_large_and_unsupported_operation() {
    let server = server();
    let too_large_subjects = (0..11)
        .map(|i| json!({ "id": format!("person-{i}") }))
        .collect::<Vec<_>>();
    let too_large = server
        .post("/claims/batch-evaluate")
        .add_header("data-purpose", "https://purpose.example.test/subsidy")
        .json(&json!({
            "subjects": too_large_subjects,
            "claims": ["farmer-under-4ha"],
            "disclosure": "predicate"
        }))
        .await;
    too_large.assert_status(StatusCode::PAYLOAD_TOO_LARGE);
    let body: Value = too_large.json();
    assert_eq!(body["code"], "batch.too_large");

    let unsupported = server
        .post("/claims/batch-evaluate")
        .add_header("data-purpose", "https://purpose.example.test/subsidy")
        .json(&json!({
            "subjects": [{"id": "person-1"}],
            "claims": ["date-of-birth"],
            "disclosure": "value"
        }))
        .await;
    unsupported.assert_status(StatusCode::NOT_IMPLEMENTED);
    let body: Value = unsupported.json();
    assert_eq!(body["code"], "claim.operation_unsupported");
}

#[tokio::test]
async fn batch_evaluate_emits_redacted_partial_failure_audit_record() {
    let (server, sink) = server_with_audit();
    let resp = server
        .post("/claims/batch-evaluate")
        .add_header("data-purpose", "https://purpose.example.test/subsidy")
        .json(&json!({
            "subjects": [{"id": "person-1"}, {"id": "missing"}],
            "claims": ["farmer-under-4ha"],
            "disclosure": "predicate"
        }))
        .await;
    resp.assert_status(StatusCode::OK);

    let record = audit_record_for(&sink, "/claims/batch-evaluate");
    assert_eq!(record["endpoint_kind"], "evidence_verification");
    assert_eq!(record["verification_decision"], "batch_evaluate");
    assert_eq!(record["row_count"], 2);
    assert!(record["claim_hash"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    assert_no_audit_leaks(&record, &["person-1", "missing", "3.5", "6.0"]);
}

#[tokio::test]
async fn batch_idempotency_replays_same_request_and_rejects_conflict() {
    let server = server();
    let request = json!({
        "subjects": [{"id": "person-1"}, {"id": "missing"}],
        "claims": ["farmer-under-4ha"],
        "disclosure": "predicate"
    });
    let first = server
        .post("/claims/batch-evaluate")
        .add_header("data-purpose", "https://purpose.example.test/subsidy")
        .add_header("idempotency-key", "same-key")
        .json(&request)
        .await;
    first.assert_status(StatusCode::OK);
    let first_body: Value = first.json();

    let replay = server
        .post("/claims/batch-evaluate")
        .add_header("data-purpose", "https://purpose.example.test/subsidy")
        .add_header("idempotency-key", "same-key")
        .json(&request)
        .await;
    replay.assert_status(StatusCode::OK);
    let replay_body: Value = replay.json();
    assert_eq!(replay_body, first_body);

    let conflict = server
        .post("/claims/batch-evaluate")
        .add_header("data-purpose", "https://purpose.example.test/subsidy")
        .add_header("idempotency-key", "same-key")
        .json(&json!({
            "subjects": [{"id": "person-2"}],
            "claims": ["farmer-under-4ha"],
            "disclosure": "predicate"
        }))
        .await;
    conflict.assert_status(StatusCode::CONFLICT);
    let body: Value = conflict.json();
    assert_eq!(body["code"], "idempotency.conflict");
}

#[tokio::test]
async fn render_is_bound_to_original_disclosure() {
    let server = server();
    let eval = server
        .post("/claims/evaluate")
        .add_header("data-purpose", "https://purpose.example.test/subsidy")
        .json(&json!({
            "subject": {"id": "person-1"},
            "claims": ["farmer-under-4ha"],
            "disclosure": "predicate",
            "format": "application/ld+json; profile=\"cccev\""
        }))
        .await;
    eval.assert_status(StatusCode::OK);
    let body: Value = eval.json();
    let evaluation_id = body["results"][0]["evaluation_id"].as_str().unwrap();

    let render = server
        .post("/evidence/render")
        .json(&json!({
            "evaluation_id": evaluation_id,
            "format": "application/ld+json; profile=\"cccev\"",
            "disclosure": "predicate"
        }))
        .await;
    render.assert_status(StatusCode::OK);
    let body: Value = render.json();
    assert!(body["@graph"].is_array());

    let widened = server
        .post("/evidence/render")
        .json(&json!({
            "evaluation_id": evaluation_id,
            "format": "application/vnd.evidence-server.claim-result+json",
            "disclosure": "value"
        }))
        .await;
    widened.assert_status(StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn render_failure_emits_audit_context() {
    let (server, sink) = server_with_audit();
    let eval = server
        .post("/claims/evaluate")
        .add_header("data-purpose", "https://purpose.example.test/subsidy")
        .json(&json!({
            "subject": {"id": "person-1"},
            "claims": ["farmer-under-4ha"],
            "disclosure": "predicate"
        }))
        .await;
    eval.assert_status(StatusCode::OK);
    let body: Value = eval.json();
    let evaluation_id = body["results"][0]["evaluation_id"].as_str().unwrap();

    let widened = server
        .post("/evidence/render")
        .json(&json!({
            "evaluation_id": evaluation_id,
            "format": "application/vnd.evidence-server.claim-result+json",
            "disclosure": "value"
        }))
        .await;
    widened.assert_status(StatusCode::FORBIDDEN);

    let record = audit_record_for(&sink, "/evidence/render");
    assert_eq!(record["endpoint_kind"], "evidence_verification");
    assert_eq!(record["verification_decision"], "render_failed");
    assert_eq!(record["verification_id"], evaluation_id);
    assert_eq!(record["error_code"], "evaluation.binding_mismatch");
    assert_no_audit_leaks(&record, &["person-1", "3.5"]);
}

#[tokio::test]
async fn render_returns_canonical_json_for_scalar_and_boolean_claims() {
    let server = server();
    let scalar_eval = server
        .post("/claims/evaluate")
        .add_header("data-purpose", "https://purpose.example.test/identity")
        .json(&json!({
            "subject": {"id": "person-1"},
            "claims": ["date-of-birth"],
            "disclosure": "value"
        }))
        .await;
    scalar_eval.assert_status(StatusCode::OK);
    let body: Value = scalar_eval.json();
    let scalar_evaluation_id = body["results"][0]["evaluation_id"].as_str().unwrap();
    let scalar_render = server
        .post("/evidence/render")
        .json(&json!({
            "evaluation_id": scalar_evaluation_id,
            "format": "application/vnd.evidence-server.claim-result+json",
            "disclosure": "value"
        }))
        .await;
    scalar_render.assert_status(StatusCode::OK);
    let body: Value = scalar_render.json();
    assert_eq!(body["results"][0]["value"], "1980-01-01");

    let boolean_eval = server
        .post("/claims/evaluate")
        .add_header("data-purpose", "https://purpose.example.test/subsidy")
        .json(&json!({
            "subject": {"id": "person-1"},
            "claims": ["farmer-under-4ha"],
            "disclosure": "predicate"
        }))
        .await;
    boolean_eval.assert_status(StatusCode::OK);
    let body: Value = boolean_eval.json();
    let boolean_evaluation_id = body["results"][0]["evaluation_id"].as_str().unwrap();
    let boolean_render = server
        .post("/evidence/render")
        .json(&json!({
            "evaluation_id": boolean_evaluation_id,
            "format": "application/vnd.evidence-server.claim-result+json",
            "disclosure": "predicate"
        }))
        .await;
    boolean_render.assert_status(StatusCode::OK);
    let body: Value = boolean_render.json();
    assert_eq!(body["results"][0]["satisfied"], true);
}

#[tokio::test]
async fn credential_issue_signs_sd_jwt_from_existing_evaluation() {
    let server = server();
    let eval = server
        .post("/claims/evaluate")
        .add_header("data-purpose", "https://purpose.example.test/subsidy")
        .json(&json!({
            "subject": {"id": "person-1"},
            "claims": ["farmer-under-4ha"],
            "disclosure": "predicate"
        }))
        .await;
    eval.assert_status(StatusCode::OK);
    let body: Value = eval.json();
    let evaluation_id = body["results"][0]["evaluation_id"].as_str().unwrap();
    let (holder_id, holder_proof) = holder_did_and_proof(
        evaluation_id,
        "farmer_status_sd_jwt",
        "predicate",
        &["farmer-under-4ha"],
    );

    let issued = server
        .post("/credentials/issue")
        .json(&json!({
            "evaluation_id": evaluation_id,
            "credential_profile": "farmer_status_sd_jwt",
            "format": "application/dc+sd-jwt",
            "disclosure": "predicate",
            "holder": {
                "binding": "did",
                "id": holder_id.clone(),
                "proof": holder_proof.clone()
            }
        }))
        .await;
    issued.assert_status(StatusCode::OK);
    let body: Value = issued.json();
    assert_eq!(body["format"], "application/dc+sd-jwt");
    let credential = body["credential"].as_str().unwrap();
    assert!(credential.contains('~'));
    assert!(credential.ends_with('~'));
    assert_eq!(credential.split('~').next_back(), Some(""));
    let jwt = credential.split('~').next().unwrap();
    let parts = jwt.split('.').collect::<Vec<_>>();
    assert_eq!(parts.len(), 3);
    let header: Value = serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).unwrap()).unwrap();
    let payload: Value =
        serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).unwrap()).unwrap();
    assert_eq!(header["typ"], "dc+sd-jwt");
    assert_eq!(
        payload["vct"],
        "https://farmer.example.test/credentials/farmer-status/v1"
    );
    assert_eq!(payload["_sd_alg"], "sha-256");
    assert!(payload["_sd"].as_array().unwrap().len() == 1);
    assert_eq!(payload["cnf"]["kid"], holder_id);
    assert!(!payload.to_string().contains(evaluation_id));

    let jwks = server.get("/.well-known/evidence/jwks.json").await;
    jwks.assert_status(StatusCode::OK);
    let jwks: Value = jwks.json();
    let jwk: Jwk = serde_json::from_value(jwks["keys"][0].clone()).expect("issuer jwk parses");
    let decoding_key = DecodingKey::from_jwk(&jwk).expect("decoding key from issuer jwk");
    let mut validation = Validation::new(Algorithm::EdDSA);
    validation.set_issuer(&["did:web:farmer.example.test"]);
    validation.validate_aud = false;
    decode::<Value>(jwt, &decoding_key, &validation).expect("issued SD-JWT verifies");
}

#[tokio::test]
async fn credential_issue_emits_redacted_audit_record() {
    let (server, sink) = server_with_audit();
    let eval = server
        .post("/claims/evaluate")
        .add_header("data-purpose", "https://purpose.example.test/subsidy")
        .json(&json!({
            "subject": {"id": "person-1"},
            "claims": ["farmer-under-4ha"],
            "disclosure": "predicate"
        }))
        .await;
    eval.assert_status(StatusCode::OK);
    let body: Value = eval.json();
    let evaluation_id = body["results"][0]["evaluation_id"].as_str().unwrap();
    let (holder_id, holder_proof) = holder_did_and_proof(
        evaluation_id,
        "farmer_status_sd_jwt",
        "predicate",
        &["farmer-under-4ha"],
    );

    let issued = server
        .post("/credentials/issue")
        .json(&json!({
            "evaluation_id": evaluation_id,
            "credential_profile": "farmer_status_sd_jwt",
            "format": "application/dc+sd-jwt",
            "disclosure": "predicate",
            "holder": {
                "binding": "did",
                "id": holder_id.clone(),
                "proof": holder_proof
            }
        }))
        .await;
    issued.assert_status(StatusCode::OK);
    let issued_body: Value = issued.json();
    let credential = issued_body["credential"].as_str().unwrap();

    let record = audit_record_for(&sink, "/credentials/issue");
    assert_eq!(record["endpoint_kind"], "evidence_verification");
    assert_eq!(record["verification_decision"], "credential_issued");
    assert_eq!(record["verification_id"], evaluation_id);
    assert!(record["claim_hash"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    assert_no_audit_leaks(
        &record,
        &[
            credential,
            holder_proof.as_str(),
            holder_id.as_str(),
            "person-1",
            "3.5",
        ],
    );
}

#[tokio::test]
async fn credential_issue_rejects_replayed_holder_proof() {
    let server = server();
    let eval = server
        .post("/claims/evaluate")
        .add_header("data-purpose", "https://purpose.example.test/subsidy")
        .json(&json!({
            "subject": {"id": "person-1"},
            "claims": ["farmer-under-4ha"],
            "disclosure": "predicate"
        }))
        .await;
    eval.assert_status(StatusCode::OK);
    let body: Value = eval.json();
    let evaluation_id = body["results"][0]["evaluation_id"].as_str().unwrap();
    let (holder_id, holder_proof) = holder_did_and_proof(
        evaluation_id,
        "farmer_status_sd_jwt",
        "predicate",
        &["farmer-under-4ha"],
    );
    let issue_body = json!({
        "evaluation_id": evaluation_id,
        "credential_profile": "farmer_status_sd_jwt",
        "format": "application/dc+sd-jwt",
        "disclosure": "predicate",
        "holder": {
            "binding": "did",
            "id": holder_id,
            "proof": holder_proof
        }
    });

    let first = server.post("/credentials/issue").json(&issue_body).await;
    first.assert_status(StatusCode::OK);

    let replay = server.post("/credentials/issue").json(&issue_body).await;
    replay.assert_status(StatusCode::CONFLICT);
    let body: Value = replay.json();
    assert_eq!(body["code"], "credential.holder_proof_replay");
}

#[tokio::test]
async fn credential_issue_enforces_profile_disclosure_policy() {
    let server = server();
    let eval = server
        .post("/claims/evaluate")
        .add_header("data-purpose", "https://purpose.example.test/subsidy")
        .json(&json!({
            "subject": {"id": "person-1"},
            "claims": ["farmer-under-4ha"],
            "disclosure": "predicate"
        }))
        .await;
    eval.assert_status(StatusCode::OK);
    let body: Value = eval.json();
    let evaluation_id = body["results"][0]["evaluation_id"].as_str().unwrap();

    let issued = server
        .post("/credentials/issue")
        .json(&json!({
            "evaluation_id": evaluation_id,
            "credential_profile": "farmer_status_redacted_sd_jwt",
            "format": "application/dc+sd-jwt",
            "disclosure": "predicate"
        }))
        .await;
    issued.assert_status(StatusCode::FORBIDDEN);
    let body: Value = issued.json();
    assert_eq!(body["code"], "claim.disclosure_not_allowed");
}

#[tokio::test]
async fn credential_issue_returns_issuer_not_configured_for_claim_without_profile() {
    let server = server();
    let eval = server
        .post("/claims/evaluate")
        .add_header("data-purpose", "https://purpose.example.test/identity")
        .json(&json!({
            "subject": {"id": "person-1"},
            "claims": ["date-of-birth"],
            "disclosure": "value"
        }))
        .await;
    eval.assert_status(StatusCode::OK);
    let body: Value = eval.json();
    let evaluation_id = body["results"][0]["evaluation_id"].as_str().unwrap();

    let issued = server
        .post("/credentials/issue")
        .json(&json!({
            "evaluation_id": evaluation_id,
            "format": "application/dc+sd-jwt",
            "disclosure": "value"
        }))
        .await;
    issued.assert_status(StatusCode::NOT_IMPLEMENTED);
    let body: Value = issued.json();
    assert_eq!(body["code"], "credential.issuer_not_configured");
}

#[tokio::test]
async fn credential_issue_rejects_format_and_claim_binding_mismatch() {
    let server = server();
    let eval = server
        .post("/claims/evaluate")
        .add_header("data-purpose", "https://purpose.example.test/subsidy")
        .json(&json!({
            "subject": {"id": "person-1"},
            "claims": ["farmer-under-4ha"],
            "disclosure": "predicate"
        }))
        .await;
    eval.assert_status(StatusCode::OK);
    let body: Value = eval.json();
    let evaluation_id = body["results"][0]["evaluation_id"].as_str().unwrap();

    let wrong_format = server
        .post("/credentials/issue")
        .json(&json!({
            "evaluation_id": evaluation_id,
            "credential_profile": "farmer_status_sd_jwt",
            "format": "application/vnd.evidence-server.claim-result+json",
            "disclosure": "predicate"
        }))
        .await;
    wrong_format.assert_status(StatusCode::NOT_IMPLEMENTED);
    let body: Value = wrong_format.json();
    assert_eq!(body["code"], "format.unsupported");

    let wrong_claims = server
        .post("/credentials/issue")
        .json(&json!({
            "evaluation_id": evaluation_id,
            "credential_profile": "farmer_status_sd_jwt",
            "format": "application/dc+sd-jwt",
            "claims": ["farmed-land-size"],
            "disclosure": "predicate"
        }))
        .await;
    wrong_claims.assert_status(StatusCode::FORBIDDEN);
    let body: Value = wrong_claims.json();
    assert_eq!(body["code"], "evaluation.binding_mismatch");
}

#[tokio::test]
async fn credential_issue_rejects_unsigned_holder_proof() {
    let server = server();
    let eval = server
        .post("/claims/evaluate")
        .add_header("data-purpose", "https://purpose.example.test/subsidy")
        .json(&json!({
            "subject": {"id": "person-1"},
            "claims": ["farmer-under-4ha"],
            "disclosure": "predicate"
        }))
        .await;
    eval.assert_status(StatusCode::OK);
    let body: Value = eval.json();
    let evaluation_id = body["results"][0]["evaluation_id"].as_str().unwrap();
    let (holder_id, _) = holder_did_and_proof(
        evaluation_id,
        "farmer_status_sd_jwt",
        "predicate",
        &["farmer-under-4ha"],
    );
    let header = URL_SAFE_NO_PAD.encode(br#"{"alg":"none"}"#);
    let payload = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "sub": holder_id.clone(),
            "aud": "evidence-server",
            "exp": (OffsetDateTime::now_utc() + time::Duration::minutes(5)).unix_timestamp(),
            "iat": OffsetDateTime::now_utc().unix_timestamp(),
            "jti": "unsigned-test",
            "evaluation_id": evaluation_id,
            "credential_profile": "farmer_status_sd_jwt",
            "disclosure": "predicate",
            "claims": ["farmer-under-4ha"],
        }))
        .unwrap(),
    );

    let issued = server
        .post("/credentials/issue")
        .json(&json!({
            "evaluation_id": evaluation_id,
            "credential_profile": "farmer_status_sd_jwt",
            "format": "application/dc+sd-jwt",
            "disclosure": "predicate",
            "holder": {
                "binding": "did",
                "id": holder_id,
                "proof": format!("{header}.{payload}.")
            }
        }))
        .await;
    issued.assert_status(StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn credential_issue_rejects_holder_did_with_private_jwk_material() {
    let server = server();
    let eval = server
        .post("/claims/evaluate")
        .add_header("data-purpose", "https://purpose.example.test/subsidy")
        .json(&json!({
            "subject": {"id": "person-1"},
            "claims": ["farmer-under-4ha"],
            "disclosure": "predicate"
        }))
        .await;
    eval.assert_status(StatusCode::OK);
    let body: Value = eval.json();
    let evaluation_id = body["results"][0]["evaluation_id"].as_str().unwrap();
    let (holder_id, holder_proof) = holder_did_and_proof_with_options(
        evaluation_id,
        "farmer_status_sd_jwt",
        "predicate",
        &["farmer-under-4ha"],
        true,
    );

    let issued = server
        .post("/credentials/issue")
        .json(&json!({
            "evaluation_id": evaluation_id,
            "credential_profile": "farmer_status_sd_jwt",
            "format": "application/dc+sd-jwt",
            "disclosure": "predicate",
            "holder": {
                "binding": "did",
                "id": holder_id,
                "proof": holder_proof
            }
        }))
        .await;
    issued.assert_status(StatusCode::BAD_REQUEST);
    let body: Value = issued.json();
    assert_eq!(body["code"], "credential.holder_proof_required");
}
