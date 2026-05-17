// SPDX-License-Identifier: Apache-2.0
//! Phase C: HTTP issuance coverage for `/verify`, aggregate execute,
//! and `/{entity}/{id}` routes.
//!
//! Each test asserts the dual response contract:
//!
//! * Caller without `Accept: application/vc+jwt` receives the normal
//!   plain JSON response.
//! * Caller with the opt-in media type receives a 200 response carrying
//!   `Content-Type: application/vc+jwt` and a compact JWS body that
//!   verifies against the configured signer's public key.
//!
//! The audit pipeline is mounted so we also assert that the
//! `provenance.vc.issued` block lands in the audit envelope when the
//! caller opted in.

use std::env;
use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use axum::middleware::from_fn;
use axum::{Extension, Router};
use axum_test::TestServer;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use datafusion::arrow::array::{Float64Array, StringArray};
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::datasource::MemTable;
use datafusion::execution::context::SessionContext;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey, SECRET_KEY_LENGTH};
use rand_core::OsRng;
use registry_relay::api::{aggregates_router, entity_router, CursorSigner};
use registry_relay::audit::{audit_layer, AuditSettings, AuditSink, InMemorySink};
use registry_relay::auth::{AuthMode, Principal, ScopeSet};
use registry_relay::config::{
    self, Config, DatasetId, ProvenanceAlgorithm, ResourceId, SoftwareSignerConfig,
};
use registry_relay::entity::EntityRegistry;
use registry_relay::ingest::{
    register_versioned_table, table_name, ReadinessSnapshot, ReadyResource,
};
use registry_relay::provenance::signers::software::SoftwareSigner;
use registry_relay::provenance::{
    IssuerMode, ProvenanceState, ResolvedClaimValidity, ResolvedProvenanceConfig, ResolvedUrls,
    Signer,
};
use registry_relay::query::{AggregateQueryEngine, EntityQueryEngine};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use tokio::sync::watch;
use ulid::Ulid;

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

const FULL_STACK_RAW_API_KEY: &str = "registry_relay_full_stack_provenance_test_key";

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn fingerprint(raw: &str) -> String {
    format!("sha256:{}", hex_lower(&Sha256::digest(raw.as_bytes())))
}

fn export_jwk(env_name: &str) -> VerifyingKey {
    let sk = SigningKey::generate(&mut OsRng);
    let vk = sk.verifying_key();
    let d_bytes: [u8; SECRET_KEY_LENGTH] = sk.to_bytes();
    let jwk = json!({
        "kty": "OKP",
        "crv": "Ed25519",
        "d": URL_SAFE_NO_PAD.encode(d_bytes),
        "x": URL_SAFE_NO_PAD.encode(vk.to_bytes()),
        "alg": "EdDSA",
    });
    env::set_var(env_name, serde_json::to_string(&jwk).unwrap());
    vk
}

fn build_provenance_state(env_name: &str) -> (Arc<ProvenanceState>, VerifyingKey) {
    let vk = export_jwk(env_name);
    let cfg = SoftwareSignerConfig {
        jwk_env: env_name.to_string(),
        signing_algorithm: ProvenanceAlgorithm::EdDSA,
    };
    let signer = SoftwareSigner::from_config(&cfg, "did:web:gw.example#issuance".to_string())
        .expect("signer builds");
    let signer: Arc<dyn Signer> = Arc::new(signer);
    let state = ProvenanceState::new(ResolvedProvenanceConfig {
        enabled: true,
        mode: IssuerMode::Gateway,
        issuer_did: "did:web:gw.example".to_string(),
        verification_method_id: "did:web:gw.example#issuance".to_string(),
        accepted_media_types: vec!["application/vc+jwt".to_string()],
        claim_validity: ResolvedClaimValidity {
            verify_result: Duration::from_secs(300),
            aggregate_result: Duration::from_secs(3600),
            entity_record: Duration::from_secs(86_400),
        },
        urls: ResolvedUrls {
            provenance_context_url: "https://gw.example/contexts/provenance/v1.jsonld".to_string(),
            schema_base_url: "https://gw.example/schemas".to_string(),
        },
        signer,
        retired_keys: Vec::new(),
    });
    (Arc::new(state), vk)
}

/// Decode the JWS payload and verify the signature against the
/// matching public key.
fn decode_and_verify_payload(jws: &str, vk: &VerifyingKey) -> Value {
    let parts: Vec<&str> = jws.split('.').collect();
    assert_eq!(parts.len(), 3, "compact JWS shape");
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    let sig_bytes = URL_SAFE_NO_PAD.decode(parts[2]).expect("sig base64url");
    let sig_arr: [u8; 64] = sig_bytes.as_slice().try_into().expect("64-byte sig");
    let signature = Signature::from_bytes(&sig_arr);
    vk.verify_strict(signing_input.as_bytes(), &signature)
        .expect("signature verifies against pubkey");
    let payload_bytes = URL_SAFE_NO_PAD.decode(parts[1]).expect("payload base64url");
    serde_json::from_slice(&payload_bytes).expect("payload JSON")
}

fn assert_credential_subject_matches_schema(
    claim_type: registry_relay::provenance::jwt_vc::ClaimType,
    subject: &Value,
) {
    let schema_bytes = match claim_type {
        registry_relay::provenance::jwt_vc::ClaimType::VerifyResult => {
            registry_relay::provenance::resources::VERIFY_RESULT_V1
        }
        registry_relay::provenance::jwt_vc::ClaimType::AggregateResult => {
            registry_relay::provenance::resources::AGGREGATE_RESULT_V1
        }
        registry_relay::provenance::jwt_vc::ClaimType::EntityRecord => {
            registry_relay::provenance::resources::ENTITY_RECORD_V1
        }
        _ => panic!("unexpected claim type {claim_type:?}"),
    };
    let schema: Value = serde_json::from_slice(schema_bytes).expect("schema JSON");
    let compiled = jsonschema::JSONSchema::compile(&schema).expect("schema compiles");
    if let Err(errors) = compiled.validate(subject) {
        let messages: Vec<String> = errors.map(|error| error.to_string()).collect();
        panic!(
            "credentialSubject for {claim_type:?} must match published schema: {messages:?}\nsubject: {subject}"
        );
    };
}

/// Install the production audit middleware on a Router. Mirrors the
/// shape used inside `build_app_with_provenance` so the
/// `provenance.vc.issued` block ends up in the JSONL envelope just
/// like in production.
fn with_audit<S>(router: Router<S>, sink: Arc<dyn AuditSink>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    router
        .layer(from_fn(audit_layer))
        .layer(Extension(AuditSettings::default()))
        .layer(Extension(sink))
}

fn write_config(tmp: &TempDir) -> Config {
    write_config_with_min_group_size(tmp, 1)
}

fn write_config_with_min_group_size(tmp: &TempDir, min_group_size: u32) -> Config {
    let path = tmp.path().join("issuance_test.yaml");
    let body = format!(
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

datasets:
  - id: social_registry
    title: Social Registry
    description: Synthetic registry
    owner: Test
    sensitivity: personal
    access_rights: restricted
    update_frequency: monthly
    source:
      type: file
      path: fixtures/social_registry.csv
    refresh:
      mode: manual
    tables:
      - id: individuals_table
        primary_key: individual_id
        schema:
          strict: true
          fields:
            - name: individual_id
              type: string
              nullable: false
            - name: municipality_code
              type: string
              nullable: true
            - name: payment_amount
              type: number
              nullable: true
    entities:
      - name: individual
        table: individuals_table
        fields:
          - name: id
            from: individual_id
          - name: municipality_code
          - name: payment_amount
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
              ops: [eq, in]
        aggregates:
          - id: by_municipality
            description: Number of individuals by municipality
            group_by:
              - municipality_code
            measures:
              - name: individual_count
                function: count
                column: id
            disclosure_control:
              min_group_size: {min_group_size}
              suppression: omit

audit:
  sink: stdout
  format: jsonl
"#
    );
    std::fs::write(&path, body).expect("write config");
    config::load(&path).expect("config loads")
}

fn register_individuals(ctx: &SessionContext, ingest_version: Ulid) {
    let schema = Arc::new(Schema::new(vec![
        Field::new("individual_id", DataType::Utf8, false),
        Field::new("municipality_code", DataType::Utf8, true),
        Field::new("payment_amount", DataType::Float64, true),
    ]));
    let batch = RecordBatch::try_new(
        Arc::clone(&schema),
        vec![
            Arc::new(StringArray::from(vec!["ind-1", "ind-2", "ind-3"])),
            Arc::new(StringArray::from(vec!["mun-1", "mun-1", "mun-2"])),
            Arc::new(Float64Array::from(vec![10.0, 20.0, 30.0])),
        ],
    )
    .expect("batch");
    let table = MemTable::try_new(schema, vec![vec![batch]]).expect("mem table");
    let dataset: DatasetId = id("social_registry");
    let resource: ResourceId = id("individuals_table");
    register_versioned_table(
        ctx,
        table_name(&dataset, &resource),
        ingest_version,
        Arc::new(table),
    )
    .expect("register table");
}

struct Harness {
    server: TestServer,
    audit_sink: InMemorySink,
    verifying_key: VerifyingKey,
}

fn build_entity_harness(env_name: &str) -> Harness {
    let tmp = TempDir::new().expect("tempdir");
    let cfg = Arc::new(write_config(&tmp));
    // Leak the tempdir so the config path stays alive for the test.
    std::mem::forget(tmp);
    let registry = Arc::new(EntityRegistry::from_config(&cfg).expect("registry"));
    let ctx = Arc::new(SessionContext::new());
    let ingest_version = Ulid::from_string("01J5K8M0000000000000000000").expect("ulid");
    register_individuals(&ctx, ingest_version);
    let query = Arc::new(EntityQueryEngine::new(
        Arc::clone(&ctx),
        Arc::clone(&registry),
    ));
    let mut snapshot = ReadinessSnapshot::default();
    snapshot.ready.insert(
        (id("social_registry"), id("individuals_table")),
        ReadyResource {
            ingest_ulid: ingest_version,
            registered_at: time::OffsetDateTime::now_utc(),
        },
    );
    let (_tx, readiness) = watch::channel(snapshot);

    let (state, verifying_key) = build_provenance_state(env_name);
    let audit_sink = InMemorySink::new();
    let sink_arc: Arc<dyn AuditSink> = Arc::new(audit_sink.clone());

    let router = entity_router::<()>()
        .layer(Extension(query))
        .layer(Extension(registry))
        .layer(Extension(Arc::clone(&cfg)))
        .layer(Extension(readiness))
        .layer(Extension(Arc::new(CursorSigner::new_random())))
        .layer(Extension(principal(&[
            "social_registry:metadata",
            "social_registry:rows",
            "social_registry:verify",
        ])))
        .layer(Extension(state));
    let router = with_audit(router, sink_arc);
    Harness {
        server: TestServer::new(router),
        audit_sink,
        verifying_key,
    }
}

fn build_aggregate_harness(env_name: &str) -> Harness {
    let tmp = TempDir::new().expect("tempdir");
    let cfg = Arc::new(write_config(&tmp));
    std::mem::forget(tmp);
    let registry = Arc::new(EntityRegistry::from_config(&cfg).expect("registry"));
    let ctx = Arc::new(SessionContext::new());
    register_individuals(
        &ctx,
        Ulid::from_string("01J5K8M0000000000000000000").expect("ulid"),
    );
    let query = Arc::new(AggregateQueryEngine::new(
        Arc::clone(&ctx),
        Arc::clone(&registry),
        Arc::clone(&cfg),
    ));

    let (state, verifying_key) = build_provenance_state(env_name);
    let audit_sink = InMemorySink::new();
    let sink_arc: Arc<dyn AuditSink> = Arc::new(audit_sink.clone());

    let router = aggregates_router::<()>()
        .layer(Extension(query))
        .layer(Extension(registry))
        .layer(Extension(Arc::clone(&cfg)))
        .layer(Extension(principal(&["social_registry:aggregate"])))
        .layer(Extension(state));
    let router = with_audit(router, sink_arc);
    Harness {
        server: TestServer::new(router),
        audit_sink,
        verifying_key,
    }
}

/// Find the last audit line whose `path` matches the request path.
fn audit_record_for(sink: &InMemorySink, path: &str) -> Value {
    let lines = sink.snapshot();
    let line = lines
        .iter()
        .rev()
        .find(|line| {
            serde_json::from_str::<Value>(line)
                .ok()
                .and_then(|v| v["path"].as_str().map(|p| p == path))
                .unwrap_or(false)
        })
        .unwrap_or_else(|| panic!("no audit record for path {path}; got {lines:?}"));
    serde_json::from_str(line).expect("audit line is JSON")
}

// ---------------------------------------------------------------------------
// /verify
// ---------------------------------------------------------------------------

#[tokio::test]
async fn verify_plain_json_path_is_byte_equivalent_without_accept_header() {
    let harness = build_entity_harness("PROVENANCE_ISSUANCE_VERIFY_PLAIN_JWK");
    let resp = harness
        .server
        .get("/datasets/social_registry/individual/verify?id=ind-1")
        .await;
    resp.assert_status_ok();
    let content_type = resp
        .header("content-type")
        .to_str()
        .unwrap_or("")
        .to_string();
    assert!(
        content_type.starts_with("application/json"),
        "plain path keeps JSON content-type, got {content_type}"
    );
    let body: Value = resp.json();
    assert_eq!(body["exists"], true);
}

#[tokio::test]
async fn verify_returns_signed_vc_when_accept_opts_in() {
    let harness = build_entity_harness("PROVENANCE_ISSUANCE_VERIFY_VC_JWK");
    let resp = harness
        .server
        .get("/datasets/social_registry/individual/verify?id=ind-1")
        .add_header("accept", "application/vc+jwt")
        .await;
    resp.assert_status_ok();
    let content_type = resp
        .header("content-type")
        .to_str()
        .unwrap_or("")
        .to_string();
    assert_eq!(content_type, "application/vc+jwt");

    // Body is a compact JWS; verify signature + claim shape.
    let body = String::from_utf8(resp.as_bytes().to_vec()).expect("body utf8");
    let payload = decode_and_verify_payload(&body, &harness.verifying_key);
    assert_eq!(payload["type"][1], "VerifyResult");
    assert_eq!(
        payload["credentialSchema"]["id"],
        "https://gw.example/schemas/verify-result/v1.json"
    );
    assert_eq!(payload["issuer"], "did:web:gw.example");
    assert_eq!(
        payload["sub"],
        "https://gw.example/datasets/social_registry/individual/ind-1"
    );
    assert_eq!(payload["credentialSubject"]["predicate"], "exists");
    assert_eq!(payload["credentialSubject"]["value"], true);
    assert_credential_subject_matches_schema(
        registry_relay::provenance::jwt_vc::ClaimType::VerifyResult,
        &payload["credentialSubject"],
    );

    // Audit envelope carries the issuance block.
    let record = audit_record_for(
        &harness.audit_sink,
        "/datasets/social_registry/individual/verify",
    );
    let provenance = &record["provenance"];
    assert_eq!(provenance["event"], "provenance.vc.issued");
    assert_eq!(provenance["iss"], "did:web:gw.example");
    assert_eq!(provenance["kid"], "did:web:gw.example#issuance");
    assert_eq!(provenance["claim_type"], "VerifyResult");
    assert_eq!(
        provenance["subject"],
        "https://gw.example/datasets/social_registry/individual/ind-1"
    );
    assert!(provenance["jti"].as_str().unwrap().starts_with("urn:uuid:"));
    assert!(provenance["validity"]["iat"].is_i64());
    assert!(provenance["validity"]["nbf"].is_i64());
    assert!(provenance["validity"]["exp"].is_i64());
}

#[tokio::test]
async fn verify_plain_path_does_not_emit_provenance_audit_block() {
    let harness = build_entity_harness("PROVENANCE_ISSUANCE_VERIFY_NO_AUDIT_JWK");
    let _resp = harness
        .server
        .get("/datasets/social_registry/individual/verify?id=ind-1")
        .await;
    let record = audit_record_for(
        &harness.audit_sink,
        "/datasets/social_registry/individual/verify",
    );
    assert!(
        record.get("provenance").is_none(),
        "plain JSON path must not surface a provenance audit block; got {record}"
    );
}

// ---------------------------------------------------------------------------
// /datasets/{dataset_id}/{entity}/{id}
// ---------------------------------------------------------------------------

#[tokio::test]
async fn entity_record_plain_json_path_unchanged_without_accept_header() {
    let harness = build_entity_harness("PROVENANCE_ISSUANCE_RECORD_PLAIN_JWK");
    let resp = harness
        .server
        .get("/datasets/social_registry/individual/ind-1")
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["id"], "ind-1");
}

#[tokio::test]
async fn entity_record_returns_signed_vc_when_accept_opts_in() {
    let harness = build_entity_harness("PROVENANCE_ISSUANCE_RECORD_VC_JWK");
    let resp = harness
        .server
        .get("/datasets/social_registry/individual/ind-1")
        .add_header("accept", "application/vc+jwt")
        .await;
    resp.assert_status_ok();
    assert_eq!(
        resp.header("content-type").to_str().unwrap_or(""),
        "application/vc+jwt"
    );

    let body = String::from_utf8(resp.as_bytes().to_vec()).expect("body utf8");
    let payload = decode_and_verify_payload(&body, &harness.verifying_key);
    assert_eq!(payload["type"][1], "EntityRecord");
    assert_eq!(
        payload["credentialSchema"]["id"],
        "https://gw.example/schemas/entity-record/v1.json"
    );
    assert_eq!(payload["credentialSubject"]["fields"]["id"], "ind-1");
    assert!(
        payload["credentialSubject"].get("expanded").is_none(),
        "no expansions requested, so `expanded` should be absent"
    );
    assert_credential_subject_matches_schema(
        registry_relay::provenance::jwt_vc::ClaimType::EntityRecord,
        &payload["credentialSubject"],
    );

    let record = audit_record_for(
        &harness.audit_sink,
        "/datasets/social_registry/individual/ind-1",
    );
    assert_eq!(record["provenance"]["claim_type"], "EntityRecord");
}

// ---------------------------------------------------------------------------
// /datasets/{dataset_id}/{entity}/aggregates/{aggregate_id}
// ---------------------------------------------------------------------------

#[tokio::test]
async fn aggregate_plain_json_path_unchanged_without_accept_header() {
    let harness = build_aggregate_harness("PROVENANCE_ISSUANCE_AGGREGATE_PLAIN_JWK");
    let resp = harness
        .server
        .get("/datasets/social_registry/individual/aggregates/by_municipality")
        .await;
    resp.assert_status_ok();
    let body: Value = resp.json();
    assert_eq!(body["aggregate_id"], "by_municipality");
    assert!(body["rows"].is_array());
}

#[tokio::test]
async fn aggregate_returns_signed_vc_when_accept_opts_in() {
    let harness = build_aggregate_harness("PROVENANCE_ISSUANCE_AGGREGATE_VC_JWK");
    let resp = harness
        .server
        .get("/datasets/social_registry/individual/aggregates/by_municipality")
        .add_header("accept", "application/vc+jwt")
        .await;
    resp.assert_status_ok();
    assert_eq!(
        resp.header("content-type").to_str().unwrap_or(""),
        "application/vc+jwt"
    );

    let body = String::from_utf8(resp.as_bytes().to_vec()).expect("body utf8");
    let payload = decode_and_verify_payload(&body, &harness.verifying_key);
    assert_eq!(payload["type"][1], "AggregateResult");
    assert_eq!(
        payload["credentialSchema"]["id"],
        "https://gw.example/schemas/aggregate-result/v1.json"
    );
    let subject = &payload["credentialSubject"];
    assert_eq!(subject["aggregateId"], "by_municipality");
    assert_eq!(subject["groupBy"][0], "municipality_code");
    assert_eq!(subject["measures"][0], "individual_count");
    let rows = subject["rows"].as_array().expect("rows array");
    assert!(!rows.is_empty());
    // The aggregate_result_subject builder splits each row into
    // `{group, values}`; cross-check the first row has both keys.
    assert!(rows[0]["group"].is_object());
    assert!(rows[0]["values"].is_object());
    assert_credential_subject_matches_schema(
        registry_relay::provenance::jwt_vc::ClaimType::AggregateResult,
        subject,
    );

    let record = audit_record_for(
        &harness.audit_sink,
        "/datasets/social_registry/individual/aggregates/by_municipality",
    );
    assert_eq!(record["provenance"]["claim_type"], "AggregateResult");
    assert_eq!(
        record["provenance"]["subject"],
        "https://gw.example/datasets/social_registry/individual/aggregates/by_municipality"
    );
}

#[tokio::test]
async fn aggregate_vc_as_of_reflects_resource_registered_at() {
    // The AggregateResult VC's `asOf` claim must reflect when the
    // underlying ingest snapshot became visible
    // (`ReadinessSnapshot::ready.registered_at`), not when the query
    // happened to run (`AggregateResult::computed_at`). The two values
    // are produced at different points in time; collapsing them into
    // one hides the freshness of the data the aggregate was computed
    // from.
    let tmp = TempDir::new().expect("tempdir");
    let cfg = Arc::new(write_config(&tmp));
    std::mem::forget(tmp);
    let registry = Arc::new(EntityRegistry::from_config(&cfg).expect("registry"));
    let ctx = Arc::new(SessionContext::new());
    let ingest_version = Ulid::from_string("01J5K8M0000000000000000000").expect("ulid");
    register_individuals(&ctx, ingest_version);
    let query = Arc::new(AggregateQueryEngine::new(
        Arc::clone(&ctx),
        Arc::clone(&registry),
        Arc::clone(&cfg),
    ));

    // Deterministic timestamp well in the past so it cannot collide
    // with the handler's `computed_at` (which uses `now_utc()`).
    let registered_at =
        time::OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("fixed past timestamp");
    let mut snapshot = ReadinessSnapshot::default();
    snapshot.ready.insert(
        (id("social_registry"), id("individuals_table")),
        ReadyResource {
            ingest_ulid: ingest_version,
            registered_at,
        },
    );
    let (_tx, readiness) = watch::channel(snapshot);

    let (state, verifying_key) = build_provenance_state("PROVENANCE_ISSUANCE_AGGREGATE_AS_OF_JWK");
    let audit_sink = InMemorySink::new();
    let sink_arc: Arc<dyn AuditSink> = Arc::new(audit_sink.clone());

    let router = aggregates_router::<()>()
        .layer(Extension(query))
        .layer(Extension(registry))
        .layer(Extension(Arc::clone(&cfg)))
        .layer(Extension(readiness))
        .layer(Extension(principal(&["social_registry:aggregate"])))
        .layer(Extension(state));
    let router = with_audit(router, sink_arc);
    let server = TestServer::new(router);

    let resp = server
        .get("/datasets/social_registry/individual/aggregates/by_municipality")
        .add_header("accept", "application/vc+jwt")
        .await;
    resp.assert_status_ok();
    let body = String::from_utf8(resp.as_bytes().to_vec()).expect("body utf8");
    let payload = decode_and_verify_payload(&body, &verifying_key);
    let subject = &payload["credentialSubject"];

    let expected_as_of = registered_at
        .format(&time::format_description::well_known::Rfc3339)
        .expect("rfc3339");
    assert_eq!(
        subject["asOf"], expected_as_of,
        "asOf must reflect the resource's ingest registered_at, not the handler's computed_at",
    );
    assert_ne!(
        subject["asOf"], subject["computedAt"],
        "asOf and computedAt are distinct: ingest time vs query time",
    );
}

#[tokio::test]
async fn aggregate_vc_subject_reflects_disclosure_suppression() {
    // When disclosure control suppresses small groups, the signed
    // `AggregateResult` VC must mirror that exact
    // shape. The credentialSubject should:
    //   * echo the configured `measures` list,
    //   * carry only the non-suppressed rows under `rows`, and
    //   * surface `suppressedGroups` as a u64 count matching the
    //     plain-JSON path.
    // With `min_group_size: 2` and three input rows (mun-1 x2,
    // mun-2 x1), the mun-2 group must drop out (default
    // `suppression: omit`) and `suppressedGroups` must equal 1.
    let tmp = TempDir::new().expect("tempdir");
    let cfg = Arc::new(write_config_with_min_group_size(&tmp, 2));
    std::mem::forget(tmp);
    let registry = Arc::new(EntityRegistry::from_config(&cfg).expect("registry"));
    let ctx = Arc::new(SessionContext::new());
    let ingest_version = Ulid::from_string("01J5K8M0000000000000000000").expect("ulid");
    register_individuals(&ctx, ingest_version);
    let query = Arc::new(AggregateQueryEngine::new(
        Arc::clone(&ctx),
        Arc::clone(&registry),
        Arc::clone(&cfg),
    ));

    let (state, verifying_key) =
        build_provenance_state("PROVENANCE_ISSUANCE_AGGREGATE_SUPPRESS_JWK");
    let audit_sink = InMemorySink::new();
    let sink_arc: Arc<dyn AuditSink> = Arc::new(audit_sink.clone());

    let router = aggregates_router::<()>()
        .layer(Extension(query))
        .layer(Extension(registry))
        .layer(Extension(Arc::clone(&cfg)))
        .layer(Extension(principal(&["social_registry:aggregate"])))
        .layer(Extension(state));
    let router = with_audit(router, sink_arc);
    let server = TestServer::new(router);

    // Plain-JSON path: capture the disclosure-controlled shape we
    // expect the VC subject to mirror.
    let plain_resp = server
        .get("/datasets/social_registry/individual/aggregates/by_municipality")
        .await;
    plain_resp.assert_status_ok();
    let plain_body: Value = plain_resp.json();
    assert_eq!(plain_body["suppressed_groups"], 1);
    let plain_rows = plain_body["rows"].as_array().expect("rows array");
    assert_eq!(plain_rows.len(), 1, "mun-2 group must be omitted");
    assert_eq!(plain_rows[0]["municipality_code"], "mun-1");
    assert_eq!(plain_rows[0]["individual_count"], 2);

    // Signed-VC path: decode the JWS and assert credentialSubject
    // mirrors the suppression result.
    let signed_resp = server
        .get("/datasets/social_registry/individual/aggregates/by_municipality")
        .add_header("accept", "application/vc+jwt")
        .await;
    signed_resp.assert_status_ok();
    assert_eq!(
        signed_resp.header("content-type").to_str().unwrap_or(""),
        "application/vc+jwt"
    );
    let body = String::from_utf8(signed_resp.as_bytes().to_vec()).expect("body utf8");
    let payload = decode_and_verify_payload(&body, &verifying_key);
    let subject = &payload["credentialSubject"];

    assert_eq!(subject["aggregateId"], "by_municipality");
    assert_eq!(subject["minGroupSize"], 2);
    assert_eq!(
        subject["suppressedGroups"], 1,
        "VC subject must mirror the plain-JSON suppression count",
    );
    let measures = subject["measures"].as_array().expect("measures array");
    assert_eq!(
        measures,
        &vec![Value::String("individual_count".to_string())],
        "VC subject must echo the configured measure names",
    );
    let rows = subject["rows"].as_array().expect("rows array");
    assert_eq!(
        rows.len(),
        1,
        "VC subject row count must mirror disclosure-controlled output",
    );
    assert_eq!(rows[0]["group"]["municipality_code"], "mun-1");
    assert_eq!(rows[0]["values"]["individual_count"], 2);
}

#[tokio::test]
async fn production_app_builder_issues_vc_after_real_api_key_auth() {
    let tmp = TempDir::new().expect("tempdir");
    let cfg = Arc::new(write_config(&tmp));
    std::mem::forget(tmp);
    let registry = Arc::new(EntityRegistry::from_config(&cfg).expect("registry"));
    let ctx = Arc::new(SessionContext::new());
    let ingest_version = Ulid::from_string("01J5K8M0000000000000000000").expect("ulid");
    register_individuals(&ctx, ingest_version);

    let query = Arc::new(EntityQueryEngine::new(
        Arc::clone(&ctx),
        Arc::clone(&registry),
    ));
    let aggregate_query = Arc::new(AggregateQueryEngine::new(
        Arc::clone(&ctx),
        Arc::clone(&registry),
        Arc::clone(&cfg),
    ));
    let mut snapshot = ReadinessSnapshot::default();
    snapshot.ready.insert(
        (id("social_registry"), id("individuals_table")),
        ReadyResource {
            ingest_ulid: ingest_version,
            registered_at: time::OffsetDateTime::now_utc(),
        },
    );
    let (_tx, readiness) = watch::channel(snapshot);

    let auth_entry = registry_relay::auth::api_key::ApiKeyEntry::new(
        "vc-full-stack".to_string(),
        ScopeSet::from_iter([
            "social_registry:metadata",
            "social_registry:rows",
            "social_registry:verify",
        ]),
        fingerprint(FULL_STACK_RAW_API_KEY),
    )
    .expect("fingerprint parses");
    let auth = Arc::new(registry_relay::auth::api_key::ApiKeyAuth::new(vec![
        auth_entry,
    ]));
    let audit_sink = InMemorySink::new();
    let sink_arc: Arc<dyn AuditSink> = Arc::new(audit_sink.clone());
    let (provenance, verifying_key) = build_provenance_state("FULL_STACK_PROVENANCE_JWK");

    let app = registry_relay::server::build_app_with_entity_query_and_provenance(
        Arc::clone(&cfg),
        auth,
        sink_arc,
        readiness,
        registry,
        query,
        aggregate_query,
        Some(provenance),
    );
    let server = TestServer::new(app);

    let resp = server
        .get("/datasets/social_registry/individual/verify?id=ind-1")
        .add_header("authorization", format!("Bearer {FULL_STACK_RAW_API_KEY}"))
        .add_header("accept", "application/vc+jwt")
        .await;
    resp.assert_status_ok();
    assert_eq!(
        resp.header("content-type").to_str().unwrap_or(""),
        "application/vc+jwt"
    );

    let body = String::from_utf8(resp.as_bytes().to_vec()).expect("body utf8");
    let payload = decode_and_verify_payload(&body, &verifying_key);
    assert_eq!(payload["type"][1], "VerifyResult");
    assert_eq!(payload["credentialSubject"]["value"], true);
    assert_credential_subject_matches_schema(
        registry_relay::provenance::jwt_vc::ClaimType::VerifyResult,
        &payload["credentialSubject"],
    );

    let record = audit_record_for(&audit_sink, "/datasets/social_registry/individual/verify");
    assert_eq!(record["principal_id"], "vc-full-stack");
    assert_eq!(record["auth_mode"], "api_key");
    assert_eq!(record["provenance"]["event"], "provenance.vc.issued");
}

// ---------------------------------------------------------------------------
// Disabled / missing provenance state must not change the plain JSON contract.
// ---------------------------------------------------------------------------

#[tokio::test]
async fn verify_returns_plain_json_when_provenance_state_is_absent() {
    // Same harness as the entity tests, but skip the ProvenanceState
    // extension. The router must still accept the request and return
    // plain JSON even when the caller asks for a signed VC.
    let tmp = TempDir::new().expect("tempdir");
    let cfg = Arc::new(write_config(&tmp));
    std::mem::forget(tmp);
    let registry = Arc::new(EntityRegistry::from_config(&cfg).expect("registry"));
    let ctx = Arc::new(SessionContext::new());
    let ingest_version = Ulid::from_string("01J5K8M0000000000000000000").expect("ulid");
    register_individuals(&ctx, ingest_version);
    let query = Arc::new(EntityQueryEngine::new(
        Arc::clone(&ctx),
        Arc::clone(&registry),
    ));
    let mut snapshot = ReadinessSnapshot::default();
    snapshot.ready.insert(
        (id("social_registry"), id("individuals_table")),
        ReadyResource {
            ingest_ulid: ingest_version,
            registered_at: time::OffsetDateTime::now_utc(),
        },
    );
    let (_tx, readiness) = watch::channel(snapshot);
    let audit_sink = InMemorySink::new();
    let sink_arc: Arc<dyn AuditSink> = Arc::new(audit_sink.clone());

    let router = entity_router::<()>()
        .layer(Extension(query))
        .layer(Extension(registry))
        .layer(Extension(Arc::clone(&cfg)))
        .layer(Extension(readiness))
        .layer(Extension(Arc::new(CursorSigner::new_random())))
        .layer(Extension(principal(&[
            "social_registry:metadata",
            "social_registry:rows",
            "social_registry:verify",
        ])));
    let router = with_audit(router, sink_arc);
    let server = TestServer::new(router);

    let resp = server
        .get("/datasets/social_registry/individual/verify?id=ind-1")
        .add_header("accept", "application/vc+jwt")
        .await;
    resp.assert_status(StatusCode::OK);
    let content_type = resp
        .header("content-type")
        .to_str()
        .unwrap_or("")
        .to_string();
    assert!(
        content_type.starts_with("application/json"),
        "without provenance state, opt-in must still serve plain JSON; got {content_type}"
    );
    let body: Value = resp.json();
    assert_eq!(body["exists"], true);
}
