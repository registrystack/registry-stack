// SPDX-License-Identifier: Apache-2.0
//! Third-party verification coverage for issued credentials.
//!
//! The goal of this test crate is to prove that a VC issued by the
//! gateway can be verified by a verifier that does NOT depend on any
//! of `data_gate`'s signing internals. If we can verify a VC using
//! only:
//!
//! * the compact JWS body returned by the gateway, and
//! * the active key's public JWK fetched from `/.well-known/did.json`,
//!
//! using independent verifier paths, then the gateway's wire format is
//! interoperable.
//!
//! What this test does NOT do:
//!
//! * It does not re-implement Ed25519. We use `jsonwebtoken` and a
//!   Node.js sidecar backed by Node's native crypto APIs; neither sees
//!   the private key material.
//! * It does not assert business semantics. The point is the round
//!   trip JWS -> public JWK -> verified payload, not the contents of
//!   the credential.

use std::env;
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use axum::{Extension, Router};
use axum_test::TestServer;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use data_gate::api::CursorSigner;
use data_gate::api::{did_router, entity_router};
use data_gate::auth::{AuthMode, Principal, ScopeSet};
use data_gate::config::{
    self, Config, DatasetId, ProvenanceAlgorithm, ResourceId, SoftwareSignerConfig,
};
use data_gate::entity::EntityRegistry;
use data_gate::ingest::{register_versioned_table, table_name, ReadinessSnapshot, ReadyResource};
use data_gate::provenance::signers::software::SoftwareSigner;
use data_gate::provenance::{
    IssuerMode, ProvenanceState, ResolvedClaimValidity, ResolvedProvenanceConfig, ResolvedUrls,
    Signer,
};
use data_gate::query::EntityQueryEngine;
use datafusion::arrow::array::StringArray;
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::datasource::MemTable;
use datafusion::execution::context::SessionContext;
use ed25519_dalek::{SigningKey, VerifyingKey, SECRET_KEY_LENGTH};
use jsonwebtoken::jwk::Jwk;
use jsonwebtoken::{Algorithm, DecodingKey, Validation};
use rand_core::OsRng;
use serde::Deserialize;
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio::sync::watch;
use ulid::Ulid;

const VM_ID: &str = "did:web:gw.example#issuance";
const ISSUER_DID: &str = "did:web:gw.example";

fn id<T: serde::de::DeserializeOwned>(value: &str) -> T {
    serde_json::from_str(&format!(r#""{value}""#)).expect("id deserializes")
}

fn principal(scopes: &[&str]) -> Principal {
    Principal {
        api_key_id: "test".to_string(),
        scopes: scopes.iter().copied().collect::<ScopeSet>(),
        auth_mode: AuthMode::ApiKey,
    }
}

/// Export an Ed25519 keypair into the named env var as a JSON Web Key.
/// Returns the verifying key so the test can cross-check the JWK fetched
/// from the DID Document.
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

fn build_state(env_name: &str) -> (Arc<ProvenanceState>, VerifyingKey) {
    let vk = export_jwk(env_name);
    let cfg = SoftwareSignerConfig {
        jwk_env: env_name.to_string(),
        signing_algorithm: ProvenanceAlgorithm::EdDSA,
    };
    let signer: Arc<dyn Signer> =
        Arc::new(SoftwareSigner::from_config(&cfg, VM_ID.to_string()).expect("signer builds"));
    let state = ProvenanceState::new(ResolvedProvenanceConfig {
        enabled: true,
        mode: IssuerMode::Gateway,
        issuer_did: ISSUER_DID.to_string(),
        verification_method_id: VM_ID.to_string(),
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

fn write_config(tmp: &TempDir) -> Config {
    let path = tmp.path().join("third_party_verification.yaml");
    std::fs::write(
        &path,
        r#"
server:
  bind: 127.0.0.1:0

catalog:
  title: Test
  base_url: https://gw.example
  publisher: Test

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
    entities:
      - name: individual
        table: individuals_table
        fields:
          - name: id
            from: individual_id
          - name: municipality_code
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

audit:
  sink: stdout
  format: jsonl
"#,
    )
    .expect("write config");
    config::load(&path).expect("config loads")
}

fn register_individuals(ctx: &SessionContext, ingest_version: Ulid) {
    let schema = Arc::new(Schema::new(vec![
        Field::new("individual_id", DataType::Utf8, false),
        Field::new("municipality_code", DataType::Utf8, true),
    ]));
    let batch = RecordBatch::try_new(
        Arc::clone(&schema),
        vec![
            Arc::new(StringArray::from(vec!["ind-1"])),
            Arc::new(StringArray::from(vec!["mun-1"])),
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

/// Compose a router that exposes both `/verify` (issuance) and
/// `/.well-known/did.json` (key publication). The auth layer from
/// `build_app_with_provenance` is skipped so the test can call
/// `/verify` directly with a `Principal` carrying the required scopes.
fn build_app(
    cfg: Arc<Config>,
    state: Arc<ProvenanceState>,
    readiness: watch::Receiver<ReadinessSnapshot>,
    query: Arc<EntityQueryEngine>,
    registry: Arc<EntityRegistry>,
) -> Router {
    let entity = entity_router::<()>()
        .layer(Extension(query))
        .layer(Extension(Arc::clone(&registry)))
        .layer(Extension(Arc::clone(&cfg)))
        .layer(Extension(readiness))
        .layer(Extension(Arc::new(CursorSigner::new_random())))
        .layer(Extension(principal(&[
            "social_registry:verify",
            "social_registry:rows",
            "social_registry:metadata",
        ])));

    // `did_router` is a `Router<()>`; merge it with the entity routes
    // and install `ProvenanceState` as a shared extension so the DID
    // handler can resolve the active verification method and the
    // `/verify` handler can issue a signed VC.
    let did = did_router::<()>();
    entity.merge(did).layer(Extension(state))
}

fn verify_with_node_crypto(jws: &str, public_jwk: &Value) {
    let script = r#"
const crypto = require('node:crypto');

const jws = process.env.DATAGATE_TEST_JWS;
const jwk = JSON.parse(process.env.DATAGATE_TEST_JWK);
const [headerB64, payloadB64, signatureB64] = jws.split('.');
if (!headerB64 || !payloadB64 || !signatureB64) {
  throw new Error('compact JWS must have three segments');
}
const header = JSON.parse(Buffer.from(headerB64, 'base64url').toString('utf8'));
const payload = JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
if (header.alg !== 'EdDSA' || header.typ !== 'vc+jwt' || header.cty !== 'vc') {
  throw new Error(`unexpected JOSE header ${JSON.stringify(header)}`);
}
const key = crypto.createPublicKey({ key: jwk, format: 'jwk' });
const ok = crypto.verify(
  null,
  Buffer.from(`${headerB64}.${payloadB64}`),
  key,
  Buffer.from(signatureB64, 'base64url')
);
if (!ok) {
  throw new Error('signature verification failed');
}
if (payload.iss !== 'did:web:gw.example') {
  throw new Error(`unexpected iss ${payload.iss}`);
}
if (!payload.jti || !payload.jti.startsWith('urn:uuid:')) {
  throw new Error(`unexpected jti ${payload.jti}`);
}
"#;
    let output = Command::new("node")
        .arg("-e")
        .arg(script)
        .env("DATAGATE_TEST_JWS", jws)
        .env(
            "DATAGATE_TEST_JWK",
            serde_json::to_string(public_jwk).expect("jwk serializes"),
        )
        .output()
        .expect("node verifier runs");
    assert!(
        output.status.success(),
        "node crypto verifier failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

/// JWT payload shape we care about for the round trip. We pull out
/// only the fields the test asserts on; extra fields are ignored.
#[derive(Debug, Deserialize)]
struct VcClaims {
    iss: String,
    sub: String,
    jti: String,
    iat: i64,
    nbf: i64,
    exp: i64,
}

#[tokio::test]
async fn third_party_verifier_can_verify_vc_against_did_document_jwk() {
    // Stand up an issuance harness.
    let (state, expected_vk) = build_state("THIRD_PARTY_VERIFICATION_JWK");
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

    let app = build_app(cfg, state, readiness, query, registry);
    let server = TestServer::new(app);

    // Step 1: fetch the DID Document and pull the active key's
    // public JWK out. A third-party verifier would do the same against
    // a real `https://` URL; we hit our in-process server here.
    let did_resp = server.get("/.well-known/did.json").await;
    did_resp.assert_status(StatusCode::OK);
    let did_body: Value = did_resp.json();
    let methods = did_body["verificationMethod"]
        .as_array()
        .expect("verificationMethod array");
    let active = methods
        .iter()
        .find(|entry| entry["id"] == VM_ID)
        .expect("active verification method present");
    let active_jwk_value = active["publicKeyJwk"].clone();

    // Cross-check that the published `x` matches the signer's actual
    // public key. If this fails, the DID Document is internally
    // inconsistent and no third-party verifier will ever succeed.
    let active_x = active_jwk_value["x"].as_str().expect("publicKeyJwk.x");
    assert_eq!(
        URL_SAFE_NO_PAD.decode(active_x).expect("x base64url"),
        expected_vk.to_bytes(),
    );

    // Step 2: request a signed VC from the issuance endpoint.
    let issue_resp = server
        .get("/datasets/social_registry/individual/verify?id=ind-1")
        .add_header("accept", "application/vc+jwt")
        .await;
    issue_resp.assert_status_ok();
    assert_eq!(
        issue_resp.header("content-type").to_str().unwrap_or(""),
        "application/vc+jwt"
    );
    let jws = String::from_utf8(issue_resp.as_bytes().to_vec()).expect("body utf8");

    // Step 3: verify the JWS using independent verifier code paths.
    // `jsonwebtoken` checks the Rust ecosystem path; the Node sidecar
    // checks a JavaScript runtime without linking any data_gate code.

    //   3a) Build the decoding key from the JWK object itself
    //   (whatever fields the DID Document publishes). This is the
    //   most realistic third-party flow.
    {
        let jwk: Jwk = serde_json::from_value(active_jwk_value.clone()).expect("jwk parses");
        let decoding_key = DecodingKey::from_jwk(&jwk).expect("decoding key from jwk");
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[ISSUER_DID]);
        validation.set_required_spec_claims(&["iss", "sub", "iat", "nbf", "exp"]);
        // `aud` is not set on these credentials.
        validation.validate_aud = false;
        let token = jsonwebtoken::decode::<VcClaims>(&jws, &decoding_key, &validation)
            .expect("third-party verify (from_jwk) succeeds");
        assert_eq!(token.claims.iss, ISSUER_DID);
        assert_eq!(
            token.claims.sub,
            "https://gw.example/datasets/social_registry/individual/ind-1"
        );
        // The validity window is sane.
        assert!(token.claims.nbf <= token.claims.iat + 1);
        assert!(token.claims.exp > token.claims.iat);
        assert!(!token.claims.jti.is_empty());
    }

    //   3b) Build the decoding key from just the base64url-encoded
    //   `x` component. This mirrors a verifier that already knows the
    //   key bytes (e.g. pinned out of band) and only needs to confirm
    //   the signature.
    {
        let decoding_key =
            DecodingKey::from_ed_components(active_x).expect("decoding key from ed components");
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.set_issuer(&[ISSUER_DID]);
        validation.set_required_spec_claims(&["iss", "sub", "iat", "nbf", "exp"]);
        validation.validate_aud = false;
        let token = jsonwebtoken::decode::<VcClaims>(&jws, &decoding_key, &validation)
            .expect("third-party verify (from_ed_components) succeeds");
        assert_eq!(token.claims.iss, ISSUER_DID);
        assert!(!token.claims.jti.is_empty());
    }

    //   3c) Verify in a JavaScript runtime. The sidecar receives only
    //   the compact JWS plus the public JWK from the DID Document.
    verify_with_node_crypto(&jws, &active_jwk_value);

    // Step 4: a verifier that trusts a different key MUST reject the
    // signature. This guards against accidentally validating on the
    // wrong key (e.g. a stale `kid`).
    {
        let wrong_sk = SigningKey::generate(&mut OsRng);
        let wrong_x = URL_SAFE_NO_PAD.encode(wrong_sk.verifying_key().to_bytes());
        let decoding_key = DecodingKey::from_ed_components(&wrong_x)
            .expect("decoding key from wrong ed components");
        let mut validation = Validation::new(Algorithm::EdDSA);
        validation.validate_aud = false;
        let empty: [&str; 0] = [];
        validation.set_required_spec_claims(&empty);
        let result = jsonwebtoken::decode::<VcClaims>(&jws, &decoding_key, &validation);
        assert!(
            result.is_err(),
            "verification against an unrelated key must fail",
        );
    }
}
