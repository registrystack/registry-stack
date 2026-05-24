// SPDX-License-Identifier: Apache-2.0
#![cfg(feature = "publicschema-cel")]

//! PublicSchema CEL feature coverage for entity-record VC issuance.

use std::env;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

use axum::http::StatusCode;
use axum::middleware::from_fn;
use axum::{Extension, Router};
use axum_test::TestServer;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use datafusion::arrow::array::StringArray;
use datafusion::arrow::datatypes::{DataType, Field, Schema};
use datafusion::arrow::record_batch::RecordBatch;
use datafusion::datasource::MemTable;
use datafusion::execution::context::SessionContext;
use ed25519_dalek::{Signature, SigningKey, VerifyingKey, SECRET_KEY_LENGTH};
use rand_core::OsRng;
use registry_relay::api::{entity_router, CursorSigner};
use registry_relay::audit::{audit_layer, AuditPipeline, AuditSettings, InMemorySink};
use registry_relay::auth::{AuthMode, Principal, ScopeSet};
use registry_relay::config::{self, Config, DatasetId, ProvenanceAlgorithm, ResourceId};
use registry_relay::entity::EntityRegistry;
use registry_relay::ingest::{
    register_versioned_table, table_name, ReadinessSnapshot, ReadyResource,
};
use registry_relay::provenance::publicschema::build_publicschema_registry;
use registry_relay::provenance::signers::software::SoftwareSigner;
use registry_relay::provenance::{
    IssuerMode, ProvenanceState, ResolvedClaimValidity, ResolvedProvenanceConfig, ResolvedUrls,
    Signer,
};
use registry_relay::query::EntityQueryEngine;
use serde_json::{json, Value};
use tempfile::TempDir;
use tokio::sync::watch;
use ulid::Ulid;

const PERSON_SCHEMA: &str = include_str!("fixtures/publicschema/person.schema.json");
const PERSON_MAPPING: &str = include_str!("../mappings/individual-person.publicschema.yaml");
const IND_1_SUBJECT_URI: &str = "https://gw.example/datasets/social_registry/individual/ind-1";

fn person_schema_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/publicschema/person.schema.json")
}

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
    let signer = SoftwareSigner::from_config(
        &registry_relay::config::SoftwareSignerConfig {
            jwk_env: env_name.to_string(),
            signing_algorithm: ProvenanceAlgorithm::EdDSA,
        },
        "did:web:gw.example#issuance".to_string(),
    )
    .expect("signer builds");
    let signer: Arc<dyn Signer> = Arc::new(signer);
    let state = ProvenanceState::new(ResolvedProvenanceConfig {
        enabled: true,
        mode: IssuerMode::Gateway,
        issuer_did: "did:web:gw.example".to_string(),
        verification_method_id: "did:web:gw.example#issuance".to_string(),
        accepted_media_types: vec!["application/vc+jwt".to_string()],
        claim_validity: ResolvedClaimValidity {
            aggregate_result: std::time::Duration::from_secs(3600),
            entity_record: std::time::Duration::from_secs(86_400),
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

fn assert_node_verifier_accepts_publicschema_person_vc(
    tmp: &TempDir,
    jws: &str,
    verifying_key: &VerifyingKey,
) {
    let jwt_path = tmp.path().join("publicschema-person.jwt");
    let did_path = tmp.path().join("did.json");
    let schema_path = tmp.path().join("publicschema-person.verifier.schema.json");
    std::fs::write(&jwt_path, jws).expect("write jwt");
    std::fs::write(
        &did_path,
        serde_json::to_vec_pretty(&json!({
            "id": "did:web:gw.example",
            "verificationMethod": [{
                "id": "did:web:gw.example#issuance",
                "type": "JsonWebKey2020",
                "controller": "did:web:gw.example",
                "publicKeyJwk": {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "x": URL_SAFE_NO_PAD.encode(verifying_key.to_bytes()),
                    "alg": "EdDSA",
                }
            }],
            "assertionMethod": ["did:web:gw.example#issuance"],
        }))
        .expect("did JSON"),
    )
    .expect("write did");
    std::fs::write(
        &schema_path,
        serde_json::to_vec_pretty(&json!({
            "type": "object",
            "required": ["id", "type", "given_name", "family_name", "date_of_birth", "gender"],
            "additionalProperties": false,
            "properties": {
                "id": { "type": "string", "format": "uri" },
                "type": { "const": "Person" },
                "given_name": { "type": "string", "minLength": 1 },
                "family_name": { "type": "string", "minLength": 1 },
                "date_of_birth": { "type": "string", "format": "date" },
                "gender": { "type": "string", "enum": ["male", "female", "other", "not_stated"] },
                "email_address": { "type": "string" }
            }
        }))
        .expect("schema JSON"),
    )
    .expect("write schema");

    let output = Command::new("node")
        .arg(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("scripts/verify_vc_jwt.mjs"))
        .arg("--jwt-file")
        .arg(&jwt_path)
        .arg("--did-document")
        .arg(&did_path)
        .arg("--issuer")
        .arg("did:web:gw.example")
        .arg("--claim-type")
        .arg("Person")
        .arg("--schema-id")
        .arg("https://publicschema.org/schemas/Person.schema.json")
        .arg("--schema")
        .arg(&schema_path)
        .arg("--quiet")
        .output()
        .expect("node verifier runs");
    assert!(
        output.status.success(),
        "node verifier failed\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}

fn with_audit<S>(router: Router<S>, sink: Arc<AuditPipeline>) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    router
        .layer(from_fn(audit_layer))
        .layer(Extension(AuditSettings::default()))
        .layer(Extension(sink))
}

fn write_config(tmp: &TempDir) -> Config {
    let mapping_path = tmp.path().join("individual-person.publicschema.yaml");
    std::fs::write(&mapping_path, PERSON_MAPPING).expect("write mapping");

    let config_path = tmp.path().join("publicschema_issuance.yaml");
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
            - name: first_name
              type: string
              nullable: false
            - name: last_name
              type: string
              nullable: false
            - name: dob
              type: string
              nullable: false
            - name: sex_code
              type: string
              nullable: false
            - name: email
              type: string
              nullable: true
    entities:
      - name: individual
        table: individuals_table
        fields:
          - name: id
            from: individual_id
          - name: first_name
          - name: last_name
          - name: dob
          - name: sex_code
          - name: email
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
        publicschema:
          target: Person
          mapping_path: "{}"
          schema_validation_path: "{}"

audit:
  sink: stdout
  format: jsonl
"#,
        mapping_path.display(),
        person_schema_path().display()
    );
    std::fs::write(&config_path, body).expect("write config");
    config::load(&config_path).expect("config loads")
}

fn load_config_with_publicschema_block(tmp: &TempDir, publicschema_block: &str) -> Config {
    let config_path = tmp.path().join("publicschema_test.yaml");
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

audit:
  sink: stdout
  format: jsonl

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
            - name: first_name
              type: string
              nullable: false
            - name: last_name
              type: string
              nullable: false
            - name: dob
              type: string
              nullable: false
            - name: sex_code
              type: string
              nullable: false
            - name: email
              type: string
              nullable: true
    entities:
      - name: individual
        table: individuals_table
        fields:
          - name: id
            from: individual_id
          - name: first_name
          - name: last_name
          - name: dob
          - name: sex_code
          - name: email
        access:
          metadata_scope: social_registry:metadata
          aggregate_scope: social_registry:aggregate
          read_scope: social_registry:rows
        api:
          default_limit: 100
          max_limit: 1000
        publicschema:
{publicschema_block}
"#
    );
    std::fs::write(&config_path, body).expect("write config");
    config::load(&config_path).expect("config loads")
}

fn ind_1_source_record() -> Value {
    json!({
        "id": "ind-1",
        "first_name": "  Amina ",
        "last_name": " Diallo  ",
        "dob": "1988-03-15",
        "sex_code": "F",
        "email": "AMINA@example.gov",
    })
}

fn register_individuals(ctx: &SessionContext, ingest_version: Ulid) {
    let schema = Arc::new(Schema::new(vec![
        Field::new("individual_id", DataType::Utf8, false),
        Field::new("first_name", DataType::Utf8, false),
        Field::new("last_name", DataType::Utf8, false),
        Field::new("dob", DataType::Utf8, false),
        Field::new("sex_code", DataType::Utf8, false),
        Field::new("email", DataType::Utf8, true),
    ]));
    let batch = RecordBatch::try_new(
        Arc::clone(&schema),
        vec![
            Arc::new(StringArray::from(vec!["ind-1"])),
            Arc::new(StringArray::from(vec!["  Amina "])),
            Arc::new(StringArray::from(vec![" Diallo  "])),
            Arc::new(StringArray::from(vec!["1988-03-15"])),
            Arc::new(StringArray::from(vec!["F"])),
            Arc::new(StringArray::from(vec!["AMINA@example.gov"])),
        ],
    )
    .expect("batch");
    let table = MemTable::try_new(schema, vec![vec![batch]]).expect("mem table");
    register_versioned_table(
        ctx,
        table_name(
            &id::<DatasetId>("social_registry"),
            &id::<ResourceId>("individuals_table"),
        ),
        ingest_version,
        Arc::new(table),
    )
    .expect("register table");
}

fn audit_record_for(sink: &InMemorySink, path: &str) -> Value {
    let lines = sink.snapshot();
    let line = lines
        .iter()
        .rev()
        .find(|line| {
            serde_json::from_str::<Value>(line)
                .ok()
                .and_then(|value| {
                    value["record"]["path"]
                        .as_str()
                        .map(|record_path| record_path == path)
                })
                .unwrap_or(false)
        })
        .unwrap_or_else(|| panic!("no audit record for path {path}; got {lines:?}"));
    let envelope: Value = serde_json::from_str(line).expect("audit envelope JSON");
    envelope["record"].clone()
}

#[test]
fn publicschema_registry_fails_when_mapping_file_is_missing() {
    let tmp = TempDir::new().expect("tempdir");
    let missing_mapping = tmp.path().join("missing.publicschema.yaml");
    let cfg = load_config_with_publicschema_block(
        &tmp,
        &format!(
            r#"          target: Person
          mapping_path: "{}"
"#,
            missing_mapping.display()
        ),
    );

    let err = build_publicschema_registry(&cfg).expect_err("missing mapping must fail startup");
    assert_eq!(err.code(), "config.validation_error");
}

#[test]
fn publicschema_registry_fails_when_mapping_does_not_compile() {
    let tmp = TempDir::new().expect("tempdir");
    let mapping_path = tmp.path().join("invalid.publicschema.yaml");
    std::fs::write(&mapping_path, "version: \"0.2\"\nproperty_mappings: [").expect("write mapping");
    let cfg = load_config_with_publicschema_block(
        &tmp,
        &format!(
            r#"          target: Person
          mapping_path: "{}"
"#,
            mapping_path.display()
        ),
    );

    let err = build_publicschema_registry(&cfg).expect_err("invalid mapping must fail startup");
    assert_eq!(err.code(), "config.validation_error");
}

#[test]
fn publicschema_registry_fails_when_validation_schema_file_is_missing() {
    let tmp = TempDir::new().expect("tempdir");
    let mapping_path = tmp.path().join("individual-person.publicschema.yaml");
    let missing_schema_path = tmp.path().join("missing-person.schema.json");
    std::fs::write(&mapping_path, PERSON_MAPPING).expect("write mapping");
    let cfg = load_config_with_publicschema_block(
        &tmp,
        &format!(
            r#"          target: Person
          mapping_path: "{}"
          schema_validation_path: "{}"
"#,
            mapping_path.display(),
            missing_schema_path.display()
        ),
    );

    let err = build_publicschema_registry(&cfg).expect_err("missing schema must fail startup");
    assert_eq!(err.code(), "config.validation_error");
}

#[test]
fn publicschema_registry_exposes_default_and_overridden_vc_profile_values() {
    let tmp = TempDir::new().expect("tempdir");
    let mapping_path = tmp.path().join("individual-person.publicschema.yaml");
    std::fs::write(&mapping_path, PERSON_MAPPING).expect("write mapping");
    let cfg = load_config_with_publicschema_block(
        &tmp,
        &format!(
            r#"          target: Person
          mapping_path: "{}"
          context_url: https://example.org/ctx/person.jsonld
          schema_url: https://example.org/schemas/person.json
          credential_type: ExamplePerson
"#,
            mapping_path.display()
        ),
    );
    let registry = build_publicschema_registry(&cfg)
        .expect("registry builds")
        .expect("profile present");

    let mapped = registry
        .mapped_entity_credential(
            "social_registry",
            "individual",
            IND_1_SUBJECT_URI,
            ind_1_source_record(),
        )
        .expect("mapping succeeds")
        .expect("mapped credential present");

    assert_eq!(mapped.subject_uri, IND_1_SUBJECT_URI);
    assert_eq!(mapped.credential_subject["id"], IND_1_SUBJECT_URI);
    assert_eq!(mapped.context_url, "https://example.org/ctx/person.jsonld");
    assert_eq!(mapped.schema_url, "https://example.org/schemas/person.json");
    assert_eq!(mapped.credential_type, "ExamplePerson");
}

#[test]
fn publicschema_runtime_schema_validation_rejects_invalid_mapped_subject() {
    let tmp = TempDir::new().expect("tempdir");
    let mapping_path = tmp
        .path()
        .join("individual-person-invalid-gender.publicschema.yaml");
    std::fs::write(
        &mapping_path,
        PERSON_MAPPING.replace("\"female\"", "\"invalid_gender\""),
    )
    .expect("write mapping");
    let cfg = load_config_with_publicschema_block(
        &tmp,
        &format!(
            r#"          target: Person
          mapping_path: "{}"
          schema_validation_path: "{}"
"#,
            mapping_path.display(),
            person_schema_path().display()
        ),
    );
    let registry = build_publicschema_registry(&cfg)
        .expect("registry builds")
        .expect("profile present");

    let err = registry
        .mapped_entity_credential(
            "social_registry",
            "individual",
            IND_1_SUBJECT_URI,
            ind_1_source_record(),
        )
        .expect_err("invalid mapped gender must fail schema validation");

    assert_eq!(err.to_string(), "publicschema schema validation failed");
}

#[test]
fn publicschema_runtime_rejects_subject_id_that_does_not_match_gateway_uri() {
    let tmp = TempDir::new().expect("tempdir");
    let mapping_path = tmp
        .path()
        .join("individual-person-wrong-subject.publicschema.yaml");
    std::fs::write(
        &mapping_path,
        PERSON_MAPPING.replace(
            "ctx.subject_uri",
            "'\"https://wrong.example/individual/ind-1\"'",
        ),
    )
    .expect("write mapping");
    let cfg = load_config_with_publicschema_block(
        &tmp,
        &format!(
            r#"          target: Person
          mapping_path: "{}"
          schema_validation_path: "{}"
"#,
            mapping_path.display(),
            person_schema_path().display()
        ),
    );
    let registry = build_publicschema_registry(&cfg)
        .expect("registry builds")
        .expect("profile present");

    let err = registry
        .mapped_entity_credential(
            "social_registry",
            "individual",
            IND_1_SUBJECT_URI,
            ind_1_source_record(),
        )
        .expect_err("wrong mapped id must fail before signing");

    assert_eq!(err.to_string(), "publicschema subject id mismatch");
}

#[tokio::test]
async fn credential_profile_override_still_emits_provenance_audit_for_publicschema_person() {
    let tmp = TempDir::new().expect("tempdir");
    let cfg = Arc::new(write_config(&tmp));
    let publicschema = Arc::new(
        build_publicschema_registry(&cfg)
            .expect("publicschema registry builds")
            .expect("publicschema mapping present"),
    );
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
    let (state, verifying_key) = build_provenance_state("PUBLICSCHEMA_FEATURE_JWK");
    let audit_sink = InMemorySink::new();
    let sink_arc: Arc<AuditPipeline> = AuditPipeline::from_sink(audit_sink.clone());

    let router = entity_router::<()>()
        .layer(Extension(query))
        .layer(Extension(registry))
        .layer(Extension(Arc::clone(&cfg)))
        .layer(Extension(readiness))
        .layer(Extension(Arc::new(CursorSigner::new_random())))
        .layer(Extension(principal(&["social_registry:rows"])))
        .layer(Extension(Arc::clone(&publicschema)))
        .layer(Extension(state));
    let server = TestServer::new(with_audit(router, sink_arc));

    let plain = server
        .get("/datasets/social_registry/individual/ind-1")
        .await;
    plain.assert_status_ok();
    let plain_body: Value = plain.json();
    assert_eq!(plain_body["id"], "ind-1");
    assert_eq!(plain_body["first_name"], "  Amina ");
    let mapped_plain = publicschema
        .mapped_entity_credential(
            "social_registry",
            "individual",
            IND_1_SUBJECT_URI,
            plain_body.clone(),
        )
        .unwrap_or_else(|err| panic!("plain entity record maps from {plain_body}: {err:?}"))
        .expect("publicschema profile present");
    assert_eq!(mapped_plain.credential_type, "Person");

    let resp = server
        .get("/datasets/social_registry/individual/ind-1")
        .add_header("accept", "application/vc+jwt")
        .await;
    if resp.status_code() != StatusCode::OK {
        panic!(
            "expected PublicSchema VC response to succeed, got {} with body {}",
            resp.status_code(),
            String::from_utf8_lossy(resp.as_bytes()),
        );
    }
    assert_eq!(
        resp.header("content-type").to_str().unwrap_or(""),
        "application/vc+jwt"
    );
    let body = String::from_utf8(resp.as_bytes().to_vec()).expect("body utf8");
    assert_node_verifier_accepts_publicschema_person_vc(&tmp, &body, &verifying_key);
    let payload = decode_and_verify_payload(&body, &verifying_key);

    assert_eq!(payload["type"][1], "Person");
    assert_eq!(
        payload["@context"][1],
        "https://publicschema.org/ctx/draft.jsonld"
    );
    assert_eq!(
        payload["credentialSchema"]["id"],
        "https://publicschema.org/schemas/Person.schema.json"
    );
    assert_eq!(
        payload["sub"],
        "https://gw.example/datasets/social_registry/individual/ind-1"
    );
    assert_eq!(
        payload["credentialSubject"],
        json!({
            "id": "https://gw.example/datasets/social_registry/individual/ind-1",
            "type": "Person",
            "given_name": "Amina",
            "family_name": "Diallo",
            "date_of_birth": "1988-03-15",
            "gender": "female",
            "email_address": "amina@example.gov",
        })
    );

    let person_schema: Value = serde_json::from_str(PERSON_SCHEMA).expect("Person schema JSON");
    let compiled_schema =
        jsonschema::JSONSchema::compile(&person_schema).expect("Person schema compiles");
    if let Err(errors) = compiled_schema.validate(&payload["credentialSubject"]) {
        let messages: Vec<String> = errors.map(|error| error.to_string()).collect();
        panic!("mapped PublicSchema Person subject must validate: {messages:?}");
    }

    let record = audit_record_for(&audit_sink, "/datasets/social_registry/individual/{id}");
    assert_eq!(record["provenance"]["claim_type"], "Person");
    assert_eq!(
        record["provenance"]["subject"],
        "https://gw.example/datasets/social_registry/individual/ind-1"
    );
}
