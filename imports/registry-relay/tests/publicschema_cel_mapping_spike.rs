// SPDX-License-Identifier: Apache-2.0
//! Spike: prove cel-mapper-core can produce a PublicSchema-shaped
//! credentialSubject that registry-relay can validate and sign.

use std::env;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use cel_mapper_core::{
    MappingRuntime, PrivacyMode, PublicSchemaEvaluateOptions, PublicSchemaEvaluationInput,
    RuntimeOptions,
};
use ed25519_dalek::{SigningKey, SECRET_KEY_LENGTH};
use rand_core::OsRng;
use registry_relay::config::{ProvenanceAlgorithm, SoftwareSignerConfig};
use registry_relay::provenance::jwt_vc::{encode, ClaimType, VcEnvelopeInputs};
use registry_relay::provenance::signers::software::SoftwareSigner;
use serde_json::{json, Value};
use time::OffsetDateTime;

const PERSON_SCHEMA: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../publicschema.org/dist/schemas/Person.schema.json"
));

fn export_jwk(env_name: &str) {
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
}

#[test]
fn cel_mapping_can_prepare_publicschema_person_subject_for_vc_signing() {
    let mapping = r#"
version: "0.2"
id: registry-relay-individual-to-publicschema-person
source: registry-relay.individual
target: publicschema.Person
runtime:
  bindings: publicschema-v1
property_mappings:
  - id: subject-id
    source: /individual_id
    target: /id
    required: true
    formula:
      to_target:
        expression: '"https://gw.example/datasets/social_registry/individual/" + source'
  - id: type
    source: /individual_id
    target: /type
    formula:
      to_target:
        expression: '"Person"'
  - id: given-name
    source: /first_name
    target: /given_name
    required: true
    formula:
      to_target:
        expression: text_normalize_space(source)
  - id: family-name
    source: /last_name
    target: /family_name
    required: true
    formula:
      to_target:
        expression: text_normalize_space(source)
  - id: date-of-birth
    source: /dob
    target: /date_of_birth
    required: true
  - id: gender
    source: /sex_code
    target: /gender
    required: true
    value_mappings:
      - source_value: M
        target_value: male
      - source_value: F
        target_value: female
      - source_value: X
        target_value: other
  - id: email
    source: /email
    target: /email_address
    formula:
      to_target:
        expression: email_normalize(source)
"#;

    let rt = MappingRuntime::new(RuntimeOptions::default());
    let compiled = rt
        .compile_publicschema_mapping(mapping, Default::default())
        .expect("PublicSchema mapping compiles at startup");

    let transform = rt.evaluate_publicschema_mapping(
        &compiled,
        PublicSchemaEvaluationInput {
            source: json!({
                "individual_id": "ind-1",
                "first_name": "  Amina ",
                "last_name": " Diallo  ",
                "dob": "1988-03-15",
                "sex_code": "F",
                "email": "AMINA@example.gov",
            }),
            context: json!({}),
            options: PublicSchemaEvaluateOptions {
                errors_mode: Some("collect".to_string()),
                privacy: PrivacyMode::Authoring,
                ..Default::default()
            },
        },
    );

    assert!(transform.ok, "transform errors: {:?}", transform.errors);
    assert!(transform.warnings.is_empty(), "{:?}", transform.warnings);
    assert_eq!(
        transform.output,
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
    assert!(
        transform.log.iter().all(|entry| entry.status == "applied"),
        "{:?}",
        transform.log
    );

    let person_schema: Value = serde_json::from_str(PERSON_SCHEMA).expect("Person schema JSON");
    let compiled_schema = jsonschema::JSONSchema::compile(&person_schema)
        .expect("PublicSchema Person schema compiles");
    if let Err(errors) = compiled_schema.validate(&transform.output) {
        let messages: Vec<String> = errors.map(|error| error.to_string()).collect();
        panic!("mapped PublicSchema Person subject must validate: {messages:?}");
    };

    let env_name = "PUBLICSCHEMA_CEL_MAPPING_SPIKE_JWK";
    export_jwk(env_name);
    let signer = SoftwareSigner::from_config(
        &SoftwareSignerConfig {
            jwk_env: env_name.to_string(),
            signing_algorithm: ProvenanceAlgorithm::EdDSA,
        },
        "did:web:gw.example#issuance".to_string(),
    )
    .expect("signer builds");

    let now = OffsetDateTime::from_unix_timestamp(1_700_000_000).expect("fixed timestamp");
    let signed = encode(
        &signer,
        VcEnvelopeInputs {
            claim_type: ClaimType::EntityRecord,
            issuer_did: "did:web:gw.example".to_string(),
            verification_method_id: "did:web:gw.example#issuance".to_string(),
            subject_uri: transform.output["id"]
                .as_str()
                .expect("mapped subject id")
                .to_string(),
            credential_subject: transform.output,
            provenance_context_url: "https://publicschema.org/ctx/draft.jsonld".to_string(),
            credential_schema_url: "https://publicschema.org/schemas/Person.schema.json"
                .to_string(),
            issued_at: now,
            valid_until: now + time::Duration::minutes(5),
        },
    )
    .expect("mapped PublicSchema subject signs as a VC");

    assert_eq!(signed.claim_type, ClaimType::EntityRecord);
    assert_eq!(
        signed.subject_uri,
        "https://gw.example/datasets/social_registry/individual/ind-1"
    );
    assert_eq!(signed.verification_method_id, "did:web:gw.example#issuance");
    assert_eq!(signed.compact_jws.split('.').count(), 3);
}
