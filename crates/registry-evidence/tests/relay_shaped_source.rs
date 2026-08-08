//! Evidence-over-Relay composition: one full signed Evidence assertion is
//! evaluated over a mock HTTP source whose wire shape mirrors a Registry
//! Relay protected read API, authenticated with OAuth client credentials.
//!
//! The mock mirrors the Relay wire shape by hand: the templated protected
//! read path and the minimal single-record JSON response body of
//! `GET /v1/datasets/{dataset_id}/entities/{entity}/records/{id}` in
//! `crates/registry-relay/openapi/registry-relay.openapi.json`. Evidence
//! proves the composition without importing or depending on any Relay code,
//! per the Evidence product boundary rules, so no Relay crate, type, or
//! fixture appears here and the record content stays synthetic and
//! domain-neutral.

#![cfg(unix)]

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use chrono::Utc;
use registry_evidence::bundle::Bundle;
use registry_evidence::config::{PreparationChannelPolicy, PreparationLimits, SourceConfig};
use registry_evidence::kernel::{
    EvidenceConstruction, EvidenceScope, OfflineKernel, ValueProjection,
};
use registry_evidence::model::{LookupResult, PublicValue, SelectorValue, SubjectBinding};
use registry_evidence::rhai_runtime::{
    RequestPartRequirement, RequestParts, RequestPartsBounds, RequestPartsLimits, RhaiRuntime,
    MAXIMUM_ARRAY_ITEMS, MAXIMUM_JSON_BODY_DEPTH, MAXIMUM_QUERY_NAME_BYTES, MAXIMUM_QUERY_PAIRS,
    MAXIMUM_QUERY_VALUE_BYTES, MAXIMUM_REQUEST_PARTS_BYTES, MAXIMUM_STRING_BYTES,
};
use registry_evidence::secrets::{SecretProvider, SecretResolver};
use registry_evidence::signing::{jwks_document, EvidenceSigner};
use registry_evidence::source::{PreparedSourceRequest, ResolvedSourceSelector, SourceExecutor};
use registry_evidence::verifier::{verify_flattened_jws, EvidenceVerificationPolicy};
use registry_platform_crypto::{LocalJwkSigner, PrivateJwk};
use serde_json::json;
use tempfile::TempDir;
use wiremock::matchers::{body_string_contains, header, method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// One prepared HTTP request, in the shape the executor consumes.
fn prepared_http_request(parts: &RequestParts) -> PreparedSourceRequest {
    PreparedSourceRequest::Http(parts.clone())
}

/// The Relay-shaped protected read for one synthetic record: the templated
/// `/v1/datasets/{dataset_id}/entities/{entity}/records/{id}` path with
/// domain-neutral dataset and entity segments and the subject's record key.
const RECORD_PATH: &str = "/v1/datasets/synthetic-units/entities/unit-record/records/REC-0001";
/// Relay requires a `Data-Purpose` header on entity record reads; the
/// deployment pins it as a reviewed fixed header.
const DATA_PURPOSE: &str = "https://relying.invalid/purpose/fixture-routing";
/// Raw record material from the mirrored Relay response body. None of it may
/// reach the signed assertion payload.
const RAW_FIELD_NAME_CANARY: &str = "area_geometry";
const RAW_FIELD_VALUE_CANARY: &str = "SYNTHETIC-AREA-GEOMETRY-CANARY";
const RECORD_KEY: &str = "REC-0001";
const RAW_REGION_CODE: &str = "R-101";

const AUDIENCE: &str = "https://relying.invalid/residence-procedure";
const BINDING_KEY: &[u8] = b"relay-composition-binding-key-32-bytes-minimum";
const REQUIREMENT: &str = "urn:example:fixture:requirement:residence-region:v1";

/// The reviewed bounded request preparation: the Relay read is a completely
/// fixed request, so both dynamic channels stay empty.
const PREPARE_SCRIPT: &str = "fn prepare(selectors, parameters) { #{query: [], body: ()} }";

/// The reviewed extraction over the Rust-projected response: only the
/// projected `region` field is visible here, and it becomes the one declared
/// fact for the residence-region acceptance derivation.
const EXTRACT_SCRIPT: &str = r#"
fn extract(source_response, parameters) {
    let region_code = get_path(source_response, "/region");
    if is_missing(region_code) { return #{outcome: "no_match"}; }
    #{outcome: "match", facts: #{official_residence_code: region_code}}
}
"#;

/// An Evidence source declared the way a deployment bundle would declare it:
/// oauth2-client-credentials against the mock token endpoint and a fixed GET
/// against the Relay-shaped record path.
fn relay_shaped_source(base_url: &str, token_endpoint: &str) -> SourceConfig {
    serde_json::from_value(json!({
        "transport": "http-json",
        "baseUrl": base_url,
        "posture": "field-projected",
        "authentication": {
            "kind": "oauth2-client-credentials",
            "tokenEndpoint": token_endpoint,
            "clientIdRef": "secret:file/relay-client-id",
            "clientSecretRef": "secret:file/relay-client-secret",
            "scope": "registry.read",
            "credentialPlacement": "form-body",
            "maximumCacheSeconds": 60
        },
        "request": {
            "method": "GET",
            "pathTemplate": "/v1/datasets/synthetic-units/entities/unit-record/records/{record}",
            "pathBindings": {
                "record": {
                    "from": "selector",
                    "role": "subject",
                    "profile": "residence-record-v1",
                    "field": "record_reference"
                }
            },
            "fixedHeaders": [
                {"name": "Accept", "value": "application/json"},
                {"name": "Data-Purpose", "value": DATA_PURPOSE}
            ],
            "selectorInputs": [{
                "role": "subject",
                "alternatives": [
                    {"profile": "residence-record-v1", "fields": ["record_reference"]}
                ]
            }],
            "prepareScript": "adapters/prepare.rhai",
            "adapterParameters": {},
            "adapterParametersSchema": "schemas/parameters.schema.yaml",
            "preparationLimits": {"query": "forbidden", "jsonBody": "forbidden"},
            "projection": ["/region"],
            "redirects": "deny",
            "timeoutMilliseconds": 1000,
            "maximumResponseBytes": 65536,
            "concurrencyLimit": 4
        },
        "responseSchema": "schemas/response.schema.yaml",
        "extractScript": "adapters/extract.rhai",
        "factSchema": "schemas/facts.schema.yaml"
    }))
    .expect("Relay-shaped source config deserializes")
}

fn resolver(entries: &[(&str, &str)]) -> (TempDir, Arc<SecretResolver>) {
    let root = tempfile::tempdir().expect("temporary secret root");
    for (name, value) in entries {
        let path = root.path().join(name);
        fs::write(&path, value).expect("write synthetic secret");
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("protect secret");
    }
    let resolver = SecretResolver::new([SecretProvider::File], root.path())
        .map(Arc::new)
        .expect("resolver builds");
    (root, resolver)
}

fn request_limits(config: &PreparationLimits) -> RequestPartsLimits {
    fn channel(policy: PreparationChannelPolicy) -> RequestPartRequirement {
        match policy {
            PreparationChannelPolicy::Required => RequestPartRequirement::Required,
            PreparationChannelPolicy::Allowed => RequestPartRequirement::Optional,
            PreparationChannelPolicy::Forbidden => RequestPartRequirement::Forbidden,
        }
    }

    fn configured(value: Option<u64>, fallback: usize) -> usize {
        value
            .map(|value| usize::try_from(value).expect("configured limit fits usize"))
            .unwrap_or(fallback)
    }

    RequestPartsLimits::new(
        channel(config.query),
        channel(config.json_body),
        RequestPartsBounds {
            maximum_query_pairs: configured(config.maximum_query_pairs, MAXIMUM_QUERY_PAIRS),
            maximum_query_name_bytes: configured(
                config.maximum_query_name_bytes,
                MAXIMUM_QUERY_NAME_BYTES,
            ),
            maximum_query_value_bytes: configured(
                config.maximum_query_value_bytes,
                MAXIMUM_QUERY_VALUE_BYTES,
            ),
            maximum_json_depth: configured(config.maximum_json_depth, MAXIMUM_JSON_BODY_DEPTH),
            maximum_collection_items: configured(
                config.maximum_collection_items,
                MAXIMUM_ARRAY_ITEMS,
            ),
            maximum_string_bytes: configured(config.maximum_string_bytes, MAXIMUM_STRING_BYTES),
            maximum_normalized_bytes: configured(
                config.maximum_normalized_bytes,
                MAXIMUM_REQUEST_PARTS_BYTES,
            ),
        },
    )
    .expect("fixture preparation limits satisfy the production ABI")
}

fn encoded_parameters(bytes: &[u8]) -> Vec<(String, String)> {
    url::form_urlencoded::parse(bytes)
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect()
}

fn contains_parameter(parameters: &[(String, String)], name: &str, value: &str) -> bool {
    parameters
        .iter()
        .any(|(actual_name, actual_value)| actual_name == name && actual_value == value)
}

fn copy_fixture_tree(source: &Path, target: &Path) {
    fs::create_dir(target).expect("fixture directory is copied");
    for entry in fs::read_dir(source).expect("fixture directory is readable") {
        let entry = entry.expect("fixture entry is readable");
        let destination = target.join(entry.file_name());
        if entry
            .file_type()
            .expect("fixture entry type is readable")
            .is_dir()
        {
            copy_fixture_tree(&entry.path(), &destination);
        } else {
            fs::copy(entry.path(), destination).expect("fixture file is copied");
        }
    }
}

fn make_fixture_bundle_read_only(path: &Path) {
    for entry in fs::read_dir(path).expect("fixture bundle is readable") {
        let entry = entry.expect("fixture bundle entry is readable");
        let child = entry.path();
        if entry
            .file_type()
            .expect("fixture bundle entry type is readable")
            .is_dir()
        {
            make_fixture_bundle_read_only(&child);
        } else {
            fs::set_permissions(child, fs::Permissions::from_mode(0o444))
                .expect("fixture bundle file becomes read-only");
        }
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o555))
        .expect("fixture bundle directory becomes read-only");
}

async fn fixture_signer() -> EvidenceSigner {
    const KEY_ID: &str = "_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo";
    const PRIVATE_JWK: &str = r#"{"kty":"EC","crv":"P-256","d":"MInq88dvxx-e1-MEfmdes4I6Gt2QbsKoEmYyk2j0Oj4","x":"3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4","y":"GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU","alg":"ES256","kid":"_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo"}"#;
    let private = PrivateJwk::parse(PRIVATE_JWK).expect("fixture key parses");
    let provider = Arc::new(LocalJwkSigner::new(private).expect("fixture signer builds"));
    EvidenceSigner::initialize(provider, KEY_ID)
        .await
        .expect("fixture signer initializes")
}

#[tokio::test]
async fn a_relay_shaped_protected_read_backs_a_full_signed_minimum_disclosure_assertion() {
    // A mock OAuth token endpoint stands in for the Relay deployment's
    // authorization server: it only answers a client-credentials grant and
    // issues one fresh bearer token.
    let token_server = MockServer::start().await;
    let records_server = MockServer::start().await;
    let client_id = format!("client-id-{}", ulid::Ulid::new());
    let client_secret = format!("client-secret-{}", ulid::Ulid::new());
    let access_token = format!("access-token-{}", ulid::Ulid::new());
    Mock::given(method("POST"))
        .and(path("/oauth/token"))
        .and(body_string_contains("grant_type=client_credentials"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": access_token.clone(),
            "token_type": "Bearer",
            "expires_in": 120,
            "scope": "registry.read"
        })))
        .expect(1)
        .mount(&token_server)
        .await;

    // The record endpoint mirrors the Relay wire shape by hand (hardcoded
    // JSON, no Relay code): the single-record body follows the OpenAPI entity
    // example shape of `id`, one codelist field, and one extra raw field.
    // Only a request carrying the exact issued bearer, the pinned Accept
    // header, and Relay's required Data-Purpose header is answered.
    Mock::given(method("GET"))
        .and(path(RECORD_PATH))
        .and(header("authorization", format!("Bearer {access_token}")))
        .and(header("accept", "application/json"))
        .and(header("data-purpose", DATA_PURPOSE))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "id": RECORD_KEY,
            "region": RAW_REGION_CODE,
            "area_geometry": RAW_FIELD_VALUE_CANARY
        })))
        .with_priority(1)
        .expect(1)
        .mount(&records_server)
        .await;
    // Any request that misses the exact bearer is rejected the way a Relay
    // deployment rejects it, and must never happen.
    Mock::given(method("GET"))
        .and(path(RECORD_PATH))
        .respond_with(ResponseTemplate::new(401).set_body_raw(
            r#"{"type":"about:blank","title":"Unauthorized","status":401}"#,
            "application/problem+json",
        ))
        .with_priority(10)
        .expect(0)
        .mount(&records_server)
        .await;

    // Deployment-shaped inputs: file-provider secrets and the declared source.
    let (_secret_root, secrets) = resolver(&[
        ("relay-client-id", client_id.as_str()),
        ("relay-client-secret", client_secret.as_str()),
    ]);
    let source = relay_shaped_source(
        &records_server.uri(),
        &format!("{}/oauth/token", token_server.uri()),
    );
    let SourceConfig::HttpJson {
        request: source_request,
        ..
    } = &source
    else {
        panic!("the declared source does not use the http-json transport");
    };

    // Bounded request preparation through the production Rhai runtime.
    let runtime = RhaiRuntime::new();
    let preparation = runtime
        .compile_preparation(PREPARE_SCRIPT)
        .expect("preparation script compiles");
    let extraction = runtime
        .compile_extraction(EXTRACT_SCRIPT)
        .expect("extraction script compiles");
    let parameters =
        serde_json::to_value(source.adapter_parameters()).expect("adapter parameters serialize");
    let script_selectors = json!({
        "subject": {
            "profile": "residence-record-v1",
            "values": {"record_reference": RECORD_KEY}
        }
    });
    let prepared = runtime
        .prepare(
            &preparation,
            &script_selectors,
            &parameters,
            &request_limits(&source_request.preparation_limits),
        )
        .expect("fixed Relay read preparation succeeds");

    // Production transport materialization pins the exact Relay-shaped read.
    let transport_selectors = vec![ResolvedSourceSelector {
        role: "subject".into(),
        profile: "residence-record-v1".into(),
        values: BTreeMap::from([(
            "record_reference".into(),
            SelectorValue::String(RECORD_KEY.into()),
        )]),
    }];
    let executor = SourceExecutor::new(&source, secrets).expect("Relay-shaped source compiles");
    let materialized = executor
        .materialize_request(&transport_selectors, &prepared_http_request(&prepared))
        .expect("Relay-shaped request materializes");
    assert_eq!(materialized.path(), Some(RECORD_PATH));
    assert_eq!(materialized.query(), None);
    assert_eq!(materialized.body(), None);

    // One end-to-end source execution: token acquisition, the authenticated
    // record read, and the Rust projection boundary.
    let projected = executor
        .execute(
            &transport_selectors,
            &prepared_http_request(&prepared),
            Utc::now(),
        )
        .await
        .expect("Relay-shaped source read succeeds");
    assert_eq!(projected, json!({"region": RAW_REGION_CODE}));
    let projected_text = serde_json::to_string(&projected).expect("projected response serializes");
    for stripped in [RAW_FIELD_NAME_CANARY, RAW_FIELD_VALUE_CANARY, RECORD_KEY] {
        assert!(
            !projected_text.contains(stripped),
            "projection let raw record material past the source boundary"
        );
    }
    let response_schema = jsonschema::JSONSchema::compile(&json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["region"],
        "properties": {"region": {"type": "string", "minLength": 1, "maxLength": 32}}
    }))
    .expect("response schema compiles");
    assert!(
        response_schema.is_valid(&projected),
        "projected Relay-shaped response is outside the declared response schema"
    );

    // Reviewed extraction produces exactly the one declared fact.
    let fact_schema = jsonschema::JSONSchema::compile(&json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["official_residence_code"],
        "properties": {
            "official_residence_code": {"type": "string", "minLength": 1, "maxLength": 32}
        }
    }))
    .expect("fact schema compiles");
    let facts = match runtime
        .extract(&extraction, &projected, &parameters, &fact_schema)
        .expect("Relay-shaped response extracts")
    {
        LookupResult::Match(facts) => facts,
        _ => panic!("Relay-shaped match returned a non-match outcome"),
    };
    assert_eq!(
        serde_json::to_value(&facts).expect("facts serialize"),
        json!({"official_residence_code": RAW_REGION_CODE})
    );

    // The immutable residence-region acceptance bundle finishes the full
    // path: real derivation, output gate, Evidence construction, signing,
    // and verification against the deployment's public JWKS.
    let acceptance_copy = tempfile::tempdir().expect("temporary acceptance bundle root");
    let acceptance_root = acceptance_copy.path().join("residence-region");
    copy_fixture_tree(
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/evidence/fixtures/acceptance/residence-region"),
        &acceptance_root,
    );
    make_fixture_bundle_read_only(&acceptance_root);
    let kernel = OfflineKernel::compile(Arc::new(
        Bundle::load(&acceptance_root).expect("immutable residence acceptance bundle loads"),
    ))
    .expect("residence acceptance kernel compiles");
    let observed_at = "2026-08-02T00:00:00Z"
        .parse()
        .expect("fixed observation time parses");
    let values = kernel
        .derive_and_validate(
            REQUIREMENT,
            &facts,
            observed_at,
            ValueProjection {
                scope: EvidenceScope::AudienceScoped {
                    audience: AUDIENCE,
                    request_nonce: registry_evidence::model::OFFLINE_EVALUATION_REQUEST_NONCE,
                },
                binding_key: BINDING_KEY,
                binding_key_version: 1,
            },
        )
        .expect("residence derivation and immutable output gate succeed");
    assert_eq!(values.as_slice().len(), 1);
    assert_eq!(
        values.as_slice()[0].provides_value_for,
        "urn:example:fixture:concept:residence-region"
    );
    assert_eq!(
        values.as_slice()[0].value,
        PublicValue::String("REGION-NORTH".to_owned())
    );
    let evidence = kernel
        .construct_evidence(
            REQUIREMENT,
            values,
            EvidenceConstruction {
                evidence_id: "urn:ulid:01J4BRXQ0ZZZZZZZZZZZZZZZZZ",
                purpose: "fixture-routing",
                scope: EvidenceScope::AudienceScoped {
                    audience: AUDIENCE,
                    request_nonce: registry_evidence::model::OFFLINE_EVALUATION_REQUEST_NONCE,
                },
                issued_at: observed_at,
                observed_at,
                subjects: vec![SubjectBinding {
                    role: "subject".to_owned(),
                    binding: format!("urn:evidence:subject:v1_{}", "A".repeat(43)),
                }],
            },
        )
        .expect("residence Evidence constructs");
    let signer = fixture_signer().await;
    let jws = signer
        .sign_json(&evidence)
        .await
        .expect("residence Evidence signs");

    // (d) The assertion payload carries only the derived answer: no raw
    // record field name or value from the mirrored Relay response body.
    let payload = String::from_utf8(
        URL_SAFE_NO_PAD
            .decode(&jws.payload)
            .expect("flattened JWS payload decodes"),
    )
    .expect("assertion payload is UTF-8 JSON");
    assert!(
        payload.contains("REGION-NORTH"),
        "the derived controlled code is disclosed"
    );
    for canary in [
        RAW_FIELD_NAME_CANARY,
        RAW_FIELD_VALUE_CANARY,
        RECORD_KEY,
        RAW_REGION_CODE,
    ] {
        assert!(
            !payload.contains(canary),
            "raw Relay record material reached the assertion payload: {canary}"
        );
    }

    // (c) The response is a signed flattened JWS that verifies against the
    // deployment's public JWKS under the exact relying policy.
    let jwks = jwks_document(signer.public_jwk(), []).expect("deployment JWKS publishes");
    let serialized = serde_json::to_vec(&jws).expect("flattened JWS serializes");
    let mut policy = EvidenceVerificationPolicy::from_accepted_transaction(
        &evidence,
        registry_evidence::model::OFFLINE_EVALUATION_REQUEST_NONCE,
        31_536_000,
        observed_at,
        0,
    )
    .expect("the fixture policy states bounds the contract allows");
    policy.issued_by = "urn:example:fixture:issuer:authority".to_owned();
    policy.provided_by = "urn:example:fixture:provider:evidence".to_owned();
    policy.requirement = REQUIREMENT.to_owned();
    policy.evidence_type = "urn:example:fixture:evidence-type:residence-region:v1".to_owned();
    policy.purpose = "fixture-routing".to_owned();
    policy.audience = AUDIENCE.to_owned();
    policy.configuration_revision = kernel
        .bundle()
        .configuration_revision(REQUIREMENT)
        .expect("the requirement has a configuration revision")
        .to_owned();
    let verified = verify_flattened_jws(&serialized, &jwks, &policy)
        .expect("signed Evidence verifies against the deployment JWKS");
    assert_eq!(verified.supported_values.len(), 1);
    assert_eq!(
        verified.supported_values[0].value,
        PublicValue::String("REGION-NORTH".to_owned())
    );

    // (a) The token endpoint was called exactly once, with the closed
    // client-credentials form and no credential in the URL.
    let token_requests = token_server
        .received_requests()
        .await
        .expect("token request journal");
    assert_eq!(token_requests.len(), 1, "exact OAuth bootstrap count");
    assert!(
        token_requests[0].url.query().is_none(),
        "token URL carries no query"
    );
    let form = encoded_parameters(&token_requests[0].body);
    assert!(
        form.len() == 4
            && contains_parameter(&form, "grant_type", "client_credentials")
            && contains_parameter(&form, "scope", "registry.read")
            && contains_parameter(&form, "client_id", &client_id)
            && contains_parameter(&form, "client_secret", &client_secret),
        "token request body is the exact reviewed client-credentials shape"
    );

    // (b) The records endpoint saw exactly one read carrying the issued
    // bearer and the pinned reviewed headers.
    let record_requests = records_server
        .received_requests()
        .await
        .expect("record request journal");
    assert_eq!(record_requests.len(), 1, "exact evidence-data count");
    let record_request = &record_requests[0];
    assert_eq!(record_request.method.as_str(), "GET");
    assert_eq!(record_request.url.path(), RECORD_PATH);
    assert!(record_request.url.query().is_none());
    assert!(record_request.body.is_empty());
    assert_eq!(
        record_request
            .headers
            .get("authorization")
            .and_then(|value| value.to_str().ok()),
        Some(format!("Bearer {access_token}").as_str()),
        "the record read carried the issued bearer"
    );
    assert_eq!(
        record_request
            .headers
            .get("data-purpose")
            .and_then(|value| value.to_str().ok()),
        Some(DATA_PURPOSE)
    );
}
