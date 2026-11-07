//! One full signed Evidence assertion over a synthetic protected registry HTTP read.
//!
//! The fixed path and cursor-paginated JSON response are ordinary source data.
//! OAuth client credentials authenticate the reviewed Adapter pack request;
//! bounded projection and lookup feed a minimum-disclosure assertion without a
//! dependency on another runtime.

#![cfg(unix)]

use std::collections::BTreeMap;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use registry_adapter_engine::evidence::{
    EvidenceAcquisitionIntent, EvidenceHookFuture, EvidenceHostHooks, EvidenceSendIntent,
    EvidenceSendMethod,
};
use registry_evidence::bundle::{evidence_package_limits, DeploymentInputs};
use registry_evidence::config::SelectorInput;
use registry_evidence::kernel::{
    EvidenceConstruction, EvidenceScope, OfflineKernel, ValueProjection,
};
use registry_evidence::model::{AssertionChannel, LookupResult, PublicValue, SubjectBinding};
use registry_evidence::pack_source::build_sources;
use registry_evidence::secrets::{SecretProvider, SecretResolver};
use registry_evidence::selector::{resolve_offline_fixture_authorization, ResolvedAuthorization};
use registry_evidence::signing::{jwks_document, EvidenceSigner};
use registry_evidence::verifier::{verify_flattened_jws, EvidenceVerificationPolicy};
use registry_platform_crypto::{LocalJwkSigner, PrivateJwk};
use serde_json::{json, Value};
use tempfile::TempDir;
use wiremock::matchers::{body_string_contains, header, method, path, query_param};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// The protected registry read for one synthetic record.
const RECORD_PATH: &str = "/v2/resources/residence-record/records";
/// Raw record material from the mirrored registry response body. None of it may
/// reach the signed assertion payload.
const RAW_FIELD_NAME_CANARY: &str = "area_geometry";
const RAW_FIELD_VALUE_CANARY: &str = "SYNTHETIC-AREA-GEOMETRY-CANARY";
const RECORD_KEY: &str = "REC-0001";
const RAW_REGION_CODE: &str = "R-101";

const AUDIENCE: &str = "https://relying.invalid/residence-procedure";
const BINDING_KEY: &[u8] = b"registry-composition-binding-key-32-bytes-minimum";
const REQUIREMENT: &str = "urn:gov:example:requirement:residence-region:v1";
const CONCEPT: &str = "urn:gov:example:concept:residence-region";
const EVIDENCE_TYPE: &str = "urn:gov:example:evidence-type:residence-region:v1";
const ISSUER: &str = "urn:gov:example:issuer:residence-authority";
const PROVIDER: &str = "urn:gov:example:evidence:residence";
const PURPOSE: &str = "residence-verification";

fn protected_read_root() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(
        "../../products/evidence/reference/request-adapter/deployment-projects/protected-read-evidence",
    )
}

fn resolver(entries: &[(&str, &str)]) -> (TempDir, Arc<SecretResolver>) {
    let root = tempfile::tempdir().expect("temporary secret root");
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700))
        .expect("protect synthetic secret root");
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
        if entry.file_name() == registry_platform_config::SUM_FILE
            || entry.file_name() == registry_platform_config::REVISION_FILE
        {
            continue;
        }
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

fn replace_once(document: String, old: &str, new: &str) -> String {
    assert_eq!(document.matches(old).count(), 1, "fixture marker is unique");
    document.replacen(old, new, 1)
}

fn refresh_package_envelope(root: &Path) {
    registry_platform_config::write_sum_file(
        root,
        None,
        &evidence_package_limits(),
        "evidencectl package",
    )
    .expect("copied package envelope is refreshed");
}

fn selector_value(resolved: &ResolvedAuthorization, inputs: &[SelectorInput]) -> Value {
    Value::Object(
        inputs
            .iter()
            .map(|input| {
                let subject = resolved
                    .subjects
                    .iter()
                    .find(|subject| subject.role == input.role)
                    .expect("derivation input role resolves");
                let alternative = input
                    .alternatives
                    .iter()
                    .find(|alternative| alternative.profile == subject.selector_profile)
                    .expect("derivation input profile resolves");
                let values = alternative
                    .fields
                    .iter()
                    .map(|name| {
                        let field = subject
                            .fields
                            .iter()
                            .find(|field| &field.name == name)
                            .expect("derivation input field resolves");
                        (name.clone(), field.value.as_json())
                    })
                    .collect();
                (
                    input.role.clone(),
                    json!({"profile": alternative.profile, "values": Value::Object(values)}),
                )
            })
            .collect(),
    )
}

struct Hooks {
    acquisitions: AtomicUsize,
    credential_reads: AtomicUsize,
}

impl Hooks {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            acquisitions: AtomicUsize::new(0),
            credential_reads: AtomicUsize::new(0),
        })
    }
}

impl EvidenceHostHooks for Hooks {
    fn before_acquisition<'a>(
        &'a self,
        intent: EvidenceAcquisitionIntent,
    ) -> EvidenceHookFuture<'a> {
        self.acquisitions.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            assert_eq!(intent.pack, "protected-registry-read");
            assert_eq!(intent.route, "residence-region");
            Ok(())
        })
    }

    fn before_credentials<'a>(&'a self, intent: EvidenceSendIntent) -> EvidenceHookFuture<'a> {
        self.credential_reads.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move {
            assert_eq!(intent.endpoint, "records");
            assert_eq!(intent.operation, None);
            assert_eq!(intent.method, EvidenceSendMethod::Get);
            Ok(())
        })
    }
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
async fn a_protected_registry_read_backs_a_full_signed_minimum_disclosure_assertion() {
    // A mock OAuth token endpoint stands in for the source deployment's
    // authorization server: it only answers a client-credentials grant and
    // issues one fresh bearer token.
    let token_server = MockServer::start().await;
    let records_server = MockServer::start().await;
    let client_id = format!("client-id-{}", ulid::Ulid::generate());
    let client_secret = format!("client-secret-{}", ulid::Ulid::generate());
    let access_token = format!("access-token-{}", ulid::Ulid::generate());
    Mock::given(method("POST"))
        .and(path("/oauth2/token"))
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

    // The record endpoint mirrors the fixed registry wire shape by hand (hardcoded
    // JSON, no product runtime code): mandatory Registry Core fields stay non-selectable,
    // selected values live in domainData, and the collection has items,
    // pageInfo, and meta.
    // Only a request carrying the exact issued bearer, the pinned Accept
    // header and V2-shaped request are answered.
    Mock::given(method("GET"))
        .and(path(RECORD_PATH))
        .and(header("authorization", format!("Bearer {access_token}")))
        .and(header("accept", "application/json"))
        .and(query_param("recordReference", RECORD_KEY))
        .and(query_param("fields", "recordReference,region"))
        .and(query_param("pageSize", "2"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "items": [{
                "registryIdentifier": "urn:example:registry:residence-records",
                "recordIdentifier": "SYNTHETIC-RECORD",
                "revisionIdentifier": "1",
                "lifecycleState": "ACTIVE",
                "schemaReference": "https://records.invalid/v2/artifacts/residence-record.schema.json",
                "semanticModelReference": "https://records.invalid/v2/artifacts/residence-record.vocabulary.jsonld",
                "authorityIdentifier": "urn:example:institution:residence-register",
                "recordedAt": "2026-08-02T00:00:00Z",
                "domainData": {
                    "recordReference": RECORD_KEY,
                    "region": RAW_REGION_CODE,
                    "area_geometry": RAW_FIELD_VALUE_CANARY
                }
            }],
            "pageInfo": {"nextCursor": null},
            "meta": {}
        })))
        .with_priority(1)
        .expect(1)
        .mount(&records_server)
        .await;
    // Any request that misses the exact bearer is rejected the way a protected registry
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

    // Copy the maintained protected-read package, then bind only its deployment
    // URLs and secret root to this synthetic process-local source.
    let deployment_root = tempfile::tempdir().expect("temporary protected-read deployment root");
    let bundle_root = deployment_root.path().join("bundle");
    copy_fixture_tree(&protected_read_root().join("bundle"), &bundle_root);
    let bundle_path = bundle_root.join("evidence.yaml");
    let bundle_yaml = fs::read_to_string(&bundle_path).expect("protected-read bundle is readable");
    let bundle_yaml = replace_once(
        bundle_yaml,
        "assuranceProfile: evidence-grade",
        "assuranceProfile: local",
    );
    let bundle_yaml = replace_once(
        bundle_yaml,
        "baseUrl: https://registry-api.gov.example",
        &format!("baseUrl: {}", records_server.uri()),
    );
    let bundle_yaml = replace_once(
        bundle_yaml,
        "tokenEndpoint: https://tokens.gov.example/oauth2/token",
        &format!("tokenEndpoint: {}/oauth2/token", token_server.uri()),
    );
    fs::write(&bundle_path, bundle_yaml).expect("local protected-read package is bound");
    refresh_package_envelope(&bundle_root);
    make_fixture_bundle_read_only(&bundle_root);

    let (secret_root, secrets) = resolver(&[
        ("registry-api-client-id", client_id.as_str()),
        ("registry-api-client-secret", client_secret.as_str()),
    ]);
    let runtime_path = deployment_root.path().join("runtime.yaml");
    let runtime_yaml = fs::read_to_string(protected_read_root().join("runtime.yaml"))
        .expect("protected-read runtime example is readable");
    let runtime_yaml = replace_once(
        runtime_yaml,
        "root: \"/etc/registry-evidence/bundle\"",
        &format!("root: \"{}\"", bundle_root.display()),
    );
    let runtime_yaml = replace_once(
        runtime_yaml,
        "root: \"/run/secrets/registry-evidence\"",
        &format!("root: \"{}\"", secret_root.path().display()),
    );
    let runtime_yaml = replace_once(
        runtime_yaml,
        "signer:\n  type: transit\n  unixSocketPath: \"/run/registry-evidence/transit-proxy.sock\"\n  mount: transit\n  keyName: evidence-signing\n  keyVersion: 7\n  attemptTimeoutMilliseconds: 2000",
        "signer:\n  type: local-jwk\n  privateKeyRef: secret:file/evidence-signing",
    );
    let runtime_yaml = replace_once(
        runtime_yaml,
        "path: \"/var/lib/registry-evidence/audit/evidence.jsonl\"",
        &format!(
            "path: \"{}\"",
            deployment_root.path().join("audit.jsonl").display()
        ),
    );
    let runtime_yaml = replace_once(
        runtime_yaml,
        "baseUrl: https://registry-api.gov.example",
        &format!("baseUrl: {}", records_server.uri()),
    );
    let runtime_yaml = replace_once(
        runtime_yaml,
        "tokenEndpoint: https://tokens.gov.example/oauth2/token",
        &format!("tokenEndpoint: {}/oauth2/token", token_server.uri()),
    );
    fs::write(&runtime_path, runtime_yaml).expect("local protected-read runtime is written");
    fs::set_permissions(&runtime_path, fs::Permissions::from_mode(0o444))
        .expect("local protected-read runtime is immutable");

    let deployment = DeploymentInputs::load(&runtime_path)
        .expect("current protected-read deployment inputs load");
    let (bundle, runtime) = deployment.into_parts();
    let bundle = Arc::new(bundle);
    let kernel = OfflineKernel::compile(Arc::clone(&bundle))
        .expect("current protected-read kernel compiles");
    let sources = build_sources(&bundle, &runtime, &secrets)
        .expect("current protected-read pack execution initializes");
    let executor = &sources["residence-register"];
    let requirement = kernel
        .requirement(REQUIREMENT)
        .expect("the maintained residence requirement exists");
    let fixture_name = requirement
        .fixtures
        .as_ref()
        .expect("the maintained residence requirement has fixtures");
    let fixture = serde_json::to_value(&bundle.fixtures[fixture_name.as_str()])
        .expect("protected-read fixture serializes");
    let case = fixture["cases"]
        .as_array()
        .expect("protected-read fixture cases")
        .iter()
        .find(|case| case["id"] == "positive")
        .and_then(Value::as_object)
        .expect("protected-read positive fixture exists");
    let resolved = resolve_offline_fixture_authorization(
        &bundle,
        requirement,
        fixture["common"].as_object(),
        case,
        AUDIENCE,
    )
    .expect("reviewed subject selector resolves through the authorization boundary");
    let inputs = executor
        .inputs(&resolved)
        .expect("only the authorized reviewed selector is projected into the pack");
    assert_eq!(inputs, json!({"recordReference": RECORD_KEY}));

    let observed_at = "2026-08-02T00:00:00Z"
        .parse()
        .expect("fixed observation time parses");
    let hooks = Hooks::new();
    let lookup = executor
        .execute(inputs, observed_at, hooks.clone())
        .await
        .expect("protected registry pack read succeeds");
    assert_eq!(hooks.acquisitions.load(Ordering::SeqCst), 1);
    assert_eq!(hooks.credential_reads.load(Ordering::SeqCst), 1);
    let LookupResult::Match(facts) = lookup else {
        panic!("protected registry pack returned a non-match outcome");
    };
    assert_eq!(
        serde_json::to_value(&facts).expect("facts serialize"),
        json!({
            "record_reference": RECORD_KEY,
            "official_residence_code": RAW_REGION_CODE
        })
    );
    let facts_text = serde_json::to_string(&facts).expect("facts serialize to text");
    for stripped in [
        RAW_FIELD_NAME_CANARY,
        RAW_FIELD_VALUE_CANARY,
        "registryIdentifier",
        "SYNTHETIC-RECORD",
        "revisionIdentifier",
        "lifecycleState",
        "schemaReference",
        "semanticModelReference",
        "authorityIdentifier",
        "recordedAt",
    ] {
        assert!(
            !facts_text.contains(stripped),
            "pack projection let an unreviewed provider field into facts"
        );
    }

    // The maintained package finishes the full path: authorized selector
    // equality, actual derivation, output gate, Evidence construction, signing,
    // and verification against the deployment's public JWKS.
    let derivation_selectors = selector_value(&resolved, &requirement.derivation.selector_inputs);
    let values = kernel
        .derive_and_validate_with_selectors(
            REQUIREMENT,
            &facts,
            &derivation_selectors,
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
    assert_eq!(values.as_slice()[0].provides_value_for, CONCEPT);
    assert_eq!(
        values.as_slice()[0].value,
        PublicValue::String("REGION-NORTH".to_owned())
    );
    let subjects = resolved
        .subjects
        .iter()
        .map(|subject| SubjectBinding {
            role: subject.role.clone(),
            binding: subject
                .binding(
                    BINDING_KEY,
                    1,
                    &bundle.config.service.trust_domain,
                    registry_evidence::binding::SubjectBindingScope::Audience(AUDIENCE),
                    PURPOSE,
                )
                .expect("authorized subject binding succeeds"),
        })
        .collect();
    let evidence = kernel
        .construct_evidence(
            REQUIREMENT,
            values,
            EvidenceConstruction {
                evidence_id: "urn:ulid:01J4BRXQ0ZZZZZZZZZZZZZZZZZ",
                purpose: PURPOSE,
                scope: EvidenceScope::AudienceScoped {
                    audience: AUDIENCE,
                    request_nonce: registry_evidence::model::OFFLINE_EVALUATION_REQUEST_NONCE,
                },
                issued_at: observed_at,
                observed_at,
                source_valid_until: None,
                channel: AssertionChannel::Source,
                subjects,
            },
        )
        .expect("residence Evidence constructs");
    let signer = fixture_signer().await;
    let jws = signer
        .sign_json(&evidence)
        .await
        .expect("residence Evidence signs");

    // (d) The assertion payload carries only the derived answer: no raw
    // record material or source credential from the protected read.
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
        "SYNTHETIC-RECORD",
        "recordReference",
        "record_reference",
        "official_residence_code",
        "registryIdentifier",
        "recordIdentifier",
        "revisionIdentifier",
        "lifecycleState",
        "schemaReference",
        "semanticModelReference",
        "authorityIdentifier",
        "recordedAt",
        client_id.as_str(),
        client_secret.as_str(),
        access_token.as_str(),
    ] {
        assert!(
            !payload.contains(canary),
            "raw registry record material or a credential reached the assertion payload"
        );
    }

    // (c) The response is a signed flattened JWS that verifies against the
    // deployment's public JWKS under the exact relying policy.
    let jwks = jwks_document(signer.public_jwk(), []).expect("deployment JWKS publishes");
    let serialized = serde_json::to_vec(&jws).expect("flattened JWS serializes");
    let flattened: Value =
        serde_json::from_slice(&serialized).expect("flattened JWS is valid JSON");
    let flattened = flattened.as_object().expect("flattened JWS is an object");
    assert_eq!(flattened.len(), 3);
    for member in ["payload", "protected", "signature"] {
        assert!(flattened.contains_key(member));
    }
    let mut policy = EvidenceVerificationPolicy::from_accepted_transaction(
        &evidence,
        registry_evidence::model::OFFLINE_EVALUATION_REQUEST_NONCE,
        31_536_000,
        observed_at,
        0,
    )
    .expect("the fixture policy states bounds the contract allows");
    policy.issued_by = ISSUER.to_owned();
    policy.provided_by = PROVIDER.to_owned();
    policy.requirement = REQUIREMENT.to_owned();
    policy.evidence_type = EVIDENCE_TYPE.to_owned();
    policy.purpose = PURPOSE.to_owned();
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
    assert_eq!(token_requests[0].method.as_str(), "POST");
    assert_eq!(token_requests[0].url.path(), "/oauth2/token");
    assert!(
        token_requests[0].url.query().is_none(),
        "token URL carries no query"
    );
    assert_eq!(
        token_requests[0]
            .headers
            .get("content-type")
            .and_then(|value| value.to_str().ok()),
        Some("application/x-www-form-urlencoded")
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
    assert_eq!(
        record_request.url.query(),
        Some("fields=recordReference%2Cregion&pageSize=2&recordReference=REC-0001")
    );
    let query: BTreeMap<_, _> = record_request.url.query_pairs().into_owned().collect();
    assert_eq!(
        query,
        BTreeMap::from([
            ("fields".to_owned(), "recordReference,region".to_owned()),
            ("pageSize".to_owned(), "2".to_owned()),
            ("recordReference".to_owned(), RECORD_KEY.to_owned()),
        ])
    );
    assert!(record_request.body.is_empty());
    assert_eq!(
        record_request
            .headers
            .get("accept")
            .and_then(|value| value.to_str().ok()),
        Some("application/json")
    );
    assert_eq!(
        record_request
            .headers
            .get("authorization")
            .and_then(|value| value.to_str().ok()),
        Some(format!("Bearer {access_token}").as_str()),
        "the record read carried the issued bearer"
    );
    assert!(record_request.headers.get("data-purpose").is_none());
}
