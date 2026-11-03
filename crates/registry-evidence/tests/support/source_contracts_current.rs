//! Retained source regressions that exercise the current pack and route API.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;
use std::process::Command;
use std::sync::Arc;

use base64::Engine as _;
use registry_adapter_core::{AdapterPack, ErrorClass, EvidenceConnectionPolicy};
use registry_adapter_engine::artifacts::PackArtifactBytes;
use registry_adapter_engine::evidence::{
    compile_evidence_pack_with_protocols, compile_evidence_with_protocols,
    EvidenceAcquisitionIntent, EvidenceBeginError, EvidenceCompileError, EvidenceCompileInputs,
    EvidenceExecutionError, EvidenceHookFuture, EvidenceHostHooks, EvidenceLimits, EvidenceLookup,
    EvidenceProgram, EvidenceRuntimeBindings,
};
use registry_adapter_engine::host_protocol::HostAccessAttribution;
use registry_evidence::config::{AuthorityKind, SourceConfig, ValueOrigin};
use registry_evidence::model::LookupResult;
use registry_evidence::pack_source::{authorized_route_inputs, PackSourceError};
use registry_evidence::selector::{
    ResolvedAuthorization, ResolvedSelectorField, ResolvedSelectorValue, ResolvedSubject,
    ResolvedSubjectScope,
};
use registry_platform_config::{SecretProvider, SecretResolver};
use registry_platform_crypto::PrivateJwk;
use serde_json::{json, Value};
use tempfile::TempDir;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

/// Synthetic P-384 client key. SMART on FHIR Backend Services names ES384
/// and RS384, so this proves the assertion path independently of the
/// runtime's own ES256 signing key.
const CLIENT_ASSERTION_PRIVATE_JWK: &str = r#"{"kty":"EC","crv":"P-384","d":"Cp2oq8BnIF6oQ2KWV-1yiR7Mf0rFOuDZ5nvS9E_9HGEODI76izZiDEFQ5kfSwCAg","x":"TH-XDvwYtzdc43QDOiBjfdQZTCx1k9Rz5ELDu_2NS8JWcCv8HlfK0T9rYijDIcAY","y":"eLx0gh3VmCC2DeubmC0CdDgno7aEBYEkz5Legyg-2GoLlFohSIop3zKCGSjhg7Ta","alg":"ES384","kid":"client-key-es384-2026-01"}"#;
/// EdDSA makes a JWK's halves independently writable: signing derives the
/// public key from `d`, so the parser must verify that the supplied `x`
/// belongs to the same key.
const CLIENT_ASSERTION_ED25519_PRIVATE_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"cjQHkqxwdgsH3B7jFYHvb_xfY3mGcJ8kkoyjc8u0_2U","x":"rdBTcf1MqWmf6DylIFpreqD5uupNPjxIU8ZegABgpHA","alg":"EdDSA","kid":"client-key-ed25519-2026-01"}"#;
/// The public half of a second synthetic pair, used to build two individually
/// valid members that do not belong together.
const SECOND_ED25519_PUBLIC_HALF: &str = "xxarJ5Sh0NKfZuRrwxwdml-ce7zcxnejxgszHDYXZuo";

struct AllowHooks;

impl EvidenceHostHooks for AllowHooks {
    fn before_acquisition<'a>(
        &'a self,
        intent: EvidenceAcquisitionIntent,
    ) -> EvidenceHookFuture<'a> {
        assert_eq!(intent.pack, "current-source-contract");
        assert_eq!(intent.route, "lookup");
        Box::pin(async { Ok(()) })
    }
}

struct PermitHooks;

impl EvidenceHostHooks for PermitHooks {
    fn before_acquisition<'a>(
        &'a self,
        _intent: EvidenceAcquisitionIntent,
    ) -> EvidenceHookFuture<'a> {
        Box::pin(async { Ok(()) })
    }
}

fn resolver(entries: &[(&str, &[u8])]) -> (TempDir, Arc<SecretResolver>) {
    let root = tempfile::tempdir().expect("temporary secret root");
    for (name, value) in entries {
        let path = root.path().join(name);
        fs::write(&path, value).expect("write synthetic secret");
        #[cfg(unix)]
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).expect("protect secret");
    }
    let resolver = SecretResolver::new([SecretProvider::File], root.path())
        .map(Arc::new)
        .expect("file secret resolver");
    (root, resolver)
}

fn pack(
    authentication: Value,
    attempt_timeout_milliseconds: u64,
) -> (AdapterPack, PackArtifactBytes) {
    let inputs = serde_json::to_vec(&json!({
        "type":"object", "additionalProperties":false, "properties":{}
    }))
    .unwrap();
    let facts = serde_json::to_vec(&json!({
        "type":"object", "additionalProperties":false, "required":["ok"],
        "properties":{"ok":{"type":"boolean"}}
    }))
    .unwrap();
    let pack = serde_json::from_value(json!({
        "id":"current-source-contract", "version":"1", "testedVersions":[],
        "endpoints":[{
            "id":"provider", "component":"http", "authentication":authentication,
            "attemptTimeoutMilliseconds":attempt_timeout_milliseconds,
            "maximumResponseBytes":4096, "requestHeaders":[],
            "operations":[{"id":"lookup", "safeUpstream":true}], "testedVersions":[]
        }],
        "sourceRoutes":[{
            "id":"lookup",
            "evidence":{
                "inputsSchema":{
                    "path":"schemas/inputs.json",
                    "digest":registry_platform_config::sha256_uri(&inputs)
                },
                "factsSchema":{
                    "path":"schemas/facts.json",
                    "digest":registry_platform_config::sha256_uri(&facts)
                }
            },
            "steps":[{"to":{"uri":"http:provider", "parameters":{
                "httpMethod":"GET", "path":"/data", "operation":"lookup"
            }}}]
        }]
    }))
    .expect("current source-contract pack");
    (
        pack,
        PackArtifactBytes::new([
            ("schemas/inputs.json".to_owned(), inputs),
            ("schemas/facts.json".to_owned(), facts),
        ]),
    )
}

fn compile_program(
    base_url: &str,
    pack_authentication: Value,
    runtime_credential: Value,
    policy_authentication: Value,
    secrets: Arc<SecretResolver>,
    attempt_timeout_milliseconds: u64,
) -> Result<EvidenceProgram, EvidenceCompileError> {
    let (pack, artifacts) = pack(pack_authentication, attempt_timeout_milliseconds);
    let runtime = EvidenceRuntimeBindings::from_shared_http(
        serde_json::from_value(json!({
            "id":"current-source", "endpoints":[{
                "endpoint":"provider", "baseUrl":base_url, "credential":runtime_credential
            }], "allowedPrivateCidrs":[]
        }))
        .expect("runtime binding"),
        secrets,
        BTreeMap::new(),
    );
    let policy: EvidenceConnectionPolicy = serde_json::from_value(json!({
        "endpoint":"provider", "baseUrl":base_url,
        "clientIdentity":"forbidden", "authentication":policy_authentication
    }))
    .expect("reviewed connection policy");
    compile_evidence_with_protocols(
        &EvidenceCompileInputs {
            pack: &pack,
            route: "lookup",
            runtime: &runtime,
            connection_id: Some("current-source"),
            connection: &[policy],
            pack_artifacts: &artifacts,
            limits: EvidenceLimits::default(),
        },
        &registry_evidence::host_protocol::registry().expect("Evidence host protocols"),
    )
}

async fn execute(program: &EvidenceProgram) -> Result<EvidenceLookup, EvidenceExecutionError> {
    let acquisition = program
        .begin_acquisition(Arc::new(AllowHooks))
        .await
        .expect("acquisition intent accepted");
    program.execute(&acquisition, json!({})).await
}

#[derive(Debug)]
enum CurrentRunError {
    Begin(EvidenceBeginError),
    Execute(EvidenceExecutionError),
}

async fn try_execute(program: &EvidenceProgram) -> Result<EvidenceLookup, CurrentRunError> {
    let acquisition = program
        .begin_acquisition(Arc::new(AllowHooks))
        .await
        .map_err(CurrentRunError::Begin)?;
    program
        .execute(&acquisition, json!({}))
        .await
        .map_err(CurrentRunError::Execute)
}

fn parameters(bytes: &[u8]) -> Vec<(String, String)> {
    url::form_urlencoded::parse(bytes)
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect()
}

fn contains_parameter(parameters: &[(String, String)], name: &str, value: &str) -> bool {
    parameters
        .iter()
        .any(|(actual_name, actual_value)| actual_name == name && actual_value == value)
}

fn route_error_class(error: EvidenceExecutionError) -> ErrorClass {
    match error {
        EvidenceExecutionError::Route(failure) => failure.class,
        other => panic!("expected a route failure, got {other:?}"),
    }
}

fn decode_jws_segment(segment: &str) -> Value {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segment)
        .expect("JWS segment is base64url");
    serde_json::from_slice(&bytes).expect("JWS segment is JSON")
}

fn selector_source() -> SourceConfig {
    serde_json::from_value(json!({
        "pack":{
            "id":"people", "version":"1",
            "digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "artifactPrefix":"adapter-packs/people/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        },
        "route":"lookup", "connection":"people",
        "inputs":{
            "personId":{"selector":{
                "role":"subject", "profile":"person-id", "field":"identifier"
            }}
        },
        "posture":"record-transformed", "factSchema":"schemas/source-facts/people.json"
    }))
    .unwrap()
}

fn selector_authorization() -> ResolvedAuthorization {
    ResolvedAuthorization {
        authority_profile: "service".to_owned(),
        authority_kind: AuthorityKind::Statutory,
        grant_id: None,
        requirement: "adult-status".to_owned(),
        purpose: "eligibility".to_owned(),
        subject_scope: ResolvedSubjectScope::Audience("urn:example:consumer".to_owned()),
        subjects: vec![ResolvedSubject {
            role: "subject".to_owned(),
            selector_profile: "person-id".to_owned(),
            value_origin: ValueOrigin::Request,
            fields: vec![
                ResolvedSelectorField {
                    name: "identifier".to_owned(),
                    value: ResolvedSelectorValue::String("0007".to_owned()),
                },
                ResolvedSelectorField {
                    name: "unrequested".to_owned(),
                    value: ResolvedSelectorValue::String("private-canary".to_owned()),
                },
            ],
        }],
    }
}

fn attribution_pack() -> (AdapterPack, PackArtifactBytes) {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/evidence/examples/standalone/adapter-packs/synthetic-register");
    let mut value: Value =
        serde_json::from_slice(&fs::read(root.join("pack.yaml")).unwrap()).unwrap();
    value.as_object_mut().unwrap().remove("apiVersion");
    value.as_object_mut().unwrap().remove("kind");
    let protocol = b"{}";
    value["endpoints"][0]["hostProtocol"] = json!({
        "id":"access-attribution-v1",
        "config":{
            "path":"protocols/access-attribution.json",
            "digest":registry_platform_config::sha256_uri(protocol)
        }
    });
    value["endpoints"][0]["authentication"] = json!({"type":"none"});
    let pack: AdapterPack = serde_json::from_value(value).unwrap();
    let mut files = vec![(
        "protocols/access-attribution.json".to_owned(),
        protocol.to_vec(),
    )];
    for pin in pack.pinned_files() {
        if pin.path != "protocols/access-attribution.json" {
            files.push((pin.path.clone(), fs::read(root.join(&pin.path)).unwrap()));
        }
    }
    (pack, PackArtifactBytes::new(files))
}

/// Only the closed pack lookup protocol may produce a source-neutral
/// unresolved outcome. Malformed or undeclared provider shapes remain
/// protocol failures before facts are released.
#[tokio::test]
async fn current_pack_outcomes_keep_unresolved_distinct_and_refuse_malformed_results() {
    for (body, expected) in [
        (
            json!({"lookup":"unresolved"}),
            Some(EvidenceLookup::Unresolved),
        ),
        (json!({"lookup":"no-match"}), Some(EvidenceLookup::NoMatch)),
        (
            json!({"lookup":"ambiguous"}),
            Some(EvidenceLookup::Ambiguous),
        ),
        (
            json!({"lookup":"matched", "facts":{"ok":true}}),
            Some(EvidenceLookup::Matched {
                facts: json!({"ok":true}),
            }),
        ),
        (json!({"lookup":"unresolved", "facts":{}}), None),
        (json!({"lookup":"matched", "facts":null}), None),
        (json!({"lookup":"dependency-failed"}), None),
    ] {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/data"))
            .respond_with(ResponseTemplate::new(200).set_body_json(body))
            .expect(1)
            .mount(&server)
            .await;
        let program = compile_program(
            &server.uri(),
            json!({"type":"none"}),
            json!({"type":"none"}),
            json!({"type":"none"}),
            Arc::new(SecretResolver::disabled()),
            1_000,
        )
        .expect("none-authenticated loopback pack compiles");
        let result = execute(&program).await;
        match expected {
            Some(expected) => assert_eq!(result.unwrap(), expected),
            None => assert!(matches!(
                result,
                Err(EvidenceExecutionError::LookupInvalid | EvidenceExecutionError::FactsInvalid)
            )),
        }
    }
}

/// Every route input is filled from the exact authorized selector field.
/// Another profile, a missing field or a duplicate role cannot substitute for
/// the reviewed binding, and unbound authorized material never reaches code.
#[test]
fn current_authorized_route_inputs_refuse_unfillable_selector_sets() {
    let source = selector_source();
    let authorization = selector_authorization();
    assert_eq!(
        authorized_route_inputs(&source, &authorization).unwrap(),
        json!({"personId":"0007"}),
        "only the exact reviewed field reaches the route"
    );

    let mut changed_profile = authorization.clone();
    changed_profile.subjects[0].selector_profile = "other-profile".to_owned();
    assert!(matches!(
        authorized_route_inputs(&source, &changed_profile),
        Err(PackSourceError::Inputs)
    ));

    let mut missing_field = authorization.clone();
    missing_field.subjects[0].fields.clear();
    assert!(matches!(
        authorized_route_inputs(&source, &missing_field),
        Err(PackSourceError::Inputs)
    ));

    let mut duplicate_role = authorization.clone();
    duplicate_role
        .subjects
        .push(duplicate_role.subjects[0].clone());
    assert!(matches!(
        authorized_route_inputs(&source, &duplicate_role),
        Err(PackSourceError::Inputs)
    ));
}

#[tokio::test]
async fn current_opted_in_attribution_is_host_owned_and_never_enters_facts() {
    use wiremock::matchers::header;

    let server = MockServer::start().await;
    let encode = |value: &str| base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value);
    Mock::given(method("GET"))
        .and(path("/people/0007"))
        .and(header(
            "registry-access-requester",
            encode("verified-requester"),
        ))
        .and(header("registry-access-purpose", encode("eligibility")))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total":1,
            "record":{
                "record_id":"0007", "birth_date":"1980-01-01",
                "residence_region":"north", "address_canary":"synthetic"
            }
        })))
        .expect(1)
        .mount(&server)
        .await;
    let (pack, artifacts) = attribution_pack();
    let checked = compile_evidence_pack_with_protocols(
        &pack,
        "person",
        &artifacts,
        EvidenceLimits::default(),
        &registry_evidence::host_protocol::registry().unwrap(),
    )
    .unwrap();
    let runtime = EvidenceRuntimeBindings::new(
        serde_json::from_value(json!({
            "id":"local", "endpoints":[{
                "endpoint":"register", "baseUrl":server.uri(), "credential":{"type":"none"}
            }], "allowedPrivateCidrs":[]
        }))
        .unwrap(),
        SecretResolver::disabled(),
    );
    let policy: EvidenceConnectionPolicy = serde_json::from_value(json!({
        "endpoint":"register", "baseUrl":server.uri(),
        "clientIdentity":"forbidden", "authentication":{"type":"none"}
    }))
    .unwrap();
    let program = checked
        .bind_live(&runtime, Some("local"), &[policy])
        .unwrap();
    assert!(program.requires_access_attribution());

    let without_context = program
        .begin_acquisition(Arc::new(PermitHooks))
        .await
        .unwrap();
    assert!(program
        .execute(&without_context, json!({"recordId":"0007"}))
        .await
        .is_err());
    assert!(server.received_requests().await.unwrap().is_empty());

    let acquisition = program
        .begin_acquisition_with_attribution(
            Arc::new(PermitHooks),
            Arc::new(HostAccessAttribution::try_new("verified-requester", "eligibility").unwrap()),
        )
        .await
        .unwrap();
    let EvidenceLookup::Matched { facts } = program
        .execute(&acquisition, json!({"recordId":"0007"}))
        .await
        .unwrap()
    else {
        panic!("unique source match");
    };
    assert!(!facts.to_string().contains("verified-requester"));
    assert!(acquisition.trusted_protocol_metadata().await.is_empty());
    let requests = server.received_requests().await.unwrap();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].body.is_empty());
    assert!(requests[0].url.query().is_none());
}

#[tokio::test]
async fn current_maintained_pack_matrix_executes_exact_routes_within_the_shared_budget() {
    use chrono::{DateTime, Utc};
    use registry_evidence::{
        bundle::evidence_package_limits,
        fixture_source::{compile_sources, fixture_acquisition},
        selector::resolve_offline_fixture_authorization,
    };

    let fixture_root =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../products/evidence/fixtures");
    let mut declared = 0_usize;
    let mut executed = 0_usize;
    for fixture_name in [
        "acceptance/all-definitions",
        "acceptance/holder-bound",
        "acceptance/adult-status",
        "acceptance/residence-region",
        "acceptance/professional-licence",
        "acceptance/legal-parent-relationship",
        "conformance/supported-values",
    ] {
        let root = fixture_root.join(fixture_name);
        let verified = registry_platform_config::verify_package(
            &root,
            &evidence_package_limits(),
            "evidencectl package",
        )
        .unwrap_or_else(|error| panic!("{fixture_name}: {error}"));
        let bundle = registry_evidence::bundle::Bundle::load_as_found(&root, &verified)
            .unwrap_or_else(|error| panic!("{fixture_name}: {error}"));
        let programs =
            compile_sources(&bundle).unwrap_or_else(|error| panic!("{fixture_name}: {error}"));

        for requirement in &bundle.config.requirements {
            let fixture_path = requirement.fixtures.as_ref().unwrap().as_str();
            let fixture = serde_json::to_value(&bundle.fixtures[fixture_path]).unwrap();
            let common = fixture["common"].as_object();
            for case in fixture["cases"].as_array().unwrap() {
                let case_id = case["id"].as_str().unwrap();
                let response_shape_negative =
                    matches!(case_id, "missing-fact" | "negative-extra-source-field");
                if case.get("source").is_none()
                    || (case.get("expectedLookup").and_then(Value::as_str).is_none()
                        && case.get("sourceFailure").and_then(Value::as_str).is_none()
                        && !response_shape_negative)
                {
                    continue;
                }
                let case_object = case.as_object().unwrap();
                declared += 1;
                let resolved = resolve_offline_fixture_authorization(
                    &bundle,
                    requirement,
                    common,
                    case_object,
                    "urn:registry-evidence:offline-evaluation",
                )
                .unwrap_or_else(|error| panic!("{fixture_name}/{case_id} authorization: {error}"));
                let observed_at = case
                    .get("observedAt")
                    .or_else(|| common.and_then(|common| common.get("observedAt")))
                    .and_then(Value::as_str)
                    .unwrap_or("2026-08-02T00:00:00Z");
                let run = programs
                    .get(requirement.initial_source())
                    .unwrap()
                    .execute_observed(
                        &resolved,
                        fixture_acquisition(&case["source"]).unwrap(),
                        None,
                        DateTime::parse_from_rfc3339(observed_at)
                            .unwrap()
                            .with_timezone(&Utc),
                    )
                    .await;
                let expected_operations = case["source"]["exchanges"].as_array().unwrap().len();
                assert_eq!(
                    run.data_operations as usize, expected_operations,
                    "{fixture_name}/{} operation count",
                    case_id
                );
                assert!(run.data_operations <= EvidenceLimits::default().maximum_data_operations());
                match case.get("expectedLookup").and_then(Value::as_str) {
                    Some("match") => {
                        let Ok(LookupResult::Match(facts)) = &run.outcome else {
                            panic!(
                                "{fixture_name}/{case_id}: expected a match, got {:?}",
                                run.outcome
                            );
                        };
                        assert!(
                            !serde_json::to_string(facts)
                                .unwrap()
                                .contains("PrivacyCanary"),
                            "{fixture_name}/{case_id}: unselected source data entered facts"
                        );
                    }
                    Some("no_match") => assert!(
                        matches!(run.outcome, Ok(LookupResult::NoMatch)),
                        "{fixture_name}/{case_id}: expected no-match, got {:?}",
                        run.outcome
                    ),
                    Some("ambiguous") => {
                        assert!(
                            matches!(run.outcome, Ok(LookupResult::Ambiguous)),
                            "{fixture_name}/{case_id}: expected ambiguous, got {:?}",
                            run.outcome
                        )
                    }
                    Some("unresolved") => {
                        assert!(
                            matches!(run.outcome, Ok(LookupResult::Unresolved)),
                            "{fixture_name}/{case_id}: expected unresolved, got {:?}",
                            run.outcome
                        )
                    }
                    Some(other) => panic!("unknown expected lookup {other}"),
                    None => assert!(
                        !matches!(run.outcome, Ok(LookupResult::Match(_))),
                        "{fixture_name}/{case_id}: a negative response-shape case released facts"
                    ),
                }
                executed += 1;
            }
        }
    }
    assert!(declared > 0, "maintained matrix selected no source cases");
    assert_eq!(
        executed, declared,
        "every selected maintained source case must execute"
    );
}

#[test]
fn current_pack_compile_refuses_get_body_and_reserved_headers_before_credentials() {
    fn refusal(mut value: Value, artifacts: &PackArtifactBytes) -> Option<String> {
        let pack = match serde_json::from_value::<AdapterPack>(value.take()) {
            Ok(pack) => pack,
            Err(error) => return Some(error.to_string()),
        };
        match compile_evidence_pack_with_protocols(
            &pack,
            "lookup",
            artifacts,
            EvidenceLimits::default(),
            &registry_evidence::host_protocol::registry().unwrap(),
        ) {
            Ok(_) => None,
            Err(error) => Some(error.to_string()),
        }
    }

    for authentication in [
        json!({"type":"static-api-key", "headerName":"X-Api-Key"}),
        json!({"type":"oauth2-client-credentials"}),
    ] {
        let (base, artifacts) = pack(authentication, 1_000);
        let mut get_body = serde_json::to_value(base).unwrap();
        get_body["sourceRoutes"][0]["steps"][0]["to"]["parameters"]["body"] =
            json!({"constant":{"private":"must-not-send"}});
        assert!(refusal(get_body, &artifacts).is_some());
    }

    let (base, artifacts) = pack(json!({"type":"none"}), 1_000);
    let mut reserved = serde_json::to_value(base).unwrap();
    reserved["endpoints"][0]["requestHeaders"] = json!(["authorization"]);
    assert!(refusal(reserved, &artifacts)
        .unwrap()
        .contains("requestHeaders entry 0 is a reserved header name"));

    let (base, artifacts) = pack(
        json!({"type":"static-api-key", "headerName":"X-Api-Key"}),
        1_000,
    );
    let mut credential_collision = serde_json::to_value(base).unwrap();
    credential_collision["endpoints"][0]["requestHeaders"] = json!(["x-api-key"]);
    assert!(refusal(credential_collision, &artifacts)
        .unwrap()
        .contains("requestHeaders entry 0 is the endpoint's api-key header"));

    let (base, artifacts) = pack(json!({"type":"none"}), 1_000);
    let mut duplicate = serde_json::to_value(base).unwrap();
    duplicate["endpoints"][0]["requestHeaders"] = json!(["X-Reviewed", "x-reviewed"]);
    assert!(refusal(duplicate, &artifacts)
        .unwrap()
        .contains("requestHeaders entry 1 repeats an earlier entry"));

    let (base, artifacts) = pack(json!({"type":"none"}), 1_000);
    let mut invalid_shaping = serde_json::to_value(base).unwrap();
    invalid_shaping["sourceRoutes"][0]["steps"]
        .as_array_mut()
        .unwrap()
        .push(json!({
            "setBody":{"jsonpath":"$["}
        }));
    assert!(refusal(invalid_shaping, &artifacts).is_some());
}

#[tokio::test]
async fn current_oauth_client_credentials_preserve_placement_resource_cache_and_redaction() {
    for placement in ["basic-header", "form-body"] {
        for (maximum_cache_seconds, expected_token_requests) in [(60_u64, 1_usize), (0, 2)] {
            let server = MockServer::start().await;
            Mock::given(method("POST"))
                .and(path("/token"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "access_token":"synthetic-access-token", "token_type":"Bearer",
                    "expires_in":120, "scope":"fixture.read"
                })))
                .expect(expected_token_requests as u64)
                .mount(&server)
                .await;
            Mock::given(method("GET"))
                .and(path("/data"))
                .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                    "lookup":"matched", "facts":{"ok":true}
                })))
                .expect(2)
                .mount(&server)
                .await;
            let (_root, secrets) = resolver(&[
                ("client-id", b"synthetic-client"),
                ("client-secret", b"synthetic-secret"),
            ]);
            let token_endpoint = format!("{}/token", server.uri());
            let runtime = json!({
                "type":"oauth2-client-credentials", "tokenEndpoint":token_endpoint,
                "clientIdRef":"secret:file/client-id",
                "clientSecretRef":"secret:file/client-secret",
                "scope":"fixture.read", "resource":"urn:example:resource",
                "credentialPlacement":placement,
                "maximumCacheSeconds":maximum_cache_seconds,
                "assumedLifetimeSeconds":120
            });
            let policy = json!({
                "type":"oauth2-client-credentials", "tokenEndpoint":token_endpoint,
                "scope":"fixture.read", "resource":"urn:example:resource",
                "credentialPlacement":placement
            });
            let program = compile_program(
                &server.uri(),
                json!({"type":"oauth2-client-credentials"}),
                runtime,
                policy,
                secrets,
                1_000,
            )
            .expect("OAuth pack compiles");
            for _ in 0..2 {
                assert_eq!(
                    execute(&program).await.unwrap(),
                    EvidenceLookup::Matched {
                        facts: json!({"ok":true})
                    }
                );
            }

            let requests = server.received_requests().await.unwrap();
            let token_requests = requests
                .iter()
                .filter(|request| request.url.path() == "/token")
                .collect::<Vec<_>>();
            assert_eq!(token_requests.len(), expected_token_requests);
            for request in token_requests {
                assert!(request.url.query().is_none());
                let form = parameters(&request.body);
                assert!(contains_parameter(
                    &form,
                    "grant_type",
                    "client_credentials"
                ));
                assert!(contains_parameter(&form, "scope", "fixture.read"));
                assert!(contains_parameter(
                    &form,
                    "resource",
                    "urn:example:resource"
                ));
                match placement {
                    "basic-header" => {
                        assert!(!form.iter().any(|(name, _)| name == "client_id"));
                        assert!(!form.iter().any(|(name, _)| name == "client_secret"));
                        assert_eq!(
                            request.headers["authorization"].to_str().unwrap(),
                            "Basic c3ludGhldGljLWNsaWVudDpzeW50aGV0aWMtc2VjcmV0"
                        );
                    }
                    "form-body" => {
                        assert!(contains_parameter(&form, "client_id", "synthetic-client"));
                        assert!(contains_parameter(
                            &form,
                            "client_secret",
                            "synthetic-secret"
                        ));
                        assert!(!request.headers.contains_key("authorization"));
                    }
                    _ => unreachable!(),
                }
            }
            assert!(requests
                .iter()
                .filter(|request| request.url.path() == "/data")
                .all(|request| {
                    request.body.is_empty()
                        && request.headers["authorization"].to_str().unwrap()
                            == "Bearer synthetic-access-token"
                }));
        }
    }
}

/// A provider that omits `expires_in` receives only the configured assumed
/// lifetime, still clamped by the cache ceiling. A zero ceiling remains
/// uncached rather than being interpreted as unbounded.
#[tokio::test]
async fn current_oauth_assumed_lifetime_is_bounded_by_the_cache_ceiling() {
    for (maximum_cache_seconds, expected_token_requests) in [(60_u64, 1_u64), (0, 2)] {
        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/token"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "access_token":"assumed-lifetime-token", "token_type":"Bearer"
            })))
            .expect(expected_token_requests)
            .mount(&server)
            .await;
        Mock::given(method("GET"))
            .and(path("/data"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "lookup":"matched", "facts":{"ok":true}
            })))
            .expect(2)
            .mount(&server)
            .await;
        let (_root, secrets) = resolver(&[
            ("client-id", b"synthetic-client"),
            ("client-secret", b"synthetic-secret"),
        ]);
        let token_endpoint = format!("{}/token", server.uri());
        let program = compile_program(
            &server.uri(),
            json!({"type":"oauth2-client-credentials"}),
            json!({
                "type":"oauth2-client-credentials", "tokenEndpoint":token_endpoint,
                "clientIdRef":"secret:file/client-id",
                "clientSecretRef":"secret:file/client-secret",
                "credentialPlacement":"form-body",
                "maximumCacheSeconds":maximum_cache_seconds,
                "assumedLifetimeSeconds":120
            }),
            json!({
                "type":"oauth2-client-credentials", "tokenEndpoint":token_endpoint,
                "credentialPlacement":"form-body"
            }),
            secrets,
            1_000,
        )
        .unwrap();
        assert!(execute(&program).await.is_ok());
        assert!(execute(&program).await.is_ok());
    }
}

/// OAuth extension members remain inert and credential canaries remain absent
/// from diagnostics. No credential placement may put a credential in the token
/// URL, and every token failure stops before an Evidence data request.
#[tokio::test]
async fn current_oauth_redaction_fixture_fails_closed_before_data_sends() {
    let fixture: Value = serde_norway::from_str(include_str!(
        "../../../../products/evidence/fixtures/conformance/oauth-credential-redaction.yaml"
    ))
    .expect("OAuth redaction fixture parses");
    let declared = fixture["cases"]
        .as_array()
        .unwrap()
        .iter()
        .map(|case| case["id"].as_str().unwrap().to_owned())
        .collect::<BTreeSet<_>>();
    let expected = BTreeSet::from([
        "malformed-token-json".to_owned(),
        "token-400".to_owned(),
        "token-401".to_owned(),
        "token-response-duplicate-access-token".to_owned(),
        "token-response-extension-members".to_owned(),
        "token-response-oversized".to_owned(),
        "token-response-wrong-access-token-field".to_owned(),
        "token-response-wrong-lifetime".to_owned(),
        "token-response-wrong-media-type".to_owned(),
        "token-response-wrong-scope".to_owned(),
        "token-response-omitted-lifetime".to_owned(),
        "token-response-omitted-lifetime-with-assumed-lifetime".to_owned(),
        "token-response-wrong-token-type".to_owned(),
        "token-success".to_owned(),
        "transport-connection-failure".to_owned(),
        "transport-timeout".to_owned(),
    ]);
    assert_eq!(declared, expected, "fixture and executable matrix drifted");

    for case_id in declared {
        let server = MockServer::start().await;
        let response = match case_id.as_str() {
            "transport-connection-failure" => None,
            "token-success" => Some(ResponseTemplate::new(200).set_body_json(json!({
                "access_token":"synthetic-access-token", "token_type":"Bearer",
                "expires_in":120, "scope":"fixture.read"
            }))),
            "token-400" => Some(ResponseTemplate::new(400).set_body_string("private-secret")),
            "token-401" => Some(ResponseTemplate::new(401).set_body_string("private-secret")),
            "malformed-token-json" => {
                Some(ResponseTemplate::new(200).set_body_raw("{invalid", "application/json"))
            }
            "token-response-oversized" => Some(ResponseTemplate::new(200).set_body_raw(
                format!("{{\"access_token\":\"{}\",\"token_type\":\"Bearer\",\"expires_in\":120}}", "x".repeat(9_000)),
                "application/json",
            )),
            "token-response-extension-members" => Some(
                ResponseTemplate::new(200).set_body_json(json!({
                    "access_token":"synthetic-access-token", "token_type":"Bearer",
                    "expires_in":120, "scope":"fixture.read",
                    "refresh_expires_in":0, "unexpected":"private-secret"
                })),
            ),
            "token-response-duplicate-access-token" => Some(
                ResponseTemplate::new(200).set_body_raw(
                    "{\"access_token\":\"synthetic-access-token\",\"token_type\":\"Bearer\",\"expires_in\":120,\"access_token\":\"private-secret\"}",
                    "application/json",
                ),
            ),
            "token-response-wrong-access-token-field" => Some(
                ResponseTemplate::new(200).set_body_json(json!({
                    "access_token":7, "token_type":"Bearer", "expires_in":120
                })),
            ),
            "token-response-wrong-token-type" => Some(
                ResponseTemplate::new(200).set_body_json(json!({
                    "access_token":"synthetic-access-token", "token_type":"MAC", "expires_in":120
                })),
            ),
            "token-response-wrong-scope" => Some(
                ResponseTemplate::new(200).set_body_json(json!({
                    "access_token":"synthetic-access-token", "token_type":"Bearer",
                    "expires_in":120, "scope":"other.scope"
                })),
            ),
            "token-response-wrong-lifetime" => Some(
                ResponseTemplate::new(200).set_body_json(json!({
                    "access_token":"synthetic-access-token", "token_type":"Bearer", "expires_in":0
                })),
            ),
            "token-response-omitted-lifetime"
            | "token-response-omitted-lifetime-with-assumed-lifetime" => Some(
                ResponseTemplate::new(200).set_body_json(json!({
                    "access_token":"synthetic-access-token", "token_type":"Bearer"
                })),
            ),
            "token-response-wrong-media-type" => Some(ResponseTemplate::new(200).set_body_raw(
                "{\"access_token\":\"synthetic-access-token\",\"token_type\":\"Bearer\",\"expires_in\":120}",
                "text/plain",
            )),
            "transport-timeout" => Some(
                ResponseTemplate::new(200)
                    .set_delay(std::time::Duration::from_secs(31))
                    .set_body_json(json!({
                        "access_token":"synthetic-access-token", "token_type":"Bearer", "expires_in":120
                    })),
            ),
            _ => panic!("unknown fixture case {case_id}"),
        };
        if let Some(response) = response {
            Mock::given(method("POST"))
                .and(path("/token"))
                .respond_with(response)
                .expect(1)
                .mount(&server)
                .await;
        }
        Mock::given(method("GET"))
            .and(path("/data"))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "lookup":"matched", "facts":{"ok":true}
            })))
            .mount(&server)
            .await;
        let (_root, secrets) = resolver(&[
            ("client-id", b"private-client-id"),
            ("client-secret", b"private-secret"),
        ]);
        let token_endpoint = if case_id == "transport-connection-failure" {
            "http://127.0.0.1:0/token".to_owned()
        } else {
            format!("{}/token", server.uri())
        };
        let assumed =
            (case_id == "token-response-omitted-lifetime-with-assumed-lifetime").then_some(120);
        let mut runtime = json!({
            "type":"oauth2-client-credentials", "tokenEndpoint":token_endpoint,
            "clientIdRef":"secret:file/client-id", "clientSecretRef":"secret:file/client-secret",
            "scope":"fixture.read", "credentialPlacement":"form-body",
            "maximumCacheSeconds":0
        });
        if let Some(seconds) = assumed {
            runtime["assumedLifetimeSeconds"] = json!(seconds);
        }
        let policy = json!({
            "type":"oauth2-client-credentials", "tokenEndpoint":token_endpoint,
            "scope":"fixture.read", "credentialPlacement":"form-body"
        });
        let program = compile_program(
            &server.uri(),
            json!({"type":"oauth2-client-credentials"}),
            runtime,
            policy,
            secrets,
            1_000,
        )
        .expect("OAuth failure case compiles");
        let result = try_execute(&program).await;
        let diagnostic = format!("{result:?}");
        let expects_success = matches!(
            case_id.as_str(),
            "token-success"
                | "token-response-extension-members"
                | "token-response-omitted-lifetime-with-assumed-lifetime"
        );
        if expects_success {
            assert!(result.is_ok(), "{case_id}: {result:?}");
        } else if case_id == "transport-connection-failure" {
            assert!(matches!(
                result,
                Err(CurrentRunError::Begin(EvidenceBeginError::Endpoint))
            ));
        } else {
            let error = match result {
                Ok(lookup) => panic!("{case_id}: unexpectedly succeeded with {lookup:?}"),
                Err(error) => error,
            };
            let class = match error {
                CurrentRunError::Execute(error) => route_error_class(error),
                CurrentRunError::Begin(error) => {
                    panic!("{case_id}: unexpected acquisition failure {error:?}")
                }
            };
            let expected = match case_id.as_str() {
                "transport-timeout" => ErrorClass::UpstreamTimeout,
                _ => ErrorClass::CredentialRejected,
            };
            assert_eq!(class, expected, "{case_id}");
        }
        for private in [
            "private-client-id",
            "private-secret",
            "synthetic-access-token",
            "/token?",
        ] {
            assert!(!diagnostic.contains(private), "{case_id}: leaked {private}");
        }
        let data_count = server
            .received_requests()
            .await
            .unwrap()
            .iter()
            .filter(|request| request.url.path() == "/data")
            .count();
        assert_eq!(data_count, usize::from(expects_success), "{case_id}");
    }
}

/// RFC 7523 replaces the shared secret with a signed assertion. The configured
/// audience reaches the claim byte-for-byte, while the default is the exact
/// configured token endpoint; neither form changes where the request is sent.
/// Unsupported, public-only and mismatched JWK material fails before transport.
#[tokio::test]
async fn current_private_key_jwt_preserves_signed_claims_audience_resource_and_key_refusals() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token":"assertion-access-token", "token_type":"Bearer", "expires_in":60
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/data"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "lookup":"matched", "facts":{"ok":true}
        })))
        .expect(1)
        .mount(&server)
        .await;
    let (_root, secrets) = resolver(&[
        ("client-id", b"synthetic-client"),
        ("assertion-key", CLIENT_ASSERTION_PRIVATE_JWK.as_bytes()),
    ]);
    let token_endpoint = format!("{}/token", server.uri());
    let assertion_audience = "https://issuer.invalid/realms/main";
    let runtime = json!({
        "type":"oauth2-private-key-jwt", "tokenEndpoint":token_endpoint,
        "clientIdRef":"secret:file/client-id", "clientAssertionKeyRef":"secret:file/assertion-key",
        "clientAssertionAudience":assertion_audience, "resource":"urn:example:resource",
        "maximumCacheSeconds":0
    });
    let policy = json!({
        "type":"oauth2-private-key-jwt", "tokenEndpoint":token_endpoint,
        "clientAssertionAudience":assertion_audience, "resource":"urn:example:resource"
    });
    let program = compile_program(
        &server.uri(),
        json!({"type":"oauth2-private-key-jwt"}),
        runtime,
        policy,
        secrets,
        1_000,
    )
    .expect("private-key-jwt pack compiles");
    execute(&program).await.unwrap();
    let requests = server.received_requests().await.unwrap();
    let token_request = requests
        .iter()
        .find(|request| request.url.path() == "/token")
        .unwrap();
    assert!(!token_request.headers.contains_key("authorization"));
    let form = parameters(&token_request.body);
    assert!(contains_parameter(
        &form,
        "grant_type",
        "client_credentials"
    ));
    assert!(contains_parameter(&form, "client_id", "synthetic-client"));
    assert!(contains_parameter(
        &form,
        "resource",
        "urn:example:resource"
    ));
    assert!(!form.iter().any(|(name, _)| name == "client_secret"));
    let assertion = form
        .iter()
        .find_map(|(name, value)| (name == "client_assertion").then_some(value.as_str()))
        .unwrap();
    let segments = assertion.split('.').collect::<Vec<_>>();
    assert_eq!(segments.len(), 3);
    let header = decode_jws_segment(segments[0]);
    let claims = decode_jws_segment(segments[1]);
    let signature = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(segments[2])
        .unwrap();
    let signing_input = &assertion[..segments[0].len() + segments[1].len() + 1];
    let key = PrivateJwk::parse(CLIENT_ASSERTION_PRIVATE_JWK).unwrap();
    registry_platform_crypto::verify(signing_input.as_bytes(), &signature, &key.public()).unwrap();
    assert_eq!(header["alg"], json!("ES384"));
    assert_eq!(header["typ"], json!("JWT"));
    assert_eq!(claims["aud"], json!(assertion_audience));
    assert_eq!(claims["iss"], json!("synthetic-client"));
    assert_eq!(claims["sub"], json!("synthetic-client"));
    assert_eq!(
        claims["exp"].as_i64().unwrap() - claims["iat"].as_i64().unwrap(),
        60
    );
    assert!(claims["jti"]
        .as_str()
        .is_some_and(|value| !value.is_empty()));

    let default_server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token":"default-audience-token", "token_type":"Bearer", "expires_in":60
        })))
        .expect(1)
        .mount(&default_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/data"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "lookup":"matched", "facts":{"ok":true}
        })))
        .expect(1)
        .mount(&default_server)
        .await;
    let (_root, secrets) = resolver(&[
        ("client-id", b"synthetic-client"),
        ("assertion-key", CLIENT_ASSERTION_PRIVATE_JWK.as_bytes()),
    ]);
    let default_token_endpoint = format!("{}/token", default_server.uri());
    let default_program = compile_program(
        &default_server.uri(),
        json!({"type":"oauth2-private-key-jwt"}),
        json!({
            "type":"oauth2-private-key-jwt", "tokenEndpoint":default_token_endpoint,
            "clientIdRef":"secret:file/client-id",
            "clientAssertionKeyRef":"secret:file/assertion-key",
            "maximumCacheSeconds":0
        }),
        json!({
            "type":"oauth2-private-key-jwt", "tokenEndpoint":default_token_endpoint
        }),
        secrets,
        1_000,
    )
    .unwrap();
    execute(&default_program).await.unwrap();
    let default_requests = default_server.received_requests().await.unwrap();
    let default_form = parameters(
        &default_requests
            .iter()
            .find(|request| request.url.path() == "/token")
            .unwrap()
            .body,
    );
    let default_assertion = default_form
        .iter()
        .find_map(|(name, value)| (name == "client_assertion").then_some(value.as_str()))
        .unwrap();
    let default_claims = decode_jws_segment(default_assertion.split('.').nth(1).unwrap());
    assert_eq!(default_claims["aud"], json!(default_token_endpoint));

    let mut mismatched_key: Value =
        serde_json::from_str(CLIENT_ASSERTION_ED25519_PRIVATE_JWK).unwrap();
    mismatched_key["x"] = json!(SECOND_ED25519_PUBLIC_HALF);
    let public_only = serde_json::to_vec(
        &PrivateJwk::parse(CLIENT_ASSERTION_PRIVATE_JWK)
            .unwrap()
            .public(),
    )
    .unwrap();
    let mut with_unsupported_member: Value =
        serde_json::from_str(CLIENT_ASSERTION_PRIVATE_JWK).unwrap();
    with_unsupported_member["oth"] = json!([]);
    let mut with_symmetric_member: Value =
        serde_json::from_str(CLIENT_ASSERTION_PRIVATE_JWK).unwrap();
    with_symmetric_member["k"] = json!("c3ltbWV0cmlj");
    let duplicate_kid =
        CLIENT_ASSERTION_PRIVATE_JWK.replacen('{', r#"{"kid":"client-key-es384-duplicate","#, 1);
    let invalid_keys = [
        ("not-json", b"not-a-jwk".to_vec()),
        ("public-only", public_only),
        (
            "duplicate-private-scalar",
            br#"{"kty":"EC","crv":"P-384","kid":"k","d":"AA","d":"BB"}"#.to_vec(),
        ),
        (
            "unsupported-member",
            serde_json::to_vec(&with_unsupported_member).unwrap(),
        ),
        (
            "symmetric-member",
            serde_json::to_vec(&with_symmetric_member).unwrap(),
        ),
        ("duplicate-key-id", duplicate_kid.into_bytes()),
        (
            "mismatched-halves",
            serde_json::to_vec(&mismatched_key).unwrap(),
        ),
    ];
    for (label, key_bytes) in invalid_keys {
        let refusal_server = MockServer::start().await;
        let (_root, secrets) = resolver(&[
            ("client-id", b"synthetic-client"),
            ("assertion-key", key_bytes.as_slice()),
        ]);
        let token_endpoint = format!("{}/token", refusal_server.uri());
        let program = compile_program(
            &refusal_server.uri(),
            json!({"type":"oauth2-private-key-jwt"}),
            json!({
                "type":"oauth2-private-key-jwt", "tokenEndpoint":token_endpoint,
                "clientIdRef":"secret:file/client-id",
                "clientAssertionKeyRef":"secret:file/assertion-key",
                "maximumCacheSeconds":0
            }),
            json!({"type":"oauth2-private-key-jwt", "tokenEndpoint":token_endpoint}),
            secrets,
            1_000,
        )
        .expect("invalid key is a runtime credential failure, not a plan failure");
        assert_eq!(
            route_error_class(execute(&program).await.unwrap_err()),
            ErrorClass::CredentialRejected,
            "{label}"
        );
        assert!(
            refusal_server.received_requests().await.unwrap().is_empty(),
            "{label}"
        );
    }
}

/// A secret file is opaque bytes. Non-UTF-8 material is a deployment failure
/// under both client-secret placements, before token or data transport.
#[tokio::test]
async fn current_binary_client_secrets_are_refused_before_token_or_data_requests() {
    for placement in ["basic-header", "form-body"] {
        let server = MockServer::start().await;
        let (_root, secrets) = resolver(&[
            ("client-id", b"synthetic-client"),
            ("client-secret", &[0xff, 0xfe, 0xfd]),
        ]);
        let token_endpoint = format!("{}/token", server.uri());
        let program = compile_program(
            &server.uri(),
            json!({"type":"oauth2-client-credentials"}),
            json!({
                "type":"oauth2-client-credentials", "tokenEndpoint":token_endpoint,
                "clientIdRef":"secret:file/client-id", "clientSecretRef":"secret:file/client-secret",
                "credentialPlacement":placement, "maximumCacheSeconds":0
            }),
            json!({
                "type":"oauth2-client-credentials", "tokenEndpoint":token_endpoint,
                "credentialPlacement":placement
            }),
            secrets,
            1_000,
        )
        .unwrap();
        assert_eq!(
            route_error_class(execute(&program).await.unwrap_err()),
            ErrorClass::CredentialRejected
        );
        assert!(server.received_requests().await.unwrap().is_empty());
    }
}

#[test]
fn current_pack_ignores_ambient_proxy_for_token_and_data_requests() {
    if std::env::var_os("EVIDENCE_CURRENT_PROXY_CHILD").is_some() {
        return;
    }
    let status = Command::new(std::env::current_exe().unwrap())
        .arg("current_pack_proxy_isolation_child")
        .arg("--nocapture")
        .env("EVIDENCE_CURRENT_PROXY_CHILD", "1")
        .env("HTTP_PROXY", "http://127.0.0.1:9")
        .env("HTTPS_PROXY", "http://127.0.0.1:9")
        .env("ALL_PROXY", "http://127.0.0.1:9")
        .env_remove("NO_PROXY")
        .env_remove("no_proxy")
        .status()
        .expect("spawn isolated proxy child");
    assert!(status.success());
}

#[tokio::test]
async fn current_pack_proxy_isolation_child() {
    if std::env::var_os("EVIDENCE_CURRENT_PROXY_CHILD").is_none() {
        return;
    }
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token":"proxy-isolation-token", "token_type":"Bearer", "expires_in":60
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/data"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "lookup":"matched", "facts":{"ok":true}
        })))
        .expect(1)
        .mount(&server)
        .await;
    let (_root, secrets) = resolver(&[
        ("client-id", b"synthetic-client"),
        ("client-secret", b"synthetic-secret"),
    ]);
    let token_endpoint = format!("{}/token", server.uri());
    let program = compile_program(
        &server.uri(),
        json!({"type":"oauth2-client-credentials"}),
        json!({
            "type":"oauth2-client-credentials", "tokenEndpoint":token_endpoint,
            "clientIdRef":"secret:file/client-id", "clientSecretRef":"secret:file/client-secret",
            "credentialPlacement":"form-body", "maximumCacheSeconds":0
        }),
        json!({
            "type":"oauth2-client-credentials", "tokenEndpoint":token_endpoint,
            "credentialPlacement":"form-body"
        }),
        secrets,
        1_000,
    )
    .unwrap();
    assert!(execute(&program).await.is_ok());
}

/// Pure pack compilation is a second gate behind authoring validation. Direct
/// callers must still be unable to construct invalid schemes, OAuth forms,
/// resource indicators or token endpoint authority.
#[test]
fn current_pack_compile_refuses_invalid_authentication_contracts() {
    for scheme in [
        "",
        "has space",
        "has,comma",
        "123456789012345678901234567890123",
    ] {
        let candidate = pack(
            json!({"type":"static-authorization", "scheme":scheme}),
            1_000,
        );
        let server = "http://127.0.0.1:1";
        let (_root, secrets) = resolver(&[("token", b"synthetic-token")]);
        let runtime = EvidenceRuntimeBindings::from_shared_http(
            serde_json::from_value(json!({
                "id":"current-source", "endpoints":[{
                    "endpoint":"provider", "baseUrl":server,
                    "credential":{"type":"static-authorization", "tokenRef":"secret:file/token"}
                }], "allowedPrivateCidrs":[]
            }))
            .unwrap(),
            secrets,
            BTreeMap::new(),
        );
        let policy: EvidenceConnectionPolicy = serde_json::from_value(json!({
            "endpoint":"provider", "baseUrl":server, "clientIdentity":"forbidden",
            "authentication":{"type":"static-authorization"}
        }))
        .unwrap();
        assert!(compile_evidence_with_protocols(
            &EvidenceCompileInputs {
                pack: &candidate.0,
                route: "lookup",
                runtime: &runtime,
                connection_id: Some("current-source"),
                connection: &[policy],
                pack_artifacts: &candidate.1,
                limits: EvidenceLimits::default(),
            },
            &registry_evidence::host_protocol::registry().unwrap(),
        )
        .is_err());
    }

    let (_root, secrets) = resolver(&[("token", b"synthetic-token")]);
    let mismatch = compile_program(
        "http://127.0.0.1:1",
        json!({"type":"static-authorization"}),
        json!({"type":"static-authorization", "tokenRef":"secret:file/token"}),
        json!({"type":"basic"}),
        secrets,
        1_000,
    );
    assert!(matches!(
        mismatch,
        Err(EvidenceCompileError::ConnectionPolicy)
    ));

    let (_root, secrets) = resolver(&[
        ("client-id", b"synthetic-client"),
        ("client-secret", b"synthetic-secret"),
    ]);
    let changed_token_endpoint = compile_program(
        "http://127.0.0.1:1",
        json!({"type":"oauth2-client-credentials"}),
        json!({
            "type":"oauth2-client-credentials",
            "tokenEndpoint":"http://127.0.0.1:1/token",
            "clientIdRef":"secret:file/client-id",
            "clientSecretRef":"secret:file/client-secret",
            "credentialPlacement":"form-body", "maximumCacheSeconds":0
        }),
        json!({
            "type":"oauth2-client-credentials",
            "tokenEndpoint":"http://127.0.0.1:1/token/",
            "credentialPlacement":"form-body"
        }),
        secrets,
        1_000,
    );
    assert!(matches!(
        changed_token_endpoint,
        Err(EvidenceCompileError::ConnectionPolicy)
    ));

    for resource in [
        "",
        "example.invalid/resource",
        "https://example.invalid/resource#fragment",
        "https://user@example.invalid/resource",
        "https://example.invalid/record with space",
        "https://example.invalid/é",
        "https://example.invalid/resource\n",
    ] {
        let (_root, secrets) = resolver(&[
            ("client-id", b"synthetic-client"),
            ("client-secret", b"synthetic-secret"),
        ]);
        let runtime_credential = json!({
            "type":"oauth2-client-credentials",
            "tokenEndpoint":"http://127.0.0.1:1/token",
            "clientIdRef":"secret:file/client-id",
            "clientSecretRef":"secret:file/client-secret",
            "resource":resource,
            "credentialPlacement":"form-body", "maximumCacheSeconds":0
        });
        let binding =
            serde_json::from_value::<registry_adapter_core::AdapterEndpointBindings>(json!({
                "id":"current-source", "endpoints":[{
                    "endpoint":"provider", "baseUrl":"http://127.0.0.1:1",
                    "credential":runtime_credential
                }], "allowedPrivateCidrs":[]
            }));
        if binding.is_err() {
            continue;
        }
        let refused = compile_program(
            "http://127.0.0.1:1",
            json!({"type":"oauth2-client-credentials"}),
            runtime_credential,
            json!({
                "type":"oauth2-client-credentials",
                "tokenEndpoint":"http://127.0.0.1:1/token",
                "resource":resource, "credentialPlacement":"form-body"
            }),
            secrets,
            1_000,
        );
        assert!(refused.is_err(), "unusable resource {resource} compiled");
    }

    for runtime_credential in [
        json!({
            "type":"oauth2-client-credentials",
            "tokenEndpoint":"http://127.0.0.1:1/token",
            "clientIdRef":"secret:file/client-id",
            "clientSecretRef":"secret:file/client-secret",
            "maximumCacheSeconds":0
        }),
        json!({
            "type":"oauth2-private-key-jwt",
            "tokenEndpoint":"http://127.0.0.1:1/token",
            "clientIdRef":"secret:file/client-id",
            "clientAssertionKeyRef":"secret:file/assertion-key",
            "credentialPlacement":"form-body", "maximumCacheSeconds":0
        }),
    ] {
        let binding = json!({
            "id":"current-source", "endpoints":[{
                "endpoint":"provider", "baseUrl":"http://127.0.0.1:1",
                "credential":runtime_credential
            }], "allowedPrivateCidrs":[]
        });
        assert!(
            serde_json::from_value::<registry_adapter_core::AdapterEndpointBindings>(binding)
                .is_err()
        );
    }
}
