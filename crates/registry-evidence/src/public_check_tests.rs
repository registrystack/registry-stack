//! End-to-end proofs for `POST /v1/public-check`, the first unauthenticated
//! route that reads registry data.
//!
//! An authored project and a target authority enter the pure compiler; the
//! resulting package is activated and served by the real runtime against a
//! mock source. The derivation fails if the stored check code ever reaches
//! it, so every successful answer below also proves the code is confined to
//! the public comparison.

#![allow(
    clippy::disallowed_methods,
    reason = "the test reads one published fixture to retain governed package fields while replacing only the compiler-owned model"
)]

use std::{
    collections::BTreeMap,
    fs,
    io::Write as _,
    os::unix::fs::PermissionsExt as _,
    path::PathBuf,
    sync::{Arc, Mutex},
    time::Duration,
};

use axum::http::{Method, StatusCode};
use axum_test::{TestResponse, TestServer};
use chrono::{DateTime, Utc};
use registry_evidence_authoring::{
    compile,
    project::{AcquisitionPosture, EvidenceProject, PackReference},
    target::{self, EvidenceTargetAuthority},
};
use registry_platform_yaml::LocalId;
use serde_json::{json, Value};
use tempfile::TempDir;
use wiremock::{
    matchers::{body_json, method, path},
    Mock, MockServer, Respond, ResponseTemplate,
};

use crate::{
    audit::PUBLIC_CHECK_AUDIT_SCHEMA,
    authority::{self, AuthorityDocument},
    bundle::{Bundle, DeploymentInputs},
    model::{
        EvidenceRequest, FlattenedJws, PublicValue, RequestedSelector, RequestedSubject,
        SelectorValue,
    },
    normalized_tests::{
        access_token, authenticator, decode_evidence, fresh_nonce, make_read_only, write_secret,
        EVIDENCE_AUDIENCE, EVIDENCE_PRIVATE_JWK, EVIDENCE_PUBLIC_JWK,
    },
    observability::REQUEST_LOG_TARGET,
    problem::ProblemCode,
    public_check::{
        parse_request, PublicCheckRequest, PUBLIC_CHECK_ANSWER_SCHEMA, PUBLIC_CHECK_ROUTE,
    },
    runtime::EvidenceRuntime,
    runtime_tests::capture_evidence_logs,
    server::{build_app, build_app_at_for_test},
};

const REQUIREMENT: &str = "urn:example:requirement:certificate-status:v1";
const PURPOSE: &str = "certificate-check";
const STATUS_CONCEPT: &str = "urn:example:concept:certificate-status:v1";
const PRINTED_CONCEPT: &str = "urn:example:concept:certificate-printed:v1";
const EXTRA_CONCEPT: &str = "urn:example:concept:certificate-internal:v1";
const SOURCE_TOKEN: &str = "public-check-source-token-canary";
const NUMBER: &str = "RN-2026-004217";
const CODE: &str = "K7QWM4XRT5PZ3NB6VHJYDC2A";

/// Which target authority the fixture activates.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Authority {
    /// A relying-service profile and the public-check activation.
    RelyingAndCheck,
    /// A relying-service profile only: the route stays unregistered.
    RelyingOnly,
    /// The public-check activation with no access profile at all.
    CheckOnly,
}

struct PublicCheckRuntime {
    _temporary: TempDir,
    runtime: Arc<EvidenceRuntime>,
    source: MockServer,
    audit_path: PathBuf,
}

impl PublicCheckRuntime {
    fn http(&self) -> TestServer {
        TestServer::new(build_app(Arc::clone(&self.runtime)))
    }

    fn http_at(&self, evaluation_time: DateTime<Utc>) -> TestServer {
        TestServer::new(build_app_at_for_test(
            Arc::clone(&self.runtime),
            evaluation_time,
        ))
    }

    fn audit(&self) -> String {
        fs::read_to_string(&self.audit_path).unwrap_or_default()
    }

    async fn mount_record(&self, number: &str, lookup: Value) {
        Mock::given(method("POST"))
            .and(path("/records"))
            .and(body_json(json!({"record_id": number})))
            .respond_with(ResponseTemplate::new(200).set_body_json(lookup))
            .mount(&self.source)
            .await;
    }

    async fn mount_response(&self, number: &str, response: ResponseTemplate) {
        Mock::given(method("POST"))
            .and(path("/records"))
            .and(body_json(json!({"record_id": number})))
            .respond_with(response)
            .mount(&self.source)
            .await;
    }

    async fn wait_for_source_requests(&self, expected: usize) {
        tokio::time::timeout(Duration::from_secs(3), async {
            while self.source_requests().await < expected {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the source is read before the test deadline");
    }

    async fn source_requests(&self) -> usize {
        self.source
            .received_requests()
            .await
            .expect("request journal is available")
            .len()
    }
}

fn matched(facts: Value) -> Value {
    json!({"lookup": "matched", "facts": facts})
}

fn record(state: &str) -> Value {
    matched(json!({
        "recordState": state,
        "checkCode": CODE,
        "holderName": "Jordan Sample",
        "expiresOn": "2028-02-29"
    }))
}

async fn public_check_runtime(authority_kind: Authority) -> PublicCheckRuntime {
    public_check_runtime_with_routes(authority_kind, pack_routes()).await
}

async fn public_check_runtime_with_routes(
    authority_kind: Authority,
    routes: Vec<compile::CheckedPackRoute>,
) -> PublicCheckRuntime {
    let source = MockServer::start().await;
    let temporary = tempfile::tempdir().expect("temporary public-check deployment");
    let package_root = temporary.path().join("package");
    let secret_root = temporary.path().join("secrets");
    let authority_root = temporary.path().join("authority");
    let runtime_path = temporary.path().join("runtime.yaml");
    let audit_path = temporary.path().join("audit.jsonl");
    fs::create_dir(&package_root).expect("package root is created");
    fs::create_dir(&secret_root).expect("secret root is created");
    fs::set_permissions(&secret_root, fs::Permissions::from_mode(0o700))
        .expect("secret root is private");

    let project = certificate_project();
    let compiled = compile::compile_with_pack_routes(&project, &scripts(), &routes)
        .expect("certificate project compiles against its checked pack route");
    let mut bundle: Value = serde_norway::from_slice(include_bytes!(
        "../../../products/evidence/fixtures/acceptance/all-definitions/evidence.yaml"
    ))
    .expect("retained target governance parses");
    let bundle_object = bundle.as_object_mut().expect("bundle is an object");
    for model_member in [
        "project",
        "maximumHolderBoundBatchSize",
        "selectorProfiles",
        "sources",
        "requirements",
        "authorityProfiles",
        "publication",
    ] {
        bundle_object.remove(model_member);
    }
    bundle["assuranceProfile"] = json!("local");
    bundle["service"]["providerId"] = json!("https://provider.example.org");
    bundle["service"]["publicOrigin"] = json!("https://provider.example.org");
    bundle["issuer"]["uri"] = json!("urn:example:certificate-check:issuer");
    bundle["responseFormats"] = json!(["signed-jws"]);
    bundle["sourceConnections"] = json!({
        "register": {
            "endpoints": [{
                "endpoint": "provider",
                "baseUrl": source.uri(),
                "authentication": {"type": "static-authorization"},
                "clientIdentity": "forbidden"
            }]
        }
    });
    bundle["authorityProfiles"] = json!({});
    for (name, value) in compiled
        .model
        .as_object()
        .expect("compiled model is an object")
    {
        bundle[name] = value.clone();
    }
    fs::write(
        package_root.join("evidence.yaml"),
        serde_norway::to_string(&bundle).expect("bundle serializes"),
    )
    .expect("bundle configuration is written");
    for (relative, bytes) in compiled.artifacts {
        let path = package_root.join(relative);
        fs::create_dir_all(path.parent().expect("artifact has a parent"))
            .expect("artifact directory is created");
        fs::write(path, bytes).expect("compiled artifact is written");
    }
    let public_key_path =
        package_root.join("public-keys/_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo.jwk.json");
    fs::create_dir_all(public_key_path.parent().expect("public key has a parent"))
        .expect("public key directory is created");
    fs::write(public_key_path, EVIDENCE_PUBLIC_JWK).expect("public key is written");
    registry_platform_config::write_sum_file(
        &package_root,
        None,
        &crate::bundle::evidence_package_limits(),
        "evidencectl package",
    )
    .expect("package checksum envelope is written");
    make_read_only(&package_root);

    let bundle = Bundle::load(&package_root).expect("certificate package loads");
    let authority = certificate_authority(authority_kind);
    let compiled_authority = target::compile_authority(&authority, &project)
        .expect("certificate authority compiles inside project ceilings");
    let authority_bytes =
        serde_norway::to_string(&compiled_authority).expect("compiled authority serializes");
    let authority = AuthorityDocument::parse("compiled-authority.yaml", authority_bytes.as_bytes())
        .expect("runtime authority parses the compiler output");
    authority::activate(
        &authority_root,
        "local",
        &bundle.config,
        bundle.package_digest(),
        &authority,
    )
    .expect("compiled target authority activates for this exact package");

    write_secret(&secret_root, "source-token", SOURCE_TOKEN);
    write_secret(&secret_root, "signing-key", EVIDENCE_PRIVATE_JWK);
    write_secret(
        &secret_root,
        "audit-hash-key",
        "public-check-audit-hash-secret-32-bytes",
    );
    write_secret(
        &secret_root,
        "subject-binding-key",
        "public-check-subject-binding-secret-32-bytes",
    );
    fs::write(
        &runtime_path,
        format!(
            r#"apiVersion: id.registrystack.org/formats/evidence/runtime/v1alpha1
kind: EvidenceRuntimeConfig
package:
  root: {}
listener:
  bind: 127.0.0.1:8080
  tlsTermination: operator-controlled-upstream
  trustProxyIdentityHeaders: false
  maximumRequestBytes: 4096
  maximumConcurrentRequests: 64
  requestTimeoutMilliseconds: 10000
  shutdownGraceMilliseconds: 30000
secretProviders:
  file:
    root: {}
signer:
  type: local-jwk
  privateKeyRef: secret:file/signing-key
audit:
  path: {}
  rotateBytes: 10485760
authority:
  root: {}
  target: local
outboundTls:
  systemRoots: true
  trustProfiles: {{}}
sourceConnections:
  register:
    id: register
    endpoints:
      - endpoint: provider
        baseUrl: {}
        credential: {{type: static-authorization, tokenRef: secret:file/source-token}}
    allowedPrivateCidrs: []
"#,
            package_root.display(),
            secret_root.display(),
            audit_path.display(),
            authority_root.display(),
            source.uri(),
        ),
    )
    .expect("runtime configuration is written");
    fs::set_permissions(&runtime_path, fs::Permissions::from_mode(0o400))
        .expect("runtime configuration is sealed");
    DeploymentInputs::load(&runtime_path).expect("package and authority ceilings both load");
    let runtime = Arc::new(
        EvidenceRuntime::initialize_with_authenticator(&runtime_path, authenticator())
            .await
            .expect("certificate runtime initializes"),
    );
    PublicCheckRuntime {
        _temporary: temporary,
        runtime,
        source,
        audit_path,
    }
}

fn certificate_project() -> EvidenceProject {
    serde_json::from_value(json!({
        "id": "certificate-check",
        "selectorProfiles": {
            "certificate-number": {
                "maximumAggregateBytes": 32,
                "fields": {"number": {"type": "string", "minimumBytes": 4, "maximumBytes": 32}}
            }
        },
        "functions": [
            {"id": "derive-certificate-check", "interface": "assertion-derive/v1", "source": "functions/derive.rhai"}
        ],
        "sources": {
            "certificate-record": {
                "pack": {"id": "synthetic-register", "version": "1"},
                "route": "certificate",
                "connection": "register",
                "inputs": {
                    "recordId": {"selector": {"role": "certificate", "profile": "certificate-number", "field": "number"}}
                },
                "acquisitionPosture": "record-transformed"
            }
        },
        "assertionDefinitions": {
            "certificate-status": {
                "question": "What is the current status of this certificate, and what does it state?",
                "semantics": {
                    "requirement": REQUIREMENT,
                    "kind": "information-requirement",
                    "evidenceType": "urn:example:evidence-type:certificate-status:v1",
                    "referenceFrameworks": ["urn:example:framework:certificate-check:v1"]
                },
                "purpose": PURPOSE,
                "grantCeiling": {
                    "authorities": ["organizational"],
                    "actorKinds": ["service"],
                    "valueOrigins": ["request"],
                    "audiences": [EVIDENCE_AUDIENCE]
                },
                "subjects": [{"role": "certificate", "selectors": ["certificate-number"]}],
                "acquisition": {"source": "certificate-record"},
                "derive": {"function": "derive-certificate-check"},
                "outputs": {
                    "status": {"concept": STATUS_CONCEPT, "type": "controlled-category", "values": ["valid", "suspended", "revoked", "expired"]},
                    "printed": {"concept": PRINTED_CONCEPT, "type": "reviewed-structured-value", "schema": "schemas/printed.json", "maximumSerializedBytes": 1024},
                    "internal": {"concept": EXTRA_CONCEPT, "type": "boolean"}
                },
                "validitySeconds": 300,
                "subjectBinding": "audience-scoped",
                "representations": ["signed-jws"],
                "publicCheck": {"checkCodeFact": "checkCode", "statusOutput": "status", "fieldsOutput": "printed"}
            }
        }
    }))
    .expect("certificate project is structurally valid")
}

fn certificate_authority(kind: Authority) -> EvidenceTargetAuthority {
    let mut document = json!({
        "target": "local",
        "project": "certificate-check",
        "accessProfiles": {}
    });
    if kind != Authority::CheckOnly {
        document["accessProfiles"]["direct"] = json!({
            "authority": "organizational",
            "actorKind": "service",
            "requesterTags": ["fixture-agency"],
            "grants": [{
                "definition": "certificate-status",
                "purpose": PURPOSE,
                "audienceFrom": "authenticated-requester",
                "representations": ["signed-jws"],
                "subjectBinding": "audience-scoped",
                "subjects": [{
                    "role": "certificate",
                    "selectorProfile": "certificate-number",
                    "valueOrigin": "request"
                }]
            }]
        });
    }
    if kind != Authority::RelyingOnly {
        document["publicCheck"] = json!({"definition": "certificate-status"});
    }
    serde_json::from_value(document).expect("certificate target authority is structurally valid")
}

/// The derivation refuses to run when the stored check code reaches it, maps
/// one synthetic record state to a derivation-input failure, and emits one
/// output the public answer must never carry.
fn scripts() -> BTreeMap<String, String> {
    BTreeMap::from([
        (
            "functions/derive.rhai".to_owned(),
            r#"fn derive(facts, selectors, context) {
    if facts["checkCode"] != () { throw "check_code_reached_derivation"; }
    let state = required(facts["recordState"], "record_state_missing");
    if state == "inconsistent" { throw "derivation_input_error"; }
    [
        #{output: "status", value: state},
        #{output: "printed", value: #{
            form: "reviewed-structured-value",
            schema: "urn:example:schema:certificate-printed",
            fields: #{
                holderName: required(facts["holderName"], "holder_name_missing"),
                expiresOn: required(facts["expiresOn"], "expiry_missing")
            }
        }},
        #{output: "internal", value: true}
    ]
}"#
            .to_owned(),
        ),
        (
            "schemas/printed.json".to_owned(),
            json!({
                "$id": "urn:example:schema:certificate-printed",
                "type": "object",
                "additionalProperties": false,
                "required": ["holderName", "expiresOn"],
                "properties": {
                    "holderName": {"type": "string", "maxLength": 64},
                    "expiresOn": {"type": "string", "maxLength": 16}
                }
            })
            .to_string(),
        ),
    ])
}

fn pack_routes() -> Vec<compile::CheckedPackRoute> {
    pack_routes_with_steps(false)
}

/// The same route with the record number bound into the Source path rather
/// than the request body.
fn path_bound_pack_routes() -> Vec<compile::CheckedPackRoute> {
    pack_routes_with_steps(true)
}

fn pack_routes_with_steps(path_bound: bool) -> Vec<compile::CheckedPackRoute> {
    const ROUTE_SCRIPT: &str = r#"fn record_request(exchange) {
    #{record_id: exchange.body.recordId}
}

fn record_result(exchange) {
    exchange.body
}
"#;
    let inputs_schema = json!({
        "type": "object",
        "additionalProperties": false,
        "required": ["recordId"],
        "properties": {"recordId": {"type": "string", "minLength": 1, "maxLength": 32}}
    });
    let facts_schema = json!({
        "type": "object",
        "additionalProperties": false,
        "properties": {
            "recordState": {"type": "string", "maxLength": 32},
            "checkCode": {"type": "string", "maxLength": 64},
            "holderName": {"type": "string", "maxLength": 64},
            "expiresOn": {"type": "string", "maxLength": 16}
        }
    });
    let artifacts = BTreeMap::from([
        (
            "schemas/inputs.json".to_owned(),
            serde_json::to_vec(&inputs_schema).expect("pack inputs schema serializes"),
        ),
        (
            "schemas/facts.json".to_owned(),
            serde_json::to_vec(&facts_schema).expect("pack facts schema serializes"),
        ),
        (
            "scripts/routes.rhai".to_owned(),
            ROUTE_SCRIPT.as_bytes().to_vec(),
        ),
    ]);
    let digest = |path: &str| {
        registry_platform_config::sha256_uri(
            artifacts
                .get(path)
                .unwrap_or_else(|| panic!("pack artifact {path} exists")),
        )
    };
    let steps = if path_bound {
        json!([
            {"setHeader": {"name": "accept", "value": {"constant": "application/json"}}},
            {"setProperty": {"name": "recordId", "value": {"jsonpath": "$.recordId"}}},
            {"setBody": {"rhai": {"file": "scripts/routes.rhai", "entrypoint": "record_request"}}},
            {"to": {"uri": "http:provider", "parameters": {
                "httpMethod": "GET",
                "path": "/records/{{record_id}}",
                "pathParameters": {"record_id": {"exchangeProperty": "recordId"}},
                "operation": "lookup"
            }}},
            {"setBody": {"rhai": {"file": "scripts/routes.rhai", "entrypoint": "record_result"}}}
        ])
    } else {
        json!([
            {"setHeader": {"name": "accept", "value": {"constant": "application/json"}}},
            {"setBody": {"rhai": {"file": "scripts/routes.rhai", "entrypoint": "record_request"}}},
            {"to": {"uri": "http:provider", "parameters": {
                "httpMethod": "POST",
                "path": "/records",
                "operation": "lookup",
                "body": {"jsonpath": "$"}
            }}},
            {"setBody": {"rhai": {"file": "scripts/routes.rhai", "entrypoint": "record_result"}}}
        ])
    };
    let pack = json!({
        "apiVersion": "id.registrystack.org/formats/adapter/pack/v1alpha1",
        "kind": "AdapterPack",
        "id": "synthetic-register",
        "version": "1",
        "testedVersions": [],
        "endpoints": [{
            "id": "provider",
            "component": "http",
            "authentication": {"type": "static-authorization"},
            "attemptTimeoutMilliseconds": 2000,
            "maximumResponseBytes": 16384,
            "requestHeaders": ["accept"],
            "operations": [{"id": "lookup", "safeUpstream": true}]
        }],
        "scripts": [{
            "path": "scripts/routes.rhai",
            "digest": digest("scripts/routes.rhai")
        }],
        "sourceRoutes": [{
            "id": "certificate",
            "evidence": {
                "inputsSchema": {"path": "schemas/inputs.json", "digest": digest("schemas/inputs.json")},
                "factsSchema": {"path": "schemas/facts.json", "digest": digest("schemas/facts.json")},
                "acquisitionPosture": "record-transformed"
            },
            "steps": steps
        }]
    });
    let pack_bytes = serde_json::to_vec(&pack).expect("certificate Adapter pack serializes");
    vec![compile::CheckedPackRoute {
        pack: PackReference {
            id: LocalId::new("synthetic-register").expect("pack id is valid"),
            version: "1".to_owned(),
        },
        route: LocalId::new("certificate").expect("route id is valid"),
        digest: registry_platform_config::sha256_uri(&pack_bytes),
        inputs_schema,
        facts_schema,
        acquisition_posture: AcquisitionPosture::RecordTransformed,
        pack_bytes,
        artifacts,
    }]
}

fn relying_request(number: &str) -> EvidenceRequest {
    EvidenceRequest {
        request_nonce: fresh_nonce(),
        requirement: REQUIREMENT.to_owned(),
        expected_configuration_revision: None,
        purpose: PURPOSE.to_owned(),
        subjects: vec![RequestedSubject {
            role: "certificate".to_owned(),
            selector: RequestedSelector {
                profile: "certificate-number".to_owned(),
                values: Some(BTreeMap::from([(
                    "number".to_owned(),
                    SelectorValue::String(number.to_owned()),
                )])),
            },
        }],
        holder_keys: Vec::new(),
    }
}

fn audit_lines(audit: &str) -> Vec<Value> {
    audit
        .lines()
        .map(|line| serde_json::from_str(line).expect("audit line is JSON"))
        .collect()
}

fn assert_absent(haystack: &str, needles: &[&str], context: &str) {
    for needle in needles {
        assert!(!haystack.contains(needle), "{context} carries {needle}");
    }
}

/// Test 7 and test 20 on the relying path: the same definition still returns
/// signed evidence over every output, and the stored code never reaches the
/// derivation or the signed bytes.
#[tokio::test]
async fn relying_path_on_the_checked_definition_signs_every_output_without_the_code() {
    let fixture = public_check_runtime(Authority::RelyingAndCheck).await;
    fixture.mount_record(NUMBER, record("valid")).await;
    let response = fixture
        .http()
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .json(&relying_request(NUMBER))
        .await;
    response.assert_status_ok();
    let jws: FlattenedJws = serde_json::from_slice(response.as_bytes()).expect("flattened JWS");
    let evidence = decode_evidence(&jws);
    let values: BTreeMap<_, _> = evidence
        .supported_values
        .iter()
        .map(|value| (value.provides_value_for.as_str(), &value.value))
        .collect();
    assert!(
        matches!(values.get(STATUS_CONCEPT), Some(PublicValue::String(status)) if status == "valid")
    );
    assert!(matches!(
        values.get(PRINTED_CONCEPT),
        Some(PublicValue::Structured(_))
    ));
    assert!(
        matches!(values.get(EXTRA_CONCEPT), Some(PublicValue::Boolean(true))),
        "an extra output stays on the relying path"
    );
    assert_absent(
        &String::from_utf8_lossy(response.as_bytes()),
        &[CODE],
        "signed evidence",
    );
    let payload = serde_json::to_string(&serde_json::to_value(&evidence).expect("evidence"))
        .expect("evidence serializes");
    assert_absent(&payload, &[CODE], "the signed payload");
    assert_absent(&fixture.audit(), &[CODE, SOURCE_TOKEN], "the audit");
}

const OPERATION: &str = "public-check-operation-0001";

fn public_request(number: &str, code: &str) -> PublicCheckRequest {
    parse_request(
        &serde_json::to_vec(&json!({"documentNumber": number, "checkCode": code}))
            .expect("public-check body serializes"),
    )
    .expect("well-shaped public-check request")
}

/// The record member of every public-check audit entry, in write order.
fn public_check_records(audit: &str) -> Vec<Value> {
    audit_lines(audit)
        .into_iter()
        .filter(|entry| entry["schema"] == PUBLIC_CHECK_AUDIT_SCHEMA)
        .map(|entry| entry["record"].clone())
        .collect()
}

/// Test 20 and the extra-output rule on the runtime: a hit answers the
/// status and the inner printed fields, the extra output and the stored code
/// stay out of the answer and the audit, and the access attempt precedes the
/// release that names exactly the two answered concepts.
#[tokio::test]
async fn a_hit_answers_the_status_and_printed_fields_and_nothing_else() {
    let fixture = public_check_runtime(Authority::RelyingAndCheck).await;
    fixture.mount_record(NUMBER, record("valid")).await;
    let bytes = fixture
        .runtime
        .evaluate_public_check(
            OPERATION,
            &public_request(NUMBER, &CODE.to_ascii_lowercase()),
        )
        .await
        .expect("a matching pair is answered");
    let answer: Value = serde_json::from_slice(&bytes).expect("answer is JSON");
    let members = answer.as_object().expect("answer is an object");
    assert_eq!(
        members.keys().map(String::as_str).collect::<Vec<_>>(),
        ["fields", "observedAt", "schema", "status"]
    );
    assert_eq!(answer["schema"], "registry.evidence.public-check/v1alpha1");
    assert_eq!(answer["status"], "valid");
    assert_eq!(
        answer["fields"],
        json!({"holderName": "Jordan Sample", "expiresOn": "2028-02-29"})
    );
    let text = String::from_utf8_lossy(&bytes);
    assert_absent(
        &text,
        &[CODE, EXTRA_CONCEPT, "internal"],
        "the public answer",
    );

    let audit = fixture.audit();
    assert_absent(
        &audit,
        &[CODE, NUMBER, SOURCE_TOKEN, EXTRA_CONCEPT],
        "the audit",
    );
    let records = public_check_records(&audit);
    assert_eq!(records.len(), 2, "one access attempt and one release");
    assert_eq!(records[0]["phase"], "access-attempt");
    assert_eq!(records[0]["decision"], "authorized");
    assert_eq!(records[1]["phase"], "disclosure-release");
    assert_eq!(records[1]["decision"], "released");
    assert_eq!(
        records[1]["disclosedConcepts"],
        json!([STATUS_CONCEPT, PRINTED_CONCEPT])
    );
    for record in &records {
        assert_eq!(record["operation"], OPERATION);
        assert_eq!(record["requirement"], REQUIREMENT);
        assert_eq!(record["purpose"], PURPOSE);
        assert_eq!(record["subjects"][0]["role"], "certificate");
        assert_eq!(
            record["subjects"][0]["selectorProfile"],
            "certificate-number"
        );
    }
}

/// A wrong code is a not-found miss the operator sees as `code-mismatch`.
#[tokio::test]
async fn a_wrong_code_is_a_miss_the_operator_sees_as_code_mismatch() {
    let fixture = public_check_runtime(Authority::RelyingAndCheck).await;
    fixture.mount_record(NUMBER, record("valid")).await;
    let failure = fixture
        .runtime
        .evaluate_public_check(
            OPERATION,
            &public_request(NUMBER, "AAAAAAAAAAAAAAAAAAAAAAAA"),
        )
        .await
        .expect_err("a wrong code is never answered");
    assert_eq!(failure.problem(), ProblemCode::ResourceNotFound);
    let records = public_check_records(&fixture.audit());
    assert_eq!(records.len(), 2);
    assert_eq!(records[0]["decision"], "authorized");
    assert_eq!(records[1]["phase"], "denial");
    assert_eq!(records[1]["decision"], "code-mismatch");
    assert_absent(&fixture.audit(), &[CODE, NUMBER, SOURCE_TOKEN], "the audit");
}

const UNKNOWN_ROUTE: &str = "/v1/not-a-route";
const BROWSER_ORIGIN: &str = "https://verify.example.org";
const INBOUND_TRACE_ID: &str = "0123456789abcdef0123456789abcdef";
const INBOUND_TRACEPARENT: &str = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01";

fn check_body(number: &str, code: &str) -> Value {
    json!({"documentNumber": number, "checkCode": code})
}

async fn check(server: &TestServer, number: &str, code: &str) -> TestResponse {
    server
        .post(PUBLIC_CHECK_ROUTE)
        .json(&check_body(number, code))
        .await
}

fn header<'a>(response: &'a TestResponse, name: &str) -> Option<&'a str> {
    response
        .headers()
        .get(name)
        .map(|value| value.to_str().expect("response header is visible ASCII"))
}

fn trace_id_of(response: &TestResponse) -> String {
    header(response, "traceparent")
        .and_then(|value| value.split('-').nth(1))
        .expect("every response carries a traceparent")
        .to_owned()
}

fn problem_code(response: &TestResponse) -> String {
    let body: Value = serde_json::from_slice(response.as_bytes()).expect("problem is JSON");
    body["code"]
        .as_str()
        .expect("problem carries a code")
        .to_owned()
}

/// What a caller can compare between two responses: the status, every header
/// but the per-request `traceparent`, and the body without its `traceId`.
fn comparable(response: &TestResponse) -> (StatusCode, Vec<(String, String)>, Value) {
    let mut headers: Vec<(String, String)> = response
        .headers()
        .iter()
        .filter(|(name, _)| name.as_str() != "traceparent")
        .map(|(name, value)| {
            (
                name.as_str().to_owned(),
                value
                    .to_str()
                    .expect("response header is visible ASCII")
                    .to_owned(),
            )
        })
        .collect();
    headers.sort();
    let mut body: Value = if response.as_bytes().is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(response.as_bytes()).expect("response body is JSON")
    };
    if let Some(members) = body.as_object_mut() {
        members.remove("traceId");
    }
    (response.status_code(), headers, body)
}

fn answer_validator() -> jsonschema::JSONSchema {
    jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&crate::contracts::public_check_answer_schema())
        .expect("public-check answer schema compiles")
}

fn audit_validator() -> jsonschema::JSONSchema {
    let schema: Value = serde_norway::from_slice(include_bytes!(
        "../../../products/evidence/contracts/public-check-audit-event.schema.yaml"
    ))
    .expect("public-check audit event schema parses");
    jsonschema::JSONSchema::options()
        .with_draft(jsonschema::Draft::Draft202012)
        .compile(&schema)
        .expect("public-check audit event schema compiles")
}

/// Test 12: with no activation the route is not registered, so a POST and a
/// browser preflight to it answer exactly as an unknown route does, down to
/// continuing the caller's trace, and nothing reaches the Source or the audit.
#[tokio::test]
async fn an_unactivated_check_answers_exactly_as_an_unknown_route() {
    let fixture = public_check_runtime(Authority::RelyingOnly).await;
    fixture.mount_record(NUMBER, record("valid")).await;
    let server = fixture.http();

    let post = |path: &'static str| {
        server
            .post(path)
            .add_header("traceparent", INBOUND_TRACEPARENT)
            .json(&check_body(NUMBER, CODE))
    };
    let preflight = |path: &'static str| {
        server
            .method(Method::OPTIONS, path)
            .add_header("traceparent", INBOUND_TRACEPARENT)
            .add_header("origin", BROWSER_ORIGIN)
            .add_header("access-control-request-method", "POST")
            .add_header("access-control-request-headers", "content-type")
    };
    let get = |path: &'static str| {
        server
            .get(path)
            .add_header("traceparent", INBOUND_TRACEPARENT)
    };

    let pairs = [
        (post(PUBLIC_CHECK_ROUTE).await, post(UNKNOWN_ROUTE).await),
        (
            preflight(PUBLIC_CHECK_ROUTE).await,
            preflight(UNKNOWN_ROUTE).await,
        ),
        (get(PUBLIC_CHECK_ROUTE).await, get(UNKNOWN_ROUTE).await),
    ];
    for (check, unknown) in &pairs {
        assert_eq!(check.status_code(), StatusCode::NOT_FOUND);
        assert_eq!(problem_code(check), "resource.not-found");
        assert_eq!(comparable(check), comparable(unknown));
        assert_eq!(header(check, "access-control-allow-origin"), None);
        assert_eq!(trace_id_of(check), INBOUND_TRACE_ID);
        assert_eq!(trace_id_of(unknown), INBOUND_TRACE_ID);
    }
    assert_eq!(fixture.source_requests().await, 0);
    assert_eq!(fixture.audit(), "", "an unregistered route writes no audit");
}

/// Test 13: every activated status is answered with the exact answer
/// contract, never stored, readable from any origin, observed now.
#[tokio::test]
async fn a_hit_answers_each_status_unstored_to_any_origin() {
    use chrono::SubsecRound as _;
    let fixture = public_check_runtime(Authority::RelyingAndCheck).await;
    let server = fixture.http();
    let validator = answer_validator();
    for (index, state) in ["valid", "suspended", "revoked", "expired"]
        .into_iter()
        .enumerate()
    {
        let number = format!("RN-2026-10000{index}");
        fixture.mount_record(&number, record(state)).await;
        let before = Utc::now().trunc_subsecs(0);
        let response = check(&server, &number, CODE).await;
        let after = Utc::now();

        assert_eq!(response.status_code(), StatusCode::OK, "{state}");
        assert_eq!(header(&response, "content-type"), Some("application/json"));
        assert_eq!(header(&response, "cache-control"), Some("no-store"));
        assert_eq!(header(&response, "access-control-allow-origin"), Some("*"));
        assert_eq!(header(&response, "access-control-allow-credentials"), None);
        let answer: Value = serde_json::from_slice(response.as_bytes()).expect("answer is JSON");
        assert!(validator.is_valid(&answer), "{answer} meets its contract");
        let observed: DateTime<Utc> = answer["observedAt"]
            .as_str()
            .expect("observedAt is a string")
            .parse()
            .expect("observedAt is RFC 3339");
        assert!(before <= observed && observed <= after, "{observed} is now");
        assert_eq!(
            answer,
            json!({
                "schema": PUBLIC_CHECK_ANSWER_SCHEMA,
                "status": state,
                "fields": {"holderName": "Jordan Sample", "expiresOn": "2028-02-29"},
                "observedAt": answer["observedAt"]
            })
        );
    }
}

/// An activation with no access profile at all still serves the check.
#[tokio::test]
async fn a_check_only_authority_serves_the_check() {
    let fixture = public_check_runtime(Authority::CheckOnly).await;
    fixture.mount_record(NUMBER, record("valid")).await;
    let response = check(&fixture.http(), NUMBER, CODE).await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let answer: Value = serde_json::from_slice(response.as_bytes()).expect("answer is JSON");
    assert_eq!(answer["status"], "valid");
}

/// Test 14: every miss class is one identical not-found response, and only
/// the audit tells them apart, without the presented or stored values.
#[tokio::test]
async fn every_miss_is_one_identical_not_found() {
    let fixture = public_check_runtime(Authority::RelyingAndCheck).await;
    let server = fixture.http();
    let validator = audit_validator();
    let without = |member: &str| {
        let mut lookup = record("valid");
        lookup["facts"]
            .as_object_mut()
            .expect("facts are an object")
            .remove(member);
        lookup
    };
    let mut malformed_code = record("valid");
    malformed_code["facts"]["checkCode"] = json!("not-a-code");
    let classes = [
        (
            "RN-MISS-0001",
            json!({"lookup": "no-match"}),
            CODE,
            "no-match",
        ),
        (
            "RN-MISS-0002",
            json!({"lookup": "ambiguous"}),
            CODE,
            "ambiguous",
        ),
        (
            "RN-MISS-0003",
            json!({"lookup": "unresolved"}),
            CODE,
            "unresolved",
        ),
        ("RN-MISS-0004", without("holderName"), CODE, "fact-missing"),
        ("RN-MISS-0005", record("inconsistent"), CODE, "fact-missing"),
        ("RN-MISS-0006", without("checkCode"), CODE, "code-mismatch"),
        ("RN-MISS-0007", malformed_code, CODE, "code-mismatch"),
        (
            "RN-MISS-0008",
            record("valid"),
            "AAAAAAAAAAAAAAAAAAAAAAAA",
            "code-mismatch",
        ),
    ];
    let mut reference = None;
    for (number, lookup, code, decision) in classes {
        fixture.mount_record(number, lookup).await;
        let response = check(&server, number, code).await;
        assert_eq!(response.status_code(), StatusCode::NOT_FOUND, "{decision}");
        assert_eq!(problem_code(&response), "resource.not-found");
        assert_eq!(header(&response, "access-control-allow-origin"), Some("*"));
        let shape = comparable(&response);
        assert_eq!(
            reference.get_or_insert_with(|| shape.clone()),
            &shape,
            "{decision}"
        );

        let records = public_check_records(&fixture.audit());
        let (access, miss) = (&records[records.len() - 2], &records[records.len() - 1]);
        assert_eq!(access["phase"], "access-attempt");
        assert_eq!(access["decision"], "authorized");
        assert_eq!(miss["phase"], "denial", "{decision}");
        assert_eq!(miss["decision"], decision);
        assert_eq!(access["operation"], miss["operation"]);
    }
    let audit = fixture.audit();
    let records = public_check_records(&audit);
    assert_eq!(
        records.len(),
        16,
        "one access attempt and one denial per miss"
    );
    for record in &records {
        assert!(validator.is_valid(record), "{record} meets its contract");
    }
    assert_absent(
        &audit,
        &[
            CODE,
            "not-a-code",
            "RN-MISS-",
            "Jordan Sample",
            SOURCE_TOKEN,
        ],
        "the audit",
    );
}

/// Test 15: a body or number the route refuses never reaches the Source or
/// the audit.
#[tokio::test]
async fn a_refused_request_reaches_neither_the_source_nor_the_audit() {
    let fixture = public_check_runtime(Authority::RelyingAndCheck).await;
    fixture.mount_record(NUMBER, record("valid")).await;
    let server = fixture.http();
    let valid = serde_json::to_vec(&check_body(NUMBER, CODE)).expect("body serializes");
    let json_bytes = |value: Value| serde_json::to_vec(&value).expect("body serializes");

    let mut refusals = vec![
        (
            "text/plain",
            server
                .post(PUBLIC_CHECK_ROUTE)
                .text(String::from_utf8(valid.clone()).expect("body is UTF-8"))
                .await,
            "evidence.invalid-request",
        ),
        (
            "no content type",
            server
                .post(PUBLIC_CHECK_ROUTE)
                .bytes(valid.clone().into())
                .await,
            "evidence.invalid-request",
        ),
        (
            "a media type parameter",
            server
                .post(PUBLIC_CHECK_ROUTE)
                .content_type("application/json; charset=utf-8")
                .bytes(valid.clone().into())
                .await,
            "evidence.invalid-request",
        ),
    ];
    let bodies = [
        (
            "not JSON",
            b"{\"documentNumber\":".to_vec(),
            "evidence.invalid-request",
        ),
        (
            "an extra member",
            json_bytes(json!({"documentNumber": NUMBER, "checkCode": CODE, "purpose": PURPOSE})),
            "evidence.invalid-request",
        ),
        (
            "a missing member",
            json_bytes(json!({"documentNumber": NUMBER})),
            "evidence.invalid-request",
        ),
        (
            "a non-string member",
            json_bytes(json!({"documentNumber": NUMBER, "checkCode": 7})),
            "evidence.invalid-request",
        ),
        (
            "a short code",
            json_bytes(check_body(NUMBER, &CODE[..23])),
            "evidence.invalid-request",
        ),
        (
            "a code outside base32",
            json_bytes(check_body(NUMBER, &format!("0{}", &CODE[1..]))),
            "evidence.invalid-request",
        ),
        (
            "an oversized body",
            json_bytes(check_body(&"A".repeat(5000), CODE)),
            "evidence.invalid-request",
        ),
        (
            "a number under the profile",
            json_bytes(check_body("ab", CODE)),
            "request.selector-invalid",
        ),
        (
            "a number over the profile",
            json_bytes(check_body(&"N".repeat(33), CODE)),
            "request.selector-invalid",
        ),
    ];
    for (case, body, code) in bodies {
        let response = server
            .post(PUBLIC_CHECK_ROUTE)
            .content_type("application/json")
            .bytes(body.into())
            .await;
        refusals.push((case, response, code));
    }
    for (case, response, code) in &refusals {
        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST, "{case}");
        assert_eq!(&problem_code(response), code, "{case}");
        assert_eq!(header(response, "access-control-allow-origin"), Some("*"));
    }
    assert_eq!(fixture.source_requests().await, 0);
    assert_eq!(fixture.audit(), "", "a refused request writes no audit");
}

/// Snapshots the audit at the moment the Source is read, then answers.
struct AuditAtSourceRead {
    audit_path: PathBuf,
    seen: Arc<Mutex<Option<String>>>,
    lookup: Value,
}

impl Respond for AuditAtSourceRead {
    fn respond(&self, _request: &wiremock::Request) -> ResponseTemplate {
        *self.seen.lock().expect("snapshot lock") =
            Some(fs::read_to_string(&self.audit_path).unwrap_or_default());
        ResponseTemplate::new(200).set_body_json(&self.lookup)
    }
}

/// Test 16: the access attempt is durable before the Source is read, the
/// release is durable before the answer, and an audit failure at either
/// point answers 503 with no answer.
#[tokio::test]
async fn the_audit_brackets_the_source_read_and_the_answer() {
    let fixture = public_check_runtime(Authority::RelyingAndCheck).await;
    let seen = Arc::new(Mutex::new(None));
    Mock::given(method("POST"))
        .and(path("/records"))
        .and(body_json(json!({"record_id": NUMBER})))
        .respond_with(AuditAtSourceRead {
            audit_path: fixture.audit_path.clone(),
            seen: Arc::clone(&seen),
            lookup: record("valid"),
        })
        .mount(&fixture.source)
        .await;
    let response = check(&fixture.http(), NUMBER, CODE).await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let at_source = seen
        .lock()
        .expect("snapshot lock")
        .take()
        .expect("the source was read");
    let at_source = public_check_records(&at_source);
    assert_eq!(
        at_source.len(),
        1,
        "only the access attempt precedes the read"
    );
    assert_eq!(at_source[0]["phase"], "access-attempt");
    let after = public_check_records(&fixture.audit());
    assert_eq!(after.len(), 2);
    assert_eq!(after[1]["phase"], "disclosure-release");
}

#[tokio::test]
async fn an_access_audit_failure_answers_503_before_the_source_is_read() {
    let fixture = public_check_runtime(Authority::RelyingAndCheck).await;
    fixture.mount_record(NUMBER, record("valid")).await;
    fs::write(&fixture.audit_path, b"{}\n").expect("audit tamper writes");
    let response = check(&fixture.http(), NUMBER, CODE).await;
    assert_eq!(response.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(problem_code(&response), "service.unavailable");
    assert_eq!(header(&response, "access-control-allow-origin"), Some("*"));
    assert_eq!(fixture.source_requests().await, 0);
    assert!(public_check_records(&fixture.audit()).is_empty());
}

#[tokio::test]
async fn a_release_audit_failure_answers_503_and_never_the_answer() {
    let fixture = public_check_runtime(Authority::RelyingAndCheck).await;
    fixture
        .mount_response(
            NUMBER,
            ResponseTemplate::new(200)
                .set_body_json(record("valid"))
                .set_delay(Duration::from_millis(300)),
        )
        .await;
    let server = fixture.http();
    let (response, ()) = tokio::join!(check(&server, NUMBER, CODE), async {
        fixture.wait_for_source_requests(1).await;
        fs::OpenOptions::new()
            .append(true)
            .open(&fixture.audit_path)
            .and_then(|mut file| file.write_all(b"{}\n"))
            .expect("audit tamper writes after the access attempt");
    });
    assert_eq!(response.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(problem_code(&response), "service.unavailable");
    assert_absent(
        &String::from_utf8_lossy(response.as_bytes()),
        &["Jordan Sample", PUBLIC_CHECK_ANSWER_SCHEMA],
        "the failure",
    );
    let records = public_check_records(&fixture.audit());
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["phase"], "access-attempt");
}

/// Test 17: a failing Source is a dependency failure, not a miss.
#[tokio::test]
async fn a_failing_source_is_a_dependency_failure_not_a_miss() {
    let fixture = public_check_runtime(Authority::RelyingAndCheck).await;
    fixture
        .mount_response("RN-FAIL-0001", ResponseTemplate::new(500))
        .await;
    fixture
        .mount_record("RN-FAIL-0002", json!({"lookup": "other"}))
        .await;
    let server = fixture.http();
    let validator = audit_validator();
    for number in ["RN-FAIL-0001", "RN-FAIL-0002"] {
        let response = check(&server, number, CODE).await;
        assert_eq!(
            response.status_code(),
            StatusCode::SERVICE_UNAVAILABLE,
            "{number}"
        );
        assert_eq!(problem_code(&response), "source.unavailable", "{number}");
        assert_eq!(header(&response, "access-control-allow-origin"), Some("*"));
        let records = public_check_records(&fixture.audit());
        let last = records.last().expect("the failure is audited");
        assert_eq!(last["phase"], "transient-failure", "{number}");
        assert_eq!(last["decision"], "dependency-failure", "{number}");
        assert!(validator.is_valid(last), "{last} meets its contract");
    }
}

/// A document number the selector profile accepts but the Source path cannot
/// carry is refused before any Source request: 503 source.unavailable
/// (ProblemCode::DependencyUnavailable). The audit holds the access attempt and
/// one terminal dependency-failure line (source-protocol), and the number and
/// code appear in neither the answer nor the audit.
#[tokio::test]
async fn a_number_the_source_path_cannot_carry_is_refused_before_the_source_is_read() {
    let fixture =
        public_check_runtime_with_routes(Authority::RelyingAndCheck, path_bound_pack_routes())
            .await;
    let server = fixture.http();
    let carryable = "RN-2026-004217";
    Mock::given(method("GET"))
        .and(path(format!("/records/{carryable}")))
        .respond_with(ResponseTemplate::new(200).set_body_json(record("valid")))
        .mount(&fixture.source)
        .await;
    for (index, number) in ["RN/2026/0042", "..\\..", "RN-100%25-4217"]
        .into_iter()
        .enumerate()
    {
        let response = check(&server, number, CODE).await;
        assert_eq!(
            response.status_code(),
            StatusCode::SERVICE_UNAVAILABLE,
            "{number}"
        );
        assert_eq!(problem_code(&response), "source.unavailable", "{number}");
        assert_eq!(header(&response, "access-control-allow-origin"), Some("*"));
        assert_eq!(fixture.source_requests().await, 0, "{number}");
        let records = public_check_records(&fixture.audit());
        assert_eq!(
            records.len(),
            2 * (index + 1),
            "{number}: an access line and a terminal line per refusal"
        );
        let [access, terminal] = &records[2 * index..] else {
            unreachable!("the slice holds this refusal's two lines");
        };
        assert_eq!(access["phase"], "access-attempt", "{number}");
        assert_eq!(access["decision"], "authorized", "{number}");
        assert_eq!(terminal["phase"], "transient-failure", "{number}");
        assert_eq!(terminal["decision"], "dependency-failure", "{number}");
        assert_eq!(terminal["safeErrorCategory"], "source-protocol", "{number}");
        assert_eq!(terminal["operation"], access["operation"], "{number}");
        assert_absent(
            &format!("{}{}", String::from_utf8_lossy(response.as_bytes()), fixture.audit()),
            &[number, CODE],
            "the refusal and its audit",
        );
    }
    let response = check(&server, carryable, CODE).await;
    assert_eq!(response.status_code(), StatusCode::OK);
    assert_eq!(fixture.source_requests().await, 1);
}

/// Test 18: the route alone allows any origin, without credentials, and its
/// preflight names exactly what a browser page needs.
#[tokio::test]
async fn only_the_check_route_is_readable_cross_origin() {
    let fixture = public_check_runtime(Authority::RelyingAndCheck).await;
    fixture.mount_record(NUMBER, record("valid")).await;
    let server = fixture.http();

    let preflight = server
        .method(Method::OPTIONS, PUBLIC_CHECK_ROUTE)
        .add_header("origin", BROWSER_ORIGIN)
        .add_header("access-control-request-method", "POST")
        .add_header("access-control-request-headers", "content-type")
        .await;
    assert_eq!(preflight.status_code(), StatusCode::OK);
    assert!(preflight.as_bytes().is_empty());
    for (name, value) in [
        ("access-control-allow-origin", "*"),
        ("access-control-allow-methods", "POST"),
        ("access-control-allow-headers", "content-type"),
        ("access-control-max-age", "600"),
        ("cross-origin-resource-policy", "cross-origin"),
        ("cache-control", "no-store"),
    ] {
        assert_eq!(header(&preflight, name), Some(value), "preflight {name}");
    }
    assert_eq!(header(&preflight, "access-control-allow-credentials"), None);
    assert_eq!(fixture.source_requests().await, 0);
    assert_eq!(fixture.audit(), "", "a preflight writes no audit");

    let responses = [
        check(&server, NUMBER, CODE).await,
        check(&server, NUMBER, "AAAAAAAAAAAAAAAAAAAAAAAA").await,
        check(&server, "ab", CODE).await,
        server.get(PUBLIC_CHECK_ROUTE).await,
    ];
    let statuses: Vec<_> = responses.iter().map(TestResponse::status_code).collect();
    assert_eq!(
        statuses,
        [
            StatusCode::OK,
            StatusCode::NOT_FOUND,
            StatusCode::BAD_REQUEST,
            StatusCode::NOT_FOUND
        ]
    );
    for response in &responses {
        assert_eq!(header(response, "access-control-allow-origin"), Some("*"));
        assert_eq!(header(response, "access-control-allow-credentials"), None);
        assert_eq!(
            header(response, "cross-origin-resource-policy"),
            Some("cross-origin")
        );
        assert_eq!(header(response, "cache-control"), Some("no-store"));
    }

    let health = server
        .get("/health")
        .add_header("origin", BROWSER_ORIGIN)
        .await;
    assert_eq!(header(&health, "access-control-allow-origin"), None);
    assert_eq!(
        header(&health, "cross-origin-resource-policy"),
        Some("same-origin")
    );
}

/// Test 19: the route reads no header but `Content-Type`. Canary values in
/// every other header a browser or proxy sends change neither the answer nor
/// the miss, reach neither the log nor the audit, and an inbound trace is
/// replaced by one the server mints.
#[test]
fn the_check_reads_no_header_but_its_content_type() {
    use chrono::SubsecRound as _;
    const CANARY_TRACE_ID: &str = "c0ffeec0ffeec0ffeec0ffeec0ffee01";
    let canaries = [
        ("authorization", "Bearer canary-authorization-value"),
        ("cookie", "session=canary-cookie-value"),
        ("user-agent", "canary-user-agent-value"),
        ("accept", "application/canary-accept-value"),
        ("forwarded", "for=192.0.2.77;by=canary-forwarded-value"),
        ("x-forwarded-for", "192.0.2.78"),
        (
            "traceparent",
            "00-c0ffeec0ffeec0ffeec0ffeec0ffee01-c0ffeec0ffee0001-01",
        ),
    ];
    let audit = Arc::new(Mutex::new(String::new()));
    let audit_out = Arc::clone(&audit);
    let logs = capture_evidence_logs(|| async move {
        let fixture = public_check_runtime(Authority::RelyingAndCheck).await;
        fixture.mount_record(NUMBER, record("valid")).await;
        let server = fixture.http_at(Utc::now().trunc_subsecs(0));
        for code in [CODE, "AAAAAAAAAAAAAAAAAAAAAAAA"] {
            let plain = check(&server, NUMBER, code).await;
            let mut request = server.post(PUBLIC_CHECK_ROUTE);
            for (name, value) in canaries {
                request = request.add_header(name, value);
            }
            let canary = request.json(&check_body(NUMBER, code)).await;
            assert_eq!(comparable(&plain), comparable(&canary), "{code}");
            assert_ne!(trace_id_of(&canary), CANARY_TRACE_ID);
        }
        *audit_out.lock().expect("audit lock") = fixture.audit();
    });

    let requests: Vec<&Value> = logs
        .iter()
        .filter(|record| record["target"] == json!(REQUEST_LOG_TARGET))
        .collect();
    assert_eq!(requests.len(), 4, "one operational record per request");
    for record in &requests {
        assert_eq!(record["fields"]["route"], PUBLIC_CHECK_ROUTE);
        assert_ne!(record["fields"]["trace_id"], CANARY_TRACE_ID);
    }
    let logged = serde_json::to_string(&logs).expect("logs serialize");
    let audit = audit.lock().expect("audit lock").clone();
    assert_eq!(public_check_records(&audit).len(), 8);
    let mut needles: Vec<&str> = canaries.iter().map(|(_, value)| *value).collect();
    needles.extend(["canary", "c0ffee", "192.0.2.7", CODE, SOURCE_TOKEN]);
    assert_absent(&logged, &needles, "the operational log");
    assert_absent(&audit, &needles, "the audit");
}
