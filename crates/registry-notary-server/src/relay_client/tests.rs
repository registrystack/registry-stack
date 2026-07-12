// SPDX-License-Identifier: Apache-2.0

use super::*;

use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::extract::{Request, State};
use axum::http::{header, Response, StatusCode};
use axum::routing::{get, post};
use axum::Router;
use axum_test::TestServer;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine as _;
use registry_notary_core::StandaloneRegistryNotaryConfig;
use registry_platform_authcommon::fingerprint_api_key;
use registry_platform_crypto::canonicalize_json;
use registry_platform_httputil::destination::{
    DestinationProfile, ServiceHopDataDestinationPolicy, MAX_SERVICE_HOP_OPERATION_TIMEOUT,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Mutex};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

const PROFILE_ID: &str = "dhis2.tracker.enrollment-status.exact";
const PROFILE_VERSION: &str = "1";
const CONTRACT_HASH: &str =
    "sha256:a2d0e7588bc1bbeb0caf3247703a15d81830875f5e84dd257f7dc163d3a4ecb6";
const PURPOSE: &str = "program-enrollment-verification";
const INPUT_NAME: &str = "tracked_entity";
const INPUT_VALUE: &str = "PQfMcpmXeFE";
const OUTPUT_NAME: &str = "status";
const EXPECTED_ISSUER: &str = "https://issuer.example.test";
const EXPECTED_AUDIENCE: &str = "registry-relay";
const EXPECTED_SUBJECT: &str = "registry-notary";
const EXPECTED_CLIENT_ID: &str = "registry-notary";
const EXPECTED_SCOPE: &str = "registry:consult:dhis2-enrollment-status";
const RESULT_SCHEMA: &str = "registry.relay.consultation-result.v1";
const CONTRACT_DOMAIN: &[u8] = b"registry.relay.consultation-contract.v1\0";
const MAX_RESULT_BYTES: usize = 64 * 1024;
const EVALUATION_ID: &str = "01JYZZZZZZZZZZZZZZZZZZZZZZ";
const CONSULTATION_ID: &str = "01K05H0JKP4VSQNYCZ0TN4D87R";
const PROFILE_ROUTE: &str = "/v1/consultations/dhis2.tracker.enrollment-status.exact/versions/1";
const EXECUTE_ROUTE: &str =
    "/v1/consultations/dhis2.tracker.enrollment-status.exact/versions/1/execute";
const NOTARY_API_KEY: &str = "notary-relay-vertical-api-key";
const NOTARY_API_KEY_HASH_ENV: &str = "REGISTRY_NOTARY_RELAY_VERTICAL_API_KEY_HASH";
const NOTARY_AUDIT_SECRET_ENV: &str = "REGISTRY_NOTARY_RELAY_VERTICAL_AUDIT_SECRET";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EvaluationIdMode {
    Fixed,
    EchoCanonical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ObservedOperation {
    Metadata,
    Execute,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct Observation {
    operation: ObservedOperation,
    exact_authorization: bool,
    exact_accept: bool,
    exact_content_type: bool,
    exact_purpose: bool,
    exact_evaluation_id: bool,
    exact_body: bool,
    forbidden_ambient_headers_absent: bool,
}

#[derive(Clone)]
struct FakeState {
    inner: Arc<FakeStateInner>,
}

struct FakeStateInner {
    metadata: Mutex<WireResponse>,
    execute: Mutex<WireResponse>,
    expected_token: Mutex<String>,
    observations: Mutex<Vec<Observation>>,
    metadata_calls: AtomicUsize,
    execute_calls: AtomicUsize,
    evaluation_id_mode: EvaluationIdMode,
}

#[derive(Clone)]
struct WireResponse {
    status: StatusCode,
    body: Vec<u8>,
    location: Option<&'static str>,
    content_types: Vec<&'static str>,
}

impl WireResponse {
    fn ok(body: Vec<u8>) -> Self {
        Self {
            status: StatusCode::OK,
            body,
            location: None,
            content_types: vec!["application/json"],
        }
    }

    fn with_content_types(mut self, content_types: Vec<&'static str>) -> Self {
        self.content_types = content_types;
        self
    }
}

struct FakeRelay {
    origin: String,
    state: FakeState,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl FakeRelay {
    async fn start(metadata: WireResponse, execute: WireResponse) -> Self {
        Self::start_with_evaluation_id_mode(metadata, execute, EvaluationIdMode::Fixed).await
    }

    async fn start_echoing_evaluation_id(metadata: WireResponse, execute: WireResponse) -> Self {
        Self::start_with_evaluation_id_mode(metadata, execute, EvaluationIdMode::EchoCanonical)
            .await
    }

    async fn start_with_evaluation_id_mode(
        metadata: WireResponse,
        execute: WireResponse,
        evaluation_id_mode: EvaluationIdMode,
    ) -> Self {
        let state = FakeState {
            inner: Arc::new(FakeStateInner {
                metadata: Mutex::new(metadata),
                execute: Mutex::new(execute),
                expected_token: Mutex::new(test_token()),
                observations: Mutex::new(Vec::new()),
                metadata_calls: AtomicUsize::new(0),
                execute_calls: AtomicUsize::new(0),
                evaluation_id_mode,
            }),
        };
        let app = Router::new()
            .route(PROFILE_ROUTE, get(metadata_handler))
            .route(EXECUTE_ROUTE, post(execute_handler))
            .with_state(state.clone());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (shutdown, receiver) = oneshot::channel();
        let task = tokio::spawn(async move {
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = receiver.await;
                })
                .await
                .unwrap();
        });
        Self {
            origin: format!("http://{address}/"),
            state,
            shutdown: Some(shutdown),
            task,
        }
    }

    async fn set_execute(&self, response: WireResponse) {
        *self.state.inner.execute.lock().await = response;
    }

    async fn set_expected_token(&self, token: &str) {
        *self.state.inner.expected_token.lock().await = token.to_owned();
    }

    async fn observations(&self) -> Vec<Observation> {
        self.state.inner.observations.lock().await.clone()
    }

    fn execute_calls(&self) -> usize {
        self.state.inner.execute_calls.load(Ordering::SeqCst)
    }

    fn metadata_calls(&self) -> usize {
        self.state.inner.metadata_calls.load(Ordering::SeqCst)
    }

    async fn shutdown(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.task.await.unwrap();
    }
}

async fn metadata_handler(State(state): State<FakeState>, request: Request) -> Response<Body> {
    state.inner.metadata_calls.fetch_add(1, Ordering::SeqCst);
    let expected_token = state.inner.expected_token.lock().await.clone();
    let observation =
        observe_request(ObservedOperation::Metadata, request, &expected_token, None).await;
    state.inner.observations.lock().await.push(observation);
    wire_response(state.inner.metadata.lock().await.clone())
}

async fn execute_handler(State(state): State<FakeState>, request: Request) -> Response<Body> {
    state.inner.execute_calls.fetch_add(1, Ordering::SeqCst);
    let expected_token = state.inner.expected_token.lock().await.clone();
    let evaluation_id = request
        .headers()
        .get("registry-notary-evaluation-id")
        .and_then(|value| value.to_str().ok())
        .map(str::to_string);
    let expected_evaluation_id = match state.inner.evaluation_id_mode {
        EvaluationIdMode::Fixed => Some(EVALUATION_ID),
        EvaluationIdMode::EchoCanonical => evaluation_id
            .as_deref()
            .filter(|value| ulid::Ulid::from_string(value).is_ok()),
    };
    let observation = observe_request(
        ObservedOperation::Execute,
        request,
        &expected_token,
        expected_evaluation_id,
    )
    .await;
    state.inner.observations.lock().await.push(observation);
    let mut response = state.inner.execute.lock().await.clone();
    if state.inner.evaluation_id_mode == EvaluationIdMode::EchoCanonical {
        if let Some(evaluation_id) = expected_evaluation_id {
            let mut body: Value = serde_json::from_slice(&response.body)
                .expect("echoing fake Relay result must contain JSON");
            body["notary_evaluation_id"] = json!(evaluation_id);
            response.body = serde_json::to_vec(&body).expect("echoed Relay result serializes");
        }
    }
    wire_response(response)
}

async fn observe_request(
    operation: ObservedOperation,
    request: Request,
    expected_token: &str,
    expected_evaluation_id: Option<&str>,
) -> Observation {
    let headers = request.headers();
    let exact_authorization = headers
        .get(header::AUTHORIZATION)
        .is_some_and(|value| value.as_bytes() == format!("Bearer {expected_token}").as_bytes());
    let exact_accept = headers
        .get(header::ACCEPT)
        .is_some_and(|value| value == "application/json");
    let exact_content_type = match operation {
        ObservedOperation::Metadata => !headers.contains_key(header::CONTENT_TYPE),
        ObservedOperation::Execute => headers
            .get(header::CONTENT_TYPE)
            .is_some_and(|value| value == "application/json"),
    };
    let exact_purpose = match operation {
        ObservedOperation::Metadata => !headers.contains_key("data-purpose"),
        ObservedOperation::Execute => headers
            .get("data-purpose")
            .is_some_and(|value| value == PURPOSE),
    };
    let exact_evaluation_id = match operation {
        ObservedOperation::Metadata => !headers.contains_key("registry-notary-evaluation-id"),
        ObservedOperation::Execute => headers
            .get("registry-notary-evaluation-id")
            .is_some_and(|value| expected_evaluation_id.is_some_and(|expected| value == expected)),
    };
    let forbidden_ambient_headers_absent = [
        header::COOKIE.as_str(),
        "forwarded",
        "x-forwarded-for",
        "proxy-authorization",
    ]
    .iter()
    .all(|name| !headers.contains_key(*name));
    let body = to_bytes(request.into_body(), 8 * 1024).await.unwrap();
    let exact_body = match operation {
        ObservedOperation::Metadata => body.is_empty(),
        ObservedOperation::Execute => {
            body.as_ref() == br#"{"inputs":{"tracked_entity":"PQfMcpmXeFE"}}"#
        }
    };
    Observation {
        operation,
        exact_authorization,
        exact_accept,
        exact_content_type,
        exact_purpose,
        exact_evaluation_id,
        exact_body,
        forbidden_ambient_headers_absent,
    }
}

fn wire_response(response: WireResponse) -> Response<Body> {
    let mut builder = Response::builder().status(response.status);
    for content_type in response.content_types {
        builder = builder.header(header::CONTENT_TYPE, content_type);
    }
    if let Some(location) = response.location {
        builder = builder.header(header::LOCATION, location);
    }
    builder.body(Body::from(response.body)).unwrap()
}

fn contract_value() -> Value {
    serde_json::from_str(include_str!(
        "../../../registry-relay/profiles/dhis2-2.41.9-enrollment-status/public-contract.json"
    ))
    .unwrap()
}

fn presence_contract_value() -> Value {
    let mut contract = contract_value();
    contract["spec"]["output_mode"] = json!("presence_only");
    contract["spec"]["output"] = json!({});
    contract["spec"]["acquisition"]["class"] = json!("bounded_full_record");
    contract["spec"]["acquisition"]["fields"] = json!({
        "record": {
            "type": "object",
            "nullable": false,
            "reject_unknown_fields": true,
            "fields": {
                "registration": {
                    "required": true,
                    "schema": {
                        "type": "object",
                        "nullable": false,
                        "reject_unknown_fields": true,
                        "fields": {
                            "status": {
                                "required": true,
                                "schema": {
                                    "type": "string",
                                    "nullable": false,
                                    "max_bytes": 64
                                }
                            }
                        }
                    }
                },
                "identifiers": {
                    "required": true,
                    "schema": {
                        "type": "array",
                        "nullable": false,
                        "max_items": 8,
                        "items": {
                            "type": "string",
                            "nullable": false,
                            "max_bytes": 128
                        }
                    }
                }
            }
        }
    });
    contract
}

fn metadata_value_for_contract(contract: &Value, contract_hash: &str) -> Value {
    let contract_json = String::from_utf8(canonicalize_json(contract).unwrap()).unwrap();
    json!({
        "contract_hash": contract_hash,
        "contract_json": contract_json,
    })
}

fn metadata_value() -> Value {
    metadata_value_for_contract(&contract_value(), CONTRACT_HASH)
}

fn metadata_response() -> WireResponse {
    WireResponse::ok(serde_json::to_vec(&metadata_value()).unwrap())
}

fn typed_hash(domain: &[u8], value: &Value) -> String {
    let canonical = canonicalize_json(value).unwrap();
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(canonical);
    let mut encoded = String::from("sha256:");
    for byte in hasher.finalize() {
        use std::fmt::Write as _;
        write!(&mut encoded, "{byte:02x}").unwrap();
    }
    encoded
}

fn result_value() -> Value {
    json!({
        "schema": RESULT_SCHEMA,
        "consultation_id": CONSULTATION_ID,
        "notary_evaluation_id": EVALUATION_ID,
        "profile": {
            "id": PROFILE_ID,
            "version": PROFILE_VERSION,
            "contract_hash": CONTRACT_HASH,
        },
        "outcome": "match",
        "data": { "status": "ACTIVE" },
        "provenance": {
            "relay_acquired_at": "2026-07-12T00:00:00Z",
            "source_observed_at": null,
            "source_revision": null,
            "acquisition_class": "source_projected_exact",
            "integration_pack": {
                "id": "dhis2.tracker.enrollment-status",
                "version": "1",
                "hash": "sha256:ec0136be504e3f98539f9e0ec10e59532ff793dbadc2e66ea1c017a632da6ac4"
            },
            "policy_id": "relay.dhis2.tracker.enrollment-status.exact",
            "policy_hash": "sha256:0456a93b515b9d60aff9f06633c792f4e63ede2f7657ef37bb2f58a840380b1f",
            "consent": {
                "outcome": "not_required",
                "verifier_id": null,
                "verifier_revision": null,
                "checked_at": null,
                "expires_at": null,
                "revocation_status": "not_applicable"
            }
        }
    })
}

fn presence_result_value(contract_hash: &str, outcome: &str, data: Value) -> Value {
    let mut result = result_value();
    result["profile"]["contract_hash"] = json!(contract_hash);
    result["outcome"] = json!(outcome);
    result["data"] = data;
    result["provenance"]["acquisition_class"] = json!("bounded_full_record");
    result
}

fn result_response() -> WireResponse {
    WireResponse::ok(serde_json::to_vec(&result_value()).unwrap())
}

fn test_claims() -> Value {
    json!({
        "iss": EXPECTED_ISSUER,
        "aud": [EXPECTED_AUDIENCE, "registry-operations"],
        "sub": EXPECTED_SUBJECT,
        "azp": EXPECTED_CLIENT_ID,
        "client_id": EXPECTED_CLIENT_ID,
        "scope": format!("registry:read {EXPECTED_SCOPE} registry:audit"),
        "iat": 1_700_000_000_i64,
        "nbf": 1_700_000_000_i64,
        "exp": 4_102_444_800_i64,
        "jti": "relay-test-token-1",
        "tenant": { "id": "test-country" },
    })
}

fn token_for_claims(claims: &Value) -> String {
    token_for_claims_and_signature(claims, b"relay-test-signature-SENSITIVE")
}

fn token_for_claims_and_signature(claims: &Value, signature: &[u8]) -> String {
    let header = json!({
        "alg": "RS256",
        "kid": "relay-test-key",
        "typ": "at+jwt",
        "x5t": "relay-test-thumbprint",
    });
    format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap()),
        URL_SAFE_NO_PAD.encode(signature),
    )
}

fn test_token() -> String {
    token_for_claims(&test_claims())
}

struct TestTokenFile {
    _directory: tempfile::TempDir,
    path: PathBuf,
}

impl TestTokenFile {
    fn new(token: &str) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("relay.jwt");
        std::fs::write(&path, token.as_bytes()).unwrap();
        Self {
            _directory: directory,
            path,
        }
    }

    fn replace(&self, token: &str) {
        let replacement = self.path.with_extension("jwt.next");
        std::fs::write(&replacement, token.as_bytes()).unwrap();
        std::fs::rename(replacement, &self.path).unwrap();
    }

    fn remove(&self) {
        std::fs::remove_file(&self.path).unwrap();
    }

    fn credential(&self) -> RelayWorkloadCredentialFile {
        RelayWorkloadCredentialFile::new(self.path.clone()).unwrap()
    }
}

fn client_with_hash(
    server: &FakeRelay,
    token_file: &TestTokenFile,
    contract_hash: &str,
) -> RelayConsultationClient {
    client_with_result(
        server,
        token_file,
        contract_hash,
        RelayExpectedResult::projected_string(OUTPUT_NAME).unwrap(),
    )
}

fn client_with_result(
    server: &FakeRelay,
    token_file: &TestTokenFile,
    contract_hash: &str,
    expected_result: RelayExpectedResult,
) -> RelayConsultationClient {
    let destination = ServiceHopDataDestinationPolicy::new(
        "registry-notary-relay",
        &server.origin,
        DestinationProfile::LoopbackDevelopmentHttp,
        &[],
    )
    .unwrap();
    RelayConsultationClient::new(
        destination,
        token_file.credential(),
        RelayProfilePin::new(PROFILE_ID, PROFILE_VERSION, contract_hash).unwrap(),
        PURPOSE,
        INPUT_NAME,
        expected_result,
    )
    .unwrap()
}

fn client(server: &FakeRelay, token_file: &TestTokenFile) -> RelayConsultationClient {
    client_with_hash(server, token_file, CONTRACT_HASH)
}

async fn verified(server: &FakeRelay, token_file: &TestTokenFile) -> VerifiedRelayClient {
    client(server, token_file).verify_profile().await.unwrap()
}

fn credential_for_path(path: PathBuf) -> Result<RelayWorkloadCredentialFile, RelayClientError> {
    RelayWorkloadCredentialFile::new(path)
}

fn all_shape_checks_pass(observation: &Observation) -> bool {
    observation.exact_authorization
        && observation.exact_accept
        && observation.exact_content_type
        && observation.exact_purpose
        && observation.exact_evaluation_id
        && observation.exact_body
        && observation.forbidden_ambient_headers_absent
}

struct ScopedEnvironment {
    previous: Vec<(&'static str, Option<std::ffi::OsString>)>,
}

impl ScopedEnvironment {
    fn set(values: &[(&'static str, &str)]) -> Self {
        let previous = values
            .iter()
            .map(|(name, value)| {
                let previous = std::env::var_os(name);
                // SAFETY: these names are unique to this test module and the
                // guard restores their previous values after the test.
                unsafe { std::env::set_var(name, value) };
                (*name, previous)
            })
            .collect();
        Self { previous }
    }
}

impl Drop for ScopedEnvironment {
    fn drop(&mut self) {
        for (name, value) in self.previous.drain(..).rev() {
            // SAFETY: this guard exclusively owns the unique test variables.
            unsafe {
                if let Some(value) = value {
                    std::env::set_var(name, value);
                } else {
                    std::env::remove_var(name);
                }
            }
        }
    }
}

fn assembled_notary_config(
    relay: &FakeRelay,
    token_file: &TestTokenFile,
    audit_path: &std::path::Path,
) -> StandaloneRegistryNotaryConfig {
    let relay_origin = serde_json::to_string(&relay.origin).expect("Relay origin serializes");
    let token_path =
        serde_json::to_string(&token_file.path.to_string_lossy()).expect("token path serializes");
    let audit_path =
        serde_json::to_string(&audit_path.to_string_lossy()).expect("audit path serializes");
    serde_norway::from_str(&format!(
        r#"
deployment:
  profile: local
server:
  bind: 127.0.0.1:0
auth:
  mode: api_key
  api_keys:
    - id: relay-vertical-verifier
      fingerprint:
        provider: env
        name: {NOTARY_API_KEY_HASH_ENV}
      scopes: [registry:evidence:dhis2-enrollment-status]
audit:
  sink: file
  path: {audit_path}
  hash_secret_env: {NOTARY_AUDIT_SECRET_ENV}
evidence:
  enabled: true
  service_id: notary-relay-vertical.test
  allowed_purposes: [{PURPOSE}]
  relay:
    base_url: {relay_origin}
    token_file: {token_path}
    allow_insecure_localhost: true
  claims:
    - id: dhis2-enrollment-known
      title: DHIS2 enrollment exists
      version: "1"
      subject_type: person
      evidence_mode:
        type: registry_backed
        consultations:
          enrollment:
            profile:
              id: {PROFILE_ID}
              version: "{PROFILE_VERSION}"
              contract_hash: {CONTRACT_HASH}
            inputs:
              {INPUT_NAME}: target.id
      value:
        type: boolean
      purpose: {PURPOSE}
      required_scopes: [registry:evidence:dhis2-enrollment-status]
      rule:
        type: exists
        source: enrollment
      disclosure:
        default: value
        allowed: [value, redacted]
      formats: [application/vnd.registry-notary.claim-result+json]
    - id: dhis2-enrollment-status
      title: DHIS2 enrollment status
      version: "1"
      subject_type: person
      evidence_mode:
        type: registry_backed
        consultations:
          enrollment:
            profile:
              id: {PROFILE_ID}
              version: "{PROFILE_VERSION}"
              contract_hash: {CONTRACT_HASH}
            inputs:
              {INPUT_NAME}: target.id
      value:
        type: string
      purpose: {PURPOSE}
      required_scopes: [registry:evidence:dhis2-enrollment-status]
      rule:
        type: extract
        source: enrollment
        field: {OUTPUT_NAME}
      disclosure:
        default: value
        allowed: [value, redacted]
      formats: [application/vnd.registry-notary.claim-result+json]
"#,
    ))
    .expect("assembled Notary configuration parses")
}

#[tokio::test]
async fn assembled_notary_relay_journey_activates_and_coalesces_two_claims() {
    let api_key_fingerprint = fingerprint_api_key(NOTARY_API_KEY);
    let _environment = ScopedEnvironment::set(&[
        (NOTARY_API_KEY_HASH_ENV, &api_key_fingerprint),
        (NOTARY_AUDIT_SECRET_ENV, "0123456789abcdef0123456789abcdef"),
    ]);
    let token_file = TestTokenFile::new(&test_token());
    let relay =
        FakeRelay::start_echoing_evaluation_id(metadata_response(), result_response()).await;
    let directory = tempfile::tempdir().expect("temporary Notary directory");
    let audit_path = directory.path().join("notary-audit.jsonl");
    let config = assembled_notary_config(&relay, &token_file, &audit_path);

    let runtime = crate::compile_notary_runtime(config).expect("Notary runtime compiles");
    assert_eq!(relay.metadata_calls(), 0);
    assert_eq!(relay.execute_calls(), 0);
    let runtime = runtime
        .activate_relay()
        .await
        .expect("Notary activates the pinned Relay profile before serving");
    assert_eq!(relay.metadata_calls(), 1);
    assert_eq!(relay.execute_calls(), 0);
    let app = crate::notary_router_from_runtime(runtime)
        .expect("activated Registry-backed runtime is serve-ready");
    let notary = TestServer::builder().http_transport().build(app);

    let response = notary
        .post("/v1/evaluations")
        .add_header("x-api-key", NOTARY_API_KEY)
        .json(&json!({
            "target": { "type": "Person", "id": INPUT_VALUE },
            "claims": ["dhis2-enrollment-known", "dhis2-enrollment-status"],
            "disclosure": "value",
            "purpose": PURPOSE,
        }))
        .await;
    response.assert_status_ok();
    let public: Value = response.json();
    let results = public["results"]
        .as_array()
        .expect("public response contains claim results");
    assert_eq!(results.len(), 2);
    let known = results
        .iter()
        .find(|result| result["claim_id"] == "dhis2-enrollment-known")
        .expect("existence claim is returned");
    let status = results
        .iter()
        .find(|result| result["claim_id"] == "dhis2-enrollment-status")
        .expect("status claim is returned");
    assert_eq!(known["value"], json!(true));
    assert_eq!(status["value"], json!("ACTIVE"));
    assert!(results
        .iter()
        .all(|result| result["provenance"]["used"]["source_count"] == json!(1)));
    let evaluation_id = results[0]["evaluation_id"]
        .as_str()
        .expect("public Notary evaluation id is present");
    assert!(ulid::Ulid::from_string(evaluation_id).is_ok());
    assert!(results
        .iter()
        .all(|result| result["evaluation_id"] == evaluation_id));

    assert_eq!(relay.metadata_calls(), 1);
    assert_eq!(relay.execute_calls(), 1);
    let observations = relay.observations().await;
    assert_eq!(observations.len(), 2);
    assert_eq!(observations[0].operation, ObservedOperation::Metadata);
    assert_eq!(observations[1].operation, ObservedOperation::Execute);
    assert!(observations.iter().all(all_shape_checks_pass));

    let public_wire = serde_json::to_string(&public).expect("public response serializes");
    assert!(!public_wire.contains(CONSULTATION_ID));
    assert!(!public_wire.contains("relay_consultation_ids"));
    assert!(!public_wire.contains("consultation_id"));

    let audit = std::fs::read_to_string(&audit_path).expect("restricted Notary audit is durable");
    let audit_record = audit
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("audit envelope parses"))
        .find_map(|envelope| {
            (envelope["record"]["path"] == "/v1/evaluations").then(|| envelope["record"].clone())
        })
        .expect("evaluation audit record exists");
    assert_eq!(audit_record["status"], json!(200));
    assert_eq!(audit_record["verification_id"], evaluation_id);
    assert_eq!(
        audit_record["relay_consultation_ids"],
        json!([CONSULTATION_ID])
    );
    assert_eq!(audit_record["source_read_count"], json!(1));
    assert_eq!(audit_record["forwarded"], json!(true));

    drop(notary);
    relay.shutdown().await;
}

#[tokio::test]
async fn exact_profile_and_execute_journey_is_strict_and_bounded() {
    let token_file = TestTokenFile::new(&test_token());
    let server = FakeRelay::start(metadata_response(), result_response()).await;
    let client = verified(&server, &token_file).await;
    assert_eq!(client.profile().pin().id(), PROFILE_ID);
    assert_eq!(client.profile().pin().version(), PROFILE_VERSION);
    assert_eq!(client.profile().pin().contract_hash(), CONTRACT_HASH);
    assert_eq!(client.profile().output_name(), Some(OUTPUT_NAME));

    let result = client
        .execute(EVALUATION_ID, Zeroizing::new(INPUT_VALUE.to_string()))
        .await
        .unwrap();
    assert_eq!(result.consultation_id().to_string(), CONSULTATION_ID);
    assert_eq!(result.outcome(), RelayConsultationOutcome::Match);
    let data = result.data().unwrap();
    assert_eq!(data.name(), OUTPUT_NAME);
    assert_eq!(data.value(), "ACTIVE");
    let observations = server.observations().await;
    assert_eq!(observations.len(), 2);
    assert_eq!(observations[0].operation, ObservedOperation::Metadata);
    assert_eq!(observations[1].operation, ObservedOperation::Execute);
    assert!(observations.iter().all(all_shape_checks_pass));
    server.shutdown().await;
}

#[tokio::test]
async fn presence_only_profile_validates_complete_acquisition_and_releases_no_output() {
    let token_file = TestTokenFile::new(&test_token());
    let contract = presence_contract_value();
    let contract_hash = typed_hash(CONTRACT_DOMAIN, &contract);
    let metadata = WireResponse::ok(
        serde_json::to_vec(&metadata_value_for_contract(&contract, &contract_hash)).unwrap(),
    );
    let result = WireResponse::ok(
        serde_json::to_vec(&presence_result_value(&contract_hash, "match", json!({}))).unwrap(),
    );
    let server = FakeRelay::start(metadata, result).await;
    let client = client_with_result(
        &server,
        &token_file,
        &contract_hash,
        RelayExpectedResult::PresenceOnly,
    )
    .verify_profile()
    .await
    .expect("presence-only profile activates after complete contract validation");
    assert_eq!(client.profile().output_name(), None);

    let result = client
        .execute(EVALUATION_ID, Zeroizing::new(INPUT_VALUE.to_string()))
        .await
        .expect("empty-object match result validates");
    assert_eq!(result.outcome(), RelayConsultationOutcome::Match);
    assert!(result.data().is_none());
    assert!(matches!(
        result.match_data(),
        Some(RelayMatchData::PresenceOnly)
    ));

    server
        .set_execute(WireResponse::ok(
            serde_json::to_vec(&presence_result_value(
                &contract_hash,
                "no_match",
                Value::Null,
            ))
            .unwrap(),
        ))
        .await;
    let no_match = client
        .execute(EVALUATION_ID, Zeroizing::new(INPUT_VALUE.to_string()))
        .await
        .expect("null no-match result validates");
    assert_eq!(no_match.outcome(), RelayConsultationOutcome::NoMatch);
    assert!(no_match.match_data().is_none());
    server.shutdown().await;
}

#[tokio::test]
async fn presence_only_metadata_mode_and_complete_acquisition_fail_closed() {
    let token_file = TestTokenFile::new(&test_token());
    let mut cases = Vec::new();

    let mut implicit_projected = presence_contract_value();
    implicit_projected["spec"]
        .as_object_mut()
        .unwrap()
        .remove("output_mode");
    cases.push(implicit_projected);

    let mut leaked_output = presence_contract_value();
    leaked_output["spec"]["output"] = json!({
        "status": {"type": "string", "nullable": false}
    });
    cases.push(leaked_output);

    let mut incomplete_acquisition = presence_contract_value();
    incomplete_acquisition["spec"]["acquisition"]["fields"]["record"]["reject_unknown_fields"] =
        json!(false);
    cases.push(incomplete_acquisition);

    let mut excessive_depth = presence_contract_value();
    let mut schema = json!({"type": "string", "nullable": false, "max_bytes": 1});
    for _ in 0..8 {
        schema = json!({
            "type": "object",
            "nullable": false,
            "reject_unknown_fields": true,
            "fields": {"nested": {"required": true, "schema": schema}}
        });
    }
    excessive_depth["spec"]["acquisition"]["fields"] = json!({"record": schema});
    cases.push(excessive_depth);

    for contract in cases {
        let hash = typed_hash(CONTRACT_DOMAIN, &contract);
        let server = FakeRelay::start(
            WireResponse::ok(
                serde_json::to_vec(&metadata_value_for_contract(&contract, &hash)).unwrap(),
            ),
            result_response(),
        )
        .await;
        assert_eq!(
            client_with_result(
                &server,
                &token_file,
                &hash,
                RelayExpectedResult::PresenceOnly,
            )
            .verify_profile()
            .await
            .expect_err("invalid presence contract must fail activation"),
            RelayClientError::InvalidProfileMetadata
        );
        server.shutdown().await;
    }

    let presence = presence_contract_value();
    let presence_hash = typed_hash(CONTRACT_DOMAIN, &presence);
    let server = FakeRelay::start(
        WireResponse::ok(
            serde_json::to_vec(&metadata_value_for_contract(&presence, &presence_hash)).unwrap(),
        ),
        result_response(),
    )
    .await;
    assert_eq!(
        client_with_result(
            &server,
            &token_file,
            &presence_hash,
            RelayExpectedResult::projected_string(OUTPUT_NAME).unwrap(),
        )
        .verify_profile()
        .await
        .expect_err("projected-string expectation cannot consume an outputless profile"),
        RelayClientError::InvalidProfileMetadata
    );
    server.shutdown().await;

    let projected = contract_value();
    let projected_hash = typed_hash(CONTRACT_DOMAIN, &projected);
    let server = FakeRelay::start(
        WireResponse::ok(
            serde_json::to_vec(&metadata_value_for_contract(&projected, &projected_hash)).unwrap(),
        ),
        result_response(),
    )
    .await;
    assert_eq!(
        client_with_result(
            &server,
            &token_file,
            &projected_hash,
            RelayExpectedResult::PresenceOnly,
        )
        .verify_profile()
        .await
        .expect_err("presence expectation cannot consume a projected profile"),
        RelayClientError::InvalidProfileMetadata
    );
    server.shutdown().await;
}

#[tokio::test]
async fn presence_only_result_rejects_payloads_and_wrong_outcome_shapes() {
    let token_file = TestTokenFile::new(&test_token());
    let contract = presence_contract_value();
    let contract_hash = typed_hash(CONTRACT_DOMAIN, &contract);
    let server = FakeRelay::start(
        WireResponse::ok(
            serde_json::to_vec(&metadata_value_for_contract(&contract, &contract_hash)).unwrap(),
        ),
        WireResponse::ok(
            serde_json::to_vec(&presence_result_value(&contract_hash, "match", json!({}))).unwrap(),
        ),
    )
    .await;
    let client = client_with_result(
        &server,
        &token_file,
        &contract_hash,
        RelayExpectedResult::PresenceOnly,
    )
    .verify_profile()
    .await
    .unwrap();

    for (outcome, data) in [
        ("match", Value::Null),
        ("match", json!({"source_field": "SENSITIVE"})),
        ("match", json!({"__notary_presence_contract_guard": true})),
        ("no_match", json!({})),
        ("ambiguous", json!({})),
    ] {
        server
            .set_execute(WireResponse::ok(
                serde_json::to_vec(&presence_result_value(&contract_hash, outcome, data)).unwrap(),
            ))
            .await;
        assert_eq!(
            client
                .execute(EVALUATION_ID, Zeroizing::new(INPUT_VALUE.to_string()))
                .await
                .expect_err("presence result shape mismatch must fail closed"),
            RelayClientError::InvalidResult
        );
    }
    server.shutdown().await;
}

#[tokio::test]
async fn metadata_pin_and_strict_json_fail_closed() {
    let token_file = TestTokenFile::new(&test_token());
    let mut cases = Vec::new();
    let mut wrong_hash = metadata_value();
    wrong_hash["contract_hash"] =
        json!("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    cases.push(serde_json::to_vec(&wrong_hash).unwrap());
    let mut wrong_id_contract = contract_value();
    wrong_id_contract["id"] = json!("other.profile");
    let wrong_id = metadata_value_for_contract(&wrong_id_contract, CONTRACT_HASH);
    cases.push(serde_json::to_vec(&wrong_id).unwrap());
    let mut unknown = metadata_value();
    unknown["unexpected"] = json!(true);
    cases.push(serde_json::to_vec(&unknown).unwrap());
    let mut obligation_contract = contract_value();
    obligation_contract["spec"]["authorization"]["mandatory_obligations"] = json!(["x"]);
    let obligation = metadata_value_for_contract(&obligation_contract, CONTRACT_HASH);
    cases.push(serde_json::to_vec(&obligation).unwrap());
    let valid = serde_json::to_string(&metadata_value()).unwrap();
    cases.push(
        valid
            .replacen("{", "{\"contract_hash\":\"duplicate-secret\",", 1)
            .into_bytes(),
    );
    let mut duplicate_contract = metadata_value();
    let contract_json = duplicate_contract["contract_json"].as_str().unwrap();
    duplicate_contract["contract_json"] =
        json!(contract_json.replacen('{', "{\"schema\":\"duplicate-secret\",", 1,));
    cases.push(serde_json::to_vec(&duplicate_contract).unwrap());
    cases.push(format!("{valid} true").into_bytes());

    for body in cases {
        let server = FakeRelay::start(WireResponse::ok(body), result_response()).await;
        let error = client(&server, &token_file)
            .verify_profile()
            .await
            .unwrap_err();
        assert_eq!(error, RelayClientError::InvalidProfileMetadata);
        server.shutdown().await;
    }
}

#[tokio::test]
async fn contract_digest_must_match_canonical_contract_returned_and_configured_hashes() {
    let token_file = TestTokenFile::new(&test_token());
    let mut contract = contract_value();
    contract["spec"]["bounds"]["timeout_ms"] = json!(4_999);
    let recomputed = typed_hash(b"registry.relay.consultation-contract.v1\0", &contract);
    for (returned_hash, configured_hash) in [
        (CONTRACT_HASH.to_string(), CONTRACT_HASH.to_string()),
        (recomputed.clone(), CONTRACT_HASH.to_string()),
        (CONTRACT_HASH.to_string(), recomputed.clone()),
    ] {
        let metadata = metadata_value_for_contract(&contract, &returned_hash);
        let server = FakeRelay::start(
            WireResponse::ok(serde_json::to_vec(&metadata).unwrap()),
            result_response(),
        )
        .await;
        assert_eq!(
            client_with_hash(&server, &token_file, &configured_hash)
                .verify_profile()
                .await
                .unwrap_err(),
            RelayClientError::InvalidProfileMetadata
        );
        server.shutdown().await;
    }
}

#[tokio::test]
async fn metadata_schema_accepts_twenty_seconds_and_rejects_a_larger_source_timeout() {
    let token_file = TestTokenFile::new(&test_token());
    let mut accepted_contract = contract_value();
    accepted_contract["spec"]["bounds"]["timeout_ms"] = json!(20_000);
    let accepted_hash = typed_hash(
        b"registry.relay.consultation-contract.v1\0",
        &accepted_contract,
    );
    let accepted = metadata_value_for_contract(&accepted_contract, &accepted_hash);
    let server = FakeRelay::start(
        WireResponse::ok(serde_json::to_vec(&accepted).unwrap()),
        result_response(),
    )
    .await;
    client_with_hash(&server, &token_file, &accepted_hash)
        .verify_profile()
        .await
        .expect("the maintained 20-second source timeout fits the metadata schema");
    server.shutdown().await;

    let mut rejected_contract = contract_value();
    rejected_contract["spec"]["bounds"]["timeout_ms"] = json!(20_001);
    let recomputed = typed_hash(
        b"registry.relay.consultation-contract.v1\0",
        &rejected_contract,
    );
    let rejected = metadata_value_for_contract(&rejected_contract, &recomputed);
    let server = FakeRelay::start(
        WireResponse::ok(serde_json::to_vec(&rejected).unwrap()),
        result_response(),
    )
    .await;
    assert_eq!(
        client_with_hash(&server, &token_file, &recomputed)
            .verify_profile()
            .await
            .expect_err("the metadata schema caps source work at 20 seconds"),
        RelayClientError::InvalidProfileMetadata
    );
    server.shutdown().await;
}

#[test]
fn client_operation_deadline_is_fixed_at_the_service_hop_bound() {
    let before = Instant::now();
    let deadline = operation_deadline().expect("fixed service-hop deadline is representable");
    let after = Instant::now();

    assert!(deadline >= before + MAX_SERVICE_HOP_OPERATION_TIMEOUT);
    assert!(deadline <= after + MAX_SERVICE_HOP_OPERATION_TIMEOUT);
    assert!(deadline > after + MAX_SERVICE_HOP_OPERATION_TIMEOUT - Duration::from_secs(1));
    assert_eq!(
        require_deadline(Instant::now()),
        Err(RelayClientError::Unavailable),
        "expiry is intentionally reported as generic Relay unavailability"
    );
    assert_eq!(
        map_send_error(DestinationSendError::DeadlineExceeded),
        RelayClientError::Unavailable
    );
    assert_eq!(
        map_response_error(
            DestinationResponseError::DeadlineExceeded,
            RelayClientError::InvalidResult,
        ),
        RelayClientError::Unavailable
    );
}

#[tokio::test]
async fn independently_reconstructed_policy_rejects_a_stale_policy_digest() {
    let token_file = TestTokenFile::new(&test_token());
    const CONTRACT_DOMAIN: &[u8] = b"registry.relay.consultation-contract.v1\0";
    let mut contract = contract_value();
    contract["spec"]["authorization"]["policy"]["max_decision_age_ms"] = json!(999);
    let recomputed = typed_hash(CONTRACT_DOMAIN, &contract);
    let metadata = metadata_value_for_contract(&contract, &recomputed);
    let server = FakeRelay::start(
        WireResponse::ok(serde_json::to_vec(&metadata).unwrap()),
        result_response(),
    )
    .await;
    assert_eq!(
        client_with_hash(&server, &token_file, &recomputed)
            .verify_profile()
            .await
            .unwrap_err(),
        RelayClientError::InvalidProfileMetadata
    );
    server.shutdown().await;
}

#[tokio::test]
async fn malformed_compact_credentials_fail_before_network() {
    let server = FakeRelay::start(metadata_response(), result_response()).await;
    for token in [
        "relay-test-token-SENSITIVE",
        "e30.e30",
        "e30.e30.c2lnbmF0dXJl.extra",
        "e30..c2lnbmF0dXJl",
        "e30.e30.c2ln=bmF0dXJl",
        "e30.e30.c2ln\nbmF0dXJl",
        "a.e30.c2lnbmF0dXJl",
    ] {
        let token_file = TestTokenFile::new(token);
        let error = client(&server, &token_file)
            .verify_profile()
            .await
            .unwrap_err();
        assert_eq!(error, RelayClientError::InvalidCredentials);
        assert!(!format!("{error:?} {error}").contains("SENSITIVE"));
    }
    assert_eq!(server.metadata_calls(), 0);

    assert_eq!(
        credential_for_path(PathBuf::from("relative.jwt")).unwrap_err(),
        RelayClientError::InvalidConfiguration
    );
    server.shutdown().await;
}

#[tokio::test]
async fn compact_credential_is_forwarded_and_relay_owns_semantic_rejection() {
    let compact = "e30.e30.c2lnbmF0dXJl";
    let token_file = TestTokenFile::new(compact);
    let server = FakeRelay::start(
        WireResponse {
            status: StatusCode::UNAUTHORIZED,
            body: b"credential-rejected-SENSITIVE".to_vec(),
            location: None,
            content_types: vec!["application/json"],
        },
        result_response(),
    )
    .await;
    server.set_expected_token(compact).await;

    let error = client(&server, &token_file)
        .verify_profile()
        .await
        .unwrap_err();

    assert_eq!(error, RelayClientError::InvalidCredentials);
    assert_eq!(server.metadata_calls(), 1);
    let observations = server.observations().await;
    assert_eq!(observations.len(), 1);
    assert!(observations[0].exact_authorization);
    assert!(!format!("{error:?} {error}").contains("SENSITIVE"));
    server.shutdown().await;
}

#[tokio::test]
async fn credential_file_rotation_and_unavailability_apply_without_restart() {
    let token_file = TestTokenFile::new(&test_token());
    let server = FakeRelay::start(metadata_response(), result_response()).await;
    let client = verified(&server, &token_file).await;

    let mut rotated_claims = test_claims();
    rotated_claims["jti"] = json!("relay-test-token-2");
    let rotated =
        token_for_claims_and_signature(&rotated_claims, b"relay-rotated-test-signature-SENSITIVE");
    token_file.replace(&format!("{rotated}\n"));
    server.set_expected_token(&rotated).await;

    client.verify_current_profile().await.unwrap();
    client
        .execute(EVALUATION_ID, Zeroizing::new(INPUT_VALUE.to_string()))
        .await
        .unwrap();
    assert_eq!(server.metadata_calls(), 2);
    assert_eq!(server.execute_calls(), 1);
    assert!(server
        .observations()
        .await
        .iter()
        .all(all_shape_checks_pass));

    token_file.replace("invalid-rotated-token-SENSITIVE");
    assert_eq!(
        client
            .execute(EVALUATION_ID, Zeroizing::new(INPUT_VALUE.to_string()))
            .await
            .unwrap_err(),
        RelayClientError::InvalidCredentials
    );
    assert_eq!(server.execute_calls(), 1);

    token_file.remove();
    assert_eq!(
        client.verify_current_profile().await.unwrap_err(),
        RelayClientError::CredentialUnavailable
    );
    assert_eq!(server.metadata_calls(), 2);
    token_file.replace(&rotated);
    client.verify_current_profile().await.unwrap();
    assert_eq!(server.metadata_calls(), 3);
    server.shutdown().await;
}

#[tokio::test]
async fn credential_file_is_bounded_and_must_remain_a_regular_file() {
    let oversized = TestTokenFile::new(&"x".repeat(MAX_TOKEN_FILE_BYTES + 1));
    assert_eq!(
        oversized.credential().authorization().await.unwrap_err(),
        RelayClientError::InvalidCredentials
    );

    let directory = tempfile::tempdir().unwrap();
    let credential = credential_for_path(directory.path().to_path_buf()).unwrap();
    assert_eq!(
        credential.authorization().await.unwrap_err(),
        RelayClientError::CredentialUnavailable
    );
}

#[tokio::test]
async fn cancelled_credential_reads_share_one_blocking_worker_gate() {
    let token_file = TestTokenFile::new(&test_token());
    let credential = token_file.credential();
    let held = Arc::clone(&credential.read_permit)
        .acquire_owned()
        .await
        .expect("test holds the one credential-read permit");

    for _ in 0..2 {
        assert!(
            tokio::time::timeout(Duration::from_millis(10), credential.authorization())
                .await
                .is_err(),
            "a cancelled retry waits behind the original read instead of spawning another worker"
        );
    }
    assert_eq!(credential.read_permit.available_permits(), 0);

    drop(held);
    credential
        .authorization()
        .await
        .expect("credential reload resumes after the original worker gate releases");
}

#[cfg(unix)]
#[tokio::test]
async fn credential_fifo_is_rejected_promptly_without_a_blocked_reader() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("relay.jwt");
    let status = std::process::Command::new("mkfifo")
        .arg(&path)
        .status()
        .expect("mkfifo command runs");
    assert!(status.success());
    let credential = credential_for_path(path).unwrap();

    let result = tokio::time::timeout(Duration::from_secs(1), credential.authorization())
        .await
        .expect("nonblocking FIFO inspection returns promptly");

    assert_eq!(result.unwrap_err(), RelayClientError::CredentialUnavailable);
}

#[tokio::test]
async fn input_pattern_rejection_performs_no_execute_network_call() {
    let token_file = TestTokenFile::new(&test_token());
    let server = FakeRelay::start(metadata_response(), result_response()).await;
    let client = verified(&server, &token_file).await;
    assert_eq!(server.execute_calls(), 0);
    assert_eq!(
        client
            .execute(EVALUATION_ID, Zeroizing::new("A!!!!!!!!!!".to_string()))
            .await
            .unwrap_err(),
        RelayClientError::InvalidRequest
    );
    assert_eq!(server.execute_calls(), 0);
    server.shutdown().await;
}

#[tokio::test]
async fn unsupported_input_pattern_is_rejected_during_profile_activation() {
    let token_file = TestTokenFile::new(&test_token());
    const CONTRACT_DOMAIN: &[u8] = b"registry.relay.consultation-contract.v1\0";
    let mut contract = contract_value();
    contract["spec"]["inputs"][INPUT_NAME]["pattern"] = json!("^.*$");
    let recomputed = typed_hash(CONTRACT_DOMAIN, &contract);
    let metadata = metadata_value_for_contract(&contract, &recomputed);
    let server = FakeRelay::start(
        WireResponse::ok(serde_json::to_vec(&metadata).unwrap()),
        result_response(),
    )
    .await;
    assert_eq!(
        client_with_hash(&server, &token_file, &recomputed)
            .verify_profile()
            .await
            .unwrap_err(),
        RelayClientError::InvalidProfileMetadata
    );
    assert_eq!(server.execute_calls(), 0);
    server.shutdown().await;
}

#[tokio::test]
async fn metadata_and_result_require_one_exact_json_media_type() {
    let token_file = TestTokenFile::new(&test_token());
    for content_types in [
        Vec::new(),
        vec!["application/problem+json"],
        vec!["application/json", "application/json"],
    ] {
        let server = FakeRelay::start(
            metadata_response().with_content_types(content_types),
            result_response(),
        )
        .await;
        assert_eq!(
            client(&server, &token_file)
                .verify_profile()
                .await
                .unwrap_err(),
            RelayClientError::InvalidProfileMetadata
        );
        server.shutdown().await;
    }

    let server = FakeRelay::start(metadata_response(), result_response()).await;
    let client = verified(&server, &token_file).await;
    for content_types in [
        Vec::new(),
        vec!["application/json; charset=utf-8"],
        vec!["application/json", "application/json"],
    ] {
        server
            .set_execute(result_response().with_content_types(content_types))
            .await;
        assert_eq!(
            client
                .execute(EVALUATION_ID, Zeroizing::new(INPUT_VALUE.to_string()))
                .await
                .unwrap_err(),
            RelayClientError::InvalidResult
        );
    }
    server.shutdown().await;
}

#[tokio::test]
async fn result_identity_provenance_shape_and_outcome_data_are_exact() {
    let token_file = TestTokenFile::new(&test_token());
    let server = FakeRelay::start(metadata_response(), result_response()).await;
    let client = verified(&server, &token_file).await;
    let mut cases = Vec::new();

    let mut wrong_hash = result_value();
    wrong_hash["profile"]["contract_hash"] =
        json!("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    cases.push(serde_json::to_vec(&wrong_hash).unwrap());
    let mut wrong_evaluation = result_value();
    wrong_evaluation["notary_evaluation_id"] = json!(CONSULTATION_ID);
    cases.push(serde_json::to_vec(&wrong_evaluation).unwrap());
    let mut wrong_consultation = result_value();
    wrong_consultation["consultation_id"] = json!("01jYZZZZZZZZZZZZZZZZZZZZZZ");
    cases.push(serde_json::to_vec(&wrong_consultation).unwrap());
    let mut wrong_provenance = result_value();
    wrong_provenance["provenance"]["policy_id"] = json!("other.policy");
    cases.push(serde_json::to_vec(&wrong_provenance).unwrap());
    let mut unknown = result_value();
    unknown["data"]["extra"] = json!("SECRET");
    cases.push(serde_json::to_vec(&unknown).unwrap());
    let mut no_match_object = result_value();
    no_match_object["outcome"] = json!("no_match");
    no_match_object["data"] = json!({"status": null});
    cases.push(serde_json::to_vec(&no_match_object).unwrap());
    let mut match_null = result_value();
    match_null["data"] = Value::Null;
    cases.push(serde_json::to_vec(&match_null).unwrap());
    let valid = serde_json::to_string(&result_value()).unwrap();
    cases.push(
        valid
            .replacen("{", "{\"schema\":\"duplicate-secret\",", 1)
            .into_bytes(),
    );
    cases.push(format!("{valid} false").into_bytes());

    for body in cases {
        server.set_execute(WireResponse::ok(body)).await;
        assert_eq!(
            client
                .execute(EVALUATION_ID, Zeroizing::new(INPUT_VALUE.to_string()))
                .await
                .unwrap_err(),
            RelayClientError::InvalidResult
        );
    }

    for (outcome, expected) in [
        ("no_match", RelayConsultationOutcome::NoMatch),
        ("ambiguous", RelayConsultationOutcome::Ambiguous),
    ] {
        let mut value = result_value();
        value["outcome"] = json!(outcome);
        value["data"] = Value::Null;
        server
            .set_execute(WireResponse::ok(serde_json::to_vec(&value).unwrap()))
            .await;
        let result = client
            .execute(EVALUATION_ID, Zeroizing::new(INPUT_VALUE.to_string()))
            .await
            .unwrap();
        assert_eq!(result.outcome(), expected);
        assert!(result.data().is_none());
    }
    server.shutdown().await;
}

#[tokio::test]
async fn status_size_redirect_and_retry_behavior_is_closed() {
    let token_file = TestTokenFile::new(&test_token());
    let server = FakeRelay::start(metadata_response(), result_response()).await;
    let client = verified(&server, &token_file).await;
    for (status, expected) in [
        (StatusCode::BAD_REQUEST, RelayClientError::InvalidRequest),
        (
            StatusCode::UNAUTHORIZED,
            RelayClientError::InvalidCredentials,
        ),
        (StatusCode::FORBIDDEN, RelayClientError::Denied),
        (StatusCode::NOT_FOUND, RelayClientError::ProfileNotFound),
        (StatusCode::TOO_MANY_REQUESTS, RelayClientError::RateLimited),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            RelayClientError::Unavailable,
        ),
    ] {
        server
            .set_execute(WireResponse {
                status,
                body: b"arbitrary-SENSITIVE-error-body".to_vec(),
                location: None,
                content_types: vec!["application/json"],
            })
            .await;
        let error = client
            .execute(EVALUATION_ID, Zeroizing::new(INPUT_VALUE.to_string()))
            .await
            .unwrap_err();
        assert_eq!(error, expected);
        assert!(!format!("{error:?} {error}").contains("SENSITIVE"));
    }

    server
        .set_execute(WireResponse::ok(vec![b' '; MAX_RESULT_BYTES + 1]))
        .await;
    assert_eq!(
        client
            .execute(EVALUATION_ID, Zeroizing::new(INPUT_VALUE.to_string()))
            .await
            .unwrap_err(),
        RelayClientError::InvalidResult
    );

    let calls_before_redirect = server.execute_calls();
    server
        .set_execute(WireResponse {
            status: StatusCode::TEMPORARY_REDIRECT,
            body: b"redirect-SENSITIVE".to_vec(),
            location: Some(EXECUTE_ROUTE),
            content_types: vec!["application/json"],
        })
        .await;
    assert_eq!(
        client
            .execute(EVALUATION_ID, Zeroizing::new(INPUT_VALUE.to_string()))
            .await
            .unwrap_err(),
        RelayClientError::UnexpectedStatus
    );
    assert_eq!(server.execute_calls(), calls_before_redirect + 1);
    server.shutdown().await;
}

#[tokio::test]
async fn debug_and_errors_never_expose_transport_or_consultation_values() {
    let token_file = TestTokenFile::new(&test_token());
    let server = FakeRelay::start(metadata_response(), result_response()).await;
    let unverified = client(&server, &token_file);
    let unverified_debug = format!("{unverified:?}");
    let client = unverified.verify_profile().await.unwrap();
    let verified_debug = format!("{client:?} {:?}", client.profile());
    let result = client
        .execute(EVALUATION_ID, Zeroizing::new(INPUT_VALUE.to_string()))
        .await
        .unwrap();
    let result_debug = format!("{result:?} {:?}", result.data().unwrap());
    let token = test_token();
    for diagnostic in [unverified_debug, verified_debug, result_debug] {
        for forbidden in [
            token.as_str(),
            &server.origin,
            PROFILE_ID,
            CONTRACT_HASH,
            PURPOSE,
            INPUT_NAME,
            INPUT_VALUE,
            OUTPUT_NAME,
            EVALUATION_ID,
            CONSULTATION_ID,
            "ACTIVE",
        ] {
            assert!(!diagnostic.contains(forbidden), "leaked {forbidden}");
        }
    }
    server.shutdown().await;
}
