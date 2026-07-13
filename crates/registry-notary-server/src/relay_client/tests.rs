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
    DestinationProfile, ServiceHopDataDestinationPolicy,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Mutex};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

const PROFILE_ID: &str = "dhis2.tracker.enrollment-status.exact";
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
const SNAPSHOT_GENERATION_ID: &str = "01K05H0JKP4VSQNYCZ0TN4D87S";
const PROFILE_ROUTE: &str = "/v1/consultations/dhis2.tracker.enrollment-status.exact";
const EXECUTE_ROUTE: &str = "/v1/consultations/dhis2.tracker.enrollment-status.exact/execute";
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
    has_valid_batch_child_identity: bool,
    batch_child_identity_absent: bool,
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
    let has_valid_batch_child_identity = headers
        .get("registry-notary-batch-child-id")
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| {
            value.len() == 43
                && value
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        });
    let batch_child_identity_absent = !headers.contains_key("registry-notary-batch-child-id");
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
            let expected = format!(
                r#"{{"contract_hash":"{}","inputs":{{"tracked_entity":"PQfMcpmXeFE"}}}}"#,
                contract_hash()
            );
            body.as_ref() == expected.as_bytes()
        }
    };
    Observation {
        operation,
        exact_authorization,
        exact_accept,
        exact_content_type,
        exact_purpose,
        exact_evaluation_id,
        has_valid_batch_child_identity,
        batch_child_identity_absent,
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

fn typed_output_contract_value() -> Value {
    let mut contract = contract_value();
    contract["spec"]["output"] = json!({
        "active": { "type": "boolean", "nullable": false },
        "birth_date": { "type": "date", "nullable": true },
        "exists": { "type": "boolean", "nullable": false },
        "sequence": {
            "type": "integer",
            "nullable": false,
            "minimum": 0,
            "maximum": 9_007_199_254_740_991_i64
        },
        "status": { "type": "string", "nullable": false, "max_bytes": 64 }
    });
    contract["spec"]["acquisition"]["fields"] = json!({
        "active": { "type": "boolean", "nullable": false },
        "birth_date": { "type": "string", "nullable": true, "max_bytes": 10 },
        "sequence": {
            "type": "integer",
            "nullable": false,
            "minimum": 0,
            "maximum": 9_007_199_254_740_991_i64
        },
        "status": { "type": "string", "nullable": false, "max_bytes": 64 }
    });
    contract
}

fn typed_output_expectation() -> RelayExpectedResult {
    RelayExpectedResult::output_map(BTreeMap::from([
        (
            "active".to_string(),
            NotaryRelayOutputContract::Boolean { nullable: false },
        ),
        (
            "birth_date".to_string(),
            NotaryRelayOutputContract::Date { nullable: true },
        ),
        (
            "exists".to_string(),
            NotaryRelayOutputContract::Boolean { nullable: false },
        ),
        (
            "sequence".to_string(),
            NotaryRelayOutputContract::Integer {
                nullable: false,
                minimum: 0,
                maximum: 9_007_199_254_740_991,
            },
        ),
        (
            "status".to_string(),
            NotaryRelayOutputContract::String {
                nullable: false,
                max_bytes: 64,
            },
        ),
    ]))
    .expect("valid typed output expectation")
}

#[test]
fn output_contract_rejects_reserved_notary_view_names() {
    for name in ["matched", "outcome", "status.code"] {
        assert!(matches!(
            RelayExpectedResult::output_map(BTreeMap::from([(
                name.to_string(),
                NotaryRelayOutputContract::Boolean { nullable: false },
            )])),
            Err(RelayClientError::InvalidConfiguration)
        ));
    }
}

fn snapshot_contract_value() -> Value {
    let mut contract = contract_value();
    contract["spec"]["acquisition"]["class"] = json!("materialized_snapshot");
    contract["spec"]["bounds"]["max_data_exchanges"] = json!(0);
    contract["spec"]["bounds"]["max_credential_exchanges"] = json!(0);
    contract["spec"]["bounds"]["max_data_destinations"] = json!(0);
    contract["spec"]["materialization"] = json!({
        "max_snapshot_age_ms": 86_400_000,
        "stale_behavior": "unavailable",
        "footprint": {
            "fields": ["status"],
            "max_source_records": 1000,
            "max_source_bytes": 1_048_576,
            "max_data_exchanges": 2,
            "max_credential_exchanges": 1,
            "max_data_destinations": 1
        },
        "refresh_class": "operator_triggered",
        "snapshot_retention_generations": 3,
        "immutable_generation": true,
        "digest_bound_active_pointer": true
    });
    contract["spec"]["runtime"] = json!({
        "platform_profile": "registry-stack.consultation.v1",
        "source_capability": "snapshot",
        "script_abi": null
    });
    contract
}

fn metadata_value_for_contract(contract: &Value, contract_hash: &str) -> Value {
    json!({
        "contract_hash": contract_hash,
        "contract": contract,
    })
}

fn metadata_value() -> Value {
    let contract = contract_value();
    let contract_hash = typed_hash(CONTRACT_DOMAIN, &contract);
    metadata_value_for_contract(&contract, &contract_hash)
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

fn contract_hash() -> String {
    typed_hash(CONTRACT_DOMAIN, &contract_value())
}

fn result_value() -> Value {
    let contract_hash = contract_hash();
    json!({
        "schema": RESULT_SCHEMA,
        "consultation_id": CONSULTATION_ID,
        "notary_evaluation_id": EVALUATION_ID,
        "profile": {
            "id": PROFILE_ID,
            "contract_hash": contract_hash,
        },
        "outcome": "match",
        "outputs": { "status": "ACTIVE" },
        "provenance": {
            "acquired_at": "2026-07-12T00:00:00Z",
            "source_observed_at": null,
            "source_revision": null,
            "acquisition_class": "source_projected_exact",
            "integration": {
                "id": "dhis2.tracker.enrollment-status",
                "revision": 1
            },
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

fn snapshot_result_value(contract_hash: &str) -> Value {
    let mut result = result_value();
    result["profile"]["contract_hash"] = json!(contract_hash);
    result["provenance"]["acquisition_class"] = json!("materialized_snapshot");
    result["provenance"]["snapshot"] = json!({
        "generation_id": SNAPSHOT_GENERATION_ID,
        "published_at": "2026-07-11T23:59:00Z"
    });
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
        "tenant": { "id": "test-project" },
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
        RelayExpectedResult::output_map(BTreeMap::from([(
            OUTPUT_NAME.to_string(),
            NotaryRelayOutputContract::String {
                nullable: false,
                max_bytes: 32,
            },
        )]))
        .unwrap(),
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
        EXPECTED_CLIENT_ID,
        RelayProfilePin::new(PROFILE_ID, contract_hash).unwrap(),
        PURPOSE,
        INPUT_NAME,
        expected_result,
    )
    .unwrap()
}

fn client(server: &FakeRelay, token_file: &TestTokenFile) -> RelayConsultationClient {
    client_with_hash(server, token_file, &contract_hash())
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
    let contract_hash = contract_hash();
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
    workload_client_id: {EXPECTED_CLIENT_ID}
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
              contract_hash: {contract_hash}
            inputs:
              {INPUT_NAME}: target.id
            outputs:
              {OUTPUT_NAME}: {{ type: string, nullable: false, max_bytes: 32 }}
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
              contract_hash: {contract_hash}
            inputs:
              {INPUT_NAME}: target.id
            outputs:
              {OUTPUT_NAME}: {{ type: string, nullable: false, max_bytes: 32 }}
      value:
        type: string
        nullable: true
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
    assert!(observations[0].batch_child_identity_absent);
    assert!(observations[1].batch_child_identity_absent);
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
    assert_eq!(client.profile().pin().contract_hash(), contract_hash());
    assert_eq!(client.profile().input_names(), [INPUT_NAME]);

    let result = client
        .execute(EVALUATION_ID, Zeroizing::new(INPUT_VALUE.to_string()))
        .await
        .unwrap();
    assert_eq!(result.consultation_id().to_string(), CONSULTATION_ID);
    assert_eq!(result.outcome(), RelayConsultationOutcome::Match);
    let Some(RelayMatchData::OutputMap(outputs)) = result.match_data() else {
        panic!("match exposes the declared output map")
    };
    let fields = outputs.fields().collect::<Vec<_>>();
    assert_eq!(fields.len(), 1);
    assert_eq!(fields[0].0, OUTPUT_NAME);
    assert!(matches!(
        fields[0].1,
        ProjectedJsonScalar::String(value) if value.as_str() == "ACTIVE"
    ));
    let observations = server.observations().await;
    assert_eq!(observations.len(), 2);
    assert_eq!(observations[0].operation, ObservedOperation::Metadata);
    assert_eq!(observations[1].operation, ObservedOperation::Execute);
    assert!(observations.iter().all(all_shape_checks_pass));
    server.shutdown().await;
}

#[tokio::test]
async fn result_union_requires_outputs_only_for_match() {
    let token_file = TestTokenFile::new(&test_token());
    let server = FakeRelay::start(metadata_response(), result_response()).await;
    let client = verified(&server, &token_file).await;

    for (wire_outcome, expected) in [
        ("no_match", RelayConsultationOutcome::NoMatch),
        ("ambiguous", RelayConsultationOutcome::Ambiguous),
    ] {
        let mut value = result_value();
        value["outcome"] = json!(wire_outcome);
        value
            .as_object_mut()
            .expect("result is an object")
            .remove("outputs");
        server
            .set_execute(WireResponse::ok(serde_json::to_vec(&value).unwrap()))
            .await;
        let result = client
            .execute(EVALUATION_ID, Zeroizing::new(INPUT_VALUE.to_string()))
            .await
            .expect("non-match outcome without outputs is valid");
        assert_eq!(result.outcome(), expected);
        assert!(result.match_data().is_none());
    }

    let mut match_without_outputs = result_value();
    match_without_outputs
        .as_object_mut()
        .expect("result is an object")
        .remove("outputs");
    server
        .set_execute(WireResponse::ok(
            serde_json::to_vec(&match_without_outputs).unwrap(),
        ))
        .await;
    assert_eq!(
        client
            .execute(EVALUATION_ID, Zeroizing::new(INPUT_VALUE.to_string()))
            .await
            .expect_err("match without outputs fails closed"),
        RelayClientError::InvalidResult
    );

    let mut no_match_with_outputs = result_value();
    no_match_with_outputs["outcome"] = json!("no_match");
    server
        .set_execute(WireResponse::ok(
            serde_json::to_vec(&no_match_with_outputs).unwrap(),
        ))
        .await;
    assert_eq!(
        client
            .execute(EVALUATION_ID, Zeroizing::new(INPUT_VALUE.to_string()))
            .await
            .expect_err("no_match with outputs fails closed"),
        RelayClientError::InvalidResult
    );
    server.shutdown().await;
}

#[tokio::test]
async fn batch_execute_propagates_one_bounded_opaque_child_identity() {
    let token_file = TestTokenFile::new(&test_token());
    let server = FakeRelay::start(metadata_response(), result_response()).await;
    let client = verified(&server, &token_file).await;
    client
        .execute_batch_inputs(
            EVALUATION_ID,
            BTreeMap::from([(
                INPUT_NAME.to_string(),
                Zeroizing::new(INPUT_VALUE.to_string()),
            )]),
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        )
        .await
        .unwrap();
    let observations = server.observations().await;
    assert!(observations[0].batch_child_identity_absent);
    assert!(!observations[1].batch_child_identity_absent);
    assert!(observations[1].has_valid_batch_child_identity);
    server.shutdown().await;
}

#[tokio::test]
async fn batch_child_terminal_replay_accepts_a_fresh_notary_evaluation_id() {
    let token_file = TestTokenFile::new(&test_token());
    let server =
        FakeRelay::start_echoing_evaluation_id(metadata_response(), result_response()).await;
    let client = verified(&server, &token_file).await;
    let child_identity = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let fresh_evaluation_id = ulid::Ulid::from_parts(3, 7).to_string();

    let first = client
        .execute_batch_inputs(
            EVALUATION_ID,
            BTreeMap::from([(
                INPUT_NAME.to_string(),
                Zeroizing::new(INPUT_VALUE.to_string()),
            )]),
            child_identity,
        )
        .await
        .expect("first batch child result validates");
    let replay = client
        .execute_batch_inputs(
            &fresh_evaluation_id,
            BTreeMap::from([(
                INPUT_NAME.to_string(),
                Zeroizing::new(INPUT_VALUE.to_string()),
            )]),
            child_identity,
        )
        .await
        .expect("terminal child replay validates against the fresh evaluation id");

    assert_eq!(first.consultation_id(), replay.consultation_id());
    let observations = server.observations().await;
    assert_eq!(observations.len(), 3);
    assert!(observations[0].batch_child_identity_absent);
    assert!(observations[1..]
        .iter()
        .all(|observation| observation.has_valid_batch_child_identity
            && !observation.batch_child_identity_absent
            && observation.exact_evaluation_id));
    server.shutdown().await;
}

#[tokio::test]
async fn multi_input_profile_forwards_bounded_inputs_and_rejects_partial_maps() {
    let token_file = TestTokenFile::new(&test_token());
    let mut contract = contract_value();
    contract["spec"]["inputs"] = json!({
        "birth_date": {
            "role": "selector",
            "type": "string",
            "format": "date",
            "maxLength": 10,
            "x-registry-max-bytes": 40,
            "pattern": "^[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]$",
            "x-registry-canonicalization": "identity"
        },
        "country_code": {
            "role": "selector",
            "type": "string",
            "maxLength": 2,
            "x-registry-max-bytes": 8,
            "pattern": "^[a-z][a-z]$",
            "x-registry-canonicalization": "ascii_lowercase"
        },
        "tracked_entity": contract["spec"]["inputs"]["tracked_entity"].clone()
    });
    let contract_hash = typed_hash(CONTRACT_DOMAIN, &contract);
    let metadata = WireResponse::ok(
        serde_json::to_vec(&metadata_value_for_contract(&contract, &contract_hash)).unwrap(),
    );
    let server = FakeRelay::start(metadata, result_response()).await;
    let destination = ServiceHopDataDestinationPolicy::new(
        "registry-notary-relay",
        &server.origin,
        DestinationProfile::LoopbackDevelopmentHttp,
        &[],
    )
    .unwrap();
    let client = RelayConsultationClient::new(
        destination,
        token_file.credential(),
        EXPECTED_CLIENT_ID,
        RelayProfilePin::new(PROFILE_ID, contract_hash.as_str()).unwrap(),
        PURPOSE,
        vec![
            "tracked_entity".to_string(),
            "country_code".to_string(),
            "birth_date".to_string(),
        ],
        RelayExpectedResult::output_map(BTreeMap::from([(
            OUTPUT_NAME.to_string(),
            NotaryRelayOutputContract::String {
                nullable: false,
                max_bytes: 32,
            },
        )]))
        .unwrap(),
    )
    .unwrap()
    .verify_profile()
    .await
    .expect("the exact three-input profile activates");

    let canonical = client
        .canonicalize_execute_inputs(
            EVALUATION_ID,
            &BTreeMap::from([
                (
                    "tracked_entity".to_string(),
                    Zeroizing::new(INPUT_VALUE.to_string()),
                ),
                ("country_code".to_string(), Zeroizing::new("TH".to_string())),
                (
                    "birth_date".to_string(),
                    Zeroizing::new("2000-01-02".to_string()),
                ),
            ]),
        )
        .expect("all bounded values pass to Relay for contract-defined canonicalization");
    assert_eq!(canonical["country_code"].as_str(), "TH");
    assert_eq!(canonical["birth_date"].as_str(), "2000-01-02");

    assert!(matches!(
        client.canonicalize_execute_inputs(
            EVALUATION_ID,
            &BTreeMap::from([(
                "tracked_entity".to_string(),
                Zeroizing::new(INPUT_VALUE.to_string()),
            )]),
        ),
        Err(RelayClientError::InvalidRequest)
    ));
    server.shutdown().await;
}

#[tokio::test]
async fn typed_output_map_verifies_exact_schema_and_rejects_bad_date() {
    let token_file = TestTokenFile::new(&test_token());
    let contract = typed_output_contract_value();
    let contract_hash = typed_hash(CONTRACT_DOMAIN, &contract);
    let mut result = result_value();
    result["profile"]["contract_hash"] = json!(contract_hash);
    result["outputs"] = json!({
        "active": true,
        "birth_date": "2010-06-15",
        "exists": true,
        "sequence": 42,
        "status": "ACTIVE"
    });
    let server = FakeRelay::start(
        WireResponse::ok(
            serde_json::to_vec(&metadata_value_for_contract(&contract, &contract_hash)).unwrap(),
        ),
        WireResponse::ok(serde_json::to_vec(&result).unwrap()),
    )
    .await;
    let client = client_with_result(
        &server,
        &token_file,
        &contract_hash,
        typed_output_expectation(),
    )
    .verify_profile()
    .await
    .expect("typed output profile verifies");
    let executed = client
        .execute(EVALUATION_ID, Zeroizing::new(INPUT_VALUE.to_string()))
        .await
        .expect("typed output result verifies");
    let Some(RelayMatchData::OutputMap(outputs)) = executed.match_data() else {
        panic!("typed output map is released")
    };
    assert_eq!(outputs.fields().len(), 5);

    let mut bad_date = result_value();
    bad_date["profile"]["contract_hash"] = json!(contract_hash);
    bad_date["outputs"] = json!({
        "active": true,
        "birth_date": "2010-02-30",
        "exists": true,
        "sequence": 42,
        "status": "ACTIVE"
    });
    server
        .set_execute(WireResponse::ok(serde_json::to_vec(&bad_date).unwrap()))
        .await;
    assert_eq!(
        client
            .execute(EVALUATION_ID, Zeroizing::new(INPUT_VALUE.to_string()))
            .await
            .expect_err("invalid full-date fails closed"),
        RelayClientError::InvalidResult
    );
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
    let mut unknown = metadata_value();
    unknown["unexpected"] = json!(true);
    cases.push(serde_json::to_vec(&unknown).unwrap());
    let valid = serde_json::to_string(&metadata_value()).unwrap();
    cases.push(
        valid
            .replacen("{", "{\"contract_hash\":\"duplicate-secret\",", 1)
            .into_bytes(),
    );
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
    let contract_hash = contract_hash();
    for (returned_hash, configured_hash) in [
        (contract_hash.clone(), contract_hash.clone()),
        (recomputed.clone(), contract_hash.clone()),
        (contract_hash, recomputed.clone()),
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
async fn readiness_rejects_each_semantic_contract_mismatch_before_execution() {
    let token_file = TestTokenFile::new(&test_token());
    let mut cases = Vec::<(&str, Value)>::new();

    let mut identity = contract_value();
    identity["id"] = json!("different.profile");
    cases.push(("profile identity", identity));

    let mut purpose = contract_value();
    purpose["spec"]["authorization"]["purposes"] = json!(["different-purpose"]);
    cases.push(("purpose", purpose));

    let mut workload = contract_value();
    workload["spec"]["authorization"]["workload"] = json!("different-workload");
    cases.push(("configured workload identity", workload));

    let mut input = contract_value();
    input["spec"]["inputs"][INPUT_NAME]["role"] = json!("parameter");
    cases.push(("input role", input));

    let mut output = contract_value();
    output["spec"]["output"][OUTPUT_NAME]["max_bytes"] = json!(31);
    cases.push(("output bounds", output));

    let mut outcome = contract_value();
    outcome["spec"]["public_behavior"]["outcomes"] = json!(["match", "no_match"]);
    cases.push(("closed outcome union", outcome));

    let mut provenance = contract_value();
    provenance["spec"]["source_provenance"]["source_observed_at"] = json!({
        "type": "acquired_rfc3339",
        "field": "missing_observation"
    });
    cases.push(("provenance", provenance));

    let mut runtime = contract_value();
    runtime["spec"]["runtime"]["source_capability"] = json!("script");
    cases.push(("runtime ABI", runtime));

    let mut platform = contract_value();
    platform["spec"]["runtime"]["platform_profile"] = json!("registry-stack.consultation.v2");
    cases.push(("platform profile", platform));

    for (label, contract) in cases {
        let contract_hash = typed_hash(CONTRACT_DOMAIN, &contract);
        let server = FakeRelay::start(
            WireResponse::ok(
                serde_json::to_vec(&metadata_value_for_contract(&contract, &contract_hash))
                    .unwrap(),
            ),
            result_response(),
        )
        .await;
        assert_eq!(
            client_with_hash(&server, &token_file, &contract_hash)
                .verify_profile()
                .await
                .expect_err(label),
            RelayClientError::InvalidProfileMetadata,
            "{label}"
        );
        assert_eq!(server.execute_calls(), 0, "{label}");
        server.shutdown().await;
    }
}

#[tokio::test]
async fn materialized_snapshot_contract_and_result_are_strictly_verified() {
    let token_file = TestTokenFile::new(&test_token());
    let contract = snapshot_contract_value();
    let contract_hash = typed_hash(CONTRACT_DOMAIN, &contract);
    let metadata = metadata_value_for_contract(&contract, &contract_hash);
    let result = snapshot_result_value(&contract_hash);
    let server = FakeRelay::start(
        WireResponse::ok(serde_json::to_vec(&metadata).unwrap()),
        WireResponse::ok(serde_json::to_vec(&result).unwrap()),
    )
    .await;
    let client = client_with_hash(&server, &token_file, &contract_hash)
        .verify_profile()
        .await
        .expect("closed materialized snapshot metadata verifies");
    let result = client
        .execute(EVALUATION_ID, Zeroizing::new(INPUT_VALUE.to_string()))
        .await
        .expect("closed materialized snapshot result verifies");
    assert_eq!(
        result.provenance().acquired_at(),
        OffsetDateTime::parse("2026-07-12T00:00:00Z", &Rfc3339).unwrap()
    );

    for (field, invalid) in [
        ("generation_id", ""),
        ("published_at", "not-a-timestamp"),
        ("published_at", "2026-07-13T00:00:00Z"),
    ] {
        let mut invalid_result = snapshot_result_value(&contract_hash);
        invalid_result["provenance"]["snapshot"][field] = json!(invalid);
        server
            .set_execute(WireResponse::ok(
                serde_json::to_vec(&invalid_result).unwrap(),
            ))
            .await;
        assert_eq!(
            client
                .execute(EVALUATION_ID, Zeroizing::new(INPUT_VALUE.to_string()))
                .await
                .expect_err("invalid snapshot provenance fails closed"),
            RelayClientError::InvalidResult
        );
    }
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
        (StatusCode::CONFLICT, RelayClientError::ContractMismatch),
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
    let result_debug = format!("{result:?} {:?}", result.match_data().unwrap());
    let token = test_token();
    let contract_hash = contract_hash();
    for diagnostic in [unverified_debug, verified_debug, result_debug] {
        for forbidden in [
            token.as_str(),
            &server.origin,
            PROFILE_ID,
            &contract_hash,
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
