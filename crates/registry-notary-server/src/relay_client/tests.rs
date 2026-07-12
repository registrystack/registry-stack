// SPDX-License-Identifier: Apache-2.0

use super::*;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use axum::body::{to_bytes, Body};
use axum::extract::{Request, State};
use axum::http::{header, Response, StatusCode};
use axum::routing::{get, post};
use axum::Router;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use registry_platform_crypto::canonicalize_json;
use registry_platform_httputil::destination::{DataDestinationPolicy, DestinationProfile};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Mutex};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

const PROFILE_ID: &str = "dhis2.tracker.enrollment-status.exact";
const PROFILE_VERSION: &str = "1";
const CONTRACT_HASH: &str =
    "sha256:eb8f6cb4dd81d8a34c25e4da393ada734caa553e7e65a06fabd613afb1fecbc9";
const PURPOSE: &str = "program-enrollment-verification";
const INPUT_NAME: &str = "tracked_entity";
const INPUT_VALUE: &str = "PQfMcpmXeFE";
const OUTPUT_NAME: &str = "status";
const EXPECTED_ISSUER: &str = "https://issuer.example.test";
const EXPECTED_AUDIENCE: &str = "registry-relay";
const EXPECTED_SCOPE: &str = "registry:consult:dhis2-enrollment-status";
const RESULT_SCHEMA: &str = "registry.relay.consultation-result.v1";
const MAX_RESULT_BYTES: usize = 64 * 1024;
const EVALUATION_ID: &str = "01JYZZZZZZZZZZZZZZZZZZZZZZ";
const CONSULTATION_ID: &str = "01K05H0JKP4VSQNYCZ0TN4D87R";
const PROFILE_ROUTE: &str = "/v1/consultations/dhis2.tracker.enrollment-status.exact/versions/1";
const EXECUTE_ROUTE: &str =
    "/v1/consultations/dhis2.tracker.enrollment-status.exact/versions/1/execute";

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
    observations: Mutex<Vec<Observation>>,
    execute_calls: AtomicUsize,
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
        let state = FakeState {
            inner: Arc::new(FakeStateInner {
                metadata: Mutex::new(metadata),
                execute: Mutex::new(execute),
                observations: Mutex::new(Vec::new()),
                execute_calls: AtomicUsize::new(0),
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

    async fn observations(&self) -> Vec<Observation> {
        self.state.inner.observations.lock().await.clone()
    }

    fn execute_calls(&self) -> usize {
        self.state.inner.execute_calls.load(Ordering::SeqCst)
    }

    async fn shutdown(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.task.await.unwrap();
    }
}

async fn metadata_handler(State(state): State<FakeState>, request: Request) -> Response<Body> {
    let observation = observe_request(ObservedOperation::Metadata, request).await;
    state.inner.observations.lock().await.push(observation);
    wire_response(state.inner.metadata.lock().await.clone())
}

async fn execute_handler(State(state): State<FakeState>, request: Request) -> Response<Body> {
    state.inner.execute_calls.fetch_add(1, Ordering::SeqCst);
    let observation = observe_request(ObservedOperation::Execute, request).await;
    state.inner.observations.lock().await.push(observation);
    wire_response(state.inner.execute.lock().await.clone())
}

async fn observe_request(operation: ObservedOperation, request: Request) -> Observation {
    let headers = request.headers();
    let exact_authorization = headers
        .get(header::AUTHORIZATION)
        .is_some_and(|value| value.as_bytes() == format!("Bearer {}", test_token()).as_bytes());
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
            .is_some_and(|value| value == EVALUATION_ID),
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

fn metadata_value() -> Value {
    let contract: Value = serde_json::from_str(include_str!(
        "../../../registry-relay/profiles/dhis2-2.41.9-enrollment-status/public-contract.json"
    ))
    .unwrap();
    json!({
        "contract_hash": CONTRACT_HASH,
        "contract": contract,
    })
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
                "hash": "sha256:017783fe880863e9dedc5138df4e1212d020ce7cfac5a13b58911fc4705f0e7a"
            },
            "policy_id": "relay.dhis2.tracker.enrollment-status.exact",
            "policy_hash": "sha256:0eaec9b82087299193efb25a9189a41b7373e64abf152ba7204fdf5b05722959",
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

fn result_response() -> WireResponse {
    WireResponse::ok(serde_json::to_vec(&result_value()).unwrap())
}

fn test_claims() -> Value {
    json!({
        "iss": EXPECTED_ISSUER,
        "aud": EXPECTED_AUDIENCE,
        "sub": "registry-notary",
        "azp": "registry-notary",
        "client_id": "registry-notary",
        "scope": EXPECTED_SCOPE,
        "iat": 1_700_000_000_i64,
        "nbf": 1_700_000_000_i64,
        "exp": 4_102_444_800_i64,
    })
}

fn token_for_claims(claims: &Value) -> String {
    let header = json!({"alg": "RS256", "kid": "relay-test-key", "typ": "at+jwt"});
    format!(
        "{}.{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).unwrap()),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(claims).unwrap()),
        URL_SAFE_NO_PAD.encode(b"relay-test-signature-SENSITIVE"),
    )
}

fn test_token() -> String {
    token_for_claims(&test_claims())
}

fn workload_credential() -> RelayWorkloadCredential {
    RelayWorkloadCredential::new(
        Zeroizing::new(test_token().into_bytes()),
        EXPECTED_ISSUER,
        EXPECTED_AUDIENCE,
        EXPECTED_SCOPE,
    )
    .unwrap()
}

fn client_with_hash(server: &FakeRelay, contract_hash: &str) -> RelayConsultationClient {
    let destination = DataDestinationPolicy::new(
        "registry-notary-relay",
        &server.origin,
        DestinationProfile::LoopbackDevelopmentHttp,
        &[],
    )
    .unwrap();
    RelayConsultationClient::new(
        destination,
        workload_credential(),
        Duration::from_secs(2),
        2,
        RelayProfilePin::new(PROFILE_ID, PROFILE_VERSION, contract_hash).unwrap(),
        PURPOSE,
        INPUT_NAME,
        RelayExpectedOutput::new(OUTPUT_NAME).unwrap(),
    )
    .unwrap()
}

fn client(server: &FakeRelay) -> RelayConsultationClient {
    client_with_hash(server, CONTRACT_HASH)
}

async fn verified(server: &FakeRelay) -> VerifiedRelayClient {
    client(server).verify_profile().await.unwrap()
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

#[tokio::test]
async fn exact_profile_and_execute_journey_is_strict_and_bounded() {
    let server = FakeRelay::start(metadata_response(), result_response()).await;
    let client = verified(&server).await;
    assert_eq!(client.profile().pin().id(), PROFILE_ID);
    assert_eq!(client.profile().pin().version(), PROFILE_VERSION);
    assert_eq!(client.profile().pin().contract_hash(), CONTRACT_HASH);
    assert_eq!(client.profile().output_name(), OUTPUT_NAME);

    let result = client
        .execute(EVALUATION_ID, Zeroizing::new(INPUT_VALUE.to_string()))
        .await
        .unwrap();
    assert_eq!(result.consultation_id().to_string(), CONSULTATION_ID);
    assert_eq!(result.outcome(), RelayConsultationOutcome::Match);
    let data = result.data().unwrap();
    assert_eq!(data.name(), OUTPUT_NAME);
    assert_eq!(data.value(), "ACTIVE");
    assert_eq!(
        result.provenance().acquisition_class(),
        RelayAcquisitionClass::SourceProjectedExact
    );

    let observations = server.observations().await;
    assert_eq!(observations.len(), 2);
    assert_eq!(observations[0].operation, ObservedOperation::Metadata);
    assert_eq!(observations[1].operation, ObservedOperation::Execute);
    assert!(observations.iter().all(all_shape_checks_pass));
    server.shutdown().await;
}

#[tokio::test]
async fn metadata_pin_and_strict_json_fail_closed() {
    let mut cases = Vec::new();
    let mut wrong_hash = metadata_value();
    wrong_hash["contract_hash"] =
        json!("sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
    cases.push(serde_json::to_vec(&wrong_hash).unwrap());
    let mut wrong_id = metadata_value();
    wrong_id["contract"]["id"] = json!("other.profile");
    cases.push(serde_json::to_vec(&wrong_id).unwrap());
    let mut unknown = metadata_value();
    unknown["unexpected"] = json!(true);
    cases.push(serde_json::to_vec(&unknown).unwrap());
    let mut obligation = metadata_value();
    obligation["contract"]["spec"]["authorization"]["mandatory_obligations"] = json!(["x"]);
    cases.push(serde_json::to_vec(&obligation).unwrap());
    let valid = serde_json::to_string(&metadata_value()).unwrap();
    cases.push(
        valid
            .replacen("{", "{\"contract_hash\":\"duplicate-secret\",", 1)
            .into_bytes(),
    );
    cases.push(
        valid
            .replacen(
                "\"schema\":",
                "\"schema\":\"duplicate-secret\",\"schema\":",
                1,
            )
            .into_bytes(),
    );
    cases.push(format!("{valid} true").into_bytes());

    for body in cases {
        let server = FakeRelay::start(WireResponse::ok(body), result_response()).await;
        let error = client(&server).verify_profile().await.unwrap_err();
        assert_eq!(error, RelayClientError::InvalidProfileMetadata);
        server.shutdown().await;
    }
}

#[tokio::test]
async fn contract_digest_must_match_canonical_contract_returned_and_configured_hashes() {
    let mut metadata = metadata_value();
    metadata["contract"]["spec"]["bounds"]["timeout_ms"] = json!(4_999);
    let recomputed = typed_hash(
        b"registry.relay.consultation-contract.v1\0",
        &metadata["contract"],
    );
    for (returned_hash, configured_hash) in [
        (CONTRACT_HASH.to_string(), CONTRACT_HASH.to_string()),
        (recomputed.clone(), CONTRACT_HASH.to_string()),
        (CONTRACT_HASH.to_string(), recomputed.clone()),
    ] {
        metadata["contract_hash"] = json!(returned_hash);
        let server = FakeRelay::start(
            WireResponse::ok(serde_json::to_vec(&metadata).unwrap()),
            result_response(),
        )
        .await;
        assert_eq!(
            client_with_hash(&server, &configured_hash)
                .verify_profile()
                .await
                .unwrap_err(),
            RelayClientError::InvalidProfileMetadata
        );
        server.shutdown().await;
    }
}

#[tokio::test]
async fn independently_reconstructed_policy_rejects_a_stale_policy_digest() {
    const CONTRACT_DOMAIN: &[u8] = b"registry.relay.consultation-contract.v1\0";
    let mut metadata = metadata_value();
    metadata["contract"]["spec"]["authorization"]["policy"]["max_decision_age_ms"] = json!(999);
    let recomputed = typed_hash(CONTRACT_DOMAIN, &metadata["contract"]);
    metadata["contract_hash"] = json!(recomputed);
    let server = FakeRelay::start(
        WireResponse::ok(serde_json::to_vec(&metadata).unwrap()),
        result_response(),
    )
    .await;
    assert_eq!(
        client_with_hash(&server, &recomputed)
            .verify_profile()
            .await
            .unwrap_err(),
        RelayClientError::InvalidProfileMetadata
    );
    server.shutdown().await;
}

#[test]
fn workload_credential_rejects_opaque_and_nonmatching_jwts() {
    let opaque = RelayWorkloadCredential::new(
        Zeroizing::new(b"relay-test-token-SENSITIVE".to_vec()),
        EXPECTED_ISSUER,
        EXPECTED_AUDIENCE,
        EXPECTED_SCOPE,
    )
    .unwrap_err();
    assert_eq!(opaque, RelayClientError::InvalidConfiguration);
    assert!(!format!("{opaque:?} {opaque}").contains("SENSITIVE"));

    let mut cases = Vec::new();
    for (field, value) in [
        ("iss", json!("https://other-issuer.example.test")),
        ("aud", json!("other-relay")),
        ("sub", json!("other-principal")),
        ("azp", json!("other-client")),
        ("client_id", json!("other-client")),
        ("scope", json!("registry:consult:other-profile")),
        ("exp", json!(1_700_000_001_i64)),
        ("nbf", json!(4_102_444_799_i64)),
    ] {
        let mut claims = test_claims();
        claims[field] = value;
        cases.push(token_for_claims(&claims));
    }
    for token in cases {
        assert_eq!(
            RelayWorkloadCredential::new(
                Zeroizing::new(token.into_bytes()),
                EXPECTED_ISSUER,
                EXPECTED_AUDIENCE,
                EXPECTED_SCOPE,
            )
            .unwrap_err(),
            RelayClientError::InvalidConfiguration
        );
    }
}

#[tokio::test]
async fn input_pattern_rejection_performs_no_execute_network_call() {
    let server = FakeRelay::start(metadata_response(), result_response()).await;
    let client = verified(&server).await;
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
    const CONTRACT_DOMAIN: &[u8] = b"registry.relay.consultation-contract.v1\0";
    let mut metadata = metadata_value();
    metadata["contract"]["spec"]["inputs"][INPUT_NAME]["pattern"] = json!("^.*$");
    let recomputed = typed_hash(CONTRACT_DOMAIN, &metadata["contract"]);
    metadata["contract_hash"] = json!(recomputed);
    let server = FakeRelay::start(
        WireResponse::ok(serde_json::to_vec(&metadata).unwrap()),
        result_response(),
    )
    .await;
    assert_eq!(
        client_with_hash(&server, &recomputed)
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
            client(&server).verify_profile().await.unwrap_err(),
            RelayClientError::InvalidProfileMetadata
        );
        server.shutdown().await;
    }

    let server = FakeRelay::start(metadata_response(), result_response()).await;
    let client = verified(&server).await;
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
    let server = FakeRelay::start(metadata_response(), result_response()).await;
    let client = verified(&server).await;
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
    let server = FakeRelay::start(metadata_response(), result_response()).await;
    let client = verified(&server).await;
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
    let server = FakeRelay::start(metadata_response(), result_response()).await;
    let unverified = client(&server);
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
