// SPDX-License-Identifier: Apache-2.0

use axum::{
    body::{Body, Bytes},
    extract::State,
    http::{HeaderMap, HeaderValue, StatusCode, Uri},
    response::IntoResponse,
    response::Response,
    routing::{get, post},
    Router,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use registry_adapter::payments::{
    g2p_model::{
        DisbursementInstruction, G2pAttempt, G2pConnectionSnapshot, G2pError, G2pHttpAuth,
        G2pProviderBinding, G2pRegistryBinding, G2pTransitRsaNoOidKeyBinding,
        PreparedG2pRegistryAction,
    },
    g2p_service::{G2pProviderError, G2pProviderPort, HttpG2pProvider},
    pack::ProviderPackPin,
    provider_mapping::{
        PaymentEndpointRole, PaymentHttpMethod, PreparedProviderRequest, ProviderAcceptance,
        ProviderObservation, ProviderObservationState, ProviderObservedMoney,
        ProviderObservedParty, ProviderPartyRole,
    },
};
use registry_payment_mifos_connector::{legacy_signature_digest, LegacySignatureHeaders};
use registry_platform_config::{SecretProvider, SecretResolver};
use registry_platform_yaml::SecretReference;
use serde_json::{json, Value};
use std::{
    collections::BTreeMap,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UnixListener,
};
use uuid::Uuid;

#[derive(Clone, Debug, PartialEq, Eq)]
struct SeenRequest {
    method: &'static str,
    path_and_query: String,
    tenant: Option<String>,
    correlation_id: Option<String>,
    signature: Option<String>,
    authorization: Option<String>,
    body: Vec<u8>,
}

#[tokio::test]
async fn bearer_http_host_preserves_one_send_and_validates_wire_observations() {
    let seen = Arc::new(Mutex::new(Vec::new()));
    let router = Router::new()
        .route("/v2/payouts", post(capture_submit))
        .route("/v2/uncertain", post(capture_uncertain))
        .route("/v2/payouts/{reference}", get(capture_status))
        .with_state(seen.clone());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}/", listener.local_addr().unwrap());
    let server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });

    let secrets = tempfile::tempdir().unwrap();
    write_secret(secrets.path().join("provider-token"), b"test-only-bearer");
    write_secret(secrets.path().join("signing-key"), b"test-only-signing-key");
    write_secret(
        secrets.path().join("response-key"),
        b"test-only-response-key",
    );
    let resolver = Arc::new(
        SecretResolver::new([SecretProvider::File], secrets.path()).expect("file resolver"),
    );
    let provider = HttpG2pProvider::new(resolver);
    let provider_binding = binding(
        &origin,
        G2pHttpAuth::Bearer {
            credential_identity: "second-provider-operator".to_owned(),
            credential_ref: SecretReference::new("secret:file/provider-token").unwrap(),
        },
    );
    let pack = pin();
    let instruction = instruction();
    let snapshot = snapshot(provider_binding.clone(), pack.clone());
    let intent = snapshot.provider_intent(&instruction).unwrap();
    let exact_body = registry_platform_canonical_json::canonicalize_json(&json!({
        "amountMinor": "100000",
        "clientReference": intent.correlation_id
    }))
    .unwrap();
    let submit = PreparedProviderRequest {
        provider_pack: pack.clone(),
        role: PaymentEndpointRole::DisbursementSubmit,
        method: PaymentHttpMethod::Post,
        path: "/v2/payouts".to_owned(),
        query: BTreeMap::from([("channel".to_owned(), "benefits".to_owned())]),
        headers: BTreeMap::from([("x-provider-tenant".to_owned(), "pilot-beta".to_owned())]),
        body: Some(exact_body.clone()),
    };
    let prepared_send = provider
        .preflight_submit(&provider_binding, &intent, &submit)
        .await
        .unwrap();
    let accepted = prepared_send.send().await.unwrap();
    assert_eq!(accepted.status, 202);
    let attempt = G2pAttempt::new(
        Uuid::new_v4(),
        "second-provider".to_owned(),
        "coordinator".to_owned(),
        instruction,
        snapshot,
        submit.clone(),
        PreparedG2pRegistryAction {
            action: "bind-payout-attempt".to_owned(),
            key: "bind-test".to_owned(),
            inputs: Default::default(),
            evidence: "prepared".to_owned(),
        },
    )
    .unwrap();
    let acceptance = ProviderAcceptance {
        correlation_id: attempt.provider_intent.correlation_id.clone(),
        references: BTreeMap::from([("payoutId".to_owned(), "provider-001".to_owned())]),
    };

    let status = PreparedProviderRequest {
        provider_pack: pack,
        role: PaymentEndpointRole::DisbursementStatus,
        method: PaymentHttpMethod::Get,
        path: "/v2/payouts/provider-001".to_owned(),
        query: BTreeMap::from([("view".to_owned(), "settlement".to_owned())]),
        headers: BTreeMap::new(),
        body: None,
    };
    let observed = provider
        .observe(&provider_binding, &attempt.provider_intent, &status)
        .await
        .unwrap();
    assert_eq!(observed.status, 200);
    let exact_observation = observation(&attempt.provider_intent.correlation_id);
    attempt
        .validate_mapped_observation(&acceptance, &exact_observation)
        .unwrap();
    for mismatched in [
        {
            let mut value = exact_observation.clone();
            value.money.minor_units = "99999".to_owned();
            value
        },
        {
            let mut value = exact_observation.clone();
            value.parties[0].value = "other-funding".to_owned();
            value
        },
        {
            let mut value = exact_observation.clone();
            value.parties[1].value = "other-recipient".to_owned();
            value
        },
    ] {
        assert!(matches!(
            attempt.validate_mapped_observation(&acceptance, &mismatched),
            Err(G2pError::Conflict)
        ));
    }

    {
        let requests = seen.lock().unwrap();
        assert_eq!(requests.len(), 2);
        assert_eq!(
            requests[0],
            SeenRequest {
                method: "POST",
                path_and_query: "/v2/payouts?channel=benefits".to_owned(),
                tenant: Some("pilot-beta".to_owned()),
                correlation_id: Some(attempt.provider_intent.correlation_id.clone()),
                signature: None,
                authorization: Some("Bearer test-only-bearer".to_owned()),
                body: exact_body,
            }
        );
        assert_eq!(
            requests[1],
            SeenRequest {
                method: "GET",
                path_and_query: "/v2/payouts/provider-001?view=settlement".to_owned(),
                tenant: None,
                correlation_id: Some(attempt.provider_intent.correlation_id.clone()),
                signature: None,
                authorization: Some("Bearer test-only-bearer".to_owned()),
                body: Vec::new(),
            }
        );
    }

    let legacy = binding(
        &origin,
        G2pHttpAuth::MifosLegacySignature {
            tenant: "pilot-beta".to_owned(),
            signing_key_identity: "test-signing-key".to_owned(),
            signing_key: Box::new(transit_key("test-signing-key", 7, 'a')),
            response_key_identity: "test-response-key".to_owned(),
            response_key: Box::new(transit_key("test-response-key", 4, 'b')),
            operations_credential_identity: "test-operations-client".to_owned(),
            operations_credential_ref: SecretReference::new("secret:file/provider-token").unwrap(),
        },
    );
    assert!(matches!(
        provider.preflight_submit(&legacy, &intent, &submit).await,
        Err(G2pProviderError::Unavailable)
    ));
    assert_eq!(seen.lock().unwrap().len(), 2);

    let mut uncertain = submit.clone();
    uncertain.path = "/v2/uncertain".to_owned();
    let uncertain_send = provider
        .preflight_submit(&provider_binding, &intent, &uncertain)
        .await
        .unwrap();
    assert!(matches!(
        uncertain_send.send().await,
        Err(G2pProviderError::OutcomeUnknown)
    ));
    assert_eq!(
        provider
            .recover_acceptance(&provider_binding, &intent, &uncertain)
            .await
            .unwrap(),
        None
    );
    let requests = seen.lock().unwrap();
    assert_eq!(requests.len(), 3);
    assert_eq!(
        requests
            .iter()
            .filter(|request| request.path_and_query.starts_with("/v2/uncertain"))
            .count(),
        1
    );
    server.abort();
}

#[derive(Clone)]
struct LegacyHttpState {
    fixture: Arc<Value>,
    seen: Arc<Mutex<Vec<SeenRequest>>>,
}

#[tokio::test]
async fn mifos_legacy_signature_host_signs_exact_requests_and_verifies_before_mapping() {
    let fixture = Arc::new(legacy_fixture());
    let (_transit_directory, socket_path, transit_digests, transit_server) =
        spawn_legacy_transit(fixture.clone());
    let seen = Arc::new(Mutex::new(Vec::new()));
    let router = Router::new()
        .route("/legacy/submit", post(legacy_valid))
        .route("/legacy/status", get(legacy_operations_status))
        .route("/legacy/rs256", post(legacy_rs256))
        .route("/legacy/changed", post(legacy_changed_body))
        .route("/legacy/wrong-tenant", post(legacy_wrong_tenant))
        .route("/legacy/missing-signature", post(legacy_missing_signature))
        .route(
            "/legacy/repeated-signature",
            post(legacy_repeated_signature),
        )
        .route("/legacy/missing-tenant", post(legacy_missing_tenant))
        .route("/legacy/repeated-tenant", post(legacy_repeated_tenant))
        .with_state(LegacyHttpState {
            fixture: fixture.clone(),
            seen: seen.clone(),
        });
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}/", listener.local_addr().unwrap());
    let http_server = tokio::spawn(async move {
        axum::serve(listener, router).await.unwrap();
    });

    let secret_directory = tempfile::tempdir().unwrap();
    write_secret(
        secret_directory.path().join("operations-token"),
        b"test-only-operations-bearer",
    );
    let resolver =
        Arc::new(SecretResolver::new([SecretProvider::File], secret_directory.path()).unwrap());
    let provider_binding = binding(
        &origin,
        G2pHttpAuth::MifosLegacySignature {
            tenant: fixture_text(&fixture, "tenant").to_owned(),
            signing_key_identity: "transit:mifos-request:v7".to_owned(),
            signing_key: Box::new(released_transit_key(
                &socket_path,
                "mifos-request",
                &fixture,
            )),
            response_key_identity: "transit:mifos-response:v7".to_owned(),
            response_key: Box::new(released_transit_key(
                &socket_path,
                "mifos-response",
                &fixture,
            )),
            operations_credential_identity: "mifos-operations-client".to_owned(),
            operations_credential_ref: SecretReference::new("secret:file/operations-token")
                .unwrap(),
        },
    );
    assert_eq!(
        provider_binding.credential_ref().as_str(),
        "secret:file/operations-token"
    );
    let provider =
        HttpG2pProvider::initialize(resolver.clone(), std::slice::from_ref(&provider_binding))
            .await
            .unwrap();
    let pack = pin();
    let snapshot = snapshot(provider_binding.clone(), pack.clone());
    let intent = snapshot.provider_intent(&instruction()).unwrap();
    let exact_body = registry_platform_canonical_json::canonicalize_json(&json!({
        "requestId": "batch-request-1",
        "correlationId": intent.correlation_id,
        "amount": "1000.00"
    }))
    .unwrap();
    let submit = legacy_request(
        pack.clone(),
        PaymentEndpointRole::DisbursementSubmit,
        PaymentHttpMethod::Post,
        "/legacy/submit",
        Some(exact_body.clone()),
    );
    let retained_preflight = HttpG2pProvider::new(resolver.clone())
        .preflight_submit(&provider_binding, &intent, &submit)
        .await
        .expect("a retained pre-dispatch binding initializes its exact pinned keys after restart");
    assert!(seen.lock().unwrap().is_empty());
    drop(retained_preflight);
    let prepared = provider
        .preflight_submit(&provider_binding, &intent, &submit)
        .await
        .unwrap();
    assert!(seen.lock().unwrap().is_empty());
    let response = prepared.send().await.unwrap();
    assert_eq!(response.status, 202);
    assert_eq!(response.body, fixture_text(&fixture, "body").as_bytes());

    let status = legacy_request(
        pack.clone(),
        PaymentEndpointRole::DisbursementStatus,
        PaymentHttpMethod::Get,
        "/legacy/status",
        None,
    );
    provider
        .observe(&provider_binding, &intent, &status)
        .await
        .unwrap();
    HttpG2pProvider::new(resolver)
        .observe(&provider_binding, &intent, &status)
        .await
        .expect("accepted attempts do not need the retired Bulk signing runtime for status");

    let rs256 = legacy_request(
        pack.clone(),
        PaymentEndpointRole::DisbursementSubmit,
        PaymentHttpMethod::Post,
        "/legacy/rs256",
        Some(exact_body.clone()),
    );
    let prepared = provider
        .preflight_submit(&provider_binding, &intent, &rs256)
        .await
        .unwrap();
    assert!(matches!(
        prepared.send().await,
        Err(G2pProviderError::OutcomeUnknown)
    ));

    for path in [
        "/legacy/changed",
        "/legacy/wrong-tenant",
        "/legacy/missing-signature",
        "/legacy/repeated-signature",
        "/legacy/missing-tenant",
        "/legacy/repeated-tenant",
    ] {
        let request = legacy_request(
            pack.clone(),
            PaymentEndpointRole::DisbursementSubmit,
            PaymentHttpMethod::Post,
            path,
            Some(exact_body.clone()),
        );
        let prepared = provider
            .preflight_submit(&provider_binding, &intent, &request)
            .await
            .unwrap();
        assert!(matches!(
            prepared.send().await,
            Err(G2pProviderError::OutcomeUnknown)
        ));
    }

    let request_count = seen.lock().unwrap().len();
    let transit_request_count = transit_digests.lock().unwrap().len();
    let mut mapped_batch_id = submit.clone();
    mapped_batch_id.headers.insert(
        "x-batchid".to_owned(),
        "mapping-must-not-select-signed-batch-id".to_owned(),
    );
    assert!(matches!(
        provider
            .preflight_submit(&provider_binding, &intent, &mapped_batch_id)
            .await,
        Err(G2pProviderError::Unavailable)
    ));
    assert_eq!(transit_digests.lock().unwrap().len(), transit_request_count);
    assert_eq!(seen.lock().unwrap().len(), request_count);

    let mut mapped_submit_auth = submit.clone();
    mapped_submit_auth.headers.insert(
        "x-signature".to_owned(),
        "mapping-must-not-select-signatures".to_owned(),
    );
    assert!(matches!(
        provider
            .preflight_submit(&provider_binding, &intent, &mapped_submit_auth)
            .await,
        Err(G2pProviderError::Unavailable)
    ));
    let mut mapped_status_auth = status.clone();
    mapped_status_auth.headers.insert(
        "authorization".to_owned(),
        "mapping-must-not-select-bearer".to_owned(),
    );
    assert!(matches!(
        provider
            .observe(&provider_binding, &intent, &mapped_status_auth)
            .await,
        Err(G2pProviderError::Unavailable)
    ));
    assert_eq!(seen.lock().unwrap().len(), request_count);

    let requests = seen.lock().unwrap();
    assert_eq!(requests.len(), 10);
    for request in requests.iter().filter(|request| request.method == "POST") {
        assert_eq!(request.tenant.as_deref(), Some("pilot"));
        assert_eq!(
            request.correlation_id.as_deref(),
            Some(intent.correlation_id.as_str())
        );
        assert_eq!(
            request.signature.as_deref(),
            Some(fixture_text(&fixture, "signatureBase64"))
        );
        assert!(request.authorization.is_none());
    }
    assert_eq!(requests[1].method, "GET");
    assert_eq!(requests[1].tenant.as_deref(), Some("pilot"));
    assert_eq!(
        requests[1].correlation_id.as_deref(),
        Some(intent.correlation_id.as_str())
    );
    assert!(requests[1].signature.is_none());
    assert_eq!(
        requests[1].authorization.as_deref(),
        Some("Bearer test-only-operations-bearer")
    );
    assert_eq!(requests[2], requests[1]);
    assert_eq!(requests[0].body, exact_body);
    assert!(requests[1].body.is_empty());

    let submit_digest = legacy_signature_digest(
        LegacySignatureHeaders::bulk_request(&intent.correlation_id, "pilot"),
        &requests[0].body,
    )
    .unwrap();
    let transit_digests = transit_digests.lock().unwrap();
    assert!(transit_digests
        .iter()
        .any(|digest| digest == submit_digest.as_str()));
    assert!(transit_digests
        .iter()
        .any(|digest| digest == fixture_text(&fixture, "bodyOnlySha3Hex")));
    assert!(!transit_digests
        .iter()
        .any(|digest| digest == fixture_text(&fixture, "uppercaseSha3Hex")));

    http_server.abort();
    transit_server.abort();
}

async fn capture_submit(
    State(seen): State<Arc<Mutex<Vec<SeenRequest>>>>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    capture(&seen, "POST", uri, headers, body);
    (axum::http::StatusCode::ACCEPTED, r#"{"accepted":true}"#)
}

async fn capture_status(
    State(seen): State<Arc<Mutex<Vec<SeenRequest>>>>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    capture(&seen, "GET", uri, headers, body);
    (axum::http::StatusCode::OK, r#"{"state":"complete"}"#)
}

async fn capture_uncertain(
    State(seen): State<Arc<Mutex<Vec<SeenRequest>>>>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    capture(&seen, "POST", uri, headers, body);
    vec![b'x'; 131_073]
}

async fn legacy_valid(
    State(state): State<LegacyHttpState>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    capture(&state.seen, "POST", uri, headers, body);
    legacy_response(
        StatusCode::ACCEPTED,
        fixture_text(&state.fixture, "body"),
        &["pilot"],
        &[fixture_text(&state.fixture, "signatureBase64")],
    )
}

async fn legacy_operations_status(
    State(state): State<LegacyHttpState>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    capture(&state.seen, "GET", uri, headers, body);
    let mut response = Response::new(Body::from(fixture_text(&state.fixture, "body").to_owned()));
    *response.status_mut() = StatusCode::OK;
    response
}

async fn legacy_rs256(
    State(state): State<LegacyHttpState>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    capture(&state.seen, "POST", uri, headers, body);
    legacy_response(
        StatusCode::BAD_REQUEST,
        fixture_text(&state.fixture, "body"),
        &["pilot"],
        &[fixture_text(&state.fixture, "rs256SignatureBase64")],
    )
}

async fn legacy_changed_body(
    State(state): State<LegacyHttpState>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    capture(&state.seen, "POST", uri, headers, body);
    legacy_response(
        StatusCode::OK,
        fixture_text(&state.fixture, "changedBody"),
        &["pilot"],
        &[fixture_text(&state.fixture, "signatureBase64")],
    )
}

async fn legacy_wrong_tenant(
    State(state): State<LegacyHttpState>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    capture(&state.seen, "POST", uri, headers, body);
    legacy_response(
        StatusCode::OK,
        fixture_text(&state.fixture, "body"),
        &["other"],
        &[fixture_text(&state.fixture, "signatureBase64")],
    )
}

async fn legacy_missing_signature(
    State(state): State<LegacyHttpState>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    capture(&state.seen, "POST", uri, headers, body);
    legacy_response(
        StatusCode::OK,
        fixture_text(&state.fixture, "body"),
        &["pilot"],
        &[],
    )
}

async fn legacy_repeated_signature(
    State(state): State<LegacyHttpState>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    capture(&state.seen, "POST", uri, headers, body);
    legacy_response(
        StatusCode::OK,
        fixture_text(&state.fixture, "body"),
        &["pilot"],
        &[
            fixture_text(&state.fixture, "signatureBase64"),
            fixture_text(&state.fixture, "signatureBase64"),
        ],
    )
}

async fn legacy_missing_tenant(
    State(state): State<LegacyHttpState>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    capture(&state.seen, "POST", uri, headers, body);
    legacy_response(
        StatusCode::OK,
        fixture_text(&state.fixture, "body"),
        &[],
        &[fixture_text(&state.fixture, "signatureBase64")],
    )
}

async fn legacy_repeated_tenant(
    State(state): State<LegacyHttpState>,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    capture(&state.seen, "POST", uri, headers, body);
    legacy_response(
        StatusCode::OK,
        fixture_text(&state.fixture, "body"),
        &["pilot", "pilot"],
        &[fixture_text(&state.fixture, "signatureBase64")],
    )
}

fn legacy_response(
    status: StatusCode,
    body: &str,
    tenants: &[&str],
    signatures: &[&str],
) -> Response {
    let mut response = Response::new(Body::from(body.to_owned()));
    *response.status_mut() = status;
    for tenant in tenants {
        response
            .headers_mut()
            .append("Platform-TenantId", HeaderValue::from_str(tenant).unwrap());
    }
    for signature in signatures {
        response
            .headers_mut()
            .append("X-SIGNATURE", HeaderValue::from_str(signature).unwrap());
    }
    response
}

fn capture(
    seen: &Mutex<Vec<SeenRequest>>,
    method: &'static str,
    uri: Uri,
    headers: HeaderMap,
    body: Bytes,
) {
    seen.lock().unwrap().push(SeenRequest {
        method,
        path_and_query: uri
            .path_and_query()
            .expect("request target")
            .as_str()
            .to_owned(),
        tenant: headers
            .get("x-provider-tenant")
            .or_else(|| headers.get("platform-tenantid"))
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
        correlation_id: headers
            .get("x-correlationid")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
        signature: headers
            .get("x-signature")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
        authorization: headers
            .get(axum::http::header::AUTHORIZATION)
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned),
        body: body.to_vec(),
    });
}

fn legacy_request(
    provider_pack: ProviderPackPin,
    role: PaymentEndpointRole,
    method: PaymentHttpMethod,
    path: &str,
    body: Option<Vec<u8>>,
) -> PreparedProviderRequest {
    PreparedProviderRequest {
        provider_pack,
        role,
        method,
        path: path.to_owned(),
        query: BTreeMap::new(),
        headers: BTreeMap::new(),
        body,
    }
}

fn legacy_fixture() -> Value {
    serde_json::from_str(include_str!(
        "../../registry-platform-crypto/tests/fixtures/mifos-bulk-v1.12.1-response-signatures.json"
    ))
    .unwrap()
}

fn fixture_text<'a>(fixture: &'a Value, key: &str) -> &'a str {
    fixture[key].as_str().unwrap()
}

fn released_transit_key(
    socket_path: &Path,
    key: &str,
    fixture: &Value,
) -> G2pTransitRsaNoOidKeyBinding {
    serde_json::from_value(json!({
        "socketPath": socket_path,
        "mount": "transit",
        "key": key,
        "version": 7,
        "publicKeyDigest": format!("sha256:{}", fixture_text(fixture, "publicKeySpkiSha256")),
        "attemptTimeoutMilliseconds": 2000
    }))
    .unwrap()
}

fn public_key_pem(encoded: &str) -> String {
    let mut pem = String::from("-----BEGIN PUBLIC KEY-----\n");
    for line in encoded.as_bytes().chunks(64) {
        pem.push_str(std::str::from_utf8(line).unwrap());
        pem.push('\n');
    }
    pem.push_str("-----END PUBLIC KEY-----\n");
    pem
}

fn spawn_legacy_transit(
    fixture: Arc<Value>,
) -> (
    tempfile::TempDir,
    PathBuf,
    Arc<Mutex<Vec<String>>>,
    tokio::task::JoinHandle<()>,
) {
    let directory = tempfile::tempdir().unwrap();
    let socket_path = directory.path().join("transit.sock");
    let listener = UnixListener::bind(&socket_path).unwrap();
    let digests = Arc::new(Mutex::new(Vec::new()));
    let observed = digests.clone();
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let fixture = fixture.clone();
            let observed = observed.clone();
            tokio::spawn(async move {
                let (method, path, body) = read_transit_request(&mut stream).await;
                let response = match (method.as_str(), path.as_str()) {
                    ("GET", "/v1/transit/keys/mifos-request") => transit_metadata(&fixture, false),
                    ("GET", "/v1/transit/keys/mifos-response") => transit_metadata(&fixture, true),
                    ("POST", "/v1/transit/sign/mifos-request/none") => {
                        let document: Value = serde_json::from_slice(&body).unwrap();
                        assert_eq!(document["key_version"], 7);
                        assert_eq!(document["prehashed"], true);
                        assert_eq!(document["signature_algorithm"], "pkcs1v15");
                        let digest = transit_digest(&document);
                        observed.lock().unwrap().push(digest);
                        json!({"data": {"signature": format!(
                            "vault:v7:{}",
                            fixture_text(&fixture, "signatureBase64")
                        )}})
                    }
                    ("POST", path) if path.starts_with("/v1/transit/verify/") => {
                        let document: Value = serde_json::from_slice(&body).unwrap();
                        assert_eq!(document["prehashed"], true);
                        assert_eq!(document["signature_algorithm"], "pkcs1v15");
                        let digest = transit_digest(&document);
                        observed.lock().unwrap().push(digest.clone());
                        let encoded = document["signature"]
                            .as_str()
                            .unwrap()
                            .strip_prefix("vault:v7:")
                            .unwrap();
                        let candidate = STANDARD.decode(encoded).unwrap();
                        let valid = if path.contains("mifos-response") {
                            digest == fixture_text(&fixture, "bodyOnlySha3Hex")
                                && encoded == fixture_text(&fixture, "signatureBase64")
                        } else {
                            candidate.iter().any(|byte| *byte != 0)
                        };
                        json!({"data": {"valid": valid}})
                    }
                    _ => panic!("unexpected Transit request {method} {path}"),
                };
                write_transit_response(&mut stream, &response).await;
            });
        }
    });
    (directory, socket_path, digests, task)
}

fn transit_metadata(fixture: &Value, imported_key: bool) -> Value {
    json!({
        "data": {
            "type": "rsa-2048",
            "derived": false,
            "exportable": false,
            "allow_plaintext_backup": false,
            "supports_signing": true,
            "latest_version": 7,
            "min_encryption_version": 1,
            "min_decryption_version": 1,
            "imported_key": imported_key,
            "keys": {"7": {"public_key": public_key_pem(fixture_text(fixture, "publicKeySpkiBase64"))}}
        }
    })
}

fn transit_digest(document: &Value) -> String {
    let decoded = STANDARD
        .decode(document["input"].as_str().unwrap())
        .unwrap();
    let digest = String::from_utf8(decoded).unwrap();
    assert_eq!(digest.len(), 64);
    assert!(digest
        .bytes()
        .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f')));
    digest
}

async fn read_transit_request(stream: &mut tokio::net::UnixStream) -> (String, String, Vec<u8>) {
    let mut request = Vec::new();
    let header_end = loop {
        let mut chunk = [0_u8; 4096];
        let read = stream.read(&mut chunk).await.unwrap();
        assert_ne!(read, 0);
        request.extend_from_slice(&chunk[..read]);
        if let Some(position) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
            break position + 4;
        }
    };
    let headers = std::str::from_utf8(&request[..header_end]).unwrap();
    assert!(headers
        .to_ascii_lowercase()
        .contains("x-vault-request: true"));
    let mut lines = headers.lines();
    let mut request_line = lines.next().unwrap().split_whitespace();
    let method = request_line.next().unwrap().to_owned();
    let path = request_line.next().unwrap().to_owned();
    let content_length = lines
        .filter_map(|line| line.split_once(':'))
        .find(|(name, _)| name.eq_ignore_ascii_case("content-length"))
        .map(|(_, value)| value.trim().parse::<usize>().unwrap())
        .unwrap_or(0);
    while request.len() < header_end + content_length {
        let mut chunk = [0_u8; 4096];
        let read = stream.read(&mut chunk).await.unwrap();
        assert_ne!(read, 0);
        request.extend_from_slice(&chunk[..read]);
    }
    (
        method,
        path,
        request[header_end..header_end + content_length].to_vec(),
    )
}

async fn write_transit_response(stream: &mut tokio::net::UnixStream, response: &Value) {
    let body = serde_json::to_vec(response).unwrap();
    let headers = format!(
        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(headers.as_bytes()).await.unwrap();
    stream.write_all(&body).await.unwrap();
}

fn binding(origin: &str, auth: G2pHttpAuth) -> G2pProviderBinding {
    G2pProviderBinding::Http {
        revision: "second-provider-v1".to_owned(),
        submit_base_url: origin.to_owned(),
        status_base_url: origin.to_owned(),
        auth,
        settings: json!({"tenant": "pilot-beta"}),
    }
}

fn transit_key(key: &str, version: u32, digest_digit: char) -> G2pTransitRsaNoOidKeyBinding {
    serde_json::from_value(json!({
        "socketPath": "/run/registry/transit.sock",
        "mount": "transit",
        "key": key,
        "version": version,
        "publicKeyDigest": format!("sha256:{}", digest_digit.to_string().repeat(64)),
        "attemptTimeoutMilliseconds": 2000
    }))
    .unwrap()
}

fn pin() -> ProviderPackPin {
    ProviderPackPin {
        id: "second-provider".to_owned(),
        version: "1".to_owned(),
        digest: format!("sha256:{}", "a".repeat(64)),
    }
}

fn instruction() -> DisbursementInstruction {
    DisbursementInstruction {
        record_id: Uuid::parse_str("00000000-0000-4000-8000-000000000200").unwrap(),
        instruction_id: Uuid::parse_str("00000000-0000-4000-8000-000000000201").unwrap(),
        instruction_version: 1,
        instruction_digest: "a".repeat(64),
        institution_id: "ministry-social-protection".to_owned(),
        service_id: "cash-transfer".to_owned(),
        programme_id: "cash-programme".to_owned(),
        cycle_id: "cycle-2026-11".to_owned(),
        beneficiary_id: "beneficiary-001".to_owned(),
        beneficiary_destination: "254700000002".to_owned(),
        funding_account_id: "programme-account".to_owned(),
        amount_minor: 100_000,
        currency: "KES".to_owned(),
        currency_scale: 2,
    }
}

fn snapshot(provider: G2pProviderBinding, provider_pack: ProviderPackPin) -> G2pConnectionSnapshot {
    G2pConnectionSnapshot {
        institution_id: "ministry-social-protection".to_owned(),
        service_id: "cash-transfer".to_owned(),
        programme_id: "cash-programme".to_owned(),
        funding_account_id: "programme-account".to_owned(),
        currency: "KES".to_owned(),
        currency_scale: 2,
        provider_pack,
        funding_party_key: "ACCOUNT_ID".to_owned(),
        recipient_party_key: "MSISDN".to_owned(),
        provider,
        registry: G2pRegistryBinding {
            base_url: "https://breg.invalid/".to_owned(),
            credential_identity: "g2p-adapter".to_owned(),
            credential_ref: SecretReference::new("secret:file/provider-token").unwrap(),
            record_route: "disbursement-instructions".to_owned(),
            record_type: "disbursement-instruction".to_owned(),
            read_profile: "g2p-adapter-read".to_owned(),
            bind_action: "bind-payout-attempt".to_owned(),
            bind_profile: "g2p-adapter-bind".to_owned(),
            report_action: "record-provider-confirmation".to_owned(),
            report_profile: "g2p-adapter-report".to_owned(),
        },
    }
}

fn observation(correlation_id: &str) -> ProviderObservation {
    ProviderObservation {
        correlation_id: correlation_id.to_owned(),
        provider_reference: "provider-001".to_owned(),
        state: ProviderObservationState::ProviderConfirmed,
        money: ProviderObservedMoney {
            minor_units: "100000".to_owned(),
            currency: "KES".to_owned(),
            scale: 2,
        },
        parties: vec![
            ProviderObservedParty {
                role: ProviderPartyRole::Funding,
                key: "ACCOUNT_ID".to_owned(),
                value: "programme-account".to_owned(),
            },
            ProviderObservedParty {
                role: ProviderPartyRole::Recipient,
                key: "MSISDN".to_owned(),
                value: "254700000002".to_owned(),
            },
        ],
    }
}

fn write_secret(path: std::path::PathBuf, value: &[u8]) {
    std::fs::write(&path, value).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}
