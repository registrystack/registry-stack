//! Black-box recovery, concurrency, and failure-state coverage for the
//! process-local OID4VCI exchange.
//!
//! These tests use the exported router and the two exported service seams. A
//! recording issuer is the complete Evidence boundary: when its call count is
//! zero, no Evidence request, source access, or Evidence release audit could
//! have happened behind a refused wallet request.

use std::{
    fs,
    sync::{Arc, Mutex},
    time::Duration,
};

use async_trait::async_trait;
use axum::{body::Bytes, http::StatusCode};
use axum_test::{TestResponse, TestServer};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use p256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng};
use registry_evidence_client::{
    EvidenceDefinitionsDocument, HolderBoundRequestSpec, SubjectBindingMode,
};
use registry_evidence_oid4vci::{
    authorizer::{AuthorizationError, AuthorizedOffer, OfferAuthorizer},
    config::DeliveryConfig,
    issuer::{CredentialIssuer, IssuanceError},
    metadata::CredentialCatalog,
    service::{
        build_app, DeliveryService, CREDENTIAL_PATH, ISSUER_METADATA_PATH, NONCE_PATH, OFFERS_PATH,
        TOKEN_PATH,
    },
    PRE_AUTHORIZED_CODE_GRANT_TYPE,
};
use registry_platform_crypto::{sign, PrivateJwk};
use serde_json::{json, Value};
use tokio::sync::Barrier;

const OFFER_TOKEN: &str = "offer-token";
const CONFIGURATION_ID: &str = "urn:example:requirement:holder-bound";
const SELECTOR_VALUE: &str = "subject-identifier-value";

const CONFIG: &str = r#"
version: 1
credentialIssuer: https://wallet.example.org
listener: {address: 127.0.0.1, port: 8090}
evidence:
  baseUrl: https://evidence.example.org
mint:
  tokenEndpoint: https://mint.example.org/token
  clientId: evidence-oid4vci
  privateKeyFile: unused-delivery-client.jwk.json
offers:
  issuer: https://mint.example.org
  jwksUri: https://mint.example.org/.well-known/jwks.json
  audiences: ["https://wallet.example.org"]
  algorithms: [EdDSA]
  authorizedClients: [adopter-front-end]
  maximumTokenLifetimeSeconds: 900
store:
  maximumOffers: 4096
  offerLifetimeSeconds: 300
  accessTokenLifetimeSeconds: 300
  nonceLifetimeSeconds: 120
  maximumTransactionCodeAttempts: 3
"#;

const DEFINITIONS: &str = r#"{
  "schema": "registry.evidence-definitions/v1",
  "assuranceProfile": "local",
  "audience": "https://wallet.example.org",
  "issuedBy": "https://registry.example.org",
  "providedBy": "https://provider.example.org",
  "holderBoundBatchMaxSize": 4,
  "definitions": [{
    "handle": "holder-bound",
    "requirement": "urn:example:requirement:holder-bound",
    "configurationRevision": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    "kind": "criterion",
    "subjectBindingMode": "holder-bound",
    "evidenceType": "urn:example:evidence-type:holder-bound",
    "purpose": "urn:example:purpose:demonstration",
    "responseFormats": ["sd-jwt-vc"],
    "referenceFrameworks": [],
    "subjects": [{
      "role": "primary",
      "cardinality": "one",
      "selector": {
        "profile": "synthetic-identifier-v1",
        "valueOrigin": "request",
        "fields": [{
          "type": "string",
          "name": "identifier",
          "minimumBytes": 1,
          "maximumBytes": 64
        }]
      }
    }],
    "concepts": [{"handle": "outcome", "concept": "urn:example:concept:outcome", "required": true, "form": "boolean"}]
  }]
}"#;

struct StubAuthorizer;

#[async_trait]
impl OfferAuthorizer for StubAuthorizer {
    async fn authorize(&self, credential: &str) -> Result<AuthorizedOffer, AuthorizationError> {
        if credential.is_empty() {
            return Err(AuthorizationError::Missing);
        }
        if credential != OFFER_TOKEN {
            return Err(AuthorizationError::Refused);
        }
        Ok(AuthorizedOffer {
            client: Some("adopter-front-end".to_owned()),
            subject: None,
        })
    }
}

struct RecordingIssuer {
    catalog: Arc<CredentialCatalog>,
    requests: Mutex<Vec<HolderBoundRequestSpec>>,
}

fn credential_catalog() -> Arc<CredentialCatalog> {
    credential_catalog_with_batch_maximum(4)
}

fn credential_catalog_with_batch_maximum(maximum: u16) -> Arc<CredentialCatalog> {
    let mut document: EvidenceDefinitionsDocument =
        serde_json::from_str(DEFINITIONS).expect("the test definitions parse");
    document.holder_bound_batch_max_size = maximum;
    assert_eq!(
        document.definitions[0].subject_binding_mode,
        Some(SubjectBindingMode::HolderBound)
    );
    Arc::new(CredentialCatalog::derive(&document))
}

impl RecordingIssuer {
    fn new() -> Self {
        Self::with_batch_maximum(4)
    }

    fn with_batch_maximum(maximum: u16) -> Self {
        Self {
            catalog: credential_catalog_with_batch_maximum(maximum),
            requests: Mutex::new(Vec::new()),
        }
    }

    fn call_count(&self) -> usize {
        self.requests
            .lock()
            .expect("the Evidence recorder is usable")
            .len()
    }
}

#[derive(Clone, Copy, Debug)]
enum PostClaimFailure {
    Refused,
    NotAvailable,
    Unavailable,
    Malformed,
    Configuration,
}

impl PostClaimFailure {
    fn error(self) -> IssuanceError {
        match self {
            Self::Refused => IssuanceError::Refused,
            Self::NotAvailable => IssuanceError::NotAvailable,
            Self::Unavailable => IssuanceError::Unavailable,
            Self::Malformed => IssuanceError::Malformed,
            Self::Configuration => {
                IssuanceError::Configuration("a private test-only configuration cause")
            }
        }
    }
}

struct FailingIssuer {
    catalog: Arc<CredentialCatalog>,
    failure: PostClaimFailure,
    attempts: Mutex<usize>,
}

#[derive(Clone, Copy)]
enum SlowBoundary {
    Catalog,
    Issuance,
}

struct SlowIssuer {
    catalog: Arc<CredentialCatalog>,
    slow_boundary: SlowBoundary,
    catalog_calls: Mutex<usize>,
    issuance_calls: Mutex<usize>,
}

impl SlowIssuer {
    fn new(slow_boundary: SlowBoundary) -> Self {
        Self {
            catalog: credential_catalog(),
            slow_boundary,
            catalog_calls: Mutex::new(0),
            issuance_calls: Mutex::new(0),
        }
    }

    fn catalog_call_count(&self) -> usize {
        *self
            .catalog_calls
            .lock()
            .expect("the slow catalog recorder is usable")
    }

    fn issuance_call_count(&self) -> usize {
        *self
            .issuance_calls
            .lock()
            .expect("the slow issuance recorder is usable")
    }
}

impl FailingIssuer {
    fn new(failure: PostClaimFailure) -> Self {
        Self {
            catalog: credential_catalog(),
            failure,
            attempts: Mutex::new(0),
        }
    }

    fn call_count(&self) -> usize {
        *self
            .attempts
            .lock()
            .expect("the failing Evidence recorder is usable")
    }
}

#[async_trait]
impl CredentialIssuer for FailingIssuer {
    async fn catalog(&self) -> Result<Arc<CredentialCatalog>, IssuanceError> {
        Ok(Arc::clone(&self.catalog))
    }

    async fn issue(&self, _spec: HolderBoundRequestSpec) -> Result<Vec<String>, IssuanceError> {
        *self
            .attempts
            .lock()
            .expect("the failing Evidence recorder is usable") += 1;
        Err(self.failure.error())
    }
}

#[async_trait]
impl CredentialIssuer for SlowIssuer {
    async fn catalog(&self) -> Result<Arc<CredentialCatalog>, IssuanceError> {
        *self
            .catalog_calls
            .lock()
            .expect("the slow catalog recorder is usable") += 1;
        if matches!(self.slow_boundary, SlowBoundary::Catalog) {
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        Ok(Arc::clone(&self.catalog))
    }

    async fn issue(&self, spec: HolderBoundRequestSpec) -> Result<Vec<String>, IssuanceError> {
        *self
            .issuance_calls
            .lock()
            .expect("the slow issuance recorder is usable") += 1;
        if matches!(self.slow_boundary, SlowBoundary::Issuance) {
            tokio::time::sleep(Duration::from_secs(5)).await;
        }
        Ok((0..spec.holder_keys.len())
            .map(|index| format!("signed.credential.{index}"))
            .collect())
    }
}

#[async_trait]
impl CredentialIssuer for RecordingIssuer {
    async fn catalog(&self) -> Result<Arc<CredentialCatalog>, IssuanceError> {
        Ok(Arc::clone(&self.catalog))
    }

    async fn issue(&self, spec: HolderBoundRequestSpec) -> Result<Vec<String>, IssuanceError> {
        let credentials = (0..spec.holder_keys.len())
            .map(|index| format!("signed.credential.{index}"))
            .collect();
        self.requests
            .lock()
            .expect("the Evidence recorder is usable")
            .push(spec);
        // Widen the interval in which concurrent requests overlap after the
        // first request has atomically claimed the access token.
        tokio::time::sleep(Duration::from_millis(5)).await;
        Ok(credentials)
    }
}

struct Harness {
    server: Arc<TestServer>,
    issuer: Arc<RecordingIssuer>,
}

fn loaded_config() -> DeliveryConfig {
    let directory = tempfile::tempdir().expect("a temporary deployment directory");
    let path = directory.path().join("oid4vci.yaml");
    fs::write(&path, CONFIG).expect("write the test deployment");
    DeliveryConfig::load(&path).expect("the reference deployment loads before test mutation")
}

fn server_with_issuer(
    mut config: DeliveryConfig,
    issuer: Arc<dyn CredentialIssuer>,
) -> Arc<TestServer> {
    // The listener belongs to a real deployment. axum-test binds its own
    // random loopback port, while every published identifier remains the
    // deployment's exact configured value.
    config.listener.port = 8090;
    let service = Arc::new(DeliveryService::with_halves(
        config,
        Arc::new(StubAuthorizer),
        issuer,
    ));
    Arc::new(
        TestServer::builder()
            .http_transport()
            .build(build_app(service)),
    )
}

fn harness(config: DeliveryConfig) -> Harness {
    let issuer = Arc::new(RecordingIssuer::new());
    let server = server_with_issuer(config, Arc::clone(&issuer) as Arc<dyn CredentialIssuer>);
    Harness { server, issuer }
}

fn offer_body(transaction_code: bool) -> Value {
    json!({
        "credentialConfigurationId": CONFIGURATION_ID,
        "subjects": [{
            "role": "primary",
            "selectorValues": {"identifier": SELECTOR_VALUE},
        }],
        "transactionCode": transaction_code,
    })
}

fn token_form(code: &str, transaction_code: Option<&str>) -> Vec<(String, String)> {
    let mut form = vec![
        (
            "grant_type".to_owned(),
            PRE_AUTHORIZED_CODE_GRANT_TYPE.to_owned(),
        ),
        ("pre-authorized_code".to_owned(), code.to_owned()),
    ];
    if let Some(transaction_code) = transaction_code {
        form.push(("tx_code".to_owned(), transaction_code.to_owned()));
    }
    form
}

fn offered_code(offer: &Value) -> String {
    offer["credentialOffer"]["grants"][PRE_AUTHORIZED_CODE_GRANT_TYPE]["pre-authorized_code"]
        .as_str()
        .expect("the offer carries a pre-authorized code")
        .to_owned()
}

async fn create_offer(server: &TestServer, transaction_code: bool) -> Value {
    let response = server
        .post(OFFERS_PATH)
        .add_header("authorization", format!("Bearer {OFFER_TOKEN}"))
        .json(&offer_body(transaction_code))
        .await;
    assert_eq!(response.status_code(), StatusCode::CREATED);
    response.json()
}

async fn access_token(server: &TestServer) -> String {
    let code = offered_code(&create_offer(server, false).await);
    let response = server.post(TOKEN_PATH).form(&token_form(&code, None)).await;
    assert_eq!(response.status_code(), StatusCode::OK);
    response.json::<Value>()["access_token"]
        .as_str()
        .expect("the response carries an access token")
        .to_owned()
}

async fn minted_nonce(server: &TestServer) -> String {
    let response = server.post(NONCE_PATH).await;
    assert_eq!(response.status_code(), StatusCode::OK);
    response.json::<Value>()["c_nonce"]
        .as_str()
        .expect("the response carries a nonce")
        .to_owned()
}

fn private_jwk() -> String {
    let key = SigningKey::random(&mut OsRng);
    let point = key.verifying_key().to_encoded_point(false);
    json!({
        "kty": "EC",
        "crv": "P-256",
        "alg": "ES256",
        "kid": "holder-key",
        "x": URL_SAFE_NO_PAD.encode(point.x().expect("the public key has x")),
        "y": URL_SAFE_NO_PAD.encode(point.y().expect("the public key has y")),
        "d": URL_SAFE_NO_PAD.encode(key.to_bytes()),
    })
    .to_string()
}

fn proof_jwt(private_key: &str, nonce: &str) -> String {
    let private = PrivateJwk::parse(private_key).expect("the holder key parses");
    let header = json!({
        "alg": "ES256",
        "typ": "openid4vci-proof+jwt",
        "jwk": private.public(),
    });
    let claims = json!({
        "aud": "https://wallet.example.org",
        "iat": chrono::Utc::now().timestamp(),
        "nonce": nonce,
    });
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let signature = sign(signing_input.as_bytes(), &private).expect("the holder proof signs");
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

fn credential_body(proofs: Vec<String>) -> Value {
    json!({
        "credential_configuration_id": CONFIGURATION_ID,
        "proofs": {"jwt": proofs},
    })
}

fn error_code(response: &TestResponse) -> String {
    response.json::<Value>()["error"]
        .as_str()
        .expect("the protocol error has a code")
        .to_owned()
}

fn assert_closed_error(response: &TestResponse, expected: &str, forbidden: &[&str]) {
    assert_eq!(
        response
            .header("content-type")
            .to_str()
            .expect("the content type is ASCII"),
        "application/json"
    );
    let body: Value = response.json();
    let object = body.as_object().expect("the protocol error is an object");
    assert_eq!(object.len(), 2, "a refusal has only the two OAuth members");
    assert!(object.contains_key("error"));
    assert!(object.contains_key("error_description"));
    assert_eq!(body["error"], json!(expected));
    let bytes = response.as_bytes();
    for value in forbidden {
        assert!(
            !bytes
                .windows(value.len())
                .any(|window| window == value.as_bytes()),
            "a refusal rendered request or state material"
        );
    }
}

fn assert_exact_problem(
    response: &TestResponse,
    status: StatusCode,
    error: &str,
    description: &str,
    forbidden: &[&str],
) {
    assert_eq!(response.status_code(), status);
    assert_closed_error(response, error, forbidden);
    assert_eq!(
        response.json::<Value>(),
        json!({"error": error, "error_description": description})
    );
}

#[tokio::test]
async fn a_recognized_token_is_claimed_before_every_later_validation_failure() {
    enum Case {
        InvalidJson,
        OtherConfiguration,
        InvalidNonce,
        InvalidProof,
        DuplicateHolderThumbprint,
    }

    let harness = harness(loaded_config());
    let key = private_jwk();
    for case in [
        Case::InvalidJson,
        Case::OtherConfiguration,
        Case::InvalidNonce,
        Case::InvalidProof,
        Case::DuplicateHolderThumbprint,
    ] {
        let token = access_token(&harness.server).await;
        let nonce = minted_nonce(&harness.server).await;
        let accepted_proof = proof_jwt(&key, &nonce);
        let (response, expected_error) = match case {
            Case::InvalidJson => (
                harness
                    .server
                    .post(CREDENTIAL_PATH)
                    .add_header("authorization", format!("Bearer {token}"))
                    .text("{")
                    .await,
                "invalid_credential_request",
            ),
            Case::OtherConfiguration => (
                harness
                    .server
                    .post(CREDENTIAL_PATH)
                    .add_header("authorization", format!("Bearer {token}"))
                    .json(&json!({
                        "credential_configuration_id": "urn:example:other",
                        "proofs": {"jwt": [accepted_proof.clone()]},
                    }))
                    .await,
                "invalid_credential_request",
            ),
            Case::InvalidNonce => (
                harness
                    .server
                    .post(CREDENTIAL_PATH)
                    .add_header("authorization", format!("Bearer {token}"))
                    .json(&credential_body(vec![proof_jwt(
                        &key,
                        "not-a-service-nonce",
                    )]))
                    .await,
                "invalid_nonce",
            ),
            Case::InvalidProof => (
                harness
                    .server
                    .post(CREDENTIAL_PATH)
                    .add_header("authorization", format!("Bearer {token}"))
                    .json(&credential_body(vec!["a.b.c".to_owned()]))
                    .await,
                "invalid_proof",
            ),
            Case::DuplicateHolderThumbprint => (
                harness
                    .server
                    .post(CREDENTIAL_PATH)
                    .add_header("authorization", format!("Bearer {token}"))
                    .json(&credential_body(vec![
                        accepted_proof.clone(),
                        accepted_proof.clone(),
                    ]))
                    .await,
                "invalid_proof",
            ),
        };
        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
        assert_eq!(error_code(&response), expected_error);

        // Correcting every request member cannot restore the claimed token.
        let retry = harness
            .server
            .post(CREDENTIAL_PATH)
            .add_header("authorization", format!("Bearer {token}"))
            .json(&credential_body(vec![accepted_proof]))
            .await;
        assert_eq!(retry.status_code(), StatusCode::UNAUTHORIZED);
        assert_closed_error(&retry, "invalid_token", &[&token, SELECTOR_VALUE]);
    }
    assert_eq!(
        harness.issuer.call_count(),
        0,
        "no Evidence request or release audit follows a validation refusal"
    );
}

#[tokio::test]
async fn invalid_utf8_is_refused_inside_the_authorization_and_claim_boundaries() {
    const BODY_CANARY: &str = "invalid-utf8-request-canary";
    let invalid_body = || Bytes::from_static(b"invalid-utf8-request-canary:\xff");
    let harness = harness(loaded_config());

    let unauthorized_offer = harness
        .server
        .post(OFFERS_PATH)
        .content_type("application/json")
        .bytes(invalid_body())
        .await;
    assert_exact_problem(
        &unauthorized_offer,
        StatusCode::UNAUTHORIZED,
        "invalid_token",
        "a bearer access token is required",
        &[BODY_CANARY],
    );

    let authorized_offer = harness
        .server
        .post(OFFERS_PATH)
        .add_header("authorization", format!("Bearer {OFFER_TOKEN}"))
        .content_type("application/json")
        .bytes(invalid_body())
        .await;
    assert_exact_problem(
        &authorized_offer,
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "the offer request is not a document this service accepts",
        &[BODY_CANARY, CONFIGURATION_ID, SELECTOR_VALUE],
    );

    let invalid_nonce = harness
        .server
        .post(NONCE_PATH)
        .content_type("application/json")
        .bytes(invalid_body())
        .await;
    assert_exact_problem(
        &invalid_nonce,
        StatusCode::BAD_REQUEST,
        "invalid_request",
        "the nonce request must be empty",
        &[BODY_CANARY],
    );

    let token = access_token(&harness.server).await;
    let nonce = minted_nonce(&harness.server).await;
    let accepted = credential_body(vec![proof_jwt(&private_jwk(), &nonce)]);
    let invalid_credential = harness
        .server
        .post(CREDENTIAL_PATH)
        .add_header("authorization", format!("Bearer {token}"))
        .content_type("application/json")
        .bytes(invalid_body())
        .await;
    assert_exact_problem(
        &invalid_credential,
        StatusCode::BAD_REQUEST,
        "invalid_credential_request",
        "the credential request is not a document this service accepts",
        &[
            BODY_CANARY,
            &token,
            &nonce,
            CONFIGURATION_ID,
            SELECTOR_VALUE,
        ],
    );

    let retry = harness
        .server
        .post(CREDENTIAL_PATH)
        .add_header("authorization", format!("Bearer {token}"))
        .json(&accepted)
        .await;
    assert_exact_problem(
        &retry,
        StatusCode::UNAUTHORIZED,
        "invalid_token",
        "the access token cannot be used",
        &[&token, &nonce, CONFIGURATION_ID, SELECTOR_VALUE],
    );
    assert_eq!(
        harness.issuer.call_count(),
        0,
        "no invalid UTF-8 path or spent-token retry reaches Evidence"
    );
}

#[tokio::test]
async fn raw_body_extraction_keeps_the_framework_payload_limit() {
    let mut config = loaded_config();
    config.listener.maximum_request_bytes = 8;
    let harness = harness(config);
    let oversized = Bytes::from_static(b"123456789");

    for path in [OFFERS_PATH, NONCE_PATH, CREDENTIAL_PATH] {
        let response = harness
            .server
            .post(path)
            .add_header("authorization", format!("Bearer {OFFER_TOKEN}"))
            .content_type("application/json")
            .bytes(oversized.clone())
            .await;
        assert_eq!(
            response.status_code(),
            StatusCode::PAYLOAD_TOO_LARGE,
            "{path}"
        );
        assert_eq!(
            response.header("content-type").to_str().expect("ASCII"),
            "text/plain; charset=utf-8",
            "{path}"
        );
        assert_eq!(
            response.text(),
            "Failed to buffer the request body: length limit exceeded",
            "{path}"
        );
    }
    assert_eq!(
        harness.issuer.call_count(),
        0,
        "a framework body-limit refusal never reaches Evidence"
    );
}

#[tokio::test]
async fn post_claim_evidence_failures_are_terminal_and_never_restore_the_token() {
    for failure in [
        PostClaimFailure::Refused,
        PostClaimFailure::NotAvailable,
        PostClaimFailure::Unavailable,
        PostClaimFailure::Malformed,
        PostClaimFailure::Configuration,
    ] {
        let issuer = Arc::new(FailingIssuer::new(failure));
        let server = server_with_issuer(
            loaded_config(),
            Arc::clone(&issuer) as Arc<dyn CredentialIssuer>,
        );
        let token = access_token(&server).await;
        let nonce = minted_nonce(&server).await;
        let request = credential_body(vec![proof_jwt(&private_jwk(), &nonce)]);

        let terminal = server
            .post(CREDENTIAL_PATH)
            .add_header("authorization", format!("Bearer {token}"))
            .json(&request)
            .await;
        assert_eq!(
            terminal.status_code(),
            StatusCode::BAD_REQUEST,
            "{failure:?}"
        );
        assert_closed_error(
            &terminal,
            "credential_request_denied",
            &[&token, &nonce, SELECTOR_VALUE, "private test-only"],
        );
        assert_eq!(
            issuer.call_count(),
            1,
            "{failure:?} reaches the Evidence boundary once"
        );

        // A deployment failure may be transient, but this authorization is not:
        // the token was permanently claimed before Evidence was called. A retry
        // needs a newly authorized exchange and must never re-enter Evidence.
        let retry = server
            .post(CREDENTIAL_PATH)
            .add_header("authorization", format!("Bearer {token}"))
            .json(&request)
            .await;
        assert_eq!(retry.status_code(), StatusCode::UNAUTHORIZED, "{failure:?}");
        assert_closed_error(&retry, "invalid_token", &[&token, &nonce, SELECTOR_VALUE]);
        assert_eq!(
            issuer.call_count(),
            1,
            "{failure:?} must not rebind the spent token"
        );
    }
}

#[tokio::test]
async fn a_post_claim_timeout_is_terminal_and_never_restores_the_token() {
    let mut config = loaded_config();
    config.listener.request_timeout_milliseconds = 100;
    let issuer = Arc::new(SlowIssuer::new(SlowBoundary::Issuance));
    let server = server_with_issuer(config, Arc::clone(&issuer) as Arc<dyn CredentialIssuer>);
    let token = access_token(&server).await;
    let nonce = minted_nonce(&server).await;
    let request = credential_body(vec![proof_jwt(&private_jwk(), &nonce)]);

    let terminal = server
        .post(CREDENTIAL_PATH)
        .add_header("authorization", format!("Bearer {token}"))
        .json(&request)
        .await;
    assert_exact_problem(
        &terminal,
        StatusCode::BAD_REQUEST,
        "credential_request_denied",
        "this credential request cannot be completed",
        &[&token, &nonce, CONFIGURATION_ID, SELECTOR_VALUE],
    );
    assert_eq!(
        issuer.issuance_call_count(),
        1,
        "the claimed request enters Evidence exactly once before timing out"
    );

    let retry = server
        .post(CREDENTIAL_PATH)
        .add_header("authorization", format!("Bearer {token}"))
        .json(&request)
        .await;
    assert_exact_problem(
        &retry,
        StatusCode::UNAUTHORIZED,
        "invalid_token",
        "the access token cannot be used",
        &[&token, &nonce, CONFIGURATION_ID, SELECTOR_VALUE],
    );
    assert_eq!(
        issuer.issuance_call_count(),
        1,
        "the spent token cannot re-enter Evidence"
    );
}

#[tokio::test]
async fn a_pre_claim_timeout_remains_retryable_without_entering_issuance() {
    let mut config = loaded_config();
    config.listener.request_timeout_milliseconds = 100;
    let issuer = Arc::new(SlowIssuer::new(SlowBoundary::Catalog));
    let server = server_with_issuer(config, Arc::clone(&issuer) as Arc<dyn CredentialIssuer>);

    let response = server
        .post(OFFERS_PATH)
        .add_header("authorization", format!("Bearer {OFFER_TOKEN}"))
        .json(&offer_body(false))
        .await;
    assert_exact_problem(
        &response,
        StatusCode::REQUEST_TIMEOUT,
        "invalid_request",
        "the request took longer than this service waits",
        &[OFFER_TOKEN, CONFIGURATION_ID, SELECTOR_VALUE],
    );
    assert_eq!(
        issuer.catalog_call_count(),
        1,
        "the pre-claim catalog lookup began exactly once"
    );
    assert_eq!(
        issuer.issuance_call_count(),
        0,
        "a pre-claim timeout never enters credential issuance"
    );
}

#[tokio::test]
async fn a_singular_ceiling_omits_batch_metadata_and_still_enforces_one_proof() {
    let issuer = Arc::new(RecordingIssuer::with_batch_maximum(1));
    let server = server_with_issuer(
        loaded_config(),
        Arc::clone(&issuer) as Arc<dyn CredentialIssuer>,
    );

    let metadata = server.get(ISSUER_METADATA_PATH).await;
    assert_eq!(metadata.status_code(), StatusCode::OK);
    assert!(
        metadata
            .json::<Value>()
            .get("batch_credential_issuance")
            .is_none(),
        "a singular credential endpoint does not advertise batch issuance"
    );

    let token = access_token(&server).await;
    let nonce = minted_nonce(&server).await;
    let singular = server
        .post(CREDENTIAL_PATH)
        .add_header("authorization", format!("Bearer {token}"))
        .json(&credential_body(vec![proof_jwt(&private_jwk(), &nonce)]))
        .await;
    assert_eq!(singular.status_code(), StatusCode::OK);
    assert_eq!(issuer.call_count(), 1);

    let token = access_token(&server).await;
    let nonce = minted_nonce(&server).await;
    let excessive = server
        .post(CREDENTIAL_PATH)
        .add_header("authorization", format!("Bearer {token}"))
        .json(&credential_body(vec![
            proof_jwt(&private_jwk(), &nonce),
            proof_jwt(&private_jwk(), &nonce),
        ]))
        .await;
    assert_eq!(excessive.status_code(), StatusCode::BAD_REQUEST);
    assert_closed_error(
        &excessive,
        "invalid_proof",
        &[&token, &nonce, SELECTOR_VALUE],
    );
    assert_eq!(
        issuer.call_count(),
        1,
        "a proof count above the pinned singular ceiling never reaches Evidence"
    );
}

#[tokio::test]
async fn missing_and_unknown_authorization_do_not_claim_a_live_exchange() {
    let harness = harness(loaded_config());
    let token = access_token(&harness.server).await;
    let nonce = minted_nonce(&harness.server).await;
    let request = credential_body(vec![proof_jwt(&private_jwk(), &nonce)]);

    let missing = harness.server.post(CREDENTIAL_PATH).json(&request).await;
    assert_eq!(missing.status_code(), StatusCode::UNAUTHORIZED);

    let unknown = harness
        .server
        .post(CREDENTIAL_PATH)
        .add_header("authorization", "Bearer unknown-access-token")
        .json(&request)
        .await;
    assert_eq!(unknown.status_code(), StatusCode::UNAUTHORIZED);
    assert_eq!(
        harness.issuer.call_count(),
        0,
        "missing and unknown authorization reach neither Evidence nor its release audit"
    );

    let accepted = harness
        .server
        .post(CREDENTIAL_PATH)
        .add_header("authorization", format!("Bearer {token}"))
        .json(&request)
        .await;
    assert_eq!(accepted.status_code(), StatusCode::OK);

    let consumed = harness
        .server
        .post(CREDENTIAL_PATH)
        .add_header("authorization", format!("Bearer {token}"))
        .json(&request)
        .await;
    assert_eq!(consumed.status_code(), StatusCode::UNAUTHORIZED);
    assert_eq!(unknown.as_bytes(), consumed.as_bytes());
    assert_eq!(harness.issuer.call_count(), 1);
}

#[tokio::test]
async fn one_stateless_nonce_is_reusable_across_separate_authorizations() {
    let harness = harness(loaded_config());
    let nonce = minted_nonce(&harness.server).await;
    let proof = proof_jwt(&private_jwk(), &nonce);

    for _ in 0..2 {
        let token = access_token(&harness.server).await;
        let response = harness
            .server
            .post(CREDENTIAL_PATH)
            .add_header("authorization", format!("Bearer {token}"))
            .json(&credential_body(vec![proof.clone()]))
            .await;
        assert_eq!(response.status_code(), StatusCode::OK);
    }
    assert_eq!(
        harness.issuer.call_count(),
        2,
        "nonce reuse alone is not replay prevention"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_code_and_token_claims_allow_one_issuance_per_generation() {
    const ROUNDS: usize = 12;
    const CONTENDERS: usize = 8;

    let harness = harness(loaded_config());
    for round in 0..ROUNDS {
        let code = offered_code(&create_offer(&harness.server, false).await);
        let barrier = Arc::new(Barrier::new(CONTENDERS));
        let mut claims = Vec::with_capacity(CONTENDERS);
        for _ in 0..CONTENDERS {
            let server = Arc::clone(&harness.server);
            let barrier = Arc::clone(&barrier);
            let form = token_form(&code, None);
            claims.push(tokio::spawn(async move {
                barrier.wait().await;
                let response = server.post(TOKEN_PATH).form(&form).await;
                let status = response.status_code();
                let body: Value = response.json();
                (status, body)
            }));
        }

        let mut access_token = None;
        let mut successful_codes = 0;
        for claim in claims {
            let (status, body) = claim.await.expect("the code contender completes");
            match status {
                StatusCode::OK => {
                    successful_codes += 1;
                    access_token = body["access_token"].as_str().map(str::to_owned);
                }
                StatusCode::BAD_REQUEST => assert_eq!(body["error"], json!("invalid_grant")),
                other => panic!("unexpected code-claim status {other}"),
            }
        }
        assert_eq!(successful_codes, 1, "round {round}");
        let access_token = access_token.expect("one code claim returns a token");

        let nonce = minted_nonce(&harness.server).await;
        let request = credential_body(vec![proof_jwt(&private_jwk(), &nonce)]);
        let barrier = Arc::new(Barrier::new(CONTENDERS));
        let mut claims = Vec::with_capacity(CONTENDERS);
        for _ in 0..CONTENDERS {
            let server = Arc::clone(&harness.server);
            let barrier = Arc::clone(&barrier);
            let token = access_token.clone();
            let request = request.clone();
            claims.push(tokio::spawn(async move {
                barrier.wait().await;
                let response = server
                    .post(CREDENTIAL_PATH)
                    .add_header("authorization", format!("Bearer {token}"))
                    .json(&request)
                    .await;
                (response.status_code(), response.json::<Value>())
            }));
        }

        let mut successful_tokens = 0;
        for claim in claims {
            let (status, body) = claim.await.expect("the token contender completes");
            match status {
                StatusCode::OK => successful_tokens += 1,
                StatusCode::UNAUTHORIZED => {
                    assert_eq!(body["error"], json!("invalid_token"));
                }
                other => panic!("unexpected token-claim status {other}"),
            }
        }
        assert_eq!(successful_tokens, 1, "round {round}");
        assert_eq!(
            harness.issuer.call_count(),
            round + 1,
            "each generation reaches Evidence at most once"
        );
    }
}

#[tokio::test]
async fn offer_saturation_fails_closed_without_evicting_a_live_exchange() {
    let mut config = loaded_config();
    config.store.maximum_offers = 4;
    let harness = harness(config);

    let mut codes = Vec::new();
    for _ in 0..4 {
        codes.push(offered_code(&create_offer(&harness.server, false).await));
    }
    let saturated = harness
        .server
        .post(OFFERS_PATH)
        .add_header("authorization", format!("Bearer {OFFER_TOKEN}"))
        .json(&offer_body(false))
        .await;
    assert_eq!(saturated.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    assert_closed_error(
        &saturated,
        "temporarily_unavailable",
        &[CONFIGURATION_ID, SELECTOR_VALUE],
    );

    let granted = harness
        .server
        .post(TOKEN_PATH)
        .form(&token_form(&codes[0], None))
        .await;
    assert_eq!(granted.status_code(), StatusCode::OK);
    let token = granted.json::<Value>()["access_token"]
        .as_str()
        .expect("the preserved offer redeems")
        .to_owned();
    let nonce = minted_nonce(&harness.server).await;
    let issued = harness
        .server
        .post(CREDENTIAL_PATH)
        .add_header("authorization", format!("Bearer {token}"))
        .json(&credential_body(vec![proof_jwt(&private_jwk(), &nonce)]))
        .await;
    assert_eq!(issued.status_code(), StatusCode::OK);
    assert_eq!(harness.issuer.call_count(), 1);
}

#[tokio::test]
async fn token_saturation_does_not_spend_the_offer_that_could_not_be_exchanged() {
    let mut config = loaded_config();
    config.store.maximum_offers = 1;
    // Store deadlines use whole seconds. This leaves the recovered offer at
    // least four seconds for the credential exchange even near a boundary.
    config.store.offer_lifetime_seconds = 5;
    config.store.access_token_lifetime_seconds = 60;
    config.store.nonce_lifetime_seconds = 30;
    let harness = harness(config);

    let held_token = access_token(&harness.server).await;
    tokio::time::sleep(Duration::from_millis(5_100)).await;

    let preserved_code = offered_code(&create_offer(&harness.server, false).await);
    let saturated = harness
        .server
        .post(TOKEN_PATH)
        .form(&token_form(&preserved_code, None))
        .await;
    assert_eq!(saturated.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    assert_closed_error(
        &saturated,
        "temporarily_unavailable",
        &[&preserved_code, &held_token],
    );
    assert_eq!(
        harness.issuer.call_count(),
        0,
        "token saturation reaches neither Evidence nor its release audit"
    );

    let nonce = minted_nonce(&harness.server).await;
    let released = harness
        .server
        .post(CREDENTIAL_PATH)
        .add_header("authorization", format!("Bearer {held_token}"))
        .json(&credential_body(vec![proof_jwt(&private_jwk(), &nonce)]))
        .await;
    assert_eq!(released.status_code(), StatusCode::OK);

    let recovered = harness
        .server
        .post(TOKEN_PATH)
        .form(&token_form(&preserved_code, None))
        .await;
    assert_eq!(recovered.status_code(), StatusCode::OK);
    assert!(recovered.json::<Value>()["access_token"].is_string());
    assert_eq!(harness.issuer.call_count(), 1);
}

#[tokio::test]
async fn restart_invalidates_outstanding_state_with_value_free_errors() {
    let first = harness(loaded_config());
    let old_code = offered_code(&create_offer(&first.server, false).await);
    let old_token = access_token(&first.server).await;
    let old_nonce = minted_nonce(&first.server).await;
    drop(first);

    let second = harness(loaded_config());
    let restarted_code = second
        .server
        .post(TOKEN_PATH)
        .form(&token_form(&old_code, None))
        .await;
    let unknown_code = second
        .server
        .post(TOKEN_PATH)
        .form(&token_form("unknown-pre-authorized-code", None))
        .await;
    assert_eq!(restarted_code.status_code(), StatusCode::BAD_REQUEST);
    assert_eq!(restarted_code.as_bytes(), unknown_code.as_bytes());
    assert_closed_error(&restarted_code, "invalid_grant", &[&old_code]);

    let nonce = minted_nonce(&second.server).await;
    let request = credential_body(vec![proof_jwt(&private_jwk(), &nonce)]);
    let restarted_token = second
        .server
        .post(CREDENTIAL_PATH)
        .add_header("authorization", format!("Bearer {old_token}"))
        .json(&request)
        .await;
    let unknown_token = second
        .server
        .post(CREDENTIAL_PATH)
        .add_header("authorization", "Bearer unknown-access-token")
        .json(&request)
        .await;
    assert_eq!(restarted_token.status_code(), StatusCode::UNAUTHORIZED);
    assert_eq!(restarted_token.as_bytes(), unknown_token.as_bytes());
    assert_closed_error(&restarted_token, "invalid_token", &[&old_token]);

    let fresh_token = access_token(&second.server).await;
    let old_nonce_response = second
        .server
        .post(CREDENTIAL_PATH)
        .add_header("authorization", format!("Bearer {fresh_token}"))
        .json(&credential_body(vec![proof_jwt(
            &private_jwk(),
            &old_nonce,
        )]))
        .await;
    assert_eq!(old_nonce_response.status_code(), StatusCode::BAD_REQUEST);
    assert_closed_error(&old_nonce_response, "invalid_nonce", &[&old_nonce]);
    assert_eq!(
        second.issuer.call_count(),
        0,
        "restart refusals reach neither Evidence nor its release audit"
    );
}

#[tokio::test]
async fn unknown_redeemed_and_locked_codes_share_one_value_free_error() {
    let harness = harness(loaded_config());
    let unknown = harness
        .server
        .post(TOKEN_PATH)
        .form(&token_form("unknown-pre-authorized-code", None))
        .await;

    let redeemed_code = offered_code(&create_offer(&harness.server, false).await);
    let first_redemption = harness
        .server
        .post(TOKEN_PATH)
        .form(&token_form(&redeemed_code, None))
        .await;
    assert_eq!(first_redemption.status_code(), StatusCode::OK);
    let redeemed = harness
        .server
        .post(TOKEN_PATH)
        .form(&token_form(&redeemed_code, None))
        .await;

    let protected = create_offer(&harness.server, true).await;
    let locked_code = offered_code(&protected);
    let transaction_code = protected["transactionCode"]
        .as_str()
        .expect("the protected offer returns its transaction code")
        .to_owned();
    for _ in 0..3 {
        let response = harness
            .server
            .post(TOKEN_PATH)
            .form(&token_form(&locked_code, Some("000000")))
            .await;
        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    }
    let locked = harness
        .server
        .post(TOKEN_PATH)
        .form(&token_form(&locked_code, Some(&transaction_code)))
        .await;

    assert_eq!(unknown.as_bytes(), redeemed.as_bytes());
    assert_eq!(unknown.as_bytes(), locked.as_bytes());
    assert_closed_error(
        &locked,
        "invalid_grant",
        &[&locked_code, &transaction_code, SELECTOR_VALUE],
    );
}

#[tokio::test]
async fn expiry_cleanup_preserves_live_state_and_releases_expired_state() {
    let mut cleanup_config = loaded_config();
    cleanup_config.store.maximum_offers = 2;
    cleanup_config.store.offer_lifetime_seconds = 1;
    let cleanup = harness(cleanup_config);

    let expired_code = offered_code(&create_offer(&cleanup.server, false).await);
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    let expired = cleanup
        .server
        .post(TOKEN_PATH)
        .form(&token_form(&expired_code, None))
        .await;
    assert_eq!(expired.status_code(), StatusCode::BAD_REQUEST);
    let unknown = cleanup
        .server
        .post(TOKEN_PATH)
        .form(&token_form("unknown-pre-authorized-code", None))
        .await;
    assert_eq!(expired.as_bytes(), unknown.as_bytes());
    assert_closed_error(&expired, "invalid_grant", &[&expired_code, SELECTOR_VALUE]);

    // Both writes fit only if the expired offer and its held prepared request
    // were pruned. Redeeming the first proves cleanup kept the newer live one.
    let live_code = offered_code(&create_offer(&cleanup.server, false).await);
    let _other_live_code = offered_code(&create_offer(&cleanup.server, false).await);
    let live = cleanup
        .server
        .post(TOKEN_PATH)
        .form(&token_form(&live_code, None))
        .await;
    assert_eq!(live.status_code(), StatusCode::OK);

    let mut token_config = loaded_config();
    token_config.store.access_token_lifetime_seconds = 1;
    let token_expiry = harness(token_config);
    let expired_token = access_token(&token_expiry.server).await;
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    let nonce = minted_nonce(&token_expiry.server).await;
    let request = credential_body(vec![proof_jwt(&private_jwk(), &nonce)]);
    let expired_token_response = token_expiry
        .server
        .post(CREDENTIAL_PATH)
        .add_header("authorization", format!("Bearer {expired_token}"))
        .json(&request)
        .await;
    let unknown_token_response = token_expiry
        .server
        .post(CREDENTIAL_PATH)
        .add_header("authorization", "Bearer unknown-access-token")
        .json(&request)
        .await;
    assert_eq!(
        expired_token_response.status_code(),
        StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        expired_token_response.as_bytes(),
        unknown_token_response.as_bytes()
    );
    assert_eq!(token_expiry.issuer.call_count(), 0);

    let mut nonce_config = loaded_config();
    nonce_config.store.access_token_lifetime_seconds = 5;
    nonce_config.store.nonce_lifetime_seconds = 1;
    let nonce_expiry = harness(nonce_config);
    let token = access_token(&nonce_expiry.server).await;
    let nonce = minted_nonce(&nonce_expiry.server).await;
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    let expired_nonce_response = nonce_expiry
        .server
        .post(CREDENTIAL_PATH)
        .add_header("authorization", format!("Bearer {token}"))
        .json(&credential_body(vec![proof_jwt(&private_jwk(), &nonce)]))
        .await;
    assert_eq!(
        expired_nonce_response.status_code(),
        StatusCode::BAD_REQUEST
    );
    assert_closed_error(&expired_nonce_response, "invalid_nonce", &[&nonce]);

    let fresh_nonce = minted_nonce(&nonce_expiry.server).await;
    let retry = nonce_expiry
        .server
        .post(CREDENTIAL_PATH)
        .add_header("authorization", format!("Bearer {token}"))
        .json(&credential_body(vec![proof_jwt(
            &private_jwk(),
            &fresh_nonce,
        )]))
        .await;
    assert_eq!(retry.status_code(), StatusCode::UNAUTHORIZED);
    assert_eq!(nonce_expiry.issuer.call_count(), 0);
}
