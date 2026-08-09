//! Registry-side interoperability profile for the pinned Inji wallet clients.
//!
//! These are ordinary, offline black-box tests. They exercise the public HTTP
//! boundary with the Final wire shapes the pinned clients produce and consume.
//! They do not run third-party code and are not a certification or a general
//! compatibility claim. The opt-in pinned-source half lives in
//! `products/evidence/scripts/compat/inji-oid4vci-upstream.sh`.

use std::{
    collections::{BTreeMap, HashMap},
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

use async_trait::async_trait;
use axum::{
    body::Bytes,
    extract::{Form, State},
    http::{header::CONTENT_TYPE, HeaderMap, StatusCode},
    response::IntoResponse,
    routing::{get, post},
    Json, Router,
};
use axum_test::TestServer;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{SecondsFormat, Utc};
use p256::{ecdsa::SigningKey, elliptic_curve::rand_core::OsRng};
use registry_evidence_client::{
    AssuranceProfile, EvidenceDefinitionsDocument, HolderBoundRequestSpec, HolderPublicKey,
    EVIDENCE_SD_JWT_VC_BATCH_MEDIA_TYPE, SD_JWT_VC_BATCH_SCHEMA_V1,
};
use registry_evidence_oid4vci::{
    authorizer::{AuthorizationError, AuthorizedOffer, OfferAuthorizer},
    config::DeliveryConfig,
    issuer::{CredentialIssuer, IssuanceError},
    metadata::CredentialCatalog,
    service::{
        build_app, DeliveryService, AUTHORIZATION_SERVER_METADATA_PATH, CREDENTIAL_PATH,
        ISSUER_METADATA_PATH, NONCE_PATH, OFFERS_PATH, TOKEN_PATH,
    },
    PRE_AUTHORIZED_CODE_GRANT_TYPE,
};
use registry_evidence_verifier::{
    model::{
        Evidence, EvidenceObjectType, JwksDocument, PublicValue, SubjectBinding,
        SubjectBindingMode, SupportedValue,
    },
    sdjwt_vc::{holder_thumbprint, issuance_input},
    verifier::{
        verify_sd_jwt_vc_presentation, ExpectedFormDocument, ExpectedOutputDocument,
        ExpectedScalarFormDocument, ExpectedSubjectDocument, HolderBoundDeclaration,
        HolderBoundPresentationPolicy, HolderBoundPresentationPolicyDocument,
    },
    EVIDENCE_SCHEMA_V1,
};
use registry_platform_crypto::{hmac_sha256_base64url_no_pad, sign, PrivateJwk, PublicJwk};
use registry_platform_sdjwt::{presentation_disclosure_hash, SdJwtIssuer};
use serde_json::{json, Value};

const OFFER_TOKEN: &str = "fixture-offer-token";
const CREDENTIAL_ISSUER: &str = "https://wallet.example.org";
const CONFIGURATION_ID: &str = "urn:example:requirement:holder-bound";
const EVIDENCE_TYPE: &str = "urn:example:evidence-type:holder-bound";
const PURPOSE: &str = "urn:example:purpose:demonstration";
const CONCEPT: &str = "urn:example:concept:outcome";
const CONFIGURATION_REVISION: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";
const PRESENTATION_AUDIENCE: &str = "urn:example:relying-party";
const PRESENTATION_NONCE: &str = "fixture-presentation-challenge";
const SUBJECT_BINDING_KEY: &[u8] = b"synthetic-interoperability-subject-binding-key";
const ADOPTER_ORIGIN: &str = "http://127.0.0.1:18440";
const ADOPTER_METRICS_ORIGIN: &str = "http://127.0.0.1:18441";
const SUPPORT_ORIGIN: &str = "http://127.0.0.1:18442";

const DEFINITIONS: &str = r#"{
  "schema": "registry.evidence-definitions/v1",
  "assuranceProfile": "local",
  "issuedBy": "https://registry.example.org",
  "providedBy": "https://provider.example.org",
  "holderBoundBatchMaxSize": 4,
  "definitions": [{
    "requirement": "urn:example:requirement:holder-bound",
    "configurationRevision": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    "kind": "criterion",
    "subjectBindingMode": "holder-bound",
    "evidenceType": "urn:example:evidence-type:holder-bound",
    "purpose": "urn:example:purpose:demonstration",
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
    "concepts": [{"id": "urn:example:concept:outcome", "form": "boolean"}]
  }]
}"#;

struct FixtureKey {
    private: String,
    public: Value,
    did_url: String,
}

impl FixtureKey {
    fn generate() -> Self {
        let key = SigningKey::random(&mut OsRng);
        let point = key.verifying_key().to_encoded_point(false);
        let public = json!({
            "kty": "EC",
            "crv": "P-256",
            "alg": "ES256",
            "x": URL_SAFE_NO_PAD.encode(point.x().expect("a P-256 point has x")),
            "y": URL_SAFE_NO_PAD.encode(point.y().expect("a P-256 point has y")),
        });
        let did_url = format!(
            "did:jwk:{}#0",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&public).expect("the public JWK serializes"))
        );
        let mut private = public.clone();
        private["kid"] = json!(did_url);
        private["d"] = json!(URL_SAFE_NO_PAD.encode(key.to_bytes()));
        Self {
            private: private.to_string(),
            public,
            did_url,
        }
    }

    fn holder_public_key(&self) -> HolderPublicKey {
        serde_json::from_value(self.public.clone()).expect("the public fixture key maps")
    }
}

struct FixtureAuthorizer;

#[async_trait]
impl OfferAuthorizer for FixtureAuthorizer {
    async fn authorize(&self, credential: &str) -> Result<AuthorizedOffer, AuthorizationError> {
        if credential.is_empty() {
            return Err(AuthorizationError::Missing);
        }
        if credential != OFFER_TOKEN {
            return Err(AuthorizationError::Refused);
        }
        Ok(AuthorizedOffer {
            client: Some("fixture-adopter".to_owned()),
            subject: None,
        })
    }
}

struct FixtureIssuer {
    catalog: Arc<CredentialCatalog>,
    signing_key: String,
    signing_public: Value,
    calls: AtomicUsize,
    requests: Mutex<Vec<HolderBoundRequestSpec>>,
    evidence: Mutex<Vec<Evidence>>,
}

impl FixtureIssuer {
    fn new() -> Self {
        let document: EvidenceDefinitionsDocument =
            serde_json::from_str(DEFINITIONS).expect("the definitions document parses");
        let generated = SigningKey::random(&mut OsRng);
        let point = generated.verifying_key().to_encoded_point(false);
        let public_without_kid = json!({
            "kty": "EC",
            "crv": "P-256",
            "alg": "ES256",
            "x": URL_SAFE_NO_PAD.encode(point.x().expect("an issuer key has x")),
            "y": URL_SAFE_NO_PAD.encode(point.y().expect("an issuer key has y")),
        });
        let parsed = PublicJwk::parse(&public_without_kid.to_string())
            .expect("the generated issuer public key parses");
        let key_id = parsed.jkt().expect("the issuer thumbprint computes");
        let mut signing_public = public_without_kid;
        signing_public["kid"] = json!(key_id);
        let mut signing_key = signing_public.clone();
        signing_key["d"] = json!(URL_SAFE_NO_PAD.encode(generated.to_bytes()));
        Self {
            catalog: Arc::new(CredentialCatalog::derive(&document)),
            signing_key: signing_key.to_string(),
            signing_public,
            calls: AtomicUsize::new(0),
            requests: Mutex::new(Vec::new()),
            evidence: Mutex::new(Vec::new()),
        }
    }

    fn call_count(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }

    fn requests(&self) -> Vec<HolderBoundRequestSpec> {
        self.requests.lock().expect("requests lock").clone()
    }

    fn issued_evidence(&self) -> Vec<Evidence> {
        self.evidence.lock().expect("evidence lock").clone()
    }

    fn trusted_jwks(&self) -> JwksDocument {
        JwksDocument {
            keys: vec![self.signing_public.clone()],
        }
    }

    async fn credentials_for(&self, holder_keys: &[HolderPublicKey]) -> Vec<String> {
        let signer = SdJwtIssuer::from_jwk(
            PrivateJwk::parse(&self.signing_key).expect("the issuer private JWK parses"),
        )
        .expect("the issuer signer initializes");
        let mut credentials = Vec::with_capacity(holder_keys.len());
        for (index, holder_key) in holder_keys.iter().enumerate() {
            let evidence = holder_bound_evidence(index, holder_key);
            let input = issuance_input(&evidence, Some(holder_key), &BTreeMap::new())
                .expect("holder-bound Evidence maps to SD-JWT VC");
            let credential = signer
                .issue(input)
                .await
                .expect("the fixture Evidence credential signs")
                .jwt;
            self.evidence.lock().expect("evidence lock").push(evidence);
            credentials.push(credential);
        }
        credentials
    }
}

#[async_trait]
impl CredentialIssuer for FixtureIssuer {
    async fn catalog(&self) -> Result<Arc<CredentialCatalog>, IssuanceError> {
        Ok(Arc::clone(&self.catalog))
    }

    async fn issue(&self, spec: HolderBoundRequestSpec) -> Result<Vec<String>, IssuanceError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        self.requests
            .lock()
            .expect("requests lock")
            .push(spec.clone());
        tokio::task::yield_now().await;

        Ok(self.credentials_for(&spec.holder_keys).await)
    }
}

fn holder_bound_evidence(index: usize, holder_key: &HolderPublicKey) -> Evidence {
    let suffix = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ"[index % 32] as char;
    let issued = Utc::now();
    let valid_until = issued + chrono::Duration::hours(1);
    Evidence {
        schema: EVIDENCE_SCHEMA_V1.to_owned(),
        assurance_profile: AssuranceProfile::Local,
        subject_binding: SubjectBindingMode::HolderBound,
        request_nonce: None,
        id: format!("urn:ulid:01J0000000000000000000000{suffix}"),
        evidence_type_name: EvidenceObjectType::Evidence,
        supports_requirement: CONFIGURATION_ID.to_owned(),
        is_conformant_to: EVIDENCE_TYPE.to_owned(),
        issued_by: "https://registry.example.org".to_owned(),
        provided_by: "https://provider.example.org".to_owned(),
        issued_at: issued.to_rfc3339_opts(SecondsFormat::Secs, true),
        observed_at: issued.to_rfc3339_opts(SecondsFormat::Secs, true),
        valid_until: valid_until.to_rfc3339_opts(SecondsFormat::Secs, true),
        purpose: PURPOSE.to_owned(),
        audience: None,
        configuration_revision: CONFIGURATION_REVISION.to_owned(),
        subjects: vec![SubjectBinding {
            role: "primary".to_owned(),
            binding: format!(
                "urn:evidence:subject:v1_{}",
                hmac_sha256_base64url_no_pad(
                    SUBJECT_BINDING_KEY,
                    holder_thumbprint(holder_key)
                        .expect("the accepted holder key has a thumbprint")
                        .as_bytes(),
                )
            ),
        }],
        supported_values: vec![SupportedValue {
            provides_value_for: CONCEPT.to_owned(),
            value: PublicValue::Boolean(true),
        }],
    }
}

fn write_config(directory: &Path) -> DeliveryConfig {
    let path = directory.join("oid4vci.yaml");
    fs::write(
        &path,
        r#"
version: 1
credentialIssuer: https://wallet.example.org
listener:
  address: 127.0.0.1
  port: 8090
evidence:
  baseUrl: https://evidence.example.org
mint:
  tokenEndpoint: https://mint.example.org/token
  clientId: evidence-oid4vci
  privateKeyFile: unused-in-wired-test.jwk
offers:
  issuer: https://mint.example.org
  jwksUri: https://mint.example.org/.well-known/jwks.json
  audiences: ["https://wallet.example.org"]
"#,
    )
    .expect("write fixture deployment");
    DeliveryConfig::load(&path).expect("the fixture deployment loads")
}

fn deployment() -> (tempfile::TempDir, Arc<FixtureIssuer>, TestServer) {
    let directory = tempfile::tempdir().expect("temporary deployment directory");
    let issuer = Arc::new(FixtureIssuer::new());
    let service = Arc::new(DeliveryService::with_halves(
        write_config(directory.path()),
        Arc::new(FixtureAuthorizer),
        Arc::clone(&issuer) as Arc<dyn CredentialIssuer>,
    ));
    let server = TestServer::new(build_app(service));
    (directory, issuer, server)
}

fn offer_body() -> Value {
    json!({
        "credentialConfigurationId": CONFIGURATION_ID,
        "subjects": [{
            "role": "primary",
            "selectorValues": {"identifier": "synthetic-fixture-value"}
        }]
    })
}

fn offered_code(response: &Value) -> String {
    response["credentialOffer"]["grants"][PRE_AUTHORIZED_CODE_GRANT_TYPE]["pre-authorized_code"]
        .as_str()
        .expect("the offer carries a code")
        .to_owned()
}

fn token_form(code: &str) -> Vec<(String, String)> {
    vec![
        (
            "grant_type".to_owned(),
            PRE_AUTHORIZED_CODE_GRANT_TYPE.to_owned(),
        ),
        ("pre-authorized_code".to_owned(), code.to_owned()),
    ]
}

async fn access_token(server: &TestServer, token_path: &str) -> String {
    let offer = server
        .post(OFFERS_PATH)
        .add_header("authorization", format!("Bearer {OFFER_TOKEN}"))
        .json(&offer_body())
        .await;
    assert_eq!(offer.status_code(), StatusCode::CREATED);
    let code = offered_code(&offer.json());
    let token = server.post(token_path).form(&token_form(&code)).await;
    assert_eq!(token.status_code(), StatusCode::OK);
    token.json::<Value>()["access_token"]
        .as_str()
        .expect("the response carries an access token")
        .to_owned()
}

async fn nonce(server: &TestServer, nonce_path: &str) -> String {
    let response = server.post(nonce_path).json(&json!({})).await;
    assert_eq!(response.status_code(), StatusCode::OK);
    response.json::<Value>()["c_nonce"]
        .as_str()
        .expect("the response carries a nonce")
        .to_owned()
}

fn signed_jwt(private_key: &str, header: Value, payload: Value) -> String {
    let key = PrivateJwk::parse(private_key).expect("the fixture key parses");
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&header).expect("header serializes")),
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&payload).expect("payload serializes"))
    );
    let signature = sign(signing_input.as_bytes(), &key).expect("the fixture key signs");
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

fn did_jwk_proof(
    key: &FixtureKey,
    audience: &str,
    nonce: &str,
    issued_at: i64,
    expiration: Option<i64>,
) -> String {
    let mut payload = json!({"aud": audience, "iat": issued_at, "nonce": nonce});
    if let Some(expiration) = expiration {
        payload["exp"] = json!(expiration);
    }
    signed_jwt(
        &key.private,
        json!({
            "alg": "ES256",
            "typ": "openid4vci-proof+jwt",
            "kid": key.did_url,
        }),
        payload,
    )
}

fn remote_key_proof(key: &FixtureKey, nonce: &str, issued_at: i64) -> String {
    signed_jwt(
        &key.private,
        json!({
            "alg": "ES256",
            "typ": "openid4vci-proof+jwt",
            "kid": "https://keys.example.org/holder#1",
        }),
        json!({"aud": CREDENTIAL_ISSUER, "iat": issued_at, "nonce": nonce}),
    )
}

fn inline_jwk_proof(
    key: &FixtureKey,
    jwk: Value,
    algorithm: &str,
    nonce: &str,
    issued_at: i64,
) -> String {
    signed_jwt(
        &key.private,
        json!({
            "alg": algorithm,
            "typ": "openid4vci-proof+jwt",
            "jwk": jwk,
        }),
        json!({"aud": CREDENTIAL_ISSUER, "iat": issued_at, "nonce": nonce}),
    )
}

async fn credential_request(
    server: &TestServer,
    credential_path: &str,
    access_token: &str,
    proofs: Vec<String>,
) -> axum_test::TestResponse {
    server
        .post(credential_path)
        .add_header("authorization", format!("Bearer {access_token}"))
        .json(&json!({
            "credential_configuration_id": CONFIGURATION_ID,
            "proofs": {"jwt": proofs},
        }))
        .await
}

fn endpoint_path(metadata: &Value, member: &str) -> String {
    let endpoint = metadata[member]
        .as_str()
        .unwrap_or_else(|| panic!("{member} is published as text"));
    let endpoint = url::Url::parse(endpoint).expect("the published endpoint is a URL");
    assert_eq!(endpoint.origin().ascii_serialization(), CREDENTIAL_ISSUER);
    endpoint.path().to_owned()
}

fn profile() -> Value {
    serde_json::from_str(include_str!(
        "../../../products/evidence/fixtures/interoperability/inji-oid4vci/profile.json"
    ))
    .expect("the sanitized profile is JSON")
}

fn relying_policy(holder: &FixtureKey) -> HolderBoundPresentationPolicy {
    let expected = holder_bound_evidence(0, &holder.holder_public_key());
    HolderBoundPresentationPolicyDocument {
        subject_binding: HolderBoundDeclaration::HolderBound,
        expected_assurance_profile: expected.assurance_profile,
        issued_by: expected.issued_by,
        provided_by: expected.provided_by,
        requirement: expected.supports_requirement,
        evidence_type: expected.is_conformant_to,
        expected_issuance_purpose: expected.purpose,
        configuration_revision: expected.configuration_revision,
        expected_subjects: expected
            .subjects
            .into_iter()
            .map(|subject| ExpectedSubjectDocument {
                role: subject.role,
                binding: subject.binding,
            })
            .collect(),
        expected_outputs: vec![ExpectedOutputDocument {
            concept: CONCEPT.to_owned(),
            form: ExpectedFormDocument::Scalar(ExpectedScalarFormDocument::Boolean),
        }],
        revoked_key_ids: Vec::new(),
        maximum_assertion_lifetime_seconds: 3_600,
        key_binding_audience: PRESENTATION_AUDIENCE.to_owned(),
        key_binding_nonce: PRESENTATION_NONCE.to_owned(),
        maximum_key_binding_age_seconds: 300,
        clock_skew_seconds: 30,
        expected_holder_key_thumbprint: None,
    }
    .try_into_policy(Utc::now())
    .expect("the independently retained policy is inside the contract bounds")
}

fn verify_presentation(
    credential: &str,
    holder: &FixtureKey,
    issuer: &FixtureIssuer,
    policy: &HolderBoundPresentationPolicy,
) {
    let presentation_iat = Utc::now().timestamp();
    let key_binding = signed_jwt(
        &holder.private,
        json!({"alg": "ES256", "typ": "kb+jwt"}),
        json!({
            "nonce": PRESENTATION_NONCE,
            "aud": PRESENTATION_AUDIENCE,
            "iat": presentation_iat,
            "sd_hash": URL_SAFE_NO_PAD.encode(presentation_disclosure_hash(credential)),
        }),
    );
    let presentation = format!("{credential}{key_binding}");
    let evidence = issuer
        .issued_evidence()
        .into_iter()
        .next()
        .expect("the fixture issuer recorded its assertion");
    assert_eq!(
        verify_sd_jwt_vc_presentation(presentation.as_bytes(), &issuer.trusted_jwks(), policy,)
            .expect("the holder-bound presentation verifies independently"),
        evidence
    );
}

#[derive(Clone)]
struct HttpSupport {
    issuer: Arc<FixtureIssuer>,
    token_calls: Arc<AtomicUsize>,
    evidence_calls: Arc<AtomicUsize>,
}

async fn support_jwks(State(support): State<HttpSupport>) -> Json<JwksDocument> {
    Json(support.issuer.trusted_jwks())
}

async fn support_token(
    State(support): State<HttpSupport>,
    Form(form): Form<HashMap<String, String>>,
) -> impl IntoResponse {
    let valid = form.get("grant_type").is_some_and(|value| {
        value == "client_credentials" || value == "urn:ietf:params:oauth:grant-type:jwt-bearer"
    }) && form
        .get("client_assertion_type")
        .is_some_and(|value| value == "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
        && form
            .get("client_assertion")
            .is_some_and(|value| !value.is_empty());
    if !valid {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid_client"})),
        );
    }
    support.token_calls.fetch_add(1, Ordering::SeqCst);
    (
        StatusCode::OK,
        Json(json!({
            "access_token": "synthetic-evidence-access",
            "token_type": "Bearer",
            "expires_in": 300,
        })),
    )
}

async fn support_definitions(
    State(_support): State<HttpSupport>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        != Some("Bearer synthetic-evidence-access")
    {
        return (StatusCode::UNAUTHORIZED, Json(json!({}))).into_response();
    }
    (
        StatusCode::OK,
        Json(serde_json::from_str::<Value>(DEFINITIONS).expect("definitions are JSON")),
    )
        .into_response()
}

async fn support_evidence(
    State(support): State<HttpSupport>,
    headers: HeaderMap,
    body: Bytes,
) -> impl IntoResponse {
    support.evidence_calls.fetch_add(1, Ordering::SeqCst);
    if headers
        .get("authorization")
        .and_then(|value| value.to_str().ok())
        != Some("Bearer synthetic-evidence-access")
    {
        return (StatusCode::UNAUTHORIZED, Json(json!({}))).into_response();
    }
    let Ok(body) = serde_json::from_slice::<Value>(&body) else {
        return (StatusCode::BAD_REQUEST, Json(json!({}))).into_response();
    };
    let Some(keys) = body.get("holderKeys").and_then(Value::as_array) else {
        return (StatusCode::BAD_REQUEST, Json(json!({}))).into_response();
    };
    let holder_keys = keys
        .iter()
        .cloned()
        .map(serde_json::from_value::<HolderPublicKey>)
        .collect::<Result<Vec<_>, _>>();
    let Ok(holder_keys) = holder_keys else {
        return (StatusCode::BAD_REQUEST, Json(json!({}))).into_response();
    };
    let credentials = support.issuer.credentials_for(&holder_keys).await;
    (
        StatusCode::OK,
        [(CONTENT_TYPE, EVIDENCE_SD_JWT_VC_BATCH_MEDIA_TYPE)],
        Json(json!({
            "schema": SD_JWT_VC_BATCH_SCHEMA_V1,
            "type": "SdJwtVcBatchEnvelope",
            "credentials": credentials,
        })),
    )
        .into_response()
}

fn adopter_config() -> String {
    format!(
        r#"version: 1
validationMode: supervised-local-development
credentialIssuer: {ADOPTER_ORIGIN}
listener:
  address: 127.0.0.1
  port: 18440
metricsListener:
  address: 127.0.0.1
  port: 18441
evidence:
  baseUrl: {SUPPORT_ORIGIN}
mint:
  tokenEndpoint: {SUPPORT_ORIGIN}/token
  clientId: evidence-oid4vci-tutorial
  privateKeyFile: delivery-client.jwk.json
offers:
  issuer: {SUPPORT_ORIGIN}
  jwksUri: {SUPPORT_ORIGIN}/.well-known/jwks.json
  audiences: ["{ADOPTER_ORIGIN}"]
  algorithms: [ES256]
  authorizedClients: [tutorial-operator]
store:
  maximumOffers: 256
  offerLifetimeSeconds: 300
  accessTokenLifetimeSeconds: 300
  nonceLifetimeSeconds: 120
  maximumTransactionCodeAttempts: 3
"#
    )
}

fn offer_access_token(issuer: &FixtureIssuer) -> String {
    let now = Utc::now().timestamp();
    signed_jwt(
        &issuer.signing_key,
        json!({
            "alg": "ES256",
            "typ": "at+jwt",
            "kid": issuer.signing_public["kid"],
        }),
        json!({
            "iss": SUPPORT_ORIGIN,
            "sub": "tutorial-operator",
            "client_id": "tutorial-operator",
            "aud": ADOPTER_ORIGIN,
            "iat": now,
            "exp": now + 300,
            "jti": "synthetic-tutorial-offer-authorization",
        }),
    )
}

fn adapter_binary() -> PathBuf {
    std::env::var_os("EVIDENCE_OID4VCI_BIN")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_evidence-oid4vci")))
}

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

struct PrivateFileGuard(PathBuf);

impl Drop for PrivateFileGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

async fn wait_until_ready(client: &reqwest::Client, url: &str) {
    for _ in 0..100 {
        if client
            .get(url)
            .send()
            .await
            .is_ok_and(|response| response.status() == reqwest::StatusCode::OK)
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
    panic!("the real delivery binary did not become ready");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn copied_config_checks_starts_and_completes_the_real_binary_journey() {
    let external_root = std::env::var_os("EVIDENCE_OID4VCI_ADOPTER_ROOT").map(PathBuf::from);
    let supplied_config = external_root.is_some();
    let temporary = external_root
        .is_none()
        .then(|| tempfile::tempdir().expect("temporary adopter directory"));
    let root = external_root.unwrap_or_else(|| {
        temporary
            .as_ref()
            .expect("temporary root exists")
            .path()
            .to_owned()
    });
    fs::create_dir_all(&root).expect("create the adopter directory");
    fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
        .expect("restrict the adopter directory");
    let config_path = root.join("oid4vci.yaml");
    if supplied_config {
        assert_eq!(
            fs::read_to_string(&config_path).expect("read the copied tutorial configuration"),
            adopter_config(),
            "the reader-gated configuration must stay identical to the executable fixture"
        );
    } else {
        fs::write(&config_path, adopter_config()).expect("write the complete tutorial config");
    }
    println!("CONFIG COPIED: complete configuration has no untracked inputs");

    let client_identity = FixtureKey::generate();
    let client_key_path = root.join("delivery-client.jwk.json");
    fs::write(&client_key_path, &client_identity.private).expect("write the client identity");
    fs::set_permissions(&client_key_path, fs::Permissions::from_mode(0o600))
        .expect("restrict the client identity");
    let private_key_guard = PrivateFileGuard(client_key_path.clone());

    let loaded = DeliveryConfig::load(&config_path).expect("the copied configuration loads");
    assert_eq!(loaded.credential_issuer, ADOPTER_ORIGIN);
    assert_eq!(loaded.evidence.base_url, SUPPORT_ORIGIN);
    assert_eq!(
        loaded.metrics_listener.as_ref().map(|item| item.port),
        Some(18441)
    );

    let binary = adapter_binary();
    let check = Command::new(&binary)
        .env("RUST_LOG", "off")
        .args(["check", "--config"])
        .arg(&config_path)
        .output()
        .expect("run the real check command");
    assert!(
        check.status.success(),
        "check failed: {}",
        String::from_utf8_lossy(&check.stderr)
    );
    println!("CONFIG CHECKED: complete delivery configuration is valid");

    let issuer = Arc::new(FixtureIssuer::new());
    let support = HttpSupport {
        issuer: Arc::clone(&issuer),
        token_calls: Arc::new(AtomicUsize::new(0)),
        evidence_calls: Arc::new(AtomicUsize::new(0)),
    };
    let support_listener = tokio::net::TcpListener::bind("127.0.0.1:18442")
        .await
        .expect("bind the synthetic Evidence and Mint support listener");
    let support_app = Router::new()
        .route("/.well-known/jwks.json", get(support_jwks))
        .route("/token", post(support_token))
        .route("/v1/evidence-definitions", get(support_definitions))
        .route("/v1/evidence", post(support_evidence))
        .with_state(support.clone());
    let support_task =
        tokio::spawn(async move { axum::serve(support_listener, support_app).await });

    let inspect = Command::new(&binary)
        .env("RUST_LOG", "off")
        .args(["inspect", "--config"])
        .arg(&config_path)
        .output()
        .expect("run the real inspect command");
    assert!(
        inspect.status.success(),
        "inspect failed: {}",
        String::from_utf8_lossy(&inspect.stderr)
    );
    let inspected: Value =
        serde_json::from_slice(&inspect.stdout).expect("inspect prints one metadata document");
    assert_eq!(
        inspected["credentialIssuerMetadata"]["batch_credential_issuance"]["batch_size"],
        json!(4)
    );
    println!("METADATA INSPECTED: derived holder-bound batch ceiling is 4");

    let mut service = ChildGuard(
        Command::new(&binary)
            .env("RUST_LOG", "off")
            .args(["serve", "--config"])
            .arg(&config_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("start the real delivery binary"),
    );
    let client = reqwest::Client::new();
    wait_until_ready(&client, &format!("{ADOPTER_ORIGIN}/ready")).await;
    assert_eq!(
        client
            .get(format!("{ADOPTER_ORIGIN}/health"))
            .send()
            .await
            .expect("health responds")
            .status(),
        reqwest::StatusCode::OK
    );
    println!("SERVICE READY: health and readiness are available on the delivery listener");

    let metrics = client
        .get(format!("{ADOPTER_METRICS_ORIGIN}/metrics"))
        .send()
        .await
        .expect("private metrics respond");
    assert_eq!(metrics.status(), reqwest::StatusCode::OK);
    assert!(metrics
        .text()
        .await
        .expect("metrics are text")
        .contains("evidence_oid4vci_outcomes_total"));
    assert_eq!(
        client
            .get(format!("{ADOPTER_ORIGIN}/metrics"))
            .send()
            .await
            .expect("the public listener answers")
            .status(),
        reqwest::StatusCode::NOT_FOUND
    );
    println!("METRICS PRIVATE: metrics exist only on the separate loopback listener");

    let issuer_metadata: Value = client
        .get(format!("{ADOPTER_ORIGIN}{ISSUER_METADATA_PATH}"))
        .send()
        .await
        .expect("issuer metadata responds")
        .error_for_status()
        .expect("issuer metadata succeeds")
        .json()
        .await
        .expect("issuer metadata is JSON");
    let configuration_id = issuer_metadata["credential_configurations_supported"]
        .as_object()
        .and_then(|items| items.keys().next())
        .expect("metadata publishes a credential configuration")
        .to_owned();
    let authorization_server = issuer_metadata["authorization_servers"][0]
        .as_str()
        .expect("metadata publishes an authorization server");
    let authorization_metadata: Value = client
        .get(format!(
            "{authorization_server}{AUTHORIZATION_SERVER_METADATA_PATH}"
        ))
        .send()
        .await
        .expect("authorization metadata responds")
        .error_for_status()
        .expect("authorization metadata succeeds")
        .json()
        .await
        .expect("authorization metadata is JSON");

    let offer: Value = client
        .post(format!("{ADOPTER_ORIGIN}{OFFERS_PATH}"))
        .bearer_auth(offer_access_token(&issuer))
        .json(&json!({
            "credentialConfigurationId": configuration_id,
            "subjects": [{
                "role": "primary",
                "selectorValues": {"identifier": "synthetic-tutorial-subject"},
            }],
        }))
        .send()
        .await
        .expect("offer creation responds")
        .error_for_status()
        .expect("offer creation succeeds")
        .json()
        .await
        .expect("the offer is JSON");
    let code = offered_code(&offer);
    let token_endpoint = authorization_metadata["token_endpoint"]
        .as_str()
        .expect("authorization metadata publishes a token endpoint");
    let token: Value = client
        .post(token_endpoint)
        .form(&token_form(&code))
        .send()
        .await
        .expect("token exchange responds")
        .error_for_status()
        .expect("token exchange succeeds")
        .json()
        .await
        .expect("the token response is JSON");
    let access_token = token["access_token"]
        .as_str()
        .expect("the token response carries an access token");
    let nonce_endpoint = issuer_metadata["nonce_endpoint"]
        .as_str()
        .expect("issuer metadata publishes a nonce endpoint");
    let minted: Value = client
        .post(nonce_endpoint)
        .json(&json!({}))
        .send()
        .await
        .expect("nonce request responds")
        .error_for_status()
        .expect("nonce request succeeds")
        .json()
        .await
        .expect("the nonce response is JSON");
    let holder = FixtureKey::generate();
    let relying_policy = relying_policy(&holder);
    let now = Utc::now().timestamp();
    let credential_endpoint = issuer_metadata["credential_endpoint"]
        .as_str()
        .expect("issuer metadata publishes a credential endpoint");
    let issued_response = client
        .post(credential_endpoint)
        .bearer_auth(access_token)
        .json(&json!({
            "credential_configuration_id": configuration_id,
            "proofs": {"jwt": [did_jwk_proof(
                &holder,
                ADOPTER_ORIGIN,
                minted["c_nonce"].as_str().expect("the nonce is text"),
                now,
                Some(now + 60),
            )]},
        }))
        .send()
        .await
        .expect("credential request responds");
    let issued_status = issued_response.status();
    let issued_body = issued_response
        .text()
        .await
        .expect("read the credential response");
    assert_eq!(
        issued_status,
        reqwest::StatusCode::OK,
        "credential response: {issued_body}; token calls: {}; Evidence calls: {}",
        support.token_calls.load(Ordering::SeqCst),
        support.evidence_calls.load(Ordering::SeqCst),
    );
    let issued: Value =
        serde_json::from_str(&issued_body).expect("the credential response is JSON");
    let credential = issued["credentials"][0]["credential"]
        .as_str()
        .expect("the response carries one credential");
    verify_presentation(credential, &holder, &issuer, &relying_policy);
    assert_eq!(support.evidence_calls.load(Ordering::SeqCst), 1);
    assert!(support.token_calls.load(Ordering::SeqCst) >= 2);
    println!("PRESENTATION VERIFIED: public wallet flow returned holder-bound Evidence");

    service.0.kill().expect("stop the delivery binary");
    let _ = service.0.wait();
    support_task.abort();
    let _ = support_task.await;
    drop(private_key_guard);
    println!("CLEANUP COMPLETE: generated private material was removed");
}

#[tokio::test]
async fn pinned_inji_shape_discovers_and_collects_plural_holder_bound_credentials() {
    let (_directory, issuer, server) = deployment();
    let profile = profile();

    let metadata = server.get(ISSUER_METADATA_PATH).await;
    assert_eq!(metadata.status_code(), StatusCode::OK);
    let metadata: Value = metadata.json();
    let configuration = &metadata["credential_configurations_supported"][CONFIGURATION_ID];
    assert_eq!(configuration["format"], profile["metadata"]["format"]);
    assert_eq!(
        configuration["cryptographic_binding_methods_supported"],
        profile["metadata"]["bindingMethods"]
    );
    assert_eq!(
        configuration["proof_types_supported"]["jwt"]["proof_signing_alg_values_supported"],
        profile["metadata"]["proofSigningAlgorithms"]
    );
    assert_eq!(
        metadata["batch_credential_issuance"]["batch_size"],
        profile["metadata"]["batchSize"]
    );

    let credential_path = endpoint_path(&metadata, "credential_endpoint");
    let nonce_path = endpoint_path(&metadata, "nonce_endpoint");
    let authorization_server = metadata["authorization_servers"][0]
        .as_str()
        .expect("one authorization server is published");
    assert_eq!(authorization_server, CREDENTIAL_ISSUER);
    let authorization = server.get(AUTHORIZATION_SERVER_METADATA_PATH).await;
    assert_eq!(authorization.status_code(), StatusCode::OK);
    let authorization: Value = authorization.json();
    assert_eq!(
        authorization["pre-authorized_grant_anonymous_access_supported"],
        profile["metadata"]["anonymousPreAuthorizedGrant"]
    );
    let token_path = endpoint_path(&authorization, "token_endpoint");

    let token = access_token(&server, &token_path).await;
    let c_nonce = nonce(&server, &nonce_path).await;
    let first = FixtureKey::generate();
    let second = FixtureKey::generate();
    let relying_policy = relying_policy(&first);
    let now = Utc::now().timestamp();
    let response = credential_request(
        &server,
        &credential_path,
        &token,
        vec![
            did_jwk_proof(&first, CREDENTIAL_ISSUER, &c_nonce, now, Some(now + 60)),
            did_jwk_proof(&second, CREDENTIAL_ISSUER, &c_nonce, now, None),
        ],
    )
    .await;
    let status = response.status_code();
    let body: Value = response.json();
    assert_eq!(status, StatusCode::OK, "body: {body}");
    let credentials = body["credentials"]
        .as_array()
        .expect("the response is plural");
    assert_eq!(credentials.len(), 2);
    assert!(credentials.iter().all(|entry| entry
        .as_object()
        .is_some_and(|object| object.len() == 1)
        && entry["credential"].is_string()));

    let requests = issuer.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].holder_keys.len(), 2);
    assert!(requests[0].holder_keys.iter().all(|key| {
        key.kid
            .as_deref()
            .is_some_and(|kid| kid.starts_with("did:jwk:") && kid.ends_with("#0"))
    }));

    // The adapter only delivered the credential. A separate relying party now
    // proves holder possession and verifies the issuer signature, disclosures,
    // holder confirmation, and complete Evidence expectations independently.
    let credential = credentials[0]["credential"]
        .as_str()
        .expect("the first credential is text");
    verify_presentation(credential, &first, &issuer, &relying_policy);
}

#[tokio::test]
async fn the_negative_matrix_spends_each_authorization_before_proof_inspection() {
    let (_directory, issuer, server) = deployment();
    let now = Utc::now().timestamp();

    for case in [
        "audience",
        "nonce",
        "tampered-nonce",
        "expiration",
        "remote-key",
        "malformed-key",
        "private-key",
        "unsupported-algorithm",
        "duplicate-key",
        "excessive-proofs",
    ] {
        let token = access_token(&server, TOKEN_PATH).await;
        let c_nonce = nonce(&server, NONCE_PATH).await;
        let key = FixtureKey::generate();
        let proofs = match case {
            "audience" => vec![did_jwk_proof(
                &key,
                "https://other.example.org",
                &c_nonce,
                now,
                None,
            )],
            "nonce" => vec![did_jwk_proof(
                &key,
                CREDENTIAL_ISSUER,
                "not-a-service-nonce",
                now,
                None,
            )],
            "tampered-nonce" => {
                let (expiry, tag) = c_nonce
                    .split_once('.')
                    .expect("a minted nonce carries its tag");
                let replacement = if tag.starts_with('A') { 'B' } else { 'A' };
                let tampered = format!("{expiry}.{replacement}{}", &tag[1..]);
                vec![did_jwk_proof(&key, CREDENTIAL_ISSUER, &tampered, now, None)]
            }
            "expiration" => vec![did_jwk_proof(
                &key,
                CREDENTIAL_ISSUER,
                &c_nonce,
                now,
                Some(now - 1),
            )],
            "remote-key" => vec![remote_key_proof(&key, &c_nonce, now)],
            "malformed-key" => vec![inline_jwk_proof(
                &key,
                json!({"kty": "EC", "crv": "P-256", "x": "bad", "y": "bad"}),
                "ES256",
                &c_nonce,
                now,
            )],
            "private-key" => vec![inline_jwk_proof(
                &key,
                serde_json::from_str(&key.private).expect("the fixture private key is JSON"),
                "ES256",
                &c_nonce,
                now,
            )],
            "unsupported-algorithm" => vec![inline_jwk_proof(
                &key,
                key.public.clone(),
                "ES384",
                &c_nonce,
                now,
            )],
            "duplicate-key" => {
                let proof = did_jwk_proof(&key, CREDENTIAL_ISSUER, &c_nonce, now, None);
                vec![proof.clone(), proof]
            }
            "excessive-proofs" => {
                let proof = did_jwk_proof(&key, CREDENTIAL_ISSUER, &c_nonce, now, None);
                vec![proof; 5]
            }
            _ => unreachable!(),
        };
        let before = issuer.call_count();
        let refused = credential_request(&server, CREDENTIAL_PATH, &token, proofs).await;
        assert_eq!(refused.status_code(), StatusCode::BAD_REQUEST, "{case}");
        assert_eq!(issuer.call_count(), before, "{case} reached Evidence");

        // A recognized token buys one attempt. Even a valid second request is
        // a replay and cannot reach Evidence after the proof refusal.
        let fresh_nonce = nonce(&server, NONCE_PATH).await;
        let retry_key = FixtureKey::generate();
        let replay = credential_request(
            &server,
            CREDENTIAL_PATH,
            &token,
            vec![did_jwk_proof(
                &retry_key,
                CREDENTIAL_ISSUER,
                &fresh_nonce,
                Utc::now().timestamp(),
                None,
            )],
        )
        .await;
        assert_eq!(replay.status_code(), StatusCode::UNAUTHORIZED, "{case}");
        assert_eq!(
            issuer.call_count(),
            before,
            "{case} replay reached Evidence"
        );
    }
}

#[tokio::test]
async fn a_nonce_is_reusable_across_authorizations_but_one_token_has_one_concurrent_winner() {
    let (_directory, issuer, server) = deployment();
    let shared_nonce = nonce(&server, NONCE_PATH).await;

    let first_token = access_token(&server, TOKEN_PATH).await;
    let second_token = access_token(&server, TOKEN_PATH).await;
    for token in [&first_token, &second_token] {
        let key = FixtureKey::generate();
        let response = credential_request(
            &server,
            CREDENTIAL_PATH,
            token,
            vec![did_jwk_proof(
                &key,
                CREDENTIAL_ISSUER,
                &shared_nonce,
                Utc::now().timestamp(),
                None,
            )],
        )
        .await;
        assert_eq!(response.status_code(), StatusCode::OK);
    }
    assert_eq!(issuer.call_count(), 2);

    let contested_token = access_token(&server, TOKEN_PATH).await;
    let key = FixtureKey::generate();
    let proofs = vec![did_jwk_proof(
        &key,
        CREDENTIAL_ISSUER,
        &shared_nonce,
        Utc::now().timestamp(),
        None,
    )];
    let first = credential_request(&server, CREDENTIAL_PATH, &contested_token, proofs.clone());
    let second = credential_request(&server, CREDENTIAL_PATH, &contested_token, proofs);
    let (first, second) = tokio::join!(first, second);
    let mut statuses = [first.status_code(), second.status_code()];
    statuses.sort();
    assert_eq!(statuses, [StatusCode::OK, StatusCode::UNAUTHORIZED]);
    assert_eq!(issuer.call_count(), 3, "only one request reached Evidence");
}
