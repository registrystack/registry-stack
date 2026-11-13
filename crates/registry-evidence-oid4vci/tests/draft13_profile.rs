//! Black-box coverage for the OpenID4VCI Draft 13 compatibility profile.
//!
//! The profile exists for one wallet family that accepts third-party issuance
//! only over Draft 13. These tests drive the exported router and prove three
//! things: the profile speaks the Draft 13 wire shapes at its own issuer
//! identifier, it shares no redeemable state with the 1.0 Final profile, and the
//! 1.0 Final profile answers exactly as it does with the compatibility profile
//! absent. A recording issuer is the complete Evidence boundary, so a zero call
//! count proves nothing reached Evidence behind a refusal.

use std::{
    collections::BTreeMap,
    fs,
    sync::{
        atomic::{AtomicI64, Ordering},
        Arc, Mutex,
    },
};

use async_trait::async_trait;
use axum::http::StatusCode;
use axum_test::{TestResponse, TestServer};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{SecondsFormat, Utc};
use p256::{ecdsa::SigningKey, elliptic_curve::Generate as _};
use registry_evidence_client::{
    AssuranceProfile, EvidenceDefinitionsDocument, HolderBoundRequestSpec, HolderPublicKey,
};
use registry_evidence_oid4vci::{
    audit::DeliveryAudit,
    authorizer::{AuthorizationError, AuthorizedOffer, OfferAuthorizer},
    config::DeliveryConfig,
    draft13,
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
        ChannelKind, Evidence, EvidenceObjectType, PublicValue, SubjectBinding, SubjectBindingMode,
        SupportedValue,
    },
    sdjwt_vc::{holder_thumbprint, issuance_input},
    EVIDENCE_SCHEMA_V1,
};
use registry_platform_audit::AuditWriter;
use registry_platform_crypto::{hmac_sha256_base64url_no_pad, sign, PrivateJwk};
use registry_platform_sdjwt::SdJwtIssuer;
use serde_json::{json, Value};

const OFFER_TOKEN: &str = "offer-token";
const FINAL_ISSUER: &str = "https://wallet.example.org";
const DRAFT13_ISSUER: &str = "https://wallet.example.org/protocol/oid4vci/draft-13";
const CONFIGURATION_ID: &str = "urn:example:requirement:holder-bound";
const EVIDENCE_TYPE: &str = "urn:example:evidence-type:holder-bound";
const SELECTOR_VALUE: &str = "subject-identifier-value";
const SUBJECT_BINDING_KEY: &[u8] = b"synthetic-draft13-subject-binding-key";

const CONFIG_HEAD: &str = r#"apiVersion: id.registrystack.org/formats/evidence/oid4vci-runtime/v1alpha1
kind: EvidenceOid4vciRuntimeConfig
credentialIssuer: https://wallet.example.org
listener: {bind: "127.0.0.1:8090"}
secretProviders:
  file:
    root: /run/secrets/evidence-oid4vci
audit:
  destination: stdout
  hashKeyRef: secret:file/unused-audit-hash-key
evidence:
  baseUrl: https://evidence.example.org
tokenClient:
  tokenEndpoint: https://mint.example.org/token
  clientId: evidence-oid4vci
  privateKeyRef: secret:file/unused-delivery-client.jwk.json
offers:
  issuer: https://mint.example.org
  jwksUri: https://mint.example.org/.well-known/jwks.json
  audiences: ["https://wallet.example.org"]
  algorithms: [EdDSA]
  allowedClients: [adopter-front-end]
  requiredScopes: [oid4vci:offer]
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
  "maximumHolderBoundBatchSize": 4,
  "definitions": [{
    "handle": "holder-bound",
    "requirement": "urn:example:requirement:holder-bound",
    "configurationRevision": "sha256:0000000000000000000000000000000000000000000000000000000000000000",
    "kind": "criterion",
    "subjectBindingMode": "holder-bound",
    "evidenceType": "urn:example:evidence-type:holder-bound",
    "purpose": "urn:example:purpose:demonstration",
    "responseFormats": ["sd-jwt-vc", "sd-jwt-vc-batch"],
    "referenceFrameworks": ["urn:example:framework:synthetic"],
    "subjects": [{
      "role": "primary",
      "cardinality": "one",
      "selector": {
        "profile": "synthetic-identifier-v1",
        "valueOrigin": "request",
        "fields": [{"type": "string", "name": "identifier", "minimumBytes": 1, "maximumBytes": 64}]
      }
    }],
    "concepts": [{"handle": "outcome", "concept": "urn:example:concept:outcome", "required": true, "form": {"type": "boolean"}}]
  }]
}"#;

fn config_text(draft13_block: Option<&str>) -> String {
    match draft13_block {
        Some(block) => format!("{CONFIG_HEAD}{block}\n"),
        None => CONFIG_HEAD.to_owned(),
    }
}

fn load_config(text: &str) -> Result<DeliveryConfig, String> {
    // The reader refuses a path through a symbolic link, and the system
    // temporary directory is one on some hosts.
    let base = std::env::temp_dir()
        .canonicalize()
        .expect("the temporary directory resolves");
    let directory = tempfile::tempdir_in(base).expect("a temporary deployment directory");
    let path = directory.path().join("oid4vci.yaml");
    fs::write(&path, text).expect("write the test deployment");
    DeliveryConfig::load(&path).map_err(|error| error.to_string())
}

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

/// The Evidence boundary. It signs a real SD-JWT VC for each holder key it is
/// handed, so a test can read the credential's `cnf` member back.
struct SigningIssuer {
    catalog: Arc<CredentialCatalog>,
    signing_key: String,
    requests: Mutex<Vec<HolderBoundRequestSpec>>,
    issued: Mutex<Vec<String>>,
}

impl SigningIssuer {
    fn new() -> Self {
        let document: EvidenceDefinitionsDocument =
            serde_json::from_str(DEFINITIONS).expect("the definitions document parses");
        let generated = SigningKey::generate();
        let point = generated.verifying_key().to_sec1_point(false);
        let signing_key = json!({
            "kty": "EC",
            "crv": "P-256",
            "alg": "ES256",
            "kid": "issuer-key",
            "x": URL_SAFE_NO_PAD.encode(point.x().expect("an issuer key has x")),
            "y": URL_SAFE_NO_PAD.encode(point.y().expect("an issuer key has y")),
            "d": URL_SAFE_NO_PAD.encode(generated.to_bytes()),
        });
        Self {
            catalog: Arc::new(CredentialCatalog::derive(&document).expect("the catalog is valid")),
            signing_key: signing_key.to_string(),
            requests: Mutex::new(Vec::new()),
            issued: Mutex::new(Vec::new()),
        }
    }

    fn call_count(&self) -> usize {
        self.requests.lock().expect("requests lock").len()
    }

    fn requests(&self) -> Vec<HolderBoundRequestSpec> {
        self.requests.lock().expect("requests lock").clone()
    }

    fn issued(&self) -> Vec<String> {
        self.issued.lock().expect("issued lock").clone()
    }
}

#[async_trait]
impl CredentialIssuer for SigningIssuer {
    async fn catalog(&self) -> Result<Arc<CredentialCatalog>, IssuanceError> {
        Ok(Arc::clone(&self.catalog))
    }

    async fn issue(&self, spec: HolderBoundRequestSpec) -> Result<Vec<String>, IssuanceError> {
        let signer = SdJwtIssuer::from_jwk(
            PrivateJwk::parse(&self.signing_key).expect("the issuer private JWK parses"),
        )
        .expect("the issuer signer initializes");
        let mut credentials = Vec::new();
        for (index, holder_key) in spec.holder_keys.iter().enumerate() {
            let evidence = holder_bound_evidence(index, holder_key);
            let input = issuance_input(&evidence, Some(holder_key), &BTreeMap::new())
                .expect("holder-bound Evidence maps to SD-JWT VC");
            credentials.push(
                signer
                    .issue(input)
                    .await
                    .expect("the fixture Evidence credential signs")
                    .jwt,
            );
        }
        self.issued
            .lock()
            .expect("issued lock")
            .extend(credentials.iter().cloned());
        self.requests.lock().expect("requests lock").push(spec);
        Ok(credentials)
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
        channel: ChannelKind::Source,
        presented_credential: None,
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
        purpose: "urn:example:purpose:demonstration".to_owned(),
        audience: None,
        configuration_revision:
            "sha256:0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
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
            provides_value_for: "urn:example:concept:outcome".to_owned(),
            value: PublicValue::Boolean(true),
        }],
    }
}

/// The wall-clock second the service reads, plus an offset a test moves.
#[derive(Clone, Default)]
struct TestClock(Arc<AtomicI64>);

impl TestClock {
    fn now(&self) -> i64 {
        Utc::now().timestamp() + self.0.load(Ordering::SeqCst)
    }

    fn advance(&self, seconds: i64) {
        self.0.fetch_add(seconds, Ordering::SeqCst);
    }
}

struct Harness {
    server: TestServer,
    issuer: Arc<SigningIssuer>,
    clock: TestClock,
}

fn harness(draft13: bool) -> Harness {
    let block = draft13.then_some("draft13Profile: {}");
    let config = load_config(&config_text(block)).expect("the deployment loads");
    let issuer = Arc::new(SigningIssuer::new());
    let clock = TestClock::default();
    let reading = clock.clone();
    let service = DeliveryService::with_halves(
        config,
        Arc::new(StubAuthorizer),
        Arc::clone(&issuer) as Arc<dyn CredentialIssuer>,
        Arc::new(
            DeliveryAudit::with_writer(
                AuditWriter::from_line_sink(Box::new(std::io::sink())),
                b"0123456789abcdef0123456789abcdef".to_vec(),
            )
            .expect("the test audit profile is valid"),
        ),
    )
    .with_clock(move || reading.now());
    let server = TestServer::new(build_app(Arc::new(service)));
    Harness {
        server,
        issuer,
        clock,
    }
}

fn offer_body() -> Value {
    json!({
        "credentialConfigurationId": CONFIGURATION_ID,
        "subjects": [{"role": "primary", "selectorValues": {"identifier": SELECTOR_VALUE}}],
    })
}

async fn create_offer(server: &TestServer, path: &str) -> Value {
    let response = server
        .post(path)
        .add_header("authorization", format!("Bearer {OFFER_TOKEN}"))
        .json(&offer_body())
        .await;
    assert_eq!(response.status_code(), StatusCode::CREATED);
    response.json()
}

fn code_of(offer: &Value) -> String {
    offer["credentialOffer"]["grants"][PRE_AUTHORIZED_CODE_GRANT_TYPE]["pre-authorized_code"]
        .as_str()
        .expect("the offer carries a pre-authorized code")
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

/// An access token and the `c_nonce` that came with it, from the Draft 13
/// profile.
async fn draft13_grant(server: &TestServer) -> (String, String) {
    let code = code_of(&create_offer(server, draft13::OFFERS_PATH).await);
    let response = server
        .post(draft13::TOKEN_PATH)
        .form(&token_form(&code))
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let body: Value = response.json();
    (
        body["access_token"]
            .as_str()
            .expect("access token")
            .to_owned(),
        body["c_nonce"].as_str().expect("c_nonce").to_owned(),
    )
}

async fn final_access_token(server: &TestServer) -> String {
    let code = code_of(&create_offer(server, OFFERS_PATH).await);
    let response = server.post(TOKEN_PATH).form(&token_form(&code)).await;
    assert_eq!(response.status_code(), StatusCode::OK);
    response.json::<Value>()["access_token"]
        .as_str()
        .expect("access token")
        .to_owned()
}

fn holder_key() -> String {
    let key = SigningKey::generate();
    let point = key.verifying_key().to_sec1_point(false);
    json!({
        "kty": "EC",
        "crv": "P-256",
        "alg": "ES256",
        "x": URL_SAFE_NO_PAD.encode(point.x().expect("the public key has x")),
        "y": URL_SAFE_NO_PAD.encode(point.y().expect("the public key has y")),
        "d": URL_SAFE_NO_PAD.encode(key.to_bytes()),
    })
    .to_string()
}

fn proof_with(private_key: &str, header_overrides: Value, claims: Value) -> String {
    let private = PrivateJwk::parse(private_key).expect("the holder key parses");
    let mut header = json!({
        "alg": "ES256",
        "typ": "openid4vci-proof+jwt",
        "jwk": private.public(),
    });
    for (name, value) in header_overrides
        .as_object()
        .expect("overrides are an object")
    {
        header[name] = value.clone();
    }
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    );
    let signature = sign(signing_input.as_bytes(), &private).expect("the holder proof signs");
    format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature))
}

fn proof(private_key: &str, audience: &str, nonce: &str, harness: &Harness) -> String {
    proof_with(
        private_key,
        json!({}),
        json!({"aud": audience, "iat": harness.clock.now(), "nonce": nonce}),
    )
}

fn credential_body(proof_jwt: &str) -> Value {
    json!({
        "format": "dc+sd-jwt",
        "vct": EVIDENCE_TYPE,
        "proof": {"proof_type": "jwt", "jwt": proof_jwt},
    })
}

async fn post_credential(server: &TestServer, token: &str, body: &Value) -> TestResponse {
    server
        .post(draft13::CREDENTIAL_PATH)
        .add_header("authorization", format!("Bearer {token}"))
        .json(body)
        .await
}

fn error_of(response: &TestResponse) -> (String, String) {
    let body: Value = response.json();
    (
        body["error"].as_str().expect("an error code").to_owned(),
        body["error_description"]
            .as_str()
            .expect("an error description")
            .to_owned(),
    )
}

fn decode_segment(segment: &str) -> Value {
    serde_json::from_slice(&URL_SAFE_NO_PAD.decode(segment).expect("base64url segment"))
        .expect("a JSON segment")
}

// Configuration.

#[test]
fn the_profile_is_off_unless_the_block_is_written() {
    let off = load_config(&config_text(None)).expect("the deployment loads");
    assert!(!off.draft13_profile);
    let on = load_config(&config_text(Some("draft13Profile: {}"))).expect("the deployment loads");
    assert!(on.draft13_profile);
    assert_eq!(on.credential_issuer, FINAL_ISSUER);
    assert_eq!(draft13::credential_issuer(&on), DRAFT13_ISSUER);
}

#[test]
fn a_draft13_block_that_is_not_an_empty_mapping_is_refused() {
    for block in [
        "draft13Profile: true",
        "draft13Profile: false",
        "draft13Profile:",
        "draft13Profile: {enabled: true}",
        "draft13Profile: {pathPrefix: /other}",
        "draft13Profile: []",
    ] {
        assert!(
            load_config(&config_text(Some(block))).is_err(),
            "{block} was accepted"
        );
    }
}

// Routing and metadata.

#[tokio::test]
async fn no_draft13_route_exists_when_the_profile_is_off() {
    let harness = harness(false);
    for path in [
        draft13::ISSUER_METADATA_PATH,
        draft13::OFFERS_PATH,
        draft13::TOKEN_PATH,
        draft13::CREDENTIAL_PATH,
    ] {
        assert_eq!(
            harness.server.get(path).await.status_code(),
            StatusCode::NOT_FOUND,
            "{path}"
        );
        assert_eq!(
            harness.server.post(path).await.status_code(),
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
}

#[tokio::test]
async fn draft13_metadata_is_plain_json_at_its_own_issuer_url() {
    let harness = harness(true);
    assert!(draft13::ISSUER_METADATA_PATH.starts_with("/protocol/oid4vci/draft-13/"));
    let response = harness.server.get(draft13::ISSUER_METADATA_PATH).await;
    assert_eq!(response.status_code(), StatusCode::OK);
    assert_eq!(
        response.header("content-type").to_str().expect("ASCII"),
        "application/json"
    );
    assert_eq!(
        response.header("cache-control").to_str().expect("ASCII"),
        "no-store"
    );
    assert_eq!(
        response.json::<Value>(),
        json!({
            "credential_issuer": DRAFT13_ISSUER,
            "credential_endpoint": format!("{DRAFT13_ISSUER}/credential"),
            "token_endpoint": format!("{DRAFT13_ISSUER}/token"),
            "grant_types_supported": [PRE_AUTHORIZED_CODE_GRANT_TYPE],
            "token_endpoint_auth_method": ["none"],
            "credential_configurations_supported": {
                CONFIGURATION_ID: {
                    "format": "dc+sd-jwt",
                    "vct": EVIDENCE_TYPE,
                    "cryptographic_binding_methods_supported": ["cose_key"],
                    "credential_signing_alg_values_supported": ["ES256"],
                    "proof_types_supported": {
                        "jwt": {"proof_signing_alg_values_supported": ["ES256"]}
                    }
                }
            }
        })
    );
    // The plain JSON document is not a signed one.
    let text = response.text();
    assert!(text.starts_with('{'));
    for absent in ["authorization_servers", "nonce_endpoint", "signed_metadata"] {
        assert!(!text.contains(absent), "metadata carries {absent}");
    }
}

#[tokio::test]
async fn cose_key_is_advertised_only_by_the_draft13_profile() {
    let harness = harness(true);
    let draft13 = harness
        .server
        .get(draft13::ISSUER_METADATA_PATH)
        .await
        .text();
    assert!(draft13.contains("\"cose_key\""));

    let final_metadata = harness.server.get(ISSUER_METADATA_PATH).await;
    let text = final_metadata.text();
    assert!(
        !text.contains("cose_key"),
        "1.0 metadata advertises cose_key"
    );
    assert_eq!(
        final_metadata.json::<Value>()["credential_configurations_supported"][CONFIGURATION_ID]
            ["cryptographic_binding_methods_supported"],
        json!(["jwk", "did:jwk"])
    );
}

#[tokio::test]
async fn the_draft13_profile_has_no_nonce_endpoint_or_authorization_server_document() {
    let harness = harness(true);
    for path in [
        "/protocol/oid4vci/draft-13/nonce",
        "/protocol/oid4vci/draft-13/.well-known/oauth-authorization-server",
    ] {
        assert_eq!(
            harness.server.post(path).await.status_code(),
            StatusCode::NOT_FOUND,
            "{path}"
        );
        assert_eq!(
            harness.server.get(path).await.status_code(),
            StatusCode::NOT_FOUND,
            "{path}"
        );
    }
}

// The 1.0 Final profile does not move.

#[tokio::test]
async fn final_documents_are_identical_with_the_draft13_profile_on_and_off() {
    let off = harness(false);
    let on = harness(true);
    for path in [ISSUER_METADATA_PATH, AUTHORIZATION_SERVER_METADATA_PATH] {
        let before = off.server.get(path).await;
        let after = on.server.get(path).await;
        assert_eq!(before.status_code(), StatusCode::OK, "{path}");
        assert_eq!(after.status_code(), StatusCode::OK, "{path}");
        assert_eq!(before.as_bytes(), after.as_bytes(), "{path}");
    }
    let metadata: Value = on.server.get(ISSUER_METADATA_PATH).await.json();
    assert_eq!(
        metadata,
        json!({
            "credential_issuer": FINAL_ISSUER,
            "credential_endpoint": format!("{FINAL_ISSUER}/credential"),
            "nonce_endpoint": format!("{FINAL_ISSUER}/nonce"),
            "authorization_servers": [FINAL_ISSUER],
            "credential_configurations_supported": {
                CONFIGURATION_ID: {
                    "format": "dc+sd-jwt",
                    "vct": EVIDENCE_TYPE,
                    "cryptographic_binding_methods_supported": ["jwk", "did:jwk"],
                    "credential_signing_alg_values_supported": ["ES256"],
                    "proof_types_supported": {
                        "jwt": {"proof_signing_alg_values_supported": ["ES256"]}
                    }
                }
            },
            "batch_credential_issuance": {"batch_size": 4}
        })
    );
}

#[tokio::test]
async fn the_final_flow_answers_the_same_shapes_with_the_draft13_profile_on() {
    let harness = harness(true);
    let offer = create_offer(&harness.server, OFFERS_PATH).await;
    assert_eq!(offer["credentialOffer"]["credential_issuer"], FINAL_ISSUER);
    assert!(
        offer["credentialOffer"]["grants"][PRE_AUTHORIZED_CODE_GRANT_TYPE]
            .get("user_pin_required")
            .is_none()
    );

    let token = harness
        .server
        .post(TOKEN_PATH)
        .form(&token_form(&code_of(&offer)))
        .await;
    let body: Value = token.json();
    assert_eq!(body["token_type"], "Bearer");
    assert_eq!(body["expires_in"], 300);
    assert!(body.get("c_nonce").is_none());
    assert_eq!(body.as_object().expect("an object").len(), 3);

    let nonce: Value = harness.server.post(NONCE_PATH).await.json();
    let key = holder_key();
    let response = harness
        .server
        .post(CREDENTIAL_PATH)
        .add_header(
            "authorization",
            format!("Bearer {}", body["access_token"].as_str().expect("token")),
        )
        .json(&json!({
            "credential_configuration_id": CONFIGURATION_ID,
            "proofs": {"jwt": [proof(&key, FINAL_ISSUER, nonce["c_nonce"].as_str().expect("nonce"), &harness)]},
        }))
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let delivered: Value = response.json();
    assert_eq!(
        delivered["credentials"].as_array().expect("plural").len(),
        1
    );
    assert_eq!(harness.issuer.call_count(), 1);
}

// Offer creation.

#[tokio::test]
async fn a_draft13_offer_names_the_draft13_issuer_and_needs_the_same_authorization() {
    let harness = harness(true);
    let unauthorized = harness
        .server
        .post(draft13::OFFERS_PATH)
        .json(&offer_body())
        .await;
    assert_eq!(unauthorized.status_code(), StatusCode::UNAUTHORIZED);

    let offer = create_offer(&harness.server, draft13::OFFERS_PATH).await;
    let object = &offer["credentialOffer"];
    assert_eq!(object["credential_issuer"], DRAFT13_ISSUER);
    assert_eq!(
        object["credential_configuration_ids"],
        json!([CONFIGURATION_ID])
    );
    let grant = &object["grants"][PRE_AUTHORIZED_CODE_GRANT_TYPE];
    assert!(grant["pre-authorized_code"].is_string());
    assert!(grant.get("tx_code").is_none());
    let uri = offer["credentialOfferUri"].as_str().expect("an offer URI");
    assert!(uri.starts_with("openid-credential-offer://?credential_offer="));
}

#[tokio::test]
async fn a_draft13_offer_with_a_transaction_code_describes_it() {
    let harness = harness(true);
    let mut body = offer_body();
    body["transactionCode"] = json!(true);
    let response = harness
        .server
        .post(draft13::OFFERS_PATH)
        .add_header("authorization", format!("Bearer {OFFER_TOKEN}"))
        .json(&body)
        .await;
    assert_eq!(response.status_code(), StatusCode::CREATED);
    let offer: Value = response.json();
    let grant = &offer["credentialOffer"]["grants"][PRE_AUTHORIZED_CODE_GRANT_TYPE];
    assert_eq!(
        grant["tx_code"],
        json!({"input_mode": "numeric", "length": 6})
    );
    assert!(offer["transactionCode"].is_string());

    let code = code_of(&offer);
    let without = harness
        .server
        .post(draft13::TOKEN_PATH)
        .form(&token_form(&code))
        .await;
    assert_eq!(without.status_code(), StatusCode::BAD_REQUEST);
    let mut form = token_form(&code);
    form.push((
        "tx_code".to_owned(),
        offer["transactionCode"].as_str().expect("code").to_owned(),
    ));
    let with = harness.server.post(draft13::TOKEN_PATH).form(&form).await;
    assert_eq!(with.status_code(), StatusCode::OK);
}

// Token endpoint.

#[tokio::test]
async fn the_draft13_token_response_is_lowercase_bearer_with_a_c_nonce() {
    let harness = harness(true);
    let code = code_of(&create_offer(&harness.server, draft13::OFFERS_PATH).await);
    let response = harness
        .server
        .post(draft13::TOKEN_PATH)
        .form(&token_form(&code))
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);
    assert_eq!(
        response.header("cache-control").to_str().expect("ASCII"),
        "no-store"
    );
    let body: Value = response.json();
    assert_eq!(body["token_type"], "bearer");
    assert_eq!(body["expires_in"], 300);
    assert_eq!(body["c_nonce_expires_in"], 120);
    assert!(body["access_token"].is_string());
    assert!(body["c_nonce"].is_string());
    assert_eq!(body.as_object().expect("an object").len(), 5);
}

#[tokio::test]
async fn the_draft13_token_request_must_be_form_encoded() {
    let harness = harness(true);
    let code = code_of(&create_offer(&harness.server, draft13::OFFERS_PATH).await);
    let response = harness
        .server
        .post(draft13::TOKEN_PATH)
        .json(&json!({
            "grant_type": PRE_AUTHORIZED_CODE_GRANT_TYPE,
            "pre-authorized_code": code,
        }))
        .await;
    assert_eq!(response.status_code(), StatusCode::UNSUPPORTED_MEDIA_TYPE);
    // The refused request spent nothing.
    let retry = harness
        .server
        .post(draft13::TOKEN_PATH)
        .form(&token_form(&code))
        .await;
    assert_eq!(retry.status_code(), StatusCode::OK);
}

#[tokio::test]
async fn the_draft13_token_endpoint_refuses_other_grants_and_spent_codes() {
    let harness = harness(true);
    let code = code_of(&create_offer(&harness.server, draft13::OFFERS_PATH).await);
    let other = harness
        .server
        .post(draft13::TOKEN_PATH)
        .form(&[("grant_type", "authorization_code"), ("code", "x")])
        .await;
    assert_eq!(error_of(&other).0, "unsupported_grant_type");

    assert_eq!(
        harness
            .server
            .post(draft13::TOKEN_PATH)
            .form(&token_form(&code))
            .await
            .status_code(),
        StatusCode::OK
    );
    let again = harness
        .server
        .post(draft13::TOKEN_PATH)
        .form(&token_form(&code))
        .await;
    assert_eq!(again.status_code(), StatusCode::BAD_REQUEST);
    assert_eq!(error_of(&again).0, "invalid_grant");
}

// Credential endpoint.

#[tokio::test]
async fn a_singular_proof_is_accepted_and_the_credential_is_delivered_unaltered() {
    let harness = harness(true);
    let (token, c_nonce) = draft13_grant(&harness.server).await;
    let key = holder_key();
    let response = post_credential(
        &harness.server,
        &token,
        &credential_body(&proof(&key, DRAFT13_ISSUER, &c_nonce, &harness)),
    )
    .await;
    assert_eq!(response.status_code(), StatusCode::OK);
    assert_eq!(
        response.header("cache-control").to_str().expect("ASCII"),
        "no-store"
    );
    let body: Value = response.json();
    assert_eq!(body.as_object().expect("an object").len(), 1);
    let issued = harness.issuer.issued();
    assert_eq!(issued.len(), 1);
    assert_eq!(body["credential"], json!(issued[0]));
    assert_eq!(harness.issuer.call_count(), 1);
    assert_eq!(harness.issuer.requests()[0].holder_keys.len(), 1);
}

/// The Partenaires Android 1.3.5078 workaround advertises `cose_key`, but the
/// credential still binds the holder's key in `cnf.jwk`, because the credential
/// is the SD-JWT VC Evidence signed for the key the proof presented.
#[tokio::test]
async fn the_credential_binds_the_holder_key_in_cnf_jwk_despite_the_advertised_cose_key() {
    let harness = harness(true);
    let advertised: Value = harness
        .server
        .get(draft13::ISSUER_METADATA_PATH)
        .await
        .json();
    assert_eq!(
        advertised["credential_configurations_supported"][CONFIGURATION_ID]
            ["cryptographic_binding_methods_supported"],
        json!(["cose_key"])
    );

    let (token, c_nonce) = draft13_grant(&harness.server).await;
    let key = holder_key();
    let response = post_credential(
        &harness.server,
        &token,
        &credential_body(&proof(&key, DRAFT13_ISSUER, &c_nonce, &harness)),
    )
    .await;
    assert_eq!(response.status_code(), StatusCode::OK);
    let credential = response.json::<Value>()["credential"]
        .as_str()
        .expect("a credential")
        .to_owned();
    let jwt = credential.split('~').next().expect("an issuer-signed JWT");
    let segments: Vec<&str> = jwt.split('.').collect();
    let header = decode_segment(segments[0]);
    let payload = decode_segment(segments[1]);
    assert_eq!(header["typ"], "dc+sd-jwt");
    assert_eq!(header["alg"], "ES256");
    let public = PrivateJwk::parse(&key).expect("the key parses").public();
    let bound = &payload["cnf"]["jwk"];
    assert_eq!(bound["kty"], "EC");
    assert_eq!(bound["crv"], "P-256");
    assert_eq!(bound["x"], json!(public.x));
    assert_eq!(bound["y"], json!(public.y));
    assert!(payload["cnf"].get("cose_key").is_none());
}

#[tokio::test]
async fn plural_proofs_are_refused_before_evidence() {
    let harness = harness(true);
    let (token, c_nonce) = draft13_grant(&harness.server).await;
    let key = holder_key();
    let jwt = proof(&key, DRAFT13_ISSUER, &c_nonce, &harness);
    let response = post_credential(
        &harness.server,
        &token,
        &json!({
            "format": "dc+sd-jwt",
            "vct": EVIDENCE_TYPE,
            "proofs": {"jwt": [jwt]},
        }),
    )
    .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    assert_eq!(error_of(&response).0, "invalid_credential_request");
    assert_eq!(harness.issuer.call_count(), 0);
}

#[tokio::test]
async fn a_final_shaped_credential_request_is_refused_by_the_draft13_endpoint() {
    let harness = harness(true);
    let (token, c_nonce) = draft13_grant(&harness.server).await;
    let key = holder_key();
    let response = post_credential(
        &harness.server,
        &token,
        &json!({
            "credential_configuration_id": CONFIGURATION_ID,
            "proofs": {"jwt": [proof(&key, DRAFT13_ISSUER, &c_nonce, &harness)]},
        }),
    )
    .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    assert_eq!(error_of(&response).0, "invalid_credential_request");
    assert_eq!(harness.issuer.call_count(), 0);
}

#[tokio::test]
async fn an_unsupported_format_or_credential_type_is_refused() {
    let harness = harness(true);
    let key = holder_key();
    for (format, vct, expected) in [
        ("vc+sd-jwt", EVIDENCE_TYPE, "unsupported_credential_format"),
        ("mso_mdoc", EVIDENCE_TYPE, "unsupported_credential_format"),
        (
            "dc+sd-jwt",
            "urn:example:other",
            "unsupported_credential_type",
        ),
    ] {
        let (token, c_nonce) = draft13_grant(&harness.server).await;
        let response = post_credential(
            &harness.server,
            &token,
            &json!({
                "format": format,
                "vct": vct,
                "proof": {
                    "proof_type": "jwt",
                    "jwt": proof(&key, DRAFT13_ISSUER, &c_nonce, &harness),
                },
            }),
        )
        .await;
        assert_eq!(
            response.status_code(),
            StatusCode::BAD_REQUEST,
            "{format} {vct}"
        );
        assert_eq!(error_of(&response).0, expected, "{format} {vct}");
    }
    assert_eq!(harness.issuer.call_count(), 0);
}

#[tokio::test]
async fn a_proof_type_other_than_jwt_is_refused() {
    let harness = harness(true);
    let (token, _) = draft13_grant(&harness.server).await;
    let response = post_credential(
        &harness.server,
        &token,
        &json!({
            "format": "dc+sd-jwt",
            "vct": EVIDENCE_TYPE,
            "proof": {"proof_type": "cwt", "cwt": "irrelevant"},
        }),
    )
    .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    assert_eq!(error_of(&response).0, "invalid_proof");
    assert_eq!(harness.issuer.call_count(), 0);
}

#[tokio::test]
async fn a_proof_with_the_wrong_header_type_is_refused() {
    let harness = harness(true);
    let (token, c_nonce) = draft13_grant(&harness.server).await;
    let key = holder_key();
    let jwt = proof_with(
        &key,
        json!({"typ": "JWT"}),
        json!({"aud": DRAFT13_ISSUER, "iat": harness.clock.now(), "nonce": c_nonce}),
    );
    let response = post_credential(&harness.server, &token, &credential_body(&jwt)).await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    assert_eq!(error_of(&response).0, "invalid_proof");
    assert_eq!(harness.issuer.call_count(), 0);
}

#[tokio::test]
async fn a_proof_for_the_wrong_audience_is_refused_including_the_final_issuer() {
    let harness = harness(true);
    let key = holder_key();
    for audience in [
        FINAL_ISSUER,
        "https://wallet.example.org/protocol/oid4vci/draft-13/",
        "https://other.example.org/protocol/oid4vci/draft-13",
        "https://wallet.example.org/protocol/oid4vci/draft-13/credential",
    ] {
        let (token, c_nonce) = draft13_grant(&harness.server).await;
        let response = post_credential(
            &harness.server,
            &token,
            &credential_body(&proof(&key, audience, &c_nonce, &harness)),
        )
        .await;
        assert_eq!(
            response.status_code(),
            StatusCode::BAD_REQUEST,
            "{audience}"
        );
        assert_eq!(error_of(&response).0, "invalid_proof", "{audience}");
    }
    assert_eq!(harness.issuer.call_count(), 0);
}

#[tokio::test]
async fn a_proof_signed_with_another_algorithm_is_refused() {
    let harness = harness(true);
    let (token, c_nonce) = draft13_grant(&harness.server).await;
    let key = holder_key();
    let jwt = proof_with(
        &key,
        json!({"alg": "ES384"}),
        json!({"aud": DRAFT13_ISSUER, "iat": harness.clock.now(), "nonce": c_nonce}),
    );
    let response = post_credential(&harness.server, &token, &credential_body(&jwt)).await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    assert_eq!(error_of(&response).0, "invalid_proof");
    assert_eq!(harness.issuer.call_count(), 0);
}

#[tokio::test]
async fn a_stale_c_nonce_is_refused() {
    let harness = harness(true);
    let (token, c_nonce) = draft13_grant(&harness.server).await;
    harness.clock.advance(121);
    let key = holder_key();
    let response = post_credential(
        &harness.server,
        &token,
        &credential_body(&proof(&key, DRAFT13_ISSUER, &c_nonce, &harness)),
    )
    .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    let (error, description) = error_of(&response);
    assert_eq!(error, "invalid_proof");
    assert!(description.contains("expired"), "{description}");
    assert_eq!(harness.issuer.call_count(), 0);
}

#[tokio::test]
async fn a_c_nonce_from_another_exchange_is_refused() {
    let harness = harness(true);
    let (_, other_nonce) = draft13_grant(&harness.server).await;
    let (token, _) = draft13_grant(&harness.server).await;
    let key = holder_key();
    let response = post_credential(
        &harness.server,
        &token,
        &credential_body(&proof(&key, DRAFT13_ISSUER, &other_nonce, &harness)),
    )
    .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    assert_eq!(error_of(&response).0, "invalid_proof");
    assert_eq!(harness.issuer.call_count(), 0);
}

#[tokio::test]
async fn a_forged_or_missing_c_nonce_is_refused() {
    let harness = harness(true);
    let key = holder_key();
    for nonce in ["forged", "9999999999.AAAA", ""] {
        let (token, _) = draft13_grant(&harness.server).await;
        let response = post_credential(
            &harness.server,
            &token,
            &credential_body(&proof(&key, DRAFT13_ISSUER, nonce, &harness)),
        )
        .await;
        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST, "{nonce}");
        assert_eq!(error_of(&response).0, "invalid_proof", "{nonce}");
    }
    assert_eq!(harness.issuer.call_count(), 0);
}

#[tokio::test]
async fn a_reused_access_token_is_refused() {
    let harness = harness(true);
    let (token, c_nonce) = draft13_grant(&harness.server).await;
    let key = holder_key();
    let body = credential_body(&proof(&key, DRAFT13_ISSUER, &c_nonce, &harness));
    assert_eq!(
        post_credential(&harness.server, &token, &body)
            .await
            .status_code(),
        StatusCode::OK
    );
    let replay = post_credential(&harness.server, &token, &body).await;
    assert_eq!(replay.status_code(), StatusCode::UNAUTHORIZED);
    assert_eq!(harness.issuer.call_count(), 1);
}

// Isolation between the profiles.

#[tokio::test]
async fn an_offer_for_one_profile_cannot_be_redeemed_through_the_other() {
    let harness = harness(true);

    let final_code = code_of(&create_offer(&harness.server, OFFERS_PATH).await);
    let crossed = harness
        .server
        .post(draft13::TOKEN_PATH)
        .form(&token_form(&final_code))
        .await;
    assert_eq!(crossed.status_code(), StatusCode::BAD_REQUEST);
    assert_eq!(error_of(&crossed).0, "invalid_grant");

    let draft_code = code_of(&create_offer(&harness.server, draft13::OFFERS_PATH).await);
    let crossed = harness
        .server
        .post(TOKEN_PATH)
        .form(&token_form(&draft_code))
        .await;
    assert_eq!(crossed.status_code(), StatusCode::BAD_REQUEST);
    assert_eq!(error_of(&crossed).0, "invalid_grant");

    // A refused cross-profile attempt spends nothing: each offer is still
    // redeemable through the profile that created it.
    assert_eq!(
        harness
            .server
            .post(TOKEN_PATH)
            .form(&token_form(&final_code))
            .await
            .status_code(),
        StatusCode::OK
    );
    assert_eq!(
        harness
            .server
            .post(draft13::TOKEN_PATH)
            .form(&token_form(&draft_code))
            .await
            .status_code(),
        StatusCode::OK
    );
}

#[tokio::test]
async fn an_access_token_for_one_profile_is_unknown_to_the_other() {
    let harness = harness(true);
    let key = holder_key();

    let final_token = final_access_token(&harness.server).await;
    let nonce: Value = harness.server.post(NONCE_PATH).await.json();
    let crossed = post_credential(
        &harness.server,
        &final_token,
        &credential_body(&proof(
            &key,
            DRAFT13_ISSUER,
            nonce["c_nonce"].as_str().expect("nonce"),
            &harness,
        )),
    )
    .await;
    assert_eq!(crossed.status_code(), StatusCode::UNAUTHORIZED);

    let (draft_token, c_nonce) = draft13_grant(&harness.server).await;
    let crossed = harness
        .server
        .post(CREDENTIAL_PATH)
        .add_header("authorization", format!("Bearer {draft_token}"))
        .json(&json!({
            "credential_configuration_id": CONFIGURATION_ID,
            "proofs": {"jwt": [proof(&key, FINAL_ISSUER, &c_nonce, &harness)]},
        }))
        .await;
    assert_eq!(crossed.status_code(), StatusCode::UNAUTHORIZED);
    assert_eq!(harness.issuer.call_count(), 0);
}

#[tokio::test]
async fn nonces_are_not_shared_between_the_profiles() {
    let harness = harness(true);
    let key = holder_key();

    // A nonce from the 1.0 nonce endpoint does not open a Draft 13 credential.
    let nonce: Value = harness.server.post(NONCE_PATH).await.json();
    let (token, _) = draft13_grant(&harness.server).await;
    let response = post_credential(
        &harness.server,
        &token,
        &credential_body(&proof(
            &key,
            DRAFT13_ISSUER,
            nonce["c_nonce"].as_str().expect("nonce"),
            &harness,
        )),
    )
    .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    assert_eq!(error_of(&response).0, "invalid_proof");

    // A Draft 13 c_nonce does not open a 1.0 credential.
    let (_, c_nonce) = draft13_grant(&harness.server).await;
    let final_token = final_access_token(&harness.server).await;
    let response = harness
        .server
        .post(CREDENTIAL_PATH)
        .add_header("authorization", format!("Bearer {final_token}"))
        .json(&json!({
            "credential_configuration_id": CONFIGURATION_ID,
            "proofs": {"jwt": [proof(&key, FINAL_ISSUER, &c_nonce, &harness)]},
        }))
        .await;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    assert_eq!(error_of(&response).0, "invalid_nonce");
    assert_eq!(harness.issuer.call_count(), 0);
}

#[tokio::test]
async fn inspect_shows_the_draft13_metadata_only_when_the_profile_is_on() {
    for (draft13, expected) in [(false, false), (true, true)] {
        let block = draft13.then_some("draft13Profile: {}");
        let config = load_config(&config_text(block)).expect("the deployment loads");
        let service = DeliveryService::with_halves(
            config,
            Arc::new(StubAuthorizer),
            Arc::new(SigningIssuer::new()) as Arc<dyn CredentialIssuer>,
            Arc::new(
                DeliveryAudit::with_writer(
                    AuditWriter::from_line_sink(Box::new(std::io::sink())),
                    b"0123456789abcdef0123456789abcdef".to_vec(),
                )
                .expect("the test audit profile is valid"),
            ),
        );
        let inspected = service.inspect().await.expect("inspection succeeds");
        assert_eq!(
            inspected.get("draft13CredentialIssuerMetadata").is_some(),
            expected
        );
        if expected {
            assert_eq!(
                inspected["draft13CredentialIssuerMetadata"]["credential_issuer"],
                DRAFT13_ISSUER
            );
        }
    }
}
