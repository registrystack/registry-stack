use std::{
    cell::RefCell,
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::{Duration, Instant},
};

use async_trait::async_trait;
use axum::{
    body::Body,
    http::{Request as HttpRequest, StatusCode},
};
use axum_test::TestServer;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::{DateTime, Utc};
use jsonwebtoken::{jwk::JwkSet, Algorithm};
use registry_platform_audit::{
    verify_jsonl_lines_with_hasher, AuditChainHasher, AuditChainProfile,
};
use registry_platform_crypto::{
    sign, KeyReadiness, LocalJwkSigner, PrivateJwk, PublicJwk, SigningAlgorithm, SigningError,
    SigningProvider,
};
use registry_platform_httputil::FetchUrlPolicy;
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig, TokenVerifier, TokenVerifierConfig};
use rusqlite::Connection;
use serde_json::{json, Value};
use tempfile::TempDir;
use tower::ServiceExt as _;
use wiremock::{
    matchers::{body_json, header, method, path, query_param},
    Mock, MockServer, ResponseTemplate,
};

use crate::{
    audit::{
        AuditAuthority, AuditDecision, AuditPhase, AuditSubject,
        AuthorityKind as AuditAuthorityKind, EvidenceAuditEvent, EvidenceAuditLog,
        ResponseProtection,
    },
    auth::{AuthenticatedContext, AuthenticationClaimsConfig, AuthenticationError, Authenticator},
    bundle::DeploymentInputs,
    config::{AssuranceProfile, ResponseFormat, MAXIMUM_HOLDER_BOUND_BATCH_SIZE},
    contracts::evidence_contract_accepts,
    local_verification::{
        prepare_local_relying_procedure, LocalRelyingProcedure, LocalRelyingProcedureInput,
        LocalResponseFormat, LOCAL_RELYING_PROCEDURE_INPUT_SCHEMA_V1,
    },
    model::{
        Evidence, EvidenceDefinitions, EvidenceRequest, EvidenceRequestBatch,
        EvidenceRequestBatchItem, EvidenceSelectorField, FlattenedJws, PublicValue,
        RequestedSelector, RequestedSubject, SdJwtVcBatchEnvelope, SelectorValue,
        UnsignedEvidenceEnvelope,
    },
    observability::{metrics_app, CORRELATION_HEADER, REQUEST_LOG_TARGET},
    problem::ProblemCode,
    runtime::{
        acquisition_budget_exhausted, EvidenceRuntime, RuntimeAuthenticator,
        RuntimeInitializationError,
    },
    server::{build_app, build_app_at_for_test, build_app_with_metrics, serve_listener_for_test},
    signing::EvidenceSigner,
    verifier::{
        verify_flattened_jws, verify_sd_jwt_vc, EvidenceVerificationPolicy,
        EvidenceVerificationPolicyDocument, ExpectedValueForm,
    },
    EVIDENCE_JWS_MEDIA_TYPE, EVIDENCE_REQUEST_BATCH_MEDIA_TYPE,
    EVIDENCE_SD_JWT_VC_BATCH_MEDIA_TYPE, EVIDENCE_SD_JWT_VC_MEDIA_TYPE,
    EVIDENCE_UNSIGNED_MEDIA_TYPE, SD_JWT_VC_BATCH_SCHEMA_V1,
};
use registry_evidence_verifier::model::{
    EvidenceRequestBatchResponse, EvidenceRequestBatchResponseItem,
};

const AUTH_PRIVATE_JWK: &str = r#"{"kty":"EC","crv":"P-256","d":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAE","x":"axfR8uEsQkf4vOblY6RA8ncDfYEt6zOg9KE5RdiYwpY","y":"T-NC4v4af5uO5-tKfA-eFivOM1drMV7Oy7ZAaDe_UfU","alg":"ES256","kid":"acceptance-auth-key"}"#;
const EVIDENCE_KEY_ID: &str = "_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo";
const EVIDENCE_PRIVATE_JWK: &str = r#"{"kty":"EC","crv":"P-256","d":"MInq88dvxx-e1-MEfmdes4I6Gt2QbsKoEmYyk2j0Oj4","x":"3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4","y":"GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU","alg":"ES256","kid":"_QkPweRjMZxmIHnz7v8tj3coTKx-90L2LRsZbkeP_Bo"}"#;
const TOKEN_ISSUER: &str = "https://identity.invalid";
const TOKEN_AUDIENCE: &str = "evidence-fixture";
const EVIDENCE_AUDIENCE: &str = "https://relying.invalid/procedure";
const AUTHORITY: &str = "statutory-caseworker-v1";
const BEARER: &str = "source-bearer-canary";
const BASIC_USER: &str = "source-user-canary";
const BASIC_PASSWORD: &str = "source-password-canary";
const PARENT_REFERENCE: &str = "synthetic-parent-reference-001";
const NON_PARENT_REFERENCE: &str = "synthetic-non-parent-reference-003";
const LOG_TOKEN_CANARY: &str = "operational-log-token-canary";
const LOG_SELECTOR_CANARY: &str = "operational-log-selector-canary";

struct AcceptanceRuntime {
    _temporary: TempDir,
    bundle_root: PathBuf,
    runtime_path: PathBuf,
    runtime: Arc<EvidenceRuntime>,
    server: MockServer,
    audit_path: PathBuf,
}

struct PreparedAcceptance {
    temporary: TempDir,
    bundle_root: PathBuf,
    runtime_path: PathBuf,
    server: MockServer,
    audit_path: PathBuf,
}

/// A prepared bundle and runtime file with no opinion about what serves the
/// configured source origin.
struct PreparedFixture {
    temporary: TempDir,
    bundle_root: PathBuf,
    runtime_path: PathBuf,
    audit_path: PathBuf,
}

struct FailOnceAfterSelfTestSigner {
    delegate: LocalJwkSigner,
    calls: AtomicUsize,
}

struct UnavailableReadinessSigner {
    delegate: LocalJwkSigner,
}

struct OversizedAfterSelfTestSigner {
    delegate: LocalJwkSigner,
    calls: AtomicUsize,
}

struct CountingAuthenticator {
    delegate: Authenticator,
    authenticate_calls: Arc<AtomicUsize>,
}

/// Start the real Evidence HTTP router over TCP for one operator-driven curl,
/// then verify the returned JWS and durable audit before completing.
///
/// This intentionally uses the deterministic acceptance source and a static
/// test JWKS. Live provider credentials are neither needed nor read here.
#[tokio::test]
#[ignore = "operator-driven local curl checkpoint"]
async fn first_curl_exercises_and_verifies_the_evidence_server() {
    let fixture = acceptance_runtime().await;
    // The documented optional unsigned curl may run before the signed one, so
    // the deterministic source accepts one or two identical lookups.
    Mock::given(method("POST"))
        .and(path("/v1/facts"))
        .and(header("accept", "application/json"))
        .and(header("authorization", format!("Bearer {BEARER}").as_str()))
        .and(body_json(json!({
            "lookup": {
                "given_name": "Amina",
                "family_name": "Diallo",
                "birth_date": "2000-01-01"
            },
            "fields": ["date_of_birth"],
            "limit": 2
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total": 1,
            "date_of_birth": "2000-01-01"
        })))
        .expect(1..=2)
        .mount(&fixture.server)
        .await;

    let request = adult_request();
    let token = access_token(Some(parent_grant_claims()));
    let state_root =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/evidence/.first-curl");
    fs::create_dir_all(&state_root).expect("first-curl state directory is created");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&state_root, fs::Permissions::from_mode(0o700))
            .expect("first-curl state directory is owner-only");
    }
    let definitions_path = state_root.join("definitions.json");
    let response_path = state_root.join("response.json");
    let unsigned_path = state_root.join("response-unsigned.json");
    for stale in [&definitions_path, &response_path, &unsigned_path] {
        match fs::remove_file(stale) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("stale first-curl output could not be removed: {error}"),
        }
    }

    let listener = tokio::net::TcpListener::bind("127.0.0.1:18080")
        .await
        .expect("first-curl listener binds on 127.0.0.1:18080");
    let address = listener
        .local_addr()
        .expect("listener address is available");
    write_secret(
        &state_root,
        "request.json",
        &serde_json::to_string_pretty(&request).expect("request serializes"),
    );
    write_secret(
        &state_root,
        "session.env",
        &format!("EVIDENCE_ACCESS_TOKEN={token}\n"),
    );

    println!(
        "Evidence first-curl server is ready at http://{address}. The ignored session.env contains only the short-lived synthetic bearer token. Use the plain curl command in products/evidence/FIRST-CURL-TEST.md."
    );

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let runtime = Arc::clone(&fixture.runtime);
    let server = tokio::spawn(async move {
        serve_listener_for_test(runtime, listener, async move {
            let _ = shutdown_rx.await;
        })
        .await
    });

    let definitions = tokio::time::timeout(Duration::from_secs(180), async {
        loop {
            if let Ok(bytes) = fs::read(&definitions_path) {
                if let Ok(definitions) = serde_json::from_slice::<EvidenceDefinitions>(&bytes) {
                    break definitions;
                }
                if let Ok(problem) = serde_json::from_slice::<Value>(&bytes) {
                    if let Some(code) = problem.get("code").and_then(Value::as_str) {
                        panic!("Evidence discovery returned the safe problem code {code}");
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("curl discovery response arrives within three minutes");
    assert_eq!(definitions.definitions.len(), 4);
    // Discovery publishes the revision an assertion for that one requirement
    // will carry, so a relying party pins per requirement and the four
    // coequal requirements do not share one deployment-wide value.
    for definition in &definitions.definitions {
        assert_eq!(
            Some(definition.configuration_revision.as_str()),
            fixture
                .runtime
                .bundle()
                .configuration_revision(&definition.requirement)
        );
    }
    let published_revisions: BTreeSet<&str> = definitions
        .definitions
        .iter()
        .map(|definition| definition.configuration_revision.as_str())
        .collect();
    assert_eq!(published_revisions.len(), 4);
    let serialized_definitions =
        serde_json::to_string(&definitions).expect("discovery response serializes");
    for prohibited in [
        "fixture-agency",
        "statutory-caseworker-v1",
        "source-a",
        "adapters/",
        "derivations/",
        "codelists/",
        "valueClaims",
        "requesterTags",
        "authorityProfiles",
        "constraints",
        "secret:",
    ] {
        assert!(!serialized_definitions.contains(prohibited));
    }

    let serialized = tokio::time::timeout(Duration::from_secs(180), async {
        loop {
            if let Ok(bytes) = fs::read(&response_path) {
                if serde_json::from_slice::<FlattenedJws>(&bytes).is_ok() {
                    break bytes;
                }
                if let Ok(problem) = serde_json::from_slice::<Value>(&bytes) {
                    if let Some(code) = problem.get("code").and_then(Value::as_str) {
                        panic!("Evidence returned the safe problem code {code}");
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("curl response arrives within three minutes");

    let evidence = verify_flattened_jws(
        &serialized,
        fixture.runtime.jwks(),
        &verification_policy(&fixture.runtime, &request, &serialized),
    )
    .expect("curl response JWS verifies against the running Evidence JWKS");
    assert_eq!(
        evidence.supported_values[0].value,
        PublicValue::Boolean(true)
    );
    assert_minimized_payload(&serialized);

    shutdown_tx
        .send(())
        .expect("first-curl server is still running");
    server
        .await
        .expect("first-curl server task joins")
        .expect("first-curl server stops cleanly");

    // The optional unsigned leg, when the operator ran it, produced its own
    // self-identifying envelope and its own pair of durable audit events.
    let unsigned_leg_ran = match fs::read(&unsigned_path) {
        Ok(bytes) => {
            let envelope: UnsignedEvidenceEnvelope = serde_json::from_slice(&bytes)
                .expect("unsigned first-curl output parses as the closed envelope");
            assert_eq!(
                envelope.evidence.request_nonce.as_deref(),
                Some(request.request_nonce.as_str())
            );
            assert!(
                verify_flattened_jws(
                    &bytes,
                    fixture.runtime.jwks(),
                    &verification_policy(&fixture.runtime, &request, &serialized),
                )
                .is_err(),
                "the strict JWS verifier must reject the unsigned envelope"
            );
            true
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => panic!("unsigned first-curl output could not be read: {error}"),
    };
    let audit = fs::read_to_string(&fixture.audit_path).expect("first-curl audit is readable");
    let expected_audit_lines = if unsigned_leg_ran { 4 } else { 2 };
    assert_eq!(audit.lines().count(), expected_audit_lines);
    assert!(!audit.contains(&request.request_nonce));
    if unsigned_leg_ran {
        println!(
            "PASS: authenticated discovery listed four safe request shapes, Evidence returned HTTP 200 in both formats, the JWS verified, the unsigned envelope was self-identifying and rejected by the JWS verifier, adult-status was true, minimization held, and all four audit events were durable."
        );
    } else {
        println!(
            "PASS: authenticated discovery listed four safe request shapes, Evidence returned HTTP 200, its JWS verified, adult-status was true, minimization held, and both audit events were durable."
        );
    }
}

#[async_trait]
impl SigningProvider for UnavailableReadinessSigner {
    fn algorithm(&self) -> SigningAlgorithm {
        self.delegate.algorithm()
    }

    fn key_id(&self) -> &str {
        self.delegate.key_id()
    }

    fn public_jwk(&self) -> PublicJwk {
        self.delegate.public_jwk()
    }

    fn readiness(&self) -> KeyReadiness {
        KeyReadiness::NotReady
    }

    async fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SigningError> {
        self.delegate.sign(payload).await
    }
}

#[async_trait]
impl RuntimeAuthenticator for CountingAuthenticator {
    async fn authenticate(
        &self,
        access_token: &str,
    ) -> Result<AuthenticatedContext, AuthenticationError> {
        self.authenticate_calls.fetch_add(1, Ordering::AcqRel);
        self.delegate.authenticate(access_token).await
    }

    async fn probe_key_source(&self) {
        self.delegate.probe_key_source().await;
    }

    async fn announce_key_source(&self) {
        self.delegate.announce_key_source().await;
    }

    async fn key_source_ready(&self) -> bool {
        true
    }
}

#[async_trait]
impl SigningProvider for FailOnceAfterSelfTestSigner {
    fn algorithm(&self) -> SigningAlgorithm {
        self.delegate.algorithm()
    }

    fn key_id(&self) -> &str {
        self.delegate.key_id()
    }

    fn public_jwk(&self) -> PublicJwk {
        self.delegate.public_jwk()
    }

    fn readiness(&self) -> KeyReadiness {
        if self.calls.load(Ordering::Acquire) == 2 {
            KeyReadiness::NotReady
        } else {
            KeyReadiness::Ready
        }
    }

    async fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SigningError> {
        match self.calls.fetch_add(1, Ordering::AcqRel) {
            0 => self.delegate.sign(payload).await,
            1 => Err(SigningError::external("synthetic unavailable signer")),
            _ => self.delegate.sign(payload).await,
        }
    }
}

#[async_trait]
impl SigningProvider for OversizedAfterSelfTestSigner {
    fn algorithm(&self) -> SigningAlgorithm {
        self.delegate.algorithm()
    }

    fn key_id(&self) -> &str {
        self.delegate.key_id()
    }

    fn public_jwk(&self) -> PublicJwk {
        self.delegate.public_jwk()
    }

    fn readiness(&self) -> KeyReadiness {
        KeyReadiness::Ready
    }

    async fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SigningError> {
        if self.calls.fetch_add(1, Ordering::AcqRel) == 0 {
            self.delegate.sign(payload).await
        } else {
            Ok(vec![0x5a; 80 * 1024])
        }
    }
}

/// A signer that refuses one nominated signature and serves every other, so a
/// test can fail a batch on a member the loop reached only after signing an
/// earlier one. Call index zero is the startup self-test.
struct FailOnNthSignatureSigner {
    delegate: LocalJwkSigner,
    calls: AtomicUsize,
    fail_at: usize,
}

#[async_trait]
impl SigningProvider for FailOnNthSignatureSigner {
    fn algorithm(&self) -> SigningAlgorithm {
        self.delegate.algorithm()
    }

    fn key_id(&self) -> &str {
        self.delegate.key_id()
    }

    fn public_jwk(&self) -> PublicJwk {
        self.delegate.public_jwk()
    }

    fn readiness(&self) -> KeyReadiness {
        KeyReadiness::Ready
    }

    async fn sign(&self, payload: &[u8]) -> Result<Vec<u8>, SigningError> {
        if self.calls.fetch_add(1, Ordering::AcqRel) == self.fail_at {
            return Err(SigningError::external("synthetic member signing failure"));
        }
        self.delegate.sign(payload).await
    }
}

#[tokio::test]
async fn real_router_serves_all_definitions_concurrently_without_crossing_boundaries() {
    let fixture = acceptance_runtime().await;
    let http = TestServer::new(build_app(Arc::clone(&fixture.runtime)));

    let health = http.get("/health").await;
    health.assert_status_ok();
    assert_eq!(health.json::<Value>(), json!({"status": "ok"}));
    let ready = http.get("/ready").await;
    ready.assert_status_ok();
    assert_eq!(ready.json::<Value>(), json!({"status": "ready"}));
    assert!(fixture
        .server
        .received_requests()
        .await
        .expect("request journal is available")
        .is_empty());
    let jwks = http.get("/.well-known/evidence/jwks.json").await;
    jwks.assert_status_ok();
    assert_eq!(jwks.header("content-type"), "application/jwk-set+json");
    assert_eq!(jwks.header("cache-control"), "public, max-age=600");
    let jwks_etag = jwks.header("etag");
    assert_eq!(
        jwks.json::<crate::model::JwksDocument>(),
        *fixture.runtime.jwks()
    );
    let not_modified = http
        .get("/.well-known/evidence/jwks.json")
        .add_header("if-none-match", jwks_etag)
        .await;
    assert_eq!(not_modified.status_code(), StatusCode::NOT_MODIFIED);
    assert_eq!(not_modified.header("cache-control"), "public, max-age=600");

    let protected_resource = http.get("/.well-known/oauth-protected-resource").await;
    protected_resource.assert_status_ok();
    assert_eq!(
        protected_resource.json::<Value>(),
        json!({
            "resource": fixture.runtime.bundle().config.service.public_origin,
            "authorization_servers": [fixture.runtime.bundle().config.authentication.issuer],
            "jwks_uri": format!(
                "{}{}",
                fixture.runtime.bundle().config.service.public_origin,
                fixture.runtime.bundle().config.signing.jwks_path
            ),
            "bearer_methods_supported": ["header"]
        })
    );
    assert_eq!(
        protected_resource.header("cache-control"),
        "public, max-age=600"
    );

    let standard_token = access_token(None);
    let parent_token = access_token(Some(parent_grant_claims()));
    let missing_credential = http.get("/v1/evidence-definitions").await;
    missing_credential.assert_status_unauthorized();
    assert_eq!(
        missing_credential.header("www-authenticate"),
        format!(
            "Bearer realm=\"registry-evidence\", resource_metadata=\"{}/.well-known/oauth-protected-resource\"",
            fixture.runtime.bundle().config.service.public_origin
        )
    );
    let standard_discovery = http
        .get("/v1/evidence-definitions")
        .add_header("authorization", format!("Bearer {standard_token}"))
        .await;
    standard_discovery.assert_status_ok();
    assert_eq!(
        standard_discovery.header("content-type"),
        "application/json"
    );
    let standard_definitions = standard_discovery.json::<EvidenceDefinitions>();
    assert_eq!(standard_definitions.definitions.len(), 3);
    for definition in &standard_definitions.definitions {
        assert_eq!(
            Some(definition.configuration_revision.as_str()),
            fixture
                .runtime
                .bundle()
                .configuration_revision(&definition.requirement)
        );
    }
    assert!(standard_definitions
        .definitions
        .iter()
        .all(|definition| !definition.requirement.contains("legal-parent")));

    let parent_discovery = http
        .get("/v1/evidence-definitions")
        .add_header("authorization", format!("Bearer {parent_token}"))
        .await;
    parent_discovery.assert_status_ok();
    let parent_definitions = parent_discovery.json::<EvidenceDefinitions>();
    assert_eq!(parent_definitions.definitions.len(), 4);
    let adult_definition = parent_definitions
        .definitions
        .iter()
        .find(|definition| definition.requirement.ends_with(":adult-status:v1"))
        .expect("authorized adult definition is discoverable");
    assert_eq!(adult_definition.handle, "adult-status");
    assert_eq!(
        adult_definition.response_formats,
        [ResponseFormat::SignedJws, ResponseFormat::UnsignedJson]
    );
    assert_eq!(adult_definition.concepts.len(), 1);
    assert_eq!(adult_definition.concepts[0].handle, "is_adult");
    assert!(adult_definition.concepts[0].required);
    assert!(adult_definition.subjects[0].selector.fields.iter().any(
        |field| matches!(field, EvidenceSelectorField::Date { name } if name == "birth_date")
    ));
    let parent_definition = parent_definitions
        .definitions
        .iter()
        .find(|definition| {
            definition
                .requirement
                .ends_with(":legal-parent-relationship:v1")
        })
        .expect("grant-backed relationship definition is discoverable");
    assert_eq!(
        parent_definition.subjects[1].selector.value_origin,
        "authenticated-grant"
    );
    let serialized_discovery =
        serde_json::to_string(&parent_definitions).expect("discovery serializes");
    for prohibited in [
        "fixture-agency",
        "statutory-caseworker-v1",
        "source-a",
        "adapters/",
        "derivations/",
        "codelists/",
        "secret:",
    ] {
        assert!(
            !serialized_discovery.contains(prohibited),
            "discovery exposed protected deployment material"
        );
    }
    assert!(fixture
        .server
        .received_requests()
        .await
        .expect("request journal is available")
        .is_empty());
    assert!(
        fs::read_to_string(&fixture.audit_path)
            .expect("audit is readable")
            .is_empty(),
        "metadata discovery must not create evidence-data audit records"
    );

    mount_success_sources(&fixture.server, false).await;
    let adult_request = adult_request();
    let residence_request = residence_request();
    let licence_request = licence_request();
    let parent_request = parent_request();

    let adult = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {standard_token}"))
        .json(&adult_request);
    let residence = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {standard_token}"))
        .json(&residence_request);
    let licence = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {standard_token}"))
        .json(&licence_request);
    let parent = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {parent_token}"))
        .json(&parent_request);
    let (adult, residence, licence, parent) = tokio::join!(adult, residence, licence, parent);

    for (response, request, expected_concept, expected_value, expected_roles) in [
        (
            adult,
            &adult_request,
            "urn:example:fixture:concept:adult-status",
            PublicValue::Boolean(true),
            vec!["subject"],
        ),
        (
            residence,
            &residence_request,
            "urn:example:fixture:concept:residence-region",
            PublicValue::String("REGION-NORTH".to_owned()),
            vec!["subject"],
        ),
        (
            licence,
            &licence_request,
            "urn:example:fixture:concept:licence-active",
            PublicValue::Boolean(true),
            vec!["subject"],
        ),
        (
            parent,
            &parent_request,
            "urn:example:fixture:concept:legal-parent-relationship-confirmed",
            PublicValue::Boolean(false),
            vec!["child", "candidate-parent"],
        ),
    ] {
        response.assert_status_ok();
        assert_eq!(response.header("content-type"), "application/jose+json");
        let jws = response.json::<FlattenedJws>();
        let serialized = serde_json::to_vec(&jws).expect("router JWS serializes");
        let evidence = verify_flattened_jws(
            &serialized,
            fixture.runtime.jwks(),
            &verification_policy(&fixture.runtime, request, &serialized),
        )
        .expect("router response verifies");
        assert_eq!(
            evidence
                .subjects
                .iter()
                .map(|subject| subject.role.as_str())
                .collect::<Vec<_>>(),
            expected_roles
        );
        assert!(evidence.supported_values.iter().any(|value| {
            value.provides_value_for == expected_concept && value.value == expected_value
        }));
        assert_minimized_payload(&serialized);
    }

    let audit = fs::read_to_string(&fixture.audit_path).expect("durable audit is readable");
    assert_eq!(audit.matches("\"phase\":\"access-attempt\"").count(), 4);
    assert_eq!(audit.matches("\"phase\":\"disclosure-release\"").count(), 4);
    for canary in privacy_canaries() {
        assert!(!audit.contains(canary));
    }
}

/// The boundary carries W3C trace context on every response while retaining a
/// separately minted operation for audit and operational logs.
#[tokio::test]
async fn trace_transport_carries_safe_response_correlation_without_replacing_operation_identity() {
    let fixture = acceptance_runtime().await;
    let http = TestServer::new(build_app(Arc::clone(&fixture.runtime)));

    let traceparent = "00-0123456789abcdef0123456789abcdef-0123456789abcdef-01";
    let health = http
        .get("/health")
        .add_header("traceparent", traceparent)
        .await;
    health.assert_status_ok();
    let first = correlation_id(&health);
    assert!(first
        .as_str()
        .expect("traceparent is text")
        .starts_with("00-0123456789abcdef0123456789abcdef-"));

    // A rejected request reports one identifier, not one per error site.
    let denied = http.get("/v1/evidence-definitions").await;
    assert_eq!(denied.status_code(), axum::http::StatusCode::UNAUTHORIZED);
    assert_eq!(
        &correlation_id(&denied)
            .as_str()
            .expect("traceparent is text")[3..35],
        denied.json::<Value>()["traceId"]
            .as_str()
            .expect("trace ID is text")
    );

    // An unrouted request correlates on the same terms.
    let unknown = http.get("/absent").await;
    assert_eq!(unknown.status_code(), axum::http::StatusCode::NOT_FOUND);
    assert_eq!(
        unknown.json::<Value>()["code"],
        ProblemCode::ResourceNotFound.code()
    );

    // Identifiers are request-scoped, never process-scoped.
    let second = http.get("/health").await;
    assert_ne!(first, correlation_id(&second));
}

/// Section 12 fixes exactly what an operational record may contain. Anything
/// outside that set is a disclosure the record has never been reviewed for, so
/// the field set is asserted whole rather than field by field.
#[test]
fn operational_logs_carry_only_the_reviewed_fields_and_disclose_no_value() {
    let emitted = capture_evidence_logs(|| async {
        let fixture = acceptance_runtime().await;
        let http = TestServer::new(build_app(Arc::clone(&fixture.runtime)));

        http.get("/health").await.assert_status_ok();

        // The body parses and its selector values are held in memory before
        // authentication rejects the request, so this exercises the disclosure
        // path rather than an early parse failure.
        let rejected = http
            .post("/v1/evidence")
            .add_header("authorization", format!("Bearer {LOG_TOKEN_CANARY}"))
            .json(&request(
                "urn:example:fixture:requirement:adult-status:v1",
                "fixture-eligibility",
                vec![requested_subject(
                    "subject",
                    "person-demographics-v1",
                    Some([
                        ("given_name", LOG_SELECTOR_CANARY),
                        ("family_name", "Diallo"),
                        ("birth_date", "2000-01-01"),
                    ]),
                )],
            ))
            .await;
        assert_eq!(
            rejected.status_code(),
            axum::http::StatusCode::UNAUTHORIZED,
            "the canary token is not a verifiable access token"
        );
    });

    let served: Vec<&Value> = emitted
        .iter()
        .filter(|record| record["target"] == json!(REQUEST_LOG_TARGET))
        .collect();
    assert_eq!(served.len(), 2, "one operational record per served request");

    for record in &served {
        let fields = record["fields"]
            .as_object()
            .expect("an operational record carries fields");
        assert_eq!(
            fields.keys().map(String::as_str).collect::<BTreeSet<_>>(),
            BTreeSet::from([
                "message",
                "route",
                "operation",
                "trace_id",
                "duration_ms",
                "status",
                "error",
                "category"
            ])
        );
        assert!(fields["duration_ms"].is_u64());
        assert!(!fields["operation"]
            .as_str()
            .expect("the operation identifier is a string")
            .is_empty());
    }

    // The route template, never the requested path, and a status category
    // rather than a code.
    assert_eq!(served[0]["fields"]["route"], json!("/health"));
    assert_eq!(served[0]["fields"]["status"], json!("success"));
    assert_eq!(served[0]["fields"]["error"], json!("none"));
    // A successful request raises no runtime failure, so it logs the fixed
    // placeholder rather than omitting the field.
    assert_eq!(served[0]["fields"]["category"], json!("none"));
    assert_eq!(served[1]["fields"]["route"], json!("/v1/evidence"));
    assert_eq!(served[1]["fields"]["status"], json!("client_error"));
    assert_eq!(
        served[1]["fields"]["error"],
        json!("auth.invalid_credential")
    );
    // The runtime's internal classification for this rejection, distinct from
    // (and narrower than) the public problem code above.
    assert_eq!(served[1]["fields"]["category"], json!("authentication"));

    // No token, selector value, purpose, or requirement identity reaches an
    // operational record this crate emits.
    let raw = serde_json::to_string(&emitted).expect("captured records serialize");
    for canary in [
        LOG_TOKEN_CANARY,
        LOG_SELECTOR_CANARY,
        "Diallo",
        "2000-01-01",
        "fixture-eligibility",
        "adult-status",
    ] {
        assert!(
            !raw.contains(canary),
            "an operational log disclosed {canary}"
        );
    }
}

/// The runtime computes a safe internal failure category for every failure;
/// the observation layer must not let the HTTP boundary discard it before a
/// served request is logged. A no-matching-record outcome and an ambiguous
/// outcome are two different unresolved classes that `runtime.rs` deliberately
/// collapses onto one category so the public contract carries no existence
/// oracle (security invariant V1-I16); this proves that collapse holds at the
/// log boundary too, not only at the `RuntimeFailure` type boundary.
#[test]
fn operational_logs_carry_the_runtime_failure_category_and_still_collapse_unresolved_classes() {
    let emitted = capture_evidence_logs(|| async {
        let fixture = acceptance_runtime().await;
        let http = TestServer::new(build_app(Arc::clone(&fixture.runtime)));
        let parent_token = access_token(Some(parent_grant_claims()));

        for response in [
            json!({"total": 0, "records": []}),
            json!({"total": 2, "records": [{}, {}]}),
        ] {
            mount_parent_source(&fixture.server, response).await;
            let failed = http
                .post("/v1/evidence")
                .add_header("authorization", format!("Bearer {parent_token}"))
                .json(&parent_request())
                .await;
            assert_eq!(
                failed.status_code(),
                axum::http::StatusCode::UNPROCESSABLE_ENTITY,
                "an unresolved record is publicly reported as unavailable evidence"
            );
            fixture.server.reset().await;
        }
    });

    let served: Vec<&Value> = emitted
        .iter()
        .filter(|record| record["target"] == json!(REQUEST_LOG_TARGET))
        .collect();
    assert_eq!(served.len(), 2, "one operational record per served request");
    for record in &served {
        assert_eq!(record["fields"]["error"], json!("evidence.unavailable"));
        assert_eq!(record["fields"]["category"], json!("evidence-unavailable"));
    }
    // A no-match failure and an ambiguous-match failure log the identical
    // category: the log record does not become a way to tell them apart.
    assert_eq!(
        served[0]["fields"]["category"],
        served[1]["fields"]["category"]
    );
}

/// Counters describe traffic. They must say how the boundary behaved without
/// naming what any request asked for, and their label set must stay bounded by
/// the route table rather than by anything a caller can send.
#[tokio::test]
async fn metrics_report_bounded_series_without_disclosing_request_content() {
    let fixture = acceptance_runtime().await;
    let (app, metrics) = build_app_with_metrics(Arc::clone(&fixture.runtime));
    let http = TestServer::new(app);

    http.get("/health").await.assert_status_ok();
    http.get("/health").await.assert_status_ok();
    let denied = http.get("/v1/evidence-definitions").await;
    assert_eq!(denied.status_code(), axum::http::StatusCode::UNAUTHORIZED);
    http.get("/absent-path-canary").await;

    let exposition = TestServer::new(metrics_app(Arc::clone(&metrics)));
    let rendered = exposition.get("/metrics").await;
    rendered.assert_status_ok();
    assert_eq!(rendered.header("content-type"), "text/plain; version=0.0.4");
    let body = rendered.text();

    assert!(body.contains(
        "evidence_http_requests_total{route=\"/health\",method=\"GET\",status=\"success\",error=\"none\"} 2\n"
    ));
    assert!(body.contains(
        "evidence_http_requests_total{route=\"/v1/evidence-definitions\",method=\"GET\",status=\"client_error\",error=\"auth.invalid_credential\"} 1\n"
    ));
    assert!(body.contains("evidence_http_request_duration_seconds_count{route=\"/health\""));

    // An unrouted request is one fixed label, never the path the caller chose.
    assert!(body.contains("route=\"unmatched\""));
    assert!(!body.contains("absent-path-canary"));
    for canary in privacy_canaries() {
        assert!(!body.contains(canary), "metrics disclosed {canary}");
    }

    // The metrics application answers for metrics only; it is not a second
    // way to reach the evidence routes.
    for path in ["/health", "/v1/evidence-definitions", "/openapi.json"] {
        assert_eq!(
            exposition.get(path).await.status_code(),
            axum::http::StatusCode::NOT_FOUND,
            "the metrics listener served {path}"
        );
    }
}

/// The metrics endpoint is opt-in deployment surface on its own socket. The
/// evidence listener must not gain a metrics route, and the two listeners must
/// share one lifecycle so shutdown leaves nothing behind.
#[tokio::test]
async fn a_configured_metrics_listener_serves_beside_the_evidence_listener() {
    let prepared = prepare_acceptance("subject-binding-secret-canary-32-bytes-minimum").await;
    let evidence_port = reserved_port();
    let metrics_port = reserved_port();
    let mut document =
        fs::read_to_string(&prepared.runtime_path).expect("runtime configuration is readable");
    replace_exact(
        &mut document,
        "port: 8080",
        &format!("port: {evidence_port}"),
        1,
    );
    document.push_str(&format!(
        "metricsListener:\n  bindHost: 127.0.0.1\n  port: {metrics_port}\n"
    ));
    // The prepared document is already read-only, as deployment requires, so
    // this variant is written before the runtime captures it.
    make_file_writable(&prepared.runtime_path);
    fs::write(&prepared.runtime_path, &document).expect("runtime configuration is rewritten");
    make_file_read_only(&prepared.runtime_path);
    let runtime = Arc::new(
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await
            .expect("the runtime initializes with a metrics listener"),
    );

    let (stop, stopped) = tokio::sync::oneshot::channel::<()>();
    let server = tokio::spawn(crate::server::serve(runtime, async move {
        let _ = stopped.await;
    }));
    let client = reqwest::Client::new();
    let evidence = format!("http://127.0.0.1:{evidence_port}");
    let telemetry = format!("http://127.0.0.1:{metrics_port}");
    await_ready(&client, &format!("{evidence}/health")).await;

    let exposition = client
        .get(format!("{telemetry}/metrics"))
        .send()
        .await
        .expect("the metrics listener answers");
    assert_eq!(exposition.status(), reqwest::StatusCode::OK);
    assert!(exposition
        .text()
        .await
        .expect("the exposition is readable")
        .contains("evidence_http_requests_total{route=\"/health\""));

    // The evidence listener gained no metrics route of its own.
    let on_evidence_listener = client
        .get(format!("{evidence}/metrics"))
        .send()
        .await
        .expect("the evidence listener answers");
    assert_eq!(
        on_evidence_listener.status(),
        reqwest::StatusCode::NOT_FOUND
    );
    assert_eq!(
        on_evidence_listener
            .json::<Value>()
            .await
            .expect("problem body")["code"],
        json!("resource.not_found")
    );

    let _ = stop.send(());
    server
        .await
        .expect("the service task joins")
        .expect("the service stops cleanly");

    // One shutdown closes both sockets.
    assert!(client
        .get(format!("{telemetry}/metrics"))
        .send()
        .await
        .is_err());
    assert!(client
        .get(format!("{evidence}/health"))
        .send()
        .await
        .is_err());
}

/// Reserve an ephemeral port and release it, so a test can name a port in
/// configuration that the operating system has just confirmed is free.
fn reserved_port() -> u16 {
    let listener =
        std::net::TcpListener::bind("127.0.0.1:0").expect("an ephemeral port is available");
    listener
        .local_addr()
        .expect("the reserved socket has an address")
        .port()
}

async fn await_ready(client: &reqwest::Client, url: &str) {
    for _ in 0..100 {
        if let Ok(response) = client.get(url).send().await {
            if response.status().is_success() {
                return;
            }
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("the evidence listener never became reachable at {url}");
}

fn correlation_id(response: &axum_test::TestResponse) -> Value {
    json!(response
        .header(CORRELATION_HEADER)
        .to_str()
        .expect("the correlation header is ASCII"))
}

/// Collect every record this crate emits while `body` runs.
///
/// The subscriber is thread-local and the request future is driven to
/// completion on this thread, so records emitted from the detached evaluation
/// task land in the same buffer.
///
/// Earlier tests serve requests with no subscriber installed, which caches the
/// request boundary's callsite as permanently uninteresting and drops the
/// global maximum level to off. A thread-local subscriber does not undo that on
/// its own, so one subscriber is installed process-wide on first use and routes
/// each record to the buffer of the thread that emitted it. Tests running
/// concurrently on other threads have no buffer and their records are dropped.
fn capture_evidence_logs<F, Fut>(body: F) -> Vec<Value>
where
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    static INSTALLED: std::sync::Once = std::sync::Once::new();
    INSTALLED.call_once(|| {
        tracing::subscriber::set_global_default(
            tracing_subscriber::fmt()
                .json()
                .with_max_level(tracing::Level::INFO)
                .with_writer(CapturedLogs)
                .finish(),
        )
        .expect("this test binary installs no other subscriber");
    });

    let buffer = Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    CAPTURED_LOGS.with(|slot| *slot.borrow_mut() = Some(Arc::clone(&buffer)));
    let executor = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("a single-threaded executor builds");
    executor.block_on(body());
    CAPTURED_LOGS.with(|slot| *slot.borrow_mut() = None);

    let raw = buffer
        .lock()
        .expect("the log buffer is not poisoned")
        .clone();
    String::from_utf8(raw)
        .expect("operational records are UTF-8")
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter(|record| {
            record["target"]
                .as_str()
                .is_some_and(|target| target.starts_with("registry_evidence"))
        })
        .collect()
}

thread_local! {
    /// The buffer `capture_evidence_logs` is filling on this thread, if any.
    static CAPTURED_LOGS: std::cell::RefCell<Option<Arc<std::sync::Mutex<Vec<u8>>>>> =
        const { std::cell::RefCell::new(None) };
}

#[derive(Clone)]
struct CapturedLogs;

impl std::io::Write for CapturedLogs {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        // A record emitted outside a capture window belongs to a test that is
        // not inspecting logs, so it is deliberately discarded rather than
        // written anywhere.
        let _ = CAPTURED_LOGS.try_with(|slot| {
            if let Some(sink) = slot.borrow().as_ref() {
                sink.lock()
                    .expect("the log buffer is not poisoned")
                    .extend_from_slice(buffer);
            }
        });
        Ok(buffer.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'writer> tracing_subscriber::fmt::MakeWriter<'writer> for CapturedLogs {
    type Writer = Self;

    fn make_writer(&'writer self) -> Self::Writer {
        self.clone()
    }
}

#[tokio::test]
async fn openapi_route_serves_the_generated_contract_without_authentication_or_source_access() {
    let fixture = acceptance_runtime().await;
    let http = TestServer::new(build_app(Arc::clone(&fixture.runtime)));

    let document = http.get("/openapi.json").await;
    document.assert_status_ok();
    assert_eq!(document.header("content-type"), "application/json");
    assert_eq!(document.header("cache-control"), "no-store");

    // The served bytes are the committed release artifact, not a second
    // hand-maintained description of the same routes.
    let generated = crate::contracts::documents().expect("generated contracts build");
    assert_eq!(document.text(), generated[crate::contracts::OPENAPI_FILE]);

    // The document is static public material: it names no definition, reveals
    // no deployment revision, and reaches no source.
    let served = document.json::<Value>();
    assert_eq!(served["openapi"], json!("3.1.0"));
    assert!(served["paths"]["/openapi.json"]["get"].is_object());
    assert!(!document
        .text()
        .contains(&fixture.runtime.bundle().revision().to_string()));
    assert!(fixture
        .server
        .received_requests()
        .await
        .expect("request journal is available")
        .is_empty());

    // Only GET is in the contract; anything else joins the closed unknown-route
    // problem response.
    let rejected = http.post("/openapi.json").await;
    assert_eq!(
        rejected.status_code(),
        ProblemCode::ResourceNotFound.status()
    );
    assert_eq!(
        rejected.json::<Value>()["code"],
        json!(ProblemCode::ResourceNotFound.code())
    );

    let audit = fs::read_to_string(&fixture.audit_path).expect("durable audit is readable");
    assert!(audit.is_empty());
}

#[tokio::test]
async fn provider_discovery_description_serves_exact_bytes_without_authentication_or_side_effects()
{
    let fixture = acceptance_runtime().await;
    let http = TestServer::new(build_app(Arc::clone(&fixture.runtime)));
    let expected = fixture
        .runtime
        .bundle()
        .discovery_description()
        .expect("acceptance bundle publishes discovery");
    assert_eq!(
        expected,
        fs::read(fixture.bundle_root.join("catalog.jsonld"))
            .expect("the packaged description is readable"),
        "the route must serve the packaged bytes, not a runtime reconstruction"
    );

    let response = http.get("/catalog.jsonld").await;
    response.assert_status_ok();
    assert_eq!(
        response.header("content-type"),
        registry_discovery_profile::MEDIA_TYPE
    );
    assert_eq!(response.header("cache-control"), "no-store");
    assert_eq!(response.as_bytes(), expected);
    registry_discovery_profile::parse_description(response.as_bytes())
        .expect("served bytes satisfy the shared profile");

    let rejected_head = http
        .method(axum::http::Method::HEAD, "/catalog.jsonld")
        .await;
    assert_eq!(
        rejected_head.status_code(),
        ProblemCode::ResourceNotFound.status()
    );
    assert!(rejected_head.as_bytes().is_empty());
    assert!(fixture
        .server
        .received_requests()
        .await
        .expect("request journal is available")
        .is_empty());
    assert!(
        fs::read_to_string(&fixture.audit_path)
            .expect("audit is readable")
            .is_empty(),
        "provider discovery must not create Evidence audit records"
    );
}

#[tokio::test]
async fn discovery_requires_authentication_and_returns_no_unentitled_definitions() {
    let fixture = acceptance_runtime().await;
    let http = TestServer::new(build_app(Arc::clone(&fixture.runtime)));

    let missing = http.get("/v1/evidence-definitions").await;
    assert_eq!(missing.status_code(), axum::http::StatusCode::UNAUTHORIZED);
    assert_eq!(
        missing.json::<Value>()["code"],
        json!("auth.invalid_credential")
    );

    let filtered = http
        .get("/v1/evidence-definitions?requirement=caller-selected")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .await;
    assert_eq!(filtered.status_code(), axum::http::StatusCode::BAD_REQUEST);
    assert_eq!(
        filtered.json::<Value>()["code"],
        json!("evidence.invalid_request")
    );

    let body_response = build_app(Arc::clone(&fixture.runtime))
        .oneshot(
            HttpRequest::builder()
                .uri("/v1/evidence-definitions")
                .header("authorization", format!("Bearer {}", access_token(None)))
                .body(Body::from("{}"))
                .expect("discovery request is valid"),
        )
        .await
        .expect("discovery router responds");
    assert_eq!(body_response.status(), axum::http::StatusCode::BAD_REQUEST);

    let now = Utc::now().timestamp();
    let unentitled = signed_access_token(json!({
        "iss": TOKEN_ISSUER,
        "aud": TOKEN_AUDIENCE,
        "sub": "unentitled-discovery-principal",
        "iat": now - 1,
        "exp": now + 3600,
        "evidence_tags": ["unentitled-agency"],
        "evidence_audience": EVIDENCE_AUDIENCE
    }));
    let response = http
        .get("/v1/evidence-definitions")
        .add_header("authorization", format!("Bearer {unentitled}"))
        .await;
    response.assert_status_ok();
    assert!(response
        .json::<EvidenceDefinitions>()
        .definitions
        .is_empty());
    assert!(fixture
        .server
        .received_requests()
        .await
        .expect("request journal is available")
        .is_empty());
    assert!(
        fs::read_to_string(&fixture.audit_path)
            .expect("audit is readable")
            .is_empty(),
        "denied discovery must not create evidence-data audit records"
    );
}

#[tokio::test]
async fn discovery_omits_an_authority_shape_that_the_runtime_would_deny_as_ambiguous() {
    let prepared = prepare_acceptance("subject-binding-secret-canary-32-bytes-minimum").await;
    make_writable(&prepared.bundle_root);
    let configuration_path = prepared.bundle_root.join("evidence.yaml");
    let mut configuration =
        fs::read_to_string(&configuration_path).expect("acceptance configuration is readable");
    replace_exact(
        &mut configuration,
        "authorityProfiles:\n  statutory-caseworker-v1:",
        r#"authorityProfiles:
  overlapping-caseworker-v1:
    kind: statutory
    requesterTags: [fixture-agency]
    grants:
      - requirement: urn:example:fixture:requirement:adult-status:v1
        purpose: fixture-eligibility
        audienceFrom: authenticated-requester
        subjects:
          - {role: subject, selectorProfile: person-demographics-v1, valueOrigin: request}
  statutory-caseworker-v1:"#,
        1,
    );
    fs::write(&configuration_path, configuration).expect("test configuration is rewritten");
    make_read_only(&prepared.bundle_root);
    let runtime = Arc::new(
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await
            .expect("overlapping runtime initializes for fail-closed request decisions"),
    );
    let http = TestServer::new(build_app(Arc::clone(&runtime)));

    let response = http
        .get("/v1/evidence-definitions")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .await;
    response.assert_status_ok();
    let definitions = response.json::<EvidenceDefinitions>();
    assert_eq!(definitions.definitions.len(), 2);
    assert!(definitions
        .definitions
        .iter()
        .all(|definition| !definition.requirement.ends_with(":adult-status:v1")));
    assert!(prepared
        .server
        .received_requests()
        .await
        .expect("request journal is available")
        .is_empty());
    assert!(fs::read_to_string(&prepared.audit_path)
        .expect("audit is readable")
        .is_empty());

    let refused = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .json(&serde_json::to_value(adult_request()).expect("request serializes"))
        .await;
    assert_eq!(refused.status_code(), axum::http::StatusCode::FORBIDDEN);
    assert_eq!(refused.json::<Value>()["code"], json!("evidence.denied"));
    assert!(prepared
        .server
        .received_requests()
        .await
        .expect("request journal is available")
        .is_empty());
    let audit = fs::read_to_string(&prepared.audit_path).expect("audit is readable");
    assert_eq!(audit.matches("\"decision\":\"not-authorized\"").count(), 1);
    assert_eq!(
        audit
            .matches("\"safeErrorCategory\":\"not-authorized\"")
            .count(),
        1
    );
}

#[tokio::test]
async fn discovery_refuses_duplicate_handles_visible_to_one_requester() {
    let prepared = prepare_acceptance("subject-binding-secret-canary-32-bytes-minimum").await;
    make_writable(&prepared.bundle_root);
    let configuration_path = prepared.bundle_root.join("evidence.yaml");
    let mut configuration =
        fs::read_to_string(&configuration_path).expect("acceptance configuration is readable");
    replace_exact(
        &mut configuration,
        "    purposes: [fixture-eligibility]",
        "    purposes: [fixture-eligibility, fixture-appeal]",
        1,
    );
    replace_exact(
        &mut configuration,
        r#"      - requirement: urn:example:fixture:requirement:adult-status:v1
        purpose: fixture-eligibility
        audienceFrom: authenticated-requester
        responseFormats: [signed-jws, unsigned-json]
        subjects:
          - {role: subject, selectorProfile: person-demographics-v1, valueOrigin: request}"#,
        r#"      - requirement: urn:example:fixture:requirement:adult-status:v1
        purpose: fixture-eligibility
        audienceFrom: authenticated-requester
        responseFormats: [signed-jws, unsigned-json]
        subjects:
          - {role: subject, selectorProfile: person-demographics-v1, valueOrigin: request}
      - requirement: urn:example:fixture:requirement:adult-status:v1
        purpose: fixture-appeal
        audienceFrom: authenticated-requester
        responseFormats: [signed-jws]
        subjects:
          - {role: subject, selectorProfile: person-demographics-v1, valueOrigin: request}"#,
        1,
    );
    fs::write(&configuration_path, configuration).expect("test configuration is rewritten");
    make_read_only(&prepared.bundle_root);
    let runtime = Arc::new(
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await
            .expect("two purpose-specific grants initialize"),
    );
    let http = TestServer::new(build_app(Arc::clone(&runtime)));

    let response = http
        .get("/v1/evidence-definitions")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .await;
    assert_eq!(response.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        response.json::<Value>()["code"],
        json!("service.unavailable")
    );
    assert!(prepared
        .server
        .received_requests()
        .await
        .expect("request journal is available")
        .is_empty());
    assert!(fs::read_to_string(&prepared.audit_path)
        .expect("audit is readable")
        .is_empty());
}

#[tokio::test]
async fn discovery_uses_the_bounded_per_principal_request_budget() {
    let prepared = prepare_acceptance("subject-binding-secret-canary-32-bytes-minimum").await;
    make_writable(&prepared.bundle_root);
    let configuration_path = prepared.bundle_root.join("evidence.yaml");
    let mut configuration =
        fs::read_to_string(&configuration_path).expect("acceptance configuration is readable");
    replace_exact(
        &mut configuration,
        "rateLimits: {requestsPerPrincipalPerMinute: 60, burstPerPrincipal: 10, failedSelectorAttemptsPerPrincipalAuthorityPerMinute: 10}",
        "rateLimits: {requestsPerPrincipalPerMinute: 1, burstPerPrincipal: 1, failedSelectorAttemptsPerPrincipalAuthorityPerMinute: 10}",
        1,
    );
    fs::write(&configuration_path, configuration).expect("test configuration is rewritten");
    make_read_only(&prepared.bundle_root);
    let runtime = Arc::new(
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await
            .expect("rate-limited discovery runtime initializes"),
    );
    let http = TestServer::new(build_app(runtime));
    let token = access_token(None);

    http.get("/v1/evidence-definitions")
        .add_header("authorization", format!("Bearer {token}"))
        .await
        .assert_status_ok();
    let limited = http
        .get("/v1/evidence-definitions")
        .add_header("authorization", format!("Bearer {token}"))
        .await;
    assert_eq!(
        limited.status_code(),
        axum::http::StatusCode::TOO_MANY_REQUESTS
    );
    assert_eq!(
        limited.json::<Value>()["code"],
        json!("evidence.rate_limited")
    );
    assert_eq!(limited.header("retry-after"), "1");
    assert!(prepared
        .server
        .received_requests()
        .await
        .expect("request journal is available")
        .is_empty());
}

/// The vocabulary carries no default: absence means audience-scoped. A
/// definition for an audience-scoped requirement must omit the key entirely
/// rather than serialize an explicit `audience-scoped` value, so a definition
/// written before binding modes existed keeps exactly the response it already
/// served.
#[tokio::test]
async fn discovery_omits_the_subject_binding_mode_for_an_audience_scoped_requirement() {
    let fixture = acceptance_runtime().await;
    let http = TestServer::new(build_app(Arc::clone(&fixture.runtime)));

    let response = http
        .get("/v1/evidence-definitions")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .await;
    response.assert_status_ok();
    let definitions = response.json::<Value>()["definitions"]
        .as_array()
        .expect("the definitions project")
        .clone();
    assert!(!definitions.is_empty());
    for definition in &definitions {
        assert!(
            definition.get("subjectBindingMode").is_none(),
            "an audience-scoped definition must not carry the key at all"
        );
    }
}

/// A relying party reading a definition for a holder-bound requirement must
/// see the mode stated explicitly, so it knows the assertions this
/// requirement issues bind to a presented holder key rather than an audience.
#[tokio::test]
async fn discovery_declares_the_holder_bound_mode_for_a_holder_bound_requirement() {
    let prepared = holder_bound_acceptance().await;
    let runtime = runtime_for(&prepared).await;
    let http = TestServer::new(build_app(Arc::clone(&runtime)));

    let response = http
        .get("/v1/evidence-definitions")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .await;
    response.assert_status_ok();
    let definitions = response.json::<Value>()["definitions"]
        .as_array()
        .expect("the definitions project")
        .clone();
    let adult_status = definitions
        .iter()
        .find(|definition| {
            definition["requirement"]
                .as_str()
                .expect("the requirement projects")
                .ends_with(":adult-status:v1")
        })
        .expect("the holder-bound requirement is discoverable");
    assert_eq!(adult_status["subjectBindingMode"], json!("holder-bound"));
}

#[tokio::test]
async fn serving_runtime_never_reloads_merges_or_falls_back_after_bundle_capture() {
    let fixture = acceptance_runtime().await;
    let captured_revision = fixture.runtime.bundle().revision().to_owned();
    let captured_runtime_revision = fixture.runtime.runtime_revision().to_owned();
    let adult_requirement = adult_request().requirement;
    let captured_requirement_revision = fixture
        .runtime
        .bundle()
        .configuration_revision(&adult_requirement)
        .expect("the captured bundle configures the requirement")
        .to_owned();
    let captured_config = fixture
        .runtime
        .bundle()
        .artifact("evidence.yaml")
        .expect("captured configuration exists")
        .to_vec();
    let adapter_path = "adapters/adult-status-source.rhai";
    let captured_adapter = fixture
        .runtime
        .bundle()
        .artifact(adapter_path)
        .expect("captured adapter exists")
        .to_vec();

    make_writable(&fixture.bundle_root);
    make_file_writable(&fixture.runtime_path);
    fs::write(
        &fixture.runtime_path,
        b"this: is-not-the-captured-runtime\n",
    )
    .expect("replace on-disk runtime configuration");
    fs::write(
        fixture.bundle_root.join("evidence.yaml"),
        b"this: is-not-the-captured-revision\n",
    )
    .expect("replace on-disk configuration");
    fs::remove_file(fixture.bundle_root.join(adapter_path)).expect("remove on-disk adapter");
    fs::write(
        fixture.bundle_root.join("adapters/fallback.rhai"),
        b"fn extract(_) { no_match() }\n",
    )
    .expect("add an unreferenced fallback-like artifact");

    assert_eq!(fixture.runtime.bundle().revision(), captured_revision);
    assert_eq!(
        fixture
            .runtime
            .bundle()
            .configuration_revision(&adult_requirement),
        Some(captured_requirement_revision.as_str())
    );
    assert_eq!(
        fixture.runtime.runtime_revision(),
        captured_runtime_revision
    );
    assert_eq!(
        fixture.runtime.bundle().artifact("evidence.yaml"),
        Some(captured_config.as_slice())
    );
    assert_eq!(
        fixture.runtime.bundle().artifact(adapter_path),
        Some(captured_adapter.as_slice())
    );
    assert!(fixture
        .runtime
        .bundle()
        .artifact("adapters/fallback.rhai")
        .is_none());

    mount_adult_source(&fixture.server, None).await;
    let request = adult_request();
    let jws = fixture
        .runtime
        .evaluate(
            "operation-captured-bundle-revision",
            &access_token(None),
            &request,
        )
        .await
        .expect("captured runtime still evaluates with captured artifacts");
    let serialized = serde_json::to_vec(&jws).expect("JWS serializes");
    let evidence = verify_flattened_jws(
        &serialized,
        fixture.runtime.jwks(),
        &verification_policy(&fixture.runtime, &request, &serialized),
    )
    .expect("captured-revision assertion verifies");
    assert_eq!(
        evidence.configuration_revision,
        captured_requirement_revision
    );
    assert_eq!(
        evidence.supported_values[0].value,
        PublicValue::Boolean(true)
    );
}

#[tokio::test]
async fn local_runtime_prepares_a_bearer_free_procedure_and_keeps_the_real_security_path() {
    let prepared = prepare_acceptance("subject-binding-secret-canary-32-bytes-minimum").await;
    let local_issuer = prepared.server.uri();
    let auth_private = PrivateJwk::parse(AUTH_PRIVATE_JWK).expect("auth test key parses");
    Mock::given(method("GET"))
        .and(path("/.well-known/jwks.json"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"keys": [auth_private.public()]})),
        )
        .mount(&prepared.server)
        .await;
    make_writable(&prepared.bundle_root);
    let configuration_path = prepared.bundle_root.join("evidence.yaml");
    let strict =
        fs::read_to_string(&configuration_path).expect("acceptance configuration is readable");
    let mut local = strict
        .replace(
            "assuranceProfile: evidence-grade",
            "assuranceProfile: local",
        )
        .lines()
        .filter(|line| !line.trim_start().starts_with("fixtures:"))
        .collect::<Vec<_>>()
        .join("\n");
    replace_exact(
        &mut local,
        "issuer: https://identity.invalid",
        &format!("issuer: {local_issuer}"),
        1,
    );
    replace_exact(
        &mut local,
        "jwksUri: https://identity.invalid/.well-known/jwks.json",
        &format!("jwksUri: {local_issuer}/.well-known/jwks.json"),
        1,
    );
    fs::write(&configuration_path, local).expect("local configuration is written");
    let fixture_directory = prepared.bundle_root.join("fixtures");
    for entry in fs::read_dir(&fixture_directory).expect("fixture directory reads") {
        fs::remove_file(entry.expect("fixture entry reads").path())
            .expect("unreferenced fixture is removed");
    }
    make_read_only(&prepared.bundle_root);

    // Close independent expectations before the source exists and before a
    // response or audit record can exist. Preparation deliberately has no
    // bearer and must not fetch the configured authentication JWKS.
    let request = adult_request();
    let deployment = DeploymentInputs::load(&prepared.runtime_path)
        .expect("the immutable local deployment reloads");
    let input = LocalRelyingProcedureInput {
        schema: LOCAL_RELYING_PROCEDURE_INPUT_SCHEMA_V1.to_owned(),
        response_format: LocalResponseFormat::SignedJws,
        requirement: request.requirement.clone(),
        purpose: request.purpose.clone(),
        audience: EVIDENCE_AUDIENCE.to_owned(),
        subjects: request.subjects.clone(),
    };
    let procedure = prepare_local_relying_procedure(&deployment, &input)
        .await
        .expect("trusted local procedure closes without a bearer");
    assert!(
        !prepared.audit_path.exists(),
        "procedure preparation never opens audit storage"
    );
    let preparation_requests = prepared
        .server
        .received_requests()
        .await
        .expect("request journal is available");
    assert!(
        preparation_requests.is_empty(),
        "procedure preparation reaches neither authentication nor source HTTP"
    );

    let mut wrong_subject_input = input.clone();
    wrong_subject_input.subjects[0]
        .selector
        .values
        .as_mut()
        .expect("adult selectors are request-owned")
        .insert(
            "family_name".to_owned(),
            SelectorValue::String("Different".to_owned()),
        );
    let wrong_subject_procedure =
        prepare_local_relying_procedure(&deployment, &wrong_subject_input)
            .await
            .expect("a different request-origin subject creates a different binding");

    let runtime = Arc::new(
        EvidenceRuntime::initialize(&prepared.runtime_path)
            .await
            .expect("local runtime initializes without an authenticator override"),
    );
    assert_eq!(
        runtime.bundle().config.assurance_profile,
        AssuranceProfile::Local
    );
    assert!(runtime.bundle().fixtures.is_empty());

    let token = access_token_for_issuer(&local_issuer, "requester-principal-canary", None);
    let http = TestServer::new(build_app(Arc::clone(&runtime)));
    let definitions_response = http
        .get("/v1/evidence-definitions")
        .add_header("authorization", format!("Bearer {token}"))
        .await;
    definitions_response.assert_status_ok();
    let definitions = definitions_response.json::<EvidenceDefinitions>();
    assert_eq!(definitions.assurance_profile, AssuranceProfile::Local);

    mount_adult_source(&prepared.server, None).await;
    let response = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {token}"))
        .json(&request)
        .await;
    response.assert_status_ok();
    assert_eq!(response.header("content-type"), "application/jose+json");
    let jws = response.json::<FlattenedJws>();
    let serialized = serde_json::to_vec(&jws).expect("JWS serializes");
    let policy = local_procedure_policy(&procedure, &request.request_nonce, Utc::now());
    let verified = verify_flattened_jws(&serialized, &procedure.trusted_jwks, &policy)
        .expect("the response strictly verifies against the prepared procedure");
    assert_eq!(
        verified.request_nonce.as_deref(),
        Some(request.request_nonce.as_str())
    );
    assert_eq!(
        verified.supported_values[0].value,
        PublicValue::Boolean(true)
    );
    assert_eq!(
        serde_json::to_value(&procedure.trusted_jwks).expect("procedure JWKS serializes"),
        serde_json::to_value(runtime.jwks()).expect("runtime JWKS serializes"),
        "the procedure pins the exact public signing JWKS"
    );

    let wrong_nonce = URL_SAFE_NO_PAD.encode([0x22; 32]);
    let wrong_nonce_policy = local_procedure_policy(&procedure, &wrong_nonce, Utc::now());
    assert!(
        verify_flattened_jws(&serialized, &procedure.trusted_jwks, &wrong_nonce_policy).is_err(),
        "a response cannot verify against another retained request nonce"
    );
    let wrong_subject_policy =
        local_procedure_policy(&wrong_subject_procedure, &request.request_nonce, Utc::now());
    assert!(
        verify_flattened_jws(
            &serialized,
            &wrong_subject_procedure.trusted_jwks,
            &wrong_subject_policy,
        )
        .is_err(),
        "a response cannot verify against another subject binding"
    );

    let mut wrong_revision = local_procedure_policy_document(&procedure, &request.request_nonce);
    wrong_revision.configuration_revision = "sha256:wrong-bundle".to_owned();
    let wrong_revision = wrong_revision
        .try_into_policy(Utc::now())
        .expect("changed revision remains a bounded policy");
    assert!(
        verify_flattened_jws(&serialized, &procedure.trusted_jwks, &wrong_revision).is_err(),
        "a response cannot verify against another configuration revision"
    );

    let mut wrong_assurance = local_procedure_policy_document(&procedure, &request.request_nonce);
    wrong_assurance.expected_assurance_profile = AssuranceProfile::Production;
    let wrong_assurance = wrong_assurance
        .try_into_policy(Utc::now())
        .expect("changed assurance remains a bounded policy");
    assert!(
        verify_flattened_jws(&serialized, &procedure.trusted_jwks, &wrong_assurance).is_err(),
        "a response cannot verify as production evidence"
    );

    let mut tampered_response = serde_json::to_value(&jws).expect("flattened response serializes");
    tampered_response["signature"] = json!("A".repeat(86));
    assert!(
        verify_flattened_jws(
            &serde_json::to_vec(&tampered_response).expect("tampered response serializes"),
            &procedure.trusted_jwks,
            &policy,
        )
        .is_err(),
        "response tampering fails closed"
    );

    let expired_at = DateTime::parse_from_rfc3339(&verified.valid_until)
        .expect("validUntil parses")
        .with_timezone(&Utc)
        + chrono::Duration::seconds(
            i64::try_from(runtime.bundle().config.signing.verifier_clock_skew_seconds)
                .expect("clock skew fits i64")
                + 1,
        );
    let expired_policy = local_procedure_policy(&procedure, &request.request_nonce, expired_at);
    assert!(
        verify_flattened_jws(&serialized, &procedure.trusted_jwks, &expired_policy).is_err(),
        "an expired response fails strict portable verification"
    );

    let evidence = verify_flattened_jws(
        &serialized,
        runtime.jwks(),
        &verification_policy(&runtime, &request, &serialized),
    )
    .expect("local assertion verifies under an explicit local expectation");
    assert_eq!(evidence.assurance_profile, AssuranceProfile::Local);

    let events = fs::read_to_string(&prepared.audit_path).expect("audit reads");
    let events = events
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("audit event parses"))
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 2);
    assert!(events
        .iter()
        .all(|event| event["record"]["assuranceProfile"] == json!("local")));
}

fn local_procedure_policy_document(
    procedure: &LocalRelyingProcedure,
    request_nonce: &str,
) -> EvidenceVerificationPolicyDocument {
    EvidenceVerificationPolicyDocument {
        expected_assurance_profile: procedure.expected_assurance_profile,
        issued_by: procedure.issued_by.clone(),
        provided_by: procedure.provided_by.clone(),
        requirement: procedure.requirement.clone(),
        evidence_type: procedure.evidence_type.clone(),
        purpose: procedure.purpose.clone(),
        audience: procedure.audience.clone(),
        configuration_revision: procedure.configuration_revision.clone(),
        request_nonce: request_nonce.to_owned(),
        expected_subjects: procedure.expected_subjects.clone(),
        expected_outputs: procedure.expected_outputs.clone(),
        revoked_key_ids: procedure.revoked_key_ids.clone(),
        maximum_assertion_lifetime_seconds: procedure.maximum_assertion_lifetime_seconds,
        clock_skew_seconds: procedure.clock_skew_seconds,
    }
}

fn local_procedure_policy(
    procedure: &LocalRelyingProcedure,
    request_nonce: &str,
    now: DateTime<Utc>,
) -> EvidenceVerificationPolicy {
    local_procedure_policy_document(procedure, request_nonce)
        .try_into_policy(now)
        .expect("the prepared local procedure states bounded policy inputs")
}

#[tokio::test]
async fn admitted_evaluation_survives_client_disconnect_and_keeps_audit_chain_usable() {
    let fixture = acceptance_runtime().await;
    mount_adult_source(&fixture.server, Some(Duration::from_millis(750))).await;

    let request = adult_request();
    let client_token = access_token(None);
    let body = serde_json::to_vec(&request).expect("request serializes");
    let app = build_app(Arc::clone(&fixture.runtime));
    let client_bound = tokio::spawn(async move {
        app.oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/v1/evidence")
                .header("authorization", format!("Bearer {client_token}"))
                .header("content-type", "application/json")
                .body(Body::from(body))
                .expect("HTTP request builds"),
        )
        .await
    });

    wait_for_source_request_count(&fixture.server, 1).await;
    client_bound.abort();
    assert!(
        client_bound
            .await
            .expect_err("client-bound handler is cancelled")
            .is_cancelled(),
        "the regression must exercise handler cancellation"
    );

    let audit = wait_for_audit_counts(&fixture.audit_path, 1, 1).await;
    assert_eq!(audit.matches("\"phase\":\"access-attempt\"").count(), 1);
    assert_eq!(audit.matches("\"phase\":\"disclosure-release\"").count(), 1);
    wait_for_runtime_ready(&fixture.runtime).await;

    fixture.server.reset().await;
    mount_adult_source(&fixture.server, None).await;
    fixture
        .runtime
        .evaluate(
            "operation-after-client-disconnect",
            &access_token(None),
            &adult_request(),
        )
        .await
        .expect("a later evaluation can append to the same audit chain");
    let audit = wait_for_audit_counts(&fixture.audit_path, 2, 2).await;
    assert_eq!(audit.matches("\"phase\":\"access-attempt\"").count(), 2);
    assert_eq!(audit.matches("\"phase\":\"disclosure-release\"").count(), 2);
    assert!(fixture.runtime.ready().await);
}

#[tokio::test]
async fn graceful_shutdown_waits_for_admitted_evaluation_and_terminal_audit() {
    let fixture = acceptance_runtime().await;
    mount_adult_source(&fixture.server, Some(Duration::from_millis(750))).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test listener binds");
    let address = listener
        .local_addr()
        .expect("listener address is available");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let runtime = Arc::clone(&fixture.runtime);
    let serving = tokio::spawn(async move {
        crate::server::serve_listener_for_test(runtime, listener, async move {
            let _ = shutdown_rx.await;
        })
        .await
    });
    tokio::task::yield_now().await;

    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("test client builds");
    let request = adult_request();
    let token = access_token(None);
    let response = tokio::spawn(async move {
        client
            .post(format!("http://{address}/v1/evidence"))
            .bearer_auth(token)
            .json(&request)
            .send()
            .await
            .expect("request completes")
    });
    wait_for_source_request_count(&fixture.server, 1).await;
    shutdown_tx
        .send(())
        .expect("server still observes shutdown signal");
    assert!(
        !serving.is_finished(),
        "shutdown cannot finish while protected evaluation is active"
    );

    let response = response.await.expect("request task completes");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    tokio::time::timeout(Duration::from_secs(3), serving)
        .await
        .expect("server drains before timeout")
        .expect("server task does not panic")
        .expect("server exits cleanly");
    let audit = wait_for_audit_counts(&fixture.audit_path, 1, 1).await;
    assert_eq!(audit.matches("\"phase\":\"access-attempt\"").count(), 1);
    assert_eq!(audit.matches("\"phase\":\"disclosure-release\"").count(), 1);
}

#[tokio::test]
async fn graceful_shutdown_waits_for_admitted_request_batch_and_terminal_audit() {
    let fixture = acceptance_runtime().await;
    mount_adult_source_expecting(&fixture.server, Some(Duration::from_millis(500)), 2).await;
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("test listener binds");
    let address = listener
        .local_addr()
        .expect("listener address is available");
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let runtime = Arc::clone(&fixture.runtime);
    let serving = tokio::spawn(async move {
        crate::server::serve_listener_for_test(runtime, listener, async move {
            let _ = shutdown_rx.await;
        })
        .await
    });
    tokio::task::yield_now().await;

    let client = reqwest::Client::builder()
        .no_proxy()
        .build()
        .expect("test client builds");
    let token = access_token(None);
    let response = tokio::spawn(async move {
        client
            .post(format!("http://{address}/v1/evidence/batch"))
            .bearer_auth(token)
            .header("accept", EVIDENCE_REQUEST_BATCH_MEDIA_TYPE)
            .json(&adult_request_batch(2))
            .send()
            .await
            .expect("request batch completes")
    });
    wait_for_source_request_count(&fixture.server, 1).await;
    shutdown_tx
        .send(())
        .expect("server still observes shutdown signal");
    assert!(
        !serving.is_finished(),
        "shutdown cannot finish while a protected request batch is active"
    );

    let response = response.await.expect("request task completes");
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    tokio::time::timeout(Duration::from_secs(4), serving)
        .await
        .expect("server drains before timeout")
        .expect("server task does not panic")
        .expect("server exits cleanly");
    let audit = wait_for_audit_counts(&fixture.audit_path, 2, 1).await;
    assert_eq!(audit.matches("\"phase\":\"access-attempt\"").count(), 2);
    assert_eq!(audit.matches("\"phase\":\"disclosure-release\"").count(), 1);
}

#[tokio::test]
async fn weak_subject_binding_key_fails_initialization_before_source_access() {
    let prepared = prepare_acceptance("0123456789012345678901234567890").await;
    let result =
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await;
    let error = match result {
        Ok(_) => panic!("a 31-byte subject-binding key must be rejected"),
        Err(error) => error,
    };
    assert!(
        matches!(error, RuntimeInitializationError::Secrets),
        "weak binding key failed at the wrong boundary: {error:?}"
    );
    assert!(
        prepared
            .server
            .received_requests()
            .await
            .expect("request journal is available")
            .is_empty(),
        "initialization cannot contact an evidence source"
    );
}

#[tokio::test]
async fn readiness_fails_for_missing_credentials_tampered_audit_and_unready_signing() {
    let prepared = prepare_acceptance("subject-binding-secret-canary-32-bytes-minimum").await;
    let runtime =
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await
            .expect("runtime initializes");
    fs::remove_file(prepared.temporary.path().join("secrets/source-a-token"))
        .expect("source credential is removed");
    assert!(
        !runtime.ready().await,
        "missing source credentials deny readiness"
    );

    let prepared = prepare_acceptance("subject-binding-secret-canary-32-bytes-minimum").await;
    let runtime =
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await
            .expect("runtime initializes");
    fs::write(&prepared.audit_path, b"{}\n").expect("audit is tampered");
    assert!(
        !runtime.ready().await,
        "invalid audit chain denies readiness"
    );

    let prepared = prepare_acceptance("subject-binding-secret-canary-32-bytes-minimum").await;
    let mut runtime =
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await
            .expect("runtime initializes");
    let private = PrivateJwk::parse(EVIDENCE_PRIVATE_JWK).expect("test signing key parses");
    let provider: Arc<dyn SigningProvider> = Arc::new(UnavailableReadinessSigner {
        delegate: LocalJwkSigner::new(private).expect("test signer builds"),
    });
    let signer = EvidenceSigner::initialize(provider, EVIDENCE_KEY_ID)
        .await
        .expect("provider self-test succeeds independently of readiness posture");
    runtime.replace_signer_for_test(signer);
    assert!(
        !runtime.ready().await,
        "unready signing provider denies readiness"
    );
}

/// Readiness asks the access-token issuer for its key set and does not let the
/// answer decide readiness.
///
/// The issuer is not this deployment's to fix, and every replica shares it. A
/// readiness check that failed on it would take the whole deployment out of
/// rotation at once, for a cause removing it from rotation cannot address, and
/// would do so while the verifier was still accepting tokens signed by keys
/// already in hand. The probe stays because the log line it produces is worth
/// having; readiness stays local because the traffic decision is.
#[tokio::test]
async fn readiness_reports_an_unretrievable_issuer_key_set_without_denying_readiness() {
    let private = PrivateJwk::parse(AUTH_PRIVATE_JWK).expect("auth test key parses");
    let issuer = MockServer::start().await;
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"keys": [private.public()]})))
        .mount(&issuer)
        .await;

    let prepared = prepare_acceptance("subject-binding-secret-canary-32-bytes-minimum").await;
    let reachable = EvidenceRuntime::initialize_with_authenticator(
        &prepared.runtime_path,
        fetching_authenticator(&format!("{}/jwks", issuer.uri())),
    )
    .await
    .expect("runtime initializes");
    assert!(
        reachable.ready().await,
        "a retrievable issuer key set is ready"
    );

    // Port 1 on the loopback interface refuses: the shape of a private CA the
    // service does not trust or an issuer that is down, where the address is
    // configured and nothing answers on it.
    let prepared = prepare_acceptance("subject-binding-secret-canary-32-bytes-minimum").await;
    let unreachable = EvidenceRuntime::initialize_with_authenticator(
        &prepared.runtime_path,
        fetching_authenticator("http://127.0.0.1:1/jwks"),
    )
    .await
    .expect("runtime initializes");
    assert!(
        unreachable.ready().await,
        "an unretrievable issuer key set is reported, not made a traffic decision"
    );
    // The probe answered, which is what the report is made from, and answering
    // did not disturb the local readiness verdict on a second check either.
    assert!(
        unreachable.ready().await,
        "a repeated check under a suppressed probe holds the same verdict"
    );
}

#[tokio::test]
async fn access_audit_failure_blocks_credentials_and_source_access() {
    let fixture = acceptance_runtime().await;
    fs::write(&fixture.audit_path, b"{}\n").expect("audit tamper writes");

    let error = fixture
        .runtime
        .evaluate(
            "operation-access-audit-failure",
            &access_token(None),
            &adult_request(),
        )
        .await
        .expect_err("an unverifiable access audit must fail closed");
    assert_eq!(error.problem(), ProblemCode::ServiceUnavailable);
    assert!(
        fixture
            .server
            .received_requests()
            .await
            .expect("request journal is available")
            .is_empty(),
        "source credentials and data requests remain untouched"
    );
}

#[tokio::test]
async fn authorization_refusal_is_minimally_audited() {
    let prepared = prepare_acceptance("subject-binding-secret-canary-32-bytes-minimum").await;
    let runtime = Arc::new(
        EvidenceRuntime::initialize_with_authenticator(
            &prepared.runtime_path,
            authenticator_with_actor_claim("evidence_actor"),
        )
        .await
        .expect("runtime initializes with an actor claim"),
    );
    let http = TestServer::new(build_app(Arc::clone(&runtime)));
    let principal = "refused-requester-principal-canary";
    let actor = "refused-actor-canary";
    let mut request = adult_request();
    request.purpose = "refused-purpose-canary".to_owned();
    let response = http
        .post("/v1/evidence")
        .add_header(
            "authorization",
            format!(
                "Bearer {}",
                access_token_for(principal, Some(json!({"evidence_actor": actor})))
            ),
        )
        .json(&serde_json::to_value(&request).expect("request serializes"))
        .await;

    assert_eq!(response.status_code(), axum::http::StatusCode::FORBIDDEN);
    assert_eq!(response.json::<Value>()["code"], json!("evidence.denied"));
    assert!(prepared
        .server
        .received_requests()
        .await
        .expect("request journal is available")
        .is_empty());

    let audit = fs::read_to_string(&prepared.audit_path).expect("audit is readable");
    let mut lines = audit.lines();
    let event =
        serde_json::from_str::<Value>(lines.next().expect("one authorization refusal is durable"))
            .expect("audit line is JSON");
    assert!(lines.next().is_none(), "only one refusal event is durable");
    let record = event["record"]
        .as_object()
        .expect("the refusal record is an object");
    assert_eq!(
        record.keys().map(String::as_str).collect::<BTreeSet<_>>(),
        BTreeSet::from([
            "actorPseudonym",
            "assuranceProfile",
            "bundleRevision",
            "decision",
            "durationMilliseconds",
            "eventId",
            "occurredAt",
            "operation",
            "phase",
            "requesterPseudonym",
            "safeErrorCategory",
            "schema",
        ])
    );
    assert_eq!(
        record["schema"],
        json!("registry.evidence.audit.authorization-refusal/v1")
    );
    assert_eq!(record["phase"], json!("denial"));
    assert_eq!(record["decision"], json!("not-authorized"));
    assert_eq!(record["safeErrorCategory"], json!("not-authorized"));
    assert!(record["requesterPseudonym"].is_string());
    assert!(record["actorPseudonym"].is_string());
    for protected in [
        principal,
        actor,
        request.requirement.as_str(),
        request.purpose.as_str(),
        request.subjects[0].selector.profile.as_str(),
        "Amina",
        "Diallo",
        "2000-01-01",
        AUTHORITY,
        EVIDENCE_AUDIENCE,
        "signed-jws",
    ] {
        assert!(
            !audit.contains(protected),
            "the refusal event must not retain protected request or authority material"
        );
    }
}

#[tokio::test]
async fn authorization_refusal_requester_pseudonym_stays_scoped() {
    let fixture = acceptance_runtime().await;
    let principal = "scoped-refusal-principal-canary";
    let token = access_token_for(principal, None);
    let http = TestServer::new(build_app(Arc::clone(&fixture.runtime)));
    for purpose in [
        "refused-purpose-one",
        "refused-purpose-one",
        "refused-purpose-two",
    ] {
        let mut request = adult_request();
        request.purpose = purpose.to_owned();
        let response = http
            .post("/v1/evidence")
            .add_header("authorization", format!("Bearer {token}"))
            .json(&serde_json::to_value(request).expect("request serializes"))
            .await;
        assert_eq!(response.status_code(), axum::http::StatusCode::FORBIDDEN);
    }

    assert!(fixture
        .server
        .received_requests()
        .await
        .expect("request journal is available")
        .is_empty());
    let audit = fs::read_to_string(&fixture.audit_path).expect("audit is readable");
    let pseudonyms = audit
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("audit line is JSON"))
        .map(|event| {
            event["record"]["requesterPseudonym"]
                .as_str()
                .expect("requester pseudonym is text")
                .to_owned()
        })
        .collect::<Vec<_>>();
    assert_eq!(pseudonyms.len(), 3);
    assert_eq!(pseudonyms[0], pseudonyms[1]);
    assert_ne!(pseudonyms[0], pseudonyms[2]);
    for protected in [principal, "refused-purpose-one", "refused-purpose-two"] {
        assert!(!audit.contains(protected));
    }
}

#[tokio::test]
async fn authorization_refusal_audit_failure_returns_service_unavailable() {
    let fixture = acceptance_runtime().await;
    fs::write(&fixture.audit_path, b"{}\n").expect("audit tamper writes");
    let mut request = adult_request();
    request.purpose = "refused-purpose-canary".to_owned();
    let http = TestServer::new(build_app(Arc::clone(&fixture.runtime)));
    let response = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .json(&serde_json::to_value(request).expect("request serializes"))
        .await;

    assert_eq!(
        response.status_code(),
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(
        response.json::<Value>()["code"],
        json!("service.unavailable")
    );
    assert!(fixture
        .server
        .received_requests()
        .await
        .expect("request journal is available")
        .is_empty());
}

#[tokio::test]
async fn invalid_selector_does_not_create_an_authorization_refusal() {
    let fixture = acceptance_runtime().await;
    let error = fixture
        .runtime
        .evaluate(
            "operation-invalid-selector-no-audit",
            &access_token(Some(parent_grant_claims())),
            &parent_request_with_candidate_values(),
        )
        .await
        .expect_err("caller substitution remains an invalid selector");

    assert_eq!(error.problem(), ProblemCode::InvalidSelector);
    assert!(fixture
        .server
        .received_requests()
        .await
        .expect("request journal is available")
        .is_empty());
    assert!(
        fs::read_to_string(&fixture.audit_path)
            .expect("audit is readable")
            .is_empty(),
        "invalid selectors must not fabricate authorization refusals"
    );
}

#[tokio::test]
async fn missing_principal_never_falls_back_to_client_id_or_azp() {
    let fixture = acceptance_runtime().await;
    let now = Utc::now().timestamp();
    let token = signed_access_token(json!({
        "iss": TOKEN_ISSUER,
        "aud": TOKEN_AUDIENCE,
        "client_id": "fallback-client-canary",
        "azp": "fallback-authorized-party-canary",
        "iat": now - 1,
        "exp": now + 3600,
        "evidence_tags": ["fixture-agency"],
        "evidence_audience": EVIDENCE_AUDIENCE
    }));
    let error = fixture
        .runtime
        .evaluate("operation-missing-principal", &token, &adult_request())
        .await
        .expect_err("a token without the configured principal claim is denied");
    assert_eq!(error.problem(), ProblemCode::AuthenticationFailed);
    assert!(
        fixture
            .server
            .received_requests()
            .await
            .expect("request journal is available")
            .is_empty(),
        "authentication failure cannot acquire source credentials"
    );
    let audit = fs::read_to_string(&fixture.audit_path).expect("audit is readable");
    assert!(audit.is_empty(), "authentication failures are not audited");
    assert!(!audit.contains("fallback-client-canary"));
    assert!(!audit.contains("fallback-authorized-party-canary"));
}

/// A confirmation claim binds the token to a sender-provided proof this
/// profile does not validate. Accepting it as an ordinary bearer would
/// silently discard the constraint the authorization server issued it under,
/// so the only safe outcome is denial.
#[tokio::test]
async fn sender_constrained_tokens_are_denied_rather_than_downgraded() {
    for confirmation in [
        json!({"jkt": "sender-constraint-canary"}),
        json!({"x5t#S256": "sender-constraint-canary"}),
        json!({"jwk": {"kty": "OKP", "crv": "Ed25519", "x": "sender-constraint-canary"}}),
    ] {
        let fixture = acceptance_runtime().await;
        let token = access_token(Some(json!({"cnf": confirmation})));
        let error = fixture
            .runtime
            .evaluate("operation-sender-constrained", &token, &adult_request())
            .await
            .expect_err("a confirmation-bound token is denied");
        assert_eq!(error.problem(), ProblemCode::AuthenticationFailed);
        assert!(
            fixture
                .server
                .received_requests()
                .await
                .expect("request journal is available")
                .is_empty(),
            "a sender-constrained token cannot acquire source credentials"
        );
        let audit = fs::read_to_string(&fixture.audit_path).expect("audit is readable");
        assert!(!audit.contains("sender-constraint-canary"));
    }
}

#[tokio::test]
async fn disclosure_audit_failure_prevents_signed_response_release() {
    let fixture = acceptance_runtime().await;
    mount_adult_source(&fixture.server, Some(Duration::from_millis(500))).await;
    let runtime = Arc::clone(&fixture.runtime);
    let token = access_token(None);
    let request = adult_request();
    let evaluation = tokio::spawn(async move {
        runtime
            .evaluate("operation-disclosure-audit-failure", &token, &request)
            .await
    });

    wait_for_source_request_count(&fixture.server, 1).await;
    fs::OpenOptions::new()
        .append(true)
        .open(&fixture.audit_path)
        .and_then(|mut file| file.write_all(b"{}\n"))
        .expect("audit tamper writes after access acceptance");
    let error = evaluation
        .await
        .expect("evaluation task completes")
        .expect_err("release audit failure cannot return a signed response");
    assert_eq!(error.problem(), ProblemCode::ServiceUnavailable);

    let audit = fs::read_to_string(&fixture.audit_path).expect("audit is readable");
    assert_eq!(audit.matches("\"phase\":\"access-attempt\"").count(), 1);
    assert_eq!(audit.matches("\"phase\":\"disclosure-release\"").count(), 0);
    assert!(
        !audit.contains("date_of_birth") && !audit.contains("2000-01-01"),
        "audit failure diagnostics cannot retain source or disclosed values"
    );
}

#[tokio::test]
async fn signing_failure_is_transient_audited_and_never_releases_unsigned_evidence() {
    let prepared = prepare_acceptance("subject-binding-secret-canary-32-bytes-minimum").await;
    let mut runtime =
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await
            .expect("runtime initializes");
    let private = PrivateJwk::parse(EVIDENCE_PRIVATE_JWK).expect("test signing key parses");
    let delegate = LocalJwkSigner::new(private).expect("local signer builds");
    let provider = Arc::new(FailOnceAfterSelfTestSigner {
        delegate,
        calls: AtomicUsize::new(0),
    });
    let signing_provider: Arc<dyn SigningProvider> = provider.clone();
    let failing_signer = EvidenceSigner::initialize(signing_provider, EVIDENCE_KEY_ID)
        .await
        .expect("signer passes its startup self-test");
    runtime.replace_signer_for_test(failing_signer);
    mount_adult_source_expecting(&prepared.server, None, 2).await;

    let error = runtime
        .evaluate(
            "operation-signing-failure",
            &access_token(None),
            &adult_request(),
        )
        .await
        .expect_err("signing failure cannot produce any success representation");
    assert_eq!(error.problem(), ProblemCode::ServiceUnavailable);
    assert_eq!(provider.readiness(), KeyReadiness::NotReady);
    assert!(
        runtime.ready().await,
        "readiness retries a failed provider so load-balanced replicas can recover"
    );
    assert_eq!(provider.readiness(), KeyReadiness::Ready);

    runtime
        .evaluate(
            "operation-signing-recovered",
            &access_token(None),
            &adult_request(),
        )
        .await
        .expect("a later signed request retries the provider and recovers");
    assert!(runtime.ready().await);

    let audit = fs::read_to_string(&prepared.audit_path).expect("audit is readable");
    assert_eq!(audit.matches("\"phase\":\"access-attempt\"").count(), 2);
    assert_eq!(audit.matches("\"decision\":\"signing-failure\"").count(), 1);
    assert_eq!(audit.matches("\"phase\":\"disclosure-release\"").count(), 1);
    for canary in privacy_canaries() {
        assert!(!audit.contains(canary));
    }
}

#[tokio::test]
async fn configured_jwks_path_is_mechanically_the_served_route() {
    let fixture = acceptance_runtime().await;
    let configured_path = fixture.runtime.bundle().config.signing.jwks_path.clone();
    let http = TestServer::new(build_app(Arc::clone(&fixture.runtime)));
    let response = http.get(&configured_path).await;
    response.assert_status_ok();
    assert_eq!(response.header("content-type"), "application/jwk-set+json");
    let keys = response.json::<crate::model::JwksDocument>();
    assert_eq!(&keys, fixture.runtime.jwks());
}

/// The declared existence-disclosure mode is an enforced invariant, not an
/// inert field: every enabled requirement declares the one closed collapse
/// mode, and the runtime's unresolved outcomes for that mode share one public
/// problem shape whether the record was absent, ambiguous, or uniquely found
/// with inconsistent derivation inputs.
#[tokio::test]
async fn declared_existence_disclosure_mode_governs_the_public_collapse() {
    let fixture = acceptance_runtime().await;
    for requirement in &fixture.runtime.bundle().config.requirements {
        assert_eq!(
            requirement.existence_disclosure,
            crate::config::ExistenceDisclosure::CollapseUnresolved,
            "{}",
            requirement.id
        );
    }

    mount_parent_source(
        &fixture.server,
        json!({"total": 1, "records": [{
            "returned_child_reference": "synthetic-other-child-record",
            "parent_references": ["synthetic-parent-reference-001"],
            "reference_namespace": "urn:example:fixture:person-reference",
            "relationship_set_contract": "urn:example:fixture:legal-parent-set:v1",
            "relationship_set_complete": true
        }]}),
    )
    .await;
    let mismatch = fixture
        .runtime
        .evaluate(
            "operation-existence-derivation-mismatch",
            &access_token(Some(parent_grant_claims())),
            &parent_request(),
        )
        .await
        .expect_err("a returned-child mismatch is not signed evidence");
    assert_eq!(mismatch.problem(), ProblemCode::EvidenceNotAvailable);

    fixture.server.reset().await;
    mount_parent_source(&fixture.server, json!({"total": 0, "records": []})).await;
    let unknown = fixture
        .runtime
        .evaluate(
            "operation-existence-unknown-record",
            &access_token(Some(parent_grant_claims())),
            &parent_request(),
        )
        .await
        .expect_err("an unknown record is not signed evidence");

    // A uniquely found record with inconsistent derivation inputs is publicly
    // indistinguishable from no record at all.
    assert_eq!(mismatch.problem(), unknown.problem());
    let trace = registry_platform_httpsec::TraceId::parse("0123456789abcdef0123456789abcdef")
        .expect("trace parses");
    assert_eq!(
        serde_json::to_value(mismatch.problem().body(trace.clone())).expect("problem serializes"),
        serde_json::to_value(unknown.problem().body(trace)).expect("problem serializes"),
    );
}

#[tokio::test]
async fn request_nonce_is_strict_and_never_reaches_source_or_audit() {
    let fixture = acceptance_runtime().await;
    let http = TestServer::new(build_app(Arc::clone(&fixture.runtime)));
    let token = access_token(None);

    // Missing, empty, short, long, padded, wrong-alphabet, oversized, and
    // noncanonical final-symbol nonces fail as malformed requests before
    // authorization, credential acquisition, or source access.
    let base = serde_json::to_value(adult_request()).expect("request serializes");
    let mut variants = Vec::new();
    let mut missing = base.clone();
    missing
        .as_object_mut()
        .expect("request is an object")
        .remove("requestNonce");
    variants.push(missing);
    for nonce in [
        String::new(),
        "A".repeat(42),
        "A".repeat(44),
        format!("{}=", "A".repeat(42)),
        format!("{}+", "A".repeat(42)),
        format!("{}B", "A".repeat(42)),
        "A".repeat(4096),
    ] {
        let mut variant = base.clone();
        variant["requestNonce"] = json!(nonce);
        variants.push(variant);
    }
    for variant in variants {
        let response = http
            .post("/v1/evidence")
            .add_header("authorization", format!("Bearer {token}"))
            .json(&variant)
            .await;
        assert_eq!(response.status_code(), axum::http::StatusCode::BAD_REQUEST);
        assert_eq!(
            response.json::<Value>()["code"],
            json!("evidence.invalid_request")
        );
    }
    // A duplicate requestNonce member fails strict JSON parsing.
    let duplicate = build_app(Arc::clone(&fixture.runtime))
        .oneshot(
            HttpRequest::builder()
                .method("POST")
                .uri("/v1/evidence")
                .header("authorization", format!("Bearer {token}"))
                .header("content-type", "application/json")
                .body(Body::from(format!(
                    r#"{{"requestNonce":"{0}","requestNonce":"{0}","requirement":"urn:example:fixture:requirement:adult-status:v1","purpose":"fixture-eligibility","subjects":[{{"role":"subject","selector":{{"profile":"person-demographics-v1","values":{{"given_name":"Amina","family_name":"Diallo","birth_date":"2000-01-01"}}}}}}]}}"#,
                    "A".repeat(43)
                )))
                .expect("duplicate-nonce request builds"),
        )
        .await
        .expect("router responds");
    assert_eq!(duplicate.status(), axum::http::StatusCode::BAD_REQUEST);
    assert!(
        fixture
            .server
            .received_requests()
            .await
            .expect("request journal is available")
            .is_empty(),
        "invalid nonces must fail before credential acquisition or source access"
    );
    assert!(
        fs::read_to_string(&fixture.audit_path)
            .expect("audit is readable")
            .is_empty(),
        "invalid nonces must not fabricate audit events"
    );

    // A unique canary nonce is echoed exactly into the signed payload and
    // reaches nothing else: not the source request, not native audit.
    mount_adult_source(&fixture.server, None).await;
    let request = adult_request();
    let nonce = request.request_nonce.clone();
    let response = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {token}"))
        .json(&request)
        .await;
    response.assert_status_ok();
    let jws = response.json::<FlattenedJws>();
    let payload = URL_SAFE_NO_PAD
        .decode(&jws.payload)
        .expect("payload decodes");
    let evidence: Evidence = serde_json::from_slice(&payload).expect("payload parses");
    assert_eq!(
        evidence.request_nonce.as_deref(),
        Some(nonce.as_str()),
        "exact nonce echo"
    );

    let audit = wait_for_audit_counts(&fixture.audit_path, 1, 1).await;
    assert!(
        !audit.contains(&nonce),
        "the request nonce must never be recorded in native audit"
    );
    for received in fixture
        .server
        .received_requests()
        .await
        .expect("request journal is available")
    {
        assert!(!received.url.as_str().contains(&nonce));
        assert!(!String::from_utf8_lossy(&received.body).contains(&nonce));
        for header_name in received.headers.keys() {
            let value = received.headers[header_name].to_str().unwrap_or_default();
            assert!(!value.contains(&nonce));
        }
    }
}

#[tokio::test]
async fn request_batch_bounds_unique_nonces_and_every_item_before_source_access() {
    let fixture = acceptance_runtime().await;
    let http = TestServer::new(build_app(Arc::clone(&fixture.runtime)));
    let token = access_token(None);

    let mut duplicate = adult_request_batch(2);
    duplicate.items[1].request_nonce = duplicate.items[0].request_nonce.clone();
    let mut invalid_later_item = adult_request_batch(2);
    invalid_later_item.items[1].subjects[0]
        .selector
        .values
        .as_mut()
        .expect("request selector values exist")
        .insert(
            "caller_extra".to_owned(),
            SelectorValue::String("must-not-reach-source".to_owned()),
        );

    for (request, expected_code) in [
        (adult_request_batch(0), "evidence.invalid_request"),
        (adult_request_batch(17), "evidence.invalid_request"),
        (duplicate, "evidence.invalid_request"),
        (invalid_later_item, "request.selector_invalid"),
    ] {
        let response = http
            .post("/v1/evidence/batch")
            .add_header("authorization", format!("Bearer {token}"))
            .add_header("accept", EVIDENCE_REQUEST_BATCH_MEDIA_TYPE)
            .json(&request)
            .await;
        assert_eq!(response.status_code(), axum::http::StatusCode::BAD_REQUEST);
        assert_eq!(response.json::<Value>()["code"], expected_code);
    }
    let mut unauthorized = adult_request_batch(2);
    unauthorized.purpose = "fixture-routing".to_owned();
    let refused = http
        .post("/v1/evidence/batch")
        .add_header("authorization", format!("Bearer {token}"))
        .add_header("accept", EVIDENCE_REQUEST_BATCH_MEDIA_TYPE)
        .json(&unauthorized)
        .await;
    assert_eq!(refused.status_code(), axum::http::StatusCode::FORBIDDEN);
    assert!(fixture
        .server
        .received_requests()
        .await
        .expect("source journal is available")
        .is_empty());
}

#[tokio::test]
async fn request_batch_later_authorization_refusal_precedes_missing_source_credential_resolution() {
    let server = MockServer::start().await;
    let prepared = prepare_fixture(
        "subject-binding-secret-canary-32-bytes-minimum",
        &server.uri(),
        &FixtureCeilings::deployment_defaults(),
    );
    let runtime = Arc::new(
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await
            .expect("runtime initializes before its source credential is removed"),
    );
    let source_credential = prepared.temporary.path().join("secrets/source-a-token");
    fs::remove_file(&source_credential).expect("source credential canary is removed");
    assert!(!source_credential.exists());

    let mut batch = adult_request_batch(2);
    batch.items[1].subjects[0] = requested_subject(
        "subject",
        "residence-record-v1",
        Some([("record_reference", "synthetic-residence-record-001")]),
    );
    let http = TestServer::new(build_app(runtime));
    let response = http
        .post("/v1/evidence/batch")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .add_header("accept", EVIDENCE_REQUEST_BATCH_MEDIA_TYPE)
        .json(&batch)
        .await;

    assert_eq!(response.status_code(), StatusCode::FORBIDDEN);
    assert_eq!(response.json::<Value>()["code"], json!("evidence.denied"));
    assert!(server
        .received_requests()
        .await
        .expect("source journal is available")
        .is_empty());
    let audit = fs::read_to_string(&prepared.audit_path).expect("audit is readable");
    assert_eq!(audit.lines().count(), 1);
    let refusal: Value = serde_json::from_str(
        audit
            .lines()
            .next()
            .expect("authorization refusal is durable"),
    )
    .expect("authorization refusal parses");
    assert_eq!(
        refusal["record"]["schema"],
        json!("registry.evidence.audit.authorization-refusal/v1")
    );
    assert_eq!(refusal["record"]["decision"], json!("not-authorized"));
    assert!(!audit.contains("access-attempt"));
    assert!(!audit.contains("terminal-failure"));
    assert!(!audit.contains("disclosure-release"));
}

#[tokio::test]
async fn request_batch_accept_negotiation_is_exact_and_precedes_source_access() {
    let fixture = acceptance_runtime().await;
    let http = TestServer::new(build_app(Arc::clone(&fixture.runtime)));
    let token = access_token(None);

    let missing = http
        .post("/v1/evidence/batch")
        .add_header("authorization", format!("Bearer {token}"))
        .json(&adult_request_batch(1))
        .await;
    assert_eq!(missing.status_code(), StatusCode::NOT_ACCEPTABLE);
    assert_eq!(missing.json::<Value>()["code"], "format.unsupported");
    assert_eq!(missing.header("vary"), "Accept");

    for invalid in [
        "*/*",
        EVIDENCE_JWS_MEDIA_TYPE,
        EVIDENCE_SD_JWT_VC_BATCH_MEDIA_TYPE,
        "application/vnd.registrystack.evidence.request-batch+json; charset=utf-8",
        "application/vnd.registrystack.evidence.request-batch+json;q=1",
        "application/vnd.registrystack.evidence.request-batch+json, application/jose+json",
        "application/json",
    ] {
        let response = http
            .post("/v1/evidence/batch")
            .add_header("authorization", format!("Bearer {token}"))
            .add_header("accept", invalid)
            .json(&adult_request_batch(1))
            .await;
        assert_eq!(
            response.status_code(),
            StatusCode::NOT_ACCEPTABLE,
            "{invalid}"
        );
        assert_eq!(response.json::<Value>()["code"], "format.unsupported");
        assert_eq!(response.header("vary"), "Accept");
    }

    assert!(fixture
        .server
        .received_requests()
        .await
        .expect("source journal is available")
        .is_empty());
}

#[tokio::test]
async fn request_batch_authenticates_once_and_atomically_charges_the_complete_item_count() {
    let server = MockServer::start().await;
    let mut ceilings = FixtureCeilings::deployment_defaults();
    ceilings.requests_per_principal_per_minute = 3;
    ceilings.burst_per_principal = 3;
    let prepared = prepare_fixture(
        "subject-binding-secret-canary-32-bytes-minimum",
        &server.uri(),
        &ceilings,
    );
    let authenticate_calls = Arc::new(AtomicUsize::new(0));
    let counting_authenticator: Arc<dyn RuntimeAuthenticator> = Arc::new(CountingAuthenticator {
        delegate: authenticator(),
        authenticate_calls: Arc::clone(&authenticate_calls),
    });
    let runtime = EvidenceRuntime::initialize_with_runtime_authenticator(
        &prepared.runtime_path,
        counting_authenticator,
    )
    .await
    .expect("runtime with a three-token principal bucket initializes");
    let mut two_items = adult_request_batch(2);
    two_items.purpose = "fixture-routing".to_owned();

    let first = runtime
        .evaluate_request_batch(
            "operation-request-batch-rate-first",
            &access_token(None),
            &two_items,
        )
        .await
        .expect_err("authorization refusal follows the complete two-token admission");
    assert_eq!(first.problem(), ProblemCode::NotAuthorized);
    assert_eq!(authenticate_calls.load(Ordering::Acquire), 1);

    let rejected = runtime
        .evaluate_request_batch(
            "operation-request-batch-rate-atomic-refusal",
            &access_token(None),
            &two_items,
        )
        .await
        .expect_err("two remaining tokens are required atomically");
    assert_eq!(rejected.problem(), ProblemCode::RateLimited);
    assert_eq!(authenticate_calls.load(Ordering::Acquire), 2);

    let mut one_item = adult_request_batch(1);
    one_item.purpose = "fixture-routing".to_owned();
    let last_token = runtime
        .evaluate_request_batch(
            "operation-request-batch-rate-last-token",
            &access_token(None),
            &one_item,
        )
        .await
        .expect_err("the failed weighted admission consumed no partial token");
    assert_eq!(last_token.problem(), ProblemCode::NotAuthorized);
    assert_eq!(authenticate_calls.load(Ordering::Acquire), 3);
    assert!(server
        .received_requests()
        .await
        .expect("source journal is available")
        .is_empty());
}

#[tokio::test]
async fn request_batch_sequential_fallback_serves_all_four_coequal_definitions() {
    let fixture = acceptance_runtime().await;
    let cases = [
        ("adult", adult_request(), access_token(None)),
        ("residence", residence_request(), access_token(None)),
        ("licence", licence_request(), access_token(None)),
        (
            "relationship",
            parent_request(),
            access_token(Some(parent_grant_claims())),
        ),
    ];

    for (name, request, token) in cases {
        match name {
            "adult" => mount_adult_source_expecting(&fixture.server, None, 2).await,
            "residence" => mount_residence_source_expecting(&fixture.server, 2).await,
            "licence" => mount_licence_source_expecting(&fixture.server, 2).await,
            "relationship" => {
                mount_parent_source_expecting(
                    &fixture.server,
                    parent_source_response(vec![PARENT_REFERENCE]),
                    2,
                )
                .await;
            }
            _ => unreachable!("closed acceptance definition"),
        }
        let batch = request_batch_from_request(&request, 2);
        let released = fixture
            .runtime
            .evaluate_request_batch(
                &format!("operation-request-batch-definition-{name}"),
                &token,
                &batch,
            )
            .await
            .unwrap_or_else(|error| panic!("{name} request batch evaluates: {error:?}"));
        let envelope: EvidenceRequestBatchResponse =
            serde_json::from_slice(released.bytes()).expect("request-batch response parses");
        assert_eq!(envelope.items.len(), 2, "{name}");
        let evidence = envelope
            .items
            .iter()
            .enumerate()
            .map(|(index, item)| match item {
                EvidenceRequestBatchResponseItem::Evidence { evidence } => {
                    let evidence = decode_evidence(evidence);
                    assert_eq!(
                        evidence.request_nonce.as_deref(),
                        Some(batch.items[index].request_nonce.as_str()),
                        "{name}/{index}"
                    );
                    evidence
                }
                EvidenceRequestBatchResponseItem::EvidenceNotAvailable => {
                    panic!("{name}/{index} is available")
                }
            })
            .collect::<Vec<_>>();
        assert_ne!(evidence[0].id, evidence[1].id, "{name}");
        assert_eq!(
            fixture
                .server
                .received_requests()
                .await
                .expect("source journal is available")
                .len(),
            2,
            "{name} executes one sequential source call per item"
        );
        fixture.server.reset().await;
    }
}

#[tokio::test]
async fn request_batch_source_neutral_fixture_matches_sequential_and_optimized_strategies() {
    let mut batch = adult_request_batch(3);
    set_batch_adult_given_name(&mut batch, 1, "Binta");
    set_batch_adult_given_name(&mut batch, 2, "Cara");

    let sequential_server = MockServer::start().await;
    let sequential_prepared = prepare_fixture(
        "subject-binding-secret-canary-32-bytes-minimum",
        &sequential_server.uri(),
        &FixtureCeilings::deployment_defaults(),
    );
    let sequential_runtime = EvidenceRuntime::initialize_with_authenticator(
        &sequential_prepared.runtime_path,
        authenticator(),
    )
    .await
    .expect("sequential runtime initializes");
    mount_named_adult_source(
        &sequential_server,
        "Amina",
        json!({"total": 1, "date_of_birth": "2000-01-01"}),
    )
    .await;
    mount_named_adult_source(&sequential_server, "Binta", json!({"total": 0})).await;
    mount_named_adult_source(
        &sequential_server,
        "Cara",
        json!({"total": 1, "date_of_birth": "2001-01-01"}),
    )
    .await;
    let sequential = sequential_runtime
        .evaluate_request_batch(
            "operation-request-batch-source-sequential",
            &access_token(None),
            &batch,
        )
        .await
        .expect("sequential request batch evaluates");
    let sequential: EvidenceRequestBatchResponse =
        serde_json::from_slice(sequential.bytes()).expect("sequential response parses");

    let optimized_server = MockServer::start().await;
    let optimized_origin = optimized_server.uri();
    let optimized_prepared = prepare_fixture_with_mutation(
        "subject-binding-secret-canary-32-bytes-minimum",
        &optimized_origin,
        &FixtureCeilings::deployment_defaults(),
        configure_optimized_adult_source_batch,
    );
    enable_source_batch_acquisition(&optimized_prepared.runtime_path);
    let optimized_runtime = EvidenceRuntime::initialize_with_authenticator(
        &optimized_prepared.runtime_path,
        authenticator(),
    )
    .await
    .expect("optimized runtime initializes");
    Mock::given(method("POST"))
        .and(path("/v1/facts"))
        .and(body_json(json!({
            "requests": [
                {
                    "slot": 0,
                    "lookup": {"given_name": "Amina", "family_name": "Diallo", "birth_date": "2000-01-01"},
                    "fields": ["date_of_birth"],
                    "limit": 2
                },
                {
                    "slot": 1,
                    "lookup": {"given_name": "Binta", "family_name": "Diallo", "birth_date": "2000-01-01"},
                    "fields": ["date_of_birth"],
                    "limit": 2
                },
                {
                    "slot": 2,
                    "lookup": {"given_name": "Cara", "family_name": "Diallo", "birth_date": "2000-01-01"},
                    "fields": ["date_of_birth"],
                    "limit": 2
                }
            ]
        })))
        // The adapter restores request order from opaque slots rather than
        // trusting a source-controlled response order.
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "results": [
                {"slot": 2, "total": 1, "date_of_birth": "2001-01-01"},
                {"slot": 0, "total": 1, "date_of_birth": "2000-01-01"},
                {"slot": 1, "total": 0}
            ]
        })))
        .expect(1)
        .mount(&optimized_server)
        .await;
    let optimized = optimized_runtime
        .evaluate_request_batch(
            "operation-request-batch-source-optimized",
            &access_token(None),
            &batch,
        )
        .await
        .expect("optimized request batch evaluates");
    let optimized: EvidenceRequestBatchResponse =
        serde_json::from_slice(optimized.bytes()).expect("optimized response parses");

    assert_eq!(
        request_batch_public_values(&optimized),
        request_batch_public_values(&sequential),
        "strategy choice cannot change logical response order or outcomes"
    );
    assert_eq!(
        sequential_server
            .received_requests()
            .await
            .expect("sequential journal is available")
            .len(),
        3
    );
    assert_eq!(
        optimized_server
            .received_requests()
            .await
            .expect("optimized journal is available")
            .len(),
        1
    );
    assert_eq!(
        request_batch_audit_access_indices(&optimized_prepared.audit_path),
        [vec![0, 1, 2]]
    );
}

#[tokio::test]
async fn request_batch_optimized_source_failure_aborts_after_one_call_without_sequential_fanout() {
    let server = MockServer::start().await;
    let prepared = prepare_fixture_with_mutation(
        "subject-binding-secret-canary-32-bytes-minimum",
        &server.uri(),
        &FixtureCeilings::deployment_defaults(),
        configure_optimized_adult_source_batch,
    );
    enable_source_batch_acquisition(&prepared.runtime_path);
    let runtime = Arc::new(
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await
            .expect("optimized runtime initializes"),
    );
    Mock::given(method("POST"))
        .and(path("/v1/facts"))
        .respond_with(ResponseTemplate::new(503))
        .expect(1)
        .mount(&server)
        .await;

    let mut batch = adult_request_batch(3);
    set_batch_adult_given_name(&mut batch, 1, "Binta");
    set_batch_adult_given_name(&mut batch, 2, "Cara");
    let http = TestServer::new(build_app(runtime));
    let response = http
        .post("/v1/evidence/batch")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .add_header("accept", EVIDENCE_REQUEST_BATCH_MEDIA_TYPE)
        .json(&batch)
        .await;

    assert_eq!(response.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.header("content-type"), "application/problem+json");
    let problem = response.json::<Value>();
    assert_eq!(problem["code"], json!("source.unavailable"));
    assert!(problem.get("items").is_none());

    let journal = server
        .received_requests()
        .await
        .expect("source journal is available");
    assert_eq!(
        journal.len(),
        1,
        "only the optimized physical call executes"
    );
    let physical_request: Value =
        serde_json::from_slice(&journal[0].body).expect("optimized source request is JSON");
    assert_eq!(
        physical_request["requests"]
            .as_array()
            .expect("optimized request carries logical members")
            .len(),
        3
    );
    assert!(
        physical_request.get("lookup").is_none(),
        "no sequential single-item request reached the source"
    );

    let audit = fs::read_to_string(&prepared.audit_path).expect("audit is readable");
    assert_eq!(audit.matches("\"phase\":\"access-attempt\"").count(), 1);
    assert_eq!(audit.matches("\"phase\":\"disclosure-release\"").count(), 0);
    assert_eq!(audit.matches("\"phase\":\"terminal-failure\"").count(), 1);
    assert_eq!(
        request_batch_audit_access_indices(&prepared.audit_path),
        [vec![0, 1, 2]]
    );
    let terminal = audit
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("audit envelope parses"))
        .find(|event| event["record"]["phase"] == "terminal-failure")
        .expect("one terminal failure exists");
    assert_eq!(terminal["record"]["decision"], json!("aborted"));
    assert_eq!(
        terminal["record"]["safeErrorCategory"],
        json!("source-status")
    );
    for prohibited in [
        "itemGroups",
        "itemIndices",
        "sourceId",
        "adapterId",
        "outcomes",
        "signingKeyId",
    ] {
        assert!(terminal["record"].get(prohibited).is_none(), "{prohibited}");
    }
}

#[tokio::test]
async fn request_batch_malformed_sequential_extraction_aborts_without_partial_release() {
    assert_sequential_batch_protocol_failure(
        "operation-request-batch-malformed-extraction",
        Some(
            r#"fn extract(source_response, context) {
    #{outcome: "no_match", extra: true}
}
"#,
        ),
        json!({"total": 1, "date_of_birth": "2000-01-01"}),
    )
    .await;
    assert_sequential_batch_protocol_failure(
        "operation-request-batch-invalid-fact-set",
        None,
        // The ordinary adult extraction decodes this unique response as a
        // match with an empty FactSet, which violates its required fact schema.
        json!({"total": 1}),
    )
    .await;
}

async fn assert_sequential_batch_protocol_failure(
    operation: &str,
    extraction: Option<&str>,
    response: Value,
) {
    let server = MockServer::start().await;
    let prepared = prepare_fixture_with_mutation(
        "subject-binding-secret-canary-32-bytes-minimum",
        &server.uri(),
        &FixtureCeilings::deployment_defaults(),
        |bundle_root| {
            if let Some(extraction) = extraction {
                fs::write(
                    bundle_root.join("adapters/adult-status-source.rhai"),
                    extraction,
                )
                .expect("malformed extraction fixture writes");
            }
        },
    );
    let runtime =
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await
            .expect("sequential runtime initializes");
    Mock::given(method("POST"))
        .and(path("/v1/facts"))
        .respond_with(ResponseTemplate::new(200).set_body_json(response))
        .expect(1)
        .mount(&server)
        .await;

    let error = runtime
        .evaluate_request_batch(operation, &access_token(None), &adult_request_batch(2))
        .await
        .expect_err("a malformed sequential member aborts the outer batch");
    assert_eq!(error.problem(), ProblemCode::DependencyUnavailable);
    assert_eq!(
        server
            .received_requests()
            .await
            .expect("source journal is available")
            .len(),
        1,
        "the second logical item must not execute after the global fault"
    );
    let audit = fs::read_to_string(&prepared.audit_path).expect("audit is readable");
    assert_eq!(audit.matches("\"phase\":\"access-attempt\"").count(), 1);
    assert_eq!(audit.matches("\"phase\":\"disclosure-release\"").count(), 0);
    assert_eq!(audit.matches("\"phase\":\"terminal-failure\"").count(), 1);
    let terminal = audit
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("audit envelope parses"))
        .find(|event| event["record"]["phase"] == "terminal-failure")
        .expect("one terminal failure exists");
    assert_eq!(terminal["record"]["safeErrorCategory"], "source-protocol");
    assert!(terminal["record"].get("outcomes").is_none());
}

#[tokio::test]
async fn request_batch_later_signing_failure_releases_no_partial_envelope() {
    let prepared = prepare_acceptance("subject-binding-secret-canary-32-bytes-minimum").await;
    let mut runtime =
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await
            .expect("runtime initializes");
    let private = PrivateJwk::parse(EVIDENCE_PRIVATE_JWK).expect("test signing key parses");
    let delegate = LocalJwkSigner::new(private).expect("local signer builds");
    let provider: Arc<dyn SigningProvider> = Arc::new(FailOnNthSignatureSigner {
        delegate,
        calls: AtomicUsize::new(0),
        // Startup self-test is call zero, the first item is call one, and the
        // second item fails after the first item was fully signed in memory.
        fail_at: 2,
    });
    let failing_signer = EvidenceSigner::initialize(provider, EVIDENCE_KEY_ID)
        .await
        .expect("signer passes its startup self-test");
    runtime.replace_signer_for_test(failing_signer);
    mount_adult_source_expecting(&prepared.server, None, 2).await;

    let http = TestServer::new(build_app(Arc::new(runtime)));
    let response = http
        .post("/v1/evidence/batch")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .add_header("accept", EVIDENCE_REQUEST_BATCH_MEDIA_TYPE)
        .json(&adult_request_batch(3))
        .await;
    assert_eq!(response.status_code(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(response.header("content-type"), "application/problem+json");
    let body = response.text();
    assert!(!body.contains("payload") && !body.contains("signature"));

    let audit = fs::read_to_string(&prepared.audit_path).expect("audit is readable");
    assert_eq!(audit.matches("\"phase\":\"disclosure-release\"").count(), 0);
    assert_eq!(audit.matches("\"phase\":\"terminal-failure\"").count(), 1);
    let terminal = audit
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("audit envelope parses"))
        .find(|event| event["record"]["phase"] == "terminal-failure")
        .expect("one terminal failure exists");
    let record = terminal["record"]
        .as_object()
        .expect("terminal failure is an object");
    for forbidden in [
        "itemIndices",
        "itemGroups",
        "sourceId",
        "adapterId",
        "outcomes",
        "signingKeyId",
        "disclosedConcepts",
    ] {
        assert!(
            !record.contains_key(forbidden),
            "terminal carries {forbidden}"
        );
    }
    assert_eq!(record["safeErrorCategory"], "signing");
}

#[tokio::test]
async fn request_batch_preserves_order_and_independent_ids_nonces_with_mixed_outcomes() {
    let fixture = acceptance_runtime().await;
    let mut batch = adult_request_batch(3);
    set_batch_adult_given_name(&mut batch, 1, "Binta");
    set_batch_adult_given_name(&mut batch, 2, "Cara");
    mount_named_adult_source(
        &fixture.server,
        "Amina",
        json!({"total": 1, "date_of_birth": "2000-01-01"}),
    )
    .await;
    mount_named_adult_source(&fixture.server, "Binta", json!({"total": 0})).await;
    mount_named_adult_source(
        &fixture.server,
        "Cara",
        json!({"total": 1, "date_of_birth": "2001-01-01"}),
    )
    .await;

    let http = TestServer::new(build_app(Arc::clone(&fixture.runtime)));
    let response = http
        .post("/v1/evidence/batch")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .add_header("accept", EVIDENCE_REQUEST_BATCH_MEDIA_TYPE)
        .json(&batch)
        .await;
    response.assert_status_ok();
    assert_eq!(
        response.header("content-type"),
        EVIDENCE_REQUEST_BATCH_MEDIA_TYPE
    );
    let envelope = response.json::<EvidenceRequestBatchResponse>();
    assert_eq!(envelope.items.len(), 3);
    let first = match &envelope.items[0] {
        EvidenceRequestBatchResponseItem::Evidence { evidence } => decode_evidence(evidence),
        EvidenceRequestBatchResponseItem::EvidenceNotAvailable => panic!("first is available"),
    };
    assert!(matches!(
        envelope.items[1],
        EvidenceRequestBatchResponseItem::EvidenceNotAvailable
    ));
    let third = match &envelope.items[2] {
        EvidenceRequestBatchResponseItem::Evidence { evidence } => decode_evidence(evidence),
        EvidenceRequestBatchResponseItem::EvidenceNotAvailable => panic!("third is available"),
    };
    assert_eq!(
        first.request_nonce.as_deref(),
        Some(batch.items[0].request_nonce.as_str())
    );
    assert_eq!(
        third.request_nonce.as_deref(),
        Some(batch.items[2].request_nonce.as_str())
    );
    assert_ne!(first.id, third.id);
    assert_eq!(first.observed_at, third.observed_at);
    assert_eq!(first.issued_at, third.issued_at);
    assert_eq!(first.issued_at, first.observed_at);

    let audit = fs::read_to_string(&fixture.audit_path).expect("audit is readable");
    assert_eq!(audit.matches("\"phase\":\"access-attempt\"").count(), 3);
    assert_eq!(audit.matches("\"phase\":\"disclosure-release\"").count(), 1);
    assert!(audit.contains("\"itemIndices\":[0]"));
    assert!(audit.contains("\"itemIndices\":[1]"));
    assert!(audit.contains("\"itemIndices\":[2]"));
    assert!(audit.contains("\"outcome\":\"evidence-not-available\""));
    for item in &batch.items {
        assert!(!audit.contains(&item.request_nonce));
    }
}

#[tokio::test]
async fn request_batch_all_unavailable_is_200_and_records_no_signing_key() {
    let fixture = acceptance_runtime().await;
    let mut batch = adult_request_batch(2);
    set_batch_adult_given_name(&mut batch, 1, "Binta");
    mount_named_adult_source(&fixture.server, "Amina", json!({"total": 0})).await;
    mount_named_adult_source(&fixture.server, "Binta", json!({"total": 0})).await;

    let http = TestServer::new(build_app(Arc::clone(&fixture.runtime)));
    let response = http
        .post("/v1/evidence/batch")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .add_header("accept", EVIDENCE_REQUEST_BATCH_MEDIA_TYPE)
        .json(&batch)
        .await;
    response.assert_status_ok();
    assert!(response
        .json::<EvidenceRequestBatchResponse>()
        .items
        .iter()
        .all(|item| matches!(item, EvidenceRequestBatchResponseItem::EvidenceNotAvailable)));
    let audit = fs::read_to_string(&fixture.audit_path).expect("audit is readable");
    let release = audit
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("audit envelope parses"))
        .find(|event| event["record"]["phase"] == "disclosure-release")
        .expect("one terminal release exists");
    assert!(release["record"].get("signingKeyId").is_none());
}

#[tokio::test]
async fn request_batch_later_dependency_failure_has_one_value_free_abort_and_no_release() {
    let fixture = acceptance_runtime().await;
    let mut batch = adult_request_batch(3);
    set_batch_adult_given_name(&mut batch, 1, "Binta");
    set_batch_adult_given_name(&mut batch, 2, "Cara");
    mount_named_adult_source(
        &fixture.server,
        "Amina",
        json!({"total": 1, "date_of_birth": "2000-01-01"}),
    )
    .await;
    Mock::given(method("POST"))
        .and(path("/v1/facts"))
        .and(body_json(adult_source_request_for("Binta")))
        .respond_with(ResponseTemplate::new(503))
        .expect(1)
        .mount(&fixture.server)
        .await;

    let http = TestServer::new(build_app(Arc::clone(&fixture.runtime)));
    let response = http
        .post("/v1/evidence/batch")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .add_header("accept", EVIDENCE_REQUEST_BATCH_MEDIA_TYPE)
        .json(&batch)
        .await;
    assert_eq!(
        response.status_code(),
        ProblemCode::DependencyUnavailable.status()
    );
    assert_eq!(response.json::<Value>()["code"], "source.unavailable");
    assert_eq!(
        fixture
            .server
            .received_requests()
            .await
            .expect("source journal is available")
            .len(),
        2,
        "a later item is not contacted after the outer abort"
    );
    let audit = fs::read_to_string(&fixture.audit_path).expect("audit is readable");
    assert_eq!(audit.matches("\"phase\":\"disclosure-release\"").count(), 0);
    assert_eq!(audit.matches("\"phase\":\"terminal-failure\"").count(), 1);
    assert_eq!(audit.matches("\"decision\":\"aborted\"").count(), 1);
    assert!(!audit.contains("Binta") && !audit.contains("Cara"));
}

/// Threat: treating a source-declared unresolved search as an outer outage
/// would disclose a different public result from the same unresolved class in
/// singular evaluation. Enforcement: the sequential batch maps the exact
/// declared search outcome to one data-free unavailable item and releases the
/// otherwise successful envelope only after every item completes.
#[tokio::test]
async fn request_batch_declared_unresolved_search_is_item_unavailable() {
    let server = MockServer::start().await;
    let source_origin = server.uri();
    let prepared = prepare_fixture_with_mutation(
        "subject-binding-secret-canary-32-bytes-minimum",
        &source_origin,
        &FixtureCeilings::deployment_defaults(),
        |bundle_root| {
            configure_search_then_fetch(bundle_root, &source_origin);
            declare_unresolved_problem(bundle_root, "source-a");
        },
    );
    let runtime = Arc::new(
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await
            .expect("declared unresolved search runtime initializes"),
    );
    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .and(body_json(adult_search_request_for("Amina", &["record_id"])))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total": 1,
            "record_id": "record-001"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/records/record-001"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"date_of_birth": "2000-01-01"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    const TRACE_CANARY: &str = "search-declared-unresolved-trace-canary";
    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .and(body_json(adult_search_request_for("Binta", &["record_id"])))
        .respond_with(declared_unresolved_response(TRACE_CANARY))
        .expect(1)
        .mount(&server)
        .await;

    let mut batch = adult_request_batch(2);
    set_batch_adult_given_name(&mut batch, 1, "Binta");
    let http = TestServer::new(build_app(runtime));
    let response = http
        .post("/v1/evidence/batch")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .add_header("accept", EVIDENCE_REQUEST_BATCH_MEDIA_TYPE)
        .json(&batch)
        .await;
    response.assert_status_ok();
    let envelope = response.json::<EvidenceRequestBatchResponse>();
    assert!(matches!(
        envelope.items.as_slice(),
        [
            EvidenceRequestBatchResponseItem::Evidence { .. },
            EvidenceRequestBatchResponseItem::EvidenceNotAvailable
        ]
    ));
    assert_eq!(
        server
            .received_requests()
            .await
            .expect("source journal is available")
            .len(),
        3
    );
    let audit = fs::read_to_string(&prepared.audit_path).expect("audit is readable");
    assert_eq!(audit.matches("\"phase\":\"disclosure-release\"").count(), 1);
    assert_eq!(audit.matches("\"phase\":\"terminal-failure\"").count(), 0);
    assert!(audit.contains("\"outcome\":\"evidence-not-available\""));
    assert!(!audit.contains(TRACE_CANARY));
}

/// Threat: releasing a completed earlier item when a later fetch reports a
/// declared unresolved result would make the ordered batch non-atomic.
/// Enforcement: a fetch-stage unresolved result remains dependency failure,
/// aborts the outer request, and emits neither item material nor a release
/// audit record.
#[tokio::test]
async fn request_batch_declared_unresolved_fetch_aborts_without_partial_release() {
    let server = MockServer::start().await;
    let source_origin = server.uri();
    let prepared = prepare_fixture_with_mutation(
        "subject-binding-secret-canary-32-bytes-minimum",
        &source_origin,
        &FixtureCeilings::deployment_defaults(),
        |bundle_root| {
            configure_search_then_fetch(bundle_root, &source_origin);
            declare_unresolved_problem(bundle_root, "source-a-fetch");
        },
    );
    let runtime = Arc::new(
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await
            .expect("declared unresolved fetch runtime initializes"),
    );
    for (given_name, record_id) in [("Amina", "record-001"), ("Binta", "record-002")] {
        Mock::given(method("POST"))
            .and(path("/v1/search"))
            .and(body_json(adult_search_request_for(
                given_name,
                &["record_id"],
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "total": 1,
                "record_id": record_id
            })))
            .expect(1)
            .mount(&server)
            .await;
    }
    Mock::given(method("GET"))
        .and(path("/v1/records/record-001"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"date_of_birth": "2000-01-01"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    const TRACE_CANARY: &str = "batch-fetch-unresolved-trace-canary";
    Mock::given(method("GET"))
        .and(path("/v1/records/record-002"))
        .respond_with(declared_unresolved_response(TRACE_CANARY))
        .expect(1)
        .mount(&server)
        .await;

    let mut batch = adult_request_batch(2);
    set_batch_adult_given_name(&mut batch, 1, "Binta");
    let http = TestServer::new(build_app(runtime));
    let response = http
        .post("/v1/evidence/batch")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .add_header("accept", EVIDENCE_REQUEST_BATCH_MEDIA_TYPE)
        .json(&batch)
        .await;
    assert_eq!(
        response.status_code(),
        ProblemCode::DependencyUnavailable.status()
    );
    let problem = response.json::<Value>();
    assert_eq!(problem["code"], "source.unavailable");
    for forbidden in ["items", "payload", "protected", "signature"] {
        assert!(
            problem.get(forbidden).is_none(),
            "outer failure carried {forbidden}"
        );
    }
    assert!(!problem.to_string().contains(TRACE_CANARY));
    assert_eq!(
        server
            .received_requests()
            .await
            .expect("source journal is available")
            .len(),
        4
    );
    let audit = fs::read_to_string(&prepared.audit_path).expect("audit is readable");
    assert_eq!(audit.matches("\"phase\":\"disclosure-release\"").count(), 0);
    assert_eq!(audit.matches("\"phase\":\"terminal-failure\"").count(), 1);
    assert!(audit.contains("\"safeErrorCategory\":\"fetch-result\""));
    assert!(!audit.contains(TRACE_CANARY));
}

/// Threat: a declared unresolved member must not be downgraded to an
/// unavailable item after another batch item has already completed its fetch
/// set. Enforcement: the member is an atomic outer dependency failure, later
/// members are not contacted, and no partial envelope is released.
#[tokio::test]
async fn request_batch_declared_unresolved_fetch_set_member_aborts_without_partial_release() {
    let server = MockServer::start().await;
    let source_origin = server.uri();
    let prepared = prepare_fixture_with_mutation(
        "subject-binding-secret-canary-32-bytes-minimum",
        &source_origin,
        &FixtureCeilings::deployment_defaults(),
        |bundle_root| {
            configure_fetch_set(bundle_root, &source_origin);
            declare_unresolved_problem(bundle_root, "source-a-fetch");
        },
    );
    enable_fetch_set_acquisition(&prepared.runtime_path);
    let runtime = Arc::new(
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await
            .expect("declared unresolved fetch-set runtime initializes"),
    );
    for (given_name, record_id, partner_ref) in [
        ("Amina", "record-001", "partner-77"),
        ("Binta", "record-002", "partner-88"),
    ] {
        Mock::given(method("POST"))
            .and(path("/v1/search"))
            .and(body_json(adult_search_request_for(
                given_name,
                &["record_id", "partner_ref"],
            )))
            .respond_with(ResponseTemplate::new(200).set_body_json(json!({
                "total": 1,
                "record_id": record_id,
                "partner_ref": partner_ref
            })))
            .expect(1)
            .mount(&server)
            .await;
    }
    Mock::given(method("POST"))
        .and(path("/v1/records/record-001"))
        .and(body_json(json!({"lookup": {"record_id": "record-001"}})))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"date_of_birth": "2000-01-01"})),
        )
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/partners"))
        .and(body_json(json!({"lookup": {"partner_ref": "partner-77"}})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"partner_status": "active"})))
        .expect(1)
        .mount(&server)
        .await;
    const TRACE_CANARY: &str = "batch-fetch-set-unresolved-trace-canary";
    Mock::given(method("POST"))
        .and(path("/v1/records/record-002"))
        .and(body_json(json!({"lookup": {"record_id": "record-002"}})))
        .respond_with(declared_unresolved_response(TRACE_CANARY))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/partners"))
        .and(body_json(json!({"lookup": {"partner_ref": "partner-88"}})))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"partner_status": "active"})))
        .expect(0)
        .mount(&server)
        .await;

    let mut batch = adult_request_batch(2);
    set_batch_adult_given_name(&mut batch, 1, "Binta");
    let http = TestServer::new(build_app(runtime));
    let response = http
        .post("/v1/evidence/batch")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .add_header("accept", EVIDENCE_REQUEST_BATCH_MEDIA_TYPE)
        .json(&batch)
        .await;
    assert_eq!(
        response.status_code(),
        ProblemCode::DependencyUnavailable.status()
    );
    let problem = response.json::<Value>();
    assert_eq!(problem["code"], "source.unavailable");
    for forbidden in ["items", "payload", "protected", "signature"] {
        assert!(
            problem.get(forbidden).is_none(),
            "outer failure carried {forbidden}"
        );
    }
    assert!(!problem.to_string().contains(TRACE_CANARY));
    assert_eq!(
        server
            .received_requests()
            .await
            .expect("source journal is available")
            .len(),
        5,
        "the failed item's later member is never contacted"
    );
    let audit = fs::read_to_string(&prepared.audit_path).expect("audit is readable");
    assert_eq!(audit.matches("\"phase\":\"disclosure-release\"").count(), 0);
    assert_eq!(audit.matches("\"phase\":\"terminal-failure\"").count(), 1);
    assert!(audit.contains("\"safeErrorCategory\":\"fetch-result\""));
    assert!(!audit.contains(TRACE_CANARY));
}

#[tokio::test]
async fn request_batch_response_above_one_mib_releases_no_partial_envelope() {
    let server = MockServer::start().await;
    let mut ceilings = FixtureCeilings::deployment_defaults();
    ceilings.requests_per_principal_per_minute = 960;
    ceilings.burst_per_principal = 16;
    let prepared = prepare_fixture(
        "subject-binding-secret-canary-32-bytes-minimum",
        &server.uri(),
        &ceilings,
    );
    let mut runtime =
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await
            .expect("runtime initializes");
    let private = PrivateJwk::parse(EVIDENCE_PRIVATE_JWK).expect("test signing key parses");
    let delegate = LocalJwkSigner::new(private).expect("local signer builds");
    let provider: Arc<dyn SigningProvider> = Arc::new(OversizedAfterSelfTestSigner {
        delegate,
        calls: AtomicUsize::new(0),
    });
    let oversized_signer = EvidenceSigner::initialize(provider, EVIDENCE_KEY_ID)
        .await
        .expect("signer passes its startup self-test");
    runtime.replace_signer_for_test(oversized_signer);
    mount_adult_source_expecting(&server, None, 16).await;

    let error = runtime
        .evaluate_request_batch(
            "operation-request-batch-response-size",
            &access_token(None),
            &adult_request_batch(16),
        )
        .await
        .expect_err("an oversized outer envelope is never released");
    assert_eq!(error.problem(), ProblemCode::ServiceUnavailable);
    assert_eq!(error.category(), "release-serialization");
    let audit = fs::read_to_string(&prepared.audit_path).expect("audit is readable");
    assert_eq!(audit.matches("\"phase\":\"disclosure-release\"").count(), 0);
    assert_eq!(audit.matches("\"phase\":\"terminal-failure\"").count(), 1);
}

#[tokio::test]
async fn accept_negotiation_is_closed_and_fails_before_source_access() {
    let fixture = acceptance_runtime().await;
    let http = TestServer::new(build_app(Arc::clone(&fixture.runtime)));
    let token = access_token(None);

    for invalid in [
        "application/json",
        "application/jose+json, application/vnd.registrystack.evidence-unsigned+json",
        "application/jose+json;q=0.9",
        "application/vnd.registrystack.evidence-unsigned+json; charset=utf-8",
        "application/*",
        "text/html",
    ] {
        let response = http
            .post("/v1/evidence")
            .add_header("authorization", format!("Bearer {token}"))
            .add_header("accept", invalid)
            .json(&serde_json::to_value(adult_request()).expect("request serializes"))
            .await;
        assert_eq!(
            response.status_code(),
            axum::http::StatusCode::NOT_ACCEPTABLE,
            "{invalid}"
        );
        assert_eq!(
            response.json::<Value>()["code"],
            json!("format.unsupported")
        );
        assert_eq!(response.header("vary"), "Accept");
    }
    assert!(
        fixture
            .server
            .received_requests()
            .await
            .expect("request journal is available")
            .is_empty(),
        "unsupported negotiation must fail before source access"
    );
    assert!(fs::read_to_string(&fixture.audit_path)
        .expect("audit is readable")
        .is_empty());

    // Missing Accept, */*, and the exact signed media type all select JWS.
    mount_adult_source(&fixture.server, None).await;
    let response = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {token}"))
        .add_header("accept", "*/*")
        .json(&serde_json::to_value(adult_request()).expect("request serializes"))
        .await;
    response.assert_status_ok();
    assert_eq!(response.header("content-type"), "application/jose+json");
    assert_eq!(response.header("vary"), "Accept");
}

#[tokio::test]
async fn absent_and_malformed_bearer_tokens_agree_when_the_request_body_is_otherwise_valid() {
    // cli-errors-23 compared a header-free request against a malformed-header
    // request that both carried an invalid `{}` body, so the comparison also
    // measured validation order rather than authentication alone. With an
    // otherwise-valid body, the two failures must be indistinguishable: a
    // caller who forgets the header and a caller whose token will never
    // verify both learn only that their bearer credential is invalid, never
    // which validation layer noticed first.
    let fixture = acceptance_runtime().await;
    let http = TestServer::new(build_app(Arc::clone(&fixture.runtime)));
    let body = serde_json::to_value(adult_request()).expect("request serializes");

    let missing_header = http.post("/v1/evidence").json(&body).await;
    assert_eq!(
        missing_header.status_code(),
        axum::http::StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        missing_header.json::<Value>()["code"],
        json!("auth.invalid_credential")
    );

    let malformed_token = http
        .post("/v1/evidence")
        .add_header("authorization", "Bearer not-a-token")
        .json(&body)
        .await;
    assert_eq!(
        malformed_token.status_code(),
        axum::http::StatusCode::UNAUTHORIZED
    );
    assert_eq!(
        malformed_token.json::<Value>()["code"],
        json!("auth.invalid_credential")
    );

    // Compared whole, not just by code: a title or detail that differed by
    // layer would still tell the two callers apart. The per-request trace ID
    // is the one member expected to vary, so it is removed rather than
    // assumed equal.
    let mut missing_body = missing_header.json::<Value>();
    let mut malformed_body = malformed_token.json::<Value>();
    for denial in [&mut missing_body, &mut malformed_body] {
        denial
            .as_object_mut()
            .expect("a problem body is an object")
            .remove("traceId");
    }
    assert_eq!(
        missing_body, malformed_body,
        "an absent and a malformed bearer token must be indistinguishable"
    );

    assert!(
        fixture
            .server
            .received_requests()
            .await
            .expect("request journal is available")
            .is_empty(),
        "authentication failure must precede source access"
    );
    assert!(fs::read_to_string(&fixture.audit_path)
        .expect("audit is readable")
        .is_empty());
}

#[tokio::test]
async fn unsigned_output_requires_both_bundle_and_grant_permission() {
    // Grant permits unsigned but the immutable bundle does not enable it.
    let prepared = prepare_acceptance("subject-binding-secret-canary-32-bytes-minimum").await;
    make_writable(&prepared.bundle_root);
    let configuration_path = prepared.bundle_root.join("evidence.yaml");
    let mut configuration =
        fs::read_to_string(&configuration_path).expect("acceptance configuration is readable");
    replace_exact(
        &mut configuration,
        "\nresponseFormats: [signed-jws, unsigned-json]",
        "\nresponseFormats: [signed-jws]",
        1,
    );
    fs::write(&configuration_path, &configuration).expect("test configuration is rewritten");
    regenerate_discovery_description(&prepared.bundle_root);
    make_read_only(&prepared.bundle_root);
    let runtime = Arc::new(
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await
            .expect("bundle-restricted runtime initializes"),
    );
    let http = TestServer::new(build_app(Arc::clone(&runtime)));
    let token = access_token(None);
    let bundle_denied = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {token}"))
        .add_header("accept", EVIDENCE_UNSIGNED_MEDIA_TYPE)
        .json(&serde_json::to_value(adult_request()).expect("request serializes"))
        .await;
    assert_eq!(
        bundle_denied.status_code(),
        axum::http::StatusCode::FORBIDDEN
    );
    let bundle_denied_body = bundle_denied.json::<Value>();
    assert_eq!(bundle_denied_body["code"], json!("evidence.denied"));
    assert!(prepared
        .server
        .received_requests()
        .await
        .expect("request journal is available")
        .is_empty());
    let audit = fs::read_to_string(&prepared.audit_path).expect("audit is readable");
    assert_eq!(audit.matches("\"decision\":\"not-authorized\"").count(), 1);
    assert_eq!(
        audit
            .matches("\"safeErrorCategory\":\"not-authorized\"")
            .count(),
        1
    );

    // The bundle enables unsigned but the matched grant withholds it. Another
    // grant's permission cannot be unioned in, and the denial is identical.
    let prepared = prepare_acceptance("subject-binding-secret-canary-32-bytes-minimum").await;
    make_writable(&prepared.bundle_root);
    let configuration_path = prepared.bundle_root.join("evidence.yaml");
    let mut configuration =
        fs::read_to_string(&configuration_path).expect("acceptance configuration is readable");
    replace_exact(
        &mut configuration,
        "purpose: fixture-eligibility\n        audienceFrom: authenticated-requester\n        responseFormats: [signed-jws, unsigned-json]",
        "purpose: fixture-eligibility\n        audienceFrom: authenticated-requester\n        responseFormats: [signed-jws]",
        1,
    );
    fs::write(&configuration_path, &configuration).expect("test configuration is rewritten");
    make_read_only(&prepared.bundle_root);
    let runtime = Arc::new(
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await
            .expect("grant-restricted runtime initializes"),
    );
    let http = TestServer::new(build_app(Arc::clone(&runtime)));
    let grant_denied = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {token}"))
        .add_header("accept", EVIDENCE_UNSIGNED_MEDIA_TYPE)
        .json(&serde_json::to_value(adult_request()).expect("request serializes"))
        .await;
    assert_eq!(
        grant_denied.status_code(),
        axum::http::StatusCode::FORBIDDEN
    );
    let grant_denied_body = grant_denied.json::<Value>();
    assert_eq!(grant_denied_body["code"], json!("evidence.denied"));
    // The two denials must not reveal which layer withheld permission.
    assert_eq!(bundle_denied_body["code"], grant_denied_body["code"]);
    assert_eq!(bundle_denied_body["title"], grant_denied_body["title"]);
    assert_eq!(bundle_denied_body["status"], grant_denied_body["status"]);
    let audit = fs::read_to_string(&prepared.audit_path).expect("audit is readable");
    assert_eq!(audit.matches("\"decision\":\"not-authorized\"").count(), 1);
    assert_eq!(
        audit
            .matches("\"safeErrorCategory\":\"not-authorized\"")
            .count(),
        1
    );
    // The signed default remains available under the restricted grant.
    mount_adult_source(&prepared.server, None).await;
    let signed = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {token}"))
        .json(&serde_json::to_value(adult_request()).expect("request serializes"))
        .await;
    signed.assert_status_ok();
    assert_eq!(signed.header("content-type"), "application/jose+json");

    // Runtime configuration is closed and cannot enable a response format.
    let prepared = prepare_acceptance("subject-binding-secret-canary-32-bytes-minimum").await;
    let mut runtime_document =
        fs::read_to_string(&prepared.runtime_path).expect("runtime configuration is readable");
    runtime_document.push_str("responseFormats: [signed-jws, unsigned-json]\n");
    make_file_writable(&prepared.runtime_path);
    fs::write(&prepared.runtime_path, runtime_document).expect("runtime override is written");
    make_file_read_only(&prepared.runtime_path);
    let error =
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await
            .expect_err("a runtime response-format override must fail startup closed");
    assert!(matches!(error, RuntimeInitializationError::Bundle));
}

#[tokio::test]
async fn unsigned_envelope_is_exact_audited_and_never_a_signing_fallback() {
    let fixture = acceptance_runtime().await;
    mount_adult_source(&fixture.server, None).await;
    let http = TestServer::new(build_app(Arc::clone(&fixture.runtime)));
    let token = access_token(None);
    let request = adult_request();
    let nonce = request.request_nonce.clone();

    let response = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {token}"))
        .add_header("accept", EVIDENCE_UNSIGNED_MEDIA_TYPE)
        .json(&serde_json::to_value(&request).expect("request serializes"))
        .await;
    response.assert_status_ok();
    assert_eq!(
        response.header("content-type"),
        EVIDENCE_UNSIGNED_MEDIA_TYPE
    );
    assert_eq!(response.header("vary"), "Accept");
    assert_eq!(response.header("cache-control"), "no-store");

    let body = response.text();
    let value: Value = serde_json::from_str(&body).expect("unsigned body is JSON");
    let members = value
        .as_object()
        .expect("envelope is an object")
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>();
    assert_eq!(
        members,
        BTreeSet::from([
            "schema".to_owned(),
            "type".to_owned(),
            "integrityProtection".to_owned(),
            "warning".to_owned(),
            "evidence".to_owned(),
        ]),
        "the envelope has no JWS member and no signing-key claim"
    );
    assert_eq!(
        value["schema"],
        json!("registry.unsigned-evidence-envelope/v1")
    );
    assert_eq!(value["type"], json!("UnsignedEvidenceEnvelope"));
    assert_eq!(value["integrityProtection"], json!("none"));
    assert_eq!(value["warning"], json!("not-cryptographically-verifiable"));
    let envelope: UnsignedEvidenceEnvelope =
        serde_json::from_str(&body).expect("envelope parses strictly");
    assert_eq!(
        envelope.evidence.request_nonce.as_deref(),
        Some(nonce.as_str())
    );
    assert!(
        evidence_contract_accepts(&value["evidence"]).expect("evidence contract is available"),
        "the nested evidence is the same closed core object"
    );

    // The strict JWS verifier rejects the unsigned representation.
    let mut policy = verification_policy_stub(&fixture.runtime, &request);
    policy.request_nonce = nonce;
    assert!(verify_flattened_jws(body.as_bytes(), fixture.runtime.jwks(), &policy).is_err());

    // Audit records the closed protection mode; the release event carries no
    // signing key identity for unsigned output.
    let audit = wait_for_audit_counts(&fixture.audit_path, 1, 1).await;
    let events = audit
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("audit line is JSON"))
        .collect::<Vec<_>>();
    let access = events
        .iter()
        .find(|event| event["record"]["phase"] == json!("access-attempt"))
        .expect("access event exists");
    let release = events
        .iter()
        .find(|event| event["record"]["phase"] == json!("disclosure-release"))
        .expect("release event exists");
    assert_eq!(access["record"]["responseProtection"], json!("unsigned"));
    assert_eq!(release["record"]["responseProtection"], json!("unsigned"));
    assert!(release["record"]["signingKeyId"].is_null());
    assert!(release["record"]["evidenceId"].is_string());
    assert!(release["record"]["disclosedConcepts"].is_array());
    assert!(!audit.contains(
        envelope
            .evidence
            .request_nonce
            .as_deref()
            .expect("audience-scoped")
    ));

    // An unready ordinary signing dependency also denies unsigned output.
    let prepared = prepare_acceptance("subject-binding-secret-canary-32-bytes-minimum").await;
    let mut runtime =
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await
            .expect("runtime initializes");
    let private = PrivateJwk::parse(EVIDENCE_PRIVATE_JWK).expect("test signing key parses");
    let delegate = LocalJwkSigner::new(private).expect("local signer builds");
    let provider: Arc<dyn SigningProvider> = Arc::new(UnavailableReadinessSigner { delegate });
    let unready_signer = EvidenceSigner::initialize(provider, EVIDENCE_KEY_ID)
        .await
        .expect("signer passes its startup self-test");
    runtime.replace_signer_for_test(unready_signer);
    mount_adult_source(&prepared.server, None).await;
    let error = runtime
        .evaluate_with_format(
            "operation-unsigned-unready-signing",
            &access_token(None),
            &adult_request(),
            ResponseFormat::UnsignedJson,
        )
        .await
        .expect_err("unsigned output still requires the signing dependency to be ready");
    assert_eq!(error.problem(), ProblemCode::ServiceUnavailable);
    let audit = fs::read_to_string(&prepared.audit_path).expect("audit is readable");
    assert_eq!(audit.matches("\"phase\":\"disclosure-release\"").count(), 0);
}

#[tokio::test]
async fn signing_failure_returns_a_problem_and_never_an_unsigned_body() {
    let prepared = prepare_acceptance("subject-binding-secret-canary-32-bytes-minimum").await;
    let mut runtime =
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await
            .expect("runtime initializes");
    let private = PrivateJwk::parse(EVIDENCE_PRIVATE_JWK).expect("test signing key parses");
    let delegate = LocalJwkSigner::new(private).expect("local signer builds");
    let provider: Arc<dyn SigningProvider> = Arc::new(FailOnceAfterSelfTestSigner {
        delegate,
        calls: AtomicUsize::new(0),
    });
    let failing_signer = EvidenceSigner::initialize(provider, EVIDENCE_KEY_ID)
        .await
        .expect("signer passes its startup self-test");
    runtime.replace_signer_for_test(failing_signer);
    mount_adult_source(&prepared.server, None).await;

    let http = TestServer::new(build_app(Arc::new(runtime)));
    let response = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .json(&serde_json::to_value(adult_request()).expect("request serializes"))
        .await;
    assert_eq!(
        response.status_code(),
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(response.header("content-type"), "application/problem+json");
    let text = response.text();
    assert!(
        !text.contains("integrityProtection") && !text.contains("UnsignedEvidenceEnvelope"),
        "a signed-path failure must never downgrade to unsigned output"
    );
}

#[tokio::test]
async fn disclosure_audit_failure_prevents_unsigned_response_release() {
    let fixture = acceptance_runtime().await;
    mount_adult_source(&fixture.server, Some(Duration::from_millis(500))).await;
    let runtime = Arc::clone(&fixture.runtime);
    let token = access_token(None);
    let request = adult_request();
    let evaluation = tokio::spawn(async move {
        runtime
            .evaluate_with_format(
                "operation-unsigned-audit-failure",
                &token,
                &request,
                ResponseFormat::UnsignedJson,
            )
            .await
    });

    wait_for_source_request_count(&fixture.server, 1).await;
    fs::OpenOptions::new()
        .append(true)
        .open(&fixture.audit_path)
        .and_then(|mut file| file.write_all(b"{}\n"))
        .expect("audit tamper writes after access acceptance");
    let error = evaluation
        .await
        .expect("evaluation task completes")
        .expect_err("release audit failure cannot return an unsigned response");
    assert_eq!(error.problem(), ProblemCode::ServiceUnavailable);
    let audit = fs::read_to_string(&fixture.audit_path).expect("audit is readable");
    assert_eq!(audit.matches("\"phase\":\"disclosure-release\"").count(), 0);
}

#[tokio::test]
async fn all_four_definitions_pass_the_explicitly_authorized_unsigned_path() {
    let fixture = acceptance_runtime().await;
    mount_success_sources(&fixture.server, true).await;
    let http = TestServer::new(build_app(Arc::clone(&fixture.runtime)));

    let cases = [
        (access_token(None), adult_request()),
        (access_token(None), residence_request()),
        (access_token(None), licence_request()),
        (access_token(Some(parent_grant_claims())), parent_request()),
    ];
    for (token, request) in cases {
        let response = http
            .post("/v1/evidence")
            .add_header("authorization", format!("Bearer {token}"))
            .add_header("accept", EVIDENCE_UNSIGNED_MEDIA_TYPE)
            .json(&serde_json::to_value(&request).expect("request serializes"))
            .await;
        response.assert_status_ok();
        assert_eq!(
            response.header("content-type"),
            EVIDENCE_UNSIGNED_MEDIA_TYPE
        );
        let envelope: UnsignedEvidenceEnvelope =
            serde_json::from_str(&response.text()).expect("envelope parses strictly");
        assert_eq!(
            envelope.evidence.request_nonce.as_deref(),
            Some(request.request_nonce.as_str())
        );
        assert!(!envelope.evidence.supported_values.is_empty());
        assert_eq!(
            envelope.evidence.subjects.len(),
            request.subjects.len(),
            "unsigned output binds the same declaration-ordered roles"
        );
    }
    let audit = wait_for_audit_counts(&fixture.audit_path, 4, 4).await;
    assert_eq!(
        audit.matches("\"responseProtection\":\"unsigned\"").count(),
        8,
        "every unsigned access and release event records the closed mode"
    );
    for canary in privacy_canaries() {
        assert!(!audit.contains(canary));
    }
}

/// Rewrite the acceptance bundle so the immutable bundle, and optionally the
/// matched grant, enable the SD-JWT VC response format.
async fn sd_jwt_vc_acceptance(grant_permits: bool) -> PreparedAcceptance {
    let prepared = prepare_acceptance("subject-binding-secret-canary-32-bytes-minimum").await;
    make_writable(&prepared.bundle_root);
    let configuration_path = prepared.bundle_root.join("evidence.yaml");
    let mut configuration =
        fs::read_to_string(&configuration_path).expect("acceptance configuration is readable");
    replace_exact(
        &mut configuration,
        "\nresponseFormats: [signed-jws, unsigned-json]",
        "\nresponseFormats: [signed-jws, unsigned-json, sd-jwt-vc]",
        1,
    );
    if grant_permits {
        replace_exact(
            &mut configuration,
            "purpose: fixture-eligibility\n        audienceFrom: authenticated-requester\n        responseFormats: [signed-jws, unsigned-json]",
            "purpose: fixture-eligibility\n        audienceFrom: authenticated-requester\n        responseFormats: [signed-jws, unsigned-json, sd-jwt-vc]",
            1,
        );
    }
    fs::write(&configuration_path, &configuration).expect("test configuration is rewritten");
    regenerate_discovery_description(&prepared.bundle_root);
    make_read_only(&prepared.bundle_root);
    prepared
}

/// Rewrite the acceptance bundle so one requirement issues under the
/// holder-bound mode, with both permission halves present: the bundle and the
/// one matched grant permit the serialization the mode allows, and the grant
/// names the mode itself.
async fn holder_bound_acceptance() -> PreparedAcceptance {
    let prepared = prepare_acceptance("subject-binding-secret-canary-32-bytes-minimum").await;
    make_writable(&prepared.bundle_root);
    let configuration_path = prepared.bundle_root.join("evidence.yaml");
    let mut configuration =
        fs::read_to_string(&configuration_path).expect("acceptance configuration is readable");
    replace_exact(
        &mut configuration,
        "\nresponseFormats: [signed-jws, unsigned-json]",
        "\nresponseFormats: [signed-jws, unsigned-json, sd-jwt-vc]",
        1,
    );
    replace_exact(
        &mut configuration,
        "purpose: fixture-eligibility\n        audienceFrom: authenticated-requester\n        responseFormats: [signed-jws, unsigned-json]",
        "purpose: fixture-eligibility\n        audienceFrom: authenticated-requester\n        responseFormats: [signed-jws, unsigned-json, sd-jwt-vc]\n        subjectBindingModes: [holder-bound]",
        1,
    );
    replace_exact(
        &mut configuration,
        "  - handle: adult-status\n    id: urn:example:fixture:requirement:adult-status:v1\n    kind: criterion",
        "  - handle: adult-status\n    id: urn:example:fixture:requirement:adult-status:v1\n    kind: criterion\n    subjectBinding: holder-bound",
        1,
    );
    fs::write(&configuration_path, &configuration).expect("test configuration is rewritten");
    regenerate_discovery_description(&prepared.bundle_root);
    make_read_only(&prepared.bundle_root);
    prepared
}

#[tokio::test]
async fn a_missing_holder_key_is_answered_after_authorization_not_before_it() {
    let prepared = holder_bound_acceptance().await;
    let runtime = runtime_for(&prepared).await;
    // No source is mounted: nothing here may reach acquisition.
    let http = TestServer::new(build_app(Arc::clone(&runtime)));
    let body = serde_json::to_value(adult_request()).expect("request serializes");

    // A requester no grant covers must not learn that this requirement is
    // holder-bound. Answering the missing holder key here would turn the
    // endpoint into an unauthenticated requirement-existence oracle.
    let unmatched = http
        .post("/v1/evidence")
        .add_header(
            "authorization",
            format!(
                "Bearer {}",
                access_token(Some(json!({"evidence_tags": ["unmatched-agency"]})))
            ),
        )
        .add_header("accept", EVIDENCE_SD_JWT_VC_MEDIA_TYPE)
        .json(&body)
        .await;
    assert_eq!(unmatched.status_code(), axum::http::StatusCode::FORBIDDEN);
    assert_eq!(unmatched.json::<Value>()["code"], json!("evidence.denied"));

    // An authorized requester asking for a serialization the mode does not
    // permit gets the same single denial. It never says which of the bundle
    // permission, the grant permission, or the mode allowlist withheld it.
    let wrong_format = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .json(&body)
        .await;
    assert_eq!(
        wrong_format.status_code(),
        axum::http::StatusCode::FORBIDDEN
    );
    assert_eq!(
        wrong_format.json::<Value>()["code"],
        json!("evidence.denied")
    );

    // The two denials came from different layers, and the caller cannot tell
    // them apart. The bodies are compared whole, not just the code, because a
    // title or a type that differed by layer would be the same oracle. The
    // per-request trace ID is the one member expected to vary, so it is
    // removed rather than assumed equal.
    let mut authorization_denial = unmatched.json::<Value>();
    let mut format_denial = wrong_format.json::<Value>();
    for denial in [&mut authorization_denial, &mut format_denial] {
        denial
            .as_object_mut()
            .expect("a problem body is an object")
            .remove("traceId");
    }
    assert_eq!(
        authorization_denial, format_denial,
        "the denial says which layer withheld the response"
    );
    let rendered = serde_json::to_string(&format_denial).expect("the denial serializes");
    for layer in ["holder", "binding", "format", "grant", "serialization"] {
        assert!(
            !rendered.contains(layer),
            "the denial names the layer that withheld the response"
        );
    }

    // Only past both gates does the missing holder key become the answer.
    let malformed = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .add_header("accept", EVIDENCE_SD_JWT_VC_MEDIA_TYPE)
        .json(&body)
        .await;
    assert_eq!(malformed.status_code(), axum::http::StatusCode::BAD_REQUEST);
    assert_eq!(
        malformed.json::<Value>()["code"],
        json!("evidence.invalid_request")
    );

    assert!(
        prepared
            .server
            .received_requests()
            .await
            .expect("request journal is available")
            .is_empty(),
        "a holder-bound request without a holder key reached acquisition"
    );
    let audit = fs::read_to_string(&prepared.audit_path).expect("audit is readable");
    assert!(
        !audit.contains("holder-key"),
        "the audit chain names the withheld request member"
    );
    for canary in privacy_canaries() {
        assert!(!audit.contains(canary));
    }
}

#[tokio::test]
async fn a_holder_bound_requirement_binds_its_subjects_under_the_presented_key() {
    let prepared = holder_bound_acceptance().await;
    let runtime = runtime_for(&prepared).await;
    mount_adult_source_expecting(&prepared.server, None, 2).await;
    let http = TestServer::new(build_app(Arc::clone(&runtime)));
    let request = adult_request();
    let mut body = serde_json::to_value(&request).expect("request serializes");

    // Two holders ask for the same assertion about the same subject. If the
    // deployment still derived every binding under the authenticated audience,
    // the two bindings would be equal and one relying party could correlate
    // the two holders' credentials.
    let mut bindings = Vec::new();
    for holder_key in [
        json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4",
            "y": "GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU"
        }),
        json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
            "y": "x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0"
        }),
    ] {
        body["holderKeys"] = json!([holder_key]);
        body["requestNonce"] = json!(fresh_request_nonce());
        let released = http
            .post("/v1/evidence")
            .add_header("authorization", format!("Bearer {}", access_token(None)))
            .add_header("accept", EVIDENCE_SD_JWT_VC_MEDIA_TYPE)
            .json(&body)
            .await;
        released.assert_status_ok();

        // The issued credential is the SD-JWT VC serialization, whose issuer
        // signed payload carries the subject bindings this mode derived.
        let credential = released.text();
        let payload = credential
            .split('.')
            .nth(1)
            .expect("the credential has a payload segment");
        let payload = URL_SAFE_NO_PAD
            .decode(payload.split('~').next().expect("the payload ends the JWS"))
            .expect("payload decodes");
        let payload: Value = serde_json::from_slice(&payload).expect("payload parses");
        let binding = payload["subjects"][0]["binding"]
            .as_str()
            .expect("the assertion binds its subject")
            .to_owned();
        bindings.push(binding);
    }

    assert_eq!(bindings.len(), 2);
    assert_ne!(
        bindings[0], bindings[1],
        "two holders received the same subject binding for one subject"
    );

    let audit = fs::read_to_string(&prepared.audit_path).expect("audit is readable");
    assert!(
        !audit.contains("3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4"),
        "the audit chain records holder key material"
    );
    for binding in &bindings {
        assert!(
            !audit.contains(binding.as_str()),
            "the audit chain records a released subject binding"
        );
    }
    for canary in privacy_canaries() {
        assert!(!audit.contains(canary));
    }
}

/// A released assertion must declare the mode it was actually derived under.
///
/// The bindings and the declared mode come from two different places in
/// issuance, so they can disagree: a deployment can derive every binding under
/// the presented holder key and still stamp the payload `audience-scoped`,
/// leaving a relying party comparing a pinned holder-bound binding against an
/// assertion that claims to be scoped to it. That contradiction is invisible
/// to a test that only inspects the bindings, so this asserts the payload's
/// own account of itself.
#[tokio::test]
async fn a_holder_bound_release_declares_the_mode_it_was_derived_under() {
    let prepared = holder_bound_acceptance().await;
    let runtime = runtime_for(&prepared).await;
    mount_adult_source_expecting(&prepared.server, None, 1).await;
    let http = TestServer::new(build_app(Arc::clone(&runtime)));
    let mut body = serde_json::to_value(adult_request()).expect("request serializes");
    body["holderKeys"] = json!([{
        "kty": "EC",
        "crv": "P-256",
        "x": "3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4",
        "y": "GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU"
    }]);

    let released = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .add_header("accept", EVIDENCE_SD_JWT_VC_MEDIA_TYPE)
        .json(&body)
        .await;
    released.assert_status_ok();

    let credential = released.text();
    let payload = credential
        .split('.')
        .nth(1)
        .expect("the credential has a payload segment");
    let payload = URL_SAFE_NO_PAD
        .decode(payload.split('~').next().expect("the payload ends the JWS"))
        .expect("payload decodes");
    let payload: Value = serde_json::from_slice(&payload).expect("payload parses");

    assert_eq!(
        payload["subjectBinding"], "holder-bound",
        "the released assertion declares a mode its bindings do not match"
    );
    assert!(
        payload.get("audience").is_none(),
        "a holder-bound assertion named a relying party"
    );
    assert!(
        payload.get("requestNonce").is_none(),
        "a holder-bound assertion echoed a request nonce it has no verifier to echo to"
    );
    assert!(
        payload["subjects"][0]["binding"]
            .as_str()
            .expect("the assertion binds its subject")
            .starts_with("urn:evidence:subject:"),
        "the assertion carries no subject binding"
    );
}

/// Under this mode the binding is derived from the presented key, so it must
/// not move with whoever asked for it.
///
/// The sibling test above proves two holders get different bindings. That is
/// still satisfied by a deployment that mixed the requester into the
/// derivation, and such a deployment would be badly broken: the same holder
/// collecting the same assertion through two relying parties would hold two
/// unequal bindings, and a relying party could poison a holder's binding
/// simply by asking under its own identity. This asks twice under one key and
/// two different authenticated requesters.
#[tokio::test]
async fn a_holder_bound_binding_does_not_move_with_the_requesting_relying_party() {
    let prepared = holder_bound_acceptance().await;
    let runtime = runtime_for(&prepared).await;
    mount_adult_source_expecting(&prepared.server, None, 2).await;
    let http = TestServer::new(build_app(Arc::clone(&runtime)));
    let mut body = serde_json::to_value(adult_request()).expect("request serializes");
    body["holderKeys"] = json!([{
        "kty": "EC",
        "crv": "P-256",
        "x": "3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4",
        "y": "GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU"
    }]);

    let mut bindings = Vec::new();
    for audience in [
        EVIDENCE_AUDIENCE,
        "https://second-relying.invalid/procedure",
    ] {
        body["requestNonce"] = json!(fresh_request_nonce());
        let token = access_token(Some(json!({"evidence_audience": audience})));
        let released = http
            .post("/v1/evidence")
            .add_header("authorization", format!("Bearer {token}"))
            .add_header("accept", EVIDENCE_SD_JWT_VC_MEDIA_TYPE)
            .json(&body)
            .await;
        released.assert_status_ok();
        let payload = released_credential_payload(&released.text());
        assert!(
            payload.get("audience").is_none(),
            "a holder-bound assertion named the requester"
        );
        bindings.push(
            payload["subjects"][0]["binding"]
                .as_str()
                .expect("the assertion binds its subject")
                .to_owned(),
        );
    }

    assert_eq!(
        bindings[0], bindings[1],
        "one holder received two bindings because the requester entered the derivation"
    );

    // Control. The equality above is only evidence of anything if the two
    // requesters were genuinely different to this deployment, so the same two
    // tokens are put through the audience-scoped path, where the requester is
    // what the binding is derived from. Those bindings must differ.
    let audience_scoped = sd_jwt_vc_acceptance(true).await;
    let runtime = runtime_for(&audience_scoped).await;
    mount_adult_source_expecting(&audience_scoped.server, None, 2).await;
    let http = TestServer::new(build_app(Arc::clone(&runtime)));
    let mut scoped_bindings = Vec::new();
    for audience in [
        EVIDENCE_AUDIENCE,
        "https://second-relying.invalid/procedure",
    ] {
        let body = serde_json::to_value(adult_request()).expect("request serializes");
        let token = access_token(Some(json!({"evidence_audience": audience})));
        let released = http
            .post("/v1/evidence")
            .add_header("authorization", format!("Bearer {token}"))
            .add_header("accept", EVIDENCE_SD_JWT_VC_MEDIA_TYPE)
            .json(&body)
            .await;
        released.assert_status_ok();
        let payload = released_credential_payload(&released.text());
        assert_eq!(
            payload["audience"],
            json!(audience),
            "the deployment did not read the requester from the presented token"
        );
        scoped_bindings.push(
            payload["subjects"][0]["binding"]
                .as_str()
                .expect("the assertion binds its subject")
                .to_owned(),
        );
    }
    assert_ne!(
        scoped_bindings[0], scoped_bindings[1],
        "the two requesters were indistinguishable, so the equality above proves nothing"
    );
}

/// A refusal pseudonym stays audience-scoped whatever mode the requirement the
/// caller was reaching for declares.
///
/// A refusal can be written before any requirement has been matched, so the
/// declared mode is not in scope when one is recorded. Deriving it without the
/// requester's audience would hand every relying party the same durable name
/// for one denied principal, which is a cross-audience identifier the mode
/// exists to prevent. The same principal asks the same holder-bound
/// requirement for a purpose no grant permits, under two audiences.
#[tokio::test]
async fn a_holder_bound_refusal_pseudonym_does_not_follow_the_principal_across_audiences() {
    const PRINCIPAL: &str = "holder-bound-refusal-principal-canary";
    const ACTOR: &str = "holder-bound-refusal-actor-canary";
    const REFUSED_PURPOSE: &str = "refused-holder-bound-purpose";
    const SECOND_AUDIENCE: &str = "https://second-relying.invalid/procedure";

    let prepared = holder_bound_acceptance().await;
    let runtime = Arc::new(
        EvidenceRuntime::initialize_with_authenticator(
            &prepared.runtime_path,
            authenticator_with_actor_claim("evidence_actor"),
        )
        .await
        .expect("runtime initializes with an actor claim"),
    );
    // No source is mounted: a refused request may reach no acquisition.
    let http = TestServer::new(build_app(Arc::clone(&runtime)));
    let mut refused = adult_request();
    refused.purpose = REFUSED_PURPOSE.to_owned();
    let mut body = serde_json::to_value(refused).expect("request serializes");
    body["holderKeys"] = json!([{
        "kty": "EC",
        "crv": "P-256",
        "x": "3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4",
        "y": "GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU"
    }]);

    for audience in [EVIDENCE_AUDIENCE, SECOND_AUDIENCE, EVIDENCE_AUDIENCE] {
        body["requestNonce"] = json!(fresh_request_nonce());
        let token = access_token_for(
            PRINCIPAL,
            Some(json!({
                "evidence_actor": ACTOR,
                "evidence_audience": audience,
            })),
        );
        let response = http
            .post("/v1/evidence")
            .add_header("authorization", format!("Bearer {token}"))
            .add_header("accept", EVIDENCE_SD_JWT_VC_MEDIA_TYPE)
            .json(&body)
            .await;
        assert_eq!(response.status_code(), axum::http::StatusCode::FORBIDDEN);
    }
    assert!(prepared
        .server
        .received_requests()
        .await
        .expect("request journal is available")
        .is_empty());

    let audit = fs::read_to_string(&prepared.audit_path).expect("audit is readable");
    let requesters = pseudonyms_for_phase(&audit, "denial", "requesterPseudonym");
    let actors = pseudonyms_for_phase(&audit, "denial", "actorPseudonym");
    assert_eq!(
        requesters.len(),
        3,
        "every request must be refused in audit"
    );
    assert_eq!(actors.len(), 3, "every refusal must carry its actor");
    for (class, pseudonyms) in [("requester", requesters), ("actor", actors)] {
        assert_ne!(
            pseudonyms[0], pseudonyms[1],
            "one denied {class} carries the same refusal pseudonym to two relying parties"
        );
        assert_eq!(
            pseudonyms[0], pseudonyms[2],
            "one denied {class} does not keep a stable pseudonym within one relying party"
        );
    }
    for protected in [
        PRINCIPAL,
        ACTOR,
        REFUSED_PURPOSE,
        EVIDENCE_AUDIENCE,
        SECOND_AUDIENCE,
    ] {
        assert!(
            !audit.contains(protected),
            "a refusal retained protected request material"
        );
    }
}

/// A released holder-bound record is scoped to no relying party, so the
/// requester pseudonym on it must not vary with the audience that asked.
///
/// This is the deliberate property the audience-scoped refusal pseudonym sits
/// beside: making every derivation name the audience would be a quiet revert
/// of the mode's audit contract.
#[tokio::test]
async fn a_holder_bound_release_pseudonym_does_not_vary_with_the_relying_party() {
    const PRINCIPAL: &str = "holder-bound-release-principal-canary";
    const SECOND_AUDIENCE: &str = "https://second-relying.invalid/procedure";

    let prepared = holder_bound_acceptance().await;
    let runtime = runtime_for(&prepared).await;
    mount_adult_source_expecting(&prepared.server, None, 2).await;
    let http = TestServer::new(build_app(Arc::clone(&runtime)));
    let mut body = serde_json::to_value(adult_request()).expect("request serializes");
    body["holderKeys"] = json!([{
        "kty": "EC",
        "crv": "P-256",
        "x": "3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4",
        "y": "GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU"
    }]);

    for audience in [EVIDENCE_AUDIENCE, SECOND_AUDIENCE] {
        body["requestNonce"] = json!(fresh_request_nonce());
        let token = access_token_for(PRINCIPAL, Some(json!({"evidence_audience": audience})));
        let released = http
            .post("/v1/evidence")
            .add_header("authorization", format!("Bearer {token}"))
            .add_header("accept", EVIDENCE_SD_JWT_VC_MEDIA_TYPE)
            .json(&body)
            .await;
        released.assert_status_ok();
    }

    let audit = wait_for_audit_counts(&prepared.audit_path, 2, 2).await;
    let released = requester_pseudonyms_for_phase(&audit, "disclosure-release");
    assert_eq!(released.len(), 2);
    assert_eq!(
        released[0], released[1],
        "a holder-bound release record was scoped to the relying party that asked"
    );
}

fn requester_pseudonyms_for_phase(audit: &str, phase: &str) -> Vec<String> {
    pseudonyms_for_phase(audit, phase, "requesterPseudonym")
}

fn pseudonyms_for_phase(audit: &str, phase: &str, field: &str) -> Vec<String> {
    audit
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("audit line is JSON"))
        .filter(|event| event["record"]["phase"] == json!(phase))
        .map(|event| {
            event["record"][field]
                .as_str()
                .expect("audit pseudonym is text")
                .to_owned()
        })
        .collect()
}

/// A requirement that does not declare the mode serves the audience-scoped
/// path whatever the caller supplies.
///
/// The optional holder key is confirmed into an audience-scoped credential so
/// a wallet can still prove possession, and that confirmation must not be
/// mistaken for a request for the mode. If it were, a caller could reach
/// holder-bound issuance on a requirement no operator declared for it, simply
/// by attaching a key.
#[tokio::test]
async fn an_undeclared_requirement_serves_audience_scoped_whatever_the_caller_supplies() {
    let prepared = sd_jwt_vc_acceptance(true).await;
    let runtime = runtime_for(&prepared).await;
    mount_adult_source_expecting(&prepared.server, None, 2).await;
    let http = TestServer::new(build_app(Arc::clone(&runtime)));
    let holder_key = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4",
        "y": "GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU"
    });

    let mut with_key = serde_json::to_value(adult_request()).expect("request serializes");
    with_key["holderKeys"] = json!([holder_key.clone()]);
    let mut bindings = Vec::new();
    for body in [
        &with_key,
        &serde_json::to_value(adult_request()).expect("request serializes"),
    ] {
        let released = http
            .post("/v1/evidence")
            .add_header("authorization", format!("Bearer {}", access_token(None)))
            .add_header("accept", EVIDENCE_SD_JWT_VC_MEDIA_TYPE)
            .json(body)
            .await;
        released.assert_status_ok();
        let payload = released_credential_payload(&released.text());
        assert_eq!(
            payload["subjectBinding"], "audience-scoped",
            "an undeclared requirement issued under the mode because a key was attached"
        );
        assert_eq!(
            payload["audience"],
            json!(EVIDENCE_AUDIENCE),
            "an audience-scoped assertion did not name the party it is scoped to"
        );
        bindings.push(
            payload["subjects"][0]["binding"]
                .as_str()
                .expect("the assertion binds its subject")
                .to_owned(),
        );
    }

    assert_eq!(
        bindings[0], bindings[1],
        "attaching a key changed which scope the binding was derived under"
    );
}

/// Key material reaches exactly one place: the confirmation the issuer signs.
///
/// The public confirmation is the point of the mode and is disclosed on
/// purpose, so the property is confinement, not absence. Everything the
/// deployment emits outward or records durably must be free of it, including
/// the requests the configured scripts prepare: those scripts run between the
/// request and the source, so a script that could read the presented key would
/// have to place it in an outbound request to use it.
#[tokio::test]
async fn holder_key_material_reaches_only_the_signed_confirmation() {
    const HOLDER_X: &str = "3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4";
    const HOLDER_Y: &str = "GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU";
    const HOLDER_KID: &str = "holder-owned-key-name-canary";

    let prepared = holder_bound_acceptance().await;
    let runtime = runtime_for(&prepared).await;
    mount_adult_source_expecting(&prepared.server, None, 1).await;
    let http = TestServer::new(build_app(Arc::clone(&runtime)));
    let mut body = serde_json::to_value(adult_request()).expect("request serializes");
    body["holderKeys"] = json!([{
        "kty": "EC",
        "crv": "P-256",
        "x": HOLDER_X,
        "y": HOLDER_Y,
        "kid": HOLDER_KID
    }]);

    let released = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .add_header("accept", EVIDENCE_SD_JWT_VC_MEDIA_TYPE)
        .json(&body)
        .await;
    released.assert_status_ok();
    let payload = released_credential_payload(&released.text());
    assert_eq!(
        payload["cnf"]["jwk"]["x"],
        json!(HOLDER_X),
        "the confirmation does not carry the presented public key"
    );
    assert_eq!(payload["cnf"]["jwk"]["y"], json!(HOLDER_Y));
    assert!(
        payload["cnf"]["jwk"].get("d").is_none(),
        "the confirmation carries a private member"
    );

    let material = [HOLDER_X, HOLDER_Y, HOLDER_KID];
    for request in prepared
        .server
        .received_requests()
        .await
        .expect("request journal is available")
    {
        let sent = String::from_utf8_lossy(&request.body).into_owned();
        let headers = format!("{:?}", request.headers);
        let url = request.url.to_string();
        for value in material {
            assert!(
                !sent.contains(value),
                "an outbound request body carried key material"
            );
            assert!(
                !headers.contains(value),
                "an outbound header carried key material"
            );
            assert!(
                !url.contains(value),
                "an outbound target carried key material"
            );
        }
    }

    let audit = wait_for_audit_counts(&prepared.audit_path, 1, 1).await;
    for value in material {
        assert!(
            !audit.contains(value),
            "the audit chain records presented key material"
        );
    }
    for canary in privacy_canaries() {
        assert!(!audit.contains(canary));
    }
}

/// The committed holder-bound acceptance bundle, served as it is committed.
///
/// The tests above rewrite the audience-scoped bundle in memory to reach the
/// mode, which proves the runtime but says nothing about whether a bundle an
/// adopter could copy declares it correctly. This serves the tracked fixture
/// unchanged apart from the deployment-only rewrites every fixture takes.
async fn holder_bound_acceptance_bundle(ceilings: &FixtureCeilings) -> PreparedAcceptance {
    let server = MockServer::start().await;
    let prepared = prepare_fixture_root_with_mutation(
        &holder_bound_fixture_root(),
        "subject-binding-secret-canary-32-bytes-minimum",
        &server.uri(),
        ceilings,
        |_| {},
    );
    PreparedAcceptance {
        temporary: prepared.temporary,
        bundle_root: prepared.bundle_root,
        runtime_path: prepared.runtime_path,
        server,
        audit_path: prepared.audit_path,
    }
}

/// Decode the issuer-signed payload of a released SD-JWT VC.
fn released_credential_payload(credential: &str) -> Value {
    let payload = credential
        .split('.')
        .nth(1)
        .expect("the credential has a payload segment");
    let payload = URL_SAFE_NO_PAD
        .decode(payload.split('~').next().expect("the payload ends the JWS"))
        .expect("payload decodes");
    serde_json::from_slice(&payload).expect("payload parses")
}

/// Adult status, residence region, professional licence status, and the
/// legal-parent relationship are coequal, so the holder-bound mode is not one
/// definition's feature. Each of the four is asked for from the committed
/// holder-bound bundle over the full served path, and each must come back
/// bound to the presented key rather than to the requester.
#[tokio::test]
async fn every_coequal_definition_issues_under_the_holder_bound_mode() {
    let prepared = holder_bound_acceptance_bundle(&FixtureCeilings::deployment_defaults()).await;
    let runtime = runtime_for(&prepared).await;
    mount_success_sources(&prepared.server, true).await;
    let http = TestServer::new(build_app(Arc::clone(&runtime)));
    let holder_key = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4",
        "y": "GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU"
    });

    let mut bindings = Vec::new();
    for (token, request) in [
        (access_token(None), adult_request()),
        (access_token(None), residence_request()),
        (access_token(None), licence_request()),
        (access_token(Some(parent_grant_claims())), parent_request()),
    ] {
        let requirement = request.requirement.clone();
        let mut body = serde_json::to_value(&request).expect("request serializes");
        body["holderKeys"] = json!([holder_key]);

        let released = http
            .post("/v1/evidence")
            .add_header("authorization", format!("Bearer {token}"))
            .add_header("accept", EVIDENCE_SD_JWT_VC_MEDIA_TYPE)
            .json(&body)
            .await;
        assert_eq!(
            released.status_code(),
            axum::http::StatusCode::OK,
            "{requirement}"
        );

        let payload = released_credential_payload(&released.text());
        assert_eq!(
            payload["subjectBinding"], "holder-bound",
            "{requirement} declares a mode it was not derived under"
        );
        assert!(
            payload.get("audience").is_none(),
            "{requirement} named a relying party"
        );
        assert!(
            payload.get("requestNonce").is_none(),
            "{requirement} echoed a request nonce it has no verifier to echo to"
        );
        for subject in payload["subjects"]
            .as_array()
            .expect("the assertion binds its subjects")
        {
            let binding = subject["binding"]
                .as_str()
                .expect("the subject carries a binding")
                .to_owned();
            assert!(
                binding.starts_with("urn:evidence:subject:"),
                "{requirement}"
            );
            bindings.push(binding);
        }
    }

    // One holder, four definitions, five subject roles in total. Every binding
    // is distinct: the holder key scopes the derivation, it does not collapse
    // subjects or definitions onto one identifier a relying party could join on.
    assert_eq!(bindings.len(), 5);
    let distinct: std::collections::BTreeSet<&String> = bindings.iter().collect();
    assert_eq!(
        distinct.len(),
        bindings.len(),
        "two holder-bound subjects share a binding"
    );

    let audit = fs::read_to_string(&prepared.audit_path).expect("audit is readable");
    assert!(
        !audit.contains("3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4"),
        "the audit chain records holder key material"
    );
    for binding in &bindings {
        assert!(
            !audit.contains(binding.as_str()),
            "the audit chain records a released subject binding"
        );
    }
    for canary in privacy_canaries() {
        assert!(!audit.contains(canary));
    }
}

/// The committed holder-bound bundle must refuse every serialization that
/// cannot carry a holder key confirmation, for every one of its definitions.
///
/// The mode allowlist and the bundle's own format list are two separate gates,
/// and a bundle could satisfy one while leaving the other open. Asking for each
/// governed non-SD-JWT-VC serialization, on each definition, is what shows the
/// tracked fixture closes both.
#[tokio::test]
async fn the_holder_bound_acceptance_bundle_serves_no_unconfirmed_serialization() {
    let prepared = holder_bound_acceptance_bundle(&FixtureCeilings::deployment_defaults()).await;
    let runtime = runtime_for(&prepared).await;
    // No source is mounted: nothing here may reach acquisition.
    let http = TestServer::new(build_app(Arc::clone(&runtime)));
    let holder_key = json!({
        "kty": "EC",
        "crv": "P-256",
        "x": "3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4",
        "y": "GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU"
    });

    for (token, request) in [
        (access_token(None), adult_request()),
        (access_token(None), residence_request()),
        (access_token(None), licence_request()),
        (access_token(Some(parent_grant_claims())), parent_request()),
    ] {
        let requirement = request.requirement.clone();
        let mut body = serde_json::to_value(&request).expect("request serializes");
        body["holderKeys"] = json!([holder_key]);
        for accept in ["application/jose+json", EVIDENCE_UNSIGNED_MEDIA_TYPE] {
            let refused = http
                .post("/v1/evidence")
                .add_header("authorization", format!("Bearer {token}"))
                .add_header("accept", accept)
                .json(&body)
                .await;
            assert_eq!(
                refused.status_code(),
                axum::http::StatusCode::FORBIDDEN,
                "{requirement} served {accept}"
            );
            assert_eq!(
                refused.json::<Value>()["code"],
                json!("evidence.denied"),
                "{requirement} explained which gate withheld {accept}"
            );
        }
    }

    assert!(
        prepared
            .server
            .received_requests()
            .await
            .expect("request journal is available")
            .is_empty(),
        "a refused serialization reached acquisition"
    );
}

/// The committed bundle enables the batch container and declares its own
/// ceiling, so both halves of that declaration are exercised on every one of
/// its definitions: a batch at the ceiling releases one independently bound
/// credential per key from one acquisition, and a batch above it is refused
/// before any source is reached.
#[tokio::test]
async fn the_holder_bound_acceptance_bundle_batches_every_definition_under_its_ceiling() {
    const DECLARED_CEILING: usize = 4;
    // A batch request costs one unit per presented key, and this walks four
    // definitions twice, so the tracked per-principal ceiling would answer 429
    // before the last definition was reached. Lifting the rate ceiling alone
    // keeps every other ceiling, the batch ceiling included, exactly as the
    // bundle declares it.
    let prepared = holder_bound_acceptance_bundle(&FixtureCeilings {
        requests_per_principal_per_minute: 1_000,
        burst_per_principal: 1_000,
        ..FixtureCeilings::deployment_defaults()
    })
    .await;
    let runtime = runtime_for(&prepared).await;
    let http = TestServer::new(build_app(Arc::clone(&runtime)));
    let cases = || {
        [
            (access_token(None), adult_request()),
            (access_token(None), residence_request()),
            (access_token(None), licence_request()),
            (access_token(Some(parent_grant_claims())), parent_request()),
        ]
    };

    // Above the ceiling first, while no source is mounted at all: a refusal
    // that reached acquisition would be caught by the mock expectations below.
    for (token, request) in cases() {
        let requirement = request.requirement.clone();
        let mut body = serde_json::to_value(&request).expect("request serializes");
        body["holderKeys"] = batch_holder_keys(DECLARED_CEILING + 1);
        let refused = http
            .post("/v1/evidence")
            .add_header("authorization", format!("Bearer {token}"))
            .add_header("accept", EVIDENCE_SD_JWT_VC_BATCH_MEDIA_TYPE)
            .json(&body)
            .await;
        assert_eq!(
            refused.status_code(),
            axum::http::StatusCode::BAD_REQUEST,
            "{requirement} released a batch above the declared ceiling"
        );
        assert_eq!(
            refused.json::<Value>()["code"],
            json!("evidence.invalid_request")
        );
    }
    assert!(
        prepared
            .server
            .received_requests()
            .await
            .expect("request journal is available")
            .is_empty(),
        "a batch above the ceiling reached acquisition"
    );

    // Each source expects exactly one call, so a batch that re-read its source
    // once per member would fail here rather than merely be slow.
    mount_success_sources(&prepared.server, true).await;
    let mut bindings = BTreeSet::new();
    for (token, request) in cases() {
        let requirement = request.requirement.clone();
        let mut body = serde_json::to_value(&request).expect("request serializes");
        body["holderKeys"] = batch_holder_keys(DECLARED_CEILING);
        let released = http
            .post("/v1/evidence")
            .add_header("authorization", format!("Bearer {token}"))
            .add_header("accept", EVIDENCE_SD_JWT_VC_BATCH_MEDIA_TYPE)
            .json(&body)
            .await;
        assert_eq!(
            released.status_code(),
            axum::http::StatusCode::OK,
            "{requirement}"
        );
        let envelope: SdJwtVcBatchEnvelope =
            serde_json::from_str(&released.text()).expect("the batch envelope parses strictly");
        assert_eq!(
            envelope.credentials.len(),
            DECLARED_CEILING,
            "{requirement}"
        );
        for credential in &envelope.credentials {
            let payload = released_credential_payload(credential);
            assert_eq!(payload["subjectBinding"], "holder-bound", "{requirement}");
            for subject in payload["subjects"]
                .as_array()
                .expect("the member binds its subjects")
            {
                assert!(
                    bindings.insert(
                        subject["binding"]
                            .as_str()
                            .expect("the subject carries a binding")
                            .to_owned()
                    ),
                    "{requirement} reused a subject binding across members"
                );
            }
        }
    }
    // Five subject roles across the four definitions, each bound once per key.
    assert_eq!(bindings.len(), 5 * DECLARED_CEILING);
}

/// Distinct P-256 public keys for batch tests, as `(x, y)` coordinate pairs.
///
/// Each pair is a real curve point, because an unacceptable key is refused at
/// the request boundary and would never reach the release path under test.
const BATCH_HOLDER_COORDINATES: [(&str, &str); 5] = [
    (
        "rVMhRw_AQKeDul4F-iEv56CtlyJKrM6u5xi2bFAUq_4",
        "5zdn5gQRuii0hVTzcJ4hWlURtMYeQk3OGREcRy9v1ps",
    ),
    (
        "RGUpcejDhxZcjveUXQ_f5ROhMoVgUsZA8lAQgGj_p_c",
        "qGIQUPRR3_DU1U4AtI9TTqsxy5sVZFYQe3S1whoMCVQ",
    ),
    (
        "Kh89S0sAKyna9LcIUwqbidX9F2fYAfEHo9yVnjnxz_8",
        "g_V0Cd3L9dBM6mV3A2opGUcpiLsUlZEYgGMlvy-BLlE",
    ),
    (
        "uqIQI6Dojkugmah66LioTMR7_sk3aXzk0KtJMnz1PVU",
        "HW2NBVGRGvpxY0FUpGZ_h8_XU3V9bw7jX9dHej5iZSI",
    ),
    (
        "xEbuhghflHAoU0cPEgzL4ShMhbE4u375LGbQwHPqJn0",
        "vnEhUQHqVftrRfQ1Ro76ShfRsmXNAG3xJf_-_jmflzs",
    ),
];

fn batch_holder_keys(count: usize) -> Value {
    Value::Array(
        BATCH_HOLDER_COORDINATES
            .iter()
            .take(count)
            .map(|(x, y)| json!({"kty": "EC", "crv": "P-256", "x": x, "y": y}))
            .collect(),
    )
}

/// Rewrite the acceptance bundle so the holder-bound requirement may also be
/// released as a batch, under the declared ceiling.
async fn holder_bound_batch_acceptance(ceiling: u16) -> PreparedAcceptance {
    let prepared = prepare_acceptance("subject-binding-secret-canary-32-bytes-minimum").await;
    make_writable(&prepared.bundle_root);
    let configuration_path = prepared.bundle_root.join("evidence.yaml");
    let mut configuration =
        fs::read_to_string(&configuration_path).expect("acceptance configuration is readable");
    replace_exact(
        &mut configuration,
        "\nresponseFormats: [signed-jws, unsigned-json]",
        &format!(
            "\nresponseFormats: [signed-jws, unsigned-json, sd-jwt-vc, sd-jwt-vc-batch]\nholderBoundBatchMaxSize: {ceiling}"
        ),
        1,
    );
    replace_exact(
        &mut configuration,
        "purpose: fixture-eligibility\n        audienceFrom: authenticated-requester\n        responseFormats: [signed-jws, unsigned-json]",
        "purpose: fixture-eligibility\n        audienceFrom: authenticated-requester\n        responseFormats: [signed-jws, unsigned-json, sd-jwt-vc, sd-jwt-vc-batch]\n        subjectBindingModes: [holder-bound]",
        1,
    );
    replace_exact(
        &mut configuration,
        "  - handle: adult-status\n    id: urn:example:fixture:requirement:adult-status:v1\n    kind: criterion",
        "  - handle: adult-status\n    id: urn:example:fixture:requirement:adult-status:v1\n    kind: criterion\n    subjectBinding: holder-bound",
        1,
    );
    fs::write(&configuration_path, &configuration).expect("test configuration is rewritten");
    regenerate_discovery_description(&prepared.bundle_root);
    make_read_only(&prepared.bundle_root);
    prepared
}

/// One batch release carries exactly one independent credential per presented
/// key, over exactly one source acquisition and one terminal release record.
#[tokio::test]
async fn a_batch_release_issues_one_independent_credential_for_each_presented_key() {
    let prepared = holder_bound_batch_acceptance(4).await;
    let runtime = runtime_for(&prepared).await;
    // The whole point of evaluating once: three credentials, one source read.
    mount_adult_source_expecting(&prepared.server, None, 1).await;
    let http = TestServer::new(build_app(Arc::clone(&runtime)));
    let mut body = serde_json::to_value(adult_request()).expect("request serializes");
    body["holderKeys"] = batch_holder_keys(3);

    let released = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .add_header("accept", EVIDENCE_SD_JWT_VC_BATCH_MEDIA_TYPE)
        .json(&body)
        .await;
    released.assert_status_ok();
    assert_eq!(
        released.header("content-type"),
        EVIDENCE_SD_JWT_VC_BATCH_MEDIA_TYPE
    );

    let envelope: SdJwtVcBatchEnvelope =
        serde_json::from_str(&released.text()).expect("the batch envelope parses strictly");
    assert_eq!(envelope.schema, SD_JWT_VC_BATCH_SCHEMA_V1);
    assert_eq!(envelope.credentials.len(), 3);

    let mut bindings = BTreeSet::new();
    let mut identifiers = BTreeSet::new();
    let mut confirmations = BTreeSet::new();
    let mut disclosures = BTreeSet::new();
    for credential in &envelope.credentials {
        let mut segments = credential.split('~');
        let issued = segments.next().expect("a credential carries its JWS");
        for disclosure in segments.filter(|segment| !segment.is_empty()) {
            assert!(
                disclosures.insert(disclosure.to_owned()),
                "two members reused one disclosure salt"
            );
        }
        let payload = URL_SAFE_NO_PAD
            .decode(issued.split('.').nth(1).expect("the JWS has a payload"))
            .expect("payload decodes");
        let payload: Value = serde_json::from_slice(&payload).expect("payload parses");
        assert_eq!(payload["subjectBinding"], "holder-bound");
        assert!(
            bindings.insert(
                payload["subjects"][0]["binding"]
                    .as_str()
                    .expect("the member binds its subject")
                    .to_owned()
            ),
            "two members carry one subject binding"
        );
        assert!(
            identifiers.insert(
                payload["jti"]
                    .as_str()
                    .expect("the member carries its own identifier")
                    .to_owned()
            ),
            "two members carry one identifier"
        );
        assert!(
            confirmations.insert(payload["cnf"]["jwk"]["x"].to_string()),
            "two members confirm one holder key"
        );
    }
    assert_eq!(bindings.len(), 3);
    assert_eq!(identifiers.len(), 3);
    assert_eq!(confirmations.len(), 3);

    // Exactly one terminal release event, naming the complete released set.
    let audit = wait_for_audit_counts(&prepared.audit_path, 1, 1).await;
    assert_eq!(audit.matches("\"phase\":\"disclosure-release\"").count(), 1);
    assert_eq!(audit.matches("\"evidenceIds\"").count(), 1);
    // A released set names itself once. The singular member and the plural one
    // are mutually exclusive, so a reader never counts one release twice.
    assert_eq!(audit.matches("\"evidenceId\":").count(), 0);
    for identifier in &identifiers {
        assert!(
            audit.contains(identifier.as_str()),
            "the release event omits a released member"
        );
    }
    for (x, _) in BATCH_HOLDER_COORDINATES {
        assert!(
            !audit.contains(x),
            "the audit chain records holder material"
        );
    }
    for canary in privacy_canaries() {
        assert!(!audit.contains(canary));
    }
}

/// A batch above the deployment's declared ceiling reaches no source.
#[tokio::test]
async fn a_batch_above_the_declared_ceiling_is_refused_before_source_access() {
    let prepared = holder_bound_batch_acceptance(2).await;
    let runtime = runtime_for(&prepared).await;
    let http = TestServer::new(build_app(Arc::clone(&runtime)));
    let mut body = serde_json::to_value(adult_request()).expect("request serializes");
    body["holderKeys"] = batch_holder_keys(3);

    let refused = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .add_header("accept", EVIDENCE_SD_JWT_VC_BATCH_MEDIA_TYPE)
        .json(&body)
        .await;
    assert_eq!(refused.status_code(), axum::http::StatusCode::BAD_REQUEST);
    assert_eq!(
        refused.json::<Value>()["code"],
        json!("evidence.invalid_request")
    );
    assert!(
        prepared
            .server
            .received_requests()
            .await
            .expect("request journal is available")
            .is_empty(),
        "a batch above the ceiling reached acquisition"
    );

    // The compile-time maximum bounds the request before the deployment's own
    // ceiling can be read at all.
    let mut oversized = serde_json::to_value(adult_request()).expect("request serializes");
    oversized["holderKeys"] = Value::Array(
        std::iter::repeat_n(
            json!({"kty": "EC", "crv": "P-256", "x": BATCH_HOLDER_COORDINATES[0].0, "y": BATCH_HOLDER_COORDINATES[0].1}),
            usize::from(MAXIMUM_HOLDER_BOUND_BATCH_SIZE) + 1,
        )
        .collect(),
    );
    let refused = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .add_header("accept", EVIDENCE_SD_JWT_VC_BATCH_MEDIA_TYPE)
        .json(&oversized)
        .await;
    assert_eq!(refused.status_code(), axum::http::StatusCode::BAD_REQUEST);
    assert_eq!(
        refused.json::<Value>()["code"],
        json!("evidence.invalid_request")
    );
}

/// Two keys that are distinct JSON but one key by RFC 7638 thumbprint would
/// silently collapse a batch to one holder, so they are refused outright.
#[tokio::test]
async fn a_repeated_holder_key_thumbprint_is_refused_before_source_access() {
    let prepared = holder_bound_batch_acceptance(4).await;
    let runtime = runtime_for(&prepared).await;
    let http = TestServer::new(build_app(Arc::clone(&runtime)));
    let (x, y) = BATCH_HOLDER_COORDINATES[0];

    for keys in [
        // Byte-identical members.
        json!([
            {"kty": "EC", "crv": "P-256", "x": x, "y": y},
            {"kty": "EC", "crv": "P-256", "x": x, "y": y},
        ]),
        // The same curve point under a wallet-chosen key identifier and a
        // declared algorithm. RFC 7638 excludes both members, so this is one
        // key wearing two names.
        json!([
            {"kty": "EC", "crv": "P-256", "x": x, "y": y, "kid": "wallet-a"},
            {"kty": "EC", "crv": "P-256", "x": x, "y": y, "kid": "wallet-b", "alg": "ES256"},
        ]),
    ] {
        let mut body = serde_json::to_value(adult_request()).expect("request serializes");
        body["holderKeys"] = keys;
        let refused = http
            .post("/v1/evidence")
            .add_header("authorization", format!("Bearer {}", access_token(None)))
            .add_header("accept", EVIDENCE_SD_JWT_VC_BATCH_MEDIA_TYPE)
            .json(&body)
            .await;
        assert_eq!(refused.status_code(), axum::http::StatusCode::BAD_REQUEST);
        assert_eq!(
            refused.json::<Value>()["code"],
            json!("evidence.invalid_request")
        );
    }

    assert!(
        prepared
            .server
            .received_requests()
            .await
            .expect("request journal is available")
            .is_empty(),
        "a repeated holder key reached acquisition"
    );
}

/// The singular credential media type carries exactly one holder key, and the
/// batch media type carries exactly one member per key.
#[tokio::test]
async fn the_singular_media_type_requires_exactly_one_holder_key() {
    let prepared = holder_bound_batch_acceptance(4).await;
    let runtime = runtime_for(&prepared).await;
    mount_adult_source_expecting(&prepared.server, None, 1).await;
    let http = TestServer::new(build_app(Arc::clone(&runtime)));

    let mut body = serde_json::to_value(adult_request()).expect("request serializes");
    body["holderKeys"] = batch_holder_keys(2);
    let refused = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .add_header("accept", EVIDENCE_SD_JWT_VC_MEDIA_TYPE)
        .json(&body)
        .await;
    assert_eq!(refused.status_code(), axum::http::StatusCode::BAD_REQUEST);
    assert_eq!(
        refused.json::<Value>()["code"],
        json!("evidence.invalid_request")
    );

    // One key is a batch of one, so the batch media type still serves it.
    let mut single = serde_json::to_value(adult_request()).expect("request serializes");
    single["holderKeys"] = batch_holder_keys(1);
    let released = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .add_header("accept", EVIDENCE_SD_JWT_VC_BATCH_MEDIA_TYPE)
        .json(&single)
        .await;
    released.assert_status_ok();
    let envelope: SdJwtVcBatchEnvelope =
        serde_json::from_str(&released.text()).expect("the batch envelope parses strictly");
    assert_eq!(envelope.credentials.len(), 1);

    // A release of one assertion names it in the singular audit member, so a
    // reader can never count one release twice.
    let audit = wait_for_audit_counts(&prepared.audit_path, 1, 1).await;
    assert_eq!(audit.matches("\"evidenceIds\"").count(), 0);
    assert_eq!(audit.matches("\"evidenceId\":").count(), 1);
}

/// Keyless audience-scoped SD-JWT VC issuance predates the holder key and is
/// unchanged by it, and one key is still only echoed into the confirmation
/// claim. The singular serialization answers at most one key in either binding
/// mode, so a request naming several is refused rather than answered in part.
#[tokio::test]
async fn audience_scoped_credential_issuance_answers_at_most_one_holder_key() {
    let prepared = sd_jwt_vc_acceptance(true).await;
    let runtime = runtime_for(&prepared).await;
    mount_adult_source_expecting(&prepared.server, None, 2).await;
    let http = TestServer::new(build_app(Arc::clone(&runtime)));

    // No holder key at all: the historic keyless path.
    let keyless = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .add_header("accept", EVIDENCE_SD_JWT_VC_MEDIA_TYPE)
        .json(&serde_json::to_value(adult_request()).expect("request serializes"))
        .await;
    keyless.assert_status_ok();
    assert!(!keyless.text().contains("cnf"));

    // One key, echoed into the confirmation without changing the binding mode.
    let mut body = serde_json::to_value(adult_request()).expect("request serializes");
    body["holderKeys"] = batch_holder_keys(1);
    let confirmed = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .add_header("accept", EVIDENCE_SD_JWT_VC_MEDIA_TYPE)
        .json(&body)
        .await;
    confirmed.assert_status_ok();
    let credential = confirmed.text();
    let payload = URL_SAFE_NO_PAD
        .decode(
            credential
                .split('~')
                .next()
                .expect("the credential carries its JWS")
                .split('.')
                .nth(1)
                .expect("the JWS has a payload"),
        )
        .expect("payload decodes");
    let payload: Value = serde_json::from_slice(&payload).expect("payload parses");
    assert_eq!(payload["subjectBinding"], "audience-scoped");
    assert_eq!(
        payload["cnf"]["jwk"]["x"],
        json!(BATCH_HOLDER_COORDINATES[0].0)
    );

    // An audience-scoped requirement may not take the batch serialization at
    // all: the envelope exists to carry one member per holder key.
    let batch = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .add_header("accept", EVIDENCE_SD_JWT_VC_BATCH_MEDIA_TYPE)
        .json(&body)
        .await;
    assert_eq!(batch.status_code(), axum::http::StatusCode::FORBIDDEN);
    assert_eq!(batch.json::<Value>()["code"], json!("evidence.denied"));

    // Two keys under a singular media type asks for two credentials over a
    // serialization that carries one. It is refused rather than answered for
    // the first key alone, and refused before the source is reached: the mock
    // is mounted for exactly the two acquisitions the requests above make.
    let mut crowded = serde_json::to_value(adult_request()).expect("request serializes");
    crowded["holderKeys"] = batch_holder_keys(2);
    let crowded = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .add_header("accept", EVIDENCE_SD_JWT_VC_MEDIA_TYPE)
        .json(&crowded)
        .await;
    assert_eq!(crowded.status_code(), axum::http::StatusCode::BAD_REQUEST);
    assert_eq!(
        crowded.json::<Value>()["code"],
        json!("evidence.invalid_request")
    );
}

/// There is no partial batch. A failure on any member releases nothing, and
/// the durable chain carries no terminal release record for the operation.
#[tokio::test]
async fn a_failure_on_a_later_batch_member_releases_nothing() {
    let prepared = holder_bound_batch_acceptance(4).await;
    let mut runtime =
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await
            .expect("runtime initializes");
    let private = PrivateJwk::parse(EVIDENCE_PRIVATE_JWK).expect("test signing key parses");
    let delegate = LocalJwkSigner::new(private).expect("local signer builds");
    // Call zero is the startup self-test and call one is the first member, so
    // the refusal lands on a member the loop reached only after signing an
    // earlier one.
    let provider: Arc<dyn SigningProvider> = Arc::new(FailOnNthSignatureSigner {
        delegate,
        calls: AtomicUsize::new(0),
        fail_at: 2,
    });
    let failing_signer = EvidenceSigner::initialize(provider, EVIDENCE_KEY_ID)
        .await
        .expect("signer passes its startup self-test");
    runtime.replace_signer_for_test(failing_signer);
    mount_adult_source_expecting(&prepared.server, None, 1).await;

    let http = TestServer::new(build_app(Arc::new(runtime)));
    let mut body = serde_json::to_value(adult_request()).expect("request serializes");
    body["holderKeys"] = batch_holder_keys(3);
    let response = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .add_header("accept", EVIDENCE_SD_JWT_VC_BATCH_MEDIA_TYPE)
        .json(&body)
        .await;

    assert_eq!(
        response.status_code(),
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(response.header("content-type"), "application/problem+json");
    let text = response.text();
    assert!(
        !text.contains('~') && !text.contains("credentials"),
        "a failed member leaked an earlier member's credential"
    );
    let audit = fs::read_to_string(&prepared.audit_path).expect("audit is readable");
    assert_eq!(audit.matches("\"phase\":\"disclosure-release\"").count(), 0);
    assert_eq!(audit.matches("\"decision\":\"signing-failure\"").count(), 1);
}

async fn runtime_for(prepared: &PreparedAcceptance) -> Arc<EvidenceRuntime> {
    Arc::new(
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await
            .expect("runtime initializes"),
    )
}

#[tokio::test]
async fn sd_jwt_format_not_permitted_by_bundle() {
    // The stock acceptance bundle enables signed and unsigned output only.
    let fixture = acceptance_runtime().await;
    let http = TestServer::new(build_app(Arc::clone(&fixture.runtime)));
    let response = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .add_header("accept", EVIDENCE_SD_JWT_VC_MEDIA_TYPE)
        .json(&serde_json::to_value(adult_request()).expect("request serializes"))
        .await;

    assert_eq!(response.status_code(), axum::http::StatusCode::FORBIDDEN);
    assert_eq!(response.json::<Value>()["code"], json!("evidence.denied"));
    assert!(
        fixture
            .server
            .received_requests()
            .await
            .expect("request journal is available")
            .is_empty(),
        "an unenabled response format is denied before source access"
    );
    let audit = fs::read_to_string(&fixture.audit_path).expect("audit is readable");
    assert_eq!(audit.matches("\"decision\":\"not-authorized\"").count(), 1);
    assert_eq!(
        audit
            .matches("\"safeErrorCategory\":\"not-authorized\"")
            .count(),
        1
    );
}

#[tokio::test]
async fn sd_jwt_format_not_permitted_by_grant() {
    // The bundle enables the format but the one matched grant withholds it.
    let prepared = sd_jwt_vc_acceptance(false).await;
    let runtime = runtime_for(&prepared).await;
    let http = TestServer::new(build_app(Arc::clone(&runtime)));
    let denied = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .add_header("accept", EVIDENCE_SD_JWT_VC_MEDIA_TYPE)
        .json(&serde_json::to_value(adult_request()).expect("request serializes"))
        .await;
    assert_eq!(denied.status_code(), axum::http::StatusCode::FORBIDDEN);
    assert_eq!(denied.json::<Value>()["code"], json!("evidence.denied"));
    assert!(prepared
        .server
        .received_requests()
        .await
        .expect("request journal is available")
        .is_empty());
    let audit = fs::read_to_string(&prepared.audit_path).expect("audit is readable");
    assert_eq!(audit.matches("\"decision\":\"not-authorized\"").count(), 1);
    assert_eq!(
        audit
            .matches("\"safeErrorCategory\":\"not-authorized\"")
            .count(),
        1
    );

    // With both gates open the same assertion is released as an SD-JWT VC.
    let prepared = sd_jwt_vc_acceptance(true).await;
    let runtime = runtime_for(&prepared).await;
    // One evaluation per response format; both must reach the same source.
    mount_adult_source_expecting(&prepared.server, None, 2).await;
    let http = TestServer::new(build_app(Arc::clone(&runtime)));
    let token = access_token(None);
    let request = adult_request();

    // The signed default establishes the independent expectations a relying
    // party retains, so the credential is verified against the other format's
    // payload rather than against itself.
    let signed = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {token}"))
        .json(&serde_json::to_value(&request).expect("request serializes"))
        .await;
    signed.assert_status_ok();
    let jws = signed.json::<FlattenedJws>();
    let payload = URL_SAFE_NO_PAD
        .decode(&jws.payload)
        .expect("payload decodes");
    let expected: Evidence = serde_json::from_slice(&payload).expect("payload parses");
    let policy = EvidenceVerificationPolicy::from_accepted_transaction(
        &expected,
        &request.request_nonce,
        48 * 60 * 60,
        Utc::now(),
        30,
    )
    .expect("the transaction states bounds the contract allows");

    let credential = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {token}"))
        .add_header("accept", EVIDENCE_SD_JWT_VC_MEDIA_TYPE)
        .json(&serde_json::to_value(&request).expect("request serializes"))
        .await;
    credential.assert_status_ok();
    assert_eq!(
        credential.header("content-type"),
        EVIDENCE_SD_JWT_VC_MEDIA_TYPE
    );
    assert_eq!(credential.header("vary"), "Accept");
    assert_eq!(credential.header("cache-control"), "no-store");

    let serialized = credential.text();
    assert!(serialized.ends_with('~'), "no key-binding JWT is issued");
    let verified = verify_sd_jwt_vc(serialized.as_bytes(), runtime.jwks(), &policy)
        .expect("the credential verifies against the signed transaction's expectations");
    assert_eq!(verified.supported_values, expected.supported_values);
    assert_eq!(verified.subjects, expected.subjects);
    assert_eq!(
        verified.request_nonce.as_deref(),
        Some(request.request_nonce.as_str())
    );

    // Audit records the closed protection mode and the signing key identity.
    let audit = wait_for_audit_counts(&prepared.audit_path, 2, 2).await;
    let events = audit
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("audit line is JSON"))
        .collect::<Vec<_>>();
    let releases = events
        .iter()
        .filter(|event| event["record"]["phase"] == json!("disclosure-release"))
        .collect::<Vec<_>>();
    let credential_release = releases
        .iter()
        .find(|event| event["record"]["responseProtection"] == json!("sd-jwt-vc"))
        .expect("the credential release records the SD-JWT VC mode");
    assert_eq!(
        credential_release["record"]["signingKeyId"],
        json!(EVIDENCE_KEY_ID)
    );
    assert!(!audit.contains(&request.request_nonce));
    for canary in privacy_canaries() {
        assert!(!audit.contains(canary));
    }
}

#[tokio::test]
async fn sd_jwt_holder_key_with_private_member_rejected() {
    let prepared = sd_jwt_vc_acceptance(true).await;
    let runtime = runtime_for(&prepared).await;
    // No source is mounted: no request may reach acquisition.
    let http = TestServer::new(build_app(Arc::clone(&runtime)));
    let mut body = serde_json::to_value(adult_request()).expect("request serializes");

    for holder_key in [
        json!({
            "kty": "EC",
            "crv": "P-256",
            "x": "3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4",
            "y": "GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU",
            "d": "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"
        }),
        json!({
            "kty": "oct",
            "crv": "Ed25519",
            "x": "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",
            "k": "c2VjcmV0LWtleS1jYW5hcnk"
        }),
    ] {
        body["holderKeys"] = json!([holder_key]);
        let response = http
            .post("/v1/evidence")
            .add_header("authorization", format!("Bearer {}", access_token(None)))
            .add_header("accept", EVIDENCE_SD_JWT_VC_MEDIA_TYPE)
            .json(&body)
            .await;
        assert_eq!(
            response.status_code(),
            axum::http::StatusCode::BAD_REQUEST,
            "a holder key carrying private material is not a request"
        );
        let problem = response.json::<Value>();
        assert_eq!(problem["code"], json!("evidence.invalid_request"));
        let text = response.text();
        assert!(
            !text.contains("nWGxne") && !text.contains("c2VjcmV0"),
            "rejected key material is never echoed"
        );
    }

    assert!(
        prepared
            .server
            .received_requests()
            .await
            .expect("request journal is available")
            .is_empty(),
        "an unacceptable holder key fails before credential acquisition"
    );
    assert!(fs::read_to_string(&prepared.audit_path)
        .expect("audit is readable")
        .is_empty());
}

#[tokio::test]
async fn sd_jwt_holder_key_wrong_algorithm_rejected() {
    let prepared = sd_jwt_vc_acceptance(true).await;
    let runtime = runtime_for(&prepared).await;
    mount_adult_source(&prepared.server, None).await;
    let http = TestServer::new(build_app(Arc::clone(&runtime)));
    let mut body = serde_json::to_value(adult_request()).expect("request serializes");

    for holder_key in [
        json!({"kty": "OKP", "crv": "P-256", "x": "3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4", "y": "GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU"}),
        json!({"kty": "EC", "crv": "P-256", "x": "3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4", "y": "GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU", "alg": "EdDSA"}),
        json!({"kty": "EC", "crv": "P-384", "x": "3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4", "y": "GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU"}),
        json!({"kty": "EC", "crv": "P-256", "x": "11qYAYKxCrfVS_7TyWQHOg", "y": "GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU"}),
        json!({"kty": "EC", "crv": "P-256", "x": "3kpzAK6fK6xyfqbdp0HvfZCqfgz7MajMviKyM6bsNE4=", "y": "GkSdSn8xqge52rp9Sv-4qPaw1Q9TJ2eMUyY22flavLU"}),
    ] {
        body["holderKeys"] = json!([holder_key.clone()]);
        let response = http
            .post("/v1/evidence")
            .add_header("authorization", format!("Bearer {}", access_token(None)))
            .add_header("accept", EVIDENCE_SD_JWT_VC_MEDIA_TYPE)
            .json(&body)
            .await;
        assert_eq!(
            response.status_code(),
            axum::http::StatusCode::BAD_REQUEST,
            "{holder_key} is outside the closed holder-key profile"
        );
        assert_eq!(
            response.json::<Value>()["code"],
            json!("evidence.invalid_request")
        );
    }

    // The same request without a holder key still succeeds, so the rejection
    // is the key's and not the format's.
    body.as_object_mut()
        .expect("request is an object")
        .remove("holderKeys");
    let accepted = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .add_header("accept", EVIDENCE_SD_JWT_VC_MEDIA_TYPE)
        .json(&body)
        .await;
    accepted.assert_status_ok();
    assert!(!accepted.text().contains("cnf"));
}

#[tokio::test]
async fn sd_jwt_signing_failure_no_fallback_format() {
    let prepared = sd_jwt_vc_acceptance(true).await;
    let mut runtime =
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await
            .expect("runtime initializes");
    let private = PrivateJwk::parse(EVIDENCE_PRIVATE_JWK).expect("test signing key parses");
    let delegate = LocalJwkSigner::new(private).expect("local signer builds");
    let provider: Arc<dyn SigningProvider> = Arc::new(FailOnceAfterSelfTestSigner {
        delegate,
        calls: AtomicUsize::new(0),
    });
    let failing_signer = EvidenceSigner::initialize(provider, EVIDENCE_KEY_ID)
        .await
        .expect("signer passes its startup self-test");
    runtime.replace_signer_for_test(failing_signer);
    mount_adult_source(&prepared.server, None).await;

    let http = TestServer::new(build_app(Arc::new(runtime)));
    let response = http
        .post("/v1/evidence")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .add_header("accept", EVIDENCE_SD_JWT_VC_MEDIA_TYPE)
        .json(&serde_json::to_value(adult_request()).expect("request serializes"))
        .await;

    assert_eq!(
        response.status_code(),
        axum::http::StatusCode::SERVICE_UNAVAILABLE
    );
    assert_eq!(response.header("content-type"), "application/problem+json");
    let text = response.text();
    assert!(
        !text.contains('~') && !text.contains("integrityProtection"),
        "a failed credential signature never falls back to another format"
    );
    let audit = fs::read_to_string(&prepared.audit_path).expect("audit is readable");
    assert_eq!(audit.matches("\"phase\":\"disclosure-release\"").count(), 0);
}

/// Serve the operator-driven SD-JWT VC demo documented in `SD-JWT-VC-DEMO.md`.
///
/// The immutable bundle and the one complete matched grant both enable the
/// credential format, so one deterministic request is released twice: once as
/// the signed default and once as an SD-JWT VC. The harness verifies the
/// credential against expectations taken from the signed transaction rather
/// than from the credential's own bytes, then leaves the pinned key set and a
/// policy document so the operator can re-verify the stored credential offline
/// with `evidence verify --sd-jwt-vc`.
#[tokio::test]
#[ignore = "operator-driven local curl demo"]
async fn sd_jwt_vc_demo_serves_a_credential_for_curl() {
    let prepared = sd_jwt_vc_acceptance(true).await;
    // One source call per response format. Both formats answer the same
    // request, so neither may reach the source more than once.
    mount_adult_source_expecting(&prepared.server, None, 2).await;
    let runtime = runtime_for(&prepared).await;

    let state_root =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../products/evidence/.sd-jwt-vc-demo");
    fs::create_dir_all(&state_root).expect("demo state directory is created");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&state_root, fs::Permissions::from_mode(0o700))
            .expect("demo state directory is owner-only");
    }
    let signed_path = state_root.join("response.jws.json");
    let credential_path = state_root.join("credential.txt");
    let metadata_path = state_root.join("issuer-metadata.json");
    let jwks_path = state_root.join("trusted.jwks.json");
    let policy_path = state_root.join("verification-policy.yaml");
    for stale in [
        &signed_path,
        &credential_path,
        &metadata_path,
        &jwks_path,
        &policy_path,
    ] {
        match fs::remove_file(stale) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => panic!("stale demo output could not be removed: {error}"),
        }
    }

    let request = adult_request();
    write_secret(
        &state_root,
        "request.json",
        &serde_json::to_string_pretty(&request).expect("request serializes"),
    );
    write_secret(
        &state_root,
        "session.env",
        &format!("EVIDENCE_ACCESS_TOKEN={}\n", access_token(None)),
    );

    let listener = tokio::net::TcpListener::bind("127.0.0.1:18081")
        .await
        .expect("demo listener binds on 127.0.0.1:18081");
    let address = listener
        .local_addr()
        .expect("listener address is available");
    println!(
        "Evidence SD-JWT VC demo server is ready at http://{address}. The ignored session.env contains only the short-lived synthetic bearer token. Use the curl commands in products/evidence/SD-JWT-VC-DEMO.md."
    );

    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel();
    let served = Arc::clone(&runtime);
    let server = tokio::spawn(async move {
        serve_listener_for_test(served, listener, async move {
            let _ = shutdown_rx.await;
        })
        .await
    });

    // The signed default is fetched first, because a relying party's
    // expectations come from the transaction it accepted, never from the
    // credential it is about to check.
    let signed = tokio::time::timeout(Duration::from_secs(180), async {
        loop {
            if let Ok(bytes) = fs::read(&signed_path) {
                if serde_json::from_slice::<FlattenedJws>(&bytes).is_ok() {
                    break bytes;
                }
                if let Ok(problem) = serde_json::from_slice::<Value>(&bytes) {
                    if let Some(code) = problem.get("code").and_then(Value::as_str) {
                        panic!("Evidence returned the safe problem code {code}");
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the signed curl response arrives within three minutes");
    let policy = verification_policy(&runtime, &request, &signed);
    let accepted = verify_flattened_jws(&signed, runtime.jwks(), &policy)
        .expect("the signed response verifies against the running Evidence JWKS");

    // A partial write looks like a malformed credential, so the last
    // verification failure is retained outside the polling future and reported
    // on timeout rather than swallowed.
    let last_failure = RefCell::new(None);
    let credential_wait = tokio::time::timeout(Duration::from_secs(180), async {
        loop {
            if let Ok(bytes) = fs::read(&credential_path) {
                if bytes.ends_with(b"~") {
                    match verify_sd_jwt_vc(&bytes, runtime.jwks(), &policy) {
                        Ok(verified) => {
                            break (
                                String::from_utf8(bytes).expect("credential is ASCII"),
                                verified,
                            )
                        }
                        Err(error) => *last_failure.borrow_mut() = Some(format!("{error:?}")),
                    }
                }
                if let Ok(problem) = serde_json::from_slice::<Value>(&bytes) {
                    if let Some(code) = problem.get("code").and_then(Value::as_str) {
                        panic!("Evidence returned the safe problem code {code}");
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    })
    .await;
    let (credential, verified) = match credential_wait {
        Ok(pair) => pair,
        Err(_) => panic!(
            "the credential curl response arrives and verifies within three minutes; \
             last verification failure: {:?}",
            last_failure.borrow()
        ),
    };

    assert!(
        credential.ends_with('~'),
        "no key-binding JWT is issued or expected"
    );
    assert_eq!(
        credential
            .split('~')
            .filter(|part| !part.is_empty())
            .count(),
        1 + accepted.supported_values.len(),
        "the unprojected demo credential carries one root disclosure per supported value"
    );
    assert_eq!(verified.supported_values, accepted.supported_values);
    assert_eq!(verified.subjects, accepted.subjects);
    assert_eq!(
        verified.request_nonce.as_deref(),
        Some(request.request_nonce.as_str())
    );

    shutdown_tx.send(()).expect("demo server is still running");
    server
        .await
        .expect("demo server task joins")
        .expect("demo server stops cleanly");

    // What an offline relying party keeps besides the credential: the closed
    // policy document, written from the accepted transaction. The pinned key
    // set is not written here, because the demo fetches it the way a relying
    // party does, from the issuer metadata route.
    fs::write(&policy_path, demo_verification_policy_document(&policy))
        .expect("the verification policy is written");

    let audit = wait_for_audit_counts(&prepared.audit_path, 2, 2).await;
    let releases = audit
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("audit line is JSON"))
        .filter(|event| event["record"]["phase"] == json!("disclosure-release"))
        .map(|event| {
            event["record"]["responseProtection"]
                .as_str()
                .expect("every release records a protection mode")
                .to_owned()
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        releases,
        BTreeSet::from(["sd-jwt-vc".to_owned(), "signed".to_owned()]),
        "each release records its own closed protection mode"
    );
    assert!(!audit.contains(&request.request_nonce));
    for canary in privacy_canaries() {
        assert!(!audit.contains(canary));
    }

    println!(
        "PASS: the same assertion was released as a signed JWS and as an SD-JWT VC, the credential verified against the signed transaction's expectations, minimization held, and both releases recorded their protection mode."
    );
}

/// Render the accepted transaction's expectations as the closed policy document
/// the `evidence verify` command parses.
fn demo_verification_policy_document(policy: &EvidenceVerificationPolicy) -> String {
    let document = json!({
        "issuedBy": policy.issued_by,
        "providedBy": policy.provided_by,
        "requirement": policy.requirement,
        "evidenceType": policy.evidence_type,
        "purpose": policy.purpose,
        "audience": policy.audience,
        "configurationRevision": policy.configuration_revision,
        "requestNonce": policy.request_nonce,
        "expectedSubjects": policy
            .expected_subjects
            .iter()
            .map(|subject| json!({"role": subject.role, "binding": subject.binding}))
            .collect::<Vec<_>>(),
        "expectedOutputs": policy
            .expected_outputs
            .iter()
            .map(|output| json!({
                "handle": output.handle,
                "concept": output.concept,
                "required": output.required,
                "form": expected_form_document(&output.form)
            }))
            .collect::<Vec<_>>(),
        "revokedKeyIds": policy.revoked_key_ids,
        "maximumAssertionLifetimeSeconds": policy.maximum_assertion_lifetime().as_secs(),
        "clockSkewSeconds": policy.clock_skew().as_secs(),
    });
    serde_norway::to_string(&document).expect("the policy document serializes as YAML")
}

/// The closed expected value-form vocabulary as a policy document writes it.
fn expected_form_document(form: &ExpectedValueForm) -> Value {
    match form {
        ExpectedValueForm::Boolean => json!("boolean"),
        ExpectedValueForm::Integer => json!("integer"),
        ExpectedValueForm::String => json!("string"),
        ExpectedValueForm::DateBucket => json!("date-bucket"),
        ExpectedValueForm::TimeBucket => json!("time-bucket"),
        ExpectedValueForm::EntityReference => json!("entity-reference"),
        ExpectedValueForm::Structured => json!("structured"),
        ExpectedValueForm::List {
            item_form,
            minimum_items,
            maximum_items,
            unique,
        } => json!({"list": {
            "items": match item_form {
                crate::verifier::ExpectedListItemForm::String => "string",
                crate::verifier::ExpectedListItemForm::EntityReference => "entity-reference",
                crate::verifier::ExpectedListItemForm::LegacyAny => {
                    panic!("legacy list policy is read-only")
                }
            },
            "minimumItems": minimum_items,
            "maximumItems": maximum_items,
            "unique": unique
        }}),
    }
}

#[tokio::test]
async fn reordered_grant_subjects_resolve_by_role_and_emit_declaration_order() {
    let prepared = prepare_acceptance("subject-binding-secret-canary-32-bytes-minimum").await;
    make_writable(&prepared.bundle_root);
    let configuration_path = prepared.bundle_root.join("evidence.yaml");
    let mut configuration =
        fs::read_to_string(&configuration_path).expect("acceptance configuration is readable");
    replace_exact(
        &mut configuration,
        r#"        subjects:
          - {role: child, selectorProfile: civil-record-reference-v1, valueOrigin: request}
          - role: candidate-parent
            selectorProfile: person-reference-v1
            valueOrigin: authenticated-grant
            valueClaims:
              person_reference: grant.candidate_parent.person_reference"#,
        r#"        subjects:
          - role: candidate-parent
            selectorProfile: person-reference-v1
            valueOrigin: authenticated-grant
            valueClaims:
              person_reference: grant.candidate_parent.person_reference
          - {role: child, selectorProfile: civil-record-reference-v1, valueOrigin: request}"#,
        1,
    );
    fs::write(&configuration_path, configuration).expect("test configuration is rewritten");
    make_read_only(&prepared.bundle_root);
    let runtime = Arc::new(
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await
            .expect("a valid bundle with reordered grant subjects initializes"),
    );
    mount_parent_source(
        &prepared.server,
        parent_source_response(vec![PARENT_REFERENCE]),
    )
    .await;

    // The request array order is also reversed independently of grant order.
    let mut request = parent_request();
    request.subjects.reverse();
    let jws = runtime
        .evaluate(
            "operation-reordered-grant-subjects",
            &access_token(Some(parent_grant_claims())),
            &request,
        )
        .await
        .expect("reordered grant subjects resolve by unique role");
    let payload = URL_SAFE_NO_PAD
        .decode(&jws.payload)
        .expect("Evidence payload is base64url");
    let evidence: Evidence = serde_json::from_slice(&payload).expect("Evidence payload is JSON");
    assert_eq!(evidence.subjects[0].role, "child");
    assert_eq!(evidence.subjects[1].role, "candidate-parent");

    // Audit subjects also use requirement declaration order.
    let audit = wait_for_audit_counts(&prepared.audit_path, 1, 1).await;
    let first_event =
        serde_json::from_str::<Value>(audit.lines().next().expect("audit has events"))
            .expect("audit line is JSON");
    let roles = first_event["record"]["subjects"]
        .as_array()
        .expect("audit subjects are an array")
        .iter()
        .map(|subject| subject["role"].as_str().expect("role is text").to_owned())
        .collect::<Vec<_>>();
    assert_eq!(roles, ["child", "candidate-parent"]);

    // The verifier accepts the expected subject set in any expectation order.
    let serialized = serde_json::to_vec(&jws).expect("JWS serializes");
    let mut policy = verification_policy_stub(&runtime, &request);
    policy.request_nonce = request.request_nonce.clone();
    policy.expected_subjects = evidence
        .subjects
        .iter()
        .rev()
        .map(|subject| crate::verifier::ExpectedSubject {
            role: subject.role.clone(),
            binding: subject.binding.clone(),
        })
        .collect();
    policy.expected_outputs = evidence
        .supported_values
        .iter()
        .map(|value| crate::verifier::ExpectedOutput {
            handle: "expected-value".to_owned(),
            concept: value.provides_value_for.clone(),
            required: true,
            form: crate::verifier::ExpectedValueForm::Boolean,
        })
        .collect();
    verify_flattened_jws(&serialized, runtime.jwks(), &policy)
        .expect("declaration-ordered subjects verify against unordered expectations");
}

/// Policy scaffold with the independent bundle-derived fields filled in and
/// empty subject and output expectations for the caller to complete.
fn verification_policy_stub(
    runtime: &EvidenceRuntime,
    request: &EvidenceRequest,
) -> EvidenceVerificationPolicy {
    let requirement = runtime
        .bundle()
        .config
        .requirements
        .iter()
        .find(|candidate| candidate.id == request.requirement)
        .expect("requirement is loaded");
    EvidenceVerificationPolicyDocument {
        expected_assurance_profile: runtime.bundle().config.assurance_profile,
        issued_by: runtime.bundle().config.issuer.id.clone(),
        provided_by: runtime.bundle().config.service.provider_id.clone(),
        requirement: request.requirement.clone(),
        evidence_type: requirement.evidence_type.clone(),
        purpose: request.purpose.clone(),
        audience: EVIDENCE_AUDIENCE.to_owned(),
        configuration_revision: runtime
            .bundle()
            .configuration_revision(&request.requirement)
            .expect("the loaded requirement has a revision")
            .to_owned(),
        request_nonce: request.request_nonce.clone(),
        expected_subjects: Vec::new(),
        expected_outputs: Vec::new(),
        revoked_key_ids: Vec::new(),
        maximum_assertion_lifetime_seconds: 48 * 60 * 60,
        clock_skew_seconds: 30,
    }
    .try_into_policy(Utc::now())
    .expect("the stub policy states bounds the contract allows")
}

#[tokio::test]
async fn multi_role_request_order_is_not_semantic_and_output_uses_declaration_order() {
    let fixture = acceptance_runtime().await;
    mount_parent_source(
        &fixture.server,
        parent_source_response(vec![PARENT_REFERENCE]),
    )
    .await;
    let mut request = parent_request();
    request.subjects.reverse();

    let response = fixture
        .runtime
        .evaluate(
            "operation-reversed-subject-order",
            &access_token(Some(parent_grant_claims())),
            &request,
        )
        .await
        .expect("roles resolve independently of request array order");
    let payload = URL_SAFE_NO_PAD
        .decode(response.payload)
        .expect("Evidence payload is base64url");
    let evidence: Evidence = serde_json::from_slice(&payload).expect("Evidence payload is JSON");
    assert_eq!(evidence.subjects[0].role, "child");
    assert_eq!(evidence.subjects[1].role, "candidate-parent");
    assert_eq!(
        fixture
            .server
            .received_requests()
            .await
            .expect("request journal is available")
            .len(),
        1
    );
    let audit = fs::read_to_string(&fixture.audit_path).expect("audit is readable");
    assert_eq!(audit.matches("\"phase\":\"access-attempt\"").count(), 1);
    assert_eq!(audit.matches("\"phase\":\"disclosure-release\"").count(), 1);
}

#[tokio::test]
async fn security_contract_rejects_unknown_and_unauthorized_requests_before_source_access() {
    let fixture = acceptance_runtime().await;
    let now = Utc::now().timestamp();
    let unentitled_token = signed_access_token(json!({
        "iss": TOKEN_ISSUER,
        "aud": TOKEN_AUDIENCE,
        "sub": "unentitled-principal",
        "iat": now - 1,
        "exp": now + 3600,
        "evidence_tags": ["unentitled-tag"],
        "evidence_audience": EVIDENCE_AUDIENCE
    }));

    let mut unknown_requirement = adult_request();
    unknown_requirement.requirement = "urn:example:fixture:requirement:unknown:v1".to_owned();
    let mut unauthorized_purpose = adult_request();
    unauthorized_purpose.purpose = "caller-selected-purpose".to_owned();
    let mut unauthorized_profile = adult_request();
    unauthorized_profile.subjects[0].selector.profile = "caller-selected-profile-v1".to_owned();

    for (operation, token, request) in [
        (
            "operation-unknown-requirement",
            access_token(None),
            unknown_requirement,
        ),
        (
            "operation-unauthorized-purpose",
            access_token(None),
            unauthorized_purpose,
        ),
        (
            "operation-unauthorized-profile",
            access_token(None),
            unauthorized_profile,
        ),
        (
            "operation-selector-possession-without-authority",
            unentitled_token,
            adult_request(),
        ),
    ] {
        let error = fixture
            .runtime
            .evaluate(operation, &token, &request)
            .await
            .expect_err("caller material cannot create authority");
        assert_eq!(error.problem(), ProblemCode::NotAuthorized);
    }

    assert!(fixture
        .server
        .received_requests()
        .await
        .expect("request journal is available")
        .is_empty());
    let audit = fs::read_to_string(&fixture.audit_path).expect("audit is readable");
    assert!(!audit.contains("\"phase\":\"access-attempt\""));
    assert_eq!(audit.matches("\"decision\":\"not-authorized\"").count(), 4);
    for protected in [
        "unentitled-principal",
        "caller-selected-purpose",
        "caller-selected-profile-v1",
    ] {
        assert!(!audit.contains(protected));
    }
}

#[tokio::test]
async fn failed_selector_budget_is_enforced_by_the_runtime_and_scoped_to_authority() {
    let prepared = prepare_acceptance("subject-binding-secret-canary-32-bytes-minimum").await;
    make_writable(&prepared.bundle_root);
    let configuration_path = prepared.bundle_root.join("evidence.yaml");
    let mut configuration =
        fs::read_to_string(&configuration_path).expect("acceptance configuration is readable");
    replace_exact(
        &mut configuration,
        "rateLimits: {requestsPerPrincipalPerMinute: 60, burstPerPrincipal: 10, failedSelectorAttemptsPerPrincipalAuthorityPerMinute: 10}",
        "rateLimits: {requestsPerPrincipalPerMinute: 120, burstPerPrincipal: 20, failedSelectorAttemptsPerPrincipalAuthorityPerMinute: 2}",
        1,
    );
    replace_exact(
        &mut configuration,
        "authorityProfiles:\n  statutory-caseworker-v1:",
        r#"authorityProfiles:
  alternate-caseworker-v1:
    kind: statutory
    requesterTags: [alternate-fixture-agency]
    grants:
      - requirement: urn:example:fixture:requirement:adult-status:v1
        purpose: fixture-eligibility
        audienceFrom: authenticated-requester
        subjects:
          - {role: subject, selectorProfile: person-demographics-v1, valueOrigin: request}
  statutory-caseworker-v1:"#,
        1,
    );
    fs::write(&configuration_path, configuration).expect("test configuration is rewritten");
    make_read_only(&prepared.bundle_root);
    let runtime =
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await
            .expect("runtime with bounded selector budget initializes");

    let mut invalid = adult_request();
    invalid.subjects[0]
        .selector
        .values
        .as_mut()
        .expect("adult selector has values")
        .remove("birth_date");
    let primary_token = access_token_for("shared-selector-principal", None);
    let mut retained_failures = String::new();
    for attempt in 0..2 {
        let error = runtime
            .evaluate(
                &format!("operation-selector-failure-primary-{attempt}"),
                &primary_token,
                &invalid,
            )
            .await
            .expect_err("invalid selectors consume the configured budget");
        assert_eq!(error.problem(), ProblemCode::InvalidSelector);
        retained_failures.push_str(&format!("{error:?} {error}\n"));
    }
    let exhausted = runtime
        .evaluate(
            "operation-selector-failure-primary-exhausted",
            &primary_token,
            &invalid,
        )
        .await
        .expect_err("the next request is rejected before selector resolution");
    assert_eq!(exhausted.problem(), ProblemCode::RateLimited);
    retained_failures.push_str(&format!("{exhausted:?} {exhausted}\n"));

    let now = Utc::now().timestamp();
    let alternate_token = signed_access_token(json!({
        "iss": TOKEN_ISSUER,
        "aud": TOKEN_AUDIENCE,
        "sub": "shared-selector-principal",
        "iat": now - 1,
        "exp": now + 3600,
        "evidence_tags": ["alternate-fixture-agency"],
        "evidence_audience": EVIDENCE_AUDIENCE
    }));
    let alternate = runtime
        .evaluate(
            "operation-selector-failure-alternate-authority",
            &alternate_token,
            &invalid,
        )
        .await
        .expect_err("a different matched authority has an independent selector budget");
    assert_eq!(alternate.problem(), ProblemCode::InvalidSelector);
    retained_failures.push_str(&format!("{alternate:?} {alternate}\n"));

    assert!(prepared
        .server
        .received_requests()
        .await
        .expect("request journal is available")
        .is_empty());
    let audit = fs::read_to_string(&prepared.audit_path).expect("audit is readable");
    assert!(
        audit.is_empty(),
        "pre-material selector failures are not audited"
    );
    retained_failures.push_str(&audit);
    for protected in [
        "shared-selector-principal",
        "alternate-fixture-agency",
        "Amina",
        "Diallo",
        "2000-01-01",
    ] {
        assert!(!audit.contains(protected));
        assert!(!retained_failures.contains(protected));
    }
    for canary in privacy_canaries() {
        assert!(
            !retained_failures.contains(canary),
            "public selector failures and audit remain value-free"
        );
    }
}

#[tokio::test]
async fn one_runtime_proves_all_definitions_and_collapses_unresolved_relationships() {
    let fixture = acceptance_runtime().await;
    assert!(
        fixture.runtime.ready().await,
        "readiness accepts local credentials and performs no evidence-data lookup"
    );
    assert!(fixture
        .server
        .received_requests()
        .await
        .expect("request journal is available")
        .is_empty());

    mount_success_sources(&fixture.server, true).await;
    let standard_token = access_token(None);
    let parent_token = access_token(Some(parent_grant_claims()));

    let cases = [
        (
            "adult",
            adult_request(),
            standard_token.as_str(),
            "urn:example:fixture:concept:adult-status",
            PublicValue::Boolean(true),
            1,
        ),
        (
            "residence",
            residence_request(),
            standard_token.as_str(),
            "urn:example:fixture:concept:residence-region",
            PublicValue::String("REGION-NORTH".to_owned()),
            1,
        ),
        (
            "licence",
            licence_request(),
            standard_token.as_str(),
            "urn:example:fixture:concept:licence-active",
            PublicValue::Boolean(true),
            1,
        ),
        (
            "parent-true",
            parent_request(),
            parent_token.as_str(),
            "urn:example:fixture:concept:legal-parent-relationship-confirmed",
            PublicValue::Boolean(true),
            2,
        ),
    ];

    for (operation_suffix, request, token, concept, expected, role_count) in cases {
        let jws = fixture
            .runtime
            .evaluate(
                &format!("operation-acceptance-{operation_suffix}"),
                token,
                &request,
            )
            .await
            .expect("full Evidence path signs");
        let serialized = serde_json::to_vec(&jws).expect("JWS serializes");
        let evidence = verify_flattened_jws(
            &serialized,
            fixture.runtime.jwks(),
            &verification_policy(&fixture.runtime, &request, &serialized),
        )
        .expect("released JWS verifies under the exact relying-procedure policy");
        assert_eq!(evidence.subjects.len(), role_count);
        if role_count == 2 {
            assert_eq!(
                evidence
                    .subjects
                    .iter()
                    .map(|subject| subject.role.as_str())
                    .collect::<Vec<_>>(),
                ["child", "candidate-parent"]
            );
        }
        assert!(evidence
            .supported_values
            .iter()
            .any(|value| value.provides_value_for == concept && value.value == expected));
        assert_minimized_payload(&serialized);
    }

    fixture.server.reset().await;
    let non_parent = non_parent_candidate();
    mount_parent_source(
        &fixture.server,
        parent_source_response(vec!["synthetic-parent-reference-002"]),
    )
    .await;
    let non_parent_token = access_token(Some(parent_grant_claims_for(non_parent)));
    let false_request = parent_request();
    let false_jws = fixture
        .runtime
        .evaluate(
            "operation-acceptance-parent-false",
            &non_parent_token,
            &false_request,
        )
        .await
        .expect("exact non-membership in the complete governed parent set is signed");
    let false_serialized = serde_json::to_vec(&false_jws).expect("JWS serializes");
    let false_evidence = verify_flattened_jws(
        &false_serialized,
        fixture.runtime.jwks(),
        &verification_policy(&fixture.runtime, &false_request, &false_serialized),
    )
    .expect("negative Evidence verifies");
    assert_eq!(
        false_evidence.supported_values[0].value,
        PublicValue::Boolean(false)
    );

    for (suffix, response) in [
        ("none", json!({"total": 0, "records": []})),
        ("ambiguous", json!({"total": 2, "records": [{}, {}]})),
    ] {
        fixture.server.reset().await;
        mount_parent_source(&fixture.server, response).await;
        let error = fixture
            .runtime
            .evaluate(
                &format!("operation-acceptance-parent-{suffix}"),
                &parent_token,
                &parent_request(),
            )
            .await
            .expect_err("unresolved pairs never produce signed Evidence");
        assert_eq!(error.problem(), ProblemCode::EvidenceNotAvailable);
    }

    fixture.server.reset().await;
    let swapped_roles = request(
        "urn:example:fixture:requirement:legal-parent-relationship:v1",
        "fixture-enrolment",
        vec![
            requested_subject(
                "candidate-parent",
                "civil-record-reference-v1",
                Some([("record_reference", "synthetic-child-record-001")]),
            ),
            requested_subject::<[(&str, &str); 0]>("child", "person-reference-v1", None),
        ],
    );
    let swapped_error = fixture
        .runtime
        .evaluate(
            "operation-acceptance-swapped-parent-roles",
            &parent_token,
            &swapped_roles,
        )
        .await
        .expect_err("role/profile substitution is rejected before source access");
    assert_eq!(swapped_error.problem(), ProblemCode::NotAuthorized);

    let substituted = parent_request_with_candidate_values();
    let error = fixture
        .runtime
        .evaluate(
            "operation-acceptance-substitution",
            &parent_token,
            &substituted,
        )
        .await
        .expect_err("caller candidate substitution is rejected before source access");
    assert_eq!(error.problem(), ProblemCode::InvalidSelector);
    let unauthorized = fixture
        .runtime
        .evaluate(
            "operation-acceptance-unauthorized",
            &access_token(Some(json!({
                "evidence_grant_id": "grant-canary",
                "evidence_authority": "different-authority",
                "grant": {"candidate_parent": parent_candidate()}
            }))),
            &parent_request(),
        )
        .await
        .expect_err("authority substitution is rejected before source access");
    assert_eq!(unauthorized.problem(), ProblemCode::NotAuthorized);
    assert!(fixture
        .server
        .received_requests()
        .await
        .expect("request journal is available")
        .is_empty());

    let audit = fs::read_to_string(&fixture.audit_path).expect("durable audit is readable");
    assert_eq!(audit.matches("\"phase\":\"access-attempt\"").count(), 7);
    assert_eq!(audit.matches("\"phase\":\"disclosure-release\"").count(), 5);
    assert_eq!(audit.matches("\"phase\":\"denial\"").count(), 4);
    assert_eq!(audit.matches("\"decision\":\"not-authorized\"").count(), 2);
    let retained_failures = format!(
        "{swapped_error:?} {swapped_error}\n{error:?} {error}\n{unauthorized:?} {unauthorized}\n{audit}"
    );
    for canary in privacy_canaries() {
        assert!(
            !retained_failures.contains(canary),
            "public failures and audit must not retain protected selector, grant, source, or secret material"
        );
    }
}

/// Threat: a Relay-style policy-hidden or ambiguous lookup must not be
/// misreported as a source outage, and its Problem Details body must not reach
/// scripts, assertions, public errors, or audit. Enforcement: the source
/// declares only the exact neutral tuple; the HTTP transport recognizes the
/// closed response and the singular acquisition maps its data-free outcome to
/// Evidence unavailable.
#[tokio::test]
async fn sec_exact_relay_lookup_declared_unresolved_maps_to_evidence_unavailable() {
    let server = MockServer::start().await;
    let prepared = prepare_fixture_with_mutation(
        "subject-binding-secret-canary-32-bytes-minimum",
        &server.uri(),
        &FixtureCeilings::deployment_defaults(),
        configure_exact_relay_lookup_source,
    );
    let runtime =
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await
            .expect("exact Relay lookup composition initializes");
    let expected_body = json!({
        "selectors": {"recordReference": "synthetic-residence-record-001"}
    });

    Mock::given(method("POST"))
        .and(path(
            "/v2/resources/residence-record/lookups/by-record-reference",
        ))
        .and(header("accept", "application/json"))
        .and(header("authorization", format!("Bearer {BEARER}").as_str()))
        .and(body_json(expected_body.clone()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "data": {"domainData": {"official_residence_code": "R-101"}}
        })))
        .expect(1)
        .mount(&server)
        .await;
    runtime
        .evaluate(
            "operation-relay-lookup-success",
            &access_token(None),
            &residence_request(),
        )
        .await
        .expect("Relay lookup data.domainData produces Evidence");

    const TRACE_CANARY: &str = "relay-upstream-trace-secret-canary";
    Mock::given(method("POST"))
        .and(path(
            "/v2/resources/residence-record/lookups/by-record-reference",
        ))
        .and(body_json(expected_body))
        .respond_with(
            ResponseTemplate::new(404)
                .insert_header("Content-Type", "application/problem+json")
                .set_body_raw(
                    format!(
                        r#"{{"type":"https://id.registrystack.org/problems/registry-relay/consultation/unresolved","title":"Requested record was not resolved","status":404,"detail":"the requested record was not resolved","code":"consultation.unresolved","traceId":"{TRACE_CANARY}"}}"#
                    ),
                    "application/problem+json",
                ),
        )
        .with_priority(1)
        .expect(2)
        .mount(&server)
        .await;
    let error = runtime
        .evaluate(
            "operation-relay-lookup-unresolved",
            &access_token(None),
            &residence_request(),
        )
        .await
        .expect_err("declared Relay unresolved releases no Evidence");
    assert_eq!(error.problem(), ProblemCode::EvidenceNotAvailable);
    let batch = request_batch_from_request(&residence_request(), 1);
    let batch_response = runtime
        .evaluate_request_batch(
            "operation-relay-lookup-unresolved-batch",
            &access_token(None),
            &batch,
        )
        .await
        .expect("sequential singular unresolved maps to one unavailable item");
    let batch_response: EvidenceRequestBatchResponse =
        serde_json::from_slice(batch_response.bytes()).expect("batch response parses");
    assert!(matches!(
        batch_response.items.as_slice(),
        [EvidenceRequestBatchResponseItem::EvidenceNotAvailable]
    ));
    let audit = fs::read_to_string(&prepared.audit_path).expect("audit is readable");
    assert!(audit.contains("\"decision\":\"unresolved\""));
    for forbidden in [
        "consultation.unresolved",
        "registry-relay/consultation/unresolved",
        TRACE_CANARY,
    ] {
        assert!(!audit.contains(forbidden), "audit leaked {forbidden}");
        assert!(
            !format!("{error:?}").contains(forbidden),
            "error leaked {forbidden}"
        );
    }
}

#[tokio::test]
async fn runtime_output_gate_rejects_every_fixture_injected_derivation_without_release() {
    let cases = [
        (
            "adult",
            "derivations/adult-status.rhai",
            r#"fn derive(facts, selectors, evaluation_context) { [#{concept_id: "urn:example:fixture:concept:adult-status", value: "true"}] }"#,
        ),
        (
            "residence",
            "derivations/residence-region.rhai",
            r#"fn derive(facts, selectors, evaluation_context) { [#{concept_id: "urn:example:fixture:concept:residence-region", value: "R-101"}] }"#,
        ),
        (
            "licence",
            "derivations/professional-licence.rhai",
            r#"fn derive(facts, selectors, evaluation_context) { [#{concept_id: "urn:example:fixture:concept:licence-active", value: true}, #{concept_id: "urn:example:fixture:concept:licence-expiry-category", value: "2026-08-20"}] }"#,
        ),
        (
            "relationship",
            "derivations/legal-parent-relationship.rhai",
            r#"fn derive(facts, selectors, evaluation_context) { [#{concept_id: "urn:example:fixture:concept:legal-parent-relationship-confirmed", value: true}, #{concept_id: "urn:example:fixture:concept:related-subject-name", value: "PrivacyCanary"}] }"#,
        ),
    ];

    for (definition, script_path, script) in cases {
        let prepared = prepare_acceptance("subject-binding-secret-canary-32-bytes-minimum").await;
        make_writable(&prepared.bundle_root);
        fs::write(prepared.bundle_root.join(script_path), script)
            .expect("test derivation replacement succeeds");
        make_read_only(&prepared.bundle_root);
        let runtime =
            EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
                .await
                .expect("runtime with a syntactically valid injected derivation initializes");
        let (request, token) = match definition {
            "adult" => {
                mount_adult_source(&prepared.server, None).await;
                (adult_request(), access_token(None))
            }
            "residence" => {
                mount_residence_source(&prepared.server).await;
                (residence_request(), access_token(None))
            }
            "licence" => {
                mount_licence_source(&prepared.server).await;
                (licence_request(), access_token(None))
            }
            "relationship" => {
                mount_parent_source(
                    &prepared.server,
                    parent_source_response(vec![PARENT_REFERENCE]),
                )
                .await;
                (parent_request(), access_token(Some(parent_grant_claims())))
            }
            _ => unreachable!("closed acceptance definitions"),
        };

        let error = runtime
            .evaluate(
                &format!("operation-output-gate-{definition}"),
                &token,
                &request,
            )
            .await
            .expect_err("invalid derived output cannot reach signing or release");
        assert_eq!(error.problem(), ProblemCode::ServiceUnavailable);
        let audit = fs::read_to_string(&prepared.audit_path).expect("audit is readable");
        assert_eq!(audit.matches("\"phase\":\"access-attempt\"").count(), 1);
        assert_eq!(
            audit
                .matches("\"safeErrorCategory\":\"output-gate\"")
                .count(),
            1
        );
        assert_eq!(audit.matches("\"phase\":\"disclosure-release\"").count(), 0);
        let requests = prepared
            .server
            .received_requests()
            .await
            .expect("request journal is available");
        assert_eq!(requests.len(), 1);
        let retained = format!(
            "{error:?} {error}\n{audit}\n{} {}",
            requests[0].method,
            requests[0].url.path()
        );
        for canary in privacy_canaries() {
            assert!(
                !retained.contains(canary),
                "public failure, audit, and non-sensitive request metadata remain minimized"
            );
        }
    }
}

#[tokio::test]
async fn runtime_rejects_an_extra_extracted_fact_before_derivation_or_release() {
    let prepared = prepare_acceptance("subject-binding-secret-canary-32-bytes-minimum").await;
    make_writable(&prepared.bundle_root);
    let adapter_path = prepared
        .bundle_root
        .join("adapters/adult-status-source.rhai");
    let mut adapter = fs::read_to_string(&adapter_path).expect("adapter is readable");
    replace_exact(
        &mut adapter,
        "facts: #{date_of_birth: date_of_birth}",
        "facts: #{date_of_birth: date_of_birth, unexpected_private_fact: \"PrivacyCanary\"}",
        1,
    );
    fs::write(adapter_path, adapter).expect("test adapter replacement succeeds");
    make_read_only(&prepared.bundle_root);
    let runtime =
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await
            .expect("runtime with a syntactically valid adapter initializes");
    mount_adult_source(&prepared.server, None).await;

    let error = runtime
        .evaluate(
            "operation-extra-extracted-fact-rejection",
            &access_token(None),
            &adult_request(),
        )
        .await
        .expect_err("a fact outside the closed fact schema cannot reach derivation");
    assert_eq!(error.problem(), ProblemCode::EvidenceNotAvailable);
    let audit = fs::read_to_string(&prepared.audit_path).expect("audit is readable");
    assert_eq!(audit.matches("\"phase\":\"access-attempt\"").count(), 1);
    assert_eq!(
        audit
            .matches("\"safeErrorCategory\":\"fact-unavailable\"")
            .count(),
        1
    );
    assert_eq!(audit.matches("\"phase\":\"disclosure-release\"").count(), 0);
    let requests = prepared
        .server
        .received_requests()
        .await
        .expect("request journal is available");
    assert_eq!(requests.len(), 1);
    let retained = format!(
        "{error:?} {error}\n{audit}\n{} {}",
        requests[0].method,
        requests[0].url.path()
    );
    for canary in privacy_canaries() {
        assert!(
            !retained.contains(canary),
            "public failure, audit, and non-sensitive request metadata remain minimized"
        );
    }
}

#[tokio::test]
async fn every_runtime_applicable_acceptance_case_reaches_terminal_audit_and_verification() {
    let fixture = acceptance_runtime().await;
    let definitions = [
        (
            "adult",
            include_bytes!(
                "../../../products/evidence/fixtures/acceptance/all-definitions/fixtures/adult-status-cases.yaml"
            )
            .as_slice(),
        ),
        (
            "residence",
            include_bytes!(
                "../../../products/evidence/fixtures/acceptance/all-definitions/fixtures/residence-region-cases.yaml"
            )
            .as_slice(),
        ),
        (
            "licence",
            include_bytes!(
                "../../../products/evidence/fixtures/acceptance/all-definitions/fixtures/professional-licence-cases.yaml"
            )
            .as_slice(),
        ),
        (
            "relationship",
            include_bytes!(
                "../../../products/evidence/fixtures/acceptance/all-definitions/fixtures/legal-parent-relationship-cases.yaml"
            )
            .as_slice(),
        ),
    ];
    let mut executed = BTreeMap::new();
    let mut runtime_equivalents = BTreeSet::new();
    let mut startup_only = BTreeSet::new();

    for (definition, bytes) in definitions {
        let matrix: Value = serde_norway::from_slice(bytes).expect("acceptance matrix parses");
        let common = matrix["common"].as_object().expect("common is an object");
        for (index, case) in matrix["cases"]
            .as_array()
            .expect("cases are an array")
            .iter()
            .enumerate()
        {
            let case = case.as_object().expect("case is an object");
            let case_id = case["id"].as_str().expect("case id is text");
            if case.contains_key("injected_derivation") {
                runtime_equivalents.insert(format!("{definition}/{case_id}:output-gate"));
                continue;
            }
            if case.contains_key("companion_bundle") {
                startup_only.insert(format!("{definition}/{case_id}:bundle-rejection"));
                continue;
            }
            if case.get("expected").and_then(Value::as_str) == Some("pre-source-selector-rejection")
            {
                runtime_equivalents.insert(format!("{definition}/{case_id}:pre-source-rejection"));
                continue;
            }

            fixture.server.reset().await;
            let request = match definition {
                "adult" => adult_request(),
                "residence" => residence_request(),
                "licence" => licence_request(),
                "relationship" => parent_request(),
                _ => unreachable!("closed definition set"),
            };
            let source_path = match definition {
                "adult" | "residence" => "/v1/facts",
                "licence" => "/v1/records",
                "relationship" => "/v1/child-relationships",
                _ => unreachable!("closed definition set"),
            };
            let source_method = if definition == "licence" {
                "GET"
            } else {
                "POST"
            };
            let is_relationship = definition == "relationship";
            let response = if let Some(source) = case.get("source") {
                ResponseTemplate::new(200).set_body_json(source)
            } else {
                match case.get("source_failure").and_then(Value::as_str) {
                    Some("timeout") => ResponseTemplate::new(200)
                        .set_body_json(json!({"total": 1}))
                        .set_delay(Duration::from_millis(3_050)),
                    Some("http-503") => ResponseTemplate::new(503),
                    Some("wrong-media-type") => {
                        ResponseTemplate::new(200).set_body_raw("{}", "text/plain")
                    }
                    Some("redirect") => {
                        ResponseTemplate::new(302).insert_header("location", "/prohibited-redirect")
                    }
                    _ => panic!("case must have source or closed source failure"),
                }
            };
            let mut source_mock = Mock::given(method(source_method))
                .and(path(source_path))
                .and(header("accept", "application/json"));
            if is_relationship {
                source_mock = source_mock
                    .and(header("authorization", format!("Bearer {BEARER}").as_str()))
                    .and(body_json(parent_source_request()));
            }
            source_mock
                .respond_with(response)
                .expect(1)
                .mount(&fixture.server)
                .await;

            let principal = format!("principal-{definition}-{index}");
            let token_claims = case
                .get("verified_token_claims")
                .cloned()
                .or_else(|| is_relationship.then(|| parent_grant_claims_for(parent_candidate())));
            let token = access_token_for(&principal, token_claims);
            let evaluation_time = acceptance_case_time(case, common);
            let audit_before = fs::read_to_string(&fixture.audit_path)
                .expect("audit is readable before router request")
                .lines()
                .count();
            let http = TestServer::new(build_app_at_for_test(
                Arc::clone(&fixture.runtime),
                evaluation_time,
            ));
            let response = http
                .post("/v1/evidence")
                .add_header("authorization", format!("Bearer {token}"))
                .json(&request)
                .await;

            if case.contains_key("expected_value") || case.contains_key("expected_values") {
                response.assert_status_ok();
                let jws = response.json::<FlattenedJws>();
                let serialized = serde_json::to_vec(&jws).expect("JWS serializes");
                let mut policy = verification_policy(&fixture.runtime, &request, &serialized);
                policy.now = evaluation_time;
                let evidence = verify_flattened_jws(&serialized, fixture.runtime.jwks(), &policy)
                    .expect("matrix JWS verifies");
                if let Some(expected) = case.get("expected_value") {
                    assert_eq!(
                        serde_json::to_value(&evidence.supported_values[0].value)
                            .expect("value serializes"),
                        *expected,
                        "{definition}/{case_id}"
                    );
                } else {
                    let expected = case["expected_values"]
                        .as_object()
                        .expect("expected values are an object");
                    for value in &evidence.supported_values {
                        let short = value
                            .provides_value_for
                            .rsplit(':')
                            .next()
                            .expect("concept has a suffix");
                        assert_eq!(
                            serde_json::to_value(&value.value).expect("value serializes"),
                            expected[short],
                            "{definition}/{case_id}/{short}"
                        );
                    }
                }
                assert_minimized_payload(&serialized);
            } else {
                let expected = match case
                    .get("expected_public_problem")
                    .and_then(Value::as_str)
                    .expect("failed case names its public problem")
                {
                    "evidence.unavailable" => ProblemCode::EvidenceNotAvailable,
                    "source.unavailable" => ProblemCode::DependencyUnavailable,
                    "service.unavailable" => ProblemCode::ServiceUnavailable,
                    _ => panic!("unknown public problem"),
                };
                response.assert_status(expected.status());
                assert_eq!(
                    response.json::<Value>()["code"],
                    expected.code(),
                    "{definition}/{case_id}"
                );
            }

            let audit = fs::read_to_string(&fixture.audit_path).expect("audit is readable");
            let new_events = audit.lines().skip(audit_before).collect::<Vec<_>>();
            assert_eq!(new_events.len(), 2, "{definition}/{case_id}");
            let first: Value = serde_json::from_str(new_events[0]).expect("access audit parses");
            let second: Value = serde_json::from_str(new_events[1]).expect("terminal audit parses");
            assert_eq!(
                first["operation"], second["operation"],
                "{definition}/{case_id}"
            );
            for protected in [
                principal.as_str(),
                "2000-01-01",
                "2008-08-02",
                "R-101",
                "R-102",
                "R-201",
                "R-999",
                "CURRENT",
                "SUSPENDED",
                "PENDING",
                "UNIQUE",
                "CONFIRMED",
                "NOT_CONFIRMED",
                "Amadou",
                "Keita",
                "1974-02-11",
                "related_subject_name",
                "synthetic-other-child-record",
                "synthetic-parent-reference-001",
                "synthetic-parent-reference-002",
                "synthetic-non-parent-reference-003",
                "synthetic-substitute-reference",
                "PrivacyCanary",
            ] {
                assert!(
                    !audit.contains(protected),
                    "audit leaked protected material"
                );
            }
            assert_eq!(
                fixture
                    .server
                    .received_requests()
                    .await
                    .expect("request journal is available")
                    .iter()
                    .filter(|request| request.url.path() == source_path)
                    .count(),
                1,
                "{definition}/{case_id} must perform exactly one evidence-data request"
            );
            *executed.entry(definition).or_insert(0_usize) += 1;
        }
    }

    assert_eq!(
        executed,
        BTreeMap::from([
            ("adult", 11),
            ("residence", 9),
            ("licence", 10),
            ("relationship", 20)
        ])
    );
    assert_eq!(
        runtime_equivalents,
        BTreeSet::from([
            "adult/negative-wrong-derived-type:output-gate".to_owned(),
            "licence/negative-exact-date-leak:output-gate".to_owned(),
            "relationship/negative-caller-candidate-substitution:pre-source-rejection".to_owned(),
            "relationship/negative-extra-family-fact:output-gate".to_owned(),
            "relationship/negative-swapped-roles:pre-source-rejection".to_owned(),
            "residence/negative-overly-precise-output:output-gate".to_owned(),
        ]),
        "every runtime-applicable non-source fixture has a named executable equivalent in this module"
    );
    assert_eq!(
        startup_only,
        BTreeSet::from([
            "adult/anti-reconstruction:bundle-rejection".to_owned(),
            "licence/anti-reconstruction:bundle-rejection".to_owned(),
            "relationship/anti-reconstruction:bundle-rejection".to_owned(),
            "residence/anti-reconstruction:bundle-rejection".to_owned(),
        ]),
        "only companion-bundle conflicts remain startup-only because an invalid bundle cannot initialize an EvidenceRuntime"
    );
}

/// Many simultaneous evaluations must leave exactly one verifiable audit chain:
/// two records per released assertion, no forked or interleaved hash links, and
/// one distinct evidence identity per request.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_evidence_requests_keep_one_verifiable_audit_chain() {
    let load = LoadFixture::start().await;
    let outcomes = load.run(LOAD_CONCURRENCY, LOAD_CONCURRENCY).await;
    assert_eq!(
        outcomes.released(),
        LOAD_CONCURRENCY,
        "every admitted concurrent request releases evidence; observed {:?}",
        outcomes.status_counts()
    );

    let audit = load.shutdown().await;
    assert_eq!(
        audit.matches("\"phase\":\"access-attempt\"").count(),
        LOAD_CONCURRENCY
    );
    assert_eq!(
        audit.matches("\"phase\":\"disclosure-release\"").count(),
        LOAD_CONCURRENCY
    );
    assert_eq!(
        released_evidence_ids(&audit).len(),
        LOAD_CONCURRENCY,
        "concurrent releases must not share an evidence identity"
    );

    let verification = verify_jsonl_lines_with_hasher(audit.lines(), &acceptance_audit_hasher())
        .expect("the concurrently written audit chain verifies under the deployment key");
    assert_eq!(verification.records, LOAD_CONCURRENCY * 2);
}

/// Report sustained request throughput against the two candidate ceilings, so
/// the dominant one is attributed from measurement rather than argument.
///
/// This asserts only correctness invariants. The rates themselves are reported,
/// never asserted: they are properties of the host filesystem and core count,
/// and a threshold here would be a flake generator. Read the report, record the
/// numbers with the hardware they came from, and compare across changes.
///
/// ```text
/// cargo test -p registry-evidence --lib -- --ignored --nocapture soak_reports
/// ```
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "opt-in throughput soak; rates are host-specific and reported, not asserted"]
async fn soak_reports_request_throughput_against_the_audit_ceiling() {
    let load = LoadFixture::start().await;

    // Warm the OAuth-free source path, JWKS cache, and connection pool so
    // first-request costs do not land inside the measured window.
    let _ = load.run(LOAD_CONCURRENCY, LOAD_CONCURRENCY).await;

    let outcomes = load.run(SOAK_REQUESTS, LOAD_CONCURRENCY).await;
    let released = outcomes.released();
    let request_rate = released as f64 / outcomes.elapsed.as_secs_f64();

    let source_rate = load.measure_source_rate(SOURCE_PROBE_REQUESTS).await;
    let append_rate = load.measure_audit_append_rate(AUDIT_PROBE_APPENDS).await;
    // Every released assertion writes an access-attempt record before source
    // access and a disclosure-release record after it.
    let audit_ceiling = append_rate / 2.0;

    let percentiles = outcomes.latency_percentiles();
    println!(
        "\n=== Evidence throughput report ===\n\
         host                : {} logical cores\n\
         load                : {SOAK_REQUESTS} requests, {LOAD_CONCURRENCY} concurrent\n\
         released            : {released} in {:.2}s\n\
         \n\
         observed request    : {request_rate:.0} rps\n\
         audit ceiling       : {audit_ceiling:.0} rps ({append_rate:.0} appends/s / 2 records per request)\n\
         mock source floor   : {source_rate:.0} rps\n\
         \n\
         latency p50/p95/p99 : {:.1} / {:.1} / {:.1} ms\n\
         audit share of ceiling: {:.0}%\n\
         ==================================\n",
        std::thread::available_parallelism().map_or(0, std::num::NonZeroUsize::get),
        outcomes.elapsed.as_secs_f64(),
        percentiles.0.as_secs_f64() * 1000.0,
        percentiles.1.as_secs_f64() * 1000.0,
        percentiles.2.as_secs_f64() * 1000.0,
        if audit_ceiling > 0.0 {
            request_rate / audit_ceiling * 100.0
        } else {
            0.0
        },
    );

    assert_eq!(
        released,
        SOAK_REQUESTS,
        "sustained load must not shed requests; observed {:?}",
        outcomes.status_counts()
    );

    let audit = load.shutdown().await;
    let expected_releases = SOAK_REQUESTS + LOAD_CONCURRENCY;
    assert_eq!(
        audit.matches("\"phase\":\"disclosure-release\"").count(),
        expected_releases
    );
    assert_eq!(released_evidence_ids(&audit).len(), expected_releases);
    let verification = verify_jsonl_lines_with_hasher(audit.lines(), &acceptance_audit_hasher())
        .expect("the audit chain written under sustained load verifies");
    assert_eq!(verification.records, expected_releases * 2);
}

fn acceptance_case_time(
    case: &serde_json::Map<String, Value>,
    common: &serde_json::Map<String, Value>,
) -> chrono::DateTime<Utc> {
    if let Some(date) = case
        .get("legal_local_date")
        .or_else(|| common.get("legal_local_date"))
        .and_then(Value::as_str)
    {
        return format!("{date}T05:00:00Z")
            .parse()
            .expect("fixed legal-local fixture date converts");
    }
    case.get("observed_at")
        .or_else(|| common.get("observed_at"))
        .and_then(Value::as_str)
        .unwrap_or("2026-08-02T00:00:00Z")
        .parse()
        .expect("fixed observation time parses")
}

async fn acceptance_runtime() -> AcceptanceRuntime {
    let prepared = prepare_acceptance("subject-binding-secret-canary-32-bytes-minimum").await;
    let runtime = Arc::new(
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await
            .expect("one immutable acceptance runtime initializes"),
    );
    AcceptanceRuntime {
        _temporary: prepared.temporary,
        bundle_root: prepared.bundle_root,
        runtime_path: prepared.runtime_path,
        runtime,
        server: prepared.server,
        audit_path: prepared.audit_path,
    }
}

#[tokio::test]
async fn request_batch_sequential_fallback_runs_every_multistage_plan_in_item_order() {
    let search_server = MockServer::start().await;
    let search_origin = search_server.uri();
    let search_prepared = prepare_fixture_with_mutation(
        "subject-binding-secret-canary-32-bytes-minimum",
        &search_origin,
        &FixtureCeilings::deployment_defaults(),
        |bundle_root| configure_search_then_fetch(bundle_root, &search_origin),
    );
    let search_runtime = EvidenceRuntime::initialize_with_authenticator(
        &search_prepared.runtime_path,
        authenticator(),
    )
    .await
    .expect("search-then-fetch runtime initializes");
    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total": 1,
            "record_id": "record-001"
        })))
        .expect(2)
        .mount(&search_server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/records/record-001"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"date_of_birth": "2000-01-01"})),
        )
        .expect(2)
        .mount(&search_server)
        .await;
    let search_release = search_runtime
        .evaluate_request_batch(
            "operation-request-batch-search-fetch-order",
            &access_token(None),
            &adult_request_batch(2),
        )
        .await
        .expect("request batch executes search then fetch for each item");
    assert!(
        serde_json::from_slice::<EvidenceRequestBatchResponse>(search_release.bytes())
            .expect("search-then-fetch response parses")
            .items
            .iter()
            .all(|item| matches!(item, EvidenceRequestBatchResponseItem::Evidence { .. }))
    );
    let search_paths = search_server
        .received_requests()
        .await
        .expect("search source journal is available")
        .iter()
        .map(|request| request.url.path().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        search_paths,
        [
            "/v1/search",
            "/v1/records/record-001",
            "/v1/search",
            "/v1/records/record-001"
        ],
        "the second item starts only after the first item completes"
    );
    assert_eq!(
        request_batch_audit_access_indices(&search_prepared.audit_path),
        [vec![0], vec![0], vec![1], vec![1]]
    );

    let set_server = MockServer::start().await;
    let set_origin = set_server.uri();
    let set_prepared = prepare_fixture_with_mutation(
        "subject-binding-secret-canary-32-bytes-minimum",
        &set_origin,
        &FixtureCeilings::deployment_defaults(),
        |bundle_root| configure_fetch_set(bundle_root, &set_origin),
    );
    enable_fetch_set_acquisition(&set_prepared.runtime_path);
    let set_runtime =
        EvidenceRuntime::initialize_with_authenticator(&set_prepared.runtime_path, authenticator())
            .await
            .expect("fetch-set runtime initializes");
    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total": 1,
            "record_id": "record-001",
            "partner_ref": "partner-77"
        })))
        .expect(2)
        .mount(&set_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/records/record-001"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"date_of_birth": "2000-01-01"})),
        )
        .expect(2)
        .mount(&set_server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/partners"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "partner_status": "active"
        })))
        .expect(2)
        .mount(&set_server)
        .await;
    let set_release = set_runtime
        .evaluate_request_batch(
            "operation-request-batch-fetch-set-order",
            &access_token(None),
            &adult_request_batch(2),
        )
        .await
        .expect("request batch executes every fetch-set stage for each item");
    assert!(
        serde_json::from_slice::<EvidenceRequestBatchResponse>(set_release.bytes())
            .expect("fetch-set response parses")
            .items
            .iter()
            .all(|item| matches!(item, EvidenceRequestBatchResponseItem::Evidence { .. }))
    );
    let set_paths = set_server
        .received_requests()
        .await
        .expect("fetch-set source journal is available")
        .iter()
        .map(|request| request.url.path().to_owned())
        .collect::<Vec<_>>();
    assert_eq!(
        set_paths,
        [
            "/v1/search",
            "/v1/records/record-001",
            "/v1/partners",
            "/v1/search",
            "/v1/records/record-001",
            "/v1/partners"
        ],
        "fetch-set stages never overlap the next logical item"
    );
    assert_eq!(
        request_batch_audit_access_indices(&set_prepared.audit_path),
        [vec![0], vec![0], vec![0], vec![1], vec![1], vec![1]]
    );
}

#[tokio::test]
async fn request_batch_sequential_fallback_executes_sqlite_items_in_request_order() {
    let server = MockServer::start().await;
    let mut extract_path = None;
    let prepared = prepare_fixture_with_mutation(
        "subject-binding-secret-canary-32-bytes-minimum",
        &server.uri(),
        &FixtureCeilings::deployment_defaults(),
        |bundle_root| {
            extract_path = Some(configure_sqlite_adult_source(bundle_root));
        },
    );
    let extract_path = extract_path.expect("SQLite extract path is captured");
    bind_sqlite_extract(&prepared.runtime_path, &extract_path);
    DeploymentInputs::load(&prepared.runtime_path)
        .unwrap_or_else(|error| panic!("SQLite deployment inputs load: {error:?}"));
    let runtime =
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await
            .expect("runtime with a reviewed SQLite extract initializes");

    let released = runtime
        .evaluate_request_batch(
            "operation-request-batch-sqlite-order",
            &access_token(None),
            &adult_request_batch(2),
        )
        .await
        .expect("SQLite source evaluates every logical item sequentially");
    let response: EvidenceRequestBatchResponse =
        serde_json::from_slice(released.bytes()).expect("SQLite batch response parses");
    assert!(response
        .items
        .iter()
        .all(|item| matches!(item, EvidenceRequestBatchResponseItem::Evidence { .. })));
    assert_eq!(
        request_batch_audit_access_indices(&prepared.audit_path),
        [vec![0], vec![1]],
        "the local statement source still records physical calls in input order"
    );
    assert!(server
        .received_requests()
        .await
        .expect("HTTP source journal is available")
        .is_empty());
}

#[tokio::test]
async fn search_then_fetch_is_two_fixed_audited_calls_with_validated_fact_handoff() {
    let server = MockServer::start().await;
    let source_origin = server.uri();
    let prepared = prepare_fixture_with_mutation(
        "subject-binding-secret-canary-32-bytes-minimum",
        &source_origin,
        &FixtureCeilings::deployment_defaults(),
        |bundle_root| configure_search_then_fetch(bundle_root, &source_origin),
    );
    let captured = Arc::new(
        crate::bundle::Bundle::load(&prepared.bundle_root)
            .unwrap_or_else(|error| panic!("search-then-fetch bundle loads: {error:?}")),
    );
    assert_eq!(
        captured
            .config
            .requirement_acquisition_posture(&adult_request().requirement),
        Some(crate::config::AcquisitionPosture::RecordTransformed)
    );
    let kernel = crate::kernel::OfflineKernel::compile(captured)
        .unwrap_or_else(|error| panic!("search-then-fetch kernel compiles: {error:?}"));
    let prior_facts = BTreeMap::from([("record_id".to_owned(), json!("record-001"))]);
    let facts = match kernel
        .extract_source(
            "source-a-fetch",
            &json!({"date_of_birth": "2000-01-01"}),
            &prior_facts,
        )
        .expect("fetch response extracts")
    {
        crate::model::LookupResult::Match(facts) => facts,
        _ => panic!("fetch response is a unique match"),
    };
    kernel
        .derive_and_validate(
            &adult_request().requirement,
            &facts,
            Utc::now(),
            crate::kernel::ValueProjection {
                scope: crate::kernel::EvidenceScope::AudienceScoped {
                    audience: EVIDENCE_AUDIENCE,
                    request_nonce: crate::model::OFFLINE_EVALUATION_REQUEST_NONCE,
                },
                binding_key: b"subject-binding-secret-canary-32-bytes-minimum",
                binding_key_version: 1,
            },
        )
        .unwrap_or_else(|error| panic!("fetch facts derive: {error:?}"));
    let runtime = Arc::new(
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await
            .expect("search-then-fetch runtime initializes"),
    );

    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .and(header("authorization", format!("Bearer {BEARER}").as_str()))
        .and(body_json(json!({
            "lookup": {
                "given_name": "Amina",
                "family_name": "Diallo",
                "birth_date": "2000-01-01"
            },
            "fields": ["record_id"],
            "limit": 2
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total": 1,
            "record_id": "record-001"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/records/record-001"))
        .and(header("authorization", format!("Bearer {BEARER}").as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "date_of_birth": "2000-01-01"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let request = adult_request();
    let jws = runtime
        .evaluate("operation-search-then-fetch", &access_token(None), &request)
        .await
        .expect("the fixed chain produces Evidence");
    let serialized = serde_json::to_vec(&jws).expect("JWS serializes");
    let evidence = verify_flattened_jws(
        &serialized,
        runtime.jwks(),
        &verification_policy(&runtime, &request, &serialized),
    )
    .expect("the chained assertion verifies");
    assert_eq!(
        evidence.supported_values[0].value,
        PublicValue::Boolean(true)
    );

    let requests = server
        .received_requests()
        .await
        .expect("request journal is available");
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0].url.path(), "/v1/search");
    assert_eq!(requests[1].url.path(), "/v1/records/record-001");

    let audit = fs::read_to_string(&prepared.audit_path).expect("audit is readable");
    let events = audit
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("audit event is JSON"))
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0]["record"]["phase"], "access-attempt");
    assert_eq!(events[0]["record"]["sourceId"], "source-a");
    assert_eq!(events[1]["record"]["phase"], "access-attempt");
    assert_eq!(events[1]["record"]["sourceId"], "source-a-fetch");
    assert_eq!(events[2]["record"]["phase"], "disclosure-release");
    assert_eq!(events[2]["record"]["sourceId"], "source-a-fetch");
    assert!(!audit.contains("record-001"));
}

#[tokio::test]
async fn declared_unresolved_fetch_after_unique_search_is_dependency_failure() {
    let server = MockServer::start().await;
    let source_origin = server.uri();
    let prepared = prepare_fixture_with_mutation(
        "subject-binding-secret-canary-32-bytes-minimum",
        &source_origin,
        &FixtureCeilings::deployment_defaults(),
        |bundle_root| {
            configure_search_then_fetch(bundle_root, &source_origin);
            let path = bundle_root.join("evidence.yaml");
            let mut config = fs::read_to_string(&path).expect("config is readable");
            replace_exact(
                &mut config,
                "  source-a-fetch:\n    transport: http-json\n",
                "  source-a-fetch:\n    transport: http-json\n    unresolvedProblem: {status: 404, type: https://id.example.invalid/problems/unresolved, code: consultation.unresolved}\n",
                1,
            );
            fs::write(path, config).expect("fetch declaration is written");
        },
    );
    let runtime =
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await
            .expect("declared unresolved fetch runtime initializes");
    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total": 1,
            "record_id": "record-001"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/records/record-001"))
        .respond_with(
            ResponseTemplate::new(404).set_body_raw(
                r#"{"type":"https://id.example.invalid/problems/unresolved","title":"Unresolved","status":404,"detail":"not resolved","code":"consultation.unresolved","traceId":"fetch-trace-canary"}"#,
                "application/problem+json",
            ),
        )
        .expect(1)
        .mount(&server)
        .await;
    let error = runtime
        .evaluate(
            "operation-declared-unresolved-fetch",
            &access_token(None),
            &adult_request(),
        )
        .await
        .expect_err("fetch unresolved is not authoritative absence");
    assert_eq!(error.problem(), ProblemCode::DependencyUnavailable);
    let audit = fs::read_to_string(&prepared.audit_path).expect("audit is readable");
    assert!(audit.contains("\"decision\":\"dependency-failure\""));
    assert!(audit.contains("\"safeErrorCategory\":\"fetch-result\""));
    assert!(!audit.contains("fetch-trace-canary"));
}

#[tokio::test]
async fn search_then_fetch_stops_after_an_unresolved_search() {
    let server = MockServer::start().await;
    let source_origin = server.uri();
    let prepared = prepare_fixture_with_mutation(
        "subject-binding-secret-canary-32-bytes-minimum",
        &source_origin,
        &FixtureCeilings::deployment_defaults(),
        |bundle_root| configure_search_then_fetch(bundle_root, &source_origin),
    );
    let runtime =
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await
            .expect("search-then-fetch runtime initializes");
    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"total": 0})))
        .expect(1)
        .mount(&server)
        .await;

    let error = runtime
        .evaluate(
            "operation-search-without-match",
            &access_token(None),
            &adult_request(),
        )
        .await
        .expect_err("an unresolved search releases no Evidence");
    assert_eq!(error.problem(), ProblemCode::EvidenceNotAvailable);
    let requests = server
        .received_requests()
        .await
        .expect("request journal is available");
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].url.path(), "/v1/search");
    let audit = fs::read_to_string(&prepared.audit_path).expect("audit is readable");
    assert_eq!(audit.lines().count(), 2);
    assert!(audit.contains("\"sourceId\":\"source-a\""));
    assert!(!audit.contains("source-a-fetch"));
}

#[tokio::test]
async fn search_then_fetch_treats_an_unresolved_fetch_as_dependency_failure() {
    let server = MockServer::start().await;
    let source_origin = server.uri();
    let prepared = prepare_fixture_with_mutation(
        "subject-binding-secret-canary-32-bytes-minimum",
        &source_origin,
        &FixtureCeilings::deployment_defaults(),
        |bundle_root| {
            configure_search_then_fetch(bundle_root, &source_origin);
            fs::write(
                bundle_root.join("adapters/adult-status-fetch-source.rhai"),
                r#"fn extract(source_response, context) {
    #{outcome: "no_match"}
}
"#,
            )
            .expect("unresolved fetch extraction is written");
        },
    );
    let runtime =
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await
            .expect("search-then-fetch runtime initializes");
    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total": 1,
            "record_id": "record-001"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/records/record-001"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(1)
        .mount(&server)
        .await;

    let error = runtime
        .evaluate(
            "operation-unresolved-fetch",
            &access_token(None),
            &adult_request(),
        )
        .await
        .expect_err("an unresolved fetch is not authoritative absence");
    assert_eq!(error.problem(), ProblemCode::DependencyUnavailable);
    assert_eq!(
        server
            .received_requests()
            .await
            .expect("request journal is available")
            .len(),
        2
    );
    let audit = fs::read_to_string(&prepared.audit_path).expect("audit is readable");
    assert!(audit.contains("\"safeErrorCategory\":\"fetch-result\""));
    assert!(!audit.contains("record-001"));
}

#[test]
fn search_then_fetch_rejects_an_unbound_prior_fact_at_startup() {
    let source_origin = "http://127.0.0.1:18081";
    let prepared = prepare_fixture_with_mutation(
        "subject-binding-secret-canary-32-bytes-minimum",
        source_origin,
        &FixtureCeilings::deployment_defaults(),
        |bundle_root| {
            configure_search_then_fetch(bundle_root, source_origin);
            let configuration_path = bundle_root.join("evidence.yaml");
            let mut configuration =
                fs::read_to_string(&configuration_path).expect("chained configuration is readable");
            replace_exact(
                &mut configuration,
                "record_id: {from: prior-fact, field: record_id}",
                "record_id: {from: prior-fact, field: missing_record_id}",
                1,
            );
            fs::write(configuration_path, configuration)
                .expect("invalid prior-fact binding is written");
        },
    );
    let error = crate::bundle::Bundle::load(&prepared.bundle_root)
        .expect_err("an unbound prior fact fails before serving");
    assert_eq!(
        error.to_string(),
        "an Evidence bundle artifact is invalid: fetch path binding references an unknown search fact"
    );
}

#[tokio::test]
async fn fetch_set_is_one_search_then_one_fixed_call_per_declared_member_in_order() {
    let server = MockServer::start().await;
    let source_origin = server.uri();
    let prepared = prepare_fixture_with_mutation(
        "subject-binding-secret-canary-32-bytes-minimum",
        &source_origin,
        &FixtureCeilings::deployment_defaults(),
        |bundle_root| configure_fetch_set(bundle_root, &source_origin),
    );
    enable_fetch_set_acquisition(&prepared.runtime_path);
    let runtime =
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await
            .expect("fetch-set runtime initializes");

    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .and(header("authorization", format!("Bearer {BEARER}").as_str()))
        .and(body_json(json!({
            "lookup": {
                "given_name": "Amina",
                "family_name": "Diallo",
                "birth_date": "2000-01-01"
            },
            "fields": ["record_id", "partner_ref"],
            "limit": 2
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total": 1,
            "record_id": "record-001",
            "partner_ref": "partner-77"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/records/record-001"))
        .and(header("authorization", format!("Bearer {BEARER}").as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "date_of_birth": "2000-01-01"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/partners"))
        .and(header("authorization", format!("Bearer {BEARER}").as_str()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "partner_status": "active"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let request = adult_request();
    let jws = runtime
        .evaluate("operation-fetch-set-ordered", &access_token(None), &request)
        .await
        .expect("the declared fetch set produces Evidence");
    let serialized = serde_json::to_vec(&jws).expect("JWS serializes");
    let evidence = verify_flattened_jws(
        &serialized,
        runtime.jwks(),
        &verification_policy(&runtime, &request, &serialized),
    )
    .expect("the fetch-set assertion verifies");
    assert_eq!(
        evidence.supported_values[0].value,
        PublicValue::Boolean(true)
    );

    let requests = server
        .received_requests()
        .await
        .expect("request journal is available");
    assert_eq!(requests.len(), 3);
    assert_eq!(requests[0].url.path(), "/v1/search");
    assert_eq!(requests[1].url.path(), "/v1/records/record-001");
    assert_eq!(requests[2].url.path(), "/v1/partners");

    let audit = fs::read_to_string(&prepared.audit_path).expect("audit is readable");
    let events = audit
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("audit event is JSON"))
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 4);
    assert_eq!(events[0]["record"]["phase"], "access-attempt");
    assert_eq!(events[0]["record"]["sourceId"], "source-a");
    assert_eq!(events[1]["record"]["phase"], "access-attempt");
    assert_eq!(events[1]["record"]["sourceId"], "source-a-fetch");
    assert_eq!(events[2]["record"]["phase"], "access-attempt");
    assert_eq!(events[2]["record"]["sourceId"], "source-a-partner");
    assert_eq!(events[3]["record"]["phase"], "disclosure-release");
    assert_eq!(
        events[3]["record"]["sourceIds"],
        json!(["source-a", "source-a-fetch", "source-a-partner"])
    );
    assert_eq!(
        events[3]["record"]["adapterIds"],
        json!([
            "adult-status-source",
            "adult-status-fetch-source",
            "adult-status-partner-source"
        ])
    );
    assert_eq!(events[3]["record"]["sourceId"], "source-a-partner");
    assert_eq!(
        events[3]["record"]["adapterId"],
        "adult-status-partner-source"
    );
    assert!(!audit.contains("record-001"));
    assert!(!audit.contains("partner-77"));
}

#[tokio::test]
async fn fetch_set_member_receives_only_its_declared_fact_inputs() {
    let server = MockServer::start().await;
    let source_origin = server.uri();
    let prepared = prepare_fixture_with_mutation(
        "subject-binding-secret-canary-32-bytes-minimum",
        &source_origin,
        &FixtureCeilings::deployment_defaults(),
        |bundle_root| {
            configure_fetch_set(bundle_root, &source_origin);
            // The first member declared `record_id` alone, so the reference the
            // second member declared must not be readable from its context at
            // all. Reading it is a preparation failure, not an absent value the
            // script could route around.
            fs::write(
                bundle_root.join("adapters/adult-status-fetch-prepare.rhai"),
                r#"fn prepare(selectors, context) {
    required(context["prior_facts"]["partner_ref"], "required_fact_missing");
    #{query: [], body: #{lookup: context["prior_facts"]}}
}
"#,
            )
            .expect("undeclared prior-fact preparation is written");
        },
    );
    enable_fetch_set_acquisition(&prepared.runtime_path);
    let runtime =
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await
            .expect("fetch-set runtime initializes");
    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total": 1,
            "record_id": "record-001",
            "partner_ref": "partner-77"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/partners"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "partner_status": "active"
        })))
        .expect(0)
        .mount(&server)
        .await;

    let error = runtime
        .evaluate(
            "operation-fetch-set-undeclared",
            &access_token(None),
            &adult_request(),
        )
        .await
        .expect_err("a member reading an undeclared fact releases no Evidence");
    assert_eq!(error.problem(), ProblemCode::ServiceUnavailable);
    let requests = server
        .received_requests()
        .await
        .expect("request journal is available");
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].url.path(), "/v1/search");
    let audit = fs::read_to_string(&prepared.audit_path).expect("audit is readable");
    assert!(audit.contains("\"safeErrorCategory\":\"request-preparation\""));
    assert!(!audit.contains("source-a-partner"));
    assert!(!audit.contains("partner-77"));
}

#[tokio::test]
async fn fetch_set_member_body_carries_only_its_declared_fact_inputs() {
    let server = MockServer::start().await;
    let source_origin = server.uri();
    let prepared = prepare_fixture_with_mutation(
        "subject-binding-secret-canary-32-bytes-minimum",
        &source_origin,
        &FixtureCeilings::deployment_defaults(),
        |bundle_root| configure_fetch_set(bundle_root, &source_origin),
    );
    enable_fetch_set_acquisition(&prepared.runtime_path);
    let runtime =
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await
            .expect("fetch-set runtime initializes");
    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total": 1,
            "record_id": "record-001",
            "partner_ref": "partner-77"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/records/record-001"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "date_of_birth": "2000-01-01"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/partners"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "partner_status": "active"
        })))
        .expect(1)
        .mount(&server)
        .await;

    runtime
        .evaluate(
            "operation-fetch-set-body-channel",
            &access_token(None),
            &adult_request(),
        )
        .await
        .expect("the declared fetch set produces Evidence");

    let requests = server
        .received_requests()
        .await
        .expect("request journal is available");
    assert_eq!(requests.len(), 3);
    // A prior fact leaves the process either through a declared path binding,
    // which startup inspects, or through the JSON body a prepare script builds,
    // which startup never reads. The allowlist projection is the only control
    // over the second channel, so it is asserted on the bytes that were sent.
    let first_body = String::from_utf8(requests[1].body.clone()).expect("member body is UTF-8");
    assert!(first_body.contains("record-001"));
    assert!(!first_body.contains("partner-77"));
    let second_body = String::from_utf8(requests[2].body.clone()).expect("member body is UTF-8");
    assert!(second_body.contains("partner-77"));
    assert!(!second_body.contains("record-001"));
}

#[tokio::test]
async fn fetch_set_stops_after_an_unresolved_search() {
    let server = MockServer::start().await;
    let source_origin = server.uri();
    let prepared = prepare_fixture_with_mutation(
        "subject-binding-secret-canary-32-bytes-minimum",
        &source_origin,
        &FixtureCeilings::deployment_defaults(),
        |bundle_root| configure_fetch_set(bundle_root, &source_origin),
    );
    enable_fetch_set_acquisition(&prepared.runtime_path);
    let runtime =
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await
            .expect("fetch-set runtime initializes");
    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"total": 0})))
        .expect(1)
        .mount(&server)
        .await;

    let error = runtime
        .evaluate(
            "operation-fetch-set-no-search",
            &access_token(None),
            &adult_request(),
        )
        .await
        .expect_err("an unresolved search releases no Evidence");
    assert_eq!(error.problem(), ProblemCode::EvidenceNotAvailable);
    let requests = server
        .received_requests()
        .await
        .expect("request journal is available");
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].url.path(), "/v1/search");
    let audit = fs::read_to_string(&prepared.audit_path).expect("audit is readable");
    assert_eq!(audit.lines().count(), 2);
    assert!(audit.contains("\"sourceId\":\"source-a\""));
    assert!(!audit.contains("source-a-fetch"));
    assert!(!audit.contains("source-a-partner"));
}

#[tokio::test]
async fn fetch_set_stops_at_the_first_unresolved_member_and_calls_no_further_source() {
    let server = MockServer::start().await;
    let source_origin = server.uri();
    let prepared = prepare_fixture_with_mutation(
        "subject-binding-secret-canary-32-bytes-minimum",
        &source_origin,
        &FixtureCeilings::deployment_defaults(),
        |bundle_root| {
            configure_fetch_set(bundle_root, &source_origin);
            fs::write(
                bundle_root.join("adapters/adult-status-fetch-source.rhai"),
                r#"fn extract(source_response, context) {
    #{outcome: "no_match"}
}
"#,
            )
            .expect("unresolved member extraction is written");
        },
    );
    enable_fetch_set_acquisition(&prepared.runtime_path);
    let runtime =
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await
            .expect("fetch-set runtime initializes");
    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total": 1,
            "record_id": "record-001",
            "partner_ref": "partner-77"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/records/record-001"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({})))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/partners"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "partner_status": "active"
        })))
        .expect(0)
        .mount(&server)
        .await;

    let error = runtime
        .evaluate(
            "operation-fetch-set-unresolved",
            &access_token(None),
            &adult_request(),
        )
        .await
        .expect_err("an unresolved member is not authoritative absence");
    assert_eq!(error.problem(), ProblemCode::DependencyUnavailable);
    let requests = server
        .received_requests()
        .await
        .expect("request journal is available");
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[1].url.path(), "/v1/records/record-001");
    let audit = fs::read_to_string(&prepared.audit_path).expect("audit is readable");
    assert!(audit.contains("\"safeErrorCategory\":\"fetch-result\""));
    assert!(!audit.contains("source-a-partner"));
    assert!(!audit.contains("record-001"));
}

#[tokio::test]
async fn declared_unresolved_fetch_set_member_after_unique_search_is_dependency_failure() {
    let server = MockServer::start().await;
    let source_origin = server.uri();
    let prepared = prepare_fixture_with_mutation(
        "subject-binding-secret-canary-32-bytes-minimum",
        &source_origin,
        &FixtureCeilings::deployment_defaults(),
        |bundle_root| {
            configure_fetch_set(bundle_root, &source_origin);
            let path = bundle_root.join("evidence.yaml");
            let mut config = fs::read_to_string(&path).expect("fetch-set config is readable");
            replace_exact(
                &mut config,
                "  source-a-fetch:\n    transport: http-json\n",
                "  source-a-fetch:\n    transport: http-json\n    unresolvedProblem: {status: 404, type: https://id.example.invalid/problems/unresolved, code: consultation.unresolved}\n",
                1,
            );
            fs::write(path, config).expect("fetch-set unresolved declaration is written");
        },
    );
    enable_fetch_set_acquisition(&prepared.runtime_path);
    let runtime =
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await
            .expect("declared unresolved fetch-set runtime initializes");
    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total": 1,
            "record_id": "record-001",
            "partner_ref": "partner-77"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/records/record-001"))
        .respond_with(ResponseTemplate::new(404).set_body_raw(
            r#"{"type":"https://id.example.invalid/problems/unresolved","title":"Unresolved","status":404,"detail":"not resolved","code":"consultation.unresolved","traceId":"fetch-set-trace-canary"}"#,
            "application/problem+json",
        ))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/partners"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "partner_status": "active"
        })))
        .expect(0)
        .mount(&server)
        .await;

    let error = runtime
        .evaluate(
            "operation-declared-unresolved-fetch-set",
            &access_token(None),
            &adult_request(),
        )
        .await
        .expect_err("a declared unresolved member is a dependency inconsistency");
    assert_eq!(error.problem(), ProblemCode::DependencyUnavailable);
    let requests = server
        .received_requests()
        .await
        .expect("request journal is available");
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[1].url.path(), "/v1/records/record-001");
    let audit = fs::read_to_string(&prepared.audit_path).expect("audit is readable");
    assert!(audit.contains("\"decision\":\"dependency-failure\""));
    assert!(audit.contains("\"safeErrorCategory\":\"fetch-result\""));
    assert!(!audit.contains("source-a-partner"));
    assert!(!audit.contains("fetch-set-trace-canary"));
    assert!(!format!("{error:?}").contains("fetch-set-trace-canary"));
}

#[tokio::test]
async fn fetch_set_abandons_acquisition_when_the_declared_budget_is_exhausted() {
    let server = MockServer::start().await;
    let source_origin = server.uri();
    let prepared = prepare_fixture_with_mutation(
        "subject-binding-secret-canary-32-bytes-minimum",
        &source_origin,
        &FixtureCeilings::deployment_defaults(),
        |bundle_root| {
            configure_fetch_set(bundle_root, &source_origin);
            let configuration_path = bundle_root.join("evidence.yaml");
            let mut configuration = fs::read_to_string(&configuration_path)
                .expect("fetch-set configuration is readable");
            replace_exact(
                &mut configuration,
                "      maximumAcquisitionMilliseconds: 5000",
                "      maximumAcquisitionMilliseconds: 800",
                1,
            );
            fs::write(configuration_path, configuration)
                .expect("shortened acquisition budget is written");
        },
    );
    enable_fetch_set_acquisition(&prepared.runtime_path);
    let runtime =
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await
            .expect("fetch-set runtime initializes");
    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total": 1,
            "record_id": "record-001",
            "partner_ref": "partner-77"
        })))
        .expect(1)
        .mount(&server)
        .await;
    // Well inside the member's own three-second ceiling and well outside the
    // acquisition budget, so the budget is what refuses and the two remain
    // separately enforced.
    Mock::given(method("POST"))
        .and(path("/v1/records/record-001"))
        .respond_with(
            ResponseTemplate::new(200)
                .set_delay(Duration::from_millis(2500))
                .set_body_json(json!({"date_of_birth": "2000-01-01"})),
        )
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/partners"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "partner_status": "active"
        })))
        .expect(0)
        .mount(&server)
        .await;

    let error = runtime
        .evaluate(
            "operation-fetch-set-budget",
            &access_token(None),
            &adult_request(),
        )
        .await
        .expect_err("an exhausted acquisition budget releases no Evidence");
    assert_eq!(error.problem(), ProblemCode::DependencyUnavailable);
    let requests = server
        .received_requests()
        .await
        .expect("request journal is available");
    assert_eq!(requests.len(), 2);
    let audit = fs::read_to_string(&prepared.audit_path).expect("audit is readable");
    assert_eq!(audit.lines().count(), 3);
    assert!(audit.contains("\"safeErrorCategory\":\"acquisition-budget\""));
    assert!(!audit.contains("\"safeErrorCategory\":\"source-timeout\""));
    assert!(!audit.contains("source-a-partner"));
}

#[test]
fn fetch_set_reads_an_exhausted_budget_before_it_enters_the_next_stage() {
    let start = Instant::now();
    let deadline = start + Duration::from_millis(50);
    assert!(!acquisition_budget_exhausted(Some(deadline), start));
    assert!(!acquisition_budget_exhausted(
        Some(deadline),
        start + Duration::from_millis(49)
    ));
    // The deadline itself is spent, not the last usable instant: a stage
    // entered with nothing left would still poll its request once, and one
    // poll is enough to contact a source the budget no longer covers.
    assert!(acquisition_budget_exhausted(
        Some(deadline),
        start + Duration::from_millis(50)
    ));
    assert!(acquisition_budget_exhausted(
        Some(deadline),
        start + Duration::from_millis(51)
    ));
    assert!(!acquisition_budget_exhausted(
        None,
        start + Duration::from_secs(3600)
    ));
}

#[tokio::test]
async fn fetch_set_derivation_receives_the_union_of_every_stage_fact_set() {
    let server = MockServer::start().await;
    let source_origin = server.uri();
    let prepared = prepare_fixture_with_mutation(
        "subject-binding-secret-canary-32-bytes-minimum",
        &source_origin,
        &FixtureCeilings::deployment_defaults(),
        |bundle_root| {
            configure_fetch_set(bundle_root, &source_origin);
            // The set form hands the derivation every stage's facts, not only
            // the last member's, so a derivation that reads all four names is
            // the assertion. A name the union did not carry reads as unit and
            // collapses the released value to false.
            fs::write(
                bundle_root.join("derivations/adult-status.rhai"),
                r#"fn derive(facts, selectors, evaluation_context) {
    let complete = facts["record_id"] == "record-001"
        && facts["partner_ref"] == "partner-77"
        && facts["date_of_birth"] == "2000-01-01"
        && facts["partner_status"] == "active";
    [#{concept_id: "urn:example:fixture:concept:adult-status", value: complete}]
}
"#,
            )
            .expect("union derivation is written");
        },
    );
    enable_fetch_set_acquisition(&prepared.runtime_path);
    let runtime =
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await
            .expect("fetch-set runtime initializes");
    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total": 1,
            "record_id": "record-001",
            "partner_ref": "partner-77"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/records/record-001"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "date_of_birth": "2000-01-01"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/partners"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "partner_status": "active"
        })))
        .expect(1)
        .mount(&server)
        .await;

    let request = adult_request();
    let jws = runtime
        .evaluate("operation-fetch-set-union", &access_token(None), &request)
        .await
        .expect("the merged fact set produces Evidence");
    let serialized = serde_json::to_vec(&jws).expect("JWS serializes");
    let evidence = verify_flattened_jws(
        &serialized,
        runtime.jwks(),
        &verification_policy(&runtime, &request, &serialized),
    )
    .expect("the fetch-set assertion verifies");
    assert_eq!(
        evidence.supported_values[0].value,
        PublicValue::Boolean(true)
    );
}

#[tokio::test]
async fn fetch_set_refuses_a_merged_fact_set_larger_than_one_derivation_accepts() {
    let server = MockServer::start().await;
    let source_origin = server.uri();
    let prepared = prepare_fixture_with_mutation(
        "subject-binding-secret-canary-32-bytes-minimum",
        &source_origin,
        &FixtureCeilings::deployment_defaults(),
        |bundle_root| {
            configure_fetch_set(bundle_root, &source_origin);
            widen_fetch_set_to_four_bulk_members(bundle_root, &source_origin);
        },
    );
    enable_fetch_set_acquisition(&prepared.runtime_path);
    let runtime =
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await
            .expect("fetch-set runtime initializes");
    // Every stage stays inside the bound its own extraction accepts and inside
    // the total string size one script may return, so nothing before the merge
    // can refuse. Only the widest declarable set, merged, crosses what a single
    // derivation accepts.
    let bulk = json!(vec!["x".repeat(64); 250]);
    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total": 1,
            "record_id": "record-001",
            "partner_ref": "partner-77",
            "search_detail": bulk
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/records/record-001"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "date_of_birth": "2000-01-01",
            "record_detail": bulk
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/partners"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "partner_status": "active",
            "partner_detail": bulk
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/third"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "third_status": "active",
            "third_detail": bulk
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/v1/fourth"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "fourth_status": "active",
            "fourth_detail": bulk
        })))
        .expect(1)
        .mount(&server)
        .await;

    let error = runtime
        .evaluate(
            "operation-fetch-set-oversized",
            &access_token(None),
            &adult_request(),
        )
        .await
        .expect_err("a merged fact set past the derivation bound releases no Evidence");
    assert_eq!(error.problem(), ProblemCode::ServiceUnavailable);
    assert_eq!(
        server
            .received_requests()
            .await
            .expect("request journal is available")
            .len(),
        5
    );
    let audit = fs::read_to_string(&prepared.audit_path).expect("audit is readable");
    let events = audit
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("audit event is JSON"))
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 6);
    assert_eq!(events[5]["record"]["phase"], "transient-failure");
    assert_eq!(
        events[5]["record"]["safeErrorCategory"],
        "acquisition-fact-size"
    );
    assert_eq!(events[5]["record"]["sourceId"], "source-a-fourth");
    assert!(events[5]["record"].get("sourceIds").is_none());
    assert!(!audit.contains("record-001"));
    assert!(!audit.contains("xxxx"));
}

#[tokio::test]
async fn search_then_fetch_release_still_omits_source_arrays() {
    let server = MockServer::start().await;
    let source_origin = server.uri();
    let prepared = prepare_fixture_with_mutation(
        "subject-binding-secret-canary-32-bytes-minimum",
        &source_origin,
        &FixtureCeilings::deployment_defaults(),
        |bundle_root| configure_search_then_fetch(bundle_root, &source_origin),
    );
    let runtime =
        EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
            .await
            .expect("search-then-fetch runtime initializes");
    Mock::given(method("POST"))
        .and(path("/v1/search"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total": 1,
            "record_id": "record-001"
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("GET"))
        .and(path("/v1/records/record-001"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "date_of_birth": "2000-01-01"
        })))
        .expect(1)
        .mount(&server)
        .await;

    runtime
        .evaluate(
            "operation-frozen-release-shape",
            &access_token(None),
            &adult_request(),
        )
        .await
        .expect("the frozen chain produces Evidence");

    let audit = fs::read_to_string(&prepared.audit_path).expect("audit is readable");
    let events = audit
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("audit event is JSON"))
        .collect::<Vec<_>>();
    assert_eq!(events.len(), 3);
    assert_eq!(events[2]["record"]["phase"], "disclosure-release");
    // The frozen forms release exactly the event they always released: the
    // stage arrays belong to the acquisition that makes more than two calls.
    assert!(events[2]["record"].get("sourceIds").is_none());
    assert!(events[2]["record"].get("adapterIds").is_none());
}

async fn prepare_acceptance(binding_secret: &str) -> PreparedAcceptance {
    let server = MockServer::start().await;
    let prepared = prepare_fixture(
        binding_secret,
        &server.uri(),
        &FixtureCeilings::deployment_defaults(),
    );
    PreparedAcceptance {
        temporary: prepared.temporary,
        bundle_root: prepared.bundle_root,
        runtime_path: prepared.runtime_path,
        server,
        audit_path: prepared.audit_path,
    }
}

/// Copy the acceptance bundle into a temporary root, point every source at
/// `source_origin`, write the synthetic secrets and the runtime configuration
/// under `ceilings`, then make the bundle and runtime file read-only.
fn prepare_fixture(
    binding_secret: &str,
    source_origin: &str,
    ceilings: &FixtureCeilings,
) -> PreparedFixture {
    prepare_fixture_with_mutation(binding_secret, source_origin, ceilings, |_| {})
}

fn prepare_fixture_with_mutation(
    binding_secret: &str,
    source_origin: &str,
    ceilings: &FixtureCeilings,
    mutate_bundle: impl FnOnce(&Path),
) -> PreparedFixture {
    prepare_fixture_root_with_mutation(
        &fixture_root(),
        binding_secret,
        source_origin,
        ceilings,
        mutate_bundle,
    )
}

fn configure_exact_relay_lookup_source(bundle_root: &Path) {
    let config_path = bundle_root.join("evidence.yaml");
    let mut config = fs::read_to_string(&config_path).expect("bundle config is readable");
    let source_b_start = config.find("  source-b:\n").expect("source-b exists");
    let source_b_end = config[source_b_start..]
        .find("  source-c:\n")
        .map(|offset| source_b_start + offset)
        .expect("source-c follows source-b");
    let mut source_b = config[source_b_start..source_b_end].to_owned();
    replace_exact(
        &mut source_b,
        "  source-b:\n    transport: http-json\n    baseUrl:",
        "  source-b:\n    transport: http-json\n    unresolvedProblem: {status: 404, type: https://id.registrystack.org/problems/registry-relay/consultation/unresolved, code: consultation.unresolved}\n    baseUrl:",
        1,
    );
    replace_exact(
        &mut source_b,
        "      path: /v1/facts\n",
        "      path: /v2/resources/residence-record/lookups/by-record-reference\n",
        1,
    );
    replace_exact(
        &mut source_b,
        "      projection: [/total, /official_residence_code]\n",
        "      projection: [/data/domainData/official_residence_code]\n",
        1,
    );
    config.replace_range(source_b_start..source_b_end, &source_b);
    fs::write(config_path, config).expect("Relay lookup source config is written");
    fs::write(
        bundle_root.join("adapters/residence-region-prepare.rhai"),
        r#"fn prepare(selectors, context) {
    #{query: [], body: #{selectors: #{recordReference: selectors["subject"]["values"]["record_reference"]}}}
}
"#,
    )
    .expect("Relay lookup preparation adapter is written");
    fs::write(
        bundle_root.join("adapters/residence-region-source.rhai"),
        r#"fn extract(source_response, context) {
    #{outcome: "match", facts: #{official_residence_code: required(get_path(source_response, "/data/domainData/official_residence_code"), "required_fact_missing")}}
}
"#,
    )
    .expect("Relay lookup extraction adapter is written");
    fs::write(
        bundle_root.join("schemas/residence-region-response.schema.yaml"),
        r#"type: object
additionalProperties: false
required: [data]
properties:
  data:
    type: object
    additionalProperties: false
    required: [domainData]
    properties:
      domainData:
        type: object
        additionalProperties: false
        required: [official_residence_code]
        properties:
          official_residence_code: {type: string, minLength: 1, maxLength: 32}
"#,
    )
    .expect("Relay lookup response schema is written");
}

/// The same preparation, from a named acceptance bundle rather than the
/// audience-scoped one. The holder-bound twin is prepared through here.
fn prepare_fixture_root_with_mutation(
    fixture_root: &Path,
    binding_secret: &str,
    source_origin: &str,
    ceilings: &FixtureCeilings,
    mutate_bundle: impl FnOnce(&Path),
) -> PreparedFixture {
    let temporary = tempfile::tempdir().expect("temporary acceptance root");
    let bundle_root = temporary.path().join("bundle");
    let runtime_path = temporary.path().join("runtime.yaml");
    let secret_root = temporary.path().join("secrets");
    let audit_path = temporary.path().join("audit.jsonl");
    fs::create_dir(&bundle_root).expect("bundle root is created");
    fs::create_dir(&secret_root).expect("secret root is created");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(&secret_root, fs::Permissions::from_mode(0o700))
            .expect("secret root is owner-only");
    }
    copy_tree(fixture_root, &bundle_root);

    rewrite_deployment_values(&bundle_root, source_origin);
    apply_fixture_ceilings(&bundle_root, ceilings);
    mutate_bundle(&bundle_root);
    write_secret(
        &secret_root,
        "audit-hash-key",
        "audit-hash-secret-canary-32-bytes-minimum",
    );
    write_secret(&secret_root, "subject-binding-key", binding_secret);
    write_secret(&secret_root, "signing-key", EVIDENCE_PRIVATE_JWK);
    write_secret(&secret_root, "source-a-token", BEARER);
    write_secret(&secret_root, "source-b-token", BEARER);
    write_secret(&secret_root, "source-c-username", BASIC_USER);
    write_secret(&secret_root, "source-c-password", BASIC_PASSWORD);
    write_secret(&secret_root, "source-d-token", BEARER);
    write_runtime_config(
        &runtime_path,
        &bundle_root,
        &secret_root,
        &audit_path,
        ceilings,
    );
    make_file_read_only(&runtime_path);
    make_read_only(&bundle_root);

    PreparedFixture {
        temporary,
        bundle_root,
        runtime_path,
        audit_path,
    }
}

fn authenticator() -> Authenticator {
    authenticator_with_optional_actor_claim(None)
}

fn authenticator_with_actor_claim(actor_claim: &str) -> Authenticator {
    authenticator_with_optional_actor_claim(Some(actor_claim))
}

fn authenticator_with_optional_actor_claim(actor_claim: Option<&str>) -> Authenticator {
    let private = PrivateJwk::parse(AUTH_PRIVATE_JWK).expect("auth test key parses");
    let jwks: JwkSet = serde_json::from_value(json!({"keys": [private.public()]}))
        .expect("static auth JWKS parses");
    let fetcher = Arc::new(JwksFetcher::new_static(jwks, JwksFetcherConfig::defaults()));
    let verifier = Arc::new(TokenVerifier::new(
        TokenVerifierConfig::access_token_profile(
            TOKEN_ISSUER,
            vec![TOKEN_AUDIENCE.to_owned()],
            vec![Algorithm::ES256],
            vec!["at+jwt".to_owned()],
        ),
        fetcher,
    ));
    Authenticator::new(
        verifier,
        AuthenticationClaimsConfig {
            principal_claim: "sub".to_owned(),
            requester_tags_claim: "evidence_tags".to_owned(),
            evidence_audience_claim: "evidence_audience".to_owned(),
            grant_id_claim: "evidence_grant_id".to_owned(),
            grant_authority_claim: "evidence_authority".to_owned(),
            actor_claim: actor_claim.map(str::to_owned),
        },
    )
}

/// The same authenticator, but resolving the issuer's keys over HTTP from a
/// given address rather than from a key set held in memory.
///
/// The fetch policy is the permissive one so a loopback test server is a legal
/// address; the deployed policy is built in `Authenticator::from_config` and is
/// not what this exercises.
fn fetching_authenticator(jwks_uri: &str) -> Authenticator {
    let verifier = Arc::new(TokenVerifier::new(
        TokenVerifierConfig::access_token_profile(
            TOKEN_ISSUER,
            vec![TOKEN_AUDIENCE.to_owned()],
            vec![Algorithm::ES256],
            vec!["at+jwt".to_owned()],
        ),
        Arc::new(JwksFetcher::new_with_fetch_url_policy(
            jwks_uri.to_owned(),
            JwksFetcherConfig::defaults(),
            FetchUrlPolicy::dev(),
        )),
    ));
    Authenticator::new(
        verifier,
        AuthenticationClaimsConfig {
            principal_claim: "sub".to_owned(),
            requester_tags_claim: "evidence_tags".to_owned(),
            evidence_audience_claim: "evidence_audience".to_owned(),
            grant_id_claim: "evidence_grant_id".to_owned(),
            grant_authority_claim: "evidence_authority".to_owned(),
            actor_claim: None,
        },
    )
}

fn access_token(extra: Option<Value>) -> String {
    access_token_for("requester-principal-canary", extra)
}

fn access_token_for(principal: &str, extra: Option<Value>) -> String {
    access_token_for_issuer(TOKEN_ISSUER, principal, extra)
}

fn access_token_for_issuer(issuer: &str, principal: &str, extra: Option<Value>) -> String {
    let now = Utc::now().timestamp();
    let mut claims = json!({
        "iss": issuer,
        "aud": TOKEN_AUDIENCE,
        "sub": principal,
        "iat": now - 1,
        "exp": now + 298,
        "evidence_tags": ["fixture-agency"],
        "evidence_audience": EVIDENCE_AUDIENCE
    });
    if let Some(Value::Object(extra)) = extra {
        claims
            .as_object_mut()
            .expect("claims are an object")
            .extend(extra);
    }
    signed_access_token(claims)
}

fn signed_access_token(claims: Value) -> String {
    let header = URL_SAFE_NO_PAD.encode(
        serde_json::to_vec(&json!({
            "alg": "ES256",
            "kid": "acceptance-auth-key",
            "typ": "at+jwt"
        }))
        .expect("JWT header serializes"),
    );
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).expect("claims serialize"));
    let signing_input = format!("{header}.{payload}");
    let key = PrivateJwk::parse(AUTH_PRIVATE_JWK).expect("auth key parses");
    let signature =
        URL_SAFE_NO_PAD.encode(sign(signing_input.as_bytes(), &key).expect("JWT signs"));
    format!("{signing_input}.{signature}")
}

fn parent_grant_claims() -> Value {
    parent_grant_claims_for(parent_candidate())
}

fn parent_grant_claims_for(candidate: Value) -> Value {
    json!({
        "evidence_grant_id": "synthetic-parentage-grant-001",
        "evidence_authority": AUTHORITY,
        "grant": {"candidate_parent": candidate}
    })
}

fn parent_candidate() -> Value {
    json!({"person_reference": PARENT_REFERENCE})
}

fn non_parent_candidate() -> Value {
    json!({"person_reference": NON_PARENT_REFERENCE})
}

async fn mount_success_sources(server: &MockServer, candidate_is_parent: bool) {
    mount_adult_source(server, None).await;
    mount_residence_source(server).await;
    mount_licence_source(server).await;
    let parents = if candidate_is_parent {
        vec![PARENT_REFERENCE]
    } else {
        vec!["synthetic-parent-reference-002"]
    };
    mount_parent_source(server, parent_source_response(parents)).await;
}

async fn mount_residence_source(server: &MockServer) {
    mount_residence_source_expecting(server, 1).await;
}

async fn mount_residence_source_expecting(server: &MockServer, expected: u64) {
    Mock::given(method("POST"))
        .and(path("/v1/facts"))
        .and(header("accept", "application/json"))
        .and(header("authorization", format!("Bearer {BEARER}").as_str()))
        .and(body_json(json!({
            "lookup": {"record_reference": "synthetic-residence-record-001"},
            "fields": ["official_residence_code"],
            "limit": 2
        })))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total": 1,
            "official_residence_code": "R-101"
        })))
        .expect(expected)
        .mount(server)
        .await;
}

async fn mount_licence_source(server: &MockServer) {
    mount_licence_source_expecting(server, 1).await;
}

async fn mount_licence_source_expecting(server: &MockServer, expected: u64) {
    let basic = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{BASIC_USER}:{BASIC_PASSWORD}"))
    );
    Mock::given(method("GET"))
        .and(path("/v1/records"))
        .and(header("accept", "application/json"))
        .and(header("authorization", basic.as_str()))
        .and(query_param("limit", "2"))
        .and(query_param("licence_reference", "synthetic-licence-001"))
        .and(query_param("registry_region", "RR-A"))
        .and(query_param(
            "fields",
            "licence_state,valid_from,valid_until",
        ))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total": 1,
            "records": [{
                "licence_state": "CURRENT",
                "valid_from": "2000-01-01",
                "valid_until": "2099-12-31",
                "historical_states": ["PENDING"]
            }]
        })))
        .expect(expected)
        .mount(server)
        .await;
}

async fn mount_adult_source(server: &MockServer, delay: Option<Duration>) {
    mount_adult_source_expecting(server, delay, 1).await;
}

fn set_batch_adult_given_name(batch: &mut EvidenceRequestBatch, index: usize, given_name: &str) {
    batch.items[index].subjects[0]
        .selector
        .values
        .as_mut()
        .expect("adult selector values exist")
        .insert(
            "given_name".to_owned(),
            SelectorValue::String(given_name.to_owned()),
        );
}

fn adult_source_request_for(given_name: &str) -> Value {
    json!({
        "lookup": {
            "given_name": given_name,
            "family_name": "Diallo",
            "birth_date": "2000-01-01"
        },
        "fields": ["date_of_birth"],
        "limit": 2
    })
}

fn adult_search_request_for(given_name: &str, requested_fields: &[&str]) -> Value {
    json!({
        "lookup": {
            "given_name": given_name,
            "family_name": "Diallo",
            "birth_date": "2000-01-01"
        },
        "fields": requested_fields,
        "limit": 2
    })
}

fn declare_unresolved_problem(bundle_root: &Path, source_id: &str) {
    let path = bundle_root.join("evidence.yaml");
    let mut config = fs::read_to_string(&path).expect("source config is readable");
    let source = format!("  {source_id}:\n    transport: http-json\n");
    let declared = format!(
        "  {source_id}:\n    transport: http-json\n    unresolvedProblem: {{status: 404, type: https://id.example.invalid/problems/unresolved, code: consultation.unresolved}}\n"
    );
    replace_exact(&mut config, &source, &declared, 1);
    fs::write(path, config).expect("declared unresolved source config is written");
}

fn declared_unresolved_response(trace_id: &str) -> ResponseTemplate {
    ResponseTemplate::new(404).set_body_raw(
        format!(
            r#"{{"type":"https://id.example.invalid/problems/unresolved","title":"Unresolved","status":404,"detail":"not resolved","code":"consultation.unresolved","traceId":"{trace_id}"}}"#
        ),
        "application/problem+json",
    )
}

async fn mount_named_adult_source(server: &MockServer, given_name: &str, response: Value) {
    Mock::given(method("POST"))
        .and(path("/v1/facts"))
        .and(header("accept", "application/json"))
        .and(header("authorization", format!("Bearer {BEARER}").as_str()))
        .and(body_json(adult_source_request_for(given_name)))
        .respond_with(ResponseTemplate::new(200).set_body_json(response))
        .expect(1)
        .mount(server)
        .await;
}

fn decode_evidence(jws: &FlattenedJws) -> Evidence {
    let payload = URL_SAFE_NO_PAD
        .decode(&jws.payload)
        .expect("flattened JWS payload decodes");
    serde_json::from_slice(&payload).expect("flattened JWS payload is Evidence")
}

fn request_batch_public_values(
    response: &EvidenceRequestBatchResponse,
) -> Vec<Option<PublicValue>> {
    response
        .items
        .iter()
        .map(|item| match item {
            EvidenceRequestBatchResponseItem::Evidence { evidence } => {
                Some(decode_evidence(evidence).supported_values[0].value.clone())
            }
            EvidenceRequestBatchResponseItem::EvidenceNotAvailable => None,
        })
        .collect()
}

/// The same fixture source mounted for an exact number of evaluations.
async fn mount_adult_source_expecting(server: &MockServer, delay: Option<Duration>, expected: u64) {
    let response = ResponseTemplate::new(200).set_body_json(json!({
        "total": 1,
        "date_of_birth": "2000-01-01"
    }));
    let response = delay.map_or(response.clone(), |delay| response.set_delay(delay));
    Mock::given(method("POST"))
        .and(path("/v1/facts"))
        .and(header("accept", "application/json"))
        .and(header("authorization", format!("Bearer {BEARER}").as_str()))
        .and(body_json(json!({
            "lookup": {
                "given_name": "Amina",
                "family_name": "Diallo",
                "birth_date": "2000-01-01"
            },
            "fields": ["date_of_birth"],
            "limit": 2
        })))
        .respond_with(response)
        .expect(expected)
        .mount(server)
        .await;
}

async fn mount_parent_source(server: &MockServer, response: Value) {
    mount_parent_source_expecting(server, response, 1).await;
}

async fn mount_parent_source_expecting(server: &MockServer, response: Value, expected: u64) {
    Mock::given(method("POST"))
        .and(path("/v1/child-relationships"))
        .and(header("accept", "application/json"))
        .and(header("authorization", format!("Bearer {BEARER}").as_str()))
        .and(body_json(parent_source_request()))
        .respond_with(ResponseTemplate::new(200).set_body_json(response))
        .expect(expected)
        .mount(server)
        .await;
}

fn parent_source_request() -> Value {
    json!({
        "lookup": {"record_reference": "synthetic-child-record-001"},
        "fields": [
            "returned_child_reference",
            "parent_references",
            "reference_namespace",
            "relationship_set_contract",
            "relationship_set_complete"
        ],
        "limit": 2
    })
}

fn parent_source_response(parent_references: Vec<&str>) -> Value {
    json!({
        "total": 1,
        "records": [{
            "returned_child_reference": "synthetic-child-record-001",
            "parent_references": parent_references,
            "reference_namespace": "urn:example:fixture:person-reference",
            "relationship_set_contract": "urn:example:fixture:legal-parent-set:v1",
            "relationship_set_complete": true
        }]
    })
}

async fn wait_for_source_request_count(server: &MockServer, expected: usize) {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            let count = server
                .received_requests()
                .await
                .expect("request journal is available")
                .len();
            if count >= expected {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("source request arrives before the test deadline");
}

fn request_batch_audit_access_indices(path: &Path) -> Vec<Vec<u8>> {
    fs::read_to_string(path)
        .expect("audit is readable")
        .lines()
        .map(|line| serde_json::from_str::<Value>(line).expect("audit envelope parses"))
        .filter(|event| event["record"]["phase"] == "access-attempt")
        .map(|event| {
            serde_json::from_value(event["record"]["itemIndices"].clone())
                .expect("batch access item indices parse")
        })
        .collect()
}

async fn wait_for_audit_counts(path: &Path, access: usize, release: usize) -> String {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let contents = fs::read_to_string(path).expect("audit is readable");
            if contents.matches("\"phase\":\"access-attempt\"").count() >= access
                && contents.matches("\"phase\":\"disclosure-release\"").count() >= release
            {
                return contents;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("terminal audit records arrive before the test deadline")
}

async fn wait_for_runtime_ready(runtime: &EvidenceRuntime) {
    tokio::time::timeout(Duration::from_secs(3), async {
        loop {
            if runtime.ready().await {
                return;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("runtime returns to ready after detached evaluation completes");
}

fn adult_request() -> EvidenceRequest {
    request(
        "urn:example:fixture:requirement:adult-status:v1",
        "fixture-eligibility",
        vec![requested_subject(
            "subject",
            "person-demographics-v1",
            Some([
                ("given_name", "Amina"),
                ("family_name", "Diallo"),
                ("birth_date", "2000-01-01"),
            ]),
        )],
    )
}

fn adult_request_batch(count: usize) -> EvidenceRequestBatch {
    request_batch_from_request(&adult_request(), count)
}

fn request_batch_from_request(template: &EvidenceRequest, count: usize) -> EvidenceRequestBatch {
    EvidenceRequestBatch {
        requirement: template.requirement.clone(),
        purpose: template.purpose.clone(),
        items: (0..count)
            .map(|_| EvidenceRequestBatchItem {
                request_nonce: fresh_request_nonce(),
                subjects: template.subjects.clone(),
            })
            .collect(),
    }
}

fn residence_request() -> EvidenceRequest {
    request(
        "urn:example:fixture:requirement:residence-region:v1",
        "fixture-routing",
        vec![requested_subject(
            "subject",
            "residence-record-v1",
            Some([("record_reference", "synthetic-residence-record-001")]),
        )],
    )
}

fn licence_request() -> EvidenceRequest {
    request(
        "urn:example:fixture:requirement:professional-licence-status:v1",
        "fixture-registration",
        vec![requested_subject(
            "subject",
            "licence-register-v1",
            Some([
                ("licence_reference", "synthetic-licence-001"),
                ("registry_region", "RR-A"),
            ]),
        )],
    )
}

fn parent_request() -> EvidenceRequest {
    request(
        "urn:example:fixture:requirement:legal-parent-relationship:v1",
        "fixture-enrolment",
        vec![
            requested_subject(
                "child",
                "civil-record-reference-v1",
                Some([("record_reference", "synthetic-child-record-001")]),
            ),
            requested_subject::<[(&str, &str); 0]>("candidate-parent", "person-reference-v1", None),
        ],
    )
}

fn parent_request_with_candidate_values() -> EvidenceRequest {
    let mut request = parent_request();
    request.subjects[1].selector.values = Some(BTreeMap::from([(
        "person_reference".to_owned(),
        SelectorValue::String("synthetic-substitute-reference".to_owned()),
    )]));
    request
}

fn request(requirement: &str, purpose: &str, subjects: Vec<RequestedSubject>) -> EvidenceRequest {
    EvidenceRequest {
        request_nonce: fresh_request_nonce(),
        requirement: requirement.to_owned(),
        purpose: purpose.to_owned(),
        subjects,
        holder_keys: Vec::new(),
    }
}

/// A unique canonical nonce per constructed request, so exact-echo and
/// non-propagation assertions cannot pass by collision.
fn fresh_request_nonce() -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    let mut bytes = [0u8; 32];
    let unique = ulid::Ulid::new().to_bytes();
    bytes[..16].copy_from_slice(&unique);
    URL_SAFE_NO_PAD.encode(bytes)
}

fn requested_subject<'a, I>(role: &str, profile: &str, values: Option<I>) -> RequestedSubject
where
    I: IntoIterator<Item = (&'a str, &'a str)>,
{
    RequestedSubject {
        role: role.to_owned(),
        selector: RequestedSelector {
            profile: profile.to_owned(),
            values: values.map(|entries| {
                entries
                    .into_iter()
                    .map(|(name, value)| (name.to_owned(), SelectorValue::String(value.to_owned())))
                    .collect()
            }),
        },
    }
}

/// Independent policy expectations for one live response. The identity,
/// requirement, purpose, audience, revision, and nonce expectations come from
/// the bundle and the retained request; the subject-binding and output-shape
/// expectations are lifted from the response as an accepted first
/// transaction, exactly as a relying party stores them for later checks.
fn verification_policy(
    runtime: &EvidenceRuntime,
    request: &EvidenceRequest,
    serialized_jws: &[u8],
) -> EvidenceVerificationPolicy {
    let requirement = runtime
        .bundle()
        .config
        .requirements
        .iter()
        .find(|candidate| candidate.id == request.requirement)
        .expect("requirement is loaded");
    let jws: FlattenedJws = serde_json::from_slice(serialized_jws).expect("flattened JWS is JSON");
    let payload = URL_SAFE_NO_PAD
        .decode(jws.payload)
        .expect("flattened JWS payload is base64url");
    let evidence: Evidence =
        serde_json::from_slice(&payload).expect("Evidence payload parses for expectations");
    let mut policy = EvidenceVerificationPolicy::from_accepted_transaction(
        &evidence,
        &request.request_nonce,
        48 * 60 * 60,
        Utc::now(),
        30,
    )
    .expect("the transaction states bounds the contract allows");
    policy.issued_by = runtime.bundle().config.issuer.id.clone();
    policy.provided_by = runtime.bundle().config.service.provider_id.clone();
    policy.requirement = request.requirement.clone();
    policy.evidence_type = requirement.evidence_type.clone();
    policy.purpose = request.purpose.clone();
    policy.audience = EVIDENCE_AUDIENCE.to_owned();
    policy.configuration_revision = runtime
        .bundle()
        .configuration_revision(&request.requirement)
        .expect("the loaded requirement has a revision")
        .to_owned();
    policy
}

fn assert_minimized_payload(serialized_jws: &[u8]) {
    let jws: FlattenedJws = serde_json::from_slice(serialized_jws).expect("flattened JWS is JSON");
    let payload = URL_SAFE_NO_PAD
        .decode(jws.payload)
        .expect("flattened JWS payload is base64url");
    let text = String::from_utf8(payload).expect("Evidence payload is UTF-8 JSON");
    for canary in privacy_canaries() {
        assert!(
            !text.contains(canary),
            "signed JWS retained protected material"
        );
    }
    for forbidden_field in [
        "record_reference",
        "given_name",
        "family_name",
        "birth_date",
        "licence_reference",
        "registry_region",
        "role_resolution",
        "relationship_status",
        "date_of_birth",
        "official_residence_code",
        "historical_states",
        "returned_child_reference",
        "parent_references",
        "reference_namespace",
        "relationship_set_contract",
        "relationship_set_complete",
        "person_reference",
    ] {
        assert!(!text.contains(forbidden_field));
    }
}

fn privacy_canaries() -> &'static [&'static str] {
    &[
        "Amina",
        "Binta",
        "Diallo",
        "Other",
        "Subject",
        "Amadou",
        "Keita",
        "2000-01-01",
        "1970-06-15",
        "1971-01-01",
        "1974-02-11",
        "synthetic-child-record-001",
        "synthetic-other-child-record",
        "synthetic-residence-record-001",
        "synthetic-licence-001",
        "synthetic-parentage-grant-001",
        "synthetic-parent-reference-001",
        "synthetic-parent-reference-002",
        "synthetic-non-parent-reference-003",
        "synthetic-substitute-reference",
        "PrivacyCanary",
        "source-bearer-canary",
        "source-user-canary",
        "source-password-canary",
        "audit-hash-secret-canary-32-bytes-minimum",
        "subject-binding-secret-canary-32-bytes-minimum",
    ]
}

fn fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/evidence/fixtures/acceptance/all-definitions")
}

/// The committed holder-bound twin of the bundle above: the same four coequal
/// definitions, declared under the holder-bound mode.
fn holder_bound_fixture_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../products/evidence/fixtures/acceptance/holder-bound")
}

fn rewrite_deployment_values(bundle_root: &Path, source_origin: &str) {
    let path = bundle_root.join("evidence.yaml");
    let mut text = fs::read_to_string(&path).expect("copied configuration is readable");
    replace_exact(&mut text, "https://source.invalid", source_origin, 4);
    replace_exact(
        &mut text,
        "assuranceProfile: evidence-grade",
        "assuranceProfile: local",
        1,
    );
    fs::write(path, text).expect("deployment-only fixture rewrite succeeds");
}

fn configure_sqlite_adult_source(bundle_root: &Path) -> PathBuf {
    let configuration_path = bundle_root.join("evidence.yaml");
    let mut configuration =
        fs::read_to_string(&configuration_path).expect("copied configuration is readable");
    let source_start = configuration
        .find("  source-a:\n")
        .expect("adult source begins");
    let source_end = configuration[source_start..]
        .find("  source-b:\n")
        .map(|offset| source_start + offset)
        .expect("next source begins");
    configuration.replace_range(
        source_start..source_end,
        r#"  source-a:
    transport: sqlite-extract
    posture: field-projected
    extractProfile: adult-register-extract
    maximumExtractAgeSeconds: 86400
    request:
      statement: queries/adult-status.sql
      columns: [{name: date_of_birth, type: string}]
      selectorInputs:
        - role: subject
          alternatives: [{profile: person-demographics-v1, fields: [given_name, family_name, birth_date]}]
      parameterBindings:
        given_name: {kind: selector, role: subject, profile: person-demographics-v1, field: given_name}
        family_name: {kind: selector, role: subject, profile: person-demographics-v1, field: family_name}
        birth_date: {kind: selector, role: subject, profile: person-demographics-v1, field: birth_date}
      projection: [/rows/*/date_of_birth]
      maximumRows: 2
      maximumCellBytes: 256
      maximumStatementSteps: 100000
      timeoutMilliseconds: 3000
      maximumResponseBytes: 65536
      concurrencyLimit: 8
    responseSchema: schemas/adult-status-response.schema.yaml
    extractScript: adapters/adult-status-source.rhai
    factSchema: schemas/adult-status-facts.schema.yaml
"#,
    );
    fs::write(configuration_path, configuration).expect("SQLite source configuration is written");
    for unused in [
        "adapters/adult-status-prepare.rhai",
        "schemas/adult-status-adapter-parameters.schema.yaml",
    ] {
        fs::remove_file(bundle_root.join(unused))
            .unwrap_or_else(|error| panic!("unused SQLite fixture artifact {unused}: {error}"));
    }
    fs::create_dir(bundle_root.join("queries")).expect("SQLite statement directory is created");
    fs::write(
        bundle_root.join("queries/adult-status.sql"),
        r#"SELECT date_of_birth
FROM person
WHERE given_name = :given_name
  AND family_name = :family_name
  AND birth_date = :birth_date
ORDER BY id
LIMIT 2;
"#,
    )
    .expect("reviewed adult SQLite statement is written");
    fs::write(
        bundle_root.join("adapters/adult-status-source.rhai"),
        r#"fn extract(source_response, context) {
    let rows = source_response["rows"];
    if rows.len == 0 { return #{outcome: "no_match"}; }
    if rows.len > 1 { return #{outcome: "ambiguous"}; }
    #{outcome: "match", facts: #{date_of_birth: required(rows[0]["date_of_birth"], "required_fact_missing")}}
}
"#,
    )
    .expect("SQLite extraction adapter is written");
    fs::write(
        bundle_root.join("schemas/adult-status-response.schema.yaml"),
        r#"type: object
additionalProperties: false
required: [rows]
properties:
  rows:
    type: array
    maxItems: 2
    items:
      type: object
      additionalProperties: false
      required: [date_of_birth]
      properties:
        date_of_birth: {type: string, format: date}
"#,
    )
    .expect("SQLite response schema is written");

    let extract_path = bundle_root
        .parent()
        .expect("bundle has a deployment root")
        .join("adult-register.sqlite");
    let published_at = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true);
    let connection = Connection::open(&extract_path).expect("SQLite extract opens");
    connection
        .execute_batch(&format!(
            "CREATE TABLE evidence_extract (published_at TEXT, publisher TEXT, extract_id TEXT);\
             INSERT INTO evidence_extract VALUES ('{published_at}', 'urn:example:fixture:adult-register', 'adult-register-001');\
             CREATE TABLE person (id TEXT PRIMARY KEY, given_name TEXT, family_name TEXT, birth_date TEXT, date_of_birth TEXT);\
             INSERT INTO person VALUES ('person-001', 'Amina', 'Diallo', '2000-01-01', '2000-01-01');"
        ))
        .expect("SQLite extract fixture is created");
    drop(connection);
    make_file_read_only(&extract_path);
    extract_path
}

fn bind_sqlite_extract(runtime_path: &Path, extract_path: &Path) {
    make_file_writable(runtime_path);
    let mut runtime = fs::read_to_string(runtime_path).expect("runtime configuration is readable");
    runtime.push_str(&format!(
        "sourceExtracts:\n  adult-register-extract:\n    path: {}\n",
        extract_path.display()
    ));
    fs::write(runtime_path, runtime).expect("SQLite extract binding is written");
    make_file_read_only(runtime_path);
}

fn configure_search_then_fetch(bundle_root: &Path, source_origin: &str) {
    let configuration_path = bundle_root.join("evidence.yaml");
    let mut configuration =
        fs::read_to_string(&configuration_path).expect("copied configuration is readable");
    replace_exact(
        &mut configuration,
        "    acquisition:\n      kind: single\n      source: source-a",
        "    acquisition:\n      kind: search-then-fetch\n      search: source-a\n      fetch: source-a-fetch",
        1,
    );
    replace_exact(
        &mut configuration,
        &format!(
            "  source-a:\n    transport: http-json\n    baseUrl: {source_origin}\n    posture: field-projected"
        ),
        &format!(
            "  source-a:\n    transport: http-json\n    baseUrl: {source_origin}\n    posture: record-transformed"
        ),
        1,
    );
    replace_exact(
        &mut configuration,
        "    authentication: {kind: static-authorization, tokenRef: secret:file/source-a-token}\n    request:\n      method: POST\n      path: /v1/facts",
        "    authentication: {kind: static-authorization, tokenRef: secret:file/source-a-token}\n    request:\n      method: POST\n      path: /v1/search",
        1,
    );
    replace_exact(
        &mut configuration,
        "      adapterParameters: {requestedFields: [date_of_birth], resultLimit: 2}",
        "      adapterParameters: {requestedFields: [record_id], resultLimit: 2}",
        1,
    );
    replace_exact(
        &mut configuration,
        "      projection: [/total, /date_of_birth]",
        "      projection: [/total, /record_id]",
        1,
    );
    replace_exact(
        &mut configuration,
        "  source-b:\n",
        r#"  source-a-fetch:
    transport: http-json
    baseUrl: https://source.invalid
    posture: field-projected
    authentication: {kind: static-authorization, tokenRef: secret:file/source-a-token}
    request:
      method: GET
      pathTemplate: /v1/records/{record_id}
      pathBindings:
        record_id: {from: prior-fact, field: record_id}
      fixedHeaders: [{name: Accept, value: application/json}]
      selectorInputs: []
      prepareScript: adapters/adult-status-fetch-prepare.rhai
      adapterParameters: {profile: fetch}
      adapterParametersSchema: schemas/adult-status-fetch-adapter-parameters.schema.yaml
      preparationLimits: {query: allowed, jsonBody: forbidden, maximumNormalizedBytes: 4096}
      projection: [/date_of_birth]
      redirects: deny
      timeoutMilliseconds: 3000
      maximumResponseBytes: 65536
      concurrencyLimit: 8
    responseSchema: schemas/adult-status-fetch-response.schema.yaml
    extractScript: adapters/adult-status-fetch-source.rhai
    factSchema: schemas/adult-status-fetch-facts.schema.yaml
  source-b:
"#,
        1,
    );
    replace_exact(
        &mut configuration,
        "    baseUrl: https://source.invalid",
        &format!("    baseUrl: {source_origin}"),
        1,
    );
    fs::write(configuration_path, configuration).expect("chained configuration is written");

    fs::write(
        bundle_root.join("adapters/adult-status-prepare.rhai"),
        r#"fn prepare(selectors, context) {
    let parameters = context["parameters"];
    let subject = selectors["subject"];
    #{query: [], body: #{lookup: #{given_name: subject["values"]["given_name"], family_name: subject["values"]["family_name"], birth_date: subject["values"]["birth_date"]}, fields: parameters["requestedFields"], limit: parameters["resultLimit"]}}
}

"#,
    )
    .expect("search preparation is written");
    fs::write(
        bundle_root.join("adapters/adult-status-source.rhai"),
        r#"fn extract(source_response, context) {
    let total = source_response["total"];
    if total == 0 { return #{outcome: "no_match"}; }
    if total > 1 { return #{outcome: "ambiguous"}; }
    #{outcome: "match", facts: #{record_id: required(get_path(source_response, "/record_id"), "required_fact_missing")}}
}
"#,
    )
    .expect("search extraction is written");
    fs::write(
        bundle_root.join("adapters/adult-status-fetch-prepare.rhai"),
        r#"fn prepare(selectors, context) {
    required(context["prior_facts"]["record_id"], "required_fact_missing");
    #{query: [], body: ()}
}
"#,
    )
    .expect("fetch preparation is written");
    fs::write(
        bundle_root.join("adapters/adult-status-fetch-source.rhai"),
        r#"fn extract(source_response, context) {
    required(context["prior_facts"]["record_id"], "required_fact_missing");
    #{outcome: "match", facts: #{date_of_birth: required(get_path(source_response, "/date_of_birth"), "required_fact_missing")}}
}
"#,
    )
    .expect("fetch extraction is written");
    fs::write(
        bundle_root.join("schemas/adult-status-adapter-parameters.schema.yaml"),
        "type: object\nadditionalProperties: false\nrequired: [requestedFields, resultLimit]\nproperties:\n  requestedFields: {const: [record_id]}\n  resultLimit: {const: 2}\n",
    )
    .expect("search parameter schema is written");
    fs::write(
        bundle_root.join("schemas/adult-status-response.schema.yaml"),
        "type: object\nadditionalProperties: false\nrequired: [total]\nproperties:\n  total: {type: integer, minimum: 0, maximum: 1000000}\n  record_id: {type: string, minLength: 1, maxLength: 128}\n",
    )
    .expect("search response schema is written");
    fs::write(
        bundle_root.join("schemas/adult-status-facts.schema.yaml"),
        "type: object\nadditionalProperties: false\nrequired: [record_id]\nproperties:\n  record_id: {type: string, minLength: 1, maxLength: 128}\n",
    )
    .expect("search fact schema is written");
    fs::write(
        bundle_root.join("schemas/adult-status-fetch-adapter-parameters.schema.yaml"),
        "type: object\nadditionalProperties: false\nrequired: [profile]\nproperties:\n  profile: {const: fetch}\n",
    )
    .expect("fetch parameter schema is written");
    fs::write(
        bundle_root.join("schemas/adult-status-fetch-response.schema.yaml"),
        "type: object\nadditionalProperties: false\nrequired: []\nproperties:\n  date_of_birth: {type: string, format: date}\n",
    )
    .expect("fetch response schema is written");
    fs::write(
        bundle_root.join("schemas/adult-status-fetch-facts.schema.yaml"),
        "type: object\nadditionalProperties: false\nrequired: [date_of_birth]\nproperties:\n  date_of_birth: {type: string, format: date}\n",
    )
    .expect("fetch fact schema is written");
    fs::write(
        bundle_root.join("derivations/adult-status.rhai"),
        r#"fn derive(facts, selectors, evaluation_context) {
    [#{concept_id: "urn:example:fixture:concept:adult-status", value: facts["date_of_birth"] == "2000-01-01"}]
}
"#,
    )
    .expect("chained derivation is written");
}

fn configure_optimized_adult_source_batch(bundle_root: &Path) {
    let configuration_path = bundle_root.join("evidence.yaml");
    let mut configuration =
        fs::read_to_string(&configuration_path).expect("copied configuration is readable");
    replace_exact(
        &mut configuration,
        "\nselectorProfiles:\n",
        "\nacquisitionCapabilities: [source-batch]\n\nselectorProfiles:\n",
        1,
    );
    replace_exact(
        &mut configuration,
        "    factSchema: schemas/adult-status-facts.schema.yaml\n",
        r#"    factSchema: schemas/adult-status-facts.schema.yaml
    batch:
      maximumItems: 16
      prepareScript: adapters/adult-status-prepare-batch.rhai
      extractScript: adapters/adult-status-extract-batch.rhai
      responseSchema: schemas/adult-status-batch-response.schema.yaml
      projection: [/results/*]
"#,
        1,
    );
    fs::write(configuration_path, configuration)
        .expect("optimized source-batch configuration is written");
    fs::write(
        bundle_root.join("adapters/adult-status-prepare-batch.rhai"),
        r#"fn prepare_batch(items, context) {
    let requests = [];
    for item in items {
        let subject = item["selectors"]["subject"];
        requests.push(#{slot: item["slot"], lookup: #{given_name: subject["values"]["given_name"], family_name: subject["values"]["family_name"], birth_date: subject["values"]["birth_date"]}, fields: context["parameters"]["requestedFields"], limit: context["parameters"]["resultLimit"]});
    }
    #{query: [], body: #{requests: requests}}
}
"#,
    )
    .expect("optimized batch preparation is written");
    fs::write(
        bundle_root.join("adapters/adult-status-extract-batch.rhai"),
        r#"fn extract_batch(response, context) {
    let output = [];
    for member in response["results"] {
        if member["total"] == 0 {
            output.push(#{slot: member["slot"], result: #{outcome: "no_match"}});
        } else if member["total"] > 1 {
            output.push(#{slot: member["slot"], result: #{outcome: "ambiguous"}});
        } else {
            output.push(#{slot: member["slot"], result: #{outcome: "match", facts: #{date_of_birth: required(get_path(member, "/date_of_birth"), "required_fact_missing")}}});
        }
    }
    output
}
"#,
    )
    .expect("optimized batch extraction is written");
    fs::write(
        bundle_root.join("schemas/adult-status-batch-response.schema.yaml"),
        r#"type: object
additionalProperties: false
required: [results]
properties:
  results:
    type: array
    minItems: 1
    maxItems: 16
    items:
      type: object
      additionalProperties: false
      required: [slot, total]
      properties:
        slot: {type: integer, minimum: 0, maximum: 15}
        total: {type: integer, minimum: 0, maximum: 1000000}
        date_of_birth: {type: string, format: date}
"#,
    )
    .expect("optimized source-batch response schema is written");
}

/// Rewrite the copied bundle into one search followed by two declared fetch
/// members, each reading a different search fact.
///
/// Both members are POST requests that build their body from the facts they
/// were given, because the JSON body is the channel no startup check can
/// inspect: the declared allowlist is the only thing standing between one
/// member's reference and another member's request.
fn configure_fetch_set(bundle_root: &Path, source_origin: &str) {
    let configuration_path = bundle_root.join("evidence.yaml");
    let mut configuration =
        fs::read_to_string(&configuration_path).expect("copied configuration is readable");
    replace_exact(
        &mut configuration,
        "\nselectorProfiles:\n",
        "\nacquisitionCapabilities: [search-then-fetch-set]\n\nselectorProfiles:\n",
        1,
    );
    replace_exact(
        &mut configuration,
        "    acquisition:\n      kind: single\n      source: source-a",
        r#"    acquisition:
      kind: search-then-fetch-set
      search: source-a
      fetch:
        - {source: source-a-fetch, factInputs: [record_id]}
        - {source: source-a-partner, factInputs: [partner_ref]}
      maximumAcquisitionMilliseconds: 5000"#,
        1,
    );
    replace_exact(
        &mut configuration,
        &format!(
            "  source-a:\n    transport: http-json\n    baseUrl: {source_origin}\n    posture: field-projected"
        ),
        &format!(
            "  source-a:\n    transport: http-json\n    baseUrl: {source_origin}\n    posture: record-transformed"
        ),
        1,
    );
    replace_exact(
        &mut configuration,
        "    authentication: {kind: static-authorization, tokenRef: secret:file/source-a-token}\n    request:\n      method: POST\n      path: /v1/facts",
        "    authentication: {kind: static-authorization, tokenRef: secret:file/source-a-token}\n    request:\n      method: POST\n      path: /v1/search",
        1,
    );
    replace_exact(
        &mut configuration,
        "      adapterParameters: {requestedFields: [date_of_birth], resultLimit: 2}",
        "      adapterParameters: {requestedFields: [record_id, partner_ref], resultLimit: 2}",
        1,
    );
    replace_exact(
        &mut configuration,
        "      projection: [/total, /date_of_birth]",
        "      projection: [/total, /record_id, /partner_ref]",
        1,
    );
    replace_exact(
        &mut configuration,
        "  source-b:\n",
        r#"  source-a-fetch:
    transport: http-json
    baseUrl: https://source.invalid
    posture: field-projected
    authentication: {kind: static-authorization, tokenRef: secret:file/source-a-token}
    request:
      method: POST
      pathTemplate: /v1/records/{record_id}
      pathBindings:
        record_id: {from: prior-fact, field: record_id}
      fixedHeaders: [{name: Accept, value: application/json}]
      selectorInputs: []
      prepareScript: adapters/adult-status-fetch-prepare.rhai
      adapterParameters: {profile: fetch}
      adapterParametersSchema: schemas/adult-status-fetch-adapter-parameters.schema.yaml
      preparationLimits: {query: forbidden, jsonBody: required, maximumJsonDepth: 8, maximumCollectionItems: 16, maximumStringBytes: 256, maximumNormalizedBytes: 4096}
      projection: [/date_of_birth]
      redirects: deny
      timeoutMilliseconds: 3000
      maximumResponseBytes: 65536
      concurrencyLimit: 8
    responseSchema: schemas/adult-status-fetch-response.schema.yaml
    extractScript: adapters/adult-status-fetch-source.rhai
    factSchema: schemas/adult-status-fetch-facts.schema.yaml
  source-a-partner:
    transport: http-json
    baseUrl: https://source.invalid
    posture: field-projected
    authentication: {kind: static-authorization, tokenRef: secret:file/source-a-token}
    request:
      method: POST
      path: /v1/partners
      fixedHeaders: [{name: Accept, value: application/json}]
      selectorInputs: []
      prepareScript: adapters/adult-status-partner-prepare.rhai
      adapterParameters: {profile: partner}
      adapterParametersSchema: schemas/adult-status-partner-adapter-parameters.schema.yaml
      preparationLimits: {query: forbidden, jsonBody: required, maximumJsonDepth: 8, maximumCollectionItems: 16, maximumStringBytes: 256, maximumNormalizedBytes: 4096}
      projection: [/partner_status]
      redirects: deny
      timeoutMilliseconds: 3000
      maximumResponseBytes: 65536
      concurrencyLimit: 8
    responseSchema: schemas/adult-status-partner-response.schema.yaml
    extractScript: adapters/adult-status-partner-source.rhai
    factSchema: schemas/adult-status-partner-facts.schema.yaml
  source-b:
"#,
        1,
    );
    replace_exact(
        &mut configuration,
        "    baseUrl: https://source.invalid",
        &format!("    baseUrl: {source_origin}"),
        2,
    );
    fs::write(configuration_path, configuration).expect("fetch-set configuration is written");

    fs::write(
        bundle_root.join("adapters/adult-status-prepare.rhai"),
        r#"fn prepare(selectors, context) {
    let parameters = context["parameters"];
    let subject = selectors["subject"];
    #{query: [], body: #{lookup: #{given_name: subject["values"]["given_name"], family_name: subject["values"]["family_name"], birth_date: subject["values"]["birth_date"]}, fields: parameters["requestedFields"], limit: parameters["resultLimit"]}}
}
"#,
    )
    .expect("search preparation is written");
    fs::write(
        bundle_root.join("adapters/adult-status-source.rhai"),
        r#"fn extract(source_response, context) {
    let total = source_response["total"];
    if total == 0 { return #{outcome: "no_match"}; }
    if total > 1 { return #{outcome: "ambiguous"}; }
    #{outcome: "match", facts: #{record_id: required(get_path(source_response, "/record_id"), "required_fact_missing"), partner_ref: required(get_path(source_response, "/partner_ref"), "required_fact_missing")}}
}
"#,
    )
    .expect("search extraction is written");
    // Each member's body is exactly the facts it was handed, so the bytes on
    // the wire are the projection and nothing else stands between them.
    fs::write(
        bundle_root.join("adapters/adult-status-fetch-prepare.rhai"),
        r#"fn prepare(selectors, context) {
    #{query: [], body: #{lookup: context["prior_facts"]}}
}
"#,
    )
    .expect("first member preparation is written");
    fs::write(
        bundle_root.join("adapters/adult-status-fetch-source.rhai"),
        r#"fn extract(source_response, context) {
    #{outcome: "match", facts: #{date_of_birth: required(get_path(source_response, "/date_of_birth"), "required_fact_missing")}}
}
"#,
    )
    .expect("first member extraction is written");
    fs::write(
        bundle_root.join("adapters/adult-status-partner-prepare.rhai"),
        r#"fn prepare(selectors, context) {
    #{query: [], body: #{lookup: context["prior_facts"]}}
}
"#,
    )
    .expect("second member preparation is written");
    fs::write(
        bundle_root.join("adapters/adult-status-partner-source.rhai"),
        r#"fn extract(source_response, context) {
    #{outcome: "match", facts: #{partner_status: required(get_path(source_response, "/partner_status"), "required_fact_missing")}}
}
"#,
    )
    .expect("second member extraction is written");
    fs::write(
        bundle_root.join("schemas/adult-status-adapter-parameters.schema.yaml"),
        "type: object\nadditionalProperties: false\nrequired: [requestedFields, resultLimit]\nproperties:\n  requestedFields: {const: [record_id, partner_ref]}\n  resultLimit: {const: 2}\n",
    )
    .expect("search parameter schema is written");
    fs::write(
        bundle_root.join("schemas/adult-status-response.schema.yaml"),
        "type: object\nadditionalProperties: false\nrequired: [total]\nproperties:\n  total: {type: integer, minimum: 0, maximum: 1000000}\n  record_id: {type: string, minLength: 1, maxLength: 128}\n  partner_ref: {type: string, minLength: 1, maxLength: 128}\n",
    )
    .expect("search response schema is written");
    fs::write(
        bundle_root.join("schemas/adult-status-facts.schema.yaml"),
        "type: object\nadditionalProperties: false\nrequired: [record_id, partner_ref]\nproperties:\n  record_id: {type: string, minLength: 1, maxLength: 128}\n  partner_ref: {type: string, minLength: 1, maxLength: 128}\n",
    )
    .expect("search fact schema is written");
    fs::write(
        bundle_root.join("schemas/adult-status-fetch-adapter-parameters.schema.yaml"),
        "type: object\nadditionalProperties: false\nrequired: [profile]\nproperties:\n  profile: {const: fetch}\n",
    )
    .expect("first member parameter schema is written");
    fs::write(
        bundle_root.join("schemas/adult-status-fetch-response.schema.yaml"),
        "type: object\nadditionalProperties: false\nrequired: []\nproperties:\n  date_of_birth: {type: string, format: date}\n",
    )
    .expect("first member response schema is written");
    fs::write(
        bundle_root.join("schemas/adult-status-fetch-facts.schema.yaml"),
        "type: object\nadditionalProperties: false\nrequired: [date_of_birth]\nproperties:\n  date_of_birth: {type: string, format: date}\n",
    )
    .expect("first member fact schema is written");
    fs::write(
        bundle_root.join("schemas/adult-status-partner-adapter-parameters.schema.yaml"),
        "type: object\nadditionalProperties: false\nrequired: [profile]\nproperties:\n  profile: {const: partner}\n",
    )
    .expect("second member parameter schema is written");
    fs::write(
        bundle_root.join("schemas/adult-status-partner-response.schema.yaml"),
        "type: object\nadditionalProperties: false\nrequired: []\nproperties:\n  partner_status: {type: string, minLength: 1, maxLength: 64}\n",
    )
    .expect("second member response schema is written");
    fs::write(
        bundle_root.join("schemas/adult-status-partner-facts.schema.yaml"),
        "type: object\nadditionalProperties: false\nrequired: [partner_status]\nproperties:\n  partner_status: {type: string, minLength: 1, maxLength: 64}\n",
    )
    .expect("second member fact schema is written");
    fs::write(
        bundle_root.join("derivations/adult-status.rhai"),
        r#"fn derive(facts, selectors, evaluation_context) {
    [#{concept_id: "urn:example:fixture:concept:adult-status", value: facts["date_of_birth"] == "2000-01-01"}]
}
"#,
    )
    .expect("fetch-set derivation is written");
}

/// Widen the fetch set to the widest form Version 1 declares: one search and
/// four members, every stage carrying a bulk array fact beside its scalar one.
///
/// Every stage stays inside the total string size one script may return, and
/// inside the serialized bound one extraction accepts. Their union is bounded
/// by neither, which is exactly the gap the acquisition closes before it
/// derives. Three stages cannot reach that gap at all, so the widest set is
/// what the case needs.
fn widen_fetch_set_to_four_bulk_members(bundle_root: &Path, source_origin: &str) {
    let bulk = "{type: array, maxItems: 250, items: {type: string, maxLength: 64}}";
    let configuration_path = bundle_root.join("evidence.yaml");
    let mut configuration =
        fs::read_to_string(&configuration_path).expect("fetch-set configuration is readable");
    replace_exact(
        &mut configuration,
        "        - {source: source-a-partner, factInputs: [partner_ref]}\n",
        "        - {source: source-a-partner, factInputs: [partner_ref]}\n        - {source: source-a-third, factInputs: [record_id]}\n        - {source: source-a-fourth, factInputs: [partner_ref]}\n",
        1,
    );
    replace_exact(
        &mut configuration,
        "      projection: [/total, /record_id, /partner_ref]",
        "      projection: [/total, /record_id, /partner_ref, /search_detail]",
        1,
    );
    replace_exact(
        &mut configuration,
        "      projection: [/date_of_birth]",
        "      projection: [/date_of_birth, /record_detail]",
        1,
    );
    replace_exact(
        &mut configuration,
        "      projection: [/partner_status]",
        "      projection: [/partner_status, /partner_detail]",
        1,
    );
    replace_exact(
        &mut configuration,
        "  source-b:\n",
        r#"  source-a-third:
    transport: http-json
    baseUrl: https://source.invalid
    posture: field-projected
    authentication: {kind: static-authorization, tokenRef: secret:file/source-a-token}
    request:
      method: POST
      path: /v1/third
      fixedHeaders: [{name: Accept, value: application/json}]
      selectorInputs: []
      prepareScript: adapters/adult-status-third-prepare.rhai
      adapterParameters: {profile: third}
      adapterParametersSchema: schemas/adult-status-third-adapter-parameters.schema.yaml
      preparationLimits: {query: forbidden, jsonBody: required, maximumJsonDepth: 8, maximumCollectionItems: 16, maximumStringBytes: 256, maximumNormalizedBytes: 4096}
      projection: [/third_status, /third_detail]
      redirects: deny
      timeoutMilliseconds: 3000
      maximumResponseBytes: 65536
      concurrencyLimit: 8
    responseSchema: schemas/adult-status-third-response.schema.yaml
    extractScript: adapters/adult-status-third-source.rhai
    factSchema: schemas/adult-status-third-facts.schema.yaml
  source-a-fourth:
    transport: http-json
    baseUrl: https://source.invalid
    posture: field-projected
    authentication: {kind: static-authorization, tokenRef: secret:file/source-a-token}
    request:
      method: POST
      path: /v1/fourth
      fixedHeaders: [{name: Accept, value: application/json}]
      selectorInputs: []
      prepareScript: adapters/adult-status-fourth-prepare.rhai
      adapterParameters: {profile: fourth}
      adapterParametersSchema: schemas/adult-status-fourth-adapter-parameters.schema.yaml
      preparationLimits: {query: forbidden, jsonBody: required, maximumJsonDepth: 8, maximumCollectionItems: 16, maximumStringBytes: 256, maximumNormalizedBytes: 4096}
      projection: [/fourth_status, /fourth_detail]
      redirects: deny
      timeoutMilliseconds: 3000
      maximumResponseBytes: 65536
      concurrencyLimit: 8
    responseSchema: schemas/adult-status-fourth-response.schema.yaml
    extractScript: adapters/adult-status-fourth-source.rhai
    factSchema: schemas/adult-status-fourth-facts.schema.yaml
  source-b:
"#,
        1,
    );
    replace_exact(
        &mut configuration,
        "    baseUrl: https://source.invalid",
        &format!("    baseUrl: {source_origin}"),
        2,
    );
    fs::write(configuration_path, configuration).expect("widened fetch set is written");

    fs::write(
        bundle_root.join("adapters/adult-status-source.rhai"),
        r#"fn extract(source_response, context) {
    let total = source_response["total"];
    if total == 0 { return #{outcome: "no_match"}; }
    if total > 1 { return #{outcome: "ambiguous"}; }
    #{outcome: "match", facts: #{record_id: required(get_path(source_response, "/record_id"), "required_fact_missing"), partner_ref: required(get_path(source_response, "/partner_ref"), "required_fact_missing"), search_detail: required(get_path(source_response, "/search_detail"), "required_fact_missing")}}
}
"#,
    )
    .expect("widened search extraction is written");
    for (adapter, status, detail) in [
        ("adult-status-fetch", "date_of_birth", "record_detail"),
        ("adult-status-partner", "partner_status", "partner_detail"),
        ("adult-status-third", "third_status", "third_detail"),
        ("adult-status-fourth", "fourth_status", "fourth_detail"),
    ] {
        fs::write(
            bundle_root.join(format!("adapters/{adapter}-prepare.rhai")),
            r#"fn prepare(selectors, context) {
    #{query: [], body: #{lookup: context["prior_facts"]}}
}
"#,
        )
        .expect("widened member preparation is written");
        fs::write(
            bundle_root.join(format!("adapters/{adapter}-source.rhai")),
            format!(
                r#"fn extract(source_response, context) {{
    #{{outcome: "match", facts: #{{{status}: required(get_path(source_response, "/{status}"), "required_fact_missing"), {detail}: required(get_path(source_response, "/{detail}"), "required_fact_missing")}}}}
}}
"#
            ),
        )
        .expect("widened member extraction is written");
    }
    fs::write(
        bundle_root.join("schemas/adult-status-response.schema.yaml"),
        format!(
            "type: object\nadditionalProperties: false\nrequired: [total]\nproperties:\n  total: {{type: integer, minimum: 0, maximum: 1000000}}\n  record_id: {{type: string, minLength: 1, maxLength: 128}}\n  partner_ref: {{type: string, minLength: 1, maxLength: 128}}\n  search_detail: {bulk}\n"
        ),
    )
    .expect("widened search response schema is written");
    fs::write(
        bundle_root.join("schemas/adult-status-facts.schema.yaml"),
        format!(
            "type: object\nadditionalProperties: false\nrequired: [record_id, partner_ref, search_detail]\nproperties:\n  record_id: {{type: string, minLength: 1, maxLength: 128}}\n  partner_ref: {{type: string, minLength: 1, maxLength: 128}}\n  search_detail: {bulk}\n"
        ),
    )
    .expect("widened search fact schema is written");
    fs::write(
        bundle_root.join("schemas/adult-status-fetch-response.schema.yaml"),
        format!(
            "type: object\nadditionalProperties: false\nrequired: []\nproperties:\n  date_of_birth: {{type: string, format: date}}\n  record_detail: {bulk}\n"
        ),
    )
    .expect("widened first member response schema is written");
    fs::write(
        bundle_root.join("schemas/adult-status-fetch-facts.schema.yaml"),
        format!(
            "type: object\nadditionalProperties: false\nrequired: [date_of_birth, record_detail]\nproperties:\n  date_of_birth: {{type: string, format: date}}\n  record_detail: {bulk}\n"
        ),
    )
    .expect("widened first member fact schema is written");
    for (schema, status, detail) in [
        ("adult-status-partner", "partner_status", "partner_detail"),
        ("adult-status-third", "third_status", "third_detail"),
        ("adult-status-fourth", "fourth_status", "fourth_detail"),
    ] {
        fs::write(
            bundle_root.join(format!("schemas/{schema}-response.schema.yaml")),
            format!(
                "type: object\nadditionalProperties: false\nrequired: []\nproperties:\n  {status}: {{type: string, minLength: 1, maxLength: 64}}\n  {detail}: {bulk}\n"
            ),
        )
        .expect("widened member response schema is written");
        fs::write(
            bundle_root.join(format!("schemas/{schema}-facts.schema.yaml")),
            format!(
                "type: object\nadditionalProperties: false\nrequired: [{status}, {detail}]\nproperties:\n  {status}: {{type: string, minLength: 1, maxLength: 64}}\n  {detail}: {bulk}\n"
            ),
        )
        .expect("widened member fact schema is written");
    }
    for (schema, profile) in [
        ("adult-status-third", "third"),
        ("adult-status-fourth", "fourth"),
    ] {
        fs::write(
            bundle_root.join(format!("schemas/{schema}-adapter-parameters.schema.yaml")),
            format!(
                "type: object\nadditionalProperties: false\nrequired: [profile]\nproperties:\n  profile: {{const: {profile}}}\n"
            ),
        )
        .expect("widened member parameter schema is written");
    }
}

/// Enable the gated acquisition kind on the operator half of the gate.
///
/// The runtime file is sealed read-only the moment it is written, which is the
/// posture every fixture starts from, so enabling a capability reopens it,
/// appends the operator declaration, and seals it again before startup reads
/// it.
fn enable_fetch_set_acquisition(runtime_path: &Path) {
    make_file_writable(runtime_path);
    let mut document =
        fs::read_to_string(runtime_path).expect("immutable runtime configuration is readable");
    document.push_str("acquisitionCapabilities: [search-then-fetch-set]\n");
    fs::write(runtime_path, document).expect("operator capability declaration is written");
    make_file_read_only(runtime_path);
}

fn enable_source_batch_acquisition(runtime_path: &Path) {
    make_file_writable(runtime_path);
    let mut document =
        fs::read_to_string(runtime_path).expect("immutable runtime configuration is readable");
    document.push_str("acquisitionCapabilities: [source-batch]\n");
    fs::write(runtime_path, document).expect("operator batch capability is written");
    make_file_read_only(runtime_path);
}

/// The deployment ceilings a prepared fixture runs under.
///
/// Every field here is a production-meaningful default in the acceptance
/// bundle or runtime file. They exist as a struct only so a throughput
/// measurement can lift the ones that would otherwise be the thing measured;
/// the lifted values are measurement scaffolding and are not a recommended
/// deployment posture.
struct FixtureCeilings {
    maximum_concurrent_requests: u32,
    audit_maximum_file_bytes: u64,
    requests_per_principal_per_minute: u64,
    burst_per_principal: u64,
    source_concurrency_limit: u16,
}

impl FixtureCeilings {
    /// The values the tracked acceptance bundle and the acceptance runtime
    /// file carry. Every existing fixture runs under exactly these.
    fn deployment_defaults() -> Self {
        Self {
            maximum_concurrent_requests: 64,
            audit_maximum_file_bytes: 10_485_760,
            requests_per_principal_per_minute: 60,
            burst_per_principal: 10,
            source_concurrency_limit: 8,
        }
    }
}

/// Rewrite the copied bundle's rate limits and per-source outbound concurrency
/// to `ceilings`. The tracked fixture under `products/evidence/fixtures` is
/// never touched: only the temporary copy is, and only before it is sealed
/// read-only.
fn apply_fixture_ceilings(bundle_root: &Path, ceilings: &FixtureCeilings) {
    let path = bundle_root.join("evidence.yaml");
    let mut text = fs::read_to_string(&path).expect("copied configuration is readable");
    replace_exact(
        &mut text,
        "requestsPerPrincipalPerMinute: 60",
        &format!(
            "requestsPerPrincipalPerMinute: {}",
            ceilings.requests_per_principal_per_minute
        ),
        1,
    );
    replace_exact(
        &mut text,
        "burstPerPrincipal: 10",
        &format!("burstPerPrincipal: {}", ceilings.burst_per_principal),
        1,
    );
    replace_exact(
        &mut text,
        "concurrencyLimit: 8",
        &format!("concurrencyLimit: {}", ceilings.source_concurrency_limit),
        4,
    );
    fs::write(path, text).expect("deployment-only ceiling rewrite succeeds");
}

fn write_runtime_config(
    runtime_path: &Path,
    bundle_root: &Path,
    secret_root: &Path,
    audit_path: &Path,
    ceilings: &FixtureCeilings,
) {
    let document = format!(
        r#"version: 1
bundleDirectory: {}
listener:
  bindHost: 127.0.0.1
  port: 8080
  tlsTermination: operator-controlled-upstream
  trustProxyIdentityHeaders: false
  maximumRequestBytes: 65536
  maximumConcurrentRequests: {}
  requestTimeoutMilliseconds: 10000
  shutdownGraceMilliseconds: 30000
secretProviders:
  file:
    root: {}
signer:
  kind: local-jwk
  privateKeyRef: secret:file/signing-key
auditStorage:
  path: {}
  maximumFileBytes: {}
outboundTls:
  systemRoots: true
  trustProfiles: {{}}
"#,
        bundle_root.display(),
        ceilings.maximum_concurrent_requests,
        secret_root.display(),
        audit_path.display(),
        ceilings.audit_maximum_file_bytes,
    );
    fs::write(runtime_path, document).expect("immutable runtime configuration is written");
}

fn replace_exact(text: &mut String, from: &str, to: &str, expected: usize) {
    assert_eq!(
        text.matches(from).count(),
        expected,
        "fixture drift for {from}"
    );
    *text = text.replace(from, to);
}

fn regenerate_discovery_description(bundle_root: &Path) {
    let config = crate::config::EvidenceConfig::parse_yaml(
        &fs::read(bundle_root.join("evidence.yaml")).expect("rewritten configuration is readable"),
    )
    .expect("rewritten configuration validates");
    let description = crate::discovery::render(&config)
        .expect("provider description renders")
        .expect("acceptance publication remains configured");
    fs::write(bundle_root.join("catalog.jsonld"), description)
        .expect("provider description is regenerated");
}

fn write_secret(root: &Path, name: &str, value: &str) {
    let path = root.join(name);
    fs::write(&path, value.as_bytes()).expect("synthetic secret is written");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
            .expect("synthetic secret is owner-only");
    }
}

fn copy_tree(source: &Path, target: &Path) {
    for entry in fs::read_dir(source).expect("acceptance fixture is readable") {
        let entry = entry.expect("fixture directory entry is readable");
        let destination = target.join(entry.file_name());
        if entry
            .file_type()
            .expect("fixture file type is readable")
            .is_dir()
        {
            fs::create_dir(&destination).expect("fixture directory is copied");
            copy_tree(&entry.path(), &destination);
        } else {
            fs::copy(entry.path(), destination).expect("fixture file is copied");
        }
    }
}

#[cfg(unix)]
fn make_file_read_only(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(path, fs::Permissions::from_mode(0o444))
        .expect("runtime configuration is immutable");
}

#[cfg(unix)]
fn make_file_writable(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(path, fs::Permissions::from_mode(0o644))
        .expect("runtime configuration becomes writable for mutation test");
}

#[cfg(not(unix))]
fn make_file_read_only(path: &Path) {
    let mut permissions = fs::metadata(path).expect("runtime metadata").permissions();
    permissions.set_readonly(true);
    fs::set_permissions(path, permissions).expect("runtime configuration is immutable");
}

#[cfg(not(unix))]
fn make_file_writable(path: &Path) {
    let mut permissions = fs::metadata(path).expect("runtime metadata").permissions();
    permissions.set_readonly(false);
    fs::set_permissions(path, permissions)
        .expect("runtime configuration becomes writable for mutation test");
}

#[cfg(unix)]
fn make_read_only(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;

    for entry in fs::read_dir(path).expect("copied bundle is readable") {
        let entry = entry.expect("bundle directory entry is readable");
        let child = entry.path();
        if entry
            .file_type()
            .expect("bundle file type is readable")
            .is_dir()
        {
            make_read_only(&child);
            fs::set_permissions(&child, fs::Permissions::from_mode(0o555))
                .expect("bundle directory is immutable");
        } else {
            fs::set_permissions(&child, fs::Permissions::from_mode(0o444))
                .expect("bundle file is immutable");
        }
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o555)).expect("bundle root is immutable");
}

#[cfg(unix)]
fn make_writable(path: &Path) {
    use std::os::unix::fs::PermissionsExt as _;

    fs::set_permissions(path, fs::Permissions::from_mode(0o755))
        .expect("bundle directory becomes writable for mutation test");
    for entry in fs::read_dir(path).expect("captured bundle remains readable") {
        let entry = entry.expect("captured bundle entry remains readable");
        let child = entry.path();
        if entry
            .file_type()
            .expect("captured bundle file type remains readable")
            .is_dir()
        {
            make_writable(&child);
        } else {
            fs::set_permissions(child, fs::Permissions::from_mode(0o644))
                .expect("bundle file becomes writable for mutation test");
        }
    }
}

#[cfg(not(unix))]
fn make_read_only(path: &Path) {
    for entry in fs::read_dir(path).expect("copied bundle is readable") {
        let entry = entry.expect("bundle directory entry is readable");
        let child = entry.path();
        if entry
            .file_type()
            .expect("bundle file type is readable")
            .is_dir()
        {
            make_read_only(&child);
        } else {
            let mut permissions = fs::metadata(&child).expect("bundle metadata").permissions();
            permissions.set_readonly(true);
            fs::set_permissions(child, permissions).expect("bundle file is immutable");
        }
    }
}

#[cfg(not(unix))]
fn make_writable(path: &Path) {
    for entry in fs::read_dir(path).expect("captured bundle remains readable") {
        let entry = entry.expect("captured bundle entry remains readable");
        let child = entry.path();
        if entry
            .file_type()
            .expect("captured bundle file type remains readable")
            .is_dir()
        {
            make_writable(&child);
        } else {
            let mut permissions = fs::metadata(&child)
                .expect("captured bundle metadata remains readable")
                .permissions();
            permissions.set_readonly(false);
            fs::set_permissions(child, permissions)
                .expect("bundle file becomes writable for mutation test");
        }
    }
}

// Concurrency and throughput harness.

/// Simultaneous virtual clients. Held below the fixture listener's 64 admitted
/// request slots so admission queueing never reads as a throughput limit.
const LOAD_CONCURRENCY: usize = 32;

/// Requests issued by one measured soak window.
const SOAK_REQUESTS: usize = 512;

/// Direct source calls used to establish the mock-source floor.
const SOURCE_PROBE_REQUESTS: usize = 256;

/// Appends used to measure the audit sink ceiling on the same filesystem.
const AUDIT_PROBE_APPENDS: usize = 200;

/// Probe ceiling. The probe writes a small fraction of this.
const AUDIT_PROBE_MAXIMUM_BYTES: u64 = 64 * 1024 * 1024;

/// The acceptance runtime behind a real TCP listener, driven by real HTTP
/// clients. Load is applied over sockets rather than through an in-process
/// router so admission, the detached evaluation task, and connection handling
/// are all measured.
struct LoadFixture {
    _temporary: TempDir,
    _source: MockServer,
    source_origin: String,
    audit_path: PathBuf,
    probe_directory: PathBuf,
    address: std::net::SocketAddr,
    client: reqwest::Client,
    shutdown: tokio::sync::oneshot::Sender<()>,
    serving: tokio::task::JoinHandle<std::io::Result<()>>,
    runtime: Arc<EvidenceRuntime>,
}

/// One measured load window.
struct LoadOutcomes {
    statuses: Vec<u16>,
    latencies: Vec<Duration>,
    elapsed: Duration,
}

impl LoadOutcomes {
    fn released(&self) -> usize {
        self.statuses
            .iter()
            .filter(|status| **status == 200)
            .count()
    }

    fn status_counts(&self) -> BTreeMap<u16, usize> {
        let mut counts = BTreeMap::new();
        for status in &self.statuses {
            *counts.entry(*status).or_insert(0_usize) += 1;
        }
        counts
    }

    /// Nearest-rank p50, p95, and p99 over the whole window.
    fn latency_percentiles(&self) -> (Duration, Duration, Duration) {
        if self.latencies.is_empty() {
            return (Duration::ZERO, Duration::ZERO, Duration::ZERO);
        }
        let mut sorted = self.latencies.clone();
        sorted.sort_unstable();
        let at = |fraction: f64| {
            let rank = (fraction * sorted.len() as f64).ceil() as usize;
            sorted[rank.clamp(1, sorted.len()) - 1]
        };
        (at(0.50), at(0.95), at(0.99))
    }
}

impl LoadFixture {
    async fn start() -> Self {
        let prepared = prepare_acceptance("subject-binding-secret-canary-32-bytes-minimum").await;
        mount_unmetered_adult_source(&prepared.server).await;
        let runtime = Arc::new(
            EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
                .await
                .expect("the load fixture runtime initializes"),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("the load listener binds");
        let address = listener
            .local_addr()
            .expect("the load listener has an address");
        let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel();
        let serving = tokio::spawn({
            let runtime = Arc::clone(&runtime);
            async move {
                serve_listener_for_test(runtime, listener, async move {
                    let _ = shutdown_rx.await;
                })
                .await
            }
        });

        let client = reqwest::Client::builder()
            .pool_max_idle_per_host(LOAD_CONCURRENCY)
            .timeout(Duration::from_secs(30))
            .build()
            .expect("the load client builds");

        Self {
            source_origin: prepared.server.uri(),
            probe_directory: prepared
                .audit_path
                .parent()
                .expect("the audit path has a parent")
                .to_path_buf(),
            audit_path: prepared.audit_path,
            _temporary: prepared.temporary,
            _source: prepared.server,
            address,
            client,
            shutdown,
            serving,
            runtime,
        }
    }

    /// Issue `total` adult-status requests across `concurrency` clients.
    ///
    /// Each request carries its own principal so the per-principal token bucket
    /// never becomes the thing under measurement. Tokens are signed up front,
    /// outside the timed window.
    async fn run(&self, total: usize, concurrency: usize) -> LoadOutcomes {
        let tokens: Arc<Vec<String>> = Arc::new(
            (0..total)
                .map(|index| access_token_for(&format!("load-principal-{index:06}"), None))
                .collect(),
        );
        let body =
            Arc::new(serde_json::to_vec(&adult_request()).expect("the load request serializes"));
        let endpoint = Arc::new(format!("http://{}/v1/evidence", self.address));

        let started = Instant::now();
        let mut workers = Vec::with_capacity(concurrency);
        for worker in 0..concurrency {
            let client = self.client.clone();
            let tokens = Arc::clone(&tokens);
            let body = Arc::clone(&body);
            let endpoint = Arc::clone(&endpoint);
            workers.push(tokio::spawn(async move {
                let mut results = Vec::new();
                let mut index = worker;
                while index < tokens.len() {
                    let attempt = Instant::now();
                    let response = client
                        .post(endpoint.as_str())
                        .header("authorization", format!("Bearer {}", tokens[index]))
                        .header("content-type", "application/json")
                        .body(body.as_ref().clone())
                        .send()
                        .await
                        .expect("the load request completes");
                    let status = response.status().as_u16();
                    // Drain the body so the connection returns to the pool.
                    let _ = response
                        .bytes()
                        .await
                        .expect("the load response body reads");
                    results.push((status, attempt.elapsed()));
                    index += concurrency;
                }
                results
            }));
        }

        let mut statuses = Vec::with_capacity(total);
        let mut latencies = Vec::with_capacity(total);
        for worker in workers {
            for (status, latency) in worker.await.expect("a load worker completes") {
                statuses.push(status);
                latencies.push(latency);
            }
        }
        LoadOutcomes {
            statuses,
            latencies,
            elapsed: started.elapsed(),
        }
    }

    /// Call the mock source directly to establish the harness floor: no result
    /// above this rate is attributable to Evidence.
    async fn measure_source_rate(&self, requests: usize) -> f64 {
        let endpoint = Arc::new(format!("{}/v1/facts", self.source_origin));
        let started = Instant::now();
        let mut workers = Vec::with_capacity(LOAD_CONCURRENCY);
        for worker in 0..LOAD_CONCURRENCY {
            let client = self.client.clone();
            let endpoint = Arc::clone(&endpoint);
            workers.push(tokio::spawn(async move {
                let mut index = worker;
                while index < requests {
                    let response = client
                        .post(endpoint.as_str())
                        .header("accept", "application/json")
                        .header("authorization", format!("Bearer {BEARER}"))
                        .json(&adult_source_request())
                        .send()
                        .await
                        .expect("the source probe request completes");
                    let _ = response.bytes().await.expect("the source probe body reads");
                    index += LOAD_CONCURRENCY;
                }
            }));
        }
        for worker in workers {
            worker.await.expect("a source probe worker completes");
        }
        requests as f64 / started.elapsed().as_secs_f64()
    }

    /// Append through a real keyed sink on the same filesystem as the runtime's
    /// own audit file. Appends are serialized by the chain, so this is a
    /// sequential measurement by construction, not by choice of harness.
    async fn measure_audit_append_rate(&self, appends: usize) -> f64 {
        let path = self.probe_directory.join("audit-throughput-probe.jsonl");
        let log = EvidenceAuditLog::initialize(
            &path,
            AUDIT_PROBE_MAXIMUM_BYTES,
            b"audit-hash-secret-canary-32-bytes-minimum".to_vec(),
            1,
        )
        .await
        .expect("the audit throughput probe initializes");

        let started = Instant::now();
        for index in 0..appends {
            log.append(audit_probe_event(index))
                .await
                .expect("the audit throughput probe appends");
        }
        appends as f64 / started.elapsed().as_secs_f64()
    }

    /// Stop the listener, drain detached evaluations, and return the audit file.
    async fn shutdown(self) -> String {
        let _ = self.shutdown.send(());
        self.serving
            .await
            .expect("the load listener task completes")
            .expect("the load listener shuts down cleanly");
        drop(self.runtime);
        fs::read_to_string(&self.audit_path).expect("the load audit file is readable")
    }
}

/// The adult source mock without a call-count expectation, so one mount serves
/// a whole load window.
async fn mount_unmetered_adult_source(server: &MockServer) {
    Mock::given(method("POST"))
        .and(path("/v1/facts"))
        .and(header("accept", "application/json"))
        .and(header("authorization", format!("Bearer {BEARER}").as_str()))
        .and(body_json(adult_source_request()))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "total": 1,
            "date_of_birth": "2000-01-01"
        })))
        .mount(server)
        .await;
}

fn adult_source_request() -> Value {
    json!({
        "lookup": {
            "given_name": "Amina",
            "family_name": "Diallo",
            "birth_date": "2000-01-01"
        },
        "fields": ["date_of_birth"],
        "limit": 2
    })
}

/// A valid access-attempt event shaped like the ones the runtime writes, so the
/// probe measures the real serialization, hashing, and fsync path.
fn audit_probe_event(index: usize) -> EvidenceAuditEvent {
    EvidenceAuditEvent::new(
        AssuranceProfile::EvidenceGrade,
        format!("audit-throughput-probe-{index:012}"),
        AuditPhase::AccessAttempt,
        "urn:example:fixture:requirement:adult-status:v1".to_owned(),
        "audit-throughput-probe".to_owned(),
        "fixture-eligibility".to_owned(),
        "hmac-sha256:v1:audit-throughput-probe-requester".to_owned(),
        AuditAuthority {
            kind: AuditAuthorityKind::Statutory,
            grant_pseudonym: None,
        },
        vec![AuditSubject {
            role: "subject".to_owned(),
            selector_profile: "person-demographics-v1".to_owned(),
            selector_bundle_pseudonym: None,
        }],
        ResponseProtection::Signed,
        AuditDecision::Authorized,
        0,
    )
}

fn acceptance_audit_hasher() -> AuditChainHasher {
    AuditChainProfile::production_from_secret_bytes(zeroize::Zeroizing::new(
        b"audit-hash-secret-canary-32-bytes-minimum".to_vec(),
    ))
    .expect("the acceptance audit chain key derives")
    .hasher()
}

/// Distinct evidence identities across every disclosure-release record.
fn released_evidence_ids(audit: &str) -> BTreeSet<String> {
    audit
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str::<Value>(line).expect("an audit line is JSON"))
        .filter_map(|envelope| {
            envelope
                .get("record")?
                .get("evidenceId")?
                .as_str()
                .map(str::to_owned)
        })
        .collect()
}

// Sustained end-to-end throughput measurement.

/// Requests offered simultaneously by the sustained driver.
///
/// Two durable audit appends sit on every request's critical path, and the
/// audit sink commits in groups: appends that arrive while a durable write is
/// in flight join the next batch instead of each paying an `fsync`. Its rate
/// therefore rises with the number of concurrent appenders and collapses
/// toward one `fsync` per append when only a few are in flight, so the offered
/// concurrency has to keep batches full. 128 also leaves Little's law room:
/// sustaining 1000 requests per second needs roughly `1000 * latency_seconds`
/// requests in flight, so 128 covers per-request latencies up to about 128 ms.
const SUSTAINED_CONCURRENCY: usize = 128;

/// The measured window. Ten seconds is long enough for group-commit batching,
/// connection reuse, and the verifier and source caches to reach steady state,
/// and short enough that the check stays runnable on demand rather than
/// becoming a nightly job.
const SUSTAINED_WINDOW: Duration = Duration::from_secs(10);

/// An unmeasured window that absorbs first-request script compilation, lazy
/// initialization, connection establishment, and audit file growth.
const SUSTAINED_WARMUP: Duration = Duration::from_secs(3);

/// The end-to-end rate this check exists to prove, in requests per second.
const SUSTAINED_TARGET_RPS: f64 = 1000.0;

/// How far the constant source's own ceiling must sit above the Evidence
/// result before the run is read as a measurement of Evidence.
///
/// A source held at a fraction `f` of its own ceiling contributes about `f` of
/// the saturation, so a factor of five keeps the source below 20 percent
/// utilization while the service under test is at 100 percent. Below this
/// factor the harness is close enough to the result to be part of what was
/// measured, and the run is reported as inconclusive rather than as a pass or
/// a failure.
const SUSTAINED_SOURCE_HEADROOM: f64 = 5.0;

/// The one constant body the sustained source returns. It satisfies the
/// projection and fact schema the acceptance bundle declares for that source.
const CONSTANT_SOURCE_BODY: &str = r#"{"total":1,"date_of_birth":"2000-01-01"}"#;

/// The ceilings the sustained fixture runs under.
///
/// Each lifted value is a production-meaningful default that would otherwise
/// become the thing measured, not a recommended deployment posture:
///
/// - `requestsPerPrincipalPerMinute: 60` with `burstPerPrincipal: 10` is one
///   request per second per principal, so an unlifted run measures the rate
///   limiter returning `evidence.rate_limited`.
/// - `maximumConcurrentRequests: 64` admits fewer requests than this driver
///   offers, so an unlifted run measures admission queueing.
/// - `concurrencyLimit: 8` per source caps outbound calls in flight, so an
///   unlifted run measures the source semaphore.
/// - `maximumFileBytes: 10485760` rotates the audit segment several times
///   inside a measured window, so an unlifted run measures segment rotation.
///
/// Deployments should keep the tracked defaults and tune from real traffic.
fn sustained_ceilings() -> FixtureCeilings {
    FixtureCeilings {
        maximum_concurrent_requests: 512,
        audit_maximum_file_bytes: 1_073_741_824,
        requests_per_principal_per_minute: 1_000_000,
        burst_per_principal: 100_000,
        source_concurrency_limit: 256,
    }
}

/// The upstream source used for sustained measurement: one `axum` handler
/// returning a constant JSON body over a real socket.
///
/// A matching mock server puts request matching, shared-state locking, and
/// per-call allocation on the measured path, and a rate measured through one
/// describes the harness rather than Evidence. This handler matches nothing,
/// locks nothing, and allocates only its response.
struct ConstantSource {
    origin: String,
    shutdown: tokio::sync::oneshot::Sender<()>,
    serving: tokio::task::JoinHandle<std::io::Result<()>>,
}

async fn start_constant_source() -> ConstantSource {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("the constant source listener binds");
    let address = listener
        .local_addr()
        .expect("the constant source listener has an address");
    let router = axum::Router::new().route(
        "/v1/facts",
        axum::routing::post(|| async {
            // Built explicitly so the response carries exactly one
            // `Content-Type`, which is what the source client requires.
            axum::response::Response::builder()
                .header(axum::http::header::CONTENT_TYPE, "application/json")
                .body(Body::from(CONSTANT_SOURCE_BODY))
                .expect("the constant source response builds")
        }),
    );
    let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel();
    let serving = tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(async move {
                let _ = shutdown_rx.await;
            })
            .await
    });
    ConstantSource {
        origin: format!("http://{address}"),
        shutdown,
        serving,
    }
}

/// One flat-out window against one endpoint. Every attempt lands in exactly
/// one of `statuses` or `transport_failures`, so nothing is dropped.
#[derive(Default)]
struct SustainedOutcome {
    statuses: BTreeMap<u16, usize>,
    latencies: Vec<Duration>,
    transport_failures: Vec<String>,
    elapsed: Duration,
}

impl SustainedOutcome {
    fn attempted(&self) -> usize {
        self.latencies.len() + self.transport_failures.len()
    }

    fn released(&self) -> usize {
        self.statuses.get(&200).copied().unwrap_or_default()
    }

    /// Attempts that did not return 200, including transport failures.
    fn unexpected(&self) -> usize {
        self.attempted() - self.released()
    }

    fn rate(&self) -> f64 {
        if self.elapsed.is_zero() {
            return 0.0;
        }
        self.released() as f64 / self.elapsed.as_secs_f64()
    }

    /// Nearest-rank p50, p95, and p99 over the whole window.
    fn latency_percentiles(&self) -> (Duration, Duration, Duration) {
        if self.latencies.is_empty() {
            return (Duration::ZERO, Duration::ZERO, Duration::ZERO);
        }
        let mut sorted = self.latencies.clone();
        sorted.sort_unstable();
        let at = |fraction: f64| {
            let rank = (fraction * sorted.len() as f64).ceil() as usize;
            sorted[rank.clamp(1, sorted.len()) - 1]
        };
        (at(0.50), at(0.95), at(0.99))
    }

    /// A short, operator-readable account of everything that was not a 200.
    fn failure_summary(&self) -> String {
        let statuses: Vec<String> = self
            .statuses
            .iter()
            .filter(|(status, _)| **status != 200)
            .map(|(status, count)| format!("{status} x{count}"))
            .collect();
        let mut summary = if statuses.is_empty() {
            "no non-2xx statuses".to_owned()
        } else {
            statuses.join(", ")
        };
        if let Some(first) = self.transport_failures.first() {
            summary.push_str(&format!(
                "; {} transport failures, first: {first}",
                self.transport_failures.len()
            ));
        }
        summary
    }
}

/// Issue requests flat out for `window` across `SUSTAINED_CONCURRENCY` closed
/// loop workers. Worker `n` presents `authorizations[n]`, so the caller decides
/// whether load spreads across principals or concentrates on one.
///
/// Both the service and the constant source are driven through this function
/// with the same client, worker count, header set, and window, so the two
/// reported rates are comparable.
async fn drive_flat_out(
    client: &reqwest::Client,
    endpoint: &str,
    body: &bytes::Bytes,
    authorizations: &[String],
    window: Duration,
) -> SustainedOutcome {
    assert_eq!(
        authorizations.len(),
        SUSTAINED_CONCURRENCY,
        "one authorization per worker"
    );
    let endpoint = Arc::new(endpoint.to_owned());
    let started = Instant::now();
    let deadline = started + window;
    let mut workers = Vec::with_capacity(SUSTAINED_CONCURRENCY);
    for authorization in authorizations {
        let client = client.clone();
        let endpoint = Arc::clone(&endpoint);
        let body = body.clone();
        let authorization = authorization.clone();
        workers.push(tokio::spawn(async move {
            let mut attempts: Vec<Result<(u16, Duration), String>> = Vec::new();
            while Instant::now() < deadline {
                let issued = Instant::now();
                let sent = client
                    .post(endpoint.as_str())
                    .header("authorization", authorization.as_str())
                    .header("content-type", "application/json")
                    .body(body.clone())
                    .send()
                    .await;
                attempts.push(match sent {
                    // Draining the body returns the connection to the pool. A
                    // body that fails to arrive is a failed request, not a
                    // successful one with a footnote.
                    Ok(response) => {
                        let status = response.status().as_u16();
                        match response.bytes().await {
                            Ok(_) => Ok((status, issued.elapsed())),
                            Err(error) => Err(error.to_string()),
                        }
                    }
                    Err(error) => Err(error.to_string()),
                });
            }
            attempts
        }));
    }

    let mut outcome = SustainedOutcome::default();
    for worker in workers {
        for attempt in worker.await.expect("a sustained load worker completes") {
            match attempt {
                Ok((status, latency)) => {
                    *outcome.statuses.entry(status).or_default() += 1;
                    outcome.latencies.push(latency);
                }
                Err(failure) => outcome.transport_failures.push(failure),
            }
        }
    }
    outcome.elapsed = started.elapsed();
    outcome
}

/// The acceptance runtime behind a real TCP listener, with a constant
/// in-process upstream source, driven by a real HTTP client over sockets.
struct SustainedFixture {
    _temporary: TempDir,
    source: ConstantSource,
    address: std::net::SocketAddr,
    client: reqwest::Client,
    /// One access token per worker, signed once outside every measured window.
    authorizations: Vec<String>,
    shutdown: tokio::sync::oneshot::Sender<()>,
    serving: tokio::task::JoinHandle<std::io::Result<()>>,
    runtime: Arc<EvidenceRuntime>,
    audit_path: PathBuf,
}

impl SustainedFixture {
    async fn start() -> Self {
        let source = start_constant_source().await;
        let prepared = prepare_fixture(
            "subject-binding-secret-canary-32-bytes-minimum",
            &source.origin,
            &sustained_ceilings(),
        );
        let runtime = Arc::new(
            EvidenceRuntime::initialize_with_authenticator(&prepared.runtime_path, authenticator())
                .await
                .expect("the sustained load runtime initializes"),
        );

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("the sustained load listener binds");
        let address = listener
            .local_addr()
            .expect("the sustained load listener has an address");
        let (shutdown, shutdown_rx) = tokio::sync::oneshot::channel();
        let serving = tokio::spawn({
            let runtime = Arc::clone(&runtime);
            async move {
                serve_listener_for_test(runtime, listener, async move {
                    let _ = shutdown_rx.await;
                })
                .await
            }
        });

        let client = reqwest::Client::builder()
            .pool_max_idle_per_host(SUSTAINED_CONCURRENCY)
            .no_proxy()
            .timeout(Duration::from_secs(30))
            .build()
            .expect("the sustained load client builds");

        // One principal per worker keeps the rate limiter's tracked key set
        // small and its per-check pruning cheap, so neither the token bucket
        // nor its map becomes the thing measured.
        let authorizations = (0..SUSTAINED_CONCURRENCY)
            .map(|worker| {
                format!(
                    "Bearer {}",
                    access_token_for(&format!("sustained-principal-{worker:04}"), None)
                )
            })
            .collect();

        Self {
            _temporary: prepared.temporary,
            source,
            address,
            client,
            authorizations,
            shutdown,
            serving,
            runtime,
            audit_path: prepared.audit_path,
        }
    }

    /// Drive the whole Evidence request path for `window`.
    async fn drive_service(&self, window: Duration) -> SustainedOutcome {
        let body = bytes::Bytes::from(
            serde_json::to_vec(&adult_request()).expect("the sustained request serializes"),
        );
        drive_flat_out(
            &self.client,
            &format!("http://{}/v1/evidence", self.address),
            &body,
            &self.authorizations,
            window,
        )
        .await
    }

    /// Drive the constant source directly to establish the harness ceiling the
    /// Evidence result has to sit well below.
    ///
    /// The probe opens its own connections and gets no warm-up, so it
    /// understates the source. That is the safe direction: it can only shrink
    /// the reported headroom, never inflate it.
    async fn drive_source(&self, window: Duration) -> SustainedOutcome {
        let body = bytes::Bytes::from(
            serde_json::to_vec(&adult_source_request()).expect("the probe body serializes"),
        );
        drive_flat_out(
            &self.client,
            &format!("{}/v1/facts", self.source.origin),
            &body,
            &self.authorizations,
            window,
        )
        .await
    }

    /// Stop the listener and the source, drain detached evaluations, and return
    /// the durable audit file.
    async fn shutdown(self) -> String {
        let _ = self.shutdown.send(());
        self.serving
            .await
            .expect("the sustained listener task completes")
            .expect("the sustained listener shuts down cleanly");
        let _ = self.source.shutdown.send(());
        self.source
            .serving
            .await
            .expect("the constant source task completes")
            .expect("the constant source shuts down cleanly");
        drop(self.runtime);
        fs::read_to_string(&self.audit_path).expect("the sustained audit file is readable")
    }
}

/// Sustain 1000 end-to-end requests per second through the whole request path.
///
/// Every measured request runs token verification, rate limiting, Rhai request
/// preparation, one outbound source call, Rhai extraction, evidence
/// construction, ES256 signing, and two durable audit appends, over real
/// sockets against the real router. At 1000 requests per second that is 2000
/// audit appends per second.
///
/// The upstream source is a constant in-process handler whose own ceiling is
/// measured in the same run, under the same client, worker count, header set,
/// and window shape. When that ceiling is not at least
/// `SUSTAINED_SOURCE_HEADROOM` times the Evidence result, the harness is part
/// of what was measured and the run is reported as inconclusive rather than as
/// a pass or a failure.
///
/// The target holds with and without `--release`; the recorded figures in
/// `products/evidence/OPERATOR-CONTRACT.md` come from the optimized build.
///
/// ```text
/// cargo test --release -p registry-evidence --lib -- --ignored --nocapture sustained_load_holds_one_thousand_requests_per_second
/// ```
#[tokio::test(flavor = "multi_thread")]
#[ignore = "opt-in sustained throughput target; host-specific and long running"]
async fn sustained_load_holds_one_thousand_requests_per_second() {
    let fixture = SustainedFixture::start().await;

    let warmup = fixture.drive_service(SUSTAINED_WARMUP).await;
    assert_eq!(
        warmup.unexpected(),
        0,
        "warm-up must already be clean; observed {}",
        warmup.failure_summary()
    );

    let measured = fixture.drive_service(SUSTAINED_WINDOW).await;
    let source = fixture.drive_source(SUSTAINED_WINDOW).await;

    let rate = measured.rate();
    let source_rate = source.rate();
    let headroom = if rate > 0.0 { source_rate / rate } else { 0.0 };
    let percentiles = measured.latency_percentiles();
    println!(
        "\n=== Evidence sustained throughput ===\n\
         host                  : {} logical cores\n\
         offered concurrency   : {SUSTAINED_CONCURRENCY} in flight, {} principals\n\
         measured window       : {:.1}s after a {:.1}s warm-up\n\
         \n\
         requests released     : {} in {:.2}s\n\
         achieved rate         : {rate:.0} rps ({:.0} audit appends/s)\n\
         target                : {SUSTAINED_TARGET_RPS:.0} rps\n\
         non-2xx and failures  : {} ({})\n\
         \n\
         latency p50           : {:.2} ms\n\
         latency p95           : {:.2} ms\n\
         latency p99           : {:.2} ms\n\
         \n\
         constant source rate  : {source_rate:.0} rps standalone, {} non-2xx and failures\n\
         source headroom       : {headroom:.1}x over Evidence (validity floor {SUSTAINED_SOURCE_HEADROOM:.1}x)\n\
         =====================================\n",
        std::thread::available_parallelism().map_or(0, std::num::NonZeroUsize::get),
        SUSTAINED_CONCURRENCY,
        SUSTAINED_WINDOW.as_secs_f64(),
        SUSTAINED_WARMUP.as_secs_f64(),
        measured.released(),
        measured.elapsed.as_secs_f64(),
        rate * 2.0,
        measured.unexpected(),
        measured.failure_summary(),
        percentiles.0.as_secs_f64() * 1000.0,
        percentiles.1.as_secs_f64() * 1000.0,
        percentiles.2.as_secs_f64() * 1000.0,
        source.unexpected(),
    );

    assert_eq!(
        measured.unexpected(),
        0,
        "sustained load must not shed requests; observed {}",
        measured.failure_summary()
    );
    assert_eq!(
        source.unexpected(),
        0,
        "the constant source probe must not shed requests; observed {}",
        source.failure_summary()
    );
    assert!(
        headroom >= SUSTAINED_SOURCE_HEADROOM,
        "INCONCLUSIVE: the constant source sustained {source_rate:.0} rps against Evidence at \
         {rate:.0} rps, only {headroom:.1}x. Below {SUSTAINED_SOURCE_HEADROOM:.1}x the harness is \
         part of what was measured, so this run is neither a pass nor a failure"
    );
    assert!(
        rate >= SUSTAINED_TARGET_RPS,
        "sustained {rate:.0} rps, below the {SUSTAINED_TARGET_RPS:.0} rps target"
    );

    // Both audit appends are on the request's critical path, so a released
    // assertion that skipped one would be a silently cheaper request.
    let released = warmup.released() + measured.released();
    let audit = fixture.shutdown().await;
    assert_eq!(
        audit.matches("\"phase\":\"access-attempt\"").count(),
        released,
        "one access-attempt record per released assertion"
    );
    assert_eq!(
        audit.matches("\"phase\":\"disclosure-release\"").count(),
        released,
        "one disclosure-release record per released assertion"
    );
}
