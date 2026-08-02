use std::{
    collections::{BTreeMap, BTreeSet},
    fs,
    io::Write as _,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

use async_trait::async_trait;
use axum::{body::Body, http::Request as HttpRequest};
use axum_test::TestServer;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use chrono::Utc;
use jsonwebtoken::{jwk::JwkSet, Algorithm};
use registry_platform_crypto::{
    sign, KeyReadiness, LocalJwkSigner, PrivateJwk, PublicJwk, SigningAlgorithm, SigningError,
    SigningProvider,
};
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig, TokenVerifier, TokenVerifierConfig};
use serde_json::{json, Value};
use tempfile::TempDir;
use tower::ServiceExt as _;
use wiremock::{
    matchers::{body_json, header, method, path, query_param},
    Mock, MockServer, ResponseTemplate,
};

use crate::{
    auth::{AuthenticationClaimsConfig, Authenticator},
    model::{
        Evidence, EvidenceDefinitions, EvidenceRequest, EvidenceSelectorField, FlattenedJws,
        PublicValue, RequestedSelector, RequestedSubject, SelectorValue,
    },
    problem::ProblemCode,
    runtime::{EvidenceRuntime, RuntimeInitializationError},
    server::{build_app, build_app_at_for_test, serve_listener_for_test},
    signing::EvidenceSigner,
    verifier::{verify_flattened_jws, EvidenceVerificationPolicy},
};

const AUTH_PRIVATE_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"acceptance-auth-key"}"#;
const EVIDENCE_PRIVATE_JWK: &str = r#"{"kty":"OKP","crv":"Ed25519","d":"2oPoxdKuO7Kpd-3JLfNW_4xwpFxItbS-fxe03ZybYEw","x":"1aj_rLJsGFgw-5v925EMmeZj5JqP44xegafEKfZbdxc","alg":"EdDSA","kid":"acceptance-evidence-key"}"#;
const TOKEN_ISSUER: &str = "https://identity.invalid";
const TOKEN_AUDIENCE: &str = "evidence-fixture";
const EVIDENCE_AUDIENCE: &str = "https://relying.invalid/procedure";
const AUTHORITY: &str = "statutory-caseworker-v1";
const BEARER: &str = "source-bearer-canary";
const BASIC_USER: &str = "source-user-canary";
const BASIC_PASSWORD: &str = "source-password-canary";
const PARENT_REFERENCE: &str = "synthetic-parent-reference-001";
const NON_PARENT_REFERENCE: &str = "synthetic-non-parent-reference-003";

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

struct FailAfterSelfTestSigner {
    delegate: LocalJwkSigner,
    calls: AtomicUsize,
}

struct UnavailableReadinessSigner {
    delegate: LocalJwkSigner,
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
    mount_adult_source(&fixture.server, None).await;

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
    for stale in [&definitions_path, &response_path] {
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
    assert_eq!(
        definitions.configuration_revision,
        fixture.runtime.bundle().revision()
    );
    let serialized_definitions =
        serde_json::to_string(&definitions).expect("discovery response serializes");
    for prohibited in [
        "fixture-agency",
        "statutory-caseworker-v1",
        "source-a",
        "adapters/",
        "derivations/",
        "codelists/",
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
        &verification_policy(&fixture.runtime, &request),
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
    let audit = fs::read_to_string(&fixture.audit_path).expect("first-curl audit is readable");
    assert_eq!(audit.lines().count(), 2);
    println!(
        "PASS: authenticated discovery listed four safe request shapes, Evidence returned HTTP 200, its JWS verified, adult-status was true, minimization held, and both audit events were durable."
    );
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
impl SigningProvider for FailAfterSelfTestSigner {
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
            Err(SigningError::external("synthetic unavailable signer"))
        }
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
    assert_eq!(
        jwks.json::<crate::model::JwksDocument>(),
        *fixture.runtime.jwks()
    );

    let standard_token = access_token(None);
    let parent_token = access_token(Some(parent_grant_claims()));
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
    assert_eq!(
        standard_definitions.configuration_revision,
        fixture.runtime.bundle().revision()
    );
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
            &verification_policy(&fixture.runtime, request),
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

#[tokio::test]
async fn discovery_requires_authentication_and_returns_no_unentitled_definitions() {
    let fixture = acceptance_runtime().await;
    let http = TestServer::new(build_app(Arc::clone(&fixture.runtime)));

    let missing = http.get("/v1/evidence-definitions").await;
    assert_eq!(missing.status_code(), axum::http::StatusCode::UNAUTHORIZED);
    assert_eq!(
        missing.json::<Value>()["code"],
        json!("authentication_failed")
    );

    let filtered = http
        .get("/v1/evidence-definitions?requirement=caller-selected")
        .add_header("authorization", format!("Bearer {}", access_token(None)))
        .await;
    assert_eq!(filtered.status_code(), axum::http::StatusCode::BAD_REQUEST);
    assert_eq!(filtered.json::<Value>()["code"], json!("malformed_request"));

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
    let http = TestServer::new(build_app(runtime));

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
    assert_eq!(limited.json::<Value>()["code"], json!("rate_limited"));
    assert_eq!(limited.header("retry-after"), "1");
    assert!(prepared
        .server
        .received_requests()
        .await
        .expect("request journal is available")
        .is_empty());
}

#[tokio::test]
async fn serving_runtime_never_reloads_merges_or_falls_back_after_bundle_capture() {
    let fixture = acceptance_runtime().await;
    let captured_revision = fixture.runtime.bundle().revision().to_owned();
    let captured_runtime_revision = fixture.runtime.runtime_revision().to_owned();
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
        &verification_policy(&fixture.runtime, &request),
    )
    .expect("captured-revision assertion verifies");
    assert_eq!(evidence.configuration_revision, captured_revision);
    assert_eq!(
        evidence.supported_values[0].value,
        PublicValue::Boolean(true)
    );
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
    let signer = EvidenceSigner::initialize(provider, "acceptance-evidence-key")
        .await
        .expect("provider self-test succeeds independently of readiness posture");
    runtime.replace_signer_for_test(signer);
    assert!(
        !runtime.ready().await,
        "unready signing provider denies readiness"
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
    assert!(!audit.contains("fallback-client-canary"));
    assert!(!audit.contains("fallback-authorized-party-canary"));
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
    let provider: Arc<dyn SigningProvider> = Arc::new(FailAfterSelfTestSigner {
        delegate,
        calls: AtomicUsize::new(0),
    });
    let failing_signer = EvidenceSigner::initialize(provider, "acceptance-evidence-key")
        .await
        .expect("signer passes its startup self-test");
    runtime.replace_signer_for_test(failing_signer);
    mount_adult_source(&prepared.server, None).await;

    let error = runtime
        .evaluate(
            "operation-signing-failure",
            &access_token(None),
            &adult_request(),
        )
        .await
        .expect_err("signing failure cannot produce any success representation");
    assert_eq!(error.problem(), ProblemCode::ServiceUnavailable);
    let audit = fs::read_to_string(&prepared.audit_path).expect("audit is readable");
    assert_eq!(audit.matches("\"phase\":\"access-attempt\"").count(), 1);
    assert_eq!(audit.matches("\"decision\":\"signing-failure\"").count(), 1);
    assert_eq!(audit.matches("\"phase\":\"disclosure-release\"").count(), 0);
    for canary in privacy_canaries() {
        assert!(!audit.contains(canary));
    }
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
            &verification_policy(&fixture.runtime, &request),
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
    let false_jws = fixture
        .runtime
        .evaluate(
            "operation-acceptance-parent-false",
            &non_parent_token,
            &parent_request(),
        )
        .await
        .expect("exact non-membership in the complete governed parent set is signed");
    let false_evidence = verify_flattened_jws(
        &serde_json::to_vec(&false_jws).expect("JWS serializes"),
        fixture.runtime.jwks(),
        &verification_policy(&fixture.runtime, &parent_request()),
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
    assert_eq!(audit.matches("\"phase\":\"denial\"").count(), 2);
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
        "facts: #{date_of_birth: source_response[\"date_of_birth\"]}",
        "facts: #{date_of_birth: source_response[\"date_of_birth\"], unexpected_private_fact: \"PrivacyCanary\"}",
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
                let mut policy = verification_policy(&fixture.runtime, &request);
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
                    "evidence_not_available" => ProblemCode::EvidenceNotAvailable,
                    "dependency_unavailable" => ProblemCode::DependencyUnavailable,
                    "service_unavailable" => ProblemCode::ServiceUnavailable,
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

async fn prepare_acceptance(binding_secret: &str) -> PreparedAcceptance {
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
    copy_tree(&fixture_root(), &bundle_root);

    let server = MockServer::start().await;
    rewrite_deployment_values(&bundle_root, &server.uri());
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
    write_runtime_config(&runtime_path, &bundle_root, &secret_root, &audit_path);
    make_file_read_only(&runtime_path);
    make_read_only(&bundle_root);

    PreparedAcceptance {
        temporary,
        bundle_root,
        runtime_path,
        server,
        audit_path,
    }
}

fn authenticator() -> Authenticator {
    let private = PrivateJwk::parse(AUTH_PRIVATE_JWK).expect("auth test key parses");
    let jwks: JwkSet = serde_json::from_value(json!({"keys": [private.public()]}))
        .expect("static auth JWKS parses");
    let fetcher = Arc::new(JwksFetcher::new_static(jwks, JwksFetcherConfig::defaults()));
    let verifier = Arc::new(TokenVerifier::new(
        TokenVerifierConfig::access_token_profile(
            TOKEN_ISSUER,
            vec![TOKEN_AUDIENCE.to_owned()],
            vec![Algorithm::EdDSA],
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
            actor_claim: None,
        },
    )
}

fn access_token(extra: Option<Value>) -> String {
    access_token_for("requester-principal-canary", extra)
}

fn access_token_for(principal: &str, extra: Option<Value>) -> String {
    let now = Utc::now().timestamp();
    let mut claims = json!({
        "iss": TOKEN_ISSUER,
        "aud": TOKEN_AUDIENCE,
        "sub": principal,
        "iat": now - 1,
        "exp": now + 3600,
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
            "alg": "EdDSA",
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
        .expect(1)
        .mount(server)
        .await;
}

async fn mount_licence_source(server: &MockServer) {
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
        .expect(1)
        .mount(server)
        .await;
}

async fn mount_adult_source(server: &MockServer, delay: Option<Duration>) {
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
        .expect(1)
        .mount(server)
        .await;
}

async fn mount_parent_source(server: &MockServer, response: Value) {
    Mock::given(method("POST"))
        .and(path("/v1/child-relationships"))
        .and(header("accept", "application/json"))
        .and(header("authorization", format!("Bearer {BEARER}").as_str()))
        .and(body_json(parent_source_request()))
        .respond_with(ResponseTemplate::new(200).set_body_json(response))
        .expect(1)
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
        requirement: requirement.to_owned(),
        purpose: purpose.to_owned(),
        subjects,
    }
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

fn verification_policy(
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
    EvidenceVerificationPolicy {
        issued_by: runtime.bundle().config.issuer.id.clone(),
        provided_by: runtime.bundle().config.service.provider_id.clone(),
        requirement: request.requirement.clone(),
        evidence_type: requirement.evidence_type.clone(),
        purpose: request.purpose.clone(),
        audience: EVIDENCE_AUDIENCE.to_owned(),
        configuration_revision: runtime.bundle().revision().to_owned(),
        now: Utc::now(),
        clock_skew: Duration::from_secs(30),
    }
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

fn rewrite_deployment_values(bundle_root: &Path, source_origin: &str) {
    let path = bundle_root.join("evidence.yaml");
    let mut text = fs::read_to_string(&path).expect("copied configuration is readable");
    replace_exact(&mut text, "https://source.invalid", source_origin, 4);
    replace_exact(
        &mut text,
        "fixture-key-2026-01",
        "acceptance-evidence-key",
        1,
    );
    fs::write(path, text).expect("deployment-only fixture rewrite succeeds");
}

fn write_runtime_config(
    runtime_path: &Path,
    bundle_root: &Path,
    secret_root: &Path,
    audit_path: &Path,
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
  maximumConcurrentRequests: 64
  requestTimeoutMilliseconds: 10000
  shutdownGraceMilliseconds: 30000
secretProviders:
  file:
    root: {}
auditStorage:
  path: {}
  maximumFileBytes: 10485760
outboundTls:
  systemRoots: true
  trustProfiles: {{}}
"#,
        bundle_root.display(),
        secret_root.display(),
        audit_path.display(),
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
