// SPDX-License-Identifier: Apache-2.0
//! Explicitly ignored end-to-end proof for the maintained DHIS2 2.41.9 journey.
//!
//! The companion runner supplies a disposable TLS PostgreSQL 16 database and
//! sources the operator-authorized DHIS2 credentials. This module never prints
//! a credential, bearer token, source URL, selector, source response, or public
//! response body. Failures retain only the closed test-stage taxonomy below.

use std::{
    env, fs,
    path::{Path, PathBuf},
    sync::Arc,
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    body::{to_bytes, Body},
    http::{header, HeaderValue, Method, Request, StatusCode},
    Extension, Router,
};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use ed25519_dalek::{pkcs8::EncodePrivateKey, SigningKey};
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use postgres_native_tls::MakeTlsConnector;
use rand_core::OsRng;
use registry_platform_audit::AuditChainProfile;
use reqwest::Url;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    task::JoinHandle,
};
use tokio_postgres::{Client, Config as PostgresConfig};
use tower::ServiceExt;
use ulid::Ulid;
use zeroize::Zeroizing;

use registry_relay::{
    audit::{AuditPipeline, InMemorySink},
    config,
    consultation::{
        operator::{
            bootstrap_state, BootstrapKeyringStatus, BootstrapStatePlaneStatus,
            BootstrapStateRequest,
        },
        ConsultationService, ConsultationServiceReadiness,
    },
    server,
};

const ADMIN_DATABASE_URL_ENV: &str = "REGISTRY_RELAY_LIVE_POSTGRES_ADMIN_URL";
const POSTGRES_CA_PATH_ENV: &str = "REGISTRY_RELAY_LIVE_POSTGRES_CA_PATH";
const RUNTIME_DATABASE_URL_ENV: &str = "REGISTRY_RELAY_CONSULTATION_DATABASE_URL";
const MAINTENANCE_DATABASE_URL_ENV: &str = "REGISTRY_RELAY_LIVE_MAINTENANCE_DATABASE_URL";
const READER_DATABASE_URL_ENV: &str = "REGISTRY_RELAY_LIVE_READER_DATABASE_URL";
const AUDIT_SECRET_ENV: &str = "REGISTRY_RELAY_AUDIT_HASH_SECRET";
const PSEUDONYM_SECRET_ENV: &str = "REGISTRY_RELAY_AUDIT_PSEUDONYM_EPOCH_1";
const DHIS2_BASE_URL_ENV: &str = "DHIS2_BASE_URL";
const DHIS2_USERNAME_ENV: &str = "DHIS2_USERNAME";
const DHIS2_PASSWORD_ENV: &str = "DHIS2_PASSWORD";

const PROFILE_ID: &str = "dhis2.tracker.enrollment-status.exact";
const PROFILE_VERSION: &str = "1";
const PROFILE_ROUTE: &str = "/v1/consultations/dhis2.tracker.enrollment-status.exact/versions/1";
const EXECUTE_ROUTE: &str =
    "/v1/consultations/dhis2.tracker.enrollment-status.exact/versions/1/execute";
const PURPOSE: &str = "program-enrollment-verification";
const REQUIRED_SCOPE: &str = "registry:consult:dhis2-enrollment-status";
const NOTARY_EVALUATION_ID: &str = "01JYZZZZZZZZZZZZZZZZZZZZZZ";
const ISSUER: &str = "https://relay-live-issuer.example.test";
const AUDIENCE: &str = "relay-consultation";
const NOTARY_PRINCIPAL: &str = "registry-notary";
const JWT_KID: &str = "relay-live-dhis2-ed25519";
const PSEUDONYM_KEY_ID: &str = "epoch-1";

const CONTRACT_HASH: &str =
    "sha256:eb8f6cb4dd81d8a34c25e4da393ada734caa553e7e65a06fabd613afb1fecbc9";
const PACK_HASH: &str = "sha256:017783fe880863e9dedc5138df4e1212d020ce7cfac5a13b58911fc4705f0e7a";

const PROFILE_DIRECTORY: &str = "profiles/dhis2-2.41.9-enrollment-status";
const CONFIG_EXAMPLE_FILE: &str = "relay-config.example.yaml";
const PUBLIC_CONTRACT_FILE: &str = "public-contract.json";
const INTEGRATION_PACK_FILE: &str = "integration-pack.json";
const CONFORMANCE_FILE: &str = "evidence/conformance.json";
const NEGATIVE_SECURITY_FILE: &str = "evidence/negative-security.json";
const MINIMIZATION_FILE: &str = "evidence/minimization.json";

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
enum LiveJourneyError {
    #[error("required live-test environment is unavailable: {0}")]
    MissingEnvironment(&'static str),
    #[error("the authorized DHIS2 base URL is invalid")]
    InvalidDhis2BaseUrl,
    #[error("the disposable PostgreSQL trust configuration is invalid")]
    InvalidPostgresTls,
    #[error("the disposable PostgreSQL database is unavailable")]
    PostgresUnavailable,
    #[error("the disposable PostgreSQL role installation failed")]
    StatePlaneInstall,
    #[error("the disposable PostgreSQL pseudonym epoch initialization failed")]
    PseudonymInitialization,
    #[error("the maintained DHIS2 artifacts could not be staged")]
    ArtifactStaging,
    #[error("the maintained DHIS2 runtime configuration did not load")]
    ConfigLoad,
    #[error("the live OIDC JWKS server could not start")]
    JwksServer,
    #[error("the live EdDSA bearer token could not be minted")]
    TokenMint,
    #[error("the production OIDC provider could not be built")]
    AuthActivation,
    #[error("the keyed audit profile could not be activated")]
    AuditActivation,
    #[error("the concrete consultation service could not be activated")]
    ConsultationActivation,
    #[error("the concrete consultation service was not ready")]
    ConsultationNotReady,
    #[error("the production protected router could not be assembled")]
    RouterAssembly,
    #[error("the protected profile metadata request failed")]
    MetadataRequest,
    #[error("the protected profile metadata response was invalid")]
    MetadataResponse,
    #[error("the protected DHIS2 consultation request failed")]
    ExecuteRequest,
    #[error("Relay rejected the live consultation as invalid")]
    ExecuteInvalidRequest,
    #[error("Relay rejected the live consultation credentials")]
    ExecuteInvalidCredentials,
    #[error("Relay denied the live consultation")]
    ExecuteDenied,
    #[error("Relay did not resolve the live consultation profile")]
    ExecuteProfileNotFound,
    #[error("Relay rate-limited the live consultation")]
    ExecuteRateLimited,
    #[error("Relay reported the live consultation unavailable")]
    ExecuteUnavailable,
    #[error("Relay recorded unavailable source credentials for the live consultation")]
    ExecuteSourceCredentialsUnavailable,
    #[error("Relay recorded the live DHIS2 source as unavailable")]
    ExecuteSourceUnavailable,
    #[error("Relay recorded a live DHIS2 response-contract violation")]
    ExecuteResponseContractViolation,
    #[error("Relay recorded a live DHIS2 cardinality violation")]
    ExecuteCardinalityViolation,
    #[error("Relay closed the live consultation before source dispatch")]
    ExecuteClosedBeforeSourceDispatch,
    #[error("Relay closed the live consultation after source dispatch without a known result")]
    ExecuteClosedAfterSourceDispatch,
    #[error("Relay left the live consultation without a terminal durable completion")]
    ExecuteMissingDurableCompletion,
    #[error("the protected DHIS2 consultation response was invalid")]
    ExecuteResponse,
    #[error("the durable consultation evidence did not match the completed journey")]
    DurableEvidence,
    #[error("the concrete consultation service did not shut down cleanly")]
    ConsultationShutdown,
    #[error("the disposable PostgreSQL state could not be cleaned up")]
    PostgresCleanup,
}

/// Run via `scripts/run-live-dhis2-consultation.sh`. The test stays ignored so
/// ordinary CI and developer test runs never contact a live registry.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires the explicit live DHIS2 runner and a disposable TLS PostgreSQL 16 instance"]
async fn live_dhis2_consultation_lifecycle() {
    if let Err(error) = run_live_dhis2_consultation_lifecycle().await {
        panic!("live DHIS2 consultation lifecycle failed: {error}");
    }
}

#[test]
fn maintained_operator_example_stages_through_real_loader() {
    let staged = StagedProfile::new(
        "https://dhis2.example.test/stable-2-41-9",
        Path::new("/tmp/registry-relay-live-test-ca.pem"),
        "http://127.0.0.1:1/keys",
    )
    .unwrap_or_else(|_| panic!("the maintained DHIS2 operator example did not stage"));
    let loaded = config::load_with_metadata(&staged.config_path)
        .unwrap_or_else(|_| panic!("the staged maintained DHIS2 operator example did not load"));
    assert!(loaded.runtime.consultation.is_some());
    assert!(loaded.consultation_artifacts.is_some());
}

#[test]
fn live_failure_diagnostics_remain_closed_and_exact() {
    for (status, code, expected) in [
        (
            StatusCode::BAD_REQUEST,
            Some("consultation.invalid_request"),
            LiveJourneyError::ExecuteInvalidRequest,
        ),
        (
            StatusCode::UNAUTHORIZED,
            Some("auth.invalid_credentials"),
            LiveJourneyError::ExecuteInvalidCredentials,
        ),
        (
            StatusCode::FORBIDDEN,
            Some("consultation.denied"),
            LiveJourneyError::ExecuteDenied,
        ),
        (
            StatusCode::NOT_FOUND,
            Some("consultation.profile_not_found"),
            LiveJourneyError::ExecuteProfileNotFound,
        ),
        (
            StatusCode::TOO_MANY_REQUESTS,
            Some("consultation.rate_limited"),
            LiveJourneyError::ExecuteRateLimited,
        ),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Some("consultation.unavailable"),
            LiveJourneyError::ExecuteUnavailable,
        ),
        (
            StatusCode::SERVICE_UNAVAILABLE,
            Some("unexpected"),
            LiveJourneyError::ExecuteRequest,
        ),
    ] {
        assert_eq!(classify_closed_execute_failure(status, code), expected);
    }

    for (outcome, class, failure, expected) in [
        (
            Some("known_complete"),
            Some("known_failure"),
            Some("credential_unavailable"),
            LiveJourneyError::ExecuteSourceCredentialsUnavailable,
        ),
        (
            Some("known_complete"),
            Some("known_failure"),
            Some("source_unavailable"),
            LiveJourneyError::ExecuteSourceUnavailable,
        ),
        (
            Some("known_complete"),
            Some("known_failure"),
            Some("response_contract_violation"),
            LiveJourneyError::ExecuteResponseContractViolation,
        ),
        (
            Some("known_complete"),
            Some("known_failure"),
            Some("cardinality_violation"),
            LiveJourneyError::ExecuteCardinalityViolation,
        ),
        (
            Some("not_started"),
            None,
            None,
            LiveJourneyError::ExecuteClosedBeforeSourceDispatch,
        ),
        (
            Some("outcome_unknown"),
            None,
            None,
            LiveJourneyError::ExecuteClosedAfterSourceDispatch,
        ),
        (
            Some("known_complete"),
            Some("known_failure"),
            Some("unexpected"),
            LiveJourneyError::ExecuteUnavailable,
        ),
    ] {
        assert_eq!(
            classify_durable_execute_failure(outcome, class, failure),
            expected
        );
    }
}

async fn run_live_dhis2_consultation_lifecycle() -> Result<(), LiveJourneyError> {
    require_nonempty_environment(DHIS2_USERNAME_ENV)?;
    require_nonempty_environment(DHIS2_PASSWORD_ENV)?;
    let dhis2_base_url = required_secret_environment(DHIS2_BASE_URL_ENV)?;
    let admin_database_url = required_secret_environment(ADMIN_DATABASE_URL_ENV)?;
    let postgres_ca_path = required_path_environment(POSTGRES_CA_PATH_ENV)?;

    let jwks = LiveJwksServer::start().await?;
    let mut environment = ScopedEnvironment::default();
    let audit_secret = random_secret();
    let pseudonym_secret = random_secret();
    environment.set(AUDIT_SECRET_ENV, audit_secret.as_str());
    environment.set(PSEUDONYM_SECRET_ENV, pseudonym_secret.as_str());

    let (mut database, database_urls) =
        LiveDatabase::provision(admin_database_url.as_str(), postgres_ca_path.as_path()).await?;
    environment.set(RUNTIME_DATABASE_URL_ENV, database_urls.runtime.as_str());
    environment.set(
        MAINTENANCE_DATABASE_URL_ENV,
        database_urls.maintenance.as_str(),
    );
    environment.set(READER_DATABASE_URL_ENV, database_urls.reader.as_str());

    let staged = StagedProfile::new(
        dhis2_base_url.as_str(),
        postgres_ca_path.as_path(),
        jwks.jwks_url(),
    )?;
    let mut loaded = config::load_with_metadata(&staged.config_path)
        .map_err(|_| LiveJourneyError::ConfigLoad)?;
    let now = current_unix_ms()?;
    let active_write_deadline_unix_ms = now + 30 * 60 * 1_000;
    let first_bootstrap = bootstrap_live_state(
        &loaded.runtime,
        database.owner_role(),
        active_write_deadline_unix_ms,
    )
    .await?;
    if first_bootstrap.state_plane != BootstrapStatePlaneStatus::InstalledOrAttested
        || first_bootstrap.keyring != BootstrapKeyringStatus::Initialized
    {
        return Err(LiveJourneyError::PseudonymInitialization);
    }
    let identical_bootstrap = bootstrap_live_state(
        &loaded.runtime,
        database.owner_role(),
        active_write_deadline_unix_ms,
    )
    .await?;
    if identical_bootstrap.state_plane != BootstrapStatePlaneStatus::InstalledOrAttested
        || identical_bootstrap.keyring != BootstrapKeyringStatus::Identical
    {
        return Err(LiveJourneyError::PseudonymInitialization);
    }
    let artifacts = loaded
        .consultation_artifacts
        .take()
        .ok_or(LiveJourneyError::ConfigLoad)?;
    let config = Arc::new(loaded.runtime);

    let auth = registry_relay::auth::runtime::build_auth(config.as_ref())
        .await
        .map_err(|_| LiveJourneyError::AuthActivation)?;
    let chain_profile = AuditChainProfile::registry_relay_from_env(AUDIT_SECRET_ENV)
        .map_err(|_| LiveJourneyError::AuditActivation)?;
    let service = ConsultationService::activate(config.as_ref(), artifacts, chain_profile.hasher())
        .await
        .map_err(|_| LiveJourneyError::ConsultationActivation)?;
    if service.readiness().await != ConsultationServiceReadiness::Ready {
        return Err(LiveJourneyError::ConsultationNotReady);
    }

    let audit = Arc::new(AuditPipeline::new_with_chain_profile(
        Arc::new(InMemorySink::new()),
        chain_profile,
    ));
    let app = server::build_app(Arc::clone(&config), auth, audit)
        .map_err(|_| LiveJourneyError::RouterAssembly)?
        .layer(Extension(Arc::clone(&service)));
    let bearer = jwks.mint_bearer()?;

    let journey = execute_protected_journey(app.clone(), bearer.as_str()).await;
    let closed_diagnostic = if matches!(journey, Err(LiveJourneyError::ExecuteUnavailable)) {
        Some(database.classify_safe_execute_failure().await)
    } else {
        None
    };
    let shutdown = service
        .shutdown()
        .await
        .map_err(|_| LiveJourneyError::ConsultationShutdown);
    drop(app);
    drop(service);
    let durable_evidence = if journey.is_ok() && shutdown.is_ok() {
        database.assert_safe_durable_evidence().await
    } else {
        Ok(())
    };
    let journey = closed_diagnostic.map_or(journey, Err);
    let cleanup = database.cleanup().await;
    drop(jwks);

    journey?;
    shutdown?;
    durable_evidence?;
    cleanup
}

async fn bootstrap_live_state(
    config: &config::Config,
    owner_role: &str,
    active_write_deadline_unix_ms: i64,
) -> Result<registry_relay::consultation::operator::BootstrapStateResult, LiveJourneyError> {
    bootstrap_state(BootstrapStateRequest {
        config,
        migration_database_url_env: ADMIN_DATABASE_URL_ENV,
        owner_role,
        keyring_maintenance_database_url_env: MAINTENANCE_DATABASE_URL_ENV,
        keyring_reader_database_url_env: READER_DATABASE_URL_ENV,
        active_key_id: PSEUDONYM_KEY_ID,
        active_write_deadline_unix_ms,
        audit_event_retention_ms: 24 * 60 * 60 * 1_000,
    })
    .await
    .map_err(|_| LiveJourneyError::StatePlaneInstall)
}

async fn execute_protected_journey(app: Router, bearer: &str) -> Result<(), LiveJourneyError> {
    let authorization_text = Zeroizing::new(format!("Bearer {bearer}"));
    let authorization = HeaderValue::from_str(authorization_text.as_str())
        .map_err(|_| LiveJourneyError::TokenMint)?;
    drop(authorization_text);
    let metadata_request = Request::builder()
        .method(Method::GET)
        .uri(PROFILE_ROUTE)
        .header(header::AUTHORIZATION, authorization.clone())
        .body(Body::empty())
        .map_err(|_| LiveJourneyError::MetadataRequest)?;
    let metadata_response = app
        .clone()
        .oneshot(metadata_request)
        .await
        .map_err(|_| LiveJourneyError::MetadataRequest)?;
    if metadata_response.status() != StatusCode::OK {
        return Err(LiveJourneyError::MetadataRequest);
    }
    let metadata = to_bytes(metadata_response.into_body(), 256 * 1024)
        .await
        .map_err(|_| LiveJourneyError::MetadataResponse)?;
    let metadata: Value =
        serde_json::from_slice(&metadata).map_err(|_| LiveJourneyError::MetadataResponse)?;
    if metadata.get("contract_hash").and_then(Value::as_str) != Some(CONTRACT_HASH)
        || metadata.pointer("/contract/id").and_then(Value::as_str) != Some(PROFILE_ID)
    {
        return Err(LiveJourneyError::MetadataResponse);
    }
    drop(metadata);

    let execute_request = Request::builder()
        .method(Method::POST)
        .uri(EXECUTE_ROUTE)
        .header(header::AUTHORIZATION, authorization)
        .header(header::CONTENT_TYPE, "application/json")
        .header("data-purpose", PURPOSE)
        .header("registry-notary-evaluation-id", NOTARY_EVALUATION_ID)
        .body(Body::from(
            br#"{"inputs":{"tracked_entity":"PQfMcpmXeFE"}}"# as &'static [u8],
        ))
        .map_err(|_| LiveJourneyError::ExecuteRequest)?;
    let execute_response = app
        .oneshot(execute_request)
        .await
        .map_err(|_| LiveJourneyError::ExecuteRequest)?;
    if execute_response.status() != StatusCode::OK {
        return Err(closed_execute_failure(execute_response).await);
    }
    let response = to_bytes(execute_response.into_body(), 64 * 1024)
        .await
        .map_err(|_| LiveJourneyError::ExecuteResponse)?;
    let response: Value =
        serde_json::from_slice(&response).map_err(|_| LiveJourneyError::ExecuteResponse)?;
    validate_public_response(&response)
}

async fn closed_execute_failure(response: axum::response::Response) -> LiveJourneyError {
    let status = response.status();
    let Ok(body) = to_bytes(response.into_body(), 8 * 1024).await else {
        return LiveJourneyError::ExecuteRequest;
    };
    let Ok(problem) = serde_json::from_slice::<Value>(&body) else {
        return LiveJourneyError::ExecuteRequest;
    };
    let code = problem.get("code").and_then(Value::as_str);
    classify_closed_execute_failure(status, code)
}

fn classify_closed_execute_failure(status: StatusCode, code: Option<&str>) -> LiveJourneyError {
    match (status, code) {
        (StatusCode::BAD_REQUEST, Some("consultation.invalid_request")) => {
            LiveJourneyError::ExecuteInvalidRequest
        }
        (StatusCode::UNAUTHORIZED, Some("auth.invalid_credentials")) => {
            LiveJourneyError::ExecuteInvalidCredentials
        }
        (StatusCode::FORBIDDEN, Some("consultation.denied")) => LiveJourneyError::ExecuteDenied,
        (StatusCode::NOT_FOUND, Some("consultation.profile_not_found")) => {
            LiveJourneyError::ExecuteProfileNotFound
        }
        (StatusCode::TOO_MANY_REQUESTS, Some("consultation.rate_limited")) => {
            LiveJourneyError::ExecuteRateLimited
        }
        (StatusCode::SERVICE_UNAVAILABLE, Some("consultation.unavailable")) => {
            LiveJourneyError::ExecuteUnavailable
        }
        _ => LiveJourneyError::ExecuteRequest,
    }
}

fn validate_public_response(response: &Value) -> Result<(), LiveJourneyError> {
    if response.get("schema").and_then(Value::as_str)
        != Some("registry.relay.consultation-result.v1")
        || response.pointer("/profile/id").and_then(Value::as_str) != Some(PROFILE_ID)
        || response.pointer("/profile/version").and_then(Value::as_str) != Some(PROFILE_VERSION)
        || response.get("notary_evaluation_id").and_then(Value::as_str)
            != Some(NOTARY_EVALUATION_ID)
    {
        return Err(LiveJourneyError::ExecuteResponse);
    }
    match response.get("outcome").and_then(Value::as_str) {
        Some("match") => {
            let data = response
                .get("data")
                .and_then(Value::as_object)
                .ok_or(LiveJourneyError::ExecuteResponse)?;
            if data.len() != 1 || !data.contains_key("status") {
                return Err(LiveJourneyError::ExecuteResponse);
            }
            let status = data
                .get("status")
                .and_then(Value::as_str)
                .ok_or(LiveJourneyError::ExecuteResponse)?;
            if status.is_empty() || status.len() > 32 || status.chars().any(char::is_control) {
                return Err(LiveJourneyError::ExecuteResponse);
            }
        }
        _ => return Err(LiveJourneyError::ExecuteResponse),
    }
    Ok(())
}

struct LiveJwksServer {
    signing: SigningKey,
    jwks_url: String,
    task: JoinHandle<()>,
}

impl LiveJwksServer {
    async fn start() -> Result<Self, LiveJourneyError> {
        let signing = SigningKey::generate(&mut OsRng);
        let verifying = signing.verifying_key();
        let jwks = json!({
            "keys": [{
                "kty": "OKP",
                "crv": "Ed25519",
                "use": "sig",
                "alg": "EdDSA",
                "kid": JWT_KID,
                "x": URL_SAFE_NO_PAD.encode(verifying.as_bytes())
            }]
        });
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|_| LiveJourneyError::JwksServer)?;
        let address = listener
            .local_addr()
            .map_err(|_| LiveJourneyError::JwksServer)?;
        let jwks = serde_json::to_vec(&jwks).map_err(|_| LiveJourneyError::JwksServer)?;
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let mut request = [0_u8; 4096];
                let Ok(read) = socket.read(&mut request).await else {
                    continue;
                };
                if read == 0 {
                    continue;
                }
                let response_head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nCache-Control: no-store\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    jwks.len()
                );
                if socket.write_all(response_head.as_bytes()).await.is_ok() {
                    let _ = socket.write_all(&jwks).await;
                }
            }
        });
        Ok(Self {
            signing,
            jwks_url: format!("http://{address}/keys"),
            task,
        })
    }

    fn jwks_url(&self) -> &str {
        &self.jwks_url
    }

    fn mint_bearer(&self) -> Result<Zeroizing<String>, LiveJourneyError> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| LiveJourneyError::TokenMint)?
            .as_secs();
        let claims = json!({
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": NOTARY_PRINCIPAL,
            "azp": NOTARY_PRINCIPAL,
            "iat": now,
            "exp": now + 300,
            "scope": REQUIRED_SCOPE
        });
        let mut header = Header::new(Algorithm::EdDSA);
        header.kid = Some(JWT_KID.to_string());
        header.typ = Some("at+jwt".to_string());
        let private = self
            .signing
            .to_pkcs8_der()
            .map_err(|_| LiveJourneyError::TokenMint)?;
        let key = EncodingKey::from_ed_der(private.as_bytes());
        encode(&header, &claims, &key)
            .map(Zeroizing::new)
            .map_err(|_| LiveJourneyError::TokenMint)
    }
}

impl Drop for LiveJwksServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct StagedProfile {
    _directory: TempDir,
    config_path: PathBuf,
}

impl StagedProfile {
    fn new(
        dhis2_base_url: &str,
        postgres_ca_path: &Path,
        jwks_url: &str,
    ) -> Result<Self, LiveJourneyError> {
        let directory = tempfile::tempdir().map_err(|_| LiveJourneyError::ArtifactStaging)?;
        let source_root = Path::new(env!("CARGO_MANIFEST_DIR")).join(PROFILE_DIRECTORY);
        let evidence_directory = directory.path().join("evidence");
        fs::create_dir(&evidence_directory).map_err(|_| LiveJourneyError::ArtifactStaging)?;

        copy_artifact(
            &source_root.join(PUBLIC_CONTRACT_FILE),
            &directory.path().join("public-contract.json"),
        )?;
        copy_artifact(
            &source_root.join(INTEGRATION_PACK_FILE),
            &directory.path().join("integration-pack.json"),
        )?;
        copy_artifact(
            &source_root.join(CONFORMANCE_FILE),
            &evidence_directory.join("conformance.json"),
        )?;
        copy_artifact(
            &source_root.join(NEGATIVE_SECURITY_FILE),
            &evidence_directory.join("negative-security.json"),
        )?;
        copy_artifact(
            &source_root.join(MINIMIZATION_FILE),
            &evidence_directory.join("minimization.json"),
        )?;

        let binding = live_private_binding(dhis2_base_url)?;
        let binding_bytes =
            serde_json::to_vec_pretty(&binding).map_err(|_| LiveJourneyError::ArtifactStaging)?;
        let binding_path = directory.path().join("private-binding.json");
        fs::write(&binding_path, &binding_bytes).map_err(|_| LiveJourneyError::ArtifactStaging)?;
        let binding_sha = sha256_uri(&binding_bytes);

        // Start from the maintained operator example, then replace only the
        // deployment-private values needed by this disposable proof. The real
        // loader below therefore catches drift in the documented baseline,
        // including every maintained artifact pin.
        let mut yaml = fs::read_to_string(source_root.join(CONFIG_EXAMPLE_FILE))
            .map_err(|_| LiveJourneyError::ArtifactStaging)?;
        replace_once(
            &mut yaml,
            r#"    issuer: "https://identity.example.gov""#,
            &format!("    issuer: {}", yaml_string(ISSUER)?),
        )?;
        replace_once(
            &mut yaml,
            r#"    jwks_url: "https://identity.example.gov/.well-known/jwks.json""#,
            &format!(
                "    jwks_url: {}\n    allow_dev_insecure_fetch_urls: true",
                yaml_string(jwks_url)?
            ),
        )?;
        replace_once(
            &mut yaml,
            "    database_url_env: REGISTRY_RELAY_CONSULTATION_DATABASE_URL",
            &format!(
                "    database_url_env: REGISTRY_RELAY_CONSULTATION_DATABASE_URL\n    root_certificate_path: {}",
                yaml_string(
                    postgres_ca_path
                        .to_str()
                        .ok_or(LiveJourneyError::ArtifactStaging)?
                )?
            ),
        )?;
        let example_binding_bytes = fs::read(source_root.join("private-binding.example.json"))
            .map_err(|_| LiveJourneyError::ArtifactStaging)?;
        let example_binding_reference = format!(
            "      - path: private-binding.example.json\n        sha256: {}",
            sha256_uri(&example_binding_bytes)
        );
        replace_once(
            &mut yaml,
            &example_binding_reference,
            &format!("      - path: private-binding.json\n        sha256: {binding_sha}"),
        )?;

        let config_path = directory.path().join("relay.yaml");
        fs::write(&config_path, yaml).map_err(|_| LiveJourneyError::ArtifactStaging)?;
        Ok(Self {
            _directory: directory,
            config_path,
        })
    }
}

fn live_private_binding(dhis2_base_url: &str) -> Result<Value, LiveJourneyError> {
    let parsed = Url::parse(dhis2_base_url).map_err(|_| LiveJourneyError::InvalidDhis2BaseUrl)?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(LiveJourneyError::InvalidDhis2BaseUrl);
    }
    let base_path = parsed.path().trim_end_matches('/');
    let application_base_path = (!base_path.is_empty()).then(|| base_path.to_string());
    let mut origin = parsed;
    origin.set_path("/");
    origin.set_query(None);
    origin.set_fragment(None);

    // The authorized public test endpoint has a usable A path but no reliable
    // AAAA response. Make that deployment fact explicit and hash-covered;
    // production bindings otherwise retain the strict dual-stack default.
    let mut destination = Map::from_iter([
        ("id".to_string(), json!("dhis2-live-data")),
        ("origin".to_string(), json!(origin.as_str())),
        ("dns_family".to_string(), json!("ipv4_only")),
        ("allowed_private_cidrs".to_string(), json!([])),
    ]);
    if let Some(path) = application_base_path {
        destination.insert("application_base_path".to_string(), json!(path));
    }
    Ok(json!({
        "profile": {"id": PROFILE_ID, "version": PROFILE_VERSION},
        "integration_pack": {"id": "dhis2.tracker.enrollment-status", "version": "1", "hash": PACK_HASH},
        "tenant": "live-test",
        "registry_instance": "dhis2-live",
        "source_instance": "tracker-api",
        "data_destination": destination,
        "credential_destination": null,
        "credential": {"ref": "dhis2-basic-reader", "generation": 1},
        "deployment_parameters": {},
        "limits": {
            "max_source_bytes": 8192,
            "timeout_ms": 5000,
            "max_in_flight": 1,
            "quota_per_minute": 10,
            "quota_burst": 2,
            "max_public_response_bytes": 4096
        },
        "capabilities": {"allow_sandboxed_rhai": false}
    }))
}

struct LiveDatabase {
    admin: Client,
    admin_driver: JoinHandle<Result<(), tokio_postgres::Error>>,
    owner_role: String,
    runtime_role: String,
    maintenance_role: String,
    reader_role: String,
}

struct ProvisionedDatabaseUrls {
    runtime: Zeroizing<String>,
    maintenance: Zeroizing<String>,
    reader: Zeroizing<String>,
}

impl LiveDatabase {
    /// Provision only the DBA-owned database identities. The public operator
    /// workflow below remains the sole installer and keyring initializer.
    async fn provision(
        admin_database_url: &str,
        postgres_ca_path: &Path,
    ) -> Result<(Self, ProvisionedDatabaseUrls), LiveJourneyError> {
        let admin_config: PostgresConfig = admin_database_url
            .parse()
            .map_err(|_| LiveJourneyError::PostgresUnavailable)?;
        let (admin, admin_driver) = connect_postgres(admin_config, postgres_ca_path).await?;

        let owner_role = role_name("owner");
        let runtime_role = role_name("runtime");
        let maintenance_role = role_name("maintenance");
        let reader_role = role_name("reader");
        let runtime_password = random_password();
        let maintenance_password = random_password();
        let reader_password = random_password();
        let database_name: String = admin
            .query_one("SELECT current_database()", &[])
            .await
            .map_err(|_| LiveJourneyError::PostgresUnavailable)?
            .try_get(0)
            .map_err(|_| LiveJourneyError::PostgresUnavailable)?;
        let role_sql = format!(
            "CREATE ROLE {owner} NOLOGIN NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;\
             CREATE ROLE {runtime} LOGIN PASSWORD {runtime_password} NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;\
             CREATE ROLE {maintenance} LOGIN PASSWORD {maintenance_password} NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;\
             CREATE ROLE {reader} LOGIN PASSWORD {reader_password} NOSUPERUSER NOCREATEROLE NOCREATEDB NOREPLICATION NOBYPASSRLS;\
             GRANT CREATE ON DATABASE {database} TO {owner};",
            owner = quote_identifier(&owner_role),
            runtime = quote_identifier(&runtime_role),
            maintenance = quote_identifier(&maintenance_role),
            reader = quote_identifier(&reader_role),
            runtime_password = quote_literal(runtime_password.as_str()),
            maintenance_password = quote_literal(maintenance_password.as_str()),
            reader_password = quote_literal(reader_password.as_str()),
            database = quote_identifier(&database_name),
        );
        admin
            .batch_execute(&role_sql)
            .await
            .map_err(|_| LiveJourneyError::StatePlaneInstall)?;
        let urls = ProvisionedDatabaseUrls {
            runtime: database_url_for_role(
                admin_database_url,
                &runtime_role,
                runtime_password.as_str(),
            )?,
            maintenance: database_url_for_role(
                admin_database_url,
                &maintenance_role,
                maintenance_password.as_str(),
            )?,
            reader: database_url_for_role(
                admin_database_url,
                &reader_role,
                reader_password.as_str(),
            )?,
        };
        Ok((
            Self {
                admin,
                admin_driver,
                owner_role,
                runtime_role,
                maintenance_role,
                reader_role,
            },
            urls,
        ))
    }

    fn owner_role(&self) -> &str {
        &self.owner_role
    }

    async fn classify_safe_execute_failure(&mut self) -> LiveJourneyError {
        let rows = match self
            .admin
            .query(
                r#"
SELECT
    record_json::jsonb #>> '{payload,outcome}' AS completion_outcome,
    record_json::jsonb #>>
        '{payload,completion_facts,execution_result,class}' AS result_class,
    record_json::jsonb #>>
        '{payload,completion_facts,execution_result,failure_class}' AS failure_class
FROM relay_state_private.audit_phase
WHERE stream_kind = 'consultation' AND phase = 'completion'
"#,
                &[],
            )
            .await
        {
            Ok(rows) => rows,
            Err(_) => return LiveJourneyError::ExecuteUnavailable,
        };
        let [row] = rows.as_slice() else {
            return if rows.is_empty() {
                LiveJourneyError::ExecuteMissingDurableCompletion
            } else {
                LiveJourneyError::ExecuteUnavailable
            };
        };
        let completion_outcome = match row.try_get::<_, Option<String>>("completion_outcome") {
            Ok(completion_outcome) => completion_outcome,
            Err(_) => return LiveJourneyError::ExecuteUnavailable,
        };
        let result_class = match row.try_get::<_, Option<String>>("result_class") {
            Ok(result_class) => result_class,
            Err(_) => return LiveJourneyError::ExecuteUnavailable,
        };
        let failure_class = match row.try_get::<_, Option<String>>("failure_class") {
            Ok(failure_class) => failure_class,
            Err(_) => return LiveJourneyError::ExecuteUnavailable,
        };
        classify_durable_execute_failure(
            completion_outcome.as_deref(),
            result_class.as_deref(),
            failure_class.as_deref(),
        )
    }

    async fn assert_safe_durable_evidence(&mut self) -> Result<(), LiveJourneyError> {
        let row = self
            .admin
            .query_one(
                r#"
WITH consultation_audit AS (
    SELECT phase, record_json::jsonb AS record
    FROM relay_state_private.audit_phase
    WHERE stream_kind = 'consultation'
), permits AS (
    SELECT kind, dispatched_at IS NOT NULL AS dispatched,
           completion_operation_id = operation_id
             AND completion_phase = 'completion'
             AND completion_envelope_id IS NOT NULL
             AND completion_record_hash IS NOT NULL AS completion_linked
    FROM relay_state_private.dispatch_permit
)
SELECT
    (SELECT count(*) FROM consultation_audit WHERE phase = 'attempt') AS attempt_count,
    (SELECT count(*) FROM consultation_audit WHERE phase = 'completion') AS completion_count,
    (SELECT min(record #>> '{payload,completion_facts,execution_result,class}')
       FROM consultation_audit WHERE phase = 'completion') AS completion_class,
    (SELECT min(record #>> '{payload,completion_facts,execution_result,outcome}')
       FROM consultation_audit WHERE phase = 'completion') AS completion_public_outcome,
    (SELECT min(record #>> '{payload,outcome}')
       FROM consultation_audit WHERE phase = 'completion') AS completion_disposition,
    (SELECT max((record #>> '{payload,completion_facts,actual_credential_exchanges}')::bigint)
       FROM consultation_audit WHERE phase = 'completion') AS actual_credential_exchanges,
    (SELECT max((record #>> '{payload,completion_facts,actual_data_exchanges}')::bigint)
       FROM consultation_audit WHERE phase = 'completion') AS actual_data_exchanges,
    (SELECT bool_and(
         record #> '{payload,completion_facts,actual_path}' =
         '[{"kind":"data","ordinal":0,"operation_id":"lookup-enrollment-status"}]'::jsonb
       ) FROM consultation_audit WHERE phase = 'completion') AS actual_path_matches,
    (SELECT count(*) FROM permits) AS total_permit_count,
    (SELECT count(*) FROM permits WHERE kind = 'data') AS data_permit_count,
    (SELECT count(*) FROM permits
       WHERE kind = 'data' AND dispatched AND completion_linked) AS linked_dispatch_count,
    (SELECT count(*) FROM relay_state_private.consultation_completion_intent
       WHERE state = 'completed') AS completed_intent_count
"#,
                &[],
            )
            .await
            .map_err(|_| LiveJourneyError::DurableEvidence)?;
        let evidence = (
            row.try_get::<_, i64>("attempt_count")
                .map_err(|_| LiveJourneyError::DurableEvidence)?,
            row.try_get::<_, i64>("completion_count")
                .map_err(|_| LiveJourneyError::DurableEvidence)?,
            row.try_get::<_, Option<String>>("completion_class")
                .map_err(|_| LiveJourneyError::DurableEvidence)?,
            row.try_get::<_, Option<String>>("completion_public_outcome")
                .map_err(|_| LiveJourneyError::DurableEvidence)?,
            row.try_get::<_, Option<String>>("completion_disposition")
                .map_err(|_| LiveJourneyError::DurableEvidence)?,
            row.try_get::<_, Option<i64>>("actual_credential_exchanges")
                .map_err(|_| LiveJourneyError::DurableEvidence)?,
            row.try_get::<_, Option<i64>>("actual_data_exchanges")
                .map_err(|_| LiveJourneyError::DurableEvidence)?,
            row.try_get::<_, Option<bool>>("actual_path_matches")
                .map_err(|_| LiveJourneyError::DurableEvidence)?,
            row.try_get::<_, i64>("total_permit_count")
                .map_err(|_| LiveJourneyError::DurableEvidence)?,
            row.try_get::<_, i64>("data_permit_count")
                .map_err(|_| LiveJourneyError::DurableEvidence)?,
            row.try_get::<_, i64>("linked_dispatch_count")
                .map_err(|_| LiveJourneyError::DurableEvidence)?,
            row.try_get::<_, i64>("completed_intent_count")
                .map_err(|_| LiveJourneyError::DurableEvidence)?,
        );
        if evidence
            != (
                1,
                1,
                Some("public_success".to_string()),
                Some("match".to_string()),
                Some("known_complete".to_string()),
                Some(0),
                Some(1),
                Some(true),
                1,
                1,
                1,
                1,
            )
        {
            return Err(LiveJourneyError::DurableEvidence);
        }
        Ok(())
    }

    async fn cleanup(self) -> Result<(), LiveJourneyError> {
        let cleanup_sql = format!(
            "DROP SCHEMA IF EXISTS relay_state_api CASCADE;\
             DROP SCHEMA IF EXISTS relay_state_private CASCADE;\
             DROP OWNED BY {runtime}, {maintenance}, {reader}, {owner};\
             DROP ROLE {runtime}, {maintenance}, {reader}, {owner};",
            runtime = quote_identifier(&self.runtime_role),
            maintenance = quote_identifier(&self.maintenance_role),
            reader = quote_identifier(&self.reader_role),
            owner = quote_identifier(&self.owner_role),
        );
        let result = self
            .admin
            .batch_execute(&cleanup_sql)
            .await
            .map_err(|_| LiveJourneyError::PostgresCleanup);
        drop(self.admin);
        self.admin_driver.abort();
        result
    }
}

fn classify_durable_execute_failure(
    completion_outcome: Option<&str>,
    result_class: Option<&str>,
    failure_class: Option<&str>,
) -> LiveJourneyError {
    match (completion_outcome, result_class, failure_class) {
        (Some("known_complete"), Some("known_failure"), Some("credential_unavailable")) => {
            LiveJourneyError::ExecuteSourceCredentialsUnavailable
        }
        (Some("known_complete"), Some("known_failure"), Some("source_unavailable")) => {
            LiveJourneyError::ExecuteSourceUnavailable
        }
        (Some("known_complete"), Some("known_failure"), Some("response_contract_violation")) => {
            LiveJourneyError::ExecuteResponseContractViolation
        }
        (Some("known_complete"), Some("known_failure"), Some("cardinality_violation")) => {
            LiveJourneyError::ExecuteCardinalityViolation
        }
        (Some("not_started"), None, None) => LiveJourneyError::ExecuteClosedBeforeSourceDispatch,
        (Some("outcome_unknown"), None, None) => LiveJourneyError::ExecuteClosedAfterSourceDispatch,
        _ => LiveJourneyError::ExecuteUnavailable,
    }
}

async fn connect_postgres(
    config: PostgresConfig,
    ca_path: &Path,
) -> Result<(Client, JoinHandle<Result<(), tokio_postgres::Error>>), LiveJourneyError> {
    let pem = fs::read(ca_path).map_err(|_| LiveJourneyError::InvalidPostgresTls)?;
    let certificate = native_tls::Certificate::from_pem(&pem)
        .map_err(|_| LiveJourneyError::InvalidPostgresTls)?;
    let mut builder = native_tls::TlsConnector::builder();
    builder.add_root_certificate(certificate);
    let connector = MakeTlsConnector::new(
        builder
            .build()
            .map_err(|_| LiveJourneyError::InvalidPostgresTls)?,
    );
    let (client, connection) = config
        .connect(connector)
        .await
        .map_err(|_| LiveJourneyError::PostgresUnavailable)?;
    let driver = tokio::spawn(connection);
    Ok((client, driver))
}

fn database_url_for_role(
    admin_database_url: &str,
    role: &str,
    password: &str,
) -> Result<Zeroizing<String>, LiveJourneyError> {
    let mut url =
        Url::parse(admin_database_url).map_err(|_| LiveJourneyError::PostgresUnavailable)?;
    url.set_username(role)
        .map_err(|_| LiveJourneyError::PostgresUnavailable)?;
    url.set_password(Some(password))
        .map_err(|_| LiveJourneyError::PostgresUnavailable)?;
    Ok(Zeroizing::new(url.to_string()))
}

fn current_unix_ms() -> Result<i64, LiveJourneyError> {
    i64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| LiveJourneyError::PseudonymInitialization)?
            .as_millis(),
    )
    .map_err(|_| LiveJourneyError::PseudonymInitialization)
}

fn copy_artifact(source: &Path, destination: &Path) -> Result<(), LiveJourneyError> {
    let bytes = fs::read(source).map_err(|_| LiveJourneyError::ArtifactStaging)?;
    fs::write(destination, &bytes).map_err(|_| LiveJourneyError::ArtifactStaging)?;
    Ok(())
}

fn sha256_uri(bytes: &[u8]) -> String {
    use std::fmt::Write as _;

    let digest = Sha256::digest(bytes);
    let mut encoded = String::with_capacity("sha256:".len() + digest.len() * 2);
    encoded.push_str("sha256:");
    for byte in digest {
        write!(&mut encoded, "{byte:02x}").expect("writing to a string cannot fail");
    }
    encoded
}

fn yaml_string(value: &str) -> Result<String, LiveJourneyError> {
    serde_json::to_string(value).map_err(|_| LiveJourneyError::ArtifactStaging)
}

fn replace_once(
    document: &mut String,
    expected: &str,
    replacement: &str,
) -> Result<(), LiveJourneyError> {
    if document.match_indices(expected).count() != 1 {
        return Err(LiveJourneyError::ArtifactStaging);
    }
    *document = document.replacen(expected, replacement, 1);
    Ok(())
}

fn required_secret_environment(name: &'static str) -> Result<Zeroizing<String>, LiveJourneyError> {
    let value = env::var(name).map_err(|_| LiveJourneyError::MissingEnvironment(name))?;
    if value.is_empty() {
        return Err(LiveJourneyError::MissingEnvironment(name));
    }
    Ok(Zeroizing::new(value))
}

fn required_path_environment(name: &'static str) -> Result<PathBuf, LiveJourneyError> {
    let value = env::var_os(name).ok_or(LiveJourneyError::MissingEnvironment(name))?;
    if value.is_empty() {
        return Err(LiveJourneyError::MissingEnvironment(name));
    }
    Ok(PathBuf::from(value))
}

fn require_nonempty_environment(name: &'static str) -> Result<(), LiveJourneyError> {
    match env::var_os(name) {
        Some(value) if !value.is_empty() => Ok(()),
        _ => Err(LiveJourneyError::MissingEnvironment(name)),
    }
}

#[derive(Default)]
struct ScopedEnvironment {
    previous: Vec<(&'static str, Option<std::ffi::OsString>)>,
}

impl ScopedEnvironment {
    fn set(&mut self, name: &'static str, value: &str) {
        self.previous.push((name, env::var_os(name)));
        env::set_var(name, value);
    }
}

impl Drop for ScopedEnvironment {
    fn drop(&mut self) {
        for (name, value) in self.previous.drain(..).rev() {
            match value {
                Some(value) => env::set_var(name, value),
                None => env::remove_var(name),
            }
        }
    }
}

fn role_name(kind: &str) -> String {
    format!(
        "relay_live_{kind}_{}",
        Ulid::new().to_string().to_ascii_lowercase()
    )
}

fn random_secret() -> Zeroizing<String> {
    Zeroizing::new(format!("{}{}", Ulid::new(), Ulid::new()))
}

fn random_password() -> Zeroizing<String> {
    Zeroizing::new(Ulid::new().to_string())
}

fn quote_identifier(value: &str) -> String {
    format!("\"{}\"", value.replace('"', "\"\""))
}

fn quote_literal(value: &str) -> String {
    format!("'{}'", value.replace('\'', "''"))
}
