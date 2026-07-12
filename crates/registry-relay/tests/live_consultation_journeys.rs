// SPDX-License-Identifier: Apache-2.0
#![cfg(unix)]
//! Explicitly ignored end-to-end proofs for maintained Relay consultation journeys.
//!
//! The companion runner supplies a disposable TLS PostgreSQL 16 database and
//! sources the operator-authorized product credentials. This module never prints
//! a credential, bearer token, source URL, selector, source response, or public
//! response body. Failures retain only the closed test-stage taxonomy below.

use std::{
    env, fs,
    fs::OpenOptions,
    io::Write as _,
    os::unix::fs::OpenOptionsExt as _,
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
use rand_core::{OsRng, RngCore as _};
use registry_notary_server::{compile_notary_runtime, notary_router_from_runtime};
use registry_platform_audit::AuditChainProfile;
use reqwest::Url;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use tempfile::TempDir;
use thiserror::Error;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    sync::watch,
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
    format::FormatRegistry,
    ingest::IngestRegistry,
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
const OPENCRVS_BASE_URL_ENV: &str = "OPENCRVS_DCI_BASE_URL";
const OPENCRVS_CLIENT_ID_ENV: &str = "OPENCRVS_DCI_CLIENT_ID";
const OPENCRVS_CLIENT_SECRET_ENV: &str = "OPENCRVS_DCI_CLIENT_SECRET";
const NOTARY_DHIS2_API_KEY_HASH_ENV: &str = "REGISTRY_NOTARY_DHIS2_API_KEY_HASH";
const NOTARY_OPENCRVS_API_KEY_HASH_ENV: &str = "REGISTRY_NOTARY_OPENCRVS_API_KEY_HASH";
const NOTARY_SYNTHETIC_API_KEY_HASH_ENV: &str = "REGISTRY_NOTARY_SYNTHETIC_SNAPSHOT_API_KEY_HASH";
const NOTARY_AUDIT_SECRET_ENV: &str = "REGISTRY_NOTARY_AUDIT_HASH_SECRET";

const PROFILE_VERSION: &str = "1";
const ISSUER: &str = "https://relay-live-issuer.example.test";
const AUDIENCE: &str = "relay-consultation";
const NOTARY_PRINCIPAL: &str = "registry-notary";
const JWT_KID: &str = "relay-live-consultation-ed25519";
const PSEUDONYM_KEY_ID: &str = "epoch-1";

const CONFIG_EXAMPLE_FILE: &str = "relay-config.example.yaml";
const NOTARY_CONFIG_EXAMPLE_FILE: &str = "notary-config.example.yaml";
const PUBLIC_CONTRACT_FILE: &str = "public-contract.json";
const INTEGRATION_PACK_FILE: &str = "integration-pack.json";
const CONFORMANCE_FILE: &str = "evidence/conformance.json";
const NEGATIVE_SECURITY_FILE: &str = "evidence/negative-security.json";
const MINIMIZATION_FILE: &str = "evidence/minimization.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum JourneyProfile {
    Dhis2,
    OpenCrvs,
    SyntheticSnapshot,
}

impl JourneyProfile {
    fn directory(self) -> &'static str {
        match self {
            Self::Dhis2 => "profiles/dhis2-2.41.9-enrollment-status",
            Self::OpenCrvs => "profiles/opencrvs-1.9.0-rc.1-farajaland-birth-record-exists",
            Self::SyntheticSnapshot => "profiles/synthetic-snapshot-exact-person-status",
        }
    }

    fn profile_id(self) -> &'static str {
        match self {
            Self::Dhis2 => "dhis2.tracker.enrollment-status.exact",
            Self::OpenCrvs => "opencrvs.dci.farajaland.birth-record-exists.exact",
            Self::SyntheticSnapshot => "synthetic.snapshot.person-status.exact",
        }
    }

    fn purpose(self) -> &'static str {
        match self {
            Self::Dhis2 => "program-enrollment-verification",
            Self::OpenCrvs => "civil-registration-verification",
            Self::SyntheticSnapshot => "benefit-status-verification",
        }
    }

    fn required_scope(self) -> &'static str {
        match self {
            Self::Dhis2 => "registry:consult:dhis2-enrollment-status",
            Self::OpenCrvs => "registry:consult:opencrvs-birth-record",
            Self::SyntheticSnapshot => "registry:consult:synthetic-snapshot-person-status",
        }
    }

    fn notary_api_key_hash_env(self) -> &'static str {
        match self {
            Self::Dhis2 => NOTARY_DHIS2_API_KEY_HASH_ENV,
            Self::OpenCrvs => NOTARY_OPENCRVS_API_KEY_HASH_ENV,
            Self::SyntheticSnapshot => NOTARY_SYNTHETIC_API_KEY_HASH_ENV,
        }
    }

    fn pack_id(self) -> &'static str {
        match self {
            Self::Dhis2 => "dhis2.tracker.enrollment-status",
            Self::OpenCrvs => "opencrvs.dci.farajaland.birth-record-exists",
            Self::SyntheticSnapshot => "synthetic.snapshot.person-status",
        }
    }

    fn pack_hash(self) -> &'static str {
        match self {
            Self::Dhis2 => {
                "sha256:ec0136be504e3f98539f9e0ec10e59532ff793dbadc2e66ea1c017a632da6ac4"
            }
            Self::OpenCrvs => {
                "sha256:04297b0429cf311c79dedd332f45d1fd7ee9d9e4b56d2c77d793fdeeeeb986aa"
            }
            Self::SyntheticSnapshot => {
                "sha256:cc490a9b51255611f3dc3b529952a185c22a32c260644b095d6b3bf6ac52fab6"
            }
        }
    }

    fn source_environment(self) -> Option<[&'static str; 2]> {
        match self {
            Self::Dhis2 => Some([DHIS2_USERNAME_ENV, DHIS2_PASSWORD_ENV]),
            Self::OpenCrvs => Some([OPENCRVS_CLIENT_ID_ENV, OPENCRVS_CLIENT_SECRET_ENV]),
            Self::SyntheticSnapshot => None,
        }
    }

    fn selector(self) -> Zeroizing<String> {
        match self {
            Self::Dhis2 => Zeroizing::new("PQfMcpmXeFE".to_string()),
            Self::OpenCrvs => Zeroizing::new(format!("{:010}", OsRng.next_u64() % 10_000_000_000)),
            Self::SyntheticSnapshot => Zeroizing::new("per-2001".to_string()),
        }
    }
}

#[derive(Debug, Clone, Copy, Error, PartialEq, Eq)]
enum LiveJourneyError {
    #[error("required live-test environment is unavailable: {0}")]
    MissingEnvironment(&'static str),
    #[error("the authorized source base URL is invalid")]
    InvalidSourceBaseUrl,
    #[error("the disposable PostgreSQL trust configuration is invalid")]
    InvalidPostgresTls,
    #[error("the disposable PostgreSQL database is unavailable")]
    PostgresUnavailable,
    #[error("the disposable PostgreSQL role installation failed")]
    StatePlaneInstall,
    #[error("the disposable PostgreSQL pseudonym epoch initialization failed")]
    PseudonymInitialization,
    #[error("the maintained consultation artifacts could not be staged")]
    ArtifactStaging,
    #[error("the maintained consultation runtime configuration did not load")]
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
    #[error("the synthetic snapshot ingest and publication failed")]
    SnapshotIngest,
    #[error("the production protected router could not be assembled")]
    RouterAssembly,
    #[error("the protected Relay listener could not be started")]
    RelayListener,
    #[error("the reloadable Relay workload credential could not be staged")]
    RelayCredentialStaging,
    #[error("the maintained Notary runtime configuration did not load")]
    NotaryConfigLoad,
    #[error("the Notary-to-Relay consultation path could not be activated")]
    NotaryActivation,
    #[error("the activated Notary-to-Relay path was not ready")]
    NotaryReadiness,
    #[error("the Notary evaluation request failed")]
    NotaryRequest,
    #[error("the minimized Notary evaluation response was invalid")]
    NotaryResponse,
    #[error("the restricted Notary audit correlation was invalid")]
    NotaryAudit,
    #[error("Relay reported the live consultation unavailable")]
    ExecuteUnavailable,
    #[error("Relay recorded unavailable source credentials for the live consultation")]
    ExecuteSourceCredentialsUnavailable,
    #[error("Relay recorded the live source as unavailable")]
    ExecuteSourceUnavailable,
    #[error("Relay recorded a live source response-contract violation")]
    ExecuteResponseContractViolation,
    #[error("Relay recorded a live source cardinality violation")]
    ExecuteCardinalityViolation,
    #[error("Relay closed the live consultation before source dispatch")]
    ExecuteClosedBeforeSourceDispatch,
    #[error("Relay closed the live consultation after source dispatch without a known result")]
    ExecuteClosedAfterSourceDispatch,
    #[error("Relay left the live consultation without a terminal durable completion")]
    ExecuteMissingDurableCompletion,
    #[error("the durable consultation evidence did not match the completed journey")]
    DurableEvidence,
    #[error("the concrete consultation service did not shut down cleanly")]
    ConsultationShutdown,
    #[error("the disposable PostgreSQL state could not be cleaned up")]
    PostgresCleanup,
}

/// Run via `scripts/run-live-consultation-journey.sh dhis2`. The test stays ignored so
/// ordinary CI and developer test runs never contact a live registry.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires the explicit live DHIS2 runner and a disposable TLS PostgreSQL 16 instance"]
async fn live_dhis2_consultation_lifecycle() {
    if let Err(error) = run_live_consultation_lifecycle(JourneyProfile::Dhis2).await {
        panic!("live DHIS2 consultation lifecycle failed: {error}");
    }
}

/// Run via `scripts/run-live-consultation-journey.sh opencrvs`. A fresh random valid
/// UIN is used only in memory and is expected to produce a closed `no_match`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires the explicit live OpenCRVS runner and a disposable TLS PostgreSQL 16 instance"]
async fn live_opencrvs_consultation_no_match_lifecycle() {
    if let Err(error) = run_live_consultation_lifecycle(JourneyProfile::OpenCrvs).await {
        panic!("live OpenCRVS consultation lifecycle failed: {error}");
    }
}

/// Run via `scripts/run-live-consultation-journey.sh synthetic`. The source fixture is
/// repository-owned; only the disposable TLS PostgreSQL state plane is external.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires the explicit synthetic runner and a disposable TLS PostgreSQL 16 instance"]
async fn synthetic_snapshot_exact_consultation_lifecycle() {
    if let Err(error) = run_live_consultation_lifecycle(JourneyProfile::SyntheticSnapshot).await {
        panic!("synthetic SnapshotExact consultation lifecycle failed: {error}");
    }
}

#[test]
fn maintained_operator_example_stages_through_real_loader() {
    for (profile, source_url) in [
        (
            JourneyProfile::Dhis2,
            "https://dhis2.example.test/stable-2-41-9",
        ),
        (JourneyProfile::OpenCrvs, "https://opencrvs.example.test"),
        (JourneyProfile::SyntheticSnapshot, ""),
    ] {
        let staged = StagedProfile::new(
            profile,
            source_url,
            Path::new("/tmp/registry-relay-live-test-ca.pem"),
            "http://127.0.0.1:1/keys",
        )
        .unwrap_or_else(|_| panic!("the maintained operator example did not stage"));
        let loaded = config::load_with_metadata(&staged.config_path)
            .unwrap_or_else(|_| panic!("the staged maintained operator example did not load"));
        assert!(loaded.runtime.consultation.is_some());
        assert!(loaded.consultation_artifacts.is_some());
    }
}

#[test]
fn maintained_notary_example_loads_and_validates() {
    for profile in [
        JourneyProfile::Dhis2,
        JourneyProfile::OpenCrvs,
        JourneyProfile::SyntheticSnapshot,
    ] {
        let path = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join(profile.directory())
            .join(NOTARY_CONFIG_EXAMPLE_FILE);
        let yaml = fs::read_to_string(path)
            .unwrap_or_else(|_| panic!("the maintained Notary operator example was not readable"));
        let config: registry_notary_core::StandaloneRegistryNotaryConfig =
            serde_norway::from_str(&yaml)
                .unwrap_or_else(|_| panic!("the maintained Notary operator example did not parse"));
        config
            .validate()
            .unwrap_or_else(|_| panic!("the maintained Notary operator example did not validate"));
    }
}

#[test]
fn durable_failure_diagnostics_remain_closed_and_exact() {
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

async fn run_live_consultation_lifecycle(profile: JourneyProfile) -> Result<(), LiveJourneyError> {
    let (source_principal, source_secret, source_base_url) = match profile.source_environment() {
        Some([source_principal_env, source_secret_env]) => {
            for name in [source_principal_env, source_secret_env] {
                require_nonempty_environment(name)?;
            }
            let source_base_url = required_secret_environment(match profile {
                JourneyProfile::Dhis2 => DHIS2_BASE_URL_ENV,
                JourneyProfile::OpenCrvs => OPENCRVS_BASE_URL_ENV,
                JourneyProfile::SyntheticSnapshot => unreachable!("synthetic source is local"),
            })?;
            (
                required_secret_environment(source_principal_env)?,
                required_secret_environment(source_secret_env)?,
                source_base_url,
            )
        }
        None => (
            Zeroizing::new("repository-owned-fixture".to_string()),
            Zeroizing::new("no-source-credential".to_string()),
            Zeroizing::new("local-snapshot-materialization".to_string()),
        ),
    };
    let admin_database_url = required_secret_environment(ADMIN_DATABASE_URL_ENV)?;
    let postgres_ca_path = required_path_environment(POSTGRES_CA_PATH_ENV)?;

    let jwks = LiveJwksServer::start().await?;
    let mut environment = ScopedEnvironment::default();
    let audit_secret = random_secret();
    let pseudonym_secret = random_secret();
    let notary_audit_secret = random_secret();
    let notary_api_key = random_secret();
    let notary_api_key_hash = sha256_uri(notary_api_key.as_bytes());
    environment.set(AUDIT_SECRET_ENV, audit_secret.as_str());
    environment.set(PSEUDONYM_SECRET_ENV, pseudonym_secret.as_str());
    environment.set(NOTARY_AUDIT_SECRET_ENV, notary_audit_secret.as_str());
    environment.set(profile.notary_api_key_hash_env(), &notary_api_key_hash);

    let (mut database, database_urls) =
        LiveDatabase::provision(admin_database_url.as_str(), postgres_ca_path.as_path()).await?;
    environment.set(RUNTIME_DATABASE_URL_ENV, database_urls.runtime.as_str());
    environment.set(
        MAINTENANCE_DATABASE_URL_ENV,
        database_urls.maintenance.as_str(),
    );
    environment.set(READER_DATABASE_URL_ENV, database_urls.reader.as_str());

    let execution = async {
        let staged = StagedProfile::new(
            profile,
            source_base_url.as_str(),
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
        let datafusion = Arc::new(datafusion::execution::context::SessionContext::new());
        let service = ConsultationService::activate(
            config.as_ref(),
            artifacts,
            chain_profile.hasher(),
            Arc::clone(&datafusion),
        )
        .await
        .map_err(|_| LiveJourneyError::ConsultationActivation)?;
        let ingest = Arc::new(
            IngestRegistry::from_config(
                config.as_ref(),
                Arc::new(FormatRegistry::with_v1_defaults()),
                Arc::from(config.server.cache_dir.as_path()),
                datafusion,
            )
            .map_err(|_| LiveJourneyError::SnapshotIngest)?,
        );
        service
            .bind_ingest_registry(ingest.as_ref())
            .map_err(|_| LiveJourneyError::SnapshotIngest)?;
        let (ingest_tx, _ingest_rx) = watch::channel(ingest.snapshot());
        ingest.run_initial_ingest(ingest_tx).await;
        if profile == JourneyProfile::SyntheticSnapshot && !ingest.snapshot().fully_ready() {
            return Err(LiveJourneyError::SnapshotIngest);
        }
        let service_execution = async {
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
            let bearer = jwks.mint_bearer(profile)?;
            let relay_token_file = staged.stage_relay_token(bearer.as_str())?;
            let notary_audit_path = staged.notary_audit_path();
            let relay = LiveRelayServer::start(app).await?;
            let notary_config = staged.load_notary_config(
                profile,
                relay.base_url(),
                &relay_token_file,
                &notary_audit_path,
            )?;
            let notary_runtime = compile_notary_runtime(notary_config)
                .map_err(|_| LiveJourneyError::NotaryActivation)?
                .activate_relay()
                .await
                .map_err(|_| LiveJourneyError::NotaryActivation)?;
            let notary_app = notary_router_from_runtime(notary_runtime)
                .map_err(|_| LiveJourneyError::NotaryActivation)?;
            assert_notary_relay_ready(notary_app.clone()).await?;

            let journey = execute_notary_journey(
                profile,
                notary_app,
                &JourneySensitiveValues {
                    source_base_url: source_base_url.as_str(),
                    notary_api_key: notary_api_key.as_str(),
                    relay_bearer: bearer.as_str(),
                    source_principal: source_principal.as_str(),
                    source_secret: source_secret.as_str(),
                },
                &notary_audit_path,
            )
            .await;
            let closed_diagnostic = if journey.is_err() {
                match database.classify_safe_execute_failure().await {
                    LiveJourneyError::ExecuteMissingDurableCompletion
                    | LiveJourneyError::ExecuteUnavailable => None,
                    diagnostic => Some(diagnostic),
                }
            } else {
                None
            };
            drop(relay);
            Ok((journey, closed_diagnostic))
        };
        let service_execution = service_execution.await;
        let shutdown = service
            .shutdown()
            .await
            .map_err(|_| LiveJourneyError::ConsultationShutdown);
        drop(service);
        let (journey, closed_diagnostic) = service_execution?;
        let durable_evidence = match (&journey, &shutdown) {
            (Ok(correlation), Ok(())) => {
                database
                    .assert_safe_durable_evidence(profile, correlation)
                    .await
            }
            _ => Ok(()),
        };
        let journey = closed_diagnostic.map_or(journey, Err);
        journey?;
        shutdown?;
        durable_evidence
    }
    .await;
    let cleanup = database.cleanup().await;
    drop(jwks);

    execution?;
    cleanup
}

async fn assert_notary_relay_ready(app: Router) -> Result<(), LiveJourneyError> {
    let request = Request::builder()
        .method(Method::GET)
        .uri("/ready")
        .body(Body::empty())
        .map_err(|_| LiveJourneyError::NotaryReadiness)?;
    let response = app
        .oneshot(request)
        .await
        .map_err(|_| LiveJourneyError::NotaryReadiness)?;
    if response.status() != StatusCode::OK && response.status() != StatusCode::SERVICE_UNAVAILABLE {
        return Err(LiveJourneyError::NotaryReadiness);
    }
    let body = to_bytes(response.into_body(), 16 * 1024)
        .await
        .map_err(|_| LiveJourneyError::NotaryReadiness)?;
    let body: Value =
        serde_json::from_slice(&body).map_err(|_| LiveJourneyError::NotaryReadiness)?;
    let overall_usable = body.get("status").and_then(Value::as_str) == Some("ready")
        || body.get("readiness_status").and_then(Value::as_str) == Some("degraded");
    if !overall_usable
        || body.pointer("/checks/failed").and_then(Value::as_u64) != Some(0)
        || body.pointer("/checks/relay/total").and_then(Value::as_u64) != Some(1)
        || body.pointer("/checks/relay/ok").and_then(Value::as_u64) != Some(1)
        || body.pointer("/checks/relay/failed").and_then(Value::as_u64) != Some(0)
    {
        return Err(LiveJourneyError::NotaryReadiness);
    }
    Ok(())
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

struct JourneyCorrelation {
    evaluation_id: String,
    consultation_id: String,
    selector: Zeroizing<String>,
    source_base_url: Zeroizing<String>,
    notary_api_key: Zeroizing<String>,
    relay_bearer: Zeroizing<String>,
    source_principal: Zeroizing<String>,
    source_secret: Zeroizing<String>,
}

struct JourneySensitiveValues<'a> {
    source_base_url: &'a str,
    notary_api_key: &'a str,
    relay_bearer: &'a str,
    source_principal: &'a str,
    source_secret: &'a str,
}

async fn execute_notary_journey(
    profile: JourneyProfile,
    app: Router,
    sensitive: &JourneySensitiveValues<'_>,
    audit_path: &Path,
) -> Result<JourneyCorrelation, LiveJourneyError> {
    let selector = profile.selector();
    let api_key_header = HeaderValue::from_str(sensitive.notary_api_key)
        .map_err(|_| LiveJourneyError::NotaryRequest)?;
    let request = Request::builder()
        .method(Method::POST)
        .uri("/v1/evaluations")
        .header("x-api-key", api_key_header)
        .header(header::CONTENT_TYPE, "application/json")
        .header("data-purpose", profile.purpose())
        .body(Body::from(
            serde_json::to_vec(&json!({
                "target": {"type": "person", "id": selector.as_str()},
                "claims": match profile {
                    JourneyProfile::Dhis2 => json!([
                        {"id": "dhis2-enrollment-known", "version": "1"},
                        {"id": "dhis2-enrollment-status", "version": "1"}
                    ]),
                    JourneyProfile::OpenCrvs => json!([
                        {"id": "opencrvs-birth-record-exists", "version": "1"}
                    ]),
                    JourneyProfile::SyntheticSnapshot => json!([
                        {"id": "synthetic-person-known", "version": "1"},
                        {"id": "synthetic-person-status", "version": "1"}
                    ]),
                },
                "disclosure": "value",
                "purpose": profile.purpose()
            }))
            .map_err(|_| LiveJourneyError::NotaryRequest)?,
        ))
        .map_err(|_| LiveJourneyError::NotaryRequest)?;
    let response = app
        .oneshot(request)
        .await
        .map_err(|_| LiveJourneyError::NotaryRequest)?;
    if response.status() != StatusCode::OK {
        return Err(LiveJourneyError::NotaryRequest);
    }
    let body = to_bytes(response.into_body(), 128 * 1024)
        .await
        .map_err(|_| LiveJourneyError::NotaryResponse)?;
    let response: Value =
        serde_json::from_slice(&body).map_err(|_| LiveJourneyError::NotaryResponse)?;
    let evaluation_id =
        validate_minimized_notary_response(profile, &response, selector.as_str(), sensitive)?;
    validate_notary_audit(audit_path, &evaluation_id, selector.as_str(), sensitive)
}

fn validate_minimized_notary_response(
    profile: JourneyProfile,
    response: &Value,
    selector: &str,
    sensitive: &JourneySensitiveValues<'_>,
) -> Result<String, LiveJourneyError> {
    let expected_result_count = match profile {
        JourneyProfile::Dhis2 => 2,
        JourneyProfile::OpenCrvs => 1,
        JourneyProfile::SyntheticSnapshot => 2,
    };
    let results = response
        .get("results")
        .and_then(Value::as_array)
        .filter(|results| results.len() == expected_result_count)
        .ok_or(LiveJourneyError::NotaryResponse)?;
    let evaluation_id = results[0]
        .get("evaluation_id")
        .and_then(Value::as_str)
        .filter(|value| value.parse::<Ulid>().is_ok())
        .ok_or(LiveJourneyError::NotaryResponse)?;
    if results.iter().any(|result| {
        result.get("evaluation_id").and_then(Value::as_str) != Some(evaluation_id)
            || result
                .pointer("/provenance/used/source_count")
                .and_then(Value::as_u64)
                != Some(1)
    }) {
        return Err(LiveJourneyError::NotaryResponse);
    }
    match profile {
        JourneyProfile::Dhis2 => {
            let known = results
                .iter()
                .find(|result| {
                    result.get("claim_id").and_then(Value::as_str) == Some("dhis2-enrollment-known")
                })
                .ok_or(LiveJourneyError::NotaryResponse)?;
            if known.get("value") != Some(&Value::Bool(true)) {
                return Err(LiveJourneyError::NotaryResponse);
            }
            let status = results
                .iter()
                .find(|result| {
                    result.get("claim_id").and_then(Value::as_str)
                        == Some("dhis2-enrollment-status")
                })
                .and_then(|result| result.get("value"))
                .and_then(Value::as_str)
                .ok_or(LiveJourneyError::NotaryResponse)?;
            if status.is_empty() || status.len() > 32 || status.chars().any(char::is_control) {
                return Err(LiveJourneyError::NotaryResponse);
            }
        }
        JourneyProfile::OpenCrvs => {
            let [result] = results.as_slice() else {
                return Err(LiveJourneyError::NotaryResponse);
            };
            if result.get("claim_id").and_then(Value::as_str)
                != Some("opencrvs-birth-record-exists")
                || result.get("value") != Some(&Value::Bool(false))
            {
                return Err(LiveJourneyError::NotaryResponse);
            }
        }
        JourneyProfile::SyntheticSnapshot => {
            let known = results
                .iter()
                .find(|result| {
                    result.get("claim_id").and_then(Value::as_str) == Some("synthetic-person-known")
                })
                .ok_or(LiveJourneyError::NotaryResponse)?;
            if known.get("value") != Some(&Value::Bool(true)) {
                return Err(LiveJourneyError::NotaryResponse);
            }
            let status = results
                .iter()
                .find(|result| {
                    result.get("claim_id").and_then(Value::as_str)
                        == Some("synthetic-person-status")
                })
                .and_then(|result| result.get("value"))
                .and_then(Value::as_str);
            if status != Some("ACTIVE") {
                return Err(LiveJourneyError::NotaryResponse);
            }
        }
    }
    let public_wire =
        serde_json::to_string(response).map_err(|_| LiveJourneyError::NotaryResponse)?;
    if [
        "consultation_id",
        "relay_consultation",
        selector,
        sensitive.source_base_url,
        sensitive.notary_api_key,
        sensitive.relay_bearer,
        sensitive.source_principal,
        sensitive.source_secret,
    ]
    .into_iter()
    .any(|sensitive| public_wire.contains(sensitive))
    {
        return Err(LiveJourneyError::NotaryResponse);
    }
    Ok(evaluation_id.to_string())
}

fn validate_notary_audit(
    path: &Path,
    expected_evaluation_id: &str,
    selector: &str,
    sensitive: &JourneySensitiveValues<'_>,
) -> Result<JourneyCorrelation, LiveJourneyError> {
    let file = fs::read_to_string(path).map_err(|_| LiveJourneyError::NotaryAudit)?;
    if [
        selector,
        sensitive.source_base_url,
        sensitive.notary_api_key,
        sensitive.relay_bearer,
        sensitive.source_principal,
        sensitive.source_secret,
    ]
    .into_iter()
    .any(|sensitive| file.contains(sensitive))
    {
        return Err(LiveJourneyError::NotaryAudit);
    }
    let mut matching = Vec::new();
    for line in file.lines() {
        let envelope: Value =
            serde_json::from_str(line).map_err(|_| LiveJourneyError::NotaryAudit)?;
        let record = envelope
            .get("record")
            .and_then(Value::as_object)
            .ok_or(LiveJourneyError::NotaryAudit)?;
        if record.get("path").and_then(Value::as_str) == Some("/v1/evaluations")
            && record.get("status").and_then(Value::as_u64) == Some(200)
        {
            matching.push(record.clone());
        }
    }
    let [record] = matching.as_slice() else {
        return Err(LiveJourneyError::NotaryAudit);
    };
    if record.get("verification_id").and_then(Value::as_str) != Some(expected_evaluation_id)
        || record.get("source_read_count").and_then(Value::as_u64) != Some(1)
        || record.get("forwarded").and_then(Value::as_bool) != Some(true)
    {
        return Err(LiveJourneyError::NotaryAudit);
    };
    let consultation_ids = record
        .get("relay_consultation_ids")
        .and_then(Value::as_array)
        .filter(|values| values.len() == 1)
        .ok_or(LiveJourneyError::NotaryAudit)?;
    let consultation_id = consultation_ids[0]
        .as_str()
        .filter(|value| value.parse::<Ulid>().is_ok())
        .ok_or(LiveJourneyError::NotaryAudit)?;
    Ok(JourneyCorrelation {
        evaluation_id: expected_evaluation_id.to_string(),
        consultation_id: consultation_id.to_string(),
        selector: Zeroizing::new(selector.to_string()),
        source_base_url: Zeroizing::new(sensitive.source_base_url.to_string()),
        notary_api_key: Zeroizing::new(sensitive.notary_api_key.to_string()),
        relay_bearer: Zeroizing::new(sensitive.relay_bearer.to_string()),
        source_principal: Zeroizing::new(sensitive.source_principal.to_string()),
        source_secret: Zeroizing::new(sensitive.source_secret.to_string()),
    })
}

struct LiveRelayServer {
    base_url: String,
    task: JoinHandle<()>,
}

impl LiveRelayServer {
    async fn start(app: Router) -> Result<Self, LiveJourneyError> {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .map_err(|_| LiveJourneyError::RelayListener)?;
        let address = listener
            .local_addr()
            .map_err(|_| LiveJourneyError::RelayListener)?;
        let task = tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        Ok(Self {
            base_url: format!("http://{address}"),
            task,
        })
    }

    fn base_url(&self) -> &str {
        &self.base_url
    }
}

impl Drop for LiveRelayServer {
    fn drop(&mut self) {
        self.task.abort();
    }
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

    fn mint_bearer(&self, profile: JourneyProfile) -> Result<Zeroizing<String>, LiveJourneyError> {
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
            "scope": profile.required_scope()
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
    directory: TempDir,
    config_path: PathBuf,
}

impl StagedProfile {
    fn new(
        profile: JourneyProfile,
        source_base_url: &str,
        postgres_ca_path: &Path,
        jwks_url: &str,
    ) -> Result<Self, LiveJourneyError> {
        let directory = tempfile::tempdir().map_err(|_| LiveJourneyError::ArtifactStaging)?;
        let source_root = Path::new(env!("CARGO_MANIFEST_DIR")).join(profile.directory());
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

        if profile == JourneyProfile::SyntheticSnapshot {
            let fixture_directory = directory.path().join("fixtures");
            fs::create_dir(&fixture_directory).map_err(|_| LiveJourneyError::ArtifactStaging)?;
            copy_artifact(
                &source_root.join("fixtures/people.csv"),
                &fixture_directory.join("people.csv"),
            )?;
        }

        let binding = if profile == JourneyProfile::SyntheticSnapshot {
            let bytes = fs::read(source_root.join("private-binding.example.json"))
                .map_err(|_| LiveJourneyError::ArtifactStaging)?;
            serde_json::from_slice(&bytes).map_err(|_| LiveJourneyError::ArtifactStaging)?
        } else {
            live_private_binding(profile, source_base_url)?
        };
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
            directory,
            config_path,
        })
    }

    fn stage_relay_token(&self, token: &str) -> Result<PathBuf, LiveJourneyError> {
        let path = self.directory.path().join("relay-workload.jwt");
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .map_err(|_| LiveJourneyError::RelayCredentialStaging)?;
        file.write_all(token.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|_| LiveJourneyError::RelayCredentialStaging)?;
        Ok(path)
    }

    fn notary_audit_path(&self) -> PathBuf {
        self.directory.path().join("notary-audit.jsonl")
    }

    fn load_notary_config(
        &self,
        profile: JourneyProfile,
        relay_base_url: &str,
        token_file: &Path,
        audit_path: &Path,
    ) -> Result<registry_notary_core::StandaloneRegistryNotaryConfig, LiveJourneyError> {
        let source_root = Path::new(env!("CARGO_MANIFEST_DIR")).join(profile.directory());
        let mut yaml = fs::read_to_string(source_root.join(NOTARY_CONFIG_EXAMPLE_FILE))
            .map_err(|_| LiveJourneyError::NotaryConfigLoad)?;
        replace_once(
            &mut yaml,
            r#"    base_url: "https://relay.example.gov""#,
            &format!(
                "    base_url: {}\n    allow_insecure_localhost: true",
                yaml_string(relay_base_url)?
            ),
        )?;
        replace_once(
            &mut yaml,
            "    token_file: /var/run/secrets/registry-notary/relay-access-token",
            &format!(
                "    token_file: {}",
                yaml_string(
                    token_file
                        .to_str()
                        .ok_or(LiveJourneyError::NotaryConfigLoad)?
                )?
            ),
        )?;
        replace_once(
            &mut yaml,
            "  sink: stdout",
            &format!(
                "  sink: file\n  path: {}",
                yaml_string(
                    audit_path
                        .to_str()
                        .ok_or(LiveJourneyError::NotaryConfigLoad)?
                )?
            ),
        )?;
        let config =
            serde_norway::from_str(&yaml).map_err(|_| LiveJourneyError::NotaryConfigLoad)?;
        Ok(config)
    }
}

fn live_private_binding(
    profile: JourneyProfile,
    source_base_url: &str,
) -> Result<Value, LiveJourneyError> {
    let parsed = Url::parse(source_base_url).map_err(|_| LiveJourneyError::InvalidSourceBaseUrl)?;
    if parsed.scheme() != "https"
        || parsed.host_str().is_none()
        || !parsed.username().is_empty()
        || parsed.password().is_some()
        || parsed.query().is_some()
        || parsed.fragment().is_some()
    {
        return Err(LiveJourneyError::InvalidSourceBaseUrl);
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
    let data_destination_id = match profile {
        JourneyProfile::Dhis2 => "dhis2-live-data",
        JourneyProfile::OpenCrvs => "opencrvs-live-data",
        JourneyProfile::SyntheticSnapshot => return Err(LiveJourneyError::InvalidSourceBaseUrl),
    };
    let mut destination = Map::from_iter([
        ("id".to_string(), json!(data_destination_id)),
        ("origin".to_string(), json!(origin.as_str())),
        ("dns_family".to_string(), json!("ipv4_only")),
        ("allowed_private_cidrs".to_string(), json!([])),
    ]);
    if let Some(path) = application_base_path {
        destination.insert("application_base_path".to_string(), json!(path));
    }
    let credential_destination = match profile {
        JourneyProfile::Dhis2 => Value::Null,
        JourneyProfile::OpenCrvs => {
            let mut credential = destination.clone();
            credential.insert("id".to_string(), json!("opencrvs-live-oauth"));
            Value::Object(credential)
        }
        JourneyProfile::SyntheticSnapshot => return Err(LiveJourneyError::InvalidSourceBaseUrl),
    };
    let (registry_instance, source_instance, credential_ref, max_source_bytes, timeout_ms) =
        match profile {
            JourneyProfile::Dhis2 => (
                "dhis2-live",
                "tracker-api",
                "dhis2-basic-reader",
                8_192,
                10_000,
            ),
            JourneyProfile::OpenCrvs => (
                "opencrvs-live",
                "dci-crvs-api",
                "opencrvs-oauth-client",
                147_456,
                20_000,
            ),
            JourneyProfile::SyntheticSnapshot => {
                return Err(LiveJourneyError::InvalidSourceBaseUrl)
            }
        };
    Ok(json!({
        "profile": {"id": profile.profile_id(), "version": PROFILE_VERSION},
        "integration_pack": {"id": profile.pack_id(), "version": "1", "hash": profile.pack_hash()},
        "tenant": "live-test",
        "registry_instance": registry_instance,
        "source_instance": source_instance,
        "data_destination": destination,
        "credential_destination": credential_destination,
        "credential": {"ref": credential_ref, "generation": 1},
        "deployment_parameters": {},
        "limits": {
            "max_source_bytes": max_source_bytes,
            "timeout_ms": timeout_ms,
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

    async fn assert_safe_durable_evidence(
        &mut self,
        profile: JourneyProfile,
        expected: &JourneyCorrelation,
    ) -> Result<(), LiveJourneyError> {
        let row = self
            .admin
            .query_one(
                r#"
WITH consultation_audit AS (
    SELECT phase, operation_id::text AS operation_id, record_json::jsonb AS record
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
    (SELECT min(operation_id)
       FROM consultation_audit WHERE phase = 'attempt') AS consultation_id,
    (SELECT min(record #>> '{payload,completion_seed,correlation,notary_evaluation_id}')
       FROM consultation_audit WHERE phase = 'attempt') AS notary_evaluation_id,
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
    (SELECT (record #> '{payload,completion_facts,actual_path}')::text
       FROM consultation_audit WHERE phase = 'completion' LIMIT 1) AS actual_path,
    (SELECT count(*) = 0 FROM consultation_audit
       WHERE strpos(record::text, $1) > 0
          OR strpos(record::text, $2) > 0
          OR strpos(record::text, $3) > 0
          OR strpos(record::text, $4) > 0
          OR strpos(record::text, $5) > 0
          OR strpos(record::text, $6) > 0) AS sensitive_values_absent,
    (SELECT count(*) FROM permits) AS total_permit_count,
    (SELECT count(*) FROM permits WHERE kind = 'data') AS data_permit_count,
    (SELECT count(*) FROM permits
       WHERE kind = 'data' AND dispatched AND completion_linked) AS linked_dispatch_count,
    (SELECT count(*) FROM relay_state_private.consultation_completion_intent
       WHERE state = 'completed') AS completed_intent_count
"#,
                &[
                    &expected.selector.as_str(),
                    &expected.source_base_url.as_str(),
                    &expected.relay_bearer.as_str(),
                    &expected.notary_api_key.as_str(),
                    &expected.source_principal.as_str(),
                    &expected.source_secret.as_str(),
                ],
            )
            .await
            .map_err(|_| LiveJourneyError::DurableEvidence)?;
        let consultation_id = row
            .try_get::<_, Option<String>>("consultation_id")
            .map_err(|_| LiveJourneyError::DurableEvidence)?;
        let notary_evaluation_id = row
            .try_get::<_, Option<String>>("notary_evaluation_id")
            .map_err(|_| LiveJourneyError::DurableEvidence)?;
        if consultation_id.as_deref() != Some(expected.consultation_id.as_str())
            || notary_evaluation_id.as_deref() != Some(expected.evaluation_id.as_str())
        {
            return Err(LiveJourneyError::DurableEvidence);
        }
        let actual_path = row
            .try_get::<_, Option<String>>("actual_path")
            .map_err(|_| LiveJourneyError::DurableEvidence)?
            .ok_or(LiveJourneyError::DurableEvidence)?;
        let actual_path: Value =
            serde_json::from_str(&actual_path).map_err(|_| LiveJourneyError::DurableEvidence)?;
        let (expected_outcome, credential_exchanges, data_exchanges, expected_path) = match profile
        {
            JourneyProfile::Dhis2 => (
                "match",
                0,
                1,
                json!([{"kind": "data", "ordinal": 0, "operation_id": "lookup-enrollment-status"}]),
            ),
            JourneyProfile::OpenCrvs => (
                "no_match",
                1,
                2,
                json!([
                    {"kind": "credential", "ordinal": 0, "operation_id": "acquire-opencrvs-token"},
                    {"kind": "data", "ordinal": 0, "operation_id": "lookup-birth-record.jwks"},
                    {"kind": "data", "ordinal": 1, "operation_id": "lookup-birth-record"}
                ]),
            ),
            JourneyProfile::SyntheticSnapshot => ("match", 0, 0, json!([])),
        };
        let sensitive_values_absent = row
            .try_get::<_, bool>("sensitive_values_absent")
            .map_err(|_| LiveJourneyError::DurableEvidence)?;
        if actual_path != expected_path || !sensitive_values_absent {
            return Err(LiveJourneyError::DurableEvidence);
        }
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
                Some(expected_outcome.to_string()),
                Some("known_complete".to_string()),
                Some(credential_exchanges),
                Some(data_exchanges),
                credential_exchanges + data_exchanges,
                data_exchanges,
                data_exchanges,
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
