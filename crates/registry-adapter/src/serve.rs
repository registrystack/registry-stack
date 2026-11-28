// SPDX-License-Identifier: Apache-2.0

//! The served process: the OIDC authenticator, the journal's PostgreSQL
//! pool, and the listener. The server refuses to start without OIDC and
//! without PostgreSQL; there is no open mode.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod, Runtime};
use registry_adapter_core::AdapterRuntimeConfig;
use registry_platform_authcommon::{validate_compact_access_token, FailedCheck, RefusalNote};
use registry_platform_config::{
    DatabaseConfig, JwksSource, OidcIssuerConfig, SecretReference as ConfigSecretReference,
    SecretResolver,
};
use registry_platform_oidc::{
    fetch_discovery_for_issuer, parse_static_jwks, AccessTokenAlgorithm, ClaimNames, DeclaredKinds,
    IssuerEntry, IssuerNetworkPolicy, IssuerSet, JwksFetcher, JwksFetcherConfig,
    OidcDiscoveryConfig, OidcError, TokenVerifier, TokenVerifierConfig, ASSERTION_ISSUER_CLAIM,
};
use registry_platform_yaml::SecretReference;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::{watch, Semaphore};
use tokio_postgres::Config as PgConfig;
use zeroize::Zeroizing;

use crate::engine::component::rest::continuation::{ContinuationCodec, CursorKey, CursorTtl};
use crate::engine::effective_contract::EffectiveContract;
use crate::engine::load::{LoadError, Loaded};
use crate::facade::{router, FacadeState};
use crate::idempotent::{
    self, PostgresIdempotencyStore, MAX_CALLER_IDENTITY_BYTES, MAX_CALLER_ISSUER_BYTES,
};
use crate::journal;
use crate::metrics::Metrics;

#[derive(Debug, Error)]
pub enum ServeError {
    #[error(transparent)]
    Load(#[from] LoadError),
    #[error("{0}")]
    Configuration(String),
    #[error("the listener could not bind: {0}")]
    Bind(String),
    #[error("the server stopped: {0}")]
    Serve(String),
    #[error("the stop signal handler could not be installed: {0}")]
    Signal(String),
    #[error("the {store} retention sweep stopped: {reason}")]
    Retention {
        /// Which store's retention stopped.
        store: &'static str,
        /// Why it stopped.
        reason: String,
    },
}

/// A verified caller.
pub struct Caller {
    /// The verified subject.
    pub reference: String,
    /// The verified issuer and admitted acting client remain process-local;
    /// the idempotency store receives only their namespace digest.
    pub issuer: String,
    pub client_id: String,
    pub scopes: Vec<String>,
    pub scope_claim: Arc<str>,
}

/// Why a request has no caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallerRefusal {
    /// The credential is absent or was refused, at the named check.
    Unauthenticated(RefusalNote),
    /// The verifier could not reach a verdict (issuer or key set outage).
    Unavailable,
}

impl CallerRefusal {
    /// The check the request failed, for the operator-side counter and log.
    #[must_use]
    pub const fn failed_check(self) -> FailedCheck {
        self.note().check
    }

    pub(crate) const fn note(self) -> RefusalNote {
        match self {
            Self::Unauthenticated(note) => note,
            Self::Unavailable => RefusalNote::new(FailedCheck::KeySourceUnavailable),
        }
    }

    pub(crate) const fn unauthenticated(check: FailedCheck) -> Self {
        Self::Unauthenticated(RefusalNote::new(check))
    }
}

/// The longest subject the journal's caller reference column holds.
const MAXIMUM_SUBJECT_BYTES: usize = 256;

pub struct Authenticator {
    issuers: IssuerSet,
    scope_claims: HashMap<Arc<str>, Arc<str>>,
}

impl Authenticator {
    /// The journal keeps the original subject for a single issuer. With
    /// multiple issuers the digest binds the verified issuer and subject.
    pub(crate) fn journal_reference(&self, caller: &Caller) -> String {
        if self.scope_claims.len() > 1 {
            // Both verified members exclude NUL. The digest fits the
            // existing journal bound.
            let principal = format!(
                "adapter-journal-caller-v1\0{}\0{}",
                caller.issuer, caller.reference
            );
            registry_platform_config::sha256_uri(principal.as_bytes())
        } else {
            caller.reference.clone()
        }
    }

    pub async fn authenticate(&self, token: &str) -> Result<Caller, CallerRefusal> {
        validate_compact_access_token(token)
            .map_err(|_| CallerRefusal::unauthenticated(FailedCheck::CredentialMalformed))?;
        let caller = self
            .issuers
            .verify(token)
            .await
            .map_err(|refusal| match refusal.error {
                OidcError::Transport(_)
                | OidcError::BoundedRead(_)
                | OidcError::FetchUrl(_)
                | OidcError::HttpStatus(_)
                | OidcError::InvalidUrl
                | OidcError::Parse
                | OidcError::InvalidJwk
                | OidcError::EmptyKeySet
                | OidcError::MissingIssuer
                | OidcError::ConflictingEndpointConfiguration => CallerRefusal::Unavailable,
                _ => {
                    let mut note = RefusalNote::new(refusal.failed_check());
                    if let Some(remedy) = refusal.remedy {
                        note = note.with_remedy(remedy);
                    }
                    CallerRefusal::Unauthenticated(note)
                }
            })?;
        let verified = caller.token;
        // An exchanged token names the authority whose assertion produced
        // it. This runtime declares no assertion authority, so it admits
        // no exchanged token.
        if verified.claims.extra.contains_key(ASSERTION_ISSUER_CLAIM) {
            return Err(CallerRefusal::unauthenticated(
                FailedCheck::TokenAssertionIssuer,
            ));
        }
        let issuer = verified
            .claims
            .iss
            .clone()
            .filter(|issuer| {
                !issuer.is_empty()
                    && issuer.len() <= MAX_CALLER_ISSUER_BYTES
                    && !issuer.contains('\0')
            })
            .ok_or(CallerRefusal::unauthenticated(FailedCheck::TokenClaims))?;
        let client_id = verified
            .matched_client_id()
            .ok()
            .flatten()
            .filter(|client| {
                !client.is_empty()
                    && client.len() <= MAX_CALLER_IDENTITY_BYTES
                    && !client.contains('\0')
            })
            .map(str::to_owned)
            .ok_or(CallerRefusal::unauthenticated(FailedCheck::TokenClient))?;
        let reference = verified
            .claims
            .sub
            .clone()
            .filter(|subject| {
                !subject.is_empty()
                    && subject.len() <= MAXIMUM_SUBJECT_BYTES
                    && !subject.contains('\0')
            })
            .ok_or(CallerRefusal::unauthenticated(FailedCheck::TokenClaims))?;
        let scope_claim = self
            .scope_claims
            .get(&caller.issuer_id)
            .cloned()
            .ok_or(CallerRefusal::unauthenticated(FailedCheck::TokenClaims))?;
        Ok(Caller {
            reference,
            issuer,
            client_id,
            scopes: verified.scopes,
            scope_claim,
        })
    }
}

pub(crate) async fn authenticator(
    runtime: &AdapterRuntimeConfig,
    resolver: &SecretResolver,
) -> Result<Authenticator, ServeError> {
    let invalid = |what: &str| ServeError::Configuration(format!("oidc: {what}"));
    let mut entries = Vec::with_capacity(runtime.oidc.set.len());
    let mut scope_claims = HashMap::with_capacity(runtime.oidc.set.len());
    for (id, entry) in runtime.oidc.set.iter() {
        let id: Arc<str> = Arc::from(id.as_str());
        let core = &entry.core;
        if scope_claims
            .insert(id.clone(), Arc::from(core.scope_claim.get().as_str()))
            .is_some()
        {
            return Err(invalid(&format!("two issuer entries share the id {id}")));
        }
        let config = TokenVerifierConfig::for_caller_issuer(core, accepted_algorithms(), None)
            .map_err(|error| invalid(&error.to_string()))?;
        let declared =
            DeclaredKinds::from_core(core).map_err(|error| invalid(&error.to_string()))?;
        let keys = issuer_keys(&core.provider, resolver).await?;
        entries.push(IssuerEntry::new(
            id,
            TokenVerifier::new(config, Arc::new(keys)),
            declared,
        ));
    }
    let issuers = IssuerSet::new(entries, ClaimNames::default())
        .map_err(|error| invalid(&error.to_string()))?;
    Ok(Authenticator {
        issuers,
        scope_claims,
    })
}

async fn issuer_keys(
    oidc: &OidcIssuerConfig,
    resolver: &SecretResolver,
) -> Result<JwksFetcher, ServeError> {
    let invalid = |what: &str| ServeError::Configuration(format!("oidc: {what}"));
    let network = IssuerNetworkPolicy::new(oidc.issuer.as_str(), oidc.allow_insecure_http)
        .map_err(|_| invalid("the issuer was refused"))?;
    Ok(match &oidc.jwks_source {
        JwksSource::Discovery {} => {
            let (discovery, policy) = fetch_discovery_for_issuer(
                &OidcDiscoveryConfig {
                    issuer: oidc.issuer.to_string(),
                    jwks_uri_override: None,
                    discovery_timeout: Duration::from_secs(5),
                    max_doc_bytes: 1024 * 1024,
                },
                oidc.allow_insecure_http,
            )
            .await
            .map_err(|_| invalid("discovery failed"))?;
            JwksFetcher::new_with_fetch_url_policy(
                discovery.jwks_uri,
                JwksFetcherConfig::defaults(),
                policy,
            )
        }
        JwksSource::Uri { uri } => JwksFetcher::new_with_fetch_url_policy(
            uri.to_string(),
            JwksFetcherConfig::defaults(),
            network.declared_jwks_fetch_policy(),
        ),
        JwksSource::Static { document_ref } | JwksSource::TestIssuer { document_ref } => {
            let document = resolver
                .resolve(document_ref)
                .map_err(|_| invalid("the static key document could not be resolved"))?;
            let jwks = parse_static_jwks(document.expose_secret()).map_err(|error| {
                match error {
                    // The document is the operator's own file, so its text names the
                    // rule it breaks and never a key value.
                    OidcError::StaticKeySet(refused) => invalid(&format!(
                        "the static key document is not a usable key set: {refused}"
                    )),
                    _ => invalid("the static key document was refused"),
                }
            })?;
            JwksFetcher::new_static(jwks, JwksFetcherConfig::defaults())
        }
    })
}

/// The cursor codec the runtime config declares, if any: the current key
/// seals, the previous key still opens.
fn codec(
    runtime: &AdapterRuntimeConfig,
    resolver: &SecretResolver,
) -> Result<Option<ContinuationCodec>, ServeError> {
    let invalid = |what: &str| ServeError::Configuration(format!("cursor key: {what}"));
    let key = |reference: &SecretReference| -> Result<CursorKey, ServeError> {
        // The key is raw bytes, so a file or variable may hold any 32.
        let parsed = ConfigSecretReference::parse(reference.as_str())
            .map_err(|_| invalid("a reference was refused"))?;
        let secret = resolver
            .resolve_binary_reference(&parsed)
            .map_err(|_| invalid("a reference could not be resolved"))?;
        CursorKey::new(Zeroizing::new(secret.expose_secret().to_vec()))
            .map_err(|error| invalid(&error.to_string()))
    };
    let Some(current) = &runtime.cursor_key_ref else {
        return Ok(None);
    };
    let previous = runtime
        .previous_cursor_key_ref
        .as_ref()
        .map(key)
        .transpose()?;
    let ttl = match runtime.cursor_ttl_seconds {
        Some(seconds) => {
            CursorTtl::from_seconds(seconds.get()).map_err(|error| invalid(&error.to_string()))?
        }
        None => CursorTtl::default(),
    };
    Ok(Some(ContinuationCodec::new(key(current)?, previous, ttl)))
}

pub(crate) fn check_database(config: &DatabaseConfig) -> Result<(), ServeError> {
    config
        .check(cfg!(feature = "postgres-test"))
        .map_err(database_transport_error)
}

fn database_transport_error(error: registry_platform_config::DatabaseTransportError) -> ServeError {
    ServeError::Configuration(format!(
        "database: {}: {error}; next: {}",
        error.code(),
        error.suggested_action()
    ))
}

pub(crate) fn pool(
    config: &DatabaseConfig,
    resolver: &SecretResolver,
    migration: bool,
    development: Option<&registry_platform_config::DevelopmentWitness>,
) -> Result<Pool, ServeError> {
    let invalid = |what: &str| ServeError::Configuration(format!("database: {what}"));
    check_database(config)?;
    let reference = if migration {
        &config.migration_url_ref
    } else {
        &config.runtime_url_ref
    };
    let protected = resolver
        .resolve(reference)
        .map_err(|_| invalid("a connection reference could not be resolved"))?;
    let url = std::str::from_utf8(protected.expose_secret())
        .map_err(|_| invalid("the connection url is not text"))?;
    let mut postgres =
        PgConfig::from_str(url).map_err(|_| invalid("the connection url is invalid"))?;
    if postgres.get_user().is_none() || postgres.get_dbname().is_none() {
        return Err(invalid("the connection url names no user or database"));
    }
    let manager_config = ManagerConfig {
        recycling_method: RecyclingMethod::Verified,
    };
    use registry_platform_config::{DatabaseHost, DatabaseTransport};
    let hosts: Vec<_> = postgres
        .get_hosts()
        .iter()
        .map(|host| match host {
            tokio_postgres::config::Host::Tcp(name) => DatabaseHost::Tcp(name.clone()),
            #[cfg(unix)]
            tokio_postgres::config::Host::Unix(_) => DatabaseHost::Unix,
        })
        .chain(
            postgres
                .get_hostaddrs()
                .iter()
                .map(|ip| DatabaseHost::Tcp(ip.to_string())),
        )
        .collect();
    let transport = config
        .plaintext_permitted(&hosts, development)
        .map_err(database_transport_error)?;
    let manager = if config.test_only_plaintext || transport != DatabaseTransport::VerifiedTls {
        postgres.ssl_mode(tokio_postgres::config::SslMode::Disable);
        Manager::from_config(postgres, tokio_postgres::NoTls, manager_config)
    } else {
        postgres.ssl_mode(tokio_postgres::config::SslMode::Require);
        Manager::from_config(postgres, tls_connector(config, resolver)?, manager_config)
    };
    Pool::builder(manager)
        .max_size(32)
        .wait_timeout(Some(Duration::from_secs(5)))
        .create_timeout(Some(Duration::from_secs(5)))
        .recycle_timeout(Some(Duration::from_secs(5)))
        .runtime(Runtime::Tokio1)
        .build()
        .map_err(|_| invalid("the pool could not be built"))
}

fn tls_connector(
    config: &DatabaseConfig,
    resolver: &SecretResolver,
) -> Result<tokio_postgres_rustls::MakeRustlsConnect, ServeError> {
    let invalid = |what: &str| ServeError::Configuration(format!("database tls: {what}"));
    let provider = rustls::crypto::ring::default_provider();
    if provider.install_default().is_err()
        && rustls::crypto::CryptoProvider::get_default().is_none()
    {
        return Err(invalid("no crypto provider could be installed"));
    }
    if let Some(reference) = &config.ca_bundle_ref {
        let certificate = resolver
            .resolve(reference)
            .map_err(|_| invalid("the trusted root could not be resolved"))?;
        let mut roots = rustls::RootCertStore::empty();
        use rustls::pki_types::pem::PemObject as _;
        let mut count = 0_usize;
        for certificate in
            rustls::pki_types::CertificateDer::pem_slice_iter(certificate.expose_secret())
        {
            roots
                .add(certificate.map_err(|_| invalid("a trusted root was not valid PEM"))?)
                .map_err(|_| invalid("a trusted root was refused"))?;
            count += 1;
        }
        if count == 0 {
            return Err(invalid("the trusted root held no certificate"));
        }
        let client = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(tokio_postgres_rustls::MakeRustlsConnect::new(client))
    } else {
        tokio_postgres_rustls::MakeRustlsConnect::with_native_certs()
            .map(|value| value.0)
            .map_err(|_| invalid("the system roots could not be loaded"))
    }
}

/// The access-token signature algorithms the facade accepts.
const ACCEPTED_ALGORITHMS: [AccessTokenAlgorithm; 2] =
    [AccessTokenAlgorithm::RS256, AccessTokenAlgorithm::ES256];

fn accepted_algorithms() -> Vec<jsonwebtoken::Algorithm> {
    ACCEPTED_ALGORITHMS
        .into_iter()
        .map(AccessTokenAlgorithm::to_jsonwebtoken)
        .collect()
}

/// Resolve on the first SIGTERM or SIGINT. The handlers are installed here,
/// before anything is served, so a failure to install one refuses startup
/// rather than leaving a runtime that SIGTERM would stop with sends in
/// flight.
pub(crate) fn shutdown_signal() -> Result<impl std::future::Future<Output = ()> + Send, ServeError>
{
    shutdown_after(registry_platform_httpsec::shutdown_signal)
}

/// Install the stop signals with `install`, turning a failure into the
/// startup error [`ServeError::Signal`].
fn shutdown_after<I, S>(install: I) -> Result<S, ServeError>
where
    I: FnOnce() -> std::io::Result<S>,
{
    install().map_err(|error| ServeError::Signal(error.to_string()))
}

/// Run one bounded `sweep` per `cadence` until shutdown. A batch that
/// reaches `batch_bound` is followed at once by another, so a backlog drains
/// without waiting for the next tick. A failed batch is logged at error level,
/// naming the store and the reason, and retried at the next tick, so
/// retention lags while the database fails and the sweeper runs until
/// shutdown. Missing privileges are refused at startup, so only transient
/// failures reach this loop.
async fn sweep_on_cadence<Sweep, Batch>(
    store: &'static str,
    cadence: Duration,
    batch_bound: u64,
    metrics: Arc<Metrics>,
    mut shutdown: watch::Receiver<bool>,
    mut sweep: Sweep,
) -> Result<(), ServeError>
where
    Sweep: FnMut() -> Batch,
    Batch: std::future::Future<Output = Result<u64, String>>,
{
    let closed = || ServeError::Retention {
        store,
        reason: "the shutdown channel closed".to_owned(),
    };
    let mut interval = tokio::time::interval(cadence);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                changed.map_err(|_| closed())?;
                return Ok(());
            }
            _ = interval.tick() => {
                loop {
                    let erased = tokio::select! {
                        changed = shutdown.changed() => {
                            changed.map_err(|_| closed())?;
                            return Ok(());
                        }
                        result = sweep() => match result {
                            Ok(erased) => erased,
                            Err(reason) => {
                                metrics.record_sweep_failure(store);
                                tracing::error!(store, reason = %reason,
                                    "retention sweep failed; retrying at the next tick");
                                break;
                            }
                        }
                    };
                    if erased < batch_bound {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            }
        }
    }
}

/// Erase one bounded response batch per cadence. Claim-time expiry remains a
/// correctness backstop, but custody does not depend on a duplicate arriving.
/// A database failure is logged at error level and retried at the next tick.
async fn sweep_idempotency_responses(
    store: PostgresIdempotencyStore,
    cadence: Duration,
    metrics: Arc<Metrics>,
    shutdown: watch::Receiver<bool>,
) -> Result<(), ServeError> {
    sweep_on_cadence(
        "idempotency response",
        cadence,
        u64::from(idempotent::MAX_SWEEP_BATCH),
        metrics,
        shutdown,
        || {
            let store = store.clone();
            async move {
                store
                    .sweep_expired(SystemTime::now(), idempotent::MAX_SWEEP_BATCH)
                    .await
                    .map_err(|error| error.to_string())
            }
        },
    )
    .await
}

/// Delete journal events older than `audit.retentionDays`, one bounded batch
/// per cadence. Every deployment sweeps, read-only ones included, so the
/// journal never keeps an event past its retention window.
async fn sweep_journal_events(
    pool: Pool,
    retention: Duration,
    metrics: Arc<Metrics>,
    shutdown: watch::Receiver<bool>,
) -> Result<(), ServeError> {
    sweep_on_cadence(
        "journal",
        retention_cadence(retention),
        u64::from(journal::MAX_RETENTION_BATCH),
        metrics,
        shutdown,
        || {
            let pool = pool.clone();
            async move {
                let cutoff = SystemTime::now().checked_sub(retention).ok_or_else(|| {
                    "the retention window reaches before the clock's epoch".to_owned()
                })?;
                let client = pool.get().await.map_err(|error| {
                    format!("the journal connection pool gave no connection: {error}")
                })?;
                journal::delete_expired(&client, cutoff)
                    .await
                    .map_err(|error| error.to_string())
            }
        },
    )
    .await
}

fn retention_cadence(retention: Duration) -> Duration {
    (retention / 2).clamp(Duration::from_secs(1), Duration::from_secs(60))
}

fn source_replay_window_seconds(support: &registry_adapter_core::SourceWriteSupport) -> u64 {
    match support {
        registry_adapter_core::SourceWriteSupport::CreateOne {
            replay_window_seconds,
        }
        | registry_adapter_core::SourceWriteSupport::ConditionalUpdateOne {
            replay_window_seconds,
        } => replay_window_seconds.get(),
    }
}

/// The journal retention window `audit.retentionDays` names.
fn journal_retention(retention_days: u32) -> Duration {
    Duration::from_secs(u64::from(retention_days) * 24 * 60 * 60)
}

fn loaded_artifact_digest(deployment: &str) -> Result<[u8; 32], ServeError> {
    let Some(hex) = deployment.strip_prefix("sha256:") else {
        return Err(ServeError::Configuration(
            "the loaded artifact digest is not sha256".to_owned(),
        ));
    };
    if hex.len() != 64 {
        return Err(ServeError::Configuration(
            "the loaded artifact digest has the wrong length".to_owned(),
        ));
    }
    let mut digest = [0_u8; 32];
    for (index, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).map_err(|_| {
            ServeError::Configuration("the loaded artifact digest is not hexadecimal".to_owned())
        })?;
    }
    Ok(digest)
}

fn async_recovery_admission(
    loaded: &Loaded,
) -> Result<HashMap<String, Arc<Semaphore>>, ServeError> {
    let mut admission = HashMap::new();
    for operation in &loaded.served {
        let Some(completion) = operation.async_completion.as_ref() else {
            continue;
        };
        let mut endpoint_ids = completion.status.endpoint_ids.iter();
        let mut minimum = endpoint_ids
            .next()
            .and_then(|id| loaded.runtime.endpoints.get(id))
            .map(|binding| binding.maximum_concurrency.get())
            .ok_or_else(|| {
                ServeError::Configuration(
                    "an asynchronous status route has no runtime endpoint".to_owned(),
                )
            })?;
        for id in endpoint_ids.chain(
            completion
                .uncertainty
                .iter()
                .flat_map(|recovery| recovery.status.endpoint_ids.iter()),
        ) {
            let concurrency = loaded
                .runtime
                .endpoints
                .get(id)
                .map(|binding| binding.maximum_concurrency.get())
                .ok_or_else(|| {
                    ServeError::Configuration(
                        "an asynchronous recovery route has no runtime endpoint".to_owned(),
                    )
                })?;
            minimum = minimum.min(concurrency);
        }
        let permits = usize::try_from(minimum).map_err(|_| {
            ServeError::Configuration(
                "an asynchronous recovery concurrency does not fit this host".to_owned(),
            )
        })?;
        admission.insert(operation.binding.clone(), Arc::new(Semaphore::new(permits)));
    }
    Ok(admission)
}

/// Load the deployment, migrate the journal, and serve until a stop signal.
pub async fn run(
    project_directory: &std::path::Path,
    profile_path: Option<&std::path::Path>,
    pack_path: Option<&std::path::Path>,
    runtime_path: &std::path::Path,
) -> Result<(), ServeError> {
    run_facade(
        project_directory,
        profile_path,
        pack_path,
        runtime_path,
        None,
        &[],
        registry_platform_config::DeclaredPosture {
            posture: registry_platform_config::Posture::Production,
            source: registry_platform_config::PostureSource::Default,
        },
    )
    .await
}

/// Host a record facade, typed payment routes, or both on one listener.
pub async fn run_configured(
    project_directory: Option<&std::path::Path>,
    profile_path: Option<&std::path::Path>,
    pack_path: Option<&std::path::Path>,
    runtime_path: &std::path::Path,
    payments_path: Option<&std::path::Path>,
    payment_provider_pack: &[std::path::PathBuf],
    declared: registry_platform_config::DeclaredPosture,
) -> Result<(), ServeError> {
    match (project_directory, payments_path) {
        (Some(project), payments) => {
            run_facade(
                project,
                profile_path,
                pack_path,
                runtime_path,
                payments,
                payment_provider_pack,
                declared,
            )
            .await
        }
        (None, Some(payments)) if profile_path.is_none() && pack_path.is_none() => {
            crate::payments::http::run_only(runtime_path, payments, payment_provider_pack, declared)
                .await
        }
        _ => Err(ServeError::Configuration(
            "a project or payment configuration is required".to_owned(),
        )),
    }
}

/// The table privileges the runtime role needs for a deployment, by table:
/// the journal and the migration ledger always, idempotency state when it
/// serves a write, the artifact fence when it declares an asynchronous or
/// resumable write, and the checkpoint bindings when it declares a resumable
/// write. Startup grants those the runtime role lacks and then checks them all.
fn runtime_requirements(
    serves_write: bool,
    declares_recovery: bool,
    declares_resume: bool,
) -> Vec<(&'static str, &'static [&'static str])> {
    let mut required: Vec<(&'static str, &'static [&'static str])> = vec![
        ("adapter_journal_events", &journal::RUNTIME_PRIVILEGES),
        ("adapter_schema_migrations", &["SELECT"]),
    ];
    if serves_write {
        required.extend(idempotent::WRITE_RUNTIME_GRANTS);
    }
    if declares_recovery {
        required.push(idempotent::RECOVERY_RUNTIME_GRANTS);
    }
    if declares_resume {
        required.push(idempotent::RESUME_RUNTIME_GRANTS);
    }
    required
}

/// Everything a runtime role must hold for a deployment: table privileges, by
/// table, and USAGE on sequences. Startup grants what the role lacks, then
/// checks it.
pub(crate) struct Requirements {
    pub(crate) tables: Vec<(&'static str, &'static [&'static str])>,
    pub(crate) sequences: Vec<&'static str>,
}

impl Requirements {
    /// What the payment host requires: the collection tables always, and the
    /// G2P tables when a disbursement connection is declared.
    pub(crate) fn payments(disbursements: bool) -> Self {
        let mut required = Self {
            tables: crate::payments::store::RUNTIME_GRANTS.to_vec(),
            sequences: vec![crate::payments::store::RUNTIME_SEQUENCE],
        };
        if disbursements {
            required
                .tables
                .extend(crate::payments::g2p_store::RUNTIME_GRANTS);
            required
                .sequences
                .push(crate::payments::g2p_store::RUNTIME_SEQUENCE);
        }
        required
    }

    pub(crate) fn extend(&mut self, other: Self) {
        self.tables.extend(other.tables);
        self.sequences.extend(other.sequences);
    }
}

/// The advisory-lock key the grant step holds for its transaction, so
/// replicas starting together do not rewrite the same catalog rows at once.
/// Its ASCII bytes spell `adap_gnt`.
const GRANT_LOCK_KEY: i64 = 0x6164_6170_5f67_6e74;

/// A PostgreSQL identifier, quoted.
fn quote_identifier(identifier: &str) -> String {
    format!("\"{}\"", identifier.replace('"', "\"\""))
}

/// The server's own message for a failed statement, without its position or
/// the statement text.
fn database_message(error: &tokio_postgres::Error) -> String {
    error
        .as_db_error()
        .map_or_else(|| error.to_string(), |db| db.message().to_owned())
}

fn grant_error(error: &tokio_postgres::Error) -> ServeError {
    ServeError::Configuration(format!("database grants: {}", database_message(error)))
}

/// The `privileges` that `grantee` lacks on `relation` (an already-quoted,
/// schema-qualified name), in the given order; all of them when the relation
/// does not exist.
async fn missing_for(
    transaction: &tokio_postgres::Transaction<'_>,
    grantee: &str,
    relation: &str,
    privileges: &[&'static str],
) -> Result<Vec<&'static str>, tokio_postgres::Error> {
    let names = privileges.to_vec();
    let held = transaction
        .query(
            "SELECT coalesce(has_table_privilege($1, to_regclass($2), privilege), false) \
             FROM unnest($3::text[]) WITH ORDINALITY AS wanted(privilege, position) \
             ORDER BY position",
            &[&grantee, &relation, &names],
        )
        .await?;
    Ok(privileges
        .iter()
        .zip(held.iter())
        .filter(|(_, row)| !row.get::<_, bool>(0))
        .map(|(privilege, _)| *privilege)
        .collect())
}

/// Whether `grantee` lacks USAGE on `relation`, a sequence given as an
/// already-quoted, schema-qualified name; true when it does not exist.
async fn lacks_sequence_usage(
    transaction: &tokio_postgres::Transaction<'_>,
    grantee: &str,
    relation: &str,
) -> Result<bool, tokio_postgres::Error> {
    let held: bool = transaction
        .query_one(
            "SELECT coalesce(has_sequence_privilege($1, to_regclass($2), 'USAGE'), false)",
            &[&grantee, &relation],
        )
        .await?
        .get(0);
    Ok(!held)
}

/// Everything `grantee` still lacks of `required` and of `USAGE` on `schema`,
/// as "PRIVILEGES on object" phrases.
async fn lacking(
    transaction: &tokio_postgres::Transaction<'_>,
    grantee: &str,
    schema: &str,
    required: &Requirements,
) -> Result<Vec<String>, tokio_postgres::Error> {
    let mut lacking = Vec::new();
    for (table, privileges) in &required.tables {
        let missing = missing_for(
            transaction,
            grantee,
            &format!("{schema}.{table}"),
            privileges,
        )
        .await?;
        if !missing.is_empty() {
            lacking.push(format!("{} on {table}", missing.join(", ")));
        }
    }
    for sequence in &required.sequences {
        if lacks_sequence_usage(transaction, grantee, &format!("{schema}.{sequence}")).await? {
            lacking.push(format!("USAGE on sequence {sequence}"));
        }
    }
    let usage: bool = transaction
        .query_one(
            "SELECT has_schema_privilege($1, current_schema(), 'USAGE')",
            &[&grantee],
        )
        .await?
        .get(0);
    if !usage {
        lacking.push(format!("USAGE on schema {schema}"));
    }
    Ok(lacking)
}

/// Grant `grantee`, the runtime session's own role, each privilege in
/// `required` it lacks and `USAGE` on the schema the migrations ran in, from
/// the migration session in one transaction under an advisory lock. A start
/// that finds everything in place issues no GRANT. Nothing beyond `required`
/// is granted: no default privileges, no grant on the idempotency migration
/// ledger.
///
/// When something is missing and the role has members, no grant is made,
/// because they would inherit it: the privilege check that follows then
/// decides, as it does for a hand-granted deployment. A member that holds
/// ADMIN OPTION on the role and has no members of its own does not count. It
/// already controls the role, as the role that created it does in the layout
/// the shared provisioning plan builds. PostgreSQL ignores or refuses a GRANT the
/// migration role has no right to make, so each privilege is checked again
/// before the commit, and a shortfall rolls everything back.
///
/// Returns whether `grantee` ends holding everything `required` names: false
/// when the members rule made no grant.
async fn grant_runtime_privileges(
    client: &mut deadpool_postgres::Client,
    grantee: &str,
    required: &Requirements,
) -> Result<bool, ServeError> {
    let transaction = client.transaction().await.map_err(|e| grant_error(&e))?;
    transaction
        .query_one("SELECT pg_advisory_xact_lock($1)", &[&GRANT_LOCK_KEY])
        .await
        .map_err(|e| grant_error(&e))?;
    let schema: Option<String> = transaction
        .query_one("SELECT quote_ident(current_schema())", &[])
        .await
        .map_err(|e| grant_error(&e))?
        .get(0);
    let schema = schema.ok_or_else(|| {
        ServeError::Configuration(
            "database: the migration role's search path names no schema to grant USAGE on"
                .to_owned(),
        )
    })?;
    let missing = lacking(&transaction, grantee, &schema, required)
        .await
        .map_err(|e| grant_error(&e))?;
    if missing.is_empty() {
        transaction.rollback().await.map_err(|e| grant_error(&e))?;
        return Ok(true);
    }
    let has_members: bool = transaction
        .query_one(
            "SELECT EXISTS (SELECT 1 FROM pg_auth_members m \
                            JOIN pg_roles r ON r.oid = m.roleid \
                            WHERE r.rolname = $1 \
                              AND m.member NOT IN (SELECT a.member FROM pg_auth_members a \
                                                   WHERE a.roleid = r.oid AND a.admin_option \
                                                     AND NOT EXISTS (SELECT 1 FROM pg_auth_members g \
                                                                     WHERE g.roleid = a.member)))",
            &[&grantee],
        )
        .await
        .map_err(|e| grant_error(&e))?
        .get(0);
    if has_members {
        tracing::warn!(
            role = grantee,
            "the runtime role has members, so no privilege is granted to it automatically"
        );
        transaction.rollback().await.map_err(|e| grant_error(&e))?;
        return Ok(false);
    }
    let mut granted = 0_usize;
    let quoted_grantee = quote_identifier(grantee);
    for (table, privileges) in &required.tables {
        let missing = missing_for(
            &transaction,
            grantee,
            &format!("{schema}.{table}"),
            privileges,
        )
        .await
        .map_err(|e| grant_error(&e))?;
        if missing.is_empty() {
            continue;
        }
        granted += missing.len();
        let missing = missing.join(", ");
        transaction
            .batch_execute(&format!(
                "GRANT {missing} ON TABLE {schema}.{table} TO {quoted_grantee}"
            ))
            .await
            .map_err(|error| {
                ServeError::Configuration(format!(
                    "database: could not grant {missing} on {table} to the runtime role: {}",
                    database_message(&error)
                ))
            })?;
    }
    for sequence in &required.sequences {
        if !lacks_sequence_usage(&transaction, grantee, &format!("{schema}.{sequence}"))
            .await
            .map_err(|e| grant_error(&e))?
        {
            continue;
        }
        granted += 1;
        transaction
            .batch_execute(&format!(
                "GRANT USAGE ON SEQUENCE {schema}.{sequence} TO {quoted_grantee}"
            ))
            .await
            .map_err(|error| {
                ServeError::Configuration(format!(
                    "database: could not grant USAGE on sequence {sequence} to the runtime role: {}",
                    database_message(&error)
                ))
            })?;
    }
    let usage: bool = transaction
        .query_one(
            "SELECT has_schema_privilege($1, current_schema(), 'USAGE')",
            &[&grantee],
        )
        .await
        .map_err(|e| grant_error(&e))?
        .get(0);
    if !usage {
        granted += 1;
        transaction
            .batch_execute(&format!(
                "GRANT USAGE ON SCHEMA {schema} TO {quoted_grantee}"
            ))
            .await
            .map_err(|error| {
                ServeError::Configuration(format!(
                    "database: could not grant USAGE on schema {schema} to the runtime role: {}",
                    database_message(&error)
                ))
            })?;
    }
    let still_lacking = lacking(&transaction, grantee, &schema, required)
        .await
        .map_err(|e| grant_error(&e))?;
    if !still_lacking.is_empty() {
        transaction.rollback().await.map_err(|e| grant_error(&e))?;
        return Err(ServeError::Configuration(format!(
            "database: after its grants the runtime role still lacks {}; PostgreSQL ignores or refuses a grant the migration role has no right to make, most likely because the migration role does not own the object, so the grants were rolled back (https://docs.registrystack.org/operate/adapter/#grant-the-runtime-database-role says what to grant by hand)",
            still_lacking.join("; lacks ")
        )));
    }
    transaction.commit().await.map_err(|e| grant_error(&e))?;
    tracing::info!(
        role = grantee,
        privileges = granted,
        "granted the runtime role the privileges it lacked"
    );
    Ok(true)
}

/// Grant the runtime session's role what `required` names, from `migration`,
/// when the two sessions are different roles. The grantee is the role the
/// runtime session proves it holds, read before any grant: a runtime URL
/// naming `public`, a role that cannot log in or a wrong password fails here,
/// and the URL's text never chooses who receives privileges. One role on both
/// sessions issues no grant and returns false, as `grant_runtime_privileges`
/// does when its members rule made none.
pub(crate) async fn grant_when_split(
    migration: &mut deadpool_postgres::Client,
    runtime: &Pool,
    required: &Requirements,
) -> Result<bool, ServeError> {
    let runtime_role: String = runtime
        .get()
        .await
        .map_err(|error| ServeError::Configuration(format!("database runtime: {error}")))?
        .query_one("SELECT current_user::text", &[])
        .await
        .map_err(|error| ServeError::Configuration(format!("database runtime: {error}")))?
        .get(0);
    let migration_role: String = migration
        .query_one("SELECT current_user::text", &[])
        .await
        .map_err(|error| ServeError::Configuration(format!("database: {error}")))?
        .get(0);
    if runtime_role == migration_role {
        return Ok(false);
    }
    grant_runtime_privileges(migration, &runtime_role, required).await
}

type LoadedServeConfig = (
    registry_platform_config::LoadedRuntimeConfig<AdapterRuntimeConfig>,
    Option<registry_platform_config::LoadedRuntimeConfig<crate::payments::config::PaymentsConfig>>,
    serde_json::Map<String, serde_json::Value>,
);

/// Read the two files before deciding whether any collected setting is allowed.
pub(crate) fn load_serve_configuration(
    runtime_path: &std::path::Path,
    payments_path: Option<&std::path::Path>,
    declared: registry_platform_config::DeclaredPosture,
) -> Result<LoadedServeConfig, ServeError> {
    use registry_platform_config::{RuntimeConfigLoader, RuntimeEnvelope};
    use registry_platform_yaml::Severity;

    let path = std::fs::canonicalize(runtime_path).unwrap_or_else(|_| runtime_path.to_path_buf());
    let runtime = RuntimeConfigLoader::new(
        RuntimeEnvelope {
            api_version: registry_adapter_core::ADAPTER_RUNTIME_API_VERSION,
            kind: registry_adapter_core::ADAPTER_RUNTIME_KIND,
        },
        declared,
    )
    .removed_keys(registry_adapter_core::ADAPTER_FACADE_REMOVED_KEYS)
    .check_offline::<AdapterRuntimeConfig>(&path, true, |_| "");
    let payments = payments_path.map(|path| crate::payments::http::load_config(path, declared));
    let oidc_diagnostics = runtime
        .loaded
        .as_ref()
        .map(|loaded| {
            let issuers = &loaded.config.oidc.set;
            let mut diagnostics = issuers.check("/oidc/issuers");
            diagnostics.extend(
                issuers.check_one_audience("/oidc/issuers", "published effective contract"),
            );
            diagnostics
        })
        .unwrap_or_default();
    let diagnostics = runtime
        .diagnostics
        .into_iter()
        .chain(oidc_diagnostics)
        .chain(
            payments
                .iter()
                .flat_map(|file| file.diagnostics.iter().cloned()),
        )
        .collect::<Vec<_>>();
    if diagnostics
        .iter()
        .any(|diagnostic| diagnostic.severity == Severity::Error)
    {
        let details = diagnostics
            .iter()
            .map(registry_platform_yaml::Diagnostic::render_human)
            .collect::<String>();
        return Err(ServeError::Configuration(format!(
            "the configuration was refused: {}",
            details.trim_end()
        )));
    }
    let mut runtime = runtime.loaded.ok_or_else(|| {
        ServeError::Configuration("the runtime configuration could not be loaded".to_owned())
    })?;
    let payments = payments
        .map(|file| {
            file.loaded.ok_or_else(|| {
                ServeError::Configuration(
                    "the payment configuration could not be loaded".to_owned(),
                )
            })
        })
        .transpose()?;
    registry_adapter_core::record_endpoint_posture(&runtime.config.endpoints, &mut runtime.posture);
    let mut readiness_posture = runtime.posture.ready_member();
    if let Some(payments) = &payments {
        let settings = readiness_posture
            .get_mut("developmentSettings")
            .and_then(serde_json::Value::as_array_mut);
        let mut payment_ready = payments.posture.ready_member();
        if let (Some(settings), Some(serde_json::Value::Array(payment_settings))) =
            (settings, payment_ready.remove("developmentSettings"))
        {
            let file = payments_path.and_then(std::path::Path::file_name);
            settings.extend(payment_settings.into_iter().map(|mut setting| {
                if let Some(file) = file {
                    setting["file"] = serde_json::json!(file.to_string_lossy());
                }
                setting
            }));
        }
    }
    if let Some((payments, file)) = payments.as_ref().zip(payments_path) {
        let file = std::fs::canonicalize(file).unwrap_or_else(|_| file.to_path_buf());
        runtime
            .posture
            .log_startup_with_files(&path, &[(&payments.posture, &file)]);
    } else {
        runtime.posture.log_startup_with_files(&path, &[]);
    }
    Ok((runtime, payments, readiness_posture))
}

async fn run_facade(
    project_directory: &std::path::Path,
    profile_path: Option<&std::path::Path>,
    pack_path: Option<&std::path::Path>,
    runtime_path: &std::path::Path,
    payments_path: Option<&std::path::Path>,
    payment_provider_pack: &[std::path::PathBuf],
    declared: registry_platform_config::DeclaredPosture,
) -> Result<(), ServeError> {
    let (runtime, payments, readiness_posture) =
        load_serve_configuration(runtime_path, payments_path, declared)?;
    let loaded = crate::engine::load::load_with_target_from_runtime(
        project_directory,
        profile_path,
        pack_path,
        runtime_path,
        runtime,
        crate::govstack::target_attachment,
    )?;
    check_database(&loaded.runtime.database)?;
    for unserved in &loaded.unserved {
        tracing::warn!(binding = %unserved.binding, reason = %unserved.reason,
            reason_code = unserved.reason_code, "binding not served");
    }
    if loaded.served.is_empty() {
        return Err(ServeError::Configuration(
            "no binding is servable by this runtime".to_owned(),
        ));
    }
    let effective_contract = EffectiveContract::from_loaded(&loaded)
        .map_err(|error| ServeError::Configuration(error.to_string()))?;
    let serves_write = loaded.served.iter().any(|served| {
        loaded
            .profile
            .operations
            .get(served.operation.as_str())
            .is_some_and(|operation| !operation.is_read())
    });
    let serves_fixed_write = loaded
        .served
        .iter()
        .any(|served| served.write_support.is_some());
    for operation in loaded.served.iter().filter(|served| {
        matches!(
            served.write_support.as_ref(),
            Some(registry_adapter_core::SourceWriteSupport::ConditionalUpdateOne { .. })
        )
    }) {
        let metadata = crate::govstack::write::metadata::resolve_runtime_write(&loaded, operation)
            .map_err(|_| {
                ServeError::Configuration(
                    "a served fixed conditional Write operation requires its exact served companion read"
                        .to_owned(),
                )
            })?;
        if metadata.companion_read.is_none() {
            return Err(ServeError::Configuration(
                "a served fixed conditional Write operation requires its exact served companion read"
                    .to_owned(),
            ));
        }
    }
    let authenticator = authenticator(&loaded.runtime, &loaded.resolver).await?;
    // Every secret the runtime reads resolves before the listener binds.
    let codec = codec(&loaded.runtime, &loaded.resolver)?;
    if serves_fixed_write && codec.is_none() {
        return Err(ServeError::Configuration(
            "cursorKeyRef is required when a fixed GovStack Write operation is served; configure one exact 32-byte key reference for opaque write guards and cursors"
                .to_owned(),
        ));
    }
    let declares_recovery = loaded
        .served
        .iter()
        .any(|served| served.async_completion.is_some() || served.resume.is_some());
    let declares_resume = loaded.served.iter().any(|served| served.resume.is_some());
    // A configuration this refuses grants nothing: it settles before any
    // database work.
    let response_retention_seconds = if serves_write {
        let retention = loaded.runtime.idempotency.ok_or_else(|| {
            ServeError::Configuration(
                "idempotency.responseRetentionSeconds is required when a write is served"
                    .to_owned(),
            )
        })?;
        let seconds = retention.response_retention_seconds.get();
        if loaded.served.iter().any(|served| {
            served
                .write_support
                .as_ref()
                .is_some_and(|support| source_replay_window_seconds(support) < seconds)
        }) {
            return Err(ServeError::Configuration(
                "a source write replay window is shorter than idempotency.responseRetentionSeconds; increase the source replayWindowSeconds or reduce response retention"
                    .to_owned(),
            ));
        }
        Some(seconds)
    } else {
        None
    };
    // The payment configuration, packs and credentials settle before any
    // database work, so a refusal grants nothing.
    let payments = match payments {
        Some(config) => Some(
            crate::payments::http::PreparedPayments::prepare(
                &loaded.runtime,
                config,
                payment_provider_pack,
            )
            .await?,
        ),
        None => None,
    };
    let shutdown = shutdown_signal()?;
    let migration = pool(
        &loaded.runtime.database,
        &loaded.resolver,
        true,
        loaded.development.as_ref(),
    )?;
    let journal = pool(
        &loaded.runtime.database,
        &loaded.resolver,
        false,
        loaded.development.as_ref(),
    )?;
    // Whether the grant step found the runtime role holding everything the
    // deployment requires in the schema the migrations ran in.
    let grants_verified;
    {
        let mut client = migration
            .get()
            .await
            .map_err(|error| ServeError::Configuration(format!("database: {error}")))?;
        journal::migrate(&mut client)
            .await
            .map_err(|error| ServeError::Configuration(format!("journal migration: {error}")))?;
        idempotent::migrate(&mut client).await.map_err(|error| {
            ServeError::Configuration(format!("idempotency migration: {error}"))
        })?;
        if payments.is_some() {
            crate::payments::http::PreparedPayments::migrate(&mut client).await?;
        }
        let mut required = Requirements {
            tables: runtime_requirements(serves_write, declares_recovery, declares_resume),
            sequences: Vec::new(),
        };
        if let Some(payments) = &payments {
            required.extend(payments.requirements());
        }
        grants_verified = grant_when_split(&mut client, &journal, &required).await?;
    }
    {
        // A runtime role that lacks a grant this deployment uses is refused
        // here, not at its first journal write, write claim or retention tick.
        let client = journal
            .get()
            .await
            .map_err(|error| ServeError::Configuration(format!("database runtime: {error}")))?;
        let required = runtime_requirements(serves_write, declares_recovery, declares_resume);
        let mut lacking = Vec::new();
        for (table, privileges) in required {
            let missing = journal::missing_table_privileges(&client, table, privileges)
                .await
                .map_err(|error| {
                    ServeError::Configuration(format!("runtime privileges: {error}"))
                })?;
            if !missing.is_empty() {
                lacking.push(format!("{} on {table}", missing.join(", ")));
            }
        }
        if !lacking.is_empty() {
            let remedy = if grants_verified {
                "the role holds them in the schema the migrations ran in, so the runtime session's search path most likely resolves a different schema; point the runtime database URL's search path at the migration schema"
            } else {
                "grant them to the runtime role"
            };
            return Err(ServeError::Configuration(format!(
                "database: the runtime role lacks {}; {remedy} (https://docs.registrystack.org/operate/adapter/#grant-the-runtime-database-role lists every grant)",
                lacking.join("; lacks "),
            )));
        }
    }
    let journal_window = journal_retention(loaded.runtime.audit.retention_days.get());
    let journal_sweep_pool = journal.clone();
    let idempotency = response_retention_seconds
        .map(|seconds| {
            PostgresIdempotencyStore::new(journal.clone(), Duration::from_secs(seconds))
                .map(|store| (store, Duration::from_secs(seconds)))
                .map_err(|error| ServeError::Configuration(format!("idempotency: {error}")))
        })
        .transpose()?;
    let artifact_digest = loaded_artifact_digest(&loaded.deployment)?;
    // Only a deployment that declares an asynchronous or resumable write
    // touches the durable artifact fence. Activation advances it and is
    // refused while another artifact still owns unfinished recovery work for
    // this deployment. A synchronous or read-only successor leaves the fence
    // alone: it mints no recovery authority, and it answers an older
    // artifact's status links as unknown because each row is bound to its
    // own artifact digest.
    if let (true, Some((store, _))) = (declares_recovery, idempotency.as_ref()) {
        store
            .ensure_async_artifact_compatible(
                loaded.runtime.id.as_str(),
                artifact_digest,
                SystemTime::now(),
            )
            .await
            .map_err(|error| {
                ServeError::Configuration(format!("asynchronous artifact custody: {error}"))
            })?;
    }
    let async_recovery = async_recovery_admission(&loaded)?;
    let async_retention = idempotency.as_ref().map(|(_, retention)| *retention);
    let facade_idempotency = idempotency.as_ref().map(|(store, _)| store.clone());
    let payments_router = match payments {
        Some(payments) => Some(payments.into_router(journal.clone()).await?),
        None => None,
    };
    let address: SocketAddr = loaded.runtime.listener.bind.0;
    let listener = TcpListener::bind(address)
        .await
        .map_err(|error| ServeError::Bind(error.to_string()))?;
    let local = listener
        .local_addr()
        .map_err(|error| ServeError::Bind(error.to_string()))?;
    for operation in &loaded.served {
        tracing::info!(operation = %operation.operation, binding = %operation.binding, "serving");
    }
    tracing::info!(address = %local, "listening");
    let metrics = Arc::new(Metrics::default());
    let metrics_for_server = Arc::clone(&metrics);
    let metrics_listener = match &loaded.runtime.metrics_listener {
        Some(configured) => {
            let metrics_address = configured.bind.socket_addr();
            if let Some(cause) = registry_adapter_core::metrics_bind_overlap(
                metrics_address,
                "facade listener",
                address,
            ) {
                return Err(ServeError::Configuration(format!(
                    "metricsListener.bind must differ from listener.bind. {}",
                    cause.remedy(registry_adapter_core::METRICS_NETWORK_EXPOSURE_KEY)
                )));
            }
            let bound = TcpListener::bind(metrics_address)
                .await
                .map_err(|error| ServeError::Bind(format!("metrics listener: {error}")))?;
            let metrics_local = bound
                .local_addr()
                .map_err(|error| ServeError::Bind(error.to_string()))?;
            tracing::info!(address = %metrics_local, "serving metrics");
            Some(bound)
        }
        None => None,
    };
    let state = Arc::new(FacadeState {
        metrics: Arc::clone(&metrics),
        codec,
        loaded,
        readiness_posture,
        effective_contract,
        authenticator,
        journal,
        idempotency: facade_idempotency,
        artifact_digest,
        async_retention,
        async_recovery,
    });
    let (shutdown_sender, shutdown_receiver) = watch::channel(false);
    let mut server_shutdown = shutdown_receiver.clone();
    let routes = match payments_router {
        Some(payments) => router(state).merge(payments),
        None => router(state),
    }
    .layer(registry_platform_httpsec::refusal_detail::name_failed_check(declared.posture))
    .layer(registry_platform_httpsec::posture_mark(declared.posture));
    let serving = axum::serve(listener, routes).with_graceful_shutdown(async move {
        let _closed = server_shutdown.changed().await;
    });
    let mut metrics_shutdown = shutdown_receiver.clone();
    let metrics_serving = async move {
        match metrics_listener {
            Some(bound) => {
                crate::metrics::serve(
                    bound,
                    Arc::clone(&metrics_for_server),
                    async move {
                        let _closed = metrics_shutdown.changed().await;
                    },
                    crate::metrics::METRICS_SHUTDOWN_TIMEOUT,
                    declared.posture,
                )
                .await
            }
            None => Ok(()),
        }
    };
    let metrics_serving = async move { tolerate_metrics_shutdown_timeout(metrics_serving.await) };
    let server = async move { tokio::try_join!(serving, metrics_serving).map(|_| ()) };
    let journal_sweep = sweep_journal_events(
        journal_sweep_pool,
        journal_window,
        Arc::clone(&metrics),
        shutdown_receiver.clone(),
    );
    let sweeper = async move {
        match idempotency {
            Some((store, retention)) => tokio::try_join!(
                journal_sweep,
                sweep_idempotency_responses(
                    store,
                    retention_cadence(retention),
                    Arc::clone(&metrics),
                    shutdown_receiver,
                ),
            )
            .map(|_| ()),
            None => journal_sweep.await,
        }
    };
    tokio::pin!(server);
    tokio::pin!(sweeper);
    tokio::select! {
        result = &mut server => {
            shutdown_sender.send(true).map_err(|_| ServeError::Serve("the retention supervisor stopped before the server".to_owned()))?;
            result.map_err(|error| ServeError::Serve(error.to_string()))?;
            sweeper.await
        }
        result = &mut sweeper => {
            let failure = result;
            shutdown_sender.send(true).map_err(|_| ServeError::Serve("the server supervisor stopped before retention".to_owned()))?;
            server.await.map_err(|error| ServeError::Serve(error.to_string()))?;
            failure
        }
        () = shutdown => {
            shutdown_sender.send(true).map_err(|_| ServeError::Serve("the server shutdown channel closed".to_owned()))?;
            let server_result = server.await.map_err(|error| ServeError::Serve(error.to_string()));
            let sweeper_result = sweeper.await;
            server_result?;
            sweeper_result
        }
    }
}

/// A metrics client that outlives the metrics listener's shutdown deadline is
/// logged and dropped. It must not end the join with the facade listener, which
/// would cut off the facade's in-flight requests.
fn tolerate_metrics_shutdown_timeout(result: std::io::Result<()>) -> std::io::Result<()> {
    match result {
        Err(error) if error.kind() == std::io::ErrorKind::TimedOut => {
            tracing::warn!(%error, "the metrics listener was cut off at the shutdown deadline");
            Ok(())
        }
        other => other,
    }
}

#[cfg(test)]
pub(crate) fn test_runtime(mut value: serde_json::Value) -> AdapterRuntimeConfig {
    use registry_platform_config::{
        DeclaredPosture, Posture, PostureSource, RuntimeConfigLoader, RuntimeEnvelope,
    };
    let envelope = RuntimeEnvelope {
        api_version: registry_adapter_core::ADAPTER_RUNTIME_API_VERSION,
        kind: registry_adapter_core::ADAPTER_RUNTIME_KIND,
    };
    value["apiVersion"] = serde_json::json!(envelope.api_version);
    value["kind"] = serde_json::json!(envelope.kind);
    RuntimeConfigLoader::new(
        envelope,
        DeclaredPosture {
            posture: Posture::Production,
            source: PostureSource::Flag,
        },
    )
    .parse_str::<AdapterRuntimeConfig>(&value.to_string(), |_| None)
    .unwrap_or_else(|error| panic!("runtime: {:?}", error.diagnostics()))
    .config
}

#[cfg(test)]
mod token_characterisation;

#[cfg(test)]
mod tests {
    use super::*;

    const STAFF_ISSUER: &str = "https://staff.example.test";
    const PARTNER_ISSUER: &str = "https://partner.example.test";

    async fn issuer_fixture(
        extra: serde_json::Value,
        second: bool,
    ) -> (
        Authenticator,
        registry_platform_crypto::PrivateJwk,
        registry_platform_crypto::PrivateJwk,
    ) {
        use registry_platform_testing::access_token_test_key;
        let staff = access_token_test_key(jsonwebtoken::Algorithm::ES256);
        let partner = access_token_test_key(jsonwebtoken::Algorithm::RS256);
        let auth =
            issuer_fixture_with_ids(extra, second, ["staff", "partner"], [&staff, &partner]).await;
        (auth, staff, partner)
    }

    async fn issuer_fixture_with_ids(
        extra: serde_json::Value,
        second: bool,
        ids: [&str; 2],
        keys: [&registry_platform_crypto::PrivateJwk; 2],
    ) -> Authenticator {
        use registry_platform_testing::jwks_from_private_jwk;
        use serde_json::json;
        use std::os::unix::fs::PermissionsExt;

        let [staff_id, partner_id] = ids;
        let directory = tempfile::tempdir().expect("key directory");
        let root = directory.path().canonicalize().expect("physical directory");
        for (name, key) in ["staff", "partner"].into_iter().zip(keys) {
            let file = root.join(format!("{name}.json"));
            std::fs::write(&file, jwks_from_private_jwk(key).to_string()).expect("write key set");
            std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600))
                .expect("owner-only key file");
        }
        let mut runtime = json!({
            "id": "caller-contract",
            "endpoints": [],
            "listener": {"bind": "127.0.0.1:8080"},
            "database": {"runtimeUrlRef": "secret:env/DB", "migrationUrlRef": "secret:env/DB"},
            "oidc": {"issuers": {
                (staff_id): {
                    "issuer": STAFF_ISSUER,
                    "audience": "staff-api",
                    "allowedClients": ["staff-client"],
                    "jwksSource": {"type": "static", "documentRef": "secret:file/staff.json"}
                }
            }},
            "allowedPrivateCidrs": ["10.0.0.0/8"],
            "audit": {"retentionDays": 90}
        });
        runtime["oidc"]["issuers"][staff_id]
            .as_object_mut()
            .expect("issuer object")
            .extend(extra.as_object().expect("issuer overrides").clone());
        if second {
            runtime["oidc"]["issuers"][partner_id] = json!({
                "issuer": PARTNER_ISSUER,
                "audience": "staff-api",
                "allowedClients": ["partner-client"],
                "scopeClaim": "scp",
                "jwksSource": {"type": "static", "documentRef": "secret:file/partner.json"}
            });
        }
        let config = test_runtime(runtime);
        let resolver = SecretResolver::new([registry_platform_config::SecretProvider::File], root)
            .expect("resolver");
        authenticator(&config, &resolver)
            .await
            .expect("authenticator")
    }

    fn issuer_token(
        key: &registry_platform_crypto::PrivateJwk,
        typ: &str,
        issuer: &str,
        overrides: serde_json::Value,
    ) -> String {
        use serde_json::json;
        let now = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("clock after epoch")
            .as_secs();
        let (audience, client) = if issuer == PARTNER_ISSUER {
            ("staff-api", "partner-client")
        } else {
            ("staff-api", "staff-client")
        };
        let mut claims = json!({
            "iss": issuer, "aud": audience, "client_id": client, "sub": "subject",
            "iat": now, "nbf": now, "exp": now + 120, "scope": "records.read", "jti": "request"
        });
        claims
            .as_object_mut()
            .expect("claims object")
            .extend(overrides.as_object().expect("claim overrides").clone());
        registry_platform_testing::sign_compact_jwt_with_key(
            key,
            typ,
            "canary-resource-key",
            claims,
        )
    }

    #[tokio::test]
    async fn a_token_from_each_configured_issuer_is_verified_under_its_own_rules() {
        use serde_json::json;
        let (auth, staff, partner) = issuer_fixture(json!({}), true).await;
        let staff_token = issuer_token(&staff, "application/at+jwt", STAFF_ISSUER, json!({}));
        let partner_token = issuer_token(
            &partner,
            "at+jwt",
            PARTNER_ISSUER,
            json!({"scp": "partner.read"}),
        );
        let staff = auth.authenticate(&staff_token).await.expect("staff caller");
        let partner = auth
            .authenticate(&partner_token)
            .await
            .expect("partner caller");
        assert_eq!(
            (staff.issuer.as_str(), staff.client_id.as_str()),
            (STAFF_ISSUER, "staff-client")
        );
        assert_eq!(staff.scopes, ["records.read"]);
        assert_eq!(&*staff.scope_claim, "scope");
        assert_eq!(
            (partner.issuer.as_str(), partner.client_id.as_str()),
            (PARTNER_ISSUER, "partner-client")
        );
        assert_eq!(partner.scopes, ["partner.read"]);
        assert_eq!(&*partner.scope_claim, "scp");
    }

    #[tokio::test]
    async fn a_jwt_typed_token_is_admitted_when_the_issuer_states_it() {
        use serde_json::json;
        let (auth, staff, _) = issuer_fixture(json!({"accessTokenType": "JWT"}), false).await;
        let token = issuer_token(&staff, "JWT", STAFF_ISSUER, json!({}));
        assert!(auth.authenticate(&token).await.is_ok());
    }

    #[tokio::test]
    async fn an_id_token_is_refused_whether_or_not_jwt_is_admitted() {
        use serde_json::json;
        for (typ, config) in [
            ("JWT", json!({})),
            ("JWT", json!({"accessTokenType": "JWT"})),
        ] {
            let (auth, staff, _) = issuer_fixture(config, false).await;
            let token = issuer_token(&staff, typ, STAFF_ISSUER, json!({"nonce": "sample"}));
            assert_eq!(
                auth.authenticate(&token)
                    .await
                    .err()
                    .map(CallerRefusal::failed_check),
                Some(FailedCheck::TokenType),
            );
        }
    }

    #[tokio::test]
    async fn a_declared_client_kind_admits_a_token_without_a_kind() {
        use serde_json::json;
        let (auth, staff, _) = issuer_fixture(
            json!({"clientActorKinds": {"staff-client": "service"}}),
            false,
        )
        .await;
        let token = issuer_token(&staff, "at+jwt", STAFF_ISSUER, json!({"scope": "openid"}));
        assert!(auth.authenticate(&token).await.is_ok());
    }

    #[tokio::test]
    async fn a_token_kind_that_contradicts_the_declared_kind_is_refused() {
        use serde_json::json;
        let (auth, staff, _) = issuer_fixture(json!({"actorKind": "service"}), false).await;
        let token = issuer_token(
            &staff,
            "at+jwt",
            STAFF_ISSUER,
            json!({"registry_actor_kind": "human"}),
        );
        assert_eq!(
            auth.authenticate(&token)
                .await
                .err()
                .map(CallerRefusal::failed_check),
            Some(FailedCheck::ActorKind),
        );
    }

    #[tokio::test]
    async fn an_unlisted_client_is_refused() {
        use serde_json::json;
        let (auth, staff, _) = issuer_fixture(json!({}), true).await;
        let token = issuer_token(
            &staff,
            "at+jwt",
            STAFF_ISSUER,
            json!({"client_id": "unknown"}),
        );
        assert_eq!(
            auth.authenticate(&token)
                .await
                .err()
                .map(CallerRefusal::failed_check),
            Some(FailedCheck::TokenClient),
        );
    }

    #[tokio::test]
    async fn an_identity_only_token_is_refused_without_a_declared_kind() {
        use serde_json::json;
        let (auth, staff, _) = issuer_fixture(json!({}), false).await;
        let token = issuer_token(
            &staff,
            "at+jwt",
            STAFF_ISSUER,
            json!({
                "scope": "openid profile email address phone offline_access"
            }),
        );
        assert_eq!(
            auth.authenticate(&token)
                .await
                .err()
                .map(CallerRefusal::failed_check),
            Some(FailedCheck::ActorKind),
        );
    }

    #[tokio::test]
    async fn a_token_client_listed_only_by_the_other_issuer_is_refused() {
        use serde_json::json;
        let (auth, _, partner) = issuer_fixture(json!({}), true).await;
        let token = issuer_token(
            &partner,
            "at+jwt",
            PARTNER_ISSUER,
            json!({
                "client_id": "staff-client", "scp": "payments:collections"
            }),
        );
        assert_eq!(
            auth.authenticate(&token)
                .await
                .err()
                .map(CallerRefusal::failed_check),
            Some(FailedCheck::TokenClient),
        );
    }

    #[tokio::test]
    async fn an_exchanged_token_from_either_issuer_is_refused() {
        use serde_json::json;
        let (auth, staff, partner) = issuer_fixture(json!({}), true).await;
        for (key, issuer) in [(&staff, STAFF_ISSUER), (&partner, PARTNER_ISSUER)] {
            let token = issuer_token(
                key,
                "at+jwt",
                issuer,
                json!({
                    (ASSERTION_ISSUER_CLAIM): "https://assertion.example.test",
                    "scp": "records.read"
                }),
            );
            assert_eq!(
                auth.authenticate(&token)
                    .await
                    .err()
                    .map(CallerRefusal::failed_check),
                Some(FailedCheck::TokenAssertionIssuer),
            );
        }
    }

    const STARTUP_PREFIX: &str = "\
apiVersion: id.registrystack.org/formats/adapter/runtime/v1alpha1
kind: AdapterRuntimeConfig
id: callers
endpoints: []
listener: {bind: '127.0.0.1:8080'}
database: {runtimeUrlRef: 'secret:env/DB', migrationUrlRef: 'secret:env/DB'}
allowedPrivateCidrs: ['10.0.0.0/8']
audit: {retentionDays: 90}
";

    fn startup_refusal(oidc: &str) -> String {
        let directory = tempfile::tempdir().expect("runtime directory");
        let file = directory.path().join("runtime.yaml");
        std::fs::write(&file, format!("{STARTUP_PREFIX}{oidc}")).expect("runtime file");
        let declared = registry_platform_config::DeclaredPosture {
            posture: registry_platform_config::Posture::Production,
            source: registry_platform_config::PostureSource::Flag,
        };
        match load_serve_configuration(&file, None, declared) {
            Err(ServeError::Configuration(message)) => message,
            _ => panic!("expected configuration refusal"),
        }
    }

    #[test]
    fn two_issuers_cannot_list_the_same_client_at_startup() {
        let message = startup_refusal(
            "oidc:\n  issuers:\n    staff: {issuer: 'https://staff.example.test', audience: api, allowedClients: [shared-client]}\n    partner: {issuer: 'https://partner.example.test', audience: api, allowedClients: [shared-client]}\n",
        );
        assert!(
            message.contains("platform.oidc.client-in-two-issuers"),
            "{message}"
        );
        assert!(
            message.contains("/oidc/issuers/staff/allowedClients/0"),
            "{message}"
        );
    }

    #[test]
    fn test_issuer_key_source_requires_development_at_startup() {
        let oidc = "oidc:\n  issuers:\n    staff: {issuer: 'https://staff.example.test', audience: api, allowedClients: [staff-client], jwksSource: {type: test-issuer, documentRef: 'secret:env/TEST_JWKS'}}\n";
        let message = startup_refusal(oidc);
        assert!(
            message.contains("platform.posture.test-issuer"),
            "{message}"
        );
        assert!(
            message.contains("/oidc/issuers/staff/jwksSource"),
            "{message}"
        );

        let directory = tempfile::tempdir().unwrap();
        let file = directory.path().join("runtime.yaml");
        std::fs::write(&file, format!("{STARTUP_PREFIX}{oidc}")).unwrap();
        let declared = registry_platform_config::DeclaredPosture {
            posture: registry_platform_config::Posture::Development,
            source: registry_platform_config::PostureSource::Flag,
        };
        assert!(load_serve_configuration(&file, None, declared).is_ok());
    }

    #[tokio::test]
    async fn journal_caller_reference_keeps_the_single_issuer_subject() {
        let (auth, staff, _) = issuer_fixture(serde_json::json!({}), false).await;
        let token = issuer_token(&staff, "at+jwt", STAFF_ISSUER, serde_json::json!({}));
        let caller = auth.authenticate(&token).await.unwrap();
        assert_eq!(auth.journal_reference(&caller), "subject");
    }

    #[tokio::test]
    async fn journal_caller_references_depend_on_issuer_urls_instead_of_entry_ids() {
        use serde_json::json;

        let (auth, staff, partner) = issuer_fixture(json!({}), true).await;
        let staff_token = issuer_token(&staff, "at+jwt", STAFF_ISSUER, json!({}));
        let partner_token = issuer_token(
            &partner,
            "at+jwt",
            PARTNER_ISSUER,
            json!({"scp": "records.read"}),
        );
        async fn references(auth: &Authenticator, first: &str, second: &str) -> [String; 2] {
            [
                auth.journal_reference(&auth.authenticate(first).await.unwrap()),
                auth.journal_reference(&auth.authenticate(second).await.unwrap()),
            ]
        }
        let original = references(&auth, &staff_token, &partner_token).await;
        assert_ne!(original[0], original[1]);

        let renamed =
            issuer_fixture_with_ids(json!({}), true, ["alpha", "zulu"], [&staff, &partner]).await;
        assert_eq!(
            references(&renamed, &staff_token, &partner_token).await,
            original
        );
    }

    #[test]
    fn two_issuers_with_the_same_iss_refuse_at_startup() {
        let message = startup_refusal(
            "oidc:\n  issuers:\n    staff: {issuer: 'https://staff.example.test', audience: api, allowedClients: [staff-client]}\n    partner: {issuer: 'https://staff.example.test', audience: api, allowedClients: [partner-client]}\n",
        );
        assert!(
            message.contains("platform.oidc.duplicate-issuer"),
            "{message}"
        );
        assert!(message.contains("/oidc/issuers/staff/issuer"), "{message}");
    }

    #[test]
    fn issuer_entries_with_different_audiences_are_refused_at_startup() {
        let message = startup_refusal(
            "oidc:\n  issuers:\n    staff: {issuer: 'https://staff.example.test', audience: staff-api, allowedClients: [staff-client]}\n    partner: {issuer: 'https://partner.example.test', audience: partner-api, allowedClients: [partner-client]}\n",
        );
        assert!(
            message.contains("platform.oidc.audiences-differ"),
            "{message}"
        );
        assert!(
            message.contains("published effective contract"),
            "{message}"
        );
    }

    #[test]
    fn moved_oidc_members_name_their_place_in_the_issuer_entry() {
        for (key, value) in [
            ("issuer", "https://legacy.example.test"),
            ("audience", "legacy-api"),
            ("jwksSource", "{type: discovery}"),
            ("allowInsecureHttp", "false"),
        ] {
            let message = startup_refusal(&format!("oidc:\n  {key}: {value}\n"));
            assert!(message.contains(&format!("/oidc/{key}")), "{message}");
            assert!(
                message.contains("Declare it under oidc.issuers.ISSUER_ID."),
                "{message}"
            );
        }
        let message = startup_refusal("allowedClients: [legacy]\n");
        assert!(message.contains("/allowedClients"), "{message}");
        assert!(
            message.contains("Declare it under oidc.issuers.ISSUER_ID.allowedClients."),
            "{message}"
        );
    }

    #[test]
    fn unrestricted_clients_is_refused_at_the_issuer_entry() {
        let message = startup_refusal(
            "oidc:\n  issuers:\n    staff: {issuer: 'https://staff.example.test', audience: api, allowedClients: unrestricted}\n",
        );
        assert!(
            message.contains("/oidc/issuers/staff/allowedClients"),
            "{message}"
        );
    }

    #[tokio::test]
    async fn a_jwt_typed_token_is_refused_by_default_and_the_log_names_the_setting() {
        use serde_json::json;
        let (auth, staff, _) = issuer_fixture(json!({}), false).await;
        let token = issuer_token(&staff, "JWT", STAFF_ISSUER, json!({}));
        let refusal = auth
            .authenticate(&token)
            .await
            .err()
            .expect("token refused");
        assert_eq!(refusal.failed_check(), FailedCheck::TokenType);
        let recorder = registry_platform_authcommon::RefusalRecorder::new("adapter").unwrap();
        let log = CapturedLog::default();
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(log.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            registry_platform_authcommon::record_refusal!(recorder, refusal.note());
        });
        let line = String::from_utf8(log.0.lock().unwrap().clone()).unwrap();
        assert!(line.contains("accessTokenType"), "{line}");
        assert!(!line.contains(&token), "{line}");
    }

    #[tokio::test]
    async fn a_token_without_a_kind_authenticates_as_unspecified() {
        use serde_json::json;
        let (auth, staff, _) = issuer_fixture(json!({}), false).await;
        let token = issuer_token(&staff, "at+jwt", STAFF_ISSUER, json!({}));
        assert!(auth.authenticate(&token).await.is_ok());
        assert_eq!(
            auth.issuers.verify(&token).await.expect("verified").kind,
            registry_platform_oidc::CallerKind::Unspecified,
        );
    }

    fn static_key_runtime() -> AdapterRuntimeConfig {
        test_runtime(serde_json::json!({
            "id": "static-key-set",
            "endpoints": [{"endpoint": "tracker", "baseUrl": "https://tracker.example.invalid"}],
            "listener": {"bind": "127.0.0.1:8080"},
            "database": {
                "runtimeUrlRef": "secret:file/database-runtime",
                "migrationUrlRef": "secret:file/database-migration"
            },
            "oidc": {"issuers": {"primary": {
                "issuer": "https://issuer.example.test",
                "audience": "registry-adapter-test",
                "jwksSource": {"type": "static", "documentRef": "secret:file/issuer-keys.json"},
                "allowedClients": ["coordinator"]
            }}},
            "allowedPrivateCidrs": ["10.0.0.0/8"],
            "audit": {"retentionDays": 90}
        }))
    }

    async fn authenticator_over(keys: &serde_json::Value) -> Result<Authenticator, ServeError> {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().expect("a scratch directory");
        let root = directory.path().canonicalize().expect("physical directory");
        let file = root.join("issuer-keys.json");
        std::fs::write(&file, keys.to_string()).expect("write the key set");
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600))
            .expect("owner-only key file");
        let resolver = SecretResolver::new([registry_platform_config::SecretProvider::File], root)
            .expect("resolver");
        authenticator(&static_key_runtime(), &resolver).await
    }

    #[cfg(not(feature = "postgres-test"))]
    #[test]
    fn outside_test_builds_plaintext_requires_an_explicit_transport() {
        let mut runtime = static_key_runtime();
        runtime.database.test_only_plaintext = true;
        let resolver =
            SecretResolver::new([registry_platform_config::SecretProvider::Environment], "")
                .unwrap();
        let error = pool(&runtime.database, &resolver, false, None)
            .expect_err("test-only transport must refuse");
        assert!(
            error
                .to_string()
                .contains("platform.database.test-only-plaintext"),
            "{error}"
        );
    }

    #[test]
    fn loopback_database_transport_refuses_a_private_network_host() {
        use std::os::unix::fs::PermissionsExt;
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path().canonicalize().unwrap();
        let file = root.join("database-runtime");
        std::fs::write(&file, "postgresql://test@10.0.0.5/registry").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let resolver =
            SecretResolver::new([registry_platform_config::SecretProvider::File], root).unwrap();
        let mut runtime = static_key_runtime();
        runtime.database.transport = Some(
            registry_platform_config::Gated::everywhere(
                registry_platform_config::DatabaseTransport::LoopbackPlaintext,
            )
            .unwrap(),
        );
        let error = pool(&runtime.database, &resolver, false, None)
            .expect_err("loopback plaintext must refuse the private host");
        assert!(
            error
                .to_string()
                .contains("platform.database.transport-host-mismatch"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn a_static_key_set_with_a_private_member_is_refused_with_the_rule_text() {
        let private =
            registry_platform_testing::access_token_test_key(jsonwebtoken::Algorithm::ES256);
        let mut keys = registry_platform_testing::jwks_from_private_jwk(&private);
        keys["keys"][0]["d"] = serde_json::json!("AQAB");
        let Err(ServeError::Configuration(text)) = authenticator_over(&keys).await else {
            panic!("a key set holding a private member is refused");
        };
        assert!(
            text.contains("not a usable key set"),
            "the refusal names the key set: {text}"
        );
        assert!(
            text.len() > "oidc: the static key document is not a usable key set: ".len(),
            "the rule text follows: {text}"
        );
        assert!(!text.contains("AQAB"), "no key value in the text: {text}");
    }

    #[tokio::test]
    async fn a_static_key_set_with_a_public_ext_member_loads() {
        let private =
            registry_platform_testing::access_token_test_key(jsonwebtoken::Algorithm::ES256);
        let mut keys = registry_platform_testing::jwks_from_private_jwk(&private);
        keys["keys"][0]["ext"] = serde_json::json!(true);
        authenticator_over(&keys)
            .await
            .map(|_| ())
            .expect("a public key set with ext loads");
    }

    #[test]
    fn runtime_requirements_follow_the_deployment_feature_set() {
        const JOURNAL: (&str, &[&str]) =
            ("adapter_journal_events", &["INSERT", "SELECT", "DELETE"]);
        const LEDGER: (&str, &[&str]) = ("adapter_schema_migrations", &["SELECT"]);
        const ENTRIES: (&str, &[&str]) = (
            "adapter_idempotency_entries",
            &["SELECT", "INSERT", "UPDATE", "DELETE"],
        );
        const RESUMES: (&str, &[&str]) = (
            "adapter_idempotency_resumes",
            &["SELECT", "INSERT", "UPDATE", "DELETE"],
        );
        const ARTIFACTS: (&str, &[&str]) = (
            "adapter_idempotency_async_artifacts",
            &["SELECT", "INSERT", "UPDATE"],
        );
        const BINDINGS: (&str, &[&str]) =
            ("adapter_idempotency_resume_bindings", &["SELECT", "INSERT"]);
        assert_eq!(runtime_requirements(false, false, false), [JOURNAL, LEDGER]);
        assert_eq!(
            runtime_requirements(true, false, false),
            [JOURNAL, LEDGER, ENTRIES, RESUMES]
        );
        assert_eq!(
            runtime_requirements(true, true, false),
            [JOURNAL, LEDGER, ENTRIES, RESUMES, ARTIFACTS]
        );
        assert_eq!(
            runtime_requirements(true, true, true),
            [JOURNAL, LEDGER, ENTRIES, RESUMES, ARTIFACTS, BINDINGS]
        );
        assert!(runtime_requirements(true, true, true)
            .iter()
            .all(|(table, _)| *table != "adapter_idempotency_schema_migrations"));
    }

    #[test]
    fn payment_requirements_follow_what_the_payment_host_checks() {
        let collections = Requirements::payments(false);
        assert_eq!(
            collections.tables,
            crate::payments::store::RUNTIME_GRANTS.to_vec()
        );
        assert_eq!(
            collections.sequences,
            ["adapter_payment_events_sequence_seq"]
        );
        let both = Requirements::payments(true);
        assert_eq!(both.tables.len(), 6);
        assert!(both
            .tables
            .iter()
            .any(|(table, privileges)| *table == "adapter_g2p_attempts"
                && *privileges == ["SELECT", "INSERT", "UPDATE"]));
        assert_eq!(
            both.sequences,
            [
                "adapter_payment_events_sequence_seq",
                "adapter_g2p_events_sequence_seq"
            ]
        );
    }

    #[test]
    fn a_role_name_is_quoted_as_one_identifier() {
        assert_eq!(quote_identifier("runtime"), "\"runtime\"");
        assert_eq!(
            quote_identifier("a\"; DROP ROLE x; --"),
            "\"a\"\"; DROP ROLE x; --\""
        );
    }

    #[test]
    fn a_metrics_shutdown_timeout_is_not_fatal_but_other_faults_are() {
        let timed_out = std::io::Error::new(std::io::ErrorKind::TimedOut, "stalled client");
        assert!(tolerate_metrics_shutdown_timeout(Err(timed_out)).is_ok());
        let fault = std::io::Error::other("accept failed");
        assert!(tolerate_metrics_shutdown_timeout(Err(fault)).is_err());
        assert!(tolerate_metrics_shutdown_timeout(Ok(())).is_ok());
    }

    use std::collections::VecDeque;
    use std::sync::Mutex;

    #[test]
    fn the_facade_accepts_exactly_rs256_and_es256_access_tokens() {
        assert_eq!(
            accepted_algorithms(),
            vec![
                jsonwebtoken::Algorithm::RS256,
                jsonwebtoken::Algorithm::ES256
            ]
        );
    }

    #[test]
    fn a_stop_signal_install_failure_refuses_startup() {
        let error = shutdown_after(|| -> std::io::Result<std::future::Pending<()>> {
            Err(std::io::Error::new(
                std::io::ErrorKind::PermissionDenied,
                "install refused",
            ))
        })
        .expect_err("an install failure is an error, never a silent wait");
        assert!(matches!(error, ServeError::Signal(_)), "{error:?}");
        assert_eq!(
            error.to_string(),
            "the stop signal handler could not be installed: install refused"
        );
    }

    #[tokio::test]
    async fn an_installed_stop_signal_resolves_when_it_fires() {
        let signal = shutdown_after(|| Ok(std::future::ready(()))).expect("installs");
        tokio::time::timeout(Duration::from_secs(5), signal)
            .await
            .expect("a fired signal resolves");
    }

    #[tokio::test]
    async fn a_full_batch_is_followed_at_once_until_one_falls_short() {
        let (sender, receiver) = watch::channel(false);
        let (called, mut calls) = tokio::sync::mpsc::unbounded_channel();
        let batches = Arc::new(Mutex::new(VecDeque::from([10_u64, 10, 3, 10])));
        let sweeping = tokio::spawn(sweep_on_cadence(
            "test",
            Duration::from_secs(3_600),
            10,
            Arc::new(Metrics::default()),
            receiver,
            move || {
                let erased = batches
                    .lock()
                    .expect("the batch list is not poisoned")
                    .pop_front()
                    .expect("the sweep asked for no more batches than listed");
                called.send(erased).expect("the test is listening");
                async move { Ok(erased) }
            },
        ));
        for expected in [10, 10, 3] {
            let erased = tokio::time::timeout(Duration::from_secs(1), calls.recv())
                .await
                .expect("a full batch is followed at once")
                .expect("the sweep is running");
            assert_eq!(erased, expected);
        }
        assert!(
            tokio::time::timeout(Duration::from_millis(100), calls.recv())
                .await
                .is_err(),
            "a short batch waits for the next cadence"
        );
        sender.send(true).expect("the sweep is listening");
        tokio::time::timeout(Duration::from_secs(1), sweeping)
            .await
            .expect("shutdown stays responsive")
            .expect("the sweep task joins")
            .expect("shutdown succeeds");
    }

    #[tokio::test]
    async fn shutdown_interrupts_a_sweep_in_flight() {
        let (sender, receiver) = watch::channel(false);
        let sweeping = tokio::spawn(sweep_on_cadence(
            "test",
            Duration::from_secs(3_600),
            10,
            Arc::new(Metrics::default()),
            receiver,
            std::future::pending::<Result<u64, String>>,
        ));
        tokio::task::yield_now().await;
        sender.send(true).expect("the sweep is listening");
        tokio::time::timeout(Duration::from_secs(1), sweeping)
            .await
            .expect("shutdown stays responsive")
            .expect("the sweep task joins")
            .expect("shutdown succeeds");
    }

    #[derive(Clone, Default)]
    struct CapturedLog(Arc<Mutex<Vec<u8>>>);

    impl std::io::Write for CapturedLog {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0
                .lock()
                .expect("the log is not poisoned")
                .extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for CapturedLog {
        type Writer = CapturedLog;

        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    #[tokio::test]
    async fn a_failed_sweep_is_logged_and_retried_at_the_next_tick() {
        use tracing::instrument::WithSubscriber;

        let log = CapturedLog::default();
        let subscriber = tracing_subscriber::fmt()
            .with_writer(log.clone())
            .with_ansi(false)
            .finish();
        let cadence = Duration::from_millis(50);
        let started = tokio::time::Instant::now();
        let (sender, receiver) = watch::channel(false);
        let (called, mut calls) = tokio::sync::mpsc::unbounded_channel();
        let batches = Arc::new(Mutex::new(VecDeque::from([
            Err("connection refused".to_owned()),
            Err("connection refused".to_owned()),
            Ok(3_u64),
        ])));
        let sweep_metrics = Arc::new(Metrics::default());
        let sweeping = tokio::spawn(
            sweep_on_cadence(
                "journal",
                cadence,
                10,
                Arc::clone(&sweep_metrics),
                receiver,
                move || {
                    let batch = batches
                        .lock()
                        .expect("the batch list is not poisoned")
                        .pop_front()
                        .expect("the sweep asked for no more batches than listed");
                    called
                        .send((tokio::time::Instant::now(), batch.is_ok()))
                        .expect("the test is listening");
                    async move { batch }
                },
            )
            .with_subscriber(subscriber),
        );
        for (tick, succeeded) in [(0_u32, false), (1, false), (2, true)] {
            let (at, ran_ok) = tokio::time::timeout(Duration::from_secs(5), calls.recv())
                .await
                .expect("the sweep runs again at its next tick")
                .expect("the sweep is still running");
            assert_eq!(ran_ok, succeeded);
            assert!(
                at.duration_since(started) >= cadence * tick,
                "batch {tick} ran before its tick, so a failure was retried at once"
            );
        }
        assert!(
            !sweeping.is_finished(),
            "a failed sweep keeps the sweeper running"
        );
        sender.send(true).expect("the sweep is listening");
        tokio::time::timeout(Duration::from_secs(1), sweeping)
            .await
            .expect("shutdown stays responsive")
            .expect("the sweep task joins")
            .expect("shutdown succeeds after failed sweeps");
        assert!(
            sweep_metrics
                .render()
                .lines()
                .any(|line| line == "adapter_retention_sweep_failures_total{store=\"journal\"} 2"),
            "the two failed batches are counted by store"
        );
        let logged = String::from_utf8(log.0.lock().expect("the log is not poisoned").clone())
            .expect("the log is UTF-8");
        let failures = logged
            .lines()
            .filter(|line| {
                line.contains("ERROR")
                    && line.contains("retention sweep failed; retrying at the next tick")
                    && line.contains("store=\"journal\"")
                    && line.contains("connection refused")
            })
            .count();
        assert_eq!(failures, 2, "{logged}");
    }

    #[test]
    fn audit_retention_days_become_the_journal_retention_window() {
        assert_eq!(journal_retention(1), Duration::from_secs(24 * 60 * 60));
        assert_eq!(
            journal_retention(90),
            Duration::from_secs(90 * 24 * 60 * 60)
        );
        assert_eq!(
            journal_retention(3_650),
            Duration::from_secs(3_650 * 24 * 60 * 60)
        );
        assert_eq!(
            retention_cadence(journal_retention(1)),
            Duration::from_secs(60)
        );
    }

    #[test]
    fn response_retention_drives_a_bounded_sweep_cadence() {
        assert_eq!(
            retention_cadence(Duration::from_secs(1)),
            Duration::from_secs(1)
        );
        assert_eq!(
            retention_cadence(Duration::from_secs(120)),
            Duration::from_secs(60)
        );
        assert_eq!(
            retention_cadence(Duration::from_secs(365 * 24 * 60 * 60)),
            Duration::from_secs(60)
        );
    }

    #[test]
    fn source_replay_window_is_read_from_both_fixed_write_guarantees() {
        for (support, expected) in [
            (
                serde_json::json!({"type": "create-one", "replayWindowSeconds": 300}),
                300,
            ),
            (
                serde_json::json!({"type": "conditional-update-one", "replayWindowSeconds": 600}),
                600,
            ),
        ] {
            let support = serde_json::from_value(support).expect("source write support");
            assert_eq!(source_replay_window_seconds(&support), expected);
        }
    }
}
