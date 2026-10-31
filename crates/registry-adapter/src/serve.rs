// SPDX-License-Identifier: Apache-2.0

//! The served process: the OIDC authenticator, the journal's PostgreSQL
//! pool, and the listener. The server refuses to start without OIDC and
//! without PostgreSQL; there is no open mode.

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod, Runtime};
use jsonwebtoken::Algorithm;
use registry_adapter_core::AdapterRuntimeConfig;
use registry_platform_authcommon::validate_compact_access_token;
use registry_platform_config::{
    DatabaseConfig, JwksSource, SecretReference as ConfigSecretReference, SecretResolver,
};
use registry_platform_oidc::{
    access_token_typ_set, fetch_discovery_for_issuer, parse_static_jwks, AuthenticationStage,
    IssuerNetworkPolicy, JwksFetcher, JwksFetcherConfig, OidcDiscoveryConfig, OidcError,
    TokenVerifier, TokenVerifierConfig, ASSERTION_ISSUER_CLAIM,
};
use registry_platform_yaml::SecretReference;
use thiserror::Error;
use tokio::net::TcpListener;
use tokio::sync::watch;
use tokio_postgres::Config as PgConfig;
use zeroize::Zeroizing;

use crate::component::rest::continuation::{ContinuationCodec, CursorKey, CursorTtl};
use crate::effective_contract::EffectiveContract;
use crate::facade::{router, FacadeState};
use crate::idempotent::{
    self, PostgresIdempotencyStore, MAX_CALLER_IDENTITY_BYTES, MAX_CALLER_ISSUER_BYTES,
};
use crate::journal;
use crate::load::{load, LoadError};

/// The access token media type the facade admits (RFC 9068).
const ACCESS_TOKEN_TYPE: &str = "at+jwt";

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
    #[error("the idempotency response-retention sweep stopped: {0}")]
    Retention(String),
}

/// A verified caller.
pub struct Caller {
    /// The verified subject, journaled as the caller reference.
    pub reference: String,
    /// The verified issuer and admitted acting client remain process-local;
    /// the idempotency store receives only their namespace digest.
    pub issuer: String,
    pub client_id: String,
    pub scopes: Vec<String>,
}

/// Why a request has no caller.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CallerRefusal {
    /// The credential is absent or was refused.
    Unauthenticated,
    /// The verifier could not reach a verdict (issuer or key set outage).
    Unavailable,
}

/// The longest subject the journal's caller reference column holds.
const MAXIMUM_SUBJECT_BYTES: usize = 256;

pub struct Authenticator {
    verifier: TokenVerifier,
}

impl Authenticator {
    /// Log the refusal of a request whose `Authorization` header is absent,
    /// not text, or not a bearer credential, so every 401 leaves the same
    /// value-free, rate-limited trace as a refused token.
    pub fn log_header_refusal(&self) {
        registry_platform_oidc::log_authentication_refusal!(
            self.verifier,
            AuthenticationStage::Header,
            "Adapter authentication refused"
        );
    }

    pub async fn authenticate(&self, token: &str) -> Result<Caller, CallerRefusal> {
        validate_compact_access_token(token).map_err(|_| {
            registry_platform_oidc::log_authentication_refusal!(
                self.verifier,
                AuthenticationStage::Header,
                "Adapter authentication refused"
            );
            CallerRefusal::Unauthenticated
        })?;
        let verified = self.verifier.verify(token).await.map_err(|error| {
            registry_platform_oidc::log_authentication_refusal!(
                self.verifier,
                error.authentication_stage(),
                "Adapter authentication refused"
            );
            match error {
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
                _ => CallerRefusal::Unauthenticated,
            }
        })?;
        // An exchanged token names the authority whose assertion produced
        // it. This runtime declares no assertion authority, so it admits
        // no exchanged token.
        if verified.claims.extra.contains_key(ASSERTION_ISSUER_CLAIM) {
            registry_platform_oidc::log_authentication_refusal!(
                self.verifier,
                AuthenticationStage::Client,
                "Adapter authentication refused: an exchanged credential arrived at a deployment that declares no assertion authority"
            );
            return Err(CallerRefusal::Unauthenticated);
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
            .ok_or_else(|| {
                registry_platform_oidc::log_authentication_refusal!(
                    self.verifier,
                    AuthenticationStage::Profile,
                    "Adapter authentication refused: the issuer is absent or unusable for caller isolation"
                );
                CallerRefusal::Unauthenticated
            })?;
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
            .ok_or_else(|| {
                registry_platform_oidc::log_authentication_refusal!(
                    self.verifier,
                    AuthenticationStage::Client,
                    "Adapter authentication refused: the admitted client identity is unavailable"
                );
                CallerRefusal::Unauthenticated
            })?;
        let reference = verified
            .claims
            .sub
            .clone()
            .filter(|subject| {
                !subject.is_empty()
                    && subject.len() <= MAXIMUM_SUBJECT_BYTES
                    && !subject.contains('\0')
            })
            .ok_or_else(|| {
                registry_platform_oidc::log_authentication_refusal!(
                    self.verifier,
                    AuthenticationStage::Profile,
                    "Adapter authentication refused: the subject is absent or unusable as a caller reference"
                );
                CallerRefusal::Unauthenticated
            })?;
        Ok(Caller {
            reference,
            issuer,
            client_id,
            scopes: verified.scopes,
        })
    }
}

async fn authenticator(
    runtime: &AdapterRuntimeConfig,
    resolver: &SecretResolver,
) -> Result<Authenticator, ServeError> {
    let oidc = &runtime.oidc;
    let invalid = |what: &str| ServeError::Configuration(format!("oidc: {what}"));
    if oidc.allow_insecure_http {
        tracing::warn!(
            "allowInsecureHttp is set: the token issuer and its keys may be fetched over plain http"
        );
    }
    let network = IssuerNetworkPolicy::new(oidc.issuer.as_str(), oidc.allow_insecure_http)
        .map_err(|_| invalid("the issuer was refused"))?;
    let keys = match &oidc.jwks_source {
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
        JwksSource::Static { document_ref } => {
            let document = resolver
                .resolve(document_ref)
                .map_err(|_| invalid("the static key document could not be resolved"))?;
            let jwks = parse_static_jwks(document.expose_secret())
                .map_err(|_| invalid("the static key document was refused"))?;
            JwksFetcher::new_static(jwks, JwksFetcherConfig::defaults())
        }
    };
    let config = TokenVerifierConfig::access_token_profile(
        oidc.issuer.to_string(),
        vec![oidc.audience.clone()],
        vec![Algorithm::RS256, Algorithm::ES256],
        access_token_typ_set(ACCESS_TOKEN_TYPE),
    )
    .with_allowed_clients(
        runtime
            .allowed_clients
            .iter()
            .map(|client| client.as_str().to_owned())
            .collect(),
    );
    Ok(Authenticator {
        verifier: TokenVerifier::new(config, Arc::new(keys)),
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

fn pool(
    config: &DatabaseConfig,
    resolver: &SecretResolver,
    migration: bool,
) -> Result<Pool, ServeError> {
    let invalid = |what: &str| ServeError::Configuration(format!("database: {what}"));
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
    #[cfg(feature = "postgres-test")]
    let manager = if config.test_only_plaintext {
        postgres.ssl_mode(tokio_postgres::config::SslMode::Disable);
        Manager::from_config(postgres, tokio_postgres::NoTls, manager_config)
    } else {
        postgres.ssl_mode(tokio_postgres::config::SslMode::Require);
        Manager::from_config(postgres, tls_connector(config, resolver)?, manager_config)
    };
    #[cfg(not(feature = "postgres-test"))]
    let manager = {
        if config.test_only_plaintext {
            return Err(invalid("plaintext connections are refused in this build"));
        }
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
    if let Some(reference) = &config.trusted_root_certificate_ref {
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

/// Resolve on the first SIGTERM or SIGINT. The handlers are installed here,
/// before anything is served, so a failure to install one refuses startup
/// rather than leaving a runtime that SIGTERM would stop with sends in
/// flight.
fn shutdown_signal() -> Result<impl std::future::Future<Output = ()>, ServeError> {
    let mut terminate = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .map_err(|error| ServeError::Signal(error.to_string()))?;
    let mut interrupt = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .map_err(|error| ServeError::Signal(error.to_string()))?;
    Ok(async move {
        tokio::select! {
            _ = interrupt.recv() => {}
            _ = terminate.recv() => {}
        }
    })
}

/// Erase one bounded response batch per cadence. Claim-time expiry remains a
/// correctness backstop, but custody does not depend on a duplicate arriving.
/// A database failure stops the supervised server instead of silently
/// extending retention.
async fn sweep_idempotency_responses(
    store: PostgresIdempotencyStore,
    cadence: Duration,
    mut shutdown: watch::Receiver<bool>,
) -> Result<(), ServeError> {
    let mut interval = tokio::time::interval(cadence);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            changed = shutdown.changed() => {
                changed.map_err(|_| ServeError::Retention("the shutdown channel closed".to_owned()))?;
                return Ok(());
            }
            _ = interval.tick() => {
                loop {
                    let erased = tokio::select! {
                        changed = shutdown.changed() => {
                            changed.map_err(|_| ServeError::Retention("the shutdown channel closed".to_owned()))?;
                            return Ok(());
                        }
                        result = store.sweep_expired(SystemTime::now(), idempotent::MAX_SWEEP_BATCH) => {
                            result.map_err(|error| ServeError::Retention(error.to_string()))?
                        }
                    };
                    if erased < u64::from(idempotent::MAX_SWEEP_BATCH) {
                        break;
                    }
                    tokio::task::yield_now().await;
                }
            }
        }
    }
}

fn retention_cadence(retention: Duration) -> Duration {
    (retention / 2).clamp(Duration::from_secs(1), Duration::from_secs(60))
}

async fn await_read_only_shutdown(mut shutdown: watch::Receiver<bool>) -> Result<(), ServeError> {
    shutdown
        .changed()
        .await
        .map_err(|_| ServeError::Serve("the read-only shutdown channel closed".to_owned()))
}

/// Load the deployment, migrate the journal, and serve until a stop signal.
pub async fn run(
    project_directory: &std::path::Path,
    profile_path: Option<&std::path::Path>,
    pack_path: Option<&std::path::Path>,
    runtime_path: &std::path::Path,
) -> Result<(), ServeError> {
    let loaded = load(project_directory, profile_path, pack_path, runtime_path)?;
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
    let authenticator = authenticator(&loaded.runtime, &loaded.resolver).await?;
    // Every secret the runtime reads resolves before the listener binds.
    let codec = codec(&loaded.runtime, &loaded.resolver)?;
    let shutdown = shutdown_signal()?;
    let migration = pool(&loaded.runtime.database, &loaded.resolver, true)?;
    {
        let client = migration
            .get()
            .await
            .map_err(|error| ServeError::Configuration(format!("database: {error}")))?;
        journal::migrate(&client)
            .await
            .map_err(|error| ServeError::Configuration(format!("journal migration: {error}")))?;
        idempotent::migrate(&client).await.map_err(|error| {
            ServeError::Configuration(format!("idempotency migration: {error}"))
        })?;
    }
    let journal = pool(&loaded.runtime.database, &loaded.resolver, false)?;
    let serves_write = loaded.served.iter().any(|served| {
        loaded
            .profile
            .operations
            .get(served.operation.as_str())
            .is_some_and(|operation| !operation.is_read())
    });
    let idempotency = match (serves_write, loaded.runtime.idempotency) {
        (true, Some(retention)) => Some((
            PostgresIdempotencyStore::new(
                journal.clone(),
                Duration::from_secs(retention.response_retention_seconds.get()),
            )
            .map_err(|error| ServeError::Configuration(format!("idempotency: {error}")))?,
            Duration::from_secs(retention.response_retention_seconds.get()),
        )),
        (true, None) => {
            return Err(ServeError::Configuration(
                "idempotency.responseRetentionSeconds is required when a write is served"
                    .to_owned(),
            ));
        }
        (false, _) => None,
    };
    let facade_idempotency = idempotency.as_ref().map(|(store, _)| store.clone());
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
    let state = Arc::new(FacadeState {
        codec,
        loaded,
        effective_contract,
        authenticator,
        journal,
        idempotency: facade_idempotency,
    });
    let (shutdown_sender, shutdown_receiver) = watch::channel(false);
    let mut server_shutdown = shutdown_receiver.clone();
    let serving = axum::serve(listener, router(state)).with_graceful_shutdown(async move {
        let _closed = server_shutdown.changed().await;
    });
    let server = async move { serving.await };
    let sweeper = async move {
        match idempotency {
            Some((store, retention)) => {
                sweep_idempotency_responses(store, retention_cadence(retention), shutdown_receiver)
                    .await
            }
            None => await_read_only_shutdown(shutdown_receiver).await,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn a_read_only_retention_supervisor_exits_on_shutdown() {
        let (sender, receiver) = watch::channel(false);
        let waiting = tokio::spawn(await_read_only_shutdown(receiver));
        sender.send(true).expect("the supervisor is listening");
        tokio::time::timeout(Duration::from_secs(1), waiting)
            .await
            .expect("read-only shutdown stays responsive")
            .expect("the supervisor task joins")
            .expect("read-only shutdown succeeds");
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
}
