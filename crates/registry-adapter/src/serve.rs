// SPDX-License-Identifier: Apache-2.0

//! The served process: the OIDC authenticator, the journal's PostgreSQL
//! pool, and the listener. The server refuses to start without OIDC and
//! without PostgreSQL; there is no open mode.

use std::net::SocketAddr;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

use deadpool_postgres::{Manager, ManagerConfig, Pool, RecyclingMethod, Runtime};
use jsonwebtoken::Algorithm;
use registry_adapter_core::AdapterRuntimeConfig;
use registry_platform_authcommon::validate_compact_access_token;
use registry_platform_config::{DatabaseConfig, JwksSource, SecretResolver};
use registry_platform_oidc::{
    access_token_typ_set, fetch_discovery_for_issuer, parse_static_jwks, IssuerNetworkPolicy,
    JwksFetcher, JwksFetcherConfig, OidcDiscoveryConfig, OidcError, TokenVerifier,
    TokenVerifierConfig,
};
use thiserror::Error;
use tokio::net::TcpListener;
use tokio_postgres::Config as PgConfig;

use crate::facade::{router, FacadeState};
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
}

/// A verified caller.
pub struct Caller {
    /// The verified subject, journaled as the caller reference.
    pub reference: String,
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

pub struct Authenticator {
    verifier: TokenVerifier,
}

impl Authenticator {
    pub async fn authenticate(&self, token: &str) -> Result<Caller, CallerRefusal> {
        validate_compact_access_token(token).map_err(|_| CallerRefusal::Unauthenticated)?;
        let verified = self
            .verifier
            .verify(token)
            .await
            .map_err(|error| match error {
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
            })?;
        let reference = verified
            .claims
            .sub
            .clone()
            .filter(|subject| !subject.is_empty())
            .ok_or(CallerRefusal::Unauthenticated)?;
        Ok(Caller {
            reference,
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
    );
    Ok(Authenticator {
        verifier: TokenVerifier::new(config, Arc::new(keys)),
    })
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

/// Load the deployment, migrate the journal, and serve until a stop signal.
pub async fn run(
    project_directory: &std::path::Path,
    runtime_path: &std::path::Path,
) -> Result<(), ServeError> {
    let loaded = load(project_directory, runtime_path)?;
    for (binding, reason) in &loaded.unserved {
        tracing::warn!(binding = %binding, reason = %reason, "binding not served");
    }
    if loaded.served.is_empty() {
        return Err(ServeError::Configuration(
            "no binding is servable by this runtime".to_owned(),
        ));
    }
    let authenticator = authenticator(&loaded.runtime, &loaded.resolver).await?;
    let migration = pool(&loaded.runtime.database, &loaded.resolver, true)?;
    {
        let client = migration
            .get()
            .await
            .map_err(|error| ServeError::Configuration(format!("database: {error}")))?;
        journal::migrate(&client)
            .await
            .map_err(|error| ServeError::Configuration(format!("journal migration: {error}")))?;
    }
    let journal = pool(&loaded.runtime.database, &loaded.resolver, false)?;
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
        loaded,
        authenticator,
        journal,
    });
    axum::serve(listener, router(state))
        .with_graceful_shutdown(async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await
        .map_err(|error| ServeError::Serve(error.to_string()))
}
