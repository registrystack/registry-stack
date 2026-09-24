// SPDX-License-Identifier: Apache-2.0

//! Startup: resolve the configured secrets and assemble both halves.
//!
//! The inbound resource server and the outbound exchange are built from their
//! own configuration sections and their own secrets. Every failure names the
//! configuration field and the stage that failed, never a resolved value.

use std::{future::Future, path::PathBuf, sync::Arc};

use axum::Router;
use registry_platform_audit::{AuditError, AuditProfile};
use registry_platform_config::{ProtectedSecret, SecretProvider, SecretResolver};
use registry_platform_crypto::PrivateJwk;
use registry_platform_oidc::{JwksFetcher, JwksFetcherConfig};
use url::Url;
use zeroize::Zeroizing;

use crate::{
    audit::ToolAuditLog,
    config::{describe_secret_failure, JwksSource, RuntimeConfig},
    contract::ContractSpec,
    gateway::{Gateway, ServiceDescription},
    inbound::{uri_fetcher, verifier, ResourceServer, ResourceServerError},
    outbound::{Outbound, OutboundError},
    server,
};

/// Why the gateway could not start. No variant carries a secret value.
#[derive(Debug, thiserror::Error)]
pub enum StartupError {
    #[error("{0}")]
    Secret(String),
    #[error("the secret configured at {0} is not a usable key")]
    Key(&'static str),
    #[error("{0} is not a usable URL")]
    Url(&'static str),
    #[error("the inbound resource server could not be configured: {0}")]
    ResourceServer(String),
    #[error("the outbound registry exchange could not be configured: {0}")]
    Outbound(String),
    #[error("the audit log could not be opened: {0}")]
    Audit(String),
    #[error("the listener could not be bound: {0}")]
    Bind(#[source] std::io::Error),
    #[error("the listener failed: {0}")]
    Serve(#[source] std::io::Error),
}

impl From<ResourceServerError> for StartupError {
    fn from(error: ResourceServerError) -> Self {
        Self::ResourceServer(error.to_string())
    }
}

impl From<OutboundError> for StartupError {
    fn from(error: OutboundError) -> Self {
        Self::Outbound(error.to_string())
    }
}

impl From<AuditError> for StartupError {
    fn from(error: AuditError) -> Self {
        Self::Audit(error.to_string())
    }
}

/// Everything startup builds before it opens the audit log.
struct Parts {
    resource_server: ResourceServer,
    outbound: Outbound,
    profile: AuditProfile,
}

fn resolver(config: &RuntimeConfig) -> Result<SecretResolver, StartupError> {
    let mut providers = Vec::new();
    if config.secret_providers.environment.is_some() {
        providers.push(SecretProvider::Environment);
    }
    let root = match &config.secret_providers.file {
        Some(file) => {
            providers.push(SecretProvider::File);
            file.root.clone()
        }
        None => PathBuf::new(),
    };
    SecretResolver::new(providers, root).map_err(|error| {
        StartupError::Secret(describe_secret_failure(
            "secretProviders",
            "secret providers",
            &error,
        ))
    })
}

fn resolve(
    resolver: &SecretResolver,
    field: &'static str,
    reference: &str,
) -> Result<ProtectedSecret, StartupError> {
    resolver
        .resolve(reference)
        .map_err(|error| StartupError::Secret(describe_secret_failure(field, reference, &error)))
}

fn text(secret: &ProtectedSecret, field: &'static str) -> Result<Zeroizing<String>, StartupError> {
    std::str::from_utf8(secret.expose_secret())
        .map(|value| Zeroizing::new(value.to_owned()))
        .map_err(|_| StartupError::Key(field))
}

fn assemble(config: &RuntimeConfig) -> Result<Parts, StartupError> {
    let secrets = resolver(config)?;
    let hash_key = resolve(&secrets, "audit.hashKeyRef", &config.audit.hash_key_ref)?;
    let profile = AuditProfile::production_from_secret_bytes(Zeroizing::new(
        hash_key.expose_secret().to_vec(),
    ))
    .map_err(|_| StartupError::Key("audit.hashKeyRef"))?;
    let development = config.development_loopback();
    let server = &config.resource_server;
    let fetcher = match &server.jwks {
        JwksSource::Uri { uri } => uri_fetcher(uri, development),
        JwksSource::Static { document_ref } => {
            let document = resolve(&secrets, "resourceServer.jwks.documentRef", document_ref)?;
            let keys = serde_json::from_slice(document.expose_secret())
                .map_err(|_| StartupError::Key("resourceServer.jwks.documentRef"))?;
            JwksFetcher::new_static(keys, JwksFetcherConfig::defaults())
        }
    };
    let resource_server = ResourceServer::new(
        server,
        &config.service.name,
        verifier(server, Arc::new(fetcher)),
        profile.key_hasher(),
        config.rate_limits.clone(),
    )?;
    let private_key = resolve(
        &secrets,
        "exchange.privateKeyRef",
        &config.exchange.private_key_ref,
    )?;
    let key = PrivateJwk::parse(&text(&private_key, "exchange.privateKeyRef")?)
        .map_err(|_| StartupError::Key("exchange.privateKeyRef"))?;
    let outbound = Outbound::new(&config.registry, &config.exchange, &server.resource, key)?;
    Ok(Parts {
        resource_server,
        outbound,
        profile,
    })
}

/// Validate the configuration and resolve every secret without opening a
/// socket or writing the audit log.
pub fn check(config: &RuntimeConfig) -> Result<(), StartupError> {
    config
        .check()
        .map_err(|error| StartupError::ResourceServer(error.to_string()))?;
    assemble(config).map(|_| ())
}

/// Build the gateway's HTTP application.
pub async fn build(config: &RuntimeConfig) -> Result<Router, StartupError> {
    let parts = assemble(config)?;
    let audit = ToolAuditLog::open(
        config.audit.path.clone(),
        config.audit.maximum_file_bytes,
        parts.profile.chain_hasher(),
    )
    .await?;
    let review_base_url = Url::parse(&config.service.review_base_url)
        .map_err(|_| StartupError::Url("service.reviewBaseUrl"))?;
    let resource = Url::parse(&config.resource_server.resource)
        .map_err(|_| StartupError::Url("resourceServer.resource"))?;
    let gateway = Gateway::new(
        parts.outbound,
        ContractSpec {
            access_profile: config.registry.access_profile.clone(),
            details_entity: config.service.details.entity.clone(),
            application_entity: config.service.application.entity.clone(),
            target_field: config.service.application.target_field.clone(),
            owner_field: config.service.application.owner_field.clone(),
        },
        ServiceDescription {
            name: config.service.name.clone(),
            description: config.service.description.clone(),
            disclosure: config.service.disclosure.clone(),
        },
        review_base_url,
        audit,
        parts.profile.key_hasher(),
    );
    Ok(server::router(
        Arc::new(gateway),
        Arc::new(parts.resource_server),
        &server::ServerOptions {
            resource: &resource,
            max_request_body_bytes: config.limits.max_request_body_bytes,
            hsts: !config.development_loopback(),
        },
    ))
}

/// Bind the configured listener and serve until `shutdown` resolves.
pub async fn serve<F>(config: &RuntimeConfig, shutdown: F) -> Result<(), StartupError>
where
    F: Future<Output = ()> + Send + 'static,
{
    let app = build(config).await?;
    let listener = tokio::net::TcpListener::bind(config.listener.bind)
        .await
        .map_err(StartupError::Bind)?;
    tracing::info!(target: "registry_breg_mcp", "gateway listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .map_err(StartupError::Serve)
}
