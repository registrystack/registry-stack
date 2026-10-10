// SPDX-License-Identifier: Apache-2.0

//! Startup: resolve the configured secrets and assemble both halves.
//!
//! The inbound resource server and the outbound exchange are built from their
//! own configuration sections and their own secrets. Every failure names the
//! configuration field and the stage that failed, never a resolved value.

use std::{future::Future, sync::Arc, time::Duration};

use axum::Router;
use registry_platform_audit::{AuditError, AuditProfile, AuditWriter};
use registry_platform_config::{JwksSource, ProtectedSecret, SecretResolver};
use registry_platform_crypto::PrivateJwk;
use registry_platform_oidc::{
    fetch_discovery_with_policy, parse_static_jwks, JwksFetcher, JwksFetcherConfig,
    OidcDiscoveryConfig,
};
use zeroize::Zeroizing;

use crate::{
    audit::ToolAuditLog,
    config::{describe_secret_failure, RuntimeConfig},
    contract::ContractSpec,
    gateway::{Gateway, ServiceDescription},
    inbound::{jwks_fetch_policy, uri_fetcher, verifier, ResourceServer, ResourceServerError},
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
        Self::Audit(error.operator_description())
    }
}

/// Everything startup builds before it opens the audit log.
struct Parts {
    resource_server: ResourceServer,
    outbound: Outbound,
    profile: AuditProfile,
}

fn resolver(config: &RuntimeConfig) -> Result<SecretResolver, StartupError> {
    config.secret_providers.resolver().map_err(|error| {
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

async fn assemble(config: &RuntimeConfig) -> Result<Parts, StartupError> {
    let secrets = resolver(config)?;
    let hash_key = resolve(
        &secrets,
        "audit.hashKeyRef",
        config.audit.key.hash_key_ref.as_str(),
    )?;
    let profile = AuditProfile::production_from_secret_bytes(Zeroizing::new(
        hash_key.expose_secret().to_vec(),
    ))
    .map_err(|_| StartupError::Key("audit.hashKeyRef"))?;
    let development = config.development_loopback();
    let server = &config.resource_server;
    let fetcher = match &server.jwks_source {
        JwksSource::Uri { uri } => uri_fetcher(uri, development),
        JwksSource::Discovery {} => {
            let policy = jwks_fetch_policy(development);
            let discovery = fetch_discovery_with_policy(
                &OidcDiscoveryConfig {
                    issuer: server.issuer.to_string(),
                    jwks_uri_override: None,
                    discovery_timeout: Duration::from_secs(5),
                    max_doc_bytes: 1024 * 1024,
                },
                &policy,
            )
            .await
            .map_err(|_| StartupError::ResourceServer("OIDC discovery failed".to_owned()))?;
            JwksFetcher::new_with_fetch_url_policy(
                discovery.jwks_uri,
                JwksFetcherConfig::defaults(),
                policy,
            )
        }
        JwksSource::Static { document_ref } => {
            let document = resolve(
                &secrets,
                "resourceServer.jwksSource.documentRef",
                document_ref,
            )?;
            let keys = parse_static_jwks(document.expose_secret())
                .map_err(|_| StartupError::Key("resourceServer.jwksSource.documentRef"))?;
            JwksFetcher::new_static(keys, JwksFetcherConfig::defaults())
        }
    };
    let resource_server = ResourceServer::new(
        server,
        config.service.name.as_str(),
        verifier(server, Arc::new(fetcher)),
        profile.key_hasher(),
        config.rate_limits.clone(),
    )?;
    let private_key = resolve(
        &secrets,
        "exchange.privateKeyRef",
        config.exchange.private_key_ref.as_str(),
    )?;
    let key = PrivateJwk::parse(&text(&private_key, "exchange.privateKeyRef")?)
        .map_err(|_| StartupError::Key("exchange.privateKeyRef"))?;
    let outbound = Outbound::new(
        &config.registry,
        &config.exchange,
        server.resource.as_str(),
        key,
    )?;
    Ok(Parts {
        resource_server,
        outbound,
        profile,
    })
}

/// Build the gateway's HTTP application.
pub async fn build(config: &RuntimeConfig) -> Result<Router, StartupError> {
    let parts = assemble(config).await?;
    // The loader already refused a destination the audit writer cannot use.
    let destination = config
        .audit
        .destination()
        .map_err(|error| StartupError::Audit(error.to_string()))?;
    let audit = ToolAuditLog::new(AuditWriter::open(destination).await?);
    let review_base_url = config.service.review_base_url.to_url();
    let resource = config.resource_server.resource.to_url();
    let gateway = Gateway::new(
        parts.outbound,
        ContractSpec {
            access_profile: config.registry.access_profile.to_string(),
            details_entity: config.service.details.entity.to_string(),
            application_entity: config.service.application.entity.to_string(),
            target_field: config.service.application.target_field.to_string(),
            owner_field: config.service.application.owner_field.to_string(),
        },
        ServiceDescription {
            name: config.service.name.as_str().to_owned(),
            description: config.service.description.as_str().to_owned(),
            disclosure: config.service.disclosure.as_str().to_owned(),
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
            max_request_body_bytes: config.limits.request_bytes(),
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
    let listener = tokio::net::TcpListener::bind(config.listener.bind.socket_addr())
        .await
        .map_err(StartupError::Bind)?;
    tracing::info!(target: "registry_breg_mcp", "gateway listening");
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
        .map_err(StartupError::Serve)
}
