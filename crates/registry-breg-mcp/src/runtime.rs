// SPDX-License-Identifier: Apache-2.0

//! Startup: preserve the BReg configuration facade over the shared MCP edge.
//!
//! The inbound resource server and the outbound exchange are built from their
//! own configuration sections and their own secrets. Every failure names the
//! configuration field and the stage that failed, never a resolved value.

use std::{future::Future, sync::Arc, time::Duration};

use axum::Router;
use registry_mcp_edge::{
    router, token_verifier, AccessTokenAlgorithm as EdgeAlgorithm, AuditOptions, GatewayCore,
    GatewayInfo, ProviderBinding, RateLimitOptions, ResourceServer, ResourceServerError,
    ResourceServerOptions, ServerOptions, TokenBucketOptions, ToolAuditLog,
};
use registry_platform_audit::{AuditError, AuditProfile, AuditWriter};
use registry_platform_config::{JwksSource, ProtectedSecret, SecretResolver};
use registry_platform_crypto::PrivateJwk;
use registry_platform_oidc::{
    fetch_discovery_for_issuer, parse_static_jwks, IssuerNetworkPolicy, JwksFetcher,
    JwksFetcherConfig, OidcDiscoveryConfig,
};
use zeroize::Zeroizing;

use crate::{
    breg_binding,
    config::{describe_secret_failure, AccessTokenAlgorithm, RuntimeConfig},
    BRegBindingError, BREG_TOOL_NAMES,
};

const PRINCIPAL_CLASS: &str = "breg-mcp-principal-v1";
const CLIENT_CLASS: &str = "breg-mcp-client-v1";
const AUDIT_SCHEMA: &str = "registry-breg-mcp.tool-call/v1";
const AUDIT_EVENT: &str = "breg_mcp.tool_call";

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
    #[error("the BReg MCP edge could not be configured: {0}")]
    Edge(String),
    #[error("the audit log could not be opened: {0}")]
    Audit(String),
    #[error("the listener could not be bound: {0}")]
    Bind(#[source] std::io::Error),
    #[error("the listener failed: {0}")]
    Serve(#[source] std::io::Error),
}

impl From<AuditError> for StartupError {
    fn from(error: AuditError) -> Self {
        Self::Audit(error.operator_description())
    }
}

/// Everything startup builds before it opens the audit log.
struct Parts {
    resource_server: ResourceServer,
    binding: ProviderBinding,
}

fn resource_server_failure(error: ResourceServerError) -> StartupError {
    let description = match error {
        ResourceServerError::RateLimit("perPrincipal") => {
            "rate limit perCitizen is invalid".to_owned()
        }
        other => other.to_string(),
    };
    StartupError::ResourceServer(description)
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
    let server = &config.resource_server;
    if let Some(diagnostic) = server.insecure_http_startup_diagnostic() {
        tracing::warn!("{diagnostic}");
    }
    let network = IssuerNetworkPolicy::new(server.issuer.as_str(), server.allow_insecure_http)
        .map_err(|error| StartupError::ResourceServer(error.to_string()))?;
    let fetcher = match &server.jwks_source {
        JwksSource::Uri { uri } => JwksFetcher::new_with_fetch_url_policy(
            uri.to_string(),
            JwksFetcherConfig::defaults(),
            network.declared_jwks_fetch_policy(),
        ),
        JwksSource::Discovery {} => {
            let (discovery, policy) = fetch_discovery_for_issuer(
                &OidcDiscoveryConfig {
                    issuer: server.issuer.to_string(),
                    jwks_uri_override: None,
                    discovery_timeout: Duration::from_secs(5),
                    max_doc_bytes: 1024 * 1024,
                },
                server.allow_insecure_http,
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
    let resource_options = ResourceServerOptions {
        resource: server.resource.as_str().to_owned(),
        issuer: server.issuer.as_str().to_owned(),
        algorithms: server
            .algorithms
            .iter()
            .copied()
            .map(edge_algorithm)
            .collect(),
        allowed_clients: server
            .allowed_clients
            .iter()
            .map(ToString::to_string)
            .collect(),
        required_scopes: server
            .required_scopes
            .iter()
            .map(|scope| scope.as_str().to_owned())
            .collect(),
        scope_claim: server.scope_claim.to_string(),
        maximum_token_lifetime: Duration::from_secs(server.maximum_token_lifetime_seconds.get()),
        allow_insecure_http: server.allow_insecure_http,
        resource_name: config.service.name.as_str().to_owned(),
        principal_audit_namespace: PRINCIPAL_CLASS.to_owned(),
        client_audit_namespace: CLIENT_CLASS.to_owned(),
    };
    let resource_server = ResourceServer::new(
        &resource_options,
        token_verifier(&resource_options, Arc::new(fetcher)),
        profile.key_hasher(),
        RateLimitOptions {
            per_principal: TokenBucketOptions {
                requests_per_minute: config.rate_limits.per_citizen.requests_per_minute.get(),
                burst: config.rate_limits.per_citizen.burst.get(),
            },
            per_client: TokenBucketOptions {
                requests_per_minute: config.rate_limits.per_client.requests_per_minute.get(),
                burst: config.rate_limits.per_client.burst.get(),
            },
        },
    )
    .map_err(resource_server_failure)?;
    let private_key = resolve(
        &secrets,
        "exchange.privateKeyRef",
        config.exchange.private_key_ref.as_str(),
    )?;
    let key = PrivateJwk::parse(&text(&private_key, "exchange.privateKeyRef")?)
        .map_err(|_| StartupError::Key("exchange.privateKeyRef"))?;
    let binding = breg_binding(
        &config.registry,
        &config.exchange,
        &config.service,
        server.resource.as_str(),
        key,
        profile.key_hasher(),
        BREG_TOOL_NAMES.into_iter().map(str::to_owned),
    )
    .map_err(|error| match error {
        BRegBindingError::Authorization => StartupError::Outbound(error.to_string()),
        BRegBindingError::Client | BRegBindingError::Tools => StartupError::Edge(error.to_string()),
    })?;
    Ok(Parts {
        resource_server,
        binding,
    })
}

const fn edge_algorithm(algorithm: AccessTokenAlgorithm) -> EdgeAlgorithm {
    match algorithm {
        AccessTokenAlgorithm::RS256 => EdgeAlgorithm::RS256,
        AccessTokenAlgorithm::RS384 => EdgeAlgorithm::RS384,
        AccessTokenAlgorithm::ES256 => EdgeAlgorithm::ES256,
        AccessTokenAlgorithm::ES384 => EdgeAlgorithm::ES384,
        AccessTokenAlgorithm::EdDSA => EdgeAlgorithm::EdDSA,
    }
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
    let resource = config.resource_server.resource.to_url();
    let info = GatewayInfo::new(
        "breg-mcp",
        config.service.name.as_str(),
        format!(
            "{}\n\n{}\n\nThe citizen is always the signed-in user. Applications are \
             submitted only on the review page prepare_review returns.",
            config.service.name.as_str(),
            config.service.description.as_str()
        ),
    )
    .map_err(|error| StartupError::Edge(error.to_string()))?;
    let audit_options = AuditOptions::new(AUDIT_SCHEMA, AUDIT_EVENT)
        .map_err(|error| StartupError::Edge(error.to_string()))?;
    let gateway = GatewayCore::new([parts.binding], audit, audit_options, info)
        .map_err(|error| StartupError::Edge(error.to_string()))?;
    Ok(router(
        Arc::new(gateway),
        Arc::new(parts.resource_server),
        &ServerOptions {
            resource,
            maximum_request_bytes: config.limits.request_bytes(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn neutral_principal_rate_limit_uses_breg_public_name() {
        let error = resource_server_failure(ResourceServerError::RateLimit("perPrincipal"));
        let description = error.to_string();
        assert!(description.contains("perCitizen"), "{description}");
        assert!(!description.contains("perPrincipal"), "{description}");
    }
}
