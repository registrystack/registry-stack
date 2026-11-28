// SPDX-License-Identifier: Apache-2.0

//! Startup: preserve the BReg configuration facade over the shared MCP edge.
//!
//! The inbound resource server and the outbound exchange are built from their
//! own configuration sections and their own secrets. Every failure names the
//! configuration field and the stage that failed, never a resolved value.

use std::{future::Future, sync::Arc, time::Duration};

use axum::Router;
use registry_mcp_edge::{
    config::describe_development_settings, router, token_verifier, AuditOptions, GatewayCore,
    GatewayInfo, ProviderBinding, RateLimitOptions, ResourceServer, ResourceServerError,
    ServerOptions, TokenBucketOptions, ToolAuditLog,
};
use registry_platform_audit::{AuditError, AuditProfile, AuditWriter};
use registry_platform_config::{
    DevelopmentWitness, JwksSource, PostureReport, ProtectedSecret, SecretResolver,
};
use registry_platform_crypto::PrivateJwk;
use registry_platform_oidc::{
    fetch_discovery_for_issuer, parse_static_jwks, IssuerNetworkPolicy, JwksFetcher,
    JwksFetcherConfig, OidcDiscoveryConfig,
};
use zeroize::Zeroizing;

use crate::{
    breg_binding,
    config::{describe_secret_failure, RuntimeConfig},
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
    #[error("{0}")]
    Posture(String),
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

/// Reads the static key document. The refusal text names what the document
/// got wrong and carries no key material, so it goes to the operator's log.
fn static_key_fetcher(document: &[u8]) -> Result<JwksFetcher, StartupError> {
    let keys = parse_static_jwks(document).map_err(|error| {
        tracing::error!(%error, "the static key set was refused");
        StartupError::Key("resourceServer.jwksSource.documentRef")
    })?;
    Ok(JwksFetcher::new_static(keys, JwksFetcherConfig::defaults()))
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

async fn assemble(
    config: &RuntimeConfig,
    posture: &PostureReport,
    development: Option<&DevelopmentWitness>,
) -> Result<Parts, StartupError> {
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
    let issuer = server
        .issuer_url(development)
        .map_err(|error| StartupError::ResourceServer(error.to_string()))?;
    let network = IssuerNetworkPolicy::new(issuer.as_str(), server.allow_insecure_http)
        .map_err(|error| StartupError::ResourceServer(error.to_string()))?;
    let jwks_source = server
        .jwks_source
        .get(development)
        .map_err(|error| StartupError::ResourceServer(error.to_string()))?;
    let fetcher = match jwks_source {
        JwksSource::Uri { uri } => JwksFetcher::new_with_fetch_url_policy(
            uri.to_string(),
            JwksFetcherConfig::defaults(),
            network.declared_jwks_fetch_policy(),
        ),
        JwksSource::Discovery {} => {
            let (discovery, policy) = fetch_discovery_for_issuer(
                &OidcDiscoveryConfig {
                    issuer: issuer.to_string(),
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
        JwksSource::Static { document_ref } | JwksSource::TestIssuer { document_ref } => {
            let document = resolve(
                &secrets,
                "resourceServer.jwksSource.documentRef",
                document_ref,
            )?;
            static_key_fetcher(document.expose_secret())?
        }
    };
    let resource_options = server
        .options(
            development,
            config.service.name.as_str(),
            PRINCIPAL_CLASS,
            CLIENT_CLASS,
        )
        .map_err(|error| StartupError::ResourceServer(error.to_string()))?;
    let resource_server = ResourceServer::new_with_posture(
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
        posture.posture(),
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
        development,
        &resource_options.resource,
        key,
        profile.key_hasher(),
        BREG_TOOL_NAMES.into_iter().map(str::to_owned),
    )
    .map_err(|error| match error {
        BRegBindingError::Authorization => StartupError::Outbound(error.to_string()),
        BRegBindingError::Client | BRegBindingError::Tools | BRegBindingError::ReviewOrigin => {
            StartupError::Edge(error.to_string())
        }
    })?;
    Ok(Parts {
        resource_server,
        binding,
    })
}

/// How an operator gets past a posture refusal at startup.
const POSTURE_REMEDY: &str = "Run breg-mcp check for each member. For a laptop or test run, \
     start with `rstack dev`, or declare development with REGISTRY_STACK_POSTURE=development or \
     --posture development.";

/// Build the gateway's HTTP application from the configuration, the posture
/// report and the witness the runtime loader returned together.
pub async fn build_with_posture(
    config: &RuntimeConfig,
    posture: &PostureReport,
    development: Option<&DevelopmentWitness>,
) -> Result<Router, StartupError> {
    if development.is_some()
        != (posture.posture() == registry_platform_config::Posture::Development)
    {
        return Err(StartupError::Posture(format!(
            "the development witness does not match the declared posture. Use the \
             configuration, posture and witness the runtime loader returned. {POSTURE_REMEDY}"
        )));
    }
    let settings = config.development_settings();
    if posture.posture() == registry_platform_config::Posture::Production && !settings.is_empty() {
        return Err(StartupError::Posture(format!(
            "production refuses development settings: {}. {POSTURE_REMEDY}",
            describe_development_settings(&settings)
        )));
    }
    let resource = config
        .resource_server
        .resource_url(development)
        .map_err(|error| StartupError::ResourceServer(error.to_string()))?
        .to_url();
    let parts = assemble(config, posture, development).await?;
    // The loader already refused a destination the audit writer cannot use.
    let destination = config
        .audit
        .destination()
        .map_err(|error| StartupError::Audit(error.to_string()))?;
    let audit = ToolAuditLog::new(AuditWriter::open(destination, posture.posture()).await?);
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
            hsts: posture.posture() != registry_platform_config::Posture::Development
                || !config.loopback_listener(),
            posture: posture.clone(),
        },
    ))
}

/// Bind the configured listener and serve until `shutdown` resolves.
pub async fn serve<F>(
    config: &RuntimeConfig,
    posture: &PostureReport,
    development: Option<&DevelopmentWitness>,
    shutdown: F,
) -> Result<(), StartupError>
where
    F: Future<Output = ()> + Send + 'static,
{
    let app = build_with_posture(config, posture, development).await?;
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

    /// A public EC key as a provider publishes it, with members the verifier
    /// does not read.
    fn provider_key_set(extra: &str) -> Vec<u8> {
        format!(
            r#"{{"keys":[{{"kty":"EC","crv":"P-256","kid":"key-1","use":"sig","alg":"ES256","ext":true,"x5c":["MIIB"],"x5t":"abc","x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4","y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"{extra}}}]}}"#
        )
        .into_bytes()
    }

    #[test]
    fn a_static_key_set_with_unknown_public_members_loads() {
        static_key_fetcher(&provider_key_set(""))
            .expect("a provider key set with ext and x5c members loads");
    }

    #[test]
    fn a_static_key_set_with_a_private_member_keeps_its_code_and_logs_the_validator_text() {
        let logs = registry_platform_testing::CapturedDiagnosticLogs::default();
        let error = tracing::dispatcher::with_default(&logs.subscriber(), || {
            let Err(error) = static_key_fetcher(&provider_key_set(r#","d":"CANARY-PRIVATE""#))
            else {
                panic!("a private member is refused");
            };
            error
        });
        assert!(matches!(
            error,
            StartupError::Key("resourceServer.jwksSource.documentRef")
        ));
        let text = logs.text();
        assert!(text.contains("private-key member"), "{text}");
        assert!(!text.contains("CANARY-PRIVATE"), "{text}");
        assert!(!error.to_string().contains("CANARY-PRIVATE"));
    }

    #[test]
    fn neutral_principal_rate_limit_uses_breg_public_name() {
        let error = resource_server_failure(ResourceServerError::RateLimit("perPrincipal"));
        let description = error.to_string();
        assert!(description.contains("perCitizen"), "{description}");
        assert!(!description.contains("perPrincipal"), "{description}");
    }
}
