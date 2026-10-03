// SPDX-License-Identifier: Apache-2.0

//! The operator runtime configuration document.
//!
//! The inbound resource server and the outbound registry exchange are two
//! sections that share no field: nothing the gateway accepts from a chat host
//! is configured by the same key as anything it presents to the registry.
//! Every credential is a `secret:env/` or `secret:file/` reference, never
//! inline text.

use std::path::{Path, PathBuf};

use registry_platform_audit::{AuditDestination, AuditDestinationError, AuditDestinationKind};
pub(crate) use registry_platform_config::describe_secret_failure;
use registry_platform_config::{
    AuditKeyConfig, ConfigBlockError, JwksSource, PrivateListenerConfig, RuntimeConfigLoader,
    RuntimeEnvelope, SecretProvidersConfig,
};
use registry_platform_httputil::{valid_resource_uri, valid_scope_token};
use serde::Deserialize;
use thiserror::Error;
use url::{Host, Url};

/// apiVersion of the gateway runtime configuration document.
pub const RUNTIME_API_VERSION: &str = "registry.registrystack.org/breg-mcp-runtime/v1alpha1";
/// Kind of the gateway runtime configuration document.
pub const RUNTIME_KIND: &str = "BRegMcpRuntimeConfig";
/// The single path the MCP endpoint is served at.
pub const MCP_PATH: &str = "/mcp";

const MAXIMUM_SERVICE_TEXT_BYTES: usize = 4096;
const MAXIMUM_NAME_BYTES: usize = 128;
const MAXIMUM_TOKEN_BYTES: usize = 512;
const DEFAULT_REQUEST_BODY_BYTES: usize = 64 * 1024;
const MAXIMUM_REQUEST_BODY_BYTES: usize = 1024 * 1024;

const RUNTIME_ENVELOPE: RuntimeEnvelope = RuntimeEnvelope {
    api_version: RUNTIME_API_VERSION,
    kind: RUNTIME_KIND,
};

/// The operator runtime configuration document.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeConfig {
    pub api_version: String,
    pub kind: String,
    pub listener: PrivateListenerConfig,
    pub secret_providers: SecretProvidersConfig,
    /// Who may call the gateway: the chat hosts' authorization server.
    pub resource_server: ResourceServerConfig,
    /// The one registry deployment and access profile the gateway acts on.
    pub registry: RegistryConfig,
    /// The gateway's own client identity at the authorization server.
    pub exchange: ExchangeConfig,
    pub service: ServiceConfig,
    pub audit: AuditConfig,
    pub rate_limits: RateLimitsConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
}

/// The inbound half: how a chat host's access token is verified.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceServerConfig {
    /// This gateway's resource identifier: the exact URL of its MCP endpoint,
    /// which every accepted token must name as its audience.
    pub resource: String,
    pub issuer: String,
    #[serde(default)]
    pub jwks_source: JwksSource,
    pub algorithms: Vec<AccessTokenAlgorithm>,
    /// The chat-host clients whose tokens the gateway accepts.
    pub allowed_clients: Vec<String>,
    /// Scopes every accepted token must carry.
    pub required_scopes: Vec<String>,
    #[serde(default = "default_scope_claim")]
    pub scope_claim: String,
    #[serde(default = "default_max_token_lifetime")]
    pub max_token_lifetime_seconds: u64,
}

fn default_scope_claim() -> String {
    "scope".to_owned()
}

const fn default_max_token_lifetime() -> u64 {
    3600
}

/// An asymmetric access-token signature algorithm.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
pub enum AccessTokenAlgorithm {
    RS256,
    RS384,
    ES256,
    ES384,
    EdDSA,
}

impl AccessTokenAlgorithm {
    #[must_use]
    pub const fn jsonwebtoken(self) -> jsonwebtoken::Algorithm {
        match self {
            Self::RS256 => jsonwebtoken::Algorithm::RS256,
            Self::RS384 => jsonwebtoken::Algorithm::RS384,
            Self::ES256 => jsonwebtoken::Algorithm::ES256,
            Self::ES384 => jsonwebtoken::Algorithm::ES384,
            Self::EdDSA => jsonwebtoken::Algorithm::EdDSA,
        }
    }
}

/// The outbound half: the registry the gateway acts on.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistryConfig {
    pub base_url: String,
    /// The standing agent access profile every call names.
    pub access_profile: String,
    /// The registry's token audience, requested as the exchange resource.
    pub audience: String,
    /// The scopes requested for the delegated registry token.
    pub scopes: Vec<String>,
    #[serde(default = "default_registry_timeout")]
    pub request_timeout_milliseconds: u64,
}

const fn default_registry_timeout() -> u64 {
    10_000
}

/// The gateway's own client identity, used only to exchange a verified
/// inbound token for a delegated registry token.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExchangeConfig {
    pub token_endpoint: String,
    pub client_id: String,
    pub private_key_ref: String,
    /// The client-assertion audience, when the authorization server expects
    /// one other than its token endpoint.
    #[serde(default)]
    pub assertion_audience: Option<String>,
}

/// The authored service a citizen is told about, and the registry entities
/// its tools work over.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceConfig {
    pub name: String,
    pub description: String,
    /// What the citizen is told about the data the chat host will see.
    pub disclosure: String,
    pub details: DetailsConfig,
    pub application: ApplicationConfig,
    /// The citizen-facing review page; an application is reviewed and
    /// submitted there, never through the chat host.
    pub review_base_url: String,
}

/// The entity holding the citizen's own record, found through the agent
/// profile's linked lookup.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DetailsConfig {
    pub entity: String,
}

/// The application entity and the two fields the gateway, never the chat
/// host, writes.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplicationConfig {
    pub entity: String,
    /// The field identifier of the field that references the citizen's own
    /// record.
    pub target_field: String,
    /// The field identifier of the field that records the citizen's
    /// principal.
    pub owner_field: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditConfig {
    #[serde(flatten)]
    pub key: AuditKeyConfig,
    #[serde(default)]
    pub destination: AuditDestinationKind,
    #[serde(default)]
    pub path: Option<PathBuf>,
    #[serde(default)]
    pub rotate_bytes: Option<u64>,
    #[serde(default)]
    pub retain_days: Option<u32>,
}

impl AuditConfig {
    pub fn destination(&self) -> Result<AuditDestination, RuntimeConfigError> {
        AuditDestination::from_settings(
            self.destination,
            self.path.clone(),
            self.rotate_bytes,
            self.retain_days,
        )
        .map_err(|error| match error {
            AuditDestinationError::RelativePath => {
                RuntimeConfigError::RelativeOperatedPath("audit.path")
            }
            error => RuntimeConfigError::InvalidAuditDestination(error),
        })
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RateLimitsConfig {
    pub per_citizen: RateLimitConfig,
    pub per_client: RateLimitConfig,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RateLimitConfig {
    pub requests_per_minute: u32,
    pub burst: u32,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LimitsConfig {
    #[serde(default = "default_request_body_bytes")]
    pub max_request_body_bytes: usize,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            max_request_body_bytes: DEFAULT_REQUEST_BODY_BYTES,
        }
    }
}

const fn default_request_body_bytes() -> usize {
    DEFAULT_REQUEST_BODY_BYTES
}

/// A value-free reason the runtime configuration was refused.
#[derive(Debug, Error)]
pub enum RuntimeConfigError {
    #[error(transparent)]
    Load(#[from] registry_platform_config::RuntimeConfigError),
    #[error(transparent)]
    Block(#[from] ConfigBlockError),
    #[error("the runtime configuration is not UTF-8 text")]
    Encoding,
    #[error("{0} must be an absolute path")]
    RelativeOperatedPath(&'static str),
    #[error(
        "the listener must bind a loopback or private address for its tlsTermination and networkExposure"
    )]
    InvalidListener,
    #[error("{0}")]
    InvalidAuditDestination(#[source] AuditDestinationError),
    #[error("{0} must be an https URL without credentials, query, or fragment; plain http is accepted only on loopback under development-loopback")]
    InvalidUrl(&'static str),
    #[error("resourceServer.resource must name the {MCP_PATH} endpoint")]
    InvalidResourcePath,
    #[error("{0} must not be empty")]
    Empty(&'static str),
    #[error("{0} is longer than this gateway accepts")]
    TooLong(&'static str),
    #[error("{0} holds a value that is not a single token")]
    InvalidToken(&'static str),
    #[error("{0} holds a value that is not an RFC 6749 scope token")]
    InvalidScope(&'static str),
    #[error("{0} must be an absolute URI without a fragment or credentials")]
    InvalidResource(&'static str),
    #[error("the gateway's own exchange client may not be an accepted inbound client")]
    ExchangeClientAdmittedInbound,
    #[error("the registry audience must differ from the gateway's own resource")]
    AudienceReused,
    #[error("{0} must be greater than zero")]
    Zero(&'static str),
    #[error("service.reviewBaseUrl must be the review page's publicOrigin, with no path")]
    ReviewBaseUrlNotOrigin,
    #[error("service.application.ownerField must name a different field than targetField")]
    OwnerFieldIsTarget,
}

impl RuntimeConfig {
    /// Load and validate the operator document.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, RuntimeConfigError> {
        let loaded = Self::loader().load::<Self>(path.as_ref())?;
        loaded.config.check()?;
        Ok(loaded.config)
    }

    #[must_use]
    pub const fn loader() -> RuntimeConfigLoader {
        RuntimeConfigLoader::new(RUNTIME_ENVELOPE)
    }

    /// Parse and validate a document already read.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, RuntimeConfigError> {
        let text = std::str::from_utf8(bytes).map_err(|_| RuntimeConfigError::Encoding)?;
        let config = Self::loader()
            .parse_str::<Self>(text, |name| std::env::var(name).ok())?
            .config;
        config.check()?;
        Ok(config)
    }

    /// Validate everything that can be checked without resolving a secret.
    pub fn check(&self) -> Result<(), RuntimeConfigError> {
        if !self.listener.is_valid() {
            return Err(RuntimeConfigError::InvalidListener);
        }
        self.secret_providers.check()?;
        self.check_resource_server()?;
        self.check_registry()?;
        self.check_service()?;
        self.audit.key.check(&self.secret_providers)?;
        self.audit.destination()?;
        self.secret_providers
            .check_reference("exchange.privateKeyRef", &self.exchange.private_key_ref)?;
        for (field, limit) in [
            ("rateLimits.perCitizen", self.rate_limits.per_citizen),
            ("rateLimits.perClient", self.rate_limits.per_client),
        ] {
            if limit.requests_per_minute == 0 || limit.burst == 0 {
                return Err(RuntimeConfigError::Zero(field));
            }
        }
        if self.limits.max_request_body_bytes == 0 {
            return Err(RuntimeConfigError::Zero("limits.maxRequestBodyBytes"));
        }
        if self.limits.max_request_body_bytes > MAXIMUM_REQUEST_BODY_BYTES {
            return Err(RuntimeConfigError::TooLong("limits.maxRequestBodyBytes"));
        }
        Ok(())
    }

    /// Whether plain-HTTP loopback endpoints are acceptable.
    #[must_use]
    pub fn development_loopback(&self) -> bool {
        self.listener.tls_termination
            == registry_platform_config::TlsTermination::DevelopmentLoopback
    }

    fn check_resource_server(&self) -> Result<(), RuntimeConfigError> {
        let development = self.development_loopback();
        let server = &self.resource_server;
        let resource = service_url(&server.resource, development)
            .ok_or(RuntimeConfigError::InvalidUrl("resourceServer.resource"))?;
        if resource.path() != MCP_PATH {
            return Err(RuntimeConfigError::InvalidResourcePath);
        }
        service_url(&server.issuer, development)
            .ok_or(RuntimeConfigError::InvalidUrl("resourceServer.issuer"))?;
        server
            .jwks_source
            .check("resourceServer.jwksSource", development)?;
        if let Some(document_ref) = server.jwks_source.document_ref() {
            self.secret_providers
                .check_reference("resourceServer.jwksSource.documentRef", document_ref)?;
        }
        if server.algorithms.is_empty() {
            return Err(RuntimeConfigError::Empty("resourceServer.algorithms"));
        }
        tokens(&server.allowed_clients, "resourceServer.allowedClients")?;
        scopes(&server.required_scopes, "resourceServer.requiredScopes")?;
        token(&server.scope_claim, "resourceServer.scopeClaim")?;
        if server.max_token_lifetime_seconds == 0 {
            return Err(RuntimeConfigError::Zero(
                "resourceServer.maxTokenLifetimeSeconds",
            ));
        }
        if server.allowed_clients.contains(&self.exchange.client_id) {
            return Err(RuntimeConfigError::ExchangeClientAdmittedInbound);
        }
        Ok(())
    }

    fn check_registry(&self) -> Result<(), RuntimeConfigError> {
        let development = self.development_loopback();
        service_url(&self.registry.base_url, development)
            .ok_or(RuntimeConfigError::InvalidUrl("registry.baseUrl"))?;
        token(&self.registry.access_profile, "registry.accessProfile")?;
        resource_uri(&self.registry.audience, "registry.audience")?;
        scopes(&self.registry.scopes, "registry.scopes")?;
        if self.registry.request_timeout_milliseconds == 0 {
            return Err(RuntimeConfigError::Zero(
                "registry.requestTimeoutMilliseconds",
            ));
        }
        if self.registry.audience == self.resource_server.resource {
            return Err(RuntimeConfigError::AudienceReused);
        }
        service_url(&self.exchange.token_endpoint, development)
            .ok_or(RuntimeConfigError::InvalidUrl("exchange.tokenEndpoint"))?;
        token(&self.exchange.client_id, "exchange.clientId")?;
        if let Some(audience) = &self.exchange.assertion_audience {
            token(audience, "exchange.assertionAudience")?;
        }
        Ok(())
    }

    fn check_service(&self) -> Result<(), RuntimeConfigError> {
        let service = &self.service;
        for (field, value) in [
            ("service.name", &service.name),
            ("service.description", &service.description),
            ("service.disclosure", &service.disclosure),
        ] {
            if value.trim().is_empty() {
                return Err(RuntimeConfigError::Empty(field));
            }
            if value.len() > MAXIMUM_SERVICE_TEXT_BYTES {
                return Err(RuntimeConfigError::TooLong(field));
            }
        }
        token(&service.details.entity, "service.details.entity")?;
        token(&service.application.entity, "service.application.entity")?;
        token(
            &service.application.target_field,
            "service.application.targetField",
        )?;
        token(
            &service.application.owner_field,
            "service.application.ownerField",
        )?;
        if service.application.owner_field == service.application.target_field {
            return Err(RuntimeConfigError::OwnerFieldIsTarget);
        }
        let review_base_url = service_url(&service.review_base_url, self.development_loopback())
            .ok_or(RuntimeConfigError::InvalidUrl("service.reviewBaseUrl"))?;
        // The review page serves its pages at the root of its publicOrigin.
        if review_base_url.path() != "/" {
            return Err(RuntimeConfigError::ReviewBaseUrlNotOrigin);
        }
        Ok(())
    }
}

fn token(value: &str, field: &'static str) -> Result<(), RuntimeConfigError> {
    if value.is_empty() {
        return Err(RuntimeConfigError::Empty(field));
    }
    if value.len() > MAXIMUM_TOKEN_BYTES {
        return Err(RuntimeConfigError::TooLong(field));
    }
    if value
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        return Err(RuntimeConfigError::InvalidToken(field));
    }
    Ok(())
}

fn tokens(values: &[String], field: &'static str) -> Result<(), RuntimeConfigError> {
    if values.is_empty() {
        return Err(RuntimeConfigError::Empty(field));
    }
    if values.len() > MAXIMUM_NAME_BYTES {
        return Err(RuntimeConfigError::TooLong(field));
    }
    values.iter().try_for_each(|value| token(value, field))
}

/// A bounded, non-empty list of RFC 6749 scope tokens, checked with the
/// platform's own scope grammar.
fn scopes(values: &[String], field: &'static str) -> Result<(), RuntimeConfigError> {
    if values.is_empty() {
        return Err(RuntimeConfigError::Empty(field));
    }
    if values.len() > MAXIMUM_NAME_BYTES {
        return Err(RuntimeConfigError::TooLong(field));
    }
    values.iter().try_for_each(|value| {
        if value.len() > MAXIMUM_TOKEN_BYTES {
            return Err(RuntimeConfigError::TooLong(field));
        }
        if !valid_scope_token(value) {
            return Err(RuntimeConfigError::InvalidScope(field));
        }
        Ok(())
    })
}

/// An RFC 8707 resource indicator, checked with the platform's own
/// resource grammar.
fn resource_uri(value: &str, field: &'static str) -> Result<(), RuntimeConfigError> {
    if value.is_empty() {
        return Err(RuntimeConfigError::Empty(field));
    }
    if value.len() > MAXIMUM_TOKEN_BYTES {
        return Err(RuntimeConfigError::TooLong(field));
    }
    if !valid_resource_uri(value) {
        return Err(RuntimeConfigError::InvalidResource(field));
    }
    Ok(())
}

/// Parse a service endpoint: https, or plain http on a loopback host under
/// development-loopback only.
pub(crate) fn service_url(value: &str, development_loopback: bool) -> Option<Url> {
    let url = Url::parse(value).ok()?;
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.host().is_none()
    {
        return None;
    }
    match url.scheme() {
        "https" => Some(url),
        "http" if development_loopback && loopback_host(&url) => Some(url),
        _ => None,
    }
}

fn loopback_host(url: &Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        Some(Host::Domain(domain)) => domain == "localhost",
        None => false,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) fn document() -> String {
        r#"apiVersion: registry.registrystack.org/breg-mcp-runtime/v1alpha1
kind: BRegMcpRuntimeConfig
listener:
  bind: 127.0.0.1:8110
  tlsTermination: operator-controlled-upstream
secretProviders:
  file:
    root: /run/secrets/breg-mcp
resourceServer:
  resource: https://gateway.example.test/mcp
  issuer: https://login.example.test
  jwksSource:
    kind: uri
    uri: https://login.example.test/jwks.json
  algorithms: [EdDSA, ES256]
  allowedClients: [chat-host]
  requiredScopes: [address-correction:self]
registry:
  baseUrl: https://registry.example.test/
  accessProfile: citizen-agent
  audience: urn:breg:citizen-address-correction
  scopes: [address-correction:self]
exchange:
  tokenEndpoint: https://login.example.test/token
  clientId: citizen-gateway
  privateKeyRef: secret:file/gateway-key
service:
  name: Address correction
  description: Correct the postal address the registry holds for you.
  disclosure: The assistant you use will see your current address and the correction you request.
  details:
    entity: person-address
  application:
    entity: address-correction-request
    targetField: address
    ownerField: owner
  reviewBaseUrl: https://review.example.test
audit:
  hashKeyRef: secret:file/audit-key
  destination: file
  path: /var/lib/breg-mcp/audit/audit.jsonl
rateLimits:
  perCitizen:
    requestsPerMinute: 30
    burst: 10
  perClient:
    requestsPerMinute: 600
    burst: 100
"#
        .to_owned()
    }

    fn load(text: &str) -> Result<RuntimeConfig, RuntimeConfigError> {
        RuntimeConfig::from_slice(text.as_bytes())
    }

    #[test]
    fn a_complete_document_loads() {
        let config = load(&document()).expect("document loads");
        assert_eq!(config.registry.access_profile, "citizen-agent");
        assert_eq!(
            config.limits.max_request_body_bytes,
            DEFAULT_REQUEST_BODY_BYTES
        );
        assert!(matches!(
            config.resource_server.jwks_source,
            JwksSource::Uri { .. }
        ));
    }

    #[test]
    fn a_relative_configuration_path_is_refused() {
        assert!(matches!(
            RuntimeConfig::load("runtime.yaml"),
            Err(RuntimeConfigError::Load(_))
        ));
    }

    #[test]
    fn an_inline_credential_is_refused_without_echoing_it() {
        const CANARY: &str = "canary-inline-private-key-material";
        for (reference, field) in [
            (
                "privateKeyRef: secret:file/gateway-key",
                "exchange.privateKeyRef",
            ),
            ("hashKeyRef: secret:file/audit-key", "audit"),
        ] {
            let key = reference.split(':').next().expect("key");
            let text = document().replace(reference, &format!("{key}: {CANARY}"));
            let error = load(&text).expect_err("an inline credential is refused");
            assert!(error.to_string().contains(field), "{error}");
            assert!(!error.to_string().contains(CANARY));
        }
        let text = document().replace(
            "    kind: uri\n    uri: https://login.example.test/jwks.json",
            &format!("    kind: static\n    documentRef: '{{\"keys\":[\"{CANARY}\"]}}'"),
        );
        let error = load(&text).expect_err("an inline key set is refused");
        assert!(matches!(&error, RuntimeConfigError::Block(_)));
        assert!(
            error
                .to_string()
                .contains("resourceServer.jwksSource.documentRef"),
            "{error}"
        );
        assert!(!error.to_string().contains(CANARY));
    }

    #[test]
    fn runtime_loader_refuses_environment_expressions_in_secret_references() {
        for (authored, expression, field) in [
            (
                "privateKeyRef: secret:file/gateway-key",
                "privateKeyRef: ${BREG_MCP_TEST_KEY:-secret:file/gateway-key}",
                "exchange.privateKeyRef",
            ),
            (
                "hashKeyRef: secret:file/audit-key",
                "hashKeyRef: ${BREG_MCP_TEST_AUDIT:-secret:file/audit-key}",
                "audit.hashKeyRef",
            ),
        ] {
            let error = load(&document().replace(authored, expression))
                .expect_err("secret references stay literal");
            assert!(error.to_string().contains(field), "{error}");
        }
    }

    #[test]
    fn an_omitted_jwks_source_uses_discovery() {
        let text = document().replace(
            "  jwksSource:\n    kind: uri\n    uri: https://login.example.test/jwks.json\n",
            "",
        );
        let config = load(&text).expect("discovery is the shared default");
        assert!(matches!(
            config.resource_server.jwks_source,
            JwksSource::Discovery {}
        ));
    }

    #[test]
    fn retired_config_keys_are_refused_as_unknown_fields() {
        let old_jwks = document().replace("jwksSource:", "jwks:");
        let error = load(&old_jwks).expect_err("old JWKS field is refused");
        assert!(matches!(error, RuntimeConfigError::Load(_)), "{error}");
        assert!(
            error.to_string().contains("unknown field `jwks`"),
            "{error}"
        );

        let old_rotation = document().replace(
            "  path: /var/lib/breg-mcp/audit/audit.jsonl",
            "  path: /var/lib/breg-mcp/audit/audit.jsonl\n  maximumFileBytes: 1048576",
        );
        let error = load(&old_rotation).expect_err("old audit rotation field is refused");
        assert!(matches!(error, RuntimeConfigError::Load(_)), "{error}");
        assert!(
            error
                .to_string()
                .contains("unknown field `maximumFileBytes`"),
            "{error}"
        );
    }

    #[test]
    fn stdout_refuses_file_only_audit_settings() {
        let text = document().replace("destination: file", "destination: stdout");
        assert!(matches!(
            load(&text),
            Err(RuntimeConfigError::InvalidAuditDestination(
                AuditDestinationError::FileOnlyField { .. }
            ))
        ));
    }

    #[test]
    fn a_refused_value_is_not_echoed() {
        const CANARY: &str = "canary-refused-value";
        let text = document().replace("burst: 10", &format!("burst: {CANARY}"));
        let error = load(&text).expect_err("a string burst is refused");
        let message = error.to_string();
        assert!(message.contains("rateLimits.perCitizen.burst"), "{message}");
        assert!(!message.contains(CANARY), "{message}");
    }

    #[test]
    fn unknown_fields_are_refused() {
        let text = document().replace("  accessProfile:", "  bearerToken: x\n  accessProfile:");
        assert!(matches!(load(&text), Err(RuntimeConfigError::Load(_))));
    }

    #[test]
    fn a_public_listener_is_refused() {
        let text = document().replace("bind: 127.0.0.1:8110", "bind: 203.0.113.9:8110");
        assert!(matches!(
            load(&text),
            Err(RuntimeConfigError::InvalidListener)
        ));
        let text = document()
            .replace("bind: 127.0.0.1:8110", "bind: 10.0.0.4:8110")
            .replace("operator-controlled-upstream", "development-loopback");
        assert!(matches!(
            load(&text),
            Err(RuntimeConfigError::InvalidListener)
        ));
    }

    #[test]
    fn plain_http_is_accepted_only_on_loopback_in_development() {
        let http = document().replace("https://registry.example.test/", "http://127.0.0.1:8080/");
        assert!(matches!(
            load(&http),
            Err(RuntimeConfigError::InvalidUrl("registry.baseUrl"))
        ));
        let development = http.replace("operator-controlled-upstream", "development-loopback");
        load(&development).expect("loopback http is accepted in development");
        let remote = document()
            .replace(
                "https://registry.example.test/",
                "http://registry.example.test/",
            )
            .replace("operator-controlled-upstream", "development-loopback");
        assert!(matches!(
            load(&remote),
            Err(RuntimeConfigError::InvalidUrl("registry.baseUrl"))
        ));
    }

    #[test]
    fn the_resource_must_name_the_mcp_endpoint() {
        let text = document().replace(
            "https://gateway.example.test/mcp",
            "https://gateway.example.test/other",
        );
        assert!(matches!(
            load(&text),
            Err(RuntimeConfigError::InvalidResourcePath)
        ));
    }

    #[test]
    fn the_gateway_client_is_never_an_inbound_client() {
        let text = document().replace("[chat-host]", "[chat-host, citizen-gateway]");
        assert!(matches!(
            load(&text),
            Err(RuntimeConfigError::ExchangeClientAdmittedInbound)
        ));
    }

    /// Scopes are RFC 6749 scope tokens, checked as every platform client
    /// checks them: a byte outside the grammar is refused at load, not at
    /// the first exchange.
    #[test]
    fn a_scope_outside_the_rfc_6749_grammar_is_refused() {
        for (from, to, field) in [
            (
                "requiredScopes: [address-correction:self]",
                "requiredScopes: [address-correction:selfé]",
                "resourceServer.requiredScopes",
            ),
            (
                "requiredScopes: [address-correction:self]",
                r#"requiredScopes: ['address-correction:"self"']"#,
                "resourceServer.requiredScopes",
            ),
            (
                "scopes: [address-correction:self]",
                r"scopes: ['address-correction\self']",
                "registry.scopes",
            ),
        ] {
            let text = document().replacen(from, to, 1);
            assert_ne!(text, document(), "{to}");
            assert!(
                matches!(load(&text), Err(RuntimeConfigError::InvalidScope(refused)) if refused == field),
                "{to}"
            );
        }
    }

    /// The registry audience is the RFC 8707 resource of every exchange, so
    /// it must be an absolute URI without a fragment or credentials.
    #[test]
    fn the_registry_audience_is_an_absolute_resource_uri() {
        for audience in [
            "citizen-address-correction",
            "https://registry.example.test/#fragment",
            "https://user@registry.example.test/",
        ] {
            let text = document().replace(
                "audience: urn:breg:citizen-address-correction",
                &format!("audience: '{audience}'"),
            );
            assert!(
                matches!(
                    load(&text),
                    Err(RuntimeConfigError::InvalidResource("registry.audience"))
                ),
                "{audience}"
            );
        }
    }

    /// The review page serves `/requests/<id>` at the root of its
    /// `publicOrigin` and signs in with root-relative return paths, so a
    /// base URL with a path would hand the citizen a link the page does not
    /// serve.
    #[test]
    fn the_review_base_url_is_an_origin_without_a_path() {
        let root = document().replace(
            "reviewBaseUrl: https://review.example.test",
            "reviewBaseUrl: https://review.example.test/",
        );
        load(&root).expect("a trailing slash is the root path");
        for base in [
            "https://review.example.test/citizen",
            "https://review.example.test/citizen/",
            "https://review.example.test//",
        ] {
            let text = document().replace(
                "reviewBaseUrl: https://review.example.test",
                &format!("reviewBaseUrl: {base}"),
            );
            assert!(
                matches!(load(&text), Err(RuntimeConfigError::ReviewBaseUrlNotOrigin)),
                "{base}"
            );
        }
    }

    /// The gateway writes the citizen's record into the target field and the
    /// citizen's principal into the owner field, so one field named twice
    /// would have the owner silently overwrite the target.
    #[test]
    fn the_owner_field_is_not_the_target_field() {
        let text = document().replace("ownerField: owner", "ownerField: address");
        assert!(matches!(
            load(&text),
            Err(RuntimeConfigError::OwnerFieldIsTarget)
        ));
    }

    #[test]
    fn the_registry_audience_is_not_the_gateway_resource() {
        let text = document().replace(
            "audience: urn:breg:citizen-address-correction",
            "audience: https://gateway.example.test/mcp",
        );
        assert!(matches!(
            load(&text),
            Err(RuntimeConfigError::AudienceReused)
        ));
    }
}
