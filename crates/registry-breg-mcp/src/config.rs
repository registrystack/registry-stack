// SPDX-License-Identifier: Apache-2.0

//! The operator runtime configuration document.
//!
//! The inbound resource server and the outbound registry exchange are two
//! sections that share no field: nothing the gateway accepts from a chat host
//! is configured by the same key as anything it presents to the registry.
//! Every credential is a `secret:env/` or `secret:file/` reference, never
//! inline text.

use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

use registry_platform_config::{SecretError, SecretReference, MAX_SECRET_BYTES};
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
const DEFAULT_AUDIT_FILE_BYTES: u64 = 64 * 1024 * 1024;
const DEFAULT_REQUEST_BODY_BYTES: usize = 64 * 1024;
const MAXIMUM_REQUEST_BODY_BYTES: usize = 1024 * 1024;

/// The operator runtime configuration document.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeConfig {
    pub api_version: String,
    pub kind: String,
    pub listener: ListenerConfig,
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

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListenerConfig {
    #[serde(default = "default_listener_bind")]
    pub bind: SocketAddr,
    pub tls_termination: TlsTermination,
    #[serde(default)]
    pub network_exposure: ListenerNetworkExposure,
}

fn default_listener_bind() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 8110))
}

/// The trusted transport boundary of the plaintext listener. Production
/// listeners sit behind operator-controlled TLS termination; direct plaintext
/// is limited to the explicit loopback-only development mode.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum TlsTermination {
    OperatorControlledUpstream,
    DevelopmentLoopback,
}

/// The operator-declared private network placement of the listener.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum ListenerNetworkExposure {
    #[default]
    PrivateAddress,
    ContainerPrivate,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretProvidersConfig {
    #[serde(default)]
    pub file: Option<FileSecretProviderConfig>,
    #[serde(default)]
    pub environment: Option<EnvironmentSecretProviderConfig>,
}

#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentSecretProviderConfig {}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileSecretProviderConfig {
    pub root: PathBuf,
}

/// The inbound half: how a chat host's access token is verified.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceServerConfig {
    /// This gateway's resource identifier: the exact URL of its MCP endpoint,
    /// which every accepted token must name as its audience.
    pub resource: String,
    pub issuer: String,
    pub jwks: JwksSource,
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

/// Where the inbound verifier reads its keys.
#[derive(Clone, Debug, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum JwksSource {
    /// Fetch the issuer's published key set.
    Uri { uri: String },
    /// A pinned key set read from a secret reference at startup.
    Static { document_ref: String },
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
    /// The API name of the field that references the citizen's own record.
    pub target_field: String,
    /// The API name of the field that records the citizen's principal.
    pub owner_field: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditConfig {
    pub path: PathBuf,
    pub hash_key_ref: String,
    #[serde(default = "default_audit_file_bytes")]
    pub maximum_file_bytes: u64,
}

const fn default_audit_file_bytes() -> u64 {
    DEFAULT_AUDIT_FILE_BYTES
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
    #[error("the runtime configuration path must be absolute")]
    RelativeRuntimePath,
    #[error("the runtime configuration could not be read")]
    Read(#[source] std::io::Error),
    #[error("the runtime configuration is not valid at {path}: {cause}")]
    Parse { path: String, cause: String },
    #[error("unsupported runtime apiVersion; expected {RUNTIME_API_VERSION}")]
    InvalidApiVersion,
    #[error("unsupported runtime kind; expected {RUNTIME_KIND}")]
    InvalidKind,
    #[error("{0} must be an absolute path")]
    RelativeOperatedPath(&'static str),
    #[error("secretProviders must enable the file provider, the environment provider, or both")]
    InvalidSecretProviders,
    #[error(
        "the listener must bind a loopback or private address for its tlsTermination and networkExposure"
    )]
    InvalidListener,
    #[error("{0} is not an exact secret:env/NAME or secret:file/name reference")]
    InlineCredential(&'static str),
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
    #[error("the gateway's own exchange client may not be an accepted inbound client")]
    ExchangeClientAdmittedInbound,
    #[error("the registry audience must differ from the gateway's own resource")]
    AudienceReused,
    #[error("{0} must be greater than zero")]
    Zero(&'static str),
}

impl RuntimeConfig {
    /// Load and validate the operator document.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, RuntimeConfigError> {
        if !path.as_ref().is_absolute() {
            return Err(RuntimeConfigError::RelativeRuntimePath);
        }
        let bytes = std::fs::read(path.as_ref()).map_err(RuntimeConfigError::Read)?;
        Self::from_slice(&bytes)
    }

    /// Parse and validate a document already read.
    pub fn from_slice(bytes: &[u8]) -> Result<Self, RuntimeConfigError> {
        let deserializer = serde_norway::Deserializer::from_slice(bytes);
        let config: Self = serde_path_to_error::deserialize(deserializer).map_err(|error| {
            let (path, cause) = refused_yaml(error);
            RuntimeConfigError::Parse { path, cause }
        })?;
        config.check()?;
        Ok(config)
    }

    /// Validate everything that can be checked without resolving a secret.
    pub fn check(&self) -> Result<(), RuntimeConfigError> {
        if self.api_version != RUNTIME_API_VERSION {
            return Err(RuntimeConfigError::InvalidApiVersion);
        }
        if self.kind != RUNTIME_KIND {
            return Err(RuntimeConfigError::InvalidKind);
        }
        self.check_operated_paths()?;
        if !valid_listener(
            self.listener.bind.ip(),
            self.listener.network_exposure,
            self.listener.tls_termination,
        ) {
            return Err(RuntimeConfigError::InvalidListener);
        }
        self.check_resource_server()?;
        self.check_registry()?;
        self.check_service()?;
        secret_reference(&self.audit.hash_key_ref, "audit.hashKeyRef")?;
        if self.audit.maximum_file_bytes == 0 {
            return Err(RuntimeConfigError::Zero("audit.maximumFileBytes"));
        }
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
        self.listener.tls_termination == TlsTermination::DevelopmentLoopback
    }

    fn check_operated_paths(&self) -> Result<(), RuntimeConfigError> {
        if self.secret_providers.file.is_none() && self.secret_providers.environment.is_none() {
            return Err(RuntimeConfigError::InvalidSecretProviders);
        }
        if self
            .secret_providers
            .file
            .as_ref()
            .is_some_and(|file| !file.root.is_absolute())
        {
            return Err(RuntimeConfigError::RelativeOperatedPath(
                "secretProviders.file.root",
            ));
        }
        if !self.audit.path.is_absolute() {
            return Err(RuntimeConfigError::RelativeOperatedPath("audit.path"));
        }
        Ok(())
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
        match &server.jwks {
            JwksSource::Uri { uri } => {
                service_url(uri, development)
                    .ok_or(RuntimeConfigError::InvalidUrl("resourceServer.jwks.uri"))?;
            }
            JwksSource::Static { document_ref } => {
                secret_reference(document_ref, "resourceServer.jwks.documentRef")?;
            }
        }
        if server.algorithms.is_empty() {
            return Err(RuntimeConfigError::Empty("resourceServer.algorithms"));
        }
        tokens(&server.allowed_clients, "resourceServer.allowedClients")?;
        tokens(&server.required_scopes, "resourceServer.requiredScopes")?;
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
        token(&self.registry.audience, "registry.audience")?;
        tokens(&self.registry.scopes, "registry.scopes")?;
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
        secret_reference(&self.exchange.private_key_ref, "exchange.privateKeyRef")?;
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
        service_url(&service.review_base_url, self.development_loopback())
            .ok_or(RuntimeConfigError::InvalidUrl("service.reviewBaseUrl"))?;
        Ok(())
    }
}

/// Explain one refused secret resolution without disclosing what it protects.
///
/// Only a reference that already parsed reaches the resolver, so the
/// reference is safe to name; the resolved bytes and opened path never appear.
pub(crate) fn describe_secret_failure(
    field: &'static str,
    reference: &str,
    error: &SecretError,
) -> String {
    let reason = match error {
        SecretError::InvalidReference => {
            return format!(
                "the secret reference configured at {field} is not an exact secret:env/NAME or secret:file/name reference"
            );
        }
        SecretError::ProviderDisabled => "its provider is not enabled for this runtime".to_owned(),
        SecretError::InvalidProviderConfiguration => {
            "the secret provider configuration is invalid".to_owned()
        }
        SecretError::Unavailable => {
            "no readable secret of that name exists under the configured provider".to_owned()
        }
        SecretError::UnsafeFile => concat!(
            "the secret file must be a regular file owned by the runtime user, ",
            "with mode 0400 or 0600, and exactly one hard link"
        )
        .to_owned(),
        SecretError::Read => "the secret could not be read".to_owned(),
        SecretError::InvalidValue => format!(
            "the secret value must be non-empty text of at most {MAX_SECRET_BYTES} bytes \
             without NUL bytes"
        ),
    };
    format!(
        "the secret reference {reference} configured at {field} could not be resolved: {reason}"
    )
}

fn secret_reference(value: &str, field: &'static str) -> Result<(), RuntimeConfigError> {
    SecretReference::parse(value)
        .map(|_| ())
        .map_err(|_| RuntimeConfigError::InlineCredential(field))
}

fn token(value: &str, field: &'static str) -> Result<(), RuntimeConfigError> {
    if value.is_empty() {
        return Err(RuntimeConfigError::Empty(field));
    }
    if value.len() > MAXIMUM_SERVICE_TEXT_BYTES.min(512) {
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

fn valid_listener(
    address: IpAddr,
    exposure: ListenerNetworkExposure,
    tls_termination: TlsTermination,
) -> bool {
    if address.is_multicast() {
        return false;
    }
    if tls_termination == TlsTermination::DevelopmentLoopback {
        return exposure == ListenerNetworkExposure::PrivateAddress && address.is_loopback();
    }
    match (address, exposure) {
        (IpAddr::V4(address), ListenerNetworkExposure::PrivateAddress) => {
            address.is_loopback() || address.is_private()
        }
        (IpAddr::V6(address), ListenerNetworkExposure::PrivateAddress) => {
            address.is_loopback() || is_unique_local(address)
        }
        (IpAddr::V4(address), ListenerNetworkExposure::ContainerPrivate) => {
            address.is_unspecified() || address.is_loopback() || address.is_private()
        }
        (IpAddr::V6(address), ListenerNetworkExposure::ContainerPrivate) => {
            address.is_unspecified() || address.is_loopback() || is_unique_local(address)
        }
    }
}

fn is_unique_local(address: Ipv6Addr) -> bool {
    address.octets()[0] & 0xfe == 0xfc
}

/// Name where a YAML document was refused and why, without the refused value.
fn refused_yaml(error: serde_path_to_error::Error<serde_norway::Error>) -> (String, String) {
    let path = error.path().to_string();
    let path = if path == "." { "/".to_owned() } else { path };
    (path, redact_refused_values(&error.into_inner().to_string()))
}

/// Keep the member, reason, and location of a refusal while the refused value
/// stays out of the message: serde reports it inside an `invalid type:` or
/// `invalid value:` clause, and only the shape word opening such a clause
/// survives.
fn redact_refused_values(message: &str) -> String {
    const CLAUSES: [&str; 2] = ["invalid type: ", "invalid value: "];
    let mut redacted = String::with_capacity(message.len());
    let mut rest = message;
    loop {
        let Some((start, len)) = CLAUSES
            .iter()
            .filter_map(|clause| rest.find(clause).map(|start| (start, clause.len())))
            .min_by_key(|(start, _)| *start)
        else {
            redacted.push_str(rest);
            return redacted;
        };
        let opened = start + len;
        redacted.push_str(&rest[..opened]);
        let (shape, tail) = split_refused_value(&rest[opened..]);
        redacted.push_str(shape);
        rest = tail;
    }
}

/// Split the text after a clause marker into the shape word serde names and
/// the remainder that follows the refused value, which serde renders with
/// `Debug` and so opens with a quote or a backtick.
fn split_refused_value(clause: &str) -> (&str, &str) {
    let bytes = clause.as_bytes();
    let mut index = 0;
    let mut shape_end = None;
    while index < bytes.len() {
        match bytes[index] {
            delimiter @ (b'"' | b'`') => {
                shape_end.get_or_insert(index);
                index = skip_delimited(bytes, index, delimiter);
            }
            b',' => break,
            _ => index += 1,
        }
    }
    let shape_end = shape_end.unwrap_or(index);
    (clause[..shape_end].trim_end(), &clause[index..])
}

/// Return the offset just past the delimited run that opens at `open`; an
/// escaped delimiter does not end the run.
fn skip_delimited(bytes: &[u8], open: usize, delimiter: u8) -> usize {
    let mut index = open + 1;
    while index < bytes.len() {
        match bytes[index] {
            b'\\' => index += 2,
            byte if byte == delimiter => return index + 1,
            _ => index += 1,
        }
    }
    bytes.len()
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
  jwks:
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
  path: /var/lib/breg-mcp/audit/audit.jsonl
  hashKeyRef: secret:file/audit-key
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
            config.resource_server.jwks,
            JwksSource::Uri { .. }
        ));
    }

    #[test]
    fn a_relative_configuration_path_is_refused() {
        assert!(matches!(
            RuntimeConfig::load("runtime.yaml"),
            Err(RuntimeConfigError::RelativeRuntimePath)
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
            ("hashKeyRef: secret:file/audit-key", "audit.hashKeyRef"),
        ] {
            let key = reference.split(':').next().expect("key");
            let text = document().replace(reference, &format!("{key}: {CANARY}"));
            let error = load(&text).expect_err("an inline credential is refused");
            assert!(
                matches!(error, RuntimeConfigError::InlineCredential(named) if named == field),
                "{error}"
            );
            assert!(!error.to_string().contains(CANARY));
        }
        let text = document().replace(
            "    kind: uri\n    uri: https://login.example.test/jwks.json",
            &format!("    kind: static\n    documentRef: '{{\"keys\":[\"{CANARY}\"]}}'"),
        );
        let error = load(&text).expect_err("an inline key set is refused");
        assert!(matches!(
            error,
            RuntimeConfigError::InlineCredential("resourceServer.jwks.documentRef")
        ));
        assert!(!error.to_string().contains(CANARY));
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
        assert!(matches!(load(&text), Err(RuntimeConfigError::Parse { .. })));
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
