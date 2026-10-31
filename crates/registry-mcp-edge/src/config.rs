// SPDX-License-Identifier: Apache-2.0

//! Product-neutral authored configuration shared by MCP gateway runtimes.

use std::{hash::Hash, path::PathBuf, time::Duration};

use registry_platform_audit::{
    AuditDestination, AuditDestinationError, AuditDestinationKind, MAX_AUDIT_RETAIN_DAYS,
    MIN_AUDIT_ROTATE_BYTES,
};
use registry_platform_config::{
    AuditKeyConfig, ConfigBlockError, JwksSource, SecretProvidersConfig, SecretReference,
};
use registry_platform_httputil::{valid_resource_uri, valid_scope_token};
use registry_platform_yaml::{BoundedU32, BoundedU64, ExternalId, Invalid, UniqueList, Url};
use serde::{de, Deserialize, Deserializer};
use url::Host;

pub use crate::AccessTokenAlgorithm;
use crate::{ResourceServerOptions, MCP_PATH};

/// The most items a restrictive client, scope, or algorithm list may hold.
const MAXIMUM_LIST_ITEMS: usize = 128;
/// The longest scope token or resource indicator, in bytes.
const MAXIMUM_TOKEN_BYTES: usize = 512;
/// The longest access-token lifetime the gateway accepts: one day.
const MAXIMUM_TOKEN_LIFETIME_SECONDS: u64 = 86_400;
/// The request body ceiling no runtime may raise past: 1 MiB.
const MAXIMUM_REQUEST_BYTES: u64 = 1024 * 1024;
/// The most requests a rate limit may admit per minute or in one burst.
const MAXIMUM_RATE: u32 = 1_000_000;
/// The largest `audit.rotateBytes` the shared audit writer accepts.
const MAXIMUM_AUDIT_ROTATE_BYTES: u64 = u32::MAX as u64;

/// The operational log level. The vocabulary is closed so configuration
/// cannot turn on debug output or dependency logging.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[cfg_attr(feature = "schema", derive(serde::Serialize, schemars::JsonSchema))]
#[serde(rename_all = "lowercase")]
pub enum LogLevel {
    Error,
    Warn,
    #[default]
    Info,
}

impl LogLevel {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Error => "error",
            Self::Warn => "warn",
            Self::Info => "info",
        }
    }
}

/// The inbound half: how a chat host's access token is verified.
#[derive(Clone, Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResourceServerConfig {
    /// This gateway's resource identifier: the exact URL of its MCP endpoint,
    /// which every accepted token must name as its audience. An https URL
    /// whose path is `/mcp`, with no query or fragment; plain http is
    /// accepted only on a loopback host under `development-loopback`.
    pub resource: Url,
    /// The exact issuer accepted in access-token `iss` claims. An https URL
    /// with no query or fragment; plain http is accepted only on a loopback
    /// host under `development-loopback`.
    pub issuer: Url,
    /// Where the issuer's signing keys come from. Omitted, they are read
    /// through the issuer's OpenID Connect discovery document.
    #[serde(default)]
    pub jwks_source: JwksSource,
    /// Permit plain HTTP beyond loopback to the declared issuer and to a JWKS
    /// URI declared in `jwksSource`.
    #[serde(default)]
    pub allow_insecure_http: bool,
    /// The asymmetric signature algorithms an accepted token may use.
    #[serde(deserialize_with = "bounded_restricting_list")]
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 128)))]
    pub algorithms: UniqueList<AccessTokenAlgorithm>,
    /// The chat-host clients whose tokens the gateway accepts.
    #[serde(deserialize_with = "bounded_restricting_list")]
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 128)))]
    pub allowed_clients: UniqueList<ExternalId>,
    /// Scopes every accepted token must carry. There is no sentinel for
    /// "any scope": a gateway that acts for a citizen always names the
    /// scope that consent was given for.
    #[serde(deserialize_with = "bounded_restricting_list")]
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 128)))]
    pub required_scopes: UniqueList<ScopeToken>,
    /// The access-token claim that carries the granted scopes.
    #[serde(default = "default_scope_claim")]
    pub scope_claim: ExternalId,
    /// The longest lifetime an accepted access token may declare, from its
    /// `iat` to its `exp`, in seconds.
    #[serde(default = "default_maximum_token_lifetime")]
    pub maximum_token_lifetime_seconds: BoundedU64<1, MAXIMUM_TOKEN_LIFETIME_SECONDS>,
}

impl ResourceServerConfig {
    /// The runtime options passed to the product-neutral authenticated edge.
    #[must_use]
    pub fn options(
        &self,
        resource_name: impl Into<String>,
        principal_audit_namespace: impl Into<String>,
        client_audit_namespace: impl Into<String>,
    ) -> ResourceServerOptions {
        ResourceServerOptions {
            resource: self.resource.as_str().to_owned(),
            issuer: self.issuer.as_str().to_owned(),
            allow_insecure_http: self.allow_insecure_http,
            algorithms: self.algorithms.iter().copied().collect(),
            allowed_clients: self
                .allowed_clients
                .iter()
                .map(ToString::to_string)
                .collect(),
            required_scopes: self
                .required_scopes
                .iter()
                .map(|scope| scope.as_str().to_owned())
                .collect(),
            scope_claim: self.scope_claim.to_string(),
            maximum_token_lifetime: Duration::from_secs(self.maximum_token_lifetime_seconds.get()),
            resource_name: resource_name.into(),
            principal_audit_namespace: principal_audit_namespace.into(),
            client_audit_namespace: client_audit_namespace.into(),
        }
    }

    /// Validate the authored resource-server boundary shared by every MCP
    /// runtime. Product runtimes retain ownership of diagnostic wording.
    #[must_use]
    pub fn validate(
        &self,
        development_loopback: bool,
        secret_providers: &SecretProvidersConfig,
    ) -> Vec<ResourceServerConfigError> {
        let mut errors = Vec::new();
        let resource = self.resource.to_url();
        if !protected_endpoint(&resource, development_loopback) {
            errors.push(ResourceServerConfigError::InsecureResource);
        } else if resource.query().is_some() || resource.fragment().is_some() {
            errors.push(ResourceServerConfigError::InvalidResource);
        }
        if resource.path() != MCP_PATH {
            errors.push(ResourceServerConfigError::ResourceNotMcpEndpoint);
        }

        let issuer = self.issuer.to_url();
        if !issuer_endpoint(&issuer, development_loopback, self.allow_insecure_http) {
            errors.push(ResourceServerConfigError::InsecureIssuer);
        } else if issuer.query().is_some() || issuer.fragment().is_some() {
            errors.push(ResourceServerConfigError::InvalidIssuer);
        }

        if let Err(error) = self.jwks_source.check_with_insecure_http(
            "resourceServer.jwksSource",
            development_loopback,
            self.allow_insecure_http,
        ) {
            errors.push(ResourceServerConfigError::JwksSource(error));
        }
        if let Some(document_ref) = self.jwks_source.document_ref() {
            if let Err(error) = secret_providers
                .check_reference("resourceServer.jwksSource.documentRef", document_ref)
            {
                errors.push(ResourceServerConfigError::JwksDocumentReference(error));
            }
        }
        errors
    }

    /// Value-free operational warning for the explicit insecure opt-in.
    #[must_use]
    pub fn insecure_http_startup_diagnostic(&self) -> Option<&'static str> {
        self.allow_insecure_http.then_some(
            "resourceServer.allowInsecureHttp permits plain HTTP to the configured issuer and to a JWKS URI declared in configuration",
        )
    }
}

/// A product-neutral authored resource-server refusal. Product formats map
/// these variants to their own stable diagnostic codes and paths.
#[derive(Debug)]
pub enum ResourceServerConfigError {
    InvalidResource,
    ResourceNotMcpEndpoint,
    InsecureResource,
    InvalidIssuer,
    InsecureIssuer,
    JwksSource(ConfigBlockError),
    JwksDocumentReference(ConfigBlockError),
}

fn protected_endpoint(url: &url::Url, development_loopback: bool) -> bool {
    url.host().is_some()
        && (url.scheme() == "https"
            || development_loopback && url.scheme() == "http" && loopback_host(url))
}

fn issuer_endpoint(url: &url::Url, development_loopback: bool, allow_insecure_http: bool) -> bool {
    url.host().is_some()
        && (url.scheme() == "https"
            || url.scheme() == "http"
                && (allow_insecure_http || development_loopback && loopback_host(url)))
}

fn loopback_host(url: &url::Url) -> bool {
    match url.host() {
        Some(Host::Ipv4(address)) => address.is_loopback(),
        Some(Host::Ipv6(address)) => address.is_loopback(),
        Some(Host::Domain(domain)) => domain.eq_ignore_ascii_case("localhost"),
        None => false,
    }
}

fn default_scope_claim() -> ExternalId {
    ExternalId::new("scope").expect("the default scope claim is an external identifier")
}

fn default_maximum_token_lifetime() -> BoundedU64<1, MAXIMUM_TOKEN_LIFETIME_SECONDS> {
    BoundedU64::new(3600).expect("the default token lifetime is within its bounds")
}

/// The gateway's own client identity, used only to exchange a verified
/// inbound token for a delegated registry token.
#[derive(Clone, Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ExchangeConfig {
    /// The authorization server's token endpoint. An https URL with no query
    /// or fragment; plain http is accepted only on a loopback host under
    /// `development-loopback`.
    pub token_endpoint: Url,
    /// The gateway's client identifier at the authorization server. It may
    /// not also be one of `resourceServer.allowedClients`.
    pub client_id: ExternalId,
    /// Secret reference to the private JWK the gateway signs its client
    /// assertions with, under a declared provider.
    pub private_key_ref: SecretReference,
    /// The client-assertion audience, when the authorization server expects
    /// one other than its token endpoint. Omitted, the assertion names the
    /// token endpoint.
    #[serde(default)]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "ExternalId", skip_serializing_if = "Option::is_none")
    )]
    pub assertion_audience: Option<ExternalId>,
}

/// The audit block every Registry Stack product shares: the hash key, then a
/// `file` (the default) or `stdout` destination, with rotation and retention
/// for a file.
#[derive(Clone, Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditConfig {
    #[serde(rename(deserialize = "registry-platform-yaml/shared-block/audit-key"))]
    #[cfg_attr(feature = "schema", schemars(flatten))]
    pub key: AuditKeyConfig,
    /// Where audit lines go: `file` or `stdout`.
    #[serde(default)]
    pub destination: AuditDestinationKind,
    /// The absolute path of the active audit file. Required for a `file`
    /// destination, and refused with `stdout`.
    #[serde(default)]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "PathBuf", skip_serializing_if = "Option::is_none")
    )]
    pub path: Option<PathBuf>,
    /// Size at which the active file rotates, in bytes, for a `file`
    /// destination. Default: 100 MiB.
    #[serde(default)]
    #[cfg_attr(
        feature = "schema",
        schemars(
            with = "BoundedU64<MIN_AUDIT_ROTATE_BYTES, MAXIMUM_AUDIT_ROTATE_BYTES>",
            skip_serializing_if = "Option::is_none"
        )
    )]
    pub rotate_bytes: Option<BoundedU64<MIN_AUDIT_ROTATE_BYTES, MAXIMUM_AUDIT_ROTATE_BYTES>>,
    /// Days a rotated file is kept, for a `file` destination. Default: 90.
    #[serde(default)]
    #[cfg_attr(
        feature = "schema",
        schemars(
            with = "BoundedU32<1, MAX_AUDIT_RETAIN_DAYS>",
            skip_serializing_if = "Option::is_none"
        )
    )]
    pub retention_days: Option<BoundedU32<1, MAX_AUDIT_RETAIN_DAYS>>,
}

impl AuditConfig {
    /// The destination the shared audit writer opens.
    pub fn destination(&self) -> Result<AuditDestination, AuditDestinationError> {
        AuditDestination::from_settings(
            self.destination,
            self.path.clone(),
            self.rotate_bytes.map(BoundedU64::get),
            self.retention_days.map(BoundedU32::get),
        )
    }
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RateLimitConfig {
    /// Requests admitted per minute, on average.
    pub requests_per_minute: BoundedU32<1, MAXIMUM_RATE>,
    /// Requests admitted at once before the average applies.
    pub burst: BoundedU32<1, MAXIMUM_RATE>,
}

#[derive(Clone, Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LimitsConfig {
    /// Largest request body the MCP endpoint reads, in bytes.
    #[serde(default = "default_maximum_request_bytes")]
    pub maximum_request_bytes: BoundedU64<1, MAXIMUM_REQUEST_BYTES>,
}

impl LimitsConfig {
    /// `maximumRequestBytes` as a length. The bound is 1 MiB, which fits
    /// `usize` on every target the workspace builds for.
    #[must_use]
    pub fn request_bytes(&self) -> usize {
        usize::try_from(self.maximum_request_bytes.get()).expect("the request bound fits usize")
    }
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            maximum_request_bytes: default_maximum_request_bytes(),
        }
    }
}

fn default_maximum_request_bytes() -> BoundedU64<1, MAXIMUM_REQUEST_BYTES> {
    BoundedU64::new(64 * 1024).expect("the default request ceiling is within its bounds")
}

macro_rules! checked_text {
    ($(#[$meta:meta])* $name:ident, $valid:expr, $invalid:expr) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn new(text: impl Into<String>) -> Result<Self, Invalid> {
                let text = text.into();
                let valid: fn(&str) -> bool = $valid;
                if valid(&text) { Ok(Self(text)) } else { Err($invalid) }
            }

            #[must_use]
            pub fn as_str(&self) -> &str { &self.0 }
        }

        impl std::ops::Deref for $name {
            type Target = str;
            fn deref(&self) -> &str { &self.0 }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
                let text = String::deserialize(deserializer)?;
                Self::new(text).map_err(Invalid::into_error)
            }
        }
    };
}

checked_text!(
    /// An RFC 6749 scope token: 1 to 512 bytes of printable ASCII other than
    /// space, `"`, and `\`, checked with the platform's own scope grammar.
    ScopeToken,
    |text| text.len() <= MAXIMUM_TOKEN_BYTES && valid_scope_token(text),
    Invalid::expected(
        "an RFC 6749 scope token of 1 to 512 printable ASCII characters, without spaces, quotes, or backslashes",
        "Write the scope as one token, exactly as the authorization server issues it."
    )
);

checked_text!(
    /// An RFC 8707 resource indicator of at most 512 bytes: an absolute URI
    /// without a fragment or user information, checked with the platform's
    /// own resource grammar.
    ResourceUri,
    |text| text.len() <= MAXIMUM_TOKEN_BYTES && valid_resource_uri(text),
    Invalid::expected(
        "an absolute URI of at most 512 characters, without a fragment or user information",
        "Write the registry's token audience as an absolute URI, such as a urn: name or an https URL, without a fragment or credentials."
    )
);

/// Deserialize a restrictive set of 1 to 128 unique items.
pub fn bounded_restricting_list<'de, D, T>(deserializer: D) -> Result<UniqueList<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Eq + Hash,
{
    let list = UniqueList::<T>::deserialize(deserializer)?;
    if list.is_empty() || list.len() > MAXIMUM_LIST_ITEMS {
        return Err(de::Error::invalid_length(list.len(), &"1 to 128 items"));
    }
    Ok(list)
}

#[cfg(feature = "schema")]
mod schema_impls {
    use std::borrow::Cow;

    use schemars::{json_schema, JsonSchema, Schema, SchemaGenerator};

    use super::{ResourceUri, ScopeToken};

    impl JsonSchema for ScopeToken {
        fn schema_name() -> Cow<'static, str> {
            Cow::Borrowed("ScopeToken")
        }

        fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
            json_schema!({
                "type": "string", "minLength": 1, "maxLength": 512,
                "pattern": "^[!#-\\[\\]-~]+$",
                "description": "An RFC 6749 scope token: printable ASCII other than space, `\"`, and `\\`."
            })
        }
    }

    impl JsonSchema for ResourceUri {
        fn schema_name() -> Cow<'static, str> {
            Cow::Borrowed("ResourceUri")
        }

        fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
            json_schema!({
                "type": "string", "minLength": 1, "maxLength": 512,
                "pattern": "^[A-Za-z][A-Za-z0-9+.-]*:(?:[A-Za-z0-9._~:/?\\[\\]@!$&'()*+,;=-]|%[0-9A-Fa-f]{2})*$",
                "description": "An RFC 8707 resource indicator: an absolute URI without a fragment. The reader also refuses user information and a URI it cannot parse."
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use registry_platform_config::{
        EnvironmentSecretProviderConfig, JwksSource, SecretProvidersConfig,
    };
    use registry_platform_yaml::{ExternalId, UniqueList, Url};

    use super::*;

    fn resource_server() -> ResourceServerConfig {
        ResourceServerConfig {
            resource: Url::new("https://gateway.example.test/mcp").expect("resource"),
            issuer: Url::new("https://login.example.test").expect("issuer"),
            jwks_source: JwksSource::Discovery {},
            allow_insecure_http: false,
            algorithms: UniqueList::new(vec![AccessTokenAlgorithm::EdDSA]).expect("algorithms"),
            allowed_clients: UniqueList::new(vec![ExternalId::new("chat-host").expect("client")])
                .expect("clients"),
            required_scopes: UniqueList::new(vec![
                ScopeToken::new("address-correction:self").expect("scope")
            ])
            .expect("scopes"),
            scope_claim: ExternalId::new("scope").expect("claim"),
            maximum_token_lifetime_seconds: BoundedU64::new(3600).expect("lifetime"),
        }
    }

    fn secret_providers() -> SecretProvidersConfig {
        SecretProvidersConfig {
            environment: Some(EnvironmentSecretProviderConfig {}),
            file: None,
        }
    }

    #[test]
    fn resource_options_preserve_the_authored_identity_and_algorithms() {
        let config = resource_server();
        let options = config.options("Address correction", "mcp.principal", "mcp.client");
        assert_eq!(options.resource, "https://gateway.example.test/mcp");
        assert_eq!(options.issuer, "https://login.example.test");
        assert_eq!(options.algorithms, vec![AccessTokenAlgorithm::EdDSA]);
        assert_eq!(options.required_scopes, vec!["address-correction:self"]);
        assert_eq!(options.resource_name, "Address correction");
        options.validate().expect("neutral options validate");
    }

    #[test]
    fn authored_resource_validation_is_shared_and_development_is_explicit() {
        let mut config = resource_server();
        config.resource = Url::new("http://127.0.0.1:8110/mcp").expect("loopback resource");
        config.issuer = Url::new("http://localhost:8111").expect("loopback issuer");
        assert!(config
            .validate(false, &secret_providers())
            .iter()
            .any(|error| { matches!(error, ResourceServerConfigError::InsecureResource) }));
        assert!(config
            .validate(false, &secret_providers())
            .iter()
            .any(|error| { matches!(error, ResourceServerConfigError::InsecureIssuer) }));
        assert!(config.validate(true, &secret_providers()).is_empty());
    }

    #[test]
    fn authored_resource_validation_reports_the_mcp_path_and_static_secret() {
        let mut config = resource_server();
        config.resource = Url::new("https://gateway.example.test/other").expect("other path");
        config.jwks_source = JwksSource::Static {
            document_ref: "secret:file/jwks".to_owned(),
        };
        let errors = config.validate(false, &secret_providers());
        assert!(errors
            .iter()
            .any(|error| { matches!(error, ResourceServerConfigError::ResourceNotMcpEndpoint) }));
        assert!(errors
            .iter()
            .any(|error| { matches!(error, ResourceServerConfigError::JwksDocumentReference(_)) }));
    }

    #[test]
    fn exchange_credentials_decode_without_a_product_runtime() {
        let exchange: ExchangeConfig = serde_json::from_value(serde_json::json!({
            "tokenEndpoint": "https://login.example.test/token",
            "clientId": "gateway-client",
            "privateKeyRef": "secret:env/GATEWAY_PRIVATE_KEY",
            "assertionAudience": "token-service"
        }))
        .expect("neutral exchange decodes");
        assert_eq!(exchange.client_id.as_str(), "gateway-client");
        assert_eq!(
            exchange.private_key_ref.as_str(),
            "secret:env/GATEWAY_PRIVATE_KEY"
        );
    }
}
