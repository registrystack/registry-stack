// SPDX-License-Identifier: Apache-2.0

//! Product-neutral authored configuration shared by MCP gateway runtimes.

use std::{hash::Hash, path::PathBuf, time::Duration};

use registry_platform_audit::{
    AuditDestination, AuditDestinationError, AuditDestinationKind, MAX_AUDIT_RETAIN_DAYS,
    MIN_AUDIT_ROTATE_BYTES,
};
use registry_platform_config::{
    AuditKeyConfig, ConfigBlockError, DevelopmentClass, DevelopmentOnlyRefused, DevelopmentSetting,
    DevelopmentWitness, FoundSetting, Gated, InsecureHttp, JwksSource, PostureReport,
    SecretProvidersConfig, SecretReference, SettingOrigin,
};
use registry_platform_httputil::{loopback::loopback_host, valid_resource_uri, valid_scope_token};
use registry_platform_yaml::{BoundedU32, BoundedU64, ExternalId, Invalid, UniqueList, Url};
use serde::{de, Deserialize, Deserializer};

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
    /// accepted when the process declares development.
    #[cfg_attr(feature = "schema", schemars(extend("x-registry-development-only" = ["platform.posture.mcp-http-resource"])))]
    #[cfg_attr(feature = "schema", schemars(with = "Url"))]
    resource: Gated<PublishedResource>,
    /// The exact issuer accepted in access-token `iss` claims. An https URL
    /// with no query or fragment. Plain HTTP requires development. Beyond
    /// loopback it also requires `allowInsecureHttp`.
    #[cfg_attr(feature = "schema", schemars(extend("x-registry-development-only" = ["platform.posture.mcp-http-published-issuer"])))]
    #[cfg_attr(feature = "schema", schemars(with = "Url"))]
    issuer: Gated<PublishedIssuer>,
    /// Where the issuer's signing keys come from. Omitted, they are read
    /// through the issuer's OpenID Connect discovery document.
    #[serde(default = "default_jwks_source")]
    #[cfg_attr(feature = "schema", schemars(default = "default_jwks_source"))]
    pub jwks_source: Gated<JwksSource>,
    /// Permit plain HTTP beyond loopback to the declared issuer and to a JWKS
    /// URI declared in `jwksSource`. Requires declared development posture.
    #[serde(default, deserialize_with = "deserialize_insecure_http")]
    #[cfg_attr(
        feature = "schema",
        schemars(extend("x-registry-development-only" = ["platform.posture.insecure-issuer-http"]))
    )]
    pub allow_insecure_http: bool,
    /// The asymmetric signature algorithms an accepted token may use.
    #[serde(deserialize_with = "bounded_restricting_list")]
    #[cfg_attr(
        feature = "schema",
        schemars(
            with = "UniqueList<schema_impls::AccessTokenAlgorithmSchema>",
            length(min = 1, max = 128)
        )
    )]
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

static HTTP_RESOURCE: DevelopmentSetting = DevelopmentSetting {
    code: "platform.posture.mcp-http-resource",
    key: "resource",
    summary: "The protected resource identifier is plain http",
    production: "Use an https resource identifier.",
};

#[derive(Clone, Debug, Deserialize)]
#[serde(transparent)]
struct PublishedResource(Url);

impl DevelopmentClass for PublishedResource {
    const SETTINGS: &'static [&'static DevelopmentSetting] = &[&HTTP_RESOURCE];

    fn development_setting(&self) -> Option<&'static DevelopmentSetting> {
        (self.0.to_url().scheme() == "http").then_some(&HTTP_RESOURCE)
    }
}

static HTTP_ISSUER: DevelopmentSetting = DevelopmentSetting {
    code: "platform.posture.mcp-http-published-issuer",
    key: "issuer",
    summary: "The published resource server issuer is plain http",
    production: "Use an https issuer.",
};

/// The issuer the gateway publishes in its protected-resource metadata and
/// accepts in `iss`. Plain http is development-only on every host.
#[derive(Clone, Debug, Deserialize)]
#[serde(transparent)]
struct PublishedIssuer(Url);

impl DevelopmentClass for PublishedIssuer {
    const SETTINGS: &'static [&'static DevelopmentSetting] = &[&HTTP_ISSUER];

    fn development_setting(&self) -> Option<&'static DevelopmentSetting> {
        (self.0.to_url().scheme() == "http").then_some(&HTTP_ISSUER)
    }
}

/// Record each of `settings` the report does not already hold. The loader
/// records most of them while it decodes, with their source positions.
pub fn record_development_settings(report: &mut PostureReport, settings: Vec<FoundSetting>) {
    for found in settings {
        let recorded = report.settings().iter().any(|recorded| {
            recorded.setting.code == found.setting.code && recorded.pointer == found.pointer
        });
        if !recorded {
            report.record(found);
        }
    }
}

/// `settings` as a value-free list for a startup refusal: each code and,
/// when it has one, its pointer.
#[must_use]
pub fn describe_development_settings(settings: &[FoundSetting]) -> String {
    settings
        .iter()
        .map(|found| match &found.pointer {
            Some(pointer) => format!("{} at {pointer}", found.setting.code),
            None => found.setting.code.to_owned(),
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// One development-only setting at `pointer`, found in the runtime file.
pub(crate) fn found_at(pointer: String, setting: &'static DevelopmentSetting) -> FoundSetting {
    FoundSetting {
        setting,
        pointer: Some(pointer),
        position: None,
        origin: SettingOrigin::RuntimeFile,
    }
}

impl ResourceServerConfig {
    pub fn resource_url(
        &self,
        development: Option<&DevelopmentWitness>,
    ) -> Result<&Url, DevelopmentOnlyRefused> {
        self.resource.get(development).map(|value| &value.0)
    }

    /// The issuer, which only a development process may read when it is
    /// plain http.
    pub fn issuer_url(
        &self,
        development: Option<&DevelopmentWitness>,
    ) -> Result<&Url, DevelopmentOnlyRefused> {
        self.issuer.get(development).map(|value| &value.0)
    }

    /// Every development-only setting this block holds, each with its
    /// pointer under `/resourceServer`. A runtime lists them with its other
    /// blocks' settings, records the list when it reads the file, and refuses
    /// to build a production gateway while the list is not empty.
    #[must_use]
    pub fn development_settings(&self) -> Vec<FoundSetting> {
        [
            ("resource", self.resource.development_setting()),
            ("issuer", self.issuer.development_setting()),
            ("jwksSource", self.jwks_source.development_setting()),
            (
                "allowInsecureHttp",
                InsecureHttp(self.allow_insecure_http).development_setting(),
            ),
        ]
        .into_iter()
        .filter_map(|(member, setting)| {
            setting.map(|setting| found_at(format!("/resourceServer/{member}"), setting))
        })
        .collect()
    }

    /// The runtime options passed to the product-neutral authenticated edge.
    pub fn options(
        &self,
        development: Option<&DevelopmentWitness>,
        resource_name: impl Into<String>,
        principal_audit_namespace: impl Into<String>,
        client_audit_namespace: impl Into<String>,
    ) -> Result<ResourceServerOptions, DevelopmentOnlyRefused> {
        Ok(ResourceServerOptions {
            resource: self.resource_url(development)?.as_str().to_owned(),
            issuer: self.issuer_url(development)?.as_str().to_owned(),
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
        })
    }

    /// Validate the authored resource-server boundary shared by every MCP
    /// runtime. Product runtimes retain ownership of diagnostic wording.
    #[must_use]
    pub fn validate(
        &self,
        allow_http_resource: bool,
        secret_providers: &SecretProvidersConfig,
        development: Option<&DevelopmentWitness>,
    ) -> Vec<ResourceServerConfigError> {
        let mut errors = Vec::new();
        if let Ok(resource) = self.resource_url(development) {
            let resource = resource.to_url();
            if !protected_endpoint(&resource, allow_http_resource) {
                errors.push(ResourceServerConfigError::InsecureResource);
            } else if resource.query().is_some() || resource.fragment().is_some() {
                errors.push(ResourceServerConfigError::InvalidResource);
            }
            if resource.path() != MCP_PATH {
                errors.push(ResourceServerConfigError::ResourceNotMcpEndpoint);
            }
        } else if !allow_http_resource {
            errors.push(ResourceServerConfigError::InsecureResource);
        }

        // A plain http issuer read without the witness is the posture
        // report's finding, not this check's.
        if let Ok(issuer) = self.issuer_url(development) {
            let issuer = issuer.to_url();
            if !issuer_endpoint(&issuer, self.allow_insecure_http) {
                errors.push(ResourceServerConfigError::InsecureIssuer);
            } else if issuer.query().is_some() || issuer.fragment().is_some() {
                errors.push(ResourceServerConfigError::InvalidIssuer);
            }
        }

        if let Ok(source) = self.jwks_source.get(development) {
            if let Err(error) = source.check_with_insecure_http(
                "resourceServer.jwksSource",
                true,
                self.allow_insecure_http,
            ) {
                errors.push(ResourceServerConfigError::JwksSource(error));
            }
            if let Some(document_ref) = source.document_ref() {
                if let Err(error) = secret_providers
                    .check_reference("resourceServer.jwksSource.documentRef", document_ref)
                {
                    errors.push(ResourceServerConfigError::JwksDocumentReference(error));
                }
            }
        }
        errors
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

fn default_jwks_source() -> Gated<JwksSource> {
    Gated::everywhere(JwksSource::default()).expect("discovery is valid in every posture")
}

fn deserialize_insecure_http<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<bool, D::Error> {
    Gated::<InsecureHttp>::deserialize(deserializer)
        .map(|value| value.development_setting().is_some())
}

fn protected_endpoint(url: &url::Url, allow_http_resource: bool) -> bool {
    url.host().is_some()
        && (url.scheme() == "https" || allow_http_resource && url.scheme() == "http")
}

fn issuer_endpoint(url: &url::Url, allow_insecure_http: bool) -> bool {
    url.host().is_some()
        && (url.scheme() == "https"
            || url.scheme() == "http" && (allow_insecure_http || is_loopback(url)))
}

fn is_loopback(url: &url::Url) -> bool {
    url.host_str()
        .is_some_and(|host| loopback_host(host).is_some())
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
    /// or fragment; plain HTTP is accepted on loopback in both postures.
    pub token_endpoint: Url,
    /// The gateway's client identifier at the authorization server. It may
    /// not also be one of `resourceServer.allowedClients`.
    pub client_id: ExternalId,
    /// Secret reference to the private JWK the gateway signs its client
    /// assertions with, under a declared provider.
    pub private_key_ref: SecretReference,
    /// The authorization server's issuer identifier, exactly as its metadata
    /// publishes it: the client assertion's sole audience. It has no default.
    pub assertion_audience: ExternalId,
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

    /// The development-only setting this block holds, with its pointer under
    /// `/audit`: a hash key a development tool generated.
    #[must_use]
    pub fn development_settings(&self) -> Vec<FoundSetting> {
        self.key
            .hash_key_custody
            .development_setting()
            .map(|setting| found_at("/audit/hashKeyCustody".to_owned(), setting))
            .into_iter()
            .collect()
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

    use super::{AccessTokenAlgorithm, ResourceUri, ScopeToken};

    /// The published schema of an accepted-token algorithm. The generated
    /// schema keeps its established member order and description.
    pub(super) struct AccessTokenAlgorithmSchema;

    impl JsonSchema for AccessTokenAlgorithmSchema {
        fn schema_name() -> Cow<'static, str> {
            Cow::Borrowed("AccessTokenAlgorithm")
        }

        fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
            let mut schema = AccessTokenAlgorithm::subset_schema(&[
                AccessTokenAlgorithm::RS256,
                AccessTokenAlgorithm::RS384,
                AccessTokenAlgorithm::ES256,
                AccessTokenAlgorithm::ES384,
                AccessTokenAlgorithm::EdDSA,
            ]);
            schema.insert(
                "description".to_owned(),
                "An asymmetric access-token signature algorithm.".into(),
            );
            schema
        }
    }

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
    use registry_platform_yaml::{ExternalId, UniqueList};

    use super::*;

    fn resource_server() -> ResourceServerConfig {
        ResourceServerConfig {
            resource: test_resource("https://gateway.example.test/mcp"),
            issuer: test_issuer("https://login.example.test"),
            jwks_source: default_jwks_source(),
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

    fn test_resource(url: impl AsRef<str>) -> Gated<PublishedResource> {
        serde_json::from_value(serde_json::json!(url.as_ref())).expect("resource URL")
    }

    fn test_issuer(url: impl AsRef<str>) -> Gated<PublishedIssuer> {
        serde_json::from_value(serde_json::json!(url.as_ref())).expect("issuer URL")
    }

    /// The witness a development process holds, from the loader that issues it.
    fn development_witness() -> DevelopmentWitness {
        use registry_platform_config::{
            DeclaredPosture, Posture, PostureSource, RuntimeConfigLoader, RuntimeEnvelope,
        };
        const API_VERSION: &str = "id.registrystack.org/formats/platform/edge-test/v1alpha1";
        RuntimeConfigLoader::new(
            RuntimeEnvelope {
                api_version: API_VERSION,
                kind: "EdgeTest",
            },
            DeclaredPosture {
                posture: Posture::Development,
                source: PostureSource::Flag,
            },
        )
        .parse_str::<serde_json::Value>(
            &format!("apiVersion: {API_VERSION}\nkind: EdgeTest\n"),
            |_| None,
        )
        .expect("a development loader reads the envelope")
        .development
        .expect("a development loader issues the witness")
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
        let options = config
            .options(None, "Address correction", "mcp.principal", "mcp.client")
            .unwrap();
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
        config.resource = test_resource("http://127.0.0.1:8110/mcp");
        config.issuer = test_issuer("http://localhost:8111");
        assert!(config
            .validate(false, &secret_providers(), None)
            .iter()
            .any(|error| { matches!(error, ResourceServerConfigError::InsecureResource) }));

        assert!(config.validate(true, &secret_providers(), None).is_empty());
    }

    #[test]
    fn unsecured_issuer_transport_admits_only_the_loopback_forms() {
        for host in ["127.0.0.2", "[::1]", "LOCALHOST", "[::ffff:127.0.0.1]"] {
            let mut config = resource_server();
            config.resource = test_resource(format!("http://{host}:8110/mcp"));
            config.issuer = test_issuer(format!("http://{host}:8111"));
            assert!(
                config
                    .validate(true, &secret_providers(), Some(&development_witness()))
                    .is_empty(),
                "{host}"
            );
        }
        for host in ["localhost.", "app.localhost", "10.0.0.1"] {
            let mut config = resource_server();
            config.resource = test_resource(format!("http://{host}:8110/mcp"));
            config.issuer = test_issuer(format!("http://{host}:8111"));
            let errors = config.validate(true, &secret_providers(), Some(&development_witness()));

            assert!(
                errors
                    .iter()
                    .any(|error| matches!(error, ResourceServerConfigError::InsecureIssuer)),
                "{host}"
            );
        }
    }

    #[test]
    fn authored_resource_validation_reports_the_mcp_path_and_static_secret() {
        let mut config = resource_server();
        config.resource = test_resource("https://gateway.example.test/other");
        config.jwks_source = Gated::everywhere(JwksSource::Static {
            document_ref: "secret:file/jwks".to_owned(),
        })
        .unwrap();
        let errors = config.validate(false, &secret_providers(), None);
        assert!(errors
            .iter()
            .any(|error| { matches!(error, ResourceServerConfigError::ResourceNotMcpEndpoint) }));
        assert!(errors
            .iter()
            .any(|error| { matches!(error, ResourceServerConfigError::JwksDocumentReference(_)) }));
    }

    /// A resource-server block with every development-only value, decoded
    /// while the posture collector runs.
    fn development_block() -> (ResourceServerConfig, Vec<FoundSetting>) {
        let (decoded, found) = registry_platform_config::collect_development_settings(|| {
            serde_json::from_value::<ResourceServerConfig>(serde_json::json!({
                "resource": "http://127.0.0.1:8110/mcp",
                "issuer": "http://login.example.test",
                "jwksSource": {"type": "test-issuer", "documentRef": "secret:env/JWKS"},
                "allowInsecureHttp": true,
                "algorithms": ["EdDSA"],
                "allowedClients": ["chat-host"],
                "requiredScopes": ["citizen:self"]
            }))
        });
        (decoded.expect("the development block decodes"), found)
    }

    #[test]
    fn an_http_issuer_is_recorded_while_decoding_and_unreadable_without_the_witness() {
        let (config, found) = development_block();
        assert!(found
            .iter()
            .any(|found| found.setting.code == "platform.posture.mcp-http-published-issuer"));
        assert_eq!(
            config.issuer_url(None).unwrap_err().setting.code,
            "platform.posture.mcp-http-published-issuer"
        );
        assert!(config.options(None, "Name", "p", "c").is_err());
    }

    #[test]
    fn development_settings_list_every_member_the_decoder_records() {
        let (config, found) = development_block();
        let listed: Vec<(&str, Option<String>)> = config
            .development_settings()
            .into_iter()
            .map(|found| (found.setting.code, found.pointer))
            .collect();
        assert_eq!(
            listed,
            [
                (
                    "platform.posture.mcp-http-resource",
                    Some("/resourceServer/resource".to_owned())
                ),
                (
                    "platform.posture.mcp-http-published-issuer",
                    Some("/resourceServer/issuer".to_owned())
                ),
                (
                    "platform.posture.test-issuer",
                    Some("/resourceServer/jwksSource".to_owned())
                ),
                (
                    "platform.posture.insecure-issuer-http",
                    Some("/resourceServer/allowInsecureHttp".to_owned())
                ),
            ]
        );
        let mut decoded: Vec<&str> = found.iter().map(|found| found.setting.code).collect();
        let mut codes: Vec<&str> = listed.iter().map(|(code, _)| *code).collect();
        decoded.sort_unstable();
        codes.sort_unstable();
        assert_eq!(codes, decoded);
        assert!(resource_server().development_settings().is_empty());

        let (audit, found) = registry_platform_config::collect_development_settings(|| {
            serde_json::from_value::<AuditConfig>(serde_json::json!({
                "registry-platform-yaml/shared-block/audit-key": {
                    "hashKeyRef": "secret:env/AUDIT",
                    "hashKeyCustody": "development-generated"
                },
                "destination": "stdout"
            }))
        });
        let audit = audit.expect("the audit block decodes");
        assert_eq!(found.len(), 1);
        let listed: Vec<(&str, Option<String>)> = audit
            .development_settings()
            .into_iter()
            .map(|found| (found.setting.code, found.pointer))
            .collect();
        assert_eq!(
            listed,
            [(
                "platform.posture.generated-audit-key",
                Some("/audit/hashKeyCustody".to_owned())
            )]
        );
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

    /// The client assertion audience is the authorization server's issuer
    /// identifier and has no default.
    #[test]
    fn exchange_credentials_without_an_assertion_audience_are_refused() {
        let error = serde_json::from_value::<ExchangeConfig>(serde_json::json!({
            "tokenEndpoint": "https://login.example.test/token",
            "clientId": "gateway-client",
            "privateKeyRef": "secret:env/GATEWAY_PRIVATE_KEY"
        }))
        .expect_err("an exchange without an assertion audience was accepted");
        assert!(error.to_string().contains("`assertionAudience`"), "{error}");
    }
}
