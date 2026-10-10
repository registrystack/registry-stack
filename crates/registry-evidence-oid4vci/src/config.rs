//! Startup-only configuration for the delivery service.
//!
//! Everything here is fixed for the lifetime of the serving process: the
//! published credential issuer identifier, the listener, the Evidence
//! deployment this service requests credentials from, the identity it
//! authenticates to the configured token issuer with, and the bounds of the in-memory store.
//!
//! The document is read whole through the shared runtime reader and validated
//! whole, so a deployment either starts on a coherent configuration or does
//! not start. `evidence-oid4vci check` runs this same validation without
//! opening a socket or reading secret material.

use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
};

use registry_platform_config::{
    ConfigBlockErrorKind, RemovedKey, RuntimeConfigLoader, RuntimeEnvelope, RuntimeFileCheck,
    SecretProvidersConfig, SecretReference, DEFAULT_STAND_IN,
};
use registry_platform_httputil::client::{
    valid_resource_uri, valid_scope_token, MAXIMUM_REQUESTED_SCOPES, MAXIMUM_REQUESTED_SCOPE_BYTES,
    MAXIMUM_SCOPE_PARAMETER_BYTES,
};
use registry_platform_yaml::{
    shape_union, BoundedU32, BoundedU64, Diagnostic, ExternalId, Invalid, Report, Severity,
    UniqueList, Url,
};
use serde::{Deserialize, Deserializer, Serialize};

/// The `apiVersion` of a delivery runtime file.
pub const OID4VCI_RUNTIME_API_VERSION: &str =
    "id.registrystack.org/formats/evidence/oid4vci-runtime/v1alpha1";

/// The `kind` of a delivery runtime file.
pub const OID4VCI_RUNTIME_KIND: &str = "EvidenceOid4vciRuntimeConfig";

/// The `$id` of the generated JSON Schema for a delivery runtime file.
pub const OID4VCI_RUNTIME_SCHEMA_ID: &str =
    "https://id.registrystack.org/schemas/evidence/oid4vci-runtime/oid4vci-runtime.v1alpha1.schema.json";

/// The file name of the generated JSON Schema for a delivery runtime file.
pub const RUNTIME_SCHEMA_FILE: &str = "oid4vci-runtime.schema.json";

/// Keys earlier releases read, each naming what replaces it.
const REMOVED_KEYS: &[RemovedKey] = &[
    RemovedKey {
        path: "version",
        replacement: "Delete version; apiVersion and kind replace it.",
    },
    RemovedKey {
        path: "mint",
        replacement: "Write tokenClient with the same members.",
    },
    RemovedKey {
        path: "listener.address",
        replacement: "Write listener.bind as host:port, such as 127.0.0.1:8090.",
    },
    RemovedKey {
        path: "listener.port",
        replacement: "Write listener.bind as host:port, such as 127.0.0.1:8090.",
    },
    RemovedKey {
        path: "metricsListener.address",
        replacement: "Write metricsListener.bind as host:port, such as 127.0.0.1:9090.",
    },
    RemovedKey {
        path: "metricsListener.port",
        replacement: "Write metricsListener.bind as host:port, such as 127.0.0.1:9090.",
    },
    RemovedKey {
        path: "tokenClient.privateKeyFile",
        replacement: "Write tokenClient.privateKeyRef as secret:file/<name> under secretProviders.file.root, or secret:env/<NAME> with secretProviders.environment enabled.",
    },
];

/// The shared runtime reader for a delivery runtime file.
#[must_use]
pub const fn loader() -> RuntimeConfigLoader {
    RuntimeConfigLoader::new(RuntimeEnvelope {
        api_version: OID4VCI_RUNTIME_API_VERSION,
        kind: OID4VCI_RUNTIME_KIND,
    })
    .removed_keys(REMOVED_KEYS)
}

/// A runtime file the service refused, with every diagnostic that decided it.
#[derive(Debug)]
pub struct ConfigError {
    diagnostics: Vec<Diagnostic>,
    unavailable: bool,
}

impl ConfigError {
    /// Every finding, each naming the file as the path was given and each
    /// positioned at the member it concerns.
    #[must_use]
    pub fn diagnostics(&self) -> &[Diagnostic] {
        &self.diagnostics
    }

    /// The file could not be read at all, as opposed to read and refused.
    #[must_use]
    pub fn is_unavailable(&self) -> bool {
        self.unavailable
    }

    /// The findings as the report a check prints.
    #[must_use]
    pub fn report(&self) -> Report {
        Report::new(self.diagnostics.clone())
    }
}

impl fmt::Display for ConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let deciding = self
            .diagnostics
            .iter()
            .find(|diagnostic| diagnostic.severity == Severity::Error);
        match deciding {
            Some(diagnostic) if !self.unavailable => write!(
                formatter,
                "{} at {}: {}",
                diagnostic.code,
                if diagnostic.path.is_empty() {
                    "the document root"
                } else {
                    diagnostic.path.as_str()
                },
                diagnostic.message
            ),
            _ => formatter.write_str("the configuration file is unavailable"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// What an offline check of one runtime file found (CFG-CHECK-1).
#[derive(Debug, Default)]
pub struct RuntimeCheck {
    /// Every finding, each naming the file as the path was given and each
    /// positioned at the member it concerns.
    pub diagnostics: Vec<Diagnostic>,
    /// The file could not be read at all, as opposed to read and refused.
    pub unavailable: bool,
}

/// Check the runtime file at the absolute `path` as `evidence-oid4vci serve`
/// reads it, with no network, socket, or secret material, and report every
/// rule it breaks.
///
/// With `substitute` set, `${NAME}` expressions are filled from the process
/// environment and every value is checked. Without it, each expression is
/// checked by syntax and position only, and a rule that reads its value is
/// left out.
#[must_use]
pub fn check_file(path: &Path, substitute: bool) -> RuntimeCheck {
    let check = loader().check_offline::<DeliveryDocument>(path, substitute, stand_in_for);
    let mut diagnostics = check.diagnostics.clone();
    if let Some(loaded) = &check.loaded {
        diagnostics.extend(
            loaded
                .config
                .findings()
                .iter()
                .filter(|finding| !reads_deferred_value(&check, finding))
                .map(|finding| positioned(&check, finding)),
        );
    }
    in_file_order(&mut diagnostics);
    RuntimeCheck {
        diagnostics,
        unavailable: check.unavailable,
    }
}

/// The transport validation boundary selected for this process.
///
/// A two-axis transport vocabulary with deliberately no third assurance
/// concept: a delivery front end that graded itself on its own scale would
/// invent a security property nothing else in the stack recognizes.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum ValidationMode {
    /// Every published and called origin uses https.
    #[default]
    Strict,
    /// One supervised process group on loopback: the credential issuer is a
    /// canonical `http://127.0.0.1:<port>` origin the listener binds exactly,
    /// and every called origin is https or a 127.0.0.1 HTTP origin.
    SupervisedLocalDevelopment,
}

/// The signature algorithms an offer token may be signed with.
///
/// The same closed vocabulary Evidence accepts on its own resource-server
/// profile. Mixing families is refused when the configuration loads rather than
/// when the first token arrives.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
pub enum AccessTokenAlgorithm {
    EdDSA,
    ES256,
    RS256,
}

/// The listener a wallet and an adopter reach.
#[derive(Debug, Eq, PartialEq)]
pub struct ListenerConfig {
    pub bind: SocketAddr,
    pub maximum_request_bytes: u32,
    pub request_timeout_milliseconds: u64,
}

/// Optional operator-only metrics listener.
///
/// Absent means no metrics endpoint exists. When present it is a distinct
/// private binding that serves no wallet or adopter route.
#[derive(Debug, Eq, PartialEq)]
pub struct MetricsListenerConfig {
    pub bind: SocketAddr,
}

/// The Evidence deployment this service requests credentials from.
///
/// A base URL and nothing else. Which credentials may be requested is the
/// Evidence bundle's decision and is read from Evidence, never restated here.
#[derive(Debug, Eq, PartialEq)]
pub struct EvidenceConfig {
    pub base_url: String,
}

/// The identity this service authenticates to its token issuer with.
///
/// This is the client half of the process. It signs a private key JWT client
/// assertion with its own key and receives an access token Evidence accepts.
/// The resource-server half, which verifies tokens presented to the
/// adopter-facing offer endpoint, is a separate identity and a separate code
/// path.
#[derive(Debug, Eq, PartialEq)]
pub struct TokenClientConfig {
    pub token_endpoint: String,
    pub client_id: String,
    /// The caller's own private JWK, as a secret reference. Resolved when the
    /// outbound client is built, never logged and never rendered.
    pub private_key_ref: SecretReference,
    /// The value the endpoint expects as the client assertion `aud`. Defaults
    /// to the token endpoint, which is the usual registration.
    pub client_assertion_audience: Option<String>,
    /// The fixed RFC 8707 resource identifier of the Evidence API.
    pub resource: Option<String>,
    /// The exact scopes requested from the issuer for Evidence access.
    pub scopes: Option<Vec<String>>,
}

impl TokenClientConfig {
    #[must_use]
    pub fn client_assertion_audience(&self) -> &str {
        self.client_assertion_audience
            .as_deref()
            .unwrap_or(&self.token_endpoint)
    }
}

/// Which values a gate admits: any value, or exactly the listed ones.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Restriction {
    /// The file wrote `unrestricted`: the gate admits any value.
    Unrestricted,
    /// The file listed the admitted values; the list is never empty.
    Listed(Vec<String>),
}

impl Restriction {
    /// The listed values, empty when the gate is unrestricted.
    #[must_use]
    pub fn items(&self) -> &[String] {
        match self {
            Self::Unrestricted => &[],
            Self::Listed(items) => items,
        }
    }
}

/// The authorization boundary of the adopter-facing offer endpoint.
///
/// This is the resource-server half of the process, and it is deliberately a
/// separate document from [`TokenClientConfig`]: the identity this service
/// authenticates to the token issuer with has nothing to do with the identities it accepts
/// tokens from, and nothing here is derived from that one.
#[derive(Debug, Eq, PartialEq)]
pub struct OfferAuthorizationConfig {
    /// Contextual claim names used by this offer-token issuer. Keep these
    /// aligned with Evidence when both verify tokens from the same deployment.
    pub claims: registry_platform_oidc::ClaimNames,
    /// The authorization server that issues offer tokens, compared exactly
    /// against a token's `iss`.
    pub issuer: String,
    pub jwks_uri: String,
    /// The audiences this service answers to. A token issued for anything else
    /// is refused, so an adopter's token for another resource server cannot be
    /// replayed here.
    pub audiences: Vec<String>,
    pub algorithms: Vec<AccessTokenAlgorithm>,
    /// Client identifiers permitted to create offers. Unrestricted accepts any
    /// client the issuer vouched for, which is the usual single-adopter
    /// deployment.
    pub authorized_clients: Restriction,
    /// Scopes every offer token must carry, checked against the verified
    /// token's scope set. Unrestricted applies no scope gate; generated
    /// configurations state `oid4vci:offer`.
    pub required_scopes: Restriction,
    pub maximum_token_lifetime_seconds: u64,
}

/// The bounds of the in-memory store.
///
/// Every one of these is a memory bound or a window, and both are load-bearing:
/// the store fails closed on saturation rather than evicting a live entry, so
/// the capacity is what an operator sizes against the offers a deployment
/// really creates, and the lifetimes are what keeps that capacity from filling
/// with state nobody is going to claim. A redeemed offer's failure ledger stays
/// for the full offer lifetime, so sustained offer creation is bounded to about
/// `maximum_offers / offer_lifetime_seconds` per second, not merely the number
/// of offers waiting to be redeemed at one instant.
#[derive(Debug, Eq, PartialEq)]
pub struct StoreConfig {
    pub maximum_offers: usize,
    pub offer_lifetime_seconds: u64,
    pub access_token_lifetime_seconds: u64,
    pub nonce_lifetime_seconds: u64,
    /// How many wrong transaction codes an offer survives.
    ///
    /// The counter lives as long as the offer does, so exhausting it locks the
    /// offer out for the rest of its life rather than for the rest of one
    /// request.
    pub maximum_transaction_code_attempts: u32,
}

impl Default for StoreConfig {
    fn default() -> Self {
        StoreDocument::default().into_config()
    }
}

/// The whole startup configuration.
///
/// There is deliberately no member for the credential configurations this
/// service publishes. Every entry is derived from the Evidence bundle, so
/// published metadata cannot describe a credential Evidence would refuse to
/// issue. The reader refuses an unknown key, so an attempt to write one by
/// hand is a load failure rather than a silently ignored key, and no type in
/// this crate deserializes one.
#[derive(Debug, Eq, PartialEq)]
pub struct DeliveryConfig {
    pub validation_mode: ValidationMode,
    /// The `credential_issuer` identifier this service publishes, and the value
    /// a wallet proof must carry as its `aud`. Held without a trailing slash,
    /// so what is published and what is compared are the same bytes.
    pub credential_issuer: String,
    pub listener: ListenerConfig,
    pub metrics_listener: Option<MetricsListenerConfig>,
    pub secret_providers: SecretProvidersConfig,
    pub evidence: EvidenceConfig,
    pub token_client: TokenClientConfig,
    pub offers: OfferAuthorizationConfig,
    pub store: StoreConfig,
}

impl DeliveryConfig {
    /// Load and validate the runtime file at the absolute `path`.
    pub fn load(path: &Path) -> Result<Self, ConfigError> {
        Self::load_reporting(path).map(|(config, _)| config)
    }

    /// Load and validate the runtime file at the absolute `path`, returning
    /// the warnings it carries beside the configuration.
    pub fn load_reporting(path: &Path) -> Result<(Self, Vec<Diagnostic>), ConfigError> {
        let mut check = loader().check_offline::<DeliveryDocument>(path, true, stand_in_for);
        let Some(loaded) = check.loaded.take() else {
            return Err(ConfigError {
                diagnostics: std::mem::take(&mut check.diagnostics),
                unavailable: check.unavailable,
            });
        };
        let mut diagnostics: Vec<Diagnostic> = loaded
            .config
            .findings()
            .iter()
            .map(|finding| positioned(&check, finding))
            .collect();
        in_file_order(&mut diagnostics);
        if diagnostics
            .iter()
            .any(|diagnostic| diagnostic.severity == Severity::Error)
        {
            return Err(ConfigError {
                diagnostics,
                unavailable: false,
            });
        }
        Ok((loaded.config.into_config(), diagnostics))
    }

    /// The first rule the listener bindings break, as a sentence.
    ///
    /// The service checks this again immediately before binding, so a
    /// configuration assembled in code is held to the rule the file is.
    pub(crate) fn binding_fault(&self) -> Option<&'static str> {
        binding_findings(
            self.listener.bind,
            self.metrics_listener.as_ref().map(|metrics| metrics.bind),
        )
        .first()
        .map(|finding| finding.message)
    }
}

// The document the reader decodes. Each type below is the authored shape of
// one mapping; `into_config` turns a document that passed every rule into the
// configuration the service runs on.

fn bounded_u32<const MIN: u32, const MAX: u32>(value: u32) -> BoundedU32<MIN, MAX> {
    BoundedU32::new(value).expect("a declared default is within its bounds")
}

fn bounded_u64<const MIN: u64, const MAX: u64>(value: u64) -> BoundedU64<MIN, MAX> {
    BoundedU64::new(value).expect("a declared default is within its bounds")
}

fn default_maximum_request_bytes() -> BoundedU32<1_024, 1_048_576> {
    bounded_u32(16 * 1024)
}

fn default_request_timeout_milliseconds() -> BoundedU64<1, 30_000> {
    bounded_u64(5_000)
}

fn default_offer_token_algorithms() -> UniqueList<AccessTokenAlgorithm> {
    UniqueList::new(vec![AccessTokenAlgorithm::EdDSA]).expect("one algorithm is distinct")
}

fn default_maximum_token_lifetime_seconds() -> BoundedU64<60, 3_600> {
    bounded_u64(900)
}

fn default_maximum_offers() -> BoundedU32<256, 1_048_576> {
    bounded_u32(4_096)
}

fn default_offer_lifetime_seconds() -> BoundedU64<60, 900> {
    bounded_u64(300)
}

fn default_access_token_lifetime_seconds() -> BoundedU64<60, 900> {
    bounded_u64(300)
}

fn default_nonce_lifetime_seconds() -> BoundedU64<30, 900> {
    bounded_u64(120)
}

fn default_maximum_transaction_code_attempts() -> BoundedU32<1, 10> {
    bounded_u32(3)
}

/// The wallet-delivery runtime file: one deployment of the OID4VCI delivery
/// front end for Evidence credentials.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeliveryDocument {
    /// The format version of this file.
    pub api_version: String,
    /// The document kind.
    pub kind: String,
    /// The transport validation boundary. Absent means strict.
    #[serde(default)]
    pub validation_mode: ValidationMode,
    /// The `credential_issuer` identifier this service publishes, and the
    /// value a wallet proof must carry as its `aud`: a bare origin with no
    /// path, query, or fragment. https in strict mode. A trailing slash is
    /// removed, so what is published and what is compared are the same bytes.
    pub credential_issuer: Url,
    /// The listener a wallet and an adopter reach.
    pub listener: ListenerDocument,
    /// The optional operator-only metrics listener: a loopback or private
    /// address the delivery listener does not use. Absent means no metrics
    /// endpoint exists.
    #[serde(default)]
    pub metrics_listener: Option<registry_platform_config::ListenerConfig>,
    /// The secret providers `tokenClient.privateKeyRef` may name.
    pub secret_providers: SecretProvidersConfig,
    /// The Evidence deployment this service requests credentials from.
    pub evidence: EvidenceDocument,
    /// The identity this service authenticates to its token issuer with.
    pub token_client: TokenClientDocument,
    /// The authorization boundary of the adopter-facing offer endpoint.
    pub offers: OffersDocument,
    /// The bounds of the in-memory store.
    #[serde(default)]
    pub store: StoreDocument,
}

/// The listener a wallet and an adopter reach.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListenerDocument {
    /// `bind`: the socket address the listener binds, with a non-zero port
    /// because the published origin names it.
    #[serde(rename(deserialize = "registry-platform-yaml/shared-block/listener"))]
    #[cfg_attr(feature = "schema", schemars(flatten))]
    pub address: registry_platform_config::ListenerConfig,
    /// The largest request body accepted, in bytes. A limit no wallet request
    /// can survive leaves the service reporting itself ready while every
    /// request fails.
    #[serde(default = "default_maximum_request_bytes")]
    pub maximum_request_bytes: BoundedU32<1_024, 1_048_576>,
    /// How long one request may take, in milliseconds.
    #[serde(default = "default_request_timeout_milliseconds")]
    pub request_timeout_milliseconds: BoundedU64<1, 30_000>,
}

/// The Evidence deployment this service requests credentials from.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EvidenceDocument {
    /// The Evidence base URL, with no query or fragment. https in strict mode.
    pub base_url: Url,
}

/// The identity this service authenticates to its token issuer with.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TokenClientDocument {
    /// The token endpoint, with no query or fragment. https in strict mode.
    pub token_endpoint: Url,
    /// The client identifier registered with the token issuer, at most 128
    /// bytes.
    pub client_id: ExternalId,
    /// The client's own private JWK, as `secret:file/<name>` under
    /// `secretProviders.file.root` or `secret:env/<NAME>`. Resolved when the
    /// outbound client is built, never logged and never rendered.
    pub private_key_ref: SecretReference,
    /// The value the endpoint expects as the client assertion `aud`. Absent
    /// means the token endpoint, which is the usual registration.
    #[serde(default)]
    pub client_assertion_audience: Option<Url>,
    /// The fixed RFC 8707 resource identifier of the Evidence API: an
    /// absolute URI with no fragment or user information.
    #[serde(default)]
    pub resource: Option<ExternalId>,
    /// The exact scopes requested from the issuer for Evidence access: 1 to
    /// 32 distinct RFC 6749 scope tokens. Absent requests no scope.
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 32)))]
    pub scopes: Option<UniqueList<ExternalId>>,
}

/// The contextual claim names an offer-token issuer uses. Each is distinct,
/// and none is a registered or authentication claim.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(default, rename_all = "camelCase", deny_unknown_fields)]
pub struct ClaimNamesDocument {
    pub actor_kind: ExternalId,
    pub purpose: ExternalId,
    pub grant_id: ExternalId,
    pub grant_source_issuer: ExternalId,
    pub grant_client: ExternalId,
    pub grant_resource: ExternalId,
    pub grant_exp: ExternalId,
    pub grant_bounds: ExternalId,
    pub approver: ExternalId,
}

impl Default for ClaimNamesDocument {
    fn default() -> Self {
        let names = registry_platform_oidc::ClaimNames::default();
        let name = |text: String| ExternalId::new(text).expect("a default claim name is valid");
        Self {
            actor_kind: name(names.actor_kind),
            purpose: name(names.purpose),
            grant_id: name(names.grant_id),
            grant_source_issuer: name(names.grant_source_issuer),
            grant_client: name(names.grant_client),
            grant_resource: name(names.grant_resource),
            grant_exp: name(names.grant_exp),
            grant_bounds: name(names.grant_bounds),
            approver: name(names.approver),
        }
    }
}

impl ClaimNamesDocument {
    fn to_claim_names(&self) -> registry_platform_oidc::ClaimNames {
        registry_platform_oidc::ClaimNames {
            actor_kind: self.actor_kind.to_string(),
            purpose: self.purpose.to_string(),
            grant_id: self.grant_id.to_string(),
            grant_source_issuer: self.grant_source_issuer.to_string(),
            grant_client: self.grant_client.to_string(),
            grant_resource: self.grant_resource.to_string(),
            grant_exp: self.grant_exp.to_string(),
            grant_bounds: self.grant_bounds.to_string(),
            approver: self.approver.to_string(),
        }
    }
}

/// The keyword `unrestricted`.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct UnrestrictedKeyword;

impl<'de> Deserialize<'de> for UnrestrictedKeyword {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        if text == "unrestricted" {
            Ok(Self)
        } else {
            Err(Invalid::expected(
                "unrestricted, or a list of at least one value",
                "Write unrestricted to admit any value, or list the admitted values.",
            )
            .into_error())
        }
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for UnrestrictedKeyword {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        "UnrestrictedKeyword".into()
    }

    fn json_schema(_generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        schemars::json_schema!({
            "description": "Admit any value.",
            "type": "string",
            "const": "unrestricted",
        })
    }
}

/// A nonempty list of distinct identifiers.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ListedIdentifiers(UniqueList<ExternalId>);

impl<'de> Deserialize<'de> for ListedIdentifiers {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let items = UniqueList::<ExternalId>::deserialize(deserializer)?;
        if items.is_empty() {
            return Err(Invalid::expected(
                "unrestricted, or a list of at least one value",
                "Write unrestricted to admit any value, or list the admitted values.",
            )
            .into_error());
        }
        Ok(Self(items))
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for ListedIdentifiers {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        "ListedIdentifiers".into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        let mut schema = generator.subschema_for::<UniqueList<ExternalId>>();
        schema.insert(
            "description".to_owned(),
            "Admit exactly these values.".into(),
        );
        schema.insert("minItems".to_owned(), 1.into());
        schema
    }
}

/// Which values a gate admits: the keyword `unrestricted`, or a nonempty list
/// of the admitted values. An empty list is refused, because it reads as both
/// "nothing" and "anything".
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(untagged))]
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum IdentifierRestriction {
    Unrestricted(UnrestrictedKeyword),
    Listed(ListedIdentifiers),
}

shape_union!(IdentifierRestriction { scalar => Unrestricted, list => Listed });

impl IdentifierRestriction {
    fn items(&self) -> &[ExternalId] {
        match self {
            Self::Unrestricted(_) => &[],
            Self::Listed(items) => &items.0,
        }
    }

    fn into_restriction(self) -> Restriction {
        match self {
            Self::Unrestricted(_) => Restriction::Unrestricted,
            Self::Listed(items) => Restriction::Listed(
                items
                    .0
                    .into_vec()
                    .into_iter()
                    .map(ExternalId::into_string)
                    .collect(),
            ),
        }
    }
}

/// The authorization boundary of the adopter-facing offer endpoint.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OffersDocument {
    /// Contextual claim names used by this offer-token issuer. Keep these
    /// aligned with Evidence when both verify tokens from the same deployment.
    #[serde(default)]
    pub claims: ClaimNamesDocument,
    /// The authorization server that issues offer tokens, compared exactly
    /// against a token's `iss`. https in strict mode.
    pub issuer: Url,
    /// The offer-token issuer's key set. https in strict mode.
    pub jwks_uri: Url,
    /// The audiences this service answers to, each at most 256 bytes. A token
    /// issued for anything else is refused.
    #[cfg_attr(feature = "schema", schemars(length(min = 1)))]
    pub audiences: UniqueList<ExternalId>,
    /// The one signature algorithm an offer token may be signed with.
    #[serde(default = "default_offer_token_algorithms")]
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 1)))]
    pub algorithms: UniqueList<AccessTokenAlgorithm>,
    /// Client identifiers permitted to create offers, each at most 128 bytes,
    /// or `unrestricted` for any client the issuer vouched for.
    pub authorized_clients: IdentifierRestriction,
    /// Scopes every offer token must carry, each an RFC 6749 scope token of at
    /// most 256 bytes, or `unrestricted` for no scope gate. Generated
    /// configurations state `oid4vci:offer`.
    pub required_scopes: IdentifierRestriction,
    /// The longest lifetime an offer token may carry, in seconds.
    #[serde(default = "default_maximum_token_lifetime_seconds")]
    pub maximum_token_lifetime_seconds: BoundedU64<60, 3_600>,
}

/// The bounds of the in-memory store.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct StoreDocument {
    /// How many offers the store holds. A store too small to hold a
    /// deployment's live offers refuses new ones rather than forgetting old
    /// ones.
    #[serde(default = "default_maximum_offers")]
    pub maximum_offers: BoundedU32<256, 1_048_576>,
    /// How long an offer lives, in seconds. Minutes, in both directions:
    /// shorter than a person can scan a code and read a message, and the flow
    /// cannot complete; longer, and a stolen offer stays useful.
    #[serde(default = "default_offer_lifetime_seconds")]
    pub offer_lifetime_seconds: BoundedU64<60, 900>,
    /// How long an access token lives, in seconds.
    #[serde(default = "default_access_token_lifetime_seconds")]
    pub access_token_lifetime_seconds: BoundedU64<60, 900>,
    /// How long a nonce lives, in seconds; at most the access token lifetime.
    #[serde(default = "default_nonce_lifetime_seconds")]
    pub nonce_lifetime_seconds: BoundedU64<30, 900>,
    /// How many wrong transaction codes an offer survives.
    #[serde(default = "default_maximum_transaction_code_attempts")]
    pub maximum_transaction_code_attempts: BoundedU32<1, 10>,
}

impl Default for StoreDocument {
    fn default() -> Self {
        Self {
            maximum_offers: default_maximum_offers(),
            offer_lifetime_seconds: default_offer_lifetime_seconds(),
            access_token_lifetime_seconds: default_access_token_lifetime_seconds(),
            nonce_lifetime_seconds: default_nonce_lifetime_seconds(),
            maximum_transaction_code_attempts: default_maximum_transaction_code_attempts(),
        }
    }
}

impl StoreDocument {
    fn into_config(self) -> StoreConfig {
        StoreConfig {
            maximum_offers: self.maximum_offers.get() as usize,
            offer_lifetime_seconds: self.offer_lifetime_seconds.get(),
            access_token_lifetime_seconds: self.access_token_lifetime_seconds.get(),
            nonce_lifetime_seconds: self.nonce_lifetime_seconds.get(),
            maximum_transaction_code_attempts: self.maximum_transaction_code_attempts.get(),
        }
    }
}

/// One rule a decoded document breaks, at the member it concerns.
#[derive(Debug)]
struct Finding {
    severity: Severity,
    code: &'static str,
    pointer: String,
    message: &'static str,
    action: &'static str,
    /// Members besides `pointer` whose value decided the finding.
    reads: &'static [&'static str],
}

impl Finding {
    fn error(
        code: &'static str,
        pointer: impl Into<String>,
        message: &'static str,
        action: &'static str,
    ) -> Self {
        Self {
            severity: Severity::Error,
            code,
            pointer: pointer.into(),
            message,
            action,
            reads: &[],
        }
    }

    fn warning(
        code: &'static str,
        pointer: impl Into<String>,
        message: &'static str,
        action: &'static str,
    ) -> Self {
        Self {
            severity: Severity::Warning,
            ..Self::error(code, pointer, message, action)
        }
    }

    fn reading(mut self, reads: &'static [&'static str]) -> Self {
        self.reads = reads;
        self
    }
}

/// Every transport finding depends on the selected validation mode.
const TRANSPORT_READS: &[&str] = &["/validationMode"];

const HTTPS_REQUIRED: &str = "evidence.oid4vci.https-required";
const URL_QUERY_OR_FRAGMENT: &str = "evidence.oid4vci.url-query-or-fragment";

impl DeliveryDocument {
    /// Every rule a decoded document breaks beyond its shape.
    fn findings(&self) -> Vec<Finding> {
        let mut findings = Vec::new();
        self.transport_findings(&mut findings);
        findings.extend(binding_findings(
            self.listener.address.bind.socket_addr(),
            self.metrics_listener
                .map(|metrics| metrics.bind.socket_addr()),
        ));
        self.secret_findings(&mut findings);
        self.token_client.findings(&mut findings);
        self.offers.findings(&mut findings);
        if self.store.nonce_lifetime_seconds.get() > self.store.access_token_lifetime_seconds.get()
        {
            // A nonce that remains valid after the access token window can
            // only advertise a retry window the credential endpoint will not
            // honor.
            findings.push(
                Finding::error(
                    "evidence.oid4vci.nonce-lifetime",
                    "/store/nonceLifetimeSeconds",
                    "the nonce lifetime must not exceed the access token lifetime",
                    "Lower store.nonceLifetimeSeconds to at most store.accessTokenLifetimeSeconds.",
                )
                .reading(&["/store/accessTokenLifetimeSeconds"]),
            );
        }
        findings
    }

    /// The origins this service calls, each with the member that states it.
    fn called_origins(&self) -> Vec<(&'static str, &Url)> {
        let mut origins = vec![
            ("/evidence/baseUrl", &self.evidence.base_url),
            (
                "/tokenClient/tokenEndpoint",
                &self.token_client.token_endpoint,
            ),
        ];
        if let Some(audience) = &self.token_client.client_assertion_audience {
            origins.push(("/tokenClient/clientAssertionAudience", audience));
        }
        origins.push(("/offers/issuer", &self.offers.issuer));
        origins.push(("/offers/jwksUri", &self.offers.jwks_uri));
        origins
    }

    fn transport_findings(&self, findings: &mut Vec<Finding>) {
        let issuer = normalized_credential_issuer(self.credential_issuer.as_str());
        match self.validation_mode {
            ValidationMode::Strict => {
                credential_issuer_findings(issuer, findings);
                for (pointer, origin) in self.called_origins() {
                    https_origin_findings(pointer, origin, findings);
                }
            }
            ValidationMode::SupervisedLocalDevelopment => {
                self.supervised_local_development_findings(issuer, findings);
            }
        }
    }

    /// Admit one supervised process group on loopback, or nothing.
    ///
    /// The credential issuer is published to wallets and compared byte for byte
    /// by a wallet proof's `aud`, so a supervised deployment has to serve
    /// exactly the origin it publishes. Every other origin this mode reaches is
    /// loopback too: a supervised group that called a real Evidence or token issuer
    /// deployment over plain HTTP would be a production deployment wearing a
    /// development label.
    fn supervised_local_development_findings(&self, issuer: &str, findings: &mut Vec<Finding>) {
        if self.credential_issuer.is_https() {
            credential_issuer_findings(issuer, findings);
        } else {
            match canonical_supervised_local_port(issuer) {
                None => findings.push(
                    Finding::error(
                        "evidence.oid4vci.supervised-issuer",
                        "/credentialIssuer",
                        "a supervised local development credential issuer must be https or a canonical 127.0.0.1 HTTP origin with an explicit non-zero port",
                        "Write the credential issuer as http://127.0.0.1:<port>, with the port the listener binds.",
                    )
                    .reading(TRANSPORT_READS),
                ),
                Some(port) => {
                    if self.listener.address.bind.socket_addr()
                        != SocketAddr::from((Ipv4Addr::LOCALHOST, port))
                    {
                        findings.push(
                            Finding::error(
                                "evidence.oid4vci.supervised-listener",
                                "/listener/bind",
                                "the supervised local development listener must exactly match its canonical credential issuer origin",
                                "Bind the listener to 127.0.0.1 on the port the credential issuer names.",
                            )
                            .reading(&["/credentialIssuer", "/validationMode"]),
                        );
                    }
                }
            }
        }
        for (pointer, origin) in self.called_origins() {
            if origin.is_https() {
                https_origin_findings(pointer, origin, findings);
            } else if !is_supervised_local_endpoint(origin) {
                findings.push(
                    Finding::error(
                        "evidence.oid4vci.supervised-endpoint",
                        pointer,
                        "a supervised local development endpoint must be https or a 127.0.0.1 HTTP origin with an explicit port and no query or fragment",
                        "Write the endpoint as http://127.0.0.1:<port> followed by an optional path, or as an https URL.",
                    )
                    .reading(TRANSPORT_READS),
                );
            }
        }
    }

    fn secret_findings(&self, findings: &mut Vec<Finding>) {
        if let Err(error) = self.secret_providers.check() {
            findings.push(match error.kind() {
                ConfigBlockErrorKind::RelativePath => Finding::error(
                    "evidence.oid4vci.secret-file-root",
                    "/secretProviders/file/root",
                    "the file secret provider root must be an absolute path",
                    "Write secretProviders.file.root as an absolute directory path.",
                ),
                _ => Finding::error(
                    "evidence.oid4vci.secret-providers",
                    "/secretProviders",
                    "secretProviders must enable the file provider, the environment provider, or both",
                    "Declare secretProviders.file with an absolute root, or secretProviders.environment as {}.",
                ),
            });
            return;
        }
        if self
            .secret_providers
            .check_reference(
                "tokenClient.privateKeyRef",
                self.token_client.private_key_ref.as_str(),
            )
            .is_err()
        {
            findings.push(
                Finding::error(
                    "evidence.oid4vci.secret-provider-disabled",
                    "/tokenClient/privateKeyRef",
                    "the client key reference names a secret provider this file does not enable",
                    "Declare the provider the reference names under secretProviders, or reference the key through an enabled provider.",
                )
                .reading(&["/secretProviders"]),
            );
        }
    }

    fn into_config(self) -> DeliveryConfig {
        let credential_issuer =
            normalized_credential_issuer(self.credential_issuer.as_str()).to_owned();
        DeliveryConfig {
            validation_mode: self.validation_mode,
            credential_issuer,
            listener: ListenerConfig {
                bind: self.listener.address.bind.socket_addr(),
                maximum_request_bytes: self.listener.maximum_request_bytes.get(),
                request_timeout_milliseconds: self.listener.request_timeout_milliseconds.get(),
            },
            metrics_listener: self.metrics_listener.map(|metrics| MetricsListenerConfig {
                bind: metrics.bind.socket_addr(),
            }),
            secret_providers: self.secret_providers,
            evidence: EvidenceConfig {
                base_url: self.evidence.base_url.into_string(),
            },
            token_client: TokenClientConfig {
                token_endpoint: self.token_client.token_endpoint.into_string(),
                client_id: self.token_client.client_id.into_string(),
                private_key_ref: self.token_client.private_key_ref,
                client_assertion_audience: self
                    .token_client
                    .client_assertion_audience
                    .map(Url::into_string),
                resource: self.token_client.resource.map(ExternalId::into_string),
                scopes: self.token_client.scopes.map(|scopes| {
                    scopes
                        .into_vec()
                        .into_iter()
                        .map(ExternalId::into_string)
                        .collect()
                }),
            },
            offers: OfferAuthorizationConfig {
                claims: self.offers.claims.to_claim_names(),
                issuer: self.offers.issuer.into_string(),
                jwks_uri: self.offers.jwks_uri.into_string(),
                audiences: self
                    .offers
                    .audiences
                    .into_vec()
                    .into_iter()
                    .map(ExternalId::into_string)
                    .collect(),
                algorithms: self.offers.algorithms.into_vec(),
                authorized_clients: self.offers.authorized_clients.into_restriction(),
                required_scopes: self.offers.required_scopes.into_restriction(),
                maximum_token_lifetime_seconds: self.offers.maximum_token_lifetime_seconds.get(),
            },
            store: self.store.into_config(),
        }
    }
}

impl TokenClientDocument {
    fn findings(&self, findings: &mut Vec<Finding>) {
        if self.client_id.trim().is_empty() || self.client_id.len() > 128 {
            findings.push(Finding::error(
                "evidence.oid4vci.client-id",
                "/tokenClient/clientId",
                "the token client identifier must be 1 to 128 bytes and not blank",
                "Write the client identifier the token issuer registered for this service.",
            ));
        }
        if let Some(resource) = &self.resource {
            if resource.len() > 2048 || !valid_resource_uri(resource) {
                findings.push(Finding::error(
                    "evidence.oid4vci.token-resource",
                    "/tokenClient/resource",
                    "the token client resource must be an absolute URI without fragment or user information, at most 2048 bytes",
                    "Write the fixed RFC 8707 resource identifier of the Evidence API, such as urn:registry:evidence.",
                ));
            }
        }
        if let Some(scopes) = &self.scopes {
            if scopes.is_empty() || scopes.len() > MAXIMUM_REQUESTED_SCOPES {
                findings.push(Finding::error(
                    "evidence.oid4vci.token-scope-count",
                    "/tokenClient/scopes",
                    "the token client must request 1 to 32 scopes",
                    "List the scopes Evidence requires, or remove tokenClient.scopes to request none.",
                ));
            }
            for (index, scope) in scopes.iter().enumerate() {
                if scope.len() > MAXIMUM_REQUESTED_SCOPE_BYTES || !valid_scope_token(scope) {
                    findings.push(Finding::error(
                        "evidence.oid4vci.token-scope",
                        format!("/tokenClient/scopes/{index}"),
                        "each requested scope must be an RFC 6749 scope token of at most 256 bytes",
                        "Write the scope without spaces, quotes, or backslashes.",
                    ));
                }
            }
            let parameter = scopes.iter().map(ExternalId::as_str).collect::<Vec<_>>();
            if parameter.join(" ").len() > MAXIMUM_SCOPE_PARAMETER_BYTES {
                findings.push(Finding::error(
                    "evidence.oid4vci.token-scope-parameter",
                    "/tokenClient/scopes",
                    "the requested scopes must join to at most 4096 bytes",
                    "Request fewer or shorter scopes.",
                ));
            }
        }
    }
}

impl OffersDocument {
    fn findings(&self, findings: &mut Vec<Finding>) {
        if self.claims.to_claim_names().validate().is_err() {
            findings.push(Finding::error(
                "evidence.oid4vci.claim-names",
                "/offers/claims",
                "the offer contextual claim names must be valid, distinct, and not registered or authentication claims",
                "Give each contextual claim its own name, none of them a registered JWT or authentication claim.",
            ));
        }
        if self.audiences.is_empty() {
            findings.push(Finding::error(
                "evidence.oid4vci.audience-count",
                "/offers/audiences",
                "the offer endpoint must state at least one audience",
                "List the audience the offer-token issuer writes into tokens for this service.",
            ));
        }
        for (index, audience) in self.audiences.iter().enumerate() {
            if audience.trim().is_empty() || audience.len() > 256 {
                findings.push(Finding::error(
                    "evidence.oid4vci.audience",
                    format!("/offers/audiences/{index}"),
                    "every offer audience must be 1 to 256 bytes and not blank",
                    "Write the audience exactly as the offer-token issuer writes it.",
                ));
            }
        }
        // The verifier refuses to be built over a mixed family, and these three
        // are three families, so one algorithm per deployment is the whole
        // range this can express.
        if self.algorithms.len() != 1 {
            findings.push(Finding::error(
                "evidence.oid4vci.algorithm-count",
                "/offers/algorithms",
                "the offer endpoint must accept exactly one signature algorithm",
                "List the one algorithm the offer-token issuer signs with.",
            ));
        }
        for (index, client) in self.authorized_clients.items().iter().enumerate() {
            if client.trim().is_empty() || client.len() > 128 {
                findings.push(Finding::error(
                    "evidence.oid4vci.authorized-client",
                    format!("/offers/authorizedClients/{index}"),
                    "every authorized offer client must be 1 to 128 bytes and not blank",
                    "Write the client identifier exactly as the offer-token issuer writes it.",
                ));
            }
        }
        for (index, scope) in self.required_scopes.items().iter().enumerate() {
            if scope.trim().is_empty() || scope.len() > 256 || !valid_scope_token(scope) {
                findings.push(Finding::error(
                    "evidence.oid4vci.required-scope",
                    format!("/offers/requiredScopes/{index}"),
                    "every required offer scope must be an RFC 6749 scope token of at most 256 bytes",
                    "Write the scope without spaces, quotes, or backslashes, such as oid4vci:offer.",
                ));
            }
        }
        for (list, items) in [
            ("/offers/audiences", &self.audiences[..]),
            ("/offers/authorizedClients", self.authorized_clients.items()),
            ("/offers/requiredScopes", self.required_scopes.items()),
        ] {
            for (index, item) in items.iter().enumerate() {
                if matches!(item.as_str(), "*" | "unrestricted") {
                    findings.push(Finding::warning(
                        "evidence.oid4vci.wildcard-spelled-item",
                        format!("{list}/{index}"),
                        "this item is compared as a literal value and admits nothing else",
                        "Write unrestricted in place of the list to admit any value, or remove the item.",
                    ));
                }
            }
        }
    }
}

/// The published identifier in the single spelling everything reads.
///
/// The metadata, the offer, and the audience a wallet proof is compared
/// against are all this one string, and the comparison is byte for byte. A
/// trailing slash is the one difference a URL parser calls equal and that
/// comparison does not, so it is removed once here rather than at each place
/// the value is read, where a site that forgot would publish an identifier no
/// conforming wallet could address.
fn normalized_credential_issuer(written: &str) -> &str {
    written.trim_end_matches('/')
}

/// Require an `https` URL with no variable parts.
///
/// The credential issuer is compared exactly by every wallet that reads it, and
/// the outbound endpoints are what this service authenticates against, so a
/// query or a fragment in any of them would weaken a comparison. The reader
/// already refuses a URL without a host or with embedded credentials.
fn https_origin_findings(pointer: &'static str, origin: &Url, findings: &mut Vec<Finding>) {
    if !origin.is_https() {
        findings.push(
            Finding::error(
                HTTPS_REQUIRED,
                pointer,
                "this origin must use https in strict validation mode",
                "Write an https URL, or set validationMode: supervised-local-development for a loopback process group.",
            )
            .reading(TRANSPORT_READS),
        );
    }
    let parsed = origin.to_url();
    if parsed.query().is_some() || parsed.fragment().is_some() {
        findings.push(Finding::error(
            URL_QUERY_OR_FRAGMENT,
            pointer,
            "a published or called origin must not carry a query or fragment",
            "Remove the query and fragment from the URL.",
        ));
    }
}

/// Require the credential issuer to be a bare `https` origin, with no path.
///
/// Every published endpoint is built by concatenating this issuer with an
/// absolute route path, and the service only ever registers routes at the
/// root, so an issuer carrying its own path would publish an endpoint the
/// service does not serve.
fn credential_issuer_findings(issuer: &str, findings: &mut Vec<Finding>) {
    const POINTER: &str = "/credentialIssuer";
    let is_https = issuer
        .get(..8)
        .is_some_and(|prefix| prefix.eq_ignore_ascii_case("https://"));
    if !is_https {
        findings.push(
            Finding::error(
                HTTPS_REQUIRED,
                POINTER,
                "this origin must use https in strict validation mode",
                "Write an https URL, or set validationMode: supervised-local-development for a loopback process group.",
            )
            .reading(TRANSPORT_READS),
        );
    }
    let parsed = url::Url::parse(issuer).ok();
    if parsed
        .as_ref()
        .is_some_and(|url| url.query().is_some() || url.fragment().is_some())
    {
        findings.push(Finding::error(
            URL_QUERY_OR_FRAGMENT,
            POINTER,
            "a published or called origin must not carry a query or fragment",
            "Remove the query and fragment from the URL.",
        ));
    }
    if parsed.is_none_or(|url| url.path() != "/") {
        findings.push(Finding::error(
            "evidence.oid4vci.issuer-path",
            POINTER,
            "the credential issuer must be a bare origin with no path",
            "Write the credential issuer as scheme, host, and port only, such as https://wallet.example.org.",
        ));
    }
}

/// Accept a plain loopback HTTP endpoint, with an optional path and nothing
/// else that could vary between what is configured and what is reached.
fn is_supervised_local_endpoint(origin: &Url) -> bool {
    let url = origin.to_url();
    url.scheme() == "http"
        && url.host_str() == Some("127.0.0.1")
        && url.port().is_some()
        && url.query().is_none()
        && url.fragment().is_none()
}

/// Parse the only HTTP origin admitted as a supervised credential issuer.
///
/// Exact reconstruction rejects URL-parser aliases such as a trailing slash,
/// leading-zero port, alternate IPv4 spelling, credentials, query, or fragment.
/// The configured issuer identity is compared exactly, not merely resolved.
fn canonical_supervised_local_port(value: &str) -> Option<u16> {
    let port = value
        .strip_prefix("http://127.0.0.1:")
        .filter(|port| !port.is_empty() && port.bytes().all(|byte| byte.is_ascii_digit()))
        .filter(|port| !port.starts_with('0'))
        .and_then(|port| port.parse::<u16>().ok())
        .filter(|port| *port != 0)?;
    (value == format!("http://127.0.0.1:{port}")).then_some(port)
}

fn normalized_bind_address(address: IpAddr) -> IpAddr {
    match address {
        IpAddr::V6(address) => address
            .to_ipv4_mapped()
            .map_or(IpAddr::V6(address), IpAddr::V4),
        address => address,
    }
}

fn is_private_metrics_address(address: IpAddr) -> bool {
    let is_private = match address {
        IpAddr::V4(address) => {
            address.is_loopback() || address.is_private() || address.is_link_local()
        }
        IpAddr::V6(address) => {
            // `IpAddr` carries no interface scope, so accepting fe80::/10
            // here would admit an unscoped link-local binding.
            address.is_loopback() || address.is_unique_local()
        }
    };
    is_private && !address.is_unspecified() && !address.is_multicast()
}

/// The rules the delivery and metrics listener bindings follow.
///
/// An ephemeral delivery port leaves the service running and reachable by
/// nobody, because the origin it published names a port it is not on. The
/// metrics listener is a distinct private binding.
fn binding_findings(listener: SocketAddr, metrics: Option<SocketAddr>) -> Vec<Finding> {
    let mut findings = Vec::new();
    if listener.port() == 0 {
        findings.push(Finding::error(
            "evidence.oid4vci.listener-port",
            "/listener/bind",
            "the listener port must be non-zero, because the published origin names it",
            "Bind the listener to the port the credential issuer origin names.",
        ));
    }
    let Some(metrics) = metrics else {
        return findings;
    };
    if metrics.port() == 0 {
        findings.push(Finding::error(
            "evidence.oid4vci.metrics-port",
            "/metricsListener/bind",
            "the metrics listener port must be non-zero",
            "Bind the metrics listener to a fixed port the delivery listener does not use.",
        ));
    }
    let address = normalized_bind_address(metrics.ip());
    if !is_private_metrics_address(address) {
        findings.push(Finding::error(
            "evidence.oid4vci.metrics-address",
            "/metricsListener/bind",
            "the metrics listener must bind a loopback or private address",
            "Bind the metrics listener to a loopback, private IPv4, or unique local IPv6 address.",
        ));
    }
    let public_address = normalized_bind_address(listener.ip());
    if metrics.port() == listener.port()
        && (public_address.is_unspecified() || public_address == address)
    {
        findings.push(
            Finding::error(
                "evidence.oid4vci.metrics-shared-binding",
                "/metricsListener/bind",
                "the metrics listener must not share the delivery listener binding",
                "Bind the metrics listener to a port the delivery listener does not use.",
            )
            .reading(&["/listener/bind"]),
        );
    }
    findings
}

/// Order `diagnostics` as the shared reader orders its own: those without a
/// line first, then by line and column, keeping the order in which equal
/// positions were found.
fn in_file_order(diagnostics: &mut [Diagnostic]) {
    diagnostics.sort_by_key(|diagnostic| {
        diagnostic
            .source
            .as_ref()
            .and_then(|source| {
                source
                    .line
                    .map(|line| (1, line, source.column.unwrap_or(0)))
            })
            .unwrap_or((0, 0, 0))
    });
}

/// `finding` at the value of its member, or, for a member that is absent, at
/// the nearest mapping above it that is present.
fn positioned(check: &RuntimeFileCheck<DeliveryDocument>, finding: &Finding) -> Diagnostic {
    let mut diagnostic = check.error_at(
        OID4VCI_RUNTIME_KIND,
        finding.code,
        &finding.pointer,
        finding.message,
        finding.action,
    );
    diagnostic.severity = finding.severity;
    let mut located = finding.pointer.as_str();
    while diagnostic
        .source
        .as_ref()
        .is_some_and(|source| source.line.is_none())
        && !located.is_empty()
    {
        located = &located[..located.rfind('/').unwrap_or(0)];
        diagnostic.source = check
            .error_at(OID4VCI_RUNTIME_KIND, "", located, "", "")
            .source;
    }
    diagnostic
}

/// Whether `finding` reads the value of a member the check left as an
/// expression, so the stand-in, not the operator's value, decided it.
fn reads_deferred_value(check: &RuntimeFileCheck<DeliveryDocument>, finding: &Finding) -> bool {
    check.defers_within(&finding.pointer)
        || finding
            .reads
            .iter()
            .any(|pointer| check.defers_within(pointer))
}

/// A value for an expression the offline check does not substitute, chosen
/// so the member it fills decodes and passes the rules about its value.
fn stand_in_for(pointer: &str) -> &'static str {
    let segments: Vec<&str> = pointer.split('/').skip(1).collect();
    match segments.as_slice() {
        ["credentialIssuer"]
        | ["evidence", "baseUrl"]
        | ["tokenClient", "tokenEndpoint" | "clientAssertionAudience"]
        | ["offers", "issuer" | "jwksUri"] => "https://deferred.invalid",
        ["listener", "bind"] => "127.0.0.1:8090",
        ["metricsListener", "bind"] => "127.0.0.1:9090",
        ["validationMode"] => "strict",
        // The list is a set, so each position takes its own algorithm.
        ["offers", "algorithms", index] => {
            const ALGORITHMS: [&str; 3] = ["EdDSA", "ES256", "RS256"];
            ALGORITHMS[index.parse::<usize>().unwrap_or(0) % ALGORITHMS.len()]
        }
        ["offers", "authorizedClients" | "requiredScopes"] => "unrestricted",
        _ => DEFAULT_STAND_IN,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::{fs, path::PathBuf};

    pub(crate) const VALID: &str = r#"apiVersion: id.registrystack.org/formats/evidence/oid4vci-runtime/v1alpha1
kind: EvidenceOid4vciRuntimeConfig
credentialIssuer: https://wallet.example.org
listener:
  bind: 127.0.0.1:8090
secretProviders:
  file:
    root: /run/secrets/evidence-oid4vci
evidence:
  baseUrl: https://evidence.example.org
tokenClient:
  tokenEndpoint: https://mint.example.org/token
  clientId: evidence-oid4vci
  privateKeyRef: secret:file/delivery-client.jwk.json
offers:
  issuer: https://mint.example.org
  jwksUri: https://mint.example.org/.well-known/jwks.json
  audiences: ["https://wallet.example.org"]
  algorithms: [EdDSA]
  authorizedClients: [adopter-front-end]
  requiredScopes: [oid4vci:offer]
  maximumTokenLifetimeSeconds: 900
store:
  maximumOffers: 4096
  offerLifetimeSeconds: 300
  accessTokenLifetimeSeconds: 300
  nonceLifetimeSeconds: 120
  maximumTransactionCodeAttempts: 3
"#;

    /// The reference deployment, for tests in other modules that need a loaded
    /// configuration rather than a configuration decision.
    pub(crate) fn valid_config() -> DeliveryConfig {
        load_from(VALID).expect("the reference configuration loads")
    }

    /// A directory whose path names no symbolic link, as the reader requires.
    pub(crate) fn canonical_tempdir() -> tempfile::TempDir {
        let base = std::env::temp_dir()
            .canonicalize()
            .expect("the temporary directory resolves");
        tempfile::tempdir_in(base).expect("temporary directory")
    }

    fn write(text: &str) -> (tempfile::TempDir, PathBuf) {
        let root = canonical_tempdir();
        let path = root.path().join("oid4vci.yaml");
        fs::write(&path, text).expect("configuration is written");
        (root, path)
    }

    fn load_from(text: &str) -> Result<DeliveryConfig, ConfigError> {
        let (_root, path) = write(text);
        DeliveryConfig::load(&path)
    }

    fn codes(error: &ConfigError) -> Vec<&str> {
        error
            .diagnostics()
            .iter()
            .map(|diagnostic| diagnostic.code.as_str())
            .collect()
    }

    /// The codes `text` is refused with.
    fn refused(text: &str) -> Vec<String> {
        let error = load_from(text).expect_err("the configuration is refused");
        codes(&error).into_iter().map(str::to_owned).collect()
    }

    fn assert_refused_with(text: &str, code: &str) {
        let refused = refused(text);
        assert!(
            refused.iter().any(|refused| refused == code),
            "expected {code}, got {refused:?}"
        );
    }

    fn check(text: &str, substitute: bool) -> RuntimeCheck {
        let (_root, path) = write(text);
        check_file(&path, substitute)
    }

    #[test]
    fn a_valid_document_loads() {
        let config = load_from(VALID).expect("the configuration loads");
        assert_eq!(config.credential_issuer, "https://wallet.example.org");
        assert_eq!(config.listener.bind, "127.0.0.1:8090".parse().unwrap());
        assert_eq!(config.listener.maximum_request_bytes, 16 * 1024);
        assert_eq!(config.listener.request_timeout_milliseconds, 5_000);
        assert_eq!(config.evidence.base_url, "https://evidence.example.org");
        assert_eq!(config.token_client.client_id, "evidence-oid4vci");
        assert_eq!(
            config.token_client.private_key_ref.as_str(),
            "secret:file/delivery-client.jwk.json"
        );
        assert_eq!(config.store.maximum_transaction_code_attempts, 3);
        assert_eq!(config.validation_mode, ValidationMode::Strict);
        assert!(check(VALID, false).diagnostics.is_empty());
    }

    #[test]
    fn the_store_block_is_optional_and_defaulted() {
        let text = VALID
            .split("store:")
            .next()
            .expect("the document has a store block");
        let config = load_from(text).expect("the configuration loads");
        assert_eq!(config.store, StoreConfig::default());
        assert_eq!(config.store.maximum_offers, 4_096);
        assert_eq!(config.store.offer_lifetime_seconds, 300);
        assert_eq!(config.store.access_token_lifetime_seconds, 300);
        assert_eq!(config.store.nonce_lifetime_seconds, 120);
        assert_eq!(config.store.maximum_transaction_code_attempts, 3);
    }

    #[test]
    fn the_client_assertion_audience_defaults_to_the_token_endpoint() {
        let config = load_from(VALID).expect("the configuration loads");
        assert_eq!(
            config.token_client.client_assertion_audience(),
            "https://mint.example.org/token"
        );

        let text = VALID.replace(
            "clientId: evidence-oid4vci",
            "clientId: evidence-oid4vci\n  clientAssertionAudience: https://mint.example.org/other",
        );
        let config = load_from(&text).expect("the configuration loads");
        assert_eq!(
            config.token_client.client_assertion_audience(),
            "https://mint.example.org/other"
        );
    }

    #[test]
    fn the_token_client_accepts_fixed_evidence_resource_and_scopes() {
        let text = VALID.replace(
            "  clientId: evidence-oid4vci",
            "  clientId: evidence-oid4vci\n  resource: urn:registry:evidence\n  scopes: [evidence:invoke, evidence:discover]",
        );
        let config = load_from(&text).expect("the token client configuration loads");
        assert_eq!(
            config.token_client.resource.as_deref(),
            Some("urn:registry:evidence")
        );
        assert_eq!(
            config.token_client.scopes.as_deref(),
            Some(["evidence:invoke".to_owned(), "evidence:discover".to_owned()].as_slice())
        );
    }

    #[test]
    fn the_token_client_refuses_unsafe_resource_and_scope_configuration() {
        for (extra, code) in [
            ("resource: /relative", "evidence.oid4vci.token-resource"),
            (
                "resource: https://user@evidence.example.org",
                "evidence.oid4vci.token-resource",
            ),
            (
                "resource: https://evidence.example.org/#fragment",
                "evidence.oid4vci.token-resource",
            ),
            (
                "resource: https://evidence.example.org/a b",
                "evidence.oid4vci.token-resource",
            ),
            (
                "resource: https://evidence.example.org/é",
                "evidence.oid4vci.token-resource",
            ),
            (
                "resource: https://evidence.example.org/%GG",
                "evidence.oid4vci.token-resource",
            ),
            ("scopes: []", "evidence.oid4vci.token-scope-count"),
            (
                "scopes: [evidence:invoke, evidence:invoke]",
                "config.duplicate-item",
            ),
            ("scopes: [\"not a scope\"]", "evidence.oid4vci.token-scope"),
        ] {
            let text = VALID.replace(
                "  clientId: evidence-oid4vci",
                &format!("  clientId: evidence-oid4vci\n  {extra}"),
            );
            assert_refused_with(&text, code);
        }
    }

    #[test]
    fn every_removed_key_names_its_replacement() {
        for (from, to, pointer) in [
            ("tokenClient:", "mint:", "/mint"),
            (
                "kind: EvidenceOid4vciRuntimeConfig",
                "kind: EvidenceOid4vciRuntimeConfig\nversion: 1",
                "/version",
            ),
            (
                "  bind: 127.0.0.1:8090",
                "  address: 127.0.0.1\n  port: 8090",
                "/listener/address",
            ),
            (
                "  privateKeyRef: secret:file/delivery-client.jwk.json",
                "  privateKeyFile: keys/delivery-client.jwk.json",
                "/tokenClient/privateKeyFile",
            ),
        ] {
            let text = VALID.replace(from, to);
            let error = load_from(&text).expect_err("a removed key is refused");
            let removed = error
                .diagnostics()
                .iter()
                .find(|diagnostic| diagnostic.code == "config.removed-key")
                .unwrap_or_else(|| panic!("no removed-key finding for {to}: {error}"));
            assert_eq!(removed.path, pointer);
            assert!(!removed.suggested_action.is_empty());
        }
    }

    #[test]
    fn a_metrics_listener_written_with_address_and_port_names_bind() {
        let text = VALID.replace(
            "secretProviders:",
            "metricsListener:\n  address: 127.0.0.1\n  port: 9090\nsecretProviders:",
        );
        let error = load_from(&text).expect_err("the removed keys are refused");
        let pointers: Vec<&str> = error
            .diagnostics()
            .iter()
            .filter(|diagnostic| diagnostic.code == "config.removed-key")
            .map(|diagnostic| diagnostic.path.as_str())
            .collect();
        assert!(pointers.contains(&"/metricsListener/address"), "{error}");
        assert!(pointers.contains(&"/metricsListener/port"), "{error}");
    }

    #[test]
    fn an_unknown_key_is_refused() {
        let text = VALID.replace(
            "kind: EvidenceOid4vciRuntimeConfig",
            "kind: EvidenceOid4vciRuntimeConfig\nunexpected: true",
        );
        assert_eq!(refused(&text), ["config.unknown-key"]);
    }

    #[test]
    fn two_unknown_keys_inside_each_platform_block_are_both_reported() {
        for (from, to, block) in [
            (
                "  bind: 127.0.0.1:8090",
                "  bind: 127.0.0.1:8090\n  first: 1\n  second: 2",
                "/listener",
            ),
            (
                "secretProviders:",
                "metricsListener:\n  bind: 127.0.0.1:9090\n  first: 1\n  second: 2\nsecretProviders:",
                "/metricsListener",
            ),
            (
                "secretProviders:\n",
                "secretProviders:\n  first: 1\n  second: 2\n",
                "/secretProviders",
            ),
            (
                "    root: /run/secrets/evidence-oid4vci",
                "    root: /run/secrets/evidence-oid4vci\n    first: 1\n    second: 2",
                "/secretProviders/file",
            ),
        ] {
            let text = VALID.replace(from, to);
            let error = load_from(&text).expect_err("unknown keys are refused");
            let unknown: Vec<&str> = error
                .diagnostics()
                .iter()
                .filter(|diagnostic| diagnostic.code == "config.unknown-key")
                .map(|diagnostic| diagnostic.path.as_str())
                .collect();
            assert_eq!(
                unknown,
                [format!("{block}/first"), format!("{block}/second")],
                "{error}"
            );
        }
    }

    #[test]
    fn a_hand_written_credential_configuration_cannot_be_expressed() {
        // Published metadata is derived from the Evidence bundle. There is no
        // configuration member to write one into, so a deployment that tries
        // fails to load rather than publishing a credential description
        // Evidence never agreed to.
        for text in [
            VALID.replace(
                "kind: EvidenceOid4vciRuntimeConfig",
                "kind: EvidenceOid4vciRuntimeConfig\ncredentialConfigurationsSupported: {}",
            ),
            VALID.replace(
                "  baseUrl: https://evidence.example.org",
                "  baseUrl: https://evidence.example.org\n  credentialConfigurationsSupported: {}",
            ),
        ] {
            assert_eq!(refused(&text), ["config.unknown-key"]);
        }
    }

    #[test]
    fn offer_claim_names_load_and_reject_shadowing() {
        let configured = VALID.replace("offers:\n", "offers:\n  claims:\n    grantId: task_id\n");
        let config = load_from(&configured).expect("custom contextual claim names load");
        assert_eq!(config.offers.claims.grant_id, "task_id");
        assert_eq!(config.offers.claims.purpose, "registry_purpose");
        for name in ["sub", "registry_grant_source_issuer"] {
            let invalid = configured.replace("grantId: task_id", &format!("grantId: {name}"));
            assert_eq!(refused(&invalid), ["evidence.oid4vci.claim-names"]);
        }
    }

    #[test]
    fn the_offer_authorization_block_is_required_and_is_not_the_client_identity() {
        // The resource-server half and the client half are separate documents.
        // A deployment that states only the client identity does not start,
        // because there would be nothing to authorize an offer against.
        let text = VALID
            .split("offers:")
            .next()
            .expect("the document has an offers block");
        assert_eq!(refused(text), ["config.missing-key"]);

        let config = load_from(VALID).expect("the configuration loads");
        assert_eq!(config.offers.issuer, "https://mint.example.org");
        assert_eq!(config.offers.audiences, ["https://wallet.example.org"]);
        assert_eq!(config.offers.algorithms, [AccessTokenAlgorithm::EdDSA]);
        assert_eq!(
            config.offers.authorized_clients,
            Restriction::Listed(vec!["adopter-front-end".to_owned()])
        );
        assert_eq!(
            config.offers.required_scopes,
            Restriction::Listed(vec!["oid4vci:offer".to_owned()])
        );
        assert_eq!(config.offers.maximum_token_lifetime_seconds, 900);
        // Nothing in the offer boundary is derived from the outbound
        // token-client identity this service authenticates with.
        assert_ne!(config.offers.issuer, config.token_client.token_endpoint);
    }

    #[test]
    fn an_offer_boundary_that_authorizes_nothing_is_refused() {
        for (from, to, code) in [
            (
                r#"  audiences: ["https://wallet.example.org"]"#,
                "  audiences: []",
                "evidence.oid4vci.audience-count",
            ),
            (
                r#"  audiences: ["https://wallet.example.org"]"#,
                r#"  audiences: [" "]"#,
                "evidence.oid4vci.audience",
            ),
            (
                "  algorithms: [EdDSA]",
                "  algorithms: []",
                "evidence.oid4vci.algorithm-count",
            ),
            (
                "  algorithms: [EdDSA]",
                "  algorithms: [EdDSA, RS256]",
                "evidence.oid4vci.algorithm-count",
            ),
            (
                "  maximumTokenLifetimeSeconds: 900",
                "  maximumTokenLifetimeSeconds: 0",
                "config.out-of-range",
            ),
            (
                "  maximumTokenLifetimeSeconds: 900",
                "  maximumTokenLifetimeSeconds: 86400",
                "config.out-of-range",
            ),
            (
                "  authorizedClients: [adopter-front-end]",
                r#"  authorizedClients: [" "]"#,
                "evidence.oid4vci.authorized-client",
            ),
            (
                "  authorizedClients: [adopter-front-end]",
                "  authorizedClients: []",
                "config.invalid-value",
            ),
            (
                "  requiredScopes: [oid4vci:offer]",
                "  requiredScopes: []",
                "config.invalid-value",
            ),
            (
                "  requiredScopes: [oid4vci:offer]",
                "  requiredScopes: [oid4vci:offer, oid4vci:offer]",
                "config.duplicate-item",
            ),
            (
                "  requiredScopes: [oid4vci:offer]",
                r#"  requiredScopes: ["not a scope"]"#,
                "evidence.oid4vci.required-scope",
            ),
            (
                "  requiredScopes: [oid4vci:offer]",
                "  requiredScopes: any",
                "config.invalid-value",
            ),
        ] {
            let text = VALID.replace(from, to);
            assert_refused_with(&text, code);
        }
    }

    /// Both gates are stated: an omitted gate would read as "any client" or
    /// "no scope", so the file has to say `unrestricted` to mean that.
    #[test]
    fn the_offer_gates_are_required_and_unrestricted_is_explicit() {
        for removed in [
            "  authorizedClients: [adopter-front-end]\n",
            "  requiredScopes: [oid4vci:offer]\n",
        ] {
            assert_eq!(refused(&VALID.replace(removed, "")), ["config.missing-key"]);
        }
        let text = VALID
            .replace(
                "  authorizedClients: [adopter-front-end]",
                "  authorizedClients: unrestricted",
            )
            .replace(
                "  requiredScopes: [oid4vci:offer]",
                "  requiredScopes: unrestricted",
            );
        let config = load_from(&text).expect("unrestricted gates load");
        assert_eq!(config.offers.authorized_clients, Restriction::Unrestricted);
        assert_eq!(config.offers.required_scopes, Restriction::Unrestricted);
        assert!(config.offers.authorized_clients.items().is_empty());
    }

    #[test]
    fn a_wildcard_spelled_item_is_a_warning_that_does_not_block_startup() {
        let text = VALID.replace(
            "  authorizedClients: [adopter-front-end]",
            "  authorizedClients: [\"*\"]",
        );
        let (_root, path) = write(&text);
        let (_, warnings) = DeliveryConfig::load_reporting(&path).expect("a warning loads");
        assert_eq!(warnings.len(), 1);
        assert_eq!(warnings[0].code, "evidence.oid4vci.wildcard-spelled-item");
        assert_eq!(warnings[0].severity, Severity::Warning);
        assert_eq!(warnings[0].path, "/offers/authorizedClients/0");
    }

    #[test]
    fn strict_mode_requires_https_for_the_offer_issuer_and_key_set() {
        for (from, to) in [
            (
                "  issuer: https://mint.example.org",
                "  issuer: http://mint.example.org",
            ),
            (
                "  jwksUri: https://mint.example.org/.well-known/jwks.json",
                "  jwksUri: http://mint.example.org/.well-known/jwks.json",
            ),
        ] {
            let text = VALID.replace(from, to);
            assert_eq!(
                refused(&text),
                [HTTPS_REQUIRED],
                "strict mode accepted {to}"
            );
        }
    }

    #[test]
    fn strict_mode_requires_https_for_every_published_and_called_origin() {
        for (from, to) in [
            (
                "credentialIssuer: https://wallet.example.org",
                "credentialIssuer: http://wallet.example.org",
            ),
            (
                "baseUrl: https://evidence.example.org",
                "baseUrl: http://evidence.example.org",
            ),
            (
                "tokenEndpoint: https://mint.example.org/token",
                "tokenEndpoint: http://mint.example.org/token",
            ),
        ] {
            let text = VALID.replace(from, to);
            assert_eq!(
                refused(&text),
                [HTTPS_REQUIRED],
                "strict mode accepted {to}"
            );
        }
    }

    #[test]
    fn a_credential_issuer_carrying_a_query_or_credentials_is_refused() {
        for (issuer, code) in [
            ("https://wallet.example.org?a=b", URL_QUERY_OR_FRAGMENT),
            ("https://wallet.example.org#f", URL_QUERY_OR_FRAGMENT),
            (
                "https://user:secret@wallet.example.org",
                "config.invalid-value",
            ),
        ] {
            let text = VALID.replace(
                "credentialIssuer: https://wallet.example.org",
                &format!("credentialIssuer: \"{issuer}\""),
            );
            let error = load_from(&text).expect_err("the issuer is refused");
            assert_eq!(
                codes(&error),
                [code],
                "the credential issuer accepted {issuer}"
            );
            // A diagnostic never repeats the value it refused.
            assert!(!error.report().render_human().contains("secret"));
        }
    }

    /// The metadata endpoints are built by concatenating the issuer with each
    /// endpoint's absolute route path, and the service only ever registers
    /// routes at the root, so an issuer that already carries a path would
    /// publish an endpoint the service does not serve.
    #[test]
    fn a_credential_issuer_carrying_a_path_is_refused() {
        let text = VALID.replace(
            "credentialIssuer: https://wallet.example.org",
            "credentialIssuer: https://wallet.example.org/tenant-a",
        );
        assert_eq!(refused(&text), ["evidence.oid4vci.issuer-path"]);
    }

    /// The identifier is held in one spelling, the one that is published.
    ///
    /// A trailing slash is the difference a URL parser calls equal and the
    /// byte-exact comparison a wallet proof's `aud` gets does not, so an
    /// operator who writes one must not end up serving an identifier no
    /// conforming wallet can address.
    #[test]
    fn a_credential_issuer_written_with_a_trailing_slash_is_held_as_it_is_published() {
        for written in [
            "https://wallet.example.org/",
            "https://wallet.example.org///",
        ] {
            let text = VALID.replace(
                "credentialIssuer: https://wallet.example.org",
                &format!("credentialIssuer: {written}"),
            );
            let config = load_from(&text).expect("the configuration loads");
            assert_eq!(config.credential_issuer, "https://wallet.example.org");
        }
    }

    fn supervised() -> String {
        VALID
            .replace(
                "kind: EvidenceOid4vciRuntimeConfig",
                "kind: EvidenceOid4vciRuntimeConfig\nvalidationMode: supervised-local-development",
            )
            .replace(
                "credentialIssuer: https://wallet.example.org",
                "credentialIssuer: http://127.0.0.1:8090",
            )
            .replace(
                "baseUrl: https://evidence.example.org",
                "baseUrl: http://127.0.0.1:8080",
            )
            .replace(
                "tokenEndpoint: https://mint.example.org/token",
                "tokenEndpoint: http://127.0.0.1:8081/token",
            )
    }

    #[test]
    fn supervised_local_development_pins_the_listener_to_the_issuer_origin() {
        let local = supervised();
        let config = load_from(&local).expect("the supervised configuration loads");
        assert_eq!(
            config.validation_mode,
            ValidationMode::SupervisedLocalDevelopment
        );

        let mismatched = local.replace("bind: 127.0.0.1:8090", "bind: 127.0.0.1:8099");
        assert_eq!(
            refused(&mismatched),
            ["evidence.oid4vci.supervised-listener"]
        );
        for issuer in [
            "http://127.0.0.1:08090",
            "http://localhost:8090",
            "http://127.0.0.1",
        ] {
            let text = local.replace(
                "credentialIssuer: http://127.0.0.1:8090",
                &format!("credentialIssuer: {issuer}"),
            );
            assert_eq!(
                refused(&text),
                ["evidence.oid4vci.supervised-issuer"],
                "the supervised issuer accepted {issuer}"
            );
        }
        let remote = local.replace(
            "baseUrl: http://127.0.0.1:8080",
            "baseUrl: http://evidence.example.org",
        );
        assert_eq!(refused(&remote), ["evidence.oid4vci.supervised-endpoint"]);
    }

    #[test]
    fn a_nonce_outliving_the_access_window_is_refused() {
        // A nonce that remains valid after the access token window can only
        // advertise a retry window the credential endpoint will not honor.
        let text = VALID.replace("nonceLifetimeSeconds: 120", "nonceLifetimeSeconds: 600");
        let error = load_from(&text).expect_err("the nonce lifetime is refused");
        assert_eq!(codes(&error), ["evidence.oid4vci.nonce-lifetime"]);
        let source = error.diagnostics()[0]
            .source
            .as_ref()
            .expect("the finding is positioned");
        assert_eq!(source.line, Some(27));
    }

    #[test]
    fn store_bounds_outside_their_ranges_are_refused() {
        for (from, to) in [
            ("maximumOffers: 4096", "maximumOffers: 8"),
            ("offerLifetimeSeconds: 300", "offerLifetimeSeconds: 86400"),
            (
                "accessTokenLifetimeSeconds: 300",
                "accessTokenLifetimeSeconds: 0",
            ),
            ("nonceLifetimeSeconds: 120", "nonceLifetimeSeconds: 0"),
            (
                "maximumTransactionCodeAttempts: 3",
                "maximumTransactionCodeAttempts: 0",
            ),
            (
                "maximumTransactionCodeAttempts: 3",
                "maximumTransactionCodeAttempts: 99",
            ),
        ] {
            let text = VALID.replace(from, to);
            assert_refused_with(&text, "config.out-of-range");
        }
    }

    #[test]
    fn the_listener_limits_no_request_can_survive_are_refused() {
        for limit in [
            "maximumRequestBytes: 8",
            "maximumRequestBytes: 4194304",
            "requestTimeoutMilliseconds: 0",
            "requestTimeoutMilliseconds: 120000",
        ] {
            let text = VALID.replace(
                "  bind: 127.0.0.1:8090",
                &format!("  bind: 127.0.0.1:8090\n  {limit}"),
            );
            assert_eq!(refused(&text), ["config.out-of-range"], "{limit}");
        }
    }

    fn with_metrics(listener: &str, metrics: &str) -> String {
        VALID.replace(
            "listener:\n  bind: 127.0.0.1:8090\n",
            &format!(
                "listener:\n  bind: \"{listener}\"\nmetricsListener:\n  bind: \"{metrics}\"\n"
            ),
        )
    }

    #[test]
    fn metrics_are_absent_by_default_and_the_optional_listener_is_private_and_distinct() {
        assert!(valid_config().metrics_listener.is_none());

        let config = load_from(&with_metrics("127.0.0.1:8090", "127.0.0.1:9090"))
            .expect("a distinct loopback listener loads");
        assert_eq!(
            config
                .metrics_listener
                .expect("metrics were configured")
                .bind,
            "127.0.0.1:9090".parse().unwrap()
        );

        for (metrics, code) in [
            ("0.0.0.0:9090", "evidence.oid4vci.metrics-address"),
            ("8.8.8.8:9090", "evidence.oid4vci.metrics-address"),
            ("127.0.0.1:8090", "evidence.oid4vci.metrics-shared-binding"),
            ("127.0.0.1:0", "evidence.oid4vci.metrics-port"),
        ] {
            let refused = refused(&with_metrics("127.0.0.1:8090", metrics));
            assert_eq!(refused, [code], "metrics accepted {metrics}");
        }
    }

    #[test]
    fn ipv4_mapped_listener_addresses_cannot_hide_a_metrics_binding_overlap() {
        let text = with_metrics("[::ffff:127.0.0.1]:8090", "127.0.0.1:8090");
        assert_eq!(refused(&text), ["evidence.oid4vci.metrics-shared-binding"]);
    }

    #[test]
    fn metrics_accept_loopback_unique_local_and_current_ipv4_private_addresses() {
        for address in [
            "127.0.0.1:9090",
            "10.0.0.1:9090",
            "172.16.0.1:9090",
            "192.168.0.1:9090",
            "169.254.1.1:9090",
            "[::1]:9090",
            "[fc00::1]:9090",
            "[fdff:ffff::1]:9090",
        ] {
            assert!(
                load_from(&with_metrics("127.0.0.1:8090", address)).is_ok(),
                "metrics refused {address}"
            );
        }
    }

    #[test]
    fn unscoped_ipv6_unicast_link_local_metrics_addresses_are_refused() {
        for address in ["[fe80::1]:9090", "[febf:ffff::1]:9090"] {
            assert_eq!(
                refused(&with_metrics("127.0.0.1:8090", address)),
                ["evidence.oid4vci.metrics-address"],
                "metrics accepted {address}"
            );
        }
    }

    #[test]
    fn a_listener_port_no_wallet_could_be_told_about_is_refused() {
        // An ephemeral port leaves the service running and reachable by nobody,
        // because the origin it published names a port it is not on.
        let text = VALID.replace("bind: 127.0.0.1:8090", "bind: 127.0.0.1:0");
        assert_eq!(refused(&text), ["evidence.oid4vci.listener-port"]);
    }

    #[test]
    fn the_client_key_is_a_secret_reference_through_an_enabled_provider() {
        let environment = VALID.replace(
            "  privateKeyRef: secret:file/delivery-client.jwk.json",
            "  privateKeyRef: secret:env/DELIVERY_CLIENT_JWK",
        );
        assert_eq!(
            refused(&environment),
            ["evidence.oid4vci.secret-provider-disabled"]
        );
        let enabled = environment.replace(
            "secretProviders:\n",
            "secretProviders:\n  environment: {}\n",
        );
        let config = load_from(&enabled).expect("an enabled provider loads");
        assert_eq!(
            config.token_client.private_key_ref.as_str(),
            "secret:env/DELIVERY_CLIENT_JWK"
        );

        let relative = VALID.replace(
            "root: /run/secrets/evidence-oid4vci",
            "root: run/secrets/evidence-oid4vci",
        );
        assert_eq!(refused(&relative), ["evidence.oid4vci.secret-file-root"]);
        let none = VALID.replace(
            "secretProviders:\n  file:\n    root: /run/secrets/evidence-oid4vci\n",
            "secretProviders: {}\n",
        );
        assert_eq!(refused(&none), ["evidence.oid4vci.secret-providers"]);
    }

    #[test]
    fn runtime_loader_refuses_environment_expressions_in_secret_references() {
        for written in [
            "${DELIVERY_CLIENT_JWK}",
            "secret:file/${DELIVERY_CLIENT_KEY_NAME}",
        ] {
            let text = VALID.replace(
                "privateKeyRef: secret:file/delivery-client.jwk.json",
                &format!("privateKeyRef: \"{written}\""),
            );
            let error = load_from(&text).expect_err("an environment expression is refused");
            let diagnostic = error
                .diagnostics()
                .iter()
                .find(|diagnostic| diagnostic.path == "/tokenClient/privateKeyRef")
                .unwrap_or_else(|| panic!("no finding at the reference: {:?}", codes(&error)));
            assert!(!diagnostic.message.contains("DELIVERY_CLIENT"));
        }
    }

    #[test]
    fn an_empty_client_identity_is_refused() {
        for (from, to, code) in [
            (
                "clientId: evidence-oid4vci",
                "clientId: \"\"",
                "config.invalid-value",
            ),
            (
                "clientId: evidence-oid4vci",
                "clientId: \" \"",
                "evidence.oid4vci.client-id",
            ),
            (
                "privateKeyRef: secret:file/delivery-client.jwk.json",
                "privateKeyRef: \"\"",
                "config.invalid-value",
            ),
        ] {
            let text = VALID.replace(from, to);
            assert_refused_with(&text, code);
        }
    }

    #[test]
    fn a_missing_document_reports_that_it_is_unavailable() {
        let root = canonical_tempdir();
        let error = DeliveryConfig::load(&root.path().join("absent.yaml"))
            .expect_err("a missing file is refused");
        assert!(error.is_unavailable());
        assert_eq!(error.to_string(), "the configuration file is unavailable");
        assert!(check_file(&root.path().join("absent.yaml"), false).unavailable);
    }

    #[test]
    fn every_finding_is_reported_at_its_member() {
        let text = VALID
            .replace(
                "credentialIssuer: https://wallet.example.org",
                "credentialIssuer: http://wallet.example.org/path",
            )
            .replace("bind: 127.0.0.1:8090", "bind: 127.0.0.1:0");
        let report = check(&text, false);
        let found: Vec<(&str, &str, Option<usize>)> = report
            .diagnostics
            .iter()
            .map(|diagnostic| {
                (
                    diagnostic.code.as_str(),
                    diagnostic.path.as_str(),
                    diagnostic.source.as_ref().and_then(|source| source.line),
                )
            })
            .collect();
        assert_eq!(
            found,
            [
                (HTTPS_REQUIRED, "/credentialIssuer", Some(3)),
                ("evidence.oid4vci.issuer-path", "/credentialIssuer", Some(3)),
                ("evidence.oid4vci.listener-port", "/listener/bind", Some(5)),
            ]
        );
        for diagnostic in &report.diagnostics {
            assert_eq!(diagnostic.artifact.as_deref(), Some(OID4VCI_RUNTIME_KIND));
        }
    }

    /// An offline check reads no environment: an expression is checked by
    /// syntax and position, and a rule about its value is left out.
    #[test]
    fn an_offline_check_skips_rules_about_a_deferred_value() {
        let text = VALID
            .replace(
                "bind: 127.0.0.1:8090",
                "bind: ${EVIDENCE_OID4VCI_TEST_UNSET_BIND}",
            )
            .replace(
                "credentialIssuer: https://wallet.example.org",
                "credentialIssuer: ${EVIDENCE_OID4VCI_TEST_UNSET_ISSUER}",
            )
            .replace(
                "  authorizedClients: [adopter-front-end]",
                "  authorizedClients: ${EVIDENCE_OID4VCI_TEST_UNSET_CLIENTS}",
            );
        assert!(check(&text, false).diagnostics.is_empty());
        let substituted = check(&text, true);
        assert!(
            substituted
                .diagnostics
                .iter()
                .any(|diagnostic| diagnostic.code == "config.substitution"),
            "{:?}",
            substituted.diagnostics
        );

        let reference = VALID.replace(
            "privateKeyRef: secret:file/delivery-client.jwk.json",
            "privateKeyRef: ${EVIDENCE_OID4VCI_TEST_UNSET_KEY}",
        );
        let refused: Vec<String> = check(&reference, false)
            .diagnostics
            .into_iter()
            .map(|diagnostic| diagnostic.code)
            .collect();
        assert_eq!(refused, ["config.substitution-not-allowed"]);
    }

    /// Two items of a list that must not repeat an item, each written as its
    /// own expression, are two items: the check does not read one stand-in
    /// into both and then refuse the list as a repeat.
    #[test]
    fn distinct_deferred_items_of_one_list_are_not_a_repeat() {
        for (from, to) in [
            (
                "  authorizedClients: [adopter-front-end]",
                "  authorizedClients: ['${EVIDENCE_OID4VCI_TEST_UNSET_FIRST}', '${EVIDENCE_OID4VCI_TEST_UNSET_SECOND}']",
            ),
            (
                "  requiredScopes: [oid4vci:offer]",
                "  requiredScopes: ['${EVIDENCE_OID4VCI_TEST_UNSET_FIRST}', '${EVIDENCE_OID4VCI_TEST_UNSET_SECOND}']",
            ),
        ] {
            let text = VALID.replacen(from, to, 1);
            assert_ne!(text, VALID, "{to}");
            let report = check(&text, false);
            assert!(report.diagnostics.is_empty(), "{to}: {:?}", report.diagnostics);
        }
    }

    /// The offer endpoint accepts one algorithm, so an expression in its list
    /// is read as an algorithm of the closed vocabulary, never as a value the
    /// list could not decode.
    #[test]
    fn deferred_algorithms_are_counted_not_read_as_a_repeat() {
        let text = VALID.replacen(
            "  algorithms: [EdDSA]",
            "  algorithms: ['${EVIDENCE_OID4VCI_TEST_UNSET_FIRST}', '${EVIDENCE_OID4VCI_TEST_UNSET_SECOND}']",
            1,
        );
        assert_ne!(text, VALID);
        let report = check(&text, false);
        let codes: Vec<&str> = report
            .diagnostics
            .iter()
            .map(|diagnostic| diagnostic.code.as_str())
            .collect();
        assert!(!codes.contains(&"config.duplicate-item"), "{codes:?}");
    }

    #[test]
    fn a_deferred_algorithm_decodes() {
        let text = VALID.replacen(
            "  algorithms: [EdDSA]",
            "  algorithms: ['${EVIDENCE_OID4VCI_TEST_UNSET_ALGORITHM}']",
            1,
        );
        assert_ne!(text, VALID);
        let report = check(&text, false);
        assert!(report.diagnostics.is_empty(), "{:?}", report.diagnostics);
    }

    #[test]
    fn the_listener_binding_rule_is_shared_with_the_serving_path() {
        let mut config = valid_config();
        assert_eq!(config.binding_fault(), None);
        config.metrics_listener = Some(MetricsListenerConfig {
            bind: "0.0.0.0:9090".parse().unwrap(),
        });
        assert_eq!(
            config.binding_fault(),
            Some("the metrics listener must bind a loopback or private address")
        );
    }
}
