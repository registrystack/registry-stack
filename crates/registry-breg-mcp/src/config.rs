// SPDX-License-Identifier: Apache-2.0

//! The operator runtime configuration document.
//!
//! The inbound resource server and the outbound registry exchange are two
//! sections that share no field: nothing the gateway accepts from a chat host
//! is configured by the same key as anything it presents to the registry.
//! Every credential is a `secret:env/` or `secret:file/` reference, never
//! inline text.
//!
//! The file is read through the shared Registry Stack runtime configuration
//! loader, so its envelope, size bound, path rules, `${VAR}` substitution,
//! and secret provider declarations match every other runtime.

use std::{fmt, path::Path};

use registry_mcp_edge::config::{bounded_restricting_list, ResourceServerConfigError};
pub use registry_mcp_edge::config::{
    AccessTokenAlgorithm, AuditConfig, ExchangeConfig, LimitsConfig, LogLevel, RateLimitConfig,
    ResourceServerConfig, ResourceUri, ScopeToken,
};
use registry_platform_audit::AuditDestinationError;
pub(crate) use registry_platform_config::describe_secret_failure;
use registry_platform_config::{
    ConfigBlockError, ConfigBlockErrorKind, LoadedRuntimeConfig, PrivateListenerConfig, RemovedKey,
    RuntimeConfigLoader, RuntimeEnvelope, SecretProvidersConfig, TlsTermination,
};
use registry_platform_yaml::{
    escape_pointer_segment, BoundedU64, Diagnostic, Invalid, LocalId, Report, RetiredApiVersion,
    UniqueList, Url,
};
use serde::{Deserialize, Deserializer};
use url::Host;

/// apiVersion of the gateway runtime configuration document.
pub const RUNTIME_API_VERSION: &str = "id.registrystack.org/formats/breg/mcp-runtime/v1alpha1";
/// Kind of the gateway runtime configuration document.
pub const RUNTIME_KIND: &str = "BRegMcpRuntimeConfig";
/// The single path the MCP endpoint is served at.
pub const MCP_PATH: &str = "/mcp";

const fn default_log_level() -> LogLevel {
    LogLevel::Info
}

/// The most characters a citizen-facing service text may hold.
const MAXIMUM_SERVICE_TEXT_CHARS: usize = 4096;
/// The shortest and longest wait for one registry call.
const MINIMUM_ATTEMPT_TIMEOUT_MILLISECONDS: u64 = 100;
const MAXIMUM_ATTEMPT_TIMEOUT_MILLISECONDS: u64 = 120_000;

const RUNTIME_ENVELOPE: RuntimeEnvelope = RuntimeEnvelope {
    api_version: RUNTIME_API_VERSION,
    kind: RUNTIME_KIND,
};

/// The apiVersion a runtime file carried before its members took their
/// shared names, refused with the renames it needs.
const RETIRED_RUNTIME_API_VERSIONS: &[RetiredApiVersion<'static>] = &[RetiredApiVersion {
    api_version: "registry.registrystack.org/breg-mcp-runtime/v1alpha1",
    replacement: "Write apiVersion id.registrystack.org/formats/breg/mcp-runtime/v1alpha1, then \
                  rename resourceServer.maxTokenLifetimeSeconds to \
                  resourceServer.maximumTokenLifetimeSeconds, \
                  registry.requestTimeoutMilliseconds to registry.attemptTimeoutMilliseconds, \
                  limits.maxRequestBodyBytes to limits.maximumRequestBytes, and \
                  audit.retainDays to audit.retentionDays.",
}];

/// Keys an earlier runtime file carried, each refused with its replacement.
const REMOVED_KEYS: &[RemovedKey] = &[
    RemovedKey {
        path: "resourceServer.maxTokenLifetimeSeconds",
        replacement: "declare resourceServer.maximumTokenLifetimeSeconds instead",
    },
    RemovedKey {
        path: "registry.requestTimeoutMilliseconds",
        replacement: "declare registry.attemptTimeoutMilliseconds instead",
    },
    RemovedKey {
        path: "limits.maxRequestBodyBytes",
        replacement: "declare limits.maximumRequestBytes instead",
    },
    RemovedKey {
        path: "audit.retainDays",
        replacement: "declare audit.retentionDays instead",
    },
    RemovedKey {
        path: "resourceServer.jwksSource.kind",
        replacement: "declare resourceServer.jwksSource.type with the same value instead",
    },
];

/// The operator runtime configuration document.
#[derive(Clone, Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeConfig {
    pub api_version: String,
    pub kind: String,
    /// Operational log level when `BREG_MCP_LOG` is not set. Defaults to
    /// `info`; accepted values are `error`, `warn`, and `info`.
    #[serde(default = "default_log_level")]
    #[cfg_attr(feature = "schema", schemars(default))]
    pub log_level: LogLevel,
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

/// The outbound half: the registry the gateway acts on.
#[derive(Clone, Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistryConfig {
    /// The registry deployment's base URL. An https URL with no query or
    /// fragment; plain http is accepted only on a loopback host under
    /// `development-loopback`.
    pub base_url: Url,
    /// The standing agent access profile every call names.
    pub access_profile: LocalId,
    /// The registry's token audience, requested as the exchange resource.
    pub audience: ResourceUri,
    /// The scopes requested for the delegated registry token.
    #[serde(deserialize_with = "bounded_restricting_list")]
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 128)))]
    pub scopes: UniqueList<ScopeToken>,
    /// How long one registry call may take before it is abandoned, in
    /// milliseconds.
    #[serde(default = "default_attempt_timeout")]
    pub attempt_timeout_milliseconds:
        BoundedU64<MINIMUM_ATTEMPT_TIMEOUT_MILLISECONDS, MAXIMUM_ATTEMPT_TIMEOUT_MILLISECONDS>,
}

fn default_attempt_timeout(
) -> BoundedU64<MINIMUM_ATTEMPT_TIMEOUT_MILLISECONDS, MAXIMUM_ATTEMPT_TIMEOUT_MILLISECONDS> {
    BoundedU64::new(10_000).expect("the default attempt timeout is within its bounds")
}

/// The authored service a citizen is told about, and the registry entities
/// its tools work over.
#[derive(Clone, Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceConfig {
    pub name: ServiceText,
    pub description: ServiceText,
    /// What the citizen is told about the data the chat host will see.
    pub disclosure: ServiceText,
    pub details: DetailsConfig,
    pub application: ApplicationConfig,
    /// The citizen-facing review page; an application is reviewed and
    /// submitted there, never through the chat host. The review page's
    /// `publicOrigin`, with no path, query, or fragment.
    pub review_base_url: Url,
}

/// The Record type holding the citizen's own record, found through the agent
/// profile's linked lookup.
#[derive(Clone, Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DetailsConfig {
    pub record_type: LocalId,
}

/// The proposal-mode Action and its target input, resolved by the gateway.
#[derive(Clone, Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplicationConfig {
    pub action: LocalId,
    /// The input identifier of the input that references the citizen's own
    /// record.
    pub target_input: LocalId,
}

#[derive(Clone, Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RateLimitsConfig {
    /// The limit each citizen's requests share.
    pub per_citizen: RateLimitConfig,
    /// The limit each chat-host client's requests share.
    pub per_client: RateLimitConfig,
}

/// Text checked by one rule, refused with one [`Invalid`] that names the
/// rule and never the value.
macro_rules! checked_text {
    ($(#[$meta:meta])* $name:ident, $valid:expr, $invalid:expr) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, Hash)]
        pub struct $name(String);

        impl $name {
            pub fn new(text: impl Into<String>) -> Result<Self, Invalid> {
                let text = text.into();
                let valid: fn(&str) -> bool = $valid;
                if valid(&text) {
                    Ok(Self(text))
                } else {
                    Err($invalid)
                }
            }

            /// The value as written.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl std::ops::Deref for $name {
            type Target = str;

            fn deref(&self) -> &str {
                &self.0
            }
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
    /// Text a citizen reads: not blank, at most 4096 characters.
    ServiceText,
    |text| !text.trim().is_empty() && text.chars().count() <= MAXIMUM_SERVICE_TEXT_CHARS,
    Invalid::expected(
        "text of at most 4096 characters that is not blank",
        "Write the sentence the citizen reads, in at most 4096 characters."
    )
);

/// Why the runtime configuration was refused: every finding, each
/// positioned in the file and naming its fix, never a value from it.
#[derive(Debug)]
pub struct RuntimeConfigError {
    pub diagnostics: Vec<Diagnostic>,
    /// The file could not be read at all, as opposed to read and refused.
    pub unavailable: bool,
}

impl RuntimeConfigError {
    /// The findings in the shared human shape (CFG-DIAG-2).
    #[must_use]
    pub fn render_human(&self) -> String {
        Report::new(self.diagnostics.clone()).render_human()
    }
}

impl fmt::Display for RuntimeConfigError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let headline = if self.unavailable {
            "the runtime configuration could not be read"
        } else {
            "the runtime configuration was refused"
        };
        write!(formatter, "{headline}\n{}", self.render_human())
    }
}

impl std::error::Error for RuntimeConfigError {}

/// What an offline check of one runtime file found.
#[derive(Debug)]
pub struct RuntimeCheck {
    /// Every finding, each naming the file as `path` was given.
    pub diagnostics: Vec<Diagnostic>,
    /// The file could not be read at all, as opposed to read and refused.
    pub unavailable: bool,
}

impl RuntimeConfig {
    /// Load and validate the operator document through the shared loader,
    /// with the process environment, as `serve` does at startup.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, RuntimeConfigError> {
        match read_runtime(path.as_ref(), true) {
            (Some(loaded), _) => Ok(loaded.config),
            (None, check) => Err(RuntimeConfigError {
                diagnostics: check.diagnostics,
                unavailable: check.unavailable,
            }),
        }
    }

    /// The loader for the gateway runtime file, with its removed keys and
    /// its retired apiVersion.
    #[must_use]
    pub const fn loader() -> RuntimeConfigLoader {
        RuntimeConfigLoader::new(RUNTIME_ENVELOPE)
            .removed_keys(REMOVED_KEYS)
            .retired_api_versions(RETIRED_RUNTIME_API_VERSIONS)
    }

    /// Whether plain-HTTP loopback endpoints are acceptable.
    #[must_use]
    pub fn development_loopback(&self) -> bool {
        self.listener.tls_termination == TlsTermination::DevelopmentLoopback
    }
}

/// Check the runtime file at the absolute `path` as `breg-mcp serve` reads
/// it, with no secret material, network, or listener (CFG-CHECK-1).
///
/// With `substitute` set, `${NAME}` expressions are filled from the process
/// environment and every value is checked. Without it, each expression is
/// checked by syntax and position only: the value checks of a member that
/// holds one are skipped, because they need the substituted text.
#[must_use]
pub fn check_runtime(path: &Path, substitute: bool) -> RuntimeCheck {
    read_runtime(path, substitute).1
}

/// The file read by the shared loader, then the members the loader cannot
/// judge checked: the listener, the secret provider block and references,
/// the endpoints, the cross-member rules, and the audit destination. The
/// configuration is returned only when nothing was found.
fn read_runtime(
    path: &Path,
    substitute: bool,
) -> (Option<LoadedRuntimeConfig<RuntimeConfig>>, RuntimeCheck) {
    let check =
        RuntimeConfig::loader().check_offline::<RuntimeConfig>(path, substitute, stand_in_for);
    let mut diagnostics = check.diagnostics.clone();
    if let Some(loaded) = &check.loaded {
        let defers = |pointer: &str| check.defers(pointer);
        for finding in findings(&loaded.config, &defers) {
            let audit_deferred =
                finding.pointer.starts_with("/audit") && check.defers("/audit/destination");
            if !check.defers(&finding.pointer) && !audit_deferred {
                diagnostics.push(check.error_at(
                    RUNTIME_KIND,
                    finding.code,
                    &finding.pointer,
                    finding.message,
                    finding.action,
                ));
            }
        }
    }
    let unavailable = check.unavailable;
    let loaded = check.loaded.filter(|_| diagnostics.is_empty());
    (
        loaded,
        RuntimeCheck {
            diagnostics,
            unavailable,
        },
    )
}

/// One refusal of a member the shared loader accepted.
struct Finding {
    code: &'static str,
    pointer: String,
    message: String,
    action: String,
}

impl Finding {
    fn new(code: &'static str, pointer: &str, message: &str, action: &str) -> Self {
        Self {
            code,
            pointer: pointer.to_owned(),
            message: message.to_owned(),
            action: action.to_owned(),
        }
    }
}

/// Every refusal of a decoded file. A rule that compares two members is
/// skipped when either holds an expression the check did not substitute.
fn findings(config: &RuntimeConfig, defers: &dyn Fn(&str) -> bool) -> Vec<Finding> {
    let mut findings = Vec::new();
    if !config.listener.is_valid() {
        findings.push(Finding::new(
            "breg.mcp-runtime.public-bind",
            "/listener/bind",
            "listener.bind is not a loopback or private address its tlsTermination and \
             networkExposure allow",
            "Bind a loopback address, or a private address behind the proxy that terminates TLS \
             with tlsTermination operator-controlled-upstream.",
        ));
    }
    let blocks = [
        config.secret_providers.check(),
        config.audit.key.check(&config.secret_providers),
        config.secret_providers.check_reference(
            "exchange.privateKeyRef",
            config.exchange.private_key_ref.as_str(),
        ),
    ];
    findings.extend(
        blocks
            .iter()
            .filter_map(|result| result.as_ref().err())
            .map(block_finding),
    );
    findings.extend(
        config
            .resource_server
            .validate(config.development_loopback(), &config.secret_providers)
            .iter()
            .filter(|error| {
                !defers("/listener/tlsTermination")
                    || !matches!(
                        error,
                        ResourceServerConfigError::InsecureResource
                            | ResourceServerConfigError::InsecureIssuer
                    )
            })
            .map(resource_server_finding),
    );
    endpoint_findings(config, defers, &mut findings);
    cross_member_findings(config, defers, &mut findings);
    if let Err(error) = config.audit.destination() {
        findings.push(audit_finding(&error));
    }
    findings
}

/// Every endpoint the gateway serves or calls is https with no query or
/// fragment, or plain http on a loopback host under `development-loopback`.
fn endpoint_findings(
    config: &RuntimeConfig,
    defers: &dyn Fn(&str) -> bool,
    findings: &mut Vec<Finding>,
) {
    let termination_known = !defers("/listener/tlsTermination");
    let development = config.development_loopback();
    let endpoints = [
        ("/registry/baseUrl", &config.registry.base_url),
        ("/exchange/tokenEndpoint", &config.exchange.token_endpoint),
        ("/service/reviewBaseUrl", &config.service.review_base_url),
    ];
    for (pointer, endpoint) in endpoints {
        let url = endpoint.to_url();
        let secure = url.scheme() == "https" || (development && loopback_host(&url));
        if termination_known && !secure {
            findings.push(Finding::new(
                "breg.mcp-runtime.plain-http-endpoint",
                pointer,
                "the endpoint uses plain http, which is accepted only on a loopback host under \
                 listener.tlsTermination development-loopback",
                "Write an https URL, run on loopback with listener.tlsTermination \
                 development-loopback.",
            ));
        } else if url.query().is_some() || url.fragment().is_some() {
            findings.push(Finding::new(
                "breg.mcp-runtime.endpoint-query-or-fragment",
                pointer,
                "the endpoint carries a query or a fragment",
                "Remove the query and the fragment from the URL.",
            ));
        }
    }
    // The review page serves its pages at the root of its publicOrigin.
    if config.service.review_base_url.to_url().path() != "/" {
        findings.push(Finding::new(
            "breg.mcp-runtime.review-base-url-not-origin",
            "/service/reviewBaseUrl",
            "service.reviewBaseUrl has a path, but the review page serves its pages at the root \
             of its publicOrigin",
            "Write the review page's publicOrigin, with no path.",
        ));
    }
}

/// The rules that compare two members of the file.
fn cross_member_findings(
    config: &RuntimeConfig,
    defers: &dyn Fn(&str) -> bool,
    findings: &mut Vec<Finding>,
) {
    let admitted = !defers("/exchange/clientId")
        && config
            .resource_server
            .allowed_clients
            .iter()
            .enumerate()
            .any(|(index, client)| {
                !defers(&format!("/resourceServer/allowedClients/{index}"))
                    && *client == config.exchange.client_id
            });
    if admitted {
        findings.push(Finding::new(
            "breg.mcp-runtime.exchange-client-admitted-inbound",
            "/exchange/clientId",
            "the gateway's own exchange client is also an accepted inbound client",
            "Give the gateway a client identifier of its own, and remove it from \
             resourceServer.allowedClients.",
        ));
    }
    if !defers("/resourceServer/resource")
        && config.registry.audience.as_str() == config.resource_server.resource.as_str()
    {
        findings.push(Finding::new(
            "breg.mcp-runtime.audience-reused",
            "/registry/audience",
            "the registry audience is the gateway's own resource",
            "Write the registry's own token audience, which differs from \
             resourceServer.resource.",
        ));
    }
}

fn loopback_host(url: &url::Url) -> bool {
    url.scheme() == "http"
        && match url.host() {
            Some(Host::Ipv4(address)) => address.is_loopback(),
            Some(Host::Ipv6(address)) => address.is_loopback(),
            Some(Host::Domain(domain)) => domain == "localhost",
            None => false,
        }
}

/// A value that satisfies the member at `pointer`, so a deferred expression
/// never decides whether its neighbours decode.
fn stand_in_for(pointer: &str) -> &'static str {
    if let Some(index) = pointer.strip_prefix("/resourceServer/algorithms/") {
        // The list is a set, so each position takes its own algorithm.
        const ALGORITHMS: [&str; 5] = ["RS256", "RS384", "ES256", "ES384", "EdDSA"];
        let index = index.parse::<usize>().unwrap_or(0);
        return ALGORITHMS[index % ALGORITHMS.len()];
    }
    match pointer {
        "/listener/bind" => "127.0.0.1:8080",
        "/listener/tlsTermination" => "operator-controlled-upstream",
        "/listener/networkExposure" => "private-address",
        "/resourceServer/resource" => "https://deferred.invalid/mcp",
        "/resourceServer/issuer"
        | "/resourceServer/jwksSource/uri"
        | "/registry/baseUrl"
        | "/exchange/tokenEndpoint"
        | "/service/reviewBaseUrl" => "https://deferred.invalid",
        "/registry/audience" => "urn:deferred",
        "/audit/destination" => "file",
        "/audit/path" => "/audit.jsonl",
        _ => registry_platform_config::DEFAULT_STAND_IN,
    }
}

fn pointer_of(dotted: &str) -> String {
    dotted
        .split('.')
        .map(|segment| format!("/{}", escape_pointer_segment(segment)))
        .collect()
}

fn resource_server_finding(error: &ResourceServerConfigError) -> Finding {
    match error {
        ResourceServerConfigError::InvalidResource => Finding::new(
            "breg.mcp-runtime.endpoint-query-or-fragment",
            "/resourceServer/resource",
            "the endpoint carries a query or a fragment",
            "Remove the query and the fragment from the URL.",
        ),
        ResourceServerConfigError::ResourceNotMcpEndpoint => Finding::new(
            "breg.mcp-runtime.resource-not-mcp-endpoint",
            "/resourceServer/resource",
            "resourceServer.resource does not name the /mcp endpoint this gateway serves",
            "Write the URL of this gateway's /mcp endpoint, as chat hosts reach it.",
        ),
        ResourceServerConfigError::InsecureResource => Finding::new(
            "breg.mcp-runtime.plain-http-endpoint",
            "/resourceServer/resource",
            "the endpoint uses plain http, which is accepted only on a loopback host under listener.tlsTermination development-loopback",
            "Write an https URL, or run on loopback with listener.tlsTermination development-loopback.",
        ),
        ResourceServerConfigError::InvalidIssuer => Finding::new(
            "breg.mcp-runtime.endpoint-query-or-fragment",
            "/resourceServer/issuer",
            "the endpoint carries a query or a fragment",
            "Remove the query and the fragment from the URL.",
        ),
        ResourceServerConfigError::InsecureIssuer => Finding::new(
            "breg.mcp-runtime.plain-http-endpoint",
            "/resourceServer/issuer",
            "the endpoint uses plain http, which is accepted only on a loopback host under listener.tlsTermination development-loopback",
            "Write an https URL, run on loopback with listener.tlsTermination development-loopback, or set resourceServer.allowInsecureHttp: true for the issuer.",
        ),
        ResourceServerConfigError::JwksSource(error)
        | ResourceServerConfigError::JwksDocumentReference(error) => block_finding(error),
    }
}

/// The code and fix for a shared block refusal.
fn block_finding(error: &ConfigBlockError) -> Finding {
    let (code, action) = match error.kind() {
        ConfigBlockErrorKind::RelativePath => (
            "breg.mcp-runtime.relative-path",
            "Write the path as an absolute path with no `.` or `..` segment.",
        ),
        ConfigBlockErrorKind::NoSecretProvider => (
            "breg.mcp-runtime.no-secret-provider",
            "Declare secretProviders.file with an absolute root, \
             secretProviders.environment: {}, or both.",
        ),
        ConfigBlockErrorKind::InvalidSecretReference => (
            "breg.mcp-runtime.invalid-secret-reference",
            "Write the reference as secret:file/<name> or secret:env/<NAME>.",
        ),
        ConfigBlockErrorKind::SecretProviderDisabled => (
            "breg.mcp-runtime.undeclared-secret-provider",
            "Declare the provider the message names under secretProviders, or reference a \
             declared one.",
        ),
        ConfigBlockErrorKind::InvalidUri => (
            "breg.mcp-runtime.invalid-jwks-uri",
            "Write an https URL without credentials; plain http is accepted only on a loopback \
             address under listener.tlsTermination development-loopback.",
        ),
        _ => (
            "breg.mcp-runtime.invalid-block",
            "Correct the member as the message describes.",
        ),
    };
    Finding {
        code,
        pointer: pointer_of(error.field()),
        message: error.to_string(),
        action: action.to_owned(),
    }
}

/// The code, position, and fix for a refusal of the audit block, under the
/// member names this file uses.
fn audit_finding(error: &AuditDestinationError) -> Finding {
    let finding = |code, pointer: &str, message: String, action: &str| Finding {
        code,
        pointer: pointer.to_owned(),
        message,
        action: action.to_owned(),
    };
    match error {
        AuditDestinationError::MissingPath => finding(
            "breg.mcp-runtime.missing-audit-path",
            "/audit",
            error.to_string(),
            "Declare audit.path as the absolute path of the active audit file, or set \
             audit.destination to stdout.",
        ),
        AuditDestinationError::FileOnlyField { field } => {
            let member = match *field {
                "retainDays" => "retentionDays",
                other => other,
            };
            finding(
                "breg.mcp-runtime.file-only-audit-member",
                &format!("/audit/{member}"),
                format!("audit.{member} applies only when audit.destination is file"),
                "Remove the member, or set audit.destination to file.",
            )
        }
        AuditDestinationError::RelativePath
        | AuditDestinationError::InvalidPathComponent
        | AuditDestinationError::NoFileName
        | AuditDestinationError::FileNameTooLong { .. } => finding(
            "breg.mcp-runtime.invalid-audit-path",
            "/audit/path",
            error.to_string(),
            "Write audit.path as an absolute file path with no `.` or `..` segment, ending in \
             a file name.",
        ),
        AuditDestinationError::PathNamesReservedCompanion {
            suffix, companion, ..
        } => finding(
            "breg.mcp-runtime.invalid-audit-path",
            "/audit/path",
            format!(
                "audit.path ends in `{suffix}`, which names the {companion} of another audit \
                 stream"
            ),
            "Choose an audit file name without that ending.",
        ),
        AuditDestinationError::RetainDaysOutOfRange { maximum } => finding(
            "breg.mcp-runtime.invalid-audit",
            "/audit/retentionDays",
            format!("audit.retentionDays must be between 1 and {maximum}"),
            "Write a number of days within the bounds.",
        ),
        _ => finding(
            "breg.mcp-runtime.invalid-audit",
            "/audit",
            error.to_string(),
            "Correct the audit block as the message describes.",
        ),
    }
}

#[cfg(feature = "schema")]
mod schema_impls {
    use std::borrow::Cow;

    use schemars::{json_schema, JsonSchema, Schema, SchemaGenerator};

    use super::ServiceText;

    impl JsonSchema for ServiceText {
        fn schema_name() -> Cow<'static, str> {
            Cow::Borrowed("ServiceText")
        }

        fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
            json_schema!({
                "type": "string",
                "minLength": 1,
                "maxLength": 4096,
                "pattern": "\\S",
                "description": "Text a citizen reads: not blank, at most 4096 characters.",
            })
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::{fs, path::PathBuf};

    use registry_platform_config::{JwksSource, SecretReference};
    use registry_platform_yaml::ExternalId;

    use super::*;

    pub(crate) fn document() -> String {
        r#"apiVersion: id.registrystack.org/formats/breg/mcp-runtime/v1alpha1
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
    type: uri
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
    recordType: person-address
  application:
    action: correct-address
    targetInput: address
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

    /// The outbound sections a unit test points at its own registry and
    /// authorization server.
    pub(crate) fn outbound_sections(
        base_url: &str,
        token_endpoint: &str,
    ) -> (RegistryConfig, ExchangeConfig) {
        let registry = RegistryConfig {
            base_url: Url::new(base_url).expect("base URL"),
            access_profile: LocalId::new("citizen-agent").expect("access profile"),
            audience: ResourceUri::new("urn:breg:citizen-address-correction").expect("audience"),
            scopes: UniqueList::new(vec![
                ScopeToken::new("address-correction:self").expect("scope")
            ])
            .expect("scopes"),
            // Use the runtime budget so loaded test runners do not impose a tighter deadline.
            attempt_timeout_milliseconds: default_attempt_timeout(),
        };
        let exchange = ExchangeConfig {
            token_endpoint: Url::new(token_endpoint).expect("token endpoint"),
            client_id: ExternalId::new("citizen-gateway").expect("client"),
            private_key_ref: SecretReference::parse("secret:file/unused").expect("reference"),
            assertion_audience: None,
        };
        (registry, exchange)
    }

    pub(crate) fn service() -> ServiceConfig {
        ServiceConfig {
            name: ServiceText::new("Address correction").expect("service name"),
            description: ServiceText::new("Correct the postal address the registry holds for you.")
                .expect("service description"),
            disclosure: ServiceText::new("The assistant will see your current address.")
                .expect("service disclosure"),
            details: DetailsConfig {
                record_type: LocalId::new("person-address").expect("details record type"),
            },
            application: ApplicationConfig {
                action: LocalId::new("correct-address").expect("application action"),
                target_input: LocalId::new("address").expect("application target input"),
            },
            review_base_url: Url::new("https://review.example.test/").expect("review base URL"),
        }
    }

    /// Write `text` as a runtime file in a fresh directory the loader
    /// accepts: absolute, and with no symbolic link on its path.
    fn written(text: &str) -> (tempfile::TempDir, PathBuf) {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory
            .path()
            .canonicalize()
            .expect("canonical directory")
            .join("runtime.yaml");
        fs::write(&path, text).expect("runtime file is written");
        (directory, path)
    }

    fn load(text: &str) -> Result<RuntimeConfig, RuntimeConfigError> {
        let (_directory, path) = written(text);
        RuntimeConfig::load(&path)
    }

    /// The codes and paths of every finding, in report order.
    fn findings_of(text: &str) -> Vec<(String, String)> {
        let (_directory, path) = written(text);
        check_runtime(&path, true)
            .diagnostics
            .into_iter()
            .map(|diagnostic| (diagnostic.code, diagnostic.path))
            .collect()
    }

    fn refused(text: &str, code: &str, path: &str) {
        let found = findings_of(text);
        assert_eq!(
            found,
            [(code.to_owned(), path.to_owned())],
            "expected exactly {code} at {path}"
        );
    }

    #[test]
    fn a_complete_document_loads() {
        let config = load(&document()).expect("document loads");
        assert_eq!(config.log_level.as_str(), "info");
        assert_eq!(config.registry.access_profile.as_str(), "citizen-agent");
        assert_eq!(config.limits.request_bytes(), 64 * 1024);
        assert_eq!(config.registry.attempt_timeout_milliseconds.get(), 10_000);
        assert_eq!(
            config.resource_server.maximum_token_lifetime_seconds.get(),
            3600
        );
        assert_eq!(config.resource_server.scope_claim.as_str(), "scope");
        assert!(matches!(
            config.resource_server.jwks_source,
            JwksSource::Uri { .. }
        ));
    }

    #[test]
    fn log_level_accepts_only_the_closed_vocabulary() {
        for accepted in ["error", "warn", "info"] {
            let text = document().replacen(
                "kind: BRegMcpRuntimeConfig\n",
                &format!("kind: BRegMcpRuntimeConfig\nlogLevel: {accepted}\n"),
                1,
            );
            assert_eq!(
                load(&text).expect("level loads").log_level.as_str(),
                accepted
            );
        }
        for refused_value in ["debug", "trace", "off", "Info", ""] {
            let yaml_value = if refused_value.is_empty() {
                "''"
            } else {
                refused_value
            };
            let text = document().replacen(
                "kind: BRegMcpRuntimeConfig\n",
                &format!("kind: BRegMcpRuntimeConfig\nlogLevel: {yaml_value}\n"),
                1,
            );
            refused(&text, "config.unknown-variant", "/logLevel");
        }
    }

    #[test]
    fn the_committed_example_loads() {
        let example = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/breg/examples/mcp-runtime/runtime.yaml")
            .canonicalize()
            .expect("the example exists");
        let check = check_runtime(&example, false);
        assert!(check.diagnostics.is_empty(), "{:?}", check.diagnostics);
    }

    #[test]
    fn a_relative_configuration_path_is_refused() {
        let error = RuntimeConfig::load("runtime.yaml").expect_err("a relative path is refused");
        let codes: Vec<&str> = error
            .diagnostics
            .iter()
            .map(|diagnostic| diagnostic.code.as_str())
            .collect();
        assert_eq!(codes, ["platform.runtime-config.path"]);
    }

    #[test]
    fn the_retired_api_version_names_its_replacement() {
        let text = document().replace(
            "id.registrystack.org/formats/breg/mcp-runtime/v1alpha1",
            "registry.registrystack.org/breg-mcp-runtime/v1alpha1",
        );
        let error = load(&text).expect_err("the retired apiVersion is refused");
        let diagnostic = &error.diagnostics[0];
        assert_eq!(diagnostic.code, "config.retired-api-version");
        assert!(
            diagnostic
                .suggested_action
                .contains("resourceServer.maximumTokenLifetimeSeconds"),
            "{}",
            diagnostic.suggested_action
        );
    }

    #[test]
    fn each_removed_key_is_refused_with_its_replacement() {
        for (from, to, path) in [
            (
                "  requiredScopes: [address-correction:self]\n",
                "  requiredScopes: [address-correction:self]\n  maxTokenLifetimeSeconds: 60\n",
                "/resourceServer/maxTokenLifetimeSeconds",
            ),
            (
                "  scopes: [address-correction:self]\n",
                "  scopes: [address-correction:self]\n  requestTimeoutMilliseconds: 5000\n",
                "/registry/requestTimeoutMilliseconds",
            ),
            (
                "rateLimits:",
                "limits:\n  maxRequestBodyBytes: 65536\nrateLimits:",
                "/limits/maxRequestBodyBytes",
            ),
            (
                "  path: /var/lib/breg-mcp/audit/audit.jsonl\n",
                "  path: /var/lib/breg-mcp/audit/audit.jsonl\n  retainDays: 30\n",
                "/audit/retainDays",
            ),
            (
                "    type: uri\n",
                "    kind: uri\n",
                "/resourceServer/jwksSource/kind",
            ),
        ] {
            let text = document().replacen(from, to, 1);
            assert_ne!(text, document(), "{to}");
            let found = findings_of(&text);
            assert!(
                found.contains(&("config.removed-key".to_owned(), path.to_owned())),
                "{path}: {found:?}"
            );
        }
    }

    /// Keys that predate the predecessor release carry no named guidance:
    /// the closed document shape refuses them as unknown keys.
    #[test]
    fn keys_older_than_the_predecessor_release_are_unknown() {
        for (from, to, path) in [
            ("jwksSource:", "jwks:", "/resourceServer/jwks"),
            (
                "  path: /var/lib/breg-mcp/audit/audit.jsonl\n",
                "  path: /var/lib/breg-mcp/audit/audit.jsonl\n  maximumFileBytes: 1048576\n",
                "/audit/maximumFileBytes",
            ),
        ] {
            let text = document().replacen(from, to, 1);
            assert_ne!(text, document(), "{to}");
            let found = findings_of(&text);
            assert!(
                found.contains(&("config.unknown-key".to_owned(), path.to_owned())),
                "{path}: {found:?}"
            );
        }
    }

    /// The shared blocks keep their members' positions: an unknown key
    /// inside each is reported where it is written, all of them at once.
    #[test]
    fn unknown_keys_inside_each_block_are_all_reported() {
        let text = document()
            .replace(
                "  tlsTermination: operator-controlled-upstream\n",
                "  tlsTermination: operator-controlled-upstream\n  listenerTypo: x\n",
            )
            .replace(
                "  hashKeyRef: secret:file/audit-key\n",
                "  hashKeyRef: secret:file/audit-key\n  auditTypo: x\n",
            )
            .replace("  accessProfile:", "  bearerToken: x\n  accessProfile:");
        let found = findings_of(&text);
        for path in [
            "/listener/listenerTypo",
            "/audit/auditTypo",
            "/registry/bearerToken",
        ] {
            assert!(
                found.contains(&("config.unknown-key".to_owned(), path.to_owned())),
                "{path}: {found:?}"
            );
        }
    }

    #[test]
    fn an_inline_credential_is_refused_without_echoing_it() {
        const CANARY: &str = "canary-inline-private-key-material";
        for (reference, path) in [
            (
                "privateKeyRef: secret:file/gateway-key",
                "/exchange/privateKeyRef",
            ),
            ("hashKeyRef: secret:file/audit-key", "/audit/hashKeyRef"),
        ] {
            let key = reference.split(':').next().expect("key");
            let text = document().replace(reference, &format!("{key}: {CANARY}"));
            let error = load(&text).expect_err("an inline credential is refused");
            assert_eq!(error.diagnostics[0].code, "config.invalid-value");
            assert_eq!(error.diagnostics[0].path, path);
            assert!(!error.to_string().contains(CANARY), "{error}");
        }
        let text = document().replace(
            "    type: uri\n    uri: https://login.example.test/jwks.json",
            &format!("    type: static\n    documentRef: '{{\"keys\":[\"{CANARY}\"]}}'"),
        );
        let error = load(&text).expect_err("an inline key set is refused");
        assert_eq!(
            error.diagnostics[0].code,
            "breg.mcp-runtime.invalid-secret-reference"
        );
        assert_eq!(
            error.diagnostics[0].path,
            "/resourceServer/jwksSource/documentRef"
        );
        assert!(!error.to_string().contains(CANARY), "{error}");
    }

    #[test]
    fn runtime_loader_refuses_environment_expressions_in_secret_references() {
        for (authored, expression, path) in [
            (
                "privateKeyRef: secret:file/gateway-key",
                "privateKeyRef: ${BREG_MCP_TEST_KEY:-secret:file/gateway-key}",
                "/exchange/privateKeyRef",
            ),
            (
                "hashKeyRef: secret:file/audit-key",
                "hashKeyRef: ${BREG_MCP_TEST_AUDIT:-secret:file/audit-key}",
                "/audit/hashKeyRef",
            ),
        ] {
            refused(
                &document().replace(authored, expression),
                "config.substitution-not-allowed",
                path,
            );
        }
    }

    #[test]
    fn an_undeclared_secret_provider_is_refused() {
        refused(
            &document().replace("secret:file/gateway-key", "secret:env/GATEWAY_KEY"),
            "breg.mcp-runtime.undeclared-secret-provider",
            "/exchange/privateKeyRef",
        );
    }

    #[test]
    fn an_omitted_jwks_source_uses_discovery() {
        let text = document().replace(
            "  jwksSource:\n    type: uri\n    uri: https://login.example.test/jwks.json\n",
            "",
        );
        let config = load(&text).expect("discovery is the shared default");
        assert!(matches!(
            config.resource_server.jwks_source,
            JwksSource::Discovery {}
        ));
    }

    #[test]
    fn stdout_refuses_file_only_audit_settings() {
        refused(
            &document().replace("destination: file", "destination: stdout"),
            "breg.mcp-runtime.file-only-audit-member",
            "/audit/path",
        );
    }

    #[test]
    fn a_refused_value_is_not_echoed() {
        const CANARY: &str = "canary-refused-value";
        let text = document().replace("burst: 10", &format!("burst: {CANARY}"));
        let error = load(&text).expect_err("a string burst is refused");
        assert_eq!(error.diagnostics[0].code, "config.expected-integer");
        assert_eq!(error.diagnostics[0].path, "/rateLimits/perCitizen/burst");
        assert!(!error.to_string().contains(CANARY), "{error}");
    }

    #[test]
    fn every_integer_is_bounded() {
        for (from, to, path) in [
            ("burst: 10", "burst: 0", "/rateLimits/perCitizen/burst"),
            (
                "requestsPerMinute: 600",
                "requestsPerMinute: 1000001",
                "/rateLimits/perClient/requestsPerMinute",
            ),
            (
                "  requiredScopes: [address-correction:self]\n",
                "  requiredScopes: [address-correction:self]\n  maximumTokenLifetimeSeconds: 0\n",
                "/resourceServer/maximumTokenLifetimeSeconds",
            ),
            (
                "  scopes: [address-correction:self]\n",
                "  scopes: [address-correction:self]\n  attemptTimeoutMilliseconds: 99\n",
                "/registry/attemptTimeoutMilliseconds",
            ),
            (
                "rateLimits:",
                "limits:\n  maximumRequestBytes: 1048577\nrateLimits:",
                "/limits/maximumRequestBytes",
            ),
        ] {
            let text = document().replacen(from, to, 1);
            assert_ne!(text, document(), "{to}");
            refused(&text, "config.out-of-range", path);
        }
    }

    #[test]
    fn a_restricting_list_is_never_empty() {
        for (from, to, path) in [
            (
                "algorithms: [EdDSA, ES256]",
                "algorithms: []",
                "/resourceServer/algorithms",
            ),
            (
                "allowedClients: [chat-host]",
                "allowedClients: []",
                "/resourceServer/allowedClients",
            ),
            (
                "requiredScopes: [address-correction:self]",
                "requiredScopes: []",
                "/resourceServer/requiredScopes",
            ),
            (
                "  scopes: [address-correction:self]",
                "  scopes: []",
                "/registry/scopes",
            ),
        ] {
            let text = document().replacen(from, to, 1);
            assert_ne!(text, document(), "{to}");
            refused(&text, "config.invalid-length", path);
        }
    }

    #[test]
    fn a_repeated_list_item_is_refused() {
        refused(
            &document().replace("[chat-host]", "[chat-host, chat-host]"),
            "config.duplicate-item",
            "/resourceServer/allowedClients/1",
        );
    }

    #[test]
    fn a_public_listener_is_refused() {
        refused(
            &document().replace("bind: 127.0.0.1:8110", "bind: 203.0.113.9:8110"),
            "breg.mcp-runtime.public-bind",
            "/listener/bind",
        );
        refused(
            &document()
                .replace("bind: 127.0.0.1:8110", "bind: 10.0.0.4:8110")
                .replace("operator-controlled-upstream", "development-loopback"),
            "breg.mcp-runtime.public-bind",
            "/listener/bind",
        );
    }

    #[test]
    fn plain_http_is_accepted_only_on_loopback_in_development() {
        let http = document().replace("https://registry.example.test/", "http://127.0.0.1:8080/");
        refused(
            &http,
            "breg.mcp-runtime.plain-http-endpoint",
            "/registry/baseUrl",
        );
        let development = http.replace("operator-controlled-upstream", "development-loopback");
        load(&development).expect("loopback http is accepted in development");
        let remote = document()
            .replace(
                "https://registry.example.test/",
                "http://registry.example.test/",
            )
            .replace("operator-controlled-upstream", "development-loopback");
        refused(
            &remote,
            "breg.mcp-runtime.plain-http-endpoint",
            "/registry/baseUrl",
        );
        let opted_in = document().replace(
            "  issuer: https://login.example.test",
            "  issuer: http://login.example.test\n  allowInsecureHttp: true",
        );
        let config = load(&opted_in).expect("explicit HTTP issuer opt-in");
        assert!(config.resource_server.allow_insecure_http);
        assert_eq!(
            config.resource_server.insecure_http_startup_diagnostic(),
            Some("resourceServer.allowInsecureHttp permits plain HTTP to the configured issuer and to a JWKS URI declared in configuration")
        );
    }

    #[test]
    fn an_endpoint_carries_no_query_or_fragment() {
        for (from, to, path) in [
            (
                "tokenEndpoint: https://login.example.test/token",
                "tokenEndpoint: https://login.example.test/token?tenant=a",
                "/exchange/tokenEndpoint",
            ),
            (
                "issuer: https://login.example.test",
                "issuer: https://login.example.test/#a",
                "/resourceServer/issuer",
            ),
        ] {
            refused(
                &document().replace(from, to),
                "breg.mcp-runtime.endpoint-query-or-fragment",
                path,
            );
        }
    }

    #[test]
    fn the_resource_must_name_the_mcp_endpoint() {
        refused(
            &document().replace(
                "https://gateway.example.test/mcp",
                "https://gateway.example.test/other",
            ),
            "breg.mcp-runtime.resource-not-mcp-endpoint",
            "/resourceServer/resource",
        );
    }

    #[test]
    fn the_gateway_client_is_never_an_inbound_client() {
        refused(
            &document().replace("[chat-host]", "[chat-host, citizen-gateway]"),
            "breg.mcp-runtime.exchange-client-admitted-inbound",
            "/exchange/clientId",
        );
    }

    /// Scopes are RFC 6749 scope tokens, checked as every platform client
    /// checks them: a byte outside the grammar is refused at load, not at
    /// the first exchange.
    #[test]
    fn a_scope_outside_the_rfc_6749_grammar_is_refused() {
        for (from, to, path) in [
            (
                "requiredScopes: [address-correction:self]",
                "requiredScopes: [address-correction:selfé]",
                "/resourceServer/requiredScopes/0",
            ),
            (
                "requiredScopes: [address-correction:self]",
                r#"requiredScopes: ['address-correction:"self"']"#,
                "/resourceServer/requiredScopes/0",
            ),
            (
                "scopes: [address-correction:self]",
                r"scopes: ['address-correction\self']",
                "/registry/scopes/0",
            ),
        ] {
            let text = document().replacen(from, to, 1);
            assert_ne!(text, document(), "{to}");
            refused(&text, "config.invalid-value", path);
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
            refused(&text, "config.invalid-value", "/registry/audience");
        }
    }

    /// The review page serves `/proposals/<id>` at the root of its
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
            refused(
                &text,
                "breg.mcp-runtime.review-base-url-not-origin",
                "/service/reviewBaseUrl",
            );
        }
    }

    #[test]
    fn the_retired_owner_input_is_unknown() {
        refused(
            &document().replace(
                "    targetInput: address",
                "    targetInput: address\n    ownerInput: owner",
            ),
            "config.unknown-key",
            "/service/application/ownerInput",
        );
    }

    #[test]
    fn the_registry_audience_is_not_the_gateway_resource() {
        refused(
            &document().replace(
                "audience: urn:breg:citizen-address-correction",
                "audience: https://gateway.example.test/mcp",
            ),
            "breg.mcp-runtime.audience-reused",
            "/registry/audience",
        );
    }

    #[test]
    fn service_text_is_never_blank() {
        refused(
            &document().replace("name: Address correction", "name: '   '"),
            "config.invalid-value",
            "/service/name",
        );
    }

    /// Without the environment, an expression is checked by position only:
    /// its value checks, and the rules that compare it, wait for `serve`.
    #[test]
    fn a_deferred_expression_skips_its_value_checks() {
        let text = document()
            .replace("bind: 127.0.0.1:8110", "bind: ${BREG_MCP_TEST_UNSET_BIND}")
            .replace(
                "clientId: citizen-gateway",
                "clientId: ${BREG_MCP_TEST_UNSET_CLIENT}",
            )
            .replace(
                "[chat-host]",
                "[chat-host, '${BREG_MCP_TEST_UNSET_CLIENT}']",
            );
        let (_directory, path) = written(&text);
        let check = check_runtime(&path, false);
        assert!(check.diagnostics.is_empty(), "{:?}", check.diagnostics);
    }

    /// Two items of a list that must not repeat an item, each written as its
    /// own expression, are two items: the check does not read one placeholder
    /// into both and then refuse the list as a repeat.
    #[test]
    fn distinct_deferred_items_of_one_list_are_not_a_repeat() {
        for (from, to) in [
            (
                "algorithms: [EdDSA, ES256]",
                "algorithms: ['${BREG_MCP_TEST_UNSET_FIRST}', '${BREG_MCP_TEST_UNSET_SECOND}']",
            ),
            (
                "allowedClients: [chat-host]",
                "allowedClients: ['${BREG_MCP_TEST_UNSET_FIRST}', '${BREG_MCP_TEST_UNSET_SECOND}']",
            ),
            (
                "requiredScopes: [address-correction:self]",
                "requiredScopes: ['${BREG_MCP_TEST_UNSET_FIRST}', '${BREG_MCP_TEST_UNSET_SECOND}']",
            ),
            (
                "  scopes: [address-correction:self]",
                "  scopes: ['${BREG_MCP_TEST_UNSET_FIRST}', '${BREG_MCP_TEST_UNSET_SECOND}']",
            ),
        ] {
            let text = document().replacen(from, to, 1);
            assert_ne!(text, document(), "{to}");
            let (_directory, path) = written(&text);
            let check = check_runtime(&path, false);
            assert!(
                check.diagnostics.is_empty(),
                "{to}: {:?}",
                check.diagnostics
            );
        }
    }

    /// A member the check cannot fill stops the read, and the check says so:
    /// it never answers with nothing about a document it did not decode.
    #[test]
    fn a_deferred_expression_that_stops_the_read_is_reported() {
        let text = document().replace("type: uri", "type: ${BREG_MCP_TEST_UNSET_KIND}");
        assert_ne!(text, document());
        let (_directory, path) = written(&text);
        let check = check_runtime(&path, false);
        let found: Vec<_> = check
            .diagnostics
            .iter()
            .map(|diagnostic| {
                (
                    diagnostic.code.as_str(),
                    diagnostic.path.as_str(),
                    diagnostic.severity,
                )
            })
            .collect();
        assert_eq!(
            found,
            [(
                registry_platform_config::INCOMPLETE_CODE,
                "/resourceServer/jwksSource/type",
                registry_platform_yaml::Severity::Warning
            )]
        );
    }
}
