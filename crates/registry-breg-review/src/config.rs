// SPDX-License-Identifier: Apache-2.0

//! The operator runtime configuration document.
//!
//! The file is read through the shared Registry Stack runtime configuration
//! loader, so its envelope, size bound, path rules, `${VAR}` substitution,
//! and secret provider declarations match every other runtime. Every
//! credential is a `secret:env/` or `secret:file/` reference, never inline
//! text.

use std::{
    fmt,
    hash::Hash,
    path::{Path, PathBuf},
};

use registry_platform_audit::{
    AuditDestination, AuditDestinationError, AuditDestinationKind, MAX_AUDIT_RETAIN_DAYS,
    MIN_AUDIT_ROTATE_BYTES,
};
pub(crate) use registry_platform_config::describe_secret_failure;
use registry_platform_config::{
    AuditKeyConfig, ConfigBlockError, ConfigBlockErrorKind, LoadedRuntimeConfig,
    PrivateListenerConfig, RemovedKey, RuntimeConfigLoader, RuntimeEnvelope, SecretProvidersConfig,
    SecretReference, TlsTermination,
};
use registry_platform_httputil::{valid_resource_uri, valid_scope_token};
use registry_platform_yaml::{
    escape_pointer_segment, BoundedU32, BoundedU64, Diagnostic, ExternalId, Invalid, LocalId,
    Report, RetiredApiVersion, UniqueList, Url,
};
use serde::{de, Deserialize, Deserializer};
use url::Host;

/// apiVersion of the review page runtime configuration document.
pub const RUNTIME_API_VERSION: &str = "id.registrystack.org/formats/breg/review-runtime/v1alpha1";
/// Kind of the review page runtime configuration document.
pub const RUNTIME_KIND: &str = "BRegReviewRuntimeConfig";

/// The path the authorization server returns a person to after sign-in,
/// relative to `publicOrigin`.
pub const CALLBACK_PATH: &str = "/signin/callback";

/// The most scopes the page requests beside `openid`.
const MAXIMUM_SCOPES: usize = 16;
/// The longest scope token or registry resource, in bytes.
const MAXIMUM_TOKEN_BYTES: usize = 512;
/// The most requests a rate limit may admit per minute or in one burst.
const MAXIMUM_RATE: u32 = 1_000_000;
/// The most sessions, or sign-ins in progress, the page may hold.
const MAXIMUM_STORE_ENTRIES: u32 = 1_000_000;
/// The shortest and longest session: one minute to one day.
const MINIMUM_SESSION_SECONDS: u64 = 60;
const MAXIMUM_SESSION_SECONDS: u64 = 86_400;
/// The shortest and longest wait for a started sign-in: one minute to one
/// hour.
const MINIMUM_SIGN_IN_SECONDS: u64 = 60;
const MAXIMUM_SIGN_IN_SECONDS: u64 = 3600;
/// The largest `audit.rotateBytes` the shared audit writer accepts.
const MAXIMUM_AUDIT_ROTATE_BYTES: u64 = u32::MAX as u64;

const RUNTIME_ENVELOPE: RuntimeEnvelope = RuntimeEnvelope {
    api_version: RUNTIME_API_VERSION,
    kind: RUNTIME_KIND,
};

/// The apiVersion a runtime file carried before its members took their
/// shared names, refused with the renames it needs.
const RETIRED_RUNTIME_API_VERSIONS: &[RetiredApiVersion<'static>] = &[RetiredApiVersion {
    api_version: "registry.registrystack.org/breg-review-runtime/v1alpha1",
    replacement: "Write apiVersion id.registrystack.org/formats/breg/review-runtime/v1alpha1, \
                  then rename limits to rateLimits and audit.retainDays to audit.retentionDays.",
}];

/// Keys an earlier runtime file carried, each refused with its replacement.
const REMOVED_KEYS: &[RemovedKey] = &[
    RemovedKey {
        path: "limits",
        replacement: "declare rateLimits instead, with the same perCitizen and globalSignIn \
                      members",
    },
    RemovedKey {
        path: "audit.retainDays",
        replacement: "declare audit.retentionDays instead",
    },
];

/// The operator runtime configuration document.
#[derive(Clone, Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeConfig {
    pub api_version: String,
    pub kind: String,
    pub listener: PrivateListenerConfig,
    /// The browser-facing origin, such as `https://review.example`: an https
    /// URL with no path, query, or fragment; plain http is accepted only on
    /// a loopback host under `development-loopback`. The sign-in redirect
    /// URI is this origin with `/signin/callback`.
    pub public_origin: Url,
    pub secret_providers: SecretProvidersConfig,
    pub sign_in: SignInConfig,
    pub registry: RegistryConfig,
    pub audit: AuditConfig,
    #[serde(default)]
    pub rate_limits: RateLimitsConfig,
    #[serde(default)]
    pub session: SessionConfig,
}

/// The OpenID Provider the page signs people in with, and the confidential
/// client it authenticates as.
#[derive(Clone, Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignInConfig {
    /// The provider's issuer. An https URL with no query or fragment; plain
    /// http is accepted only on a loopback host under `development-loopback`.
    pub issuer: Url,
    /// The page's client identifier at the provider.
    pub client_id: ExternalId,
    /// Secret reference to the client's private JWK, used for
    /// `private_key_jwt` client authentication, under a declared provider.
    pub client_key_ref: SecretReference,
    /// Scopes requested beside `openid`, such as the review scope the
    /// registry profile requires. The page always requests `openid`, so the
    /// list does not name it.
    #[serde(deserialize_with = "scope_list")]
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 16)))]
    pub scopes: UniqueList<ScopeToken>,
}

/// The Base Registry Engine deployment and the one access profile the page
/// reads and submits through.
#[derive(Clone, Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistryConfig {
    /// The registry deployment's base URL. An https URL with no query or
    /// fragment; plain http is accepted only on a loopback host under
    /// `development-loopback`.
    pub base_url: Url,
    /// The RFC 8707 resource indicator the person's access token names.
    pub resource: ResourceUri,
    /// The change-request entity identifier.
    pub entity: LocalId,
    /// The reference field naming the record the request changes. The page
    /// reads that record under the person's own token before it offers the
    /// submit form, because the registry does not tie a request's target to
    /// its requester.
    pub target_field: LocalId,
    /// The registry access profile every read and submit names.
    pub access_profile: LocalId,
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
    /// The absolute path of the active audit file, for a `file` destination.
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(with = "PathBuf"))]
    pub path: Option<PathBuf>,
    /// Size at which the active file rotates, in bytes, for a `file`
    /// destination. Default: 100 MiB.
    #[serde(default)]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "BoundedU64<MIN_AUDIT_ROTATE_BYTES, MAXIMUM_AUDIT_ROTATE_BYTES>")
    )]
    pub rotate_bytes: Option<BoundedU64<MIN_AUDIT_ROTATE_BYTES, MAXIMUM_AUDIT_ROTATE_BYTES>>,
    /// Days a rotated file is kept, for a `file` destination. Default: 90.
    #[serde(default)]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "BoundedU32<1, MAX_AUDIT_RETAIN_DAYS>")
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

/// The page's own request limits. It reads neither peer addresses nor
/// forwarded headers, so it cannot tell one browser from another before
/// sign-in: a per-client limit belongs at the edge proxy.
#[derive(Clone, Copy, Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RateLimitsConfig {
    /// One limit for each signed-in person, shared by all their sessions,
    /// on every request that presents a session. Default: 120 a minute,
    /// burst 30.
    #[serde(default = "default_per_citizen")]
    pub per_citizen: RateLimitConfig,
    /// One limit shared by everyone on the unauthenticated sign-in routes,
    /// `/signin` and `/signin/callback`. Default: 600 a minute, burst 120.
    #[serde(default = "default_global_sign_in")]
    pub global_sign_in: RateLimitConfig,
}

impl Default for RateLimitsConfig {
    fn default() -> Self {
        Self {
            per_citizen: default_per_citizen(),
            global_sign_in: default_global_sign_in(),
        }
    }
}

fn rate(requests_per_minute: u32, burst: u32) -> RateLimitConfig {
    RateLimitConfig {
        requests_per_minute: BoundedU32::new(requests_per_minute)
            .expect("a default rate is within its bounds"),
        burst: BoundedU32::new(burst).expect("a default burst is within its bounds"),
    }
}

fn default_per_citizen() -> RateLimitConfig {
    rate(120, 30)
}

fn default_global_sign_in() -> RateLimitConfig {
    rate(600, 120)
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionConfig {
    /// The most signed-in sessions the page holds at once. Default: 10000.
    #[serde(default = "default_store_entries")]
    pub maximum_sessions: BoundedU32<1, MAXIMUM_STORE_ENTRIES>,
    /// The most sign-ins in progress the page holds at once. It must hold
    /// every sign-in `rateLimits.globalSignIn` admits within
    /// `signInLifetimeSeconds`. Default: 10000.
    #[serde(default = "default_store_entries")]
    pub maximum_pending_sign_ins: BoundedU32<1, MAXIMUM_STORE_ENTRIES>,
    /// The longest a session lasts. A session also ends when the access
    /// token it holds expires, whichever comes first. Default: 3600.
    #[serde(default = "default_maximum_lifetime")]
    pub maximum_lifetime_seconds: BoundedU64<MINIMUM_SESSION_SECONDS, MAXIMUM_SESSION_SECONDS>,
    /// How long a started sign-in may take to return from the provider.
    /// Default: 600.
    #[serde(default = "default_sign_in_lifetime")]
    pub sign_in_lifetime_seconds: BoundedU64<MINIMUM_SIGN_IN_SECONDS, MAXIMUM_SIGN_IN_SECONDS>,
}

impl SessionConfig {
    /// `maximumSessions` as a count. The bound fits `usize` on every target
    /// the workspace builds for.
    #[must_use]
    pub fn sessions(&self) -> usize {
        usize::try_from(self.maximum_sessions.get()).expect("the session bound fits usize")
    }

    /// `maximumPendingSignIns` as a count.
    #[must_use]
    pub fn pending_sign_ins(&self) -> usize {
        usize::try_from(self.maximum_pending_sign_ins.get())
            .expect("the pending sign-in bound fits usize")
    }
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            maximum_sessions: default_store_entries(),
            maximum_pending_sign_ins: default_store_entries(),
            maximum_lifetime_seconds: default_maximum_lifetime(),
            sign_in_lifetime_seconds: default_sign_in_lifetime(),
        }
    }
}

fn default_store_entries() -> BoundedU32<1, MAXIMUM_STORE_ENTRIES> {
    BoundedU32::new(10_000).expect("the default store size is within its bounds")
}

fn default_maximum_lifetime() -> BoundedU64<MINIMUM_SESSION_SECONDS, MAXIMUM_SESSION_SECONDS> {
    BoundedU64::new(3600).expect("the default session lifetime is within its bounds")
}

fn default_sign_in_lifetime() -> BoundedU64<MINIMUM_SIGN_IN_SECONDS, MAXIMUM_SIGN_IN_SECONDS> {
    BoundedU64::new(600).expect("the default sign-in lifetime is within its bounds")
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
                Self::new(text).map_err(de::Error::custom)
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
        "an RFC 6749 scope token of 1 to 512 printable ASCII characters, without spaces, quotes, \
         or backslashes",
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
        "Write the registry's token audience as an absolute URI, such as a urn: name or an \
         https URL, without a fragment or credentials."
    )
);

/// A set of 1 to 16 scopes: the page always names the scope its access
/// profile requires, so an empty list is refused rather than read as "none".
fn scope_list<'de, D>(deserializer: D) -> Result<UniqueList<ScopeToken>, D::Error>
where
    D: Deserializer<'de>,
{
    bounded(deserializer, MAXIMUM_SCOPES, &"1 to 16 items")
}

fn bounded<'de, D, T>(
    deserializer: D,
    maximum: usize,
    expected: &dyn de::Expected,
) -> Result<UniqueList<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Eq + Hash,
{
    let list = UniqueList::<T>::deserialize(deserializer)?;
    if list.is_empty() || list.len() > maximum {
        return Err(de::Error::invalid_length(list.len(), expected));
    }
    Ok(list)
}

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

    /// The loader for the review page runtime file, with its removed keys
    /// and its retired apiVersion.
    #[must_use]
    pub const fn loader() -> RuntimeConfigLoader {
        RuntimeConfigLoader::new(RUNTIME_ENVELOPE)
            .removed_keys(REMOVED_KEYS)
            .retired_api_versions(RETIRED_RUNTIME_API_VERSIONS)
    }

    /// Whether the document declares the loopback-only development mode.
    #[must_use]
    pub fn development(&self) -> bool {
        self.listener.tls_termination == TlsTermination::DevelopmentLoopback
    }

    /// The browser-facing origin, without a trailing slash.
    #[must_use]
    pub fn origin(&self) -> String {
        self.public_origin.as_str().trim_end_matches('/').to_owned()
    }

    /// The exact redirect URI registered with the provider.
    #[must_use]
    pub fn redirect_uri(&self) -> url::Url {
        self.public_origin
            .to_url()
            .join(CALLBACK_PATH)
            .expect("an absolute path joins onto an http or https origin")
    }
}

/// Check the runtime file at the absolute `path` as `breg-review serve`
/// reads it, with no secret material, network, or listener (CFG-CHECK-1).
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
/// the endpoints, the scopes, the session store, and the audit destination.
/// The configuration is returned only when nothing was found.
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

/// Every refusal of a decoded file.
fn findings(config: &RuntimeConfig, defers: &dyn Fn(&str) -> bool) -> Vec<Finding> {
    let mut findings = Vec::new();
    if !config.listener.is_valid() {
        findings.push(Finding::new(
            "breg.review-runtime.public-bind",
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
            "signIn.clientKeyRef",
            config.sign_in.client_key_ref.as_str(),
        ),
    ];
    findings.extend(
        blocks
            .iter()
            .filter_map(|result| result.as_ref().err())
            .map(block_finding),
    );
    endpoint_findings(config, defers, &mut findings);
    for (index, scope) in config.sign_in.scopes.iter().enumerate() {
        if scope.as_str() == "openid" {
            findings.push(Finding::new(
                "breg.review-runtime.openid-scope",
                &format!("/signIn/scopes/{index}"),
                "signIn.scopes names openid, which the page requests on every sign-in",
                "Remove openid from signIn.scopes and keep the scopes the registry access \
                 profile requires.",
            ));
        }
    }
    // Every sign-in the global limit admits stays pending for up to its
    // lifetime, so the store must hold them all. A store the limit could
    // fill would keep refusing sign-ins long after the limit refilled.
    let global = config.rate_limits.global_sign_in;
    let admitted = u64::from(global.burst.get())
        + (u64::from(global.requests_per_minute.get())
            * config.session.sign_in_lifetime_seconds.get())
        .div_ceil(60);
    if u64::from(config.session.maximum_pending_sign_ins.get()) < admitted {
        findings.push(Finding::new(
            "breg.review-runtime.pending-sign-ins-fillable",
            "/session/maximumPendingSignIns",
            "session.maximumPendingSignIns cannot hold every sign-in rateLimits.globalSignIn \
             admits within session.signInLifetimeSeconds",
            "Raise session.maximumPendingSignIns to at least rateLimits.globalSignIn.burst plus \
             requestsPerMinute times session.signInLifetimeSeconds divided by 60, or lower the \
             sign-in limit.",
        ));
    }
    if let Err(error) = config.audit.destination() {
        findings.push(audit_finding(&error));
    }
    findings
}

/// Every endpoint the page serves or calls is https with no query or
/// fragment, or plain http on a loopback host under `development-loopback`.
/// The public origin also has no path.
fn endpoint_findings(
    config: &RuntimeConfig,
    defers: &dyn Fn(&str) -> bool,
    findings: &mut Vec<Finding>,
) {
    let termination_known = !defers("/listener/tlsTermination");
    let development = config.development();
    let endpoints = [
        ("/publicOrigin", &config.public_origin),
        ("/signIn/issuer", &config.sign_in.issuer),
        ("/registry/baseUrl", &config.registry.base_url),
    ];
    for (pointer, endpoint) in endpoints {
        let url = endpoint.to_url();
        let secure = url.scheme() == "https" || (development && loopback_host(&url));
        if termination_known && !secure {
            findings.push(Finding::new(
                "breg.review-runtime.plain-http-endpoint",
                pointer,
                "the endpoint uses plain http, which is accepted only on a loopback host under \
                 listener.tlsTermination development-loopback",
                "Write an https URL, or run on loopback with listener.tlsTermination \
                 development-loopback.",
            ));
        } else if url.query().is_some() || url.fragment().is_some() {
            findings.push(Finding::new(
                "breg.review-runtime.endpoint-query-or-fragment",
                pointer,
                "the endpoint carries a query or a fragment",
                "Remove the query and the fragment from the URL.",
            ));
        }
    }
    // The page serves its routes and its callback at the root of its origin.
    if config.public_origin.to_url().path() != "/" {
        findings.push(Finding::new(
            "breg.review-runtime.public-origin-not-origin",
            "/publicOrigin",
            "publicOrigin has a path, but the page serves its routes and its sign-in callback at \
             the root of its origin",
            "Write the scheme, host, and port the browser reaches the page at, with no path.",
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

/// Whether `url`, read from the provider's discovery document, is an
/// endpoint the runtime may call for this mode: https, or plain http on a
/// loopback host in development, with no user information or fragment.
pub(crate) fn allowed_discovered_endpoint(url: &url::Url, development: bool) -> bool {
    let secure = match url.scheme() {
        "https" => true,
        "http" => development && loopback_host(url),
        _ => false,
    };
    secure
        && url.username().is_empty()
        && url.password().is_none()
        && url.host().is_some()
        && url.fragment().is_none()
}

/// A value that satisfies the member at `pointer`, so a deferred expression
/// never decides whether its neighbours decode.
fn stand_in_for(pointer: &str) -> &'static str {
    match pointer {
        "/listener/bind" => "127.0.0.1:8080",
        "/listener/tlsTermination" => "operator-controlled-upstream",
        "/listener/networkExposure" => "private-address",
        "/publicOrigin" | "/signIn/issuer" | "/registry/baseUrl" => "https://deferred.invalid",
        "/registry/resource" => "urn:deferred",
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

/// The code and fix for a shared block refusal.
fn block_finding(error: &ConfigBlockError) -> Finding {
    let (code, action) = match error.kind() {
        ConfigBlockErrorKind::RelativePath => (
            "breg.review-runtime.relative-path",
            "Write the path as an absolute path with no `.` or `..` segment.",
        ),
        ConfigBlockErrorKind::NoSecretProvider => (
            "breg.review-runtime.no-secret-provider",
            "Declare secretProviders.file with an absolute root, \
             secretProviders.environment: {}, or both.",
        ),
        ConfigBlockErrorKind::InvalidSecretReference => (
            "breg.review-runtime.invalid-secret-reference",
            "Write the reference as secret:file/<name> or secret:env/<NAME>.",
        ),
        ConfigBlockErrorKind::SecretProviderDisabled => (
            "breg.review-runtime.undeclared-secret-provider",
            "Declare the provider the message names under secretProviders, or reference a \
             declared one.",
        ),
        _ => (
            "breg.review-runtime.invalid-block",
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
            "breg.review-runtime.missing-audit-path",
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
                "breg.review-runtime.file-only-audit-member",
                &format!("/audit/{member}"),
                format!("audit.{member} applies only when audit.destination is file"),
                "Remove the member, or set audit.destination to file.",
            )
        }
        AuditDestinationError::RelativePath
        | AuditDestinationError::InvalidPathComponent
        | AuditDestinationError::NoFileName
        | AuditDestinationError::FileNameTooLong { .. } => finding(
            "breg.review-runtime.invalid-audit-path",
            "/audit/path",
            error.to_string(),
            "Write audit.path as an absolute file path with no `.` or `..` segment, ending in \
             a file name.",
        ),
        AuditDestinationError::PathNamesReservedCompanion {
            suffix, companion, ..
        } => finding(
            "breg.review-runtime.invalid-audit-path",
            "/audit/path",
            format!(
                "audit.path ends in `{suffix}`, which names the {companion} of another audit \
                 stream"
            ),
            "Choose an audit file name without that ending.",
        ),
        AuditDestinationError::RetainDaysOutOfRange { maximum } => finding(
            "breg.review-runtime.invalid-audit",
            "/audit/retentionDays",
            format!("audit.retentionDays must be between 1 and {maximum}"),
            "Write a number of days within the bounds.",
        ),
        _ => finding(
            "breg.review-runtime.invalid-audit",
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

    use super::{ResourceUri, ScopeToken};

    impl JsonSchema for ScopeToken {
        fn schema_name() -> Cow<'static, str> {
            Cow::Borrowed("ScopeToken")
        }

        fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
            json_schema!({
                "type": "string",
                "minLength": 1,
                "maxLength": 512,
                "pattern": "^[!#-\\[\\]-~]+$",
                "description": "An RFC 6749 scope token: printable ASCII other than space, `\"`, and `\\`.",
            })
        }
    }

    impl JsonSchema for ResourceUri {
        fn schema_name() -> Cow<'static, str> {
            Cow::Borrowed("ResourceUri")
        }

        fn json_schema(_generator: &mut SchemaGenerator) -> Schema {
            json_schema!({
                "type": "string",
                "minLength": 1,
                "maxLength": 512,
                "pattern": "^[A-Za-z][A-Za-z0-9+.-]*:(?:[A-Za-z0-9._~:/?\\[\\]@!$&'()*+,;=-]|%[0-9A-Fa-f]{2})*$",
                "description": "An RFC 8707 resource indicator: an absolute URI without a fragment. The reader also refuses user information and a URI it cannot parse.",
            })
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::fs;

    use super::*;

    pub(crate) fn document() -> String {
        r#"apiVersion: id.registrystack.org/formats/breg/review-runtime/v1alpha1
kind: BRegReviewRuntimeConfig
listener:
  bind: 10.0.0.5:8115
  tlsTermination: operator-controlled-upstream
publicOrigin: https://review.example
secretProviders:
  file:
    root: /run/secrets
  environment: {}
signIn:
  issuer: https://id.example
  clientId: citizen-review-page
  clientKeyRef: secret:file/client-key.jwk
  scopes: [address-correction:self]
registry:
  baseUrl: https://registry.example/base
  resource: https://registry.example/base
  entity: address-correction-request
  targetField: address
  accessProfile: citizen-review
audit:
  hashKeyRef: secret:env/BREG_REVIEW_AUDIT_KEY
  path: /var/lib/breg-review/audit.jsonl
"#
        .to_owned()
    }

    /// The development variant of [`document`]: loopback endpoints under
    /// `development-loopback`.
    fn development() -> String {
        document()
            .replace("10.0.0.5:8115", "127.0.0.1:8115")
            .replace("operator-controlled-upstream", "development-loopback")
            .replace("https://review.example", "http://127.0.0.1:8115")
            .replace(
                "issuer: https://id.example",
                "issuer: http://127.0.0.1:9000",
            )
            .replace(
                "baseUrl: https://registry.example/base",
                "baseUrl: http://127.0.0.1:9100/base",
            )
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
    fn a_production_document_loads_with_its_defaults() {
        let config = load(&document()).expect("valid document");
        assert!(!config.development());
        assert_eq!(
            config.redirect_uri().as_str(),
            "https://review.example/signin/callback"
        );
        assert_eq!(config.origin(), "https://review.example");
        assert_eq!(config.session.sessions(), 10_000);
        assert_eq!(config.session.pending_sign_ins(), 10_000);
        assert_eq!(config.session.maximum_lifetime_seconds.get(), 3600);
        assert_eq!(config.session.sign_in_lifetime_seconds.get(), 600);
        assert_eq!(
            config.rate_limits.per_citizen.requests_per_minute.get(),
            120
        );
        assert_eq!(config.rate_limits.global_sign_in.burst.get(), 120);
        assert_eq!(config.registry.target_field.as_str(), "address");
    }

    #[test]
    fn the_committed_example_loads() {
        let example = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../products/breg/examples/review-runtime/runtime.yaml")
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
            "id.registrystack.org/formats/breg/review-runtime/v1alpha1",
            "registry.registrystack.org/breg-review-runtime/v1alpha1",
        );
        let error = load(&text).expect_err("the retired apiVersion is refused");
        let diagnostic = &error.diagnostics[0];
        assert_eq!(diagnostic.code, "config.retired-api-version");
        assert!(
            diagnostic.suggested_action.contains("rateLimits"),
            "{}",
            diagnostic.suggested_action
        );
    }

    #[test]
    fn each_removed_key_is_refused_with_its_replacement() {
        for (text, path) in [
            (
                format!(
                    "{}limits:\n  globalSignIn: {{ requestsPerMinute: 600, burst: 120 }}\n",
                    document()
                ),
                "/limits",
            ),
            (
                document().replace(
                    "  path: /var/lib/breg-review/audit.jsonl\n",
                    "  path: /var/lib/breg-review/audit.jsonl\n  retainDays: 30\n",
                ),
                "/audit/retainDays",
            ),
        ] {
            assert_ne!(text, document(), "{path}");
            let found = findings_of(&text);
            assert!(
                found.contains(&("config.removed-key".to_owned(), path.to_owned())),
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
                "  hashKeyRef: secret:env/BREG_REVIEW_AUDIT_KEY\n",
                "  hashKeyRef: secret:env/BREG_REVIEW_AUDIT_KEY\n  auditTypo: x\n",
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
    fn a_per_address_limit_is_not_accepted() {
        let text = format!(
            "{}rateLimits:\n  perAddress: {{ requestsPerMinute: 600, burst: 120 }}\n",
            document()
        );
        refused(&text, "config.unknown-key", "/rateLimits/perAddress");
    }

    #[test]
    fn the_global_sign_in_cap_cannot_fill_the_pending_store() {
        // 600 starts a minute over a 600-second sign-in lifetime, plus the
        // burst, is 6120 sign-ins in flight at most.
        let with = |pending: u32| {
            format!(
                "{}rateLimits:\n  globalSignIn: {{ requestsPerMinute: 600, burst: 120 }}\n\
                 session:\n  maximumPendingSignIns: {pending}\n  signInLifetimeSeconds: 600\n",
                document()
            )
        };
        refused(
            &with(6119),
            "breg.review-runtime.pending-sign-ins-fillable",
            "/session/maximumPendingSignIns",
        );
        let error = load(&with(6119)).expect_err("a store the cap can fill");
        assert!(!error.to_string().contains("6119"), "{error}");
        load(&with(6120)).expect("a store the cap cannot fill");
    }

    #[test]
    fn an_inline_credential_is_refused_without_echoing_it() {
        const CANARY: &str = "inline-canary-value";
        for (reference, path) in [
            (
                "clientKeyRef: secret:file/client-key.jwk",
                "/signIn/clientKeyRef",
            ),
            (
                "hashKeyRef: secret:env/BREG_REVIEW_AUDIT_KEY",
                "/audit/hashKeyRef",
            ),
        ] {
            let key = reference.split(':').next().expect("key");
            let text = document().replace(
                reference,
                &format!("{key}: '{{\"kty\":\"OKP\",\"d\":\"{CANARY}\"}}'"),
            );
            let error = load(&text).expect_err("an inline credential is refused");
            assert_eq!(error.diagnostics[0].code, "config.invalid-value");
            assert_eq!(error.diagnostics[0].path, path);
            assert!(!error.to_string().contains(CANARY), "{error}");
        }
    }

    #[test]
    fn runtime_loader_refuses_environment_expressions_in_secret_references() {
        for (authored, expression, path) in [
            (
                "clientKeyRef: secret:file/client-key.jwk",
                "clientKeyRef: '${CLIENT_KEY_REF}'",
                "/signIn/clientKeyRef",
            ),
            (
                "root: /run/secrets",
                "root: ${SECRET_ROOT}",
                "/secretProviders/file/root",
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
            &document().replace("  environment: {}\n", ""),
            "breg.review-runtime.undeclared-secret-provider",
            "/audit/hashKeyRef",
        );
    }

    /// Without the environment, an expression is checked by position only:
    /// its value checks wait for `serve`.
    #[test]
    fn a_deferred_expression_skips_its_value_checks() {
        let text = document()
            .replace(
                "publicOrigin: https://review.example",
                "publicOrigin: ${BREG_REVIEW_TEST_UNSET_ORIGIN}",
            )
            .replace(
                "bind: 10.0.0.5:8115",
                "bind: ${BREG_REVIEW_TEST_UNSET_BIND}",
            )
            .replace(
                "scopes: [address-correction:self]",
                "scopes: ['${BREG_REVIEW_TEST_UNSET_SCOPE}']",
            );
        let (_directory, path) = written(&text);
        let check = check_runtime(&path, false);
        assert!(check.diagnostics.is_empty(), "{:?}", check.diagnostics);
    }

    #[test]
    fn a_refused_value_is_not_echoed() {
        const CANARY: &str = "x-canary";
        let text = document().replace(
            "clientId: citizen-review-page",
            &format!("clientId: [{CANARY}]"),
        );
        let error = load(&text).expect_err("a sequence where a string belongs");
        assert_eq!(error.diagnostics[0].path, "/signIn/clientId");
        assert!(!error.to_string().contains(CANARY), "{error}");
    }

    #[test]
    fn every_integer_is_bounded() {
        for (extra, path) in [
            (
                "rateLimits:\n  perCitizen: { requestsPerMinute: 0, burst: 1 }\n",
                "/rateLimits/perCitizen/requestsPerMinute",
            ),
            (
                "rateLimits:\n  globalSignIn: { requestsPerMinute: 1, burst: 1000001 }\n",
                "/rateLimits/globalSignIn/burst",
            ),
            (
                "session:\n  maximumSessions: 0\n",
                "/session/maximumSessions",
            ),
            (
                "session:\n  maximumPendingSignIns: 1000001\n",
                "/session/maximumPendingSignIns",
            ),
            (
                "session:\n  maximumLifetimeSeconds: 59\n",
                "/session/maximumLifetimeSeconds",
            ),
            (
                "session:\n  signInLifetimeSeconds: 3601\n",
                "/session/signInLifetimeSeconds",
            ),
            (
                "session:\n  maximumLifetimeSeconds: 86401\n",
                "/session/maximumLifetimeSeconds",
            ),
        ] {
            refused(
                &format!("{}{extra}", document()),
                "config.out-of-range",
                path,
            );
        }
    }

    #[test]
    fn plaintext_endpoints_are_development_loopback_only() {
        for (from, to, path) in [
            (
                "publicOrigin: https://review.example",
                "publicOrigin: http://review.example",
                "/publicOrigin",
            ),
            (
                "issuer: https://id.example",
                "issuer: http://id.example",
                "/signIn/issuer",
            ),
            (
                "baseUrl: https://registry.example/base",
                "baseUrl: http://registry.example/base",
                "/registry/baseUrl",
            ),
        ] {
            refused(
                &document().replace(from, to),
                "breg.review-runtime.plain-http-endpoint",
                path,
            );
        }
        assert!(load(&development()).expect("development").development());
        refused(
            &development().replace("http://127.0.0.1:9000", "http://id.example"),
            "breg.review-runtime.plain-http-endpoint",
            "/signIn/issuer",
        );
        refused(
            &development().replace("bind: 127.0.0.1:8115", "bind: 0.0.0.0:8115"),
            "breg.review-runtime.public-bind",
            "/listener/bind",
        );
    }

    #[test]
    fn the_shared_listener_requires_an_explicit_bind() {
        let omitted = development().replace("  bind: 127.0.0.1:8115\n", "");
        assert_ne!(omitted, development());
        let found = findings_of(&omitted);
        assert!(
            found.contains(&("config.missing-key".to_owned(), "/listener".to_owned())),
            "{found:?}"
        );
    }

    #[test]
    fn the_shared_listener_preserves_ipv6_exposure_rules() {
        let production_ula = document().replace("bind: 10.0.0.5:8115", "bind: \"[fd00::15]:8115\"");
        load(&production_ula).expect("a private production IPv6 address");

        let development = development()
            .replace("bind: 127.0.0.1:8115", "bind: \"[::1]:8115\"")
            .replace("http://127.0.0.1:8115", "http://[::1]:8115")
            .replace("http://127.0.0.1:9000", "http://[::1]:9000")
            .replace("http://127.0.0.1:9100/base", "http://[::1]:9100/base");
        load(&development).expect("IPv6 loopback development");
        refused(
            &development.replace("bind: \"[::1]:8115\"", "bind: \"[::]:8115\""),
            "breg.review-runtime.public-bind",
            "/listener/bind",
        );
    }

    #[test]
    fn the_public_origin_is_an_origin_only() {
        let root = document().replace(
            "publicOrigin: https://review.example",
            "publicOrigin: https://review.example/",
        );
        let config = load(&root).expect("a trailing slash is the root path");
        assert_eq!(config.origin(), "https://review.example");
        for (origin, code) in [
            (
                "https://review.example/path",
                "breg.review-runtime.public-origin-not-origin",
            ),
            (
                "https://review.example/?q=1",
                "breg.review-runtime.endpoint-query-or-fragment",
            ),
        ] {
            refused(
                &document().replace(
                    "publicOrigin: https://review.example",
                    &format!("publicOrigin: {origin}"),
                ),
                code,
                "/publicOrigin",
            );
        }
        refused(
            &document().replace(
                "publicOrigin: https://review.example",
                "publicOrigin: https://user@review.example",
            ),
            "config.invalid-value",
            "/publicOrigin",
        );
    }

    #[test]
    fn registry_identifiers_are_local_identifiers() {
        for (from, to, path) in [
            (
                "targetField: address",
                "targetField: ''",
                "/registry/targetField",
            ),
            (
                "targetField: address",
                "targetField: Address",
                "/registry/targetField",
            ),
            (
                "targetField: address",
                "targetField: new address",
                "/registry/targetField",
            ),
            (
                "targetField: address",
                "targetField: \"../address\"",
                "/registry/targetField",
            ),
            (
                "entity: address-correction-request",
                "entity: address.correction",
                "/registry/entity",
            ),
            (
                "accessProfile: citizen-review",
                "accessProfile: Citizen",
                "/registry/accessProfile",
            ),
        ] {
            refused(&document().replace(from, to), "config.invalid-value", path);
        }
        let missing = document().replace("  targetField: address\n", "");
        let found = findings_of(&missing);
        assert!(
            found.contains(&("config.missing-key".to_owned(), "/registry".to_owned())),
            "{found:?}"
        );
    }

    #[test]
    fn scopes_are_unique_bounded_and_exclude_openid() {
        let scopes = |list: &str| {
            document().replace(
                "scopes: [address-correction:self]",
                &format!("scopes: {list}"),
            )
        };
        refused(&scopes("[]"), "config.invalid-length", "/signIn/scopes");
        let seventeen = (0..17)
            .map(|index| format!("s{index}"))
            .collect::<Vec<_>>()
            .join(", ");
        refused(
            &scopes(&format!("[{seventeen}]")),
            "config.invalid-length",
            "/signIn/scopes",
        );
        refused(
            &scopes("[a, a]"),
            "config.duplicate-item",
            "/signIn/scopes/1",
        );
        refused(
            &scopes("[\"a b\"]"),
            "config.invalid-value",
            "/signIn/scopes/0",
        );
        refused(
            &scopes("[a, openid]"),
            "breg.review-runtime.openid-scope",
            "/signIn/scopes/1",
        );
    }

    #[test]
    fn the_registry_resource_is_an_absolute_resource_uri() {
        for resource in [
            "registry",
            "https://registry.example/#fragment",
            "https://user@registry.example/",
        ] {
            refused(
                &document().replace(
                    "resource: https://registry.example/base",
                    &format!("resource: '{resource}'"),
                ),
                "config.invalid-value",
                "/registry/resource",
            );
        }
    }

    #[test]
    fn stdout_refuses_file_only_audit_settings() {
        refused(
            &document().replace(
                "  path: /var/lib/breg-review/audit.jsonl\n",
                "  path: /var/lib/breg-review/audit.jsonl\n  destination: stdout\n",
            ),
            "breg.review-runtime.file-only-audit-member",
            "/audit/path",
        );
    }

    #[test]
    fn a_discovered_endpoint_follows_the_mode() {
        let parse = |text: &str| url::Url::parse(text).expect("url");
        assert!(allowed_discovered_endpoint(
            &parse("https://id.example/token"),
            false
        ));
        assert!(!allowed_discovered_endpoint(
            &parse("http://127.0.0.1:9000/token"),
            false
        ));
        assert!(allowed_discovered_endpoint(
            &parse("http://127.0.0.1:9000/token"),
            true
        ));
        assert!(!allowed_discovered_endpoint(
            &parse("http://id.example/token"),
            true
        ));
        assert!(!allowed_discovered_endpoint(
            &parse("https://user@id.example/token"),
            false
        ));
        assert!(!allowed_discovered_endpoint(
            &parse("https://id.example/token#a"),
            false
        ));
    }
}
