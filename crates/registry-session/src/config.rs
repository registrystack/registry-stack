// SPDX-License-Identifier: Apache-2.0

//! The operator runtime configuration document.
//!
//! The file is read through the shared Registry Stack runtime configuration
//! loader, so its envelope, size bound, path rules, `${VAR}` substitution, and
//! secret provider declarations match every other runtime. Every credential is
//! a `secret:env/` or `secret:file/` reference, never inline text.
//!
//! Two views are derived from the file and never typed: the audience set of
//! each sign-in kind ([`RuntimeConfig::audience_set`]) and the route a request
//! path belongs to ([`RuntimeConfig::route`]).

use std::{
    fmt,
    hash::Hash,
    path::{Path, PathBuf},
};

use registry_platform_audit::{
    AuditDestination, AuditDestinationError, AuditDestinationKind, MAX_AUDIT_RETAIN_DAYS,
    MIN_AUDIT_ROTATE_BYTES,
};
pub use registry_platform_config::describe_secret_failure;
use registry_platform_config::{
    AuditKeyConfig, ConfigBlockError, ConfigBlockErrorKind, ListenerBind, LoadedRuntimeConfig,
    PrivateListenerConfig, RuntimeConfigLoader, RuntimeEnvelope, SecretProvidersConfig,
    SecretReference, TlsTermination,
};
use registry_platform_httputil::{loopback::loopback_host, valid_resource_uri, valid_scope_token};
use registry_platform_yaml::{
    escape_pointer_segment, BoundedU32, BoundedU64, Diagnostic, ExternalId, Identified, Invalid,
    LocalId, Report, UniqueList, Url,
};
use serde::{de, Deserialize, Deserializer};

/// apiVersion of the session service runtime configuration document.
pub const RUNTIME_API_VERSION: &str =
    "id.registrystack.org/formats/platform/session-runtime/v1alpha1";
/// Kind of the session service runtime configuration document.
pub const RUNTIME_KIND: &str = "PlatformSessionRuntimeConfig";

/// The path prefix under which the service serves its own routes. No module or
/// page prefix may sit at or below it.
pub const SESSION_PREFIX: &str = "/session/";

/// The session cookie's name in production: `__Host-` pins it to the exact
/// host over https.
pub const SESSION_COOKIE: &str = "__Host-registry-session";
/// The session cookie's name under `development-loopback`: plain http cannot
/// carry a `Secure` cookie, and a `__Host-` name requires one.
pub const DEVELOPMENT_SESSION_COOKIE: &str = "registry-session";
/// The sign-in flow cookie's name in production.
pub const FLOW_COOKIE: &str = "__Host-registry-signin";
/// The sign-in flow cookie's name under `development-loopback`.
pub const DEVELOPMENT_FLOW_COOKIE: &str = "registry-signin";

/// The most audiences one sign-in kind may hold. Each further audience is one
/// more top-level token request at sign-in.
pub const MAXIMUM_AUDIENCES_PER_KIND: usize = 4;

/// The word a module writes as its `audience` to use the person audience.
const PERSON_AUDIENCE: &str = "person";

/// The most scopes one sign-in kind requests beside `openid`.
const MAXIMUM_SCOPES: usize = 16;
/// The most ID-token claims who-am-I may return.
const MAXIMUM_CLAIMS: usize = 32;
/// The longest scope token, claim name or resource, in bytes.
const MAXIMUM_TOKEN_BYTES: usize = 512;
/// The longest module or page path prefix, in bytes.
const MAXIMUM_PREFIX_BYTES: usize = 256;
/// The most requests a rate limit may admit per minute or in one burst.
const MAXIMUM_RATE: u32 = 1_000_000;
/// The most sessions, or sign-ins in progress, the service may hold.
const MAXIMUM_STORE_ENTRIES: u32 = 1_000_000;
/// The shortest and longest absolute session lifetime: five minutes to a day.
const MINIMUM_SESSION_SECONDS: u64 = 300;
const MAXIMUM_SESSION_SECONDS: u64 = 86_400;
/// The shortest and longest span before expiry in which an access token is
/// renewed.
const MINIMUM_RENEW_SECONDS: u64 = 10;
const MAXIMUM_RENEW_SECONDS: u64 = 240;
/// The shortest and longest wait for a started sign-in: one minute to one
/// hour.
const MINIMUM_SIGN_IN_SECONDS: u64 = 60;
const MAXIMUM_SIGN_IN_SECONDS: u64 = 3600;
/// The largest `audit.rotateBytes` the shared audit writer accepts.
const MAXIMUM_AUDIT_ROTATE_BYTES: u64 = u32::MAX as u64;

/// ID-token claims who-am-I returns when the file names none.
const DEFAULT_CLAIMS: [&str; 4] = ["sub", "name", "email", "email_verified"];

/// Claims that describe a token or its protocol exchange rather than the
/// person. Who-am-I never returns them.
const TOKEN_CLAIMS: [&str; 13] = [
    "iss", "aud", "exp", "nbf", "iat", "jti", "nonce", "at_hash", "c_hash", "s_hash", "azp", "cnf",
    "sid",
];

const RUNTIME_ENVELOPE: RuntimeEnvelope = RuntimeEnvelope {
    api_version: RUNTIME_API_VERSION,
    kind: RUNTIME_KIND,
};

/// The operational log level. The vocabulary is closed so configuration cannot
/// turn on debug output or dependency logging.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
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

const fn default_log_level() -> LogLevel {
    LogLevel::Info
}

/// The operator runtime configuration document.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeConfig {
    pub api_version: String,
    pub kind: String,
    /// Operational log level. Defaults to `info`; accepted values are
    /// `error`, `warn`, and `info`.
    #[serde(default = "default_log_level")]
    pub log_level: LogLevel,
    /// The listener for the service's public routes.
    pub listener: PrivateListenerConfig,
    /// The address the gateway's authorization check calls. It takes the
    /// public listener's `tlsTermination` and `networkExposure` and must
    /// differ from `listener.bind`.
    pub check_listener: ListenerBind,
    /// The browser-facing origin of the gateway, such as
    /// `https://app.example`: an https URL with no path, query, or fragment;
    /// plain http is accepted only on a loopback host under
    /// `development-loopback`.
    pub public_origin: Url,
    pub secret_providers: SecretProvidersConfig,
    pub issuer: IssuerConfig,
    /// The audience several modules share, written once. A module takes it by
    /// writing `audience: person`.
    #[serde(default)]
    pub person_audience: Option<ResourceUri>,
    /// The products a page calls, each under one path prefix.
    pub modules: Vec<ModuleConfig>,
    /// The page routes that need a session of one kind.
    pub pages: Vec<PageConfig>,
    /// One confidential client per kind of sign-in, keyed by kind.
    #[serde(deserialize_with = "registry_platform_yaml::id_keyed_by_local_id")]
    pub sign_ins: Vec<SignInConfig>,
    #[serde(default)]
    pub session: SessionConfig,
    #[serde(default)]
    pub who_am_i: WhoAmIConfig,
    pub audit: AuditConfig,
    #[serde(default)]
    pub rate_limits: RateLimitsConfig,
}

/// The OpenID Provider the service signs people in with. Every endpoint is
/// written out: there is no discovery.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IssuerConfig {
    /// The expected `iss` of every ID token, compared exactly.
    pub id: ExternalId,
    /// The authorization endpoint the browser visits.
    pub authorization: Url,
    /// The end-session endpoint the browser visits.
    pub end_session: Url,
    /// The token endpoint the service calls.
    pub token: Url,
    /// The revocation endpoint the service calls.
    pub revocation: Url,
    /// The signing key set the service calls.
    pub jwks: Url,
}

impl IssuerConfig {
    fn endpoints(&self) -> [(&'static str, &Url); 5] {
        [
            ("/issuer/authorization", &self.authorization),
            ("/issuer/endSession", &self.end_session),
            ("/issuer/token", &self.token),
            ("/issuer/revocation", &self.revocation),
            ("/issuer/jwks", &self.jwks),
        ]
    }
}

/// Where a module's token audience comes from.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ModuleAudience {
    /// The `personAudience` the file declares.
    Person,
    /// An audience of the module's own.
    Resource(ResourceUri),
}

impl<'de> Deserialize<'de> for ModuleAudience {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = String::deserialize(deserializer)?;
        if text == PERSON_AUDIENCE {
            return Ok(Self::Person);
        }
        ResourceUri::new(text).map(Self::Resource).map_err(|_| {
            Invalid::expected(
                "the word person, or an absolute URI of at most 512 characters without a \
                     fragment or user information",
                "Write person to use the personAudience, or the module's token audience as \
                     an absolute URI.",
            )
            .into_error()
        })
    }
}

/// One product a page calls, reached under one path prefix.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ModuleConfig {
    /// The module's name in this file, unique among its modules.
    pub id: LocalId,
    /// The path prefix the module owns: it starts and ends with `/`.
    pub prefix: String,
    /// The audience of the token the service attaches to calls to the module.
    pub audience: ModuleAudience,
    /// The kinds that may call the module. Omitted, every kind may.
    #[serde(default)]
    pub sign_ins: Option<UniqueList<LocalId>>,
}

impl ModuleConfig {
    /// Whether a person signed in as `kind` may call the module.
    #[must_use]
    pub fn admits(&self, kind: &str) -> bool {
        self.sign_ins
            .as_ref()
            .is_none_or(|kinds| kinds.iter().any(|allowed| allowed.as_str() == kind))
    }
}

/// A page route: pages under the prefix need a session of one kind.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PageConfig {
    /// The path prefix the pages sit under: it starts and ends with `/`.
    pub prefix: String,
    /// The kind of session the pages need.
    pub sign_in: LocalId,
}

/// One kind of sign-in and the confidential client it uses at the provider.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignInConfig {
    /// The kind's name, the key it is written under.
    pub id: LocalId,
    /// The client identifier at the provider.
    pub client_id: ExternalId,
    /// Secret reference to the client secret, under a declared provider.
    pub client_secret_ref: SecretReference,
    /// Scopes requested beside `openid`, which the service always requests.
    #[serde(deserialize_with = "scope_list")]
    pub scopes: UniqueList<ScopeToken>,
}

impl Identified for SignInConfig {
    fn id(&self) -> &str {
        self.id.as_str()
    }
}

/// The audit block every Registry Stack product shares: the hash key, then a
/// `file` (the default) or `stdout` destination, with rotation and retention
/// for a file.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditConfig {
    #[serde(rename(deserialize = "registry-platform-yaml/shared-block/audit-key"))]
    pub key: AuditKeyConfig,
    /// Where audit lines go: `file` or `stdout`.
    #[serde(default)]
    pub destination: AuditDestinationKind,
    /// The absolute path of the active audit file. Required for a `file`
    /// destination, and refused with `stdout`.
    #[serde(default)]
    pub path: Option<PathBuf>,
    /// Size at which the active file rotates, in bytes, for a `file`
    /// destination. Default: 100 MiB.
    #[serde(default)]
    pub rotate_bytes: Option<BoundedU64<MIN_AUDIT_ROTATE_BYTES, MAXIMUM_AUDIT_ROTATE_BYTES>>,
    /// Days a rotated file is kept, for a `file` destination. Default: 90.
    #[serde(default)]
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
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RateLimitConfig {
    /// Requests admitted per minute, on average.
    pub requests_per_minute: BoundedU32<1, MAXIMUM_RATE>,
    /// Requests admitted at once before the average applies.
    pub burst: BoundedU32<1, MAXIMUM_RATE>,
}

/// The service's own request limits. It reads neither peer addresses nor
/// forwarded headers, so it cannot tell one browser from another before
/// sign-in: a per-client limit belongs at the gateway.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RateLimitsConfig {
    /// One limit for each signed-in person, shared by all their sessions, on
    /// every request that presents a session. Default: 120 a minute, burst
    /// 30.
    #[serde(default = "default_per_person")]
    pub per_person: RateLimitConfig,
    /// One limit shared by everyone on the unauthenticated sign-in routes.
    /// Default: 600 a minute, burst 120.
    #[serde(default = "default_global_sign_in")]
    pub global_sign_in: RateLimitConfig,
}

impl Default for RateLimitsConfig {
    fn default() -> Self {
        Self {
            per_person: default_per_person(),
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

fn default_per_person() -> RateLimitConfig {
    rate(120, 30)
}

fn default_global_sign_in() -> RateLimitConfig {
    rate(600, 120)
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionConfig {
    /// The most signed-in sessions the service holds at once. Default: 10000.
    #[serde(default = "default_store_entries")]
    pub maximum_sessions: BoundedU32<1, MAXIMUM_STORE_ENTRIES>,
    /// The most sign-ins in progress the service holds at once. It must hold
    /// every sign-in `rateLimits.globalSignIn` admits within
    /// `signInLifetimeSeconds`. Default: 10000.
    #[serde(default = "default_store_entries")]
    pub maximum_pending_sign_ins: BoundedU32<1, MAXIMUM_STORE_ENTRIES>,
    /// The longest a session lasts, whatever renewals it makes. Default:
    /// 28800.
    #[serde(default = "default_absolute_lifetime")]
    pub absolute_lifetime_seconds: BoundedU64<MINIMUM_SESSION_SECONDS, MAXIMUM_SESSION_SECONDS>,
    /// How long before an access token expires a call renews it. Default: 60.
    #[serde(default = "default_renew_before")]
    pub renew_before_seconds: BoundedU64<MINIMUM_RENEW_SECONDS, MAXIMUM_RENEW_SECONDS>,
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
            absolute_lifetime_seconds: default_absolute_lifetime(),
            renew_before_seconds: default_renew_before(),
            sign_in_lifetime_seconds: default_sign_in_lifetime(),
        }
    }
}

fn default_store_entries() -> BoundedU32<1, MAXIMUM_STORE_ENTRIES> {
    BoundedU32::new(10_000).expect("the default store size is within its bounds")
}

fn default_absolute_lifetime() -> BoundedU64<MINIMUM_SESSION_SECONDS, MAXIMUM_SESSION_SECONDS> {
    BoundedU64::new(28_800).expect("the default session lifetime is within its bounds")
}

fn default_renew_before() -> BoundedU64<MINIMUM_RENEW_SECONDS, MAXIMUM_RENEW_SECONDS> {
    BoundedU64::new(60).expect("the default renewal span is within its bounds")
}

fn default_sign_in_lifetime() -> BoundedU64<MINIMUM_SIGN_IN_SECONDS, MAXIMUM_SIGN_IN_SECONDS> {
    BoundedU64::new(600).expect("the default sign-in lifetime is within its bounds")
}

/// What who-am-I returns.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WhoAmIConfig {
    /// The ID-token claims who-am-I returns, a closed list. Default: `sub`,
    /// `name`, `email`, `email_verified`.
    #[serde(default, deserialize_with = "optional_claim_list")]
    pub claims: Option<UniqueList<ClaimName>>,
}

impl WhoAmIConfig {
    /// The claim names who-am-I returns.
    #[must_use]
    pub fn claim_names(&self) -> Vec<String> {
        match &self.claims {
            Some(claims) => claims
                .iter()
                .map(|claim| claim.as_str().to_owned())
                .collect(),
            None => DEFAULT_CLAIMS
                .iter()
                .map(|claim| (*claim).to_owned())
                .collect(),
        }
    }
}

/// Text checked by one rule, refused with one [`Invalid`] that names the rule
/// and never the value.
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
        "Write the token audience as an absolute URI, such as a urn: name or an https URL, \
         without a fragment or credentials."
    )
);

checked_text!(
    /// An ID-token claim name: 1 to 64 ASCII letters, digits, `_`, `-`, `.`
    /// or `:`.
    ClaimName,
    |text| {
        (1..=64).contains(&text.len())
            && text.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b':')
            })
    },
    Invalid::expected(
        "a claim name of 1 to 64 ASCII letters, digits, underscores, hyphens, dots, or colons",
        "Write the claim name exactly as it appears in the ID token."
    )
);

/// A set of 0 to 16 scopes.
fn scope_list<'de, D>(deserializer: D) -> Result<UniqueList<ScopeToken>, D::Error>
where
    D: Deserializer<'de>,
{
    bounded(deserializer, MAXIMUM_SCOPES, &"0 to 16 items")
}

/// A set of 0 to 32 claim names, or none written.
fn optional_claim_list<'de, D>(deserializer: D) -> Result<Option<UniqueList<ClaimName>>, D::Error>
where
    D: Deserializer<'de>,
{
    bounded(deserializer, MAXIMUM_CLAIMS, &"0 to 32 items").map(Some)
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
    if list.len() > maximum {
        return Err(de::Error::invalid_length(list.len(), expected));
    }
    Ok(list)
}

/// Why the runtime configuration was refused: every finding, each positioned
/// in the file and naming its fix, never a value from it.
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

/// The route a request path belongs to.
#[derive(Clone, Copy, Debug)]
pub enum Route<'a> {
    /// A call to a product: the service attaches a bearer token.
    Module(&'a ModuleConfig),
    /// A page: the service only requires a session of the page's kind.
    Page(&'a PageConfig),
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

    /// The loader for the session service runtime file.
    #[must_use]
    pub const fn loader() -> RuntimeConfigLoader {
        RuntimeConfigLoader::new_without_posture(RUNTIME_ENVELOPE)
    }

    /// Whether the document declares the loopback-only development mode.
    #[must_use]
    pub fn development(&self) -> bool {
        self.listener.tls_termination == TlsTermination::DevelopmentLoopback
    }

    /// The session cookie's name for the declared transport.
    #[must_use]
    pub fn session_cookie(&self) -> &'static str {
        if self.development() {
            DEVELOPMENT_SESSION_COOKIE
        } else {
            SESSION_COOKIE
        }
    }

    /// The sign-in flow cookie's name for the declared transport.
    #[must_use]
    pub fn flow_cookie(&self) -> &'static str {
        if self.development() {
            DEVELOPMENT_FLOW_COOKIE
        } else {
            FLOW_COOKIE
        }
    }

    /// The browser-facing origin, without a trailing slash.
    #[must_use]
    pub fn origin(&self) -> String {
        self.public_origin.as_str().trim_end_matches('/').to_owned()
    }

    /// The configuration of the sign-in kind `kind`.
    #[must_use]
    pub fn sign_in(&self, kind: &str) -> Option<&SignInConfig> {
        self.sign_ins
            .iter()
            .find(|sign_in| sign_in.id.as_str() == kind)
    }

    /// The audience a module's token is issued for: its own URI, or the
    /// person audience. `None` only for a document the loader refuses.
    #[must_use]
    pub fn module_audience<'a>(&'a self, module: &'a ModuleConfig) -> Option<&'a str> {
        match &module.audience {
            ModuleAudience::Person => self.person_audience.as_ref().map(ResourceUri::as_str),
            ModuleAudience::Resource(resource) => Some(resource.as_str()),
        }
    }

    /// The distinct audiences of the modules `kind` may call, the person
    /// audience first when any of them uses it, then the others in module
    /// order.
    #[must_use]
    pub fn audience_set(&self, kind: &str) -> Vec<&str> {
        if self.sign_in(kind).is_none() {
            return Vec::new();
        }
        let reached: Vec<&ModuleConfig> = self
            .modules
            .iter()
            .filter(|module| module.admits(kind))
            .collect();
        let mut audiences = Vec::new();
        if reached
            .iter()
            .any(|module| module.audience == ModuleAudience::Person)
        {
            audiences.extend(self.person_audience.as_ref().map(ResourceUri::as_str));
        }
        for module in reached {
            if let Some(audience) = self.module_audience(module) {
                if !audiences.contains(&audience) {
                    audiences.push(audience);
                }
            }
        }
        audiences
    }

    /// The route `path` belongs to: the module or page with the longest
    /// prefix that `path` starts with. `path` carries no query.
    #[must_use]
    pub fn route(&self, path: &str) -> Option<Route<'_>> {
        let module = self
            .modules
            .iter()
            .filter(|module| path.starts_with(&module.prefix))
            .max_by_key(|module| module.prefix.len());
        let page = self
            .pages
            .iter()
            .filter(|page| path.starts_with(&page.prefix))
            .max_by_key(|page| page.prefix.len());
        match (module, page) {
            (Some(module), Some(page)) if page.prefix.len() > module.prefix.len() => {
                Some(Route::Page(page))
            }
            (Some(module), _) => Some(Route::Module(module)),
            (None, Some(page)) => Some(Route::Page(page)),
            (None, None) => None,
        }
    }
}

/// Check the runtime file at the absolute `path` as the service reads it, with
/// no secret material, network, or listener (CFG-CHECK-1).
///
/// With `substitute` set, `${NAME}` expressions are filled from the process
/// environment and every value is checked. Without it, each expression is
/// checked by syntax and position only: the value checks of a member that holds
/// one are skipped, because they need the substituted text.
#[must_use]
pub fn check_runtime(path: &Path, substitute: bool) -> RuntimeCheck {
    read_runtime(path, substitute).1
}

/// The file read by the shared loader, then the members the loader cannot
/// judge checked. The configuration is returned only when nothing was found.
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
    listener_findings(config, defers, &mut findings);
    let mut blocks = vec![
        config.secret_providers.check(),
        config.audit.key.check(&config.secret_providers),
    ];
    for sign_in in &config.sign_ins {
        blocks.push(config.secret_providers.check_reference(
            &format!("signIns.{}.clientSecretRef", sign_in.id.as_str()),
            sign_in.client_secret_ref.as_str(),
        ));
    }
    findings.extend(
        blocks
            .iter()
            .filter_map(|result| result.as_ref().err())
            .map(block_finding),
    );
    endpoint_findings(config, defers, &mut findings);
    for sign_in in &config.sign_ins {
        for (index, scope) in sign_in.scopes.iter().enumerate() {
            if scope.as_str() == "openid" {
                findings.push(Finding::new(
                    "platform.session-runtime.openid-scope",
                    &format!(
                        "/signIns/{}/scopes/{index}",
                        escape_pointer_segment(sign_in.id.as_str())
                    ),
                    "a sign-in kind names the openid scope, which the service requests on every \
                     sign-in",
                    "Remove openid from the kind's scopes and keep the scopes the products \
                     require.",
                ));
            }
        }
    }
    route_findings(config, &mut findings);
    kind_findings(config, &mut findings);
    for (index, claim) in config
        .who_am_i
        .claims
        .iter()
        .flat_map(|claims| claims.iter())
        .enumerate()
    {
        if TOKEN_CLAIMS.contains(&claim.as_str()) {
            findings.push(Finding::new(
                "platform.session-runtime.token-claim",
                &format!("/whoAmI/claims/{index}"),
                "whoAmI.claims names a claim that describes the token or its exchange rather \
                 than the person",
                "Remove the claim, and name only claims that describe the person.",
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
            "platform.session-runtime.pending-sign-ins-fillable",
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

/// The public listener and the check listener: both on addresses their
/// declared exposure allows, and not the same address.
fn listener_findings(
    config: &RuntimeConfig,
    defers: &dyn Fn(&str) -> bool,
    findings: &mut Vec<Finding>,
) {
    if !config.listener.is_valid() {
        findings.push(Finding::new(
            "platform.session-runtime.public-bind",
            "/listener/bind",
            "listener.bind is not a loopback or private address its tlsTermination and \
             networkExposure allow",
            "Bind a loopback address, or a private address behind the proxy that terminates TLS \
             with tlsTermination operator-controlled-upstream.",
        ));
    }
    let check = PrivateListenerConfig {
        bind: config.check_listener,
        ..config.listener
    };
    if !check.is_valid() {
        findings.push(Finding::new(
            "platform.session-runtime.check-public-bind",
            "/checkListener",
            "checkListener is not a loopback or private address the listener's tlsTermination \
             and networkExposure allow",
            "Bind a loopback address, or a private address only the gateway can reach.",
        ));
    }
    if config.check_listener == config.listener.bind && !defers("/listener/bind") {
        findings.push(Finding::new(
            "platform.session-runtime.check-listener-not-distinct",
            "/checkListener",
            "checkListener is the same address as listener.bind, which would serve the check on \
             the public listener",
            "Give the check its own address, reachable only by the gateway.",
        ));
    }
}

/// Every endpoint the service serves or calls is https with no query or
/// fragment, or plain http on a loopback host under `development-loopback`.
/// The public origin also has no path.
fn endpoint_findings(
    config: &RuntimeConfig,
    defers: &dyn Fn(&str) -> bool,
    findings: &mut Vec<Finding>,
) {
    let termination_known = !defers("/listener/tlsTermination");
    let development = config.development();
    let mut endpoints = vec![("/publicOrigin", &config.public_origin)];
    endpoints.extend(config.issuer.endpoints());
    for (pointer, endpoint) in endpoints {
        let url = endpoint.to_url();
        let secure = url.scheme() == "https" || (development && is_loopback(&url));
        if termination_known && !secure {
            findings.push(Finding::new(
                "platform.session-runtime.plain-http-endpoint",
                pointer,
                "the endpoint uses plain http, which is accepted only on a loopback host under \
                 listener.tlsTermination development-loopback",
                "Write an https URL, or run on loopback with listener.tlsTermination \
                 development-loopback.",
            ));
        } else if url.query().is_some() || url.fragment().is_some() {
            findings.push(Finding::new(
                "platform.session-runtime.endpoint-query-or-fragment",
                pointer,
                "the endpoint carries a query or a fragment",
                "Remove the query and the fragment from the URL.",
            ));
        }
    }
    // The service serves its routes at the root of the gateway's origin.
    if config.public_origin.to_url().path() != "/" {
        findings.push(Finding::new(
            "platform.session-runtime.public-origin-not-origin",
            "/publicOrigin",
            "publicOrigin has a path, but the service is reached at the root of the gateway's \
             origin",
            "Write the scheme, host, and port the browser reaches the gateway at, with no path.",
        ));
    }
}

/// Whether `prefix` is a path prefix the check can match exactly: it starts
/// and ends with `/`, holds only visible ASCII, and has no empty segment, dot
/// segment, percent sign, backslash, query, or fragment.
fn clean_prefix(prefix: &str) -> bool {
    prefix.len() <= MAXIMUM_PREFIX_BYTES
        && prefix.starts_with('/')
        && prefix.ends_with('/')
        && prefix.bytes().all(|byte| byte.is_ascii_graphic())
        && !prefix.contains(['%', '\\', '?', '#'])
        && !prefix.contains("//")
        && prefix
            .split('/')
            .all(|segment| segment != "." && segment != "..")
}

/// Prefix rules for modules and pages: clean, outside the service's own
/// routes, and not shared. Module ids are unique, and a module that takes
/// the person audience needs one declared.
fn route_findings(config: &RuntimeConfig, findings: &mut Vec<Finding>) {
    let prefixes = config
        .modules
        .iter()
        .enumerate()
        .map(|(index, module)| (format!("/modules/{index}/prefix"), module.prefix.as_str()))
        .chain(
            config
                .pages
                .iter()
                .enumerate()
                .map(|(index, page)| (format!("/pages/{index}/prefix"), page.prefix.as_str())),
        );
    let mut seen: Vec<&str> = Vec::new();
    for (pointer, prefix) in prefixes {
        if !clean_prefix(prefix) {
            findings.push(Finding::new(
                "platform.session-runtime.invalid-prefix",
                &pointer,
                "the prefix is not a path that starts and ends with / and holds no empty or dot \
                 segment, percent sign, backslash, query, or fragment",
                "Write the prefix as an exact path such as /api/registry/.",
            ));
        } else if prefix.starts_with(SESSION_PREFIX) {
            findings.push(Finding::new(
                "platform.session-runtime.prefix-under-session",
                &pointer,
                "the prefix is under /session/, which the service keeps for its own routes",
                "Choose a prefix outside /session/.",
            ));
        }
        if seen.contains(&prefix) {
            findings.push(Finding::new(
                "platform.session-runtime.duplicate-prefix",
                &pointer,
                "another module or page has the same prefix",
                "Give each module and page its own prefix.",
            ));
        }
        seen.push(prefix);
    }
    for (index, module) in config.modules.iter().enumerate() {
        if config.modules[..index]
            .iter()
            .any(|earlier| earlier.id == module.id)
        {
            findings.push(Finding::new(
                "platform.session-runtime.duplicate-module-id",
                &format!("/modules/{index}/id"),
                "another module has the same id",
                "Give each module its own id.",
            ));
        }
        if module.audience == ModuleAudience::Person && config.person_audience.is_none() {
            findings.push(Finding::new(
                "platform.session-runtime.person-audience-missing",
                &format!("/modules/{index}/audience"),
                "the module takes the person audience, but personAudience is not declared",
                "Declare personAudience, or write the module's own audience as an absolute URI.",
            ));
        }
    }
}

/// Sign-in kinds: every kind a module or page names is declared, every
/// declared kind reaches a module or a page, and no kind holds more
/// audiences than one sign-in may request.
fn kind_findings(config: &RuntimeConfig, findings: &mut Vec<Finding>) {
    let declared = |kind: &LocalId| config.sign_in(kind.as_str()).is_some();
    for (index, module) in config.modules.iter().enumerate() {
        for (position, kind) in module
            .sign_ins
            .iter()
            .flat_map(|kinds| kinds.iter())
            .enumerate()
        {
            if !declared(kind) {
                findings.push(Finding::new(
                    "platform.session-runtime.undeclared-sign-in-kind",
                    &format!("/modules/{index}/signIns/{position}"),
                    "the module names a sign-in kind that signIns does not declare",
                    "Declare the kind under signIns, or name a declared kind.",
                ));
            }
        }
    }
    for (index, page) in config.pages.iter().enumerate() {
        if !declared(&page.sign_in) {
            findings.push(Finding::new(
                "platform.session-runtime.undeclared-sign-in-kind",
                &format!("/pages/{index}/signIn"),
                "the page names a sign-in kind that signIns does not declare",
                "Declare the kind under signIns, or name a declared kind.",
            ));
        }
    }
    for sign_in in &config.sign_ins {
        let kind = sign_in.id.as_str();
        let pointer = format!("/signIns/{}", escape_pointer_segment(kind));
        let reaches = config.modules.iter().any(|module| module.admits(kind))
            || config
                .pages
                .iter()
                .any(|page| page.sign_in.as_str() == kind);
        if !reaches {
            findings.push(Finding::new(
                "platform.session-runtime.unreachable-sign-in-kind",
                &pointer,
                "no module and no page uses the sign-in kind",
                "Name the kind in a module's signIns or a page's signIn, or remove it.",
            ));
        }
        if config.audience_set(kind).len() > MAXIMUM_AUDIENCES_PER_KIND {
            findings.push(Finding::new(
                "platform.session-runtime.too-many-audiences",
                &pointer,
                "the modules the kind may call use more than 4 distinct audiences, and each \
                 audience is one more token request at sign-in",
                "Move modules into the person audience, or limit which kinds may call them.",
            ));
        }
    }
}

fn is_loopback(url: &url::Url) -> bool {
    url.scheme() == "http"
        && url
            .host_str()
            .is_some_and(|host| loopback_host(host).is_some())
}

/// A value that satisfies the member at `pointer`, so a deferred expression
/// never decides whether its neighbours decode.
fn stand_in_for(pointer: &str) -> &'static str {
    match pointer {
        "/listener/bind" => "127.0.0.1:8080",
        "/checkListener" => "127.0.0.1:8081",
        "/listener/tlsTermination" => "operator-controlled-upstream",
        "/listener/networkExposure" => "private-address",
        "/publicOrigin" => "https://deferred.invalid",
        "/personAudience" => "urn:deferred",
        "/audit/destination" => "file",
        "/audit/path" => "/audit.jsonl",
        other if other.starts_with("/issuer/") && other != "/issuer/id" => {
            "https://deferred.invalid"
        }
        other if other.starts_with("/modules/") && other.ends_with("/audience") => "person",
        other if other.starts_with("/modules/") && other.ends_with("/prefix") => "/deferred/",
        other if other.starts_with("/pages/") && other.ends_with("/prefix") => "/deferred/",
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
            "platform.session-runtime.relative-path",
            "Write the path as an absolute path with no `.` or `..` segment.",
        ),
        ConfigBlockErrorKind::NoSecretProvider => (
            "platform.session-runtime.no-secret-provider",
            "Declare secretProviders.file with an absolute root, \
             secretProviders.environment: {}, or both.",
        ),
        ConfigBlockErrorKind::InvalidSecretReference => (
            "platform.session-runtime.invalid-secret-reference",
            "Write the reference as secret:file/<name> or secret:env/<NAME>.",
        ),
        ConfigBlockErrorKind::SecretProviderDisabled => (
            "platform.session-runtime.undeclared-secret-provider",
            "Declare the provider the message names under secretProviders, or reference a \
             declared one.",
        ),
        _ => (
            "platform.session-runtime.invalid-block",
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
            "platform.session-runtime.missing-audit-path",
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
                "platform.session-runtime.file-only-audit-member",
                &format!("/audit/{member}"),
                format!("audit.{member} applies only when audit.destination is file"),
                "Remove the member, or set audit.destination to file.",
            )
        }
        AuditDestinationError::RelativePath
        | AuditDestinationError::InvalidPathComponent
        | AuditDestinationError::NoFileName
        | AuditDestinationError::FileNameTooLong { .. } => finding(
            "platform.session-runtime.invalid-audit-path",
            "/audit/path",
            error.to_string(),
            "Write audit.path as an absolute file path with no `.` or `..` segment, ending in \
             a file name.",
        ),
        AuditDestinationError::PathNamesReservedCompanion {
            suffix, companion, ..
        } => finding(
            "platform.session-runtime.invalid-audit-path",
            "/audit/path",
            format!(
                "audit.path ends in `{suffix}`, which names the {companion} of another audit \
                 stream"
            ),
            "Choose an audit file name without that ending.",
        ),
        AuditDestinationError::RetainDaysOutOfRange { maximum } => finding(
            "platform.session-runtime.invalid-audit",
            "/audit/retentionDays",
            format!("audit.retentionDays must be between 1 and {maximum}"),
            "Write a number of days within the bounds.",
        ),
        _ => finding(
            "platform.session-runtime.invalid-audit",
            "/audit",
            error.to_string(),
            "Correct the audit block as the message describes.",
        ),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use std::fs;

    use super::*;

    pub(crate) fn document() -> String {
        r"apiVersion: id.registrystack.org/formats/platform/session-runtime/v1alpha1
kind: PlatformSessionRuntimeConfig
listener:
  bind: 10.0.0.5:8120
  tlsTermination: operator-controlled-upstream
checkListener: 10.0.0.5:8121
publicOrigin: https://app.example
secretProviders:
  file:
    root: /run/secrets
  environment: {}
issuer:
  id: https://id.example
  authorization: https://id.example/oauth2/authorize
  endSession: https://id.example/oauth2/logout
  token: https://id.example/oauth2/token
  revocation: https://id.example/oauth2/revoke
  jwks: https://id.example/oauth2/jwks
personAudience: https://api.example/person
modules:
  - id: registry
    prefix: /api/registry/
    audience: person
  - id: scheduling
    prefix: /api/scheduling/
    audience: person
  - id: casework
    prefix: /api/casework/
    audience: https://casework.example/api
    signIns: [staff]
pages:
  - prefix: /apply/
    signIn: citizen
  - prefix: /staff/
    signIn: staff
signIns:
  citizen:
    clientId: citizen-app
    clientSecretRef: secret:file/citizen-secret
    scopes: [registry:read]
  staff:
    clientId: staff-app
    clientSecretRef: secret:file/staff-secret
    scopes: [registry:read, casework:work]
audit:
  hashKeyRef: secret:env/SESSION_AUDIT_KEY
  path: /var/lib/session/audit.jsonl
"
        .to_owned()
    }

    /// The development variant of [`document`]: loopback endpoints under
    /// `development-loopback`.
    pub(crate) fn development() -> String {
        document()
            .replace("10.0.0.5:8120", "127.0.0.1:8120")
            .replace("10.0.0.5:8121", "127.0.0.1:8121")
            .replace("operator-controlled-upstream", "development-loopback")
            .replace("https://app.example", "http://127.0.0.1:8120")
            .replace("https://id.example", "http://127.0.0.1:9000")
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

    pub(crate) fn load(text: &str) -> Result<RuntimeConfig, RuntimeConfigError> {
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

    fn found(text: &str, code: &str, path: &str) {
        let found = findings_of(text);
        assert!(
            found.contains(&(code.to_owned(), path.to_owned())),
            "expected {code} at {path}: {found:?}"
        );
    }

    fn code(name: &str) -> String {
        format!("platform.session-runtime.{name}")
    }

    #[test]
    fn a_production_document_loads_with_its_defaults() {
        let config = load(&document()).expect("valid document");
        assert_eq!(config.log_level.as_str(), "info");
        assert!(!config.development());
        assert_eq!(config.origin(), "https://app.example");
        assert_eq!(config.session.sessions(), 10_000);
        assert_eq!(config.session.pending_sign_ins(), 10_000);
        assert_eq!(config.session.absolute_lifetime_seconds.get(), 28_800);
        assert_eq!(config.session.renew_before_seconds.get(), 60);
        assert_eq!(config.session.sign_in_lifetime_seconds.get(), 600);
        assert_eq!(config.rate_limits.per_person.requests_per_minute.get(), 120);
        assert_eq!(config.rate_limits.global_sign_in.burst.get(), 120);
        assert_eq!(
            config.who_am_i.claim_names(),
            ["sub", "name", "email", "email_verified"]
        );
        assert_eq!(config.sign_ins.len(), 2);
        assert_eq!(
            config.sign_in("staff").expect("staff").client_id.as_str(),
            "staff-app"
        );
        assert!(config.sign_in("ghost").is_none());
    }

    #[test]
    fn the_development_document_loads() {
        assert!(load(&development()).expect("development").development());
    }

    #[test]
    fn log_level_accepts_only_the_closed_vocabulary() {
        let with = |level: &str| {
            document().replacen(
                "kind: PlatformSessionRuntimeConfig\n",
                &format!("kind: PlatformSessionRuntimeConfig\nlogLevel: {level}\n"),
                1,
            )
        };
        for accepted in ["error", "warn", "info"] {
            assert_eq!(
                load(&with(accepted))
                    .expect("level loads")
                    .log_level
                    .as_str(),
                accepted
            );
        }
        for refused_value in ["debug", "trace", "off", "Info"] {
            refused(&with(refused_value), "config.unknown-variant", "/logLevel");
        }
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
    fn unknown_keys_are_all_reported_where_they_are_written() {
        let text = document()
            .replace(
                "  tlsTermination: operator-controlled-upstream\n",
                "  tlsTermination: operator-controlled-upstream\n  listenerTypo: x\n",
            )
            .replace(
                "  jwks: https://id.example/oauth2/jwks\n",
                "  jwks: https://id.example/oauth2/jwks\n  discovery: x\n",
            )
            .replace(
                "    clientId: staff-app\n",
                "    clientId: staff-app\n    secret: x\n",
            );
        for path in [
            "/listener/listenerTypo",
            "/issuer/discovery",
            "/signIns/staff/secret",
        ] {
            found(&text, "config.unknown-key", path);
        }
    }

    #[test]
    fn an_inline_credential_is_refused_without_echoing_it() {
        const CANARY: &str = "inline-canary-value";
        for (reference, path) in [
            (
                "clientSecretRef: secret:file/staff-secret",
                "/signIns/staff/clientSecretRef",
            ),
            (
                "hashKeyRef: secret:env/SESSION_AUDIT_KEY",
                "/audit/hashKeyRef",
            ),
        ] {
            let key = reference.split(':').next().expect("key");
            let text = document().replace(reference, &format!("{key}: '{CANARY}'"));
            let error = load(&text).expect_err("an inline credential is refused");
            assert_eq!(error.diagnostics[0].code, "config.invalid-value");
            assert_eq!(error.diagnostics[0].path, path);
            assert!(!error.to_string().contains(CANARY), "{error}");
        }
    }

    #[test]
    fn an_undeclared_secret_provider_is_refused() {
        refused(
            &document().replace("  environment: {}\n", ""),
            &code("undeclared-secret-provider"),
            "/audit/hashKeyRef",
        );
        assert_eq!(
            findings_of(&document().replace("  file:\n    root: /run/secrets\n", "")),
            [
                (
                    code("undeclared-secret-provider"),
                    "/signIns/citizen/clientSecretRef".to_owned()
                ),
                (
                    code("undeclared-secret-provider"),
                    "/signIns/staff/clientSecretRef".to_owned()
                ),
            ]
        );
    }

    #[test]
    fn a_deferred_expression_skips_its_value_checks() {
        let text = document()
            .replace(
                "publicOrigin: https://app.example",
                "publicOrigin: ${SESSION_TEST_UNSET_ORIGIN}",
            )
            .replace(
                "checkListener: 10.0.0.5:8121",
                "checkListener: ${SESSION_TEST_UNSET_CHECK}",
            )
            .replace(
                "prefix: /api/scheduling/",
                "prefix: ${SESSION_TEST_UNSET_PREFIX}",
            )
            .replace(
                "token: https://id.example/oauth2/token",
                "token: ${SESSION_TEST_UNSET_TOKEN}",
            );
        let (_directory, path) = written(&text);
        let check = check_runtime(&path, false);
        assert!(check.diagnostics.is_empty(), "{:?}", check.diagnostics);
    }

    #[test]
    fn every_integer_is_bounded() {
        for (extra, path) in [
            (
                "rateLimits:\n  perPerson: { requestsPerMinute: 0, burst: 1 }\n",
                "/rateLimits/perPerson/requestsPerMinute",
            ),
            (
                "session:\n  maximumSessions: 0\n",
                "/session/maximumSessions",
            ),
            (
                "session:\n  absoluteLifetimeSeconds: 299\n",
                "/session/absoluteLifetimeSeconds",
            ),
            (
                "session:\n  absoluteLifetimeSeconds: 86401\n",
                "/session/absoluteLifetimeSeconds",
            ),
            (
                "session:\n  renewBeforeSeconds: 9\n",
                "/session/renewBeforeSeconds",
            ),
            (
                "session:\n  renewBeforeSeconds: 241\n",
                "/session/renewBeforeSeconds",
            ),
            (
                "session:\n  signInLifetimeSeconds: 3601\n",
                "/session/signInLifetimeSeconds",
            ),
        ] {
            refused(
                &format!("{}{extra}", document()),
                "config.out-of-range",
                path,
            );
        }
        let bounds = format!(
            "{}session:\n  absoluteLifetimeSeconds: 300\n  renewBeforeSeconds: 240\n",
            document()
        );
        load(&bounds).expect("the bounds themselves are accepted");
    }

    #[test]
    fn the_global_sign_in_cap_cannot_fill_the_pending_store() {
        let with = |pending: u32| {
            format!(
                "{}rateLimits:\n  globalSignIn: {{ requestsPerMinute: 600, burst: 120 }}\n\
                 session:\n  maximumPendingSignIns: {pending}\n  signInLifetimeSeconds: 600\n",
                document()
            )
        };
        refused(
            &with(6119),
            &code("pending-sign-ins-fillable"),
            "/session/maximumPendingSignIns",
        );
        let error = load(&with(6119)).expect_err("a store the cap can fill");
        assert!(!error.to_string().contains("6119"), "{error}");
        load(&with(6120)).expect("a store the cap cannot fill");
    }

    #[test]
    fn plaintext_endpoints_are_development_loopback_only() {
        for (from, to, path) in [
            (
                "publicOrigin: https://app.example",
                "publicOrigin: http://app.example",
                "/publicOrigin",
            ),
            (
                "authorization: https://id.example",
                "authorization: http://id.example",
                "/issuer/authorization",
            ),
            (
                "endSession: https://id.example",
                "endSession: http://id.example",
                "/issuer/endSession",
            ),
            (
                "token: https://id.example",
                "token: http://id.example",
                "/issuer/token",
            ),
            (
                "revocation: https://id.example",
                "revocation: http://id.example",
                "/issuer/revocation",
            ),
            (
                "jwks: https://id.example",
                "jwks: http://id.example",
                "/issuer/jwks",
            ),
        ] {
            refused(
                &document().replace(from, to),
                &code("plain-http-endpoint"),
                path,
            );
        }
        refused(
            &development().replace("http://127.0.0.1:9000/oauth2/token", "http://id.example/t"),
            &code("plain-http-endpoint"),
            "/issuer/token",
        );
        refused(
            &development().replace("bind: 127.0.0.1:8120", "bind: 0.0.0.0:8120"),
            &code("public-bind"),
            "/listener/bind",
        );
    }

    #[test]
    fn an_endpoint_with_a_query_or_fragment_is_refused() {
        for suffix in ["?a=1", "#frag"] {
            refused(
                &document().replace(
                    "token: https://id.example/oauth2/token",
                    &format!("token: https://id.example/oauth2/token{suffix}"),
                ),
                &code("endpoint-query-or-fragment"),
                "/issuer/token",
            );
        }
    }

    #[test]
    fn the_public_origin_is_an_origin_only() {
        let root = document().replace(
            "publicOrigin: https://app.example",
            "publicOrigin: https://app.example/",
        );
        assert_eq!(
            load(&root)
                .expect("a trailing slash is the root path")
                .origin(),
            "https://app.example"
        );
        refused(
            &document().replace(
                "publicOrigin: https://app.example",
                "publicOrigin: https://app.example/path",
            ),
            &code("public-origin-not-origin"),
            "/publicOrigin",
        );
    }

    #[test]
    fn the_check_listener_must_differ_from_the_public_listener() {
        refused(
            &document().replace(
                "checkListener: 10.0.0.5:8121",
                "checkListener: 10.0.0.5:8120",
            ),
            &code("check-listener-not-distinct"),
            "/checkListener",
        );
    }

    #[test]
    fn the_check_listener_follows_the_listener_exposure_rules() {
        refused(
            &document().replace(
                "checkListener: 10.0.0.5:8121",
                "checkListener: 8.8.8.8:8121",
            ),
            &code("check-public-bind"),
            "/checkListener",
        );
        refused(
            &development().replace(
                "checkListener: 127.0.0.1:8121",
                "checkListener: 10.0.0.5:8121",
            ),
            &code("check-public-bind"),
            "/checkListener",
        );
        let missing = document().replace("checkListener: 10.0.0.5:8121\n", "");
        found(&missing, "config.missing-key", "");
    }

    #[test]
    fn a_prefix_must_be_a_clean_path_prefix() {
        for bad in [
            "api/registry/",
            "/api/registry",
            "/api//registry/",
            "/api/./registry/",
            "/api/../registry/",
            "/api/%2e/",
            "/api/a%2Fb/",
            "/api/a%25/",
            "/api\\registry/",
            "/api/a?b=1/",
            "/api/a#b/",
            "",
        ] {
            let text = document().replace("prefix: /api/registry/", &format!("prefix: '{bad}'"));
            refused(&text, &code("invalid-prefix"), "/modules/0/prefix");
            let text = document().replace("prefix: /apply/", &format!("prefix: '{bad}'"));
            refused(&text, &code("invalid-prefix"), "/pages/0/prefix");
        }
        for fine in ["/", "/api/.hidden/", "/api/v1.2/"] {
            let text = document().replace("/api/registry/", fine);
            assert_eq!(findings_of(&text), []);
        }
    }

    #[test]
    fn a_prefix_under_the_session_routes_is_refused() {
        for bad in ["/session/", "/session/x/"] {
            refused(
                &document().replace("/api/registry/", bad),
                &code("prefix-under-session"),
                "/modules/0/prefix",
            );
            refused(
                &document().replace("/apply/", bad),
                &code("prefix-under-session"),
                "/pages/0/prefix",
            );
        }
        assert_eq!(
            findings_of(&document().replace("/apply/", "/sessions/")),
            []
        );
    }

    #[test]
    fn two_equal_prefixes_are_refused_across_modules_and_pages() {
        refused(
            &document().replace("/api/scheduling/", "/api/registry/"),
            &code("duplicate-prefix"),
            "/modules/1/prefix",
        );
        refused(
            &document().replace("/apply/", "/api/casework/"),
            &code("duplicate-prefix"),
            "/pages/0/prefix",
        );
        refused(
            &document().replace("/staff/", "/apply/"),
            &code("duplicate-prefix"),
            "/pages/1/prefix",
        );
    }

    #[test]
    fn two_modules_cannot_share_an_id() {
        refused(
            &document().replace("id: scheduling", "id: registry"),
            &code("duplicate-module-id"),
            "/modules/1/id",
        );
    }

    #[test]
    fn the_person_audience_must_be_declared_to_be_used() {
        let text = document().replace("personAudience: https://api.example/person\n", "");
        let found = findings_of(&text);
        assert_eq!(
            found,
            [
                (
                    code("person-audience-missing"),
                    "/modules/0/audience".to_owned()
                ),
                (
                    code("person-audience-missing"),
                    "/modules/1/audience".to_owned()
                ),
            ]
        );
    }

    #[test]
    fn the_person_audience_and_module_audiences_are_resource_uris() {
        for bad in [
            "registry",
            "https://x.example/#frag",
            "https://user@x.example/",
        ] {
            refused(
                &document().replace(
                    "personAudience: https://api.example/person",
                    &format!("personAudience: '{bad}'"),
                ),
                "config.invalid-value",
                "/personAudience",
            );
            refused(
                &document().replace(
                    "audience: https://casework.example/api",
                    &format!("audience: '{bad}'"),
                ),
                "config.invalid-value",
                "/modules/2/audience",
            );
        }
    }

    #[test]
    fn a_kind_named_but_not_declared_is_refused() {
        refused(
            &document().replace("signIns: [staff]", "signIns: [staff, ghost]"),
            &code("undeclared-sign-in-kind"),
            "/modules/2/signIns/1",
        );
        refused(
            &document().replace("signIn: citizen", "signIn: ghost"),
            &code("undeclared-sign-in-kind"),
            "/pages/0/signIn",
        );
    }

    #[test]
    fn a_kind_that_reaches_nothing_is_refused() {
        let text = document()
            .replace(
                "audience: person\n",
                "audience: person\n    signIns: [citizen, staff]\n",
            )
            .replace(
                "audit:\n",
                "  orphan:\n    clientId: orphan-app\n    clientSecretRef: secret:file/orphan-secret\n    \
                 scopes: []\naudit:\n",
            );
        refused(&text, &code("unreachable-sign-in-kind"), "/signIns/orphan");
        // A page of its own kind is enough to reach.
        let reached = text.replace(
            "  - prefix: /staff/\n    signIn: staff\n",
            "  - prefix: /staff/\n    signIn: staff\n  - prefix: /orphans/\n    signIn: orphan\n",
        );
        assert_eq!(findings_of(&reached), []);
    }

    #[test]
    fn more_than_four_audiences_in_one_kind_are_refused() {
        let extra = |count: usize| {
            let modules: String = (0..count)
                .map(|index| {
                    format!(
                        "  - id: extra{index}\n    prefix: /api/extra{index}/\n    audience: \
                         https://extra{index}.example/api\n"
                    )
                })
                .collect();
            document().replace("pages:\n", &format!("{modules}pages:\n"))
        };
        // Citizen: person plus three is four. Staff: person, casework and three is five.
        refused(&extra(3), &code("too-many-audiences"), "/signIns/staff");
        // Staff at four audiences: person, casework and two others.
        assert_eq!(findings_of(&extra(2)), []);
        found(&extra(4), &code("too-many-audiences"), "/signIns/citizen");
        found(&extra(4), &code("too-many-audiences"), "/signIns/staff");
    }

    #[test]
    fn audience_sets_follow_the_modules_a_kind_may_call() {
        let config = load(&document()).expect("valid document");
        assert_eq!(
            config.audience_set("citizen"),
            ["https://api.example/person"]
        );
        assert_eq!(
            config.audience_set("staff"),
            ["https://api.example/person", "https://casework.example/api"]
        );
        assert!(config.audience_set("ghost").is_empty());
    }

    #[test]
    fn the_person_audience_is_first_even_when_a_module_of_another_audience_comes_first() {
        let text = document().replace(
            "modules:\n  - id: registry\n    prefix: /api/registry/\n    audience: person\n",
            "modules:\n  - id: other\n    prefix: /api/other/\n    audience: https://other.example/api\n  - \
             id: registry\n    prefix: /api/registry/\n    audience: person\n",
        );
        let config = load(&text).expect("valid document");
        assert_eq!(
            config.audience_set("staff"),
            [
                "https://api.example/person",
                "https://other.example/api",
                "https://casework.example/api"
            ]
        );
    }

    #[test]
    fn moving_a_module_out_of_the_person_audience_adds_it_to_every_kind_that_calls_it() {
        let text = document().replace(
            "    prefix: /api/scheduling/\n    audience: person\n",
            "    prefix: /api/scheduling/\n    audience: https://scheduling.example/api\n",
        );
        let config = load(&text).expect("valid document");
        assert_eq!(
            config.audience_set("citizen"),
            [
                "https://api.example/person",
                "https://scheduling.example/api"
            ]
        );
        assert_eq!(
            config.audience_set("staff"),
            [
                "https://api.example/person",
                "https://scheduling.example/api",
                "https://casework.example/api"
            ]
        );
    }

    #[test]
    fn a_kind_that_reaches_only_its_own_audiences_has_no_person_audience() {
        let text = document()
            .replace(
                "    prefix: /api/registry/\n    audience: person\n",
                "    prefix: /api/registry/\n    audience: person\n    signIns: [citizen]\n",
            )
            .replace(
                "    prefix: /api/scheduling/\n    audience: person\n",
                "    prefix: /api/scheduling/\n    audience: person\n    signIns: [citizen]\n",
            );
        let config = load(&text).expect("valid document");
        assert_eq!(
            config.audience_set("staff"),
            ["https://casework.example/api"]
        );
    }

    #[test]
    fn routes_take_the_longest_prefix_across_modules_and_pages() {
        let text = document().replace(
            "pages:\n",
            "pages:\n  - prefix: /api/casework/docs/\n    signIn: staff\n",
        );
        let config = load(&text).expect("valid document");
        let module = |path: &str| match config.route(path) {
            Some(Route::Module(module)) => module.id.as_str().to_owned(),
            other => panic!("{path}: {other:?}"),
        };
        assert_eq!(module("/api/registry/records/1"), "registry");
        assert_eq!(module("/api/casework/tasks"), "casework");
        assert!(matches!(
            config.route("/api/casework/docs/a.html"),
            Some(Route::Page(page)) if page.sign_in.as_str() == "staff"
        ));
        assert!(matches!(config.route("/apply/form"), Some(Route::Page(_))));
        assert!(config.route("/api/registry").is_none());
        assert!(config.route("/api/unknown/").is_none());
        assert!(config.route("/session/sign-in").is_none());
    }

    #[test]
    fn who_am_i_claims_are_a_closed_list_without_token_claims() {
        let with = |claims: &str| format!("{}whoAmI:\n  claims: {claims}\n", document());
        assert_eq!(
            load(&with("[sub, preferred_username]"))
                .expect("claims")
                .who_am_i
                .claim_names(),
            ["sub", "preferred_username"]
        );
        assert!(load(&with("[]"))
            .expect("none")
            .who_am_i
            .claim_names()
            .is_empty());
        for token_claim in ["at_hash", "nonce", "iss", "aud", "exp", "c_hash", "sid"] {
            refused(
                &with(&format!("[sub, {token_claim}]")),
                &code("token-claim"),
                "/whoAmI/claims/1",
            );
        }
        refused(
            &with("[sub, sub]"),
            "config.duplicate-item",
            "/whoAmI/claims/1",
        );
        refused(&with("['a b']"), "config.invalid-value", "/whoAmI/claims/0");
    }

    #[test]
    fn scopes_are_unique_bounded_and_exclude_openid() {
        let scopes =
            |list: &str| document().replace("scopes: [registry:read]", &format!("scopes: {list}"));
        load(&scopes("[]")).expect("a kind may request no further scope");
        let seventeen = (0..17)
            .map(|index| format!("s{index}"))
            .collect::<Vec<_>>()
            .join(", ");
        refused(
            &scopes(&format!("[{seventeen}]")),
            "config.invalid-length",
            "/signIns/citizen/scopes",
        );
        refused(
            &scopes("[a, a]"),
            "config.duplicate-item",
            "/signIns/citizen/scopes/1",
        );
        refused(
            &scopes("[\"a b\"]"),
            "config.invalid-value",
            "/signIns/citizen/scopes/0",
        );
        refused(
            &scopes("[a, openid]"),
            &code("openid-scope"),
            "/signIns/citizen/scopes/1",
        );
    }

    #[test]
    fn sign_in_kinds_are_local_identifiers() {
        refused(
            &document().replace("  citizen:\n", "  Citizen:\n"),
            "config.invalid-value",
            "/signIns/Citizen",
        );
    }

    #[test]
    fn cookie_names_follow_the_declared_transport() {
        let production = load(&document()).expect("production");
        assert_eq!(production.session_cookie(), "__Host-registry-session");
        assert_eq!(production.flow_cookie(), "__Host-registry-signin");
        let development = load(&development()).expect("development");
        assert_eq!(development.session_cookie(), "registry-session");
        assert_eq!(development.flow_cookie(), "registry-signin");
    }

    #[test]
    fn stdout_refuses_file_only_audit_settings() {
        refused(
            &document().replace(
                "  path: /var/lib/session/audit.jsonl\n",
                "  path: /var/lib/session/audit.jsonl\n  destination: stdout\n",
            ),
            &code("file-only-audit-member"),
            "/audit/path",
        );
    }
}
