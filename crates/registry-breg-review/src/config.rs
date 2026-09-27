// SPDX-License-Identifier: Apache-2.0

//! The operator runtime configuration document.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use registry_platform_audit::{AuditDestination, AuditDestinationError, AuditDestinationKind};
pub(crate) use registry_platform_config::describe_secret_failure;
use registry_platform_config::{
    AuditKeyConfig, ConfigBlockError, PrivateListenerConfig, RuntimeConfigLoader, RuntimeEnvelope,
    SecretProvidersConfig, SecretResolver, TlsTermination,
};
use registry_platform_httputil::client::{valid_resource_uri, valid_scope_token};
use serde::Deserialize;
use thiserror::Error;
use url::Url;

pub const RUNTIME_API_VERSION: &str = "registry.registrystack.org/breg-review-runtime/v1alpha1";
pub const RUNTIME_KIND: &str = "BRegReviewRuntimeConfig";

/// The envelope every review-page runtime configuration carries.
pub const RUNTIME_ENVELOPE: RuntimeEnvelope = RuntimeEnvelope {
    api_version: RUNTIME_API_VERSION,
    kind: RUNTIME_KIND,
};

/// The path the authorization server returns a person to after sign-in,
/// relative to `publicOrigin`.
pub const CALLBACK_PATH: &str = "/signin/callback";

const MAXIMUM_SCOPES: usize = 16;
const MAXIMUM_IDENTIFIER_BYTES: usize = 128;

/// The operator runtime configuration document.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeConfig {
    pub api_version: String,
    pub kind: String,
    pub listener: PrivateListenerConfig,
    /// The browser-facing origin, such as `https://review.example`. The
    /// sign-in redirect URI is this origin with `/signin/callback`.
    pub public_origin: String,
    pub secret_providers: SecretProvidersConfig,
    pub sign_in: SignInConfig,
    pub registry: RegistryConfig,
    pub audit: AuditConfig,
    #[serde(default)]
    pub limits: LimitsConfig,
    #[serde(default)]
    pub session: SessionConfig,
}

/// The OpenID Provider the page signs people in with, and the confidential
/// client it authenticates as.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SignInConfig {
    pub issuer: String,
    pub client_id: String,
    /// A `secret:env/` or `secret:file/` reference to the client's private
    /// JWK, used for `private_key_jwt` client authentication.
    pub client_key_ref: String,
    /// Scopes requested beside `openid`, such as the review scope the
    /// registry profile requires.
    pub scopes: Vec<String>,
}

/// The Base Registry Engine deployment and the one access profile the page
/// reads and submits through.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RegistryConfig {
    pub base_url: String,
    /// The RFC 8707 resource indicator the person's access token names.
    pub resource: String,
    /// The change-request entity identifier.
    pub entity: String,
    /// The reference field naming the record the request changes. The page
    /// reads that record under the person's own token before it offers the
    /// submit form, because the registry does not tie a request's target to
    /// its requester.
    pub target_field: String,
    pub access_profile: String,
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
        .map_err(RuntimeConfigError::InvalidAuditDestination)
    }
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RateConfig {
    pub requests_per_minute: u32,
    pub burst: u32,
}

/// The page's own request limits. It reads neither peer addresses nor
/// forwarded headers, so it cannot tell one browser from another before
/// sign-in: a per-client limit belongs at the edge proxy.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct LimitsConfig {
    /// One limit for each signed-in person, shared by all their sessions,
    /// on every request that presents a session.
    #[serde(default = "default_per_citizen")]
    pub per_citizen: RateConfig,
    /// One limit shared by everyone on the unauthenticated sign-in routes,
    /// `/signin` and `/signin/callback`.
    #[serde(default = "default_global_sign_in")]
    pub global_sign_in: RateConfig,
}

impl Default for LimitsConfig {
    fn default() -> Self {
        Self {
            per_citizen: default_per_citizen(),
            global_sign_in: default_global_sign_in(),
        }
    }
}

const fn default_per_citizen() -> RateConfig {
    RateConfig {
        requests_per_minute: 120,
        burst: 30,
    }
}

const fn default_global_sign_in() -> RateConfig {
    RateConfig {
        requests_per_minute: 600,
        burst: 120,
    }
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionConfig {
    #[serde(default = "default_maximum_sessions")]
    pub maximum_sessions: usize,
    #[serde(default = "default_maximum_pending_sign_ins")]
    pub maximum_pending_sign_ins: usize,
    /// The longest a session lasts. A session also ends when the access
    /// token it holds expires, whichever comes first.
    #[serde(default = "default_maximum_lifetime_seconds")]
    pub maximum_lifetime_seconds: u64,
    /// How long a started sign-in may take to return from the provider.
    #[serde(default = "default_sign_in_lifetime_seconds")]
    pub sign_in_lifetime_seconds: u64,
}

impl Default for SessionConfig {
    fn default() -> Self {
        Self {
            maximum_sessions: default_maximum_sessions(),
            maximum_pending_sign_ins: default_maximum_pending_sign_ins(),
            maximum_lifetime_seconds: default_maximum_lifetime_seconds(),
            sign_in_lifetime_seconds: default_sign_in_lifetime_seconds(),
        }
    }
}

const fn default_maximum_sessions() -> usize {
    10_000
}

const fn default_maximum_pending_sign_ins() -> usize {
    10_000
}

const fn default_maximum_lifetime_seconds() -> u64 {
    3600
}

const fn default_sign_in_lifetime_seconds() -> u64 {
    600
}

impl RuntimeConfig {
    /// Load and validate the operator document.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, RuntimeConfigError> {
        let loaded = Self::loader().load::<Self>(path.as_ref())?;
        loaded.config.check()?;
        Ok(loaded.config)
    }

    /// The shared loader under the review page's exact envelope.
    #[must_use]
    pub const fn loader() -> RuntimeConfigLoader {
        RuntimeConfigLoader::new(RUNTIME_ENVELOPE)
    }

    /// Whether the document declares the loopback-only development mode.
    #[must_use]
    pub fn development(&self) -> bool {
        self.listener.tls_termination == TlsTermination::DevelopmentLoopback
    }

    /// The validated browser-facing origin, without a trailing slash.
    #[must_use]
    pub fn origin(&self) -> String {
        self.public_origin.trim_end_matches('/').to_owned()
    }

    /// The exact redirect URI registered with the provider.
    pub fn redirect_uri(&self) -> Result<Url, RuntimeConfigError> {
        Url::parse(&format!("{}{CALLBACK_PATH}", self.origin()))
            .map_err(|_| RuntimeConfigError::InvalidPublicOrigin)
    }

    pub fn check(&self) -> Result<(), RuntimeConfigError> {
        self.secret_providers.check()?;
        self.audit.destination()?;
        if !self.listener.is_valid() {
            return Err(RuntimeConfigError::InvalidListener);
        }
        let development = self.development();
        let origin =
            Url::parse(&self.public_origin).map_err(|_| RuntimeConfigError::InvalidPublicOrigin)?;
        if !allowed_endpoint(&origin, development)
            || origin.path() != "/"
            || origin.query().is_some()
            || origin.fragment().is_some()
        {
            return Err(RuntimeConfigError::InvalidPublicOrigin);
        }
        let issuer =
            Url::parse(&self.sign_in.issuer).map_err(|_| RuntimeConfigError::InvalidSignIn)?;
        if !allowed_endpoint(&issuer, development)
            || issuer.query().is_some()
            || issuer.fragment().is_some()
            || !valid_client_id(&self.sign_in.client_id)
            || self.sign_in.scopes.is_empty()
            || self.sign_in.scopes.len() > MAXIMUM_SCOPES
        {
            return Err(RuntimeConfigError::InvalidSignIn);
        }
        let mut scopes = BTreeSet::new();
        for scope in &self.sign_in.scopes {
            if !valid_scope_token(scope) || scope == "openid" || !scopes.insert(scope) {
                return Err(RuntimeConfigError::InvalidSignIn);
            }
        }
        let base =
            Url::parse(&self.registry.base_url).map_err(|_| RuntimeConfigError::InvalidRegistry)?;
        if !allowed_endpoint(&base, development)
            || base.query().is_some()
            || base.fragment().is_some()
            || !valid_resource_uri(&self.registry.resource)
            || !valid_identifier(&self.registry.entity)
            || !valid_identifier(&self.registry.target_field)
            || !valid_identifier(&self.registry.access_profile)
        {
            return Err(RuntimeConfigError::InvalidRegistry);
        }
        for rate in [self.limits.per_citizen, self.limits.global_sign_in] {
            if rate.requests_per_minute == 0 || rate.burst == 0 {
                return Err(RuntimeConfigError::InvalidLimits);
            }
        }
        let session = self.session;
        if !(1..=1_000_000).contains(&session.maximum_sessions)
            || !(1..=1_000_000).contains(&session.maximum_pending_sign_ins)
            || !(60..=86_400).contains(&session.maximum_lifetime_seconds)
            || !(60..=3600).contains(&session.sign_in_lifetime_seconds)
        {
            return Err(RuntimeConfigError::InvalidSession);
        }
        // Every sign-in the global limit admits stays pending for up to its
        // lifetime, so the store must hold them all. A store the limit could
        // fill would keep refusing sign-ins long after the limit refilled.
        let global = self.limits.global_sign_in;
        let admitted = u64::from(global.burst)
            + (u64::from(global.requests_per_minute) * session.sign_in_lifetime_seconds)
                .div_ceil(60);
        if (session.maximum_pending_sign_ins as u64) < admitted {
            return Err(RuntimeConfigError::PendingSignInsFillable { admitted });
        }
        self.secret_providers
            .check_reference("signIn.clientKeyRef", &self.sign_in.client_key_ref)?;
        self.audit.key.check(&self.secret_providers)?;
        Ok(())
    }

    /// Build the resolver for exactly the providers the document enables.
    pub fn secret_resolver(&self) -> Result<SecretResolver, RuntimeConfigError> {
        self.secret_providers
            .resolver()
            .map_err(|_| RuntimeConfigError::InvalidSecretProviders)
    }
}

/// An endpoint is HTTPS, or plain HTTP on a loopback host in development.
/// Userinfo is never accepted.
fn allowed_endpoint(url: &Url, development: bool) -> bool {
    if !url.username().is_empty() || url.password().is_some() || url.host().is_none() {
        return false;
    }
    match url.scheme() {
        "https" => true,
        "http" => development && is_loopback_host(url),
        _ => false,
    }
}

fn is_loopback_host(url: &Url) -> bool {
    match url.host() {
        Some(url::Host::Ipv4(address)) => address.is_loopback(),
        Some(url::Host::Ipv6(address)) => address.is_loopback(),
        Some(url::Host::Domain(domain)) => domain == "localhost",
        None => false,
    }
}

/// Whether `url` is an endpoint the runtime may call for this mode.
pub(crate) fn allowed_discovered_endpoint(url: &Url, development: bool) -> bool {
    allowed_endpoint(url, development) && url.fragment().is_none()
}

fn valid_client_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 256 && value.bytes().all(|byte| byte.is_ascii_graphic())
}

fn valid_identifier(value: &str) -> bool {
    let bytes = value.as_bytes();
    matches!(bytes.first(), Some(b'a'..=b'z'))
        && bytes.len() <= MAXIMUM_IDENTIFIER_BYTES
        && bytes.iter().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_' | b'.')
        })
}

#[derive(Debug, Error)]
pub enum RuntimeConfigError {
    #[error(transparent)]
    Load(#[from] registry_platform_config::RuntimeConfigError),
    #[error(transparent)]
    Block(#[from] ConfigBlockError),
    #[error("secretProviders must explicitly enable file, environment, or both")]
    InvalidSecretProviders,
    #[error("{0}")]
    InvalidAuditDestination(#[source] AuditDestinationError),
    #[error("listener is not valid for its declared TLS termination and network exposure")]
    InvalidListener,
    #[error("publicOrigin must be an https origin with no path, query, or userinfo; plain http is accepted only on loopback in development")]
    InvalidPublicOrigin,
    #[error("signIn is invalid: the issuer must be https (loopback http only in development), the client id visible ASCII, and scopes unique valid tokens other than openid")]
    InvalidSignIn,
    #[error("registry is invalid: the base URL must be https (loopback http only in development), the resource an absolute URI, and the entity, target field, and access profile identifiers")]
    InvalidRegistry,
    #[error("limits must admit at least one request per minute and a burst of at least one")]
    InvalidLimits,
    #[error("session bounds are outside their accepted ranges")]
    InvalidSession,
    #[error("session.maximumPendingSignIns must hold every sign-in limits.globalSignIn admits within session.signInLifetimeSeconds: at least {admitted}")]
    PendingSignInsFillable { admitted: u64 },
}

impl RuntimeConfigError {
    #[must_use]
    pub fn path(&self) -> &str {
        match self {
            Self::Load(error) => error.field(),
            Self::Block(error) => error.field(),
            Self::InvalidSecretProviders => "secretProviders",
            Self::InvalidAuditDestination(error) => match error {
                AuditDestinationError::MissingPath | AuditDestinationError::RelativePath => {
                    "audit.path"
                }
                AuditDestinationError::FileOnlyField { field: "path" } => "audit.path",
                AuditDestinationError::FileOnlyField {
                    field: "rotateBytes",
                }
                | AuditDestinationError::RotateBytesOutOfRange { .. } => "audit.rotateBytes",
                AuditDestinationError::FileOnlyField {
                    field: "retainDays",
                }
                | AuditDestinationError::RetainDaysOutOfRange { .. } => "audit.retainDays",
                _ => "audit",
            },
            Self::InvalidListener => "listener",
            Self::InvalidPublicOrigin => "publicOrigin",
            Self::InvalidSignIn => "signIn",
            Self::InvalidRegistry => "registry",
            Self::InvalidLimits => "limits",
            Self::InvalidSession => "session",
            Self::PendingSignInsFillable { .. } => "session.maximumPendingSignIns",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn document(overrides: &[(&str, &str)]) -> String {
        let mut values = vec![
            ("tls", "operator-controlled-upstream"),
            ("bind", "10.0.0.5:8115"),
            ("origin", "https://review.example"),
            ("issuer", "https://id.example"),
            ("clientKeyRef", "secret:file/client-key.jwk"),
            ("hashKeyRef", "secret:env/BREG_REVIEW_AUDIT_KEY"),
            ("baseUrl", "https://registry.example/base"),
            ("scopes", "[address-correction:self]"),
            ("targetField", "address"),
        ];
        for (key, value) in overrides {
            let slot = values
                .iter_mut()
                .find(|(candidate, _)| candidate == key)
                .expect("known override");
            slot.1 = value;
        }
        let value = |key: &str| {
            values
                .iter()
                .find(|(candidate, _)| *candidate == key)
                .map(|(_, value)| *value)
                .expect("known key")
        };
        format!(
            "apiVersion: {RUNTIME_API_VERSION}\n\
             kind: {RUNTIME_KIND}\n\
             listener:\n  bind: \"{bind}\"\n  tlsTermination: {tls}\n\
             publicOrigin: {origin}\n\
             secretProviders:\n  file:\n    root: /run/secrets\n  environment: {{}}\n\
             signIn:\n  issuer: {issuer}\n  clientId: citizen-review-page\n  clientKeyRef: '{client_key}'\n  scopes: {scopes}\n\
             registry:\n  baseUrl: {base}\n  resource: https://registry.example/base\n  entity: address-correction-request\n  targetField: {target}\n  accessProfile: citizen-review\n\
             audit:\n  path: /var/lib/breg-review/audit.jsonl\n  hashKeyRef: {hash}\n",
            bind = value("bind"),
            tls = value("tls"),
            origin = value("origin"),
            issuer = value("issuer"),
            client_key = value("clientKeyRef"),
            scopes = value("scopes"),
            base = value("baseUrl"),
            hash = value("hashKeyRef"),
            target = value("targetField"),
        )
    }

    fn load(text: &str) -> Result<RuntimeConfig, RuntimeConfigError> {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("runtime.yaml");
        std::fs::write(&path, text).expect("write runtime document");
        RuntimeConfig::load(path.canonicalize().expect("runtime path canonicalizes"))
    }

    #[test]
    fn a_production_document_loads_with_its_defaults() {
        let config = load(&document(&[])).expect("valid document");
        assert!(!config.development());
        assert_eq!(
            config.redirect_uri().unwrap().as_str(),
            "https://review.example/signin/callback"
        );
        assert_eq!(config.session.maximum_sessions, 10_000);
        assert_eq!(config.limits.per_citizen.requests_per_minute, 120);
    }

    #[test]
    fn the_global_sign_in_cap_cannot_fill_the_pending_store() {
        // 600 starts a minute over a 600-second sign-in lifetime, plus the
        // burst, is 6120 sign-ins in flight at most.
        let with = |pending: usize| {
            format!(
                "{}limits:\n  globalSignIn: {{ requestsPerMinute: 600, burst: 120 }}\n\
                 session:\n  maximumPendingSignIns: {pending}\n  signInLifetimeSeconds: 600\n",
                document(&[])
            )
        };
        let error = load(&with(6119)).expect_err("a store the cap can fill");
        assert_eq!(error.path(), "session.maximumPendingSignIns");
        assert!(error.to_string().contains("6120"), "{error}");
        load(&with(6120)).expect("a store the cap cannot fill");
    }

    #[test]
    fn a_per_address_limit_is_not_accepted() {
        let text = format!(
            "{}limits:\n  perAddress: {{ requestsPerMinute: 600, burst: 120 }}\n",
            document(&[])
        );
        assert!(load(&text).is_err());
    }

    #[test]
    fn an_inline_credential_is_refused_without_echoing_it() {
        let canary = "{\"kty\":\"OKP\",\"d\":\"inline-canary-value\"}";
        let error = load(&document(&[("clientKeyRef", canary)])).expect_err("inline key");
        assert_eq!(error.path(), "signIn.clientKeyRef");
        let message = error.to_string();
        assert!(!message.contains("inline-canary-value"), "{message}");
        assert!(message.contains("secret:env/NAME or secret:file/name"));
    }

    #[test]
    fn runtime_loader_refuses_environment_expressions_in_secret_references() {
        let base = document(&[]);
        for (text, field) in [
            (
                base.replace(
                    "clientKeyRef: 'secret:file/client-key.jwk'",
                    "clientKeyRef: '${CLIENT_KEY_REF}'",
                ),
                "signIn.clientKeyRef",
            ),
            (
                base.replace("root: /run/secrets", "root: ${SECRET_ROOT}"),
                "secretProviders.file.root",
            ),
        ] {
            let error = RuntimeConfig::loader()
                .parse_str::<RuntimeConfig>(&text, |_| Some("withheld".to_owned()))
                .expect_err("secret-bearing fields do not substitute");
            assert_eq!(
                error.kind(),
                registry_platform_config::RuntimeConfigErrorKind::SubstitutionInReference
            );
            assert_eq!(error.field(), field);
        }
    }

    #[test]
    fn runtime_loader_substitutes_an_ordinary_endpoint() {
        let text = document(&[]).replace(
            "publicOrigin: https://review.example",
            "publicOrigin: ${PUBLIC_ORIGIN}",
        );
        let loaded = RuntimeConfig::loader()
            .parse_str::<RuntimeConfig>(&text, |name| {
                (name == "PUBLIC_ORIGIN").then(|| "https://review.example".to_owned())
            })
            .expect("ordinary deployment setting substitutes");
        loaded.config.check().expect("substituted document checks");
    }

    #[test]
    fn runtime_loader_enforces_structure_envelope_and_size_bounds() {
        for (text, expected) in [
            (
                document(&[]).replace(
                    &format!("apiVersion: {RUNTIME_API_VERSION}\n"),
                    "apiVersion: unsupported/v1\n",
                ),
                registry_platform_config::RuntimeConfigErrorKind::Envelope,
            ),
            (
                format!("{}kind: {RUNTIME_KIND}\n", document(&[])),
                registry_platform_config::RuntimeConfigErrorKind::Syntax,
            ),
            (
                "apiVersion: [unterminated\n".to_owned(),
                registry_platform_config::RuntimeConfigErrorKind::Syntax,
            ),
        ] {
            let error = RuntimeConfig::loader()
                .parse_str::<RuntimeConfig>(&text, |_| None)
                .expect_err("invalid structure or envelope");
            assert_eq!(error.kind(), expected, "{text}");
        }

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("oversized.yaml");
        let oversized = format!(
            "{}\n# {}",
            document(&[]),
            "x".repeat(registry_platform_config::DEFAULT_MAX_RUNTIME_CONFIG_BYTES as usize)
        );
        std::fs::write(&path, oversized).unwrap();
        let error =
            RuntimeConfig::load(path.canonicalize().unwrap()).expect_err("oversized document");
        let RuntimeConfigError::Load(error) = error else {
            panic!("shared loader should refuse the size bound")
        };
        assert_eq!(
            error.kind(),
            registry_platform_config::RuntimeConfigErrorKind::Bounds
        );
    }

    #[test]
    fn a_refused_value_never_survives_the_parse_error() {
        let text = document(&[]).replace("clientId: citizen-review-page", "clientId: [x-canary]");
        let error = load(&text).expect_err("sequence where a string belongs");
        assert!(!error.to_string().contains("x-canary"), "{error}");
    }

    #[test]
    fn plaintext_endpoints_are_development_loopback_only() {
        for (key, value) in [
            ("origin", "http://review.example"),
            ("issuer", "http://id.example"),
            ("baseUrl", "http://registry.example/base"),
        ] {
            assert!(load(&document(&[(key, value)])).is_err(), "{key}");
        }
        let development = document(&[
            ("tls", "development-loopback"),
            ("bind", "127.0.0.1:8115"),
            ("origin", "http://127.0.0.1:8115"),
            ("issuer", "http://127.0.0.1:9000"),
            ("baseUrl", "http://127.0.0.1:9100/base"),
        ]);
        assert!(load(&development).expect("development").development());
        let exposed = development.replace("127.0.0.1:8115\"", "0.0.0.0:8115\"");
        assert_eq!(load(&exposed).expect_err("exposed").path(), "listener");
    }

    #[test]
    fn the_shared_listener_requires_an_explicit_bind() {
        let development = document(&[
            ("tls", "development-loopback"),
            ("origin", "http://127.0.0.1:8115"),
            ("issuer", "http://127.0.0.1:9000"),
            ("baseUrl", "http://127.0.0.1:9100/base"),
        ]);
        let omitted = development.replace("  bind: \"10.0.0.5:8115\"\n", "");
        assert_ne!(omitted, development);
        assert_eq!(load(&omitted).expect_err("missing bind").path(), "listener");
    }

    #[test]
    fn the_shared_listener_preserves_ipv6_exposure_rules() {
        let production_ula =
            document(&[]).replace("bind: \"10.0.0.5:8115\"", "bind: \"[fd00::15]:8115\"");
        load(&production_ula).expect("a private production IPv6 address");

        let development = document(&[
            ("tls", "development-loopback"),
            ("bind", "[::1]:8115"),
            ("origin", "http://[::1]:8115"),
            ("issuer", "http://[::1]:9000"),
            ("baseUrl", "http://[::1]:9100/base"),
        ]);
        load(&development).expect("IPv6 loopback development");
        let exposed = development.replace("bind: \"[::1]:8115\"", "bind: \"[::]:8115\"");
        assert_eq!(
            load(&exposed).expect_err("public development bind").path(),
            "listener"
        );
    }

    #[test]
    fn the_public_origin_is_an_origin_only() {
        for origin in [
            "https://review.example/path",
            "https://review.example/?q=1",
            "https://user@review.example",
        ] {
            assert_eq!(
                load(&document(&[("origin", origin)]))
                    .expect_err("not an origin")
                    .path(),
                "publicOrigin"
            );
        }
    }

    #[test]
    fn the_target_field_is_a_field_identifier() {
        let config = load(&document(&[])).expect("valid document");
        assert_eq!(config.registry.target_field, "address");
        for target in ["''", "Address", "new address", "\"../address\""] {
            assert_eq!(
                load(&document(&[("targetField", target)]))
                    .expect_err("invalid target field")
                    .path(),
                "registry",
                "{target}"
            );
        }
        let missing = document(&[]).replace("  targetField: address\n", "");
        assert!(load(&missing).is_err());
    }

    #[test]
    fn scopes_are_unique_and_exclude_openid() {
        for scopes in ["[]", "[openid]", "[a, a]", "[\"a b\"]"] {
            assert_eq!(
                load(&document(&[("scopes", scopes)]))
                    .expect_err("invalid scopes")
                    .path(),
                "signIn"
            );
        }
    }
}
