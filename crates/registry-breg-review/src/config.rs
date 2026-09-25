// SPDX-License-Identifier: Apache-2.0

//! The operator runtime configuration document.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

use registry_platform_config::{
    SecretError, SecretProvider, SecretReference, SecretResolver, MAX_SECRET_BYTES,
};
use registry_platform_httputil::client::{valid_resource_uri, valid_scope_token};
use serde::Deserialize;
use thiserror::Error;
use url::Url;

pub const RUNTIME_API_VERSION: &str = "registry.registrystack.org/breg-review-runtime/v1alpha1";
pub const RUNTIME_KIND: &str = "BRegReviewRuntimeConfig";

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
    pub listener: ListenerConfig,
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
    "127.0.0.1:8115"
        .parse()
        .expect("valid review page listener default")
}

/// Declares the trusted transport boundary for the plaintext HTTP listener.
/// Production listeners require operator-controlled upstream TLS termination;
/// direct plaintext is limited to the explicit loopback-only development mode.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum TlsTermination {
    OperatorControlledUpstream,
    DevelopmentLoopback,
}

/// The operator-declared private network placement of the HTTP listener.
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
    pub path: PathBuf,
    pub hash_key_ref: String,
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
        if !path.as_ref().is_absolute() {
            return Err(RuntimeConfigError::RelativeRuntimePath);
        }
        let bytes = std::fs::read(path.as_ref()).map_err(RuntimeConfigError::Read)?;
        let deserializer = serde_norway::Deserializer::from_slice(&bytes);
        let config: Self = serde_path_to_error::deserialize(deserializer).map_err(|error| {
            let (path, cause) = refused_yaml(error);
            RuntimeConfigError::Parse { path, cause }
        })?;
        config.check()?;
        Ok(config)
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
        if self.api_version != RUNTIME_API_VERSION {
            return Err(RuntimeConfigError::InvalidApiVersion);
        }
        if self.kind != RUNTIME_KIND {
            return Err(RuntimeConfigError::InvalidKind);
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
        if self.secret_providers.file.is_none() && self.secret_providers.environment.is_none() {
            return Err(RuntimeConfigError::InvalidSecretProviders);
        }
        if !valid_listener(
            self.listener.bind.ip(),
            self.listener.network_exposure,
            self.listener.tls_termination,
        ) {
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
        self.validate_secret_references()
    }

    fn validate_secret_references(&self) -> Result<(), RuntimeConfigError> {
        for (path, raw) in [
            ("signIn.clientKeyRef", &self.sign_in.client_key_ref),
            ("audit.hashKeyRef", &self.audit.hash_key_ref),
        ] {
            let reference = SecretReference::parse(raw.clone())
                .map_err(|_| RuntimeConfigError::InvalidSecretReference { path })?;
            let enabled = match reference.provider() {
                SecretProvider::File => self.secret_providers.file.is_some(),
                SecretProvider::Environment => self.secret_providers.environment.is_some(),
            };
            if !enabled {
                return Err(RuntimeConfigError::SecretProviderRequired { path });
            }
        }
        Ok(())
    }

    /// Build the resolver for exactly the providers the document enables.
    pub fn secret_resolver(&self) -> Result<SecretResolver, RuntimeConfigError> {
        let mut providers = Vec::new();
        if self.secret_providers.file.is_some() {
            providers.push(SecretProvider::File);
        }
        if self.secret_providers.environment.is_some() {
            providers.push(SecretProvider::Environment);
        }
        SecretResolver::new(
            providers,
            self.secret_providers
                .file
                .as_ref()
                .map_or_else(|| Path::new(""), |file| file.root.as_path()),
        )
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

/// Explain a secret resolution failure with the configured reference and the
/// rule that broke, never the secret bytes.
pub(crate) fn describe_secret_failure(
    field: &'static str,
    reference: &str,
    error: &SecretError,
) -> String {
    let reason = match error {
        SecretError::InvalidReference => {
            "it is not an exact secret:env/NAME or secret:file/name reference".to_owned()
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
    format!("{field} {reference} could not be resolved: {reason}")
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

/// Name where a YAML document was refused and why, so an operator reading a
/// startup failure can open the document at the place that failed.
///
/// `serde_path_to_error` renders a refusal it never attributed to a member as
/// `.`, which names nothing an operator can look up, so a document refused
/// whole is reported at its root. The reason is serde's own, and carries the
/// line and column the reader stopped on.
fn refused_yaml(error: serde_path_to_error::Error<serde_norway::Error>) -> (String, String) {
    let path = error.path().to_string();
    let path = if path == "." { "/".to_owned() } else { path };
    (path, redact_refused_values(&error.into_inner().to_string()))
}

/// Keep the parts of a refusal an operator acts on, the member, the reason
/// and the location, while the refused value stays out of the message.
///
/// serde reports the offending value inside an `invalid type:` or an
/// `invalid value:` clause. Only the shape word that opens such a clause
/// survives, so the message still says a string arrived where a number was
/// required without repeating the string. A runtime configuration names
/// secret references and endpoints, and a startup refusal is written to the
/// operator's log.
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
/// the remainder that follows the refused value.
///
/// serde renders the value with `Debug`, so it opens with a quote or a
/// backtick and may hold the comma that would otherwise end the clause.
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

/// Return the offset just past the delimited run that opens at `open`.
///
/// A delimiter inside a `Debug` rendering arrives escaped, so it does not end
/// the run.
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

#[derive(Debug, Error)]
pub enum RuntimeConfigError {
    #[error("the review page runtime configuration could not be read")]
    Read(#[source] std::io::Error),
    #[error("the review page runtime configuration is not valid YAML at {path}: {cause}")]
    Parse { path: String, cause: String },
    #[error(
        "unsupported review page runtime apiVersion; expected registry.registrystack.org/breg-review-runtime/v1alpha1"
    )]
    InvalidApiVersion,
    #[error("unsupported review page runtime kind; expected BRegReviewRuntimeConfig")]
    InvalidKind,
    #[error("the operated runtime path {0} must be absolute")]
    RelativeOperatedPath(&'static str),
    #[error("the selected review page runtime configuration path must be absolute")]
    RelativeRuntimePath,
    #[error("secretProviders must explicitly enable file, environment, or both")]
    InvalidSecretProviders,
    #[error("{path} is not a valid secret reference; credentials are accepted only as secret:env/NAME or secret:file/name")]
    InvalidSecretReference { path: &'static str },
    #[error("{path} uses a secret provider that is not explicitly enabled")]
    SecretProviderRequired { path: &'static str },
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
            Self::InvalidApiVersion => "apiVersion",
            Self::InvalidKind => "kind",
            Self::RelativeOperatedPath(path) => path,
            Self::RelativeRuntimePath | Self::Read(_) => "/",
            Self::Parse { path, .. } => path,
            Self::InvalidSecretProviders => "secretProviders",
            Self::InvalidSecretReference { path } | Self::SecretProviderRequired { path } => path,
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
        RuntimeConfig::load(&path)
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
    fn an_omitted_bind_listens_beside_the_gateway_not_on_its_port() {
        let development = document(&[
            ("tls", "development-loopback"),
            ("origin", "http://127.0.0.1:8115"),
            ("issuer", "http://127.0.0.1:9000"),
            ("baseUrl", "http://127.0.0.1:9100/base"),
        ]);
        let omitted = development.replace("  bind: \"10.0.0.5:8115\"\n", "");
        assert_ne!(omitted, development);
        let config = load(&omitted).expect("development without a bind");
        assert_eq!(
            config.listener.bind,
            "127.0.0.1:8115".parse::<SocketAddr>().unwrap()
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
