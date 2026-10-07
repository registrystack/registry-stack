// SPDX-License-Identifier: Apache-2.0

//! The operator runtime configuration document and the package it names.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use jsonwebtoken::Algorithm;
use registry_messaging_core::{
    ProviderKind, MESSAGING_RUNTIME_API_VERSION, MESSAGING_RUNTIME_KIND, PACKAGE_FILE,
};
use registry_platform_audit::{AuditDestination, AuditDestinationError, AuditDestinationKind};
use registry_platform_config::{
    AuditKeyConfig, ConfigBlockError, RuntimeConfigLoader, RuntimeEnvelope, SecretResolver,
    REMOVED_OIDC_JWKS_URI,
};
pub use registry_platform_config::{
    DatabaseConfig, EnvironmentSecretProviderConfig, FileSecretProviderConfig,
    JwksSource as OidcJwksSource, ListenerConfig as MetricsListenerConfig, ListenerNetworkExposure,
    OidcClientsConfig, OidcIssuerConfig, PackageConfig as RuntimePackageConfig,
    PrivateListenerConfig as ListenerConfig,
    RuntimeConfigErrorKind as SharedRuntimeConfigErrorKind, SecretProvidersConfig, TlsTermination,
    MAX_ASSERTION_ISSUERS_PER_CLIENT as MAXIMUM_ASSERTION_ISSUERS_PER_CLIENT,
    MAX_ASSERTION_ISSUER_BYTES as MAXIMUM_ASSERTION_ISSUER_BYTES,
    MAX_ASSERTION_ISSUER_CLIENTS as MAXIMUM_ASSERTION_ISSUER_CLIENTS,
    MAX_ASSERTION_ISSUER_CLIENT_BYTES as MAXIMUM_ASSERTION_ISSUER_CLIENT_BYTES,
};
use registry_platform_oidc::{
    access_token_typ_set, fetch_discovery, parse_static_jwks, JwksFetcher, JwksFetcherConfig,
    OidcDiscoveryConfig, TokenVerifierConfig,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::http_provider::HttpProviderSettings;
use crate::package::{load_runtime_package, LoadedPackage, PackageLoadError};
use crate::smtp::SmtpProviderSettings;

pub(crate) use registry_platform_config::describe_secret_failure;

/// The configuration name of a provider kind.
pub(crate) const fn provider_kind_name(kind: ProviderKind) -> &'static str {
    match kind {
        ProviderKind::Smtp => "smtp",
        ProviderKind::Http => "http",
    }
}

/// The largest runtime document or package document the runtime reads.
const MAXIMUM_DOCUMENT_BYTES: u64 = 1024 * 1024;

/// The default listener binding. Each Registry Stack runtime has its own
/// default port so a laptop can run several side by side.
pub const DEFAULT_LISTENER_BIND: &str = "127.0.0.1:8107";

/// The RFC 9068 access-token media type this runtime verifies. The pair of
/// spellings it admits is derived, never authored, so no deployment can widen
/// it to an ordinary JWT.
const MESSAGING_ACCESS_TOKEN_TYPE: &str = "at+jwt";

pub const MESSAGING_RUNTIME_ENVELOPE: RuntimeEnvelope = RuntimeEnvelope {
    api_version: MESSAGING_RUNTIME_API_VERSION,
    kind: MESSAGING_RUNTIME_KIND,
};

pub const MESSAGING_REMOVED_KEYS: &[registry_platform_config::RemovedKey] =
    &[REMOVED_OIDC_JWKS_URI];

/// Retention defaults and bounds. A jurisdiction's retention schedule
/// approves the deployed values; the bounds only keep a typo from becoming a
/// policy.
pub const DEFAULT_PAYLOAD_DAYS: u16 = 7;
pub const MAXIMUM_PAYLOAD_DAYS: u16 = 30;
pub const DEFAULT_RECORD_DAYS: u16 = 90;
pub const MAXIMUM_RECORD_DAYS: u16 = 3650;
pub const DEFAULT_SUBMISSION_RECEIPT_DAYS: u16 = 7;

/// The most trust profiles one runtime document declares.
pub const MAXIMUM_TLS_TRUST_PROFILES: usize = 64;

/// The operator runtime configuration document.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeConfig {
    pub api_version: String,
    pub kind: String,
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(required, with = "IdentityConfig"))]
    pub identity: Option<IdentityConfig>,
    pub package: RuntimePackageConfig,
    pub listener: ListenerConfig,
    #[serde(default)]
    pub metrics_listener: Option<MetricsListenerConfig>,
    pub secret_providers: SecretProvidersConfig,
    pub database: DatabaseConfig,
    pub authentication: AuthenticationConfig,
    pub audit: AuditConfig,
    #[serde(default)]
    pub retention: RetentionConfig,
    /// The runtime half of each package provider, by provider id: where the
    /// provider is and how the runtime authenticates to it. A package
    /// provider with no entry has no transport, and its messages fail with
    /// `provider-unconfigured`.
    #[serde(default)]
    pub providers: BTreeMap<String, ProviderConnection>,
    /// Named PEM bundles an `http` provider's `tlsTrustProfile` trusts in
    /// addition to the system roots.
    #[serde(default)]
    pub tls_trust_profiles: BTreeMap<String, TlsTrustProfileConfig>,
}

/// The logical database identity this deployment owns. It is independent of
/// the connection URL and PostgreSQL database name.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityConfig {
    #[cfg_attr(feature = "schema", schemars(length(min = 1, max = 256)))]
    pub database_id: String,
}

/// One provider's runtime half. The package declares the provider's kind,
/// and for an `http` provider its scripts; the two halves must name the same
/// kind.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum ProviderConnection {
    Smtp(SmtpProviderSettings),
    /// Boxed: an `http` connection is several times the size of an `smtp`
    /// one.
    Http(Box<HttpProviderSettings>),
}

impl ProviderConnection {
    /// The provider kind this connection is for.
    #[must_use]
    pub const fn kind(&self) -> ProviderKind {
        match self {
            Self::Smtp(_) => ProviderKind::Smtp,
            Self::Http(_) => ProviderKind::Http,
        }
    }

    /// Every secret reference the connection names, with the member naming
    /// it.
    #[must_use]
    pub fn secret_references(&self) -> Vec<(&'static str, &str)> {
        match self {
            Self::Smtp(settings) => settings.secret_references(),
            Self::Http(settings) => settings.secret_references(),
        }
    }
}

/// A PEM bundle of one or more certificate authorities, held in the secret
/// provider so it is read under the same file checks as every credential.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TlsTrustProfileConfig {
    pub bundle_ref: String,
}

impl std::fmt::Debug for TlsTrustProfileConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TlsTrustProfileConfig")
            .field("bundle_ref", &"<redacted>")
            .finish()
    }
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthenticationConfig {
    pub oidc: OidcConfig,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OidcConfig {
    /// The exact token issuer, audience, and signing-key source.
    #[serde(flatten)]
    pub provider: OidcIssuerConfig,
    /// The OAuth clients this runtime admits. Every access profile resolves
    /// its caller from the matched client, so the list is never empty, and
    /// every client a profile names must appear here.
    #[serde(flatten)]
    pub clients: OidcClientsConfig,
    #[serde(default = "default_scope_claim")]
    pub scope_claim: String,
}

fn default_scope_claim() -> String {
    "registry_scopes".to_owned()
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
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

/// Retention periods the retention sweep enforces. Every value is deployment
/// configuration: a jurisdiction's retention schedule approves the deployed
/// numbers, and the audit journal records them at startup.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetentionConfig {
    /// How long a message's rendered payload and recipient contact are kept,
    /// from 1 to 30 days.
    #[serde(default = "default_payload_days")]
    pub payload_days: u16,
    /// How long the content-free message record is kept, at least as long as
    /// the payload and at most ten years.
    #[serde(default = "default_record_days")]
    pub record_days: u16,
    /// How long a submission receipt stays replayable under its idempotency
    /// key, from one day to the record period.
    #[serde(default = "default_submission_receipt_days")]
    pub submission_receipt_days: u16,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            payload_days: DEFAULT_PAYLOAD_DAYS,
            record_days: DEFAULT_RECORD_DAYS,
            submission_receipt_days: DEFAULT_SUBMISSION_RECEIPT_DAYS,
        }
    }
}

const fn default_payload_days() -> u16 {
    DEFAULT_PAYLOAD_DAYS
}

const fn default_record_days() -> u16 {
    DEFAULT_RECORD_DAYS
}

const fn default_submission_receipt_days() -> u16 {
    DEFAULT_SUBMISSION_RECEIPT_DAYS
}

impl RuntimeConfig {
    /// Load and validate the operator document at an absolute path, reading
    /// `${VAR}` expressions from the process environment.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, RuntimeConfigError> {
        let loaded = Self::loader().load::<Self>(path.as_ref())?;
        loaded.config.check()?;
        Ok(loaded.config)
    }

    /// Load and validate the operator document, reading `${VAR}` expressions
    /// through `lookup`.
    pub fn load_with_environment(
        path: impl AsRef<Path>,
        lookup: &impl Fn(&str) -> Option<String>,
    ) -> Result<Self, RuntimeConfigError> {
        let loaded = Self::loader().load_with::<Self>(path.as_ref(), lookup)?;
        loaded.config.check()?;
        Ok(loaded.config)
    }

    #[must_use]
    pub const fn loader() -> RuntimeConfigLoader {
        RuntimeConfigLoader::new(MESSAGING_RUNTIME_ENVELOPE)
            .removed_keys(MESSAGING_REMOVED_KEYS)
            .max_bytes(MAXIMUM_DOCUMENT_BYTES)
    }

    /// Parse the operator document without checking it, for focused tests.
    #[cfg(test)]
    fn parse_with_environment(
        bytes: &[u8],
        lookup: &impl Fn(&str) -> Option<String>,
    ) -> Result<Self, RuntimeConfigError> {
        let text = std::str::from_utf8(bytes).map_err(|_| RuntimeConfigError::InvalidEncoding)?;
        Ok(Self::loader().parse_str(text, lookup)?.config)
    }

    #[must_use]
    pub fn package_path(&self) -> PathBuf {
        self.package.root.join(PACKAGE_FILE)
    }

    /// Read and check the package this deployment runs. Every client a
    /// profile names must be one the OIDC settings admit, or the profile
    /// could never be reached, and a pinned `expectedDigest` must equal the
    /// digest of what was read.
    pub fn load_package(&self) -> Result<LoadedPackage, RuntimeConfigError> {
        let loaded = load_runtime_package(&self.package).map_err(RuntimeConfigError::Package)?;
        let allowed: BTreeSet<&str> = self
            .authentication
            .oidc
            .clients
            .allowed_clients
            .iter()
            .map(String::as_str)
            .collect();
        for profile in loaded.package.access_profiles().iter() {
            if let Some(client) = profile
                .requester_clients
                .iter()
                .find(|client| !allowed.contains(client.as_str()))
            {
                return Err(RuntimeConfigError::ProfileClientNotAllowed {
                    profile: profile.id.clone(),
                    client: client.clone(),
                });
            }
        }
        Ok(loaded)
    }

    #[must_use]
    pub fn database_id(&self) -> &str {
        self.identity
            .as_ref()
            .map_or("", |identity| identity.database_id.as_str())
    }

    pub fn check(&self) -> Result<(), RuntimeConfigError> {
        let identity = self
            .identity
            .as_ref()
            .ok_or(RuntimeConfigError::MissingIdentity)?;
        let database_id = identity.database_id.as_str();
        if database_id.trim().is_empty()
            || database_id.trim() != database_id
            || database_id.len() > 256
            || database_id.chars().any(char::is_control)
        {
            return Err(RuntimeConfigError::InvalidIdentity);
        }
        self.package.check()?;
        self.secret_providers.check()?;
        self.audit.destination()?;
        if !self.listener.is_valid() {
            return Err(RuntimeConfigError::InvalidListener);
        }
        if let Some(metrics) = &self.metrics_listener {
            if !valid_metrics_listener(metrics.bind.socket_addr(), self.listener.bind.socket_addr())
            {
                return Err(RuntimeConfigError::InvalidMetricsListener);
            }
        }
        let oidc = &self.authentication.oidc;
        let development_loopback =
            self.listener.tls_termination == TlsTermination::DevelopmentLoopback;
        oidc.provider
            .check("authentication.oidc", development_loopback)?;
        oidc.clients.check("authentication.oidc")?;
        if oidc.scope_claim.is_empty()
            || oidc.clients.allowed_clients.is_empty()
            || oidc.clients.allowed_clients.iter().any(String::is_empty)
        {
            return Err(RuntimeConfigError::InvalidOidc);
        }
        self.validate_assertion_issuers()?;
        if self.database.runtime_url_ref.is_empty() || self.database.migration_url_ref.is_empty() {
            return Err(RuntimeConfigError::InvalidDatabaseReference);
        }
        self.audit.key.check(&self.secret_providers)?;
        let retention = self.retention;
        if !(1..=MAXIMUM_PAYLOAD_DAYS).contains(&retention.payload_days)
            || !(retention.payload_days..=MAXIMUM_RECORD_DAYS).contains(&retention.record_days)
            || !(1..=retention.record_days).contains(&retention.submission_receipt_days)
        {
            return Err(RuntimeConfigError::InvalidRetention);
        }
        self.validate_secret_references()?;
        #[cfg(not(feature = "postgres-test"))]
        if self.database.test_only_plaintext {
            return Err(RuntimeConfigError::PlaintextDatabase);
        }
        let loaded = self.load_package()?;
        self.check_providers(&loaded)?;
        Ok(())
    }

    /// Hold every trust profile and provider connection to its checks
    /// without resolving a secret: each connection must be for a provider
    /// the package declares, of the declared kind, and every reference it
    /// names must parse and use an enabled secret provider.
    fn check_providers(&self, loaded: &LoadedPackage) -> Result<(), RuntimeConfigError> {
        if self.tls_trust_profiles.len() > MAXIMUM_TLS_TRUST_PROFILES {
            return Err(RuntimeConfigError::Connection {
                path: "tlsTrustProfiles".to_owned(),
                reason: format!("declares more than {MAXIMUM_TLS_TRUST_PROFILES} profiles"),
            });
        }
        for (name, profile) in &self.tls_trust_profiles {
            self.check_reference("bundleRef", &profile.bundle_ref)
                .map_err(|reason| RuntimeConfigError::Connection {
                    path: format!("tlsTrustProfiles.{name}"),
                    reason,
                })?;
        }
        for (id, connection) in &self.providers {
            let refused = |reason: String| RuntimeConfigError::Connection {
                path: format!("providers.{id}"),
                reason,
            };
            let declared = loaded
                .package
                .provider(id)
                .ok_or_else(|| refused("the package does not declare this provider".to_owned()))?;
            if declared.kind != connection.kind() {
                return Err(refused(format!(
                    "the package declares it with kind {}",
                    provider_kind_name(declared.kind)
                )));
            }
            for (field, reference) in connection.secret_references() {
                self.check_reference(field, reference).map_err(refused)?;
            }
            match connection {
                ProviderConnection::Smtp(settings) => {
                    settings
                        .check(self.listener.tls_termination == TlsTermination::DevelopmentLoopback)
                        .map_err(|error| refused(error.to_string()))?;
                }
                ProviderConnection::Http(settings) => {
                    let source = loaded.providers.get(id).ok_or_else(|| {
                        refused("the package ships no providers/<id>/provider.yaml".to_owned())
                    })?;
                    let trust = match &settings.tls_trust_profile {
                        None => None,
                        Some(name) if self.tls_trust_profiles.contains_key(name) => Some(&[][..]),
                        Some(_) => {
                            return Err(refused(
                                "tlsTrustProfile names a profile tlsTrustProfiles does not \
                                 declare"
                                    .to_owned(),
                            ))
                        }
                    };
                    settings
                        .check_connection(&source.package, trust)
                        .map_err(|error| refused(error.to_string()))?;
                }
            }
        }
        Ok(())
    }

    /// Check one secret reference parses and uses an enabled provider,
    /// naming only its member when it does not.
    fn check_reference(&self, field: &str, raw: &str) -> Result<(), String> {
        self.secret_providers
            .check_reference(field, raw)
            .map_err(|error| error.to_string())
    }

    /// Refuse an assertion-issuer map with too many clients, an oversized
    /// client key or issuer string, too many issuers for one client, a
    /// repeated issuer, or a client the deployment does not admit.
    fn validate_assertion_issuers(&self) -> Result<(), RuntimeConfigError> {
        let oidc = &self.authentication.oidc;
        for (client, issuers) in &oidc.clients.assertion_issuers {
            if issuers.is_empty() || !oidc.clients.allowed_clients.contains(client) {
                return Err(RuntimeConfigError::InvalidOidc);
            }
        }
        Ok(())
    }

    fn validate_secret_references(&self) -> Result<(), RuntimeConfigError> {
        let mut references = self.database.references();
        references.push(("audit.hashKeyRef", self.audit.key.hash_key_ref.as_str()));
        if let Some(document_ref) = self.authentication.oidc.provider.jwks_source.document_ref() {
            references.push(("authentication.oidc.jwksSource.documentRef", document_ref));
        }
        for (path, raw) in references {
            self.secret_providers.check_reference(path, raw)?;
        }
        Ok(())
    }

    /// Build the token verifier's key source from the configured JWKS source.
    pub async fn jwks_fetcher(
        &self,
        secrets: &SecretResolver,
    ) -> Result<std::sync::Arc<JwksFetcher>, RuntimeConfigError> {
        let fetcher = match &self.authentication.oidc.provider.jwks_source {
            OidcJwksSource::Discovery {} => {
                let discovery = fetch_discovery(&OidcDiscoveryConfig {
                    issuer: self.authentication.oidc.provider.issuer.clone(),
                    jwks_uri_override: None,
                    discovery_timeout: Duration::from_secs(5),
                    max_doc_bytes: 1024 * 1024,
                })
                .await
                .map_err(|_| RuntimeConfigError::Oidc)?;
                JwksFetcher::new(discovery.jwks_uri, JwksFetcherConfig::defaults())
            }
            OidcJwksSource::Uri { uri } => {
                JwksFetcher::new(uri.clone(), JwksFetcherConfig::defaults())
            }
            OidcJwksSource::Static { document_ref } => {
                let document = secrets.resolve(document_ref).map_err(|error| {
                    RuntimeConfigError::OidcJwksSecret(describe_secret_failure(
                        "authentication.oidc.jwksSource.documentRef",
                        document_ref,
                        &error,
                    ))
                })?;
                let jwks = parse_static_jwks(document.expose_secret())
                    .map_err(|_| RuntimeConfigError::Oidc)?;
                JwksFetcher::new_static(jwks, JwksFetcherConfig::defaults())
            }
        };
        Ok(std::sync::Arc::new(fetcher))
    }

    /// The access-token verifier profile this deployment's OIDC settings
    /// describe.
    ///
    /// RFC 9068 gives the access token one media type spelled two ways, and
    /// [`access_token_typ_set`] admits exactly that pair, so an ID token or any
    /// other JWT minted for this audience is refused.
    #[must_use]
    pub fn verifier_profile(&self) -> TokenVerifierConfig {
        TokenVerifierConfig::access_token_profile(
            self.authentication.oidc.provider.issuer.clone(),
            vec![self.authentication.oidc.provider.audience.clone()],
            vec![Algorithm::RS256, Algorithm::ES256],
            access_token_typ_set(MESSAGING_ACCESS_TOKEN_TYPE),
        )
        .with_scope_claim(self.authentication.oidc.scope_claim.clone())
        .with_allowed_clients(self.authentication.oidc.clients.allowed_clients.clone())
        .with_assertion_issuers(self.authentication.oidc.clients.assertion_issuers.clone())
    }

    /// Whether this deployment declared any token-exchange authority.
    #[must_use]
    pub fn binds_assertion_issuers(&self) -> bool {
        !self
            .authentication
            .oidc
            .clients
            .assertion_issuers
            .is_empty()
    }

    /// Build the secret resolver from the providers this document enables.
    pub fn secret_resolver(&self) -> Result<SecretResolver, RuntimeConfigError> {
        self.secret_providers
            .resolver()
            .map_err(|_| RuntimeConfigError::InvalidSecretProviders)
    }
}

/// The metrics listener binds a concrete private address on a non-zero port
/// and never shares the public listener's socket: sharing it would publish
/// the counters on the listener the public contract describes.
fn valid_metrics_listener(metrics: SocketAddr, listener: SocketAddr) -> bool {
    let address = metrics.ip();
    let private = match address {
        IpAddr::V4(address) => address.is_loopback() || address.is_private(),
        IpAddr::V6(address) => address.is_loopback() || is_unique_local(address),
    };
    if metrics.port() == 0 || !private || address.is_unspecified() || address.is_multicast() {
        return false;
    }
    // An IPv6 wildcard socket is commonly dual-stack, so it covers both
    // families; the IPv4 wildcard covers only IPv4.
    let wildcard_covers_metrics = match listener.ip() {
        IpAddr::V4(listener) => listener.is_unspecified() && address.is_ipv4(),
        IpAddr::V6(listener) => listener.is_unspecified(),
    };
    !((address == listener.ip() || wildcard_covers_metrics) && metrics.port() == listener.port())
}

fn is_unique_local(address: Ipv6Addr) -> bool {
    address.segments()[0] & 0xfe00 == 0xfc00
}

/// Name where a YAML document was refused and why. A refusal serde never
/// attributed to a member is reported at the document root.
pub(crate) fn refused_yaml(
    error: serde_path_to_error::Error<serde_norway::Error>,
) -> (String, String) {
    let path = error.path().to_string();
    let path = if path == "." { "/".to_owned() } else { path };
    (path, redact_refused_values(&error.into_inner().to_string()))
}

/// Keep the member, the reason, and the location of a refusal while the
/// refused value stays out of the message. Only the shape word that opens an
/// `invalid type:` or `invalid value:` clause survives, because the value
/// might be a secret reference, a database URL, or a credential typed in the
/// wrong place, and a startup refusal is written to the operator's log.
pub(crate) fn redact_refused_values(message: &str) -> String {
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
/// `Debug` inside quotes or backticks.
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

/// Return the offset just past the delimited run that opens at `open`. An
/// escaped delimiter inside the run does not end it.
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
    #[error("identity.databaseId is required; add identity.databaseId with the logical id of the database this deployment owns")]
    MissingIdentity,
    #[error("identity.databaseId must be non-empty, at most 256 bytes, without surrounding whitespace or control characters")]
    InvalidIdentity,
    #[error(transparent)]
    Shared(#[from] registry_platform_config::RuntimeConfigError),
    #[error(transparent)]
    Block(#[from] ConfigBlockError),
    #[error("audit destination is invalid: {0}")]
    InvalidAuditDestination(#[source] AuditDestinationError),
    #[error("the Messaging runtime configuration is not UTF-8 text")]
    InvalidEncoding,
    #[error("the operated runtime path {0} must be absolute")]
    RelativeOperatedPath(&'static str),
    #[error("secretProviders must explicitly enable file, environment, or both")]
    InvalidSecretProviders,
    #[error("listener is not valid for its declared TLS termination and network exposure")]
    InvalidListener,
    #[error(
        "metricsListener.bind must be a private address on a non-zero port, apart from the \
         listener"
    )]
    InvalidMetricsListener,
    #[error(
        "authentication.oidc is invalid: issuer, audience, scopeClaim, and a non-empty \
         allowedClients list are required, and assertionIssuers may name only allowed clients \
         within its bounds"
    )]
    InvalidOidc,
    #[error(
        "database.runtimeUrlRef and database.migrationUrlRef must be non-empty secret references"
    )]
    InvalidDatabaseReference,
    #[error(
        "retention is out of bounds: payloadDays 1 to 30, recordDays from payloadDays to 3650, \
         submissionReceiptDays from 1 to recordDays"
    )]
    InvalidRetention,
    #[error("plaintext PostgreSQL is test-only")]
    PlaintextDatabase,
    #[error("the Messaging package at {0}")]
    Package(#[source] PackageLoadError),
    #[error(
        "access profile {profile} names requester client {client}, which \
         authentication.oidc.allowedClients does not admit"
    )]
    ProfileClientNotAllowed { profile: String, client: String },
    #[error("the OIDC issuer could not be initialized")]
    Oidc,
    #[error("the static OIDC signing keys could not be loaded: {0}")]
    OidcJwksSecret(String),
    #[error("{path} is refused: {reason}")]
    Connection { path: String, reason: String },
}

impl RuntimeConfigError {
    /// The document member the refusal is about.
    #[must_use]
    pub fn path(&self) -> &str {
        match self {
            Self::MissingIdentity | Self::InvalidIdentity => "identity.databaseId",
            Self::Shared(error) => error.field(),
            Self::Block(error) => error.field(),
            Self::InvalidAuditDestination(_) => "audit",
            Self::InvalidEncoding => "/",
            Self::RelativeOperatedPath(path) => path,
            Self::InvalidSecretProviders => "secretProviders",
            Self::InvalidOidc | Self::Oidc => "authentication.oidc",
            Self::OidcJwksSecret(_) => "authentication.oidc.jwksSource.documentRef",
            Self::InvalidListener => "listener",
            Self::InvalidMetricsListener => "metricsListener.bind",
            Self::InvalidDatabaseReference | Self::PlaintextDatabase => "database",
            Self::InvalidRetention => "retention",
            Self::Package(error) => error.path(),
            Self::ProfileClientNotAllowed { .. } => "authentication.oidc.allowedClients",
            Self::Connection { path, .. } => path,
        }
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use serde_json::{json, Value};

    /// The starter package's manifest, as a value a test may change.
    pub(crate) fn package_value() -> Value {
        let text =
            std::fs::read_to_string(crate::package::tests::starter_root().join(PACKAGE_FILE))
                .unwrap();
        serde_norway::from_str(&text).unwrap()
    }

    pub(crate) fn runtime_value(root: &Path) -> Value {
        json!({
            "apiVersion": MESSAGING_RUNTIME_API_VERSION,
            "kind": MESSAGING_RUNTIME_KIND,
        "identity": {"databaseId": "messaging-test"},
            "package": {"root": root.join("package")},
            "listener": {"bind": "127.0.0.1:8107", "tlsTermination": "development-loopback"},
            "secretProviders": {"file": {"root": root.join("secrets")}, "environment": {}},
            "database": {
                "runtimeUrlRef": "secret:env/MESSAGING_RUNTIME_URL",
                "migrationUrlRef": "secret:env/MESSAGING_MIGRATION_URL"
            },
            "authentication": {"oidc": {
                "issuer": "https://identity.example.test",
                "audience": "urn:example:messaging",
                "allowedClients": ["case-system", "operations-console"]
            }},
            "audit": {"path": root.join("audit"), "hashKeyRef": "secret:file/audit-hash-key"}
        })
    }

    /// Write the starter templates, `package` as the manifest, and a runtime
    /// document under `root`, returning the runtime document's path.
    pub(crate) fn write_project(root: &Path, runtime: &Value, package: &Value) -> PathBuf {
        let package_root = root.join("package");
        crate::package::tests::copy_starter(&package_root);
        std::fs::write(
            package_root.join(PACKAGE_FILE),
            serde_norway::to_string(package).unwrap(),
        )
        .unwrap();
        let _ = std::fs::remove_file(package_root.join(registry_platform_config::SUM_FILE));
        let _ = std::fs::remove_file(package_root.join(registry_platform_config::REVISION_FILE));
        registry_platform_config::write_sum_file(
            &package_root,
            None,
            &crate::package::package_limits(),
            crate::package::PACKAGE_COMMAND,
        )
        .unwrap();
        let path = root.join("runtime.yaml");
        std::fs::write(&path, serde_norway::to_string(runtime).unwrap()).unwrap();
        std::fs::canonicalize(path).unwrap()
    }

    fn no_environment(_: &str) -> Option<String> {
        None
    }

    fn load(runtime: Value) -> Result<RuntimeConfig, RuntimeConfigError> {
        let root = tempfile::tempdir().unwrap();
        let mut runtime = runtime;
        rebase(&mut runtime, root.path());
        let path = write_project(root.path(), &runtime, &package_value());
        RuntimeConfig::load_with_environment(path, &no_environment)
    }

    /// Tests build documents against a placeholder root; point every path
    /// still under it at the temporary directory this load runs in.
    fn rebase(runtime: &mut Value, root: &Path) {
        for pointer in ["/package/root", "/audit/path", "/secretProviders/file/root"] {
            if let Some(value) = runtime.pointer_mut(pointer) {
                if let Some(rest) = value
                    .as_str()
                    .and_then(|text| text.strip_prefix("/placeholder/"))
                {
                    *value = json!(root.join(rest));
                }
            }
        }
    }

    fn base() -> Value {
        runtime_value(Path::new("/placeholder"))
    }

    #[test]
    fn database_identity_is_required_bounded_and_value_free() {
        let mut runtime = base();
        runtime.as_object_mut().unwrap().remove("identity");
        let error = load(runtime).unwrap_err();
        assert_eq!(error.path(), "identity.databaseId");
        assert!(error
            .to_string()
            .contains("identity.databaseId is required"));
        for database_id in [
            "",
            " ",
            " production",
            "production ",
            "private\nidentity",
            &"x".repeat(257),
        ] {
            let mut runtime = base();
            runtime["identity"] = json!({"databaseId": database_id});
            let error = load(runtime).unwrap_err();
            assert_eq!(error.path(), "identity.databaseId");
            assert!(matches!(error, RuntimeConfigError::InvalidIdentity));
            assert!(!error.to_string().contains("private"));
        }
        let mut runtime = base();
        runtime["identity"] = json!({"databaseId": "x".repeat(256)});
        assert_eq!(load(runtime).unwrap().database_id().len(), 256);
    }

    #[test]
    fn shared_runtime_configuration_blocks_use_the_platform_contract() {
        let config = load(base()).unwrap();
        assert_eq!(config.retention, RetentionConfig::default());
        assert_eq!(config.authentication.oidc.scope_claim, "registry_scopes");
        assert!(config.metrics_listener.is_none());
        assert_eq!(
            config.listener.bind.socket_addr(),
            DEFAULT_LISTENER_BIND.parse().unwrap()
        );
        assert!(!config.binds_assertion_issuers());
    }

    #[test]
    fn an_unknown_key_is_refused_with_its_path() {
        for (pointer, key) in [
            ("", "extraSection"),
            ("/listener", "port"),
            ("/database", "url"),
            ("/authentication/oidc", "clientSecret"),
            ("/retention", "payloadHours"),
        ] {
            let mut value = base();
            if pointer == "/retention" {
                value["retention"] = json!({});
            }
            value
                .pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert(key.to_owned(), json!("x"));
            let error = load(value).unwrap_err();
            assert!(
                matches!(error, RuntimeConfigError::Shared(_)),
                "{key}: {error}"
            );
            assert!(error.to_string().contains(key), "{error}");
        }
    }

    #[test]
    fn shared_runtime_loader_refuses_environment_expressions_in_secret_references() {
        let mut value = base();
        value["database"]["runtimeUrlRef"] = json!("${DATABASE_URL}");
        let error = load(value).unwrap_err();
        assert!(matches!(error, RuntimeConfigError::Shared(_)), "{error}");
        assert_eq!(error.path(), "database.runtimeUrlRef");
        assert!(error.to_string().contains("secret reference"), "{error}");

        let mut value = base();
        value["audit"]["hashKeyRef"] = json!("secret:env/${KEY_NAME:-AUDIT}");
        let error = load(value).unwrap_err();
        assert_eq!(error.path(), "audit.hashKeyRef");

        let mut value = base();
        value["authentication"]["oidc"]["jwksSource"] =
            json!({"kind": "static", "documentRef": "${JWKS}"});
        let error = load(value).unwrap_err();
        assert_eq!(error.path(), "authentication.oidc.jwksSource.documentRef");
    }

    #[test]
    fn an_environment_expression_reaching_a_credential_field_through_an_alias_is_refused() {
        let root = tempfile::tempdir().unwrap();
        let path = write_project(root.path(), &runtime_value(root.path()), &package_value());
        let text = std::fs::read_to_string(&path).unwrap().replace(
            "runtimeUrlRef: secret:env/MESSAGING_RUNTIME_URL",
            "runtimeUrlRef: *spliced",
        );
        let text = format!("x-spliced: &spliced ${{DATABASE_URL}}\n{text}");
        std::fs::write(&path, text).unwrap();
        let error = RuntimeConfig::load_with_environment(&path, &|_| {
            Some("postgres://user:hunter2@db".to_owned())
        })
        .unwrap_err();
        // Anchors and aliases are outside the shared YAML subset, so both are
        // refused before any substitution runs.
        assert_eq!(error.path(), "x-spliced", "{error}");
        let message = error.to_string();
        assert!(
            message.contains("error[yaml.alias]") && message.contains("/database/runtimeUrlRef"),
            "{message}"
        );
        assert!(!message.contains("hunter2"), "{message}");
    }

    #[test]
    fn a_refused_expression_never_repeats_the_value_or_the_default() {
        let mut value = base();
        value["database"]["runtimeUrlRef"] = json!("${X:-postgres://user:hunter2@db}");
        let error = load(value).unwrap_err();
        assert!(!error.to_string().contains("hunter2"), "{error}");
        assert!(!format!("{error:?}").contains("hunter2"));

        let root = tempfile::tempdir().unwrap();
        let mut runtime = runtime_value(root.path());
        runtime["authentication"]["oidc"]["issuer"] = json!("https://${HOST}/");
        let path = write_project(root.path(), &runtime, &package_value());
        let error = RuntimeConfig::load_with_environment(&path, &|_| {
            Some("hunter2.example\nkind: Other".to_owned())
        })
        .unwrap_err();
        assert!(!error.to_string().contains("hunter2"), "{error}");
        assert!(!format!("{error:?}").contains("hunter2"));
    }

    #[test]
    fn shared_runtime_loader_substitutes_only_parsed_non_secret_strings() {
        let root = tempfile::tempdir().unwrap();
        let mut runtime = runtime_value(root.path());
        runtime["listener"]["bind"] = json!("${MESSAGING_BIND}");
        runtime["authentication"]["oidc"]["issuer"] = json!("${ISSUER:-https://fallback.test}");
        let path = write_project(root.path(), &runtime, &package_value());
        let config = RuntimeConfig::load_with_environment(&path, &|name| {
            (name == "MESSAGING_BIND").then(|| "127.0.0.1:9107".to_owned())
        })
        .unwrap();
        assert_eq!(
            config.listener.bind.socket_addr(),
            "127.0.0.1:9107".parse().unwrap()
        );
        assert_eq!(
            config.authentication.oidc.provider.issuer,
            "https://fallback.test"
        );

        // Substitution runs over the parsed document, so an unset variable
        // is attributed to its member.
        let error = RuntimeConfig::load_with_environment(&path, &no_environment).unwrap_err();
        assert!(matches!(error, RuntimeConfigError::Shared(_)), "{error}");
        assert_eq!(error.path(), "listener.bind");
        assert!(error.to_string().contains("MESSAGING_BIND"), "{error}");
    }

    #[test]
    fn removed_jwks_uri_names_jwks_source_replacement() {
        let mut value = base();
        value["authentication"]["oidc"]["jwksUri"] =
            json!("https://identity.example.test/jwks.json");
        let error = load(value).unwrap_err();
        assert_eq!(error.path(), "authentication.oidc.jwksUri");
        assert!(matches!(
            error,
            RuntimeConfigError::Shared(ref shared)
                if shared.kind() == SharedRuntimeConfigErrorKind::RemovedKey
        ));
        assert!(error.to_string().contains("jwksSource"), "{error}");
    }

    #[test]
    fn an_expanded_value_can_never_change_the_document_shape() {
        let root = tempfile::tempdir().unwrap();
        let mut runtime = runtime_value(root.path());
        runtime["kind"] = json!("${SNEAKY}");
        let path = write_project(root.path(), &runtime, &package_value());
        let error = RuntimeConfig::load_with_environment(&path, &|_| {
            Some(format!("x\nkind: {MESSAGING_RUNTIME_KIND}"))
        })
        .unwrap_err();
        assert!(matches!(error, RuntimeConfigError::Shared(_)), "{error}");

        let mut runtime = runtime_value(root.path());
        runtime["authentication"]["oidc"]["issuer"] = json!("https://${HOST}/");
        let path = write_project(root.path(), &runtime, &package_value());
        for value in [
            "a.example\nkind: Other",
            "a.example, b.example",
            "a.example # c",
        ] {
            let error = RuntimeConfig::load_with_environment(&path, &|_| Some(value.to_owned()))
                .unwrap_err();
            assert!(matches!(error, RuntimeConfigError::Block(_)), "{error}");
            assert_eq!(error.path(), "authentication.oidc.issuer");
        }
    }

    #[test]
    fn the_starter_runtime_example_parses_as_written() {
        let example = crate::package::tests::starter_root().join("runtime.example.yaml");
        let bytes = std::fs::read(example).unwrap();
        RuntimeConfig::parse_with_environment(&bytes, &no_environment).unwrap();
    }

    #[test]
    fn a_malformed_environment_expression_is_refused() {
        for issuer in ["${ISSUER", "${1BAD}", "${}"] {
            let mut value = base();
            value["authentication"]["oidc"]["issuer"] = json!(issuer);
            let error = load(value).unwrap_err();
            assert!(
                matches!(
                    error,
                    RuntimeConfigError::Shared(_) | RuntimeConfigError::Block(_)
                ),
                "{issuer}: {error}"
            );
        }
    }

    #[test]
    fn retention_bounds_are_enforced() {
        for retention in [
            json!({"payloadDays": 0}),
            json!({"payloadDays": 31}),
            json!({"payloadDays": 10, "recordDays": 9}),
            json!({"recordDays": 3651}),
            json!({"submissionReceiptDays": 0}),
            json!({"recordDays": 10, "payloadDays": 5, "submissionReceiptDays": 11}),
        ] {
            let mut value = base();
            value["retention"] = retention.clone();
            let error = load(value).unwrap_err();
            assert!(
                matches!(error, RuntimeConfigError::InvalidRetention),
                "{retention}: {error}"
            );
        }
        let mut value = base();
        value["retention"] =
            json!({"payloadDays": 30, "recordDays": 30, "submissionReceiptDays": 30});
        load(value).unwrap();
    }

    #[test]
    fn the_metrics_listener_must_be_private_and_apart_from_the_listener() {
        for bind in [
            "127.0.0.1:8107",
            "0.0.0.0:9090",
            "[::]:9090",
            "203.0.113.4:9090",
            "127.0.0.1:0",
            "[2001:db8::1]:9090",
        ] {
            let mut value = base();
            value["metricsListener"] = json!({"bind": bind});
            let error = load(value).unwrap_err();
            assert!(
                matches!(error, RuntimeConfigError::InvalidMetricsListener),
                "{bind}: {error}"
            );
            assert!(!format!("{error:?}").contains(bind));
        }
        let mut value = base();
        value["metricsListener"] = json!({"bind": "127.0.0.1:9107"});
        assert!(load(value).unwrap().metrics_listener.is_some());
    }

    #[test]
    fn the_metrics_listener_may_not_share_a_wildcard_listener_port() {
        assert!(!valid_metrics_listener(
            "10.0.0.5:8107".parse().unwrap(),
            "0.0.0.0:8107".parse().unwrap()
        ));
        assert!(!valid_metrics_listener(
            "10.0.0.5:8107".parse().unwrap(),
            "[::]:8107".parse().unwrap()
        ));
        assert!(valid_metrics_listener(
            "[fd00::5]:8107".parse().unwrap(),
            "0.0.0.0:8107".parse().unwrap()
        ));
    }

    #[test]
    fn allowed_clients_are_required_and_must_cover_every_profile() {
        let mut value = base();
        value["authentication"]["oidc"]["allowedClients"] = json!([]);
        assert!(matches!(
            load(value).unwrap_err(),
            RuntimeConfigError::InvalidOidc
        ));

        let mut value = base();
        value["authentication"]["oidc"]
            .as_object_mut()
            .unwrap()
            .remove("allowedClients");
        assert!(matches!(
            load(value).unwrap_err(),
            RuntimeConfigError::InvalidOidc
        ));

        let mut value = base();
        value["authentication"]["oidc"]["allowedClients"] = json!(["case-system"]);
        let error = load(value).unwrap_err();
        assert!(
            matches!(error, RuntimeConfigError::ProfileClientNotAllowed { .. }),
            "{error}"
        );
    }

    #[test]
    fn assertion_issuers_may_name_only_allowed_clients() {
        let mut value = base();
        value["authentication"]["oidc"]["assertionIssuers"] =
            json!({"unknown-client": ["https://assertions.example.test"]});
        assert!(matches!(
            load(value).unwrap_err(),
            RuntimeConfigError::InvalidOidc
        ));
        let mut value = base();
        value["authentication"]["oidc"]["assertionIssuers"] =
            json!({"case-system": ["https://a.test", "https://a.test"]});
        assert!(matches!(
            load(value).unwrap_err(),
            RuntimeConfigError::Block(_)
        ));
        let mut value = base();
        value["authentication"]["oidc"]["assertionIssuers"] =
            json!({"case-system": ["https://assertions.example.test"]});
        assert!(load(value).unwrap().binds_assertion_issuers());
    }

    #[test]
    fn runtime_package_digest_pin_reports_expected_and_found() {
        let mut value = base();
        value["package"]["expectedDigest"] = json!("sha256:ABC");
        assert!(matches!(
            load(value).unwrap_err(),
            RuntimeConfigError::Block(_)
        ));

        let root = tempfile::tempdir().unwrap();
        let mut runtime = runtime_value(root.path());
        let path = write_project(root.path(), &runtime, &package_value());
        let config = RuntimeConfig::load_with_environment(&path, &no_environment).unwrap();
        let digest = config.load_package().unwrap().package.digest().to_owned();

        runtime["package"]["expectedDigest"] = json!(digest);
        let path = write_project(root.path(), &runtime, &package_value());
        RuntimeConfig::load_with_environment(&path, &no_environment).unwrap();

        let pinned = format!("sha256:{}", "a".repeat(64));
        runtime["package"]["expectedDigest"] = json!(pinned);
        let path = write_project(root.path(), &runtime, &package_value());
        let error = RuntimeConfig::load_with_environment(&path, &no_environment).unwrap_err();
        assert!(matches!(&error, RuntimeConfigError::Package(_)), "{error}");
        assert_eq!(error.path(), "package.expectedDigest");
        assert!(error.to_string().contains(&digest), "{error}");

        // A changed template is a changed package: the pin that matched it
        // no longer does.
        runtime["package"]["expectedDigest"] = json!(digest);
        let path = write_project(root.path(), &runtime, &package_value());
        std::fs::write(
            root.path()
                .join("package/templates/appointment-reminder/1/en/subject.j2"),
            "Changed {{ day|date }}",
        )
        .unwrap();
        assert!(matches!(
            RuntimeConfig::load_with_environment(&path, &no_environment).unwrap_err(),
            RuntimeConfigError::Package(_)
        ));
    }

    #[test]
    fn listener_and_secret_rules_are_enforced() {
        let mut value = base();
        value["listener"]["bind"] = json!("10.0.0.5:8107");
        assert!(matches!(
            load(value).unwrap_err(),
            RuntimeConfigError::InvalidListener
        ));

        let mut value = base();
        value["listener"] = json!({
            "bind": "0.0.0.0:8107",
            "tlsTermination": "operator-controlled-upstream",
            "networkExposure": "container-private"
        });
        load(value).unwrap();

        let mut value = base();
        value["database"]["runtimeUrlRef"] = json!("postgres://user:hunter2@db/messaging");
        let error = load(value).unwrap_err();
        assert!(matches!(error, RuntimeConfigError::Block(_)));
        assert!(!error.to_string().contains("hunter2"));

        let mut value = base();
        value["secretProviders"] = json!({"file": {"root": "/placeholder/secrets"}});
        assert!(matches!(
            load(value).unwrap_err(),
            RuntimeConfigError::Block(_)
        ));

        let mut value = base();
        value["secretProviders"] = json!({});
        assert!(matches!(
            load(value).unwrap_err(),
            RuntimeConfigError::Block(_)
        ));
    }

    #[test]
    fn relative_paths_are_refused() {
        let mut value = base();
        value["audit"]["path"] = json!("audit");
        let error = load(value).unwrap_err();
        assert_eq!(error.path(), "audit.path");
        assert!(matches!(
            RuntimeConfig::load_with_environment("runtime.yaml", &no_environment),
            Err(RuntimeConfigError::Shared(_))
        ));
    }

    #[cfg(not(feature = "postgres-test"))]
    #[test]
    fn plaintext_postgres_is_refused_outside_the_test_build() {
        let mut value = base();
        value["database"]["testOnlyPlaintext"] = json!(true);
        assert!(matches!(
            load(value).unwrap_err(),
            RuntimeConfigError::PlaintextDatabase
        ));
    }

    #[test]
    fn a_refused_value_is_not_repeated() {
        let mut value = base();
        value["retention"] = json!({"payloadDays": "secret:env/hunter2"});
        let error = load(value).unwrap_err();
        assert!(!error.to_string().contains("hunter2"), "{error}");
    }

    #[test]
    fn debug_output_redacts_database_references() {
        let config = load(base()).unwrap();
        let rendered = format!("{config:?}");
        assert!(!rendered.contains("MESSAGING_RUNTIME_URL"));
        assert!(!rendered.contains("MESSAGING_MIGRATION_URL"));
    }

    #[test]
    fn an_invalid_package_is_refused_at_load() {
        let root = tempfile::tempdir().unwrap();
        let runtime = runtime_value(root.path());
        let mut package = package_value();
        package["accessProfiles"][0]["templates"] = json!([]);
        let path = write_project(root.path(), &runtime, &package);
        let error = RuntimeConfig::load_with_environment(&path, &no_environment).unwrap_err();
        assert!(matches!(error, RuntimeConfigError::Package(_)), "{error}");
        assert_eq!(error.path(), "package.root/messaging.yaml");

        let mut package = package_value();
        package["accessProfiles"][0]["providerUrl"] = json!("https://x.test");
        let path = write_project(root.path(), &runtime, &package);
        let error = RuntimeConfig::load_with_environment(&path, &no_environment).unwrap_err();
        assert!(matches!(error, RuntimeConfigError::Package(_)), "{error}");
        assert!(error.to_string().contains("providerUrl"), "{error}");

        let mut package = package_value();
        package["providers"][0]["endpointRef"] = json!("${RELAY_URL}");
        let path = write_project(root.path(), &runtime, &package);
        let error = RuntimeConfig::load_with_environment(&path, &no_environment).unwrap_err();
        assert!(error.to_string().contains("endpointRef"), "{error}");
        assert!(!error.to_string().contains("RELAY_URL"), "{error}");
    }

    /// Runtime connections for both starter providers.
    pub(crate) fn provider_connections() -> Value {
        json!({
            "mail-relay": {
                "kind": "smtp",
                "host": "smtp.example.org",
                "tls": "starttls",
                "authentication": {
                    "usernameRef": "secret:file/smtp-username",
                    "passwordRef": "secret:env/SMTP_PASSWORD"
                }
            },
            "sms-gateway": {
                "kind": "http",
                "baseUrl": "https://gateway.example.org/v1/",
                "timeoutMilliseconds": 5000,
                "maximumResponseBytes": 65536,
                "concurrencyLimit": 4,
                "redirects": "deny",
                "authentication": {
                    "kind": "static-authorization",
                    "tokenRef": "secret:file/gateway-token"
                },
                "callbackVerifier": {
                    "kind": "hmac-sha256-body",
                    "header": "x-signature",
                    "encoding": "hex",
                    "secretRef": "secret:file/gateway-callback-key"
                }
            }
        })
    }

    /// Enable only the file secret provider, moving the database
    /// references onto it.
    fn file_secrets_only(value: &mut Value) {
        value["secretProviders"] = json!({"file": {"root": "/placeholder/secrets"}});
        value["database"]["runtimeUrlRef"] = json!("secret:file/runtime-url");
        value["database"]["migrationUrlRef"] = json!("secret:file/migration-url");
    }

    #[test]
    fn provider_connections_load_against_the_package_declarations() {
        let mut value = base();
        value["providers"] = provider_connections();
        value["providers"]["sms-gateway"]["tlsTrustProfile"] = json!("gateway-ca");
        value["tlsTrustProfiles"] = json!({"gateway-ca": {"bundleRef": "secret:file/gateway-ca"}});
        let config = load(value).unwrap();
        assert_eq!(config.providers.len(), 2);
        assert!(matches!(
            config.providers["mail-relay"],
            ProviderConnection::Smtp(_)
        ));
        assert!(matches!(
            config.providers["sms-gateway"],
            ProviderConnection::Http(_)
        ));
        let rendered = format!("{config:?}");
        for reference in ["SMTP_PASSWORD", "gateway-token", "secret:file/gateway-ca"] {
            assert!(!rendered.contains(reference), "{rendered}");
        }

        // A package provider without a connection is not a configuration
        // error: its messages fail with provider-unconfigured.
        load(base()).unwrap();
    }

    #[test]
    fn a_connection_the_package_does_not_declare_or_of_another_kind_is_refused() {
        let mut value = base();
        value["providers"] = json!({"relay-two": provider_connections()["mail-relay"].clone()});
        let error = load(value).unwrap_err();
        assert_eq!(error.path(), "providers.relay-two");
        assert!(error.to_string().contains("does not declare"), "{error}");

        let mut value = base();
        value["providers"] = json!({"mail-relay": provider_connections()["sms-gateway"].clone()});
        let error = load(value).unwrap_err();
        assert_eq!(error.path(), "providers.mail-relay");
        assert!(error.to_string().contains("kind smtp"), "{error}");
    }

    #[test]
    fn a_connection_that_fails_its_checks_names_the_provider_and_the_member() {
        let mut value = base();
        value["providers"] = provider_connections();
        value["providers"]["mail-relay"]["port"] = json!(0);
        let error = load(value).unwrap_err();
        assert_eq!(error.path(), "providers.mail-relay");
        assert!(error.to_string().contains("port"), "{error}");

        let mut value = base();
        value["providers"] = provider_connections();
        value["providers"]["sms-gateway"]["concurrencyLimit"] = json!(9);
        let error = load(value).unwrap_err();
        assert_eq!(error.path(), "providers.sms-gateway");
        assert!(error.to_string().contains("concurrencyLimit"), "{error}");

        let mut value = base();
        value["providers"] = provider_connections();
        value["providers"]["sms-gateway"]
            .as_object_mut()
            .unwrap()
            .remove("callbackVerifier");
        let error = load(value).unwrap_err();
        assert_eq!(error.path(), "providers.sms-gateway");
        assert!(error.to_string().contains("callbackVerifier"), "{error}");

        let mut value = base();
        value["providers"] = provider_connections();
        value["providers"]["sms-gateway"]["region"] = json!("eu");
        assert!(matches!(
            load(value).unwrap_err(),
            RuntimeConfigError::Shared(_)
        ));
    }

    #[test]
    fn a_provider_secret_reference_must_parse_and_name_an_enabled_secret_provider() {
        let mut value = base();
        value["providers"] = provider_connections();
        value["providers"]["mail-relay"]["authentication"]["passwordRef"] = json!("hunter2");
        let error = load(value).unwrap_err();
        assert_eq!(error.path(), "providers.mail-relay");
        assert!(
            error.to_string().contains("authentication.passwordRef"),
            "{error}"
        );
        assert!(!error.to_string().contains("hunter2"), "{error}");

        let mut value = base();
        value["providers"] = provider_connections();
        value["providers"]["sms-gateway"]["authentication"]["tokenRef"] = json!("hunter2");
        let error = load(value).unwrap_err();
        assert_eq!(error.path(), "providers.sms-gateway");
        assert!(
            error.to_string().contains("authentication.tokenRef"),
            "{error}"
        );
        assert!(!error.to_string().contains("hunter2"), "{error}");

        let mut value = base();
        file_secrets_only(&mut value);
        value["providers"] = provider_connections();
        let error = load(value).unwrap_err();
        assert_eq!(error.path(), "providers.mail-relay");
        assert!(error.to_string().contains("not enabled"), "{error}");

        let mut value = base();
        file_secrets_only(&mut value);
        value["providers"] = json!({"sms-gateway": provider_connections()["sms-gateway"].clone()});
        value["providers"]["sms-gateway"]["callbackVerifier"]["secretRef"] =
            json!("secret:env/CALLBACK_KEY");
        let error = load(value).unwrap_err();
        assert_eq!(error.path(), "providers.sms-gateway");
        assert!(
            error.to_string().contains("callbackVerifier.secretRef"),
            "{error}"
        );
    }

    #[test]
    fn a_trust_profile_must_be_declared_and_its_bundle_a_secret_reference() {
        let mut value = base();
        value["providers"] = provider_connections();
        value["providers"]["sms-gateway"]["tlsTrustProfile"] = json!("gateway-ca");
        let error = load(value).unwrap_err();
        assert_eq!(error.path(), "providers.sms-gateway");
        assert!(error.to_string().contains("tlsTrustProfile"), "{error}");

        let mut value = base();
        value["tlsTrustProfiles"] = json!({"gateway-ca": {"bundleRef": "/etc/ca.pem"}});
        let error = load(value).unwrap_err();
        assert_eq!(error.path(), "tlsTrustProfiles.gateway-ca");
        assert!(error.to_string().contains("bundleRef"), "{error}");

        let mut value = base();
        file_secrets_only(&mut value);
        value["tlsTrustProfiles"] = json!({"gateway-ca": {"bundleRef": "secret:env/CA"}});
        let error = load(value).unwrap_err();
        assert_eq!(error.path(), "tlsTrustProfiles.gateway-ca");
    }

    #[test]
    fn the_verifier_admits_only_the_access_token_media_type() {
        let config = load(base()).unwrap();
        let profile = config.verifier_profile();
        assert!(registry_platform_oidc::is_access_token_typ_pair(
            &profile.allowed_typ
        ));
        assert!(!profile
            .allowed_typ
            .iter()
            .any(|value| value.eq_ignore_ascii_case("JWT")));
    }
}
