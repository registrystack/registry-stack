// SPDX-License-Identifier: Apache-2.0

//! The operator runtime configuration document and the package it names.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use jsonwebtoken::jwk::{AlgorithmParameters, JwkSet};
use jsonwebtoken::Algorithm;
use registry_messaging_core::{
    valid_package_digest, ProviderKind, MESSAGING_RUNTIME_API_VERSION, MESSAGING_RUNTIME_KIND,
    PACKAGE_FILE,
};
use registry_platform_config::{
    expand_config_env_vars_with, reject_config_env_expressions_in, SecretError, SecretProvider,
    SecretReference, SecretResolver, MAX_SECRET_BYTES,
};
use registry_platform_oidc::{
    access_token_typ_set, fetch_discovery, JwksFetcher, JwksFetcherConfig, OidcDiscoveryConfig,
    TokenVerifierConfig,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::http_provider::HttpProviderSettings;
use crate::package::{load_package, LoadedPackage, PackageLoadError};
use crate::smtp::SmtpProviderSettings;

/// The suffix naming a credential member. Every secret reference in the
/// runtime document is spelled this way, and none may carry an environment
/// expression.
const CREDENTIAL_MEMBER_SUFFIX: &str = "Ref";

/// Explain one refused secret reference without disclosing what it protects.
///
/// A valid reference is safe and useful to name, but invalid operator-authored
/// text might itself be a literal credential, so only its field is named. The
/// resolved bytes and opened path never appear.
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
    if error == &SecretError::InvalidReference {
        format!("the secret reference configured at {field} could not be resolved: {reason}")
    } else {
        format!("the secret reference {reference} could not be resolved: {reason}")
    }
}

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

/// Bounds on the authored assertion-issuer map, matching the Casework and
/// Scheduling runtimes. They keep one operator document from becoming an
/// unbounded verifier input.
pub(crate) const MAXIMUM_ASSERTION_ISSUER_CLIENTS: usize = 64;
pub(crate) const MAXIMUM_ASSERTION_ISSUER_CLIENT_BYTES: usize = 128;
pub(crate) const MAXIMUM_ASSERTION_ISSUERS_PER_CLIENT: usize = 16;
pub(crate) const MAXIMUM_ASSERTION_ISSUER_BYTES: usize = 512;

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
    /// Named PEM bundles an `http` provider's `tlsTrustProfile` trusts
    /// instead of the public web roots.
    #[serde(default)]
    pub tls_trust_profiles: BTreeMap<String, TlsTrustProfileConfig>,
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

/// The root of an authored Messaging package, holding `messaging.yaml` and
/// its `templates/` tree.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimePackageConfig {
    pub root: PathBuf,
    /// The `sha256:` digest the operator pins the package to. The runtime
    /// computes the digest of the package it reads and refuses to start when
    /// the two differ.
    #[serde(default)]
    pub expected_digest: Option<String>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ListenerConfig {
    #[serde(default = "default_listener_bind")]
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub bind: SocketAddr,
    pub tls_termination: TlsTermination,
    #[serde(default)]
    pub network_exposure: ListenerNetworkExposure,
}

fn default_listener_bind() -> SocketAddr {
    DEFAULT_LISTENER_BIND
        .parse()
        .expect("valid Messaging listener default")
}

/// Declares the trusted transport boundary for the plaintext HTTP listener.
/// Production listeners require operator-controlled upstream TLS termination;
/// direct plaintext is limited to the explicit loopback-only development mode.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum TlsTermination {
    OperatorControlledUpstream,
    DevelopmentLoopback,
}

/// The operator-declared private network placement of the HTTP listener.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum ListenerNetworkExposure {
    #[default]
    PrivateAddress,
    ContainerPrivate,
}

/// The operator-private listener that serves `/metrics`. It is a separate
/// socket rather than a route on the public listener, so reaching the
/// counters requires reaching a different, private address.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetricsListenerConfig {
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub bind: SocketAddr,
}

impl std::fmt::Debug for MetricsListenerConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("MetricsListenerConfig")
            .field("bind", &"<redacted>")
            .finish()
    }
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SecretProvidersConfig {
    #[serde(default)]
    pub file: Option<FileSecretProviderConfig>,
    #[serde(default)]
    pub environment: Option<EnvironmentSecretProviderConfig>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentSecretProviderConfig {}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FileSecretProviderConfig {
    pub root: PathBuf,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DatabaseConfig {
    pub runtime_url_ref: String,
    pub migration_url_ref: String,
    #[serde(default)]
    pub trusted_root_certificate_ref: Option<String>,
    #[serde(default)]
    pub test_only_plaintext: bool,
}

impl std::fmt::Debug for DatabaseConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DatabaseConfig")
            .field("runtime_url_ref", &"<redacted>")
            .field("migration_url_ref", &"<redacted>")
            .field(
                "trusted_root_certificate_ref",
                &self
                    .trusted_root_certificate_ref
                    .as_ref()
                    .map(|_| "<redacted>"),
            )
            .field("test_only_plaintext", &self.test_only_plaintext)
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
    pub issuer: String,
    pub audience: String,
    #[serde(default)]
    pub jwks_uri: Option<String>,
    #[serde(default)]
    pub jwks_source: OidcJwksSource,
    #[serde(default = "default_scope_claim")]
    pub scope_claim: String,
    /// The OAuth clients this runtime admits. Every access profile resolves
    /// its caller from the matched client, so the list is never empty, and
    /// every client a profile names must appear here.
    pub allowed_clients: Vec<String>,
    /// The assertion authorities each client may exchange a subject token
    /// from, keyed by client identifier. A deployment that performs no token
    /// exchange leaves this empty, and an exchanged token is then refused.
    #[serde(default)]
    pub assertion_issuers: BTreeMap<String, Vec<String>>,
}

fn default_scope_claim() -> String {
    "registry_scopes".to_owned()
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum OidcJwksSource {
    #[default]
    Discovery,
    Static {
        #[serde(rename = "documentRef")]
        document_ref: String,
    },
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditConfig {
    pub path: PathBuf,
    pub hash_key_ref: String,
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
        Self::load_with_environment(path, &|name| std::env::var(name).ok())
    }

    /// Load and validate the operator document, reading `${VAR}` expressions
    /// through `lookup`.
    pub fn load_with_environment(
        path: impl AsRef<Path>,
        lookup: &impl Fn(&str) -> Option<String>,
    ) -> Result<Self, RuntimeConfigError> {
        if !path.as_ref().is_absolute() {
            return Err(RuntimeConfigError::RelativeRuntimePath);
        }
        let bytes = read_bounded(path.as_ref()).map_err(RuntimeConfigError::Read)?;
        let config = Self::parse_with_environment(&bytes, lookup)?;
        config.check()?;
        Ok(config)
    }

    /// Parse the operator document without checking it.
    ///
    /// Environment expressions are expanded over the document text by
    /// `registry-platform-config` before the YAML is parsed, so an expanded
    /// value is quoted as one string where it fills a whole value and refused
    /// where it could change the document's shape. Before that, the document
    /// as written is read once to refuse an expression in any member whose
    /// name ends in `Ref`: a credential is named by a `secret:` reference the
    /// resolver reads, never by text an environment variable spliced in.
    fn parse_with_environment(
        bytes: &[u8],
        lookup: &impl Fn(&str) -> Option<String>,
    ) -> Result<Self, RuntimeConfigError> {
        let written: serde_json::Value =
            serde_norway::from_slice(bytes).map_err(|error| RuntimeConfigError::Parse {
                path: "/".to_owned(),
                cause: redact_refused_values(&error.to_string()),
            })?;
        reject_config_env_expressions_in(&written, |name| name.ends_with(CREDENTIAL_MEMBER_SUFFIX))
            .map_err(|refused| RuntimeConfigError::Environment {
                path: refused.path().to_owned(),
                reason: "an environment expression is not accepted in a credential member; name \
                     the secret with a secret:env/NAME or secret:file/name reference instead"
                    .to_owned(),
            })?;
        // `from_slice` above has already refused a document that is not UTF-8.
        let text = std::str::from_utf8(bytes).map_err(|_| RuntimeConfigError::Parse {
            path: "/".to_owned(),
            cause: "the document is not UTF-8".to_owned(),
        })?;
        let expanded = expand_config_env_vars_with(text, lookup).map_err(|error| {
            RuntimeConfigError::Environment {
                path: "/".to_owned(),
                reason: error.to_string(),
            }
        })?;
        if expanded.len() as u64 > MAXIMUM_DOCUMENT_BYTES {
            return Err(RuntimeConfigError::Environment {
                path: "/".to_owned(),
                reason: "the expanded document exceeds one mebibyte".to_owned(),
            });
        }
        let document: serde_norway::Value =
            serde_norway::from_str(&expanded).map_err(|error| RuntimeConfigError::Parse {
                path: "/".to_owned(),
                cause: redact_refused_values(&error.to_string()),
            })?;
        serde_path_to_error::deserialize(document).map_err(|error| {
            let (path, cause) = refused_yaml(error);
            RuntimeConfigError::Parse { path, cause }
        })
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
        let loaded = load_package(&self.package.root).map_err(RuntimeConfigError::Package)?;
        if let Some(expected) = &self.package.expected_digest {
            if expected != loaded.package.digest() {
                return Err(RuntimeConfigError::PackageDigestMismatch {
                    expected: expected.clone(),
                    actual: loaded.package.digest().to_owned(),
                });
            }
        }
        let allowed: BTreeSet<&str> = self
            .authentication
            .oidc
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

    pub fn check(&self) -> Result<(), RuntimeConfigError> {
        if self.api_version != MESSAGING_RUNTIME_API_VERSION {
            return Err(RuntimeConfigError::InvalidApiVersion);
        }
        if self.kind != MESSAGING_RUNTIME_KIND {
            return Err(RuntimeConfigError::InvalidKind);
        }
        if !self.package.root.is_absolute() {
            return Err(RuntimeConfigError::RelativeOperatedPath("package.root"));
        }
        if let Some(digest) = &self.package.expected_digest {
            if !valid_package_digest(digest) {
                return Err(RuntimeConfigError::InvalidExpectedDigest);
            }
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
        if let Some(metrics) = &self.metrics_listener {
            if !valid_metrics_listener(metrics.bind, self.listener.bind) {
                return Err(RuntimeConfigError::InvalidMetricsListener);
            }
        }
        let oidc = &self.authentication.oidc;
        if oidc.issuer.is_empty()
            || oidc.audience.is_empty()
            || oidc.scope_claim.is_empty()
            || oidc.allowed_clients.is_empty()
            || oidc.allowed_clients.iter().any(String::is_empty)
        {
            return Err(RuntimeConfigError::InvalidOidc);
        }
        self.validate_assertion_issuers()?;
        if self.database.runtime_url_ref.is_empty() || self.database.migration_url_ref.is_empty() {
            return Err(RuntimeConfigError::InvalidDatabaseReference);
        }
        if self.audit.hash_key_ref.is_empty() {
            return Err(RuntimeConfigError::InvalidAuditReference);
        }
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
        let reference = SecretReference::parse(raw)
            .map_err(|_| format!("{field} is not a valid secret reference"))?;
        let enabled = match reference.provider() {
            SecretProvider::File => self.secret_providers.file.is_some(),
            SecretProvider::Environment => self.secret_providers.environment.is_some(),
        };
        if enabled {
            Ok(())
        } else {
            Err(format!(
                "{field} uses a secret provider that is not explicitly enabled"
            ))
        }
    }

    /// Refuse an assertion-issuer map with too many clients, an oversized
    /// client key or issuer string, too many issuers for one client, a
    /// repeated issuer, or a client the deployment does not admit.
    fn validate_assertion_issuers(&self) -> Result<(), RuntimeConfigError> {
        let oidc = &self.authentication.oidc;
        if oidc.assertion_issuers.len() > MAXIMUM_ASSERTION_ISSUER_CLIENTS {
            return Err(RuntimeConfigError::InvalidOidc);
        }
        for (client, issuers) in &oidc.assertion_issuers {
            if client.is_empty()
                || client.len() > MAXIMUM_ASSERTION_ISSUER_CLIENT_BYTES
                || issuers.is_empty()
                || issuers.len() > MAXIMUM_ASSERTION_ISSUERS_PER_CLIENT
                || !oidc.allowed_clients.contains(client)
            {
                return Err(RuntimeConfigError::InvalidOidc);
            }
            let mut seen = BTreeSet::new();
            for issuer in issuers {
                if issuer.is_empty()
                    || issuer.len() > MAXIMUM_ASSERTION_ISSUER_BYTES
                    || !seen.insert(issuer)
                {
                    return Err(RuntimeConfigError::InvalidOidc);
                }
            }
        }
        Ok(())
    }

    fn validate_secret_references(&self) -> Result<(), RuntimeConfigError> {
        let mut references = vec![
            ("database.runtimeUrlRef", &self.database.runtime_url_ref),
            ("database.migrationUrlRef", &self.database.migration_url_ref),
            ("audit.hashKeyRef", &self.audit.hash_key_ref),
        ];
        if let Some(reference) = &self.database.trusted_root_certificate_ref {
            references.push(("database.trustedRootCertificateRef", reference));
        }
        if let OidcJwksSource::Static { document_ref } = &self.authentication.oidc.jwks_source {
            references.push(("authentication.oidc.jwksSource.documentRef", document_ref));
        }
        for (path, raw) in references {
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

    /// Build the token verifier's key source from the configured JWKS source.
    pub async fn jwks_fetcher(
        &self,
        secrets: &SecretResolver,
    ) -> Result<std::sync::Arc<JwksFetcher>, RuntimeConfigError> {
        let fetcher = match &self.authentication.oidc.jwks_source {
            OidcJwksSource::Discovery => {
                let discovery = fetch_discovery(&OidcDiscoveryConfig {
                    issuer: self.authentication.oidc.issuer.clone(),
                    jwks_uri_override: self.authentication.oidc.jwks_uri.clone(),
                    discovery_timeout: Duration::from_secs(5),
                    max_doc_bytes: 1024 * 1024,
                })
                .await
                .map_err(|_| RuntimeConfigError::Oidc)?;
                JwksFetcher::new(discovery.jwks_uri, JwksFetcherConfig::defaults())
            }
            OidcJwksSource::Static { document_ref } => {
                let document = secrets.resolve(document_ref).map_err(|error| {
                    RuntimeConfigError::OidcJwksSecret(describe_secret_failure(
                        "authentication.oidc.jwksSource.documentRef",
                        document_ref,
                        &error,
                    ))
                })?;
                let jwks = parse_static_jwks(document.expose_secret())?;
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
            self.authentication.oidc.issuer.clone(),
            vec![self.authentication.oidc.audience.clone()],
            vec![Algorithm::RS256, Algorithm::ES256],
            access_token_typ_set(MESSAGING_ACCESS_TOKEN_TYPE),
        )
        .with_scope_claim(self.authentication.oidc.scope_claim.clone())
        .with_allowed_clients(self.authentication.oidc.allowed_clients.clone())
        .with_assertion_issuers(self.authentication.oidc.assertion_issuers.clone())
    }

    /// Whether this deployment declared any token-exchange authority.
    #[must_use]
    pub fn binds_assertion_issuers(&self) -> bool {
        !self.authentication.oidc.assertion_issuers.is_empty()
    }

    /// Build the secret resolver from the providers this document enables.
    pub fn secret_resolver(&self) -> Result<SecretResolver, RuntimeConfigError> {
        let mut providers = Vec::new();
        if self.secret_providers.environment.is_some() {
            providers.push(SecretProvider::Environment);
        }
        if self.secret_providers.file.is_some() {
            providers.push(SecretProvider::File);
        }
        let root = self
            .secret_providers
            .file
            .as_ref()
            .map_or_else(|| PathBuf::from("/"), |file| file.root.clone());
        SecretResolver::new(providers, root).map_err(|_| RuntimeConfigError::InvalidSecretProviders)
    }
}

fn read_bounded(path: &Path) -> std::io::Result<Vec<u8>> {
    use std::io::Read as _;
    let file = std::fs::File::open(path)?;
    let mut bytes = Vec::new();
    file.take(MAXIMUM_DOCUMENT_BYTES + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAXIMUM_DOCUMENT_BYTES {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "the document exceeds one mebibyte",
        ));
    }
    Ok(bytes)
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

fn parse_static_jwks(bytes: &[u8]) -> Result<JwkSet, RuntimeConfigError> {
    let jwks: JwkSet = serde_json::from_slice(bytes).map_err(|_| RuntimeConfigError::Oidc)?;
    let mut kids = BTreeSet::new();
    if jwks.keys.is_empty()
        || jwks.keys.iter().any(|key| {
            !matches!(
                key.algorithm,
                AlgorithmParameters::RSA(_) | AlgorithmParameters::EllipticCurve(_)
            ) || key
                .common
                .key_id
                .as_ref()
                .is_none_or(|kid| kid.is_empty() || !kids.insert(kid.clone()))
        })
    {
        return Err(RuntimeConfigError::Oidc);
    }
    Ok(jwks)
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
    #[error("the Messaging runtime configuration could not be read")]
    Read(#[source] std::io::Error),
    #[error("the Messaging runtime configuration is not valid at {path}: {cause}")]
    Parse { path: String, cause: String },
    #[error("the environment expression at {path} is refused: {reason}")]
    Environment { path: String, reason: String },
    #[error("unsupported Messaging runtime apiVersion; expected {MESSAGING_RUNTIME_API_VERSION}")]
    InvalidApiVersion,
    #[error("unsupported Messaging runtime kind; expected {MESSAGING_RUNTIME_KIND}")]
    InvalidKind,
    #[error("the operated runtime path {0} must be absolute")]
    RelativeOperatedPath(&'static str),
    #[error("the selected Messaging runtime configuration path must be absolute")]
    RelativeRuntimePath,
    #[error("package.expectedDigest must be sha256: followed by 64 lowercase hexadecimal digits")]
    InvalidExpectedDigest,
    #[error(
        "package.expectedDigest is {expected}, but the package under package.root has digest \
         {actual}"
    )]
    PackageDigestMismatch { expected: String, actual: String },
    #[error("secretProviders must explicitly enable file, environment, or both")]
    InvalidSecretProviders,
    #[error("{path} is not a valid secret reference")]
    InvalidSecretReference { path: &'static str },
    #[error("{path} uses a secret provider that is not explicitly enabled")]
    SecretProviderRequired { path: &'static str },
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
    #[error("audit.hashKeyRef must be a non-empty secret reference")]
    InvalidAuditReference,
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
            Self::InvalidApiVersion => "apiVersion",
            Self::InvalidKind => "kind",
            Self::RelativeOperatedPath(path) => path,
            Self::RelativeRuntimePath | Self::Read(_) => "/",
            Self::Parse { path, .. } => path,
            Self::Environment { path, .. } => path,
            Self::InvalidExpectedDigest | Self::PackageDigestMismatch { .. } => {
                "package.expectedDigest"
            }
            Self::InvalidSecretProviders => "secretProviders",
            Self::InvalidSecretReference { path } | Self::SecretProviderRequired { path } => path,
            Self::InvalidOidc | Self::Oidc => "authentication.oidc",
            Self::OidcJwksSecret(_) => "authentication.oidc.jwksSource.documentRef",
            Self::InvalidListener => "listener",
            Self::InvalidMetricsListener => "metricsListener.bind",
            Self::InvalidDatabaseReference | Self::PlaintextDatabase => "database",
            Self::InvalidAuditReference => "audit.hashKeyRef",
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
        let path = root.join("runtime.yaml");
        std::fs::write(&path, serde_norway::to_string(runtime).unwrap()).unwrap();
        path
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
    fn a_development_configuration_loads_with_its_defaults() {
        let config = load(base()).unwrap();
        assert_eq!(config.retention, RetentionConfig::default());
        assert_eq!(config.authentication.oidc.scope_claim, "registry_scopes");
        assert!(config.metrics_listener.is_none());
        assert_eq!(config.listener.bind, DEFAULT_LISTENER_BIND.parse().unwrap());
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
                matches!(error, RuntimeConfigError::Parse { .. }),
                "{key}: {error}"
            );
            assert!(error.to_string().contains(key), "{error}");
        }
    }

    #[test]
    fn an_environment_expression_in_a_credential_field_is_refused() {
        let mut value = base();
        value["database"]["runtimeUrlRef"] = json!("${DATABASE_URL}");
        let error = load(value).unwrap_err();
        assert!(
            matches!(error, RuntimeConfigError::Environment { .. }),
            "{error}"
        );
        assert_eq!(error.path(), "database.runtimeUrlRef");
        assert!(error.to_string().contains("credential member"), "{error}");

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
        assert_eq!(error.path(), "database.runtimeUrlRef", "{error}");
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
    fn an_environment_expression_elsewhere_is_expanded() {
        let root = tempfile::tempdir().unwrap();
        let mut runtime = runtime_value(root.path());
        runtime["listener"]["bind"] = json!("${MESSAGING_BIND}");
        runtime["authentication"]["oidc"]["issuer"] = json!("${ISSUER:-https://fallback.test}");
        let path = write_project(root.path(), &runtime, &package_value());
        let config = RuntimeConfig::load_with_environment(&path, &|name| {
            (name == "MESSAGING_BIND").then(|| "127.0.0.1:9107".to_owned())
        })
        .unwrap();
        assert_eq!(config.listener.bind, "127.0.0.1:9107".parse().unwrap());
        assert_eq!(config.authentication.oidc.issuer, "https://fallback.test");

        // Expansion runs over the document text, so an unset variable is
        // refused at the document root rather than at its member.
        let error = RuntimeConfig::load_with_environment(&path, &no_environment).unwrap_err();
        assert!(
            matches!(error, RuntimeConfigError::Environment { .. }),
            "{error}"
        );
        assert_eq!(error.path(), "/");
        assert!(error.to_string().contains("MESSAGING_BIND"), "{error}");
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
        assert!(matches!(error, RuntimeConfigError::InvalidKind), "{error}");

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
            assert!(
                matches!(error, RuntimeConfigError::Environment { .. }),
                "{error}"
            );
            assert_eq!(error.path(), "/");
            assert!(error.to_string().contains("HOST"), "{error}");
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
                matches!(error, RuntimeConfigError::Environment { .. }),
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
            RuntimeConfigError::Parse { .. }
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
            RuntimeConfigError::InvalidOidc
        ));
        let mut value = base();
        value["authentication"]["oidc"]["assertionIssuers"] =
            json!({"case-system": ["https://assertions.example.test"]});
        assert!(load(value).unwrap().binds_assertion_issuers());
    }

    #[test]
    fn a_pinned_package_digest_must_equal_the_digest_of_the_package_read() {
        let mut value = base();
        value["package"]["expectedDigest"] = json!("sha256:ABC");
        assert!(matches!(
            load(value).unwrap_err(),
            RuntimeConfigError::InvalidExpectedDigest
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
        assert!(
            matches!(
                &error,
                RuntimeConfigError::PackageDigestMismatch { expected, actual }
                    if *expected == pinned && *actual == digest
            ),
            "{error}"
        );
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
            RuntimeConfigError::PackageDigestMismatch { .. }
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
        assert!(matches!(
            error,
            RuntimeConfigError::InvalidSecretReference {
                path: "database.runtimeUrlRef"
            }
        ));
        assert!(!error.to_string().contains("hunter2"));

        let mut value = base();
        value["secretProviders"] = json!({"file": {"root": "/placeholder/secrets"}});
        assert!(matches!(
            load(value).unwrap_err(),
            RuntimeConfigError::SecretProviderRequired { .. }
        ));

        let mut value = base();
        value["secretProviders"] = json!({});
        assert!(matches!(
            load(value).unwrap_err(),
            RuntimeConfigError::InvalidSecretProviders
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
            Err(RuntimeConfigError::RelativeRuntimePath)
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
            RuntimeConfigError::Parse { .. }
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
        assert!(
            error.to_string().contains("not explicitly enabled"),
            "{error}"
        );

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
