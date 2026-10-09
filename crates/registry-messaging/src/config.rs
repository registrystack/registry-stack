// SPDX-License-Identifier: Apache-2.0

//! The operator runtime configuration document and the package it names.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use jsonwebtoken::Algorithm;
use registry_messaging_core::{
    typed, ProviderKind, MESSAGING_RUNTIME_API_VERSION, MESSAGING_RUNTIME_KIND, PACKAGE_FILE,
    RETIRED_MESSAGING_RUNTIME_API_VERSION,
};
use registry_platform_audit::{
    AuditDestination, AuditDestinationError, AuditDestinationKind, MAX_AUDIT_RETAIN_DAYS,
    MIN_AUDIT_ROTATE_BYTES,
};
use registry_platform_config::{
    AuditKeyConfig, ConfigBlockError, ConfigBlockErrorKind, RemovedKey, RuntimeConfigLoader,
    RuntimeEnvelope, RuntimeFileCheck, SecretReference, SecretResolver, DEFAULT_STAND_IN,
    REMOVED_OIDC_JWKS_URI,
};
pub use registry_platform_config::{
    DatabaseConfig, EnvironmentSecretProviderConfig, FileSecretProviderConfig,
    JwksSource as OidcJwksSource, ListenerConfig as MetricsListenerConfig, ListenerNetworkExposure,
    OidcClientsConfig, OidcIssuerConfig, PackageConfig as RuntimePackageConfig,
    PrivateListenerConfig as ListenerConfig, SecretProvidersConfig, TlsTermination,
    MAX_ASSERTION_ISSUERS_PER_CLIENT as MAXIMUM_ASSERTION_ISSUERS_PER_CLIENT,
    MAX_ASSERTION_ISSUER_BYTES as MAXIMUM_ASSERTION_ISSUER_BYTES,
    MAX_ASSERTION_ISSUER_CLIENTS as MAXIMUM_ASSERTION_ISSUER_CLIENTS,
    MAX_ASSERTION_ISSUER_CLIENT_BYTES as MAXIMUM_ASSERTION_ISSUER_CLIENT_BYTES,
    UNAVAILABLE_CODE as RUNTIME_CONFIG_UNAVAILABLE_CODE,
};
use registry_platform_oidc::{
    access_token_typ_set, fetch_discovery, parse_static_jwks, JwksFetcher, JwksFetcherConfig,
    OidcDiscoveryConfig, TokenVerifierConfig,
};
use registry_platform_yaml::{
    escape_pointer_segment, Diagnostic, Related, Report, RetiredApiVersion,
};
use serde::{Deserialize, Deserializer};
use thiserror::Error;

use crate::http_provider::{HttpProviderError, HttpProviderSettings};
use crate::package::{load_runtime_package, LoadedPackage, PackageLoadError, PackageLoadReason};
use crate::smtp::SmtpProviderSettings;

pub(crate) use registry_platform_config::describe_secret_failure;

/// The configuration name of a provider kind.
pub(crate) const fn provider_kind_name(kind: ProviderKind) -> &'static str {
    match kind {
        ProviderKind::Smtp => "smtp",
        ProviderKind::Http => "http",
    }
}

/// Read a member that holds one exact secret reference (CFG-SEC-1), refusing
/// any other text at the member's own position. The model keeps the
/// reference as text.
pub(crate) fn secret_reference<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    SecretReference::deserialize(deserializer).map(|reference| reference.as_str().to_owned())
}

/// [`secret_reference`] for an optional member; absent reads as `None`
/// through `serde(default)`.
pub(crate) fn optional_secret_reference<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    secret_reference(deserializer).map(Some)
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

/// The keys the runtime document no longer accepts, each with what replaced
/// it (CFG-CHANGE-2).
pub const MESSAGING_REMOVED_KEYS: &[RemovedKey] = &[
    REMOVED_OIDC_JWKS_URI,
    RemovedKey {
        path: "providers.*.attemptTimeoutSeconds",
        replacement: "Write attemptTimeoutMilliseconds in milliseconds: \
                      `attemptTimeoutSeconds: 10` becomes `attemptTimeoutMilliseconds: 10000`.",
    },
    RemovedKey {
        path: "providers.*.timeoutMilliseconds",
        replacement: "Write attemptTimeoutMilliseconds with the same number of milliseconds.",
    },
    RemovedKey {
        path: "providers.*.concurrencyLimit",
        replacement: "Write maximumConcurrentRequests with the same value.",
    },
    RemovedKey {
        path: "providers.*.kind",
        replacement: "Write type with the same value.",
    },
    RemovedKey {
        path: "providers.*.authentication.kind",
        replacement: "Write type with the same value.",
    },
    RemovedKey {
        path: "providers.*.callbackVerifier.kind",
        replacement: "Write type with the same value.",
    },
    RemovedKey {
        path: "retention.payloadDays",
        replacement: "Write retention.payloadRetentionDays with the same value.",
    },
    RemovedKey {
        path: "retention.recordDays",
        replacement: "Write retention.recordRetentionDays with the same value.",
    },
    RemovedKey {
        path: "retention.submissionReceiptDays",
        replacement: "Write retention.submissionReceiptRetentionDays with the same value.",
    },
    RemovedKey {
        path: "audit.retainDays",
        replacement: "Write audit.retentionDays with the same value.",
    },
];

/// The `apiVersion` values the runtime document no longer accepts.
const MESSAGING_RETIRED_API_VERSIONS: &[RetiredApiVersion<'static>] = &[RetiredApiVersion {
    api_version: RETIRED_MESSAGING_RUNTIME_API_VERSION,
    replacement: "Write apiVersion: id.registrystack.org/formats/messaging/runtime/v1alpha1.",
}];

/// Retention defaults and bounds. A jurisdiction's retention schedule
/// approves the deployed values; the bounds only keep a typo from becoming a
/// policy.
pub const DEFAULT_PAYLOAD_RETENTION_DAYS: u16 = 7;
pub const MAXIMUM_PAYLOAD_RETENTION_DAYS: u16 = 30;
pub const DEFAULT_RECORD_RETENTION_DAYS: u16 = 90;
pub const MAXIMUM_RECORD_RETENTION_DAYS: u16 = 3650;
pub const DEFAULT_SUBMISSION_RECEIPT_RETENTION_DAYS: u16 = 7;

/// The most trust profiles one runtime document declares.
pub const MAXIMUM_TLS_TRUST_PROFILES: usize = 64;

/// The largest `audit.rotateBytes`.
pub const MAXIMUM_AUDIT_ROTATE_BYTES: u64 = u32::MAX as u64;

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
    #[serde(default, deserialize_with = "typed::local_id_map")]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "typed::local_id_map_schema::<ProviderConnection>")
    )]
    pub providers: BTreeMap<String, ProviderConnection>,
    /// Named PEM bundles an `http` provider's `tlsTrustProfile` trusts in
    /// addition to the system roots, at most 64.
    #[serde(default, deserialize_with = "typed::local_id_map")]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "typed::local_id_map_schema::<TlsTrustProfileConfig>")
    )]
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

/// One provider's runtime half. The package declares the provider's type,
/// and for an `http` provider its scripts; the two halves must name the same
/// type.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
#[derive(Clone, Debug, Deserialize)]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ProviderConnection {
    Smtp {
        #[serde(rename(deserialize = "registry-platform-yaml/shared-block/smtp-provider"))]
        #[cfg_attr(feature = "schema", schemars(flatten))]
        settings: SmtpProviderSettings,
    },
    Http {
        /// Boxed: an `http` connection is several times the size of an
        /// `smtp` one.
        #[serde(rename(deserialize = "registry-platform-yaml/shared-block/http-provider"))]
        #[cfg_attr(feature = "schema", schemars(flatten))]
        settings: Box<HttpProviderSettings>,
    },
}
registry_platform_yaml::tagged_union!(ProviderConnection);

impl ProviderConnection {
    /// The provider kind this connection is for.
    #[must_use]
    pub const fn kind(&self) -> ProviderKind {
        match self {
            Self::Smtp { .. } => ProviderKind::Smtp,
            Self::Http { .. } => ProviderKind::Http,
        }
    }

    /// Every secret reference the connection names, with the member naming
    /// it.
    #[must_use]
    pub fn secret_references(&self) -> Vec<(&'static str, &str)> {
        match self {
            Self::Smtp { settings } => settings.secret_references(),
            Self::Http { settings } => settings.secret_references(),
        }
    }
}

/// A PEM bundle of one or more certificate authorities, held in the secret
/// provider so it is read under the same file checks as every credential.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TlsTrustProfileConfig {
    #[serde(deserialize_with = "secret_reference")]
    #[cfg_attr(feature = "schema", schemars(with = "SecretReference"))]
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

/// The OIDC issuer whose access tokens this runtime accepts, the clients it
/// admits, and the claim carrying their scopes.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OidcConfig {
    /// The exact token issuer, audience, and signing-key source.
    #[serde(rename(deserialize = "registry-platform-yaml/shared-block/oidc-issuer"))]
    #[cfg_attr(feature = "schema", schemars(flatten))]
    pub provider: OidcIssuerConfig,
    /// The OAuth clients this runtime admits. Every access profile resolves
    /// its caller from the matched client, so the list is never empty, and
    /// every client a profile names must appear here.
    #[serde(rename(deserialize = "registry-platform-yaml/shared-block/oidc-clients"))]
    #[cfg_attr(feature = "schema", schemars(flatten))]
    pub clients: OidcClientsConfig,
    #[serde(default = "default_scope_claim")]
    pub scope_claim: String,
}

fn default_scope_claim() -> String {
    "registry_scopes".to_owned()
}

/// Where the audit journal is written and the key its hashes are made with.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditConfig {
    /// The secret keying the audit journal's hashes, `hashKeyRef`.
    #[serde(rename(deserialize = "registry-platform-yaml/shared-block/audit-key"))]
    #[cfg_attr(feature = "schema", schemars(flatten))]
    pub key: AuditKeyConfig,
    /// Where audit entries go: a rotated `file` (the default) or `stdout`.
    #[serde(default)]
    pub destination: AuditDestinationKind,
    /// The absolute path of the active audit file, for `destination: file`.
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(extend("pattern" = "^/")))]
    pub path: Option<PathBuf>,
    /// The size at which the active file is sealed and a new one begun.
    #[serde(
        default,
        deserialize_with = "typed::optional_bounded_u64::<_, MIN_AUDIT_ROTATE_BYTES, MAXIMUM_AUDIT_ROTATE_BYTES>"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(range(min = MIN_AUDIT_ROTATE_BYTES, max = MAXIMUM_AUDIT_ROTATE_BYTES))
    )]
    pub rotate_bytes: Option<u64>,
    /// How many days a sealed audit file is kept.
    #[serde(
        default,
        rename = "retentionDays",
        deserialize_with = "typed::optional_bounded_u32::<_, 1, MAX_AUDIT_RETAIN_DAYS>"
    )]
    #[cfg_attr(feature = "schema", schemars(range(min = 1, max = MAX_AUDIT_RETAIN_DAYS)))]
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
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetentionConfig {
    /// How long a message's rendered payload and recipient contact are kept,
    /// from 1 to 30 days.
    #[serde(
        default = "default_payload_retention_days",
        deserialize_with = "typed::bounded_u16::<_, 1, 30>"
    )]
    #[cfg_attr(feature = "schema", schemars(range(min = 1, max = 30)))]
    pub payload_retention_days: u16,
    /// How long the content-free message record is kept, at least as long as
    /// the payload and at most ten years.
    #[serde(
        default = "default_record_retention_days",
        deserialize_with = "typed::bounded_u16::<_, 1, 3650>"
    )]
    #[cfg_attr(feature = "schema", schemars(range(min = 1, max = 3650)))]
    pub record_retention_days: u16,
    /// How long a submission receipt stays replayable under its idempotency
    /// key, from one day to the record period.
    #[serde(
        default = "default_submission_receipt_retention_days",
        deserialize_with = "typed::bounded_u16::<_, 1, 3650>"
    )]
    #[cfg_attr(feature = "schema", schemars(range(min = 1, max = 3650)))]
    pub submission_receipt_retention_days: u16,
}

const _: () = assert!(MAXIMUM_PAYLOAD_RETENTION_DAYS == 30);
const _: () = assert!(MAXIMUM_RECORD_RETENTION_DAYS == 3650);

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            payload_retention_days: DEFAULT_PAYLOAD_RETENTION_DAYS,
            record_retention_days: DEFAULT_RECORD_RETENTION_DAYS,
            submission_receipt_retention_days: DEFAULT_SUBMISSION_RECEIPT_RETENTION_DAYS,
        }
    }
}

impl RetentionConfig {
    /// The retention periods as the audit journal and `messagingctl` report
    /// them, keyed as the runtime document spells them.
    #[must_use]
    pub fn report(&self) -> serde_json::Value {
        serde_json::json!({
            "payloadRetentionDays": self.payload_retention_days,
            "recordRetentionDays": self.record_retention_days,
            "submissionReceiptRetentionDays": self.submission_receipt_retention_days,
        })
    }
}

const fn default_payload_retention_days() -> u16 {
    DEFAULT_PAYLOAD_RETENTION_DAYS
}

const fn default_record_retention_days() -> u16 {
    DEFAULT_RECORD_RETENTION_DAYS
}

const fn default_submission_receipt_retention_days() -> u16 {
    DEFAULT_SUBMISSION_RECEIPT_RETENTION_DAYS
}

/// A rule a runtime document must satisfy on its own; it records every
/// finding.
type FileRule = fn(&RuntimeConfig, &mut Vec<RuntimeConfigError>);
/// A rule a runtime document must satisfy against the package it serves.
type PackageRule = fn(&RuntimeConfig, &LoadedPackage, &mut Vec<RuntimeConfigError>);

/// The rules a runtime document satisfies on its own, in the order startup
/// applies them.
const FILE_RULES: &[FileRule] = &[
    RuntimeConfig::check_identity,
    RuntimeConfig::check_package_block,
    RuntimeConfig::check_secret_providers,
    RuntimeConfig::check_audit,
    RuntimeConfig::check_secret_references,
    RuntimeConfig::check_listeners,
    RuntimeConfig::check_oidc,
    RuntimeConfig::check_database,
    RuntimeConfig::check_retention,
    RuntimeConfig::check_provider_settings,
];

/// The rules a runtime document satisfies against the package it serves.
const PACKAGE_RULES: &[PackageRule] = &[
    RuntimeConfig::check_profile_clients,
    RuntimeConfig::check_providers,
];

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
            .retired_api_versions(MESSAGING_RETIRED_API_VERSIONS)
            .max_bytes(MAXIMUM_DOCUMENT_BYTES)
    }

    /// Parse the operator document without checking it, for focused tests.
    #[cfg(test)]
    fn parse_with_environment(
        text: &str,
        lookup: &impl Fn(&str) -> Option<String>,
    ) -> Result<Self, RuntimeConfigError> {
        Ok(Self::loader().parse_str(text, lookup)?.config)
    }

    #[must_use]
    pub fn package_path(&self) -> PathBuf {
        self.package.root.join(PACKAGE_FILE)
    }

    /// Read and check the package this deployment runs, and hold this
    /// document to the rules about it: every client a profile names must be
    /// one the OIDC settings admit, or the profile could never be reached;
    /// every provider connection must be for a provider the package declares,
    /// of the declared type; and a pinned `expectedDigest` must equal the
    /// digest of what was read.
    pub fn load_package(&self) -> Result<LoadedPackage, RuntimeConfigError> {
        let loaded = load_runtime_package(&self.package).map_err(RuntimeConfigError::Package)?;
        let mut findings = Vec::new();
        for rule in PACKAGE_RULES {
            rule(self, &loaded, &mut findings);
        }
        first(findings)?;
        Ok(loaded)
    }

    #[must_use]
    pub fn database_id(&self) -> &str {
        self.identity
            .as_ref()
            .map_or("", |identity| identity.database_id.as_str())
    }

    /// Refuse the document at its first broken rule, then read the package
    /// it names and refuse it at the first rule about that package.
    pub fn check(&self) -> Result<(), RuntimeConfigError> {
        first(self.findings(None))?;
        self.load_package().map(|_| ())
    }

    /// Every rule this document breaks, in the order startup applies them.
    /// The rules about the package it serves run when `package` is given.
    /// Each finding names the member it concerns and never a configured
    /// value.
    #[must_use]
    pub fn findings(&self, package: Option<&LoadedPackage>) -> Vec<RuntimeConfigError> {
        let mut findings = Vec::new();
        for rule in FILE_RULES {
            rule(self, &mut findings);
        }
        if let Some(package) = package {
            for rule in PACKAGE_RULES {
                rule(self, package, &mut findings);
            }
        }
        findings
    }

    fn check_identity(&self, findings: &mut Vec<RuntimeConfigError>) {
        match &self.identity {
            None => findings.push(RuntimeConfigError::MissingIdentity),
            Some(identity) if !valid_database_id(&identity.database_id) => {
                findings.push(RuntimeConfigError::InvalidIdentity);
            }
            Some(_) => {}
        }
    }

    fn check_package_block(&self, findings: &mut Vec<RuntimeConfigError>) {
        if let Err(error) = self.package.check() {
            findings.push(error.into());
        }
    }

    fn check_secret_providers(&self, findings: &mut Vec<RuntimeConfigError>) {
        if let Err(error) = self.secret_providers.check() {
            findings.push(error.into());
        }
    }

    fn check_audit(&self, findings: &mut Vec<RuntimeConfigError>) {
        if let Err(error) = self.audit.destination() {
            findings.push(error);
        }
    }

    /// Every secret reference must name a provider `secretProviders`
    /// enables. Each already parsed as an exact reference when the document
    /// was read.
    fn check_secret_references(&self, findings: &mut Vec<RuntimeConfigError>) {
        // With no provider enabled every reference would be refused; the
        // provider rule reports that once.
        if self.secret_providers.check().is_err() {
            return;
        }
        let mut references = self.database.references();
        references.push(("audit.hashKeyRef", self.audit.key.hash_key_ref.as_str()));
        if let Some(document_ref) = self.authentication.oidc.provider.jwks_source.document_ref() {
            references.push(("authentication.oidc.jwksSource.documentRef", document_ref));
        }
        for (field, raw) in references {
            if let Err(error) = self.secret_providers.check_reference(field, raw) {
                findings.push(error.into());
            }
        }
        for (name, profile) in &self.tls_trust_profiles {
            self.check_keyed_reference(
                findings,
                &["tlsTrustProfiles", name, "bundleRef"],
                &profile.bundle_ref,
            );
        }
        for (id, connection) in &self.providers {
            for (member, reference) in connection.secret_references() {
                let mut segments = vec!["providers", id.as_str()];
                segments.extend(member.split('.'));
                self.check_keyed_reference(findings, &segments, reference);
            }
        }
    }

    /// Check one secret reference of a member under a map keyed by an id the
    /// operator chose, located structurally so the finding points at its
    /// member.
    fn check_keyed_reference(
        &self,
        findings: &mut Vec<RuntimeConfigError>,
        segments: &[&str],
        raw: &str,
    ) {
        if let Err(error) = self
            .secret_providers
            .check_reference(&segments.join("."), raw)
        {
            findings.push(RuntimeConfigError::BindingSecret {
                pointer: pointer_to(segments),
                error,
            });
        }
    }

    fn check_listeners(&self, findings: &mut Vec<RuntimeConfigError>) {
        if !self.listener.is_valid() {
            findings.push(RuntimeConfigError::InvalidListener);
        }
        if let Some(metrics) = &self.metrics_listener {
            if !valid_metrics_listener(metrics.bind.socket_addr(), self.listener.bind.socket_addr())
            {
                findings.push(RuntimeConfigError::InvalidMetricsListener);
            }
        }
    }

    fn check_oidc(&self, findings: &mut Vec<RuntimeConfigError>) {
        let oidc = &self.authentication.oidc;
        if let Err(error) = oidc.provider.check(
            "authentication.oidc",
            self.listener.tls_termination == TlsTermination::DevelopmentLoopback,
        ) {
            findings.push(error.into());
        }
        if let Err(error) = oidc.clients.check("authentication.oidc") {
            findings.push(error.into());
        }
        if oidc.scope_claim.is_empty() {
            findings.push(RuntimeConfigError::EmptyScopeClaim);
        }
        // Every access profile resolves its caller from the matched client,
        // so an empty list would admit every client the issuer verifies
        // while reaching no profile. Development keeps no exception.
        if oidc.clients.allowed_clients.is_empty()
            || oidc.clients.allowed_clients.iter().any(String::is_empty)
        {
            findings.push(RuntimeConfigError::AllowedClientsRequired);
        }
        // The shared client list keeps what it reads, so the set rule
        // (CFG-ID-6) is checked here, at the repetition.
        let mut seen = BTreeMap::new();
        for (index, client) in oidc.clients.allowed_clients.iter().enumerate() {
            let at = |index: usize| {
                pointer_to(&[
                    "authentication",
                    "oidc",
                    "allowedClients",
                    &index.to_string(),
                ])
            };
            if let Some(first) = seen.insert(client.as_str(), index) {
                findings.push(RuntimeConfigError::DuplicateAllowedClient {
                    pointer: at(index),
                    first: at(first),
                });
            }
        }
        for (client, issuers) in &oidc.clients.assertion_issuers {
            let pointer = pointer_to(&["authentication", "oidc", "assertionIssuers", client]);
            if issuers.is_empty() {
                findings.push(RuntimeConfigError::EmptyAssertionIssuers {
                    pointer: pointer.clone(),
                });
            }
            if !oidc.clients.allowed_clients.contains(client) {
                findings.push(RuntimeConfigError::AssertionIssuerClientNotAllowed { pointer });
            }
        }
    }

    fn check_database(&self, findings: &mut Vec<RuntimeConfigError>) {
        if self.database.runtime_url_ref.is_empty() || self.database.migration_url_ref.is_empty() {
            findings.push(RuntimeConfigError::InvalidDatabaseReference);
        }
        #[cfg(not(feature = "postgres-test"))]
        if self.database.test_only_plaintext {
            findings.push(RuntimeConfigError::PlaintextDatabase);
        }
    }

    /// Each period is bounded when it is read; together the record outlives
    /// the payload and no receipt outlives its record.
    fn check_retention(&self, findings: &mut Vec<RuntimeConfigError>) {
        let retention = self.retention;
        if retention.record_retention_days < retention.payload_retention_days {
            findings.push(RuntimeConfigError::RecordRetentionShorterThanPayload);
        }
        if retention.submission_receipt_retention_days > retention.record_retention_days {
            findings.push(RuntimeConfigError::ReceiptRetentionLongerThanRecord);
        }
    }

    /// Hold every trust profile and provider connection to the checks that
    /// need no package and no secret.
    fn check_provider_settings(&self, findings: &mut Vec<RuntimeConfigError>) {
        if self.tls_trust_profiles.len() > MAXIMUM_TLS_TRUST_PROFILES {
            findings.push(RuntimeConfigError::TooManyTlsTrustProfiles);
        }
        let development_listener =
            self.listener.tls_termination == TlsTermination::DevelopmentLoopback;
        for (id, connection) in &self.providers {
            match connection {
                ProviderConnection::Smtp { settings } => {
                    if let Err(error) = settings.check(development_listener) {
                        findings.push(RuntimeConfigError::Connection {
                            pointer: provider_pointer(id, error.member()),
                            reason: error.to_string(),
                        });
                    }
                }
                ProviderConnection::Http { settings } => {
                    if settings
                        .tls_trust_profile
                        .as_ref()
                        .is_some_and(|name| !self.tls_trust_profiles.contains_key(name))
                    {
                        findings.push(RuntimeConfigError::UndeclaredTrustProfile {
                            provider: id.clone(),
                        });
                    }
                }
            }
        }
    }

    fn check_profile_clients(
        &self,
        loaded: &LoadedPackage,
        findings: &mut Vec<RuntimeConfigError>,
    ) {
        let allowed: BTreeSet<&str> = self
            .authentication
            .oidc
            .clients
            .allowed_clients
            .iter()
            .map(String::as_str)
            .collect();
        for profile in loaded.package.access_profiles().iter() {
            if profile
                .requester_clients
                .iter()
                .any(|client| !allowed.contains(client.as_str()))
            {
                findings.push(RuntimeConfigError::ProfileClientNotAllowed {
                    profile: profile.id.clone(),
                });
            }
        }
    }

    /// Each connection must be for a provider the package declares, of the
    /// declared type, and an `http` connection must satisfy the package half
    /// it completes.
    fn check_providers(&self, loaded: &LoadedPackage, findings: &mut Vec<RuntimeConfigError>) {
        for (id, connection) in &self.providers {
            let Some(declared) = loaded.package.provider(id) else {
                findings.push(RuntimeConfigError::UndeclaredProvider {
                    provider: id.clone(),
                });
                continue;
            };
            if declared.kind != connection.kind() {
                findings.push(RuntimeConfigError::ProviderTypeMismatch {
                    provider: id.clone(),
                    declared: provider_kind_name(declared.kind),
                });
                continue;
            }
            let ProviderConnection::Http { settings } = connection else {
                continue;
            };
            let Some(source) = loaded.providers.get(id) else {
                findings.push(RuntimeConfigError::MissingProviderSource {
                    provider: id.clone(),
                });
                continue;
            };
            // The trust bundle itself is a secret, resolved at activation;
            // here only whether one is named matters.
            let trust = settings
                .tls_trust_profile
                .as_ref()
                .filter(|name| self.tls_trust_profiles.contains_key(*name))
                .map(|_| &[][..]);
            if settings.tls_trust_profile.is_some() && trust.is_none() {
                // check_provider_settings reports the undeclared profile.
                continue;
            }
            if let Err(error) = settings.check_connection(&source.package, trust) {
                let member = match &error {
                    HttpProviderError::Invalid { field, .. } => field,
                    HttpProviderError::Secret(_) | HttpProviderError::Script { .. } => "",
                };
                findings.push(RuntimeConfigError::Connection {
                    pointer: provider_pointer(id, member),
                    reason: error.to_string(),
                });
            }
        }
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

/// A database identity is non-empty text of at most 256 bytes, without
/// surrounding whitespace or control characters.
fn valid_database_id(database_id: &str) -> bool {
    !database_id.trim().is_empty()
        && database_id.trim() == database_id
        && database_id.len() <= 256
        && !database_id.chars().any(char::is_control)
}

fn first(findings: Vec<RuntimeConfigError>) -> Result<(), RuntimeConfigError> {
    findings.into_iter().next().map_or(Ok(()), Err)
}

/// The JSON Pointer of the member these key segments name.
fn pointer_to(segments: &[&str]) -> String {
    segments
        .iter()
        .map(|segment| format!("/{}", escape_pointer_segment(segment)))
        .collect()
}

/// The JSON Pointer of `member`, a dotted path inside the connection of
/// provider `id`, or of the connection itself when `member` is empty.
fn provider_pointer(id: &str, member: &str) -> String {
    let mut segments = vec!["providers", id];
    segments.extend(member.split('.').filter(|segment| !segment.is_empty()));
    pointer_to(&segments)
}

/// A package refusal as a sentence: a digest pin that does not match names
/// the pin's own member, any other refusal names the package entry.
fn package_sentence(error: &PackageLoadError) -> String {
    if matches!(error.reason(), PackageLoadReason::DigestMismatch { .. }) {
        error.to_string()
    } else {
        format!("the Messaging package at {error}")
    }
}

/// The dotted spelling of a JSON Pointer, as refusals name members.
fn dotted(pointer: &str) -> String {
    pointer
        .split('/')
        .skip(1)
        .map(|segment| segment.replace("~1", "/").replace("~0", "~"))
        .collect::<Vec<_>>()
        .join(".")
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

/// The package an offline check holds a runtime document's package rules
/// against.
#[derive(Clone, Copy, Debug)]
pub enum CheckedAgainst<'a> {
    /// The package `package.root` names, read and verified, its pinned
    /// digest included, as `messaging serve` reads it.
    NamedPackage,
    /// This package, or authoring project, in place of the one
    /// `package.root` names. `package.expectedDigest` is not compared with
    /// it, since a pin names a built package.
    Package(&'a LoadedPackage),
    /// No package: only the rules the document satisfies on its own.
    Nothing,
}

/// What an offline check of one runtime document found (CFG-CHECK-1).
#[derive(Debug)]
pub struct RuntimeCheck {
    /// Every finding, each naming the file as the path was given and each
    /// positioned at the member it concerns: the runtime document's, in file
    /// order, then those the package's authored files hold.
    pub diagnostics: Vec<Diagnostic>,
    /// The file, or the package it names, could not be read at all, as
    /// opposed to read and refused.
    pub unavailable: bool,
    /// The package `package.root` names, when the check read it.
    pub package: Option<LoadedPackage>,
    /// The runtime document and every package file the check read.
    pub files_checked: usize,
    check: RuntimeFileCheck<RuntimeConfig>,
}

impl RuntimeCheck {
    /// The decoded document, when the shared reader accepted it. A member
    /// the check left as an expression holds a stand-in.
    #[must_use]
    pub fn config(&self) -> Option<&RuntimeConfig> {
        self.check.loaded.as_ref().map(|loaded| &loaded.config)
    }

    /// Whether a member at, above, or below `pointer` holds an expression
    /// the check did not substitute, so its decoded value is a stand-in.
    #[must_use]
    pub fn defers_within(&self, pointer: &str) -> bool {
        self.check.defers_within(pointer)
    }
}

/// Check the runtime document at the absolute `path` as `messaging serve`
/// reads it, with no database, network, or secret material, and report
/// every rule it breaks. The rules about the package it serves run against
/// the package `against` selects.
///
/// With `substitute` set, `${NAME}` expressions are filled from the process
/// environment and every value is checked. Without it, each expression is
/// checked by syntax and position only, and a rule that reads its value is
/// left out.
#[must_use]
pub fn check_runtime_file(
    path: &Path,
    against: CheckedAgainst<'_>,
    substitute: bool,
) -> RuntimeCheck {
    let check =
        RuntimeConfig::loader().check_offline::<RuntimeConfig>(path, substitute, stand_in_for);
    let mut diagnostics = check.diagnostics.clone();
    let mut unavailable = check.unavailable;
    let mut named = None;
    let mut refused_package = Report::default();
    if let Some(loaded) = &check.loaded {
        let config = &loaded.config;
        let mut findings = Vec::new();
        let package = match against {
            CheckedAgainst::Package(package) => Some(package),
            CheckedAgainst::Nothing => None,
            CheckedAgainst::NamedPackage if check.defers_within("/package") => None,
            CheckedAgainst::NamedPackage => match load_runtime_package(&config.package) {
                Ok(package) => Some(&*named.insert(package)),
                Err(error) => {
                    unavailable |= error.is_read_failure();
                    if let Some(report) = error.report() {
                        refused_package = report.clone();
                    } else {
                        findings.push(RuntimeConfigError::Package(error));
                    }
                    None
                }
            },
        };
        findings.extend(config.findings(package));
        diagnostics.extend(
            findings
                .iter()
                .filter(|finding| !reads_deferred_value(&check, finding))
                .map(|finding| positioned(&check, finding)),
        );
    }
    in_file_order(&mut diagnostics);
    let mut files_checked = 1 + refused_package.files_checked().unwrap_or(0);
    diagnostics.extend(refused_package.into_diagnostics());
    let given = match against {
        CheckedAgainst::Package(package) => Some(package),
        CheckedAgainst::NamedPackage | CheckedAgainst::Nothing => None,
    };
    if let Some(package) = named.as_ref().or(given) {
        diagnostics.extend_from_slice(package.warnings().diagnostics());
        files_checked += package.warnings().files_checked().unwrap_or(0);
    }
    RuntimeCheck {
        diagnostics,
        unavailable,
        package: named,
        files_checked,
        check,
    }
}

/// The report `messaging serve` prints when it refuses the runtime document
/// at `path` with `error`: the shared loader's diagnostics, every
/// diagnostic the package's authored files hold, or every rule the document
/// breaks, each at its position. `None` for a refusal of a dependency, or of
/// a package that could not be read, which its message alone describes.
#[must_use]
pub fn startup_report(path: &Path, error: &RuntimeConfigError) -> Option<Report> {
    match error {
        RuntimeConfigError::Load(error) => {
            return Some(Report::new(error.diagnostics().to_vec()));
        }
        RuntimeConfigError::Package(error) => return error.report().cloned(),
        _ => {}
    }
    if !error.in_file() {
        return None;
    }
    let check = RuntimeConfig::loader().check_offline::<RuntimeConfig>(path, true, stand_in_for);
    let config = &check.loaded.as_ref()?.config;
    let package = load_runtime_package(&config.package).ok();
    let mut diagnostics: Vec<Diagnostic> = config
        .findings(package.as_ref())
        .iter()
        .map(|finding| positioned(&check, finding))
        .collect();
    in_file_order(&mut diagnostics);
    (!diagnostics.is_empty()).then(|| Report::new(diagnostics))
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
fn positioned(check: &RuntimeFileCheck<RuntimeConfig>, finding: &RuntimeConfigError) -> Diagnostic {
    let pointer = finding.pointer();
    let mut diagnostic = check.error_at(
        MESSAGING_RUNTIME_KIND,
        finding.code(),
        &pointer,
        finding.to_string(),
        finding.suggested_action(),
    );
    if let RuntimeConfigError::DuplicateAllowedClient { first, .. } = finding {
        let source = check
            .error_at(MESSAGING_RUNTIME_KIND, "", first, "", "")
            .source;
        if let Some(source) = source {
            diagnostic.related.push(Related {
                file: source.file,
                line: source.line,
                column: source.column,
                path: first.clone(),
                message: "the first listing of this client".to_owned(),
            });
        }
    }
    let mut located = pointer.as_str();
    while diagnostic
        .source
        .as_ref()
        .is_some_and(|source| source.line.is_none())
        && !located.is_empty()
    {
        located = &located[..located.rfind('/').unwrap_or(0)];
        diagnostic.source = check
            .error_at(MESSAGING_RUNTIME_KIND, "", located, "", "")
            .source;
    }
    diagnostic
}

/// Whether `finding` reads the value of a member the check left as an
/// expression, so the stand-in, not the operator's value, decided it.
fn reads_deferred_value(
    check: &RuntimeFileCheck<RuntimeConfig>,
    finding: &RuntimeConfigError,
) -> bool {
    let pointer = finding.pointer();
    let reads: Vec<String> = match finding {
        RuntimeConfigError::InvalidListener => vec!["/listener".to_owned()],
        RuntimeConfigError::InvalidMetricsListener => vec!["/listener/bind".to_owned()],
        RuntimeConfigError::Block(error) if error.field().starts_with("authentication.oidc.") => {
            vec!["/listener/tlsTermination".to_owned()]
        }
        RuntimeConfigError::RelativeOperatedPath(_)
        | RuntimeConfigError::InvalidAuditDestination(_) => vec!["/audit".to_owned()],
        RuntimeConfigError::AssertionIssuerClientNotAllowed { .. }
        | RuntimeConfigError::DuplicateAllowedClient { .. }
        | RuntimeConfigError::ProfileClientNotAllowed { .. } => {
            vec!["/authentication/oidc/allowedClients".to_owned()]
        }
        // A connection rule reads several members of its provider, and the
        // listener's termination decides whether development transport is
        // accepted.
        RuntimeConfigError::Connection { .. }
        | RuntimeConfigError::UndeclaredTrustProfile { .. } => {
            let root: String = pointer.split('/').take(3).collect::<Vec<_>>().join("/");
            vec![root, "/listener/tlsTermination".to_owned()]
        }
        _ => Vec::new(),
    };
    check.defers_within(&pointer) || reads.iter().any(|pointer| check.defers_within(pointer))
}

/// A value for an expression the offline check does not substitute, chosen
/// so the member it fills decodes and passes the rules about its value.
fn stand_in_for(pointer: &str) -> &'static str {
    let segments: Vec<&str> = pointer.split('/').skip(1).collect();
    match segments.as_slice() {
        ["listener", "bind"] => DEFAULT_LISTENER_BIND,
        ["listener", "tlsTermination"] => "development-loopback",
        ["listener", "networkExposure"] => "private-address",
        ["metricsListener", "bind"] => "127.0.0.1:9107",
        ["audit", "destination"] => "file",
        ["package", "root"] | ["audit", "path"] | ["secretProviders", "file", "root"] => {
            "/deferred"
        }
        ["package", "expectedDigest"] => {
            "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        }
        ["authentication", "oidc", "issuer"]
        | ["authentication", "oidc", "jwksSource", "uri"]
        | ["providers", _, "authentication", "tokenEndpoint"] => "https://deferred.invalid",
        ["providers", _, "baseUrl"] => "https://deferred.invalid/",
        ["providers", _, "callbackVerifier", "url"] => "https://deferred.invalid/deferred",
        ["providers", _, "tls"] => "starttls",
        _ => DEFAULT_STAND_IN,
    }
}

/// Why the runtime document, or the package it names, was refused. Every
/// message names the member and never a configured value.
#[derive(Debug, Error)]
pub enum RuntimeConfigError {
    #[error("identity.databaseId is required; add identity.databaseId with the logical id of the database this deployment owns")]
    MissingIdentity,
    #[error("identity.databaseId must be non-empty, at most 256 bytes, without surrounding whitespace or control characters")]
    InvalidIdentity,
    #[error(transparent)]
    Load(#[from] registry_platform_config::RuntimeConfigError),
    #[error(transparent)]
    Block(#[from] ConfigBlockError),
    #[error("{error}")]
    BindingSecret {
        pointer: String,
        #[source]
        error: ConfigBlockError,
    },
    #[error("{}", audit_message(.0))]
    InvalidAuditDestination(AuditDestinationError),
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
    #[error("authentication.oidc.scopeClaim must not be empty")]
    EmptyScopeClaim,
    #[error(
        "authentication.oidc.allowedClients must list at least one non-empty client identifier"
    )]
    AllowedClientsRequired,
    #[error("{} repeats a client listed earlier in authentication.oidc.allowedClients", dotted(.pointer))]
    DuplicateAllowedClient { pointer: String, first: String },
    #[error("{} must list at least one issuer", dotted(.pointer))]
    EmptyAssertionIssuers { pointer: String },
    #[error("{} names a client authentication.oidc.allowedClients does not admit", dotted(.pointer))]
    AssertionIssuerClientNotAllowed { pointer: String },
    #[error(
        "database.runtimeUrlRef and database.migrationUrlRef must be non-empty secret references"
    )]
    InvalidDatabaseReference,
    #[error("plaintext PostgreSQL is test-only")]
    PlaintextDatabase,
    #[error("retention.recordRetentionDays must be at least retention.payloadRetentionDays")]
    RecordRetentionShorterThanPayload,
    #[error(
        "retention.submissionReceiptRetentionDays must be at most \
         retention.recordRetentionDays"
    )]
    ReceiptRetentionLongerThanRecord,
    #[error("tlsTrustProfiles declares more than {MAXIMUM_TLS_TRUST_PROFILES} profiles")]
    TooManyTlsTrustProfiles,
    #[error(
        "providers.{provider}.tlsTrustProfile names a profile tlsTrustProfiles does not declare"
    )]
    UndeclaredTrustProfile { provider: String },
    #[error("{} is refused: {reason}", dotted(.pointer))]
    Connection { pointer: String, reason: String },
    #[error("{}", package_sentence(.0))]
    Package(#[source] PackageLoadError),
    #[error(
        "access profile {profile} names a requester client \
         authentication.oidc.allowedClients does not admit"
    )]
    ProfileClientNotAllowed { profile: String },
    #[error("providers.{provider} names a provider the package does not declare")]
    UndeclaredProvider { provider: String },
    #[error("providers.{provider} has a type other than the package declares, {declared}")]
    ProviderTypeMismatch {
        provider: String,
        declared: &'static str,
    },
    #[error(
        "providers.{provider} completes an http provider the package ships no provider.yaml for"
    )]
    MissingProviderSource { provider: String },
    #[error("the OIDC issuer could not be initialized")]
    Oidc,
    #[error("the static OIDC signing keys could not be loaded: {0}")]
    OidcJwksSecret(String),
}

/// The package refusal that a pinned digest decides.
const PACKAGE_EXPECTED_DIGEST: &str = "package.expectedDigest";

/// The fix for a refused package.
const REBUILD_PACKAGE: &str =
    "Correct the project as `messagingctl check --project` reports, then rebuild the package with `messagingctl package` and point package.root at it.";

impl RuntimeConfigError {
    /// The JSON Pointer, in the runtime document, of the member this refusal
    /// concerns. A member that is absent is located by the mapping that
    /// lacks it when the refusal is positioned.
    #[must_use]
    pub fn pointer(&self) -> String {
        match self {
            Self::Load(error) => error.deciding_diagnostic().path.clone(),
            Self::BindingSecret { pointer, .. }
            | Self::EmptyAssertionIssuers { pointer }
            | Self::AssertionIssuerClientNotAllowed { pointer }
            | Self::DuplicateAllowedClient { pointer, .. }
            | Self::Connection { pointer, .. } => pointer.clone(),
            Self::Block(error) => pointer_to(&error.field().split('.').collect::<Vec<_>>()),
            Self::MissingIdentity => "/identity".to_owned(),
            Self::InvalidIdentity => "/identity/databaseId".to_owned(),
            Self::InvalidAuditDestination(error) => {
                pointer_to(&audit_field(error).split('.').collect::<Vec<_>>())
            }
            Self::RelativeOperatedPath(path) => pointer_to(&path.split('.').collect::<Vec<_>>()),
            Self::InvalidSecretProviders => "/secretProviders".to_owned(),
            Self::InvalidListener => "/listener".to_owned(),
            Self::InvalidMetricsListener => "/metricsListener/bind".to_owned(),
            Self::EmptyScopeClaim => "/authentication/oidc/scopeClaim".to_owned(),
            Self::AllowedClientsRequired | Self::ProfileClientNotAllowed { .. } => {
                "/authentication/oidc/allowedClients".to_owned()
            }
            Self::InvalidDatabaseReference => "/database".to_owned(),
            Self::PlaintextDatabase => "/database/testOnlyPlaintext".to_owned(),
            Self::RecordRetentionShorterThanPayload => "/retention/recordRetentionDays".to_owned(),
            Self::ReceiptRetentionLongerThanRecord => {
                "/retention/submissionReceiptRetentionDays".to_owned()
            }
            Self::TooManyTlsTrustProfiles => "/tlsTrustProfiles".to_owned(),
            Self::UndeclaredTrustProfile { provider } => {
                provider_pointer(provider, "tlsTrustProfile")
            }
            Self::UndeclaredProvider { provider } | Self::MissingProviderSource { provider } => {
                provider_pointer(provider, "")
            }
            Self::ProviderTypeMismatch { provider, .. } => provider_pointer(provider, "type"),
            Self::Package(error) if error.path() == PACKAGE_EXPECTED_DIGEST => {
                "/package/expectedDigest".to_owned()
            }
            Self::Package(_) => "/package/root".to_owned(),
            Self::Oidc => "/authentication/oidc".to_owned(),
            Self::OidcJwksSecret(_) => "/authentication/oidc/jwksSource/documentRef".to_owned(),
        }
    }

    /// The diagnostic code of this refusal.
    #[must_use]
    pub fn code(&self) -> &str {
        match self {
            Self::Load(error) => &error.deciding_diagnostic().code,
            Self::Block(error) | Self::BindingSecret { error, .. } => block_finding(error).0,
            Self::MissingIdentity => "messaging.runtime.missing-identity",
            Self::InvalidIdentity => "messaging.runtime.invalid-database-id",
            Self::InvalidAuditDestination(_) => "messaging.runtime.invalid-audit",
            Self::RelativeOperatedPath(_) => "messaging.runtime.relative-path",
            Self::InvalidSecretProviders => "messaging.runtime.unusable-secret-providers",
            Self::InvalidListener => "messaging.runtime.invalid-listener",
            Self::InvalidMetricsListener => "messaging.runtime.invalid-metrics-listener",
            Self::EmptyScopeClaim => "messaging.runtime.empty-scope-claim",
            Self::AllowedClientsRequired => "messaging.runtime.allowed-clients-required",
            Self::DuplicateAllowedClient { .. } => "config.duplicate-item",
            Self::EmptyAssertionIssuers { .. } => "messaging.runtime.empty-assertion-issuers",
            Self::AssertionIssuerClientNotAllowed { .. } => {
                "messaging.runtime.assertion-issuer-client-not-allowed"
            }
            Self::InvalidDatabaseReference => "messaging.runtime.invalid-database-reference",
            Self::PlaintextDatabase => "messaging.runtime.plaintext-database",
            Self::RecordRetentionShorterThanPayload => {
                "messaging.runtime.record-retention-shorter-than-payload"
            }
            Self::ReceiptRetentionLongerThanRecord => {
                "messaging.runtime.receipt-retention-longer-than-record"
            }
            Self::TooManyTlsTrustProfiles => "messaging.runtime.too-many-tls-trust-profiles",
            Self::UndeclaredTrustProfile { .. } => "messaging.runtime.undeclared-tls-trust-profile",
            Self::Connection { .. } => "messaging.runtime.invalid-provider-connection",
            Self::Package(error) if error.path() == PACKAGE_EXPECTED_DIGEST => {
                "messaging.package.digest-mismatch"
            }
            Self::Package(_) => "messaging.package.invalid",
            Self::ProfileClientNotAllowed { .. } => "messaging.runtime.profile-client-not-allowed",
            Self::UndeclaredProvider { .. } => "messaging.runtime.undeclared-provider",
            Self::ProviderTypeMismatch { .. } => "messaging.runtime.provider-type-mismatch",
            Self::MissingProviderSource { .. } => "messaging.package.missing-provider-source",
            Self::Oidc => "messaging.runtime-dependency.unavailable",
            Self::OidcJwksSecret(_) => "messaging.runtime.unreadable-jwks-secret",
        }
    }

    /// What the operator does to clear this refusal.
    #[must_use]
    pub fn suggested_action(&self) -> String {
        let action = match self {
            Self::Load(error) => return error.deciding_diagnostic().suggested_action.clone(),
            Self::Block(error) | Self::BindingSecret { error, .. } => block_finding(error).1,
            Self::MissingIdentity => {
                "Add `identity: {databaseId: messaging-production}` with a logical id chosen for this deployment."
            }
            Self::InvalidIdentity => {
                "Write identity.databaseId as at most 256 bytes without surrounding whitespace or control characters."
            }
            Self::InvalidAuditDestination(error) => audit_action(error),
            Self::RelativeOperatedPath(path) => {
                return format!("Write {path} as an absolute path.");
            }
            Self::InvalidSecretProviders => {
                "Make the directory secretProviders.file.root names readable, or enable only secretProviders.environment."
            }
            Self::InvalidListener => {
                "Bind to a loopback address under development-loopback; under operator-controlled-upstream bind to a loopback or private address, or to the unspecified address only with networkExposure: container-private."
            }
            Self::InvalidMetricsListener => {
                "Bind metricsListener to a loopback or private address with a nonzero port the API listener does not use."
            }
            Self::EmptyScopeClaim => {
                "Name the claim that carries the caller's scopes, or remove the member to use registry_scopes."
            }
            Self::AllowedClientsRequired => {
                "List every client identifier this deployment admits in authentication.oidc.allowedClients."
            }
            Self::DuplicateAllowedClient { .. } => {
                "List each client once in authentication.oidc.allowedClients."
            }
            Self::EmptyAssertionIssuers { .. } => {
                "List the issuers this client may exchange a subject token from, or remove the client from assertionIssuers."
            }
            Self::AssertionIssuerClientNotAllowed { .. } => {
                "Add the client to authentication.oidc.allowedClients, or remove it from assertionIssuers."
            }
            Self::InvalidDatabaseReference => {
                "Write database.runtimeUrlRef and database.migrationUrlRef as secret references."
            }
            Self::PlaintextDatabase => {
                "Remove database.testOnlyPlaintext; a deployment reaches PostgreSQL over TLS."
            }
            Self::RecordRetentionShorterThanPayload => {
                "Raise retention.recordRetentionDays to at least retention.payloadRetentionDays."
            }
            Self::ReceiptRetentionLongerThanRecord => {
                "Lower retention.submissionReceiptRetentionDays to at most retention.recordRetentionDays."
            }
            Self::TooManyTlsTrustProfiles => {
                "Declare at most 64 profiles under tlsTrustProfiles, removing those no provider names."
            }
            Self::UndeclaredTrustProfile { .. } => {
                "Declare the profile under tlsTrustProfiles, or name one that is declared."
            }
            Self::Connection { .. } => {
                "Correct the provider connection member so it meets the rule the message names."
            }
            Self::Package(error) if error.path() == PACKAGE_EXPECTED_DIGEST => {
                "Set package.expectedDigest to the digest `messagingctl package` reported for the package at package.root, or remove it."
            }
            Self::Package(_) => REBUILD_PACKAGE,
            Self::ProfileClientNotAllowed { .. } => {
                "Add every requester client the package's access profiles name to authentication.oidc.allowedClients."
            }
            Self::UndeclaredProvider { .. } => {
                "Remove the connection, or declare the provider in the package and rebuild it with `messagingctl package`."
            }
            Self::ProviderTypeMismatch { .. } => {
                "Write the connection's type as the package declares it."
            }
            Self::MissingProviderSource { .. } => REBUILD_PACKAGE,
            Self::Oidc => {
                "Restore access to the configured OIDC issuer or mounted JWKS, then retry."
            }
            Self::OidcJwksSecret(_) => {
                "Make the secret authentication.oidc.jwksSource.documentRef names readable and hold a JWKS document."
            }
        };
        action.to_owned()
    }

    /// Whether this refusal is a rule the runtime document itself breaks,
    /// which an offline check reports at its position in the file. A
    /// refusal of the package, of an unreachable dependency, or one the
    /// shared loader already positioned is not.
    #[must_use]
    pub fn in_file(&self) -> bool {
        !matches!(
            self,
            Self::Load(_)
                | Self::Package(_)
                | Self::MissingProviderSource { .. }
                | Self::InvalidSecretProviders
                | Self::Oidc
                | Self::OidcJwksSecret(_)
        )
    }
}

/// The member an audit destination refusal concerns, spelled with dots.
fn audit_field(error: &AuditDestinationError) -> &'static str {
    match error {
        AuditDestinationError::FileOnlyField {
            field: "rotateBytes",
        }
        | AuditDestinationError::RotateBytesOutOfRange { .. } => "audit.rotateBytes",
        AuditDestinationError::FileOnlyField {
            field: "retainDays",
        }
        | AuditDestinationError::RetainDaysOutOfRange { .. } => "audit.retentionDays",
        AuditDestinationError::InvalidProcessRole
        | AuditDestinationError::ProcessRoleOverlapsStream => "audit",
        _ => "audit.path",
    }
}

/// An audit destination refusal in the runtime document's own spelling, never
/// naming a configured value.
fn audit_message(error: &AuditDestinationError) -> String {
    match error {
        AuditDestinationError::FileOnlyField { .. } => format!(
            "{} applies only when audit.destination is file",
            audit_field(error)
        ),
        AuditDestinationError::RetainDaysOutOfRange { maximum } => {
            format!("audit.retentionDays must be between 1 and {maximum}")
        }
        AuditDestinationError::PathNamesReservedCompanion {
            suffix, companion, ..
        } => format!(
            "audit.path names the {companion} of another audit stream: a file name ending in \
             `{suffix}` is reserved for it"
        ),
        error => error.to_string(),
    }
}

fn audit_action(error: &AuditDestinationError) -> &'static str {
    match error {
        AuditDestinationError::MissingPath => {
            "Add audit.path, the absolute path of the active audit file, or set audit.destination: stdout."
        }
        AuditDestinationError::RelativePath | AuditDestinationError::InvalidPathComponent => {
            "Write audit.path as an absolute path without `.` or `..` segments."
        }
        AuditDestinationError::NoFileName
        | AuditDestinationError::FileNameTooLong { .. }
        | AuditDestinationError::PathNamesReservedCompanion { .. } => {
            "End audit.path in a file name within the bound, without a suffix the audit writer reserves."
        }
        AuditDestinationError::FileOnlyField { .. } => {
            "Remove the member, or set audit.destination: file."
        }
        AuditDestinationError::RotateBytesOutOfRange { .. }
        | AuditDestinationError::RetainDaysOutOfRange { .. } => {
            "Write a value within the range the message names, or remove the member to use its default."
        }
        _ => "Correct the audit block as the message describes.",
    }
}

/// The code and fix of a shared block refusal.
fn block_finding(error: &ConfigBlockError) -> (&'static str, &'static str) {
    match error.kind() {
        ConfigBlockErrorKind::RelativePath => (
            "messaging.runtime.relative-path",
            "Write the path as an absolute path without `.` or `..` segments.",
        ),
        ConfigBlockErrorKind::NoSecretProvider => (
            "messaging.runtime.no-secret-provider",
            "Enable secretProviders.file, secretProviders.environment, or both.",
        ),
        ConfigBlockErrorKind::InvalidSecretReference => (
            "messaging.runtime.invalid-secret-reference",
            "Write the reference as secret:env/NAME or secret:file/name.",
        ),
        ConfigBlockErrorKind::SecretProviderDisabled => (
            "messaging.runtime.secret-provider-disabled",
            "Enable the provider the reference names under secretProviders, or reference an enabled one.",
        ),
        ConfigBlockErrorKind::Empty => ("messaging.runtime.empty-value", "Give the member a value."),
        ConfigBlockErrorKind::InvalidDigest => (
            "messaging.runtime.invalid-digest",
            "Write the sha256: digest `messagingctl package` reported, or remove the member.",
        ),
        ConfigBlockErrorKind::InvalidUri => (
            "messaging.runtime.invalid-uri",
            "Write an absolute https URL without credentials, query, or fragment.",
        ),
        ConfigBlockErrorKind::InvalidAudience => (
            "messaging.runtime.invalid-audience",
            "Write the audience as non-empty text without control characters, within the bound the message names.",
        ),
        ConfigBlockErrorKind::InvalidAssertionIssuers => (
            "messaging.runtime.invalid-assertion-issuers",
            "Keep assertionIssuers within the bounds the message names, with non-empty clients and issuers and no issuer repeated for one client.",
        ),
    }
}

#[cfg(test)]
pub(crate) mod tests {
    #![allow(
        clippy::disallowed_methods,
        reason = "tests read back the YAML the code under test wrote, or a published contract or fixture, to assert on it; they read no operator configuration"
    )]
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
        assert_eq!(error.pointer(), "/identity");
        assert_eq!(error.code(), "messaging.runtime.missing-identity");
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
            assert_eq!(error.pointer(), "/identity/databaseId");
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
                matches!(error, RuntimeConfigError::Load(_)),
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
        assert!(matches!(error, RuntimeConfigError::Load(_)), "{error}");
        assert_eq!(error.pointer(), "/database/runtimeUrlRef");
        assert!(error.to_string().contains("secret reference"), "{error}");

        let mut value = base();
        value["audit"]["hashKeyRef"] = json!("secret:env/${KEY_NAME:-AUDIT}");
        let error = load(value).unwrap_err();
        assert_eq!(error.pointer(), "/audit/hashKeyRef");

        let mut value = base();
        value["authentication"]["oidc"]["jwksSource"] =
            json!({"kind": "static", "documentRef": "${JWKS}"});
        let error = load(value).unwrap_err();
        assert_eq!(
            error.pointer(),
            "/authentication/oidc/jwksSource/documentRef"
        );
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
        assert_eq!(error.pointer(), "/x-spliced", "{error}");
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
        assert!(matches!(error, RuntimeConfigError::Load(_)), "{error}");
        assert_eq!(error.pointer(), "/listener/bind");
        assert!(error.to_string().contains("MESSAGING_BIND"), "{error}");
    }

    #[test]
    fn removed_jwks_uri_names_jwks_source_replacement() {
        let mut value = base();
        value["authentication"]["oidc"]["jwksUri"] =
            json!("https://identity.example.test/jwks.json");
        let error = load(value).unwrap_err();
        assert_eq!(error.pointer(), "/authentication/oidc/jwksUri");
        assert_eq!(error.code(), "config.removed-key");
        assert!(error.suggested_action().contains("jwksSource"), "{error}");
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
        assert!(matches!(error, RuntimeConfigError::Load(_)), "{error}");

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
            assert_eq!(error.pointer(), "/authentication/oidc/issuer");
        }
    }

    #[test]
    fn the_starter_runtime_example_parses_as_written() {
        let example = crate::package::tests::starter_root().join("runtime.example.yaml");
        let text = std::fs::read_to_string(example).unwrap();
        RuntimeConfig::parse_with_environment(&text, &no_environment).unwrap();
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
                    RuntimeConfigError::Load(_) | RuntimeConfigError::Block(_)
                ),
                "{issuer}: {error}"
            );
        }
    }

    #[test]
    fn retention_bounds_are_enforced() {
        for (retention, pointer) in [
            (
                json!({"payloadRetentionDays": 0}),
                "/retention/payloadRetentionDays",
            ),
            (
                json!({"payloadRetentionDays": 31}),
                "/retention/payloadRetentionDays",
            ),
            (
                json!({"recordRetentionDays": 3651}),
                "/retention/recordRetentionDays",
            ),
            (
                json!({"submissionReceiptRetentionDays": 0}),
                "/retention/submissionReceiptRetentionDays",
            ),
        ] {
            let mut value = base();
            value["retention"] = retention.clone();
            let error = load(value).unwrap_err();
            assert!(
                matches!(error, RuntimeConfigError::Load(_)),
                "{retention}: {error}"
            );
            assert_eq!(error.code(), "config.out-of-range", "{retention}");
            assert_eq!(error.pointer(), pointer, "{retention}");
        }

        let mut value = base();
        value["retention"] = json!({"payloadRetentionDays": 10, "recordRetentionDays": 9});
        let error = load(value).unwrap_err();
        assert!(
            matches!(error, RuntimeConfigError::RecordRetentionShorterThanPayload),
            "{error}"
        );
        assert_eq!(error.pointer(), "/retention/recordRetentionDays");

        let mut value = base();
        value["retention"] = json!({
            "recordRetentionDays": 10,
            "payloadRetentionDays": 5,
            "submissionReceiptRetentionDays": 11
        });
        let error = load(value).unwrap_err();
        assert!(
            matches!(error, RuntimeConfigError::ReceiptRetentionLongerThanRecord),
            "{error}"
        );
        assert_eq!(error.pointer(), "/retention/submissionReceiptRetentionDays");

        let mut value = base();
        value["retention"] = json!({
            "payloadRetentionDays": 30,
            "recordRetentionDays": 30,
            "submissionReceiptRetentionDays": 30
        });
        load(value).unwrap();
    }

    #[test]
    fn a_removed_key_names_the_key_that_replaced_it() {
        for (section, key, value, replacement) in [
            ("retention", "payloadDays", json!(7), "payloadRetentionDays"),
            ("retention", "recordDays", json!(90), "recordRetentionDays"),
            (
                "retention",
                "submissionReceiptDays",
                json!(7),
                "submissionReceiptRetentionDays",
            ),
            ("audit", "retainDays", json!(30), "audit.retentionDays"),
        ] {
            let mut runtime = base();
            if runtime.get(section).is_none() {
                runtime[section] = json!({});
            }
            runtime[section][key] = value;
            let error = load(runtime).unwrap_err();
            assert_eq!(error.code(), "config.removed-key", "{key}: {error}");
            assert_eq!(error.pointer(), format!("/{section}/{key}"));
            assert!(error.suggested_action().contains(replacement), "{error}");
        }

        for (pointer, key, value, replacement) in [
            (
                "/providers/sms-gateway",
                "attemptTimeoutSeconds",
                json!(10),
                "`attemptTimeoutSeconds: 10` becomes `attemptTimeoutMilliseconds: 10000`",
            ),
            (
                "/providers/sms-gateway",
                "timeoutMilliseconds",
                json!(5000),
                "attemptTimeoutMilliseconds",
            ),
            (
                "/providers/sms-gateway",
                "concurrencyLimit",
                json!(4),
                "maximumConcurrentRequests",
            ),
            ("/providers/mail-relay", "kind", json!("smtp"), "type"),
            (
                "/providers/sms-gateway/authentication",
                "kind",
                json!("static-authorization"),
                "type",
            ),
            (
                "/providers/sms-gateway/callbackVerifier",
                "kind",
                json!("hmac-sha256-body"),
                "type",
            ),
        ] {
            let mut runtime = base();
            runtime["providers"] = provider_connections();
            runtime
                .pointer_mut(pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .insert(key.to_owned(), value);
            let error = load(runtime).unwrap_err();
            let removed: Vec<_> = match &error {
                RuntimeConfigError::Load(error) => error
                    .diagnostics()
                    .iter()
                    .filter(|diagnostic| diagnostic.code == "config.removed-key")
                    .collect(),
                other => panic!("{key}: {other}"),
            };
            assert_eq!(removed.len(), 1, "{key}: {error}");
            assert_eq!(removed[0].path, format!("{pointer}/{key}"));
            assert!(
                removed[0].suggested_action.contains(replacement),
                "{key}: {}",
                removed[0].suggested_action
            );
            assert!(removed[0].source.as_ref().unwrap().line.is_some());
        }
    }

    #[test]
    fn a_retired_api_version_names_its_replacement() {
        let mut runtime = base();
        runtime["apiVersion"] = json!(RETIRED_MESSAGING_RUNTIME_API_VERSION);
        let error = load(runtime).unwrap_err();
        assert_eq!(error.code(), "config.retired-api-version", "{error}");
        assert_eq!(error.pointer(), "/apiVersion");
        assert!(
            error
                .suggested_action()
                .contains(MESSAGING_RUNTIME_API_VERSION),
            "{error}"
        );
    }

    /// Two keys no block declares, inside the mapping at `pointer`, are both
    /// reported, each at its own line.
    fn assert_two_unknown_keys_reported(mut runtime: Value, pointer: &str) {
        let mapping = runtime
            .pointer_mut(pointer)
            .unwrap()
            .as_object_mut()
            .unwrap();
        mapping.insert("firstStray".to_owned(), json!("x"));
        mapping.insert("secondStray".to_owned(), json!("y"));
        let error = load(runtime).unwrap_err();
        let RuntimeConfigError::Load(load_error) = &error else {
            panic!("{pointer}: {error}");
        };
        let unknown: Vec<_> = load_error
            .diagnostics()
            .iter()
            .filter(|diagnostic| diagnostic.code == "config.unknown-key")
            .collect();
        assert_eq!(unknown.len(), 2, "{pointer}: {error}");
        let mut paths: Vec<&str> = unknown
            .iter()
            .map(|diagnostic| diagnostic.path.as_str())
            .collect();
        paths.sort_unstable();
        assert_eq!(
            paths,
            [
                format!("{pointer}/firstStray"),
                format!("{pointer}/secondStray")
            ]
        );
        let lines: BTreeSet<usize> = unknown
            .iter()
            .map(|diagnostic| diagnostic.source.as_ref().unwrap().line.unwrap())
            .collect();
        assert_eq!(lines.len(), 2, "{pointer}: {error}");
    }

    #[test]
    fn every_shared_block_reports_each_unknown_key_at_its_position() {
        // The OIDC issuer and client blocks share one mapping.
        assert_two_unknown_keys_reported(base(), "/authentication/oidc");
        assert_two_unknown_keys_reported(base(), "/audit");
        let mut runtime = base();
        runtime["providers"] = provider_connections();
        assert_two_unknown_keys_reported(runtime.clone(), "/providers/mail-relay");
        assert_two_unknown_keys_reported(runtime, "/providers/sms-gateway");
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
        let error = load(value).unwrap_err();
        assert!(
            matches!(error, RuntimeConfigError::AllowedClientsRequired),
            "{error}"
        );
        assert_eq!(error.pointer(), "/authentication/oidc/allowedClients");
        assert!(error.suggested_action().contains("allowedClients"));

        let mut value = base();
        value["authentication"]["oidc"]
            .as_object_mut()
            .unwrap()
            .remove("allowedClients");
        assert!(matches!(
            load(value).unwrap_err(),
            RuntimeConfigError::AllowedClientsRequired
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
    fn a_repeated_allowed_client_is_refused_at_the_repetition() {
        let mut value = base();
        let clients = value["authentication"]["oidc"]["allowedClients"]
            .as_array_mut()
            .unwrap();
        let first = clients[0].clone();
        clients.push(first);
        let last = clients.len() - 1;
        let error = load(value).unwrap_err();
        assert!(
            matches!(error, RuntimeConfigError::DuplicateAllowedClient { .. }),
            "{error}"
        );
        assert_eq!(error.code(), "config.duplicate-item");
        assert_eq!(
            error.pointer(),
            format!("/authentication/oidc/allowedClients/{last}")
        );
        assert!(error.suggested_action().contains("allowedClients"));
    }

    #[test]
    fn assertion_issuers_may_name_only_allowed_clients() {
        let mut value = base();
        value["authentication"]["oidc"]["assertionIssuers"] =
            json!({"unknown-client": ["https://assertions.example.test"]});
        let error = load(value).unwrap_err();
        assert!(
            matches!(
                error,
                RuntimeConfigError::AssertionIssuerClientNotAllowed { .. }
            ),
            "{error}"
        );
        assert_eq!(
            error.pointer(),
            "/authentication/oidc/assertionIssuers/unknown-client"
        );
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
    fn runtime_package_digest_pin_names_the_found_digest() {
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
        assert_eq!(error.pointer(), "/package/expectedDigest");
        assert!(error.to_string().contains(&digest), "{error}");
        assert!(!error.to_string().contains(&pinned), "{error}");

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
    fn an_empty_assertion_issuer_map_is_refused_at_its_pointer() {
        let mut value = base();
        value["authentication"]["oidc"]["assertionIssuers"] = json!({});
        let error = load(value).unwrap_err();
        assert_eq!(error.pointer(), "/authentication/oidc/assertionIssuers");
    }

    #[test]
    fn relative_paths_are_refused() {
        let mut value = base();
        value["audit"]["path"] = json!("audit");
        let error = load(value).unwrap_err();
        assert_eq!(error.pointer(), "/audit/path");
        assert!(matches!(
            RuntimeConfig::load_with_environment("runtime.yaml", &no_environment),
            Err(RuntimeConfigError::Load(_))
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
    fn a_refused_package_value_is_not_repeated_in_the_startup_report() {
        let root = tempfile::tempdir().unwrap();
        let runtime = runtime_value(root.path());
        let canary = "DO_NOT_DISCLOSE_PACKAGE_VALUE";
        let mut package = package_value();
        package["accessProfiles"][0]["id"] = json!(canary);
        package["accessProfiles"][0]["principalClaim"] = json!(canary);
        let path = write_project(root.path(), &runtime, &package);
        let error = RuntimeConfig::load_with_environment(&path, &no_environment).unwrap_err();
        assert!(matches!(error, RuntimeConfigError::Package(_)), "{error}");
        assert!(!error.to_string().contains(canary), "{error}");
        let report = startup_report(&path, &error).expect("a package report");
        assert!(report.error_count() > 0);
        for diagnostic in report.diagnostics() {
            assert!(!diagnostic.message.contains(canary), "{diagnostic:?}");
            assert!(
                !diagnostic.suggested_action.contains(canary),
                "{diagnostic:?}"
            );
        }
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
        assert_eq!(error.pointer(), "/package/root");
        assert!(
            error.to_string().contains(" package.root/messaging.yaml "),
            "{error}"
        );

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
        assert!(!error.to_string().contains("RELAY_URL"), "{error}");
        let RuntimeConfigError::Package(error) = error else {
            panic!("{error}");
        };
        let refusals: Vec<_> = error
            .report()
            .expect("an authored expression is refused with a report")
            .diagnostics()
            .iter()
            .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
            .collect();
        assert_eq!(
            refusals,
            [(
                "config.substitution-not-allowed",
                "/providers/0/endpointRef"
            )]
        );
    }

    /// Runtime connections for both starter providers.
    pub(crate) fn provider_connections() -> Value {
        json!({
            "mail-relay": {
                "type": "smtp",
                "host": "smtp.example.org",
                "tls": "starttls",
                "authentication": {
                    "usernameRef": "secret:file/smtp-username",
                    "passwordRef": "secret:env/SMTP_PASSWORD"
                }
            },
            "sms-gateway": {
                "type": "http",
                "baseUrl": "https://gateway.example.org/v1/",
                "attemptTimeoutMilliseconds": 5000,
                "maximumResponseBytes": 65536,
                "maximumConcurrentRequests": 4,
                "redirects": "deny",
                "authentication": {
                    "type": "static-authorization",
                    "tokenRef": "secret:file/gateway-token"
                },
                "callbackVerifier": {
                    "type": "hmac-sha256-body",
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
            ProviderConnection::Smtp { .. }
        ));
        assert!(matches!(
            config.providers["sms-gateway"],
            ProviderConnection::Http { .. }
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
        assert_eq!(error.pointer(), "/providers/relay-two");
        assert_eq!(error.code(), "messaging.runtime.undeclared-provider");
        assert!(error.to_string().contains("does not declare"), "{error}");

        let mut value = base();
        value["providers"] = json!({"mail-relay": provider_connections()["sms-gateway"].clone()});
        let error = load(value).unwrap_err();
        assert_eq!(error.pointer(), "/providers/mail-relay/type");
        assert_eq!(error.code(), "messaging.runtime.provider-type-mismatch");
        assert!(
            error
                .to_string()
                .contains("type other than the package declares, smtp"),
            "{error}"
        );
    }

    #[test]
    fn a_connection_that_fails_its_checks_names_the_provider_and_the_member() {
        let mut value = base();
        value["providers"] = provider_connections();
        value["providers"]["mail-relay"]["port"] = json!(0);
        let error = load(value).unwrap_err();
        assert_eq!(error.code(), "config.out-of-range", "{error}");
        assert_eq!(error.pointer(), "/providers/mail-relay/port");

        let mut value = base();
        value["providers"] = provider_connections();
        value["providers"]["mail-relay"]["port"] = json!(465);
        let error = load(value).unwrap_err();
        assert_eq!(
            error.code(),
            "messaging.runtime.invalid-provider-connection"
        );
        assert_eq!(error.pointer(), "/providers/mail-relay/port");

        let mut value = base();
        value["providers"] = provider_connections();
        value["providers"]["sms-gateway"]["maximumConcurrentRequests"] = json!(9);
        let error = load(value).unwrap_err();
        assert_eq!(
            error.pointer(),
            "/providers/sms-gateway/maximumConcurrentRequests"
        );
        assert!(
            error.to_string().contains("maximumConcurrentRequests"),
            "{error}"
        );

        let mut value = base();
        value["providers"] = provider_connections();
        value["providers"]["sms-gateway"]
            .as_object_mut()
            .unwrap()
            .remove("callbackVerifier");
        let error = load(value).unwrap_err();
        assert_eq!(error.pointer(), "/providers/sms-gateway/callbackVerifier");
        assert!(error.to_string().contains("callbackVerifier"), "{error}");

        let mut value = base();
        value["providers"] = provider_connections();
        value["providers"]["sms-gateway"]["region"] = json!("eu");
        assert!(matches!(
            load(value).unwrap_err(),
            RuntimeConfigError::Load(_)
        ));
    }

    #[test]
    fn a_provider_secret_reference_must_parse_and_name_an_enabled_secret_provider() {
        let mut value = base();
        value["providers"] = provider_connections();
        value["providers"]["mail-relay"]["authentication"]["passwordRef"] = json!("hunter2");
        let error = load(value).unwrap_err();
        assert!(matches!(error, RuntimeConfigError::Load(_)), "{error}");
        assert_eq!(
            error.pointer(),
            "/providers/mail-relay/authentication/passwordRef"
        );
        assert!(!error.to_string().contains("hunter2"), "{error}");

        let mut value = base();
        value["providers"] = provider_connections();
        value["providers"]["sms-gateway"]["authentication"]["tokenRef"] = json!("hunter2");
        let error = load(value).unwrap_err();
        assert!(matches!(error, RuntimeConfigError::Load(_)), "{error}");
        assert_eq!(
            error.pointer(),
            "/providers/sms-gateway/authentication/tokenRef"
        );
        assert!(!error.to_string().contains("hunter2"), "{error}");

        let mut value = base();
        file_secrets_only(&mut value);
        value["providers"] = provider_connections();
        let error = load(value).unwrap_err();
        assert!(
            matches!(error, RuntimeConfigError::BindingSecret { .. }),
            "{error}"
        );
        assert_eq!(
            error.pointer(),
            "/providers/mail-relay/authentication/passwordRef"
        );
        assert_eq!(error.code(), "messaging.runtime.secret-provider-disabled");

        let mut value = base();
        file_secrets_only(&mut value);
        value["providers"] = json!({"sms-gateway": provider_connections()["sms-gateway"].clone()});
        value["providers"]["sms-gateway"]["callbackVerifier"]["secretRef"] =
            json!("secret:env/CALLBACK_KEY");
        let error = load(value).unwrap_err();
        assert_eq!(
            error.pointer(),
            "/providers/sms-gateway/callbackVerifier/secretRef"
        );
        assert!(!error.to_string().contains("CALLBACK_KEY"), "{error}");
    }

    #[test]
    fn a_trust_profile_must_be_declared_and_its_bundle_a_secret_reference() {
        let mut value = base();
        value["providers"] = provider_connections();
        value["providers"]["sms-gateway"]["tlsTrustProfile"] = json!("gateway-ca");
        let error = load(value).unwrap_err();
        assert!(
            matches!(error, RuntimeConfigError::UndeclaredTrustProfile { .. }),
            "{error}"
        );
        assert_eq!(error.pointer(), "/providers/sms-gateway/tlsTrustProfile");

        let mut value = base();
        value["tlsTrustProfiles"] = json!({"gateway-ca": {"bundleRef": "/etc/ca.pem"}});
        let error = load(value).unwrap_err();
        assert!(matches!(error, RuntimeConfigError::Load(_)), "{error}");
        assert_eq!(error.pointer(), "/tlsTrustProfiles/gateway-ca/bundleRef");

        let mut value = base();
        file_secrets_only(&mut value);
        value["tlsTrustProfiles"] = json!({"gateway-ca": {"bundleRef": "secret:env/CA"}});
        let error = load(value).unwrap_err();
        assert_eq!(error.pointer(), "/tlsTrustProfiles/gateway-ca/bundleRef");
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

    fn codes_and_pointers(diagnostics: &[Diagnostic]) -> Vec<(&str, &str)> {
        diagnostics
            .iter()
            .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
            .collect()
    }

    #[test]
    fn an_offline_check_reports_every_broken_rule_at_its_position() {
        let root = tempfile::tempdir().unwrap();
        let mut runtime = runtime_value(root.path());
        runtime["retention"] = json!({"payloadRetentionDays": 10, "recordRetentionDays": 9});
        runtime["providers"] = provider_connections();
        runtime["providers"]["sms-gateway"]["tlsTrustProfile"] = json!("gateway-ca");
        runtime["authentication"]["oidc"]["allowedClients"] = json!(["case-system"]);
        let path = write_project(root.path(), &runtime, &package_value());

        let check = check_runtime_file(&path, CheckedAgainst::Nothing, true);
        assert!(!check.unavailable);
        assert_eq!(
            codes_and_pointers(&check.diagnostics),
            [
                (
                    "messaging.runtime.undeclared-tls-trust-profile",
                    "/providers/sms-gateway/tlsTrustProfile"
                ),
                (
                    "messaging.runtime.record-retention-shorter-than-payload",
                    "/retention/recordRetentionDays"
                ),
            ]
        );
        for diagnostic in &check.diagnostics {
            let source = diagnostic.source.as_ref().unwrap();
            assert_eq!(source.file, path.display().to_string());
            assert!(source.line.is_some() && source.column.is_some());
            assert!(!diagnostic.suggested_action.is_empty());
        }

        // The rules about the package run when the package is given.
        let text = std::fs::read_to_string(&path).unwrap();
        let config = RuntimeConfig::parse_with_environment(&text, &no_environment).unwrap();
        let package = load_runtime_package(&config.package).unwrap();
        let check = check_runtime_file(&path, CheckedAgainst::Package(&package), true);
        assert!(codes_and_pointers(&check.diagnostics).contains(&(
            "messaging.runtime.profile-client-not-allowed",
            "/authentication/oidc/allowedClients"
        )));

        // The package `package.root` names is the one the check reads by
        // default.
        let check = check_runtime_file(&path, CheckedAgainst::NamedPackage, true);
        assert!(check.package.is_some());
        assert!(codes_and_pointers(&check.diagnostics).contains(&(
            "messaging.runtime.profile-client-not-allowed",
            "/authentication/oidc/allowedClients"
        )));

        // The startup refusal reports the same findings.
        let error = RuntimeConfig::load_with_environment(&path, &no_environment).unwrap_err();
        let report = startup_report(&path, &error).unwrap();
        assert_eq!(report.diagnostics().len(), 3, "{error}");
    }

    #[test]
    fn an_offline_check_without_substitution_leaves_an_expression_to_the_deployment() {
        let root = tempfile::tempdir().unwrap();
        let mut runtime = runtime_value(root.path());
        runtime["listener"]["bind"] = json!("${MESSAGING_CHECK_UNSET_BIND}");
        runtime["authentication"]["oidc"]["issuer"] = json!("${MESSAGING_CHECK_UNSET_ISSUER}");
        let path = write_project(root.path(), &runtime, &package_value());

        let check = check_runtime_file(&path, CheckedAgainst::Nothing, false);
        assert!(check.diagnostics.is_empty(), "{:?}", check.diagnostics);

        let check = check_runtime_file(&path, CheckedAgainst::Nothing, true);
        assert_eq!(
            codes_and_pointers(&check.diagnostics),
            [
                ("config.substitution", "/authentication/oidc/issuer"),
                ("config.substitution", "/listener/bind"),
            ]
        );
    }

    #[test]
    fn an_offline_check_of_an_absent_named_package_reports_it_at_the_root() {
        let root = tempfile::tempdir().unwrap();
        let mut runtime = runtime_value(root.path());
        let absent = root.path().canonicalize().unwrap().join("absent-package");
        runtime["package"]["root"] = json!(absent.display().to_string());
        let path = write_project(root.path(), &runtime, &package_value());

        let check = check_runtime_file(&path, CheckedAgainst::NamedPackage, true);
        assert!(check.unavailable);
        assert!(check.package.is_none());
        assert_eq!(
            codes_and_pointers(&check.diagnostics),
            [("messaging.package.invalid", "/package/root")]
        );
        let source = check.diagnostics[0].source.as_ref().unwrap();
        assert!(source.line.is_some());

        // An expression the check leaves to the deployment is not read.
        runtime["package"]["root"] = json!("${MESSAGING_CHECK_UNSET_ROOT}");
        let path = write_project(root.path(), &runtime, &package_value());
        let check = check_runtime_file(&path, CheckedAgainst::NamedPackage, false);
        assert!(!check.unavailable);
        assert!(check.diagnostics.is_empty(), "{:?}", check.diagnostics);
    }

    #[test]
    fn an_offline_check_of_an_unreadable_file_reports_it_unavailable() {
        let root = tempfile::tempdir().unwrap();
        let absent = root.path().canonicalize().unwrap().join("absent.yaml");
        let check = check_runtime_file(&absent, CheckedAgainst::Nothing, true);
        assert!(check.unavailable);
        assert_eq!(check.diagnostics.len(), 1);
    }

    #[test]
    fn a_startup_refusal_by_the_reader_reports_every_reader_diagnostic() {
        let mut runtime = base();
        runtime["audit"]["firstStray"] = json!(1);
        runtime["listener"]["secondStray"] = json!(2);
        let root = tempfile::tempdir().unwrap();
        rebase(&mut runtime, root.path());
        let path = write_project(root.path(), &runtime, &package_value());
        let error = RuntimeConfig::load_with_environment(&path, &no_environment).unwrap_err();
        let report = startup_report(&path, &error).unwrap();
        assert_eq!(
            codes_and_pointers(report.diagnostics()),
            [
                ("config.unknown-key", "/audit/firstStray"),
                ("config.unknown-key", "/listener/secondStray"),
            ]
        );
    }
}
