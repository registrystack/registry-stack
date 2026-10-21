// SPDX-License-Identifier: Apache-2.0

//! The operator runtime configuration document.
//!
//! The document is read through the shared runtime loader, so its envelope,
//! keys, and value types are refused exactly as every Registry Stack runtime
//! refuses them. The rules below are the ones a document must satisfy on its
//! own; each finding names the member it concerns and never a configured
//! value.

use std::collections::BTreeMap;
use std::path::Path;

use registry_documents_core::{
    DOCUMENTS_RUNTIME_API_VERSION, DOCUMENTS_RUNTIME_KIND, MAXIMUM_DOCUMENT_BYTES,
};
use registry_platform_audit::{AuditDestination, AuditDestinationKind};
pub use registry_platform_config::{
    AuditKeyConfig, DatabaseConfig, OidcClientsConfig, OidcIssuerConfig, PackageConfig,
    PrivateListenerConfig as ListenerConfig, SecretProvidersConfig, TlsTermination,
};
use registry_platform_config::{
    ConfigBlockError, RuntimeConfigLoader, RuntimeEnvelope, RuntimeFileCheck, SecretReference,
    SecretResolver, DEFAULT_STAND_IN, REMOVED_OIDC_JWKS_SOURCE_KIND, REMOVED_OIDC_JWKS_URI,
};
use registry_platform_yaml::{
    BoundedU32, BoundedU64, Diagnostic, ExternalId, LocalId, Report, Url,
};
use serde::Deserialize;
use thiserror::Error;

pub(crate) use registry_platform_config::describe_secret_failure;

/// The default listener binding. Each Registry Stack runtime has its own
/// default port so a laptop can run several side by side.
pub const DEFAULT_LISTENER_BIND: &str = "127.0.0.1:8116";

pub const DOCUMENTS_RUNTIME_ENVELOPE: RuntimeEnvelope = RuntimeEnvelope {
    api_version: DOCUMENTS_RUNTIME_API_VERSION,
    kind: DOCUMENTS_RUNTIME_KIND,
};

/// The keys the runtime document refuses with the sentence naming what
/// replaced them (CFG-CHANGE-2): the shared OIDC key-source spellings.
const DOCUMENTS_REMOVED_KEYS: &[registry_platform_config::RemovedKey] =
    &[REMOVED_OIDC_JWKS_URI, REMOVED_OIDC_JWKS_SOURCE_KIND];

/// The longest a content verifier or hook destination attempt may run.
pub const MAXIMUM_ATTEMPT_TIMEOUT_MILLISECONDS: u32 = 60_000;

/// The most delivery attempts a hook destination may configure.
pub const MAXIMUM_HOOK_ATTEMPTS: u32 = 32;

/// The longest a submission receipt may be retained, in days.
pub const MAXIMUM_RECEIPT_RETENTION_DAYS: u32 = 365;

/// The longest a hook payload may be retained, in days.
pub const MAXIMUM_HOOK_PAYLOAD_RETENTION_DAYS: u32 = 30;

/// The operator runtime configuration document.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeConfig {
    pub api_version: String,
    pub kind: String,
    /// Optional in the type so a missing block gets a refusal naming the key
    /// to add; the document requires it.
    #[serde(default)]
    #[cfg_attr(feature = "schema", schemars(required, with = "IdentityConfig"))]
    pub identity: Option<IdentityConfig>,
    pub package: PackageConfig,
    pub listener: ListenerConfig,
    pub secret_providers: SecretProvidersConfig,
    pub database: DatabaseConfig,
    pub authentication: AuthenticationConfig,
    pub audit: AuditConfig,
    pub storage: StorageConfig,
    pub content_verification: ContentVerificationConfig,
    pub cleanup: CleanupConfig,
    #[serde(default)]
    pub destinations: DestinationsConfig,
    #[serde(default)]
    pub retention: RetentionConfig,
}

/// The logical database identity this deployment owns. It is independent of
/// the connection URL and PostgreSQL database name.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityConfig {
    pub database_id: LocalId,
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
    /// its caller from the matched client, so the list is never empty.
    #[serde(rename(deserialize = "registry-platform-yaml/shared-block/oidc-clients"))]
    #[cfg_attr(feature = "schema", schemars(flatten))]
    pub clients: OidcClientsConfig,
    #[serde(default = "default_scope_claim")]
    pub scope_claim: ExternalId,
}

fn default_scope_claim() -> ExternalId {
    ExternalId::new("scope").expect("`scope` is an external identifier")
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
    pub path: Option<std::path::PathBuf>,
}

/// Where document version bytes are held.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
#[derive(Clone, Debug, Deserialize)]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum StorageConfig {
    /// Document version bytes held in PostgreSQL.
    Database {
        /// The deployment ceiling on one document version; a policy's
        /// mandatory restriction may only be lower.
        maximum_document_bytes: BoundedU64<1, MAXIMUM_DOCUMENT_BYTES>,
    },
}
registry_platform_yaml::tagged_union!(StorageConfig);

/// The content verifier every document version passes before it becomes
/// releasable.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[cfg_attr(feature = "schema", schemars(!remote, tag = "type"))]
#[derive(Clone, Deserialize)]
#[serde(
    remote = "Self",
    rename_all = "kebab-case",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ContentVerificationConfig {
    /// An HTTP verifier the runtime asks about each document version.
    Http {
        url: Url,
        authorization_ref: SecretReference,
        /// Non-secret identity of the verifier and its rules generation.
        policy_id: ExternalId,
        attempt_timeout_milliseconds: BoundedU32<100, MAXIMUM_ATTEMPT_TIMEOUT_MILLISECONDS>,
    },
    /// No verifier, accepted only beside `tlsTermination:
    /// development-loopback`.
    Disabled {},
}
registry_platform_yaml::tagged_union!(ContentVerificationConfig);

impl std::fmt::Debug for ContentVerificationConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Http { .. } => "ContentVerificationConfig::Http(<redacted>)",
            Self::Disabled {} => "ContentVerificationConfig::Disabled",
        })
    }
}

/// Erasure of what expired and revoked document grants released.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CleanupConfig {
    pub erasure: Erasure,
}

/// Whether erasure work runs. `paused` stops it; expired and revoked
/// document grants stop releasing bytes regardless.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum Erasure {
    Active,
    Paused,
}

/// Where the project's hooks deliver, by destination id.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DestinationsConfig {
    #[serde(default)]
    #[cfg_attr(
        feature = "schema",
        schemars(schema_with = "registry_documents_core::local_id_map_schema::<HookDestination>")
    )]
    pub hooks: BTreeMap<LocalId, HookDestination>,
}

/// One URL a hook delivers its projection to, and the key it signs with.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HookDestination {
    pub url: Url,
    pub hmac_sha256_key_ref: SecretReference,
    pub attempt_timeout_milliseconds: BoundedU32<100, MAXIMUM_ATTEMPT_TIMEOUT_MILLISECONDS>,
    pub maximum_attempts: BoundedU32<1, MAXIMUM_HOOK_ATTEMPTS>,
}

impl std::fmt::Debug for HookDestination {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HookDestination")
            .field("url", &"<redacted>")
            .field("hmac_sha256_key_ref", &"<redacted>")
            .field(
                "attempt_timeout_milliseconds",
                &self.attempt_timeout_milliseconds,
            )
            .field("maximum_attempts", &self.maximum_attempts)
            .finish()
    }
}

/// Retention periods, in days. A jurisdiction's retention schedule approves
/// the deployed values; the bounds only keep a typo from becoming a policy.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetentionConfig {
    #[serde(default = "default_receipt_retention_days")]
    pub receipt_retention_days: BoundedU32<1, MAXIMUM_RECEIPT_RETENTION_DAYS>,
    #[serde(default = "default_hook_payload_retention_days")]
    pub hook_payload_retention_days: BoundedU32<1, MAXIMUM_HOOK_PAYLOAD_RETENTION_DAYS>,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            receipt_retention_days: default_receipt_retention_days(),
            hook_payload_retention_days: default_hook_payload_retention_days(),
        }
    }
}

fn default_receipt_retention_days() -> BoundedU32<1, MAXIMUM_RECEIPT_RETENTION_DAYS> {
    BoundedU32::new(7).expect("seven days is within the receipt retention bounds")
}

fn default_hook_payload_retention_days() -> BoundedU32<1, MAXIMUM_HOOK_PAYLOAD_RETENTION_DAYS> {
    BoundedU32::new(7).expect("seven days is within the hook payload retention bounds")
}

/// One rule the runtime document breaks: the member it concerns, as a JSON
/// pointer, and what to do about it. It never carries a configured value.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Finding {
    pub code: &'static str,
    pub pointer: String,
    pub message: String,
    pub suggested_action: &'static str,
}

impl Finding {
    fn new(
        code: &'static str,
        pointer: &str,
        message: impl Into<String>,
        suggested_action: &'static str,
    ) -> Self {
        Self {
            code,
            pointer: pointer.to_owned(),
            message: message.into(),
            suggested_action,
        }
    }

    fn block(pointer: &str, error: &ConfigBlockError) -> Self {
        Self::new(
            "documents.runtime.invalid-block",
            pointer,
            error.to_string(),
            "Correct the member the message names.",
        )
    }
}

/// Why the runtime document was refused.
#[derive(Debug, Error)]
pub enum RuntimeConfigError {
    /// The shared loader refused the file: it could not be read, or its
    /// envelope, keys, or values are not the format.
    #[error("{0}")]
    Load(#[from] registry_platform_config::RuntimeConfigError),
    /// The file decoded and breaks at least one runtime rule.
    #[error("{}", refused(.0))]
    Refused(Vec<Finding>),
    /// The secret providers could not be prepared.
    #[error("the secret providers could not be prepared: {0}")]
    SecretProviders(String),
}

fn refused(findings: &[Finding]) -> String {
    match findings {
        [] => "the runtime configuration was refused".to_owned(),
        [only] => only.message.clone(),
        [first, rest @ ..] => format!(
            "{} (and {} more; run documentsctl check --runtime-config for every finding)",
            first.message,
            rest.len()
        ),
    }
}

impl RuntimeConfig {
    #[must_use]
    pub const fn loader() -> RuntimeConfigLoader {
        RuntimeConfigLoader::new(DOCUMENTS_RUNTIME_ENVELOPE).removed_keys(DOCUMENTS_REMOVED_KEYS)
    }

    /// Load and check the operator document at an absolute path, reading
    /// `${VAR}` expressions from the process environment.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, RuntimeConfigError> {
        let loaded = Self::loader().load::<Self>(path.as_ref())?;
        let findings = loaded.config.findings();
        if findings.is_empty() {
            Ok(loaded.config)
        } else {
            Err(RuntimeConfigError::Refused(findings))
        }
    }

    /// The resolver for every secret reference this document names.
    pub fn secret_resolver(&self) -> Result<SecretResolver, RuntimeConfigError> {
        self.secret_providers
            .resolver()
            .map_err(|error| RuntimeConfigError::SecretProviders(error.to_string()))
    }

    /// Every rule this document breaks, in document order.
    #[must_use]
    pub fn findings(&self) -> Vec<Finding> {
        let mut findings = Vec::new();
        self.check_identity(&mut findings);
        if let Err(error) = self.package.check() {
            findings.push(Finding::block("/package", &error));
        }
        self.check_listener(&mut findings);
        self.check_secret_providers(&mut findings);
        self.check_database(&mut findings);
        self.check_oidc(&mut findings);
        self.check_audit(&mut findings);
        self.check_content_verification(&mut findings);
        self.check_hook_destinations(&mut findings);
        findings
    }

    fn check_identity(&self, findings: &mut Vec<Finding>) {
        if self.identity.is_none() {
            findings.push(Finding::new(
                "documents.runtime.missing-identity",
                "/identity",
                "identity.databaseId is required",
                "Add `identity: {databaseId: registry-documents-production}` with a logical id chosen for this deployment.",
            ));
        }
    }

    fn check_listener(&self, findings: &mut Vec<Finding>) {
        if !self.listener.is_valid() {
            findings.push(Finding::new(
                "documents.runtime.invalid-listener",
                "/listener",
                "listener.bind is not allowed for the declared tlsTermination and networkExposure",
                "Bind a loopback address for development-loopback, a loopback or private address behind operator-controlled-upstream, or the unspecified address only with container-private.",
            ));
        }
    }

    fn check_secret_providers(&self, findings: &mut Vec<Finding>) {
        if let Err(error) = self.secret_providers.check() {
            findings.push(Finding::block("/secretProviders", &error));
            return;
        }
        let mut references: Vec<(String, &str)> = self
            .database
            .references()
            .into_iter()
            .map(|(field, reference)| (field.to_owned(), reference))
            .collect();
        if let ContentVerificationConfig::Http {
            authorization_ref, ..
        } = &self.content_verification
        {
            references.push((
                "contentVerification.authorizationRef".to_owned(),
                authorization_ref.as_str(),
            ));
        }
        for (id, destination) in &self.destinations.hooks {
            references.push((
                format!("destinations.hooks.{id}.hmacSha256KeyRef"),
                destination.hmac_sha256_key_ref.as_str(),
            ));
        }
        for (field, reference) in references {
            if let Err(error) = self.secret_providers.check_reference(&field, reference) {
                findings.push(Finding::block(&dotted_pointer(&field), &error));
            }
        }
        if let Err(error) = self.audit.key.check(&self.secret_providers) {
            findings.push(Finding::block("/audit/hashKeyRef", &error));
        }
    }

    fn check_database(&self, findings: &mut Vec<Finding>) {
        if self.database.test_only_plaintext && !cfg!(feature = "postgres-test") {
            findings.push(Finding::new(
                "documents.runtime.plaintext-database",
                "/database/testOnlyPlaintext",
                "database.testOnlyPlaintext is accepted only by test builds",
                "Remove database.testOnlyPlaintext and connect over TLS.",
            ));
        }
    }

    fn check_oidc(&self, findings: &mut Vec<Finding>) {
        let oidc = &self.authentication.oidc;
        let development = self.listener.tls_termination == TlsTermination::DevelopmentLoopback;
        if let Err(error) = oidc.provider.check("authentication.oidc", development) {
            findings.push(Finding::block("/authentication/oidc", &error));
        }
        if let Err(error) = oidc.clients.check("authentication.oidc") {
            findings.push(Finding::block("/authentication/oidc", &error));
        }
        if oidc.clients.allowed_clients.is_empty() {
            findings.push(Finding::new(
                "documents.runtime.allowed-clients-required",
                "/authentication/oidc/allowedClients",
                "authentication.oidc.allowedClients must list the clients this runtime admits; `unrestricted` is refused",
                "List every OAuth client an access profile names under allowedClients.",
            ));
        }
    }

    fn check_audit(&self, findings: &mut Vec<Finding>) {
        if let Err(error) = AuditDestination::from_settings(
            self.audit.destination,
            self.audit.path.clone(),
            None,
            None,
        ) {
            findings.push(Finding::new(
                "documents.runtime.invalid-audit",
                "/audit",
                error.to_string(),
                "Write audit.path as an absolute file path for destination file, or choose destination stdout.",
            ));
        }
    }

    fn check_content_verification(&self, findings: &mut Vec<Finding>) {
        let development = self.listener.tls_termination == TlsTermination::DevelopmentLoopback;
        match &self.content_verification {
            ContentVerificationConfig::Disabled {} if !development => {
                findings.push(Finding::new(
                    "documents.runtime.content-verification-disabled",
                    "/contentVerification/type",
                    "contentVerification type disabled is accepted only beside listener.tlsTermination development-loopback",
                    "Configure an http content verifier, or run the listener in development-loopback mode.",
                ));
            }
            ContentVerificationConfig::Http { url, .. } if !url.is_https() && !development => {
                findings.push(Finding::new(
                    "documents.runtime.insecure-url",
                    "/contentVerification/url",
                    "contentVerification.url must be an https URL",
                    "Write an https URL, or run the listener in development-loopback mode.",
                ));
            }
            _ => {}
        }
    }

    fn check_hook_destinations(&self, findings: &mut Vec<Finding>) {
        let development = self.listener.tls_termination == TlsTermination::DevelopmentLoopback;
        for (id, destination) in &self.destinations.hooks {
            if !destination.url.is_https() && !development {
                findings.push(Finding::new(
                    "documents.runtime.insecure-url",
                    &format!("/destinations/hooks/{}/url", escape(id.as_str())),
                    format!("destinations.hooks.{id}.url must be an https URL"),
                    "Write an https URL, or run the listener in development-loopback mode.",
                ));
            }
        }
    }
}

fn escape(segment: &str) -> String {
    registry_platform_yaml::escape_pointer_segment(segment)
}

/// The JSON pointer of a dotted field name.
fn dotted_pointer(field: &str) -> String {
    field
        .split('.')
        .map(|segment| format!("/{}", escape(segment)))
        .collect()
}

/// What an offline check of one runtime document found (CFG-CHECK-1).
#[derive(Debug)]
pub struct RuntimeCheck {
    /// Every finding, positioned at the member it concerns, in file order.
    pub report: Report,
    /// The file could not be read at all, as opposed to read and refused.
    pub unavailable: bool,
}

/// Check the runtime document at the absolute `path` as `documents serve`
/// reads it, with no database, network, or secret material, and report every
/// rule it breaks.
///
/// With `substitute` set, `${NAME}` expressions are filled from the process
/// environment and every value is checked. Without it, each expression is
/// checked by syntax and position only, and a rule about its value is left
/// out.
#[must_use]
pub fn check_runtime_file(path: &Path, substitute: bool) -> RuntimeCheck {
    let check =
        RuntimeConfig::loader().check_offline::<RuntimeConfig>(path, substitute, stand_in_for);
    let diagnostics: Vec<Diagnostic> = match &check.loaded {
        Some(loaded) => loaded
            .config
            .findings()
            .iter()
            .filter(|finding| !check.defers_within(&finding.pointer))
            .map(|finding| positioned(&check, finding))
            .collect(),
        None => Vec::new(),
    };
    RuntimeCheck {
        report: check.report_with(DOCUMENTS_RUNTIME_KIND, diagnostics),
        unavailable: check.unavailable,
    }
}

/// The report `documents serve` prints when it refuses the runtime document
/// at `path`: every diagnostic the shared loader or the runtime rules hold,
/// each at its position. `None` for a refusal that is not about the file.
#[must_use]
pub fn startup_report(path: &Path, error: &RuntimeConfigError) -> Option<Report> {
    match error {
        RuntimeConfigError::Load(error) => Some(Report::new(error.diagnostics().to_vec())),
        RuntimeConfigError::Refused(_) => {
            let report = check_runtime_file(path, true).report;
            (!report.is_empty()).then_some(report)
        }
        RuntimeConfigError::SecretProviders(_) => None,
    }
}

/// `finding` at the value of its member, or, for a member that is absent, at
/// the nearest mapping above it that is present.
fn positioned(check: &RuntimeFileCheck<RuntimeConfig>, finding: &Finding) -> Diagnostic {
    let mut diagnostic = check.error_at(
        DOCUMENTS_RUNTIME_KIND,
        finding.code,
        &finding.pointer,
        finding.message.clone(),
        finding.suggested_action,
    );
    let mut located = finding.pointer.as_str();
    while diagnostic
        .source
        .as_ref()
        .is_some_and(|source| source.line.is_none())
        && !located.is_empty()
    {
        located = &located[..located.rfind('/').unwrap_or(0)];
        diagnostic.source = check
            .error_at(DOCUMENTS_RUNTIME_KIND, "", located, "", "")
            .source;
    }
    diagnostic
}

/// A value for an expression the offline check does not substitute, chosen
/// so the member it fills decodes and passes the rules about its value.
fn stand_in_for(pointer: &str) -> &'static str {
    let segments: Vec<&str> = pointer.split('/').skip(1).collect();
    match segments.as_slice() {
        ["listener", "bind"] => DEFAULT_LISTENER_BIND,
        ["listener", "tlsTermination"] => "development-loopback",
        ["listener", "networkExposure"] => "private-address",
        ["audit", "destination"] => "file",
        ["package", "root"] | ["audit", "path"] | ["secretProviders", "file", "root"] => {
            "/deferred"
        }
        ["package", "expectedDigest"] => {
            "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        }
        ["authentication", "oidc", "issuer"]
        | ["authentication", "oidc", "jwksSource", "uri"]
        | ["contentVerification", "url"]
        | ["destinations", "hooks", _, "url"] => "https://deferred.invalid",
        _ => DEFAULT_STAND_IN,
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const STARTER_RUNTIME: &str =
        include_str!("../../../products/documents/examples/starter/runtime.example.yaml");

    fn parse(text: &str) -> Result<RuntimeConfig, RuntimeConfigError> {
        let config = RuntimeConfig::loader()
            .parse_str::<RuntimeConfig>(text, |_| None)?
            .config;
        let findings = config.findings();
        if findings.is_empty() {
            Ok(config)
        } else {
            Err(RuntimeConfigError::Refused(findings))
        }
    }

    fn codes(error: RuntimeConfigError) -> Vec<String> {
        match error {
            RuntimeConfigError::Refused(findings) => findings
                .iter()
                .map(|finding| finding.code.to_owned())
                .collect(),
            RuntimeConfigError::Load(error) => error
                .diagnostics()
                .iter()
                .map(|diagnostic| diagnostic.code.clone())
                .collect(),
            RuntimeConfigError::SecretProviders(message) => vec![message],
        }
    }

    #[test]
    fn the_starter_runtime_document_is_accepted() {
        let config = parse(STARTER_RUNTIME).expect("the starter runtime document");
        assert_eq!(
            config.identity.as_ref().unwrap().database_id.as_str(),
            "registry-documents-production"
        );
        assert_eq!(
            config.listener.bind.socket_addr().to_string(),
            DEFAULT_LISTENER_BIND
        );
        assert!(matches!(
            config.storage,
            StorageConfig::Database { maximum_document_bytes } if u64::from(maximum_document_bytes) == 16_777_216
        ));
        assert!(matches!(
            config.content_verification,
            ContentVerificationConfig::Http { .. }
        ));
        assert_eq!(config.cleanup.erasure, Erasure::Active);
        assert_eq!(config.destinations.hooks.len(), 1);
        assert_eq!(config.retention, RetentionConfig::default());
    }

    #[test]
    fn an_unknown_member_is_refused_by_the_shared_reader() {
        let text = STARTER_RUNTIME.replace("cleanup:\n", "unexpected: true\ncleanup:\n");
        assert!(codes(parse(&text).unwrap_err()).contains(&"config.unknown-key".to_owned()));
    }

    #[test]
    fn a_missing_identity_is_refused_by_name() {
        let text = STARTER_RUNTIME.replace(
            "identity:\n  # The one database this deployment owns.\n  databaseId: registry-documents-production\n",
            "",
        );
        assert_ne!(
            text, STARTER_RUNTIME,
            "the fixture names the identity block"
        );
        assert_eq!(
            codes(parse(&text).unwrap_err()),
            ["documents.runtime.missing-identity"]
        );
    }

    #[test]
    fn shared_runtime_loader_refuses_environment_expressions_in_secret_references() {
        for (written, substituted, pointer) in [
            (
                "runtimeUrlRef: secret:file/runtime-database-url",
                "runtimeUrlRef: ${DATABASE_URL}",
                "/database/runtimeUrlRef",
            ),
            (
                "hashKeyRef: secret:file/documents-audit-key",
                "hashKeyRef: secret:env/${KEY_NAME:-AUDIT}",
                "/audit/hashKeyRef",
            ),
        ] {
            let text = STARTER_RUNTIME.replacen(written, substituted, 1);
            assert_ne!(text, STARTER_RUNTIME, "{pointer}");
            let RuntimeConfigError::Load(error) = parse(&text).unwrap_err() else {
                panic!("{pointer}: the shared loader refuses the reference");
            };
            let found: Vec<(&str, &str)> = error
                .diagnostics()
                .iter()
                .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
                .collect();
            assert_eq!(found, [("config.substitution-not-allowed", pointer)]);
        }
    }

    #[test]
    fn unrestricted_clients_are_refused() {
        let text = STARTER_RUNTIME.replace(
            "allowedClients: [civil-registry-app, citizen-portal, case-portal, partner-portal]",
            "allowedClients: unrestricted",
        );
        assert_ne!(text, STARTER_RUNTIME);
        assert_eq!(
            codes(parse(&text).unwrap_err()),
            ["documents.runtime.allowed-clients-required"]
        );
    }

    #[test]
    fn disabled_content_verification_requires_development_loopback() {
        let disabled = STARTER_RUNTIME.replace(
            "  type: http\n  url: https://scanner.example.test/v1/verify\n  authorizationRef: secret:file/content-verifier-authorization\n  policyId: documents-default\n  attemptTimeoutMilliseconds: 10000\n",
            "  type: disabled\n",
        );
        assert_ne!(disabled, STARTER_RUNTIME);
        assert_eq!(
            codes(parse(&disabled).unwrap_err()),
            ["documents.runtime.content-verification-disabled"]
        );
        let development = disabled.replace(
            "tlsTermination: operator-controlled-upstream",
            "tlsTermination: development-loopback",
        );
        assert!(parse(&development).is_ok());
    }

    #[test]
    fn a_reference_to_a_disabled_provider_is_refused() {
        let text = STARTER_RUNTIME.replace(
            "hmacSha256KeyRef: secret:file/custodian-events-hmac",
            "hmacSha256KeyRef: secret:env/CUSTODIAN_EVENTS_HMAC",
        );
        assert_ne!(text, STARTER_RUNTIME);
        let error = parse(&text).unwrap_err();
        let RuntimeConfigError::Refused(findings) = error else {
            panic!("a refused document");
        };
        assert_eq!(findings.len(), 1);
        assert_eq!(
            findings[0].pointer,
            "/destinations/hooks/custodian-events/hmacSha256KeyRef"
        );
        assert!(!findings[0].message.contains("CUSTODIAN_EVENTS_HMAC"));
    }

    #[test]
    fn a_plaintext_hook_destination_is_refused_outside_development() {
        let text = STARTER_RUNTIME.replace(
            "url: https://civil-registry.example.test/document-events",
            "url: http://civil-registry.example.test/document-events",
        );
        assert_ne!(text, STARTER_RUNTIME);
        assert_eq!(
            codes(parse(&text).unwrap_err()),
            ["documents.runtime.insecure-url"]
        );
    }

    #[test]
    fn a_storage_ceiling_above_the_product_bound_is_out_of_range() {
        let text = STARTER_RUNTIME.replace(
            "maximumDocumentBytes: 16777216",
            "maximumDocumentBytes: 1073741825",
        );
        assert_ne!(text, STARTER_RUNTIME);
        assert!(codes(parse(&text).unwrap_err()).contains(&"config.out-of-range".to_owned()));
    }

    #[test]
    fn plaintext_database_is_refused_outside_test_builds() {
        let text = STARTER_RUNTIME.replace(
            "  migrationUrlRef: secret:file/migration-database-url\n",
            "  migrationUrlRef: secret:file/migration-database-url\n  testOnlyPlaintext: true\n",
        );
        assert_ne!(text, STARTER_RUNTIME);
        let result = parse(&text);
        if cfg!(feature = "postgres-test") {
            assert!(result.is_ok());
        } else {
            assert_eq!(
                codes(result.unwrap_err()),
                ["documents.runtime.plaintext-database"]
            );
        }
    }
}
