// SPDX-License-Identifier: Apache-2.0

//! The operator runtime configuration document and the policy package
//! identity it verifies.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use jsonwebtoken::Algorithm;
pub(crate) use registry_platform_config::describe_secret_failure;
use registry_platform_config::{
    redact_refused_values, reject_environment_expressions_in_authored_yaml, sha256_uri,
    ConfigBlockError, PackageDigestMismatch, RemovedKey, RuntimeConfigErrorKind,
    RuntimeConfigLoader, RuntimeEnvelope, SecretResolver, REMOVED_OIDC_JWKS_URI,
};
pub use registry_platform_config::{
    AuditKeyConfig, DatabaseConfig, EnvironmentSecretProviderConfig, FileSecretProviderConfig,
    JwksSource, ListenerNetworkExposure, OidcClientsConfig, OidcIssuerConfig, PackageConfig,
    PrivateListenerConfig as ListenerConfig, SecretProvidersConfig, TlsTermination,
};
use registry_platform_oidc::{
    access_token_typ_set, fetch_discovery, parse_static_jwks, JwksFetcher, JwksFetcherConfig,
    OidcDiscoveryConfig, TokenVerifierConfig,
};
use registry_scheduling_core::{
    parse_policy_yaml, SchedulingPolicy, AUTHORED_POLICY_FILE, SCHEDULING_PACKAGE_MANIFEST_FILE,
    SCHEDULING_RUNTIME_API_VERSION, SCHEDULING_RUNTIME_KIND,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAXIMUM_POLICY_FILE_BYTES: usize = 1024 * 1024;
const MAXIMUM_PACKAGE_MANIFEST_BYTES: usize = 1024 * 1024;

/// apiVersion of the package manifest written beside the authored policy.
///
/// The manifest names a package identity; the authored policy names a policy.
/// They are two documents with two readers, so they carry two names and
/// neither reader accepts the other's document.
pub const SCHEDULING_PACKAGE_MANIFEST_API_VERSION: &str =
    "registry.registrystack.org/scheduling-policy-package-manifest/v1alpha1";

/// Kind of the package manifest written beside the authored policy.
pub const SCHEDULING_PACKAGE_MANIFEST_KIND: &str = "SchedulingPolicyPackageManifest";

/// The default number of days a stored idempotency receipt is replayable
/// before the retention sweep erases it. The default is a floor, not a
/// recommendation: a jurisdiction's retention schedule approves the deployed
/// value, and the deployed value is what the audit journal records.
pub const DEFAULT_ATTEMPT_RECEIPT_DAYS: u16 = 7;

/// The envelope every Scheduling runtime configuration carries.
pub const SCHEDULING_RUNTIME_ENVELOPE: RuntimeEnvelope = RuntimeEnvelope {
    api_version: SCHEDULING_RUNTIME_API_VERSION,
    kind: SCHEDULING_RUNTIME_KIND,
};

/// Keys an earlier Scheduling runtime configuration accepted, each refused
/// with the key that replaced it.
pub const SCHEDULING_REMOVED_KEYS: &[RemovedKey] = &[REMOVED_OIDC_JWKS_URI];

/// The operator runtime configuration document.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeConfig {
    pub api_version: String,
    pub kind: String,
    pub package: PackageConfig,
    pub listener: ListenerConfig,
    pub secret_providers: SecretProvidersConfig,
    pub database: DatabaseConfig,
    pub authentication: AuthenticationConfig,
    pub audit: AuditConfig,
    #[serde(default)]
    pub destinations: DestinationsConfig,
    pub retention: RetentionConfig,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthenticationConfig {
    pub oidc: OidcConfig,
}

/// The access tokens this runtime accepts: the issuer and its keys, the
/// clients admitted, and the scopes each route family requires.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OidcConfig {
    /// The exact issuer, the one audience every token carries, and where the
    /// issuer's signing keys come from.
    #[serde(flatten)]
    pub provider: OidcIssuerConfig,
    /// The clients admitted and the assertion authorities each may exchange
    /// a subject token from. A deployment that performs no token exchange
    /// leaves `assertionIssuers` empty; once a client is listed, an assertion
    /// minted by an unrelated authority the issuer happens to federate cannot
    /// become a booking credential here.
    #[serde(flatten)]
    pub clients: OidcClientsConfig,
    #[serde(default = "default_scope_claim")]
    pub scope_claim: String,
    /// The scope every listing and availability read requires.
    #[serde(default = "default_reads_scope")]
    pub reads_scope: String,
    /// The scope the separately authorized explain path requires.
    #[serde(default = "default_explain_scope")]
    pub explain_scope: String,
}

/// The RFC 9068 access-token media type this runtime verifies. The pair of
/// spellings it admits is derived, never authored, so no deployment can widen
/// it to an ordinary JWT.
const SCHEDULING_ACCESS_TOKEN_TYPE: &str = "at+jwt";

fn default_scope_claim() -> String {
    "registry_scopes".to_owned()
}
fn default_reads_scope() -> String {
    "scheduling-read".to_owned()
}
fn default_explain_scope() -> String {
    "scheduling-explain".to_owned()
}

/// The audit journal: where it is written and the key its hashes use.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuditConfig {
    pub path: PathBuf,
    /// The secret keying the audit journal's hashes, `hashKeyRef`.
    #[serde(flatten)]
    pub key: AuditKeyConfig,
}

/// Where due reminder and lifecycle-hook intents are dispatched. An absent
/// reminders destination and an empty hook map are supported: intents stay
/// local, so an operator can adopt the product before wiring delivery buses.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DestinationsConfig {
    #[serde(default)]
    pub reminders: Option<ReminderDestinationConfig>,
    /// Logical URL hook destinations. The governed policy names only these
    /// ids; URL, signing secret, and retry ceilings stay deployment-owned.
    #[serde(default)]
    pub hooks: BTreeMap<String, HookDestinationConfig>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReminderDestinationConfig {
    pub url: String,
    #[serde(default)]
    pub bearer_token_ref: Option<String>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HookDestinationConfig {
    pub url: String,
    pub hmac_sha256_key_ref: String,
    #[serde(default = "default_hook_attempt_timeout_milliseconds")]
    pub attempt_timeout_milliseconds: u32,
    #[serde(default = "default_hook_maximum_attempts")]
    pub maximum_attempts: u8,
}

const fn default_hook_attempt_timeout_milliseconds() -> u32 {
    5_000
}

const fn default_hook_maximum_attempts() -> u8 {
    8
}

/// Retention periods the retention sweep enforces. Every value is deployment
/// configuration, never policy: a jurisdiction's retention schedule approves
/// the deployed numbers, and changing one is an operational event.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetentionConfig {
    /// How long a stored idempotency receipt stays replayable.
    #[serde(default = "default_attempt_receipt_days")]
    pub attempt_receipt_days: u16,
    /// Lifetime of canonical hook envelopes retained for retry and
    /// dead-letter inspection.
    #[serde(default = "default_hook_payload_days")]
    pub hook_payload_days: u16,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            attempt_receipt_days: DEFAULT_ATTEMPT_RECEIPT_DAYS,
            hook_payload_days: default_hook_payload_days(),
        }
    }
}

fn default_attempt_receipt_days() -> u16 {
    DEFAULT_ATTEMPT_RECEIPT_DAYS
}

const fn default_hook_payload_days() -> u16 {
    7
}

/// The immutable identity of a packaged policy: the digest of the package
/// envelope over its exact authored files. A scheduling package is one
/// authored policy file, so the manifest is small, but it is still a
/// separate document the runtime verifies rather than trusts.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyPackageManifest {
    pub api_version: String,
    pub kind: String,
    pub policy_digest: String,
    pub files: Vec<PolicyPackageFile>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PolicyPackageFile {
    pub path: String,
    pub sha256: String,
    pub bytes: u64,
}

impl PolicyPackageManifest {
    /// Build the immutable identity for an already validated policy text.
    pub fn build(policy_text: &str) -> Result<Self, PolicyPackageError> {
        let bytes = policy_text.as_bytes();
        if bytes.len() > MAXIMUM_POLICY_FILE_BYTES {
            return Err(PolicyPackageError::Invalid);
        }
        let files = vec![PolicyPackageFile {
            path: AUTHORED_POLICY_FILE.to_owned(),
            sha256: sha256_uri(bytes),
            bytes: u64::try_from(bytes.len()).map_err(|_| PolicyPackageError::Invalid)?,
        }];
        Ok(Self {
            api_version: SCHEDULING_PACKAGE_MANIFEST_API_VERSION.to_owned(),
            kind: SCHEDULING_PACKAGE_MANIFEST_KIND.to_owned(),
            policy_digest: package_digest(&files)?,
            files,
        })
    }

    fn verify(&self, policy_text: &str) -> Result<(), PolicyPackageError> {
        let expected = Self::build(policy_text)?;
        if self.api_version != expected.api_version
            || self.kind != expected.kind
            || self.files != expected.files
            || self.policy_digest != expected.policy_digest
        {
            return Err(PolicyPackageError::Invalid);
        }
        Ok(())
    }
}

/// Verify the package beside `scheduling.yaml`. An absent manifest is
/// distinguished so local authored development remains usable.
pub fn verify_policy_package(
    policy_path: &Path,
    policy_text: &str,
) -> Result<Option<String>, PolicyPackageError> {
    if policy_path.file_name().and_then(|name| name.to_str()) != Some(AUTHORED_POLICY_FILE) {
        return Err(PolicyPackageError::Invalid);
    }
    let root = policy_path.parent().ok_or(PolicyPackageError::Invalid)?;
    let manifest_path = root.join(SCHEDULING_PACKAGE_MANIFEST_FILE);
    if !manifest_path.exists() {
        return Ok(None);
    }
    let metadata = std::fs::symlink_metadata(&manifest_path).map_err(PolicyPackageError::Read)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.len() > MAXIMUM_PACKAGE_MANIFEST_BYTES as u64
    {
        return Err(PolicyPackageError::Invalid);
    }
    let bytes = std::fs::read(&manifest_path).map_err(PolicyPackageError::Read)?;
    let manifest: PolicyPackageManifest =
        serde_json::from_slice(&bytes).map_err(|_| PolicyPackageError::Invalid)?;
    manifest.verify(policy_text)?;
    Ok(Some(manifest.policy_digest))
}

fn package_digest(files: &[PolicyPackageFile]) -> Result<String, PolicyPackageError> {
    let identity = serde_json::json!({
        "apiVersion": SCHEDULING_PACKAGE_MANIFEST_API_VERSION,
        "kind": SCHEDULING_PACKAGE_MANIFEST_KIND,
        "files": files,
    });
    let canonical = registry_platform_canonical_json::canonicalize_json(&identity)
        .map_err(|_| PolicyPackageError::Invalid)?;
    Ok(sha256_uri(&canonical))
}

impl RuntimeConfig {
    /// Load and validate the operator document, reading the authored policy
    /// beside it. The bytes never re-enter a parser after startup.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, RuntimeConfigError> {
        let loaded = Self::loader().load::<Self>(path.as_ref())?;
        loaded.config.check()?;
        Ok(loaded.config)
    }

    /// The shared runtime configuration loader under Scheduling's envelope
    /// and removed keys.
    #[must_use]
    pub const fn loader() -> RuntimeConfigLoader {
        RuntimeConfigLoader::new(SCHEDULING_RUNTIME_ENVELOPE).removed_keys(SCHEDULING_REMOVED_KEYS)
    }

    #[must_use]
    pub fn policy_path(&self) -> PathBuf {
        self.package.root.join(AUTHORED_POLICY_FILE)
    }

    /// Read and validate the authored policy this deployment runs.
    pub fn load_policy(&self) -> Result<SchedulingPolicy, RuntimeConfigError> {
        let policy_text =
            std::fs::read_to_string(self.policy_path()).map_err(RuntimeConfigError::PolicyRead)?;
        let policy = parse_policy_yaml(&policy_text).map_err(|error| {
            let (path, cause) = refused_yaml(error);
            RuntimeConfigError::PolicyParse { path, cause }
        })?;
        reject_environment_expressions_in_authored_yaml(&policy_text).map_err(|error| {
            if error.kind() == RuntimeConfigErrorKind::AuthoredSyntax {
                RuntimeConfigError::PolicyParse {
                    path: error.field().to_owned(),
                    cause: error.message().to_owned(),
                }
            } else {
                RuntimeConfigError::PolicyEnvironmentExpression {
                    field: error.field().to_owned(),
                }
            }
        })?;
        if !policy.check().is_empty() {
            return Err(RuntimeConfigError::PolicyFindings);
        }
        // A present manifest is verified against the exact policy text; the
        // digest the runtime publishes is the policy's own, not the manifest's.
        verify_policy_package(&self.policy_path(), &policy_text)
            .map_err(RuntimeConfigError::PolicyPackage)?;
        Ok(policy)
    }

    /// Return the verified package identity, if this is a packaged
    /// deployment. Production configurations always have one.
    pub fn policy_package_digest(&self) -> Result<Option<String>, RuntimeConfigError> {
        let policy_text =
            std::fs::read_to_string(self.policy_path()).map_err(RuntimeConfigError::PolicyRead)?;
        verify_policy_package(&self.policy_path(), &policy_text)
            .map_err(RuntimeConfigError::PolicyPackage)
    }

    pub fn check(&self) -> Result<(), RuntimeConfigError> {
        if self.api_version != SCHEDULING_RUNTIME_API_VERSION
            || self.kind != SCHEDULING_RUNTIME_KIND
        {
            return Err(RuntimeConfigError::InvalidEnvelope);
        }
        self.package.check()?;
        self.secret_providers.check()?;
        if !self.audit.path.is_absolute() {
            return Err(RuntimeConfigError::RelativeOperatedPath("audit.path"));
        }
        if !self.listener.is_valid() {
            return Err(RuntimeConfigError::InvalidListener);
        }
        self.authentication.oidc.provider.check(
            "authentication.oidc",
            self.listener.tls_termination == TlsTermination::DevelopmentLoopback,
        )?;
        self.authentication
            .oidc
            .clients
            .check("authentication.oidc")?;
        if self.authentication.oidc.scope_claim.is_empty()
            || self.authentication.oidc.reads_scope.is_empty()
            || self.authentication.oidc.explain_scope.is_empty()
            || self.authentication.oidc.explain_scope == self.authentication.oidc.reads_scope
        {
            return Err(RuntimeConfigError::InvalidOidc);
        }
        // An empty client list admits every client the issuer verifies, so a
        // deployment that simply forgot the field would accept a token minted
        // for an unrelated application in the same realm. Development loopback
        // keeps that convenience; a deployment behind an operator-controlled
        // terminator must name the clients it admits.
        if self.listener.tls_termination == TlsTermination::OperatorControlledUpstream
            && self.authentication.oidc.clients.allowed_clients.is_empty()
        {
            return Err(RuntimeConfigError::InvalidOidc);
        }
        if self.database.runtime_url_ref.is_empty() || self.database.migration_url_ref.is_empty() {
            return Err(RuntimeConfigError::InvalidDatabaseReference);
        }
        if self.retention.attempt_receipt_days == 0
            || !(1..=30).contains(&self.retention.hook_payload_days)
        {
            return Err(RuntimeConfigError::InvalidRetention);
        }
        if let Some(reminders) = &self.destinations.reminders {
            if !valid_destination_url(&reminders.url) {
                return Err(RuntimeConfigError::InvalidDestination);
            }
        }
        if self.destinations.hooks.len() > 128 {
            return Err(RuntimeConfigError::InvalidHookDestination);
        }
        for (id, destination) in &self.destinations.hooks {
            if !valid_logical_destination_id(id)
                || !valid_destination_url(&destination.url)
                || !(100..=10_000).contains(&destination.attempt_timeout_milliseconds)
                || !(1..=20).contains(&destination.maximum_attempts)
            {
                return Err(RuntimeConfigError::InvalidHookDestination);
            }
        }
        self.validate_secret_references()?;

        let policy = self.load_policy()?;
        let declared_hook_destinations = policy
            .hooks
            .iter()
            .filter_map(|hook| match &hook.handler {
                registry_platform_hooks::HookHandlerSource::Url { destination_id } => {
                    Some(destination_id.as_str())
                }
                _ => None,
            })
            .collect::<BTreeSet<_>>();
        let configured_hook_destinations =
            self.destinations.hooks.keys().map(String::as_str).collect();
        if !declared_hook_destinations.is_subset(&configured_hook_destinations) {
            return Err(RuntimeConfigError::HookDestinationInventoryMismatch);
        }
        let package_digest = self.policy_package_digest()?;
        match package_digest.as_deref() {
            Some(found) => self.package.verify_digest(found)?,
            None if self.listener.tls_termination == TlsTermination::OperatorControlledUpstream
                || self.package.expected_digest.is_some() =>
            {
                return Err(RuntimeConfigError::ProductionPolicyPackageRequired);
            }
            None => {}
        }
        #[cfg(not(feature = "postgres-test"))]
        if self.database.test_only_plaintext {
            return Err(RuntimeConfigError::PlaintextDatabase);
        }
        Ok(())
    }

    fn validate_secret_references(&self) -> Result<(), RuntimeConfigError> {
        let mut references: Vec<(String, &str)> = self
            .database
            .references()
            .into_iter()
            .map(|(field, reference)| (field.to_owned(), reference))
            .collect();
        references.push((
            "audit.hashKeyRef".to_owned(),
            self.audit.key.hash_key_ref.as_str(),
        ));
        if let Some(document_ref) = self.authentication.oidc.provider.jwks_source.document_ref() {
            references.push((
                "authentication.oidc.jwksSource.documentRef".to_owned(),
                document_ref,
            ));
        }
        if let Some(reminders) = &self.destinations.reminders {
            if let Some(reference) = &reminders.bearer_token_ref {
                references.push((
                    "destinations.reminders.bearerTokenRef".to_owned(),
                    reference,
                ));
            }
        }
        for (id, destination) in &self.destinations.hooks {
            references.push((
                format!("destinations.hooks.{id}.hmacSha256KeyRef"),
                &destination.hmac_sha256_key_ref,
            ));
        }
        for (field, raw) in references {
            self.secret_providers.check_reference(&field, raw)?;
        }
        Ok(())
    }

    pub async fn oidc_verifier(
        &self,
        secrets: &SecretResolver,
    ) -> Result<(TokenVerifierConfig, std::sync::Arc<JwksFetcher>), RuntimeConfigError> {
        let fetcher = match &self.authentication.oidc.provider.jwks_source {
            JwksSource::Uri { uri } => JwksFetcher::new(uri.clone(), JwksFetcherConfig::defaults()),
            JwksSource::Discovery {} => {
                let discovery_config = OidcDiscoveryConfig {
                    issuer: self.authentication.oidc.provider.issuer.clone(),
                    jwks_uri_override: None,
                    discovery_timeout: Duration::from_secs(5),
                    max_doc_bytes: 1024 * 1024,
                };
                let discovery = fetch_discovery(&discovery_config)
                    .await
                    .map_err(|_| RuntimeConfigError::Oidc)?;
                JwksFetcher::new(discovery.jwks_uri, JwksFetcherConfig::defaults())
            }
            JwksSource::Static { document_ref } => {
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
        Ok((self.verifier_profile(), std::sync::Arc::new(fetcher)))
    }

    /// The access-token verifier profile this deployment's OIDC settings
    /// describe.
    ///
    /// RFC 9068 gives the access token one media type spelled two ways,
    /// `at+jwt` and `application/at+jwt`, and requires a resource server to
    /// accept that pair and refuse every other `typ`. The list comes from
    /// [`access_token_typ_set`] so a plain `JWT` stays out: an ID token, a
    /// UserInfo JWT or any other JWT minted for this audience is not an
    /// access token, and admitting one would let a credential issued for
    /// another purpose book, reschedule or cancel an appointment.
    pub(crate) fn verifier_profile(&self) -> TokenVerifierConfig {
        TokenVerifierConfig::access_token_profile(
            self.authentication.oidc.provider.issuer.clone(),
            vec![self.authentication.oidc.provider.audience.clone()],
            vec![Algorithm::RS256, Algorithm::ES256],
            access_token_typ_set(SCHEDULING_ACCESS_TOKEN_TYPE),
        )
        .with_scope_claim(self.authentication.oidc.scope_claim.clone())
        .with_allowed_clients(self.authentication.oidc.clients.allowed_clients.clone())
        .with_assertion_issuers(self.authentication.oidc.clients.assertion_issuers.clone())
    }
}

/// A reminder destination URL is an absolute http(s) URL without userinfo.
/// Plain http is accepted only for an explicit loopback host, so a plaintext
/// destination can never silently point at another machine. Full network
/// egress policy is the deployment's perimeter concern, the same boundary
/// BREG draws for its webhook origins.
fn valid_destination_url(value: &str) -> bool {
    let Ok(parsed) = url::Url::parse(value) else {
        return false;
    };
    if parsed.username().is_empty()
        && parsed.password().is_none()
        && parsed.host().is_some()
        && parsed.port_or_known_default().is_some_and(|port| port != 0)
        // The destination is one reviewed endpoint, not a template a
        // configuration value may widen; the runtime's frozen transport
        // refuses a query or fragment, so the authoring check refuses it
        // first.
        && parsed.query().is_none()
        && parsed.fragment().is_none()
    {
        match parsed.scheme() {
            "https" => true,
            "http" => matches!(
                parsed.host_str(),
                Some("127.0.0.1") | Some("localhost") | Some("[::1]")
            ),
            _ => false,
        }
    } else {
        false
    }
}

fn valid_logical_destination_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
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

#[derive(Debug, Error)]
pub enum PolicyPackageError {
    #[error("the Scheduling policy package could not be read")]
    Read(#[source] std::io::Error),
    #[error("the Scheduling policy package is invalid or does not match its exact inputs")]
    Invalid,
}

#[derive(Debug, Error)]
pub enum RuntimeConfigError {
    #[error(transparent)]
    Load(#[from] registry_platform_config::RuntimeConfigError),
    #[error(transparent)]
    Block(#[from] ConfigBlockError),
    #[error(transparent)]
    PackageDigest(#[from] PackageDigestMismatch),
    #[error(
        "apiVersion and kind must be exactly registry.registrystack.org/scheduling-runtime/v1alpha1 and SchedulingRuntimeConfig"
    )]
    InvalidEnvelope,
    #[error("the operated runtime path {0} must be absolute")]
    RelativeOperatedPath(&'static str),
    #[error("the authored scheduling policy could not be read")]
    PolicyRead(#[source] std::io::Error),
    #[error(
        "{field} in the authored scheduling policy holds an environment expression; ${{...}} substitution applies to runtime.yaml only, so write the value in scheduling.yaml directly"
    )]
    PolicyEnvironmentExpression { field: String },
    #[error("the authored scheduling policy is not valid YAML at {path}: {cause}")]
    PolicyParse { path: String, cause: String },
    #[error("the authored scheduling policy does not pass its checks")]
    PolicyFindings,
    #[error("the Scheduling policy package is invalid")]
    PolicyPackage(#[source] PolicyPackageError),
    #[error("operator-controlled production requires a verified Scheduling policy package")]
    ProductionPolicyPackageRequired,
    #[error("listener is not valid for its declared TLS termination and network exposure")]
    InvalidListener,
    #[error("authentication.oidc is invalid")]
    InvalidOidc,
    #[error(
        "database.runtimeUrlRef and database.migrationUrlRef must be non-empty secret references"
    )]
    InvalidDatabaseReference,
    #[error("retention.attemptReceiptDays must be at least one day")]
    InvalidRetention,
    #[error("destinations.reminders.url is not a valid destination URL")]
    InvalidDestination,
    #[error("a destinations.hooks binding is invalid")]
    InvalidHookDestination,
    #[error("destinations.hooks must bind every destination declared by the policy")]
    HookDestinationInventoryMismatch,
    #[error("plaintext PostgreSQL is test-only")]
    PlaintextDatabase,
    #[error("the OIDC issuer could not be initialized")]
    Oidc,
    #[error("the static OIDC signing keys could not be loaded: {0}")]
    OidcJwksSecret(String),
}

impl RuntimeConfigError {
    #[must_use]
    pub fn path(&self) -> &str {
        match self {
            Self::Load(error) => error.field(),
            Self::Block(error) => error.field(),
            Self::PackageDigest(_) => "package.expectedDigest",
            Self::InvalidEnvelope => "apiVersion",
            Self::RelativeOperatedPath(path) => path,
            Self::InvalidOidc | Self::Oidc => "authentication.oidc",
            Self::OidcJwksSecret(_) => "authentication.oidc.jwksSource.documentRef",
            Self::InvalidListener => "listener",
            Self::InvalidDatabaseReference | Self::PlaintextDatabase => "database",
            Self::InvalidRetention => "retention",
            Self::InvalidDestination => "destinations.reminders.url",
            Self::InvalidHookDestination | Self::HookDestinationInventoryMismatch => {
                "destinations.hooks"
            }
            Self::PolicyRead(_)
            | Self::PolicyParse { .. }
            | Self::PolicyEnvironmentExpression { .. } => "package.root/scheduling.yaml",
            Self::PolicyFindings | Self::PolicyPackage(_) => "package.root",
            Self::ProductionPolicyPackageRequired => "package.root",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_platform_config::{
        MAX_ASSERTION_ISSUERS_PER_CLIENT, MAX_ASSERTION_ISSUER_BYTES, MAX_ASSERTION_ISSUER_CLIENTS,
        MAX_ASSERTION_ISSUER_CLIENT_BYTES,
    };
    use registry_platform_oidc::is_access_token_typ_pair;
    use registry_scheduling_core::{SCHEDULING_POLICY_API_VERSION, SCHEDULING_POLICY_KIND};

    const POLICY: &str = r#"apiVersion: registry.registrystack.org/scheduling-policy-package/v1alpha1
kind: SchedulingPolicyPackage
scheduling: {id: standalone-exact-time, version: 1}
services: [{id: registry-update, label: Registry record update}]
holidaySets: [{id: none, revision: 1, because: test, dates: []}]
openings:
  - id: weekdays
    location: north-counter
    holidaySet: none
    weekdays: [mon, tue, wed, thu, fri]
    startTime: "09:00"
    endTime: "12:00"
    effectiveFrom: "2026-01-01"
    effectiveUntil: "2027-01-01"
    because: test
offerings:
  - id: registry-update-30
    service: registry-update
    label: 30-minute counter update
    mode: exact-time
    location: north-counter
    because: test
    cancellationCutoffMinutes: 240
    exactTime:
      durationMinutes: 30
      bufferBeforeMinutes: 5
      bufferAfterMinutes: 5
      leadTimeMinutes: 120
      horizonDays: 60
      pool: north-counter
      startIncrementMinutes: 30
      maxRecipients: 1
    requiresCapabilities: []
    prerequisites: []
holdPolicy: {ttlMinutes: 10, maxPerCaller: 2, because: test}
"#;

    /// A temporary directory named by its canonical path: the loader refuses
    /// a runtime configuration reached through a symbolic link, and the
    /// system temporary directory is one on some platforms.
    fn canonical_tempdir() -> tempfile::TempDir {
        tempfile::tempdir_in(std::fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap()
    }

    fn write_policy(root: &Path) {
        std::fs::create_dir_all(root).unwrap();
        std::fs::write(root.join(AUTHORED_POLICY_FILE), POLICY).unwrap();
    }

    fn operator_value(package: &Path, tls: &str) -> serde_json::Value {
        let root = package.parent().expect("package parent");
        serde_json::json!({
            "apiVersion": SCHEDULING_RUNTIME_API_VERSION,
            "kind": SCHEDULING_RUNTIME_KIND,
            "package": {"root": package},
            "listener": {"bind": "127.0.0.1:8105", "tlsTermination": tls},
            "secretProviders": {"file": {"root": root.join("secrets")}, "environment": {}},
            "database": {
                "runtimeUrlRef": "secret:env/RUNTIME",
                "migrationUrlRef": "secret:env/MIGRATION"
            },
            "authentication": {"oidc": {
                "issuer": "https://identity.example.test",
                "audience": "urn:example:scheduling",
                "allowedClients": ["scheduling-booking-agent"]
            }},
            "audit": {"path": root.join("audit.ndjson"), "hashKeyRef": "secret:file/audit"},
            "destinations": {},
            "retention": {"attemptReceiptDays": 7}
        })
    }

    fn write_operator(root: &Path, document: serde_json::Value) -> PathBuf {
        let operator = root.join("runtime.yaml");
        std::fs::write(&operator, serde_norway::to_string(&document).unwrap()).unwrap();
        operator
    }

    #[test]
    fn a_development_configuration_loads_and_exposes_its_defaults() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        write_policy(&package);
        let operator = write_operator(
            root.path(),
            operator_value(&package, "development-loopback"),
        );
        let config = RuntimeConfig::load(&operator).expect("configuration is accepted");
        assert_eq!(config.authentication.oidc.scope_claim, "registry_scopes");
        assert_eq!(config.authentication.oidc.reads_scope, "scheduling-read");
        assert_eq!(
            config.authentication.oidc.explain_scope,
            "scheduling-explain"
        );
        assert_eq!(config.retention.attempt_receipt_days, 7);
        assert_eq!(config.retention.hook_payload_days, 7);
        assert!(config.destinations.reminders.is_none());
        assert!(config.destinations.hooks.is_empty());
        let policy = config.load_policy().expect("policy loads");
        assert_eq!(policy.scheduling.id, "standalone-exact-time");
    }

    #[test]
    fn production_requires_a_verified_package_while_loopback_accepts_authoring() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        write_policy(&package);
        let operator = write_operator(
            root.path(),
            operator_value(&package, "operator-controlled-upstream"),
        );
        assert!(matches!(
            RuntimeConfig::load(&operator),
            Err(RuntimeConfigError::ProductionPolicyPackageRequired)
        ));

        let manifest = PolicyPackageManifest::build(POLICY).unwrap();
        std::fs::write(
            package.join(SCHEDULING_PACKAGE_MANIFEST_FILE),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();
        let config = RuntimeConfig::load(&operator).expect("packaged production is accepted");
        assert_eq!(
            config.policy_package_digest().unwrap(),
            Some(manifest.policy_digest)
        );

        std::fs::write(
            package.join(AUTHORED_POLICY_FILE),
            POLICY.replace("30-minute", "31-minute"),
        )
        .unwrap();
        assert!(matches!(
            RuntimeConfig::load(&operator),
            Err(RuntimeConfigError::PolicyPackage(_))
        ));
    }

    #[test]
    fn explain_and_read_scopes_must_differ_and_retention_must_be_positive() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        write_policy(&package);
        for (patch, expected) in [
            (
                serde_json::json!({"explainScope": "scheduling-read"}),
                RuntimeConfigError::InvalidOidc,
            ),
            (
                serde_json::json!({"attemptReceiptDays": 0}),
                RuntimeConfigError::InvalidRetention,
            ),
            (
                serde_json::json!({"reminders": {"url": "not-a-url"}}),
                RuntimeConfigError::InvalidDestination,
            ),
        ] {
            let mut document = operator_value(&package, "development-loopback");
            if patch.get("attemptReceiptDays").is_some() {
                document["retention"] = patch;
            } else if patch.get("reminders").is_some() {
                document["destinations"] = patch;
            } else {
                document["authentication"]["oidc"]
                    .as_object_mut()
                    .unwrap()
                    .extend(
                        patch
                            .as_object()
                            .unwrap()
                            .iter()
                            .map(|(k, v)| (k.clone(), v.clone())),
                    );
            }
            let operator = write_operator(root.path(), document);
            let outcome = RuntimeConfig::load(&operator);
            assert!(
                matches!(&outcome, Err(error) if std::mem::discriminant(error) == std::mem::discriminant(&expected)),
                "expected {expected:?}, got {outcome:?}"
            );
        }
    }

    #[test]
    fn a_hook_policy_requires_and_accepts_its_deployment_binding() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        write_policy(&package);
        let hooked = format!(
            "{POLICY}hooks:\n  - id: appointment-observer\n    phase: after\n    trigger: appointment.confirmed\n    projection: []\n    handler:\n      kind: url\n      destinationId: appointment-events\n"
        );
        std::fs::write(package.join(AUTHORED_POLICY_FILE), hooked).unwrap();
        let mut document = operator_value(&package, "development-loopback");
        let operator = write_operator(root.path(), document.clone());
        assert!(matches!(
            RuntimeConfig::load(&operator),
            Err(RuntimeConfigError::HookDestinationInventoryMismatch)
        ));

        document["destinations"]["hooks"] = serde_json::json!({
            "appointment-events": {
                "url": "https://events.example.test/scheduling",
                "hmacSha256KeyRef": "secret:file/hook-key"
            }
        });
        let operator = write_operator(root.path(), document);
        let config = RuntimeConfig::load(&operator).expect("the hook destination is bound");
        assert!(config.destinations.hooks.contains_key("appointment-events"));
    }

    #[test]
    fn typed_parse_path_does_not_echo_the_rejected_value() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        write_policy(&package);
        let canary = "DO_NOT_DISCLOSE_RUNTIME_VALUE";
        let mut document = operator_value(&package, "development-loopback");
        document["database"]["testOnlyPlaintext"] = serde_json::json!(canary);
        // The refusal this pins exists only without the test feature: with
        // it, plaintext is the configuration the suite itself runs under.
        #[cfg(not(feature = "postgres-test"))]
        let operator = write_operator(root.path(), document);
        #[cfg(not(feature = "postgres-test"))]
        {
            let error = RuntimeConfig::load(&operator).unwrap_err();
            assert_eq!(error.path(), "database.testOnlyPlaintext");
            assert!(!error.to_string().contains(canary));
        }
    }

    #[test]
    fn a_runtime_document_refused_whole_is_reported_at_the_root() {
        let root = canonical_tempdir();
        let operator = root.path().join("runtime.yaml");
        let canary = "DO_NOT_DISCLOSE_RUNTIME_VALUE";
        std::fs::write(&operator, format!("{canary}\n")).unwrap();

        let error = RuntimeConfig::load(&operator).unwrap_err();
        let message = error.to_string();
        // A refusal the reader never attributed to a member belongs to the
        // document, and "." names nothing an operator can look up.
        assert_eq!(error.path(), "/");
        assert!(!message.contains(" at ."), "{message}");
        assert!(message.contains("must be a YAML mapping"), "{message}");
        assert!(!message.contains(canary), "{message}");
    }

    #[test]
    fn the_runtime_configuration_is_read_through_the_shared_loader() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        write_policy(&package);

        let error = RuntimeConfig::load("runtime.yaml").unwrap_err();
        assert!(matches!(
            &error,
            RuntimeConfigError::Load(load) if load.code() == "runtime_config.path"
        ));

        let mut document = operator_value(&package, "development-loopback");
        document["listener"].as_object_mut().unwrap().remove("bind");
        let error = RuntimeConfig::load(write_operator(root.path(), document)).unwrap_err();
        assert_eq!(error.path(), "listener");
        assert!(error.to_string().contains("bind"), "{error}");
    }

    #[test]
    fn a_removed_jwks_uri_names_its_replacement() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        write_policy(&package);
        let mut document = operator_value(&package, "development-loopback");
        document["authentication"]["oidc"]["jwksUri"] =
            serde_json::json!("https://identity.example.test/jwks");
        let error = RuntimeConfig::load(write_operator(root.path(), document)).unwrap_err();
        assert_eq!(error.path(), "authentication.oidc.jwksUri");
        assert!(
            error.to_string().contains("authentication.oidc.jwksSource"),
            "{error}"
        );

        let mut document = operator_value(&package, "development-loopback");
        document["authentication"]["oidc"]["jwksSource"] =
            serde_json::json!({"kind": "uri", "uri": "https://identity.example.test/jwks"});
        let config = RuntimeConfig::load(write_operator(root.path(), document)).unwrap();
        assert_eq!(
            config.authentication.oidc.provider.jwks_source.uri(),
            Some("https://identity.example.test/jwks")
        );
    }

    #[test]
    fn environment_expressions_substitute_values_but_never_secret_references() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        write_policy(&package);
        let mut document = operator_value(&package, "development-loopback");
        document["authentication"]["oidc"]["audience"] =
            serde_json::json!("${SCHEDULING_TEST_AUDIENCE:-urn:example:substituted}");
        let config = RuntimeConfig::load(write_operator(root.path(), document)).unwrap();
        assert_eq!(
            config.authentication.oidc.provider.audience,
            "urn:example:substituted"
        );

        let mut document = operator_value(&package, "development-loopback");
        document["database"]["runtimeUrlRef"] =
            serde_json::json!("${SCHEDULING_TEST_REFERENCE:-secret:env/RUNTIME}");
        let error = RuntimeConfig::load(write_operator(root.path(), document)).unwrap_err();
        assert!(matches!(
            &error,
            RuntimeConfigError::Load(load)
                if load.code() == "runtime_config.substitution_in_reference"
        ));
        assert_eq!(error.path(), "database.runtimeUrlRef");
    }

    #[test]
    fn an_authored_policy_carrying_an_environment_expression_is_refused() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        std::fs::create_dir_all(&package).unwrap();
        std::fs::write(
            package.join(AUTHORED_POLICY_FILE),
            POLICY.replace(
                "    because: test\nofferings:",
                "    because: ${OPENING_REASON}\nofferings:",
            ),
        )
        .unwrap();
        let operator = write_operator(
            root.path(),
            operator_value(&package, "development-loopback"),
        );
        let error = RuntimeConfig::load(&operator).unwrap_err();
        assert!(matches!(
            &error,
            RuntimeConfigError::PolicyEnvironmentExpression { field } if field == "openings.0.because"
        ));
        assert!(error.to_string().contains("runtime.yaml only"), "{error}");
    }

    #[test]
    fn a_malformed_authored_policy_is_a_parse_refusal() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        std::fs::create_dir_all(&package).unwrap();
        std::fs::write(
            package.join(AUTHORED_POLICY_FILE),
            format!("{POLICY}services: [unterminated\n"),
        )
        .unwrap();
        let operator = write_operator(
            root.path(),
            operator_value(&package, "development-loopback"),
        );
        let error = RuntimeConfig::load(&operator).unwrap_err();
        assert!(
            matches!(&error, RuntimeConfigError::PolicyParse { .. }),
            "{error}"
        );
    }

    #[test]
    fn a_pinned_package_digest_must_match_the_verified_package() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        write_policy(&package);
        let manifest = PolicyPackageManifest::build(POLICY).unwrap();
        std::fs::write(
            package.join(SCHEDULING_PACKAGE_MANIFEST_FILE),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let mut document = operator_value(&package, "operator-controlled-upstream");
        document["package"]["expectedDigest"] = serde_json::json!(manifest.policy_digest);
        RuntimeConfig::load(write_operator(root.path(), document)).expect("the pin matches");

        let mut document = operator_value(&package, "operator-controlled-upstream");
        document["package"]["expectedDigest"] =
            serde_json::json!(format!("sha256:{}", "0".repeat(64)));
        let error = RuntimeConfig::load(write_operator(root.path(), document)).unwrap_err();
        assert!(matches!(error, RuntimeConfigError::PackageDigest(_)));
        assert_eq!(error.path(), "package.expectedDigest");
        assert!(
            error.to_string().contains("update package.expectedDigest"),
            "{error}"
        );
    }

    #[test]
    fn a_refused_value_never_survives_the_clause_that_names_it() {
        // The value serde renders may hold the comma that ends the clause,
        // so the shape word is where the rendering opens, not the comma.
        assert_eq!(
            redact_refused_values(
                "invalid type: string \"secret:env/URL, and more\", expected u16 at line 3 column 5"
            ),
            "invalid type: string, expected u16 at line 3 column 5"
        );
        // A refusal naming a member rather than a value is carried whole: the
        // member name is what the operator has to correct.
        assert_eq!(
            redact_refused_values("unknown field `bnd`, expected `bind` at line 4 column 3"),
            "unknown field `bnd`, expected `bind` at line 4 column 3"
        );
    }

    #[test]
    fn a_runtime_document_the_reader_stops_on_names_the_line_and_column() {
        let root = canonical_tempdir();
        let operator = root.path().join("runtime.yaml");
        // A tab can never open an indented line, so the reader stops on it.
        std::fs::write(&operator, "apiVersion: v1\n\tkind: x\n").unwrap();

        let error = RuntimeConfig::load(&operator).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("line 2"), "{message}");
        assert!(message.contains("column 1"), "{message}");
    }

    #[test]
    fn a_rejected_runtime_member_names_the_cause_without_the_value() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        write_policy(&package);
        let canary = "DO_NOT_DISCLOSE_RUNTIME_VALUE";
        let mut document = operator_value(&package, "development-loopback");
        document["retention"]["attemptReceiptDays"] = serde_json::json!(canary);
        let operator = write_operator(root.path(), document);

        let error = RuntimeConfig::load(&operator).unwrap_err();
        let message = error.to_string();
        assert_eq!(error.path(), "retention.attemptReceiptDays");
        assert!(
            message.contains("retention.attemptReceiptDays"),
            "{message}"
        );
        assert!(message.contains("invalid type: string"), "{message}");
        assert!(message.contains("expected u16"), "{message}");
        assert!(!message.contains(canary), "{message}");
    }

    #[test]
    fn a_refused_authored_policy_names_the_member_and_the_cause() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        std::fs::create_dir_all(&package).unwrap();
        std::fs::write(
            package.join(AUTHORED_POLICY_FILE),
            "scheduling: {id: standalone-exact-time, version: one}\n",
        )
        .unwrap();
        let operator = write_operator(
            root.path(),
            operator_value(&package, "development-loopback"),
        );

        let error = RuntimeConfig::load(&operator).unwrap_err();
        let message = error.to_string();
        assert_eq!(error.path(), "package.root/scheduling.yaml");
        assert!(message.contains("scheduling.version"), "{message}");
        assert!(message.contains("invalid type: string"), "{message}");
        assert!(message.contains("line"), "{message}");
        assert!(message.contains("column"), "{message}");
    }

    // The package manifest and the policy it identifies are two documents
    // with two readers: the manifest is verified by the runtime at startup,
    // the policy is parsed by the authoring grammar. A reader that accepts
    // one must be able to refuse the other on its declared names alone.
    #[test]
    fn a_package_manifest_is_a_different_document_from_the_policy_it_identifies() {
        let manifest = PolicyPackageManifest::build(POLICY).expect("the policy is packaged");
        assert_ne!(manifest.api_version, SCHEDULING_POLICY_API_VERSION);
        assert_ne!(manifest.kind, SCHEDULING_POLICY_KIND);
        assert_eq!(
            manifest.api_version,
            SCHEDULING_PACKAGE_MANIFEST_API_VERSION
        );
        assert_eq!(manifest.kind, SCHEDULING_PACKAGE_MANIFEST_KIND);
    }

    // A deployment identity is only an identity if a document of another kind
    // cannot stand in for it. The manifest is verified against its own names,
    // so an authored policy's names never carry a package identity.
    #[test]
    fn a_manifest_wearing_the_authored_policy_names_is_refused() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        write_policy(&package);
        let manifest = PolicyPackageManifest::build(POLICY).expect("the policy is packaged");
        let mut document = serde_json::to_value(&manifest).unwrap();
        document["apiVersion"] = serde_json::json!(SCHEDULING_POLICY_API_VERSION);
        document["kind"] = serde_json::json!(SCHEDULING_POLICY_KIND);
        std::fs::write(
            package.join(SCHEDULING_PACKAGE_MANIFEST_FILE),
            serde_json::to_vec_pretty(&document).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            verify_policy_package(&package.join(AUTHORED_POLICY_FILE), POLICY),
            Err(PolicyPackageError::Invalid)
        ));
    }

    #[test]
    fn a_production_deployment_must_name_the_clients_it_admits() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        write_policy(&package);
        let manifest = PolicyPackageManifest::build(POLICY).unwrap();
        std::fs::write(
            package.join(SCHEDULING_PACKAGE_MANIFEST_FILE),
            serde_json::to_vec_pretty(&manifest).unwrap(),
        )
        .unwrap();

        let mut document = operator_value(&package, "operator-controlled-upstream");
        document["authentication"]["oidc"]
            .as_object_mut()
            .unwrap()
            .remove("allowedClients");
        let operator = write_operator(root.path(), document);
        assert!(
            matches!(
                RuntimeConfig::load(&operator),
                Err(RuntimeConfigError::InvalidOidc)
            ),
            "a production deployment with no allowedClients was accepted"
        );

        let operator = write_operator(
            root.path(),
            operator_value(&package, "operator-controlled-upstream"),
        );
        RuntimeConfig::load(&operator).expect("a named client list is accepted");

        // Development loopback keeps the convenience: it is not a deployment
        // an unrelated client can reach.
        let mut document = operator_value(&package, "development-loopback");
        document["authentication"]["oidc"]
            .as_object_mut()
            .unwrap()
            .remove("allowedClients");
        let operator = write_operator(root.path(), document);
        RuntimeConfig::load(&operator).expect("development loopback stays permissive");
    }

    #[test]
    fn a_declared_assertion_authority_binds_the_client_that_may_exchange_from_it() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        write_policy(&package);
        let mut document = operator_value(&package, "development-loopback");
        document["authentication"]["oidc"]["assertionIssuers"] = serde_json::json!({
            "scheduling-booking-agent": ["https://authority.example.test"]
        });
        let operator = write_operator(root.path(), document);
        let config = RuntimeConfig::load(&operator).expect("an assertion authority is declarable");
        assert_eq!(
            config.verifier_profile().assertion_issuers,
            BTreeMap::from([(
                "scheduling-booking-agent".to_owned(),
                vec!["https://authority.example.test".to_owned()]
            )]),
            "the declared assertion authorities never reached the verifier"
        );
    }

    #[test]
    fn an_assertion_issuer_map_outside_its_bounds_is_refused() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        write_policy(&package);
        let oversized_client = "c".repeat(MAX_ASSERTION_ISSUER_CLIENT_BYTES + 1);
        let oversized_issuer = format!("https://{}", "a".repeat(MAX_ASSERTION_ISSUER_BYTES));
        let too_many_clients: serde_json::Map<String, serde_json::Value> = (0
            ..=MAX_ASSERTION_ISSUER_CLIENTS)
            .map(|index| {
                (
                    format!("client-{index}"),
                    serde_json::json!(["https://a.test"]),
                )
            })
            .collect();
        let too_many_issuers: Vec<String> = (0..=MAX_ASSERTION_ISSUERS_PER_CLIENT)
            .map(|index| format!("https://authority-{index}.test"))
            .collect();
        for refused in [
            serde_json::json!({"": ["https://a.test"]}),
            serde_json::json!({oversized_client: ["https://a.test"]}),
            serde_json::json!({"client": [""]}),
            serde_json::json!({"client": [oversized_issuer]}),
            serde_json::json!({"client": ["https://a.test", "https://a.test"]}),
            serde_json::Value::Object(too_many_clients),
            serde_json::json!({"client": too_many_issuers}),
        ] {
            let mut document = operator_value(&package, "development-loopback");
            document["authentication"]["oidc"]["assertionIssuers"] = refused.clone();
            let operator = write_operator(root.path(), document);
            let error = RuntimeConfig::load(&operator).expect_err(&format!(
                "an assertion-issuer map outside its bounds was accepted: {refused}"
            ));
            assert!(
                matches!(error, RuntimeConfigError::Block(_)),
                "{refused}: {error:?}"
            );
            assert_eq!(error.path(), "authentication.oidc.assertionIssuers");
        }
    }

    #[test]
    fn the_oidc_issuer_and_clients_are_the_shared_blocks() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        write_policy(&package);

        let mut document = operator_value(&package, "development-loopback");
        document["authentication"]["oidc"]["issuer"] =
            serde_json::json!("http://identity.example.test");
        let operator = write_operator(root.path(), document);
        let error = RuntimeConfig::load(&operator).expect_err("a remote http issuer");
        assert_eq!(error.path(), "authentication.oidc.issuer");

        // The flattened blocks leave the enclosing block closed.
        let mut document = operator_value(&package, "development-loopback");
        document["authentication"]["oidc"]["issuerr"] =
            serde_json::json!("https://identity.example.test");
        let operator = write_operator(root.path(), document);
        let error = RuntimeConfig::load(&operator).expect_err("an unknown oidc member");
        assert!(error.to_string().contains("issuerr"), "{error}");
    }

    #[test]
    fn the_access_token_profile_admits_only_the_rfc_9068_pair() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        write_policy(&package);
        let operator = write_operator(
            root.path(),
            operator_value(&package, "development-loopback"),
        );
        let config = RuntimeConfig::load(&operator).expect("configuration is accepted");
        let profile = config.verifier_profile();
        assert!(
            is_access_token_typ_pair(&profile.allowed_typ),
            "the access-token profile is not the RFC 9068 pair: {:?}",
            profile.allowed_typ
        );
        assert!(
            !profile
                .allowed_typ
                .iter()
                .any(|value| value.eq_ignore_ascii_case("JWT")),
            "a plain JWT reaches the access-token profile: {:?}",
            profile.allowed_typ
        );
    }

    #[test]
    fn listener_requires_a_private_address_or_explicit_container_network() {
        let listener = |bind: &str, exposure, tls_termination| ListenerConfig {
            bind: bind.parse().unwrap(),
            tls_termination,
            network_exposure: exposure,
        };
        assert!(listener(
            "127.0.0.1:8105",
            ListenerNetworkExposure::PrivateAddress,
            TlsTermination::OperatorControlledUpstream,
        )
        .is_valid());
        assert!(!listener(
            "203.0.113.10:8105",
            ListenerNetworkExposure::ContainerPrivate,
            TlsTermination::OperatorControlledUpstream,
        )
        .is_valid());
        assert!(listener(
            "[::]:8105",
            ListenerNetworkExposure::ContainerPrivate,
            TlsTermination::OperatorControlledUpstream,
        )
        .is_valid());
        assert!(!listener(
            "10.20.30.40:8105",
            ListenerNetworkExposure::PrivateAddress,
            TlsTermination::DevelopmentLoopback,
        )
        .is_valid());

        // The runtime refuses the same listener at load.
        let root = canonical_tempdir();
        let package = root.path().join("package");
        write_policy(&package);
        let mut document = operator_value(&package, "development-loopback");
        document["listener"]["bind"] = serde_json::json!("10.20.30.40:8105");
        let operator = write_operator(root.path(), document);
        assert!(matches!(
            RuntimeConfig::load(&operator),
            Err(RuntimeConfigError::InvalidListener)
        ));
    }

    /// The runtime's static JWKS arm hands the resolved document to the
    /// shared parser and refuses a key set it cannot trust before any
    /// verifier exists: a symmetric key, an unnamed key, two keys sharing a
    /// name, or no key at all.
    #[cfg(unix)]
    #[tokio::test]
    async fn static_jwks_requires_unique_named_asymmetric_keys() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = canonical_tempdir();
        let package = root.path().join("package");
        write_policy(&package);
        let secrets_root = root.path().join("secrets");
        std::fs::create_dir(&secrets_root).unwrap();
        let mut document = operator_value(&package, "development-loopback");
        document["authentication"]["oidc"]["jwksSource"] =
            serde_json::json!({"kind": "static", "documentRef": "secret:file/jwks.json"});
        let config = RuntimeConfig::load(write_operator(root.path(), document)).unwrap();
        let secrets = config.secret_providers.resolver().unwrap();
        let jwks = secrets_root.join("jwks.json");

        let write_jwks = |bytes: &[u8]| {
            std::fs::write(&jwks, bytes).unwrap();
            std::fs::set_permissions(&jwks, std::fs::Permissions::from_mode(0o600)).unwrap();
        };

        write_jwks(br#"{"keys":[{"kty":"RSA","kid":"one","n":"AQAB","e":"AQAB"}]}"#);
        config
            .oidc_verifier(&secrets)
            .await
            .expect("one named asymmetric key is accepted");

        for (case, invalid) in [
            ("symmetric", br#"{"keys":[{"kty":"oct","kid":"one","k":"AA"}]}"#.as_slice()),
            ("unnamed", br#"{"keys":[{"kty":"RSA","n":"AQAB","e":"AQAB"}]}"#),
            (
                "duplicate name",
                br#"{"keys":[{"kty":"RSA","kid":"one","n":"AQAB","e":"AQAB"},{"kty":"RSA","kid":"one","n":"AQAB","e":"AQAB"}]}"#,
            ),
            ("empty", br#"{"keys":[]}"#),
        ] {
            write_jwks(invalid);
            let error = config
                .oidc_verifier(&secrets)
                .await
                .map(|_| ())
                .expect_err(case);
            assert!(
                matches!(error, RuntimeConfigError::Oidc),
                "{case}: {error}"
            );
            assert_eq!(error.path(), "authentication.oidc", "{case}");
        }
    }
}
