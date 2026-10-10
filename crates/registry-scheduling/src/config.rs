// SPDX-License-Identifier: Apache-2.0

//! The operator runtime configuration document and the package it
//! verifies.

use std::collections::{BTreeMap, BTreeSet};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::Duration;

use jsonwebtoken::Algorithm;
use registry_platform_audit::{
    AuditDestination, AuditDestinationError, AuditDestinationKind, MAX_AUDIT_RETAIN_DAYS,
    MIN_AUDIT_ROTATE_BYTES,
};
pub(crate) use registry_platform_config::describe_secret_failure;
use registry_platform_config::package::is_envelope_file;
use registry_platform_config::{
    sha256_uri, ConfigBlockError, ConfigBlockErrorKind, PackageDigestMismatch, PackageError,
    PackageErrorKind, PackageLimits, RemovedKey, RuntimeConfigLoader, RuntimeEnvelope,
    RuntimeFileCheck, SecretReference, SecretResolver, VerifiedPackage, DEFAULT_STAND_IN,
    REMOVED_OIDC_JWKS_SOURCE_KIND, REMOVED_OIDC_JWKS_URI,
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
use registry_platform_yaml::{
    escape_pointer_segment, Diagnostic, Invalid, LocalId, Report, RetiredApiVersion,
};
use registry_scheduling_core::{
    bounded_u32, ObserverHandler, SchedulingPolicy, AUTHORED_POLICY_FILE,
    RETIRED_SCHEDULING_RUNTIME_API_VERSION, SCHEDULING_RUNTIME_API_VERSION,
    SCHEDULING_RUNTIME_KIND,
};
use serde::{Deserialize, Deserializer};
use thiserror::Error;

const MAXIMUM_POLICY_FILE_BYTES: usize = 1024 * 1024;

/// The command that writes a Scheduling package, named by every package
/// refusal.
pub const PACKAGE_COMMAND: &str = "schedulingctl package";

/// The manifest file an earlier `schedulingctl package` wrote beside the
/// policy. A package root that still holds it is refused with the command
/// that rebuilds the package.
pub const RETIRED_PACKAGE_MANIFEST_FILE: &str = "scheduling.package.json";

/// The default number of days a stored idempotency receipt is replayable
/// before the retention sweep erases it. The default is a floor, not a
/// recommendation: a jurisdiction's retention schedule approves the deployed
/// value, and the deployed value is what the audit entries record.
pub const DEFAULT_ATTEMPT_RECEIPT_RETENTION_DAYS: u32 = 7;

/// The longest a stored idempotency receipt may stay replayable, in days.
pub const MAX_ATTEMPT_RECEIPT_RETENTION_DAYS: u32 = 65_535;

/// The longest a canonical hook envelope may be retained for retry and
/// dead-letter inspection, in days.
pub const MAX_HOOK_PAYLOAD_RETENTION_DAYS: u32 = 30;

/// The most hook destinations one deployment may bind.
pub const MAX_HOOK_DESTINATIONS: usize = 128;

/// The shortest one hook delivery attempt may be bounded to, in milliseconds.
pub const MIN_HOOK_ATTEMPT_TIMEOUT_MILLISECONDS: u32 = 100;

/// The longest one hook delivery attempt may be bounded to, in milliseconds.
pub const MAX_HOOK_ATTEMPT_TIMEOUT_MILLISECONDS: u32 = 10_000;

/// The most delivery attempts a hook destination may allow one event.
pub const MAX_HOOK_ATTEMPTS: u8 = 20;

/// The largest `audit.rotateBytes` the shared audit writer accepts.
const MAXIMUM_AUDIT_ROTATE_BYTES: u64 = u32::MAX as u64;

/// The envelope every Scheduling runtime configuration carries.
pub const SCHEDULING_RUNTIME_ENVELOPE: RuntimeEnvelope = RuntimeEnvelope {
    api_version: SCHEDULING_RUNTIME_API_VERSION,
    kind: SCHEDULING_RUNTIME_KIND,
};

/// Keys an earlier Scheduling runtime configuration accepted, each refused
/// with the key that replaced it.
pub const SCHEDULING_REMOVED_KEYS: &[RemovedKey] = &[
    REMOVED_OIDC_JWKS_URI,
    REMOVED_OIDC_JWKS_SOURCE_KIND,
    RemovedKey {
        path: "audit.retainDays",
        replacement: "Rename audit.retainDays to audit.retentionDays",
    },
    RemovedKey {
        path: "retention.attemptReceiptDays",
        replacement: "Rename retention.attemptReceiptDays to retention.attemptReceiptRetentionDays",
    },
    RemovedKey {
        path: "retention.hookPayloadDays",
        replacement: "Rename retention.hookPayloadDays to retention.hookPayloadRetentionDays",
    },
];

/// The apiVersions an earlier Scheduling runtime configuration carried, each
/// refused with the one that replaced it.
pub const SCHEDULING_RETIRED_RUNTIME_API_VERSIONS: &[RetiredApiVersion<'static>] =
    &[RetiredApiVersion {
        api_version: RETIRED_SCHEDULING_RUNTIME_API_VERSION,
        replacement: "Write apiVersion: id.registrystack.org/formats/scheduling/runtime/v1alpha1.",
    }];

/// The operator runtime configuration document.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeConfig {
    pub api_version: String,
    pub kind: String,
    /// The logical identity of the database this deployment owns. The first
    /// `schedulingctl apply` records it; every later apply and every startup
    /// refuses a database that recorded another.
    // Required. Optional here only so that a missing block is refused with a
    // diagnostic naming the key to add; the generated schema lists it as
    // required.
    #[cfg_attr(feature = "schema", schemars(required, with = "IdentityConfig"))]
    pub identity: Option<IdentityConfig>,
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

/// The longest `identity.databaseId` accepted, in bytes.
pub const MAX_DATABASE_ID_BYTES: usize = 256;

/// The `identity.databaseId` grammar as a JSON Schema pattern: no control
/// character, and no leading or trailing Unicode whitespace. The schema's
/// `maxLength` counts characters, so the byte bound
/// [`MAX_DATABASE_ID_BYTES`] is enforced only when the document is loaded.
#[cfg(feature = "schema")]
const DATABASE_ID_PATTERN: &str = r"^[^\u0000-\u001f\u007f-\u009f \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000](?:[^\u0000-\u001f\u007f-\u009f]*[^\u0000-\u001f\u007f-\u009f \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000])?$";

/// The deployment identity block.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityConfig {
    /// An operator-chosen logical id for the database, for example
    /// `scheduling-production`. It is never derived from a URL or a
    /// PostgreSQL database name. It is at most 256 UTF-8 bytes, carries no
    /// control character, and has no leading or trailing whitespace.
    #[cfg_attr(
        feature = "schema",
        schemars(length(min = 1, max = MAX_DATABASE_ID_BYTES), regex(pattern = DATABASE_ID_PATTERN))
    )]
    pub database_id: String,
}

fn valid_database_id(value: &str) -> bool {
    !value.trim().is_empty()
        && value.trim() == value
        && value.len() <= MAX_DATABASE_ID_BYTES
        && !value.chars().any(char::is_control)
}

/// A secret reference, `secret:env/NAME` or `secret:file/name` (CFG-SEC-1),
/// kept as written. The reader refuses any other spelling at its position
/// without repeating it.
fn secret_reference<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    SecretReference::deserialize(deserializer).map(|reference| reference.as_str().to_owned())
}

/// An optional member holding a secret reference; absent reads as `None`
/// through `serde(default)`.
fn optional_secret_reference<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    secret_reference(deserializer).map(Some)
}

/// The policy and package identity produced by one verified package load.
#[derive(Clone, Debug)]
pub struct LoadedSchedulingPolicy {
    pub policy: SchedulingPolicy,
    pub package_digest: String,
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
    #[serde(rename(deserialize = "registry-platform-yaml/shared-block/oidc-issuer"))]
    #[cfg_attr(feature = "schema", schemars(flatten))]
    pub provider: OidcIssuerConfig,
    /// The clients admitted and the assertion authorities each may exchange
    /// a subject token from. A deployment that performs no token exchange
    /// leaves `assertionIssuers` empty; once a client is listed, an assertion
    /// minted by an unrelated authority the issuer happens to federate cannot
    /// become a booking credential here.
    #[serde(rename(deserialize = "registry-platform-yaml/shared-block/oidc-clients"))]
    #[cfg_attr(feature = "schema", schemars(flatten))]
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
    /// The secret keying the audit journal's hashes, `hashKeyRef`.
    #[serde(rename(deserialize = "registry-platform-yaml/shared-block/audit-key"))]
    #[cfg_attr(feature = "schema", schemars(flatten))]
    pub key: AuditKeyConfig,
    /// Where audit entries go: a rotated `file` (the default) or `stdout`.
    #[serde(default)]
    pub destination: AuditDestinationKind,
    /// The active audit file. Required for, and only allowed with, `file`.
    #[serde(default)]
    pub path: Option<PathBuf>,
    /// Rotate the active file once it reaches this many bytes. Only allowed
    /// with `file`; omitted, the file rotates at 100 MiB.
    #[serde(
        default,
        deserialize_with = "registry_scheduling_core::optional_bounded_u64::<_, MIN_AUDIT_ROTATE_BYTES, MAXIMUM_AUDIT_ROTATE_BYTES>"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(range(min = MIN_AUDIT_ROTATE_BYTES, max = MAXIMUM_AUDIT_ROTATE_BYTES))
    )]
    pub rotate_bytes: Option<u64>,
    /// Delete rotated files older than this many days. Only allowed with
    /// `file`; omitted, rotated files are kept 90 days.
    #[serde(
        default,
        deserialize_with = "registry_scheduling_core::optional_bounded_u32::<_, 1, MAX_AUDIT_RETAIN_DAYS>"
    )]
    #[cfg_attr(feature = "schema", schemars(range(min = 1, max = MAX_AUDIT_RETAIN_DAYS)))]
    pub retention_days: Option<u32>,
}

impl AuditConfig {
    /// The destination this configuration names, with the shared defaults.
    pub fn destination(&self) -> Result<AuditDestination, RuntimeConfigError> {
        AuditDestination::from_settings(
            self.destination,
            self.path.clone(),
            self.rotate_bytes,
            self.retention_days,
        )
        .map_err(|error| match error {
            AuditDestinationError::RelativePath => {
                RuntimeConfigError::RelativeOperatedPath("audit.path")
            }
            error => RuntimeConfigError::InvalidAuditDestination(error),
        })
    }
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
    /// At most 128 are bound, each keyed by a local identifier.
    #[serde(default, deserialize_with = "hook_destinations")]
    #[cfg_attr(feature = "schema", schemars(schema_with = "hook_destinations_schema"))]
    pub hooks: BTreeMap<String, HookDestinationConfig>,
}

/// The hook destination map: at most [`MAX_HOOK_DESTINATIONS`] bindings,
/// each keyed by a local identifier (CFG-ID-1).
fn hook_destinations<'de, D>(
    deserializer: D,
) -> Result<BTreeMap<String, HookDestinationConfig>, D::Error>
where
    D: Deserializer<'de>,
{
    let hooks = BTreeMap::<LocalId, HookDestinationConfig>::deserialize(deserializer)?;
    if hooks.len() > MAX_HOOK_DESTINATIONS {
        return Err(Invalid::expected(
            "at most 128 hook destinations",
            "Remove hook destinations until at most 128 remain.",
        )
        .into_error());
    }
    Ok(hooks
        .into_iter()
        .map(|(id, destination)| (id.into_string(), destination))
        .collect())
}

#[cfg(feature = "schema")]
fn hook_destinations_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
    schemars::json_schema!({
        "type": "object",
        "maxProperties": MAX_HOOK_DESTINATIONS,
        "propertyNames": generator.subschema_for::<LocalId>(),
        "additionalProperties": generator.subschema_for::<HookDestinationConfig>()
    })
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReminderDestinationConfig {
    /// An https URL, or http on 127.0.0.1, localhost, or [::1], without a
    /// query or fragment.
    #[serde(deserialize_with = "registry_scheduling_core::url")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Url"))]
    pub url: String,
    #[serde(default, deserialize_with = "optional_secret_reference")]
    #[cfg_attr(feature = "schema", schemars(with = "Option<SecretReference>"))]
    pub bearer_token_ref: Option<String>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HookDestinationConfig {
    /// An https URL, or http on 127.0.0.1, localhost, or [::1], without a
    /// query or fragment.
    #[serde(deserialize_with = "registry_scheduling_core::url")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Url"))]
    pub url: String,
    #[serde(deserialize_with = "secret_reference")]
    #[cfg_attr(feature = "schema", schemars(with = "SecretReference"))]
    pub hmac_sha256_key_ref: String,
    /// How long one delivery attempt may take, from 100 through 10000
    /// milliseconds.
    #[serde(
        default = "default_hook_attempt_timeout_milliseconds",
        deserialize_with = "bounded_u32::<_, MIN_HOOK_ATTEMPT_TIMEOUT_MILLISECONDS, MAX_HOOK_ATTEMPT_TIMEOUT_MILLISECONDS>"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(range(
            min = MIN_HOOK_ATTEMPT_TIMEOUT_MILLISECONDS,
            max = MAX_HOOK_ATTEMPT_TIMEOUT_MILLISECONDS
        ))
    )]
    pub attempt_timeout_milliseconds: u32,
    /// How many delivery attempts one event gets, from 1 through 20.
    #[serde(
        default = "default_hook_maximum_attempts",
        deserialize_with = "hook_attempts"
    )]
    #[cfg_attr(feature = "schema", schemars(range(min = 1, max = MAX_HOOK_ATTEMPTS)))]
    pub maximum_attempts: u8,
}

/// A hook destination's attempt count, from 1 through [`MAX_HOOK_ATTEMPTS`].
fn hook_attempts<'de, D>(deserializer: D) -> Result<u8, D::Error>
where
    D: Deserializer<'de>,
{
    const MAX: u32 = MAX_HOOK_ATTEMPTS as u32;
    let attempts = bounded_u32::<D, 1, MAX>(deserializer)?;
    u8::try_from(attempts).map_err(|_| Invalid::out_of_range(1, MAX).into_error())
}

impl HookDestinationConfig {
    /// Whether the attempt timeout and attempt count stay inside the
    /// delivery budget: the bound the reader enforces at load and hook
    /// activation enforces again before it binds the destination.
    pub(crate) fn within_delivery_budget(&self) -> bool {
        (MIN_HOOK_ATTEMPT_TIMEOUT_MILLISECONDS..=MAX_HOOK_ATTEMPT_TIMEOUT_MILLISECONDS)
            .contains(&self.attempt_timeout_milliseconds)
            && (1..=MAX_HOOK_ATTEMPTS).contains(&self.maximum_attempts)
    }
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
    /// How long a stored idempotency receipt stays replayable, from one
    /// through 65535 days.
    #[serde(
        default = "default_attempt_receipt_retention_days",
        deserialize_with = "bounded_u32::<_, 1, MAX_ATTEMPT_RECEIPT_RETENTION_DAYS>"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(range(min = 1, max = MAX_ATTEMPT_RECEIPT_RETENTION_DAYS))
    )]
    pub attempt_receipt_retention_days: u32,
    /// Lifetime of canonical hook envelopes retained for retry and
    /// dead-letter inspection, from one through thirty days.
    #[serde(
        default = "default_hook_payload_retention_days",
        deserialize_with = "bounded_u32::<_, 1, MAX_HOOK_PAYLOAD_RETENTION_DAYS>"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(range(min = 1, max = MAX_HOOK_PAYLOAD_RETENTION_DAYS))
    )]
    pub hook_payload_retention_days: u32,
}

impl Default for RetentionConfig {
    fn default() -> Self {
        Self {
            attempt_receipt_retention_days: DEFAULT_ATTEMPT_RECEIPT_RETENTION_DAYS,
            hook_payload_retention_days: default_hook_payload_retention_days(),
        }
    }
}

const fn default_attempt_receipt_retention_days() -> u32 {
    DEFAULT_ATTEMPT_RECEIPT_RETENTION_DAYS
}

const fn default_hook_payload_retention_days() -> u32 {
    7
}

/// The bounds a Scheduling package holds to: each file at most one MiB.
#[must_use]
pub fn package_limits() -> PackageLimits {
    PackageLimits {
        max_file_bytes: MAXIMUM_POLICY_FILE_BYTES as u64,
        ..PackageLimits::default()
    }
}

/// Verify the package at `package.root`: its `SHA256SUMS`, the
/// `package.expectedDigest` pin, and that it holds exactly `scheduling.yaml`.
/// Every listener mode serves a package: a directory without `SHA256SUMS` is
/// refused with the packaging command, whether or not a digest is pinned.
pub fn verify_scheduling_package(
    package: &PackageConfig,
) -> Result<VerifiedPackage, RuntimeConfigError> {
    if std::fs::symlink_metadata(package.root.join(RETIRED_PACKAGE_MANIFEST_FILE)).is_ok() {
        return Err(RuntimeConfigError::RetiredPackageManifest);
    }
    let verified = package
        .verify_package(&package_limits(), PACKAGE_COMMAND)
        .map_err(|error| match error.kind() {
            PackageErrorKind::DigestMismatch(mismatch) => {
                RuntimeConfigError::PackageDigest(mismatch.clone())
            }
            _ => RuntimeConfigError::Package(error),
        })?;
    let extra = verified
        .files()
        .filter(|path| !is_envelope_file(path) && *path != AUTHORED_POLICY_FILE)
        .map(ToOwned::to_owned)
        .collect::<Vec<_>>();
    if verified.file_digest(AUTHORED_POLICY_FILE).is_none() || !extra.is_empty() {
        return Err(RuntimeConfigError::PackageContents { extra });
    }
    Ok(verified)
}

impl RuntimeConfig {
    /// Load and validate the operator document, reading the authored policy
    /// beside it. The bytes never re-enter a parser after startup.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, RuntimeConfigError> {
        let loaded = Self::loader().load::<Self>(path.as_ref())?;
        loaded.config.check()?;
        Ok(loaded.config)
    }

    /// The shared runtime configuration loader under Scheduling's envelope,
    /// removed keys, and retired apiVersions.
    #[must_use]
    pub const fn loader() -> RuntimeConfigLoader {
        RuntimeConfigLoader::new(SCHEDULING_RUNTIME_ENVELOPE)
            .removed_keys(SCHEDULING_REMOVED_KEYS)
            .retired_api_versions(SCHEDULING_RETIRED_RUNTIME_API_VERSIONS)
    }

    #[must_use]
    pub fn policy_path(&self) -> PathBuf {
        self.package.root.join(AUTHORED_POLICY_FILE)
    }

    /// Read and validate the packaged policy this deployment runs.
    pub fn load_policy(&self) -> Result<LoadedSchedulingPolicy, RuntimeConfigError> {
        let package = verify_scheduling_package(&self.package)?;
        let path = self.policy_path();
        let bytes = read_policy(&path)?;
        // The policy is served only when the bytes just read are the bytes
        // the package lists; the digest the runtime publishes is the
        // package's.
        if package.file_digest(AUTHORED_POLICY_FILE).as_deref() != Some(sha256_uri(&bytes).as_str())
        {
            return Err(RuntimeConfigError::PolicyChanged);
        }
        let policy = SchedulingPolicy::read(&path.display().to_string(), &bytes)
            .map_err(RuntimeConfigError::Policy)?
            .value;
        Ok(LoadedSchedulingPolicy {
            policy,
            package_digest: package.digest().to_owned(),
        })
    }

    /// The configured `identity.databaseId`. [`RuntimeConfig::check`] has
    /// refused a document without one.
    #[must_use]
    pub fn database_id(&self) -> &str {
        self.identity
            .as_ref()
            .map_or("", |identity| identity.database_id.as_str())
    }

    /// Return the digest of the verified package this deployment serves.
    pub fn package_digest(&self) -> Result<String, RuntimeConfigError> {
        Ok(verify_scheduling_package(&self.package)?
            .digest()
            .to_owned())
    }

    /// Refuse the first rule this file breaks on its own, then read the
    /// packaged policy and refuse the first rule the file breaks against it.
    pub fn check(&self) -> Result<(), RuntimeConfigError> {
        first(self.findings(None))?;
        let policy = self.load_policy()?.policy;
        self.check_against_policy(&policy)
    }

    /// Refuse the first rule this file breaks against `policy`, the policy
    /// its package holds.
    pub fn check_against_policy(
        &self,
        policy: &SchedulingPolicy,
    ) -> Result<(), RuntimeConfigError> {
        let mut findings = Vec::new();
        for rule in POLICY_RULES {
            rule(self, policy, &mut findings);
        }
        first(findings)
    }

    /// Every rule this file breaks, in the order startup applies them. The
    /// rules about the policy the file binds run when `policy` is given.
    /// Each finding names the member it concerns and never a configured
    /// value.
    #[must_use]
    pub fn findings(&self, policy: Option<&SchedulingPolicy>) -> Vec<RuntimeConfigError> {
        let mut findings = Vec::new();
        for rule in FILE_RULES {
            rule(self, &mut findings);
        }
        if let Some(policy) = policy {
            for rule in POLICY_RULES {
                rule(self, policy, &mut findings);
            }
        }
        findings
    }

    fn check_envelope(&self, findings: &mut Vec<RuntimeConfigError>) {
        if self.api_version != SCHEDULING_RUNTIME_API_VERSION {
            findings.push(RuntimeConfigError::InvalidApiVersion);
        }
        if self.kind != SCHEDULING_RUNTIME_KIND {
            findings.push(RuntimeConfigError::InvalidKind);
        }
    }

    fn check_identity(&self, findings: &mut Vec<RuntimeConfigError>) {
        match &self.identity {
            None => findings.push(RuntimeConfigError::MissingIdentity),
            Some(identity) if !valid_database_id(&identity.database_id) => {
                findings.push(RuntimeConfigError::InvalidDatabaseId);
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

    fn check_secret_references(&self, findings: &mut Vec<RuntimeConfigError>) {
        // With no provider enabled every reference would be refused; the
        // provider rule reports that once.
        if self.secret_providers.check().is_err() {
            return;
        }
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
        if let Some(reference) = self
            .destinations
            .reminders
            .as_ref()
            .and_then(|reminders| reminders.bearer_token_ref.as_deref())
        {
            references.push((
                "destinations.reminders.bearerTokenRef".to_owned(),
                reference,
            ));
        }
        for (field, raw) in references {
            if let Err(error) = self.secret_providers.check_reference(&field, raw) {
                findings.push(error.into());
            }
        }
        for (id, destination) in &self.destinations.hooks {
            self.check_binding_reference(
                findings,
                &["destinations", "hooks", id, "hmacSha256KeyRef"],
                &destination.hmac_sha256_key_ref,
            );
        }
    }

    /// Check one secret reference of a member under a map keyed by an id the
    /// operator chose, located structurally.
    fn check_binding_reference(
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
        // `allowedClients: unrestricted` admits every client the issuer
        // verifies, so the deployment would accept a token minted for an
        // unrelated application in the same realm. A development file is
        // copied toward production, so every file lists the clients it admits
        // (CFG-EMPTY-2): the reader refuses an omitted member and `[]`, and
        // `unrestricted` is refused here in every mode.
        if oidc.clients.allowed_clients.is_empty() {
            findings.push(RuntimeConfigError::AllowedClientsRequired);
        }
        for (path, value) in [
            ("authentication.oidc.scopeClaim", &oidc.scope_claim),
            ("authentication.oidc.readsScope", &oidc.reads_scope),
            ("authentication.oidc.explainScope", &oidc.explain_scope),
        ] {
            if value.is_empty() {
                findings.push(RuntimeConfigError::InvalidOidcClaim {
                    path,
                    reason: "must not be empty",
                });
            }
        }
        // The explain path discloses why a slot is refused, so a token that
        // may only read availability must not also open it.
        if !oidc.explain_scope.is_empty() && oidc.explain_scope == oidc.reads_scope {
            findings.push(RuntimeConfigError::InvalidOidcClaim {
                path: "authentication.oidc.explainScope",
                reason: "must differ from authentication.oidc.readsScope",
            });
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

    fn check_destinations(&self, findings: &mut Vec<RuntimeConfigError>) {
        if let Some(reminders) = &self.destinations.reminders {
            if !valid_destination_url(&reminders.url) {
                findings.push(RuntimeConfigError::invalid_destination_url(&[
                    "destinations",
                    "reminders",
                    "url",
                ]));
            }
        }
        for (id, destination) in &self.destinations.hooks {
            if !valid_destination_url(&destination.url) {
                findings.push(RuntimeConfigError::invalid_destination_url(&[
                    "destinations",
                    "hooks",
                    id,
                    "url",
                ]));
            }
        }
    }

    /// Every URL hook destination the policy names is bound under
    /// `destinations.hooks`.
    fn check_hook_inventory(
        &self,
        policy: &SchedulingPolicy,
        findings: &mut Vec<RuntimeConfigError>,
    ) {
        let declared = policy
            .hooks
            .iter()
            .map(|hook| {
                let ObserverHandler::Url { destination_id } = &hook.handler;
                destination_id.as_str()
            })
            .collect::<BTreeSet<_>>();
        if declared
            .iter()
            .any(|destination| !self.destinations.hooks.contains_key(*destination))
        {
            findings.push(RuntimeConfigError::HookDestinationInventoryMismatch);
        }
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

/// A rule a runtime file must satisfy on its own; it records every finding.
type FileRule = fn(&RuntimeConfig, &mut Vec<RuntimeConfigError>);
/// A rule a runtime file must satisfy against the policy it binds.
type PolicyRule = fn(&RuntimeConfig, &SchedulingPolicy, &mut Vec<RuntimeConfigError>);

/// The rules a runtime file satisfies on its own, in the order startup
/// applies them.
const FILE_RULES: &[FileRule] = &[
    RuntimeConfig::check_envelope,
    RuntimeConfig::check_identity,
    RuntimeConfig::check_package_block,
    RuntimeConfig::check_secret_providers,
    RuntimeConfig::check_audit,
    RuntimeConfig::check_secret_references,
    RuntimeConfig::check_listeners,
    RuntimeConfig::check_oidc,
    RuntimeConfig::check_database,
    RuntimeConfig::check_destinations,
];

/// The rules a runtime file satisfies against the policy it binds.
const POLICY_RULES: &[PolicyRule] = &[RuntimeConfig::check_hook_inventory];

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

/// Read the packaged policy, at most one byte past its bound: a longer file
/// cannot match the digest its package lists.
fn read_policy(path: &Path) -> Result<Vec<u8>, RuntimeConfigError> {
    let file = std::fs::File::open(path).map_err(|_| RuntimeConfigError::PolicyUnreadable)?;
    let mut bytes = Vec::new();
    file.take(MAXIMUM_POLICY_FILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| RuntimeConfigError::PolicyUnreadable)?;
    Ok(bytes)
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

/// A logical hook destination id is a lowercase ASCII letter followed by up
/// to 63 lowercase letters, digits, `-`, or `_`. Hook compilation and
/// activation decide ids with this one check; the runtime configuration
/// reads them as local identifiers, the same grammar.
pub(crate) fn valid_logical_destination_id(value: &str) -> bool {
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

/// What an offline check of one runtime file found (CFG-CHECK-1).
#[derive(Debug, Default)]
pub struct RuntimeCheck {
    /// Every finding, each naming the file as the path was given and each
    /// positioned at the member it concerns.
    pub diagnostics: Vec<Diagnostic>,
    /// The file could not be read at all, as opposed to read and refused.
    pub unavailable: bool,
}

/// Check the runtime file at the absolute `path` as `scheduling` reads it,
/// with no package, database, network, or secret material, and report every
/// rule it breaks. The rules about the policy the file binds run against
/// `policy` when one is given.
///
/// With `substitute` set, `${NAME}` expressions are filled from the process
/// environment and every value is checked. Without it, each expression is
/// checked by syntax and position only, and a rule that reads its value is
/// left out.
#[must_use]
pub fn check_runtime(
    path: &Path,
    policy: Option<&SchedulingPolicy>,
    substitute: bool,
) -> RuntimeCheck {
    let check =
        RuntimeConfig::loader().check_offline::<RuntimeConfig>(path, substitute, stand_in_for);
    let mut diagnostics = check.diagnostics.clone();
    if let Some(loaded) = &check.loaded {
        diagnostics.extend(
            loaded
                .config
                .findings(policy)
                .iter()
                .filter(|finding| !reads_deferred_value(&check, finding))
                .map(|finding| positioned(&check, finding)),
        );
    }
    in_file_order(&mut diagnostics);
    RuntimeCheck {
        diagnostics,
        unavailable: check.unavailable,
    }
}

/// The report `scheduling` prints when it refuses the runtime file at
/// `path` with `error`: the shared loader's diagnostics, the packaged
/// policy's own report, or every rule the file breaks, each at its position.
/// A refusal of the package or of a dependency is one diagnostic at the member
/// that names it. `None` when the file itself cannot be read.
#[must_use]
pub fn startup_report(path: &Path, error: &RuntimeConfigError) -> Option<Report> {
    match error {
        RuntimeConfigError::Load(error) => return Some(Report::new(error.diagnostics().to_vec())),
        RuntimeConfigError::Policy(report) => return Some(report.clone()),
        _ => {}
    }
    let check = RuntimeConfig::loader().check_offline::<RuntimeConfig>(path, true, stand_in_for);
    if !error.in_file() {
        check.loaded.as_ref()?;
        return Some(Report::new(vec![positioned(&check, error)]));
    }
    let config = &check.loaded.as_ref()?.config;
    let policy = config.load_policy().ok();
    let mut diagnostics: Vec<Diagnostic> = config
        .findings(policy.as_ref().map(|loaded| &loaded.policy))
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
        SCHEDULING_RUNTIME_KIND,
        finding.code(),
        &pointer,
        finding.to_string(),
        finding.suggested_action(),
    );
    let mut located = pointer.as_str();
    while diagnostic
        .source
        .as_ref()
        .is_some_and(|source| source.line.is_none())
        && !located.is_empty()
    {
        located = &located[..located.rfind('/').unwrap_or(0)];
        diagnostic.source = check
            .error_at(SCHEDULING_RUNTIME_KIND, "", located, "", "")
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
    let reads: &[&str] = match finding {
        RuntimeConfigError::InvalidListener => &["/listener"],
        RuntimeConfigError::Block(error) if error.field().starts_with("authentication.oidc.") => {
            &["/listener/tlsTermination"]
        }
        RuntimeConfigError::InvalidOidcClaim { .. } => &[
            "/authentication/oidc/readsScope",
            "/authentication/oidc/explainScope",
        ],
        RuntimeConfigError::RelativeOperatedPath(_)
        | RuntimeConfigError::InvalidAuditDestination(_) => &["/audit"],
        RuntimeConfigError::HookDestinationInventoryMismatch => &["/destinations/hooks"],
        _ => &[],
    };
    check.defers_within(&finding.pointer())
        || reads.iter().any(|pointer| check.defers_within(pointer))
}

/// A value for an expression the offline check does not substitute, chosen
/// so the member it fills decodes and passes the rules about its value.
fn stand_in_for(pointer: &str) -> &'static str {
    let segments: Vec<&str> = pointer.split('/').skip(1).collect();
    match segments.as_slice() {
        ["listener", "bind"] => "127.0.0.1:8100",
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
        | ["destinations", "reminders", "url"]
        | ["destinations", "hooks", _, "url"] => "https://deferred.invalid",
        _ => DEFAULT_STAND_IN,
    }
}

#[derive(Debug, Error)]
pub enum RuntimeConfigError {
    #[error(transparent)]
    Load(#[from] registry_platform_config::RuntimeConfigError),
    #[error(transparent)]
    Block(#[from] ConfigBlockError),
    /// A secret reference of a member under a map keyed by an operator-chosen
    /// id, located structurally.
    #[error("{error}")]
    BindingSecret {
        pointer: String,
        #[source]
        error: ConfigBlockError,
    },
    #[error(
        "unsupported Scheduling runtime apiVersion; expected id.registrystack.org/formats/scheduling/runtime/v1alpha1"
    )]
    InvalidApiVersion,
    #[error("unsupported Scheduling runtime kind; expected SchedulingRuntimeConfig")]
    InvalidKind,
    #[error(
        "the runtime configuration must name the database it activates packages in; add `identity: {{databaseId: scheduling-production}}` with a logical id chosen for this deployment"
    )]
    MissingIdentity,
    #[error(
        "identity.databaseId must be non-empty, at most 256 bytes, without surrounding whitespace or control characters"
    )]
    InvalidDatabaseId,
    #[error("the operated runtime path {0} must be absolute")]
    RelativeOperatedPath(&'static str),
    /// The packaged policy's own report: every rule it breaks, each at its
    /// position in `scheduling.yaml`.
    #[error("package.root/scheduling.yaml does not pass its checks")]
    Policy(Report),
    #[error("package.root/scheduling.yaml could not be read")]
    PolicyUnreadable,
    #[error(transparent)]
    Package(PackageError),
    #[error(transparent)]
    PackageDigest(PackageDigestMismatch),
    #[error(
        "the package at package.root must hold exactly scheduling.yaml{}; rebuild it with `schedulingctl package`",
        extra_files(extra)
    )]
    PackageContents { extra: Vec<String> },
    #[error(
        "package.root holds scheduling.package.json, which Scheduling no longer reads; rebuild the package with `schedulingctl package`, which writes SHA256SUMS"
    )]
    RetiredPackageManifest,
    #[error(
        "package.root/scheduling.yaml changed after its package was verified; deploy the whole package again"
    )]
    PolicyChanged,
    #[error("listener is not valid for its declared TLS termination and network exposure")]
    InvalidListener,
    #[error("{path} {reason}")]
    InvalidOidcClaim {
        path: &'static str,
        reason: &'static str,
    },
    #[error(
        "authentication.oidc.allowedClients must name every client the deployment admits; unrestricted would admit every client the issuer verifies"
    )]
    AllowedClientsRequired,
    #[error(
        "database.runtimeUrlRef and database.migrationUrlRef must be non-empty secret references"
    )]
    InvalidDatabaseReference,
    #[error("{}", audit_message(.0))]
    InvalidAuditDestination(#[source] AuditDestinationError),
    #[error(
        "{path} must be an https URL, or an http URL on 127.0.0.1, localhost, or [::1], with a nonzero port and no query or fragment"
    )]
    InvalidDestinationUrl { path: String, pointer: String },
    #[error(
        "destinations.hooks must bind every destination scheduling.yaml hooks[].handler.destinationId names"
    )]
    HookDestinationInventoryMismatch,
    #[error("plaintext PostgreSQL is test-only")]
    PlaintextDatabase,
    #[error("the OIDC issuer could not be initialized")]
    Oidc,
    #[error("the static OIDC signing keys could not be loaded: {0}")]
    OidcJwksSecret(String),
}

/// The fix for a rebuilt package, named by every package refusal.
const REBUILD_PACKAGE: &str =
    "Rebuild the package with `schedulingctl package`, then point package.root at it.";

impl RuntimeConfigError {
    fn invalid_destination_url(segments: &[&str]) -> Self {
        Self::InvalidDestinationUrl {
            path: segments.join("."),
            pointer: pointer_to(segments),
        }
    }

    /// The member this refusal concerns, as a dotted name (`listener.bind`).
    /// Three kinds of refusal return something else, and `pointer` answers
    /// them before it splits this name into a JSON Pointer: `Load` returns
    /// the JSON Pointer its diagnostic already carries, and the package
    /// refusals return a package path (`package.root`,
    /// `package.root/scheduling.yaml`).
    fn member(&self) -> &str {
        match self {
            Self::Load(error) => &error.deciding_diagnostic().path,
            Self::Block(error) | Self::BindingSecret { error, .. } => error.field(),
            Self::InvalidApiVersion => "apiVersion",
            Self::InvalidKind => "kind",
            Self::MissingIdentity | Self::InvalidDatabaseId => "identity.databaseId",
            Self::RelativeOperatedPath(path) => path,
            Self::InvalidOidcClaim { path, .. } => path,
            Self::InvalidDestinationUrl { path, .. } => path,
            Self::Oidc => "authentication.oidc",
            Self::AllowedClientsRequired => "authentication.oidc.allowedClients",
            Self::OidcJwksSecret(_) => "authentication.oidc.jwksSource.documentRef",
            Self::InvalidListener => "listener.bind",
            Self::InvalidDatabaseReference => "database",
            Self::PlaintextDatabase => "database.testOnlyPlaintext",
            Self::InvalidAuditDestination(error) => audit_field(error),
            Self::HookDestinationInventoryMismatch => "destinations.hooks",
            Self::Policy(_) | Self::PolicyUnreadable | Self::PolicyChanged => {
                "package.root/scheduling.yaml"
            }
            Self::Package(_) | Self::PackageContents { .. } | Self::RetiredPackageManifest => {
                "package.root"
            }
            Self::PackageDigest(_) => "package.expectedDigest",
        }
    }

    /// The JSON Pointer, in the runtime file, of the member this refusal
    /// concerns. A member that is absent is located by the mapping that
    /// lacks it when the refusal is positioned.
    #[must_use]
    pub fn pointer(&self) -> String {
        match self {
            Self::Load(error) => error.deciding_diagnostic().path.clone(),
            Self::BindingSecret { pointer, .. } | Self::InvalidDestinationUrl { pointer, .. } => {
                pointer.clone()
            }
            Self::MissingIdentity => "/identity".to_owned(),
            Self::Policy(_)
            | Self::PolicyUnreadable
            | Self::PolicyChanged
            | Self::Package(_)
            | Self::PackageContents { .. }
            | Self::RetiredPackageManifest => "/package/root".to_owned(),
            _ => pointer_to(&self.member().split('.').collect::<Vec<_>>()),
        }
    }

    /// The diagnostic code of this refusal.
    #[must_use]
    pub fn code(&self) -> &str {
        match self {
            Self::Load(error) => &error.deciding_diagnostic().code,
            Self::Block(error) | Self::BindingSecret { error, .. } => block_finding(error).0,
            Self::InvalidApiVersion => "scheduling.runtime.unsupported-api-version",
            Self::InvalidKind => "scheduling.runtime.wrong-kind",
            Self::MissingIdentity => "scheduling.runtime.missing-identity",
            Self::InvalidDatabaseId => "scheduling.runtime.invalid-database-id",
            Self::RelativeOperatedPath(_) => "scheduling.runtime.relative-path",
            Self::Policy(_) => "scheduling.package.invalid-project",
            Self::PolicyUnreadable => "scheduling.package.unreadable-project",
            Self::Package(_) => "scheduling.package.invalid",
            Self::PackageDigest(_) => "scheduling.package.digest-mismatch",
            Self::PackageContents { .. } => "scheduling.package.unexpected-contents",
            Self::RetiredPackageManifest => "scheduling.package.retired-manifest",
            Self::PolicyChanged => "scheduling.package.file-changed",
            Self::InvalidListener => "scheduling.runtime.invalid-listener",
            Self::InvalidOidcClaim { .. } => "scheduling.runtime.invalid-oidc-claim",
            Self::AllowedClientsRequired => "scheduling.runtime.allowed-clients-required",
            Self::InvalidDatabaseReference => "scheduling.runtime.invalid-database-reference",
            Self::InvalidAuditDestination(_) => "scheduling.runtime.invalid-audit",
            Self::InvalidDestinationUrl { .. } => "scheduling.runtime.invalid-destination-url",
            Self::HookDestinationInventoryMismatch => "scheduling.runtime.unbound-hook-destination",
            Self::PlaintextDatabase => "scheduling.runtime.plaintext-database",
            Self::Oidc => "scheduling.runtime-dependency.unavailable",
            Self::OidcJwksSecret(_) => "scheduling.runtime.unreadable-jwks-secret",
        }
    }

    /// What the operator does to clear this refusal.
    #[must_use]
    pub fn suggested_action(&self) -> String {
        let action = match self {
            Self::Load(error) => return error.deciding_diagnostic().suggested_action.clone(),
            Self::Block(error) | Self::BindingSecret { error, .. } => block_finding(error).1,
            Self::InvalidApiVersion => {
                "Write apiVersion: id.registrystack.org/formats/scheduling/runtime/v1alpha1."
            }
            Self::InvalidKind => "Write kind: SchedulingRuntimeConfig.",
            Self::MissingIdentity => {
                "Add `identity: {databaseId: scheduling-production}` with a logical id chosen for this deployment."
            }
            Self::InvalidDatabaseId => {
                "Write identity.databaseId as at most 256 bytes without surrounding whitespace or control characters."
            }
            Self::RelativeOperatedPath(path) => {
                return format!("Write {path} as an absolute path.");
            }
            Self::Policy(_) => {
                "Correct scheduling.yaml as `schedulingctl check` reports, then rebuild the package with `schedulingctl package`."
            }
            Self::PolicyUnreadable
            | Self::Package(_)
            | Self::PackageContents { .. }
            | Self::RetiredPackageManifest
            | Self::PolicyChanged => REBUILD_PACKAGE,
            Self::PackageDigest(_) => {
                "Set package.expectedDigest to the digest `schedulingctl package` reported for the package at package.root, or remove it."
            }
            Self::InvalidListener => {
                "Bind to a loopback address under development-loopback; under operator-controlled-upstream bind to a loopback or private address, or to the unspecified address only with networkExposure: container-private."
            }
            Self::InvalidOidcClaim { .. } => {
                "Name a non-empty value, with explainScope distinct from readsScope, or remove the member to use its default."
            }
            Self::AllowedClientsRequired => {
                "List every client identifier this deployment admits in authentication.oidc.allowedClients, then retry."
            }
            Self::InvalidDatabaseReference => {
                "Write database.runtimeUrlRef and database.migrationUrlRef as secret references."
            }
            Self::InvalidAuditDestination(error) => audit_action(error),
            Self::InvalidDestinationUrl { .. } => {
                "Write an https URL with a host, or an http URL on 127.0.0.1, localhost, or [::1] for local development, without a query or fragment."
            }
            Self::HookDestinationInventoryMismatch => {
                "Add a destinations.hooks entry for each destination scheduling.yaml hooks[].handler.destinationId names."
            }
            Self::PlaintextDatabase => {
                "Remove database.testOnlyPlaintext; a deployment reaches PostgreSQL over TLS."
            }
            Self::Oidc => {
                "Restore access to the configured OIDC issuer or mounted JWKS, then retry."
            }
            Self::OidcJwksSecret(_) => {
                "Make the secret authentication.oidc.jwksSource.documentRef names readable and hold a JWKS document."
            }
        };
        action.to_owned()
    }

    /// Whether this refusal is a rule the runtime file itself breaks, which
    /// an offline check reports at its position in the file. A refusal of
    /// the package, of an unreachable dependency, or one the shared loader
    /// already positioned is not.
    #[must_use]
    pub fn in_file(&self) -> bool {
        !matches!(
            self,
            Self::Load(_)
                | Self::Policy(_)
                | Self::PolicyUnreadable
                | Self::Package(_)
                | Self::PackageDigest(_)
                | Self::PackageContents { .. }
                | Self::RetiredPackageManifest
                | Self::PolicyChanged
                | Self::Oidc
                | Self::OidcJwksSecret(_)
        )
    }
}

fn extra_files(extra: &[String]) -> String {
    if extra.is_empty() {
        String::new()
    } else {
        format!(", not {}", extra.join(", "))
    }
}

/// The member of the audit block an audit destination refusal concerns.
/// Scheduling names the retention member `retentionDays` (CFG-NAME-5), so
/// this and [`audit_message`] say so rather than repeat the shared text.
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

/// An audit destination refusal in Scheduling's own member names, without
/// the configured path.
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
            "audit.path names the {companion} of another audit stream: a file name ending in `{suffix}` is reserved for it"
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
            "scheduling.runtime.relative-path",
            "Write the path as an absolute path without `.` or `..` segments.",
        ),
        ConfigBlockErrorKind::NoSecretProvider => (
            "scheduling.runtime.no-secret-provider",
            "Enable secretProviders.file, secretProviders.environment, or both.",
        ),
        ConfigBlockErrorKind::InvalidSecretReference => (
            "scheduling.runtime.invalid-secret-reference",
            "Write the reference as secret:env/NAME or secret:file/name.",
        ),
        ConfigBlockErrorKind::SecretProviderDisabled => (
            "scheduling.runtime.secret-provider-disabled",
            "Enable the provider the reference names under secretProviders, or reference an enabled one.",
        ),
        ConfigBlockErrorKind::Empty => (
            "scheduling.runtime.empty-value",
            "Give the member a value.",
        ),
        ConfigBlockErrorKind::InvalidDigest => (
            "scheduling.runtime.invalid-digest",
            "Write the sha256: digest `schedulingctl package` reported, or remove the member.",
        ),
        ConfigBlockErrorKind::InvalidUri => (
            "scheduling.runtime.invalid-uri",
            "Write an absolute https URL without credentials, query, or fragment.",
        ),
        ConfigBlockErrorKind::InvalidAudience => (
            "scheduling.runtime.invalid-audience",
            "Write the audience as non-empty text without control characters, within the bound the message names.",
        ),
        ConfigBlockErrorKind::InvalidAssertionIssuers => (
            "scheduling.runtime.invalid-assertion-issuers",
            "Keep assertionIssuers within the bounds the message names, with non-empty clients and issuers and no issuer repeated for one client.",
        ),
    }
}

/// Test support: whether the shared reader accepts `block`, written as one
/// block of the runtime file, as `T`.
#[cfg(test)]
pub(crate) fn reads_block<T: serde::de::DeserializeOwned>(block: &serde_json::Value) -> bool {
    use registry_platform_yaml::{EnvelopeRule, Expect, FormatSpec};
    const BLOCK: FormatSpec<'static> = FormatSpec {
        kind: "RuntimeBlock",
        envelope: EnvelopeRule::Exempt {
            reason: "one block of a runtime file",
        },
        removed_keys: &[],
    };
    registry_platform_yaml::decode_document::<T>(
        "block.yaml",
        block.to_string().as_bytes(),
        &Expect::one(&BLOCK),
    )
    .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use registry_platform_config::package::write_sum_file;
    use registry_platform_config::SUM_FILE;
    use registry_platform_config::{
        MAX_ASSERTION_ISSUERS_PER_CLIENT, MAX_ASSERTION_ISSUER_BYTES, MAX_ASSERTION_ISSUER_CLIENTS,
        MAX_ASSERTION_ISSUER_CLIENT_BYTES,
    };
    use registry_platform_oidc::is_access_token_typ_pair;

    const POLICY: &str = r#"apiVersion: id.registrystack.org/formats/scheduling/project/v1alpha1
kind: SchedulingProject
project:
  id: registry-updates
  version: "1"
services:
  - id: registry-update
    label: Registry record update
offerings:
  - id: registry-update-30
    service: registry-update
    label: 30-minute counter update
    mode: exact-time
    location: north-counter
    because: A 30-minute update at an interchangeable station.
    exactTime:
      durationMinutes: 30
      bufferBeforeMinutes: 5
      bufferAfterMinutes: 5
      leadTimeMinutes: 120
      horizonDays: 60
      pool: update-stations
      startIncrementMinutes: 30
      maximumRecipients: 1
    cancellationCutoffMinutes: 240
holidaySets:
  - id: office-holidays
    revision: 1
    because: Public holidays observed by the registry office.
    dates: ["2026-12-25"]
openings:
  - id: counter-hours
    location: north-counter
    holidaySet: office-holidays
    weekdays: [mon, tue, wed, thu, fri]
    startTime: "09:00"
    endTime: "12:30"
    effectiveFrom: "2026-10-01"
    effectiveUntil: "2026-12-31"
    because: Counter opening hours reviewed by the office manager.
channels: [public, assisted]
holdPolicy:
  ttlMinutes: 5
  maximumPerCaller: 3
  because: Holds are short because counter capacity is scarce.
"#;

    const OBSERVER: &str = "hooks:
  - id: appointment-observer
    phase: after
    trigger: appointment.confirmed
    projection: []
    handler:
      type: url
      destinationId: appointment-events
";

    /// A temporary directory named by its canonical path: the loader refuses
    /// a runtime configuration reached through a symbolic link, and the
    /// system temporary directory is one on some platforms.
    fn canonical_tempdir() -> tempfile::TempDir {
        tempfile::tempdir_in(std::fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap()
    }

    fn write_policy(root: &Path) {
        package_policy(root, POLICY);
    }

    /// Write `policy` as the package's `scheduling.yaml` and list it in a
    /// fresh `SHA256SUMS`, as `schedulingctl package` does.
    fn package_policy(root: &Path, policy: &str) {
        std::fs::create_dir_all(root).unwrap();
        std::fs::write(root.join(AUTHORED_POLICY_FILE), policy).unwrap();
        if root.join(SUM_FILE).exists() {
            std::fs::remove_file(root.join(SUM_FILE)).unwrap();
        }
        write_sum_file(root, None, &package_limits(), PACKAGE_COMMAND).unwrap();
    }

    fn operator_value(package: &Path, tls: &str) -> serde_json::Value {
        let root = package.parent().expect("package parent");
        serde_json::json!({
            "apiVersion": SCHEDULING_RUNTIME_API_VERSION,
            "kind": SCHEDULING_RUNTIME_KIND,
            "identity": {"databaseId": "scheduling-test"},
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
            "retention": {"attemptReceiptRetentionDays": 7}
        })
    }

    fn operator_document(package: &Path, tls: &str) -> String {
        serde_norway::to_string(&operator_value(package, tls)).unwrap()
    }

    fn write_operator(root: &Path, document: serde_json::Value) -> PathBuf {
        let operator = root.join("runtime.yaml");
        std::fs::write(&operator, serde_norway::to_string(&document).unwrap()).unwrap();
        operator
    }

    fn parse_runtime(document: &serde_json::Value) -> Result<RuntimeConfig, RuntimeConfigError> {
        let text = serde_norway::to_string(document).unwrap();
        RuntimeConfig::loader()
            .parse_str::<RuntimeConfig>(&text, |_| None)
            .map(|loaded| loaded.config)
            .map_err(RuntimeConfigError::Load)
    }

    /// A packaged development deployment: the package directory and the
    /// runtime document that serves it.
    fn development(root: &Path) -> (PathBuf, serde_json::Value) {
        let package = root.join("package");
        write_policy(&package);
        let document = operator_value(&package, "development-loopback");
        (package, document)
    }

    /// The code and pointer of a refusal, the pair an operator acts on.
    fn refusal(error: &RuntimeConfigError) -> (String, String) {
        (error.code().to_owned(), error.pointer())
    }

    #[test]
    fn an_empty_assertion_issuer_map_is_refused_at_its_pointer() {
        let root = canonical_tempdir();
        let (_, mut document) = development(root.path());
        document["authentication"]["oidc"]["assertionIssuers"] = serde_json::json!({});
        let error = parse_runtime(&document).expect_err("an empty map is refused");
        assert_eq!(error.pointer(), "/authentication/oidc/assertionIssuers");
    }

    #[test]
    fn a_listed_client_with_no_assertion_issuers_is_refused_at_that_client() {
        let root = canonical_tempdir();
        let (_, mut document) = development(root.path());
        document["authentication"]["oidc"]["assertionIssuers"] =
            serde_json::json!({"case-portal": []});
        let error = parse_runtime(&document).expect_err("an empty issuer list is refused");
        assert_eq!(error.code(), "config.invalid-value", "{error}");
        assert_eq!(
            error.pointer(),
            "/authentication/oidc/assertionIssuers/case-portal"
        );
    }

    #[test]
    fn a_development_configuration_loads_and_exposes_its_defaults() {
        let root = canonical_tempdir();
        let (_, document) = development(root.path());
        let config = RuntimeConfig::load(write_operator(root.path(), document))
            .expect("configuration is accepted");
        assert_eq!(config.authentication.oidc.scope_claim, "registry_scopes");
        assert_eq!(config.authentication.oidc.reads_scope, "scheduling-read");
        assert_eq!(
            config.authentication.oidc.explain_scope,
            "scheduling-explain"
        );
        assert_eq!(config.retention.attempt_receipt_retention_days, 7);
        assert_eq!(config.retention.hook_payload_retention_days, 7);
        assert!(config.destinations.reminders.is_none());
        assert!(config.destinations.hooks.is_empty());
        let policy = config.load_policy().expect("policy loads").policy;
        assert_eq!(&*policy.project.id, "registry-updates");
    }

    #[test]
    fn a_missing_identity_block_is_refused_with_the_key_to_add() {
        let root = canonical_tempdir();
        let (_, mut document) = development(root.path());
        document.as_object_mut().unwrap().remove("identity");
        let error = RuntimeConfig::load(write_operator(root.path(), document))
            .expect_err("a configuration without identity is refused");
        assert_eq!(
            refusal(&error),
            (
                "scheduling.runtime.missing-identity".to_owned(),
                "/identity".to_owned()
            )
        );
        assert!(
            error.suggested_action().contains("identity: {databaseId:"),
            "{error}"
        );
    }

    #[test]
    fn identity_database_id_is_a_bounded_trimmed_printable_value() {
        let root = canonical_tempdir();
        let (_, base) = development(root.path());
        let load = |database_id: serde_json::Value| {
            let mut document = base.clone();
            document["identity"] = serde_json::json!({"databaseId": database_id});
            RuntimeConfig::load(write_operator(root.path(), document))
        };
        let config = load(serde_json::json!("scheduling-production")).expect("valid id");
        assert_eq!(config.database_id(), "scheduling-production");
        load(serde_json::json!("x".repeat(MAX_DATABASE_ID_BYTES)))
            .expect("the bound itself is accepted");
        for invalid in [
            "   ".to_owned(),
            " scheduling-production".to_owned(),
            "scheduling-production ".to_owned(),
            "scheduling\nproduction".to_owned(),
            "x".repeat(MAX_DATABASE_ID_BYTES + 1),
        ] {
            let error = load(serde_json::json!(invalid)).expect_err("invalid id is refused");
            assert_eq!(
                refusal(&error),
                (
                    "scheduling.runtime.invalid-database-id".to_owned(),
                    "/identity/databaseId".to_owned()
                ),
                "{invalid:?}"
            );
        }
        let mut document = base.clone();
        document["identity"]["extra"] = serde_json::json!("value");
        let error = RuntimeConfig::load(write_operator(root.path(), document))
            .expect_err("identity refuses an unknown key");
        assert_eq!(
            refusal(&error),
            (
                "config.unknown-key".to_owned(),
                "/identity/extra".to_owned()
            )
        );
    }

    #[test]
    fn the_audit_block_takes_a_file_or_stdout_destination() {
        let root = canonical_tempdir();
        let (_, base) = development(root.path());
        let audit_file = root.path().join("audit.ndjson");
        let load = |audit: serde_json::Value| {
            let mut document = base.clone();
            document["audit"] = audit;
            RuntimeConfig::load(write_operator(root.path(), document))
        };

        let config = load(serde_json::json!({
            "path": audit_file,
            "hashKeyRef": "secret:file/audit",
            "rotateBytes": MIN_AUDIT_ROTATE_BYTES,
            "retentionDays": MAX_AUDIT_RETAIN_DAYS,
        }))
        .expect("a file destination is the default");
        assert!(matches!(
            config.audit.destination(),
            Ok(AuditDestination::File(_))
        ));
        let config = load(serde_json::json!({
            "destination": "stdout",
            "hashKeyRef": "secret:file/audit",
        }))
        .expect("a stdout destination takes no path");
        assert!(matches!(
            config.audit.destination(),
            Ok(AuditDestination::Stdout)
        ));

        for (audit, code, pointer) in [
            (
                serde_json::json!({"destination": "stdout", "path": audit_file}),
                "scheduling.runtime.invalid-audit",
                "/audit/path",
            ),
            (
                serde_json::json!({"destination": "stdout", "rotateBytes": MIN_AUDIT_ROTATE_BYTES}),
                "scheduling.runtime.invalid-audit",
                "/audit/rotateBytes",
            ),
            (
                serde_json::json!({"destination": "stdout", "retentionDays": 30}),
                "scheduling.runtime.invalid-audit",
                "/audit/retentionDays",
            ),
            (
                serde_json::json!({"destination": "file"}),
                "scheduling.runtime.invalid-audit",
                "/audit/path",
            ),
            (
                serde_json::json!({"path": "audit.ndjson"}),
                "scheduling.runtime.relative-path",
                "/audit/path",
            ),
            (
                serde_json::json!({"path": audit_file, "rotateBytes": 1024}),
                "config.out-of-range",
                "/audit/rotateBytes",
            ),
            (
                serde_json::json!({"path": audit_file, "retentionDays": MAX_AUDIT_RETAIN_DAYS + 1}),
                "config.out-of-range",
                "/audit/retentionDays",
            ),
            (
                serde_json::json!({"path": audit_file, "retentionDays": 0}),
                "config.out-of-range",
                "/audit/retentionDays",
            ),
        ] {
            let mut audit = audit;
            audit["hashKeyRef"] = serde_json::json!("secret:file/audit");
            let error = load(audit.clone()).expect_err("the audit block is refused");
            assert_eq!(
                refusal(&error),
                (code.to_owned(), pointer.to_owned()),
                "{audit}: {error}"
            );
            assert!(!error.suggested_action().is_empty(), "{audit}");
        }

        // Scheduling's audit refusals name its own member, retentionDays.
        let error = load(serde_json::json!({
            "destination": "stdout",
            "retentionDays": 30,
            "hashKeyRef": "secret:file/audit",
        }))
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "audit.retentionDays applies only when audit.destination is file"
        );
    }

    #[test]
    fn a_removed_runtime_key_names_the_key_that_replaced_it() {
        let root = canonical_tempdir();
        let (_, base) = development(root.path());
        for (member, value, pointer, replacement) in [
            (
                "audit",
                "retainDays",
                "/audit/retainDays",
                "audit.retentionDays",
            ),
            (
                "retention",
                "attemptReceiptDays",
                "/retention/attemptReceiptDays",
                "retention.attemptReceiptRetentionDays",
            ),
            (
                "retention",
                "hookPayloadDays",
                "/retention/hookPayloadDays",
                "retention.hookPayloadRetentionDays",
            ),
        ] {
            let mut document = base.clone();
            document[member][value] = serde_json::json!(7);
            let error = RuntimeConfig::load(write_operator(root.path(), document)).unwrap_err();
            assert_eq!(
                refusal(&error),
                ("config.removed-key".to_owned(), pointer.to_owned())
            );
            assert!(
                error.suggested_action().contains(replacement),
                "{}",
                error.suggested_action()
            );
        }
    }

    #[test]
    fn a_retired_runtime_api_version_names_its_replacement() {
        let root = canonical_tempdir();
        let (_, mut document) = development(root.path());
        document["apiVersion"] = serde_json::json!(RETIRED_SCHEDULING_RUNTIME_API_VERSION);
        let error = RuntimeConfig::load(write_operator(root.path(), document)).unwrap_err();
        assert_eq!(
            refusal(&error),
            (
                "config.retired-api-version".to_owned(),
                "/apiVersion".to_owned()
            )
        );
        assert!(
            error
                .suggested_action()
                .contains(SCHEDULING_RUNTIME_API_VERSION),
            "{}",
            error.suggested_action()
        );
    }

    #[test]
    fn one_verified_load_supplies_the_policy_and_its_package_identity() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        write_policy(&package);
        let operator = write_operator(
            root.path(),
            operator_value(&package, "operator-controlled-upstream"),
        );
        let config = RuntimeConfig::load(&operator).expect("configuration is accepted");

        let loaded = config
            .load_policy()
            .expect("policy and package load together");
        assert_eq!(&*loaded.policy.project.id, "registry-updates");
        assert_eq!(
            loaded.package_digest,
            sha256_uri(&std::fs::read(package.join(SUM_FILE)).unwrap())
        );
    }

    #[test]
    fn every_listener_mode_verifies_the_package_without_a_pin() {
        for tls in ["development-loopback", "operator-controlled-upstream"] {
            let root = canonical_tempdir();
            let package = root.path().join("package");
            write_policy(&package);
            let operator = write_operator(root.path(), operator_value(&package, tls));
            let config = RuntimeConfig::load(&operator).expect("the package is admitted");
            assert_eq!(
                config.package_digest().unwrap(),
                sha256_uri(&std::fs::read(package.join(SUM_FILE)).unwrap())
            );

            let refused = |named: &str| {
                let error = RuntimeConfig::load(&operator).unwrap_err();
                let message = error.to_string();
                assert_eq!(error.pointer(), "/package/root", "{tls}: {message}");
                assert!(!error.in_file(), "{tls}: {message}");
                assert!(message.contains(named), "{tls}: {message}");
                assert!(message.contains(PACKAGE_COMMAND), "{tls}: {message}");
                assert!(
                    error.suggested_action().contains(PACKAGE_COMMAND),
                    "{tls}: {message}"
                );
            };

            let policy = package.join(AUTHORED_POLICY_FILE);
            std::fs::write(&policy, format!("{POLICY}# changed\n")).unwrap();
            refused("changed: scheduling.yaml");
            std::fs::write(&policy, POLICY).unwrap();

            std::fs::write(package.join("notes.txt"), "stale\n").unwrap();
            refused("extra: notes.txt");
            std::fs::remove_file(package.join("notes.txt")).unwrap();

            std::fs::remove_file(&policy).unwrap();
            refused("missing: scheduling.yaml");
            std::fs::write(&policy, POLICY).unwrap();
            RuntimeConfig::load(&operator).expect("the restored package is admitted");

            std::fs::write(package.join(RETIRED_PACKAGE_MANIFEST_FILE), "{}").unwrap();
            refused(RETIRED_PACKAGE_MANIFEST_FILE);
            std::fs::remove_file(package.join(RETIRED_PACKAGE_MANIFEST_FILE)).unwrap();

            std::fs::remove_file(package.join(SUM_FILE)).unwrap();
            refused("has no SHA256SUMS");
        }
    }

    #[test]
    fn scopes_retention_and_destinations_are_refused_at_their_member() {
        let root = canonical_tempdir();
        let (_, base) = development(root.path());
        let hook = |extra: serde_json::Value| {
            let mut binding = serde_json::json!({
                "url": "https://events.example.test/scheduling",
                "hmacSha256KeyRef": "secret:file/hook-key"
            });
            binding
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            serde_json::json!({"hooks": {"appointment-events": binding}})
        };
        for (member, patch, code, pointer) in [
            (
                "oidc",
                serde_json::json!({"explainScope": "scheduling-read"}),
                "scheduling.runtime.invalid-oidc-claim",
                "/authentication/oidc/explainScope",
            ),
            (
                "oidc",
                serde_json::json!({"scopeClaim": ""}),
                "scheduling.runtime.invalid-oidc-claim",
                "/authentication/oidc/scopeClaim",
            ),
            (
                "retention",
                serde_json::json!({"attemptReceiptRetentionDays": 0}),
                "config.out-of-range",
                "/retention/attemptReceiptRetentionDays",
            ),
            (
                "retention",
                serde_json::json!({"hookPayloadRetentionDays": 0}),
                "config.out-of-range",
                "/retention/hookPayloadRetentionDays",
            ),
            (
                "retention",
                serde_json::json!({"hookPayloadRetentionDays": MAX_HOOK_PAYLOAD_RETENTION_DAYS + 1}),
                "config.out-of-range",
                "/retention/hookPayloadRetentionDays",
            ),
            (
                "destinations",
                serde_json::json!({"reminders": {"url": "not-a-url"}}),
                "config.invalid-value",
                "/destinations/reminders/url",
            ),
            (
                "destinations",
                serde_json::json!({"reminders": {"url": "https://reminders.example.test/due?all=1"}}),
                "scheduling.runtime.invalid-destination-url",
                "/destinations/reminders/url",
            ),
            (
                "destinations",
                serde_json::json!({"reminders": {"url": "http://reminders.example.test/due"}}),
                "scheduling.runtime.invalid-destination-url",
                "/destinations/reminders/url",
            ),
            (
                "destinations",
                serde_json::json!({"reminders": {
                    "url": "https://reminders.example.test/due",
                    "bearerTokenRef": "vault:reminders"
                }}),
                "config.invalid-value",
                "/destinations/reminders/bearerTokenRef",
            ),
            (
                "destinations",
                serde_json::json!({"hooks": {"Appointment-Events": {
                    "url": "https://events.example.test/scheduling",
                    "hmacSha256KeyRef": "secret:file/hook-key"
                }}}),
                "config.invalid-value",
                "/destinations/hooks/Appointment-Events",
            ),
            (
                "destinations",
                hook(serde_json::json!({"maximumAttempts": MAX_HOOK_ATTEMPTS + 1})),
                "config.out-of-range",
                "/destinations/hooks/appointment-events/maximumAttempts",
            ),
            (
                "destinations",
                hook(serde_json::json!({"maximumAttempts": 0})),
                "config.out-of-range",
                "/destinations/hooks/appointment-events/maximumAttempts",
            ),
            (
                "destinations",
                hook(serde_json::json!({
                    "attemptTimeoutMilliseconds": MIN_HOOK_ATTEMPT_TIMEOUT_MILLISECONDS - 1
                })),
                "config.out-of-range",
                "/destinations/hooks/appointment-events/attemptTimeoutMilliseconds",
            ),
            (
                "destinations",
                hook(serde_json::json!({"url": "https://events.example.test/hook#fragment"})),
                "scheduling.runtime.invalid-destination-url",
                "/destinations/hooks/appointment-events/url",
            ),
        ] {
            let mut document = base.clone();
            if member == "oidc" {
                document["authentication"]["oidc"]
                    .as_object_mut()
                    .unwrap()
                    .extend(patch.as_object().unwrap().clone());
            } else {
                document[member] = patch.clone();
            }
            let error = RuntimeConfig::load(write_operator(root.path(), document))
                .expect_err("the member is refused");
            assert_eq!(
                refusal(&error),
                (code.to_owned(), pointer.to_owned()),
                "{patch}: {error}"
            );
        }
    }

    #[test]
    fn more_hook_destinations_than_the_bound_are_refused_with_the_bound_named() {
        let root = canonical_tempdir();
        let (_, mut document) = development(root.path());
        let bound = |count: usize| {
            (0..count)
                .map(|index| {
                    (
                        format!("events-{index}"),
                        serde_json::json!({
                            "url": "https://events.example.test/scheduling",
                            "hmacSha256KeyRef": "secret:file/hook-key"
                        }),
                    )
                })
                .collect::<serde_json::Map<_, _>>()
        };
        document["destinations"]["hooks"] = bound(MAX_HOOK_DESTINATIONS).into();
        parse_runtime(&document).expect("the bound itself is accepted");
        document["destinations"]["hooks"] = bound(MAX_HOOK_DESTINATIONS + 1).into();
        let error = parse_runtime(&document).expect_err("one past the bound is refused");
        assert_eq!(error.pointer(), "/destinations/hooks");
        assert!(error.suggested_action().contains("128"), "{error}");
    }

    #[test]
    fn a_hook_binding_secret_is_checked_against_the_enabled_providers() {
        let root = canonical_tempdir();
        let (_, mut document) = development(root.path());
        document["secretProviders"]
            .as_object_mut()
            .unwrap()
            .remove("environment");
        document["destinations"]["hooks"] = serde_json::json!({
            "appointment-events": {
                "url": "https://events.example.test/scheduling",
                "hmacSha256KeyRef": "secret:env/HOOK_KEY"
            }
        });
        document["database"] = serde_json::json!({
            "runtimeUrlRef": "secret:file/runtime",
            "migrationUrlRef": "secret:file/migration"
        });
        let config = parse_runtime(&document).expect("the document decodes");
        let findings = config.findings(None);
        let found: Vec<(String, String)> = findings.iter().map(refusal).collect();
        assert_eq!(
            found,
            [(
                "scheduling.runtime.secret-provider-disabled".to_owned(),
                "/destinations/hooks/appointment-events/hmacSha256KeyRef".to_owned()
            )]
        );
    }

    #[test]
    fn a_hook_policy_requires_and_accepts_its_deployment_binding() {
        let root = canonical_tempdir();
        let (package, mut document) = development(root.path());
        package_policy(&package, &format!("{POLICY}{OBSERVER}"));
        let error = RuntimeConfig::load(write_operator(root.path(), document.clone()))
            .expect_err("an unbound hook destination is refused");
        assert_eq!(
            refusal(&error),
            (
                "scheduling.runtime.unbound-hook-destination".to_owned(),
                "/destinations/hooks".to_owned()
            )
        );

        document["destinations"]["hooks"] = serde_json::json!({
            "appointment-events": {
                "url": "https://events.example.test/scheduling",
                "hmacSha256KeyRef": "secret:file/hook-key"
            }
        });
        let config = RuntimeConfig::load(write_operator(root.path(), document))
            .expect("the hook destination is bound");
        let binding = &config.destinations.hooks["appointment-events"];
        assert_eq!(binding.attempt_timeout_milliseconds, 5_000);
        assert_eq!(binding.maximum_attempts, 8);
        assert!(binding.within_delivery_budget());
    }

    #[test]
    fn typed_parse_path_does_not_echo_the_rejected_value() {
        let root = canonical_tempdir();
        let (_, mut document) = development(root.path());
        let canary = "DO_NOT_DISCLOSE_RUNTIME_VALUE";
        document["database"]["testOnlyPlaintext"] = serde_json::json!(canary);
        let error = RuntimeConfig::load(write_operator(root.path(), document)).unwrap_err();
        assert_eq!(error.pointer(), "/database/testOnlyPlaintext");
        let RuntimeConfigError::Load(load) = &error else {
            panic!("a reader refusal: {error}");
        };
        for diagnostic in load.diagnostics() {
            assert!(!diagnostic.message.contains(canary), "{diagnostic:?}");
            assert!(
                !diagnostic.suggested_action.contains(canary),
                "{diagnostic:?}"
            );
        }
        assert!(!error.to_string().contains(canary));
    }

    #[cfg(not(feature = "postgres-test"))]
    #[test]
    fn plaintext_postgres_is_refused_outside_the_test_suite() {
        let root = canonical_tempdir();
        let (_, mut document) = development(root.path());
        document["database"]["testOnlyPlaintext"] = serde_json::json!(true);
        let error = RuntimeConfig::load(write_operator(root.path(), document)).unwrap_err();
        assert_eq!(
            refusal(&error),
            (
                "scheduling.runtime.plaintext-database".to_owned(),
                "/database/testOnlyPlaintext".to_owned()
            )
        );
    }

    #[test]
    fn a_runtime_document_refused_whole_is_reported_at_the_root() {
        let root = canonical_tempdir();
        let operator = root.path().join("runtime.yaml");
        let canary = "DO_NOT_DISCLOSE_RUNTIME_VALUE";
        std::fs::write(&operator, format!("{canary}\n")).unwrap();

        let error = RuntimeConfig::load(&operator).unwrap_err();
        assert!(matches!(error, RuntimeConfigError::Load(_)), "{error}");
        assert_eq!(error.pointer(), "");
        assert!(!error.to_string().contains(canary), "{error}");
    }

    #[test]
    fn the_runtime_configuration_is_read_through_the_shared_loader() {
        let error = RuntimeConfig::load("runtime.yaml").unwrap_err();
        assert!(matches!(error, RuntimeConfigError::Load(_)), "{error}");
        assert!(error.to_string().contains("absolute"), "{error}");

        let root = canonical_tempdir();
        let (_, mut document) = development(root.path());
        document["listener"].as_object_mut().unwrap().remove("bind");
        let error = RuntimeConfig::load(write_operator(root.path(), document)).unwrap_err();
        assert_eq!(
            refusal(&error),
            ("config.missing-key".to_owned(), "/listener".to_owned())
        );
        assert!(error.to_string().contains("bind"), "{error}");
    }

    #[test]
    fn a_runtime_document_the_reader_stops_on_names_the_line_and_column() {
        let root = canonical_tempdir();
        let operator = root.path().join("runtime.yaml");
        // A tab can never open an indented line, so the reader stops on it.
        std::fs::write(&operator, "apiVersion: v1\n\tkind: x\n").unwrap();

        let error = RuntimeConfig::load(&operator).unwrap_err();
        let RuntimeConfigError::Load(load) = &error else {
            panic!("a reader refusal: {error}");
        };
        let source = load
            .deciding_diagnostic()
            .source
            .as_ref()
            .expect("a positioned refusal");
        assert_eq!(source.file, operator.display().to_string());
        assert_eq!(source.line, Some(2));
    }

    #[test]
    fn a_removed_jwks_uri_names_its_replacement() {
        let root = canonical_tempdir();
        let (_, base) = development(root.path());
        let mut document = base.clone();
        document["authentication"]["oidc"]["jwksUri"] =
            serde_json::json!("https://identity.example.test/jwks");
        let error = RuntimeConfig::load(write_operator(root.path(), document)).unwrap_err();
        assert_eq!(
            refusal(&error),
            (
                "config.removed-key".to_owned(),
                "/authentication/oidc/jwksUri".to_owned()
            )
        );
        assert!(
            error
                .suggested_action()
                .contains("authentication.oidc.jwksSource"),
            "{error}"
        );

        let mut document = base;
        document["authentication"]["oidc"]["jwksSource"] =
            serde_json::json!({"type": "uri", "uri": "https://identity.example.test/jwks"});
        let config = RuntimeConfig::load(write_operator(root.path(), document)).unwrap();
        assert_eq!(
            config.authentication.oidc.provider.jwks_source.uri(),
            Some("https://identity.example.test/jwks")
        );
    }

    #[test]
    fn a_jwks_source_tagged_by_kind_names_type() {
        let root = canonical_tempdir();
        let (_, mut document) = development(root.path());
        document["authentication"]["oidc"]["jwksSource"] =
            serde_json::json!({"kind": "uri", "uri": "https://identity.example.test/jwks"});
        let error = RuntimeConfig::load(write_operator(root.path(), document)).unwrap_err();
        assert_eq!(
            refusal(&error),
            (
                "config.removed-key".to_owned(),
                "/authentication/oidc/jwksSource/kind".to_owned()
            )
        );
        assert!(
            error
                .suggested_action()
                .contains("authentication.oidc.jwksSource.type"),
            "{error}"
        );
        assert!(
            !error.to_string().contains("identity.example.test"),
            "{error}"
        );
    }

    #[test]
    fn environment_expressions_substitute_values_but_never_secret_references() {
        let root = canonical_tempdir();
        let (_, base) = development(root.path());
        let mut document = base.clone();
        document["authentication"]["oidc"]["audience"] =
            serde_json::json!("${SCHEDULING_TEST_AUDIENCE:-urn:example:substituted}");
        let config = RuntimeConfig::load(write_operator(root.path(), document)).unwrap();
        assert_eq!(
            config.authentication.oidc.provider.audience,
            "urn:example:substituted"
        );

        let mut document = base;
        document["database"]["runtimeUrlRef"] =
            serde_json::json!("${SCHEDULING_TEST_REFERENCE:-secret:env/RUNTIME}");
        let error = RuntimeConfig::load(write_operator(root.path(), document)).unwrap_err();
        assert_eq!(
            refusal(&error),
            (
                "config.substitution-not-allowed".to_owned(),
                "/database/runtimeUrlRef".to_owned()
            )
        );
    }

    /// The `pointer code` pairs of a packaged policy's own report.
    fn policy_refusal(error: &RuntimeConfigError) -> Vec<String> {
        let RuntimeConfigError::Policy(report) = error else {
            panic!("a packaged policy refusal: {error}");
        };
        report
            .diagnostics()
            .iter()
            .map(|diagnostic| format!("{} {}", diagnostic.path, diagnostic.code))
            .collect()
    }

    #[test]
    fn a_packaged_policy_carrying_an_environment_expression_is_refused() {
        let root = canonical_tempdir();
        let (package, document) = development(root.path());
        package_policy(
            &package,
            &POLICY.replace(
                "    because: Counter opening hours reviewed by the office manager.\n",
                "    because: ${OPENING_REASON}\n",
            ),
        );
        let path = write_operator(root.path(), document);
        let error = RuntimeConfig::load(&path).unwrap_err();
        assert_eq!(
            policy_refusal(&error),
            ["/openings/0/because config.substitution-not-allowed"]
        );
        assert_eq!(error.code(), "scheduling.package.invalid-project");
        assert!(!error.in_file());
        let report = startup_report(&path, &error).expect("the policy's own report");
        assert_eq!(report.error_count(), 1);
    }

    #[test]
    fn a_refused_packaged_policy_names_the_member_and_its_position() {
        let root = canonical_tempdir();
        let (package, document) = development(root.path());
        let canary = "DO_NOT_DISCLOSE_POLICY_VALUE";
        package_policy(
            &package,
            &POLICY.replace("ttlMinutes: 5", &format!("ttlMinutes: {canary}")),
        );
        let error = RuntimeConfig::load(write_operator(root.path(), document)).unwrap_err();
        assert_eq!(
            policy_refusal(&error),
            ["/holdPolicy/ttlMinutes config.expected-integer"]
        );
        let RuntimeConfigError::Policy(report) = &error else {
            unreachable!();
        };
        for diagnostic in report.diagnostics() {
            assert!(!diagnostic.message.contains(canary), "{diagnostic:?}");
            assert!(
                !diagnostic.suggested_action.contains(canary),
                "{diagnostic:?}"
            );
        }
        assert!(!error.to_string().contains(canary), "{error}");
        let source = report.diagnostics()[0].source.as_ref().unwrap();
        assert!(source.file.ends_with(AUTHORED_POLICY_FILE), "{source:?}");
        assert!(
            source.line.is_some() && source.column.is_some(),
            "{source:?}"
        );
        assert!(error.suggested_action().contains("schedulingctl check"));
    }

    #[test]
    fn a_pinned_package_digest_must_match_the_verified_package() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        write_policy(&package);
        let digest = sha256_uri(&std::fs::read(package.join(SUM_FILE)).unwrap());

        let mut document = operator_value(&package, "operator-controlled-upstream");
        document["package"]["expectedDigest"] = serde_json::json!(digest);
        let config =
            RuntimeConfig::load(write_operator(root.path(), document)).expect("the pin matches");
        assert_eq!(config.package_digest().unwrap(), digest);

        let mut document = operator_value(&package, "operator-controlled-upstream");
        let expected = format!("sha256:{}", "0".repeat(64));
        document["package"]["expectedDigest"] = serde_json::json!(&expected);
        let error = RuntimeConfig::load(write_operator(root.path(), document)).unwrap_err();
        assert_eq!(
            refusal(&error),
            (
                "scheduling.package.digest-mismatch".to_owned(),
                "/package/expectedDigest".to_owned()
            )
        );
        assert_eq!(
            error.to_string(),
            format!(
                "package.expectedDigest is {expected} but the package at package.root is \
                 {digest}; deploy the pinned package or update package.expectedDigest"
            )
        );
    }

    #[test]
    fn a_rejected_runtime_member_names_the_cause_without_the_value() {
        let root = canonical_tempdir();
        let (_, mut document) = development(root.path());
        let canary = "DO_NOT_DISCLOSE_RUNTIME_VALUE";
        document["retention"]["attemptReceiptRetentionDays"] = serde_json::json!(canary);

        let error = RuntimeConfig::load(write_operator(root.path(), document)).unwrap_err();
        assert_eq!(error.pointer(), "/retention/attemptReceiptRetentionDays");
        let RuntimeConfigError::Load(load) = &error else {
            panic!("a reader refusal: {error}");
        };
        for diagnostic in load.diagnostics() {
            assert!(!diagnostic.message.contains(canary), "{diagnostic:?}");
            assert!(
                !diagnostic.suggested_action.contains(canary),
                "{diagnostic:?}"
            );
        }
        assert!(!error.to_string().contains(canary), "{error}");
    }

    #[test]
    fn every_deployment_must_name_the_clients_it_admits() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        write_policy(&package);
        let expected = (
            "scheduling.runtime.allowed-clients-required".to_owned(),
            "/authentication/oidc/allowedClients".to_owned(),
        );

        // The decision is written in every file, in either listener mode: an
        // omitted member, an empty list, and a repeated client are refused
        // by the reader, and `unrestricted` by the runtime, development
        // loopback included (CFG-EMPTY-2).
        for termination in ["operator-controlled-upstream", "development-loopback"] {
            let mut omitted = operator_value(&package, termination);
            omitted["authentication"]["oidc"]
                .as_object_mut()
                .unwrap()
                .remove("allowedClients");
            let error = RuntimeConfig::load(write_operator(root.path(), omitted))
                .expect_err("a deployment with no allowedClients was accepted");
            assert_eq!(error.code(), "config.missing-key", "{termination}: {error}");
            assert!(error.to_string().contains("allowedClients"), "{error}");

            let mut empty = operator_value(&package, termination);
            empty["authentication"]["oidc"]["allowedClients"] = serde_json::json!([]);
            let error = RuntimeConfig::load(write_operator(root.path(), empty))
                .expect_err("a deployment with an empty allowedClients was accepted");
            assert_eq!(
                refusal(&error),
                (
                    "config.invalid-value".to_owned(),
                    "/authentication/oidc/allowedClients".to_owned()
                ),
                "{termination}: {error}"
            );

            let mut repeated = operator_value(&package, termination);
            repeated["authentication"]["oidc"]["allowedClients"] =
                serde_json::json!(["scheduling-booking-agent", "scheduling-booking-agent"]);
            let error = RuntimeConfig::load(write_operator(root.path(), repeated))
                .expect_err("a repeated client was accepted");
            assert_eq!(
                refusal(&error),
                (
                    "config.duplicate-item".to_owned(),
                    "/authentication/oidc/allowedClients/1".to_owned()
                ),
                "{termination}: {error}"
            );

            let mut unrestricted = operator_value(&package, termination);
            unrestricted["authentication"]["oidc"]["allowedClients"] =
                serde_json::json!("unrestricted");
            let error = RuntimeConfig::load(write_operator(root.path(), unrestricted))
                .expect_err("a deployment admitting every client was accepted");
            assert_eq!(refusal(&error), expected, "{termination}");

            RuntimeConfig::load(write_operator(
                root.path(),
                operator_value(&package, termination),
            ))
            .expect("a named client list is accepted");
        }
    }

    #[test]
    fn a_declared_assertion_authority_binds_the_client_that_may_exchange_from_it() {
        let root = canonical_tempdir();
        let (_, mut document) = development(root.path());
        document["authentication"]["oidc"]["assertionIssuers"] = serde_json::json!({
            "scheduling-booking-agent": ["https://authority.example.test"]
        });
        let config = RuntimeConfig::load(write_operator(root.path(), document))
            .expect("an assertion authority is declarable");
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
        let (_, base) = development(root.path());
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
            let mut document = base.clone();
            document["authentication"]["oidc"]["assertionIssuers"] = refused.clone();
            let error = RuntimeConfig::load(write_operator(root.path(), document)).expect_err(
                &format!("an assertion-issuer map outside its bounds was accepted: {refused}"),
            );
            assert_eq!(
                refusal(&error),
                (
                    "scheduling.runtime.invalid-assertion-issuers".to_owned(),
                    "/authentication/oidc/assertionIssuers".to_owned()
                ),
                "{refused}"
            );
        }
    }

    #[test]
    fn the_oidc_issuer_and_clients_are_the_shared_blocks() {
        let root = canonical_tempdir();
        let (_, base) = development(root.path());

        let mut document = base.clone();
        document["authentication"]["oidc"]["issuer"] =
            serde_json::json!("http://identity.example.test");
        let error = RuntimeConfig::load(write_operator(root.path(), document))
            .expect_err("a remote http issuer");
        assert_eq!(error.pointer(), "/authentication/oidc/issuer");

        // The shared blocks leave the enclosing block closed.
        let mut document = base;
        document["authentication"]["oidc"]["issuerr"] =
            serde_json::json!("https://identity.example.test");
        let error = RuntimeConfig::load(write_operator(root.path(), document))
            .expect_err("an unknown oidc member");
        assert_eq!(
            refusal(&error),
            (
                "config.unknown-key".to_owned(),
                "/authentication/oidc/issuerr".to_owned()
            )
        );
    }

    /// The platform blocks are read through the shared-block recipe rather
    /// than serde `flatten`, so every unknown key inside one is reported, each
    /// at its own line and column, not only the first.
    #[test]
    fn two_unknown_keys_inside_each_shared_block_are_all_reported_with_positions() {
        let root = canonical_tempdir();
        let document = operator_document(&root.path().join("package"), "development-loopback");
        let insert_after = |text: String, line: &str, added: &str| {
            assert!(text.contains(line), "the fixture holds {line:?}");
            text.replacen(line, &format!("{line}{added}"), 1)
        };
        let text = insert_after(
            document,
            "    issuer: https://identity.example.test\n",
            "    issuers: canary-a\n    allowedClient: canary-b\n",
        );
        let text = insert_after(
            text,
            "  hashKeyRef: secret:file/audit\n",
            "  hashKey: canary-c\n  paths: canary-d\n",
        );
        let error = RuntimeConfig::loader()
            .parse_str::<RuntimeConfig>(&text, |_| None)
            .expect_err("unknown keys inside the shared blocks are refused");
        let line_of = |key: &str| {
            text.lines()
                .position(|line| line.trim_start().starts_with(&format!("{key}: canary-")))
                .map(|index| index + 1)
                .expect("the fixture holds the key")
        };
        let reported: Vec<(String, String, Option<usize>, Option<usize>)> = error
            .diagnostics()
            .iter()
            .map(|diagnostic| {
                let source = diagnostic
                    .source
                    .as_ref()
                    .expect("a reader diagnostic has a source");
                (
                    diagnostic.code.clone(),
                    diagnostic.path.clone(),
                    source.line,
                    source.column,
                )
            })
            .collect();
        for (path, key, column) in [
            ("/authentication/oidc/issuers", "issuers", 5),
            ("/authentication/oidc/allowedClient", "allowedClient", 5),
            ("/audit/hashKey", "hashKey", 3),
            ("/audit/paths", "paths", 3),
        ] {
            let expected = (
                "config.unknown-key".to_owned(),
                path.to_owned(),
                Some(line_of(key)),
                Some(column),
            );
            assert!(reported.contains(&expected), "{expected:?} in {reported:?}");
        }
        let human = error.to_string();
        assert!(!human.contains("canary-"), "{human}");
    }

    #[test]
    fn an_explicit_null_is_refused_where_an_omitted_member_would_load() {
        let root = canonical_tempdir();
        let mut document = operator_value(&root.path().join("package"), "development-loopback");
        document["audit"] = serde_json::json!({
            "hashKeyRef": "secret:env/AUDIT_HASH_KEY",
            "destination": "stdout"
        });
        let audit = parse_runtime(&document)
            .expect("an omitted path loads")
            .audit;
        assert_eq!(
            audit.destination().expect("stdout takes no file settings"),
            AuditDestination::Stdout
        );

        for (nulled, pointer) in [
            (&["audit", "path"][..], "/audit/path"),
            (
                &["authentication", "oidc", "scopeClaim"][..],
                "/authentication/oidc/scopeClaim",
            ),
            (
                &["destinations", "reminders"][..],
                "/destinations/reminders",
            ),
        ] {
            let mut document = document.clone();
            let (last, parents) = nulled.split_last().unwrap();
            let mut member = &mut document;
            for parent in parents {
                member = &mut member[*parent];
            }
            member[*last] = serde_json::Value::Null;
            let error = parse_runtime(&document).expect_err("an explicit null is refused");
            assert_eq!(error.pointer(), pointer, "{error}");
        }
    }

    #[test]
    fn the_access_token_profile_admits_only_the_rfc_9068_pair() {
        let root = canonical_tempdir();
        let (_, document) = development(root.path());
        let config = RuntimeConfig::load(write_operator(root.path(), document))
            .expect("configuration is accepted");
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
        let (_, mut document) = development(root.path());
        document["listener"]["bind"] = serde_json::json!("10.20.30.40:8105");
        let error = RuntimeConfig::load(write_operator(root.path(), document)).unwrap_err();
        assert_eq!(
            refusal(&error),
            (
                "scheduling.runtime.invalid-listener".to_owned(),
                "/listener/bind".to_owned()
            )
        );
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
        let (_, mut document) = development(root.path());
        let secrets_root = root.path().join("secrets");
        std::fs::create_dir(&secrets_root).unwrap();
        document["authentication"]["oidc"]["jwksSource"] =
            serde_json::json!({"type": "static", "documentRef": "secret:file/jwks.json"});
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
            assert_eq!(
                refusal(&error),
                (
                    "scheduling.runtime-dependency.unavailable".to_owned(),
                    "/authentication/oidc".to_owned()
                ),
                "{case}"
            );
            assert!(!error.in_file(), "{case}");
        }
    }

    /// A runtime file that breaks three rules, each away from the others.
    fn file_breaking_three_rules(root: &Path) -> PathBuf {
        let mut document = operator_value(&root.join("package"), "development-loopback");
        document["identity"]["databaseId"] = serde_json::json!(" padded ");
        document["listener"]["bind"] = serde_json::json!("10.0.0.5:8100");
        document["destinations"] = serde_json::json!({
            "reminders": {"url": "http://reminders.example.test/due"}
        });
        write_operator(root, document)
    }

    #[test]
    fn cfg_check_1_every_rule_a_runtime_file_breaks_is_reported_at_its_position() {
        let root = canonical_tempdir();
        let path = file_breaking_three_rules(root.path());
        let check = check_runtime(&path, None, false);
        assert!(!check.unavailable);
        let found: Vec<(&str, &str)> = check
            .diagnostics
            .iter()
            .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
            .collect();
        assert_eq!(
            found,
            [
                (
                    "scheduling.runtime.invalid-destination-url",
                    "/destinations/reminders/url"
                ),
                (
                    "scheduling.runtime.invalid-database-id",
                    "/identity/databaseId"
                ),
                ("scheduling.runtime.invalid-listener", "/listener/bind"),
            ]
        );
        for diagnostic in &check.diagnostics {
            assert_eq!(
                diagnostic.artifact.as_deref(),
                Some(SCHEDULING_RUNTIME_KIND)
            );
            let source = diagnostic.source.as_ref().expect("a positioned finding");
            assert_eq!(source.file, path.display().to_string());
            assert!(source.line.is_some(), "{diagnostic:?}");
            assert!(!diagnostic.suggested_action.is_empty(), "{diagnostic:?}");
            for value in ["padded", "10.0.0.5", "reminders.example.test"] {
                assert!(!diagnostic.message.contains(value), "{diagnostic:?}");
                assert!(
                    !diagnostic.suggested_action.contains(value),
                    "{diagnostic:?}"
                );
            }
        }
    }

    #[test]
    fn cfg_check_1_an_absent_member_is_located_at_the_mapping_that_lacks_it() {
        let root = canonical_tempdir();
        let mut document = operator_value(&root.path().join("package"), "development-loopback");
        document.as_object_mut().unwrap().remove("identity");
        let path = write_operator(root.path(), document);
        let check = check_runtime(&path, None, false);
        assert_eq!(check.diagnostics.len(), 1, "{:?}", check.diagnostics);
        let diagnostic = &check.diagnostics[0];
        assert_eq!(diagnostic.code, "scheduling.runtime.missing-identity");
        assert_eq!(diagnostic.path, "/identity");
        assert_eq!(diagnostic.source.as_ref().unwrap().line, Some(1));
    }

    #[test]
    fn cfg_check_1_a_rule_reading_a_deferred_expression_is_left_out() {
        let root = canonical_tempdir();
        let mut document = operator_value(&root.path().join("package"), "development-loopback");
        document["listener"]["bind"] = serde_json::json!("${SCHEDULING_OFFLINE_CHECK_UNSET_BIND}");
        // Under operator-controlled-upstream an empty client list is refused;
        // the rule reads the deferred termination, so the check leaves it out.
        document["listener"]["tlsTermination"] =
            serde_json::json!("${SCHEDULING_OFFLINE_CHECK_UNSET_TLS}");
        let path = write_operator(root.path(), document);
        let deferred = check_runtime(&path, None, false);
        assert!(
            deferred.diagnostics.is_empty(),
            "{:?}",
            deferred.diagnostics
        );

        let substituted = check_runtime(&path, None, true);
        let found: Vec<(&str, &str)> = substituted
            .diagnostics
            .iter()
            .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
            .collect();
        assert_eq!(
            found,
            [
                ("config.substitution", "/listener/bind"),
                ("config.substitution", "/listener/tlsTermination"),
            ]
        );
    }

    #[test]
    fn cfg_check_1_a_member_after_a_value_of_two_expressions_is_still_checked() {
        let root = canonical_tempdir();
        let mut document = operator_value(&root.path().join("package"), "development-loopback");
        document["listener"]["bind"] = serde_json::json!(
            "${SCHEDULING_OFFLINE_CHECK_UNSET_HOST}:${SCHEDULING_OFFLINE_CHECK_UNSET_PORT}"
        );
        document["retention"]["hookPayloadRetentionDays"] = serde_json::json!(0);
        let path = write_operator(root.path(), document);
        let check = check_runtime(&path, None, false);
        let found: Vec<(&str, &str)> = check
            .diagnostics
            .iter()
            .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
            .collect();
        assert_eq!(
            found,
            [("config.out-of-range", "/retention/hookPayloadRetentionDays")]
        );
    }

    #[test]
    fn cfg_check_1_the_policy_rules_run_against_the_given_policy() {
        let root = canonical_tempdir();
        let document = operator_value(&root.path().join("package"), "development-loopback");
        let path = write_operator(root.path(), document);
        assert!(check_runtime(&path, None, false).diagnostics.is_empty());

        let policy = SchedulingPolicy::read(
            AUTHORED_POLICY_FILE,
            format!("{POLICY}{OBSERVER}").as_bytes(),
        )
        .unwrap()
        .value;
        let check = check_runtime(&path, Some(&policy), false);
        let found: Vec<(&str, &str)> = check
            .diagnostics
            .iter()
            .map(|diagnostic| (diagnostic.code.as_str(), diagnostic.path.as_str()))
            .collect();
        assert_eq!(
            found,
            [(
                "scheduling.runtime.unbound-hook-destination",
                "/destinations/hooks"
            )]
        );
        assert!(check.diagnostics[0].source.as_ref().unwrap().line.is_some());
    }

    #[test]
    fn a_startup_refusal_reports_every_rule_the_runtime_file_breaks() {
        let root = canonical_tempdir();
        let path = file_breaking_three_rules(root.path());
        let error = RuntimeConfig::load(&path).unwrap_err();
        assert_eq!(error.code(), "scheduling.runtime.invalid-database-id");
        let report = startup_report(&path, &error).expect("a rule of the file");
        assert_eq!(report.error_count(), 3);
        assert!(report.diagnostics().iter().all(|diagnostic| diagnostic
            .source
            .as_ref()
            .unwrap()
            .line
            .is_some()));

        let mut document = operator_value(&root.path().join("package"), "development-loopback");
        document["listener"]["unknownOne"] = serde_json::json!(1);
        document["retention"]["unknownTwo"] = serde_json::json!(2);
        let path = write_operator(root.path(), document);
        let error = RuntimeConfig::load(&path).unwrap_err();
        let report = startup_report(&path, &error).expect("a loader refusal");
        let unknown: Vec<&str> = report
            .diagnostics()
            .iter()
            .map(|diagnostic| diagnostic.path.as_str())
            .collect();
        assert_eq!(unknown, ["/listener/unknownOne", "/retention/unknownTwo"]);
    }

    #[test]
    fn a_package_refusal_is_reported_at_the_package_root_member() {
        let root = canonical_tempdir();
        let document = operator_value(&root.path().join("package"), "development-loopback");
        let path = write_operator(root.path(), document);
        let error = RuntimeConfig::load(&path).expect_err("no package exists");
        assert!(!error.in_file(), "{error}");
        let report = startup_report(&path, &error).expect("a positioned package refusal");
        let [diagnostic] = report.diagnostics() else {
            panic!("one diagnostic expected: {report:?}");
        };
        assert_eq!(diagnostic.code, error.code());
        assert_eq!(diagnostic.path, "/package/root");
        let source = diagnostic.source.as_ref().expect("the file is named");
        assert!(source.line.is_some(), "{source:?}");
        assert!(!diagnostic.suggested_action.is_empty());
    }

    #[test]
    fn an_audit_path_refusal_never_repeats_the_configured_path() {
        let error = RuntimeConfigError::InvalidAuditDestination(
            AuditDestinationError::PathNamesReservedCompanion {
                stream: "registry-scheduling".to_owned(),
                suffix: ".state",
                companion: "state file",
            },
        );
        assert_eq!(error.pointer(), "/audit/path");
        assert!(
            !error.to_string().contains("registry-scheduling"),
            "{error}"
        );
    }
}
