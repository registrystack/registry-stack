// SPDX-License-Identifier: Apache-2.0

//! The operator runtime configuration document and the package it
//! verifies.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use jsonwebtoken::Algorithm;
use registry_platform_audit::{AuditDestination, AuditDestinationError, AuditDestinationKind};
pub(crate) use registry_platform_config::describe_secret_failure;
use registry_platform_config::package::is_envelope_file;
use registry_platform_config::{
    redact_refused_values, reject_environment_expressions_in_authored_yaml, sha256_uri,
    ConfigBlockError, PackageDigestMismatch, PackageError, PackageErrorKind, PackageLimits,
    RemovedKey, RuntimeConfigErrorKind, RuntimeConfigLoader, RuntimeEnvelope, SecretResolver,
    VerifiedPackage, REMOVED_OIDC_JWKS_URI,
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
    parse_policy_yaml, SchedulingPolicy, AUTHORED_POLICY_FILE, SCHEDULING_RUNTIME_API_VERSION,
    SCHEDULING_RUNTIME_KIND,
};
use serde::Deserialize;
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
pub const DEFAULT_ATTEMPT_RECEIPT_DAYS: u16 = 7;

/// The longest a canonical hook envelope may be retained for retry and
/// dead-letter inspection.
pub const MAX_HOOK_PAYLOAD_DAYS: u16 = 30;

/// The most hook destinations one deployment may bind.
pub const MAX_HOOK_DESTINATIONS: usize = 128;

/// The shortest one hook delivery attempt may be bounded to, in milliseconds.
pub const MIN_HOOK_ATTEMPT_TIMEOUT_MILLISECONDS: u32 = 100;

/// The longest one hook delivery attempt may be bounded to, in milliseconds.
pub const MAX_HOOK_ATTEMPT_TIMEOUT_MILLISECONDS: u32 = 10_000;

/// The most delivery attempts a hook destination may allow one event.
pub const MAX_HOOK_ATTEMPTS: u8 = 20;

/// The logical hook destination id grammar `valid_logical_destination_id`
/// checks, as a JSON Schema pattern.
#[cfg(feature = "schema")]
const HOOK_DESTINATION_ID_PATTERN: &str = "^[a-z][a-z0-9_-]{0,63}$";

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
    /// The logical identity of the database this deployment owns. The first
    /// `schedulingctl apply` records it; every later apply and every startup
    /// refuses a database that recorded another.
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
    /// The secret keying the audit journal's hashes, `hashKeyRef`.
    #[serde(flatten)]
    pub key: AuditKeyConfig,
    /// Where audit entries go: a rotated `file` (the default) or `stdout`.
    #[serde(default)]
    pub destination: AuditDestinationKind,
    /// The active audit file. Required for, and only allowed with, `file`.
    #[serde(default)]
    pub path: Option<PathBuf>,
    /// Rotate the active file once it reaches this many bytes (default 100 MiB).
    #[serde(default)]
    pub rotate_bytes: Option<u64>,
    /// Delete rotated files older than this many days (default 90).
    #[serde(default)]
    pub retain_days: Option<u32>,
}

impl AuditConfig {
    /// The destination this configuration names, with the shared defaults.
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
    /// At most 128 are bound, each id a lowercase ASCII letter followed by up
    /// to 63 lowercase letters, digits, `-`, or `_`.
    #[serde(default)]
    #[cfg_attr(
        feature = "schema",
        schemars(extend(
            "maxProperties" = MAX_HOOK_DESTINATIONS,
            "propertyNames" = {"pattern": HOOK_DESTINATION_ID_PATTERN}
        ))
    )]
    pub hooks: BTreeMap<String, HookDestinationConfig>,
}

impl DestinationsConfig {
    /// Refuse a destination the dispatcher does not honour: a reminder URL
    /// outside the destination rules, more than [`MAX_HOOK_DESTINATIONS`]
    /// hook bindings, or a hook binding whose id, URL, attempt timeout, or
    /// attempt count is outside its bounds.
    pub fn check(&self) -> Result<(), RuntimeConfigError> {
        if let Some(reminders) = &self.reminders {
            if !valid_destination_url(&reminders.url) {
                return Err(RuntimeConfigError::InvalidDestination);
            }
        }
        if self.hooks.len() > MAX_HOOK_DESTINATIONS {
            return Err(RuntimeConfigError::InvalidHookDestination);
        }
        for (id, destination) in &self.hooks {
            if !valid_logical_destination_id(id)
                || !valid_destination_url(&destination.url)
                || !destination.within_delivery_budget()
            {
                return Err(RuntimeConfigError::InvalidHookDestination);
            }
        }
        Ok(())
    }
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
    /// How long one delivery attempt may take, from 100 through 10000
    /// milliseconds.
    #[serde(default = "default_hook_attempt_timeout_milliseconds")]
    #[cfg_attr(
        feature = "schema",
        schemars(range(
            min = MIN_HOOK_ATTEMPT_TIMEOUT_MILLISECONDS,
            max = MAX_HOOK_ATTEMPT_TIMEOUT_MILLISECONDS
        ))
    )]
    pub attempt_timeout_milliseconds: u32,
    /// How many delivery attempts one event gets, from 1 through 20.
    #[serde(default = "default_hook_maximum_attempts")]
    #[cfg_attr(feature = "schema", schemars(range(min = 1, max = MAX_HOOK_ATTEMPTS)))]
    pub maximum_attempts: u8,
}

impl HookDestinationConfig {
    /// Whether the attempt timeout and attempt count stay inside the
    /// delivery budget: the bound [`DestinationsConfig::check`] enforces at
    /// load and hook activation enforces again before it binds the
    /// destination.
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
    /// How long a stored idempotency receipt stays replayable, at least one
    /// day.
    #[serde(default = "default_attempt_receipt_days")]
    #[cfg_attr(feature = "schema", schemars(range(min = 1)))]
    pub attempt_receipt_days: u16,
    /// Lifetime of canonical hook envelopes retained for retry and
    /// dead-letter inspection, from one through thirty days.
    #[serde(default = "default_hook_payload_days")]
    #[cfg_attr(feature = "schema", schemars(range(min = 1, max = MAX_HOOK_PAYLOAD_DAYS)))]
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

impl RetentionConfig {
    /// Refuse a period the retention sweep does not honour.
    pub fn check(&self) -> Result<(), RuntimeConfigError> {
        if self.attempt_receipt_days == 0
            || !(1..=MAX_HOOK_PAYLOAD_DAYS).contains(&self.hook_payload_days)
        {
            return Err(RuntimeConfigError::InvalidRetention);
        }
        Ok(())
    }
}

fn default_attempt_receipt_days() -> u16 {
    DEFAULT_ATTEMPT_RECEIPT_DAYS
}

const fn default_hook_payload_days() -> u16 {
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

    /// Read and validate the packaged policy this deployment runs.
    pub fn load_policy(&self) -> Result<LoadedSchedulingPolicy, RuntimeConfigError> {
        let package = verify_scheduling_package(&self.package)?;
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
        // The policy is served only when the text just parsed is the text the
        // package lists; the digest the runtime publishes is the policy's
        // own, not the package's.
        if package.file_digest(AUTHORED_POLICY_FILE).as_deref()
            != Some(sha256_uri(policy_text.as_bytes()).as_str())
        {
            return Err(RuntimeConfigError::PolicyChanged);
        }
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

    pub fn check(&self) -> Result<(), RuntimeConfigError> {
        if self.api_version != SCHEDULING_RUNTIME_API_VERSION
            || self.kind != SCHEDULING_RUNTIME_KIND
        {
            return Err(RuntimeConfigError::InvalidEnvelope);
        }
        let Some(identity) = &self.identity else {
            return Err(RuntimeConfigError::MissingIdentity);
        };
        let database_id = identity.database_id.as_str();
        if database_id.trim().is_empty()
            || database_id.trim() != database_id
            || database_id.len() > MAX_DATABASE_ID_BYTES
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
        self.retention.check()?;
        self.destinations.check()?;
        self.validate_secret_references()?;

        let policy = self.load_policy()?.policy;
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

/// A logical hook destination id is a lowercase ASCII letter followed by up
/// to 63 lowercase letters, digits, `-`, or `_`. The runtime configuration
/// and hook compilation and activation all decide ids with this one check.
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
    #[error(
        "identity.databaseId is required; add\nidentity:\n  databaseId: scheduling-production\nwith the logical id of the database this deployment owns"
    )]
    MissingIdentity,
    #[error(
        "identity.databaseId must be non-empty, at most 256 bytes, without surrounding whitespace or control characters"
    )]
    InvalidIdentity,
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
    #[error(transparent)]
    Package(PackageError),
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
    #[error("authentication.oidc is invalid")]
    InvalidOidc,
    #[error(
        "database.runtimeUrlRef and database.migrationUrlRef must be non-empty secret references"
    )]
    InvalidDatabaseReference,
    #[error("{0}")]
    InvalidAuditDestination(#[source] AuditDestinationError),
    #[error(
        "retention.attemptReceiptDays must be at least one day, and retention.hookPayloadDays from one through thirty days"
    )]
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
            Self::MissingIdentity | Self::InvalidIdentity => "identity.databaseId",
            Self::RelativeOperatedPath(path) => path,
            Self::InvalidOidc | Self::Oidc => "authentication.oidc",
            Self::OidcJwksSecret(_) => "authentication.oidc.jwksSource.documentRef",
            Self::InvalidListener => "listener",
            Self::InvalidDatabaseReference | Self::PlaintextDatabase => "database",
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
            Self::InvalidRetention => "retention",
            Self::InvalidDestination => "destinations.reminders.url",
            Self::InvalidHookDestination | Self::HookDestinationInventoryMismatch => {
                "destinations.hooks"
            }
            Self::PolicyRead(_)
            | Self::PolicyParse { .. }
            | Self::PolicyEnvironmentExpression { .. } => "package.root/scheduling.yaml",
            Self::PolicyChanged => "package.root/scheduling.yaml",
            Self::PolicyFindings
            | Self::Package(_)
            | Self::PackageContents { .. }
            | Self::RetiredPackageManifest => "package.root",
        }
    }
}

fn extra_files(extra: &[String]) -> String {
    if extra.is_empty() {
        String::new()
    } else {
        format!(", not {}", extra.join(", "))
    }
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

    #[test]
    fn a_stdout_destination_accepts_an_explicit_null_path() {
        let audit: AuditConfig = serde_json::from_value(serde_json::json!({
            "hashKeyRef": "secret:env/AUDIT_HASH_KEY",
            "destination": "stdout",
            "path": null
        }))
        .expect("an explicit null is the same absence as an omitted field");
        assert_eq!(
            audit.destination().expect("stdout takes no file settings"),
            AuditDestination::Stdout
        );
    }

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
        let loaded = config.load_policy().expect("policy loads");
        let policy = loaded.policy;
        assert_eq!(policy.scheduling.id, "standalone-exact-time");
    }

    #[test]
    fn identity_database_id_is_required_and_names_the_key_to_add() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        write_policy(&package);
        let mut document = operator_value(&package, "development-loopback");
        document.as_object_mut().unwrap().remove("identity");
        let error = RuntimeConfig::load(write_operator(root.path(), document))
            .expect_err("a configuration without identity is refused");
        assert!(
            matches!(error, RuntimeConfigError::MissingIdentity),
            "{error}"
        );
        assert_eq!(error.path(), "identity.databaseId");
        assert!(
            error.to_string().contains("identity:\n  databaseId:"),
            "{error}"
        );
    }

    #[test]
    fn identity_database_id_is_a_bounded_trimmed_printable_value() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        write_policy(&package);
        let load = |database_id: serde_json::Value| {
            let mut document = operator_value(&package, "development-loopback");
            document["identity"] = serde_json::json!({"databaseId": database_id});
            RuntimeConfig::load(write_operator(root.path(), document))
        };
        let config = load(serde_json::json!("scheduling-production")).expect("valid id");
        assert_eq!(config.database_id(), "scheduling-production");
        load(serde_json::json!("x".repeat(MAX_DATABASE_ID_BYTES)))
            .expect("the bound itself is accepted");
        for invalid in [
            String::new(),
            "   ".to_owned(),
            " scheduling-production".to_owned(),
            "scheduling-production ".to_owned(),
            "scheduling\nproduction".to_owned(),
            "x".repeat(MAX_DATABASE_ID_BYTES + 1),
        ] {
            let error = load(serde_json::json!(invalid)).expect_err("invalid id is refused");
            assert!(
                matches!(error, RuntimeConfigError::InvalidIdentity),
                "{invalid:?}: {error}"
            );
            assert_eq!(error.path(), "identity.databaseId");
        }
        let mut document = operator_value(&package, "development-loopback");
        document["identity"]["extra"] = serde_json::json!("value");
        RuntimeConfig::load(write_operator(root.path(), document))
            .expect_err("identity refuses an unknown key");
    }

    #[test]
    fn the_audit_block_takes_a_file_or_stdout_destination() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        write_policy(&package);
        let audit_file = root.path().join("audit.ndjson");
        let load = |audit: serde_json::Value| {
            let mut document = operator_value(&package, "development-loopback");
            document["audit"] = audit;
            RuntimeConfig::load(write_operator(root.path(), document))
        };

        let config = load(serde_json::json!({
            "path": audit_file,
            "hashKeyRef": "secret:file/audit",
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

        for (audit, path) in [
            (
                serde_json::json!({"destination": "stdout", "path": audit_file}),
                "audit.path",
            ),
            (
                serde_json::json!({"destination": "stdout", "rotateBytes": 1_048_576}),
                "audit.rotateBytes",
            ),
            (
                serde_json::json!({"destination": "stdout", "retainDays": 30}),
                "audit.retainDays",
            ),
            (serde_json::json!({"destination": "file"}), "audit.path"),
            (serde_json::json!({"path": "audit.ndjson"}), "audit.path"),
            (
                serde_json::json!({"path": audit_file, "rotateBytes": 1024}),
                "audit.rotateBytes",
            ),
            (
                serde_json::json!({"path": audit_file, "retainDays": 36_501}),
                "audit.retainDays",
            ),
        ] {
            let mut audit = audit;
            audit["hashKeyRef"] = serde_json::json!("secret:file/audit");
            let error = load(audit.clone()).expect_err("the audit block is refused");
            assert_eq!(error.path(), path, "{audit}: {error}");
        }
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
        assert_eq!(loaded.policy.scheduling.id, "standalone-exact-time");
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
                assert_eq!(error.path(), "package.root", "{tls}: {message}");
                assert!(message.contains(named), "{tls}: {message}");
                assert!(message.contains(PACKAGE_COMMAND), "{tls}: {message}");
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
                serde_json::json!({"hookPayloadDays": 0}),
                RuntimeConfigError::InvalidRetention,
            ),
            (
                serde_json::json!({"hookPayloadDays": MAX_HOOK_PAYLOAD_DAYS + 1}),
                RuntimeConfigError::InvalidRetention,
            ),
            (
                serde_json::json!({"reminders": {"url": "not-a-url"}}),
                RuntimeConfigError::InvalidDestination,
            ),
            (
                serde_json::json!({"hooks": {"Appointment-Events": {
                    "url": "https://events.example.test/scheduling",
                    "hmacSha256KeyRef": "secret:file/hook-key"
                }}}),
                RuntimeConfigError::InvalidHookDestination,
            ),
            (
                serde_json::json!({"hooks": {"appointment-events": {
                    "url": "https://events.example.test/scheduling",
                    "hmacSha256KeyRef": "secret:file/hook-key",
                    "maximumAttempts": MAX_HOOK_ATTEMPTS + 1
                }}}),
                RuntimeConfigError::InvalidHookDestination,
            ),
        ] {
            let mut document = operator_value(&package, "development-loopback");
            if patch.get("attemptReceiptDays").is_some() || patch.get("hookPayloadDays").is_some() {
                document["retention"] = patch;
            } else if patch.get("reminders").is_some() || patch.get("hooks").is_some() {
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
        package_policy(&package, &hooked);
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
        assert!(message.contains("it must be a mapping"), "{message}");
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
        package_policy(
            &package,
            &POLICY.replace(
                "    because: test\nofferings:",
                "    because: ${OPENING_REASON}\nofferings:",
            ),
        );
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
        package_policy(&package, &format!("{POLICY}services: [unterminated\n"));
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
        assert!(matches!(&error, RuntimeConfigError::PackageDigest(_)));
        assert_eq!(error.path(), "package.expectedDigest");
        assert_eq!(
            error.to_string(),
            format!(
                "package.expectedDigest is {expected} but the package at package.root is \
                 {digest}; deploy the pinned package or update package.expectedDigest"
            )
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
        assert!(
            message.contains(&format!("{}:2:1", operator.display())),
            "{message}"
        );
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
            message.contains("/retention/attemptReceiptDays"),
            "{message}"
        );
        assert!(
            message.contains("expected a whole number of days from 0 to 65535"),
            "{message}"
        );
        assert!(!message.contains(canary), "{message}");
    }

    #[test]
    fn a_refused_authored_policy_names_the_member_and_the_cause() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        package_policy(
            &package,
            "scheduling: {id: standalone-exact-time, version: one}\n",
        );
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

    #[test]
    fn a_production_deployment_must_name_the_clients_it_admits() {
        let root = canonical_tempdir();
        let package = root.path().join("package");
        write_policy(&package);

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
