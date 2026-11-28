use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::time::Duration;

use registry_casework_core::{CaseworkProject, ConfigLoadError};
use registry_platform_audit::{
    AuditDestination, AuditDestinationError, AuditDestinationKind, MAX_AUDIT_RETAIN_DAYS,
    MIN_AUDIT_ROTATE_BYTES,
};
pub(crate) use registry_platform_config::describe_secret_failure;
use registry_platform_config::package::is_envelope_file;
use registry_platform_config::{
    sha256_uri, ConfigBlockError, ConfigBlockErrorKind, DatabaseTransportError, DeclaredPosture,
    DevelopmentOnlyRefused, DevelopmentSetting, DevelopmentWitness, FoundSetting,
    LoadedRuntimeConfig, MetricsBindError, PackageConfig, PackageDigestMismatch, PackageError,
    PackageErrorKind, PackageLimits, PostureReport, RemovedKey, RuntimeConfigLoader,
    RuntimeEnvelope, RuntimeFileCheck, SecretReference, SecretResolver, SettingOrigin,
    VerifiedPackage, DEFAULT_STAND_IN, REMOVED_OIDC_JWKS_SOURCE_KIND, REMOVED_OIDC_JWKS_URI,
};
pub use registry_platform_config::{
    AuditKeyConfig, DatabaseConfig, EnvironmentSecretProviderConfig, FileSecretProviderConfig,
    JwksSource, ListenerNetworkExposure, MetricsListenerConfig, OidcClientsConfig,
    OidcIssuerConfig, PrivateListenerConfig as ListenerConfig, SecretProvidersConfig,
    TlsTermination,
};
use registry_platform_httputil::loopback;
use registry_platform_oidc::{
    access_token_typ_set, fetch_discovery_for_issuer, parse_static_jwks, AccessTokenAlgorithm,
    IssuerNetworkPolicy, JwksFetcher, JwksFetcherConfig, OidcDiscoveryConfig, OidcError,
    TokenVerifierConfig,
};
use registry_platform_yaml::{
    escape_pointer_segment, Diagnostic, Report, RetiredApiVersion, Severity,
};
use serde::{Deserialize, Deserializer};
use thiserror::Error;

/// The command that builds a Casework package, named in every package refusal.
pub const PACKAGE_COMMAND: &str = "caseworkctl package";
pub const RUNTIME_CONFIG_API_VERSION: &str =
    "id.registrystack.org/formats/casework/runtime/v1alpha1";
/// The apiVersion an earlier Casework runtime configuration carried.
pub const RETIRED_RUNTIME_CONFIG_API_VERSION: &str =
    "registry.registrystack.org/casework-runtime/v1alpha1";
pub const RUNTIME_CONFIG_KIND: &str = "CaseworkRuntimeConfig";
pub const POLICY_FILE: &str = "casework.yaml";

/// The envelope every Casework runtime configuration carries.
pub const CASEWORK_RUNTIME_ENVELOPE: RuntimeEnvelope = RuntimeEnvelope {
    api_version: RUNTIME_CONFIG_API_VERSION,
    kind: RUNTIME_CONFIG_KIND,
};

/// The apiVersions an earlier Casework runtime configuration carried, each
/// refused with the one that replaced it.
pub const CASEWORK_RETIRED_RUNTIME_API_VERSIONS: &[RetiredApiVersion<'static>] =
    &[RetiredApiVersion {
        api_version: RETIRED_RUNTIME_CONFIG_API_VERSION,
        replacement: "Write apiVersion: id.registrystack.org/formats/casework/runtime/v1alpha1.",
    }];

/// Keys an earlier Casework runtime configuration accepted, each refused with
/// the key that replaced it.
pub const CASEWORK_REMOVED_KEYS: &[RemovedKey] = &[
    REMOVED_OIDC_JWKS_URI,
    REMOVED_OIDC_JWKS_SOURCE_KIND,
    RemovedKey {
        path: "authentication.oidc.principalClaim",
        replacement: "declare accessProfiles.PROFILE_ID.principalClaim in casework.yaml",
    },
    RemovedKey {
        path: "authentication.oidc.deniedKids",
        replacement: "Rename deniedKids to revokedKeyIds",
    },
    RemovedKey {
        path: "audit.retainDays",
        replacement: "Rename audit.retainDays to audit.retentionDays",
    },
    RemovedKey {
        path: "reviewCompletionDestinations.*.bearerTokenRef",
        replacement: "Configure hmacSha256KeyRef with a Standard Webhooks signing key",
    },
    RemovedKey {
        path: "reviewCompletionDestinations.*.auth",
        replacement: "Configure hmacSha256KeyRef with a Standard Webhooks signing key",
    },
    RemovedKey {
        path: "reviewCompletionDestinations.*.timeoutMilliseconds",
        replacement: "Rename timeoutMilliseconds to attemptTimeoutMilliseconds",
    },
    RemovedKey {
        path: "reviewCompletionDestinations.*.retrySeconds",
        replacement: "Rename retrySeconds to retryDelaySeconds",
    },
    RemovedKey {
        path: "package.expectedPolicyDigest",
        replacement: "Write package.expectedDigest, the digest `caseworkctl package` reports.",
    },
];
/// The RFC 9068 access-token media type this runtime verifies. The pair of
/// spellings it admits is derived from this one value, never authored, so no
/// deployment can widen it to an ordinary JWT.
const CASEWORK_ACCESS_TOKEN_TYPE: &str = "at+jwt";
const MAXIMUM_PACKAGE_FILE_BYTES: usize = 1024 * 1024;
/// The largest `audit.rotateBytes` the shared audit writer accepts.
const MAXIMUM_AUDIT_ROTATE_BYTES: u64 = u32::MAX as u64;
pub(crate) const MINIMUM_REVIEW_COMPLETION_TIMEOUT_MILLISECONDS: u64 = 100;
pub(crate) const MAXIMUM_REVIEW_COMPLETION_TIMEOUT_MILLISECONDS: u64 = 30_000;
pub(crate) const MINIMUM_REVIEW_COMPLETION_ATTEMPTS: u32 = 1;
pub(crate) const MAXIMUM_REVIEW_COMPLETION_ATTEMPTS: u32 = 100;
pub(crate) const MINIMUM_REVIEW_COMPLETION_RETRY_SECONDS: u64 = 1;
pub(crate) const MAXIMUM_REVIEW_COMPLETION_RETRY_SECONDS: u64 = 86_400;

/// The bounds a Casework package holds to: each file at most one MiB.
#[must_use]
pub fn package_limits() -> PackageLimits {
    PackageLimits {
        max_file_bytes: MAXIMUM_PACKAGE_FILE_BYTES as u64,
        ..PackageLimits::default()
    }
}

/// The files a Casework package holds besides `SHA256SUMS` and `REVISION`:
/// `casework.yaml`, captured display schemas, and context exports it names.
pub fn package_inputs(
    project: &CaseworkProject,
    policy_bytes: &[u8],
) -> Result<BTreeSet<String>, RuntimeConfigError> {
    let mut inputs = BTreeSet::from([POLICY_FILE.to_owned()]);
    for reference in CaseworkProject::schema_references(POLICY_FILE, policy_bytes)
        .map_err(|report| RuntimeConfigError::Project(ConfigLoadError::Refused(report)))?
    {
        if normalized_relative_path(&reference).is_none() {
            return Err(RuntimeConfigError::ContextExport);
        }
        inputs.insert(reference);
    }
    for provider in &project.context_providers {
        let description = provider
            .description
            .as_ref()
            .ok_or(RuntimeConfigError::ContextExport)?;
        if normalized_relative_path(description).is_none() {
            return Err(RuntimeConfigError::ContextExport);
        }
        inputs.insert(description.clone());
    }
    Ok(inputs)
}

/// Verify the Casework package at `package.root` and its pin. Every listener
/// mode serves a package: a directory without `SHA256SUMS` is refused with the
/// packaging command, whether or not a digest is pinned.
pub fn verify_casework_package(
    package: &RuntimePackageConfig,
    project: &CaseworkProject,
) -> Result<VerifiedPackage, RuntimeConfigError> {
    let verified = verify_casework_envelope(package)?;
    let policy_bytes = capture_verified_file(&package.root, &verified, POLICY_FILE)?;
    verify_casework_contents(project, &policy_bytes, &verified)?;
    Ok(verified)
}

fn verify_casework_envelope(
    package: &RuntimePackageConfig,
) -> Result<VerifiedPackage, RuntimeConfigError> {
    let verified = package
        .shared()
        .verify_package(&package_limits(), PACKAGE_COMMAND)
        .map_err(|error| match error.kind() {
            PackageErrorKind::DigestMismatch(mismatch) => {
                RuntimeConfigError::PackageDigest(mismatch.clone())
            }
            _ => RuntimeConfigError::Package(error),
        })?;
    Ok(verified)
}

fn verify_casework_contents(
    project: &CaseworkProject,
    policy_bytes: &[u8],
    verified: &VerifiedPackage,
) -> Result<(), RuntimeConfigError> {
    let expected = package_inputs(project, policy_bytes)?;
    let found = verified
        .files()
        .filter(|path| !is_envelope_file(path))
        .map(ToOwned::to_owned)
        .collect::<BTreeSet<_>>();
    if found != expected {
        return Err(RuntimeConfigError::PackageContents {
            missing: expected.difference(&found).cloned().collect(),
            extra: found.difference(&expected).cloned().collect(),
        });
    }
    Ok(())
}

#[derive(Debug)]
pub struct LoadedCaseworkPackage {
    digest: String,
    project: CaseworkProject,
    context_exports: BTreeMap<String, Vec<u8>>,
}

impl LoadedCaseworkPackage {
    #[must_use]
    pub fn digest(&self) -> &str {
        &self.digest
    }

    #[must_use]
    pub const fn project(&self) -> &CaseworkProject {
        &self.project
    }

    #[must_use]
    pub fn context_export(&self, path: &str) -> Option<&[u8]> {
        self.context_exports.get(path).map(Vec::as_slice)
    }
}

fn normalized_relative_path(value: &str) -> Option<PathBuf> {
    let path = Path::new(value);
    if value.is_empty() || path.is_absolute() {
        return None;
    }
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::Normal(component) => normalized.push(component),
            _ => return None,
        }
    }
    (normalized.to_str() == Some(value)).then_some(normalized)
}

/// Read a regular file of at most `maximum` bytes, refusing a link.
fn read_bounded_file(path: &Path, maximum: usize) -> Option<Vec<u8>> {
    let metadata = std::fs::symlink_metadata(path).ok()?;
    if !metadata.file_type().is_file() || metadata.len() > maximum as u64 {
        return None;
    }
    std::fs::read(path).ok()
}

fn capture_verified_file(
    root: &Path,
    verified: &VerifiedPackage,
    relative: &str,
) -> Result<Vec<u8>, RuntimeConfigError> {
    let bytes =
        read_bounded_file(&root.join(relative), MAXIMUM_PACKAGE_FILE_BYTES).ok_or_else(|| {
            RuntimeConfigError::PackageFileChanged {
                path: relative.to_owned(),
            }
        })?;
    if verified.file_digest(relative).as_deref() != Some(sha256_uri(&bytes).as_str()) {
        return Err(RuntimeConfigError::PackageFileChanged {
            path: relative.to_owned(),
        });
    }
    Ok(bytes)
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimeConfig {
    pub api_version: String,
    pub kind: String,
    // Required. Optional here only so that a missing block is refused with a
    // diagnostic naming the key to add, rather than a generic parse error; the
    // generated schema lists it as required.
    #[serde(default)]
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
    pub task_authority: Option<TaskAuthorityConfig>,
    /// Provider transport bindings keyed by the deploymentRef `casework.yaml` declares.
    #[serde(
        default,
        deserialize_with = "registry_casework_core::typed::local_id_keys"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(
            with = "BTreeMap<registry_platform_yaml::LocalId, registry_casework_breg::BregBinding>"
        )
    )]
    pub context_providers: BTreeMap<String, registry_casework_breg::BregBinding>,
    /// Completion destinations keyed by the destination id a review producer
    /// names in `casework.yaml`, kept as written.
    #[serde(
        default,
        deserialize_with = "registry_casework_core::typed::external_id_keys"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(
            with = "BTreeMap<registry_platform_yaml::ExternalId, ReviewCompletionRuntimeConfig>"
        )
    )]
    pub review_completion_destinations: BTreeMap<String, ReviewCompletionRuntimeConfig>,
}

/// The longest `identity.databaseId` accepted, in bytes. It matches the bound
/// the Base Registry Engine applies to its own deployment identifiers.
pub const MAX_DATABASE_ID_BYTES: usize = 256;

/// The `identity.databaseId` grammar as a JSON Schema pattern: no control
/// character, and no leading or trailing Unicode whitespace. The schema's
/// `maxLength` counts characters, so the byte bound
/// [`MAX_DATABASE_ID_BYTES`] is enforced only when the document is loaded.
#[cfg(feature = "schema")]
const DATABASE_ID_PATTERN: &str = r"^[^\u0000-\u001f\u007f-\u009f \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000](?:[^\u0000-\u001f\u007f-\u009f]*[^\u0000-\u001f\u007f-\u009f \u00a0\u1680\u2000-\u200a\u2028\u2029\u202f\u205f\u3000])?$";

/// The logical identity of the database this deployment activates packages
/// in. It is chosen by the operator (for example `casework-production`) and
/// never derived from a URL or a PostgreSQL database name. The first
/// `caseworkctl apply` records it, and every later apply and every startup
/// refuses a database whose recorded identity differs.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityConfig {
    #[cfg_attr(
        feature = "schema",
        schemars(length(min = 1, max = MAX_DATABASE_ID_BYTES), regex(pattern = DATABASE_ID_PATTERN))
    )]
    pub database_id: String,
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

pub(crate) const CURRENT_COMPLETION_KEY: &str = "hmacSha256KeyRef";
pub(crate) const PREVIOUS_COMPLETION_KEY: &str = "previousHmacSha256KeyRef";

fn optional_secret_reference<'de, D>(deserializer: D) -> Result<Option<SecretReference>, D::Error>
where
    D: Deserializer<'de>,
{
    SecretReference::deserialize(deserializer).map(Some)
}

fn valid_database_id(value: &str) -> bool {
    !value.trim().is_empty()
        && value.trim() == value
        && value.len() <= MAX_DATABASE_ID_BYTES
        && !value.chars().any(char::is_control)
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewCompletionRuntimeConfig {
    #[serde(deserialize_with = "registry_casework_core::typed::url")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Url"))]
    pub url: String,
    /// Exact bytes of the current Standard Webhooks signing key.
    pub hmac_sha256_key_ref: SecretReference,
    /// Exact bytes of the previous signing key during rotation.
    #[serde(default, deserialize_with = "optional_secret_reference")]
    pub previous_hmac_sha256_key_ref: Option<SecretReference>,
    #[serde(
        default = "default_review_completion_timeout_ms",
        deserialize_with = "registry_casework_core::typed::bounded_u64::<_, MINIMUM_REVIEW_COMPLETION_TIMEOUT_MILLISECONDS, MAXIMUM_REVIEW_COMPLETION_TIMEOUT_MILLISECONDS>"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(range(
            min = MINIMUM_REVIEW_COMPLETION_TIMEOUT_MILLISECONDS,
            max = MAXIMUM_REVIEW_COMPLETION_TIMEOUT_MILLISECONDS
        ))
    )]
    pub attempt_timeout_milliseconds: u64,
    #[serde(
        default = "default_review_completion_attempts",
        deserialize_with = "registry_casework_core::typed::bounded_u32::<_, MINIMUM_REVIEW_COMPLETION_ATTEMPTS, MAXIMUM_REVIEW_COMPLETION_ATTEMPTS>"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(range(
            min = MINIMUM_REVIEW_COMPLETION_ATTEMPTS,
            max = MAXIMUM_REVIEW_COMPLETION_ATTEMPTS
        ))
    )]
    pub maximum_attempts: u32,
    #[serde(
        default = "default_review_completion_retry_seconds",
        deserialize_with = "registry_casework_core::typed::bounded_u64::<_, MINIMUM_REVIEW_COMPLETION_RETRY_SECONDS, MAXIMUM_REVIEW_COMPLETION_RETRY_SECONDS>"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(range(
            min = MINIMUM_REVIEW_COMPLETION_RETRY_SECONDS,
            max = MAXIMUM_REVIEW_COMPLETION_RETRY_SECONDS
        ))
    )]
    pub retry_delay_seconds: u64,
}

fn default_review_completion_timeout_ms() -> u64 {
    5_000
}
fn default_review_completion_attempts() -> u32 {
    12
}
fn default_review_completion_retry_seconds() -> u64 {
    30
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TaskAuthorityConfig {
    #[serde(deserialize_with = "registry_casework_core::typed::url")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Url"))]
    pub issuer: String,
    pub exchange_audience: String,
    #[serde(deserialize_with = "secret_reference")]
    #[cfg_attr(feature = "schema", schemars(with = "SecretReference"))]
    pub signing_key_ref: String,
    /// Service client IDs mapped to their one protected resource audience.
    #[serde(deserialize_with = "registry_casework_core::typed::external_id_keys")]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "BTreeMap<registry_platform_yaml::ExternalId, String>")
    )]
    pub status_clients: BTreeMap<String, String>,
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RuntimePackageConfig {
    /// Absolute path of the package directory.
    pub root: PathBuf,
    /// `sha256:` label of the package digest, the digest of the package's
    /// `SHA256SUMS` file. When set, the runtime refuses to start on any other
    /// package, and on an authored project that has no `SHA256SUMS`.
    /// Omitted, the runtime starts on whichever package `root` holds.
    #[serde(
        default,
        deserialize_with = "registry_casework_core::typed::optional_digest"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(with = "Option<registry_platform_yaml::Digest>")
    )]
    pub expected_digest: Option<String>,
}

impl RuntimePackageConfig {
    /// The shared `package.root` and `package.expectedDigest` block.
    #[must_use]
    pub fn shared(&self) -> PackageConfig {
        PackageConfig {
            root: self.root.clone(),
            expected_digest: self.expected_digest.clone(),
        }
    }
}

/// Check the operator-private listener for `/metrics` and `/version`.
///
/// It is separate from the API listener so the counters and the active
/// package digest never appear on the surface the public contract describes.
fn validate_metrics_listener(
    metrics: MetricsListenerConfig,
    listener: &ListenerConfig,
) -> Result<(), RuntimeConfigError> {
    let bind = metrics.bind.socket_addr();
    registry_platform_config::check_metrics_bind_address(bind, metrics.network_exposure)
        .map_err(RuntimeConfigError::InvalidMetricsListener)?;
    registry_platform_config::check_metrics_bind_apart(
        bind,
        &[("listener", listener.bind.socket_addr())],
    )
    .map_err(RuntimeConfigError::MetricsListenerSharesSocket)
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthenticationConfig {
    pub oidc: OidcConfig,
}

/// The access tokens this runtime accepts: the issuer and its keys, the
/// clients admitted, the scope claim, and the claim that marks a human actor.
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
    /// a subject token from, keyed by client identifier. An empty
    /// `assertionIssuers` map applies no rule; see
    /// [`registry_platform_oidc::TokenVerifierConfig::assertion_issuers`].
    #[serde(rename(deserialize = "registry-platform-yaml/shared-block/oidc-clients"))]
    #[cfg_attr(feature = "schema", schemars(flatten))]
    pub clients: OidcClientsConfig,
    #[serde(default = "default_scope_claim")]
    pub scope_claim: String,
    #[serde(default)]
    pub human_identity: HumanIdentityConfig,
    /// Signing-key identifiers Casework refuses locally, even while the issuer
    /// still publishes them; listing a key does not revoke it at the issuer.
    /// Omitted, no key is refused; written, the list is non-empty.
    #[serde(default, deserialize_with = "present_revoked_key_ids")]
    pub revoked_key_ids: Option<RevokedKeyIds>,
    /// Optional deployment bound on the lifetime declared by an incoming
    /// access token, independently of the issuer's own policy.
    #[serde(
        default,
        deserialize_with = "registry_casework_core::typed::optional_bounded_u64::<_, 1, 7_200>"
    )]
    #[cfg_attr(feature = "schema", schemars(range(min = 1, max = 7_200)))]
    pub maximum_token_lifetime_seconds: Option<u64>,
    /// Explicitly opted-in delegated staff readers, keyed by the policy id a
    /// dedicated read client sends. Absence disables delegated staff reads.
    #[serde(
        default,
        deserialize_with = "optional_delegated_staff_readers",
        skip_serializing_if = "Option::is_none"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(
            with = "Option<BTreeMap<registry_platform_yaml::LocalId, DelegatedStaffReaderConfig>>"
        )
    )]
    pub delegated_staff_readers: Option<BTreeMap<String, DelegatedStaffReaderConfig>>,
}

static UNRESTRICTED_CLIENTS: DevelopmentSetting = DevelopmentSetting {
    code: "casework.posture.unrestricted-clients",
    key: "allowedClients",
    summary: "every client the issuer admits is accepted",
    production: "List the clients the deployment admits.",
};

const ALLOWED_CLIENTS_POINTER: &str = "/authentication/oidc/allowedClients";

fn unrestricted_clients_setting(check: &RuntimeFileCheck<RuntimeConfig>) -> Option<FoundSetting> {
    let clients = &check.loaded.as_ref()?.config.authentication.oidc.clients;
    if !clients.allowed_clients.is_empty() {
        return None;
    }
    let source = check
        .error_at(RUNTIME_CONFIG_KIND, "", ALLOWED_CLIENTS_POINTER, "", "")
        .source;
    let position = source.and_then(|source| {
        Some(registry_platform_yaml::Position {
            line: source.line?,
            column: source.column?,
        })
    });
    Some(FoundSetting {
        setting: &UNRESTRICTED_CLIENTS,
        pointer: Some(ALLOWED_CLIENTS_POINTER.to_owned()),
        position,
        origin: SettingOrigin::RuntimeFile,
    })
}

fn optional_delegated_staff_readers<'de, D>(
    deserializer: D,
) -> Result<Option<BTreeMap<String, DelegatedStaffReaderConfig>>, D::Error>
where
    D: Deserializer<'de>,
{
    registry_casework_core::typed::local_id_keys(deserializer).map(Some)
}

/// One deployment-owned delegation ceiling. The policy id is the containing
/// map key, never a human profile supplied by the HTTP caller.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DelegatedStaffReaderConfig {
    #[serde(deserialize_with = "registry_casework_core::typed::local_id")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::LocalId"))]
    pub profile: String,
    pub client: String,
    pub actor_subject: String,
    #[serde(deserialize_with = "registry_casework_core::typed::url")]
    #[cfg_attr(feature = "schema", schemars(with = "registry_platform_yaml::Url"))]
    pub assertion_issuer: String,
    pub required_scope: String,
    #[serde(deserialize_with = "registry_casework_core::typed::bounded_u64::<_, 1, 300>")]
    #[cfg_attr(feature = "schema", schemars(range(min = 1, max = 300)))]
    pub maximum_token_lifetime_seconds: u64,
    #[serde(
        default,
        deserialize_with = "optional_delegated_source_profiles",
        skip_serializing_if = "Vec::is_empty"
    )]
    #[cfg_attr(
        feature = "schema",
        schemars(
            with = "registry_platform_yaml::UniqueList<registry_platform_yaml::LocalId>",
            length(min = 1, max = 32)
        )
    )]
    pub source_profiles: Vec<String>,
}

fn optional_delegated_source_profiles<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    registry_platform_yaml::UniqueList::<registry_platform_yaml::LocalId>::deserialize(deserializer)
        .and_then(|profiles| {
            if profiles.is_empty() || profiles.len() > 32 {
                return Err(serde::de::Error::custom(
                    "sourceProfiles must contain from 1 through 32 distinct local identifiers",
                ));
            }
            Ok(profiles
                .into_iter()
                .map(registry_platform_yaml::LocalId::into_string)
                .collect())
        })
}

/// An empty list is not how the file says "refuse no key" (CFG-EMPTY-2):
/// omitting the member says it.
fn present_revoked_key_ids<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<RevokedKeyIds>, D::Error> {
    RevokedKeyIds::deserialize(deserializer).map(Some)
}

/// A written list of refused keys: distinct external key identifiers with a
/// bounded deployment size. Absence, rather than an empty list, means refuse
/// no key.
#[derive(Clone, Debug)]
pub struct RevokedKeyIds(registry_platform_yaml::UniqueList<registry_platform_yaml::ExternalId>);

impl<'de> Deserialize<'de> for RevokedKeyIds {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let kids =
            registry_platform_yaml::UniqueList::<registry_platform_yaml::ExternalId>::deserialize(
                deserializer,
            )?;
        if kids.is_empty() {
            return Err(registry_platform_yaml::Invalid::expected(
                "at least one key identifier",
                "List at least one key identifier to refuse, or delete revokedKeyIds to refuse no key.",
            )
            .into_error());
        }
        if kids.len() > 128 {
            return Err(registry_platform_yaml::Invalid::expected(
                "at most 128 key identifiers",
                "Remove key identifiers from revokedKeyIds until it lists at most 128.",
            )
            .into_error());
        }
        Ok(Self(kids))
    }
}

#[cfg(feature = "schema")]
impl schemars::JsonSchema for RevokedKeyIds {
    fn inline_schema() -> bool {
        true
    }

    fn schema_name() -> std::borrow::Cow<'static, str> {
        "RevokedKeyIds".into()
    }

    fn json_schema(generator: &mut schemars::SchemaGenerator) -> schemars::Schema {
        let mut schema = generator.subschema_for::<
            registry_platform_yaml::UniqueList<registry_platform_yaml::ExternalId>,
        >();
        schema.insert("minItems".to_owned(), 1.into());
        schema.insert("maxItems".to_owned(), 128.into());
        schema
    }
}

#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HumanIdentityConfig {
    #[serde(default = "default_human_identity_claim")]
    pub claim: String,
    #[serde(default = "default_human_identity_value")]
    pub value: String,
}

impl Default for HumanIdentityConfig {
    fn default() -> Self {
        Self {
            claim: default_human_identity_claim(),
            value: default_human_identity_value(),
        }
    }
}

fn default_scope_claim() -> String {
    "registry_scopes".to_owned()
}
fn default_human_identity_claim() -> String {
    "registry_actor_kind".to_owned()
}
fn default_human_identity_value() -> String {
    "human".to_owned()
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
        deserialize_with = "registry_casework_core::typed::optional_bounded_u64::<_, MIN_AUDIT_ROTATE_BYTES, MAXIMUM_AUDIT_ROTATE_BYTES>"
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
        deserialize_with = "registry_casework_core::typed::optional_bounded_u32::<_, 1, MAX_AUDIT_RETAIN_DAYS>"
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

impl RuntimeConfig {
    /// Load and validate the operator document, reading the authored project
    /// and its package beside it.
    pub fn load(
        path: impl AsRef<Path>,
        declared: DeclaredPosture,
    ) -> Result<LoadedRuntimeConfig<Self>, RuntimeConfigError> {
        let loaded = Self::load_file(path.as_ref(), declared)?;
        loaded.config.check()?;
        Ok(loaded)
    }

    /// Decode and enforce posture before any package or dependency is opened.
    pub fn load_file(
        path: &Path,
        declared: DeclaredPosture,
    ) -> Result<LoadedRuntimeConfig<Self>, RuntimeConfigError> {
        // The offline reader with substitutions enabled decodes once under the
        // same file rules and leaves the decision to the combined report.
        let mut check = Self::loader(declared).check_offline::<Self>(path, true, stand_in_for);
        let setting = unrestricted_clients_setting(&check);
        let Some(mut loaded) = check.loaded.take() else {
            return Err(RuntimeConfigError::ReadReport(Report::new(
                check.diagnostics,
            )));
        };
        if let Some(setting) = setting {
            loaded.posture.record(setting);
        }
        loaded.posture.decide(path)?;
        Ok(loaded)
    }

    /// The shared runtime configuration loader under Casework's envelope,
    /// removed keys, and retired apiVersions.
    #[must_use]
    pub const fn loader(declared: DeclaredPosture) -> RuntimeConfigLoader {
        RuntimeConfigLoader::new(CASEWORK_RUNTIME_ENVELOPE, declared)
            .removed_keys(CASEWORK_REMOVED_KEYS)
            .retired_api_versions(CASEWORK_RETIRED_RUNTIME_API_VERSIONS)
            .require_trusted_ownership()
    }

    #[must_use]
    pub fn policy_path(&self) -> PathBuf {
        self.package.root.join(POLICY_FILE)
    }

    /// Refuse the first rule this file breaks on its own, then verify the
    /// package at `package.root` and refuse the first rule the file breaks
    /// against the project that package holds.
    pub fn check(&self) -> Result<(), RuntimeConfigError> {
        first(self.findings(None))?;
        let package = self.capture_package_after_verification(|| {})?;
        self.check_against_project(package.project())
    }

    /// Refuse the first rule this file breaks against `project`, the project
    /// its package holds.
    pub fn check_against_project(
        &self,
        project: &CaseworkProject,
    ) -> Result<(), RuntimeConfigError> {
        let mut findings = Vec::new();
        for rule in PROJECT_RULES {
            rule(self, project, &mut findings);
        }
        first(findings)
    }

    /// Every rule this file breaks, in the order startup applies them. The
    /// rules about the project the file binds run when `project` is given.
    /// Each finding names the member it concerns and never a configured
    /// value.
    #[must_use]
    pub fn findings(&self, project: Option<&CaseworkProject>) -> Vec<RuntimeConfigError> {
        let mut findings = Vec::new();
        for rule in FILE_RULES {
            rule(self, &mut findings);
        }
        if let Some(project) = project {
            for rule in PROJECT_RULES {
                rule(self, project, &mut findings);
            }
        }
        findings
    }

    /// The operator-chosen database identity. Empty only on a document that
    /// [`RuntimeConfig::check`] has not accepted.
    #[must_use]
    pub fn database_id(&self) -> &str {
        self.identity
            .as_ref()
            .map_or("", |identity| identity.database_id.as_str())
    }

    /// Verify the package at `package.root` again and return its digest.
    pub fn package_digest(&self) -> Result<String, RuntimeConfigError> {
        Ok(self.load_package()?.digest)
    }

    /// Verify, validate, and capture the exact package bytes a consumer will use.
    pub fn load_package(&self) -> Result<LoadedCaseworkPackage, RuntimeConfigError> {
        self.load_package_after_verification(|| {})
    }

    fn load_package_after_verification(
        &self,
        after_verification: impl FnOnce(),
    ) -> Result<LoadedCaseworkPackage, RuntimeConfigError> {
        let package = self.capture_package_after_verification(after_verification)?;
        self.check_against_project(package.project())?;
        Ok(package)
    }

    fn capture_package_after_verification(
        &self,
        after_verification: impl FnOnce(),
    ) -> Result<LoadedCaseworkPackage, RuntimeConfigError> {
        let verified = verify_casework_envelope(&self.package)?;
        after_verification();

        let policy_bytes = capture_verified_file(&self.package.root, &verified, POLICY_FILE)?;
        let schema_references = CaseworkProject::schema_references(POLICY_FILE, &policy_bytes)
            .map_err(|report| RuntimeConfigError::Project(ConfigLoadError::Refused(report)))?;
        let schemas = schema_references
            .into_iter()
            .map(|reference| {
                let bytes = capture_verified_file(&self.package.root, &verified, &reference)?;
                Ok((reference, bytes))
            })
            .collect::<Result<BTreeMap<_, _>, RuntimeConfigError>>()?;
        let project = CaseworkProject::read_with_schemas(POLICY_FILE, &policy_bytes, &schemas)
            .map(|decoded| decoded.value)
            .map_err(|report| RuntimeConfigError::Project(ConfigLoadError::Refused(report)))?;
        verify_casework_contents(&project, &policy_bytes, &verified)?;

        let mut context_exports = BTreeMap::new();
        for provider in &project.context_providers {
            let Some(path) = &provider.description else {
                continue;
            };
            let bytes = capture_verified_file(&self.package.root, &verified, path)?;
            let export: registry_casework_breg::BregContextExport =
                serde_json::from_slice(&bytes).map_err(|_| RuntimeConfigError::ContextExport)?;
            export
                .check()
                .map_err(|_| RuntimeConfigError::ContextExport)?;
            if export.source_namespace != provider.source_namespace || project.review_policies.iter().any(|policy| {
                matches!(&policy.context, registry_casework_core::ReviewContextPolicy::CurrentSource { provider: id, contract } if id == &provider.id && contract != &export.contract)
            }) {
                return Err(RuntimeConfigError::ContextExport);
            }
            context_exports.insert(path.clone(), bytes);
        }

        Ok(LoadedCaseworkPackage {
            digest: verified.digest().to_owned(),
            project,
            context_exports,
        })
    }

    fn check_envelope(&self, findings: &mut Vec<RuntimeConfigError>) {
        if self.api_version != RUNTIME_CONFIG_API_VERSION {
            findings.push(RuntimeConfigError::InvalidApiVersion);
        }
        if self.kind != RUNTIME_CONFIG_KIND {
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

    fn check_identifier_collisions(&self, findings: &mut Vec<RuntimeConfigError>) {
        if !registry_platform_yaml::lookalike_local_id_pairs(
            self.context_providers.keys().map(String::as_str),
        )
        .is_empty()
        {
            findings.push(RuntimeConfigError::ContextProviderIdCollision);
        }
    }

    fn check_package_block(&self, findings: &mut Vec<RuntimeConfigError>) {
        if let Err(error) = self.package.shared().check() {
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

    fn direct_secret_references(&self) -> Vec<(String, &str)> {
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
        if let Some(authority) = &self.task_authority {
            references.push((
                "taskAuthority.signingKeyRef".to_owned(),
                authority.signing_key_ref.as_str(),
            ));
        }
        references
    }

    fn binding_secret_references(&self) -> Vec<(Vec<&str>, &str)> {
        let mut references = Vec::new();
        for (source_id, binding) in &self.context_providers {
            for (member, reference) in [
                ("clientIdRef", &binding.client_id_ref),
                ("clientAssertionKeyRef", &binding.client_assertion_key_ref),
            ] {
                references.push((
                    vec!["contextProviders", source_id.as_str(), member],
                    reference.as_str(),
                ));
            }
            if let Some(delegated) = &binding.delegated_display_exchange {
                for (member, reference) in [
                    ("clientIdRef", &delegated.client_id_ref),
                    ("clientAssertionKeyRef", &delegated.client_assertion_key_ref),
                ] {
                    references.push((
                        vec![
                            "contextProviders",
                            source_id.as_str(),
                            "delegatedDisplayExchange",
                            member,
                        ],
                        reference.as_str(),
                    ));
                }
            }
        }
        references
    }

    fn completion_key_references(&self) -> impl Iterator<Item = ([&str; 3], &SecretReference)> {
        self.review_completion_destinations
            .iter()
            .flat_map(|(id, destination)| {
                [
                    (
                        CURRENT_COMPLETION_KEY,
                        Some(&destination.hmac_sha256_key_ref),
                    ),
                    (
                        PREVIOUS_COMPLETION_KEY,
                        destination.previous_hmac_sha256_key_ref.as_ref(),
                    ),
                ]
                .into_iter()
                .filter_map(move |(member, reference)| {
                    reference.map(|reference| {
                        (
                            ["reviewCompletionDestinations", id.as_str(), member],
                            reference,
                        )
                    })
                })
            })
    }

    /// Resolve serving secrets without contacting their consumers or retaining
    /// their values. Migration credentials may remain off the serving host and
    /// are resolved only by `caseworkctl apply`. This checks provider and file
    /// availability, bounded secret material, and completion signing key policy.
    pub fn check_runtime_secrets(&self, resolver: &SecretResolver) -> Result<(), Report> {
        let references =
            self.direct_secret_references()
                .into_iter()
                .filter(|(field, _)| field != "database.migrationUrlRef")
                .map(|(field, reference)| {
                    let pointer = pointer_to(&field.split('.').collect::<Vec<_>>());
                    (field, pointer, reference)
                })
                .chain(self.binding_secret_references().into_iter().map(
                    |(segments, reference)| (segments.join("."), pointer_to(&segments), reference),
                ));
        let mut diagnostics = Vec::new();
        for (field, pointer, reference) in references {
            if let Err(error) = resolver.resolve(reference) {
                diagnostics.push(Diagnostic::error(
                    "casework.runtime.secret-unavailable",
                    pointer,
                    describe_secret_failure(&field, reference, &error),
                    "Provision a runtime-readable secret through the configured provider and retry doctor.",
                ));
            }
        }
        if let Err(errors) = crate::runtime::review_completion_targets(
            &self.review_completion_destinations,
            resolver,
        ) {
            use crate::runtime::CompletionKeyError;

            for error in errors {
                let (field, code) = match &error {
                    CompletionKeyError::Unavailable { path, .. } => {
                        (path, "casework.runtime.secret-unavailable")
                    }
                    CompletionKeyError::Invalid { path, .. }
                    | CompletionKeyError::Repeated { second: path, .. }
                    | CompletionKeyError::PreviousEqualsCurrent { previous: path, .. } => {
                        (path, "casework.runtime.invalid-completion-key")
                    }
                };
                let (section, field) = field.split_once('.').expect("completion key section");
                let (destination, member) = field.rsplit_once('.').expect("completion key member");
                diagnostics.push(Diagnostic::error(
                    code,
                    pointer_to(&[section, destination, member]),
                    error.to_string(),
                    "Retry doctor after correcting the completion signing key configuration.",
                ));
            }
        }
        if diagnostics.is_empty() {
            Ok(())
        } else {
            Err(Report::new(diagnostics))
        }
    }

    fn check_secret_references(&self, findings: &mut Vec<RuntimeConfigError>) {
        // With no provider enabled every reference would be refused; the
        // provider rule reports that once.
        if self.secret_providers.check().is_err() {
            return;
        }
        for (field, raw) in self.direct_secret_references() {
            if let Err(error) = self.secret_providers.check_reference(&field, raw) {
                findings.push(error.into());
            }
        }
        for (segments, raw) in self.binding_secret_references() {
            self.check_binding_reference(findings, &segments, raw);
        }
        for (segments, reference) in self.completion_key_references() {
            self.check_binding_reference(findings, &segments, reference.as_str());
        }
    }

    /// Check one secret reference of a member under a map keyed by an id the
    /// operator chose, located structurally so a key holding `.` or `/`
    /// still points at its member.
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
        if let Some(metrics_listener) = &self.metrics_listener {
            if let Err(error) = validate_metrics_listener(*metrics_listener, &self.listener) {
                findings.push(error);
            }
        }
    }

    fn check_oidc(&self, findings: &mut Vec<RuntimeConfigError>) {
        let oidc = &self.authentication.oidc;
        if let Err(error) = oidc.provider.check("authentication.oidc") {
            findings.push(error.into());
        }
        if let Err(error) = oidc.clients.check("authentication.oidc") {
            findings.push(error.into());
        }
        for (path, value) in [
            ("authentication.oidc.scopeClaim", &oidc.scope_claim),
            (
                "authentication.oidc.humanIdentity.claim",
                &oidc.human_identity.claim,
            ),
            (
                "authentication.oidc.humanIdentity.value",
                &oidc.human_identity.value,
            ),
        ] {
            if value.is_empty() {
                findings.push(RuntimeConfigError::InvalidOidcClaim {
                    path,
                    reason: "must not be empty",
                });
            }
        }
        if !oidc.scope_claim.is_empty() && oidc.human_identity.claim == oidc.scope_claim {
            findings.push(RuntimeConfigError::InvalidOidcClaim {
                path: "authentication.oidc.humanIdentity.claim",
                reason: "must differ from authentication.oidc.scopeClaim",
            });
        }
        if let Some(readers) = &oidc.delegated_staff_readers {
            if readers.is_empty() {
                findings.push(delegated_staff_reader_finding(
                    &["authentication", "oidc", "delegatedStaffReaders"],
                    "must not be empty when written",
                    "Delete delegatedStaffReaders to disable delegated reads, or name at least one reader policy.",
                ));
            }
            for (policy, reader) in readers {
                let base = [
                    "authentication",
                    "oidc",
                    "delegatedStaffReaders",
                    policy.as_str(),
                ];
                if !oidc.clients.allowed_clients.contains(&reader.client) {
                    let mut path = base.to_vec();
                    path.push("client");
                    findings.push(delegated_staff_reader_finding(
                        &path,
                        "must be named by authentication.oidc.allowedClients",
                        "Add this exact client to allowedClients; unrestricted client admission cannot enable delegated staff reads.",
                    ));
                }
                if oidc
                    .clients
                    .assertion_issuers
                    .get(&reader.client)
                    .is_none_or(|issuers| !issuers.contains(&reader.assertion_issuer))
                {
                    let mut path = base.to_vec();
                    path.push("assertionIssuer");
                    findings.push(delegated_staff_reader_finding(
                        &path,
                        "must be listed for this client by authentication.oidc.assertionIssuers",
                        "Bind the client to this exact subject-token issuer in assertionIssuers.",
                    ));
                }
                for (member, value) in [
                    ("client", reader.client.as_str()),
                    ("actorSubject", reader.actor_subject.as_str()),
                ] {
                    if registry_platform_yaml::ExternalId::new(value).is_err() {
                        let mut path = base.to_vec();
                        path.push(member);
                        findings.push(delegated_staff_reader_finding(
                            &path,
                            "must be a bounded external identifier",
                            "Write the exact non-empty identifier issued in the verified token.",
                        ));
                    }
                }
                if !valid_delegated_scope(&reader.required_scope) {
                    let mut path = base.to_vec();
                    path.push("requiredScope");
                    findings.push(delegated_staff_reader_finding(
                        &path,
                        "must be one bounded OAuth scope without whitespace",
                        "Name one distinct scope issued only for delegated staff reads.",
                    ));
                }
                if oidc
                    .maximum_token_lifetime_seconds
                    .is_some_and(|maximum| reader.maximum_token_lifetime_seconds > maximum)
                {
                    let mut path = base.to_vec();
                    path.push("maximumTokenLifetimeSeconds");
                    findings.push(delegated_staff_reader_finding(
                        &path,
                        "must not exceed authentication.oidc.maximumTokenLifetimeSeconds",
                        "Lower this delegated-reader lifetime or raise the deployment-wide bound without exceeding 300 seconds.",
                    ));
                }
            }
        }
    }

    fn check_database(&self, findings: &mut Vec<RuntimeConfigError>) {
        if self.database.runtime_url_ref.is_empty() || self.database.migration_url_ref.is_empty() {
            findings.push(RuntimeConfigError::InvalidDatabaseReference);
        }
        if let Err(error) = self.database.check(cfg!(feature = "postgres-test")) {
            findings.push(RuntimeConfigError::DatabaseTransport(error));
        }
    }

    fn check_review_completion_destinations(&self, findings: &mut Vec<RuntimeConfigError>) {
        for (destination_id, destination) in &self.review_completion_destinations {
            if destination_id.is_empty() {
                findings.push(RuntimeConfigError::InvalidReviewCompletionDestination {
                    path: "reviewCompletionDestinations".to_owned(),
                    pointer: "/reviewCompletionDestinations".to_owned(),
                    reason: "must not hold an empty destination id",
                });
            }
            if !valid_review_completion_url(&destination.url) {
                let segments = ["reviewCompletionDestinations", destination_id, "url"];
                findings.push(RuntimeConfigError::InvalidReviewCompletionDestination {
                    path: segments.join("."),
                    pointer: pointer_to(&segments),
                    reason: "must be an https URL with a host, or an http URL on a loopback literal (127.0.0.0/8, ::1 or ::ffff:127.0.0.0/104), without userinfo, query, or fragment",
                });
            }
        }
    }

    /// Refuses a context-provider binding that provider construction would
    /// refuse, at the member that breaks the rule, without resolving a secret.
    fn check_context_providers(&self, findings: &mut Vec<RuntimeConfigError>) {
        for (deployment, binding) in &self.context_providers {
            if binding
                .human_source_authentication
                .as_ref()
                .is_some_and(|auth| auth.audience == self.authentication.oidc.provider.audience)
            {
                findings.push(RuntimeConfigError::InvalidContextProvider {
                    path: format!(
                        "contextProviders.{deployment}.humanSourceAuthentication.audience"
                    ),
                    pointer: pointer_to(&[
                        "contextProviders",
                        deployment,
                        "humanSourceAuthentication",
                        "audience",
                    ]),
                    reason: "must differ from the Casework audience".to_owned(),
                });
            }
            let Err(refusal) = binding.check_offline() else {
                continue;
            };
            let mut segments = vec!["contextProviders", deployment.as_str()];
            segments.extend(refusal.member.split('/').skip(1));
            findings.push(RuntimeConfigError::InvalidContextProvider {
                path: segments.join("."),
                pointer: pointer_to(&segments),
                reason: refusal.reason,
            });
        }
    }

    fn check_principal_claims(
        &self,
        project: &CaseworkProject,
        findings: &mut Vec<RuntimeConfigError>,
    ) {
        if project
            .access_profiles
            .iter()
            .any(|profile| profile.principal_claim == self.authentication.oidc.human_identity.claim)
        {
            findings.push(RuntimeConfigError::PrincipalClaimConflict);
        }
    }

    fn check_delegated_staff_readers(
        &self,
        project: &CaseworkProject,
        findings: &mut Vec<RuntimeConfigError>,
    ) {
        let Some(readers) = &self.authentication.oidc.delegated_staff_readers else {
            return;
        };
        for (policy, reader) in readers {
            let base = [
                "authentication",
                "oidc",
                "delegatedStaffReaders",
                policy.as_str(),
            ];
            let Some(profile) = project
                .access_profiles
                .iter()
                .find(|profile| profile.id == reader.profile)
            else {
                let mut path = base.to_vec();
                path.push("profile");
                findings.push(delegated_staff_reader_finding(
                    &path,
                    "must name an access profile in casework.yaml",
                    "Name one existing Staff profile.",
                ));
                continue;
            };
            if profile.acts_as != registry_casework_core::CaseworkActsAs::Staff {
                let mut path = base.to_vec();
                path.push("profile");
                findings.push(delegated_staff_reader_finding(
                    &path,
                    "must name a Staff profile",
                    "Use a Staff profile; delegated Supervisor, Administrator and Requester authority is refused.",
                ));
            }
            if profile
                .required_scopes
                .iter()
                .any(|scope| scope == &reader.required_scope)
            {
                let mut path = base.to_vec();
                path.push("requiredScope");
                findings.push(delegated_staff_reader_finding(
                    &path,
                    "must be distinct from the profile's human scopes",
                    "Issue a separate scope used only by this delegated reader policy.",
                ));
            }
            let current_source_deployments = project
                .review_policies
                .iter()
                .filter(|review_policy| {
                    review_policy.stages.iter().any(|stage| {
                        stage
                            .deciding_profiles
                            .iter()
                            .any(|candidate| candidate == &reader.profile)
                    })
                })
                .filter_map(|review_policy| {
                    let registry_casework_core::ReviewContextPolicy::CurrentSource {
                        provider, ..
                    } = &review_policy.context
                    else {
                        return None;
                    };
                    project
                        .context_providers
                        .iter()
                        .find(|candidate| candidate.id == provider.as_str())
                        .map(|provider| provider.deployment_ref.as_str())
                })
                .collect::<BTreeSet<_>>();
            if reader.source_profiles.is_empty() && !current_source_deployments.is_empty() {
                let mut path = base.to_vec();
                path.push("sourceProfiles");
                findings.push(delegated_staff_reader_finding(
                    &path,
                    "is required when this Staff profile can decide current-source review work",
                    "List the source disclosure profiles this reader may use, or remove this Staff profile from every current-source review stage it must not read.",
                ));
            } else if let Some(deployment_ref) =
                current_source_deployments
                    .iter()
                    .copied()
                    .find(|deployment_ref| {
                        !reader.source_profiles.is_empty()
                            && self
                                .context_providers
                                .get(*deployment_ref)
                                .is_some_and(|binding| binding.delegated_display_exchange.is_none())
                    })
            {
                let path = [
                    "contextProviders",
                    deployment_ref,
                    "delegatedDisplayExchange",
                ];
                findings.push(delegated_staff_reader_finding(
                    &path,
                    "is required when a delegated reader authorizes source profiles for current-source work through this provider",
                    "Configure the provider's delegatedDisplayExchange, or remove the reader's sourceProfiles after removing its Staff profile from current-source review stages.",
                ));
            }
        }
    }

    fn check_task_authority(
        &self,
        project: &CaseworkProject,
        findings: &mut Vec<RuntimeConfigError>,
    ) {
        use registry_platform_httputil::valid_resource_uri;
        let allowed_clients = &self.authentication.oidc.clients.allowed_clients;
        let Some(authority) = &self.task_authority else {
            if !project.task_templates.is_empty() {
                findings.push(task_authority_finding(
                    &["taskAuthority"],
                    "is required when casework.yaml declares taskTemplates",
                    "Add a taskAuthority block naming issuer, exchangeAudience, signingKeyRef, and statusClients.",
                ));
            }
            return;
        };
        for (member, value) in [
            ("issuer", &authority.issuer),
            ("exchangeAudience", &authority.exchange_audience),
        ] {
            if !valid_resource_uri(value) {
                findings.push(task_authority_finding(
                    &["taskAuthority", member],
                    "must be an absolute URI without userinfo or a fragment",
                    "Write the absolute URI the task grant names here.",
                ));
            }
        }
        if allowed_clients.is_empty() {
            findings.push(task_authority_finding(
                &["authentication", "oidc", "allowedClients"],
                "must name every client taskAuthority admits",
                "List in authentication.oidc.allowedClients every client taskAuthority.statusClients and casework.yaml taskTemplates.TEMPLATE_ID.client name.",
            ));
        }
        if authority.status_clients.len() > MAXIMUM_STATUS_CLIENTS {
            findings.push(task_authority_finding(
                &["taskAuthority", "statusClients"],
                "must map at most 64 clients",
                "Remove status clients until at most 64 remain.",
            ));
        }
        for (client, resource) in &authority.status_clients {
            if !allowed_clients.is_empty() && !allowed_clients.contains(client) {
                findings.push(task_authority_finding(
                    &["taskAuthority", "statusClients", client],
                    "must be a client authentication.oidc.allowedClients admits",
                    "Add the client to authentication.oidc.allowedClients, or remove it from taskAuthority.statusClients.",
                ));
            }
            if !valid_resource_uri(resource) {
                findings.push(task_authority_finding(
                    &["taskAuthority", "statusClients", client],
                    "must map the client to an absolute resource URI without userinfo or a fragment",
                    "Map the client to the absolute URI of the one resource it reads status from.",
                ));
            }
        }
        let templates = &project.task_templates;
        if templates.iter().any(|template| {
            template.agent.issuer != self.authentication.oidc.provider.issuer.as_str()
        }) {
            findings.push(task_authority_finding(
                &["authentication", "oidc", "issuer"],
                "must be the issuer every casework.yaml taskTemplates.TEMPLATE_ID.agent.issuer names",
                "Name the same issuer in authentication.oidc.issuer and in each taskTemplates.TEMPLATE_ID.agent.issuer.",
            ));
        }
        if !allowed_clients.is_empty()
            && templates
                .iter()
                .any(|template| !allowed_clients.contains(&template.client))
        {
            findings.push(task_authority_finding(
                &["authentication", "oidc", "allowedClients"],
                "must admit every client casework.yaml taskTemplates.TEMPLATE_ID.client names",
                "Add each taskTemplates.TEMPLATE_ID.client to authentication.oidc.allowedClients.",
            ));
        }
        if templates
            .iter()
            .any(|template| !valid_resource_uri(&template.resource))
        {
            findings.push(task_authority_finding(
                &["taskAuthority"],
                "cannot grant a casework.yaml taskTemplates.TEMPLATE_ID.resource that is not an absolute URI without userinfo or a fragment",
                "Write each taskTemplates.TEMPLATE_ID.resource in casework.yaml as the absolute URI of the resource the grant is for.",
            ));
        }
    }

    fn check_context_provider_set(
        &self,
        project: &CaseworkProject,
        findings: &mut Vec<RuntimeConfigError>,
    ) {
        let declared_providers = project
            .context_providers
            .iter()
            .map(|provider| provider.deployment_ref.as_str())
            .collect::<BTreeSet<_>>();
        let configured_providers = self
            .context_providers
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();
        if self.context_providers.keys().any(String::is_empty)
            || !configured_providers.is_subset(&declared_providers)
        {
            findings.push(RuntimeConfigError::InvalidContextProviders);
        }
    }

    fn check_completion_destinations_configured(
        &self,
        project: &CaseworkProject,
        findings: &mut Vec<RuntimeConfigError>,
    ) {
        if project
            .trusted_producers
            .iter()
            .filter_map(|producer| producer.completion.as_ref())
            .any(|completion| {
                !self
                    .review_completion_destinations
                    .contains_key(&completion.destination_id)
            })
        {
            findings.push(RuntimeConfigError::UnconfiguredReviewCompletionDestination);
        }
    }

    pub async fn oidc_verifier(
        &self,
        secrets: &SecretResolver,
        witness: Option<&DevelopmentWitness>,
    ) -> Result<(TokenVerifierConfig, std::sync::Arc<JwksFetcher>), RuntimeConfigError> {
        let profile = self.verifier_profile(witness)?;
        let provider = &self.authentication.oidc.provider;
        let network =
            IssuerNetworkPolicy::new(provider.issuer.as_str(), provider.allow_insecure_http)
                .map_err(|_| RuntimeConfigError::Oidc)?;
        let fetcher = match &provider.jwks_source {
            JwksSource::Uri { uri } => {
                let policy = network.declared_jwks_fetch_policy();
                JwksFetcher::new_with_fetch_url_policy(
                    uri.to_string(),
                    JwksFetcherConfig::defaults(),
                    policy,
                )
            }
            JwksSource::Discovery {} => {
                let discovery_config = OidcDiscoveryConfig {
                    issuer: self.authentication.oidc.provider.issuer.to_string(),
                    jwks_uri_override: None,
                    discovery_timeout: Duration::from_secs(5),
                    max_doc_bytes: 1024 * 1024,
                };
                let (discovery, policy) =
                    fetch_discovery_for_issuer(&discovery_config, provider.allow_insecure_http)
                        .await
                        .map_err(|_| RuntimeConfigError::Oidc)?;
                JwksFetcher::new_with_fetch_url_policy(
                    discovery.jwks_uri,
                    JwksFetcherConfig::defaults(),
                    policy,
                )
            }
            JwksSource::Static { document_ref } | JwksSource::TestIssuer { document_ref } => {
                let document = secrets.resolve(document_ref).map_err(|error| {
                    RuntimeConfigError::OidcJwksSecret(describe_secret_failure(
                        "authentication.oidc.jwksSource.documentRef",
                        document_ref,
                        &error,
                    ))
                })?;
                let jwks =
                    parse_static_jwks(document.expose_secret()).map_err(|error| match error {
                        OidcError::StaticKeySet(refusal) => {
                            RuntimeConfigError::OidcJwksSecret(refusal.to_string())
                        }
                        _ => RuntimeConfigError::Oidc,
                    })?;
                JwksFetcher::new_static(jwks, JwksFetcherConfig::defaults())
            }
        };
        Ok((profile, std::sync::Arc::new(fetcher)))
    }

    /// The access-token verifier profile this deployment's OIDC settings
    /// describe.
    ///
    /// RFC 9068 gives the access token one media type spelled two ways,
    /// `at+jwt` and `application/at+jwt`, and requires a resource server to
    /// accept that pair and refuse every other `typ`. The list comes from
    /// [`access_token_typ_set`] so a plain `JWT` stays out: an ID token, a
    /// UserInfo JWT, or any other JWT minted for this audience is not an
    /// access token, and admitting one would let a credential issued for
    /// another purpose claim, draft, and act on casework.
    pub(crate) fn human_source_audiences(
        &self,
        project: &CaseworkProject,
    ) -> BTreeMap<String, String> {
        project
            .context_providers
            .iter()
            .filter_map(|provider| {
                self.context_providers
                    .get(&provider.deployment_ref)
                    .and_then(|binding| binding.human_source_authentication.as_ref())
                    .map(|auth| (provider.id.clone(), auth.audience.clone()))
            })
            .collect()
    }

    pub(crate) fn verifier_profile(
        &self,
        witness: Option<&DevelopmentWitness>,
    ) -> Result<TokenVerifierConfig, DevelopmentOnlyRefused> {
        let clients = &self.authentication.oidc.clients;
        if clients.allowed_clients.is_empty() && witness.is_none() {
            return Err(DevelopmentOnlyRefused {
                setting: &UNRESTRICTED_CLIENTS,
            });
        }
        Ok(TokenVerifierConfig::access_token_profile(
            self.authentication.oidc.provider.issuer.to_string(),
            vec![self.authentication.oidc.provider.audience.clone()],
            vec![
                AccessTokenAlgorithm::RS256.to_jsonwebtoken(),
                AccessTokenAlgorithm::ES256.to_jsonwebtoken(),
            ],
            access_token_typ_set(CASEWORK_ACCESS_TOKEN_TYPE),
        )
        .with_scope_claim(self.authentication.oidc.scope_claim.clone())
        .with_allowed_clients(clients.allowed_clients.clone())
        .with_assertion_issuers(clients.assertion_issuers.clone())
        .with_denied_kids(
            self.authentication
                .oidc
                .revoked_key_ids
                .iter()
                .flat_map(|kids| kids.0.iter())
                .map(|kid| kid.as_str().to_owned())
                .collect(),
        )
        .with_max_token_lifetime(
            self.authentication
                .oidc
                .maximum_token_lifetime_seconds
                .map(Duration::from_secs),
        ))
    }
}

/// A rule a runtime file must satisfy on its own; it records every finding.
type FileRule = fn(&RuntimeConfig, &mut Vec<RuntimeConfigError>);
/// A rule a runtime file must satisfy against the project it binds.
type ProjectRule = fn(&RuntimeConfig, &CaseworkProject, &mut Vec<RuntimeConfigError>);

/// The rules a runtime file satisfies on its own, in the order startup
/// applies them.
const FILE_RULES: &[FileRule] = &[
    RuntimeConfig::check_envelope,
    RuntimeConfig::check_identity,
    RuntimeConfig::check_identifier_collisions,
    RuntimeConfig::check_package_block,
    RuntimeConfig::check_secret_providers,
    RuntimeConfig::check_audit,
    RuntimeConfig::check_secret_references,
    RuntimeConfig::check_listeners,
    RuntimeConfig::check_oidc,
    RuntimeConfig::check_database,
    RuntimeConfig::check_review_completion_destinations,
    RuntimeConfig::check_context_providers,
];

/// The rules a runtime file satisfies against the project it binds.
const PROJECT_RULES: &[ProjectRule] = &[
    RuntimeConfig::check_principal_claims,
    RuntimeConfig::check_delegated_staff_readers,
    RuntimeConfig::check_task_authority,
    RuntimeConfig::check_context_provider_set,
    RuntimeConfig::check_completion_destinations_configured,
];

/// The most status clients one task authority maps.
const MAXIMUM_STATUS_CLIENTS: usize = 64;

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

fn task_authority_finding(
    segments: &[&str],
    reason: &'static str,
    action: &'static str,
) -> RuntimeConfigError {
    RuntimeConfigError::InvalidTaskAuthority {
        path: segments.join("."),
        pointer: pointer_to(segments),
        reason,
        action,
    }
}

fn delegated_staff_reader_finding(
    segments: &[&str],
    reason: &'static str,
    action: &'static str,
) -> RuntimeConfigError {
    RuntimeConfigError::InvalidDelegatedStaffReader {
        path: segments.join("."),
        pointer: pointer_to(segments),
        reason,
        action,
    }
}

fn valid_delegated_scope(scope: &str) -> bool {
    !scope.is_empty()
        && scope.len() <= 256
        && scope
            .bytes()
            .all(|byte| (0x21..=0x7e).contains(&byte) && byte != b'"' && byte != b'\\')
}

fn valid_review_completion_url(raw: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(raw) else {
        return false;
    };
    if !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return false;
    }
    match url.scheme() {
        "https" => url.host_str().is_some(),
        "http" => url
            .host_str()
            .is_some_and(|host| loopback::loopback_literal(host).is_some()),
        _ => false,
    }
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

fn runtime_identifier_collision_diagnostics(
    check: &RuntimeFileCheck<RuntimeConfig>,
    config: &RuntimeConfig,
) -> Vec<Diagnostic> {
    let ids = config
        .context_providers
        .keys()
        .map(String::as_str)
        .collect::<Vec<_>>();
    registry_platform_yaml::lookalike_local_id_pairs(ids.iter().copied())
        .into_iter()
        .map(|(first, second)| {
            let first_pointer = format!(
                "/contextProviders/{}",
                escape_pointer_segment(ids[first])
            );
            let second_pointer = format!(
                "/contextProviders/{}",
                escape_pointer_segment(ids[second])
            );
            let mut diagnostic = check.error_at_key(
                RUNTIME_CONFIG_KIND,
                "casework.runtime.context-provider-id-collision",
                &second_pointer,
                format!(
                    "local identifiers `{}` and `{}` differ only by `-` versus `_`",
                    ids[first], ids[second]
                ),
                "Rename one context provider identifier so the definitions remain distinct after separator normalization.",
            );
            check.add_related_key(
                &mut diagnostic,
                &first_pointer,
                format!("the other definition is `{}`", ids[first]),
            );
            diagnostic
        })
        .collect()
}

/// Check the runtime file at the absolute `path` as `casework serve` reads
/// it, with no package, database, network, or secret material, and report
/// every rule it breaks. The rules about the project the file binds run
/// against `project` when one is given.
///
/// With `substitute` set, `${NAME}` expressions are filled from the process
/// environment and every value is checked. Without it, each expression is
/// checked by syntax and position only, and a rule that reads its value is
/// left out.
#[must_use]
pub fn check_runtime(
    path: &Path,
    project: Option<&CaseworkProject>,
    substitute: bool,
    declared: DeclaredPosture,
) -> RuntimeCheck {
    let check = RuntimeConfig::loader(declared).check_offline::<RuntimeConfig>(
        path,
        substitute,
        stand_in_for,
    );
    let mut diagnostics = Vec::new();
    if let Some(loaded) = &check.loaded {
        if let Some(setting) = unrestricted_clients_setting(&check) {
            let mut posture = PostureReport::new(declared);
            posture.record(setting);
            diagnostics.extend(posture.diagnostics(path));
        }
        diagnostics.extend(
            loaded
                .config
                .findings(project)
                .iter()
                .filter(|finding| !finding.is_identifier_collision())
                .filter(|finding| !reads_deferred_value(&check, finding))
                .map(|finding| positioned(&check, finding)),
        );
        diagnostics.extend(runtime_identifier_collision_diagnostics(
            &check,
            &loaded.config,
        ));
    }
    let report = check.report_with(RUNTIME_CONFIG_KIND, diagnostics);
    RuntimeCheck {
        diagnostics: report.into_diagnostics(),
        unavailable: check.unavailable,
    }
}

/// The report `casework serve` prints when it refuses the runtime file at
/// `path` with `error`: the shared loader's diagnostics, or every rule the
/// file breaks, each at its position. `None` for a refusal of the package or
/// of a dependency, which its message alone describes.
#[must_use]
pub fn startup_report(
    path: &Path,
    error: &RuntimeConfigError,
    declared: DeclaredPosture,
) -> Option<Report> {
    if let Some(diagnostics) = error.load_diagnostics() {
        return Some(Report::new(diagnostics.to_vec()));
    }
    if !error.in_file() {
        return None;
    }
    let check =
        RuntimeConfig::loader(declared).check_offline::<RuntimeConfig>(path, true, stand_in_for);
    let loaded = check.loaded.as_ref()?;
    let config = &loaded.config;
    let package = config.capture_package_after_verification(|| {}).ok();
    let mut diagnostics: Vec<Diagnostic> = config
        .findings(package.as_ref().map(LoadedCaseworkPackage::project))
        .iter()
        .filter(|finding| !finding.is_identifier_collision())
        .map(|finding| positioned(&check, finding))
        .collect();
    diagnostics.extend(runtime_identifier_collision_diagnostics(&check, config));
    let report = check.report_with(RUNTIME_CONFIG_KIND, diagnostics);
    (!report.is_empty()).then_some(report)
}

/// `finding` at the value of its member, or, for a member that is absent, at
/// the nearest mapping above it that is present.
fn positioned(check: &RuntimeFileCheck<RuntimeConfig>, finding: &RuntimeConfigError) -> Diagnostic {
    let pointer = finding.pointer();
    let mut diagnostic = check.error_at(
        RUNTIME_CONFIG_KIND,
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
            .error_at(RUNTIME_CONFIG_KIND, "", located, "", "")
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
        RuntimeConfigError::InvalidMetricsListener(_) => &["/metricsListener/networkExposure"],
        RuntimeConfigError::MetricsListenerSharesSocket(_) => &["/listener/bind"],
        RuntimeConfigError::Block(error) if error.field().starts_with("authentication.oidc.") => {
            &["/listener/tlsTermination"]
        }
        RuntimeConfigError::InvalidOidcClaim { .. } => &["/authentication/oidc/scopeClaim"],
        RuntimeConfigError::RelativeOperatedPath(_)
        | RuntimeConfigError::InvalidAuditDestination(_) => &["/audit"],
        RuntimeConfigError::InvalidTaskAuthority { pointer, .. }
            if pointer.starts_with("/taskAuthority/statusClients/") =>
        {
            &["/authentication/oidc/allowedClients"]
        }
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
        ["listener", "tlsTermination"] => "loopback-plaintext",
        ["listener", "networkExposure"] => "private-address",
        ["metricsListener", "bind"] => "127.0.0.1:9100",
        ["metricsListener", "networkExposure"] => "private-address",
        ["audit", "destination"] => "file",
        ["package", "root"] | ["audit", "path"] | ["secretProviders", "file", "root"] => {
            "/deferred"
        }
        ["package", "expectedDigest"] => {
            "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        }
        ["authentication", "oidc", "issuer"]
        | ["authentication", "oidc", "jwksSource", "uri"]
        | ["taskAuthority", "issuer" | "exchangeAudience"]
        | ["taskAuthority", "statusClients", _]
        | ["contextProviders", _, "baseUrl" | "tokenEndpoint" | "clientAssertionAudience" | "resource"]
        | ["reviewCompletionDestinations", _, "url"] => "https://deferred.invalid",
        _ => DEFAULT_STAND_IN,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jsonwebtoken::Algorithm;
    use registry_platform_authcommon::FailedCheck;
    use registry_platform_config::write_package;
    use serde_json::json;

    #[test]
    fn read_report_accessors_select_the_first_error() {
        let report = RuntimeConfigError::ReadReport(Report::new(vec![
            Diagnostic::warning("example.warning", "/warning", "warning", "warning action"),
            Diagnostic::error("example.error", "/error", "error", "error action"),
            Diagnostic::error("example.later", "/later", "later", "later action"),
        ]));
        assert_eq!(report.code(), "example.error");
        assert_eq!(report.pointer(), "/error");
        assert_eq!(report.suggested_action(), "error action");
    }

    #[test]
    fn development_only_refusal_uses_the_setting_member_and_remedy() {
        let error = RuntimeConfigError::from(DevelopmentOnlyRefused {
            setting: &UNRESTRICTED_CLIENTS,
        });
        assert_eq!(error.code(), UNRESTRICTED_CLIENTS.code);
        assert_eq!(error.pointer(), ALLOWED_CLIENTS_POINTER);
        let remedy = error.suggested_action();
        assert!(remedy.starts_with(UNRESTRICTED_CLIENTS.production));
        assert!(remedy.contains("--posture development"));
    }

    #[test]
    fn read_report_accessors_use_a_warning_when_no_errors_are_present() {
        let report = RuntimeConfigError::ReadReport(Report::new(vec![Diagnostic::warning(
            "example.warning",
            "/warning",
            "warning",
            "warning action",
        )]));
        assert_eq!(report.code(), "example.warning");
        assert_eq!(report.pointer(), "/warning");
        assert_eq!(report.suggested_action(), "warning action");
    }

    const TEST_POSTURE: DeclaredPosture = DeclaredPosture {
        posture: registry_platform_config::Posture::Development,
        source: registry_platform_config::PostureSource::Flag,
    };

    const STANDALONE: &str =
        include_str!("../../../products/casework/examples/standalone-decision/casework.yaml");
    const SCHEMA: &str = r#"{"type":"object","additionalProperties":false,"required":["summary","reference"],"properties":{"summary":{"type":"string","maxLength":160},"reference":{"type":"string","maxLength":120}}}"#;

    fn read_operator(value: &serde_json::Value, directory: &Path) -> RuntimeConfig {
        let path = write_operator(value, directory);
        RuntimeConfig::loader(TEST_POSTURE)
            .load::<RuntimeConfig>(&path)
            .unwrap()
            .config
    }

    fn write_operator(value: &serde_json::Value, directory: &Path) -> PathBuf {
        let path = directory.canonicalize().unwrap().join("runtime.yaml");
        std::fs::write(&path, serde_norway::to_string(value).unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700)).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        }
        path
    }

    #[cfg(unix)]
    fn write_ownership_test_runtime(directory: &Path) -> PathBuf {
        let path = directory.join("runtime.yaml");
        std::fs::write(
            &path,
            format!("apiVersion: {RUNTIME_CONFIG_API_VERSION}\nkind: {RUNTIME_CONFIG_KIND}\n"),
        )
        .unwrap();
        path
    }

    #[cfg(unix)]
    fn assert_unsafe_runtime(error: registry_platform_config::RuntimeConfigError) {
        let diagnostic = error.deciding_diagnostic();
        assert_eq!(diagnostic.code, "platform.runtime-config.unsafe-file");
        assert!(diagnostic
            .message
            .contains("owned by root or the runtime user"));
        assert!(diagnostic
            .suggested_action
            .contains("remove group and other write permission"));
    }

    #[cfg(unix)]
    #[test]
    fn runtime_loader_accepts_an_owner_writable_file_in_a_private_directory() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        let path = write_ownership_test_runtime(directory.path());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        RuntimeConfig::loader(TEST_POSTURE)
            .load::<serde_json::Value>(&path)
            .expect("an owner-writable runtime in a private directory loads");
    }

    #[cfg(unix)]
    #[test]
    fn runtime_loader_refuses_a_group_writable_file() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        let path = write_ownership_test_runtime(directory.path());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660)).unwrap();
        let result = RuntimeConfig::loader(TEST_POSTURE).load::<serde_json::Value>(&path);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();

        assert_unsafe_runtime(result.expect_err("a group-writable runtime is refused"));
    }

    #[cfg(unix)]
    #[test]
    fn runtime_loader_refuses_a_group_writable_ancestor() {
        use std::os::unix::fs::PermissionsExt as _;

        let directory = tempfile::tempdir().unwrap();
        let writable = directory.path().join("writable");
        std::fs::create_dir(&writable).unwrap();
        std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o770)).unwrap();
        let path = write_ownership_test_runtime(&writable);
        let result = RuntimeConfig::loader(TEST_POSTURE).load::<serde_json::Value>(&path);
        std::fs::set_permissions(&writable, std::fs::Permissions::from_mode(0o700)).unwrap();

        assert_unsafe_runtime(
            result.expect_err("a runtime below a group-writable directory is refused"),
        );
    }

    fn operator_value(package: &Path, directory: &Path) -> serde_json::Value {
        json!({
            "apiVersion":RUNTIME_CONFIG_API_VERSION,"kind":RUNTIME_CONFIG_KIND,
            "identity":{"databaseId":"test"},"package":{"root":package},
            "listener":{"bind":"127.0.0.1:8100","tlsTermination":"loopback-plaintext","networkExposure":"private-address"},
            "secretProviders":{"file":{"root":directory.join("secrets")}},
            "database":{"runtimeUrlRef":"secret:file/runtime-url","migrationUrlRef":"secret:file/migration-url"},
            "authentication":{"oidc":{"issuer":"https://identity.example.test","audience":"urn:example:casework","allowedClients":"unrestricted","scopeClaim":"scope","humanIdentity":{"claim":"registry_actor_kind","value":"human"}}},
            "audit":{"path":directory.join("audit.ndjson"),"hashKeyRef":"secret:file/audit-key"}
        })
    }

    #[test]
    fn unrestricted_clients_are_a_runtime_file_setting() {
        let root = tempfile::tempdir().unwrap();
        let path = write_operator(&operator_value(root.path(), root.path()), root.path());
        let checked = RuntimeConfig::loader(TEST_POSTURE).check_offline::<RuntimeConfig>(
            &path,
            false,
            stand_in_for,
        );
        let setting = unrestricted_clients_setting(&checked).unwrap();
        assert_eq!(setting.origin, SettingOrigin::RuntimeFile);
    }

    #[test]
    fn client_admission_follows_posture_on_each_listener() {
        use registry_platform_config::{Posture, PostureSource};
        let root = tempfile::tempdir().unwrap();
        let production = DeclaredPosture {
            posture: Posture::Production,
            source: PostureSource::Flag,
        };
        let mut value = operator_value(root.path(), root.path());
        for listener in [
            "loopback-plaintext",
            "development-loopback",
            "operator-controlled-upstream",
        ] {
            value["listener"]["tlsTermination"] = json!(listener);
            let path = write_operator(&value, root.path());
            let error = RuntimeConfig::load_file(&path, production).unwrap_err();
            assert_eq!(error.code(), "casework.posture.unrestricted-clients");
            let loaded = RuntimeConfig::load_file(&path, TEST_POSTURE).unwrap();
            assert_eq!(
                loaded.posture.ready_member()["developmentSettings"],
                json!([{
                    "code": "casework.posture.unrestricted-clients",
                    "pointer": ALLOWED_CLIENTS_POINTER,
                }])
            );
            assert!(matches!(
                loaded.config.verifier_profile(None),
                Err(refused) if refused.setting.code == UNRESTRICTED_CLIENTS.code
            ));
            assert!(loaded
                .config
                .verifier_profile(loaded.development.as_ref())
                .is_ok());

            let logs = registry_platform_testing::CapturedDiagnosticLogs::default();
            tracing::dispatcher::with_default(&logs.subscriber(), || loaded.posture.log_startup());
            let log = logs.text();
            assert!(log.contains("posture declared"), "{log}");
            assert!(
                log.contains("casework.posture.unrestricted-clients"),
                "{log}"
            );
        }
    }

    #[test]
    fn loopback_issuer_http_needs_no_setting_in_production() {
        use registry_platform_config::{Posture, PostureSource};
        let root = tempfile::tempdir().unwrap();
        let production = DeclaredPosture {
            posture: Posture::Production,
            source: PostureSource::Flag,
        };
        let mut value = operator_value(root.path(), root.path());
        value["authentication"]["oidc"]["issuer"] = json!("http://127.0.0.1:8091");
        value["authentication"]["oidc"]["allowedClients"] = json!(["test-client"]);
        for listener in [
            "loopback-plaintext",
            "development-loopback",
            "operator-controlled-upstream",
        ] {
            value["listener"]["tlsTermination"] = json!(listener);
            let path = write_operator(&value, root.path());
            let loaded = RuntimeConfig::load_file(&path, production).unwrap();
            assert!(loaded.config.findings(None).is_empty());
        }
    }

    #[cfg(not(feature = "postgres-test"))]
    #[test]
    fn ordinary_builds_refuse_the_test_only_database_transport() {
        let root = tempfile::tempdir().unwrap();
        let mut value = operator_value(root.path(), root.path());
        value["database"]["testOnlyPlaintext"] = json!(true);
        let config = read_operator(&value, root.path());
        let findings = config.findings(None);
        assert!(findings.iter().any(|finding| finding.code()
            == "platform.database.test-only-plaintext"
            && finding.pointer() == "/database/testOnlyPlaintext"));
    }

    /// Resolve the verifier of a runtime file whose static key set is `document`.
    async fn verifier_for_static_key_set(
        document: &serde_json::Value,
    ) -> Result<(), RuntimeConfigError> {
        use std::os::unix::fs::PermissionsExt as _;
        let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let secrets = root.path().join("secrets");
        std::fs::create_dir(&secrets).unwrap();
        std::fs::set_permissions(&secrets, std::fs::Permissions::from_mode(0o700)).unwrap();
        let file = secrets.join("jwks");
        std::fs::write(&file, document.to_string()).unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).unwrap();
        let mut value = operator_value(root.path(), root.path());
        value["authentication"]["oidc"]["jwksSource"] =
            json!({"type":"static", "documentRef":"secret:file/jwks"});
        value["authentication"]["oidc"]["allowedClients"] = json!(["test-client"]);
        let config = read_operator(&value, root.path());
        let resolver =
            SecretResolver::new([registry_platform_config::SecretProvider::File], &secrets)
                .unwrap();
        config.oidc_verifier(&resolver, None).await.map(|_| ())
    }

    fn public_rsa_key(kid: &str) -> serde_json::Value {
        json!({"kty":"RSA","kid":kid,"alg":"RS256","n":"sXchDaQebHnPiGvyDOAT4saGEUetSyo9MKLOoWFsueri23bOdgWp4Dy1WlUzewbgBHod5pcM9H95GQRV3JDXboIRROSBigeC5yjU1hGzHHyXss8UDprecbAYxknTcQkhslANGRUZmdTOQ5qTRsLAt6BTYuyvVRdhS8exSZEy_c4gs_7svlJJQ4H9_NxsiIoLwAEk7-Q3UXERGYw_75IDrGA84-lA_-Ct4eTlXHBIY2EaV7t7LjJaynVJCpkv4LKjTTAumiGUIuQhrNhZLuF_RJLqHpM2kgWFLU7-VTdL1VbC2tejvcI2BlMkEpk1BzBZI0KQB0GaDWFLN-aEAw3vRw","e":"AQAB"})
    }

    #[tokio::test]
    async fn a_static_key_set_with_unknown_public_members_loads() {
        let mut key = public_rsa_key("signing-1");
        key["ext"] = json!(true);
        key["x5c"] = json!(["MIIB"]);
        key["x5t"] = json!("thumbprint");
        key["use"] = json!("sig");
        key["key_ops"] = json!(["verify"]);
        let mut encryption = public_rsa_key("encryption-1");
        encryption["use"] = json!("enc");
        let document = json!({"keys": [key, encryption], "issuer": "an unknown top-level member"});
        verifier_for_static_key_set(&document)
            .await
            .expect("members the validator does not name are ignored");
    }

    #[tokio::test]
    async fn a_static_key_set_with_a_private_member_is_refused_with_its_text() {
        let mut key = public_rsa_key("signing-1");
        key["d"] = json!("canary-private-exponent");
        let error = verifier_for_static_key_set(&json!({"keys": [key]}))
            .await
            .expect_err("a private member is refused");
        assert_eq!(error.code(), "casework.runtime.unreadable-jwks-secret");
        let rendered = error.to_string();
        assert!(rendered.contains("private-key member \"d\""), "{rendered}");
        assert!(!rendered.contains("canary"), "{rendered}");
        assert!(!rendered.contains("signing-1"), "{rendered}");
    }

    #[test]
    fn a_review_completion_destination_may_use_http_only_on_a_loopback_address() {
        for admitted in [
            "https://completion.example.test/reviews",
            "http://127.0.0.1:9000/reviews",
            "http://127.0.0.2/reviews",
            "http://[::1]:9000/reviews",
            "http://[::ffff:127.0.0.1]/reviews",
        ] {
            assert!(valid_review_completion_url(admitted), "{admitted}");
        }
        for refused in [
            "http://localhost/reviews",
            "http://LOCALHOST:9000/reviews",
            "http://localhost./reviews",
            "http://app.localhost/reviews",
            "http://10.0.0.1/reviews",
            "http://0.0.0.0/reviews",
            "http://completion.example.test/reviews",
            "http://127.0.0.1@example.test/reviews",
        ] {
            assert!(!valid_review_completion_url(refused), "{refused}");
        }
    }

    #[test]
    fn metrics_listener_wildcard_needs_container_private_exposure() {
        let directory = tempfile::tempdir().unwrap();
        let (_, _, project) = referenced_policy();
        let refused = |value: &serde_json::Value| {
            read_operator(value, directory.path())
                .findings(Some(&project))
                .iter()
                .any(|finding| finding.code() == "casework.runtime.invalid-metrics-listener")
        };
        let mut value = operator_value(directory.path(), directory.path());
        value["metricsListener"] = json!({"bind": "0.0.0.0:9100"});
        assert!(refused(&value), "the wildcard needs the declaration");
        value["metricsListener"] =
            json!({"bind": "0.0.0.0:9100", "networkExposure": "container-private"});
        assert!(!refused(&value), "container-private permits the wildcard");
        value["metricsListener"] =
            json!({"bind": "0.0.0.0:8100", "networkExposure": "container-private"});
        assert!(refused(&value), "a wildcard on the served port overlaps");
        value["metricsListener"] =
            json!({"bind": "8.8.8.8:9100", "networkExposure": "container-private"});
        assert!(refused(&value), "a public address is still refused");
    }

    #[test]
    fn metrics_listener_refusal_names_its_cause_and_remedy() {
        let directory = tempfile::tempdir().unwrap();
        let (_, _, project) = referenced_policy();
        let refusal = |bind: &str| {
            let mut value = operator_value(directory.path(), directory.path());
            value["metricsListener"] = json!({"bind": bind});
            let findings = read_operator(&value, directory.path()).findings(Some(&project));
            let finding = findings
                .iter()
                .find(|finding| finding.code() == "casework.runtime.invalid-metrics-listener")
                .expect("the metrics bind is refused");
            (finding.to_string(), finding.suggested_action())
        };
        let (message, action) = refusal("8.8.8.8:9100");
        assert!(message.contains("must be loopback or private"), "{message}");
        assert!(
            action.contains("keep metrics off public addresses"),
            "{action}"
        );
        assert!(!action.contains("container-private"), "{action}");
        let (_, action) = refusal("127.0.0.1:0");
        assert!(action.contains("non-zero port"), "{action}");
        assert!(!action.contains("container-private"), "{action}");
        let (_, action) = refusal("127.0.0.1:8100");
        assert!(action.contains("its own port"), "{action}");
        assert!(!action.contains("container-private"), "{action}");
        let (_, action) = refusal("0.0.0.0:9100");
        assert!(
            action.contains("metricsListener.networkExposure: container-private"),
            "{action}"
        );
    }

    #[test]
    fn delegated_staff_reader_requires_an_exact_client_actor_scope_and_staff_profile() {
        let directory = tempfile::tempdir().unwrap();
        let mut value = operator_value(directory.path(), directory.path());
        value["authentication"]["oidc"]["allowedClients"] = json!(["registry-mcp"]);
        value["authentication"]["oidc"]["assertionIssuers"] = json!({
            "registry-mcp": ["https://people.example.test"]
        });
        value["authentication"]["oidc"]["delegatedStaffReaders"] = json!({
            "assistant-reader": {
                "profile": "staff",
                "client": "registry-mcp",
                "actorSubject": "registry-mcp",
                "assertionIssuer": "https://people.example.test",
                "requiredScope": "casework:staff:delegated-read",
                "maximumTokenLifetimeSeconds": 300,
                "sourceProfiles": ["review-agent"]
            }
        });
        let config = read_operator(&value, directory.path());
        let (_, _, project) = referenced_policy();
        assert!(config.findings(Some(&project)).is_empty());

        let mut changed = config.clone();
        changed
            .authentication
            .oidc
            .delegated_staff_readers
            .as_mut()
            .unwrap()
            .get_mut("assistant-reader")
            .unwrap()
            .actor_subject = "other-gateway".to_owned();
        // A different configured actor is valid configuration; the token must
        // match it exactly at authentication time.
        assert!(changed.findings(Some(&project)).is_empty());

        let mut changed = config.clone();
        changed
            .authentication
            .oidc
            .delegated_staff_readers
            .as_mut()
            .unwrap()
            .get_mut("assistant-reader")
            .unwrap()
            .required_scope = "casework:staff".to_owned();
        assert!(changed.findings(Some(&project)).iter().any(|finding| {
            finding.code() == "casework.runtime.invalid-delegated-staff-reader"
                && finding.pointer().ends_with("/requiredScope")
        }));
    }

    #[test]
    fn delegated_staff_reader_allows_client_rotation_for_one_staff_profile() {
        let directory = tempfile::tempdir().unwrap();
        let mut value = operator_value(directory.path(), directory.path());
        value["authentication"]["oidc"]["allowedClients"] =
            json!(["registry-mcp-blue", "registry-mcp-green"]);
        value["authentication"]["oidc"]["assertionIssuers"] = json!({
            "registry-mcp-blue": ["https://people.example.test"],
            "registry-mcp-green": ["https://people.example.test"]
        });
        value["authentication"]["oidc"]["delegatedStaffReaders"] = json!({
            "assistant-reader-blue": {
                "profile": "staff",
                "client": "registry-mcp-blue",
                "actorSubject": "registry-mcp-blue",
                "assertionIssuer": "https://people.example.test",
                "requiredScope": "casework:staff:delegated-read",
                "maximumTokenLifetimeSeconds": 300,
                "sourceProfiles": ["review-agent"]
            },
            "assistant-reader-green": {
                "profile": "staff",
                "client": "registry-mcp-green",
                "actorSubject": "registry-mcp-green",
                "assertionIssuer": "https://people.example.test",
                "requiredScope": "casework:staff:delegated-read",
                "maximumTokenLifetimeSeconds": 300,
                "sourceProfiles": ["review-agent"]
            }
        });
        let config = read_operator(&value, directory.path());
        let (_, _, project) = referenced_policy();

        assert!(config.findings(Some(&project)).is_empty());
    }

    #[test]
    fn delegated_reader_source_profiles_require_exchange_on_reachable_configured_provider() {
        let directory = tempfile::tempdir().unwrap();
        let mut value = operator_value(directory.path(), directory.path());
        value["authentication"]["oidc"]["allowedClients"] = json!(["registry-mcp"]);
        value["authentication"]["oidc"]["assertionIssuers"] = json!({
            "registry-mcp": ["https://people.example.test"]
        });
        value["authentication"]["oidc"]["delegatedStaffReaders"] = json!({
            "assistant-reader": {
                "profile": "staff",
                "client": "registry-mcp",
                "actorSubject": "registry-mcp",
                "assertionIssuer": "https://people.example.test",
                "requiredScope": "casework:staff:delegated-read",
                "maximumTokenLifetimeSeconds": 300,
                "sourceProfiles": ["review-agent"]
            }
        });
        value["contextProviders"] = json!({
            "facility": {
                "baseUrl": "https://registry.example.test",
                "statusProfile": "review-status",
                "tokenEndpoint": "https://identity.example.test/token",
                "clientIdRef": "secret:file/client-id",
                "clientAssertionKeyRef": "secret:file/client-key",
                "clientAssertionAudience": "https://identity.example.test"
            }
        });
        let mut project = referenced_policy().2;
        project.context_providers = vec![registry_casework_core::ReviewContextProviderPolicy {
            id: "facility-context".to_owned(),
            description: None,
            capabilities: vec![
                registry_casework_core::ReviewContextCapability::HumanDisplay,
                registry_casework_core::ReviewContextCapability::ServiceStatus,
            ],
            source_namespace: "facility-registry".to_owned(),
            deployment_ref: "facility".to_owned(),
            service_profiles: BTreeMap::from([(
                registry_casework_core::ReviewContextCapability::ServiceStatus,
                "review-status".to_owned(),
            )]),
        }];
        project.review_policies[0].context =
            registry_casework_core::ReviewContextPolicy::CurrentSource {
                provider: "facility-context".to_owned(),
                contract: registry_casework_core::ReviewContextContract {
                    id: "urn:test:facility-context".to_owned(),
                    revision: registry_casework_core::ContentDigest::for_bytes(b"revision"),
                    schema_digest: registry_casework_core::ContentDigest::for_bytes(b"schema"),
                },
            };

        let config = read_operator(&value, directory.path());
        let mut findings = Vec::new();
        config.check_delegated_staff_readers(&project, &mut findings);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(
            findings[0].pointer(),
            "/contextProviders/facility/delegatedDisplayExchange"
        );

        value["contextProviders"]["facility"]["delegatedDisplayExchange"] = json!({
            "tokenEndpoint": "https://identity.example.test/token",
            "clientIdRef": "secret:file/delegated-client-id",
            "clientAssertionKeyRef": "secret:file/delegated-client-key",
            "clientAssertionAudience": "https://identity.example.test",
            "resource": "urn:casework:facility-registry",
            "scopes": ["registry:proposal:review"],
            "generation": "test-generation"
        });
        let configured = read_operator(&value, directory.path());
        let mut findings = Vec::new();
        configured.check_delegated_staff_readers(&project, &mut findings);
        assert!(findings.is_empty(), "{findings:?}");

        value["authentication"]["oidc"]["delegatedStaffReaders"]["assistant-reader"]
            .as_object_mut()
            .unwrap()
            .remove("sourceProfiles");
        let missing_source_profiles = read_operator(&value, directory.path());
        let mut findings = Vec::new();
        missing_source_profiles.check_delegated_staff_readers(&project, &mut findings);
        assert_eq!(findings.len(), 1, "{findings:?}");
        assert_eq!(
            findings[0].pointer(),
            "/authentication/oidc/delegatedStaffReaders/assistant-reader/sourceProfiles"
        );
    }

    #[test]
    fn submitted_only_delegated_reader_may_omit_source_profiles() {
        let directory = tempfile::tempdir().unwrap();
        let mut value = operator_value(directory.path(), directory.path());
        value["authentication"]["oidc"]["allowedClients"] = json!(["registry-mcp"]);
        value["authentication"]["oidc"]["assertionIssuers"] = json!({
            "registry-mcp": ["https://people.example.test"]
        });
        value["authentication"]["oidc"]["delegatedStaffReaders"] = json!({
            "assistant-reader": {
                "profile": "staff",
                "client": "registry-mcp",
                "actorSubject": "registry-mcp",
                "assertionIssuer": "https://people.example.test",
                "requiredScope": "casework:staff:delegated-read",
                "maximumTokenLifetimeSeconds": 300
            }
        });
        let config = read_operator(&value, directory.path());
        let project = referenced_policy().2;
        let mut findings = Vec::new();
        config.check_delegated_staff_readers(&project, &mut findings);
        assert!(findings.is_empty(), "{findings:?}");
    }

    fn referenced_policy() -> (Vec<u8>, BTreeMap<String, Vec<u8>>, CaseworkProject) {
        let start = STANDALONE.find("    displaySchema:\n").unwrap();
        let end = STANDALONE[start..].find("    outcomes:\n").unwrap() + start;
        let authored = format!(
            "{}    displaySchema:\n      $ref: schemas/review.json\n{}",
            &STANDALONE[..start],
            &STANDALONE[end..]
        )
        .into_bytes();
        let schemas =
            BTreeMap::from([("schemas/review.json".to_owned(), SCHEMA.as_bytes().to_vec())]);
        let project = CaseworkProject::read_with_schemas(POLICY_FILE, &authored, &schemas)
            .unwrap()
            .value;
        (authored, schemas, project)
    }

    /// Verify one HS256 token under the profile `value` configures, so a test
    /// reads its refused keys and lifetime bound exactly as startup does.
    async fn verify_under_operator_profile(
        value: &serde_json::Value,
        kid: &str,
        lifetime_seconds: i64,
    ) -> Result<registry_casework_core::ActorContext, crate::auth::AuthenticationError> {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
        const SECRET: &[u8] = b"canary-casework-oidc-test-secret";
        let directory = tempfile::tempdir().unwrap();
        let path = write_operator(value, directory.path());
        let loaded = RuntimeConfig::load_file(&path, TEST_POSTURE).unwrap();
        let config = loaded.config;
        let mut profile = config
            .verifier_profile(loaded.development.as_ref())
            .unwrap();
        profile.allowed_algorithms = vec![Algorithm::HS256];
        let keys = std::sync::Arc::new(JwksFetcher::new_static(
            serde_json::from_value(json!({"keys": [{
                "kty": "oct", "kid": kid, "alg": "HS256", "use": "sig",
                "k": URL_SAFE_NO_PAD.encode(SECRET),
            }]}))
            .unwrap(),
            JwksFetcherConfig::defaults(),
        ));
        let (_, _, project) = referenced_policy();
        let profile_id = project.access_profiles[0].id.to_string();
        let scopes = project.access_profiles[0].required_scopes.join(" ");
        let authenticator = crate::CaseworkAuthenticator::new(
            &project,
            profile,
            keys,
            config.authentication.oidc.human_identity.clone(),
        );
        let now = chrono::Utc::now().timestamp();
        let mut header = jsonwebtoken::Header::new(Algorithm::HS256);
        header.kid = Some(kid.to_owned());
        header.typ = Some("at+jwt".to_owned());
        let claims = json!({
            "iss": "https://identity.example.test", "aud": "urn:example:casework",
            "sub": "reviewer-1", "azp": "reviewer-app", "scope": scopes,
            "registry_actor_kind": "human",
            "iat": now, "exp": now + lifetime_seconds,
        });
        let token = jsonwebtoken::encode(
            &header,
            &claims,
            &jsonwebtoken::EncodingKey::from_secret(SECRET),
        )
        .unwrap();
        authenticator.authenticate(&token, &profile_id).await
    }

    #[tokio::test]
    async fn omitting_revoked_key_ids_and_maximum_token_lifetime_keeps_current_acceptance() {
        let directory = tempfile::tempdir().unwrap();
        let value = operator_value(directory.path(), directory.path());
        verify_under_operator_profile(&value, "signing-1", 86_400)
            .await
            .expect("no refused keys and no lifetime bound accept a day-long token");
    }

    #[tokio::test]
    async fn a_token_signed_by_a_revoked_key_id_is_refused_like_any_other_verification_failure() {
        let directory = tempfile::tempdir().unwrap();
        let mut value = operator_value(directory.path(), directory.path());
        value["authentication"]["oidc"]["revokedKeyIds"] = json!(["signing-1"]);
        let refused = verify_under_operator_profile(&value, "signing-1", 300).await;
        assert_eq!(
            refused.unwrap_err(),
            crate::auth::AuthenticationError::Refused(FailedCheck::TokenKey)
        );
        verify_under_operator_profile(&value, "signing-2", 300)
            .await
            .expect("a key not on the list still verifies");
    }

    #[tokio::test]
    async fn a_token_outliving_the_maximum_token_lifetime_is_refused() {
        let directory = tempfile::tempdir().unwrap();
        let mut value = operator_value(directory.path(), directory.path());
        value["authentication"]["oidc"]["maximumTokenLifetimeSeconds"] = json!(300);
        verify_under_operator_profile(&value, "signing-1", 300)
            .await
            .expect("a token within the bound verifies");
        let refused = verify_under_operator_profile(&value, "signing-1", 301).await;
        assert_eq!(
            refused.unwrap_err(),
            crate::auth::AuthenticationError::Refused(FailedCheck::TokenTime)
        );
    }

    #[test]
    fn an_empty_revoked_key_ids_list_or_an_out_of_range_lifetime_is_refused_with_its_fix() {
        let directory = tempfile::tempdir().unwrap();
        let mut value = operator_value(directory.path(), directory.path());
        value["authentication"]["oidc"]["revokedKeyIds"] = json!([]);
        let path = write_operator(&value, directory.path());
        let error = RuntimeConfig::loader(TEST_POSTURE)
            .load::<RuntimeConfig>(&path)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains(
                "List at least one key identifier to refuse, or delete revokedKeyIds to refuse no key."
            ),
            "{error}"
        );
        let mut value = operator_value(directory.path(), directory.path());
        value["authentication"]["oidc"]["revokedKeyIds"] =
            json!((0..129).map(|n| format!("signing-{n}")).collect::<Vec<_>>());
        let path = write_operator(&value, directory.path());
        let error = RuntimeConfig::loader(TEST_POSTURE)
            .load::<RuntimeConfig>(&path)
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("Remove key identifiers from revokedKeyIds until it lists at most 128."),
            "{error}"
        );
        let mut value = operator_value(directory.path(), directory.path());
        value["authentication"]["oidc"]["maximumTokenLifetimeSeconds"] = json!(0);
        let path = write_operator(&value, directory.path());
        let error = RuntimeConfig::loader(TEST_POSTURE)
            .load::<RuntimeConfig>(&path)
            .unwrap_err()
            .to_string();
        assert!(error.contains("maximumTokenLifetimeSeconds"), "{error}");
    }

    #[test]
    fn package_inputs_include_exact_referenced_schema_bytes() {
        let (authored, _, project) = referenced_policy();
        let inputs = package_inputs(&project, &authored).unwrap();
        assert_eq!(
            inputs,
            BTreeSet::from(["casework.yaml".to_owned(), "schemas/review.json".to_owned()])
        );
    }

    #[test]
    fn serving_secret_preflight_covers_configured_optional_consumers_with_structural_paths() {
        let root = tempfile::tempdir_in(std::env::temp_dir().canonicalize().unwrap()).unwrap();
        let mut value = operator_value(root.path(), root.path());
        value["database"]["caBundleRef"] = json!("secret:file/db-ca");
        value["authentication"]["oidc"]["jwksSource"] =
            json!({"type":"static", "documentRef":"secret:file/jwks"});
        value["authentication"]["oidc"]["allowedClients"] = json!(["test-client"]);
        value["taskAuthority"] = json!({"issuer":"https://casework.example.test","exchangeAudience":"urn:example:exchange","signingKeyRef":"secret:file/signer","statusClients":{}});
        value["contextProviders"] = json!({"facility":{
            "baseUrl":"https://registry.example.test", "statusProfile":"review-status",
            "tokenEndpoint":"https://identity.example.test/token", "clientIdRef":"secret:file/client-id", "clientAssertionKeyRef":"secret:file/client-key",
            "clientAssertionAudience":"https://identity.example.test",
            "delegatedDisplayExchange": {
                "tokenEndpoint":"https://identity.example.test/token",
                "clientIdRef":"secret:file/delegated-client-id",
                "clientAssertionKeyRef":"secret:file/delegated-client-key",
                "clientAssertionAudience":"https://identity.example.test",
                "resource":"urn:casework:facility-breg",
                "scopes":["registry:proposal:review"],
                "generation":"test-generation"
            }
        }});
        value["reviewCompletionDestinations"] = json!({
            "receiver./key":{"url":"https://completion.example.test/reviews","hmacSha256KeyRef":"secret:file/current","previousHmacSha256KeyRef":"secret:file/previous"}
        });
        let config = read_operator(&value, root.path());
        let resolver = SecretResolver::new(
            [registry_platform_config::SecretProvider::File],
            root.path(),
        )
        .unwrap();
        let report = config.check_runtime_secrets(&resolver).unwrap_err();
        let paths = report
            .diagnostics()
            .iter()
            .map(|diagnostic| diagnostic.path.as_str())
            .collect::<Vec<_>>();
        assert_eq!(
            paths,
            [
                "/database/runtimeUrlRef",
                "/database/caBundleRef",
                "/audit/hashKeyRef",
                "/authentication/oidc/jwksSource/documentRef",
                "/taskAuthority/signingKeyRef",
                "/contextProviders/facility/clientIdRef",
                "/contextProviders/facility/clientAssertionKeyRef",
                "/contextProviders/facility/delegatedDisplayExchange/clientIdRef",
                "/contextProviders/facility/delegatedDisplayExchange/clientAssertionKeyRef",
                "/reviewCompletionDestinations/receiver.~1key/hmacSha256KeyRef",
                "/reviewCompletionDestinations/receiver.~1key/previousHmacSha256KeyRef"
            ]
        );
        assert!(!report.render_human().contains("secret:file/"));
    }

    #[test]
    fn context_provider_ids_refuse_separator_lookalikes_at_both_keys() {
        fn key_position(text: &str, id: &str) -> (usize, usize) {
            text.lines()
                .enumerate()
                .find_map(|(line, text)| {
                    (text.trim_start() == format!("{id}:")).then(|| {
                        (
                            line + 1,
                            text.find(id).expect("key begins on its source line") + 1,
                        )
                    })
                })
                .expect("runtime key is authored")
        }

        let directory = tempfile::tempdir().unwrap();
        let mut value = operator_value(directory.path(), directory.path());
        value["contextProviders"] = json!({
            "registry-main": {
                "baseUrl": "https://registry.example.test",
                "statusProfile": "review-status",
                "tokenEndpoint": "https://identity.example.test/token",
                "clientIdRef": "secret:file/client-id",
                "clientAssertionKeyRef": "secret:file/client-key",
                "clientAssertionAudience": "https://identity.example.test"
            },
            "registry_main": {
                "baseUrl": "https://registry.example.test",
                "statusProfile": "review-status",
                "tokenEndpoint": "https://identity.example.test/token",
                "clientIdRef": "secret:file/other-id",
                "clientAssertionKeyRef": "secret:file/other-key",
                "clientAssertionAudience": "https://identity.example.test"
            }
        });
        let config = read_operator(&value, directory.path());
        assert!(config
            .findings(None)
            .iter()
            .any(RuntimeConfigError::is_identifier_collision));
        let path = write_operator(&value, directory.path());
        let text = std::fs::read_to_string(&path).unwrap();
        let check = check_runtime(&path, None, false, TEST_POSTURE);
        let collisions = check
            .diagnostics
            .iter()
            .filter(|diagnostic| diagnostic.code.ends_with("-id-collision"))
            .collect::<Vec<_>>();
        assert_eq!(collisions.len(), 1, "{collisions:?}");
        let diagnostic = collisions[0];
        assert_eq!(
            diagnostic.code,
            "casework.runtime.context-provider-id-collision"
        );
        assert_eq!(diagnostic.path, "/contextProviders/registry_main");
        assert_eq!(diagnostic.related.len(), 1);
        assert_eq!(
            diagnostic.related[0].path,
            "/contextProviders/registry-main"
        );
        let source = diagnostic.source.as_ref().expect("primary source");
        assert_eq!(
            (source.line.unwrap(), source.column.unwrap()),
            key_position(&text, "registry_main")
        );
        assert_eq!(
            (
                diagnostic.related[0].line.unwrap(),
                diagnostic.related[0].column.unwrap(),
            ),
            key_position(&text, "registry-main")
        );
        value["contextProviders"]
            .as_object_mut()
            .unwrap()
            .remove("registry_main");
        value["reviewCompletionDestinations"] = json!({
            "registry_main": {"url": "https://completion.example.test/reviews"}
        });
        let path = write_operator(&value, directory.path());
        assert!(check_runtime(&path, None, false, TEST_POSTURE)
            .diagnostics
            .iter()
            .all(|diagnostic| !diagnostic.code.ends_with("-id-collision")));
    }

    #[test]
    fn a_deferred_listener_bind_defers_only_the_metrics_socket_comparison() {
        let directory = tempfile::tempdir().unwrap();
        let check = |bind: &str| {
            let mut value = operator_value(directory.path(), directory.path());
            value["authentication"]["oidc"]["allowedClients"] = json!(["test-client"]);
            value["listener"]["bind"] = json!("${CASEWORK_OFFLINE_CHECK_UNSET_BIND}");
            value["metricsListener"] = json!({"bind": bind});
            let path = write_operator(&value, directory.path());
            check_runtime(&path, None, false, TEST_POSTURE)
                .diagnostics
                .iter()
                .map(|diagnostic| (diagnostic.code.clone(), diagnostic.path.clone()))
                .collect::<Vec<_>>()
        };
        // The stand-in listener is 127.0.0.1:8100: a metrics bind on it is not
        // judged until the environment supplies the real listener.
        assert!(check("127.0.0.1:8100").is_empty());
        for bind in ["169.254.1.1:9464", "203.0.113.4:9464", "0.0.0.0:9464"] {
            assert_eq!(
                check(bind),
                [(
                    "casework.runtime.invalid-metrics-listener".to_owned(),
                    "/metricsListener/bind".to_owned()
                )],
                "{bind}"
            );
        }
    }

    #[test]
    fn human_source_verifier_binds_logical_provider_through_exact_deployment_reference() {
        let directory = tempfile::tempdir().unwrap();
        let mut value = operator_value(directory.path(), directory.path());
        value["contextProviders"] = json!({"source-deployment": {
            "baseUrl":"https://source.example.test", "statusProfile":"status", "tokenEndpoint":"https://identity.example.test/token",
            "clientIdRef":"secret:file/client", "clientAssertionKeyRef":"secret:file/key",
            "clientAssertionAudience":"https://identity.example.test",
            "humanSourceAuthentication":{"audience":"urn:example:breg"}
        }});
        let config = read_operator(&value, directory.path());
        let mut project = CaseworkProject::from_slice(STANDALONE.as_bytes()).unwrap();
        project.context_providers = vec![registry_casework_core::ReviewContextProviderPolicy {
            id: "logical-source".into(),
            description: None,
            capabilities: vec![registry_casework_core::ReviewContextCapability::HumanDisplay],
            source_namespace: "source".into(),
            deployment_ref: "source-deployment".into(),
            service_profiles: BTreeMap::new(),
        }];
        assert_eq!(
            config.human_source_audiences(&project),
            BTreeMap::from([("logical-source".into(), "urn:example:breg".into())])
        );
        project.context_providers[0].deployment_ref = "logical-source".into();
        assert!(config.human_source_audiences(&project).is_empty());
    }

    #[test]
    fn context_provider_bindings_are_refused_at_the_member_and_rule_provider_construction_refuses()
    {
        let directory = tempfile::tempdir().unwrap();
        let binding = json!({
            "baseUrl": "https://registry.example.test",
            "statusProfile": "review-status",
            "tokenEndpoint": "https://identity.example.test/token",
            "clientIdRef": "secret:file/client-id",
            "clientAssertionKeyRef": "secret:file/client-key",
            "clientAssertionAudience": "https://identity.example.test",
            "resource": "urn:example:registry",
            "scopes": ["registry:proposal:review-status"]
        });
        let mut value = operator_value(directory.path(), directory.path());
        value["contextProviders"] = json!({ "registry-main": binding.clone() });
        let path = write_operator(&value, directory.path());
        assert!(check_runtime(&path, None, false, TEST_POSTURE)
            .diagnostics
            .iter()
            .all(|diagnostic| diagnostic.code != "casework.runtime.invalid-context-provider"));

        for (member, refused, pointer, rule) in [
            (
                "resource",
                json!("registry"),
                "/contextProviders/registry-main/resource",
                "absolute URI",
            ),
            (
                "baseUrl",
                json!("http://registry.example.test"),
                "/contextProviders/registry-main/baseUrl",
                "HTTPS",
            ),
            (
                "delegatedDisplayExchange",
                json!({
                    "tokenEndpoint": "https://identity.example.test/token",
                    "clientIdRef": "secret:file/source-id",
                    "clientAssertionKeyRef": "secret:file/source-key",
                    "clientAssertionAudience": "https://identity.example.test",
                    "resource": "urn:example:registry",
                    "scopes": ["registry:proposal:review"],
                    "generation": ""
                }),
                "/contextProviders/registry-main/delegatedDisplayExchange/generation",
                "generation",
            ),
        ] {
            let mut binding = binding.clone();
            binding[member] = refused;
            value["contextProviders"] = json!({ "registry-main": binding });
            let config = read_operator(&value, directory.path());
            let error = first(config.findings(None)).expect_err("the binding is refused");
            assert_eq!(error.code(), "casework.runtime.invalid-context-provider");
            assert_eq!(error.pointer(), pointer);
            assert!(error.in_file(), "{error}");
            let message = error.to_string();
            assert!(message.contains(rule), "{message}");
            assert!(!message.contains("response"), "{message}");
            let path = write_operator(&value, directory.path());
            let check = check_runtime(&path, None, false, TEST_POSTURE);
            let diagnostic = check
                .diagnostics
                .iter()
                .find(|diagnostic| diagnostic.code == "casework.runtime.invalid-context-provider")
                .expect("the offline check reports the refusal");
            assert_eq!(diagnostic.path, pointer);
            assert!(diagnostic.message.contains(rule), "{diagnostic:?}");
            assert!(diagnostic.source.is_some(), "{diagnostic:?}");
        }
    }

    /// The client assertion audience is the authorization server's issuer
    /// identifier and has no default, so a binding or a delegated exchange
    /// that does not state it is refused when the file is read.
    #[test]
    fn a_context_provider_without_an_assertion_audience_is_refused_naming_the_member() {
        let directory = tempfile::tempdir().unwrap();
        let client = json!({
            "tokenEndpoint": "https://identity.example.test/token",
            "clientIdRef": "secret:file/source-id",
            "clientAssertionKeyRef": "secret:file/source-key",
            "clientAssertionAudience": "https://identity.example.test",
            "resource": "urn:example:registry",
            "scopes": ["registry:proposal:review"],
            "generation": "casework-source-v1"
        });
        let binding = json!({
            "baseUrl": "https://registry.example.test",
            "statusProfile": "review-status",
            "tokenEndpoint": "https://identity.example.test/token",
            "clientIdRef": "secret:file/client-id",
            "clientAssertionKeyRef": "secret:file/client-key",
            "clientAssertionAudience": "https://identity.example.test",
            "delegatedDisplayExchange": client
        });
        for pointer in [
            "/contextProviders/registry-main",
            "/contextProviders/registry-main/delegatedDisplayExchange",
        ] {
            let mut value = operator_value(directory.path(), directory.path());
            value["contextProviders"] = json!({ "registry-main": binding.clone() });
            value
                .pointer_mut(pointer)
                .and_then(serde_json::Value::as_object_mut)
                .expect("the member exists")
                .remove("clientAssertionAudience");
            let path = write_operator(&value, directory.path());
            let check = check_runtime(&path, None, false, TEST_POSTURE);
            let diagnostic = check
                .diagnostics
                .iter()
                .find(|diagnostic| diagnostic.code == "config.missing-key")
                .unwrap_or_else(|| panic!("{pointer}: no missing-key diagnostic: {check:?}"));
            assert!(
                diagnostic.message.contains("clientAssertionAudience"),
                "{diagnostic:?}"
            );
            assert!(diagnostic.path.starts_with(pointer), "{diagnostic:?}");
        }
    }

    #[test]
    fn environment_expressions_substitute_values_but_never_secret_references() {
        let temp =
            tempfile::tempdir_in(std::fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
        let package = temp.path().join("package");
        let mut document = operator_value(&package, temp.path());
        document["authentication"]["oidc"]["audience"] =
            json!("${CASEWORK_CONFIG_SUBSTITUTION_AUDIENCE}");
        let path = write_operator(&document, temp.path());
        let config = RuntimeConfig::loader(TEST_POSTURE)
            .load_with::<RuntimeConfig>(&path, |name| {
                (name == "CASEWORK_CONFIG_SUBSTITUTION_AUDIENCE")
                    .then(|| "urn:example:substituted".to_owned())
            })
            .unwrap()
            .config;
        assert_eq!(
            config.authentication.oidc.provider.audience,
            "urn:example:substituted"
        );

        document["database"]["runtimeUrlRef"] = json!("${CASEWORK_CONFIG_SUBSTITUTION_REFERENCE}");
        let path = write_operator(&document, temp.path());
        let error = RuntimeConfig::loader(TEST_POSTURE)
            .load_with::<RuntimeConfig>(&path, |name| match name {
                "CASEWORK_CONFIG_SUBSTITUTION_AUDIENCE" => {
                    Some("urn:example:substituted".to_owned())
                }
                "CASEWORK_CONFIG_SUBSTITUTION_REFERENCE" => {
                    Some("secret:file/runtime-url".to_owned())
                }
                _ => None,
            })
            .unwrap_err();
        let diagnostic = error.deciding_diagnostic();
        assert_eq!(diagnostic.code, "config.substitution-not-allowed");
        assert_eq!(diagnostic.path, "/database/runtimeUrlRef");
    }

    #[test]
    fn an_authored_project_carrying_an_environment_expression_is_refused() {
        let authored = STANDALONE.replace(
            "  id: standalone-decision\n",
            "  id: ${CASEWORK_TEST_PROJECT_ID:-standalone-decision}\n",
        );
        let report = CaseworkProject::read(POLICY_FILE, authored.as_bytes()).unwrap_err();
        assert_eq!(report.error_count(), 1, "{report:?}");
        let diagnostic = &report.diagnostics()[0];
        assert_eq!(diagnostic.code, "config.substitution-not-allowed");
        assert_eq!(diagnostic.path, "/project/id");
        assert!(!diagnostic.message.contains("CASEWORK_TEST_PROJECT_ID"));
        assert!(diagnostic.message.contains("runtime.yaml"));
    }

    #[test]
    fn a_package_digest_mismatch_is_refused_in_the_shared_shape() {
        let temp =
            tempfile::tempdir_in(std::fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
        let package = temp.path().join("package");
        write_package(
            &package,
            &BTreeMap::from([(POLICY_FILE.to_owned(), STANDALONE.as_bytes().to_vec())]),
            None,
            &package_limits(),
            PACKAGE_COMMAND,
        )
        .unwrap();
        let found = sha256_uri(&std::fs::read(package.join("SHA256SUMS")).unwrap());
        let expected = format!("sha256:{}", "0".repeat(64));
        assert_ne!(expected, found);
        let mut document = operator_value(&package, temp.path());
        document["package"]["expectedDigest"] = json!(&expected);

        let error =
            RuntimeConfig::load(write_operator(&document, temp.path()), TEST_POSTURE).unwrap_err();
        assert_eq!(error.code(), "casework.package.digest-mismatch");
        assert_eq!(error.pointer(), "/package/expectedDigest");
        assert_eq!(
            error.to_string(),
            format!(
                "package.expectedDigest is {expected} but the package at package.root is {found}; \
                 deploy the pinned package or update package.expectedDigest"
            )
        );
    }

    #[test]
    fn package_capture_refuses_a_schema_changed_after_verification() {
        let temp =
            tempfile::tempdir_in(std::fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
        let package = temp.path().join("package");
        let (authored, schemas, _) = referenced_policy();
        let mut inputs = schemas;
        inputs.insert(POLICY_FILE.to_owned(), authored);
        write_package(&package, &inputs, None, &package_limits(), PACKAGE_COMMAND).unwrap();
        let operator = operator_value(&package, temp.path());
        let config = read_operator(&operator, temp.path());
        let loaded = config.load_package().unwrap();
        assert_eq!(loaded.project().review_policies.len(), 1);
        let changed = config.load_package_after_verification(|| {
            std::fs::write(package.join("schemas/review.json"), b"{}\n").unwrap();
        });
        assert!(
            matches!(changed, Err(RuntimeConfigError::PackageFileChanged { path }) if path == "schemas/review.json")
        );
    }

    #[test]
    fn omitted_context_provider_does_not_block_a_submitted_review() {
        let temp =
            tempfile::tempdir_in(std::fs::canonicalize(std::env::temp_dir()).unwrap()).unwrap();
        let project = CaseworkProject::load(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../products/casework/examples/canonical-review/casework.yaml"
        ))
        .unwrap();
        #[allow(
            clippy::disallowed_methods,
            reason = "Mutate this maintained fixture before exercising the governed operator loader."
        )]
        let mut operator: serde_json::Value = serde_norway::from_str(include_str!(
            "../../../products/casework/examples/canonical-review/runtime.example.yaml"
        ))
        .unwrap();
        let binding = operator["contextProviders"]["facility-registry"].clone();
        operator["contextProviders"] = json!({});
        let config = read_operator(&operator, temp.path());
        let mut findings = Vec::new();
        config.check_context_provider_set(&project, &mut findings);
        assert!(findings.is_empty());
        assert!(project.compile_policy("decision").is_ok());

        operator["contextProviders"]["unknown"] = binding;
        let config = read_operator(&operator, temp.path());
        let mut findings = Vec::new();
        config.check_context_provider_set(&project, &mut findings);
        assert!(matches!(
            findings.as_slice(),
            [RuntimeConfigError::InvalidContextProviders]
        ));
    }
}

#[derive(Debug, Error)]
pub enum RuntimeConfigError {
    #[error(transparent)]
    Load(#[from] registry_platform_config::RuntimeConfigError),
    #[error("the Casework runtime configuration was refused")]
    ReadReport(Report),
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
    #[error("unsupported Casework runtime apiVersion; expected id.registrystack.org/formats/casework/runtime/v1alpha1")]
    InvalidApiVersion,
    #[error("unsupported Casework runtime kind; expected CaseworkRuntimeConfig")]
    InvalidKind,
    #[error(
        "the runtime configuration must name the database it activates packages in; add `identity: {{databaseId: casework-production}}` with a logical id chosen for this deployment"
    )]
    MissingIdentity,
    #[error(
        "identity.databaseId must be non-empty, at most 256 bytes, without surrounding whitespace or control characters"
    )]
    InvalidDatabaseId,
    #[error("contextProviders contains identifiers that differ only by `-` versus `_`")]
    ContextProviderIdCollision,
    #[error("the operated runtime path {0} must be absolute")]
    RelativeOperatedPath(&'static str),
    #[error("the Casework project is invalid")]
    Project(#[source] registry_casework_core::ConfigLoadError),
    #[error(
        "package.root/casework.yaml must be a regular file of at most one MiB; rebuild the package with `caseworkctl package`"
    )]
    PolicyUnreadable,
    #[error(transparent)]
    Package(PackageError),
    #[error(transparent)]
    PackageDigest(PackageDigestMismatch),
    #[error(
        "the package at package.root must hold exactly casework.yaml and its declared schema and context export files{}{}; rebuild it with `caseworkctl package`",
        if missing.is_empty() { String::new() } else { format!("; missing: {}", missing.join(", ")) },
        if extra.is_empty() { String::new() } else { format!("; extra: {}", extra.join(", ")) },
    )]
    PackageContents {
        missing: Vec<String>,
        extra: Vec<String>,
    },
    #[error(
        "the packaged file {path} changed after package verification; rebuild it with `caseworkctl package`"
    )]
    PackageFileChanged { path: String },
    #[error("an imported review-context export does not match its pinned policy contract")]
    ContextExport,
    #[error("the Casework runtime configuration is invalid")]
    Invalid,
    #[error("listener is not valid for its declared TLS termination and network exposure")]
    InvalidListener,
    #[error("metricsListener.bind is refused: {0}")]
    InvalidMetricsListener(MetricsBindError),
    /// The same refusal as `InvalidMetricsListener`, for a metrics bind that
    /// is acceptable alone but shares the API listener's socket. It is
    /// separate so the offline check can defer it while the listener bind is
    /// an expression.
    #[error("metricsListener.bind is refused: {0}")]
    MetricsListenerSharesSocket(MetricsBindError),
    #[error("{path} {reason}")]
    InvalidOidcClaim {
        path: &'static str,
        reason: &'static str,
    },
    #[error(
        "authentication.oidc.humanIdentity.claim must differ from every accessProfiles.PROFILE_ID.principalClaim in casework.yaml"
    )]
    PrincipalClaimConflict,
    #[error("{path} {reason}")]
    InvalidTaskAuthority {
        path: String,
        pointer: String,
        reason: &'static str,
        action: &'static str,
    },
    #[error("{path} {reason}")]
    InvalidDelegatedStaffReader {
        path: String,
        pointer: String,
        reason: &'static str,
        action: &'static str,
    },
    #[error(
        "database.runtimeUrlRef and database.migrationUrlRef must be non-empty secret references"
    )]
    InvalidDatabaseReference,
    #[error("{}", audit_message(.0))]
    InvalidAuditDestination(#[source] AuditDestinationError),
    #[error("contextProviders contains a deploymentRef casework.yaml does not declare")]
    InvalidContextProviders,
    #[error("{path}: {reason}")]
    InvalidContextProvider {
        path: String,
        pointer: String,
        reason: String,
    },
    #[error("{path} {reason}")]
    InvalidReviewCompletionDestination {
        path: String,
        pointer: String,
        reason: &'static str,
    },
    #[error(
        "reviewCompletionDestinations must configure every destination casework.yaml trustedProducers.PRODUCER_ID.completion.destinationId names"
    )]
    UnconfiguredReviewCompletionDestination,
    #[error(transparent)]
    DatabaseTransport(DatabaseTransportError),
    #[error(transparent)]
    DevelopmentOnly(#[from] DevelopmentOnlyRefused),
    #[error("the OIDC issuer could not be initialized")]
    Oidc,
    #[error("the static OIDC signing keys could not be loaded: {0}")]
    OidcJwksSecret(String),
}

/// The fix for a rebuilt package, named by every package refusal.
const REBUILD_PACKAGE: &str =
    "Rebuild the package with `caseworkctl package`, then point package.root at it.";

fn first_read_error(report: &Report) -> &Diagnostic {
    report
        .diagnostics()
        .iter()
        .find(|diagnostic| diagnostic.severity == Severity::Error)
        .unwrap_or(&report.diagnostics()[0])
}

impl RuntimeConfigError {
    fn is_identifier_collision(&self) -> bool {
        matches!(self, Self::ContextProviderIdCollision)
    }

    /// The dotted member path of a refusal that carries no pointer of its
    /// own; [`Self::pointer`] is the location every caller reads.
    fn member(&self) -> &str {
        match self {
            Self::Block(error) => error.field(),
            Self::InvalidApiVersion => "apiVersion",
            Self::InvalidKind => "kind",
            Self::InvalidDatabaseId => "identity.databaseId",
            Self::ContextProviderIdCollision => "contextProviders",
            Self::RelativeOperatedPath(path) => path,
            Self::InvalidOidcClaim { path, .. } => path,
            Self::PrincipalClaimConflict => "authentication.oidc.humanIdentity.claim",
            Self::Oidc => "authentication.oidc",
            Self::OidcJwksSecret(_) => "authentication.oidc.jwksSource.documentRef",
            Self::InvalidListener => "listener.bind",
            Self::InvalidMetricsListener(_) | Self::MetricsListenerSharesSocket(_) => {
                "metricsListener.bind"
            }
            Self::InvalidDatabaseReference => "database",
            Self::DatabaseTransport(DatabaseTransportError::TestOnlyPlaintext) => {
                "database.testOnlyPlaintext"
            }
            Self::DatabaseTransport(_) => "database.transport",
            Self::DevelopmentOnly(_) => "authentication.oidc.allowedClients",
            Self::InvalidAuditDestination(error) => audit_field(error),
            Self::InvalidContextProviders => "contextProviders",
            Self::UnconfiguredReviewCompletionDestination => "reviewCompletionDestinations",
            Self::PackageDigest(_) => "package.expectedDigest",
            // Located by `pointer` itself.
            Self::Load(_)
            | Self::ReadReport(_)
            | Self::BindingSecret { .. }
            | Self::InvalidReviewCompletionDestination { .. }
            | Self::InvalidContextProvider { .. }
            | Self::InvalidTaskAuthority { .. }
            | Self::InvalidDelegatedStaffReader { .. }
            | Self::MissingIdentity
            | Self::Project(_)
            | Self::PolicyUnreadable
            | Self::Package(_)
            | Self::PackageContents { .. }
            | Self::PackageFileChanged { .. }
            | Self::ContextExport
            | Self::Invalid => "",
        }
    }

    /// The JSON Pointer, in the runtime file, of the member this refusal
    /// concerns. A member that is absent is located by the mapping that
    /// lacks it when the refusal is positioned.
    #[must_use]
    pub fn pointer(&self) -> String {
        match self {
            Self::Load(error) => error.deciding_diagnostic().path.clone(),
            Self::ReadReport(report) => first_read_error(report).path.clone(),
            Self::BindingSecret { pointer, .. }
            | Self::InvalidReviewCompletionDestination { pointer, .. }
            | Self::InvalidContextProvider { pointer, .. }
            | Self::InvalidTaskAuthority { pointer, .. }
            | Self::InvalidDelegatedStaffReader { pointer, .. } => pointer.clone(),
            Self::MissingIdentity => "/identity".to_owned(),
            Self::Project(_)
            | Self::PolicyUnreadable
            | Self::Package(_)
            | Self::PackageContents { .. }
            | Self::PackageFileChanged { .. }
            | Self::ContextExport => "/package/root".to_owned(),
            Self::Invalid => String::new(),
            _ => pointer_to(&self.member().split('.').collect::<Vec<_>>()),
        }
    }

    /// The diagnostic code of this refusal.
    #[must_use]
    pub fn code(&self) -> &str {
        match self {
            Self::Load(error) => &error.deciding_diagnostic().code,
            Self::ReadReport(report) => &first_read_error(report).code,
            Self::Block(error) | Self::BindingSecret { error, .. } => block_finding(error).0,
            Self::InvalidApiVersion => "casework.runtime.unsupported-api-version",
            Self::InvalidKind => "casework.runtime.wrong-kind",
            Self::MissingIdentity => "casework.runtime.missing-identity",
            Self::InvalidDatabaseId => "casework.runtime.invalid-database-id",
            Self::ContextProviderIdCollision => "casework.runtime.context-provider-id-collision",
            Self::RelativeOperatedPath(_) => "casework.runtime.relative-path",
            Self::Project(_) => "casework.package.invalid-project",
            Self::PolicyUnreadable => "casework.package.unreadable-project",
            Self::Package(_) => "casework.package.invalid",
            Self::PackageDigest(_) => "casework.package.digest-mismatch",
            Self::PackageContents { .. } => "casework.package.unexpected-contents",
            Self::PackageFileChanged { .. } => "casework.package.file-changed",
            Self::ContextExport => "casework.package.context-export-mismatch",
            Self::Invalid => "casework.runtime.invalid",
            Self::InvalidListener => "casework.runtime.invalid-listener",
            Self::InvalidMetricsListener(_) | Self::MetricsListenerSharesSocket(_) => {
                "casework.runtime.invalid-metrics-listener"
            }
            Self::InvalidOidcClaim { .. } => "casework.runtime.invalid-oidc-claim",
            Self::PrincipalClaimConflict => "casework.runtime.principal-claim-conflict",
            Self::InvalidTaskAuthority { .. } => "casework.runtime.invalid-task-authority",
            Self::InvalidDelegatedStaffReader { .. } => {
                "casework.runtime.invalid-delegated-staff-reader"
            }
            Self::InvalidDatabaseReference => "casework.runtime.invalid-database-reference",
            Self::InvalidAuditDestination(_) => "casework.runtime.invalid-audit",
            Self::InvalidContextProviders => "casework.runtime.context-providers-mismatch",
            Self::InvalidContextProvider { .. } => "casework.runtime.invalid-context-provider",
            Self::InvalidReviewCompletionDestination { .. } => {
                "casework.runtime.invalid-review-completion-destination"
            }
            Self::UnconfiguredReviewCompletionDestination => {
                "casework.runtime.unconfigured-review-completion-destination"
            }
            Self::DatabaseTransport(error) => error.code(),
            Self::DevelopmentOnly(error) => error.setting.code,
            Self::Oidc => "casework.runtime-dependency.unavailable",
            Self::OidcJwksSecret(_) => "casework.runtime.unreadable-jwks-secret",
        }
    }

    /// What the operator does to clear this refusal.
    #[must_use]
    pub fn suggested_action(&self) -> String {
        let action = match self {
            Self::Load(error) => return error.deciding_diagnostic().suggested_action.clone(),
            Self::ReadReport(report) => return first_read_error(report).suggested_action.clone(),
            Self::Block(error) | Self::BindingSecret { error, .. } => block_finding(error).1,
            Self::InvalidApiVersion => {
                "Write apiVersion: id.registrystack.org/formats/casework/runtime/v1alpha1."
            }
            Self::InvalidKind => "Write kind: CaseworkRuntimeConfig.",
            Self::MissingIdentity => {
                "Add `identity: {databaseId: casework-production}` with a logical id chosen for this deployment."
            }
            Self::InvalidDatabaseId => {
                "Write identity.databaseId as at most 256 bytes without surrounding whitespace or control characters."
            }
            Self::ContextProviderIdCollision => {
                "Rename one context provider identifier so the definitions remain distinct after separator normalization."
            }
            Self::RelativeOperatedPath(path) => {
                return format!("Write {path} as an absolute path.");
            }
            Self::Project(_) => {
                "Correct casework.yaml as `caseworkctl check` reports, then rebuild the package with `caseworkctl package`."
            }
            Self::PolicyUnreadable
            | Self::Package(_)
            | Self::PackageContents { .. }
            | Self::PackageFileChanged { .. } => REBUILD_PACKAGE,
            Self::PackageDigest(_) => {
                "Set package.expectedDigest to the digest `caseworkctl package` reported for the package at package.root, or remove it."
            }
            Self::ContextExport => {
                "Export and pair the producer's review-context contract again, then rebuild the package with `caseworkctl package`."
            }
            Self::Invalid => "Correct the runtime configuration as the message describes.",
            Self::InvalidListener => {
                "Bind to a loopback address under loopback-plaintext; under operator-controlled-upstream bind to a loopback or private address, or to the unspecified address only with networkExposure: container-private."
            }
            Self::InvalidMetricsListener(cause) | Self::MetricsListenerSharesSocket(cause) => {
                return cause.remedy("metricsListener.networkExposure");
            }
            Self::InvalidOidcClaim { .. } => {
                "Name a non-empty claim distinct from authentication.oidc.scopeClaim, or remove the member to use its default."
            }
            Self::PrincipalClaimConflict => {
                "Name a humanIdentity.claim that no accessProfiles.PROFILE_ID.principalClaim in casework.yaml uses."
            }
            Self::InvalidTaskAuthority { action, .. }
            | Self::InvalidDelegatedStaffReader { action, .. } => action,
            Self::InvalidDatabaseReference => {
                "Write database.runtimeUrlRef and database.migrationUrlRef as secret references."
            }
            Self::InvalidAuditDestination(error) => audit_action(error),
            Self::InvalidContextProviders => {
                "Remove the unrecognized contextProviders key, or declare its deploymentRef in casework.yaml. Omitted providers remain unavailable to their current-source reviews."
            }
            Self::InvalidContextProvider { .. } => {
                "Correct the context provider member so it meets the rule the message names."
            }
            Self::InvalidReviewCompletionDestination { .. } => {
                "Give the destination a non-empty id and an https URL with a host, or an http URL on a loopback literal (127.0.0.0/8, ::1 or ::ffff:127.0.0.0/104) for local development."
            }
            Self::UnconfiguredReviewCompletionDestination => {
                "Add a reviewCompletionDestinations entry for each destination casework.yaml trustedProducers.PRODUCER_ID.completion.destinationId names."
            }
            Self::DatabaseTransport(error) => error.suggested_action(),
            Self::DevelopmentOnly(error) => {
                return format!(
                    "{} For a laptop or test run, start it with `rstack dev`, or declare development with {POSTURE_ENV}={DEVELOPMENT} or --posture {DEVELOPMENT}.",
                    error.setting.production,
                    POSTURE_ENV = registry_platform_config::POSTURE_ENV,
                    DEVELOPMENT = registry_platform_config::DEVELOPMENT,
                );
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

    /// Positioned diagnostics from the governed runtime file reader.
    pub fn load_diagnostics(&self) -> Option<&[Diagnostic]> {
        match self {
            Self::Load(error) => Some(error.diagnostics()),
            Self::ReadReport(report) => Some(report.diagnostics()),
            _ => None,
        }
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
                | Self::ReadReport(_)
                | Self::Project(_)
                | Self::PolicyUnreadable
                | Self::Package(_)
                | Self::PackageDigest(_)
                | Self::PackageContents { .. }
                | Self::PackageFileChanged { .. }
                | Self::ContextExport
                | Self::Invalid
                | Self::Oidc
                | Self::OidcJwksSecret(_)
        )
    }
}

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

/// An audit destination refusal in Casework's own member names. Casework
/// names the retention member `retentionDays` (CFG-NAME-5), so this and
/// [`audit_field`] say so rather than repeat the shared text.
fn audit_message(error: &AuditDestinationError) -> String {
    match error {
        AuditDestinationError::FileOnlyField { .. } => format!(
            "{} applies only when audit.destination is file",
            audit_field(error)
        ),
        AuditDestinationError::RetainDaysOutOfRange { maximum } => {
            format!("audit.retentionDays must be between 1 and {maximum}")
        }
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
            "casework.runtime.relative-path",
            "Write the path as an absolute path without `.` or `..` segments.",
        ),
        ConfigBlockErrorKind::NoSecretProvider => (
            "casework.runtime.no-secret-provider",
            "Enable secretProviders.file, secretProviders.environment, or both.",
        ),
        ConfigBlockErrorKind::InvalidSecretReference => (
            "casework.runtime.invalid-secret-reference",
            "Write the reference as secret:env/NAME or secret:file/name.",
        ),
        ConfigBlockErrorKind::SecretProviderDisabled => (
            "casework.runtime.secret-provider-disabled",
            "Enable the provider the reference names under secretProviders, or reference an enabled one.",
        ),
        ConfigBlockErrorKind::Empty => (
            "casework.runtime.empty-value",
            "Give the member a value.",
        ),
        ConfigBlockErrorKind::InvalidDigest => (
            "casework.runtime.invalid-digest",
            "Write the sha256: digest `caseworkctl package` reported, or remove the member.",
        ),
        ConfigBlockErrorKind::InvalidUri => (
            "casework.runtime.invalid-uri",
            "Write an absolute https URL without credentials, query, or fragment.",
        ),
        ConfigBlockErrorKind::InvalidAudience => (
            "casework.runtime.invalid-audience",
            "Write the audience as non-empty text without control characters, within the bound the message names.",
        ),
        ConfigBlockErrorKind::InvalidAssertionIssuers => (
            "casework.runtime.invalid-assertion-issuers",
            "Keep assertionIssuers within the bounds the message names, with non-empty clients and issuers and no issuer repeated for one client.",
        ),
    }
}
