use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::time::Duration;

use jsonwebtoken::Algorithm;
use registry_casework_core::{CaseworkProject, ConfigLoadError};
use registry_platform_audit::{
    AuditDestination, AuditDestinationError, AuditDestinationKind, MAX_AUDIT_RETAIN_DAYS,
    MIN_AUDIT_ROTATE_BYTES,
};
pub(crate) use registry_platform_config::describe_secret_failure;
use registry_platform_config::package::is_envelope_file;
use registry_platform_config::{
    sha256_uri, ConfigBlockError, ConfigBlockErrorKind, PackageConfig, PackageDigestMismatch,
    PackageError, PackageErrorKind, PackageLimits, RemovedKey, RuntimeConfigLoader,
    RuntimeEnvelope, RuntimeFileCheck, SecretReference, SecretResolver, VerifiedPackage,
    DEFAULT_STAND_IN, REMOVED_OIDC_JWKS_SOURCE_KIND, REMOVED_OIDC_JWKS_URI,
};
pub use registry_platform_config::{
    AuditKeyConfig, DatabaseConfig, EnvironmentSecretProviderConfig, FileSecretProviderConfig,
    JwksSource, ListenerNetworkExposure, OidcClientsConfig, OidcIssuerConfig,
    PrivateListenerConfig as ListenerConfig, SecretProvidersConfig, TlsTermination,
};
use registry_platform_oidc::{
    access_token_typ_set, fetch_discovery, parse_static_jwks, JwksFetcher, JwksFetcherConfig,
    OidcDiscoveryConfig, TokenVerifierConfig,
};
use registry_platform_yaml::{escape_pointer_segment, Diagnostic, Report, RetiredApiVersion};
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
        path: "audit.retainDays",
        replacement: "Rename audit.retainDays to audit.retentionDays",
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

/// An optional member holding a secret reference; absent reads as `None`
/// through `serde(default)`.
fn optional_secret_reference<'de, D>(deserializer: D) -> Result<Option<String>, D::Error>
where
    D: Deserializer<'de>,
{
    secret_reference(deserializer).map(Some)
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
    /// Shorthand for `auth` with no header: the secret is presented as
    /// `Authorization: Bearer`. Exactly one of this and `auth` is configured.
    #[serde(default, deserialize_with = "optional_secret_reference")]
    #[cfg_attr(feature = "schema", schemars(with = "Option<SecretReference>"))]
    pub bearer_token_ref: Option<String>,
    #[serde(default)]
    pub auth: Option<ReviewCompletionAuthConfig>,
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

/// How a completion destination presents its secret. Without `header` the
/// secret is sent as `Authorization: Bearer`; with one, the raw secret is the
/// value of that header and no `Authorization` header is sent.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReviewCompletionAuthConfig {
    #[serde(default)]
    #[cfg_attr(
        feature = "schema",
        schemars(length(min = 1, max = MAXIMUM_REVIEW_COMPLETION_HEADER_NAME_BYTES))
    )]
    pub header: Option<String>,
    #[serde(deserialize_with = "secret_reference")]
    #[cfg_attr(feature = "schema", schemars(with = "SecretReference"))]
    pub secret_ref: String,
}

impl ReviewCompletionRuntimeConfig {
    /// The secret reference this destination presents, when exactly one of
    /// `bearerTokenRef` and `auth` names it.
    #[must_use]
    pub fn secret_ref(&self) -> Option<&str> {
        match (&self.bearer_token_ref, &self.auth) {
            (Some(reference), None) => Some(reference),
            (None, Some(auth)) => Some(&auth.secret_ref),
            _ => None,
        }
    }

    /// The header that carries the secret instead of `Authorization: Bearer`.
    #[must_use]
    pub fn secret_header(&self) -> Option<&str> {
        self.auth.as_ref().and_then(|auth| auth.header.as_deref())
    }
}

const MAXIMUM_REVIEW_COMPLETION_HEADER_NAME_BYTES: usize = 64;

/// Header names a completion destination may not carry its secret in.
///
/// Authentication, host and routing, cookie, framing, hop-by-hop, forwarding,
/// proxy, and tracing headers belong to the runtime or the operator's network
/// path, the same closed set Evidence refuses for its source headers. The
/// `idempotency-key` and `registry-` headers are the completion contract's own.
const RESERVED_REVIEW_COMPLETION_HEADER_NAMES: [&str; 39] = [
    "authorization",
    "proxy-authorization",
    "www-authenticate",
    "proxy-authenticate",
    "host",
    "cookie",
    "set-cookie",
    "content-length",
    "content-type",
    "transfer-encoding",
    "expect",
    "connection",
    "keep-alive",
    "te",
    "trailer",
    "upgrade",
    "proxy-connection",
    "forwarded",
    "via",
    "x-real-ip",
    "x-client-ip",
    "x-cluster-client-ip",
    "true-client-ip",
    "cf-connecting-ip",
    "fastly-client-ip",
    "x-appengine-user-ip",
    "x-azure-clientip",
    "traceparent",
    "tracestate",
    "baggage",
    "b3",
    "x-cloud-trace-context",
    "x-request-id",
    "x-correlation-id",
    "x-amzn-trace-id",
    "x-original-url",
    "x-rewrite-url",
    "x-original-method",
    "idempotency-key",
];

const RESERVED_REVIEW_COMPLETION_HEADER_PREFIXES: [&str; 8] = [
    "x-forwarded-",
    "proxy-",
    "sec-",
    "x-b3-",
    "x-envoy-",
    "x-datadog-",
    "x-http-method",
    "registry-",
];

fn valid_review_completion_header_name(name: &str) -> bool {
    let lower = name.to_ascii_lowercase();
    !name.is_empty()
        && name.len() <= MAXIMUM_REVIEW_COMPLETION_HEADER_NAME_BYTES
        && name.bytes().all(is_http_token_byte)
        && !RESERVED_REVIEW_COMPLETION_HEADER_PREFIXES
            .iter()
            .any(|prefix| lower.starts_with(prefix))
        && !RESERVED_REVIEW_COMPLETION_HEADER_NAMES.contains(&lower.as_str())
}

fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
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

/// Operator-private listener for `/metrics` and `/version`.
///
/// It is separate from the API listener so the counters and the active
/// package digest never appear on the surface the public contract describes.
#[cfg_attr(feature = "schema", derive(schemars::JsonSchema))]
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetricsListenerConfig {
    #[cfg_attr(feature = "schema", schemars(with = "String"))]
    pub bind: SocketAddr,
}

impl MetricsListenerConfig {
    fn validate(&self, listener: &ListenerConfig) -> Result<(), RuntimeConfigError> {
        let address = self.bind.ip();
        let private = match address {
            IpAddr::V4(address) => address.is_loopback() || address.is_private(),
            IpAddr::V6(address) => address.is_loopback() || is_unique_local(address),
        };
        if self.bind.port() == 0 || !private || address.is_multicast() {
            return Err(RuntimeConfigError::InvalidMetricsListener);
        }
        // An IPv6 wildcard socket is commonly dual-stack, so it is treated as
        // covering both families on every host; the IPv4 wildcard covers
        // only IPv4.
        let listener_address = listener.bind.ip();
        let listener_port = listener.bind.socket_addr().port();
        let wildcard_covers_metrics = match listener_address {
            IpAddr::V4(listener_address) => listener_address.is_unspecified() && address.is_ipv4(),
            IpAddr::V6(listener_address) => listener_address.is_unspecified(),
        };
        if (address == listener_address || wildcard_covers_metrics)
            && self.bind.port() == listener_port
        {
            return Err(RuntimeConfigError::InvalidMetricsListener);
        }
        Ok(())
    }
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
    pub fn load(path: impl AsRef<Path>) -> Result<Self, RuntimeConfigError> {
        let loaded = Self::loader().load::<Self>(path.as_ref())?;
        loaded.config.check()?;
        Ok(loaded.config)
    }

    /// The shared runtime configuration loader under Casework's envelope,
    /// removed keys, and retired apiVersions.
    #[must_use]
    pub const fn loader() -> RuntimeConfigLoader {
        RuntimeConfigLoader::new(CASEWORK_RUNTIME_ENVELOPE)
            .removed_keys(CASEWORK_REMOVED_KEYS)
            .retired_api_versions(CASEWORK_RETIRED_RUNTIME_API_VERSIONS)
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
        }
        for (destination_id, destination) in &self.review_completion_destinations {
            match (&destination.bearer_token_ref, &destination.auth) {
                (Some(reference), None) => {
                    references.push((
                        vec![
                            "reviewCompletionDestinations",
                            destination_id.as_str(),
                            "bearerTokenRef",
                        ],
                        reference.as_str(),
                    ));
                }
                (None, Some(auth)) => {
                    references.push((
                        vec![
                            "reviewCompletionDestinations",
                            destination_id.as_str(),
                            "auth",
                            "secretRef",
                        ],
                        auth.secret_ref.as_str(),
                    ));
                }
                _ => {}
            }
        }
        references
    }

    /// Resolve serving secrets without contacting their consumers or retaining
    /// their values. Migration credentials may remain off the serving host and
    /// are resolved only by `caseworkctl apply`. This checks provider/file
    /// availability and bounded secret text, not key formats or remote services.
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
        for (destination_id, destination) in &self.review_completion_destinations {
            let at = ["reviewCompletionDestinations", destination_id.as_str()];
            match (&destination.bearer_token_ref, &destination.auth) {
                (Some(_), None) => {}
                (None, Some(auth)) => {
                    if auth
                        .header
                        .as_deref()
                        .is_some_and(|header| !valid_review_completion_header_name(header))
                    {
                        let segments = [at[0], at[1], "auth", "header"];
                        findings.push(RuntimeConfigError::InvalidReviewCompletionAuth {
                            path: segments.join("."),
                            pointer: pointer_to(&segments),
                        });
                    }
                }
                _ => {
                    let segments = [at[0], at[1], "auth"];
                    findings.push(RuntimeConfigError::InvalidReviewCompletionAuth {
                        path: segments.join("."),
                        pointer: pointer_to(&segments),
                    });
                }
            }
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
            if let Err(error) = metrics_listener.validate(&self.listener) {
                findings.push(error);
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
        // `allowedClients: unrestricted` admits every client the issuer
        // verifies, so the deployment would accept a token minted for an
        // unrelated application in the same realm. Development loopback keeps
        // that convenience; a deployment behind an operator-controlled
        // terminator must name the clients it admits.
        if self.listener.tls_termination == TlsTermination::OperatorControlledUpstream
            && oidc.clients.allowed_clients.is_empty()
        {
            findings.push(RuntimeConfigError::AllowedClientsRequired);
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
                    reason: "must be an https URL with a host, or an http URL on 127.0.0.1 or [::1], without userinfo, query, or fragment",
                });
            }
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
                "List in authentication.oidc.allowedClients every client taskAuthority.statusClients and casework.yaml taskTemplates[].client name.",
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
                "must be the issuer every casework.yaml taskTemplates[].agent.issuer names",
                "Name the same issuer in authentication.oidc.issuer and in each taskTemplates[].agent.issuer.",
            ));
        }
        if !allowed_clients.is_empty()
            && templates
                .iter()
                .any(|template| !allowed_clients.contains(&template.client))
        {
            findings.push(task_authority_finding(
                &["authentication", "oidc", "allowedClients"],
                "must admit every client casework.yaml taskTemplates[].client names",
                "Add each taskTemplates[].client to authentication.oidc.allowedClients.",
            ));
        }
        if templates
            .iter()
            .any(|template| !valid_resource_uri(&template.resource))
        {
            findings.push(task_authority_finding(
                &["taskAuthority"],
                "cannot grant a casework.yaml taskTemplates[].resource that is not an absolute URI without userinfo or a fragment",
                "Write each taskTemplates[].resource in casework.yaml as the absolute URI of the resource the grant is for.",
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
    ) -> Result<(TokenVerifierConfig, std::sync::Arc<JwksFetcher>), RuntimeConfigError> {
        let fetcher = match &self.authentication.oidc.provider.jwks_source {
            JwksSource::Uri { uri } => {
                JwksFetcher::new(uri.to_string(), JwksFetcherConfig::defaults())
            }
            JwksSource::Discovery {} => {
                let discovery_config = OidcDiscoveryConfig {
                    issuer: self.authentication.oidc.provider.issuer.to_string(),
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
    /// UserInfo JWT, or any other JWT minted for this audience is not an
    /// access token, and admitting one would let a credential issued for
    /// another purpose claim, draft, and act on casework.
    pub(crate) fn verifier_profile(&self) -> TokenVerifierConfig {
        TokenVerifierConfig::access_token_profile(
            self.authentication.oidc.provider.issuer.to_string(),
            vec![self.authentication.oidc.provider.audience.clone()],
            vec![Algorithm::RS256, Algorithm::ES256],
            access_token_typ_set(CASEWORK_ACCESS_TOKEN_TYPE),
        )
        .with_scope_claim(self.authentication.oidc.scope_claim.clone())
        .with_allowed_clients(self.authentication.oidc.clients.allowed_clients.clone())
        .with_assertion_issuers(self.authentication.oidc.clients.assertion_issuers.clone())
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
    RuntimeConfig::check_package_block,
    RuntimeConfig::check_secret_providers,
    RuntimeConfig::check_audit,
    RuntimeConfig::check_secret_references,
    RuntimeConfig::check_listeners,
    RuntimeConfig::check_oidc,
    RuntimeConfig::check_database,
    RuntimeConfig::check_review_completion_destinations,
];

/// The rules a runtime file satisfies against the project it binds.
const PROJECT_RULES: &[ProjectRule] = &[
    RuntimeConfig::check_principal_claims,
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
        "http" => matches!(url.host_str(), Some("127.0.0.1" | "::1" | "[::1]")),
        _ => false,
    }
}

fn is_unique_local(address: Ipv6Addr) -> bool {
    address.octets()[0] & 0xfe == 0xfc
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
) -> RuntimeCheck {
    let check =
        RuntimeConfig::loader().check_offline::<RuntimeConfig>(path, substitute, stand_in_for);
    let mut diagnostics = check.diagnostics.clone();
    if let Some(loaded) = &check.loaded {
        diagnostics.extend(
            loaded
                .config
                .findings(project)
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

/// The report `casework serve` prints when it refuses the runtime file at
/// `path` with `error`: the shared loader's diagnostics, or every rule the
/// file breaks, each at its position. `None` for a refusal of the package or
/// of a dependency, which its message alone describes.
#[must_use]
pub fn startup_report(path: &Path, error: &RuntimeConfigError) -> Option<Report> {
    if let RuntimeConfigError::Load(error) = error {
        return Some(Report::new(error.diagnostics().to_vec()));
    }
    if !error.in_file() {
        return None;
    }
    let check = RuntimeConfig::loader().check_offline::<RuntimeConfig>(path, true, stand_in_for);
    let config = &check.loaded.as_ref()?.config;
    let package = config.capture_package_after_verification(|| {}).ok();
    let mut diagnostics: Vec<Diagnostic> = config
        .findings(package.as_ref().map(LoadedCaseworkPackage::project))
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
        RuntimeConfigError::InvalidMetricsListener => &["/listener/bind"],
        RuntimeConfigError::AllowedClientsRequired => &["/listener/tlsTermination"],
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
        ["listener", "tlsTermination"] => "development-loopback",
        ["listener", "networkExposure"] => "private-address",
        ["metricsListener", "bind"] => "127.0.0.1:9100",
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
    use registry_platform_config::write_package;
    use serde_json::json;

    const STANDALONE: &str =
        include_str!("../../../products/casework/examples/standalone-decision/casework.yaml");
    const SCHEMA: &str = r#"{"type":"object","additionalProperties":false,"required":["summary","reference"],"properties":{"summary":{"type":"string","maxLength":160},"reference":{"type":"string","maxLength":120}}}"#;

    fn read_operator(value: &serde_json::Value, directory: &Path) -> RuntimeConfig {
        let path = write_operator(value, directory);
        RuntimeConfig::loader()
            .load::<RuntimeConfig>(&path)
            .unwrap()
            .config
    }

    fn write_operator(value: &serde_json::Value, directory: &Path) -> PathBuf {
        let path = directory.join("runtime.yaml");
        std::fs::write(&path, serde_norway::to_string(value).unwrap()).unwrap();
        path
    }

    fn operator_value(package: &Path, directory: &Path) -> serde_json::Value {
        json!({
            "apiVersion":RUNTIME_CONFIG_API_VERSION,"kind":RUNTIME_CONFIG_KIND,
            "identity":{"databaseId":"test"},"package":{"root":package},
            "listener":{"bind":"127.0.0.1:8100","tlsTermination":"development-loopback","networkExposure":"private-address"},
            "secretProviders":{"file":{"root":directory.join("secrets")}},
            "database":{"runtimeUrlRef":"secret:file/runtime-url","migrationUrlRef":"secret:file/migration-url"},
            "authentication":{"oidc":{"issuer":"https://identity.example.test","audience":"urn:example:casework","allowedClients":"unrestricted","scopeClaim":"scope","humanIdentity":{"claim":"registry_actor_kind","value":"human"}}},
            "audit":{"path":directory.join("audit.ndjson"),"hashKeyRef":"secret:file/audit-key"}
        })
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
        value["database"]["trustedRootCertificateRef"] = json!("secret:file/db-ca");
        value["authentication"]["oidc"]["jwksSource"] =
            json!({"type":"static", "documentRef":"secret:file/jwks"});
        value["taskAuthority"] = json!({"issuer":"https://casework.example.test","exchangeAudience":"urn:example:exchange","signingKeyRef":"secret:file/signer","statusClients":{}});
        value["contextProviders"] = json!({"facility":{
            "baseUrl":"https://registry.example.test", "statusProfile":"review-status",
            "tokenEndpoint":"https://identity.example.test/token", "clientIdRef":"secret:file/client-id", "clientAssertionKeyRef":"secret:file/client-key"
        }});
        value["reviewCompletionDestinations"] = json!({
            "bearer":{"url":"https://completion.example.test/reviews","bearerTokenRef":"secret:file/bearer"},
            "header./receiver":{"url":"https://completion.example.test/reviews","auth":{"header":"x-api-key","secretRef":"secret:file/header"}}
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
                "/database/trustedRootCertificateRef",
                "/audit/hashKeyRef",
                "/authentication/oidc/jwksSource/documentRef",
                "/taskAuthority/signingKeyRef",
                "/contextProviders/facility/clientIdRef",
                "/contextProviders/facility/clientAssertionKeyRef",
                "/reviewCompletionDestinations/bearer/bearerTokenRef",
                "/reviewCompletionDestinations/header.~1receiver/auth/secretRef"
            ]
        );
        assert!(!report.render_human().contains("secret:file/"));
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
        let config = RuntimeConfig::loader()
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
        let error = RuntimeConfig::loader()
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

        let error = RuntimeConfig::load(write_operator(&document, temp.path())).unwrap_err();
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
    #[error(
        "metricsListener.bind must be a loopback or private address with a nonzero port that the API listener does not also occupy"
    )]
    InvalidMetricsListener,
    #[error("{path} {reason}")]
    InvalidOidcClaim {
        path: &'static str,
        reason: &'static str,
    },
    #[error(
        "authentication.oidc.humanIdentity.claim must differ from every accessProfiles.PROFILE_ID.principalClaim in casework.yaml"
    )]
    PrincipalClaimConflict,
    #[error(
        "authentication.oidc.allowedClients must name every client the deployment admits under operator-controlled-upstream; unrestricted admits every client the issuer verifies"
    )]
    AllowedClientsRequired,
    #[error("{path} {reason}")]
    InvalidTaskAuthority {
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
    #[error(
        "{path} must name exactly one completion secret, in a header the runtime does not reserve"
    )]
    InvalidReviewCompletionAuth { path: String, pointer: String },
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
    #[error("plaintext PostgreSQL is test-only")]
    PlaintextDatabase,
    #[error("the OIDC issuer could not be initialized")]
    Oidc,
    #[error("the static OIDC signing keys could not be loaded: {0}")]
    OidcJwksSecret(String),
}

/// The fix for a rebuilt package, named by every package refusal.
const REBUILD_PACKAGE: &str =
    "Rebuild the package with `caseworkctl package`, then point package.root at it.";

impl RuntimeConfigError {
    /// The dotted member path of a refusal that carries no pointer of its
    /// own; [`Self::pointer`] is the location every caller reads.
    fn member(&self) -> &str {
        match self {
            Self::Block(error) => error.field(),
            Self::InvalidApiVersion => "apiVersion",
            Self::InvalidKind => "kind",
            Self::InvalidDatabaseId => "identity.databaseId",
            Self::RelativeOperatedPath(path) => path,
            Self::InvalidOidcClaim { path, .. } => path,
            Self::PrincipalClaimConflict => "authentication.oidc.humanIdentity.claim",
            Self::Oidc => "authentication.oidc",
            Self::AllowedClientsRequired => "authentication.oidc.allowedClients",
            Self::OidcJwksSecret(_) => "authentication.oidc.jwksSource.documentRef",
            Self::InvalidListener => "listener.bind",
            Self::InvalidMetricsListener => "metricsListener.bind",
            Self::InvalidDatabaseReference => "database",
            Self::PlaintextDatabase => "database.testOnlyPlaintext",
            Self::InvalidAuditDestination(error) => audit_field(error),
            Self::InvalidContextProviders => "contextProviders",
            Self::UnconfiguredReviewCompletionDestination => "reviewCompletionDestinations",
            Self::PackageDigest(_) => "package.expectedDigest",
            // Located by `pointer` itself.
            Self::Load(_)
            | Self::BindingSecret { .. }
            | Self::InvalidReviewCompletionAuth { .. }
            | Self::InvalidReviewCompletionDestination { .. }
            | Self::InvalidTaskAuthority { .. }
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
            Self::BindingSecret { pointer, .. }
            | Self::InvalidReviewCompletionAuth { pointer, .. }
            | Self::InvalidReviewCompletionDestination { pointer, .. }
            | Self::InvalidTaskAuthority { pointer, .. } => pointer.clone(),
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
            Self::Block(error) | Self::BindingSecret { error, .. } => block_finding(error).0,
            Self::InvalidApiVersion => "casework.runtime.unsupported-api-version",
            Self::InvalidKind => "casework.runtime.wrong-kind",
            Self::MissingIdentity => "casework.runtime.missing-identity",
            Self::InvalidDatabaseId => "casework.runtime.invalid-database-id",
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
            Self::InvalidMetricsListener => "casework.runtime.invalid-metrics-listener",
            Self::InvalidOidcClaim { .. } => "casework.runtime.invalid-oidc-claim",
            Self::PrincipalClaimConflict => "casework.runtime.principal-claim-conflict",
            Self::AllowedClientsRequired => "casework.runtime.allowed-clients-required",
            Self::InvalidTaskAuthority { .. } => "casework.runtime.invalid-task-authority",
            Self::InvalidDatabaseReference => "casework.runtime.invalid-database-reference",
            Self::InvalidAuditDestination(_) => "casework.runtime.invalid-audit",
            Self::InvalidContextProviders => "casework.runtime.context-providers-mismatch",
            Self::InvalidReviewCompletionAuth { .. } => {
                "casework.runtime.invalid-review-completion-auth"
            }
            Self::InvalidReviewCompletionDestination { .. } => {
                "casework.runtime.invalid-review-completion-destination"
            }
            Self::UnconfiguredReviewCompletionDestination => {
                "casework.runtime.unconfigured-review-completion-destination"
            }
            Self::PlaintextDatabase => "casework.runtime.plaintext-database",
            Self::Oidc => "casework.runtime-dependency.unavailable",
            Self::OidcJwksSecret(_) => "casework.runtime.unreadable-jwks-secret",
        }
    }

    /// What the operator does to clear this refusal.
    #[must_use]
    pub fn suggested_action(&self) -> String {
        let action = match self {
            Self::Load(error) => return error.deciding_diagnostic().suggested_action.clone(),
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
                "Bind to a loopback address under development-loopback; under operator-controlled-upstream bind to a loopback or private address, or to the unspecified address only with networkExposure: container-private."
            }
            Self::InvalidMetricsListener => {
                "Bind metricsListener to a loopback or private address with a nonzero port the API listener does not use."
            }
            Self::InvalidOidcClaim { .. } => {
                "Name a non-empty claim distinct from authentication.oidc.scopeClaim, or remove the member to use its default."
            }
            Self::PrincipalClaimConflict => {
                "Name a humanIdentity.claim that no accessProfiles.PROFILE_ID.principalClaim in casework.yaml uses."
            }
            Self::AllowedClientsRequired => {
                "List every client identifier this deployment admits in authentication.oidc.allowedClients, then retry."
            }
            Self::InvalidTaskAuthority { action, .. } => action,
            Self::InvalidDatabaseReference => {
                "Write database.runtimeUrlRef and database.migrationUrlRef as secret references."
            }
            Self::InvalidAuditDestination(error) => audit_action(error),
            Self::InvalidContextProviders => {
                "Remove the unrecognized contextProviders key, or declare its deploymentRef in casework.yaml. Omitted providers remain unavailable to their current-source reviews."
            }
            Self::InvalidReviewCompletionAuth { .. } => {
                "Configure exactly one of bearerTokenRef and auth.secretRef, and name in auth.header only a header the runtime does not reserve."
            }
            Self::InvalidReviewCompletionDestination { .. } => {
                "Give the destination a non-empty id and an https URL with a host, or an http URL on 127.0.0.1 or [::1] for local development."
            }
            Self::UnconfiguredReviewCompletionDestination => {
                "Add a reviewCompletionDestinations entry for each destination casework.yaml trustedProducers.PRODUCER_ID.completion.destinationId names."
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
